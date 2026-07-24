//! Wire-compatible with Python `rnprobe.py`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::timeout;

use rns_identity::destination::{DestType, Destination, Direction, ProofStrategy};
use rns_identity::identity::Identity;
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{
    AnnounceRpcEntry, OutboundRequest, TransportMessage, TransportQuery, TransportQueryResponse,
};
use rns_wire::constants::MTU;
use rns_wire::context::PacketContext;
use rns_wire::flags::{DestinationType, HeaderType, PacketFlags, PacketType, TransportType};
use rns_wire::hash::packet_hash_pair;
use rns_wire::header::PacketHeader;

/// Python rnprobe `DEFAULT_TIMEOUT`.
const DEFAULT_TIMEOUT_SECS: f64 = 12.0;

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("timed out waiting for path to destination")]
    PathTimeout,
    #[error("probe size {0} exceeds MTU {1}")]
    MtuExceeded(usize, usize),
    #[error("timed out waiting for proof")]
    PacketTimeout,
    #[error("encryption failed: {0}")]
    EncryptError(String),
    #[error("destination's identity is not in the local announce cache")]
    NoIdentity,
    #[error("transport channel closed")]
    TransportClosed,
    #[error("invalid destination name")]
    InvalidName,
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub rtt: Duration,
    /// 0 for direct.
    pub hops: u8,
    pub via: Option<[u8; 16]>,
    pub interface: Option<String>,
    pub destination_hash: [u8; 16],
}

/// Signs every inbound DATA with a PROOF (Python `PROVE_ALL`). Callers must
/// persist `identity` (canonical `<storage_dir>/probe_identity`) for a stable
/// destination hash across restarts.
pub async fn spawn_probe_responder(
    transport_tx: mpsc::Sender<TransportMessage>,
    identity: Identity,
    app_name: &str,
) -> Result<[u8; 16], ProbeError> {
    let mut dest = Destination::new(Some(&identity), Direction::In, DestType::Single, app_name)
        .map_err(|e| ProbeError::Internal(format!("destination: {e}")))?;
    dest.set_proof_strategy(ProofStrategy::ProveAll);
    let dest_hash = dest.hash;

    let (event_tx, mut event_rx) = mpsc::channel::<DestinationEvent>(64);

    transport_tx
        .send(TransportMessage::RegisterDestination {
            hash: dest_hash,
            app_name: app_name.to_string(),
            delivery_tx: Some(event_tx),
        })
        .await
        .map_err(|_| ProbeError::TransportClosed)?;

    let identity = Arc::new(identity);
    let mut destination = dest;
    // Implicit proof is Python's default (`use_implicit_proof = Yes`).
    let implicit = true;

    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let (raw, interface_id) = match event {
                DestinationEvent::InboundPacket { raw, interface_id } => (raw, interface_id),
                DestinationEvent::AnnounceRequested(request) => {
                    let raw = match destination.announce_packet(
                        identity.as_ref(),
                        None,
                        None,
                        request.path_response,
                        request.tag.as_deref(),
                        unix_now(),
                    ) {
                        Ok(raw) => raw,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                path_response = request.path_response,
                                "probe responder: failed to build requested announce"
                            );
                            continue;
                        }
                    };
                    let outbound = OutboundRequest {
                        raw: Bytes::from(raw),
                        destination_hash: dest_hash,
                    };
                    let message = if let Some(interface_id) = request.attached_interface {
                        TransportMessage::OutboundAttached {
                            request: outbound,
                            interface_id,
                        }
                    } else {
                        TransportMessage::Outbound(outbound)
                    };
                    if transport_tx.send(message).await.is_err() {
                        tracing::debug!("probe responder: transport closed, exiting");
                        break;
                    }
                    continue;
                }
                _ => continue,
            };
            let (header, _) = match PacketHeader::unpack(&raw) {
                Ok(h) => h,
                Err(e) => {
                    tracing::debug!(error = %e, "probe responder: bad header");
                    continue;
                }
            };
            if header.flags.packet_type != PacketType::Data {
                continue;
            }

            let (full_hash, trunc_hash) = packet_hash_pair(&raw, header.flags.header_type);
            let proof_payload = match identity.prove(&full_hash, implicit) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(error = %e, "probe responder: sign failed");
                    continue;
                }
            };

            // Proof destination = truncated_packet_hash of source DATA; payload plaintext.
            let proof_flags = PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Proof,
            };
            let proof_header = PacketHeader {
                flags: proof_flags,
                hops: 0,
                transport_id: None,
                destination_hash: trunc_hash,
                context: PacketContext::None,
            };
            let mut proof_raw = proof_header.pack();
            proof_raw.extend_from_slice(&proof_payload);

            if transport_tx
                .send(TransportMessage::OutboundAttached {
                    request: OutboundRequest {
                        raw: Bytes::from(proof_raw),
                        destination_hash: trunc_hash,
                    },
                    interface_id,
                })
                .await
                .is_err()
            {
                tracing::debug!("probe responder: transport closed, exiting");
                break;
            }

            tracing::debug!(
                dest = hex::encode(dest_hash),
                trunc = hex::encode(trunc_hash),
                implicit,
                "probe responder: sent proof"
            );
        }

        tracing::debug!(
            dest = hex::encode(dest_hash),
            "probe responder: event loop exited"
        );
    });

    tracing::info!(
        dest = %hex::encode(dest_hash),
        app_name,
        "probe responder registered"
    );

    Ok(dest_hash)
}

/// Filters DeliveryProof fan-out down to this probe's `msg_id`.
struct DeliveryProofWaiter {
    msg_id: String,
    rx: Mutex<mpsc::Receiver<DestinationEvent>>,
    transport_tx: mpsc::Sender<TransportMessage>,
    probe_dest_hash: [u8; 16],
}

impl DeliveryProofWaiter {
    async fn wait(&self, wait_for: Duration) -> Option<Option<Duration>> {
        let mut rx = self.rx.lock().await;
        let deadline = Instant::now() + wait_for;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let ev = match timeout(remaining, rx.recv()).await {
                Ok(Some(ev)) => ev,
                Ok(None) => return None,
                Err(_) => return None,
            };
            if let DestinationEvent::DeliveryProof { msg_id, rtt } = ev {
                if msg_id == self.msg_id {
                    return Some(rtt);
                }
            }
        }
    }
}

impl Drop for DeliveryProofWaiter {
    fn drop(&mut self) {
        let _ = self
            .transport_tx
            .try_send(TransportMessage::DeregisterDestination {
                hash: self.probe_dest_hash,
            });
    }
}

/// `None` waits mirror Python rnprobe: `DEFAULT_TIMEOUT +
/// get_first_hop_timeout(dest)`, resolved fresh at each wait.
pub async fn probe_once(
    transport_tx: mpsc::Sender<TransportMessage>,
    dest_hash: [u8; 16],
    app_name: &str,
    size: usize,
    proof_wait: Option<Duration>,
    path_wait: Option<Duration>,
    use_implicit_proof: bool,
) -> Result<ProbeOutcome, ProbeError> {
    if size > MTU {
        return Err(ProbeError::MtuExceeded(size, MTU));
    }

    let has_path = match query(
        &transport_tx,
        TransportQuery::GetNextHop { dest: dest_hash },
    )
    .await?
    {
        TransportQueryResponse::HashResult(h) => h.is_some(),
        _ => false,
    };
    // Local destinations have no next_hop but are still reachable.
    let interface_id_resp = query(
        &transport_tx,
        TransportQuery::GetNextHopInterfaceId { dest: dest_hash },
    )
    .await?;
    let has_interface = matches!(interface_id_resp, TransportQueryResponse::IntResult(n) if n >= 0);

    if !has_path && !has_interface {
        transport_tx
            .send(TransportMessage::RequestPath {
                destination_hash: dest_hash,
            })
            .await
            .map_err(|_| ProbeError::TransportClosed)?;

        let path_wait = match path_wait {
            Some(d) => d,
            None => default_probe_wait(&transport_tx, dest_hash).await?,
        };

        let (await_tx, await_rx) = oneshot::channel();
        transport_tx
            .send(TransportMessage::AwaitPath {
                dest: dest_hash,
                reply: await_tx,
            })
            .await
            .map_err(|_| ProbeError::TransportClosed)?;

        let found = timeout(path_wait, await_rx)
            .await
            .map_err(|_| ProbeError::PathTimeout)?
            .unwrap_or(false);
        if !found {
            return Err(ProbeError::PathTimeout);
        }
    }

    let announces = match query(&transport_tx, TransportQuery::GetRecentAnnounces).await? {
        TransportQueryResponse::Announces(v) => v,
        _ => Vec::new(),
    };
    let pubkey = find_public_key(&announces, &dest_hash).ok_or(ProbeError::NoIdentity)?;

    let remote_identity =
        Identity::from_public_key(&pubkey).map_err(|e| ProbeError::EncryptError(e.to_string()))?;
    let out_dest = Destination::new(
        Some(&remote_identity),
        Direction::Out,
        DestType::Single,
        app_name,
    )
    .map_err(|e| ProbeError::Internal(format!("out destination: {e}")))?;
    debug_assert_eq!(out_dest.hash, dest_hash);

    let payload = rns_crypto::random::random_bytes(size);
    let ciphertext = out_dest
        .encrypt(&payload, &remote_identity, None)
        .map_err(|e| ProbeError::EncryptError(e.to_string()))?;

    let flags = PacketFlags {
        header_type: HeaderType::Header1,
        context_flag: false,
        transport_type: TransportType::Broadcast,
        destination_type: DestinationType::Single,
        packet_type: PacketType::Data,
    };
    let header = PacketHeader {
        flags,
        hops: 0,
        transport_id: None,
        destination_hash: dest_hash,
        context: PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(&ciphertext);

    if raw.len() > MTU {
        return Err(ProbeError::MtuExceeded(raw.len(), MTU));
    }

    let (full_hash, trunc_hash) = packet_hash_pair(&raw, HeaderType::Header1);

    // Per probe, like Python's per-packet `timeout or DEFAULT_TIMEOUT + fht`.
    let proof_wait = match proof_wait {
        Some(d) => d,
        None => default_probe_wait(&transport_tx, dest_hash).await?,
    };

    // trunc_hash keys `receipt_table`; unique msg_id filters fan-out.
    let msg_id = format!(
        "probe.{}.{:x}",
        hex::encode(&trunc_hash[..4]),
        std::process::id()
    );
    transport_tx
        .send(TransportMessage::RegisterReceipt {
            truncated_hash: trunc_hash,
            full_hash,
            destination_hash: dest_hash,
            destination_public_key: pubkey,
            msg_id: msg_id.clone(),
            timeout: Some(proof_wait + Duration::from_secs(1)),
        })
        .await
        .map_err(|_| ProbeError::TransportClosed)?;

    // Fresh identity avoids hash collision with real destinations.
    let probe_listener = Destination::new(None, Direction::In, DestType::Single, "probe.client")
        .map_err(|e| ProbeError::Internal(format!("listener dest: {e}")))?;
    let listener_hash = probe_listener.hash;
    let (ev_tx, ev_rx) = mpsc::channel::<DestinationEvent>(16);
    transport_tx
        .send(TransportMessage::RegisterDestination {
            hash: listener_hash,
            app_name: "probe.client".to_string(),
            delivery_tx: Some(ev_tx),
        })
        .await
        .map_err(|_| ProbeError::TransportClosed)?;

    let waiter = DeliveryProofWaiter {
        msg_id: msg_id.clone(),
        rx: Mutex::new(ev_rx),
        transport_tx: transport_tx.clone(),
        probe_dest_hash: listener_hash,
    };

    let path_meta = collect_path_meta(&transport_tx, dest_hash).await;
    let send_instant = Instant::now();
    transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: dest_hash,
        }))
        .await
        .map_err(|_| ProbeError::TransportClosed)?;

    let rtt_from_receipt = waiter
        .wait(proof_wait)
        .await
        .ok_or(ProbeError::PacketTimeout)?;
    let rtt = rtt_from_receipt.unwrap_or_else(|| send_instant.elapsed());

    let _ = use_implicit_proof;

    Ok(ProbeOutcome {
        rtt,
        hops: path_meta.hops,
        via: path_meta.via,
        interface: path_meta.interface,
        destination_hash: dest_hash,
    })
}

async fn default_probe_wait(
    tx: &mpsc::Sender<TransportMessage>,
    dest: [u8; 16],
) -> Result<Duration, ProbeError> {
    let first_hop = match query(tx, TransportQuery::FirstHopTimeout { dest }).await? {
        TransportQueryResponse::FloatResult(Some(t)) => t,
        _ => rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT,
    };
    Ok(Duration::from_secs_f64(DEFAULT_TIMEOUT_SECS + first_hop))
}

pub fn parse_dest_hash(hex_str: &str) -> Result<[u8; 16], ProbeError> {
    let bytes = hex::decode(hex_str.trim()).map_err(|_| ProbeError::InvalidName)?;
    <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| ProbeError::InvalidName)
}

pub fn default_probe_app_name() -> &'static str {
    "rnstransport.probe"
}

#[derive(Default)]
struct PathMeta {
    hops: u8,
    via: Option<[u8; 16]>,
    interface: Option<String>,
}

async fn collect_path_meta(tx: &mpsc::Sender<TransportMessage>, dest: [u8; 16]) -> PathMeta {
    let mut meta = PathMeta::default();
    if let Ok(TransportQueryResponse::PathTable(entries)) =
        query(tx, TransportQuery::GetPathTable).await
    {
        if let Some(entry) = entries.into_iter().find(|e| e.hash == dest) {
            meta.hops = entry.hops;
            meta.via = entry.via;
            meta.interface = Some(entry.interface);
        }
    }
    meta
}

async fn query(
    tx: &mpsc::Sender<TransportMessage>,
    query: TransportQuery,
) -> Result<TransportQueryResponse, ProbeError> {
    let (resp_tx, resp_rx) = oneshot::channel();
    tx.send(TransportMessage::Rpc {
        query,
        response_tx: resp_tx,
    })
    .await
    .map_err(|_| ProbeError::TransportClosed)?;
    resp_rx.await.map_err(|_| ProbeError::TransportClosed)
}

fn find_public_key(announces: &[AnnounceRpcEntry], dest_hash: &[u8; 16]) -> Option<[u8; 64]> {
    announces
        .iter()
        .find(|a| &a.dest_hash == dest_hash)
        .and_then(|a| a.public_key)
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_app_name_matches_python() {
        // Python: Transport.APP_NAME = "rnstransport", aspect = "probe".
        assert_eq!(default_probe_app_name(), "rnstransport.probe");
    }

    #[test]
    fn parse_dest_hash_valid() {
        let h = parse_dest_hash("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(
            h,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
    }

    #[test]
    fn parse_dest_hash_too_short_errors() {
        assert!(parse_dest_hash("deadbeef").is_err());
    }

    #[test]
    fn parse_dest_hash_non_hex_errors() {
        assert!(parse_dest_hash("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn find_public_key_returns_match() {
        let entries = vec![
            AnnounceRpcEntry {
                dest_hash: [0xAA; 16],
                hops: 0,
                app_data: None,
                timestamp: 0.0,
                public_key: Some([0x11; 64]),
                ratchet: None,
                name_hash: [0; 10],
                is_path_response: false,
                retained: false,
            },
            AnnounceRpcEntry {
                dest_hash: [0xBB; 16],
                hops: 1,
                app_data: None,
                timestamp: 0.0,
                public_key: Some([0x22; 64]),
                ratchet: None,
                name_hash: [0; 10],
                is_path_response: false,
                retained: false,
            },
        ];
        assert_eq!(find_public_key(&entries, &[0xBB; 16]), Some([0x22; 64]));
        assert_eq!(find_public_key(&entries, &[0xCC; 16]), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn responder_replies_to_data_with_proof() {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(16);

        let identity = Identity::new();
        let identity_pub = identity.get_public_key();
        let spawn_tx = tx.clone();
        let spawn_handle = tokio::spawn(async move {
            spawn_probe_responder(spawn_tx, identity, default_probe_app_name()).await
        });

        let first = rx.recv().await.expect("RegisterDestination");
        let (dest_hash_from_msg, delivery_tx) = match first {
            TransportMessage::RegisterDestination {
                hash,
                delivery_tx: Some(dt),
                ..
            } => (hash, dt),
            other => panic!("expected RegisterDestination, got {other:?}"),
        };
        let dest_hash = spawn_handle.await.unwrap().unwrap();
        assert_eq!(dest_hash, dest_hash_from_msg);

        let flags = PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
        };
        let header = PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: dest_hash,
            context: PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0xEE; 32]);
        let (expected_full, expected_trunc) = packet_hash_pair(&raw, HeaderType::Header1);

        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: bytes::Bytes::from(raw),
                interface_id: 0,
            })
            .await
            .unwrap();

        let outbound = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for proof")
            .expect("channel closed");
        let (request, interface_id) = match outbound {
            TransportMessage::OutboundAttached {
                request,
                interface_id,
            } => (request, interface_id),
            other => panic!("expected OutboundAttached, got {other:?}"),
        };
        let OutboundRequest {
            raw: proof_raw,
            destination_hash,
        } = request;

        assert_eq!(destination_hash, expected_trunc);
        assert_eq!(interface_id, 0);

        let (proof_header, data_offset) = PacketHeader::unpack(&proof_raw).unwrap();
        assert_eq!(proof_header.flags.packet_type, PacketType::Proof);
        assert_eq!(proof_header.flags.destination_type, DestinationType::Single);
        assert_eq!(proof_header.flags.header_type, HeaderType::Header1);
        assert_eq!(proof_header.destination_hash, expected_trunc);

        let payload = &proof_raw[data_offset..];
        assert_eq!(payload.len(), 64, "expected implicit 64-byte proof");

        let remote = Identity::from_public_key(&identity_pub).unwrap();
        let mut sig = [0u8; 64];
        sig.copy_from_slice(payload);
        assert!(
            remote.verify(&expected_full, &sig),
            "proof signature must verify over full packet hash"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn responder_sends_attached_path_response_announce() {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(16);

        let identity = Identity::new();
        let spawn_tx = tx.clone();
        let spawn_handle = tokio::spawn(async move {
            spawn_probe_responder(spawn_tx, identity, default_probe_app_name()).await
        });

        let first = rx.recv().await.expect("RegisterDestination");
        let delivery_tx = match first {
            TransportMessage::RegisterDestination {
                delivery_tx: Some(dt),
                ..
            } => dt,
            other => panic!("expected RegisterDestination, got {other:?}"),
        };
        let dest_hash = spawn_handle.await.unwrap().unwrap();

        delivery_tx
            .send(DestinationEvent::AnnounceRequested(
                rns_transport::link_messages::AnnounceRequest {
                    app_name: default_probe_app_name().to_string(),
                    path_response: true,
                    tag: Some(vec![0xA5; 16]),
                    attached_interface: Some(7),
                },
            ))
            .await
            .unwrap();

        let outbound = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for path response")
            .expect("channel closed");
        let (request, interface_id) = match outbound {
            TransportMessage::OutboundAttached {
                request,
                interface_id,
            } => (request, interface_id),
            other => panic!("expected OutboundAttached, got {other:?}"),
        };

        assert_eq!(interface_id, 7);
        assert_eq!(request.destination_hash, dest_hash);
        let (header, _offset) = PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(header.flags.packet_type, PacketType::Announce);
        assert_eq!(header.flags.destination_type, DestinationType::Single);
        assert_eq!(header.destination_hash, dest_hash);
        assert_eq!(header.context, PacketContext::PathResponse);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn responder_ignores_non_data_packets() {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(16);
        let identity = Identity::new();
        let spawn_tx = tx.clone();
        let h = tokio::spawn(async move {
            spawn_probe_responder(spawn_tx, identity, default_probe_app_name()).await
        });
        let reg = rx.recv().await.unwrap();
        let delivery_tx = match reg {
            TransportMessage::RegisterDestination {
                delivery_tx: Some(dt),
                ..
            } => dt,
            _ => panic!("expected RegisterDestination"),
        };
        let dest_hash = h.await.unwrap().unwrap();

        let flags = PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
        };
        let header = PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: dest_hash,
            context: PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0xAB; 64]);

        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: bytes::Bytes::from(raw),
                interface_id: 0,
            })
            .await
            .unwrap();

        match tokio::time::timeout(Duration::from_millis(150), rx.recv()).await {
            Err(_) => (),
            Ok(other) => panic!("unexpected response to non-DATA packet: {other:?}"),
        }
    }
}
