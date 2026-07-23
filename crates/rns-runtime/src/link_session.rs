//! Persistent initiator-side Reticulum Link sessions for applications.
//!
//! Unlike [`crate::link_client::LinkClient`], which opens a Link for one
//! request/response exchange, this module keeps the Link alive and exposes
//! ordinary encrypted Link packets until either peer closes the session.

use std::collections::HashSet;
use std::time::Duration;

use bytes::Bytes;
use rns_crypto::ed25519::Ed25519PublicKey;
use rns_identity::identity::Identity;
use rns_link::link::{CloseReason, Link, LinkAction, LinkState};
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{
    AnnounceRpcEntry, OutboundRequest, TransportMessage, TransportQuery, TransportQueryResponse,
};
use tokio::sync::{mpsc, oneshot};

const COMMAND_BUFFER: usize = 64;
const EVENT_BUFFER: usize = 256;

#[derive(Debug, Clone)]
pub struct LinkSessionConfig {
    pub destination_hash: [u8; 16],
    pub remote_public_key: [u8; 64],
    pub hops: u8,
    pub establishment_timeout: Duration,
    pub client_label: String,
    pub identify: bool,
}

impl LinkSessionConfig {
    pub fn identified(
        destination_hash: [u8; 16],
        remote_public_key: [u8; 64],
        client_label: impl Into<String>,
    ) -> Self {
        Self {
            destination_hash,
            remote_public_key,
            hops: 1,
            establishment_timeout: Duration::from_secs(30),
            client_label: client_label.into(),
            identify: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSessionCloseReason {
    Local,
    Remote,
    Timeout,
    TransportUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkSessionEvent {
    Packet {
        data: Vec<u8>,
        packet_hash: [u8; 32],
    },
    PacketDelivered {
        packet_hash: [u8; 32],
    },
    Stale,
    Recovered,
    Closed {
        reason: LinkSessionCloseReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSessionPacketReceipt {
    pub link_id: [u8; 16],
    pub packet_hash: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum LinkSessionError {
    #[error("transport channel is unavailable")]
    TransportUnavailable,
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    #[error("destination announce did not include a public key")]
    PublicKeyUnavailable,
    #[error("link proof validation failed: {0}")]
    ProofInvalid(String),
    #[error("link establishment failed: {0}")]
    HandshakeFailed(String),
    #[error("local identity could not sign Link identification")]
    IdentificationUnavailable,
    #[error("link encryption failed")]
    LinkCrypto,
    #[error("link is not active")]
    LinkNotActive,
    #[error("payload is {actual} bytes; Link MDU is {max}")]
    PayloadTooLarge { actual: usize, max: usize },
    #[error("Link session task is no longer running")]
    SessionClosed,
}

enum LinkSessionCommand {
    SendPacket {
        payload: Vec<u8>,
        result_tx: oneshot::Sender<Result<LinkSessionPacketReceipt, LinkSessionError>>,
    },
    Close,
}

#[derive(Clone)]
pub struct LinkSessionHandle {
    link_id: [u8; 16],
    mdu: usize,
    command_tx: mpsc::Sender<LinkSessionCommand>,
}

impl LinkSessionHandle {
    pub fn link_id(&self) -> [u8; 16] {
        self.link_id
    }

    pub fn mdu(&self) -> usize {
        self.mdu
    }

    pub async fn send_packet(
        &self,
        payload: Vec<u8>,
    ) -> Result<LinkSessionPacketReceipt, LinkSessionError> {
        if payload.len() > self.mdu {
            return Err(LinkSessionError::PayloadTooLarge {
                actual: payload.len(),
                max: self.mdu,
            });
        }
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::SendPacket { payload, result_tx })
            .await
            .map_err(|_| LinkSessionError::SessionClosed)?;
        result_rx
            .await
            .map_err(|_| LinkSessionError::SessionClosed)?
    }

    pub async fn close(&self) {
        let _ = self.command_tx.send(LinkSessionCommand::Close).await;
    }
}

pub struct LinkSession {
    pub handle: LinkSessionHandle,
    pub events: mpsc::Receiver<LinkSessionEvent>,
}

/// Ensures a cancelled or failed handshake cannot leave its temporary Link
/// destination registered in the transport actor. Once the session actor owns
/// cleanup, `disarm` transfers that responsibility.
struct DestinationRegistrationGuard {
    transport_tx: mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    armed: bool,
}

impl DestinationRegistrationGuard {
    fn new(transport_tx: mpsc::Sender<TransportMessage>, link_id: [u8; 16]) -> Self {
        Self {
            transport_tx,
            link_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DestinationRegistrationGuard {
    fn drop(&mut self) {
        if self.armed {
            deregister_destination(&self.transport_tx, self.link_id);
        }
    }
}

impl LinkSession {
    pub async fn connect(
        transport_tx: mpsc::Sender<TransportMessage>,
        identity: Identity,
        config: LinkSessionConfig,
    ) -> Result<Self, LinkSessionError> {
        let (mut link, request_data) = Link::new_initiator(config.destination_hash, config.hops);
        let link_id = link.link_id;
        let (delivery_tx, mut delivery_rx) = mpsc::channel::<DestinationEvent>(EVENT_BUFFER);

        transport_tx
            .send(TransportMessage::RegisterDestination {
                hash: link_id,
                app_name: config.client_label,
                delivery_tx: Some(delivery_tx),
            })
            .await
            .map_err(|_| LinkSessionError::TransportUnavailable)?;
        let mut registration = DestinationRegistrationGuard::new(transport_tx.clone(), link_id);

        let request = build_link_request_packet(config.destination_hash, &request_data);
        if transport_tx
            .send(TransportMessage::Outbound(OutboundRequest {
                raw: request,
                destination_hash: config.destination_hash,
            }))
            .await
            .is_err()
        {
            return Err(LinkSessionError::TransportUnavailable);
        }

        let proof = match tokio::time::timeout(
            config.establishment_timeout,
            wait_for_link_proof(&mut delivery_rx, link_id),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(LinkSessionError::Timeout("link proof")),
        };
        let proof = match proof {
            Ok(proof) => proof,
            Err(error) => return Err(error),
        };

        let peer_signing_key: [u8; 32] = config.remote_public_key[32..]
            .try_into()
            .map_err(|_| LinkSessionError::ProofInvalid("invalid public-key length".into()))?;
        let verify_key = Ed25519PublicKey::from_bytes(&peer_signing_key)
            .map_err(|error| LinkSessionError::ProofInvalid(error.to_string()))?;
        let rtt_data = link
            .validate_proof(&proof, &verify_key, &peer_signing_key)
            .map_err(|error| LinkSessionError::ProofInvalid(format!("{error:?}")))?;

        send_raw(
            &transport_tx,
            link_id,
            build_data_packet(link_id, rns_wire::context::PacketContext::Lrrtt, &rtt_data),
        )
        .await?;

        if config.identify {
            // Let the responder activate the Link before LINKIDENTIFY arrives.
            // This mirrors the timing used by the long-lived rnsh client.
            let identify_delay =
                Duration::from_secs_f64((link.rtt_secs() * 1.1 + 0.05).clamp(0.25, 1.0));
            tokio::time::sleep(identify_delay).await;
            let public_key = identity.get_public_key();
            let identify_data = link
                .identify_with_fallible(&public_key, |message| identity.sign(message))
                .map_err(|_| LinkSessionError::IdentificationUnavailable)?;
            send_raw(
                &transport_tx,
                link_id,
                build_data_packet(
                    link_id,
                    rns_wire::context::PacketContext::LinkIdentify,
                    &identify_data,
                ),
            )
            .await?;
            // Avoid racing the first application packet ahead of identification
            // on high-latency transports.
            tokio::time::sleep(identify_delay).await;
        }

        let (command_tx, command_rx) = mpsc::channel(COMMAND_BUFFER);
        let (event_tx, events) = mpsc::channel(EVENT_BUFFER);
        let handle = LinkSessionHandle {
            link_id,
            mdu: link.mdu,
            command_tx,
        };
        tokio::spawn(run_session_actor(
            transport_tx,
            identity,
            link,
            delivery_rx,
            command_rx,
            event_tx,
        ));
        registration.disarm();

        Ok(Self { handle, events })
    }
}

pub async fn discover_destination(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
    timeout: Duration,
) -> Result<AnnounceRpcEntry, LinkSessionError> {
    if let Some(entry) = lookup_destination(transport_tx, destination_hash).await? {
        if entry.public_key.is_some() {
            return Ok(entry);
        }
    }

    rns_transport::await_path::await_path(transport_tx, destination_hash, timeout)
        .await
        .map_err(|_| LinkSessionError::Timeout("destination path"))?;
    let entry = lookup_destination(transport_tx, destination_hash)
        .await?
        .ok_or(LinkSessionError::PublicKeyUnavailable)?;
    if entry.public_key.is_none() {
        return Err(LinkSessionError::PublicKeyUnavailable);
    }
    Ok(entry)
}

pub async fn lookup_destination(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
) -> Result<Option<AnnounceRpcEntry>, LinkSessionError> {
    let (response_tx, response_rx) = oneshot::channel();
    transport_tx
        .send(TransportMessage::Rpc {
            query: TransportQuery::GetRecentAnnounces,
            response_tx,
        })
        .await
        .map_err(|_| LinkSessionError::TransportUnavailable)?;
    let response = response_rx
        .await
        .map_err(|_| LinkSessionError::TransportUnavailable)?;
    let TransportQueryResponse::Announces(entries) = response else {
        return Ok(None);
    };
    Ok(entries
        .into_iter()
        .find(|entry| entry.dest_hash == destination_hash))
}

async fn run_session_actor(
    transport_tx: mpsc::Sender<TransportMessage>,
    identity: Identity,
    mut link: Link,
    mut delivery_rx: mpsc::Receiver<DestinationEvent>,
    mut command_rx: mpsc::Receiver<LinkSessionCommand>,
    event_tx: mpsc::Sender<LinkSessionEvent>,
) {
    let link_id = link.link_id;
    let mut pending_packets = HashSet::<[u8; 32]>::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let close_reason = loop {
        tokio::select! {
            command = command_rx.recv() => {
                match command {
                    Some(LinkSessionCommand::SendPacket { payload, result_tx }) => {
                        let result = send_application_packet(
                            &transport_tx,
                            &mut link,
                            &mut pending_packets,
                            payload,
                        ).await;
                        let transport_failed = matches!(result, Err(LinkSessionError::TransportUnavailable));
                        let _ = result_tx.send(result);
                        if transport_failed {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    Some(LinkSessionCommand::Close) | None => {
                        send_local_teardown(&transport_tx, &mut link).await;
                        break LinkSessionCloseReason::Local;
                    }
                }
            }
            event = delivery_rx.recv() => {
                let Some(event) = event else {
                    break LinkSessionCloseReason::TransportUnavailable;
                };
                match process_destination_event(
                    &transport_tx,
                    &identity,
                    &mut link,
                    &mut pending_packets,
                    &event_tx,
                    event,
                ).await {
                    Ok(Some(reason)) => break reason,
                    Ok(None) => {}
                    Err(_) => break LinkSessionCloseReason::TransportUnavailable,
                }
            }
            _ = ticker.tick() => {
                match link.tick() {
                    LinkAction::SendKeepalive => {
                        if send_keepalive(&transport_tx, &mut link).await.is_err() {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    LinkAction::TransitionedToStale => {
                        let _ = event_tx.send(LinkSessionEvent::Stale).await;
                        if send_keepalive(&transport_tx, &mut link).await.is_err() {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    LinkAction::SendTeardownAndClose(data) => {
                        let _ = send_raw(
                            &transport_tx,
                            link_id,
                            build_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &data),
                        ).await;
                        break LinkSessionCloseReason::Timeout;
                    }
                    LinkAction::Closed(_) => break LinkSessionCloseReason::Timeout,
                    LinkAction::None => {}
                }
            }
        }
    };

    deregister_destination(&transport_tx, link_id);
    let _ = event_tx
        .send(LinkSessionEvent::Closed {
            reason: close_reason,
        })
        .await;
}

async fn send_application_packet(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link: &mut Link,
    pending_packets: &mut HashSet<[u8; 32]>,
    payload: Vec<u8>,
) -> Result<LinkSessionPacketReceipt, LinkSessionError> {
    // STALE is a recoverable Link state, not a closed transport. Application
    // traffic such as a peer heartbeat reply must still be allowed through:
    // the reply may be the packet that lets the remote side recover the Link.
    if !matches!(link.state, LinkState::Active | LinkState::Stale) {
        return Err(LinkSessionError::LinkNotActive);
    }
    if payload.len() > link.mdu {
        return Err(LinkSessionError::PayloadTooLarge {
            actual: payload.len(),
            max: link.mdu,
        });
    }
    let encrypted = link
        .encrypt(&payload)
        .map_err(|_| LinkSessionError::LinkCrypto)?;
    let raw = build_data_packet(
        link.link_id,
        rns_wire::context::PacketContext::None,
        &encrypted,
    );
    let packet_hash = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
    send_raw(transport_tx, link.link_id, raw).await?;
    link.record_tx(encrypted.len());
    pending_packets.insert(packet_hash);
    Ok(LinkSessionPacketReceipt {
        link_id: link.link_id,
        packet_hash,
    })
}

async fn process_destination_event(
    transport_tx: &mpsc::Sender<TransportMessage>,
    identity: &Identity,
    link: &mut Link,
    pending_packets: &mut HashSet<[u8; 32]>,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    event: DestinationEvent,
) -> Result<Option<LinkSessionCloseReason>, LinkSessionError> {
    match event {
        DestinationEvent::LinkClosed { link_id } if link_id == link.link_id => {
            return Ok(Some(LinkSessionCloseReason::Remote));
        }
        DestinationEvent::InboundPacket { raw, .. } => {
            let Ok((header, data_offset)) = rns_wire::header::PacketHeader::unpack(&raw) else {
                return Ok(None);
            };
            if header.destination_hash != link.link_id || raw.len() < data_offset {
                return Ok(None);
            }
            let body = &raw[data_offset..];

            if header.flags.packet_type == rns_wire::flags::PacketType::Proof
                && matches!(
                    header.context,
                    rns_wire::context::PacketContext::None
                        | rns_wire::context::PacketContext::LinkProof
                )
            {
                if body.len() >= 32 {
                    let mut packet_hash = [0u8; 32];
                    packet_hash.copy_from_slice(&body[..32]);
                    if pending_packets.contains(&packet_hash)
                        && link.validate_packet_proof(&packet_hash, body)
                    {
                        pending_packets.remove(&packet_hash);
                        let _ = event_tx
                            .send(LinkSessionEvent::PacketDelivered { packet_hash })
                            .await;
                    }
                }
                return Ok(None);
            }

            if header.flags.packet_type != rns_wire::flags::PacketType::Data {
                return Ok(None);
            }

            let was_stale = link.state == LinkState::Stale;
            match header.context {
                rns_wire::context::PacketContext::Keepalive => {
                    link.record_inbound();
                    link.record_rx(body.len());
                }
                rns_wire::context::PacketContext::LinkClose => {
                    link.record_rx(body.len());
                    if link.receive_teardown(body) {
                        return Ok(Some(LinkSessionCloseReason::Remote));
                    }
                }
                rns_wire::context::PacketContext::Lrrtt => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    let _ = link.update_rtt_from_packet(body);
                }
                rns_wire::context::PacketContext::None => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    let Ok(plaintext) = link.decrypt(body) else {
                        return Ok(None);
                    };
                    let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);
                    if let Ok(proof) =
                        link.prove_packet_with_fallible(&packet_hash, |hash| identity.sign(hash))
                    {
                        let proof_raw = build_proof_packet(
                            link.link_id,
                            rns_wire::context::PacketContext::LinkProof,
                            &proof,
                        );
                        send_raw(transport_tx, link.link_id, proof_raw).await?;
                        link.record_tx(proof.len());
                    }
                    event_tx
                        .send(LinkSessionEvent::Packet {
                            data: plaintext,
                            packet_hash,
                        })
                        .await
                        .map_err(|_| LinkSessionError::SessionClosed)?;
                }
                _ => {}
            }
            if was_stale && link.state == LinkState::Active {
                let _ = event_tx.send(LinkSessionEvent::Recovered).await;
            }
        }
        _ => {}
    }
    Ok(None)
}

async fn wait_for_link_proof(
    delivery_rx: &mut mpsc::Receiver<DestinationEvent>,
    link_id: [u8; 16],
) -> Result<Vec<u8>, LinkSessionError> {
    while let Some(event) = delivery_rx.recv().await {
        match event {
            DestinationEvent::LinkClosed { link_id: closed } if closed == link_id => {
                return Err(LinkSessionError::HandshakeFailed("Link closed".into()));
            }
            DestinationEvent::InboundPacket { raw, .. } => {
                let Ok((header, data_offset)) = rns_wire::header::PacketHeader::unpack(&raw) else {
                    continue;
                };
                if header.destination_hash == link_id
                    && header.flags.packet_type == rns_wire::flags::PacketType::Proof
                    && raw.len() > data_offset
                {
                    return Ok(raw[data_offset..].to_vec());
                }
            }
            _ => {}
        }
    }
    Err(LinkSessionError::HandshakeFailed(
        "destination event stream closed".into(),
    ))
}

async fn send_keepalive(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link: &mut Link,
) -> Result<(), LinkSessionError> {
    let raw = build_data_packet(
        link.link_id,
        rns_wire::context::PacketContext::Keepalive,
        &[rns_link::constants::KEEPALIVE_REQUEST],
    );
    send_raw(transport_tx, link.link_id, raw).await?;
    link.record_tx_keepalive(1);
    Ok(())
}

async fn send_local_teardown(transport_tx: &mpsc::Sender<TransportMessage>, link: &mut Link) {
    let link_id = link.link_id;
    let Some(data) = link.teardown(CloseReason::InitiatorClosed) else {
        return;
    };
    let _ = send_raw(
        transport_tx,
        link_id,
        build_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &data),
    )
    .await;
}

async fn send_raw(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
    raw: Bytes,
) -> Result<(), LinkSessionError> {
    transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw,
            destination_hash,
        }))
        .await
        .map_err(|_| LinkSessionError::TransportUnavailable)
}

fn deregister_destination(transport_tx: &mpsc::Sender<TransportMessage>, link_id: [u8; 16]) {
    let message = TransportMessage::DeregisterDestination { hash: link_id };
    match transport_tx.try_send(message) {
        Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
        Err(mpsc::error::TrySendError::Full(message)) => {
            // Cleanup must not be lost merely because the transport actor is
            // momentarily busy. Handshake guards can call this from Drop, so
            // enqueue asynchronously instead of blocking the current task.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let transport_tx = transport_tx.clone();
                runtime.spawn(async move {
                    let _ = transport_tx.send(message).await;
                });
            }
        }
    }
}

fn build_link_request_packet(destination_hash: [u8; 16], request_data: &[u8]) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::LinkRequest,
        },
        hops: 0,
        transport_id: None,
        destination_hash,
        context: rns_wire::context::PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(request_data);
    Bytes::from(raw)
}

fn build_data_packet(
    link_id: [u8; 16],
    context: rns_wire::context::PacketContext,
    body: &[u8],
) -> Bytes {
    build_packet(link_id, rns_wire::flags::PacketType::Data, context, body)
}

fn build_proof_packet(
    link_id: [u8; 16],
    context: rns_wire::context::PacketContext,
    body: &[u8],
) -> Bytes {
    build_packet(link_id, rns_wire::flags::PacketType::Proof, context, body)
}

fn build_packet(
    link_id: [u8; 16],
    packet_type: rns_wire::flags::PacketType,
    context: rns_wire::context::PacketContext,
    body: &[u8],
) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type,
        },
        hops: 0,
        transport_id: None,
        destination_hash: link_id,
        context,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(body);
    Bytes::from(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::ed25519::Ed25519PrivateKey;

    #[test]
    fn application_packets_use_link_destination_and_none_context() {
        let link_id = [0xAB; 16];
        let packet = build_data_packet(link_id, rns_wire::context::PacketContext::None, &[1, 2, 3]);
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&packet).unwrap();
        assert_eq!(header.destination_hash, link_id);
        assert_eq!(
            header.flags.destination_type,
            rns_wire::flags::DestinationType::Link
        );
        assert_eq!(header.flags.packet_type, rns_wire::flags::PacketType::Data);
        assert_eq!(header.context, rns_wire::context::PacketContext::None);
        assert_eq!(&packet[offset..], &[1, 2, 3]);
    }

    #[tokio::test]
    async fn application_packets_can_answer_while_link_is_stale() {
        let destination_hash = [0xBC; 16];
        let server_signing = Ed25519PrivateKey::generate();
        let server_public = server_signing.public_key();
        let (mut initiator, request_data) = Link::new_initiator(destination_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &server_signing, destination_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &server_public, &server_public.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();
        initiator.state = LinkState::Stale;

        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let mut pending_packets = HashSet::new();
        let receipt = send_application_packet(
            &transport_tx,
            &mut initiator,
            &mut pending_packets,
            b"pong".to_vec(),
        )
        .await
        .expect("a stale Link must still be able to answer its peer");

        let sent = match transport_rx.recv().await.unwrap() {
            TransportMessage::Outbound(request) => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&sent.raw).unwrap();
        assert_eq!(header.destination_hash, initiator.link_id);
        assert_eq!(responder.decrypt(&sent.raw[offset..]).unwrap(), b"pong");
        assert_eq!(
            receipt.packet_hash,
            rns_wire::hash::packet_hash(&sent.raw, header.flags.header_type)
        );
    }

    #[tokio::test]
    async fn cancelled_handshake_deregisters_temporary_link_destination() {
        let destination_hash = [0x33; 16];
        let remote_identity = Identity::new();
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(8);

        let connect = tokio::spawn(LinkSession::connect(
            transport_tx,
            Identity::new(),
            LinkSessionConfig {
                destination_hash,
                remote_public_key: remote_identity.get_public_key(),
                hops: 1,
                establishment_timeout: Duration::from_secs(30),
                client_label: "test.cancelled-link-session".into(),
                identify: false,
            },
        ));

        let link_id = match transport_rx.recv().await.unwrap() {
            TransportMessage::RegisterDestination { hash, .. } => hash,
            other => panic!("unexpected transport message: {other:?}"),
        };
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::Outbound(_))
        ));

        connect.abort();
        assert!(matches!(connect.await, Err(error) if error.is_cancelled()));
        match tokio::time::timeout(Duration::from_secs(1), transport_rx.recv())
            .await
            .expect("deregistration timeout")
            .expect("transport channel closed")
        {
            TransportMessage::DeregisterDestination { hash } => assert_eq!(hash, link_id),
            other => panic!("unexpected transport message: {other:?}"),
        }
    }

    #[tokio::test]
    async fn persistent_session_identifies_and_exchanges_link_packets() {
        let destination_hash = [0x44; 16];
        let server_identity = Identity::new();
        let server_public = server_identity.get_public_key();
        let server_signing = server_identity.get_signing_key().unwrap();
        let client_identity = Identity::new();
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(64);

        let connect = tokio::spawn(LinkSession::connect(
            transport_tx.clone(),
            client_identity.clone(),
            LinkSessionConfig {
                destination_hash,
                remote_public_key: server_public,
                hops: 1,
                establishment_timeout: Duration::from_secs(2),
                client_label: "test.link-session".into(),
                identify: true,
            },
        ));

        let delivery_tx = match transport_rx.recv().await.unwrap() {
            TransportMessage::RegisterDestination {
                hash,
                delivery_tx: Some(tx),
                ..
            } => {
                assert_ne!(hash, destination_hash);
                tx
            }
            other => panic!("unexpected transport message: {other:?}"),
        };

        let request = match transport_rx.recv().await.unwrap() {
            TransportMessage::Outbound(request) => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (request_header, request_offset) =
            rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            request_header.flags.packet_type,
            rns_wire::flags::PacketType::LinkRequest
        );
        let (mut responder, proof) = Link::new_responder(
            &request.raw[request_offset..],
            &server_signing,
            destination_hash,
            1,
        )
        .unwrap();
        let proof_packet = build_proof_packet(
            responder.link_id,
            rns_wire::context::PacketContext::None,
            &proof,
        );
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: proof_packet,
                interface_id: 1,
            })
            .await
            .unwrap();

        let rtt = match transport_rx.recv().await.unwrap() {
            TransportMessage::Outbound(request) => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (rtt_header, rtt_offset) = rns_wire::header::PacketHeader::unpack(&rtt.raw).unwrap();
        assert_eq!(rtt_header.context, rns_wire::context::PacketContext::Lrrtt);
        responder
            .receive_rtt_packet(&rtt.raw[rtt_offset..])
            .unwrap();

        let identify = match transport_rx.recv().await.unwrap() {
            TransportMessage::Outbound(request) => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (identify_header, identify_offset) =
            rns_wire::header::PacketHeader::unpack(&identify.raw).unwrap();
        assert_eq!(
            identify_header.context,
            rns_wire::context::PacketContext::LinkIdentify
        );
        let identified = responder
            .handle_identification(&identify.raw[identify_offset..])
            .unwrap();
        assert_eq!(identified, client_identity.get_public_key());

        let mut session = connect.await.unwrap().unwrap();
        let receipt = session
            .handle
            .send_packet(b"hello hub".to_vec())
            .await
            .unwrap();
        let sent = match transport_rx.recv().await.unwrap() {
            TransportMessage::Outbound(request) => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (sent_header, sent_offset) = rns_wire::header::PacketHeader::unpack(&sent.raw).unwrap();
        assert_eq!(sent_header.context, rns_wire::context::PacketContext::None);
        assert_eq!(
            responder.decrypt(&sent.raw[sent_offset..]).unwrap(),
            b"hello hub"
        );
        assert_eq!(
            receipt.packet_hash,
            rns_wire::hash::packet_hash(&sent.raw, sent_header.flags.header_type)
        );

        let inbound_ciphertext = responder.encrypt(b"hello client").unwrap();
        let inbound = build_data_packet(
            responder.link_id,
            rns_wire::context::PacketContext::None,
            &inbound_ciphertext,
        );
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: inbound,
                interface_id: 1,
            })
            .await
            .unwrap();
        let event = session.events.recv().await.unwrap();
        assert!(matches!(
            event,
            LinkSessionEvent::Packet { ref data, .. } if data == b"hello client"
        ));
        let proof = match transport_rx.recv().await.unwrap() {
            TransportMessage::Outbound(request) => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (proof_header, _) = rns_wire::header::PacketHeader::unpack(&proof.raw).unwrap();
        assert_eq!(
            proof_header.flags.packet_type,
            rns_wire::flags::PacketType::Proof
        );
        assert_eq!(
            proof_header.context,
            rns_wire::context::PacketContext::LinkProof
        );

        session.handle.close().await;
        let close = match transport_rx.recv().await.unwrap() {
            TransportMessage::Outbound(request) => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (close_header, close_offset) =
            rns_wire::header::PacketHeader::unpack(&close.raw).unwrap();
        assert_eq!(
            close_header.context,
            rns_wire::context::PacketContext::LinkClose
        );
        assert!(responder.receive_teardown(&close.raw[close_offset..]));
        assert_eq!(
            session.events.recv().await,
            Some(LinkSessionEvent::Closed {
                reason: LinkSessionCloseReason::Local
            })
        );
    }
}
