//! Initiator-side Link client for `rnstatus -R` / `rnpath -R`. Each `query`
//! does the full handshake (pubkey discovery → link → identify → request →
//! response → close) over its own destination channel.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::timeout;

use rns_crypto::ed25519::Ed25519PublicKey;
use rns_identity::destination::Destination;
use rns_identity::identity::Identity;
use rns_link::link::{CloseReason, Link};
use rns_protocol::resource::{InboundTransfer, TransferAction};
use rns_protocol::resource_adv::ResourceAdvertisement;
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{
    InterfaceId, LinkEndpointLifecycleEvent, LinkEndpointRole, OutboundRequest, TransportMessage,
};

use crate::destination_resolver::{
    DestinationResolveError, DestinationResolveOptions, resolve_destination_on_transport,
};

#[derive(Debug, thiserror::Error)]
pub enum LinkClientError {
    #[error("transport channel closed or full")]
    TransportUnavailable,
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    #[error("could not discover remote identity public key for destination")]
    PubkeyNotDiscovered,
    #[error("link proof validation failed: {0}")]
    ProofInvalid(String),
    #[error("link establishment failed: {0}")]
    HandshakeFailed(String),
    #[error("local identity has no signing key (cannot identify on link)")]
    NoSigningKey,
    #[error("encryption failure on link: {0}")]
    LinkCrypto(String),
    #[error("unexpected response from remote: {0}")]
    UnexpectedResponse(String),
}

#[derive(Clone)]
pub struct LinkClient {
    transport_tx: mpsc::Sender<TransportMessage>,
    identity: Arc<Identity>,
}

struct LinkClientEndpoint<'a> {
    delivery_rx: &'a mut mpsc::Receiver<DestinationEvent>,
    lifecycle_rx: &'a mut mpsc::UnboundedReceiver<LinkEndpointLifecycleEvent>,
    attached_interface: InterfaceId,
}

impl LinkClient {
    pub fn new(transport_tx: mpsc::Sender<TransportMessage>, identity: Identity) -> Self {
        Self {
            transport_tx,
            identity: Arc::new(identity),
        }
    }

    /// Open a Link to `app_name` on `remote_transport_hash`, send one
    /// request, return the response.
    pub async fn query(
        &self,
        remote_transport_hash: [u8; 16],
        app_name: &str,
        path: &str,
        payload: Vec<u8>,
        hops: u8,
        overall_timeout: Duration,
    ) -> Result<Vec<u8>, LinkClientError> {
        let started = Instant::now();
        let deadline = started + overall_timeout;

        let dest_hash =
            Destination::hash_from_name_and_identity(app_name, Some(&remote_transport_hash));

        let pubkey = resolve_destination_on_transport(
            &self.transport_tx,
            dest_hash,
            DestinationResolveOptions::new(time_remaining(deadline)?),
        )
        .await
        .map_err(map_destination_resolve_error)?
        .public_key;

        let (mut link, request_data) = Link::new_initiator(dest_hash, hops);
        let link_id = link.link_id;

        // Register link_id as a destination so inbound LRPROOF / Response
        // packets route back to this task via dest_rx.
        let (dest_tx, mut dest_rx) = mpsc::channel::<DestinationEvent>(128);
        self.send_msg(TransportMessage::RegisterDestination {
            hash: link_id,
            app_name: "rnstatus.linkclient".to_string(),
            delivery_tx: Some(dest_tx),
        })
        .await?;
        let mut registration = crate::link_endpoint::LinkEndpointCleanupGuard::new(
            self.transport_tx.clone(),
            link_id,
            LinkEndpointRole::Initiator,
        );

        let req_pkt = build_link_request_packet(dest_hash, &request_data);
        self.send_msg(TransportMessage::Outbound(OutboundRequest {
            raw: req_pkt,
            destination_hash: dest_hash,
        }))
        .await?;

        let identity_ed25519_pub: [u8; 32] = pubkey[32..64].try_into().map_err(|_| {
            LinkClientError::ProofInvalid("remote public key is not 64 bytes".into())
        })?;
        let identity_verify_key = Ed25519PublicKey::from_bytes(&identity_ed25519_pub)
            .map_err(|e| LinkClientError::ProofInvalid(format!("verify key: {e}")))?;
        let proof = timeout(
            time_remaining(deadline)?,
            crate::link_endpoint::wait_for_valid_proof(
                &mut dest_rx,
                &mut link,
                &identity_verify_key,
                &identity_ed25519_pub,
            ),
        )
        .await
        .map_err(|_| LinkClientError::Timeout("link proof"))?
        .map_err(|error| match error {
            crate::link_endpoint::LinkProofWaitError::LinkClosed => {
                LinkClientError::HandshakeFailed("link closed".into())
            }
            crate::link_endpoint::LinkProofWaitError::DeliveryClosed => {
                LinkClientError::HandshakeFailed("destination channel closed".into())
            }
        })?;
        let attached_interface = proof.interface_id;
        let rtt_data = proof.rtt_data;

        let mut endpoint_lifecycle_rx = crate::link_endpoint::bind(
            &self.transport_tx,
            link_id,
            attached_interface,
            LinkEndpointRole::Initiator,
        )
        .await
        .map_err(|_| LinkClientError::TransportUnavailable)?;
        registration.endpoint_bound();
        let mut endpoint = LinkClientEndpoint {
            delivery_rx: &mut dest_rx,
            lifecycle_rx: &mut endpoint_lifecycle_rx,
            attached_interface,
        };

        let rtt_pkt =
            build_data_packet(link_id, rns_wire::context::PacketContext::Lrrtt, &rtt_data);
        self.send_link_packet(link_id, rtt_pkt).await?;

        let our_pub = self.identity.get_public_key();
        let our_priv = self
            .identity
            .get_signing_key()
            .ok_or(LinkClientError::NoSigningKey)?;
        let identify_data = link
            .identify(&our_pub, &our_priv)
            .map_err(|e| LinkClientError::LinkCrypto(format!("identify: {e:?}")))?;
        let identify_pkt = build_data_packet(
            link_id,
            rns_wire::context::PacketContext::LinkIdentify,
            &identify_data,
        );
        self.send_link_packet(link_id, identify_pkt).await?;

        let req_timeout = Duration::from_secs(5);
        let (encrypted_req, request_id) = link
            .request(path, Some(&payload), req_timeout)
            .map_err(|e| LinkClientError::LinkCrypto(format!("request: {e:?}")))?;
        let request_pkt = build_data_packet(
            link_id,
            rns_wire::context::PacketContext::Request,
            &encrypted_req,
        );
        let packet_request_id = rns_wire::hash::truncated_packet_hash(
            &request_pkt,
            rns_wire::flags::HeaderType::Header1,
        );
        link.update_pending_request_id(&request_id, packet_request_id);
        self.send_link_packet(link_id, request_pkt).await?;

        let response = wait_for_response(
            &self.transport_tx,
            &mut endpoint,
            &mut link,
            link_id,
            packet_request_id,
            time_remaining(deadline)?,
        )
        .await;

        // Tear down even on failure so the remote doesn't keep link state.
        let endpoint_closing = self.send_close(&mut link).await.unwrap_or(false);
        if !endpoint_closing {
            let _ = registration.cleanup().await;
        } else {
            registration.disarm();
        }

        response
    }

    async fn send_msg(&self, msg: TransportMessage) -> Result<(), LinkClientError> {
        self.transport_tx
            .send(msg)
            .await
            .map_err(|_| LinkClientError::TransportUnavailable)
    }

    async fn send_link_packet(&self, link_id: [u8; 16], raw: Bytes) -> Result<(), LinkClientError> {
        crate::link_endpoint::send(
            &self.transport_tx,
            link_id,
            LinkEndpointRole::Initiator,
            raw,
        )
        .await
        .map_err(|_| LinkClientError::TransportUnavailable)
    }

    async fn send_close(&self, link: &mut Link) -> Result<bool, LinkClientError> {
        let link_id = link.link_id;
        let Some(teardown_data) = link.teardown(CloseReason::InitiatorClosed) else {
            return Ok(false);
        };
        let close_pkt = build_data_packet(
            link_id,
            rns_wire::context::PacketContext::LinkClose,
            &teardown_data,
        );
        crate::link_endpoint::send_and_unbind(
            &self.transport_tx,
            link_id,
            LinkEndpointRole::Initiator,
            close_pkt,
        )
        .await
        .map(|()| true)
        .map_err(|_| LinkClientError::TransportUnavailable)
    }
}

fn time_remaining(deadline: Instant) -> Result<Duration, LinkClientError> {
    let now = Instant::now();
    if now >= deadline {
        Err(LinkClientError::Timeout("overall query"))
    } else {
        Ok(deadline - now)
    }
}

fn map_destination_resolve_error(error: DestinationResolveError) -> LinkClientError {
    match error {
        DestinationResolveError::Timeout => LinkClientError::Timeout("destination resolution"),
        DestinationResolveError::TransportUnavailable => LinkClientError::TransportUnavailable,
        DestinationResolveError::UnexpectedResponse(operation) => {
            LinkClientError::UnexpectedResponse(operation.to_string())
        }
    }
}

async fn wait_for_response(
    transport_tx: &mpsc::Sender<TransportMessage>,
    endpoint: &mut LinkClientEndpoint<'_>,
    link: &mut Link,
    link_id: [u8; 16],
    request_id: [u8; 16],
    deadline: Duration,
) -> Result<Vec<u8>, LinkClientError> {
    let fut = async {
        let mut inbound_resources: HashMap<[u8; 32], InboundTransfer> = HashMap::new();

        loop {
            let ev = tokio::select! {
                event = endpoint.delivery_rx.recv() => event.ok_or_else(|| LinkClientError::HandshakeFailed(
                    "destination channel closed".into(),
                ))?,
                terminal = endpoint.lifecycle_rx.recv() => {
                    return Err(LinkClientError::HandshakeFailed(format!(
                        "link endpoint terminated: {terminal:?}"
                    )));
                }
            };
            match ev {
                DestinationEvent::LinkClosed { link_id: closed_id } if closed_id == link_id => {
                    return Err(LinkClientError::HandshakeFailed("link closed".into()));
                }
                DestinationEvent::InboundPacket {
                    raw, interface_id, ..
                } => {
                    if interface_id != endpoint.attached_interface {
                        continue;
                    }
                    let (header, data_offset) = match rns_wire::header::PacketHeader::unpack(&raw) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };
                    if header.destination_hash != link_id {
                        continue;
                    }
                    let body = &raw[data_offset..];
                    match header.context {
                        rns_wire::context::PacketContext::Response => {
                            match link.handle_response(body) {
                                Ok((id, response_data)) => {
                                    if id == request_id {
                                        return Ok(response_data);
                                    }
                                }
                                Err(e) => {
                                    return Err(LinkClientError::LinkCrypto(format!(
                                        "response decrypt: {e:?}"
                                    )));
                                }
                            }
                        }
                        rns_wire::context::PacketContext::ResourceAdv => {
                            let plaintext = link.decrypt(body).map_err(|e| {
                                LinkClientError::LinkCrypto(format!(
                                    "resource advertisement decrypt: {e:?}"
                                ))
                            })?;
                            let adv = ResourceAdvertisement::unpack(&plaintext).map_err(|e| {
                                LinkClientError::UnexpectedResponse(format!(
                                    "resource advertisement: {e}"
                                ))
                            })?;

                            if !adv.flags.is_response
                                || adv.request_id.as_deref() != Some(request_id.as_slice())
                            {
                                continue;
                            }

                            let mut random_hash = [0u8; rns_protocol::resource::RANDOM_HASH_SIZE];
                            let copy_len = adv.random_hash.len().min(random_hash.len());
                            random_hash[..copy_len].copy_from_slice(&adv.random_hash[..copy_len]);

                            let rtt = link.rtt.unwrap_or(Duration::from_millis(500));
                            let mut transfer = InboundTransfer::from_advertisement(
                                adv.num_parts,
                                adv.transfer_size,
                                adv.data_size,
                                random_hash,
                                adv.resource_hash,
                                adv.flags,
                                adv.get_map_hashes(),
                                rtt,
                            )
                            .map_err(|e| {
                                LinkClientError::UnexpectedResponse(format!(
                                    "resource transfer: {e:?}"
                                ))
                            })?;

                            if let TransferAction::SendRequest(req) = transfer.request_next() {
                                send_link_data(
                                    transport_tx,
                                    link,
                                    link_id,
                                    rns_wire::context::PacketContext::ResourceReq,
                                    &req,
                                    true,
                                )
                                .await?;
                            }

                            inbound_resources.insert(adv.resource_hash, transfer);
                        }
                        rns_wire::context::PacketContext::Resource => {
                            let mut action_to_send = None;
                            let mut completed_rh = None;

                            for (rh, transfer) in &mut inbound_resources {
                                let action = transfer.receive_part(body.to_vec());
                                match action {
                                    TransferAction::SendHmu(_) | TransferAction::SendRequest(_) => {
                                        action_to_send = Some(action);
                                    }
                                    TransferAction::Complete => {
                                        completed_rh = Some(*rh);
                                    }
                                    TransferAction::Failed(reason) => {
                                        return Err(LinkClientError::UnexpectedResponse(format!(
                                            "resource transfer failed: {reason}"
                                        )));
                                    }
                                    _ => {}
                                }

                                if completed_rh.is_none() && transfer.resource.is_complete() {
                                    completed_rh = Some(*rh);
                                }
                                if action_to_send.is_some() || completed_rh.is_some() {
                                    break;
                                }
                            }

                            if let Some(action) = action_to_send {
                                let (context, payload) = match action {
                                    TransferAction::SendHmu(hmu) => {
                                        (rns_wire::context::PacketContext::ResourceHmu, hmu)
                                    }
                                    TransferAction::SendRequest(req) => {
                                        (rns_wire::context::PacketContext::ResourceReq, req)
                                    }
                                    _ => unreachable!(),
                                };
                                send_link_data(
                                    transport_tx,
                                    link,
                                    link_id,
                                    context,
                                    &payload,
                                    true,
                                )
                                .await?;
                            }

                            if let Some(rh) = completed_rh {
                                let (assembled, proof) = {
                                    let transfer =
                                        inbound_resources.get_mut(&rh).ok_or_else(|| {
                                            LinkClientError::UnexpectedResponse(
                                                "completed resource disappeared".into(),
                                            )
                                        })?;
                                    let keys = link.session_keys().ok_or_else(|| {
                                        LinkClientError::LinkCrypto(
                                            "resource response missing link keys".into(),
                                        )
                                    })?;
                                    let decrypt_fn = move |data: &[u8]| {
                                        rns_link::encryption::link_decrypt(&keys, data).map_err(
                                            |_| {
                                                rns_protocol::resource::ResourceError::DecryptFailed
                                            },
                                        )
                                    };
                                    transfer.complete(Some(&decrypt_fn)).map_err(|e| {
                                        LinkClientError::UnexpectedResponse(format!(
                                            "resource assemble: {e:?}"
                                        ))
                                    })?
                                };

                                send_link_proof(transport_tx, link_id, &proof).await?;
                                inbound_resources.remove(&rh);
                                match link.handle_response_plaintext(&assembled) {
                                    Ok((id, response_data)) => {
                                        if id == request_id {
                                            return Ok(response_data);
                                        }
                                    }
                                    Err(e) => {
                                        return Err(LinkClientError::LinkCrypto(format!(
                                            "resource response decode: {e:?}"
                                        )));
                                    }
                                }
                            }
                        }
                        rns_wire::context::PacketContext::ResourceHmu => {
                            let plaintext = link.decrypt(body).map_err(|e| {
                                LinkClientError::LinkCrypto(format!(
                                    "resource hashmap update decrypt: {e:?}"
                                ))
                            })?;
                            let (rh, segment, hashmap) =
                                rns_protocol::resource::parse_hashmap_update(&plaintext).map_err(
                                    |e| {
                                        LinkClientError::UnexpectedResponse(format!(
                                            "resource hashmap update: {e:?}"
                                        ))
                                    },
                                )?;
                            let Some(transfer) = inbound_resources.get_mut(&rh) else {
                                continue;
                            };
                            match transfer.hashmap_update(segment, &hashmap) {
                                TransferAction::SendRequest(req) => {
                                    send_link_data(
                                        transport_tx,
                                        link,
                                        link_id,
                                        rns_wire::context::PacketContext::ResourceReq,
                                        &req,
                                        true,
                                    )
                                    .await?;
                                }
                                // Empty/invalid HMU cancels the transfer (RESOURCE_RCL, 1.3.9).
                                TransferAction::SendCancel(cancel_type, resource_hash) => {
                                    let context = match cancel_type {
                                        rns_protocol::resource::CancelType::Icl => {
                                            rns_wire::context::PacketContext::ResourceIcl
                                        }
                                        rns_protocol::resource::CancelType::Rcl => {
                                            rns_wire::context::PacketContext::ResourceRcl
                                        }
                                    };
                                    send_link_data(
                                        transport_tx,
                                        link,
                                        link_id,
                                        context,
                                        &resource_hash,
                                        true,
                                    )
                                    .await?;
                                }
                                _ => {}
                            }
                        }
                        rns_wire::context::PacketContext::LinkClose
                            if link.receive_teardown(body) =>
                        {
                            return Err(LinkClientError::HandshakeFailed(
                                "link closed by remote".into(),
                            ));
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    };
    timeout(deadline, fut)
        .await
        .map_err(|_| LinkClientError::Timeout("response"))?
}

async fn send_link_data(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link: &mut Link,
    link_id: [u8; 16],
    context: rns_wire::context::PacketContext,
    body: &[u8],
    encrypt: bool,
) -> Result<(), LinkClientError> {
    let payload = if encrypt {
        link.encrypt(body)
            .map_err(|e| LinkClientError::LinkCrypto(format!("resource control: {e:?}")))?
    } else {
        body.to_vec()
    };
    let packet = build_data_packet(link_id, context, &payload);
    crate::link_endpoint::send(transport_tx, link_id, LinkEndpointRole::Initiator, packet)
        .await
        .map_err(|_| LinkClientError::TransportUnavailable)
}

async fn send_link_proof(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    proof: &[u8],
) -> Result<(), LinkClientError> {
    let packet = build_proof_packet(
        link_id,
        rns_wire::context::PacketContext::ResourcePrf,
        proof,
    );
    crate::link_endpoint::send(transport_tx, link_id, LinkEndpointRole::Initiator, packet)
        .await
        .map_err(|_| LinkClientError::TransportUnavailable)
}

fn build_link_request_packet(dest_hash: [u8; 16], request_data: &[u8]) -> Bytes {
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
        destination_hash: dest_hash,
        context: rns_wire::context::PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(request_data);
    Bytes::from(raw)
}

fn build_proof_packet(
    link_id: [u8; 16],
    context: rns_wire::context::PacketContext,
    body: &[u8],
) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Proof,
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

fn build_data_packet(
    link_id: [u8; 16],
    context: rns_wire::context::PacketContext,
    body: &[u8],
) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Data,
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

    #[test]
    fn build_link_request_packet_has_link_request_type() {
        let pkt = build_link_request_packet([0xAA; 16], &[0x01, 0x02, 0x03]);
        let (header, _) = rns_wire::header::PacketHeader::unpack(&pkt).unwrap();
        assert_eq!(
            header.flags.packet_type,
            rns_wire::flags::PacketType::LinkRequest
        );
        assert_eq!(header.destination_hash, [0xAA; 16]);
    }

    #[test]
    fn build_data_packet_carries_context() {
        let pkt = build_data_packet([0xBB; 16], rns_wire::context::PacketContext::Lrrtt, &[0x42]);
        let (header, _) = rns_wire::header::PacketHeader::unpack(&pkt).unwrap();
        assert_eq!(header.context, rns_wire::context::PacketContext::Lrrtt);
        assert_eq!(header.flags.packet_type, rns_wire::flags::PacketType::Data);
    }

    #[tokio::test]
    async fn time_remaining_returns_err_after_deadline() {
        let past = Instant::now();
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(matches!(
            time_remaining(past),
            Err(LinkClientError::Timeout(_))
        ));
    }

    #[tokio::test]
    async fn send_close_uses_authenticated_teardown_payload() {
        let dest_hash = [0xCC; 16];
        let responder_key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let responder_pub = responder_key.public_key();
        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &responder_key, dest_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &responder_pub, &responder_pub.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();

        let (transport_tx, mut transport_rx) = mpsc::channel(4);
        let client = LinkClient::new(transport_tx, Identity::new());
        let close = tokio::spawn(async move { client.send_close(&mut initiator).await });

        let TransportMessage::SendLinkEndpointAndUnbind {
            role,
            request,
            result_tx,
            ..
        } = transport_rx.recv().await.unwrap()
        else {
            panic!("expected outbound close packet");
        };
        assert_eq!(role, LinkEndpointRole::Initiator);
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(header.context, rns_wire::context::PacketContext::LinkClose);
        assert!(responder.receive_teardown(&request.raw[offset..]));
        let _ = result_tx.send(rns_transport::messages::LinkEndpointSendResult::Sent);
        assert!(close.await.unwrap().unwrap());
    }
}
