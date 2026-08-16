use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use rns_crypto::ed25519::Ed25519PublicKey;
use rns_link::link::Link;
use rns_transport::link_messages::{DestinationEvent, PacketMetrics};
use rns_transport::messages::{
    InterfaceId, LinkEndpointBindResult, LinkEndpointBinding, LinkEndpointLifecycleEvent,
    LinkEndpointRole, LinkEndpointSendResult, LinkEndpointUnbindResult, OutboundRequest,
    TransportMessage,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum LinkEndpointError {
    #[error("transport channel is unavailable")]
    TransportUnavailable,
    #[error("Link endpoint could not be bound: {0:?}")]
    Bind(LinkEndpointBindResult),
    #[error("Link endpoint rejected outbound packet: {0:?}")]
    Send(LinkEndpointSendResult),
    #[error("Link endpoint cleanup was rejected: {0:?}")]
    Unbind(LinkEndpointUnbindResult),
}

/// Owns cleanup for a temporary initiator Link destination until ownership is
/// transferred to a long-lived actor or an atomic final send succeeds.
///
/// Cancellation cannot use `try_send`: a full transport ingress queue is a
/// normal transient condition. Drop therefore transfers cleanup to a retained
/// task which waits for admission, verifies typed endpoint ownership, and only
/// then deregisters the temporary destination.
pub(crate) struct LinkEndpointCleanupGuard {
    transport_tx: mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    role: LinkEndpointRole,
    endpoint_bound: bool,
    armed: bool,
}

impl LinkEndpointCleanupGuard {
    pub(crate) fn new(
        transport_tx: mpsc::Sender<TransportMessage>,
        link_id: [u8; 16],
        role: LinkEndpointRole,
    ) -> Self {
        Self {
            transport_tx,
            link_id,
            role,
            endpoint_bound: false,
            armed: true,
        }
    }

    pub(crate) fn endpoint_bound(&mut self) {
        self.endpoint_bound = true;
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    pub(crate) async fn cleanup(&mut self) -> Result<(), LinkEndpointError> {
        cleanup_registered_link(
            &self.transport_tx,
            self.link_id,
            self.role,
            self.endpoint_bound,
        )
        .await?;
        self.endpoint_bound = false;
        self.armed = false;
        Ok(())
    }
}

impl Drop for LinkEndpointCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let transport_tx = self.transport_tx.clone();
        let link_id = self.link_id;
        let role = self.role;
        let endpoint_bound = self.endpoint_bound;
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::error!(
                link_id = %hex::encode(link_id),
                role = ?role,
                "cannot retain Link endpoint cleanup without a Tokio runtime"
            );
            return;
        };
        runtime.spawn(async move {
            if let Err(error) =
                cleanup_registered_link(&transport_tx, link_id, role, endpoint_bound).await
            {
                tracing::error!(
                    link_id = %hex::encode(link_id),
                    role = ?role,
                    error = %error,
                    "retained Link endpoint cleanup failed"
                );
            }
        });
    }
}

pub(crate) struct PendingLinkEndpointSend {
    pub(crate) link_id: [u8; 16],
    pub(crate) role: LinkEndpointRole,
    pub(crate) final_unbind: bool,
    pub(crate) result_rx: oneshot::Receiver<LinkEndpointSendResult>,
}

struct AtomicFinalSendGuard {
    transport_tx: mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    role: LinkEndpointRole,
    result_rx: Option<oneshot::Receiver<LinkEndpointSendResult>>,
}

impl AtomicFinalSendGuard {
    async fn result(&mut self) -> Result<LinkEndpointSendResult, LinkEndpointError> {
        let result = self
            .result_rx
            .as_mut()
            .expect("atomic final-send result receiver")
            .await;
        self.result_rx = None;
        result.map_err(|_| LinkEndpointError::TransportUnavailable)
    }
}

impl Drop for AtomicFinalSendGuard {
    fn drop(&mut self) {
        let Some(result_rx) = self.result_rx.take() else {
            return;
        };
        let transport_tx = self.transport_tx.clone();
        let link_id = self.link_id;
        let role = self.role;
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::error!(
                link_id = %hex::encode(link_id),
                role = ?role,
                "cannot retain atomic Link close result without a Tokio runtime"
            );
            return;
        };
        runtime.spawn(async move {
            match result_rx.await {
                Ok(LinkEndpointSendResult::Sent | LinkEndpointSendResult::Queued { .. }) => {}
                Ok(_) | Err(_) => {
                    let _ = cleanup_registered_link(&transport_tx, link_id, role, true).await;
                }
            }
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkProofWaitError {
    LinkClosed,
    DeliveryClosed,
}

pub(crate) struct ValidatedLinkProof {
    pub(crate) rtt_data: Vec<u8>,
    pub(crate) interface_id: InterfaceId,
    pub(crate) metrics: PacketMetrics,
}

/// Wait for the first cryptographically valid LRPROOF while the Link remains
/// pending. Invalid candidates are unauthenticated input and cannot terminate
/// establishment or select the endpoint interface.
pub(crate) async fn wait_for_valid_proof(
    delivery_rx: &mut mpsc::Receiver<DestinationEvent>,
    link: &mut Link,
    identity_verify_key: &Ed25519PublicKey,
    identity_ed25519_pub_bytes: &[u8; 32],
) -> Result<ValidatedLinkProof, LinkProofWaitError> {
    let link_id = link.link_id;
    while let Some(event) = delivery_rx.recv().await {
        match event {
            DestinationEvent::LinkClosed { link_id: closed } if closed == link_id => {
                return Err(LinkProofWaitError::LinkClosed);
            }
            DestinationEvent::InboundPacket {
                raw,
                interface_id,
                metrics,
            } => {
                let Ok((header, data_offset)) = rns_wire::header::PacketHeader::unpack(&raw) else {
                    continue;
                };
                if header.destination_hash != link_id
                    || header.flags.packet_type != rns_wire::flags::PacketType::Proof
                    || raw.len() <= data_offset
                {
                    continue;
                }
                match link.validate_proof(
                    &raw[data_offset..],
                    identity_verify_key,
                    identity_ed25519_pub_bytes,
                ) {
                    Ok(rtt_data) => {
                        return Ok(ValidatedLinkProof {
                            rtt_data,
                            interface_id,
                            metrics,
                        });
                    }
                    Err(error) => {
                        tracing::debug!(
                            link_id = %hex::encode(link_id),
                            interface_id,
                            error = ?error,
                            "ignoring unauthenticated LRPROOF candidate"
                        );
                    }
                }
            }
            _ => {}
        }
    }
    Err(LinkProofWaitError::DeliveryClosed)
}

pub(crate) async fn bind(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    interface_id: InterfaceId,
    role: LinkEndpointRole,
) -> Result<mpsc::UnboundedReceiver<LinkEndpointLifecycleEvent>, LinkEndpointError> {
    let (lifecycle_tx, lifecycle_rx) = mpsc::unbounded_channel();
    let (result_tx, result_rx) = oneshot::channel();
    transport_tx
        .send(TransportMessage::BindLinkEndpoint {
            binding: LinkEndpointBinding {
                link_id,
                interface_id,
                role,
            },
            lifecycle_tx,
            result_tx,
        })
        .await
        .map_err(|_| LinkEndpointError::TransportUnavailable)?;
    match result_rx
        .await
        .map_err(|_| LinkEndpointError::TransportUnavailable)?
    {
        // A successful fresh bind transfers this lifecycle sender into the
        // transport actor. `AlreadyBound` retains the original sender, so the
        // newly-created receiver would never observe terminal events and must
        // fail closed instead of pretending to own the endpoint.
        LinkEndpointBindResult::Bound => Ok(lifecycle_rx),
        result => Err(LinkEndpointError::Bind(result)),
    }
}

pub(crate) async fn send_best_effort(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    role: LinkEndpointRole,
    raw: Bytes,
) -> Result<LinkEndpointSendResult, LinkEndpointError> {
    let (result_tx, result_rx) = oneshot::channel();
    transport_tx
        .send(TransportMessage::SendLinkEndpointBestEffort {
            link_id,
            role,
            request: OutboundRequest {
                raw,
                destination_hash: link_id,
            },
            result_tx,
        })
        .await
        .map_err(|_| LinkEndpointError::TransportUnavailable)?;
    result_rx
        .await
        .map_err(|_| LinkEndpointError::TransportUnavailable)
}

pub(crate) async fn send_and_unbind(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    role: LinkEndpointRole,
    raw: Bytes,
) -> Result<(), LinkEndpointError> {
    let (result_tx, result_rx) = oneshot::channel();
    transport_tx
        .send(TransportMessage::SendLinkEndpointAndUnbind {
            link_id,
            role,
            request: OutboundRequest {
                raw,
                destination_hash: link_id,
            },
            result_tx,
        })
        .await
        .map_err(|_| LinkEndpointError::TransportUnavailable)?;
    // Once admitted, retain ownership of the typed result across caller
    // cancellation. A successful atomic operation owns the final FIFO drain;
    // a rejected one falls back to ordered explicit cleanup.
    let mut final_send = AtomicFinalSendGuard {
        transport_tx: transport_tx.clone(),
        link_id,
        role,
        result_rx: Some(result_rx),
    };
    match final_send.result().await? {
        LinkEndpointSendResult::Sent | LinkEndpointSendResult::Queued { .. } => Ok(()),
        result => Err(LinkEndpointError::Send(result)),
    }
}

pub(crate) async fn send(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    role: LinkEndpointRole,
    raw: Bytes,
) -> Result<(), LinkEndpointError> {
    let (result_tx, result_rx) = oneshot::channel();
    transport_tx
        .send(TransportMessage::SendLinkEndpoint {
            link_id,
            role,
            request: OutboundRequest {
                raw,
                destination_hash: link_id,
            },
            result_tx,
        })
        .await
        .map_err(|_| LinkEndpointError::TransportUnavailable)?;
    match result_rx
        .await
        .map_err(|_| LinkEndpointError::TransportUnavailable)?
    {
        LinkEndpointSendResult::Sent | LinkEndpointSendResult::Queued { .. } => Ok(()),
        result => Err(LinkEndpointError::Send(result)),
    }
}

pub(crate) async fn unbind(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    role: LinkEndpointRole,
) -> Result<LinkEndpointUnbindResult, LinkEndpointError> {
    let (result_tx, result_rx) = oneshot::channel();
    transport_tx
        .send(TransportMessage::UnbindLinkEndpoint {
            link_id,
            role,
            result_tx,
        })
        .await
        .map_err(|_| LinkEndpointError::TransportUnavailable)?;
    result_rx
        .await
        .map_err(|_| LinkEndpointError::TransportUnavailable)
}

async fn cleanup_registered_link(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    role: LinkEndpointRole,
    endpoint_bound: bool,
) -> Result<(), LinkEndpointError> {
    if endpoint_bound {
        match unbind(transport_tx, link_id, role).await? {
            LinkEndpointUnbindResult::Unbound | LinkEndpointUnbindResult::NotBound => {}
            result @ LinkEndpointUnbindResult::RoleMismatch => {
                return Err(LinkEndpointError::Unbind(result));
            }
        }
    }
    transport_tx
        .send(TransportMessage::DeregisterDestination { hash: link_id })
        .await
        .map_err(|_| LinkEndpointError::TransportUnavailable)
}

pub(crate) fn send_message(
    link_id: [u8; 16],
    role: LinkEndpointRole,
    raw: Bytes,
) -> (TransportMessage, PendingLinkEndpointSend) {
    let (result_tx, result_rx) = oneshot::channel();
    (
        TransportMessage::SendLinkEndpoint {
            link_id,
            role,
            request: OutboundRequest {
                raw,
                destination_hash: link_id,
            },
            result_tx,
        },
        PendingLinkEndpointSend {
            link_id,
            role,
            final_unbind: false,
            result_rx,
        },
    )
}

pub(crate) fn send_and_unbind_message(
    link_id: [u8; 16],
    role: LinkEndpointRole,
    raw: Bytes,
) -> (TransportMessage, PendingLinkEndpointSend) {
    let (result_tx, result_rx) = oneshot::channel();
    (
        TransportMessage::SendLinkEndpointAndUnbind {
            link_id,
            role,
            request: OutboundRequest {
                raw,
                destination_hash: link_id,
            },
            result_tx,
        },
        PendingLinkEndpointSend {
            link_id,
            role,
            final_unbind: true,
            result_rx,
        },
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rns_crypto::ed25519::Ed25519PrivateKey;
    use rns_link::link::{Link, LinkState};

    use super::*;

    fn proof_packet(link_id: [u8; 16], proof: &[u8]) -> Bytes {
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
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(proof);
        raw.into()
    }

    #[tokio::test]
    async fn invalid_proof_does_not_win_interface_race_before_valid_proof() {
        let destination_hash = [0xA4; 16];
        let signing_key = Ed25519PrivateKey::generate();
        let verify_key = signing_key.public_key();
        let (mut initiator, request_data) = Link::new_initiator(destination_hash, 1);
        let (_responder, proof) =
            Link::new_responder(&request_data, &signing_key, destination_hash, 1).unwrap();
        let mut invalid = proof.clone();
        invalid[0] ^= 0x80;
        let link_id = initiator.link_id;
        let (event_tx, mut event_rx) = mpsc::channel(2);
        event_tx
            .send(DestinationEvent::InboundPacket {
                raw: proof_packet(link_id, &invalid),
                interface_id: 41,
                metrics: PacketMetrics {
                    rssi: Some(-10.0),
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        event_tx
            .send(DestinationEvent::InboundPacket {
                raw: proof_packet(link_id, &proof),
                interface_id: 42,
                metrics: PacketMetrics {
                    rssi: Some(-80.0),
                    ..Default::default()
                },
            })
            .await
            .unwrap();

        let validated = wait_for_valid_proof(
            &mut event_rx,
            &mut initiator,
            &verify_key,
            &verify_key.to_bytes(),
        )
        .await
        .unwrap();
        assert_eq!(validated.interface_id, 42);
        assert_eq!(validated.metrics.rssi, Some(-80.0));
        assert!(matches!(
            initiator.state,
            LinkState::Handshake | LinkState::Active
        ));
        assert!(initiator.session_keys().is_some());
    }

    #[tokio::test]
    async fn invalid_proof_only_waits_for_original_timeout() {
        let destination_hash = [0xA5; 16];
        let signing_key = Ed25519PrivateKey::generate();
        let verify_key = signing_key.public_key();
        let (mut initiator, request_data) = Link::new_initiator(destination_hash, 1);
        let (_responder, mut proof) =
            Link::new_responder(&request_data, &signing_key, destination_hash, 1).unwrap();
        proof[0] ^= 0x80;
        let link_id = initiator.link_id;
        let (event_tx, mut event_rx) = mpsc::channel(1);
        event_tx
            .send(DestinationEvent::InboundPacket {
                raw: proof_packet(link_id, &proof),
                interface_id: 99,
                metrics: PacketMetrics::default(),
            })
            .await
            .unwrap();

        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                wait_for_valid_proof(
                    &mut event_rx,
                    &mut initiator,
                    &verify_key,
                    &verify_key.to_bytes(),
                ),
            )
            .await
            .is_err()
        );
        assert_eq!(initiator.state, LinkState::Pending);
        drop(event_tx);
    }

    #[tokio::test]
    async fn dropped_cleanup_guard_survives_transport_ingress_backpressure() {
        let link_id = [0xC1; 16];
        let (transport_tx, mut transport_rx) = mpsc::channel(1);
        transport_tx.send(TransportMessage::Shutdown).await.unwrap();

        let mut guard =
            LinkEndpointCleanupGuard::new(transport_tx, link_id, LinkEndpointRole::Initiator);
        guard.endpoint_bound();
        drop(guard);

        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::Shutdown)
        ));
        let Some(TransportMessage::UnbindLinkEndpoint {
            link_id: unbound,
            role,
            result_tx,
        }) = transport_rx.recv().await
        else {
            panic!("retained cleanup must enqueue typed unbind after capacity returns");
        };
        assert_eq!(unbound, link_id);
        assert_eq!(role, LinkEndpointRole::Initiator);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), transport_rx.recv())
                .await
                .is_err(),
            "destination deregistration must wait for the typed unbind result"
        );
        let _ = result_tx.send(LinkEndpointUnbindResult::Unbound);
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterDestination { hash }) if hash == link_id
        ));
    }

    #[tokio::test]
    async fn role_mismatch_never_deregisters_another_endpoint_owner() {
        let link_id = [0xC2; 16];
        let (transport_tx, mut transport_rx) = mpsc::channel(2);
        let cleanup = tokio::spawn(async move {
            cleanup_registered_link(&transport_tx, link_id, LinkEndpointRole::Initiator, true).await
        });
        let Some(TransportMessage::UnbindLinkEndpoint { result_tx, .. }) =
            transport_rx.recv().await
        else {
            panic!("expected typed unbind");
        };
        let _ = result_tx.send(LinkEndpointUnbindResult::RoleMismatch);
        assert!(matches!(
            cleanup.await.unwrap(),
            Err(LinkEndpointError::Unbind(
                LinkEndpointUnbindResult::RoleMismatch
            ))
        ));
        assert!(
            transport_rx.try_recv().is_err(),
            "role mismatch must not deregister the foreign Link destination"
        );
    }

    #[tokio::test]
    async fn cancelled_atomic_close_retains_queued_fifo_ownership() {
        let link_id = [0xC3; 16];
        let (transport_tx, mut transport_rx) = mpsc::channel(2);
        let call_tx = transport_tx.clone();
        let close = tokio::spawn(async move {
            send_and_unbind(
                &call_tx,
                link_id,
                LinkEndpointRole::Initiator,
                proof_packet(link_id, b"final"),
            )
            .await
        });
        let Some(TransportMessage::SendLinkEndpointAndUnbind { result_tx, .. }) =
            transport_rx.recv().await
        else {
            panic!("expected atomic final send");
        };
        close.abort();
        let _ = close.await;
        let _ = result_tx.send(LinkEndpointSendResult::Queued { depth: 1 });
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(
            transport_rx.try_recv().is_err(),
            "accepted atomic close owns FIFO drain; cancellation must not preempt it"
        );
        drop(transport_tx);
    }
}
