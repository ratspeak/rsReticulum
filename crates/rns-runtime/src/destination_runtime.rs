//! App-facing ownership for an inbound SINGLE destination.
//!
//! Python binds Destination construction, transport registration, Link
//! handling, and callbacks to process-global state. This facade keeps those
//! responsibilities explicit: one registration owns one responder
//! [`LinkManager`], exposes bounded event receivers, and deregisters when
//! closed.

use rns_identity::destination::{
    AllowPolicy, DestType, Destination, DestinationError, Direction, ProofStrategy,
};
use rns_identity::identity::Identity;
use rns_link::link::{CloseReason, ResourceStrategy};
use rns_protocol::channel_message::{ChannelMessageError, MessageBase};
use rns_transport::messages::TransportMessage;
use tokio::sync::{mpsc, oneshot};

use crate::link_manager::{
    ChannelSendError, ChannelSendReceipt, DestinationAnnounceOptions, DestinationControlError,
    DestinationRequest, LinkChannelMessage, LinkManager, LinkManagerCommand, LinkPacketProof,
    LinkPacketSendReceipt, LinkPayloadSendReceipt, LinkResourceEvent, LinkResourceProof,
    LinkResourceSendReceipt, LinkSendError, RequestOutcome, ResourceCompletion,
};

const DEFAULT_EVENT_CAPACITY: usize = 128;
const COMMAND_CAPACITY: usize = 256;

#[derive(Debug, Clone)]
pub struct DestinationRuntimeOptions {
    pub proof_strategy: ProofStrategy,
    pub accepts_links: bool,
    pub resource_strategy: ResourceStrategy,
    pub event_capacity: usize,
}

impl Default for DestinationRuntimeOptions {
    fn default() -> Self {
        Self {
            proof_strategy: ProofStrategy::ProveNone,
            accepts_links: true,
            resource_strategy: ResourceStrategy::AcceptNone,
            event_capacity: DEFAULT_EVENT_CAPACITY,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationPacket {
    pub data: Vec<u8>,
    pub raw: Vec<u8>,
}

/// Bounded event receivers owned by one registered destination.
pub struct DestinationEvents {
    pub packets: mpsc::Receiver<DestinationPacket>,
    pub links_established: mpsc::Receiver<[u8; 16]>,
    pub links_identified: mpsc::Receiver<([u8; 16], [u8; 16])>,
    pub link_packets: mpsc::Receiver<(Vec<u8>, [u8; 16])>,
    pub link_packet_proofs: mpsc::Receiver<LinkPacketProof>,
    pub resource_completions: mpsc::Receiver<ResourceCompletion>,
    pub resource_proofs: mpsc::Receiver<LinkResourceProof>,
    pub resource_events: mpsc::Receiver<LinkResourceEvent>,
    pub channel_messages: mpsc::Receiver<LinkChannelMessage>,
    pub links_closed: mpsc::Receiver<[u8; 16]>,
}

#[derive(Debug, thiserror::Error)]
pub enum DestinationRuntimeError {
    #[error(transparent)]
    Destination(#[from] DestinationError),
    #[error(transparent)]
    Control(#[from] DestinationControlError),
    #[error(transparent)]
    LinkSend(#[from] LinkSendError),
    #[error(transparent)]
    ChannelSend(#[from] ChannelSendError),
    #[error("destination event capacity must be greater than zero")]
    InvalidEventCapacity,
    #[error("destination manager is no longer available")]
    ManagerUnavailable,
}

#[derive(Clone)]
pub struct DestinationHandle {
    destination_hash: [u8; 16],
    app_name: String,
    command_tx: mpsc::Sender<LinkManagerCommand>,
}

impl DestinationHandle {
    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination_hash
    }

    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    pub async fn announce(
        &self,
        options: DestinationAnnounceOptions,
    ) -> Result<(), DestinationRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::AnnounceWith {
                options,
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        result_rx
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)??;
        Ok(())
    }

    pub async fn set_accepts_links(&self, accepts: bool) -> Result<(), DestinationRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::SetAcceptsLinks {
                accepts,
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        result_rx
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)??;
        Ok(())
    }

    pub async fn register_request_handler<F>(
        &self,
        path: impl Into<String>,
        allow: AllowPolicy,
        allowed_list: Vec<[u8; 16]>,
        auto_compress: bool,
        handler: F,
    ) -> Result<bool, DestinationRuntimeError>
    where
        F: Fn(DestinationRequest) -> RequestOutcome + Send + 'static,
    {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::RegisterRequestHandler {
                path: path.into(),
                allow,
                allowed_list,
                auto_compress,
                handler: Box::new(handler),
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        result_rx
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)
    }

    pub async fn deregister_request_handler(
        &self,
        path: impl Into<String>,
    ) -> Result<bool, DestinationRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::DeregisterRequestHandler {
                path: path.into(),
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        result_rx
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)
    }

    pub async fn send_link_packet(
        &self,
        link_id: [u8; 16],
        payload: impl Into<Vec<u8>>,
    ) -> Result<LinkPacketSendReceipt, DestinationRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::SendLinkPacket {
                link_id,
                payload: payload.into(),
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        Ok(result_rx
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)??)
    }

    pub async fn send_link_resource(
        &self,
        link_id: [u8; 16],
        payload: impl Into<Vec<u8>>,
        auto_compress: bool,
    ) -> Result<LinkResourceSendReceipt, DestinationRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::SendLinkResource {
                link_id,
                payload: payload.into(),
                auto_compress,
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        Ok(result_rx
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)??)
    }

    pub async fn send_link_payload(
        &self,
        link_id: [u8; 16],
        payload: impl Into<Vec<u8>>,
        auto_compress: bool,
    ) -> Result<LinkPayloadSendReceipt, DestinationRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::SendLinkPayload {
                link_id,
                payload: payload.into(),
                auto_compress,
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        Ok(result_rx
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)??)
    }

    pub async fn send_channel(
        &self,
        link_id: [u8; 16],
        msg_type: u16,
        payload: impl Into<Vec<u8>>,
    ) -> Result<ChannelSendReceipt, DestinationRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::SendChannelMessage {
                link_id,
                message: Box::new(RawChannelMessage {
                    msg_type,
                    payload: payload.into(),
                }),
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        Ok(result_rx
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)??)
    }

    pub async fn close_link(
        &self,
        link_id: [u8; 16],
        reason: CloseReason,
        send_teardown: bool,
    ) -> Result<(), DestinationRuntimeError> {
        self.command_tx
            .send(LinkManagerCommand::CloseLink {
                link_id,
                reason,
                send_teardown,
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)
    }

    pub async fn shutdown(&self) -> Result<(), DestinationRuntimeError> {
        self.command_tx
            .send(LinkManagerCommand::Shutdown)
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)
    }
}

/// Owns one live inbound destination and its responder Link manager.
pub struct RegisteredDestination {
    pub handle: DestinationHandle,
    pub events: DestinationEvents,
    stopped_rx: Option<oneshot::Receiver<()>>,
}

impl RegisteredDestination {
    pub async fn register(
        transport_tx: mpsc::Sender<TransportMessage>,
        identity: Identity,
        app_name: impl Into<String>,
        options: DestinationRuntimeOptions,
    ) -> Result<Self, DestinationRuntimeError> {
        if options.event_capacity == 0 {
            return Err(DestinationRuntimeError::InvalidEventCapacity);
        }
        let app_name = app_name.into();
        let destination =
            Destination::new(Some(&identity), Direction::In, DestType::Single, &app_name)?;
        let destination_hash = destination.hash;
        let (delivery_tx, delivery_rx) = mpsc::channel(options.event_capacity);
        transport_tx
            .send(TransportMessage::RegisterDestination {
                hash: destination_hash,
                app_name: app_name.clone(),
                delivery_tx: Some(delivery_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;

        let mut manager = LinkManager::with_destination(
            transport_tx.clone(),
            delivery_rx,
            &identity,
            &app_name,
            identity.get_signing_key(),
        );
        manager.set_resource_strategy(options.resource_strategy);
        manager.set_use_implicit_proof(true);
        let owned_destination = manager
            .destination_mut()
            .ok_or(DestinationControlError::DestinationUnavailable)?;
        owned_destination.set_proof_strategy(options.proof_strategy);
        owned_destination.set_accepts_links(options.accepts_links);

        let capacity = options.event_capacity;
        let (packet_tx, packets) = mpsc::channel(capacity);
        owned_destination.set_packet_callback(Box::new(move |data, raw| {
            let _ = packet_tx.try_send(DestinationPacket {
                data: data.to_vec(),
                raw: raw.to_vec(),
            });
        }));

        let (links_established_tx, links_established) = mpsc::channel(capacity);
        let (links_identified_tx, links_identified) = mpsc::channel(capacity);
        let (link_packets_tx, link_packets) = mpsc::channel(capacity);
        let (link_packet_proofs_tx, link_packet_proofs) = mpsc::channel(capacity);
        let (resource_completions_tx, resource_completions) = mpsc::channel(capacity);
        let (resource_proofs_tx, resource_proofs) = mpsc::channel(capacity);
        let (resource_events_tx, resource_events) = mpsc::channel(capacity);
        let (channel_messages_tx, channel_messages) = mpsc::channel(capacity);
        let (links_closed_tx, links_closed) = mpsc::channel(capacity);
        manager.set_link_established_channel(links_established_tx);
        manager.set_link_identified_channel(links_identified_tx);
        manager.set_link_packet_channel(link_packets_tx);
        manager.set_link_packet_proof_channel(link_packet_proofs_tx);
        manager.set_resource_completion_channel(resource_completions_tx);
        manager.set_outbound_resource_proof_channel(resource_proofs_tx);
        manager.set_resource_event_channel(resource_events_tx);
        manager.set_channel_message_channel(channel_messages_tx);
        manager.set_link_closed_channel(links_closed_tx);

        let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (stopped_tx, stopped_rx) = oneshot::channel();
        let manager_transport_tx = transport_tx;
        tokio::spawn(async move {
            manager.run_with_commands(command_rx).await;
            let _ = manager_transport_tx
                .send(TransportMessage::DeregisterDestination {
                    hash: destination_hash,
                })
                .await;
            let _ = stopped_tx.send(());
        });

        Ok(Self {
            handle: DestinationHandle {
                destination_hash,
                app_name,
                command_tx,
            },
            events: DestinationEvents {
                packets,
                links_established,
                links_identified,
                link_packets,
                link_packet_proofs,
                resource_completions,
                resource_proofs,
                resource_events,
                channel_messages,
                links_closed,
            },
            stopped_rx: Some(stopped_rx),
        })
    }

    pub async fn close(mut self) -> Result<(), DestinationRuntimeError> {
        self.handle.shutdown().await?;
        if let Some(stopped_rx) = self.stopped_rx.take() {
            stopped_rx
                .await
                .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        }
        Ok(())
    }
}

impl Drop for RegisteredDestination {
    fn drop(&mut self) {
        let command = LinkManagerCommand::Shutdown;
        match self.handle.command_tx.try_send(command) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
            Err(mpsc::error::TrySendError::Full(command)) => {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    let command_tx = self.handle.command_tx.clone();
                    runtime.spawn(async move {
                        let _ = command_tx.send(command).await;
                    });
                }
            }
        }
    }
}

struct RawChannelMessage {
    msg_type: u16,
    payload: Vec<u8>,
}

impl MessageBase for RawChannelMessage {
    fn msg_type(&self) -> u16 {
        self.msg_type
    }

    fn pack(&self) -> Vec<u8> {
        self.payload.clone()
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
        self.payload = raw.to_vec();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_transport::messages::TransportMessage;

    #[tokio::test]
    async fn registration_announces_and_deregisters_exact_destination() {
        let identity = Identity::new();
        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let registration = RegisteredDestination::register(
            transport_tx,
            identity,
            "example.runtime",
            DestinationRuntimeOptions::default(),
        )
        .await
        .unwrap();
        let destination_hash = registration.handle.destination_hash();

        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::RegisterDestination { hash, .. }) if hash == destination_hash
        ));
        registration
            .handle
            .announce(DestinationAnnounceOptions {
                app_data: Some(b"hello".to_vec()),
                ..DestinationAnnounceOptions::default()
            })
            .await
            .unwrap();
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::Outbound(_)) | Some(TransportMessage::OutboundAttached { .. })
        ));

        registration.close().await.unwrap();
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterDestination { hash }) if hash == destination_hash
        ));
    }
}
