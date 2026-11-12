//! App-facing ownership for an inbound SINGLE destination.
//!
//! One registration owns one responder [`LinkManager`] and its event receivers.
//! Most receivers are bounded; ordinary Link packet delivery uses an unbounded
//! queue. Close the registration explicitly to wait for manager shutdown and
//! submission of destination deregistration.

use rns_identity::destination::{
    AllowPolicy, DefaultAppData, DestType, Destination, DestinationError, Direction, ProofStrategy,
};
use rns_identity::identity::Identity;
use rns_link::link::{CloseReason, ResourceStrategy};
use rns_protocol::channel::ChannelError;
use rns_protocol::channel_message::{ChannelMessageError, MessageBase};
use rns_protocol::resource_adv::ResourceAdvertisement;
use rns_transport::messages::TransportMessage;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

use crate::link_manager::{
    ChannelSendError, ChannelSendReceipt, DeferredAdmission, DeferredRequestResponder,
    DestinationAnnounceOptions, DestinationControlError, DestinationRequest, LinkChannelMessage,
    LinkManager, LinkManagerCommand, LinkPacketProof, LinkPacketSendReceipt,
    LinkPayloadSendReceipt, LinkResourceEvent, LinkResourceProof, LinkResourceSendReceipt,
    LinkSendError, RequestOutcome, ResourceCompletion,
};

const DEFAULT_EVENT_CAPACITY: usize = 128;
const COMMAND_CAPACITY: usize = 256;

type ResourceAcceptCallback = dyn Fn([u8; 16], &ResourceAdvertisement) -> bool + Send + Sync;

#[derive(Debug, Clone)]
pub struct DestinationRuntimeOptions {
    pub proof_strategy: ProofStrategy,
    pub accepts_links: bool,
    pub resource_strategy: ResourceStrategy,
    pub event_capacity: usize,
    /// Announce app data used whenever an announce (including a path
    /// response) carries none explicitly.
    pub default_app_data: Option<Vec<u8>>,
    /// Per-advertisement acceptance policy for ordinary Resources, consulted when
    /// `resource_strategy` is `AcceptApp`.
    pub resource_accept: Option<ResourceAcceptPolicy>,
    /// Synchronous LinkIdentify gate; returning false closes the link.
    pub identity_gate: Option<IdentityGatePolicy>,
    /// User Channel message types registered before the manager starts.
    pub channel_message_types: Vec<u16>,
    /// Target destination stamp value (Python `Destination.set_value`).
    pub stamp_value: Option<f64>,
    /// Announced link-request cost (Python `Destination.set_link_cost`).
    pub link_cost: Option<f64>,
    /// Largest advertised total size of an inbound Resource, which the
    /// destination reassembles in memory; `None` accepts any size. See
    /// [`rns_protocol::resource::DEFAULT_INBOUND_REASSEMBLY_LIMIT`].
    pub inbound_reassembly_limit: Option<usize>,
    /// Exact endpoint dispatch from the same runtime
    /// (`ReticulumHandle::link_endpoint_dispatch_handle`). Deferred request
    /// handlers require it.
    pub endpoint_dispatch:
        Option<rns_transport::link_endpoint_dispatch::LinkEndpointDispatchHandle>,
}

impl Default for DestinationRuntimeOptions {
    fn default() -> Self {
        Self {
            proof_strategy: ProofStrategy::ProveNone,
            accepts_links: true,
            resource_strategy: ResourceStrategy::AcceptNone,
            event_capacity: DEFAULT_EVENT_CAPACITY,
            default_app_data: None,
            resource_accept: None,
            identity_gate: None,
            channel_message_types: Vec::new(),
            stamp_value: None,
            link_cost: None,
            inbound_reassembly_limit: Some(
                rns_protocol::resource::DEFAULT_INBOUND_REASSEMBLY_LIMIT,
            ),
            endpoint_dispatch: None,
        }
    }
}

/// Clonable per-advertisement acceptance policy for ordinary inbound Resources.
/// Request/response transfers use their own handling. The callback
/// receives `(link_id, advertisement)` and runs synchronously on the manager;
/// it is consulted only with `ResourceStrategy::AcceptApp`.
#[derive(Clone)]
pub struct ResourceAcceptPolicy(Arc<ResourceAcceptCallback>);

impl ResourceAcceptPolicy {
    pub fn new(
        policy: impl Fn([u8; 16], &ResourceAdvertisement) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(policy))
    }
}

impl fmt::Debug for ResourceAcceptPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResourceAcceptPolicy")
    }
}

/// Clonable synchronous gate for a verified LinkIdentify message. The callback
/// receives `(link_id, identity_hash)`; false closes that Link before later
/// packets are processed. This does not require peers to identify before
/// sending data or Resource advertisements; enforce that separately.
#[derive(Clone)]
pub struct IdentityGatePolicy(Arc<dyn Fn([u8; 16], [u8; 16]) -> bool + Send + Sync>);

impl IdentityGatePolicy {
    pub fn new(gate: impl Fn([u8; 16], [u8; 16]) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(gate))
    }
}

impl fmt::Debug for IdentityGatePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdentityGatePolicy")
    }
}

/// Persistent ratchet settings for inbound destination packets. Key retention
/// and expiry determine the history exposed by compromise of the stored ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationRatchetOptions {
    /// Persistent ratchet-ring file. Legacy files may authenticate only the
    /// current public key; see `PersistentRatchetRing::open` before accepting
    /// an existing file.
    pub path: PathBuf,
    /// Reject packets encrypted only to the base identity key.
    pub enforce: bool,
}

impl DestinationRatchetOptions {
    /// Use `path` with ratchet enforcement disabled.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            enforce: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationPacket {
    pub data: Vec<u8>,
    pub raw: Vec<u8>,
}

/// Event receivers owned by one registered destination. Receivers are bounded
/// by `event_capacity` except `link_packets`, which is unbounded and must be
/// drained to avoid memory growth. Notification queues can drop events when
/// full. Link proof policy is independent of application consumption; receipt
/// of a proof does not establish that the application processed the payload.
pub struct DestinationEvents {
    pub packets: mpsc::Receiver<DestinationPacket>,
    pub links_established: mpsc::Receiver<[u8; 16]>,
    pub links_identified: mpsc::Receiver<([u8; 16], [u8; 16])>,
    pub link_packets: mpsc::UnboundedReceiver<(Vec<u8>, [u8; 16])>,
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
    OrdinaryPacketConfiguration(#[from] crate::link_manager::LinkPacketConfigurationError),
    #[error(transparent)]
    Destination(#[from] DestinationError),
    #[error(transparent)]
    Control(#[from] DestinationControlError),
    #[error(transparent)]
    LinkSend(#[from] LinkSendError),
    #[error(transparent)]
    ChannelSend(#[from] ChannelSendError),
    #[error(transparent)]
    Channel(#[from] ChannelError),
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

    pub(crate) fn command_tx(&self) -> &mpsc::Sender<LinkManagerCommand> {
        &self.command_tx
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

    /// Set the target destination stamp value, clamped as Python's `set_value`.
    pub async fn set_stamp_value(&self, value: f64) -> Result<(), DestinationRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::SetStampValue {
                value,
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        result_rx
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)??;
        Ok(())
    }

    /// Set the announced link-request cost, clamped as Python's `set_link_cost`.
    pub async fn set_link_cost(&self, cost: f64) -> Result<(), DestinationRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::SetLinkCost {
                cost,
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        result_rx
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)??;
        Ok(())
    }

    /// Set or clear the default app data used whenever an announce (including
    /// a path response) carries none explicitly.
    pub async fn set_default_app_data(
        &self,
        app_data: Option<Vec<u8>>,
    ) -> Result<(), DestinationRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::SetDefaultAppData {
                app_data,
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
        auto_compress: impl Into<crate::resource_source::AutoCompress>,
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
                auto_compress: auto_compress.into(),
                handler: Box::new(handler),
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        result_rx
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)
    }

    /// Register a handler that hands its responder to a worker, so slow work
    /// never runs on the manager task. See
    /// [`LinkManager::register_deferred_request_handler`]; registration fails
    /// without `DestinationRuntimeOptions::endpoint_dispatch`.
    pub async fn register_deferred_request_handler<F>(
        &self,
        path: impl Into<String>,
        allow: AllowPolicy,
        allowed_list: Vec<[u8; 16]>,
        auto_compress: impl Into<crate::resource_source::AutoCompress>,
        response_byte_limit: usize,
        handler: F,
    ) -> Result<bool, DestinationRuntimeError>
    where
        F: Fn(DestinationRequest, DeferredRequestResponder) + Send + 'static,
    {
        self.register_deferred_request_handler_with(
            path,
            allow,
            allowed_list,
            auto_compress,
            DeferredAdmission::new(response_byte_limit),
            handler,
        )
        .await
    }

    /// [`Self::register_deferred_request_handler`] with declared admission
    /// accounting and refusal replies. See
    /// [`LinkManager::register_deferred_request_handler_with`].
    pub async fn register_deferred_request_handler_with<F>(
        &self,
        path: impl Into<String>,
        allow: AllowPolicy,
        allowed_list: Vec<[u8; 16]>,
        auto_compress: impl Into<crate::resource_source::AutoCompress>,
        admission: DeferredAdmission,
        handler: F,
    ) -> Result<bool, DestinationRuntimeError>
    where
        F: Fn(DestinationRequest, DeferredRequestResponder) + Send + 'static,
    {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::RegisterDeferredRequestHandler {
                path: path.into(),
                allow,
                allowed_list,
                auto_compress: auto_compress.into(),
                admission,
                handler: Box::new(handler),
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        result_rx
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)
    }

    /// Destination.set_max_request_size: REQUEST packets larger than `limit`
    /// bytes are ignored and larger request Resources are rejected. `None`
    /// accepts any size.
    pub async fn set_max_request_size(
        &self,
        limit: Option<usize>,
    ) -> Result<(), DestinationRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkManagerCommand::SetMaxRequestSize {
                limit,
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
/// Use `close` to await shutdown; dropping requests it on a best-effort basis.
/// These mailbox-based registration methods reject `ProofStrategy::ProveApp`
/// because they do not carry exact endpoint-dispatch authority.
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
        Self::register_inner(transport_tx, identity, app_name, options, None).await
    }

    /// Register a destination whose announce rotation and inbound decryption
    /// use a persistent ratchet ring. A current ratchet is ensured before use.
    /// Existing legacy files are accepted with the authentication limits of
    /// `PersistentRatchetRing::open`; this method does not expose their format.
    pub async fn register_ratcheted(
        transport_tx: mpsc::Sender<TransportMessage>,
        identity: Identity,
        app_name: impl Into<String>,
        options: DestinationRuntimeOptions,
        ratchet_options: DestinationRatchetOptions,
    ) -> Result<Self, DestinationRuntimeError> {
        Self::register_inner(
            transport_tx,
            identity,
            app_name,
            options,
            Some(ratchet_options),
        )
        .await
    }

    async fn register_inner(
        transport_tx: mpsc::Sender<TransportMessage>,
        identity: Identity,
        app_name: impl Into<String>,
        options: DestinationRuntimeOptions,
        ratchet_options: Option<DestinationRatchetOptions>,
    ) -> Result<Self, DestinationRuntimeError> {
        if options.event_capacity == 0 {
            return Err(DestinationRuntimeError::InvalidEventCapacity);
        }
        // This compatibility constructor receives only the transport mailbox,
        // which cannot grant exact endpoint-generation dispatch authority.
        if options.proof_strategy == ProofStrategy::ProveApp {
            return Err(
                crate::link_manager::LinkPacketConfigurationError::ExactDispatchRequired.into(),
            );
        }
        let app_name = app_name.into();
        let destination =
            Destination::new(Some(&identity), Direction::In, DestType::Single, &app_name)?;
        let destination_hash = destination.hash;
        let (delivery_tx, delivery_rx) = mpsc::channel(options.event_capacity);

        let mut manager = LinkManager::with_destination(
            transport_tx.clone(),
            delivery_rx,
            &identity,
            &app_name,
            identity.get_signing_key(),
        );
        if let Some(ratchet_options) = ratchet_options {
            manager.enable_persistent_ratchets(ratchet_options.path, ratchet_options.enforce)?;
        }
        manager.set_resource_strategy(options.resource_strategy);
        manager.set_inbound_reassembly_limit(options.inbound_reassembly_limit);
        if let Some(dispatch) = options.endpoint_dispatch.clone() {
            manager.set_link_endpoint_dispatch_handle(dispatch);
        }
        manager.set_use_implicit_proof(true);
        if let Some(policy) = options.resource_accept.clone() {
            manager.set_resource_accept_handler(move |link_id, adv| (policy.0)(link_id, adv));
        }
        if let Some(gate) = options.identity_gate.clone() {
            manager.set_link_identity_gate(move |link_id, identity| (gate.0)(link_id, identity));
        }
        for msg_type in &options.channel_message_types {
            manager.register_channel_message_type(*msg_type)?;
        }
        let owned_destination = manager
            .destination_mut()
            .ok_or(DestinationControlError::DestinationUnavailable)?;
        owned_destination.set_proof_strategy(options.proof_strategy);
        owned_destination.set_accepts_links(options.accepts_links);
        if let Some(app_data) = options.default_app_data.clone() {
            owned_destination.set_default_app_data(DefaultAppData::Static(app_data));
        }
        if let Some(value) = options.stamp_value {
            owned_destination.set_value(
                value,
                crate::destination_stamper::policy().destination_value,
            );
        }
        if let Some(cost) = options.link_cost {
            owned_destination.set_link_cost(cost);
        }

        transport_tx
            .send(TransportMessage::RegisterDestination {
                hash: destination_hash,
                app_name: app_name.clone(),
                delivery_tx: Some(delivery_tx),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;
        transport_tx
            .send(TransportMessage::SetLocalDestinationKey {
                hash: destination_hash,
                public_key: identity.get_public_key(),
            })
            .await
            .map_err(|_| DestinationRuntimeError::ManagerUnavailable)?;

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
        let (link_packets_tx, link_packets) = mpsc::unbounded_channel();
        let (link_packet_proofs_tx, link_packet_proofs) = mpsc::channel(capacity);
        let (resource_completions_tx, resource_completions) = mpsc::channel(capacity);
        let (resource_proofs_tx, resource_proofs) = mpsc::channel(capacity);
        let (resource_events_tx, resource_events) = mpsc::channel(capacity);
        let (channel_messages_tx, channel_messages) = mpsc::channel(capacity);
        let (links_closed_tx, links_closed) = mpsc::channel(capacity);
        manager.set_link_established_channel(links_established_tx);
        manager.set_link_identified_channel(links_identified_tx);
        manager.set_link_packet_channel(link_packets_tx)?;
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
    use crate::link_session::{LinkSession, LinkSessionConfig, LinkSessionEvent};
    use rns_protocol::channel_message::SYSTEM_MESSAGE_TYPE_MIN;
    use rns_transport::actor::TransportActor;
    use rns_transport::messages::TransportMessage;
    use std::time::Duration;

    #[tokio::test]
    async fn register_applies_policy_options_and_rejects_reserved_channel_types() {
        let identity = Identity::new();
        let (transport_tx, mut transport_rx) = mpsc::channel(16);

        let reserved = RegisteredDestination::register(
            transport_tx.clone(),
            identity.clone(),
            "example.runtime.policies",
            DestinationRuntimeOptions {
                channel_message_types: vec![SYSTEM_MESSAGE_TYPE_MIN],
                ..DestinationRuntimeOptions::default()
            },
        )
        .await;
        assert!(matches!(reserved, Err(DestinationRuntimeError::Channel(_))));
        assert!(
            transport_rx.try_recv().is_err(),
            "a reserved channel type must fail before transport registration"
        );

        let registration = RegisteredDestination::register(
            transport_tx,
            identity,
            "example.runtime.policies",
            DestinationRuntimeOptions {
                resource_strategy: ResourceStrategy::AcceptApp,
                resource_accept: Some(ResourceAcceptPolicy::new(|_, _| false)),
                identity_gate: Some(IdentityGatePolicy::new(|_, _| true)),
                channel_message_types: vec![0x0100],
                default_app_data: Some(b"policy app data".to_vec()),
                ..DestinationRuntimeOptions::default()
            },
        )
        .await
        .expect("valid policy options must register");
        registration.close().await.unwrap();
    }

    #[tokio::test]
    async fn registration_announces_and_deregisters_exact_destination() {
        let identity = Identity::new();
        let public = identity.get_public_key();
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
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::SetLocalDestinationKey { hash, public_key })
                if hash == destination_hash && public_key == public
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

    #[tokio::test]
    async fn deferred_request_handler_answers_from_a_worker_thread() {
        let (actor, transport_tx) = TransportActor::new();
        let dispatch = actor.link_endpoint_dispatch_handle();
        let actor_task = tokio::spawn(actor.run());
        let server_identity = Identity::new();
        let server_public_key = server_identity.get_public_key();

        let without = RegisteredDestination::register(
            transport_tx.clone(),
            server_identity.clone(),
            "example.runtime.deferred",
            DestinationRuntimeOptions::default(),
        )
        .await
        .unwrap();
        let refused = without
            .handle
            .register_deferred_request_handler(
                "/slow",
                AllowPolicy::AllowAll,
                Vec::new(),
                false,
                4096,
                |_, _| {},
            )
            .await
            .unwrap();
        assert!(!refused, "deferred handlers need exact endpoint dispatch");
        without.close().await.unwrap();

        let registration = RegisteredDestination::register(
            transport_tx.clone(),
            server_identity,
            "example.runtime.deferred",
            DestinationRuntimeOptions {
                endpoint_dispatch: Some(dispatch),
                ..DestinationRuntimeOptions::default()
            },
        )
        .await
        .unwrap();
        let registered = registration
            .handle
            .register_deferred_request_handler(
                "/slow",
                AllowPolicy::AllowAll,
                Vec::new(),
                false,
                4096,
                |request, responder| {
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(200));
                        let mut reply = b"done:".to_vec();
                        reply.extend_from_slice(&request.data);
                        let _ = responder.respond(RequestOutcome::ReplyBytes(reply));
                    });
                },
            )
            .await
            .unwrap();
        assert!(registered);
        registration
            .handle
            .register_request_handler("/fast", AllowPolicy::AllowAll, Vec::new(), false, |_| {
                RequestOutcome::ReplyBytes(b"fast".to_vec())
            })
            .await
            .unwrap();

        let session = tokio::time::timeout(
            Duration::from_secs(3),
            LinkSession::connect(
                transport_tx.clone(),
                Identity::new(),
                LinkSessionConfig {
                    destination_hash: registration.handle.destination_hash(),
                    remote_public_key: server_public_key,
                    hops: 1,
                    establishment_timeout: Duration::from_secs(2),
                    client_label: "test.deferred".into(),
                    identify: true,
                    track_phy_stats: false,
                    proof_strategy: rns_identity::destination::ProofStrategy::ProveNone,
                    resource_dir: None,
                    inbound_reassembly_limit: None,
                },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let timeout = Some(Duration::from_secs(5));
        let (slow, fast) = tokio::join!(session.handle.request("/slow", b"x", timeout), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let reply = session.handle.request("/fast", b"", timeout).await;
            (reply, std::time::Instant::now())
        });
        let slow_done = std::time::Instant::now();
        assert_eq!(slow.unwrap().data, b"done:x");
        let (fast, fast_done) = fast;
        assert_eq!(fast.unwrap().data, b"fast");
        assert!(
            fast_done < slow_done,
            "the manager must keep answering while a deferred worker runs"
        );

        session.handle.close().await;
        registration.close().await.unwrap();
        transport_tx.send(TransportMessage::Shutdown).await.unwrap();
        actor_task.await.unwrap();
    }

    #[tokio::test]
    async fn link_session_connects_to_destination_on_same_transport_actor() {
        let (actor, transport_tx) = TransportActor::new();
        let actor_task = tokio::spawn(actor.run());
        let server_identity = Identity::new();
        let server_public_key = server_identity.get_public_key();
        let mut registration = RegisteredDestination::register(
            transport_tx.clone(),
            server_identity,
            "example.runtime.loopback",
            DestinationRuntimeOptions::default(),
        )
        .await
        .unwrap();
        let destination_hash = registration.handle.destination_hash();
        let client_identity = Identity::new();
        let expected_client = client_identity.hash;

        let mut session = tokio::time::timeout(
            Duration::from_secs(3),
            LinkSession::connect(
                transport_tx.clone(),
                client_identity,
                LinkSessionConfig {
                    destination_hash,
                    remote_public_key: server_public_key,
                    hops: 1,
                    establishment_timeout: Duration::from_secs(2),
                    client_label: "test.same-actor-link".into(),
                    identify: true,
                    track_phy_stats: false,
                    proof_strategy: rns_identity::destination::ProofStrategy::ProveNone,
                    resource_dir: None,
                    inbound_reassembly_limit: None,
                },
            ),
        )
        .await
        .expect("same-actor Link establishment timed out")
        .expect("same-actor Link establishment failed");
        let link_id = session.handle.link_id();

        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                registration.events.links_established.recv()
            )
            .await
            .unwrap(),
            Some(link_id)
        );
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                registration.events.links_identified.recv()
            )
            .await
            .unwrap(),
            Some((link_id, expected_client))
        );

        session
            .handle
            .send_packet(b"client to server".to_vec())
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                registration.events.link_packets.recv()
            )
            .await
            .unwrap(),
            Some((b"client to server".to_vec(), link_id))
        );

        registration
            .handle
            .send_link_packet(link_id, b"server to client".to_vec())
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(LinkSessionEvent::Packet { data, .. }) = session.events.recv().await {
                    break data;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(received, b"server to client");

        session.handle.close().await;
        registration.close().await.unwrap();
        transport_tx.send(TransportMessage::Shutdown).await.unwrap();
        actor_task.await.unwrap();
    }

    #[tokio::test]
    async fn ratcheted_registration_advertises_and_decrypts_owned_ring() {
        let identity = Identity::new();
        let app_name = "example.runtime.ratcheted";
        let dir =
            std::env::temp_dir().join(format!("reticulum_runtime_ratchets_{}", identity.hexhash()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ratchet_path = dir.join("ratchets");
        let (transport_tx, mut transport_rx) = mpsc::channel(16);

        let mut registration = RegisteredDestination::register_ratcheted(
            transport_tx,
            identity.clone(),
            app_name,
            DestinationRuntimeOptions::default(),
            DestinationRatchetOptions {
                path: ratchet_path.clone(),
                enforce: true,
            },
        )
        .await
        .unwrap();
        let destination_hash = registration.handle.destination_hash();
        let delivery_tx = match transport_rx.recv().await.unwrap() {
            TransportMessage::RegisterDestination {
                hash,
                delivery_tx: Some(delivery_tx),
                ..
            } => {
                assert_eq!(hash, destination_hash);
                delivery_tx
            }
            other => panic!("expected destination registration, got {other:?}"),
        };
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::SetLocalDestinationKey { hash, .. }) if hash == destination_hash
        ));

        registration
            .handle
            .announce(DestinationAnnounceOptions::default())
            .await
            .unwrap();
        let announce_raw = match transport_rx.recv().await.unwrap() {
            TransportMessage::Outbound(request) => request.raw,
            TransportMessage::OutboundAttached { request, .. } => request.raw,
            other => panic!("expected ratcheted announce, got {other:?}"),
        };
        let (announce_header, _) = rns_wire::header::PacketHeader::unpack(&announce_raw).unwrap();
        assert_eq!(
            announce_header.flags.packet_type,
            rns_wire::flags::PacketType::Announce
        );
        assert!(announce_header.flags.context_flag);

        let ratchet = rns_identity::ratchet::RatchetRing::load_verified(&ratchet_path, &identity)
            .unwrap()
            .ring()
            .current_public_key()
            .unwrap();
        let mut wrong_ratchet = ratchet;
        wrong_ratchet[0] ^= 0xFF;
        assert!(matches!(
            registration
                .handle
                .announce(DestinationAnnounceOptions {
                    ratchet: Some(wrong_ratchet),
                    ..DestinationAnnounceOptions::default()
                })
                .await,
            Err(DestinationRuntimeError::Control(
                DestinationControlError::ManagedRatchetMismatch
            ))
        ));
        assert!(
            transport_rx.try_recv().is_err(),
            "a mismatched managed ratchet must not be advertised"
        );

        let public_identity = Identity::from_public_key(&identity.get_public_key()).unwrap();
        let mut outbound = Destination::new(
            Some(&public_identity),
            Direction::Out,
            DestType::Single,
            app_name,
        )
        .unwrap();
        outbound.set_remote_ratchet(ratchet);
        let ciphertext = outbound
            .encrypt(
                b"forward secret",
                &public_identity,
                outbound.remote_ratchet_pub.as_ref(),
            )
            .unwrap();
        let packet = rns_wire::packet::Packet::new(
            rns_wire::header::PacketHeader {
                flags: rns_wire::flags::PacketFlags {
                    header_type: rns_wire::flags::HeaderType::Header1,
                    context_flag: false,
                    transport_type: rns_wire::flags::TransportType::Broadcast,
                    destination_type: rns_wire::flags::DestinationType::Single,
                    packet_type: rns_wire::flags::PacketType::Data,
                },
                hops: 0,
                transport_id: None,
                destination_hash,
                context: rns_wire::context::PacketContext::None,
            },
            ciphertext,
        )
        .unwrap();
        delivery_tx
            .send(
                rns_transport::link_messages::DestinationEvent::InboundPacket {
                    raw: bytes::Bytes::from(packet.raw),
                    interface_owner: None,
                    interface_id: 1,
                    metrics: rns_transport::link_messages::PacketMetrics::default(),
                },
            )
            .await
            .unwrap();

        let delivered = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            registration.events.packets.recv(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(delivered.data, b"forward secret");

        registration.close().await.unwrap();
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterDestination { hash }) if hash == destination_hash
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn failed_ratchet_setup_does_not_leak_transport_registration() {
        let identity = Identity::new();
        let root = std::env::temp_dir().join(format!(
            "reticulum_runtime_missing_ratchets_{}",
            identity.hexhash()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let ratchet_path = root.join("missing").join("ratchets");
        let (transport_tx, mut transport_rx) = mpsc::channel(4);

        let result = RegisteredDestination::register_ratcheted(
            transport_tx,
            identity,
            "example.runtime.ratchet-failure",
            DestinationRuntimeOptions::default(),
            DestinationRatchetOptions::new(ratchet_path),
        )
        .await;
        assert!(matches!(
            result,
            Err(DestinationRuntimeError::Control(
                DestinationControlError::RatchetPersistence(_)
            ))
        ));
        assert!(
            transport_rx.try_recv().is_err(),
            "failed local setup must not register a destination with transport"
        );
    }
}
