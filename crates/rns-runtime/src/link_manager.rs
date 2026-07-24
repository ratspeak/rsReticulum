//! Responder side of Reticulum links: accepts link requests, holds per-link
//! state (session keys, channel, in/outbound transfers), drives keepalives
//! and teardown. Lives here to break the rns-transport ↔ rns-link cycle.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::sha::truncated_hash;
use rns_identity::destination::{AllowPolicy, DestType, Destination, Direction};
use rns_identity::identity::Identity;
use rns_link::link::{CloseReason, Link, LinkAction, LinkState, ResourceStrategy};
use rns_protocol::channel::{ChannelError, LinkChannel};
use rns_protocol::channel_message::MessageBase;
use rns_protocol::resource::{
    InboundTransfer, MAX_EFFICIENT_SIZE, MAX_SEGMENTS, MultiSegmentInbound, MultiSegmentOutbound,
    OutboundTransfer, TransferAction,
};
use rns_protocol::resource_adv::ResourceAdvertisement;
use rns_transport::link_messages::{AnnounceRequest, DestinationEvent};
use rns_transport::messages::{OutboundRequest, TransportMessage};

struct ActiveLink {
    link: Link,
    _interface_id: u64,
    /// Created lazily on first CHANNEL packet.
    channel: Option<LinkChannel>,
    inbound_resources: HashMap<[u8; 32], InboundTransfer>,
    outbound_resources: HashMap<[u8; 32], OutboundTransfer>,
    outbound_split_queues: HashMap<[u8; 32], VecDeque<OutboundTransfer>>,
    /// Split-resource reassembly keyed by `original_hash`; dropped on full delivery or cancel.
    inbound_split_resources: HashMap<[u8; 32], MultiSegmentInbound>,
    /// Reverse index per-segment `resource_hash` → coordinator; routes assembled
    /// bytes without re-parsing the ADV.
    segment_routing: HashMap<[u8; 32], SegmentRoute>,
}

#[derive(Debug, Clone, Copy)]
struct SegmentRoute {
    original_hash: [u8; 32],
    segment_index: usize,
}

#[derive(Debug)]
pub struct LinkResponse {
    pub link_id: [u8; 16],
    pub request_id: [u8; 16],
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct LinkChannelMessage {
    pub link_id: [u8; 16],
    pub msg_type: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ChannelSendReceipt {
    pub link_id: [u8; 16],
    pub sequence: u16,
    pub packet_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct LinkPacketSendReceipt {
    pub link_id: [u8; 16],
    pub packet_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct LinkResourceSendReceipt {
    pub link_id: [u8; 16],
    pub resource_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct LinkPacketProof {
    pub link_id: [u8; 16],
    pub packet_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct LinkResourceProof {
    pub link_id: [u8; 16],
    pub resource_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkResourceDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkResourceConclusion {
    Complete,
    Cancelled,
    Rejected,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkResourceEvent {
    Started {
        link_id: [u8; 16],
        resource_id: [u8; 32],
        direction: LinkResourceDirection,
        data_size: usize,
        total_segments: usize,
    },
    Progress {
        link_id: [u8; 16],
        resource_id: [u8; 32],
        direction: LinkResourceDirection,
        transferred: usize,
        total: usize,
    },
    Concluded {
        link_id: [u8; 16],
        resource_id: [u8; 32],
        direction: LinkResourceDirection,
        conclusion: LinkResourceConclusion,
    },
}

#[derive(Debug, Clone)]
pub enum LinkPayloadSendReceipt {
    Packet(LinkPacketSendReceipt),
    Resource(LinkResourceSendReceipt),
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelSendError {
    #[error("link not found")]
    LinkNotFound,
    #[error("link is not active")]
    LinkNotActive,
    #[error("link session keys are unavailable")]
    NoSessionKeys,
    #[error("channel error: {0}")]
    Channel(#[from] ChannelError),
    #[error("transport channel is full or closed")]
    TransportUnavailable,
}

#[derive(Debug, thiserror::Error)]
pub enum LinkSendError {
    #[error("link not found")]
    LinkNotFound,
    #[error("link is not active")]
    LinkNotActive,
    #[error("link session keys are unavailable")]
    NoSessionKeys,
    #[error("transport channel is full or closed")]
    TransportUnavailable,
    #[error("resource transfer could not be started")]
    ResourceStartFailed,
}

pub enum LinkManagerCommand {
    SendChannelMessage {
        link_id: [u8; 16],
        message: Box<dyn MessageBase>,
        result_tx: Option<oneshot::Sender<Result<ChannelSendReceipt, ChannelSendError>>>,
    },
    SendLinkPacket {
        link_id: [u8; 16],
        payload: Vec<u8>,
        result_tx: Option<oneshot::Sender<Result<LinkPacketSendReceipt, LinkSendError>>>,
    },
    SendLinkResource {
        link_id: [u8; 16],
        payload: Vec<u8>,
        auto_compress: bool,
        result_tx: Option<oneshot::Sender<Result<LinkResourceSendReceipt, LinkSendError>>>,
    },
    SendLinkPayload {
        link_id: [u8; 16],
        payload: Vec<u8>,
        auto_compress: bool,
        result_tx: Option<oneshot::Sender<Result<LinkPayloadSendReceipt, LinkSendError>>>,
    },
    CancelLinkResource {
        link_id: [u8; 16],
        resource_id: [u8; 32],
        direction: LinkResourceDirection,
        result_tx: Option<oneshot::Sender<bool>>,
    },
    CloseLink {
        link_id: [u8; 16],
        reason: CloseReason,
        send_teardown: bool,
    },
    /// Broadcast an announce using the manager's owned Destination.
    Announce,
    /// Broadcast an announce with the same options exposed by Python's
    /// `Destination.announce`.
    AnnounceWith {
        options: DestinationAnnounceOptions,
        result_tx: Option<oneshot::Sender<Result<(), DestinationControlError>>>,
    },
    /// Change whether the owned Destination accepts new inbound Links.
    SetAcceptsLinks {
        accepts: bool,
        result_tx: Option<oneshot::Sender<Result<(), DestinationControlError>>>,
    },
    /// Register or replace a Python-compatible per-path request handler.
    RegisterRequestHandler {
        path: String,
        allow: AllowPolicy,
        allowed_list: Vec<[u8; 16]>,
        auto_compress: bool,
        handler: DestinationRequestHandler,
        result_tx: Option<oneshot::Sender<bool>>,
    },
    /// Remove a per-path request handler.
    DeregisterRequestHandler {
        path: String,
        result_tx: Option<oneshot::Sender<bool>>,
    },
    Shutdown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestinationAnnounceOptions {
    pub app_data: Option<Vec<u8>>,
    pub path_response: bool,
    pub attached_interface: Option<rns_transport::messages::InterfaceId>,
    pub tag: Option<Vec<u8>>,
    /// Public ratchet key to advertise, when the caller manages a ratchet ring.
    pub ratchet: Option<[u8; 32]>,
}

#[derive(Debug, thiserror::Error)]
pub enum DestinationControlError {
    #[error("link manager does not own a destination")]
    DestinationUnavailable,
    #[error("link manager does not own a signing identity")]
    IdentityUnavailable,
    #[error("destination operation failed: {0}")]
    Destination(#[from] rns_identity::destination::DestinationError),
    #[error("transport channel is full or closed")]
    TransportUnavailable,
}

/// Resource hash + sender metadata (e.g. rncp filename).
#[derive(Debug, Clone)]
pub struct ResourceCompletion {
    pub link_id: [u8; 16],
    pub resource_hash: [u8; 32],
    pub data: Vec<u8>,
    /// msgpack-encoded metadata, if the sender attached any.
    pub metadata: Option<Vec<u8>>,
}

/// Result of an extended request handler. `Reply` is the ordinary response;
/// `ReplyWithResource` sends an inline ack followed by a resource transfer
/// (rncp --fetch). Python: `RNS.Resource(..., target_link=link)`.
#[derive(Debug, Clone)]
pub enum RequestOutcome {
    Reply(Vec<u8>),
    ReplyWithResource {
        ack: Vec<u8>,
        data: Vec<u8>,
        /// Optional msgpack-encoded metadata (e.g. `{"name": "file.bin"}`).
        metadata: Option<Vec<u8>>,
        auto_compress: bool,
    },
    /// Silently drop; caller sees a timeout. Useful for ACL denies.
    Drop,
}

/// Python-compatible context supplied to a per-path Destination request handler.
#[derive(Clone)]
pub struct DestinationRequest {
    pub path: String,
    pub data: Vec<u8>,
    pub request_id: [u8; 16],
    pub link_id: [u8; 16],
    pub remote_identity: Option<Identity>,
    pub requested_at: f64,
}

pub type DestinationRequestHandler =
    Box<dyn Fn(DestinationRequest) -> RequestOutcome + Send + 'static>;

type RequestHandler = Box<dyn Fn([u8; 16], [u8; 16], Vec<u8>) -> Option<Vec<u8>> + Send>;
type RequestHandlerEx = Box<dyn Fn([u8; 16], [u8; 16], Vec<u8>) -> RequestOutcome + Send>;
type LinkIdentityGate = Box<dyn Fn([u8; 16], [u8; 16]) -> bool + Send>;
type ResourceAcceptHandler = Box<dyn Fn([u8; 16], &ResourceAdvertisement) -> bool + Send>;

struct RegisteredRequestHandler {
    path: String,
    allow: AllowPolicy,
    allowed_list: Vec<[u8; 16]>,
    auto_compress: bool,
    handler: DestinationRequestHandler,
}

struct ResourceTransferStart {
    data: Vec<u8>,
    metadata: Option<Vec<u8>>,
    auto_compress: bool,
    request_id: Option<Vec<u8>>,
    is_response: bool,
    allow_handshake: bool,
}

pub struct LinkManager {
    transport_tx: mpsc::Sender<TransportMessage>,
    event_rx: mpsc::Receiver<DestinationEvent>,
    active_links: HashMap<[u8; 16], ActiveLink>,
    /// Raw software signing key, when available. Hardware-backed identities sign
    /// through `identity` instead.
    identity_key: Option<Ed25519PrivateKey>,
    pub destination_hash: [u8; 16],
    destination: Option<Destination>,
    identity: Option<Identity>,
    /// `(link_id, path_hash, data) -> Option<response>`.
    request_handler: Option<RequestHandler>,
    /// Wins over `request_handler` when set; can schedule a resource transfer.
    request_handler_ex: Option<RequestHandlerEx>,
    /// Python-compatible Destination handlers keyed by truncated path hash.
    destination_request_handlers: HashMap<[u8; 16], RegisteredRequestHandler>,
    /// Accepted request Resources keyed by `(link_id, original_hash)`.
    pending_inbound_request_resources: HashSet<([u8; 16], [u8; 32])>,
    /// Called when the transport actor asks this destination to re-announce.
    announce_handler: Option<Box<dyn FnMut() + Send>>,
    response_tx: Option<mpsc::Sender<LinkResponse>>,
    /// Legacy LXMF completion notifier.
    resource_completed_tx: Option<mpsc::Sender<(Vec<u8>, [u8; 16])>>,
    /// Resource hash + metadata.
    resource_completion_tx: Option<mpsc::Sender<ResourceCompletion>>,
    /// Default policy applied to current and future responder Links. AcceptAll
    /// preserves the established LXMF DIRECT behavior.
    resource_strategy: ResourceStrategy,
    /// Application decision hook used only when the strategy is AcceptApp.
    resource_accept_handler: Option<ResourceAcceptHandler>,
    /// Fires when a link reaches the active state.
    link_established_tx: Option<mpsc::Sender<[u8; 16]>>,
    /// Fires on LinkIdentify before a resource ADV can race it.
    link_identified_tx: Option<mpsc::Sender<([u8; 16], [u8; 16])>>,
    /// Synchronous LinkIdentify gate. Returning false closes the link before
    /// later resource packets can be accepted.
    link_identity_gate: Option<LinkIdentityGate>,
    /// Decrypted link-packet stream (LXMF DIRECT).
    link_packet_tx: Option<mpsc::Sender<(Vec<u8>, [u8; 16])>>,
    /// Valid proof for an application link packet sent through this manager.
    link_packet_proof_tx: Option<mpsc::Sender<LinkPacketProof>>,
    /// Valid proof for an application resource sent through this manager.
    outbound_resource_proof_tx: Option<mpsc::Sender<LinkResourceProof>>,
    /// Unified inbound/outbound Resource lifecycle.
    resource_event_tx: Option<mpsc::Sender<LinkResourceEvent>>,
    /// Decrypted channel envelopes as `(link_id, msg_type, payload)`.
    channel_message_tx: Option<mpsc::Sender<LinkChannelMessage>>,
    /// Fires when an active link is closed or torn down.
    link_closed_tx: Option<mpsc::Sender<[u8; 16]>>,
    /// Raw pass-through for non-link packets (e.g. opportunistic LXMF).
    inbound_raw_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Whether destination delivery proofs contain only the signature.
    use_implicit_proof: bool,
    /// Remote identity hash → link_id; populated on LinkIdentify for outbound reuse.
    backchannel_links: HashMap<[u8; 16], [u8; 16]>,
    /// Shared reverse map so sync request handlers can look up the authenticated peer.
    link_identities: Arc<Mutex<HashMap<[u8; 16], [u8; 16]>>>,
}

impl LinkManager {
    pub fn new(
        transport_tx: mpsc::Sender<TransportMessage>,
        event_rx: mpsc::Receiver<DestinationEvent>,
        destination_hash: [u8; 16],
        identity_key: Option<Ed25519PrivateKey>,
    ) -> Self {
        Self {
            transport_tx,
            event_rx,
            active_links: HashMap::new(),
            identity_key,
            destination_hash,
            destination: None,
            identity: None,
            request_handler: None,
            request_handler_ex: None,
            destination_request_handlers: HashMap::new(),
            pending_inbound_request_resources: HashSet::new(),
            announce_handler: None,
            response_tx: None,
            resource_completed_tx: None,
            resource_completion_tx: None,
            resource_strategy: ResourceStrategy::AcceptAll,
            resource_accept_handler: None,
            link_established_tx: None,
            link_identified_tx: None,
            link_identity_gate: None,
            link_packet_tx: None,
            link_packet_proof_tx: None,
            outbound_resource_proof_tx: None,
            resource_event_tx: None,
            channel_message_tx: None,
            link_closed_tx: None,
            inbound_raw_tx: None,
            use_implicit_proof: true,
            backchannel_links: HashMap::new(),
            link_identities: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Wraps its own [`Destination`] so acceptance gating + dest callbacks are active.
    pub fn with_destination(
        transport_tx: mpsc::Sender<TransportMessage>,
        event_rx: mpsc::Receiver<DestinationEvent>,
        identity: &Identity,
        app_name: &str,
        // `None` for hardware-backed identities (no extractable signing key);
        // link proofs are routed through the backend-aware `Identity`.
        identity_key: Option<Ed25519PrivateKey>,
    ) -> Self {
        let dest = match Destination::new(Some(identity), Direction::In, DestType::Single, app_name)
        {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::error!(error = %e, app_name, "Destination::new() failed — link manager will not accept links");
                None
            }
        };

        let destination_hash = dest.as_ref().map(|d| d.hash).unwrap_or([0; 16]);
        let manager_identity = clone_identity(identity);

        Self {
            transport_tx,
            event_rx,
            active_links: HashMap::new(),
            identity_key,
            destination_hash,
            destination: dest,
            identity: manager_identity,
            request_handler: None,
            request_handler_ex: None,
            destination_request_handlers: HashMap::new(),
            pending_inbound_request_resources: HashSet::new(),
            announce_handler: None,
            response_tx: None,
            resource_completed_tx: None,
            resource_completion_tx: None,
            resource_strategy: ResourceStrategy::AcceptAll,
            resource_accept_handler: None,
            link_established_tx: None,
            link_identified_tx: None,
            link_identity_gate: None,
            link_packet_tx: None,
            link_packet_proof_tx: None,
            outbound_resource_proof_tx: None,
            resource_event_tx: None,
            channel_message_tx: None,
            link_closed_tx: None,
            inbound_raw_tx: None,
            use_implicit_proof: true,
            backchannel_links: HashMap::new(),
            link_identities: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn get_backchannel_link(&self, identity_hash: &[u8; 16]) -> Option<[u8; 16]> {
        self.backchannel_links.get(identity_hash).copied()
    }

    /// Destination owned by a manager created with [`Self::with_destination`].
    pub fn destination(&self) -> Option<&Destination> {
        self.destination.as_ref()
    }

    /// Mutable destination access for installing packet/proof callbacks and
    /// selecting the destination proof strategy before the manager is run.
    pub fn destination_mut(&mut self) -> Option<&mut Destination> {
        self.destination.as_mut()
    }

    /// Match the runtime `use_implicit_proof` setting for destination proofs.
    pub fn set_use_implicit_proof(&mut self, use_implicit_proof: bool) {
        self.use_implicit_proof = use_implicit_proof;
    }

    /// Shared auth map for sync request handlers (which can't borrow `self`).
    /// Populated on `LinkIdentify`, pruned on link close.
    pub fn link_identities_handle(&self) -> Arc<Mutex<HashMap<[u8; 16], [u8; 16]>>> {
        Arc::clone(&self.link_identities)
    }

    pub fn try_step(&mut self) -> bool {
        match self.event_rx.try_recv() {
            Ok(event) => {
                self.handle_event(event);
                true
            }
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                false
            }
        }
    }

    pub async fn step(&mut self) -> bool {
        let Some(event) = self.event_rx.recv().await else {
            return false;
        };
        self.handle_event(event);
        true
    }

    pub fn tick(&mut self) {
        self.on_tick();
    }

    pub async fn run(mut self) {
        let mut tick_interval = tokio::time::interval(std::time::Duration::from_secs(1));

        loop {
            tokio::select! {
                event = self.event_rx.recv() => {
                    match event {
                        Some(evt) => self.handle_event(evt),
                        None => break,
                    }
                }
                _ = tick_interval.tick() => {
                    self.tick();
                }
            }
        }
    }

    pub async fn run_with_commands(mut self, mut command_rx: mpsc::Receiver<LinkManagerCommand>) {
        let mut last_tick = std::time::Instant::now();
        loop {
            while let Ok(command) = command_rx.try_recv() {
                if !self.handle_command(command) {
                    return;
                }
            }

            while self.try_step() {}

            if last_tick.elapsed() >= std::time::Duration::from_secs(1) {
                self.tick();
                last_tick = std::time::Instant::now();
            }

            if command_rx.is_closed() && command_rx.is_empty() {
                return;
            }

            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    fn handle_command(&mut self, command: LinkManagerCommand) -> bool {
        match command {
            LinkManagerCommand::SendChannelMessage {
                link_id,
                message,
                result_tx,
            } => {
                let result = self.send_channel_message(&link_id, message.as_ref());
                if let Some(tx) = result_tx {
                    let _ = tx.send(result);
                }
                true
            }
            LinkManagerCommand::SendLinkPacket {
                link_id,
                payload,
                result_tx,
            } => {
                let result = self.send_link_packet(&link_id, &payload);
                if let Some(tx) = result_tx {
                    let _ = tx.send(result);
                }
                true
            }
            LinkManagerCommand::SendLinkResource {
                link_id,
                payload,
                auto_compress,
                result_tx,
            } => {
                let result = self.send_link_resource(&link_id, payload, auto_compress);
                if let Some(tx) = result_tx {
                    let _ = tx.send(result);
                }
                true
            }
            LinkManagerCommand::SendLinkPayload {
                link_id,
                payload,
                auto_compress,
                result_tx,
            } => {
                let result = self.send_link_payload(&link_id, payload, auto_compress);
                if let Some(tx) = result_tx {
                    let _ = tx.send(result);
                }
                true
            }
            LinkManagerCommand::CancelLinkResource {
                link_id,
                resource_id,
                direction,
                result_tx,
            } => {
                let result = self.cancel_link_resource(&link_id, &resource_id, direction);
                if let Some(tx) = result_tx {
                    let _ = tx.send(result);
                }
                true
            }
            LinkManagerCommand::CloseLink {
                link_id,
                reason,
                send_teardown,
            } => {
                self.close_active_link(link_id, reason, send_teardown);
                true
            }
            LinkManagerCommand::Announce => {
                if let Some(handler) = self.announce_handler.as_mut() {
                    handler();
                } else {
                    let app_name = self
                        .destination
                        .as_ref()
                        .map(|destination| destination.app_name.clone())
                        .unwrap_or_default();
                    let _ = self.send_destination_announce(
                        AnnounceRequest::normal(app_name),
                        None,
                        None,
                    );
                }
                true
            }
            LinkManagerCommand::AnnounceWith { options, result_tx } => {
                let app_name = self
                    .destination
                    .as_ref()
                    .map(|destination| destination.app_name.clone())
                    .unwrap_or_default();
                let request = AnnounceRequest {
                    app_name,
                    path_response: options.path_response,
                    tag: options.tag,
                    attached_interface: options.attached_interface,
                };
                let result = self.send_destination_announce(
                    request,
                    options.app_data.as_deref(),
                    options.ratchet.as_ref(),
                );
                if let Some(tx) = result_tx {
                    let _ = tx.send(result);
                }
                true
            }
            LinkManagerCommand::SetAcceptsLinks { accepts, result_tx } => {
                let result = self
                    .destination
                    .as_mut()
                    .ok_or(DestinationControlError::DestinationUnavailable)
                    .map(|destination| destination.set_accepts_links(accepts));
                if let Some(tx) = result_tx {
                    let _ = tx.send(result);
                }
                true
            }
            LinkManagerCommand::RegisterRequestHandler {
                path,
                allow,
                allowed_list,
                auto_compress,
                handler,
                result_tx,
            } => {
                let result = self.register_request_handler_boxed(
                    &path,
                    allow,
                    allowed_list,
                    auto_compress,
                    handler,
                );
                if let Some(tx) = result_tx {
                    let _ = tx.send(result);
                }
                true
            }
            LinkManagerCommand::DeregisterRequestHandler { path, result_tx } => {
                let result = self.deregister_request_handler(&path);
                if let Some(tx) = result_tx {
                    let _ = tx.send(result);
                }
                true
            }
            LinkManagerCommand::Shutdown => false,
        }
    }

    fn handle_event(&mut self, event: DestinationEvent) {
        match event {
            DestinationEvent::LinkRequest { raw, interface_id } => {
                self.handle_link_request(&raw, interface_id);
            }
            DestinationEvent::InboundPacket { raw, interface_id } => {
                self.handle_inbound_packet(&raw, interface_id);
            }
            DestinationEvent::LinkEstablished { link_id } => {
                if let Some(ref tx) = self.link_established_tx {
                    let _ = tx.try_send(link_id);
                }
                tracing::debug!(link_id = hex::encode(link_id), "link established event");
            }
            DestinationEvent::LinkClosed { link_id } => {
                if self.close_active_link(link_id, CloseReason::InitiatorClosed, true) {
                    tracing::debug!(link_id = hex::encode(link_id), "link closed");
                }
            }
            DestinationEvent::DeliveryProof { msg_id, .. } => {
                tracing::debug!(msg_id = %msg_id, "delivery proof (unhandled in link manager)");
            }
            DestinationEvent::AnnounceRequested(request) => {
                if request.path_response {
                    let _ = self.send_destination_announce(request, None, None);
                } else if let Some(handler) = self.announce_handler.as_mut() {
                    handler();
                } else {
                    let _ = self.send_destination_announce(request, None, None);
                }
            }
        }
    }

    fn send_destination_announce(
        &mut self,
        request: AnnounceRequest,
        app_data: Option<&[u8]>,
        ratchet: Option<&[u8; 32]>,
    ) -> Result<(), DestinationControlError> {
        let Some(destination) = self.destination.as_mut() else {
            tracing::debug!(
                app_name = %request.app_name,
                path_response = request.path_response,
                "announce requested but no destination is configured"
            );
            return Err(DestinationControlError::DestinationUnavailable);
        };
        let Some(identity) = self.identity.as_ref() else {
            tracing::warn!(
                app_name = %request.app_name,
                path_response = request.path_response,
                "announce requested but no private identity is available"
            );
            return Err(DestinationControlError::IdentityUnavailable);
        };

        let raw = destination.announce_packet(
            identity,
            app_data,
            ratchet,
            request.path_response,
            request.tag.as_deref(),
            unix_now(),
        )?;

        let outbound = OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: self.destination_hash,
        };
        let message = if let Some(interface_id) = request.attached_interface {
            TransportMessage::OutboundAttached {
                request: outbound,
                interface_id,
            }
        } else {
            TransportMessage::Outbound(outbound)
        };
        if let Err(error) = self.transport_tx.try_send(message) {
            tracing::warn!(
                app_name = %request.app_name,
                path_response = request.path_response,
                err = %error,
                "failed to queue requested announce"
            );
            return Err(DestinationControlError::TransportUnavailable);
        }
        Ok(())
    }

    fn handle_link_request(&mut self, raw: &[u8], interface_id: u64) {
        let (header, data_offset) = match rns_wire::header::PacketHeader::unpack(raw) {
            Ok(h) => h,
            Err(_) => return,
        };

        if raw.len() <= data_offset {
            tracing::warn!("link request has no payload data");
            return;
        }
        let request_data = &raw[data_offset..];

        let hops = header.hops;

        if let Some(ref dest) = self.destination {
            if !dest.accept_link_requests {
                tracing::debug!("link request rejected — destination not accepting links");
                return;
            }
        }

        let responder = match (&self.identity_key, &self.identity) {
            (Some(identity_key), _) => {
                Link::new_responder(request_data, identity_key, self.destination_hash, hops)
            }
            (None, Some(identity)) => {
                let identity_ed25519_pub = identity_ed25519_public_key(identity);
                Link::new_responder_with(
                    request_data,
                    &identity_ed25519_pub,
                    self.destination_hash,
                    hops,
                    |signed_data| identity.sign(signed_data),
                )
            }
            (None, None) => {
                tracing::warn!("link request received but no identity signer configured");
                return;
            }
        };
        let (link, proof_data) = match responder {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(error = %e, "link handshake failed");
                return;
            }
        };

        let link_id = link.link_id;

        let proof_flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Proof,
        };
        // Hops = 0 at origin (Python `Packet.__init__`).
        let proof_hops = 0;
        let proof_header = rns_wire::header::PacketHeader {
            flags: proof_flags,
            hops: proof_hops,
            transport_id: None,
            destination_hash: link_id,
            context: rns_wire::context::PacketContext::Lrproof,
        };
        let mut proof_raw = proof_header.pack();
        proof_raw.extend_from_slice(&proof_data);

        tracing::info!(
            link_id = hex::encode(link_id),
            proof_len = proof_raw.len(),
            proof_data_len = proof_data.len(),
            "link proof packet built"
        );

        let _ = self
            .transport_tx
            .try_send(TransportMessage::Outbound(OutboundRequest {
                raw: Bytes::from(proof_raw),
                destination_hash: link_id,
            }));

        // Required: transport drops link-addressed packets (LRRTT, Resource,
        // Keepalive...) as unroutable without this registration.
        let _ = self.transport_tx.try_send(TransportMessage::RegisterLink {
            link_id,
            destination_hash: self.destination_hash,
            interface_id,
            next_hop: None,
            remaining_hops: 0,
            initiator: false,
        });

        tracing::info!(
            link_id = hex::encode(link_id),
            dest = hex::encode(self.destination_hash),
            request_hops = hops,
            "link request handled — ECDH handshake complete, proof sent, link registered"
        );

        if let Some(ref mut dest) = self.destination {
            dest.incoming_link_request(link_id);
        }

        // LXMF DIRECT uses resource transfer past `LINK_PACKET_MAX_CONTENT`;
        // the manager default remains AcceptAll for backwards compatibility,
        // but applications can explicitly select Python-style policies.
        let mut link = link;
        link.resource_strategy = self.resource_strategy;

        self.active_links.insert(
            link_id,
            ActiveLink {
                link,
                _interface_id: interface_id,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );
    }

    fn handle_inbound_packet(&mut self, raw: &[u8], interface_id: u64) {
        let (header, data_offset) = match rns_wire::header::PacketHeader::unpack(raw) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, raw_len = raw.len(), "link_manager: packet header parse failed");
                return;
            }
        };

        let data = if raw.len() > data_offset {
            &raw[data_offset..]
        } else {
            &[]
        };

        // For link packets `destination_hash` is the link_id; otherwise it's
        // a destination-level packet for app decryption (opportunistic LXMF).
        let link_id = header.destination_hash;

        if !self.active_links.contains_key(&link_id) {
            let processed = self.dispatch_destination_packet(raw, interface_id);
            if let Some(ref tx) = self.inbound_raw_tx {
                let _ = tx.try_send(raw.to_vec());
            }
            tracing::debug!(
                dest = hex::encode(link_id),
                data_len = data.len(),
                processed,
                "link_manager: non-link packet forwarded to application (raw)"
            );
            return;
        }

        let Some(attached_interface) = self
            .active_links
            .get(&link_id)
            .map(|active| active._interface_id)
        else {
            return;
        };
        if interface_id != attached_interface {
            tracing::warn!(
                link_id = %hex::encode(link_id),
                interface_id,
                attached_interface,
                "link packet ignored on unexpected interface"
            );
            return;
        }

        tracing::info!(
            link_id = hex::encode(link_id),
            context = ?header.context,
            data_len = data.len(),
            "inbound link packet"
        );

        if header.flags.packet_type == rns_wire::flags::PacketType::Proof
            && matches!(
                header.context,
                rns_wire::context::PacketContext::None
                    | rns_wire::context::PacketContext::LinkProof
            )
        {
            self.handle_link_packet_proof(link_id, data);
            return;
        }

        let mut completed_request_resource = None;

        match header.context {
            rns_wire::context::PacketContext::Lrrtt => {
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_rx(data.len());
                    if active.link.state == LinkState::Handshake {
                        match active.link.receive_rtt_packet(data) {
                            Ok(()) => {
                                // +1 mirrors Python's increment-on-receive
                                // (Transport.py:1491) before Link.py:525 reads
                                // packet.hops; the delivered raw is unadjusted.
                                active.link.expected_hops = Some(header.hops.saturating_add(1));
                                tracing::info!(
                                    link_id = hex::encode(link_id),
                                    rtt_ms = active.link.rtt.map(|r| r.as_millis()).unwrap_or(0),
                                    "link activated via LRRTT"
                                );

                                if let Some(ref cb) = active.link.link_established_callback {
                                    cb(&active.link);
                                }
                                if let Some(ref dest) = self.destination {
                                    dest.on_link_established(link_id);
                                }
                                if let Some(ref tx) = self.link_established_tx {
                                    let _ = tx.try_send(link_id);
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    link_id = hex::encode(link_id),
                                    error = %e,
                                    "LRRTT processing failed"
                                );
                            }
                        }
                    }
                }
            }
            rns_wire::context::PacketContext::LinkIdentify => {
                let mut close_rejected_link = false;
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_rx(data.len());
                    // First-identity-wins (1.3.9): capture prior state so a repeat
                    // identification is treated as a no-op rather than re-tracking
                    // the peer and re-firing identity side effects.
                    let was_identified = active.link.identified;
                    match active.link.handle_identification(data) {
                        Ok(_) if was_identified => {
                            tracing::debug!(
                                link_id = hex::encode(link_id),
                                "ignoring repeat link identification (first-identity-wins)"
                            );
                        }
                        Ok(remote_pub) => {
                            let identity_hash = rns_crypto::sha::truncated_hash(&remote_pub);
                            let accepted = self
                                .link_identity_gate
                                .as_ref()
                                .map(|gate| gate(link_id, identity_hash))
                                .unwrap_or(true);
                            self.backchannel_links.insert(identity_hash, link_id);
                            if let Ok(mut ids) = self.link_identities.lock() {
                                ids.insert(link_id, identity_hash);
                            }
                            if let Some(ref tx) = self.link_identified_tx {
                                let _ = tx.try_send((link_id, identity_hash));
                            }
                            tracing::info!(
                                link_id = hex::encode(link_id),
                                remote_pub = hex::encode(&remote_pub[..8]),
                                identity_hash = hex::encode(identity_hash),
                                "remote peer identified on link — backchannel tracked"
                            );
                            if let Some(ref cb) = active.link.remote_identified_callback {
                                cb(&active.link, &remote_pub);
                            }
                            if !accepted {
                                close_rejected_link = true;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                link_id = hex::encode(link_id),
                                error = %e,
                                "link identification failed"
                            );
                        }
                    }
                }
                if close_rejected_link {
                    let _ = self.close_active_link(link_id, CloseReason::InitiatorClosed, true);
                }
            }
            rns_wire::context::PacketContext::Keepalive => {
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_inbound();
                    active.link.record_rx(data.len());

                    // Keepalives are NOT encrypted (Packet.py:205-208).
                    if data.first() == Some(&rns_link::constants::KEEPALIVE_REQUEST) {
                        // Only the responder replies.
                        if active.link.is_initiator {
                            tracing::trace!(
                                link_id = hex::encode(link_id),
                                "ignoring keepalive request on initiator side"
                            );
                        } else {
                            let resp_header = rns_wire::header::PacketHeader {
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
                                context: rns_wire::context::PacketContext::Keepalive,
                            };
                            let mut resp_raw = resp_header.pack();
                            resp_raw.push(rns_link::constants::KEEPALIVE_RESPONSE);
                            active.link.record_tx_keepalive(1);
                            let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                                OutboundRequest {
                                    raw: Bytes::from(resp_raw),
                                    destination_hash: link_id,
                                },
                            ));
                        }
                    }
                }
            }
            rns_wire::context::PacketContext::LinkClose => {
                let verified = self.active_links.get_mut(&link_id).is_some_and(|active| {
                    active.link.record_rx(data.len());
                    active.link.receive_teardown(data)
                });
                if verified {
                    tracing::info!(link_id = hex::encode(link_id), "link torn down by remote");
                    self.close_active_link(link_id, CloseReason::DestinationClosed, false);
                }
            }
            rns_wire::context::PacketContext::Channel => {
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_inbound();
                    active.link.record_rx(data.len());

                    if !matches!(active.link.state, LinkState::Active | LinkState::Stale) {
                        tracing::debug!(
                            link_id = hex::encode(link_id),
                            state = ?active.link.state,
                            "channel data received before active link"
                        );
                        return;
                    }

                    if active.channel.is_none()
                        && Self::ensure_link_channel(active, link_id).is_none()
                    {
                        tracing::debug!(
                            link_id = hex::encode(link_id),
                            "channel data received before session keys were available"
                        );
                        return;
                    }

                    let pkt_hash = rns_wire::hash::packet_hash(raw, header.flags.header_type);
                    if let Ok(proof_data) = active.link.prove_packet_with_link_key(&pkt_hash) {
                        Self::send_link_packet_proof(
                            &self.transport_tx,
                            &link_id,
                            &proof_data,
                            rns_wire::context::PacketContext::None,
                        );
                        // Proofs to a link count into txbytes (Link.py:388, Packet.py:291).
                        active.link.record_tx(proof_data.len());
                        tracing::debug!(
                            link_id = hex::encode(link_id),
                            proof_len = proof_data.len(),
                            "delivery proof sent for channel packet"
                        );
                    }

                    if let Some(ref mut channel) = active.channel {
                        match channel.receive_data(data) {
                            Ok(messages) => {
                                if let Some(ref tx) = self.channel_message_tx {
                                    for (msg_type, payload) in messages {
                                        let _ = tx.try_send(LinkChannelMessage {
                                            link_id,
                                            msg_type,
                                            payload,
                                        });
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    link_id = hex::encode(link_id),
                                    error = %e,
                                    "channel data processing failed"
                                );
                            }
                        }
                    }
                }
            }
            rns_wire::context::PacketContext::ResourceAdv => {
                // A successfully-decrypted but unparseable advertisement means the
                // peer is misbehaving, so tear the link down (1.3.9's dispatch-
                // exception teardown). Decrypt failures stay a silent drop, and the
                // Rust-specific segment-metadata guards below stay a silent reject so
                // a peer cannot kill an established link by racing bad split metadata.
                let mut teardown_link = false;
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_inbound();
                    active.link.record_rx(data.len());

                    if let Ok(plaintext) = active.link.decrypt(data) {
                        'adv: {
                            let adv = match ResourceAdvertisement::unpack(&plaintext) {
                                Ok(adv) => adv,
                                Err(e) => {
                                    tracing::warn!(
                                        link_id = hex::encode(link_id),
                                        error = %e,
                                        "tearing down link: unparseable resource advertisement"
                                    );
                                    teardown_link = true;
                                    break 'adv;
                                }
                            };

                            // Request-resources (a REQUEST carried as a resource) are
                            // accepted only when this destination has request handlers
                            // registered (1.3.9); otherwise ignore without teardown.
                            if adv.flags.is_request
                                && self.request_handler.is_none()
                                && self.request_handler_ex.is_none()
                                && self.destination_request_handlers.is_empty()
                            {
                                tracing::debug!(
                                    link_id = hex::encode(link_id),
                                    "ignoring inbound request-resource: no request handlers registered"
                                );
                                break 'adv;
                            }

                            // Python always accepts request/response Resources
                            // through their dedicated receipt paths. Ordinary
                            // Resources follow the configured Link policy.
                            if !adv.flags.is_request && !adv.flags.is_response {
                                match self.resource_strategy {
                                    ResourceStrategy::AcceptAll => {}
                                    ResourceStrategy::AcceptNone => {
                                        tracing::debug!(
                                            link_id = hex::encode(link_id),
                                            resource = hex::encode(&adv.resource_hash[..8]),
                                            "ignoring inbound Resource advertisement by policy"
                                        );
                                        break 'adv;
                                    }
                                    ResourceStrategy::AcceptApp => {
                                        let accepted = self
                                            .resource_accept_handler
                                            .as_ref()
                                            .is_some_and(|handler| handler(link_id, &adv));
                                        if !accepted {
                                            let sent = Self::send_resource_action(
                                                &self.transport_tx,
                                                active,
                                                &link_id,
                                                TransferAction::SendCancel(
                                                    rns_protocol::resource::CancelType::Rcl,
                                                    adv.resource_hash,
                                                ),
                                            );
                                            tracing::debug!(
                                                link_id = hex::encode(link_id),
                                                resource = hex::encode(&adv.resource_hash[..8]),
                                                cancel_sent = sent,
                                                "inbound Resource advertisement rejected by application"
                                            );
                                            break 'adv;
                                        }
                                    }
                                }
                            }

                            // Split-resource routing set up before the per-segment
                            // transfer. The MAX_SEGMENTS cap is load-bearing: a peer
                            // could otherwise advertise u32::MAX and OOM
                            // `MultiSegmentInbound::new`.
                            if adv.total_segments > 1 {
                                if adv.total_segments > MAX_SEGMENTS
                                    || adv.segment_index == 0
                                    || adv.segment_index > adv.total_segments
                                {
                                    tracing::warn!(
                                        link_id = hex::encode(link_id),
                                        total_segments = adv.total_segments,
                                        segment_index = adv.segment_index,
                                        max_segments = MAX_SEGMENTS,
                                        "rejecting split-resource ADV with out-of-range segment metadata"
                                    );
                                    break 'adv;
                                }
                                // Mid-stream changes to `total_segments` are rejected.
                                let entry = active
                                    .inbound_split_resources
                                    .entry(adv.original_hash)
                                    .or_insert_with(|| {
                                        MultiSegmentInbound::new(
                                            adv.total_segments,
                                            adv.original_hash,
                                        )
                                    });
                                if entry.total_segments != adv.total_segments {
                                    tracing::warn!(
                                        link_id = hex::encode(link_id),
                                        original = hex::encode(&adv.original_hash[..8]),
                                        coord_total = entry.total_segments,
                                        adv_total = adv.total_segments,
                                        "split-resource ADV total_segments mismatched coordinator; ignoring"
                                    );
                                    break 'adv;
                                }
                                active.segment_routing.insert(
                                    adv.resource_hash,
                                    SegmentRoute {
                                        original_hash: adv.original_hash,
                                        segment_index: adv.segment_index,
                                    },
                                );
                            }

                            let map_hashes = adv.get_map_hashes();
                            let mut transfer_flags = adv.flags;
                            if adv.total_segments > 1 && adv.segment_index > 1 {
                                transfer_flags.has_metadata = false;
                            }
                            let rtt = active
                                .link
                                .rtt
                                .unwrap_or(std::time::Duration::from_millis(500));
                            let mut rh = [0u8; rns_protocol::resource::RANDOM_HASH_SIZE];
                            let copy_len = adv.random_hash.len().min(rh.len());
                            rh[..copy_len].copy_from_slice(&adv.random_hash[..copy_len]);

                            if let Ok(mut transfer) = InboundTransfer::from_advertisement(
                                adv.num_parts,
                                adv.transfer_size,
                                adv.data_size,
                                rh,
                                adv.resource_hash,
                                transfer_flags,
                                map_hashes,
                                rtt,
                            ) {
                                if adv.flags.is_request {
                                    self.pending_inbound_request_resources
                                        .insert((link_id, adv.original_hash));
                                }

                                // Python Resource.accept → request_next: initial request
                                // accepts the ADV and names the parts.
                                let action = transfer.request_next();
                                if let TransferAction::SendRequest(req_data) = action {
                                    if let Ok(encrypted) = active.link.encrypt(&req_data) {
                                        let req_header = rns_wire::header::PacketHeader {
                                            flags: rns_wire::flags::PacketFlags {
                                                header_type: rns_wire::flags::HeaderType::Header1,
                                                context_flag: false,
                                                transport_type:
                                                    rns_wire::flags::TransportType::Broadcast,
                                                destination_type:
                                                    rns_wire::flags::DestinationType::Link,
                                                packet_type: rns_wire::flags::PacketType::Data,
                                            },
                                            hops: 0,
                                            transport_id: None,
                                            destination_hash: link_id,
                                            context: rns_wire::context::PacketContext::ResourceReq,
                                        };
                                        let mut req_raw = req_header.pack();
                                        req_raw.extend_from_slice(&encrypted);
                                        let _ = self.transport_tx.try_send(
                                            TransportMessage::Outbound(OutboundRequest {
                                                raw: Bytes::from(req_raw),
                                                destination_hash: link_id,
                                            }),
                                        );
                                    }
                                }

                                active.link.track_incoming_resource(adv.resource_hash);
                                active.inbound_resources.insert(adv.resource_hash, transfer);
                                if adv.segment_index == 1 {
                                    Self::emit_resource_event(
                                        &self.resource_event_tx,
                                        LinkResourceEvent::Started {
                                            link_id,
                                            resource_id: if adv.total_segments > 1 {
                                                adv.original_hash
                                            } else {
                                                adv.resource_hash
                                            },
                                            direction: LinkResourceDirection::Inbound,
                                            data_size: adv.data_size,
                                            total_segments: adv.total_segments,
                                        },
                                    );
                                }
                                tracing::info!(
                                    link_id = hex::encode(link_id),
                                    resource = hex::encode(&adv.resource_hash[..8]),
                                    parts = adv.num_parts,
                                    "inbound resource accepted — initial request sent"
                                );
                            }
                        }
                    }
                }
                if teardown_link {
                    let _ = self.close_active_link(link_id, CloseReason::DestinationClosed, true);
                }
            }
            rns_wire::context::PacketContext::Resource => {
                // Python encrypts payload ONCE before chunking (Resource.py:424);
                // chunks ride raw. Decrypt happens in InboundTransfer::complete.
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_inbound();
                    active.link.record_rx(data.len());

                    {
                        let plaintext = data.to_vec();
                        let mut resource_action_to_send = None;
                        let mut completed_rh = None;
                        let mut progressed_rh = None;
                        for (rh, transfer) in &mut active.inbound_resources {
                            let progress_before = transfer.progress();
                            let action = transfer.receive_part(plaintext.clone());
                            tracing::info!(
                                link_id = hex::encode(link_id),
                                resource = hex::encode(&rh[..8]),
                                action = ?action,
                                is_complete = transfer.resource.is_complete(),
                                total_parts = transfer.resource.total_parts,
                                received = transfer.resource.consecutive_completed,
                                "resource part received — action"
                            );
                            match action {
                                TransferAction::SendHmu(_) | TransferAction::SendRequest(_) => {
                                    resource_action_to_send = Some(action);
                                }
                                TransferAction::Complete => {
                                    completed_rh = Some(*rh);
                                }
                                _ => {}
                            }
                            if completed_rh.is_none() && transfer.resource.is_complete() {
                                completed_rh = Some(*rh);
                            }
                            if transfer.progress() > progress_before {
                                progressed_rh = Some(*rh);
                            }
                            if resource_action_to_send.is_some() || completed_rh.is_some() {
                                break;
                            }
                        }

                        if let Some(resource_hash) = progressed_rh {
                            Self::emit_inbound_resource_progress(
                                &self.resource_event_tx,
                                active,
                                link_id,
                                resource_hash,
                            );
                        }

                        if let Some(action) = resource_action_to_send {
                            let (context, payload) = match action {
                                TransferAction::SendHmu(hmu) => {
                                    (rns_wire::context::PacketContext::ResourceHmu, hmu)
                                }
                                TransferAction::SendRequest(req) => {
                                    (rns_wire::context::PacketContext::ResourceReq, req)
                                }
                                _ => unreachable!(),
                            };
                            if let Ok(encrypted) = active.link.encrypt(&payload) {
                                let hmu_header = rns_wire::header::PacketHeader {
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
                                let mut hmu_raw = hmu_header.pack();
                                hmu_raw.extend_from_slice(&encrypted);
                                active.link.record_tx(encrypted.len());
                                let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                                    OutboundRequest {
                                        raw: Bytes::from(hmu_raw),
                                        destination_hash: link_id,
                                    },
                                ));
                            }
                        }

                        if let Some(rh) = completed_rh {
                            // Reverses pre-chunk encryption (Resource.py:424).
                            let decrypt_fn = |data: &[u8]| -> Result<
                                Vec<u8>,
                                rns_protocol::resource::ResourceError,
                            > {
                                active.link.decrypt(data).map_err(|_| {
                                    rns_protocol::resource::ResourceError::DecryptFailed
                                })
                            };

                            if let Some(transfer) = active.inbound_resources.get_mut(&rh) {
                                if let Ok((assembled_data, proof)) =
                                    transfer.complete(Some(&decrypt_fn))
                                {
                                    // PROOF+RESOURCE_PRF = plaintext, PacketType::Proof
                                    // (Packet.py:195-197). Each split segment still needs its
                                    // own proof or the sender retries.
                                    let prf_header = rns_wire::header::PacketHeader {
                                        flags: rns_wire::flags::PacketFlags {
                                            header_type: rns_wire::flags::HeaderType::Header1,
                                            context_flag: false,
                                            transport_type:
                                                rns_wire::flags::TransportType::Broadcast,
                                            destination_type:
                                                rns_wire::flags::DestinationType::Link,
                                            packet_type: rns_wire::flags::PacketType::Proof,
                                        },
                                        hops: 0,
                                        transport_id: None,
                                        destination_hash: link_id,
                                        context: rns_wire::context::PacketContext::ResourcePrf,
                                    };
                                    let mut prf_raw = prf_header.pack();
                                    prf_raw.extend_from_slice(&proof);
                                    active.link.record_tx(proof.len());
                                    let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                                        OutboundRequest {
                                            raw: Bytes::from(prf_raw),
                                            destination_hash: link_id,
                                        },
                                    ));

                                    // Split resources route to a coordinator keyed by
                                    // `original_hash`; completion fires only on full reassembly.
                                    if let Some(route) = active.segment_routing.remove(&rh) {
                                        let seg_meta = active
                                            .inbound_resources
                                            .get(&rh)
                                            .and_then(|t| t.resource.metadata.clone());

                                        if let Some(coord) = active
                                            .inbound_split_resources
                                            .get_mut(&route.original_hash)
                                        {
                                            match coord.set_segment_data(
                                                route.segment_index,
                                                assembled_data,
                                            ) {
                                                Ok(()) => {
                                                    if let Some(meta) = seg_meta {
                                                        coord.set_metadata(meta);
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::warn!(
                                                        link_id = hex::encode(link_id),
                                                        original = hex::encode(
                                                            &route.original_hash[..8]
                                                        ),
                                                        segment = route.segment_index,
                                                        error = ?e,
                                                        "split-resource coordinator rejected segment"
                                                    );
                                                }
                                            }

                                            if coord.is_complete() {
                                                match coord.reassemble() {
                                                    Ok(blob) => {
                                                        let metadata = coord.metadata.take();
                                                        let total_segments = coord.total_segments;
                                                        let is_request = self
                                                            .pending_inbound_request_resources
                                                            .remove(&(
                                                                link_id,
                                                                route.original_hash,
                                                            ));
                                                        if is_request {
                                                            completed_request_resource = Some(blob);
                                                        } else {
                                                            if let Some(ref tx) =
                                                                self.resource_completion_tx
                                                            {
                                                                let _ = tx.try_send(
                                                                    ResourceCompletion {
                                                                        link_id,
                                                                        resource_hash: route
                                                                            .original_hash,
                                                                        data: blob.clone(),
                                                                        metadata,
                                                                    },
                                                                );
                                                            }
                                                            if let Some(ref tx) =
                                                                self.resource_completed_tx
                                                            {
                                                                let _ =
                                                                    tx.try_send((blob, link_id));
                                                            }
                                                        }
                                                        tracing::info!(
                                                            link_id = hex::encode(link_id),
                                                            original = hex::encode(
                                                                &route.original_hash[..8]
                                                            ),
                                                            total_segments,
                                                            "split-resource reassembly complete"
                                                        );
                                                        Self::emit_resource_event(
                                                            &self.resource_event_tx,
                                                            LinkResourceEvent::Concluded {
                                                                link_id,
                                                                resource_id: route.original_hash,
                                                                direction:
                                                                    LinkResourceDirection::Inbound,
                                                                conclusion:
                                                                    LinkResourceConclusion::Complete,
                                                            },
                                                        );
                                                    }
                                                    Err(e) => {
                                                        self.pending_inbound_request_resources
                                                            .remove(&(
                                                                link_id,
                                                                route.original_hash,
                                                            ));
                                                        tracing::warn!(
                                                            link_id = hex::encode(link_id),
                                                            original = hex::encode(
                                                                &route.original_hash[..8]
                                                            ),
                                                            error = ?e,
                                                            "split-resource reassembly failed"
                                                        );
                                                        Self::emit_resource_event(
                                                            &self.resource_event_tx,
                                                            LinkResourceEvent::Concluded {
                                                                link_id,
                                                                resource_id: route.original_hash,
                                                                direction:
                                                                    LinkResourceDirection::Inbound,
                                                                conclusion:
                                                                    LinkResourceConclusion::Failed(
                                                                        e.to_string(),
                                                                    ),
                                                            },
                                                        );
                                                    }
                                                }
                                                active
                                                    .inbound_split_resources
                                                    .remove(&route.original_hash);
                                            } else {
                                                tracing::debug!(
                                                    link_id = hex::encode(link_id),
                                                    original =
                                                        hex::encode(&route.original_hash[..8]),
                                                    segment = route.segment_index,
                                                    progress = coord.assembled_count(),
                                                    total = coord.total_segments,
                                                    "split-resource segment received — awaiting more"
                                                );
                                            }
                                        } else {
                                            tracing::warn!(
                                                link_id = hex::encode(link_id),
                                                original = hex::encode(&route.original_hash[..8]),
                                                "split-resource coordinator missing for completed segment"
                                            );
                                        }
                                    } else {
                                        // Single-segment path: rncp channel keeps metadata +
                                        // resource hash; the legacy LXMF channel drops both.
                                        let is_request = self
                                            .pending_inbound_request_resources
                                            .remove(&(link_id, rh));
                                        if is_request {
                                            completed_request_resource = Some(assembled_data);
                                        } else {
                                            if let Some(ref tx) = self.resource_completion_tx {
                                                let metadata = active
                                                    .inbound_resources
                                                    .get(&rh)
                                                    .and_then(|t| t.resource.metadata.clone());
                                                let _ = tx.try_send(ResourceCompletion {
                                                    link_id,
                                                    resource_hash: rh,
                                                    data: assembled_data.clone(),
                                                    metadata,
                                                });
                                            }

                                            if let Some(ref tx) = self.resource_completed_tx {
                                                let _ = tx.try_send((assembled_data, link_id));
                                            }
                                        }

                                        tracing::debug!(
                                            link_id = hex::encode(link_id),
                                            resource = hex::encode(&rh[..8]),
                                            "inbound resource transfer completed — proof sent"
                                        );
                                        Self::emit_resource_event(
                                            &self.resource_event_tx,
                                            LinkResourceEvent::Concluded {
                                                link_id,
                                                resource_id: rh,
                                                direction: LinkResourceDirection::Inbound,
                                                conclusion: LinkResourceConclusion::Complete,
                                            },
                                        );
                                    }
                                }
                            }
                            active.link.untrack_resource(&rh);
                            active.inbound_resources.remove(&rh);
                        }
                    }
                }
            }
            rns_wire::context::PacketContext::ResourceReq => {
                // Receiver's HMU for outbound transfer (Link.py:1104-1124).
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_inbound();
                    active.link.record_rx(data.len());
                    if let Ok(plaintext) = active.link.decrypt(data) {
                        if plaintext.len() > 32 {
                            // Exhaustion flag shifts the resource hash by MAPHASH_LEN.
                            let resource_hash_start =
                                if plaintext[0] == rns_protocol::resource::HASHMAP_IS_EXHAUSTED {
                                    1 + rns_protocol::resource::MAPHASH_LEN
                                } else {
                                    1
                                };
                            if plaintext.len() >= resource_hash_start + 32 {
                                let mut rh = [0u8; 32];
                                rh.copy_from_slice(
                                    &plaintext[resource_hash_start..resource_hash_start + 32],
                                );
                                let packet_hash =
                                    rns_wire::hash::packet_hash(raw, header.flags.header_type);
                                let (actions, progressed) = active
                                    .outbound_resources
                                    .get_mut(&rh)
                                    .map(|transfer| {
                                        let before = transfer.progress();
                                        let actions =
                                            transfer.handle_request_packet(packet_hash, &plaintext);
                                        (actions, transfer.progress() > before)
                                    })
                                    .unwrap_or_default();
                                for action in actions {
                                    let (context, body) = match action {
                                        TransferAction::SendPart(idx, part_data) => {
                                            tracing::trace!(
                                                link_id = hex::encode(link_id),
                                                part = idx,
                                                "sent resource part (request response)"
                                            );
                                            (
                                                rns_wire::context::PacketContext::Resource,
                                                Bytes::from(part_data),
                                            )
                                        }
                                        TransferAction::SendHmu(hmu) => {
                                            let Ok(encrypted) = active.link.encrypt(&hmu) else {
                                                continue;
                                            };
                                            (
                                                rns_wire::context::PacketContext::ResourceHmu,
                                                Bytes::from(encrypted),
                                            )
                                        }
                                        TransferAction::SendRequest(req) => {
                                            let Ok(encrypted) = active.link.encrypt(&req) else {
                                                continue;
                                            };
                                            (
                                                rns_wire::context::PacketContext::ResourceReq,
                                                Bytes::from(encrypted),
                                            )
                                        }
                                        TransferAction::SendCancel(cancel_type, resource_hash) => {
                                            let Ok(encrypted) = active.link.encrypt(&resource_hash)
                                            else {
                                                continue;
                                            };
                                            let context = match cancel_type {
                                                rns_protocol::resource::CancelType::Icl => {
                                                    rns_wire::context::PacketContext::ResourceIcl
                                                }
                                                rns_protocol::resource::CancelType::Rcl => {
                                                    rns_wire::context::PacketContext::ResourceRcl
                                                }
                                            };
                                            (context, Bytes::from(encrypted))
                                        }
                                        _ => continue,
                                    };
                                    let part_header = rns_wire::header::PacketHeader {
                                        flags: rns_wire::flags::PacketFlags {
                                            header_type: rns_wire::flags::HeaderType::Header1,
                                            context_flag: false,
                                            transport_type:
                                                rns_wire::flags::TransportType::Broadcast,
                                            destination_type:
                                                rns_wire::flags::DestinationType::Link,
                                            packet_type: rns_wire::flags::PacketType::Data,
                                        },
                                        hops: 0,
                                        transport_id: None,
                                        destination_hash: link_id,
                                        context,
                                    };
                                    let mut raw = part_header.pack();
                                    raw.extend_from_slice(&body);
                                    active.link.record_tx(body.len());
                                    let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                                        OutboundRequest {
                                            raw: Bytes::from(raw),
                                            destination_hash: link_id,
                                        },
                                    ));
                                }
                                if progressed {
                                    Self::emit_outbound_resource_progress(
                                        &self.resource_event_tx,
                                        active,
                                        link_id,
                                        rh,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            rns_wire::context::PacketContext::ResourceIcl => {
                // Sender-initiated cancel of an inbound transfer (Link.py:1135-1142).
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_inbound();
                    active.link.record_rx(data.len());
                    if let Ok(plaintext) = active.link.decrypt(data) {
                        if plaintext.len() >= 32 {
                            let mut rh = [0u8; 32];
                            rh.copy_from_slice(&plaintext[..32]);
                            let resource_id = Self::inbound_resource_identity(active, &rh).0;
                            if let Some(transfer) = active.inbound_resources.get_mut(&rh) {
                                transfer.handle_cancel();
                                Self::drop_inbound_resource(active, &rh);
                                self.pending_inbound_request_resources
                                    .remove(&(link_id, resource_id));
                                tracing::debug!(
                                    link_id = hex::encode(link_id),
                                    "RESOURCE_ICL — inbound transfer cancelled"
                                );
                                Self::emit_resource_event(
                                    &self.resource_event_tx,
                                    LinkResourceEvent::Concluded {
                                        link_id,
                                        resource_id,
                                        direction: LinkResourceDirection::Inbound,
                                        conclusion: LinkResourceConclusion::Cancelled,
                                    },
                                );
                            }
                        }
                    }
                }
            }
            rns_wire::context::PacketContext::ResourceRcl => {
                // Receiver-initiated reject of an outbound transfer (Link.py:1144-1151).
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_inbound();
                    active.link.record_rx(data.len());
                    if let Ok(plaintext) = active.link.decrypt(data) {
                        if plaintext.len() >= 32 {
                            let mut rh = [0u8; 32];
                            rh.copy_from_slice(&plaintext[..32]);
                            let resource_id = active
                                .outbound_resources
                                .get(&rh)
                                .map(Self::outbound_resource_identity)
                                .map(|identity| identity.0);
                            if let Some(resource_id) = resource_id {
                                if let Some(transfer) = active.outbound_resources.get_mut(&rh) {
                                    transfer.resource.handle_cancel();
                                }
                                active.outbound_resources.remove(&rh);
                                active.outbound_split_queues.remove(&resource_id);
                                active.link.untrack_resource(&rh);
                                tracing::debug!(
                                    link_id = hex::encode(link_id),
                                    "RESOURCE_RCL — outbound transfer rejected"
                                );
                                Self::emit_resource_event(
                                    &self.resource_event_tx,
                                    LinkResourceEvent::Concluded {
                                        link_id,
                                        resource_id,
                                        direction: LinkResourceDirection::Outbound,
                                        conclusion: LinkResourceConclusion::Rejected,
                                    },
                                );
                            }
                        }
                    }
                }
            }
            rns_wire::context::PacketContext::ResourceHmu => {
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_inbound();
                    active.link.record_rx(data.len());
                    if let Ok(plaintext) = active.link.decrypt(data) {
                        if let Ok((rh, segment, hashmap)) =
                            rns_protocol::resource::parse_hashmap_update(&plaintext)
                        {
                            if let Some(transfer) = active.inbound_resources.get_mut(&rh) {
                                let action = transfer.hashmap_update(segment, &hashmap);
                                // A solicited HMU may either request the next parts or
                                // cancel the transfer (RESOURCE_RCL) on an empty/invalid
                                // update (1.3.9).
                                let outbound = match action {
                                    TransferAction::SendRequest(req) => {
                                        active.link.encrypt(&req).ok().map(|enc| {
                                            (rns_wire::context::PacketContext::ResourceReq, enc)
                                        })
                                    }
                                    TransferAction::SendCancel(cancel_type, resource_hash) => {
                                        active.link.encrypt(&resource_hash).ok().map(|enc| {
                                            let context = match cancel_type {
                                                rns_protocol::resource::CancelType::Icl => {
                                                    rns_wire::context::PacketContext::ResourceIcl
                                                }
                                                rns_protocol::resource::CancelType::Rcl => {
                                                    rns_wire::context::PacketContext::ResourceRcl
                                                }
                                            };
                                            (context, enc)
                                        })
                                    }
                                    _ => None,
                                };
                                if let Some((context, encrypted)) = outbound {
                                    let req_header = rns_wire::header::PacketHeader {
                                        flags: rns_wire::flags::PacketFlags {
                                            header_type: rns_wire::flags::HeaderType::Header1,
                                            context_flag: false,
                                            transport_type:
                                                rns_wire::flags::TransportType::Broadcast,
                                            destination_type:
                                                rns_wire::flags::DestinationType::Link,
                                            packet_type: rns_wire::flags::PacketType::Data,
                                        },
                                        hops: 0,
                                        transport_id: None,
                                        destination_hash: link_id,
                                        context,
                                    };
                                    let mut req_raw = req_header.pack();
                                    req_raw.extend_from_slice(&encrypted);
                                    active.link.record_tx(encrypted.len());
                                    let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                                        OutboundRequest {
                                            raw: Bytes::from(req_raw),
                                            destination_hash: link_id,
                                        },
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            rns_wire::context::PacketContext::ResourcePrf => {
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_inbound();
                    // RESOURCE_PRF proofs route through Link.receive (Transport.py:2268).
                    active.link.record_rx(data.len());
                    if data.len() >= 64 {
                        let mut rh = [0u8; 32];
                        rh.copy_from_slice(&data[..32]);
                        let queue_key = active
                            .outbound_resources
                            .get(&rh)
                            .and_then(|transfer| transfer.resource.original_hash);
                        let complete = active
                            .outbound_resources
                            .get_mut(&rh)
                            .is_some_and(|transfer| transfer.handle_proof(data));
                        if complete {
                            active.outbound_resources.remove(&rh);
                            let mut started_next_segment = false;
                            let completed_resource_hash = queue_key.unwrap_or(rh);
                            if let Some(key) = queue_key {
                                let (next, empty) = if let Some(queue) =
                                    active.outbound_split_queues.get_mut(&key)
                                {
                                    let next = queue.pop_front();
                                    (next, queue.is_empty())
                                } else {
                                    (None, false)
                                };
                                if empty {
                                    active.outbound_split_queues.remove(&key);
                                }
                                if let Some(next) = next {
                                    let _ = Self::start_outbound_transfer(
                                        &self.transport_tx,
                                        active,
                                        &link_id,
                                        next,
                                    );
                                    started_next_segment = true;
                                }
                            }
                            if !started_next_segment {
                                if let Some(ref tx) = self.outbound_resource_proof_tx {
                                    let _ = tx.try_send(LinkResourceProof {
                                        link_id,
                                        resource_hash: completed_resource_hash,
                                    });
                                }
                                Self::emit_resource_event(
                                    &self.resource_event_tx,
                                    LinkResourceEvent::Concluded {
                                        link_id,
                                        resource_id: completed_resource_hash,
                                        direction: LinkResourceDirection::Outbound,
                                        conclusion: LinkResourceConclusion::Complete,
                                    },
                                );
                            }
                        }
                    }
                }
            }
            rns_wire::context::PacketContext::Request => {
                let parsed = self.active_links.get_mut(&link_id).and_then(|active| {
                    active.link.record_inbound();
                    active.link.record_rx(data.len());
                    active.link.handle_request(data).ok()
                });

                if let Some((_packed_request_id, path_hash, requested_at, request_data)) = parsed {
                    // Packet-sized requests use the truncated RNS packet hash.
                    // Resource-sized requests use the packed-request hash.
                    let request_id =
                        rns_wire::hash::truncated_packet_hash(raw, header.flags.header_type);
                    self.handle_parsed_request(
                        link_id,
                        request_id,
                        path_hash,
                        requested_at,
                        request_data,
                    );
                }
            }
            rns_wire::context::PacketContext::Response => {
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_inbound();
                    active.link.record_rx(data.len());

                    if let Ok((request_id, response_data)) = active.link.handle_response(data) {
                        tracing::debug!(
                            link_id = hex::encode(link_id),
                            request_id = hex::encode(request_id),
                            response_len = response_data.len(),
                            "link response received — delivering to caller"
                        );

                        if let Some(ref tx) = self.response_tx {
                            let _ = tx.try_send(LinkResponse {
                                link_id,
                                request_id,
                                data: response_data,
                            });
                        }
                    }
                }
            }
            _ => {
                // Application data on a link (LXMF DIRECT).
                let identity_key_bytes = self.identity_key.as_ref().map(|key| key.to_bytes());
                let identity_for_signing = if identity_key_bytes.is_none() {
                    self.identity.clone()
                } else {
                    None
                };
                if let Some(active) = self.active_links.get_mut(&link_id) {
                    active.link.record_inbound();
                    active.link.record_rx(data.len());
                    if let Ok(plaintext) = active.link.decrypt(data) {
                        if let Some(ref cb) = active.link.packet_callback {
                            cb(&plaintext);
                        }
                        if let Some(ref tx) = self.link_packet_tx {
                            let _ = tx.try_send((plaintext, link_id));
                        }
                        tracing::debug!(
                            link_id = hex::encode(link_id),
                            "link data packet decrypted and forwarded"
                        );

                        // Link proofs are unencrypted (Packet.py:198-200).
                        let pkt_hash = rns_wire::hash::packet_hash(raw, header.flags.header_type);
                        let proof = if let Some(key_bytes) = identity_key_bytes {
                            let signing_key = Ed25519PrivateKey::from_bytes(&key_bytes);
                            active.link.prove_packet(&pkt_hash, &signing_key)
                        } else if let Some(identity) = identity_for_signing.as_ref() {
                            active
                                .link
                                .prove_packet_with_fallible(&pkt_hash, |hash| identity.sign(hash))
                        } else {
                            Err(rns_link::encryption::LinkCryptoError::EncryptionFailed)
                        };
                        match proof {
                            Ok(proof_data) => {
                                let proof_header = rns_wire::header::PacketHeader {
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
                                    context: rns_wire::context::PacketContext::LinkProof,
                                };
                                let mut proof_raw = proof_header.pack();
                                proof_raw.extend_from_slice(&proof_data);
                                // Proofs to a link count into txbytes (Link.py:388, Packet.py:291).
                                active.link.record_tx(proof_data.len());
                                let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                                    OutboundRequest {
                                        raw: Bytes::from(proof_raw),
                                        destination_hash: link_id,
                                    },
                                ));
                                tracing::info!(
                                    link_id = hex::encode(link_id),
                                    proof_len = proof_data.len(),
                                    "delivery proof sent for link data packet (unencrypted)"
                                );
                            }
                            Err(_) => {
                                tracing::warn!(
                                    link_id = hex::encode(link_id),
                                    "could not sign delivery proof for link data packet"
                                );
                            }
                        }
                    }
                }
            }
        }

        if let Some(payload) = completed_request_resource {
            match Link::parse_request(&payload) {
                Ok((request_id, path_hash, requested_at, request_data)) => {
                    self.handle_parsed_request(
                        link_id,
                        request_id,
                        path_hash,
                        requested_at,
                        request_data,
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        link_id = hex::encode(link_id),
                        error = %error,
                        "completed request Resource could not be parsed"
                    );
                }
            }
        }
    }

    fn on_tick(&mut self) {
        let mut to_remove = Vec::new();

        for (link_id, active) in &mut self.active_links {
            if let Some(channel) = active.channel.as_mut() {
                channel.update_rtt(active.link.rtt_secs());
            }
            let timed_out_channel_sequences = active
                .channel
                .as_ref()
                .map(LinkChannel::timed_out_sequences)
                .unwrap_or_default();
            for sequence in timed_out_channel_sequences {
                let resend =
                    active
                        .channel
                        .as_mut()
                        .and_then(|channel| match channel.timeout(sequence) {
                            Ok(resend) => resend,
                            Err(ChannelError::MaxRetriesExceeded) => {
                                tracing::warn!(
                                    link_id = hex::encode(link_id),
                                    sequence,
                                    "channel packet exceeded max retries"
                                );
                                to_remove.push(*link_id);
                                None
                            }
                            Err(error) => {
                                tracing::warn!(
                                    link_id = hex::encode(link_id),
                                    sequence,
                                    error = %error,
                                    "channel packet retry failed"
                                );
                                None
                            }
                        });
                let Some(data) = resend else {
                    continue;
                };

                let packet_hash =
                    Self::resend_channel_data(&self.transport_tx, link_id, sequence, &data);
                if let Some(channel) = active.channel.as_mut() {
                    channel.track_outbound_packet_hash(packet_hash, sequence);
                }
                active.link.record_tx(data.len());
            }

            let inbound_watchdog_actions: Vec<([u8; 32], TransferAction)> = active
                .inbound_resources
                .iter_mut()
                .filter_map(|(resource_hash, transfer)| {
                    let action = transfer.check_timeout();
                    if matches!(action, TransferAction::None) {
                        None
                    } else {
                        Some((*resource_hash, action))
                    }
                })
                .collect();
            for (resource_hash, action) in inbound_watchdog_actions {
                if !active.inbound_resources.contains_key(&resource_hash) {
                    continue;
                }
                match action {
                    TransferAction::Failed(reason) => {
                        let resource_id = Self::inbound_resource_identity(active, &resource_hash).0;
                        Self::drop_inbound_resource(active, &resource_hash);
                        Self::emit_resource_event(
                            &self.resource_event_tx,
                            LinkResourceEvent::Concluded {
                                link_id: *link_id,
                                resource_id,
                                direction: LinkResourceDirection::Inbound,
                                conclusion: LinkResourceConclusion::Failed(reason.clone()),
                            },
                        );
                        tracing::warn!(
                            link_id = hex::encode(link_id),
                            resource = hex::encode(&resource_hash[..8]),
                            %reason,
                            "inbound resource watchdog exhausted"
                        );
                    }
                    retry => {
                        if Self::send_resource_action(&self.transport_tx, active, link_id, retry) {
                            tracing::debug!(
                                link_id = hex::encode(link_id),
                                resource = hex::encode(&resource_hash[..8]),
                                "inbound resource watchdog requested retry"
                            );
                        }
                    }
                }
            }

            let outbound_watchdog_actions: Vec<([u8; 32], TransferAction)> = active
                .outbound_resources
                .iter_mut()
                .filter_map(|(resource_hash, transfer)| {
                    let action = transfer.check_timeout();
                    if matches!(action, TransferAction::None) {
                        None
                    } else {
                        Some((*resource_hash, action))
                    }
                })
                .collect();
            for (resource_hash, action) in outbound_watchdog_actions {
                match action {
                    TransferAction::Failed(reason) => {
                        if let Some(transfer) = active.outbound_resources.remove(&resource_hash) {
                            let resource_id = Self::outbound_resource_identity(&transfer).0;
                            active.outbound_split_queues.remove(&resource_id);
                            active.link.untrack_resource(&resource_hash);
                            Self::emit_resource_event(
                                &self.resource_event_tx,
                                LinkResourceEvent::Concluded {
                                    link_id: *link_id,
                                    resource_id,
                                    direction: LinkResourceDirection::Outbound,
                                    conclusion: LinkResourceConclusion::Failed(reason.clone()),
                                },
                            );
                        }
                        tracing::warn!(
                            link_id = hex::encode(link_id),
                            resource = hex::encode(&resource_hash[..8]),
                            %reason,
                            "outbound resource watchdog exhausted"
                        );
                    }
                    retry => {
                        if Self::send_resource_action(&self.transport_tx, active, link_id, retry) {
                            tracing::debug!(
                                link_id = hex::encode(link_id),
                                resource = hex::encode(&resource_hash[..8]),
                                "outbound resource advertisement retried"
                            );
                        }
                    }
                }
            }

            if !active.inbound_resources.is_empty() || !active.outbound_resources.is_empty() {
                active.link.record_inbound();
            }
            let action = active.link.tick();
            match action {
                LinkAction::SendKeepalive => {
                    Self::send_keepalive_packet(&self.transport_tx, link_id);
                    active.link.record_tx_keepalive(1);
                }
                LinkAction::TransitionedToStale => {
                    // Python double-sends on stale transition (Link.py:797-802, initiator only).
                    if active.link.is_initiator {
                        Self::send_keepalive_packet(&self.transport_tx, link_id);
                        active.link.record_tx_keepalive(1);
                    }
                    tracing::debug!(link_id = hex::encode(link_id), "link transitioned to stale");
                }
                LinkAction::SendTeardownAndClose(ref teardown_data) => {
                    if !teardown_data.is_empty() {
                        let td_header = rns_wire::header::PacketHeader {
                            flags: rns_wire::flags::PacketFlags {
                                header_type: rns_wire::flags::HeaderType::Header1,
                                context_flag: false,
                                transport_type: rns_wire::flags::TransportType::Broadcast,
                                destination_type: rns_wire::flags::DestinationType::Link,
                                packet_type: rns_wire::flags::PacketType::Data,
                            },
                            hops: 0,
                            transport_id: None,
                            destination_hash: *link_id,
                            context: rns_wire::context::PacketContext::LinkClose,
                        };
                        let mut td_raw = td_header.pack();
                        td_raw.extend_from_slice(teardown_data);
                        let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                            OutboundRequest {
                                raw: Bytes::from(td_raw),
                                destination_hash: *link_id,
                            },
                        ));
                    }
                    to_remove.push(*link_id);
                    tracing::info!(
                        link_id = hex::encode(link_id),
                        "link stale timeout, teardown sent"
                    );
                }
                LinkAction::Closed(_) => {
                    to_remove.push(*link_id);
                }
                LinkAction::None => {}
            }
        }

        for link_id in to_remove {
            if self.close_active_link(link_id, CloseReason::Timeout, false) {
                tracing::debug!(link_id = hex::encode(link_id), "link removed by tick");
            }
        }
    }

    fn close_active_link(
        &mut self,
        link_id: [u8; 16],
        reason: CloseReason,
        send_teardown: bool,
    ) -> bool {
        let Some(mut active) = self.active_links.remove(&link_id) else {
            return false;
        };
        let inbound_resource_ids: HashSet<[u8; 32]> = active
            .inbound_resources
            .keys()
            .map(|resource_hash| Self::inbound_resource_identity(&active, resource_hash).0)
            .collect();
        let outbound_resource_ids: HashSet<[u8; 32]> = active
            .outbound_resources
            .values()
            .map(Self::outbound_resource_identity)
            .map(|identity| identity.0)
            .collect();

        if send_teardown {
            if let Some(teardown_data) = active.link.teardown(reason) {
                Self::send_link_close_packet(&self.transport_tx, &link_id, &teardown_data);
            }
        } else {
            active.link.mark_closed(reason);
        }

        if let Some(ref cb) = active.link.link_closed_callback {
            cb(&active.link);
        }

        self.backchannel_links.retain(|_, lid| *lid != link_id);
        self.pending_inbound_request_resources
            .retain(|(pending_link_id, _)| *pending_link_id != link_id);
        if let Ok(mut ids) = self.link_identities.lock() {
            ids.remove(&link_id);
        }
        let _ = self
            .transport_tx
            .try_send(TransportMessage::DeregisterDestination { hash: link_id });
        if let Some(ref tx) = self.link_closed_tx {
            let _ = tx.try_send(link_id);
        }
        let failure = format!("link closed: {reason:?}");
        for resource_id in inbound_resource_ids {
            Self::emit_resource_event(
                &self.resource_event_tx,
                LinkResourceEvent::Concluded {
                    link_id,
                    resource_id,
                    direction: LinkResourceDirection::Inbound,
                    conclusion: LinkResourceConclusion::Failed(failure.clone()),
                },
            );
        }
        for resource_id in outbound_resource_ids {
            Self::emit_resource_event(
                &self.resource_event_tx,
                LinkResourceEvent::Concluded {
                    link_id,
                    resource_id,
                    direction: LinkResourceDirection::Outbound,
                    conclusion: LinkResourceConclusion::Failed(failure.clone()),
                },
            );
        }

        true
    }

    fn send_link_close_packet(
        transport_tx: &mpsc::Sender<TransportMessage>,
        link_id: &[u8; 16],
        teardown_data: &[u8],
    ) {
        let td_header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type: rns_wire::flags::PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: *link_id,
            context: rns_wire::context::PacketContext::LinkClose,
        };
        let mut td_raw = td_header.pack();
        td_raw.extend_from_slice(teardown_data);
        let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(td_raw),
            destination_hash: *link_id,
        }));
    }

    fn send_keepalive_packet(transport_tx: &mpsc::Sender<TransportMessage>, link_id: &[u8; 16]) {
        let ka_header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type: rns_wire::flags::PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: *link_id,
            context: rns_wire::context::PacketContext::Keepalive,
        };
        let mut ka_raw = ka_header.pack();
        ka_raw.push(rns_link::constants::KEEPALIVE_REQUEST);
        let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(ka_raw),
            destination_hash: *link_id,
        }));
    }

    fn send_resource_action(
        transport_tx: &mpsc::Sender<TransportMessage>,
        active: &mut ActiveLink,
        link_id: &[u8; 16],
        action: TransferAction,
    ) -> bool {
        let (context, payload, encrypted, packet_type) = match action {
            TransferAction::SendAdvertisement(payload) => (
                rns_wire::context::PacketContext::ResourceAdv,
                payload,
                true,
                rns_wire::flags::PacketType::Data,
            ),
            TransferAction::SendPart(_, payload) => (
                rns_wire::context::PacketContext::Resource,
                payload,
                false,
                rns_wire::flags::PacketType::Data,
            ),
            TransferAction::SendProof(payload) => (
                rns_wire::context::PacketContext::ResourcePrf,
                payload,
                false,
                rns_wire::flags::PacketType::Proof,
            ),
            TransferAction::SendHmu(payload) => (
                rns_wire::context::PacketContext::ResourceHmu,
                payload,
                true,
                rns_wire::flags::PacketType::Data,
            ),
            TransferAction::SendRequest(payload) => (
                rns_wire::context::PacketContext::ResourceReq,
                payload,
                true,
                rns_wire::flags::PacketType::Data,
            ),
            TransferAction::SendCancel(cancel_type, resource_hash) => {
                let context = match cancel_type {
                    rns_protocol::resource::CancelType::Icl => {
                        rns_wire::context::PacketContext::ResourceIcl
                    }
                    rns_protocol::resource::CancelType::Rcl => {
                        rns_wire::context::PacketContext::ResourceRcl
                    }
                };
                (
                    context,
                    resource_hash.to_vec(),
                    true,
                    rns_wire::flags::PacketType::Data,
                )
            }
            TransferAction::None | TransferAction::Complete | TransferAction::Failed(_) => {
                return false;
            }
        };
        let body = if encrypted {
            let Ok(body) = active.link.encrypt(&payload) else {
                return false;
            };
            body
        } else {
            payload
        };

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
            destination_hash: *link_id,
            context,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&body);
        active.link.record_tx(body.len());
        transport_tx
            .try_send(TransportMessage::Outbound(OutboundRequest {
                raw: Bytes::from(raw),
                destination_hash: *link_id,
            }))
            .is_ok()
    }

    fn emit_resource_event(
        resource_event_tx: &Option<mpsc::Sender<LinkResourceEvent>>,
        event: LinkResourceEvent,
    ) {
        if let Some(tx) = resource_event_tx {
            let _ = tx.try_send(event);
        }
    }

    fn inbound_resource_identity(
        active: &ActiveLink,
        resource_hash: &[u8; 32],
    ) -> ([u8; 32], usize, usize) {
        active
            .segment_routing
            .get(resource_hash)
            .map(|route| {
                let total_segments = active
                    .inbound_split_resources
                    .get(&route.original_hash)
                    .map(|coordinator| coordinator.total_segments)
                    .unwrap_or(1);
                (route.original_hash, route.segment_index, total_segments)
            })
            .unwrap_or((*resource_hash, 1, 1))
    }

    fn outbound_resource_identity(transfer: &OutboundTransfer) -> ([u8; 32], usize, usize) {
        (
            transfer
                .resource
                .original_hash
                .unwrap_or(transfer.resource.resource_hash),
            transfer.resource.segment_index,
            transfer.resource.total_segments,
        )
    }

    fn emit_inbound_resource_progress(
        resource_event_tx: &Option<mpsc::Sender<LinkResourceEvent>>,
        active: &ActiveLink,
        link_id: [u8; 16],
        resource_hash: [u8; 32],
    ) {
        let Some(transfer) = active.inbound_resources.get(&resource_hash) else {
            return;
        };
        let (resource_id, segment_index, total_segments) =
            Self::inbound_resource_identity(active, &resource_hash);
        let total = transfer.resource.data_size;
        let progress = ((segment_index.saturating_sub(1) as f64 + transfer.progress())
            / total_segments.max(1) as f64)
            .clamp(0.0, 1.0);
        Self::emit_resource_event(
            resource_event_tx,
            LinkResourceEvent::Progress {
                link_id,
                resource_id,
                direction: LinkResourceDirection::Inbound,
                transferred: (progress * total as f64).floor() as usize,
                total,
            },
        );
    }

    fn emit_outbound_resource_progress(
        resource_event_tx: &Option<mpsc::Sender<LinkResourceEvent>>,
        active: &ActiveLink,
        link_id: [u8; 16],
        resource_hash: [u8; 32],
    ) {
        let Some(transfer) = active.outbound_resources.get(&resource_hash) else {
            return;
        };
        let (resource_id, segment_index, total_segments) =
            Self::outbound_resource_identity(transfer);
        let total = transfer.resource.advertisement_data_size;
        let progress = ((segment_index.saturating_sub(1) as f64 + transfer.progress())
            / total_segments.max(1) as f64)
            .clamp(0.0, 1.0);
        Self::emit_resource_event(
            resource_event_tx,
            LinkResourceEvent::Progress {
                link_id,
                resource_id,
                direction: LinkResourceDirection::Outbound,
                transferred: (progress * total as f64).floor() as usize,
                total,
            },
        );
    }

    fn drop_inbound_resource(active: &mut ActiveLink, resource_hash: &[u8; 32]) {
        active.link.untrack_resource(resource_hash);
        active.inbound_resources.remove(resource_hash);

        let Some(route) = active.segment_routing.remove(resource_hash) else {
            return;
        };
        active.inbound_split_resources.remove(&route.original_hash);
        let siblings: Vec<[u8; 32]> = active
            .segment_routing
            .iter()
            .filter_map(|(sibling_hash, sibling_route)| {
                (sibling_route.original_hash == route.original_hash).then_some(*sibling_hash)
            })
            .collect();
        for sibling_hash in siblings {
            active.segment_routing.remove(&sibling_hash);
            active.inbound_resources.remove(&sibling_hash);
            active.link.untrack_resource(&sibling_hash);
        }
    }

    fn send_link_packet_proof(
        transport_tx: &mpsc::Sender<TransportMessage>,
        link_id: &[u8; 16],
        proof_data: &[u8],
        context: rns_wire::context::PacketContext,
    ) {
        let proof_header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type: rns_wire::flags::PacketType::Proof,
            },
            hops: 0,
            transport_id: None,
            destination_hash: *link_id,
            context,
        };
        let mut proof_raw = proof_header.pack();
        proof_raw.extend_from_slice(proof_data);
        let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(proof_raw),
            destination_hash: *link_id,
        }));
    }

    fn resend_channel_data(
        transport_tx: &mpsc::Sender<TransportMessage>,
        link_id: &[u8; 16],
        sequence: u16,
        data: &[u8],
    ) -> [u8; 32] {
        let channel_header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type: rns_wire::flags::PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: *link_id,
            context: rns_wire::context::PacketContext::Channel,
        };
        let mut raw = channel_header.pack();
        raw.extend_from_slice(data);
        let packet_hash = rns_wire::hash::packet_hash(&raw, channel_header.flags.header_type);
        let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: *link_id,
        }));
        tracing::debug!(
            link_id = hex::encode(link_id),
            sequence,
            packet_hash = hex::encode(&packet_hash[..8]),
            "channel packet retransmitted"
        );
        packet_hash
    }

    fn ensure_link_channel(active: &mut ActiveLink, link_id: [u8; 16]) -> Option<&mut LinkChannel> {
        if active.channel.is_none() {
            let rtt = active.link.rtt_secs();
            let mdu = active.link.mdu;
            let keys = active.link.session_keys()?;
            active.channel = Some(LinkChannel::new_encrypted_with_mdu(link_id, rtt, mdu, keys));
            active.link.mark_channel_created();
        }
        active.channel.as_mut()
    }

    fn handle_link_packet_proof(&mut self, link_id: [u8; 16], proof_data: &[u8]) {
        let Some(active) = self.active_links.get_mut(&link_id) else {
            return;
        };

        active.link.record_inbound();
        if proof_data.len() < 96 {
            tracing::warn!(
                link_id = hex::encode(link_id),
                proof_len = proof_data.len(),
                "short link packet proof ignored"
            );
            return;
        }

        let mut packet_hash = [0u8; 32];
        packet_hash.copy_from_slice(&proof_data[..32]);
        if !active.link.validate_packet_proof(&packet_hash, proof_data) {
            tracing::warn!(
                link_id = hex::encode(link_id),
                packet_hash = hex::encode(&packet_hash[..8]),
                "invalid link packet proof ignored"
            );
            return;
        }

        let rtt = active.link.rtt_secs();
        let mut matched_channel_sequence = false;
        if let Some(channel) = active.channel.as_mut() {
            if let Some(sequence) = channel.delivered_by_packet_hash(&packet_hash, rtt) {
                matched_channel_sequence = true;
                active.link.keepalive.record_proof();
                tracing::debug!(
                    link_id = hex::encode(link_id),
                    sequence,
                    packet_hash = hex::encode(&packet_hash[..8]),
                    "channel packet delivery proof accepted"
                );
            }
        }
        if !matched_channel_sequence {
            if let Some(ref tx) = self.link_packet_proof_tx {
                let _ = tx.try_send(LinkPacketProof {
                    link_id,
                    packet_hash,
                });
            }
        }
    }

    fn handle_parsed_request(
        &mut self,
        link_id: [u8; 16],
        request_id: [u8; 16],
        path_hash: [u8; 16],
        requested_at: f64,
        data: Vec<u8>,
    ) {
        if !self
            .active_links
            .get(&link_id)
            .is_some_and(|active| active.link.state == LinkState::Active)
        {
            tracing::debug!(
                link_id = hex::encode(link_id),
                request_id = hex::encode(request_id),
                "link request ignored before Link activation"
            );
            return;
        }

        let remote_identity = self
            .active_links
            .get(&link_id)
            .and_then(|active| active.link.remote_identity())
            .and_then(|public_key| Identity::from_public_key(public_key).ok());

        let mut response_auto_compress = false;
        let outcome = if let Some(registered) = self.destination_request_handlers.get(&path_hash) {
            let allowed = match registered.allow {
                AllowPolicy::AllowNone => false,
                AllowPolicy::AllowAll => true,
                AllowPolicy::AllowList => remote_identity.as_ref().is_some_and(|identity| {
                    registered
                        .allowed_list
                        .iter()
                        .any(|allowed| allowed == &identity.hash)
                }),
            };

            if allowed {
                response_auto_compress = registered.auto_compress;
                (registered.handler)(DestinationRequest {
                    path: registered.path.clone(),
                    data: data.clone(),
                    request_id,
                    link_id,
                    remote_identity,
                    requested_at,
                })
            } else {
                tracing::debug!(
                    link_id = hex::encode(link_id),
                    request_id = hex::encode(request_id),
                    path = %registered.path,
                    "link request denied by destination handler policy"
                );
                RequestOutcome::Drop
            }
        } else if let Some(ref handler) = self.request_handler_ex {
            handler(link_id, path_hash, data.clone())
        } else if let Some(ref handler) = self.request_handler {
            match handler(link_id, path_hash, data) {
                Some(response) => RequestOutcome::Reply(response),
                None => RequestOutcome::Drop,
            }
        } else {
            RequestOutcome::Drop
        };

        let (response, fetch_spec) = match outcome {
            RequestOutcome::Reply(response) => (Some(response), None),
            RequestOutcome::ReplyWithResource {
                ack,
                data,
                metadata,
                auto_compress,
            } => (Some(ack), Some((data, metadata, auto_compress))),
            RequestOutcome::Drop => (None, None),
        };

        if let Some(response) = response {
            match Link::pack_response(&request_id, &response) {
                Ok(packed_response) => {
                    let mdu = self
                        .active_links
                        .get(&link_id)
                        .map(|active| active.link.mdu)
                        .unwrap_or_default();
                    if packed_response.len() <= mdu {
                        if let Some(active) = self.active_links.get_mut(&link_id) {
                            if let Ok(encrypted) = active.link.encrypt(&packed_response) {
                                let response_header = rns_wire::header::PacketHeader {
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
                                    context: rns_wire::context::PacketContext::Response,
                                };
                                let mut raw = response_header.pack();
                                raw.extend_from_slice(&encrypted);
                                active.link.record_tx(encrypted.len());
                                let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                                    OutboundRequest {
                                        raw: Bytes::from(raw),
                                        destination_hash: link_id,
                                    },
                                ));
                                tracing::debug!(
                                    link_id = hex::encode(link_id),
                                    request_id = hex::encode(request_id),
                                    response_len = response.len(),
                                    "link request handled — response sent"
                                );
                            }
                        }
                    } else if self
                        .start_response_resource(
                            &link_id,
                            packed_response,
                            request_id,
                            response_auto_compress,
                        )
                        .is_some()
                    {
                        tracing::debug!(
                            link_id = hex::encode(link_id),
                            request_id = hex::encode(request_id),
                            "link request handled — response sent as Resource"
                        );
                    } else {
                        tracing::warn!(
                            link_id = hex::encode(link_id),
                            request_id = hex::encode(request_id),
                            "link request Resource response could not be started"
                        );
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        link_id = hex::encode(link_id),
                        request_id = hex::encode(request_id),
                        error = %error,
                        "link request response could not be packed"
                    );
                }
            }
        } else {
            tracing::debug!(
                link_id = hex::encode(link_id),
                request_id = hex::encode(request_id),
                path = hex::encode(path_hash),
                "link request received — no handler response"
            );
        }

        if let Some((data, metadata, auto_compress)) = fetch_spec {
            if self
                .start_resource_transfer_inner(
                    &link_id,
                    ResourceTransferStart {
                        data,
                        metadata,
                        auto_compress,
                        request_id: None,
                        is_response: false,
                        allow_handshake: true,
                    },
                )
                .is_none()
            {
                tracing::warn!(
                    link_id = hex::encode(link_id),
                    "link request follow-up Resource could not be started"
                );
            }
        }
    }

    pub fn set_request_handler<F>(&mut self, handler: F)
    where
        F: Fn([u8; 16], [u8; 16], Vec<u8>) -> Option<Vec<u8>> + Send + 'static,
    {
        self.request_handler = Some(Box::new(handler));
    }

    /// Handler that may schedule a follow-up resource transfer (rncp --fetch).
    /// Takes precedence over [`Self::set_request_handler`].
    pub fn set_request_handler_ex<F>(&mut self, handler: F)
    where
        F: Fn([u8; 16], [u8; 16], Vec<u8>) -> RequestOutcome + Send + 'static,
    {
        self.request_handler_ex = Some(Box::new(handler));
    }

    /// Register or replace a request handler for `path`.
    ///
    /// The callback receives the same request context as Python Reticulum's
    /// `Destination.register_request_handler`: path, data, request id, Link id,
    /// authenticated remote identity (when identified), and request timestamp.
    pub fn register_request_handler<F>(
        &mut self,
        path: &str,
        allow: AllowPolicy,
        allowed_list: Option<Vec<[u8; 16]>>,
        auto_compress: bool,
        handler: F,
    ) -> bool
    where
        F: Fn(DestinationRequest) -> RequestOutcome + Send + 'static,
    {
        self.register_request_handler_boxed(
            path,
            allow,
            allowed_list.unwrap_or_default(),
            auto_compress,
            Box::new(handler),
        )
    }

    fn register_request_handler_boxed(
        &mut self,
        path: &str,
        allow: AllowPolicy,
        allowed_list: Vec<[u8; 16]>,
        auto_compress: bool,
        handler: DestinationRequestHandler,
    ) -> bool {
        if path.is_empty() {
            return false;
        }

        if let Some(destination) = self.destination.as_mut() {
            destination.register_request_handler(
                path,
                allow,
                Some(allowed_list.clone()),
                auto_compress,
            );
        }

        self.destination_request_handlers.insert(
            truncated_hash(path.as_bytes()),
            RegisteredRequestHandler {
                path: path.to_string(),
                allow,
                allowed_list,
                auto_compress,
                handler,
            },
        );
        true
    }

    /// Remove the request handler registered for `path`.
    pub fn deregister_request_handler(&mut self, path: &str) -> bool {
        if let Some(destination) = self.destination.as_mut() {
            destination.deregister_request_handler(path);
        }
        self.destination_request_handlers
            .remove(&truncated_hash(path.as_bytes()))
            .is_some()
    }

    pub fn set_announce_handler<F>(&mut self, handler: F)
    where
        F: FnMut() + Send + 'static,
    {
        self.announce_handler = Some(Box::new(handler));
    }

    pub fn set_response_channel(&mut self, tx: mpsc::Sender<LinkResponse>) {
        self.response_tx = Some(tx);
    }

    pub fn set_resource_completed_channel(&mut self, tx: mpsc::Sender<(Vec<u8>, [u8; 16])>) {
        self.resource_completed_tx = Some(tx);
    }

    pub fn set_resource_completion_channel(&mut self, tx: mpsc::Sender<ResourceCompletion>) {
        self.resource_completion_tx = Some(tx);
    }

    /// Set the inbound Resource policy for current and future responder Links.
    ///
    /// Request and response Resources remain protocol-owned and bypass this
    /// policy, matching Python Reticulum. The manager defaults to
    /// [`ResourceStrategy::AcceptAll`] for LXMF compatibility.
    pub fn set_resource_strategy(&mut self, strategy: ResourceStrategy) {
        self.resource_strategy = strategy;
        for active in self.active_links.values_mut() {
            active.link.set_resource_strategy(strategy);
        }
    }

    /// Install the per-advertisement decision hook used by
    /// [`ResourceStrategy::AcceptApp`].
    pub fn set_resource_accept_handler<F>(&mut self, handler: F)
    where
        F: Fn([u8; 16], &ResourceAdvertisement) -> bool + Send + 'static,
    {
        self.resource_accept_handler = Some(Box::new(handler));
    }

    pub fn clear_resource_accept_handler(&mut self) {
        self.resource_accept_handler = None;
    }

    /// Fires when a link reaches the active state.
    pub fn set_link_established_channel(&mut self, tx: mpsc::Sender<[u8; 16]>) {
        self.link_established_tx = Some(tx);
    }

    /// Fires on LinkIdentify before any resource ADV can race it.
    pub fn set_link_identified_channel(&mut self, tx: mpsc::Sender<([u8; 16], [u8; 16])>) {
        self.link_identified_tx = Some(tx);
    }

    pub fn set_link_identity_gate<F>(&mut self, gate: F)
    where
        F: Fn([u8; 16], [u8; 16]) -> bool + Send + 'static,
    {
        self.link_identity_gate = Some(Box::new(gate));
    }

    pub fn set_link_packet_channel(&mut self, tx: mpsc::Sender<(Vec<u8>, [u8; 16])>) {
        self.link_packet_tx = Some(tx);
    }

    pub fn set_link_packet_proof_channel(&mut self, tx: mpsc::Sender<LinkPacketProof>) {
        self.link_packet_proof_tx = Some(tx);
    }

    pub fn set_outbound_resource_proof_channel(&mut self, tx: mpsc::Sender<LinkResourceProof>) {
        self.outbound_resource_proof_tx = Some(tx);
    }

    pub fn set_resource_event_channel(&mut self, tx: mpsc::Sender<LinkResourceEvent>) {
        self.resource_event_tx = Some(tx);
    }

    pub fn set_channel_message_channel(&mut self, tx: mpsc::Sender<LinkChannelMessage>) {
        self.channel_message_tx = Some(tx);
    }

    pub fn set_link_closed_channel(&mut self, tx: mpsc::Sender<[u8; 16]>) {
        self.link_closed_tx = Some(tx);
    }

    /// Raw destination-encrypted packets for app-level decryption (opportunistic LXMF).
    pub fn set_inbound_raw_channel(&mut self, tx: mpsc::Sender<Vec<u8>>) {
        self.inbound_raw_tx = Some(tx);
    }

    pub fn active_link_count(&self) -> usize {
        self.active_links.len()
    }

    pub fn get_link(&self, link_id: &[u8; 16]) -> Option<&Link> {
        self.active_links.get(link_id).map(|a| &a.link)
    }

    pub fn get_link_mut(&mut self, link_id: &[u8; 16]) -> Option<&mut Link> {
        self.active_links.get_mut(link_id).map(|a| &mut a.link)
    }

    pub fn get_channel(&mut self, link_id: &[u8; 16]) -> Option<&mut LinkChannel> {
        let active = self.active_links.get_mut(link_id)?;
        Self::ensure_link_channel(active, *link_id)
    }

    pub fn send_channel_message(
        &mut self,
        link_id: &[u8; 16],
        msg: &dyn MessageBase,
    ) -> Result<ChannelSendReceipt, ChannelSendError> {
        let active = self
            .active_links
            .get(link_id)
            .ok_or(ChannelSendError::LinkNotFound)?;
        if !matches!(active.link.state, LinkState::Active | LinkState::Stale) {
            return Err(ChannelSendError::LinkNotActive);
        }

        let transport_tx = self.transport_tx.clone();
        let permit = transport_tx
            .try_reserve()
            .map_err(|_| ChannelSendError::TransportUnavailable)?;

        let active = self
            .active_links
            .get_mut(link_id)
            .ok_or(ChannelSendError::LinkNotFound)?;
        let prepared = Self::ensure_link_channel(active, *link_id)
            .ok_or(ChannelSendError::NoSessionKeys)?
            .prepare_send_tracked(msg)?;

        let channel_header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type: rns_wire::flags::PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: *link_id,
            context: rns_wire::context::PacketContext::Channel,
        };
        let mut raw = channel_header.pack();
        raw.extend_from_slice(&prepared.data);

        let packet_hash = rns_wire::hash::packet_hash(&raw, channel_header.flags.header_type);
        if let Some(channel) = active.channel.as_mut() {
            channel.track_outbound_packet_hash(packet_hash, prepared.sequence);
        }
        active.link.record_tx(prepared.data.len());

        permit.send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: *link_id,
        }));

        Ok(ChannelSendReceipt {
            link_id: *link_id,
            sequence: prepared.sequence,
            packet_hash,
        })
    }

    pub fn send_link_packet(
        &mut self,
        link_id: &[u8; 16],
        payload: &[u8],
    ) -> Result<LinkPacketSendReceipt, LinkSendError> {
        let active = self
            .active_links
            .get(link_id)
            .ok_or(LinkSendError::LinkNotFound)?;
        if active.link.state != LinkState::Active {
            return Err(LinkSendError::LinkNotActive);
        }

        let encrypted = active
            .link
            .encrypt(payload)
            .map_err(|_| LinkSendError::NoSessionKeys)?;
        let transport_tx = self.transport_tx.clone();
        let permit = transport_tx
            .try_reserve()
            .map_err(|_| LinkSendError::TransportUnavailable)?;

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
            destination_hash: *link_id,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&encrypted);
        let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);

        let active = self
            .active_links
            .get_mut(link_id)
            .ok_or(LinkSendError::LinkNotFound)?;
        active.link.record_tx(encrypted.len());
        permit.send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: *link_id,
        }));

        Ok(LinkPacketSendReceipt {
            link_id: *link_id,
            packet_hash,
        })
    }

    pub fn send_link_resource(
        &mut self,
        link_id: &[u8; 16],
        payload: Vec<u8>,
        auto_compress: bool,
    ) -> Result<LinkResourceSendReceipt, LinkSendError> {
        let active = self
            .active_links
            .get(link_id)
            .ok_or(LinkSendError::LinkNotFound)?;
        if active.link.state != LinkState::Active {
            return Err(LinkSendError::LinkNotActive);
        }
        if active.link.session_keys().is_none() {
            return Err(LinkSendError::NoSessionKeys);
        }

        let resource_hash = self
            .start_resource_transfer(link_id, payload, auto_compress)
            .ok_or(LinkSendError::ResourceStartFailed)?;

        Ok(LinkResourceSendReceipt {
            link_id: *link_id,
            resource_hash,
        })
    }

    pub fn send_link_payload(
        &mut self,
        link_id: &[u8; 16],
        payload: Vec<u8>,
        auto_compress: bool,
    ) -> Result<LinkPayloadSendReceipt, LinkSendError> {
        let active = self
            .active_links
            .get(link_id)
            .ok_or(LinkSendError::LinkNotFound)?;
        if active.link.state != LinkState::Active {
            return Err(LinkSendError::LinkNotActive);
        }

        if payload.len() <= active.link.mdu {
            self.send_link_packet(link_id, &payload)
                .map(LinkPayloadSendReceipt::Packet)
        } else {
            self.send_link_resource(link_id, payload, auto_compress)
                .map(LinkPayloadSendReceipt::Resource)
        }
    }

    /// Cancel an active Resource by the logical id returned in lifecycle
    /// events or [`LinkResourceSendReceipt`].
    pub fn cancel_link_resource(
        &mut self,
        link_id: &[u8; 16],
        resource_id: &[u8; 32],
        direction: LinkResourceDirection,
    ) -> bool {
        let Some(active) = self.active_links.get_mut(link_id) else {
            return false;
        };

        let cancelled_id = match direction {
            LinkResourceDirection::Outbound => {
                let segment_hash =
                    active
                        .outbound_resources
                        .iter()
                        .find_map(|(segment_hash, transfer)| {
                            let (logical_id, _, _) = Self::outbound_resource_identity(transfer);
                            (logical_id == *resource_id || *segment_hash == *resource_id)
                                .then_some(*segment_hash)
                        });
                let Some(segment_hash) = segment_hash else {
                    return false;
                };
                let logical_id = active
                    .outbound_resources
                    .get(&segment_hash)
                    .map(Self::outbound_resource_identity)
                    .map(|identity| identity.0)
                    .unwrap_or(segment_hash);
                let _ = Self::send_resource_action(
                    &self.transport_tx,
                    active,
                    link_id,
                    TransferAction::SendCancel(
                        rns_protocol::resource::CancelType::Icl,
                        segment_hash,
                    ),
                );
                if let Some(mut transfer) = active.outbound_resources.remove(&segment_hash) {
                    transfer.handle_cancel();
                }
                active.outbound_split_queues.remove(&logical_id);
                active.link.untrack_resource(&segment_hash);
                logical_id
            }
            LinkResourceDirection::Inbound => {
                let segment_hash = active.inbound_resources.keys().find_map(|segment_hash| {
                    let (logical_id, _, _) = Self::inbound_resource_identity(active, segment_hash);
                    (logical_id == *resource_id || *segment_hash == *resource_id)
                        .then_some(*segment_hash)
                });
                let Some(segment_hash) = segment_hash else {
                    return false;
                };
                let logical_id = Self::inbound_resource_identity(active, &segment_hash).0;
                let _ = Self::send_resource_action(
                    &self.transport_tx,
                    active,
                    link_id,
                    TransferAction::SendCancel(
                        rns_protocol::resource::CancelType::Rcl,
                        segment_hash,
                    ),
                );
                Self::drop_inbound_resource(active, &segment_hash);
                logical_id
            }
        };

        Self::emit_resource_event(
            &self.resource_event_tx,
            LinkResourceEvent::Concluded {
                link_id: *link_id,
                resource_id: cancelled_id,
                direction,
                conclusion: LinkResourceConclusion::Cancelled,
            },
        );
        true
    }

    pub fn process_destination_packet(&self, raw: &[u8], identity: &Identity) -> Option<Vec<u8>> {
        let dest = self.destination.as_ref()?;
        let (header, data_offset) = rns_wire::header::PacketHeader::unpack(raw).ok()?;
        if header.destination_hash != dest.hash
            || header.flags.destination_type as u8 != dest.dest_type as u8
        {
            return None;
        }
        let data = &raw[data_offset..];
        let packet_type = header.flags.packet_type as u8;

        match dest.receive_packet(packet_type, data, raw, identity) {
            Ok(Some(plaintext)) => Some(plaintext),
            _ => None,
        }
    }

    fn dispatch_destination_packet(&self, raw: &[u8], interface_id: u64) -> bool {
        let Some(identity) = self.identity.as_ref() else {
            return false;
        };
        let Some(_plaintext) = self.process_destination_packet(raw, identity) else {
            return false;
        };
        let Some(destination) = self.destination.as_ref() else {
            return false;
        };
        let Ok((header, _)) = rns_wire::header::PacketHeader::unpack(raw) else {
            return false;
        };

        if header.flags.packet_type != rns_wire::flags::PacketType::Data
            || !destination.should_prove(raw)
        {
            return true;
        }

        let (packet_hash, proof_destination) =
            rns_wire::hash::packet_hash_pair(raw, header.flags.header_type);
        let proof = match destination.prove(&packet_hash, identity, self.use_implicit_proof) {
            Ok(proof) => proof,
            Err(e) => {
                tracing::warn!(
                    destination = %hex::encode(destination.hash),
                    error = %e,
                    "failed to prove destination packet"
                );
                return true;
            }
        };

        let proof_header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Single,
                packet_type: rns_wire::flags::PacketType::Proof,
            },
            hops: 0,
            transport_id: None,
            destination_hash: proof_destination,
            context: rns_wire::context::PacketContext::None,
        };
        let mut proof_raw = proof_header.pack();
        proof_raw.extend_from_slice(&proof);
        let request = OutboundRequest {
            raw: Bytes::from(proof_raw),
            destination_hash: proof_destination,
        };
        if let Err(e) = self
            .transport_tx
            .try_send(TransportMessage::OutboundAttached {
                request,
                interface_id,
            })
        {
            tracing::warn!(
                destination = %hex::encode(destination.hash),
                err = %e,
                "failed to queue destination packet proof"
            );
        }
        true
    }

    /// Sends ADV + initial window, registers transfer so later HMU drives the rest.
    pub fn start_resource_transfer(
        &mut self,
        link_id: &[u8; 16],
        data: Vec<u8>,
        auto_compress: bool,
    ) -> Option<[u8; 32]> {
        self.start_resource_transfer_with_metadata(link_id, data, None, auto_compress)
    }

    /// As [`Self::start_resource_transfer`] but attaches msgpack metadata
    /// (e.g. `{"name": "file.bin"}`). Used by rncp --fetch.
    pub fn start_resource_transfer_with_metadata(
        &mut self,
        link_id: &[u8; 16],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        auto_compress: bool,
    ) -> Option<[u8; 32]> {
        self.start_resource_transfer_inner(
            link_id,
            ResourceTransferStart {
                data,
                metadata,
                auto_compress,
                request_id: None,
                is_response: false,
                allow_handshake: false,
            },
        )
    }

    fn start_response_resource(
        &mut self,
        link_id: &[u8; 16],
        packed_response: Vec<u8>,
        request_id: [u8; 16],
        auto_compress: bool,
    ) -> Option<[u8; 32]> {
        self.start_resource_transfer_inner(
            link_id,
            ResourceTransferStart {
                data: packed_response,
                metadata: None,
                auto_compress,
                request_id: Some(request_id.to_vec()),
                is_response: true,
                allow_handshake: false,
            },
        )
    }

    fn start_resource_transfer_inner(
        &mut self,
        link_id: &[u8; 16],
        request: ResourceTransferStart,
    ) -> Option<[u8; 32]> {
        let ResourceTransferStart {
            data,
            metadata,
            auto_compress,
            request_id,
            is_response,
            allow_handshake,
        } = request;
        let data_size = data.len();
        let active = self.active_links.get_mut(link_id)?;
        let state_allows_transfer = active.link.state == LinkState::Active
            || (allow_handshake && active.link.state == LinkState::Handshake);
        if !state_allows_transfer {
            return None;
        }

        let rtt = active
            .link
            .rtt
            .unwrap_or(std::time::Duration::from_millis(500));
        // Pre-encrypt before chunking so each part is raw ciphertext under MTU
        // (matches Python Resource over a link).
        let session_keys = active.link.session_keys()?;
        let encrypt_fn = |plaintext: &[u8]| -> Vec<u8> {
            rns_link::encryption::link_encrypt(&session_keys, plaintext)
                .unwrap_or_else(|_| plaintext.to_vec())
        };
        let metadata_wire_size = metadata.as_ref().map(|m| 3 + m.len()).unwrap_or(0);
        let resources = if metadata_wire_size + data.len() <= MAX_EFFICIENT_SIZE {
            let mut resource = if metadata.is_some() {
                rns_protocol::resource::OutboundResource::with_options(
                    data,
                    auto_compress,
                    metadata,
                    None,
                    Some(&encrypt_fn),
                )
                .ok()?
            } else {
                rns_protocol::resource::OutboundResource::new(
                    data,
                    auto_compress,
                    Some(&encrypt_fn),
                )
                .ok()?
            };
            resource.flags.is_response = is_response;
            resource.request_id = request_id.clone();
            vec![resource]
        } else {
            MultiSegmentOutbound::with_options(
                data,
                auto_compress,
                metadata,
                request_id.clone(),
                is_response,
                Some(&encrypt_fn),
            )
            .ok()?
            .segments
        };

        let resource_key = resources
            .first()
            .map(|r| r.original_hash.unwrap_or(r.resource_hash))?;
        let total_segments = resources.len();

        let mut transfers: VecDeque<OutboundTransfer> = resources
            .into_iter()
            .map(|resource| OutboundTransfer::from_prebuilt(resource, rtt))
            .collect();
        let first = transfers.pop_front()?;
        Self::start_outbound_transfer(&self.transport_tx, active, link_id, first)?;
        if !transfers.is_empty() {
            active.outbound_split_queues.insert(resource_key, transfers);
        }
        Self::emit_resource_event(
            &self.resource_event_tx,
            LinkResourceEvent::Started {
                link_id: *link_id,
                resource_id: resource_key,
                direction: LinkResourceDirection::Outbound,
                data_size,
                total_segments,
            },
        );

        Some(resource_key)
    }

    fn start_outbound_transfer(
        transport_tx: &mpsc::Sender<TransportMessage>,
        active: &mut ActiveLink,
        link_id: &[u8; 16],
        mut transfer: OutboundTransfer,
    ) -> Option<[u8; 32]> {
        let action = transfer.tick();
        let adv_data = match action {
            TransferAction::SendAdvertisement(adv) => adv,
            _ => return None,
        };

        let resource_hash = transfer.resource.resource_hash;
        let encrypted = active.link.encrypt(&adv_data).ok()?;
        let adv_header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type: rns_wire::flags::PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: *link_id,
            context: rns_wire::context::PacketContext::ResourceAdv,
        };
        let mut raw = adv_header.pack();
        raw.extend_from_slice(&encrypted);
        active.link.record_tx(encrypted.len());
        let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: *link_id,
        }));

        active.outbound_resources.insert(resource_hash, transfer);
        tracing::debug!(
            link_id = hex::encode(link_id),
            resource = hex::encode(&resource_hash[..8]),
            "outbound resource transfer started"
        );
        Some(resource_hash)
    }

    pub fn complete_resource(
        &mut self,
        link_id: &[u8; 16],
        resource_hash: &[u8; 32],
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        let active = self.active_links.get_mut(link_id)?;
        let transfer = active.inbound_resources.get_mut(resource_hash)?;
        match transfer.complete(None) {
            Ok((data, proof)) => {
                active.link.untrack_resource(resource_hash);
                active.inbound_resources.remove(resource_hash);
                Some((data, proof))
            }
            Err(_) => None,
        }
    }
}

fn clone_identity(identity: &Identity) -> Option<Identity> {
    // Clone preserves a hardware backend (shared Arc) — there is no extractable
    // private key to copy; software identities clone their key material.
    if identity.has_private_key() || identity.has_backend() {
        Some(identity.clone())
    } else {
        None
    }
}

fn identity_ed25519_public_key(identity: &Identity) -> [u8; 32] {
    let public_key = identity.get_public_key();
    let mut ed25519_pub = [0u8; 32];
    ed25519_pub.copy_from_slice(&public_key[32..64]);
    ed25519_pub
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub fn register_destination(
    transport_tx: &mpsc::Sender<TransportMessage>,
    dest_hash: [u8; 16],
    app_name: &str,
) -> mpsc::Receiver<DestinationEvent> {
    let (tx, rx) = mpsc::channel(256);
    if let Err(e) = transport_tx.try_send(TransportMessage::RegisterDestination {
        hash: dest_hash,
        app_name: app_name.to_string(),
        delivery_tx: Some(tx),
    }) {
        tracing::warn!(dest = hex::encode(dest_hash), err = %e,
            "failed to register destination with transport; packets will not be delivered");
    }
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_identity::identity::LocalKeyBackend;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    const TEST_CHANNEL_MSG_TYPE: u16 = 0x1234;

    struct TestSigningBackend {
        signing_key: Ed25519PrivateKey,
        available: AtomicBool,
    }

    impl LocalKeyBackend for TestSigningBackend {
        fn sign_ed25519(&self, message: &[u8]) -> Option<[u8; 64]> {
            self.available
                .load(Ordering::SeqCst)
                .then(|| self.signing_key.sign(message))
        }

        fn ecdh(&self, _peer_pub: &[u8; 32]) -> Option<[u8; 32]> {
            None
        }
    }

    struct TestChannelNoop;

    impl rns_protocol::channel_message::MessageBase for TestChannelNoop {
        fn msg_type(&self) -> u16 {
            TEST_CHANNEL_MSG_TYPE
        }

        fn pack(&self) -> Vec<u8> {
            Vec::new()
        }

        fn unpack(
            &mut self,
            _raw: &[u8],
        ) -> Result<(), rns_protocol::channel_message::ChannelMessageError> {
            Ok(())
        }
    }

    fn link_request_raw(dest_hash: [u8; 16], request_data: &[u8]) -> Vec<u8> {
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::LinkRequest,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(request_data);
        raw
    }

    fn backend_identity(available: bool) -> (Identity, [u8; 32], [u8; 32]) {
        let software = Identity::new();
        let public_key = software.get_public_key();
        let identity_ed25519_pub = identity_ed25519_public_key(&software);
        let signing_seed = software.get_signing_key().unwrap().to_bytes();
        let backend: Arc<dyn LocalKeyBackend> = Arc::new(TestSigningBackend {
            signing_key: Ed25519PrivateKey::from_bytes(&signing_seed),
            available: AtomicBool::new(available),
        });
        let backend_identity = Identity::from_backend(&public_key, backend).unwrap();
        (backend_identity, identity_ed25519_pub, signing_seed)
    }

    #[test]
    fn test_link_manager_creation() {
        let (tx, _rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let lm = LinkManager::new(tx, event_rx, [0xAA; 16], None);
        assert_eq!(lm.active_link_count(), 0);
        assert_eq!(lm.resource_strategy, ResourceStrategy::AcceptAll);
    }

    #[tokio::test]
    async fn test_register_destination_channel() {
        let (actor, tx) = rns_transport::actor::TransportActor::new();
        tokio::spawn(actor.run());

        let dest_hash = [0xAA; 16];
        let _rx = register_destination(&tx, dest_hash, "test.app");

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let _ = tx.send(TransportMessage::Shutdown).await;
    }

    #[test]
    fn test_link_manager_handles_link_closed() {
        let (tx, mut rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(tx, event_rx, [0xCC; 16], None);
        let (closed_tx, mut closed_rx) = mpsc::channel(1);
        lm.set_link_closed_channel(closed_tx);

        let identity_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xCC; 16];
        let (link, _proof) = rns_link::link::Link::new_initiator(dest_hash, 1);
        let link_id = link.link_id;

        lm.active_links.insert(
            link_id,
            ActiveLink {
                link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );
        assert_eq!(lm.active_link_count(), 1);

        lm.handle_event(DestinationEvent::LinkClosed { link_id });
        assert_eq!(lm.active_link_count(), 0);
        assert_eq!(closed_rx.try_recv().unwrap(), link_id);
        assert!(
            matches!(
                rx.try_recv().unwrap(),
                TransportMessage::DeregisterDestination { hash } if hash == link_id
            ),
            "link manager must deregister closed link destination"
        );

        let _ = identity_key;
    }

    #[test]
    fn remote_link_close_runs_full_cleanup() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let dest_hash = [0xD0; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();
        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();
        let link_id = responder.link_id;

        let callback_fired = Arc::new(AtomicBool::new(false));
        let callback_fired_clone = Arc::clone(&callback_fired);
        responder.set_link_closed_callback(move |link| {
            assert_eq!(link.state, LinkState::Closed);
            callback_fired_clone.store(true, Ordering::SeqCst);
        });

        let close_body = initiator.teardown(CloseReason::InitiatorClosed).unwrap();
        let close_header = rns_wire::header::PacketHeader {
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
            context: rns_wire::context::PacketContext::LinkClose,
        };
        let mut close_raw = close_header.pack();
        close_raw.extend_from_slice(&close_body);

        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, dest_hash, None);
        let (closed_tx, mut closed_rx) = mpsc::channel(1);
        lm.set_link_closed_channel(closed_tx);
        lm.backchannel_links.insert([0xAB; 16], link_id);
        lm.link_identities
            .lock()
            .unwrap()
            .insert(link_id, [0xAB; 16]);
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: responder,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        lm.handle_inbound_packet(&close_raw, 2);
        assert_eq!(
            lm.active_link_count(),
            1,
            "link traffic from another interface must be ignored"
        );
        assert!(closed_rx.try_recv().is_err());
        assert!(transport_rx.try_recv().is_err());

        lm.handle_inbound_packet(&close_raw, 1);

        assert_eq!(lm.active_link_count(), 0);
        assert!(callback_fired.load(Ordering::SeqCst));
        assert_eq!(closed_rx.try_recv().unwrap(), link_id);
        assert!(lm.backchannel_links.is_empty());
        assert!(lm.link_identities.lock().unwrap().get(&link_id).is_none());
        assert!(
            matches!(
                transport_rx.try_recv().unwrap(),
                TransportMessage::DeregisterDestination { hash } if hash == link_id
            ),
            "verified remote close must deregister link destination"
        );
    }

    #[test]
    fn try_step_processes_queued_destination_event_without_consuming_manager() {
        let (tx, _rx) = mpsc::channel(16);
        let (event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(tx, event_rx, [0xCE; 16], None);

        let dest_hash = [0xCE; 16];
        let (link, _proof) = rns_link::link::Link::new_initiator(dest_hash, 1);
        let link_id = link.link_id;
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        event_tx
            .try_send(DestinationEvent::LinkClosed { link_id })
            .unwrap();

        assert!(lm.try_step());
        assert_eq!(lm.active_link_count(), 0);
        assert!(!lm.try_step());
    }

    #[test]
    fn test_link_request_without_identity_rejected() {
        let (tx, _rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(tx, event_rx, [0xDD; 16], None);

        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::LinkRequest,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: [0xDD; 16],
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0xAA; 67]);

        lm.handle_link_request(&raw, 1);

        assert_eq!(lm.active_link_count(), 0);
    }

    #[test]
    fn backend_identity_accepts_link_request_without_raw_signing_key() {
        let (tx, mut rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let (identity, identity_ed25519_pub, _signing_seed) = backend_identity(true);
        let mut lm = LinkManager::with_destination(tx, event_rx, &identity, "test.hw", None);

        let dest_hash = lm.destination_hash;
        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let raw = link_request_raw(dest_hash, &request_data);

        lm.handle_link_request(&raw, 1);

        assert_eq!(lm.active_link_count(), 1);
        let outbound = rx.try_recv().expect("link proof should be queued");
        let TransportMessage::Outbound(request) = outbound else {
            panic!("expected outbound link proof");
        };
        let (proof_header, proof_offset) =
            rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            proof_header.context,
            rns_wire::context::PacketContext::Lrproof
        );
        let identity_pub =
            rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&identity_ed25519_pub).unwrap();
        let rtt = initiator
            .validate_proof(
                &request.raw[proof_offset..],
                &identity_pub,
                &identity_ed25519_pub,
            )
            .expect("backend-signed proof validates");
        assert!(!rtt.is_empty());
    }

    #[test]
    fn backend_identity_link_request_fails_closed_when_signer_unavailable() {
        let (tx, mut rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let (identity, _identity_ed25519_pub, _signing_seed) = backend_identity(false);
        let mut lm = LinkManager::with_destination(tx, event_rx, &identity, "test.hw", None);

        let dest_hash = lm.destination_hash;
        let (_initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let raw = link_request_raw(dest_hash, &request_data);

        lm.handle_link_request(&raw, 1);

        assert_eq!(lm.active_link_count(), 0);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_with_destination_constructor() {
        let (tx, _rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);

        let identity = Identity::new();
        let signing_key = identity.get_signing_key().unwrap();

        let lm =
            LinkManager::with_destination(tx, event_rx, &identity, "test.app", Some(signing_key));

        assert!(lm.destination.is_some());
        assert_eq!(lm.active_link_count(), 0);
    }

    fn destination_data_packet(
        identity: &Identity,
        app_name: &str,
        destination_hash: [u8; 16],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let destination =
            Destination::new(Some(identity), Direction::Out, DestType::Single, app_name).unwrap();
        let ciphertext = destination.encrypt(plaintext, identity, None).unwrap();
        let header = rns_wire::header::PacketHeader {
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
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&ciphertext);
        raw
    }

    #[test]
    fn live_destination_dispatch_runs_callback_and_preserves_raw_delivery() {
        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let identity = Identity::new();
        let mut manager = LinkManager::with_destination(
            transport_tx,
            event_rx,
            &identity,
            "test.dispatch",
            identity.get_signing_key(),
        );
        let observed = Arc::new(Mutex::new(None));
        let callback_observed = Arc::clone(&observed);
        manager
            .destination_mut()
            .unwrap()
            .set_packet_callback(Box::new(move |plaintext, raw| {
                *callback_observed.lock().unwrap() = Some((plaintext.to_vec(), raw.to_vec()));
            }));
        let (raw_tx, mut raw_rx) = mpsc::channel(1);
        manager.set_inbound_raw_channel(raw_tx);
        let plaintext = b"live destination dispatch";
        let raw = destination_data_packet(
            &identity,
            "test.dispatch",
            manager.destination_hash,
            plaintext,
        );

        manager.handle_inbound_packet(&raw, 23);

        assert_eq!(
            *observed.lock().unwrap(),
            Some((plaintext.to_vec(), raw.clone()))
        );
        assert_eq!(raw_rx.try_recv().unwrap(), raw);
        assert!(
            transport_rx.try_recv().is_err(),
            "ProveNone must not emit a delivery proof"
        );
    }

    #[test]
    fn live_destination_dispatch_honors_proof_strategy_and_format() {
        use rns_identity::destination::ProofStrategy;

        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let identity = Identity::new();
        let public_identity = Identity::from_public_key(&identity.get_public_key()).unwrap();
        let mut manager = LinkManager::with_destination(
            transport_tx,
            event_rx,
            &identity,
            "test.prove",
            identity.get_signing_key(),
        );
        manager
            .destination_mut()
            .unwrap()
            .set_proof_strategy(ProofStrategy::ProveAll);
        manager.set_use_implicit_proof(false);
        let raw = destination_data_packet(
            &identity,
            "test.prove",
            manager.destination_hash,
            b"prove me",
        );
        let (expected_hash, expected_destination) =
            rns_wire::hash::packet_hash_pair(&raw, rns_wire::flags::HeaderType::Header1);

        manager.handle_inbound_packet(&raw, 41);

        let TransportMessage::OutboundAttached {
            request,
            interface_id,
        } = transport_rx.try_recv().unwrap()
        else {
            panic!("expected attached destination proof");
        };
        assert_eq!(interface_id, 41);
        assert_eq!(request.destination_hash, expected_destination);
        let (header, data_offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(header.flags.packet_type, rns_wire::flags::PacketType::Proof);
        assert_eq!(header.destination_hash, expected_destination);
        let proof = &request.raw[data_offset..];
        assert_eq!(proof.len(), 96);
        assert_eq!(&proof[..32], expected_hash.as_slice());
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&proof[32..]);
        assert!(public_identity.verify(&expected_hash, &signature));
    }

    #[test]
    fn path_response_announce_request_sends_attached_path_response() {
        let (tx, mut rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);

        let identity = Identity::new();
        let signing_key = identity.get_signing_key().unwrap();
        let mut lm =
            LinkManager::with_destination(tx, event_rx, &identity, "test.app", Some(signing_key));

        let tag = vec![0xA5; 16];
        lm.handle_event(DestinationEvent::AnnounceRequested(AnnounceRequest {
            app_name: "test.app".to_string(),
            path_response: true,
            tag: Some(tag.clone()),
            attached_interface: Some(7),
        }));

        let first = rx
            .try_recv()
            .expect("path response announce should be queued");
        let TransportMessage::OutboundAttached {
            request,
            interface_id,
        } = first
        else {
            panic!("expected attached outbound path response");
        };
        assert_eq!(interface_id, 7);
        let first_raw = request.raw.clone();
        let (header, _offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(header.destination_hash, lm.destination_hash);
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::PathResponse
        );
        assert_eq!(
            header.flags.header_type,
            rns_wire::flags::HeaderType::Header1
        );

        lm.handle_event(DestinationEvent::AnnounceRequested(AnnounceRequest {
            app_name: "test.app".to_string(),
            path_response: true,
            tag: Some(tag),
            attached_interface: Some(7),
        }));

        let second = rx
            .try_recv()
            .expect("cached path response announce should be queued");
        let TransportMessage::OutboundAttached {
            request: second_request,
            interface_id: second_interface_id,
        } = second
        else {
            panic!("expected attached outbound path response");
        };
        assert_eq!(second_interface_id, 7);
        assert_eq!(
            second_request.raw, first_raw,
            "same path-response tag should reuse cached announce bytes"
        );
    }

    #[test]
    fn destination_commands_announce_and_change_link_acceptance() {
        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let identity = Identity::new();
        let mut manager = LinkManager::with_destination(
            transport_tx,
            event_rx,
            &identity,
            "test.commands",
            identity.get_signing_key(),
        );

        let (accept_tx, accept_rx) = oneshot::channel();
        assert!(manager.handle_command(LinkManagerCommand::SetAcceptsLinks {
            accepts: false,
            result_tx: Some(accept_tx),
        }));
        assert!(matches!(accept_rx.blocking_recv(), Ok(Ok(()))));
        assert!(
            !manager.destination().unwrap().accepts_links(),
            "the live manager must consult the updated destination gate"
        );

        let ratchet = [0xA5; 32];
        let (announce_tx, announce_rx) = oneshot::channel();
        assert!(manager.handle_command(LinkManagerCommand::AnnounceWith {
            options: DestinationAnnounceOptions {
                app_data: Some(b"command app data".to_vec()),
                ratchet: Some(ratchet),
                ..DestinationAnnounceOptions::default()
            },
            result_tx: Some(announce_tx),
        }));
        assert!(matches!(announce_rx.blocking_recv(), Ok(Ok(()))));

        let TransportMessage::Outbound(request) = transport_rx.try_recv().unwrap() else {
            panic!("expected destination announce");
        };
        let (header, data_offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(header.destination_hash, manager.destination_hash);
        assert_eq!(
            header.flags.packet_type,
            rns_wire::flags::PacketType::Announce
        );
        assert!(header.flags.context_flag);
        let announce =
            rns_identity::announce::AnnounceData::unpack(&request.raw[data_offset..], true)
                .unwrap();
        assert_eq!(announce.ratchet, Some(ratchet));
        assert_eq!(
            announce.app_data.as_deref(),
            Some(b"command app data".as_slice())
        );
    }

    #[test]
    fn default_announce_command_uses_owned_destination() {
        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let identity = Identity::new();
        let mut manager = LinkManager::with_destination(
            transport_tx,
            event_rx,
            &identity,
            "test.default.announce",
            identity.get_signing_key(),
        );

        assert!(manager.handle_command(LinkManagerCommand::Announce));
        assert!(matches!(
            transport_rx.try_recv(),
            Ok(TransportMessage::Outbound(_))
        ));
    }

    #[test]
    fn link_established_channel_fires_when_responder_activates() {
        let dest_hash = [0x35; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();
        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (responder, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();
        let link_id = responder.link_id;

        let (transport_tx, _transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, dest_hash, None);
        let (established_tx, mut established_rx) = mpsc::channel(1);
        lm.set_link_established_channel(established_tx);
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: responder,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

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
            context: rns_wire::context::PacketContext::Lrrtt,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&rtt_data);

        lm.handle_inbound_packet(&raw, 1);

        assert_eq!(established_rx.try_recv().unwrap(), link_id);
        assert_eq!(lm.get_link(&link_id).unwrap().state, LinkState::Active);
    }

    /// Destination side learns expected_hops from the LRRTT packet at
    /// activation (Link.py:525); +1 mirrors Python's increment-on-receive.
    /// The initiator keeps its construction-time value (Link.py:282).
    #[test]
    fn lrrtt_activation_sets_expected_hops_on_destination_side() {
        let dest_hash = [0x37; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();
        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 2);
        let (responder, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 2).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();
        let link_id = responder.link_id;
        assert_eq!(responder.expected_hops, None);

        let (transport_tx, _transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, dest_hash, None);
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: responder,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        let header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type: rns_wire::flags::PacketType::Data,
            },
            hops: 3,
            transport_id: None,
            destination_hash: link_id,
            context: rns_wire::context::PacketContext::Lrrtt,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&rtt_data);

        lm.handle_inbound_packet(&raw, 1);

        let link = lm.get_link(&link_id).unwrap();
        assert_eq!(link.state, LinkState::Active);
        assert_eq!(link.expected_hops, Some(4));
        assert_eq!(initiator.expected_hops, Some(2));
    }

    #[test]
    fn request_resource_transfer_can_start_before_responder_lrrtt_activation() {
        let dest_hash = [0x36; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let (_initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (responder, _proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();
        let link_id = responder.link_id;
        assert_eq!(responder.state, LinkState::Handshake);

        let (transport_tx, mut transport_rx) = mpsc::channel(64);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, dest_hash, None);

        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: responder,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        assert!(
            lm.start_resource_transfer(&link_id, b"direct".to_vec(), false)
                .is_none(),
            "ordinary callers still require an active link"
        );

        let resource_hash = lm
            .start_resource_transfer_inner(
                &link_id,
                ResourceTransferStart {
                    data: b"fetch-response".to_vec(),
                    metadata: None,
                    auto_compress: false,
                    request_id: None,
                    is_response: false,
                    allow_handshake: true,
                },
            )
            .expect("request-triggered resource can start during handshake");

        let outbound = transport_rx.try_recv().expect("resource adv queued");
        let TransportMessage::Outbound(request) = outbound else {
            panic!("expected outbound resource advertisement");
        };
        let (header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(header.destination_hash, link_id);
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceAdv
        );

        assert!(
            lm.active_links
                .get(&link_id)
                .unwrap()
                .outbound_resources
                .contains_key(&resource_hash)
        );
    }

    #[test]
    fn test_destination_link_acceptance_gating() {
        let (tx, _transport_rx) = mpsc::channel(64);
        let (_event_tx, event_rx) = mpsc::channel(16);

        let identity = Identity::new();
        let signing_key = identity.get_signing_key().unwrap();

        let mut lm =
            LinkManager::with_destination(tx, event_rx, &identity, "test.gate", Some(signing_key));

        if let Some(ref mut dest) = lm.destination {
            dest.set_accepts_links(false);
        }

        let dest_hash = lm.destination_hash;
        let (_initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::LinkRequest,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&request_data);

        lm.handle_link_request(&raw, 1);

        assert_eq!(lm.active_link_count(), 0);
    }

    /// Drives a full handshake; returns both ends `Active` with matching keys.
    fn handshaken_link_pair_with_identity() -> (Link, Link, Ed25519PrivateKey) {
        let dest_hash = [0x77u8; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (mut responder, proof_data) =
            rns_link::link::Link::new_responder(&request_data, &identity_key, dest_hash, 1)
                .expect("responder");
        let rtt_data = initiator
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .expect("validate proof");
        responder
            .receive_rtt_packet(&rtt_data)
            .expect("receive rtt");
        assert_eq!(initiator.state, LinkState::Active);
        assert_eq!(responder.state, LinkState::Active);
        (initiator, responder, identity_key)
    }

    /// Drives a full handshake; returns both ends `Active` with matching keys.
    fn handshaken_link_pair() -> (Link, Link) {
        let (initiator, responder, _identity_key) = handshaken_link_pair_with_identity();
        (initiator, responder)
    }

    fn resource_advertisement_packet(sender_link: &Link, advertisement: &[u8]) -> Vec<u8> {
        let encrypted = sender_link
            .encrypt(advertisement)
            .expect("encrypt Resource advertisement");
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
            destination_hash: sender_link.link_id,
            context: rns_wire::context::PacketContext::ResourceAdv,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&encrypted);
        raw
    }

    #[test]
    fn destination_request_handler_receives_context_and_enforces_allowlist() {
        let (mut sender_link, mut receiver_link) = handshaken_link_pair();
        let remote_identity = Identity::new();
        let identify = sender_link
            .identify(
                &remote_identity.get_public_key(),
                &remote_identity.get_signing_key().unwrap(),
            )
            .unwrap();
        receiver_link.handle_identification(&identify).unwrap();
        let link_id = receiver_link.link_id;

        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut manager = LinkManager::new(transport_tx, event_rx, [0xA1; 16], None);
        manager.active_links.insert(
            link_id,
            ActiveLink {
                link: receiver_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        type ObservedRequest = (String, Vec<u8>, [u8; 16], [u8; 16], [u8; 16], f64);
        let observed: Arc<Mutex<Option<ObservedRequest>>> = Arc::new(Mutex::new(None));
        let observed_handler = Arc::clone(&observed);
        assert!(manager.register_request_handler(
            "status",
            AllowPolicy::AllowList,
            Some(vec![remote_identity.hash]),
            true,
            move |request| {
                let remote_hash = request.remote_identity.as_ref().unwrap().hash;
                *observed_handler.lock().unwrap() = Some((
                    request.path,
                    request.data,
                    request.request_id,
                    request.link_id,
                    remote_hash,
                    request.requested_at,
                ));
                RequestOutcome::Reply(b"ok".to_vec())
            },
        ));

        let (encrypted_request, _) = sender_link
            .request("status", Some(b"hello"), std::time::Duration::from_secs(5))
            .unwrap();
        let request_header = rns_wire::header::PacketHeader {
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
            context: rns_wire::context::PacketContext::Request,
        };
        let mut raw = request_header.pack();
        raw.extend_from_slice(&encrypted_request);
        let packet_request_id =
            rns_wire::hash::truncated_packet_hash(&raw, request_header.flags.header_type);
        manager.handle_inbound_packet(&raw, 1);

        let observed = observed.lock().unwrap().take().unwrap();
        assert_eq!(observed.0, "status");
        assert_eq!(observed.1, b"hello");
        assert_eq!(observed.2, packet_request_id);
        assert_eq!(observed.3, link_id);
        assert_eq!(observed.4, remote_identity.hash);
        assert!(observed.5 > 0.0);

        let TransportMessage::Outbound(response) =
            transport_rx.try_recv().expect("inline response")
        else {
            panic!("expected inline response");
        };
        let (response_header, response_offset) =
            rns_wire::header::PacketHeader::unpack(&response.raw).unwrap();
        assert_eq!(
            response_header.context,
            rns_wire::context::PacketContext::Response
        );
        let (response_id, response_data) = sender_link
            .handle_response(&response.raw[response_offset..])
            .unwrap();
        assert_eq!(response_id, packet_request_id);
        assert_eq!(response_data, b"ok");

        let denied_calls = Arc::new(AtomicUsize::new(0));
        let denied_calls_handler = Arc::clone(&denied_calls);
        assert!(manager.register_request_handler(
            "status",
            AllowPolicy::AllowList,
            Some(vec![[0xFF; 16]]),
            false,
            move |_| {
                denied_calls_handler.fetch_add(1, Ordering::SeqCst);
                RequestOutcome::Reply(b"must not run".to_vec())
            },
        ));

        let (denied_request, _) = sender_link
            .request("status", Some(b"denied"), std::time::Duration::from_secs(5))
            .unwrap();
        let mut denied_raw = request_header.pack();
        denied_raw.extend_from_slice(&denied_request);
        manager.handle_inbound_packet(&denied_raw, 1);
        assert_eq!(denied_calls.load(Ordering::SeqCst), 0);
        assert!(transport_rx.try_recv().is_err());
        assert!(manager.deregister_request_handler("status"));
        assert!(!manager.deregister_request_handler("status"));
    }

    #[test]
    fn completed_request_resource_dispatches_handler_not_resource_callbacks() {
        let (sender_link, receiver_link) = handshaken_link_pair();
        let link_id = receiver_link.link_id;
        let (transport_tx, mut transport_rx) = mpsc::channel(64);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut manager = LinkManager::new(transport_tx, event_rx, [0xA2; 16], None);
        let (completion_tx, mut completion_rx) = mpsc::channel(1);
        manager.set_resource_completion_channel(completion_tx);
        let (legacy_tx, mut legacy_rx) = mpsc::channel(1);
        manager.set_resource_completed_channel(legacy_tx);
        manager.active_links.insert(
            link_id,
            ActiveLink {
                link: receiver_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        let request_data = vec![0x5A; rns_wire::constants::LINK_MDU * 2];
        let path_hash = truncated_hash(b"bulk");
        let request_value = rmpv::Value::Array(vec![
            rmpv::Value::F64(1_234.5),
            rmpv::Value::Binary(path_hash.to_vec()),
            rmpv::Value::Binary(request_data.clone()),
        ]);
        let mut packed_request = Vec::new();
        rmpv::encode::write_value(&mut packed_request, &request_value).unwrap();
        let expected_request_id = truncated_hash(&packed_request);

        type ObservedResourceRequest = ([u8; 16], Vec<u8>, f64);
        let observed: Arc<Mutex<Option<ObservedResourceRequest>>> = Arc::new(Mutex::new(None));
        let observed_handler = Arc::clone(&observed);
        assert!(manager.register_request_handler(
            "bulk",
            AllowPolicy::AllowAll,
            None,
            false,
            move |request| {
                *observed_handler.lock().unwrap() =
                    Some((request.request_id, request.data, request.requested_at));
                RequestOutcome::Reply(b"accepted".to_vec())
            },
        ));

        let mut sender = OutboundTransfer::new_encrypted(
            packed_request,
            false,
            std::time::Duration::from_millis(10),
            sender_link.session_keys().unwrap(),
        )
        .unwrap();
        sender.resource.flags.is_request = true;
        sender.resource.request_id = Some(expected_request_id.to_vec());
        let advertisement = match sender.tick() {
            TransferAction::SendAdvertisement(advertisement) => advertisement,
            other => panic!("unexpected Resource action: {other:?}"),
        };
        let resource_hash = sender.resource.resource_hash;
        manager.handle_inbound_packet(
            &resource_advertisement_packet(&sender_link, &advertisement),
            1,
        );

        assert!(
            manager
                .pending_inbound_request_resources
                .contains(&(link_id, resource_hash))
        );
        let _initial_request = transport_rx.try_recv().expect("initial Resource request");

        let total_parts = sender.resource.parts.len();
        let active = manager.active_links.get_mut(&link_id).unwrap();
        let inbound = active.inbound_resources.get_mut(&resource_hash).unwrap();
        inbound.resource.window.window = total_parts;
        inbound.outstanding_parts = total_parts;

        for part in &sender.resource.parts {
            let part_header = rns_wire::header::PacketHeader {
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
                context: rns_wire::context::PacketContext::Resource,
            };
            let mut raw = part_header.pack();
            raw.extend_from_slice(part);
            manager.handle_inbound_packet(&raw, 1);
        }

        let observed = observed.lock().unwrap().take().unwrap();
        assert_eq!(observed.0, expected_request_id);
        assert_eq!(observed.1, request_data);
        assert_eq!(observed.2, 1_234.5);
        assert!(completion_rx.try_recv().is_err());
        assert!(legacy_rx.try_recv().is_err());
        assert!(
            !manager
                .pending_inbound_request_resources
                .contains(&(link_id, resource_hash))
        );

        let mut saw_proof = false;
        let mut response = None;
        while let Ok(message) = transport_rx.try_recv() {
            let TransportMessage::Outbound(request) = message else {
                continue;
            };
            let (header, offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
            match header.context {
                rns_wire::context::PacketContext::ResourcePrf => saw_proof = true,
                rns_wire::context::PacketContext::Response => {
                    response = Some(request.raw[offset..].to_vec());
                }
                _ => {}
            }
        }
        assert!(saw_proof);
        let mut sender_link = sender_link;
        let (response_id, response_data) = sender_link.handle_response(&response.unwrap()).unwrap();
        assert_eq!(response_id, expected_request_id);
        assert_eq!(response_data, b"accepted");
    }

    #[test]
    fn channel_packet_is_proved_and_dispatched() {
        let (sender_link, receiver_link, _identity_key) = handshaken_link_pair_with_identity();
        let link_id = receiver_link.link_id;
        let receiver_rtt = receiver_link.rtt_secs();
        let receiver_keys = receiver_link.session_keys().unwrap();
        let mut sender_channel = rns_protocol::channel::LinkChannel::new_encrypted(
            link_id,
            sender_link.rtt_secs(),
            sender_link.session_keys().unwrap(),
        );
        let payload = sender_channel.prepare_send(&TestChannelNoop).unwrap();

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
            context: rns_wire::context::PacketContext::Channel,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&payload);
        let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);

        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, [0xBB; 16], None);
        let (channel_tx, mut channel_rx) = mpsc::channel(4);
        lm.set_channel_message_channel(channel_tx);
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: receiver_link,
                _interface_id: 1,
                channel: Some(rns_protocol::channel::LinkChannel::new_encrypted(
                    link_id,
                    receiver_rtt,
                    receiver_keys,
                )),
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        lm.handle_inbound_packet(&raw, 1);

        let delivered = channel_rx.try_recv().expect("channel message dispatched");
        assert_eq!(delivered.link_id, link_id);
        assert_eq!(delivered.msg_type, TEST_CHANNEL_MSG_TYPE);
        assert!(delivered.payload.is_empty());

        let outbound = transport_rx.try_recv().expect("channel proof queued");
        let TransportMessage::Outbound(request) = outbound else {
            panic!("expected outbound proof");
        };
        let (proof_header, proof_offset) =
            rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(proof_header.destination_hash, link_id);
        assert_eq!(
            proof_header.flags.packet_type,
            rns_wire::flags::PacketType::Proof
        );
        assert_eq!(proof_header.context, rns_wire::context::PacketContext::None);
        let proof_data = &request.raw[proof_offset..];
        assert_eq!(&proof_data[..32], &packet_hash);
        assert!(sender_link.validate_packet_proof(&packet_hash, proof_data));
    }

    /// 1.3.8 stats parity (Packet.py:291): tx counts the link payload after
    /// the context byte — the same unit rx counts (Link.py:929) — so a channel
    /// echo round-trip yields matching data counters on both peers.
    #[test]
    fn channel_echo_round_trip_counts_matching_tx_rx_bytes() {
        fn payload_len(raw: &[u8]) -> u64 {
            let (_, offset) = rns_wire::header::PacketHeader::unpack(raw).unwrap();
            (raw.len() - offset) as u64
        }
        fn next_outbound(rx: &mut mpsc::Receiver<TransportMessage>) -> Bytes {
            match rx.try_recv().expect("outbound packet queued") {
                TransportMessage::Outbound(request) => request.raw,
                _ => panic!("expected outbound packet"),
            }
        }
        fn active_link_entry(link: Link) -> ActiveLink {
            ActiveLink {
                link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            }
        }

        let (initiator, responder, _identity_key) = handshaken_link_pair_with_identity();
        let link_id = responder.link_id;

        let (tx_a, mut rx_a) = mpsc::channel(16);
        let (_event_tx_a, event_rx_a) = mpsc::channel(16);
        let mut lm_a = LinkManager::new(tx_a, event_rx_a, [0xA1; 16], None);
        lm_a.active_links
            .insert(link_id, active_link_entry(initiator));

        let (tx_b, mut rx_b) = mpsc::channel(16);
        let (_event_tx_b, event_rx_b) = mpsc::channel(16);
        let mut lm_b = LinkManager::new(tx_b, event_rx_b, [0xB1; 16], None);
        lm_b.active_links
            .insert(link_id, active_link_entry(responder));

        // A -> B channel data; B proves it back.
        lm_a.send_channel_message(&link_id, &TestChannelNoop)
            .unwrap();
        let data_ab = next_outbound(&mut rx_a);
        lm_b.handle_inbound_packet(&data_ab, 1);
        let proof_b = next_outbound(&mut rx_b);
        lm_a.handle_inbound_packet(&proof_b, 1);

        // B -> A echo; A proves it back.
        lm_b.send_channel_message(&link_id, &TestChannelNoop)
            .unwrap();
        let data_ba = next_outbound(&mut rx_b);
        lm_a.handle_inbound_packet(&data_ba, 1);
        let proof_a = next_outbound(&mut rx_a);
        lm_b.handle_inbound_packet(&proof_a, 1);

        let (a_tx, a_rx, a_txc, a_rxc) = lm_a.get_link(&link_id).unwrap().traffic_stats();
        let (b_tx, b_rx, b_txc, b_rxc) = lm_b.get_link(&link_id).unwrap().traffic_stats();

        // tx counts data + delivery proofs; proofs never route through
        // Link.receive, so rx counts data payloads only (Python parity).
        assert_eq!(a_tx, payload_len(&data_ab) + payload_len(&proof_a));
        assert_eq!(b_tx, payload_len(&data_ba) + payload_len(&proof_b));
        assert_eq!(a_rx, payload_len(&data_ba));
        assert_eq!(b_rx, payload_len(&data_ab));
        // Data components match across peers — the 1.3.8 unit consistency.
        assert_eq!(a_tx - payload_len(&proof_a), b_rx);
        assert_eq!(b_tx - payload_len(&proof_b), a_rx);
        assert_eq!((a_txc, a_rxc), (2, 1));
        assert_eq!((b_txc, b_rxc), (2, 1));
    }

    #[test]
    fn backend_identity_signs_link_packet_delivery_proof() {
        let (identity, identity_ed25519_pub, signing_seed) = backend_identity(true);
        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm =
            LinkManager::with_destination(transport_tx, event_rx, &identity, "test.hw", None);

        let dest_hash = lm.destination_hash;
        let identity_pub =
            rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&identity_ed25519_pub).unwrap();
        let signing_key = Ed25519PrivateKey::from_bytes(&signing_seed);
        let (mut sender_link, request_data) = Link::new_initiator(dest_hash, 1);
        let (mut receiver_link, proof_data) =
            Link::new_responder(&request_data, &signing_key, dest_hash, 1).unwrap();
        let rtt_data = sender_link
            .validate_proof(&proof_data, &identity_pub, &identity_ed25519_pub)
            .unwrap();
        receiver_link.receive_rtt_packet(&rtt_data).unwrap();
        let link_id = receiver_link.link_id;

        let encrypted = sender_link.encrypt(b"link payload").unwrap();
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
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&encrypted);
        let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);

        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: receiver_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        lm.handle_inbound_packet(&raw, 1);

        let outbound = transport_rx
            .try_recv()
            .expect("backend-signed delivery proof queued");
        let TransportMessage::Outbound(request) = outbound else {
            panic!("expected outbound proof");
        };
        let (proof_header, proof_offset) =
            rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(proof_header.destination_hash, link_id);
        assert_eq!(
            proof_header.flags.packet_type,
            rns_wire::flags::PacketType::Proof
        );
        assert_eq!(
            proof_header.context,
            rns_wire::context::PacketContext::LinkProof
        );
        let proof_data = &request.raw[proof_offset..];
        assert_eq!(&proof_data[..32], &packet_hash);
        assert!(sender_link.validate_packet_proof(&packet_hash, proof_data));
    }

    #[test]
    fn channel_packet_opens_channel_before_proof_and_dispatch() {
        let (sender_link, receiver_link, _identity_key) = handshaken_link_pair_with_identity();
        let link_id = receiver_link.link_id;
        let mut sender_channel = rns_protocol::channel::LinkChannel::new_encrypted(
            link_id,
            sender_link.rtt_secs(),
            sender_link.session_keys().unwrap(),
        );
        let payload = sender_channel.prepare_send(&TestChannelNoop).unwrap();

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
            context: rns_wire::context::PacketContext::Channel,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&payload);

        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, [0xBD; 16], None);
        let (channel_tx, mut channel_rx) = mpsc::channel(4);
        lm.set_channel_message_channel(channel_tx);
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: receiver_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        lm.handle_inbound_packet(&raw, 1);

        let delivered = channel_rx.try_recv().expect("channel message dispatched");
        assert_eq!(delivered.link_id, link_id);
        assert_eq!(delivered.msg_type, TEST_CHANNEL_MSG_TYPE);
        let outbound = transport_rx.try_recv().expect("channel proof queued");
        assert!(matches!(outbound, TransportMessage::Outbound(_)));
        assert!(lm.active_links.get(&link_id).unwrap().channel.is_some());
    }

    #[test]
    fn channel_packet_before_active_link_is_not_proved_or_dispatched() {
        let dest_hash = [0x78u8; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();
        let (mut sender_link, request_data) = Link::new_initiator(dest_hash, 1);
        let (receiver_link, proof_data) =
            rns_link::link::Link::new_responder(&request_data, &identity_key, dest_hash, 1)
                .expect("responder");
        let _rtt_data = sender_link
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .expect("validate proof");
        assert_eq!(sender_link.state, LinkState::Active);
        assert_eq!(receiver_link.state, LinkState::Handshake);

        let link_id = receiver_link.link_id;
        let receiver_keys = receiver_link.session_keys().unwrap();
        let mut sender_channel = rns_protocol::channel::LinkChannel::new_encrypted(
            link_id,
            sender_link.rtt_secs(),
            sender_link.session_keys().unwrap(),
        );
        let payload = sender_channel.prepare_send(&TestChannelNoop).unwrap();

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
            context: rns_wire::context::PacketContext::Channel,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&payload);

        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, [0xBE; 16], None);
        let (channel_tx, mut channel_rx) = mpsc::channel(4);
        lm.set_channel_message_channel(channel_tx);
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: receiver_link,
                _interface_id: 1,
                channel: Some(rns_protocol::channel::LinkChannel::new_encrypted(
                    link_id,
                    0.0,
                    receiver_keys,
                )),
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        lm.handle_inbound_packet(&raw, 1);

        assert!(channel_rx.try_recv().is_err());
        assert!(transport_rx.try_recv().is_err());
        assert!(
            lm.active_links
                .get(&link_id)
                .unwrap()
                .channel
                .as_ref()
                .unwrap()
                .is_ready_to_send()
        );
    }

    #[test]
    fn link_packet_proof_marks_channel_sequence_delivered() {
        let (sender_link, receiver_link, _identity_key) = handshaken_link_pair_with_identity();
        let link_id = sender_link.link_id;

        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, [0xBC; 16], None);
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: sender_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        let receipt = lm
            .send_channel_message(&link_id, &TestChannelNoop)
            .expect("channel message sent");
        assert_eq!(receipt.sequence, 0);

        let outbound = transport_rx.try_recv().expect("channel packet queued");
        let TransportMessage::Outbound(request) = outbound else {
            panic!("expected outbound channel packet");
        };
        let (sent_header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            sent_header.context,
            rns_wire::context::PacketContext::Channel
        );
        assert_eq!(
            receipt.packet_hash,
            rns_wire::hash::packet_hash(&request.raw, sent_header.flags.header_type)
        );
        assert_eq!(lm.get_channel(&link_id).unwrap().outstanding_count(), 1);

        let proof_data = receiver_link
            .prove_packet_with_link_key(&receipt.packet_hash)
            .unwrap();
        let proof_header = rns_wire::header::PacketHeader {
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
        let mut proof_raw = proof_header.pack();
        proof_raw.extend_from_slice(&proof_data);

        lm.handle_inbound_packet(&proof_raw, 1);

        assert_eq!(lm.get_channel(&link_id).unwrap().outstanding_count(), 0);
        assert!(lm.get_channel(&link_id).unwrap().is_ready_to_send());
    }

    #[test]
    fn send_link_packet_emits_plain_link_data_and_proof_event() {
        let (initiator_link, responder_link, _identity_key) = handshaken_link_pair_with_identity();
        let link_id = responder_link.link_id;

        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, [0xC1; 16], None);
        let (proof_tx, mut proof_rx) = mpsc::channel(4);
        lm.set_link_packet_proof_channel(proof_tx);
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: responder_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        let receipt = lm
            .send_link_packet(&link_id, b"backchannel payload")
            .expect("link packet queued");
        let outbound = transport_rx.try_recv().expect("link packet outbound");
        let TransportMessage::Outbound(request) = outbound else {
            panic!("expected outbound link packet");
        };
        let (sent_header, sent_offset) =
            rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(sent_header.context, rns_wire::context::PacketContext::None);
        assert_eq!(sent_header.destination_hash, link_id);
        assert_eq!(
            receipt.packet_hash,
            rns_wire::hash::packet_hash(&request.raw, sent_header.flags.header_type)
        );
        assert_eq!(
            initiator_link.decrypt(&request.raw[sent_offset..]).unwrap(),
            b"backchannel payload"
        );

        let proof_data = initiator_link
            .prove_packet_with_link_key(&receipt.packet_hash)
            .unwrap();
        let proof_header = rns_wire::header::PacketHeader {
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
        let mut proof_raw = proof_header.pack();
        proof_raw.extend_from_slice(&proof_data);
        lm.handle_inbound_packet(&proof_raw, 1);

        let proof = proof_rx.try_recv().expect("link packet proof event");
        assert_eq!(proof.link_id, link_id);
        assert_eq!(proof.packet_hash, receipt.packet_hash);
    }

    #[test]
    fn send_link_resource_emits_resource_proof_event() {
        let (_initiator_link, responder_link, _identity_key) = handshaken_link_pair_with_identity();
        let link_id = responder_link.link_id;

        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, [0xC2; 16], None);
        let (proof_tx, mut proof_rx) = mpsc::channel(4);
        lm.set_outbound_resource_proof_channel(proof_tx);
        let (resource_event_tx, mut resource_event_rx) = mpsc::channel(4);
        lm.set_resource_event_channel(resource_event_tx);
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: responder_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        let receipt = lm
            .send_link_resource(&link_id, b"resource payload".to_vec(), false)
            .expect("resource started");
        assert_eq!(
            resource_event_rx.try_recv().unwrap(),
            LinkResourceEvent::Started {
                link_id,
                resource_id: receipt.resource_hash,
                direction: LinkResourceDirection::Outbound,
                data_size: b"resource payload".len(),
                total_segments: 1,
            }
        );
        let outbound = transport_rx.try_recv().expect("resource ADV outbound");
        let TransportMessage::Outbound(request) = outbound else {
            panic!("expected outbound resource ADV");
        };
        let (adv_header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            adv_header.context,
            rns_wire::context::PacketContext::ResourceAdv
        );

        let proof_data = {
            let active = lm.active_links.get(&link_id).unwrap();
            let transfer = active
                .outbound_resources
                .get(&receipt.resource_hash)
                .expect("outbound resource tracked");
            let mut proof = Vec::new();
            proof.extend_from_slice(&transfer.resource.resource_hash);
            proof.extend_from_slice(&transfer.resource.expected_proof);
            proof
        };
        let proof_header = rns_wire::header::PacketHeader {
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
            context: rns_wire::context::PacketContext::ResourcePrf,
        };
        let mut proof_raw = proof_header.pack();
        proof_raw.extend_from_slice(&proof_data);
        lm.handle_inbound_packet(&proof_raw, 1);

        let proof = proof_rx.try_recv().expect("resource proof event");
        assert_eq!(proof.link_id, link_id);
        assert_eq!(proof.resource_hash, receipt.resource_hash);
        assert_eq!(
            resource_event_rx.try_recv().unwrap(),
            LinkResourceEvent::Concluded {
                link_id,
                resource_id: receipt.resource_hash,
                direction: LinkResourceDirection::Outbound,
                conclusion: LinkResourceConclusion::Complete,
            }
        );
    }

    #[test]
    fn outbound_resource_can_be_cancelled_through_manager_command() {
        let (peer_link, local_link, _identity_key) = handshaken_link_pair_with_identity();
        let link_id = local_link.link_id;
        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut manager = LinkManager::new(transport_tx, event_rx, [0xC5; 16], None);
        let (resource_event_tx, mut resource_event_rx) = mpsc::channel(4);
        manager.set_resource_event_channel(resource_event_tx);
        manager.active_links.insert(
            link_id,
            ActiveLink {
                link: local_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        let receipt = manager
            .send_link_resource(&link_id, b"cancel me".to_vec(), false)
            .unwrap();
        let _advertisement = transport_rx.try_recv().unwrap();
        let _started = resource_event_rx.try_recv().unwrap();
        let (result_tx, mut result_rx) = oneshot::channel();
        assert!(
            manager.handle_command(LinkManagerCommand::CancelLinkResource {
                link_id,
                resource_id: receipt.resource_hash,
                direction: LinkResourceDirection::Outbound,
                result_tx: Some(result_tx),
            })
        );
        assert!(result_rx.try_recv().unwrap());

        let TransportMessage::Outbound(cancellation) = transport_rx.try_recv().unwrap() else {
            panic!("expected outbound Resource cancellation");
        };
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&cancellation.raw).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceIcl
        );
        assert_eq!(
            peer_link.decrypt(&cancellation.raw[offset..]).unwrap(),
            receipt.resource_hash
        );
        assert_eq!(
            resource_event_rx.try_recv().unwrap(),
            LinkResourceEvent::Concluded {
                link_id,
                resource_id: receipt.resource_hash,
                direction: LinkResourceDirection::Outbound,
                conclusion: LinkResourceConclusion::Cancelled,
            }
        );
        assert!(manager.active_links[&link_id].outbound_resources.is_empty());
    }

    #[test]
    fn tick_retries_lost_resource_advertisement() {
        let (peer_link, local_link, _identity_key) = handshaken_link_pair_with_identity();
        let link_id = local_link.link_id;
        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut manager = LinkManager::new(transport_tx, event_rx, [0xC3; 16], None);

        let mut transfer = OutboundTransfer::new(
            b"advertisement retry".to_vec(),
            false,
            std::time::Duration::from_millis(1),
        )
        .unwrap();
        assert!(matches!(
            transfer.tick(),
            TransferAction::SendAdvertisement(_)
        ));
        transfer.started_at = std::time::Instant::now() - std::time::Duration::from_secs(60);
        let resource_hash = transfer.resource.resource_hash;

        let mut outbound_resources = HashMap::new();
        outbound_resources.insert(resource_hash, transfer);
        manager.active_links.insert(
            link_id,
            ActiveLink {
                link: local_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources,
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        manager.tick();

        let TransportMessage::Outbound(request) =
            transport_rx.try_recv().expect("retried advertisement")
        else {
            panic!("expected outbound advertisement");
        };
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceAdv
        );
        let plaintext = peer_link.decrypt(&request.raw[offset..]).unwrap();
        let advertisement = ResourceAdvertisement::unpack(&plaintext).unwrap();
        assert_eq!(advertisement.resource_hash, resource_hash);
        assert_eq!(
            manager.active_links[&link_id].outbound_resources[&resource_hash].retries,
            1
        );
    }

    #[test]
    fn tick_retries_stalled_inbound_resource_request() {
        let (peer_link, local_link, _identity_key) = handshaken_link_pair_with_identity();
        let link_id = local_link.link_id;
        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut manager = LinkManager::new(transport_tx, event_rx, [0xC4; 16], None);

        let outbound =
            rns_protocol::resource::OutboundResource::new(vec![0xAB; 2000], false, None).unwrap();
        let resource_hash = outbound.resource_hash;
        let mut transfer = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            outbound.data.len(),
            outbound.random_hash,
            resource_hash,
            outbound.flags,
            outbound.map_hashes,
            std::time::Duration::from_millis(1),
        )
        .unwrap();
        assert!(matches!(
            transfer.request_next(),
            TransferAction::SendRequest(_)
        ));
        transfer.last_activity = std::time::Instant::now() - std::time::Duration::from_secs(60);
        let initial_retries = transfer.retries_left;

        let mut inbound_resources = HashMap::new();
        inbound_resources.insert(resource_hash, transfer);
        let mut local_link = local_link;
        local_link.track_incoming_resource(resource_hash);
        manager.active_links.insert(
            link_id,
            ActiveLink {
                link: local_link,
                _interface_id: 1,
                channel: None,
                inbound_resources,
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        manager.tick();

        let TransportMessage::Outbound(request) =
            transport_rx.try_recv().expect("retried resource request")
        else {
            panic!("expected outbound resource request");
        };
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceReq
        );
        let plaintext = peer_link.decrypt(&request.raw[offset..]).unwrap();
        assert!(
            plaintext
                .windows(resource_hash.len())
                .any(|window| window == resource_hash)
        );
        assert_eq!(
            manager.active_links[&link_id].inbound_resources[&resource_hash].retries_left,
            initial_retries - 1
        );
    }

    #[test]
    fn unmatched_valid_link_packet_proof_does_not_record_keepalive_proof() {
        let (sender_link, receiver_link, _identity_key) = handshaken_link_pair_with_identity();
        let link_id = sender_link.link_id;

        let (transport_tx, _transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, [0xBF; 16], None);
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: sender_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        let packet_hash = [0x5Au8; 32];
        let proof_data = receiver_link
            .prove_packet_with_link_key(&packet_hash)
            .expect("valid link-key proof");
        let proof_header = rns_wire::header::PacketHeader {
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
        let mut proof_raw = proof_header.pack();
        proof_raw.extend_from_slice(&proof_data);

        assert!(
            lm.active_links
                .get(&link_id)
                .unwrap()
                .link
                .keepalive
                .last_proof
                .is_none()
        );
        lm.handle_inbound_packet(&proof_raw, 1);
        assert!(
            lm.active_links
                .get(&link_id)
                .unwrap()
                .link
                .keepalive
                .last_proof
                .is_none()
        );
    }

    /// Receive-side split-resource reassembly: two manually-marked segments
    /// produce one `ResourceCompletion` keyed by `original_hash`. Synthesizing
    /// segments avoids the >2000 parts that `MultiSegmentOutbound` would emit;
    /// rncp_interop covers realistic sizes via the full HMU loop.
    #[tokio::test(flavor = "current_thread")]
    async fn test_split_resource_inbound_reassembles_via_coordinator() {
        use rns_protocol::resource::{OutboundResource, OutboundTransfer, TransferAction};

        let (sender_link, receiver_link) = handshaken_link_pair();
        let link_id = receiver_link.link_id;

        let (transport_tx, mut transport_rx) = mpsc::channel(4096);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, [0xBB; 16], None);

        let (completion_tx, mut completion_rx) = mpsc::channel(8);
        lm.set_resource_completion_channel(completion_tx);
        let (legacy_tx, mut legacy_rx) = mpsc::channel(8);
        lm.set_resource_completed_channel(legacy_tx);

        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: receiver_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        // Two 8 KiB chunks; ~20 parts each fit in the ADV's initial hashmap
        // (~70 entries) so no HMU round-trip is needed.
        let chunk_size = 8 * 1024;
        let chunk_a: Vec<u8> = (0..chunk_size).map(|i| (i % 251) as u8).collect();
        let chunk_b: Vec<u8> = (0..chunk_size).map(|i| ((i + 7) % 251) as u8).collect();
        let payload: Vec<u8> = chunk_a.iter().chain(chunk_b.iter()).copied().collect();

        // `original_hash` is just the coordinator HashMap key; per-segment
        // hashes enforce integrity.
        let original_hash: [u8; 32] = [0x5A; 32];

        let chunks = [chunk_a, chunk_b];
        let total_segments = chunks.len();

        let encrypt_fn = |d: &[u8]| sender_link.encrypt(d).expect("link encrypt");
        let rtt = std::time::Duration::from_millis(50);

        for (i, chunk) in chunks.into_iter().enumerate() {
            let mut segment =
                OutboundResource::with_options(chunk, false, None, None, Some(&encrypt_fn))
                    .expect("build segment");
            // Stamp split metadata so the ADV carries total_segments / segment_index / original_hash.
            segment.flags.split = true;
            segment.segment_index = i + 1;
            segment.total_segments = total_segments;
            segment.original_hash = Some(original_hash);

            let mut transfer = OutboundTransfer::from_prebuilt(segment, rtt);
            let action = transfer.tick();
            let adv_bytes = match action {
                TransferAction::SendAdvertisement(b) => b,
                other => panic!("expected SendAdvertisement, got {other:?}"),
            };

            let encrypted_adv = sender_link.encrypt(&adv_bytes).expect("encrypt adv");
            let adv_header = rns_wire::header::PacketHeader {
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
                context: rns_wire::context::PacketContext::ResourceAdv,
            };
            let mut adv_raw = adv_header.pack();
            adv_raw.extend_from_slice(&encrypted_adv);
            lm.handle_inbound_packet(&adv_raw, 1);

            // Widen the receiver's WINDOW_INITIAL=4 so the blast fits in one shot.
            let segment_rh = transfer.resource.resource_hash;
            let total_parts = transfer.resource.parts.len();
            if let Some(active) = lm.active_links.get_mut(&link_id) {
                if let Some(in_transfer) = active.inbound_resources.get_mut(&segment_rh) {
                    in_transfer.resource.window.window = total_parts;
                    in_transfer.outstanding_parts = total_parts;
                }
            }

            for part in &transfer.resource.parts {
                let part_header = rns_wire::header::PacketHeader {
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
                    context: rns_wire::context::PacketContext::Resource,
                };
                let mut part_raw = part_header.pack();
                part_raw.extend_from_slice(part);
                lm.handle_inbound_packet(&part_raw, 1);
            }
        }

        // Drain the queued ResourceReq / ResourcePrf so the channel isn't pinned.
        while transport_rx.try_recv().is_ok() {}

        let completion = completion_rx
            .try_recv()
            .expect("expected exactly one ResourceCompletion");
        assert_eq!(
            completion.resource_hash, original_hash,
            "completion must surface original_hash, not a per-segment hash"
        );
        assert_eq!(completion.link_id, link_id);
        assert_eq!(completion.data, payload, "reassembled bytes match input");
        assert!(
            completion_rx.try_recv().is_err(),
            "no per-segment completion events should fire for a split resource"
        );

        let (legacy_data, legacy_link) = legacy_rx
            .try_recv()
            .expect("legacy channel must also fire once");
        assert_eq!(legacy_link, link_id);
        assert_eq!(
            legacy_data, payload,
            "legacy callback receives reassembled blob, not per-segment chunks"
        );
        assert!(
            legacy_rx.try_recv().is_err(),
            "legacy channel must also collapse to one event per original"
        );

        // Coordinator + routing entries cleaned up after success.
        let active = lm.active_links.get(&link_id).unwrap();
        assert!(
            active.inbound_split_resources.is_empty(),
            "coordinator must be removed after reassembly completes"
        );
        assert!(
            active.segment_routing.is_empty(),
            "routing entries must be removed after each segment completes"
        );
        assert!(
            active.inbound_resources.is_empty(),
            "per-segment transfers must be removed after each segment completes"
        );
    }

    /// MAX_SEGMENTS cap: oversized `total_segments` is rejected without
    /// allocating a coordinator (would OOM `Vec` otherwise).
    #[tokio::test(flavor = "current_thread")]
    async fn test_split_resource_rejects_oversized_total_segments() {
        use rns_protocol::resource::{MAX_SEGMENTS, ResourceFlags};
        use rns_protocol::resource_adv::ResourceAdvertisement;

        let (sender_link, receiver_link) = handshaken_link_pair();
        let link_id = receiver_link.link_id;

        let (transport_tx, mut _transport_rx) = mpsc::channel(64);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, [0xCC; 16], None);
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: receiver_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        let evil_total = MAX_SEGMENTS + 1;
        let mut adv = ResourceAdvertisement::with_metadata_size(
            64,
            32,
            1,
            [0x42; 32],
            vec![0x11; 4],
            ResourceFlags {
                split: true,
                ..Default::default()
            },
            &[],
            rns_wire::constants::LINK_MDU,
            0,
        );
        adv.original_hash = [0x99; 32];
        adv.segment_index = 1;
        adv.total_segments = evil_total;

        let adv_bytes = adv.pack();
        let encrypted = sender_link.encrypt(&adv_bytes).expect("encrypt");
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
            context: rns_wire::context::PacketContext::ResourceAdv,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&encrypted);
        lm.handle_inbound_packet(&raw, 1);

        let active = lm.active_links.get(&link_id).expect("link still present");
        assert!(
            active.inbound_split_resources.is_empty(),
            "no coordinator must be allocated for an over-cap total_segments"
        );
        assert!(
            active.segment_routing.is_empty(),
            "no routing must be inserted for a rejected ADV"
        );
        assert!(
            active.inbound_resources.is_empty(),
            "no per-segment transfer must be opened for a rejected ADV"
        );
    }

    // 1.3.9: an inbound request-resource is ignored (no transfer opened, link
    // kept) when the destination has no request handlers registered.
    #[tokio::test(flavor = "current_thread")]
    async fn test_inbound_request_resource_ignored_without_handlers() {
        use rns_protocol::resource::ResourceFlags;
        use rns_protocol::resource_adv::ResourceAdvertisement;

        let (sender_link, receiver_link) = handshaken_link_pair();
        let link_id = receiver_link.link_id;

        let (transport_tx, mut _transport_rx) = mpsc::channel(64);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, [0xCC; 16], None);
        assert!(lm.request_handler.is_none() && lm.request_handler_ex.is_none());
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: receiver_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        let adv = ResourceAdvertisement::with_metadata_size(
            64,
            32,
            1,
            [0x42; 32],
            vec![0x11; 4],
            ResourceFlags {
                is_request: true,
                ..Default::default()
            },
            &[],
            rns_wire::constants::LINK_MDU,
            0,
        );
        let encrypted = sender_link.encrypt(&adv.pack()).expect("encrypt");
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
            context: rns_wire::context::PacketContext::ResourceAdv,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&encrypted);
        lm.handle_inbound_packet(&raw, 1);

        let active = lm.active_links.get(&link_id).expect("link still present");
        assert!(
            active.inbound_resources.is_empty(),
            "request-resource must not open a transfer without handlers"
        );
    }

    #[test]
    fn resource_application_policy_accepts_rejects_and_ignores() {
        let (sender_link, receiver_link) = handshaken_link_pair();
        let link_id = receiver_link.link_id;
        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut manager = LinkManager::new(transport_tx, event_rx, [0xCE; 16], None);
        manager.active_links.insert(
            link_id,
            ActiveLink {
                link: receiver_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );
        manager.set_resource_strategy(ResourceStrategy::AcceptApp);

        let decision_calls = Arc::new(AtomicUsize::new(0));
        let rejected_calls = Arc::clone(&decision_calls);
        manager.set_resource_accept_handler(move |seen_link, advertisement| {
            assert_eq!(seen_link, link_id);
            assert_eq!(advertisement.data_size, b"rejected".len());
            rejected_calls.fetch_add(1, Ordering::SeqCst);
            false
        });

        let mut rejected_sender = OutboundTransfer::new_encrypted(
            b"rejected".to_vec(),
            false,
            std::time::Duration::from_millis(10),
            sender_link.session_keys().unwrap(),
        )
        .unwrap();
        let rejected_advertisement = match rejected_sender.tick() {
            TransferAction::SendAdvertisement(advertisement) => advertisement,
            other => panic!("unexpected Resource action: {other:?}"),
        };
        let rejected_hash = rejected_sender.resource.resource_hash;
        manager.handle_inbound_packet(
            &resource_advertisement_packet(&sender_link, &rejected_advertisement),
            1,
        );

        let TransportMessage::Outbound(rejection) =
            transport_rx.try_recv().expect("Resource rejection")
        else {
            panic!("expected outbound Resource rejection");
        };
        let (rejection_header, rejection_offset) =
            rns_wire::header::PacketHeader::unpack(&rejection.raw).unwrap();
        assert_eq!(
            rejection_header.context,
            rns_wire::context::PacketContext::ResourceRcl
        );
        assert_eq!(
            sender_link
                .decrypt(&rejection.raw[rejection_offset..])
                .unwrap(),
            rejected_hash
        );
        assert!(manager.active_links[&link_id].inbound_resources.is_empty());

        let accepted_calls = Arc::clone(&decision_calls);
        manager.set_resource_accept_handler(move |seen_link, advertisement| {
            assert_eq!(seen_link, link_id);
            assert_eq!(advertisement.data_size, b"accepted".len());
            accepted_calls.fetch_add(1, Ordering::SeqCst);
            true
        });
        let mut accepted_sender = OutboundTransfer::new_encrypted(
            b"accepted".to_vec(),
            false,
            std::time::Duration::from_millis(10),
            sender_link.session_keys().unwrap(),
        )
        .unwrap();
        let accepted_advertisement = match accepted_sender.tick() {
            TransferAction::SendAdvertisement(advertisement) => advertisement,
            other => panic!("unexpected Resource action: {other:?}"),
        };
        let accepted_hash = accepted_sender.resource.resource_hash;
        manager.handle_inbound_packet(
            &resource_advertisement_packet(&sender_link, &accepted_advertisement),
            1,
        );

        let TransportMessage::Outbound(request) =
            transport_rx.try_recv().expect("initial Resource request")
        else {
            panic!("expected outbound Resource request");
        };
        let (request_header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            request_header.context,
            rns_wire::context::PacketContext::ResourceReq
        );
        assert!(
            manager.active_links[&link_id]
                .inbound_resources
                .contains_key(&accepted_hash)
        );
        assert_eq!(decision_calls.load(Ordering::SeqCst), 2);

        manager.set_resource_strategy(ResourceStrategy::AcceptNone);
        let mut ignored_sender = OutboundTransfer::new_encrypted(
            b"ignored".to_vec(),
            false,
            std::time::Duration::from_millis(10),
            sender_link.session_keys().unwrap(),
        )
        .unwrap();
        let ignored_advertisement = match ignored_sender.tick() {
            TransferAction::SendAdvertisement(advertisement) => advertisement,
            other => panic!("unexpected Resource action: {other:?}"),
        };
        let ignored_hash = ignored_sender.resource.resource_hash;
        manager.handle_inbound_packet(
            &resource_advertisement_packet(&sender_link, &ignored_advertisement),
            1,
        );

        assert!(transport_rx.try_recv().is_err());
        assert!(
            !manager.active_links[&link_id]
                .inbound_resources
                .contains_key(&ignored_hash)
        );
        assert_eq!(
            decision_calls.load(Ordering::SeqCst),
            2,
            "AcceptNone must not invoke the application callback"
        );

        manager.set_request_handler(|_, _, _| None);
        let mut request_sender = OutboundTransfer::new_encrypted(
            b"request resource".to_vec(),
            false,
            std::time::Duration::from_millis(10),
            sender_link.session_keys().unwrap(),
        )
        .unwrap();
        request_sender.resource.flags.is_request = true;
        let request_advertisement = match request_sender.tick() {
            TransferAction::SendAdvertisement(advertisement) => advertisement,
            other => panic!("unexpected Resource action: {other:?}"),
        };
        let request_hash = request_sender.resource.resource_hash;
        manager.handle_inbound_packet(
            &resource_advertisement_packet(&sender_link, &request_advertisement),
            1,
        );

        let TransportMessage::Outbound(request) = transport_rx
            .try_recv()
            .expect("request-Resource acceptance")
        else {
            panic!("expected outbound Resource request");
        };
        let (request_header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            request_header.context,
            rns_wire::context::PacketContext::ResourceReq
        );
        assert!(
            manager.active_links[&link_id]
                .inbound_resources
                .contains_key(&request_hash),
            "request Resources bypass the ordinary application policy"
        );
        assert_eq!(decision_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn inbound_resource_lifecycle_reports_progress_and_completion() {
        let (sender_link, receiver_link) = handshaken_link_pair();
        let link_id = receiver_link.link_id;
        let payload = b"inbound lifecycle".to_vec();
        let (transport_tx, mut transport_rx) = mpsc::channel(16);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut manager = LinkManager::new(transport_tx, event_rx, [0xCF; 16], None);
        let (resource_event_tx, mut resource_event_rx) = mpsc::channel(8);
        manager.set_resource_event_channel(resource_event_tx);
        manager.active_links.insert(
            link_id,
            ActiveLink {
                link: receiver_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        let mut sender = OutboundTransfer::new_encrypted(
            payload.clone(),
            false,
            std::time::Duration::from_millis(10),
            sender_link.session_keys().unwrap(),
        )
        .unwrap();
        let advertisement = match sender.tick() {
            TransferAction::SendAdvertisement(advertisement) => advertisement,
            other => panic!("unexpected Resource action: {other:?}"),
        };
        let resource_id = sender.resource.resource_hash;
        manager.handle_inbound_packet(
            &resource_advertisement_packet(&sender_link, &advertisement),
            1,
        );
        assert_eq!(
            resource_event_rx.try_recv().unwrap(),
            LinkResourceEvent::Started {
                link_id,
                resource_id,
                direction: LinkResourceDirection::Inbound,
                data_size: payload.len(),
                total_segments: 1,
            }
        );

        let TransportMessage::Outbound(request) =
            transport_rx.try_recv().expect("initial Resource request")
        else {
            panic!("expected outbound Resource request");
        };
        let (request_header, request_offset) =
            rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            request_header.context,
            rns_wire::context::PacketContext::ResourceReq
        );
        let plaintext = sender_link.decrypt(&request.raw[request_offset..]).unwrap();
        let packet_hash =
            rns_wire::hash::packet_hash(&request.raw, request_header.flags.header_type);
        let actions = sender.handle_request_packet(packet_hash, &plaintext);
        assert_eq!(actions.len(), 1);
        let TransferAction::SendPart(_, part) = &actions[0] else {
            panic!("expected one Resource part");
        };
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
            context: rns_wire::context::PacketContext::Resource,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(part);
        manager.handle_inbound_packet(&raw, 1);

        assert_eq!(
            resource_event_rx.try_recv().unwrap(),
            LinkResourceEvent::Progress {
                link_id,
                resource_id,
                direction: LinkResourceDirection::Inbound,
                transferred: payload.len(),
                total: payload.len(),
            }
        );
        assert_eq!(
            resource_event_rx.try_recv().unwrap(),
            LinkResourceEvent::Concluded {
                link_id,
                resource_id,
                direction: LinkResourceDirection::Inbound,
                conclusion: LinkResourceConclusion::Complete,
            }
        );

        let TransportMessage::Outbound(proof) = transport_rx.try_recv().expect("Resource proof")
        else {
            panic!("expected outbound Resource proof");
        };
        let (proof_header, proof_offset) =
            rns_wire::header::PacketHeader::unpack(&proof.raw).unwrap();
        assert_eq!(
            proof_header.context,
            rns_wire::context::PacketContext::ResourcePrf
        );
        assert!(sender.handle_proof(&proof.raw[proof_offset..]));
        assert!(manager.active_links[&link_id].inbound_resources.is_empty());
    }

    // 1.3.9: a successfully-decrypted but unparseable advertisement tears down
    // the link (the dispatch-exception teardown).
    #[tokio::test(flavor = "current_thread")]
    async fn test_unparseable_advertisement_tears_down_link() {
        let (sender_link, receiver_link) = handshaken_link_pair();
        let link_id = receiver_link.link_id;

        let (transport_tx, mut _transport_rx) = mpsc::channel(64);
        let (_event_tx, event_rx) = mpsc::channel(16);
        let mut lm = LinkManager::new(transport_tx, event_rx, [0xCC; 16], None);
        lm.active_links.insert(
            link_id,
            ActiveLink {
                link: receiver_link,
                _interface_id: 1,
                channel: None,
                inbound_resources: HashMap::new(),
                outbound_resources: HashMap::new(),
                outbound_split_queues: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                segment_routing: HashMap::new(),
            },
        );

        // A payload that decrypts fine but is not a msgpack map fails unpack.
        let encrypted = sender_link
            .encrypt(b"\xff not a resource advertisement")
            .expect("encrypt");
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
            context: rns_wire::context::PacketContext::ResourceAdv,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&encrypted);
        lm.handle_inbound_packet(&raw, 1);

        assert!(
            !lm.active_links.contains_key(&link_id),
            "unparseable advertisement must tear the link down"
        );
    }

    #[test]
    fn test_real_link_request_handshake() {
        let (tx, mut transport_rx) = mpsc::channel(64);
        let (_event_tx, event_rx) = mpsc::channel(16);

        let identity_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xEE; 16];
        let mut lm = LinkManager::new(tx, event_rx, dest_hash, Some(identity_key));

        let (initiator_link, request_data) = Link::new_initiator(dest_hash, 1);

        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::LinkRequest,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&request_data);

        lm.handle_link_request(&raw, 1);

        assert_eq!(lm.active_link_count(), 1);
        let link_id = initiator_link.link_id;
        let active = lm.get_link(&link_id).unwrap();
        assert_eq!(active.state, LinkState::Handshake);

        let outbound = transport_rx.try_recv();
        assert!(
            outbound.is_ok(),
            "proof packet should be queued for sending"
        );
    }
}
