//! Persistent initiator-side Reticulum Link sessions for applications.
//!
//! Unlike [`crate::link_client::LinkClient`], which opens a Link for one
//! request/response exchange, this module keeps the Link alive and exposes
//! ordinary encrypted Link packets until either peer closes the session.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Cursor;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rns_crypto::ed25519::Ed25519PublicKey;
use rns_identity::identity::Identity;
use rns_link::link::{CloseReason, Link, LinkAction, LinkPhyStats, LinkState};
use rns_protocol::channel::{
    ChannelError, HandlerId, LinkChannel, MessageCallback, PreparedChannelData,
};
use rns_protocol::channel_message::{ChannelMessageError, MessageBase};
use rns_protocol::resource::{
    CancelType, HASHMAP_IS_EXHAUSTED, InboundTransfer, MAPHASH_LEN, MAX_SEGMENTS,
    MultiSegmentInbound, OutboundTransfer, RANDOM_HASH_SIZE, TransferAction, get_map_hash,
    parse_hashmap_update,
};
use rns_protocol::resource_adv::ResourceAdvertisement;
use rns_transport::link_messages::{DestinationEvent, PacketMetrics};
use rns_transport::messages::{
    AnnounceRpcEntry, InterfaceId, OutboundRequest, TransportMessage, TransportQuery,
    TransportQueryResponse,
};
use tokio::sync::{mpsc, oneshot, watch};

use crate::resource_source::{
    PreparedResourceSegment, PreparedResourceSource, ResourceOptions, ResourceSource,
    ResourceSourceError,
};

const COMMAND_BUFFER: usize = 64;
const EVENT_BUFFER: usize = 256;
const MAX_PENDING_REQUESTS: usize = 64;
const MAX_QUEUED_RESOURCES: usize = 8;
const MAX_PENDING_RESOURCE_OFFERS: usize = 8;
const RESOURCE_OFFER_TIMEOUT: Duration = Duration::from_secs(30);
const RESOURCE_REJECTION_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct LinkSessionConfig {
    pub destination_hash: [u8; 16],
    pub remote_public_key: [u8; 64],
    pub hops: u8,
    pub establishment_timeout: Duration,
    pub client_label: String,
    pub identify: bool,
    pub track_phy_stats: bool,
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
            track_phy_stats: false,
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
    RequestConcluded {
        request_id: [u8; 16],
        succeeded: bool,
    },
    ResourceStarted {
        resource_id: [u8; 32],
        direction: LinkSessionResourceDirection,
        data_size: usize,
        total_segments: usize,
    },
    ResourceProgress {
        resource_id: [u8; 32],
        direction: LinkSessionResourceDirection,
        transferred: usize,
        total: usize,
    },
    ResourceConcluded {
        resource_id: [u8; 32],
        direction: LinkSessionResourceDirection,
        succeeded: bool,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSessionResponse {
    pub request_id: [u8; 16],
    pub data: Vec<u8>,
    /// Metadata attached to a file-style Resource response.
    pub metadata: Option<Vec<u8>>,
    pub response_time: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSessionChannelReceipt {
    pub link_id: [u8; 16],
    pub sequence: u16,
    pub packet_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSessionResourceDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSessionResourceReceipt {
    pub link_id: [u8; 16],
    pub resource_id: [u8; 32],
    pub data_size: usize,
    pub total_segments: usize,
}

/// App-facing lifecycle handle for an outbound Link Resource.
///
/// The transfer itself remains owned by the Link session actor. Cloning the
/// progress receiver does not duplicate transfer state, and dropping this
/// handle does not implicitly cancel the transfer.
pub struct LinkSessionResourceHandle {
    link_id: [u8; 16],
    resource_id: [u8; 32],
    data_size: usize,
    total_segments: usize,
    progress_rx: watch::Receiver<f64>,
    conclusion_rx: oneshot::Receiver<Result<LinkSessionResourceReceipt, LinkSessionResourceError>>,
    command_tx: mpsc::Sender<LinkSessionCommand>,
}

impl LinkSessionResourceHandle {
    pub fn link_id(&self) -> [u8; 16] {
        self.link_id
    }

    pub fn resource_id(&self) -> [u8; 32] {
        self.resource_id
    }

    pub fn data_size(&self) -> usize {
        self.data_size
    }

    pub fn total_segments(&self) -> usize {
        self.total_segments
    }

    pub fn progress(&self) -> watch::Receiver<f64> {
        self.progress_rx.clone()
    }

    pub async fn cancel(&self) -> Result<bool, LinkSessionResourceError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::Resource(
                LinkSessionResourceCommand::Cancel {
                    resource_id: self.resource_id,
                    result_tx,
                },
            ))
            .await
            .map_err(|_| LinkSessionResourceError::SessionClosed)?;
        result_rx
            .await
            .map_err(|_| LinkSessionResourceError::SessionClosed)?
    }

    pub async fn concluded(self) -> Result<LinkSessionResourceReceipt, LinkSessionResourceError> {
        self.conclusion_rx
            .await
            .map_err(|_| LinkSessionResourceError::SessionClosed)?
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSessionReceivedResource {
    pub link_id: [u8; 16],
    pub resource_id: [u8; 32],
    pub data: Vec<u8>,
    pub metadata: Option<Vec<u8>>,
    pub total_segments: usize,
    pub request_id: Option<Vec<u8>>,
    pub is_request: bool,
    pub is_response: bool,
}

/// A bounded inbound Resource advertisement awaiting an application decision.
///
/// Offers are rejected after 30 seconds if the application does not decide.
/// Accepting creates a lifecycle handle; dropping an offer leaves that timeout
/// in force rather than accepting data implicitly.
pub struct LinkSessionResourceOffer {
    link_id: [u8; 16],
    resource_id: [u8; 32],
    segment_hash: [u8; 32],
    data_size: usize,
    transfer_size: usize,
    total_segments: usize,
    request_id: Option<Vec<u8>>,
    is_request: bool,
    is_response: bool,
    command_tx: mpsc::Sender<LinkSessionCommand>,
}

impl LinkSessionResourceOffer {
    pub fn link_id(&self) -> [u8; 16] {
        self.link_id
    }

    pub fn resource_id(&self) -> [u8; 32] {
        self.resource_id
    }

    pub fn data_size(&self) -> usize {
        self.data_size
    }

    pub fn transfer_size(&self) -> usize {
        self.transfer_size
    }

    pub fn total_segments(&self) -> usize {
        self.total_segments
    }

    pub fn request_id(&self) -> Option<&[u8]> {
        self.request_id.as_deref()
    }

    pub fn is_request(&self) -> bool {
        self.is_request
    }

    pub fn is_response(&self) -> bool {
        self.is_response
    }

    pub async fn accept(
        self,
    ) -> Result<LinkSessionInboundResourceHandle, LinkSessionResourceError> {
        let (progress_tx, progress_rx) = watch::channel(0.0);
        let (conclusion_tx, conclusion_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::Resource(
                LinkSessionResourceCommand::AcceptInbound {
                    segment_hash: self.segment_hash,
                    progress_tx,
                    conclusion_tx,
                    result_tx,
                },
            ))
            .await
            .map_err(|_| LinkSessionResourceError::SessionClosed)?;
        result_rx
            .await
            .map_err(|_| LinkSessionResourceError::SessionClosed)??;
        Ok(LinkSessionInboundResourceHandle {
            link_id: self.link_id,
            resource_id: self.resource_id,
            data_size: self.data_size,
            total_segments: self.total_segments,
            progress_rx,
            conclusion_rx,
            command_tx: self.command_tx,
        })
    }

    pub async fn reject(self) -> Result<bool, LinkSessionResourceError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::Resource(
                LinkSessionResourceCommand::RejectInbound {
                    segment_hash: self.segment_hash,
                    result_tx,
                },
            ))
            .await
            .map_err(|_| LinkSessionResourceError::SessionClosed)?;
        result_rx
            .await
            .map_err(|_| LinkSessionResourceError::SessionClosed)?
    }
}

pub struct LinkSessionInboundResourceHandle {
    link_id: [u8; 16],
    resource_id: [u8; 32],
    data_size: usize,
    total_segments: usize,
    progress_rx: watch::Receiver<f64>,
    conclusion_rx: oneshot::Receiver<Result<LinkSessionReceivedResource, LinkSessionResourceError>>,
    command_tx: mpsc::Sender<LinkSessionCommand>,
}

impl LinkSessionInboundResourceHandle {
    pub fn link_id(&self) -> [u8; 16] {
        self.link_id
    }

    pub fn resource_id(&self) -> [u8; 32] {
        self.resource_id
    }

    pub fn data_size(&self) -> usize {
        self.data_size
    }

    pub fn total_segments(&self) -> usize {
        self.total_segments
    }

    pub fn progress(&self) -> watch::Receiver<f64> {
        self.progress_rx.clone()
    }

    pub async fn cancel(&self) -> Result<bool, LinkSessionResourceError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::Resource(
                LinkSessionResourceCommand::CancelInbound {
                    resource_id: self.resource_id,
                    result_tx,
                },
            ))
            .await
            .map_err(|_| LinkSessionResourceError::SessionClosed)?;
        result_rx
            .await
            .map_err(|_| LinkSessionResourceError::SessionClosed)?
    }

    pub async fn concluded(self) -> Result<LinkSessionReceivedResource, LinkSessionResourceError> {
        self.conclusion_rx
            .await
            .map_err(|_| LinkSessionResourceError::SessionClosed)?
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LinkSessionResourceError {
    #[error("link is not active")]
    LinkNotActive,
    #[error("link resource encryption failed")]
    LinkCrypto,
    #[error("transport channel is unavailable")]
    TransportUnavailable,
    #[error("resource queue is full")]
    QueueFull,
    #[error("resource preparation task failed")]
    PreparationTask,
    #[error("resource transfer was cancelled")]
    Cancelled,
    #[error("resource transfer was rejected by the peer")]
    Rejected,
    #[error("inbound resource offer is no longer available")]
    OfferExpired,
    #[error("inbound resource advertisement is invalid: {0}")]
    InvalidAdvertisement(String),
    #[error("resource transfer failed: {0}")]
    Failed(String),
    #[error(transparent)]
    Source(#[from] ResourceSourceError),
    #[error("Link session task is no longer running")]
    SessionClosed,
}

#[derive(Debug, thiserror::Error)]
pub enum LinkSessionChannelError {
    #[error("link is not active")]
    LinkNotActive,
    #[error("transport channel is unavailable")]
    TransportUnavailable,
    #[error("channel error: {0}")]
    Channel(#[from] ChannelError),
    #[error("Link session task is no longer running")]
    SessionClosed,
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
    #[error("request is {actual} bytes; requests above Link MDU {max} require Resource transfer")]
    RequestRequiresResource { actual: usize, max: usize },
    #[error("request Resource transfer failed: {0}")]
    RequestResourceFailed(String),
    #[error("too many Link requests are already pending")]
    TooManyPendingRequests,
    #[error("Link session task is no longer running")]
    SessionClosed,
}

enum LinkSessionCommand {
    SendPacket {
        payload: Vec<u8>,
        result_tx: oneshot::Sender<Result<LinkSessionPacketReceipt, LinkSessionError>>,
    },
    Request {
        path: String,
        data: Vec<u8>,
        timeout: Option<Duration>,
        result_tx: oneshot::Sender<Result<LinkSessionResponse, LinkSessionError>>,
    },
    RequestResourceConcluded {
        request_id: [u8; 16],
        result: Result<LinkSessionResourceReceipt, LinkSessionResourceError>,
    },
    RequestResourceReceived {
        request_id: [u8; 16],
        result: Result<LinkSessionReceivedResource, LinkSessionResourceError>,
    },
    Channel(LinkSessionChannelCommand),
    Resource(LinkSessionResourceCommand),
    Close,
}

enum LinkSessionChannelCommand {
    RegisterMessageType {
        msg_type: u16,
        result_tx: oneshot::Sender<Result<(), LinkSessionChannelError>>,
    },
    RegisterSystemType {
        msg_type: u16,
        result_tx: oneshot::Sender<Result<(), LinkSessionChannelError>>,
    },
    AddMessageHandler {
        handler: MessageCallback,
        result_tx: oneshot::Sender<Result<HandlerId, LinkSessionChannelError>>,
    },
    RemoveMessageHandler {
        id: HandlerId,
        result_tx: oneshot::Sender<Result<bool, LinkSessionChannelError>>,
    },
    ClearMessageHandlers {
        result_tx: oneshot::Sender<Result<(), LinkSessionChannelError>>,
    },
    Send {
        msg_type: u16,
        payload: Vec<u8>,
        result_tx: oneshot::Sender<Result<LinkSessionChannelReceipt, LinkSessionChannelError>>,
    },
    IsReady {
        result_tx: oneshot::Sender<Result<bool, LinkSessionChannelError>>,
    },
    IsDrained {
        result_tx: oneshot::Sender<Result<bool, LinkSessionChannelError>>,
    },
    Shutdown {
        result_tx: oneshot::Sender<Result<(), LinkSessionChannelError>>,
    },
}

enum LinkSessionResourceCommand {
    Start {
        source: PreparedResourceSource,
        progress_tx: watch::Sender<f64>,
        conclusion_tx:
            oneshot::Sender<Result<LinkSessionResourceReceipt, LinkSessionResourceError>>,
        result_tx: oneshot::Sender<Result<ResourceStartInfo, LinkSessionResourceError>>,
    },
    Cancel {
        resource_id: [u8; 32],
        result_tx: oneshot::Sender<Result<bool, LinkSessionResourceError>>,
    },
    AcceptInbound {
        segment_hash: [u8; 32],
        progress_tx: watch::Sender<f64>,
        conclusion_tx:
            oneshot::Sender<Result<LinkSessionReceivedResource, LinkSessionResourceError>>,
        result_tx: oneshot::Sender<Result<(), LinkSessionResourceError>>,
    },
    RejectInbound {
        segment_hash: [u8; 32],
        result_tx: oneshot::Sender<Result<bool, LinkSessionResourceError>>,
    },
    CancelInbound {
        resource_id: [u8; 32],
        result_tx: oneshot::Sender<Result<bool, LinkSessionResourceError>>,
    },
}

struct ResourceStartInfo {
    resource_id: [u8; 32],
    data_size: usize,
    total_segments: usize,
}

struct PendingSessionRequest {
    sent_at: Instant,
    result_tx: oneshot::Sender<Result<LinkSessionResponse, LinkSessionError>>,
}

struct SessionOutboundResource {
    source: PreparedResourceSource,
    transfer: OutboundTransfer,
    resource_id: [u8; 32],
    segment_index: usize,
    total_segments: usize,
    data_size: usize,
    completed_bytes: usize,
    segment_data_size: usize,
    reported_bytes: usize,
    reported_progress: f64,
    lifecycle_started: bool,
    progress_tx: watch::Sender<f64>,
    conclusion_tx: oneshot::Sender<Result<LinkSessionResourceReceipt, LinkSessionResourceError>>,
}

struct PendingInboundResourceOffer {
    advertisement: ResourceAdvertisement,
    offered_at: Instant,
}

struct SessionInboundResource {
    transfer: InboundTransfer,
    resource_id: [u8; 32],
    segment_index: usize,
}

struct SessionInboundLogical {
    data_size: usize,
    total_segments: usize,
    request_id: Option<Vec<u8>>,
    is_request: bool,
    is_response: bool,
    progress_tx: watch::Sender<f64>,
    conclusion_tx: oneshot::Sender<Result<LinkSessionReceivedResource, LinkSessionResourceError>>,
    coordinator: Option<MultiSegmentInbound>,
    current_segment: Option<[u8; 32]>,
    reported_bytes: usize,
    reported_progress: f64,
}

struct InboundResourceLifecycle {
    progress_tx: watch::Sender<f64>,
    conclusion_tx: oneshot::Sender<Result<LinkSessionReceivedResource, LinkSessionResourceError>>,
}

struct InboundResourceSinks<'a> {
    event_tx: &'a mpsc::Sender<LinkSessionEvent>,
    command_tx: &'a mpsc::Sender<LinkSessionCommand>,
    offer_tx: &'a mpsc::Sender<LinkSessionResourceOffer>,
}

struct SessionActorChannels {
    transport_tx: mpsc::Sender<TransportMessage>,
    command_tx: mpsc::Sender<LinkSessionCommand>,
    event_tx: mpsc::Sender<LinkSessionEvent>,
    resource_offer_tx: mpsc::Sender<LinkSessionResourceOffer>,
    phy_stats_tx: watch::Sender<LinkPhyStats>,
}

struct DestinationEventContext<'a> {
    transport_tx: &'a mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    identity: &'a Identity,
    sinks: InboundResourceSinks<'a>,
    phy_stats_tx: &'a watch::Sender<LinkPhyStats>,
}

struct SessionRequestContext<'a> {
    transport_tx: &'a mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &'a mut Link,
    resources: &'a mut SessionResources,
    event_tx: &'a mpsc::Sender<LinkSessionEvent>,
    command_tx: &'a mpsc::Sender<LinkSessionCommand>,
}

#[derive(Default)]
struct SessionResources {
    outbound: Option<SessionOutboundResource>,
    queued: VecDeque<SessionOutboundResource>,
    pending_inbound: HashMap<[u8; 32], PendingInboundResourceOffer>,
    inbound: HashMap<[u8; 32], SessionInboundResource>,
    inbound_logicals: HashMap<[u8; 32], SessionInboundLogical>,
    rejected_inbound: HashMap<[u8; 32], Instant>,
}

struct SessionActorState {
    packets: HashSet<[u8; 32]>,
    requests: HashMap<[u8; 16], PendingSessionRequest>,
    channel: LinkChannel,
    resources: SessionResources,
}

struct PackedChannelMessage {
    msg_type: u16,
    payload: Vec<u8>,
}

impl MessageBase for PackedChannelMessage {
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

/// Cloneable app-facing handle for the reliable channel owned by a Link
/// session. Sequencing, proofs, retransmissions, and callbacks remain
/// serialized inside the session actor.
#[derive(Clone)]
pub struct LinkSessionChannelHandle {
    link_id: [u8; 16],
    mdu: usize,
    command_tx: mpsc::Sender<LinkSessionCommand>,
}

impl LinkSessionChannelHandle {
    pub fn link_id(&self) -> [u8; 16] {
        self.link_id
    }

    pub fn mdu(&self) -> usize {
        self.mdu
    }

    async fn invoke<T>(
        &self,
        command: impl FnOnce(
            oneshot::Sender<Result<T, LinkSessionChannelError>>,
        ) -> LinkSessionChannelCommand,
    ) -> Result<T, LinkSessionChannelError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::Channel(command(result_tx)))
            .await
            .map_err(|_| LinkSessionChannelError::SessionClosed)?;
        result_rx
            .await
            .map_err(|_| LinkSessionChannelError::SessionClosed)?
    }

    pub async fn register_message_type(
        &self,
        msg_type: u16,
    ) -> Result<(), LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::RegisterMessageType {
            msg_type,
            result_tx,
        })
        .await
    }

    pub async fn register_system_type(&self, msg_type: u16) -> Result<(), LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::RegisterSystemType {
            msg_type,
            result_tx,
        })
        .await
    }

    pub async fn add_message_handler<F>(
        &self,
        handler: F,
    ) -> Result<HandlerId, LinkSessionChannelError>
    where
        F: Fn(u16, &[u8]) -> bool + Send + 'static,
    {
        self.invoke(|result_tx| LinkSessionChannelCommand::AddMessageHandler {
            handler: Box::new(handler),
            result_tx,
        })
        .await
    }

    pub async fn remove_message_handler(
        &self,
        id: HandlerId,
    ) -> Result<bool, LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::RemoveMessageHandler { id, result_tx })
            .await
    }

    pub(crate) fn try_remove_message_handler(&self, id: HandlerId) {
        let (result_tx, _result_rx) = oneshot::channel();
        let _ = self.command_tx.try_send(LinkSessionCommand::Channel(
            LinkSessionChannelCommand::RemoveMessageHandler { id, result_tx },
        ));
    }

    pub async fn clear_message_handlers(&self) -> Result<(), LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::ClearMessageHandlers { result_tx })
            .await
    }

    pub async fn send(
        &self,
        message: &dyn MessageBase,
    ) -> Result<LinkSessionChannelReceipt, LinkSessionChannelError> {
        self.send_raw(message.msg_type(), message.pack()).await
    }

    pub async fn send_raw(
        &self,
        msg_type: u16,
        payload: impl Into<Vec<u8>>,
    ) -> Result<LinkSessionChannelReceipt, LinkSessionChannelError> {
        let payload = payload.into();
        self.invoke(|result_tx| LinkSessionChannelCommand::Send {
            msg_type,
            payload,
            result_tx,
        })
        .await
    }

    pub async fn is_ready_to_send(&self) -> Result<bool, LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::IsReady { result_tx })
            .await
    }

    /// True when all previously-sent channel messages have been acknowledged.
    pub async fn is_drained(&self) -> Result<bool, LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::IsDrained { result_tx })
            .await
    }

    pub async fn shutdown(&self) -> Result<(), LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::Shutdown { result_tx })
            .await
    }
}

#[derive(Clone)]
pub struct LinkSessionHandle {
    link_id: [u8; 16],
    mdu: usize,
    command_tx: mpsc::Sender<LinkSessionCommand>,
    phy_stats_rx: watch::Receiver<LinkPhyStats>,
}

impl LinkSessionHandle {
    pub fn link_id(&self) -> [u8; 16] {
        self.link_id
    }

    pub fn mdu(&self) -> usize {
        self.mdu
    }

    /// Latest physical-layer measurements observed for this Link.
    ///
    /// Values remain empty unless tracking was enabled when the session was
    /// opened.
    pub fn phy_stats(&self) -> LinkPhyStats {
        *self.phy_stats_rx.borrow()
    }

    /// Subscribe to physical-layer measurement updates for this Link.
    pub fn watch_phy_stats(&self) -> watch::Receiver<LinkPhyStats> {
        self.phy_stats_rx.clone()
    }

    pub fn channel(&self) -> LinkSessionChannelHandle {
        LinkSessionChannelHandle {
            link_id: self.link_id,
            mdu: rns_protocol::channel::Channel::channel_mdu(self.mdu),
            command_tx: self.command_tx.clone(),
        }
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

    /// Send a request and wait for its response.
    ///
    /// Requests and responses larger than the current Link MDU transparently
    /// use Reticulum Resource transfer, matching Python RNS.
    pub async fn request(
        &self,
        path: &str,
        data: &[u8],
        timeout: Option<Duration>,
    ) -> Result<LinkSessionResponse, LinkSessionError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::Request {
                path: path.to_string(),
                data: data.to_vec(),
                timeout,
                result_tx,
            })
            .await
            .map_err(|_| LinkSessionError::SessionClosed)?;
        result_rx
            .await
            .map_err(|_| LinkSessionError::SessionClosed)?
    }

    /// Start a bounded-memory Link Resource transfer.
    ///
    /// Source inspection and hashing run on the blocking pool. Large sources
    /// are then read one bounded segment at a time as each preceding segment
    /// is proved by the peer.
    pub async fn send_resource<S>(
        &self,
        source: S,
        options: ResourceOptions,
    ) -> Result<LinkSessionResourceHandle, LinkSessionResourceError>
    where
        S: ResourceSource + 'static,
    {
        let source =
            tokio::task::spawn_blocking(move || PreparedResourceSource::prepare(source, options))
                .await
                .map_err(|_| LinkSessionResourceError::PreparationTask)??;
        let (progress_tx, progress_rx) = watch::channel(0.0);
        let (conclusion_tx, conclusion_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::Resource(
                LinkSessionResourceCommand::Start {
                    source,
                    progress_tx,
                    conclusion_tx,
                    result_tx,
                },
            ))
            .await
            .map_err(|_| LinkSessionResourceError::SessionClosed)?;
        let start = result_rx
            .await
            .map_err(|_| LinkSessionResourceError::SessionClosed)??;
        Ok(LinkSessionResourceHandle {
            link_id: self.link_id,
            resource_id: start.resource_id,
            data_size: start.data_size,
            total_segments: start.total_segments,
            progress_rx,
            conclusion_rx,
            command_tx: self.command_tx.clone(),
        })
    }

    pub async fn send_resource_bytes(
        &self,
        data: Vec<u8>,
        options: ResourceOptions,
    ) -> Result<LinkSessionResourceHandle, LinkSessionResourceError> {
        self.send_resource(Cursor::new(data), options).await
    }

    pub async fn close(&self) {
        let _ = self.command_tx.send(LinkSessionCommand::Close).await;
    }
}

pub struct LinkSession {
    pub handle: LinkSessionHandle,
    pub events: mpsc::Receiver<LinkSessionEvent>,
    pub resource_offers: mpsc::Receiver<LinkSessionResourceOffer>,
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
        link.track_phy_stats(config.track_phy_stats);
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
        let (proof, attached_interface, proof_metrics) = match proof {
            Ok(proof) => proof,
            Err(error) => return Err(error),
        };
        update_link_phy_stats(&mut link, proof_metrics);

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
            attached_interface,
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
                attached_interface,
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

        let channel_keys = link.session_keys().ok_or(LinkSessionError::LinkCrypto)?;
        let channel =
            LinkChannel::new_encrypted_with_mdu(link_id, link.rtt_secs(), link.mdu, channel_keys);
        let (command_tx, command_rx) = mpsc::channel(COMMAND_BUFFER);
        let (event_tx, events) = mpsc::channel(EVENT_BUFFER);
        let (resource_offer_tx, resource_offers) = mpsc::channel(MAX_PENDING_RESOURCE_OFFERS);
        let (phy_stats_tx, phy_stats_rx) = watch::channel(link.phy_stats_snapshot());
        let handle = LinkSessionHandle {
            link_id,
            mdu: link.mdu,
            command_tx: command_tx.clone(),
            phy_stats_rx,
        };
        tokio::spawn(run_session_actor(
            identity,
            (link, channel),
            attached_interface,
            delivery_rx,
            command_rx,
            SessionActorChannels {
                transport_tx,
                command_tx,
                event_tx,
                resource_offer_tx,
                phy_stats_tx,
            },
        ));
        registration.disarm();

        Ok(Self {
            handle,
            events,
            resource_offers,
        })
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
    identity: Identity,
    link_and_channel: (Link, LinkChannel),
    attached_interface: InterfaceId,
    mut delivery_rx: mpsc::Receiver<DestinationEvent>,
    mut command_rx: mpsc::Receiver<LinkSessionCommand>,
    channels: SessionActorChannels,
) {
    let SessionActorChannels {
        transport_tx,
        command_tx,
        event_tx,
        resource_offer_tx,
        phy_stats_tx,
    } = channels;
    let (mut link, channel) = link_and_channel;
    let link_id = link.link_id;
    let mut state = SessionActorState {
        packets: HashSet::new(),
        requests: HashMap::new(),
        channel,
        resources: SessionResources::default(),
    };
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let close_reason = loop {
        tokio::select! {
            command = command_rx.recv() => {
                match command {
                    Some(LinkSessionCommand::SendPacket { payload, result_tx }) => {
                        let result = send_application_packet(
                            &transport_tx,
                            attached_interface,
                            &mut link,
                            &mut state.packets,
                            payload,
                        ).await;
                        let transport_failed = matches!(result, Err(LinkSessionError::TransportUnavailable));
                        let _ = result_tx.send(result);
                        if transport_failed {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    Some(LinkSessionCommand::Request {
                        path,
                        data,
                        timeout,
                        result_tx,
                    }) => {
                        if state.requests.len() >= MAX_PENDING_REQUESTS {
                            let _ = result_tx.send(Err(LinkSessionError::TooManyPendingRequests));
                            continue;
                        }
                        match send_link_request(
                            SessionRequestContext {
                                transport_tx: &transport_tx,
                                attached_interface,
                                link: &mut link,
                                resources: &mut state.resources,
                                event_tx: &event_tx,
                                command_tx: &command_tx,
                            },
                            &path,
                            &data,
                            timeout,
                        ).await {
                            Ok(request_id) => {
                                state.requests.insert(
                                    request_id,
                                    PendingSessionRequest {
                                        sent_at: Instant::now(),
                                        result_tx,
                                    },
                                );
                            }
                            Err(error) => {
                                let transport_failed =
                                    matches!(error, LinkSessionError::TransportUnavailable);
                                let _ = result_tx.send(Err(error));
                                if transport_failed {
                                    break LinkSessionCloseReason::TransportUnavailable;
                                }
                            }
                        }
                    }
                    Some(LinkSessionCommand::RequestResourceConcluded {
                        request_id,
                        result,
                    }) => {
                        if let Err(error) = result {
                            fail_session_request(
                                &mut link,
                                &mut state.requests,
                                &event_tx,
                                request_id,
                                LinkSessionError::RequestResourceFailed(error.to_string()),
                            );
                        } else {
                            let _ = link.mark_request_resource_sent(&request_id);
                        }
                    }
                    Some(LinkSessionCommand::RequestResourceReceived {
                        request_id,
                        result,
                    }) => {
                        conclude_request_resource_response(
                            &mut link,
                            &mut state.requests,
                            &event_tx,
                            request_id,
                            result,
                        );
                    }
                    Some(LinkSessionCommand::Channel(command)) => {
                        let transport_failed = handle_channel_command(
                            &transport_tx,
                            attached_interface,
                            &mut link,
                            &mut state.channel,
                            command,
                        ).await;
                        if transport_failed {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    Some(LinkSessionCommand::Resource(command)) => {
                        let transport_failed = handle_resource_command(
                            &transport_tx,
                            attached_interface,
                            &mut link,
                            &mut state.resources,
                            &event_tx,
                            command,
                        ).await;
                        if transport_failed {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    Some(LinkSessionCommand::Close) | None => {
                        send_local_teardown(&transport_tx, attached_interface, &mut link).await;
                        break LinkSessionCloseReason::Local;
                    }
                }
            }
            event = delivery_rx.recv() => {
                let Some(event) = event else {
                    break LinkSessionCloseReason::TransportUnavailable;
                };
                match process_destination_event(
                    DestinationEventContext {
                        transport_tx: &transport_tx,
                        attached_interface,
                        identity: &identity,
                        sinks: InboundResourceSinks {
                            event_tx: &event_tx,
                            command_tx: &command_tx,
                            offer_tx: &resource_offer_tx,
                        },
                        phy_stats_tx: &phy_stats_tx,
                    },
                    &mut link,
                    &mut state,
                    event,
                ).await {
                    Ok(Some(reason)) => break reason,
                    Ok(None) => {}
                    Err(_) => break LinkSessionCloseReason::TransportUnavailable,
                }
            }
            _ = ticker.tick() => {
                state.channel.update_rtt(link.rtt_secs());
                if let Err(error) = resend_timed_out_channel_messages(
                    &transport_tx,
                    attached_interface,
                    &mut link,
                    &mut state.channel,
                ).await {
                    match error {
                        LinkSessionChannelError::Channel(ChannelError::MaxRetriesExceeded) => {
                            send_local_teardown(&transport_tx, attached_interface, &mut link).await;
                            break LinkSessionCloseReason::Timeout;
                        }
                        _ => break LinkSessionCloseReason::TransportUnavailable,
                    }
                }
                if poll_outbound_resource(
                    &transport_tx,
                    attached_interface,
                    &mut link,
                    &mut state.resources,
                    &event_tx,
                ).await {
                    break LinkSessionCloseReason::TransportUnavailable;
                }
                if poll_inbound_resources(
                    &transport_tx,
                    attached_interface,
                    &mut link,
                    &mut state.resources,
                    &event_tx,
                ).await {
                    break LinkSessionCloseReason::TransportUnavailable;
                }
                if state.resources.outbound.is_some() || !state.resources.inbound.is_empty() {
                    // Resource watchdogs own liveness while a transfer is in
                    // flight, matching the responder Link manager.
                    link.record_inbound();
                }
                let action = link.tick();
                reap_concluded_requests(&link, &mut state.requests, &event_tx);
                match action {
                    LinkAction::SendKeepalive => {
                        if send_keepalive(&transport_tx, attached_interface, &mut link)
                            .await
                            .is_err()
                        {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    LinkAction::TransitionedToStale => {
                        let _ = event_tx.send(LinkSessionEvent::Stale).await;
                        if send_keepalive(&transport_tx, attached_interface, &mut link)
                            .await
                            .is_err()
                        {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    LinkAction::SendTeardownAndClose(data) => {
                        let _ = send_raw(
                            &transport_tx,
                            attached_interface,
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

    state.channel.shutdown();
    fail_pending_requests(&mut state.requests, &event_tx);
    fail_outbound_resources(&mut link, &mut state.resources, &event_tx);
    fail_inbound_resources(&mut link, &mut state.resources, &event_tx);
    deregister_destination(&transport_tx, link_id);
    let _ = event_tx
        .send(LinkSessionEvent::Closed {
            reason: close_reason,
        })
        .await;
}

async fn handle_channel_command(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    channel: &mut LinkChannel,
    command: LinkSessionChannelCommand,
) -> bool {
    match command {
        LinkSessionChannelCommand::RegisterMessageType {
            msg_type,
            result_tx,
        } => {
            let _ = result_tx.send(
                channel
                    .register_message_type(msg_type)
                    .map_err(LinkSessionChannelError::from),
            );
        }
        LinkSessionChannelCommand::RegisterSystemType {
            msg_type,
            result_tx,
        } => {
            channel.register_system_type(msg_type);
            let _ = result_tx.send(Ok(()));
        }
        LinkSessionChannelCommand::AddMessageHandler { handler, result_tx } => {
            let _ = result_tx.send(Ok(channel.add_message_handler(handler)));
        }
        LinkSessionChannelCommand::RemoveMessageHandler { id, result_tx } => {
            let _ = result_tx.send(Ok(channel.remove_message_handler(id)));
        }
        LinkSessionChannelCommand::ClearMessageHandlers { result_tx } => {
            channel.clear_message_handlers();
            let _ = result_tx.send(Ok(()));
        }
        LinkSessionChannelCommand::Send {
            msg_type,
            payload,
            result_tx,
        } => {
            let result = send_channel_message(
                transport_tx,
                attached_interface,
                link,
                channel,
                PackedChannelMessage { msg_type, payload },
            )
            .await;
            let transport_failed =
                matches!(result, Err(LinkSessionChannelError::TransportUnavailable));
            let _ = result_tx.send(result);
            return transport_failed;
        }
        LinkSessionChannelCommand::IsReady { result_tx } => {
            let ready = matches!(link.state, LinkState::Active | LinkState::Stale)
                && channel.is_ready_to_send();
            let _ = result_tx.send(Ok(ready));
        }
        LinkSessionChannelCommand::IsDrained { result_tx } => {
            let _ = result_tx.send(Ok(channel.is_drained()));
        }
        LinkSessionChannelCommand::Shutdown { result_tx } => {
            channel.shutdown();
            let _ = result_tx.send(Ok(()));
        }
    }
    false
}

async fn handle_resource_command(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    command: LinkSessionResourceCommand,
) -> bool {
    match command {
        LinkSessionResourceCommand::Start {
            mut source,
            progress_tx,
            conclusion_tx,
            result_tx,
        } => {
            if !matches!(link.state, LinkState::Active | LinkState::Stale) {
                let _ = result_tx.send(Err(LinkSessionResourceError::LinkNotActive));
                return false;
            }
            if resources.outbound.is_some() && resources.queued.len() >= MAX_QUEUED_RESOURCES {
                let _ = result_tx.send(Err(LinkSessionResourceError::QueueFull));
                return false;
            }
            let Some(keys) = link.session_keys() else {
                let _ = result_tx.send(Err(LinkSessionResourceError::LinkCrypto));
                return false;
            };
            let rtt = Duration::from_secs_f64(link.rtt_secs().max(0.001));
            let segment = match source.next_segment(&keys, rtt) {
                Ok(Some(segment)) => segment,
                Ok(None) => {
                    let _ = result_tx.send(Err(LinkSessionResourceError::Failed(
                        "resource source produced no segment".into(),
                    )));
                    return false;
                }
                Err(error) => {
                    let _ = result_tx.send(Err(error.into()));
                    return false;
                }
            };
            let start = ResourceStartInfo {
                resource_id: segment.logical_hash,
                data_size: segment.data_size,
                total_segments: segment.total_segments,
            };
            let outbound =
                SessionOutboundResource::new(source, segment, progress_tx, conclusion_tx);

            if resources.outbound.is_some() {
                resources.queued.push_back(outbound);
                let _ = result_tx.send(Ok(start));
                return false;
            }

            let mut outbound = outbound;
            match begin_outbound_resource(
                transport_tx,
                attached_interface,
                link,
                &mut outbound,
                event_tx,
            )
            .await
            {
                Ok(()) => {
                    resources.outbound = Some(outbound);
                    let _ = result_tx.send(Ok(start));
                    false
                }
                Err(error) => {
                    let transport_failed =
                        matches!(error, LinkSessionResourceError::TransportUnavailable);
                    let _ = result_tx.send(Err(error));
                    transport_failed
                }
            }
        }
        LinkSessionResourceCommand::Cancel {
            resource_id,
            result_tx,
        } => {
            if resources
                .outbound
                .as_ref()
                .is_some_and(|outbound| outbound.resource_id == resource_id)
            {
                let mut outbound = resources
                    .outbound
                    .take()
                    .expect("resource presence checked");
                let segment_hash = outbound.transfer.resource.resource_hash;
                outbound.transfer.handle_cancel();
                let send_result = send_resource_action(
                    transport_tx,
                    attached_interface,
                    link,
                    TransferAction::SendCancel(CancelType::Icl, segment_hash),
                )
                .await;
                link.untrack_resource(&segment_hash);
                conclude_outbound_resource(
                    outbound,
                    event_tx,
                    Err(LinkSessionResourceError::Cancelled),
                );
                let _ = result_tx.send(Ok(true));
                let transport_failed = matches!(
                    send_result,
                    Err(LinkSessionResourceError::TransportUnavailable)
                );
                transport_failed
                    || activate_next_queued(
                        transport_tx,
                        attached_interface,
                        link,
                        resources,
                        event_tx,
                    )
                    .await
            } else if let Some(position) = resources
                .queued
                .iter()
                .position(|outbound| outbound.resource_id == resource_id)
            {
                let outbound = resources
                    .queued
                    .remove(position)
                    .expect("queued resource position checked");
                conclude_outbound_resource(
                    outbound,
                    event_tx,
                    Err(LinkSessionResourceError::Cancelled),
                );
                let _ = result_tx.send(Ok(true));
                false
            } else {
                let _ = result_tx.send(Ok(false));
                false
            }
        }
        LinkSessionResourceCommand::AcceptInbound {
            segment_hash,
            progress_tx,
            conclusion_tx,
            result_tx,
        } => {
            let result = accept_inbound_offer(
                transport_tx,
                attached_interface,
                link,
                resources,
                event_tx,
                segment_hash,
                InboundResourceLifecycle {
                    progress_tx,
                    conclusion_tx,
                },
            )
            .await;
            let transport_failed =
                matches!(result, Err(LinkSessionResourceError::TransportUnavailable));
            let _ = result_tx.send(result);
            transport_failed
        }
        LinkSessionResourceCommand::RejectInbound {
            segment_hash,
            result_tx,
        } => {
            let result = reject_inbound_offer(
                transport_tx,
                attached_interface,
                link,
                resources,
                segment_hash,
            )
            .await;
            let transport_failed =
                matches!(result, Err(LinkSessionResourceError::TransportUnavailable));
            let _ = result_tx.send(result);
            transport_failed
        }
        LinkSessionResourceCommand::CancelInbound {
            resource_id,
            result_tx,
        } => {
            let result = cancel_inbound_resource(
                transport_tx,
                attached_interface,
                link,
                resources,
                event_tx,
                resource_id,
            )
            .await;
            let transport_failed =
                matches!(result, Err(LinkSessionResourceError::TransportUnavailable));
            let _ = result_tx.send(result);
            transport_failed
        }
    }
}

impl SessionOutboundResource {
    fn new(
        source: PreparedResourceSource,
        segment: PreparedResourceSegment,
        progress_tx: watch::Sender<f64>,
        conclusion_tx: oneshot::Sender<
            Result<LinkSessionResourceReceipt, LinkSessionResourceError>,
        >,
    ) -> Self {
        Self {
            source,
            transfer: segment.transfer,
            resource_id: segment.logical_hash,
            segment_index: segment.segment_index,
            total_segments: segment.total_segments,
            data_size: segment.data_size,
            completed_bytes: 0,
            segment_data_size: segment.segment_data_size,
            reported_bytes: 0,
            reported_progress: 0.0,
            lifecycle_started: false,
            progress_tx,
            conclusion_tx,
        }
    }

    fn replace_segment(&mut self, segment: PreparedResourceSegment) {
        debug_assert_eq!(self.resource_id, segment.logical_hash);
        debug_assert_eq!(self.data_size, segment.data_size);
        debug_assert_eq!(self.total_segments, segment.total_segments);
        self.transfer = segment.transfer;
        self.segment_index = segment.segment_index;
        self.segment_data_size = segment.segment_data_size;
    }

    fn transferred_bytes(&self) -> usize {
        let segment_bytes =
            (self.transfer.progress() * self.segment_data_size as f64).floor() as usize;
        self.completed_bytes
            .saturating_add(segment_bytes)
            .min(self.data_size)
    }

    fn mark_current_segment_complete(&mut self) -> (usize, f64) {
        self.completed_bytes = self
            .completed_bytes
            .saturating_add(self.segment_data_size)
            .min(self.data_size);
        let progress = if self.data_size == 0 {
            1.0
        } else {
            self.completed_bytes as f64 / self.data_size as f64
        };
        (self.completed_bytes, progress)
    }
}

async fn begin_outbound_resource(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    outbound: &mut SessionOutboundResource,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
) -> Result<(), LinkSessionResourceError> {
    if !matches!(link.state, LinkState::Active | LinkState::Stale) {
        return Err(LinkSessionResourceError::LinkNotActive);
    }
    let action = outbound.transfer.tick();
    if !matches!(action, TransferAction::SendAdvertisement(_)) {
        return Err(LinkSessionResourceError::Failed(
            "resource did not produce an advertisement".into(),
        ));
    }
    send_resource_action(transport_tx, attached_interface, link, action).await?;
    link.track_outgoing_resource(outbound.transfer.resource.resource_hash);
    if !outbound.lifecycle_started {
        outbound.lifecycle_started = true;
        let _ = event_tx.try_send(LinkSessionEvent::ResourceStarted {
            resource_id: outbound.resource_id,
            direction: LinkSessionResourceDirection::Outbound,
            data_size: outbound.data_size,
            total_segments: outbound.total_segments,
        });
    }
    report_outbound_progress(outbound, event_tx);
    Ok(())
}

async fn activate_next_queued(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
) -> bool {
    while resources.outbound.is_none() {
        let Some(mut next) = resources.queued.pop_front() else {
            return false;
        };
        match begin_outbound_resource(transport_tx, attached_interface, link, &mut next, event_tx)
            .await
        {
            Ok(()) => {
                resources.outbound = Some(next);
                return false;
            }
            Err(error) => {
                let transport_failed =
                    matches!(error, LinkSessionResourceError::TransportUnavailable);
                conclude_outbound_resource(
                    next,
                    event_tx,
                    Err(LinkSessionResourceError::Failed(error.to_string())),
                );
                if transport_failed {
                    return true;
                }
            }
        }
    }
    false
}

fn report_outbound_progress(
    outbound: &mut SessionOutboundResource,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
) {
    let transferred = outbound.transferred_bytes();
    let progress = if outbound.data_size == 0 {
        outbound.transfer.progress()
    } else {
        transferred as f64 / outbound.data_size as f64
    }
    .clamp(0.0, 1.0);
    publish_outbound_progress(outbound, event_tx, transferred, progress);
}

fn publish_outbound_progress(
    outbound: &mut SessionOutboundResource,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    transferred: usize,
    progress: f64,
) {
    if transferred == outbound.reported_bytes && progress == outbound.reported_progress {
        return;
    }
    outbound.reported_bytes = transferred;
    outbound.reported_progress = progress;
    outbound.progress_tx.send_replace(progress);
    let _ = event_tx.try_send(LinkSessionEvent::ResourceProgress {
        resource_id: outbound.resource_id,
        direction: LinkSessionResourceDirection::Outbound,
        transferred,
        total: outbound.data_size,
    });
}

fn conclude_outbound_resource(
    outbound: SessionOutboundResource,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    result: Result<LinkSessionResourceReceipt, LinkSessionResourceError>,
) {
    let succeeded = result.is_ok();
    let resource_id = outbound.resource_id;
    let _ = outbound.conclusion_tx.send(result);
    let _ = event_tx.try_send(LinkSessionEvent::ResourceConcluded {
        resource_id,
        direction: LinkSessionResourceDirection::Outbound,
        succeeded,
    });
}

fn fail_outbound_resources(
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
) {
    if let Some(outbound) = resources.outbound.take() {
        link.untrack_resource(&outbound.transfer.resource.resource_hash);
        conclude_outbound_resource(
            outbound,
            event_tx,
            Err(LinkSessionResourceError::SessionClosed),
        );
    }
    for outbound in resources.queued.drain(..) {
        conclude_outbound_resource(
            outbound,
            event_tx,
            Err(LinkSessionResourceError::SessionClosed),
        );
    }
}

async fn poll_outbound_resource(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
) -> bool {
    let action = resources
        .outbound
        .as_mut()
        .map(|outbound| outbound.transfer.check_timeout())
        .unwrap_or(TransferAction::None);
    match action {
        TransferAction::None => {
            if let Some(outbound) = resources.outbound.as_mut() {
                report_outbound_progress(outbound, event_tx);
            }
            false
        }
        TransferAction::Failed(reason) => {
            let outbound = resources
                .outbound
                .take()
                .expect("watchdog action requires an outbound resource");
            link.untrack_resource(&outbound.transfer.resource.resource_hash);
            conclude_outbound_resource(
                outbound,
                event_tx,
                Err(LinkSessionResourceError::Failed(reason)),
            );
            activate_next_queued(transport_tx, attached_interface, link, resources, event_tx).await
        }
        retry => match send_resource_action(transport_tx, attached_interface, link, retry).await {
            Ok(()) => false,
            Err(error) => {
                let transport_failed =
                    matches!(error, LinkSessionResourceError::TransportUnavailable);
                if let Some(outbound) = resources.outbound.take() {
                    link.untrack_resource(&outbound.transfer.resource.resource_hash);
                    conclude_outbound_resource(
                        outbound,
                        event_tx,
                        Err(LinkSessionResourceError::Failed(error.to_string())),
                    );
                }
                transport_failed
            }
        },
    }
}

async fn send_resource_action(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    action: TransferAction,
) -> Result<(), LinkSessionResourceError> {
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
                CancelType::Icl => rns_wire::context::PacketContext::ResourceIcl,
                CancelType::Rcl => rns_wire::context::PacketContext::ResourceRcl,
            };
            (
                context,
                resource_hash.to_vec(),
                true,
                rns_wire::flags::PacketType::Data,
            )
        }
        TransferAction::None | TransferAction::Complete | TransferAction::Failed(_) => {
            return Ok(());
        }
    };
    let body = if encrypted {
        link.encrypt(&payload)
            .map_err(|_| LinkSessionResourceError::LinkCrypto)?
    } else {
        payload
    };
    let raw = build_packet(link.link_id, packet_type, context, &body);
    send_raw(transport_tx, attached_interface, link.link_id, raw)
        .await
        .map_err(|_| LinkSessionResourceError::TransportUnavailable)?;
    link.record_tx(body.len());
    Ok(())
}

fn resource_request_hash(request: &[u8]) -> Option<[u8; 32]> {
    let hash_start = match request.first().copied()? {
        HASHMAP_IS_EXHAUSTED => 1 + MAPHASH_LEN,
        _ => 1,
    };
    let hash_end = hash_start.checked_add(32)?;
    let mut resource_hash = [0u8; 32];
    resource_hash.copy_from_slice(request.get(hash_start..hash_end)?);
    Some(resource_hash)
}

async fn handle_outbound_resource_request(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    packet_hash: [u8; 32],
    encrypted_request: &[u8],
) -> bool {
    let Ok(request) = link.decrypt(encrypted_request) else {
        return false;
    };
    let Some(resource_hash) = resource_request_hash(&request) else {
        return false;
    };
    let Some(outbound) = resources.outbound.as_mut() else {
        return false;
    };
    if outbound.transfer.resource.resource_hash != resource_hash {
        return false;
    }
    let actions = outbound
        .transfer
        .handle_request_packet(packet_hash, &request);

    for action in actions {
        if let Err(error) =
            send_resource_action(transport_tx, attached_interface, link, action).await
        {
            let transport_failed = matches!(error, LinkSessionResourceError::TransportUnavailable);
            let outbound = resources
                .outbound
                .take()
                .expect("request matched active resource");
            link.untrack_resource(&outbound.transfer.resource.resource_hash);
            conclude_outbound_resource(
                outbound,
                event_tx,
                Err(LinkSessionResourceError::Failed(error.to_string())),
            );
            if transport_failed {
                return true;
            }
            return activate_next_queued(
                transport_tx,
                attached_interface,
                link,
                resources,
                event_tx,
            )
            .await;
        }
    }
    if let Some(outbound) = resources.outbound.as_mut() {
        report_outbound_progress(outbound, event_tx);
    }
    false
}

async fn handle_outbound_resource_proof(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    proof: &[u8],
) -> bool {
    if proof.len() < 64 {
        return false;
    }
    let Some(outbound) = resources.outbound.as_mut() else {
        return false;
    };
    if proof[..32] != outbound.transfer.resource.resource_hash
        || !outbound.transfer.handle_proof(proof)
    {
        return false;
    }

    let mut outbound = resources
        .outbound
        .take()
        .expect("proof matched active resource");
    let segment_hash = outbound.transfer.resource.resource_hash;
    link.untrack_resource(&segment_hash);
    let (completed_bytes, completed_progress) = outbound.mark_current_segment_complete();
    publish_outbound_progress(&mut outbound, event_tx, completed_bytes, completed_progress);

    let Some(keys) = link.session_keys() else {
        conclude_outbound_resource(
            outbound,
            event_tx,
            Err(LinkSessionResourceError::LinkCrypto),
        );
        return activate_next_queued(transport_tx, attached_interface, link, resources, event_tx)
            .await;
    };
    let rtt = Duration::from_secs_f64(link.rtt_secs().max(0.001));
    match outbound.source.next_segment(&keys, rtt) {
        Ok(Some(segment)) => {
            outbound.replace_segment(segment);
            match begin_outbound_resource(
                transport_tx,
                attached_interface,
                link,
                &mut outbound,
                event_tx,
            )
            .await
            {
                Ok(()) => {
                    resources.outbound = Some(outbound);
                    false
                }
                Err(error) => {
                    let transport_failed =
                        matches!(error, LinkSessionResourceError::TransportUnavailable);
                    conclude_outbound_resource(
                        outbound,
                        event_tx,
                        Err(LinkSessionResourceError::Failed(error.to_string())),
                    );
                    transport_failed
                        || activate_next_queued(
                            transport_tx,
                            attached_interface,
                            link,
                            resources,
                            event_tx,
                        )
                        .await
                }
            }
        }
        Ok(None) => {
            outbound.completed_bytes = outbound.data_size;
            let data_size = outbound.data_size;
            publish_outbound_progress(&mut outbound, event_tx, data_size, 1.0);
            let receipt = LinkSessionResourceReceipt {
                link_id: link.link_id,
                resource_id: outbound.resource_id,
                data_size: outbound.data_size,
                total_segments: outbound.total_segments,
            };
            conclude_outbound_resource(outbound, event_tx, Ok(receipt));
            activate_next_queued(transport_tx, attached_interface, link, resources, event_tx).await
        }
        Err(error) => {
            conclude_outbound_resource(outbound, event_tx, Err(error.into()));
            activate_next_queued(transport_tx, attached_interface, link, resources, event_tx).await
        }
    }
}

async fn handle_outbound_resource_rejection(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    encrypted_rejection: &[u8],
) -> bool {
    let Ok(rejection) = link.decrypt(encrypted_rejection) else {
        return false;
    };
    let Some(resource_hash) = rejection.get(..32) else {
        return false;
    };
    let Some(outbound) = resources.outbound.as_mut() else {
        return false;
    };
    if resource_hash != outbound.transfer.resource.resource_hash {
        return false;
    }
    outbound.transfer.resource.handle_cancel();
    let outbound = resources
        .outbound
        .take()
        .expect("rejection matched active resource");
    link.untrack_resource(&outbound.transfer.resource.resource_hash);
    conclude_outbound_resource(outbound, event_tx, Err(LinkSessionResourceError::Rejected));
    activate_next_queued(transport_tx, attached_interface, link, resources, event_tx).await
}

fn resource_logical_id(advertisement: &ResourceAdvertisement) -> [u8; 32] {
    if advertisement.total_segments > 1 {
        advertisement.original_hash
    } else {
        advertisement.resource_hash
    }
}

fn validate_inbound_advertisement(
    advertisement: &ResourceAdvertisement,
) -> Result<(), LinkSessionResourceError> {
    if advertisement.total_segments == 0
        || advertisement.total_segments > MAX_SEGMENTS
        || advertisement.segment_index == 0
        || advertisement.segment_index > advertisement.total_segments
    {
        return Err(LinkSessionResourceError::InvalidAdvertisement(
            "segment metadata is out of range".into(),
        ));
    }
    if advertisement.total_segments == 1 && advertisement.segment_index != 1 {
        return Err(LinkSessionResourceError::InvalidAdvertisement(
            "single-segment resource has a non-first segment index".into(),
        ));
    }
    Ok(())
}

fn inbound_transfer_from_advertisement(
    advertisement: &ResourceAdvertisement,
    rtt: Duration,
) -> Result<InboundTransfer, LinkSessionResourceError> {
    validate_inbound_advertisement(advertisement)?;
    let mut random_hash = [0u8; RANDOM_HASH_SIZE];
    let random = advertisement
        .random_hash
        .get(..RANDOM_HASH_SIZE)
        .ok_or_else(|| {
            LinkSessionResourceError::InvalidAdvertisement(
                "resource random hash is truncated".into(),
            )
        })?;
    random_hash.copy_from_slice(random);
    let mut flags = advertisement.flags;
    if advertisement.total_segments > 1 && advertisement.segment_index > 1 {
        flags.has_metadata = false;
    }
    InboundTransfer::from_advertisement(
        advertisement.num_parts,
        advertisement.transfer_size,
        advertisement.data_size,
        random_hash,
        advertisement.resource_hash,
        flags,
        advertisement.get_map_hashes(),
        rtt,
    )
    .map_err(|error| LinkSessionResourceError::InvalidAdvertisement(error.to_string()))
}

async fn accept_inbound_offer(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    segment_hash: [u8; 32],
    lifecycle: InboundResourceLifecycle,
) -> Result<(), LinkSessionResourceError> {
    let pending = resources
        .pending_inbound
        .remove(&segment_hash)
        .ok_or(LinkSessionResourceError::OfferExpired)?;
    let advertisement = pending.advertisement;
    let resource_id = resource_logical_id(&advertisement);
    if advertisement.segment_index != 1 || resources.inbound_logicals.contains_key(&resource_id) {
        return Err(LinkSessionResourceError::OfferExpired);
    }

    let rtt = Duration::from_secs_f64(link.rtt_secs().max(0.001));
    let mut transfer = inbound_transfer_from_advertisement(&advertisement, rtt)?;
    let request = match transfer.request_next() {
        TransferAction::SendRequest(request) => request,
        _ => {
            return Err(LinkSessionResourceError::InvalidAdvertisement(
                "resource did not produce an initial request".into(),
            ));
        }
    };
    send_resource_action(
        transport_tx,
        attached_interface,
        link,
        TransferAction::SendRequest(request),
    )
    .await?;

    let coordinator = (advertisement.total_segments > 1).then(|| {
        MultiSegmentInbound::new(advertisement.total_segments, advertisement.original_hash)
    });
    resources.inbound_logicals.insert(
        resource_id,
        SessionInboundLogical {
            data_size: advertisement.data_size,
            total_segments: advertisement.total_segments,
            request_id: advertisement.request_id.clone(),
            is_request: advertisement.flags.is_request,
            is_response: advertisement.flags.is_response,
            progress_tx: lifecycle.progress_tx,
            conclusion_tx: lifecycle.conclusion_tx,
            coordinator,
            current_segment: Some(segment_hash),
            reported_bytes: 0,
            reported_progress: 0.0,
        },
    );
    resources.inbound.insert(
        segment_hash,
        SessionInboundResource {
            transfer,
            resource_id,
            segment_index: advertisement.segment_index,
        },
    );
    link.track_incoming_resource(segment_hash);
    let _ = event_tx.try_send(LinkSessionEvent::ResourceStarted {
        resource_id,
        direction: LinkSessionResourceDirection::Inbound,
        data_size: advertisement.data_size,
        total_segments: advertisement.total_segments,
    });
    Ok(())
}

async fn reject_inbound_offer(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    segment_hash: [u8; 32],
) -> Result<bool, LinkSessionResourceError> {
    let Some(pending) = resources.pending_inbound.remove(&segment_hash) else {
        return Ok(false);
    };
    let resource_id = resource_logical_id(&pending.advertisement);
    send_resource_action(
        transport_tx,
        attached_interface,
        link,
        TransferAction::SendCancel(CancelType::Rcl, segment_hash),
    )
    .await?;
    resources
        .rejected_inbound
        .insert(resource_id, Instant::now());
    Ok(true)
}

fn remove_inbound_segments(
    link: &mut Link,
    resources: &mut SessionResources,
    resource_id: [u8; 32],
) {
    let segment_hashes: Vec<[u8; 32]> = resources
        .inbound
        .iter()
        .filter_map(|(segment_hash, inbound)| {
            (inbound.resource_id == resource_id).then_some(*segment_hash)
        })
        .collect();
    for segment_hash in segment_hashes {
        resources.inbound.remove(&segment_hash);
        link.untrack_resource(&segment_hash);
    }
}

fn conclude_inbound_resource(
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    resource_id: [u8; 32],
    result: Result<LinkSessionReceivedResource, LinkSessionResourceError>,
) {
    let Some(logical) = resources.inbound_logicals.remove(&resource_id) else {
        return;
    };
    let succeeded = result.is_ok();
    let _ = logical.conclusion_tx.send(result);
    let _ = event_tx.try_send(LinkSessionEvent::ResourceConcluded {
        resource_id,
        direction: LinkSessionResourceDirection::Inbound,
        succeeded,
    });
}

async fn cancel_inbound_resource(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    resource_id: [u8; 32],
) -> Result<bool, LinkSessionResourceError> {
    let Some(current_segment) = resources
        .inbound_logicals
        .get(&resource_id)
        .map(|logical| logical.current_segment)
    else {
        return Ok(false);
    };
    if let Some(segment_hash) = current_segment {
        send_resource_action(
            transport_tx,
            attached_interface,
            link,
            TransferAction::SendCancel(CancelType::Rcl, segment_hash),
        )
        .await?;
    }
    remove_inbound_segments(link, resources, resource_id);
    resources
        .rejected_inbound
        .insert(resource_id, Instant::now());
    conclude_inbound_resource(
        resources,
        event_tx,
        resource_id,
        Err(LinkSessionResourceError::Cancelled),
    );
    Ok(true)
}

async fn accept_followup_inbound_segment(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    advertisement: ResourceAdvertisement,
) -> Result<(), LinkSessionResourceError> {
    let resource_id = resource_logical_id(&advertisement);
    let Some(logical) = resources.inbound_logicals.get(&resource_id) else {
        return Err(LinkSessionResourceError::OfferExpired);
    };
    if logical.total_segments != advertisement.total_segments || logical.current_segment.is_some() {
        return Err(LinkSessionResourceError::InvalidAdvertisement(
            "split-resource sequence does not match the active transfer".into(),
        ));
    }
    let expected_segment = logical
        .coordinator
        .as_ref()
        .map(|coordinator| coordinator.assembled_count() + 1)
        .unwrap_or(1);
    if advertisement.segment_index != expected_segment {
        return Err(LinkSessionResourceError::InvalidAdvertisement(format!(
            "expected segment {expected_segment}, received {}",
            advertisement.segment_index
        )));
    }

    let rtt = Duration::from_secs_f64(link.rtt_secs().max(0.001));
    let mut transfer = inbound_transfer_from_advertisement(&advertisement, rtt)?;
    let request = match transfer.request_next() {
        TransferAction::SendRequest(request) => request,
        _ => {
            return Err(LinkSessionResourceError::InvalidAdvertisement(
                "resource did not produce an initial request".into(),
            ));
        }
    };
    send_resource_action(
        transport_tx,
        attached_interface,
        link,
        TransferAction::SendRequest(request),
    )
    .await?;

    let segment_hash = advertisement.resource_hash;
    resources.inbound.insert(
        segment_hash,
        SessionInboundResource {
            transfer,
            resource_id,
            segment_index: advertisement.segment_index,
        },
    );
    if let Some(logical) = resources.inbound_logicals.get_mut(&resource_id) {
        logical.current_segment = Some(segment_hash);
    }
    link.track_incoming_resource(segment_hash);
    Ok(())
}

async fn process_inbound_resource_advertisement(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    pending_requests: &HashMap<[u8; 16], PendingSessionRequest>,
    sinks: InboundResourceSinks<'_>,
    encrypted_advertisement: &[u8],
) -> bool {
    let Ok(plaintext) = link.decrypt(encrypted_advertisement) else {
        return false;
    };
    let Ok(advertisement) = ResourceAdvertisement::unpack(&plaintext) else {
        return false;
    };
    let segment_hash = advertisement.resource_hash;
    let resource_id = resource_logical_id(&advertisement);
    if validate_inbound_advertisement(&advertisement).is_err() {
        return matches!(
            send_resource_action(
                transport_tx,
                attached_interface,
                link,
                TransferAction::SendCancel(CancelType::Rcl, segment_hash),
            )
            .await,
            Err(LinkSessionResourceError::TransportUnavailable)
        );
    }
    let rtt = Duration::from_secs_f64(link.rtt_secs().max(0.001));
    if inbound_transfer_from_advertisement(&advertisement, rtt).is_err() {
        return matches!(
            send_resource_action(
                transport_tx,
                attached_interface,
                link,
                TransferAction::SendCancel(CancelType::Rcl, segment_hash),
            )
            .await,
            Err(LinkSessionResourceError::TransportUnavailable)
        );
    }

    if resources
        .rejected_inbound
        .get(&resource_id)
        .is_some_and(|rejected_at| rejected_at.elapsed() < RESOURCE_REJECTION_TTL)
    {
        return matches!(
            send_resource_action(
                transport_tx,
                attached_interface,
                link,
                TransferAction::SendCancel(CancelType::Rcl, segment_hash),
            )
            .await,
            Err(LinkSessionResourceError::TransportUnavailable)
        );
    }
    if resources.inbound.contains_key(&segment_hash)
        || resources.pending_inbound.contains_key(&segment_hash)
    {
        return false;
    }

    if resources.inbound_logicals.contains_key(&resource_id) {
        return match accept_followup_inbound_segment(
            transport_tx,
            attached_interface,
            link,
            resources,
            advertisement,
        )
        .await
        {
            Ok(()) => false,
            Err(error) => {
                tracing::debug!(%error, "rejecting invalid follow-up Resource advertisement");
                let transport_failed = matches!(
                    send_resource_action(
                        transport_tx,
                        attached_interface,
                        link,
                        TransferAction::SendCancel(CancelType::Rcl, segment_hash),
                    )
                    .await,
                    Err(LinkSessionResourceError::TransportUnavailable)
                );
                fail_inbound_logical(
                    link,
                    resources,
                    sinks.event_tx,
                    resource_id,
                    LinkSessionResourceError::Failed(error.to_string()),
                );
                transport_failed
            }
        };
    }

    let has_pending_logical = resources
        .pending_inbound
        .values()
        .any(|pending| resource_logical_id(&pending.advertisement) == resource_id);

    // Response Resources are protocol-internal request continuations, not
    // application Resource offers. Match the authenticated advertisement to a
    // live request and accept it automatically, as Python RNS does.
    if advertisement.flags.is_response {
        let Some(request_id_bytes) = advertisement.request_id.as_deref() else {
            return false;
        };
        let Ok(request_id) = <[u8; 16]>::try_from(request_id_bytes) else {
            return false;
        };
        if advertisement.flags.is_request
            || advertisement.segment_index != 1
            || has_pending_logical
            || !pending_requests.contains_key(&request_id)
        {
            return false;
        }

        resources.pending_inbound.insert(
            segment_hash,
            PendingInboundResourceOffer {
                advertisement,
                offered_at: Instant::now(),
            },
        );
        let (progress_tx, _progress_rx) = watch::channel(0.0);
        let (conclusion_tx, conclusion_rx) = oneshot::channel();
        let result = accept_inbound_offer(
            transport_tx,
            attached_interface,
            link,
            resources,
            sinks.event_tx,
            segment_hash,
            InboundResourceLifecycle {
                progress_tx,
                conclusion_tx,
            },
        )
        .await;
        let completion_tx = sinks.command_tx.clone();
        tokio::spawn(async move {
            let result = conclusion_rx
                .await
                .unwrap_or(Err(LinkSessionResourceError::SessionClosed));
            let _ = completion_tx
                .send(LinkSessionCommand::RequestResourceReceived { request_id, result })
                .await;
        });
        return matches!(result, Err(LinkSessionResourceError::TransportUnavailable));
    }

    if advertisement.segment_index != 1
        || has_pending_logical
        || resources.pending_inbound.len() >= MAX_PENDING_RESOURCE_OFFERS
    {
        return matches!(
            send_resource_action(
                transport_tx,
                attached_interface,
                link,
                TransferAction::SendCancel(CancelType::Rcl, segment_hash),
            )
            .await,
            Err(LinkSessionResourceError::TransportUnavailable)
        );
    }

    let offer = LinkSessionResourceOffer {
        link_id: link.link_id,
        resource_id,
        segment_hash,
        data_size: advertisement.data_size,
        transfer_size: advertisement.transfer_size,
        total_segments: advertisement.total_segments,
        request_id: advertisement.request_id.clone(),
        is_request: advertisement.flags.is_request,
        is_response: advertisement.flags.is_response,
        command_tx: sinks.command_tx.clone(),
    };
    resources.pending_inbound.insert(
        segment_hash,
        PendingInboundResourceOffer {
            advertisement,
            offered_at: Instant::now(),
        },
    );
    if sinks.offer_tx.try_send(offer).is_err() {
        resources.pending_inbound.remove(&segment_hash);
        resources
            .rejected_inbound
            .insert(resource_id, Instant::now());
        return matches!(
            send_resource_action(
                transport_tx,
                attached_interface,
                link,
                TransferAction::SendCancel(CancelType::Rcl, segment_hash),
            )
            .await,
            Err(LinkSessionResourceError::TransportUnavailable)
        );
    }
    false
}

fn report_inbound_progress(
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    segment_hash: [u8; 32],
) {
    let Some(inbound) = resources.inbound.get(&segment_hash) else {
        return;
    };
    let resource_id = inbound.resource_id;
    let segment_index = inbound.segment_index;
    let segment_progress = inbound.transfer.progress();
    let Some(logical) = resources.inbound_logicals.get_mut(&resource_id) else {
        return;
    };
    let progress = if logical.total_segments == 0 {
        0.0
    } else {
        ((segment_index.saturating_sub(1) as f64 + segment_progress)
            / logical.total_segments as f64)
            .clamp(0.0, 1.0)
    };
    let transferred = (progress * logical.data_size as f64).floor() as usize;
    if transferred == logical.reported_bytes && progress == logical.reported_progress {
        return;
    }
    logical.reported_bytes = transferred;
    logical.reported_progress = progress;
    logical.progress_tx.send_replace(progress);
    let _ = event_tx.try_send(LinkSessionEvent::ResourceProgress {
        resource_id,
        direction: LinkSessionResourceDirection::Inbound,
        transferred,
        total: logical.data_size,
    });
}

fn fail_inbound_logical(
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    resource_id: [u8; 32],
    error: LinkSessionResourceError,
) {
    remove_inbound_segments(link, resources, resource_id);
    conclude_inbound_resource(resources, event_tx, resource_id, Err(error));
}

async fn complete_inbound_segment(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    segment_hash: [u8; 32],
) -> bool {
    let Some(mut inbound) = resources.inbound.remove(&segment_hash) else {
        return false;
    };
    link.untrack_resource(&segment_hash);
    let resource_id = inbound.resource_id;
    let segment_index = inbound.segment_index;
    let Some(keys) = link.session_keys() else {
        fail_inbound_logical(
            link,
            resources,
            event_tx,
            resource_id,
            LinkSessionResourceError::LinkCrypto,
        );
        return false;
    };
    let decrypt = |ciphertext: &[u8]| {
        rns_link::encryption::link_decrypt(&keys, ciphertext)
            .map_err(|_| rns_protocol::resource::ResourceError::DecryptFailed)
    };
    let (data, proof) = match inbound.transfer.complete(Some(&decrypt)) {
        Ok(completed) => completed,
        Err(error) => {
            let transport_failed = matches!(
                send_resource_action(
                    transport_tx,
                    attached_interface,
                    link,
                    TransferAction::SendCancel(CancelType::Rcl, segment_hash),
                )
                .await,
                Err(LinkSessionResourceError::TransportUnavailable)
            );
            fail_inbound_logical(
                link,
                resources,
                event_tx,
                resource_id,
                LinkSessionResourceError::Failed(error.to_string()),
            );
            return transport_failed;
        }
    };
    let metadata = inbound.transfer.resource.metadata.clone();
    if let Err(error) = send_resource_action(
        transport_tx,
        attached_interface,
        link,
        TransferAction::SendProof(proof),
    )
    .await
    {
        let transport_failed = matches!(error, LinkSessionResourceError::TransportUnavailable);
        fail_inbound_logical(
            link,
            resources,
            event_tx,
            resource_id,
            LinkSessionResourceError::Failed(error.to_string()),
        );
        return transport_failed;
    }

    let mut complete_data = None;
    let mut complete_metadata = metadata.clone();
    let mut coordinator_error = None;
    if let Some(logical) = resources.inbound_logicals.get_mut(&resource_id) {
        logical.current_segment = None;
        if let Some(coordinator) = logical.coordinator.as_mut() {
            if let Err(error) = coordinator.set_segment_data(segment_index, data) {
                coordinator_error = Some(error.to_string());
            } else {
                if let Some(metadata) = metadata {
                    coordinator.set_metadata(metadata);
                }
                if coordinator.is_complete() {
                    match coordinator.reassemble() {
                        Ok(data) => {
                            complete_data = Some(data);
                            complete_metadata = coordinator.metadata.take();
                        }
                        Err(error) => coordinator_error = Some(error.to_string()),
                    }
                }
            }
        } else {
            complete_data = Some(data);
        }
    }
    if let Some(error) = coordinator_error {
        fail_inbound_logical(
            link,
            resources,
            event_tx,
            resource_id,
            LinkSessionResourceError::Failed(error),
        );
        return false;
    }

    let Some(data) = complete_data else {
        return false;
    };
    let Some(logical) = resources.inbound_logicals.get(&resource_id) else {
        return false;
    };
    let received = LinkSessionReceivedResource {
        link_id: link.link_id,
        resource_id,
        data,
        metadata: complete_metadata,
        total_segments: logical.total_segments,
        request_id: logical.request_id.clone(),
        is_request: logical.is_request,
        is_response: logical.is_response,
    };
    conclude_inbound_resource(resources, event_tx, resource_id, Ok(received));
    false
}

async fn handle_inbound_resource_part(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    part: &[u8],
) -> bool {
    let segment_hash = resources
        .inbound
        .iter()
        .find_map(|(segment_hash, inbound)| {
            let map_hash = get_map_hash(part, &inbound.transfer.resource.random_hash);
            inbound
                .transfer
                .resource
                .map_hashes
                .contains(&map_hash)
                .then_some(*segment_hash)
        });
    let Some(segment_hash) = segment_hash else {
        return false;
    };
    let (resource_id, action, complete) = {
        let inbound = resources
            .inbound
            .get_mut(&segment_hash)
            .expect("selected inbound resource exists");
        let action = inbound.transfer.receive_part(part.to_vec());
        (
            inbound.resource_id,
            action,
            inbound.transfer.resource.is_complete(),
        )
    };
    report_inbound_progress(resources, event_tx, segment_hash);

    match action {
        TransferAction::Complete => {
            return complete_inbound_segment(
                transport_tx,
                attached_interface,
                link,
                resources,
                event_tx,
                segment_hash,
            )
            .await;
        }
        TransferAction::Failed(reason) => {
            fail_inbound_logical(
                link,
                resources,
                event_tx,
                resource_id,
                LinkSessionResourceError::Failed(reason),
            );
            return false;
        }
        TransferAction::SendRequest(_)
        | TransferAction::SendHmu(_)
        | TransferAction::SendCancel(_, _) => {
            let cancel = matches!(action, TransferAction::SendCancel(_, _));
            if let Err(error) =
                send_resource_action(transport_tx, attached_interface, link, action).await
            {
                let transport_failed =
                    matches!(error, LinkSessionResourceError::TransportUnavailable);
                fail_inbound_logical(
                    link,
                    resources,
                    event_tx,
                    resource_id,
                    LinkSessionResourceError::Failed(error.to_string()),
                );
                return transport_failed;
            }
            if cancel {
                fail_inbound_logical(
                    link,
                    resources,
                    event_tx,
                    resource_id,
                    LinkSessionResourceError::Failed(
                        "receiver cancelled an invalid Resource transfer".into(),
                    ),
                );
            }
        }
        TransferAction::None
        | TransferAction::SendAdvertisement(_)
        | TransferAction::SendPart(_, _)
        | TransferAction::SendProof(_) => {}
    }
    if complete {
        complete_inbound_segment(
            transport_tx,
            attached_interface,
            link,
            resources,
            event_tx,
            segment_hash,
        )
        .await
    } else {
        false
    }
}

async fn handle_inbound_resource_hmu(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    encrypted_hmu: &[u8],
) -> bool {
    let Ok(plaintext) = link.decrypt(encrypted_hmu) else {
        return false;
    };
    let Ok((segment_hash, segment, hashmap)) = parse_hashmap_update(&plaintext) else {
        return false;
    };
    let Some(inbound) = resources.inbound.get_mut(&segment_hash) else {
        return false;
    };
    let resource_id = inbound.resource_id;
    let action = inbound.transfer.hashmap_update(segment, &hashmap);
    let cancel = matches!(action, TransferAction::SendCancel(_, _));
    if matches!(action, TransferAction::None) {
        return false;
    }
    if let Err(error) = send_resource_action(transport_tx, attached_interface, link, action).await {
        let transport_failed = matches!(error, LinkSessionResourceError::TransportUnavailable);
        fail_inbound_logical(
            link,
            resources,
            event_tx,
            resource_id,
            LinkSessionResourceError::Failed(error.to_string()),
        );
        return transport_failed;
    }
    if cancel {
        fail_inbound_logical(
            link,
            resources,
            event_tx,
            resource_id,
            LinkSessionResourceError::Failed(
                "sender returned an invalid Resource hashmap update".into(),
            ),
        );
    }
    false
}

fn handle_inbound_resource_cancel(
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    encrypted_cancel: &[u8],
) {
    let Ok(cancel) = link.decrypt(encrypted_cancel) else {
        return;
    };
    let Some(segment_hash) = cancel.get(..32) else {
        return;
    };
    let mut segment = [0u8; 32];
    segment.copy_from_slice(segment_hash);
    let Some(inbound) = resources.inbound.get_mut(&segment) else {
        return;
    };
    inbound.transfer.handle_cancel();
    let resource_id = inbound.resource_id;
    remove_inbound_segments(link, resources, resource_id);
    conclude_inbound_resource(
        resources,
        event_tx,
        resource_id,
        Err(LinkSessionResourceError::Cancelled),
    );
}

async fn poll_inbound_resources(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
) -> bool {
    resources
        .rejected_inbound
        .retain(|_, rejected_at| rejected_at.elapsed() < RESOURCE_REJECTION_TTL);

    let expired_offers: Vec<[u8; 32]> = resources
        .pending_inbound
        .iter()
        .filter_map(|(segment_hash, pending)| {
            (pending.offered_at.elapsed() >= RESOURCE_OFFER_TIMEOUT).then_some(*segment_hash)
        })
        .collect();
    for segment_hash in expired_offers {
        let Some(pending) = resources.pending_inbound.remove(&segment_hash) else {
            continue;
        };
        resources
            .rejected_inbound
            .insert(resource_logical_id(&pending.advertisement), Instant::now());
        let send_result = send_resource_action(
            transport_tx,
            attached_interface,
            link,
            TransferAction::SendCancel(CancelType::Rcl, segment_hash),
        )
        .await;
        if matches!(
            send_result,
            Err(LinkSessionResourceError::TransportUnavailable)
        ) {
            return true;
        }
    }

    let watchdog_actions: Vec<([u8; 32], [u8; 32], TransferAction)> = resources
        .inbound
        .iter_mut()
        .filter_map(|(segment_hash, inbound)| {
            let action = inbound.transfer.check_timeout();
            (!matches!(action, TransferAction::None)).then_some((
                *segment_hash,
                inbound.resource_id,
                action,
            ))
        })
        .collect();
    for (segment_hash, resource_id, action) in watchdog_actions {
        match action {
            TransferAction::Failed(reason) => {
                fail_inbound_logical(
                    link,
                    resources,
                    event_tx,
                    resource_id,
                    LinkSessionResourceError::Failed(reason),
                );
            }
            action => {
                let cancel = matches!(action, TransferAction::SendCancel(_, _));
                if let Err(error) =
                    send_resource_action(transport_tx, attached_interface, link, action).await
                {
                    let transport_failed =
                        matches!(error, LinkSessionResourceError::TransportUnavailable);
                    fail_inbound_logical(
                        link,
                        resources,
                        event_tx,
                        resource_id,
                        LinkSessionResourceError::Failed(error.to_string()),
                    );
                    if transport_failed {
                        return true;
                    }
                } else if cancel {
                    resources.inbound.remove(&segment_hash);
                    link.untrack_resource(&segment_hash);
                    fail_inbound_logical(
                        link,
                        resources,
                        event_tx,
                        resource_id,
                        LinkSessionResourceError::Failed(
                            "Resource watchdog cancelled the transfer".into(),
                        ),
                    );
                }
            }
        }
    }
    false
}

fn fail_inbound_resources(
    link: &mut Link,
    resources: &mut SessionResources,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
) {
    resources.pending_inbound.clear();
    resources.rejected_inbound.clear();
    let resource_ids: Vec<[u8; 32]> = resources.inbound_logicals.keys().copied().collect();
    for resource_id in resource_ids {
        remove_inbound_segments(link, resources, resource_id);
        conclude_inbound_resource(
            resources,
            event_tx,
            resource_id,
            Err(LinkSessionResourceError::SessionClosed),
        );
    }
}

async fn send_channel_message(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    channel: &mut LinkChannel,
    message: PackedChannelMessage,
) -> Result<LinkSessionChannelReceipt, LinkSessionChannelError> {
    if !matches!(link.state, LinkState::Active | LinkState::Stale) {
        return Err(LinkSessionChannelError::LinkNotActive);
    }
    let prepared = channel.prepare_send_tracked(&message)?;
    send_channel_data(transport_tx, attached_interface, link, channel, prepared).await
}

async fn send_channel_data(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    channel: &mut LinkChannel,
    prepared: PreparedChannelData,
) -> Result<LinkSessionChannelReceipt, LinkSessionChannelError> {
    let raw = build_data_packet(
        link.link_id,
        rns_wire::context::PacketContext::Channel,
        &prepared.data,
    );
    let packet_hash = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
    send_raw(transport_tx, attached_interface, link.link_id, raw)
        .await
        .map_err(|_| LinkSessionChannelError::TransportUnavailable)?;
    link.record_tx(prepared.data.len());
    channel.track_outbound_packet_hash(packet_hash, prepared.sequence);
    Ok(LinkSessionChannelReceipt {
        link_id: link.link_id,
        sequence: prepared.sequence,
        packet_hash,
    })
}

async fn resend_timed_out_channel_messages(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    channel: &mut LinkChannel,
) -> Result<(), LinkSessionChannelError> {
    for sequence in channel.timed_out_sequences() {
        let Some(data) = channel.timeout(sequence)? else {
            continue;
        };
        send_channel_data(
            transport_tx,
            attached_interface,
            link,
            channel,
            PreparedChannelData { sequence, data },
        )
        .await?;
    }
    Ok(())
}

async fn send_link_request(
    context: SessionRequestContext<'_>,
    path: &str,
    data: &[u8],
    timeout: Option<Duration>,
) -> Result<[u8; 16], LinkSessionError> {
    let SessionRequestContext {
        transport_tx,
        attached_interface,
        link,
        resources,
        event_tx,
        command_tx,
    } = context;
    if link.state != LinkState::Active {
        return Err(LinkSessionError::LinkNotActive);
    }
    let timeout = timeout.unwrap_or_else(|| link.default_request_timeout());
    let (packed, initial_request_id) = link
        .prepare_request(path, Some(data), timeout)
        .map_err(|_| LinkSessionError::LinkCrypto)?;

    if packed.len() > link.mdu {
        if resources.outbound.is_some() && resources.queued.len() >= MAX_QUEUED_RESOURCES {
            link.fail_pending_request(&initial_request_id);
            return Err(LinkSessionError::RequestResourceFailed(
                LinkSessionResourceError::QueueFull.to_string(),
            ));
        }
        let mut source =
            PreparedResourceSource::prepare_request(Cursor::new(packed), initial_request_id)
                .map_err(|error| {
                    link.fail_pending_request(&initial_request_id);
                    LinkSessionError::RequestResourceFailed(error.to_string())
                })?;
        let Some(keys) = link.session_keys() else {
            link.fail_pending_request(&initial_request_id);
            return Err(LinkSessionError::LinkCrypto);
        };
        let rtt = Duration::from_secs_f64(link.rtt_secs().max(0.001));
        let segment = source
            .next_segment(&keys, rtt)
            .map_err(|error| {
                link.fail_pending_request(&initial_request_id);
                LinkSessionError::RequestResourceFailed(error.to_string())
            })?
            .ok_or_else(|| {
                link.fail_pending_request(&initial_request_id);
                LinkSessionError::RequestResourceFailed(
                    "request Resource source produced no segment".into(),
                )
            })?;
        let (progress_tx, _progress_rx) = watch::channel(0.0);
        let (conclusion_tx, conclusion_rx) = oneshot::channel();
        let mut outbound =
            SessionOutboundResource::new(source, segment, progress_tx, conclusion_tx);

        if resources.outbound.is_some() {
            resources.queued.push_back(outbound);
        } else if let Err(error) = begin_outbound_resource(
            transport_tx,
            attached_interface,
            link,
            &mut outbound,
            event_tx,
        )
        .await
        {
            link.fail_pending_request(&initial_request_id);
            return Err(LinkSessionError::RequestResourceFailed(error.to_string()));
        } else {
            resources.outbound = Some(outbound);
        }

        if !link.mark_request_resource_sending(&initial_request_id) {
            link.fail_pending_request(&initial_request_id);
            return Err(LinkSessionError::LinkCrypto);
        }
        let completion_tx = command_tx.clone();
        tokio::spawn(async move {
            let result = conclusion_rx
                .await
                .unwrap_or(Err(LinkSessionResourceError::SessionClosed));
            let _ = completion_tx
                .send(LinkSessionCommand::RequestResourceConcluded {
                    request_id: initial_request_id,
                    result,
                })
                .await;
        });
        return Ok(initial_request_id);
    }

    let encrypted = match link.encrypt(&packed) {
        Ok(encrypted) => encrypted,
        Err(_) => {
            link.fail_pending_request(&initial_request_id);
            return Err(LinkSessionError::LinkCrypto);
        }
    };
    let raw = build_data_packet(
        link.link_id,
        rns_wire::context::PacketContext::Request,
        &encrypted,
    );
    let request_id =
        rns_wire::hash::truncated_packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
    if !link.update_pending_request_id(&initial_request_id, request_id) {
        link.fail_pending_request(&initial_request_id);
        return Err(LinkSessionError::LinkCrypto);
    }
    if let Err(error) = send_raw(transport_tx, attached_interface, link.link_id, raw).await {
        link.fail_pending_request(&request_id);
        return Err(error);
    }
    link.record_tx(encrypted.len());
    Ok(request_id)
}

fn reap_concluded_requests(
    link: &Link,
    pending_requests: &mut HashMap<[u8; 16], PendingSessionRequest>,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
) {
    let active: HashSet<[u8; 16]> = link
        .pending_requests
        .iter()
        .map(|receipt| {
            let mut request_id = [0u8; 16];
            request_id.copy_from_slice(&receipt.request_id[..16]);
            request_id
        })
        .collect();
    let concluded: Vec<[u8; 16]> = pending_requests
        .keys()
        .copied()
        .filter(|request_id| !active.contains(request_id))
        .collect();
    for request_id in concluded {
        if let Some(pending) = pending_requests.remove(&request_id) {
            let _ = pending
                .result_tx
                .send(Err(LinkSessionError::Timeout("Link request")));
            let _ = event_tx.try_send(LinkSessionEvent::RequestConcluded {
                request_id,
                succeeded: false,
            });
        }
    }
}

fn conclude_request_resource_response(
    link: &mut Link,
    pending_requests: &mut HashMap<[u8; 16], PendingSessionRequest>,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    request_id: [u8; 16],
    result: Result<LinkSessionReceivedResource, LinkSessionResourceError>,
) {
    if !pending_requests.contains_key(&request_id) {
        return;
    }
    let received = match result {
        Ok(received)
            if received.is_response
                && !received.is_request
                && received.request_id.as_deref() == Some(request_id.as_slice()) =>
        {
            received
        }
        Ok(_) => {
            fail_session_request(
                link,
                pending_requests,
                event_tx,
                request_id,
                LinkSessionError::RequestResourceFailed(
                    "response Resource metadata did not match the pending request".into(),
                ),
            );
            return;
        }
        Err(error) => {
            fail_session_request(
                link,
                pending_requests,
                event_tx,
                request_id,
                LinkSessionError::RequestResourceFailed(error.to_string()),
            );
            return;
        }
    };

    let (response_data, metadata) = if received.metadata.is_some() {
        (received.data, received.metadata)
    } else {
        let Ok((packed_request_id, response_data)) = Link::parse_response_plaintext(&received.data)
        else {
            fail_session_request(
                link,
                pending_requests,
                event_tx,
                request_id,
                LinkSessionError::RequestResourceFailed(
                    "response Resource contained invalid response data".into(),
                ),
            );
            return;
        };
        if packed_request_id != request_id {
            fail_session_request(
                link,
                pending_requests,
                event_tx,
                request_id,
                LinkSessionError::RequestResourceFailed(
                    "response Resource named a different request".into(),
                ),
            );
            return;
        }
        (response_data, None)
    };

    if !link.deliver_response_data(&request_id, response_data.clone()) {
        fail_session_request(
            link,
            pending_requests,
            event_tx,
            request_id,
            LinkSessionError::Timeout("Link request"),
        );
        return;
    }
    let Some(pending) = pending_requests.remove(&request_id) else {
        return;
    };
    let response = LinkSessionResponse {
        request_id,
        data: response_data,
        metadata,
        response_time: pending.sent_at.elapsed(),
    };
    let _ = pending.result_tx.send(Ok(response));
    let _ = event_tx.try_send(LinkSessionEvent::RequestConcluded {
        request_id,
        succeeded: true,
    });
}

fn fail_session_request(
    link: &mut Link,
    pending_requests: &mut HashMap<[u8; 16], PendingSessionRequest>,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    request_id: [u8; 16],
    error: LinkSessionError,
) {
    link.fail_pending_request(&request_id);
    let Some(pending) = pending_requests.remove(&request_id) else {
        return;
    };
    let _ = pending.result_tx.send(Err(error));
    let _ = event_tx.try_send(LinkSessionEvent::RequestConcluded {
        request_id,
        succeeded: false,
    });
}

fn fail_pending_requests(
    pending_requests: &mut HashMap<[u8; 16], PendingSessionRequest>,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
) {
    for (request_id, pending) in pending_requests.drain() {
        let _ = pending.result_tx.send(Err(LinkSessionError::SessionClosed));
        let _ = event_tx.try_send(LinkSessionEvent::RequestConcluded {
            request_id,
            succeeded: false,
        });
    }
}

async fn send_application_packet(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
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
    send_raw(transport_tx, attached_interface, link.link_id, raw).await?;
    link.record_tx(encrypted.len());
    pending_packets.insert(packet_hash);
    Ok(LinkSessionPacketReceipt {
        link_id: link.link_id,
        packet_hash,
    })
}

async fn process_destination_event(
    context: DestinationEventContext<'_>,
    link: &mut Link,
    state: &mut SessionActorState,
    event: DestinationEvent,
) -> Result<Option<LinkSessionCloseReason>, LinkSessionError> {
    let DestinationEventContext {
        transport_tx,
        attached_interface,
        identity,
        sinks,
        phy_stats_tx,
    } = context;
    let InboundResourceSinks {
        event_tx,
        command_tx,
        offer_tx: resource_offer_tx,
    } = sinks;
    match event {
        DestinationEvent::LinkClosed { link_id } if link_id == link.link_id => {
            return Ok(Some(LinkSessionCloseReason::Remote));
        }
        DestinationEvent::InboundPacket {
            raw,
            interface_id,
            metrics,
        } => {
            // Python pins an established Link to the interface that delivered
            // its proof. Accepting Link traffic from another interface would
            // both break route affinity and permit cross-interface injection.
            if interface_id != attached_interface {
                return Ok(None);
            }
            let Ok((header, data_offset)) = rns_wire::header::PacketHeader::unpack(&raw) else {
                return Ok(None);
            };
            if header.destination_hash != link.link_id || raw.len() < data_offset {
                return Ok(None);
            }
            update_link_phy_stats(link, metrics);
            publish_link_phy_stats(link, phy_stats_tx);
            let body = &raw[data_offset..];
            let was_stale = link.state == LinkState::Stale;

            if header.flags.packet_type == rns_wire::flags::PacketType::Proof
                && header.context == rns_wire::context::PacketContext::ResourcePrf
            {
                link.record_inbound();
                link.record_rx(body.len());
                if handle_outbound_resource_proof(
                    transport_tx,
                    attached_interface,
                    link,
                    &mut state.resources,
                    event_tx,
                    body,
                )
                .await
                {
                    return Err(LinkSessionError::TransportUnavailable);
                }
                if was_stale && link.state == LinkState::Active {
                    let _ = event_tx.send(LinkSessionEvent::Recovered).await;
                }
                return Ok(None);
            }

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
                    if link.validate_packet_proof(&packet_hash, body) {
                        let delivered_packet = state.packets.remove(&packet_hash);
                        let delivered_channel = if delivered_packet {
                            false
                        } else {
                            state
                                .channel
                                .delivered_by_packet_hash(&packet_hash, link.rtt_secs())
                                .is_some()
                        };
                        if delivered_packet || delivered_channel {
                            link.record_inbound();
                            link.keepalive.record_proof();
                        }
                        if delivered_packet {
                            let _ = event_tx
                                .send(LinkSessionEvent::PacketDelivered { packet_hash })
                                .await;
                        }
                    }
                }
                return Ok(None);
            }

            if header.flags.packet_type != rns_wire::flags::PacketType::Data {
                return Ok(None);
            }

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
                rns_wire::context::PacketContext::Response => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    if let Ok((request_id, data)) = link.handle_response(body) {
                        if let Some(request) = state.requests.remove(&request_id) {
                            let response = LinkSessionResponse {
                                request_id,
                                data,
                                metadata: None,
                                response_time: request.sent_at.elapsed(),
                            };
                            let _ = request.result_tx.send(Ok(response));
                            let _ = event_tx.try_send(LinkSessionEvent::RequestConcluded {
                                request_id,
                                succeeded: true,
                            });
                        }
                    }
                }
                rns_wire::context::PacketContext::None => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    let Ok(plaintext) = link.decrypt(body) else {
                        return Ok(None);
                    };
                    let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);
                    send_packet_proof(
                        transport_tx,
                        attached_interface,
                        identity,
                        link,
                        &packet_hash,
                    )
                    .await?;
                    event_tx
                        .send(LinkSessionEvent::Packet {
                            data: plaintext,
                            packet_hash,
                        })
                        .await
                        .map_err(|_| LinkSessionError::SessionClosed)?;
                }
                rns_wire::context::PacketContext::Channel => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);
                    send_packet_proof(
                        transport_tx,
                        attached_interface,
                        identity,
                        link,
                        &packet_hash,
                    )
                    .await?;
                    let _ = state.channel.receive_data(body);
                }
                rns_wire::context::PacketContext::ResourceReq => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);
                    if handle_outbound_resource_request(
                        transport_tx,
                        attached_interface,
                        link,
                        &mut state.resources,
                        event_tx,
                        packet_hash,
                        body,
                    )
                    .await
                    {
                        return Err(LinkSessionError::TransportUnavailable);
                    }
                }
                rns_wire::context::PacketContext::ResourceAdv => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    if process_inbound_resource_advertisement(
                        transport_tx,
                        attached_interface,
                        link,
                        &mut state.resources,
                        &state.requests,
                        InboundResourceSinks {
                            event_tx,
                            command_tx,
                            offer_tx: resource_offer_tx,
                        },
                        body,
                    )
                    .await
                    {
                        return Err(LinkSessionError::TransportUnavailable);
                    }
                }
                rns_wire::context::PacketContext::Resource => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    if handle_inbound_resource_part(
                        transport_tx,
                        attached_interface,
                        link,
                        &mut state.resources,
                        event_tx,
                        body,
                    )
                    .await
                    {
                        return Err(LinkSessionError::TransportUnavailable);
                    }
                }
                rns_wire::context::PacketContext::ResourceHmu => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    if handle_inbound_resource_hmu(
                        transport_tx,
                        attached_interface,
                        link,
                        &mut state.resources,
                        event_tx,
                        body,
                    )
                    .await
                    {
                        return Err(LinkSessionError::TransportUnavailable);
                    }
                }
                rns_wire::context::PacketContext::ResourceIcl => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    handle_inbound_resource_cancel(link, &mut state.resources, event_tx, body);
                }
                rns_wire::context::PacketContext::ResourceRcl => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    if handle_outbound_resource_rejection(
                        transport_tx,
                        attached_interface,
                        link,
                        &mut state.resources,
                        event_tx,
                        body,
                    )
                    .await
                    {
                        return Err(LinkSessionError::TransportUnavailable);
                    }
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

async fn send_packet_proof(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    identity: &Identity,
    link: &mut Link,
    packet_hash: &[u8; 32],
) -> Result<(), LinkSessionError> {
    let Ok(proof) = link.prove_packet_with_fallible(packet_hash, |hash| identity.sign(hash)) else {
        return Ok(());
    };
    let proof_raw = build_proof_packet(
        link.link_id,
        rns_wire::context::PacketContext::LinkProof,
        &proof,
    );
    send_raw(transport_tx, attached_interface, link.link_id, proof_raw).await?;
    link.record_tx(proof.len());
    Ok(())
}

async fn wait_for_link_proof(
    delivery_rx: &mut mpsc::Receiver<DestinationEvent>,
    link_id: [u8; 16],
) -> Result<(Vec<u8>, InterfaceId, PacketMetrics), LinkSessionError> {
    while let Some(event) = delivery_rx.recv().await {
        match event {
            DestinationEvent::LinkClosed { link_id: closed } if closed == link_id => {
                return Err(LinkSessionError::HandshakeFailed("Link closed".into()));
            }
            DestinationEvent::InboundPacket {
                raw,
                interface_id,
                metrics,
            } => {
                let Ok((header, data_offset)) = rns_wire::header::PacketHeader::unpack(&raw) else {
                    continue;
                };
                if header.destination_hash == link_id
                    && header.flags.packet_type == rns_wire::flags::PacketType::Proof
                    && raw.len() > data_offset
                {
                    return Ok((raw[data_offset..].to_vec(), interface_id, metrics));
                }
            }
            _ => {}
        }
    }
    Err(LinkSessionError::HandshakeFailed(
        "destination event stream closed".into(),
    ))
}

fn update_link_phy_stats(link: &mut Link, metrics: PacketMetrics) {
    link.update_phy_stats(
        metrics.rssi.map(f64::from),
        metrics.snr.map(f64::from),
        metrics.q.map(f64::from),
    );
}

fn publish_link_phy_stats(link: &Link, tx: &watch::Sender<LinkPhyStats>) {
    let next = link.phy_stats_snapshot();
    tx.send_if_modified(|current| {
        if *current == next {
            false
        } else {
            *current = next;
            true
        }
    });
}

async fn send_keepalive(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
) -> Result<(), LinkSessionError> {
    let raw = build_data_packet(
        link.link_id,
        rns_wire::context::PacketContext::Keepalive,
        &[rns_link::constants::KEEPALIVE_REQUEST],
    );
    send_raw(transport_tx, attached_interface, link.link_id, raw).await?;
    link.record_tx_keepalive(1);
    Ok(())
}

async fn send_local_teardown(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
) {
    let link_id = link.link_id;
    let Some(data) = link.teardown(CloseReason::InitiatorClosed) else {
        return;
    };
    let _ = send_raw(
        transport_tx,
        attached_interface,
        link_id,
        build_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &data),
    )
    .await;
}

async fn send_raw(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    destination_hash: [u8; 16],
    raw: Bytes,
) -> Result<(), LinkSessionError> {
    transport_tx
        .send(TransportMessage::OutboundAttached {
            request: OutboundRequest {
                raw,
                destination_hash,
            },
            interface_id: attached_interface,
        })
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
    use rns_protocol::channel_message::{MessageBase, SMT_STREAM_DATA};
    use rns_protocol::stream_data::StreamDataMessage;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[test]
    fn split_resource_progress_counts_a_proved_segment_once() {
        let destination_hash = [0xAC; 16];
        let server_signing = Ed25519PrivateKey::generate();
        let server_public = server_signing.public_key();
        let (mut initiator, request_data) = Link::new_initiator(destination_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &server_signing, destination_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &server_public, &server_public.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();

        let data_size = rns_protocol::resource::MAX_EFFICIENT_SIZE + 17;
        let mut source = PreparedResourceSource::prepare(
            Cursor::new(vec![0xA5; data_size]),
            ResourceOptions::default(),
        )
        .unwrap();
        let first = source
            .next_segment(
                &initiator.session_keys().unwrap(),
                Duration::from_millis(100),
            )
            .unwrap()
            .unwrap();
        let (progress_tx, _progress_rx) = watch::channel(0.0);
        let (conclusion_tx, _conclusion_rx) = oneshot::channel();
        let mut outbound = SessionOutboundResource::new(source, first, progress_tx, conclusion_tx);

        let (completed, progress) = outbound.mark_current_segment_complete();
        assert_eq!(completed, rns_protocol::resource::MAX_EFFICIENT_SIZE);
        assert!(progress > 0.0 && progress < 1.0);
        assert_eq!(
            progress,
            rns_protocol::resource::MAX_EFFICIENT_SIZE as f64 / data_size as f64
        );
    }

    #[tokio::test]
    async fn expired_inbound_resource_offer_is_rejected() {
        let destination_hash = [0xAD; 16];
        let server_signing = Ed25519PrivateKey::generate();
        let server_public = server_signing.public_key();
        let (mut initiator, request_data) = Link::new_initiator(destination_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &server_signing, destination_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &server_public, &server_public.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();

        let mut sender = OutboundTransfer::new_encrypted(
            b"expire inbound offer".to_vec(),
            false,
            Duration::from_secs_f64(responder.rtt_secs().max(0.001)),
            responder.session_keys().unwrap(),
        )
        .unwrap();
        let advertisement = match sender.tick() {
            TransferAction::SendAdvertisement(advertisement) => {
                ResourceAdvertisement::unpack(&advertisement).expect("unpack advertisement")
            }
            other => panic!("unexpected Resource action: {other:?}"),
        };
        let resource_id = resource_logical_id(&advertisement);
        let segment_hash = advertisement.resource_hash;
        let mut resources = SessionResources::default();
        resources.pending_inbound.insert(
            segment_hash,
            PendingInboundResourceOffer {
                advertisement,
                offered_at: Instant::now() - RESOURCE_OFFER_TIMEOUT,
            },
        );
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let (event_tx, _event_rx) = mpsc::channel::<LinkSessionEvent>(1);

        assert!(
            !poll_inbound_resources(&transport_tx, 7, &mut initiator, &mut resources, &event_tx,)
                .await
        );
        assert!(resources.pending_inbound.is_empty());
        assert!(resources.rejected_inbound.contains_key(&resource_id));

        let rejection = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 7,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&rejection.raw).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceRcl
        );
        assert_eq!(
            responder.decrypt(&rejection.raw[offset..]).unwrap(),
            segment_hash
        );
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
            7,
            &mut initiator,
            &mut pending_packets,
            b"pong".to_vec(),
        )
        .await
        .expect("a stale Link must still be able to answer its peer");

        let sent = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 7,
            } => request,
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
    async fn oversized_request_starts_a_request_resource() {
        let destination_hash = [0xBE; 16];
        let server_signing = Ed25519PrivateKey::generate();
        let server_public = server_signing.public_key();
        let (mut initiator, request_data) = Link::new_initiator(destination_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &server_signing, destination_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &server_public, &server_public.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();
        let mdu = initiator.mdu;
        let payload = vec![0u8; mdu];
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let (event_tx, _event_rx) = mpsc::channel::<LinkSessionEvent>(4);
        let (command_tx, _command_rx) = mpsc::channel::<LinkSessionCommand>(4);
        let mut resources = SessionResources::default();

        let request_id = send_link_request(
            SessionRequestContext {
                transport_tx: &transport_tx,
                attached_interface: 1,
                link: &mut initiator,
                resources: &mut resources,
                event_tx: &event_tx,
                command_tx: &command_tx,
            },
            "/large",
            &payload,
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();
        assert_eq!(initiator.pending_requests.len(), 1);
        assert_eq!(
            initiator.pending_requests[0].state,
            rns_link::request::RequestState::SendingResource
        );

        let advertisement = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&advertisement.raw).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceAdv
        );
        let plaintext = responder.decrypt(&advertisement.raw[offset..]).unwrap();
        let advertisement = ResourceAdvertisement::unpack(&plaintext).unwrap();
        assert!(advertisement.flags.is_request);
        assert!(!advertisement.flags.is_response);
        assert_eq!(
            advertisement.request_id.as_deref(),
            Some(request_id.as_slice())
        );
    }

    #[tokio::test]
    async fn response_resource_is_accepted_and_concludes_matching_request() {
        let destination_hash = [0xBF; 16];
        let server_signing = Ed25519PrivateKey::generate();
        let server_public = server_signing.public_key();
        let (mut initiator, request_data) = Link::new_initiator(destination_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &server_signing, destination_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &server_public, &server_public.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();

        let (_packed_request, request_id) = initiator
            .prepare_request("/large-response", Some(b""), Duration::from_secs(5))
            .unwrap();
        let (result_tx, result_rx) = oneshot::channel();
        let mut pending_requests = HashMap::from([(
            request_id,
            PendingSessionRequest {
                sent_at: Instant::now(),
                result_tx,
            },
        )]);

        let packed_response = Link::pack_response(&request_id, b"resource response").unwrap();
        let mut response_sender = OutboundTransfer::new_encrypted(
            packed_response,
            false,
            Duration::from_secs_f64(responder.rtt_secs().max(0.001)),
            responder.session_keys().unwrap(),
        )
        .unwrap();
        response_sender.resource.flags.is_response = true;
        response_sender.resource.request_id = Some(request_id.to_vec());
        let advertisement = match response_sender.tick() {
            TransferAction::SendAdvertisement(advertisement) => advertisement,
            other => panic!("unexpected responder Resource action: {other:?}"),
        };

        let mut resources = SessionResources::default();
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(8);
        let (command_tx, mut command_rx) = mpsc::channel::<LinkSessionCommand>(8);
        let (event_tx, _event_rx) = mpsc::channel::<LinkSessionEvent>(8);
        let (offer_tx, mut offer_rx) = mpsc::channel::<LinkSessionResourceOffer>(1);
        assert!(
            !process_inbound_resource_advertisement(
                &transport_tx,
                1,
                &mut initiator,
                &mut resources,
                &pending_requests,
                InboundResourceSinks {
                    event_tx: &event_tx,
                    command_tx: &command_tx,
                    offer_tx: &offer_tx,
                },
                &responder.encrypt(&advertisement).unwrap(),
            )
            .await
        );
        assert!(
            offer_rx.try_recv().is_err(),
            "response Resources must not be surfaced as application offers"
        );

        let request = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (request_header, request_offset) =
            rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            request_header.context,
            rns_wire::context::PacketContext::ResourceReq
        );
        let request_plaintext = responder.decrypt(&request.raw[request_offset..]).unwrap();
        let request_hash =
            rns_wire::hash::packet_hash(&request.raw, request_header.flags.header_type);
        let actions = response_sender.handle_request_packet(request_hash, &request_plaintext);
        assert!(!actions.is_empty());
        for action in actions {
            let TransferAction::SendPart(_, part) = action else {
                continue;
            };
            assert!(
                !handle_inbound_resource_part(
                    &transport_tx,
                    1,
                    &mut initiator,
                    &mut resources,
                    &event_tx,
                    &part,
                )
                .await
            );
        }

        let command = tokio::time::timeout(Duration::from_secs(1), command_rx.recv())
            .await
            .expect("response Resource conclusion timeout")
            .expect("response Resource command channel closed");
        let LinkSessionCommand::RequestResourceReceived {
            request_id: concluded_id,
            result,
        } = command
        else {
            panic!("unexpected Link session command");
        };
        assert_eq!(concluded_id, request_id);
        conclude_request_resource_response(
            &mut initiator,
            &mut pending_requests,
            &event_tx,
            concluded_id,
            result,
        );

        let response = result_rx.await.unwrap().unwrap();
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.data, b"resource response");
        assert_eq!(response.metadata, None);
        assert!(pending_requests.is_empty());
        assert!(initiator.pending_requests.is_empty());
    }

    #[tokio::test]
    async fn session_actor_recovers_and_answers_data_received_after_stale() {
        let destination_hash = [0xBD; 16];
        let server_signing = Ed25519PrivateKey::generate();
        let server_public = server_signing.public_key();
        let client_identity = Identity::new();
        let (mut initiator, request_data) = Link::new_initiator(destination_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &server_signing, destination_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &server_public, &server_public.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();

        // Make the actor enter STALE on its first tick. The subsequent inbound
        // application packet models a peer heartbeat arriving during the
        // recoverable stale grace period.
        initiator.keepalive.stale_time = Duration::ZERO;
        initiator.keepalive.keepalive_interval = Duration::from_secs(60);

        let link_id = initiator.link_id;
        let mdu = initiator.mdu;
        let channel = LinkChannel::new_encrypted_with_mdu(
            link_id,
            initiator.rtt_secs(),
            mdu,
            initiator.session_keys().unwrap(),
        );
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(16);
        let (delivery_tx, delivery_rx) = mpsc::channel::<DestinationEvent>(16);
        let (command_tx, command_rx) = mpsc::channel::<LinkSessionCommand>(16);
        let (event_tx, mut event_rx) = mpsc::channel::<LinkSessionEvent>(16);
        let (resource_offer_tx, _resource_offer_rx) = mpsc::channel::<LinkSessionResourceOffer>(1);
        let (phy_stats_tx, phy_stats_rx) = watch::channel(LinkPhyStats::default());
        let handle = LinkSessionHandle {
            link_id,
            mdu,
            command_tx: command_tx.clone(),
            phy_stats_rx,
        };

        tokio::spawn(run_session_actor(
            client_identity,
            (initiator, channel),
            7,
            delivery_rx,
            command_rx,
            SessionActorChannels {
                transport_tx,
                command_tx,
                event_tx,
                resource_offer_tx,
                phy_stats_tx,
            },
        ));

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
                .await
                .unwrap(),
            Some(LinkSessionEvent::Stale)
        );
        let stale_keepalive = transport_rx.recv().await.unwrap();
        assert!(matches!(
            stale_keepalive,
            TransportMessage::OutboundAttached {
                interface_id: 7,
                ..
            }
        ));

        let inbound_ciphertext = responder.encrypt(b"ping").unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_data_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::None,
                    &inbound_ciphertext,
                ),
                interface_id: 7,
                metrics: Default::default(),
            })
            .await
            .unwrap();

        let inbound_proof = transport_rx.recv().await.unwrap();
        assert!(matches!(
            inbound_proof,
            TransportMessage::OutboundAttached {
                interface_id: 7,
                ..
            }
        ));
        assert!(matches!(
            event_rx.recv().await,
            Some(LinkSessionEvent::Packet { ref data, .. }) if data == b"ping"
        ));
        assert_eq!(event_rx.recv().await, Some(LinkSessionEvent::Recovered));

        handle
            .send_packet(b"pong".to_vec())
            .await
            .expect("the recovered actor must accept the heartbeat response");
        let response = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 7,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&response.raw).unwrap();
        assert_eq!(responder.decrypt(&response.raw[offset..]).unwrap(), b"pong");

        handle.close().await;
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
                track_phy_stats: false,
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
                track_phy_stats: true,
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
                metrics: PacketMetrics {
                    rssi: Some(-87.0),
                    snr: Some(6.5),
                    q: Some(0.75),
                },
            })
            .await
            .unwrap();

        let rtt = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (rtt_header, rtt_offset) = rns_wire::header::PacketHeader::unpack(&rtt.raw).unwrap();
        assert_eq!(rtt_header.context, rns_wire::context::PacketContext::Lrrtt);
        responder
            .receive_rtt_packet(&rtt.raw[rtt_offset..])
            .unwrap();

        let identify = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
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
        assert_eq!(
            session.handle.phy_stats(),
            LinkPhyStats {
                rssi: Some(-87.0),
                snr: Some(6.5),
                q: Some(0.75),
            }
        );
        let mut phy_stats_rx = session.handle.watch_phy_stats();
        let receipt = session
            .handle
            .send_packet(b"hello hub".to_vec())
            .await
            .unwrap();
        let sent = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
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

        let request_handle = session.handle.clone();
        let request_task = tokio::spawn(async move {
            request_handle
                .request("/echo", b"request body", Some(Duration::from_secs(2)))
                .await
        });
        let request = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (request_header, request_offset) =
            rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            request_header.context,
            rns_wire::context::PacketContext::Request
        );
        let (_packed_id, path_hash, _timestamp, request_data) = responder
            .handle_request(&request.raw[request_offset..])
            .unwrap();
        assert_eq!(path_hash, rns_crypto::sha::truncated_hash(b"/echo"));
        assert_eq!(request_data, b"request body");
        let request_id =
            rns_wire::hash::truncated_packet_hash(&request.raw, request_header.flags.header_type);
        let response = responder
            .create_response(&request_id, b"response body")
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_data_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::Response,
                    &response,
                ),
                interface_id: 1,
                metrics: PacketMetrics {
                    rssi: Some(-72.0),
                    snr: Some(8.0),
                    q: Some(1.0),
                },
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), phy_stats_rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            *phy_stats_rx.borrow(),
            LinkPhyStats {
                rssi: Some(-72.0),
                snr: Some(8.0),
                q: Some(1.0),
            }
        );
        let response = request_task.await.unwrap().unwrap();
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.data, b"response body");
        assert!(matches!(
            session.events.recv().await,
            Some(LinkSessionEvent::RequestConcluded {
                request_id: concluded,
                succeeded: true,
            }) if concluded == request_id
        ));

        let timeout_handle = session.handle.clone();
        let timeout_task = tokio::spawn(async move {
            timeout_handle
                .request("/timeout", b"", Some(Duration::ZERO))
                .await
        });
        let timed_out_request = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (timed_out_header, _) =
            rns_wire::header::PacketHeader::unpack(&timed_out_request.raw).unwrap();
        let timed_out_id = rns_wire::hash::truncated_packet_hash(
            &timed_out_request.raw,
            timed_out_header.flags.header_type,
        );
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), timeout_task)
                .await
                .expect("request timeout result")
                .unwrap(),
            Err(LinkSessionError::Timeout("Link request"))
        ));
        assert!(matches!(
            session.events.recv().await,
            Some(LinkSessionEvent::RequestConcluded {
                request_id: concluded,
                succeeded: false,
            }) if concluded == timed_out_id
        ));

        let channel = session.handle.channel();
        assert_eq!(
            channel.mdu(),
            rns_protocol::channel::Channel::channel_mdu(session.handle.mdu())
        );
        channel.register_message_type(0x0042).await.unwrap();
        let (message_tx_guard, mut message_rx) = mpsc::unbounded_channel();
        let message_tx = message_tx_guard.clone();
        let handler_id = channel
            .add_message_handler(move |msg_type, payload| {
                let _ = message_tx.send((msg_type, payload.to_vec()));
                true
            })
            .await
            .unwrap();
        let mut responder_channel = LinkChannel::new_encrypted_with_mdu(
            responder.link_id,
            responder.rtt_secs(),
            responder.mdu,
            responder.session_keys().unwrap(),
        );
        responder_channel.register_message_type(0x0042).unwrap();

        let first_receipt = channel
            .send_raw(0x0042, b"first channel frame")
            .await
            .unwrap();
        let first_channel_packet = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (first_channel_header, first_channel_offset) =
            rns_wire::header::PacketHeader::unpack(&first_channel_packet.raw).unwrap();
        assert_eq!(
            first_channel_header.context,
            rns_wire::context::PacketContext::Channel
        );
        assert_eq!(
            responder_channel
                .receive_data(&first_channel_packet.raw[first_channel_offset..])
                .unwrap(),
            vec![(0x0042, b"first channel frame".to_vec())]
        );

        let second_receipt = channel
            .send_raw(0x0042, b"second channel frame")
            .await
            .unwrap();
        let second_channel_packet = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (_, second_channel_offset) =
            rns_wire::header::PacketHeader::unpack(&second_channel_packet.raw).unwrap();
        assert_eq!(
            responder_channel
                .receive_data(&second_channel_packet.raw[second_channel_offset..])
                .unwrap(),
            vec![(0x0042, b"second channel frame".to_vec())]
        );
        assert!(!channel.is_ready_to_send().await.unwrap());

        let first_proof = responder
            .prove_packet_with_fallible(&first_receipt.packet_hash, |hash| {
                server_identity.sign(hash)
            })
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_proof_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::LinkProof,
                    &first_proof,
                ),
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if channel.is_ready_to_send().await.unwrap() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("channel proof should reopen the send window");

        let second_proof = responder
            .prove_packet_with_fallible(&second_receipt.packet_hash, |hash| {
                server_identity.sign(hash)
            })
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_proof_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::LinkProof,
                    &second_proof,
                ),
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if channel.is_drained().await.unwrap() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all channel frames should drain after their proofs");

        let inbound_prepared = responder_channel
            .prepare_send_tracked(&PackedChannelMessage {
                msg_type: 0x0042,
                payload: b"inbound channel frame".to_vec(),
            })
            .unwrap();
        let inbound_channel_packet = build_data_packet(
            responder.link_id,
            rns_wire::context::PacketContext::Channel,
            &inbound_prepared.data,
        );
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: inbound_channel_packet,
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), message_rx.recv())
                .await
                .unwrap(),
            Some((0x0042, b"inbound channel frame".to_vec()))
        );
        let inbound_proof = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (inbound_proof_header, _) =
            rns_wire::header::PacketHeader::unpack(&inbound_proof.raw).unwrap();
        assert_eq!(
            inbound_proof_header.flags.packet_type,
            rns_wire::flags::PacketType::Proof
        );
        responder_channel.delivered(inbound_prepared.sequence, responder.rtt_secs());

        assert!(channel.remove_message_handler(handler_id).await.unwrap());
        let ignored_prepared = responder_channel
            .prepare_send_tracked(&PackedChannelMessage {
                msg_type: 0x0042,
                payload: b"ignored after removal".to_vec(),
            })
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_data_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::Channel,
                    &ignored_prepared.data,
                ),
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), message_rx.recv())
                .await
                .is_err()
        );
        let _ignored_proof = transport_rx.recv().await.unwrap();
        responder_channel.delivered(ignored_prepared.sequence, responder.rtt_secs());

        responder_channel.register_system_type(SMT_STREAM_DATA);
        let mut buffer = channel.create_bidirectional_buffer(7, 8).await.unwrap();
        assert_eq!(buffer.reader().stream_id(), 7);

        let inbound_stream = StreamDataMessage::new(7, b"buffer inbound".to_vec(), false);
        let inbound_stream_prepared = responder_channel
            .prepare_send_tracked(&inbound_stream)
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_data_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::Channel,
                    &inbound_stream_prepared.data,
                ),
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        let mut inbound_buffer = vec![0; b"buffer inbound".len()];
        tokio::time::timeout(
            Duration::from_secs(1),
            buffer.read_exact(&mut inbound_buffer),
        )
        .await
        .expect("Buffer reader should wake for its stream")
        .unwrap();
        assert_eq!(inbound_buffer, b"buffer inbound");
        let _inbound_stream_proof = transport_rx.recv().await.unwrap();
        responder_channel.delivered(inbound_stream_prepared.sequence, responder.rtt_secs());

        buffer.write_all(b"buffer outbound").await.unwrap();
        let outbound_stream_packet = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (outbound_stream_header, outbound_stream_offset) =
            rns_wire::header::PacketHeader::unpack(&outbound_stream_packet.raw).unwrap();
        let outbound_stream_messages = responder_channel
            .receive_data(&outbound_stream_packet.raw[outbound_stream_offset..])
            .unwrap();
        assert_eq!(outbound_stream_messages.len(), 1);
        assert_eq!(outbound_stream_messages[0].0, SMT_STREAM_DATA);
        let mut outbound_stream = StreamDataMessage::new(0, Vec::new(), false);
        outbound_stream
            .unpack(&outbound_stream_messages[0].1)
            .unwrap();
        assert_eq!(outbound_stream.stream_id, 8);
        assert_eq!(outbound_stream.data, b"buffer outbound");
        assert!(!outbound_stream.eof);

        let outbound_stream_hash = rns_wire::hash::packet_hash(
            &outbound_stream_packet.raw,
            outbound_stream_header.flags.header_type,
        );
        let outbound_stream_proof = responder
            .prove_packet_with_fallible(&outbound_stream_hash, |hash| server_identity.sign(hash))
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_proof_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::LinkProof,
                    &outbound_stream_proof,
                ),
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();

        buffer.shutdown().await.unwrap();
        let eof_packet = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (eof_header, eof_offset) =
            rns_wire::header::PacketHeader::unpack(&eof_packet.raw).unwrap();
        let eof_messages = responder_channel
            .receive_data(&eof_packet.raw[eof_offset..])
            .unwrap();
        assert_eq!(eof_messages.len(), 1);
        let mut eof = StreamDataMessage::new(0, Vec::new(), false);
        eof.unpack(&eof_messages[0].1).unwrap();
        assert_eq!(eof.stream_id, 8);
        assert!(eof.eof);
        assert!(eof.data.is_empty());

        let eof_hash = rns_wire::hash::packet_hash(&eof_packet.raw, eof_header.flags.header_type);
        let eof_proof = responder
            .prove_packet_with_fallible(&eof_hash, |hash| server_identity.sign(hash))
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_proof_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::LinkProof,
                    &eof_proof,
                ),
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        buffer.close_reader().await.unwrap();

        let inbound_ciphertext = responder.encrypt(b"hello client").unwrap();
        let inbound = build_data_packet(
            responder.link_id,
            rns_wire::context::PacketContext::None,
            &inbound_ciphertext,
        );
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: inbound.clone(),
                interface_id: 9,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), session.events.recv())
                .await
                .is_err(),
            "Link traffic from a different interface must be ignored"
        );
        assert!(
            transport_rx.try_recv().is_err(),
            "off-interface Link traffic must not be proved"
        );
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: inbound,
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        let event = session.events.recv().await.unwrap();
        assert!(matches!(
            event,
            LinkSessionEvent::Packet { ref data, .. } if data == b"hello client"
        ));
        let proof = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
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

        let resource_payload = b"resource payload over the persistent Link".to_vec();
        let resource = session
            .handle
            .send_resource_bytes(resource_payload.clone(), ResourceOptions::default())
            .await
            .unwrap();
        let resource_id = resource.resource_id();
        let progress = resource.progress();
        assert_eq!(
            session.events.recv().await,
            Some(LinkSessionEvent::ResourceStarted {
                resource_id,
                direction: LinkSessionResourceDirection::Outbound,
                data_size: resource_payload.len(),
                total_segments: 1,
            })
        );

        let advertisement = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (advertisement_header, advertisement_offset) =
            rns_wire::header::PacketHeader::unpack(&advertisement.raw).unwrap();
        assert_eq!(
            advertisement_header.context,
            rns_wire::context::PacketContext::ResourceAdv
        );
        let advertisement_plaintext = responder
            .decrypt(&advertisement.raw[advertisement_offset..])
            .unwrap();
        let advertisement =
            rns_protocol::resource_adv::ResourceAdvertisement::unpack(&advertisement_plaintext)
                .unwrap();
        assert_eq!(advertisement.resource_hash, resource_id);

        let mut random_hash = [0u8; rns_protocol::resource::RANDOM_HASH_SIZE];
        random_hash.copy_from_slice(
            &advertisement.random_hash[..rns_protocol::resource::RANDOM_HASH_SIZE],
        );
        let mut inbound_resource = rns_protocol::resource::InboundTransfer::from_advertisement(
            advertisement.num_parts,
            advertisement.transfer_size,
            advertisement.data_size,
            random_hash,
            advertisement.resource_hash,
            advertisement.flags,
            advertisement.get_map_hashes(),
            Duration::from_secs_f64(responder.rtt_secs().max(0.001)),
        )
        .unwrap();
        let request = match inbound_resource.request_next() {
            TransferAction::SendRequest(request) => request,
            other => panic!("unexpected initial resource action: {other:?}"),
        };
        let encrypted_request = responder.encrypt(&request).unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_data_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::ResourceReq,
                    &encrypted_request,
                ),
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();

        let part = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (part_header, part_offset) = rns_wire::header::PacketHeader::unpack(&part.raw).unwrap();
        assert_eq!(
            part_header.context,
            rns_wire::context::PacketContext::Resource
        );
        assert_eq!(
            inbound_resource.receive_part(part.raw[part_offset..].to_vec()),
            TransferAction::Complete
        );
        let decrypt_resource =
            |ciphertext: &[u8]| -> Result<Vec<u8>, rns_protocol::resource::ResourceError> {
                responder
                    .decrypt(ciphertext)
                    .map_err(|_| rns_protocol::resource::ResourceError::DecryptFailed)
            };
        let (received_resource, resource_proof) =
            inbound_resource.complete(Some(&decrypt_resource)).unwrap();
        assert_eq!(received_resource, resource_payload);
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_proof_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::ResourcePrf,
                    &resource_proof,
                ),
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();

        let resource_receipt = resource.concluded().await.unwrap();
        assert_eq!(resource_receipt.resource_id, resource_id);
        assert_eq!(resource_receipt.data_size, resource_payload.len());
        assert_eq!(*progress.borrow(), 1.0);
        assert!(matches!(
            session.events.recv().await,
            Some(LinkSessionEvent::ResourceProgress {
                resource_id: progressed,
                direction: LinkSessionResourceDirection::Outbound,
                transferred,
                total,
            }) if progressed == resource_id
                && transferred == resource_payload.len()
                && total == resource_payload.len()
        ));
        assert_eq!(
            session.events.recv().await,
            Some(LinkSessionEvent::ResourceConcluded {
                resource_id,
                direction: LinkSessionResourceDirection::Outbound,
                succeeded: true,
            })
        );

        let active_resource = session
            .handle
            .send_resource_bytes(b"cancel active".to_vec(), ResourceOptions::default())
            .await
            .unwrap();
        let active_resource_id = active_resource.resource_id();
        assert_eq!(
            session.events.recv().await,
            Some(LinkSessionEvent::ResourceStarted {
                resource_id: active_resource_id,
                direction: LinkSessionResourceDirection::Outbound,
                data_size: b"cancel active".len(),
                total_segments: 1,
            })
        );
        let active_advertisement = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (active_advertisement_header, _) =
            rns_wire::header::PacketHeader::unpack(&active_advertisement.raw).unwrap();
        assert_eq!(
            active_advertisement_header.context,
            rns_wire::context::PacketContext::ResourceAdv
        );

        let queued_resource = session
            .handle
            .send_resource_bytes(b"cancel queued".to_vec(), ResourceOptions::default())
            .await
            .unwrap();
        let queued_resource_id = queued_resource.resource_id();
        assert!(
            transport_rx.try_recv().is_err(),
            "queued resources must not advertise before the active transfer concludes"
        );
        assert!(queued_resource.cancel().await.unwrap());
        assert!(matches!(
            queued_resource.concluded().await,
            Err(LinkSessionResourceError::Cancelled)
        ));
        assert_eq!(
            session.events.recv().await,
            Some(LinkSessionEvent::ResourceConcluded {
                resource_id: queued_resource_id,
                direction: LinkSessionResourceDirection::Outbound,
                succeeded: false,
            })
        );

        assert!(active_resource.cancel().await.unwrap());
        let cancellation = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (cancellation_header, cancellation_offset) =
            rns_wire::header::PacketHeader::unpack(&cancellation.raw).unwrap();
        assert_eq!(
            cancellation_header.context,
            rns_wire::context::PacketContext::ResourceIcl
        );
        assert_eq!(
            responder
                .decrypt(&cancellation.raw[cancellation_offset..])
                .unwrap(),
            active_resource_id
        );
        assert!(matches!(
            active_resource.concluded().await,
            Err(LinkSessionResourceError::Cancelled)
        ));
        assert_eq!(
            session.events.recv().await,
            Some(LinkSessionEvent::ResourceConcluded {
                resource_id: active_resource_id,
                direction: LinkSessionResourceDirection::Outbound,
                succeeded: false,
            })
        );

        let inbound_payload = b"resource sent from the responder".to_vec();
        let mut inbound_sender = OutboundTransfer::new_encrypted(
            inbound_payload.clone(),
            false,
            Duration::from_secs_f64(responder.rtt_secs().max(0.001)),
            responder.session_keys().unwrap(),
        )
        .unwrap();
        let inbound_advertisement = match inbound_sender.tick() {
            TransferAction::SendAdvertisement(advertisement) => advertisement,
            other => panic!("unexpected responder Resource action: {other:?}"),
        };
        let inbound_resource_id = inbound_sender.resource.resource_hash;
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_data_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::ResourceAdv,
                    &responder.encrypt(&inbound_advertisement).unwrap(),
                ),
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        let offer = tokio::time::timeout(Duration::from_secs(1), session.resource_offers.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(offer.resource_id(), inbound_resource_id);
        assert_eq!(offer.data_size(), inbound_payload.len());
        let inbound_resource = offer.accept().await.unwrap();
        let inbound_progress = inbound_resource.progress();
        assert_eq!(
            session.events.recv().await,
            Some(LinkSessionEvent::ResourceStarted {
                resource_id: inbound_resource_id,
                direction: LinkSessionResourceDirection::Inbound,
                data_size: inbound_payload.len(),
                total_segments: 1,
            })
        );
        let inbound_request = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (inbound_request_header, inbound_request_offset) =
            rns_wire::header::PacketHeader::unpack(&inbound_request.raw).unwrap();
        assert_eq!(
            inbound_request_header.context,
            rns_wire::context::PacketContext::ResourceReq
        );
        let inbound_request_plaintext = responder
            .decrypt(&inbound_request.raw[inbound_request_offset..])
            .unwrap();
        let inbound_request_hash = rns_wire::hash::packet_hash(
            &inbound_request.raw,
            inbound_request_header.flags.header_type,
        );
        let inbound_actions =
            inbound_sender.handle_request_packet(inbound_request_hash, &inbound_request_plaintext);
        assert!(!inbound_actions.is_empty());
        for action in inbound_actions {
            let TransferAction::SendPart(_, part) = action else {
                panic!("unexpected responder Resource action: {action:?}");
            };
            delivery_tx
                .send(DestinationEvent::InboundPacket {
                    raw: build_data_packet(
                        responder.link_id,
                        rns_wire::context::PacketContext::Resource,
                        &part,
                    ),
                    interface_id: 1,
                    metrics: Default::default(),
                })
                .await
                .unwrap();
        }

        let inbound_proof = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (inbound_proof_header, inbound_proof_offset) =
            rns_wire::header::PacketHeader::unpack(&inbound_proof.raw).unwrap();
        assert_eq!(
            inbound_proof_header.context,
            rns_wire::context::PacketContext::ResourcePrf
        );
        assert_eq!(
            inbound_proof_header.flags.packet_type,
            rns_wire::flags::PacketType::Proof
        );
        assert!(inbound_sender.handle_proof(&inbound_proof.raw[inbound_proof_offset..]));
        let received = inbound_resource.concluded().await.unwrap();
        assert_eq!(received.resource_id, inbound_resource_id);
        assert_eq!(received.data, inbound_payload);
        assert_eq!(*inbound_progress.borrow(), 1.0);
        assert!(matches!(
            session.events.recv().await,
            Some(LinkSessionEvent::ResourceProgress {
                resource_id,
                direction: LinkSessionResourceDirection::Inbound,
                transferred,
                total,
            }) if resource_id == inbound_resource_id
                && transferred == inbound_payload.len()
                && total == inbound_payload.len()
        ));
        assert_eq!(
            session.events.recv().await,
            Some(LinkSessionEvent::ResourceConcluded {
                resource_id: inbound_resource_id,
                direction: LinkSessionResourceDirection::Inbound,
                succeeded: true,
            })
        );

        let mut rejected_sender = OutboundTransfer::new_encrypted(
            b"reject inbound".to_vec(),
            false,
            Duration::from_secs_f64(responder.rtt_secs().max(0.001)),
            responder.session_keys().unwrap(),
        )
        .unwrap();
        let rejected_advertisement = match rejected_sender.tick() {
            TransferAction::SendAdvertisement(advertisement) => advertisement,
            other => panic!("unexpected responder Resource action: {other:?}"),
        };
        let rejected_id = rejected_sender.resource.resource_hash;
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_data_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::ResourceAdv,
                    &responder.encrypt(&rejected_advertisement).unwrap(),
                ),
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        let rejected_offer = session.resource_offers.recv().await.unwrap();
        assert!(rejected_offer.reject().await.unwrap());
        let rejection = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (rejection_header, rejection_offset) =
            rns_wire::header::PacketHeader::unpack(&rejection.raw).unwrap();
        assert_eq!(
            rejection_header.context,
            rns_wire::context::PacketContext::ResourceRcl
        );
        assert_eq!(
            responder
                .decrypt(&rejection.raw[rejection_offset..])
                .unwrap(),
            rejected_id
        );

        let mut cancelled_sender = OutboundTransfer::new_encrypted(
            b"cancel inbound".to_vec(),
            false,
            Duration::from_secs_f64(responder.rtt_secs().max(0.001)),
            responder.session_keys().unwrap(),
        )
        .unwrap();
        let cancelled_advertisement = match cancelled_sender.tick() {
            TransferAction::SendAdvertisement(advertisement) => advertisement,
            other => panic!("unexpected responder Resource action: {other:?}"),
        };
        let cancelled_id = cancelled_sender.resource.resource_hash;
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_data_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::ResourceAdv,
                    &responder.encrypt(&cancelled_advertisement).unwrap(),
                ),
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        let cancelled_offer = session.resource_offers.recv().await.unwrap();
        let cancelled_inbound = cancelled_offer.accept().await.unwrap();
        assert_eq!(
            session.events.recv().await,
            Some(LinkSessionEvent::ResourceStarted {
                resource_id: cancelled_id,
                direction: LinkSessionResourceDirection::Inbound,
                data_size: b"cancel inbound".len(),
                total_segments: 1,
            })
        );
        let _cancelled_request = transport_rx.recv().await.unwrap();
        assert!(cancelled_inbound.cancel().await.unwrap());
        let cancellation = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (cancellation_header, cancellation_offset) =
            rns_wire::header::PacketHeader::unpack(&cancellation.raw).unwrap();
        assert_eq!(
            cancellation_header.context,
            rns_wire::context::PacketContext::ResourceRcl
        );
        assert_eq!(
            responder
                .decrypt(&cancellation.raw[cancellation_offset..])
                .unwrap(),
            cancelled_id
        );
        assert!(matches!(
            cancelled_inbound.concluded().await,
            Err(LinkSessionResourceError::Cancelled)
        ));
        assert_eq!(
            session.events.recv().await,
            Some(LinkSessionEvent::ResourceConcluded {
                resource_id: cancelled_id,
                direction: LinkSessionResourceDirection::Inbound,
                succeeded: false,
            })
        );

        session.handle.close().await;
        let close = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
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
