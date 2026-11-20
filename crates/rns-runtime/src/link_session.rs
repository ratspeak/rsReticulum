//! Persistent initiator-side Reticulum Link sessions for applications.
//!
//! A session carries encrypted packets, request/response exchanges, Channels
//! and Resources until closed or timed out. [`crate::link_client::LinkClient`]
//! provides a separate convenience API for one request/response exchange.
//! Keep draining [`LinkSession::events`] while using the handles; a full event
//! queue can stall the actor, including its protocol timers and close handling.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rns_crypto::ed25519::Ed25519PublicKey;
use rns_identity::destination::ProofStrategy;
use rns_identity::identity::Identity;
use rns_link::link::{CloseReason, Link, LinkAction, LinkPhyStats, LinkState};
use rns_protocol::channel::{
    ChannelError, HandlerId, LinkChannel, MessageCallback, PreparedChannelData,
};
use rns_protocol::channel_message::{ChannelMessageError, MessageBase};
use rns_protocol::resource::{
    CancelType, DEFAULT_INBOUND_REASSEMBLY_LIMIT, HASHMAP_IS_EXHAUSTED, InboundTransfer,
    MAPHASH_LEN, MultiSegmentInbound, OutboundTransfer, RANDOM_HASH_SIZE, TransferAction,
    get_map_hash, parse_hashmap_update,
};
use rns_protocol::resource_adv::ResourceAdvertisement;
use rns_transport::link_messages::{DestinationEvent, PacketMetrics};
use rns_transport::messages::{
    AnnounceRpcEntry, InterfaceId, LinkEndpointRole, OutboundRequest, TransportMessage,
    TransportQuery, TransportQueryResponse,
};
use tokio::sync::{mpsc, oneshot, watch};

use crate::resource_source::{
    PreparedResourceSegment, PreparedResourceSource, ResourceOptions, ResourceSource,
    ResourceSourceError,
};
use crate::resource_spool::{ResourceSpool, spool_dir};

const COMMAND_BUFFER: usize = 64;
const EVENT_BUFFER: usize = 256;
const MAX_PENDING_REQUESTS: usize = 64;
const MAX_QUEUED_RESOURCES: usize = 8;
const MAX_PENDING_RESOURCE_OFFERS: usize = 8;
const RESOURCE_REJECTION_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
/// Remote destination and establishment options. The caller must supply a
/// trusted association between `destination_hash` and `remote_public_key`;
/// connection verifies the Link proof with the supplied signing key, without
/// re-deriving a destination from an application name.
///
/// `identified` defaults to one hop, a 30-second establishment timeout,
/// LinkIdentify enabled and physical-stat tracking disabled. The timeout
/// covers request admission and proof waiting, not every registration, binding
/// or identification operation; see `LinkSession::connect`.
pub struct LinkSessionConfig {
    pub destination_hash: [u8; 16],
    pub remote_public_key: [u8; 64],
    pub hops: u8,
    pub establishment_timeout: Duration,
    pub client_label: String,
    pub identify: bool,
    pub track_phy_stats: bool,
    /// Proof policy for inbound plain Link data. An initiator's Link destination
    /// is an OUT destination, which Python leaves at `PROVE_NONE`; `ProveApp`
    /// has no callback here and proves nothing.
    pub proof_strategy: ProofStrategy,
    /// Where file responses and Resources accepted to a file are written by
    /// default, as Reticulum.resourcepath; the system temp dir when unset.
    pub resource_dir: Option<PathBuf>,
    /// Largest advertised total size of an inbound Resource the session
    /// reassembles in memory; `None` reassembles any size. Spooled responses
    /// and Resources accepted with
    /// [`LinkSessionResourceOffer::accept_to_file`] are not bounded by it. See
    /// [`DEFAULT_INBOUND_REASSEMBLY_LIMIT`].
    pub inbound_reassembly_limit: Option<usize>,
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
            proof_strategy: ProofStrategy::ProveNone,
            resource_dir: None,
            inbound_reassembly_limit: Some(DEFAULT_INBOUND_REASSEMBLY_LIMIT),
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
/// Session observations. Packet and state events can backpressure the actor;
/// request/Resource lifecycle notifications use best-effort sends and may be
/// dropped if the event queue is full. Use returned request/Resource handles
/// for their terminal outcomes. `PacketDelivered` means a valid peer packet
/// proof, not application processing or durable storage.
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
/// Local send result for an ordinary packet. The endpoint accepted it as sent
/// or queued; this is not an on-air or peer-delivery acknowledgment. A later
/// `LinkSessionEvent::PacketDelivered` carries a verified peer proof.
pub struct LinkSessionPacketReceipt {
    pub link_id: [u8; 16],
    pub packet_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinkSessionResponse {
    pub request_id: [u8; 16],
    /// Byte view of the response: binary and string contents as-is, any other
    /// value re-encoded as MessagePack. For a file response, the file bytes,
    /// unless they were spooled to `file`.
    pub data: Vec<u8>,
    /// The response value as sent, e.g. `Value::Binary` for Python `bytes`.
    /// `Value::Nil` for a file response.
    pub value: rmpv::Value,
    /// Packed metadata of a file response; `None` for ordinary responses.
    pub metadata: Option<Vec<u8>>,
    /// Spooled response data: always for a file response (one with
    /// metadata), and for other Resource responses when
    /// [`RequestOptions::spool_dir`] is set. The caller owns and removes it.
    pub file: Option<PathBuf>,
    pub response_time: Duration,
    /// RequestReceipt.response_size: the advertised response data size.
    pub response_size: Option<u64>,
    /// RequestReceipt.response_transfer_size: bytes on the wire.
    pub response_transfer_size: Option<u64>,
    /// RequestReceipt.started_at: request sent, or request Resource delivered.
    pub started_at: Option<Instant>,
    /// RequestReceipt.response_concluded_at.
    pub response_concluded_at: Option<Instant>,
}

/// Options for [`LinkSessionHandle::request_with_options`], as the optional
/// arguments of Link.request.
#[derive(Debug, Clone, Default)]
pub struct RequestOptions {
    /// `None` selects the Link's RTT-based response timeout.
    pub timeout: Option<Duration>,
    /// Larger responses are rejected and fail the request.
    pub max_response_size: Option<usize>,
    /// Receives response Resource progress in `[0.0, 1.0]`.
    pub progress: Option<watch::Sender<f64>>,
    /// Directory for spooled responses. File responses are always spooled,
    /// by default to the system temporary directory; with this set, other
    /// Resource responses are spooled too instead of held in memory.
    pub spool_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Local sent-or-queued result for a Channel packet. The Channel continues
/// tracking proofs and retries after this return; this receipt does not
/// establish peer application consumption.
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
/// Successful outbound Resource conclusion after valid proofs for every
/// segment. This does not attest to remote file writes or durable storage.
pub struct LinkSessionResourceReceipt {
    pub link_id: [u8; 16],
    /// Logical hash: Python's `original_hash`.
    pub resource_id: [u8; 32],
    /// Hash of the final segment: Python's `get_hash()` in the concluded callback.
    pub last_segment_hash: [u8; 32],
    pub data_size: usize,
    pub total_segments: usize,
}

/// App-facing lifecycle handle for an outbound Link Resource.
///
/// The transfer itself remains owned by the Link session actor. Cloning the
/// progress receiver does not duplicate transfer state, and dropping this
/// handle does not implicitly cancel the transfer.
///
/// `cancel` reports whether the actor removed an active or queued transfer;
/// it does not confirm cancellation at the peer. Progress can reach its end
/// before final proof; use `concluded` for the protocol outcome.
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
    /// Set instead of `data` when a request response was spooled to disk or
    /// the offer was accepted with
    /// [`LinkSessionResourceOffer::accept_to_file`]. The receiver owns the
    /// file: move it or remove it.
    pub file: Option<PathBuf>,
    pub metadata: Option<Vec<u8>>,
    pub total_segments: usize,
    pub request_id: Option<Vec<u8>>,
    pub is_request: bool,
    pub is_response: bool,
}

/// An inbound Resource advertisement awaiting an application decision.
///
/// The actor keeps up to eight undecided offers. Its periodic timer rejects an
/// undecided offer once a Python sender would have stopped re-advertising a
/// request Resource; an occupied actor can delay that check.
/// Dropping an offer leaves this expiry in force and does not accept data.
/// Acceptance covers the logical transfer and valid follow-up segments.
/// Response Resources for pending requests are accepted internally, without an
/// offer. Inspect the advertised size before accepting: `accept` assembles the
/// data in memory, up to the session's in-memory limit, and `accept_to_file`
/// assembles any size into a file.
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

    /// Accept the Resource and receive its data in memory. An offer above
    /// [`LinkSessionConfig::inbound_reassembly_limit`] is rejected with
    /// [`LinkSessionResourceError::TooLarge`]; use [`Self::accept_to_file`].
    pub async fn accept(
        self,
    ) -> Result<LinkSessionInboundResourceHandle, LinkSessionResourceError> {
        self.accept_with(None).await
    }

    /// Accept the Resource into a file, whatever its size, as upstream
    /// assembles every Resource under `Reticulum.resourcepath` (Resource.py).
    /// The file is written in `dir`, or in the session's resource directory.
    /// Each verified segment is appended before its proof is sent, so one
    /// segment at a time is held in memory. `concluded` returns the path in
    /// [`LinkSessionReceivedResource::file`] with empty `data`; a transfer
    /// that fails, is cancelled or cannot be written leaves no file behind.
    pub async fn accept_to_file(
        self,
        dir: Option<PathBuf>,
    ) -> Result<LinkSessionInboundResourceHandle, LinkSessionResourceError> {
        self.accept_with(Some(dir)).await
    }

    async fn accept_with(
        self,
        file_dir: Option<Option<PathBuf>>,
    ) -> Result<LinkSessionInboundResourceHandle, LinkSessionResourceError> {
        let (progress_tx, progress_rx) = watch::channel(0.0);
        let (conclusion_tx, conclusion_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::Resource(
                LinkSessionResourceCommand::AcceptInbound {
                    segment_hash: self.segment_hash,
                    file_dir,
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

/// Lifecycle handle for an accepted inbound Resource. `concluded` returns the
/// complete payload, in memory or as a file, after assembly and local proof
/// admission; the application still owns processing and persistence. Dropping this handle
/// does not cancel reception. `cancel` returns whether a live logical transfer
/// was removed locally, not an acknowledgment from its sender. Progress is a
/// coalescing estimate; only `concluded` establishes success.
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
    #[error("resource control rejected: {0}")]
    Control(#[from] rns_protocol::resource::ResourceError),
    #[error("resource transfer failed: {0}")]
    Failed(String),
    #[error("resource of {size} bytes exceeds the {max}-byte limit")]
    TooLarge { size: u64, max: usize },
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
    #[error("link request admission failed: {0}")]
    RequestDispatch(#[from] rns_transport::link_messages::LinkRequestDispatchError),
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
    #[error("response of {size} bytes exceeds the {max}-byte limit")]
    ResponseRejected { size: u64, max: usize },
    #[error("Link session task is no longer running")]
    SessionClosed,
    #[error("link request stamp failed: {0}")]
    StampFailure(#[from] rns_link::stamp::LinkStampError),
}

enum LinkSessionCommand {
    SendPacket {
        payload: Vec<u8>,
        result_tx: oneshot::Sender<Result<LinkSessionPacketReceipt, LinkSessionError>>,
    },
    Request {
        path: String,
        data: rmpv::Value,
        options: RequestOptions,
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
    CloseWait {
        result_tx: oneshot::Sender<Result<(bool, Duration), LinkSessionChannelError>>,
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
        /// `Some` assembles into a file, in the given or the default directory.
        file_dir: Option<Option<PathBuf>>,
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
    /// The request timeout, re-applied while a split response waits for its
    /// next segment.
    timeout: Duration,
    result_tx: oneshot::Sender<Result<LinkSessionResponse, LinkSessionError>>,
    max_response_size: Option<usize>,
    progress_tx: Option<watch::Sender<f64>>,
    spool_dir: Option<PathBuf>,
    response_size: Option<u64>,
    response_transfer_size: Option<u64>,
    started_at: Option<Instant>,
}

impl PendingSessionRequest {
    fn new(
        result_tx: oneshot::Sender<Result<LinkSessionResponse, LinkSessionError>>,
        options: RequestOptions,
        timeout: Duration,
        sent_as_packet: bool,
    ) -> Self {
        let now = Instant::now();
        Self {
            sent_at: now,
            timeout,
            result_tx,
            max_response_size: options.max_response_size,
            progress_tx: options.progress,
            spool_dir: options.spool_dir,
            response_size: None,
            response_transfer_size: None,
            started_at: sent_as_packet.then_some(now),
        }
    }

    fn add_transfer_size(&mut self, size: usize) {
        let total = self.response_transfer_size.get_or_insert(0);
        *total = total.saturating_add(size as u64);
    }

    fn into_response(
        self,
        request_id: [u8; 16],
        body: ResponseBody,
    ) -> (
        oneshot::Sender<Result<LinkSessionResponse, LinkSessionError>>,
        LinkSessionResponse,
    ) {
        let response = LinkSessionResponse {
            request_id,
            data: body.data,
            value: body.value,
            metadata: body.metadata,
            file: body.file,
            response_time: self.sent_at.elapsed(),
            response_size: self.response_size,
            response_transfer_size: self.response_transfer_size,
            started_at: self.started_at,
            response_concluded_at: Some(Instant::now()),
        };
        (self.result_tx, response)
    }
}

struct ResponseBody {
    data: Vec<u8>,
    value: rmpv::Value,
    metadata: Option<Vec<u8>>,
    file: Option<PathBuf>,
}

/// A response written to disk by a blocking writer, so the actor never
/// touches the file. Dropping it ends the writer.
struct ResponseSpool {
    path: PathBuf,
    segments: std::sync::mpsc::Sender<Vec<u8>>,
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
    spool: Option<ResponseSpool>,
    /// The file of a Resource accepted to a file. Dropping it unfinished
    /// removes the partial file.
    file: Option<ResourceSpool>,
    /// Payload bytes assembled so far.
    received_bytes: usize,
    /// RequestReceipt.max_response_size, enforced on received bytes too.
    max_bytes: Option<usize>,
    /// When the last segment completed while more are due.
    segment_gap_since: Option<Instant>,
    /// Longest wait for the next segment's advertisement.
    segment_gap_timeout: Option<Duration>,
    /// Largest total of payload bytes accepted for this transfer.
    size_bound: usize,
}

struct InboundResourceLifecycle {
    progress_tx: watch::Sender<f64>,
    conclusion_tx: oneshot::Sender<Result<LinkSessionReceivedResource, LinkSessionResourceError>>,
    spool: Option<ResponseSpool>,
    /// Directory of a Resource accepted to a file.
    file_dir: Option<PathBuf>,
    max_bytes: Option<usize>,
    segment_gap_timeout: Option<Duration>,
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
    interface_owner: Option<rns_transport::messages::InterfaceOwnerId>,
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
    resource_dir: Option<PathBuf>,
    inbound_reassembly_limit: Option<usize>,
    /// Python `Link.last_resource_window` / `last_resource_eifr`.
    last_inbound: Option<(usize, Option<f64>)>,
}

struct SessionActorState {
    packets: HashSet<[u8; 32]>,
    requests: HashMap<[u8; 16], PendingSessionRequest>,
    channel: LinkChannel,
    /// Python `Link.get_channel()`: set by the first channel command.
    channel_open: bool,
    proof_strategy: ProofStrategy,
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

/// Cloneable handle to the session's reliable Channel. Sequencing, proofs,
/// retransmissions and callbacks run in the session actor. Register incoming
/// message types and a handler before expecting application delivery.
/// Callbacks run synchronously in registration order; returning true stops the
/// callback chain. They must not block or wait for another command on this
/// session. Peer packet proofs do not establish application consumption.
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

    /// True when the Channel's transmit ring is empty. Normal acknowledgments
    /// empty it, but `shutdown` also discards the ring. This result alone does
    /// not prove delivery or application consumption.
    pub async fn is_drained(&self) -> Result<bool, LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::IsDrained { result_tx })
            .await
    }

    /// Channel readiness and the Python Buffer close wait, `link.rtt * len(tx_ring)`.
    pub(crate) async fn close_wait(&self) -> Result<(bool, Duration), LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::CloseWait { result_tx })
            .await
    }

    /// Shut down this Channel and discard buffered messages and handlers.
    /// This does not drain delivery or close the containing Link session.
    pub async fn shutdown(&self) -> Result<(), LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::Shutdown { result_tx })
            .await
    }
}

#[derive(Clone)]
pub struct LinkSessionHandle {
    link_id: [u8; 16],
    mdu: usize,
    rtt: f64,
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

    /// Round-trip time in seconds measured when the link proof arrived.
    pub fn rtt(&self) -> f64 {
        self.rtt
    }

    /// Latest physical-layer measurements observed for this Link.
    ///
    /// Values remain empty unless tracking was enabled when the session was
    /// opened.
    pub fn phy_stats(&self) -> LinkPhyStats {
        *self.phy_stats_rx.borrow()
    }

    /// Subscribe to the latest physical-layer snapshot. Watch receivers may
    /// coalesce updates; this is not a record of every received packet.
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

    /// Encrypt and submit one ordinary packet within the Link MDU. The result
    /// is local sent-or-queued admission; observe packet proofs separately.
    /// This path does not retransmit ordinary packets automatically.
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

    /// Send a request and wait for its response. A packed request above the
    /// Link MDU uses a Resource; matching response Resources are accepted
    /// internally without an application Resource offer.
    ///
    /// `None` selects the Link's RTT-based response timeout. For a Resource
    /// request, that timeout starts after the request Resource is proved; it
    /// does not bound queueing, transfer or every transport wait. Apply a caller
    /// deadline when needed. Dropping this future does not cancel an admitted
    /// request or its remote work. At most 64 requests may be pending.
    /// `data` is sent as a byte string (Python `bytes`); use
    /// [`Self::request_with_options`] to send another MessagePack value.
    pub async fn request(
        &self,
        path: &str,
        data: &[u8],
        timeout: Option<Duration>,
    ) -> Result<LinkSessionResponse, LinkSessionError> {
        self.request_with_options(
            path,
            rmpv::Value::Binary(data.to_vec()),
            RequestOptions {
                timeout,
                ..RequestOptions::default()
            },
        )
        .await
    }

    /// Send a request whose data is packed by type, as Link.request packs
    /// `data` (`Value::Nil` for none), and wait for its response.
    ///
    /// Once a response Resource is accepted the request timeout no longer
    /// applies; the Resource's own watchdogs end a stalled transfer.
    pub async fn request_with_options(
        &self,
        path: &str,
        data: rmpv::Value,
        options: RequestOptions,
    ) -> Result<LinkSessionResponse, LinkSessionError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::Request {
                path: path.to_string(),
                data,
                options,
                result_tx,
            })
            .await
            .map_err(|_| LinkSessionError::SessionClosed)?;
        result_rx
            .await
            .map_err(|_| LinkSessionError::SessionClosed)?
    }

    /// Prepare and start or queue a Link Resource transfer. Source inspection
    /// and hashing run on the blocking pool before queue admission. The actor
    /// allows one active outbound Resource and up to eight queued Resources.
    ///
    /// Each queued transfer retains its source and first prepared segment.
    /// Later segments are read synchronously in the session actor after the
    /// previous segment is proved; use a stable, finite source whose reads do
    /// not stall the actor. This bounds segment buffering per transfer, not
    /// memory across concurrent preparation calls or caller-owned sources.
    /// Dropping the returned handle does not cancel the transfer; use its
    /// `cancel` and `concluded` methods for explicit lifecycle handling.
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

    /// Queue a request to close the session. Return does not wait for teardown,
    /// cleanup or the `Closed` event; it also hides an already-closed command
    /// channel. Continue draining events while waiting for closure.
    pub async fn close(&self) {
        let _ = self.command_tx.send(LinkSessionCommand::Close).await;
    }
}

/// Session handles and receive queues. The background actor retains its own
/// command sender, so dropping application handles alone does not reliably
/// stop it. Call `handle.close()` explicitly and keep draining `events`.
/// Ordinary inbound packets are proved before application event delivery;
/// this API does not provide application-controlled packet proof receipts.
pub struct LinkSession {
    pub handle: LinkSessionHandle,
    pub events: mpsc::Receiver<LinkSessionEvent>,
    pub resource_offers: mpsc::Receiver<LinkSessionResourceOffer>,
}

impl LinkSession {
    /// Establish a Link using the configured remote key and spawn its actor.
    /// No destination discovery is performed here. When `identify` is enabled,
    /// the local identity must be able to sign; success is not remote application
    /// authorization of that identity.
    ///
    /// The establishment timeout bounds request admission and proof waiting;
    /// generating a link request stamp is bounded by `lr_stamp_timeout` before it.
    /// Some transport operations and identification delays are outside it; use
    /// an outer timeout for a deadline on the entire call.
    pub async fn connect(
        transport_tx: mpsc::Sender<TransportMessage>,
        identity: Identity,
        config: LinkSessionConfig,
    ) -> Result<Self, LinkSessionError> {
        let (mut link, request_data) =
            crate::link_stamp::new_initiator(&transport_tx, config.destination_hash, config.hops)
                .await?;
        // Python starts the establishment watchdog after stamping (Link.py).
        let deadline = Instant::now()
            .checked_add(config.establishment_timeout)
            .ok_or_else(|| LinkSessionError::HandshakeFailed("unrepresentable timeout".into()))?;
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
        let mut registration = crate::link_endpoint::LinkEndpointCleanupGuard::new(
            transport_tx.clone(),
            link_id,
            LinkEndpointRole::Initiator,
        );

        let request = build_link_request_packet(config.destination_hash, &request_data);
        tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            rns_transport::link_messages::dispatch_link_request(
                &transport_tx,
                OutboundRequest {
                    raw: request,
                    destination_hash: config.destination_hash,
                },
            ),
        )
        .await
        .map_err(|_| LinkSessionError::Timeout("link request admission"))??;

        let peer_signing_key: [u8; 32] = config.remote_public_key[32..]
            .try_into()
            .map_err(|_| LinkSessionError::ProofInvalid("invalid public-key length".into()))?;
        let verify_key = Ed25519PublicKey::from_bytes(&peer_signing_key)
            .map_err(|error| LinkSessionError::ProofInvalid(error.to_string()))?;
        let proof = match tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            crate::link_endpoint::wait_for_valid_proof(
                &mut delivery_rx,
                &mut link,
                &verify_key,
                &peer_signing_key,
            ),
        )
        .await
        {
            Ok(Ok(proof)) => proof,
            Ok(Err(crate::link_endpoint::LinkProofWaitError::LinkClosed)) => {
                return Err(LinkSessionError::HandshakeFailed("Link closed".into()));
            }
            Ok(Err(crate::link_endpoint::LinkProofWaitError::DeliveryClosed)) => {
                return Err(LinkSessionError::HandshakeFailed(
                    "destination event stream closed".into(),
                ));
            }
            Err(_) => return Err(LinkSessionError::Timeout("link proof")),
        };
        let attached_interface = proof.interface_id;
        let interface_owner = proof.interface_owner;
        let rtt_data = proof.rtt_data;
        update_link_phy_stats(&mut link, proof.metrics);

        // The cryptographically valid LRPROOF's receiving interface is the
        // immutable egress attachment for this initiator endpoint. Install it
        // before LRRTT or any other established-Link packet can be emitted.
        let endpoint_lifecycle_rx = crate::link_endpoint::bind(
            &transport_tx,
            link_id,
            attached_interface,
            interface_owner,
            LinkEndpointRole::Initiator,
        )
        .await
        .map_err(|_| LinkSessionError::TransportUnavailable)?;
        registration.endpoint_bound();

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
            rtt: link.rtt_secs(),
            command_tx: command_tx.clone(),
            phy_stats_rx,
        };
        tokio::spawn(run_session_actor(
            (
                link,
                channel,
                config.proof_strategy,
                config.resource_dir,
                config.inbound_reassembly_limit,
            ),
            attached_interface,
            interface_owner,
            delivery_rx,
            endpoint_lifecycle_rx,
            command_rx,
            SessionActorChannels {
                transport_tx,
                command_tx,
                event_tx,
                resource_offer_tx,
                phy_stats_tx,
            },
            registration,
        ));

        Ok(Self {
            handle,
            events,
            resource_offers,
        })
    }
}

/// Resolve destination identity metadata, requesting a path if needed, then
/// read the announce-cache entry with its public key. Cache hits do not prove
/// current reachability or perform fresh signature verification. The final
/// cache lookup has no timeout; use an outer deadline to bound the whole call.
pub async fn discover_destination(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
    timeout: Duration,
) -> Result<AnnounceRpcEntry, LinkSessionError> {
    crate::destination_resolver::resolve_destination_on_transport(
        transport_tx,
        destination_hash,
        crate::destination_resolver::DestinationResolveOptions::new(timeout),
    )
    .await
    .map_err(|error| match error {
        crate::destination_resolver::DestinationResolveError::Timeout => {
            LinkSessionError::Timeout("destination identity")
        }
        crate::destination_resolver::DestinationResolveError::TransportUnavailable => {
            LinkSessionError::TransportUnavailable
        }
        crate::destination_resolver::DestinationResolveError::UnexpectedResponse(operation) => {
            LinkSessionError::HandshakeFailed(format!(
                "unexpected transport response during {operation}"
            ))
        }
    })?;
    let entry = lookup_destination(transport_tx, destination_hash)
        .await?
        .ok_or(LinkSessionError::PublicKeyUnavailable)?;
    if entry.public_key.is_none() {
        return Err(LinkSessionError::PublicKeyUnavailable);
    }
    Ok(entry)
}

/// Read matching metadata from the transport's recent-announce cache. This
/// issues no path request, performs no fresh signature verification, and has
/// no timeout of its own. `None` can also mean an unexpected RPC response.
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

#[allow(clippy::too_many_arguments)]
async fn run_session_actor(
    link_and_channel: (
        Link,
        LinkChannel,
        ProofStrategy,
        Option<PathBuf>,
        Option<usize>,
    ),
    attached_interface: InterfaceId,
    interface_owner: Option<rns_transport::messages::InterfaceOwnerId>,
    mut delivery_rx: mpsc::Receiver<DestinationEvent>,
    mut endpoint_lifecycle_rx: mpsc::UnboundedReceiver<
        rns_transport::messages::LinkEndpointLifecycleEvent,
    >,
    mut command_rx: mpsc::Receiver<LinkSessionCommand>,
    channels: SessionActorChannels,
    mut registration: crate::link_endpoint::LinkEndpointCleanupGuard,
) {
    let SessionActorChannels {
        transport_tx,
        command_tx,
        event_tx,
        resource_offer_tx,
        phy_stats_tx,
    } = channels;
    let (mut link, channel, proof_strategy, resource_dir, inbound_reassembly_limit) =
        link_and_channel;
    let link_id = link.link_id;
    let mut state = SessionActorState {
        packets: HashSet::new(),
        requests: HashMap::new(),
        channel,
        channel_open: false,
        proof_strategy,
        resources: SessionResources {
            resource_dir,
            inbound_reassembly_limit,
            ..SessionResources::default()
        },
    };
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut endpoint_closing = false;
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
                        options,
                        result_tx,
                    }) => {
                        if state.requests.len() >= MAX_PENDING_REQUESTS {
                            let _ = result_tx.send(Err(LinkSessionError::TooManyPendingRequests));
                            continue;
                        }
                        let timeout = options
                            .timeout
                            .unwrap_or_else(|| link.default_request_timeout());
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
                            Some(timeout),
                        ).await {
                            Ok((request_id, sent_as_packet)) => {
                                state.requests.insert(
                                    request_id,
                                    PendingSessionRequest::new(
                                        result_tx,
                                        options,
                                        timeout,
                                        sent_as_packet,
                                    ),
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
                            if let Some(pending) = state.requests.get_mut(&request_id) {
                                pending.started_at.get_or_insert_with(Instant::now);
                            }
                        }
                    }
                    Some(LinkSessionCommand::RequestResourceReceived {
                        request_id,
                        result,
                    }) => {
                        // Another response Resource for this request may still
                        // complete it, as response_resource_concluded allows.
                        if result.is_err()
                            && state.resources.inbound_logicals.values().any(|logical| {
                                logical.is_response
                                    && logical.request_id.as_deref() == Some(request_id.as_slice())
                            })
                        {
                            continue;
                        }
                        conclude_request_resource_response(
                            &mut link,
                            &mut state.requests,
                            &event_tx,
                            request_id,
                            result,
                        );
                    }
                    Some(LinkSessionCommand::Channel(command)) => {
                        state.channel_open = true;
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
                        endpoint_closing =
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
                        interface_owner,
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
            lifecycle = endpoint_lifecycle_rx.recv() => {
                match lifecycle {
                    Some(event) => {
                        tracing::warn!(
                            link_id = %hex::encode(event.binding.link_id),
                            interface_id = event.binding.interface_id,
                            reason = ?event.reason,
                            dropped_packets = event.dropped_packets,
                            "established Link endpoint became terminal"
                        );
                        break LinkSessionCloseReason::TransportUnavailable;
                    }
                    None => break LinkSessionCloseReason::TransportUnavailable,
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
                            endpoint_closing = send_local_teardown(
                                &transport_tx,
                                attached_interface,
                                &mut link,
                            )
                            .await;
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
                let was_active = link.state == LinkState::Active;
                let action = link.tick();
                if was_active && link.state == LinkState::Stale {
                    let _ = event_tx.send(LinkSessionEvent::Stale).await;
                }
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
                        if send_keepalive(&transport_tx, attached_interface, &mut link)
                            .await
                            .is_err()
                        {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    LinkAction::SendTeardownAndClose(data) => {
                        endpoint_closing = crate::link_endpoint::send_and_unbind(
                            &transport_tx,
                            link_id,
                            LinkEndpointRole::Initiator,
                            build_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &data),
                        ).await.is_ok();
                        break LinkSessionCloseReason::Timeout;
                    }
                    LinkAction::Closed(_) => break LinkSessionCloseReason::Timeout,
                    LinkAction::None => {}
                }
            }
        }
    };

    command_rx.close();
    while let Ok(command) = command_rx.try_recv() {
        discard_undelivered_spool(&command);
    }
    state.channel.shutdown();
    fail_pending_requests(&mut state.requests, &event_tx);
    fail_outbound_resources(&mut link, &mut state.resources, &event_tx);
    fail_inbound_resources(&mut link, &mut state.resources, &event_tx);
    if !endpoint_closing {
        let _ = registration.cleanup().await;
    } else {
        registration.disarm();
    }
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
        LinkSessionChannelCommand::CloseWait { result_tx } => {
            let wait = link.rtt_secs() * channel.outstanding_count() as f64;
            let wait = Duration::try_from_secs_f64(wait).unwrap_or(Duration::from_secs(15));
            let _ = result_tx.send(Ok((channel.is_ready_to_send(), wait)));
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
            let segment = match source.next_segment(&keys, rtt, link.resource_sdu()) {
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
            file_dir,
            progress_tx,
            conclusion_tx,
            result_tx,
        } => {
            let file_dir = file_dir
                .map(|dir| dir.unwrap_or_else(|| spool_dir(resources.resource_dir.as_deref())));
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
                    spool: None,
                    file_dir,
                    max_bytes: None,
                    segment_gap_timeout: None,
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
    outbound.transfer.advertisement_mdu = link.mdu;
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
        retry => match send_resource_action(transport_tx, attached_interface, link, retry.clone())
            .await
        {
            Ok(()) if matches!(retry, TransferAction::SendCancel(_, _)) => {
                let outbound = resources
                    .outbound
                    .take()
                    .expect("watchdog action requires an outbound resource");
                link.untrack_resource(&outbound.transfer.resource.resource_hash);
                let reason = outbound
                    .transfer
                    .failure_reason()
                    .unwrap_or("resource transfer failed")
                    .to_string();
                conclude_outbound_resource(
                    outbound,
                    event_tx,
                    Err(LinkSessionResourceError::Failed(reason)),
                );
                activate_next_queued(transport_tx, attached_interface, link, resources, event_tx)
                    .await
            }
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
            // Resource.cancel() sends ICL/RCL only on an active Link (Resource.py).
            if link.state != LinkState::Active {
                return Ok(());
            }
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
        TransferAction::QueryProofCache(proof_data) => {
            return transport_tx
                .send(TransportMessage::CacheRequest {
                    packet_hash: rns_protocol::resource::resource_proof_packet_hash(
                        &link.link_id,
                        &proof_data,
                    ),
                    destination_hash: link.link_id,
                })
                .await
                .map_err(|_| LinkSessionResourceError::TransportUnavailable);
        }
        TransferAction::None | TransferAction::Complete | TransferAction::Failed(_) => {
            return Ok(());
        }
    };
    rns_protocol::resource_control::check_control_frame(
        context,
        payload.len(),
        encrypted,
        rns_wire::constants::HEADER_MINSIZE,
        link.mtu as usize,
    )?;
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
    match outbound
        .source
        .next_segment(&keys, rtt, link.resource_sdu())
    {
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
                last_segment_hash: outbound.transfer.resource.resource_hash,
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
    link: &Link,
    previous: Option<(usize, Option<f64>)>,
) -> Result<InboundTransfer, LinkSessionResourceError> {
    let rtt = Duration::from_secs_f64(link.rtt_secs().max(0.001));
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
    InboundTransfer::from_advertisement_with_link(
        advertisement.num_parts,
        advertisement.transfer_size,
        advertisement.data_size,
        random_hash,
        advertisement.resource_hash,
        flags,
        advertisement.get_map_hashes(),
        rns_protocol::resource::InboundLinkFacts {
            rtt,
            establishment_cost: link.establishment_cost,
            previous_window: previous.map(|(window, _)| window),
            previous_eifr: previous.and_then(|(_, eifr)| eifr),
        },
    )
    .map(|mut transfer| {
        transfer.resource.sdu = link.resource_sdu();
        transfer
    })
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
    // Only a file can take a Resource above the in-memory limit.
    if lifecycle.spool.is_none()
        && lifecycle.file_dir.is_none()
        && let Some(max) = resources.inbound_reassembly_limit
        && advertisement.data_size > max
    {
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
        return Err(LinkSessionResourceError::TooLarge {
            size: advertisement.data_size as u64,
            max,
        });
    }

    let mut transfer =
        inbound_transfer_from_advertisement(&advertisement, link, resources.last_inbound)?;
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
    let file = lifecycle
        .file_dir
        .as_deref()
        .map(|dir| ResourceSpool::new(dir, &resource_id));
    let in_memory_limit = match (&lifecycle.spool, &file) {
        (None, None) => resources.inbound_reassembly_limit,
        _ => None,
    };
    let size_bound = advertisement
        .data_size
        .min(in_memory_limit.unwrap_or(usize::MAX));
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
            spool: lifecycle.spool,
            file,
            received_bytes: 0,
            max_bytes: lifecycle.max_bytes,
            segment_gap_since: None,
            segment_gap_timeout: lifecycle.segment_gap_timeout,
            size_bound,
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
    // A failed spool is removed by its writer's owner once the writer ends;
    // a failed file is removed when `logical` drops.
    let succeeded = result.is_ok();
    if let Err(Ok(received)) = logical.conclusion_tx.send(result)
        && let Some(path) = received.file
    {
        // The handle is gone, so nobody else can remove the file.
        let _ = std::fs::remove_file(path);
    }
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
    if let Some(max) = logical.max_bytes
        && advertisement.data_size > max
    {
        return Err(LinkSessionResourceError::TooLarge {
            size: advertisement.data_size as u64,
            max,
        });
    }

    let mut transfer =
        inbound_transfer_from_advertisement(&advertisement, link, resources.last_inbound)?;
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
        logical.segment_gap_since = None;
    }
    link.track_incoming_resource(segment_hash);
    Ok(())
}

async fn process_inbound_resource_advertisement(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    resources: &mut SessionResources,
    pending_requests: &mut HashMap<[u8; 16], PendingSessionRequest>,
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
    if inbound_transfer_from_advertisement(&advertisement, link, None).is_err() {
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
        if advertisement.flags.is_response
            && let Some(pending) = advertisement
                .request_id
                .as_deref()
                .and_then(|id| <[u8; 16]>::try_from(id).ok())
                .and_then(|id| pending_requests.get_mut(&id))
        {
            pending.add_transfer_size(advertisement.transfer_size);
        }
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
        let pending = pending_requests
            .get_mut(&request_id)
            .expect("pending request checked above");
        if let Some(max) = pending.max_response_size
            && advertisement.data_size > max
        {
            let size = advertisement.data_size as u64;
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
            tracing::debug!(size, max, "rejected response with excessive size");
            fail_session_request(
                link,
                pending_requests,
                sinks.event_tx,
                request_id,
                LinkSessionError::ResponseRejected { size, max },
            );
            return transport_failed;
        }
        if !link.mark_request_receiving(&request_id) {
            return false;
        }
        pending
            .response_size
            .get_or_insert(advertisement.data_size as u64);
        pending.add_transfer_size(advertisement.transfer_size);
        pending.started_at.get_or_insert_with(Instant::now);
        let progress_tx = pending
            .progress_tx
            .clone()
            .unwrap_or_else(|| watch::channel(0.0).0);
        // A file response is handed over as a file, as Resource.assemble does;
        // other responses are unpacked in memory unless a spool dir is given.
        let spool = pending
            .spool_dir
            .clone()
            .or_else(|| {
                advertisement
                    .flags
                    .has_metadata
                    .then(|| spool_dir(resources.resource_dir.as_deref()))
            })
            .and_then(|dir| open_response_spool(&dir, &resource_id));
        let (spool, writer) = match spool {
            Some((spool, writer)) => (Some(spool), Some(writer)),
            None => (None, None),
        };
        let spool_path = spool.as_ref().map(|spool| spool.path.clone());
        if spool.is_none()
            && let Some(max) = resources.inbound_reassembly_limit
            && advertisement.data_size > max
        {
            let size = advertisement.data_size as u64;
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
            tracing::debug!(
                size,
                max,
                "rejected response above the inbound reassembly limit"
            );
            fail_session_request(
                link,
                pending_requests,
                sinks.event_tx,
                request_id,
                LinkSessionError::ResponseRejected { size, max },
            );
            return transport_failed;
        }
        let max_bytes = pending.max_response_size;
        let segment_gap_timeout = Some(pending.timeout);

        resources.pending_inbound.insert(
            segment_hash,
            PendingInboundResourceOffer {
                advertisement,
                offered_at: Instant::now(),
            },
        );
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
                spool,
                file_dir: None,
                max_bytes,
                segment_gap_timeout,
            },
        )
        .await;
        let completion_tx = sinks.command_tx.clone();
        tokio::spawn(async move {
            let result = conclusion_rx
                .await
                .unwrap_or(Err(LinkSessionResourceError::SessionClosed));
            let result = finish_response_spool(result, writer, spool_path).await;
            if let Err(mpsc::error::SendError(command)) = completion_tx
                .send(LinkSessionCommand::RequestResourceReceived { request_id, result })
                .await
            {
                discard_undelivered_spool(&command);
            }
        });
        return matches!(result, Err(LinkSessionResourceError::TransportUnavailable));
    }

    // An offer above the in-memory limit still reaches the application,
    // which can take it as a file.
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
    let completion = inbound.transfer.complete(Some(&decrypt));
    // Link.resource_concluded (Link.py).
    resources.last_inbound = Some((
        inbound.transfer.resource.window.window,
        inbound.transfer.eifr,
    ));
    link.resource_concluded(
        inbound.transfer.resource.total_size,
        inbound.transfer.started_at.elapsed().as_secs_f64(),
        true,
    );
    let (data, proof) = match completion {
        Ok(completed) => completed,
        Err(error) => {
            // Only a decompression overflow is rejected and tears the Link
            // down; a corrupt assembly sends nothing (Resource.py).
            let reject = matches!(
                error,
                rns_protocol::resource::ResourceError::DecompressedTooLarge
            );
            let transport_failed = reject
                && matches!(
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
            if reject {
                send_local_teardown(transport_tx, attached_interface, link).await;
                return true;
            }
            return transport_failed;
        }
    };
    let metadata = inbound.transfer.resource.metadata.clone();
    let metadata_size = metadata.as_ref().map_or(0, |metadata| 3 + metadata.len());
    let overflow = resources
        .inbound_logicals
        .get(&resource_id)
        .and_then(|logical| {
            let received = logical
                .received_bytes
                .saturating_add(data.len())
                .saturating_add(metadata_size);
            (received > logical.size_bound).then(|| match logical.max_bytes {
                Some(max) if received > max => LinkSessionResourceError::TooLarge {
                    size: received as u64,
                    max,
                },
                _ => LinkSessionResourceError::Failed("received more data than advertised".into()),
            })
        });
    if let Some(error) = overflow {
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
        fail_inbound_logical(link, resources, event_tx, resource_id, error);
        return transport_failed;
    }
    // Resource.assemble writes the segment before Resource.prove: a failed
    // write sends neither a proof nor a cancel, and the Link stays up.
    let segment_len = data.len();
    let data = match resources
        .inbound_logicals
        .get_mut(&resource_id)
        .and_then(|logical| logical.file.as_mut())
    {
        Some(file) => {
            if let Err(error) = file.append(&data) {
                tracing::error!(%error, "could not write received Resource data");
                fail_inbound_logical(
                    link,
                    resources,
                    event_tx,
                    resource_id,
                    LinkSessionResourceError::Failed(format!(
                        "could not write Resource data: {error}"
                    )),
                );
                return false;
            }
            Vec::new()
        }
        None => data,
    };
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
        logical.received_bytes = logical
            .received_bytes
            .saturating_add(segment_len)
            .saturating_add(metadata_size);
        if let Some(max) = logical.max_bytes
            && logical.received_bytes > max
        {
            let size = logical.received_bytes as u64;
            tracing::debug!(size, max, "rejected response with excessive received size");
            fail_inbound_logical(
                link,
                resources,
                event_tx,
                resource_id,
                LinkSessionResourceError::TooLarge { size, max },
            );
            return false;
        }
        // A spooled response keeps only segment order in memory.
        let data = match logical.spool.as_ref() {
            Some(spool) => {
                if spool.segments.send(data).is_err() {
                    coordinator_error = Some("response spool writer stopped".to_string());
                }
                Vec::new()
            }
            None => data,
        };
        if coordinator_error.is_some() {
        } else if let Some(coordinator) = logical.coordinator.as_mut() {
            if let Err(error) = coordinator.set_segment_data(segment_index, data) {
                coordinator_error = Some(error.to_string());
            } else {
                if let Some(metadata) = metadata {
                    coordinator.set_metadata(metadata);
                }
                if coordinator.is_complete() {
                    match coordinator.take_reassembled() {
                        Ok(data) => {
                            complete_data = Some(data);
                            complete_metadata = coordinator.metadata.take();
                        }
                        Err(error) => coordinator_error = Some(error.to_string()),
                    }
                } else {
                    logical.segment_gap_since = Some(Instant::now());
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
    let Some(logical) = resources.inbound_logicals.get_mut(&resource_id) else {
        return false;
    };
    let file = match logical.file.take() {
        Some(file) => Some(file.finish().0),
        None => logical.spool.as_ref().map(|spool| spool.path.clone()),
    };
    let received = LinkSessionReceivedResource {
        link_id: link.link_id,
        resource_id,
        data,
        file,
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
        | TransferAction::SendProof(_)
        | TransferAction::QueryProofCache(_) => {}
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

async fn handle_inbound_resource_cancel(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
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
    // Link.py runs Resource.cancel(), which answers with RCL.
    let action = inbound.transfer.cancel();
    let resource_id = inbound.resource_id;
    let _ = send_resource_action(transport_tx, attached_interface, link, action).await;
    remove_inbound_segments(link, resources, resource_id);
    conclude_inbound_resource(
        resources,
        event_tx,
        resource_id,
        Err(LinkSessionResourceError::Cancelled),
    );
}

/// Advertisement lifetime of a Python request Resource: its timeout is the
/// request timeout, retried `MAX_ADV_RETRIES` times after the first attempt.
fn resource_offer_timeout(link: &Link) -> Duration {
    let attempt = link.rtt_secs() * rns_link::constants::TRAFFIC_TIMEOUT_FACTOR
        + rns_link::constants::RESPONSE_MAX_GRACE_TIME * 1.125
        + rns_protocol::resource::PROCESSING_GRACE;
    Duration::from_secs_f64(attempt * (rns_protocol::resource::MAX_ADV_RETRIES + 1) as f64)
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

    let offer_timeout = resource_offer_timeout(link);
    let expired_offers: Vec<[u8; 32]> = resources
        .pending_inbound
        .iter()
        .filter_map(|(segment_hash, pending)| {
            (pending.offered_at.elapsed() >= offer_timeout).then_some(*segment_hash)
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

    // A sender that stops between segments of a split response: no Resource
    // watchdog runs then, so the request timeout bounds each gap.
    let stalled: Vec<[u8; 32]> = resources
        .inbound_logicals
        .iter()
        .filter_map(|(resource_id, logical)| {
            let since = logical.segment_gap_since?;
            (since.elapsed() > logical.segment_gap_timeout?).then_some(*resource_id)
        })
        .collect();
    for resource_id in stalled {
        fail_inbound_logical(
            link,
            resources,
            event_tx,
            resource_id,
            LinkSessionResourceError::Failed("next response segment was not advertised".into()),
        );
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
    if link.state != LinkState::Active {
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
    data: &rmpv::Value,
    timeout: Option<Duration>,
) -> Result<([u8; 16], bool), LinkSessionError> {
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
        .prepare_request_value(path, data, timeout)
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
        let mut segment = source
            .next_segment(&keys, rtt, link.resource_sdu())
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
        // Link.request passes its timeout to the request Resource.
        segment.transfer.advertisement_timeout = Some(timeout);
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
        return Ok((initial_request_id, false));
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
    Ok((request_id, true))
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
        remove_spooled_response(&result);
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
            remove_spooled_response(&result);
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
        Err(LinkSessionResourceError::TooLarge { size, max }) => {
            fail_session_request(
                link,
                pending_requests,
                event_tx,
                request_id,
                LinkSessionError::ResponseRejected { size, max },
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

    let body = if received.metadata.is_some() {
        // Link.response_resource_concluded: metadata marks a file response.
        ResponseBody {
            data: received.data,
            value: rmpv::Value::Nil,
            metadata: received.metadata,
            file: received.file,
        }
    } else {
        // A spooled response was read back off the actor.
        let packed = received.data;
        let Ok((packed_request_id, value)) = Link::parse_response_value(&packed) else {
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
        ResponseBody {
            data: rns_link::link::value_bytes_view(&value).unwrap_or_default(),
            value,
            metadata: None,
            file: None,
        }
    };

    deliver_session_response(link, pending_requests, event_tx, request_id, body);
}

/// Link.handle_response for a single-packet response, with the
/// max_response_size check applied to `len(packb(response)) - 2`.
fn conclude_packet_response(
    link: &mut Link,
    pending_requests: &mut HashMap<[u8; 16], PendingSessionRequest>,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    request_id: [u8; 16],
    value: rmpv::Value,
) {
    let Some(pending) = pending_requests.get_mut(&request_id) else {
        return;
    };
    let mut packed = Vec::new();
    let _ = rmpv::encode::write_value(&mut packed, &value);
    let size = packed.len().saturating_sub(2);
    pending.response_size = Some(size as u64);
    pending.add_transfer_size(size);
    if let Some(max) = pending.max_response_size
        && size > max
    {
        tracing::debug!(size, max, "rejected response with excessive size");
        fail_session_request(
            link,
            pending_requests,
            event_tx,
            request_id,
            LinkSessionError::ResponseRejected {
                size: size as u64,
                max,
            },
        );
        return;
    }
    let body = ResponseBody {
        data: rns_link::link::value_bytes_view(&value).unwrap_or_default(),
        value,
        metadata: None,
        file: None,
    };
    deliver_session_response(link, pending_requests, event_tx, request_id, body);
}

fn deliver_session_response(
    link: &mut Link,
    pending_requests: &mut HashMap<[u8; 16], PendingSessionRequest>,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    request_id: [u8; 16],
    body: ResponseBody,
) {
    // The response goes to the caller directly; the receipt keeps no copy.
    if !link.deliver_response_data(&request_id, Vec::new()) {
        if let Some(path) = &body.file {
            let _ = std::fs::remove_file(path);
        }
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
        if let Some(path) = &body.file {
            let _ = std::fs::remove_file(path);
        }
        return;
    };
    if let Some(progress_tx) = &pending.progress_tx {
        progress_tx.send_replace(1.0);
    }
    let (result_tx, response) = pending.into_response(request_id, body);
    if let Err(Ok(response)) = result_tx.send(Ok(response))
        && let Some(path) = response.file
    {
        // The requester is gone, so nobody else can remove the file.
        let _ = std::fs::remove_file(path);
    }
    let _ = event_tx.try_send(LinkSessionEvent::RequestConcluded {
        request_id,
        succeeded: true,
    });
}

type SpoolWriter = oneshot::Receiver<std::io::Result<()>>;

fn open_response_spool(
    dir: &std::path::Path,
    resource_id: &[u8; 32],
) -> Option<(ResponseSpool, SpoolWriter)> {
    // The id is chosen by the peer and the directory may be shared: never
    // reuse or follow an existing entry.
    let nonce = rns_crypto::random::random_bytes(8);
    let path = dir.join(format!(
        "{}-{}",
        hex::encode(resource_id),
        hex::encode(nonce)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = match options.open(&path) {
        Ok(file) => file,
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "response spool unavailable; receiving in memory");
            return None;
        }
    };
    let (segments, segment_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (written_tx, written) = oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let mut result = Ok(());
        for segment in segment_rx {
            if result.is_ok() {
                result = file.write_all(&segment);
            }
        }
        let _ = written_tx.send(result);
    });
    Some((ResponseSpool { path, segments }, written))
}

/// Wait for the spool writer, then hand over the file, read a spooled
/// MessagePack response back into memory, or remove a failed spool. The file
/// work runs on the blocking pool.
async fn finish_response_spool(
    result: Result<LinkSessionReceivedResource, LinkSessionResourceError>,
    writer: Option<SpoolWriter>,
    path: Option<PathBuf>,
) -> Result<LinkSessionReceivedResource, LinkSessionResourceError> {
    let (Some(writer), Some(path)) = (writer, path) else {
        return result;
    };
    let written = writer
        .await
        .unwrap_or_else(|_| Err(std::io::Error::other("response spool writer stopped")));
    let result = match (result, written) {
        (Ok(_), Err(error)) => Err(LinkSessionResourceError::Failed(format!(
            "response spool write failed: {error}"
        ))),
        (result, _) => result,
    };
    tokio::task::spawn_blocking(move || match result {
        Ok(mut received) if received.metadata.is_none() => {
            let read = std::fs::read(&path);
            let _ = std::fs::remove_file(&path);
            received.data = read.map_err(|error| {
                LinkSessionResourceError::Failed(format!("response spool read failed: {error}"))
            })?;
            received.file = None;
            Ok(received)
        }
        Ok(received) => Ok(received),
        Err(error) => {
            let _ = std::fs::remove_file(&path);
            Err(error)
        }
    })
    .await
    .unwrap_or(Err(LinkSessionResourceError::SessionClosed))
}

fn remove_spooled_response(result: &Result<LinkSessionReceivedResource, LinkSessionResourceError>) {
    if let Ok(received) = result
        && let Some(path) = &received.file
    {
        let _ = std::fs::remove_file(path);
    }
}

fn discard_undelivered_spool(command: &LinkSessionCommand) {
    if let LinkSessionCommand::RequestResourceReceived { result, .. } = command {
        remove_spooled_response(result);
    }
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
        interface_owner: expected_owner,
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
            interface_owner,
            metrics,
        } => {
            // Python pins an established Link to the interface that delivered
            // its proof. Accepting Link traffic from another interface would
            // both break route affinity and permit cross-interface injection.
            if interface_id != attached_interface || interface_owner != expected_owner {
                return Ok(None);
            }
            let Ok((header, data_offset)) = rns_wire::header::PacketHeader::unpack(&raw) else {
                return Ok(None);
            };
            if header.destination_hash != link.link_id || raw.len() < data_offset {
                return Ok(None);
            }
            if header.context != rns_wire::context::PacketContext::Keepalive {
                link.record_inbound_data();
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
                    if link.validate_peer_packet_proof(&packet_hash, body).is_ok() {
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
                // Link.py applies LRRTT only on the responder; initiators just count it.
                rns_wire::context::PacketContext::Lrrtt => {
                    link.record_inbound();
                    link.record_rx(body.len());
                }
                rns_wire::context::PacketContext::Response => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    if let Ok(plaintext) = link.decrypt(body)
                        && let Ok((request_id, value)) = Link::parse_response_value(&plaintext)
                        && state.requests.contains_key(&request_id)
                    {
                        conclude_packet_response(
                            link,
                            &mut state.requests,
                            event_tx,
                            request_id,
                            value,
                        );
                    }
                }
                rns_wire::context::PacketContext::None => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    let Ok(plaintext) = link.decrypt(body) else {
                        return Ok(None);
                    };
                    let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);
                    if state.proof_strategy == ProofStrategy::ProveAll {
                        send_packet_proof(transport_tx, attached_interface, link, &packet_hash)
                            .await?;
                    }
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
                    if !state.channel_open {
                        tracing::debug!(
                            link_id = hex::encode(link.link_id),
                            "channel data received without open channel"
                        );
                        return Ok(None);
                    }
                    let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);
                    send_packet_proof(transport_tx, attached_interface, link, &packet_hash).await?;
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
                        &mut state.requests,
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
                    handle_inbound_resource_cancel(
                        transport_tx,
                        attached_interface,
                        link,
                        &mut state.resources,
                        event_tx,
                        body,
                    )
                    .await;
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
    link: &mut Link,
    packet_hash: &[u8; 32],
) -> Result<(), LinkSessionError> {
    let Ok(proof) = link.prove_packet_with_local_signer(packet_hash) else {
        return Ok(());
    };
    let proof_raw =
        build_proof_packet(link.link_id, rns_wire::context::PacketContext::None, &proof);
    send_raw(transport_tx, attached_interface, link.link_id, proof_raw).await?;
    link.record_tx(proof.len());
    Ok(())
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
    _attached_interface: InterfaceId,
    link: &mut Link,
) -> bool {
    let link_id = link.link_id;
    let Some(data) = link.teardown(CloseReason::InitiatorClosed) else {
        return false;
    };
    crate::link_endpoint::send_and_unbind(
        transport_tx,
        link_id,
        LinkEndpointRole::Initiator,
        build_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &data),
    )
    .await
    .is_ok()
}

async fn send_raw(
    transport_tx: &mpsc::Sender<TransportMessage>,
    _attached_interface: InterfaceId,
    destination_hash: [u8; 16],
    raw: Bytes,
) -> Result<(), LinkSessionError> {
    crate::link_endpoint::send(
        transport_tx,
        destination_hash,
        LinkEndpointRole::Initiator,
        raw,
    )
    .await
    .map_err(|_| LinkSessionError::TransportUnavailable)
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

    fn test_transport_channel(
        capacity: usize,
    ) -> (
        mpsc::Sender<TransportMessage>,
        mpsc::Receiver<TransportMessage>,
    ) {
        let (transport_tx, mut transport_rx) = mpsc::channel(capacity);
        let (observed_tx, observed_rx) = mpsc::channel(capacity);
        tokio::spawn(async move {
            while let Some(message) = transport_rx.recv().await {
                let observed = match message {
                    TransportMessage::SendLinkRequest { request, result_tx } => {
                        let _ = result_tx.send(Ok(()));
                        TransportMessage::Outbound(request)
                    }
                    TransportMessage::SendLinkEndpoint {
                        link_id,
                        role,
                        request,
                        result_tx,
                    } => {
                        let _ =
                            result_tx.send(rns_transport::messages::LinkEndpointSendResult::Sent);
                        let (result_tx, _result_rx) = oneshot::channel();
                        TransportMessage::SendLinkEndpoint {
                            link_id,
                            role,
                            request,
                            result_tx,
                        }
                    }
                    TransportMessage::SendLinkEndpointAndUnbind {
                        link_id,
                        role,
                        request,
                        result_tx,
                    } => {
                        let _ =
                            result_tx.send(rns_transport::messages::LinkEndpointSendResult::Sent);
                        let (result_tx, _result_rx) = oneshot::channel();
                        TransportMessage::SendLinkEndpointAndUnbind {
                            link_id,
                            role,
                            request,
                            result_tx,
                        }
                    }
                    TransportMessage::UnbindLinkEndpoint {
                        link_id,
                        role,
                        result_tx,
                    } => {
                        let _ = result_tx
                            .send(rns_transport::messages::LinkEndpointUnbindResult::Unbound);
                        let (result_tx, _result_rx) = oneshot::channel();
                        TransportMessage::UnbindLinkEndpoint {
                            link_id,
                            role,
                            result_tx,
                        }
                    }
                    message => message,
                };
                if observed_tx.send(observed).await.is_err() {
                    break;
                }
            }
        });
        (transport_tx, observed_rx)
    }

    async fn next_initiator_endpoint(rx: &mut mpsc::Receiver<TransportMessage>) -> OutboundRequest {
        loop {
            match rx.recv().await.expect("transport channel closed") {
                TransportMessage::BindLinkEndpoint {
                    binding,
                    lifecycle_tx,
                    result_tx,
                } => {
                    assert_eq!(binding.role, LinkEndpointRole::Initiator);
                    let _ = result_tx.send(rns_transport::messages::LinkEndpointBindResult::Bound);
                    std::mem::forget(lifecycle_tx);
                }
                TransportMessage::SendLinkEndpoint {
                    role,
                    request,
                    result_tx,
                    ..
                }
                | TransportMessage::SendLinkEndpointAndUnbind {
                    role,
                    request,
                    result_tx,
                    ..
                } => {
                    assert_eq!(role, LinkEndpointRole::Initiator);
                    let _ = result_tx.send(rns_transport::messages::LinkEndpointSendResult::Sent);
                    return request;
                }
                message => panic!("unexpected transport message: {message:?}"),
            }
        }
    }

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
                initiator.resource_sdu(),
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
                offered_at: Instant::now() - resource_offer_timeout(&initiator),
            },
        );
        let (transport_tx, mut transport_rx) = test_transport_channel(1);
        let (event_tx, _event_rx) = mpsc::channel::<LinkSessionEvent>(1);

        assert!(
            !poll_inbound_resources(&transport_tx, 7, &mut initiator, &mut resources, &event_tx,)
                .await
        );
        assert!(resources.pending_inbound.is_empty());
        assert!(resources.rejected_inbound.contains_key(&resource_id));

        let rejection = next_initiator_endpoint(&mut transport_rx).await;
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

    /// An ordinary inbound Resource of `data` advertising `advertised` bytes,
    /// offered to a session with the given reassembly limit and accepted when
    /// offered, into a file when `file_dir` is given. Returns the control
    /// packet contexts sent and the conclusion, or why it was not accepted.
    async fn drive_session_inbound(
        data: Vec<u8>,
        advertised: usize,
        limit: Option<usize>,
        file_dir: Option<PathBuf>,
    ) -> (
        Vec<rns_wire::context::PacketContext>,
        Option<Result<LinkSessionReceivedResource, LinkSessionResourceError>>,
    ) {
        let destination_hash = [0xAE; 16];
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
            data,
            false,
            Duration::from_secs_f64(responder.rtt_secs().max(0.001)),
            responder.session_keys().unwrap(),
        )
        .unwrap();
        sender.resource.advertisement_data_size = advertised;
        let TransferAction::SendAdvertisement(advertisement) = sender.tick() else {
            panic!("expected an advertisement");
        };
        let segment_hash = sender.resource.resource_hash;

        let mut resources = SessionResources {
            inbound_reassembly_limit: limit,
            ..Default::default()
        };
        let mut pending_requests = HashMap::new();
        let (transport_tx, mut transport_rx) = test_transport_channel(16);
        let (command_tx, _command_rx) = mpsc::channel::<LinkSessionCommand>(8);
        let (event_tx, _event_rx) = mpsc::channel::<LinkSessionEvent>(16);
        let (offer_tx, mut offer_rx) = mpsc::channel::<LinkSessionResourceOffer>(1);
        process_inbound_resource_advertisement(
            &transport_tx,
            1,
            &mut initiator,
            &mut resources,
            &mut pending_requests,
            InboundResourceSinks {
                event_tx: &event_tx,
                command_tx: &command_tx,
                offer_tx: &offer_tx,
            },
            &responder.encrypt(&advertisement).unwrap(),
        )
        .await;

        let mut conclusion = None;
        if offer_rx.try_recv().is_ok() {
            let (progress_tx, _progress_rx) = watch::channel(0.0);
            let (conclusion_tx, mut conclusion_rx) = oneshot::channel();
            let accepted = accept_inbound_offer(
                &transport_tx,
                1,
                &mut initiator,
                &mut resources,
                &event_tx,
                segment_hash,
                InboundResourceLifecycle {
                    progress_tx,
                    conclusion_tx,
                    spool: None,
                    file_dir,
                    max_bytes: None,
                    segment_gap_timeout: None,
                },
            )
            .await;
            match accepted {
                Ok(()) => {
                    for part in sender.resource.parts.clone() {
                        handle_inbound_resource_part(
                            &transport_tx,
                            1,
                            &mut initiator,
                            &mut resources,
                            &event_tx,
                            &part,
                        )
                        .await;
                    }
                    conclusion = conclusion_rx.try_recv().ok();
                }
                Err(error) => conclusion = Some(Err(error)),
            }
        }
        drop(transport_tx);
        let mut contexts = Vec::new();
        while let Ok(Some(message)) =
            tokio::time::timeout(Duration::from_millis(200), transport_rx.recv()).await
        {
            match message {
                TransportMessage::BindLinkEndpoint {
                    lifecycle_tx,
                    result_tx,
                    ..
                } => {
                    let _ = result_tx.send(rns_transport::messages::LinkEndpointBindResult::Bound);
                    std::mem::forget(lifecycle_tx);
                }
                TransportMessage::SendLinkEndpoint {
                    request, result_tx, ..
                }
                | TransportMessage::SendLinkEndpointAndUnbind {
                    request, result_tx, ..
                } => {
                    let _ = result_tx.send(rns_transport::messages::LinkEndpointSendResult::Sent);
                    contexts.push(
                        rns_wire::header::PacketHeader::unpack(&request.raw)
                            .unwrap()
                            .0
                            .context,
                    );
                }
                _ => {}
            }
        }
        (contexts, conclusion)
    }

    #[tokio::test]
    async fn inbound_resource_above_session_reassembly_limit_needs_a_file() {
        let data = vec![0x5C; 4000];
        let limit = Some(data.len() - 1);
        let (contexts, conclusion) =
            drive_session_inbound(data.clone(), data.len(), limit, None).await;
        assert_eq!(
            contexts,
            vec![rns_wire::context::PacketContext::ResourceRcl]
        );
        assert!(
            matches!(
                conclusion,
                Some(Err(LinkSessionResourceError::TooLarge {
                    size: 4000,
                    max: 3999
                }))
            ),
            "accepting into memory above the limit is refused: {conclusion:?}"
        );

        let (_, conclusion) = drive_session_inbound(data.clone(), data.len(), None, None).await;
        assert_eq!(conclusion.unwrap().unwrap().data, data);

        let dir = tempfile::tempdir().unwrap();
        let (contexts, conclusion) =
            drive_session_inbound(data.clone(), data.len(), limit, Some(dir.path().into())).await;
        assert_eq!(
            contexts.last(),
            Some(&rns_wire::context::PacketContext::ResourcePrf)
        );
        let received = conclusion.unwrap().unwrap();
        assert!(received.data.is_empty());
        let path = received
            .file
            .expect("the Resource is handed over as a file");
        assert!(path.starts_with(dir.path()));
        assert!(std::fs::read(&path).unwrap() == data);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn inbound_resource_accepted_to_a_file_leaves_nothing_behind_on_failure() {
        let data = vec![0x5E; 4000];

        // More data than advertised: cancelled, not proved.
        let dir = tempfile::tempdir().unwrap();
        let (contexts, conclusion) =
            drive_session_inbound(data.clone(), 3999, Some(0), Some(dir.path().into())).await;
        assert!(matches!(
            conclusion,
            Some(Err(LinkSessionResourceError::Failed(_)))
        ));
        assert!(!contexts.contains(&rns_wire::context::PacketContext::ResourcePrf));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        // A directory that cannot be written: Resource.assemble marks the
        // Resource corrupt, which sends neither a proof nor a cancel.
        let missing = dir.path().join("absent");
        let (contexts, conclusion) =
            drive_session_inbound(data.clone(), data.len(), Some(0), Some(missing)).await;
        assert!(matches!(
            conclusion,
            Some(Err(LinkSessionResourceError::Failed(_)))
        ));
        assert!(
            contexts
                .iter()
                .all(|context| *context == rns_wire::context::PacketContext::ResourceReq),
            "only part requests are sent: {contexts:?}"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        // The handle is gone before the transfer ends: nobody can take the file.
        let (progress_tx, _progress_rx) = watch::channel(0.0);
        let (conclusion_tx, conclusion_rx) = oneshot::channel();
        drop(conclusion_rx);
        let mut file = ResourceSpool::new(dir.path(), &[9; 32]);
        file.append(&data).unwrap();
        let path = file.finish().0;
        let mut resources = SessionResources::default();
        resources.inbound_logicals.insert(
            [9; 32],
            SessionInboundLogical {
                data_size: data.len(),
                total_segments: 1,
                request_id: None,
                is_request: false,
                is_response: false,
                progress_tx,
                conclusion_tx,
                coordinator: None,
                current_segment: None,
                reported_bytes: 0,
                reported_progress: 0.0,
                spool: None,
                file: None,
                received_bytes: 0,
                max_bytes: None,
                segment_gap_since: None,
                segment_gap_timeout: None,
                size_bound: data.len(),
            },
        );
        let (event_tx, _event_rx) = mpsc::channel(4);
        conclude_inbound_resource(
            &mut resources,
            &event_tx,
            [9; 32],
            Ok(LinkSessionReceivedResource {
                link_id: [0; 16],
                resource_id: [9; 32],
                data: Vec::new(),
                file: Some(path.clone()),
                metadata: None,
                total_segments: 1,
                request_id: None,
                is_request: false,
                is_response: false,
            }),
        );
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn inbound_resource_sending_more_than_advertised_is_cut_off() {
        let data = vec![0x5D; 4000];
        let (contexts, conclusion) = drive_session_inbound(data, 3999, None, None).await;
        assert!(matches!(
            conclusion,
            Some(Err(LinkSessionResourceError::Failed(_)))
        ));
        assert_eq!(
            contexts.last(),
            Some(&rns_wire::context::PacketContext::ResourceRcl)
        );
        assert!(!contexts.contains(&rns_wire::context::PacketContext::ResourcePrf));
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

        let (transport_tx, mut transport_rx) = test_transport_channel(1);
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

        let sent = next_initiator_endpoint(&mut transport_rx).await;
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
        let (transport_tx, mut transport_rx) = test_transport_channel(1);
        let (event_tx, _event_rx) = mpsc::channel::<LinkSessionEvent>(4);
        let (command_tx, _command_rx) = mpsc::channel::<LinkSessionCommand>(4);
        let mut resources = SessionResources::default();

        let (request_id, _) = send_link_request(
            SessionRequestContext {
                transport_tx: &transport_tx,
                attached_interface: 1,
                link: &mut initiator,
                resources: &mut resources,
                event_tx: &event_tx,
                command_tx: &command_tx,
            },
            "/large",
            &rmpv::Value::Binary(payload.clone()),
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();
        assert_eq!(initiator.pending_requests.len(), 1);
        assert_eq!(
            initiator.pending_requests[0].state,
            rns_link::request::RequestState::SendingResource
        );

        let advertisement = next_initiator_endpoint(&mut transport_rx).await;
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
            .prepare_request_value(
                "/large-response",
                &rmpv::Value::Binary(Vec::new()),
                Duration::from_secs(5),
            )
            .unwrap();
        let (result_tx, result_rx) = oneshot::channel();
        let mut pending_requests = HashMap::from([(
            request_id,
            PendingSessionRequest::new(
                result_tx,
                RequestOptions::default(),
                Duration::from_secs(5),
                true,
            ),
        )]);

        let packed_response = Link::pack_response_value(
            &request_id,
            &rmpv::Value::Binary(b"resource response".to_vec()),
        )
        .unwrap();
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
        let (transport_tx, mut transport_rx) = test_transport_channel(8);
        let (command_tx, mut command_rx) = mpsc::channel::<LinkSessionCommand>(8);
        let (event_tx, _event_rx) = mpsc::channel::<LinkSessionEvent>(8);
        let (offer_tx, mut offer_rx) = mpsc::channel::<LinkSessionResourceOffer>(1);
        assert!(
            !process_inbound_resource_advertisement(
                &transport_tx,
                1,
                &mut initiator,
                &mut resources,
                &mut pending_requests,
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

        let request = next_initiator_endpoint(&mut transport_rx).await;
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
    async fn response_resource_larger_than_advertised_is_rejected_on_received_bytes() {
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
            .prepare_request_value(
                "/large-response",
                &rmpv::Value::Binary(Vec::new()),
                Duration::from_secs(5),
            )
            .unwrap();
        let (result_tx, result_rx) = oneshot::channel();
        let mut pending_requests = HashMap::from([(
            request_id,
            PendingSessionRequest::new(
                result_tx,
                RequestOptions {
                    max_response_size: Some(10),
                    ..RequestOptions::default()
                },
                Duration::from_secs(5),
                true,
            ),
        )]);

        let packed_response = Link::pack_response_value(
            &request_id,
            &rmpv::Value::Binary(b"resource response".to_vec()),
        )
        .unwrap();
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
        // The sender under-reports its size to pass the advertisement check.
        let mut lying = ResourceAdvertisement::unpack(&advertisement).unwrap();
        lying.data_size = 8;
        let advertisement = lying.pack();

        let mut resources = SessionResources::default();
        let (transport_tx, mut transport_rx) = test_transport_channel(8);
        let (command_tx, mut command_rx) = mpsc::channel::<LinkSessionCommand>(8);
        let (event_tx, _event_rx) = mpsc::channel::<LinkSessionEvent>(8);
        let (offer_tx, mut offer_rx) = mpsc::channel::<LinkSessionResourceOffer>(1);
        assert!(
            !process_inbound_resource_advertisement(
                &transport_tx,
                1,
                &mut initiator,
                &mut resources,
                &mut pending_requests,
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

        let request = next_initiator_endpoint(&mut transport_rx).await;
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

        let result = result_rx.await.unwrap();
        assert!(
            matches!(
                result,
                Err(LinkSessionError::ResponseRejected { max: 10, .. })
            ),
            "{result:?}"
        );
        assert!(pending_requests.is_empty());
    }

    #[tokio::test]
    async fn file_responses_and_request_limits_between_runtime_peers() {
        use crate::destination_runtime::{DestinationRuntimeOptions, RegisteredDestination};
        use crate::link_manager::RequestOutcome;
        use rns_identity::destination::AllowPolicy;

        let (actor, transport_tx) = rns_transport::actor::TransportActor::new();
        let actor_task = tokio::spawn(actor.run());
        let server_identity = Identity::new();
        let server_public_key = server_identity.get_public_key();
        let registration = RegisteredDestination::register(
            transport_tx.clone(),
            server_identity,
            "example.runtime.requests",
            DestinationRuntimeOptions::default(),
        )
        .await
        .unwrap();
        // Two segments: the second one is read while the first transfers.
        let file: Vec<u8> = (0..rns_protocol::resource::MAX_EFFICIENT_SIZE + 4096)
            .map(|i| (i * 7 % 251) as u8)
            .collect();
        let metadata = vec![0x81, 0xa4, b'n', b'a', b'm', b'e', 0xc4, 0x01, b'f'];
        let (served, served_metadata) = (file.clone(), metadata.clone());
        let handle = &registration.handle;
        handle
            .register_request_handler("/file", AllowPolicy::AllowAll, vec![], false, move |_| {
                RequestOutcome::ReplyFile {
                    source: Box::new(Cursor::new(served.clone())),
                    metadata: Some(served_metadata.clone()),
                }
            })
            .await
            .unwrap();
        handle
            .register_request_handler("/big", AllowPolicy::AllowAll, vec![], false, |_| {
                RequestOutcome::ReplyBytes(vec![0x55; 2000])
            })
            .await
            .unwrap();
        handle.set_max_request_size(Some(100)).await.unwrap();

        let session = LinkSession::connect(
            transport_tx.clone(),
            Identity::new(),
            LinkSessionConfig {
                destination_hash: handle.destination_hash(),
                remote_public_key: server_public_key,
                hops: 1,
                establishment_timeout: Duration::from_secs(2),
                client_label: "test.requests".into(),
                identify: false,
                track_phy_stats: false,
                proof_strategy: ProofStrategy::ProveNone,
                resource_dir: None,
                inbound_reassembly_limit: None,
            },
        )
        .await
        .unwrap();
        let spool = std::env::temp_dir().join(format!(
            "rns-request-spool-{}",
            hex::encode(rns_crypto::random::random_bytes(8))
        ));
        std::fs::create_dir(&spool).unwrap();

        let response = session
            .handle
            .request_with_options(
                "/file",
                rmpv::Value::Nil,
                RequestOptions {
                    timeout: Some(Duration::from_secs(60)),
                    spool_dir: Some(spool.clone()),
                    ..RequestOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(response.metadata, Some(metadata));
        let path = response.file.expect("a file response is spooled");
        assert!(path.starts_with(&spool));
        assert!(std::fs::read(&path).unwrap() == file);
        std::fs::remove_file(path).unwrap();

        // Destination.max_request_size: a larger request is ignored.
        let ignored = session
            .handle
            .request_with_options(
                "/big",
                rmpv::Value::Binary(vec![0; 200]),
                RequestOptions {
                    timeout: Some(Duration::from_secs(1)),
                    ..RequestOptions::default()
                },
            )
            .await;
        assert!(
            matches!(ignored, Err(LinkSessionError::Timeout(_))),
            "{ignored:?}"
        );

        // RequestReceipt.max_response_size: a larger response is rejected.
        let rejected = session
            .handle
            .request_with_options(
                "/big",
                rmpv::Value::Nil,
                RequestOptions {
                    timeout: Some(Duration::from_secs(10)),
                    max_response_size: Some(1000),
                    ..RequestOptions::default()
                },
            )
            .await;
        assert!(
            matches!(
                rejected,
                Err(LinkSessionError::ResponseRejected { max: 1000, .. })
            ),
            "{rejected:?}"
        );
        assert_eq!(std::fs::read_dir(&spool).unwrap().count(), 0);
        std::fs::remove_dir(&spool).unwrap();

        session.handle.close().await;
        registration.close().await.unwrap();
        transport_tx.send(TransportMessage::Shutdown).await.unwrap();
        actor_task.await.unwrap();
    }

    #[tokio::test]
    async fn spooled_response_is_removed_unless_a_requester_receives_it() {
        let dir = std::env::temp_dir().join(format!(
            "rns-response-spool-{}",
            hex::encode(rns_crypto::random::random_bytes(8))
        ));
        std::fs::create_dir(&dir).unwrap();

        let (queued, _) = open_response_spool(&dir, &[7; 32]).unwrap();
        let (orphaned, _) = open_response_spool(&dir, &[7; 32]).unwrap();
        assert_ne!(queued.path, orphaned.path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&queued.path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // A completion still queued when the session ends.
        discard_undelivered_spool(&LinkSessionCommand::RequestResourceReceived {
            request_id: [1; 16],
            result: Ok(LinkSessionReceivedResource {
                link_id: [0; 16],
                resource_id: [7; 32],
                data: Vec::new(),
                file: Some(queued.path.clone()),
                metadata: Some(vec![0x80]),
                total_segments: 1,
                request_id: Some(vec![1; 16]),
                is_request: false,
                is_response: true,
            }),
        });
        assert!(!queued.path.exists());

        // A requester that stopped waiting.
        let destination_hash = [0xBE; 16];
        let server_signing = Ed25519PrivateKey::generate();
        let server_public = server_signing.public_key();
        let (mut initiator, request_data) = Link::new_initiator(destination_hash, 1);
        let (_responder, proof_data) =
            Link::new_responder(&request_data, &server_signing, destination_hash, 1).unwrap();
        initiator
            .validate_proof(&proof_data, &server_public, &server_public.to_bytes())
            .unwrap();
        let (_packed, request_id) = initiator
            .prepare_request_value("/file", &rmpv::Value::Nil, Duration::from_secs(5))
            .unwrap();
        let (result_tx, result_rx) = oneshot::channel();
        drop(result_rx);
        let (progress_tx, progress_rx) = watch::channel(0.0);
        let options = RequestOptions {
            progress: Some(progress_tx),
            ..RequestOptions::default()
        };
        let mut pending_requests = HashMap::from([(
            request_id,
            PendingSessionRequest::new(result_tx, options, Duration::from_secs(5), true),
        )]);
        let (event_tx, _event_rx) = mpsc::channel::<LinkSessionEvent>(8);
        deliver_session_response(
            &mut initiator,
            &mut pending_requests,
            &event_tx,
            request_id,
            ResponseBody {
                data: Vec::new(),
                value: rmpv::Value::Nil,
                metadata: Some(vec![0x80]),
                file: Some(orphaned.path.clone()),
            },
        );
        assert!(!orphaned.path.exists());
        assert!(pending_requests.is_empty());
        assert_eq!(*progress_rx.borrow(), 1.0);

        std::fs::remove_dir(&dir).unwrap();
    }

    #[tokio::test]
    async fn session_actor_recovers_and_answers_data_received_after_stale() {
        let destination_hash = [0xBD; 16];
        let server_signing = Ed25519PrivateKey::generate();
        let server_public = server_signing.public_key();
        let _client_identity = Identity::new();
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
        initiator.keepalive.keepalive_interval = Duration::ZERO;

        let link_id = initiator.link_id;
        let mdu = initiator.mdu;
        let channel = LinkChannel::new_encrypted_with_mdu(
            link_id,
            initiator.rtt_secs(),
            mdu,
            initiator.session_keys().unwrap(),
        );
        let (transport_tx, mut transport_rx) = test_transport_channel(16);
        let (delivery_tx, delivery_rx) = mpsc::channel::<DestinationEvent>(16);
        let (endpoint_lifecycle_tx, endpoint_lifecycle_rx) = mpsc::unbounded_channel();
        let (command_tx, command_rx) = mpsc::channel::<LinkSessionCommand>(16);
        let (event_tx, mut event_rx) = mpsc::channel::<LinkSessionEvent>(16);
        let (resource_offer_tx, _resource_offer_rx) = mpsc::channel::<LinkSessionResourceOffer>(1);
        let (phy_stats_tx, phy_stats_rx) = watch::channel(LinkPhyStats::default());
        let handle = LinkSessionHandle {
            link_id,
            mdu,
            rtt: 0.0,
            command_tx: command_tx.clone(),
            phy_stats_rx,
        };
        let mut registration = crate::link_endpoint::LinkEndpointCleanupGuard::new(
            transport_tx.clone(),
            link_id,
            LinkEndpointRole::Initiator,
        );
        registration.endpoint_bound();

        tokio::spawn(run_session_actor(
            (initiator, channel, ProofStrategy::ProveNone, None, None),
            7,
            None,
            delivery_rx,
            endpoint_lifecycle_rx,
            command_rx,
            SessionActorChannels {
                transport_tx,
                command_tx,
                event_tx,
                resource_offer_tx,
                phy_stats_tx,
            },
            registration,
        ));

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
                .await
                .unwrap(),
            Some(LinkSessionEvent::Stale)
        );
        let keepalive = next_initiator_endpoint(&mut transport_rx).await;
        assert_eq!(
            keepalive.raw.last(),
            Some(&rns_link::constants::KEEPALIVE_REQUEST)
        );

        let inbound_ciphertext = responder.encrypt(b"ping").unwrap();
        let inbound_packet = build_data_packet(
            responder.link_id,
            rns_wire::context::PacketContext::None,
            &inbound_ciphertext,
        );
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: inbound_packet.clone(),
                interface_owner: None,
                interface_id: 8,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        tokio::task::yield_now().await;
        assert!(transport_rx.try_recv().is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(25), event_rx.recv())
                .await
                .is_err(),
            "wrong-interface ingress must not mutate Link state or emit plaintext"
        );
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: inbound_packet,
                interface_owner: None,
                interface_id: 7,
                metrics: Default::default(),
            })
            .await
            .unwrap();

        assert!(matches!(
            event_rx.recv().await,
            Some(LinkSessionEvent::Packet { ref data, .. }) if data == b"ping"
        ));
        assert_eq!(event_rx.recv().await, Some(LinkSessionEvent::Recovered));

        handle
            .send_packet(b"pong".to_vec())
            .await
            .expect("the recovered actor must accept the heartbeat response");
        let response = next_initiator_endpoint(&mut transport_rx).await;
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&response.raw).unwrap();
        assert_eq!(responder.decrypt(&response.raw[offset..]).unwrap(), b"pong");

        endpoint_lifecycle_tx
            .send(rns_transport::messages::LinkEndpointLifecycleEvent {
                binding: rns_transport::messages::LinkEndpointBinding {
                    link_id,
                    interface_owner: None,
                    interface_id: 7,
                    role: LinkEndpointRole::Initiator,
                },
                reason: rns_transport::messages::LinkEndpointTerminalReason::InterfaceRemoved,
                dropped_packets: 1,
            })
            .unwrap();
        let TransportMessage::UnbindLinkEndpoint { result_tx, .. } =
            transport_rx.recv().await.unwrap()
        else {
            panic!("terminal endpoint cleanup must explicitly unbind");
        };
        let _ = result_tx.send(rns_transport::messages::LinkEndpointUnbindResult::Unbound);
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterDestination { hash }) if hash == link_id
        ));
        assert_eq!(
            event_rx.recv().await,
            Some(LinkSessionEvent::Closed {
                reason: LinkSessionCloseReason::TransportUnavailable,
            })
        );
    }

    async fn answer_no_link_cost(rx: &mut mpsc::Receiver<TransportMessage>) {
        match rx.recv().await.unwrap() {
            TransportMessage::Rpc {
                query: TransportQuery::RecallLinkCost { .. },
                response_tx,
            } => {
                let _ = response_tx.send(TransportQueryResponse::FloatResult(None));
            }
            other => panic!("expected link cost recall, got {other:?}"),
        }
        match rx.recv().await.unwrap() {
            TransportMessage::Rpc {
                query: TransportQuery::GetNextHopHardwareMtu { .. },
                response_tx,
            } => {
                let _ = response_tx.send(TransportQueryResponse::IntResult(-1));
            }
            other => panic!("expected next-hop MTU query, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn capacity_rejection_finishes_handshake_before_proof_timeout() {
        let (tx, mut rx) = mpsc::channel(8);
        let connect = tokio::spawn(LinkSession::connect(
            tx,
            Identity::new(),
            LinkSessionConfig {
                destination_hash: [0x71; 16],
                remote_public_key: Identity::new().get_public_key(),
                hops: 1,
                establishment_timeout: Duration::from_secs(30),
                client_label: "capacity".into(),
                identify: false,
                track_phy_stats: false,
                proof_strategy: ProofStrategy::ProveNone,
                resource_dir: None,
                inbound_reassembly_limit: None,
            },
        ));
        answer_no_link_cost(&mut rx).await;
        let link_id = match rx.recv().await.unwrap() {
            TransportMessage::RegisterDestination { hash, .. } => hash,
            other => panic!("unexpected registration: {other:?}"),
        };
        let expected = rns_transport::link_messages::LinkRequestDispatchError::Capacity(
            rns_transport::InterfaceCapacityError::LinkCapacityUnavailable {
                interface_id: 7,
                clear_mtu: 499,
                required: 500,
            },
        );
        match rx.recv().await.unwrap() {
            TransportMessage::SendLinkRequest { result_tx, .. } => {
                result_tx.send(Err(expected)).unwrap();
            }
            other => panic!("unexpected dispatch: {other:?}"),
        }
        let result = tokio::time::timeout(Duration::from_secs(1), connect)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(result, Err(LinkSessionError::RequestDispatch(error)) if error == expected)
        );
        assert!(
            matches!(rx.recv().await, Some(TransportMessage::DeregisterDestination { hash }) if hash == link_id)
        );
    }

    #[tokio::test]
    async fn cancelled_handshake_deregisters_temporary_link_destination() {
        let destination_hash = [0x33; 16];
        let remote_identity = Identity::new();
        let (transport_tx, mut transport_rx) = test_transport_channel(8);

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
                proof_strategy: ProofStrategy::ProveNone,
                resource_dir: None,
                inbound_reassembly_limit: None,
            },
        ));

        answer_no_link_cost(&mut transport_rx).await;
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
    async fn post_bind_send_failure_unbinds_before_deregistering_destination() {
        let destination_hash = [0x34; 16];
        let remote_identity = Identity::new();
        let remote_signing = remote_identity.get_signing_key().unwrap();
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(16);

        let connect = tokio::spawn(LinkSession::connect(
            transport_tx,
            Identity::new(),
            LinkSessionConfig {
                destination_hash,
                remote_public_key: remote_identity.get_public_key(),
                hops: 1,
                establishment_timeout: Duration::from_secs(2),
                client_label: "test.post-bind-failure".into(),
                identify: false,
                track_phy_stats: false,
                proof_strategy: ProofStrategy::ProveNone,
                resource_dir: None,
                inbound_reassembly_limit: None,
            },
        ));

        answer_no_link_cost(&mut transport_rx).await;
        let (link_id, delivery_tx) = match transport_rx.recv().await.unwrap() {
            TransportMessage::RegisterDestination {
                hash,
                delivery_tx: Some(delivery_tx),
                ..
            } => (hash, delivery_tx),
            other => panic!("unexpected transport message: {other:?}"),
        };
        let request = match transport_rx.recv().await.unwrap() {
            TransportMessage::SendLinkRequest { request, result_tx } => {
                let _ = result_tx.send(Ok(()));
                request
            }
            TransportMessage::Outbound(request) => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (_, request_offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        let (_responder, proof) = Link::new_responder(
            &request.raw[request_offset..],
            &remote_signing,
            destination_hash,
            1,
        )
        .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_proof_packet(link_id, rns_wire::context::PacketContext::None, &proof),
                interface_owner: None,
                interface_id: 23,
                metrics: Default::default(),
            })
            .await
            .unwrap();

        let TransportMessage::BindLinkEndpoint {
            binding,
            lifecycle_tx,
            result_tx,
        } = transport_rx.recv().await.unwrap()
        else {
            panic!("valid LRPROOF must bind before LRRTT");
        };
        assert_eq!(binding.link_id, link_id);
        assert_eq!(binding.interface_id, 23);
        assert_eq!(binding.role, LinkEndpointRole::Initiator);
        let _ = result_tx.send(rns_transport::messages::LinkEndpointBindResult::Bound);
        std::mem::forget(lifecycle_tx);

        let TransportMessage::SendLinkEndpoint {
            role,
            request,
            result_tx,
            ..
        } = transport_rx.recv().await.unwrap()
        else {
            panic!("LRRTT must use the bound endpoint");
        };
        assert_eq!(role, LinkEndpointRole::Initiator);
        let (header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(header.context, rns_wire::context::PacketContext::Lrrtt);
        let _ = result_tx.send(rns_transport::messages::LinkEndpointSendResult::NotBound);
        assert!(matches!(
            connect.await.unwrap(),
            Err(LinkSessionError::TransportUnavailable)
        ));

        let TransportMessage::UnbindLinkEndpoint {
            link_id: unbound,
            role,
            result_tx,
        } = transport_rx.recv().await.unwrap()
        else {
            panic!("post-bind failure must unbind before deregistration");
        };
        assert_eq!(unbound, link_id);
        assert_eq!(role, LinkEndpointRole::Initiator);
        let _ = result_tx.send(rns_transport::messages::LinkEndpointUnbindResult::Unbound);
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterDestination { hash }) if hash == link_id
        ));
    }

    /// Link.py initiators ignore LRRTT. A destination reporting an infinite RTT
    /// used to panic the session actor instead.
    #[tokio::test]
    async fn initiator_session_survives_hostile_lrrtt() {
        let destination_hash = [0x45; 16];
        let server_identity = Identity::new();
        let server_signing = server_identity.get_signing_key().unwrap();
        let (transport_tx, mut transport_rx) = test_transport_channel(64);

        let connect = tokio::spawn(LinkSession::connect(
            transport_tx,
            Identity::new(),
            LinkSessionConfig {
                destination_hash,
                remote_public_key: server_identity.get_public_key(),
                hops: 1,
                establishment_timeout: Duration::from_secs(2),
                client_label: "test.hostile-lrrtt".into(),
                identify: false,
                track_phy_stats: false,
                proof_strategy: ProofStrategy::ProveNone,
                resource_dir: None,
                inbound_reassembly_limit: None,
            },
        ));
        answer_no_link_cost(&mut transport_rx).await;
        let delivery_tx = match transport_rx.recv().await.unwrap() {
            TransportMessage::RegisterDestination {
                delivery_tx: Some(tx),
                ..
            } => tx,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let request = match transport_rx.recv().await.unwrap() {
            TransportMessage::SendLinkRequest { request, result_tx } => {
                let _ = result_tx.send(Ok(()));
                request
            }
            TransportMessage::Outbound(request) => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (_, request_offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        let (mut responder, proof) = Link::new_responder(
            &request.raw[request_offset..],
            &server_signing,
            destination_hash,
            1,
        )
        .unwrap();
        let link_id = responder.link_id;
        let inbound = move |context, body: &[u8]| DestinationEvent::InboundPacket {
            raw: build_data_packet(link_id, context, body),
            interface_owner: None,
            interface_id: 1,
            metrics: PacketMetrics::default(),
        };
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_proof_packet(link_id, rns_wire::context::PacketContext::None, &proof),
                interface_owner: None,
                interface_id: 1,
                metrics: PacketMetrics::default(),
            })
            .await
            .unwrap();
        let rtt = next_initiator_endpoint(&mut transport_rx).await;
        let (_, rtt_offset) = rns_wire::header::PacketHeader::unpack(&rtt.raw).unwrap();
        responder
            .receive_rtt_packet(&rtt.raw[rtt_offset..])
            .unwrap();
        let mut session = connect.await.unwrap().unwrap();

        let mut hostile_rtt = Vec::new();
        rmpv::encode::write_value(&mut hostile_rtt, &rmpv::Value::F64(f64::INFINITY)).unwrap();
        let hostile_rtt = responder.encrypt(&hostile_rtt).unwrap();
        delivery_tx
            .send(inbound(
                rns_wire::context::PacketContext::Lrrtt,
                &hostile_rtt,
            ))
            .await
            .unwrap();
        let after = responder.encrypt(b"after hostile LRRTT").unwrap();
        delivery_tx
            .send(inbound(rns_wire::context::PacketContext::None, &after))
            .await
            .unwrap();

        match tokio::time::timeout(Duration::from_secs(2), session.events.recv()).await {
            Ok(Some(LinkSessionEvent::Packet { data, .. })) => {
                assert_eq!(data, b"after hostile LRRTT");
            }
            other => panic!("session must survive a hostile LRRTT: {other:?}"),
        }
    }

    #[tokio::test]
    async fn persistent_session_identifies_and_exchanges_link_packets() {
        let destination_hash = [0x44; 16];
        let server_identity = Identity::new();
        let server_public = server_identity.get_public_key();
        let server_signing = server_identity.get_signing_key().unwrap();
        let client_identity = Identity::new();
        let (transport_tx, mut transport_rx) = test_transport_channel(64);

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
                proof_strategy: ProofStrategy::ProveAll,
                resource_dir: None,
                inbound_reassembly_limit: None,
            },
        ));

        answer_no_link_cost(&mut transport_rx).await;
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
            TransportMessage::SendLinkRequest { request, result_tx } => {
                let _ = result_tx.send(Ok(()));
                request
            }
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
                interface_owner: None,
                interface_id: 1,
                metrics: PacketMetrics {
                    rssi: Some(-87.0),
                    snr: Some(6.5),
                    q: Some(0.75),
                },
            })
            .await
            .unwrap();

        let TransportMessage::BindLinkEndpoint {
            binding,
            lifecycle_tx,
            result_tx,
        } = transport_rx.recv().await.unwrap()
        else {
            panic!("valid LRPROOF must bind the initiator endpoint before LRRTT");
        };
        assert_eq!(binding.link_id, responder.link_id);
        assert_eq!(binding.interface_id, 1);
        assert_eq!(binding.role, LinkEndpointRole::Initiator);
        let _ = result_tx.send(rns_transport::messages::LinkEndpointBindResult::Bound);
        std::mem::forget(lifecycle_tx);

        let rtt = next_initiator_endpoint(&mut transport_rx).await;
        let (rtt_header, rtt_offset) = rns_wire::header::PacketHeader::unpack(&rtt.raw).unwrap();
        assert_eq!(rtt_header.context, rns_wire::context::PacketContext::Lrrtt);
        responder
            .receive_rtt_packet(&rtt.raw[rtt_offset..])
            .unwrap();

        let identify = next_initiator_endpoint(&mut transport_rx).await;
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
        let sent = next_initiator_endpoint(&mut transport_rx).await;
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
        let request = next_initiator_endpoint(&mut transport_rx).await;
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
            .create_response_value(&request_id, &rmpv::Value::Binary(b"response body".to_vec()))
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_data_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::Response,
                    &response,
                ),
                interface_owner: None,
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
        let timed_out_request = next_initiator_endpoint(&mut transport_rx).await;
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
        let first_channel_packet = next_initiator_endpoint(&mut transport_rx).await;
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
        let second_channel_packet = next_initiator_endpoint(&mut transport_rx).await;
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
            .prove_responder_packet_with(&first_receipt.packet_hash, |hash| {
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
                interface_owner: None,
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
            .prove_responder_packet_with(&second_receipt.packet_hash, |hash| {
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
                interface_owner: None,
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
        let (inbound_channel_header, _) =
            rns_wire::header::PacketHeader::unpack(&inbound_channel_packet).unwrap();
        let inbound_channel_hash = rns_wire::hash::packet_hash(
            &inbound_channel_packet,
            inbound_channel_header.flags.header_type,
        );
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: inbound_channel_packet,
                interface_owner: None,
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
        let inbound_proof = next_initiator_endpoint(&mut transport_rx).await;
        let (inbound_proof_header, inbound_proof_offset) =
            rns_wire::header::PacketHeader::unpack(&inbound_proof.raw).unwrap();
        assert_eq!(
            inbound_proof_header.flags.packet_type,
            rns_wire::flags::PacketType::Proof
        );
        responder
            .validate_peer_packet_proof(
                &inbound_channel_hash,
                &inbound_proof.raw[inbound_proof_offset..],
            )
            .expect("initiator Channel proof must use the LINKREQUEST transient key");
        let mut identity_signed_channel_proof = Vec::with_capacity(96);
        identity_signed_channel_proof.extend_from_slice(&inbound_channel_hash);
        identity_signed_channel_proof.extend_from_slice(
            &client_identity
                .sign(&inbound_channel_hash)
                .expect("application identity can sign the negative-control proof"),
        );
        assert!(
            responder
                .validate_peer_packet_proof(&inbound_channel_hash, &identity_signed_channel_proof,)
                .is_err(),
            "the unrelated application identity must not authenticate an initiator proof"
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
                interface_owner: None,
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
        let _ignored_proof = next_initiator_endpoint(&mut transport_rx).await;
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
                interface_owner: None,
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
        let _inbound_stream_proof = next_initiator_endpoint(&mut transport_rx).await;
        responder_channel.delivered(inbound_stream_prepared.sequence, responder.rtt_secs());

        buffer.write_all(b"buffer outbound").await.unwrap();
        buffer.flush().await.unwrap();
        let outbound_stream_packet = next_initiator_endpoint(&mut transport_rx).await;
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
            .prove_responder_packet_with(&outbound_stream_hash, |hash| server_identity.sign(hash))
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_proof_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::LinkProof,
                    &outbound_stream_proof,
                ),
                interface_owner: None,
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();

        buffer.shutdown().await.unwrap();
        let eof_packet = next_initiator_endpoint(&mut transport_rx).await;
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
            .prove_responder_packet_with(&eof_hash, |hash| server_identity.sign(hash))
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_proof_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::LinkProof,
                    &eof_proof,
                ),
                interface_owner: None,
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
        let (inbound_header, _) = rns_wire::header::PacketHeader::unpack(&inbound).unwrap();
        let inbound_hash = rns_wire::hash::packet_hash(&inbound, inbound_header.flags.header_type);
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: inbound.clone(),
                interface_owner: None,
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
                interface_owner: None,
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
        let proof = next_initiator_endpoint(&mut transport_rx).await;
        let (proof_header, proof_offset) =
            rns_wire::header::PacketHeader::unpack(&proof.raw).unwrap();
        assert_eq!(
            proof_header.flags.packet_type,
            rns_wire::flags::PacketType::Proof
        );
        assert_eq!(proof_header.context, rns_wire::context::PacketContext::None);
        responder
            .validate_peer_packet_proof(&inbound_hash, &proof.raw[proof_offset..])
            .expect("initiator ordinary proof must use the LINKREQUEST transient key");

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

        let advertisement = next_initiator_endpoint(&mut transport_rx).await;
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
                interface_owner: None,
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();

        let part = next_initiator_endpoint(&mut transport_rx).await;
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
                interface_owner: None,
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
        let active_advertisement = next_initiator_endpoint(&mut transport_rx).await;
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
        let cancellation = next_initiator_endpoint(&mut transport_rx).await;
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
                interface_owner: None,
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
        let inbound_request = next_initiator_endpoint(&mut transport_rx).await;
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
                    interface_owner: None,
                    interface_id: 1,
                    metrics: Default::default(),
                })
                .await
                .unwrap();
        }

        let inbound_proof = next_initiator_endpoint(&mut transport_rx).await;
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
                interface_owner: None,
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        let rejected_offer = session.resource_offers.recv().await.unwrap();
        assert!(rejected_offer.reject().await.unwrap());
        let rejection = next_initiator_endpoint(&mut transport_rx).await;
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
                interface_owner: None,
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
        let _cancelled_request = next_initiator_endpoint(&mut transport_rx).await;
        assert!(cancelled_inbound.cancel().await.unwrap());
        let cancellation = next_initiator_endpoint(&mut transport_rx).await;
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
        let close = next_initiator_endpoint(&mut transport_rx).await;
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
