//! Actor-model interface for the transport.
//!
//! Commands and queries for the task that owns transport routing state.
//! The actor also has dedicated control channels, public setup state and
//! driver-shared counters. Sending a command only admits it to a mailbox;
//! use the operation-specific reply when a local result is required.
//!
//! Debug output can contain packet bytes, names and query payloads. It is
//! not a sanitized diagnostic or aggregate-only interface.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};

use bytes::Bytes;
use tokio::sync::{mpsc, watch};

use crate::constants::{InterfaceDirection, InterfaceMode};
pub use crate::ingress::HeldAnnounce;
use crate::ingress::IngressController;

pub type InterfaceId = u64;
pub use crate::interface_ownership::{
    InterfaceCapacityError, InterfaceOwner, InterfaceOwnerId, InterfacePacketCapacity,
    InterfaceTransportSender,
};

/// Optional aggregate counts supplied by an interface driver.
///
/// This record contains no endpoint, address, name or free-form field. That
/// restriction applies to this record, not to the surrounding interface stats,
/// which include names and other configuration metadata.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InterfaceInspectionSnapshot {
    pub active_clients: Option<u64>,
    pub blocked_ips: Option<u64>,
}

/// A driver-owned callback for live aggregate interface counts.
///
/// `GetInterfaceStats` calls it synchronously once per inspected interface and
/// substitutes empty counts if it panics. Keep locks short and do not perform
/// I/O: the callback executes on the actor task.
#[derive(Clone)]
pub struct InterfaceInspectionSource {
    snapshot: Arc<dyn Fn() -> InterfaceInspectionSnapshot + Send + Sync>,
}

impl InterfaceInspectionSource {
    /// Store a callback; this does not call it or start a polling task.
    pub fn new<F>(snapshot: F) -> Self
    where
        F: Fn() -> InterfaceInspectionSnapshot + Send + Sync + 'static,
    {
        Self {
            snapshot: Arc::new(snapshot),
        }
    }

    /// Call the callback synchronously. Unlike `GetInterfaceStats`, this method
    /// does not catch callback panics.
    pub fn snapshot(&self) -> InterfaceInspectionSnapshot {
        (self.snapshot)()
    }
}

impl std::fmt::Debug for InterfaceInspectionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceInspectionSource")
            .finish_non_exhaustive()
    }
}

/// Opaque identity for one transport announce-handler registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AnnounceHandlerId(pub(crate) u64);

/// Interface role used by routing and shared-instance policy. It is separate
/// from `InterfaceMode`, which controls forwarding/discovery policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterfaceRole {
    /// Ordinary network interface.
    #[default]
    Normal,
    /// Local shared-instance listener.
    SharedServer,
    /// Accepted local client behind the shared listener.
    LocalClient,
    /// Leaf process connection to an existing shared instance.
    SharedInstancePeer,
}

impl InterfaceRole {
    /// Return the role label used by interface statistics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::SharedServer => "shared_server",
            Self::LocalClient => "local_client",
            Self::SharedInstancePeer => "shared_instance_peer",
        }
    }
}

/// Raw driver input and optional physical-layer observations. Submit through
/// the current `InterfaceTransportSender`; the actor rejects an unwrapped
/// `TransportMessage::Inbound`. Metrics are interface-supplied, with no quality
/// normalization performed by this record.
#[derive(Debug)]
pub struct InboundPacket {
    pub raw: Bytes,
    pub interface_id: InterfaceId,
    pub rssi: Option<f32>,
    pub snr: Option<f32>,
    pub q: Option<f32>,
}

/// Packet bytes and destination supplied by the caller for local dispatch.
/// This record does not construct, sign, encrypt or validate a packet.
#[derive(Debug)]
pub struct OutboundRequest {
    pub raw: Bytes,
    pub destination_hash: [u8; 16],
}

/// Latest state of one explicitly tracked outbound packet. A watch channel
/// retains the latest state, not an event history; a slow reader may skip updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptUpdate {
    Sent,
    Delivered { rtt: std::time::Duration },
    TimedOut,
    Failed,
    Culled,
}

/// Caller-supplied receipt metadata installed by `SendPacket` in the same
/// actor turn as dispatch. The caller must provide hashes and a destination
/// identity matching the packet; registration does not verify that binding.
/// `None` timeout uses 180 seconds. Initialize the watch channel to `Sent`;
/// terminal updates replace its current value.
pub struct TrackedReceiptRegistration {
    pub truncated_hash: [u8; 16],
    pub full_hash: [u8; 32],
    pub destination_hash: [u8; 16],
    pub destination_public_key: [u8; 64],
    pub timeout: Option<std::time::Duration>,
    pub status_tx: watch::Sender<ReceiptUpdate>,
}

impl std::fmt::Debug for TrackedReceiptRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedReceiptRegistration")
            .field("truncated_hash", &self.truncated_hash)
            .field("destination_hash", &self.destination_hash)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// Immediate local dispatch outcome. `Sent` means at least one eligible
/// interface or in-process destination queue accepted the packet, not remote
/// delivery. `NoInterface` also covers invalid packets and failed immediate
/// admission; an announce may still be retained for a later retry.
/// `ReceiptCollision` means the truncated receipt key was already registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundDispatchResult {
    Sent,
    NoInterface,
    ReceiptCollision,
}

/// Which side of an established Link owns one transport endpoint.
///
/// This role is immutable for the lifetime of a binding. Keeping it in the
/// transport command prevents two local Link owners from accidentally
/// sharing the same egress queue when an in-process Link has both endpoints
/// on one actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkEndpointRole {
    Initiator,
    Responder,
}

/// Immutable egress attachment for one locally-owned established Link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkEndpointBinding {
    pub interface_owner: Option<InterfaceOwnerId>,
    pub link_id: [u8; 16],
    pub interface_id: InterfaceId,
    pub role: LinkEndpointRole,
}

/// Result of installing an established-Link endpoint binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkEndpointBindResult {
    Bound,
    AlreadyBound,
    /// The same Link endpoint is already attached to different immutable
    /// metadata. Callers must tear the old endpoint down before rebinding.
    Conflict {
        interface_id: InterfaceId,
        role: LinkEndpointRole,
    },
    InterfaceUnavailable,
}

/// Why transport permanently removed a locally-owned Link endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkEndpointTerminalReason {
    Unbound,
    InterfaceRemoved,
    InterfaceClosed,
    InterfaceOffline,
    InterfaceNotOutbound,
    EgressQueueExhausted,
    TransportShutdown,
}

/// Terminal event attempted once when transport removes a Link binding.
/// The notification can be lost if its receiver has closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkEndpointLifecycleEvent {
    pub binding: LinkEndpointBinding,
    pub reason: LinkEndpointTerminalReason,
    /// Packets retained in the endpoint FIFO, plus any packet counted during
    /// terminal admission failure. This is not a count of over-the-air losses.
    pub dropped_packets: usize,
}

/// Immediate result of handing an established-Link packet to transport.
///
/// `Sent` reports local driver/in-process queue admission. `Queued` reports
/// admission to the bounded per-Link FIFO, before driver acceptance. Neither
/// confirms remote delivery. Terminal interface failures use the lifecycle
/// channel; transport does not reroute this binding to another interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkEndpointSendResult {
    Sent,
    Queued {
        depth: usize,
    },
    /// A best-effort packet was discarded because reliable traffic was
    /// already queued or the exact interface queue was full.
    DroppedBackpressure,
    NotBound,
    RoleMismatch,
    InvalidPacket,
    Terminated(LinkEndpointTerminalReason),
}

/// Result of explicitly releasing one established-Link endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkEndpointUnbindResult {
    Unbound,
    NotBound,
    RoleMismatch,
}

/// Explicit maintenance trigger. The actor ignores `timestamp` and reads its
/// own current time. `TransportActor::run` also schedules maintenance internally.
#[derive(Debug)]
pub struct TimerTick {
    pub timestamp: f64,
}

/// Registration metadata, capacity policy and TX sender for one interface.
/// Public fields and builder methods store caller values; they do not start a
/// driver. Registration and dispatch apply ownership/capacity checks separately.
pub struct InterfaceEntry {
    pub owner: InterfaceOwner,
    pub packet_capacity: InterfacePacketCapacity,
    pub name: String,
    pub mode: InterfaceMode,
    pub role: InterfaceRole,
    /// The listener that accepted this interface; `None` for configured ones.
    pub parent_id: Option<InterfaceId>,
    pub direction: InterfaceDirection,
    /// Declared bitrate in bits per second, used for timing estimates.
    pub bitrate: u64,
    /// Reported hardware MTU in bytes. Admission uses `packet_capacity`.
    pub mtu: u32,
    pub tx: mpsc::Sender<Bytes>,
    pub ifac_key: Option<rns_identity::ifac::IfacKey>,
    /// Configured IFAC size in bytes; inactive when no key is set.
    pub ifac_size: usize,
    /// Announce bitrate fraction: 0.02 represents 2%.
    pub announce_cap: f64,
    /// Earliest Unix time at which the next announce may be sent — enforces
    /// `ANNOUNCE_CAP` spacing in the outbound path.
    pub announce_allowed_at: f64,
    pub announce_rate_target: Option<f64>,
    pub announce_rate_grace: Option<u32>,
    pub announce_rate_penalty: Option<f64>,
    /// Shared with the driver so the actor sees online-state flips without
    /// polling. `None` when the driver doesn't expose one (e.g. in-memory test
    /// interfaces).
    pub online: Option<Arc<AtomicBool>>,
    pub rxb: Option<Arc<std::sync::atomic::AtomicU64>>,
    pub txb: Option<Arc<std::sync::atomic::AtomicU64>>,
    /// Optional driver-owned aggregate inspection source.
    pub inspection: Option<InterfaceInspectionSource>,
    /// Packets dropped by counted full-queue admission failures. This is not
    /// a count of every send failure or of packets retained for later retry.
    pub tx_drops: Arc<std::sync::atomic::AtomicU64>,
    /// Pre-IFAC bytes of the packets counted by transport as full-queue drops.
    pub tx_dropped_bytes: u64,
    /// Inbound packets counted as malformed or invalid by transport.
    pub protocol_violations: u64,
    /// Inbound packets dropped for a missing, invalid or unexpected IFAC.
    pub ifac_violations: u64,
    /// Inbound packets rejected by the transport packet filter.
    pub packet_filter_hits: u64,
    pub ingress: IngressController,
    /// Announces awaiting bandwidth-capped retransmission. Drained in
    /// hop-priority order (lowest hops first, oldest among ties).
    pub announce_queue: Vec<QueuedAnnounce>,
    /// Driver-supplied multipoint metadata. The current actor allows same-interface
    /// announce relay for ordinary network roles independently of this flag;
    /// setting it does not install a driver-level loop filter.
    pub multipoint: bool,
    /// Enable unknown-path discovery for requests arriving on this interface,
    /// independently of its mode.
    pub recursive_prs: bool,
    /// Whether to rebroadcast announces whose next-hop interface uses
    /// `InterfaceMode::Internal`.
    pub announces_from_internal: bool,
}

impl InterfaceEntry {
    /// Minimal entry with defaults for everything optional. Use the
    /// chainable `with_*` methods to fill in IFAC, rate limits, and
    /// driver-shared counters.
    pub fn new(
        name: String,
        mode: InterfaceMode,
        direction: InterfaceDirection,
        bitrate: u64,
        mtu: u32,
        tx: mpsc::Sender<Bytes>,
    ) -> Self {
        Self {
            owner: InterfaceOwner::new(),
            packet_capacity: InterfacePacketCapacity::base(mtu),
            name,
            mode,
            role: InterfaceRole::Normal,
            parent_id: None,
            direction,
            bitrate,
            mtu,
            tx,
            ifac_key: None,
            ifac_size: 0,
            announce_cap: crate::constants::ANNOUNCE_CAP,
            announce_allowed_at: 0.0,
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,
            online: None,
            rxb: None,
            txb: None,
            inspection: None,
            tx_drops: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            tx_dropped_bytes: 0,
            protocol_violations: 0,
            ifac_violations: 0,
            packet_filter_hits: 0,
            ingress: IngressController::new(),
            announce_queue: Vec::new(),
            multipoint: false,
            recursive_prs: false,
            announces_from_internal: true,
        }
    }

    /// Replace admission capacity without changing the separately reported `mtu`.
    pub fn with_packet_capacity(mut self, capacity: InterfacePacketCapacity) -> Self {
        self.packet_capacity = capacity;
        self
    }
    /// Replace the registration owner; current-generation checks occur at admission.
    pub fn with_owner(mut self, owner: InterfaceOwner) -> Self {
        self.owner = owner;
        self
    }
    /// Return configured IFAC bytes when a key exists, or zero without a key.
    pub fn active_ifac_bytes(&self) -> usize {
        if self.ifac_key.is_some() {
            self.ifac_size
        } else {
            0
        }
    }
    /// Check current ownership and clear/wire byte capacity before allocation.
    /// This does not parse a header or check direction or driver online state.
    pub fn accepts_clear_packet(&self, len: usize) -> bool {
        self.owner.is_current()
            && self
                .effective_clear_mtu()
                .is_ok_and(|mtu| len <= mtu as usize)
            && len
                .checked_add(self.active_ifac_bytes())
                .is_some_and(|wire| wire <= self.packet_capacity.max_wire_packet_bytes as usize)
    }
    /// Compute clear-packet capacity after IFAC. An active key requires an IFAC
    /// size in 1..=64 bytes; invalid capacity or IFAC returns an error.
    pub fn effective_clear_mtu(&self) -> Result<u32, InterfaceCapacityError> {
        if self.ifac_key.is_some() && !(1..=64).contains(&self.ifac_size) {
            return Err(InterfaceCapacityError::InvalidIfac);
        }
        self.packet_capacity
            .effective_clear_mtu(self.active_ifac_bytes())
    }

    /// Store the multipoint metadata flag.
    pub fn with_multipoint(mut self, multipoint: bool) -> Self {
        self.multipoint = multipoint;
        self
    }

    /// Store an IFAC key and size in bytes. This builder does not validate the
    /// size; `effective_clear_mtu` rejects active sizes outside 1..=64.
    pub fn with_ifac(mut self, key: [u8; 64], size: usize) -> Self {
        self.ifac_key = Some(key.into());
        self.ifac_size = size;
        self
    }

    /// Store the minimum inter-announce interval and extra penalty in seconds,
    /// plus the tolerated violation count. Values are not validated here. The
    /// receive path uses these to suppress rebroadcast, not announce-cache updates.
    pub fn with_announce_rate(mut self, target: f64, grace: u32, penalty: f64) -> Self {
        self.announce_rate_target = Some(target);
        self.announce_rate_grace = Some(grace);
        self.announce_rate_penalty = Some(penalty);
        self
    }

    /// Store the role used by shared-instance routing policy.
    pub fn with_role(mut self, role: InterfaceRole) -> Self {
        self.role = role;
        self
    }

    /// Attach driver-owned online state and cumulative RX/TX byte counters.
    pub fn with_counters(
        mut self,
        online: Arc<AtomicBool>,
        rxb: Arc<std::sync::atomic::AtomicU64>,
        txb: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        self.online = Some(online);
        self.rxb = Some(rxb);
        self.txb = Some(txb);
        self
    }
}

/// Announce queued for bandwidth-capped retransmission on an interface.
#[derive(Debug, Clone)]
pub struct QueuedAnnounce {
    pub destination_hash: [u8; 16],
    /// Queue-insertion time (Unix seconds); used as tie-breaker in priority ordering.
    pub time: f64,
    pub hops: u8,
    pub raw: Bytes,
}

impl std::fmt::Debug for InterfaceEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceEntry")
            .field("name", &self.name)
            .field("mode", &self.mode)
            .field("role", &self.role)
            .field("parent_id", &self.parent_id)
            .field("direction", &self.direction)
            .field("bitrate", &self.bitrate)
            .field("mtu", &self.mtu)
            .field("ifac_size", &self.ifac_size)
            .field("announce_cap", &self.announce_cap)
            .field("announce_allowed_at", &self.announce_allowed_at)
            .field("has_inspection", &self.inspection.is_some())
            .field("held_announces", &self.ingress.held_count())
            .field("announce_queue", &self.announce_queue.len())
            .finish()
    }
}

/// Event pushed to a registered announce handler.
#[derive(Debug, Clone)]
pub struct AnnounceHandlerEvent {
    pub destination_hash: [u8; 16],
    /// Identity hash recovered from the validated announce payload.
    pub identity_hash: Option<[u8; 16]>,
    pub announce_packet_hash: [u8; 32],
    pub is_path_response: bool,
    pub hops: u8,
    pub app_data: Option<Vec<u8>>,
    /// X25519 || Ed25519 public key from the announce payload.
    pub public_key: Option<[u8; 64]>,
    pub ratchet: Option<[u8; 32]>,
    /// Ten-byte name hash from the destination's expanded hash name, including
    /// any aspects or generated-identity suffix. The actor rejects missing or
    /// invalid announce payloads before dispatching handlers.
    pub name_hash: [u8; 10],
}

/// Optional routing controls for an explicit path request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathRequestOptions {
    /// Restrict requests to this interface. `None` offers them to eligible
    /// outbound interfaces; it does not guarantee queue admission.
    pub on_interface: Option<InterfaceId>,
    /// Caller-supplied request tag. At most the first 16 bytes are transmitted.
    pub tag: Option<Vec<u8>>,
    /// Apply recursive path-request announce-cap gating on an attached interface.
    pub recursive: bool,
}

/// Commands accepted by the transport actor. Some require a current
/// producer-bound `InterfaceEvent`; others are trusted application operations.
/// A mailbox send is not an operation acknowledgment. Unless a variant says
/// otherwise, dropping its reply receiver does not cancel admitted work.
// This is the transport actor's public message surface. Boxing individual
// variants would churn all senders/receivers for little runtime benefit.
#[allow(clippy::large_enum_variant)]
pub enum TransportMessage {
    /// Producer-bound event. A stale registration cannot act on a replacement.
    InterfaceEvent {
        interface_id: InterfaceId,
        owner: InterfaceOwner,
        message: Box<TransportMessage>,
    },
    /// Driver input; requires a current owner-bound `InterfaceEvent`.
    Inbound(InboundPacket),
    /// Dispatch without a result reply. Eligible Data packets receive an automatic
    /// receipt, using any cached destination key; failures are not replied.
    Outbound(OutboundRequest),
    /// Validate and dispatch a Link request, replying with local admission only.
    /// A closed reply receiver is checked before processing; later cancellation
    /// cannot retract transmitted bytes.
    SendLinkRequest {
        request: OutboundRequest,
        result_tx: tokio::sync::oneshot::Sender<
            Result<(), crate::link_messages::LinkRequestDispatchError>,
        >,
    },
    /// Best-effort dispatch restricted to one interface, without a result reply.
    OutboundAttached {
        request: OutboundRequest,
        interface_id: InterfaceId,
    },
    /// Install one immutable, locally-owned established-Link attachment.
    /// This table is deliberately separate from the transit `LinkTable`.
    BindLinkEndpoint {
        binding: LinkEndpointBinding,
        lifecycle_tx: mpsc::UnboundedSender<LinkEndpointLifecycleEvent>,
        result_tx: tokio::sync::oneshot::Sender<LinkEndpointBindResult>,
    },
    /// Explicitly release a locally-owned established-Link attachment.
    UnbindLinkEndpoint {
        link_id: [u8; 16],
        role: LinkEndpointRole,
        result_tx: tokio::sync::oneshot::Sender<LinkEndpointUnbindResult>,
    },
    /// Reliably admit one packet into an established Link's ordered egress.
    SendLinkEndpoint {
        link_id: [u8; 16],
        role: LinkEndpointRole,
        request: OutboundRequest,
        result_tx: tokio::sync::oneshot::Sender<LinkEndpointSendResult>,
    },
    /// Reliably admit a packet only for the exact captured endpoint generation.
    /// The immutable authority remains attached while this command waits in a
    /// mailbox, so reusing a Link ID cannot redirect old Resource output.
    SendLinkEndpointExact {
        authority: crate::link_endpoint_dispatch::LinkEndpointDispatchToken,
        request: OutboundRequest,
        result_tx: tokio::sync::oneshot::Sender<LinkEndpointSendResult>,
    },
    /// Use the reliable send path for a final packet, then remove the endpoint
    /// and temporary Link destination after a successful FIFO drain or terminal
    /// failure. Failure can discard queued bytes; `Queued` does not guarantee
    /// eventual interface admission.
    SendLinkEndpointAndUnbind {
        link_id: [u8; 16],
        role: LinkEndpointRole,
        request: OutboundRequest,
        result_tx: tokio::sync::oneshot::Sender<LinkEndpointSendResult>,
    },
    /// Attempt exact-interface established-Link egress without entering the
    /// reliable per-Link FIFO. Intended for bounded realtime media only.
    SendLinkEndpointBestEffort {
        link_id: [u8; 16],
        role: LinkEndpointRole,
        request: OutboundRequest,
        result_tx: tokio::sync::oneshot::Sender<LinkEndpointSendResult>,
    },
    /// Dispatch a packet and reply with its immediate local admission result.
    /// Optional receipt registration occurs in the same actor turn. The result
    /// is not remote delivery; see `OutboundDispatchResult` for retained announces.
    SendPacket {
        request: OutboundRequest,
        attached_interface: Option<InterfaceId>,
        receipt: Option<TrackedReceiptRegistration>,
        result_tx: tokio::sync::oneshot::Sender<OutboundDispatchResult>,
    },
    /// Change a still-pending receipt duration relative to its original send time,
    /// without restarting the timer. Reply is false if no pending receipt matches.
    SetReceiptTimeout {
        truncated_hash: [u8; 16],
        timeout: std::time::Duration,
        result_tx: tokio::sync::oneshot::Sender<bool>,
    },
    Tick(TimerTick),
    /// Query or mutation paired with a reply. `TransportQuery` includes destructive
    /// cache operations; admission is not an authorization check.
    Rpc {
        query: TransportQuery,
        response_tx: tokio::sync::oneshot::Sender<TransportQueryResponse>,
    },
    /// Register a local destination without an acknowledgment. A supplied delivery
    /// channel replaces the previous one; `None` leaves an existing channel intact.
    RegisterDestination {
        hash: [u8; 16],
        app_name: String,
        delivery_tx: Option<mpsc::Sender<crate::link_messages::DestinationEvent>>,
    },
    /// Remove the local destination registration and its delivery channel.
    DeregisterDestination {
        hash: [u8; 16],
    },
    /// Install a legacy bounded callback channel without a registration reply.
    /// Full channels drop events; a closed channel is reaped.
    RegisterAnnounceHandler {
        aspect_filter: Option<String>,
        receive_path_responses: bool,
        callback_tx: mpsc::Sender<AnnounceHandlerEvent>,
    },
    /// Register one owned announce subscription and acknowledge once the actor
    /// has installed it. `dropped_events` counts full-channel dispatch failures.
    /// If the registration reply cannot be delivered, the subscription is removed.
    RegisterAnnounceSubscription {
        aspect_filter: Option<String>,
        receive_path_responses: bool,
        callback_tx: mpsc::Sender<AnnounceHandlerEvent>,
        dropped_events: Arc<AtomicU64>,
        result_tx: tokio::sync::oneshot::Sender<AnnounceHandlerId>,
    },
    /// Remove matching legacy handlers; `None` selects all legacy handlers.
    /// Active exact subscriptions are not selected by this filter. Closed handlers
    /// of either kind are also reaped.
    DeregisterAnnounceHandler {
        aspect_filter: Option<String>,
    },
    /// Remove the exact subscription identified by `id`, and reap closed handlers.
    /// An optional reply reports whether that ID was present.
    DeregisterAnnounceSubscription {
        id: AnnounceHandlerId,
        result_tx: Option<tokio::sync::oneshot::Sender<bool>>,
    },
    /// Replay a matching packet from the local on-disk announce cache when
    /// available. On a miss, a network CacheRequest is emitted only when transport
    /// is enabled. This command has no success reply.
    CacheRequest {
        packet_hash: [u8; 32],
        destination_hash: [u8; 16],
    },
    /// Request discovery using default explicit-request options; no reply is sent.
    RequestPath {
        destination_hash: [u8; 16],
    },
    /// Request discovery with explicit interface/tag policy; no reply is sent.
    RequestPathWithOptions {
        destination_hash: [u8; 16],
        options: PathRequestOptions,
    },
    /// Register an interface with current ownership and valid packet capacity.
    /// Replacement requires a newer owner generation. Rejected entries are
    /// ignored without a reply.
    RegisterInterface {
        id: InterfaceId,
        entry: InterfaceEntry,
    },
    /// Remove an interface through its current owner-bound event; bare commands
    /// are rejected so an old driver cannot remove a replacement.
    DeregisterInterface {
        id: InterfaceId,
    },
    /// Set trusted local storage and synchronously load saved state. File errors
    /// are logged, not returned; initialization may also migrate legacy cache data.
    SetStoragePaths {
        storage_dir: std::path::PathBuf,
    },
    /// Change forwarding mode and identity/persistence policy. Disabling transport
    /// also cancels pending background announce and recursive-discovery work.
    SetTransportEnabled {
        enabled: bool,
    },
    /// Set the internal identity hash and recompute the visible transport hash
    /// according to forwarding/static-identity policy.
    SetTransportIdentity {
        identity_hash: [u8; 16],
    },
    /// Set accepted on-disk blackhole source filenames and load matching entries.
    /// This does not purge entries already loaded from other sources.
    SetBlackholeSources {
        sources: Vec<[u8; 16]>,
    },
    /// Handle loss of the current shared-instance peer: invalidate routing state
    /// and terminate peer-bound Link endpoints. This is not a blanket pause of
    /// all packet processing. Submit through the current interface owner.
    SharedConnectionLost,
    /// Restore the current shared-instance peer and invalidate prior routing
    /// state. Submit through that interface owner.
    SharedConnectionRestored {
        interface_id: InterfaceId,
    },
    /// Driver-built tunnel synthesis packet ready for transmission on the
    /// given interface. The actor does not build these because it does not
    /// hold the signing identity.
    SynthesizeTunnel {
        interface_id: InterfaceId,
        raw_packet: Bytes,
    },
    /// Register a legacy receipt for later proof matching and destination fan-out.
    /// An existing entry with the same truncated hash is replaced. The caller must
    /// provide packet hashes and a trusted destination key that belong together.
    RegisterReceipt {
        truncated_hash: [u8; 16],
        full_hash: [u8; 32],
        /// Destination used to construct the packet. The caller is responsible
        /// for authenticating its supplied public key before registration.
        destination_hash: [u8; 16],
        destination_public_key: [u8; 64],
        msg_id: String,
        /// Override default 180s timeout when `Some`.
        timeout: Option<std::time::Duration>,
    },
    /// Register a receipt with an unbounded direct proof sink, replacing an
    /// existing entry with the same truncated hash. This avoids bounded mailbox
    /// capacity loss, but a closed receiver can still lose the notification.
    /// The caller must authenticate and bind the supplied key/hashes; `None`
    /// timeout uses 180 seconds.
    RegisterReceiptWithProof {
        truncated_hash: [u8; 16],
        full_hash: [u8; 32],
        destination_hash: [u8; 16],
        destination_public_key: [u8; 64],
        msg_id: String,
        timeout: Option<std::time::Duration>,
        proof_tx: mpsc::UnboundedSender<crate::link_messages::DestinationEvent>,
    },
    /// Record local Link bookkeeping after ownership/capacity checks. Initiators
    /// remain pending until `ActivateLink`; responder entries start validated.
    /// This command trusts the caller to have performed the corresponding protocol
    /// checks and does not itself prove a handshake.
    RegisterLink {
        interface_owner: Option<InterfaceOwnerId>,
        link_id: [u8; 16],
        destination_hash: [u8; 16],
        interface_id: InterfaceId,
        next_hop: Option<[u8; 16]>,
        remaining_hops: u8,
        initiator: bool,
    },
    /// Mark an existing Link entry validated and established. This command
    /// performs no cryptographic handshake verification itself.
    ActivateLink {
        link_id: [u8; 16],
    },
    /// Reply true if a non-expired path is cached or subsequently learned, and
    /// otherwise initiate discovery and park a waiter. Maintenance expires waiters
    /// after 15 seconds; that is not a strict caller deadline or reachability proof.
    /// Use `await_path` to bound command admission plus the reply wait.
    AwaitPath {
        dest: [u8; 16],
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    /// Request actor shutdown and its synchronous state-save path. There is no
    /// completion reply, and this is not a durability acknowledgment.
    Shutdown,
}

/// Static string name for a `TransportMessage` variant, used as a `msg`
/// field on the `actor.handle_message` span. Using a fixed &'static str
/// keeps the span field cheap (no allocation in the hot path).
pub fn msg_variant_name(msg: &TransportMessage) -> &'static str {
    match msg {
        TransportMessage::InterfaceEvent { .. } => "InterfaceEvent",
        TransportMessage::SendLinkRequest { .. } => "SendLinkRequest",
        TransportMessage::Inbound(_) => "Inbound",
        TransportMessage::Outbound(_) => "Outbound",
        TransportMessage::OutboundAttached { .. } => "OutboundAttached",
        TransportMessage::BindLinkEndpoint { .. } => "BindLinkEndpoint",
        TransportMessage::UnbindLinkEndpoint { .. } => "UnbindLinkEndpoint",
        TransportMessage::SendLinkEndpoint { .. } => "SendLinkEndpoint",
        TransportMessage::SendLinkEndpointExact { .. } => "SendLinkEndpointExact",
        TransportMessage::SendLinkEndpointAndUnbind { .. } => "SendLinkEndpointAndUnbind",
        TransportMessage::SendLinkEndpointBestEffort { .. } => "SendLinkEndpointBestEffort",
        TransportMessage::SendPacket { .. } => "SendPacket",
        TransportMessage::SetReceiptTimeout { .. } => "SetReceiptTimeout",
        TransportMessage::Tick(_) => "Tick",
        TransportMessage::Rpc { .. } => "Rpc",
        TransportMessage::RegisterDestination { .. } => "RegisterDestination",
        TransportMessage::DeregisterDestination { .. } => "DeregisterDestination",
        TransportMessage::RegisterAnnounceHandler { .. } => "RegisterAnnounceHandler",
        TransportMessage::RegisterAnnounceSubscription { .. } => "RegisterAnnounceSubscription",
        TransportMessage::DeregisterAnnounceHandler { .. } => "DeregisterAnnounceHandler",
        TransportMessage::DeregisterAnnounceSubscription { .. } => "DeregisterAnnounceSubscription",
        TransportMessage::CacheRequest { .. } => "CacheRequest",
        TransportMessage::RequestPath { .. } => "RequestPath",
        TransportMessage::RequestPathWithOptions { .. } => "RequestPathWithOptions",
        TransportMessage::RegisterInterface { .. } => "RegisterInterface",
        TransportMessage::DeregisterInterface { .. } => "DeregisterInterface",
        TransportMessage::SetStoragePaths { .. } => "SetStoragePaths",
        TransportMessage::SetTransportEnabled { .. } => "SetTransportEnabled",
        TransportMessage::SetTransportIdentity { .. } => "SetTransportIdentity",
        TransportMessage::SetBlackholeSources { .. } => "SetBlackholeSources",
        TransportMessage::SharedConnectionLost => "SharedConnectionLost",
        TransportMessage::SharedConnectionRestored { .. } => "SharedConnectionRestored",
        TransportMessage::SynthesizeTunnel { .. } => "SynthesizeTunnel",
        TransportMessage::RegisterReceipt { .. } => "RegisterReceipt",
        TransportMessage::RegisterReceiptWithProof { .. } => "RegisterReceiptWithProof",
        TransportMessage::RegisterLink { .. } => "RegisterLink",
        TransportMessage::ActivateLink { .. } => "ActivateLink",
        TransportMessage::AwaitPath { .. } => "AwaitPath",
        TransportMessage::Shutdown => "Shutdown",
    }
}

/// Local introspection and mutation operations carried by `TransportMessage::Rpc`.
/// These variants are not an access-control boundary. Responses describe local
/// state and command results, not remote presence or persistence guarantees.
#[derive(Debug, Clone)]
pub enum TransportQuery {
    /// Return currently non-expired paths; presence is not proof of reachability.
    GetPathTable,
    /// Read metadata, counters and optional synchronous driver inspection.
    /// Missing counters report zero; absent online state reports true. Rate fields
    /// are currently zero placeholders, not measured throughput.
    GetInterfaceStats,
    GetRateTable,
    GetLinkCount,
    GetRecentAnnounces,
    /// Return cached identity metadata without updating `last_used`. Locally
    /// restored cache metadata is trusted; this query performs no fresh signature
    /// verification, age check or network presence check.
    RecallDestination {
        dest: [u8; 16],
    },
    /// Whether a non-expired path currently exists for `dest`.
    HasPath {
        dest: [u8; 16],
    },
    /// Hop count for a non-expired path, or `PATHFINDER_M` when unknown.
    HopsTo {
        dest: [u8; 16],
    },
    GetNextHop {
        dest: [u8; 16],
    },
    GetNextHopIfName {
        dest: [u8; 16],
    },
    GetNextHopBitrate {
        dest: [u8; 16],
    },
    GetNextHopHardwareMtu {
        dest: [u8; 16],
    },
    GetNextHopInterfaceId {
        dest: [u8; 16],
    },
    GetPacketRssi {
        packet_hash: [u8; 32],
    },
    GetPacketSnr {
        packet_hash: [u8; 32],
    },
    GetPacketQ {
        packet_hash: [u8; 32],
    },
    /// Return 500*8/declared first-hop bitrate + 6 seconds. A missing route,
    /// interface or positive bitrate falls back to 6 seconds. This uses the
    /// protocol 500-byte MTU, not the reported hardware MTU.
    FirstHopTimeout {
        dest: [u8; 16],
    },
    /// Return 500*8/declared interface bitrate in seconds, or zero when no positive
    /// bitrate is available. This is a caller timing estimate; unvalidated
    /// transport-table retention is separately bitrate-independent.
    ExtraLinkProofTimeout {
        interface_id: InterfaceId,
    },
    DropPath {
        dest: [u8; 16],
    },
    /// Temporarily reject new path installs through this interface for the
    /// destination. Duration must be positive and finite. This does not remove
    /// the current route or guarantee that an alternative will be learned.
    SuppressPathInterface {
        dest: [u8; 16],
        interface_id: InterfaceId,
        duration: f64,
    },
    /// Apply suppression to the current non-expired path interface. Returns false
    /// without such a path or for an invalid duration; the existing route remains.
    SuppressCurrentPathInterface {
        dest: [u8; 16],
        duration: f64,
    },
    DropAnnounceQueues,
    GetBlackholedIdentities,
    BlackholeIdentity {
        hash: [u8; 16],
        ttl: Option<f64>,
        reason: crate::blackhole::BlackholeReason,
        reason_label: Option<String>,
    },
    UnblackholeIdentity {
        hash: [u8; 16],
    },
    /// Single-hash blackhole lookup returning `BoolResult`.
    IsBlackholed {
        hash: [u8; 16],
    },
    /// Drop every non-Manual entry; response is `IntResult(count_cleared)`.
    /// Separate from unblackhole-by-hash so operators can flush auto-populated
    /// entries without losing their explicit blocks.
    ClearSystemBlackholes,
    /// Build a MessagePack manifest from local entries whose identity public keys
    /// are present in the announce cache. `publisher` is caller-supplied. This
    /// operation neither signs the manifest nor freshly verifies cached identities.
    BuildBlackholeManifest {
        publisher: [u8; 16],
    },
    /// Decode and merge a MessagePack manifest. Caller must authenticate its source
    /// and apply authorization policy first: this query does not verify a publisher
    /// or bind inner source fields to a trusted peer. Returns operation count or error.
    ApplyBlackholeManifest {
        payload: Vec<u8>,
    },
    /// Set a registered interface's shared online flag false if present. This does
    /// not invoke a driver shutdown; an absent flag is still reported as `Ok`.
    HaltInterface {
        id: InterfaceId,
    },
    /// Set a registered interface's shared online flag true if present. This does
    /// not reopen a driver; an absent flag is still reported as `Ok`.
    ResumeInterface {
        id: InterfaceId,
    },
    /// Remove paths using a next hop and return the removed count. This operation
    /// does not itself mark routing state dirty or confirm a disk save.
    DropAllVia {
        next_hop: [u8; 16],
    },
    /// Clear cached routes and pending discovery state, then attempt a synchronous
    /// routing-state save. `IntResult` is the removed route count; save failures
    /// are logged and do not change that response.
    DropPathTable,
    /// Clear cached announce metadata and attempt a synchronous routing-state
    /// save. The returned count does not confirm persistence. Individual on-disk
    /// packet-cache files are not removed by this operation.
    DropRecentAnnounces,
    /// Serialize the actor's status tuple: a list of interface key/value string
    /// pairs and, optionally, Link count. This local helper is not the authenticated
    /// remote-management service or a general wire-compatibility guarantee.
    RemoteStatus {
        include_link_count: bool,
    },
    /// Serialize local path entries filtered by destination and hop limit. Each
    /// entry contains hex destination, hops, timestamp and interface name. Expired
    /// entries can remain until culling; `command` is currently ignored. This is
    /// not the authenticated remote-management service.
    RemotePath {
        command: String,
        destination: Option<[u8; 16]>,
        max_hops: Option<u8>,
    },
    SetPathState {
        dest: [u8; 16],
        state: crate::constants::PathState,
    },
    GetPathState {
        dest: [u8; 16],
    },
    PathIsUnresponsive {
        dest: [u8; 16],
    },
    /// Pin known announce metadata against age-based maintenance cleanup. Returns
    /// false if unknown. Explicit cache clearing still removes retained entries;
    /// use `UnretainDestination` to release the pin.
    RetainDestination {
        dest: [u8; 16],
    },
    RetainIdentity {
        identity_hash: [u8; 16],
    },
    UseDestination {
        dest: [u8; 16],
    },
    UnretainDestination {
        dest: [u8; 16],
    },
    /// Run announce-metadata cleanup now and return the remaining count. Periodic
    /// cleanup is additionally subject to its interval and startup-grace gates.
    CleanKnownDestinations,
    /// Resolve a raw 16-byte value as a destination first, then as an identity hash,
    /// using cached public keys. Returns `HashResult(None)` on a miss. This does
    /// not freshly authenticate the cache or contact a peer.
    ResolveIdentityHash {
        input: [u8; 16],
    },
    /// Batch lookup answering "which of these destinations belong to a
    /// currently-blackholed identity?". Composes `recent_announces` and the
    /// blackhole table inside the actor so callers never juggle hash types.
    /// Response: `BlackholedDests(Vec<dest_hash>)`.
    FilterBlackholedDests {
        dests: Vec<[u8; 16]>,
    },
    /// Remove Manual blackhole entries whose identity has no matching cached
    /// public key. The returned count reflects cache presence, not identity validity;
    /// a legitimate but unseen or pruned identity can be removed.
    PurgeUnverifiedBlackholes,
}

/// Local actor results. `Ok` confirms handling only; individual operations
/// define their own admission, cache and persistence limits.
#[derive(Debug)]
pub enum TransportQueryResponse {
    PathTable(Vec<PathTableRpcEntry>),
    InterfaceStats(Vec<InterfaceStatRpcEntry>),
    RateTable(Vec<RateTableRpcEntry>),
    Announces(Vec<AnnounceRpcEntry>),
    RecalledDestination(Option<RecalledDestinationRpcEntry>),
    IntResult(i64),
    FloatResult(Option<f64>),
    StringResult(Option<String>),
    HashResult(Option<[u8; 16]>),
    BoolResult(bool),
    PathStateResult(crate::constants::PathState),
    BlackholeList(Vec<BlackholeRpcEntry>),
    /// Subset of dest hashes supplied to `FilterBlackholedDests` whose
    /// announcer identity is currently blackholed.
    BlackholedDests(Vec<[u8; 16]>),
    /// Pre-serialized binary payload (msgpack for remote-* RPCs).
    Data(Vec<u8>),
    Ok,
    Error(String),
}

/// Snapshot of a cached route. Times are Unix seconds; returned interface
/// metadata can use fallback values if the interface is no longer registered.
#[derive(Debug, Clone)]
pub struct PathTableRpcEntry {
    pub hash: [u8; 16],
    pub timestamp: f64,
    pub via: Option<[u8; 16]>,
    pub hops: u8,
    pub expires: f64,
    pub interface: String,
    pub interface_id: InterfaceId,
    pub interface_mode: InterfaceMode,
    pub interface_role: InterfaceRole,
}

/// Interface metadata and sampled counters. Driver counters use independent
/// atomic reads, so this is not a coherent instant across all fields. Missing
/// counters become zero and missing online state becomes true; current
/// `rx_rate`/`tx_rate` values are zero placeholders. `bitrate` is declared bits
/// per second, `mtu` is reported bytes, `ifac_size` is configured bytes, and
/// `announce_cap` is a fraction. Names can contain caller-supplied text.
#[derive(Debug, Clone, Default)]
pub struct InterfaceStatRpcEntry {
    pub id: InterfaceId,
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub online: bool,
    pub bitrate: u64,
    pub mtu: u32,
    pub mode: String,
    pub role: String,
    pub announce_queue: Option<u64>,
    pub held_announces: u64,
    pub incoming_announce_frequency: f64,
    pub outgoing_announce_frequency: f64,
    pub incoming_pr_frequency: f64,
    pub outgoing_pr_frequency: f64,
    pub burst_active: bool,
    pub burst_activated: f64,
    pub pr_burst_active: bool,
    pub pr_burst_activated: f64,
    pub clients: Option<u64>,
    pub blocked_ips: Option<u64>,
    pub announce_rate_target: Option<f64>,
    pub announce_rate_grace: Option<u32>,
    pub announce_rate_penalty: Option<f64>,
    pub announce_cap: f64,
    pub ifac_size: usize,
    pub tx_drops: u64,
    pub tx_dropped_bytes: u64,
    /// Announces counted by the interface ingress controller.
    pub announces_received: u64,
    pub announces_sent: u64,
    pub path_requests_received: u64,
    pub path_requests_sent: u64,
    pub protocol_violations: u64,
    pub ifac_violations: u64,
    pub packet_filter_hits: u64,
    /// The listener that accepted this interface.
    pub parent_id: Option<InterfaceId>,
}

/// Announce-rate state: rate is announces per second; timestamps, `last` and
/// `blocked_until` are Unix seconds. A zero deadline means no active penalty.
#[derive(Debug, Clone)]
pub struct RateTableRpcEntry {
    pub hash: [u8; 16],
    pub rate: f64,
    pub last: f64,
    pub rate_violations: u32,
    pub blocked_until: f64,
    pub timestamps: Vec<f64>,
}

/// Cached announce metadata, possibly restored from trusted local storage.
/// This snapshot does not freshly verify a signature or establish a live path.
#[derive(Debug, Clone)]
pub struct AnnounceRpcEntry {
    pub dest_hash: [u8; 16],
    pub hops: u8,
    pub app_data: Option<Vec<u8>>,
    pub timestamp: f64,
    pub public_key: Option<[u8; 64]>,
    pub ratchet: Option<[u8; 32]>,
    /// Ten-byte announce name hash from the destination's expanded hash name,
    /// which can include aspects and a generated-identity suffix.
    pub name_hash: [u8; 10],
    /// True when the cached announce arrived as a path response instead of a
    /// fresh network announce.
    pub is_path_response: bool,
    /// Pinned via `RetainDestination`; the maintenance sweep skips the
    /// entry regardless of age while this is `true`.
    pub retained: bool,
}

/// Identity-bearing metadata returned by [`TransportQuery::RecallDestination`].
/// It is trusted cache content, not a fresh signature or reachability result.
#[derive(Debug, Clone)]
pub struct RecalledDestinationRpcEntry {
    pub dest_hash: [u8; 16],
    pub public_key: [u8; 64],
    pub app_data: Option<Vec<u8>>,
    pub ratchet: Option<[u8; 32]>,
    pub hops: u8,
    pub timestamp: f64,
}

/// Blackhole-table snapshot. Times and TTL are seconds; source attribution
/// can come from stored metadata or the local transport identity fallback.
#[derive(Debug, Clone)]
pub struct BlackholeRpcEntry {
    pub identity_hash: [u8; 16],
    pub source: Option<[u8; 16]>,
    pub created: f64,
    /// `None` means permanent.
    pub ttl: Option<f64>,
    pub reason: crate::blackhole::BlackholeReason,
    pub reason_label: Option<String>,
    /// Whether a currently cached public key hashes to `identity_hash`. This is
    /// a cache-presence test, not fresh signature validation, proof of reachability
    /// or a judgment that an absent identity is invalid.
    pub verified: bool,
}

impl std::fmt::Debug for TransportMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendLinkRequest { request, .. } => {
                f.debug_tuple("SendLinkRequest").field(request).finish()
            }
            Self::InterfaceEvent {
                interface_id,
                owner,
                message,
            } => f
                .debug_struct("InterfaceEvent")
                .field("interface_id", interface_id)
                .field("owner", owner)
                .field("message", message)
                .finish(),
            Self::Inbound(p) => f.debug_tuple("Inbound").field(p).finish(),
            Self::Outbound(r) => f.debug_tuple("Outbound").field(r).finish(),
            Self::OutboundAttached {
                request,
                interface_id,
            } => f
                .debug_struct("OutboundAttached")
                .field("request", request)
                .field("interface_id", interface_id)
                .finish(),
            Self::BindLinkEndpoint { binding, .. } => f
                .debug_struct("BindLinkEndpoint")
                .field("binding", binding)
                .finish_non_exhaustive(),
            Self::UnbindLinkEndpoint { link_id, role, .. } => f
                .debug_struct("UnbindLinkEndpoint")
                .field("link_id", link_id)
                .field("role", role)
                .finish_non_exhaustive(),
            Self::SendLinkEndpoint {
                link_id,
                role,
                request,
                ..
            } => f
                .debug_struct("SendLinkEndpoint")
                .field("link_id", link_id)
                .field("role", role)
                .field("request", request)
                .finish_non_exhaustive(),
            Self::SendLinkEndpointExact {
                authority, request, ..
            } => f
                .debug_struct("SendLinkEndpointExact")
                .field("binding", &authority.binding())
                .field("request", request)
                .finish_non_exhaustive(),
            Self::SendLinkEndpointAndUnbind {
                link_id,
                role,
                request,
                ..
            } => f
                .debug_struct("SendLinkEndpointAndUnbind")
                .field("link_id", link_id)
                .field("role", role)
                .field("request", request)
                .finish_non_exhaustive(),
            Self::SendLinkEndpointBestEffort {
                link_id,
                role,
                request,
                ..
            } => f
                .debug_struct("SendLinkEndpointBestEffort")
                .field("link_id", link_id)
                .field("role", role)
                .field("request", request)
                .finish_non_exhaustive(),
            Self::SendPacket {
                request,
                attached_interface,
                receipt,
                ..
            } => f
                .debug_struct("SendPacket")
                .field("request", request)
                .field("attached_interface", attached_interface)
                .field("receipt", receipt)
                .finish(),
            Self::SetReceiptTimeout {
                truncated_hash,
                timeout,
                ..
            } => f
                .debug_struct("SetReceiptTimeout")
                .field("truncated_hash", truncated_hash)
                .field("timeout", timeout)
                .finish_non_exhaustive(),
            Self::Tick(t) => f.debug_tuple("Tick").field(t).finish(),
            Self::Rpc { query, .. } => f.debug_struct("Rpc").field("query", query).finish(),
            Self::RegisterDestination { hash, app_name, .. } => f
                .debug_struct("RegisterDestination")
                .field("hash", hash)
                .field("app_name", app_name)
                .finish(),
            Self::DeregisterDestination { hash } => f
                .debug_struct("DeregisterDestination")
                .field("hash", hash)
                .finish(),
            Self::RegisterAnnounceHandler { aspect_filter, .. } => f
                .debug_struct("RegisterAnnounceHandler")
                .field("aspect_filter", aspect_filter)
                .finish(),
            Self::RegisterAnnounceSubscription { aspect_filter, .. } => f
                .debug_struct("RegisterAnnounceSubscription")
                .field("aspect_filter", aspect_filter)
                .finish(),
            Self::DeregisterAnnounceHandler { aspect_filter } => f
                .debug_struct("DeregisterAnnounceHandler")
                .field("aspect_filter", aspect_filter)
                .finish(),
            Self::DeregisterAnnounceSubscription { id, .. } => f
                .debug_struct("DeregisterAnnounceSubscription")
                .field("id", id)
                .finish(),
            Self::CacheRequest {
                packet_hash,
                destination_hash,
            } => f
                .debug_struct("CacheRequest")
                .field("packet_hash", packet_hash)
                .field("destination_hash", destination_hash)
                .finish(),
            Self::RequestPath { destination_hash } => f
                .debug_struct("RequestPath")
                .field("destination_hash", destination_hash)
                .finish(),
            Self::RequestPathWithOptions {
                destination_hash,
                options,
            } => f
                .debug_struct("RequestPathWithOptions")
                .field("destination_hash", destination_hash)
                .field("options", options)
                .finish(),
            Self::RegisterInterface { id, entry } => f
                .debug_struct("RegisterInterface")
                .field("id", id)
                .field("entry", entry)
                .finish(),
            Self::DeregisterInterface { id } => f
                .debug_struct("DeregisterInterface")
                .field("id", id)
                .finish(),
            Self::SetStoragePaths { storage_dir } => f
                .debug_struct("SetStoragePaths")
                .field("storage_dir", storage_dir)
                .finish(),
            Self::SetTransportEnabled { enabled } => f
                .debug_struct("SetTransportEnabled")
                .field("enabled", enabled)
                .finish(),
            Self::SetTransportIdentity { identity_hash } => f
                .debug_struct("SetTransportIdentity")
                .field("identity_hash", identity_hash)
                .finish(),
            Self::SetBlackholeSources { sources } => f
                .debug_struct("SetBlackholeSources")
                .field("sources", sources)
                .finish(),
            Self::SharedConnectionLost => f.debug_struct("SharedConnectionLost").finish(),
            Self::SharedConnectionRestored { interface_id } => f
                .debug_struct("SharedConnectionRestored")
                .field("interface_id", interface_id)
                .finish(),
            Self::SynthesizeTunnel { interface_id, .. } => f
                .debug_struct("SynthesizeTunnel")
                .field("interface_id", interface_id)
                .finish(),
            Self::RegisterReceipt {
                truncated_hash,
                msg_id,
                ..
            } => f
                .debug_struct("RegisterReceipt")
                .field("truncated_hash", truncated_hash)
                .field("msg_id", msg_id)
                .finish(),
            Self::RegisterReceiptWithProof {
                truncated_hash,
                msg_id,
                ..
            } => f
                .debug_struct("RegisterReceiptWithProof")
                .field("truncated_hash", truncated_hash)
                .field("msg_id", msg_id)
                .finish(),
            Self::RegisterLink {
                link_id,
                destination_hash,
                initiator,
                ..
            } => f
                .debug_struct("RegisterLink")
                .field("link_id", link_id)
                .field("destination_hash", destination_hash)
                .field("initiator", initiator)
                .finish(),
            Self::ActivateLink { link_id } => f
                .debug_struct("ActivateLink")
                .field("link_id", link_id)
                .finish(),
            Self::AwaitPath { dest, .. } => {
                f.debug_struct("AwaitPath").field("dest", dest).finish()
            }
            Self::Shutdown => write!(f, "Shutdown"),
        }
    }
}
