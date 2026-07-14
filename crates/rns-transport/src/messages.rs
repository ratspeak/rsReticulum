//! Actor-model interface for the transport.
//!
//! Every routing state mutation flows through `TransportMessage` into the
//! single task that owns the routing tables. This eliminates shared mutable
//! state and its locking on the hot path; other components interact with the
//! transport exclusively via `mpsc` senders and `oneshot` reply channels.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::constants::{InterfaceDirection, InterfaceMode};
pub use crate::ingress::HeldAnnounce;
use crate::ingress::IngressController;

pub type InterfaceId = u64;

/// Transport-level role of an interface. Python Reticulum distinguishes
/// ordinary network interfaces, the local shared-instance listener, accepted
/// local clients behind that listener, and the one interface a leaf process uses
/// to reach an existing shared instance. Several routing rules depend on that
/// distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterfaceRole {
    #[default]
    Normal,
    SharedServer,
    LocalClient,
    SharedInstancePeer,
}

impl InterfaceRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::SharedServer => "shared_server",
            Self::LocalClient => "local_client",
            Self::SharedInstancePeer => "shared_instance_peer",
        }
    }
}

#[derive(Debug)]
pub struct InboundPacket {
    pub raw: Bytes,
    pub interface_id: InterfaceId,
    pub rssi: Option<f32>,
    pub snr: Option<f32>,
    pub q: Option<f32>,
}

#[derive(Debug)]
pub struct OutboundRequest {
    pub raw: Bytes,
    pub destination_hash: [u8; 16],
}

/// Periodic maintenance tick. Drives cache culling, retransmit scheduling,
/// and rate-limit decay so the actor needs no internal timer.
#[derive(Debug)]
pub struct TimerTick {
    pub timestamp: f64,
}

/// Metadata and TX handle for one registered interface. The actor owns the
/// sender; driver code holds only the matching receiver.
pub struct InterfaceEntry {
    pub name: String,
    pub mode: InterfaceMode,
    pub role: InterfaceRole,
    pub direction: InterfaceDirection,
    pub bitrate: u64,
    pub mtu: u32,
    pub tx: mpsc::Sender<Bytes>,
    pub ifac_key: Option<[u8; 64]>,
    pub ifac_size: usize,
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
    /// Incremented when an outbound `try_send` cannot enqueue — surfaced in
    /// interface stats to flag a driver whose receiver is falling behind.
    pub tx_drops: Arc<std::sync::atomic::AtomicU64>,
    pub ingress: IngressController,
    /// Announces awaiting bandwidth-capped retransmission. Drained in
    /// hop-priority order (lowest hops first, oldest among ties).
    pub announce_queue: Vec<QueuedAnnounce>,
    /// Multipoint medium whose peers cannot hear each other (e.g. BLE Peer:
    /// each peer is a separate point-to-point GATT link presented as one
    /// interface). Unlike a shared broadcast medium, an announce arriving on
    /// such an interface must be relayed back out the SAME interface to reach
    /// its other peers. Loop safety comes from the announce-table dedup + hop
    /// cap and the driver's own per-peer anti-loop filter.
    pub multipoint: bool,
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
            name,
            mode,
            role: InterfaceRole::Normal,
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
            tx_drops: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ingress: IngressController::new(),
            announce_queue: Vec::new(),
            multipoint: false,
        }
    }

    pub fn with_multipoint(mut self, multipoint: bool) -> Self {
        self.multipoint = multipoint;
        self
    }

    pub fn with_ifac(mut self, key: [u8; 64], size: usize) -> Self {
        self.ifac_key = Some(key);
        self.ifac_size = size;
        self
    }

    pub fn with_announce_rate(mut self, target: f64, grace: u32, penalty: f64) -> Self {
        self.announce_rate_target = Some(target);
        self.announce_rate_grace = Some(grace);
        self.announce_rate_penalty = Some(penalty);
        self
    }

    pub fn with_role(mut self, role: InterfaceRole) -> Self {
        self.role = role;
        self
    }

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
            .field("direction", &self.direction)
            .field("bitrate", &self.bitrate)
            .field("mtu", &self.mtu)
            .field("ifac_size", &self.ifac_size)
            .field("announce_cap", &self.announce_cap)
            .field("announce_allowed_at", &self.announce_allowed_at)
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
    /// `SHA-256(app_name)[:10]` of the aspect this destination announced
    /// under. Zero array if the announce arrived without a payload (degenerate
    /// case — handlers with `aspect_filter == None` still receive it).
    pub name_hash: [u8; 10],
}

/// Every mutation of transport state enters through this enum — the actor
/// dispatches on the variant, so adding a new operation is a matter of adding
/// a variant and a match arm rather than exposing a new lock or shared type.
// This is the transport actor's public message surface. Boxing individual
// variants would churn all senders/receivers for little runtime benefit.
#[allow(clippy::large_enum_variant)]
pub enum TransportMessage {
    Inbound(InboundPacket),
    Outbound(OutboundRequest),
    OutboundAttached {
        request: OutboundRequest,
        interface_id: InterfaceId,
    },
    Tick(TimerTick),
    /// Read-only query paired with a oneshot reply channel — used for all
    /// RPC and introspection so callers don't need direct state access.
    Rpc {
        query: TransportQuery,
        response_tx: tokio::sync::oneshot::Sender<TransportQueryResponse>,
    },
    RegisterDestination {
        hash: [u8; 16],
        app_name: String,
        delivery_tx: Option<mpsc::Sender<crate::link_messages::DestinationEvent>>,
    },
    DeregisterDestination {
        hash: [u8; 16],
    },
    RegisterAnnounceHandler {
        aspect_filter: Option<String>,
        receive_path_responses: bool,
        callback_tx: mpsc::Sender<AnnounceHandlerEvent>,
    },
    /// Remove handler(s) whose `aspect_filter` matches; `None` removes all.
    /// Handlers with closed senders are also reaped on dispatch.
    DeregisterAnnounceHandler {
        aspect_filter: Option<String>,
    },
    /// Ask the actor to satisfy a packet request: replay from its recent-
    /// announce cache when possible, otherwise emit a CacheRequest packet.
    CacheRequest {
        packet_hash: [u8; 32],
        destination_hash: [u8; 16],
    },
    RequestPath {
        destination_hash: [u8; 16],
    },
    RegisterInterface {
        id: InterfaceId,
        entry: InterfaceEntry,
    },
    DeregisterInterface {
        id: InterfaceId,
    },
    SetStoragePaths {
        storage_dir: std::path::PathBuf,
    },
    SetTransportEnabled {
        enabled: bool,
    },
    SetTransportIdentity {
        identity_hash: [u8; 16],
    },
    SetBlackholeSources {
        sources: Vec<[u8; 16]>,
    },
    /// Shared-instance connection dropped; pause packet processing until the
    /// matching `SharedConnectionRestored` arrives.
    SharedConnectionLost,
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
    /// Register an outbound-packet receipt so the inbound path can match
    /// arriving proofs back to `msg_id`.
    RegisterReceipt {
        truncated_hash: [u8; 16],
        full_hash: [u8; 32],
        msg_id: String,
        /// Override default 180s timeout when `Some`.
        timeout: Option<std::time::Duration>,
    },
    /// Record a new link in the table. `initiator=true` means we started the
    /// handshake, so the entry is pending until `ActivateLink` arrives.
    RegisterLink {
        link_id: [u8; 16],
        destination_hash: [u8; 16],
        interface_id: InterfaceId,
        next_hop: Option<[u8; 16]>,
        remaining_hops: u8,
        initiator: bool,
    },
    /// Promote a pending (initiator) link to validated.
    ActivateLink {
        link_id: [u8; 16],
    },
    /// Block the caller until a path to `dest` is learned or the caller's
    /// timeout fires. Used by request APIs that must not return before
    /// forwarding is possible.
    AwaitPath {
        dest: [u8; 16],
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    Shutdown,
}

/// Static string name for a `TransportMessage` variant, used as a `msg`
/// field on the `actor.handle_message` span. Using a fixed &'static str
/// keeps the span field cheap (no allocation in the hot path).
pub fn msg_variant_name(msg: &TransportMessage) -> &'static str {
    match msg {
        TransportMessage::Inbound(_) => "Inbound",
        TransportMessage::Outbound(_) => "Outbound",
        TransportMessage::OutboundAttached { .. } => "OutboundAttached",
        TransportMessage::Tick(_) => "Tick",
        TransportMessage::Rpc { .. } => "Rpc",
        TransportMessage::RegisterDestination { .. } => "RegisterDestination",
        TransportMessage::DeregisterDestination { .. } => "DeregisterDestination",
        TransportMessage::RegisterAnnounceHandler { .. } => "RegisterAnnounceHandler",
        TransportMessage::DeregisterAnnounceHandler { .. } => "DeregisterAnnounceHandler",
        TransportMessage::CacheRequest { .. } => "CacheRequest",
        TransportMessage::RequestPath { .. } => "RequestPath",
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
        TransportMessage::RegisterLink { .. } => "RegisterLink",
        TransportMessage::ActivateLink { .. } => "ActivateLink",
        TransportMessage::AwaitPath { .. } => "AwaitPath",
        TransportMessage::Shutdown => "Shutdown",
    }
}

/// Read-mostly queries carried by `TransportMessage::Rpc`.
#[derive(Debug, Clone)]
pub enum TransportQuery {
    GetPathTable,
    GetInterfaceStats,
    GetRateTable,
    GetLinkCount,
    GetRecentAnnounces,
    GetNextHop {
        dest: [u8; 16],
    },
    GetNextHopIfName {
        dest: [u8; 16],
    },
    GetNextHopBitrate {
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
    /// First-hop timeout: `MTU * per_byte_latency + DEFAULT_PER_HOP_TIMEOUT`.
    FirstHopTimeout {
        dest: [u8; 16],
    },
    /// Extra link-proof timeout for a slow interface: `MTU * per_byte_latency`.
    ExtraLinkProofTimeout {
        interface_id: InterfaceId,
    },
    DropPath {
        dest: [u8; 16],
    },
    /// Temporarily reject path-table installs for `dest` learned through
    /// `interface_id`. Used after link establishment failure so rediscovery can
    /// consider alternate interfaces instead of immediately reselecting the
    /// path that just failed.
    SuppressPathInterface {
        dest: [u8; 16],
        interface_id: InterfaceId,
        duration: f64,
    },
    /// Temporarily reject path-table installs for `dest` learned through the
    /// interface that currently owns the path.
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
    /// Build this node's distributed blackhole `/list` manifest. Response is
    /// `Data(msgpack)`.
    BuildBlackholeManifest {
        publisher: [u8; 16],
    },
    /// Merge a distributed blackhole `/list` manifest. Response is
    /// `IntResult(count_applied)`.
    ApplyBlackholeManifest {
        payload: Vec<u8>,
    },
    HaltInterface {
        id: InterfaceId,
    },
    ResumeInterface {
        id: InterfaceId,
    },
    DropAllVia {
        next_hop: [u8; 16],
    },
    /// Drop every cached route from the path table and persist the empty table.
    /// Response: `IntResult(count_cleared)`.
    DropPathTable,
    /// Drop every cached announce snapshot and persist the empty cache.
    /// Response: `IntResult(count_cleared)`.
    DropRecentAnnounces,
    /// Remote-status RPC — interface stats + optional link count, wire-format
    /// compatible with `Transport.remote_status_handler`.
    RemoteStatus {
        include_link_count: bool,
    },
    /// Remote-path RPC — path table filtered by destination and hop limit,
    /// wire-format compatible with `Transport.remote_path_handler`.
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
    /// Pin / unpin a destination from the cache. While retained, the
    /// maintenance sweep will not reap the entry regardless of age.
    /// Returns `BoolResult(true)` when the destination is known to the
    /// cache, `false` when not.
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
    /// Immediate cleanup trigger. Returns `IntResult(entries_remaining)`.
    /// The actor tick runs cleanup every 5 minutes regardless.
    CleanKnownDestinations,
    /// Resolve a 16-byte hex blob — which may be either a destination hash or
    /// an identity hash — to a canonical identity hash via `recent_announces`.
    /// Returns `HashResult(Some(_))` on hit, `HashResult(None)` when the input
    /// is neither a known destination nor a known identity. Read-only.
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
    /// Drop every Manual blackhole entry whose identity is not currently in
    /// `recent_announces`. Returns `IntResult(count_purged)`. Use sparingly —
    /// this can drop legit-but-unseen entries.
    PurgeUnverifiedBlackholes,
    /// Recall the 64-byte identity public key for a destination previously
    /// learned from a validated announce (`recent_announces`). Used by
    /// `LinkClient` so Nomad/page browsers skip a fresh path-response wait when
    /// the key is already cached. Response: `PublicKeyResult`.
    RecallDestinationPublicKey {
        dest: [u8; 16],
    },
}

#[derive(Debug)]
pub enum TransportQueryResponse {
    PathTable(Vec<PathTableRpcEntry>),
    InterfaceStats(Vec<InterfaceStatRpcEntry>),
    RateTable(Vec<RateTableRpcEntry>),
    Announces(Vec<AnnounceRpcEntry>),
    IntResult(i64),
    FloatResult(Option<f64>),
    StringResult(Option<String>),
    HashResult(Option<[u8; 16]>),
    /// 64-byte `X25519_pub || Ed25519_pub` for `RecallDestinationPublicKey`.
    PublicKeyResult(Option<[u8; 64]>),
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

#[derive(Debug, Clone)]
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
    pub announce_rate_target: Option<f64>,
    pub announce_rate_grace: Option<u32>,
    pub announce_rate_penalty: Option<f64>,
    pub announce_cap: f64,
    pub ifac_size: usize,
    pub tx_drops: u64,
}

#[derive(Debug, Clone)]
pub struct RateTableRpcEntry {
    pub hash: [u8; 16],
    pub rate: f64,
    pub last: f64,
    pub rate_violations: u32,
    pub blocked_until: f64,
    pub timestamps: Vec<f64>,
}

#[derive(Debug, Clone)]
pub struct AnnounceRpcEntry {
    pub dest_hash: [u8; 16],
    pub hops: u8,
    pub app_data: Option<Vec<u8>>,
    pub timestamp: f64,
    pub public_key: Option<[u8; 64]>,
    pub ratchet: Option<[u8; 32]>,
    /// `SHA-256(app_name)[:10]` for the announced aspect.
    pub name_hash: [u8; 10],
    /// True when the cached announce arrived as a path response instead of a
    /// fresh network announce.
    pub is_path_response: bool,
    /// Pinned via `RetainDestination`; the maintenance sweep skips the
    /// entry regardless of age while this is `true`.
    pub retained: bool,
}

#[derive(Debug, Clone)]
pub struct BlackholeRpcEntry {
    pub identity_hash: [u8; 16],
    pub source: Option<[u8; 16]>,
    pub created: f64,
    /// `None` means permanent.
    pub ttl: Option<f64>,
    pub reason: crate::blackhole::BlackholeReason,
    pub reason_label: Option<String>,
    /// True if `recent_announces` currently contains an announce whose public
    /// key hashes to `identity_hash`. False means we cannot confirm this entry
    /// is a real identity — it may be garbage from a pre-fix caller, or a real
    /// identity whose announce we have not yet received / has been pruned.
    pub verified: bool,
}

impl std::fmt::Debug for TransportMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
            Self::DeregisterAnnounceHandler { aspect_filter } => f
                .debug_struct("DeregisterAnnounceHandler")
                .field("aspect_filter", aspect_filter)
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
