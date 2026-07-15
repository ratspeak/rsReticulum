use crate::now_f64;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

use crate::announce::AnnounceTable;
use crate::blackhole::BlackholeTable;
use crate::constants::*;
use crate::hashlist::PacketHashlist;
use crate::link_table::LinkTable;
use crate::messages::{
    InterfaceEntry, InterfaceId, InterfaceRole, TransportMessage, msg_variant_name,
};
use crate::path_table::PathTable;
use crate::rate_limit::RateTable;
use crate::reverse_table::ReverseTable;
use crate::traffic::TrafficCounter;
use crate::tunnel::TunnelTable;
use rns_wire::receipt::{PacketReceipt, ReceiptStatus};

mod inbound;
mod maintenance;
mod outbound;
mod persistence;
mod rpc;

/// Owns every routing table and drains the `TransportMessage` channel in one
/// task. The single-owner model means the hot path has no shared state and no
/// locks — callers drive the actor by sending typed commands rather than
/// reaching into the tables directly.
pub struct TransportActor {
    rx: mpsc::Receiver<TransportMessage>,

    pub path_table: PathTable,
    pub link_table: LinkTable,
    pub announce_table: AnnounceTable,
    /// Python `held_announces`: normal queued announces temporarily displaced
    /// while a known-path response occupies `announce_table`.
    pub held_announces: HashMap<[u8; 16], crate::announce::AnnounceEntry>,
    pub reverse_table: ReverseTable,
    pub tunnel_table: TunnelTable,
    pub packet_hashlist: PacketHashlist,
    pub rate_table: RateTable,
    pub blackhole_table: BlackholeTable,
    pub traffic: TrafficCounter,
    pub packet_metrics: HashMap<[u8; 32], PacketMetrics>,
    pub packet_metrics_order: VecDeque<[u8; 32]>,

    pub receipt_table: HashMap<[u8; 16], PacketReceipt>,
    /// Truncated packet hash → LXMF msg_id for pairing delivery proofs back
    /// to their originating outbound message.
    pub receipt_msg_ids: HashMap<[u8; 16], String>,

    pub interfaces: HashMap<InterfaceId, InterfaceEntry>,

    pub local_destinations: HashSet<[u8; 16]>,
    pub destination_channels:
        HashMap<[u8; 16], mpsc::Sender<crate::link_messages::DestinationEvent>>,
    pub path_requests: HashMap<[u8; 16], f64>,
    /// Python `discovery_path_requests`: external interfaces waiting for a
    /// matching announce while this transport recursively searches elsewhere.
    pub discovery_path_requests: HashMap<[u8; 16], DiscoveryPathRequest>,
    /// Python `discovery_pr_tags`: destination hash plus truncated path-request tag.
    pub discovery_pr_tags: HashMap<Vec<u8>, f64>,
    /// Python `pending_discovery_prs`: failed-link rediscovery requests queued
    /// for throttled emission.
    pub pending_discovery_prs: VecDeque<PendingDiscoveryPathRequest>,
    /// Destination/interface pairs temporarily barred from installing paths.
    /// Used when a Direct LinkRequest timed out on one route, so the next
    /// path request can discover alternates instead of instantly reusing it.
    pub path_interface_suppressions: HashMap<([u8; 16], InterfaceId), f64>,
    last_discovery_pr_tx: f64,
    /// External interface waiting for a path response from a local shared client.
    /// Python calls this `pending_local_path_requests`.
    pub pending_local_path_requests: HashMap<[u8; 16], InterfaceId>,
    pub path_states: HashMap<[u8; 16], PathState>,

    /// Tasks blocked on `AwaitPath`. Each entry pairs the oneshot reply with
    /// the registration timestamp so `expire_path_waiters` can bound how long
    /// a caller can wait before receiving a negative result.
    pub path_waiters: HashMap<[u8; 16], Vec<(tokio::sync::oneshot::Sender<bool>, f64)>>,

    last_tables_cull: f64,
    last_links_check: f64,
    last_receipts_check: f64,
    last_announces_check: f64,
    last_cache_clean: f64,
    /// Last on-disk announce-cache sweep. 0.0 until the first sweep is
    /// actually scheduled, so a tick that fires before storage init doesn't
    /// consume the boot slot.
    last_announce_cache_sweep: f64,
    last_blackhole_check: f64,
    last_rate_cull: f64,
    last_held_announce_check: f64,

    pub is_transport_enabled: bool,
    /// Wire-facing transport identity (Python `Transport.identity`): HEADER_2
    /// path responses, link-request transport_id matching, local next-hop
    /// answers. On non-transport nodes this rotates per boot by default —
    /// see `apply_transport_identity_policy`.
    pub transport_identity_hash: Option<[u8; 16]>,
    /// Persisted transport identity (Python 1.3.8 `Transport._identity`,
    /// Transport.py:211-215). RPC-key derivation and operator identification
    /// stay bound to this; never emitted on the wire when the ephemeral
    /// policy is active.
    pub internal_identity_hash: Option<[u8; 16]>,
    /// Per-boot ephemeral identity hash substituted for the persisted one
    /// when transport is disabled and `static_transport_identity` is unset
    /// (Python 1.3.8 Transport.py:234-238). Generated lazily once per boot;
    /// the runtime may pre-seed it with the hash of a full ephemeral
    /// `Identity` so runtime-side consumers (discovery announcer, blackhole
    /// publisher) share the same value.
    pub ephemeral_identity_hash: Option<[u8; 16]>,
    /// Python 1.3.8 `static_transport_identity` config key (Reticulum.py:502-504,
    /// default false): opts a non-transport node out of the per-boot ephemeral
    /// transport identity. Set by the runtime before spawn.
    pub static_transport_identity: bool,
    /// Python 1.3.8 `Transport.local_hops_delta` (Transport.py:167,240): when
    /// the `local_hops_delta` config key is set, a per-boot random 2..=7
    /// replaces the hops byte of locally-originated packets at egress
    /// (`should_apply_delta`/`mangle_hops`). 0 = disabled (the default). Set
    /// by the runtime before spawn.
    pub local_hops_delta: u8,
    pub blackhole_sources: Vec<[u8; 16]>,
    /// Live snapshot of currently blackholed identity hashes, shared with the
    /// runtime's link layer so the LINKIDENTIFY handler can tear down links
    /// from blackholed identities (Python 1.3.8 Link.py:966-968) without an
    /// actor round-trip. Rebuilt on every blackhole-table mutation.
    pub blackholed_snapshot: Arc<std::sync::RwLock<HashSet<[u8; 16]>>>,

    /// True when connected to a shared Reticulum instance — the transport
    /// defers to the shared instance for routing decisions rather than
    /// originating them locally.
    pub is_shared_instance: bool,
    /// Sticky process-mode marker for shared-instance clients. It remains true
    /// after a shared connection drops so shutdown cannot persist an empty
    /// local routing table over the real shared instance's cache.
    pub shared_instance_client_mode: bool,

    pub storage_dir: Option<PathBuf>,

    /// Last save (Unix seconds) — gates the periodic save tick. 0 forces an
    /// initial baseline write after storage initialisation.
    pub last_state_save: f64,

    /// Set when persisted-state mutates; cleared after each `save_state`.
    /// Gates the periodic tick so idle devices don't spin disk uselessly.
    pub state_dirty: bool,
    /// Guards the blocking-pool routing-state writer; concurrent writers
    /// would race on the shared `<file>.tmp` paths.
    pub routing_save_in_flight: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub hashlist_save_in_flight: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Guards the blocking-pool announce-cache sweep (Python parity with the
    /// non-blocking `cache_clean_lock`: an in-flight sweep skips the pass).
    pub announce_sweep_in_flight: std::sync::Arc<std::sync::atomic::AtomicBool>,

    /// Persisted path entries waiting on their interface to re-register.
    /// Drained by `drain_pending_for_interface` on `RegisterInterface`.
    pub pending_path_entries: Vec<crate::persistence::PersistedPathEntry>,
    /// Tunnel-table equivalent of `pending_path_entries`.
    pub pending_tunnel_entries: Vec<crate::persistence::PersistedTunnelEntry>,

    /// Cache of recently learnt announces, keyed by dest_hash for O(1) upsert.
    pub recent_announces: HashMap<[u8; 16], RecentAnnounce>,

    /// Grace window before cache cleaning runs — protects freshly restored
    /// entries from being aged out before real traffic refreshes them.
    startup_complete: bool,
    startup_time: f64,

    /// Try_send failures into destination channels (diagnostic gauge).
    pub channel_drops: u64,

    announce_handlers: Vec<AnnounceHandlerRegistration>,

    /// Foreground/background flag shared with the app layer. Flipping to
    /// background switches the maintenance tick to the long interval so the
    /// actor stops burning CPU (and battery) while the app is suspended.
    pub is_foreground: Arc<AtomicBool>,
}

/// Cached announce metadata for diagnostics + CacheRequest replay. Raw
/// announce bytes live on disk (`cache/announces/<packet_hash>`, written
/// event-driven at receive — Python `Transport.cache` parity) and are fetched
/// via `packet_hash`; keeping them in RAM doubled per-destination retention
/// and dominated the periodic state snapshot. `retained` pins the entry
/// against the cull sweep (`RetainDestination` / `UnretainDestination`).
#[derive(Debug, Clone)]
pub struct RecentAnnounce {
    pub dest_hash: [u8; 16],
    pub hops: u8,
    pub app_data: Option<Vec<u8>>,
    /// Announce receive time (Python `known_destinations[0]`). Not bumped on
    /// use — see `last_used`.
    pub timestamp: f64,
    pub public_key: Option<[u8; 64]>,
    pub ratchet: Option<[u8; 32]>,
    /// Disk-cache key for the raw announce. `None` for legacy entries whose
    /// cache file could not be recovered; replay paths treat that as a miss.
    pub packet_hash: Option<[u8; 32]>,
    /// Captured at receive so RPC consumers don't re-parse the raw packet.
    pub is_path_response: bool,
    pub retained: bool,
    /// Last `UseDestination` touch (Python `known_destinations[4]`). Drives
    /// the `UNUSED_DESTINATION_LINGER` sweep for pathless entries.
    pub last_used: Option<f64>,
    /// `SHA-256(app_name)[:10]` so cache consumers can filter by aspect
    /// without re-parsing the announce. Zeroed if the announce had no payload.
    pub name_hash: [u8; 10],
}

#[derive(Debug, Clone, Copy)]
pub struct DiscoveryPathRequest {
    pub requesting_interface: InterfaceId,
    pub timeout: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingDiscoveryPathRequest {
    pub destination_hash: [u8; 16],
    pub blocked_interface: Option<InterfaceId>,
}

struct AnnounceHandlerRegistration {
    aspect_filter: Option<String>,
    receive_path_responses: bool,
    tx: tokio::sync::mpsc::Sender<crate::messages::AnnounceHandlerEvent>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PacketMetrics {
    pub rssi: Option<f32>,
    pub snr: Option<f32>,
    pub q: Option<f32>,
}

impl TransportActor {
    pub fn new() -> (Self, mpsc::Sender<TransportMessage>) {
        Self::new_with_capacity(4096, HASHLIST_MAXSIZE)
    }

    /// Benchmarks at scale override both caps to avoid running the host out of
    /// memory with synthetic traffic.
    pub fn new_with_capacity(
        channel_cap: usize,
        hashlist_cap: usize,
    ) -> (Self, mpsc::Sender<TransportMessage>) {
        let (tx, rx) = mpsc::channel(channel_cap);

        let actor = Self {
            rx,
            path_table: PathTable::new(),
            link_table: LinkTable::new(),
            announce_table: AnnounceTable::new(),
            held_announces: HashMap::new(),
            reverse_table: ReverseTable::new(),
            tunnel_table: TunnelTable::new(),
            packet_hashlist: PacketHashlist::new_with_capacity(hashlist_cap),
            rate_table: RateTable::new(),
            blackhole_table: BlackholeTable::new(),
            traffic: TrafficCounter::new(),
            packet_metrics: HashMap::new(),
            packet_metrics_order: VecDeque::new(),
            receipt_table: HashMap::new(),
            receipt_msg_ids: HashMap::new(),
            interfaces: HashMap::new(),
            local_destinations: HashSet::new(),
            destination_channels: HashMap::new(),
            path_requests: HashMap::new(),
            discovery_path_requests: HashMap::new(),
            discovery_pr_tags: HashMap::new(),
            pending_discovery_prs: VecDeque::new(),
            path_interface_suppressions: HashMap::new(),
            last_discovery_pr_tx: 0.0,
            pending_local_path_requests: HashMap::new(),
            path_states: HashMap::new(),
            path_waiters: HashMap::new(),
            last_tables_cull: 0.0,
            last_links_check: 0.0,
            last_receipts_check: 0.0,
            last_announces_check: 0.0,
            last_cache_clean: 0.0,
            last_announce_cache_sweep: 0.0,
            last_blackhole_check: 0.0,
            last_rate_cull: 0.0,
            last_held_announce_check: 0.0,
            is_transport_enabled: false,
            transport_identity_hash: None,
            internal_identity_hash: None,
            ephemeral_identity_hash: None,
            static_transport_identity: false,
            local_hops_delta: 0,
            blackhole_sources: Vec::new(),
            blackholed_snapshot: Arc::new(std::sync::RwLock::new(HashSet::new())),
            is_shared_instance: false,
            shared_instance_client_mode: false,
            storage_dir: None,
            last_state_save: 0.0,
            state_dirty: false,
            routing_save_in_flight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            hashlist_save_in_flight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            announce_sweep_in_flight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
            pending_path_entries: Vec::new(),
            pending_tunnel_entries: Vec::new(),
            recent_announces: HashMap::new(),
            startup_complete: false,
            startup_time: 0.0,
            channel_drops: 0,
            announce_handlers: Vec::new(),
            is_foreground: Arc::new(AtomicBool::new(true)),
        };

        (actor, tx)
    }

    /// Load persisted state before the actor starts draining live traffic.
    ///
    /// Startup restore can touch thousands of Python cache files on slow
    /// storage. Doing that work after `run()` starts blocks interface
    /// registration, RPC queries and inbound packet processing behind a
    /// synchronous `SetStoragePaths` message.
    pub fn initialize_storage(&mut self, storage_dir: PathBuf) {
        self.storage_dir = Some(storage_dir);
        self.load_state();
    }

    /// Run the actor event loop. Messages are processed sequentially so no
    /// routing state is ever touched from two tasks at once.
    pub async fn run(mut self) {
        let mut tick_interval = tokio::time::interval(Duration::from_millis(JOB_INTERVAL_MS));
        let mut was_foreground = true;

        loop {
            tokio::select! {
                msg = self.rx.recv() => {
                    match msg {
                        Some(TransportMessage::Shutdown) | None => {
                            self.on_shutdown();
                            break;
                        }
                        Some(msg) => self.handle_message(msg),
                    }
                }
                _ = tick_interval.tick() => {
                    let is_fg = self.is_foreground.load(std::sync::atomic::Ordering::Relaxed);
                    if is_fg != was_foreground {
                        if is_fg {
                            // Foreground resume: full maintenance pass now.
                            self.on_resume();
                        } else {
                            // Background: flush state so an OS kill (force-quit,
                            // OOM) cannot lose this session's learnings. Async —
                            // on desktop this edge fires on every focus loss.
                            self.save_state_async();
                        }
                        #[cfg(feature = "mobile-throttle")]
                        {
                            let ms = if is_fg { JOB_INTERVAL_MS } else { JOB_INTERVAL_BG_MS };
                            tick_interval = tokio::time::interval(Duration::from_millis(ms));
                            tick_interval.tick().await;
                        }
                        was_foreground = is_fg;
                    }
                    self.on_tick();
                }
            }
        }
    }

    fn handle_message(&mut self, msg: TransportMessage) {
        let variant = msg_variant_name(&msg);
        let _span =
            tracing::span!(tracing::Level::DEBUG, "actor.handle_message", msg = variant).entered();
        match msg {
            TransportMessage::Inbound(packet) => {
                self.on_inbound(packet);
            }
            TransportMessage::Outbound(request) => {
                self.on_outbound(request);
            }
            TransportMessage::OutboundAttached {
                request,
                interface_id,
            } => {
                self.on_outbound_attached(request, interface_id);
            }
            TransportMessage::Tick(_) => {
                self.on_tick();
            }
            TransportMessage::RegisterDestination {
                hash,
                app_name,
                delivery_tx,
            } => {
                self.local_destinations.insert(hash);
                if let Some(tx) = delivery_tx {
                    self.destination_channels.insert(hash, tx.clone());
                    // On a shared-instance connection, the destination is
                    // brand new to the shared peer; fire an announce so it
                    // learns the path immediately instead of waiting for the
                    // next scheduled broadcast.
                    if self.is_shared_instance {
                        if let Err(e) =
                            tx.try_send(crate::link_messages::DestinationEvent::AnnounceRequested(
                                crate::link_messages::AnnounceRequest::normal(app_name.clone()),
                            ))
                        {
                            self.channel_drops += 1;
                            warn!(dest = hex::encode(hash), drops = self.channel_drops, err = %e,
                                "failed to send AnnounceRequested (channel full)");
                        }
                        debug!(
                            dest = hex::encode(hash),
                            "auto-announce triggered for shared instance registration"
                        );
                    }
                }
            }
            TransportMessage::DeregisterDestination { hash } => {
                self.local_destinations.remove(&hash);
                self.destination_channels.remove(&hash);
            }
            TransportMessage::CacheRequest {
                packet_hash,
                destination_hash,
            } => {
                // Serve straight from the disk announce cache (Python parity:
                // cache_request_packet reads the cache file), then replay
                // through our own inbound path (interface_id=0 marks it as
                // locally injected, not from the wire).
                if let Some(raw) = self.cached_announce_raw(&packet_hash) {
                    debug!(hash = %hex::encode(&packet_hash[..8]), "cache request: local hit, replaying");
                    let inbound = crate::messages::InboundPacket {
                        raw: Bytes::from(raw),
                        interface_id: 0,
                        rssi: None,
                        snr: None,
                        q: None,
                    };
                    self.on_inbound(inbound);
                    return;
                }

                // Local miss: only transport nodes forward the request
                // outward — a leaf can't usefully relay a cache query.
                if self.is_transport_enabled {
                    debug!(hash = %hex::encode(&packet_hash[..8]), "cache request: local miss, querying network");
                    let flags = rns_wire::flags::PacketFlags {
                        header_type: rns_wire::flags::HeaderType::Header1,
                        context_flag: false,
                        transport_type: rns_wire::flags::TransportType::Broadcast,
                        destination_type: rns_wire::flags::DestinationType::Single,
                        packet_type: rns_wire::flags::PacketType::Data,
                    };
                    let header = rns_wire::header::PacketHeader {
                        flags,
                        hops: 0,
                        transport_id: None,
                        destination_hash,
                        context: rns_wire::context::PacketContext::CacheRequest,
                    };
                    let mut raw = header.pack();
                    raw.extend_from_slice(&packet_hash);
                    self.broadcast_on_interfaces(&raw, None);
                }
            }
            TransportMessage::RequestPath { destination_hash } => {
                self.on_path_request(destination_hash);
            }
            TransportMessage::Rpc { query, response_tx } => {
                let response = self.handle_query(query);
                let _ = response_tx.send(response);
            }
            TransportMessage::RegisterAnnounceHandler {
                aspect_filter,
                receive_path_responses,
                callback_tx,
            } => {
                self.announce_handlers.push(AnnounceHandlerRegistration {
                    aspect_filter,
                    receive_path_responses,
                    tx: callback_tx,
                });
            }
            TransportMessage::DeregisterAnnounceHandler { aspect_filter } => {
                // Also sweep closed channels here so deregister doubles as
                // garbage-collection for handlers whose owner dropped
                // without explicitly unregistering.
                self.announce_handlers.retain(|registration| {
                    if registration.tx.is_closed() {
                        return false;
                    }
                    if let Some(ref target) = aspect_filter {
                        registration.aspect_filter.as_ref() != Some(target)
                    } else {
                        true
                    }
                });
            }
            TransportMessage::SetTransportEnabled { enabled } => {
                debug!(enabled, "setting transport enabled");
                self.is_transport_enabled = enabled;
                // The runtime sends the identity before the enable flag, so
                // the swap decision must be re-evaluated here.
                self.apply_transport_identity_policy();
            }
            TransportMessage::SetTransportIdentity { identity_hash } => {
                debug!(
                    hash = hex::encode(identity_hash),
                    "setting transport identity"
                );
                self.internal_identity_hash = Some(identity_hash);
                self.apply_transport_identity_policy();
                self.load_python_blackhole_if_ready();
            }
            TransportMessage::SetBlackholeSources { sources } => {
                debug!(count = sources.len(), "setting blackhole sources");
                self.blackhole_sources = sources;
                self.load_python_blackhole_if_ready();
            }
            TransportMessage::SharedConnectionLost => {
                tracing::warn!("shared instance connection lost — suspending transport");
                self.is_shared_instance = false;
                self.shared_instance_client_mode = true;
                self.clear_shared_connection_state();
            }
            TransportMessage::SharedConnectionRestored { interface_id } => {
                tracing::info!(interface_id, "shared instance connection restored");
                self.shared_instance_client_mode = true;
                self.clear_shared_connection_state();
                self.is_shared_instance = true;
                self.request_announces_from_local_destinations();
            }
            TransportMessage::SynthesizeTunnel {
                interface_id,
                raw_packet,
            } => {
                debug!(
                    interface_id,
                    len = raw_packet.len(),
                    "sending tunnel synthesis packet"
                );
                self.send_to_interface(interface_id, &raw_packet);
            }
            TransportMessage::RegisterInterface { id, entry } => {
                let is_outbound = entry.direction.outbound;
                let iface_name = entry.name.clone();
                let role = entry.role;
                if role == InterfaceRole::LocalClient && interface_marked_offline(&entry) {
                    tracing::info!(
                        id,
                        name = %iface_name,
                        role = role.as_str(),
                        "skipping registration for interface already marked offline"
                    );
                    return;
                }
                debug!(id, name = %iface_name, outbound = is_outbound, role = role.as_str(), "registering interface");
                self.interfaces.insert(id, entry);
                if !self.startup_complete && self.startup_time == 0.0 {
                    self.startup_time = now_f64();
                }
                // Rebind any persisted path/tunnel entries that referenced
                // this interface by name. Done immediately on register so
                // queries from other code (e.g. announce replay below) see
                // the restored paths.
                self.drain_pending_for_interface(id, &iface_name);
                // Python interface registration does not trigger announce
                // retransmission. Cached/path-response announces stay queued
                // for the announce job, and local shared clients only receive
                // live announces or request-driven responses after connect.
            }
            TransportMessage::DeregisterInterface { id } => {
                debug!(id, "deregistering interface");
                self.deregister_interface(id);
            }
            TransportMessage::SetStoragePaths { storage_dir } => {
                debug!(path = %storage_dir.display(), "setting storage paths");
                self.storage_dir = Some(storage_dir);
                self.load_state();
            }
            TransportMessage::RegisterReceipt {
                truncated_hash,
                full_hash,
                msg_id,
                timeout,
            } => {
                let receipt = PacketReceipt::new(
                    full_hash,
                    truncated_hash,
                    Some(timeout.unwrap_or(std::time::Duration::from_secs(180))),
                );
                self.receipt_table.insert(truncated_hash, receipt);
                self.receipt_msg_ids.insert(truncated_hash, msg_id);
                debug!(
                    trunc = hex::encode(truncated_hash),
                    "registered receipt for outbound LXMF message"
                );
            }
            TransportMessage::RegisterLink {
                link_id,
                destination_hash,
                interface_id,
                next_hop,
                remaining_hops,
                initiator,
            } => {
                // Initiators start pending (validated=false) until the proof
                // arrives; non-initiators already hold a validated link.
                let now = now_f64();
                let entry = crate::link_table::LinkEntry {
                    timestamp: now,
                    next_hop,
                    interface_id,
                    remaining_hops,
                    destination_hash,
                    established: !initiator,
                    validated: !initiator,
                    proof_timeout: now + 60.0,
                    receiving_interface: interface_id,
                    taken_hops: 0,
                };
                self.link_table.insert(link_id, entry);

                // Link-addressed packets (LRRTT, Resource, Keepalive, …) use
                // link_id as their destination_hash, not the original
                // destination hash. Register link_id as a local destination
                // and route it to the parent's channel; otherwise those
                // packets hit the data router and get dropped as unroutable.
                self.local_destinations.insert(link_id);
                if let Some(tx) = self.destination_channels.get(&destination_hash) {
                    self.destination_channels.insert(link_id, tx.clone());
                }

                debug!(link_id = hex::encode(link_id), initiator, "registered link");
            }
            TransportMessage::ActivateLink { link_id } => {
                if let Some(entry) = self.link_table.get_mut(&link_id) {
                    entry.validated = true;
                    entry.established = true;
                    debug!(link_id = hex::encode(link_id), "activated link");
                } else {
                    tracing::warn!(
                        link_id = hex::encode(link_id),
                        "attempted to activate link not in pending table"
                    );
                }
            }
            TransportMessage::AwaitPath { dest, reply } => {
                if self.path_table.has_path(&dest) {
                    let _ = reply.send(true);
                } else {
                    self.on_path_request(dest);
                    let now = now_f64();
                    self.path_waiters
                        .entry(dest)
                        .or_default()
                        .push((reply, now));
                    debug!(dest = hex::encode(dest), "registered path waiter");
                }
            }
            TransportMessage::Shutdown => unreachable!(),
        }
    }

    fn is_local_client_interface(&self, id: InterfaceId) -> bool {
        self.interfaces
            .get(&id)
            .is_some_and(|entry| entry.role == InterfaceRole::LocalClient)
    }

    fn is_shared_instance_peer_interface(&self, id: InterfaceId) -> bool {
        self.interfaces
            .get(&id)
            .is_some_and(|entry| entry.role == InterfaceRole::SharedInstancePeer)
    }

    /// Python 1.3.8 Transport.should_apply_delta (Transport.py:1356-1359):
    /// mangle only locally-originated (hops==0) non-PLAIN/GROUP packets, never
    /// when this node is itself a shared-instance client, and never on
    /// local-client / shared-instance edges.
    fn should_apply_delta(
        &self,
        header: &rns_wire::header::PacketHeader,
        interface_id: InterfaceId,
    ) -> bool {
        self.local_hops_delta != 0
            && !self.is_shared_instance
            && header.hops == 0
            && header.flags.destination_type != rns_wire::flags::DestinationType::Plain
            && header.flags.destination_type != rns_wire::flags::DestinationType::Group
            && !self.is_local_client_interface(interface_id)
            && !self.is_shared_instance_peer_interface(interface_id)
    }

    /// Python 1.3.8 Transport.mangle_hops (Transport.py:1362-1365): rewrite
    /// the hops byte to the per-boot delta. `transport_insert` additionally
    /// re-frames a HEADER_1 announce as HEADER_2|TRANSPORT carrying this
    /// node's transport identity hash (packet grows by 17 bytes).
    fn mangle_hops(
        &self,
        raw: &[u8],
        header: &rns_wire::header::PacketHeader,
        transport_insert: bool,
    ) -> Vec<u8> {
        if transport_insert && let Some(transport_id) = self.transport_identity_hash {
            let mut flags = header.flags;
            flags.header_type = rns_wire::flags::HeaderType::Header2;
            flags.transport_type = rns_wire::flags::TransportType::Transport;
            let new_header = rns_wire::header::PacketHeader {
                flags,
                hops: self.local_hops_delta,
                transport_id: Some(transport_id),
                destination_hash: header.destination_hash,
                context: header.context,
            };
            let mut out = new_header.pack();
            out.extend_from_slice(&raw[header.size()..]);
            return out;
        }
        let mut out = raw.to_vec();
        out[1] = self.local_hops_delta;
        out
    }

    fn adjusted_inbound_hops(&self, raw_hops: u8, interface_id: InterfaceId) -> u8 {
        let mut hops = raw_hops.saturating_add(1);

        // Python Transport increments every inbound packet, then subtracts for
        // local shared-instance clients and for a leaf's shared-instance peer
        // interface. That keeps local clients spoofed as zero-hop while normal
        // external neighbours become one-hop paths.
        if self.has_local_client_interfaces() {
            if self.is_local_client_interface(interface_id) {
                hops = hops.saturating_sub(1);
            }
        } else if self.is_shared_instance_peer_interface(interface_id) {
            hops = hops.saturating_sub(1);
        }

        hops
    }

    fn has_local_client_interfaces(&self) -> bool {
        self.interfaces
            .values()
            .any(|entry| entry.role == InterfaceRole::LocalClient)
    }

    fn local_client_interface_ids_except(&self, except: Option<InterfaceId>) -> Vec<InterfaceId> {
        self.interfaces
            .iter()
            .filter_map(|(&id, entry)| {
                if except == Some(id) || entry.role != InterfaceRole::LocalClient {
                    None
                } else {
                    Some(id)
                }
            })
            .collect()
    }

    fn clear_shared_connection_state(&mut self) {
        self.path_table = PathTable::new();
        self.link_table = LinkTable::new();
        self.announce_table = AnnounceTable::new();
        self.held_announces.clear();
        self.reverse_table = ReverseTable::new();
        self.tunnel_table = TunnelTable::new();
        self.pending_path_entries.clear();
        self.pending_tunnel_entries.clear();
        self.path_requests.clear();
        self.path_states.clear();
        self.packet_metrics.clear();
        self.packet_metrics_order.clear();
        self.discovery_path_requests.clear();
        self.pending_local_path_requests.clear();
        self.pending_discovery_prs.clear();
        self.last_discovery_pr_tx = 0.0;
        self.state_dirty = true;
    }

    /// Python 1.3.8 Transport.py:234-238: when transport is disabled and
    /// `static_transport_identity` is unset (the default), the wire-facing
    /// transport identity becomes a fresh per-boot identity while the
    /// persisted one is retained as `internal_identity_hash`
    /// (`Transport._identity`). Re-evaluated on both SetTransportIdentity and
    /// SetTransportEnabled so the runtime's message order doesn't matter.
    fn apply_transport_identity_policy(&mut self) {
        let Some(internal) = self.internal_identity_hash else {
            return;
        };
        if !self.is_transport_enabled && !self.static_transport_identity {
            let ephemeral = *self
                .ephemeral_identity_hash
                .get_or_insert_with(|| rns_identity::identity::Identity::new().hash);
            if self.transport_identity_hash != Some(ephemeral) {
                debug!(
                    hash = hex::encode(ephemeral),
                    "initialized ephemeral transport identity"
                );
                self.transport_identity_hash = Some(ephemeral);
            }
        } else {
            self.transport_identity_hash = Some(internal);
        }
    }

    /// Rebuild the shared blackhole snapshot from the authoritative table.
    /// Called after every blackhole-table mutation; TTL-expired entries drop
    /// out here and on the periodic cull (Python parity: the 60s expiry job,
    /// Transport.py:986-1002).
    fn publish_blackhole_snapshot(&self) {
        let now = now_f64();
        let set: HashSet<[u8; 16]> = self
            .blackhole_table
            .iter_entries()
            .filter(|(_, entry)| entry.ttl.is_none_or(|ttl| now - entry.created < ttl))
            .map(|(hash, _)| hash.into_bytes())
            .collect();
        if let Ok(mut guard) = self.blackholed_snapshot.write() {
            *guard = set;
        }
    }

    fn record_packet_metrics(&mut self, packet_hash: [u8; 32], metrics: PacketMetrics) {
        if metrics.rssi.is_none() && metrics.snr.is_none() && metrics.q.is_none() {
            return;
        }
        if !self.packet_metrics.contains_key(&packet_hash) {
            self.packet_metrics_order.push_back(packet_hash);
        }
        self.packet_metrics.insert(packet_hash, metrics);
        while self.packet_metrics_order.len() > LOCAL_CLIENT_CACHE_MAXSIZE {
            if let Some(old_hash) = self.packet_metrics_order.pop_front() {
                self.packet_metrics.remove(&old_hash);
            }
        }
    }

    fn request_announces_from_local_destinations(&mut self) {
        let destinations: Vec<(
            [u8; 16],
            mpsc::Sender<crate::link_messages::DestinationEvent>,
        )> = self
            .destination_channels
            .iter()
            .map(|(hash, tx)| (*hash, tx.clone()))
            .collect();
        for (hash, tx) in destinations {
            if let Err(e) = tx.try_send(crate::link_messages::DestinationEvent::AnnounceRequested(
                crate::link_messages::AnnounceRequest::normal(String::new()),
            )) {
                self.channel_drops += 1;
                warn!(dest = hex::encode(hash), drops = self.channel_drops, err = %e,
                    "failed to send AnnounceRequested after shared instance reconnect");
            }
        }
    }

    fn send_announce_to_local_clients(
        &mut self,
        cached_raw: &[u8],
        destination_hash: [u8; 16],
        hops: u8,
        except: Option<InterfaceId>,
        context: rns_wire::context::PacketContext,
    ) {
        let ids = self.local_client_interface_ids_except(except);
        if ids.is_empty() {
            return;
        }
        let raw = self.transport_announce_from_raw(cached_raw, destination_hash, hops, context);
        for id in ids {
            self.send_to_interface(id, &raw);
        }
    }

    fn transport_announce_from_raw(
        &self,
        cached_raw: &[u8],
        destination_hash: [u8; 16],
        hops: u8,
        context: rns_wire::context::PacketContext,
    ) -> Vec<u8> {
        let Ok((cached_header, payload_offset)) =
            rns_wire::header::PacketHeader::unpack(cached_raw)
        else {
            return cached_raw.to_vec();
        };

        let Some(transport_id) = self.transport_identity_hash else {
            return cached_raw.to_vec();
        };

        let header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header2,
                context_flag: cached_header.flags.context_flag,
                transport_type: rns_wire::flags::TransportType::Transport,
                destination_type: rns_wire::flags::DestinationType::Single,
                packet_type: rns_wire::flags::PacketType::Announce,
            },
            hops,
            transport_id: Some(transport_id),
            destination_hash,
            context,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&cached_raw[payload_offset..]);
        raw
    }

    /// Returns the number of waiters that were notified.
    fn fire_path_waiters(&mut self, dest: &[u8; 16]) -> usize {
        if let Some(waiters) = self.path_waiters.remove(dest) {
            let n = waiters.len();
            for (reply, _created_at) in waiters {
                let _ = reply.send(true);
            }
            debug!(dest = hex::encode(dest), count = n, "fired path waiters");
            n
        } else {
            0
        }
    }

    /// Pin an entry so `cleanup` never reaps it. Exposed via `RetainDestination`.
    #[allow(dead_code)]
    pub(super) fn retain_destination(&mut self, dest_hash: &[u8; 16]) -> bool {
        if let Some(entry) = self.recent_announces.get_mut(dest_hash) {
            entry.retained = true;
            self.state_dirty = true;
            true
        } else {
            false
        }
    }

    /// Pin all cached announces made by `identity_hash`. Exposed via
    /// `RetainIdentity` for Python 1.2.5 rnid parity.
    pub(super) fn retain_identity(&mut self, identity_hash: &[u8; 16]) -> bool {
        let mut retained = false;
        for entry in self.recent_announces.values_mut() {
            let Some(public_key) = entry.public_key else {
                continue;
            };
            let computed_id_hash = rns_crypto::sha::truncated_hash(&public_key);
            if &computed_id_hash == identity_hash {
                entry.retained = true;
                retained = true;
            }
        }
        if retained {
            self.state_dirty = true;
        }
        retained
    }

    /// Mark a destination's cached metadata as used, matching Python's
    /// `_used_destination_data` refresh semantics for shared clients.
    /// `timestamp` stays the announce time (Python keeps announce time and
    /// use time as separate fields); the linger sweep reads `last_used`.
    pub(super) fn use_destination(&mut self, dest_hash: &[u8; 16]) -> bool {
        if let Some(entry) = self.recent_announces.get_mut(dest_hash) {
            entry.last_used = Some(now_f64());
            self.state_dirty = true;
            true
        } else {
            false
        }
    }

    /// Release a pin set by `retain_destination`; cleanup runs by `timestamp` again.
    #[allow(dead_code)]
    pub(super) fn unretain_destination(&mut self, dest_hash: &[u8; 16]) -> bool {
        if let Some(entry) = self.recent_announces.get_mut(dest_hash) {
            entry.retained = false;
            self.state_dirty = true;
            true
        } else {
            false
        }
    }

    /// Send `false` to any waiter that has been parked longer than
    /// `PATH_WAITER_TIMEOUT`, so a caller that lost its chance to race with
    /// a learned path doesn't wait forever.
    fn expire_path_waiters(&mut self, now: f64) {
        const PATH_WAITER_TIMEOUT: f64 = 15.0;

        // Remove-then-reinsert dodges the simultaneous mutable borrow that
        // would otherwise happen when partitioning in place.
        let keys: Vec<[u8; 16]> = self.path_waiters.keys().copied().collect();
        for dest in keys {
            if let Some(waiters) = self.path_waiters.remove(&dest) {
                let mut kept = Vec::new();
                for (reply, created_at) in waiters {
                    if now - created_at >= PATH_WAITER_TIMEOUT {
                        let _ = reply.send(false);
                    } else {
                        kept.push((reply, created_at));
                    }
                }
                if !kept.is_empty() {
                    self.path_waiters.insert(dest, kept);
                }
            }
        }
    }

    /// Drop `id` from the interface table and unwind tunnels + paths bound
    /// to it. Shared by `DeregisterInterface` and the `Closed`-tx auto-drop.
    fn deregister_interface(&mut self, id: InterfaceId) {
        let role = self.interfaces.get(&id).map(|entry| entry.role);
        // Flip the driver-shared online flag before dropping the entry:
        // driver tasks gated on it (Auto beacons/discovery, BLE loops) hold
        // their own Arc clones and would otherwise spin forever.
        if let Some(online) = self.interfaces.get(&id).and_then(|e| e.online.as_ref()) {
            online.store(false, std::sync::atomic::Ordering::SeqCst);
        }
        self.void_tunnel_interface(id);
        let dropped = self.path_table.drop_all_via(id);
        if dropped > 0 {
            debug!(id, dropped, "dropped paths via deregistered interface");
        }
        self.path_interface_suppressions
            .retain(|(_, interface_id), _| *interface_id != id);
        self.pending_local_path_requests
            .retain(|_, waiting_interface| *waiting_interface != id);
        self.discovery_path_requests
            .retain(|_, request| request.requesting_interface != id);
        self.interfaces.remove(&id);
        if role == Some(InterfaceRole::SharedInstancePeer) {
            tracing::warn!(
                interface_id = id,
                "shared instance peer interface deregistered — clearing shared routing state"
            );
            self.is_shared_instance = false;
            self.shared_instance_client_mode = true;
            self.clear_shared_connection_state();
        }
    }

    fn suppress_path_interface(
        &mut self,
        dest: [u8; 16],
        interface_id: InterfaceId,
        duration: f64,
    ) -> bool {
        if duration <= 0.0 || !duration.is_finite() {
            return false;
        }
        let until = now_f64() + duration;
        self.path_interface_suppressions
            .insert((dest, interface_id), until);
        debug!(
            dest = %hex::encode(dest),
            interface_id,
            duration,
            "temporarily suppressing path interface"
        );
        true
    }

    fn is_path_interface_suppressed(
        &mut self,
        dest: [u8; 16],
        interface_id: InterfaceId,
        now: f64,
    ) -> bool {
        let key = (dest, interface_id);
        match self.path_interface_suppressions.get(&key).copied() {
            Some(until) if now < until => true,
            Some(_) => {
                self.path_interface_suppressions.remove(&key);
                false
            }
            None => false,
        }
    }

    fn cull_path_interface_suppressions(&mut self, now: f64) {
        self.path_interface_suppressions
            .retain(|_, until| now < *until);
    }

    /// Send raw bytes on `id`, IFAC-wrapping first if configured.
    ///
    /// `try_send` failures: `Full` bumps `tx_drops`; `Closed` auto-deregisters
    /// (zombie interface — receiver dropped without DeregisterInterface).
    #[tracing::instrument(
        level = "trace",
        name = "actor.send_to_interface",
        skip_all,
        fields(interface_id = id, raw_len = raw.len()),
    )]
    fn send_to_interface(&mut self, id: InterfaceId, raw: &[u8]) {
        let Some(entry) = self.interfaces.get(&id) else {
            return;
        };
        if entry.role == InterfaceRole::LocalClient && interface_marked_offline(entry) {
            tracing::info!(
                interface_id = id,
                interface_name = %entry.name,
                "interface marked offline; auto-deregistering"
            );
            self.deregister_interface(id);
            return;
        }
        let Some(entry) = self.interfaces.get(&id) else {
            return;
        };
        if !entry.direction.outbound {
            return;
        }
        let data: Bytes = if let Some(ref ifac_key) = entry.ifac_key {
            Bytes::from(crate::ifac::ifac_sign(raw, ifac_key, entry.ifac_size))
        } else {
            Bytes::copy_from_slice(raw)
        };
        match entry.tx.try_send(data) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                let tx_drops = entry
                    .tx_drops
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                if tx_drops <= 8 || tx_drops.is_power_of_two() {
                    tracing::error!(
                        interface_id = id,
                        interface_name = %entry.name,
                        queue_remaining = entry.tx.capacity(),
                        queue_max = entry.tx.max_capacity(),
                        tx_drops,
                        "PACKET DROPPED: interface TX channel full"
                    );
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tracing::info!(
                    interface_id = id,
                    interface_name = %entry.name,
                    "interface TX channel closed (downstream task exited); auto-deregistering"
                );
                self.deregister_interface(id);
            }
        }
    }

    #[tracing::instrument(
        level = "trace",
        name = "actor.broadcast_on_interfaces",
        skip_all,
        fields(raw_len = raw.len()),
    )]
    fn broadcast_on_interfaces(&mut self, raw: &[u8], except: Option<InterfaceId>) {
        // Collect ids first so the borrow on self.interfaces ends before
        // send_to_interface (which may mutate it via auto-deregister) runs.
        let ids: Vec<InterfaceId> = self
            .interfaces
            .iter()
            .filter_map(|(&id, entry)| {
                if except == Some(id) || !entry.direction.outbound {
                    None
                } else {
                    Some(id)
                }
            })
            .collect();
        // Python 1.3.8 Transport.py:1342-1344: locally-originated non-announce
        // packets get the per-boot hops delta, decided per egress interface.
        let delta_header = (self.local_hops_delta != 0)
            .then(|| rns_wire::header::PacketHeader::unpack(raw).ok())
            .flatten()
            .map(|(header, _)| header);
        for id in ids {
            match &delta_header {
                Some(header) if self.should_apply_delta(header, id) => {
                    let mangled = self.mangle_hops(raw, header, false);
                    self.send_to_interface(id, &mangled);
                }
                _ => self.send_to_interface(id, raw),
            }
        }
    }

    fn interface_allows_announce(
        &self,
        id: InterfaceId,
        destination_hash: &[u8; 16],
        except: Option<InterfaceId>,
    ) -> bool {
        let Some(entry) = self.interfaces.get(&id) else {
            return false;
        };
        if !entry.direction.outbound {
            return false;
        }
        // Normally an announce is never sent back out its source interface
        // (loopback / dedup churn on a shared medium). A multipoint interface
        // (e.g. BLE Peer) is the exception: its peers can't hear each other, so
        // relaying back out reaches the ones the source peer couldn't. The
        // driver's per-peer anti-loop filter keeps it off the source peer, and
        // the announce-table dedup + hop cap bound propagation.
        if except == Some(id) && !entry.multipoint {
            return false;
        }

        // Python 1.3.8 Transport.py:1210-1240 hoists the instance-local check
        // and the announce's next-hop (learned-from) interface.
        // `from_iface_mode`: None = no live path; Some(None) = path via an
        // unregistered interface (Python's mode-less hasattr case);
        // Some(Some(mode)) otherwise. Never consulted for local destinations.
        let local = self.local_destinations.contains(destination_hash);
        let from_iface_mode = self
            .path_table
            .get_live(destination_hash)
            .map(|path| self.interfaces.get(&path.interface_id).map(|i| i.mode));

        // Mode-independent gate: a non-local announce whose next-hop interface
        // doesn't exist is never rebroadcast (Transport.py:1216-1218).
        if !local && from_iface_mode.is_none() {
            trace!(
                dest = hex::encode(destination_hash),
                interface = id,
                "blocking announce broadcast: next hop interface doesn't exist"
            );
            return false;
        }

        // Per-interface announces_from_internal opt-out for internal-origin
        // announces; checked before the egress-mode gates (Transport.py:1220).
        if !local
            && !entry.announces_from_internal
            && from_iface_mode == Some(Some(InterfaceMode::Internal))
        {
            trace!(
                dest = hex::encode(destination_hash),
                interface = id,
                "blocking announce broadcast: internal-mode next hop interface"
            );
            return false;
        }

        match entry.mode {
            InterfaceMode::AccessPoint => false,
            InterfaceMode::Internal => {
                // Internal egress relays everything except boundary-origin and
                // mode-less-origin announces (Transport.py:1228-1236).
                local
                    || !matches!(
                        from_iface_mode,
                        Some(None) | Some(Some(InterfaceMode::Boundary))
                    )
            }
            InterfaceMode::Roaming => {
                local
                    || !matches!(
                        from_iface_mode,
                        Some(None) | Some(Some(InterfaceMode::Roaming | InterfaceMode::Boundary))
                    )
            }
            InterfaceMode::Boundary => {
                local
                    || !matches!(
                        from_iface_mode,
                        Some(None) | Some(Some(InterfaceMode::Roaming))
                    )
            }
            InterfaceMode::Full | InterfaceMode::PointToPoint | InterfaceMode::Gateway => true,
        }
    }

    fn broadcast_local_announce_on_interfaces(&mut self, raw: &[u8], except: Option<InterfaceId>) {
        let header = rns_wire::header::PacketHeader::unpack(raw)
            .ok()
            .map(|(h, _)| h);
        let destination_hash = header
            .as_ref()
            .map(|h| h.destination_hash)
            .unwrap_or([0u8; 16]);
        let ids: Vec<InterfaceId> = self
            .interfaces
            .keys()
            .copied()
            .filter(|id| self.interface_allows_announce(*id, &destination_hash, except))
            .collect();
        for id in ids {
            // Python 1.3.8 Transport.py:1345: delta-mangled HEADER_1 announces
            // are re-framed as HEADER_2|TRANSPORT with our transport identity.
            match &header {
                Some(h) if self.should_apply_delta(h, id) => {
                    let transport_insert =
                        h.flags.header_type == rns_wire::flags::HeaderType::Header1;
                    let mangled = self.mangle_hops(raw, h, transport_insert);
                    self.send_to_interface(id, &mangled);
                }
                _ => self.send_to_interface(id, raw),
            }
            if let Some(entry) = self.interfaces.get_mut(&id) {
                entry.ingress.sent_announce();
            }
        }
    }

    /// Enqueue an announce on every eligible outbound interface (except
    /// optionally one). Eligibility mirrors Python's AP/roaming/boundary mode
    /// gates. Enqueueing lets `process_announce_queues` apply ANNOUNCE_CAP
    /// spacing and hop priority.
    fn broadcast_announce_on_interfaces(&mut self, raw: &[u8], except: Option<InterfaceId>) {
        let destination_hash = rns_wire::header::PacketHeader::unpack(raw)
            .ok()
            .map(|(h, _)| h.destination_hash)
            .unwrap_or([0u8; 16]);
        let hops = raw.get(1).copied().unwrap_or(0);
        let now = now_f64();
        // One copy at the boundary; per-interface queue entries clone the
        // shared Arc for free.
        let shared = Bytes::copy_from_slice(raw);

        let ids: Vec<InterfaceId> = self
            .interfaces
            .keys()
            .copied()
            .filter(|id| self.interface_allows_announce(*id, &destination_hash, except))
            .collect();

        for id in ids {
            let Some(entry) = self.interfaces.get_mut(&id) else {
                continue;
            };
            entry.announce_queue.push(crate::messages::QueuedAnnounce {
                destination_hash,
                time: now,
                hops,
                raw: shared.clone(),
            });
            if entry.announce_queue.len() > MAX_QUEUED_ANNOUNCES {
                let excess = entry.announce_queue.len() - MAX_QUEUED_ANNOUNCES;
                entry.announce_queue.drain(..excess);
            }
        }
    }

    /// `None` when the cached announce fails to parse — Python 1.3.8
    /// Transport.py:2984 treats that as a cache miss and never emits the raw
    /// bytes (unpack also rejects hops >= PATHFINDER_M, Packet.py:247-248).
    fn path_response_from_cached_announce(
        &self,
        cached_raw: &[u8],
        destination_hash: [u8; 16],
        hops: u8,
    ) -> Option<Vec<u8>> {
        let Ok((cached_header, payload_offset)) =
            rns_wire::header::PacketHeader::unpack(cached_raw)
        else {
            return None;
        };
        if cached_header.hops >= PATHFINDER_M {
            return None;
        }

        let (header_type, transport_type, transport_id) =
            if let Some(transport_id) = self.transport_identity_hash {
                (
                    rns_wire::flags::HeaderType::Header2,
                    rns_wire::flags::TransportType::Transport,
                    Some(transport_id),
                )
            } else {
                (
                    cached_header.flags.header_type,
                    cached_header.flags.transport_type,
                    cached_header.transport_id,
                )
            };

        let flags = rns_wire::flags::PacketFlags {
            header_type,
            context_flag: cached_header.flags.context_flag,
            transport_type,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id,
            destination_hash,
            context: rns_wire::context::PacketContext::PathResponse,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&cached_raw[payload_offset..]);
        Some(raw)
    }

    pub fn has_path(&self, dest_hash: &[u8; 16]) -> bool {
        self.path_table.has_path(dest_hash)
    }

    pub fn hops_to(&self, dest_hash: &[u8; 16]) -> Option<u8> {
        self.path_table.hops_to(dest_hash)
    }

    /// Test-only: flush all pending announce retransmits immediately,
    /// bypassing `ANNOUNCES_CHECK_INTERVAL` and the per-entry retransmit
    /// timeouts. Production code must never call this.
    #[cfg(test)]
    fn flush_pending_announces(&mut self) {
        let far_future = now_f64() + 10.0;
        let due = self.announce_table.due_for_retransmit(far_future);
        for hash in due {
            let send_info = self.announce_table.get(&hash).map(|e| {
                (
                    e.packet_raw.clone(),
                    e.source_interface,
                    e.attached_interface,
                    e.block_rebroadcast,
                )
            });
            if let Some((raw, _source_iface, Some(attached_interface), true)) = send_info {
                self.send_to_interface(attached_interface, &raw);
                self.announce_table.remove(&hash);
                if let Some(held_entry) = self.held_announces.remove(hash.as_bytes()) {
                    self.announce_table.insert(*hash.as_bytes(), held_entry);
                }
                continue;
            }
            if let Some(entry) = self.announce_table.get_mut(&hash) {
                entry.retries += 1;
                entry.retransmit_timeout = far_future + PATHFINDER_G + rand_window();
            }
            if let Some((raw, source_iface, _, _)) = send_info {
                self.broadcast_announce_on_interfaces(&raw, source_iface);
            }
        }
        self.flush_announce_queues();
    }

    /// Test-only helper: drain every interface's announce queue synchronously,
    /// bypassing the bandwidth-spacing gate. Mirrors what `process_announce_queues`
    /// does but without the `now >= announce_allowed_at` check.
    #[cfg(test)]
    pub(crate) fn flush_announce_queues(&mut self) {
        let iface_ids: Vec<InterfaceId> = self.interfaces.keys().copied().collect();
        for iface_id in iface_ids {
            loop {
                let next = match self.interfaces.get_mut(&iface_id) {
                    Some(entry) if !entry.announce_queue.is_empty() && entry.direction.outbound => {
                        Some(entry.announce_queue.remove(0).raw)
                    }
                    _ => None,
                };
                match next {
                    Some(raw) => self.send_to_interface(iface_id, &raw),
                    None => break,
                }
            }
        }
    }
}

fn interface_marked_offline(entry: &InterfaceEntry) -> bool {
    entry
        .online
        .as_ref()
        .map(|online| !online.load(std::sync::atomic::Ordering::SeqCst))
        .unwrap_or(false)
}

fn announce_timebase(random_blob: &[u8; 10]) -> u64 {
    let mut emitted = [0u8; 8];
    emitted[3..].copy_from_slice(&random_blob[5..10]);
    u64::from_be_bytes(emitted)
}

fn path_timebase_from_random_blobs<'a>(random_blobs: impl Iterator<Item = &'a [u8; 10]>) -> u64 {
    random_blobs.map(announce_timebase).max().unwrap_or(0)
}

/// Random jitter in `[0, PATHFINDER_RW)` for announce rebroadcast timing.
/// The jitter avoids synchronized retransmits when many nodes learn the
/// same announce in the same tick.
fn rand_window() -> f64 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let r: f64 = rng.r#gen();
    r * PATHFINDER_RW
}

fn mode_discovers_unknown_paths(mode: InterfaceMode) -> bool {
    // Python 1.3.8 Interface.py:55 DISCOVER_PATHS_FOR.
    matches!(
        mode,
        InterfaceMode::AccessPoint
            | InterfaceMode::Gateway
            | InterfaceMode::Roaming
            | InterfaceMode::Internal
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{InterfaceDirection, InterfaceMode};
    use crate::messages::{
        InboundPacket, InterfaceEntry, OutboundRequest, TransportQuery, TransportQueryResponse,
    };
    use crate::path_table::PathEntry;

    fn make_valid_announce(app_name: &str, hops: u8) -> (Bytes, [u8; 16]) {
        let identity = rns_identity::identity::Identity::new();
        let dest_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
            app_name,
            Some(&identity.hash),
        );
        let announce_data =
            rns_identity::announce::AnnounceData::create(&identity, app_name, None, None).unwrap();
        let payload = announce_data.pack();

        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&payload);
        (Bytes::from(raw), dest_hash)
    }

    fn make_announce_for_with_random_blob(
        identity: &rns_identity::identity::Identity,
        app_name: &str,
        hops: u8,
        random_blob: [u8; 10],
    ) -> (Bytes, [u8; 16]) {
        let dest_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
            app_name,
            Some(&identity.hash),
        );
        let public_key = identity.get_public_key();
        let name_hash = rns_identity::name_hash::name_hash(app_name);
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&dest_hash);
        signed_data.extend_from_slice(&public_key);
        signed_data.extend_from_slice(&name_hash);
        signed_data.extend_from_slice(&random_blob);
        let signature = identity.sign(&signed_data).unwrap();
        let announce_data = rns_identity::announce::AnnounceData {
            public_key,
            name_hash,
            random_hash: random_blob,
            ratchet: None,
            signature,
            app_data: None,
        };
        let payload = announce_data.pack();

        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&payload);
        (Bytes::from(raw), dest_hash)
    }

    fn random_blob(prefix: u8, emitted: u64) -> [u8; 10] {
        let mut blob = [prefix; 10];
        let emitted = emitted.to_be_bytes();
        blob[5..].copy_from_slice(&emitted[3..8]);
        blob
    }

    /// Dummy-payload variant with no valid signature — only for tests that
    /// do not exercise announce validation.
    #[allow(dead_code)]
    fn make_announce_packet_for_identity(
        dest_hash: [u8; 16],
        hops: u8,
        _identity: Option<&rns_identity::identity::Identity>,
    ) -> Bytes {
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        // Add some payload to meet minimum packet requirements
        raw.extend_from_slice(&[0u8; 32]);
        Bytes::from(raw)
    }

    fn make_data_packet(dest_hash: [u8; 16], hops: u8) -> Bytes {
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0xDD; 32]);
        Bytes::from(raw)
    }

    fn make_link_request_packet(dest_hash: [u8; 16], hops: u8) -> Bytes {
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::LinkRequest,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0xCC; 64]);
        Bytes::from(raw)
    }

    fn make_link_data_packet(link_id: [u8; 16], hops: u8) -> Bytes {
        make_link_data_packet_with_context(
            link_id,
            hops,
            rns_wire::context::PacketContext::Resource,
        )
    }

    fn make_link_data_packet_with_context(
        link_id: [u8; 16],
        hops: u8,
        context: rns_wire::context::PacketContext,
    ) -> Bytes {
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id: None,
            destination_hash: link_id,
            context,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0xDA; 32]);
        Bytes::from(raw)
    }

    fn make_proof_packet(dest_hash: [u8; 16], hops: u8) -> Bytes {
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Proof,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0xEE; 32]);
        Bytes::from(raw)
    }

    fn make_link_proof_packet(link_id: [u8; 16], hops: u8) -> Bytes {
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Proof,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id: None,
            destination_hash: link_id,
            context: rns_wire::context::PacketContext::LinkProof,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0xEF; 32]);
        Bytes::from(raw)
    }

    fn make_test_interface(name: &str) -> (InterfaceEntry, mpsc::Receiver<Bytes>) {
        let (tx, rx) = mpsc::channel(64);
        let entry = InterfaceEntry {
            name: name.to_string(),
            mode: InterfaceMode::Gateway,
            role: InterfaceRole::Normal,
            direction: InterfaceDirection::bidirectional(),
            bitrate: 115200,
            mtu: 500,
            tx,
            ifac_key: None,
            ifac_size: 0,
            announce_cap: ANNOUNCE_CAP,
            announce_allowed_at: 0.0,
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,
            online: None,
            rxb: None,
            txb: None,
            tx_drops: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            multipoint: false,
            recursive_prs: false,
            announces_from_internal: true,
            ingress: crate::ingress::IngressController::new(),
            announce_queue: Vec::new(),
        };
        (entry, rx)
    }

    #[test]
    fn test_actor_creation() {
        let (actor, _tx) = TransportActor::new();
        assert!(actor.path_table.is_empty());
        assert!(actor.link_table.is_empty());
        assert!(actor.packet_hashlist.is_empty());
    }

    #[test]
    fn test_register_destination() {
        let (mut actor, _tx) = TransportActor::new();
        let hash = [0xAA; 16];
        actor.handle_message(TransportMessage::RegisterDestination {
            hash,
            app_name: "test.app".to_string(),
            delivery_tx: None,
        });
        assert!(actor.local_destinations.contains(&hash));
    }

    #[test]
    fn test_deregister_destination() {
        let (mut actor, _tx) = TransportActor::new();
        let hash = [0xAA; 16];
        actor.local_destinations.insert(hash);
        actor.handle_message(TransportMessage::DeregisterDestination { hash });
        assert!(!actor.local_destinations.contains(&hash));
    }

    #[tokio::test]
    async fn test_actor_shutdown() {
        let (actor, tx) = TransportActor::new();
        let handle = tokio::spawn(actor.run());
        tx.send(TransportMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[test]
    fn test_register_interface() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, _rx) = make_test_interface("test_iface");
        actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry });
        assert!(actor.interfaces.contains_key(&1));
        assert_eq!(actor.interfaces.get(&1).unwrap().name, "test_iface");
    }

    #[test]
    fn test_multipoint_interface_relays_announce_to_source() {
        let (mut actor, _tx) = TransportActor::new();
        let dest = [0xAB; 16];

        // Point-to-multipoint medium whose peers can't hear each other:
        // an announce arriving here must be allowed back out the same
        // interface. A normal interface must still exclude its source.
        let (normal, _rx) = make_test_interface("normal");
        actor.interfaces.insert(1, normal);
        let (mut mp, _rx2) = make_test_interface("ble");
        mp.multipoint = true;
        actor.interfaces.insert(2, mp);
        // The relayed announce has installed a path (next-hop gate parity).
        actor
            .path_table
            .insert(dest, PathEntry::new(None, 1, 2, InterfaceMode::Gateway));

        assert!(
            !actor.interface_allows_announce(1, &dest, Some(1)),
            "normal interface must not relay an announce back to its source"
        );
        assert!(
            actor.interface_allows_announce(2, &dest, Some(2)),
            "multipoint interface must relay an announce back to its other peers"
        );
    }

    #[test]
    fn test_deregister_interface() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, _rx) = make_test_interface("test_iface");
        actor.interfaces.insert(1, entry);
        actor.handle_message(TransportMessage::DeregisterInterface { id: 1 });
        assert!(!actor.interfaces.contains_key(&1));
    }

    /// T1-3 regression: deregistering must flip the driver-shared `online`
    /// flag so flag-gated driver tasks (Auto beacons/discovery, BLE loops,
    /// RNodeMulti subs) exit instead of spinning on an orphaned Arc.
    #[test]
    fn test_deregister_interface_flips_shared_online_flag() {
        let (mut actor, _tx) = TransportActor::new();
        let (mut entry, _rx) = make_test_interface("test_iface");
        let online = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        entry.online = Some(online.clone());
        actor.interfaces.insert(1, entry);

        actor.handle_message(TransportMessage::DeregisterInterface { id: 1 });

        assert!(!actor.interfaces.contains_key(&1));
        assert!(
            !online.load(std::sync::atomic::Ordering::SeqCst),
            "driver-shared online flag must be false after deregister"
        );
    }

    #[test]
    fn test_send_to_interface() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, mut rx) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry);

        let data = vec![0x01, 0x02, 0x03];
        actor.send_to_interface(1, &data);

        let received = rx.try_recv().unwrap();
        assert_eq!(received, data);
    }

    #[test]
    fn test_send_to_interface_inbound_only() {
        let (mut actor, _tx) = TransportActor::new();
        let (mut entry, mut rx) = make_test_interface("iface_in");
        entry.direction = InterfaceDirection::inbound_only();
        actor.interfaces.insert(1, entry);

        actor.send_to_interface(1, &[0x01, 0x02]);
        assert!(rx.try_recv().is_err()); // Should not have sent
    }

    #[test]
    fn test_send_to_interface_full_channel_counts_drops_without_deregistering() {
        let (mut actor, _tx) = TransportActor::new();
        let (tx, mut rx) = mpsc::channel(1);
        let tx_drops = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut entry = InterfaceEntry::new(
            "full".to_string(),
            InterfaceMode::Full,
            InterfaceDirection::bidirectional(),
            1_000_000,
            500,
            tx,
        );
        entry.tx_drops = tx_drops.clone();
        actor.interfaces.insert(1, entry);

        actor.send_to_interface(1, &[0x01]);
        actor.send_to_interface(1, &[0x02]);
        actor.send_to_interface(1, &[0x03]);

        assert_eq!(rx.try_recv().unwrap(), Bytes::from_static(&[0x01]));
        assert_eq!(tx_drops.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert!(actor.interfaces.contains_key(&1));
    }

    #[test]
    fn test_register_interface_skips_already_offline_child() {
        let (mut actor, _tx) = TransportActor::new();
        let (_raw, dest_hash) = make_valid_announce("test.offline.local_client", 0);
        actor.recent_announces.insert(
            dest_hash,
            RecentAnnounce {
                dest_hash,
                hops: 0,
                app_data: None,
                timestamp: now_f64(),
                public_key: None,
                ratchet: None,
                packet_hash: Some([0xAB; 32]),
                is_path_response: false,
                retained: false,
                last_used: None,
                name_hash: [0u8; 10],
            },
        );

        let (mut entry, mut rx) = make_test_interface("SharedInstanceServer/client_4");
        entry.role = InterfaceRole::LocalClient;
        entry.online = Some(Arc::new(AtomicBool::new(false)));
        let tx_drops = entry.tx_drops.clone();

        actor.handle_message(TransportMessage::RegisterInterface { id: 4, entry });

        assert!(
            !actor.interfaces.contains_key(&4),
            "offline child handles must not be registered after disconnect"
        );
        assert!(
            rx.try_recv().is_err(),
            "offline child must not receive cached announce replay"
        );
        assert_eq!(
            tx_drops.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "offline registration should not count as TX pressure"
        );
    }

    #[test]
    fn test_register_interface_allows_offline_shared_instance_peer() {
        let (mut actor, _tx) = TransportActor::new();
        let (mut entry, mut rx) = make_test_interface("SharedInstanceClient");
        entry.role = InterfaceRole::SharedInstancePeer;
        entry.online = Some(Arc::new(AtomicBool::new(false)));

        actor.handle_message(TransportMessage::RegisterInterface { id: 44, entry });

        assert!(
            actor.interfaces.contains_key(&44),
            "shared-instance peers must remain registered while reconnecting"
        );
        actor.send_to_interface(44, &[0xA5, 0x5A]);
        assert_eq!(
            rx.try_recv().unwrap(),
            Bytes::from_static(&[0xA5, 0x5A]),
            "offline shared peer should not use local-client stale-handle reaping"
        );
        assert!(
            actor.interfaces.contains_key(&44),
            "offline shared peer should not be auto-deregistered"
        );
    }

    #[test]
    fn test_register_local_client_does_not_replay_cached_announces() {
        let (mut actor, _tx) = TransportActor::new();

        let cached_announces = 1_200;
        for i in 0..cached_announces {
            let mut dest_hash = [0; 16];
            dest_hash[8..].copy_from_slice(&(i as u64).to_be_bytes());
            actor.recent_announces.insert(
                dest_hash,
                RecentAnnounce {
                    dest_hash,
                    hops: 1,
                    app_data: None,
                    timestamp: i as f64,
                    public_key: None,
                    ratchet: None,
                    packet_hash: None,
                    is_path_response: false,
                    retained: false,
                    last_used: None,
                    name_hash: [0; 10],
                },
            );
        }
        assert!(
            actor.recent_announces.len() > 1_000,
            "fixture must model the large cache seen in contributor reports"
        );

        let (mut entry, mut rx) = make_test_interface("SharedInstanceServer/client_9");
        entry.role = InterfaceRole::LocalClient;
        let tx_drops = entry.tx_drops.clone();

        actor.handle_message(TransportMessage::RegisterInterface { id: 9, entry });

        assert_eq!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty),
            "registering a local shared client must not dump cached announces"
        );
        assert_eq!(
            tx_drops.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "registering a local shared client must not create TX pressure"
        );
        assert!(actor.interfaces.contains_key(&9));
    }

    #[test]
    fn test_register_interface_does_not_replay_announce_table() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let dest_hash = [0xA7; 16];
        actor.announce_table.insert(
            dest_hash,
            crate::announce::AnnounceEntry {
                timestamp: now_f64(),
                retransmit_timeout: now_f64(),
                retries: 0,
                received_from: [0x22; 16],
                hops: 2,
                packet_raw: vec![0x51, 0x01, 0x02],
                local_rebroadcasts: 0,
                block_rebroadcast: false,
                attached_interface: None,
                source_interface: None,
            },
        );

        let (entry, mut rx) = make_test_interface("tcp_backbone");
        actor.handle_message(TransportMessage::RegisterInterface { id: 10, entry });

        assert_eq!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty),
            "interface registration must not replay queued announces"
        );
        assert!(
            actor.announce_table.get(&dest_hash).is_some(),
            "announce job, not registration, owns queued announce processing"
        );
    }

    #[test]
    fn local_client_path_request_uses_cached_announce_without_startup_dump() {
        let dir = std::env::temp_dir().join("rns_local_client_cached_path_response");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        actor.transport_identity_hash = Some([0x77; 16]);
        actor.storage_dir = Some(dir.clone());

        let cached_announces = 1_200;
        for i in 0..cached_announces {
            let mut dest_hash = [0; 16];
            dest_hash[8..].copy_from_slice(&(i as u64).to_be_bytes());
            actor.recent_announces.insert(
                dest_hash,
                RecentAnnounce {
                    dest_hash,
                    hops: 1,
                    app_data: None,
                    timestamp: i as f64,
                    public_key: None,
                    ratchet: None,
                    packet_hash: None,
                    is_path_response: false,
                    retained: false,
                    last_used: None,
                    name_hash: [0; 10],
                },
            );
        }
        let (target_raw, target_dest) = make_valid_announce("test.shared.cached_path_response", 2);
        let target_ph =
            rns_wire::hash::packet_hash(&target_raw, rns_wire::flags::HeaderType::Header1);
        crate::persistence::write_python_cached_announce_if_absent(
            &dir.join("cache").join("announces"),
            &target_ph,
            &target_raw,
            None,
        )
        .unwrap();
        actor.recent_announces.insert(
            target_dest,
            RecentAnnounce {
                dest_hash: target_dest,
                hops: 3,
                app_data: None,
                timestamp: cached_announces as f64,
                public_key: None,
                ratchet: None,
                packet_hash: Some(target_ph),
                is_path_response: false,
                retained: false,
                last_used: None,
                name_hash: [0; 10],
            },
        );
        let mut target_path =
            crate::path_table::PathEntry::new(Some([0x22; 16]), 3, 2, InterfaceMode::Gateway);
        target_path.packet_hash = Some(target_ph);
        actor.path_table.insert(target_dest, target_path);
        assert!(
            actor.recent_announces.len() > 1_000,
            "fixture must keep a large cache while proving request-driven use"
        );

        let (mut local_client, mut local_rx) =
            make_test_interface("SharedInstanceServer/client_10");
        local_client.role = InterfaceRole::LocalClient;
        actor.handle_message(TransportMessage::RegisterInterface {
            id: 1,
            entry: local_client,
        });
        assert_eq!(
            local_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty),
            "local shared client must not receive cached announces on connect"
        );

        actor.handle_inbound_path_request(&make_path_request_payload(target_dest, None), 1);
        assert_eq!(
            local_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty),
            "path request should queue the cached response for the announce job"
        );

        actor.flush_pending_announces();
        let response = local_rx
            .try_recv()
            .expect("cached announce should be returned after a local path request");
        let (header, _) = rns_wire::header::PacketHeader::unpack(&response).unwrap();
        assert_eq!(header.destination_hash, target_dest);
        assert_eq!(header.hops, 3);
        assert_eq!(header.transport_id, Some([0x77; 16]));
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::PathResponse
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_send_to_interface_auto_deregisters_offline_entry_before_queueing() {
        let (mut actor, _tx) = TransportActor::new();
        let (mut entry, mut rx) = make_test_interface("SharedInstanceServer/client_5");
        entry.role = InterfaceRole::LocalClient;
        entry.online = Some(Arc::new(AtomicBool::new(false)));
        let tx_drops = entry.tx_drops.clone();
        actor.interfaces.insert(5, entry);

        actor.send_to_interface(5, &[0x01, 0x02, 0x03]);

        assert!(
            !actor.interfaces.contains_key(&5),
            "offline interface should be reaped before enqueue"
        );
        assert!(
            rx.try_recv().is_err(),
            "offline interface should not receive outbound bytes"
        );
        assert_eq!(
            tx_drops.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "offline interface should not report queue drops"
        );
    }

    #[test]
    fn test_broadcast_on_interfaces() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, mut rx1) = make_test_interface("iface1");
        let (entry2, mut rx2) = make_test_interface("iface2");
        let (entry3, mut rx3) = make_test_interface("iface3");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);
        actor.interfaces.insert(3, entry3);

        let data = vec![0xAA, 0xBB];
        actor.broadcast_on_interfaces(&data, Some(2));

        // Interface 1 and 3 should receive, interface 2 (excluded) should not
        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_err());
        assert!(rx3.try_recv().is_ok());
    }

    /// Regression test for the SharedInstance zombie-interface leak
    /// (investigated 2026-04-24): when an interface's tx receiver is dropped
    /// without a matching `DeregisterInterface`, `send_to_interface` must
    /// detect `TrySendError::Closed` on the first attempt and auto-reap the
    /// entry so it can't absorb every subsequent broadcast into a dead
    /// mailbox. Prior behavior logged `tx_drops` forever, accumulating tens
    /// of thousands of dropped packets per minute.
    #[test]
    fn test_send_to_interface_auto_deregisters_closed_channel() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, rx) = make_test_interface("zombie");
        actor.interfaces.insert(7, entry);
        assert!(actor.interfaces.contains_key(&7));

        // Simulate the downstream write-loop exiting: the receiver is dropped
        // while the sender (inside the interface entry) stays alive.
        drop(rx);

        let data = vec![0xDE, 0xAD];
        actor.send_to_interface(7, &data);

        assert!(
            !actor.interfaces.contains_key(&7),
            "send_to_interface should reap entries whose tx channel is Closed"
        );
    }

    /// Same scenario but via `broadcast_on_interfaces` — the collection
    /// walker must tolerate self.interfaces mutation from the inner
    /// auto-deregister path (we collect ids first to avoid the borrow).
    #[test]
    fn test_broadcast_reaps_closed_interface() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry_live, mut rx_live) = make_test_interface("live");
        let (entry_dead, rx_dead) = make_test_interface("dead");
        actor.interfaces.insert(1, entry_live);
        actor.interfaces.insert(2, entry_dead);
        drop(rx_dead);

        actor.broadcast_on_interfaces(&[0xAA], None);

        assert!(rx_live.try_recv().is_ok(), "live interface still receives");
        assert!(actor.interfaces.contains_key(&1));
        assert!(
            !actor.interfaces.contains_key(&2),
            "dead interface should be reaped by broadcast"
        );
    }

    /// `DeregisterInterface` must be idempotent: a second message for the
    /// same id (e.g. auto-deregister already fired, then an explicit
    /// `DeregisterInterface { id }` arrives from the read-loop teardown in
    /// `local.rs`) must not panic and must leave state untouched.
    #[test]
    fn test_duplicate_deregister_is_idempotent() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, _rx) = make_test_interface("twice");
        actor.interfaces.insert(9, entry);

        actor.handle_message(TransportMessage::DeregisterInterface { id: 9 });
        assert!(!actor.interfaces.contains_key(&9));

        // Second deregister on a missing id: must be a no-op.
        actor.handle_message(TransportMessage::DeregisterInterface { id: 9 });
        assert!(!actor.interfaces.contains_key(&9));

        // And a deregister for an id that never existed.
        actor.handle_message(TransportMessage::DeregisterInterface { id: 999 });
    }

    /// Deregistering an interface must cascade through every routing table
    /// that points at it: paths via the interface, tunnels anchored to it,
    /// and the interface entry itself all go away in one shot.
    #[test]
    fn test_deregister_cleans_path_and_tunnel_tables() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, _rx) = make_test_interface("doomed");
        actor.interfaces.insert(42, entry);

        // Install a path via interface 42 and a tunnel anchored on it.
        let dest = [0x11; 16];
        actor.path_table.insert(
            dest,
            crate::path_table::PathEntry::new(None, 2, 42, InterfaceMode::Gateway),
        );
        let tunnel_id = [0x22; 32];
        let mut tunnel_paths = std::collections::HashMap::new();
        tunnel_paths.insert(
            dest,
            crate::tunnel::TunnelPath {
                timestamp: now_f64(),
                next_hop: None,
                hops: 2,
                expires: now_f64() + 600.0,
                random_blobs: vec![],
                packet_hash: None,
            },
        );
        actor.tunnel_table.insert(crate::tunnel::TunnelEntry {
            tunnel_id,
            interface_id: 42,
            tunnel_paths,
            expires: now_f64() + 600.0,
        });

        assert!(actor.path_table.has_path(&dest));
        assert_eq!(actor.tunnel_table.get(&tunnel_id).unwrap().interface_id, 42);

        actor.handle_message(TransportMessage::DeregisterInterface { id: 42 });

        assert!(
            !actor.interfaces.contains_key(&42),
            "interface entry removed"
        );
        assert!(
            !actor.path_table.has_path(&dest),
            "paths via the interface dropped"
        );
        // Tunnel interface_id voided to 0 (matches void_tunnel_interface contract).
        assert_eq!(
            actor.tunnel_table.get(&tunnel_id).unwrap().interface_id,
            0,
            "tunnel interface voided"
        );
    }

    /// `RegisterInterface` with an id that's already in use replaces the
    /// entry in place. The old `tx` is dropped, so anything still holding
    /// the old `rx` observes `Closed` on the next recv. We cover this
    /// deliberately because it's the failure mode if a reconnect raced a
    /// deregister: the caller may have allocated a fresh id or reused one.
    #[test]
    fn test_register_over_existing_id_replaces_entry() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry_old, mut rx_old) = make_test_interface("old");
        actor.handle_message(TransportMessage::RegisterInterface {
            id: 5,
            entry: entry_old,
        });

        let (entry_new, mut rx_new) = make_test_interface("new");
        actor.handle_message(TransportMessage::RegisterInterface {
            id: 5,
            entry: entry_new,
        });

        assert_eq!(actor.interfaces.get(&5).unwrap().name, "new");

        // A send on id=5 reaches the new receiver, not the old one.
        actor.send_to_interface(5, &[0xAB]);
        assert!(rx_new.try_recv().is_ok(), "new rx gets the packet");
        // Old rx sees the sender dropped — try_recv returns Disconnected.
        assert!(
            matches!(
                rx_old.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
            ),
            "old rx observes the old tx was dropped"
        );
    }

    /// `on_inbound` must tolerate `InboundPacket { interface_id, .. }` where
    /// `interface_id` is not in `self.interfaces`. This happens naturally
    /// during teardown: a packet was enqueued by the read-loop just before
    /// the deregister message fired, and arrives at the actor afterwards.
    #[test]
    fn test_inbound_packet_for_unknown_interface_id() {
        let (mut actor, _tx) = TransportActor::new();
        // No interface registered. Fabricate a minimal packet header that
        // decodes cleanly so we exercise the "unknown interface_id" path
        // rather than the malformed-header path.
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
            destination_hash: [0x33; 16],
            context: rns_wire::context::PacketContext::None,
        };
        let raw = header.pack();

        let paths_before = actor.path_table.is_empty();
        let interfaces_before = actor.interfaces.len();

        actor.on_inbound(crate::messages::InboundPacket {
            interface_id: 12345,
            raw: Bytes::from(raw),
            rssi: None,
            snr: None,
            q: None,
        });

        assert_eq!(
            actor.interfaces.len(),
            interfaces_before,
            "interface set untouched"
        );
        assert_eq!(
            actor.path_table.is_empty(),
            paths_before,
            "path table untouched"
        );
    }

    #[test]
    fn test_broadcast_announce_skips_access_point() {
        // AccessPoint interfaces must not receive relayed announces.
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, mut rx1) = make_test_interface("full_iface");
        let (mut entry2, mut rx2) = make_test_interface("ap_iface");
        entry2.mode = InterfaceMode::AccessPoint;
        let (entry3, mut rx3) = make_test_interface("gateway_iface");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);
        actor.interfaces.insert(3, entry3);

        let (data, dest) = make_valid_announce("test.ap.skip", 1);
        actor
            .path_table
            .insert(dest, PathEntry::new(None, 1, 1, InterfaceMode::Gateway));
        actor.broadcast_announce_on_interfaces(&data, None);
        actor.flush_announce_queues();

        // Full and Gateway should receive, AccessPoint should not
        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_err()); // AP skipped
        assert!(rx3.try_recv().is_ok());
    }

    #[test]
    fn test_announce_propagation() {
        let (mut actor, _tx) = TransportActor::new();
        // Only transport-enabled nodes rebroadcast announces.
        actor.is_transport_enabled = true;
        actor.transport_identity_hash = Some([0xAB; 16]);
        let (entry1, mut _rx1) = make_test_interface("iface1");
        let (entry2, mut rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let (raw, dest_hash) = make_valid_announce("test.propagation", 3);

        // Inject announce on interface 1
        actor.on_inbound(InboundPacket {
            raw: raw.clone(),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Path table stores Python-parity inbound-adjusted hops.
        assert!(actor.path_table.has_path(&dest_hash));
        assert_eq!(actor.path_table.hops_to(&dest_hash), Some(4));

        // Flush deferred announces (rebroadcast is now deferred via announce table)
        actor.flush_pending_announces();

        // Interface 2 should receive the adjusted hop value for the next leg.
        let rebroadcast = rx2.try_recv().unwrap();
        assert_eq!(rebroadcast[1], 4);
        let (rebroadcast_header, _) = rns_wire::header::PacketHeader::unpack(&rebroadcast).unwrap();
        assert_eq!(
            rebroadcast_header.flags.header_type,
            rns_wire::flags::HeaderType::Header2
        );
        assert_eq!(rebroadcast_header.transport_id, Some([0xAB; 16]));
    }

    #[test]
    fn test_announce_not_rebroadcast_without_transport() {
        let (mut actor, _tx) = TransportActor::new();
        // transport disabled (default) — should NOT rebroadcast
        let (entry1, mut _rx1) = make_test_interface("iface1");
        let (entry2, mut rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let (raw, dest_hash) = make_valid_announce("test.no_rebroadcast", 3);

        actor.on_inbound(InboundPacket {
            raw: raw.clone(),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Path should still be learned
        assert!(actor.path_table.has_path(&dest_hash));

        // But announce should NOT be in announce_table for rebroadcast
        actor.flush_pending_announces();
        assert!(
            rx2.try_recv().is_err(),
            "non-transport node should not rebroadcast announces"
        );
    }

    #[test]
    fn test_data_forwarding() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        let transport_id = [0xAA; 16];
        actor.transport_identity_hash = Some(transport_id);

        let (entry1, mut _rx1) = make_test_interface("iface1");
        let (entry2, mut rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        // Insert a path pointing to interface 2
        let dest_hash = [0x22; 16];
        let path_entry = crate::path_table::PathEntry::new(
            Some([0xBB; 16]),
            2,
            2, // interface 2
            InterfaceMode::Gateway,
        );
        actor.path_table.insert(dest_hash, path_entry);

        // Inject in-transport Header2 data addressed to this transport.
        let raw = make_header2_data_packet(transport_id, dest_hash, 1, b"transported_data");
        actor.on_inbound(InboundPacket {
            raw: raw.clone(),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Interface 2 should have received the forwarded packet
        let forwarded = rx2.try_recv().unwrap();
        assert_eq!(forwarded[1], 2); // raw 1 -> inbound-adjusted 2
        let (forwarded_header, offset) =
            rns_wire::header::PacketHeader::unpack(&forwarded).unwrap();
        assert_eq!(
            forwarded_header.flags.header_type,
            rns_wire::flags::HeaderType::Header2
        );
        assert_eq!(forwarded_header.transport_id, Some([0xBB; 16]));
        assert_eq!(&forwarded[offset..], b"transported_data");
    }

    #[test]
    fn test_proof_routing() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true; // reverse table + proof routing requires transport

        let (entry1, mut rx1) = make_test_interface("iface1");
        let (entry2, mut _rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        // Insert reverse entry: dest_hash -> interface 1
        let dest_hash = [0x33; 16];
        actor.reverse_table.insert(dest_hash, 1, 3);

        // Inject proof on interface 2
        let raw = make_proof_packet(dest_hash, 0);
        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });

        // Interface 1 should have received the proof
        let proof = rx1.try_recv().unwrap();
        assert!(!proof.is_empty());
    }

    #[test]
    fn test_duplicate_rejection() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        let (entry2, mut rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let (raw, _dest_hash) = make_valid_announce("test.duplicate", 0);

        // First inject
        actor.on_inbound(InboundPacket {
            raw: raw.clone(),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Drain rebroadcast
        let _ = rx2.try_recv();

        // Second inject of same packet — should be dropped as duplicate
        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Interface 2 should NOT have received another rebroadcast
        assert!(rx2.try_recv().is_err());
    }

    #[test]
    fn test_link_request_forwarding() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        let transport_id = [0xAA; 16];
        actor.transport_identity_hash = Some(transport_id);

        let (entry1, _rx1) = make_test_interface("iface1");
        let (entry2, mut rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        // Insert a path pointing to interface 2
        let dest_hash = [0x55; 16];
        let path_entry =
            crate::path_table::PathEntry::new(Some([0xBB; 16]), 1, 2, InterfaceMode::Gateway);
        actor.path_table.insert(dest_hash, path_entry);

        // Inject in-transport link request on interface 1
        let raw = make_header2_link_request_packet(transport_id, dest_hash, 0, &[0x42; 64]);
        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Interface 2 should have received the forwarded link request
        let forwarded = rx2.try_recv().unwrap();
        assert_eq!(forwarded[1], 1); // raw 0 -> inbound-adjusted 1
        let (forwarded_header, _) = rns_wire::header::PacketHeader::unpack(&forwarded).unwrap();
        assert_eq!(
            forwarded_header.flags.header_type,
            rns_wire::flags::HeaderType::Header1
        );
        assert_eq!(forwarded_header.transport_id, None);
    }

    fn make_lrproof_packet_with_payload(link_id: [u8; 16], hops: u8, payload: &[u8]) -> Bytes {
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Proof,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id: None,
            destination_hash: link_id,
            context: rns_wire::context::PacketContext::Lrproof,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(payload);
        Bytes::from(raw)
    }

    fn make_lrproof_packet(
        link_id: [u8; 16],
        hops: u8,
        destination_identity: &rns_identity::identity::Identity,
        signalling: Option<[u8; 3]>,
    ) -> Bytes {
        let destination_public_key = destination_identity.get_public_key();
        let mut destination_ed25519 = [0u8; 32];
        destination_ed25519.copy_from_slice(&destination_public_key[32..64]);
        let responder_x25519_pub = [0x42; 32];

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&link_id);
        signed_data.extend_from_slice(&responder_x25519_pub);
        signed_data.extend_from_slice(&destination_ed25519);
        if let Some(signalling) = signalling {
            signed_data.extend_from_slice(&signalling);
        }
        let signature = destination_identity.sign(&signed_data).unwrap();

        let mut payload = Vec::new();
        payload.extend_from_slice(&signature);
        payload.extend_from_slice(&responder_x25519_pub);
        if let Some(signalling) = signalling {
            payload.extend_from_slice(&signalling);
        }
        make_lrproof_packet_with_payload(link_id, hops, &payload)
    }

    #[test]
    fn test_lrproof_routing_through_relay() {
        // LRPROOF travels back up the link-table chain toward the initiator.
        // A mismatch between the packet's and the entry's remaining-hops value
        // silently drops the proof at the relay, so this guards that path.
        //
        // Scenario: Initiator → Relay → Destination (remaining_hops=1 at relay)
        let (mut relay, _tx) = TransportActor::new();
        relay.is_transport_enabled = true;

        let (entry1, mut rx1) = make_test_interface("to_initiator");
        let (entry2, _rx2) = make_test_interface("to_destination");
        relay.interfaces.insert(1, entry1);
        relay.interfaces.insert(2, entry2);

        // Create a link_table entry as if the relay forwarded a LINKREQUEST
        // from interface 1 (initiator side) to interface 2 (destination side)
        let link_id = [0x77; 16];
        let destination_hash = [0xCC; 16];
        let destination_identity = rns_identity::identity::Identity::new();
        insert_announce_for(&mut relay, destination_hash, &destination_identity);
        let link_entry = crate::link_table::LinkEntry {
            timestamp: now_f64(),
            next_hop: Some([0xBB; 16]),
            interface_id: 2,   // next-hop interface (toward destination)
            remaining_hops: 1, // 1 hop from relay to destination
            destination_hash,
            established: false,
            validated: false,
            proof_timeout: now_f64() + 120.0,
            receiving_interface: 1, // came from initiator side
            taken_hops: 0,
        };
        relay.link_table.insert(link_id, link_entry);

        // Destination sends LRPROOF with hops=0 (new proof, not incremented).
        // Proof arrives at relay on interface 2 (the destination side).
        let proof = make_lrproof_packet(link_id, 0, &destination_identity, Some([1, 0, 0]));
        relay.on_inbound(InboundPacket {
            raw: proof,
            interface_id: 2, // arrived from destination side
            rssi: None,
            snr: None,
            q: None,
        });

        // Relay should route the proof back to interface 1 (initiator side)
        let routed = rx1
            .try_recv()
            .expect("LRPROOF should be routed to initiator interface");
        assert!(!routed.is_empty());
        // The forwarded proof should have hops incremented to 1
        assert_eq!(
            routed[1], 1,
            "proof hops should be incremented when forwarded"
        );

        // Link should now be validated
        let entry = relay.link_table.get(&link_id).unwrap();
        assert!(
            entry.validated,
            "link should be marked validated after proof routing"
        );
    }

    #[test]
    fn test_lrproof_routing_direct_attached_destination() {
        // Scenario: Initiator -> relay -> directly attached destination.
        // The relay's path to the destination has remaining_hops=1, and the
        // destination emits a fresh LRPROOF with hops=0.
        let (mut relay, _tx) = TransportActor::new();
        relay.is_transport_enabled = true;

        let (entry1, mut rx1) = make_test_interface("to_initiator");
        let (entry2, _rx2) = make_test_interface("to_destination");
        relay.interfaces.insert(1, entry1);
        relay.interfaces.insert(2, entry2);

        let link_id = [0x79; 16];
        let destination_hash = [0xCD; 16];
        let destination_identity = rns_identity::identity::Identity::new();
        insert_announce_for(&mut relay, destination_hash, &destination_identity);
        relay.link_table.insert(
            link_id,
            crate::link_table::LinkEntry {
                timestamp: now_f64(),
                next_hop: None,
                interface_id: 2,
                remaining_hops: 1,
                destination_hash,
                established: false,
                validated: false,
                proof_timeout: now_f64() + 120.0,
                receiving_interface: 1,
                taken_hops: 0,
            },
        );

        let proof = make_lrproof_packet(link_id, 0, &destination_identity, None);
        relay.on_inbound(InboundPacket {
            raw: proof,
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });

        let routed = rx1
            .try_recv()
            .expect("direct-attached LRPROOF should route back to initiator");
        assert_eq!(
            routed[1], 1,
            "forwarded direct-attached proof should be one hop from initiator"
        );
        assert!(relay.link_table.get(&link_id).unwrap().validated);
    }

    #[test]
    fn test_lrproof_transit_rejects_invalid_signature() {
        let (mut relay, _tx) = TransportActor::new();
        relay.is_transport_enabled = true;

        let (entry1, mut rx1) = make_test_interface("to_initiator");
        let (entry2, _rx2) = make_test_interface("to_destination");
        relay.interfaces.insert(1, entry1);
        relay.interfaces.insert(2, entry2);

        let link_id = [0x7C; 16];
        let destination_hash = [0xDC; 16];
        let destination_identity = rns_identity::identity::Identity::new();
        insert_announce_for(&mut relay, destination_hash, &destination_identity);
        relay.link_table.insert(
            link_id,
            crate::link_table::LinkEntry {
                timestamp: now_f64(),
                next_hop: None,
                interface_id: 2,
                remaining_hops: 1,
                destination_hash,
                established: false,
                validated: false,
                proof_timeout: now_f64() + 120.0,
                receiving_interface: 1,
                taken_hops: 0,
            },
        );

        let mut proof =
            make_lrproof_packet(link_id, 0, &destination_identity, Some([4, 5, 6])).to_vec();
        let last = proof.len() - 1;
        proof[last] ^= 0x01;
        relay.on_inbound(InboundPacket {
            raw: Bytes::from(proof),
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(
            rx1.try_recv().is_err(),
            "invalid LRPROOF must not be forwarded"
        );
        assert!(
            !relay.link_table.get(&link_id).unwrap().validated,
            "invalid LRPROOF must not mark link-table entry validated"
        );
    }

    #[test]
    fn test_lrproof_transit_requires_known_destination_identity() {
        let (mut relay, _tx) = TransportActor::new();
        relay.is_transport_enabled = true;

        let (entry1, mut rx1) = make_test_interface("to_initiator");
        let (entry2, _rx2) = make_test_interface("to_destination");
        relay.interfaces.insert(1, entry1);
        relay.interfaces.insert(2, entry2);

        let link_id = [0x7D; 16];
        let destination_hash = [0xDD; 16];
        let destination_identity = rns_identity::identity::Identity::new();
        relay.link_table.insert(
            link_id,
            crate::link_table::LinkEntry {
                timestamp: now_f64(),
                next_hop: None,
                interface_id: 2,
                remaining_hops: 1,
                destination_hash,
                established: false,
                validated: false,
                proof_timeout: now_f64() + 120.0,
                receiving_interface: 1,
                taken_hops: 0,
            },
        );

        relay.on_inbound(InboundPacket {
            raw: make_lrproof_packet(link_id, 0, &destination_identity, None),
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(
            rx1.try_recv().is_err(),
            "LRPROOF without known destination identity must not be forwarded"
        );
        assert!(!relay.link_table.get(&link_id).unwrap().validated);
    }

    #[test]
    fn test_lrproof_transit_rejects_malformed_lengths() {
        for (idx, payload_len) in [95usize, 97, 98, 100].into_iter().enumerate() {
            let (mut relay, _tx) = TransportActor::new();
            relay.is_transport_enabled = true;

            let (entry1, mut rx1) = make_test_interface("to_initiator");
            let (entry2, _rx2) = make_test_interface("to_destination");
            relay.interfaces.insert(1, entry1);
            relay.interfaces.insert(2, entry2);

            let mut link_id = [0x7E; 16];
            link_id[15] = idx as u8;
            let destination_hash = [0xDE; 16];
            let destination_identity = rns_identity::identity::Identity::new();
            insert_announce_for(&mut relay, destination_hash, &destination_identity);
            relay.link_table.insert(
                link_id,
                crate::link_table::LinkEntry {
                    timestamp: now_f64(),
                    next_hop: None,
                    interface_id: 2,
                    remaining_hops: 1,
                    destination_hash,
                    established: false,
                    validated: false,
                    proof_timeout: now_f64() + 120.0,
                    receiving_interface: 1,
                    taken_hops: 0,
                },
            );

            relay.on_inbound(InboundPacket {
                raw: make_lrproof_packet_with_payload(link_id, 0, &vec![0xAA; payload_len]),
                interface_id: 2,
                rssi: None,
                snr: None,
                q: None,
            });

            assert!(
                rx1.try_recv().is_err(),
                "malformed LRPROOF length {payload_len} must not be forwarded"
            );
            assert!(!relay.link_table.get(&link_id).unwrap().validated);
        }
    }

    #[test]
    fn test_link_data_routes_via_link_table_both_directions() {
        let (mut relay, _tx) = TransportActor::new();
        relay.is_transport_enabled = true;

        let (entry1, mut rx1) = make_test_interface("to_initiator");
        let (entry2, mut rx2) = make_test_interface("to_destination");
        relay.interfaces.insert(1, entry1);
        relay.interfaces.insert(2, entry2);

        let link_id = [0x7A; 16];
        relay.link_table.insert(
            link_id,
            crate::link_table::LinkEntry {
                timestamp: now_f64(),
                next_hop: None,
                interface_id: 2,
                remaining_hops: 1,
                destination_hash: [0xCE; 16],
                established: true,
                validated: true,
                proof_timeout: now_f64() + 120.0,
                receiving_interface: 1,
                taken_hops: 1,
            },
        );

        relay.on_inbound(InboundPacket {
            raw: make_link_data_packet(link_id, 0),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        let to_destination = rx2
            .try_recv()
            .expect("initiator link data should route to destination side");
        assert_eq!(to_destination[1], 1);

        relay.on_inbound(InboundPacket {
            raw: make_link_data_packet(link_id, 0),
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });
        let to_initiator = rx1
            .try_recv()
            .expect("destination link data should route to initiator side");
        assert_eq!(to_initiator[1], 1);
    }

    #[test]
    fn test_link_table_forwarding_inserts_hash_after_claim() {
        let (mut relay, _tx) = TransportActor::new();
        relay.is_transport_enabled = true;

        let (entry1, _rx1) = make_test_interface("to_initiator");
        let (entry2, mut rx2) = make_test_interface("to_destination");
        relay.interfaces.insert(1, entry1);
        relay.interfaces.insert(2, entry2);

        let link_id = [0x7F; 16];
        relay.link_table.insert(
            link_id,
            crate::link_table::LinkEntry {
                timestamp: now_f64(),
                next_hop: None,
                interface_id: 2,
                remaining_hops: 1,
                destination_hash: [0xDF; 16],
                established: true,
                validated: true,
                proof_timeout: now_f64() + 120.0,
                receiving_interface: 1,
                taken_hops: 1,
            },
        );

        let raw =
            make_link_data_packet_with_context(link_id, 0, rns_wire::context::PacketContext::None);
        let packet_hash = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
        assert!(
            !relay.packet_hashlist.contains(&packet_hash),
            "link-table packets must not be inserted before routing claims them"
        );

        relay.on_inbound(InboundPacket {
            raw: raw.clone(),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(
            relay.packet_hashlist.contains(&packet_hash),
            "claimed link-table packet hash must be inserted after forwarding"
        );
        rx2.try_recv().expect("first link packet should forward");

        relay.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(
            rx2.try_recv().is_err(),
            "duplicate link-table packet should be dropped after hash insertion"
        );
    }

    #[test]
    fn test_link_proof_routes_via_link_table() {
        let (mut relay, _tx) = TransportActor::new();
        relay.is_transport_enabled = true;

        let (entry1, mut rx1) = make_test_interface("to_initiator");
        let (entry2, _rx2) = make_test_interface("to_destination");
        relay.interfaces.insert(1, entry1);
        relay.interfaces.insert(2, entry2);

        let link_id = [0x7B; 16];
        relay.link_table.insert(
            link_id,
            crate::link_table::LinkEntry {
                timestamp: now_f64(),
                next_hop: None,
                interface_id: 2,
                remaining_hops: 1,
                destination_hash: [0xCF; 16],
                established: true,
                validated: true,
                proof_timeout: now_f64() + 120.0,
                receiving_interface: 1,
                taken_hops: 1,
            },
        );

        relay.on_inbound(InboundPacket {
            raw: make_link_proof_packet(link_id, 0),
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });

        let routed = rx1
            .try_recv()
            .expect("link proof should route back to initiator side");
        assert_eq!(routed[1], 1);
    }

    #[test]
    fn test_lrproof_routing_3hop_chain() {
        // Test multi-relay chain: Initiator → RelayA → RelayB → Destination
        // RelayA has remaining_hops=2, RelayB has remaining_hops=1.

        // RelayB — closer to destination.
        let (mut relay_b, _tx_b) = TransportActor::new();
        relay_b.is_transport_enabled = true;

        let (entry_b1, mut rx_b1) = make_test_interface("relayB_to_relayA");
        let (entry_b2, _rx_b2) = make_test_interface("relayB_to_dest");
        relay_b.interfaces.insert(1, entry_b1);
        relay_b.interfaces.insert(2, entry_b2);

        let link_id = [0x88; 16];
        let destination_hash = [0xEE; 16];
        let destination_identity = rns_identity::identity::Identity::new();
        insert_announce_for(&mut relay_b, destination_hash, &destination_identity);
        relay_b.link_table.insert(
            link_id,
            crate::link_table::LinkEntry {
                timestamp: now_f64(),
                next_hop: Some([0xDD; 16]),
                interface_id: 2, // toward destination
                remaining_hops: 1,
                destination_hash,
                established: false,
                validated: false,
                proof_timeout: now_f64() + 120.0,
                receiving_interface: 1, // from RelayA
                taken_hops: 1,
            },
        );

        // RelayA — closer to initiator.
        let (mut relay_a, _tx_a) = TransportActor::new();
        relay_a.is_transport_enabled = true;

        let (entry_a1, mut rx_a1) = make_test_interface("relayA_to_initiator");
        let (entry_a2, _rx_a2) = make_test_interface("relayA_to_relayB");
        relay_a.interfaces.insert(1, entry_a1);
        relay_a.interfaces.insert(2, entry_a2);

        insert_announce_for(&mut relay_a, destination_hash, &destination_identity);
        relay_a.link_table.insert(
            link_id,
            crate::link_table::LinkEntry {
                timestamp: now_f64(),
                next_hop: Some([0xCC; 16]),
                interface_id: 2, // toward RelayB
                remaining_hops: 2,
                destination_hash,
                established: false,
                validated: false,
                proof_timeout: now_f64() + 120.0,
                receiving_interface: 1, // from Initiator
                taken_hops: 0,
            },
        );

        // Proof travels back: Destination → RelayB → RelayA.
        // Destination sends proof with hops=0.
        let proof = make_lrproof_packet(link_id, 0, &destination_identity, Some([1, 2, 3]));
        relay_b.on_inbound(InboundPacket {
            raw: proof,
            interface_id: 2, // from destination
            rssi: None,
            snr: None,
            q: None,
        });

        // RelayB should forward proof to RelayA (interface 1) with hops=1
        let forwarded_b = rx_b1
            .try_recv()
            .expect("RelayB should route proof toward RelayA");
        assert_eq!(forwarded_b[1], 1, "RelayB should increment proof hops to 1");

        // RelayA receives proof with hops=1.
        relay_a.on_inbound(InboundPacket {
            raw: forwarded_b,
            interface_id: 2, // from RelayB
            rssi: None,
            snr: None,
            q: None,
        });

        // RelayA should forward proof to Initiator (interface 1) with hops=2
        let forwarded_a = rx_a1
            .try_recv()
            .expect("RelayA should route proof toward Initiator");
        assert_eq!(forwarded_a[1], 2, "RelayA should increment proof hops to 2");

        // Both links should be validated
        assert!(relay_b.link_table.get(&link_id).unwrap().validated);
        assert!(relay_a.link_table.get(&link_id).unwrap().validated);
    }

    #[test]
    fn test_outbound_broadcast_plain() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, mut rx1) = make_test_interface("iface1");
        let (entry2, mut rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        // Build a Plain/Data outbound
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Plain,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: [0x66; 16],
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0xFF; 20]);

        actor.on_outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: [0x66; 16],
        });

        // Both interfaces should receive the broadcast
        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }

    #[test]
    fn test_outbound_single_with_path() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, mut rx1) = make_test_interface("iface1");
        let (entry2, mut rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let dest_hash = [0x77; 16];

        // Insert path to interface 2
        let path_entry =
            crate::path_table::PathEntry::new(Some([0xBB; 16]), 1, 2, InterfaceMode::Gateway);
        actor.path_table.insert(dest_hash, path_entry);

        let raw = make_data_packet(dest_hash, 0);
        actor.on_outbound(OutboundRequest {
            raw,
            destination_hash: dest_hash,
        });

        // Only interface 2 should receive (directed via path)
        assert!(rx1.try_recv().is_err());
        assert!(rx2.try_recv().is_ok());
    }

    #[test]
    fn outbound_no_path_proof_does_not_request_path() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, mut rx) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry);

        let dest_hash = [0x42; 16];
        let raw = make_proof_packet(dest_hash, 0);
        actor.on_outbound(OutboundRequest {
            raw: raw.clone(),
            destination_hash: dest_hash,
        });

        let sent = rx.try_recv().expect("proof should broadcast");
        assert_eq!(sent, raw);
        assert!(
            rx.try_recv().is_err(),
            "proof should not be followed by a path request"
        );
        assert!(!actor.path_requests.contains_key(&dest_hash));
    }

    fn assert_link_request_pins_to_path_owner(
        owner_name: &str,
        owner_mode: InterfaceMode,
        owner_role: InterfaceRole,
        alternate_name: &str,
        alternate_mode: InterfaceMode,
        alternate_role: InterfaceRole,
    ) {
        let (mut actor, _tx) = TransportActor::new();
        let (mut owner_entry, mut owner_rx) = make_test_interface(owner_name);
        let (mut alternate_entry, mut alternate_rx) = make_test_interface(alternate_name);
        owner_entry.mode = owner_mode;
        owner_entry.role = owner_role;
        alternate_entry.mode = alternate_mode;
        alternate_entry.role = alternate_role;
        actor.interfaces.insert(1, owner_entry);
        actor.interfaces.insert(2, alternate_entry);

        let dest_hash = [0xA7; 16];
        let owner_path = crate::path_table::PathEntry::new(None, 1, 1, owner_mode);
        actor.path_table.insert(dest_hash, owner_path);

        actor.on_outbound(OutboundRequest {
            raw: make_link_request_packet(dest_hash, 0),
            destination_hash: dest_hash,
        });

        let sent = owner_rx
            .try_recv()
            .expect("Direct LinkRequest should follow the owned path");
        let (header, _) = rns_wire::header::PacketHeader::unpack(&sent).unwrap();
        assert_eq!(
            header.flags.packet_type,
            rns_wire::flags::PacketType::LinkRequest
        );
        assert!(
            alternate_rx.try_recv().is_err(),
            "alternate interface {alternate_name} stays unused while {owner_name} owns the path"
        );
    }

    #[test]
    fn direct_link_request_without_path_broadcasts_to_all_interfaces() {
        let (mut actor, _tx) = TransportActor::new();
        let (mut auto_entry, mut auto_rx) = make_test_interface("Local Network");
        let (mut tcp_entry, mut tcp_rx) = make_test_interface("TCP peer");
        let (mut rnode_entry, mut rnode_rx) = make_test_interface("RNode");
        auto_entry.mode = InterfaceMode::Full;
        tcp_entry.mode = InterfaceMode::Full;
        rnode_entry.mode = InterfaceMode::Full;
        actor.interfaces.insert(1, auto_entry);
        actor.interfaces.insert(2, tcp_entry);
        actor.interfaces.insert(3, rnode_entry);

        let dest_hash = [0xA8; 16];
        actor.on_outbound(OutboundRequest {
            raw: make_link_request_packet(dest_hash, 0),
            destination_hash: dest_hash,
        });

        auto_rx
            .try_recv()
            .expect("no-path Direct LinkRequest should broadcast to Local Network");
        tcp_rx
            .try_recv()
            .expect("no-path Direct LinkRequest should broadcast to TCP");
        rnode_rx
            .try_recv()
            .expect("no-path Direct LinkRequest should broadcast to RNode");
    }

    #[test]
    fn direct_link_request_pins_to_path_owner_across_interface_types() {
        let cases = [
            (
                "Local Network",
                InterfaceMode::Full,
                InterfaceRole::Normal,
                "TCP peer",
                InterfaceMode::Full,
                InterfaceRole::Normal,
            ),
            (
                "BLE peer",
                InterfaceMode::Full,
                InterfaceRole::Normal,
                "TCP peer",
                InterfaceMode::Full,
                InterfaceRole::Normal,
            ),
            (
                "RNode",
                InterfaceMode::Full,
                InterfaceRole::Normal,
                "TCP peer",
                InterfaceMode::Full,
                InterfaceRole::Normal,
            ),
            (
                "TCP peer",
                InterfaceMode::Full,
                InterfaceRole::Normal,
                "Local Network",
                InterfaceMode::Full,
                InterfaceRole::Normal,
            ),
            (
                "SharedInstanceServer/client",
                InterfaceMode::Full,
                InterfaceRole::LocalClient,
                "TCP peer",
                InterfaceMode::Full,
                InterfaceRole::Normal,
            ),
        ];

        for (owner_name, owner_mode, owner_role, alternate_name, alternate_mode, alternate_role) in
            cases
        {
            assert_link_request_pins_to_path_owner(
                owner_name,
                owner_mode,
                owner_role,
                alternate_name,
                alternate_mode,
                alternate_role,
            );
        }
    }

    #[test]
    fn suppressed_path_owner_does_not_reclaim_route_during_rediscovery() {
        let (mut actor, _tx) = TransportActor::new();
        let (auto_entry, _auto_rx) = make_test_interface("Local Network");
        let (tcp_entry, _tcp_rx) = make_test_interface("TCP peer");
        actor.interfaces.insert(1, auto_entry);
        actor.interfaces.insert(2, tcp_entry);

        let identity = rns_identity::identity::Identity::new();
        let (auto_announce, dest_hash) =
            make_announce_for_with_random_blob(&identity, "lxmf.delivery", 1, [0x11; 10]);
        let (tcp_announce, _) =
            make_announce_for_with_random_blob(&identity, "lxmf.delivery", 1, [0x22; 10]);

        actor.path_table.insert(
            dest_hash,
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Full),
        );
        match actor.handle_query(TransportQuery::SuppressCurrentPathInterface {
            dest: dest_hash,
            duration: 30.0,
        }) {
            TransportQueryResponse::BoolResult(true) => {}
            other => panic!("expected current path-interface suppression, got {other:?}"),
        }
        actor.path_table.remove(&dest_hash);

        actor.on_inbound(InboundPacket {
            raw: auto_announce,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(
            !actor.path_table.has_path(&dest_hash),
            "suppressed Local Network announce must not reinstall the failed path"
        );

        actor.on_inbound(InboundPacket {
            raw: tcp_announce,
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });
        let path = actor
            .path_table
            .get(&dest_hash)
            .expect("alternate TCP announce should install a path");
        assert_eq!(path.interface_id, 2);
    }

    #[test]
    fn test_rate_tracking() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let dest_hash = [0x88; 16];

        // Record multiple announces from the same destination
        for _ in 0..5 {
            actor.rate_table.record(dest_hash);
        }

        let rate = actor.rate_table.get_rate(&dest_hash);
        assert!(rate > 0.0, "rate should be tracked");
    }

    #[test]
    fn test_ifac_interface_send() {
        let (mut actor, _tx) = TransportActor::new();
        let (mut entry, mut rx) = make_test_interface("ifac_iface");

        // Configure IFAC on this interface
        let ifac_key = rns_identity::ifac::derive_ifac_key(Some("test"), Some("pass")).unwrap();
        entry.ifac_key = Some(ifac_key);
        entry.ifac_size = 4;
        actor.interfaces.insert(1, entry);

        let data = vec![0x01, 0x02, 0x03, 0x04];
        actor.send_to_interface(1, &data);

        let sent = rx.try_recv().unwrap();
        // The sent data should be longer (IFAC tag prepended)
        assert_eq!(sent.len(), 4 + data.len()); // ifac_size + original

        // The IFAC flag should be set on byte 0 (flags byte)
        assert!(sent[0] & 0x80 != 0);
    }

    #[test]
    fn test_ifac_inbound_verify() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true; // rebroadcast requires transport
        let ifac_key = rns_identity::ifac::derive_ifac_key(Some("test"), Some("pass")).unwrap();
        let ifac_size = 4;

        let (mut entry1, _rx1) = make_test_interface("ifac_in");
        entry1.ifac_key = Some(ifac_key);
        entry1.ifac_size = ifac_size;
        actor.interfaces.insert(1, entry1);

        let (entry2, mut rx2) = make_test_interface("iface2");
        actor.interfaces.insert(2, entry2);

        // Build a valid signed announce packet
        let (announce, dest_hash) = make_valid_announce("test.ifac", 0);

        // Sign it with IFAC
        let signed = crate::ifac::ifac_sign(&announce, &ifac_key, ifac_size);

        // Inject the signed packet
        actor.on_inbound(InboundPacket {
            raw: Bytes::from(signed),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Path should be learned
        assert!(actor.path_table.has_path(&dest_hash));

        // Flush deferred announces (rebroadcast is now deferred via announce table)
        actor.flush_pending_announces();

        // Rebroadcast should appear on interface 2
        assert!(rx2.try_recv().is_ok());
    }

    #[test]
    fn test_ifac_inbound_reject_bad() {
        let (mut actor, _tx) = TransportActor::new();
        let ifac_key = rns_identity::ifac::derive_ifac_key(Some("test"), Some("pass")).unwrap();
        let wrong_key = rns_identity::ifac::derive_ifac_key(Some("wrong"), Some("key")).unwrap();
        let ifac_size = 4;

        let (mut entry1, _rx1) = make_test_interface("ifac_in");
        entry1.ifac_key = Some(ifac_key);
        entry1.ifac_size = ifac_size;
        actor.interfaces.insert(1, entry1);

        // Build valid announce and sign with WRONG IFAC key
        let (announce, dest_hash) = make_valid_announce("test.ifac_reject", 0);
        let signed = crate::ifac::ifac_sign(&announce, &wrong_key, ifac_size);

        actor.on_inbound(InboundPacket {
            raw: Bytes::from(signed),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Path should NOT be learned (IFAC verification fails)
        assert!(!actor.path_table.has_path(&dest_hash));
    }

    #[test]
    fn test_announce_retransmit() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (entry1, mut rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let (raw, dest_hash) = make_valid_announce("test.retransmit", 0);
        // Processing the announce installs the path before any retransmit
        // (next-hop gate parity).
        actor.path_table.insert(
            dest_hash,
            PathEntry::new(None, 1, 1, InterfaceMode::Gateway),
        );

        // Insert an announce entry that is due for retransmit
        let announce_entry = crate::announce::AnnounceEntry {
            timestamp: 0.0,
            retransmit_timeout: 0.0, // already due
            retries: 0,
            received_from: dest_hash,
            hops: 0,
            packet_raw: raw.to_vec(),
            local_rebroadcasts: 0,
            block_rebroadcast: false,
            attached_interface: None,
            source_interface: None,
        };
        actor.announce_table.insert(dest_hash, announce_entry);

        // Trigger tick
        actor.last_announces_check = 0.0;
        actor.on_tick();

        // Interface 1 should have received the retransmit
        assert!(rx1.try_recv().is_ok());
    }

    #[test]
    fn test_local_data_delivery() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let dest_hash = [0xCC; 16];
        actor.local_destinations.insert(dest_hash);

        let (dest_tx, mut dest_rx) = mpsc::channel(16);
        actor.destination_channels.insert(dest_hash, dest_tx);

        // Inject data packet for local destination
        let raw = make_data_packet(dest_hash, 0);
        actor.on_inbound(InboundPacket {
            raw: raw.clone(),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Should be delivered to destination channel as DestinationEvent
        let delivered = dest_rx.try_recv().unwrap();
        match delivered {
            crate::link_messages::DestinationEvent::InboundPacket { raw: data, .. } => {
                assert_eq!(data, raw);
            }
            _ => panic!("expected InboundPacket event"),
        }
    }

    #[test]
    fn data_path_response_context_does_not_install_path() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let dest_hash = [0x3A; 16];
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::PathResponse,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(b"not_an_announce");

        actor.on_inbound(InboundPacket {
            raw: Bytes::from(raw),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(
            !actor.path_table.has_path(&dest_hash),
            "only validated ANNOUNCE path responses may install paths"
        );
    }

    #[test]
    fn test_valid_announce_accepted() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let (raw, dest_hash) = make_valid_announce("test.valid", 0);

        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(actor.path_table.has_path(&dest_hash));
    }

    #[test]
    fn test_header_only_announce_rejected() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let (raw, dest_hash) = make_valid_announce("test.header_only", 0);
        let header_only = Bytes::copy_from_slice(&raw[..rns_wire::constants::HEADER_MINSIZE]);

        actor.on_inbound(InboundPacket {
            raw: header_only,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(!actor.path_table.has_path(&dest_hash));
        assert!(!actor.recent_announces.contains_key(&dest_hash));
    }

    #[test]
    fn test_blackholed_identity_announce_rejected_but_destination_hash_entry_is_not() {
        let identity = rns_identity::identity::Identity::new();
        let (raw, dest_hash) = make_announce_for(&identity, "test.blackhole.identity", 0);
        assert_ne!(
            dest_hash, identity.hash,
            "test requires distinct destination and identity hashes"
        );

        let (mut destination_blackholed_actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        destination_blackholed_actor.interfaces.insert(1, entry1);
        destination_blackholed_actor
            .blackhole_table
            .add_with_reason(dest_hash, None, crate::blackhole::BlackholeReason::Manual);
        destination_blackholed_actor.on_inbound(InboundPacket {
            raw: raw.clone(),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(destination_blackholed_actor.path_table.has_path(&dest_hash));
        assert!(
            destination_blackholed_actor
                .recent_announces
                .contains_key(&dest_hash)
        );

        let (mut identity_blackholed_actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        identity_blackholed_actor.interfaces.insert(1, entry1);
        identity_blackholed_actor.blackhole_table.add_with_reason(
            identity.hash,
            None,
            crate::blackhole::BlackholeReason::Manual,
        );
        identity_blackholed_actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(!identity_blackholed_actor.path_table.has_path(&dest_hash));
        assert!(
            !identity_blackholed_actor
                .recent_announces
                .contains_key(&dest_hash)
        );
    }

    #[test]
    fn test_known_destination_key_mismatch_rejects_inbound_announce() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let identity = rns_identity::identity::Identity::new();
        let other_identity = rns_identity::identity::Identity::new();
        let other_public_key = other_identity.get_public_key();
        let (raw, dest_hash) = make_announce_for(&identity, "test.known_key_mismatch", 0);
        actor.recent_announces.insert(
            dest_hash,
            RecentAnnounce {
                dest_hash,
                hops: 4,
                app_data: Some(b"existing".to_vec()),
                timestamp: 1.0,
                public_key: Some(other_public_key),
                ratchet: None,
                packet_hash: Some([0xAB; 32]),
                is_path_response: false,
                retained: false,
                last_used: None,
                name_hash: [0xCC; 10],
            },
        );

        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(!actor.path_table.has_path(&dest_hash));
        let cached = actor
            .recent_announces
            .get(&dest_hash)
            .expect("existing entry must not be removed");
        assert_eq!(cached.public_key, Some(other_public_key));
        assert_eq!(cached.packet_hash, Some([0xAB; 32]));
        assert_eq!(cached.name_hash, [0xCC; 10]);
    }

    #[test]
    fn retain_identity_marks_all_matching_recent_announces() {
        let (mut actor, _tx) = TransportActor::new();
        let identity = rns_identity::identity::Identity::new();
        let public_key = identity.get_public_key();
        let other_public_key = rns_identity::identity::Identity::new().get_public_key();
        let dest_a = [0xA1; 16];
        let dest_b = [0xB2; 16];
        let dest_c = [0xC3; 16];

        for (dest_hash, public_key) in [
            (dest_a, Some(public_key)),
            (dest_b, Some(public_key)),
            (dest_c, Some(other_public_key)),
        ] {
            actor.recent_announces.insert(
                dest_hash,
                RecentAnnounce {
                    dest_hash,
                    hops: 1,
                    app_data: None,
                    timestamp: 1.0,
                    public_key,
                    ratchet: None,
                    packet_hash: None,
                    is_path_response: false,
                    retained: false,
                    last_used: None,
                    name_hash: [0; 10],
                },
            );
        }

        assert!(actor.retain_identity(&identity.hash));
        assert!(actor.recent_announces[&dest_a].retained);
        assert!(actor.recent_announces[&dest_b].retained);
        assert!(!actor.recent_announces[&dest_c].retained);
        assert!(actor.state_dirty);
    }

    #[test]
    fn test_replayed_announce_random_blob_does_not_replace_path() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        let (entry1, _rx1) = make_test_interface("iface1");
        let (entry2, _rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let identity = rns_identity::identity::Identity::new();
        let blob = random_blob(0xA1, 100);
        let (raw_first, dest_hash) =
            make_announce_for_with_random_blob(&identity, "test.replay.same", 3, blob);
        let (raw_replay, _) =
            make_announce_for_with_random_blob(&identity, "test.replay.same", 1, blob);
        let (htx, mut hrx) = mpsc::channel(8);
        actor.announce_handlers.push(AnnounceHandlerRegistration {
            aspect_filter: None,
            receive_path_responses: false,
            tx: htx,
        });

        actor.on_inbound(InboundPacket {
            raw: raw_first,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        let first_event = hrx.try_recv().expect("fresh announce should dispatch");
        assert_eq!(first_event.hops, 4);

        actor.on_inbound(InboundPacket {
            raw: raw_replay,
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });

        let path = actor.path_table.get(&dest_hash).unwrap();
        assert_eq!(path.hops, 4);
        assert_eq!(path.interface_id, 1);
        assert_eq!(path.random_blobs.len(), 1);
        assert!(path.has_random_blob(&blob));
        assert_eq!(
            actor.recent_announces.get(&dest_hash).unwrap().hops,
            4,
            "replayed announces must not refresh recent announce state"
        );
        assert!(
            hrx.try_recv().is_err(),
            "replayed announces must not dispatch announce handlers"
        );
        assert_eq!(
            actor
                .announce_table
                .get(&dest_hash)
                .unwrap()
                .source_interface,
            Some(1),
            "replayed announces must not refresh rebroadcast state"
        );
    }

    #[test]
    fn test_newer_equal_or_higher_hop_announce_replaces_path() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        let (entry2, _rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let identity = rns_identity::identity::Identity::new();
        let old_blob = random_blob(0xA2, 100);
        let equal_new_blob = random_blob(0xB2, 101);
        let higher_new_blob = random_blob(0xC2, 102);
        let (raw_first, dest_hash) =
            make_announce_for_with_random_blob(&identity, "test.replay.newer", 3, old_blob);
        let (raw_equal_new, _) =
            make_announce_for_with_random_blob(&identity, "test.replay.newer", 3, equal_new_blob);
        let (raw_higher_new, _) =
            make_announce_for_with_random_blob(&identity, "test.replay.newer", 5, higher_new_blob);

        actor.on_inbound(InboundPacket {
            raw: raw_first,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        actor.on_inbound(InboundPacket {
            raw: raw_equal_new,
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });
        let path = actor.path_table.get(&dest_hash).unwrap();
        assert_eq!(path.hops, 4);
        assert_eq!(path.interface_id, 2);
        assert!(path.has_random_blob(&old_blob));
        assert!(path.has_random_blob(&equal_new_blob));

        actor.on_inbound(InboundPacket {
            raw: raw_higher_new,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        let path = actor.path_table.get(&dest_hash).unwrap();
        assert_eq!(path.hops, 6);
        assert_eq!(path.interface_id, 1);
        assert!(path.has_random_blob(&higher_new_blob));
    }

    #[test]
    fn test_older_higher_hop_announce_waits_for_expiry_or_unresponsive_path() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        let (entry2, _rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let identity = rns_identity::identity::Identity::new();
        let current_blob = random_blob(0xA3, 200);
        let older_blob = random_blob(0xB3, 199);
        let (raw_current, dest_hash) =
            make_announce_for_with_random_blob(&identity, "test.replay.older", 1, current_blob);
        let (raw_older, _) =
            make_announce_for_with_random_blob(&identity, "test.replay.older", 5, older_blob);

        actor.on_inbound(InboundPacket {
            raw: raw_current.clone(),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        actor.on_inbound(InboundPacket {
            raw: raw_older.clone(),
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });
        let path = actor.path_table.get(&dest_hash).unwrap();
        assert_eq!(path.hops, 2);
        assert_eq!(path.interface_id, 1);
        assert!(!path.has_random_blob(&older_blob));

        actor.path_table.get_mut(&dest_hash).unwrap().expires = 0.0;
        actor.on_inbound(InboundPacket {
            raw: raw_older,
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });
        let path = actor.path_table.get(&dest_hash).unwrap();
        assert_eq!(path.hops, 6);
        assert_eq!(path.interface_id, 2);
        assert!(path.has_random_blob(&older_blob));
    }

    #[test]
    fn test_unresponsive_path_accepts_same_timebase_higher_hop_replay() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        let (entry2, _rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let identity = rns_identity::identity::Identity::new();
        let blob = random_blob(0xA4, 300);
        let (raw_current, dest_hash) =
            make_announce_for_with_random_blob(&identity, "test.replay.unresponsive", 1, blob);
        let (raw_replay, _) =
            make_announce_for_with_random_blob(&identity, "test.replay.unresponsive", 5, blob);

        actor.on_inbound(InboundPacket {
            raw: raw_current,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        actor
            .path_table
            .set_state(dest_hash, crate::constants::PathState::Unresponsive);
        actor.on_inbound(InboundPacket {
            raw: raw_replay,
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });

        let path = actor.path_table.get(&dest_hash).unwrap();
        assert_eq!(path.hops, 6);
        assert_eq!(path.interface_id, 2);
        assert_eq!(
            actor.path_table.get_state(&dest_hash),
            crate::constants::PathState::Unknown,
            "replacement path must clear stale unresponsive state"
        );
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let (raw, dest_hash) = make_valid_announce("test.tamper", 0);
        let mut raw = raw.to_vec();

        // Tamper with a byte in the payload (signature area)
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;

        actor.on_inbound(InboundPacket {
            raw: Bytes::from(raw),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Path should NOT be learned due to invalid signature
        assert!(!actor.path_table.has_path(&dest_hash));
    }

    #[test]
    fn test_wrong_dest_hash_rejected() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        // Create a valid announce but then change the dest_hash in the header
        let identity = rns_identity::identity::Identity::new();
        let app_name = "test.wrong_hash";
        let dest_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
            app_name,
            Some(&identity.hash),
        );
        let announce_data =
            rns_identity::announce::AnnounceData::create(&identity, app_name, None, None).unwrap();
        let payload = announce_data.pack();

        // Use a WRONG dest_hash in the header
        let wrong_hash = [0xFF; 16];
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: wrong_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&payload);

        actor.on_inbound(InboundPacket {
            raw: Bytes::from(raw),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Neither the wrong hash nor the real hash should be learned
        assert!(!actor.path_table.has_path(&wrong_hash));
        assert!(!actor.path_table.has_path(&dest_hash));
    }

    fn make_header2_data_packet(
        transport_id: [u8; 16],
        dest_hash: [u8; 16],
        hops: u8,
        payload: &[u8],
    ) -> Bytes {
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header2,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Transport,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id: Some(transport_id),
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(payload);
        Bytes::from(raw)
    }

    fn make_header2_link_request_packet(
        transport_id: [u8; 16],
        dest_hash: [u8; 16],
        hops: u8,
        payload: &[u8],
    ) -> Bytes {
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header2,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Transport,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::LinkRequest,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id: Some(transport_id),
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(payload);
        Bytes::from(raw)
    }

    fn make_header2_announce(
        transport_id: [u8; 16],
        app_name: &str,
        hops: u8,
    ) -> (Bytes, [u8; 16], rns_identity::identity::Identity) {
        let identity = rns_identity::identity::Identity::new();
        let dest_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
            app_name,
            Some(&identity.hash),
        );
        let announce_data =
            rns_identity::announce::AnnounceData::create(&identity, app_name, None, None).unwrap();
        let payload = announce_data.pack();

        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header2,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Transport,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops,
            transport_id: Some(transport_id),
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&payload);
        (Bytes::from(raw), dest_hash, identity)
    }

    #[test]
    fn test_header2_data_local_delivery() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let transport_id = [0xAA; 16];
        let dest_hash = [0xBB; 16];
        actor.local_destinations.insert(dest_hash);

        let (dest_tx, mut dest_rx) = mpsc::channel(16);
        actor.destination_channels.insert(dest_hash, dest_tx);

        // Build Header2 Data packet (as a transport relay would send)
        let payload = b"encrypted_lxmf_data_here";
        let raw = make_header2_data_packet(transport_id, dest_hash, 2, payload);

        actor.on_inbound(InboundPacket {
            raw: raw.clone(),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Should be delivered to destination channel
        let delivered = dest_rx.try_recv().unwrap();
        match delivered {
            crate::link_messages::DestinationEvent::InboundPacket { raw: data, .. } => {
                // The raw bytes delivered include the full Header2 header
                assert_eq!(data, raw);
                // Verify that PacketHeader::unpack correctly extracts the payload
                let (hdr, data_offset) = rns_wire::header::PacketHeader::unpack(&data).unwrap();
                assert_eq!(hdr.destination_hash, dest_hash);
                assert_eq!(hdr.transport_id, Some(transport_id));
                assert_eq!(data_offset, 35); // Header2 offset
                assert_eq!(&data[data_offset..], payload);
            }
            _ => panic!("expected InboundPacket event"),
        }
    }

    #[test]
    fn test_header2_data_transport_forwarding() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (entry1, _rx1) = make_test_interface("iface_in");
        let (entry2, mut rx2) = make_test_interface("iface_out");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let transport_id = [0xAA; 16]; // hub identity
        let dest_hash = [0xBB; 16]; // final destination (NOT local)
        actor.transport_identity_hash = Some(transport_id);

        // Set up path: dest_hash is reachable via interface 2
        let path_entry = crate::path_table::PathEntry::new(
            Some([0xCC; 16]), // next_hop
            1,
            2, // interface 2
            InterfaceMode::Gateway,
        );
        actor.path_table.insert(dest_hash, path_entry);

        // Inject Header2 Data
        let payload = b"relay_this_data";
        let raw = make_header2_data_packet(transport_id, dest_hash, 1, payload);

        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Should be forwarded via interface 2 with Python-style final-hop
        // Header2 -> Header1 rewrite and inbound-adjusted hops.
        let forwarded = rx2.try_recv().unwrap();
        assert_eq!(forwarded[1], 2); // raw 1 -> inbound-adjusted 2
        let (hdr, offset) = rns_wire::header::PacketHeader::unpack(&forwarded).unwrap();
        assert_eq!(hdr.flags.header_type, rns_wire::flags::HeaderType::Header1);
        assert_eq!(hdr.transport_id, None);
        assert_eq!(hdr.destination_hash, dest_hash);
        assert_eq!(&forwarded[offset..], payload);
    }

    #[test]
    fn test_header2_transport_packet_for_other_transport_is_dropped() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        actor.transport_identity_hash = Some([0xAA; 16]);

        let (entry1, _rx1) = make_test_interface("iface_in");
        let (entry2, mut rx2) = make_test_interface("iface_out");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let dest_hash = [0xBB; 16];
        actor.path_table.insert(
            dest_hash,
            crate::path_table::PathEntry::new(None, 1, 2, InterfaceMode::Gateway),
        );

        let raw = make_header2_data_packet([0xCC; 16], dest_hash, 1, b"not_for_us");
        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(rx2.try_recv().is_err());
    }

    #[test]
    fn test_header2_packet_for_other_transport_is_not_forwarded_to_local_client() {
        let (mut actor, _tx) = TransportActor::new();
        actor.transport_identity_hash = Some([0xAA; 16]);

        let (external, _external_rx) = make_test_interface("external");
        let (mut local_client, mut local_rx) = make_test_interface("SharedInstanceServer/client");
        local_client.role = InterfaceRole::LocalClient;
        actor.interfaces.insert(1, external);
        actor.interfaces.insert(2, local_client);

        let dest_hash = [0xBC; 16];
        actor.path_table.insert(
            dest_hash,
            crate::path_table::PathEntry::new(None, 0, 2, InterfaceMode::Gateway),
        );

        let raw = make_header2_data_packet([0xCC; 16], dest_hash, 0, b"wrong_transport");
        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(local_rx.try_recv().is_err());
    }

    #[test]
    fn test_outbound_header1_to_header2_wrapping() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, mut rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let dest_hash = [0xDD; 16];
        let next_hop = [0xEE; 16];

        // next_hop present + hops > 1 triggers Header1 -> Header2 wrap.
        // At 1 hop, only a shared-instance client wraps.
        let path_entry =
            crate::path_table::PathEntry::new(Some(next_hop), 2, 1, InterfaceMode::Gateway);
        actor.path_table.insert(dest_hash, path_entry);

        // Build outbound Header1 Data
        let payload = b"outbound_message_data";
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(payload);

        actor.on_outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: dest_hash,
        });

        // Interface should receive Header2 with transport_id = next_hop
        let sent = rx1.try_recv().unwrap();
        let (sent_hdr, sent_offset) = rns_wire::header::PacketHeader::unpack(&sent).unwrap();
        assert_eq!(
            sent_hdr.flags.header_type,
            rns_wire::flags::HeaderType::Header2
        );
        assert_eq!(
            sent_hdr.flags.transport_type,
            rns_wire::flags::TransportType::Transport
        );
        assert_eq!(sent_hdr.transport_id, Some(next_hop));
        assert_eq!(sent_hdr.destination_hash, dest_hash);
        assert_eq!(sent_offset, 35);
        // Payload is preserved after wrapping
        assert_eq!(&sent[sent_offset..], payload);
    }

    #[test]
    fn test_outbound_wrapping_preserves_context_and_flags() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, mut rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let dest_hash = [0x11; 16];
        let next_hop = [0x22; 16];

        let path_entry =
            crate::path_table::PathEntry::new(Some(next_hop), 2, 1, InterfaceMode::Gateway);
        actor.path_table.insert(dest_hash, path_entry);

        // Build Header1 with specific context and destination type
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0xAB; 50]); // substantial payload

        actor.on_outbound(OutboundRequest {
            raw: Bytes::from(raw.clone()),
            destination_hash: dest_hash,
        });

        let sent = rx1.try_recv().unwrap();
        let (sent_hdr, offset) = rns_wire::header::PacketHeader::unpack(&sent).unwrap();

        // Packet type and destination type preserved
        assert_eq!(
            sent_hdr.flags.packet_type,
            rns_wire::flags::PacketType::Data
        );
        assert_eq!(
            sent_hdr.flags.destination_type,
            rns_wire::flags::DestinationType::Single
        );
        assert_eq!(sent_hdr.context, rns_wire::context::PacketContext::None);
        assert_eq!(sent_hdr.hops, 0);
        // Payload = everything after the original 19-byte Header1 header
        assert_eq!(&sent[offset..], &[0xAB; 50]);
    }

    #[test]
    fn test_header2_announce_learns_next_hop() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let transport_id = [0xAA; 16]; // transport relay
        let (raw, dest_hash, _identity) = make_header2_announce(transport_id, "test.h2announce", 2);

        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Path should be learned with next_hop = transport_id
        assert!(actor.path_table.has_path(&dest_hash));
        let path = actor.path_table.get(&dest_hash).unwrap();
        assert_eq!(path.next_hop, Some(transport_id));
        assert_eq!(path.hops, 3);
        assert_eq!(path.interface_id, 1);
    }

    #[test]
    fn test_tunnel_learned_header2_announce_records_full_metadata() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let tunnel_id = [0x31; 32];
        actor.tunnel_table.insert(crate::tunnel::TunnelEntry {
            tunnel_id,
            interface_id: 1,
            tunnel_paths: std::collections::HashMap::new(),
            expires: now_f64() + 600.0,
        });

        let transport_id = [0xAA; 16];
        let (raw, dest_hash, _identity) =
            make_header2_announce(transport_id, "test.tunnel.h2announce", 2);
        let expected_packet_hash =
            rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header2);

        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        let tunnel = actor.tunnel_table.get(&tunnel_id).unwrap();
        let tunnel_path = tunnel.tunnel_paths.get(&dest_hash).unwrap();
        assert_eq!(tunnel_path.next_hop, Some(transport_id));
        assert_eq!(tunnel_path.hops, 3);
        assert_eq!(tunnel_path.packet_hash, Some(expected_packet_hash));
        assert!(
            !tunnel_path.random_blobs.is_empty(),
            "tunnel path must preserve announce random blobs for freshness comparisons"
        );
    }

    #[test]
    fn test_restore_tunnel_path_preserves_next_hop_and_packet_hash() {
        let (mut actor, _tx) = TransportActor::new();

        let tunnel_id = [0x32; 32];
        let dest_hash = [0x44; 16];
        let next_hop = [0x55; 16];
        let packet_hash = [0x66; 32];
        let random_blob = random_blob(0x77, 100);
        let mut tunnel_paths = std::collections::HashMap::new();
        tunnel_paths.insert(
            dest_hash,
            crate::tunnel::TunnelPath {
                timestamp: now_f64(),
                next_hop: Some(next_hop),
                hops: 4,
                expires: now_f64() + 600.0,
                random_blobs: vec![random_blob],
                packet_hash: Some(packet_hash),
            },
        );
        actor.tunnel_table.insert(crate::tunnel::TunnelEntry {
            tunnel_id,
            interface_id: 0,
            tunnel_paths,
            expires: now_f64() + 600.0,
        });

        actor.restore_tunnel_paths(&tunnel_id, 9);

        let restored = actor.path_table.get(&dest_hash).unwrap();
        assert_eq!(restored.next_hop, Some(next_hop));
        assert_eq!(restored.packet_hash, Some(packet_hash));
        assert_eq!(restored.interface_id, 9);
        assert!(restored.has_random_blob(&random_blob));
    }

    #[test]
    fn test_restore_tunnel_path_drops_older_than_active_path() {
        let (mut actor, _tx) = TransportActor::new();

        let tunnel_id = [0x33; 32];
        let dest_hash = [0x45; 16];
        let mut active = crate::path_table::PathEntry::new(None, 4, 1, InterfaceMode::Gateway);
        let active_blob = random_blob(0x80, 200);
        active.add_random_blob(active_blob);
        actor.path_table.insert(dest_hash, active);

        let tunnel_blob = random_blob(0x81, 100);
        let mut tunnel_paths = std::collections::HashMap::new();
        tunnel_paths.insert(
            dest_hash,
            crate::tunnel::TunnelPath {
                timestamp: now_f64(),
                next_hop: Some([0x99; 16]),
                hops: 4,
                expires: now_f64() + 600.0,
                random_blobs: vec![tunnel_blob],
                packet_hash: Some([0x88; 32]),
            },
        );
        actor.tunnel_table.insert(crate::tunnel::TunnelEntry {
            tunnel_id,
            interface_id: 0,
            tunnel_paths,
            expires: now_f64() + 600.0,
        });

        actor.restore_tunnel_paths(&tunnel_id, 9);

        let active_after = actor.path_table.get(&dest_hash).unwrap();
        assert_eq!(active_after.interface_id, 1);
        assert!(active_after.has_random_blob(&active_blob));
        assert!(
            !actor
                .tunnel_table
                .get(&tunnel_id)
                .unwrap()
                .tunnel_paths
                .contains_key(&dest_hash),
            "older tunnel path should be pruned after losing freshness comparison"
        );
    }

    #[test]
    fn test_maintenance_culls_stale_tunnel_paths() {
        let (mut actor, _tx) = TransportActor::new();

        let tunnel_id = [0x34; 32];
        let stale_dest = [0x46; 16];
        let fresh_dest = [0x47; 16];
        let mut tunnel_paths = std::collections::HashMap::new();
        tunnel_paths.insert(
            stale_dest,
            crate::tunnel::TunnelPath {
                timestamp: now_f64() - TUNNEL_PATH_TIMEOUT as f64 - 1.0,
                next_hop: None,
                hops: 1,
                expires: now_f64() + 600.0,
                random_blobs: vec![],
                packet_hash: Some([0x46; 32]),
            },
        );
        tunnel_paths.insert(
            fresh_dest,
            crate::tunnel::TunnelPath {
                timestamp: now_f64(),
                next_hop: None,
                hops: 1,
                expires: now_f64() + 600.0,
                random_blobs: vec![],
                packet_hash: Some([0x47; 32]),
            },
        );
        actor.tunnel_table.insert(crate::tunnel::TunnelEntry {
            tunnel_id,
            interface_id: 1,
            tunnel_paths,
            expires: now_f64() + 600.0,
        });

        actor.cull_stale_tunnel_paths(now_f64());

        let tunnel = actor.tunnel_table.get(&tunnel_id).unwrap();
        assert!(!tunnel.tunnel_paths.contains_key(&stale_dest));
        assert!(tunnel.tunnel_paths.contains_key(&fresh_dest));
    }

    #[test]
    fn test_header1_announce_learns_path_no_next_hop() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, _rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let (raw, dest_hash) = make_valid_announce("test.direct", 0);

        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(actor.path_table.has_path(&dest_hash));
        let path = actor.path_table.get(&dest_hash).unwrap();
        assert_eq!(
            path.next_hop, None,
            "Header1 announce should have no next_hop"
        );
        assert_eq!(path.hops, 1);
    }

    #[test]
    fn test_announce_then_outbound_wrapping_chain() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, mut rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        // Step 1: Receive Header2 announce (from dest via transport relay)
        // Use raw hops=2 so the path records inbound-adjusted hops=3.
        let transport_id = [0xCC; 16];
        let (announce_raw, dest_hash, _identity) =
            make_header2_announce(transport_id, "test.chain", 2);

        actor.on_inbound(InboundPacket {
            raw: announce_raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Drain the announce rebroadcast
        let _ = rx1.try_recv();

        // Verify path learned with next_hop
        assert!(actor.path_table.has_path(&dest_hash));
        assert_eq!(
            actor.path_table.get(&dest_hash).unwrap().next_hop,
            Some(transport_id)
        );

        // Send outbound Data to that destination.
        let payload = b"hello_mesh_world";
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(payload);

        actor.on_outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: dest_hash,
        });

        // Should be wrapped as Header2 with transport_id = transport relay
        let sent = rx1.try_recv().unwrap();
        let (sent_hdr, offset) = rns_wire::header::PacketHeader::unpack(&sent).unwrap();
        assert_eq!(
            sent_hdr.flags.header_type,
            rns_wire::flags::HeaderType::Header2
        );
        assert_eq!(sent_hdr.transport_id, Some(transport_id));
        assert_eq!(sent_hdr.destination_hash, dest_hash);
        assert_eq!(&sent[offset..], payload);
    }

    #[test]
    fn test_header1_data_unknown_dest_no_transport_dropped() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = false;

        let (entry1, _rx1) = make_test_interface("iface1");
        let (entry2, mut rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let dest_hash = [0xFF; 16]; // unknown, not local, no path
        let raw = make_data_packet(dest_hash, 0);

        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Nothing forwarded (not a transport node)
        assert!(rx2.try_recv().is_err());
    }

    #[test]
    fn test_header1_data_transport_enabled_does_not_forward() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (entry1, _rx1) = make_test_interface("iface1");
        let (entry2, mut rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let dest_hash = [0x44; 16];
        let path_entry = crate::path_table::PathEntry::new(
            None, // direct path, no next_hop
            0,
            2,
            InterfaceMode::Gateway,
        );
        actor.path_table.insert(dest_hash, path_entry);

        let raw = make_data_packet(dest_hash, 0);

        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Python transport relays only in-transport Header2 packets addressed
        // to the local transport identity. Header1 traffic is direct only.
        assert!(rx2.try_recv().is_err());
    }

    #[test]
    fn test_header2_link_request_final_hop_rewrites_to_header1() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (entry1, _rx1) = make_test_interface("iface_in");
        let (entry2, mut rx2) = make_test_interface("iface_out");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let transport_id = [0xAA; 16];
        let dest_hash = [0xBB; 16];
        actor.transport_identity_hash = Some(transport_id);
        actor.path_table.insert(
            dest_hash,
            crate::path_table::PathEntry::new(None, 1, 2, InterfaceMode::Gateway),
        );

        let payload = [0x42; 64];
        let raw = make_header2_link_request_packet(transport_id, dest_hash, 1, &payload);
        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        let forwarded = rx2.try_recv().unwrap();
        let (hdr, offset) = rns_wire::header::PacketHeader::unpack(&forwarded).unwrap();
        assert_eq!(hdr.flags.header_type, rns_wire::flags::HeaderType::Header1);
        assert_eq!(
            hdr.flags.packet_type,
            rns_wire::flags::PacketType::LinkRequest
        );
        assert_eq!(hdr.transport_id, None);
        assert_eq!(hdr.hops, 2);
        assert_eq!(&forwarded[offset..], &payload);
    }

    #[test]
    fn test_outbound_no_next_hop_sends_header1() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry1, mut rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let dest_hash = [0x55; 16];
        let path_entry = crate::path_table::PathEntry::new(
            None, // no next_hop → no wrapping
            0,
            1,
            InterfaceMode::Gateway,
        );
        actor.path_table.insert(dest_hash, path_entry);

        let raw = make_data_packet(dest_hash, 0);
        actor.on_outbound(OutboundRequest {
            raw,
            destination_hash: dest_hash,
        });

        let sent = rx1.try_recv().unwrap();
        let (sent_hdr, _) = rns_wire::header::PacketHeader::unpack(&sent).unwrap();
        assert_eq!(
            sent_hdr.flags.header_type,
            rns_wire::flags::HeaderType::Header1,
            "no next_hop should send as Header1 without wrapping"
        );
        assert_eq!(sent_hdr.transport_id, None);
    }

    #[test]
    fn test_peer_hub_client_full_relay_chain() {
        let (mut peer, _peer_tx) = TransportActor::new();
        let (mut hub, _hub_tx) = TransportActor::new();
        let (mut client, _client_tx) = TransportActor::new();

        hub.is_transport_enabled = true; // Hub is transport node
        let hub_transport_id = [0xA1; 16];
        hub.transport_identity_hash = Some(hub_transport_id);

        // Wire interfaces (we'll manually relay between them)
        let (peer_iface, mut peer_rx) = make_test_interface("peer_tcp");
        let (hub_iface1, mut hub_rx1) = make_test_interface("hub_tcp_to_peer");
        let (hub_iface2, mut hub_rx2) = make_test_interface("hub_tcp_to_client");
        let (client_iface, _client_rx) = make_test_interface("client_tcp");

        peer.interfaces.insert(1, peer_iface);
        hub.interfaces.insert(1, hub_iface1);
        hub.interfaces.insert(2, hub_iface2);
        client.interfaces.insert(1, client_iface);

        // Client announces itself.
        let client_identity = rns_identity::identity::Identity::new();
        let client_dest_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
            "lxmf.delivery",
            Some(&client_identity.hash),
        );
        let announce_data = rns_identity::announce::AnnounceData::create(
            &client_identity,
            "lxmf.delivery",
            None,
            None,
        )
        .unwrap();
        let announce_payload = announce_data.pack();

        // Register the client's local destination.
        let (client_dest_tx, mut client_dest_rx) = mpsc::channel(16);
        client.local_destinations.insert(client_dest_hash);
        client
            .destination_channels
            .insert(client_dest_hash, client_dest_tx);

        // Client sends announce as Header1 outbound.
        let announce_flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        };
        let announce_header = rns_wire::header::PacketHeader {
            flags: announce_flags,
            hops: 0,
            transport_id: None,
            destination_hash: client_dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut announce_raw = announce_header.pack();
        announce_raw.extend_from_slice(&announce_payload);

        // Inject the announce into the hub.
        hub.on_inbound(InboundPacket {
            raw: Bytes::from(announce_raw.clone()),
            interface_id: 2, // arrived from client-side interface
            rssi: None,
            snr: None,
            q: None,
        });

        // Hub should have learned path to client_dest_hash via interface 2.
        assert!(hub.path_table.has_path(&client_dest_hash));
        let hub_path = hub.path_table.get(&client_dest_hash).unwrap();
        assert_eq!(hub_path.interface_id, 2);
        assert_eq!(hub_path.next_hop, None, "direct announce → no next_hop");

        // Flush deferred announces (rebroadcast is now deferred via announce table)
        hub.flush_pending_announces();

        // Hub rebroadcasts announce on other interfaces.
        let rebroadcast = hub_rx1.try_recv().unwrap();
        assert_eq!(rebroadcast[1], 1); // hub's inbound-adjusted announce hops

        // Peer receives the rebroadcast.
        peer.on_inbound(InboundPacket {
            raw: rebroadcast,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Peer should know the path to client_dest_hash.
        assert!(peer.path_table.has_path(&client_dest_hash));
        assert_eq!(
            peer.path_table.get(&client_dest_hash).unwrap().next_hop,
            Some(hub_transport_id)
        );

        // Peer sends LXMF Data to the client. Production would encrypt and
        // wrap into a Data packet; the test uses an opaque ciphertext.
        let lxmf_ciphertext = b"fake_encrypted_lxmf_message_payload_with_some_data";

        let data_flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let data_header = rns_wire::header::PacketHeader {
            flags: data_flags,
            hops: 0,
            transport_id: None,
            destination_hash: client_dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut data_raw = data_header.pack();
        data_raw.extend_from_slice(lxmf_ciphertext);

        // Peer sends outbound.
        peer.on_outbound(OutboundRequest {
            raw: Bytes::from(data_raw.clone()),
            destination_hash: client_dest_hash,
        });

        // Peer's interface sends Header2 addressed to the hub learned from
        // the transport announce.
        let peer_sent = peer_rx.try_recv().unwrap();
        let (peer_sent_header, _) = rns_wire::header::PacketHeader::unpack(&peer_sent).unwrap();
        assert_eq!(peer_sent_header.transport_id, Some(hub_transport_id));

        // Hub receives the Data from the peer.
        hub.on_inbound(InboundPacket {
            raw: peer_sent.clone(),
            interface_id: 1, // arrived from peer side
            rssi: None,
            snr: None,
            q: None,
        });

        // Hub is a transport node with a path to client_dest_hash via
        // interface 2, so process_data() forwards it.
        let hub_forwarded = hub_rx2.try_recv().unwrap();

        // Verify hub forwarded final hop as Header1 with inbound-adjusted hops.
        let (fwd_hdr, fwd_offset) = rns_wire::header::PacketHeader::unpack(&hub_forwarded).unwrap();
        assert_eq!(fwd_hdr.flags.packet_type, rns_wire::flags::PacketType::Data);
        assert_eq!(
            fwd_hdr.flags.header_type,
            rns_wire::flags::HeaderType::Header1
        );
        assert_eq!(fwd_hdr.destination_hash, client_dest_hash);
        assert_eq!(fwd_hdr.hops, 1);
        assert_eq!(&hub_forwarded[fwd_offset..], lxmf_ciphertext);

        // Client receives the forwarded Data.
        client.on_inbound(InboundPacket {
            raw: hub_forwarded,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // Client's local destination should have received the packet.
        let delivered = client_dest_rx.try_recv().unwrap();
        match delivered {
            crate::link_messages::DestinationEvent::InboundPacket { raw, .. } => {
                let (d_hdr, d_offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
                assert_eq!(d_hdr.destination_hash, client_dest_hash);
                assert_eq!(
                    &raw[d_offset..],
                    lxmf_ciphertext,
                    "LXMF ciphertext should arrive intact"
                );
            }
            _ => panic!("expected InboundPacket event"),
        }
    }

    #[test]
    fn test_bidirectional_via_hub() {
        let (mut hub, _hub_tx) = TransportActor::new();
        hub.is_transport_enabled = true;
        let hub_transport_id = [0xAA; 16];
        hub.transport_identity_hash = Some(hub_transport_id);

        let (hub_iface1, mut hub_rx1) = make_test_interface("hub_to_tdeck");
        let (hub_iface2, mut hub_rx2) = make_test_interface("hub_to_rust");
        hub.interfaces.insert(1, hub_iface1);
        hub.interfaces.insert(2, hub_iface2);

        // Hub knows paths to both nodes
        let tdeck_dest = [0x11; 16];
        let rust_dest = [0x22; 16];

        // Path to T-Deck: via interface 1, direct final hop
        hub.path_table.insert(
            tdeck_dest,
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Gateway),
        );
        // Path to Rust: via interface 2, direct final hop
        hub.path_table.insert(
            rust_dest,
            crate::path_table::PathEntry::new(None, 1, 2, InterfaceMode::Gateway),
        );

        // T-Deck → Hub → Rust
        let msg_a = make_header2_data_packet(hub_transport_id, rust_dest, 0, b"a");
        hub.on_inbound(InboundPacket {
            raw: msg_a,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        let fwd_a = hub_rx2
            .try_recv()
            .expect("should forward to Rust via iface 2");
        let (hdr_a, _) = rns_wire::header::PacketHeader::unpack(&fwd_a).unwrap();
        assert_eq!(hdr_a.destination_hash, rust_dest);

        // Rust → Hub → T-Deck
        let msg_b = make_header2_data_packet(hub_transport_id, tdeck_dest, 0, b"b");
        hub.on_inbound(InboundPacket {
            raw: msg_b,
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });
        let fwd_b = hub_rx1
            .try_recv()
            .expect("should forward to T-Deck via iface 1");
        let (hdr_b, _) = rns_wire::header::PacketHeader::unpack(&fwd_b).unwrap();
        assert_eq!(hdr_b.destination_hash, tdeck_dest);
    }

    #[test]
    fn test_packet_hash_dedup_header1_then_header2() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        let transport_id = [0xBB; 16];
        actor.transport_identity_hash = Some(transport_id);

        let (entry1, _rx1) = make_test_interface("iface1");
        let (entry2, mut rx2) = make_test_interface("iface2");
        actor.interfaces.insert(1, entry1);
        actor.interfaces.insert(2, entry2);

        let dest_hash = [0x99; 16];
        actor.path_table.insert(
            dest_hash,
            crate::path_table::PathEntry::new(Some([0xAA; 16]), 1, 2, InterfaceMode::Gateway),
        );

        // Inject Header2 Data addressed to this transport.
        let raw_h2 = make_header2_data_packet(transport_id, dest_hash, 0, b"dedupe");
        actor.on_inbound(InboundPacket {
            raw: raw_h2.clone(),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        // First packet should be forwarded
        assert!(rx2.try_recv().is_ok());

        // Now inject the exact same packet again — should be deduplicated.
        actor.on_inbound(InboundPacket {
            raw: raw_h2,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(rx2.try_recv().is_err(), "duplicate should be dropped");
    }

    /// Dedup hash is content-stable: Header1 and its Header2-wrapped twin
    /// collide so a wrapped relay cannot bypass dedup on the next hop.
    #[test]
    fn test_header1_header2_same_content_same_hash() {
        // This validates the hash dedup design: same dest+context+payload
        // produces the same hash regardless of Header1 vs Header2 wrapping
        let dest = [0xBB; 16];
        let transport_id = [0xCC; 16];
        let payload = b"test_payload_data";

        // Header1
        let raw_h1 = {
            let flags = rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Single,
                packet_type: rns_wire::flags::PacketType::Data,
            };
            let header = rns_wire::header::PacketHeader {
                flags,
                hops: 0,
                transport_id: None,
                destination_hash: dest,
                context: rns_wire::context::PacketContext::None,
            };
            let mut raw = header.pack();
            raw.extend_from_slice(payload);
            raw
        };

        // Header2 with same dest+context+payload
        let raw_h2 = {
            let flags = rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header2,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Transport,
                destination_type: rns_wire::flags::DestinationType::Single,
                packet_type: rns_wire::flags::PacketType::Data,
            };
            let header = rns_wire::header::PacketHeader {
                flags,
                hops: 3,
                transport_id: Some(transport_id),
                destination_hash: dest,
                context: rns_wire::context::PacketContext::None,
            };
            let mut raw = header.pack();
            raw.extend_from_slice(payload);
            raw
        };

        let hash_h1 = rns_wire::hash::packet_hash(&raw_h1, rns_wire::flags::HeaderType::Header1);
        let hash_h2 = rns_wire::hash::packet_hash(&raw_h2, rns_wire::flags::HeaderType::Header2);
        assert_eq!(
            hash_h1, hash_h2,
            "Header1 and Header2 with same content must produce same packet hash"
        );
    }

    #[test]
    fn test_shared_instance_wraps_at_1_hop() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_shared_instance = true;

        let (entry1, mut rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let dest_hash = [0xAA; 16];
        let next_hop = [0xBB; 16];

        // Path with 1 hop and next_hop: should wrap on shared instance
        let path_entry =
            crate::path_table::PathEntry::new(Some(next_hop), 1, 1, InterfaceMode::Gateway);
        actor.path_table.insert(dest_hash, path_entry);

        let raw = make_data_packet(dest_hash, 0);
        actor.on_outbound(OutboundRequest {
            raw,
            destination_hash: dest_hash,
        });

        let sent = rx1.try_recv().unwrap();
        let (sent_hdr, _) = rns_wire::header::PacketHeader::unpack(&sent).unwrap();
        assert_eq!(
            sent_hdr.flags.header_type,
            rns_wire::flags::HeaderType::Header2
        );
        assert_eq!(sent_hdr.transport_id, Some(next_hop));
    }

    #[test]
    fn test_non_shared_instance_wraps_at_1_hop_with_next_hop() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_shared_instance = false;

        let (entry1, mut rx1) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry1);

        let dest_hash = [0xAA; 16];
        let next_hop = [0xBB; 16];

        // Path with 1 hop and next_hop: MUST wrap even without shared instance,
        // because transport nodes only forward Header2 packets.
        let path_entry =
            crate::path_table::PathEntry::new(Some(next_hop), 1, 1, InterfaceMode::Gateway);
        actor.path_table.insert(dest_hash, path_entry);

        let raw = make_data_packet(dest_hash, 0);
        actor.on_outbound(OutboundRequest {
            raw,
            destination_hash: dest_hash,
        });

        let sent = rx1.try_recv().unwrap();
        let (sent_hdr, _) = rns_wire::header::PacketHeader::unpack(&sent).unwrap();
        assert_eq!(
            sent_hdr.flags.header_type,
            rns_wire::flags::HeaderType::Header2
        );
        assert_eq!(sent_hdr.transport_id, Some(next_hop));
    }

    #[test]
    fn test_path_expire_force_cull() {
        let mut table = PathTable::new();
        let hash = [0xCC; 16];
        table.insert(
            hash,
            crate::path_table::PathEntry::new(None, 0, 1, InterfaceMode::Gateway),
        );
        assert!(table.has_path(&hash));

        // expire() should set expires=0 and immediately cull
        table.expire(&hash);
        assert!(!table.has_path(&hash));
    }

    #[test]
    fn test_announce_queue_life_culling() {
        let (mut actor, _tx) = TransportActor::new();
        let (mut entry, _rx) = make_test_interface("iface1");
        // Add stale announce queue entries
        entry.announce_queue.push(crate::messages::QueuedAnnounce {
            destination_hash: [0x01; 16],
            time: 0.0, // Very old
            hops: 1,
            raw: Bytes::from_static(&[0u8; 32]),
        });
        entry.announce_queue.push(crate::messages::QueuedAnnounce {
            destination_hash: [0x02; 16],
            time: now_f64(), // Fresh
            hops: 1,
            raw: Bytes::from_static(&[0u8; 32]),
        });
        actor.interfaces.insert(1, entry);

        // Cull at current time
        actor.cull_announce_queues(now_f64());

        // Only the fresh entry should remain
        assert_eq!(actor.interfaces.get(&1).unwrap().announce_queue.len(), 1);
        assert_eq!(
            actor.interfaces.get(&1).unwrap().announce_queue[0].destination_hash,
            [0x02; 16]
        );
    }

    #[test]
    fn test_register_link_initiator() {
        let (mut actor, _tx) = TransportActor::new();
        let link_id = [0xAA; 16];

        actor.handle_message(TransportMessage::RegisterLink {
            link_id,
            destination_hash: [0xBB; 16],
            interface_id: 1,
            next_hop: Some([0xCC; 16]),
            remaining_hops: 3,
            initiator: true,
        });

        let entry = actor.link_table.get(&link_id).unwrap();
        assert!(!entry.validated);
        assert!(!entry.established);
    }

    #[test]
    fn test_register_link_responder() {
        let (mut actor, _tx) = TransportActor::new();
        let link_id = [0xAA; 16];

        actor.handle_message(TransportMessage::RegisterLink {
            link_id,
            destination_hash: [0xBB; 16],
            interface_id: 1,
            next_hop: None,
            remaining_hops: 0,
            initiator: false,
        });

        let entry = actor.link_table.get(&link_id).unwrap();
        assert!(entry.validated);
        assert!(entry.established);
    }

    #[test]
    fn test_activate_link() {
        let (mut actor, _tx) = TransportActor::new();
        let link_id = [0xAA; 16];

        // Register as initiator (pending)
        actor.handle_message(TransportMessage::RegisterLink {
            link_id,
            destination_hash: [0xBB; 16],
            interface_id: 1,
            next_hop: None,
            remaining_hops: 0,
            initiator: true,
        });
        assert!(!actor.link_table.get(&link_id).unwrap().validated);

        // Activate
        actor.handle_message(TransportMessage::ActivateLink { link_id });
        let entry = actor.link_table.get(&link_id).unwrap();
        assert!(entry.validated);
        assert!(entry.established);
    }

    #[test]
    fn test_deferred_cache_clean() {
        let (mut actor, _tx) = TransportActor::new();
        assert!(!actor.startup_complete);

        // Before any interface is registered, startup_time is 0
        assert_eq!(actor.startup_time, 0.0);

        // Register an interface to start the startup timer
        let (entry, _rx) = make_test_interface("iface1");
        actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry });
        assert!(actor.startup_time > 0.0);
        assert!(!actor.startup_complete);
    }

    #[test]
    fn test_held_announce_storage() {
        let (mut actor, _tx) = TransportActor::new();
        let (mut entry, _rx) = make_test_interface("iface1");

        let dest_hash = [0xDD; 16];
        entry.ingress.hold_announce(crate::ingress::HeldAnnounce {
            raw: Bytes::from_static(&[0u8; 32]),
            hops: 2,
            destination_hash: dest_hash,
            receiving_interface_id: 1,
        });
        actor.interfaces.insert(1, entry);

        assert_eq!(actor.interfaces.get(&1).unwrap().ingress.held_count(), 1);
    }

    #[test]
    fn test_interface_stats_include_pr_and_burst_state() {
        let (mut actor, _tx) = TransportActor::new();
        let (mut entry, _rx) = make_test_interface("stats_iface");

        for _ in 0..50 {
            entry.ingress.received_announce();
            entry.ingress.received_path_request();
        }
        assert!(entry.ingress.should_ingress_limit());
        assert!(entry.ingress.should_ingress_limit_pr());
        for _ in 0..3 {
            entry.ingress.sent_announce();
            entry.ingress.sent_path_request();
        }
        actor.interfaces.insert(1, entry);

        match actor.handle_query(TransportQuery::GetInterfaceStats) {
            TransportQueryResponse::InterfaceStats(stats) => {
                assert_eq!(stats.len(), 1);
                let entry = &stats[0];
                assert!(entry.incoming_announce_frequency > 0.0);
                assert!(entry.outgoing_announce_frequency > 0.0);
                assert!(entry.incoming_pr_frequency > 0.0);
                assert!(entry.outgoing_pr_frequency > 0.0);
                assert!(entry.burst_active);
                assert!(entry.burst_activated > 0.0);
                assert!(entry.pr_burst_active);
                assert!(entry.pr_burst_activated > 0.0);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// Floods a fresh actor with a tight burst of *unique* announces on one
    /// interface, then asserts: (a) the per-interface ingress controller
    /// engaged burst mode, and (b) the controller is now holding at least
    /// one of the held announces. This is the integration sibling of the
    /// `IngressController` unit tests in `ingress.rs` — it pins the wiring
    /// in `inbound.rs` that calls `received_announce()` and `hold_announce()`.
    #[test]
    fn test_inbound_announce_flood_engages_ingress_hold() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (entry_in, _rx_in) = make_test_interface("flooded_iface");
        let (entry_out, _rx_out) = make_test_interface("relay_iface");
        actor.interfaces.insert(1, entry_in);
        actor.interfaces.insert(2, entry_out);

        // Burst many distinct announces. Each unique destination ensures the
        // packet hashlist doesn't dedupe them — every one passes through the
        // ingress gate on its own merits.
        for _ in 0..50 {
            let (raw, _dest) = make_valid_announce("test.flood", 1);
            actor.on_inbound(crate::messages::InboundPacket {
                raw,
                interface_id: 1,
                rssi: None,
                snr: None,
                q: None,
            });
        }

        let entry = actor.interfaces.get(&1).expect("inbound interface present");
        assert!(
            entry.ingress.is_burst_active(),
            "flood of 50 announces in a tight loop must engage burst mode"
        );
        assert!(
            entry.ingress.held_count() > 0,
            "burst mode must result in at least one held announce (got {})",
            entry.ingress.held_count()
        );
    }

    /// Ingress-limit is bypassed for announces whose destination matches an
    /// outstanding path request — the announce *is* the answer, so holding it
    /// only delays resolution. This pins the bypass: with the interface in
    /// burst-active state, an announce for a pending `path_requests` entry
    /// must be processed (held_count unchanged), while one for an unknown
    /// destination must still be held.
    #[test]
    fn test_path_request_destination_bypasses_ingress_hold() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (entry_in, _rx_in) = make_test_interface("path_req_iface");
        actor.interfaces.insert(1, entry_in);

        // Drive the controller into burst-active state.
        for _ in 0..50 {
            let (raw, _dest) = make_valid_announce("test.flood", 1);
            actor.on_inbound(crate::messages::InboundPacket {
                raw,
                interface_id: 1,
                rssi: None,
                snr: None,
                q: None,
            });
        }
        assert!(
            actor.interfaces.get(&1).unwrap().ingress.is_burst_active(),
            "precondition: burst must be active before testing bypass"
        );
        let held_before = actor.interfaces.get(&1).unwrap().ingress.held_count();

        // Build an announce for a fresh destination, register it as an active
        // path request, then send it. The bypass must let it through.
        let (raw_match, dest_match) = make_valid_announce("test.path_req.match", 1);
        actor.path_requests.insert(dest_match, now_f64());
        actor.on_inbound(crate::messages::InboundPacket {
            raw: raw_match,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        let held_after_bypass = actor.interfaces.get(&1).unwrap().ingress.held_count();
        assert_eq!(
            held_after_bypass, held_before,
            "an announce whose destination is in path_requests must NOT be held"
        );

        // Discovery requests on behalf of another peer use the same bypass.
        let (raw_discovery, dest_discovery) = make_valid_announce("test.path_req.discovery", 1);
        actor.discovery_path_requests.insert(
            dest_discovery,
            DiscoveryPathRequest {
                requesting_interface: 1,
                timeout: now_f64() + PATH_REQUEST_TIMEOUT,
            },
        );
        actor.on_inbound(crate::messages::InboundPacket {
            raw: raw_discovery,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        let held_after_discovery = actor.interfaces.get(&1).unwrap().ingress.held_count();
        assert_eq!(
            held_after_discovery, held_after_bypass,
            "an announce whose destination is in discovery_path_requests must NOT be held"
        );

        // Control: an announce for an unknown destination must still be held.
        let (raw_other, _dest_other) = make_valid_announce("test.path_req.other", 1);
        actor.on_inbound(crate::messages::InboundPacket {
            raw: raw_other,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        let held_after_other = actor.interfaces.get(&1).unwrap().ingress.held_count();
        assert!(
            held_after_other > held_after_discovery,
            "control: a burst-time announce without a matching path request must still be held"
        );
    }

    #[test]
    fn test_invalid_announces_do_not_trip_ingress_hold() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (entry_in, _rx_in) = make_test_interface("invalid_flood_iface");
        actor.interfaces.insert(1, entry_in);

        for _ in 0..50 {
            let (raw, _dest) = make_valid_announce("test.invalid.flood", 1);
            let mut raw = raw.to_vec();
            let last = raw.len() - 1;
            raw[last] ^= 0x01;
            actor.on_inbound(crate::messages::InboundPacket {
                raw: Bytes::from(raw),
                interface_id: 1,
                rssi: None,
                snr: None,
                q: None,
            });
        }

        let entry = actor.interfaces.get(&1).unwrap();
        assert!(
            !entry.ingress.is_burst_active(),
            "signature-invalid announces must be dropped before ingress accounting"
        );
        assert_eq!(entry.ingress.held_count(), 0);
        assert_eq!(actor.path_table.iter().count(), 0);
    }

    #[test]
    fn test_known_reannounce_bypasses_ingress_hold() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (entry_in, _rx_in) = make_test_interface("known_reannounce_iface");
        actor.interfaces.insert(1, entry_in);

        let identity = rns_identity::identity::Identity::new();
        let old_blob = random_blob(0x91, 10);
        let (first_raw, dest_hash) =
            make_announce_for_with_random_blob(&identity, "test.known.ingress", 1, old_blob);
        actor.on_inbound(crate::messages::InboundPacket {
            raw: first_raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(actor.path_table.has_path(&dest_hash));

        for _ in 0..50 {
            let (raw, _dest) = make_valid_announce("test.known.flood", 1);
            actor.on_inbound(crate::messages::InboundPacket {
                raw,
                interface_id: 1,
                rssi: None,
                snr: None,
                q: None,
            });
        }
        let held_before = actor.interfaces.get(&1).unwrap().ingress.held_count();
        assert!(actor.interfaces.get(&1).unwrap().ingress.is_burst_active());

        let new_blob = random_blob(0x92, 11);
        let (reannounce_raw, _) =
            make_announce_for_with_random_blob(&identity, "test.known.ingress", 1, new_blob);
        actor.on_inbound(crate::messages::InboundPacket {
            raw: reannounce_raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        assert_eq!(
            actor.interfaces.get(&1).unwrap().ingress.held_count(),
            held_before,
            "known re-announces must not be held during ingress burst"
        );
        assert!(
            actor
                .path_table
                .get(&dest_hash)
                .unwrap()
                .has_random_blob(&new_blob),
            "known re-announce must refresh the active path"
        );
    }

    #[test]
    fn test_known_path_response_bypasses_ingress_hold_but_unknown_is_held() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (entry_in, _rx_in) = make_test_interface("path_response_ingress_iface");
        actor.interfaces.insert(1, entry_in);

        let identity = rns_identity::identity::Identity::new();
        let (first_raw, known_dest) = make_announce_for(&identity, "test.known.path_response", 1);
        actor.on_inbound(crate::messages::InboundPacket {
            raw: first_raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(actor.path_table.has_path(&known_dest));

        for _ in 0..50 {
            let (raw, _dest) = make_valid_announce("test.path_response.flood", 1);
            actor.on_inbound(crate::messages::InboundPacket {
                raw,
                interface_id: 1,
                rssi: None,
                snr: None,
                q: None,
            });
        }
        assert!(actor.interfaces.get(&1).unwrap().ingress.is_burst_active());
        let held_before = actor.interfaces.get(&1).unwrap().ingress.held_count();

        let (known_response, _) = make_announce_for_context(
            &identity,
            "test.known.path_response",
            1,
            rns_wire::context::PacketContext::PathResponse,
        );
        actor.on_inbound(crate::messages::InboundPacket {
            raw: known_response,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert_eq!(
            actor.interfaces.get(&1).unwrap().ingress.held_count(),
            held_before,
            "known path responses must not be held during ingress burst"
        );

        let other_identity = rns_identity::identity::Identity::new();
        let (unknown_response, unknown_dest) = make_announce_for_context(
            &other_identity,
            "test.unknown.path_response",
            1,
            rns_wire::context::PacketContext::PathResponse,
        );
        actor.on_inbound(crate::messages::InboundPacket {
            raw: unknown_response,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(
            actor.interfaces.get(&1).unwrap().ingress.held_count() > held_before,
            "unsolicited unknown path responses remain subject to ingress hold"
        );
        assert!(
            !actor.path_table.has_path(&unknown_dest),
            "held unknown path response must not install a route immediately"
        );
    }

    /// `broadcast_announce_on_interfaces` must enqueue rather than send
    /// directly, and `process_announce_queues` must drain one entry per
    /// gate-open while pushing `announce_allowed_at` forward by the
    /// `tx_time / announce_cap` formula. This test exercises both halves.
    #[test]
    fn test_broadcast_announce_queues_then_spaces_via_cap() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, mut rx) = make_test_interface("spaced_iface");
        actor.interfaces.insert(1, entry);

        let (raw, dest) = make_valid_announce("test.cap", 0);
        let raw_len = raw.len();

        // Two distinct announces back-to-back. The first call must just
        // enqueue (nothing on the wire yet). Both destinations are local so
        // the next-hop gate does not apply.
        actor.local_destinations.insert(dest);
        actor.broadcast_announce_on_interfaces(&raw, None);
        let (raw2, dest2) = make_valid_announce("test.cap.b", 0);
        actor.local_destinations.insert(dest2);
        actor.broadcast_announce_on_interfaces(&raw2, None);
        assert!(
            rx.try_recv().is_err(),
            "broadcast_announce_on_interfaces must NOT send directly — it queues"
        );
        assert_eq!(
            actor.interfaces.get(&1).unwrap().announce_queue.len(),
            2,
            "both announces must sit in the per-interface queue"
        );

        // Drain once: only the lowest-hops entry should send and the gate
        // should slide forward by tx_time/announce_cap.
        let now = now_f64();
        actor.process_announce_queues(now);
        assert!(
            rx.try_recv().is_ok(),
            "process_announce_queues must release one announce on the wire"
        );

        let entry = actor.interfaces.get(&1).expect("interface still present");
        let expected_delay =
            (raw_len as f64 * 8.0) / entry.bitrate.max(1) as f64 / entry.announce_cap.max(0.001);
        let actual_delay = entry.announce_allowed_at - now;
        assert!(
            (actual_delay - expected_delay).abs() < 1e-6,
            "announce_allowed_at must be pushed forward by tx_time/cap (expected {expected_delay}, got {actual_delay})"
        );
        assert_eq!(
            entry.announce_queue.len(),
            1,
            "the second announce must remain queued behind the bandwidth gate"
        );

        // A second drain at the same `now` is gated — no further sends.
        actor.process_announce_queues(now);
        assert!(
            rx.try_recv().is_err(),
            "second drain before announce_allowed_at must not release the next entry"
        );
    }

    #[test]
    fn test_blackhole_rpc_operations() {
        let (mut actor, _tx) = TransportActor::new();

        // Add a blackhole via RPC
        let resp = actor.handle_query(crate::messages::TransportQuery::BlackholeIdentity {
            hash: [0xAA; 16],
            ttl: None,
            reason: crate::blackhole::BlackholeReason::Manual,
            reason_label: None,
        });
        assert!(matches!(resp, crate::messages::TransportQueryResponse::Ok));
        assert!(actor.blackhole_table.is_blackholed(&[0xAA; 16]));

        // Remove via RPC — returns BoolResult(true) when something was removed.
        let resp = actor.handle_query(crate::messages::TransportQuery::UnblackholeIdentity {
            hash: [0xAA; 16],
        });
        assert!(matches!(
            resp,
            crate::messages::TransportQueryResponse::BoolResult(true)
        ));
        assert!(!actor.blackhole_table.is_blackholed(&[0xAA; 16]));

        // Removing a non-existent hash returns BoolResult(false).
        let resp = actor.handle_query(crate::messages::TransportQuery::UnblackholeIdentity {
            hash: [0xAA; 16],
        });
        assert!(matches!(
            resp,
            crate::messages::TransportQueryResponse::BoolResult(false)
        ));

        // IsBlackholed query
        actor.blackhole_table.add_with_reason(
            [0xBB; 16],
            None,
            crate::blackhole::BlackholeReason::Malformed,
        );
        let resp =
            actor.handle_query(crate::messages::TransportQuery::IsBlackholed { hash: [0xBB; 16] });
        assert!(matches!(
            resp,
            crate::messages::TransportQueryResponse::BoolResult(true)
        ));
        let resp =
            actor.handle_query(crate::messages::TransportQuery::IsBlackholed { hash: [0xCC; 16] });
        assert!(matches!(
            resp,
            crate::messages::TransportQueryResponse::BoolResult(false)
        ));

        // ClearSystemBlackholes drops Malformed/RateLimit/ProtocolViolation but
        // leaves Manual entries intact. We use a real identity for the Manual
        // entry so it survives the manifest publication filter (Stage 3) which
        // refuses to republish identities not backed by a known announce.
        let manual_identity = rns_identity::identity::Identity::new();
        let manual_public_key = manual_identity.get_public_key();
        actor.recent_announces.insert(
            [0xD0; 16],
            RecentAnnounce {
                dest_hash: [0xD0; 16],
                hops: 1,
                app_data: None,
                timestamp: 1.0,
                public_key: Some(manual_public_key),
                ratchet: None,
                packet_hash: None,
                is_path_response: false,
                retained: false,
                last_used: None,
                name_hash: [0; 10],
            },
        );
        actor.blackhole_table.add_with_reason(
            manual_identity.hash,
            None,
            crate::blackhole::BlackholeReason::Manual,
        );
        actor.blackhole_table.add_with_reason(
            [0xEE; 16],
            None,
            crate::blackhole::BlackholeReason::RateLimit,
        );
        let resp = actor.handle_query(crate::messages::TransportQuery::ClearSystemBlackholes);
        let cleared = match resp {
            crate::messages::TransportQueryResponse::IntResult(n) => n,
            other => panic!("expected IntResult, got {other:?}"),
        };
        assert_eq!(cleared, 2);
        assert!(actor.blackhole_table.is_blackholed(&manual_identity.hash));
        assert!(!actor.blackhole_table.is_blackholed(&[0xBB; 16]));
        assert!(!actor.blackhole_table.is_blackholed(&[0xEE; 16]));

        let payload =
            match actor.handle_query(crate::messages::TransportQuery::BuildBlackholeManifest {
                publisher: [0x99; 16],
            }) {
                crate::messages::TransportQueryResponse::Data(payload) => payload,
                other => panic!("expected Data manifest, got {other:?}"),
            };
        let decoded = crate::discovery::decode_manifest(&payload).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0, manual_identity.hash);
        assert_eq!(decoded[0].1.source.as_bytes(), &[0x99; 16]);

        let (mut subscriber, _tx) = TransportActor::new();
        let applied = match subscriber
            .handle_query(crate::messages::TransportQuery::ApplyBlackholeManifest { payload })
        {
            crate::messages::TransportQueryResponse::IntResult(n) => n,
            other => panic!("expected IntResult, got {other:?}"),
        };
        assert_eq!(applied, 1);
        assert!(
            subscriber
                .blackhole_table
                .is_blackholed(&manual_identity.hash)
        );
    }

    // Python 1.3.8 Transport.py:234-238: transport disabled + default config
    // swaps the wire-facing identity to a per-boot ephemeral one, keeping the
    // persisted hash as the internal identity.
    #[test]
    fn ephemeral_transport_identity_swap_when_transport_disabled() {
        let (mut actor, _tx) = TransportActor::new();
        let persistent = [0x11; 16];

        actor.handle_message(TransportMessage::SetTransportIdentity {
            identity_hash: persistent,
        });

        assert_eq!(actor.internal_identity_hash, Some(persistent));
        let ephemeral = actor
            .transport_identity_hash
            .expect("wire identity must be set");
        assert_ne!(
            ephemeral, persistent,
            "wire identity must not expose the persisted hash"
        );

        // Per-boot stable: a repeated identity set keeps the same ephemeral.
        actor.handle_message(TransportMessage::SetTransportIdentity {
            identity_hash: persistent,
        });
        assert_eq!(actor.transport_identity_hash, Some(ephemeral));

        // Enabling transport restores the persistent identity (the runtime
        // sends SetTransportIdentity before SetTransportEnabled).
        actor.handle_message(TransportMessage::SetTransportEnabled { enabled: true });
        assert_eq!(actor.transport_identity_hash, Some(persistent));
    }

    #[test]
    fn static_transport_identity_flag_keeps_persistent_identity() {
        let (mut actor, _tx) = TransportActor::new();
        actor.static_transport_identity = true;
        let persistent = [0x22; 16];

        actor.handle_message(TransportMessage::SetTransportIdentity {
            identity_hash: persistent,
        });

        assert_eq!(actor.transport_identity_hash, Some(persistent));
        assert_eq!(actor.internal_identity_hash, Some(persistent));
        assert_eq!(actor.ephemeral_identity_hash, None);
    }

    #[test]
    fn preseeded_ephemeral_identity_hash_is_used() {
        // The runtime may generate the full ephemeral Identity itself (its
        // discovery/blackhole destinations need the keys) and pre-seed the
        // hash so both layers agree on the wire value.
        let (mut actor, _tx) = TransportActor::new();
        actor.ephemeral_identity_hash = Some([0xEE; 16]);

        actor.handle_message(TransportMessage::SetTransportIdentity {
            identity_hash: [0x33; 16],
        });

        assert_eq!(actor.transport_identity_hash, Some([0xEE; 16]));
        assert_eq!(actor.internal_identity_hash, Some([0x33; 16]));
    }

    #[test]
    fn transport_enabled_before_identity_keeps_persistent_identity() {
        let (mut actor, _tx) = TransportActor::new();
        actor.handle_message(TransportMessage::SetTransportEnabled { enabled: true });
        actor.handle_message(TransportMessage::SetTransportIdentity {
            identity_hash: [0x44; 16],
        });
        assert_eq!(actor.transport_identity_hash, Some([0x44; 16]));
        assert_eq!(actor.ephemeral_identity_hash, None);
    }

    // ---- local_hops_delta (Python 1.3.8 Transport.py:1356-1365, 1.3.7
    // eacff56f instance-local exclusions) ----

    fn make_data_packet_with_dest_type(
        dest_hash: [u8; 16],
        destination_type: rns_wire::flags::DestinationType,
    ) -> Bytes {
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0xDD; 32]);
        Bytes::from(raw)
    }

    #[test]
    fn local_hops_delta_disabled_by_default_is_noop() {
        let (mut actor, _tx) = TransportActor::new();
        assert_eq!(actor.local_hops_delta, 0);
        let (entry, mut rx) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry);

        let raw = make_data_packet([0x21; 16], 0);
        actor.on_outbound(OutboundRequest {
            raw: raw.clone(),
            destination_hash: [0x21; 16],
        });
        let sent = rx.try_recv().unwrap();
        assert_eq!(&sent[..], &raw[..], "disabled delta must not touch bytes");
    }

    #[test]
    fn local_hops_delta_mangles_outbound_by_destination_type() {
        let (mut actor, _tx) = TransportActor::new();
        actor.local_hops_delta = 5;
        let (entry, mut rx) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry);

        // SINGLE data: hops byte rewritten to the delta, rest untouched.
        let raw = make_data_packet_with_dest_type([0x21; 16], rns_wire::flags::DestinationType::Single);
        actor.on_outbound(OutboundRequest {
            raw: raw.clone(),
            destination_hash: [0x21; 16],
        });
        let sent = rx.try_recv().unwrap();
        assert_eq!(sent[1], 5);
        assert_eq!(sent[0], raw[0]);
        assert_eq!(&sent[2..], &raw[2..]);
        while rx.try_recv().is_ok() {} // drain the automatic path request

        // PLAIN and GROUP destinations are excluded (Transport.py:1358).
        for dest_type in [
            rns_wire::flags::DestinationType::Plain,
            rns_wire::flags::DestinationType::Group,
        ] {
            let raw = make_data_packet_with_dest_type([0x22; 16], dest_type);
            actor.on_outbound(OutboundRequest {
                raw: raw.clone(),
                destination_hash: [0x22; 16],
            });
            let sent = rx.try_recv().unwrap();
            assert_eq!(&sent[..], &raw[..], "{dest_type:?} must not be mangled");
        }
    }

    #[test]
    fn local_hops_delta_announce_transport_insert() {
        let (mut actor, _tx) = TransportActor::new();
        actor.local_hops_delta = 4;
        let transport_id = [0x77; 16];
        actor.transport_identity_hash = Some(transport_id);
        let (entry, mut rx) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry);

        let (raw, dest_hash) = make_valid_announce("delta.announce", 0);
        actor.local_destinations.insert(dest_hash);
        actor.on_outbound(OutboundRequest {
            raw: raw.clone(),
            destination_hash: dest_hash,
        });

        let sent = rx.try_recv().unwrap();
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&sent).unwrap();
        assert_eq!(
            header.flags.header_type,
            rns_wire::flags::HeaderType::Header2
        );
        assert_eq!(
            header.flags.transport_type,
            rns_wire::flags::TransportType::Transport
        );
        assert_eq!(header.flags.packet_type, rns_wire::flags::PacketType::Announce);
        assert_eq!(header.transport_id, Some(transport_id));
        assert_eq!(header.destination_hash, dest_hash);
        assert_eq!(header.hops, 4);
        assert_eq!(
            sent.len(),
            raw.len() + 16,
            "HEADER_2 insert adds the 16-byte transport_id"
        );
        assert_eq!(
            &sent[offset..],
            &raw[rns_wire::constants::HEADER_MINSIZE..],
            "announce payload must be preserved"
        );
        // The hashable part skips hops/transport bits, so the packet hash is
        // stable across the mangle (Python Packet.get_hashable_part).
        assert_eq!(
            rns_wire::hash::packet_hash(&sent, rns_wire::flags::HeaderType::Header2),
            rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1),
        );
    }

    #[test]
    fn local_hops_delta_applies_on_known_path_sends() {
        let (mut actor, _tx) = TransportActor::new();
        actor.local_hops_delta = 3;
        let (entry, mut rx) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry);

        // Transport-wrapped send (Transport.py:1153): hops byte = delta.
        let dest_a = [0x31; 16];
        actor.path_table.insert(
            dest_a,
            crate::path_table::PathEntry::new(Some([0xBB; 16]), 2, 1, InterfaceMode::Gateway),
        );
        actor.on_outbound(OutboundRequest {
            raw: make_data_packet(dest_a, 0),
            destination_hash: dest_a,
        });
        let sent = rx.try_recv().unwrap();
        let (header, _) = rns_wire::header::PacketHeader::unpack(&sent).unwrap();
        assert_eq!(
            header.flags.header_type,
            rns_wire::flags::HeaderType::Header2
        );
        assert_eq!(header.transport_id, Some([0xBB; 16]));
        assert_eq!(header.hops, 3, "wrapped send must carry the delta");

        // Direct send (Transport.py:1186-1187): mangle_hops.
        let dest_b = [0x32; 16];
        actor.path_table.insert(
            dest_b,
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Gateway),
        );
        actor.on_outbound(OutboundRequest {
            raw: make_data_packet(dest_b, 0),
            destination_hash: dest_b,
        });
        let sent = rx.try_recv().unwrap();
        assert_eq!(sent[1], 3, "direct send must carry the delta");
    }

    #[test]
    fn local_hops_delta_skips_local_client_and_shared_peer_interfaces() {
        let (mut actor, _tx) = TransportActor::new();
        actor.local_hops_delta = 6;

        let (mut client, mut client_rx) = make_test_interface("local_client");
        client.role = InterfaceRole::LocalClient;
        let (mut peer, mut peer_rx) = make_test_interface("shared_peer");
        peer.role = InterfaceRole::SharedInstancePeer;
        let (normal, mut normal_rx) = make_test_interface("external");
        actor.interfaces.insert(1, client);
        actor.interfaces.insert(2, peer);
        actor.interfaces.insert(3, normal);

        actor.on_outbound(OutboundRequest {
            raw: make_data_packet([0x41; 16], 0),
            destination_hash: [0x41; 16],
        });

        assert_eq!(client_rx.try_recv().unwrap()[1], 0, "local client exempt");
        assert_eq!(peer_rx.try_recv().unwrap()[1], 0, "shared peer exempt");
        assert_eq!(normal_rx.try_recv().unwrap()[1], 6, "external mangled");
    }

    #[test]
    fn local_hops_delta_suppressed_when_connected_to_shared_instance() {
        let (mut actor, _tx) = TransportActor::new();
        actor.local_hops_delta = 6;
        actor.is_shared_instance = true;
        let (entry, mut rx) = make_test_interface("iface1");
        actor.interfaces.insert(1, entry);

        actor.on_outbound(OutboundRequest {
            raw: make_data_packet([0x42; 16], 0),
            destination_hash: [0x42; 16],
        });
        assert_eq!(
            rx.try_recv().unwrap()[1],
            0,
            "shared-instance clients never apply the delta themselves"
        );
    }

    #[test]
    fn local_hops_delta_link_table_substitution_and_instance_local_exemption() {
        // Shared-instance host forwarding link traffic for a local client
        // (Transport.py:1731).
        let (mut actor, _tx) = TransportActor::new();
        actor.local_hops_delta = 6;

        let (mut client, _client_rx) = make_test_interface("local_client");
        client.role = InterfaceRole::LocalClient;
        let (external, mut external_rx) = make_test_interface("external");
        actor.interfaces.insert(1, client);
        actor.interfaces.insert(2, external);

        let link_id = [0x51; 16];
        actor.link_table.insert(
            link_id,
            crate::link_table::LinkEntry {
                timestamp: now_f64(),
                next_hop: None,
                interface_id: 2,
                remaining_hops: 1,
                destination_hash: [0xC1; 16],
                established: true,
                validated: true,
                proof_timeout: now_f64() + 120.0,
                receiving_interface: 1,
                taken_hops: 0,
            },
        );
        actor.on_inbound(InboundPacket {
            raw: make_link_data_packet(link_id, 0),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        let forwarded = external_rx.try_recv().unwrap();
        assert_eq!(forwarded[1], 6, "local-client link traffic gets the delta");

        // Instance-local link (both sides local clients): exempt — this is
        // the 1.3.6 regression fixed in 1.3.7 (eacff56f).
        let (mut actor, _tx) = TransportActor::new();
        actor.local_hops_delta = 6;
        let (mut client_a, _rx_a) = make_test_interface("client_a");
        client_a.role = InterfaceRole::LocalClient;
        let (mut client_b, mut rx_b) = make_test_interface("client_b");
        client_b.role = InterfaceRole::LocalClient;
        actor.interfaces.insert(1, client_a);
        actor.interfaces.insert(2, client_b);

        let link_id = [0x52; 16];
        actor.link_table.insert(
            link_id,
            crate::link_table::LinkEntry {
                timestamp: now_f64(),
                next_hop: None,
                interface_id: 2,
                remaining_hops: 0,
                destination_hash: [0xC2; 16],
                established: true,
                validated: true,
                proof_timeout: now_f64() + 120.0,
                receiving_interface: 1,
                taken_hops: 0,
            },
        );
        actor.on_inbound(InboundPacket {
            raw: make_link_data_packet(link_id, 0),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        let forwarded = rx_b.try_recv().unwrap();
        assert_eq!(
            forwarded[1], 0,
            "instance-local link traffic must keep its true hop count"
        );
    }

    #[test]
    fn local_hops_delta_lrproof_transit_exclusions() {
        // Destination is a local client, initiator is external: the proof
        // leaving the instance gets the delta (Transport.py:2222).
        let (mut actor, _tx) = TransportActor::new();
        actor.local_hops_delta = 6;
        actor.is_transport_enabled = true;

        let (external, mut external_rx) = make_test_interface("to_initiator");
        let (mut client, _client_rx) = make_test_interface("local_client");
        client.role = InterfaceRole::LocalClient;
        actor.interfaces.insert(1, external);
        actor.interfaces.insert(2, client);

        let link_id = [0x61; 16];
        let destination_hash = [0xC3; 16];
        let destination_identity = rns_identity::identity::Identity::new();
        insert_announce_for(&mut actor, destination_hash, &destination_identity);
        actor.link_table.insert(
            link_id,
            crate::link_table::LinkEntry {
                timestamp: now_f64(),
                next_hop: None,
                interface_id: 2,
                remaining_hops: 0,
                destination_hash,
                established: false,
                validated: false,
                proof_timeout: now_f64() + 120.0,
                receiving_interface: 1,
                taken_hops: 1,
            },
        );
        let proof = make_lrproof_packet(link_id, 0, &destination_identity, None);
        actor.on_inbound(InboundPacket {
            raw: proof,
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });
        let routed = external_rx.try_recv().unwrap();
        assert_eq!(routed[1], 6, "proof leaving the instance gets the delta");

        // Instance-local link: proof between two local clients is exempt.
        let (mut actor, _tx) = TransportActor::new();
        actor.local_hops_delta = 6;
        let (mut client_a, mut rx_a) = make_test_interface("client_a");
        client_a.role = InterfaceRole::LocalClient;
        let (mut client_b, _rx_b) = make_test_interface("client_b");
        client_b.role = InterfaceRole::LocalClient;
        actor.interfaces.insert(1, client_a);
        actor.interfaces.insert(2, client_b);

        let link_id = [0x62; 16];
        let destination_hash = [0xC4; 16];
        let destination_identity = rns_identity::identity::Identity::new();
        insert_announce_for(&mut actor, destination_hash, &destination_identity);
        actor.link_table.insert(
            link_id,
            crate::link_table::LinkEntry {
                timestamp: now_f64(),
                next_hop: None,
                interface_id: 2,
                remaining_hops: 0,
                destination_hash,
                established: false,
                validated: false,
                proof_timeout: now_f64() + 120.0,
                receiving_interface: 1,
                taken_hops: 0,
            },
        );
        let proof = make_lrproof_packet(link_id, 0, &destination_identity, None);
        actor.on_inbound(InboundPacket {
            raw: proof,
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });
        let routed = rx_a.try_recv().unwrap();
        assert_eq!(
            routed[1], 0,
            "instance-local link proof must keep its true hop count"
        );
    }

    #[test]
    fn local_hops_delta_reverse_proof_exclusions() {
        // Proof originated by a local client heading to an external requester
        // gets the delta (Transport.py:2287).
        let (mut actor, _tx) = TransportActor::new();
        actor.local_hops_delta = 6;
        actor.is_transport_enabled = true;

        let (external, mut external_rx) = make_test_interface("external");
        let (mut client, _client_rx) = make_test_interface("local_client");
        client.role = InterfaceRole::LocalClient;
        actor.interfaces.insert(1, external);
        actor.interfaces.insert(2, client);

        let proof_hash = [0x71; 16];
        actor.reverse_table.insert(proof_hash, 1, 1);
        actor.on_inbound(InboundPacket {
            raw: make_proof_packet(proof_hash, 0),
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });
        let routed = external_rx.try_recv().unwrap();
        assert_eq!(routed[1], 6, "local-client proof gets the delta");

        // Proof heading back to a local client is exempt (1.3.7 eacff56f).
        let (mut actor, _tx) = TransportActor::new();
        actor.local_hops_delta = 6;
        actor.is_transport_enabled = true;
        let (mut client_a, mut rx_a) = make_test_interface("client_a");
        client_a.role = InterfaceRole::LocalClient;
        let (mut client_b, _rx_b) = make_test_interface("client_b");
        client_b.role = InterfaceRole::LocalClient;
        actor.interfaces.insert(1, client_a);
        actor.interfaces.insert(2, client_b);

        let proof_hash = [0x72; 16];
        actor.reverse_table.insert(proof_hash, 1, 0);
        actor.on_inbound(InboundPacket {
            raw: make_proof_packet(proof_hash, 0),
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });
        let routed = rx_a.try_recv().unwrap();
        assert_eq!(
            routed[1], 0,
            "proof to a local client must keep its true hop count"
        );
    }

    #[test]
    fn local_hops_delta_strips_transport_header_on_local_client_delivery() {
        // Transport.py:1613-1619: with the delta active, HEADER_2 frames
        // delivered to a local shared client lose their transport headers.
        let (mut actor, _tx) = TransportActor::new();
        actor.local_hops_delta = 6;
        actor.is_transport_enabled = true;
        let transport_id = [0x88; 16];
        actor.transport_identity_hash = Some(transport_id);

        let (external, _external_rx) = make_test_interface("external");
        let (mut client, mut client_rx) = make_test_interface("local_client");
        client.role = InterfaceRole::LocalClient;
        actor.interfaces.insert(1, external);
        actor.interfaces.insert(2, client);

        let dest_hash = [0x81; 16];
        actor.path_table.insert(
            dest_hash,
            crate::path_table::PathEntry::new(None, 0, 2, InterfaceMode::Gateway),
        );

        let raw = make_header2_data_packet(transport_id, dest_hash, 1, b"to_local_client");
        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        let delivered = client_rx.try_recv().unwrap();
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&delivered).unwrap();
        assert_eq!(
            header.flags.header_type,
            rns_wire::flags::HeaderType::Header1,
            "transport headers must be stripped for local-client delivery"
        );
        assert_eq!(
            header.flags.transport_type,
            rns_wire::flags::TransportType::Broadcast
        );
        assert_eq!(header.transport_id, None);
        assert_eq!(header.hops, 2, "raw 1 -> inbound-adjusted 2");
        assert_eq!(&delivered[offset..], b"to_local_client");
    }

    // Shared snapshot consumed by the runtime link layer for the Python 1.3.8
    // Link.py:966-968 blackholed-identity link teardown.
    #[test]
    fn blackhole_snapshot_tracks_rpc_mutations() {
        let (mut actor, _tx) = TransportActor::new();
        let snapshot = actor.blackholed_snapshot.clone();
        assert!(snapshot.read().unwrap().is_empty());

        actor.handle_query(crate::messages::TransportQuery::BlackholeIdentity {
            hash: [0xAB; 16],
            ttl: None,
            reason: crate::blackhole::BlackholeReason::Manual,
            reason_label: None,
        });
        assert!(snapshot.read().unwrap().contains(&[0xAB; 16]));

        actor.handle_query(crate::messages::TransportQuery::UnblackholeIdentity {
            hash: [0xAB; 16],
        });
        assert!(!snapshot.read().unwrap().contains(&[0xAB; 16]));

        // System entries surface too, and ClearSystemBlackholes removes them.
        actor.handle_query(crate::messages::TransportQuery::BlackholeIdentity {
            hash: [0xAC; 16],
            ttl: None,
            reason: crate::blackhole::BlackholeReason::RateLimit,
            reason_label: None,
        });
        assert!(snapshot.read().unwrap().contains(&[0xAC; 16]));
        actor.handle_query(crate::messages::TransportQuery::ClearSystemBlackholes);
        assert!(!snapshot.read().unwrap().contains(&[0xAC; 16]));
    }

    #[test]
    fn blackhole_snapshot_filters_expired_entries() {
        let (mut actor, _tx) = TransportActor::new();
        let now = crate::now_f64();
        actor.blackhole_table.insert_entry(
            [0xE1; 16],
            crate::blackhole::BlackholeEntry {
                created: now - 100.0,
                ttl: Some(50.0),
                reason: crate::blackhole::BlackholeReason::Manual,
                reason_label: None,
                source: None,
            },
        );
        actor.blackhole_table.insert_entry(
            [0xE2; 16],
            crate::blackhole::BlackholeEntry {
                created: now,
                ttl: Some(500.0),
                reason: crate::blackhole::BlackholeReason::Manual,
                reason_label: None,
                source: None,
            },
        );
        actor.publish_blackhole_snapshot();

        let snapshot = actor.blackholed_snapshot.read().unwrap();
        assert!(
            !snapshot.contains(&[0xE1; 16]),
            "expired TTL must not surface"
        );
        assert!(snapshot.contains(&[0xE2; 16]));
    }

    #[test]
    fn test_announce_cache_persistence_roundtrip() {
        use crate::persistence::*;

        let announces = vec![RecentAnnounce {
            dest_hash: [0xAA; 16],
            hops: 2,
            app_data: Some(vec![1, 2, 3]),
            timestamp: 1234567890.0,
            public_key: Some([0x42; 64]),
            ratchet: None,
            packet_hash: Some([0x55; 32]),
            is_path_response: true,
            retained: false,
            last_used: Some(1234567999.0),
            name_hash: [0x77; 10],
        }];

        let dir = std::env::temp_dir().join("reticulum_rs_test_announce_cache");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("announce_cache.msgpack");

        save_announce_cache(&announces, &path).unwrap();
        let loaded = load_announce_cache(&path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].destination_hash, [0xAA; 16].to_vec());
        assert_eq!(loaded[0].hops, 2);
        assert_eq!(loaded[0].app_data, Some(vec![1, 2, 3]));
        assert_eq!(loaded[0].packet_hash, Some([0x55; 32].to_vec()));
        assert!(loaded[0].is_path_response);
        assert_eq!(loaded[0].last_used, Some(1234567999.0));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_void_tunnel_on_interface_disconnect() {
        let (mut actor, _tx) = TransportActor::new();

        // Create a tunnel on interface 1
        let tunnel_id = [0xFF; 32];
        let dest_hash = [0xAA; 16];

        let mut tunnel_paths = std::collections::HashMap::new();
        tunnel_paths.insert(
            dest_hash,
            crate::tunnel::TunnelPath {
                timestamp: now_f64(),
                next_hop: None,
                hops: 2,
                expires: now_f64() + 600.0,
                random_blobs: vec![],
                packet_hash: None,
            },
        );

        actor.tunnel_table.insert(crate::tunnel::TunnelEntry {
            tunnel_id,
            interface_id: 1,
            tunnel_paths,
            expires: now_f64() + 600.0,
        });

        // Also add a path for this dest through the tunnel
        let path_entry = crate::path_table::PathEntry::new(None, 2, 1, InterfaceMode::Gateway);
        actor.path_table.insert(dest_hash, path_entry);
        assert!(actor.path_table.has_path(&dest_hash));

        // Void the interface
        actor.void_tunnel_interface(1);

        // Path should be removed
        assert!(!actor.path_table.has_path(&dest_hash));

        // Tunnel interface should be voided (set to 0)
        assert_eq!(actor.tunnel_table.get(&tunnel_id).unwrap().interface_id, 0);
    }

    #[test]
    fn test_cache_request_handler() {
        let dir = std::env::temp_dir().join("rns_cache_request_handler");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true; // cache request broadcast requires transport
        actor.storage_dir = Some(dir.clone()); // announce receive writes the disk cache

        // Register an outbound interface to receive the replayed announce
        let (iface, mut rx) = make_test_interface("out1");
        actor.interfaces.insert(1, iface);

        // Create and inject a valid announce
        let (announce_raw, dest_hash) = make_valid_announce("test.cache", 0);

        // Compute the packet hash (this is what the cache request will contain)
        let packet_hash =
            rns_wire::hash::packet_hash(&announce_raw, rns_wire::flags::HeaderType::Header1);

        // Process the announce through inbound — populates path_table + recent_announces
        let inbound = crate::messages::InboundPacket {
            raw: announce_raw.clone(),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        };
        actor.on_inbound(inbound);

        // Verify metadata cached and raw bytes written to the disk announce cache
        assert_eq!(actor.recent_announces.len(), 1);
        let cached = actor
            .recent_announces
            .get(&dest_hash)
            .expect("announce should be cached under its dest_hash");
        assert_eq!(cached.packet_hash, Some(packet_hash));
        let on_disk = crate::persistence::load_python_cached_announce(
            &dir.join("cache").join("announces"),
            &packet_hash,
        )
        .unwrap()
        .expect("announce receive should write the disk cache file");
        assert_eq!(on_disk.raw_packet, announce_raw.to_vec());

        // Verify path_table has the packet_hash
        let path_entry = actor.path_table.get(&dest_hash);
        assert!(path_entry.is_some());
        assert_eq!(path_entry.unwrap().packet_hash, Some(packet_hash));

        // Build a CacheRequest: Data packet with context=CacheRequest, payload=32-byte packet hash
        let cr_flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let cr_header = rns_wire::header::PacketHeader {
            flags: cr_flags,
            hops: 0,
            transport_id: None,
            destination_hash: [0x00; 16], // CacheRequest dest doesn't matter for lookup
            context: rns_wire::context::PacketContext::CacheRequest,
        };
        let mut cr_raw = cr_header.pack();
        cr_raw.extend_from_slice(&packet_hash); // 32-byte payload

        // Process the cache request
        actor.handle_cache_request(&cr_raw, &cr_header, 1);
        actor.flush_announce_queues();

        // The output interface should have received the replayed announce
        let replayed = rx.try_recv();
        assert!(
            replayed.is_ok(),
            "expected replayed announce on output interface"
        );
        assert_eq!(replayed.unwrap(), announce_raw);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cache_request_miss() {
        let (mut actor, _tx) = TransportActor::new();

        let cr_flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let cr_header = rns_wire::header::PacketHeader {
            flags: cr_flags,
            hops: 0,
            transport_id: None,
            destination_hash: [0x00; 16],
            context: rns_wire::context::PacketContext::CacheRequest,
        };
        let mut cr_raw = cr_header.pack();
        cr_raw.extend_from_slice(&[0xFF; 32]);

        actor.handle_cache_request(&cr_raw, &cr_header, 1);
    }

    #[test]
    fn test_cache_request_invalid_payload_length() {
        let (mut actor, _tx) = TransportActor::new();

        let cr_flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let cr_header = rns_wire::header::PacketHeader {
            flags: cr_flags,
            hops: 0,
            transport_id: None,
            destination_hash: [0x00; 16],
            context: rns_wire::context::PacketContext::CacheRequest,
        };
        let mut cr_raw = cr_header.pack();
        cr_raw.extend_from_slice(&[0xFF; 16]);

        actor.handle_cache_request(&cr_raw, &cr_header, 1);
    }

    #[test]
    fn load_state_drops_expired_paths_and_stages_others() {
        let dir = std::env::temp_dir().join("rns_load_drop_expired");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Pre-populate with a fresh + an expired entry, both bound to the
        // same logical interface name.
        let now = crate::now_f64();
        let mut table = crate::path_table::PathTable::new();
        table.insert(
            [0xAA; 16],
            crate::path_table::PathEntry::new(None, 1, 7, InterfaceMode::Gateway),
        );
        // expired entry — manually construct so we can backdate `expires`.
        table.insert(
            [0xBB; 16],
            crate::path_table::PathEntry {
                timestamp: now - 86400.0,
                next_hop: None,
                hops: 1,
                expires: now - 1.0,
                random_blobs: Default::default(),
                interface_id: 7,
                packet_hash: None,
            },
        );

        let mut names = std::collections::HashMap::new();
        names.insert(7u64, "tcp_backbone".to_string());
        let path = dir.join("path_table.msgpack");
        crate::persistence::save_path_table(&table, &names, &path).unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.storage_dir = Some(dir.clone());
        actor.load_state();

        // Expired entry dropped, fresh entry staged for rebind.
        assert_eq!(actor.pending_path_entries.len(), 1);
        assert_eq!(
            actor.pending_path_entries[0].interface_name.as_deref(),
            Some("tcp_backbone")
        );
        // Live path table is still empty until RegisterInterface arrives.
        assert!(!actor.path_table.has_path(&[0xAA; 16]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn initialize_storage_uses_python_cache_index_for_destination_table() {
        let dir = std::env::temp_dir().join("rns_load_python_destination_cache_index");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let now = crate::now_f64();
        let cached_dest = [0xCA; 16];
        let missing_dest = [0xDB; 16];
        let mut cached_entry =
            crate::path_table::PathEntry::new(None, 1, 7, InterfaceMode::Gateway);
        cached_entry.timestamp = now;
        cached_entry.expires = now + 3600.0;
        cached_entry.packet_hash = Some([0x11; 32]);
        let mut missing_entry =
            crate::path_table::PathEntry::new(None, 1, 7, InterfaceMode::Gateway);
        missing_entry.timestamp = now;
        missing_entry.expires = now + 3600.0;
        missing_entry.packet_hash = Some([0x22; 32]);

        let mut table = crate::path_table::PathTable::new();
        table.insert(cached_dest, cached_entry);
        table.insert(missing_dest, missing_entry);

        let mut names = std::collections::HashMap::new();
        names.insert(7u64, "Border_TCP".to_string());
        crate::persistence::save_python_destination_table(
            &table,
            &names,
            &dir.join("destination_table"),
        )
        .unwrap();

        // Disk cache file exists only for cached_dest's announce packet hash.
        crate::persistence::write_python_cached_announce_if_absent(
            &dir.join("cache").join("announces"),
            &[0x11; 32],
            &[0xFE; 42],
            Some("Border_TCP"),
        )
        .unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.initialize_storage(dir.clone());

        assert_eq!(actor.pending_path_entries.len(), 1);
        assert_eq!(
            actor.pending_path_entries[0].destination_hash,
            cached_dest.to_vec()
        );
        assert!(actor.recent_announces.contains_key(&cached_dest));
        assert!(!actor.recent_announces.contains_key(&missing_dest));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn register_interface_rebinds_pending_paths_to_new_id() {
        let dir = std::env::temp_dir().join("rns_rebind_paths");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Save with interface_id=7 → name "tcp_backbone".
        let mut table = crate::path_table::PathTable::new();
        table.insert(
            [0xAA; 16],
            crate::path_table::PathEntry::new(None, 1, 7, InterfaceMode::Gateway),
        );
        let mut names = std::collections::HashMap::new();
        names.insert(7u64, "tcp_backbone".to_string());
        crate::persistence::save_path_table(&table, &names, &dir.join("path_table.msgpack"))
            .unwrap();

        // Fresh actor → load → register interface under a *different* id.
        let (mut actor, _tx) = TransportActor::new();
        actor.storage_dir = Some(dir.clone());
        actor.load_state();
        assert_eq!(actor.pending_path_entries.len(), 1);

        let (entry, _rx) = make_test_interface("tcp_backbone");
        actor.handle_message(TransportMessage::RegisterInterface { id: 42, entry });

        // Path is now in the live table, bound to the new id.
        assert!(actor.path_table.has_path(&[0xAA; 16]));
        let bound = actor.path_table.iter().next().unwrap().1;
        assert_eq!(bound.interface_id, 42);
        // Pending list drained.
        assert!(actor.pending_path_entries.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_connection_restored_discards_local_routing_state() {
        let (mut actor, _tx) = TransportActor::new();
        actor.path_table.insert(
            [0xAA; 16],
            crate::path_table::PathEntry::new(None, 1, 7, InterfaceMode::Gateway),
        );
        actor
            .pending_path_entries
            .push(crate::persistence::PersistedPathEntry {
                destination_hash: vec![0xBB; 16],
                timestamp: 1.0,
                next_hop: None,
                hops: 1,
                expires: 9999999999.0,
                random_blobs: Vec::new(),
                interface_id: 0,
                interface_name: Some("SharedInstanceClient".to_string()),
                interface_hash: None,
                packet_hash: None,
            });
        actor.path_requests.insert([0xCC; 16], 1.0);
        actor
            .path_states
            .insert([0xDD; 16], crate::constants::PathState::Unresponsive);
        actor.recent_announces.insert(
            [0xEE; 16],
            RecentAnnounce {
                dest_hash: [0xEE; 16],
                hops: 1,
                app_data: None,
                timestamp: 1.0,
                public_key: Some([0x11; 64]),
                ratchet: None,
                packet_hash: None,
                is_path_response: false,
                retained: false,
                last_used: None,
                name_hash: [0; 10],
            },
        );

        actor.handle_message(TransportMessage::SharedConnectionRestored { interface_id: 42 });

        assert!(actor.is_shared_instance);
        assert!(actor.shared_instance_client_mode);
        assert!(!actor.path_table.has_path(&[0xAA; 16]));
        assert!(actor.pending_path_entries.is_empty());
        assert!(actor.path_requests.is_empty());
        assert!(actor.path_states.is_empty());
        assert!(
            actor.recent_announces.contains_key(&[0xEE; 16]),
            "known destination metadata is retained separately from routing state"
        );
    }

    #[test]
    fn legacy_v2_path_snapshot_is_dropped_on_load() {
        // v2 had no `interface_name`; entries can't be rebound, so they
        // must not leak into pending or the live table.
        use serde::Serialize;
        #[derive(Serialize)]
        struct V2Entry {
            destination_hash: Vec<u8>,
            timestamp: f64,
            next_hop: Option<Vec<u8>>,
            hops: u8,
            expires: f64,
            random_blobs: Vec<Vec<u8>>,
            interface_id: u64,
        }
        #[derive(Serialize)]
        struct V2Table {
            entries: Vec<V2Entry>,
            version: u32,
        }

        let dir = std::env::temp_dir().join("rns_legacy_v2_drop");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let v2 = V2Table {
            entries: vec![V2Entry {
                destination_hash: vec![0xAA; 16],
                timestamp: 1.0,
                next_hop: None,
                hops: 1,
                expires: 9999999999.0,
                random_blobs: vec![],
                interface_id: 1,
            }],
            version: 2,
        };
        let bytes = rmp_serde::to_vec(&v2).unwrap();
        std::fs::write(dir.join("path_table.msgpack"), &bytes).unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.storage_dir = Some(dir.clone());
        actor.load_state();
        assert!(actor.pending_path_entries.is_empty());
        assert_eq!(actor.path_table.iter().count(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_then_load_round_trips_interface_name() {
        // Same actor lifecycle, on every platform: save with iface name
        // populated, load, register interface under a fresh id, assert the
        // entry rebinds.
        let dir = std::env::temp_dir().join("rns_round_trip_iface_name");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // First lifecycle: register iface, insert path, shutdown saves.
        {
            let (mut actor, _tx) = TransportActor::new();
            actor.storage_dir = Some(dir.clone());
            let (entry, _rx) = make_test_interface("ble_peer");
            actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry });
            actor.path_table.insert(
                [0xCC; 16],
                crate::path_table::PathEntry::new(None, 2, 1, InterfaceMode::Gateway),
            );
            actor.on_shutdown();
        }

        // Second lifecycle: load, register iface under a different id, expect rebind.
        let (mut actor2, _tx2) = TransportActor::new();
        actor2.storage_dir = Some(dir.clone());
        actor2.load_state();
        assert_eq!(actor2.pending_path_entries.len(), 1);

        let (entry, _rx) = make_test_interface("ble_peer");
        actor2.handle_message(TransportMessage::RegisterInterface { id: 99, entry });
        assert!(actor2.path_table.has_path(&[0xCC; 16]));
        assert_eq!(actor2.path_table.iter().next().unwrap().1.interface_id, 99);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn periodic_save_writes_path_table_when_dirty() {
        let dir = std::env::temp_dir().join("rns_periodic_save_dirty");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.storage_dir = Some(dir.clone());
        let (entry, _rx) = make_test_interface("tcp_backbone");
        actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry });
        actor.path_table.insert(
            [0xAA; 16],
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Gateway),
        );
        // Bypass the actor message path → manually flag dirty (production
        // mutation sites do this themselves).
        actor.state_dirty = true;

        // Backdate so the save trigger fires; push last_tables_cull forward
        // so the cull paths (which also flag dirty as a defensive
        // false-positive) don't run this tick and re-dirty the flag.
        let n = now_f64();
        actor.last_state_save = n - STATE_SAVE_INTERVAL_SECS - 1.0;
        actor.last_tables_cull = n;
        actor.last_blackhole_check = n;

        let path = dir.join("path_table.msgpack");
        assert!(!path.exists(), "no save yet — file shouldn't exist");

        actor.on_tick();

        assert!(path.exists(), "dirty + interval elapsed must save");
        assert!(!actor.state_dirty, "save should clear dirty flag");
        let entries = crate::persistence::load_path_table(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].destination_hash, [0xAA; 16].to_vec());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn periodic_save_skipped_when_clean() {
        // Dirty gate: an idle device with no mutations since last save
        // shouldn't spin disk on every flush interval.
        let dir = std::env::temp_dir().join("rns_periodic_save_clean");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.storage_dir = Some(dir.clone());
        let (entry, _rx) = make_test_interface("tcp_backbone");
        actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry });

        // Backdate to make the interval check pass — but state_dirty stays
        // false, so no save should happen.
        actor.last_state_save = now_f64() - STATE_SAVE_INTERVAL_SECS - 1.0;
        actor.state_dirty = false;
        let path = dir.join("path_table.msgpack");

        actor.on_tick();

        assert!(!path.exists(), "clean state must not trigger periodic save");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn announce_marks_state_dirty() {
        // Sanity check that the hot path — receiving an announce that
        // inserts a path_table entry — actually flips the dirty flag.
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        let (entry, _rx) = make_test_interface("test_iface");
        actor.interfaces.insert(1, entry);
        assert!(!actor.state_dirty);

        let (raw, _dest) = make_valid_announce("test.dirty", 1);
        actor.on_inbound(crate::messages::InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(actor.state_dirty, "inbound announce should set state_dirty");
    }

    #[test]
    fn foreground_to_background_triggers_save() {
        // The run loop owns its interval; exercise the save path directly.
        let dir = std::env::temp_dir().join("rns_fg_to_bg_save");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.storage_dir = Some(dir.clone());
        let (entry, _rx) = make_test_interface("tcp_backbone");
        actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry });
        actor.path_table.insert(
            [0xBB; 16],
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Gateway),
        );

        let path = dir.join("path_table.msgpack");
        assert!(!path.exists());

        // Same call site the falling edge in `run` makes.
        actor.save_state();

        assert!(path.exists(), "falling-edge save must write path_table");
        assert!(
            actor.last_state_save > 0.0,
            "save should bump last_state_save"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_instance_save_state_skips_transport_snapshots() {
        let dir = std::env::temp_dir().join("rns_shared_client_skip_save");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.storage_dir = Some(dir.clone());
        actor.is_shared_instance = true;
        actor.shared_instance_client_mode = true;
        actor.state_dirty = true;
        actor.path_table.insert(
            [0xAA; 16],
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Gateway),
        );
        actor.recent_announces.insert(
            [0xBB; 16],
            RecentAnnounce {
                dest_hash: [0xBB; 16],
                hops: 1,
                app_data: None,
                timestamp: 1.0,
                public_key: Some([0x22; 64]),
                ratchet: None,
                packet_hash: None,
                is_path_response: false,
                retained: false,
                last_used: None,
                name_hash: [0; 10],
            },
        );

        actor.save_state();

        assert!(!dir.join("path_table.msgpack").exists());
        assert!(!dir.join("destination_table").exists());
        assert!(!dir.join("announce_cache.msgpack").exists());
        assert!(!dir.join("packet_hashlist").exists());
        assert!(!actor.state_dirty);
        assert!(actor.last_state_save > 0.0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn outbound_announce_respects_access_point_mode() {
        let (mut actor, _tx) = TransportActor::new();
        let (mut ap, mut ap_rx) = make_test_interface("ap");
        ap.mode = InterfaceMode::AccessPoint;
        actor.interfaces.insert(1, ap);
        let (gw, mut gw_rx) = make_test_interface("gateway");
        actor.interfaces.insert(2, gw);

        let (raw, dest) = make_valid_announce("test.outbound.ap", 0);
        // Own announces are always for registered (instance-local) destinations.
        actor.local_destinations.insert(dest);
        actor.handle_message(TransportMessage::Outbound(OutboundRequest {
            raw,
            destination_hash: dest,
        }));

        assert!(
            ap_rx.try_recv().is_err(),
            "AP-mode interfaces must not receive general announce broadcasts"
        );
        assert!(
            gw_rx.try_recv().is_ok(),
            "gateway-mode interface should carry the announce"
        );
    }

    #[test]
    fn announce_mode_rules_match_roaming_and_boundary_policy() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut via_roaming, _rx1) = make_test_interface("via_roaming");
        via_roaming.mode = InterfaceMode::Roaming;
        actor.interfaces.insert(1, via_roaming);
        let (mut gateway, _rx2) = make_test_interface("gateway");
        gateway.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(2, gateway);
        let (mut roaming, _rx3) = make_test_interface("roaming");
        roaming.mode = InterfaceMode::Roaming;
        actor.interfaces.insert(3, roaming);
        let (mut boundary, _rx4) = make_test_interface("boundary");
        boundary.mode = InterfaceMode::Boundary;
        actor.interfaces.insert(4, boundary);

        let (raw, dest) = make_valid_announce("test.mode.roaming", 1);
        actor.path_table.insert(
            dest,
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Roaming),
        );

        actor.broadcast_announce_on_interfaces(&raw, None);

        assert_eq!(
            actor.interfaces.get(&2).unwrap().announce_queue.len(),
            1,
            "gateway should rebroadcast a path learned from roaming"
        );
        assert_eq!(
            actor.interfaces.get(&3).unwrap().announce_queue.len(),
            0,
            "roaming should not rebroadcast a path learned from roaming"
        );
        assert_eq!(
            actor.interfaces.get(&4).unwrap().announce_queue.len(),
            0,
            "boundary should not rebroadcast a path learned from roaming"
        );

        let (raw2, dest2) = make_valid_announce("test.mode.gateway", 1);
        actor.path_table.insert(
            dest2,
            crate::path_table::PathEntry::new(None, 1, 2, InterfaceMode::Gateway),
        );
        actor.broadcast_announce_on_interfaces(&raw2, None);

        assert_eq!(
            actor.interfaces.get(&3).unwrap().announce_queue.len(),
            1,
            "roaming may rebroadcast paths learned from gateway/full-style interfaces"
        );
        assert_eq!(
            actor.interfaces.get(&4).unwrap().announce_queue.len(),
            1,
            "boundary may rebroadcast paths learned from gateway/full-style interfaces"
        );
    }

    /// Python 1.3.8 Packet.py:247-248: raw hops byte >= PATHFINDER_M is
    /// malformed for every packet type; 127 is the maximum valid value.
    #[test]
    fn inbound_hop_count_at_or_above_max_is_dropped_for_all_packet_types() {
        let (mut actor, _tx) = TransportActor::new();
        let (dest_tx, mut dest_rx) = mpsc::channel(8);
        let dest = [0xE1; 16];
        actor.local_destinations.insert(dest);
        actor.destination_channels.insert(dest, dest_tx);

        // Data: 128 dropped at parse, 127 delivered.
        actor.on_inbound(InboundPacket {
            raw: make_data_packet(dest, PATHFINDER_M),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(dest_rx.try_recv().is_err(), "hops=128 data must be dropped");
        actor.on_inbound(InboundPacket {
            raw: make_data_packet(dest, PATHFINDER_M - 1),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(
            dest_rx.try_recv().is_ok(),
            "hops=127 data must be processed"
        );

        // LinkRequest: 128 dropped at parse, 127 delivered.
        let lr_dest = [0xE2; 16];
        let (lr_tx, mut lr_rx) = mpsc::channel(8);
        actor.local_destinations.insert(lr_dest);
        actor.destination_channels.insert(lr_dest, lr_tx);
        actor.on_inbound(InboundPacket {
            raw: make_link_request_packet(lr_dest, PATHFINDER_M),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(
            lr_rx.try_recv().is_err(),
            "hops=128 link request must be dropped"
        );
        actor.on_inbound(InboundPacket {
            raw: make_link_request_packet(lr_dest, PATHFINDER_M - 1),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(
            lr_rx.try_recv().is_ok(),
            "hops=127 link request must be processed"
        );

        // Proof: 128 leaves the receipt pending, 127 delivers it.
        let proof_dest = [0xE3; 16];
        actor.receipt_table.insert(
            proof_dest,
            PacketReceipt::new([0u8; 32], proof_dest, Some(Duration::from_secs(180))),
        );
        actor.on_inbound(InboundPacket {
            raw: make_proof_packet(proof_dest, PATHFINDER_M),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(
            actor.receipt_table.contains_key(&proof_dest),
            "hops=128 proof must be dropped"
        );
        actor.on_inbound(InboundPacket {
            raw: make_proof_packet(proof_dest, PATHFINDER_M - 1),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(
            !actor.receipt_table.contains_key(&proof_dest),
            "hops=127 proof must be processed"
        );

        // Announce: 128 dropped at parse, no path learned.
        let (announce_raw, announce_dest) = make_valid_announce("test.hops.parse", PATHFINDER_M);
        actor.on_inbound(InboundPacket {
            raw: announce_raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(
            actor.path_table.get(&announce_dest).is_none(),
            "hops=128 announce must be dropped"
        );
    }

    /// The announce hop cap is checked post-adjustment with `>=`: a raw
    /// 127-hop announce (128 after increment) is not path-learned, while a
    /// raw 126-hop announce is.
    #[test]
    fn announce_hop_cap_boundary_after_inbound_adjustment() {
        let (mut actor, _tx) = TransportActor::new();
        let (iface, _rx) = make_test_interface("wire");
        actor.interfaces.insert(1, iface);

        let (raw_127, dest_127) = make_valid_announce("test.hops.cap.a", PATHFINDER_M - 1);
        actor.on_inbound(InboundPacket {
            raw: raw_127,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(
            actor.path_table.get(&dest_127).is_none(),
            "raw 127-hop announce adjusts to 128 and must not be path-learned"
        );

        let (raw_126, dest_126) = make_valid_announce("test.hops.cap.b", PATHFINDER_M - 2);
        actor.on_inbound(InboundPacket {
            raw: raw_126,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert_eq!(
            actor.path_table.get(&dest_126).map(|e| e.hops),
            Some(PATHFINDER_M - 1),
            "raw 126-hop announce must still be path-learned"
        );
    }

    /// Python 1.3.8 Transport.py:1216-1218: mode-independent block when the
    /// destination is not instance-local and no next-hop interface exists.
    #[test]
    fn announce_broadcast_blocked_without_next_hop_interface_unless_local() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        let (mut full, _rx) = make_test_interface("full");
        full.mode = InterfaceMode::Full;
        actor.interfaces.insert(1, full);

        let (raw, dest) = make_valid_announce("test.nexthop.gate", 1);
        actor.broadcast_announce_on_interfaces(&raw, None);
        assert_eq!(
            actor.interfaces.get(&1).unwrap().announce_queue.len(),
            0,
            "non-local announce without a known path must not be rebroadcast"
        );

        actor.local_destinations.insert(dest);
        actor.broadcast_announce_on_interfaces(&raw, None);
        assert_eq!(
            actor.interfaces.get(&1).unwrap().announce_queue.len(),
            1,
            "instance-local destinations are exempt from the next-hop gate"
        );
    }

    /// Python 1.3.8 Transport.py:1220-1236: internal-mode egress and
    /// announces_from_internal origin gating.
    #[test]
    fn internal_mode_announce_gating_matches_python_138() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut boundary, _rx1) = make_test_interface("boundary");
        boundary.mode = InterfaceMode::Boundary;
        actor.interfaces.insert(1, boundary);
        let (mut internal_egress, _rx2) = make_test_interface("internal_egress");
        internal_egress.mode = InterfaceMode::Internal;
        actor.interfaces.insert(2, internal_egress);
        let (mut full, _rx3) = make_test_interface("full");
        full.mode = InterfaceMode::Full;
        actor.interfaces.insert(3, full);

        // Boundary-origin announce: blocked on internal egress, allowed on full.
        let (raw_b, dest_b) = make_valid_announce("test.internal.from_boundary", 1);
        actor.path_table.insert(
            dest_b,
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Boundary),
        );
        actor.broadcast_announce_on_interfaces(&raw_b, None);
        assert_eq!(
            actor.interfaces.get(&2).unwrap().announce_queue.len(),
            0,
            "internal egress must block boundary-origin announces"
        );
        assert_eq!(
            actor.interfaces.get(&3).unwrap().announce_queue.len(),
            1,
            "full egress relays boundary-origin announces"
        );

        // Full-origin announce: allowed on internal egress.
        let (raw_f, dest_f) = make_valid_announce("test.internal.from_full", 1);
        actor.path_table.insert(
            dest_f,
            crate::path_table::PathEntry::new(None, 1, 3, InterfaceMode::Full),
        );
        actor.broadcast_announce_on_interfaces(&raw_f, None);
        assert_eq!(
            actor.interfaces.get(&2).unwrap().announce_queue.len(),
            1,
            "internal egress relays full-origin announces"
        );

        // Mode-less origin (unregistered interface): blocked on internal
        // egress, allowed on full egress.
        let (raw_m, dest_m) = make_valid_announce("test.internal.modeless", 1);
        actor.path_table.insert(
            dest_m,
            crate::path_table::PathEntry::new(None, 1, 99, InterfaceMode::Full),
        );
        actor.broadcast_announce_on_interfaces(&raw_m, None);
        assert_eq!(
            actor.interfaces.get(&2).unwrap().announce_queue.len(),
            1,
            "internal egress must block announces from mode-less interfaces"
        );
        assert_eq!(
            actor.interfaces.get(&3).unwrap().announce_queue.len(),
            3,
            "full egress relays announces from mode-less interfaces"
        );

        // Local destination is exempt on internal egress even without a path.
        let (raw_l, dest_l) = make_valid_announce("test.internal.local", 0);
        actor.local_destinations.insert(dest_l);
        actor.broadcast_announce_on_interfaces(&raw_l, None);
        assert_eq!(
            actor.interfaces.get(&2).unwrap().announce_queue.len(),
            2,
            "instance-local announces pass internal egress gating"
        );
    }

    /// Python 1.3.8 Transport.py:1219-1221: announces_from_internal=False on
    /// the egress interface blocks internal-origin announces, ordered before
    /// the egress-mode gates.
    #[test]
    fn announces_from_internal_false_blocks_internal_origin_rebroadcast() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut internal_origin, _rx1) = make_test_interface("internal_origin");
        internal_origin.mode = InterfaceMode::Internal;
        actor.interfaces.insert(1, internal_origin);
        let (mut opted_out, _rx2) = make_test_interface("opted_out");
        opted_out.mode = InterfaceMode::Full;
        opted_out.announces_from_internal = false;
        actor.interfaces.insert(2, opted_out);
        let (mut default_full, _rx3) = make_test_interface("default_full");
        default_full.mode = InterfaceMode::Full;
        actor.interfaces.insert(3, default_full);

        let (raw, dest) = make_valid_announce("test.afi.origin", 1);
        actor.path_table.insert(
            dest,
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Internal),
        );
        actor.broadcast_announce_on_interfaces(&raw, None);
        assert_eq!(
            actor.interfaces.get(&2).unwrap().announce_queue.len(),
            0,
            "announces_from_internal=false must block internal-origin announces"
        );
        assert_eq!(
            actor.interfaces.get(&3).unwrap().announce_queue.len(),
            1,
            "default announces_from_internal=true relays internal-origin announces"
        );

        // Instance-local destinations are exempt from the opt-out.
        let (raw_l, dest_l) = make_valid_announce("test.afi.local", 0);
        actor.local_destinations.insert(dest_l);
        actor.broadcast_announce_on_interfaces(&raw_l, None);
        assert_eq!(
            actor.interfaces.get(&2).unwrap().announce_queue.len(),
            1,
            "local announces bypass the announces_from_internal opt-out"
        );
    }

    /// Python 1.3.8 Transport.py:2946-2947 (commit 03ddb082): recursive_prs
    /// forces unknown-path discovery independent of interface mode; Internal
    /// joins DISCOVER_PATHS_FOR (Interface.py:55).
    #[test]
    fn recursive_prs_option_forces_unknown_path_discovery() {
        assert!(mode_discovers_unknown_paths(InterfaceMode::Internal));

        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut full, _full_rx) = make_test_interface("full");
        full.mode = InterfaceMode::Full;
        actor.interfaces.insert(1, full);
        let (mut boundary, mut boundary_rx) = make_test_interface("boundary");
        boundary.mode = InterfaceMode::Boundary;
        actor.interfaces.insert(2, boundary);

        actor.handle_inbound_path_request(&make_path_request_payload([0x61; 16], None), 1);
        assert!(
            boundary_rx.try_recv().is_err(),
            "full mode without recursive_prs must not discover unknown paths"
        );

        actor.interfaces.get_mut(&1).unwrap().recursive_prs = true;
        actor.handle_inbound_path_request(&make_path_request_payload([0x62; 16], None), 1);
        assert!(
            boundary_rx.try_recv().is_ok(),
            "recursive_prs must force unknown-path discovery regardless of mode"
        );
    }

    /// Python 1.3.8 Transport.py:2685-2697: next_hop/next_hop_interface fall
    /// back to the transport identity / shared-instance interface for
    /// instance-local destinations.
    #[test]
    fn next_hop_rpc_falls_back_to_local_destinations() {
        let (mut actor, _tx) = TransportActor::new();
        actor.transport_identity_hash = Some([0x77; 16]);
        let dest = [0x71; 16];
        actor.local_destinations.insert(dest);

        match actor.handle_query(TransportQuery::GetNextHop { dest }) {
            TransportQueryResponse::HashResult(h) => assert_eq!(h, Some([0x77; 16])),
            other => panic!("unexpected response: {other:?}"),
        }
        // No shared-instance interface: interface queries stay empty.
        match actor.handle_query(TransportQuery::GetNextHopIfName { dest }) {
            TransportQueryResponse::StringResult(name) => assert_eq!(name, None),
            other => panic!("unexpected response: {other:?}"),
        }

        let (mut shared, _rx) = make_test_interface("shared_server");
        shared.role = InterfaceRole::SharedServer;
        actor.interfaces.insert(5, shared);
        match actor.handle_query(TransportQuery::GetNextHopIfName { dest }) {
            TransportQueryResponse::StringResult(name) => {
                assert_eq!(name.as_deref(), Some("shared_server"))
            }
            other => panic!("unexpected response: {other:?}"),
        }
        match actor.handle_query(TransportQuery::GetNextHopInterfaceId { dest }) {
            TransportQueryResponse::IntResult(id) => assert_eq!(id, 5),
            other => panic!("unexpected response: {other:?}"),
        }

        // Unknown non-local destinations still resolve to nothing.
        let unknown = [0x72; 16];
        match actor.handle_query(TransportQuery::GetNextHop { dest: unknown }) {
            TransportQueryResponse::HashResult(h) => assert_eq!(h, None),
            other => panic!("unexpected response: {other:?}"),
        }
        match actor.handle_query(TransportQuery::GetNextHopInterfaceId { dest: unknown }) {
            TransportQueryResponse::IntResult(id) => assert_eq!(id, -1),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// Python 1.3.8 Transport.py:2984: a cached announce that fails to unpack
    /// is a miss — no path response is synthesized from raw bytes.
    #[test]
    fn path_response_from_unparseable_cached_announce_is_a_miss() {
        let (actor, _tx) = TransportActor::new();

        assert!(
            actor
                .path_response_from_cached_announce(&[0x01, 0x02], [0xAA; 16], 1)
                .is_none(),
            "garbage cached bytes must not produce a path response"
        );

        let (raw_bad_hops, dest) = make_valid_announce("test.cache.badhops", PATHFINDER_M);
        assert!(
            actor
                .path_response_from_cached_announce(&raw_bad_hops, dest, 1)
                .is_none(),
            "cached announce with hops >= PATHFINDER_M must be treated as a miss"
        );

        let (raw_ok, dest_ok) = make_valid_announce("test.cache.ok", 1);
        assert!(
            actor
                .path_response_from_cached_announce(&raw_ok, dest_ok, 1)
                .is_some()
        );
    }

    fn make_path_request_payload(
        destination_hash: [u8; 16],
        requestor_transport_id: Option<[u8; 16]>,
    ) -> Vec<u8> {
        make_path_request_payload_with_tag(destination_hash, requestor_transport_id, [0xA5; 16])
    }

    fn make_path_request_payload_with_tag(
        destination_hash: [u8; 16],
        requestor_transport_id: Option<[u8; 16]>,
        tag: [u8; 16],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&destination_hash);
        if let Some(id) = requestor_transport_id {
            payload.extend_from_slice(&id);
        }
        payload.extend_from_slice(&tag);
        payload
    }

    fn prime_ingress_pr_burst(actor: &mut TransportActor, interface_id: InterfaceId) {
        let ingress = &mut actor
            .interfaces
            .get_mut(&interface_id)
            .expect("test interface should exist")
            .ingress;
        for _ in 0..IC_BURST_MIN_SAMPLES {
            ingress.received_path_request();
        }
    }

    fn enable_and_prime_egress_pr_limit(actor: &mut TransportActor, interface_id: InterfaceId) {
        let ingress = &mut actor
            .interfaces
            .get_mut(&interface_id)
            .expect("test interface should exist")
            .ingress;
        *ingress =
            crate::ingress::IngressController::with_overrides(&crate::ingress::IngressOverrides {
                egress_control: Some(true),
                ..Default::default()
            });
        for _ in 0..IC_BURST_MIN_SAMPLES {
            ingress.sent_path_request();
        }
    }

    fn expired_link(
        destination_hash: [u8; 16],
        receiving_interface: InterfaceId,
        taken_hops: u8,
    ) -> crate::link_table::ExpiredLink {
        crate::link_table::ExpiredLink {
            next_hop: Some([0xAB; 16]),
            interface_id: 2,
            remaining_hops: 2,
            destination_hash,
            receiving_interface,
            taken_hops,
        }
    }

    #[test]
    fn path_request_payloads_use_python_default_lengths() {
        let destination = [0x11; 16];
        let requestor = [0x22; 16];

        let leaf = make_path_request_payload(destination, None);
        assert_eq!(leaf.len(), 32);
        assert_eq!(&leaf[..16], &destination);
        assert_eq!(&leaf[16..], &[0xA5; 16]);

        let transport = make_path_request_payload(destination, Some(requestor));
        assert_eq!(transport.len(), 48);
        assert_eq!(&transport[..16], &destination);
        assert_eq!(&transport[16..32], &requestor);
        assert_eq!(&transport[32..], &[0xA5; 16]);
    }

    #[test]
    fn on_path_request_broadcasts_python_sized_leaf_payload() {
        let (mut actor, _tx) = TransportActor::new();
        let (gateway, mut gateway_rx) = make_test_interface("gateway");
        actor.interfaces.insert(1, gateway);

        let requested = [0x33; 16];
        actor.on_path_request(requested);

        let raw = gateway_rx
            .try_recv()
            .expect("path request should broadcast on outbound interface");
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        assert_eq!(
            header.destination_hash,
            rns_identity::destination::Destination::hash_from_name_and_identity(
                "rnstransport.path.request",
                None
            )
        );
        let payload = &raw[offset..];
        assert_eq!(payload.len(), 32);
        assert_eq!(&payload[..16], &requested);
    }

    #[test]
    fn explicit_path_request_sends_even_when_path_is_known() {
        let (mut actor, _tx) = TransportActor::new();
        let (gateway, mut gateway_rx) = make_test_interface("gateway");
        actor.interfaces.insert(1, gateway);

        let requested = [0x35; 16];
        actor.path_table.insert(
            requested,
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Gateway),
        );

        actor.on_path_request(requested);

        let raw = gateway_rx
            .try_recv()
            .expect("explicit path refresh should still send");
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        assert_eq!(&raw[offset..offset + 16], &requested);
    }

    #[test]
    fn await_path_requests_unknown_path_before_waiting() {
        let (mut actor, _tx) = TransportActor::new();
        let (gateway, mut gateway_rx) = make_test_interface("gateway");
        actor.interfaces.insert(1, gateway);

        let requested = [0x34; 16];
        let (reply, _reply_rx) = tokio::sync::oneshot::channel();
        actor.handle_message(TransportMessage::AwaitPath {
            dest: requested,
            reply,
        });

        let raw = gateway_rx
            .try_recv()
            .expect("awaiting an unknown path should emit a path request");
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        assert_eq!(&raw[offset..offset + 16], &requested);
        assert!(actor.path_waiters.contains_key(&requested));
    }

    #[test]
    fn transport_path_request_includes_identity_and_sixteen_byte_tag() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        actor.transport_identity_hash = Some([0x44; 16]);
        let (gateway, mut gateway_rx) = make_test_interface("gateway");
        actor.interfaces.insert(1, gateway);

        let requested = [0x55; 16];
        actor.on_path_request(requested);

        let raw = gateway_rx
            .try_recv()
            .expect("transport path request should broadcast on outbound interface");
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        let payload = &raw[offset..];
        assert_eq!(payload.len(), 48);
        assert_eq!(&payload[..16], &requested);
        assert_eq!(&payload[16..32], &[0x44; 16]);
    }

    #[test]
    fn unknown_path_request_only_forwards_from_discovery_modes() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut boundary, mut boundary_rx) = make_test_interface("boundary");
        boundary.mode = InterfaceMode::Boundary;
        actor.interfaces.insert(1, boundary);
        let (mut gateway, mut gateway_rx) = make_test_interface("gateway");
        gateway.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(2, gateway);

        actor.handle_inbound_path_request(&make_path_request_payload([0x11; 16], None), 1);
        assert!(
            gateway_rx.try_recv().is_err(),
            "boundary interfaces should not trigger recursive unknown path discovery"
        );

        actor.handle_inbound_path_request(&make_path_request_payload([0x22; 16], None), 2);
        assert!(
            boundary_rx.try_recv().is_ok(),
            "gateway interfaces should forward recursive unknown path discovery"
        );
    }

    #[test]
    fn gateway_mode_without_transport_does_not_relay_unknown_path_requests() {
        let (mut actor, _tx) = TransportActor::new();

        let (mut gateway, _gateway_rx) = make_test_interface("gateway");
        gateway.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, gateway);
        let (boundary, mut boundary_rx) = make_test_interface("boundary");
        actor.interfaces.insert(2, boundary);

        actor.handle_inbound_path_request(&make_path_request_payload([0x33; 16], None), 1);

        assert!(
            boundary_rx.try_recv().is_err(),
            "gateway mode must not relay unknown path discovery unless transport is enabled"
        );
        assert!(
            actor.discovery_path_requests.is_empty(),
            "non-transport nodes must not track recursive discovery state"
        );
    }

    #[test]
    fn inbound_tagless_path_request_is_ignored() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut gateway, _gateway_rx) = make_test_interface("gateway");
        gateway.mode = InterfaceMode::Gateway;
        gateway.ingress = crate::ingress::IngressController::disabled();
        actor.interfaces.insert(1, gateway);
        let (mut boundary, mut boundary_rx) = make_test_interface("boundary");
        boundary.mode = InterfaceMode::Boundary;
        actor.interfaces.insert(2, boundary);

        let requested = [0xD1; 16];
        actor.handle_inbound_path_request(&requested, 1);

        assert!(boundary_rx.try_recv().is_err());
        assert!(actor.discovery_pr_tags.is_empty());
        assert!(!actor.path_requests.contains_key(&requested));
    }

    #[test]
    fn inbound_path_request_dedupes_by_destination_and_tag() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut gateway, _gateway_rx) = make_test_interface("gateway");
        gateway.mode = InterfaceMode::Gateway;
        gateway.ingress = crate::ingress::IngressController::disabled();
        actor.interfaces.insert(1, gateway);
        let (mut boundary, mut boundary_rx) = make_test_interface("boundary");
        boundary.mode = InterfaceMode::Boundary;
        actor.interfaces.insert(2, boundary);

        let requested = [0xD2; 16];
        let first = make_path_request_payload_with_tag(requested, None, [0xA5; 16]);
        actor.handle_inbound_path_request(&first, 1);
        boundary_rx
            .try_recv()
            .expect("first tagged request should be forwarded");

        actor.handle_inbound_path_request(&first, 1);
        assert!(
            boundary_rx.try_recv().is_err(),
            "duplicate destination+tag should be suppressed"
        );

        let second_tag = make_path_request_payload_with_tag(requested, None, [0xB6; 16]);
        actor.handle_inbound_path_request(&second_tag, 1);
        assert!(
            boundary_rx.try_recv().is_err(),
            "same destination with a new tag should not forward while discovery is already waiting"
        );
        assert_eq!(
            actor.discovery_pr_tags.len(),
            2,
            "Python remembers the new tag even when the waiting destination suppresses forwarding"
        );

        actor
            .discovery_path_requests
            .get_mut(&requested)
            .expect("first forwarded request should create a waiting discovery entry")
            .timeout = 0.0;
        actor.on_tick();
        actor
            .interfaces
            .get_mut(&2)
            .expect("boundary interface should still exist")
            .announce_allowed_at = 0.0;

        let third_tag = make_path_request_payload_with_tag(requested, None, [0xC7; 16]);
        actor.handle_inbound_path_request(&third_tag, 1);
        boundary_rx.try_recv().expect(
            "same destination should forward again after the waiting discovery entry expires",
        );
        assert_eq!(actor.discovery_pr_tags.len(), 3);
    }

    #[test]
    fn duplicate_path_requests_still_count_toward_ingress_frequency() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut gateway, _gateway_rx) = make_test_interface("gateway");
        gateway.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, gateway);
        let (mut boundary, mut boundary_rx) = make_test_interface("boundary");
        boundary.mode = InterfaceMode::Boundary;
        actor.interfaces.insert(2, boundary);

        let requested = [0xD4; 16];
        let payload = make_path_request_payload_with_tag(requested, None, [0xAA; 16]);
        actor.handle_inbound_path_request(&payload, 1);
        boundary_rx
            .try_recv()
            .expect("first tagged request should be forwarded");

        actor.handle_inbound_path_request(&payload, 1);
        actor.handle_inbound_path_request(&payload, 1);

        assert!(boundary_rx.try_recv().is_err());
        assert!(
            actor
                .interfaces
                .get(&1)
                .unwrap()
                .ingress
                .incoming_pr_frequency()
                > 0.0,
            "duplicate tagged PRs must still contribute to ingress PR stats"
        );
    }

    #[test]
    fn pr_ingress_burst_blocks_only_unknown_recursive_forwarding() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut gateway, _gateway_rx) = make_test_interface("gateway");
        gateway.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, gateway);
        let (mut boundary, mut boundary_rx) = make_test_interface("boundary");
        boundary.mode = InterfaceMode::Boundary;
        actor.interfaces.insert(2, boundary);
        prime_ingress_pr_burst(&mut actor, 1);

        let requested = [0xE0; 16];
        actor.handle_inbound_path_request(&make_path_request_payload(requested, None), 1);

        assert!(
            boundary_rx.try_recv().is_err(),
            "PR burst on ingress interface must suppress unknown recursive forwarding"
        );
        assert!(
            !actor.discovery_path_requests.contains_key(&requested),
            "suppressed recursive PRs should not create waiting discovery entries"
        );
    }

    #[test]
    fn pr_ingress_burst_does_not_block_local_destination_response() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut gateway, _gateway_rx) = make_test_interface("gateway");
        gateway.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, gateway);
        prime_ingress_pr_burst(&mut actor, 1);

        let dest = [0xE1; 16];
        let tag = [0xE2; 16];
        let (event_tx, mut event_rx) = mpsc::channel(4);
        actor.local_destinations.insert(dest);
        actor.destination_channels.insert(dest, event_tx);

        actor.handle_inbound_path_request(&make_path_request_payload_with_tag(dest, None, tag), 1);

        let event = event_rx
            .try_recv()
            .expect("local destination should still be asked to announce");
        let crate::link_messages::DestinationEvent::AnnounceRequested(request) = event else {
            panic!("expected AnnounceRequested event");
        };
        assert!(request.path_response);
        assert_eq!(request.tag.as_deref(), Some(&tag[..]));
    }

    #[test]
    fn pr_ingress_burst_does_not_block_known_path_response() {
        let dir = std::env::temp_dir().join("rns_pr_burst_known_path");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        actor.transport_identity_hash = Some([0x44; 16]);
        actor.storage_dir = Some(dir.clone());

        let (mut gateway, _gateway_rx) = make_test_interface("gateway");
        gateway.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, gateway);
        let (next_hop_iface, _rx2) = make_test_interface("next_hop_iface");
        actor.interfaces.insert(2, next_hop_iface);
        prime_ingress_pr_burst(&mut actor, 1);

        let (raw, dest) = make_valid_announce("test.pr_burst.known_path", 1);
        let ph = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
        crate::persistence::write_python_cached_announce_if_absent(
            &dir.join("cache").join("announces"),
            &ph,
            &raw,
            None,
        )
        .unwrap();
        let mut path_entry =
            crate::path_table::PathEntry::new(Some([0xAB; 16]), 2, 2, InterfaceMode::Gateway);
        path_entry.packet_hash = Some(ph);
        actor.path_table.insert(dest, path_entry);
        actor.recent_announces.insert(
            dest,
            RecentAnnounce {
                dest_hash: dest,
                hops: 2,
                app_data: None,
                timestamp: now_f64(),
                public_key: None,
                ratchet: None,
                packet_hash: Some(ph),
                is_path_response: false,
                retained: false,
                last_used: None,
                name_hash: [0u8; 10],
            },
        );

        actor.handle_inbound_path_request(&make_path_request_payload(dest, None), 1);

        let queued = actor
            .announce_table
            .get(&dest)
            .expect("known path response should still be queued during PR burst");
        assert!(queued.block_rebroadcast);
        assert_eq!(queued.attached_interface, Some(1));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pr_ingress_burst_does_not_block_local_client_forwarding() {
        let (mut actor, _tx) = TransportActor::new();

        let (mut local_client, _local_rx) = make_test_interface("SharedInstanceServer/client_6");
        local_client.role = InterfaceRole::LocalClient;
        actor.interfaces.insert(1, local_client);
        let (gateway, mut gateway_rx) = make_test_interface("gateway");
        actor.interfaces.insert(2, gateway);
        prime_ingress_pr_burst(&mut actor, 1);

        let requested = [0xE3; 16];
        actor.handle_inbound_path_request(&make_path_request_payload(requested, None), 1);

        gateway_rx
            .try_recv()
            .expect("local-client PR forwarding must bypass ingress PR burst");
    }

    #[test]
    fn recursive_path_request_egress_limit_skips_only_limited_interface() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut requestor, _requestor_rx) = make_test_interface("requestor");
        requestor.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, requestor);
        let (limited, mut limited_rx) = make_test_interface("limited");
        actor.interfaces.insert(2, limited);
        let (open, mut open_rx) = make_test_interface("open");
        actor.interfaces.insert(3, open);
        enable_and_prime_egress_pr_limit(&mut actor, 2);

        actor.handle_inbound_path_request(&make_path_request_payload([0xE4; 16], None), 1);

        assert!(
            limited_rx.try_recv().is_err(),
            "egress-limited interface should be skipped"
        );
        open_rx
            .try_recv()
            .expect("non-limited outbound interface should still receive recursive PR");
    }

    #[test]
    fn recursive_path_request_egress_limit_is_inactive_by_default() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut requestor, _requestor_rx) = make_test_interface("requestor");
        requestor.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, requestor);
        let (mut outbound, mut outbound_rx) = make_test_interface("outbound");
        for _ in 0..IC_BURST_MIN_SAMPLES {
            outbound.ingress.sent_path_request();
        }
        actor.interfaces.insert(2, outbound);

        actor.handle_inbound_path_request(&make_path_request_payload([0xE5; 16], None), 1);

        outbound_rx
            .try_recv()
            .expect("default egress_control=false must not suppress recursive PRs");
    }

    #[test]
    fn recursive_path_request_skips_queued_announces_and_active_cap() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut requestor, _requestor_rx) = make_test_interface("requestor");
        requestor.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, requestor);
        let (mut queued, mut queued_rx) = make_test_interface("queued");
        queued.announce_queue.push(crate::messages::QueuedAnnounce {
            destination_hash: [0xAA; 16],
            time: now_f64(),
            hops: 1,
            raw: Bytes::from_static(&[0x01, 0x02]),
        });
        actor.interfaces.insert(2, queued);
        let (mut capped, mut capped_rx) = make_test_interface("capped");
        capped.announce_allowed_at = now_f64() + 60.0;
        actor.interfaces.insert(3, capped);

        actor.handle_inbound_path_request(&make_path_request_payload([0xE6; 16], None), 1);

        assert!(queued_rx.try_recv().is_err());
        assert!(capped_rx.try_recv().is_err());
    }

    #[test]
    fn recursive_path_request_updates_announce_cap_window() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut requestor, _requestor_rx) = make_test_interface("requestor");
        requestor.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, requestor);
        let (outbound, mut outbound_rx) = make_test_interface("outbound");
        actor.interfaces.insert(2, outbound);

        actor.handle_inbound_path_request(&make_path_request_payload([0xE7; 16], None), 1);

        outbound_rx
            .try_recv()
            .expect("recursive PR should be transmitted");
        assert!(
            actor.interfaces.get(&2).unwrap().announce_allowed_at > now_f64(),
            "recursive PR send should reserve announce-cap airtime"
        );
    }

    #[test]
    fn outgoing_path_request_frequency_counts_direct_forwarded_and_recursive_sends() {
        let (mut direct, _tx) = TransportActor::new();
        let (direct_iface, mut direct_rx) = make_test_interface("direct");
        direct.interfaces.insert(1, direct_iface);
        direct.on_path_request([0x10; 16]);
        direct.on_path_request([0x11; 16]);
        direct_rx.try_recv().expect("first direct PR");
        direct_rx.try_recv().expect("second direct PR");
        assert!(
            direct
                .interfaces
                .get(&1)
                .unwrap()
                .ingress
                .outgoing_pr_frequency()
                > 0.0
        );

        let (mut forwarded, _tx) = TransportActor::new();
        let (mut local_client, _local_rx) = make_test_interface("SharedInstanceServer/client_7");
        local_client.role = InterfaceRole::LocalClient;
        forwarded.interfaces.insert(1, local_client);
        let (gateway, mut gateway_rx) = make_test_interface("gateway");
        forwarded.interfaces.insert(2, gateway);
        forwarded.handle_inbound_path_request(&make_path_request_payload([0x12; 16], None), 1);
        forwarded.handle_inbound_path_request(&make_path_request_payload([0x13; 16], None), 1);
        gateway_rx.try_recv().expect("first forwarded PR");
        gateway_rx.try_recv().expect("second forwarded PR");
        assert!(
            forwarded
                .interfaces
                .get(&2)
                .unwrap()
                .ingress
                .outgoing_pr_frequency()
                > 0.0
        );

        let (mut recursive, _tx) = TransportActor::new();
        recursive.is_transport_enabled = true;
        let (mut requestor, _requestor_rx) = make_test_interface("requestor");
        requestor.mode = InterfaceMode::Gateway;
        recursive.interfaces.insert(1, requestor);
        let (outbound, mut outbound_rx) = make_test_interface("outbound");
        recursive.interfaces.insert(2, outbound);
        recursive.handle_inbound_path_request(&make_path_request_payload([0x14; 16], None), 1);
        recursive
            .interfaces
            .get_mut(&2)
            .unwrap()
            .announce_allowed_at = 0.0;
        recursive.handle_inbound_path_request(&make_path_request_payload([0x15; 16], None), 1);
        outbound_rx.try_recv().expect("first recursive PR");
        outbound_rx.try_recv().expect("second recursive PR");
        assert!(
            recursive
                .interfaces
                .get(&2)
                .unwrap()
                .ingress
                .outgoing_pr_frequency()
                > 0.0
        );
    }

    #[test]
    fn recursive_path_request_rewrites_requestor_transport_id() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        actor.transport_identity_hash = Some([0x44; 16]);

        let (mut gateway, _gateway_rx) = make_test_interface("gateway");
        gateway.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, gateway);
        let (mut boundary, mut boundary_rx) = make_test_interface("boundary");
        boundary.mode = InterfaceMode::Boundary;
        actor.interfaces.insert(2, boundary);

        let requested = [0xD3; 16];
        let original_requestor = [0x99; 16];
        let tag = [0xC7; 16];
        let incoming = make_path_request_payload_with_tag(requested, Some(original_requestor), tag);
        actor.handle_inbound_path_request(&incoming, 1);

        let forwarded = boundary_rx
            .try_recv()
            .expect("recursive path request should be forwarded");
        let (_header, offset) = rns_wire::header::PacketHeader::unpack(&forwarded).unwrap();
        let payload = &forwarded[offset..];
        assert_eq!(payload.len(), 48);
        assert_eq!(&payload[..16], &requested);
        assert_eq!(
            &payload[16..32],
            &[0x44; 16],
            "recursive request must advertise this transport as requester"
        );
        assert_eq!(&payload[32..48], &tag);
    }

    #[test]
    fn local_destination_path_request_preserves_response_context() {
        let (mut actor, _tx) = TransportActor::new();
        let (requestor, _requestor_rx) = make_test_interface("requestor");
        actor.interfaces.insert(1, requestor);

        let dest = [0xDA; 16];
        let (event_tx, mut event_rx) = mpsc::channel(4);
        actor.local_destinations.insert(dest);
        actor.destination_channels.insert(dest, event_tx);

        let tag = [0xDB; 16];
        actor.handle_inbound_path_request(&make_path_request_payload_with_tag(dest, None, tag), 1);

        let event = event_rx
            .try_recv()
            .expect("local path request should ask the destination to announce");
        let crate::link_messages::DestinationEvent::AnnounceRequested(request) = event else {
            panic!("expected AnnounceRequested event");
        };
        assert!(request.path_response);
        assert_eq!(request.tag.as_deref(), Some(&tag[..]));
        assert_eq!(request.attached_interface, Some(1));
    }

    #[test]
    fn outbound_attached_sends_only_to_target_interface() {
        let (mut actor, _tx) = TransportActor::new();
        let (iface_a, mut rx_a) = make_test_interface("a");
        actor.interfaces.insert(1, iface_a);
        let (iface_b, mut rx_b) = make_test_interface("b");
        actor.interfaces.insert(2, iface_b);

        let (raw, dest) = make_valid_announce("test.path_response.attached", 0);
        actor.handle_message(TransportMessage::OutboundAttached {
            request: OutboundRequest {
                raw: raw.clone(),
                destination_hash: dest,
            },
            interface_id: 2,
        });

        assert!(
            rx_a.try_recv().is_err(),
            "attached outbound packets must not broadcast to other interfaces"
        );
        assert_eq!(
            rx_b.try_recv()
                .expect("target interface should receive packet"),
            raw
        );
    }

    #[test]
    fn discovery_path_request_is_answered_by_later_matching_announce() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        actor.transport_identity_hash = Some([0x44; 16]);

        let (mut requestor, mut requestor_rx) = make_test_interface("requestor");
        requestor.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, requestor);
        let (mut boundary, mut boundary_rx) = make_test_interface("boundary");
        boundary.mode = InterfaceMode::Boundary;
        actor.interfaces.insert(2, boundary);

        let (announce_raw, dest) = make_valid_announce("test.discovery_path.later_announce", 1);
        let tag = [0xD8; 16];
        actor.handle_inbound_path_request(&make_path_request_payload_with_tag(dest, None, tag), 1);

        assert!(
            actor.discovery_path_requests.contains_key(&dest),
            "unknown recursive path requests must remember the requesting interface"
        );
        let forwarded = boundary_rx
            .try_recv()
            .expect("transport should recursively forward the path request");
        let (_forwarded_header, forwarded_offset) =
            rns_wire::header::PacketHeader::unpack(&forwarded).unwrap();
        assert_eq!(&forwarded[forwarded_offset..forwarded_offset + 16], &dest);

        actor.on_inbound(crate::messages::InboundPacket {
            raw: announce_raw.clone(),
            interface_id: 2,
            rssi: None,
            snr: None,
            q: None,
        });

        let response = requestor_rx
            .try_recv()
            .expect("matching announce should be returned to the original requester");
        let (response_header, response_offset) =
            rns_wire::header::PacketHeader::unpack(&response).unwrap();
        assert_eq!(response_header.destination_hash, dest);
        assert_eq!(
            response_header.context,
            rns_wire::context::PacketContext::PathResponse
        );
        assert_eq!(
            response_header.flags.header_type,
            rns_wire::flags::HeaderType::Header2
        );
        assert_eq!(response_header.transport_id, Some([0x44; 16]));

        let (_announce_header, announce_offset) =
            rns_wire::header::PacketHeader::unpack(&announce_raw).unwrap();
        assert_eq!(
            &response[response_offset..],
            &announce_raw[announce_offset..]
        );
        assert!(
            actor.discovery_path_requests.contains_key(&dest),
            "Python leaves discovery_path_requests in place until timeout cleanup"
        );
    }

    #[test]
    fn discovery_path_requests_expire_on_maintenance_tick() {
        let (mut actor, _tx) = TransportActor::new();
        let requested = [0xD9; 16];
        actor.discovery_path_requests.insert(
            requested,
            DiscoveryPathRequest {
                requesting_interface: 1,
                timeout: 0.0,
            },
        );

        actor.on_tick();

        assert!(
            !actor.discovery_path_requests.contains_key(&requested),
            "waiting discovery path requests should expire after PATH_REQUEST_TIMEOUT"
        );
    }

    #[test]
    fn pending_discovery_pr_queue_caps_at_32() {
        let (mut actor, _tx) = TransportActor::new();
        let now = now_f64();

        for value in 0u8..40 {
            actor.queue_discovery_path_request([value; 16], None, now);
        }

        assert_eq!(actor.pending_discovery_prs.len(), MAX_QUEUED_DISCOVERY_PRS);
        assert_eq!(
            actor
                .pending_discovery_prs
                .front()
                .unwrap()
                .destination_hash,
            [0x00; 16],
            "full queue should retain earlier entries and drop new excess entries"
        );
        assert_eq!(
            actor.pending_discovery_prs.back().unwrap().destination_hash,
            [31; 16]
        );
    }

    #[test]
    fn queued_discovery_prs_emit_at_throttle_cadence() {
        let (mut actor, _tx) = TransportActor::new();
        let (iface, mut rx) = make_test_interface("gateway");
        actor.interfaces.insert(1, iface);
        let now = now_f64();

        actor.queue_discovery_path_request([0xA1; 16], None, now);
        actor.queue_discovery_path_request([0xA2; 16], None, now);

        actor.process_pending_discovery_path_requests(now + DISCOVERY_PR_TX_THROTTLE - 0.01);
        assert!(rx.try_recv().is_err());
        assert_eq!(actor.pending_discovery_prs.len(), 2);

        actor.process_pending_discovery_path_requests(now + DISCOVERY_PR_TX_THROTTLE);
        rx.try_recv()
            .expect("first queued discovery PR should transmit after throttle");
        assert_eq!(actor.pending_discovery_prs.len(), 1);

        actor.process_pending_discovery_path_requests(now + DISCOVERY_PR_TX_THROTTLE + 0.1);
        assert!(rx.try_recv().is_err());
        assert_eq!(actor.pending_discovery_prs.len(), 1);

        actor.process_pending_discovery_path_requests(now + DISCOVERY_PR_TX_THROTTLE * 2.0);
        rx.try_recv()
            .expect("second queued discovery PR should wait for the next throttle window");
        assert!(actor.pending_discovery_prs.is_empty());
    }

    #[test]
    fn queued_discovery_pr_skips_blocked_interface() {
        let (mut actor, _tx) = TransportActor::new();
        let (iface_a, mut rx_a) = make_test_interface("a");
        actor.interfaces.insert(1, iface_a);
        let (iface_b, mut rx_b) = make_test_interface("b");
        actor.interfaces.insert(2, iface_b);
        let (iface_c, mut rx_c) = make_test_interface("c");
        actor.interfaces.insert(3, iface_c);
        let now = now_f64();

        actor.queue_discovery_path_request([0xB1; 16], Some(2), now);
        actor.process_pending_discovery_path_requests(now + DISCOVERY_PR_TX_THROTTLE);

        rx_a.try_recv()
            .expect("unblocked interface should receive queued discovery PR");
        assert!(
            rx_b.try_recv().is_err(),
            "blocked interface must be excluded from rediscovery"
        );
        rx_c.try_recv()
            .expect("other unblocked interface should receive queued discovery PR");
    }

    #[test]
    fn failed_link_missing_path_queues_rediscovery() {
        let (mut actor, _tx) = TransportActor::new();
        let dest = [0xB2; 16];

        actor.handle_expired_unvalidated_link(expired_link(dest, 1, 2), now_f64());

        assert_eq!(actor.pending_discovery_prs.len(), 1);
        assert_eq!(
            actor
                .pending_discovery_prs
                .front()
                .unwrap()
                .destination_hash,
            dest
        );
        assert_eq!(
            actor
                .pending_discovery_prs
                .front()
                .unwrap()
                .blocked_interface,
            None
        );
    }

    #[test]
    fn failed_link_taken_hops_zero_queues_when_not_recently_requested() {
        let (mut actor, _tx) = TransportActor::new();
        let dest = [0xB3; 16];
        actor.path_table.insert(
            dest,
            crate::path_table::PathEntry::new(Some([0xAA; 16]), 2, 2, InterfaceMode::Gateway),
        );
        let now = now_f64();

        actor.handle_expired_unvalidated_link(expired_link(dest, 1, 0), now);
        assert_eq!(actor.pending_discovery_prs.len(), 1);

        let (mut throttled, _tx) = TransportActor::new();
        throttled.path_table.insert(
            dest,
            crate::path_table::PathEntry::new(Some([0xAA; 16]), 2, 2, InterfaceMode::Gateway),
        );
        throttled.path_requests.insert(dest, now);
        throttled.handle_expired_unvalidated_link(expired_link(dest, 1, 0), now);
        assert!(
            throttled.pending_discovery_prs.is_empty(),
            "taken_hops=0 rediscovery should respect PATH_REQUEST_MI"
        );
    }

    #[test]
    fn failed_link_previous_one_hop_destination_marks_unresponsive() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        let (mut gateway, _rx) = make_test_interface("gateway");
        gateway.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, gateway);
        let dest = [0xB4; 16];
        actor.path_table.insert(
            dest,
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Gateway),
        );

        actor.handle_expired_unvalidated_link(expired_link(dest, 1, 2), now_f64());

        let request = actor.pending_discovery_prs.front().unwrap();
        assert_eq!(request.destination_hash, dest);
        assert_eq!(request.blocked_interface, Some(1));
        assert_eq!(actor.path_table.get_state(&dest), PathState::Unresponsive);
    }

    #[test]
    fn failed_link_one_hop_initiator_marks_unresponsive() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        let (mut gateway, _rx) = make_test_interface("gateway");
        gateway.mode = InterfaceMode::Gateway;
        actor.interfaces.insert(1, gateway);
        let dest = [0xB5; 16];
        actor.path_table.insert(
            dest,
            crate::path_table::PathEntry::new(Some([0xAA; 16]), 2, 2, InterfaceMode::Gateway),
        );

        actor.handle_expired_unvalidated_link(expired_link(dest, 1, 1), now_f64());

        let request = actor.pending_discovery_prs.front().unwrap();
        assert_eq!(request.destination_hash, dest);
        assert_eq!(request.blocked_interface, Some(1));
        assert_eq!(actor.path_table.get_state(&dest), PathState::Unresponsive);
    }

    #[test]
    fn failed_link_boundary_interface_does_not_mark_unresponsive() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        let (mut boundary, _rx) = make_test_interface("boundary");
        boundary.mode = InterfaceMode::Boundary;
        actor.interfaces.insert(1, boundary);
        let dest = [0xB6; 16];
        actor.path_table.insert(
            dest,
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Boundary),
        );

        actor.handle_expired_unvalidated_link(expired_link(dest, 1, 2), now_f64());

        assert_eq!(
            actor
                .pending_discovery_prs
                .front()
                .unwrap()
                .blocked_interface,
            Some(1)
        );
        assert_eq!(actor.path_table.get_state(&dest), PathState::Unknown);
    }

    #[test]
    fn non_transport_leaf_expires_current_path_before_rediscovery() {
        let (mut actor, _tx) = TransportActor::new();
        let dest = [0xB7; 16];
        actor.path_table.insert(
            dest,
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Gateway),
        );

        actor.handle_expired_unvalidated_link(expired_link(dest, 1, 2), now_f64());

        assert!(!actor.path_table.has_path(&dest));
        assert_eq!(actor.pending_discovery_prs.len(), 1);
    }

    #[test]
    fn path_request_markers_survive_30s_and_expire_after_120s() {
        let (mut actor, _tx) = TransportActor::new();
        let keep = [0xB8; 16];
        let expire = [0xB9; 16];
        let now = now_f64();
        actor.path_requests.insert(keep, now - 31.0);
        actor
            .path_requests
            .insert(expire, now - PATH_REQUEST_GATE_TIMEOUT - 1.0);

        actor.on_tick();

        assert!(actor.path_requests.contains_key(&keep));
        assert!(!actor.path_requests.contains_key(&expire));
    }

    #[test]
    fn known_path_request_does_not_answer_requestor_next_hop() {
        let dir = std::env::temp_dir().join("rns_path_request_next_hop");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        actor.transport_identity_hash = Some([0x44; 16]);
        actor.storage_dir = Some(dir.clone());

        let (requestor, mut requestor_rx) = make_test_interface("requestor");
        actor.interfaces.insert(1, requestor);
        let (next_hop_iface, _rx2) = make_test_interface("next_hop_iface");
        actor.interfaces.insert(2, next_hop_iface);

        let next_hop = [0xAB; 16];
        let (raw, dest) = make_valid_announce("test.path.request.next_hop", 1);
        let ph = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
        crate::persistence::write_python_cached_announce_if_absent(
            &dir.join("cache").join("announces"),
            &ph,
            &raw,
            None,
        )
        .unwrap();
        let mut path_entry =
            crate::path_table::PathEntry::new(Some(next_hop), 2, 2, InterfaceMode::Gateway);
        path_entry.packet_hash = Some(ph);
        actor.path_table.insert(dest, path_entry);
        actor.recent_announces.insert(
            dest,
            RecentAnnounce {
                dest_hash: dest,
                hops: 2,
                app_data: None,
                timestamp: now_f64(),
                public_key: None,
                ratchet: None,
                packet_hash: Some(ph),
                is_path_response: false,
                retained: false,
                last_used: None,
                name_hash: [0u8; 10],
            },
        );

        actor.handle_inbound_path_request(&make_path_request_payload(dest, Some(next_hop)), 1);
        assert!(
            requestor_rx.try_recv().is_err(),
            "must not answer a path request when the requestor is our next hop"
        );

        actor.handle_inbound_path_request(
            &make_path_request_payload_with_tag(dest, Some([0xCD; 16]), [0xB6; 16]),
            1,
        );
        assert!(
            requestor_rx.try_recv().is_err(),
            "known path responses should be grace-queued, not sent immediately"
        );
        let queued = actor
            .announce_table
            .get(&dest)
            .expect("known path response should be queued");
        assert!(queued.block_rebroadcast);
        assert_eq!(queued.attached_interface, Some(1));

        actor.flush_pending_announces();
        let response = requestor_rx
            .try_recv()
            .expect("non-looping requestor should receive a path response");
        assert!(actor.announce_table.get(&dest).is_none());
        let (header, _) = rns_wire::header::PacketHeader::unpack(&response).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::PathResponse
        );
        assert_eq!(
            header.flags.header_type,
            rns_wire::flags::HeaderType::Header2
        );
        assert_eq!(header.transport_id, Some([0x44; 16]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_path_response_restores_displaced_announce() {
        let dir = std::env::temp_dir().join("rns_path_request_held");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        actor.transport_identity_hash = Some([0x44; 16]);
        actor.storage_dir = Some(dir.clone());

        let (requestor, mut requestor_rx) = make_test_interface("requestor");
        actor.interfaces.insert(1, requestor);
        let (next_hop_iface, _rx2) = make_test_interface("next_hop_iface");
        actor.interfaces.insert(2, next_hop_iface);

        let (raw, dest) = make_valid_announce("test.path.request.held", 1);
        let ph = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
        crate::persistence::write_python_cached_announce_if_absent(
            &dir.join("cache").join("announces"),
            &ph,
            &raw,
            None,
        )
        .unwrap();
        let mut path_entry =
            crate::path_table::PathEntry::new(Some([0xAB; 16]), 2, 2, InterfaceMode::Gateway);
        path_entry.packet_hash = Some(ph);
        actor.path_table.insert(dest, path_entry);
        actor.recent_announces.insert(
            dest,
            RecentAnnounce {
                dest_hash: dest,
                hops: 2,
                app_data: None,
                timestamp: now_f64(),
                public_key: None,
                ratchet: None,
                packet_hash: Some(ph),
                is_path_response: false,
                retained: false,
                last_used: None,
                name_hash: [0u8; 10],
            },
        );

        let held_raw = vec![0xAA, 0xBB, 0xCC];
        actor.announce_table.insert(
            dest,
            crate::announce::AnnounceEntry {
                timestamp: now_f64(),
                retransmit_timeout: now_f64() + 10.0,
                retries: 0,
                received_from: [0x22; 16],
                hops: 1,
                packet_raw: held_raw.clone(),
                local_rebroadcasts: 0,
                block_rebroadcast: false,
                attached_interface: None,
                source_interface: Some(2),
            },
        );

        actor.handle_inbound_path_request(&make_path_request_payload(dest, None), 1);

        let queued_response = actor
            .announce_table
            .get(&dest)
            .expect("path response should temporarily occupy announce table");
        assert!(queued_response.block_rebroadcast);
        assert_eq!(queued_response.attached_interface, Some(1));
        assert!(
            actor.held_announces.contains_key(&dest),
            "normal queued announce should be held while path response is served"
        );

        actor.flush_pending_announces();
        requestor_rx
            .try_recv()
            .expect("requestor should receive queued path response");

        let restored = actor
            .announce_table
            .get(&dest)
            .expect("held normal announce should be restored after path response send");
        assert!(!restored.block_rebroadcast);
        assert_eq!(restored.packet_raw, held_raw);
        assert!(!actor.held_announces.contains_key(&dest));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_path_request_not_answered_on_same_roaming_interface() {
        let dir = std::env::temp_dir().join("rns_path_request_roaming");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;
        // Cached announce is fully available — only the roaming rule may block.
        actor.storage_dir = Some(dir.clone());

        let (mut roaming, mut roaming_rx) = make_test_interface("roaming");
        roaming.mode = InterfaceMode::Roaming;
        actor.interfaces.insert(1, roaming);

        let (raw, dest) = make_valid_announce("test.path.request.roaming", 1);
        let ph = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
        crate::persistence::write_python_cached_announce_if_absent(
            &dir.join("cache").join("announces"),
            &ph,
            &raw,
            None,
        )
        .unwrap();
        let mut path_entry = crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Roaming);
        path_entry.packet_hash = Some(ph);
        actor.path_table.insert(dest, path_entry);
        actor.recent_announces.insert(
            dest,
            RecentAnnounce {
                dest_hash: dest,
                hops: 1,
                app_data: None,
                timestamp: now_f64(),
                public_key: None,
                ratchet: None,
                packet_hash: Some(ph),
                is_path_response: false,
                retained: false,
                last_used: None,
                name_hash: [0u8; 10],
            },
        );

        actor.handle_inbound_path_request(&make_path_request_payload(dest, None), 1);
        assert!(
            roaming_rx.try_recv().is_err(),
            "roaming interface should not answer with a path learned on itself"
        );
        assert!(
            actor.announce_table.get(&dest).is_none(),
            "roaming rule must block the queued path response, not just the send"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_client_announce_rebroadcasts_without_transport_mode() {
        let (mut actor, _tx) = TransportActor::new();
        actor.transport_identity_hash = Some([0x44; 16]);

        let (mut local_client, mut local_rx) = make_test_interface("SharedInstanceServer/client_2");
        local_client.role = InterfaceRole::LocalClient;
        actor.interfaces.insert(1, local_client);
        let (gateway, mut gateway_rx) = make_test_interface("gateway");
        actor.interfaces.insert(2, gateway);

        let (raw, _dest) = make_valid_announce("test.shared.local_announce", 0);
        actor.on_inbound(crate::messages::InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        actor.on_tick();

        assert!(
            local_rx.try_recv().is_err(),
            "local-client announce must not echo back to its origin"
        );
        let forwarded = gateway_rx
            .try_recv()
            .expect("local-client announce should be sent to external interfaces");
        let (header, _) = rns_wire::header::PacketHeader::unpack(&forwarded).unwrap();
        assert_eq!(
            header.flags.packet_type,
            rns_wire::flags::PacketType::Announce
        );
        assert_eq!(header.hops, 0);
    }

    #[test]
    fn external_announce_replays_to_local_client_with_transport_identity() {
        let (mut actor, _tx) = TransportActor::new();
        actor.transport_identity_hash = Some([0x55; 16]);

        let (external, _external_rx) = make_test_interface("external");
        actor.interfaces.insert(1, external);
        let (mut local_client, mut local_rx) = make_test_interface("SharedInstanceServer/client_3");
        local_client.role = InterfaceRole::LocalClient;
        actor.interfaces.insert(2, local_client);

        let (raw, dest) = make_valid_announce("test.shared.external_announce", 1);
        actor.on_inbound(crate::messages::InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        let replay = local_rx
            .try_recv()
            .expect("external announce should be replayed to local clients");
        let (header, _) = rns_wire::header::PacketHeader::unpack(&replay).unwrap();
        assert_eq!(header.destination_hash, dest);
        assert_eq!(
            header.flags.header_type,
            rns_wire::flags::HeaderType::Header2
        );
        assert_eq!(header.transport_id, Some([0x55; 16]));
        assert_eq!(header.context, rns_wire::context::PacketContext::None);
    }

    #[test]
    fn local_client_path_request_forwards_without_transport_mode() {
        let (mut actor, _tx) = TransportActor::new();
        let (mut local_client, _local_rx) = make_test_interface("SharedInstanceServer/client_4");
        local_client.role = InterfaceRole::LocalClient;
        actor.interfaces.insert(1, local_client);
        let (gateway, mut gateway_rx) = make_test_interface("gateway");
        actor.interfaces.insert(2, gateway);

        let requested = [0x33; 16];
        actor.handle_inbound_path_request(&make_path_request_payload(requested, None), 1);

        let forwarded = gateway_rx
            .try_recv()
            .expect("shared instance must forward local-client path requests");
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&forwarded).unwrap();
        assert_eq!(
            header.destination_hash,
            rns_identity::destination::Destination::hash_from_name_and_identity(
                "rnstransport.path.request",
                None
            )
        );
        assert_eq!(&forwarded[offset..offset + 16], &requested);
    }

    #[test]
    fn external_path_request_for_local_client_round_trips_path_response() {
        let (mut actor, _tx) = TransportActor::new();
        actor.transport_identity_hash = Some([0x66; 16]);

        let (mut local_client, mut local_rx) = make_test_interface("SharedInstanceServer/client_5");
        local_client.role = InterfaceRole::LocalClient;
        actor.interfaces.insert(1, local_client);
        let (external, mut external_rx) = make_test_interface("external");
        actor.interfaces.insert(2, external);

        let (raw, dest) = make_valid_announce("test.shared.local_path_response", 0);
        actor.path_table.insert(
            dest,
            crate::path_table::PathEntry::new(None, 0, 1, InterfaceMode::Gateway),
        );

        actor.handle_inbound_path_request(&make_path_request_payload(dest, None), 2);
        assert!(
            actor.pending_local_path_requests.contains_key(&dest),
            "external request for a local-client destination should be tracked"
        );
        assert!(
            local_rx.try_recv().is_ok(),
            "external path request should be forwarded to local clients"
        );

        let mut response_raw = raw.to_vec();
        response_raw[rns_wire::constants::HEADER_MINSIZE - 1] =
            rns_wire::context::PacketContext::PathResponse.to_byte();
        actor.on_inbound(crate::messages::InboundPacket {
            raw: Bytes::from(response_raw),
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        let response = external_rx
            .try_recv()
            .expect("local-client path response should be returned to the external requester");
        let (header, _) = rns_wire::header::PacketHeader::unpack(&response).unwrap();
        assert_eq!(header.destination_hash, dest);
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::PathResponse
        );
        assert_eq!(
            header.flags.header_type,
            rns_wire::flags::HeaderType::Header2
        );
        assert_eq!(header.transport_id, Some([0x66; 16]));
    }

    #[test]
    fn shared_connection_lost_clears_state_without_deregistering_peer() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_shared_instance = true;

        let (mut shared_peer, _rx) = make_test_interface("SharedInstanceClient");
        shared_peer.role = InterfaceRole::SharedInstancePeer;
        shared_peer.online = Some(Arc::new(AtomicBool::new(false)));
        actor.interfaces.insert(1, shared_peer);
        actor.path_table.insert(
            [0x11; 16],
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Gateway),
        );
        actor.reverse_table.insert([0x22; 16], 1, 1);
        actor.pending_local_path_requests.insert([0x33; 16], 1);

        actor.handle_message(TransportMessage::SharedConnectionLost);

        assert!(!actor.is_shared_instance);
        assert!(actor.shared_instance_client_mode);
        assert!(
            actor.interfaces.contains_key(&1),
            "connection-loss events should suspend shared routing without deleting the peer"
        );
        assert!(actor.path_table.is_empty());
        assert!(actor.reverse_table.is_empty());
        assert!(actor.pending_local_path_requests.is_empty());
    }

    #[test]
    fn shared_instance_peer_deregister_clears_shared_route_state() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_shared_instance = true;

        let (mut shared_peer, _rx) = make_test_interface("SharedInstanceClient");
        shared_peer.role = InterfaceRole::SharedInstancePeer;
        actor.interfaces.insert(1, shared_peer);
        actor.path_table.insert(
            [0x11; 16],
            crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Gateway),
        );
        actor.reverse_table.insert([0x22; 16], 1, 1);
        actor.pending_local_path_requests.insert([0x33; 16], 1);

        actor.handle_message(TransportMessage::DeregisterInterface { id: 1 });

        assert!(!actor.is_shared_instance);
        assert!(actor.path_table.is_empty());
        assert!(actor.reverse_table.is_empty());
        assert!(actor.pending_local_path_requests.is_empty());
    }

    /// Build a valid announce on `app_name` from the supplied identity. Returns
    /// `(raw_packet, dest_hash)`. Used by the aspect-filter dispatch tests so
    /// one identity can announce under several aspects within a single test.
    fn make_announce_for(
        identity: &rns_identity::identity::Identity,
        app_name: &str,
        hops: u8,
    ) -> (Bytes, [u8; 16]) {
        make_announce_for_context(
            identity,
            app_name,
            hops,
            rns_wire::context::PacketContext::None,
        )
    }

    fn make_announce_for_context(
        identity: &rns_identity::identity::Identity,
        app_name: &str,
        hops: u8,
        context: rns_wire::context::PacketContext,
    ) -> (Bytes, [u8; 16]) {
        let dest_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
            app_name,
            Some(&identity.hash),
        );
        let announce_data =
            rns_identity::announce::AnnounceData::create(identity, app_name, None, None).unwrap();
        let payload = announce_data.pack();

        let header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Single,
                packet_type: rns_wire::flags::PacketType::Announce,
            },
            hops,
            transport_id: None,
            destination_hash: dest_hash,
            context,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&payload);
        (Bytes::from(raw), dest_hash)
    }

    #[test]
    fn dispatch_with_no_filter_receives_all() {
        let (mut actor, _tx) = TransportActor::new();
        let (mut entry, _rx) = make_test_interface("test_iface");
        entry.ingress = crate::ingress::IngressController::disabled();
        actor.interfaces.insert(1, entry);

        let (htx, mut hrx) = mpsc::channel(8);
        actor.announce_handlers.push(AnnounceHandlerRegistration {
            aspect_filter: None,
            receive_path_responses: false,
            tx: htx,
        });

        let identity = rns_identity::identity::Identity::new();
        for aspect in &["lxmf.delivery", "lxmf.propagation", "nomadnetwork.node"] {
            let (raw, _dh) = make_announce_for(&identity, aspect, 1);
            actor.on_inbound(crate::messages::InboundPacket {
                raw,
                interface_id: 1,
                rssi: None,
                snr: None,
                q: None,
            });
        }

        let mut received = 0;
        while hrx.try_recv().is_ok() {
            received += 1;
        }
        assert_eq!(received, 3, "None-filter handler must receive all aspects");
    }

    #[test]
    fn dispatch_with_filter_only_matching_aspect() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, _rx) = make_test_interface("test_iface");
        actor.interfaces.insert(1, entry);

        let (htx, mut hrx) = mpsc::channel(8);
        actor.announce_handlers.push(AnnounceHandlerRegistration {
            aspect_filter: Some("lxmf.delivery".to_string()),
            receive_path_responses: false,
            tx: htx,
        });

        let identity = rns_identity::identity::Identity::new();
        let (raw_delivery, dh_delivery) = make_announce_for(&identity, "lxmf.delivery", 1);
        let (raw_prop, _) = make_announce_for(&identity, "lxmf.propagation", 1);
        let (raw_nomad, _) = make_announce_for(&identity, "nomadnetwork.node", 1);

        for raw in [raw_delivery, raw_prop, raw_nomad] {
            actor.on_inbound(crate::messages::InboundPacket {
                raw,
                interface_id: 1,
                rssi: None,
                snr: None,
                q: None,
            });
        }

        let mut events = Vec::new();
        while let Ok(ev) = hrx.try_recv() {
            events.push(ev);
        }
        assert_eq!(
            events.len(),
            1,
            "filtered handler must only receive matching aspect"
        );
        assert_eq!(events[0].destination_hash, dh_delivery);
        assert_eq!(
            events[0].name_hash,
            rns_identity::name_hash::name_hash("lxmf.delivery")
        );
    }

    #[test]
    fn multiple_handlers_independent_filters() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, _rx) = make_test_interface("test_iface");
        actor.interfaces.insert(1, entry);

        let (h_del_tx, mut h_del_rx) = mpsc::channel(8);
        let (h_prop_tx, mut h_prop_rx) = mpsc::channel(8);
        actor.announce_handlers.push(AnnounceHandlerRegistration {
            aspect_filter: Some("lxmf.delivery".to_string()),
            receive_path_responses: false,
            tx: h_del_tx,
        });
        actor.announce_handlers.push(AnnounceHandlerRegistration {
            aspect_filter: Some("lxmf.propagation".to_string()),
            receive_path_responses: false,
            tx: h_prop_tx,
        });

        let identity = rns_identity::identity::Identity::new();
        let (raw_delivery, dh_delivery) = make_announce_for(&identity, "lxmf.delivery", 1);
        let (raw_prop, dh_prop) = make_announce_for(&identity, "lxmf.propagation", 1);

        for raw in [raw_delivery, raw_prop] {
            actor.on_inbound(crate::messages::InboundPacket {
                raw,
                interface_id: 1,
                rssi: None,
                snr: None,
                q: None,
            });
        }

        let del_events: Vec<_> = std::iter::from_fn(|| h_del_rx.try_recv().ok()).collect();
        let prop_events: Vec<_> = std::iter::from_fn(|| h_prop_rx.try_recv().ok()).collect();

        assert_eq!(del_events.len(), 1, "delivery handler sees one event");
        assert_eq!(del_events[0].destination_hash, dh_delivery);
        assert_eq!(prop_events.len(), 1, "propagation handler sees one event");
        assert_eq!(prop_events[0].destination_hash, dh_prop);
    }

    #[test]
    fn path_response_handler_requires_opt_in() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, _rx) = make_test_interface("test_iface");
        actor.interfaces.insert(1, entry);

        let (default_tx, mut default_rx) = mpsc::channel(8);
        actor.announce_handlers.push(AnnounceHandlerRegistration {
            aspect_filter: None,
            receive_path_responses: false,
            tx: default_tx,
        });
        let (opt_in_tx, mut opt_in_rx) = mpsc::channel(8);
        actor.announce_handlers.push(AnnounceHandlerRegistration {
            aspect_filter: None,
            receive_path_responses: true,
            tx: opt_in_tx,
        });

        let identity = rns_identity::identity::Identity::new();
        let (raw, dest_hash) = make_announce_for_context(
            &identity,
            "test.path_response.handler",
            1,
            rns_wire::context::PacketContext::PathResponse,
        );
        let expected_hash = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
        actor.on_inbound(crate::messages::InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(
            default_rx.try_recv().is_err(),
            "path responses must not reach default handlers"
        );
        let event = opt_in_rx
            .try_recv()
            .expect("opt-in handler should receive path response");
        assert_eq!(event.destination_hash, dest_hash);
        assert_eq!(event.announce_packet_hash, expected_hash);
        assert!(event.is_path_response);
    }

    #[test]
    fn path_response_bypasses_announce_rate_limit() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut entry, _rx) = make_test_interface("limited_iface");
        entry.announce_rate_target = Some(999.0);
        entry.announce_rate_grace = Some(0);
        entry.announce_rate_penalty = Some(60.0);
        actor.interfaces.insert(1, entry);

        let (handler_tx, mut handler_rx) = mpsc::channel(8);
        actor.announce_handlers.push(AnnounceHandlerRegistration {
            aspect_filter: None,
            receive_path_responses: true,
            tx: handler_tx,
        });

        let identity = rns_identity::identity::Identity::new();
        let (raw, dest_hash) = make_announce_for_context(
            &identity,
            "test.path_response.rate",
            1,
            rns_wire::context::PacketContext::PathResponse,
        );
        assert!(
            !actor
                .rate_table
                .check_interface_rate(dest_hash, 999.0, 0, 60.0)
        );
        assert!(
            actor
                .rate_table
                .check_interface_rate(dest_hash, 999.0, 0, 60.0),
            "precondition: destination is rate-blocked before path response arrives"
        );

        actor.on_inbound(crate::messages::InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(
            actor.path_table.has_path(&dest_hash),
            "path response must still teach the path while rate-blocked"
        );
        assert!(
            actor.recent_announces.contains_key(&dest_hash),
            "path response must still update announce cache while rate-blocked"
        );
        assert!(
            actor.announce_table.get(&dest_hash).is_none(),
            "path responses are not queued for normal rebroadcast"
        );
        assert!(
            handler_rx.try_recv().unwrap().is_path_response,
            "opt-in handlers still receive rate-blocked path responses"
        );
    }

    #[test]
    fn rate_limited_live_announce_still_learns_but_does_not_rebroadcast() {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = true;

        let (mut entry, _rx) = make_test_interface("limited_iface");
        entry.announce_rate_target = Some(999.0);
        entry.announce_rate_grace = Some(0);
        entry.announce_rate_penalty = Some(60.0);
        actor.interfaces.insert(1, entry);

        let identity = rns_identity::identity::Identity::new();
        let (first_raw, dest_hash) =
            make_announce_for_with_random_blob(&identity, "test.live.rate", 1, random_blob(1, 1));
        actor.on_inbound(crate::messages::InboundPacket {
            raw: first_raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        actor.announce_table.remove(&dest_hash);

        let (second_raw, _) =
            make_announce_for_with_random_blob(&identity, "test.live.rate", 1, random_blob(2, 2));
        actor.on_inbound(crate::messages::InboundPacket {
            raw: second_raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        assert!(
            actor.path_table.has_path(&dest_hash),
            "rate-blocked live announce must still update path state"
        );
        assert!(
            actor.recent_announces.contains_key(&dest_hash),
            "rate-blocked live announce must still update recent announce state"
        );
        assert!(
            actor.announce_table.get(&dest_hash).is_none(),
            "rate-blocked live announce must not be queued for rebroadcast"
        );
    }

    #[test]
    fn recent_announces_carry_name_hash() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, _rx) = make_test_interface("test_iface");
        actor.interfaces.insert(1, entry);

        let identity = rns_identity::identity::Identity::new();
        let (raw, dh) = make_announce_for(&identity, "lxmf.delivery", 2);
        actor.on_inbound(crate::messages::InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });

        let entry = actor
            .recent_announces
            .get(&dh)
            .expect("announce must be cached");
        assert_eq!(
            entry.name_hash,
            rns_identity::name_hash::name_hash("lxmf.delivery"),
            "RecentAnnounce.name_hash must match SHA-256(app_name)[:10]"
        );

        match actor.handle_query(crate::messages::TransportQuery::GetRecentAnnounces) {
            crate::messages::TransportQueryResponse::Announces(entries) => {
                let rpc_entry = entries
                    .iter()
                    .find(|entry| entry.dest_hash == dh)
                    .expect("announce must be exposed over RPC");
                assert_eq!(
                    rpc_entry.name_hash,
                    rns_identity::name_hash::name_hash("lxmf.delivery"),
                    "AnnounceRpcEntry.name_hash must preserve the cached aspect hash"
                );
            }
            other => panic!("expected Announces response, got {other:?}"),
        }
    }

    #[test]
    fn drop_recent_announces_clears_cached_snapshots() {
        let (mut actor, _tx) = TransportActor::new();
        let (entry, _rx) = make_test_interface("test_iface");
        actor.interfaces.insert(1, entry);

        let identity = rns_identity::identity::Identity::new();
        let (raw, dh) = make_announce_for(&identity, "lxmf.delivery", 2);
        actor.on_inbound(crate::messages::InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
        assert!(actor.recent_announces.contains_key(&dh));

        match actor.handle_query(crate::messages::TransportQuery::DropRecentAnnounces) {
            crate::messages::TransportQueryResponse::IntResult(n) => assert_eq!(n, 1),
            other => panic!("expected IntResult response, got {other:?}"),
        }
        assert!(actor.recent_announces.is_empty());
        assert!(!actor.state_dirty);
    }

    #[test]
    fn drop_path_table_clears_routes_and_pending_path_state() {
        let (mut actor, _tx) = TransportActor::new();
        let dest = [0xAB; 16];
        actor.path_table.insert(
            dest,
            PathEntry::new(Some([0xCD; 16]), 3, 7, InterfaceMode::Full),
        );
        actor
            .pending_path_entries
            .push(crate::persistence::PersistedPathEntry {
                destination_hash: vec![0x11; 16],
                timestamp: 1.0,
                next_hop: None,
                hops: 1,
                expires: 2.0,
                random_blobs: Vec::new(),
                interface_id: 7,
                interface_name: Some("missing".into()),
                interface_hash: None,
                packet_hash: None,
            });
        actor.pending_local_path_requests.insert(dest, 7);
        actor
            .pending_discovery_prs
            .push_back(PendingDiscoveryPathRequest {
                destination_hash: dest,
                blocked_interface: Some(7),
            });

        match actor.handle_query(crate::messages::TransportQuery::DropPathTable) {
            crate::messages::TransportQueryResponse::IntResult(n) => assert_eq!(n, 1),
            other => panic!("expected IntResult response, got {other:?}"),
        }
        assert!(actor.path_table.is_empty());
        assert!(actor.pending_path_entries.is_empty());
        assert!(actor.pending_local_path_requests.is_empty());
        assert!(actor.pending_discovery_prs.is_empty());
        assert!(!actor.state_dirty);
    }

    /// Helper: insert a synthetic recent_announce for `(dest_hash, identity)`.
    fn insert_announce_for(
        actor: &mut TransportActor,
        dest_hash: [u8; 16],
        identity: &rns_identity::identity::Identity,
    ) {
        actor.recent_announces.insert(
            dest_hash,
            RecentAnnounce {
                dest_hash,
                hops: 1,
                app_data: None,
                timestamp: 1.0,
                public_key: Some(identity.get_public_key()),
                ratchet: None,
                packet_hash: None,
                is_path_response: false,
                retained: false,
                last_used: None,
                name_hash: [0; 10],
            },
        );
    }

    #[test]
    fn resolve_identity_hash_dest_branch() {
        let (mut actor, _tx) = TransportActor::new();
        let identity = rns_identity::identity::Identity::new();
        let dest_hash = [0xA1; 16];
        insert_announce_for(&mut actor, dest_hash, &identity);

        let resp = actor.handle_query(crate::messages::TransportQuery::ResolveIdentityHash {
            input: dest_hash,
        });
        match resp {
            crate::messages::TransportQueryResponse::HashResult(Some(h)) => {
                assert_eq!(h, identity.hash);
            }
            other => panic!("expected HashResult(Some(_)), got {other:?}"),
        }
    }

    #[test]
    fn resolve_identity_hash_identity_branch() {
        let (mut actor, _tx) = TransportActor::new();
        let identity = rns_identity::identity::Identity::new();
        insert_announce_for(&mut actor, [0xB2; 16], &identity);

        // Input IS already the identity hash.
        let resp = actor.handle_query(crate::messages::TransportQuery::ResolveIdentityHash {
            input: identity.hash,
        });
        match resp {
            crate::messages::TransportQueryResponse::HashResult(Some(h)) => {
                assert_eq!(h, identity.hash);
            }
            other => panic!("expected HashResult(Some(_)), got {other:?}"),
        }
    }

    #[test]
    fn resolve_identity_hash_unknown() {
        let (mut actor, _tx) = TransportActor::new();
        let resp = actor.handle_query(crate::messages::TransportQuery::ResolveIdentityHash {
            input: [0xCC; 16],
        });
        assert!(matches!(
            resp,
            crate::messages::TransportQueryResponse::HashResult(None)
        ));
    }

    #[test]
    fn filter_blackholed_dests_returns_only_blackholed() {
        let (mut actor, _tx) = TransportActor::new();
        let blocked = rns_identity::identity::Identity::new();
        let allowed = rns_identity::identity::Identity::new();
        let dest_blocked = [0xA1; 16];
        let dest_allowed = [0xA2; 16];
        let dest_unknown = [0xA3; 16];
        insert_announce_for(&mut actor, dest_blocked, &blocked);
        insert_announce_for(&mut actor, dest_allowed, &allowed);
        actor.blackhole_table.add(blocked.hash, None);

        let resp = actor.handle_query(crate::messages::TransportQuery::FilterBlackholedDests {
            dests: vec![dest_blocked, dest_allowed, dest_unknown],
        });
        match resp {
            crate::messages::TransportQueryResponse::BlackholedDests(v) => {
                assert_eq!(v, vec![dest_blocked]);
            }
            other => panic!("expected BlackholedDests, got {other:?}"),
        }
    }

    #[test]
    fn blackhole_identity_scrubs_path_table() {
        let (mut actor, _tx) = TransportActor::new();
        let identity = rns_identity::identity::Identity::new();
        let other = rns_identity::identity::Identity::new();
        let (raw_a, dest_a) = make_announce_for(&identity, "lxmf.delivery", 2);
        let (raw_b, dest_b) = make_announce_for(&identity, "lxmf.propagation", 2);
        let (raw_c, dest_c) = make_announce_for(&other, "lxmf.delivery", 2);

        actor.is_transport_enabled = true;
        let (mut entry, _rx) = make_test_interface("scrub_iface");
        entry.ingress = crate::ingress::IngressController::disabled();
        actor.interfaces.insert(1, entry);

        for raw in [raw_a, raw_b, raw_c] {
            actor.on_inbound(crate::messages::InboundPacket {
                raw,
                interface_id: 1,
                rssi: None,
                snr: None,
                q: None,
            });
        }
        assert!(actor.path_table.has_path(&dest_a));
        assert!(actor.path_table.has_path(&dest_b));
        assert!(actor.path_table.has_path(&dest_c));

        let resp = actor.handle_query(crate::messages::TransportQuery::BlackholeIdentity {
            hash: identity.hash,
            ttl: None,
            reason: crate::blackhole::BlackholeReason::Manual,
            reason_label: None,
        });
        assert!(matches!(resp, crate::messages::TransportQueryResponse::Ok));

        // Both destinations belonging to `identity` are scrubbed; `other` survives.
        assert!(!actor.path_table.has_path(&dest_a));
        assert!(!actor.path_table.has_path(&dest_b));
        assert!(actor.path_table.has_path(&dest_c));
    }

    #[test]
    fn manifest_publication_skips_unverified_entries() {
        let (mut actor, _tx) = TransportActor::new();
        let verified = rns_identity::identity::Identity::new();
        let unverified_id = [0xFE; 16]; // no matching announce
        insert_announce_for(&mut actor, [0xA1; 16], &verified);
        actor.blackhole_table.add_with_reason(
            verified.hash,
            None,
            crate::blackhole::BlackholeReason::Manual,
        );
        actor.blackhole_table.add_with_reason(
            unverified_id,
            None,
            crate::blackhole::BlackholeReason::Manual,
        );

        let payload =
            match actor.handle_query(crate::messages::TransportQuery::BuildBlackholeManifest {
                publisher: [0x99; 16],
            }) {
                crate::messages::TransportQueryResponse::Data(p) => p,
                other => panic!("expected Data manifest, got {other:?}"),
            };
        let decoded = crate::discovery::decode_manifest(&payload).unwrap();
        assert_eq!(
            decoded.len(),
            1,
            "only the verified entry should be published"
        );
        assert_eq!(decoded[0].0, verified.hash);
    }

    #[test]
    fn get_blackholed_identities_decorates_verified_flag() {
        let (mut actor, _tx) = TransportActor::new();
        let known = rns_identity::identity::Identity::new();
        insert_announce_for(&mut actor, [0xA1; 16], &known);
        actor.blackhole_table.add(known.hash, None);
        actor.blackhole_table.add([0xFE; 16], None);

        let entries =
            match actor.handle_query(crate::messages::TransportQuery::GetBlackholedIdentities) {
                crate::messages::TransportQueryResponse::BlackholeList(v) => v,
                other => panic!("expected BlackholeList, got {other:?}"),
            };
        assert_eq!(entries.len(), 2);
        for e in entries {
            if e.identity_hash == known.hash {
                assert!(e.verified, "known identity should be verified");
            } else {
                assert!(!e.verified, "unknown identity must not be verified");
            }
        }
    }

    #[test]
    fn purge_unverified_blackholes_drops_only_unverified() {
        let (mut actor, _tx) = TransportActor::new();
        let known = rns_identity::identity::Identity::new();
        insert_announce_for(&mut actor, [0xA1; 16], &known);
        actor.blackhole_table.add_with_reason(
            known.hash,
            None,
            crate::blackhole::BlackholeReason::Manual,
        );
        actor.blackhole_table.add_with_reason(
            [0xFE; 16],
            None,
            crate::blackhole::BlackholeReason::Manual,
        );
        // Non-Manual entries are not affected by PurgeUnverifiedBlackholes regardless
        // of verification state — they're managed by ClearSystemBlackholes.
        actor.blackhole_table.add_with_reason(
            [0xFD; 16],
            None,
            crate::blackhole::BlackholeReason::RateLimit,
        );

        let resp = actor.handle_query(crate::messages::TransportQuery::PurgeUnverifiedBlackholes);
        let purged = match resp {
            crate::messages::TransportQueryResponse::IntResult(n) => n,
            other => panic!("expected IntResult, got {other:?}"),
        };
        assert_eq!(purged, 1);
        assert!(actor.blackhole_table.is_blackholed(&known.hash));
        assert!(!actor.blackhole_table.is_blackholed(&[0xFE; 16]));
        assert!(actor.blackhole_table.is_blackholed(&[0xFD; 16]));
    }
}
