//! BLE Peer-to-Peer mesh interface. Each device acts as both Central
//! (scanner/GATT client) and Peripheral (advertiser/GATT server)
//! simultaneously.
//!
//! ## Dual-service GATT
//!
//! ### Ratspeak (primary)
//! - Service: `a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d`
//! - RX:      `…4c5e` (WRITE, WRITE_NO_RESPONSE)
//! - TX:      `…4c5f` (READ, NOTIFY)
//! - ID:      `…4c60` (READ) — 16-byte identity hash
//!
//! ### Columba (cross-app compat)
//! - Service: `37145b00-442d-4a94-917f-8f42c5da28e3`
//! - RX:      `…28e5` (WRITE, WRITE_NO_RESPONSE)
//! - TX:      `…28e4` (READ, NOTIFY, INDICATE)
//! - ID:      `…28e6` (READ)
//!
//! ## Fragmentation
//!
//! Packets larger than (MTU - 3), and small packets whose first byte would
//! collide with START / CONTINUE / END frame tags, use a 5-byte header
//! `[type:1][seq:2-BE][total:2-BE]`. Reassembly timeout 30s. Small ambiguous
//! packets are encoded as a two-frame START/END sequence instead of LONE so
//! older reassemblers can still decode them.
//!
//! Keepalive: 15s interval, 1-byte ping; 3 misses → disconnect. Cap 7
//! simultaneous peers.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::traits::{
    InterfaceDirection, InterfaceError, InterfaceHandle, InterfaceId, InterfaceMode,
};
use rns_transport::messages::TransportMessage;

// Peer writes RX, we notify TX, ID is hash.
pub const RATSPEAK_SERVICE_UUID: Uuid = Uuid::from_u128(0xa1b2c3d4_e5f6_4a5b_8c9d_0e1f2a3b4c5d);
pub const RATSPEAK_RX_UUID: Uuid = Uuid::from_u128(0xa1b2c3d4_e5f6_4a5b_8c9d_0e1f2a3b4c5e);
pub const RATSPEAK_TX_UUID: Uuid = Uuid::from_u128(0xa1b2c3d4_e5f6_4a5b_8c9d_0e1f2a3b4c5f);
pub const RATSPEAK_ID_UUID: Uuid = Uuid::from_u128(0xa1b2c3d4_e5f6_4a5b_8c9d_0e1f2a3b4c60);

// Same shape with different UUIDs.
pub const COLUMBA_SERVICE_UUID: Uuid = Uuid::from_u128(0x37145b00_442d_4a94_917f_8f42c5da28e3);
pub const COLUMBA_TX_UUID: Uuid = Uuid::from_u128(0x37145b00_442d_4a94_917f_8f42c5da28e4);
pub const COLUMBA_RX_UUID: Uuid = Uuid::from_u128(0x37145b00_442d_4a94_917f_8f42c5da28e5);
pub const COLUMBA_ID_UUID: Uuid = Uuid::from_u128(0x37145b00_442d_4a94_917f_8f42c5da28e6);

pub const MAX_PEERS: usize = 7;
/// Upper bound on a fragment set's `total`. A Reticulum packet is <=500 bytes,
/// so even at a pathologically small ATT MTU the count stays well under this;
/// the cap stops an unauthenticated writer from sizing a reassembly buffer off
/// an attacker-controlled 16-bit field (multi-MB allocation per START frame).
pub const MAX_FRAGMENTS: u16 = 64;
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
pub const KEEPALIVE_MAX_MISSES: u32 = 3;
pub const FRAGMENT_TIMEOUT: Duration = Duration::from_secs(30);
pub const MIN_RSSI: i16 = -85;
pub const SCAN_ACTIVE_INTERVAL: Duration = Duration::from_secs(5);
pub const SCAN_IDLE_INTERVAL: Duration = Duration::from_secs(30);
pub const BLE_FRAGMENT_PACING: Duration = Duration::from_millis(8);

/// Recently-disconnected peers stay "wanted" — scan loop uses the active
/// interval for them until they reconnect or the entry expires.
pub const RECONNECT_BACKOFF_FAILURES: u32 = 3;
pub const RECONNECT_BACKOFF_DURATION: Duration = Duration::from_secs(300);
pub const RECONNECT_PRUNE_AFTER: Duration = Duration::from_secs(600);

/// `(disconnect_time, consecutive_failure_count)` keyed by BLE scan address.
pub type RecentlyDisconnected = Arc<std::sync::Mutex<HashMap<String, (Instant, u32)>>>;

pub fn new_recently_disconnected() -> RecentlyDisconnected {
    Arc::new(std::sync::Mutex::new(HashMap::new()))
}

/// Seeded entries start at `(now, 0)` — candidate, not in backoff.
pub fn seed_recently_disconnected(map: &RecentlyDisconnected, addresses: Vec<String>) {
    if addresses.is_empty() {
        return;
    }
    if let Ok(mut guard) = map.lock() {
        let now = Instant::now();
        for address in addresses {
            if !address.is_empty() {
                guard.entry(address).or_insert((now, 0));
            }
        }
    }
}

/// All-zero is the sentinel ("no identity yet") and must never reach
/// advertising.
pub fn is_valid_identity_hash(bytes: &[u8]) -> bool {
    bytes.len() == 16 && bytes.iter().any(|b| *b != 0)
}

/// Long enough to absorb transport store-and-forward jitter; short enough
/// that legitimate retransmits eventually reach the original sender.
pub const ANTI_LOOP_TTL: Duration = Duration::from_secs(30);

/// `payload_hash → (sources, first_seen)`. Lets the fan-out skip echoing
/// a packet back to the peers it arrived from.
pub type AntiLoopMap =
    Arc<std::sync::Mutex<HashMap<u64, (std::collections::HashSet<String>, Instant)>>>;

pub fn new_anti_loop_map() -> AntiLoopMap {
    Arc::new(std::sync::Mutex::new(HashMap::new()))
}

fn payload_hash(data: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut h);
    h.finish()
}

#[cfg(any(test, target_os = "android"))]
fn parse_newline_addresses(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .map(str::to_string)
        .collect()
}

fn should_pace_after_fragment(index: usize, total: usize) -> bool {
    index < total.saturating_sub(1)
}

#[cfg(any(test, not(target_os = "android")))]
async fn pace_after_ble_fragment(index: usize, total: usize) {
    if should_pace_after_fragment(index, total) {
        tokio::time::sleep(BLE_FRAGMENT_PACING).await;
    }
}

#[cfg(target_os = "android")]
fn sleep_after_ble_fragment_blocking(index: usize, total: usize) {
    if should_pace_after_fragment(index, total) {
        std::thread::sleep(BLE_FRAGMENT_PACING);
    }
}

/// A second call from the same source within `ANTI_LOOP_TTL` refreshes the timestamp.
pub fn anti_loop_record(map: &AntiLoopMap, source: String, payload: &[u8]) {
    let h = payload_hash(payload);
    if let Ok(mut g) = map.lock() {
        let entry = g
            .entry(h)
            .or_insert_with(|| (std::collections::HashSet::new(), Instant::now()));
        entry.0.insert(source);
        entry.1 = Instant::now();
    }
}

/// false iff `dest` is one of the peers `payload` arrived from.
pub fn anti_loop_should_send(map: &AntiLoopMap, dest: &str, payload: &[u8]) -> bool {
    let h = payload_hash(payload);
    if let Ok(g) = map.lock() {
        if let Some((srcs, t)) = g.get(&h) {
            if t.elapsed() < ANTI_LOOP_TTL && srcs.contains(dest) {
                return false;
            }
        }
    }
    true
}

pub fn anti_loop_prune(map: &AntiLoopMap) {
    if let Ok(mut g) = map.lock() {
        g.retain(|_, (_, t)| t.elapsed() < ANTI_LOOP_TTL);
    }
}

#[derive(Debug, Default)]
struct BlePeerLinkRegistry {
    identity_by_address: HashMap<String, String>,
}

impl BlePeerLinkRegistry {
    fn set_identity(&mut self, address: String, identity_hash: String) {
        if !address.is_empty() && !identity_hash.is_empty() {
            self.identity_by_address.insert(address, identity_hash);
        }
    }

    #[cfg(any(test, target_os = "android", target_os = "ios", target_os = "macos"))]
    fn address_for_writer_key<'a>(&self, writer_key: &'a str) -> &'a str {
        writer_key.strip_prefix("central:").unwrap_or(writer_key)
    }

    #[cfg(any(test, target_os = "android", target_os = "ios", target_os = "macos"))]
    fn should_send_peripheral_subscriber(
        &self,
        subscriber_address: &str,
        central_writer_keys: &[String],
    ) -> bool {
        if central_writer_keys
            .iter()
            .any(|key| self.address_for_writer_key(key) == subscriber_address)
        {
            return false;
        }

        let Some(subscriber_identity) = self.identity_by_address.get(subscriber_address) else {
            return true;
        };

        !central_writer_keys.iter().any(|key| {
            let writer_address = self.address_for_writer_key(key);
            self.identity_by_address
                .get(writer_address)
                .is_some_and(|writer_identity| writer_identity == subscriber_identity)
        })
    }
}

type LinkRegistry = Arc<tokio::sync::RwLock<BlePeerLinkRegistry>>;

/// Returns the destination-hash hex of `raw` ONLY if it is a signed announce
/// whose Ed25519 signature verifies. Binding a peer's identity from an
/// unverified announce let an in-range attacker claim a known contact's
/// identity (mislabelling the peer and poisoning the dual-role dedup registry);
/// the signature check means a claim can't be forged without the private key.
fn verified_announce_identity_hex(raw: &[u8]) -> Option<String> {
    let (header, payload_offset) = rns_wire::header::PacketHeader::unpack(raw).ok()?;
    if header.flags.packet_type != rns_wire::flags::PacketType::Announce {
        return None;
    }
    let payload = raw.get(payload_offset..)?;
    let announce =
        rns_identity::announce::AnnounceData::unpack(payload, header.flags.context_flag).ok()?;
    announce.verify_signature(&header.destination_hash).ok()?;
    Some(hex::encode(header.destination_hash))
}

#[cfg(any(test, target_os = "android", target_os = "ios", target_os = "macos"))]
fn payload_needs_redundant_role_fanout(payload: &[u8]) -> bool {
    rns_wire::header::PacketHeader::unpack(payload)
        .is_ok_and(|(header, _)| header.flags.packet_type == rns_wire::flags::PacketType::Proof)
}

#[cfg(any(test, target_os = "android", target_os = "ios", target_os = "macos"))]
fn should_send_peripheral_payload(
    registry: &BlePeerLinkRegistry,
    subscriber_address: &str,
    central_writer_keys: &[String],
    payload: &[u8],
) -> bool {
    payload_needs_redundant_role_fanout(payload)
        || registry.should_send_peripheral_subscriber(subscriber_address, central_writer_keys)
}

fn reconnect_in_backoff(map: &RecentlyDisconnected, address: &str) -> bool {
    if in_churn_backoff(address) {
        return true;
    }
    if let Ok(guard) = map.lock() {
        if let Some((when, fails)) = guard.get(address) {
            return *fails >= RECONNECT_BACKOFF_FAILURES
                && when.elapsed() < RECONNECT_BACKOFF_DURATION;
        }
    }
    false
}

fn record_disconnect(map: &RecentlyDisconnected, address: &str) {
    if address.is_empty() {
        return;
    }
    note_peer_disconnected(address);
    if let Ok(mut guard) = map.lock() {
        guard
            .entry(address.to_string())
            .and_modify(|(when, _)| *when = Instant::now())
            .or_insert((Instant::now(), 0));
    }
}

fn record_reconnect_failure(map: &RecentlyDisconnected, address: &str) {
    if address.is_empty() {
        return;
    }
    if let Ok(mut guard) = map.lock() {
        guard
            .entry(address.to_string())
            .and_modify(|(when, fails)| {
                *when = Instant::now();
                *fails = fails.saturating_add(1);
            })
            .or_insert((Instant::now(), 1));
    }
}

fn record_reconnect_success(map: &RecentlyDisconnected, address: &str) {
    note_peer_connected(address);
    if let Ok(mut guard) = map.lock() {
        guard.remove(address);
    }
}

/// iOS-rotated CBPeripheral.identifier whose advertising address moved —
/// seed at the backoff threshold so later scan cycles skip it instead of
/// burning another 5s connect timeout. Apple-only because the caller path
/// is gated on Apple BLE central plumbing (`ble_central_apple_connect`).
#[cfg(all(feature = "ble", any(target_os = "ios", target_os = "macos")))]
fn record_connect_timeout_ghost(map: &RecentlyDisconnected, address: &str) {
    if let Ok(mut guard) = map.lock() {
        guard.insert(
            address.to_string(),
            (Instant::now(), RECONNECT_BACKOFF_FAILURES),
        );
    }
}

/// Drop the entry on RPA-rotation disconnects so the next scan reconnects
/// without backoff drag. Apple-only — RPA rotation is a CoreBluetooth
/// concept (`DisconnectReason::Rotation`).
#[cfg(all(feature = "ble", any(target_os = "ios", target_os = "macos")))]
fn record_rotation_disconnect(map: &RecentlyDisconnected, address: &str) {
    if let Ok(mut guard) = map.lock() {
        guard.remove(address);
    }
}

fn prune_recently_disconnected(map: &RecentlyDisconnected) {
    prune_churn_track();
    if let Ok(mut guard) = map.lock() {
        guard.retain(|_, (when, _)| when.elapsed() < RECONNECT_PRUNE_AFTER);
    }
}

/// A connect that survives at least this long is a healthy session and resets
/// the churn counter; a drop sooner is counted as a flap. Longer than
/// `KEEPALIVE_INTERVAL` so at least one keepalive must have succeeded.
const CHURN_MIN_STABLE: Duration = Duration::from_secs(20);

/// `(connected_at, flap_count, last_update)` keyed by BLE address. Separate
/// from `RecentlyDisconnected` because a successful connect clears that map's
/// failure count — so connect-then-drop flapping never accumulated backoff
/// there. This counter survives connects and only resets on a stable session.
type ChurnEntry = (Option<Instant>, u32, Instant);

fn churn_track() -> &'static std::sync::Mutex<HashMap<String, ChurnEntry>> {
    static CHURN: std::sync::OnceLock<std::sync::Mutex<HashMap<String, ChurnEntry>>> =
        std::sync::OnceLock::new();
    CHURN.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn note_peer_connected(address: &str) {
    if address.is_empty() {
        return;
    }
    if let Ok(mut g) = churn_track().lock() {
        let e = g
            .entry(address.to_string())
            .or_insert((None, 0, Instant::now()));
        e.0 = Some(Instant::now());
        e.2 = Instant::now();
    }
}

fn note_peer_disconnected(address: &str) {
    if address.is_empty() {
        return;
    }
    if let Ok(mut g) = churn_track().lock() {
        if let Some(e) = g.get_mut(address) {
            // Only count as a flap when we know it connected recently; a
            // missing connect stamp defaults to "stable" so a missed
            // note_peer_connected can never manufacture wrongful backoff.
            let flapped = e.0.is_some_and(|t| t.elapsed() < CHURN_MIN_STABLE);
            e.1 = if flapped { e.1.saturating_add(1) } else { 0 };
            e.0 = None;
            e.2 = Instant::now();
        }
    }
}

fn in_churn_backoff(address: &str) -> bool {
    if let Ok(g) = churn_track().lock() {
        if let Some((_, count, last)) = g.get(address) {
            return *count >= RECONNECT_BACKOFF_FAILURES
                && last.elapsed() < RECONNECT_BACKOFF_DURATION;
        }
    }
    false
}

fn prune_churn_track() {
    if let Ok(mut g) = churn_track().lock() {
        g.retain(|_, (_, _, last)| last.elapsed() < RECONNECT_PRUNE_AFTER);
    }
}

/// True if any entry is still "wanted" — not pruned and not in backoff.
fn has_wanted_reconnects(map: &RecentlyDisconnected) -> bool {
    if let Ok(guard) = map.lock() {
        guard.iter().any(|(_, (when, fails))| {
            when.elapsed() < RECONNECT_PRUNE_AFTER
                && (*fails < RECONNECT_BACKOFF_FAILURES
                    || when.elapsed() >= RECONNECT_BACKOFF_DURATION)
        })
    } else {
        false
    }
}

/// Already-connected peers stay alive via keepalive.
pub const SCAN_BACKGROUND_INTERVAL: Duration = Duration::from_secs(60);

const SCAN_SLEEP_SLICE: Duration = Duration::from_secs(2);

/// Exits early on foreground-resume or `wake` notify.
async fn scan_sleep(
    total: Duration,
    foreground: &Arc<AtomicBool>,
    was_foreground: bool,
    wake: &Arc<tokio::sync::Notify>,
) {
    if was_foreground {
        tokio::select! {
            _ = tokio::time::sleep(total) => {}
            _ = wake.notified() => {}
        }
        return;
    }
    let deadline = std::time::Instant::now() + total;
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return;
        }
        let remaining = (deadline - now).min(SCAN_SLEEP_SLICE);
        tokio::select! {
            _ = tokio::time::sleep(remaining) => {}
            _ = wake.notified() => return,
        }
        if foreground.load(Ordering::Relaxed) {
            return;
        }
    }
}

/// BLE 5.0 max.
pub const TARGET_MTU: u16 = 517;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentType {
    Lone = 0x00,
    Start = 0x01,
    Continue = 0x02,
    End = 0x03,
}

impl FragmentType {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Lone),
            0x01 => Some(Self::Start),
            0x02 => Some(Self::Continue),
            0x03 => Some(Self::End),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlePeer {
    /// 16-byte hex Reticulum identity hash.
    pub identity_hash: String,
    /// May rotate on Android.
    pub ble_address: String,
    pub rssi: i16,
    pub protocol: PeerProtocol,
    pub connected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PeerProtocol {
    Ratspeak,
    Columba,
}

/// Surfaces as `ble_peer_*` events for embedding UIs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlePeerEvent {
    Discovered {
        address: String,
        rssi: i16,
        protocol: PeerProtocol,
    },
    Connected {
        address: String,
        identity_hash: String,
        protocol: PeerProtocol,
    },
    Disconnected {
        address: String,
        reason: String,
    },
    /// Notify pipe wired — subscribed-to-TX completed on either side.
    /// Embedding UIs can fire an immediate announce on this so identity
    /// exchange happens on first contact rather than waiting for auto-announce.
    SubscribeReady {
        address: String,
    },
    /// Identity hash learned from the first signed Reticulum announce.
    /// Used to dedup peers across central+peripheral roles where the BLE
    /// address differs for the same physical device — notably on Apple,
    /// where `CBPeripheral.identifier` vs `CBCentral.identifier` don't
    /// match without bonding.
    IdentityResolved {
        address: String,
        identity_hash: String,
    },
    RssiUpdate {
        address: String,
        rssi: i16,
    },
    /// Peripheral role failed to start (e.g. Windows without packaged-app
    /// identity). Mesh continues central-only.
    PeripheralUnavailable {
        reason: String,
    },
    StatusChanged {
        state: PeerState,
        peer_count: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    Off,
    Starting,
    On,
    PermissionNeeded,
    BluetoothOff,
    Unavailable,
}

/// Lets sync JNI/ObjC callbacks publish without threading senders through
/// every site. Replaced at each spawn.
static EVENT_DISPATCH: std::sync::OnceLock<std::sync::RwLock<Option<mpsc::Sender<BlePeerEvent>>>> =
    std::sync::OnceLock::new();

fn event_dispatch_slot() -> &'static std::sync::RwLock<Option<mpsc::Sender<BlePeerEvent>>> {
    EVENT_DISPATCH.get_or_init(|| std::sync::RwLock::new(None))
}

/// Replaces any previous installation.
pub fn install_event_dispatcher(tx: mpsc::Sender<BlePeerEvent>) {
    if let Ok(mut slot) = event_dispatch_slot().write() {
        *slot = Some(tx);
    }
}

pub fn clear_event_dispatcher() {
    if let Ok(mut slot) = event_dispatch_slot().write() {
        *slot = None;
    }
}

/// `try_send` — sync callbacks must not block. A drop here means the relay
/// channel is full, which on tight Rust scan loops (Windows central path)
/// can happen during burst events. Log so we see it instead of state silently
/// going stale (e.g. UI stuck "Scanning…" because a Connected was dropped).
pub(crate) fn dispatch_event(event: BlePeerEvent) {
    if let Ok(slot) = event_dispatch_slot().read() {
        if let Some(tx) = slot.as_ref() {
            if let Err(e) = tx.try_send(event) {
                tracing::warn!(
                    error = %e,
                    "BLE peer event dispatch dropped — relay channel full or closed"
                );
            }
        }
    }
}

fn peer_state_for_count(peer_count: usize) -> PeerState {
    if peer_count > 0 {
        PeerState::On
    } else {
        PeerState::Starting
    }
}

fn dispatch_status_changed(state: PeerState, peer_count: usize) {
    // Keep the transport-shared online flag in step with real interface state
    // so a dead/Off/BluetoothOff radio stops being handed outbound packets.
    interface_online_flag().store(
        matches!(state, PeerState::On | PeerState::Starting),
        Ordering::SeqCst,
    );
    dispatch_event(BlePeerEvent::StatusChanged { state, peer_count });
}

/// `false` means the radio truly stops, not just the TX channel dropping.
static BLE_PEER_RUNNING: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

pub(crate) fn running_flag() -> Arc<AtomicBool> {
    BLE_PEER_RUNNING
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

/// Shared with the transport actor as the interface's `online` flag. Tracks
/// real operational state (via [`dispatch_status_changed`]) rather than
/// staying `true` forever, and is what Halt/Resume toggles. Distinct from
/// `running_flag` (session lifecycle) so a Halt doesn't tear down the loops.
static BLE_PEER_ONLINE: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

fn interface_online_flag() -> Arc<AtomicBool> {
    BLE_PEER_ONLINE
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

static BLE_PEER_GENERATION: std::sync::OnceLock<AtomicU64> = std::sync::OnceLock::new();
type BlePeerChildTask = (u64, tokio::task::JoinHandle<()>);
type BlePeerChildTasks = std::sync::Mutex<Vec<BlePeerChildTask>>;
static BLE_PEER_CHILD_TASKS: std::sync::OnceLock<BlePeerChildTasks> = std::sync::OnceLock::new();

fn generation_counter() -> &'static AtomicU64 {
    BLE_PEER_GENERATION.get_or_init(|| AtomicU64::new(0))
}

fn child_tasks() -> &'static BlePeerChildTasks {
    BLE_PEER_CHILD_TASKS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

fn begin_ble_peer_session() -> u64 {
    let generation = generation_counter().fetch_add(1, Ordering::SeqCst) + 1;
    running_flag().store(true, Ordering::SeqCst);
    generation
}

fn invalidate_ble_peer_session() -> u64 {
    running_flag().store(false, Ordering::SeqCst);
    generation_counter().fetch_add(1, Ordering::SeqCst) + 1
}

fn generation_is_current(generation: u64) -> bool {
    running_flag().load(Ordering::SeqCst)
        && generation_counter().load(Ordering::SeqCst) == generation
}

fn track_child_task(generation: u64, handle: tokio::task::JoinHandle<()>) {
    if let Ok(mut tasks) = child_tasks().lock() {
        tasks.push((generation, handle));
    } else {
        handle.abort();
    }
}

fn abort_ble_peer_child_tasks() {
    if let Ok(mut tasks) = child_tasks().lock() {
        for (_, task) in tasks.drain(..) {
            task.abort();
        }
    }
}

async fn stop_central_connections() {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    crate::ble_central_apple_connect::disconnect_all();

    #[cfg(target_os = "android")]
    android_peripheral::peer_client_disconnect_all();

    #[cfg(all(
        feature = "ble",
        not(any(target_os = "android", target_os = "ios", target_os = "macos"))
    ))]
    disconnect_central_peripherals().await;
}

/// Caller must still `DeregisterInterface` on the transport actor to drop
/// paths + remove the interface entry.
pub async fn stop_ble_peer_interface() {
    tracing::info!("stop_ble_peer_interface: signalling shutdown + stopping peripheral");
    let generation = invalidate_ble_peer_session();
    stop_central_connections().await;
    abort_ble_peer_child_tasks();

    // A scan aborted mid-cycle leaves the Apple central lifecycle stuck in
    // Scanning, so the next enable's start_scan is rejected and the central
    // role stays dead until process restart. Reset it here — stop_scan is a
    // no-op when already idle and keeps the manager alive for reuse (releasing
    // it per-toggle trips the macOS alloc-cycle Unsupported bug).
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    if let Err(e) = crate::ble_central_apple::stop_scan().await {
        tracing::warn!(error = %e, "BLE peer: apple central stop_scan during teardown");
    }

    if let Err(e) = stop_peripheral().await {
        tracing::warn!(error = %e, "BLE peer: stop_peripheral failed during teardown");
    } else {
        tracing::info!("stop_ble_peer_interface: peripheral stopped");
    }
    dispatch_status_changed(PeerState::Off, 0);
    clear_event_dispatcher();
    tracing::info!(generation, "stop_ble_peer_interface: done");
}

#[derive(Debug, Clone)]
pub struct BlePeerConfig {
    pub name: String,
    /// 16-byte Reticulum identity hash for this node.
    pub identity_hash: Vec<u8>,
    pub mode: InterfaceMode,
}

impl BlePeerConfig {
    pub fn new(name: &str, identity_hash: Vec<u8>) -> Self {
        Self {
            name: name.to_string(),
            identity_hash,
            mode: InterfaceMode::Full,
        }
    }
}

const FRAGMENT_HEADER_LEN: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FragmentHeader {
    kind: FragmentType,
    seq: u16,
    total: u16,
}

type FragmentReassembly = HashMap<u16, (Vec<Option<Vec<u8>>>, Instant)>;

fn raw_packet_needs_fragment_envelope(data: &[u8]) -> bool {
    matches!(
        data.first().copied(),
        Some(x)
            if x == FragmentType::Start as u8
                || x == FragmentType::Continue as u8
                || x == FragmentType::End as u8
    )
}

fn make_fragment(kind: FragmentType, seq: u16, total: u16, payload: &[u8]) -> Vec<u8> {
    let mut frag = Vec::with_capacity(FRAGMENT_HEADER_LEN + payload.len());
    frag.push(kind as u8);
    frag.extend_from_slice(&seq.to_be_bytes());
    frag.extend_from_slice(&total.to_be_bytes());
    frag.extend_from_slice(payload);
    frag
}

fn parse_fragment_header(data: &[u8]) -> Option<FragmentHeader> {
    if data.len() < FRAGMENT_HEADER_LEN {
        return None;
    }

    let kind = FragmentType::from_byte(data[0])?;
    if kind == FragmentType::Lone {
        // Reticulum DATA packets commonly start with 0x00. This transport no
        // longer emits explicit LONE frames, so preserve 0x00 as legacy raw
        // packet data and only parse START/CONTINUE/END envelopes.
        return None;
    }

    let seq = u16::from_be_bytes([data[1], data[2]]);
    let total = u16::from_be_bytes([data[3], data[4]]);
    if total == 0 || total > MAX_FRAGMENTS || seq >= total {
        return None;
    }

    let valid = match kind {
        FragmentType::Lone => false,
        FragmentType::Start => seq == 0 && total >= 2,
        FragmentType::Continue => total >= 3 && seq > 0 && seq < total - 1,
        FragmentType::End => total >= 2 && seq == total - 1,
    };
    valid.then_some(FragmentHeader { kind, seq, total })
}

pub fn fragment_packet(data: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    let payload_mtu = mtu.saturating_sub(FRAGMENT_HEADER_LEN);
    if payload_mtu == 0 {
        return vec![data.to_vec()];
    }

    // Raw packets beginning with 0x01/0x02/0x03 collide with START/CONTINUE/END
    // frame tags. Direct LXMF LinkRequests are Header1 packets whose first byte
    // is 0x02, so they must be enveloped even when they fit in a single ATT
    // write. Use a two-frame START/END sequence instead of a LONE frame so
    // peers with the older reassembler can still decode the packet.
    if data.len() <= mtu.saturating_sub(3) && !raw_packet_needs_fragment_envelope(data) {
        return vec![data.to_vec()];
    }

    let chunks: Vec<&[u8]> = data.chunks(payload_mtu).collect();
    if chunks.len() == 1 {
        return vec![
            make_fragment(FragmentType::Start, 0, 2, chunks[0]),
            make_fragment(FragmentType::End, 1, 2, &[]),
        ];
    }

    let total = chunks.len() as u16;
    let mut fragments = Vec::with_capacity(chunks.len());

    for (i, chunk) in chunks.iter().enumerate() {
        let ftype = if i == 0 {
            FragmentType::Start
        } else if i == chunks.len() - 1 {
            FragmentType::End
        } else {
            FragmentType::Continue
        };

        let seq = i as u16;
        fragments.push(make_fragment(ftype, seq, total, chunk));
    }

    fragments
}

pub fn reassemble_fragments(fragments: &[Vec<u8>]) -> Option<Vec<u8>> {
    if fragments.is_empty() {
        return None;
    }

    let mut total: Option<u16> = None;
    let mut parts: Vec<Option<&[u8]>> = Vec::new();
    for frag in fragments {
        let header = parse_fragment_header(frag)?;
        if total.is_some_and(|expected| expected != header.total) {
            return None;
        }
        if total.is_none() {
            total = Some(header.total);
            parts.resize(header.total as usize, None);
        }
        let slot = parts.get_mut(header.seq as usize)?;
        if slot.is_some() {
            return None;
        }
        *slot = Some(&frag[FRAGMENT_HEADER_LEN..]);
    }

    let mut result = Vec::new();
    for part in parts {
        result.extend_from_slice(part?);
    }
    Some(result)
}

fn consume_ble_frame(data: Vec<u8>, reassembly: &mut FragmentReassembly) -> Option<Vec<u8>> {
    let Some(header) = parse_fragment_header(&data) else {
        return Some(data);
    };

    if header.kind != FragmentType::Start && !reassembly.contains_key(&header.total) {
        // CONTINUE/END cannot begin a real fragment set on an ordered BLE
        // characteristic. Treat it as a legacy raw Reticulum packet instead;
        // this lets updated receivers accept old raw Header1 LinkRequest
        // packets that begin with 0x02 when no matching START was observed.
        return Some(data);
    }

    if header.kind == FragmentType::Start {
        reassembly.insert(
            header.total,
            (vec![None; header.total as usize], Instant::now()),
        );
    }

    let entry = reassembly
        .entry(header.total)
        .or_insert_with(|| (vec![None; header.total as usize], Instant::now()));
    if entry.0.len() != header.total as usize {
        entry.0 = vec![None; header.total as usize];
        entry.1 = Instant::now();
    }
    entry.0[header.seq as usize] = Some(data[FRAGMENT_HEADER_LEN..].to_vec());

    if header.kind != FragmentType::End {
        return None;
    }

    if entry.0.iter().any(|part| part.is_none()) {
        return None;
    }
    let (parts, _) = reassembly.remove(&header.total)?;
    let mut result = Vec::new();
    for part in parts {
        result.extend_from_slice(&part?);
    }
    Some(result)
}

fn prune_reassembly(reassembly: &mut FragmentReassembly) {
    reassembly.retain(|_, (_, started)| started.elapsed() < FRAGMENT_TIMEOUT);
}

/// 60s positive-ID cache for the btleplug scan path. WinRT's advertisement
/// parse is empirically eventually-consistent: the same iOS RPA can yield
/// services_count=1 in one 3s scan window and 0 in the next, even when iOS
/// is broadcasting continuously. Once we've classified an address as
/// Ratspeak/Columba, remembering it for a TTL > the inter-scan gap means a
/// flaky parse on the next sighting doesn't kick the peer out of recognition.
/// 60s is comfortably less than iOS's ~15-minute RPA rotation window, so
/// stale entries can't false-positive a different device.
#[cfg(all(feature = "ble", not(any(target_os = "ios", target_os = "macos"))))]
const RECENT_PEER_TTL: Duration = Duration::from_secs(60);

#[cfg(all(feature = "ble", not(any(target_os = "ios", target_os = "macos"))))]
fn recent_ratspeak_cache() -> &'static std::sync::Mutex<HashMap<String, (Instant, PeerProtocol)>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, (Instant, PeerProtocol)>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

#[cfg(all(feature = "ble", not(any(target_os = "ios", target_os = "macos"))))]
fn recent_ratspeak_remember(address: &str, protocol: PeerProtocol) {
    if let Ok(mut cache) = recent_ratspeak_cache().lock() {
        cache.insert(address.to_string(), (Instant::now(), protocol));
    }
}

#[cfg(all(feature = "ble", not(any(target_os = "ios", target_os = "macos"))))]
fn recent_ratspeak_lookup(address: &str) -> Option<PeerProtocol> {
    let cache = recent_ratspeak_cache().lock().ok()?;
    let (seen_at, protocol) = cache.get(address)?;
    if seen_at.elapsed() < RECENT_PEER_TTL {
        Some(*protocol)
    } else {
        None
    }
}

#[cfg(all(feature = "ble", not(any(target_os = "ios", target_os = "macos"))))]
fn recent_ratspeak_prune() {
    if let Ok(mut cache) = recent_ratspeak_cache().lock() {
        cache.retain(|_, (t, _)| t.elapsed() < RECENT_PEER_TTL);
    }
}

// Apple goes through `crate::ble_central_apple` for `AllowDuplicatesKey=YES`
// (btleplug doesn't expose it, so peers "disappear" after a couple minutes).
// Linux/Windows/Android stay on btleplug.

/// Scan for BLE mesh peers advertising Ratspeak or Columba.
///
/// Creates a fresh btleplug adapter, so use this only for scan-only callers.
/// Scan-then-connect flows must use [`scan_mesh_peers_shared`] with the same
/// adapter they later pass to `connect_mesh_peer`; btleplug adapter instances
/// do not share peripheral registries.
///
/// Safe entry point for one-off scan-only callers and the Apple branch
/// (which uses the native CoreBluetooth path).
pub async fn scan_mesh_peers(timeout_secs: u64) -> Result<Vec<BlePeer>, String> {
    #[cfg(all(feature = "ble", any(target_os = "ios", target_os = "macos")))]
    {
        apple_scan_mesh_peers(timeout_secs).await
    }

    #[cfg(all(feature = "ble", not(any(target_os = "ios", target_os = "macos"))))]
    {
        // On Android, btleplug must be initialized or global_adapter() will panic.
        #[cfg(target_os = "android")]
        if !crate::ble_rnode::is_btleplug_initialized() {
            return Err(
                "BLE not initialized on Android — grant Bluetooth permissions and restart".into(),
            );
        }

        use btleplug::api::Manager as _;
        use btleplug::platform::Manager;

        let manager = Manager::new()
            .await
            .map_err(|e| format!("BLE manager init failed: {e}"))?;
        let adapters = manager
            .adapters()
            .await
            .map_err(|e| format!("No BLE adapters: {e}"))?;
        let adapter = adapters.into_iter().next().ok_or("No BLE adapter found")?;
        return scan_mesh_peers_shared(&adapter, timeout_secs).await;
    }

    #[cfg(not(feature = "ble"))]
    Err("BLE feature not enabled".into())
}

/// Scan for BLE mesh peers using a caller-provided adapter.
///
/// Scan with the adapter that will also be used for connect.
#[cfg(all(feature = "ble", not(any(target_os = "ios", target_os = "macos"))))]
pub async fn scan_mesh_peers_shared(
    adapter: &btleplug::platform::Adapter,
    timeout_secs: u64,
) -> Result<Vec<BlePeer>, String> {
    use btleplug::api::{Central, Peripheral as _, ScanFilter};

    // WinRT UUID filters miss real advertisements on common chipsets. Scan
    // unfiltered and classify service UUIDs ourselves so discovery is visible.
    adapter
        .start_scan(ScanFilter::default())
        .await
        .map_err(|e| format!("Scan failed: {e}"))?;

    tokio::time::sleep(Duration::from_secs(timeout_secs)).await;
    adapter.stop_scan().await.ok();

    let peripherals = adapter
        .peripherals()
        .await
        .map_err(|e| format!("Peripheral list failed: {e}"))?;

    recent_ratspeak_prune();

    let mut peers = Vec::new();
    for p in peripherals {
        let Ok(Some(props)) = p.properties().await else {
            continue;
        };
        // RSSI is display-only here. BlueZ/WinRT often omit RSSI on cached
        // peripherals, and service UUID plus link watchdogs are the real gates.
        // -100 is a UI sentinel for "Unknown".
        let rssi = props.rssi.unwrap_or(-100);
        let address_str = props.address.to_string();

        // WinRT populates `services` from the parsed advertisement payload,
        // but its parse is eventually-consistent and frequently empty.
        // `service_data` keys come from a separate parse path that often
        // succeeds when `services` is empty. Check both.
        let saw_ratspeak_now = props.services.contains(&RATSPEAK_SERVICE_UUID)
            || props.service_data.contains_key(&RATSPEAK_SERVICE_UUID);
        let saw_columba_now = props.services.contains(&COLUMBA_SERVICE_UUID)
            || props.service_data.contains_key(&COLUMBA_SERVICE_UUID);

        if saw_ratspeak_now || saw_columba_now {
            let proto = if saw_ratspeak_now {
                PeerProtocol::Ratspeak
            } else {
                PeerProtocol::Columba
            };
            recent_ratspeak_remember(&address_str, proto);
        }
        let cached = recent_ratspeak_lookup(&address_str);
        let saw_ratspeak = saw_ratspeak_now || cached == Some(PeerProtocol::Ratspeak);
        let saw_columba = saw_columba_now || cached == Some(PeerProtocol::Columba);
        let from_cache = !saw_ratspeak_now && !saw_columba_now && cached.is_some();

        tracing::info!(
            target: "ble_trace",
            step = "scan.peripheral_seen",
            address = %props.address,
            rssi,
            services_count = props.services.len(),
            service_data_keys = props.service_data.len(),
            saw_ratspeak,
            saw_columba,
            from_cache,
            local_name = ?props.local_name,
            "BLE scan peripheral seen"
        );

        // No RSSI floor — see the comment above where `rssi` is
        // captured. The UUID match below is the only connection gate.
        if !saw_ratspeak && !saw_columba {
            continue;
        }

        peers.push(BlePeer {
            // Identity is learned from the first signed announce.
            identity_hash: String::new(),
            ble_address: address_str,
            rssi,
            protocol: if saw_ratspeak {
                PeerProtocol::Ratspeak
            } else {
                PeerProtocol::Columba
            },
            connected: false,
        });
    }
    Ok(peers)
}

/// Dedupes by peripheral identifier, keeps strongest RSSI.
#[cfg(all(feature = "ble", any(target_os = "ios", target_os = "macos")))]
async fn apple_scan_mesh_peers(timeout_secs: u64) -> Result<Vec<BlePeer>, String> {
    use crate::ble_central_apple;

    let services = vec![RATSPEAK_SERVICE_UUID, COLUMBA_SERVICE_UUID];
    let mut rx = ble_central_apple::start_scan(services).await?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut seen: HashMap<String, BlePeer> = HashMap::new();

    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let event = match tokio::time::timeout(remaining, rx.recv()).await {
            Err(_) | Ok(None) => break,
            Ok(Some(ev)) => ev,
        };
        merge_sighting(&mut seen, event);
    }

    // Best-effort — lifecycle rewinds on next toggle if this fails.
    if let Err(e) = ble_central_apple::stop_scan().await {
        tracing::warn!("Apple BLE scan teardown warning: {e}");
    }

    let peers: Vec<BlePeer> = seen.into_values().collect();
    tracing::info!(
        target: "ble_trace",
        step = "scan.cycle_summary",
        peer_count = peers.len(),
        peers = ?peers.iter().map(|p| format!("{}@{}dBm/{:?}", p.ble_address, p.rssi, p.protocol)).collect::<Vec<_>>(),
        "Apple BLE scan cycle complete"
    );
    Ok(peers)
}

/// Drops weaker-than-[`MIN_RSSI`]; keeps strongest RSSI per peer; upgrades
/// Columba → Ratspeak but never the reverse. Used by Apple's
/// `apple_scan_mesh_peers` (Apple-only) and by `sighting_tests` (all
/// platforms when `cfg(test, feature = "ble")`); on a Linux/Windows
/// release build neither caller is compiled, so the compiler reports
/// it dead — the allow keeps the function available for both contexts.
#[cfg(feature = "ble")]
#[allow(dead_code)]
fn merge_sighting(
    seen: &mut HashMap<String, BlePeer>,
    event: crate::ble_central_lifecycle::DiscoveryEvent,
) {
    use crate::ble_central_lifecycle::AdvertisedProtocol;

    if event.rssi < MIN_RSSI {
        return;
    }
    let protocol = match event.protocol {
        AdvertisedProtocol::Ratspeak => PeerProtocol::Ratspeak,
        AdvertisedProtocol::Columba => PeerProtocol::Columba,
    };
    seen.entry(event.identifier.clone())
        .and_modify(|p| {
            if event.rssi > p.rssi {
                p.rssi = event.rssi;
            }
            if matches!(protocol, PeerProtocol::Ratspeak) {
                p.protocol = PeerProtocol::Ratspeak;
            }
        })
        .or_insert_with(|| BlePeer {
            // Identity is learned from the first signed announce after a
            // GATT link opens.
            identity_hash: String::new(),
            ble_address: event.identifier.clone(),
            rssi: event.rssi,
            protocol,
            connected: false,
        });
}

#[cfg(all(test, feature = "ble"))]
mod sighting_tests {
    use super::*;
    use crate::ble_central_lifecycle::{AdvertisedProtocol, DiscoveryEvent};
    use std::time::Instant;

    fn mk(
        ident: &str,
        rssi: i16,
        protocol: AdvertisedProtocol,
        services: Vec<Uuid>,
    ) -> DiscoveryEvent {
        DiscoveryEvent {
            identifier: ident.into(),
            rssi,
            services,
            protocol,
            seen_at: Instant::now(),
        }
    }

    #[test]
    fn empty_input_produces_empty_map() {
        let seen: HashMap<String, BlePeer> = HashMap::new();
        assert_eq!(seen.len(), 0);
    }

    #[test]
    fn single_ratspeak_sighting_is_inserted() {
        let mut seen = HashMap::new();
        merge_sighting(
            &mut seen,
            mk(
                "AABB",
                -60,
                AdvertisedProtocol::Ratspeak,
                vec![RATSPEAK_SERVICE_UUID],
            ),
        );
        assert_eq!(seen.len(), 1);
        let p = seen.get("AABB").unwrap();
        assert_eq!(p.ble_address, "AABB");
        assert_eq!(p.rssi, -60);
        assert_eq!(p.protocol, PeerProtocol::Ratspeak);
        assert!(!p.connected);
        assert!(p.identity_hash.is_empty());
    }

    #[test]
    fn below_min_rssi_is_dropped() {
        let mut seen = HashMap::new();
        merge_sighting(
            &mut seen,
            mk(
                "AABB",
                MIN_RSSI - 1,
                AdvertisedProtocol::Ratspeak,
                vec![RATSPEAK_SERVICE_UUID],
            ),
        );
        assert!(seen.is_empty(), "weak sighting must not produce a peer");
    }

    #[test]
    fn rssi_strengthens_on_subsequent_sighting() {
        let mut seen = HashMap::new();
        merge_sighting(
            &mut seen,
            mk(
                "AABB",
                -80,
                AdvertisedProtocol::Ratspeak,
                vec![RATSPEAK_SERVICE_UUID],
            ),
        );
        merge_sighting(
            &mut seen,
            mk(
                "AABB",
                -55,
                AdvertisedProtocol::Ratspeak,
                vec![RATSPEAK_SERVICE_UUID],
            ),
        );
        assert_eq!(seen.get("AABB").unwrap().rssi, -55);
    }

    #[test]
    fn rssi_does_not_weaken_on_subsequent_sighting() {
        let mut seen = HashMap::new();
        merge_sighting(
            &mut seen,
            mk(
                "AABB",
                -55,
                AdvertisedProtocol::Ratspeak,
                vec![RATSPEAK_SERVICE_UUID],
            ),
        );
        merge_sighting(
            &mut seen,
            mk(
                "AABB",
                -85,
                AdvertisedProtocol::Ratspeak,
                vec![RATSPEAK_SERVICE_UUID],
            ),
        );
        assert_eq!(
            seen.get("AABB").unwrap().rssi,
            -55,
            "strongest RSSI must stick even after a weaker sighting"
        );
    }

    #[test]
    fn columba_upgrades_to_ratspeak_when_both_seen() {
        let mut seen = HashMap::new();
        merge_sighting(
            &mut seen,
            mk(
                "AABB",
                -60,
                AdvertisedProtocol::Columba,
                vec![COLUMBA_SERVICE_UUID],
            ),
        );
        assert_eq!(seen.get("AABB").unwrap().protocol, PeerProtocol::Columba);
        merge_sighting(
            &mut seen,
            mk(
                "AABB",
                -60,
                AdvertisedProtocol::Ratspeak,
                vec![RATSPEAK_SERVICE_UUID],
            ),
        );
        assert_eq!(
            seen.get("AABB").unwrap().protocol,
            PeerProtocol::Ratspeak,
            "full Ratspeak protocol must win once advertised"
        );
    }

    #[test]
    fn ratspeak_does_not_downgrade_to_columba() {
        let mut seen = HashMap::new();
        merge_sighting(
            &mut seen,
            mk(
                "AABB",
                -60,
                AdvertisedProtocol::Ratspeak,
                vec![RATSPEAK_SERVICE_UUID],
            ),
        );
        merge_sighting(
            &mut seen,
            mk(
                "AABB",
                -60,
                AdvertisedProtocol::Columba,
                vec![COLUMBA_SERVICE_UUID],
            ),
        );
        assert_eq!(seen.get("AABB").unwrap().protocol, PeerProtocol::Ratspeak);
    }

    #[test]
    fn distinct_peers_each_get_their_own_entry() {
        let mut seen = HashMap::new();
        merge_sighting(
            &mut seen,
            mk(
                "AABB",
                -55,
                AdvertisedProtocol::Ratspeak,
                vec![RATSPEAK_SERVICE_UUID],
            ),
        );
        merge_sighting(
            &mut seen,
            mk(
                "CCDD",
                -70,
                AdvertisedProtocol::Columba,
                vec![COLUMBA_SERVICE_UUID],
            ),
        );
        assert_eq!(seen.len(), 2);
        assert_eq!(seen.get("AABB").unwrap().protocol, PeerProtocol::Ratspeak);
        assert_eq!(seen.get("CCDD").unwrap().protocol, PeerProtocol::Columba);
    }

    #[test]
    fn at_exact_min_rssi_threshold_peer_is_kept() {
        let mut seen = HashMap::new();
        merge_sighting(
            &mut seen,
            mk(
                "AABB",
                MIN_RSSI,
                AdvertisedProtocol::Ratspeak,
                vec![RATSPEAK_SERVICE_UUID],
            ),
        );
        assert_eq!(seen.len(), 1, "peer at exactly MIN_RSSI must be kept");
    }
}

/// Called from `JNI_OnLoad`.
#[cfg(target_os = "android")]
pub fn init_android_jvm(vm: jni::JavaVM) {
    android_peripheral::init_jvm(vm);
}

pub async fn start_peripheral(_identity_hash: &[u8]) -> Result<(), String> {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        return apple_peripheral::start_advertising(_identity_hash).await;
    }

    #[cfg(target_os = "android")]
    {
        return android_peripheral::start_advertising(_identity_hash).await;
    }

    #[cfg(target_os = "linux")]
    {
        return linux_peripheral::start_advertising(_identity_hash).await;
    }

    #[cfg(target_os = "windows")]
    {
        return windows_peripheral::start_advertising(_identity_hash).await;
    }

    #[cfg(not(any(
        target_os = "ios",
        target_os = "macos",
        target_os = "android",
        target_os = "linux",
        target_os = "windows"
    )))]
    {
        tracing::warn!("BLE Peripheral not available on this platform");
        Err("BLE Peripheral not supported on this platform".into())
    }
}

pub async fn stop_peripheral() -> Result<(), String> {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        apple_peripheral::stop_advertising().await
    }

    #[cfg(target_os = "android")]
    {
        android_peripheral::stop_advertising().await
    }

    #[cfg(target_os = "linux")]
    {
        linux_peripheral::stop_advertising().await
    }

    #[cfg(target_os = "windows")]
    {
        windows_peripheral::stop_advertising().await
    }

    #[cfg(not(any(
        target_os = "ios",
        target_os = "macos",
        target_os = "android",
        target_os = "linux",
        target_os = "windows"
    )))]
    {
        Ok(())
    }
}

// Apple peripheral (CBPeripheralManager). State restoration is iOS-specific;
// macOS doesn't suspend processes the same way, so cold-rescan works there.

/// Funnels into the GATT-server reassembler so both directions share
/// reassembly state.
#[cfg(any(target_os = "ios", target_os = "macos"))]
pub(crate) fn try_push_apple_inbound(peer: String, data: Vec<u8>) -> bool {
    apple_peripheral::try_push_inbound(peer, data)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod apple_peripheral {
    use super::*;
    use objc2::runtime::{AnyClass, AnyObject, ClassBuilder, Sel};
    use objc2::{msg_send, sel};
    use objc2_foundation::NSString;
    use std::sync::OnceLock;

    /// 256 × ~200B ≈ 50KB — absorbs an LXMF burst (~40 frags) without OOM.
    const INBOUND_CAPACITY: usize = 256;

    type InboundFrame = (String, Vec<u8>);
    type InboundSender = tokio::sync::mpsc::Sender<InboundFrame>;
    type InboundReceiver = tokio::sync::mpsc::Receiver<InboundFrame>;

    /// `peer_id` is `CBCentral.identifier.UUIDString` (or empty if unknown).
    static INBOUND_TX: OnceLock<std::sync::Mutex<Option<InboundSender>>> = OnceLock::new();
    static INBOUND_RX: OnceLock<std::sync::Mutex<Option<InboundReceiver>>> = OnceLock::new();

    fn inbound_tx_slot() -> &'static std::sync::Mutex<Option<InboundSender>> {
        INBOUND_TX.get_or_init(|| std::sync::Mutex::new(None))
    }

    fn inbound_rx_slot() -> &'static std::sync::Mutex<Option<InboundReceiver>> {
        INBOUND_RX.get_or_init(|| std::sync::Mutex::new(None))
    }

    fn reset_inbound_channel() {
        let (tx, rx) = tokio::sync::mpsc::channel::<InboundFrame>(INBOUND_CAPACITY);
        if let Ok(mut slot) = inbound_tx_slot().lock() {
            *slot = Some(tx);
        }
        if let Ok(mut slot) = inbound_rx_slot().lock() {
            *slot = Some(rx);
        }
    }

    fn clear_inbound_channel() {
        if let Ok(mut slot) = inbound_tx_slot().lock() {
            *slot = None;
        }
        if let Ok(mut slot) = inbound_rx_slot().lock() {
            *slot = None;
        }
    }

    fn inbound_sender() -> Option<InboundSender> {
        inbound_tx_slot()
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().cloned())
    }

    pub fn take_inbound_rx() -> Option<tokio::sync::mpsc::Receiver<(String, Vec<u8>)>> {
        inbound_rx_slot().lock().ok().and_then(|mut opt| opt.take())
    }

    pub(super) fn try_push_inbound(peer: String, data: Vec<u8>) -> bool {
        inbound_sender().is_some_and(|tx| tx.try_send((peer, data)).is_ok())
    }

    struct SendPtr(*mut AnyObject);
    unsafe impl Send for SendPtr {}
    unsafe impl Sync for SendPtr {}
    static MANAGER_PTR: OnceLock<std::sync::Mutex<SendPtr>> = OnceLock::new();

    /// The `OnceLock` can only be initialized once, so hold the manager pointer
    /// behind interior mutability — otherwise `set()` on a second enable cycle
    /// is a silent no-op, stranding notify_tx on the old (torn-down) manager
    /// and leaving the new one advertising unstoppably.
    fn manager_ptr_slot() -> &'static std::sync::Mutex<SendPtr> {
        MANAGER_PTR.get_or_init(|| std::sync::Mutex::new(SendPtr(std::ptr::null_mut())))
    }

    /// Installs a freshly-constructed manager, tearing down any predecessor
    /// that was never stopped (an enable without an intervening disable) so it
    /// can't keep advertising after we've replaced it.
    fn set_manager_ptr(mgr_raw: *mut AnyObject) {
        let mut guard = manager_ptr_slot()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = guard.0;
        *guard = SendPtr(mgr_raw);
        drop(guard);
        if !prev.is_null() {
            tracing::warn!("iOS BLE Peripheral: replacing a live manager ptr without teardown");
            unsafe {
                let _: () = msg_send![prev, stopAdvertising];
                let _: () = msg_send![prev, setDelegate: std::ptr::null::<AnyObject>()];
                let _: () = msg_send![prev, release];
            }
        }
    }
    static DELEGATE_CLASS: OnceLock<&'static AnyClass> = OnceLock::new();

    static LIFECYCLE: OnceLock<crate::ble_peer_lifecycle::PeripheralLifecycle> = OnceLock::new();

    fn lifecycle() -> &'static crate::ble_peer_lifecycle::PeripheralLifecycle {
        LIFECYCLE.get_or_init(crate::ble_peer_lifecycle::PeripheralLifecycle::new)
    }

    /// Trace invalid transitions instead of panicking — BLE stacks deliver
    /// out-of-order callbacks occasionally.
    fn apply_event(
        event: crate::ble_peer_lifecycle::LifecycleEvent,
    ) -> Option<crate::ble_peer_lifecycle::PeripheralState> {
        match lifecycle().apply(event.clone()) {
            Ok(state) => {
                tracing::trace!(?event, ?state, "Apple BLE lifecycle");
                Some(state)
            }
            Err(err) => {
                tracing::warn!(?err, "Apple BLE lifecycle: rejected transition");
                None
            }
        }
    }

    /// Must stay stable across updates; changing forfeits
    /// previously-backgrounded GATT subscriptions.
    const PERIPHERAL_RESTORE_ID: &str = "org.ratspeak.ios.peripheral";

    // objc2-core-bluetooth 0.2.2 only exports the central-role keys; link
    // the peripheral-role NSString constants directly.
    #[link(name = "CoreBluetooth", kind = "framework")]
    unsafe extern "C" {
        static CBPeripheralManagerOptionRestoreIdentifierKey: &'static NSString;
        static CBPeripheralManagerRestoredStateServicesKey: &'static NSString;
        static CBPeripheralManagerRestoredStateAdvertisementDataKey: &'static NSString;
    }

    /// Ratspeak primary + Columba compat.
    const EXPECTED_SERVICE_COUNT: usize = 2;

    /// Reset on each start/stop so cycles don't leak stale acks.
    static SERVICES_ADDED_COUNT: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// Cleared by `stop_advertising` so a later PoweredOn recovery doesn't
    /// silently re-advertise after the user disabled BLE Mesh.
    static LAST_IDENTITY_HASH: OnceLock<std::sync::Mutex<Option<Vec<u8>>>> = OnceLock::new();

    fn last_identity_hash() -> &'static std::sync::Mutex<Option<Vec<u8>>> {
        LAST_IDENTITY_HASH.get_or_init(|| std::sync::Mutex::new(None))
    }

    fn cb_state_name(state: i64) -> &'static str {
        match state {
            0 => "Unknown",
            1 => "Resetting",
            2 => "Unsupported",
            3 => "Unauthorized",
            4 => "PoweredOff",
            5 => "PoweredOn",
            _ => "UnknownVariant",
        }
    }

    /// CB disconnects all centrals on PoweredOff but `didUnsubscribe`
    /// doesn't fire reliably across the transition — drain defensively.
    fn clear_subscribed_centrals_for_recovery() {
        if let Ok(mut map) = subscribed_centrals_map().lock() {
            for (_, ptr) in map.drain() {
                if !ptr.0.is_null() {
                    unsafe {
                        let _: () = msg_send![ptr.0, release];
                    }
                }
            }
        }
        if let Ok(mut map) = central_subscribed_chars_map().lock() {
            map.clear();
        }
    }

    fn drain_characteristic_registry() {
        if let Ok(mut map) = characteristic_registry().lock() {
            for (_, ptr) in map.drain() {
                if !ptr.0.is_null() {
                    unsafe {
                        let _: () = msg_send![ptr.0, release];
                    }
                }
            }
        }
    }

    /// Must be stashed BEFORE manager construction so the first `PoweredOn`
    /// delegate callback (which races the worker thread) finds it. Calling
    /// `addService:` / `startAdvertising:` before PoweredOn is silently a
    /// no-op in CB.
    struct PendingAdvertise {
        identity_hash: Vec<u8>,
    }
    static PENDING_ADVERTISE: OnceLock<std::sync::Mutex<Option<PendingAdvertise>>> =
        OnceLock::new();

    fn pending_advertise() -> &'static std::sync::Mutex<Option<PendingAdvertise>> {
        PENDING_ADVERTISE.get_or_init(|| std::sync::Mutex::new(None))
    }

    /// The worker (not the delegate) runs `register_services_and_advertise`
    /// because objc2's debug class-verify panics when `msg_send` runs from
    /// CB's main dispatch queue in delegate context.
    static POWERED_ON_TX: OnceLock<std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>> =
        OnceLock::new();

    fn powered_on_tx() -> &'static std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>> {
        POWERED_ON_TX.get_or_init(|| std::sync::Mutex::new(None))
    }

    /// Each entry holds a +1 retain (released on unsubscribe / disconnect / drain).
    static SUBSCRIBED_CENTRALS: OnceLock<std::sync::Mutex<HashMap<String, SendPtr>>> =
        OnceLock::new();

    fn subscribed_centrals_map() -> &'static std::sync::Mutex<HashMap<String, SendPtr>> {
        SUBSCRIBED_CENTRALS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
    }

    /// Lets the fan-out skip writes to characteristics a central never
    /// subscribed to. Writing to both Ratspeak + Columba for every fragment
    /// doubles radio pressure and drops half of LXMF payloads to queue-full.
    static CENTRAL_SUBSCRIBED_CHARS: OnceLock<
        std::sync::Mutex<HashMap<String, std::collections::HashSet<Uuid>>>,
    > = OnceLock::new();

    fn central_subscribed_chars_map()
    -> &'static std::sync::Mutex<HashMap<String, std::collections::HashSet<Uuid>>> {
        CENTRAL_SUBSCRIBED_CHARS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
    }

    #[allow(dead_code)]
    pub fn subscribed_central_addresses() -> Vec<String> {
        match subscribed_centrals_map().lock() {
            Ok(g) => g.keys().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn subscribed_centrals_for_char(char_uuid: Uuid) -> Vec<String> {
        match central_subscribed_chars_map().lock() {
            Ok(g) => g
                .iter()
                .filter(|(_, chars)| chars.contains(&char_uuid))
                .map(|(id, _)| id.clone())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Drained by `peripheralManagerIsReadyToUpdateSubscribers:`.
    struct PendingNotify {
        peer: String,
        char_uuid: Uuid,
        data: Vec<u8>,
    }
    const PENDING_NOTIFY_CAP: usize = 128;
    static PENDING_NOTIFY: OnceLock<std::sync::Mutex<std::collections::VecDeque<PendingNotify>>> =
        OnceLock::new();

    fn pending_notify_queue() -> &'static std::sync::Mutex<std::collections::VecDeque<PendingNotify>>
    {
        PENDING_NOTIFY.get_or_init(|| std::sync::Mutex::new(std::collections::VecDeque::new()))
    }

    /// Returns empty string if input is null or extraction fails.
    unsafe fn nsstring_to_string(s: *mut AnyObject) -> String {
        if s.is_null() {
            return String::new();
        }
        unsafe {
            let utf8: *const std::ffi::c_char = msg_send![&*s, UTF8String];
            // 4 = NSUTF8StringEncoding
            let len: usize = msg_send![&*s, lengthOfBytesUsingEncoding: 4usize];
            if utf8.is_null() || len == 0 {
                return String::new();
            }
            let bytes = std::slice::from_raw_parts(utf8 as *const u8, len);
            String::from_utf8_lossy(bytes).into_owned()
        }
    }

    unsafe fn central_identifier(req: *mut AnyObject) -> String {
        if req.is_null() {
            return String::new();
        }
        unsafe {
            let central: *mut AnyObject = msg_send![&*req, central];
            if central.is_null() {
                return String::new();
            }
            let identifier: *mut AnyObject = msg_send![&*central, identifier];
            if identifier.is_null() {
                return String::new();
            }
            let uuid_string: *mut AnyObject = msg_send![&*identifier, UUIDString];
            nsstring_to_string(uuid_string)
        }
    }

    fn get_delegate_class() -> &'static AnyClass {
        DELEGATE_CLASS.get_or_init(|| {
            let superclass = AnyClass::get("NSObject").unwrap();
            let mut builder = ClassBuilder::new("RatspeakBleDelegate", superclass).unwrap();

            extern "C" fn did_update_state(
                _this: *mut AnyObject,
                _sel: Sel,
                peripheral: *mut AnyObject,
            ) {
                if peripheral.is_null() {
                    return;
                }
                let state: i64 = unsafe { msg_send![&*peripheral, state] };
                tracing::info!(
                    state,
                    name = cb_state_name(state),
                    "iOS BLE Peripheral: state update"
                );

                match state {
                    // 0=Unknown 1=Resetting 2=Unsupported 3=Unauthorized
                    // 4=PoweredOff 5=PoweredOn.
                    0 => {}

                    1 => {
                        apply_event(
                            crate::ble_peer_lifecycle::LifecycleEvent::PlatformUnavailable {
                                reason: "resetting".into(),
                            },
                        );
                        clear_subscribed_centrals_for_recovery();
                    }

                    2 => {
                        apply_event(
                            crate::ble_peer_lifecycle::LifecycleEvent::FatalError {
                                reason: "bluetooth unsupported".into(),
                            },
                        );
                    }

                    3 => {
                        apply_event(
                            crate::ble_peer_lifecycle::LifecycleEvent::FatalError {
                                reason: "bluetooth permission denied".into(),
                            },
                        );
                    }

                    // PoweredOff: keep manager around so the next PoweredOn
                    // can re-register. `stop_advertising` clears
                    // LAST_IDENTITY_HASH, so a user-stopped recovery is a no-op.
                    4 => {
                        apply_event(
                            crate::ble_peer_lifecycle::LifecycleEvent::PlatformUnavailable {
                                reason: "bluetooth off".into(),
                            },
                        );
                        clear_subscribed_centrals_for_recovery();
                    }

                    // PoweredOn: hand off to the waiting worker (initial
                    // path), or re-register from `LAST_IDENTITY_HASH` if the
                    // worker already exited (recovery path).
                    5 => {
                        // `take()` empties the slot so a subsequent PoweredOn
                        // takes the recovery branch.
                        let tx = match powered_on_tx().lock() {
                            Ok(mut g) => g.take(),
                            Err(e) => {
                                tracing::error!(
                                    "iOS BLE Peripheral: powered_on_tx lock err: {e}"
                                );
                                return;
                            }
                        };
                        if let Some(tx) = tx {
                            if let Err(e) = tx.send(()) {
                                tracing::error!(
                                    "iOS BLE Peripheral: powered_on signal send err: {e}"
                                );
                                return;
                            }
                            tracing::info!(
                                "iOS BLE Peripheral: powered on (initial), releasing worker"
                            );
                            apply_event(
                                crate::ble_peer_lifecycle::LifecycleEvent::PlatformReady,
                            );
                            return;
                        }

                        // Recovery branch: re-register if the lifecycle was
                        // rewound to StartingWaitingPlatform and we still
                        // have a stashed identity hash.
                        let state = lifecycle().current();
                        let should_recover = matches!(
                            state,
                            crate::ble_peer_lifecycle::PeripheralState::StartingWaitingPlatform
                        );
                        if !should_recover {
                            tracing::info!(
                                ?state,
                                "iOS BLE Peripheral: powered on, no recovery needed"
                            );
                            return;
                        }
                        let Some(id_hash) = ({
                            match last_identity_hash().lock() {
                                Ok(g) => g.clone(),
                                Err(_) => None,
                            }
                        }) else {
                            tracing::warn!(
                                "iOS BLE Peripheral: recovery-ready but LAST_IDENTITY_HASH unset"
                            );
                            return;
                        };
                        let mgr_lock = manager_ptr_slot();
                        let mgr_ptr = match mgr_lock.lock() {
                            Ok(g) if !g.0.is_null() => g.0,
                            _ => {
                                tracing::warn!(
                                    "iOS BLE Peripheral: recovery-ready but manager is null"
                                );
                                return;
                            }
                        };
                        apply_event(
                            crate::ble_peer_lifecycle::LifecycleEvent::PlatformReady,
                        );
                        // Drop stale retained characteristics so the new
                        // registry reflects fresh CBMutableCharacteristic
                        // pointers CB is about to hand us.
                        SERVICES_ADDED_COUNT
                            .store(0, std::sync::atomic::Ordering::SeqCst);
                        drain_characteristic_registry();
                        // Services must register off the main dispatch queue
                        // — objc2's debug class-verify rejects msg_send from
                        // main in delegate context.
                        //
                        // Cast to `usize` rather than capturing a `SendPtr`:
                        // edition-2021+ precise-capture would otherwise
                        // reduce the capture to the inner `*mut AnyObject`
                        // (not Send), defeating the wrapper.
                        let mgr_addr = mgr_ptr as usize;
                        std::thread::spawn(move || unsafe {
                            let mgr = mgr_addr as *mut AnyObject;
                            match register_services_and_advertise(mgr, &id_hash) {
                                Ok(()) => tracing::info!(
                                    "iOS BLE Peripheral: recovery — re-registered services"
                                ),
                                Err(e) => {
                                    tracing::error!(
                                        "iOS BLE Peripheral: recovery register+advertise failed: {e}"
                                    );
                                    apply_event(
                                        crate::ble_peer_lifecycle::LifecycleEvent::PlatformUnavailable {
                                            reason: format!("recovery re-register failed: {e}"),
                                        },
                                    );
                                }
                            }
                        });
                    }

                    _ => {
                        tracing::warn!(
                            state,
                            "iOS BLE Peripheral: unknown CBManagerState variant"
                        );
                    }
                }
            }

            // Until this fires the lifecycle is StartingAdvertising;
            // `err` is null on success.
            extern "C" fn did_start_advertising(
                _this: *mut AnyObject,
                _sel: Sel,
                _peripheral: *mut AnyObject,
                err: *mut AnyObject,
            ) {
                if err.is_null() {
                    tracing::info!("iOS BLE Peripheral: advertising started");
                    apply_event(crate::ble_peer_lifecycle::LifecycleEvent::AdvertiseStarted);
                } else {
                    // Failure here is typically recoverable (user can toggle
                    // BT), so rewind to WaitingPlatform rather than Failed.
                    let reason = unsafe {
                        let desc: *mut AnyObject = msg_send![&*err, localizedDescription];
                        nsstring_to_string(desc)
                    };
                    tracing::warn!(
                        reason = %reason,
                        "iOS BLE Peripheral: startAdvertising error"
                    );
                    apply_event(crate::ble_peer_lifecycle::LifecycleEvent::PlatformUnavailable {
                        reason,
                    });
                }
            }

            extern "C" fn did_add_service(
                _this: *mut AnyObject,
                _sel: Sel,
                _p: *mut AnyObject,
                _s: *mut AnyObject,
                err: *mut AnyObject,
            ) {
                if err.is_null() {
                    tracing::info!("iOS BLE: service registered");
                    // Once both Ratspeak + Columba are in, drive the
                    // lifecycle forward so AdvertiseStarted can legally follow.
                    let count = SERVICES_ADDED_COUNT
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        + 1;
                    if count >= EXPECTED_SERVICE_COUNT {
                        apply_event(
                            crate::ble_peer_lifecycle::LifecycleEvent::ServicesAdded,
                        );
                    }
                } else {
                    tracing::warn!("iOS BLE: service registration failed");
                    let reason = unsafe {
                        let desc: *mut AnyObject = msg_send![&*err, localizedDescription];
                        nsstring_to_string(desc)
                    };
                    apply_event(crate::ble_peer_lifecycle::LifecycleEvent::PlatformUnavailable {
                        reason,
                    });
                }
            }

            extern "C" fn did_receive_writes(
                _this: *mut AnyObject,
                _sel: Sel,
                peripheral: *mut AnyObject,
                requests: *mut AnyObject,
            ) {
                if peripheral.is_null() || requests.is_null() {
                    return;
                }
                unsafe {
                    let count: usize = msg_send![&*requests, count];
                    for i in 0..count {
                        let req: *mut AnyObject = msg_send![&*requests, objectAtIndex: i];
                        if req.is_null() {
                            continue;
                        }
                        let peer_id = central_identifier(req);
                        let value: *mut AnyObject = msg_send![&*req, value];
                        if value.is_null() {
                            continue;
                        }
                        let len: usize = msg_send![&*value, length];
                        let ptr: *const std::ffi::c_void = msg_send![&*value, bytes];
                        if !ptr.is_null() && len > 0 {
                            let data = std::slice::from_raw_parts(ptr as *const u8, len).to_vec();
                            tracing::debug!(
                                target: "ble_trace",
                                step = "apple_peripheral.write_recv",
                                peer = %peer_id,
                                len = data.len(),
                                "Apple BLE peripheral: write received"
                            );
                            if let Some(tx) = inbound_sender() {
                                // CB dispatch queue is synchronous, so try_send +
                                // drop-on-full instead of blocking the callback.
                                if let Err(e) = tx.try_send((peer_id, data)) {
                                    tracing::warn!(
                                        "Apple BLE inbound channel full, dropping frame: {e}"
                                    );
                                }
                            }
                        }
                        let _: () =
                            msg_send![&*peripheral, respondToRequest: &*req, withResult: 0i64];
                    }
                }
            }

            extern "C" fn did_subscribe(
                _this: *mut AnyObject,
                _sel: Sel,
                _peripheral: *mut AnyObject,
                central: *mut AnyObject,
                characteristic: *mut AnyObject,
            ) {
                if central.is_null() {
                    return;
                }
                unsafe {
                    let identifier: *mut AnyObject = msg_send![&*central, identifier];
                    if identifier.is_null() {
                        return;
                    }
                    let uuid_string: *mut AnyObject = msg_send![&*identifier, UUIDString];
                    let id = nsstring_to_string(uuid_string);
                    if id.is_empty() {
                        return;
                    }
                    let char_uuid = uuid_for_characteristic(characteristic);
                    // First-ever subscribe per central also takes the +1
                    // retain that pairs with the release in did_unsubscribe.
                    let first_ever_sub_for_central = {
                        let mut chars_map = central_subscribed_chars_map().lock().unwrap();
                        let entry = chars_map.entry(id.clone()).or_default();
                        let first = entry.is_empty();
                        if let Some(u) = char_uuid {
                            entry.insert(u);
                        }
                        first
                    };
                    let mut map = subscribed_centrals_map().lock().unwrap();
                    let already_subscribed = map.contains_key(&id);
                    if !already_subscribed {
                        let _: *mut AnyObject = msg_send![&*central, retain];
                        map.insert(id.clone(), SendPtr(central));
                    }
                    tracing::info!(peer = %id, ?char_uuid, "Apple BLE: central subscribed");
                    if first_ever_sub_for_central && !already_subscribed {
                        drop(map);
                        // Surface the subscribe as a connected peer for the
                        // UI cache. identity_hash is left blank until the
                        // announce resolves it.
                        super::dispatch_event(BlePeerEvent::Connected {
                            address: id.clone(),
                            identity_hash: String::new(),
                            protocol: PeerProtocol::Ratspeak,
                        });
                        super::dispatch_event(BlePeerEvent::SubscribeReady { address: id });
                    }
                }
            }

            // Unsubscribing from one of two subscribed chars does NOT
            // disconnect the peer (matches Android behavior); only when the
            // per-central set goes empty do we release + emit Disconnected.
            extern "C" fn did_unsubscribe(
                _this: *mut AnyObject,
                _sel: Sel,
                _peripheral: *mut AnyObject,
                central: *mut AnyObject,
                characteristic: *mut AnyObject,
            ) {
                if central.is_null() {
                    return;
                }
                unsafe {
                    let identifier: *mut AnyObject = msg_send![&*central, identifier];
                    if identifier.is_null() {
                        return;
                    }
                    let uuid_string: *mut AnyObject = msg_send![&*identifier, UUIDString];
                    let id = nsstring_to_string(uuid_string);
                    if id.is_empty() {
                        return;
                    }
                    let char_uuid = uuid_for_characteristic(characteristic);
                    let all_gone = {
                        let mut chars_map = central_subscribed_chars_map().lock().unwrap();
                        if let Some(u) = char_uuid {
                            if let Some(set) = chars_map.get_mut(&id) {
                                set.remove(&u);
                            }
                        }
                        let empty = chars_map.get(&id).is_none_or(|s| s.is_empty());
                        if empty {
                            chars_map.remove(&id);
                        }
                        empty
                    };
                    tracing::info!(peer = %id, ?char_uuid, all_gone, "Apple BLE: central unsubscribed");
                    if all_gone {
                        let mut map = subscribed_centrals_map().lock().unwrap();
                        let was_subscribed = map.remove(&id).is_some_and(|ptr| {
                            let _: () = msg_send![ptr.0, release];
                            true
                        });
                        if was_subscribed {
                            drop(map);
                            super::dispatch_event(BlePeerEvent::Disconnected {
                                address: id,
                                reason: "central unsubscribed".into(),
                            });
                        }
                    }
                }
            }

            // Without retrying here, fragmented LXMF messages silently
            // lose every fragment past the first because the queue isn't
            // ready between writes.
            extern "C" fn is_ready_to_update(
                _this: *mut AnyObject,
                _sel: Sel,
                _peripheral: *mut AnyObject,
            ) {
                loop {
                    let entry = {
                        let mut q = pending_notify_queue().lock().unwrap();
                        q.pop_front()
                    };
                    let Some(entry) = entry else { break };
                    if !notify_tx_inner(Some(&entry.peer), entry.char_uuid, &entry.data) {
                        // Still full — requeue at front and wait for the
                        // next ready-to-update callback.
                        let mut q = pending_notify_queue().lock().unwrap();
                        q.push_front(entry);
                        break;
                    }
                }
            }

            // Fires BEFORE `peripheralManagerDidUpdateState:` when iOS
            // resurrects the process for a background BLE event.
            extern "C" fn will_restore_state(
                _this: *mut AnyObject,
                _sel: Sel,
                peripheral: *mut AnyObject,
                dict: *mut AnyObject,
            ) {
                if dict.is_null() {
                    tracing::info!(
                        "iOS BLE Peripheral: willRestoreState (empty dict)"
                    );
                    return;
                }
                unsafe {
                    let services: *mut AnyObject = msg_send![&*dict,
                        objectForKey: CBPeripheralManagerRestoredStateServicesKey];
                    let ad_data: *mut AnyObject = msg_send![&*dict,
                        objectForKey: CBPeripheralManagerRestoredStateAdvertisementDataKey];

                    let service_count: usize = if services.is_null() {
                        0
                    } else {
                        msg_send![&*services, count]
                    };
                    let has_ad_data = !ad_data.is_null();

                    tracing::info!(
                        target: "ble_trace",
                        step = "peripheral.will_restore_state",
                        service_count,
                        has_ad_data,
                        "iOS BLE Peripheral: willRestoreState"
                    );

                    // Services + their CBMutableCharacteristics are already
                    // attached to the manager per Apple's docs; we just need
                    // to repopulate CHARACTERISTIC_REGISTRY so notify_tx can
                    // resolve TX pointers by UUID.
                    if !services.is_null() {
                        for i in 0..service_count {
                            let svc: *mut AnyObject =
                                msg_send![&*services, objectAtIndex: i];
                            if svc.is_null() {
                                continue;
                            }
                            let chars: *mut AnyObject =
                                msg_send![&*svc, characteristics];
                            if chars.is_null() {
                                continue;
                            }
                            let cc: usize = msg_send![&*chars, count];
                            for j in 0..cc {
                                let ch: *mut AnyObject =
                                    msg_send![&*chars, objectAtIndex: j];
                                if ch.is_null() {
                                    continue;
                                }
                                let cb_uuid: *mut AnyObject =
                                    msg_send![&*ch, UUID];
                                if cb_uuid.is_null() {
                                    continue;
                                }
                                let uuid_str_obj: *mut AnyObject =
                                    msg_send![&*cb_uuid, UUIDString];
                                let uuid_str = nsstring_to_string(uuid_str_obj);
                                let uuid = match Uuid::parse_str(&uuid_str) {
                                    Ok(u) => u,
                                    Err(_) => continue,
                                };
                                // RX is delegate-driven; we only need TX
                                // pointers in the registry for notify_tx.
                                if uuid == RATSPEAK_TX_UUID
                                    || uuid == COLUMBA_TX_UUID
                                {
                                    // Outlive the autorelease-pool drain.
                                    let _: *mut AnyObject =
                                        msg_send![ch, retain];
                                    register_characteristic(uuid, ch);
                                    tracing::info!(
                                        target: "ble_trace",
                                        step = "peripheral.restore_char",
                                        uuid = %uuid,
                                        "iOS BLE Peripheral: registered restored TX characteristic"
                                    );
                                }
                            }
                        }
                    }

                    // Skip when ad_data is nil — the app wasn't advertising
                    // at suspend time, so don't resurrect that state.
                    if has_ad_data && !peripheral.is_null() {
                        let _: () =
                            msg_send![&*peripheral, startAdvertising: ad_data];
                        tracing::info!(
                            target: "ble_trace",
                            step = "peripheral.restore_resumed_advertising",
                            "iOS BLE Peripheral: startAdvertising resumed from restored ad data"
                        );
                    }
                }
            }

            unsafe {
                builder.add_method(
                    sel!(peripheralManagerDidUpdateState:),
                    did_update_state as extern "C" fn(*mut AnyObject, Sel, *mut AnyObject),
                );
                builder.add_method(
                    sel!(peripheralManagerDidStartAdvertising:error:),
                    did_start_advertising
                        as extern "C" fn(
                            *mut AnyObject,
                            Sel,
                            *mut AnyObject,
                            *mut AnyObject,
                        ),
                );
                builder.add_method(
                    sel!(peripheralManager:didAddService:error:),
                    did_add_service
                        as extern "C" fn(
                            *mut AnyObject,
                            Sel,
                            *mut AnyObject,
                            *mut AnyObject,
                            *mut AnyObject,
                        ),
                );
                builder.add_method(
                    sel!(peripheralManager:didReceiveWriteRequests:),
                    did_receive_writes
                        as extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject),
                );
                builder.add_method(
                    sel!(peripheralManager:central:didSubscribeToCharacteristic:),
                    did_subscribe
                        as extern "C" fn(
                            *mut AnyObject,
                            Sel,
                            *mut AnyObject,
                            *mut AnyObject,
                            *mut AnyObject,
                        ),
                );
                builder.add_method(
                    sel!(peripheralManager:central:didUnsubscribeFromCharacteristic:),
                    did_unsubscribe
                        as extern "C" fn(
                            *mut AnyObject,
                            Sel,
                            *mut AnyObject,
                            *mut AnyObject,
                            *mut AnyObject,
                        ),
                );
                builder.add_method(
                    sel!(peripheralManagerIsReadyToUpdateSubscribers:),
                    is_ready_to_update
                        as extern "C" fn(*mut AnyObject, Sel, *mut AnyObject),
                );
                builder.add_method(
                    sel!(peripheralManager:willRestoreState:),
                    will_restore_state
                        as extern "C" fn(
                            *mut AnyObject,
                            Sel,
                            *mut AnyObject,
                            *mut AnyObject,
                        ),
                );
            }

            builder.register()
        })
    }

    /// Push `data` on the TX characteristic matching `char_uuid`; targets
    /// `to_peer` if set, all subscribed centrals otherwise. Targeted writes
    /// queue onto PENDING_NOTIFY on backpressure; broadcasts can't be
    /// replayed coherently without per-central addressing, so they don't.
    pub fn notify_tx(to_peer: Option<&str>, char_uuid: Uuid, data: &[u8]) -> bool {
        let ok = notify_tx_inner(to_peer, char_uuid, data);
        if !ok {
            if let Some(peer_id) = to_peer {
                let mut q = pending_notify_queue().lock().unwrap();
                if q.len() >= PENDING_NOTIFY_CAP {
                    q.pop_front();
                }
                q.push_back(PendingNotify {
                    peer: peer_id.to_string(),
                    char_uuid,
                    data: data.to_vec(),
                });
                tracing::warn!(%char_uuid, bytes = data.len(), peer = %peer_id, depth = q.len(), "Apple BLE notify_tx: queued for retry (radio queue full)");
            }
        }
        ok
    }

    /// Returns the raw `updateValue:` result without touching the retry
    /// queue, so it's safe to call from the is-ready-to-update flush loop.
    fn notify_tx_inner(to_peer: Option<&str>, char_uuid: Uuid, data: &[u8]) -> bool {
        let mgr_lock = manager_ptr_slot();
        let mgr = match mgr_lock.lock() {
            Ok(g) if !g.0.is_null() => g.0,
            _ => {
                tracing::warn!("Apple BLE notify_tx: manager null or poisoned");
                return false;
            }
        };
        let char_ptr = match characteristic_for_uuid(char_uuid) {
            Some(p) => p,
            None => {
                tracing::warn!(%char_uuid, "Apple BLE notify_tx: characteristic not registered");
                return false;
            }
        };
        unsafe {
            let arr_cls = match AnyClass::get("NSArray") {
                Some(c) => c,
                None => return false,
            };
            let data_cls = match AnyClass::get("NSData") {
                Some(c) => c,
                None => return false,
            };
            let payload: *mut AnyObject = msg_send![data_cls,
                dataWithBytes: data.as_ptr() as *const std::ffi::c_void,
                length: data.len()];
            let centrals: *mut AnyObject = if let Some(peer_id) = to_peer {
                let map = subscribed_centrals_map().lock().unwrap();
                let ptr = match map.get(peer_id) {
                    Some(p) => p.0,
                    None => {
                        tracing::warn!(peer = %peer_id, "Apple BLE notify_tx: peer not in subscribed map");
                        return false;
                    }
                };
                let one = [ptr as *const AnyObject];
                msg_send![arr_cls, arrayWithObjects: one.as_ptr(), count: 1usize]
            } else {
                std::ptr::null_mut()
            };
            let ok: bool = msg_send![
                mgr,
                updateValue: payload,
                forCharacteristic: char_ptr,
                onSubscribedCentrals: centrals,
            ];
            ok
        }
    }

    // We only need the TX chars from notify_tx, but the registry is keyed
    // by UUID for symmetry.
    static CHARACTERISTIC_REGISTRY: OnceLock<std::sync::Mutex<HashMap<Uuid, SendPtr>>> =
        OnceLock::new();

    fn characteristic_registry() -> &'static std::sync::Mutex<HashMap<Uuid, SendPtr>> {
        CHARACTERISTIC_REGISTRY.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
    }

    fn register_characteristic(uuid: Uuid, ptr: *mut AnyObject) {
        let mut map = characteristic_registry().lock().unwrap();
        map.insert(uuid, SendPtr(ptr));
    }

    fn characteristic_for_uuid(uuid: Uuid) -> Option<*mut AnyObject> {
        let map = characteristic_registry().lock().ok()?;
        map.get(&uuid).map(|p| p.0)
    }

    /// Reverse of `characteristic_for_uuid`; lets the subscribe delegate
    /// avoid bouncing through `CBCharacteristic.UUID.UUIDString` on the
    /// main queue.
    fn uuid_for_characteristic(ptr: *mut AnyObject) -> Option<Uuid> {
        if ptr.is_null() {
            return None;
        }
        let map = characteristic_registry().lock().ok()?;
        map.iter()
            .find(|(_, sp)| sp.0 == ptr)
            .map(|(uuid, _)| *uuid)
    }

    /// Returns a raw retained pointer.
    fn cbuuid(uuid: &Uuid) -> *mut AnyObject {
        let s = NSString::from_str(&uuid.to_string());
        unsafe {
            let cls = AnyClass::get("CBUUID").unwrap();
            let obj: *mut AnyObject = msg_send![cls, UUIDWithString: &*s];
            let _: *mut AnyObject = msg_send![obj, retain];
            obj
        }
    }

    pub async fn start_advertising(identity_hash: &[u8]) -> Result<(), String> {
        // Drive the lifecycle BEFORE any side effects.
        apply_event(crate::ble_peer_lifecycle::LifecycleEvent::StartRequested);
        SERVICES_ADDED_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);

        let id_hash = identity_hash.to_vec();
        // Stash for the PoweredOff → PoweredOn recovery path in
        // `did_update_state` (cleared by `stop_advertising`).
        if let Ok(mut g) = last_identity_hash().lock() {
            *g = Some(id_hash.clone());
        }
        reset_inbound_channel();

        // Stash pending + signal sender BEFORE creating the manager —
        // `peripheralManagerDidUpdateState:` fires on the main queue and
        // can race ahead of our worker thread. If either is still None when
        // PoweredOn lands, services never register.
        match pending_advertise().lock() {
            Ok(mut g) => {
                *g = Some(PendingAdvertise {
                    identity_hash: id_hash.clone(),
                });
            }
            Err(e) => return Err(format!("pending_advertise lock poisoned: {e}")),
        }

        let (signal_tx, signal_rx) = std::sync::mpsc::channel::<()>();
        match powered_on_tx().lock() {
            Ok(mut g) => *g = Some(signal_tx),
            Err(e) => return Err(format!("powered_on_tx lock poisoned: {e}")),
        }

        // Dedicated thread (detached): sidesteps Send issues with raw ObjC
        // pointers, and keeps register_services_and_advertise off the main
        // queue (objc2's debug class-verify panics when msg_send runs from
        // CB's main dispatch queue in delegate context).
        std::thread::spawn(move || unsafe {
            let delegate_cls = get_delegate_class();
            let delegate_raw: *mut AnyObject = msg_send![delegate_cls, alloc];
            let delegate_raw: *mut AnyObject = msg_send![delegate_raw, init];

            let Some(mgr_cls) = AnyClass::get("CBPeripheralManager") else {
                tracing::error!("iOS BLE Peripheral: CBPeripheralManager class not found");
                return;
            };
            let mgr_raw: *mut AnyObject = msg_send![mgr_cls, alloc];
            // RestoreIdentifierKey lets iOS resurrect this peripheral for a
            // background BLE event after the process is killed.
            let opts: *mut AnyObject = {
                let dict_cls =
                    AnyClass::get("NSDictionary").expect("NSDictionary must exist at runtime");
                let id = NSString::from_str(PERIPHERAL_RESTORE_ID);
                msg_send![dict_cls,
                    dictionaryWithObject: &*id,
                    forKey: CBPeripheralManagerOptionRestoreIdentifierKey]
            };
            let mgr_raw: *mut AnyObject = msg_send![mgr_raw,
                initWithDelegate: delegate_raw,
                queue: std::ptr::null::<AnyObject>(),
                options: opts,
            ];
            // `retain` returns `id`; binding as `*mut AnyObject` avoids
            // objc2's debug class-verify tripping on KVO-swizzled subclasses
            // like `NSKVONotifying_CBPeripheralManager`.
            let _: *mut AnyObject = msg_send![mgr_raw, retain];

            set_manager_ptr(mgr_raw);
            tracing::info!("iOS BLE Peripheral: manager created, waiting for PoweredOn");

            // 10s safety net; CB normally reports state within ~100ms.
            match signal_rx.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(()) => {}
                Err(e) => {
                    tracing::error!("iOS BLE Peripheral: timed out waiting for PoweredOn: {e}");
                    if let Ok(mut g) = pending_advertise().lock() {
                        *g = None;
                    }
                    return;
                }
            }

            // On subsequent Bluetooth-cycled PoweredOn firings there will
            // be nothing to do.
            let pending = match pending_advertise().lock() {
                Ok(mut g) => g.take(),
                Err(e) => {
                    tracing::error!("iOS BLE Peripheral: pending lock err: {e}");
                    return;
                }
            };
            let Some(pending) = pending else {
                tracing::info!("iOS BLE Peripheral: pending was already taken, skipping");
                return;
            };

            match register_services_and_advertise(mgr_raw, &pending.identity_hash) {
                Ok(()) => tracing::info!(
                    "iOS BLE Peripheral: powered on, registering services + advertising"
                ),
                Err(e) => tracing::error!("iOS BLE Peripheral: register+advertise failed: {e}"),
            }
        });

        Ok(())
    }

    /// Columba is registered in the GATT server for post-connect service
    /// discovery but intentionally NOT in `kCBAdvDataServiceUUIDs` — two
    /// 128-bit UUIDs exceed the BLE 4.x 31-byte advertising payload, and
    /// iOS would overflow one into the scan response (which some Android
    /// `ScanFilter.setServiceUuid` paths miss).
    unsafe fn register_services_and_advertise(
        mgr_raw: *mut AnyObject,
        id_hash: &[u8],
    ) -> Result<(), String> {
        unsafe {
            let char_cls = AnyClass::get("CBMutableCharacteristic")
                .ok_or("CBMutableCharacteristic not found")?;
            let svc_cls = AnyClass::get("CBMutableService").ok_or("CBMutableService not found")?;
            let arr_cls = AnyClass::get("NSArray").ok_or("NSArray not found")?;
            let dict_cls = AnyClass::get("NSDictionary").ok_or("NSDictionary not found")?;

            // RX (write + writeNoResponse)
            let rx_raw: *mut AnyObject = msg_send![char_cls, alloc];
            let rx_raw: *mut AnyObject = msg_send![rx_raw,
                initWithType: cbuuid(&RATSPEAK_RX_UUID), properties: 0x0Cu64,
                value: std::ptr::null::<AnyObject>(), permissions: 0x02u64];
            // TX (read + notify)
            let tx_raw: *mut AnyObject = msg_send![char_cls, alloc];
            let tx_raw: *mut AnyObject = msg_send![tx_raw,
                initWithType: cbuuid(&RATSPEAK_TX_UUID), properties: 0x12u64,
                value: std::ptr::null::<AnyObject>(), permissions: 0x01u64];
            // Keep the registry pointer valid for notify_tx.
            let _: *mut AnyObject = msg_send![tx_raw, retain];
            register_characteristic(RATSPEAK_TX_UUID, tx_raw);
            // No static ID characteristic: it exposed a MAC-rotation-stable
            // identity read to any connecting scanner (a tracking vector) and
            // was never read by this stack — identity is learned from signed
            // announces instead.

            // Ratspeak service (primary)
            let svc_raw: *mut AnyObject = msg_send![svc_cls, alloc];
            let svc_raw: *mut AnyObject = msg_send![svc_raw,
                initWithType: cbuuid(&RATSPEAK_SERVICE_UUID), primary: true];
            let char_ptrs = [
                rx_raw as *const AnyObject,
                tx_raw as *const AnyObject,
            ];
            let chars: *mut AnyObject = msg_send![arr_cls,
                arrayWithObjects: char_ptrs.as_ptr(), count: 2usize];
            let _: () = msg_send![svc_raw, setCharacteristics: chars];
            let _: () = msg_send![mgr_raw, addService: svc_raw];

            // Columba compat (secondary, omitted from advertising payload).
            let c_rx_raw: *mut AnyObject = msg_send![char_cls, alloc];
            let c_rx_raw: *mut AnyObject = msg_send![c_rx_raw,
                initWithType: cbuuid(&COLUMBA_RX_UUID), properties: 0x0Cu64,
                value: std::ptr::null::<AnyObject>(), permissions: 0x02u64];
            let c_tx_raw: *mut AnyObject = msg_send![char_cls, alloc];
            let c_tx_raw: *mut AnyObject = msg_send![c_tx_raw,
                initWithType: cbuuid(&COLUMBA_TX_UUID), properties: 0x12u64,
                value: std::ptr::null::<AnyObject>(), permissions: 0x01u64];
            let _: *mut AnyObject = msg_send![c_tx_raw, retain];
            register_characteristic(COLUMBA_TX_UUID, c_tx_raw);
            let c_svc_raw: *mut AnyObject = msg_send![svc_cls, alloc];
            let c_svc_raw: *mut AnyObject = msg_send![c_svc_raw,
                initWithType: cbuuid(&COLUMBA_SERVICE_UUID), primary: false];
            let c_char_ptrs = [
                c_rx_raw as *const AnyObject,
                c_tx_raw as *const AnyObject,
            ];
            let c_chars: *mut AnyObject = msg_send![arr_cls,
                arrayWithObjects: c_char_ptrs.as_ptr(), count: 2usize];
            let _: () = msg_send![c_svc_raw, setCharacteristics: c_chars];
            let _: () = msg_send![mgr_raw, addService: c_svc_raw];

            // One 128-bit UUID fits in the 31-byte BLE 4.x adv PDU; two do not.
            let ad_key = NSString::from_str("kCBAdvDataServiceUUIDs");
            let uuid_ptrs = [cbuuid(&RATSPEAK_SERVICE_UUID) as *const AnyObject];
            let uuid_arr: *mut AnyObject = msg_send![arr_cls,
                arrayWithObjects: uuid_ptrs.as_ptr(), count: 1usize];
            let ad_dict: *mut AnyObject = msg_send![dict_cls,
                dictionaryWithObject: uuid_arr, forKey: &*ad_key];
            let _: () = msg_send![mgr_raw, startAdvertising: ad_dict];

            tracing::info!(
                target: "ble_trace",
                step = "peripheral.advertise_started",
                advertised_uuid = %RATSPEAK_SERVICE_UUID,
                gatt_services = "Ratspeak (primary) + Columba (secondary)",
                identity_hash_bytes = id_hash.len(),
                "Apple BLE Peripheral: advertising started"
            );
            Ok(())
        }
    }

    /// Walks the lifecycle state machine in lockstep with the platform
    /// work: stopAdvertising, poll `isAdvertising` until the radio
    /// confirms, removeAllServices, release retained resources, detach
    /// the delegate, null the stored manager pointer, then Reset. The
    /// "fast path" of just calling stopAdvertising + removeAllServices and
    /// returning leaves CB in a dirty state that breaks subsequent enables.
    pub async fn stop_advertising() -> Result<(), String> {
        apply_event(crate::ble_peer_lifecycle::LifecycleEvent::StopRequested);
        clear_inbound_channel();

        if let Ok(mut g) = pending_advertise().lock() {
            *g = None;
        }
        // Dropping the sender wakes the worker thread's recv_timeout with a
        // Disconnected error, which it handles as a cancel.
        if let Ok(mut g) = powered_on_tx().lock() {
            *g = None;
        }
        // User disabled BLE Mesh, so a later OS-initiated PoweredOn
        // recovery in `did_update_state` must NOT silently re-advertise.
        if let Ok(mut g) = last_identity_hash().lock() {
            *g = None;
        }

        let state = lifecycle().current();
        let needs_stop_ad = matches!(
            state,
            crate::ble_peer_lifecycle::PeripheralState::StoppingAdvertisement
        );
        let needs_remove = matches!(
            state,
            crate::ble_peer_lifecycle::PeripheralState::StoppingAdvertisement
                | crate::ble_peer_lifecycle::PeripheralState::StoppingRemovingServices
        );

        // No platform-side work required — finish the lifecycle and return.
        if !needs_stop_ad && !needs_remove {
            apply_event(crate::ble_peer_lifecycle::LifecycleEvent::Reset);
            return Ok(());
        }

        // Holding the lock across `await` would deadlock with concurrent
        // notify_tx; take the raw ptr out and drop the guard.
        let mgr_ptr: *mut AnyObject = {
            let lock = manager_ptr_slot();
            match lock.lock() {
                Ok(g) if !g.0.is_null() => g.0,
                _ => {
                    tracing::warn!(
                        "iOS BLE Peripheral: stop requested but manager ptr is null/poisoned"
                    );
                    if needs_stop_ad {
                        apply_event(crate::ble_peer_lifecycle::LifecycleEvent::AdvertiseStopped);
                    }
                    apply_event(crate::ble_peer_lifecycle::LifecycleEvent::ServicesRemoved);
                    apply_event(crate::ble_peer_lifecycle::LifecycleEvent::Reset);
                    return Ok(());
                }
            }
        };

        // SendPtr lets the raw pointer cross `await` (`*mut AnyObject: !Send`).
        let mgr_send = SendPtr(mgr_ptr);

        if needs_stop_ad {
            unsafe {
                let _: () = msg_send![mgr_send.0, stopAdvertising];
            }
            // CB has no peripheralManagerDidStopAdvertising delegate — poll
            // `isAdvertising`. Radio flips within ~20ms; 1s budget covers
            // contended radios and bounce loops.
            const POLL_INTERVAL_MS: u64 = 50;
            const POLL_ITERATIONS: u32 = 20;
            let mut confirmed = false;
            for _ in 0..POLL_ITERATIONS {
                let advertising: bool = unsafe { msg_send![mgr_send.0, isAdvertising] };
                if !advertising {
                    confirmed = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS)).await;
            }
            if !confirmed {
                tracing::warn!(
                    "iOS BLE Peripheral: isAdvertising still true after {} ms; proceeding with teardown",
                    POLL_INTERVAL_MS * u64::from(POLL_ITERATIONS)
                );
            }
            apply_event(crate::ble_peer_lifecycle::LifecycleEvent::AdvertiseStopped);
        }

        unsafe {
            let _: () = msg_send![mgr_send.0, removeAllServices];
        }
        apply_event(crate::ble_peer_lifecycle::LifecycleEvent::ServicesRemoved);

        // Without this, every toggle cycle leaks two CBMutableCharacteristic
        // pointers and notify_tx can race onto dead characteristics post-teardown.
        {
            let mut map = characteristic_registry().lock().unwrap();
            for (_, ptr) in map.drain() {
                if !ptr.0.is_null() {
                    unsafe {
                        let _: () = msg_send![ptr.0, release];
                    }
                }
            }
        }
        SERVICES_ADDED_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);

        // CB fires `didUnsubscribe` as services disappear, but we can't
        // depend on those having landed yet. Each entry holds a +1, so
        // releasing defensively here is safe.
        {
            let mut map = subscribed_centrals_map().lock().unwrap();
            for (_, ptr) in map.drain() {
                if !ptr.0.is_null() {
                    unsafe {
                        let _: () = msg_send![ptr.0, release];
                    }
                }
            }
        }
        {
            let mut map = central_subscribed_chars_map().lock().unwrap();
            map.clear();
        }

        // Detach delegate before release so queued callbacks on CB's main
        // dispatch queue become no-ops rather than UAF on the delegate.
        unsafe {
            let _: () = msg_send![mgr_send.0, setDelegate: std::ptr::null::<AnyObject>()];
        }

        // Balance the explicit `retain` from `start_advertising`. The
        // original `alloc` reference is intentionally NOT released — the
        // radio may still have in-flight delegate invocations queued on CB's
        // main dispatch queue, and a second release would race that queue
        // with a UAF. The resulting leak is bounded (~KB per toggle cycle).
        unsafe {
            let _: () = msg_send![mgr_send.0, release];
        }

        // OnceLock can't be cleared, but the inner Mutex<SendPtr> lets us
        // null the pointer so notify_tx + the next start cycle see no manager.
        if let Ok(mut guard) = manager_ptr_slot().lock() {
            *guard = SendPtr(std::ptr::null_mut());
        }

        // Any queued retries reference characteristics we just released;
        // drop them rather than let a later flush dereference a dead ptr.
        {
            let mut q = pending_notify_queue().lock().unwrap();
            q.clear();
        }

        apply_event(crate::ble_peer_lifecycle::LifecycleEvent::Reset);

        tracing::info!("iOS BLE Peripheral: teardown complete");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Android Peripheral (JNI to BluetoothGattServer)
// ---------------------------------------------------------------------------

/// Public wrapper so callers can tear down a single Android peer connection
/// without reaching into the private `android_peripheral` module.
#[cfg(target_os = "android")]
pub fn disconnect_android_peer(address: &str) {
    android_peripheral::peer_client_disconnect(address);
}

#[cfg(target_os = "android")]
pub fn android_ble_peer_availability_json() -> Result<String, String> {
    android_peripheral::ble_peer_availability_json()
}

#[cfg(target_os = "android")]
mod android_peripheral {
    use super::*;
    use jni::JavaVM;
    use jni::objects::{GlobalRef, JObject, JValue};
    use std::sync::OnceLock;

    static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();
    static ADVERTISER_REF: OnceLock<std::sync::Mutex<Option<GlobalRef>>> = OnceLock::new();
    static CALLBACK_REF: OnceLock<std::sync::Mutex<Option<GlobalRef>>> = OnceLock::new();

    fn advertiser_slot() -> &'static std::sync::Mutex<Option<GlobalRef>> {
        ADVERTISER_REF.get_or_init(|| std::sync::Mutex::new(None))
    }

    fn callback_slot() -> &'static std::sync::Mutex<Option<GlobalRef>> {
        CALLBACK_REF.get_or_init(|| std::sync::Mutex::new(None))
    }

    /// Registry of per-peer `online` flags so the JNI disconnect callback can
    /// flip them without holding a direct handle to the Tokio task that owns
    /// the connection. The Android central task registers each peer's flag at
    /// connect time and unregisters on cleanup.
    static PEER_ONLINE: OnceLock<std::sync::Mutex<HashMap<String, Arc<AtomicBool>>>> =
        OnceLock::new();

    fn peer_online_map() -> &'static std::sync::Mutex<HashMap<String, Arc<AtomicBool>>> {
        PEER_ONLINE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
    }

    /// Register an `online` flag the JNI disconnect callback can flip. Called
    /// by the Android central task after a successful peer client connect.
    pub fn register_peer_online(address: String, flag: Arc<AtomicBool>) {
        if let Ok(mut g) = peer_online_map().lock() {
            g.insert(address, flag);
        }
    }

    /// Remove an entry from the registry. Called from the central task's
    /// cleanup phase so the map doesn't grow unbounded.
    pub fn unregister_peer_online(address: &str) {
        if let Ok(mut g) = peer_online_map().lock() {
            g.remove(address);
        }
    }

    fn signal_peer_offline(address: &str) {
        if let Ok(g) = peer_online_map().lock() {
            if let Some(flag) = g.get(address) {
                flag.store(false, Ordering::SeqCst);
            }
        }
    }

    /// Inbound channel capacity. See apple_peripheral::INBOUND_CAPACITY for rationale.
    const INBOUND_CAPACITY: usize = 256;

    /// Inbound channel: each item is `(peer_address, data)` where `peer_address`
    /// is the source BluetoothDevice MAC string passed from RatspeakGattCallback.kt.
    /// See apple_peripheral::INBOUND_TX for the same shape on Apple platforms —
    /// the consumer in spawn_ble_peer_interface keys per-peer reassembly off this.
    type InboundFrame = (String, Vec<u8>);
    type InboundSender = tokio::sync::mpsc::Sender<InboundFrame>;
    type InboundReceiver = tokio::sync::mpsc::Receiver<InboundFrame>;

    static INBOUND_TX: OnceLock<std::sync::Mutex<Option<InboundSender>>> = OnceLock::new();
    static INBOUND_RX: OnceLock<std::sync::Mutex<Option<InboundReceiver>>> = OnceLock::new();

    fn inbound_tx_slot() -> &'static std::sync::Mutex<Option<InboundSender>> {
        INBOUND_TX.get_or_init(|| std::sync::Mutex::new(None))
    }

    fn inbound_rx_slot() -> &'static std::sync::Mutex<Option<InboundReceiver>> {
        INBOUND_RX.get_or_init(|| std::sync::Mutex::new(None))
    }

    fn reset_inbound_channel() {
        let (tx, rx) = tokio::sync::mpsc::channel::<InboundFrame>(INBOUND_CAPACITY);
        if let Ok(mut slot) = inbound_tx_slot().lock() {
            *slot = Some(tx);
        }
        if let Ok(mut slot) = inbound_rx_slot().lock() {
            *slot = Some(rx);
        }
    }

    fn clear_inbound_channel() {
        if let Ok(mut slot) = inbound_tx_slot().lock() {
            *slot = None;
        }
        if let Ok(mut slot) = inbound_rx_slot().lock() {
            *slot = None;
        }
    }

    /// Take the inbound receiver (call once from spawn_ble_peer_interface).
    pub fn take_inbound_rx() -> Option<tokio::sync::mpsc::Receiver<(String, Vec<u8>)>> {
        inbound_rx_slot().lock().ok().and_then(|mut opt| opt.take())
    }

    /// Called from JNI native method when the GATT server receives data from a peer.
    /// `peer_address` is the source BluetoothDevice MAC (or random rotating addr).
    pub fn on_gatt_data_received(peer_address: String, data: Vec<u8>) {
        let tx = inbound_tx_slot()
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().cloned());
        if let Some(tx) = tx {
            // JNI callback is synchronous on the binder thread; try_send + drop-on-full
            // is preferred over blocking the Android GATT stack when the reassembler stalls.
            if let Err(e) = tx.try_send((peer_address, data)) {
                tracing::warn!("Android BLE inbound channel full, dropping frame: {e}");
            }
        }
    }

    /// Store the JavaVM for later JNI calls (called from Tauri Android init).
    pub fn init_jvm(vm: JavaVM) {
        let _ = JAVA_VM.set(vm);
    }

    fn with_env<F, R>(f: F) -> Result<R, String>
    where
        F: FnOnce(&jni::JNIEnv) -> Result<R, String>,
    {
        let vm = JAVA_VM.get().ok_or("JavaVM not initialized")?;
        let env = vm
            .attach_current_thread()
            .map_err(|e| format!("JNI attach: {e}"))?;
        let result = f(&env);
        // Always clear any lingering Java exception before returning.
        // jni-rs panics on the next JNI call if the env still has one
        // pending — even one we already converted to a Rust error.
        jni_clear(&env);
        result
    }

    /// Clear any pending JNI exception so the next JNI call doesn't see a
    /// dirty env. Java exceptions remain pending after a failed JNI call;
    /// jni-rs treats subsequent calls as undefined behavior. Call this after
    /// any swallowed `.ok()` and on error paths before bubbling up.
    fn jni_clear(env: &jni::JNIEnv) {
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
        }
    }

    /// Resolve the system BluetoothAdapter via the modern BluetoothManager
    /// path. Mirrors `RatspeakBleServer.openGattServer` (Kotlin) and avoids
    /// the deprecated `BluetoothAdapter.getDefaultAdapter()` which
    /// SecurityExceptions on Android 12+ without BLUETOOTH_CONNECT and is
    /// removed entirely on some Android 14+ vendor builds.
    fn get_bluetooth_adapter<'a>(
        env: &'a jni::JNIEnv,
        context: JObject<'a>,
    ) -> Result<JObject<'a>, String> {
        let svc = env
            .new_string("bluetooth")
            .map_err(|e| format!("bluetooth service name: {e}"))?;
        let manager = env
            .call_method(
                context,
                "getSystemService",
                "(Ljava/lang/String;)Ljava/lang/Object;",
                &[JValue::Object(svc.into())],
            )
            .map_err(|e| {
                jni_clear(env);
                format!("getSystemService(bluetooth): {e}")
            })?
            .l()
            .map_err(|e| format!("BluetoothManager cast: {e}"))?;
        if manager.is_null() {
            return Err("BluetoothManager unavailable on this device".into());
        }
        let adapter = env
            .call_method(
                manager,
                "getAdapter",
                "()Landroid/bluetooth/BluetoothAdapter;",
                &[],
            )
            .map_err(|e| {
                jni_clear(env);
                format!("BluetoothManager.getAdapter: {e}")
            })?
            .l()
            .map_err(|e| format!("BluetoothAdapter cast: {e}"))?;
        if adapter.is_null() {
            return Err("BluetoothAdapter unavailable (radio off?)".into());
        }
        Ok(adapter)
    }

    /// Get the application Context via ActivityThread.currentApplication().
    fn get_app_context<'a>(env: &'a jni::JNIEnv) -> Result<JObject<'a>, String> {
        let at_cls = env
            .find_class("android/app/ActivityThread")
            .map_err(|e| format!("ActivityThread class: {e}"))?;
        let app = env
            .call_static_method(
                at_cls,
                "currentApplication",
                "()Landroid/app/Application;",
                &[],
            )
            .map_err(|e| format!("currentApplication: {e}"))?
            .l()
            .map_err(|e| format!("{e}"))?;
        if app.is_null() {
            return Err("currentApplication returned null".into());
        }
        Ok(app)
    }

    /// Cached application ClassLoader (a GlobalRef so it survives across
    /// thread attaches). Why: env.find_class() uses the *system* ClassLoader
    /// when called from a Rust-spawned thread, which doesn't know about
    /// app-bundled classes (org.ratspeak.android.*) — they ClassNotFoundException.
    /// We must instead route loadClass() through the Application context's
    /// loader to reach the app's DEX.
    static APP_CLASS_LOADER: OnceLock<jni::objects::GlobalRef> = OnceLock::new();

    fn ensure_class_loader(env: &jni::JNIEnv) -> Result<&'static jni::objects::GlobalRef, String> {
        if APP_CLASS_LOADER.get().is_none() {
            let context = get_app_context(env)?;
            let loader = env
                .call_method(context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
                .map_err(|e| {
                    jni_clear(env);
                    format!("getClassLoader: {e}")
                })?
                .l()
                .map_err(|e| format!("ClassLoader cast: {e}"))?;
            let global = env
                .new_global_ref(loader)
                .map_err(|e| format!("global ref: {e}"))?;
            let _ = APP_CLASS_LOADER.set(global);
        }
        APP_CLASS_LOADER
            .get()
            .ok_or_else(|| "ClassLoader not initialized".to_string())
    }

    /// Resolve a Ratspeak app class (e.g. "org.ratspeak.android.RatspeakBleServer")
    /// via the application ClassLoader. Use this — not env.find_class — for
    /// any org/ratspeak/android/* class. Accepts dotted form.
    fn find_app_class<'a>(
        env: &'a jni::JNIEnv,
        dotted: &str,
    ) -> Result<jni::objects::JClass<'a>, String> {
        let loader = ensure_class_loader(env)?;
        let name = env
            .new_string(dotted)
            .map_err(|e| format!("class name: {e}"))?;
        let cls = env
            .call_method(
                loader.as_obj(),
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[JValue::Object(name.into())],
            )
            .map_err(|e| {
                jni_clear(env);
                format!("loadClass({dotted}): {e}")
            })?
            .l()
            .map_err(|e| format!("Class cast: {e}"))?;
        Ok(jni::objects::JClass::from(cls))
    }

    pub fn ble_peer_availability_json() -> Result<String, String> {
        with_env(|env| {
            let context = get_app_context(env)?;
            let cls = find_app_class(env, "org.ratspeak.android.RatspeakBleAvailability")
                .map_err(|e| format!("RatspeakBleAvailability class: {e}"))?;
            let result = env
                .call_static_method(
                    cls,
                    "check",
                    "(Landroid/content/Context;)Ljava/lang/String;",
                    &[JValue::Object(context)],
                )
                .map_err(|e| format!("RatspeakBleAvailability.check: {e}"))?
                .l()
                .map_err(|e| format!("{e}"))?;
            if result.is_null() {
                return Err("RatspeakBleAvailability returned null".into());
            }
            let jstr: jni::objects::JString = result.into();
            Ok(env
                .get_string(jstr)
                .map(|s| s.to_string_lossy().into_owned())
                .map_err(|e| format!("availability string: {e}"))?)
        })
    }

    pub async fn start_advertising(identity_hash: &[u8]) -> Result<(), String> {
        // Set up inbound channel for GATT server write callbacks (see INBOUND_TX docs)
        reset_inbound_channel();

        let id_hash = identity_hash.to_vec();
        tokio::task::spawn_blocking(move || {
            with_env(|env| {
                // ── 1. Open GATT Server ──
                let context = get_app_context(env)?;
                let id_bytes = env.byte_array_from_slice(&id_hash)
                    .map_err(|e| format!("byte_array: {e}"))?;

                let server_cls = find_app_class(env, "org.ratspeak.android.RatspeakBleServer")
                    .map_err(|e| format!("RatspeakBleServer class: {e}"))?;
                let opened = env.call_static_method(
                    server_cls, "openGattServer",
                    "(Landroid/content/Context;[B)Z",
                    &[JValue::Object(context), JValue::Object(JObject::from(id_bytes))],
                ).map_err(|e| format!("openGattServer: {e}"))?.z().unwrap_or(false);

                if !opened {
                    tracing::warn!("Android BLE Peripheral: GATT server failed to open");
                } else {
                    tracing::info!("Android BLE Peripheral: GATT server opened");
                }

                // ── 2. Start BLE Advertising ──
                // Use BluetoothManager.getAdapter() (modern API), not the
                // deprecated BluetoothAdapter.getDefaultAdapter() which
                // throws SecurityException on Android 12+ without the
                // BLUETOOTH_CONNECT permission and is removed on some 14+
                // vendor builds.
                let adapter = get_bluetooth_adapter(env, context)?;

                let advertiser = env.call_method(
                    adapter, "getBluetoothLeAdvertiser",
                    "()Landroid/bluetooth/le/BluetoothLeAdvertiser;", &[],
                ).map_err(|e| { jni_clear(env); format!("getBluetoothLeAdvertiser: {e}") })?
                 .l().map_err(|e| format!("{e}"))?;
                if advertiser.is_null() {
                    return Err("BluetoothLeAdvertiser unavailable (multi-adv not supported?)".into());
                }

                // Build AdvertiseSettings
                let settings_cls = env.find_class("android/bluetooth/le/AdvertiseSettings$Builder")
                    .map_err(|e| format!("{e}"))?;
                let builder = env.new_object(settings_cls, "()V", &[]).map_err(|e| format!("{e}"))?;
                env.call_method(builder, "setAdvertiseMode",
                    "(I)Landroid/bluetooth/le/AdvertiseSettings$Builder;",
                    &[JValue::Int(1)]).ok(); // BALANCED
                jni_clear(env);
                env.call_method(builder, "setTxPowerLevel",
                    "(I)Landroid/bluetooth/le/AdvertiseSettings$Builder;",
                    &[JValue::Int(3)]).ok(); // HIGH
                jni_clear(env);
                env.call_method(builder, "setConnectable",
                    "(Z)Landroid/bluetooth/le/AdvertiseSettings$Builder;",
                    &[JValue::Bool(1)]).ok();
                jni_clear(env);
                let settings = env.call_method(builder, "build",
                    "()Landroid/bluetooth/le/AdvertiseSettings;", &[])
                    .map_err(|e| { jni_clear(env); format!("{e}") })?
                    .l().map_err(|e| format!("{e}"))?;

                // Advertise only the primary Ratspeak service UUID. Two
                // 128-bit UUIDs (32 bytes) overflow the 31-byte BLE 4.x
                // advertising PDU and the advertiser reports
                // ADVERTISE_FAILED_DATA_TOO_LARGE. Columba remains registered
                // as a GATT service and is discovered after connect.
                let data_cls = env.find_class("android/bluetooth/le/AdvertiseData$Builder")
                    .map_err(|e| format!("{e}"))?;
                let data_b = env.new_object(data_cls, "()V", &[]).map_err(|e| format!("{e}"))?;

                let uuid_cls = env.find_class("java/util/UUID").map_err(|e| format!("{e}"))?;
                let puuid_cls = env.find_class("android/os/ParcelUuid").map_err(|e| format!("{e}"))?;

                let r_str = env.new_string(RATSPEAK_SERVICE_UUID.to_string()).map_err(|e| format!("{e}"))?;
                let r_uuid = env.call_static_method(uuid_cls, "fromString",
                    "(Ljava/lang/String;)Ljava/util/UUID;",
                    &[JValue::Object(r_str.into())])
                    .map_err(|e| { jni_clear(env); format!("{e}") })?
                    .l().map_err(|e| format!("{e}"))?;
                let r_puuid = env.new_object(puuid_cls, "(Ljava/util/UUID;)V",
                    &[JValue::Object(r_uuid)]).map_err(|e| format!("{e}"))?;
                env.call_method(data_b, "addServiceUuid",
                    "(Landroid/os/ParcelUuid;)Landroid/bluetooth/le/AdvertiseData$Builder;",
                    &[JValue::Object(r_puuid)]).ok();
                jni_clear(env);

                let ad_data = env.call_method(data_b, "build",
                    "()Landroid/bluetooth/le/AdvertiseData;", &[])
                    .map_err(|e| { jni_clear(env); format!("{e}") })?
                    .l().map_err(|e| format!("{e}"))?;

                // Create AdvertiseCallback
                let callback_cls = find_app_class(env, "org.ratspeak.android.RatspeakAdvertiseCallback")
                    .map_err(|e| format!("RatspeakAdvertiseCallback class not found: {e}"))?;
                let callback = env.new_object(callback_cls, "()V", &[])
                    .map_err(|e| { jni_clear(env); format!("RatspeakAdvertiseCallback init: {e}") })?;
                let callback_ref = env.new_global_ref(callback).map_err(|e| format!("{e}"))?;

                env.call_method(advertiser, "startAdvertising",
                    "(Landroid/bluetooth/le/AdvertiseSettings;Landroid/bluetooth/le/AdvertiseData;Landroid/bluetooth/le/AdvertiseCallback;)V",
                    &[JValue::Object(settings), JValue::Object(ad_data), JValue::Object(callback_ref.as_obj())])
                    .map_err(|e| { jni_clear(env); format!("startAdvertising: {e}") })?;

                if let Ok(mut slot) = advertiser_slot().lock() {
                    *slot = Some(env.new_global_ref(advertiser).map_err(|e| format!("{e}"))?);
                }
                if let Ok(mut slot) = callback_slot().lock() {
                    *slot = Some(callback_ref);
                }
                tracing::info!("Android BLE Peripheral: advertising started");
                Ok(())
            })
        }).await.map_err(|e| format!("{e}"))?
    }

    pub async fn stop_advertising() -> Result<(), String> {
        clear_inbound_channel();
        peer_client_disconnect_all();
        tokio::task::spawn_blocking(|| {
            // Close GATT server
            with_env(|env| {
                let server_cls = find_app_class(env, "org.ratspeak.android.RatspeakBleServer")
                    .map_err(|e| format!("{e}"))?;
                env.call_static_method(server_cls, "closeGattServer", "()V", &[])
                    .map_err(|e| format!("closeGattServer: {e}"))?;
                Ok(())
            })
            .ok();

            // Stop advertising
            let adv_ref = advertiser_slot()
                .lock()
                .ok()
                .and_then(|mut slot| slot.take());
            let callback_ref = callback_slot().lock().ok().and_then(|mut slot| slot.take());
            if let Some(adv) = adv_ref {
                with_env(|env| {
                    let cb = callback_ref
                        .as_ref()
                        .map(|r| r.as_obj())
                        .unwrap_or(JObject::null());
                    env.call_method(
                        adv.as_obj(),
                        "stopAdvertising",
                        "(Landroid/bluetooth/le/AdvertiseCallback;)V",
                        &[JValue::Object(cb)],
                    )
                    .map_err(|e| format!("{e}"))?;
                    tracing::info!("Android BLE Peripheral: advertising stopped");
                    Ok(())
                })?;
            }
            Ok(())
        })
        .await
        .map_err(|e| format!("{e}"))?
    }

    // ── JNI native methods called by RatspeakGattCallback.kt ──
    //
    // Use raw jni::sys types in extern signatures to avoid lifetime issues
    // (JObject<'a> / JString<'a> can't be expressed in extern "system" fns).

    /// Called when a remote peer writes data to the RX characteristic.
    /// The `address` parameter is the source BluetoothDevice MAC; we tag the
    /// inbound packet with it so the consumer can keep per-peer reassembly state
    /// and skip relaying the packet back to the same peer (anti-loop).
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_ratspeak_android_RatspeakGattCallback_nativeBleGattDataReceived(
        env: jni::JNIEnv,
        _this: jni::sys::jobject,
        address: jni::sys::jstring,
        data: jni::sys::jbyteArray,
    ) {
        let addr = jstring_to_owned(&env, address);
        if let Ok(bytes) = env.convert_byte_array(data) {
            on_gatt_data_received(addr, bytes);
        }
    }

    /// Called when a remote peer connects to the GATT server.
    /// Wired into the BlePeerEvent dispatcher for real-time connect events.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_ratspeak_android_RatspeakGattCallback_nativeBleGattPeerConnected(
        env: jni::JNIEnv,
        _this: jni::sys::jobject,
        address: jni::sys::jstring,
    ) {
        let addr = jstring_to_owned(&env, address);
        if !addr.is_empty() {
            tracing::info!(peer = %addr, "Android GATT: peer connected");
            super::dispatch_event(BlePeerEvent::Connected {
                address: addr,
                identity_hash: String::new(),
                protocol: PeerProtocol::Ratspeak,
            });
        }
    }

    /// Remote peer enabled CCCD on the TX characteristic. Triggers an
    /// immediate announce so identity is exchanged on first contact.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_ratspeak_android_RatspeakGattCallback_nativeBleGattPeerSubscribed(
        env: jni::JNIEnv,
        _this: jni::sys::jobject,
        address: jni::sys::jstring,
    ) {
        let addr = jstring_to_owned(&env, address);
        if !addr.is_empty() {
            tracing::info!(peer = %addr, "Android GATT: peer subscribed to TX");
            super::dispatch_event(BlePeerEvent::SubscribeReady { address: addr });
        }
    }

    /// Called when a remote peer disconnects from the GATT server.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_ratspeak_android_RatspeakGattCallback_nativeBleGattPeerDisconnected(
        env: jni::JNIEnv,
        _this: jni::sys::jobject,
        address: jni::sys::jstring,
    ) {
        let addr = jstring_to_owned(&env, address);
        if !addr.is_empty() {
            tracing::info!(peer = %addr, "Android GATT: peer disconnected");
            super::dispatch_event(BlePeerEvent::Disconnected {
                address: addr,
                reason: "GATT disconnect".into(),
            });
        }
    }

    /// Helper: convert a possibly-null jstring into an owned Rust String,
    /// falling back to empty on conversion failure.
    fn jstring_to_owned(env: &jni::JNIEnv, raw: jni::sys::jstring) -> String {
        if raw.is_null() {
            return String::new();
        }
        let jstr: jni::objects::JString = jni::objects::JObject::from(raw).into();
        env.get_string(jstr)
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Push a notification to a specific connected GATT-server peer over the named
    /// TX characteristic. Returns false if the JVM bridge is unavailable or the
    /// Kotlin call fails. Used by the spawn function's outbound fan-out.
    pub fn notify_tx(peer_address: &str, char_uuid: Uuid, data: &[u8]) -> bool {
        with_env(|env| {
            let server_cls = find_app_class(env, "org.ratspeak.android.RatspeakBleServer")
                .map_err(|e| format!("RatspeakBleServer class: {e}"))?;
            let addr_str = env
                .new_string(peer_address)
                .map_err(|e| format!("addr string: {e}"))?;
            let uuid_str = env
                .new_string(char_uuid.to_string())
                .map_err(|e| format!("uuid string: {e}"))?;
            let payload = env
                .byte_array_from_slice(data)
                .map_err(|e| format!("byte array: {e}"))?;
            let ok = env
                .call_static_method(
                    server_cls,
                    "notifyTx",
                    "(Ljava/lang/String;Ljava/lang/String;[B)Z",
                    &[
                        JValue::Object(addr_str.into()),
                        JValue::Object(uuid_str.into()),
                        JValue::Object(JObject::from(payload)),
                    ],
                )
                .map_err(|e| format!("notifyTx call: {e}"))?
                .z()
                .unwrap_or(false);
            Ok(ok)
        })
        .unwrap_or(false)
    }

    /// Snapshot of GATT-server-side central addresses currently subscribed to
    /// the named TX characteristic. The fan-out enumerates this list and
    /// filters per peer through the in-process anti-loop map before issuing
    /// individual `notify_tx` calls.
    pub fn subscribed_addresses_for(char_uuid: Uuid) -> Vec<String> {
        with_env(|env| {
            let server_cls = find_app_class(env, "org.ratspeak.android.RatspeakBleServer")
                .map_err(|e| format!("RatspeakBleServer class: {e}"))?;
            let uuid_str = env
                .new_string(char_uuid.to_string())
                .map_err(|e| format!("uuid string: {e}"))?;
            let result = env
                .call_static_method(
                    server_cls,
                    "subscribedAddressesFor",
                    "(Ljava/lang/String;)Ljava/lang/String;",
                    &[JValue::Object(uuid_str.into())],
                )
                .map_err(|e| format!("subscribedAddressesFor call: {e}"))?
                .l()
                .map_err(|e| format!("subscribedAddressesFor result: {e}"))?;
            let jstr: jni::objects::JString = result.into();
            let owned = env
                .get_string(jstr)
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            Ok(super::parse_newline_addresses(&owned))
        })
        .unwrap_or_default()
    }

    /// Snapshot of remote centrals currently connected to our local GATT
    /// server, whether or not they have completed CCCD subscription yet. The
    /// Android central scan loop uses this to avoid initiating a second,
    /// opposite-direction GATT connection to the same phone while its inbound
    /// peripheral-side connection is already live.
    pub fn connected_or_subscribed_addresses() -> Vec<String> {
        with_env(|env| {
            let server_cls = find_app_class(env, "org.ratspeak.android.RatspeakBleServer")
                .map_err(|e| format!("RatspeakBleServer class: {e}"))?;
            let result = env
                .call_static_method(
                    server_cls,
                    "connectedOrSubscribedAddresses",
                    "()Ljava/lang/String;",
                    &[],
                )
                .map_err(|e| format!("connectedOrSubscribedAddresses call: {e}"))?
                .l()
                .map_err(|e| format!("connectedOrSubscribedAddresses result: {e}"))?;
            let jstr: jni::objects::JString = result.into();
            let owned = env
                .get_string(jstr)
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            Ok(super::parse_newline_addresses(&owned))
        })
        .unwrap_or_default()
    }

    /// Broadcast a notification to every subscribed central on the named TX
    /// characteristic, optionally excluding `exclude_address` (used by the
    /// anti-loop filter to skip echoing a packet back to the peer it arrived
    /// from). Returns the number of subscribers we attempted to notify.
    #[allow(dead_code)]
    pub fn broadcast_notify_tx(char_uuid: Uuid, data: &[u8], exclude_address: Option<&str>) -> i32 {
        with_env(|env| {
            let server_cls = find_app_class(env, "org.ratspeak.android.RatspeakBleServer")
                .map_err(|e| format!("RatspeakBleServer class: {e}"))?;
            let uuid_str = env
                .new_string(char_uuid.to_string())
                .map_err(|e| format!("uuid string: {e}"))?;
            let payload = env
                .byte_array_from_slice(data)
                .map_err(|e| format!("byte array: {e}"))?;
            let exclude_obj = match exclude_address {
                Some(a) => JObject::from(
                    env.new_string(a)
                        .map_err(|e| format!("exclude string: {e}"))?,
                ),
                None => JObject::null(),
            };
            let count = env
                .call_static_method(
                    server_cls,
                    "broadcastTx",
                    "(Ljava/lang/String;[BLjava/lang/String;)I",
                    &[
                        JValue::Object(uuid_str.into()),
                        JValue::Object(JObject::from(payload)),
                        JValue::Object(exclude_obj),
                    ],
                )
                .map_err(|e| format!("broadcastTx call: {e}"))?
                .i()
                .unwrap_or(0);
            Ok(count)
        })
        .unwrap_or(0)
    }

    // ── Native Central role (Kotlin RatspeakBlePeerClient) ──
    //
    // btleplug's Android backend is broken on Android 14+ (deprecated
    // `BluetoothAdapter.getDefaultAdapter()` and `connectGatt(null, ...)`),
    // so we drive the Central role through a native Kotlin GATT client just
    // like RNode BLE does. The Rust side owns the peer-connection state
    // machine; the Kotlin side just hosts GATT plumbing and forwards bytes.

    /// Inbound from a peer client (we connected as Central). Funnels into the
    /// same per-peer reassembly channel the GATT server uses — the consumer
    /// in `spawn_ble_peer_interface` keys off `address` so packets from the
    /// two roles never collide.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_ratspeak_android_RatspeakBlePeerClient_nativePeerClientDataReceived(
        env: jni::JNIEnv,
        _this: jni::sys::jobject,
        address: jni::sys::jstring,
        data: jni::sys::jbyteArray,
    ) {
        let addr = jstring_to_owned(&env, address);
        if let Ok(bytes) = env.convert_byte_array(data) {
            on_gatt_data_received(addr, bytes);
        }
    }

    /// A peer client connection dropped (centrally-initiated side).
    /// We emit a Disconnected event so the mesh-state task can prune it
    /// without waiting for a keepalive miss.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_ratspeak_android_RatspeakBlePeerClient_nativePeerClientDisconnected(
        env: jni::JNIEnv,
        _this: jni::sys::jobject,
        address: jni::sys::jstring,
    ) {
        let addr = jstring_to_owned(&env, address);
        if !addr.is_empty() {
            tracing::info!(peer = %addr, "Android peer client: disconnected");
            // Flip the central task's per-peer `online` flag so its write loop
            // exits and the connected_addrs entry gets pruned on the next cycle.
            signal_peer_offline(&addr);
            super::dispatch_event(BlePeerEvent::Disconnected {
                address: addr,
                reason: "peer client GATT disconnect".into(),
            });
        }
    }

    /// Connect → discover services → subscribe to notifications. Identity
    /// flows in via the first signed announce afterwards. Blocking — must
    /// run on `spawn_blocking` because the Kotlin side uses CountDownLatches
    /// that deadlock on the GATT callback thread.
    pub fn peer_client_connect(address: &str) -> Result<(), String> {
        with_env(|env| {
            let context = get_app_context(env)?;
            let cls = find_app_class(env, "org.ratspeak.android.RatspeakBlePeerClient")
                .map_err(|e| format!("RatspeakBlePeerClient class: {e}"))?;
            let addr_str = env
                .new_string(address)
                .map_err(|e| format!("addr string: {e}"))?;
            let ok = env
                .call_static_method(
                    cls,
                    "connectFromNative",
                    "(Landroid/content/Context;Ljava/lang/String;)Z",
                    &[JValue::Object(context), JValue::Object(addr_str.into())],
                )
                .map_err(|e| format!("connectFromNative: {e}"))?
                .z()
                .map_err(|e| format!("{e}"))?;
            if !ok {
                return Err("peer connect failed".into());
            }
            Ok(())
        })
    }

    /// Push outbound bytes to a connected peer (Central side). The caller is
    /// responsible for fragmentation. Returns false if the address has no
    /// live client or the JNI call fails.
    pub fn peer_client_write(address: &str, data: &[u8]) -> bool {
        with_env(|env| {
            let cls = find_app_class(env, "org.ratspeak.android.RatspeakBlePeerClient")
                .map_err(|e| format!("RatspeakBlePeerClient class: {e}"))?;
            let addr_str = env
                .new_string(address)
                .map_err(|e| format!("addr string: {e}"))?;
            let payload = env
                .byte_array_from_slice(data)
                .map_err(|e| format!("byte array: {e}"))?;
            let ok = env
                .call_static_method(
                    cls,
                    "write",
                    "(Ljava/lang/String;[B)Z",
                    &[
                        JValue::Object(addr_str.into()),
                        JValue::Object(JObject::from(payload)),
                    ],
                )
                .map_err(|e| format!("write: {e}"))?
                .z()
                .unwrap_or(false);
            Ok(ok)
        })
        .unwrap_or(false)
    }

    /// Minimum negotiated ATT payload across every central subscribed to
    /// `char_uuid` on our GATT server. Used by the peripheral broadcast
    /// fan-out to size fragments so a single notify reaches everyone.
    /// Falls back to 244 bytes when no subscribers.
    pub fn min_subscribed_payload(char_uuid: Uuid) -> usize {
        const FALLBACK: usize = 244;
        let v = with_env(|env| {
            let cls = find_app_class(env, "org.ratspeak.android.RatspeakBleServer")
                .map_err(|e| format!("RatspeakBleServer class: {e}"))?;
            let uuid_str = env
                .new_string(char_uuid.to_string())
                .map_err(|e| format!("uuid string: {e}"))?;
            let mtu = env
                .call_static_method(
                    cls,
                    "getMinSubscribedPayload",
                    "(Ljava/lang/String;)I",
                    &[JValue::Object(uuid_str.into())],
                )
                .map_err(|e| format!("getMinSubscribedPayload: {e}"))?
                .i()
                .map_err(|e| format!("{e}"))?;
            Ok(mtu)
        })
        .unwrap_or(FALLBACK as i32);
        if v <= 0 { FALLBACK } else { v as usize }
    }

    /// Negotiated payload size (MTU - 3) for the Central-side peer client at
    /// `address`. Returns the conservative 244-byte default if the bridge is
    /// unavailable, the address has no live client, or MTU negotiation hasn't
    /// completed. Used by the per-peer write loop to size fragments.
    pub fn peer_client_mtu(address: &str) -> usize {
        const FALLBACK: usize = 244;
        let v = with_env(|env| {
            let cls = find_app_class(env, "org.ratspeak.android.RatspeakBlePeerClient")
                .map_err(|e| format!("RatspeakBlePeerClient class: {e}"))?;
            let addr_str = env
                .new_string(address)
                .map_err(|e| format!("addr string: {e}"))?;
            let mtu = env
                .call_static_method(
                    cls,
                    "getMtu",
                    "(Ljava/lang/String;)I",
                    &[JValue::Object(addr_str.into())],
                )
                .map_err(|e| format!("getMtu: {e}"))?
                .i()
                .map_err(|e| format!("{e}"))?;
            Ok(mtu)
        })
        .unwrap_or(FALLBACK as i32);
        if v <= 0 { FALLBACK } else { v as usize }
    }

    /// Tear down the peer client connection for `address`. Idempotent.
    pub fn peer_client_disconnect(address: &str) {
        let _ = with_env(|env| {
            let cls = find_app_class(env, "org.ratspeak.android.RatspeakBlePeerClient")
                .map_err(|e| format!("RatspeakBlePeerClient class: {e}"))?;
            let addr_str = env
                .new_string(address)
                .map_err(|e| format!("addr string: {e}"))?;
            env.call_static_method(
                cls,
                "disconnect",
                "(Ljava/lang/String;)V",
                &[JValue::Object(addr_str.into())],
            )
            .map_err(|e| format!("disconnect: {e}"))?;
            Ok::<(), String>(())
        });
    }

    /// Tear down every Android central-side peer client known to the current
    /// BLE Peer runtime. Used during interface stop so disabling the mesh
    /// releases native GATT connections immediately instead of waiting for
    /// later callbacks or scan-loop cleanup.
    pub fn peer_client_disconnect_all() {
        let addrs = peer_online_map()
            .lock()
            .ok()
            .map(|g| g.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for addr in &addrs {
            signal_peer_offline(addr);
            peer_client_disconnect(addr);
        }
        if let Ok(mut g) = peer_online_map().lock() {
            g.clear();
        }
    }

    /// Scan for nearby BLE mesh peers using a service-UUID filter at the
    /// radio firmware level (battery-efficient). Returns
    /// `(address, rssi, protocol)` tuples. Blocking — runs on `spawn_blocking`.
    pub fn peer_scan_mesh(timeout_ms: i64) -> Vec<(String, i16, PeerProtocol)> {
        with_env(|env| {
            let context = get_app_context(env)?;
            let cls = find_app_class(env, "org.ratspeak.android.RatspeakBlePeerClient")
                .map_err(|e| format!("RatspeakBlePeerClient class: {e}"))?;
            let result = env
                .call_static_method(
                    cls,
                    "scanMesh",
                    "(Landroid/content/Context;J)[Ljava/lang/String;",
                    &[JValue::Object(context), JValue::Long(timeout_ms)],
                )
                .map_err(|e| format!("scanMesh: {e}"))?
                .l()
                .map_err(|e| format!("{e}"))?;
            if result.is_null() {
                return Ok(Vec::new());
            }
            let arr = result.into_inner();
            let len = env
                .get_array_length(arr)
                .map_err(|e| format!("array len: {e}"))?;
            let mut out = Vec::with_capacity(len as usize);
            for i in 0..len {
                let item = env
                    .get_object_array_element(arr, i)
                    .map_err(|e| format!("array idx: {e}"))?;
                let s: jni::objects::JString = item.into();
                let owned = env
                    .get_string(s)
                    .map(|js| js.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if owned.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = owned.split('|').collect();
                if parts.len() != 3 {
                    continue;
                }
                let rssi = parts[1].parse::<i16>().unwrap_or(-100);
                let protocol = if parts[2] == "ratspeak" {
                    PeerProtocol::Ratspeak
                } else {
                    PeerProtocol::Columba
                };
                out.push((parts[0].to_string(), rssi, protocol));
            }
            Ok(out)
        })
        .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Linux Peripheral (BlueZ GATT server via bluer)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_peripheral {
    //! Real BLE Peripheral on Linux via the `bluer` crate (BlueZ D-Bus).
    //!
    //! Symmetric counterpart to the Apple/Android peripheral modules: registers
    //! the Ratspeak + Columba GATT services, accepts connections from peer
    //! centrals, funnels inbound writes through a per-process channel that the
    //! spawn function's reassembler consumes (matching the apple/android shape),
    //! and exposes a `notify_tx` for the outbound fan-out.
    //!
    //! Requires BlueZ 5.46+; on older distros the user may need
    //! `Experimental = true` in /etc/bluetooth/main.conf for full GATT server
    //! support. Registration failures are surfaced as clear UI-facing errors.
    use super::*;
    use bluer::adv::Advertisement;
    use bluer::gatt::local::{
        Application, ApplicationHandle, Characteristic, CharacteristicNotifier,
        CharacteristicNotify, CharacteristicNotifyMethod, CharacteristicRead, CharacteristicWrite,
        CharacteristicWriteMethod, Service,
    };
    use std::sync::OnceLock;
    use tokio::sync::Mutex as AsyncMutex;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    /// Per-process inbound channel — write callbacks push (peer_address, data)
    /// pairs that the spawn function's per-peer reassembler consumes.
    type InboundFrame = (String, Vec<u8>);
    type InboundSender = mpsc::Sender<InboundFrame>;
    type InboundReceiver = mpsc::Receiver<InboundFrame>;
    type InboundSenderSlot = std::sync::Mutex<Option<InboundSender>>;
    type InboundReceiverSlot = std::sync::Mutex<Option<InboundReceiver>>;

    static INBOUND_TX: OnceLock<InboundSenderSlot> = OnceLock::new();
    static INBOUND_RX: OnceLock<InboundReceiverSlot> = OnceLock::new();

    /// Per-characteristic notifier registry keyed by TX char UUID. Each value
    /// is the latest bluer `CharacteristicNotifier` handed to us by the most
    /// recent subscribe; we call `.notify(payload)` on it from notify_tx.
    /// `None` means no central is currently subscribed.
    type NotifierMap = Arc<AsyncMutex<HashMap<Uuid, Option<CharacteristicNotifier>>>>;
    static NOTIFIERS: OnceLock<NotifierMap> = OnceLock::new();

    /// App + advertisement handles — held to keep the registration alive for
    /// the lifetime of the interface. Dropping these unregisters everything.
    static HANDLES: OnceLock<
        std::sync::Mutex<Option<(ApplicationHandle, bluer::adv::AdvertisementHandle)>>,
    > = OnceLock::new();

    fn notifier_map() -> &'static NotifierMap {
        NOTIFIERS.get_or_init(|| Arc::new(AsyncMutex::new(HashMap::new())))
    }

    fn handles_slot()
    -> &'static std::sync::Mutex<Option<(ApplicationHandle, bluer::adv::AdvertisementHandle)>> {
        HANDLES.get_or_init(|| std::sync::Mutex::new(None))
    }

    fn inbound_tx_slot() -> &'static InboundSenderSlot {
        INBOUND_TX.get_or_init(|| std::sync::Mutex::new(None))
    }

    fn inbound_rx_slot() -> &'static InboundReceiverSlot {
        INBOUND_RX.get_or_init(|| std::sync::Mutex::new(None))
    }

    fn reset_inbound_channel() {
        let (tx, rx) = mpsc::channel::<InboundFrame>(256);
        if let Ok(mut slot) = inbound_tx_slot().lock() {
            *slot = Some(tx);
        }
        if let Ok(mut slot) = inbound_rx_slot().lock() {
            *slot = Some(rx);
        }
    }

    fn clear_inbound_channel() {
        if let Ok(mut slot) = inbound_tx_slot().lock() {
            *slot = None;
        }
        if let Ok(mut slot) = inbound_rx_slot().lock() {
            *slot = None;
        }
    }

    fn inbound_sender() -> Option<InboundSender> {
        inbound_tx_slot()
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().cloned())
    }

    /// Drain the inbound channel receiver. The spawn function calls this once
    /// at startup and pumps the resulting receiver into the per-peer
    /// reassembler.
    pub fn take_inbound_rx() -> Option<InboundReceiver> {
        inbound_rx_slot().lock().ok().and_then(|mut g| g.take())
    }

    /// Push a notification on the named TX characteristic. Returns true if
    /// there is a live subscriber and the call was queued. The actual
    /// notification I/O happens inside bluer asynchronously; we only drive
    /// the API call here.
    pub fn notify_tx(char_uuid: Uuid, data: &[u8]) -> bool {
        let map = notifier_map();
        let payload = data.to_vec();
        // Take the notifier out so we can call `.notify()` (which takes
        // `&mut self`) without holding the map lock across an await.
        // try_lock failure is rare but not impossible if a subscribe event
        // fires concurrently — log it so operators can correlate "notify
        // disappeared" with "subscriber rolled in" during handoff.
        let notifier_taken = {
            let mut g = match map.try_lock() {
                Ok(g) => g,
                Err(_) => {
                    tracing::warn!(
                        target: "ble_trace",
                        step = "linux_notify.lock_contention",
                        %char_uuid,
                        bytes = data.len(),
                        "Linux BLE notify: notifier map lock contended — dropping payload"
                    );
                    return false;
                }
            };
            g.get_mut(&char_uuid).and_then(|opt| opt.take())
        };
        if let Some(mut n) = notifier_taken {
            let map2 = map.clone();
            tokio::spawn(async move {
                if n.notify(payload).await.is_err() {
                    tracing::warn!(
                        target: "ble_trace",
                        step = "linux_notify.notify_failed",
                        %char_uuid,
                        "Linux BLE notify failed; central likely dropped"
                    );
                    return;
                }
                // Reinsert if the notifier is still live. is_stopped() goes
                // true once the central unsubscribes or disconnects.
                if !n.is_stopped() {
                    let mut g = map2.lock().await;
                    g.insert(char_uuid, Some(n));
                } else {
                    tracing::info!(
                        target: "ble_trace",
                        step = "linux_notify.notifier_stopped",
                        %char_uuid,
                        "Linux BLE: subscriber dropped — notifier retired from registry"
                    );
                }
            });
            true
        } else {
            tracing::debug!(
                target: "ble_trace",
                step = "linux_notify.no_subscriber",
                %char_uuid,
                bytes = data.len(),
                "Linux BLE notify: no subscriber — dropping payload"
            );
            false
        }
    }

    /// Snapshot of TX characteristics currently bound to a notifier sink. The
    /// fan-out uses this to decide whether to fragment + push a payload.
    /// `pub` for symmetry with the Apple/Windows peripherals' equivalent
    /// query — no in-tree caller yet, so the compiler reports it dead.
    #[allow(dead_code)]
    pub fn subscribed_tx_uuids() -> Vec<Uuid> {
        let map = notifier_map();
        match map.try_lock() {
            Ok(g) => g
                .iter()
                .filter(|(_, v)| v.is_some())
                .map(|(k, _)| *k)
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Start GATT server + LE advertising. Must be called from a tokio
    /// runtime context (bluer needs the current dispatcher).
    pub async fn start_advertising(_identity_hash: &[u8]) -> Result<(), String> {
        // Ensure inbound channel exists before any write callback fires.
        // identity_hash is unused: the static ID characteristic was removed as
        // a tracking vector; identity is exchanged via signed announces.
        reset_inbound_channel();

        let session = bluer::Session::new()
            .await
            .map_err(|e| format!("bluer session: {e}"))?;
        let adapter = session
            .default_adapter()
            .await
            .map_err(|e| format!("bluer default adapter: {e}"))?;
        adapter
            .set_powered(true)
            .await
            .map_err(|e| format!("adapter power on: {e}"))?;

        let app = Application {
            services: vec![
                build_service(
                    super::RATSPEAK_SERVICE_UUID,
                    super::RATSPEAK_RX_UUID,
                    super::RATSPEAK_TX_UUID,
                )
                .await,
                build_service(
                    super::COLUMBA_SERVICE_UUID,
                    super::COLUMBA_RX_UUID,
                    super::COLUMBA_TX_UUID,
                )
                .await,
            ],
            ..Default::default()
        };
        let app_handle = match adapter.serve_gatt_application(app).await {
            Ok(h) => h,
            Err(e) => {
                let reason = format!(
                    "Linux BLE peripheral unavailable: serve_gatt_application: {e}. \
                     BlueZ likely needs `Experimental = true` in /etc/bluetooth/main.conf, \
                     then `sudo systemctl restart bluetooth`. Mesh continues central-only."
                );
                super::dispatch_event(super::BlePeerEvent::PeripheralUnavailable {
                    reason: reason.clone(),
                });
                return Err(reason);
            }
        };

        // Advertise only the primary Ratspeak service UUID. Two 128-bit
        // UUIDs (32 bytes) plus AD Flags + local name overflow the 31-byte
        // legacy BLE adv PDU, and BlueZ rejects the advertisement set with
        // kernel mgmt status MGMT_STATUS_INVALID_PARAMS (0x0d) — surfaced
        // in `journalctl -u bluetooth` as `src/advertising.c:add_client_complete()
        // Failed to add advertisement: Invalid Parameters`. Apple
        // (apple_peripheral) and Android (android_peripheral) hit the same
        // limit and already drop Columba from the advertised set; Columba
        // remains registered as a GATT service and is discovered by centrals
        // after connect via primary service discovery.
        let mut service_uuids = std::collections::BTreeSet::new();
        service_uuids.insert(super::RATSPEAK_SERVICE_UUID);
        let adv = Advertisement {
            service_uuids,
            discoverable: Some(true),
            local_name: Some("Ratspeak".into()),
            ..Default::default()
        };
        let adv_handle = match adapter.advertise(adv).await {
            Ok(h) => h,
            Err(e) => {
                let reason = format!(
                    "Linux BLE advertising rejected: {e}. \
                     Check `journalctl -u bluetooth` for the kernel mgmt status — \
                     `Invalid Parameters` typically means the adv data overflowed \
                     31 bytes; other statuses point to BlueZ/controller config. \
                     Mesh continues central-only."
                );
                super::dispatch_event(super::BlePeerEvent::PeripheralUnavailable {
                    reason: reason.clone(),
                });
                return Err(reason);
            }
        };

        if let Ok(mut slot) = handles_slot().lock() {
            *slot = Some((app_handle, adv_handle));
        }
        tracing::info!("Linux BLE Peripheral: GATT app + advertising registered via bluer");
        Ok(())
    }

    async fn build_service(service_uuid: Uuid, rx_uuid: Uuid, tx_uuid: Uuid) -> Service {
        // Inbound RX: peer writes here, we push (peer_addr, data) on the
        // shared channel for the spawn function's reassembler.
        let rx_uuid_for_trace = rx_uuid;
        let rx_char = Characteristic {
            uuid: rx_uuid,
            write: Some(CharacteristicWrite {
                write: true,
                write_without_response: true,
                method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, req| {
                    let addr = req.device_address.to_string();
                    let char_uuid = rx_uuid_for_trace;
                    let byte_len = new_value.len();
                    Box::pin(async move {
                        if let Some(tx) = inbound_sender() {
                            if let Err(e) = tx.try_send((addr.clone(), new_value)) {
                                // Channel full — log so operators see the
                                // backpressure signal instead of finding
                                // silent fragment loss.
                                tracing::warn!(
                                    target: "ble_trace",
                                    step = "linux_rx.channel_full",
                                    peer = %addr,
                                    %char_uuid,
                                    bytes = byte_len,
                                    err = %e,
                                    "Linux BLE RX: inbound channel full, dropping frame"
                                );
                            }
                        }
                        Ok(())
                    })
                })),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Outbound TX: notify on subscribe. bluer hands the callback a
        // `CharacteristicNotifier` per subscribe; we stash it keyed by char
        // UUID so notify_tx can find it. Only the latest subscriber's
        // notifier is kept (one central per TX char in the common mesh case).
        let tx_uuid_for_notify = tx_uuid;
        let tx_char = Characteristic {
            uuid: tx_uuid,
            notify: Some(CharacteristicNotify {
                notify: true,
                method: CharacteristicNotifyMethod::Fun(Box::new(move |notifier| {
                    let uuid = tx_uuid_for_notify;
                    Box::pin(async move {
                        let map = notifier_map();
                        let mut g = map.lock().await;
                        let displaced = g.insert(uuid, Some(notifier)).is_some();
                        tracing::info!(
                            target: "ble_trace",
                            step = "linux_notify.subscribe",
                            char_uuid = %uuid,
                            displaced,
                            "Linux BLE: central subscribed to TX characteristic"
                        );
                    })
                })),
                ..Default::default()
            }),
            ..Default::default()
        };

        // No static ID characteristic: it exposed a MAC-rotation-stable
        // identity read to any connecting scanner (a tracking vector) and was
        // never read by this stack — identity is learned from signed announces.
        Service {
            uuid: service_uuid,
            primary: true,
            characteristics: vec![rx_char, tx_char],
            ..Default::default()
        }
    }

    pub async fn stop_advertising() -> Result<(), String> {
        clear_inbound_channel();
        let dropped_handles = {
            if let Ok(mut slot) = handles_slot().lock() {
                // Dropping the handles unregisters the GATT app + advertising.
                slot.take().is_some()
            } else {
                false
            }
        };
        // Clear notifier sinks — they reference a dropped service handle now.
        // Fall back to the async lock if try_lock is contended so we don't
        // leak a live notifier that would attempt to notify into a retired
        // service. The operation is fast (no await across service ops).
        let cleared_notifiers = {
            let mut g = notifier_map().lock().await;
            let count = g.len();
            g.clear();
            count
        };
        tracing::info!(
            target: "ble_trace",
            step = "linux_peripheral.stop",
            dropped_handles,
            cleared_notifiers,
            "Linux BLE Peripheral: GATT app + advertising deregistered"
        );
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows_peripheral {
    //! Windows BLE Peripheral via WinRT `GattServiceProvider`.
    //!
    //! Works on Windows 10 1809+ for MSIX-packaged apps with the
    //! `bluetoothGenericAttributeProfile` capability. Unpackaged Win32 apps
    //! hit `AccessDenied` on `CreateAsync` — we detect that path and fall
    //! back to central-only with a clear `PeripheralUnavailable` event so
    //! embedding UIs can direct users toward a packaged installer.
    //!
    //! Writes from connected centrals route through a per-process
    //! (peer_address, data) channel that the spawn function's reassembler
    //! consumes, matching the Apple/Android/Linux shape. Notifications are
    //! driven by the outbound fan-out through `notify_tx` — bluer-style,
    //! one notifier per characteristic UUID (the common 1-central-per-char
    //! case; Windows doesn't surface the subscriber identity in the subscribe
    //! event without extra plumbing).
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use tokio::sync::mpsc;
    use windows::Devices::Bluetooth::GenericAttributeProfile::{
        GattCharacteristicProperties, GattLocalCharacteristic, GattLocalCharacteristicParameters,
        GattProtectionLevel, GattServiceProvider, GattServiceProviderAdvertisingParameters,
        GattSubscribedClient,
    };
    use windows::Foundation::TypedEventHandler;
    use windows::Storage::Streams::{DataReader, DataWriter};
    use windows::core::GUID;

    /// Per-process inbound channel. `GattLocalCharacteristic` write events
    /// push `(session_id_string, data)` pairs on the sender; the spawn
    /// function's reassembler consumes them via `take_inbound_rx`.
    type InboundFrame = (String, Vec<u8>);
    type InboundSender = mpsc::Sender<InboundFrame>;
    type InboundReceiver = mpsc::Receiver<InboundFrame>;
    static INBOUND_TX: OnceLock<Mutex<Option<InboundSender>>> = OnceLock::new();
    static INBOUND_RX: OnceLock<Mutex<Option<mpsc::Receiver<(String, Vec<u8>)>>>> = OnceLock::new();

    /// Held state across a single start/stop cycle. `_provider` keeps the
    /// service registration alive; `_tx_chars` keeps the notifiable
    /// characteristics alive; `_handlers` keeps the ValueChanged /
    /// SubscribedClientsChanged event registrations alive (dropping the
    /// registration token leaves the handler orphaned but linked — the
    /// runtime will still invoke it; holding them lets us cleanly detach).
    ///
    /// Stored as a homogeneous `Option<Inner>` under a single mutex so
    /// `stop_advertising` can atomically take + drop the whole bundle.
    struct Inner {
        provider_ratspeak: GattServiceProvider,
        provider_columba: GattServiceProvider,
        tx_chars: std::collections::HashMap<uuid::Uuid, GattLocalCharacteristic>,
    }
    static INNER: OnceLock<Mutex<Option<Inner>>> = OnceLock::new();

    fn inner_slot() -> &'static Mutex<Option<Inner>> {
        INNER.get_or_init(|| Mutex::new(None))
    }

    fn inbound_tx_slot() -> &'static Mutex<Option<InboundSender>> {
        INBOUND_TX.get_or_init(|| Mutex::new(None))
    }

    fn inbound_rx_slot() -> &'static Mutex<Option<InboundReceiver>> {
        INBOUND_RX.get_or_init(|| Mutex::new(None))
    }

    fn reset_inbound_channel() {
        let (tx, rx) = mpsc::channel::<InboundFrame>(256);
        if let Ok(mut slot) = inbound_tx_slot().lock() {
            *slot = Some(tx);
        }
        if let Ok(mut slot) = inbound_rx_slot().lock() {
            *slot = Some(rx);
        }
    }

    fn clear_inbound_channel() {
        if let Ok(mut slot) = inbound_tx_slot().lock() {
            *slot = None;
        }
        if let Ok(mut slot) = inbound_rx_slot().lock() {
            *slot = None;
        }
    }

    fn inbound_sender() -> Option<InboundSender> {
        inbound_tx_slot()
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().cloned())
    }

    pub fn take_inbound_rx() -> Option<mpsc::Receiver<(String, Vec<u8>)>> {
        inbound_rx_slot().lock().ok().and_then(|mut opt| opt.take())
    }

    fn uuid_to_guid(u: uuid::Uuid) -> GUID {
        let (d1, d2, d3, d4) = u.as_fields();
        GUID::from_values(d1, d2, d3, *d4)
    }

    /// Build one service (RX write, TX notify, ID read) and hand back the
    /// started provider. Returns the TX characteristic so the caller can
    /// stash it in the registry for notify_tx lookups.
    ///
    /// Blocking: uses `IAsyncOperation::get()` to wait on WinRT async calls
    /// instead of `.await`. `windows` 0.58 has an awkward `IntoFuture`
    /// story that doesn't cleanly mesh with Rust `.await`; blocking is
    /// fine here because this is called once per start/stop cycle from
    /// `start_advertising`, which wraps the whole thing in
    /// `tokio::task::spawn_blocking` so the executor isn't stalled.
    fn build_and_start_service(
        service_uuid: uuid::Uuid,
        rx_uuid: uuid::Uuid,
        tx_uuid: uuid::Uuid,
    ) -> Result<(GattServiceProvider, GattLocalCharacteristic), String> {
        let svc_guid = uuid_to_guid(service_uuid);
        let create_result = GattServiceProvider::CreateAsync(svc_guid)
            .map_err(|e| format!("GattServiceProvider::CreateAsync call: {e}"))?
            .get()
            .map_err(|e| format!("GattServiceProvider::CreateAsync get: {e}"))?;
        if create_result
            .Error()
            .map_err(|e| format!("CreateResult.Error(): {e}"))?
            .0
            != 0
        {
            return Err(format!(
                "GattServiceProvider creation returned BluetoothError {:?} — likely missing MSIX \
                 packaging or `bluetoothGenericAttributeProfile` capability",
                create_result.Error().ok()
            ));
        }
        let provider = create_result
            .ServiceProvider()
            .map_err(|e| format!("CreateResult.ServiceProvider(): {e}"))?;
        let service = provider
            .Service()
            .map_err(|e| format!("ServiceProvider.Service(): {e}"))?;

        // RX characteristic — client writes here.
        let rx_params =
            GattLocalCharacteristicParameters::new().map_err(|e| format!("rx params: {e}"))?;
        rx_params
            .SetCharacteristicProperties(
                GattCharacteristicProperties::Write
                    | GattCharacteristicProperties::WriteWithoutResponse,
            )
            .map_err(|e| format!("rx props: {e}"))?;
        rx_params
            .SetWriteProtectionLevel(GattProtectionLevel::Plain)
            .map_err(|e| format!("rx write protection: {e}"))?;
        let rx_create = service
            .CreateCharacteristicAsync(uuid_to_guid(rx_uuid), &rx_params)
            .map_err(|e| format!("rx create call: {e}"))?
            .get()
            .map_err(|e| format!("rx create get: {e}"))?;
        let rx_char = rx_create
            .Characteristic()
            .map_err(|e| format!("rx Characteristic(): {e}"))?;
        // Write handler: pull bytes out of the request's Value, push on the
        // inbound channel with the session's DeviceId as peer identifier.
        let handler = TypedEventHandler::<
            GattLocalCharacteristic,
            windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs,
        >::new(move |_sender, args| {
            let args = match args {
                Some(a) => a,
                None => return Ok(()),
            };
            let deferral = args.GetDeferral().ok();
            let session = args.Session()?;
            // BluetoothDeviceId isn't stringable directly; go through its
            // HSTRING `.Id()`, then use HSTRING's Display impl
            // (UTF-16 lossy) via ToString. Used purely as a peer-address
            // key for fan-out / anti-loop — format just needs to be stable
            // per device for the duration of the session.
            let device_id = session
                .DeviceId()
                .ok()
                .and_then(|d| d.Id().ok())
                .map(|s| s.to_string())
                .unwrap_or_default();
            let request = args.GetRequestAsync()?.get()?;
            let buf = request.Value()?;
            let reader = DataReader::FromBuffer(&buf)?;
            let len = reader.UnconsumedBufferLength()? as usize;
            let mut bytes = vec![0u8; len];
            reader.ReadBytes(&mut bytes)?;
            if let Some(tx) = inbound_sender() {
                if let Err(e) = tx.try_send((device_id.clone(), bytes)) {
                    tracing::warn!(
                        target: "ble_trace",
                        step = "windows_rx.channel_full",
                        peer = %device_id,
                        err = %e,
                        "Windows BLE RX: inbound channel full, dropping frame"
                    );
                }
            }
            let _ = request.Respond();
            if let Some(d) = deferral {
                let _ = d.Complete();
            }
            Ok(())
        });
        rx_char
            .WriteRequested(&handler)
            .map_err(|e| format!("rx WriteRequested subscribe: {e}"))?;

        // TX characteristic — we push notifications here via notify_tx.
        let tx_params =
            GattLocalCharacteristicParameters::new().map_err(|e| format!("tx params: {e}"))?;
        tx_params
            .SetCharacteristicProperties(
                GattCharacteristicProperties::Notify | GattCharacteristicProperties::Read,
            )
            .map_err(|e| format!("tx props: {e}"))?;
        tx_params
            .SetReadProtectionLevel(GattProtectionLevel::Plain)
            .map_err(|e| format!("tx read protection: {e}"))?;
        let tx_create = service
            .CreateCharacteristicAsync(uuid_to_guid(tx_uuid), &tx_params)
            .map_err(|e| format!("tx create call: {e}"))?
            .get()
            .map_err(|e| format!("tx create get: {e}"))?;
        let tx_char = tx_create
            .Characteristic()
            .map_err(|e| format!("tx Characteristic(): {e}"))?;
        // Subscribe log so operators can correlate "notify failed" with
        // "no subscribers yet".
        let char_uuid_for_log = tx_uuid;
        let sub_handler =
            TypedEventHandler::<GattLocalCharacteristic, windows::core::IInspectable>::new(
                move |sender, _args| {
                    let count = match sender {
                        Some(c) => c.SubscribedClients().and_then(|v| v.Size()).unwrap_or(0),
                        None => 0,
                    };
                    tracing::info!(
                        target: "ble_trace",
                        step = "windows_notify.subscribers_changed",
                        char_uuid = %char_uuid_for_log,
                        count,
                        "Windows BLE: subscribers changed"
                    );
                    Ok(())
                },
            );
        tx_char
            .SubscribedClientsChanged(&sub_handler)
            .map_err(|e| format!("tx SubscribedClientsChanged subscribe: {e}"))?;

        // No static ID characteristic: it exposed a MAC-rotation-stable
        // identity read to any connecting scanner (a tracking vector) and was
        // never read by this stack — identity is learned from signed announces.

        // Advertise the service.
        let adv_params = GattServiceProviderAdvertisingParameters::new()
            .map_err(|e| format!("adv params: {e}"))?;
        adv_params
            .SetIsConnectable(true)
            .map_err(|e| format!("adv IsConnectable: {e}"))?;
        adv_params
            .SetIsDiscoverable(true)
            .map_err(|e| format!("adv IsDiscoverable: {e}"))?;
        provider
            .StartAdvertisingWithParameters(&adv_params)
            .map_err(|e| format!("StartAdvertising: {e}"))?;

        Ok((provider, tx_char))
    }

    pub async fn start_advertising(_identity_hash: &[u8]) -> Result<(), String> {
        reset_inbound_channel();

        // WinRT GATT setup uses `.get()` internally (see
        // build_and_start_service) because windows 0.58 `IAsyncOperation`
        // doesn't play well with `.await`. Hop to spawn_blocking so the
        // tokio executor isn't parked for the ~tens of ms each service
        // registration takes.

        // Attempt Ratspeak service first. If CreateAsync fails because the
        // app is unpackaged (AccessDenied), surface a user-friendly error
        // and bail — further service creates would just repeat the failure.
        let ratspeak = match tokio::task::spawn_blocking(move || {
            build_and_start_service(
                super::RATSPEAK_SERVICE_UUID,
                super::RATSPEAK_RX_UUID,
                super::RATSPEAK_TX_UUID,
            )
        })
        .await
        .map_err(|e| format!("Ratspeak GATT spawn_blocking join: {e}"))?
        {
            Ok(r) => r,
            Err(e) => {
                super::dispatch_event(BlePeerEvent::PeripheralUnavailable {
                    reason: format!(
                        "Windows BLE peripheral unavailable (install the MSIX build for discoverability): {e}"
                    ),
                });
                return Err(e);
            }
        };
        let columba = tokio::task::spawn_blocking(move || {
            build_and_start_service(
                super::COLUMBA_SERVICE_UUID,
                super::COLUMBA_RX_UUID,
                super::COLUMBA_TX_UUID,
            )
        })
        .await
        .map_err(|e| format!("Columba GATT spawn_blocking join: {e}"))?
        .map_err(|e| format!("Columba compat service failed: {e}"))?;

        let mut tx_chars = std::collections::HashMap::new();
        tx_chars.insert(super::RATSPEAK_TX_UUID, ratspeak.1);
        tx_chars.insert(super::COLUMBA_TX_UUID, columba.1);

        let inner = Inner {
            provider_ratspeak: ratspeak.0,
            provider_columba: columba.0,
            tx_chars,
        };
        if let Ok(mut slot) = inner_slot().lock() {
            *slot = Some(inner);
        }
        tracing::info!(
            target: "ble_trace",
            step = "windows_peripheral.start",
            "Windows BLE Peripheral: GattServiceProvider registered + advertising"
        );
        Ok(())
    }

    pub async fn stop_advertising() -> Result<(), String> {
        clear_inbound_channel();
        let inner = {
            if let Ok(mut slot) = inner_slot().lock() {
                slot.take()
            } else {
                None
            }
        };
        let Some(inner) = inner else {
            tracing::debug!(
                target: "ble_trace",
                step = "windows_peripheral.stop.noop",
                "Windows BLE Peripheral: stop_advertising with no active provider"
            );
            return Ok(());
        };
        // Mirror the start path: WinRT GattServiceProvider calls block until
        // the publisher state actually transitions, and on a busy radio the
        // synchronous StopAdvertising() can take long enough to stall the
        // Tokio executor. Drop the providers from inside spawn_blocking so the
        // OS confirms the advertisement is down before this future resolves;
        // otherwise a rapid disable->enable can race with the kernel still
        // releasing the prior publisher.
        if let Err(e) = tokio::task::spawn_blocking(move || {
            if let Err(e) = inner.provider_ratspeak.StopAdvertising() {
                tracing::warn!(
                    target: "ble_trace",
                    step = "windows_peripheral.stop.ratspeak_err",
                    err = %e,
                    "Windows BLE Peripheral: Ratspeak StopAdvertising failed"
                );
            }
            if let Err(e) = inner.provider_columba.StopAdvertising() {
                tracing::warn!(
                    target: "ble_trace",
                    step = "windows_peripheral.stop.columba_err",
                    err = %e,
                    "Windows BLE Peripheral: Columba StopAdvertising failed"
                );
            }
            // Dropping Inner releases the providers + characteristics (their
            // event handlers detach automatically via the WinRT refcount).
            drop(inner);
        })
        .await
        {
            tracing::warn!(
                target: "ble_trace",
                step = "windows_peripheral.stop.join_err",
                err = %e,
                "Windows BLE Peripheral: StopAdvertising spawn_blocking join failed"
            );
        }
        tracing::info!(
            target: "ble_trace",
            step = "windows_peripheral.stop",
            "Windows BLE Peripheral: GattServiceProvider stopped + released"
        );
        Ok(())
    }

    /// Outbound notify on a specific TX characteristic. Broadcasts to all
    /// currently-subscribed clients (Windows doesn't address individual
    /// subscribers from the provider side without per-client plumbing we
    /// don't yet need). Returns true if the notify was queued.
    pub fn notify_tx(char_uuid: uuid::Uuid, data: &[u8]) -> bool {
        let Some(slot) = INNER.get() else {
            return false;
        };
        let guard = match slot.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let Some(inner) = guard.as_ref() else {
            return false;
        };
        let Some(tx_char) = inner.tx_chars.get(&char_uuid) else {
            return false;
        };
        let writer = match DataWriter::new() {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(
                    target: "ble_trace",
                    step = "windows_notify.writer_err",
                    %char_uuid,
                    err = %e,
                    "Windows BLE notify: DataWriter::new failed"
                );
                return false;
            }
        };
        if let Err(e) = writer.WriteBytes(data) {
            tracing::warn!(
                target: "ble_trace",
                step = "windows_notify.write_bytes_err",
                %char_uuid,
                err = %e,
                "Windows BLE notify: WriteBytes failed"
            );
            return false;
        }
        let buf = match writer.DetachBuffer() {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    target: "ble_trace",
                    step = "windows_notify.detach_err",
                    %char_uuid,
                    err = %e,
                    "Windows BLE notify: DetachBuffer failed"
                );
                return false;
            }
        };
        match tx_char.NotifyValueAsync(&buf) {
            Ok(_op) => true,
            Err(e) => {
                tracing::warn!(
                    target: "ble_trace",
                    step = "windows_notify.notify_err",
                    %char_uuid,
                    err = %e,
                    "Windows BLE notify: NotifyValueAsync failed"
                );
                false
            }
        }
    }

    /// Best-effort count of currently-subscribed clients across both TX
    /// characteristics. Used by the fan-out to decide whether to fragment.
    #[allow(dead_code)]
    pub fn subscribed_client_count(char_uuid: uuid::Uuid) -> u32 {
        let Some(slot) = INNER.get() else {
            return 0;
        };
        let guard = match slot.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        let Some(inner) = guard.as_ref() else {
            return 0;
        };
        let Some(tx_char) = inner.tx_chars.get(&char_uuid) else {
            return 0;
        };
        tx_char
            .SubscribedClients()
            .and_then(|v| v.Size())
            .unwrap_or(0)
    }

    /// Silence unused-variable warnings for types that are imported but only
    /// referenced in specific event-handler paths at compile time.
    #[allow(dead_code)]
    fn _keep_types_alive(_: Option<GattSubscribedClient>) {}
}

// ---------------------------------------------------------------------------
// Spawn — dual-mode mesh interface
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Central role — peer connection via btleplug
// ---------------------------------------------------------------------------

/// GATT connection to a mesh peer (Central role) — btleplug-typed, used on
/// Linux + Windows. Apple platforms have a parallel native pipeline rooted
/// in [`crate::ble_central_apple_connect`] (because btleplug allocates its
/// own `CBCentralManager` and two managers in one process don't share
/// peripheral caches on macOS); Android drives the same primitives via JNI
/// in `RatspeakBlePeerClient.kt`.
#[cfg(all(
    feature = "ble",
    not(any(target_os = "android", target_os = "ios", target_os = "macos"))
))]
struct MeshPeerConnection {
    peripheral: btleplug::platform::Peripheral,
    rx_char: btleplug::api::Characteristic,
    tx_char: btleplug::api::Characteristic,
    write_mtu: usize,
    /// Source key used by the anti-loop map. Matches the BLE address
    /// the Central sees so per-payload "do not echo back" filtering aligns
    /// with what the periph_rx consumer records on inbound reassembly.
    ble_address: String,
}

/// Connected btleplug peripherals keyed by BLE address. `peer_read_loop`
/// disconnects on graceful exit, but interface teardown aborts that task
/// before its cleanup runs, so hold clones here to disconnect explicitly —
/// mirrors the Apple/Android `disconnect_all` paths.
#[cfg(all(
    feature = "ble",
    not(any(target_os = "android", target_os = "ios", target_os = "macos"))
))]
fn central_peripherals()
-> &'static std::sync::Mutex<HashMap<String, btleplug::platform::Peripheral>> {
    static REG: std::sync::OnceLock<
        std::sync::Mutex<HashMap<String, btleplug::platform::Peripheral>>,
    > = std::sync::OnceLock::new();
    REG.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

#[cfg(all(
    feature = "ble",
    not(any(target_os = "android", target_os = "ios", target_os = "macos"))
))]
async fn disconnect_central_peripherals() {
    use btleplug::api::Peripheral as _;
    let peripherals: Vec<btleplug::platform::Peripheral> = match central_peripherals().lock() {
        Ok(mut m) => m.drain().map(|(_, p)| p).collect(),
        Err(_) => return,
    };
    for p in peripherals {
        let _ = p.disconnect().await;
    }
}

/// Connect to a discovered mesh peer and subscribe to TX notifications.
///
/// No BLE-level identity exchange. Identity is learned later from the first
/// signed Reticulum announce over the link; sending unframed identity bytes
/// here corrupts the fragment reassembler on first contact.
///
/// Linux + Windows only — see [`MeshPeerConnection`] header for why Apple
/// uses a parallel native path.
#[cfg(all(
    feature = "ble",
    not(any(target_os = "android", target_os = "ios", target_os = "macos"))
))]
async fn connect_mesh_peer(
    adapter: &btleplug::platform::Adapter,
    peer: &BlePeer,
) -> Result<MeshPeerConnection, String> {
    use btleplug::api::{Central, Peripheral as _};

    tracing::info!(
        target: "ble_trace",
        step = "peer.connect_begin",
        address = %peer.ble_address,
        rssi = peer.rssi,
        protocol = ?peer.protocol,
        "BLE mesh: starting connect"
    );

    // Find peripheral by address from the adapter's cached list.
    //
    // Match on `p.address().to_string()` (MAC) rather than
    // `p.id().to_string()` because btleplug's `id()` is platform-
    // dependent — D-Bus path on Linux, MAC on Windows, CB UUID on
    // Apple — while `peer.ble_address` is always populated from
    // `props.address.to_string()` upstream (MAC). Matching on `id()`
    // would never resolve the Linux peer and surface the misleading
    // "Peer X no longer visible" error even though the peripheral was
    // freshly discovered. (Apple uses a separate native central path
    // — see `apple_scan_mesh_peers` — and never enters this loop.)
    let peripherals = adapter
        .peripherals()
        .await
        .map_err(|e| format!("Peripheral list: {e}"))?;
    let peripheral = peripherals
        .into_iter()
        .find(|p| {
            p.address()
                .to_string()
                .eq_ignore_ascii_case(&peer.ble_address)
        })
        .ok_or_else(|| format!("Peer {} no longer visible", peer.ble_address))?;

    // Connect with retry (pattern from ble_rnode.rs)
    let mut last_err = String::new();
    for attempt in 1..=3 {
        match peripheral.connect().await {
            Ok(()) => {
                tracing::info!(
                    target: "ble_trace",
                    step = "peer.connect_ok",
                    address = %peer.ble_address,
                    attempt,
                    "BLE mesh: GATT connect succeeded"
                );
                break;
            }
            Err(e) => {
                last_err = format!("{e}");
                tracing::warn!(
                    target: "ble_trace",
                    step = "peer.connect_fail",
                    attempt,
                    address = %peer.ble_address,
                    error = %e,
                    "BLE mesh connect attempt failed"
                );
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
    if !peripheral.is_connected().await.unwrap_or(false) {
        return Err(format!("Connect failed after 3 attempts: {last_err}"));
    }

    // Discover services
    peripheral
        .discover_services()
        .await
        .map_err(|e| format!("Service discovery: {e}"))?;
    let chars = peripheral.characteristics();
    tracing::info!(
        target: "ble_trace",
        step = "peer.services_discovered",
        address = %peer.ble_address,
        char_count = chars.len(),
        char_uuids = ?chars.iter().map(|c| c.uuid.to_string()).collect::<Vec<_>>(),
        "BLE mesh: GATT services discovered"
    );

    // Find characteristics — try Ratspeak UUIDs first, fall back to Columba
    let (rx_uuid, tx_uuid, protocol) = if peer.protocol == PeerProtocol::Ratspeak {
        (RATSPEAK_RX_UUID, RATSPEAK_TX_UUID, PeerProtocol::Ratspeak)
    } else {
        (COLUMBA_RX_UUID, COLUMBA_TX_UUID, PeerProtocol::Columba)
    };

    let rx_char = chars
        .iter()
        .find(|c| c.uuid == rx_uuid)
        .ok_or_else(|| format!("RX characteristic not found for {:?}", protocol))?
        .clone();
    let tx_char = chars
        .iter()
        .find(|c| c.uuid == tx_uuid)
        .ok_or_else(|| format!("TX characteristic not found for {:?}", protocol))?
        .clone();

    // Subscribe to TX notifications (peer → us)
    peripheral
        .subscribe(&tx_char)
        .await
        .map_err(|e| format!("Subscribe TX: {e}"))?;
    tracing::info!(
        target: "ble_trace",
        step = "peer.subscribed",
        address = %peer.ble_address,
        tx_char = %tx_uuid,
        "BLE mesh: subscribed to peer TX notifications"
    );

    // btleplug 0.11 exposes no negotiated-MTU getter, and there is no length
    // field to detect a stack-side truncation, so we must not assume more than
    // the lowest MTU any real peer negotiates. 182 = the iOS default ATT MTU
    // 185 minus the 3-byte ATT header; every modern BLE stack negotiates at
    // least this, so writes of this size are never silently truncated (the
    // 244 assumption corrupted multi-fragment packets sent to a <247-MTU peer,
    // e.g. an iOS peripheral). Per-peer negotiated sizing here waits on a
    // btleplug MTU API.
    let write_mtu = 182;

    tracing::info!(
        target: "ble_trace",
        step = "peer.connected",
        address = %peer.ble_address,
        protocol = ?protocol,
        "BLE mesh peer connected"
    );

    // Register for explicit disconnect on interface teardown (the read loop's
    // own disconnect is skipped when its task is aborted).
    if let Ok(mut reg) = central_peripherals().lock() {
        reg.insert(peer.ble_address.clone(), peripheral.clone());
    }

    Ok(MeshPeerConnection {
        peripheral,
        rx_char,
        tx_char,
        write_mtu,
        ble_address: peer.ble_address.clone(),
    })
}

/// Per-peer read loop: receive notifications, reassemble fragments, forward
/// to transport. Linux + Windows only — Apple's notify delegate pushes
/// directly into `apple_peripheral::INBOUND_TX` so the global per-peer
/// reassembler handles inbound without a per-connection task.
type PeerWriterRegistry = Arc<tokio::sync::RwLock<HashMap<String, mpsc::Sender<Bytes>>>>;

fn central_writer_key(address: &str) -> String {
    format!("central:{address}")
}

#[cfg(all(
    feature = "ble",
    not(any(target_os = "android", target_os = "ios", target_os = "macos"))
))]
struct PeerReadLoopCtx {
    interface_id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    peer_online: Arc<AtomicBool>,
    rxb: Arc<AtomicU64>,
    peer_writers: PeerWriterRegistry,
    peer_writer_key: String,
    recently_disconnected: RecentlyDisconnected,
    anti_loop: AntiLoopMap,
    link_registry: LinkRegistry,
}

#[cfg(all(
    feature = "ble",
    not(any(target_os = "android", target_os = "ios", target_os = "macos"))
))]
async fn peer_read_loop(conn: MeshPeerConnection, ctx: PeerReadLoopCtx) {
    let PeerReadLoopCtx {
        interface_id,
        transport_tx,
        peer_online,
        rxb,
        peer_writers,
        peer_writer_key,
        recently_disconnected,
        anti_loop,
        link_registry,
    } = ctx;
    let peer_address: String = conn.ble_address.clone();
    use btleplug::api::Peripheral as _;
    use futures::StreamExt;

    let mut notification_stream = match conn.peripheral.notifications().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "BLE mesh notification stream failed");
            peer_online.store(false, Ordering::SeqCst);
            return;
        }
    };

    // Fragment reassembly buffer: maps total_count to per-sequence payload slots.
    let mut reassembly: FragmentReassembly = HashMap::new();
    let mut identity_announced = false;
    let mut missed_keepalives: u32 = 0;

    loop {
        // Global shutdown takes precedence over
        // the per-peer `peer_online` flag. Flipping `peer_online` here as well
        // lets the write-side and scan-side cleanup see the peer as dead on
        // their next tick, matching the keepalive-timeout cleanup path below.
        if !peer_online.load(Ordering::SeqCst) || !running_flag().load(Ordering::SeqCst) {
            peer_online.store(false, Ordering::SeqCst);
            break;
        }

        let notification = tokio::select! {
            n = notification_stream.next() => n,
            _ = tokio::time::sleep(KEEPALIVE_INTERVAL) => {
                // Send keepalive ping (1-byte 0x00)
                if let Err(e) = conn.peripheral.write(
                    &conn.rx_char, &[0x00],
                    btleplug::api::WriteType::WithoutResponse
                ).await {
                    missed_keepalives += 1;
                    tracing::warn!(
                        target: "ble_trace",
                        step = "keepalive.tx_fail",
                        peer = %conn.ble_address,
                        missed = missed_keepalives,
                        err = %e,
                        "keepalive write failed"
                    );
                    if missed_keepalives >= KEEPALIVE_MAX_MISSES {
                        tracing::warn!(
                            target: "ble_trace",
                            step = "keepalive.timeout",
                            peer = %conn.ble_address,
                            missed = missed_keepalives,
                            "BLE mesh peer keepalive timeout, disconnecting"
                        );
                        peer_online.store(false, Ordering::SeqCst);
                        break;
                    }
                } else {
                    if missed_keepalives > 0 {
                        tracing::info!(
                            target: "ble_trace",
                            step = "keepalive.recovered",
                            peer = %conn.ble_address,
                            "keepalive recovered after misses"
                        );
                    }
                    missed_keepalives = 0;
                }
                continue;
            }
        };

        match notification {
            Some(n) if n.uuid == conn.tx_char.uuid => {
                let data = n.value;
                if data.is_empty() {
                    continue;
                }
                missed_keepalives = 0;

                // Keepalive ping (1 byte) — just acknowledge, no transport forward
                if data.len() == 1 && data[0] == 0x00 {
                    continue;
                }

                let complete_packet = consume_ble_frame(data, &mut reassembly);

                // Forward complete packet to transport
                if let Some(raw) = complete_packet {
                    rxb.fetch_add(raw.len() as u64, Ordering::Relaxed);
                    if !identity_announced {
                        if let Some(id_hex) = verified_announce_identity_hex(&raw) {
                            link_registry
                                .write()
                                .await
                                .set_identity(conn.ble_address.clone(), id_hex.clone());
                            dispatch_event(BlePeerEvent::IdentityResolved {
                                address: conn.ble_address.clone(),
                                identity_hash: id_hex,
                            });
                            identity_announced = true;
                        }
                    }
                    // Register the source so the fan-out anti-loop filter
                    // doesn't echo this exact payload back to the peer it
                    // came from.
                    anti_loop_record(&anti_loop, conn.ble_address.clone(), &raw);
                    let msg = TransportMessage::Inbound(rns_transport::messages::InboundPacket {
                        raw: Bytes::from(raw),
                        interface_id,
                        rssi: None,
                        snr: None,
                        q: None,
                    });
                    if transport_tx.send(msg).await.is_err() {
                        peer_online.store(false, Ordering::SeqCst);
                        break;
                    }
                }

                // Clean up timed-out reassembly buffers
                prune_reassembly(&mut reassembly);
            }
            Some(_) => {} // Notification from other characteristic — ignore
            None => {
                tracing::info!("BLE mesh peer notification stream ended");
                peer_online.store(false, Ordering::SeqCst);
                break;
            }
        }
    }

    // Cleanup: disconnect and remove writer
    let _ = conn.peripheral.disconnect().await;
    if let Ok(mut reg) = central_peripherals().lock() {
        reg.remove(&peer_address);
    }
    let mut writers = peer_writers.write().await;
    writers.remove(&peer_writer_key);
    tracing::info!(address = %peer_address, "BLE mesh peer disconnected and cleaned up");

    // Mark this peer as a wanted-reconnect target keyed by BLE address.
    // The scan loop checks this map and uses SCAN_ACTIVE_INTERVAL until
    // either we reconnect or the entry expires. Identity-keyed
    // tracking is gone because the BLE link no longer exchanges identity.
    record_disconnect(&recently_disconnected, &peer_address);
    dispatch_event(BlePeerEvent::Disconnected {
        address: peer_address,
        reason: "central disconnect".into(),
    });
}

/// Per-peer write loop: fragment and write outbound data to peer's RX
/// characteristic via btleplug. Linux + Windows only — Apple's outbound
/// path lives inline in the spawn body and calls
/// `ble_central_apple_connect::write_peer` per fragment.
#[cfg(all(
    feature = "ble",
    not(any(target_os = "android", target_os = "ios", target_os = "macos"))
))]
async fn peer_write_loop(
    peripheral: btleplug::platform::Peripheral,
    rx_char: btleplug::api::Characteristic,
    write_mtu: usize,
    mut rx: mpsc::Receiver<Bytes>,
    peer_online: Arc<AtomicBool>,
    peer_address: String,
    anti_loop: AntiLoopMap,
) {
    // Coarse announce-relay counter: every 5 successful writes we log enough
    // detail to diagnose drop patterns without enabling verbose logging.
    let mut tx_count: u64 = 0;
    // Bounded sleep inside the recv select so the loop wakes even when no
    // outbound data is flowing; without it, global shutdown would leave
    // this task alive until the next packet or the peer's read-loop
    // dropped the write_tx sender. 1s is short enough for teardown to feel
    // immediate and long enough to add no measurable battery cost.
    const SHUTDOWN_POLL: Duration = Duration::from_secs(1);
    loop {
        let data = tokio::select! {
            v = rx.recv() => match v {
                Some(d) => d,
                None => break,
            },
            _ = tokio::time::sleep(SHUTDOWN_POLL) => {
                if !peer_online.load(Ordering::SeqCst)
                    || !running_flag().load(Ordering::SeqCst)
                {
                    peer_online.store(false, Ordering::SeqCst);
                    break;
                }
                continue;
            }
        };
        if !peer_online.load(Ordering::SeqCst) || !running_flag().load(Ordering::SeqCst) {
            peer_online.store(false, Ordering::SeqCst);
            break;
        }

        // Don't echo a packet back to the peer it just came from.
        if !anti_loop_should_send(&anti_loop, &peer_address, &data) {
            continue;
        }

        let fragments = fragment_packet(&data, write_mtu);
        for (idx, frag) in fragments.iter().enumerate() {
            if let Err(e) =
                crate::ble_rnode::ble_write(&peripheral, &rx_char, frag, write_mtu).await
            {
                tracing::warn!(
                    target: "ble_trace",
                    step = "peer.write_fail",
                    peer = %peer_address,
                    tx_count = tx_count,
                    frag_len = frag.len(),
                    err = %e,
                    "BLE mesh peer write failed"
                );
                peer_online.store(false, Ordering::SeqCst);
                return;
            }
            pace_after_ble_fragment(idx, fragments.len()).await;
        }
        tx_count += 1;
        if tx_count % 5 == 0 {
            tracing::info!(
                target: "ble_trace",
                step = "peer.tx_progress",
                peer = %peer_address,
                tx_count = tx_count,
                last_len = data.len(),
                "BLE mesh outbound frames (rolling count)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Spawn
// ---------------------------------------------------------------------------

/// Spawn a BLE Peer-to-Peer mesh interface.
///
/// Starts both Central (scanning + GATT client) and Peripheral (advertising +
/// GATT server) roles simultaneously. Discovered peers are connected,
/// identities exchanged, and raw Reticulum packets flow bidirectionally
/// through the interface — enabling announces, LXMF messages, and all
/// protocol traffic over BLE. Compatible with Columba (Torlando) BLE mesh.
pub async fn spawn_ble_peer_interface(
    config: BlePeerConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    is_foreground: Arc<AtomicBool>,
    foreground_wake: Arc<tokio::sync::Notify>,
    seed_addresses: Vec<String>,
) -> Result<InterfaceHandle, InterfaceError> {
    let name = config.name.clone();

    // Reset the process-wide running flag and advance the session generation
    // so callbacks/tasks from a previous enable cannot outlive this interface.
    let generation = begin_ble_peer_session();
    dispatch_status_changed(PeerState::Starting, 0);

    // Start peripheral (GATT server + advertising)
    if let Err(e) = start_peripheral(&config.identity_hash).await {
        tracing::warn!(name = %name, error = %e, "BLE Peripheral start failed, running Central-only");
    }

    // Anti-loop / source filter: records which peer just delivered each
    // payload so the fan-out skips echoing it back. Shared across the
    // peripheral inbound consumer, the Central read loops, and the fan-out
    // task on every platform.
    let anti_loop = new_anti_loop_map();
    let link_registry: LinkRegistry =
        Arc::new(tokio::sync::RwLock::new(BlePeerLinkRegistry::default()));

    // TX/RX byte counters. Declared up here so the peripheral inbound
    // reassembly task spawned next can clone shared_rxb into its closure.
    let shared_txb = Arc::new(AtomicU64::new(0));
    let shared_rxb = Arc::new(AtomicU64::new(0));

    // Spawn peripheral inbound consumer: receives data written by peers
    // connecting to our GATT server (Peripheral role), reassembles fragments,
    // and forwards complete packets to the transport actor.
    {
        let transport_periph = transport_tx.clone();
        let anti_loop_p = anti_loop.clone();
        let link_registry_p = link_registry.clone();
        // Apple (iOS+macOS) and Android peripheral modules expose a per-process
        // inbound channel populated by their delegate / GATT-server callback.
        // All platform peripheral modules surface a `(peer_id, data)`
        // receiver via `take_inbound_rx`. The per-peer reassembler below
        // drains it and feeds the transport.
        let periph_rx = {
            #[cfg(any(target_os = "ios", target_os = "macos"))]
            {
                apple_peripheral::take_inbound_rx()
            }
            #[cfg(target_os = "android")]
            {
                android_peripheral::take_inbound_rx()
            }
            #[cfg(target_os = "linux")]
            {
                linux_peripheral::take_inbound_rx()
            }
            #[cfg(target_os = "windows")]
            {
                windows_peripheral::take_inbound_rx()
            }
            #[cfg(not(any(
                target_os = "ios",
                target_os = "macos",
                target_os = "android",
                target_os = "linux",
                target_os = "windows"
            )))]
            {
                // No peripheral support on this platform (e.g. BSDs).
                // Central-only mode continues to work; just no inbound
                // channel for peripheral writes to consume.
                None::<tokio::sync::mpsc::Receiver<(String, Vec<u8>)>>
            }
        };
        if let Some(mut rx) = periph_rx {
            let rxb = shared_rxb.clone();
            track_child_task(
                generation,
                tokio::spawn(async move {
                    // Per-peer reassembly: outer key is the source peer identifier
                    // (BluetoothDevice MAC on Android; CBCentral.identifier UUID
                    // string on Apple). Two peers writing fragments concurrently
                    // can no longer corrupt each other's reassembly buffers.
                    type PeerReassembly = FragmentReassembly;
                    let mut reassembly: HashMap<String, PeerReassembly> = HashMap::new();
                    // Identity is learned from the first signed Reticulum announce.
                    // Emit once per peer address so callers can dedupe
                    // central/peripheral views of the same device.
                    let mut identity_announced: std::collections::HashSet<String> =
                        std::collections::HashSet::new();
                    while let Some((peer, data)) = rx.recv().await {
                        if !generation_is_current(generation) {
                            break;
                        }
                        tracing::debug!(
                            target: "ble_trace",
                            step = "reassembly.frame",
                            peer = %peer,
                            len = data.len(),
                            first_byte = data.first().copied().unwrap_or(0),
                            "BLE Peer reassembly: frame received"
                        );
                        if data.is_empty() || (data.len() == 1 && data[0] == 0x00) {
                            continue; // Empty or keepalive
                        }
                        let per_peer = reassembly.entry(peer.clone()).or_default();
                        let complete = consume_ble_frame(data, per_peer);

                        if let Some(raw) = complete {
                            rxb.fetch_add(raw.len() as u64, Ordering::Relaxed);
                            let parse_result = rns_wire::packet::Packet::from_raw(&raw);
                            match &parse_result {
                                Ok(parsed) => tracing::debug!(
                                    target: "ble_trace",
                                    step = "reassembly.complete",
                                    peer = %peer,
                                    len = raw.len(),
                                    packet_type = ?parsed.header.flags.packet_type,
                                    "BLE Peer reassembly: complete packet"
                                ),
                                Err(e) => tracing::debug!(
                                    target: "ble_trace",
                                    step = "reassembly.complete",
                                    peer = %peer,
                                    len = raw.len(),
                                    parse_err = %e,
                                    "BLE Peer reassembly: complete packet (parse failed)"
                                ),
                            }
                            // Identity learning: associate this peer address
                            // with an identity for caller-side dedup, but only
                            // from a signature-verified announce. Binding from
                            // an unverified announce let an in-range attacker
                            // claim a known contact's identity and poison the
                            // dual-role dedup registry.
                            if !identity_announced.contains(&peer) {
                                if let Some(id_hex) = verified_announce_identity_hex(&raw) {
                                    identity_announced.insert(peer.clone());
                                    link_registry_p
                                        .write()
                                        .await
                                        .set_identity(peer.clone(), id_hex.clone());
                                    dispatch_event(BlePeerEvent::IdentityResolved {
                                        address: peer.clone(),
                                        identity_hash: id_hex,
                                    });
                                }
                            }
                            // Record this packet's source so the outbound
                            // fan-out can skip echoing it back to the same peer.
                            anti_loop_record(&anti_loop_p, peer.clone(), &raw);
                            let msg =
                                TransportMessage::Inbound(rns_transport::messages::InboundPacket {
                                    raw: Bytes::from(raw),
                                    interface_id: id,
                                    rssi: None,
                                    snr: None,
                                    q: None,
                                });
                            if transport_periph.send(msg).await.is_err() {
                                break;
                            }
                        }

                        // Drop expired reassembly buffers (per peer, then per fragment-set).
                        for buf in reassembly.values_mut() {
                            prune_reassembly(buf);
                        }
                        reassembly.retain(|_, m| !m.is_empty());
                    }
                }),
            );
        }
    }

    // Outbound channel (transport → interface → BLE peers)
    let (tx, mut app_rx) = mpsc::channel::<Bytes>(64);

    // Shared peer write channels keyed by role/address. Each connected
    // central-side peer gets a write channel; disconnect paths remove the key
    // explicitly so reconnect churn does not grow stale fan-out targets.
    let peer_writers: PeerWriterRegistry = Arc::new(tokio::sync::RwLock::new(HashMap::new()));

    // Write task: forward outbound packets to (a) every peer we connected to as
    // Central via the per-peer write channels, AND (b) every peer that
    // connected to us as Central — i.e. a subscriber on our peripheral TX
    // characteristic — via the platform notify_tx broadcast. Without (b),
    // the mesh is one-way for any pair where only one side initiated as
    // Central, which is exactly half of the symmetric-mesh promise.
    //
    // Per-peer MTU is queried before fragmenting on Android; Apple
    // platforms rely on CoreBluetooth's auto-negotiated min and a safe
    // 182-byte cap (iOS default ATT MTU 185 minus 3 ATT header bytes).
    let txb_w = shared_txb.clone();
    let writers_w = peer_writers.clone();
    let anti_loop_fan = anti_loop.clone();
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    let link_registry_fan = link_registry.clone();
    track_child_task(
        generation,
        tokio::spawn(async move {
            // Apple-side fallback (no per-central API exposed up to us yet).
            // Gated to Apple because the only consumer is the Apple-cfg
            // fragmentation block below — on Linux/Windows the const would
            // be dead.
            #[cfg(any(target_os = "ios", target_os = "macos"))]
            const APPLE_NOTIFY_MTU: usize = 182;

            while let Some(payload) = app_rx.recv().await {
                if !generation_is_current(generation) {
                    break;
                }
                txb_w.fetch_add(payload.len() as u64, Ordering::Relaxed);

                // (a) Centrals we initiated to — peer_write_loop fragments inside
                //     and runs its own per-peer anti-loop check before writing.
                let writer_snapshot = {
                    let readers = writers_w.read().await;
                    readers
                        .iter()
                        .map(|(key, tx)| (key.clone(), tx.clone()))
                        .collect::<Vec<_>>()
                };
                #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
                let central_writer_keys = writer_snapshot
                    .iter()
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                let mut closed_writers = Vec::new();
                for (key, peer_tx) in writer_snapshot {
                    if peer_tx.send(payload.clone()).await.is_err() {
                        closed_writers.push(key);
                    }
                }
                if !closed_writers.is_empty() {
                    let mut writers = writers_w.write().await;
                    for key in closed_writers {
                        writers.remove(&key);
                    }
                }

                // (b) Subscribers on our peripheral TX. Fragment here so each
                //     NOTIFY frame fits the per-peer (Android) or conservative
                //     (Apple) ATT MTU. Enumerate subscribed centrals and skip
                //     any whose address is recorded as the source of this exact
                //     payload (anti-loop).
                #[cfg(any(target_os = "ios", target_os = "macos"))]
                {
                    let rats_subs =
                        apple_peripheral::subscribed_centrals_for_char(RATSPEAK_TX_UUID);
                    let col_subs = apple_peripheral::subscribed_centrals_for_char(COLUMBA_TX_UUID);
                    let frags = fragment_packet(&payload, APPLE_NOTIFY_MTU);
                    tracing::info!(
                        rats_subs = rats_subs.len(),
                        col_subs = col_subs.len(),
                        payload_bytes = payload.len(),
                        frags = frags.len(),
                        "Apple BLE peripheral fan-out: writing outbound"
                    );
                    for (char_uuid, subs, label) in [
                        (RATSPEAK_TX_UUID, &rats_subs, "ratspeak"),
                        (COLUMBA_TX_UUID, &col_subs, "columba"),
                    ] {
                        for addr in subs {
                            let send_on_peripheral = {
                                let links = link_registry_fan.read().await;
                                should_send_peripheral_payload(
                                    &links,
                                    addr,
                                    &central_writer_keys,
                                    &payload,
                                )
                            };
                            if !send_on_peripheral {
                                tracing::debug!(
                                    peer = %addr,
                                    char = label,
                                    "Apple BLE fan-out: central path preferred"
                                );
                                continue;
                            }
                            if !anti_loop_should_send(&anti_loop_fan, addr, &payload) {
                                tracing::info!(peer = %addr, char = label, "Apple BLE fan-out: anti-loop skip");
                                continue;
                            }
                            let mut ok_frags = 0usize;
                            for (idx, frag) in frags.iter().enumerate() {
                                if apple_peripheral::notify_tx(Some(addr), char_uuid, frag) {
                                    ok_frags += 1;
                                }
                                pace_after_ble_fragment(idx, frags.len()).await;
                            }
                            tracing::info!(
                                peer = %addr,
                                total_frags = frags.len(),
                                ok_frags,
                                char = label,
                                "Apple BLE fan-out: notify_tx results"
                            );
                        }
                    }
                }
                #[cfg(target_os = "linux")]
                {
                    // bluer's Notifier is keyed by characteristic only — it does
                    // not surface which central subscribed, so there is NO
                    // per-subscriber anti-loop or dual-role dedupe on this leg
                    // (unlike apple/android). A packet is broadcast to every
                    // subscriber, which means a peer we are ALSO connected to as
                    // Central receives it twice (once here, once on the central
                    // write leg). Transport's packet hashlist dedups the copy so
                    // this is wasted airtime, not misdelivery. Per-subscriber
                    // notify routing (needed to suppress the echo) rides with the
                    // deferred per-peer child-interface work.
                    const LINUX_NOTIFY_MTU: usize = 244;
                    let frags = fragment_packet(&payload, LINUX_NOTIFY_MTU);
                    for (idx, frag) in frags.iter().enumerate() {
                        let _ = linux_peripheral::notify_tx(RATSPEAK_TX_UUID, frag);
                        let _ = linux_peripheral::notify_tx(COLUMBA_TX_UUID, frag);
                        pace_after_ble_fragment(idx, frags.len()).await;
                    }
                    let _ = &anti_loop_fan; // per-subscriber filtering not available here
                }
                #[cfg(target_os = "windows")]
                {
                    // WinRT GattLocalCharacteristic.NotifyValueAsync broadcasts to
                    // every subscribed client; we do not yet track per-client
                    // device ids (NotifyValueForSubscribedClientAsync +
                    // SubscribedClientsChanged), so as on Linux there is NO
                    // per-subscriber anti-loop or dual-role dedupe here. A
                    // dual-role peer receives each packet twice; transport dedups
                    // it, so the cost is airtime only. Per-client routing rides
                    // with the deferred per-peer child-interface work.
                    const WINDOWS_NOTIFY_MTU: usize = 244;
                    let frags = fragment_packet(&payload, WINDOWS_NOTIFY_MTU);
                    for (idx, frag) in frags.iter().enumerate() {
                        let _ = windows_peripheral::notify_tx(RATSPEAK_TX_UUID, frag);
                        let _ = windows_peripheral::notify_tx(COLUMBA_TX_UUID, frag);
                        pace_after_ble_fragment(idx, frags.len()).await;
                    }
                    let _ = &anti_loop_fan; // per-subscriber filtering not available here
                }
                #[cfg(target_os = "android")]
                {
                    // Query the min subscribed payload per characteristic so the
                    // chunk size adapts to the lowest-capacity central, alongside
                    // the per-characteristic subscriber list for anti-loop
                    // addressing.
                    let (rats_mtu, col_mtu, rats_subs, col_subs) =
                        tokio::task::spawn_blocking(|| {
                            (
                                android_peripheral::min_subscribed_payload(RATSPEAK_TX_UUID),
                                android_peripheral::min_subscribed_payload(COLUMBA_TX_UUID),
                                android_peripheral::subscribed_addresses_for(RATSPEAK_TX_UUID),
                                android_peripheral::subscribed_addresses_for(COLUMBA_TX_UUID),
                            )
                        })
                        .await
                        .unwrap_or((182, 182, Vec::new(), Vec::new()));
                    let rats_frags = fragment_packet(&payload, rats_mtu);
                    for addr in &rats_subs {
                        let send_on_peripheral = {
                            let links = link_registry_fan.read().await;
                            should_send_peripheral_payload(
                                &links,
                                addr,
                                &central_writer_keys,
                                &payload,
                            )
                        };
                        if !send_on_peripheral {
                            continue;
                        }
                        if !anti_loop_should_send(&anti_loop_fan, addr, &payload) {
                            continue;
                        }
                        let addr_owned = addr.clone();
                        let frags_owned = rats_frags.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            let total = frags_owned.len();
                            for (idx, frag) in frags_owned.iter().enumerate() {
                                let _ = android_peripheral::notify_tx(
                                    &addr_owned,
                                    RATSPEAK_TX_UUID,
                                    frag,
                                );
                                sleep_after_ble_fragment_blocking(idx, total);
                            }
                        })
                        .await;
                    }
                    let col_frags = fragment_packet(&payload, col_mtu);
                    for addr in &col_subs {
                        let send_on_peripheral = {
                            let links = link_registry_fan.read().await;
                            should_send_peripheral_payload(
                                &links,
                                addr,
                                &central_writer_keys,
                                &payload,
                            )
                        };
                        if !send_on_peripheral {
                            continue;
                        }
                        if !anti_loop_should_send(&anti_loop_fan, addr, &payload) {
                            continue;
                        }
                        let addr_owned = addr.clone();
                        let frags_owned = col_frags.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            let total = frags_owned.len();
                            for (idx, frag) in frags_owned.iter().enumerate() {
                                let _ = android_peripheral::notify_tx(
                                    &addr_owned,
                                    COLUMBA_TX_UUID,
                                    frag,
                                );
                                sleep_after_ble_fragment_blocking(idx, total);
                            }
                        })
                        .await;
                    }
                }
            }
        }),
    );

    // Shared "recently disconnected" registry. Lets the scan loop
    // prioritize reconnecting to peers we know about, and applies an
    // exponential-backoff window after repeated failures.
    //
    // Seeded from persisted recently-disconnected addresses so a fresh process
    // launch immediately prefers peers from the previous session, instead of
    // waiting to observe a disconnect first.
    let recently_disconnected = new_recently_disconnected();
    seed_recently_disconnected(&recently_disconnected, seed_addresses);

    // Main mesh management task — scan, discover, connect, manage peers.
    //
    // Three implementations:
    //   * Linux + Windows: btleplug (BlueZ / WinRT) — the cross-platform
    //     crate works fine on those platforms.
    //   * Apple (iOS + macOS): bypass btleplug entirely. Scan goes through
    //     `ble_central_apple` (custom CBCentralManager for AllowDuplicates)
    //     and connect through `ble_central_apple_connect` (objc2 native
    //     CBPeripheral lifecycle). This mirrors Android's all-native pipeline
    //     and exists because btleplug allocates its own CBCentralManager —
    //     two managers in one process don't share peripheral caches on macOS,
    //     so every connect attempt resolved to "Peer X no longer visible".
    //   * Android: native Kotlin RatspeakBlePeerClient via JNI (btleplug's
    //     Android backend is broken on 14+, same issue as RNode).
    #[cfg(all(
        feature = "ble",
        not(target_os = "android"),
        not(any(target_os = "ios", target_os = "macos"))
    ))]
    let read_task = {
        let rxb = shared_rxb.clone();
        let transport = transport_tx.clone();
        let recently_disc = recently_disconnected.clone();
        let mesh_name = name.clone();
        let writers = peer_writers.clone();
        let anti_loop = anti_loop.clone();
        let wake = foreground_wake.clone();

        tokio::spawn(async move {
            // Connected peers keyed by BLE address. Identity-keyed dedupe
            // lives at the transport layer once signed announces arrive.
            let mut connected_addrs: HashMap<String, Arc<AtomicBool>> = HashMap::new();
            let mut scan_interval = SCAN_ACTIVE_INTERVAL;

            // Get adapter once, reuse for all scans.
            let adapter = match crate::ble_rnode::get_adapter().await {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!(error = %e, "BLE mesh: failed to get adapter, Central role disabled");
                    // Keep running (Peripheral role may still work)
                    loop {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    }
                }
            };

            loop {
                if !generation_is_current(generation) {
                    tracing::info!("BLE mesh Central scan loop: shutdown signal, exiting");
                    break;
                }

                // Clean up disconnected peers
                let previous_peer_count = connected_addrs.len();
                connected_addrs.retain(|addr, online| {
                    let alive = online.load(Ordering::SeqCst);
                    if !alive {
                        tracing::info!(
                            target: "ble_trace",
                            step = "peer.lost",
                            address = %addr,
                            "BLE mesh peer connection ended \u{2014} dropping from connected set"
                        );
                    }
                    alive
                });
                if connected_addrs.len() != previous_peer_count {
                    dispatch_status_changed(
                        peer_state_for_count(connected_addrs.len()),
                        connected_addrs.len(),
                    );
                }

                // Drop "recently disconnected" entries that have aged out.
                prune_recently_disconnected(&recently_disc);
                // Drop anti-loop dedupe entries past their 30s TTL.
                anti_loop_prune(&anti_loop);

                // Scan for mesh peers. Pass the central loop's adapter so the
                // peripheral registry stays consistent between scan and connect
                // -- using a freshly-created adapter inside scan_mesh_peers
                // would split caches and produce "Peer X no longer visible" on
                // the connect attempt. Same root cause class as the macOS
                // bypass at the central scan loop above.
                match scan_mesh_peers_shared(&adapter, 3).await {
                    Ok(peers) => {
                        // Active scan if we either saw new peers OR have a
                        // wanted-reconnect entry that's not in backoff.
                        let next_interval =
                            if !peers.is_empty() || has_wanted_reconnects(&recently_disc) {
                                SCAN_ACTIVE_INTERVAL
                            } else {
                                SCAN_IDLE_INTERVAL
                            };
                        if next_interval != scan_interval {
                            tracing::info!(
                                target: "ble_trace",
                                step = "scan.interval_changed",
                                prev_ms = scan_interval.as_millis() as u64,
                                next_ms = next_interval.as_millis() as u64,
                                scanned_peer_count = peers.len(),
                                wanted_reconnects = has_wanted_reconnects(&recently_disc),
                                connected_count = connected_addrs.len(),
                                "scan interval transition"
                            );
                        }
                        scan_interval = next_interval;

                        for peer in &peers {
                            dispatch_event(BlePeerEvent::Discovered {
                                address: peer.ble_address.clone(),
                                rssi: peer.rssi,
                                protocol: peer.protocol,
                            });
                            // Skip if already connected
                            if connected_addrs.contains_key(&peer.ble_address) {
                                dispatch_event(BlePeerEvent::RssiUpdate {
                                    address: peer.ble_address.clone(),
                                    rssi: peer.rssi,
                                });
                                continue;
                            }

                            // Enforce MAX_PEERS limit
                            if connected_addrs.len() >= MAX_PEERS {
                                tracing::debug!(
                                    "BLE mesh: MAX_PEERS ({MAX_PEERS}) reached, skipping"
                                );
                                break;
                            }

                            // Skip peers in reconnect backoff.
                            if reconnect_in_backoff(&recently_disc, &peer.ble_address) {
                                tracing::debug!(
                                    address = %peer.ble_address,
                                    "BLE mesh: peer in reconnect backoff, skipping"
                                );
                                continue;
                            }

                            tracing::info!(
                                target: "ble_trace",
                                step = "peer.discovered",
                                name = %mesh_name,
                                address = %peer.ble_address,
                                rssi = peer.rssi,
                                protocol = ?peer.protocol,
                                connected_count = connected_addrs.len(),
                                "BLE mesh peer discovered, connecting..."
                            );

                            // Connect, subscribe, set up data flow.
                            // No BLE-level identity exchange — identity is
                            // learned later from the first signed Reticulum
                            // announce that flows over the link.
                            match connect_mesh_peer(&adapter, peer).await {
                                Ok(conn) => {
                                    // Drop the wanted-reconnect entry now
                                    // that we've reconnected.
                                    record_reconnect_success(&recently_disc, &peer.ble_address);

                                    let peer_online = Arc::new(AtomicBool::new(true));

                                    // Per-peer write channel
                                    let (peer_write_tx, peer_write_rx) = mpsc::channel::<Bytes>(64);
                                    let peer_writer_key = central_writer_key(&peer.ble_address);
                                    writers
                                        .write()
                                        .await
                                        .insert(peer_writer_key.clone(), peer_write_tx.clone());

                                    // Track this peer
                                    connected_addrs
                                        .insert(peer.ble_address.clone(), peer_online.clone());

                                    // Spawn per-peer write loop
                                    let p_write = conn.peripheral.clone();
                                    let rx_c = conn.rx_char.clone();
                                    let mtu = conn.write_mtu;
                                    let online_w = peer_online.clone();
                                    let addr_w = peer.ble_address.clone();
                                    let anti_loop_w = anti_loop.clone();
                                    track_child_task(
                                        generation,
                                        tokio::spawn(async move {
                                            peer_write_loop(
                                                p_write,
                                                rx_c,
                                                mtu,
                                                peer_write_rx,
                                                online_w,
                                                addr_w,
                                                anti_loop_w,
                                            )
                                            .await;
                                        }),
                                    );

                                    // Spawn per-peer read loop
                                    let transport_r = transport.clone();
                                    let online_r = peer_online.clone();
                                    let rxb_r = rxb.clone();
                                    let writers_r = writers.clone();
                                    let recently_r = recently_disc.clone();
                                    let anti_loop_r = anti_loop.clone();
                                    let link_registry_r = link_registry.clone();
                                    let proto_evt = peer.protocol;
                                    let addr_evt = peer.ble_address.clone();
                                    track_child_task(
                                        generation,
                                        tokio::spawn(async move {
                                            peer_read_loop(
                                                conn,
                                                PeerReadLoopCtx {
                                                    interface_id: id,
                                                    transport_tx: transport_r,
                                                    peer_online: online_r,
                                                    rxb: rxb_r,
                                                    peer_writers: writers_r,
                                                    peer_writer_key,
                                                    recently_disconnected: recently_r,
                                                    anti_loop: anti_loop_r,
                                                    link_registry: link_registry_r,
                                                },
                                            )
                                            .await;
                                        }),
                                    );
                                    dispatch_event(BlePeerEvent::Connected {
                                        address: addr_evt.clone(),
                                        identity_hash: String::new(),
                                        protocol: proto_evt,
                                    });
                                    dispatch_status_changed(
                                        peer_state_for_count(connected_addrs.len()),
                                        connected_addrs.len(),
                                    );
                                    // Kick-announce: now that we're subscribed
                                    // to the peer's TX, ask the embedding UI to
                                    // fire an immediate Reticulum announce so
                                    // identity exchange happens on first contact.
                                    dispatch_event(BlePeerEvent::SubscribeReady {
                                        address: addr_evt,
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        address = %peer.ble_address,
                                        error = %e,
                                        "BLE mesh peer connection failed"
                                    );
                                    record_reconnect_failure(&recently_disc, &peer.ble_address);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "BLE mesh scan cycle failed");
                    }
                }

                // Override scan interval when backgrounded for battery savings
                // (mobile only — desktop scans at the foreground interval always).
                #[cfg(feature = "mobile-throttle")]
                let was_foreground = is_foreground.load(Ordering::Relaxed);
                #[cfg(feature = "mobile-throttle")]
                let effective_interval = if was_foreground {
                    scan_interval
                } else {
                    SCAN_BACKGROUND_INTERVAL
                };
                #[cfg(not(feature = "mobile-throttle"))]
                let was_foreground = true;
                #[cfg(not(feature = "mobile-throttle"))]
                let effective_interval = scan_interval;
                scan_sleep(effective_interval, &is_foreground, was_foreground, &wake).await;
            }
        })
    };

    // Apple (iOS + macOS) central task — objc2-native scan + connect + per-peer
    // write loops. Inbound bytes flow through the existing INBOUND_TX channel
    // (apple_peripheral::try_push_inbound) which the per-peer reassembly task
    // above already drains; per-peer read loops are not needed because the
    // ble_central_apple_connect module's notify delegate pushes directly into
    // that channel. Disconnect propagation: ble_central_apple's didDisconnect
    // delegate calls on_did_disconnect, which flips the per-peer online flag
    // and dispatches BlePeerEvent::Disconnected.
    #[cfg(all(feature = "ble", any(target_os = "ios", target_os = "macos")))]
    let read_task = {
        let mesh_name = name.clone();
        let writers = peer_writers.clone();
        let recently_disc = recently_disconnected.clone();
        let anti_loop = anti_loop.clone();
        let wake = foreground_wake.clone();

        tokio::spawn(async move {
            let mut connected_addrs: HashMap<String, Arc<AtomicBool>> = HashMap::new();
            let mut scan_interval = SCAN_ACTIVE_INTERVAL;
            loop {
                if !generation_is_current(generation) {
                    tracing::info!("Apple BLE mesh Central scan loop: shutdown signal, exiting");
                    crate::ble_central_apple_connect::disconnect_all();
                    break;
                }

                // Drop peers whose disconnect delegate flipped their flag.
                // Consult the disconnect reason stashed by `on_did_disconnect`
                // (one-shot via `take_last_disconnect_reason`) to choose
                // between rotation-aware reconnect (zero-out backoff so the
                // peer comes back fast on next scan) and genuine-failure
                // accumulation (existing 3-strike path).
                let previous_peer_count = connected_addrs.len();
                connected_addrs.retain(|addr, online| {
                    let alive = online.load(Ordering::SeqCst);
                    if !alive {
                        let reason =
                            crate::ble_central_apple_connect::take_last_disconnect_reason(addr);
                        match reason {
                            Some(crate::ble_central_apple_connect::DisconnectReason::Rotation) => {
                                tracing::info!(
                                    target: "ble_trace",
                                    step = "apple_connect.rotation_drop",
                                    address = %addr,
                                    "Apple BLE mesh peer dropped via RPA rotation \u{2014} fast reconnect path"
                                );
                                record_rotation_disconnect(&recently_disc, addr);
                            }
                            _ => {
                                tracing::info!(
                                    target: "ble_trace",
                                    step = "peer.lost",
                                    address = %addr,
                                    reason = ?reason,
                                    "Apple BLE mesh peer connection ended \u{2014} dropping from connected set"
                                );
                                record_disconnect(&recently_disc, addr);
                            }
                        }
                    }
                    alive
                });
                if connected_addrs.len() != previous_peer_count {
                    dispatch_status_changed(
                        peer_state_for_count(connected_addrs.len()),
                        connected_addrs.len(),
                    );
                }

                prune_recently_disconnected(&recently_disc);
                anti_loop_prune(&anti_loop);
                crate::ble_central_apple_connect::prune_discovered();

                match scan_mesh_peers(3).await {
                    Ok(peers) => {
                        let next_interval =
                            if !peers.is_empty() || has_wanted_reconnects(&recently_disc) {
                                SCAN_ACTIVE_INTERVAL
                            } else {
                                SCAN_IDLE_INTERVAL
                            };
                        if next_interval != scan_interval {
                            tracing::info!(
                                target: "ble_trace",
                                step = "scan.interval_changed",
                                prev_ms = scan_interval.as_millis() as u64,
                                next_ms = next_interval.as_millis() as u64,
                                scanned_peer_count = peers.len(),
                                wanted_reconnects = has_wanted_reconnects(&recently_disc),
                                connected_count = connected_addrs.len(),
                                "Apple scan interval transition"
                            );
                        }
                        scan_interval = next_interval;

                        let peripheral_peer_addresses =
                            apple_peripheral::subscribed_central_addresses();

                        for peer in &peers {
                            dispatch_event(BlePeerEvent::Discovered {
                                address: peer.ble_address.clone(),
                                rssi: peer.rssi,
                                protocol: peer.protocol,
                            });
                            if connected_addrs.contains_key(&peer.ble_address) {
                                dispatch_event(BlePeerEvent::RssiUpdate {
                                    address: peer.ble_address.clone(),
                                    rssi: peer.rssi,
                                });
                                continue;
                            }
                            if peripheral_peer_addresses
                                .iter()
                                .any(|addr| addr == &peer.ble_address)
                            {
                                dispatch_event(BlePeerEvent::RssiUpdate {
                                    address: peer.ble_address.clone(),
                                    rssi: peer.rssi,
                                });
                                record_reconnect_success(&recently_disc, &peer.ble_address);
                                tracing::debug!(
                                    target: "ble_trace",
                                    step = "peer.connect_suppressed",
                                    address = %peer.ble_address,
                                    "Apple BLE mesh: peer already subscribed to local peripheral, skipping central connect"
                                );
                                continue;
                            }
                            if connected_addrs.len() >= MAX_PEERS {
                                tracing::debug!(
                                    "Apple BLE mesh: MAX_PEERS ({MAX_PEERS}) reached, skipping"
                                );
                                break;
                            }
                            if reconnect_in_backoff(&recently_disc, &peer.ble_address) {
                                tracing::debug!(
                                    address = %peer.ble_address,
                                    "Apple BLE mesh: peer in reconnect backoff, skipping"
                                );
                                continue;
                            }

                            tracing::info!(
                                target: "ble_trace",
                                step = "peer.discovered",
                                name = %mesh_name,
                                address = %peer.ble_address,
                                rssi = peer.rssi,
                                protocol = ?peer.protocol,
                                connected_count = connected_addrs.len(),
                                "Apple BLE mesh peer discovered, connecting..."
                            );

                            match crate::ble_central_apple_connect::connect_peer(
                                peer.ble_address.clone(),
                                peer.protocol,
                            )
                            .await
                            {
                                Ok(cp) => {
                                    record_reconnect_success(&recently_disc, &peer.ble_address);
                                    let online = cp.online.clone();

                                    let (peer_write_tx, mut peer_write_rx) =
                                        mpsc::channel::<Bytes>(64);
                                    let peer_writer_key = central_writer_key(&peer.ble_address);
                                    writers
                                        .write()
                                        .await
                                        .insert(peer_writer_key.clone(), peer_write_tx.clone());
                                    connected_addrs
                                        .insert(peer.ble_address.clone(), online.clone());

                                    // Per-peer write loop. Inbound is handled
                                    // by the global INBOUND_TX reassembler;
                                    // there's no equivalent peer_read_loop on
                                    // Apple because the connect module's
                                    // notify delegate already pushes there.
                                    let online_w = online.clone();
                                    let addr_w = peer.ble_address.clone();
                                    let anti_loop_w = anti_loop.clone();
                                    let writers_cleanup = writers.clone();
                                    let writer_key_cleanup = peer_writer_key.clone();
                                    let mtu = cp.write_mtu;
                                    track_child_task(
                                        generation,
                                        tokio::spawn(async move {
                                            const SHUTDOWN_POLL: Duration = Duration::from_secs(1);
                                            let mut tx_count: u64 = 0;
                                            loop {
                                                let data = tokio::select! {
                                                    v = peer_write_rx.recv() => match v {
                                                        Some(d) => d,
                                                        None => break,
                                                    },
                                                    _ = tokio::time::sleep(SHUTDOWN_POLL) => {
                                                        if !online_w.load(Ordering::SeqCst)
                                                            || !generation_is_current(generation)
                                                        {
                                                            online_w.store(false, Ordering::SeqCst);
                                                            break;
                                                        }
                                                        continue;
                                                    }
                                                };
                                                if !online_w.load(Ordering::SeqCst)
                                                    || !generation_is_current(generation)
                                                {
                                                    online_w.store(false, Ordering::SeqCst);
                                                    break;
                                                }
                                                if !anti_loop_should_send(
                                                    &anti_loop_w,
                                                    &addr_w,
                                                    &data,
                                                ) {
                                                    continue;
                                                }
                                                let frags = fragment_packet(&data, mtu);
                                                let mut all_ok = true;
                                                for (idx, frag) in frags.iter().enumerate() {
                                                    if let Err(e) =
                                                        crate::ble_central_apple_connect::write_peer(
                                                            &addr_w, frag,
                                                        )
                                                    {
                                                        tracing::warn!(
                                                            target: "ble_trace",
                                                            step = "peer.write_fail",
                                                            peer = %addr_w,
                                                            tx_count = tx_count,
                                                            frag_len = frag.len(),
                                                            err = %e,
                                                            "Apple BLE mesh peer write failed"
                                                        );
                                                        online_w.store(false, Ordering::SeqCst);
                                                        all_ok = false;
                                                        break;
                                                    }
                                                    pace_after_ble_fragment(idx, frags.len()).await;
                                                }
                                                if !all_ok {
                                                    break;
                                                }
                                                tx_count += 1;
                                                if tx_count % 5 == 0 {
                                                    tracing::info!(
                                                        target: "ble_trace",
                                                        step = "peer.tx_progress",
                                                        peer = %addr_w,
                                                        tx_count = tx_count,
                                                        last_len = data.len(),
                                                        "Apple BLE mesh outbound frames (rolling count)"
                                                    );
                                                }
                                            }
                                            writers_cleanup
                                                .write()
                                                .await
                                                .remove(&writer_key_cleanup);
                                        }),
                                    );

                                    dispatch_event(BlePeerEvent::Connected {
                                        address: peer.ble_address.clone(),
                                        identity_hash: String::new(),
                                        protocol: peer.protocol,
                                    });
                                    dispatch_status_changed(
                                        peer_state_for_count(connected_addrs.len()),
                                        connected_addrs.len(),
                                    );
                                    dispatch_event(BlePeerEvent::SubscribeReady {
                                        address: peer.ble_address.clone(),
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        address = %peer.ble_address,
                                        error = %e,
                                        "Apple BLE mesh peer connection failed"
                                    );
                                    // Distinguish ghost-identifier timeouts from
                                    // genuine peer failures. CoreBluetooth's
                                    // `connectPeripheral:` doesn't self-time-out
                                    // when the underlying advertised address has
                                    // moved (RPA rotation), so our 5s connect
                                    // timeout is the only way to detect a ghost.
                                    // Mark ghost identifiers with one-strike
                                    // backoff so they don't recur in the next 5
                                    // minutes; everything else accumulates the
                                    // 3-strike retry budget like before.
                                    let err_str = e.to_string();
                                    if err_str.contains("connect: timed out") {
                                        record_connect_timeout_ghost(
                                            &recently_disc,
                                            &peer.ble_address,
                                        );
                                        tracing::info!(
                                            target: "ble_trace",
                                            step = "apple_connect.ghost_backoff",
                                            address = %peer.ble_address,
                                            "Apple BLE mesh: ghost identifier flagged for full backoff"
                                        );
                                    } else {
                                        record_reconnect_failure(&recently_disc, &peer.ble_address);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "Apple BLE mesh scan cycle failed");
                    }
                }

                #[cfg(feature = "mobile-throttle")]
                let was_foreground = is_foreground.load(Ordering::Relaxed);
                #[cfg(feature = "mobile-throttle")]
                let effective_interval = if was_foreground {
                    scan_interval
                } else {
                    SCAN_BACKGROUND_INTERVAL
                };
                #[cfg(not(feature = "mobile-throttle"))]
                let was_foreground = true;
                #[cfg(not(feature = "mobile-throttle"))]
                let effective_interval = scan_interval;
                scan_sleep(effective_interval, &is_foreground, was_foreground, &wake).await;
            }
        })
    };

    // Android central task — JNI-driven scan + connect + per-peer write loops.
    // Inbound bytes are wired through the same INBOUND_TX channel the GATT
    // server uses (RatspeakBlePeerClient.nativePeerClientDataReceived calls
    // android_peripheral::on_gatt_data_received), so the existing per-peer
    // reassembly consumer above handles both Central- and Peripheral-side
    // traffic without any additional plumbing.
    #[cfg(target_os = "android")]
    let read_task = {
        let mesh_name = name.clone();
        let writers = peer_writers.clone();
        let foreground = is_foreground.clone();
        let recently_disc = recently_disconnected.clone();
        let anti_loop = anti_loop.clone();
        let wake = foreground_wake.clone();

        tokio::spawn(async move {
            // Scan timeout per cycle — short enough to feel responsive when a
            // new peer powers on, long enough to catch low-duty-cycle adverts.
            const SCAN_TIMEOUT_MS: i64 = 3000;
            let mut connected_addrs: HashMap<String, Arc<AtomicBool>> = HashMap::new();

            loop {
                if !generation_is_current(generation) {
                    tracing::info!(
                        "BLE mesh (Android) Central scan loop: shutdown signal, exiting"
                    );
                    break;
                }

                prune_recently_disconnected(&recently_disc);
                // Drop anti-loop dedupe entries past their 30s TTL.
                anti_loop_prune(&anti_loop);

                // Drop peers whose JNI disconnect callback flipped their flag.
                // unregister cleans the static registry that backs that callback.
                let previous_peer_count = connected_addrs.len();
                connected_addrs.retain(|addr, online| {
                    let alive = online.load(Ordering::SeqCst);
                    if !alive {
                        tracing::info!(address = %addr, "BLE mesh (Android) peer connection ended");
                        // Mark this address as a wanted-reconnect target.
                        // Identity-keyed tracking is gone because the BLE link
                        // no longer exchanges identity.
                        record_disconnect(&recently_disc, addr);
                        android_peripheral::unregister_peer_online(addr);
                        android_peripheral::peer_client_disconnect(addr);
                    }
                    alive
                });
                if connected_addrs.len() != previous_peer_count {
                    dispatch_status_changed(
                        peer_state_for_count(connected_addrs.len()),
                        connected_addrs.len(),
                    );
                }

                // Native scan via BluetoothLeScanner with a service-UUID
                // filter (battery-efficient — radio firmware filters
                // adverts before waking the host).
                let scan_results = tokio::task::spawn_blocking(move || {
                    android_peripheral::peer_scan_mesh(SCAN_TIMEOUT_MS)
                })
                .await
                .unwrap_or_default();

                let scan_interval =
                    if !scan_results.is_empty() || has_wanted_reconnects(&recently_disc) {
                        SCAN_ACTIVE_INTERVAL
                    } else {
                        SCAN_IDLE_INTERVAL
                    };

                let peripheral_peer_addresses = if scan_results.is_empty() {
                    Vec::new()
                } else {
                    tokio::task::spawn_blocking(
                        android_peripheral::connected_or_subscribed_addresses,
                    )
                    .await
                    .unwrap_or_default()
                };

                for (addr, rssi, protocol) in &scan_results {
                    dispatch_event(BlePeerEvent::Discovered {
                        address: addr.clone(),
                        rssi: *rssi,
                        protocol: *protocol,
                    });
                    if connected_addrs.contains_key(addr) {
                        dispatch_event(BlePeerEvent::RssiUpdate {
                            address: addr.clone(),
                            rssi: *rssi,
                        });
                        continue;
                    }
                    if peripheral_peer_addresses.iter().any(|peer| peer == addr) {
                        dispatch_event(BlePeerEvent::RssiUpdate {
                            address: addr.clone(),
                            rssi: *rssi,
                        });
                        record_reconnect_success(&recently_disc, addr);
                        tracing::debug!(
                            target: "ble_trace",
                            step = "peer.connect_suppressed",
                            address = %addr,
                            "BLE mesh (Android): peer already connected to local GATT server, skipping central connect"
                        );
                        continue;
                    }
                    if connected_addrs.len() >= MAX_PEERS {
                        tracing::debug!(
                            "BLE mesh (Android): MAX_PEERS ({MAX_PEERS}) reached, skipping"
                        );
                        break;
                    }
                    if *rssi < MIN_RSSI {
                        continue;
                    }
                    if reconnect_in_backoff(&recently_disc, addr) {
                        tracing::debug!(
                            address = %addr,
                            "BLE mesh (Android): peer in reconnect backoff, skipping"
                        );
                        continue;
                    }

                    tracing::info!(
                        name = %mesh_name,
                        address = %addr,
                        rssi = *rssi,
                        protocol = ?protocol,
                        "BLE mesh (Android) peer discovered, connecting..."
                    );

                    // Blocking connect call — Kotlin uses CountDownLatches that
                    // would deadlock on the GATT callback thread.
                    let addr_clone = addr.clone();
                    let connect_result = tokio::task::spawn_blocking(move || {
                        android_peripheral::peer_client_connect(&addr_clone)
                    })
                    .await
                    .unwrap_or_else(|e| Err(format!("spawn_blocking: {e}")));

                    match connect_result {
                        Ok(()) => {
                            let peer_online = Arc::new(AtomicBool::new(true));
                            android_peripheral::register_peer_online(
                                addr.clone(),
                                peer_online.clone(),
                            );

                            let (peer_write_tx, mut peer_write_rx) = mpsc::channel::<Bytes>(64);
                            let peer_writer_key = central_writer_key(addr);
                            writers
                                .write()
                                .await
                                .insert(peer_writer_key.clone(), peer_write_tx.clone());
                            connected_addrs.insert(addr.clone(), peer_online.clone());

                            // Per-peer write loop: bytes from the fan-out task
                            // come through `peer_write_rx`, get fragmented,
                            // and each fragment is pushed to Kotlin via JNI.
                            let online_w = peer_online.clone();
                            let addr_w = addr.clone();
                            let anti_loop_w = anti_loop.clone();
                            let writers_cleanup = writers.clone();
                            let writer_key_cleanup = peer_writer_key.clone();
                            track_child_task(
                                generation,
                                tokio::spawn(async move {
                                    // Bounded recv wake so global shutdown
                                    // tears this task down within ~1s even when
                                    // there's no outbound traffic. Without it the
                                    // task would live until the scan loop's
                                    // cleanup-on-next-tick dropped the write_tx.
                                    const SHUTDOWN_POLL: Duration = Duration::from_secs(1);
                                    loop {
                                        let data = tokio::select! {
                                            v = peer_write_rx.recv() => match v {
                                                Some(d) => d,
                                                None => break,
                                            },
                                            _ = tokio::time::sleep(SHUTDOWN_POLL) => {
                                                if !online_w.load(Ordering::SeqCst)
                                                    || !generation_is_current(generation)
                                                {
                                                    online_w.store(false, Ordering::SeqCst);
                                                    break;
                                                }
                                                continue;
                                            }
                                        };
                                        if !online_w.load(Ordering::SeqCst)
                                            || !generation_is_current(generation)
                                        {
                                            online_w.store(false, Ordering::SeqCst);
                                            break;
                                        }
                                        // Don't echo a packet back to its source.
                                        if !anti_loop_should_send(&anti_loop_w, &addr_w, &data) {
                                            continue;
                                        }
                                        // Query the per-peer negotiated MTU each
                                        // iteration so we pick up post-connect MTU
                                        // exchange results.
                                        let addr_mtu = addr_w.clone();
                                        let mtu = tokio::task::spawn_blocking(move || {
                                            android_peripheral::peer_client_mtu(&addr_mtu)
                                        })
                                        .await
                                        .unwrap_or(244);
                                        let frags = fragment_packet(&data, mtu);
                                        let addr_w2 = addr_w.clone();
                                        let send_ok = tokio::task::spawn_blocking(move || {
                                            let total = frags.len();
                                            for (idx, frag) in frags.iter().enumerate() {
                                                if !android_peripheral::peer_client_write(
                                                    &addr_w2, frag,
                                                ) {
                                                    return false;
                                                }
                                                sleep_after_ble_fragment_blocking(idx, total);
                                            }
                                            true
                                        })
                                        .await
                                        .unwrap_or(false);
                                        if !send_ok {
                                            tracing::warn!(
                                                peer = %addr_w,
                                                "Android peer client write failed, marking offline"
                                            );
                                            online_w.store(false, Ordering::SeqCst);
                                            break;
                                        }
                                    }
                                    writers_cleanup.write().await.remove(&writer_key_cleanup);
                                }),
                            );

                            // Drop any wanted-reconnect entry for this peer.
                            record_reconnect_success(&recently_disc, addr);
                            tracing::info!(
                                address = %addr,
                                protocol = ?protocol,
                                "BLE mesh (Android) peer connected"
                            );
                            dispatch_event(BlePeerEvent::Connected {
                                address: addr.clone(),
                                identity_hash: String::new(),
                                protocol: *protocol,
                            });
                            dispatch_status_changed(
                                peer_state_for_count(connected_addrs.len()),
                                connected_addrs.len(),
                            );
                            // Kick-announce — see iOS Central path.
                            dispatch_event(BlePeerEvent::SubscribeReady {
                                address: addr.clone(),
                            });
                        }
                        Err(e) => {
                            tracing::warn!(
                                address = %addr,
                                error = %e,
                                "BLE mesh (Android) peer connection failed"
                            );
                            record_reconnect_failure(&recently_disc, addr);
                        }
                    }
                }

                #[cfg(feature = "mobile-throttle")]
                let was_foreground = foreground.load(Ordering::Relaxed);
                #[cfg(feature = "mobile-throttle")]
                let effective_interval = if was_foreground {
                    scan_interval
                } else {
                    SCAN_BACKGROUND_INTERVAL
                };
                #[cfg(not(feature = "mobile-throttle"))]
                let was_foreground = true;
                #[cfg(not(feature = "mobile-throttle"))]
                let effective_interval = scan_interval;
                scan_sleep(effective_interval, &foreground, was_foreground, &wake).await;
            }
        })
    };

    #[cfg(all(not(feature = "ble"), not(target_os = "android")))]
    let read_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    Ok(InterfaceHandle {
        id,
        parent_id: None,
        name,
        mode: config.mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: true,
            forward: true,
            repeat: false,
        },
        bitrate: 250_000, // BLE 1M PHY effective throughput
        mtu: 500,
        online: interface_online_flag(),
        txb: Some(shared_txb),
        rxb: Some(shared_rxb),
        tx,
        read_task,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fragmentation ──

    #[test]
    fn test_fragmentation_lone() {
        let data = vec![0x04, 2, 3, 4, 5];
        let frags = fragment_packet(&data, 100);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], data);
    }

    #[test]
    fn test_fragmentation_envelopes_ambiguous_small_packets() {
        for first in [
            FragmentType::Start as u8,
            FragmentType::Continue as u8,
            FragmentType::End as u8,
        ] {
            let mut data = vec![first];
            data.extend(1u8..80u8);

            let frags = fragment_packet(&data, 100);
            assert_eq!(frags.len(), 2);
            assert_eq!(frags[0][0], FragmentType::Start as u8);
            assert_eq!(frags[1][0], FragmentType::End as u8);
            assert_eq!(reassemble_fragments(&frags).unwrap(), data);
        }
    }

    #[test]
    fn test_direct_link_request_header_is_not_sent_raw() {
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
            destination_hash: [0xAA; 16],
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0x55; 64]);
        assert_eq!(raw[0], FragmentType::Continue as u8);

        let frags = fragment_packet(&raw, 500);
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0][0], FragmentType::Start as u8);
        assert_eq!(frags[1][0], FragmentType::End as u8);
        assert_eq!(reassemble_fragments(&frags).unwrap(), raw);
    }

    #[test]
    fn test_fragmentation_multi() {
        let data = vec![0u8; 200];
        let frags = fragment_packet(&data, 50);
        assert!(frags.len() > 1);
        for frag in &frags {
            assert!(frag.len() <= 50);
            assert!(frag.len() >= 5);
        }
        let reassembled = reassemble_fragments(&frags).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_fragment_types() {
        let data = vec![0u8; 200];
        let frags = fragment_packet(&data, 50);
        assert_eq!(frags[0][0], FragmentType::Start as u8);
        for frag in &frags[1..frags.len() - 1] {
            assert_eq!(frag[0], FragmentType::Continue as u8);
        }
        assert_eq!(frags.last().unwrap()[0], FragmentType::End as u8);
    }

    #[test]
    fn test_fragmentation_exact_mtu() {
        // Data that exactly fills one LONE frame (no header needed)
        let data = vec![0xAA; 50];
        let frags = fragment_packet(&data, 53); // 53 - 3 = 50 LONE threshold
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], data); // No header prefix
    }

    #[test]
    fn test_fragmentation_one_byte_over() {
        // Data one byte over the LONE threshold triggers multi-fragment
        let mtu: usize = 50;
        let lone_max = mtu.saturating_sub(3);
        let data = vec![0xBB; lone_max + 1];
        let frags = fragment_packet(&data, mtu);
        assert!(frags.len() > 1);
        let reassembled = reassemble_fragments(&frags).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_fragmentation_large_packet() {
        let data = vec![0xCC; 2048];
        let frags = fragment_packet(&data, 100);
        assert!(frags.len() > 20);
        let reassembled = reassemble_fragments(&frags).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_fragmentation_tiny_mtu() {
        // MTU of 8: 5-byte header + 3 bytes payload per fragment
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let frags = fragment_packet(&data, 8);
        assert!(frags.len() >= 3);
        let reassembled = reassemble_fragments(&frags).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_fragmentation_mtu_too_small() {
        // MTU <= 5 means payload_mtu = 0, so we cannot add an envelope.
        let data = vec![1, 2, 3];
        let frags = fragment_packet(&data, 5);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], data);
    }

    #[test]
    fn test_fragmentation_empty_data() {
        let frags = fragment_packet(&[], 100);
        assert_eq!(frags.len(), 1);
        assert!(frags[0].is_empty());
    }

    #[test]
    fn test_fragmentation_single_byte() {
        let frags = fragment_packet(&[0xFF], 100);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], vec![0xFF]);
    }

    #[test]
    fn test_fragment_header_structure() {
        let data = vec![0u8; 100];
        let frags = fragment_packet(&data, 30);
        // Check header: [type:1][seq:2-BE][total:2-BE]
        let first = &frags[0];
        assert_eq!(first[0], FragmentType::Start as u8);
        let seq = u16::from_be_bytes([first[1], first[2]]);
        assert_eq!(seq, 0);
        let total = u16::from_be_bytes([first[3], first[4]]);
        assert_eq!(total as usize, frags.len());
    }

    #[test]
    fn test_fragment_sequence_numbers() {
        let data = vec![0u8; 200];
        let frags = fragment_packet(&data, 30);
        for (i, frag) in frags.iter().enumerate() {
            let seq = u16::from_be_bytes([frag[1], frag[2]]);
            assert_eq!(seq as usize, i);
        }
    }

    // ── Reassembly ──

    #[test]
    fn test_reassemble_empty() {
        assert!(reassemble_fragments(&[]).is_none());
    }

    #[test]
    fn test_reassembly_rejects_oversized_total() {
        // A START claiming more fragments than MAX_FRAGMENTS must be rejected at
        // header parse, so an unauthenticated writer can't size a reassembly
        // buffer off the attacker-controlled 16-bit `total` field.
        let start = make_fragment(FragmentType::Start, 0, MAX_FRAGMENTS + 1, &[0xAA; 4]);
        assert!(parse_fragment_header(&start).is_none());

        // consume_ble_frame therefore forwards it as a raw passthrough frame
        // (no allocation) rather than opening a reassembly entry.
        let mut reassembly: FragmentReassembly = HashMap::new();
        let out = consume_ble_frame(start.clone(), &mut reassembly);
        assert_eq!(out, Some(start));
        assert!(reassembly.is_empty());
    }

    #[test]
    fn test_reassemble_malformed_short() {
        // Fragments shorter than 5 bytes should be rejected
        let bad = vec![vec![0x01, 0x00]];
        assert!(reassemble_fragments(&bad).is_none());
    }

    #[test]
    fn test_reassemble_header_only() {
        // A two-frame empty payload is valid; START(total=1) is not.
        let start = vec![FragmentType::Start as u8, 0, 0, 0, 2];
        let end = vec![FragmentType::End as u8, 0, 1, 0, 2];
        let result = reassemble_fragments(&[start, end]);
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn test_reassemble_rejects_invalid_start_total() {
        let frag = vec![FragmentType::Start as u8, 0, 0, 0, 1];
        assert!(reassemble_fragments(&[frag]).is_none());
    }

    #[test]
    fn test_consume_ble_frame_preserves_legacy_raw_data_zero() {
        let raw = vec![0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB];
        let mut reassembly = FragmentReassembly::new();
        assert_eq!(consume_ble_frame(raw.clone(), &mut reassembly), Some(raw));
        assert!(reassembly.is_empty());
    }

    #[test]
    fn test_consume_ble_frame_preserves_legacy_raw_link_request_without_start() {
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
            destination_hash: [0xAA; 16],
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0x55; 64]);
        assert_eq!(raw[0], FragmentType::Continue as u8);

        let mut reassembly = FragmentReassembly::new();
        assert_eq!(consume_ble_frame(raw.clone(), &mut reassembly), Some(raw));
        assert!(reassembly.is_empty());
    }

    #[test]
    fn test_consume_ble_frame_decodes_enveloped_link_request() {
        let raw = {
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
                destination_hash: [0x11; 16],
                context: rns_wire::context::PacketContext::None,
            };
            let mut raw = header.pack();
            raw.extend_from_slice(&[0x22; 64]);
            raw
        };

        let frags = fragment_packet(&raw, 500);
        let mut reassembly = FragmentReassembly::new();
        assert_eq!(consume_ble_frame(frags[0].clone(), &mut reassembly), None);
        assert_eq!(
            consume_ble_frame(frags[1].clone(), &mut reassembly),
            Some(raw)
        );
        assert!(reassembly.is_empty());
    }

    // ── Service UUIDs ──

    #[test]
    fn test_service_uuids() {
        assert_ne!(RATSPEAK_SERVICE_UUID, COLUMBA_SERVICE_UUID);
        assert_ne!(RATSPEAK_RX_UUID, COLUMBA_RX_UUID);
        assert_ne!(RATSPEAK_TX_UUID, COLUMBA_TX_UUID);
    }

    #[test]
    fn test_ratspeak_uuids_distinct_from_each_other() {
        let uuids = [
            RATSPEAK_SERVICE_UUID,
            RATSPEAK_RX_UUID,
            RATSPEAK_TX_UUID,
            RATSPEAK_ID_UUID,
        ];
        for i in 0..uuids.len() {
            for j in (i + 1)..uuids.len() {
                assert_ne!(uuids[i], uuids[j]);
            }
        }
    }

    #[test]
    fn test_columba_uuids_distinct_from_each_other() {
        let uuids = [
            COLUMBA_SERVICE_UUID,
            COLUMBA_RX_UUID,
            COLUMBA_TX_UUID,
            COLUMBA_ID_UUID,
        ];
        for i in 0..uuids.len() {
            for j in (i + 1)..uuids.len() {
                assert_ne!(uuids[i], uuids[j]);
            }
        }
    }

    // ── Config ──

    #[test]
    fn test_ble_peer_config_defaults() {
        let cfg = BlePeerConfig::new("mesh0", vec![0u8; 16]);
        assert_eq!(cfg.name, "mesh0");
        assert_eq!(cfg.identity_hash.len(), 16);
        assert_eq!(cfg.mode, InterfaceMode::Full);
    }

    // ── BlePeer struct serialization ──

    #[test]
    fn test_ble_peer_serialization() {
        let peer = BlePeer {
            identity_hash: "abcdef0123456789".into(),
            ble_address: "AA:BB:CC:DD:EE:FF".into(),
            rssi: -65,
            protocol: PeerProtocol::Ratspeak,
            connected: true,
        };
        let json = serde_json::to_string(&peer).unwrap();
        assert!(json.contains("\"protocol\":\"Ratspeak\""));
        assert!(json.contains("\"connected\":true"));
        assert!(json.contains("\"rssi\":-65"));
    }

    #[test]
    fn test_ble_peer_roundtrip() {
        let peer = BlePeer {
            identity_hash: "0011223344556677".into(),
            ble_address: "11:22:33:44:55:66".into(),
            rssi: -80,
            protocol: PeerProtocol::Columba,
            connected: false,
        };
        let json = serde_json::to_string(&peer).unwrap();
        let deserialized: BlePeer = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.identity_hash, peer.identity_hash);
        assert_eq!(deserialized.ble_address, peer.ble_address);
        assert_eq!(deserialized.rssi, peer.rssi);
        assert_eq!(deserialized.protocol, PeerProtocol::Columba);
        assert!(!deserialized.connected);
    }

    #[test]
    fn test_peer_protocol_serialization() {
        let r = serde_json::to_string(&PeerProtocol::Ratspeak).unwrap();
        assert_eq!(r, "\"Ratspeak\"");
        let c = serde_json::to_string(&PeerProtocol::Columba).unwrap();
        assert_eq!(c, "\"Columba\"");
    }

    #[test]
    fn newline_address_parser_filters_blank_entries() {
        let parsed = parse_newline_addresses("\nAA:BB:CC:DD:EE:FF\n\n  11:22:33:44:55:66  \n");
        assert_eq!(
            parsed,
            vec![
                "AA:BB:CC:DD:EE:FF".to_string(),
                "11:22:33:44:55:66".to_string()
            ]
        );
    }

    #[test]
    fn fragment_pacing_skips_final_fragment() {
        assert!(!should_pace_after_fragment(0, 0));
        assert!(!should_pace_after_fragment(0, 1));
        assert!(should_pace_after_fragment(0, 2));
        assert!(!should_pace_after_fragment(1, 2));
        assert!(!should_pace_after_fragment(2, 2));
    }

    #[test]
    fn link_registry_prefers_central_same_address() {
        let registry = BlePeerLinkRegistry::default();
        assert!(!registry.should_send_peripheral_subscriber(
            "AA:BB:CC:DD:EE:FF",
            &[central_writer_key("AA:BB:CC:DD:EE:FF")]
        ));
        assert!(registry.should_send_peripheral_subscriber(
            "11:22:33:44:55:66",
            &[central_writer_key("AA:BB:CC:DD:EE:FF")]
        ));
    }

    #[test]
    fn link_registry_prefers_central_same_identity() {
        let mut registry = BlePeerLinkRegistry::default();
        registry.set_identity("central-addr".into(), "identity-a".into());
        registry.set_identity("peripheral-addr".into(), "identity-a".into());
        registry.set_identity("other-addr".into(), "identity-b".into());

        assert!(!registry.should_send_peripheral_subscriber(
            "peripheral-addr",
            &[central_writer_key("central-addr")]
        ));
        assert!(registry.should_send_peripheral_subscriber(
            "other-addr",
            &[central_writer_key("central-addr")]
        ));
    }

    fn raw_test_packet(
        packet_type: rns_wire::flags::PacketType,
        context: rns_wire::context::PacketContext,
    ) -> Vec<u8> {
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
            destination_hash: [0x44; 16],
            context,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0xAA; 96]);
        raw
    }

    #[test]
    fn proof_payload_bypasses_role_preference() {
        let registry = BlePeerLinkRegistry::default();
        let writer_keys = [central_writer_key("AA:BB:CC:DD:EE:FF")];
        let proof = raw_test_packet(
            rns_wire::flags::PacketType::Proof,
            rns_wire::context::PacketContext::LinkProof,
        );
        let data = raw_test_packet(
            rns_wire::flags::PacketType::Data,
            rns_wire::context::PacketContext::None,
        );

        assert!(payload_needs_redundant_role_fanout(&proof));
        assert!(should_send_peripheral_payload(
            &registry,
            "AA:BB:CC:DD:EE:FF",
            &writer_keys,
            &proof,
        ));
        assert!(!payload_needs_redundant_role_fanout(&data));
        assert!(!should_send_peripheral_payload(
            &registry,
            "AA:BB:CC:DD:EE:FF",
            &writer_keys,
            &data,
        ));
    }

    #[test]
    fn malformed_payload_uses_normal_role_preference() {
        let registry = BlePeerLinkRegistry::default();
        let writer_keys = [central_writer_key("AA:BB:CC:DD:EE:FF")];

        assert!(!payload_needs_redundant_role_fanout(
            b"not-a-reticulum-packet"
        ));
        assert!(!should_send_peripheral_payload(
            &registry,
            "AA:BB:CC:DD:EE:FF",
            &writer_keys,
            b"not-a-reticulum-packet",
        ));
    }

    #[test]
    fn recently_disconnected_reconnects_are_address_keyed() {
        let map = new_recently_disconnected();
        seed_recently_disconnected(&map, vec![String::new(), "peer-address".into()]);

        {
            let guard = map.lock().unwrap();
            assert!(!guard.contains_key(""));
            assert!(guard.contains_key("peer-address"));
        }

        assert!(!reconnect_in_backoff(&map, "peer-address"));
        record_reconnect_failure(&map, "peer-address");
        record_reconnect_failure(&map, "peer-address");
        record_reconnect_failure(&map, "peer-address");
        assert!(reconnect_in_backoff(&map, "peer-address"));

        record_reconnect_success(&map, "peer-address");
        assert!(!reconnect_in_backoff(&map, "peer-address"));
    }

    #[test]
    fn peer_status_state_reflects_peer_count() {
        assert_eq!(peer_state_for_count(0), PeerState::Starting);
        assert_eq!(peer_state_for_count(1), PeerState::On);
        assert_eq!(peer_state_for_count(7), PeerState::On);
    }

    #[test]
    fn churn_backoff_engages_on_rapid_connect_drop() {
        // Unique address: churn_track is a process-global shared across tests.
        let addr = "churn-flap-aa:01";
        assert!(!in_churn_backoff(addr));
        // Connect + immediate drop is well under CHURN_MIN_STABLE, so each
        // cycle counts as a flap; the backoff must engage at the threshold.
        for _ in 0..RECONNECT_BACKOFF_FAILURES {
            note_peer_connected(addr);
            note_peer_disconnected(addr);
        }
        assert!(
            in_churn_backoff(addr),
            "rapid connect/drop flapping must engage churn backoff"
        );
    }

    #[test]
    fn churn_missing_connect_stamp_never_backs_off() {
        // A disconnect with no recorded connect stamp defaults to "stable" so a
        // missed note_peer_connected can never manufacture wrongful backoff.
        let addr = "churn-nostamp-bb:02";
        for _ in 0..(RECONNECT_BACKOFF_FAILURES + 2) {
            note_peer_disconnected(addr);
        }
        assert!(!in_churn_backoff(addr));
    }

    // ── Constants ──

    #[test]
    fn test_protocol_constants() {
        assert_eq!(MAX_PEERS, 7);
        assert_eq!(KEEPALIVE_INTERVAL.as_secs(), 15);
        assert_eq!(KEEPALIVE_MAX_MISSES, 3);
        assert_eq!(FRAGMENT_TIMEOUT.as_secs(), 30);
        assert_eq!(MIN_RSSI, -85);
        assert_eq!(SCAN_ACTIVE_INTERVAL.as_secs(), 5);
        assert_eq!(SCAN_IDLE_INTERVAL.as_secs(), 30);
        assert_eq!(SCAN_BACKGROUND_INTERVAL.as_secs(), 60);
        assert_eq!(TARGET_MTU, 517);
    }

    #[test]
    fn test_fragment_type_values() {
        assert_eq!(FragmentType::Lone as u8, 0x00);
        assert_eq!(FragmentType::Start as u8, 0x01);
        assert_eq!(FragmentType::Continue as u8, 0x02);
        assert_eq!(FragmentType::End as u8, 0x03);
    }
}
