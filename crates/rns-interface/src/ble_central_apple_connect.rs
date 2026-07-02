//! Apple central-role connect lifecycle. Sister to
//! [`ble_central_apple`](crate::ble_central_apple) (which owns scanning).
//!
//! Apple-specific because btleplug's CoreBluetooth backend allocates its
//! own manager, and two managers in the same process don't share peripheral
//! caches on macOS, so `adapter.peripherals()` returns empty every cycle.

#![cfg(any(target_os = "ios", target_os = "macos"))]

use objc2::runtime::{AnyClass, AnyObject, ClassBuilder, Sel};
use objc2::{msg_send, sel};
use objc2_foundation::NSString;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::ble_peer::{
    COLUMBA_RX_UUID, COLUMBA_SERVICE_UUID, COLUMBA_TX_UUID, PeerProtocol, RATSPEAK_RX_UUID,
    RATSPEAK_SERVICE_UUID, RATSPEAK_TX_UUID,
};

/// `connectPeripheral:` does not self-time-out; iOS RPA rotation leaves
/// ghost identifiers in `Connecting` state forever. 5s recycles ghosts
/// before they block the scan-loop pipeline.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Generous safety net for service / characteristic / notify discovery
/// (CoreBluetooth normally responds in ~200 ms).
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

const DISCOVERED_TTL: Duration = Duration::from_secs(60);

/// Sized to absorb an LXMF fragment burst (~40 × 244B) without unbounded
/// growth on a stuck peer. FIFO drop-oldest.
const PENDING_WRITE_CAP: usize = 128;

struct SendPtr(*mut AnyObject);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

/// Keyed by `CBPeripheral.identifier.UUIDString`.
static CONNECTED_PEERS: OnceLock<Mutex<HashMap<String, Arc<ConnectedPeer>>>> = OnceLock::new();

/// `std::sync::Mutex` so the CB-main-queue delegate can resolve without
/// crossing `.await`.
type PendingKey = (String, CallbackKind);
type PendingSender = oneshot::Sender<Result<(), String>>;
type PendingMap = HashMap<PendingKey, PendingSender>;

static PENDING: OnceLock<Mutex<PendingMap>> = OnceLock::new();

/// Each entry holds a +1 retain — released on prune or replace.
static DISCOVERED: OnceLock<Mutex<HashMap<String, DiscoveredEntry>>> = OnceLock::new();

static DELEGATE_CLASS: OnceLock<&'static AnyClass> = OnceLock::new();

/// Per-peer online flag the disconnect callback can flip without going
/// through the `ConnectedPeer` map.
static ONLINE_FLAGS: OnceLock<Mutex<HashMap<String, Arc<AtomicBool>>>> = OnceLock::new();

/// One-shot disconnect classification, consumed by
/// [`take_last_disconnect_reason`] so the scan loop can distinguish
/// transient RPA-rotation drops from genuine peer failures.
static LAST_DISCONNECT_REASON: OnceLock<Mutex<HashMap<String, DisconnectReason>>> = OnceLock::new();

/// Drained by `peripheralIsReadyToSendWriteWithoutResponse:`.
static PENDING_WRITE: OnceLock<Mutex<HashMap<String, VecDeque<Vec<u8>>>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisconnectReason {
    /// `CBErrorPeripheralConnectionTimeout` — almost always an iPhone /
    /// Pixel RPA rotating out from under our open link. The peer
    /// re-advertises within ~1s.
    Rotation,
    OtherError,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
enum CallbackKind {
    Connect,
    Services,
    Chars,
    Notify,
}

struct DiscoveredEntry {
    peripheral: SendPtr,
    seen_at: Instant,
}

impl Drop for DiscoveredEntry {
    fn drop(&mut self) {
        if !self.peripheral.0.is_null() {
            unsafe {
                let _: () = msg_send![self.peripheral.0, release];
            }
        }
    }
}

fn connected_peers() -> &'static Mutex<HashMap<String, Arc<ConnectedPeer>>> {
    CONNECTED_PEERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn pending() -> &'static Mutex<PendingMap> {
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

fn discovered() -> &'static Mutex<HashMap<String, DiscoveredEntry>> {
    DISCOVERED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn online_flags() -> &'static Mutex<HashMap<String, Arc<AtomicBool>>> {
    ONLINE_FLAGS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn last_disconnect_reason() -> &'static Mutex<HashMap<String, DisconnectReason>> {
    LAST_DISCONNECT_REASON.get_or_init(|| Mutex::new(HashMap::new()))
}

fn pending_write() -> &'static Mutex<HashMap<String, VecDeque<Vec<u8>>>> {
    PENDING_WRITE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn take_last_disconnect_reason(address: &str) -> Option<DisconnectReason> {
    last_disconnect_reason()
        .lock()
        .ok()
        .and_then(|mut g| g.remove(address))
}

/// Drop frees the retained ObjC objects. Disconnect goes via
/// [`disconnect_peer`] (`cancelPeripheralConnection:`); the delegate
/// callback removes the map entry, dropping the last `Arc`.
pub struct ConnectedPeer {
    pub address: String,
    pub protocol: PeerProtocol,
    pub write_mtu: usize,
    pub online: Arc<AtomicBool>,
    peripheral: SendPtr,
    delegate: SendPtr,
    rx_char: SendPtr,
    tx_char: SendPtr,
}

impl Drop for ConnectedPeer {
    fn drop(&mut self) {
        unsafe {
            // Clear the (weakly-retained) delegate first so a late callback
            // can't fire into freed memory after the release below.
            if !self.peripheral.0.is_null() {
                let _: () =
                    msg_send![self.peripheral.0, setDelegate: std::ptr::null::<AnyObject>()];
            }
            for p in [
                &self.delegate,
                &self.rx_char,
                &self.tx_char,
                &self.peripheral,
            ] {
                if !p.0.is_null() {
                    let _: () = msg_send![p.0, release];
                }
            }
        }
    }
}

/// connect → discoverServices → discoverCharacteristics → setNotifyValue,
/// gated on each step's delegate callback. Tears down partial state on Err.
pub async fn connect_peer(
    address: String,
    protocol: PeerProtocol,
) -> Result<Arc<ConnectedPeer>, String> {
    if is_connected(&address) {
        return Err(format!("already connected: {address}"));
    }

    prune_discovered();

    // SendPtr keeps the future `Send` across awaits.
    let peripheral = SendPtr(
        take_discovered(&address)
            .ok_or_else(|| format!("peripheral {address} not in discovered cache"))?,
    );

    let manager = match crate::ble_central_apple::central_manager_ptr() {
        Some(p) => SendPtr(p),
        None => {
            unsafe {
                let _: () = msg_send![peripheral.0, release];
            }
            return Err("central manager not initialized".into());
        }
    };

    let delegate_cls = peripheral_delegate_class();
    let delegate = SendPtr(unsafe {
        let alloced: *mut AnyObject = msg_send![delegate_cls, alloc];
        let inited: *mut AnyObject = msg_send![alloced, init];
        inited
    });

    // Free fn (not closure) so the future stays `Send` past the captured
    // raw pointers.
    fn teardown_partial(
        address: &str,
        manager: *mut AnyObject,
        peripheral: *mut AnyObject,
        delegate: *mut AnyObject,
        reason: &str,
    ) {
        tracing::warn!(
            target: "ble_trace",
            step = "apple_connect.partial_teardown",
            address = %address,
            reason = %reason,
            "Apple BLE central connect: tearing down partial connection"
        );
        unsafe {
            let _: () = msg_send![&*manager, cancelPeripheralConnection: peripheral];
            let _: () = msg_send![peripheral, setDelegate: std::ptr::null::<AnyObject>()];
            let _: () = msg_send![delegate, release];
            let _: () = msg_send![peripheral, release];
        }
        if let Ok(mut g) = pending().lock() {
            for kind in [
                CallbackKind::Connect,
                CallbackKind::Services,
                CallbackKind::Chars,
                CallbackKind::Notify,
            ] {
                g.remove(&(address.to_owned(), kind));
            }
        }
    }

    // Step 1: connectPeripheral
    tracing::info!(
        target: "ble_trace",
        step = "apple_connect.connect_issued",
        address = %address,
        protocol = ?protocol,
        "Apple BLE central: connectPeripheral"
    );
    let rx = install_pending(&address, CallbackKind::Connect);
    unsafe {
        let _: () = msg_send![&*manager.0,
            connectPeripheral: peripheral.0,
            options: std::ptr::null::<AnyObject>()];
    }
    if let Err(e) = await_step(rx, "connect", CONNECT_TIMEOUT).await {
        teardown_partial(&address, manager.0, peripheral.0, delegate.0, &e);
        return Err(e);
    }
    tracing::info!(
        target: "ble_trace",
        step = "apple_connect.did_connect",
        address = %address,
        "Apple BLE central: peripheral connected"
    );

    // Step 2: setDelegate, then discoverServices for the target only.
    let target_service_uuid = match protocol {
        PeerProtocol::Ratspeak => RATSPEAK_SERVICE_UUID,
        PeerProtocol::Columba => COLUMBA_SERVICE_UUID,
    };
    // install_pending must run BEFORE the CB call so a fast-path callback
    // (cached service data) can't race ahead of its own entry.
    let rx = install_pending(&address, CallbackKind::Services);
    unsafe {
        let _: () = msg_send![peripheral.0, setDelegate: delegate.0];
        let svc_filter = build_cbuuid_array(&[target_service_uuid]);
        let _: () = msg_send![peripheral.0, discoverServices: svc_filter];
    }
    if let Err(e) = await_step(rx, "discoverServices", DISCOVERY_TIMEOUT).await {
        teardown_partial(&address, manager.0, peripheral.0, delegate.0, &e);
        return Err(e);
    }

    let service = match unsafe { find_service(peripheral.0, target_service_uuid) } {
        Some(p) => SendPtr(p),
        None => {
            let msg = format!("target service {target_service_uuid} not present after discovery");
            teardown_partial(&address, manager.0, peripheral.0, delegate.0, &msg);
            return Err(msg);
        }
    };
    tracing::info!(
        target: "ble_trace",
        step = "apple_connect.services_discovered",
        address = %address,
        service = %target_service_uuid,
        "Apple BLE central: services discovered"
    );

    // Step 3: discoverCharacteristics for rx + tx UUIDs.
    let (rx_uuid, tx_uuid) = match protocol {
        PeerProtocol::Ratspeak => (RATSPEAK_RX_UUID, RATSPEAK_TX_UUID),
        PeerProtocol::Columba => (COLUMBA_RX_UUID, COLUMBA_TX_UUID),
    };
    let rx = install_pending(&address, CallbackKind::Chars);
    unsafe {
        let chars_filter = build_cbuuid_array(&[rx_uuid, tx_uuid]);
        let _: () = msg_send![peripheral.0,
            discoverCharacteristics: chars_filter,
            forService: service.0];
    }
    if let Err(e) = await_step(rx, "discoverCharacteristics", DISCOVERY_TIMEOUT).await {
        teardown_partial(&address, manager.0, peripheral.0, delegate.0, &e);
        return Err(e);
    }

    let rx_char = match unsafe { find_char(service.0, rx_uuid) } {
        Some(p) => SendPtr(p),
        None => {
            let msg = format!("rx characteristic {rx_uuid} missing after discovery");
            teardown_partial(&address, manager.0, peripheral.0, delegate.0, &msg);
            return Err(msg);
        }
    };
    let tx_char = match unsafe { find_char(service.0, tx_uuid) } {
        Some(p) => SendPtr(p),
        None => {
            let msg = format!("tx characteristic {tx_uuid} missing after discovery");
            teardown_partial(&address, manager.0, peripheral.0, delegate.0, &msg);
            return Err(msg);
        }
    };
    // The peripheral owns these; retain so they outlive any single
    // delegate callback frame.
    unsafe {
        let _: *mut AnyObject = msg_send![rx_char.0, retain];
        let _: *mut AnyObject = msg_send![tx_char.0, retain];
    }
    tracing::info!(
        target: "ble_trace",
        step = "apple_connect.chars_discovered",
        address = %address,
        rx = %rx_uuid,
        tx = %tx_uuid,
        "Apple BLE central: characteristics discovered"
    );

    // Step 4: setNotifyValue:YES on tx_char (CB handles CCCD internally).
    let rx = install_pending(&address, CallbackKind::Notify);
    unsafe {
        let _: () = msg_send![peripheral.0,
            setNotifyValue: true,
            forCharacteristic: tx_char.0];
    }
    if let Err(e) = await_step(rx, "setNotifyValue", DISCOVERY_TIMEOUT).await {
        // Balance the rx/tx retains on failure.
        unsafe {
            let _: () = msg_send![rx_char.0, release];
            let _: () = msg_send![tx_char.0, release];
        }
        teardown_partial(&address, manager.0, peripheral.0, delegate.0, &e);
        return Err(e);
    }
    tracing::info!(
        target: "ble_trace",
        step = "apple_connect.notify_enabled",
        address = %address,
        tx_char = %tx_uuid,
        "Apple BLE central: notifications enabled"
    );

    let online = Arc::new(AtomicBool::new(true));
    {
        let mut g = online_flags().lock().expect("online_flags lock");
        g.insert(address.clone(), online.clone());
    }
    // CB auto-negotiates the ATT MTU during connection setup and exposes the
    // usable per-write payload via maximumWriteValueLengthForType:. Reading it
    // (rather than assuming 244) both prevents silent truncation on a link that
    // negotiated a smaller MTU and unlocks larger writes (iOS commonly 512).
    // Clamp: floor at the ATT-23 minimum, ceil at our fragment TARGET_MTU.
    const WRITE_WITHOUT_RESPONSE: usize = 1; // CBCharacteristicWriteWithoutResponse
    let negotiated: usize =
        unsafe { msg_send![peripheral.0, maximumWriteValueLengthForType: WRITE_WITHOUT_RESPONSE] };
    let write_mtu = negotiated.clamp(20, crate::ble_peer::TARGET_MTU as usize);
    tracing::info!(
        target: "ble_trace",
        step = "apple_connect.mtu",
        address = %address,
        negotiated,
        write_mtu,
        "Apple BLE central: negotiated write MTU"
    );
    let peer = Arc::new(ConnectedPeer {
        address: address.clone(),
        protocol,
        write_mtu,
        online: online.clone(),
        peripheral,
        delegate,
        rx_char,
        tx_char,
    });
    {
        let mut g = connected_peers().lock().expect("connected_peers lock");
        g.insert(address.clone(), peer.clone());
    }
    Ok(peer)
}

/// Queues into [`PENDING_WRITE`] when `canSendWriteWithoutResponse` is
/// false — without queueing, fragmented LXMF messages silently lose every
/// fragment past the first on a loaded radio.
pub fn write_peer(address: &str, data: &[u8]) -> Result<(), String> {
    let peer = {
        let g = connected_peers().lock().expect("connected_peers lock");
        g.get(address).cloned()
    };
    let peer = peer.ok_or_else(|| format!("peer {address} not connected"))?;
    if !peer.online.load(Ordering::SeqCst) {
        return Err(format!("peer {address} marked offline"));
    }

    // The flag can flip back to false at any time after returning true
    // (per Apple's docs); the ready-to-send delegate drains the queue.
    let ready: bool = unsafe { msg_send![peer.peripheral.0, canSendWriteWithoutResponse] };
    if ready {
        unsafe { issue_write(&peer, data) };
        return Ok(());
    }

    let mut g = pending_write().lock().expect("pending_write lock");
    let q = g.entry(address.to_owned()).or_default();
    if q.len() >= PENDING_WRITE_CAP {
        q.pop_front();
        tracing::warn!(
            target: "ble_trace",
            step = "central.write_overflow_drop",
            peer = %address,
            cap = PENDING_WRITE_CAP,
            "Apple BLE central: pending-write ring overflowed, dropping oldest"
        );
    }
    q.push_back(data.to_vec());
    tracing::debug!(
        target: "ble_trace",
        step = "central.write_queued",
        peer = %address,
        bytes = data.len(),
        depth = q.len(),
        "Apple BLE central: write queued (radio queue full)"
    );
    Ok(())
}

/// Requeues at front if canSend flips false mid-drain.
unsafe fn drain_pending_writes(address: &str) {
    let peer = {
        let g = connected_peers().lock().expect("connected_peers lock");
        match g.get(address) {
            Some(p) => p.clone(),
            None => return,
        }
    };
    if !peer.online.load(Ordering::SeqCst) {
        return;
    }
    let mut drained = 0usize;
    loop {
        let entry = {
            let mut g = pending_write().lock().expect("pending_write lock");
            g.get_mut(address).and_then(|q| q.pop_front())
        };
        let Some(data) = entry else {
            break;
        };
        let ready: bool = unsafe { msg_send![peer.peripheral.0, canSendWriteWithoutResponse] };
        if !ready {
            let mut g = pending_write().lock().expect("pending_write lock");
            g.entry(address.to_owned()).or_default().push_front(data);
            break;
        }
        unsafe { issue_write(&peer, &data) };
        drained += 1;
    }
    if drained > 0 {
        tracing::debug!(
            target: "ble_trace",
            step = "central.write_drained",
            peer = %address,
            drained,
            "Apple BLE central: pending writes drained"
        );
    }
}

/// Caller must have either confirmed `canSendWriteWithoutResponse` or be
/// OK with silent drop on a full radio queue.
///
/// # Safety
/// `peer.peripheral.0` and `peer.rx_char.0` must be retained, valid CB
/// pointers.
unsafe fn issue_write(peer: &Arc<ConnectedPeer>, data: &[u8]) {
    unsafe {
        let nsdata = nsdata_from_slice(data);
        const WRITE_WITHOUT_RESPONSE: i64 = 1;
        let _: () = msg_send![peer.peripheral.0,
            writeValue: nsdata,
            forCharacteristic: peer.rx_char.0,
            type: WRITE_WITHOUT_RESPONSE];
    }
}

/// Idempotent.
pub fn disconnect_peer(address: &str) {
    let peer = {
        let mut g = connected_peers().lock().expect("connected_peers lock");
        g.remove(address)
    };
    let Some(peer) = peer else {
        return;
    };
    peer.online.store(false, Ordering::SeqCst);
    if let Ok(mut g) = pending_write().lock() {
        g.remove(address);
    }
    if let Some(manager_ptr) = crate::ble_central_apple::central_manager_ptr() {
        unsafe {
            let _: () = msg_send![&*manager_ptr,
                cancelPeripheralConnection: peer.peripheral.0];
        }
    }
    // online_flags entry stays — the disconnect callback flips it.
    tracing::info!(
        target: "ble_trace",
        step = "apple_connect.disconnect_issued",
        address = %address,
        "Apple BLE central: cancelPeripheralConnection"
    );
}

pub fn is_connected(address: &str) -> bool {
    connected_peers()
        .lock()
        .map(|g| g.contains_key(address))
        .unwrap_or(false)
}

pub fn disconnect_all() {
    let addrs: Vec<String> = {
        let g = connected_peers().lock().expect("connected_peers lock");
        g.keys().cloned().collect()
    };
    for addr in addrs {
        disconnect_peer(&addr);
    }
    if let Ok(mut g) = online_flags().lock() {
        g.clear();
    }
}

/// Adopt a CBPeripheral handed back via `centralManager:willRestoreState:`.
/// Apple guarantees `peripheral.services` is populated and prior TX-char
/// subscriptions are preserved — only the delegate needs rebinding. On
/// success ownership of the +1 retain passes to `ConnectedPeer::drop`; on
/// Err the retain is released.
///
/// # Safety
/// `peripheral` must be a retained, non-null `CBPeripheral *` whose state
/// is `Connected (= 2)`.
pub unsafe fn adopt_restored_peer(
    address: String,
    peripheral: *mut AnyObject,
) -> Result<(), String> {
    if address.is_empty() || peripheral.is_null() {
        return Err("adopt_restored_peer: empty address or null peripheral".into());
    }
    if is_connected(&address) {
        unsafe {
            let _: () = msg_send![peripheral, release];
        }
        return Ok(());
    }

    let (service, protocol, rx_uuid, tx_uuid) = unsafe {
        if let Some(s) = find_service(peripheral, RATSPEAK_SERVICE_UUID) {
            (
                s,
                PeerProtocol::Ratspeak,
                RATSPEAK_RX_UUID,
                RATSPEAK_TX_UUID,
            )
        } else if let Some(s) = find_service(peripheral, COLUMBA_SERVICE_UUID) {
            (s, PeerProtocol::Columba, COLUMBA_RX_UUID, COLUMBA_TX_UUID)
        } else {
            let _: () = msg_send![peripheral, release];
            return Err(format!(
                "adopt_restored_peer: peripheral {address} has no Ratspeak or Columba service"
            ));
        }
    };

    let rx_char = match unsafe { find_char(service, rx_uuid) } {
        Some(p) => SendPtr(p),
        None => {
            unsafe {
                let _: () = msg_send![peripheral, release];
            }
            return Err(format!(
                "adopt_restored_peer: peripheral {address} missing RX char {rx_uuid}"
            ));
        }
    };
    let tx_char = match unsafe { find_char(service, tx_uuid) } {
        Some(p) => SendPtr(p),
        None => {
            unsafe {
                let _: () = msg_send![rx_char.0, retain];
                let _: () = msg_send![rx_char.0, release];
                let _: () = msg_send![peripheral, release];
            }
            return Err(format!(
                "adopt_restored_peer: peripheral {address} missing TX char {tx_uuid}"
            ));
        }
    };
    unsafe {
        // Outlive the autorelease-pool drain; ConnectedPeer::drop balances.
        let _: *mut AnyObject = msg_send![rx_char.0, retain];
        let _: *mut AnyObject = msg_send![tx_char.0, retain];
    }

    let delegate_cls = peripheral_delegate_class();
    let delegate = SendPtr(unsafe {
        let alloced: *mut AnyObject = msg_send![delegate_cls, alloc];
        let inited: *mut AnyObject = msg_send![alloced, init];
        inited
    });
    unsafe {
        let _: () = msg_send![peripheral, setDelegate: delegate.0];
    }

    let online = Arc::new(AtomicBool::new(true));
    {
        let mut g = online_flags().lock().expect("online_flags lock");
        g.insert(address.clone(), online.clone());
    }
    let peer = Arc::new(ConnectedPeer {
        address: address.clone(),
        protocol,
        write_mtu: 244,
        online,
        peripheral: SendPtr(peripheral),
        delegate,
        rx_char,
        tx_char,
    });
    {
        let mut g = connected_peers().lock().expect("connected_peers lock");
        g.insert(address.clone(), peer);
    }
    tracing::info!(
        target: "ble_trace",
        step = "apple_connect.adopted_restored",
        address = %address,
        protocol = ?protocol,
        "Apple BLE central: adopted restored peripheral"
    );
    Ok(())
}

/// CB keeps connections alive thanks to `bluetooth-central`
/// UIBackgroundMode + restore-identifier; this just logs inventory.
pub fn on_app_will_resign_active() {
    let connected = connected_peers().lock().map(|g| g.len()).unwrap_or(0);
    let pending = pending_write()
        .lock()
        .map(|g| g.values().map(|q| q.len()).sum::<usize>())
        .unwrap_or(0);
    tracing::info!(
        target: "ble_trace",
        step = "apple_connect.foregrounding_inventory",
        connected_peers = connected,
        pending_writes = pending,
        "Apple BLE central: app will resign active \u{2014} connections kept alive by bluetooth-central background mode"
    );
}

/// Prune discovered pointers older than [`DISCOVERED_TTL`] — after a long
/// background those are RPA-rotated ghosts.
pub fn on_app_did_become_active() {
    prune_discovered();
    let discovered_remaining = match discovered().lock() {
        Ok(g) => g.len(),
        Err(_) => 0,
    };
    let connected = connected_peers().lock().map(|g| g.len()).unwrap_or(0);
    tracing::info!(
        target: "ble_trace",
        step = "apple_connect.foregrounded",
        connected_peers = connected,
        discovered_remaining,
        "Apple BLE central: app did become active \u{2014} discovery cache pruned"
    );
}

/// Replacing an entry releases the old one.
///
/// # Safety
/// `peripheral` must be valid and non-null; this function retains it.
pub unsafe fn record_discovered(address: String, peripheral: *mut AnyObject) {
    if address.is_empty() || peripheral.is_null() {
        return;
    }
    unsafe {
        // Survive the scan delegate's autorelease-pool drain.
        let _: *mut AnyObject = msg_send![peripheral, retain];
    }
    let mut g = match discovered().lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let entry = DiscoveredEntry {
        peripheral: SendPtr(peripheral),
        seen_at: Instant::now(),
    };
    g.insert(address, entry);
}

pub fn prune_discovered() {
    let mut g = match discovered().lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    g.retain(|_, e| e.seen_at.elapsed() < DISCOVERED_TTL);
}

fn take_discovered(address: &str) -> Option<*mut AnyObject> {
    let mut g = discovered().lock().ok()?;
    let entry = g.remove(address)?;
    // Forget so DiscoveredEntry::drop doesn't release — caller now owns the
    // +1 retain from record_discovered.
    let p = entry.peripheral.0;
    std::mem::forget(entry);
    Some(p)
}

pub fn on_did_connect(address: &str) {
    resolve_pending(address, CallbackKind::Connect, Ok(()));
}

pub fn on_did_fail_connect(address: &str, err: String) {
    resolve_pending(address, CallbackKind::Connect, Err(err));
}

pub fn on_did_disconnect(address: &str, err: Option<String>) {
    let removed = {
        let mut g = match connected_peers().lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        g.remove(address)
    };
    if let Some(peer) = removed {
        peer.online.store(false, Ordering::SeqCst);
    }
    if let Ok(mut g) = online_flags().lock() {
        if let Some(flag) = g.remove(address) {
            flag.store(false, Ordering::SeqCst);
        }
    }

    let classified = classify_disconnect_reason(err.as_deref());
    if let Ok(mut g) = last_disconnect_reason().lock() {
        g.insert(address.to_string(), classified);
    }

    let reason = err.clone().unwrap_or_else(|| "peer disconnected".into());
    // Short-circuit any in-flight step so the awaiting task returns without
    // burning the 10s timeout.
    for kind in [
        CallbackKind::Connect,
        CallbackKind::Services,
        CallbackKind::Chars,
        CallbackKind::Notify,
    ] {
        resolve_pending(address, kind, Err(format!("peer disconnected: {reason}")));
    }
    tracing::info!(
        target: "ble_trace",
        step = "apple_connect.did_disconnect",
        address = %address,
        error = ?err,
        "Apple BLE central: didDisconnectPeripheral"
    );
    crate::ble_peer::dispatch_event(crate::ble_peer::BlePeerEvent::Disconnected {
        address: address.into(),
        reason,
    });
}

fn install_pending(address: &str, kind: CallbackKind) -> oneshot::Receiver<Result<(), String>> {
    let (tx, rx) = oneshot::channel();
    let mut g = pending().lock().expect("pending lock");
    g.insert((address.to_owned(), kind), tx);
    rx
}

fn resolve_pending(address: &str, kind: CallbackKind, result: Result<(), String>) {
    let tx = {
        let mut g = match pending().lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        g.remove(&(address.to_owned(), kind))
    };
    if let Some(tx) = tx {
        let _ = tx.send(result);
    }
}

/// English-locale, case-insensitive substring match against rotation
/// signatures: `CBErrorPeripheralConnectionTimeout` (constant or localized
/// "timed out unexpectedly") and "specified device has disconnected".
fn classify_disconnect_reason(err: Option<&str>) -> DisconnectReason {
    let Some(s) = err else {
        return DisconnectReason::OtherError;
    };
    let lower = s.to_ascii_lowercase();
    if lower.contains("timed out unexpectedly")
        || lower.contains("cberrorperipheralconnectiontimeout")
        || lower.contains("specified device has disconnected")
    {
        DisconnectReason::Rotation
    } else {
        DisconnectReason::OtherError
    }
}

async fn await_step(
    rx: oneshot::Receiver<Result<(), String>>,
    label: &'static str,
    timeout: Duration,
) -> Result<(), String> {
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(e))) => Err(format!("{label}: {e}")),
        Ok(Err(_)) => Err(format!("{label}: oneshot dropped before reply")),
        Err(_) => Err(format!("{label}: timed out after {timeout:?}")),
    }
}

fn peripheral_delegate_class() -> &'static AnyClass {
    DELEGATE_CLASS.get_or_init(|| {
        let superclass = AnyClass::get("NSObject").expect("NSObject must exist");
        let mut builder = ClassBuilder::new("RatspeakBlePeripheralDelegate", superclass)
            .expect("ClassBuilder for peripheral delegate must succeed");

        extern "C" fn did_discover_services(
            _this: *mut AnyObject,
            _sel: Sel,
            peripheral: *mut AnyObject,
            error: *mut AnyObject,
        ) {
            let address = unsafe { peripheral_identifier(peripheral) };
            if address.is_empty() {
                return;
            }
            let result = if error.is_null() {
                Ok(())
            } else {
                Err(unsafe { nserror_message(error) })
            };
            resolve_pending(&address, CallbackKind::Services, result);
        }

        extern "C" fn did_discover_characteristics(
            _this: *mut AnyObject,
            _sel: Sel,
            peripheral: *mut AnyObject,
            _service: *mut AnyObject,
            error: *mut AnyObject,
        ) {
            let address = unsafe { peripheral_identifier(peripheral) };
            if address.is_empty() {
                return;
            }
            let result = if error.is_null() {
                Ok(())
            } else {
                Err(unsafe { nserror_message(error) })
            };
            resolve_pending(&address, CallbackKind::Chars, result);
        }

        extern "C" fn did_update_notification_state(
            _this: *mut AnyObject,
            _sel: Sel,
            peripheral: *mut AnyObject,
            _characteristic: *mut AnyObject,
            error: *mut AnyObject,
        ) {
            let address = unsafe { peripheral_identifier(peripheral) };
            if address.is_empty() {
                return;
            }
            let result = if error.is_null() {
                Ok(())
            } else {
                Err(unsafe { nserror_message(error) })
            };
            resolve_pending(&address, CallbackKind::Notify, result);
        }

        extern "C" fn did_update_value_for_characteristic(
            _this: *mut AnyObject,
            _sel: Sel,
            peripheral: *mut AnyObject,
            characteristic: *mut AnyObject,
            error: *mut AnyObject,
        ) {
            if peripheral.is_null() || characteristic.is_null() || !error.is_null() {
                return;
            }
            let address = unsafe { peripheral_identifier(peripheral) };
            if address.is_empty() {
                return;
            }
            let bytes = unsafe { characteristic_value_bytes(characteristic) };
            if bytes.is_empty() {
                return;
            }
            tracing::debug!(
                target: "ble_trace",
                step = "apple_connect.notify_recv",
                address = %address,
                len = bytes.len(),
                "Apple BLE central: notify received"
            );
            // Same INBOUND_TX as apple_peripheral's GATT-server delegate —
            // one reassembler downstream.
            if !crate::ble_peer::try_push_apple_inbound(address.clone(), bytes) {
                tracing::warn!(
                    target: "ble_trace",
                    step = "apple_connect.inbound_drop",
                    address = %address,
                    "Apple BLE central: inbound channel full or uninitialised"
                );
            }
        }

        // Kept registered so a future With-Response write doesn't crash on
        // missing selector. We use WriteWithoutResponse, so this is informational.
        extern "C" fn did_write_value_for_characteristic(
            _this: *mut AnyObject,
            _sel: Sel,
            _peripheral: *mut AnyObject,
            _characteristic: *mut AnyObject,
            _error: *mut AnyObject,
        ) {
        }

        extern "C" fn is_ready_to_send_write_without_response(
            _this: *mut AnyObject,
            _sel: Sel,
            peripheral: *mut AnyObject,
        ) {
            let address = unsafe { peripheral_identifier(peripheral) };
            if address.is_empty() {
                return;
            }
            unsafe { drain_pending_writes(&address) };
        }

        unsafe {
            builder.add_method(
                sel!(peripheral:didDiscoverServices:),
                did_discover_services
                    as extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject),
            );
            builder.add_method(
                sel!(peripheral:didDiscoverCharacteristicsForService:error:),
                did_discover_characteristics
                    as extern "C" fn(
                        *mut AnyObject,
                        Sel,
                        *mut AnyObject,
                        *mut AnyObject,
                        *mut AnyObject,
                    ),
            );
            builder.add_method(
                sel!(peripheral:didUpdateNotificationStateForCharacteristic:error:),
                did_update_notification_state
                    as extern "C" fn(
                        *mut AnyObject,
                        Sel,
                        *mut AnyObject,
                        *mut AnyObject,
                        *mut AnyObject,
                    ),
            );
            builder.add_method(
                sel!(peripheral:didUpdateValueForCharacteristic:error:),
                did_update_value_for_characteristic
                    as extern "C" fn(
                        *mut AnyObject,
                        Sel,
                        *mut AnyObject,
                        *mut AnyObject,
                        *mut AnyObject,
                    ),
            );
            builder.add_method(
                sel!(peripheral:didWriteValueForCharacteristic:error:),
                did_write_value_for_characteristic
                    as extern "C" fn(
                        *mut AnyObject,
                        Sel,
                        *mut AnyObject,
                        *mut AnyObject,
                        *mut AnyObject,
                    ),
            );
            builder.add_method(
                sel!(peripheralIsReadyToSendWriteWithoutResponse:),
                is_ready_to_send_write_without_response
                    as extern "C" fn(*mut AnyObject, Sel, *mut AnyObject),
            );
        }
        builder.register()
    })
}

/// Autoreleased `NSArray<CBUUID>`; CB retains internally.
fn build_cbuuid_array(uuids: &[Uuid]) -> *mut AnyObject {
    if uuids.is_empty() {
        return std::ptr::null_mut();
    }
    let cbuuid_cls = match AnyClass::get("CBUUID") {
        Some(c) => c,
        None => return std::ptr::null_mut(),
    };
    let nsarr_cls = match AnyClass::get("NSArray") {
        Some(c) => c,
        None => return std::ptr::null_mut(),
    };
    let mut raw_ptrs: Vec<*const AnyObject> = Vec::with_capacity(uuids.len());
    for u in uuids {
        let s = NSString::from_str(&u.to_string());
        unsafe {
            let cb: *mut AnyObject = msg_send![cbuuid_cls, UUIDWithString: &*s];
            raw_ptrs.push(cb as *const AnyObject);
        }
    }
    unsafe {
        msg_send![nsarr_cls,
            arrayWithObjects: raw_ptrs.as_ptr(),
            count: raw_ptrs.len()]
    }
}

/// Autoreleased `NSData` over a copy of `bytes`; valid for the synchronous
/// CB call only.
unsafe fn nsdata_from_slice(bytes: &[u8]) -> *mut AnyObject {
    let cls = AnyClass::get("NSData").expect("NSData class must exist");
    let ptr = bytes.as_ptr() as *const std::ffi::c_void;
    let len = bytes.len();
    unsafe { msg_send![cls, dataWithBytes: ptr, length: len] }
}

unsafe fn find_service(peripheral: *mut AnyObject, uuid: Uuid) -> Option<*mut AnyObject> {
    if peripheral.is_null() {
        return None;
    }
    unsafe {
        let services: *mut AnyObject = msg_send![&*peripheral, services];
        if services.is_null() {
            return None;
        }
        let count: usize = msg_send![&*services, count];
        for i in 0..count {
            let svc: *mut AnyObject = msg_send![&*services, objectAtIndex: i];
            if svc.is_null() {
                continue;
            }
            let cb_uuid: *mut AnyObject = msg_send![&*svc, UUID];
            if cb_uuid.is_null() {
                continue;
            }
            if cbuuid_matches(cb_uuid, uuid) {
                return Some(svc);
            }
        }
    }
    None
}

unsafe fn find_char(service: *mut AnyObject, uuid: Uuid) -> Option<*mut AnyObject> {
    if service.is_null() {
        return None;
    }
    unsafe {
        let chars: *mut AnyObject = msg_send![&*service, characteristics];
        if chars.is_null() {
            return None;
        }
        let count: usize = msg_send![&*chars, count];
        for i in 0..count {
            let ch: *mut AnyObject = msg_send![&*chars, objectAtIndex: i];
            if ch.is_null() {
                continue;
            }
            let cb_uuid: *mut AnyObject = msg_send![&*ch, UUID];
            if cb_uuid.is_null() {
                continue;
            }
            if cbuuid_matches(cb_uuid, uuid) {
                return Some(ch);
            }
        }
    }
    None
}

/// CBUUID's `UUIDString` returns whichever form (16-bit short or 128-bit)
/// CB canonicalised to.
unsafe fn cbuuid_matches(cb_uuid: *mut AnyObject, target: Uuid) -> bool {
    unsafe {
        let s_obj: *mut AnyObject = msg_send![&*cb_uuid, UUIDString];
        if s_obj.is_null() {
            return false;
        }
        let s = nsstring_to_string(s_obj);
        if let Ok(parsed) = Uuid::parse_str(&s) {
            return parsed == target;
        }
        if let Ok(expanded) = expand_short_uuid(&s) {
            return expanded == target;
        }
    }
    false
}

fn expand_short_uuid(s: &str) -> Result<Uuid, ()> {
    let hex = s.trim();
    match hex.len() {
        4 => {
            let v = u16::from_str_radix(hex, 16).map_err(|_| ())?;
            Uuid::parse_str(&format!("0000{v:04x}-0000-1000-8000-00805f9b34fb")).map_err(|_| ())
        }
        8 => {
            let v = u32::from_str_radix(hex, 16).map_err(|_| ())?;
            Uuid::parse_str(&format!("{v:08x}-0000-1000-8000-00805f9b34fb")).map_err(|_| ())
        }
        _ => Err(()),
    }
}

unsafe fn peripheral_identifier(peripheral: *mut AnyObject) -> String {
    if peripheral.is_null() {
        return String::new();
    }
    unsafe {
        let id_obj: *mut AnyObject = msg_send![&*peripheral, identifier];
        if id_obj.is_null() {
            return String::new();
        }
        let uuid_str: *mut AnyObject = msg_send![&*id_obj, UUIDString];
        nsstring_to_string(uuid_str)
    }
}

unsafe fn characteristic_value_bytes(characteristic: *mut AnyObject) -> Vec<u8> {
    if characteristic.is_null() {
        return Vec::new();
    }
    unsafe {
        let value: *mut AnyObject = msg_send![&*characteristic, value];
        if value.is_null() {
            return Vec::new();
        }
        let len: usize = msg_send![&*value, length];
        if len == 0 {
            return Vec::new();
        }
        let ptr: *const std::ffi::c_void = msg_send![&*value, bytes];
        if ptr.is_null() {
            return Vec::new();
        }
        std::slice::from_raw_parts(ptr as *const u8, len).to_vec()
    }
}

unsafe fn nserror_message(err: *mut AnyObject) -> String {
    if err.is_null() {
        return String::new();
    }
    unsafe {
        let desc: *mut AnyObject = msg_send![&*err, localizedDescription];
        nsstring_to_string(desc)
    }
}

unsafe fn nsstring_to_string(s: *mut AnyObject) -> String {
    if s.is_null() {
        return String::new();
    }
    unsafe {
        let utf8: *const std::ffi::c_char = msg_send![&*s, UTF8String];
        let len: usize = msg_send![&*s, lengthOfBytesUsingEncoding: 4usize];
        if utf8.is_null() || len == 0 {
            return String::new();
        }
        let bytes = std::slice::from_raw_parts(utf8 as *const u8, len);
        String::from_utf8_lossy(bytes).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_short_uuid_round_trip_16bit() {
        let u = expand_short_uuid("180D").expect("must parse");
        assert_eq!(
            u,
            Uuid::parse_str("0000180d-0000-1000-8000-00805f9b34fb").unwrap()
        );
    }

    #[test]
    fn expand_short_uuid_round_trip_32bit() {
        let u = expand_short_uuid("0000180D").expect("must parse");
        assert_eq!(
            u,
            Uuid::parse_str("0000180d-0000-1000-8000-00805f9b34fb").unwrap()
        );
    }

    #[test]
    fn expand_short_uuid_rejects_unsupported_lengths() {
        assert!(expand_short_uuid("180").is_err());
        assert!(expand_short_uuid("zzzz").is_err());
        assert!(expand_short_uuid("").is_err());
    }

    #[test]
    fn pending_install_and_resolve_round_trip() {
        let _ = pending().lock().unwrap().drain();
        let mut rx = install_pending("test-addr", CallbackKind::Connect);
        resolve_pending("test-addr", CallbackKind::Connect, Ok(()));
        let got = rx.try_recv().unwrap();
        assert!(got.is_ok());
    }

    #[test]
    fn pending_resolve_unknown_is_silent_noop() {
        resolve_pending("nope", CallbackKind::Notify, Err("ignored".into()));
    }

    #[test]
    fn classify_rotation_via_localized_description() {
        let r = classify_disconnect_reason(Some("The connection has timed out unexpectedly."));
        assert_eq!(r, DisconnectReason::Rotation);
    }

    #[test]
    fn classify_rotation_via_cb_error_constant() {
        let r =
            classify_disconnect_reason(Some("CBErrorPeripheralConnectionTimeout: connection lost"));
        assert_eq!(r, DisconnectReason::Rotation);
    }

    #[test]
    fn classify_rotation_is_case_insensitive() {
        let r = classify_disconnect_reason(Some("TIMED OUT UNEXPECTEDLY"));
        assert_eq!(r, DisconnectReason::Rotation);
    }

    #[test]
    fn classify_rotation_via_specified_device_disconnected() {
        let r = classify_disconnect_reason(Some("The specified device has disconnected from us."));
        assert_eq!(r, DisconnectReason::Rotation);
    }

    #[test]
    fn classify_other_error_fallthrough() {
        assert_eq!(
            classify_disconnect_reason(Some("Bluetooth radio off")),
            DisconnectReason::OtherError
        );
        assert_eq!(
            classify_disconnect_reason(None),
            DisconnectReason::OtherError
        );
    }

    #[test]
    fn last_disconnect_reason_round_trip() {
        let _ = last_disconnect_reason().lock().unwrap().drain();
        last_disconnect_reason()
            .lock()
            .unwrap()
            .insert("addr-x".into(), DisconnectReason::Rotation);
        let got = take_last_disconnect_reason("addr-x");
        assert_eq!(got, Some(DisconnectReason::Rotation));
        assert_eq!(take_last_disconnect_reason("addr-x"), None);
    }
}
