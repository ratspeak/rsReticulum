//! Apple CBCentralManager scan driver.
//!
//! Exists to pass `CBCentralManagerScanOptionAllowDuplicatesKey = YES` to
//! `scanForPeripheralsWithServices:options:` — btleplug does not expose
//! that key, and without it CoreBluetooth reports each peripheral at most
//! once per scan session.

#![cfg(any(target_os = "ios", target_os = "macos"))]

use crate::ble_central_lifecycle::{
    CentralEvent, CentralLifecycle, CentralState, DiscoveryEvent, classify_protocol,
};
use crate::ble_peer::{COLUMBA_SERVICE_UUID, RATSPEAK_SERVICE_UUID};
use objc2::runtime::{AnyClass, AnyObject, ClassBuilder, Sel};
use objc2::{msg_send, sel};
use objc2_core_bluetooth::{
    CBAdvertisementDataServiceUUIDsKey, CBCentralManagerOptionRestoreIdentifierKey,
    CBCentralManagerRestoredStatePeripheralsKey, CBCentralManagerRestoredStateScanOptionsKey,
    CBCentralManagerRestoredStateScanServicesKey, CBCentralManagerScanOptionAllowDuplicatesKey,
};
use objc2_foundation::NSString;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Must stay stable across updates; changing forfeits previously-backgrounded connections.
const CENTRAL_RESTORE_ID: &str = "org.ratspeak.ios.central";

struct SendPtr(*mut AnyObject);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

/// Live CBCentralManager. Null when no scan is in flight.
static MANAGER_PTR: OnceLock<Mutex<SendPtr>> = OnceLock::new();
static DELEGATE_CLASS: OnceLock<&'static AnyClass> = OnceLock::new();
static LIFECYCLE: OnceLock<CentralLifecycle> = OnceLock::new();
/// Replaced every `start_scan` so each cycle has a fresh receiver.
static DISCOVERY_TX: OnceLock<Mutex<Option<mpsc::UnboundedSender<DiscoveryEvent>>>> =
    OnceLock::new();
/// Worker thread waits on this until `did_update_state` reports `PoweredOn`.
static POWERED_ON_TX: OnceLock<Mutex<Option<std::sync::mpsc::Sender<()>>>> = OnceLock::new();
static SCAN_SERVICES: OnceLock<Mutex<Vec<Uuid>>> = OnceLock::new();

fn lifecycle() -> &'static CentralLifecycle {
    LIFECYCLE.get_or_init(CentralLifecycle::new)
}

/// Trace invalid transitions instead of panicking — BLE stacks occasionally
/// deliver redundant callbacks.
fn apply_event(event: CentralEvent) -> Option<CentralState> {
    match lifecycle().apply(event.clone()) {
        Ok(state) => {
            tracing::trace!(?event, ?state, "Apple BLE central lifecycle");
            Some(state)
        }
        Err(err) => {
            tracing::warn!(?err, "Apple BLE central lifecycle: rejected transition");
            None
        }
    }
}

fn discovery_tx() -> &'static Mutex<Option<mpsc::UnboundedSender<DiscoveryEvent>>> {
    DISCOVERY_TX.get_or_init(|| Mutex::new(None))
}

fn powered_on_tx() -> &'static Mutex<Option<std::sync::mpsc::Sender<()>>> {
    POWERED_ON_TX.get_or_init(|| Mutex::new(None))
}

fn scan_services() -> &'static Mutex<Vec<Uuid>> {
    SCAN_SERVICES.get_or_init(|| Mutex::new(Vec::new()))
}

fn manager_slot() -> &'static Mutex<SendPtr> {
    MANAGER_PTR.get_or_init(|| Mutex::new(SendPtr(std::ptr::null_mut())))
}

/// Start a CBCentralManager scan with `AllowDuplicatesKey = YES`. Empty
/// `services` scans for all advertisements.
pub async fn start_scan(
    services: Vec<Uuid>,
) -> Result<mpsc::UnboundedReceiver<DiscoveryEvent>, String> {
    let cur = lifecycle().current();
    if matches!(
        cur,
        CentralState::Scanning | CentralState::StartingWaitingPlatform | CentralState::StoppingScan
    ) {
        return Err(format!("BLE scan already in progress (state={cur:?})"));
    }

    apply_event(CentralEvent::StartRequested);

    let (tx, rx) = mpsc::unbounded_channel::<DiscoveryEvent>();
    {
        let mut g = discovery_tx()
            .lock()
            .map_err(|e| format!("discovery_tx lock poisoned: {e}"))?;
        *g = Some(tx);
    }
    {
        let mut g = scan_services()
            .lock()
            .map_err(|e| format!("scan_services lock poisoned: {e}"))?;
        *g = services;
    }

    // CoreBluetooth on macOS returns state=Unsupported on rapid alloc/release
    // cycles, so the first manager stays retained and later cycles just rotate
    // the discovery channel and reissue `scanForPeripheralsWithServices`.
    let existing_mgr: Option<*mut AnyObject> = {
        match manager_slot().lock() {
            Ok(g) if !g.0.is_null() => Some(g.0),
            _ => None,
        }
    };
    if let Some(mgr_raw) = existing_mgr {
        unsafe {
            scan_with_manager(mgr_raw)
                .map_err(|e| format!("rescan on persistent manager failed: {e}"))?;
        }
        apply_event(CentralEvent::PlatformReady);
        tracing::info!(
            target: "ble_trace",
            step = "central.scan_reused_manager",
            "Apple BLE Central: rescan invoked on persistent manager"
        );
        return Ok(rx);
    }

    let (signal_tx, signal_rx) = std::sync::mpsc::channel::<()>();
    {
        let mut g = powered_on_tx()
            .lock()
            .map_err(|e| format!("powered_on_tx lock poisoned: {e}"))?;
        *g = Some(signal_tx);
    }

    // OS thread: raw `*mut AnyObject` isn't Send, and
    // `initWithDelegate:queue:nil` wires the delegate to CoreBluetooth's
    // main dispatch queue.
    std::thread::spawn(move || unsafe {
        let delegate_cls = get_delegate_class();
        let delegate_raw: *mut AnyObject = msg_send![delegate_cls, alloc];
        let delegate_raw: *mut AnyObject = msg_send![delegate_raw, init];

        let Some(mgr_cls) = AnyClass::get("CBCentralManager") else {
            tracing::error!("Apple BLE Central: CBCentralManager class not found");
            return;
        };
        let mgr_raw: *mut AnyObject = msg_send![mgr_cls, alloc];
        // RestoreIdentifierKey lets iOS resurrect us for a background BLE
        // event after the process is killed.
        let opts = match build_init_options() {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("Apple BLE Central: init-options build failed: {e}");
                std::ptr::null_mut::<AnyObject>()
            }
        };
        let mgr_raw: *mut AnyObject = msg_send![mgr_raw,
            initWithDelegate: delegate_raw,
            queue: std::ptr::null::<AnyObject>(),
            options: opts,
        ];
        // `retain` returns `id`; binding as `*mut AnyObject` avoids objc2's
        // debug class-verify tripping on KVO-swizzled subclasses.
        let _: *mut AnyObject = msg_send![mgr_raw, retain];

        if let Ok(mut g) = manager_slot().lock() {
            *g = SendPtr(mgr_raw);
        }
        tracing::info!("Apple BLE Central: manager created, waiting for PoweredOn");

        // 10s safety net; real Bluetooth-off/permission errors surface
        // through did_update_state, not here.
        if let Err(e) = signal_rx.recv_timeout(Duration::from_secs(10)) {
            tracing::error!("Apple BLE Central: timed out waiting for PoweredOn: {e}");
            return;
        }

        match scan_with_manager(mgr_raw) {
            Ok(()) => tracing::info!(
                "Apple BLE Central: scanForPeripherals invoked (AllowDuplicates=YES)"
            ),
            Err(e) => tracing::error!("Apple BLE Central: scan invocation failed: {e}"),
        }
    });

    Ok(rx)
}

/// Idempotent.
pub async fn stop_scan() -> Result<(), String> {
    let cur = lifecycle().current();
    if matches!(
        cur,
        CentralState::Idle | CentralState::Stopped | CentralState::Failed
    ) {
        tracing::debug!(state = ?cur, "Apple BLE Central: stop_scan is a no-op");
        return Ok(());
    }

    apply_event(CentralEvent::StopRequested);

    // Issue the ObjC calls outside the manager lock so concurrent
    // did_discover callbacks (which take the same lock) can't deadlock.
    let mgr_ptr: *mut AnyObject = {
        match manager_slot().lock() {
            Ok(g) if !g.0.is_null() => g.0,
            _ => {
                // No manager ever constructed, or already torn down.
                finalize_stop();
                return Ok(());
            }
        }
    };

    unsafe {
        // We do NOT release the manager — the next start_scan reuses it.
        // Per-cycle release on macOS triggers CBManagerStateUnsupported.
        // `teardown_central` does the full release on interface shutdown.
        let _: () = msg_send![&*mgr_ptr, stopScan];
    }

    finalize_stop();
    Ok(())
}

/// Full teardown — interface shutdown only. Per-cycle stops use
/// [`stop_scan`] to keep the manager alive (macOS alloc-cycle bug).
pub async fn teardown_central() -> Result<(), String> {
    let _ = stop_scan().await;

    let mgr_ptr: *mut AnyObject = match manager_slot().lock() {
        Ok(g) if !g.0.is_null() => g.0,
        _ => return Ok(()),
    };

    unsafe {
        // Detach delegate before release so a late main-queue callback
        // can't fire into a freed object.
        let _: () = msg_send![&*mgr_ptr, setDelegate: std::ptr::null::<AnyObject>()];
        // Balance the explicit retain from start_scan; the original alloc
        // ref is intentionally left intact — CoreBluetooth keeps one for
        // main-queue drain and a double-release UAFs on contended teardown.
        let _: () = msg_send![&*mgr_ptr, release];
    }

    if let Ok(mut g) = manager_slot().lock() {
        *g = SendPtr(std::ptr::null_mut());
    }

    Ok(())
}

fn finalize_stop() {
    if let Some(lock) = POWERED_ON_TX.get()
        && let Ok(mut g) = lock.lock()
    {
        *g = None;
    }
    // Drop the discovery sender so receivers don't hang on recv.
    if let Some(lock) = DISCOVERY_TX.get()
        && let Ok(mut g) = lock.lock()
    {
        *g = None;
    }
    apply_event(CentralEvent::ScanStopped);
    apply_event(CentralEvent::Reset);
}

pub fn current_state() -> CentralState {
    lifecycle().current()
}

/// Persistent `CBCentralManager` pointer. Apple central peripheral caches
/// are per-manager, not per-process — `ble_central_apple_connect` must
/// drive `connectPeripheral:` against the same manager that scanned.
pub fn central_manager_ptr() -> Option<*mut AnyObject> {
    let lock = MANAGER_PTR.get()?;
    let g = lock.lock().ok()?;
    if g.0.is_null() { None } else { Some(g.0) }
}

fn get_delegate_class() -> &'static AnyClass {
    DELEGATE_CLASS.get_or_init(|| {
        let superclass = AnyClass::get("NSObject").expect("NSObject must exist");
        let mut builder = ClassBuilder::new("RatspeakBleCentralDelegate", superclass)
            .expect("ClassBuilder for central delegate must succeed");

        extern "C" fn did_update_state(
            _this: *mut AnyObject,
            _sel: Sel,
            central: *mut AnyObject,
        ) {
            if central.is_null() {
                return;
            }
            let state: i64 = unsafe { msg_send![&*central, state] };
            tracing::info!(
                state,
                name = cb_state_name(state),
                "Apple BLE Central: state update"
            );

            match state {
                // CBManagerState: 0=Unknown 1=Resetting 2=Unsupported
                // 3=Unauthorized 4=PoweredOff 5=PoweredOn.
                0 => {}

                1 => {
                    apply_event(CentralEvent::PlatformUnavailable {
                        reason: "resetting".into(),
                    });
                }

                2 => {
                    apply_event(CentralEvent::FatalError {
                        reason: "bluetooth unsupported".into(),
                    });
                }

                3 => {
                    apply_event(CentralEvent::FatalError {
                        reason: "bluetooth permission denied".into(),
                    });
                }

                4 => {
                    apply_event(CentralEvent::PlatformUnavailable {
                        reason: "bluetooth off".into(),
                    });
                }

                // PoweredOn: signal the start_scan worker, or reissue
                // scanForPeripherals if the worker already exited (recovery).
                5 => {
                    let tx = match powered_on_tx().lock() {
                        Ok(mut g) => g.take(),
                        Err(e) => {
                            tracing::error!("Apple BLE Central: powered_on_tx lock err: {e}");
                            return;
                        }
                    };
                    if let Some(tx) = tx {
                        if let Err(e) = tx.send(()) {
                            tracing::error!(
                                "Apple BLE Central: powered_on signal send err: {e}"
                            );
                            return;
                        }
                        apply_event(CentralEvent::PlatformReady);
                        tracing::info!(
                            "Apple BLE Central: powered on (initial), releasing worker"
                        );
                        return;
                    }

                    let s = lifecycle().current();
                    if !matches!(s, CentralState::StartingWaitingPlatform) {
                        tracing::info!(state = ?s, "Apple BLE Central: PoweredOn with no recovery needed");
                        return;
                    }
                    let Some(mgr_lock) = MANAGER_PTR.get() else {
                        tracing::warn!(
                            "Apple BLE Central: recovery PoweredOn but manager slot unset"
                        );
                        return;
                    };
                    let mgr_ptr = match mgr_lock.lock() {
                        Ok(g) if !g.0.is_null() => g.0,
                        _ => {
                            tracing::warn!(
                                "Apple BLE Central: recovery PoweredOn but manager is null"
                            );
                            return;
                        }
                    };
                    unsafe {
                        match scan_with_manager(mgr_ptr) {
                            Ok(()) => {
                                apply_event(CentralEvent::PlatformReady);
                                tracing::info!(
                                    "Apple BLE Central: powered on (recovery), scan resumed"
                                );
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Apple BLE Central: recovery scan invocation failed: {e}"
                                );
                            }
                        }
                    }
                }

                _ => {
                    tracing::warn!(state, "Apple BLE Central: unknown CBManagerState");
                }
            }
        }

        // iOS calls this BEFORE `centralManagerDidUpdateState:` when
        // resurrecting our process for a background BLE event. Restored TX
        // subscriptions survive; we just need a live per-peripheral delegate
        // before any further callbacks fire.
        extern "C" fn will_restore_state(
            _this: *mut AnyObject,
            _sel: Sel,
            _central: *mut AnyObject,
            dict: *mut AnyObject,
        ) {
            if dict.is_null() {
                tracing::info!("Apple BLE Central: willRestoreState (empty dict)");
                return;
            }
            unsafe {
                let peripherals: *mut AnyObject =
                    msg_send![&*dict, objectForKey: CBCentralManagerRestoredStatePeripheralsKey];
                let scan_services: *mut AnyObject =
                    msg_send![&*dict, objectForKey: CBCentralManagerRestoredStateScanServicesKey];
                let scan_options: *mut AnyObject =
                    msg_send![&*dict, objectForKey: CBCentralManagerRestoredStateScanOptionsKey];

                let peripheral_count: usize = if peripherals.is_null() {
                    0
                } else {
                    msg_send![&*peripherals, count]
                };
                let service_count: usize = if scan_services.is_null() {
                    0
                } else {
                    msg_send![&*scan_services, count]
                };
                let has_options = !scan_options.is_null();

                tracing::info!(
                    target: "ble_trace",
                    step = "central.will_restore_state",
                    peripheral_count,
                    service_count,
                    has_options,
                    "Apple BLE Central: willRestoreState"
                );

                // Adopt only Connected peripherals; other states fall through
                // to the next scan cycle. On error `adopt_restored_peer`
                // releases the retain.
                if !peripherals.is_null() {
                    for i in 0..peripheral_count {
                        let p: *mut AnyObject = msg_send![&*peripherals, objectAtIndex: i];
                        if p.is_null() {
                            continue;
                        }
                        let state: i64 = msg_send![&*p, state];
                        let identifier = peripheral_identifier(p);
                        if identifier.is_empty() {
                            tracing::warn!(
                                target: "ble_trace",
                                step = "central.restore_skip_no_id",
                                cb_state = state,
                                "Apple BLE Central: skipping restored peripheral with no identifier"
                            );
                            continue;
                        }
                        const CB_PERIPHERAL_STATE_CONNECTED: i64 = 2;
                        if state != CB_PERIPHERAL_STATE_CONNECTED {
                            tracing::info!(
                                target: "ble_trace",
                                step = "central.restore_skip_state",
                                address = %identifier,
                                cb_state = state,
                                "Apple BLE Central: restored peripheral not in Connected state \u{2014} deferring to scan rediscovery"
                            );
                            continue;
                        }
                        // ConnectedPeer::drop balances this retain on success;
                        // adopt_restored_peer releases on failure.
                        let _: *mut AnyObject = msg_send![p, retain];
                        match crate::ble_central_apple_connect::adopt_restored_peer(
                            identifier.clone(),
                            p,
                        ) {
                            Ok(()) => {
                                tracing::info!(
                                    target: "ble_trace",
                                    step = "central.restore_adopted",
                                    address = %identifier,
                                    "Apple BLE Central: restored Connected peripheral adopted"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    target: "ble_trace",
                                    step = "central.restore_adopt_failed",
                                    address = %identifier,
                                    error = %e,
                                    "Apple BLE Central: adopt_restored_peer failed; the helper already released the retain"
                                );
                            }
                        }
                    }
                }
            }
        }

        extern "C" fn did_discover(
            _this: *mut AnyObject,
            _sel: Sel,
            _central: *mut AnyObject,
            peripheral: *mut AnyObject,
            ad_data: *mut AnyObject,
            rssi: *mut AnyObject,
        ) {
            if peripheral.is_null() {
                return;
            }
            let identifier = unsafe { peripheral_identifier(peripheral) };
            let rssi_i16: i16 = unsafe { nsnumber_to_i16(rssi) };
            if identifier.is_empty() {
                tracing::debug!(
                    target: "ble_trace",
                    step = "central.discover_drop_no_id",
                    rssi = rssi_i16,
                    "Apple BLE Central: didDiscoverPeripheral with empty identifier"
                );
                return;
            }
            let services = unsafe { extract_advertised_services(ad_data) };
            let classified =
                classify_protocol(&services, RATSPEAK_SERVICE_UUID, COLUMBA_SERVICE_UUID);
            tracing::debug!(
                target: "ble_trace",
                step = "central.discover",
                peripheral = %identifier,
                rssi = rssi_i16,
                advertised_services = ?services,
                classified = ?classified,
                "Apple BLE Central: didDiscoverPeripheral"
            );
            let protocol = match classified {
                Some(p) => p,
                // Duplicates mode occasionally reports ads that don't fully
                // match the filter.
                None => return,
            };

            // The connect path needs the same CBPeripheral pointer the scan
            // saw — Apple central peripheral caches don't cross managers.
            // CoreBluetooth delivers a valid `CBPeripheral *` for this delegate call.
            unsafe {
                crate::ble_central_apple_connect::record_discovered(
                    identifier.clone(),
                    peripheral,
                );
            }

            let event = DiscoveryEvent {
                identifier,
                rssi: rssi_i16,
                services,
                protocol,
                seen_at: Instant::now(),
            };

            // No sender means stop_scan raced us between the radio event
            // and this callback — drop silently.
            if let Some(lock) = DISCOVERY_TX.get()
                && let Ok(g) = lock.lock()
                    && let Some(tx) = g.as_ref() {
                        let _ = tx.send(event);
                    }
        }

        // Connection-state callbacks share this delegate (one delegate per
        // CBCentralManager) and forward to ble_central_apple_connect.
        extern "C" fn did_connect(
            _this: *mut AnyObject,
            _sel: Sel,
            _central: *mut AnyObject,
            peripheral: *mut AnyObject,
        ) {
            let address = unsafe { peripheral_identifier(peripheral) };
            if address.is_empty() {
                return;
            }
            tracing::info!(
                target: "ble_trace",
                step = "central.did_connect",
                address = %address,
                "Apple BLE Central: didConnectPeripheral"
            );
            crate::ble_central_apple_connect::on_did_connect(&address);
        }

        extern "C" fn did_fail_to_connect(
            _this: *mut AnyObject,
            _sel: Sel,
            _central: *mut AnyObject,
            peripheral: *mut AnyObject,
            error: *mut AnyObject,
        ) {
            let address = unsafe { peripheral_identifier(peripheral) };
            if address.is_empty() {
                return;
            }
            let err = if error.is_null() {
                "didFailToConnect (no error description)".to_string()
            } else {
                unsafe { nserror_message(error) }
            };
            tracing::warn!(
                target: "ble_trace",
                step = "central.did_fail_connect",
                address = %address,
                error = %err,
                "Apple BLE Central: didFailToConnectPeripheral"
            );
            crate::ble_central_apple_connect::on_did_fail_connect(&address, err);
        }

        extern "C" fn did_disconnect(
            _this: *mut AnyObject,
            _sel: Sel,
            _central: *mut AnyObject,
            peripheral: *mut AnyObject,
            error: *mut AnyObject,
        ) {
            let address = unsafe { peripheral_identifier(peripheral) };
            if address.is_empty() {
                return;
            }
            let err = if error.is_null() {
                None
            } else {
                Some(unsafe { nserror_message(error) })
            };
            tracing::info!(
                target: "ble_trace",
                step = "central.did_disconnect",
                address = %address,
                error = ?err,
                "Apple BLE Central: didDisconnectPeripheral"
            );
            crate::ble_central_apple_connect::on_did_disconnect(&address, err);
        }

        unsafe {
            builder.add_method(
                sel!(centralManagerDidUpdateState:),
                did_update_state as extern "C" fn(*mut AnyObject, Sel, *mut AnyObject),
            );
            builder.add_method(
                sel!(centralManager:willRestoreState:),
                will_restore_state
                    as extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject),
            );
            builder.add_method(
                sel!(centralManager:didDiscoverPeripheral:advertisementData:RSSI:),
                did_discover
                    as extern "C" fn(
                        *mut AnyObject,
                        Sel,
                        *mut AnyObject,
                        *mut AnyObject,
                        *mut AnyObject,
                        *mut AnyObject,
                    ),
            );
            builder.add_method(
                sel!(centralManager:didConnectPeripheral:),
                did_connect
                    as extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject),
            );
            builder.add_method(
                sel!(centralManager:didFailToConnectPeripheral:error:),
                did_fail_to_connect
                    as extern "C" fn(
                        *mut AnyObject,
                        Sel,
                        *mut AnyObject,
                        *mut AnyObject,
                        *mut AnyObject,
                    ),
            );
            builder.add_method(
                sel!(centralManager:didDisconnectPeripheral:error:),
                did_disconnect
                    as extern "C" fn(
                        *mut AnyObject,
                        Sel,
                        *mut AnyObject,
                        *mut AnyObject,
                        *mut AnyObject,
                    ),
            );
        }

        builder.register()
    })
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

/// # Safety
/// `mgr_raw` must be a retained, non-null `CBCentralManager` whose delegate
/// has been installed and whose `state` is PoweredOn.
unsafe fn scan_with_manager(mgr_raw: *mut AnyObject) -> Result<(), String> {
    let services = scan_services()
        .lock()
        .map_err(|e| format!("scan_services lock poisoned: {e}"))?
        .clone();

    unsafe {
        // nil filter = scan all.
        let svc_arr: *mut AnyObject = if services.is_empty() {
            std::ptr::null_mut()
        } else {
            let arr_cls = AnyClass::get("NSArray").ok_or("NSArray not found")?;
            let mut raw_ptrs: Vec<*const AnyObject> = Vec::with_capacity(services.len());
            for u in &services {
                raw_ptrs.push(cbuuid(u) as *const AnyObject);
            }
            msg_send![arr_cls,
                arrayWithObjects: raw_ptrs.as_ptr(),
                count: raw_ptrs.len()]
        };

        let number_cls = AnyClass::get("NSNumber").ok_or("NSNumber not found")?;
        let dict_cls = AnyClass::get("NSDictionary").ok_or("NSDictionary not found")?;
        let yes: *mut AnyObject = msg_send![number_cls, numberWithBool: true];
        let opts: *mut AnyObject = msg_send![dict_cls,
            dictionaryWithObject: yes,
            forKey: CBCentralManagerScanOptionAllowDuplicatesKey];

        tracing::info!(
            target: "ble_trace",
            step = "central.scan_invoked",
            filter_count = services.len(),
            filter_uuids = ?services,
            "Apple BLE Central: scanForPeripheralsWithServices"
        );
        let _: () = msg_send![&*mgr_raw,
            scanForPeripheralsWithServices: svc_arr,
            options: opts];
    }
    Ok(())
}

/// `{ RestoreIdentifierKey: CENTRAL_RESTORE_ID }`. Ignored on macOS.
unsafe fn build_init_options() -> Result<*mut AnyObject, String> {
    unsafe {
        let dict_cls = AnyClass::get("NSDictionary").ok_or("NSDictionary not found")?;
        let restore_id = NSString::from_str(CENTRAL_RESTORE_ID);
        let opts: *mut AnyObject = msg_send![dict_cls,
            dictionaryWithObject: &*restore_id,
            forKey: CBCentralManagerOptionRestoreIdentifierKey];
        Ok(opts)
    }
}

fn cb_state_name(state: i64) -> &'static str {
    match state {
        0 => "unknown",
        1 => "resetting",
        2 => "unsupported",
        3 => "unauthorized",
        4 => "poweredOff",
        5 => "poweredOn",
        _ => "?",
    }
}

unsafe fn peripheral_identifier(peripheral: *mut AnyObject) -> String {
    unsafe {
        let id_obj: *mut AnyObject = msg_send![&*peripheral, identifier];
        if id_obj.is_null() {
            return String::new();
        }
        let uuid_str: *mut AnyObject = msg_send![&*id_obj, UUIDString];
        nsstring_to_string(uuid_str)
    }
}

/// Short SIG forms like "180D" are expanded to the Bluetooth base UUID.
unsafe fn extract_advertised_services(ad_data: *mut AnyObject) -> Vec<Uuid> {
    if ad_data.is_null() {
        return Vec::new();
    }
    unsafe {
        let arr: *mut AnyObject =
            msg_send![&*ad_data, objectForKey: CBAdvertisementDataServiceUUIDsKey];
        if arr.is_null() {
            return Vec::new();
        }
        let count: usize = msg_send![&*arr, count];
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let cb: *mut AnyObject = msg_send![&*arr, objectAtIndex: i];
            if cb.is_null() {
                continue;
            }
            let s_obj: *mut AnyObject = msg_send![&*cb, UUIDString];
            if s_obj.is_null() {
                continue;
            }
            let s = nsstring_to_string(s_obj);
            match Uuid::parse_str(&s) {
                Ok(u) => out.push(u),
                Err(_) => {
                    if let Ok(u) = parse_short_uuid(&s) {
                        out.push(u);
                    }
                }
            }
        }
        out
    }
}

/// Null → `-100` (treated as far-away, not drop-worthy).
unsafe fn nsnumber_to_i16(n: *mut AnyObject) -> i16 {
    if n.is_null() {
        return -100;
    }
    let v: i32 = unsafe { msg_send![&*n, intValue] };
    v.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

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

fn cbuuid(uuid: &Uuid) -> *mut AnyObject {
    let s = NSString::from_str(&uuid.to_string());
    unsafe {
        let cls = AnyClass::get("CBUUID").expect("CBUUID must exist at runtime");
        let obj: *mut AnyObject = msg_send![cls, UUIDWithString: &*s];
        // UUIDWithString: returns autoreleased; retain so the pointer
        // survives the autorelease pool drain.
        let _: *mut AnyObject = msg_send![obj, retain];
        obj
    }
}

/// Expand a SIG short UUID ("180D" / "0000180D") to its 128-bit form using
/// the Bluetooth base UUID.
fn parse_short_uuid(s: &str) -> Result<Uuid, ()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_short_uuid_expands_16bit_to_base_uuid() {
        let u = parse_short_uuid("180D").expect("must parse");
        assert_eq!(
            u,
            Uuid::parse_str("0000180d-0000-1000-8000-00805f9b34fb").unwrap()
        );
    }

    #[test]
    fn parse_short_uuid_expands_32bit_to_base_uuid() {
        let u = parse_short_uuid("0000180D").expect("must parse");
        assert_eq!(
            u,
            Uuid::parse_str("0000180d-0000-1000-8000-00805f9b34fb").unwrap()
        );
    }

    #[test]
    fn parse_short_uuid_is_case_insensitive() {
        let u1 = parse_short_uuid("180d").unwrap();
        let u2 = parse_short_uuid("180D").unwrap();
        assert_eq!(u1, u2);
    }

    #[test]
    fn parse_short_uuid_rejects_non_hex() {
        assert!(parse_short_uuid("zzzz").is_err());
        assert!(parse_short_uuid("").is_err());
        assert!(parse_short_uuid("180").is_err());
        assert!(parse_short_uuid("1800000D").is_ok());
    }

    #[test]
    fn cb_state_name_covers_documented_states() {
        assert_eq!(cb_state_name(0), "unknown");
        assert_eq!(cb_state_name(1), "resetting");
        assert_eq!(cb_state_name(2), "unsupported");
        assert_eq!(cb_state_name(3), "unauthorized");
        assert_eq!(cb_state_name(4), "poweredOff");
        assert_eq!(cb_state_name(5), "poweredOn");
        assert_eq!(cb_state_name(99), "?");
    }
}
