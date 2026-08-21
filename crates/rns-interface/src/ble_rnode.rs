//! RNode over BLE via the Nordic UART Service. Same KISS command set as
//! serial RNode, tunnelled through GATT notify/write.

mod generation;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

#[cfg(any(
    test,
    target_os = "ios",
    target_os = "macos",
    target_os = "windows",
    target_os = "android"
))]
use btleplug::api::CharPropFlags;
use btleplug::api::{
    Central, CentralEvent, CentralState, Manager as _, Peripheral as _, ScanFilter,
    ValueNotification, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral, PeripheralId};
use bytes::Bytes;
#[cfg(test)]
use futures::FutureExt;
use futures::StreamExt;
use rand::RngCore;
use tokio::sync::mpsc;
use uuid::Uuid;

use generation::{
    BleGenerationExit, BleGenerationId, BleOperationStage, PendingOutbound,
    run_generation_operation,
};

type BleCentralEventStream = std::pin::Pin<Box<dyn futures::Stream<Item = CentralEvent> + Send>>;

#[cfg(target_os = "android")]
static BTLEPLUG_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Set from `JNI_OnLoad` after `btleplug::platform::init()` succeeds.
/// Without it, btleplug has no JVM reference and every call panics.
#[cfg(target_os = "android")]
pub fn mark_btleplug_initialized() {
    BTLEPLUG_INITIALIZED.store(true, Ordering::SeqCst);
}

#[cfg(target_os = "android")]
pub fn is_btleplug_initialized() -> bool {
    BTLEPLUG_INITIALIZED.load(Ordering::SeqCst)
}

use crate::kiss;
use crate::rnode::{
    self, RNodeCapabilityAdmissionError, RNodeDriverShutdown, RNodeRadioSettings, RNodeResponse,
    RNodeRuntimeReason, RNodeSnapshotPublisher, RNodeSpawnError, RNodeStartupOptions,
    RNodeTransportClass, SpawnedRNodeInterface,
};
use crate::rnode_capabilities::RNodeRadioAdmission;
use crate::rnode_capability_preflight::{RNodeCapabilityPreflight, build_rnode_capability_request};
use crate::rnode_protocol::{RNodeProtocolState, RNodeProtocolTarget, RNodeReadiness};
use crate::traits::{
    InterfaceDirection, InterfaceError, InterfaceHandle, InterfaceId, InterfaceMode,
};
use rns_transport::messages::TransportMessage;

pub const NUS_SERVICE_UUID: Uuid = Uuid::from_u128(0x6E400001_B5A3_F393_E0A9_E50E24DCCA9E);
/// Host writes RNode commands here.
pub const NUS_RX_CHAR_UUID: Uuid = Uuid::from_u128(0x6E400002_B5A3_F393_E0A9_E50E24DCCA9E);
/// Device notifies the host here.
pub const NUS_TX_CHAR_UUID: Uuid = Uuid::from_u128(0x6E400003_B5A3_F393_E0A9_E50E24DCCA9E);

const RECONNECT_WAIT: u64 = 1;
/// Fast early recovery, then indefinite low-duty retries. A two-minute cap made
/// a reachable radio appear dead long after returning to range.
const RECONNECT_WAIT_MAX: u64 = 30;
/// `None` retries forever; teardown goes via `stop_ble_rnode_interface`.
const MAX_RECONNECT_TRIES: Option<usize> = None;
const SCAN_TIMEOUT: u64 = 3;
/// Bounds disable-while-offline teardown latency to ~1s.
const RUNNING_POLL: Duration = Duration::from_secs(1);
/// No CoreBluetooth or GATT operation may hold the generation owner forever.
const BLE_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
/// Upstream Android RNode BLE applies each RF control independently.
const BLE_CONTROL_STAGE_SETTLE: Duration = Duration::from_millis(150);
const BLE_POST_INIT_SETTLE: Duration = Duration::from_secs(1);
/// ATT's mandatory 23-byte baseline MTU leaves 20 bytes for a characteristic
/// value. CoreBluetooth exposes the negotiated per-peripheral limit through
/// `maximumWriteValueLength(for:)`, but btleplug 0.11.8 neither calls nor
/// exposes it. Its no-response write path also reports success immediately,
/// even when CoreBluetooth cannot deliver the value. Upstream Reticulum avoids
/// this by reading Bleak's `max_write_without_response_size` for every link.
/// Stay at the guaranteed baseline on Apple until btleplug exposes that value.
const BLE_DEFAULT_ATT_WRITE_PAYLOAD: usize = 20;
/// RNode's reviewed high-throughput ATT MTU is 247 (247 - 3 ATT bytes).
const BLE_RNODE_ATT_WRITE_PAYLOAD: usize = 244;
#[cfg(target_os = "linux")]
const RNODE_POST_BOND_SETTLE: Duration = Duration::from_millis(2600);
const RNODE_NATIVE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(6);
const RNODE_NATIVE_HANDSHAKE_PROBE: Duration = Duration::from_millis(650);
const RNODE_BLE_READINESS_TIMEOUT: Duration = Duration::from_secs(10);
/// Closed localhost-only command emitted by Ratspeak's Android GATT owner after
/// one complete KISS data frame crosses its generation-fenced write boundary.
/// It is consumed inside the native bridge and never reaches RNode protocol or
/// Reticulum transport processing.
const RNODE_NATIVE_BRIDGE_ACK_COMMAND: u8 = 0xA0;
const RNODE_NATIVE_BRIDGE_ACK_MAGIC: &[u8; 5] = b"RSBA\x01";
const RNODE_NATIVE_BRIDGE_ACK_PAYLOAD_LEN: usize = RNODE_NATIVE_BRIDGE_ACK_MAGIC.len() + 8;
const RNODE_NATIVE_MAX_PACKET: usize = 508;
const RNODE_NATIVE_MAX_ESCAPED_FRAME: usize = RNODE_NATIVE_MAX_PACKET * 2 + 3;
const RNODE_NATIVE_ACK_MIN_WRITE_CHUNK: usize = BLE_DEFAULT_ATT_WRITE_PAYLOAD;
const RNODE_NATIVE_ACK_WORST_CASE_CHUNKS: u64 =
    RNODE_NATIVE_MAX_ESCAPED_FRAME.div_ceil(RNODE_NATIVE_ACK_MIN_WRITE_CHUNK) as u64;
// Shared with RatspeakBleGatt's exact write loop: every chunk can spend 1.2s
// being accepted, 5s awaiting its GATT callback, and 12ms pacing before the
// next chunk. MTU negotiation may legally retain the 20-byte ATT baseline, so
// derive from that 51-chunk case and add two seconds after its 316.8s bound.
const RNODE_NATIVE_ACK_ENQUEUE_RETRY_MS: u64 = 1_200;
const RNODE_NATIVE_ACK_CALLBACK_MS: u64 = 5_000;
const RNODE_NATIVE_ACK_PACING_MS: u64 = 12;
const RNODE_NATIVE_ACK_MARGIN_MS: u64 = 2_000;
const RNODE_NATIVE_BRIDGE_ACK_TIMEOUT_MS: u64 = RNODE_NATIVE_ACK_WORST_CASE_CHUNKS
    * (RNODE_NATIVE_ACK_ENQUEUE_RETRY_MS + RNODE_NATIVE_ACK_CALLBACK_MS)
    + (RNODE_NATIVE_ACK_WORST_CASE_CHUNKS - 1) * RNODE_NATIVE_ACK_PACING_MS
    + RNODE_NATIVE_ACK_MARGIN_MS;
const RNODE_NATIVE_BRIDGE_ACK_TIMEOUT: Duration =
    Duration::from_millis(RNODE_NATIVE_BRIDGE_ACK_TIMEOUT_MS);
/// Only complete frames following the final Ready-producing echo in its same
/// TCP read cross the startup boundary; this keeps that carry explicitly bound.
const RNODE_NATIVE_STARTUP_ACTIVE_CARRY_MAX: usize = 4096;
/// Android's physical GATT owner may finish a trusted radio DATA record while
/// Rust replaces its localhost TCP generation. Hold those complete records
/// until this generation independently proves typed Ready; 64 KiB is well
/// above the RNode's 6,144-byte receive buffer without becoming unbounded.
const RNODE_NATIVE_STARTUP_PRE_READY_DATA_MAX_BYTES: usize = 64 * 1024;
const RNODE_NATIVE_STARTUP_PRE_READY_DATA_MAX_RECORDS: usize = 256;
#[cfg(not(test))]
const RNODE_BLE_CAPABILITY_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const RNODE_BLE_CAPABILITY_PREFLIGHT_TIMEOUT: Duration = Duration::from_millis(500);
/// A short idle interval closes the ordered receive side before strict startup
/// mutates the radio. RNode command responses are normally immediate; a busy or
/// continuously ambiguous stream is safer to reconnect than to misattribute.
#[cfg(not(test))]
const RNODE_BLE_STARTUP_QUIET: Duration = Duration::from_millis(100);
#[cfg(test)]
const RNODE_BLE_STARTUP_QUIET: Duration = Duration::from_millis(5);

/// `stop_ble_rnode_interface` flips false; the read_task removes the entry
/// on its way out.
static RNODE_RUNNING: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<InterfaceId, Arc<AtomicBool>>>,
> = std::sync::OnceLock::new();

fn running_map()
-> &'static std::sync::Mutex<std::collections::HashMap<InterfaceId, Arc<AtomicBool>>> {
    RNODE_RUNNING.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn register_running(id: InterfaceId) -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(true));
    if let Ok(mut map) = running_map().lock() {
        map.insert(id, flag.clone());
    }
    flag
}

fn unregister_running(id: InterfaceId, running: &Arc<AtomicBool>) {
    if let Ok(mut map) = running_map().lock() {
        let owns_entry = map
            .get(&id)
            .is_some_and(|registered| Arc::ptr_eq(registered, running));
        if owns_entry {
            map.remove(&id);
        }
    }
}

/// Compatibility facade requesting shutdown of the currently registered BLE
/// RNode for `id`.
///
/// New owners should retain [`crate::rnode::RNodeDriverHandle`] and call
/// [`crate::rnode::RNodeDriverHandle::request_shutdown`] so later ID reuse
/// cannot redirect the request.
pub fn stop_ble_rnode_interface(id: InterfaceId) {
    if let Ok(map) = running_map().lock() {
        if let Some(flag) = map.get(&id) {
            flag.store(false, Ordering::SeqCst);
            tracing::info!(id, "BLE RNode: stop signal sent");
            ble_diag(format!("[ble] stop_ble_rnode_interface({id})"));
        }
    }
}

fn reconnect_try_exhausted(tries: &mut usize) -> bool {
    if let Some(max_tries) = MAX_RECONNECT_TRIES {
        *tries += 1;
        *tries >= max_tries
    } else {
        false
    }
}

fn reconnect_delay_with_jitter(seconds: u64, random: u64) -> Duration {
    let base = Duration::from_secs(seconds.max(1));
    let jitter_cap_ms = seconds.max(1).saturating_mul(200); // 0..20%
    let jitter_ms = random % jitter_cap_ms.saturating_add(1);
    base + Duration::from_millis(jitter_ms)
}

fn ble_reconnect_delay(seconds: u64) -> Duration {
    reconnect_delay_with_jitter(seconds, rand::rngs::OsRng.next_u64())
}

const fn ble_write_chunk_size() -> usize {
    if cfg!(any(target_os = "ios", target_os = "macos")) {
        BLE_DEFAULT_ATT_WRITE_PAYLOAD
    } else {
        BLE_RNODE_ATT_WRITE_PAYLOAD
    }
}

const fn ble_write_type() -> WriteType {
    if cfg!(any(target_os = "ios", target_os = "macos")) {
        // btleplug 0.11.8's CoreBluetooth no-response path returns before the
        // controller accepts the value and does not observe
        // canSendWriteWithoutResponse. Ordered response writes are the only
        // acknowledgement boundary this driver can safely own on Apple.
        WriteType::WithResponse
    } else {
        WriteType::WithoutResponse
    }
}

fn ble_scan_filter() -> ScanFilter {
    if cfg!(any(target_os = "ios", target_os = "macos")) {
        // An explicit service filter is required for CoreBluetooth background
        // rediscovery. The target resolver still validates identity/name.
        ScanFilter {
            services: vec![NUS_SERVICE_UUID],
        }
    } else {
        ScanFilter::default()
    }
}

async fn bounded_ble_operation<T, E>(
    operation: &'static str,
    future: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, InterfaceError>
where
    E: std::fmt::Display,
{
    match tokio::time::timeout(BLE_OPERATION_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(InterfaceError::SendFailed(format!(
            "BLE {operation}: {error}"
        ))),
        Err(_) => Err(InterfaceError::SendFailed(format!(
            "BLE {operation} timed out"
        ))),
    }
}

/// Claim the generation-local one-packet RNode transmit permit.
///
/// A valid positive `CMD_READY` replenishes the boolean permit and every data
/// packet, including a station-ID packet, must atomically consume it.  Merely
/// observing `true` lets multiple queued packets pass on one READY response.
fn claim_ble_packet_permit(flow_control: bool, ready: &AtomicBool) -> bool {
    !flow_control
        || ready
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
}

/// Packet admission becomes latched only after the physical generation has
/// completed its startup boundary.  Later protocol evidence may degrade the
/// observation snapshot, but cannot retroactively turn valid active-session
/// `CMD_DATA` into startup traffic.  A reconnect constructs a fresh latch.
#[derive(Clone, Copy, Debug, Default)]
struct ActiveBlePacketAdmission {
    admitted: bool,
}

impl ActiveBlePacketAdmission {
    fn for_startup_policy(strict: bool) -> Self {
        Self { admitted: !strict }
    }

    fn observe_readiness(&mut self, readiness: RNodeReadiness) {
        self.admitted |= matches!(readiness, RNodeReadiness::Ready);
    }

    fn allows_packet(self) -> bool {
        self.admitted
    }
}

#[cfg(test)]
pub(crate) fn is_registered(id: InterfaceId) -> bool {
    running_map()
        .lock()
        .map(|m| m.contains_key(&id))
        .unwrap_or(false)
}

/// Returns `true` if shutdown was signalled during the wait.
async fn wait_or_shutdown(total: Duration, flag: &AtomicBool) -> bool {
    let deadline = std::time::Instant::now() + total;
    while std::time::Instant::now() < deadline {
        if !flag.load(Ordering::SeqCst) {
            return true;
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        tokio::time::sleep(remaining.min(RUNNING_POLL)).await;
    }
    !flag.load(Ordering::SeqCst)
}

#[cfg(any(test, target_os = "ios", target_os = "macos"))]
fn adapter_power_transition_wakes(saw_powered_off: &mut bool, state: CentralState) -> bool {
    match state {
        CentralState::PoweredOff => {
            *saw_powered_off = true;
            false
        }
        CentralState::PoweredOn => *saw_powered_off,
        CentralState::Unknown => false,
    }
}

/// Wait for the ordinary reconnect cadence, but on Apple treat adapter power
/// as state rather than repeated connection failure. CoreBluetooth publishes
/// `StateUpdate`; a bounded state poll covers a missed or ended event stream.
/// Other platforms retain their already-qualified reconnect behavior.
async fn wait_for_ble_retry(adapter: &Adapter, total: Duration, flag: &AtomicBool) -> bool {
    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    {
        let _ = adapter;
        return wait_or_shutdown(total, flag).await;
    }

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        let deadline = tokio::time::Instant::now() + total;
        let setup_timeout = total.min(RUNNING_POLL);
        let mut events = tokio::time::timeout(setup_timeout, adapter.events())
            .await
            .ok()
            .and_then(Result::ok);
        let mut saw_powered_off = tokio::time::timeout(setup_timeout, adapter.adapter_state())
            .await
            .ok()
            .and_then(Result::ok)
            .is_some_and(|state| state == CentralState::PoweredOff);

        loop {
            if !flag.load(Ordering::SeqCst) {
                return true;
            }
            let now = tokio::time::Instant::now();
            if !saw_powered_off && now >= deadline {
                return false;
            }
            let wake = if saw_powered_off {
                RUNNING_POLL
            } else {
                (deadline - now).min(RUNNING_POLL)
            };
            enum AdapterWaitEvent {
                Event(Option<CentralEvent>),
                Tick,
            }
            let event = if let Some(events) = events.as_mut() {
                tokio::select! {
                    event = events.next() => AdapterWaitEvent::Event(event),
                    _ = tokio::time::sleep(wake) => AdapterWaitEvent::Tick,
                }
            } else {
                tokio::time::sleep(wake).await;
                AdapterWaitEvent::Tick
            };
            match event {
                AdapterWaitEvent::Event(Some(CentralEvent::StateUpdate(state))) => {
                    if adapter_power_transition_wakes(&mut saw_powered_off, state) {
                        return false;
                    }
                }
                AdapterWaitEvent::Event(Some(_)) | AdapterWaitEvent::Tick => {}
                AdapterWaitEvent::Event(None) => events = None,
            }
            if saw_powered_off
                && tokio::time::timeout(RUNNING_POLL, adapter.adapter_state())
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .is_some_and(|state| state == CentralState::PoweredOn)
            {
                return false;
            }
        }
    }
}

fn is_rnode_handshake_frame(cmd: u8, frame: &[u8]) -> bool {
    (cmd == rnode::CMD_DETECT && frame.first().copied() == Some(rnode::DETECT_RESP))
        || (cmd == rnode::CMD_FW_VERSION && !frame.is_empty())
}

#[cfg(test)]
fn reduce_native_handshake_bytes(
    protocol_state: &mut RNodeProtocolState,
    deframer: &mut kiss::RawKissDeframer,
    bytes: &[u8],
) -> bool {
    let frames = deframer.feed(bytes);
    let accepted = frames
        .iter()
        .any(|(command, frame)| is_rnode_handshake_frame(*command, frame));

    // Reduce the complete read batch before admitting the generation. In
    // particular, DETECT and firmware commonly arrive together; returning at
    // the first accepted frame would silently discard the remaining evidence.
    for (command, frame) in frames {
        protocol_state.apply_frame(command, &frame);
    }

    accepted
}

fn hold_native_pre_ready_data(
    frame: Vec<u8>,
    pre_ready_data: &mut Vec<Vec<u8>>,
    pre_ready_data_bytes: &mut usize,
) -> bool {
    let next_bytes = pre_ready_data_bytes.saturating_add(frame.len());
    if pre_ready_data.len() >= RNODE_NATIVE_STARTUP_PRE_READY_DATA_MAX_RECORDS
        || next_bytes > RNODE_NATIVE_STARTUP_PRE_READY_DATA_MAX_BYTES
    {
        return false;
    }
    pre_ready_data.push(frame);
    *pre_ready_data_bytes = next_bytes;
    true
}

fn reduce_native_handshake_bytes_preserving_data(
    protocol_state: &mut RNodeProtocolState,
    deframer: &mut kiss::RawKissDeframer,
    bytes: &[u8],
    pre_ready_data: &mut Vec<Vec<u8>>,
    pre_ready_data_bytes: &mut usize,
) -> Result<bool, ()> {
    let frames = deframer.feed(bytes);
    let accepted = frames
        .iter()
        .any(|(command, frame)| is_rnode_handshake_frame(*command, frame));
    for (command, frame) in frames {
        if command == kiss::CMD_DATA {
            if !hold_native_pre_ready_data(frame, pre_ready_data, pre_ready_data_bytes) {
                return Err(());
            }
        } else {
            protocol_state.apply_frame(command, &frame);
        }
    }
    Ok(accepted)
}

fn is_pairing_transition_error(error: &InterfaceError) -> bool {
    matches!(
        error,
        InterfaceError::SendFailed(message) if message.starts_with("BLE pairing in progress:")
    )
}

/// The GATT operation that establishes authenticated access before normal NUS
/// traffic begins.
///
/// ESP RNodes advertise their encrypted TX value as readable, while the
/// Bluefruit NUS used by nRF RNodes advertises TX as notification-only and
/// secures its CCCD. CoreBluetooth must not be asked to read a characteristic
/// that does not advertise `READ`; subscribing to the secured CCCD is the
/// authentication trigger for that shape instead.
#[cfg(any(
    test,
    target_os = "ios",
    target_os = "macos",
    target_os = "windows",
    target_os = "android"
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DesktopPairingTrigger {
    EncryptedRead,
    SecuredSubscribe,
}

#[cfg(any(
    test,
    target_os = "ios",
    target_os = "macos",
    target_os = "windows",
    target_os = "android"
))]
impl DesktopPairingTrigger {
    const fn label(self) -> &'static str {
        match self {
            Self::EncryptedRead => "encrypted_read",
            Self::SecuredSubscribe => "secured_subscribe",
        }
    }
}

#[cfg(any(
    test,
    target_os = "ios",
    target_os = "macos",
    target_os = "windows",
    target_os = "android"
))]
fn desktop_pairing_trigger_for_properties(
    properties: CharPropFlags,
    apple_core_bluetooth: bool,
) -> DesktopPairingTrigger {
    let notification_only =
        properties.contains(CharPropFlags::NOTIFY) && !properties.contains(CharPropFlags::READ);
    if apple_core_bluetooth && notification_only {
        DesktopPairingTrigger::SecuredSubscribe
    } else {
        DesktopPairingTrigger::EncryptedRead
    }
}

const BLE_LIFECYCLE_TRACE_TARGET: &str = "rns_interface::ble_rnode::lifecycle";

/// Privacy-safe generation trace. This target deliberately excludes device
/// identifiers, names, UUIDs, platform error strings, values, and packet data,
/// so qualification builds can enable it without enabling raw `ble_diag`.
fn trace_ble_lifecycle(
    generation_id: BleGenerationId,
    stage: &'static str,
    result_class: &'static str,
    tx_read: Option<bool>,
    tx_notify: Option<bool>,
) {
    tracing::info!(
        target: BLE_LIFECYCLE_TRACE_TARGET,
        generation = generation_id.get(),
        stage,
        result_class,
        tx_read,
        tx_notify,
        "BLE RNode generation lifecycle"
    );
}

fn generation_exit_result_class(error: &BleGenerationExit) -> &'static str {
    match error {
        BleGenerationExit::TargetDisconnected { .. } => "target_disconnected",
        BleGenerationExit::DeadlineElapsed { .. } => "deadline_elapsed",
        BleGenerationExit::StopRequested { .. } => "stop_requested",
        BleGenerationExit::EventStreamEnded { .. } => "event_stream_ended",
        BleGenerationExit::StageFailed { .. } => "stage_failed",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BleTargetResolutionClass {
    FirstRnode,
    PrimaryId,
    PrimaryName,
    GenerationStableName,
}

impl BleTargetResolutionClass {
    const fn label(self) -> &'static str {
        match self {
            Self::FirstRnode => "first_rnode",
            Self::PrimaryId => "primary_id",
            Self::PrimaryName => "primary_name",
            Self::GenerationStableName => "generation_stable_name",
        }
    }
}

fn ble_name_resolution_class(
    primary_target: &str,
    generation_stable_name: Option<&str>,
    advertised_name: &str,
) -> Option<BleTargetResolutionClass> {
    if advertised_name == primary_target {
        Some(BleTargetResolutionClass::PrimaryName)
    } else if generation_stable_name == Some(advertised_name) {
        Some(BleTargetResolutionClass::GenerationStableName)
    } else {
        None
    }
}

/// Android's native bridge can come up immediately after SMP completes, while
/// rsCardputer's RNode BLE stack is still settling. Probe detect a few times
/// inside one connection attempt so a single dropped early frame does not cost
/// a full reconnect backoff.
struct NativeHandshakeState<'a> {
    protocol_state: &'a mut RNodeProtocolState,
    deframer: &'a mut kiss::RawKissDeframer,
    running_task: &'a AtomicBool,
    pre_ready_data: &'a mut Vec<Vec<u8>>,
    pre_ready_data_bytes: &'a mut usize,
}

async fn probe_native_rnode_handshake(
    tcp_read: &mut tokio::net::tcp::OwnedReadHalf,
    tcp_write: &mut tokio::net::tcp::OwnedWriteHalf,
    timeout: Duration,
    probe_interval: Duration,
    state: NativeHandshakeState<'_>,
) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let detect_seq = rnode::build_detect_sequence();
    let mut buf = [0u8; 1024];
    let deadline = std::time::Instant::now() + timeout;
    let mut next_probe = std::time::Instant::now();

    while std::time::Instant::now() < deadline {
        if !state.running_task.load(Ordering::SeqCst) {
            return false;
        }

        let now = std::time::Instant::now();
        if now >= next_probe {
            if let Err(e) = tcp_write.write_all(&detect_seq).await {
                tracing::warn!(error = %e, "BLE RNode native detect probe write failed");
                return false;
            }
            let _ = tcp_write.flush().await;
            next_probe = std::time::Instant::now() + probe_interval;
        }

        let now = std::time::Instant::now();
        let read_budget = next_probe
            .min(deadline)
            .saturating_duration_since(now)
            .min(RUNNING_POLL);
        if read_budget.is_zero() {
            tokio::task::yield_now().await;
            continue;
        }

        let read = tokio::time::timeout(read_budget, tcp_read.read(&mut buf)).await;
        let n = match read {
            Ok(Ok(0)) => return false,
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return false,
            Err(_) => continue,
        };

        match reduce_native_handshake_bytes_preserving_data(
            state.protocol_state,
            state.deframer,
            &buf[..n],
            state.pre_ready_data,
            state.pre_ready_data_bytes,
        ) {
            Ok(true) => return true,
            Ok(false) => {}
            Err(()) => {
                tracing::warn!("native BLE pre-Ready DATA carry exceeded bound during handshake");
                return false;
            }
        }
    }

    false
}

enum BleCapabilityPreflightOutcome {
    Admitted {
        protocol_state: RNodeProtocolState,
        admission: RNodeRadioAdmission,
    },
    Stopped,
    Retry(BleCapabilityRetry),
    Rejected(RNodeCapabilityAdmissionError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BleCapabilityRetry {
    ResponseTimedOut,
    TransportEnded,
    TransportIo,
    BoundaryOverflow,
    BoundaryTimedOut,
}

impl BleCapabilityRetry {
    const fn log_class(self) -> &'static str {
        match self {
            Self::ResponseTimedOut => "response_timeout",
            Self::TransportEnded => "transport_ended",
            Self::TransportIo => "transport_io",
            Self::BoundaryOverflow => "boundary_overflow",
            Self::BoundaryTimedOut => "boundary_timeout",
        }
    }
}

const BLE_PREFLIGHT_BOUNDARY_MAX_ITEMS: usize = 128;
const BLE_PREFLIGHT_BOUNDARY_MAX_BYTES: usize = 4 * 1024;

enum BlePreflightBoundaryError {
    Stopped,
    Retry(BleCapabilityRetry),
    Rejected(RNodeCapabilityAdmissionError),
}

/// Consume the ordered desktop notification tail until the stream has been
/// quiet for `quiet`. The already-admitted preflight remains authoritative:
/// deterministic evidence such as a duplicate EEPROM response, CMD_ERROR, or
/// malformed control still rejects this connection generation.
async fn drain_desktop_ble_preinit<S, E, I, P>(
    notification_stream: &mut S,
    adapter_events: &mut E,
    is_target_disconnect: &mut P,
    preflight: &mut RNodeCapabilityPreflight,
    running: &AtomicBool,
    timeout: Duration,
    quiet: Duration,
) -> Result<(), BlePreflightBoundaryError>
where
    S: futures::Stream<Item = ValueNotification> + Unpin,
    E: futures::Stream<Item = I> + Unpin,
    P: FnMut(&I) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut quiet_deadline = tokio::time::Instant::now() + quiet;
    let mut items = 0usize;
    let mut total = 0usize;
    loop {
        if !running.load(Ordering::SeqCst) {
            return Err(BlePreflightBoundaryError::Stopped);
        }
        let now = tokio::time::Instant::now();
        if now >= quiet_deadline {
            return Ok(());
        }
        if now >= deadline {
            return Err(BlePreflightBoundaryError::Retry(
                BleCapabilityRetry::BoundaryTimedOut,
            ));
        }

        let wake = quiet_deadline.min(deadline).min(now + RUNNING_POLL);
        let notification = tokio::select! {
            biased;
            notification = notification_stream.next() => Some(notification),
            event = adapter_events.next() => match event {
                Some(event) if is_target_disconnect(&event) => {
                    return Err(BlePreflightBoundaryError::Retry(
                        BleCapabilityRetry::TransportEnded,
                    ));
                }
                Some(_) => None,
                None => {
                    return Err(BlePreflightBoundaryError::Retry(
                        BleCapabilityRetry::TransportEnded,
                    ));
                }
            },
            _ = tokio::time::sleep_until(wake) => None,
        };
        let Some(notification) = notification else {
            continue;
        };
        let Some(notification) = notification else {
            return Err(BlePreflightBoundaryError::Retry(
                BleCapabilityRetry::TransportEnded,
            ));
        };
        items = items.saturating_add(1);
        total = total.saturating_add(notification.value.len());
        if items > BLE_PREFLIGHT_BOUNDARY_MAX_ITEMS || total > BLE_PREFLIGHT_BOUNDARY_MAX_BYTES {
            return Err(BlePreflightBoundaryError::Retry(
                BleCapabilityRetry::BoundaryOverflow,
            ));
        }
        quiet_deadline = tokio::time::Instant::now() + quiet;
        if notification.uuid == NUS_TX_CHAR_UUID {
            preflight
                .observe_read(&notification.value)
                .map_err(BlePreflightBoundaryError::Rejected)?;
        }
    }
}

async fn drain_native_ble_preinit(
    tcp_read: &mut tokio::net::tcp::OwnedReadHalf,
    preflight: &mut RNodeCapabilityPreflight,
    running: &AtomicBool,
    timeout: Duration,
    quiet: Duration,
) -> Result<(), BlePreflightBoundaryError> {
    use tokio::io::AsyncReadExt;

    let deadline = tokio::time::Instant::now() + timeout;
    let mut quiet_deadline = tokio::time::Instant::now() + quiet;
    let mut items = 0usize;
    let mut total = 0usize;
    let mut buffer = [0u8; crate::rnode_capability_preflight::RNODE_CAPABILITY_READ_BUFFER_BYTES];
    loop {
        if !running.load(Ordering::SeqCst) {
            return Err(BlePreflightBoundaryError::Stopped);
        }
        let now = tokio::time::Instant::now();
        if now >= quiet_deadline {
            return Ok(());
        }
        if now >= deadline {
            return Err(BlePreflightBoundaryError::Retry(
                BleCapabilityRetry::BoundaryTimedOut,
            ));
        }

        let wake = quiet_deadline.min(deadline).min(now + RUNNING_POLL);
        let read = tokio::time::timeout_at(wake, tcp_read.read(&mut buffer)).await;
        let count = match read {
            Ok(Ok(0)) => {
                return Err(BlePreflightBoundaryError::Retry(
                    BleCapabilityRetry::TransportEnded,
                ));
            }
            Ok(Ok(count)) => count,
            Ok(Err(_)) => {
                return Err(BlePreflightBoundaryError::Retry(
                    BleCapabilityRetry::TransportIo,
                ));
            }
            Err(_) => continue,
        };
        items = items.saturating_add(1);
        total = total.saturating_add(count);
        if items > BLE_PREFLIGHT_BOUNDARY_MAX_ITEMS || total > BLE_PREFLIGHT_BOUNDARY_MAX_BYTES {
            return Err(BlePreflightBoundaryError::Retry(
                BleCapabilityRetry::BoundaryOverflow,
            ));
        }
        quiet_deadline = tokio::time::Instant::now() + quiet;
        preflight
            .observe_read(&buffer[..count])
            .map_err(BlePreflightBoundaryError::Rejected)?;
    }
}

fn ble_radio_settings(config: &BleRNodeConfig) -> RNodeRadioSettings {
    RNodeRadioSettings::new(
        config.frequency,
        config.bandwidth,
        config.spreading_factor,
        config.coding_rate,
        config.tx_power,
    )
}

async fn observe_desktop_ble_capability<S, E, I, P>(
    notification_stream: &mut S,
    adapter_events: &mut E,
    mut is_target_disconnect: P,
    settings: RNodeRadioSettings,
    running: &AtomicBool,
    timeout: Duration,
) -> BleCapabilityPreflightOutcome
where
    S: futures::Stream<Item = ValueNotification> + Unpin,
    E: futures::Stream<Item = I> + Unpin,
    P: FnMut(&I) -> bool,
{
    let mut preflight = RNodeCapabilityPreflight::new(settings);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        if !running.load(Ordering::SeqCst) {
            return BleCapabilityPreflightOutcome::Stopped;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return BleCapabilityPreflightOutcome::Retry(BleCapabilityRetry::ResponseTimedOut);
        }
        let wait = deadline.saturating_duration_since(now).min(RUNNING_POLL);
        let notification = tokio::select! {
            notification = notification_stream.next() => Some(notification),
            event = adapter_events.next() => match event {
                Some(event) if is_target_disconnect(&event) => {
                    return BleCapabilityPreflightOutcome::Retry(
                        BleCapabilityRetry::TransportEnded,
                    );
                }
                Some(_) => None,
                None => {
                    return BleCapabilityPreflightOutcome::Retry(
                        BleCapabilityRetry::TransportEnded,
                    );
                }
            },
            _ = tokio::time::sleep(wait) => None,
        };
        let Some(notification) = notification else {
            continue;
        };
        let Some(notification) = notification else {
            return BleCapabilityPreflightOutcome::Retry(BleCapabilityRetry::TransportEnded);
        };
        if notification.uuid != NUS_TX_CHAR_UUID {
            continue;
        }
        match preflight.observe_read(&notification.value) {
            Ok(Some(admission)) => {
                if let Err(error) = drain_desktop_ble_preinit(
                    notification_stream,
                    adapter_events,
                    &mut is_target_disconnect,
                    &mut preflight,
                    running,
                    timeout,
                    RNODE_BLE_STARTUP_QUIET,
                )
                .await
                {
                    return match error {
                        BlePreflightBoundaryError::Stopped => {
                            BleCapabilityPreflightOutcome::Stopped
                        }
                        BlePreflightBoundaryError::Retry(reason) => {
                            BleCapabilityPreflightOutcome::Retry(reason)
                        }
                        BlePreflightBoundaryError::Rejected(error) => {
                            BleCapabilityPreflightOutcome::Rejected(error)
                        }
                    };
                }
                return BleCapabilityPreflightOutcome::Admitted {
                    protocol_state: preflight.into_protocol_state(),
                    admission,
                };
            }
            Ok(None) => {}
            Err(error) => return BleCapabilityPreflightOutcome::Rejected(error),
        }
    }
}

async fn run_native_ble_capability_preflight(
    tcp_read: &mut tokio::net::tcp::OwnedReadHalf,
    tcp_write: &mut tokio::net::tcp::OwnedWriteHalf,
    settings: RNodeRadioSettings,
    running: &AtomicBool,
    timeout: Duration,
    probe_interval: Duration,
) -> BleCapabilityPreflightOutcome {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if !running.load(Ordering::SeqCst) {
        return BleCapabilityPreflightOutcome::Stopped;
    }
    let detect = rnode::build_detect_sequence();
    if tcp_write.write_all(&detect).await.is_err() || tcp_write.flush().await.is_err() {
        return BleCapabilityPreflightOutcome::Retry(BleCapabilityRetry::TransportIo);
    }
    // The EEPROM request is intentionally issued exactly once per connection
    // generation. Repeated native handshake probes below never repeat it.
    if tcp_write
        .write_all(&build_rnode_capability_request())
        .await
        .is_err()
        || tcp_write.flush().await.is_err()
    {
        return BleCapabilityPreflightOutcome::Retry(BleCapabilityRetry::TransportIo);
    }

    let mut preflight = RNodeCapabilityPreflight::new(settings);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut next_probe = tokio::time::Instant::now() + probe_interval;
    let mut buffer = [0u8; crate::rnode_capability_preflight::RNODE_CAPABILITY_READ_BUFFER_BYTES];

    loop {
        if !running.load(Ordering::SeqCst) {
            return BleCapabilityPreflightOutcome::Stopped;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return BleCapabilityPreflightOutcome::Retry(BleCapabilityRetry::ResponseTimedOut);
        }
        if now >= next_probe {
            if tcp_write.write_all(&detect).await.is_err() || tcp_write.flush().await.is_err() {
                return BleCapabilityPreflightOutcome::Retry(BleCapabilityRetry::TransportIo);
            }
            next_probe = tokio::time::Instant::now() + probe_interval;
        }

        let wait = next_probe
            .min(deadline)
            .saturating_duration_since(tokio::time::Instant::now())
            .min(RUNNING_POLL);
        if wait.is_zero() {
            tokio::task::yield_now().await;
            continue;
        }
        let read = tokio::time::timeout(wait, tcp_read.read(&mut buffer)).await;
        let count = match read {
            Ok(Ok(0)) => {
                return BleCapabilityPreflightOutcome::Retry(BleCapabilityRetry::TransportEnded);
            }
            Ok(Ok(count)) => count,
            Ok(Err(_)) => {
                return BleCapabilityPreflightOutcome::Retry(BleCapabilityRetry::TransportIo);
            }
            Err(_) => continue,
        };
        match preflight.observe_read(&buffer[..count]) {
            Ok(Some(admission)) => {
                if let Err(error) = drain_native_ble_preinit(
                    tcp_read,
                    &mut preflight,
                    running,
                    timeout,
                    RNODE_BLE_STARTUP_QUIET,
                )
                .await
                {
                    return match error {
                        BlePreflightBoundaryError::Stopped => {
                            BleCapabilityPreflightOutcome::Stopped
                        }
                        BlePreflightBoundaryError::Retry(reason) => {
                            BleCapabilityPreflightOutcome::Retry(reason)
                        }
                        BlePreflightBoundaryError::Rejected(error) => {
                            BleCapabilityPreflightOutcome::Rejected(error)
                        }
                    };
                }
                return BleCapabilityPreflightOutcome::Admitted {
                    protocol_state: preflight.into_protocol_state(),
                    admission,
                };
            }
            Ok(None) => {}
            Err(error) => return BleCapabilityPreflightOutcome::Rejected(error),
        }
    }
}

// iOS drops sandboxed-app stdout/stderr; embedding UIs can surface this
// broadcast in their diagnostics view.
static BLE_DIAG_TX: std::sync::OnceLock<tokio::sync::broadcast::Sender<String>> =
    std::sync::OnceLock::new();

fn ble_diag_sender() -> &'static tokio::sync::broadcast::Sender<String> {
    BLE_DIAG_TX.get_or_init(|| tokio::sync::broadcast::channel::<String>(256).0)
}

pub fn subscribe_ble_diag() -> tokio::sync::broadcast::Receiver<String> {
    ble_diag_sender().subscribe()
}

pub(crate) fn ble_diag(msg: impl Into<String>) {
    let msg = msg.into();
    tracing::info!(target: "ble_diag", "{msg}");
    let _ = ble_diag_sender().send(msg);
}

// Linux SMP pairing prompt plumbing. BlueZ does not auto-prompt from an
// encrypted-characteristic read, so we initiate `Device::pair()` explicitly
// and register one process-lifetime Agent to proxy the passkey prompt.
//
// The typed state is intentional: BlueZ may retry `request_passkey` after a
// cancel or timeout, and a bare dropped oneshot lets stale prompts leak back
// to subscribers. `aborted` short-circuits the agent before it broadcasts.

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LinuxPairingPrompt {
    pub device: String,
    /// Pair attempt id used to dedupe and dismiss stale prompts.
    #[serde(default)]
    pub attempt_id: u64,
}

/// Emitted when a pairing attempt ends so the UI can clear its modal.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LinuxPairingFinished {
    pub attempt_id: u64,
    /// "ok", "cancelled", "timed_out", or a short BlueZ error string.
    pub status: String,
}

#[cfg(target_os = "linux")]
static LINUX_PAIRING_PROMPT_TX: std::sync::OnceLock<
    tokio::sync::broadcast::Sender<LinuxPairingPrompt>,
> = std::sync::OnceLock::new();

#[cfg(target_os = "linux")]
fn linux_pairing_prompt_sender() -> &'static tokio::sync::broadcast::Sender<LinuxPairingPrompt> {
    LINUX_PAIRING_PROMPT_TX.get_or_init(|| tokio::sync::broadcast::channel(8).0)
}

#[cfg(target_os = "linux")]
static LINUX_PAIRING_FINISHED_TX: std::sync::OnceLock<
    tokio::sync::broadcast::Sender<LinuxPairingFinished>,
> = std::sync::OnceLock::new();

#[cfg(target_os = "linux")]
fn linux_pairing_finished_sender() -> &'static tokio::sync::broadcast::Sender<LinuxPairingFinished>
{
    LINUX_PAIRING_FINISHED_TX.get_or_init(|| tokio::sync::broadcast::channel(8).0)
}

/// Subscribe to passkey prompts so the UI can render the user-facing modal.
/// Linux only; on Apple/Windows the OS owns the dialog.
#[cfg(target_os = "linux")]
pub fn subscribe_linux_pairing_prompts() -> tokio::sync::broadcast::Receiver<LinuxPairingPrompt> {
    linux_pairing_prompt_sender().subscribe()
}

/// Subscribe to `linux_trigger_pairing` completion events so the UI can clear
/// any modal still associated with the just-finished attempt.
#[cfg(target_os = "linux")]
pub fn subscribe_linux_pairing_finished() -> tokio::sync::broadcast::Receiver<LinuxPairingFinished>
{
    linux_pairing_finished_sender().subscribe()
}

#[cfg(target_os = "linux")]
struct LinuxPairingState {
    attempt_id: u64,
    aborted: bool,
    passkey_tx: Option<tokio::sync::oneshot::Sender<u32>>,
    /// Notify the in-flight `linux_trigger_pairing` task to drop its
    /// `device.pair()` future, which bluer turns into a BlueZ
    /// `CancelPairing` call.
    cancel_notify: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(target_os = "linux")]
static LINUX_PAIRING_STATE: std::sync::Mutex<Option<LinuxPairingState>> =
    std::sync::Mutex::new(None);

#[cfg(target_os = "linux")]
static LINUX_PAIRING_ATTEMPT_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Hand a user-entered passkey back to a waiting agent callback. Returns
/// `false` if no pairing is in flight or the attempt was aborted.
#[cfg(target_os = "linux")]
pub fn linux_submit_passkey(passkey: u32) -> bool {
    if let Ok(mut guard) = LINUX_PAIRING_STATE.lock() {
        if let Some(state) = guard.as_mut() {
            if state.aborted {
                return false;
            }
            if let Some(tx) = state.passkey_tx.take() {
                return tx.send(passkey).is_ok();
            }
        }
    }
    false
}

/// Tear down the in-flight pair attempt:
///   1. Flip `aborted` so any subsequent `request_passkey` rejects without
///      broadcasting a fresh prompt.
///   2. Drop the oneshot so the current `request_passkey` (if any) resolves
///      with `Canceled`.
///   3. Notify the task running `linux_trigger_pairing` to drop its
///      `device.pair()` future — bluer translates that drop into a BlueZ
///      `CancelPairing` D-Bus call so the daemon stops retrying SMP.
///   4. Drain any prompts queued in the broadcast channel so a relay that
///      hasn't run since cancel can't surface a stale prompt.
#[cfg(target_os = "linux")]
pub fn linux_cancel_pairing() {
    let cancel_notify = if let Ok(mut guard) = LINUX_PAIRING_STATE.lock() {
        match guard.as_mut() {
            Some(state) => {
                state.aborted = true;
                let _ = state.passkey_tx.take();
                Some(state.cancel_notify.clone())
            }
            None => None,
        }
    } else {
        None
    };
    if let Some(notify) = cancel_notify {
        notify.notify_waiters();
    }
    ble_diag("[pair][linux] cancel requested");
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BleDeviceType {
    /// Advertises the Nordic UART Service.
    RNode,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BleDevice {
    pub name: String,
    pub address: String,
    pub rssi: Option<i16>,
    pub device_type: BleDeviceType,
    /// True if the OS already has a bond with this device.
    ///
    /// Reliability by platform:
    ///   - Android: ground truth (Kotlin reads `BluetoothDevice.bondState`).
    ///   - Linux: ground truth (bluer's `device.is_paired()` queried in
    ///     `scan_ble_devices`).
    ///   - Apple (iOS / macOS) and Windows: always `false` — neither
    ///     CoreBluetooth nor btleplug's WinRT backend exposes bond state.
    ///     Embedding UIs should hide bonded-state badges on these platforms.
    pub bonded: bool,
}

#[derive(Debug, Clone)]
pub struct BleRNodeConfig {
    pub name: String,
    /// The `ble://` URI: address, name, or empty for any RNode.
    pub ble_uri: String,
    pub frequency: u32,
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: u8,
    pub mode: InterfaceMode,
    pub flow_control: bool,
    pub st_alock: Option<f32>,
    pub lt_alock: Option<f32>,
    /// Station-ID beacon: seconds between IDs, armed by data TX
    /// (Python `id_interval`/`id_callsign`, callsign max 32 bytes).
    pub id_interval: Option<u64>,
    pub id_callsign: Option<Vec<u8>>,
}

impl BleRNodeConfig {
    pub fn new(name: &str, ble_uri: &str) -> Self {
        Self {
            name: name.to_string(),
            ble_uri: ble_uri.to_string(),
            frequency: 868_000_000,
            bandwidth: 125_000,
            spreading_factor: 7,
            coding_rate: 5,
            tx_power: 14,
            mode: InterfaceMode::Full,
            // Python RNodeInterface defaults flow_control off.
            flow_control: false,
            st_alock: None,
            lt_alock: None,
            id_interval: None,
            id_callsign: None,
        }
    }

    /// Validate RF and airtime settings before adapter or task side effects.
    pub fn validate(&self) -> Result<(), rnode::RNodeConfigValidationError> {
        rnode_config_from_ble_config(self).validate()
    }
}

/// Station-ID beacon parameters, disabled for oversized callsigns
/// (Python RNodeInterface.py:333-343).
fn beacon_from_config(config: &BleRNodeConfig) -> Option<(Duration, Bytes)> {
    config
        .id_interval
        .zip(config.id_callsign.clone())
        .filter(|(_, callsign)| {
            let ok = callsign.len() <= rnode::CALLSIGN_MAX_LEN;
            if !ok {
                tracing::error!(
                    name = %config.name,
                    len = callsign.len(),
                    "id_callsign exceeds {} bytes, beaconing disabled",
                    rnode::CALLSIGN_MAX_LEN
                );
            }
            ok
        })
        .map(|(interval, callsign)| (Duration::from_secs(interval), Bytes::from(callsign)))
}

fn rnode_config_from_ble_config(config: &BleRNodeConfig) -> rnode::RNodeConfig {
    rnode::RNodeConfig {
        name: config.name.clone(),
        port: config.ble_uri.clone(),
        baud_rate: 0,
        frequency: config.frequency,
        bandwidth: config.bandwidth,
        spreading_factor: config.spreading_factor,
        coding_rate: config.coding_rate,
        tx_power: config.tx_power,
        mode: config.mode,
        flow_control: config.flow_control,
        st_alock: config.st_alock,
        lt_alock: config.lt_alock,
        id_interval: config.id_interval,
        id_callsign: config.id_callsign.clone(),
    }
}

fn build_ble_rnode_init_sequence(config: &BleRNodeConfig) -> Vec<u8> {
    build_ble_rnode_init_stages(config).concat()
}

fn build_ble_rnode_init_stages(config: &BleRNodeConfig) -> Vec<Vec<u8>> {
    rnode::build_ble_radio_reassertion_stages(&rnode_config_from_ble_config(config))
}

/// Native legacy admission deliberately discards handshake deframer state, so
/// re-request detection/firmware evidence after radio init. Explicit capability
/// admission retains its private detect/firmware evidence and uses the ordinary
/// RNode init sequence without this refresh marker.
fn build_native_rnode_init_sequence(config: &BleRNodeConfig) -> Vec<u8> {
    let mut sequence = build_ble_rnode_init_sequence(config);
    sequence.extend(rnode::build_detect_sequence());
    sequence
}

pub(crate) async fn get_adapter() -> Result<Adapter, InterfaceError> {
    // btleplug's Android global_adapter() panics without init; under
    // panic=abort that kills the app. Fail loudly so the UI can prompt.
    #[cfg(target_os = "android")]
    if !BTLEPLUG_INITIALIZED.load(Ordering::SeqCst) {
        return Err(InterfaceError::SendFailed(
            "BLE not initialized on Android — grant Bluetooth permissions and restart".into(),
        ));
    }

    let manager = bounded_ble_operation("manager init", Manager::new()).await?;
    let adapters = bounded_ble_operation("adapter enumeration", manager.adapters()).await?;
    adapters
        .into_iter()
        .next()
        .ok_or_else(|| InterfaceError::SendFailed("No BLE adapter found".into()))
}

/// Cheap "is there a BLE adapter?" probe with no `start_scan` side effect.
/// Use this for startup-time availability checks instead of `scan_ble_devices(0)`,
/// which actually starts (and immediately stops) a scan and noisily logs an
/// `[BLE scan] adapter acquired` line per call.
pub async fn ble_adapter_present() -> Result<bool, String> {
    match get_adapter().await {
        Ok(_) => Ok(true),
        Err(e) => Err(format!("{e}")),
    }
}

/// Tags anything advertising the Nordic UART Service as `RNode`, the rest
/// as `Unknown`.
///
/// `bonded` semantics by platform:
///   - **Linux**: queried directly from BlueZ via bluer's `device.is_paired()`.
///     Ground truth.
///   - **Android**: not used here — the Android frontend bypasses this
///     function entirely and reads `BluetoothDevice.bondState` natively in
///     Kotlin.
///   - **Apple (iOS / macOS) and Windows**: always `false`. CoreBluetooth
///     (by design, for privacy) and btleplug's WinRT backend don't expose
///     bond state to apps. Embedding UIs should hide bonded-state badges on
///     these platforms.
///
/// Apple bonded-state detection would require an objc2 bridge to
/// `CBCentralManager.retrievePeripheralsWithIdentifiers(_:)` or a local cache.
///
/// Windows bonded-state detection would require a WinRT
/// `BluetoothLEDevice.DeviceInformation.Pairing.IsPaired` binding.
pub async fn scan_ble_devices(timeout_secs: u64) -> Result<Vec<BleDevice>, String> {
    let adapter = get_adapter().await.map_err(|e| format!("{e}"))?;

    tracing::info!("[BLE scan] adapter acquired, starting scan (timeout={timeout_secs}s)");
    if let Err(e) = bounded_ble_operation("scan start", adapter.start_scan(ble_scan_filter())).await
    {
        tracing::error!("[BLE scan] start_scan failed: {e:?}");
        return Err(format!("Scan start failed: {e}"));
    }

    tokio::time::sleep(Duration::from_secs(timeout_secs)).await;

    let peripherals = bounded_ble_operation("peripheral list", adapter.peripherals())
        .await
        .map_err(|e| format!("{e}"))?;

    // On Linux, get a bluer adapter handle once so we can query bond state
    // per peripheral without paying the D-Bus session setup repeatedly.
    #[cfg(target_os = "linux")]
    let bluer_adapter = match linux_bluer_session().await {
        Ok(session) => match session.default_adapter().await {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::warn!(
                    "[BLE scan] bluer adapter unavailable, bonded flags will read false: {e}"
                );
                None
            }
        },
        Err(e) => {
            tracing::warn!(
                "[BLE scan] bluer session unavailable, bonded flags will read false: {e}"
            );
            None
        }
    };

    let mut devices = Vec::new();
    for p in peripherals {
        if let Ok(Some(props)) = bounded_ble_operation("properties", p.properties()).await {
            let name = props.local_name.clone().unwrap_or_default();
            if name.is_empty() {
                continue;
            }

            let service_uuids = &props.services;
            // NUS UUID + "RNode" name prefix keeps generic Nordic-UART
            // devices (Bangle.js, Adafruit demos) out of the picker. The
            // name-only fallback covers iOS scan-response quirks where
            // service UUIDs are missing from the initial advert.
            let has_nus = service_uuids.contains(&NUS_SERVICE_UUID);
            let name_match = name.starts_with("RNode");
            let is_rnode = name_match && (has_nus || service_uuids.is_empty());
            if !is_rnode {
                continue;
            }

            let address = p.id().to_string();

            #[cfg(target_os = "linux")]
            let bonded = match (&bluer_adapter, parse_linux_ble_address(&address).ok()) {
                (Some(adapter), Some(addr)) => match adapter.device(addr) {
                    Ok(device) => device.is_paired().await.unwrap_or(false),
                    Err(_) => false,
                },
                _ => false,
            };
            #[cfg(not(target_os = "linux"))]
            let bonded = false;

            devices.push(BleDevice {
                name,
                address,
                rssi: props.rssi,
                device_type: BleDeviceType::RNode,
                bonded,
            });
        }
    }

    bounded_ble_operation("scan stop", adapter.stop_scan())
        .await
        .ok();
    Ok(devices)
}

/// Accepts:
///   `ble://<MAC>`, `ble://<name>`, or bare `ble://` (first RNode found).
async fn resolve_ble_target(
    adapter: &Adapter,
    ble_uri: &str,
    generation_stable_name: Option<&str>,
) -> Result<(Peripheral, BleTargetResolutionClass), InterfaceError> {
    let target = ble_uri.strip_prefix("ble://").unwrap_or(ble_uri);
    ble_diag(format!("[ble] resolve_ble_target target='{target}'"));

    bounded_ble_operation("scan start", adapter.start_scan(ble_scan_filter()))
        .await
        .inspect_err(|error| ble_diag(format!("[ble] start_scan err: {error}")))?;
    tokio::time::sleep(Duration::from_secs(SCAN_TIMEOUT)).await;
    bounded_ble_operation("scan stop", adapter.stop_scan())
        .await
        .ok();

    let peripherals = bounded_ble_operation("peripheral list", adapter.peripherals()).await?;
    ble_diag(format!(
        "[ble] scan found {} peripherals",
        peripherals.len()
    ));

    if target.is_empty() {
        for p in &peripherals {
            if let Ok(Some(props)) = bounded_ble_operation("properties", p.properties()).await {
                if props.services.contains(&NUS_SERVICE_UUID) {
                    return Ok((p.clone(), BleTargetResolutionClass::FirstRnode));
                }
                // A populated list without NUS means a different device;
                // only fall back to the name on empty service lists.
                if props.services.is_empty() {
                    if let Some(ref name) = props.local_name {
                        if name.starts_with("RNode ") {
                            return Ok((p.clone(), BleTargetResolutionClass::FirstRnode));
                        }
                    }
                }
            }
        }
        return Err(InterfaceError::SendFailed(
            "No RNode BLE device found".into(),
        ));
    }

    // `peripheral.id().to_string()` is MAC on Linux/Android, CB UUID on
    // iOS/macOS — same string the scanner exposes.
    for p in &peripherals {
        let addr = p.id().to_string();
        if addr.eq_ignore_ascii_case(target) {
            ble_diag(format!("[ble] resolve matched by address: {addr}"));
            return Ok((p.clone(), BleTargetResolutionClass::PrimaryId));
        }
    }

    // Friendly-name resolution remains a fallback behind the configured
    // platform ID. After an exact first generation, its verified RNode name is
    // retained in memory so a post-bond CoreBluetooth handle replacement can
    // be resolved without changing the public/configured identity.
    for p in &peripherals {
        if let Ok(Some(props)) = bounded_ble_operation("properties", p.properties()).await {
            if let Some(ref name) = props.local_name {
                if let Some(resolution_class) =
                    ble_name_resolution_class(target, generation_stable_name, name)
                {
                    if resolution_class == BleTargetResolutionClass::PrimaryName {
                        ble_diag(format!("[ble] resolve matched by name: {name}"));
                    } else {
                        ble_diag("[ble] resolve matched by generation-stable advertised name");
                    }
                    return Ok((p.clone(), resolution_class));
                }
            }
        }
    }

    ble_diag(format!(
        "[ble] resolve failed: no peripheral matches '{target}'"
    ));
    Err(InterfaceError::SendFailed(format!(
        "BLE device not found: {target}. Ensure it is powered on and paired."
    )))
}

struct BleRNodeConnection {
    generation_id: BleGenerationId,
    peripheral: Peripheral,
    adapter_events: BleCentralEventStream,
    rx_char: btleplug::api::Characteristic,
    // Retained so the resolved write characteristic remains part of the
    // connection state even though writes currently go through `peripheral`.
    #[allow(dead_code)]
    tx_char: btleplug::api::Characteristic,
    write_mtu: usize,
}

struct NativePendingOutbound {
    outbound: PendingOutbound,
    expected_ack: Option<u64>,
    sent_at: Option<tokio::time::Instant>,
}

impl NativePendingOutbound {
    fn new(outbound: PendingOutbound) -> Self {
        Self {
            outbound,
            expected_ack: None,
            sent_at: None,
        }
    }

    fn reset_for_generation(&mut self) {
        self.expected_ack = None;
        self.sent_at = None;
    }

    fn acknowledgement_timed_out(&self, now: tokio::time::Instant) -> bool {
        self.sent_at
            .is_some_and(|sent_at| now.duration_since(sent_at) >= RNODE_NATIVE_BRIDGE_ACK_TIMEOUT)
    }
}

fn native_bridge_acknowledged_data_frames(command: u8, payload: &[u8]) -> Option<u64> {
    if command != RNODE_NATIVE_BRIDGE_ACK_COMMAND
        || payload.len() != RNODE_NATIVE_BRIDGE_ACK_PAYLOAD_LEN
        || &payload[..RNODE_NATIVE_BRIDGE_ACK_MAGIC.len()] != RNODE_NATIVE_BRIDGE_ACK_MAGIC
    {
        return None;
    }
    Some(u64::from_be_bytes(
        payload[RNODE_NATIVE_BRIDGE_ACK_MAGIC.len()..]
            .try_into()
            .expect("native bridge acknowledgement width checked"),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeStartupReductionError {
    MalformedBridgeAck,
    ActiveCarryOverflow,
    PreReadyDataOverflow,
}

fn reduce_native_startup_bytes(
    protocol_state: &mut RNodeProtocolState,
    deframer: &mut kiss::RawKissDeframer,
    bytes: &[u8],
    pre_ready_data: &mut Vec<Vec<u8>>,
    pre_ready_data_bytes: &mut usize,
    active_frames: &mut Vec<(u8, Vec<u8>)>,
    active_bytes: &mut usize,
) -> Result<(), NativeStartupReductionError> {
    for (command, frame) in deframer.feed(bytes) {
        if command == RNODE_NATIVE_BRIDGE_ACK_COMMAND {
            if native_bridge_acknowledged_data_frames(command, &frame).is_none() {
                return Err(NativeStartupReductionError::MalformedBridgeAck);
            }
            // No application data is emitted during startup, so an exact ACK
            // is consumed without becoming RNode evidence or transport data.
            continue;
        }
        if matches!(protocol_state.readiness(), RNodeReadiness::Ready) {
            if command != kiss::CMD_DATA {
                protocol_state.apply_frame(command, &frame);
            }
            *active_bytes = active_bytes.saturating_add(frame.len().saturating_add(1));
            if *active_bytes > RNODE_NATIVE_STARTUP_ACTIVE_CARRY_MAX {
                return Err(NativeStartupReductionError::ActiveCarryOverflow);
            }
            active_frames.push((command, frame));
            if !matches!(protocol_state.readiness(), RNodeReadiness::Ready) {
                active_frames.clear();
                *active_bytes = 0;
            }
        } else if command == kiss::CMD_DATA {
            if !hold_native_pre_ready_data(frame, pre_ready_data, pre_ready_data_bytes) {
                return Err(NativeStartupReductionError::PreReadyDataOverflow);
            }
        } else {
            protocol_state.apply_frame(command, &frame);
        }
    }
    Ok(())
}

async fn connect_rnode(
    adapter: &Adapter,
    ble_uri: &str,
    generation_stable_name: &mut Option<String>,
    running: &AtomicBool,
    generation_id: BleGenerationId,
) -> Result<BleRNodeConnection, InterfaceError> {
    ble_diag(format!("[ble] connect_rnode start uri={ble_uri}"));
    let alternate_name = if cfg!(any(target_os = "ios", target_os = "macos")) {
        generation_stable_name.as_deref()
    } else {
        None
    };
    let (peripheral, resolution_class) =
        match resolve_ble_target(adapter, ble_uri, alternate_name).await {
            Ok(resolved) => resolved,
            Err(error) => {
                trace_ble_lifecycle(generation_id, "target_resolution", "failed", None, None);
                return Err(error);
            }
        };
    trace_ble_lifecycle(
        generation_id,
        "target_resolution",
        resolution_class.label(),
        None,
        None,
    );
    ble_diag(format!("[ble] resolved peripheral id={}", peripheral.id()));
    let target_id = peripheral.id();
    // The exact target event receiver is installed before any connection
    // future. CoreBluetooth can otherwise remove a peripheral while btleplug
    // leaves connect/read/subscribe pending forever.
    let mut adapter_events =
        bounded_ble_operation("adapter event stream", adapter.events()).await?;

    #[cfg(target_os = "linux")]
    {
        // BlueZ needs explicit pairing before we open a btleplug GATT
        // connection. If this creates a fresh bond, RNode intentionally
        // disconnects shortly afterwards; wait through that before connect().
        let bluer_addr = parse_linux_ble_address(&peripheral.address().to_string())?;
        if linux_trigger_pairing(bluer_addr).await? {
            ble_diag("[pair][linux] fresh bond complete — waiting for RNode post-pair disconnect");
            tokio::time::sleep(RNODE_POST_BOND_SETTLE).await;
        }
    }

    let mut last_err = String::new();
    for attempt in 1..=3 {
        trace_ble_lifecycle(generation_id, "connect", "started", None, None);
        match run_generation_operation(
            BleOperationStage::Connect,
            peripheral.connect(),
            &mut adapter_events,
            running,
            |event| matches!(event, CentralEvent::DeviceDisconnected(id) if id == &target_id),
        )
        .await
        {
            Ok(()) => {
                trace_ble_lifecycle(generation_id, "connect", "accepted", None, None);
                tracing::info!(address = %peripheral.id(), attempt, "BLE RNode connected");
                ble_diag(format!(
                    "[ble] peripheral.connect() ok on attempt {attempt}"
                ));
                break;
            }
            Err(error) => {
                trace_ble_lifecycle(
                    generation_id,
                    "connect",
                    generation_exit_result_class(&error),
                    None,
                    None,
                );
                last_err = error.to_string();
                tracing::warn!(attempt, error = %error, "BLE RNode connect attempt failed");
                ble_diag(format!(
                    "[ble] peripheral.connect() err on attempt {attempt}: {error}"
                ));
                if matches!(
                    error,
                    BleGenerationExit::StopRequested { .. }
                        | BleGenerationExit::EventStreamEnded { .. }
                ) {
                    return Err(InterfaceError::SendFailed(error.to_string()));
                }
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    let connected = run_generation_operation(
        BleOperationStage::ConnectedCheck,
        peripheral.is_connected(),
        &mut adapter_events,
        running,
        |event| matches!(event, CentralEvent::DeviceDisconnected(id) if id == &target_id),
    )
    .await
    .map_err(|error| {
        trace_ble_lifecycle(
            generation_id,
            "connected_check",
            generation_exit_result_class(&error),
            None,
            None,
        );
        InterfaceError::SendFailed(error.to_string())
    })?;
    if !connected {
        trace_ble_lifecycle(
            generation_id,
            "connected_check",
            "not_connected",
            None,
            None,
        );
        ble_diag(format!(
            "[ble] is_connected=false after retries: {last_err}"
        ));
        return Err(InterfaceError::SendFailed(format!(
            "BLE connect failed after 3 attempts: {last_err}"
        )));
    }
    trace_ble_lifecycle(generation_id, "connected_check", "accepted", None, None);

    ble_diag("[ble] discover_services start");
    trace_ble_lifecycle(generation_id, "discovery", "started", None, None);
    run_generation_operation(
        BleOperationStage::Discovery,
        peripheral.discover_services(),
        &mut adapter_events,
        running,
        |event| matches!(event, CentralEvent::DeviceDisconnected(id) if id == &target_id),
    )
    .await
    .map_err(|error| {
        trace_ble_lifecycle(
            generation_id,
            "discovery",
            generation_exit_result_class(&error),
            None,
            None,
        );
        ble_diag(format!("[ble] discover_services err: {error}"));
        InterfaceError::SendFailed(error.to_string())
    })?;
    trace_ble_lifecycle(generation_id, "discovery", "accepted", None, None);
    ble_diag("[ble] discover_services ok");

    let chars = peripheral.characteristics();
    ble_diag(format!("[ble] characteristics count={}", chars.len()));
    let rx_char = chars
        .iter()
        .find(|c| c.uuid == NUS_RX_CHAR_UUID)
        .ok_or_else(|| {
            trace_ble_lifecycle(generation_id, "discovery", "nus_rx_missing", None, None);
            ble_diag("[ble] NUS RX char not found");
            InterfaceError::SendFailed("NUS RX characteristic not found. Is this an RNode?".into())
        })?
        .clone();
    let tx_char = chars
        .iter()
        .find(|c| c.uuid == NUS_TX_CHAR_UUID)
        .ok_or_else(|| {
            trace_ble_lifecycle(generation_id, "discovery", "nus_tx_missing", None, None);
            ble_diag("[ble] NUS TX char not found");
            InterfaceError::SendFailed("NUS TX characteristic not found. Is this an RNode?".into())
        })?
        .clone();
    if generation_stable_name.is_none() {
        if let Ok(Some(properties)) =
            bounded_ble_operation("resolved target properties", peripheral.properties()).await
        {
            if let Some(name) = properties
                .local_name
                .filter(|name| name.starts_with("RNode "))
            {
                *generation_stable_name = Some(name);
            }
        }
    }
    ble_diag(format!(
        "[ble] RX/TX chars found; RX props={:?} TX props={:?}",
        rx_char.properties, tx_char.properties
    ));

    // Select one authentication trigger from the discovered GATT contract.
    // ESP RNodes expose an encrypted readable TX value, so the established
    // read-before-subscribe sequence remains authoritative. Bluefruit nRF
    // RNodes expose TX as notification-only and secure the CCCD; on Apple the
    // subscription itself must trigger SMP. The exact generation owner below
    // fences either operation against the intentional post-bond disconnect.
    // Windows and Android retain their reviewed encrypted-read behavior, and
    // Linux uses explicit BlueZ pairing before `connect()`, above.
    #[cfg(any(
        target_os = "ios",
        target_os = "macos",
        target_os = "windows",
        target_os = "android"
    ))]
    let pairing_trigger = desktop_pairing_trigger_for_properties(
        tx_char.properties,
        cfg!(any(target_os = "ios", target_os = "macos")),
    );
    #[cfg(any(
        target_os = "ios",
        target_os = "macos",
        target_os = "windows",
        target_os = "android"
    ))]
    {
        trace_ble_lifecycle(
            generation_id,
            "pairing_trigger",
            pairing_trigger.label(),
            Some(tx_char.properties.contains(CharPropFlags::READ)),
            Some(tx_char.properties.contains(CharPropFlags::NOTIFY)),
        );
        ble_diag(format!(
            "[pair] trigger={} tx_read={} tx_notify={}",
            pairing_trigger.label(),
            tx_char.properties.contains(CharPropFlags::READ),
            tx_char.properties.contains(CharPropFlags::NOTIFY),
        ));

        if pairing_trigger == DesktopPairingTrigger::EncryptedRead {
            desktop_trigger_pairing(
                &peripheral,
                &tx_char,
                &mut adapter_events,
                running,
                &target_id,
                generation_id,
            )
            .await?;
        }
    }

    // A notification-only secured CCCD is an interactive pairing operation on
    // Apple. Give the system prompt the same human-entry deadline as the
    // encrypted read path. Once bonded, this subscription completes normally
    // and is not repeated within the accepted generation.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    let subscribe_stage = if pairing_trigger == DesktopPairingTrigger::SecuredSubscribe {
        BleOperationStage::PairingSubscribe
    } else {
        BleOperationStage::Subscribe
    };
    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    let subscribe_stage = BleOperationStage::Subscribe;

    ble_diag("[ble] subscribe TX start");
    trace_ble_lifecycle(generation_id, "subscribe", "started", None, None);
    run_generation_operation(
        subscribe_stage,
        peripheral.subscribe(&tx_char),
        &mut adapter_events,
        running,
        |event| matches!(event, CentralEvent::DeviceDisconnected(id) if id == &target_id),
    )
    .await
    .map_err(|error| map_subscribe_generation_error(generation_id, error))?;
    trace_ble_lifecycle(generation_id, "subscribe", "accepted", None, None);
    ble_diag("[ble] subscribe TX ok");

    let write_mtu = ble_write_chunk_size();
    tracing::info!(write_mtu, "BLE RNode write chunk size");
    ble_diag(format!("[ble] write chunk size={write_mtu}"));

    Ok(BleRNodeConnection {
        generation_id,
        peripheral,
        adapter_events,
        rx_char,
        tx_char,
        write_mtu,
    })
}

fn map_subscribe_generation_error(
    generation_id: BleGenerationId,
    error: BleGenerationExit,
) -> InterfaceError {
    trace_ble_lifecycle(
        generation_id,
        "subscribe",
        generation_exit_result_class(&error),
        None,
        None,
    );
    ble_diag(format!("[ble] subscribe TX err: {error}"));
    let detail = match &error {
        BleGenerationExit::TargetDisconnected { .. }
        | BleGenerationExit::StageFailed {
            stage: BleOperationStage::PairingSubscribe,
            ..
        } => format!("BLE pairing in progress: {error}"),
        BleGenerationExit::DeadlineElapsed {
            stage: BleOperationStage::PairingSubscribe,
        } => "BLE pairing timed out while enabling secured notifications. Did you enter the 6-digit passkey shown on the RNode when the system prompted?".into(),
        _ => error.to_string(),
    };
    InterfaceError::SendFailed(detail)
}

/// Trigger authentication through a TX value that advertises encrypted reads.
/// The system shows its passkey dialog (code on the RNode display) and may
/// briefly drop L2CAP. Caller MUST NOT recover in-place — on Apple the post-SMP
/// CBPeripheral can enter a zombie state where `connect()` / `is_connected()`
/// hang; on Windows btleplug returns the read error and we bubble it so the
/// reconnect loop re-resolves with a fresh handle.
///
/// Works on iOS + macOS (CoreBluetooth) and Windows 10/11 (WinRT GATT —
/// `GattCharacteristic::ReadValueAsync` triggers Windows' built-in
/// pairing flow when the characteristic requires authentication). Linux
/// uses `linux_trigger_pairing` instead — BlueZ requires an explicit
/// `Device::pair()` plus a registered Agent for the passkey callback.
///
/// Android behaves like Windows: a GATT op on an auth-required readable char makes
/// the platform start bonding (system passkey dialog) and retry the op
/// internally once bonded. Without this read-first step the subscribe()
/// CCCD write fails instantly with insufficient-auth while the bond is
/// still running — first add fails, second connect works. If the stack
/// errors instead of blocking, the error maps to "BLE pairing in
/// progress" and the reconnect loop retries on a 1s cadence until the
/// bond lands.
///
/// Apple notification-only TX characteristics do not enter this function;
/// their secured CCCD subscription is the authentication trigger.
#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "windows",
    target_os = "android"
))]
async fn desktop_trigger_pairing(
    peripheral: &Peripheral,
    tx_char: &btleplug::api::Characteristic,
    adapter_events: &mut BleCentralEventStream,
    running: &AtomicBool,
    target_id: &PeripheralId,
    generation_id: BleGenerationId,
) -> Result<(), InterfaceError> {
    ble_diag(format!(
        "[pair] reading TX char — triggers SMP if unbonded: props={:?}",
        tx_char.properties
    ));
    trace_ble_lifecycle(generation_id, "pairing_read", "started", None, None);

    // Observe before issuing the encrypted read. The nRF RNode deliberately
    // disconnects after it has durably stored a fresh bond. On CoreBluetooth,
    // btleplug's characteristic callback ignores ATT read errors, so its read
    // future is not guaranteed to wake even though the adapter publishes the
    // disconnect. Race both signals and route either one through the existing
    // generation-local reconnect loop.
    let pairing_result = run_generation_operation(
        BleOperationStage::PairingRead,
        peripheral.read(tx_char),
        adapter_events,
        running,
        |event| matches!(event, CentralEvent::DeviceDisconnected(id) if id == target_id),
    )
    .await;

    match pairing_result {
        Ok(bytes) => {
            trace_ble_lifecycle(generation_id, "pairing_read", "accepted", None, None);
            ble_diag(format!(
                "[pair] TX read ok ({} bytes) — bonded",
                bytes.len()
            ));
            Ok(())
        }
        Err(BleGenerationExit::StageFailed { reason, .. }) => {
            trace_ble_lifecycle(generation_id, "pairing_read", "stage_failed", None, None);
            // SMP just ran or is in progress — outer loop must retry with
            // a fresh peripheral.
            ble_diag(format!(
                "[pair] TX read err ({reason}) — surfacing to reconnect loop"
            ));
            Err(InterfaceError::SendFailed(format!(
                "BLE pairing in progress: {reason}"
            )))
        }
        Err(BleGenerationExit::TargetDisconnected { .. }) => {
            trace_ble_lifecycle(
                generation_id,
                "pairing_read",
                "target_disconnected",
                None,
                None,
            );
            ble_diag(
                "[pair] target disconnected after encrypted read — fresh bond transition; reconnecting",
            );
            Err(InterfaceError::SendFailed(
                "BLE pairing in progress: RNode completed fresh bond and disconnected; reconnecting"
                    .into(),
            ))
        }
        Err(BleGenerationExit::DeadlineElapsed { .. }) => {
            trace_ble_lifecycle(
                generation_id,
                "pairing_read",
                "deadline_elapsed",
                None,
                None,
            );
            ble_diag("[pair] TX read timed out after 60s — passkey not entered?");
            Err(InterfaceError::SendFailed(
                "BLE pairing timed out. Did you enter the 6-digit passkey shown on the RNode when the system prompted?".into(),
            ))
        }
        Err(error) => {
            trace_ble_lifecycle(
                generation_id,
                "pairing_read",
                generation_exit_result_class(&error),
                None,
                None,
            );
            Err(InterfaceError::SendFailed(error.to_string()))
        }
    }
}

/// One-time global handle for the bluer Agent. BlueZ keeps the agent alive
/// only as long as this `AgentHandle` exists, so we park it in a OnceCell
/// for the lifetime of the process.
#[cfg(target_os = "linux")]
static LINUX_PAIRING_AGENT: tokio::sync::OnceCell<bluer::agent::AgentHandle> =
    tokio::sync::OnceCell::const_new();

/// Reuse the same bluer D-Bus session + adapter across pair attempts. Each
/// `Session::new()` is a fresh D-Bus connection (~1s to set up) so we cache
/// it for the process lifetime, mirroring how `LINUX_PAIRING_AGENT` is
/// kept alive. The bluer Session itself is `Clone` (Arc-backed) so we hand
/// out cheap copies.
#[cfg(target_os = "linux")]
static LINUX_BLUER_SESSION: tokio::sync::OnceCell<bluer::Session> =
    tokio::sync::OnceCell::const_new();

#[cfg(target_os = "linux")]
async fn linux_bluer_session() -> Result<&'static bluer::Session, InterfaceError> {
    LINUX_BLUER_SESSION
        .get_or_try_init(|| async {
            bluer::Session::new()
                .await
                .map_err(|e| InterfaceError::SendFailed(format!("bluer session: {e}")))
        })
        .await
}

#[cfg(target_os = "linux")]
async fn ensure_linux_pairing_agent(session: &bluer::Session) -> Result<(), InterfaceError> {
    LINUX_PAIRING_AGENT
        .get_or_try_init(|| async {
            let agent = bluer::agent::Agent {
                request_default: false,
                request_passkey: Some(Box::new(|req| {
                    Box::pin(async move {
                        let device = req.device.to_string();
                        // Snapshot the current attempt and install a fresh
                        // oneshot under the same lock so we can't race a
                        // concurrent `linux_cancel_pairing`.
                        let (rx, attempt_id) = {
                            let mut guard = match LINUX_PAIRING_STATE.lock() {
                                Ok(g) => g,
                                Err(_) => return Err(bluer::agent::ReqError::Rejected),
                            };
                            let state = match guard.as_mut() {
                                Some(s) if !s.aborted => s,
                                _ => {
                                    ble_diag(format!(
                                        "[pair][linux] request_passkey rejected (no active attempt) device={device}"
                                    ));
                                    return Err(bluer::agent::ReqError::Canceled);
                                }
                            };
                            let (tx, rx) = tokio::sync::oneshot::channel::<u32>();
                            state.passkey_tx = Some(tx);
                            (rx, state.attempt_id)
                        };
                        ble_diag(format!(
                            "[pair][linux] request_passkey attempt={attempt_id} device={device}"
                        ));
                        let _ = linux_pairing_prompt_sender().send(LinuxPairingPrompt {
                            device,
                            attempt_id,
                        });
                        match tokio::time::timeout(Duration::from_secs(60), rx).await {
                            Ok(Ok(passkey)) => {
                                // Verify the attempt is still current and
                                // not aborted before handing the passkey
                                // to BlueZ — guards against the user
                                // submitting and immediately cancelling.
                                let still_active = LINUX_PAIRING_STATE
                                    .lock()
                                    .ok()
                                    .and_then(|g| {
                                        g.as_ref().map(|s| {
                                            !s.aborted && s.attempt_id == attempt_id
                                        })
                                    })
                                    .unwrap_or(false);
                                if !still_active {
                                    ble_diag("[pair][linux] passkey arrived after abort");
                                    return Err(bluer::agent::ReqError::Canceled);
                                }
                                ble_diag("[pair][linux] passkey received from user");
                                Ok(passkey)
                            }
                            Ok(Err(_)) => {
                                ble_diag("[pair][linux] passkey channel cancelled");
                                Err(bluer::agent::ReqError::Canceled)
                            }
                            Err(_) => {
                                ble_diag("[pair][linux] passkey timeout after 60s");
                                Err(bluer::agent::ReqError::Canceled)
                            }
                        }
                    })
                })),
                ..Default::default()
            };
            session.register_agent(agent).await.map_err(|e| {
                InterfaceError::SendFailed(format!("bluer register_agent: {e}"))
            })
        })
        .await?;
    Ok(())
}

/// Parse a BLE address string into a `bluer::Address`, accepting either
/// a plain MAC (`AA:BB:CC:DD:EE:FF`) or a btleplug-Linux peripheral id
/// (BlueZ D-Bus path like `hci0/dev_AA_BB_CC_DD_EE_FF`).
///
/// btleplug's `Peripheral::id().to_string()` returns the D-Bus path on
/// Linux, and that's what `scan_ble_devices` ships to the frontend in the
/// `BleDevice.address` field. The wizard echoes it back via
/// `add_lora_interface` → `spawn_ble_rnode_interface` → `connect_rnode`
/// → `linux_trigger_pairing`, so this helper has to accept both forms.
#[cfg(target_os = "linux")]
fn parse_linux_ble_address(addr: &str) -> Result<bluer::Address, InterfaceError> {
    if let Ok(parsed) = addr.parse::<bluer::Address>() {
        return Ok(parsed);
    }
    if let Some(tail) = addr.rsplit('/').next() {
        if let Some(mac_part) = tail.strip_prefix("dev_") {
            let mac = mac_part.replace('_', ":");
            return mac.parse::<bluer::Address>().map_err(|e| {
                InterfaceError::SendFailed(format!(
                    "invalid BLE address (BlueZ path '{addr}' → '{mac}'): {e}"
                ))
            });
        }
    }
    Err(InterfaceError::SendFailed(format!(
        "invalid BLE address {addr}: not a MAC nor a BlueZ D-Bus path"
    )))
}

/// Linux SMP trigger via bluer. BlueZ does not auto-prompt SMP from an
/// encrypted-char read (unlike CoreBluetooth/WinRT) — pairing must be
/// initiated explicitly. Skips if already bonded; otherwise registers the
/// process-wide passkey Agent (idempotent) and drives `Device::pair()`
/// under a 60s budget. The agent's `request_passkey` proxies the prompt
/// to subscribers via the broadcast + oneshot pair declared above.
///
/// Single-flight: any prior attempt's state is aborted before installing
/// the new one. The pair() future is selected against a cancel `Notify`
/// so a user-driven cancel actually drops the future — bluer's
/// `Device::pair()` translates "future dropped" into a BlueZ
/// `CancelPairing` D-Bus call (see bluer 0.17 device.rs:256), so the
/// daemon stops retrying SMP instead of re-invoking `request_passkey`
/// every ~60s.
#[cfg(target_os = "linux")]
async fn linux_trigger_pairing(bluer_addr: bluer::Address) -> Result<bool, InterfaceError> {
    let overall_start = std::time::Instant::now();

    // Reuse the cached session so the second-and-subsequent attempts skip
    // the ~1s D-Bus setup. Build the agent and adapter once; reuse them.
    let t_session = std::time::Instant::now();
    let session = linux_bluer_session().await?;
    ble_diag(format!(
        "[pair][linux] session ready in {:.2}s",
        t_session.elapsed().as_secs_f32()
    ));

    let t_adapter = std::time::Instant::now();
    let adapter = session
        .default_adapter()
        .await
        .map_err(|e| InterfaceError::SendFailed(format!("bluer default adapter: {e}")))?;
    let device = adapter
        .device(bluer_addr)
        .map_err(|e| InterfaceError::SendFailed(format!("bluer device({bluer_addr}): {e}")))?;
    ble_diag(format!(
        "[pair][linux] adapter+device handles in {:.2}s",
        t_adapter.elapsed().as_secs_f32()
    ));

    let t_paired = std::time::Instant::now();
    if device.is_paired().await.unwrap_or(false) {
        ble_diag(format!(
            "[pair][linux] already bonded with {bluer_addr} (is_paired check {:.2}s)",
            t_paired.elapsed().as_secs_f32()
        ));
        return Ok(false);
    }
    ble_diag(format!(
        "[pair][linux] is_paired=false in {:.2}s",
        t_paired.elapsed().as_secs_f32()
    ));

    let t_agent = std::time::Instant::now();
    ensure_linux_pairing_agent(session).await?;
    ble_diag(format!(
        "[pair][linux] agent ready in {:.2}s",
        t_agent.elapsed().as_secs_f32()
    ));

    // We deliberately do NOT call `device.connect()` here. bluer's
    // `device.pair()` (issued below) translates to a `Pair Device` MGMT
    // command that BlueZ runs as: `Set Bondable / Set IO Capability /
    // Pair Device` BEFORE any L2CAP traffic, then opens the LL connection
    // and runs SMP atomically. Pre-connecting opens an unencrypted link
    // first; the RNode firmware then sends an `SMP: Security Request`
    // (auth_req=0x0d, Bonding+MITM+SC) before BlueZ has Bondable enabled,
    // and BlueZ replies `Pairing not supported (0x05)`. RNode marks the
    // pair attempt failed and ignores the subsequent retry, leaving
    // `device.pair()` to time out 30s later with `Authentication Canceled`.
    // For the connect_rnode call site (post-btleplug-connect path), the
    // device is expected to be already bonded and the early-return above
    // short-circuits.

    let attempt_id =
        LINUX_PAIRING_ATTEMPT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    let cancel_notify = std::sync::Arc::new(tokio::sync::Notify::new());
    ble_diag(format!(
        "[pair][linux] preflight total {:.2}s before device.pair()",
        overall_start.elapsed().as_secs_f32()
    ));

    // Tear down any prior attempt's state and install a fresh one. The
    // previous attempt's task (if any) is signalled via the captured
    // notify before we replace it; its select! arm wakes and drops its
    // pair() future, which propagates to BlueZ as CancelPairing.
    {
        let prior_notify = if let Ok(mut guard) = LINUX_PAIRING_STATE.lock() {
            let prior = guard.take().map(|mut prior| {
                prior.aborted = true;
                let _ = prior.passkey_tx.take();
                prior.cancel_notify.clone()
            });
            *guard = Some(LinuxPairingState {
                attempt_id,
                aborted: false,
                passkey_tx: None,
                cancel_notify: cancel_notify.clone(),
            });
            prior
        } else {
            None
        };
        if let Some(notify) = prior_notify {
            notify.notify_waiters();
        }
    }

    let t_pair = std::time::Instant::now();
    ble_diag(format!(
        "[pair][linux] device.pair() start attempt={attempt_id} addr={bluer_addr}"
    ));
    // tokio::select drops the losing arm's future. When cancel_notify wins,
    // the timeout(...) future drops, which drops the inner device.pair()
    // future, which fires bluer's CancelPairing on BlueZ (per
    // bluer-0.17/src/device.rs:256).
    let outcome: Result<(), InterfaceError> = tokio::select! {
        biased;
        _ = cancel_notify.notified() => {
            ble_diag(format!(
                "[pair][linux] pair cancelled by user attempt={attempt_id} after {:.2}s",
                t_pair.elapsed().as_secs_f32()
            ));
            Err(InterfaceError::SendFailed("BLE pairing cancelled".into()))
        }
        res = tokio::time::timeout(Duration::from_secs(60), device.pair()) => match res {
            Ok(Ok(())) => {
                ble_diag(format!(
                    "[pair][linux] paired ok attempt={attempt_id} with {bluer_addr} in {:.2}s",
                    t_pair.elapsed().as_secs_f32()
                ));
                Ok(())
            }
            Ok(Err(e)) => {
                ble_diag(format!(
                    "[pair][linux] pair err attempt={attempt_id} after {:.2}s: {e}",
                    t_pair.elapsed().as_secs_f32()
                ));
                Err(InterfaceError::SendFailed(format!(
                    "BLE pairing failed: {e}"
                )))
            }
            Err(_) => {
                ble_diag(format!(
                    "[pair][linux] pair timed out after 60s attempt={attempt_id}"
                ));
                Err(InterfaceError::SendFailed(
                    "BLE pairing timed out. Did you enter the 6-digit passkey shown on the RNode when the system prompted?".into(),
                ))
            }
        }
    };

    // Clear our state slot if it still owns this attempt (a concurrent
    // newer attempt would have already overwritten it; respect that).
    let status = match &outcome {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("{e}"),
    };
    if let Ok(mut guard) = LINUX_PAIRING_STATE.lock() {
        if guard
            .as_ref()
            .is_some_and(|state| state.attempt_id == attempt_id)
        {
            *guard = None;
        }
    }
    let _ = linux_pairing_finished_sender().send(LinuxPairingFinished { attempt_id, status });
    outcome.map(|()| true)
}

/// Write one complete extended-KISS frame/burst through a bounded GATT
/// acknowledgement boundary. Apple uses ordered response writes; other
/// platforms retain their qualified no-response policy.
pub(crate) async fn ble_write(
    peripheral: &Peripheral,
    rx_char: &btleplug::api::Characteristic,
    data: &[u8],
    mtu: usize,
) -> Result<(), InterfaceError> {
    if mtu == 0 {
        return Err(InterfaceError::SendFailed(
            "BLE write chunk size cannot be zero".into(),
        ));
    }
    let write_type = ble_write_type();
    tokio::time::timeout(BLE_OPERATION_TIMEOUT, async {
        for chunk in data.chunks(mtu) {
            peripheral
                .write(rx_char, chunk, write_type)
                .await
                .map_err(|e| InterfaceError::SendFailed(format!("BLE write: {e}")))?;
        }
        Ok(())
    })
    .await
    .map_err(|_| InterfaceError::SendFailed("BLE write timed out".into()))?
}

async fn ble_write_for_generation(
    conn: &mut BleRNodeConnection,
    data: &[u8],
    stage: BleOperationStage,
    running: &AtomicBool,
) -> Result<(), InterfaceError> {
    if conn.write_mtu == 0 {
        return Err(InterfaceError::SendFailed(
            "BLE write chunk size cannot be zero".into(),
        ));
    }
    let target_id = conn.peripheral.id();
    let chunk_count = data.len().div_ceil(conn.write_mtu);
    for (chunk_index, chunk) in data.chunks(conn.write_mtu).enumerate() {
        run_generation_operation(
            stage,
            conn.peripheral
                .write(&conn.rx_char, chunk, ble_write_type()),
            &mut conn.adapter_events,
            running,
            |event| matches!(event, CentralEvent::DeviceDisconnected(id) if id == &target_id),
        )
        .await
        .map_err(|error| {
            InterfaceError::SendFailed(format!(
                "BLE generation {} {stage} chunk {}/{}: {error}",
                conn.generation_id.get(),
                chunk_index + 1,
                chunk_count,
            ))
        })?;
    }
    Ok(())
}

async fn ble_reassert_radio(
    conn: &mut BleRNodeConnection,
    stages: &[Vec<u8>],
    running: &AtomicBool,
) -> Result<(), InterfaceError> {
    for stage in stages {
        ble_write_for_generation(conn, stage, BleOperationStage::Configure, running).await?;
        tokio::time::sleep(BLE_CONTROL_STAGE_SETTLE).await;
    }
    tokio::time::sleep(BLE_POST_INIT_SETTLE).await;
    Ok(())
}

async fn ble_send_radio_off(conn: &mut BleRNodeConnection) {
    let seq = rnode::build_detach_sequence();
    match ble_write(&conn.peripheral, &conn.rx_char, &seq, conn.write_mtu).await {
        Ok(()) => ble_diag("[ble] detach sent before disconnect"),
        Err(e) => ble_diag(format!("[ble] detach before disconnect failed: {e}")),
    }
}

async fn bounded_ble_disconnect(peripheral: &Peripheral) {
    let _ = tokio::time::timeout(
        BleOperationStage::Disconnect.deadline(),
        peripheral.disconnect(),
    )
    .await;
}

fn publish_ble_stopped(publisher: &mut RNodeSnapshotPublisher, reason: RNodeRuntimeReason) {
    publisher.shutting_down(reason);
    publisher.stopped(reason);
}

fn project_ble_rnode_frame(
    publisher: &RNodeSnapshotPublisher,
    protocol_state: &mut RNodeProtocolState,
    command: u8,
    frame: &[u8],
) {
    let effect = protocol_state.apply_frame(command, frame);
    publisher.protocol_effect(protocol_state, effect);
}

/// Apply one active-session frame to both the observer and the generation's
/// packet-admission latch. Both desktop GATT and Android's native loopback
/// path use this exact boundary.
fn project_active_ble_rnode_frame(
    publisher: &RNodeSnapshotPublisher,
    protocol_state: &mut RNodeProtocolState,
    packet_admission: &mut ActiveBlePacketAdmission,
    command: u8,
    frame: &[u8],
) -> bool {
    project_ble_rnode_frame(publisher, protocol_state, command, frame);
    packet_admission.observe_readiness(protocol_state.readiness());
    packet_admission.allows_packet()
}

enum BleHandshakeOutcome {
    Observed,
    Retry(&'static str),
    Stopped,
}

async fn observe_desktop_ble_handshake<S, E>(
    notification_stream: &mut S,
    adapter_events: &mut E,
    target_id: &PeripheralId,
    running: &AtomicBool,
    protocol_state: &mut RNodeProtocolState,
    deframer: &mut kiss::RawKissDeframer,
) -> BleHandshakeOutcome
where
    S: futures::Stream<Item = ValueNotification> + Unpin,
    E: futures::Stream<Item = CentralEvent> + Unpin,
{
    let deadline = tokio::time::Instant::now() + BleOperationStage::Detect.deadline();
    loop {
        let evidence = protocol_state.evidence();
        if evidence.detected {
            if let Some(firmware) = evidence.firmware {
                return if firmware.is_supported() {
                    BleHandshakeOutcome::Observed
                } else {
                    BleHandshakeOutcome::Retry("RNode firmware is unsupported")
                };
            }
        }
        if evidence.radio_initialisation_fault {
            return BleHandshakeOutcome::Retry("RNode reported a radio initialisation fault");
        }

        tokio::select! {
            notification = notification_stream.next() => match notification {
                Some(notification) if notification.uuid == NUS_TX_CHAR_UUID => {
                    for (command, frame) in deframer.feed(&notification.value) {
                        protocol_state.apply_frame(command, &frame);
                    }
                }
                Some(_) => {}
                None => return BleHandshakeOutcome::Retry(
                    "notification stream ended before detect evidence",
                ),
            },
            event = adapter_events.next() => match event {
                Some(CentralEvent::DeviceDisconnected(peripheral_id))
                    if &peripheral_id == target_id =>
                {
                    return BleHandshakeOutcome::Retry(
                        "target disconnected before detect evidence",
                    );
                }
                Some(_) => {}
                None => return BleHandshakeOutcome::Retry(
                    "adapter event stream ended before detect evidence",
                ),
            },
            _ = tokio::time::sleep(RUNNING_POLL) => {
                if !running.load(Ordering::SeqCst) {
                    return BleHandshakeOutcome::Stopped;
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                return BleHandshakeOutcome::Retry("detect evidence timed out");
            }
        }
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
#[cfg(test)]
struct BleStartupProjection {
    complete_frames: usize,
    legacy_packets_suppressed: usize,
}

#[cfg(test)]
fn project_ble_rnode_startup_bytes(
    publisher: &RNodeSnapshotPublisher,
    protocol_state: &mut RNodeProtocolState,
    deframer: &mut kiss::RawKissDeframer,
    bytes: &[u8],
) -> BleStartupProjection {
    let mut projection = BleStartupProjection::default();
    for (command, frame) in deframer.feed(bytes) {
        projection.complete_frames += 1;
        if command == kiss::CMD_DATA && !frame.is_empty() {
            projection.legacy_packets_suppressed += 1;
        }
        project_ble_rnode_frame(publisher, protocol_state, command, &frame);
    }
    projection
}

/// Auto-reconnect across drops; resolve_ble_target re-runs every retry so
/// iOS RPA rotation heals automatically.
pub async fn spawn_ble_rnode_interface(
    config: BleRNodeConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, InterfaceError> {
    Ok(
        spawn_ble_rnode_interface_with_driver(config, id, transport_tx)
            .await?
            .interface,
    )
}

/// Spawn a desktop BLE RNode interface with privacy-safe local observation.
///
/// This retains btleplug ownership and the compatibility facade above. The
/// native Android TCP bridge has its own lifecycle and is intentionally not
/// projected here.
pub async fn spawn_ble_rnode_interface_with_driver(
    config: BleRNodeConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<SpawnedRNodeInterface, InterfaceError> {
    spawn_ble_rnode_interface_with_driver_and_options(
        config,
        id,
        transport_tx,
        RNodeStartupOptions::default(),
    )
    .await
    .map_err(RNodeSpawnError::into_legacy_interface_error)
}

/// Spawn a desktop BLE RNode interface with an explicit startup policy.
///
/// BLE connection work remains asynchronous, so capability results arrive on
/// the returned driver observation rather than as a late function error. A
/// deterministic capability rejection on any connection generation publishes
/// terminal [`RNodeRuntimeReason::CapabilityAdmissionRejected`]. A response
/// timeout or transport loss retains the established BLE reconnect policy.
/// [`RNodeStartupOptions::default`] preserves the historical wire sequence.
pub async fn spawn_ble_rnode_interface_with_driver_and_options(
    config: BleRNodeConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    options: RNodeStartupOptions,
) -> Result<SpawnedRNodeInterface, RNodeSpawnError> {
    config.validate().map_err(|error| {
        InterfaceError::SendFailed(format!("rnode config {}: {error}", error.field()))
    })?;
    let protocol_target = RNodeProtocolTarget::new(
        config.frequency,
        config.bandwidth,
        config.spreading_factor,
        config.coding_rate,
        config.tx_power,
    );
    let online = Arc::new(AtomicBool::new(false));
    let online_handle = online.clone();
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let task_rxb = shared_rxb.clone();
    let task_txb = shared_txb.clone();
    let (tx, mut outbound_rx) = mpsc::channel::<Bytes>(256);
    let running = register_running(id);
    let (snapshot_publisher, driver) = rnode::new_rnode_driver_observation_with_shutdown(
        RNodeTransportClass::Ble,
        RNodeDriverShutdown::from_running_flag(running.clone()),
    );

    let bitrate = rnode::calculate_bitrate(
        config.spreading_factor,
        config.coding_rate,
        config.bandwidth,
    );

    let init_stage_template = build_ble_rnode_init_stages(&config);

    let name = config.name.clone();
    let mode = config.mode;
    let flow_control = config.flow_control;
    let beacon = beacon_from_config(&config);
    let ble_uri = config.ble_uri.clone();
    let log_name = name.clone();
    let running_task = running.clone();

    let read_task = tokio::spawn(async move {
        let mut snapshot_publisher = snapshot_publisher;
        let mut tries: usize = 0;
        let mut backoff = RECONNECT_WAIT;
        let mut initial_attempt = true;
        let mut generation_counter = BleGenerationId::default();
        // CoreBluetooth can replace/evict the peripheral handle during the
        // intentional nRF post-bond disconnect. Preserve the first verified
        // RNode advertised name only inside this runtime as a secondary
        // generation selector; the configured URI remains authoritative.
        let mut generation_stable_target_name: Option<String> = None;

        // Drop guard: every early return must clear the running-flag map
        // entry, or stale entries confuse later spawns reusing the id.
        struct Cleanup(InterfaceId, Arc<AtomicBool>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                unregister_running(self.0, &self.1);
            }
        }
        let _cleanup = Cleanup(id, running_task.clone());

        let mut pending_outbound: Option<PendingOutbound> = None;
        let mut first_tx: Option<tokio::time::Instant> = None;

        loop {
            if !running_task.load(Ordering::SeqCst) {
                ble_diag("[ble] read_task exiting — running flag cleared");
                publish_ble_stopped(&mut snapshot_publisher, RNodeRuntimeReason::StopRequested);
                return;
            }
            if initial_attempt {
                initial_attempt = false;
            } else {
                snapshot_publisher.reconnect_started();
            }
            // Re-acquire each iteration so mid-session permission grants or
            // adapter toggles heal automatically.
            let adapter = match get_adapter().await {
                Ok(a) => a,
                Err(e) => {
                    snapshot_publisher.connection_attempt_failed();
                    tracing::warn!(name = %log_name, error = %e, "BLE adapter acquisition failed");
                    if reconnect_try_exhausted(&mut tries) {
                        tracing::warn!(name = %log_name, "BLE RNode: max reconnect tries reached");
                        snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                        return;
                    }
                    if wait_or_shutdown(Duration::from_secs(backoff), &running_task).await {
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                    continue;
                }
            };

            let generation_id = generation_counter.next();
            let mut conn = match connect_rnode(
                &adapter,
                &ble_uri,
                &mut generation_stable_target_name,
                &running_task,
                generation_id,
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    let pairing_transition = is_pairing_transition_error(&e);
                    let retry_wait = if pairing_transition { 1 } else { backoff };
                    snapshot_publisher.connection_attempt_failed();
                    tracing::warn!(name = %log_name, error = %e, "BLE RNode connect failed");
                    ble_diag(format!(
                        "[ble] connect_rnode err: {e} — retrying in {retry_wait}s (attempt {})",
                        tries + 1
                    ));
                    if reconnect_try_exhausted(&mut tries) {
                        tracing::warn!(name = %log_name, "BLE RNode: max reconnect tries reached");
                        ble_diag("[ble] max reconnect tries reached — giving up");
                        snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                        return;
                    }
                    if wait_for_ble_retry(&adapter, Duration::from_secs(retry_wait), &running_task)
                        .await
                    {
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    if pairing_transition {
                        backoff = RECONNECT_WAIT;
                    } else {
                        backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                    }
                    continue;
                }
            };

            // btleplug creates a fresh event/broadcast receiver when
            // `notifications()` is called. Acquire it before detect/init so
            // startup evidence cannot race ahead of the observation stream.
            let target_peripheral_id = conn.peripheral.id();
            trace_ble_lifecycle(
                generation_id,
                "notification_acquisition",
                "started",
                None,
                None,
            );
            let mut notification_stream = match run_generation_operation(
                BleOperationStage::NotificationAcquisition,
                conn.peripheral.notifications(),
                &mut conn.adapter_events,
                &running_task,
                |event| matches!(event, CentralEvent::DeviceDisconnected(id) if id == &target_peripheral_id),
            )
            .await
            {
                Ok(stream) => {
                    trace_ble_lifecycle(
                        generation_id,
                        "notification_acquisition",
                        "accepted",
                        None,
                        None,
                    );
                    stream
                }
                Err(e) => {
                    trace_ble_lifecycle(
                        generation_id,
                        "notification_acquisition",
                        generation_exit_result_class(&e),
                        None,
                        None,
                    );
                    snapshot_publisher.connection_attempt_failed();
                    tracing::warn!(error = %e, "BLE RNode notification stream failed");
                    let _ =
                        tokio::time::timeout(Duration::from_secs(3), conn.peripheral.disconnect())
                            .await;
                    if reconnect_try_exhausted(&mut tries) {
                        tracing::warn!(name = %log_name, "BLE RNode: max reconnect tries reached");
                        snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                        return;
                    }
                    if wait_for_ble_retry(
                        &adapter,
                        Duration::from_secs(backoff),
                        &running_task,
                    )
                    .await
                    {
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                    continue;
                }
            };
            let mut protocol_state = RNodeProtocolState::new(protocol_target);
            let mut deframer = kiss::RawKissDeframer::new();
            ble_diag("[ble] sending detect sequence");
            trace_ble_lifecycle(generation_id, "detect_write", "started", None, None);
            let detect_seq = rnode::build_detect_sequence();
            if let Err(e) = ble_write_for_generation(
                &mut conn,
                &detect_seq,
                BleOperationStage::Detect,
                &running_task,
            )
            .await
            {
                trace_ble_lifecycle(generation_id, "detect_write", "failed", None, None);
                snapshot_publisher.connection_attempt_failed();
                tracing::warn!(error = %e, "BLE RNode detect write failed");
                ble_diag(format!("[ble] detect write failed: {e}"));
                let _ = tokio::time::timeout(Duration::from_secs(3), conn.peripheral.disconnect())
                    .await;
                if reconnect_try_exhausted(&mut tries) {
                    tracing::warn!(name = %log_name, "BLE RNode: max reconnect tries reached");
                    snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                    return;
                }
                if wait_for_ble_retry(&adapter, Duration::from_secs(backoff), &running_task).await {
                    publish_ble_stopped(&mut snapshot_publisher, RNodeRuntimeReason::StopRequested);
                    return;
                }
                backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                continue;
            }
            trace_ble_lifecycle(generation_id, "detect_write", "accepted", None, None);
            ble_diag("[ble] detect sent ok");

            let capability_admission = if options.requires_capability_admission() {
                if !running_task.load(Ordering::SeqCst) {
                    let _ =
                        tokio::time::timeout(Duration::from_secs(3), conn.peripheral.disconnect())
                            .await;
                    publish_ble_stopped(&mut snapshot_publisher, RNodeRuntimeReason::StopRequested);
                    return;
                }
                if let Err(error) = ble_write_for_generation(
                    &mut conn,
                    &build_rnode_capability_request(),
                    BleOperationStage::Capability,
                    &running_task,
                )
                .await
                {
                    snapshot_publisher.connection_attempt_failed();
                    tracing::warn!(
                        name = %log_name,
                        error = %error,
                        "BLE RNode capability request write failed"
                    );
                    let _ =
                        tokio::time::timeout(Duration::from_secs(3), conn.peripheral.disconnect())
                            .await;
                    if reconnect_try_exhausted(&mut tries) {
                        snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                        return;
                    }
                    if wait_for_ble_retry(&adapter, Duration::from_secs(backoff), &running_task)
                        .await
                    {
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                    continue;
                }

                match observe_desktop_ble_capability(
                    &mut notification_stream,
                    &mut conn.adapter_events,
                    |event| matches!(event, CentralEvent::DeviceDisconnected(id) if id == &target_peripheral_id),
                    ble_radio_settings(&config),
                    &running_task,
                    RNODE_BLE_CAPABILITY_PREFLIGHT_TIMEOUT,
                )
                .await
                {
                    BleCapabilityPreflightOutcome::Admitted {
                        protocol_state,
                        admission,
                    } => Some((protocol_state, admission)),
                    BleCapabilityPreflightOutcome::Stopped => {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(3),
                            conn.peripheral.disconnect(),
                        )
                        .await;
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    BleCapabilityPreflightOutcome::Retry(reason) => {
                        snapshot_publisher.connection_attempt_failed();
                        tracing::warn!(
                            name = %log_name,
                            admission_failure = reason.log_class(),
                            "BLE RNode capability preflight will retry"
                        );
                        let _ = tokio::time::timeout(
                            Duration::from_secs(3),
                            conn.peripheral.disconnect(),
                        )
                        .await;
                        if reconnect_try_exhausted(&mut tries) {
                            snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                            return;
                        }
                        if wait_for_ble_retry(
                            &adapter,
                            Duration::from_secs(backoff),
                            &running_task,
                        )
                        .await
                        {
                            publish_ble_stopped(
                                &mut snapshot_publisher,
                                RNodeRuntimeReason::StopRequested,
                            );
                            return;
                        }
                        backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                        continue;
                    }
                    BleCapabilityPreflightOutcome::Rejected(error) => {
                        tracing::warn!(
                            name = %log_name,
                            admission_failure = error.log_class(),
                            "BLE RNode capability admission rejected"
                        );
                        let _ = tokio::time::timeout(
                            Duration::from_secs(3),
                            conn.peripheral.disconnect(),
                        )
                        .await;
                        snapshot_publisher.stopped_for_admission_rejection(error.failure_class());
                        return;
                    }
                }
            } else {
                match observe_desktop_ble_handshake(
                    &mut notification_stream,
                    &mut conn.adapter_events,
                    &target_peripheral_id,
                    &running_task,
                    &mut protocol_state,
                    &mut deframer,
                )
                .await
                {
                    BleHandshakeOutcome::Observed => {
                        trace_ble_lifecycle(
                            generation_id,
                            "detect_handshake",
                            "observed",
                            None,
                            None,
                        );
                        None
                    }
                    BleHandshakeOutcome::Stopped => {
                        trace_ble_lifecycle(
                            generation_id,
                            "detect_handshake",
                            "stop_requested",
                            None,
                            None,
                        );
                        bounded_ble_disconnect(&conn.peripheral).await;
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    BleHandshakeOutcome::Retry(reason) => {
                        trace_ble_lifecycle(generation_id, "detect_handshake", "retry", None, None);
                        snapshot_publisher.connection_attempt_failed();
                        tracing::warn!(
                            name = %log_name,
                            reason,
                            "BLE RNode detect handshake will retry"
                        );
                        bounded_ble_disconnect(&conn.peripheral).await;
                        if reconnect_try_exhausted(&mut tries) {
                            snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                            return;
                        }
                        if wait_for_ble_retry(&adapter, Duration::from_secs(backoff), &running_task)
                            .await
                        {
                            publish_ble_stopped(
                                &mut snapshot_publisher,
                                RNodeRuntimeReason::StopRequested,
                            );
                            return;
                        }
                        backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                        continue;
                    }
                }
            };

            let admitted_capability = capability_admission.map(|(state, admission)| {
                protocol_state = state;
                admission
            });

            // A strict preflight stop cannot mutate the radio. Both policies
            // have now observed detect/firmware evidence before this boundary.
            if options.requires_capability_admission() && !running_task.load(Ordering::SeqCst) {
                let _ = tokio::time::timeout(Duration::from_secs(3), conn.peripheral.disconnect())
                    .await;
                publish_ble_stopped(&mut snapshot_publisher, RNodeRuntimeReason::StopRequested);
                return;
            }

            ble_diag("[ble] reasserting radio without RADIO_OFF");
            trace_ble_lifecycle(generation_id, "radio_reassertion", "started", None, None);
            if let Err(error) =
                ble_reassert_radio(&mut conn, &init_stage_template, &running_task).await
            {
                trace_ble_lifecycle(generation_id, "radio_reassertion", "failed", None, None);
                // A failed BLE generation is abandoned without sending OFF.
                // The RNode keeps the last complete radio state online while
                // this client reconnects and reasserts the full desired set.
                snapshot_publisher.connection_attempt_failed();
                tracing::warn!(error = %error, "BLE RNode radio reassertion failed");
                ble_diag(format!("[ble] radio reassertion failed: {error}"));
                let _ = tokio::time::timeout(Duration::from_secs(3), conn.peripheral.disconnect())
                    .await;
                if reconnect_try_exhausted(&mut tries) {
                    snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                    return;
                }
                if wait_for_ble_retry(&adapter, Duration::from_secs(backoff), &running_task).await {
                    publish_ble_stopped(&mut snapshot_publisher, RNodeRuntimeReason::StopRequested);
                    return;
                }
                backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                continue;
            }
            trace_ble_lifecycle(generation_id, "radio_reassertion", "accepted", None, None);
            ble_diag("[ble] radio reassertion sent ok — awaiting typed readiness");

            enum StartupReadinessOutcome {
                Ready,
                Retry(&'static str),
                Stopped,
            }
            let readiness_deadline = tokio::time::Instant::now() + RNODE_BLE_READINESS_TIMEOUT;
            let startup_outcome = loop {
                if matches!(protocol_state.readiness(), RNodeReadiness::Ready) {
                    break StartupReadinessOutcome::Ready;
                }
                tokio::select! {
                    notification = notification_stream.next() => match notification {
                        Some(notification) if notification.uuid == NUS_TX_CHAR_UUID => {
                            for (command, frame) in deframer.feed(&notification.value) {
                                // Startup owns control evidence only. Data is
                                // discarded until the complete typed target is
                                // Ready, so no application traffic crosses an
                                // unvalidated generation boundary.
                                protocol_state.apply_frame(command, &frame);
                            }
                        }
                        Some(_) => {}
                        None => break StartupReadinessOutcome::Retry(
                            "notification stream ended before Ready",
                        ),
                    },
                    event = conn.adapter_events.next() => match event {
                        Some(CentralEvent::DeviceDisconnected(peripheral_id))
                            if peripheral_id == target_peripheral_id =>
                        {
                            break StartupReadinessOutcome::Retry(
                                "target disconnected before Ready",
                            );
                        }
                        Some(_) => {}
                        None => break StartupReadinessOutcome::Retry(
                            "adapter event stream ended before Ready",
                        ),
                    },
                    _ = tokio::time::sleep(RUNNING_POLL) => {
                        if !running_task.load(Ordering::SeqCst) {
                            break StartupReadinessOutcome::Stopped;
                        }
                    }
                    _ = tokio::time::sleep_until(readiness_deadline) => {
                        break StartupReadinessOutcome::Retry("typed readiness timed out");
                    }
                }
            };

            match startup_outcome {
                StartupReadinessOutcome::Ready => {
                    trace_ble_lifecycle(generation_id, "typed_readiness", "ready", None, None);
                }
                StartupReadinessOutcome::Stopped => {
                    trace_ble_lifecycle(
                        generation_id,
                        "typed_readiness",
                        "stop_requested",
                        None,
                        None,
                    );
                    snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                    ble_send_radio_off(&mut conn).await;
                    let _ =
                        tokio::time::timeout(Duration::from_secs(3), conn.peripheral.disconnect())
                            .await;
                    snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                    return;
                }
                StartupReadinessOutcome::Retry(reason) => {
                    let result_class = match reason {
                        "notification stream ended before Ready" => "notification_stream_ended",
                        "target disconnected before Ready" => "target_disconnected",
                        "adapter event stream ended before Ready" => "event_stream_ended",
                        "typed readiness timed out" => "deadline_elapsed",
                        _ => "retry",
                    };
                    trace_ble_lifecycle(generation_id, "typed_readiness", result_class, None, None);
                    snapshot_publisher.connection_attempt_failed();
                    tracing::warn!(name = %log_name, reason, "BLE RNode did not reach Ready");
                    ble_diag(format!("[ble] readiness retry: {reason}"));
                    let _ =
                        tokio::time::timeout(Duration::from_secs(3), conn.peripheral.disconnect())
                            .await;
                    if reconnect_try_exhausted(&mut tries) {
                        snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                        return;
                    }
                    if wait_for_ble_retry(&adapter, Duration::from_secs(backoff), &running_task)
                        .await
                    {
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                    continue;
                }
            }

            // Never carry a partial startup frame into the admitted session.
            deframer.reset();
            if let Some(admission) = admitted_capability {
                snapshot_publisher.capability_connection_established(&protocol_state, admission);
            } else {
                snapshot_publisher.connection_established();
                snapshot_publisher.sync_protocol_state(&protocol_state);
            }
            online_handle.store(true, Ordering::SeqCst);
            tries = 0;
            backoff = RECONNECT_WAIT;
            tracing::info!(
                name = %log_name,
                ble_uri = %ble_uri,
                bitrate_bps = bitrate,
                "BLE RNode typed Ready"
            );

            let mut active_packet_admission = ActiveBlePacketAdmission::for_startup_policy(
                options.requires_capability_admission(),
            );
            active_packet_admission.observe_readiness(protocol_state.readiness());

            let ready = AtomicBool::new(true);

            let mut last_rssi: Option<f32> = None;
            let mut last_snr: Option<f32> = None;
            let mut transport_closed = false;

            enum GenerationEvent {
                Notification(Option<ValueNotification>),
                Adapter(Option<CentralEvent>),
                Outbound(Option<Bytes>),
                Poll,
            }

            'read: loop {
                if !online_handle.load(Ordering::SeqCst) {
                    trace_ble_lifecycle(
                        generation_id,
                        "active_generation",
                        "online_cleared",
                        None,
                        None,
                    );
                    break 'read;
                }
                if !running_task.load(Ordering::SeqCst) {
                    trace_ble_lifecycle(
                        generation_id,
                        "active_generation",
                        "stop_requested",
                        None,
                        None,
                    );
                    snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                    ble_send_radio_off(&mut conn).await;
                    break 'read;
                }

                let event = tokio::select! {
                    n = notification_stream.next() => GenerationEvent::Notification(n),
                    e = conn.adapter_events.next() => GenerationEvent::Adapter(e),
                    data = outbound_rx.recv(), if pending_outbound.is_none() => {
                        GenerationEvent::Outbound(data)
                    }
                    _ = tokio::time::sleep(RUNNING_POLL) => GenerationEvent::Poll,
                };

                match event {
                    GenerationEvent::Notification(Some(n)) if n.uuid == NUS_TX_CHAR_UUID => {
                        for (cmd, frame) in deframer.feed(&n.value) {
                            let data_allowed = project_active_ble_rnode_frame(
                                &snapshot_publisher,
                                &mut protocol_state,
                                &mut active_packet_admission,
                                cmd,
                                &frame,
                            );
                            match rnode::process_rnode_response(
                                cmd,
                                &frame,
                                id,
                                &mut last_rssi,
                                &mut last_snr,
                            ) {
                                RNodeResponse::Packet(msg) => {
                                    if data_allowed {
                                        task_rxb.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                        if transport_tx.send(msg).await.is_err() {
                                            trace_ble_lifecycle(
                                                generation_id,
                                                "active_generation",
                                                "transport_consumer_closed",
                                                None,
                                                None,
                                            );
                                            tracing::warn!(id, "transport channel closed");
                                            transport_closed = true;
                                            break 'read;
                                        }
                                    }
                                }
                                RNodeResponse::Ready(is_ready) => {
                                    ready.store(is_ready, Ordering::SeqCst);
                                }
                                RNodeResponse::None => {}
                            }
                        }
                    }
                    GenerationEvent::Notification(Some(_)) => {}
                    GenerationEvent::Notification(None) => {
                        trace_ble_lifecycle(
                            generation_id,
                            "active_generation",
                            "notification_stream_ended",
                            None,
                            None,
                        );
                        tracing::warn!("BLE RNode notification stream ended");
                        break 'read;
                    }
                    GenerationEvent::Adapter(Some(CentralEvent::DeviceDisconnected(
                        peripheral_id,
                    ))) if peripheral_id == target_peripheral_id => {
                        trace_ble_lifecycle(
                            generation_id,
                            "active_generation",
                            "target_disconnected",
                            None,
                            None,
                        );
                        tracing::warn!("BLE RNode disconnected; ending connection generation");
                        ble_diag("[ble] target DeviceDisconnected — reconnecting");
                        break 'read;
                    }
                    GenerationEvent::Adapter(Some(CentralEvent::StateUpdate(
                        CentralState::PoweredOff,
                    ))) => {
                        trace_ble_lifecycle(
                            generation_id,
                            "active_generation",
                            "adapter_powered_off",
                            None,
                            None,
                        );
                        tracing::info!("BLE adapter powered off; waiting for adapter recovery");
                        break 'read;
                    }
                    GenerationEvent::Adapter(Some(_)) => {}
                    GenerationEvent::Adapter(None) => {
                        trace_ble_lifecycle(
                            generation_id,
                            "active_generation",
                            "event_stream_ended",
                            None,
                            None,
                        );
                        tracing::warn!("BLE adapter event stream ended");
                        break 'read;
                    }
                    GenerationEvent::Outbound(Some(data)) => {
                        pending_outbound = Some(PendingOutbound::new(data, false));
                    }
                    GenerationEvent::Outbound(None) => {
                        trace_ble_lifecycle(
                            generation_id,
                            "active_generation",
                            "outbound_channel_closed",
                            None,
                            None,
                        );
                        tracing::warn!(id, "BLE RNode outbound channel closed");
                        transport_closed = true;
                        break 'read;
                    }
                    GenerationEvent::Poll => {
                        if pending_outbound.is_none() {
                            if let (Some((interval, callsign)), Some(first)) =
                                (beacon.as_ref(), first_tx)
                            {
                                if first.elapsed() >= *interval {
                                    tracing::debug!("BLE RNode scheduling station-ID beacon");
                                    pending_outbound =
                                        Some(PendingOutbound::new(callsign.clone(), true));
                                }
                            }
                        }
                    }
                }

                if pending_outbound.is_some() && claim_ble_packet_permit(flow_control, &ready) {
                    let pending = pending_outbound
                        .as_ref()
                        .expect("pending BLE outbound checked above");
                    let framed = kiss::frame(pending.payload());
                    match ble_write_for_generation(
                        &mut conn,
                        &framed,
                        BleOperationStage::ActiveWrite,
                        &running_task,
                    )
                    .await
                    {
                        Ok(()) => {
                            // Count only a complete acknowledged frame. If the
                            // generation fails before this boundary, retain the
                            // original payload and retry its full KISS frame.
                            task_txb.fetch_add(pending.payload().len() as u64, Ordering::Relaxed);
                            if pending.is_station_id() {
                                first_tx = None;
                            } else if first_tx.is_none() {
                                first_tx = Some(tokio::time::Instant::now());
                            }
                            pending_outbound = None;
                        }
                        Err(error) => {
                            trace_ble_lifecycle(
                                generation_id,
                                "active_generation",
                                "write_failed",
                                None,
                                None,
                            );
                            tracing::warn!(%error, "BLE RNode write failed; retaining payload");
                            ble_diag(format!(
                                "[ble] outbound write failed; payload retained: {error}"
                            ));
                            break 'read;
                        }
                    }
                }
            }

            online_handle.store(false, Ordering::SeqCst);
            bounded_ble_disconnect(&conn.peripheral).await;

            if transport_closed {
                publish_ble_stopped(
                    &mut snapshot_publisher,
                    RNodeRuntimeReason::TransportConsumerClosed,
                );
                return;
            }
            if !running_task.load(Ordering::SeqCst) {
                snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                return;
            }

            snapshot_publisher.connection_lost();
            trace_ble_lifecycle(generation_id, "reconnect", "scheduled", None, None);
            if reconnect_try_exhausted(&mut tries) {
                tracing::warn!(name = %log_name, "BLE RNode: max reconnect tries reached");
                snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                return;
            }
            tracing::info!(name = %log_name, seconds = backoff, "BLE RNode reconnecting");
            if wait_for_ble_retry(&adapter, ble_reconnect_delay(backoff), &running_task).await {
                publish_ble_stopped(&mut snapshot_publisher, RNodeRuntimeReason::StopRequested);
                return;
            }
            backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
        }
    });

    let interface = InterfaceHandle {
        id,
        parent_id: None,
        name,
        mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: true,
            forward: false,
            repeat: false,
        },
        bitrate,
        mtu: 508,
        online,
        rxb: Some(shared_rxb),
        txb: Some(shared_txb),
        inspection: None,
        tx,
        read_task,
    };

    Ok(SpawnedRNodeInterface { interface, driver })
}

/// Android-only TCP-bridge variant. btleplug's deprecated JNI breaks on
/// Android 14+, so Kotlin (`RatspeakBleGatt.kt`) owns the GATT lifecycle
/// and forwards NUS bytes over `tcp_port`.
pub async fn spawn_ble_rnode_interface_native(
    config: BleRNodeConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    tcp_port: u16,
) -> Result<InterfaceHandle, InterfaceError> {
    Ok(
        spawn_ble_rnode_interface_native_with_driver(config, id, transport_tx, tcp_port)
            .await?
            .interface,
    )
}

/// Spawn an Android native-bridge BLE RNode interface with privacy-safe local
/// driver observation.
///
/// Kotlin retains exclusive GATT ownership. The returned driver handle
/// observes only the Rust TCP-bridge generation and bounded RNode protocol
/// state; it never exposes the bridge port, BLE target, device identity, raw
/// frames, radio values, or unrestricted errors.
pub async fn spawn_ble_rnode_interface_native_with_driver(
    config: BleRNodeConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    tcp_port: u16,
) -> Result<SpawnedRNodeInterface, InterfaceError> {
    spawn_ble_rnode_interface_native_with_driver_and_options(
        config,
        id,
        transport_tx,
        tcp_port,
        RNodeStartupOptions::default(),
    )
    .await
    .map_err(RNodeSpawnError::into_legacy_interface_error)
}

/// Spawn an Android native-bridge BLE RNode with an explicit startup policy.
///
/// Kotlin retains exclusive GATT ownership; strict admission runs only across
/// the existing Rust TCP bridge. Because bridge connection is asynchronous,
/// deterministic capability rejection is reported as terminal
/// [`RNodeRuntimeReason::CapabilityAdmissionRejected`] on the returned driver.
/// Response timeout, EOF, and transport I/O retain reconnect behavior.
pub async fn spawn_ble_rnode_interface_native_with_driver_and_options(
    config: BleRNodeConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    tcp_port: u16,
    options: RNodeStartupOptions,
) -> Result<SpawnedRNodeInterface, RNodeSpawnError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    config.validate().map_err(|error| {
        InterfaceError::SendFailed(format!("rnode config {}: {error}", error.field()))
    })?;
    let protocol_target = RNodeProtocolTarget::new(
        config.frequency,
        config.bandwidth,
        config.spreading_factor,
        config.coding_rate,
        config.tx_power,
    );
    let online = Arc::new(AtomicBool::new(false));
    let online_handle = online.clone();
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let task_rxb = shared_rxb.clone();
    let task_txb = shared_txb.clone();
    let (tx, mut outbound_rx) = mpsc::channel::<Bytes>(256);

    let bitrate = rnode::calculate_bitrate(
        config.spreading_factor,
        config.coding_rate,
        config.bandwidth,
    );

    let init_seq_template = build_native_rnode_init_sequence(&config);

    let name = config.name.clone();
    let mode = config.mode;
    let flow_control = config.flow_control;
    let beacon = beacon_from_config(&config);
    let ble_uri = config.ble_uri.clone();
    let log_name = name.clone();
    let running = register_running(id);
    let (snapshot_publisher, driver) = rnode::new_rnode_driver_observation_with_shutdown(
        RNodeTransportClass::Ble,
        RNodeDriverShutdown::from_running_flag(running.clone()),
    );
    let running_task = running.clone();

    let read_task = tokio::spawn(async move {
        let mut snapshot_publisher = snapshot_publisher;
        let mut tries: usize = 0;
        let mut backoff = RECONNECT_WAIT;
        let mut initial_attempt = true;
        let mut pending_outbound: Option<NativePendingOutbound> = None;
        let mut first_tx: Option<tokio::time::Instant> = None;

        struct Cleanup(InterfaceId, Arc<AtomicBool>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                unregister_running(self.0, &self.1);
            }
        }
        let _cleanup = Cleanup(id, running_task.clone());

        loop {
            if !running_task.load(Ordering::SeqCst) {
                ble_diag("[ble-native] read_task exiting — running flag cleared");
                publish_ble_stopped(&mut snapshot_publisher, RNodeRuntimeReason::StopRequested);
                return;
            }
            if initial_attempt {
                initial_attempt = false;
            } else {
                snapshot_publisher.reconnect_started();
            }
            let stream = match tokio::net::TcpStream::connect(format!("127.0.0.1:{tcp_port}")).await
            {
                Ok(s) => s,
                Err(e) => {
                    snapshot_publisher.connection_attempt_failed();
                    tracing::warn!(name = %log_name, tcp_port, error = %e, "TCP bridge connect failed");
                    if reconnect_try_exhausted(&mut tries) {
                        tracing::warn!(name = %log_name, "BLE RNode native: max reconnect tries reached");
                        snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                        return;
                    }
                    if wait_or_shutdown(Duration::from_secs(backoff), &running_task).await {
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                    continue;
                }
            };

            let (mut tcp_read, mut tcp_write) = stream.into_split();
            let mut protocol_state = RNodeProtocolState::new(protocol_target);
            let mut startup_deframer = kiss::RawKissDeframer::new();
            let mut startup_pre_ready_data: Vec<Vec<u8>> = Vec::new();
            let mut startup_pre_ready_data_bytes = 0usize;
            let capability_admission = if options.requires_capability_admission() {
                match run_native_ble_capability_preflight(
                    &mut tcp_read,
                    &mut tcp_write,
                    ble_radio_settings(&config),
                    &running_task,
                    RNODE_BLE_CAPABILITY_PREFLIGHT_TIMEOUT,
                    RNODE_NATIVE_HANDSHAKE_PROBE,
                )
                .await
                {
                    BleCapabilityPreflightOutcome::Admitted {
                        protocol_state: admitted_state,
                        admission,
                    } => {
                        protocol_state = admitted_state;
                        Some(admission)
                    }
                    BleCapabilityPreflightOutcome::Stopped => {
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    BleCapabilityPreflightOutcome::Retry(reason) => {
                        snapshot_publisher.connection_attempt_failed();
                        tracing::warn!(
                            name = %log_name,
                            admission_failure = reason.log_class(),
                            "BLE RNode native capability preflight will retry"
                        );
                        if reconnect_try_exhausted(&mut tries) {
                            snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                            return;
                        }
                        if wait_or_shutdown(Duration::from_secs(backoff), &running_task).await {
                            publish_ble_stopped(
                                &mut snapshot_publisher,
                                RNodeRuntimeReason::StopRequested,
                            );
                            return;
                        }
                        backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                        continue;
                    }
                    BleCapabilityPreflightOutcome::Rejected(error) => {
                        tracing::warn!(
                            name = %log_name,
                            admission_failure = error.log_class(),
                            "BLE RNode native capability admission rejected"
                        );
                        snapshot_publisher.stopped_for_admission_rejection(error.failure_class());
                        return;
                    }
                }
            } else {
                // Preserve native bridge compatibility: either a confirmed
                // detect response or any non-empty firmware response admits
                // the connection in the legacy policy.
                let detected = probe_native_rnode_handshake(
                    &mut tcp_read,
                    &mut tcp_write,
                    RNODE_NATIVE_HANDSHAKE_TIMEOUT,
                    RNODE_NATIVE_HANDSHAKE_PROBE,
                    NativeHandshakeState {
                        protocol_state: &mut protocol_state,
                        deframer: &mut startup_deframer,
                        running_task: &running_task,
                        pre_ready_data: &mut startup_pre_ready_data,
                        pre_ready_data_bytes: &mut startup_pre_ready_data_bytes,
                    },
                )
                .await;
                if !detected {
                    if !running_task.load(Ordering::SeqCst) {
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    snapshot_publisher.connection_attempt_failed();
                    tracing::warn!(
                        name = %log_name,
                        "BLE RNode handshake timed out — RNode did not respond to detect, retrying"
                    );
                    if reconnect_try_exhausted(&mut tries) {
                        tracing::warn!(name = %log_name, "BLE RNode native: max reconnect tries reached");
                        snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                        return;
                    }
                    if wait_or_shutdown(Duration::from_secs(backoff), &running_task).await {
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                    continue;
                }
                None
            };

            if options.requires_capability_admission() && !running_task.load(Ordering::SeqCst) {
                publish_ble_stopped(&mut snapshot_publisher, RNodeRuntimeReason::StopRequested);
                return;
            }

            if options.requires_capability_admission() {
                if !running_task.load(Ordering::SeqCst) {
                    snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                    let _ = tcp_write.write_all(&rnode::build_detach_sequence()).await;
                    let _ = tcp_write.flush().await;
                    snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                    return;
                }

                if tcp_write.write_all(&init_seq_template).await.is_err()
                    || tcp_write.flush().await.is_err()
                {
                    let _ = tcp_write.write_all(&rnode::build_detach_sequence()).await;
                    let _ = tcp_write.flush().await;
                    if !running_task.load(Ordering::SeqCst) {
                        snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                        snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                        return;
                    }
                    snapshot_publisher.connection_attempt_failed();
                    tracing::warn!("BLE RNode native init write failed");
                    if reconnect_try_exhausted(&mut tries) {
                        snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                        return;
                    }
                    if wait_or_shutdown(Duration::from_secs(backoff), &running_task).await {
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                    continue;
                }
            } else {
                // Preserve the native legacy init plus evidence refresh as one
                // write, byte-for-byte.
                if let Err(e) = tcp_write.write_all(&init_seq_template).await {
                    snapshot_publisher.connection_attempt_failed();
                    tracing::warn!(error = %e, "BLE RNode native init/evidence refresh write failed");
                    if reconnect_try_exhausted(&mut tries) {
                        tracing::warn!(name = %log_name, "BLE RNode native: max reconnect tries reached");
                        snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                        return;
                    }
                    if wait_or_shutdown(Duration::from_secs(backoff), &running_task).await {
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                    continue;
                }
            }

            if options.requires_capability_admission() && !running_task.load(Ordering::SeqCst) {
                snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                let _ = tcp_write.write_all(&rnode::build_detach_sequence()).await;
                let _ = tcp_write.flush().await;
                snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                return;
            }

            // Match desktop BLE and serial/TCP: a carrier plus accepted init
            // writes are not public readiness. Hold both `online` and queued
            // application packets until fresh post-init echoes prove the exact
            // configured radio target and RADIO_STATE_ON for this TCP generation.
            enum NativeStartupOutcome {
                Ready,
                Retry(&'static str),
                Stopped,
            }
            let mut startup_buf = [0u8; 4096];
            let mut startup_active_frames: Vec<(u8, Vec<u8>)> = Vec::new();
            let mut startup_active_bytes = 0usize;
            let readiness_deadline = tokio::time::Instant::now() + RNODE_BLE_READINESS_TIMEOUT;
            let startup_outcome = loop {
                if matches!(protocol_state.readiness(), RNodeReadiness::Ready) {
                    break NativeStartupOutcome::Ready;
                }
                tokio::select! {
                    result = tcp_read.read(&mut startup_buf) => match result {
                        Ok(0) => break NativeStartupOutcome::Retry(
                            "native bridge closed before typed Ready",
                        ),
                        Ok(count) => {
                            match reduce_native_startup_bytes(
                                &mut protocol_state,
                                &mut startup_deframer,
                                &startup_buf[..count],
                                &mut startup_pre_ready_data,
                                &mut startup_pre_ready_data_bytes,
                                &mut startup_active_frames,
                                &mut startup_active_bytes,
                            ) {
                                Ok(()) => {}
                                Err(NativeStartupReductionError::MalformedBridgeAck) => {
                                    break NativeStartupOutcome::Retry(
                                        "malformed native bridge acknowledgement",
                                    );
                                }
                                Err(NativeStartupReductionError::ActiveCarryOverflow) => {
                                    break NativeStartupOutcome::Retry(
                                        "post-readiness startup carry exceeded bound",
                                    );
                                }
                                Err(NativeStartupReductionError::PreReadyDataOverflow) => {
                                    break NativeStartupOutcome::Retry(
                                        "pre-readiness native DATA carry exceeded bound",
                                    );
                                }
                            }
                        }
                        Err(_) => break NativeStartupOutcome::Retry(
                            "native bridge read failed before typed Ready",
                        ),
                    },
                    _ = tokio::time::sleep(RUNNING_POLL) => {
                        if !running_task.load(Ordering::SeqCst) {
                            break NativeStartupOutcome::Stopped;
                        }
                    }
                    _ = tokio::time::sleep_until(readiness_deadline) => {
                        break NativeStartupOutcome::Retry("typed readiness timed out");
                    }
                }
            };

            match startup_outcome {
                NativeStartupOutcome::Ready => {}
                NativeStartupOutcome::Stopped => {
                    snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                    let _ = tcp_write.write_all(&rnode::build_detach_sequence()).await;
                    let _ = tcp_write.flush().await;
                    snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                    return;
                }
                NativeStartupOutcome::Retry(reason) => {
                    snapshot_publisher.connection_attempt_failed();
                    tracing::warn!(name = %log_name, reason, "BLE RNode native did not reach Ready");
                    if reconnect_try_exhausted(&mut tries) {
                        snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                        return;
                    }
                    drop(tcp_read);
                    drop(tcp_write);
                    if wait_or_shutdown(Duration::from_secs(backoff), &running_task).await {
                        publish_ble_stopped(
                            &mut snapshot_publisher,
                            RNodeRuntimeReason::StopRequested,
                        );
                        return;
                    }
                    backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                    continue;
                }
            }

            if !running_task.load(Ordering::SeqCst) {
                snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                let _ = tcp_write.write_all(&rnode::build_detach_sequence()).await;
                let _ = tcp_write.flush().await;
                snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                return;
            }

            tracing::info!(
                name = %log_name,
                ble_uri = %ble_uri,
                tcp_port,
                bitrate_bps = bitrate,
                "BLE RNode native typed Ready"
            );

            tries = 0;
            backoff = RECONNECT_WAIT;
            // The protocol state above is already exact Ready. Publish the raw
            // online bit before the driver snapshot so no observer can consume
            // a Ready event while the corresponding interface row remains red.
            online_handle.store(true, Ordering::SeqCst);
            if let Some(admission) = capability_admission {
                snapshot_publisher.capability_connection_established(&protocol_state, admission);
            } else {
                snapshot_publisher.connection_established();
                snapshot_publisher.sync_protocol_state(&protocol_state);
            }

            let ready = AtomicBool::new(true);
            let mut active_packet_admission = ActiveBlePacketAdmission::for_startup_policy(
                options.requires_capability_admission(),
            );
            active_packet_admission.observe_readiness(protocol_state.readiness());
            if let Some(pending) = pending_outbound.as_mut() {
                pending.reset_for_generation();
            }

            // `startup_deframer` begins after init/preflight and reaches Ready
            // only on a complete control frame. Any partial frame remaining at
            // that point therefore began after the exact Ready boundary and
            // belongs to this active TCP generation.
            let mut deframer = startup_deframer;
            let mut last_rssi: Option<f32> = None;
            let mut last_snr: Option<f32> = None;
            let mut buf = [0u8; 4096];
            let mut transport_closed = false;
            let mut bridge_acknowledged = 0u64;

            // Complete frames after the exact Ready boundary are projected
            // before any outbound payload can be selected.
            let startup_ready_frames = startup_pre_ready_data
                .drain(..)
                .map(|frame| (kiss::CMD_DATA, frame))
                .chain(startup_active_frames.drain(..));
            for (command, frame) in startup_ready_frames {
                let data_allowed = project_active_ble_rnode_frame(
                    &snapshot_publisher,
                    &mut protocol_state,
                    &mut active_packet_admission,
                    command,
                    &frame,
                );
                match rnode::process_rnode_response(
                    command,
                    &frame,
                    id,
                    &mut last_rssi,
                    &mut last_snr,
                ) {
                    RNodeResponse::Packet(msg) => {
                        if data_allowed {
                            task_rxb.fetch_add(frame.len() as u64, Ordering::Relaxed);
                            if transport_tx.send(msg).await.is_err() {
                                transport_closed = true;
                                break;
                            }
                        }
                    }
                    RNodeResponse::Ready(is_ready) => {
                        ready.store(is_ready, Ordering::SeqCst);
                    }
                    RNodeResponse::None => {}
                }
            }
            if transport_closed {
                online_handle.store(false, Ordering::SeqCst);
                drop(tcp_read);
                drop(tcp_write);
                publish_ble_stopped(
                    &mut snapshot_publisher,
                    RNodeRuntimeReason::TransportConsumerClosed,
                );
                return;
            }

            enum NativeGenerationEvent {
                Read(std::io::Result<usize>),
                Outbound(Option<Bytes>),
                Poll,
            }

            'read: loop {
                if !online_handle.load(Ordering::SeqCst) {
                    break 'read;
                }
                if !running_task.load(Ordering::SeqCst) {
                    snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                    let _ = tcp_write.write_all(&rnode::build_detach_sequence()).await;
                    let _ = tcp_write.flush().await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    break 'read;
                }

                let event = tokio::select! {
                    result = tcp_read.read(&mut buf) => NativeGenerationEvent::Read(result),
                    outbound = outbound_rx.recv(), if pending_outbound.is_none() => {
                        NativeGenerationEvent::Outbound(outbound)
                    }
                    _ = tokio::time::sleep(RUNNING_POLL) => NativeGenerationEvent::Poll,
                };

                match event {
                    NativeGenerationEvent::Read(Ok(0)) => {
                        tracing::warn!("BLE RNode native bridge closed (EOF)");
                        break 'read;
                    }
                    NativeGenerationEvent::Read(Err(error)) => {
                        tracing::warn!(%error, "BLE RNode native read error");
                        break 'read;
                    }
                    NativeGenerationEvent::Read(Ok(count)) => {
                        for (command, frame) in deframer.feed(&buf[..count]) {
                            if command == RNODE_NATIVE_BRIDGE_ACK_COMMAND {
                                let Some(acknowledged) =
                                    native_bridge_acknowledged_data_frames(command, &frame)
                                else {
                                    tracing::warn!(
                                        "BLE RNode native bridge emitted a malformed acknowledgement"
                                    );
                                    break 'read;
                                };
                                if acknowledged <= bridge_acknowledged {
                                    // Duplicate callbacks are harmless and cannot release a
                                    // later payload because counters are monotonic per socket.
                                    continue;
                                }
                                let expected = pending_outbound
                                    .as_ref()
                                    .and_then(|pending| pending.expected_ack);
                                if expected != Some(acknowledged)
                                    || acknowledged != bridge_acknowledged.saturating_add(1)
                                {
                                    tracing::warn!(
                                        "BLE RNode native bridge acknowledgement was out of sequence"
                                    );
                                    break 'read;
                                }
                                let completed = pending_outbound.take().expect(
                                    "matching bridge acknowledgement requires pending data",
                                );
                                task_txb.fetch_add(
                                    completed.outbound.payload().len() as u64,
                                    Ordering::Relaxed,
                                );
                                if completed.outbound.is_station_id() {
                                    first_tx = None;
                                } else if first_tx.is_none() {
                                    first_tx = Some(tokio::time::Instant::now());
                                }
                                bridge_acknowledged = acknowledged;
                                continue;
                            }

                            let data_allowed = project_active_ble_rnode_frame(
                                &snapshot_publisher,
                                &mut protocol_state,
                                &mut active_packet_admission,
                                command,
                                &frame,
                            );
                            match rnode::process_rnode_response(
                                command,
                                &frame,
                                id,
                                &mut last_rssi,
                                &mut last_snr,
                            ) {
                                RNodeResponse::Packet(msg) => {
                                    if data_allowed {
                                        task_rxb.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                        if transport_tx.send(msg).await.is_err() {
                                            tracing::warn!(id, "transport channel closed");
                                            transport_closed = true;
                                            break 'read;
                                        }
                                    }
                                }
                                RNodeResponse::Ready(is_ready) => {
                                    ready.store(is_ready, Ordering::SeqCst);
                                }
                                RNodeResponse::None => {}
                            }
                        }
                    }
                    NativeGenerationEvent::Outbound(Some(data)) => {
                        pending_outbound = Some(NativePendingOutbound::new(PendingOutbound::new(
                            data, false,
                        )));
                    }
                    NativeGenerationEvent::Outbound(None) => {
                        tracing::warn!(id, "BLE RNode native outbound channel closed");
                        transport_closed = true;
                        break 'read;
                    }
                    NativeGenerationEvent::Poll => {
                        if pending_outbound.as_ref().is_some_and(|pending| {
                            pending.acknowledgement_timed_out(tokio::time::Instant::now())
                        }) {
                            tracing::warn!(
                                "BLE RNode native bridge acknowledgement timed out; retaining payload"
                            );
                            break 'read;
                        }
                        if pending_outbound.is_none() {
                            if let (Some((interval, callsign)), Some(first)) =
                                (beacon.as_ref(), first_tx)
                            {
                                if first.elapsed() >= *interval {
                                    tracing::debug!(
                                        "BLE RNode (native) scheduling station-ID beacon"
                                    );
                                    pending_outbound = Some(NativePendingOutbound::new(
                                        PendingOutbound::new(callsign.clone(), true),
                                    ));
                                }
                            }
                        }
                    }
                }

                let should_write = pending_outbound
                    .as_ref()
                    .is_some_and(|pending| pending.expected_ack.is_none());
                if should_write && claim_ble_packet_permit(flow_control, &ready) {
                    let pending = pending_outbound
                        .as_ref()
                        .expect("native pending outbound checked above");
                    let framed = kiss::frame(pending.outbound.payload());
                    if let Err(error) = tcp_write.write_all(&framed).await {
                        tracing::warn!(%error, "BLE RNode native write error; retaining payload");
                        break 'read;
                    }
                    if let Err(error) = tcp_write.flush().await {
                        tracing::warn!(%error, "BLE RNode native flush error; retaining payload");
                        break 'read;
                    }
                    let expected_ack = bridge_acknowledged.saturating_add(1);
                    pending_outbound
                        .as_mut()
                        .expect("native pending outbound checked above")
                        .expected_ack = Some(expected_ack);
                    pending_outbound
                        .as_mut()
                        .expect("native pending outbound checked above")
                        .sent_at = Some(tokio::time::Instant::now());
                }
            }

            online_handle.store(false, Ordering::SeqCst);
            if let Some(pending) = pending_outbound.as_mut() {
                // TCP completion without the exact bridge ACK is ambiguous.
                // Retain and retry the complete packet on the next generation;
                // Reticulum packet deduplication makes this safer than loss.
                pending.reset_for_generation();
            }
            drop(tcp_read);
            drop(tcp_write);

            if transport_closed {
                publish_ble_stopped(
                    &mut snapshot_publisher,
                    RNodeRuntimeReason::TransportConsumerClosed,
                );
                return;
            }

            if !running_task.load(Ordering::SeqCst) {
                snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                return;
            }

            snapshot_publisher.connection_lost();
            if reconnect_try_exhausted(&mut tries) {
                tracing::warn!(name = %log_name, "BLE RNode native: max reconnect tries reached");
                snapshot_publisher.stopped(RNodeRuntimeReason::DriverTerminated);
                return;
            }
            tracing::info!(name = %log_name, seconds = backoff, "BLE RNode native reconnecting");
            if wait_or_shutdown(ble_reconnect_delay(backoff), &running_task).await {
                publish_ble_stopped(&mut snapshot_publisher, RNodeRuntimeReason::StopRequested);
                return;
            }
            backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
        }
    });

    let interface = InterfaceHandle {
        id,
        parent_id: None,
        name,
        mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: true,
            forward: false,
            repeat: false,
        },
        bitrate,
        mtu: 508,
        online,
        rxb: Some(shared_rxb),
        txb: Some(shared_txb),
        inspection: None,
        tx,
        read_task,
    };

    Ok(SpawnedRNodeInterface { interface, driver })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kiss;
    use crate::rnode;
    use md5::{Digest, Md5};

    fn capability_eeprom(model: u8) -> Vec<u8> {
        let mut bytes = vec![0xFF; 1024];
        bytes[0] = 0x03;
        bytes[1] = model;
        bytes[2..11].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let checksum: [u8; 16] = Md5::digest(&bytes[..11]).into();
        bytes[11..27].copy_from_slice(&checksum);
        bytes[0x9B] = 0x73;
        bytes
    }

    fn unprovisioned_capability_eeprom() -> Vec<u8> {
        let mut bytes = capability_eeprom(0xB8);
        bytes[0x9B] = 0xFF;
        for byte in &mut bytes[11..27] {
            *byte = 0x5A;
        }
        bytes
    }

    fn strict_capability_response_with_eeprom(eeprom: &[u8]) -> Vec<u8> {
        let mut response = kiss::frame_with_command(kiss::CMD_DATA, b"preflight-private");
        response.extend(kiss::frame_with_command(
            rnode::CMD_DETECT,
            &[rnode::DETECT_RESP],
        ));
        response.extend(kiss::frame_with_command(
            rnode::CMD_FW_VERSION,
            &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
        ));
        response.extend(kiss::frame_with_command(rnode::CMD_ROM_READ, eeprom));
        response
    }

    fn strict_capability_response(model: u8) -> Vec<u8> {
        strict_capability_response_with_eeprom(&capability_eeprom(model))
    }

    fn capability_notifications(bytes: &[u8]) -> Vec<ValueNotification> {
        bytes
            .chunks(180)
            .map(|chunk| ValueNotification {
                uuid: NUS_TX_CHAR_UUID,
                value: chunk.to_vec(),
            })
            .collect()
    }

    #[test]
    fn ble_flow_ready_is_a_saturating_one_packet_permit() {
        let ready = AtomicBool::new(true);
        assert!(claim_ble_packet_permit(true, &ready));
        assert!(
            !claim_ble_packet_permit(true, &ready),
            "one positive READY must not release a second packet"
        );

        ready.store(true, Ordering::SeqCst);
        assert!(claim_ble_packet_permit(true, &ready));
        assert!(!ready.load(Ordering::SeqCst));

        assert!(claim_ble_packet_permit(false, &ready));
        assert!(claim_ble_packet_permit(false, &ready));
    }

    #[test]
    fn native_bridge_ack_is_closed_exact_and_generation_local() {
        let wire = [
            kiss::FEND,
            RNODE_NATIVE_BRIDGE_ACK_COMMAND,
            0x52,
            0x53,
            0x42,
            0x41,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            kiss::FEND,
        ];
        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&wire);
        assert_eq!(frames.len(), 1);
        assert_eq!(
            native_bridge_acknowledged_data_frames(frames[0].0, &frames[0].1),
            Some(1),
            "the Android and Rust bridge share one exact wire contract"
        );

        let mut payload = RNODE_NATIVE_BRIDGE_ACK_MAGIC.to_vec();
        payload.extend_from_slice(&7u64.to_be_bytes());
        assert_eq!(
            native_bridge_acknowledged_data_frames(RNODE_NATIVE_BRIDGE_ACK_COMMAND, &payload),
            Some(7)
        );
        assert_eq!(
            native_bridge_acknowledged_data_frames(kiss::CMD_DATA, &payload),
            None,
            "ordinary RNode data can never be interpreted as a bridge ACK"
        );

        let mut wrong_magic = payload.clone();
        wrong_magic[0] ^= 0x01;
        assert_eq!(
            native_bridge_acknowledged_data_frames(RNODE_NATIVE_BRIDGE_ACK_COMMAND, &wrong_magic,),
            None
        );
        assert_eq!(
            native_bridge_acknowledged_data_frames(
                RNODE_NATIVE_BRIDGE_ACK_COMMAND,
                &payload[..payload.len() - 1],
            ),
            None
        );
    }

    #[test]
    fn native_bridge_ack_timeout_exceeds_the_shared_android_write_bound() {
        assert_eq!(RNODE_NATIVE_ACK_WORST_CASE_CHUNKS, 51);
        let write_bound_ms = RNODE_NATIVE_ACK_WORST_CASE_CHUNKS
            * (RNODE_NATIVE_ACK_ENQUEUE_RETRY_MS + RNODE_NATIVE_ACK_CALLBACK_MS)
            + (RNODE_NATIVE_ACK_WORST_CASE_CHUNKS - 1) * RNODE_NATIVE_ACK_PACING_MS;
        assert_eq!(write_bound_ms, 316_800);
        assert_eq!(RNODE_NATIVE_BRIDGE_ACK_TIMEOUT_MS, 318_800);
        assert!(RNODE_NATIVE_BRIDGE_ACK_TIMEOUT_MS > write_bound_ms);
    }

    #[test]
    fn native_startup_holds_pre_ready_data_and_preserves_post_ready_order() {
        let target = RNodeProtocolTarget::new(915_000_000, 125_000, 7, 5, 17);
        let mut state = RNodeProtocolState::new(target);
        for (command, frame) in [
            (rnode::CMD_DETECT, vec![rnode::DETECT_RESP]),
            (
                rnode::CMD_FW_VERSION,
                vec![rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            ),
            (
                rnode::CMD_FREQUENCY,
                target.frequency.to_be_bytes().to_vec(),
            ),
            (
                rnode::CMD_BANDWIDTH,
                target.bandwidth.to_be_bytes().to_vec(),
            ),
            (rnode::CMD_SF, vec![target.spreading_factor]),
            (rnode::CMD_CR, vec![target.coding_rate]),
            (rnode::CMD_TXPOWER, vec![target.tx_power]),
        ] {
            state.apply_frame(command, &frame);
        }
        assert!(!matches!(state.readiness(), RNodeReadiness::Ready));

        let held = b"pre-ready";
        let retained = b"post-ready";
        let mut same_read = kiss::frame(held);
        same_read.extend(kiss::frame_with_command(
            rnode::CMD_RADIO_STATE,
            &[rnode::RADIO_STATE_ON],
        ));
        same_read.extend(kiss::frame(retained));
        let mut deframer = kiss::RawKissDeframer::new();
        let mut pre_ready_data = Vec::new();
        let mut pre_ready_data_bytes = 0;
        let mut active_frames = Vec::new();
        let mut active_bytes = 0;
        assert_eq!(
            reduce_native_startup_bytes(
                &mut state,
                &mut deframer,
                &same_read,
                &mut pre_ready_data,
                &mut pre_ready_data_bytes,
                &mut active_frames,
                &mut active_bytes,
            ),
            Ok(())
        );
        assert_eq!(state.readiness(), RNodeReadiness::Ready);
        assert_eq!(pre_ready_data, vec![held.to_vec()]);
        assert_eq!(pre_ready_data_bytes, held.len());
        assert_eq!(active_frames, vec![(kiss::CMD_DATA, retained.to_vec())]);
        assert_eq!(active_bytes, retained.len() + 1);
    }

    #[test]
    fn native_startup_carries_partial_data_begun_after_ready_into_active_read() {
        let target = RNodeProtocolTarget::new(915_000_000, 125_000, 7, 5, 17);
        let mut state = RNodeProtocolState::new(target);
        for (command, frame) in [
            (rnode::CMD_DETECT, vec![rnode::DETECT_RESP]),
            (
                rnode::CMD_FW_VERSION,
                vec![rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            ),
            (
                rnode::CMD_FREQUENCY,
                target.frequency.to_be_bytes().to_vec(),
            ),
            (
                rnode::CMD_BANDWIDTH,
                target.bandwidth.to_be_bytes().to_vec(),
            ),
            (rnode::CMD_SF, vec![target.spreading_factor]),
            (rnode::CMD_CR, vec![target.coding_rate]),
            (rnode::CMD_TXPOWER, vec![target.tx_power]),
        ] {
            state.apply_frame(command, &frame);
        }

        let retained = b"post-ready-split-across-reads";
        let framed = kiss::frame(retained);
        let split = framed.len() / 2;
        let mut first_read =
            kiss::frame_with_command(rnode::CMD_RADIO_STATE, &[rnode::RADIO_STATE_ON]);
        first_read.extend_from_slice(&framed[..split]);

        let mut startup_deframer = kiss::RawKissDeframer::new();
        let mut pre_ready_data = Vec::new();
        let mut pre_ready_data_bytes = 0;
        let mut active_frames = Vec::new();
        let mut active_bytes = 0;
        assert_eq!(
            reduce_native_startup_bytes(
                &mut state,
                &mut startup_deframer,
                &first_read,
                &mut pre_ready_data,
                &mut pre_ready_data_bytes,
                &mut active_frames,
                &mut active_bytes,
            ),
            Ok(())
        );
        assert_eq!(state.readiness(), RNodeReadiness::Ready);
        assert!(pre_ready_data.is_empty());
        assert!(active_frames.is_empty());

        let mut active_deframer = startup_deframer;
        assert_eq!(
            active_deframer.feed(&framed[split..]),
            vec![(kiss::CMD_DATA, retained.to_vec())]
        );
        assert!(active_deframer.feed(&[]).is_empty());
    }

    #[test]
    fn native_startup_pre_ready_data_bound_exceeds_rnode_receive_buffer_and_fails_explicitly() {
        let target = RNodeProtocolTarget::new(915_000_000, 125_000, 7, 5, 17);
        let mut state = RNodeProtocolState::new(target);
        let mut deframer = kiss::RawKissDeframer::new();
        let mut pre_ready_data = Vec::new();
        let mut pre_ready_data_bytes = 0;
        let mut active_frames = Vec::new();
        let mut active_bytes = 0;
        let record = vec![0x41; RNODE_NATIVE_MAX_PACKET];

        for _ in 0..129 {
            assert_eq!(
                reduce_native_startup_bytes(
                    &mut state,
                    &mut deframer,
                    &kiss::frame(&record),
                    &mut pre_ready_data,
                    &mut pre_ready_data_bytes,
                    &mut active_frames,
                    &mut active_bytes,
                ),
                Ok(())
            );
        }
        assert!(pre_ready_data_bytes > 6_144);
        assert!(pre_ready_data_bytes <= RNODE_NATIVE_STARTUP_PRE_READY_DATA_MAX_BYTES);
        assert_eq!(
            reduce_native_startup_bytes(
                &mut state,
                &mut deframer,
                &kiss::frame(&record),
                &mut pre_ready_data,
                &mut pre_ready_data_bytes,
                &mut active_frames,
                &mut active_bytes,
            ),
            Err(NativeStartupReductionError::PreReadyDataOverflow)
        );
    }

    #[test]
    fn native_pending_payload_survives_generation_reset_without_old_ack_state() {
        let payload = Bytes::from_static(b"retain-across-generation");
        let mut pending = NativePendingOutbound::new(PendingOutbound::new(payload.clone(), false));
        pending.expected_ack = Some(9);
        pending.sent_at = Some(tokio::time::Instant::now());

        pending.reset_for_generation();

        assert_eq!(pending.outbound.payload(), &payload);
        assert_eq!(pending.expected_ack, None);
        assert_eq!(pending.sent_at, None);
    }

    #[test]
    fn ble_reconnect_jitter_stays_within_twenty_percent() {
        assert_eq!(reconnect_delay_with_jitter(1, 0), Duration::from_secs(1));
        assert!(reconnect_delay_with_jitter(1, u64::MAX) <= Duration::from_millis(1_200));
        assert!(reconnect_delay_with_jitter(30, u64::MAX) <= Duration::from_secs(36));
    }

    #[test]
    fn adapter_power_recovery_wakes_only_after_observed_off_state() {
        let mut saw_powered_off = false;
        assert!(!adapter_power_transition_wakes(
            &mut saw_powered_off,
            CentralState::PoweredOn,
        ));
        assert!(!adapter_power_transition_wakes(
            &mut saw_powered_off,
            CentralState::Unknown,
        ));
        assert!(!adapter_power_transition_wakes(
            &mut saw_powered_off,
            CentralState::PoweredOff,
        ));
        assert!(saw_powered_off);
        assert!(adapter_power_transition_wakes(
            &mut saw_powered_off,
            CentralState::PoweredOn,
        ));
    }

    #[test]
    fn ble_write_chunk_size_matches_platform_transport_guarantee() {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            assert_eq!(ble_write_chunk_size(), BLE_DEFAULT_ATT_WRITE_PAYLOAD);
            assert!(matches!(ble_write_type(), WriteType::WithResponse));
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            assert_eq!(ble_write_chunk_size(), BLE_RNODE_ATT_WRITE_PAYLOAD);
            assert!(matches!(ble_write_type(), WriteType::WithoutResponse));
        }
    }

    #[test]
    fn ble_init_stages_fit_the_apple_baseline_and_never_turn_radio_off() {
        let stages = build_ble_rnode_init_stages(&BleRNodeConfig::new("ble0", "ble://RNode"));
        assert!(
            stages
                .iter()
                .all(|stage| stage.len() <= BLE_DEFAULT_ATT_WRITE_PAYLOAD)
        );
        let mut deframer = kiss::RawKissDeframer::new();
        let frames: Vec<_> = stages
            .iter()
            .flat_map(|stage| deframer.feed(stage))
            .collect();
        assert!(frames.iter().all(|(command, payload)| {
            *command != rnode::CMD_RADIO_STATE || payload.as_slice() != [rnode::RADIO_STATE_OFF]
        }));
    }

    #[test]
    fn fresh_bond_disconnect_uses_fast_pairing_transition_retry() {
        let transition = InterfaceError::SendFailed(
            "BLE pairing in progress: RNode completed fresh bond and disconnected; reconnecting"
                .into(),
        );
        assert!(is_pairing_transition_error(&transition));

        let ordinary_disconnect =
            InterfaceError::SendFailed("BLE connect failed: device disconnected".into());
        assert!(!is_pairing_transition_error(&ordinary_disconnect));
    }

    #[test]
    fn apple_pairing_trigger_follows_discovered_tx_properties() {
        let esp_tx = CharPropFlags::READ | CharPropFlags::NOTIFY;
        assert_eq!(
            desktop_pairing_trigger_for_properties(esp_tx, true),
            DesktopPairingTrigger::EncryptedRead,
            "Apple must retain the reviewed encrypted-read trigger for ESP TX"
        );

        let nrf_tx = CharPropFlags::NOTIFY;
        assert_eq!(
            desktop_pairing_trigger_for_properties(nrf_tx, true),
            DesktopPairingTrigger::SecuredSubscribe,
            "Apple must authenticate a Bluefruit notify-only TX through its CCCD"
        );
        assert_eq!(
            desktop_pairing_trigger_for_properties(nrf_tx, false),
            DesktopPairingTrigger::EncryptedRead,
            "Android and Windows retain their existing encrypted-read behavior"
        );
    }

    #[test]
    fn corebluetooth_uuid_primary_uses_verified_name_for_post_bond_resolution() {
        let configured_uuid = "64F6A7A3-7349-4D15-92B7-AEAE9D2A0E61";
        let verified_name = "RNode 0544";

        assert_eq!(
            ble_name_resolution_class(configured_uuid, None, verified_name),
            None,
            "an unverified name must not replace the configured UUID"
        );
        assert_eq!(
            ble_name_resolution_class(configured_uuid, Some(verified_name), verified_name),
            Some(BleTargetResolutionClass::GenerationStableName),
            "the first exact RNode name must survive a post-bond CB handle replacement"
        );
        assert_eq!(
            ble_name_resolution_class(configured_uuid, Some(verified_name), "RNode 9999"),
            None,
            "a different advertised RNode name must not satisfy the fallback"
        );
    }

    #[test]
    fn apple_nrf_fresh_bond_disconnect_retries_without_invalid_read_and_reaches_ready() {
        let nrf_tx = CharPropFlags::NOTIFY;

        // Generation one authenticates through the secured CCCD. Official nRF
        // RNode firmware then disconnects intentionally after storing the bond.
        assert_eq!(
            desktop_pairing_trigger_for_properties(nrf_tx, true),
            DesktopPairingTrigger::SecuredSubscribe
        );
        let mut generations = BleGenerationId::default();
        let first_generation = generations.next();
        let transition = map_subscribe_generation_error(
            first_generation,
            BleGenerationExit::TargetDisconnected {
                stage: BleOperationStage::PairingSubscribe,
            },
        );
        assert!(is_pairing_transition_error(&transition));
        assert_eq!(
            BleOperationStage::PairingSubscribe.deadline(),
            Duration::from_secs(60),
            "the secured CCCD trigger must leave time for human PIN entry"
        );
        assert_eq!(
            BleOperationStage::Subscribe.deadline(),
            Duration::from_secs(10),
            "ordinary notification subscription retains its bounded deadline"
        );

        let immediate_auth_error = map_subscribe_generation_error(
            first_generation,
            BleGenerationExit::StageFailed {
                stage: BleOperationStage::PairingSubscribe,
                reason: "redacted platform error".into(),
            },
        );
        assert!(is_pairing_transition_error(&immediate_auth_error));

        // The outer owner re-resolves a fresh peripheral for generation two.
        // Its GATT contract still selects subscribe directly; after the stored
        // bond admits that CCCD write, normal protocol evidence reaches Ready.
        assert_eq!(
            desktop_pairing_trigger_for_properties(nrf_tx, true),
            DesktopPairingTrigger::SecuredSubscribe
        );
        let second_generation = generations.next();
        assert_ne!(first_generation, second_generation);
        let target = RNodeProtocolTarget::new(915_000_000, 250_000, 9, 5, 17);
        let mut protocol_state = RNodeProtocolState::new(target);
        for (command, frame) in [
            (rnode::CMD_DETECT, vec![rnode::DETECT_RESP]),
            (
                rnode::CMD_FW_VERSION,
                vec![rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            ),
            (
                rnode::CMD_FREQUENCY,
                target.frequency.to_be_bytes().to_vec(),
            ),
            (
                rnode::CMD_BANDWIDTH,
                target.bandwidth.to_be_bytes().to_vec(),
            ),
            (rnode::CMD_SF, vec![target.spreading_factor]),
            (rnode::CMD_CR, vec![target.coding_rate]),
            (rnode::CMD_TXPOWER, vec![target.tx_power]),
            (rnode::CMD_RADIO_STATE, vec![rnode::RADIO_STATE_ON]),
        ] {
            protocol_state.apply_frame(command, &frame);
        }
        assert_eq!(protocol_state.readiness(), RNodeReadiness::Ready);
    }

    #[test]
    fn active_packet_admission_latches_for_one_physical_generation() {
        let mut startup = ActiveBlePacketAdmission::for_startup_policy(true);
        assert!(!startup.allows_packet());

        startup.observe_readiness(RNodeReadiness::Ready);
        assert!(startup.allows_packet());

        startup.observe_readiness(RNodeReadiness::Blocked(
            crate::rnode_protocol::RNodeReadinessBlocker::Missing(
                crate::rnode_protocol::RNodeReadinessEvidence::Frequency,
            ),
        ));
        assert!(
            startup.allows_packet(),
            "later evidence regression must not discard active-session packets"
        );

        let legacy = ActiveBlePacketAdmission::for_startup_policy(false);
        assert!(legacy.allows_packet());

        // A reconnect never inherits the prior generation's active boundary.
        let reconnect = ActiveBlePacketAdmission::for_startup_policy(true);
        assert!(!reconnect.allows_packet());
    }

    #[test]
    fn test_ble_rnode_config_defaults() {
        let cfg = BleRNodeConfig::new("ble-rnode", "ble://RNode 3B87");
        assert_eq!(cfg.name, "ble-rnode");
        assert_eq!(cfg.ble_uri, "ble://RNode 3B87");
        assert_eq!(cfg.frequency, 868_000_000);
        assert_eq!(cfg.bandwidth, 125_000);
        assert_eq!(cfg.spreading_factor, 7);
        assert_eq!(cfg.coding_rate, 5);
        assert_eq!(cfg.tx_power, 14);
        assert!(
            !cfg.flow_control,
            "flow_control defaults off (Python parity)"
        );
        assert!(cfg.st_alock.is_none());
        assert!(cfg.lt_alock.is_none());
    }

    #[test]
    fn test_ble_rnode_config_custom_params() {
        let mut cfg = BleRNodeConfig::new("custom", "ble://F4:12:73:29:4E:89");
        cfg.frequency = 915_000_000;
        cfg.bandwidth = 250_000;
        cfg.spreading_factor = 12;
        cfg.coding_rate = 8;
        cfg.tx_power = 22;
        cfg.mode = InterfaceMode::AccessPoint;
        cfg.flow_control = false;
        cfg.st_alock = Some(50.0);
        cfg.lt_alock = Some(75.0);

        assert_eq!(cfg.frequency, 915_000_000);
        assert_eq!(cfg.bandwidth, 250_000);
        assert_eq!(cfg.spreading_factor, 12);
        assert_eq!(cfg.coding_rate, 8);
        assert_eq!(cfg.tx_power, 22);
        assert_eq!(cfg.mode, InterfaceMode::AccessPoint);
        assert!(!cfg.flow_control);
        assert_eq!(cfg.st_alock, Some(50.0));
        assert_eq!(cfg.lt_alock, Some(75.0));
    }

    #[test]
    fn ble_rnode_config_uses_canonical_rf_and_airtime_validation() {
        let mut cfg = BleRNodeConfig::new("validated", "ble://RNode");
        assert!(cfg.validate().is_ok());

        cfg.frequency = 0;
        assert!(matches!(
            cfg.validate(),
            Err(rnode::RNodeConfigValidationError::OutOfRange {
                field: rnode::RNodeConfigField::Frequency,
                ..
            })
        ));

        cfg = BleRNodeConfig::new("validated", "ble://RNode");
        cfg.st_alock = Some(f32::NAN);
        assert!(matches!(
            cfg.validate(),
            Err(rnode::RNodeConfigValidationError::NonFinite {
                field: rnode::RNodeConfigField::ShortTermAirtime,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn ble_rnode_spawns_reject_invalid_config_before_running_registration() {
        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(1);
        for (id, native) in [(0xB1E0_0001, false), (0xB1E0_0002, true)] {
            let mut cfg = BleRNodeConfig::new("invalid", "ble://RNode");
            cfg.tx_power = u8::MAX;
            let result = if native {
                spawn_ble_rnode_interface_native_with_driver(cfg, id, transport_tx.clone(), 1).await
            } else {
                spawn_ble_rnode_interface_with_driver(cfg, id, transport_tx.clone()).await
            };
            assert!(matches!(result, Err(InterfaceError::SendFailed(_))));
            assert!(
                !running_map()
                    .lock()
                    .expect("running map mutex poisoned")
                    .contains_key(&id),
                "invalid config must not create a running-map entry"
            );
        }
    }

    #[test]
    fn test_ble_rnode_config_empty_uri() {
        let cfg = BleRNodeConfig::new("any-rnode", "ble://");
        assert_eq!(cfg.ble_uri, "ble://");
    }

    #[test]
    fn test_ble_rnode_config_address_uri() {
        let cfg = BleRNodeConfig::new("addr-rnode", "ble://F4:12:73:29:4E:89");
        assert_eq!(cfg.ble_uri, "ble://F4:12:73:29:4E:89");
    }

    #[test]
    fn test_ble_rnode_config_name_uri() {
        let cfg = BleRNodeConfig::new("named-rnode", "ble://RNode 3B87");
        assert_eq!(cfg.ble_uri, "ble://RNode 3B87");
    }

    #[test]
    fn test_nus_uuids() {
        assert_eq!(
            NUS_SERVICE_UUID.to_string().to_uppercase(),
            "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
        );
        assert_eq!(
            NUS_RX_CHAR_UUID.to_string().to_uppercase(),
            "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
        );
        assert_eq!(
            NUS_TX_CHAR_UUID.to_string().to_uppercase(),
            "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"
        );
    }

    #[test]
    fn test_nus_service_uuid_distinct() {
        assert_ne!(NUS_SERVICE_UUID, NUS_RX_CHAR_UUID);
        assert_ne!(NUS_SERVICE_UUID, NUS_TX_CHAR_UUID);
        assert_ne!(NUS_RX_CHAR_UUID, NUS_TX_CHAR_UUID);
    }

    // ── Shutdown / running-flag tests ──

    #[test]
    fn test_register_unregister_running() {
        let id: InterfaceId = 0xDEAD_BEEF_0000_0001;
        assert!(!is_registered(id));
        let flag = register_running(id);
        assert!(is_registered(id));
        assert!(flag.load(Ordering::SeqCst));
        unregister_running(id, &flag);
        assert!(!is_registered(id));
    }

    #[test]
    fn test_stop_ble_rnode_interface_sets_flag() {
        let id: InterfaceId = 0xDEAD_BEEF_0000_0002;
        let flag = register_running(id);
        assert!(flag.load(Ordering::SeqCst));
        stop_ble_rnode_interface(id);
        assert!(!flag.load(Ordering::SeqCst));
        // Map entry survives until the owning task's Drop runs; clean up.
        unregister_running(id, &flag);
    }

    #[test]
    fn test_stop_ble_rnode_interface_unknown_id_is_noop() {
        let id: InterfaceId = 0xDEAD_BEEF_0000_0003;
        assert!(!is_registered(id));
        stop_ble_rnode_interface(id);
        assert!(!is_registered(id));
    }

    #[test]
    fn test_ble_exact_shutdown_and_cleanup_resist_same_id_aba() {
        let id: InterfaceId = 0xDEAD_BEEF_0000_0004;
        let old_running = register_running(id);
        let (_old_publisher, old_driver) = rnode::new_rnode_driver_observation_with_shutdown(
            RNodeTransportClass::Ble,
            RNodeDriverShutdown::from_running_flag(old_running.clone()),
        );

        let new_running = register_running(id);
        let (_new_publisher, _new_driver) = rnode::new_rnode_driver_observation_with_shutdown(
            RNodeTransportClass::Ble,
            RNodeDriverShutdown::from_running_flag(new_running.clone()),
        );

        unregister_running(id, &old_running);
        assert!(
            is_registered(id),
            "retired task cleanup must preserve the newer compatibility entry"
        );
        old_driver.request_shutdown();
        assert!(!old_running.load(Ordering::SeqCst));
        assert!(
            new_running.load(Ordering::SeqCst),
            "the retired handle must not stop the newer same-ID BLE driver"
        );

        stop_ble_rnode_interface(id);
        assert!(
            !new_running.load(Ordering::SeqCst),
            "the compatibility facade must still stop the current registration"
        );
        unregister_running(id, &new_running);
    }

    #[tokio::test]
    async fn test_wait_or_shutdown_returns_false_when_flag_stays_set() {
        // Short real-time wait; flag stays true → full duration elapses.
        let flag = AtomicBool::new(true);
        let started = std::time::Instant::now();
        let cleared = wait_or_shutdown(Duration::from_millis(120), &flag).await;
        assert!(!cleared, "should return false when flag stayed set");
        assert!(
            started.elapsed() >= Duration::from_millis(100),
            "should have waited roughly the full deadline"
        );
    }

    #[tokio::test]
    async fn test_wait_or_shutdown_returns_true_when_flag_already_cleared() {
        // Fast path: flag is false on entry, helper should return true
        // without consuming the full deadline.
        let flag = AtomicBool::new(false);
        let started = std::time::Instant::now();
        let cleared = wait_or_shutdown(Duration::from_secs(5), &flag).await;
        assert!(cleared, "should return true immediately when flag is clear");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "should not have waited the full deadline"
        );
    }

    #[tokio::test]
    async fn test_wait_or_shutdown_returns_true_when_flag_cleared_mid_wait() {
        // Background task clears the flag partway through; helper wakes
        // at its next RUNNING_POLL tick (≤ 1 s) and bails before the
        // 3 s overall deadline.
        let flag = Arc::new(AtomicBool::new(true));
        let flag_bg = flag.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            flag_bg.store(false, Ordering::SeqCst);
        });
        let started = std::time::Instant::now();
        let cleared = wait_or_shutdown(Duration::from_secs(3), &flag).await;
        assert!(cleared, "should return true once flag cleared during wait");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "should have woken at next poll tick, not slept the full deadline"
        );
    }

    // ── Device type tests ──

    #[test]
    fn test_device_type_rnode_serialization() {
        let dev = BleDevice {
            name: "RNode 3B87".into(),
            address: "F4:12:73:29:4E:89".into(),
            rssi: Some(-65),
            device_type: BleDeviceType::RNode,
            bonded: false,
        };
        let json = serde_json::to_string(&dev).unwrap();
        assert!(json.contains("\"device_type\":\"rnode\""));
        assert!(json.contains("\"rssi\":-65"));
        assert!(json.contains("\"bonded\":false"));
    }

    #[test]
    fn test_device_type_unknown_serialization() {
        let dev = BleDevice {
            name: "Unknown Device".into(),
            address: "11:22:33:44:55:66".into(),
            rssi: None,
            device_type: BleDeviceType::Unknown,
            bonded: false,
        };
        let json = serde_json::to_string(&dev).unwrap();
        assert!(json.contains("\"device_type\":\"unknown\""));
    }

    #[test]
    fn test_device_type_equality() {
        assert_eq!(BleDeviceType::RNode, BleDeviceType::RNode);
        assert_eq!(BleDeviceType::Unknown, BleDeviceType::Unknown);
        assert_ne!(BleDeviceType::RNode, BleDeviceType::Unknown);
    }

    #[test]
    fn test_ble_device_no_rssi() {
        let dev = BleDevice {
            name: "RNode 1234".into(),
            address: "AA:BB:CC:DD:EE:FF".into(),
            rssi: None,
            device_type: BleDeviceType::RNode,
            bonded: false,
        };
        let json = serde_json::to_string(&dev).unwrap();
        assert!(json.contains("\"rssi\":null"));
    }

    #[test]
    fn test_ble_device_full_roundtrip() {
        let dev = BleDevice {
            name: "RNode 3B87".into(),
            address: "F4:12:73:29:4E:89".into(),
            rssi: Some(-42),
            device_type: BleDeviceType::RNode,
            bonded: false,
        };
        let json = serde_json::to_string(&dev).unwrap();
        let deserialized: BleDevice = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "RNode 3B87");
        assert_eq!(deserialized.address, "F4:12:73:29:4E:89");
        assert_eq!(deserialized.rssi, Some(-42));
        assert_eq!(deserialized.device_type, BleDeviceType::RNode);
        assert!(!deserialized.bonded);
    }

    // ── KISS framing over BLE ──

    #[test]
    fn test_kiss_frame_fits_single_ble_chunk() {
        let payload = vec![0x42; 100];
        let framed = kiss::frame(&payload);
        assert!(framed.len() <= 512);
        let chunks: Vec<&[u8]> = framed.chunks(512).collect();
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn test_kiss_frame_requires_chunking() {
        let payload = vec![0x42; 500];
        let framed = kiss::frame(&payload);
        assert_eq!(framed.len(), 503); // 500 + FEND + CMD + FEND
        let chunks: Vec<&[u8]> = framed.chunks(256).collect();
        assert_eq!(chunks.len(), 2);
    }

    #[test]
    fn test_kiss_frame_with_many_special_bytes() {
        // All FEND bytes → each doubles due to escaping
        let payload = vec![kiss::FEND; 100];
        let framed = kiss::frame(&payload);
        assert_eq!(framed.len(), 200 + 3); // 2 bytes per FEND + overhead
    }

    #[test]
    fn test_kiss_deframe_from_ble_notification_chunks() {
        let payload = b"hello from rnode over ble";
        let framed = kiss::frame(payload);

        let mut deframer = kiss::RawKissDeframer::new();
        let mut frames_received = Vec::new();
        for chunk in framed.chunks(10) {
            frames_received.extend(deframer.feed(chunk));
        }
        assert_eq!(frames_received.len(), 1);
        assert_eq!(frames_received[0].0, kiss::CMD_DATA);
        assert_eq!(frames_received[0].1, payload);
    }

    #[test]
    fn test_kiss_deframe_multiple_frames_in_one_notification() {
        let f1 = kiss::frame(b"first");
        let f2 = kiss::frame(b"second");
        let mut combined = f1;
        combined.extend_from_slice(&f2);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&combined);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].1, b"first");
        assert_eq!(frames[1].1, b"second");
    }

    #[test]
    fn test_kiss_deframe_split_across_notifications() {
        let framed = kiss::frame(b"split test data");
        let mid = framed.len() / 2;

        let mut deframer = kiss::RawKissDeframer::new();
        let first = deframer.feed(&framed[..mid]);
        assert!(first.is_empty());

        let second = deframer.feed(&framed[mid..]);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].1, b"split test data");
    }

    // ── Init sequence tests ──

    fn frame_command_count(frames: &[(u8, Vec<u8>)], command: u8) -> usize {
        frames.iter().filter(|(cmd, _)| *cmd == command).count()
    }

    #[test]
    fn test_ble_init_sequence_uses_rnode_helpers() {
        let ble_cfg = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let rnode_cfg = rnode_config_from_ble_config(&ble_cfg);
        let seq = build_ble_rnode_init_sequence(&ble_cfg);
        assert!(!seq.is_empty());
        assert_eq!(
            seq,
            rnode::build_ble_radio_reassertion_stages(&rnode_cfg).concat()
        );

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(frames.len(), 6);
        assert_eq!(
            frames[0],
            (
                rnode::CMD_FREQUENCY,
                ble_cfg.frequency.to_be_bytes().to_vec()
            )
        );
        assert_eq!(
            frames.last().unwrap(),
            &(rnode::CMD_RADIO_STATE, vec![rnode::RADIO_STATE_ON])
        );
    }

    #[test]
    fn test_ble_detect_sequence_parseable() {
        let seq = rnode::build_detect_sequence();
        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(frames.len(), 4);
    }

    #[test]
    fn test_ble_full_init_with_airtime() {
        let mut cfg = BleRNodeConfig::new("test", "ble://");
        cfg.st_alock = Some(25.0);
        cfg.lt_alock = Some(50.0);
        // Airtime locks are part of the init sequence, before RADIO_STATE_ON.
        let seq = build_ble_rnode_init_sequence(&cfg);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(frames.len(), 8);
        assert_eq!(
            frames[0],
            (rnode::CMD_FREQUENCY, cfg.frequency.to_be_bytes().to_vec())
        );
        assert_eq!(
            frames.last().unwrap(),
            &(rnode::CMD_RADIO_STATE, vec![rnode::RADIO_STATE_ON])
        );
        assert_eq!(frame_command_count(&frames, rnode::CMD_ST_ALOCK), 1);
        assert_eq!(frame_command_count(&frames, rnode::CMD_LT_ALOCK), 1);
        let radio_on = frames.len() - 1;
        let st = frames
            .iter()
            .position(|(cmd, _)| *cmd == rnode::CMD_ST_ALOCK)
            .expect("CMD_ST_ALOCK present");
        let lt = frames
            .iter()
            .position(|(cmd, _)| *cmd == rnode::CMD_LT_ALOCK)
            .expect("CMD_LT_ALOCK present");
        assert!(st < radio_on);
        assert!(lt < radio_on);
    }

    #[test]
    fn test_desktop_ble_observation_tracks_attempts_and_fresh_generations() {
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let target = RNodeProtocolTarget::new(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );
        let (mut publisher, driver) = rnode::new_rnode_driver_observation(RNodeTransportClass::Ble);

        let initial = driver.snapshot();
        assert_eq!(initial.transport, RNodeTransportClass::Ble);
        assert_eq!(initial.phase, rnode::RNodeRuntimePhase::Connecting);
        assert_eq!(initial.connection_generation, 0);

        publisher.connection_attempt_failed();
        let failed = driver.snapshot();
        assert_eq!(failed.phase, rnode::RNodeRuntimePhase::ReconnectBackoff);
        assert_eq!(
            failed.reason,
            Some(RNodeRuntimeReason::ConnectionAttemptFailed)
        );

        publisher.reconnect_started();
        assert_eq!(driver.snapshot().reconnect_attempt, 1);
        publisher.connection_established();

        let mut first_generation = RNodeProtocolState::new(target);
        for (command, frame) in [
            (rnode::CMD_DETECT, vec![rnode::DETECT_RESP]),
            (
                rnode::CMD_FW_VERSION,
                vec![rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            ),
            (
                rnode::CMD_FREQUENCY,
                target.frequency.to_be_bytes().to_vec(),
            ),
            (
                rnode::CMD_BANDWIDTH,
                target.bandwidth.to_be_bytes().to_vec(),
            ),
            (rnode::CMD_SF, vec![target.spreading_factor]),
            (rnode::CMD_CR, vec![target.coding_rate]),
            (rnode::CMD_TXPOWER, vec![target.tx_power]),
            (rnode::CMD_RADIO_STATE, vec![rnode::RADIO_STATE_ON]),
        ] {
            project_ble_rnode_frame(&publisher, &mut first_generation, command, &frame);
        }

        let ready = driver.snapshot();
        assert_eq!(ready.connection_generation, 1);
        assert_eq!(ready.phase, rnode::RNodeRuntimePhase::Ready);
        assert_eq!(
            ready.configuration,
            rnode::RNodeConfigurationState::Verified
        );

        publisher.connection_lost();
        let lost = driver.snapshot();
        assert_eq!(lost.phase, rnode::RNodeRuntimePhase::ReconnectBackoff);
        assert_eq!(lost.connection_generation, 0);
        assert_eq!(lost.disconnect_total, 1);
        assert_eq!(lost.detection, rnode::RNodeDetectionState::Unknown);

        publisher.reconnect_started();
        publisher.connection_established();
        let mut second_generation = RNodeProtocolState::new(target);
        project_ble_rnode_frame(&publisher, &mut second_generation, rnode::CMD_READY, &[1]);

        let second = driver.snapshot();
        assert_eq!(second.connection_generation, 2);
        assert_eq!(second.phase, rnode::RNodeRuntimePhase::AwaitingReadiness);
        assert_eq!(second.detection, rnode::RNodeDetectionState::Unknown);
        assert_eq!(
            second.transmit_flow,
            rnode::RNodeTransmitFlowState::Permitted
        );

        publish_ble_stopped(&mut publisher, RNodeRuntimeReason::StopRequested);
        let stopped = driver.snapshot();
        assert_eq!(stopped.phase, rnode::RNodeRuntimePhase::Stopped);
        assert_eq!(stopped.reason, Some(RNodeRuntimeReason::StopRequested));
    }

    #[test]
    fn test_desktop_ble_observation_rejects_malformed_startup_evidence() {
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let target = RNodeProtocolTarget::new(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );
        let (mut publisher, driver) = rnode::new_rnode_driver_observation(RNodeTransportClass::Ble);
        publisher.connection_established();
        let mut protocol_state = RNodeProtocolState::new(target);

        let before = driver.snapshot();
        project_ble_rnode_frame(&publisher, &mut protocol_state, rnode::CMD_DETECT, &[]);
        assert!(Arc::ptr_eq(&before, &driver.snapshot()));

        project_ble_rnode_frame(
            &publisher,
            &mut protocol_state,
            rnode::CMD_DETECT,
            &[rnode::DETECT_RESP],
        );
        let detected = driver.snapshot();
        assert_eq!(detected.detection, rnode::RNodeDetectionState::Confirmed);
        assert_eq!(detected.phase, rnode::RNodeRuntimePhase::AwaitingReadiness);

        publisher.stopped(RNodeRuntimeReason::StopRequested);
    }

    #[test]
    fn test_desktop_ble_startup_drain_projects_control_without_legacy_packet_effect() {
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let target = RNodeProtocolTarget::new(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );
        let (mut publisher, driver) = rnode::new_rnode_driver_observation(RNodeTransportClass::Ble);
        publisher.connection_established();
        let mut protocol_state = RNodeProtocolState::new(target);
        let mut deframer = kiss::RawKissDeframer::new();

        let packet = [0x01, 0x02, 0x03];
        let mut startup_bytes = kiss::frame(&packet);
        startup_bytes.extend(kiss::frame_with_command(
            rnode::CMD_DETECT,
            &[rnode::DETECT_RESP],
        ));

        let projection = project_ble_rnode_startup_bytes(
            &publisher,
            &mut protocol_state,
            &mut deframer,
            &startup_bytes,
        );
        assert_eq!(
            projection,
            BleStartupProjection {
                complete_frames: 2,
                legacy_packets_suppressed: 1,
            }
        );
        assert_eq!(
            driver.snapshot().detection,
            rnode::RNodeDetectionState::Confirmed
        );

        // The startup data was packet-shaped and would have entered the
        // legacy forwarding path if the drain had called it.
        let mut rssi = None;
        let mut snr = None;
        assert!(matches!(
            rnode::process_rnode_response(kiss::CMD_DATA, &packet, 7, &mut rssi, &mut snr),
            RNodeResponse::Packet(_)
        ));

        publisher.stopped(RNodeRuntimeReason::StopRequested);
    }

    #[test]
    fn test_desktop_ble_startup_drain_discards_partial_packet_at_active_boundary() {
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let target = RNodeProtocolTarget::new(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );
        let (mut publisher, _) = rnode::new_rnode_driver_observation(RNodeTransportClass::Ble);
        publisher.connection_established();
        let mut protocol_state = RNodeProtocolState::new(target);

        let framed = kiss::frame(&[0x01, 0x02, 0x03]);
        let split = framed.len() - 1;
        let (startup_prefix, active_tail) = framed.split_at(split);

        let mut carried = kiss::RawKissDeframer::new();
        assert!(carried.feed(startup_prefix).is_empty());
        assert_eq!(
            carried.feed(active_tail),
            vec![(kiss::CMD_DATA, vec![0x01, 0x02, 0x03])]
        );

        let mut boundary_deframer = kiss::RawKissDeframer::new();
        let projection = project_ble_rnode_startup_bytes(
            &publisher,
            &mut protocol_state,
            &mut boundary_deframer,
            startup_prefix,
        );
        assert_eq!(projection, BleStartupProjection::default());

        boundary_deframer.reset();
        assert!(boundary_deframer.feed(active_tail).is_empty());

        publisher.stopped(RNodeRuntimeReason::StopRequested);
    }

    #[test]
    fn test_native_ble_handshake_reduces_full_accepted_batch_before_publication() {
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let target = RNodeProtocolTarget::new(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );
        let (mut publisher, driver) = rnode::new_rnode_driver_observation(RNodeTransportClass::Ble);
        let unpublished = driver.snapshot();
        let mut protocol_state = RNodeProtocolState::new(target);
        let mut deframer = kiss::RawKissDeframer::new();

        let mut batch = kiss::frame_with_command(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
        batch.extend(kiss::frame_with_command(
            rnode::CMD_FW_VERSION,
            &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
        ));

        assert!(reduce_native_handshake_bytes(
            &mut protocol_state,
            &mut deframer,
            &batch,
        ));
        let evidence = protocol_state.evidence();
        assert!(evidence.detected);
        assert_eq!(
            evidence.firmware,
            Some(crate::rnode_protocol::RNodeFirmwareVersion::new(
                rnode::REQUIRED_FW_VER_MAJ,
                rnode::REQUIRED_FW_VER_MIN,
            ))
        );
        assert!(
            Arc::ptr_eq(&unpublished, &driver.snapshot()),
            "pending handshake evidence must remain private until generation admission"
        );

        publisher.connection_established();
        assert!(publisher.sync_protocol_state(&protocol_state));
        let admitted = driver.snapshot();
        assert_eq!(admitted.connection_generation, 1);
        assert_eq!(admitted.detection, rnode::RNodeDetectionState::Confirmed);
        assert_eq!(
            admitted.firmware_compatibility,
            rnode::RNodeFirmwareCompatibility::Supported
        );

        publisher.stopped(RNodeRuntimeReason::StopRequested);
    }

    #[test]
    fn test_native_ble_init_reissues_typed_handshake_evidence() {
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let base_init = build_ble_rnode_init_sequence(&config);
        let evidence_refresh = rnode::build_detect_sequence();
        let native_init = build_native_rnode_init_sequence(&config);

        assert_eq!(&native_init[..base_init.len()], base_init.as_slice());
        assert_eq!(&native_init[base_init.len()..], evidence_refresh.as_slice());
    }

    #[test]
    fn ble_init_sequence_uses_no_probe_controls() {
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&build_ble_rnode_init_sequence(&config));

        assert_eq!(
            frames.first(),
            Some(&(
                rnode::CMD_FREQUENCY,
                config.frequency.to_be_bytes().to_vec()
            ))
        );
        assert_eq!(
            frames.last(),
            Some(&(rnode::CMD_RADIO_STATE, vec![rnode::RADIO_STATE_ON]))
        );
        assert!(frames.iter().all(|(command, _)| {
            !matches!(
                *command,
                rnode::CMD_READY | rnode::CMD_STAT_TX | rnode::CMD_ROM_READ
            )
        }));
        assert!(frames.iter().all(|(command, payload)| {
            *command != rnode::CMD_RADIO_STATE || payload.as_slice() != [rnode::RADIO_STATE_OFF]
        }));
    }

    #[test]
    fn test_native_ble_split_control_is_recovered_by_post_init_refresh() {
        let target = RNodeProtocolTarget::new(915_000_000, 125_000, 7, 5, 17);
        let mut protocol_state = RNodeProtocolState::new(target);
        let mut handshake_deframer = kiss::RawKissDeframer::new();

        let firmware = kiss::frame_with_command(
            rnode::CMD_FW_VERSION,
            &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
        );
        let split = firmware.len() - 2;
        let (firmware_prefix, firmware_tail) = firmware.split_at(split);
        let mut accepted_read = kiss::frame_with_command(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
        accepted_read.extend_from_slice(firmware_prefix);

        assert!(reduce_native_handshake_bytes(
            &mut protocol_state,
            &mut handshake_deframer,
            &accepted_read,
        ));
        assert!(
            protocol_state.evidence().firmware.is_none(),
            "the split firmware frame is not complete at admission"
        );

        // Admission drops the handshake deframer. The unread tail cannot
        // complete by itself, but the post-init detect sequence elicits a full
        // replacement response that restores typed evidence.
        drop(handshake_deframer);
        let mut active_bytes = firmware_tail.to_vec();
        active_bytes.extend_from_slice(&firmware);
        let mut active_deframer = kiss::RawKissDeframer::new();
        let active_frames = active_deframer.feed(&active_bytes);
        assert_eq!(
            active_frames,
            vec![(
                rnode::CMD_FW_VERSION,
                vec![rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            )]
        );
        for (command, frame) in active_frames {
            protocol_state.apply_frame(command, &frame);
        }
        assert!(protocol_state.evidence().firmware.is_some());
    }

    #[test]
    fn test_native_ble_split_data_is_discarded_at_active_boundary() {
        let target = RNodeProtocolTarget::new(915_000_000, 125_000, 7, 5, 17);
        let mut protocol_state = RNodeProtocolState::new(target);
        let mut handshake_deframer = kiss::RawKissDeframer::new();
        let partial_packet = kiss::frame(&[0x11, 0x22, 0x33]);
        let split = partial_packet.len() - 2;
        let (packet_prefix, packet_tail) = partial_packet.split_at(split);
        let mut accepted_read = kiss::frame_with_command(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
        accepted_read.extend_from_slice(packet_prefix);

        assert!(reduce_native_handshake_bytes(
            &mut protocol_state,
            &mut handshake_deframer,
            &accepted_read,
        ));

        drop(handshake_deframer);
        let firmware_response = kiss::frame_with_command(
            rnode::CMD_FW_VERSION,
            &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
        );
        let active_packet = vec![0x44, 0x55];
        let mut active_bytes = packet_tail.to_vec();
        active_bytes.extend_from_slice(&firmware_response);
        active_bytes.extend_from_slice(&kiss::frame(&active_packet));

        let mut active_deframer = kiss::RawKissDeframer::new();
        let active_frames = active_deframer.feed(&active_bytes);
        assert_eq!(
            active_frames,
            vec![
                (
                    rnode::CMD_FW_VERSION,
                    vec![rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
                ),
                (kiss::CMD_DATA, active_packet),
            ]
        );
        assert!(
            active_frames
                .iter()
                .all(|(command, frame)| *command != kiss::CMD_DATA
                    || frame.as_slice() != [0x11, 0x22, 0x33]),
            "partial pre-init data must never enter active legacy forwarding"
        );
    }

    #[tokio::test]
    async fn test_native_ble_handshake_probe_accepts_loopback_batch() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind native bridge loopback");
        let address = listener.local_addr().expect("loopback address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept native bridge");
            let mut probe = [0u8; 256];
            let read = stream.read(&mut probe).await.expect("read detect probe");
            assert!(read > 0);

            let mut batch = kiss::frame_with_command(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
            batch.extend(kiss::frame_with_command(
                rnode::CMD_FW_VERSION,
                &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            ));
            stream
                .write_all(&batch)
                .await
                .expect("write handshake response batch");
            probe[..read].to_vec()
        });

        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect native bridge loopback");
        let (mut read, mut write) = stream.into_split();
        let target = RNodeProtocolTarget::new(915_000_000, 125_000, 7, 5, 17);
        let mut protocol_state = RNodeProtocolState::new(target);
        let mut handshake_deframer = kiss::RawKissDeframer::new();
        let running = AtomicBool::new(true);
        let mut pre_ready_data = Vec::new();
        let mut pre_ready_data_bytes = 0;

        assert!(
            probe_native_rnode_handshake(
                &mut read,
                &mut write,
                Duration::from_secs(1),
                Duration::from_millis(100),
                NativeHandshakeState {
                    protocol_state: &mut protocol_state,
                    deframer: &mut handshake_deframer,
                    running_task: &running,
                    pre_ready_data: &mut pre_ready_data,
                    pre_ready_data_bytes: &mut pre_ready_data_bytes,
                },
            )
            .await
        );
        assert!(pre_ready_data.is_empty());
        let legacy_request = server.await.expect("native bridge server task");
        assert_eq!(legacy_request, rnode::build_detect_sequence());
        assert!(
            !RNodeStartupOptions::default().requires_capability_admission(),
            "legacy wrapper must not opt into EEPROM admission"
        );

        let evidence = protocol_state.evidence();
        assert!(evidence.detected);
        assert!(evidence.firmware.is_some());
    }

    fn native_ready_response(config: &BleRNodeConfig) -> Vec<u8> {
        let mut response = kiss::frame_with_command(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
        response.extend(kiss::frame_with_command(
            rnode::CMD_FW_VERSION,
            &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
        ));
        response.extend(kiss::frame_with_command(
            rnode::CMD_FREQUENCY,
            &config.frequency.to_be_bytes(),
        ));
        response.extend(kiss::frame_with_command(
            rnode::CMD_BANDWIDTH,
            &config.bandwidth.to_be_bytes(),
        ));
        response.extend(kiss::frame_with_command(
            rnode::CMD_SF,
            &[config.spreading_factor],
        ));
        response.extend(kiss::frame_with_command(
            rnode::CMD_CR,
            &[config.coding_rate],
        ));
        response.extend(kiss::frame_with_command(
            rnode::CMD_TXPOWER,
            &[config.tx_power],
        ));
        response.extend(kiss::frame_with_command(
            rnode::CMD_RADIO_STATE,
            &[rnode::RADIO_STATE_ON],
        ));
        response
    }

    async fn native_test_read_through_command(
        stream: &mut tokio::net::TcpStream,
        terminal_command: u8,
    ) -> Vec<(u8, Vec<u8>)> {
        use tokio::io::AsyncReadExt;

        let mut deframer = kiss::RawKissDeframer::new();
        let mut frames = Vec::new();
        let mut buffer = [0u8; 2048];
        while !frames
            .iter()
            .any(|(command, _)| *command == terminal_command)
        {
            let count = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer))
                .await
                .expect("native bridge request timed out")
                .expect("native bridge request read");
            assert!(count > 0, "native bridge closed before expected command");
            frames.extend(deframer.feed(&buffer[..count]));
        }
        frames
    }

    #[tokio::test]
    async fn native_ble_waits_for_ready_and_retries_unacknowledged_payload_next_generation() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind native reliability bridge");
        let port = listener
            .local_addr()
            .expect("native reliability bridge address")
            .port();
        let config = BleRNodeConfig::new("native-reliability", "ble://RNode 0544");
        let server_config = config.clone();
        let payload = Bytes::from_static(b"queued-before-physical-reconnect");
        let server_payload = payload.clone();
        let post_ready_inbound = Bytes::from_static(b"same-read-post-ready-inbound");
        let server_post_ready_inbound = post_ready_inbound.clone();
        let pre_ready_reconnect_inbound =
            Bytes::from_static(b"physical-data-completed-across-tcp-replacement");
        let server_pre_ready_reconnect_inbound = pre_ready_reconnect_inbound.clone();
        let (awaiting_ready_tx, awaiting_ready_rx) = tokio::sync::oneshot::channel();
        let (first_unacknowledged_tx, first_unacknowledged_rx) = tokio::sync::oneshot::channel();

        let server = tokio::spawn(async move {
            let mut awaiting_ready_tx = Some(awaiting_ready_tx);
            let mut first_unacknowledged_tx = Some(first_unacknowledged_tx);
            for generation in 1..=2 {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("accept native reliability generation");

                let probe = native_test_read_through_command(&mut stream, rnode::CMD_MCU).await;
                assert!(
                    probe.iter().all(|(command, _)| *command != kiss::CMD_DATA),
                    "application data must not precede handshake"
                );
                let mut handshake = Vec::new();
                if generation == 2 {
                    // Android's physical GATT assembler may finish this record
                    // across the old/new localhost socket boundary and write it
                    // before the replacement generation's handshake response.
                    handshake.extend(kiss::frame(&server_pre_ready_reconnect_inbound));
                }
                handshake.extend(kiss::frame_with_command(
                    rnode::CMD_DETECT,
                    &[rnode::DETECT_RESP],
                ));
                handshake.extend(kiss::frame_with_command(
                    rnode::CMD_FW_VERSION,
                    &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
                ));
                stream
                    .write_all(&handshake)
                    .await
                    .expect("write native handshake");

                let init = native_test_read_through_command(&mut stream, rnode::CMD_MCU).await;
                assert!(
                    init.iter().any(|(command, frame)| {
                        *command == rnode::CMD_RADIO_STATE
                            && frame.as_slice() == [rnode::RADIO_STATE_ON]
                    }),
                    "native generation must request radio-on before readiness"
                );
                assert!(
                    init.iter().all(|(command, _)| *command != kiss::CMD_DATA),
                    "queued payload must remain behind exact Ready"
                );

                if generation == 1 {
                    let _ = awaiting_ready_tx.take().expect("first Ready gate").send(());
                    let mut unexpected = [0u8; 64];
                    assert!(
                        tokio::time::timeout(
                            Duration::from_millis(120),
                            stream.read(&mut unexpected),
                        )
                        .await
                        .is_err(),
                        "Rust must not write queued application data before typed Ready"
                    );
                }

                let mut ready_response = native_ready_response(&server_config);
                if generation == 1 {
                    ready_response.extend(kiss::frame(&server_post_ready_inbound));
                }
                stream
                    .write_all(&ready_response)
                    .await
                    .expect("write native Ready evidence");
                let application =
                    native_test_read_through_command(&mut stream, kiss::CMD_DATA).await;
                let observed = application
                    .iter()
                    .find_map(|(command, frame)| (*command == kiss::CMD_DATA).then_some(frame));
                assert_eq!(observed.map(Vec::as_slice), Some(server_payload.as_ref()));

                if generation == 1 {
                    let _ = first_unacknowledged_tx
                        .take()
                        .expect("first unacknowledged gate")
                        .send(());
                    // Simulate adapter loss after Android accepted the Rust TCP
                    // write but before an acknowledged GATT callback existed.
                    continue;
                }

                let mut acknowledgement = RNODE_NATIVE_BRIDGE_ACK_MAGIC.to_vec();
                acknowledgement.extend_from_slice(&1u64.to_be_bytes());
                stream
                    .write_all(&kiss::frame_with_command(
                        RNODE_NATIVE_BRIDGE_ACK_COMMAND,
                        &acknowledgement,
                    ))
                    .await
                    .expect("write generation-fenced bridge ACK");

                let mut detach = [0u8; 64];
                let _ =
                    tokio::time::timeout(Duration::from_secs(3), stream.read(&mut detach)).await;
            }
        });

        let id = 0xB1E0_A11C;
        let (transport_tx, mut transport_rx) = mpsc::channel(8);
        let spawned = spawn_ble_rnode_interface_native_with_driver(config, id, transport_tx, port)
            .await
            .expect("spawn native reliability interface");
        let tx = spawned.interface.tx.clone();
        let online = spawned.interface.online.clone();
        let txb = spawned
            .interface
            .txb
            .as_ref()
            .expect("native TXB counter")
            .clone();
        let mut snapshots = spawned.driver.watch();

        tx.send(payload.clone())
            .await
            .expect("queue payload before reconnect readiness");
        awaiting_ready_rx
            .await
            .expect("first generation reached pre-Ready gate");
        assert!(
            !online.load(Ordering::SeqCst),
            "physical bridge plus accepted init must remain publicly offline"
        );

        let ready = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let snapshot = snapshots
                    .changed()
                    .await
                    .expect("native reliability publisher closed");
                if snapshot.phase == rnode::RNodeRuntimePhase::Ready {
                    break snapshot;
                }
            }
        })
        .await
        .expect("native typed Ready publication timeout");
        assert_eq!(ready.connection_generation, 1);
        assert!(
            online.load(Ordering::SeqCst),
            "Ready publication must observe the corresponding raw online bit"
        );
        let inbound = tokio::time::timeout(Duration::from_secs(1), transport_rx.recv())
            .await
            .expect("same-read post-Ready inbound timeout")
            .expect("same-read post-Ready transport message");
        let TransportMessage::Inbound(inbound) = inbound else {
            panic!("expected inbound transport packet after Ready");
        };
        assert_eq!(inbound.raw, post_ready_inbound);

        first_unacknowledged_rx
            .await
            .expect("first generation received queued payload");
        assert_eq!(
            txb.load(Ordering::Relaxed),
            0,
            "TCP write alone must neither clear nor count payload"
        );

        let second_ready = tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                let snapshot = snapshots
                    .changed()
                    .await
                    .expect("native reliability publisher closed before reconnect Ready");
                if snapshot.phase == rnode::RNodeRuntimePhase::Ready
                    && snapshot.connection_generation == 2
                {
                    break snapshot;
                }
            }
        })
        .await
        .expect("replacement generation fresh Ready timeout");
        assert_eq!(second_ready.connection_generation, 2);
        let held_inbound = tokio::time::timeout(Duration::from_secs(1), transport_rx.recv())
            .await
            .expect("pre-Ready physical DATA release timeout")
            .expect("pre-Ready physical DATA transport message");
        let TransportMessage::Inbound(held_inbound) = held_inbound else {
            panic!("expected held inbound transport packet after reconnect Ready");
        };
        assert_eq!(held_inbound.raw, pre_ready_reconnect_inbound);

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if txb.load(Ordering::Relaxed) == payload.len() as u64 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("second-generation acknowledged payload timeout");
        assert!(
            matches!(
                transport_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "the internal bridge acknowledgement must never reach Reticulum transport"
        );

        spawned.driver.request_shutdown();
        tokio::time::timeout(Duration::from_secs(3), spawned.interface.read_task)
            .await
            .expect("native reliability shutdown timeout")
            .expect("native reliability task join");
        server.await.expect("native reliability bridge task");
    }

    #[tokio::test]
    async fn strict_desktop_ble_preflight_admits_verified_and_unverified_without_data_leakage() {
        for (response, expected_capability) in [
            (
                strict_capability_response(0xB8),
                rnode::RNodeCapabilityState::Verified,
            ),
            (
                strict_capability_response(0xFE),
                rnode::RNodeCapabilityState::Unverified,
            ),
            (
                strict_capability_response_with_eeprom(&unprovisioned_capability_eeprom()),
                rnode::RNodeCapabilityState::Unprovisioned,
            ),
        ] {
            let mut queued = capability_notifications(&response);
            queued.push(ValueNotification {
                uuid: NUS_TX_CHAR_UUID,
                value: kiss::frame(b"queued-before-init"),
            });
            let mut notifications = futures::stream::iter(queued.into_iter())
                .chain(futures::stream::pending::<ValueNotification>());
            let mut events = futures::stream::pending::<()>();
            let running = AtomicBool::new(true);
            let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
            let outcome = observe_desktop_ble_capability(
                &mut notifications,
                &mut events,
                |_| false,
                ble_radio_settings(&config),
                &running,
                Duration::from_secs(1),
            )
            .await;

            let BleCapabilityPreflightOutcome::Admitted {
                protocol_state,
                admission,
            } = outcome
            else {
                panic!("strict desktop BLE response should admit");
            };
            assert_eq!(
                matches!(admission, RNodeRadioAdmission::Verified { .. }),
                expected_capability == rnode::RNodeCapabilityState::Verified
            );
            assert_eq!(
                matches!(admission, RNodeRadioAdmission::Unprovisioned),
                expected_capability == rnode::RNodeCapabilityState::Unprovisioned
            );
            let evidence = protocol_state.evidence();
            assert!(evidence.detected);
            assert!(evidence.firmware.is_some());
            assert_eq!(evidence.frequency, None);
            assert_eq!(evidence.radio_state, None);
            assert!(
                notifications.next().now_or_never().is_none(),
                "the distinct queued pre-init notification must be drained"
            );

            let (mut publisher, driver) =
                rnode::new_rnode_driver_observation(RNodeTransportClass::Ble);
            publisher.capability_connection_established(&protocol_state, admission);
            let snapshot = driver.snapshot();
            assert_eq!(snapshot.connection_generation, 1);
            assert_eq!(snapshot.capability, expected_capability);
            assert_eq!(
                snapshot.configuration,
                rnode::RNodeConfigurationState::Unknown
            );
            assert_eq!(snapshot.radio, rnode::RNodeObservedRadioState::Unknown);
            publisher.stopped(RNodeRuntimeReason::StopRequested);
        }
    }

    #[tokio::test]
    async fn strict_desktop_ble_preflight_classifies_rejection_and_transient_loss() {
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let settings = ble_radio_settings(&config);
        let running = AtomicBool::new(true);
        let mut events = futures::stream::pending::<()>();

        let mut invalid_bytes = kiss::frame_with_command(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
        invalid_bytes.extend(kiss::frame_with_command(
            rnode::CMD_FW_VERSION,
            &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
        ));
        invalid_bytes.extend(kiss::frame_with_command(rnode::CMD_ROM_READ, &[0; 8]));
        let mut invalid = futures::stream::iter(capability_notifications(&invalid_bytes));
        assert!(matches!(
            observe_desktop_ble_capability(
                &mut invalid,
                &mut events,
                |_| false,
                settings,
                &running,
                Duration::from_secs(1)
            )
            .await,
            BleCapabilityPreflightOutcome::Rejected(
                RNodeCapabilityAdmissionError::CapabilityImage(_)
            )
        ));

        let response = strict_capability_response(0xB8);
        let mut duplicate_tail = capability_notifications(&response);
        duplicate_tail.extend(capability_notifications(&kiss::frame_with_command(
            rnode::CMD_ROM_READ,
            &capability_eeprom(0xB8),
        )));
        let mut duplicate_tail = futures::stream::iter(duplicate_tail)
            .chain(futures::stream::pending::<ValueNotification>());
        assert!(matches!(
            observe_desktop_ble_capability(
                &mut duplicate_tail,
                &mut events,
                |_| false,
                settings,
                &running,
                Duration::from_secs(1),
            )
            .await,
            BleCapabilityPreflightOutcome::Rejected(
                RNodeCapabilityAdmissionError::DuplicateEepromResponse
            )
        ));

        let mut ended = futures::stream::empty::<ValueNotification>();
        assert!(matches!(
            observe_desktop_ble_capability(
                &mut ended,
                &mut events,
                |_| false,
                settings,
                &running,
                Duration::from_secs(1),
            )
            .await,
            BleCapabilityPreflightOutcome::Retry(BleCapabilityRetry::TransportEnded)
        ));

        let mut pending = futures::stream::pending::<ValueNotification>();
        assert!(matches!(
            observe_desktop_ble_capability(
                &mut pending,
                &mut events,
                |_| false,
                settings,
                &running,
                Duration::from_millis(5)
            )
            .await,
            BleCapabilityPreflightOutcome::Retry(BleCapabilityRetry::ResponseTimedOut)
        ));
    }

    #[test]
    fn strict_active_handler_keeps_same_notification_data_ready_and_rssi_after_fresh_rf() {
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let target = RNodeProtocolTarget::new(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );
        let mut state = RNodeProtocolState::new(target);
        state.apply_frame(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
        state.apply_frame(
            rnode::CMD_FW_VERSION,
            &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
        );
        state.apply_frame(rnode::CMD_RADIO_STATE, &[rnode::RADIO_STATE_OFF]);
        let (mut publisher, driver) = rnode::new_rnode_driver_observation(RNodeTransportClass::Ble);
        publisher.capability_connection_established(
            &state,
            RNodeRadioAdmission::Verified {
                product_code: 0x03,
                model_code: 0xB8,
            },
        );

        let mut notification =
            kiss::frame_with_command(rnode::CMD_RADIO_STATE, &[rnode::RADIO_STATE_OFF]);
        notification.extend(kiss::frame_with_command(
            rnode::CMD_FREQUENCY,
            &target.frequency.to_be_bytes(),
        ));
        notification.extend(kiss::frame_with_command(
            rnode::CMD_BANDWIDTH,
            &target.bandwidth.to_be_bytes(),
        ));
        notification.extend(kiss::frame_with_command(
            rnode::CMD_SF,
            &[target.spreading_factor],
        ));
        notification.extend(kiss::frame_with_command(
            rnode::CMD_CR,
            &[target.coding_rate],
        ));
        notification.extend(kiss::frame_with_command(
            rnode::CMD_TXPOWER,
            &[target.tx_power],
        ));
        notification.extend(kiss::frame_with_command(
            rnode::CMD_RADIO_STATE,
            &[rnode::RADIO_STATE_ON],
        ));
        notification.extend(kiss::frame(b"first-active-packet"));
        notification.extend(kiss::frame_with_command(rnode::CMD_READY, &[1]));
        notification.extend(kiss::frame_with_command(rnode::CMD_STAT_RSSI, &[67]));

        let mut deframer = kiss::RawKissDeframer::new();
        let mut last_rssi = None;
        let mut last_snr = None;
        let mut packets = 0usize;
        let mut flow_ready = false;
        let mut packet_admission = ActiveBlePacketAdmission::for_startup_policy(true);
        packet_admission.observe_readiness(state.readiness());
        for (command, frame) in deframer.feed(&notification) {
            let data_allowed = project_active_ble_rnode_frame(
                &publisher,
                &mut state,
                &mut packet_admission,
                command,
                &frame,
            );
            match rnode::process_rnode_response(command, &frame, 1, &mut last_rssi, &mut last_snr) {
                RNodeResponse::Packet(_) if data_allowed => packets += 1,
                RNodeResponse::Ready(value) => flow_ready = value,
                RNodeResponse::Packet(_) | RNodeResponse::None => {}
            }
        }

        assert_eq!(packets, 1, "fresh post-Ready DATA must not be drained");
        assert!(flow_ready, "same-notification READY must be applied");
        assert_eq!(
            last_rssi,
            Some(-90.0),
            "same-notification RSSI must be retained"
        );
        assert!(matches!(state.readiness(), RNodeReadiness::Ready));
        assert_eq!(driver.snapshot().phase, rnode::RNodeRuntimePhase::Ready);
        publisher.stopped(RNodeRuntimeReason::StopRequested);
    }

    #[test]
    fn strict_active_admission_survives_first_frame_readiness_regression() {
        let target = RNodeProtocolTarget::new(915_000_000, 125_000, 8, 6, 17);
        let mut state = RNodeProtocolState::new(target);
        state.apply_frame(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
        state.apply_frame(
            rnode::CMD_FW_VERSION,
            &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
        );
        state.apply_frame(rnode::CMD_FREQUENCY, &target.frequency.to_be_bytes());
        state.apply_frame(rnode::CMD_BANDWIDTH, &target.bandwidth.to_be_bytes());
        state.apply_frame(rnode::CMD_SF, &[target.spreading_factor]);
        state.apply_frame(rnode::CMD_CR, &[target.coding_rate]);
        state.apply_frame(rnode::CMD_TXPOWER, &[target.tx_power]);
        state.apply_frame(rnode::CMD_RADIO_STATE, &[rnode::RADIO_STATE_ON]);
        assert_eq!(state.readiness(), RNodeReadiness::Ready);

        let (publisher, _driver) = rnode::new_rnode_driver_observation(RNodeTransportClass::Ble);
        let mut admission = ActiveBlePacketAdmission::for_startup_policy(true);
        admission.observe_readiness(state.readiness());

        let mismatched_frequency = target.frequency.saturating_add(101).to_be_bytes();
        assert!(project_active_ble_rnode_frame(
            &publisher,
            &mut state,
            &mut admission,
            rnode::CMD_FREQUENCY,
            &mismatched_frequency,
        ));
        assert_ne!(state.readiness(), RNodeReadiness::Ready);
        assert!(project_active_ble_rnode_frame(
            &publisher,
            &mut state,
            &mut admission,
            kiss::CMD_DATA,
            b"valid-active-packet",
        ));

        let mut reconnect = ActiveBlePacketAdmission::for_startup_policy(true);
        let mut reconnect_state = RNodeProtocolState::new(target);
        assert!(!project_active_ble_rnode_frame(
            &publisher,
            &mut reconnect_state,
            &mut reconnect,
            kiss::CMD_DATA,
            b"pre-admission-packet",
        ));
    }

    #[tokio::test]
    async fn strict_native_ble_preflight_orders_one_rom_request_before_admission() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind native strict bridge loopback");
        let address = listener.local_addr().expect("strict bridge address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept strict bridge");
            let mut commands = Vec::new();
            let mut deframer = kiss::RawKissDeframer::new();
            let mut buffer = [0u8; 1024];
            while !commands.contains(&rnode::CMD_ROM_READ) {
                let count = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer))
                    .await
                    .expect("strict request timeout")
                    .expect("strict request read");
                assert!(count > 0, "strict request ended before ROM read");
                commands.extend(
                    deframer
                        .feed(&buffer[..count])
                        .into_iter()
                        .map(|(command, _)| command),
                );
            }
            stream
                .write_all(&strict_capability_response(0xB8))
                .await
                .expect("write strict response");
            tokio::time::sleep(Duration::from_millis(50)).await;
            commands
        });

        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect strict bridge");
        let (mut read, mut write) = stream.into_split();
        let running = AtomicBool::new(true);
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let outcome = run_native_ble_capability_preflight(
            &mut read,
            &mut write,
            ble_radio_settings(&config),
            &running,
            Duration::from_secs(1),
            Duration::from_millis(100),
        )
        .await;
        assert!(matches!(
            outcome,
            BleCapabilityPreflightOutcome::Admitted {
                admission: RNodeRadioAdmission::Verified { .. },
                ..
            }
        ));

        let commands = server.await.expect("strict bridge server task");
        assert_eq!(
            commands
                .iter()
                .filter(|command| **command == rnode::CMD_ROM_READ)
                .count(),
            1
        );
        let detect = commands
            .iter()
            .position(|command| *command == rnode::CMD_DETECT)
            .expect("detect command");
        let rom = commands
            .iter()
            .position(|command| *command == rnode::CMD_ROM_READ)
            .expect("ROM command");
        assert!(detect < rom);
        assert!(
            commands.iter().all(|command| {
                !matches!(
                    *command,
                    rnode::CMD_FREQUENCY
                        | rnode::CMD_BANDWIDTH
                        | rnode::CMD_SF
                        | rnode::CMD_CR
                        | rnode::CMD_TXPOWER
                        | rnode::CMD_RADIO_STATE
                )
            }),
            "strict preflight must not send radio init"
        );
    }

    #[tokio::test]
    async fn strict_native_ble_preflight_admits_unprovisioned_eeprom() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind unprovisioned strict bridge");
        let address = listener.local_addr().expect("unprovisioned bridge address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept unprovisioned bridge");
            let mut commands = Vec::new();
            let mut deframer = kiss::RawKissDeframer::new();
            let mut buffer = [0u8; 1024];
            while !commands.contains(&rnode::CMD_ROM_READ) {
                let count = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer))
                    .await
                    .expect("unprovisioned request timeout")
                    .expect("unprovisioned request read");
                assert!(count > 0, "request ended before ROM read");
                commands.extend(
                    deframer
                        .feed(&buffer[..count])
                        .into_iter()
                        .map(|(command, _)| command),
                );
            }
            stream
                .write_all(&strict_capability_response_with_eeprom(
                    &unprovisioned_capability_eeprom(),
                ))
                .await
                .expect("write unprovisioned response");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect unprovisioned bridge");
        let (mut read, mut write) = stream.into_split();
        let running = AtomicBool::new(true);
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let outcome = run_native_ble_capability_preflight(
            &mut read,
            &mut write,
            ble_radio_settings(&config),
            &running,
            Duration::from_secs(1),
            Duration::from_millis(100),
        )
        .await;
        let BleCapabilityPreflightOutcome::Admitted {
            protocol_state,
            admission,
        } = outcome
        else {
            panic!("unprovisioned EEPROM must admit on the native path");
        };
        assert_eq!(admission, RNodeRadioAdmission::Unprovisioned);
        assert!(protocol_state.evidence().detected);
        server.await.expect("unprovisioned bridge server task");
    }

    #[tokio::test]
    async fn strict_native_ble_stop_before_preflight_writes_nothing() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind stopped strict bridge");
        let address = listener.local_addr().expect("stopped bridge address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept stopped bridge");
            let mut byte = [0u8; 1];
            stream.read(&mut byte).await.expect("stopped bridge read")
        });

        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect stopped bridge");
        let (mut read, mut write) = stream.into_split();
        let running = AtomicBool::new(false);
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        assert!(matches!(
            run_native_ble_capability_preflight(
                &mut read,
                &mut write,
                ble_radio_settings(&config),
                &running,
                Duration::from_secs(1),
                Duration::from_millis(100),
            )
            .await,
            BleCapabilityPreflightOutcome::Stopped
        ));
        drop(read);
        drop(write);
        assert_eq!(server.await.expect("stopped bridge server task"), 0);
    }

    #[tokio::test]
    async fn strict_native_ble_boundary_drains_buffered_preinit_read() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind buffered strict bridge");
        let address = listener.local_addr().expect("buffered bridge address");
        let (written_tx, written_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept buffered bridge");
            stream
                .write_all(&kiss::frame(b"queued-before-init"))
                .await
                .expect("write queued pre-init packet");
            stream.flush().await.expect("flush queued pre-init packet");
            let _ = written_tx.send(());
            let _ = release_rx.await;
        });

        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect buffered bridge");
        let (mut read, _write) = stream.into_split();
        written_rx.await.expect("queued write notification");
        read.readable().await.expect("buffered read readiness");
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let mut preflight = RNodeCapabilityPreflight::new(ble_radio_settings(&config));
        let running = AtomicBool::new(true);
        assert!(
            drain_native_ble_preinit(
                &mut read,
                &mut preflight,
                &running,
                Duration::from_secs(1),
                Duration::from_millis(5),
            )
            .await
            .is_ok()
        );
        let mut byte = [0u8; 1];
        assert_eq!(
            read.try_read(&mut byte)
                .expect_err("buffer must be empty")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        let _ = release_tx.send(());
        server.await.expect("buffered bridge server task");
    }

    #[tokio::test]
    async fn strict_native_ble_boundary_rejects_duplicate_rom_after_admission() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind duplicate-ROM bridge");
        let address = listener.local_addr().expect("duplicate-ROM address");
        let (written_tx, written_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let duplicate = kiss::frame_with_command(rnode::CMD_ROM_READ, &capability_eeprom(0xB8));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept duplicate-ROM bridge");
            stream
                .write_all(&duplicate)
                .await
                .expect("write duplicate ROM response");
            stream.flush().await.expect("flush duplicate ROM response");
            let _ = written_tx.send(());
            let _ = release_rx.await;
        });

        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect duplicate-ROM bridge");
        let (mut read, _write) = stream.into_split();
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let mut preflight = RNodeCapabilityPreflight::new(ble_radio_settings(&config));
        let mut admitted = false;
        for chunk in strict_capability_response(0xB8).chunks(512) {
            admitted |= preflight
                .observe_read(chunk)
                .expect("valid initial capability response")
                .is_some();
        }
        assert!(admitted);
        let running = AtomicBool::new(true);
        written_rx.await.expect("duplicate ROM write notification");
        assert!(matches!(
            drain_native_ble_preinit(
                &mut read,
                &mut preflight,
                &running,
                Duration::from_secs(1),
                Duration::from_millis(5),
            )
            .await,
            Err(BlePreflightBoundaryError::Rejected(
                RNodeCapabilityAdmissionError::DuplicateEepromResponse
            ))
        ));
        let _ = release_tx.send(());
        server.await.expect("duplicate-ROM bridge task");
    }

    #[tokio::test]
    async fn strict_native_ble_spawn_publishes_deterministic_rejection_as_terminal() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind rejecting strict bridge");
        let port = listener
            .local_addr()
            .expect("rejecting bridge address")
            .port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept rejecting bridge");
            let mut deframer = kiss::RawKissDeframer::new();
            let mut buffer = [0u8; 1024];
            loop {
                let count = stream
                    .read(&mut buffer)
                    .await
                    .expect("read rejecting request");
                assert!(count > 0, "strict request ended before ROM read");
                if deframer
                    .feed(&buffer[..count])
                    .iter()
                    .any(|(command, _)| *command == rnode::CMD_ROM_READ)
                {
                    break;
                }
            }
            let mut invalid = kiss::frame_with_command(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
            invalid.extend(kiss::frame_with_command(
                rnode::CMD_FW_VERSION,
                &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            ));
            invalid.extend(kiss::frame_with_command(rnode::CMD_ROM_READ, &[0; 8]));
            stream
                .write_all(&invalid)
                .await
                .expect("write rejecting response");
        });

        let (transport_tx, _transport_rx) = mpsc::channel(8);
        let spawned = spawn_ble_rnode_interface_native_with_driver_and_options(
            BleRNodeConfig::new("strict-native", "ble://RNode 1234"),
            987_654,
            transport_tx,
            port,
            RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .expect("spawn strict native observer");
        let mut subscription = spawned.driver.watch();
        let terminal = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let snapshot = subscription
                    .changed()
                    .await
                    .expect("strict native publisher closed");
                if snapshot.phase == rnode::RNodeRuntimePhase::Stopped {
                    break snapshot;
                }
            }
        })
        .await
        .expect("strict rejection publication timeout");
        assert_eq!(
            terminal.reason,
            Some(RNodeRuntimeReason::CapabilityAdmissionRejected)
        );
        assert_eq!(
            terminal.capability_admission_failure,
            Some(rnode::RNodeCapabilityAdmissionFailureClass::InvalidCapabilityImage)
        );
        assert!(!spawned.interface.online.load(Ordering::SeqCst));
        spawned
            .interface
            .read_task
            .await
            .expect("strict rejecting task join");
        server.await.expect("rejecting bridge server task");
    }

    #[test]
    fn test_native_ble_observation_uses_fresh_reducer_each_generation() {
        let config = BleRNodeConfig::new("ble0", "ble://RNode 1234");
        let target = RNodeProtocolTarget::new(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );
        let (mut publisher, driver) = rnode::new_rnode_driver_observation(RNodeTransportClass::Ble);

        let mut first_generation = RNodeProtocolState::new(target);
        first_generation.apply_frame(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
        publisher.connection_established();
        publisher.sync_protocol_state(&first_generation);
        assert_eq!(
            driver.snapshot().detection,
            rnode::RNodeDetectionState::Confirmed
        );

        publisher.connection_lost();
        publisher.reconnect_started();
        let second_generation = RNodeProtocolState::new(target);
        publisher.connection_established();
        assert!(!publisher.sync_protocol_state(&second_generation));

        let fresh = driver.snapshot();
        assert_eq!(fresh.connection_generation, 2);
        assert_eq!(fresh.disconnect_total, 1);
        assert_eq!(fresh.detection, rnode::RNodeDetectionState::Unknown);
        assert_eq!(
            fresh.firmware_compatibility,
            rnode::RNodeFirmwareCompatibility::Unknown
        );
        assert_eq!(fresh.transmit_flow, rnode::RNodeTransmitFlowState::Unknown);

        publisher.stopped(RNodeRuntimeReason::StopRequested);
    }

    #[test]
    fn test_native_ble_pre_admission_reset_is_not_misattributed_to_new_generation() {
        let target = RNodeProtocolTarget::new(915_000_000, 125_000, 7, 5, 17);
        let mut protocol_state = RNodeProtocolState::new(target);
        let mut deframer = kiss::RawKissDeframer::new();
        let mut batch = kiss::frame_with_command(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
        batch.extend(kiss::frame_with_command(rnode::CMD_RESET, &[0xF8]));
        batch.extend(kiss::frame_with_command(
            rnode::CMD_FW_VERSION,
            &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
        ));

        assert!(reduce_native_handshake_bytes(
            &mut protocol_state,
            &mut deframer,
            &batch,
        ));
        assert!(
            !protocol_state.evidence().detected,
            "reset must clear evidence accumulated earlier in the pending batch"
        );
        assert!(protocol_state.evidence().firmware.is_some());

        let (mut publisher, driver) = rnode::new_rnode_driver_observation(RNodeTransportClass::Ble);
        publisher.connection_established();
        publisher.sync_protocol_state(&protocol_state);
        let admitted = driver.snapshot();
        assert_eq!(admitted.reason, None);
        assert_eq!(admitted.detection, rnode::RNodeDetectionState::Unknown);
        assert_eq!(
            admitted.firmware_compatibility,
            rnode::RNodeFirmwareCompatibility::Supported
        );

        // Once the generation exists, the same typed effect is reported
        // immediately and clears its public protocol observations.
        project_ble_rnode_frame(&publisher, &mut protocol_state, rnode::CMD_RESET, &[0xF8]);
        let reset = driver.snapshot();
        assert_eq!(reset.reason, Some(RNodeRuntimeReason::DeviceReset));
        assert_eq!(
            reset.firmware_compatibility,
            rnode::RNodeFirmwareCompatibility::Unknown
        );

        publisher.stopped(RNodeRuntimeReason::StopRequested);
    }

    #[test]
    fn test_native_ble_malformed_accepted_handshake_has_no_typed_publication() {
        let target = RNodeProtocolTarget::new(915_000_000, 125_000, 7, 5, 17);
        let mut protocol_state = RNodeProtocolState::new(target);
        let mut deframer = kiss::RawKissDeframer::new();

        // Preserve the native bridge's historical permissive firmware
        // handshake: any non-empty firmware response admits the connection.
        // The strict reducer still rejects this wrong-width payload.
        let malformed =
            kiss::frame_with_command(rnode::CMD_FW_VERSION, &[rnode::REQUIRED_FW_VER_MAJ]);
        assert!(reduce_native_handshake_bytes(
            &mut protocol_state,
            &mut deframer,
            &malformed,
        ));
        assert!(protocol_state.evidence().firmware.is_none());

        let (mut publisher, driver) = rnode::new_rnode_driver_observation(RNodeTransportClass::Ble);
        publisher.connection_established();
        let before = driver.snapshot();
        assert!(!publisher.sync_protocol_state(&protocol_state));
        assert!(Arc::ptr_eq(&before, &driver.snapshot()));

        publisher.stopped(RNodeRuntimeReason::StopRequested);
    }

    #[test]
    fn test_native_ble_compatibility_and_observed_spawn_apis_compile() {
        let _compatibility_facade = spawn_ble_rnode_interface_native;
        let _observed_api = spawn_ble_rnode_interface_native_with_driver;
        let _strict_observed_api = spawn_ble_rnode_interface_native_with_driver_and_options;
        let _desktop_compatibility_facade = spawn_ble_rnode_interface;
        let _desktop_observed_api = spawn_ble_rnode_interface_with_driver;
        let _desktop_strict_observed_api = spawn_ble_rnode_interface_with_driver_and_options;
    }

    // ── process_rnode_response tests ──

    #[test]
    fn test_response_data_packet() {
        let data = vec![0x01, 0x02, 0x03];
        let mut rssi = Some(-65.0_f32);
        let mut snr = Some(8.0_f32);
        match rnode::process_rnode_response(kiss::CMD_DATA, &data, 42, &mut rssi, &mut snr) {
            rnode::RNodeResponse::Packet(msg) => {
                if let rns_transport::messages::TransportMessage::Inbound(pkt) = msg {
                    assert_eq!(pkt.raw, data);
                    assert_eq!(pkt.interface_id, 42);
                    assert_eq!(pkt.rssi, Some(-65.0));
                    assert_eq!(pkt.snr, Some(8.0));
                } else {
                    panic!("Expected Inbound packet");
                }
            }
            _ => panic!("Expected Packet response"),
        }
        assert!(rssi.is_none());
        assert!(snr.is_none());
    }

    #[test]
    fn test_response_empty_data_ignored() {
        let mut rssi = None;
        let mut snr = None;
        match rnode::process_rnode_response(kiss::CMD_DATA, &[], 1, &mut rssi, &mut snr) {
            rnode::RNodeResponse::None => {}
            _ => panic!("Expected None for empty data"),
        }
    }

    #[test]
    fn test_response_rssi_updates() {
        let mut rssi = None;
        let mut snr = None;
        rnode::process_rnode_response(rnode::CMD_STAT_RSSI, &[92], 1, &mut rssi, &mut snr);
        assert_eq!(rssi, Some(-65.0));
    }

    #[test]
    fn test_response_snr_updates() {
        let mut rssi = None;
        let mut snr = None;
        rnode::process_rnode_response(rnode::CMD_STAT_SNR, &[32], 1, &mut rssi, &mut snr);
        assert_eq!(snr, Some(8.0));
    }

    #[test]
    fn test_response_rssi_snr_reset_after_data() {
        let mut rssi = Some(-70.0_f32);
        let mut snr = Some(6.0_f32);
        rnode::process_rnode_response(kiss::CMD_DATA, &[0xFF], 1, &mut rssi, &mut snr);
        assert!(rssi.is_none());
        assert!(snr.is_none());
    }

    #[test]
    fn test_response_ready_true() {
        let mut rssi = None;
        let mut snr = None;
        match rnode::process_rnode_response(rnode::CMD_READY, &[0x01], 1, &mut rssi, &mut snr) {
            rnode::RNodeResponse::Ready(true) => {}
            _ => panic!("Expected Ready(true)"),
        }
    }

    #[test]
    fn test_response_ready_false() {
        let mut rssi = None;
        let mut snr = None;
        match rnode::process_rnode_response(rnode::CMD_READY, &[0x00], 1, &mut rssi, &mut snr) {
            rnode::RNodeResponse::Ready(false) => {}
            _ => panic!("Expected Ready(false)"),
        }
    }

    #[test]
    fn test_response_detect() {
        let mut rssi = None;
        let mut snr = None;
        match rnode::process_rnode_response(
            rnode::CMD_DETECT,
            &[rnode::DETECT_RESP],
            1,
            &mut rssi,
            &mut snr,
        ) {
            rnode::RNodeResponse::None => {}
            _ => panic!("Expected None"),
        }
    }

    #[test]
    fn test_response_radio_state_on() {
        let mut rssi = None;
        let mut snr = None;
        match rnode::process_rnode_response(
            rnode::CMD_RADIO_STATE,
            &[rnode::RADIO_STATE_ON],
            1,
            &mut rssi,
            &mut snr,
        ) {
            rnode::RNodeResponse::None => {}
            _ => panic!("Expected None"),
        }
    }

    #[test]
    fn test_response_firmware_version() {
        let mut rssi = None;
        let mut snr = None;
        match rnode::process_rnode_response(rnode::CMD_FW_VERSION, &[2, 10], 1, &mut rssi, &mut snr)
        {
            rnode::RNodeResponse::None => {}
            _ => panic!("Expected None"),
        }
    }

    #[test]
    fn test_response_battery_status() {
        let mut rssi = None;
        let mut snr = None;
        match rnode::process_rnode_response(
            rnode::CMD_STAT_BAT,
            &[0x0E, 0x74],
            1,
            &mut rssi,
            &mut snr,
        ) {
            rnode::RNodeResponse::None => {}
            _ => panic!("Expected None"),
        }
    }

    #[test]
    fn test_response_temperature() {
        let mut rssi = None;
        let mut snr = None;
        match rnode::process_rnode_response(rnode::CMD_STAT_TEMP, &[25], 1, &mut rssi, &mut snr) {
            rnode::RNodeResponse::None => {}
            _ => panic!("Expected None"),
        }
    }

    #[test]
    fn test_response_error() {
        let mut rssi = None;
        let mut snr = None;
        match rnode::process_rnode_response(rnode::CMD_ERROR, &[0x01], 1, &mut rssi, &mut snr) {
            rnode::RNodeResponse::None => {}
            _ => panic!("Expected None"),
        }
    }

    #[test]
    fn test_response_unknown_command() {
        let mut rssi = None;
        let mut snr = None;
        match rnode::process_rnode_response(0xFE, &[0x01, 0x02], 1, &mut rssi, &mut snr) {
            rnode::RNodeResponse::None => {}
            _ => panic!("Expected None for unknown command"),
        }
    }

    // ── Write chunking tests ──

    #[test]
    fn test_data_chunking_512() {
        let data = vec![0u8; 1024];
        let chunks: Vec<&[u8]> = data.chunks(512).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 512);
        assert_eq!(chunks[1].len(), 512);
    }

    #[test]
    fn test_data_chunking_exact_boundary() {
        let data = vec![0u8; 512];
        let chunks: Vec<&[u8]> = data.chunks(512).collect();
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn test_data_chunking_small() {
        let data = [0u8; 20];
        let chunks: Vec<&[u8]> = data.chunks(512).collect();
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn test_data_no_chunking_needed() {
        let data = [0u8; 100];
        let chunks: Vec<&[u8]> = data.chunks(512).collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 100);
    }

    // ── Hardware-dependent tests (require BLE adapter + paired RNode) ──

    #[tokio::test]
    #[ignore]
    async fn test_ble_scan_finds_devices() {
        let devices = scan_ble_devices(3).await.expect("BLE scan failed");
        println!("Found {} BLE devices:", devices.len());
        for d in &devices {
            println!(
                "  {} ({}) RSSI:{:?} Type:{:?}",
                d.name, d.address, d.rssi, d.device_type
            );
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_ble_connect_to_rnode() {
        let adapter = get_adapter().await.expect("No BLE adapter");
        let running = AtomicBool::new(true);
        let mut generation_stable_name = None;
        let conn = connect_rnode(
            &adapter,
            "ble://",
            &mut generation_stable_name,
            &running,
            BleGenerationId::default().next(),
        )
        .await
        .expect("No RNode found. Pair an RNode first.");
        assert!(conn.peripheral.is_connected().await.unwrap_or(false));
        conn.peripheral.disconnect().await.ok();
    }

    #[tokio::test]
    #[ignore]
    async fn test_ble_rnode_full_lifecycle() {
        let (transport_tx, mut _transport_rx) = mpsc::channel(64);
        let config = BleRNodeConfig::new("test-rnode", "ble://");
        let handle = spawn_ble_rnode_interface(config, 99, transport_tx)
            .await
            .expect("Failed to spawn BLE RNode interface");

        assert!(handle.online.load(Ordering::SeqCst));
        assert_eq!(handle.mtu, 508);
        assert_eq!(handle.id, 99);

        tokio::time::sleep(Duration::from_secs(2)).await;
        handle.online.store(false, Ordering::SeqCst);
    }
}
