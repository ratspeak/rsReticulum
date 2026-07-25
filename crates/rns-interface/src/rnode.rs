//! LoRa radio control via RNode firmware's extended-KISS protocol.
//! Shared constants + transport-agnostic response handler. Serial:
//! [`spawn_rnode_interface`] (feature `serial`); BLE: [`crate::ble_rnode`].
//!
//! Transport selection is driven by the `port` string in [`RNodeConfig`]:
//!   - `/dev/ttyUSB0`, `COM3`, etc.  -> serial (feature `serial` required)
//!   - `tcp://192.168.1.1`           -> TCP, default port 7633
//!   - `tcp://192.168.1.1:9000`      -> TCP, explicit port

use bytes::Bytes;

use crate::kiss;
use crate::traits::{InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use crate::rnode_protocol::{
    FREQUENCY_TOLERANCE_HZ, RNodeProtocolEffect, RNodeProtocolState, RNodeProtocolTarget,
    RNodeRadioState, RNodeReadiness,
};
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use crate::traits::{InterfaceDirection, InterfaceHandle};
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use std::collections::HashMap;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use std::time::Duration;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use tokio::sync::{mpsc, oneshot, watch};

pub const CMD_FREQUENCY: u8 = 0x01;
pub const CMD_BANDWIDTH: u8 = 0x02;
pub const CMD_TXPOWER: u8 = 0x03;
pub const CMD_SF: u8 = 0x04;
pub const CMD_CR: u8 = 0x05;
pub const CMD_RADIO_STATE: u8 = 0x06;
pub const CMD_RADIO_LOCK: u8 = 0x07;
pub const CMD_DETECT: u8 = 0x08;
pub const CMD_IMPLICIT: u8 = 0x09;
pub const CMD_LEAVE: u8 = 0x0A;
pub const CMD_PROMISC: u8 = 0x0E;
pub const CMD_READY: u8 = 0x0F;

pub const CMD_STAT_RX: u8 = 0x21;
pub const CMD_STAT_TX: u8 = 0x22;
pub const CMD_STAT_RSSI: u8 = 0x23;
pub const CMD_STAT_SNR: u8 = 0x24;
pub const CMD_STAT_CHTM: u8 = 0x25;
pub const CMD_STAT_PHYPRM: u8 = 0x26;
pub const CMD_STAT_BAT: u8 = 0x27;
pub const CMD_STAT_EDROP: u8 = 0x28;

pub const CMD_STAT_TEMP: u8 = 0x29;
pub const CMD_ERROR: u8 = 0x90;

pub const CMD_BLINK: u8 = 0x30;
pub const CMD_RANDOM: u8 = 0x40;

pub const CMD_FB_EXT: u8 = 0x41;
pub const CMD_FB_READ: u8 = 0x42;
pub const CMD_FB_WRITE: u8 = 0x43;
pub const CMD_BT_CTRL: u8 = 0x46;

pub const CMD_BOARD: u8 = 0x47;
pub const CMD_PLATFORM: u8 = 0x48;
pub const CMD_MCU: u8 = 0x49;
pub const CMD_FW_VERSION: u8 = 0x50;
pub const CMD_ROM_READ: u8 = 0x51;
pub const CMD_ROM_WRITE: u8 = 0x52;
pub const CMD_CONF_SAVE: u8 = 0x53;
pub const CMD_CONF_DELETE: u8 = 0x54;
pub const CMD_DEV_HASH: u8 = 0x56;
pub const CMD_DEV_SIG: u8 = 0x57;
pub const CMD_FW_HASH: u8 = 0x58;
pub const CMD_ROM_WIPE: u8 = 0x59;
pub const CMD_HASHES: u8 = 0x60;
pub const CMD_FW_UPD: u8 = 0x61;
pub const CMD_BT_PIN: u8 = 0x62;

pub const CMD_ST_ALOCK: u8 = 0x0B;
pub const CMD_LT_ALOCK: u8 = 0x0C;

pub const CMD_RESET: u8 = 0x55;
pub const CMD_DISP_INT: u8 = 0x45;
pub const CMD_DISP_ADR: u8 = 0x63;
pub const CMD_DISP_BLNK: u8 = 0x64;
pub const CMD_NP_INT: u8 = 0x65;
pub const CMD_DISP_ROT: u8 = 0x67;
pub const CMD_DISP_RCND: u8 = 0x68;
pub const CMD_DIS_IA: u8 = 0x69;
pub const CMD_WIFI_MODE: u8 = 0x6A;
pub const CMD_WIFI_SSID: u8 = 0x6B;
pub const CMD_WIFI_PSK: u8 = 0x6C;
pub const CMD_CFG_READ: u8 = 0x6D;
pub const CMD_WIFI_CHN: u8 = 0x6E;
pub const CMD_WIFI_IP: u8 = 0x84;
pub const CMD_WIFI_NM: u8 = 0x85;

pub const DETECT_REQ: u8 = 0x73;
pub const DETECT_RESP: u8 = 0x46;

pub const REQUIRED_FW_VER_MAJ: u8 = 1;
pub const REQUIRED_FW_VER_MIN: u8 = 52;

pub const RSSI_OFFSET: i32 = 157;

pub const RECONNECT_WAIT: u64 = 5;

pub const RADIO_STATE_ON: u8 = 0x01;
pub const RADIO_STATE_OFF: u8 = 0x00;

/// Lowest RF frequency accepted by the generic upstream RNode interface.
pub const RNODE_FREQUENCY_MIN_HZ: u32 = 137_000_000;
/// Highest RF frequency accepted by the generic upstream RNode interface.
pub const RNODE_FREQUENCY_MAX_HZ: u32 = 3_000_000_000;
/// Lowest RF bandwidth accepted by the generic upstream RNode interface.
pub const RNODE_BANDWIDTH_MIN_HZ: u32 = 7_800;
/// Highest RF bandwidth accepted by the generic upstream RNode interface.
pub const RNODE_BANDWIDTH_MAX_HZ: u32 = 1_625_000;
pub const RNODE_SPREADING_FACTOR_MIN: u8 = 5;
pub const RNODE_SPREADING_FACTOR_MAX: u8 = 12;
pub const RNODE_CODING_RATE_MIN: u8 = 5;
pub const RNODE_CODING_RATE_MAX: u8 = 8;
pub const RNODE_TX_POWER_MIN_DBM: u8 = 0;
pub const RNODE_TX_POWER_MAX_DBM: u8 = 37;

/// Default TCP port for RNode-over-IP.
pub const DEFAULT_TCP_PORT: u16 = 7633;

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_READ_TIMEOUT_MS: u64 = 100;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_CONNECT_TIMEOUT_SECS: u64 = 5;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_KEEPIDLE_SECS: u64 = 5;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_KEEPINTVL_SECS: u64 = 2;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_KEEPCNT: u32 = 12;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_USER_TIMEOUT_SECS: u64 = 24;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_BUFFER_BYTES: usize = 131_072;

/// Local transport category for the generic RNode driver.
///
/// This intentionally carries no endpoint or device identity.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeTransportClass {
    #[cfg(feature = "serial")]
    Serial,
    Tcp,
}

/// Coarse lifecycle phase of the generic RNode driver.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeRuntimePhase {
    Connecting,
    AwaitingReadiness,
    /// The active connection has complete, compatible protocol evidence.
    Ready,
    ReconnectBackoff,
    ShuttingDown,
    Stopped,
}

/// Detection evidence observed for the active connection generation.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeDetectionState {
    Unknown,
    Confirmed,
    Unconfirmed,
}

/// Compatibility of the observed firmware with this generic RNode driver.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeFirmwareCompatibility {
    Unknown,
    Supported,
    Unsupported,
}

/// Verification state for the configured radio parameters.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeConfigurationState {
    Unknown,
    Verified,
    Mismatch,
}

/// Radio power state observed from the active RNode connection.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeObservedRadioState {
    Unknown,
    On,
    Off,
}

/// KISS transmit-flow permission observed from the active connection.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeTransmitFlowState {
    Unknown,
    Permitted,
    Blocked,
}

/// Privacy-safe reason for the latest driver or admitted protocol transition.
///
/// Reasons are deliberately closed classifications: unrestricted transport or
/// device errors never enter the observation channel.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeRuntimeReason {
    ConnectionAttemptFailed,
    ConnectionLost,
    StopRequested,
    TransportConsumerClosed,
    DriverTerminated,
    DeviceReset,
    RadioInitialisationFault,
}

/// Privacy-safe local observation of one generic RNode driver.
///
/// This type intentionally contains no interface id or label, path, endpoint,
/// device identity, raw error, exact firmware/RF values, telemetry, hashes,
/// EEPROM contents, or frame data.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RNodeRuntimeSnapshot {
    pub transport: RNodeTransportClass,
    pub phase: RNodeRuntimePhase,
    /// Non-zero only while a usable opened and cloned connection is active.
    pub connection_generation: u64,
    /// Consecutive post-initial connection attempts; reset on success.
    pub reconnect_attempt: u64,
    /// Total post-initial connection attempts for this driver.
    pub reconnect_total: u64,
    /// Unplanned active-session losses that entered retry.
    pub disconnect_total: u64,
    pub detection: RNodeDetectionState,
    pub firmware_compatibility: RNodeFirmwareCompatibility,
    pub configuration: RNodeConfigurationState,
    pub radio: RNodeObservedRadioState,
    pub transmit_flow: RNodeTransmitFlowState,
    pub reason: Option<RNodeRuntimeReason>,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl RNodeRuntimeSnapshot {
    fn initial(transport: RNodeTransportClass) -> Self {
        Self {
            transport,
            phase: RNodeRuntimePhase::Connecting,
            connection_generation: 0,
            reconnect_attempt: 0,
            reconnect_total: 0,
            disconnect_total: 0,
            detection: RNodeDetectionState::Unknown,
            firmware_compatibility: RNodeFirmwareCompatibility::Unknown,
            configuration: RNodeConfigurationState::Unknown,
            radio: RNodeObservedRadioState::Unknown,
            transmit_flow: RNodeTransmitFlowState::Unknown,
            reason: None,
        }
    }

    fn reset_protocol_observations(&mut self) {
        self.detection = RNodeDetectionState::Unknown;
        self.firmware_compatibility = RNodeFirmwareCompatibility::Unknown;
        self.configuration = RNodeConfigurationState::Unknown;
        self.radio = RNodeObservedRadioState::Unknown;
        self.transmit_flow = RNodeTransmitFlowState::Unknown;
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn project_rnode_protocol_effect(
    snapshot: &mut RNodeRuntimeSnapshot,
    state: &RNodeProtocolState,
    effect: RNodeProtocolEffect,
) -> bool {
    if matches!(
        effect,
        RNodeProtocolEffect::NoChange | RNodeProtocolEffect::Rejected(_)
    ) {
        return false;
    }

    let before = snapshot.clone();
    let evidence = state.evidence();
    let target = state.target();

    snapshot.detection = if !state.detection_observed() {
        RNodeDetectionState::Unknown
    } else if evidence.detected {
        RNodeDetectionState::Confirmed
    } else {
        RNodeDetectionState::Unconfirmed
    };
    snapshot.firmware_compatibility = match evidence.firmware {
        None => RNodeFirmwareCompatibility::Unknown,
        Some(firmware) if firmware.is_supported() => RNodeFirmwareCompatibility::Supported,
        Some(_) => RNodeFirmwareCompatibility::Unsupported,
    };

    let configuration_mismatch = evidence
        .frequency
        .is_some_and(|frequency| frequency.abs_diff(target.frequency) > FREQUENCY_TOLERANCE_HZ)
        || evidence
            .bandwidth
            .is_some_and(|bandwidth| bandwidth != target.bandwidth)
        || evidence
            .spreading_factor
            .is_some_and(|spreading_factor| spreading_factor != target.spreading_factor)
        || evidence
            .coding_rate
            .is_some_and(|coding_rate| coding_rate != target.coding_rate)
        || evidence
            .tx_power
            .is_some_and(|tx_power| tx_power != target.tx_power);
    let configuration_complete = evidence.frequency.is_some()
        && evidence.bandwidth.is_some()
        && evidence.spreading_factor.is_some()
        && evidence.coding_rate.is_some()
        && evidence.tx_power.is_some();
    snapshot.configuration = if configuration_mismatch {
        RNodeConfigurationState::Mismatch
    } else if configuration_complete {
        RNodeConfigurationState::Verified
    } else {
        RNodeConfigurationState::Unknown
    };

    snapshot.radio = match evidence.radio_state {
        None => RNodeObservedRadioState::Unknown,
        Some(RNodeRadioState::Off) => RNodeObservedRadioState::Off,
        Some(RNodeRadioState::On) => RNodeObservedRadioState::On,
    };
    snapshot.transmit_flow = if !state.flow_permission_observed() {
        RNodeTransmitFlowState::Unknown
    } else if evidence.flow_permitted {
        RNodeTransmitFlowState::Permitted
    } else {
        RNodeTransmitFlowState::Blocked
    };
    snapshot.phase = match state.readiness() {
        RNodeReadiness::Ready => RNodeRuntimePhase::Ready,
        RNodeReadiness::Blocked(_) => RNodeRuntimePhase::AwaitingReadiness,
    };

    match effect {
        RNodeProtocolEffect::Reset => {
            snapshot.reason = Some(RNodeRuntimeReason::DeviceReset);
        }
        RNodeProtocolEffect::RadioInitialisationFault => {
            snapshot.reason = Some(RNodeRuntimeReason::RadioInitialisationFault);
        }
        RNodeProtocolEffect::EvidenceChanged(_) | RNodeProtocolEffect::FlowPermissionChanged(_) => {
            if evidence.radio_initialisation_fault {
                snapshot.reason = Some(RNodeRuntimeReason::RadioInitialisationFault);
            } else if snapshot.phase == RNodeRuntimePhase::Ready
                && snapshot.reason == Some(RNodeRuntimeReason::DeviceReset)
            {
                snapshot.reason = None;
            }
        }
        RNodeProtocolEffect::NoChange | RNodeProtocolEffect::Rejected(_) => {
            unreachable!("non-publishing effects returned above")
        }
    }

    *snapshot != before
}

/// Cloneable, observation-only handle for a generic serial/RNode-TCP driver.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone)]
pub struct RNodeDriverHandle {
    state: watch::Receiver<Arc<RNodeRuntimeSnapshot>>,
}

/// Clone-only subscription to generic RNode driver observations.
///
/// The underlying Tokio receiver stays private so callers cannot retain a
/// watch borrow across driver publication. Both accessors return an owned
/// [`Arc`] and release the internal borrow before returning.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone)]
pub struct RNodeDriverSubscription {
    state: watch::Receiver<Arc<RNodeRuntimeSnapshot>>,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl RNodeDriverHandle {
    /// Return the latest privacy-safe driver snapshot.
    pub fn snapshot(&self) -> Arc<RNodeRuntimeSnapshot> {
        self.state.borrow().clone()
    }

    /// Subscribe to future driver snapshots.
    pub fn watch(&self) -> RNodeDriverSubscription {
        RNodeDriverSubscription {
            state: self.state.clone(),
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl RNodeDriverSubscription {
    /// Return the latest snapshot without retaining a watch borrow.
    pub fn snapshot(&self) -> Arc<RNodeRuntimeSnapshot> {
        self.state.borrow().clone()
    }

    /// Wait for a publication and return its cloned snapshot.
    ///
    /// `None` means the driver publisher has closed.
    pub async fn changed(&mut self) -> Option<Arc<RNodeRuntimeSnapshot>> {
        self.state.changed().await.ok()?;
        Some(self.snapshot())
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl std::fmt::Debug for RNodeDriverHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RNodeDriverHandle")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl std::fmt::Debug for RNodeDriverSubscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RNodeDriverSubscription")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

/// Generic interface handle paired with its local RNode driver observation.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[non_exhaustive]
pub struct SpawnedRNodeInterface {
    pub interface: InterfaceHandle,
    pub driver: RNodeDriverHandle,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
struct RNodeSnapshotPublisher {
    state: watch::Sender<Arc<RNodeRuntimeSnapshot>>,
    last_connection_generation: u64,
    terminal: bool,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl RNodeSnapshotPublisher {
    fn new(state: watch::Sender<Arc<RNodeRuntimeSnapshot>>) -> Self {
        Self {
            state,
            last_connection_generation: 0,
            terminal: false,
        }
    }

    fn update(&self, update: impl FnOnce(&mut RNodeRuntimeSnapshot)) -> bool {
        let current = self.state.borrow().clone();
        let mut next = (*current).clone();
        update(&mut next);
        if &next == current.as_ref() {
            return false;
        }
        self.state.send_replace(Arc::new(next));
        true
    }

    fn connection_established(&mut self) {
        self.last_connection_generation = self.last_connection_generation.saturating_add(1).max(1);
        let generation = self.last_connection_generation;
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::AwaitingReadiness;
            snapshot.connection_generation = generation;
            snapshot.reconnect_attempt = 0;
            snapshot.reason = None;
            snapshot.reset_protocol_observations();
        });
    }

    fn reconnect_started(&self) {
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::Connecting;
            snapshot.connection_generation = 0;
            snapshot.reconnect_attempt = snapshot.reconnect_attempt.saturating_add(1);
            snapshot.reconnect_total = snapshot.reconnect_total.saturating_add(1);
            snapshot.reason = None;
            snapshot.reset_protocol_observations();
        });
    }

    fn connection_attempt_failed(&self) {
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::ReconnectBackoff;
            snapshot.connection_generation = 0;
            snapshot.reason = Some(RNodeRuntimeReason::ConnectionAttemptFailed);
            snapshot.reset_protocol_observations();
        });
    }

    fn connection_lost(&self) {
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::ReconnectBackoff;
            snapshot.connection_generation = 0;
            snapshot.disconnect_total = snapshot.disconnect_total.saturating_add(1);
            snapshot.reason = Some(RNodeRuntimeReason::ConnectionLost);
            snapshot.reset_protocol_observations();
        });
    }

    fn protocol_effect(&self, state: &RNodeProtocolState, effect: RNodeProtocolEffect) -> bool {
        if matches!(
            effect,
            RNodeProtocolEffect::NoChange | RNodeProtocolEffect::Rejected(_)
        ) {
            return false;
        }
        let mut projection_changed = false;
        let published = self.update(|snapshot| {
            projection_changed = project_rnode_protocol_effect(snapshot, state, effect);
        });
        debug_assert_eq!(published, projection_changed);
        published
    }

    fn shutting_down(&self, reason: RNodeRuntimeReason) {
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::ShuttingDown;
            snapshot.reason = Some(reason);
        });
    }

    fn stopped(&mut self, reason: RNodeRuntimeReason) {
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::Stopped;
            snapshot.connection_generation = 0;
            snapshot.reason = Some(reason);
            snapshot.reset_protocol_observations();
        });
        self.terminal = true;
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl Drop for RNodeSnapshotPublisher {
    fn drop(&mut self) {
        if self.terminal {
            return;
        }
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::Stopped;
            snapshot.connection_generation = 0;
            snapshot.reason = Some(RNodeRuntimeReason::DriverTerminated);
            snapshot.reset_protocol_observations();
        });
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
type RNodeStopRegistry = Mutex<HashMap<InterfaceId, mpsc::Sender<()>>>;

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn rnode_stop_registry() -> &'static RNodeStopRegistry {
    static REGISTRY: OnceLock<RNodeStopRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
struct RNodeStopRegistryGuard {
    id: InterfaceId,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl Drop for RNodeStopRegistryGuard {
    fn drop(&mut self) {
        rnode_stop_registry()
            .lock()
            .expect("rnode_stop_registry mutex poisoned")
            .remove(&self.id);
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn register_rnode_stop(id: InterfaceId, stop_tx: mpsc::Sender<()>) -> RNodeStopRegistryGuard {
    rnode_stop_registry()
        .lock()
        .expect("rnode_stop_registry mutex poisoned")
        .insert(id, stop_tx);
    RNodeStopRegistryGuard { id }
}

/// Ask a serial/TCP RNode interface to send upstream's detach sequence before
/// runtime teardown aborts the task. Idempotent; unknown ids are ignored.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub fn stop_rnode_interface(id: InterfaceId) {
    let stop_tx = rnode_stop_registry()
        .lock()
        .expect("rnode_stop_registry mutex poisoned")
        .get(&id)
        .cloned();
    let Some(stop_tx) = stop_tx else {
        tracing::debug!(id, "RNode stop requested for unknown interface");
        return;
    };
    match stop_tx.try_send(()) {
        Ok(()) => tracing::info!(id, "RNode stop signal sent"),
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::debug!(id, "RNode stop signal already pending")
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!(id, "RNode stop signal receiver already closed")
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
enum RNodeWriteRequest {
    Packet(Bytes),
    Raw(Vec<u8>, oneshot::Sender<()>),
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn send_detach_request(conn_tx: &mpsc::Sender<RNodeWriteRequest>, id: InterfaceId) {
    let (done_tx, done_rx) = oneshot::channel();
    if conn_tx
        .send(RNodeWriteRequest::Raw(build_detach_sequence(), done_tx))
        .await
        .is_err()
    {
        tracing::warn!(id, "RNode detach sequence could not be queued");
        return;
    }

    match tokio::time::timeout(Duration::from_millis(500), done_rx).await {
        Ok(Ok(())) => tracing::info!(id, "RNode detach sequence sent"),
        Ok(Err(_)) => tracing::warn!(id, "RNode detach writer dropped acknowledgement"),
        Err(_) => tracing::warn!(id, "RNode detach sequence timed out"),
    }
}

// Transport abstraction

/// Parsed representation of the `port` config field.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Debug, Clone)]
pub enum PortConfig {
    /// A local serial device path, e.g. `/dev/ttyUSB0` or `COM3`.
    #[cfg(feature = "serial")]
    Serial { path: String, baud: u32 },
    /// A TCP endpoint, e.g. `tcp://192.168.1.1` or `tcp://192.168.1.1:9000`.
    Tcp { addr: String },
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl PortConfig {
    pub fn parse(port: &str, baud: u32) -> Result<Self, String> {
        #[cfg(not(feature = "serial"))]
        let _ = baud;

        if let Some(rest) = strip_tcp_scheme(port) {
            let addr = parse_tcp_endpoint(rest)?;
            Ok(Self::Tcp { addr })
        } else {
            #[cfg(feature = "serial")]
            {
                Ok(Self::Serial {
                    path: port.to_string(),
                    baud,
                })
            }
            #[cfg(not(feature = "serial"))]
            Err("RNode serial ports require the 'serial' feature; use tcp://host[:port] for TCP RNodes".to_string())
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn strip_tcp_scheme(port: &str) -> Option<&str> {
    const TCP_SCHEME: &str = "tcp://";
    port.get(..TCP_SCHEME.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(TCP_SCHEME))
        .and_then(|_| port.get(TCP_SCHEME.len()..))
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn parse_tcp_endpoint(endpoint: &str) -> Result<String, String> {
    if endpoint.is_empty() {
        return Err("missing TCP host".to_string());
    }

    if let Some(rest) = endpoint.strip_prefix('[') {
        let Some(closing) = rest.find(']') else {
            return Err("missing closing ']' in IPv6 TCP host".to_string());
        };
        let host = &rest[..closing];
        if host.is_empty() {
            return Err("missing TCP host".to_string());
        }

        let tail = &rest[closing + 1..];
        let port = if tail.is_empty() {
            DEFAULT_TCP_PORT
        } else if let Some(port) = tail.strip_prefix(':') {
            parse_tcp_port(port)?
        } else {
            return Err("unexpected text after bracketed TCP host".to_string());
        };

        return Ok(format!("[{host}]:{port}"));
    }

    let colon_count = endpoint.matches(':').count();
    match colon_count {
        0 => Ok(format!("{endpoint}:{DEFAULT_TCP_PORT}")),
        1 => {
            let (host, port) = endpoint
                .rsplit_once(':')
                .expect("colon_count guarantees a separator");
            if host.is_empty() {
                return Err("missing TCP host".to_string());
            }
            Ok(format!("{host}:{}", parse_tcp_port(port)?))
        }
        _ => Ok(format!("[{endpoint}]:{DEFAULT_TCP_PORT}")),
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn parse_tcp_port(port: &str) -> Result<u16, String> {
    if port.is_empty() {
        return Err("missing TCP port".to_string());
    }
    port.parse::<u16>()
        .map_err(|_| format!("invalid TCP port: {port}"))
}

/// A unified sync I/O stream for either a serial port or a TCP socket.
///
/// Both variants support `Read + Write + Send + 'static` so the existing
/// `spawn_blocking` read/write loops require minimal changes.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub enum RNodeStream {
    #[cfg(feature = "serial")]
    Serial(Box<dyn serialport::SerialPort>),
    Tcp(std::net::TcpStream),
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl RNodeStream {
    /// Open a serial port.
    #[cfg(feature = "serial")]
    pub fn open_serial(path: &str, baud: u32) -> std::io::Result<Self> {
        let port = serialport::new(path, baud)
            .timeout(Duration::from_millis(RNODE_READ_TIMEOUT_MS))
            .open()
            .map_err(std::io::Error::other)?;
        Ok(Self::Serial(port))
    }

    /// Connect to a TCP socket (blocking).
    pub fn connect_tcp(addr: &str) -> std::io::Result<Self> {
        Self::connect_tcp_with_timeout(addr, Duration::from_secs(RNODE_TCP_CONNECT_TIMEOUT_SECS))
    }

    fn connect_tcp_with_timeout(addr: &str, timeout: Duration) -> std::io::Result<Self> {
        use std::net::ToSocketAddrs;

        let mut last_error = None;
        for socket_addr in addr.to_socket_addrs()? {
            match std::net::TcpStream::connect_timeout(&socket_addr, timeout) {
                Ok(stream) => return Self::from_tcp_stream(stream),
                Err(e) => last_error = Some(e),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("no socket addresses resolved for {addr}"),
            )
        }))
    }

    fn from_tcp_stream(stream: std::net::TcpStream) -> std::io::Result<Self> {
        // Mirror the serial timeout so the read loop doesn't block forever.
        stream.set_read_timeout(Some(Duration::from_millis(RNODE_READ_TIMEOUT_MS)))?;
        stream.set_nodelay(true)?;
        crate::socket_tuning::set_keepalive_tuned(
            &stream,
            Duration::from_secs(RNODE_TCP_KEEPIDLE_SECS),
            Duration::from_secs(RNODE_TCP_KEEPINTVL_SECS),
            RNODE_TCP_KEEPCNT,
            Duration::from_secs(RNODE_TCP_USER_TIMEOUT_SECS),
        );
        crate::socket_tuning::set_socket_buffers(&stream, RNODE_TCP_BUFFER_BYTES);
        Ok(Self::Tcp(stream))
    }

    /// Shallow-clone the stream for the write half.
    ///
    /// - Serial: uses `SerialPort::try_clone`.
    /// - TCP: uses `TcpStream::try_clone` (both halves share the same fd).
    pub fn try_clone(&self) -> std::io::Result<Self> {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => Ok(Self::Serial(p.try_clone().map_err(std::io::Error::other)?)),
            Self::Tcp(s) => Ok(Self::Tcp(s.try_clone()?)),
        }
    }

    /// Human-readable description for log messages.
    pub fn description(&self) -> String {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => p.name().unwrap_or_else(|| "<unknown serial>".to_string()),
            Self::Tcp(s) => s
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "<unknown tcp>".to_string()),
        }
    }

    fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl std::io::Read for RNodeStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => p.read(buf),
            Self::Tcp(s) => s.read(buf),
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl std::io::Write for RNodeStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => p.write(buf),
            Self::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => p.flush(),
            Self::Tcp(s) => s.flush(),
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn read_rnode_stream(
    mut stream: RNodeStream,
    mut buf: [u8; 1024],
) -> Result<(RNodeStream, [u8; 1024], usize), (RNodeStream, std::io::Error)> {
    use std::io::Read;

    match stream.read(&mut buf) {
        Ok(0) if stream.is_tcp() => Err((
            stream,
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "RNode TCP socket closed"),
        )),
        Ok(n) => Ok((stream, buf, n)),
        // Serial returns TimedOut; TCP returns WouldBlock on non-blocking
        // or TimedOut on a read-timeout. Treat both as "no data yet".
        Err(e)
            if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock =>
        {
            Ok((stream, buf, 0))
        }
        Err(e) => Err((stream, e)),
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn open_configured_rnode_stream(
    config: &RNodeConfig,
    port_cfg: &PortConfig,
) -> Result<RNodeStream, crate::traits::InterfaceError> {
    let port = match port_cfg {
        #[cfg(feature = "serial")]
        PortConfig::Serial { path, baud } => {
            tracing::info!(
                name = %config.name,
                port = %path,
                baud = baud,
                "RNode serial interface opening"
            );
            RNodeStream::open_serial(path, *baud).map_err(|e| {
                crate::traits::InterfaceError::SendFailed(format!("rnode serial open: {}", e))
            })?
        }
        PortConfig::Tcp { addr } => {
            tracing::info!(
                name = %config.name,
                addr = %addr,
                "RNode TCP interface connecting"
            );
            let addr = addr.clone();
            tokio::task::spawn_blocking(move || RNodeStream::connect_tcp(&addr))
                .await
                .map_err(|e| {
                    crate::traits::InterfaceError::SendFailed(format!("rnode tcp spawn: {}", e))
                })?
                .map_err(|e| {
                    crate::traits::InterfaceError::SendFailed(format!("rnode tcp connect: {}", e))
                })?
        }
    };

    tracing::info!(
        name = %config.name,
        endpoint = %port.description(),
        freq = config.frequency,
        bw = config.bandwidth,
        sf = config.spreading_factor,
        "RNode interface opened"
    );

    {
        let mut detect_port = port.try_clone().map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode clone: {}", e))
        })?;
        let detect_seq = build_detect_sequence();
        use std::io::Write;
        detect_port.write_all(&detect_seq).map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode detect write: {}", e))
        })?;
        detect_port.flush().map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode detect flush: {}", e))
        })?;
    }

    {
        let mut init_port = port.try_clone().map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode clone: {}", e))
        })?;
        let init_seq = build_init_sequence(config);
        use std::io::Write;
        init_port.write_all(&init_seq).map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode init write: {}", e))
        })?;
        init_port.flush().map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode init flush: {}", e))
        })?;
    }

    Ok(port)
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn reconnect_delay() -> Duration {
    #[cfg(test)]
    {
        Duration::from_millis(100)
    }
    #[cfg(not(test))]
    {
        Duration::from_secs(RECONNECT_WAIT)
    }
}

#[derive(Debug, Clone)]
pub struct RNodeConfig {
    pub name: String,
    /// Serial device path (`/dev/ttyUSB0`) **or** TCP URL (`tcp://host[:port]`).
    pub port: String,
    pub baud_rate: u32,
    /// Hz.
    pub frequency: u32,
    /// Hz.
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    /// dBm.
    pub tx_power: u8,
    pub mode: InterfaceMode,
    pub flow_control: bool,
    /// Short-term airtime cap, percent (0.0..100.0). `None` = unlimited.
    pub st_alock: Option<f32>,
    /// Long-term airtime cap, percent (0.0..100.0). `None` = unlimited.
    pub lt_alock: Option<f32>,
    /// Station-ID beacon: seconds between IDs, armed by data TX
    /// (Python `id_interval`/`id_callsign`, callsign max 32 bytes).
    pub id_interval: Option<u64>,
    pub id_callsign: Option<Vec<u8>>,
}

/// A generic RNode configuration field rejected before any device I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RNodeConfigField {
    Frequency,
    Bandwidth,
    SpreadingFactor,
    CodingRate,
    TxPower,
    ShortTermAirtime,
    LongTermAirtime,
}

impl RNodeConfigField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Frequency => "frequency",
            Self::Bandwidth => "bandwidth",
            Self::SpreadingFactor => "spreadingfactor",
            Self::CodingRate => "codingrate",
            Self::TxPower => "txpower",
            Self::ShortTermAirtime => "airtime_limit_short",
            Self::LongTermAirtime => "airtime_limit_long",
        }
    }
}

impl std::fmt::Display for RNodeConfigField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Typed failure returned by [`RNodeConfig::validate`].
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum RNodeConfigValidationError {
    #[error("{value} is outside {minimum}..={maximum}")]
    OutOfRange {
        field: RNodeConfigField,
        value: f64,
        minimum: f64,
        maximum: f64,
    },
    #[error("must be finite, got {value}")]
    NonFinite { field: RNodeConfigField, value: f32 },
}

impl RNodeConfigValidationError {
    pub const fn field(&self) -> RNodeConfigField {
        match self {
            Self::OutOfRange { field, .. } | Self::NonFinite { field, .. } => *field,
        }
    }
}

/// Python `RNodeInterface.CALLSIGN_MAX_LEN`.
pub const CALLSIGN_MAX_LEN: usize = 32;

impl RNodeConfig {
    pub fn new(name: &str, port: &str) -> Self {
        Self {
            name: name.to_string(),
            port: port.to_string(),
            baud_rate: 115200,
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

    /// Validate all generic RNode RF and airtime settings without touching the
    /// configured endpoint. These bounds match upstream RNodeInterface 1.4.
    pub fn validate(&self) -> Result<(), RNodeConfigValidationError> {
        validate_integer_range(
            RNodeConfigField::Frequency,
            self.frequency,
            RNODE_FREQUENCY_MIN_HZ,
            RNODE_FREQUENCY_MAX_HZ,
        )?;
        validate_integer_range(
            RNodeConfigField::Bandwidth,
            self.bandwidth,
            RNODE_BANDWIDTH_MIN_HZ,
            RNODE_BANDWIDTH_MAX_HZ,
        )?;
        validate_integer_range(
            RNodeConfigField::SpreadingFactor,
            self.spreading_factor,
            RNODE_SPREADING_FACTOR_MIN,
            RNODE_SPREADING_FACTOR_MAX,
        )?;
        validate_integer_range(
            RNodeConfigField::CodingRate,
            self.coding_rate,
            RNODE_CODING_RATE_MIN,
            RNODE_CODING_RATE_MAX,
        )?;
        validate_integer_range(
            RNodeConfigField::TxPower,
            self.tx_power,
            RNODE_TX_POWER_MIN_DBM,
            RNODE_TX_POWER_MAX_DBM,
        )?;
        validate_airtime(RNodeConfigField::ShortTermAirtime, self.st_alock)?;
        validate_airtime(RNodeConfigField::LongTermAirtime, self.lt_alock)?;
        Ok(())
    }
}

fn validate_integer_range<T>(
    field: RNodeConfigField,
    value: T,
    minimum: T,
    maximum: T,
) -> Result<(), RNodeConfigValidationError>
where
    T: Copy + PartialOrd + Into<f64>,
{
    if value < minimum || value > maximum {
        return Err(RNodeConfigValidationError::OutOfRange {
            field,
            value: value.into(),
            minimum: minimum.into(),
            maximum: maximum.into(),
        });
    }
    Ok(())
}

fn validate_airtime(
    field: RNodeConfigField,
    value: Option<f32>,
) -> Result<(), RNodeConfigValidationError> {
    let Some(value) = value else {
        return Ok(());
    };
    if !value.is_finite() {
        return Err(RNodeConfigValidationError::NonFinite { field, value });
    }
    if !(0.0..=100.0).contains(&value) {
        return Err(RNodeConfigValidationError::OutOfRange {
            field,
            value: f64::from(value),
            minimum: 0.0,
            maximum: 100.0,
        });
    }
    Ok(())
}

/// LoRa on-air bps via `SF * (4/CR) / (2^SF / BW_kHz) * 1000`. 0 on invalid.
pub fn calculate_bitrate(sf: u8, cr: u8, bandwidth_hz: u32) -> u64 {
    if sf == 0 || cr == 0 || bandwidth_hz == 0 {
        return 0;
    }
    let sf_f = sf as f64;
    let cr_f = cr as f64;
    let bw_khz = bandwidth_hz as f64 / 1000.0;
    let two_pow_sf = (2.0_f64).powf(sf_f);
    if two_pow_sf == 0.0 {
        return 0;
    }
    let bitrate = sf_f * (4.0 / cr_f) / (two_pow_sf / bw_khz) * 1000.0;
    if bitrate.is_finite() && bitrate > 0.0 {
        bitrate as u64
    } else {
        0
    }
}

pub fn build_detect_sequence() -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    kiss::frame_with_command_into(CMD_DETECT, &[DETECT_REQ], &mut out);
    kiss::frame_with_command_into(CMD_FW_VERSION, &[0x00], &mut out);
    kiss::frame_with_command_into(CMD_PLATFORM, &[0x00], &mut out);
    kiss::frame_with_command_into(CMD_MCU, &[0x00], &mut out);
    out
}

/// Airtime-lock commands. Percent is encoded as `(percent * 100)` big-endian u16.
pub fn build_airtime_sequence(config: &RNodeConfig) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    if let Some(st) = config.st_alock {
        let at = (st * 100.0) as u16;
        let c1 = (at >> 8) as u8;
        let c2 = (at & 0xFF) as u8;
        kiss::frame_with_command_into(CMD_ST_ALOCK, &[c1, c2], &mut out);
    }
    if let Some(lt) = config.lt_alock {
        let at = (lt * 100.0) as u16;
        let c1 = (at >> 8) as u8;
        let c2 = (at & 0xFF) as u8;
        kiss::frame_with_command_into(CMD_LT_ALOCK, &[c1, c2], &mut out);
    }
    out
}

fn u32_to_bytes(val: u32) -> [u8; 4] {
    val.to_be_bytes()
}

/// KISS init sequence. Order matters: turn the radio off first so persisted
/// TNC startup profiles cannot keep old parameters active, airtime locks
/// precede RADIO_STATE=ON, and RADIO_STATE=ON must be last.
pub fn build_init_sequence(config: &RNodeConfig) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_OFF], &mut out);
    kiss::frame_with_command_into(CMD_FREQUENCY, &u32_to_bytes(config.frequency), &mut out);
    kiss::frame_with_command_into(CMD_BANDWIDTH, &u32_to_bytes(config.bandwidth), &mut out);
    kiss::frame_with_command_into(CMD_SF, &[config.spreading_factor], &mut out);
    kiss::frame_with_command_into(CMD_CR, &[config.coding_rate], &mut out);
    kiss::frame_with_command_into(CMD_TXPOWER, &[config.tx_power], &mut out);
    out.extend_from_slice(&build_airtime_sequence(config));
    kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_ON], &mut out);
    out
}

/// KISS sequence for returning an RNode radio to idle before disconnecting.
pub fn build_radio_off_sequence() -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_OFF], &mut out);
    out
}

/// KISS sequence matching upstream RNodeInterface.detach(): radio off, then
/// leave host-controlled mode so device UI state is reset before disconnect.
pub fn build_detach_sequence() -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_OFF], &mut out);
    kiss::frame_with_command_into(CMD_LEAVE, &[0xFF], &mut out);
    out
}

// Hot-path interface adapters pass this enum around directly; boxing the
// packet variant would add allocation to every received frame.
#[allow(clippy::large_enum_variant)]
pub enum RNodeResponse {
    Packet(TransportMessage),
    Ready(bool),
    None,
}

/// Python: raw unsigned RSSI byte minus `RSSI_OFFSET` (157) → dBm.
pub fn decode_rssi_byte(byte: u8) -> f32 {
    byte as f32 - RSSI_OFFSET as f32
}

/// Python: signed SNR byte × 0.25 → dB.
pub fn decode_snr_byte(byte: u8) -> f32 {
    byte as i8 as f32 / 4.0
}

/// Official RNode battery telemetry is `[state, percent]`, not millivolts.
pub fn decode_battery_status(frame: &[u8]) -> Option<(u8, u8)> {
    (frame.len() >= 2).then(|| (frame[0], frame[1].min(100)))
}

/// Official RNode temperature telemetry stores Celsius with a +120 offset.
pub fn decode_temperature_byte(byte: u8) -> Option<i8> {
    let temperature_c = i16::from(byte) - 120;
    (-30..=90)
        .contains(&temperature_c)
        .then_some(temperature_c as i8)
}

/// Dispatch decoded KISS frame; shared by serial and BLE transports.
pub fn process_rnode_response(
    cmd: u8,
    frame: &[u8],
    id: InterfaceId,
    last_rssi: &mut Option<f32>,
    last_snr: &mut Option<f32>,
) -> RNodeResponse {
    match cmd {
        kiss::CMD_DATA => {
            if frame.is_empty() {
                return RNodeResponse::None;
            }
            let msg = TransportMessage::Inbound(InboundPacket {
                raw: Bytes::copy_from_slice(frame),
                interface_id: id,
                rssi: *last_rssi,
                snr: *last_snr,
                q: None,
            });
            // RSSI/SNR stats attach to the next data frame; clear once consumed.
            *last_rssi = None;
            *last_snr = None;
            RNodeResponse::Packet(msg)
        }
        CMD_STAT_RSSI => {
            if !frame.is_empty() {
                *last_rssi = Some(decode_rssi_byte(frame[0]));
            }
            RNodeResponse::None
        }
        CMD_STAT_SNR => {
            if !frame.is_empty() {
                *last_snr = Some(decode_snr_byte(frame[0]));
            }
            RNodeResponse::None
        }
        CMD_READY => {
            let is_ready = frame.first().copied().unwrap_or(0) != 0;
            RNodeResponse::Ready(is_ready)
        }
        CMD_DETECT => {
            if frame.first().copied() == Some(DETECT_RESP) {
                tracing::info!(id, "RNode detected");
            }
            RNodeResponse::None
        }
        CMD_RADIO_STATE => {
            if frame.first().copied() == Some(RADIO_STATE_ON) {
                tracing::info!(id, "RNode radio online");
            } else {
                tracing::warn!(id, "RNode radio offline");
            }
            RNodeResponse::None
        }
        CMD_FW_VERSION => {
            if frame.len() >= 2 {
                let major = frame[0];
                let minor = frame[1];
                tracing::info!(
                    id,
                    major,
                    minor,
                    "RNode firmware version {}.{}",
                    major,
                    minor,
                );
                if major < REQUIRED_FW_VER_MAJ
                    || (major == REQUIRED_FW_VER_MAJ && minor < REQUIRED_FW_VER_MIN)
                {
                    tracing::warn!(
                        id,
                        "RNode firmware {}.{} below required {}.{}",
                        major,
                        minor,
                        REQUIRED_FW_VER_MAJ,
                        REQUIRED_FW_VER_MIN,
                    );
                }
            }
            RNodeResponse::None
        }
        CMD_ST_ALOCK => {
            if frame.len() >= 2 {
                let at = ((frame[0] as u16) << 8) | frame[1] as u16;
                let pct = at as f32 / 100.0;
                tracing::debug!(id, "RNode short-term airtime limit: {:.2}%", pct);
            }
            RNodeResponse::None
        }
        CMD_LT_ALOCK => {
            if frame.len() >= 2 {
                let at = ((frame[0] as u16) << 8) | frame[1] as u16;
                let pct = at as f32 / 100.0;
                tracing::debug!(id, "RNode long-term airtime limit: {:.2}%", pct);
            }
            RNodeResponse::None
        }
        CMD_STAT_BAT => {
            if let Some((state, percent)) = decode_battery_status(frame) {
                tracing::debug!(
                    id,
                    battery_state = state,
                    battery_percent = percent,
                    "RNode battery status"
                );
            }
            RNodeResponse::None
        }
        CMD_STAT_TEMP => {
            if let Some(temperature_c) = frame
                .first()
                .and_then(|byte| decode_temperature_byte(*byte))
            {
                tracing::debug!(id, temperature_c, "RNode temperature");
            }
            RNodeResponse::None
        }
        CMD_RADIO_LOCK => {
            let locked = frame.first().copied().unwrap_or(0) != 0;
            tracing::debug!(id, locked, "RNode radio lock state");
            RNodeResponse::None
        }
        CMD_ERROR => {
            tracing::warn!(
                id,
                error_code = frame.first().copied().unwrap_or(0),
                "RNode reported error"
            );
            RNodeResponse::None
        }
        _ => {
            tracing::debug!(id, cmd, "RNode: ignoring KISS command");
            RNodeResponse::None
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
/// Compatibility facade returning the original generic interface handle.
pub async fn spawn_rnode_interface(
    config: RNodeConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    Ok(spawn_rnode_interface_with_driver(config, id, transport_tx)
        .await?
        .interface)
}

/// Spawn a generic serial/RNode-TCP interface with local lifecycle observation.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub async fn spawn_rnode_interface_with_driver(
    config: RNodeConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<SpawnedRNodeInterface, crate::traits::InterfaceError> {
    config.validate().map_err(|error| {
        crate::traits::InterfaceError::SendFailed(format!(
            "rnode config {}: {error}",
            error.field()
        ))
    })?;
    let protocol_target = RNodeProtocolTarget::new(
        config.frequency,
        config.bandwidth,
        config.spreading_factor,
        config.coding_rate,
        config.tx_power,
    );

    let port_cfg = PortConfig::parse(&config.port, config.baud_rate).map_err(|e| {
        crate::traits::InterfaceError::SendFailed(format!("rnode port parse: {}", e))
    })?;
    let transport = match &port_cfg {
        #[cfg(feature = "serial")]
        PortConfig::Serial { .. } => RNodeTransportClass::Serial,
        PortConfig::Tcp { .. } => RNodeTransportClass::Tcp,
    };

    let port = open_configured_rnode_stream(&config, &port_cfg).await?;
    let (snapshot_tx, snapshot_rx) =
        watch::channel(Arc::new(RNodeRuntimeSnapshot::initial(transport)));
    let driver = RNodeDriverHandle { state: snapshot_rx };

    let bitrate = calculate_bitrate(
        config.spreading_factor,
        config.coding_rate,
        config.bandwidth,
    );
    tracing::info!(
        bitrate_bps = bitrate,
        bitrate_kbps = format!("{:.2}", bitrate as f64 / 1000.0),
        "RNode on-air bitrate calculated"
    );

    let online = Arc::new(AtomicBool::new(true));
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<Bytes>(256);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
    let stop_guard = register_rnode_stop(id, stop_tx);
    let name = config.name.clone();
    let mode = config.mode;
    let flow_control = config.flow_control;
    // Python RNodeInterface.py:333-343: oversized callsigns disable beaconing.
    let beacon: Option<(Duration, Bytes)> = config
        .id_interval
        .zip(config.id_callsign.clone())
        .filter(|(_, callsign)| {
            let ok = callsign.len() <= CALLSIGN_MAX_LEN;
            if !ok {
                tracing::error!(
                    name = %config.name,
                    len = callsign.len(),
                    "id_callsign exceeds {CALLSIGN_MAX_LEN} bytes, beaconing disabled"
                );
            }
            ok
        })
        .map(|(interval, callsign)| (Duration::from_secs(interval), Bytes::from(callsign)));

    let online_r = online.clone();
    let rxb_r = shared_rxb.clone();
    let txb_r = shared_txb.clone();
    let task_config = config.clone();
    let task_port_cfg = port_cfg.clone();
    let task_name = config.name.clone();
    let read_task = tokio::spawn(async move {
        let mut snapshot_publisher = RNodeSnapshotPublisher::new(snapshot_tx);
        let _stop_guard = stop_guard;
        let mut next_port = Some(port);

        loop {
            if stop_rx.try_recv().is_ok() {
                tracing::info!(name = %task_name, "RNode stop requested before reconnect");
                snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                return;
            }
            let mut port_r = match next_port.take() {
                Some(port) => port,
                None => {
                    snapshot_publisher.reconnect_started();
                    match open_configured_rnode_stream(&task_config, &task_port_cfg).await {
                        Ok(port) => port,
                        Err(e) => {
                            online_r.store(false, Ordering::SeqCst);
                            snapshot_publisher.connection_attempt_failed();
                            tracing::warn!(
                                name = %task_name,
                                error = %e,
                                "RNode reconnect failed"
                            );
                            tokio::select! {
                                _ = stop_rx.recv() => {
                                    tracing::info!(name = %task_name, "RNode stop requested during reconnect backoff");
                                    snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                                    snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                                    return;
                                }
                                _ = tokio::time::sleep(reconnect_delay()) => {}
                            }
                            continue;
                        }
                    }
                }
            };

            online_r.store(true, Ordering::SeqCst);
            let port_write = match port_r.try_clone() {
                Ok(port) => port,
                Err(e) => {
                    tracing::warn!(error = %e, "RNode clone failed before reconnect");
                    online_r.store(false, Ordering::SeqCst);
                    snapshot_publisher.connection_attempt_failed();
                    tokio::select! {
                        _ = stop_rx.recv() => {
                            tracing::info!(name = %task_name, "RNode stop requested during reconnect backoff");
                            snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                            snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                            return;
                        }
                        _ = tokio::time::sleep(reconnect_delay()) => {}
                    }
                    continue;
                }
            };
            let mut protocol_state = RNodeProtocolState::new(protocol_target);
            snapshot_publisher.connection_established();

            let ready = Arc::new(AtomicBool::new(true));
            let (conn_tx, mut conn_rx) = mpsc::channel::<RNodeWriteRequest>(256);
            let conn_tx_for_stop = conn_tx.clone();

            let online_w = online_r.clone();
            let ready_w = ready.clone();
            let txb_w = txb_r.clone();
            let beacon_w = beacon.clone();
            let write_handle = tokio::spawn(async move {
                let mut port_w = port_write;
                // Python first_tx semantics: armed by data TX, cleared when
                // the callsign beacon goes out (RNodeInterface.py:712-718, 1142-1146).
                let mut first_tx: Option<tokio::time::Instant> = None;
                loop {
                    let request = if let Some((interval, ref callsign)) = beacon_w {
                        match tokio::time::timeout(Duration::from_secs(1), conn_rx.recv()).await {
                            Ok(Some(request)) => request,
                            Ok(None) => break,
                            Err(_) => {
                                if first_tx.is_none_or(|t| t.elapsed() < interval) {
                                    continue;
                                }
                                tracing::debug!("RNode transmitting station-ID beacon");
                                RNodeWriteRequest::Packet(callsign.clone())
                            }
                        }
                    } else {
                        match conn_rx.recv().await {
                            Some(request) => request,
                            None => break,
                        }
                    };
                    let (framed, is_packet, done_tx) = match request {
                        RNodeWriteRequest::Packet(data) => {
                            if let Some((_, ref callsign)) = beacon_w {
                                if data == *callsign {
                                    first_tx = None;
                                } else if first_tx.is_none() {
                                    first_tx = Some(tokio::time::Instant::now());
                                }
                            }
                            if let Ok((header, _)) = rns_wire::header::PacketHeader::unpack(&data) {
                                tracing::debug!(
                                    id,
                                    raw_len = data.len(),
                                    packet_type = ?header.flags.packet_type,
                                    context = ?header.context,
                                    dest = %hex::encode(header.destination_hash),
                                    "RNode queued packet"
                                );
                            } else {
                                tracing::debug!(id, raw_len = data.len(), "RNode queued packet");
                            }
                            txb_w
                                .fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                            (kiss::frame(&data), true, None)
                        }
                        RNodeWriteRequest::Raw(frame, done_tx) => (frame, false, Some(done_tx)),
                    };
                    if is_packet && flow_control {
                        while !ready_w.load(Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            if !online_w.load(Ordering::SeqCst) {
                                return;
                            }
                        }
                    }
                    let framed_len = framed.len();
                    let result = crate::serial_io::blocking_write_all(port_w, framed).await;
                    if let Some(done_tx) = done_tx {
                        let _ = done_tx.send(());
                    }
                    match result {
                        Ok(p) => {
                            if is_packet {
                                tracing::debug!(id, framed_len, "RNode packet write complete");
                            }
                            port_w = p;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "RNode write error");
                            online_w.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            });

            let rx_ref = rx.clone();
            let fwd_handle = tokio::spawn(async move {
                let mut guard = rx_ref.lock().await;
                while let Some(data) = guard.recv().await {
                    if conn_tx.send(RNodeWriteRequest::Packet(data)).await.is_err() {
                        break;
                    }
                }
            });

            let mut deframer = kiss::RawKissDeframer::new();
            let mut buf = [0u8; 1024];
            let mut last_rssi: Option<f32> = None;
            let mut last_snr: Option<f32> = None;
            let mut transport_closed = false;
            let mut stop_requested = false;

            loop {
                if stop_rx.try_recv().is_ok() {
                    tracing::info!(name = %task_name, "RNode stop requested");
                    snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                    send_detach_request(&conn_tx_for_stop, id).await;
                    stop_requested = true;
                    break;
                }
                if !online_r.load(Ordering::SeqCst) {
                    break;
                }
                let result =
                    tokio::task::spawn_blocking(move || read_rnode_stream(port_r, buf)).await;

                match result {
                    Ok(Ok((p, b, n))) => {
                        port_r = p;
                        buf = b;
                        if n > 0 {
                            for (cmd, frame) in deframer.feed(&buf[..n]) {
                                let effect = protocol_state.apply_frame(cmd, &frame);
                                snapshot_publisher.protocol_effect(&protocol_state, effect);
                                match process_rnode_response(
                                    cmd,
                                    &frame,
                                    id,
                                    &mut last_rssi,
                                    &mut last_snr,
                                ) {
                                    RNodeResponse::Packet(msg) => {
                                        rxb_r.fetch_add(
                                            frame.len() as u64,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                        if transport_tx.send(msg).await.is_err() {
                                            tracing::warn!(id, "transport channel closed");
                                            transport_closed = true;
                                            break;
                                        }
                                    }
                                    RNodeResponse::Ready(is_ready) => {
                                        ready.store(is_ready, Ordering::SeqCst);
                                    }
                                    RNodeResponse::None => {}
                                }
                            }
                            if transport_closed {
                                break;
                            }
                        }
                    }
                    Ok(Err((_p, e))) => {
                        tracing::warn!(error = %e, "RNode read error");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "RNode read task panicked");
                        break;
                    }
                }
            }

            if transport_closed {
                snapshot_publisher.shutting_down(RNodeRuntimeReason::TransportConsumerClosed);
            }
            online_r.store(false, Ordering::SeqCst);
            fwd_handle.abort();
            let _ = fwd_handle.await;
            write_handle.abort();
            let _ = write_handle.await;

            if stop_requested {
                snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                return;
            }
            if transport_closed {
                snapshot_publisher.stopped(RNodeRuntimeReason::TransportConsumerClosed);
                return;
            }

            snapshot_publisher.connection_lost();
            tracing::info!(name = %task_name, "RNode reconnecting");
            tokio::select! {
                _ = stop_rx.recv() => {
                    tracing::info!(name = %task_name, "RNode stop requested during reconnect backoff");
                    snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                    snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                    return;
                }
                _ = tokio::time::sleep(reconnect_delay()) => {}
            }
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

    #[test]
    fn test_rnode_config() {
        let cfg = RNodeConfig::new("rnode0", "/dev/ttyACM0");
        assert_eq!(cfg.baud_rate, 115200);
        assert_eq!(cfg.frequency, 868_000_000);
        assert_eq!(cfg.spreading_factor, 7);
        assert!(
            !cfg.flow_control,
            "flow_control defaults off (Python parity)"
        );
        assert!(cfg.st_alock.is_none());
        assert!(cfg.lt_alock.is_none());
        assert!(cfg.validate().is_ok());
    }

    fn assert_invalid_config_field(config: &RNodeConfig, expected: RNodeConfigField) {
        let error = config.validate().expect_err("configuration must fail");
        assert_eq!(error.field(), expected, "{error}");
    }

    #[test]
    fn test_rnode_config_validation_accepts_all_inclusive_boundaries() {
        let mut config = RNodeConfig::new("rnode0", "/dev/ttyACM0");
        config.frequency = RNODE_FREQUENCY_MIN_HZ;
        config.bandwidth = RNODE_BANDWIDTH_MIN_HZ;
        config.spreading_factor = RNODE_SPREADING_FACTOR_MIN;
        config.coding_rate = RNODE_CODING_RATE_MIN;
        config.tx_power = RNODE_TX_POWER_MIN_DBM;
        config.st_alock = Some(0.0);
        config.lt_alock = Some(0.0);
        assert!(config.validate().is_ok());

        config.frequency = RNODE_FREQUENCY_MAX_HZ;
        config.bandwidth = RNODE_BANDWIDTH_MAX_HZ;
        config.spreading_factor = RNODE_SPREADING_FACTOR_MAX;
        config.coding_rate = RNODE_CODING_RATE_MAX;
        config.tx_power = RNODE_TX_POWER_MAX_DBM;
        config.st_alock = Some(100.0);
        config.lt_alock = Some(100.0);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_rnode_config_validation_rejects_each_just_outside_boundary() {
        let mut config = RNodeConfig::new("rnode0", "/dev/ttyACM0");

        config.frequency = RNODE_FREQUENCY_MIN_HZ - 1;
        assert_invalid_config_field(&config, RNodeConfigField::Frequency);
        config.frequency = RNODE_FREQUENCY_MAX_HZ + 1;
        assert_invalid_config_field(&config, RNodeConfigField::Frequency);
        config.frequency = 868_000_000;

        config.bandwidth = RNODE_BANDWIDTH_MIN_HZ - 1;
        assert_invalid_config_field(&config, RNodeConfigField::Bandwidth);
        config.bandwidth = RNODE_BANDWIDTH_MAX_HZ + 1;
        assert_invalid_config_field(&config, RNodeConfigField::Bandwidth);
        config.bandwidth = 125_000;

        config.spreading_factor = RNODE_SPREADING_FACTOR_MIN - 1;
        assert_invalid_config_field(&config, RNodeConfigField::SpreadingFactor);
        config.spreading_factor = RNODE_SPREADING_FACTOR_MAX + 1;
        assert_invalid_config_field(&config, RNodeConfigField::SpreadingFactor);
        config.spreading_factor = 7;

        config.coding_rate = RNODE_CODING_RATE_MIN - 1;
        assert_invalid_config_field(&config, RNodeConfigField::CodingRate);
        config.coding_rate = RNODE_CODING_RATE_MAX + 1;
        assert_invalid_config_field(&config, RNodeConfigField::CodingRate);
        config.coding_rate = 5;

        // The lower config stores TX power as u8, so its lower just-outside
        // case is covered at the signed runtime boundary below.
        config.tx_power = RNODE_TX_POWER_MAX_DBM + 1;
        assert_invalid_config_field(&config, RNodeConfigField::TxPower);
        config.tx_power = 14;

        config.st_alock = Some(-f32::EPSILON);
        assert_invalid_config_field(&config, RNodeConfigField::ShortTermAirtime);
        config.st_alock = Some(100.0 + f32::EPSILON * 100.0);
        assert_invalid_config_field(&config, RNodeConfigField::ShortTermAirtime);
        config.st_alock = None;

        config.lt_alock = Some(-f32::EPSILON);
        assert_invalid_config_field(&config, RNodeConfigField::LongTermAirtime);
        config.lt_alock = Some(100.0 + f32::EPSILON * 100.0);
        assert_invalid_config_field(&config, RNodeConfigField::LongTermAirtime);
    }

    #[test]
    fn test_rnode_config_validation_rejects_non_finite_airtime() {
        for invalid in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut config = RNodeConfig::new("rnode0", "/dev/ttyACM0");
            config.st_alock = Some(invalid);
            assert_invalid_config_field(&config, RNodeConfigField::ShortTermAirtime);

            config.st_alock = None;
            config.lt_alock = Some(invalid);
            assert_invalid_config_field(&config, RNodeConfigField::LongTermAirtime);
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_invalid_rnode_config_fails_before_endpoint_parsing() {
        let mut config = RNodeConfig::new("rnode-invalid", "tcp://");
        config.frequency = RNODE_FREQUENCY_MIN_HZ - 1;
        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(1);

        let error = match spawn_rnode_interface(config, 1, transport_tx).await {
            Err(error) => error,
            Ok(_) => panic!("invalid RF configuration must fail"),
        };
        let message = error.to_string();
        assert!(message.contains("frequency"), "{message}");
        assert!(!message.contains("port parse"), "{message}");
    }

    /// Python parity (RNodeInterface.py:878,880): RSSI = raw byte − 157,
    /// SNR = signed byte × 0.25.
    #[test]
    fn test_rssi_snr_decode_matches_python() {
        assert_eq!(decode_rssi_byte(67), -90.0);
        assert_eq!(decode_rssi_byte(157), 0.0);
        assert_eq!(decode_rssi_byte(0), -157.0);
        assert_eq!(decode_snr_byte(20), 5.0);
        assert_eq!(decode_snr_byte(0xF6), -2.5); // -10 as i8

        let mut rssi = None;
        let mut snr = None;
        let resp = process_rnode_response(CMD_STAT_RSSI, &[67], 0, &mut rssi, &mut snr);
        assert!(matches!(resp, RNodeResponse::None));
        assert_eq!(rssi, Some(-90.0));
    }

    #[test]
    fn test_battery_and_temperature_decode_match_official_rnode_wire_format() {
        assert_eq!(decode_battery_status(&[0x02, 73]), Some((0x02, 73)));
        assert_eq!(decode_battery_status(&[0x01, 140]), Some((0x01, 100)));
        assert_eq!(decode_battery_status(&[0x01]), None);

        assert_eq!(decode_temperature_byte(90), Some(-30));
        assert_eq!(decode_temperature_byte(120), Some(0));
        assert_eq!(decode_temperature_byte(210), Some(90));
        assert_eq!(decode_temperature_byte(89), None);
        assert_eq!(decode_temperature_byte(211), None);
    }

    #[test]
    fn test_init_sequence_parseable() {
        let cfg = RNodeConfig::new("rnode0", "/dev/ttyACM0");
        let seq = build_init_sequence(&cfg);
        assert!(!seq.is_empty());
        assert_eq!(seq[0], kiss::FEND);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(frames.len(), 7);
        assert_eq!(frames[0], (CMD_RADIO_STATE, vec![RADIO_STATE_OFF]));
        assert_eq!(frames[6], (CMD_RADIO_STATE, vec![RADIO_STATE_ON]));
    }

    /// Byte-exact vs Python `setSTALock`/`setLTALock` (RNodeInterface.py:612-630):
    /// `at = int(pct * 100)` big-endian u16, KISS-escaped, framed per command.
    #[test]
    fn test_airtime_sequence_matches_python_encoding() {
        let mut cfg = RNodeConfig::new("rnode0", "/dev/ttyACM0");
        cfg.st_alock = Some(33.0);
        cfg.lt_alock = Some(3.3);
        let seq = build_airtime_sequence(&cfg);

        // st: 3300 = 0x0CE4, lt: 330 = 0x014A — no KISS-special bytes, framed verbatim.
        let expected = [
            kiss::FEND,
            CMD_ST_ALOCK,
            0x0C,
            0xE4,
            kiss::FEND,
            kiss::FEND,
            CMD_LT_ALOCK,
            0x01,
            0x4A,
            kiss::FEND,
        ];
        assert_eq!(seq, expected);

        cfg.st_alock = None;
        cfg.lt_alock = None;
        assert!(build_airtime_sequence(&cfg).is_empty());
    }

    /// Airtime frames are part of the radio init sequence when configured.
    #[test]
    fn test_init_sequence_includes_airtime_commands() {
        let mut cfg = RNodeConfig::new("rnode0", "/dev/ttyACM0");
        cfg.st_alock = Some(10.0);
        cfg.lt_alock = Some(1.0);
        let seq = build_init_sequence(&cfg);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        let cmds: Vec<u8> = frames.iter().map(|(c, _)| *c).collect();
        assert_eq!(frames[0], (CMD_RADIO_STATE, vec![RADIO_STATE_OFF]));
        assert_eq!(
            frames.last().unwrap(),
            &(CMD_RADIO_STATE, vec![RADIO_STATE_ON])
        );
        assert_eq!(
            cmds.iter().filter(|&&cmd| cmd == CMD_ST_ALOCK).count(),
            1,
            "init must send CMD_ST_ALOCK exactly once"
        );
        assert_eq!(
            cmds.iter().filter(|&&cmd| cmd == CMD_LT_ALOCK).count(),
            1,
            "init must send CMD_LT_ALOCK exactly once"
        );
        let radio_on = cmds.len() - 1;
        let st = cmds
            .iter()
            .position(|&cmd| cmd == CMD_ST_ALOCK)
            .expect("CMD_ST_ALOCK present");
        let lt = cmds
            .iter()
            .position(|&cmd| cmd == CMD_LT_ALOCK)
            .expect("CMD_LT_ALOCK present");
        assert!(st < radio_on, "CMD_ST_ALOCK must precede RADIO_STATE_ON");
        assert!(lt < radio_on, "CMD_LT_ALOCK must precede RADIO_STATE_ON");
    }

    #[test]
    fn test_u32_to_bytes() {
        assert_eq!(u32_to_bytes(868_000_000), 868_000_000u32.to_be_bytes());
        assert_eq!(u32_to_bytes(0x01020304), [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_calculate_bitrate() {
        // 7 * (4/5) / (2^7 / 125) * 1000 = 5468.75 bps -> 5468.
        let br = calculate_bitrate(7, 5, 125_000);
        assert_eq!(br, 5468);

        let br2 = calculate_bitrate(12, 8, 125_000);
        assert!(br2 > 0);
        assert!(br2 < br);

        assert_eq!(calculate_bitrate(0, 5, 125_000), 0);
        assert_eq!(calculate_bitrate(7, 0, 125_000), 0);
        assert_eq!(calculate_bitrate(7, 5, 0), 0);
    }

    #[test]
    fn test_detect_sequence() {
        let seq = build_detect_sequence();
        assert!(!seq.is_empty());
        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0].0, CMD_DETECT);
    }

    #[test]
    fn test_radio_off_sequence() {
        let seq = build_radio_off_sequence();
        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(frames, vec![(CMD_RADIO_STATE, vec![RADIO_STATE_OFF])]);
    }

    #[test]
    fn test_detach_sequence() {
        let seq = build_detach_sequence();
        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(
            frames,
            vec![
                (CMD_RADIO_STATE, vec![RADIO_STATE_OFF]),
                (CMD_LEAVE, vec![0xFF]),
            ]
        );
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_stop_rnode_interface_signals_registered_driver() {
        let id = 0x0BAD_5700;
        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        let guard = register_rnode_stop(id, stop_tx);

        stop_rnode_interface(id);

        assert!(stop_rx.try_recv().is_ok());
        drop(guard);
        stop_rnode_interface(id);
    }

    #[test]
    fn test_airtime_sequence() {
        let mut cfg = RNodeConfig::new("rnode0", "/dev/ttyACM0");
        assert!(build_airtime_sequence(&cfg).is_empty());

        cfg.st_alock = Some(15.0);
        cfg.lt_alock = Some(25.0);
        let seq = build_airtime_sequence(&cfg);
        assert!(!seq.is_empty());

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].0, CMD_ST_ALOCK);
        assert_eq!(frames[1].0, CMD_LT_ALOCK);
    }

    #[test]
    fn test_rnode_admin_constants_match_upstream() {
        assert_eq!(CMD_BOARD, 0x47);
        assert_eq!(CMD_BT_PIN, 0x62);
        assert_eq!(CMD_DISP_INT, 0x45);
        assert_eq!(CMD_DISP_ADR, 0x63);
        assert_eq!(CMD_WIFI_IP, 0x84);
        assert_eq!(CMD_WIFI_NM, 0x85);
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_port_config_serial() {
        let cfg = PortConfig::parse("/dev/ttyUSB0", 115200).unwrap();
        assert!(matches!(cfg, PortConfig::Serial { path, .. } if path == "/dev/ttyUSB0"));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_default_port() {
        let cfg = PortConfig::parse("tcp://192.168.1.1", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "192.168.1.1:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_explicit_port() {
        let cfg = PortConfig::parse("tcp://192.168.1.1:9000", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "192.168.1.1:9000"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_hostname() {
        let cfg = PortConfig::parse("tcp://rnode.local", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "rnode.local:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_case_insensitive_scheme() {
        let cfg = PortConfig::parse("TCP://rnode.local", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "rnode.local:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_empty_host_rejected() {
        let err = PortConfig::parse("tcp://", 115200).unwrap_err();
        assert!(err.contains("missing TCP host"));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_invalid_port_rejected() {
        let err = PortConfig::parse("tcp://rnode.local:notaport", 115200).unwrap_err();
        assert!(err.contains("invalid TCP port"));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_missing_port_rejected() {
        let err = PortConfig::parse("tcp://rnode.local:", 115200).unwrap_err();
        assert!(err.contains("missing TCP port"));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_bracketed_ipv6_default_port() {
        let cfg = PortConfig::parse("tcp://[2001:db8::1]", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "[2001:db8::1]:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_bracketed_ipv6_explicit_port() {
        let cfg = PortConfig::parse("tcp://[2001:db8::1]:9000", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "[2001:db8::1]:9000"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_unbracketed_ipv6_default_port() {
        let cfg = PortConfig::parse("tcp://2001:db8::1", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "[2001:db8::1]:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_malformed_bracketed_ipv6_rejected() {
        let err = PortConfig::parse("tcp://[2001:db8::1", 115200).unwrap_err();
        assert!(err.contains("missing closing"));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn tcp_startup_bytes(config: &RNodeConfig) -> Vec<u8> {
        let mut startup = build_detect_sequence();
        startup.extend_from_slice(&build_init_sequence(config));
        startup
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn read_exact_tcp(stream: &mut std::net::TcpStream, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        std::io::Read::read_exact(stream, &mut bytes).unwrap();
        bytes
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn assert_protocol_observations_unknown(snapshot: &RNodeRuntimeSnapshot) {
        assert_eq!(snapshot.detection, RNodeDetectionState::Unknown);
        assert_eq!(
            snapshot.firmware_compatibility,
            RNodeFirmwareCompatibility::Unknown
        );
        assert_eq!(snapshot.configuration, RNodeConfigurationState::Unknown);
        assert_eq!(snapshot.radio, RNodeObservedRadioState::Unknown);
        assert_eq!(snapshot.transmit_flow, RNodeTransmitFlowState::Unknown);
        assert_ne!(snapshot.phase, RNodeRuntimePhase::Ready);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    const TEST_PROTOCOL_TARGET: RNodeProtocolTarget =
        RNodeProtocolTarget::new(915_000_000, 125_000, 7, 5, 17);

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn protocol_required_frames(target: RNodeProtocolTarget) -> [(u8, Vec<u8>); 8] {
        [
            (CMD_DETECT, vec![DETECT_RESP]),
            (
                CMD_FW_VERSION,
                vec![REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN],
            ),
            (CMD_FREQUENCY, target.frequency.to_be_bytes().to_vec()),
            (CMD_BANDWIDTH, target.bandwidth.to_be_bytes().to_vec()),
            (CMD_SF, vec![target.spreading_factor]),
            (CMD_CR, vec![target.coding_rate]),
            (CMD_TXPOWER, vec![target.tx_power]),
            (CMD_RADIO_STATE, vec![RADIO_STATE_ON]),
        ]
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn protocol_test_snapshot() -> RNodeRuntimeSnapshot {
        let mut snapshot = RNodeRuntimeSnapshot::initial(RNodeTransportClass::Tcp);
        snapshot.phase = RNodeRuntimePhase::AwaitingReadiness;
        snapshot.connection_generation = 1;
        snapshot
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn apply_projected_frame(
        state: &mut RNodeProtocolState,
        snapshot: &mut RNodeRuntimeSnapshot,
        command: u8,
        payload: &[u8],
    ) -> bool {
        let effect = state.apply_frame(command, payload);
        project_rnode_protocol_effect(snapshot, state, effect)
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn for_each_protocol_permutation<const N: usize>(
        values: &mut [usize; N],
        size: usize,
        callback: &mut impl FnMut(&[usize; N]),
    ) {
        if size == 1 {
            callback(values);
            return;
        }

        for_each_protocol_permutation(values, size - 1, callback);
        for index in 0..(size - 1) {
            let swap_index = if size.is_multiple_of(2) { index } else { 0 };
            values.swap(swap_index, size - 1);
            for_each_protocol_permutation(values, size - 1, callback);
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_rnode_protocol_projection_is_complete_for_every_required_frame_order() {
        let frames = protocol_required_frames(TEST_PROTOCOL_TARGET);
        let mut order = [0, 1, 2, 3, 4, 5, 6, 7];
        let mut count = 0usize;

        for_each_protocol_permutation(&mut order, 8, &mut |permutation| {
            let mut state = RNodeProtocolState::new(TEST_PROTOCOL_TARGET);
            let mut snapshot = protocol_test_snapshot();

            for (position, frame_index) in permutation.iter().copied().enumerate() {
                let (command, payload) = &frames[frame_index];
                let effect = state.apply_frame(*command, payload);
                assert!(!matches!(
                    effect,
                    RNodeProtocolEffect::NoChange | RNodeProtocolEffect::Rejected(_)
                ));
                project_rnode_protocol_effect(&mut snapshot, &state, effect);
                if position < 7 {
                    assert_eq!(snapshot.phase, RNodeRuntimePhase::AwaitingReadiness);
                }
            }

            assert_eq!(snapshot.phase, RNodeRuntimePhase::Ready);
            assert_eq!(snapshot.detection, RNodeDetectionState::Confirmed);
            assert_eq!(
                snapshot.firmware_compatibility,
                RNodeFirmwareCompatibility::Supported
            );
            assert_eq!(snapshot.configuration, RNodeConfigurationState::Verified);
            assert_eq!(snapshot.radio, RNodeObservedRadioState::On);
            assert_eq!(snapshot.transmit_flow, RNodeTransmitFlowState::Unknown);
            assert_eq!(snapshot.reason, None);
            count += 1;
        });

        assert_eq!(count, 40_320);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn projected_configuration(
        frequency: u32,
        bandwidth: u32,
        spreading_factor: u8,
        coding_rate: u8,
        tx_power: u8,
    ) -> RNodeConfigurationState {
        let mut state = RNodeProtocolState::new(TEST_PROTOCOL_TARGET);
        let mut snapshot = protocol_test_snapshot();
        for (command, payload) in [
            (CMD_FREQUENCY, frequency.to_be_bytes().to_vec()),
            (CMD_BANDWIDTH, bandwidth.to_be_bytes().to_vec()),
            (CMD_SF, vec![spreading_factor]),
            (CMD_CR, vec![coding_rate]),
            (CMD_TXPOWER, vec![tx_power]),
        ] {
            apply_projected_frame(&mut state, &mut snapshot, command, &payload);
        }
        snapshot.configuration
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_rnode_protocol_projection_configuration_boundaries_and_mismatches() {
        let target = TEST_PROTOCOL_TARGET;
        for frequency in [
            target.frequency - FREQUENCY_TOLERANCE_HZ,
            target.frequency + FREQUENCY_TOLERANCE_HZ,
        ] {
            assert_eq!(
                projected_configuration(
                    frequency,
                    target.bandwidth,
                    target.spreading_factor,
                    target.coding_rate,
                    target.tx_power,
                ),
                RNodeConfigurationState::Verified
            );
        }
        for frequency in [
            target.frequency - FREQUENCY_TOLERANCE_HZ - 1,
            target.frequency + FREQUENCY_TOLERANCE_HZ + 1,
        ] {
            assert_eq!(
                projected_configuration(
                    frequency,
                    target.bandwidth,
                    target.spreading_factor,
                    target.coding_rate,
                    target.tx_power,
                ),
                RNodeConfigurationState::Mismatch
            );
        }

        for (bandwidth, spreading_factor, coding_rate, tx_power) in [
            (
                target.bandwidth - 1,
                target.spreading_factor,
                target.coding_rate,
                target.tx_power,
            ),
            (
                target.bandwidth + 1,
                target.spreading_factor,
                target.coding_rate,
                target.tx_power,
            ),
            (
                target.bandwidth,
                target.spreading_factor - 1,
                target.coding_rate,
                target.tx_power,
            ),
            (
                target.bandwidth,
                target.spreading_factor + 1,
                target.coding_rate,
                target.tx_power,
            ),
            (
                target.bandwidth,
                target.spreading_factor,
                target.coding_rate - 1,
                target.tx_power,
            ),
            (
                target.bandwidth,
                target.spreading_factor,
                target.coding_rate + 1,
                target.tx_power,
            ),
            (
                target.bandwidth,
                target.spreading_factor,
                target.coding_rate,
                target.tx_power - 1,
            ),
            (
                target.bandwidth,
                target.spreading_factor,
                target.coding_rate,
                target.tx_power + 1,
            ),
        ] {
            assert_eq!(
                projected_configuration(
                    target.frequency,
                    bandwidth,
                    spreading_factor,
                    coding_rate,
                    tx_power,
                ),
                RNodeConfigurationState::Mismatch
            );
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_rnode_protocol_projection_suppresses_hidden_value_only_publications() {
        let mut state = RNodeProtocolState::new(TEST_PROTOCOL_TARGET);
        let mut snapshot = protocol_test_snapshot();
        for (command, payload) in protocol_required_frames(TEST_PROTOCOL_TARGET) {
            apply_projected_frame(&mut state, &mut snapshot, command, &payload);
        }
        assert_eq!(snapshot.phase, RNodeRuntimePhase::Ready);

        let (state_tx, state_rx) = watch::channel(Arc::new(snapshot.clone()));
        let driver = RNodeDriverHandle { state: state_rx };
        let publisher = RNodeSnapshotPublisher::new(state_tx);
        let subscription = driver.watch();
        let retained = subscription.snapshot();

        let firmware_effect = state.apply_frame(
            CMD_FW_VERSION,
            &[REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN + 1],
        );
        assert!(matches!(
            firmware_effect,
            RNodeProtocolEffect::EvidenceChanged(_)
        ));
        let mut projected = snapshot.clone();
        assert!(!project_rnode_protocol_effect(
            &mut projected,
            &state,
            firmware_effect,
        ));
        assert_eq!(projected, snapshot);
        assert!(!publisher.protocol_effect(&state, firmware_effect));
        assert!(Arc::ptr_eq(&retained, &subscription.snapshot()));

        let frequency_effect = state.apply_frame(
            CMD_FREQUENCY,
            &(TEST_PROTOCOL_TARGET.frequency + FREQUENCY_TOLERANCE_HZ).to_be_bytes(),
        );
        assert!(matches!(
            frequency_effect,
            RNodeProtocolEffect::EvidenceChanged(_)
        ));
        assert!(!project_rnode_protocol_effect(
            &mut projected,
            &state,
            frequency_effect,
        ));
        assert_eq!(projected, snapshot);
        assert!(!publisher.protocol_effect(&state, frequency_effect));
        assert!(Arc::ptr_eq(&retained, &driver.snapshot()));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_rnode_protocol_projection_flow_never_establishes_readiness() {
        let mut state = RNodeProtocolState::new(TEST_PROTOCOL_TARGET);
        let mut snapshot = protocol_test_snapshot();

        assert!(apply_projected_frame(
            &mut state,
            &mut snapshot,
            CMD_READY,
            &[1],
        ));
        assert_eq!(snapshot.transmit_flow, RNodeTransmitFlowState::Permitted);
        assert_eq!(snapshot.phase, RNodeRuntimePhase::AwaitingReadiness);
        assert_eq!(snapshot.detection, RNodeDetectionState::Unknown);

        for (command, payload) in protocol_required_frames(TEST_PROTOCOL_TARGET) {
            apply_projected_frame(&mut state, &mut snapshot, command, &payload);
        }
        assert_eq!(snapshot.phase, RNodeRuntimePhase::Ready);

        assert!(apply_projected_frame(
            &mut state,
            &mut snapshot,
            CMD_READY,
            &[0],
        ));
        assert_eq!(snapshot.transmit_flow, RNodeTransmitFlowState::Blocked);
        assert_eq!(snapshot.phase, RNodeRuntimePhase::Ready);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_rnode_protocol_projection_maps_negative_protocol_observations() {
        let mut state = RNodeProtocolState::new(TEST_PROTOCOL_TARGET);
        let mut snapshot = protocol_test_snapshot();

        for (command, payload) in [
            (CMD_DETECT, vec![0]),
            (
                CMD_FW_VERSION,
                vec![REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN - 1],
            ),
            (CMD_RADIO_STATE, vec![RADIO_STATE_OFF]),
            (CMD_READY, vec![0]),
        ] {
            assert!(apply_projected_frame(
                &mut state,
                &mut snapshot,
                command,
                &payload,
            ));
        }

        assert_eq!(snapshot.detection, RNodeDetectionState::Unconfirmed);
        assert_eq!(
            snapshot.firmware_compatibility,
            RNodeFirmwareCompatibility::Unsupported
        );
        assert_eq!(snapshot.radio, RNodeObservedRadioState::Off);
        assert_eq!(snapshot.transmit_flow, RNodeTransmitFlowState::Blocked);
        assert_eq!(snapshot.phase, RNodeRuntimePhase::AwaitingReadiness);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_rnode_protocol_projection_rejects_malformed_frames_then_recovers() {
        let mut state = RNodeProtocolState::new(TEST_PROTOCOL_TARGET);
        let mut snapshot = protocol_test_snapshot();
        assert!(apply_projected_frame(
            &mut state,
            &mut snapshot,
            CMD_DETECT,
            &[DETECT_RESP],
        ));
        let before = snapshot.clone();

        for (command, payload) in [
            (CMD_FW_VERSION, vec![REQUIRED_FW_VER_MAJ]),
            (
                CMD_FW_VERSION,
                vec![REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN, 0],
            ),
            (CMD_RADIO_STATE, vec![2]),
            (CMD_READY, vec![1, 0]),
            (CMD_RESET, vec![0]),
            (CMD_ERROR, vec![0x7F]),
        ] {
            assert!(!apply_projected_frame(
                &mut state,
                &mut snapshot,
                command,
                &payload,
            ));
            assert_eq!(snapshot, before);
        }

        for (command, payload) in protocol_required_frames(TEST_PROTOCOL_TARGET) {
            apply_projected_frame(&mut state, &mut snapshot, command, &payload);
        }
        assert_eq!(snapshot.phase, RNodeRuntimePhase::Ready);
        assert_eq!(snapshot.configuration, RNodeConfigurationState::Verified);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_rnode_protocol_projection_reset_and_fault_reasons_are_closed_and_sticky() {
        let mut state = RNodeProtocolState::new(TEST_PROTOCOL_TARGET);
        let mut snapshot = protocol_test_snapshot();
        for (command, payload) in protocol_required_frames(TEST_PROTOCOL_TARGET) {
            apply_projected_frame(&mut state, &mut snapshot, command, &payload);
        }
        assert_eq!(snapshot.phase, RNodeRuntimePhase::Ready);

        assert!(apply_projected_frame(
            &mut state,
            &mut snapshot,
            CMD_ERROR,
            &[0x01],
        ));
        assert_eq!(snapshot.phase, RNodeRuntimePhase::AwaitingReadiness);
        assert_eq!(
            snapshot.reason,
            Some(RNodeRuntimeReason::RadioInitialisationFault)
        );

        assert!(apply_projected_frame(
            &mut state,
            &mut snapshot,
            CMD_READY,
            &[1],
        ));
        assert_eq!(
            snapshot.reason,
            Some(RNodeRuntimeReason::RadioInitialisationFault)
        );
        assert_eq!(snapshot.phase, RNodeRuntimePhase::AwaitingReadiness);

        assert!(apply_projected_frame(
            &mut state,
            &mut snapshot,
            CMD_RESET,
            &[0xF8],
        ));
        assert_protocol_observations_unknown(&snapshot);
        assert_eq!(snapshot.reason, Some(RNodeRuntimeReason::DeviceReset));

        for (position, (command, payload)) in protocol_required_frames(TEST_PROTOCOL_TARGET)
            .into_iter()
            .enumerate()
        {
            apply_projected_frame(&mut state, &mut snapshot, command, &payload);
            if position < 7 {
                assert_eq!(snapshot.reason, Some(RNodeRuntimeReason::DeviceReset));
            }
        }
        assert_eq!(snapshot.phase, RNodeRuntimePhase::Ready);
        assert_eq!(snapshot.reason, None);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    async fn wait_for_rnode_snapshot(
        state: &mut RNodeDriverSubscription,
        predicate: impl Fn(&RNodeRuntimeSnapshot) -> bool,
    ) -> Arc<RNodeRuntimeSnapshot> {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let snapshot = state.snapshot();
                if predicate(&snapshot) {
                    return snapshot;
                }
                state
                    .changed()
                    .await
                    .expect("RNode snapshot publisher ended before expected state");
            }
        })
        .await
        .expect("timed out waiting for RNode snapshot")
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn write_fragmented_tcp(stream: &mut std::net::TcpStream, bytes: &[u8]) {
        let chunk_sizes = [1, 2, 5, 3, 8];
        let mut offset = 0usize;
        let mut chunk_index = 0usize;
        while offset < bytes.len() {
            let end = (offset + chunk_sizes[chunk_index % chunk_sizes.len()]).min(bytes.len());
            std::io::Write::write_all(stream, &bytes[offset..end]).unwrap();
            offset = end;
            chunk_index += 1;
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    async fn receive_inbound_packet(
        receiver: &mut mpsc::Receiver<TransportMessage>,
    ) -> InboundPacket {
        match tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("timed out waiting for inbound RNode packet")
            .expect("transport channel closed before inbound RNode packet")
        {
            TransportMessage::Inbound(packet) => packet,
            _ => panic!("unexpected non-inbound transport message"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_driver_initial_snapshot_is_private_and_protocol_unknown() {
        const PRIVATE_NAME: &str = "PRIVATE_RNODE_NAME_SENTINEL_2d7f";

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = RNodeConfig::new(PRIVATE_NAME, &format!("tcp://{addr}"));
        config.tx_power = 17;
        let expected_startup = tcp_startup_bytes(&config);
        let server_expected_startup = expected_startup.clone();
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let (send_responses_tx, send_responses_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let startup = read_exact_tcp(&mut stream, server_expected_startup.len());
            accepted_tx.send(startup).unwrap();
            if send_responses_rx
                .recv_timeout(Duration::from_secs(3))
                .is_err()
            {
                return;
            }

            let mut responses = Vec::new();
            kiss::frame_with_command_into(CMD_DETECT, &[DETECT_RESP], &mut responses);
            kiss::frame_with_command_into(
                CMD_FW_VERSION,
                &[REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN],
                &mut responses,
            );
            kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_ON], &mut responses);
            kiss::frame_with_command_into(CMD_READY, &[1], &mut responses);
            kiss::frame_with_command_into(kiss::CMD_DATA, b"snapshot-barrier", &mut responses);
            std::io::Write::write_all(&mut stream, &responses).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(3));
        });

        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(8);
        let spawned = spawn_rnode_interface_with_driver(config, 0x2D7F, transport_tx)
            .await
            .unwrap();
        let mut state = spawned.driver.watch();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), accepted_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            expected_startup
        );
        let connected = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.phase == RNodeRuntimePhase::AwaitingReadiness
                && snapshot.connection_generation == 1
        })
        .await;
        assert_eq!(connected.transport, RNodeTransportClass::Tcp);
        assert_eq!(connected.reconnect_attempt, 0);
        assert_eq!(connected.reconnect_total, 0);
        assert_eq!(connected.disconnect_total, 0);
        assert_eq!(connected.reason, None);
        assert_protocol_observations_unknown(&connected);

        send_responses_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), transport_rx.recv())
            .await
            .unwrap()
            .expect("packet barrier must reach transport");
        let after_protocol_frames = spawned.driver.snapshot();
        assert_eq!(
            after_protocol_frames.phase,
            RNodeRuntimePhase::AwaitingReadiness
        );
        assert_eq!(
            after_protocol_frames.detection,
            RNodeDetectionState::Confirmed
        );
        assert_eq!(
            after_protocol_frames.firmware_compatibility,
            RNodeFirmwareCompatibility::Supported
        );
        assert_eq!(
            after_protocol_frames.configuration,
            RNodeConfigurationState::Unknown
        );
        assert_eq!(after_protocol_frames.radio, RNodeObservedRadioState::On);
        assert_eq!(
            after_protocol_frames.transmit_flow,
            RNodeTransmitFlowState::Permitted
        );
        assert_eq!(after_protocol_frames.reason, None);

        let debug = format!("{:?} {:?}", spawned.driver, spawned.driver.snapshot());
        assert!(!debug.contains(PRIVATE_NAME), "{debug}");
        assert!(!debug.contains(&addr.to_string()), "{debug}");

        spawned.interface.read_task.abort();
        let _ = spawned.interface.read_task.await;
        let terminal = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.phase == RNodeRuntimePhase::Stopped
                && snapshot.reason == Some(RNodeRuntimeReason::DriverTerminated)
        })
        .await;
        assert_eq!(terminal.connection_generation, 0);

        release_tx.send(()).unwrap();
        server.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_driver_projects_fragmented_reordered_controls_and_forwards_packets() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("rnode-projection", &format!("tcp://{addr}"));
        let target = RNodeProtocolTarget::new(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );
        let expected_startup = tcp_startup_bytes(&config);
        let first_packet = vec![0x01, kiss::FEND, kiss::FESC, 0x02];
        let middle_packet = b"projection-middle".to_vec();
        let final_packet = b"projection-ready".to_vec();
        let expected_rxb = (first_packet.len() + middle_packet.len() + final_packet.len()) as u64;

        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server_first_packet = first_packet.clone();
        let server_middle_packet = middle_packet.clone();
        let server_final_packet = final_packet.clone();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_nodelay(true).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(
                read_exact_tcp(&mut stream, expected_startup.len()),
                expected_startup
            );
            accepted_tx.send(()).unwrap();
            if start_rx.recv_timeout(Duration::from_secs(3)).is_err() {
                return;
            }

            let mut malformed = Vec::new();
            kiss::frame_with_command_into(CMD_READY, &[1], &mut malformed);
            kiss::frame_with_command_into(CMD_DETECT, &[], &mut malformed);
            kiss::frame_with_command_into(CMD_FW_VERSION, &[REQUIRED_FW_VER_MAJ], &mut malformed);
            kiss::frame_with_command_into(
                CMD_FW_VERSION,
                &[REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN, 0],
                &mut malformed,
            );
            kiss::frame_with_command_into(CMD_RADIO_STATE, &[2], &mut malformed);
            kiss::frame_with_command_into(CMD_READY, &[0, 1], &mut malformed);
            kiss::frame_with_command_into(CMD_RESET, &[0], &mut malformed);
            kiss::frame_with_command_into(CMD_ERROR, &[0x7F], &mut malformed);
            kiss::frame_with_command_into(kiss::CMD_DATA, &server_first_packet, &mut malformed);
            write_fragmented_tcp(&mut stream, &malformed);

            if continue_rx.recv_timeout(Duration::from_secs(3)).is_err() {
                return;
            }
            let mut valid = Vec::new();
            kiss::frame_with_command_into(
                CMD_BANDWIDTH,
                &target.bandwidth.to_be_bytes(),
                &mut valid,
            );
            kiss::frame_with_command_into(CMD_DETECT, &[DETECT_RESP], &mut valid);
            kiss::frame_with_command_into(
                CMD_FW_VERSION,
                &[REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN],
                &mut valid,
            );
            kiss::frame_with_command_into(CMD_DETECT, &[DETECT_RESP], &mut valid);
            kiss::frame_with_command_into(kiss::CMD_DATA, &server_middle_packet, &mut valid);
            kiss::frame_with_command_into(
                CMD_FREQUENCY,
                &target.frequency.to_be_bytes(),
                &mut valid,
            );
            kiss::frame_with_command_into(CMD_CR, &[target.coding_rate], &mut valid);
            kiss::frame_with_command_into(CMD_TXPOWER, &[target.tx_power], &mut valid);
            kiss::frame_with_command_into(CMD_SF, &[target.spreading_factor], &mut valid);
            kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_ON], &mut valid);
            kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_ON], &mut valid);
            kiss::frame_with_command_into(kiss::CMD_DATA, &server_final_packet, &mut valid);
            write_fragmented_tcp(&mut stream, &valid);
            let _ = release_rx.recv_timeout(Duration::from_secs(3));
        });

        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(8);
        let spawned = spawn_rnode_interface_with_driver(config, 0xF12A, transport_tx)
            .await
            .unwrap();
        let mut state = spawned.driver.watch();
        tokio::time::timeout(Duration::from_secs(2), accepted_rx.recv())
            .await
            .expect("TCP accept notification timed out")
            .expect("TCP peer ended before accept notification");
        wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.connection_generation == 1
                && snapshot.phase == RNodeRuntimePhase::AwaitingReadiness
        })
        .await;
        assert_protocol_observations_unknown(&state.snapshot());

        start_tx.send(()).unwrap();
        let first = receive_inbound_packet(&mut transport_rx).await;
        assert_eq!(first.raw.as_ref(), first_packet);
        let after_malformed = state.snapshot();
        assert_eq!(
            after_malformed.transmit_flow,
            RNodeTransmitFlowState::Permitted
        );
        assert_eq!(after_malformed.phase, RNodeRuntimePhase::AwaitingReadiness);
        assert_eq!(after_malformed.detection, RNodeDetectionState::Unknown);
        assert_eq!(
            after_malformed.firmware_compatibility,
            RNodeFirmwareCompatibility::Unknown
        );
        assert_eq!(
            after_malformed.configuration,
            RNodeConfigurationState::Unknown
        );
        assert_eq!(after_malformed.radio, RNodeObservedRadioState::Unknown);
        assert_eq!(after_malformed.reason, None);

        continue_tx.send(()).unwrap();
        let middle = receive_inbound_packet(&mut transport_rx).await;
        let final_barrier = receive_inbound_packet(&mut transport_rx).await;
        assert_eq!(middle.raw.as_ref(), middle_packet);
        assert_eq!(final_barrier.raw.as_ref(), final_packet);
        let ready = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.connection_generation == 1 && snapshot.phase == RNodeRuntimePhase::Ready
        })
        .await;
        assert_eq!(ready.detection, RNodeDetectionState::Confirmed);
        assert_eq!(
            ready.firmware_compatibility,
            RNodeFirmwareCompatibility::Supported
        );
        assert_eq!(ready.configuration, RNodeConfigurationState::Verified);
        assert_eq!(ready.radio, RNodeObservedRadioState::On);
        assert_eq!(ready.transmit_flow, RNodeTransmitFlowState::Permitted);
        assert_eq!(ready.reason, None);
        assert_eq!(
            spawned
                .interface
                .rxb
                .as_ref()
                .expect("RNode RX counter")
                .load(Ordering::Relaxed),
            expected_rxb
        );

        spawned.interface.read_task.abort();
        let _ = spawned.interface.read_task.await;
        release_tx.send(()).unwrap();
        server.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_driver_eof_reconnect_updates_generation_and_counters() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("rnode-observed-reconnect", &format!("tcp://{addr}"));
        let target = RNodeProtocolTarget::new(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );
        let expected_startup = tcp_startup_bytes(&config);
        let ready_barrier = b"generation-one-ready".to_vec();
        let server_ready_barrier = ready_barrier.clone();
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let (close_first_tx, close_first_rx) = std::sync::mpsc::channel();
        let (release_second_tx, release_second_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            first
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(
                read_exact_tcp(&mut first, expected_startup.len()),
                expected_startup
            );
            let mut ready_frames = Vec::new();
            for (command, payload) in protocol_required_frames(target) {
                kiss::frame_with_command_into(command, &payload, &mut ready_frames);
            }
            kiss::frame_with_command_into(kiss::CMD_DATA, &server_ready_barrier, &mut ready_frames);
            std::io::Write::write_all(&mut first, &ready_frames).unwrap();
            accepted_tx.send(1).unwrap();
            if close_first_rx.recv_timeout(Duration::from_secs(3)).is_err() {
                return;
            }
            first.shutdown(std::net::Shutdown::Both).unwrap();

            listener.set_nonblocking(true).unwrap();
            let accept_deadline = std::time::Instant::now() + Duration::from_secs(3);
            let (mut second, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= accept_deadline {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("second RNode TCP accept failed: {error}"),
                }
            };
            second.set_nonblocking(false).unwrap();
            second
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(
                read_exact_tcp(&mut second, expected_startup.len()),
                expected_startup
            );
            accepted_tx.send(2).unwrap();
            let _ = release_second_rx.recv_timeout(Duration::from_secs(3));
        });

        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(8);
        let spawned = spawn_rnode_interface_with_driver(config, 0xE0F1, transport_tx)
            .await
            .unwrap();
        let mut state = spawned.driver.watch();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), accepted_rx.recv())
                .await
                .expect("initial TCP accept notification timed out")
                .expect("initial TCP peer ended without notification"),
            1
        );
        let packet = receive_inbound_packet(&mut transport_rx).await;
        assert_eq!(packet.raw.as_ref(), ready_barrier);
        let first = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.connection_generation == 1 && snapshot.phase == RNodeRuntimePhase::Ready
        })
        .await;
        assert_eq!(first.reconnect_total, 0);
        assert_eq!(first.disconnect_total, 0);
        assert_eq!(first.configuration, RNodeConfigurationState::Verified);

        close_first_tx.send(()).unwrap();
        let disconnected = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.connection_generation == 0
                && snapshot.phase == RNodeRuntimePhase::ReconnectBackoff
                && snapshot.disconnect_total == 1
        })
        .await;
        assert_eq!(
            disconnected.reason,
            Some(RNodeRuntimeReason::ConnectionLost)
        );
        assert_protocol_observations_unknown(&disconnected);

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(4), accepted_rx.recv())
                .await
                .expect("reconnect TCP accept notification timed out")
                .expect("TCP peer ended before reconnect notification"),
            2
        );
        let second = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.connection_generation == 2
                && snapshot.phase == RNodeRuntimePhase::AwaitingReadiness
        })
        .await;
        assert_eq!(second.reconnect_attempt, 0);
        assert_eq!(second.reconnect_total, 1);
        assert_eq!(second.disconnect_total, 1);
        assert_eq!(second.reason, None);
        assert_protocol_observations_unknown(&second);

        spawned.interface.read_task.abort();
        let _ = spawned.interface.read_task.await;
        release_second_tx.send(()).unwrap();
        server.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_driver_retry_failures_increment_attempt_counters() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("rnode-retry-failures", &format!("tcp://{addr}"));
        let expected_startup = tcp_startup_bytes(&config);
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let (close_tx, close_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(
                read_exact_tcp(&mut stream, expected_startup.len()),
                expected_startup
            );
            accepted_tx.send(()).unwrap();
            close_rx.recv().unwrap();
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            // Dropping the listener makes every subsequent attempt fail.
        });

        let id = 0xFA11;
        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(8);
        let spawned = spawn_rnode_interface_with_driver(config, id, transport_tx)
            .await
            .unwrap();
        let mut state = spawned.driver.watch();
        accepted_rx.recv().await.unwrap();
        wait_for_rnode_snapshot(&mut state, |snapshot| snapshot.connection_generation == 1).await;

        close_tx.send(()).unwrap();
        server.join().unwrap();
        let failed = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.phase == RNodeRuntimePhase::ReconnectBackoff
                && snapshot.reason == Some(RNodeRuntimeReason::ConnectionAttemptFailed)
                && snapshot.reconnect_total >= 2
                && snapshot.reconnect_attempt >= 2
        })
        .await;
        assert_eq!(failed.connection_generation, 0);
        assert_eq!(failed.reconnect_attempt, failed.reconnect_total);
        assert_eq!(failed.disconnect_total, 1);
        assert_protocol_observations_unknown(&failed);

        stop_rnode_interface(id);
        let terminal = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.phase == RNodeRuntimePhase::Stopped
                && snapshot.reason == Some(RNodeRuntimeReason::StopRequested)
        })
        .await;
        assert_eq!(terminal.connection_generation, 0);
        assert_eq!(terminal.disconnect_total, 1);
        assert!(terminal.reconnect_total >= 2);
        let _ = spawned.interface.read_task.await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_driver_stop_is_terminal_and_preserves_exact_detach_bytes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("rnode-observed-stop", &format!("tcp://{addr}"));
        let expected_startup = tcp_startup_bytes(&config);
        let expected_detach = build_detach_sequence();
        let detach_len = expected_detach.len();
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let (detach_tx, mut detach_rx) = tokio::sync::mpsc::unbounded_channel();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(
                read_exact_tcp(&mut stream, expected_startup.len()),
                expected_startup
            );
            accepted_tx.send(()).unwrap();
            detach_tx
                .send(read_exact_tcp(&mut stream, detach_len))
                .unwrap();
        });

        let id = 0x570F;
        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(8);
        let spawned = spawn_rnode_interface_with_driver(config, id, transport_tx)
            .await
            .unwrap();
        let mut state = spawned.driver.watch();
        accepted_rx.recv().await.unwrap();
        wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.connection_generation == 1
                && snapshot.phase == RNodeRuntimePhase::AwaitingReadiness
        })
        .await;
        // This owned clone remains live through publication, detach, and task
        // completion; it cannot retain Tokio's internal watch read guard.
        let held_connected_snapshot = state.snapshot();

        stop_rnode_interface(id);
        let terminal = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.phase == RNodeRuntimePhase::Stopped
                && snapshot.reason == Some(RNodeRuntimeReason::StopRequested)
        })
        .await;
        assert_eq!(terminal.connection_generation, 0);
        assert_eq!(terminal.disconnect_total, 0);
        assert_eq!(detach_rx.recv().await.unwrap(), expected_detach);
        assert_eq!(held_connected_snapshot.connection_generation, 1);

        let _ = spawned.interface.read_task.await;
        server.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_tcp_eof_is_read_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
        });

        let stream = RNodeStream::connect_tcp(&addr.to_string()).unwrap();
        let _clone = stream.try_clone().unwrap();
        accept.join().unwrap();

        match read_rnode_stream(stream, [0u8; 1024]) {
            Ok(_) => panic!("closed TCP socket should be EOF"),
            Err((_stream, err)) => assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_tcp_connect_accepts_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
        });

        let stream =
            RNodeStream::connect_tcp_with_timeout(&addr.to_string(), Duration::from_millis(500))
                .unwrap();
        assert!(stream.is_tcp());

        drop(stream);
        accept.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_legacy_rnode_spawn_facade_reconnects_after_eof() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("rnode-tcp", &format!("tcp://{addr}"));
        let expected_init_len = build_detect_sequence().len()
            + build_init_sequence(&config).len()
            + build_airtime_sequence(&config).len();
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();

        let server = std::thread::spawn(move || {
            for attempt in 1..=2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();

                let mut buf = [0u8; 512];
                let mut total = 0usize;
                while total < expected_init_len {
                    match std::io::Read::read(&mut stream, &mut buf) {
                        Ok(0) => break,
                        Ok(n) => total += n,
                        Err(_) => break,
                    }
                }
                if attempt == 2 {
                    accepted_tx.send(attempt).unwrap();
                    std::thread::sleep(Duration::from_millis(500));
                } else {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    accepted_tx.send(attempt).unwrap();
                }
            }
        });

        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(8);
        let handle = spawn_rnode_interface(config, 77, transport_tx)
            .await
            .unwrap();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), accepted_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            1
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(7), accepted_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            2
        );
        assert!(handle.online.load(Ordering::SeqCst));

        handle.read_task.abort();
        drop(handle.tx);
        server.join().unwrap();
    }
}
