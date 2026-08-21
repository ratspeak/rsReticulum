//! LoRa radio control via RNode firmware's extended-KISS protocol.
//! Shared constants + transport-agnostic response handler. Serial:
//! [`spawn_rnode_interface`] (feature `serial`); BLE: the optional
//! `ble_rnode` module (feature `ble`).
//!
//! Transport selection is driven by the `port` string in [`RNodeConfig`]:
//!   - `/dev/ttyUSB0`, `COM3`, etc.  -> serial (feature `serial` required)
//!   - `tcp://192.168.1.1`           -> TCP, default port 7633
//!   - `tcp://192.168.1.1:9000`      -> TCP, explicit port

use bytes::Bytes;

use crate::kiss;
use crate::traits::{InterfaceHandle, InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
use crate::rnode_protocol::{
    FREQUENCY_TOLERANCE_HZ, RNodeProtocolEffect, RNodeProtocolState, RNodeRadioState,
    RNodeReadiness,
};
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use crate::{rnode_protocol::RNodeProtocolTarget, traits::InterfaceDirection};
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use std::sync::{Mutex, OnceLock};
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use std::time::Duration;
#[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android", test))]
use tokio::sync::mpsc;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use tokio::sync::oneshot;
use tokio::sync::watch;

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

/// Startup policy for an RNode transport.
///
/// The fields stay private so adding a future policy cannot silently change
/// external struct literals. [`Default`] preserves the historical startup
/// sequence exactly and does not request EEPROM contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RNodeStartupOptions {
    capability_policy: RNodeCapabilityPolicy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum RNodeCapabilityPolicy {
    #[default]
    Legacy,
    RequireValidatedAdmission,
}

impl RNodeStartupOptions {
    /// Require a validated EEPROM capability image before radio settings are
    /// sent to each connection generation.
    ///
    /// Known models enforce their reviewed frequency and TX-power limits.
    /// A validated but unknown or quarantined model is admitted explicitly as
    /// unverified; no model alias or capability profile is inferred.
    ///
    /// Each options-aware transport documents how its first connection reports
    /// admission failure. Synchronously prepared transports can return
    /// [`RNodeSpawnError::CapabilityAdmission`]; asynchronously connecting
    /// transports publish the outcome through their driver observation. A
    /// deterministic rejection after a driver has been returned terminates it
    /// with [`RNodeRuntimeReason::CapabilityAdmissionRejected`]. Ordinary
    /// transport failures retain that transport's reconnect policy.
    pub const fn require_capability_admission() -> Self {
        Self {
            capability_policy: RNodeCapabilityPolicy::RequireValidatedAdmission,
        }
    }

    #[cfg(any(
        feature = "serial",
        feature = "rnode-tcp",
        feature = "ble",
        target_os = "android"
    ))]
    pub(crate) const fn requires_capability_admission(self) -> bool {
        matches!(
            self.capability_policy,
            RNodeCapabilityPolicy::RequireValidatedAdmission
        )
    }
}

impl Default for RNodeStartupOptions {
    fn default() -> Self {
        Self {
            capability_policy: RNodeCapabilityPolicy::Legacy,
        }
    }
}

/// Typed, privacy-bounded failure from strict RNode capability admission.
///
/// No variant can retain EEPROM contents, stable device identifiers, raw
/// frames, endpoints, or unrestricted device error values.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum RNodeCapabilityAdmissionError {
    #[error("RNode capability response timed out")]
    ResponseTimedOut,
    #[error("RNode capability preflight exceeded its bounded read count ({limit})")]
    ReadLimitExceeded { limit: usize },
    #[error("RNode capability preflight exceeded its bounded input size ({limit} bytes)")]
    InputLimitExceeded { limit: usize },
    #[error("RNode capability preflight exceeded its bounded frame count ({limit})")]
    FrameLimitExceeded { limit: usize },
    #[error("RNode capability preflight received a malformed protocol frame")]
    MalformedProtocolFrame {
        rejection: crate::rnode_protocol::RNodeFrameRejection,
    },
    #[error("RNode reported a device error during capability preflight")]
    DeviceError,
    #[error("RNode detection was not confirmed during capability preflight")]
    DetectionRejected,
    #[error("RNode firmware is unsupported")]
    UnsupportedFirmware,
    #[error("RNode returned more than one EEPROM capability response")]
    DuplicateEepromResponse,
    #[error("invalid RNode EEPROM capability image: {0}")]
    CapabilityImage(#[source] crate::rnode_capabilities::RNodeCapabilityParseError),
    #[error("RNode radio settings were rejected: {0}")]
    RadioSettings(#[source] crate::rnode_capabilities::RNodeRadioAdmissionError),
}

/// Closed, privacy-safe classification of a capability admission failure.
///
/// Variants mirror [`RNodeCapabilityAdmissionError`] one-to-one but carry no
/// limits, values, or device data, so the classification can cross the
/// observation boundary. [`Self::log_class`] returns the stable log token for
/// each class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeCapabilityAdmissionFailureClass {
    ResponseTimedOut,
    ReadLimit,
    InputLimit,
    FrameLimit,
    MalformedProtocol,
    DeviceError,
    DetectionRejected,
    UnsupportedFirmware,
    DuplicateEeprom,
    InvalidCapabilityImage,
    RadioSettingsRejected,
}

impl RNodeCapabilityAdmissionFailureClass {
    /// Stable log token for this failure class.
    pub const fn log_class(self) -> &'static str {
        match self {
            Self::ResponseTimedOut => "response_timeout",
            Self::ReadLimit => "read_limit",
            Self::InputLimit => "input_limit",
            Self::FrameLimit => "frame_limit",
            Self::MalformedProtocol => "malformed_protocol",
            Self::DeviceError => "device_error",
            Self::DetectionRejected => "detection_rejected",
            Self::UnsupportedFirmware => "unsupported_firmware",
            Self::DuplicateEeprom => "duplicate_eeprom",
            Self::InvalidCapabilityImage => "invalid_capability_image",
            Self::RadioSettingsRejected => "radio_settings_rejected",
        }
    }
}

impl RNodeCapabilityAdmissionError {
    /// The privacy-safe classification for this admission failure.
    pub fn failure_class(&self) -> RNodeCapabilityAdmissionFailureClass {
        match self {
            Self::ResponseTimedOut => RNodeCapabilityAdmissionFailureClass::ResponseTimedOut,
            Self::ReadLimitExceeded { .. } => RNodeCapabilityAdmissionFailureClass::ReadLimit,
            Self::InputLimitExceeded { .. } => RNodeCapabilityAdmissionFailureClass::InputLimit,
            Self::FrameLimitExceeded { .. } => RNodeCapabilityAdmissionFailureClass::FrameLimit,
            Self::MalformedProtocolFrame { .. } => {
                RNodeCapabilityAdmissionFailureClass::MalformedProtocol
            }
            Self::DeviceError => RNodeCapabilityAdmissionFailureClass::DeviceError,
            Self::DetectionRejected => RNodeCapabilityAdmissionFailureClass::DetectionRejected,
            Self::UnsupportedFirmware => RNodeCapabilityAdmissionFailureClass::UnsupportedFirmware,
            Self::DuplicateEepromResponse => RNodeCapabilityAdmissionFailureClass::DuplicateEeprom,
            Self::CapabilityImage(_) => {
                RNodeCapabilityAdmissionFailureClass::InvalidCapabilityImage
            }
            Self::RadioSettings(_) => RNodeCapabilityAdmissionFailureClass::RadioSettingsRejected,
        }
    }

    #[cfg(any(
        feature = "serial",
        feature = "rnode-tcp",
        feature = "ble",
        target_os = "android"
    ))]
    pub(crate) fn log_class(&self) -> &'static str {
        self.failure_class().log_class()
    }
}

/// Typed startup failure for an options-aware RNode spawn API.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RNodeSpawnError {
    #[error(transparent)]
    Interface(#[from] crate::traits::InterfaceError),
    #[error(transparent)]
    CapabilityAdmission(#[from] RNodeCapabilityAdmissionError),
}

impl RNodeSpawnError {
    #[cfg(any(
        feature = "serial",
        feature = "rnode-tcp",
        feature = "ble",
        target_os = "android"
    ))]
    pub(crate) fn into_legacy_interface_error(self) -> crate::traits::InterfaceError {
        match self {
            Self::Interface(error) => error,
            Self::CapabilityAdmission(error) => crate::traits::InterfaceError::SendFailed(format!(
                "rnode capability admission: {error}"
            )),
        }
    }
}

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeTransportClass {
    Serial,
    Tcp,
    Ble,
    Usb,
}

/// Coarse lifecycle phase of the generic RNode driver.
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeDetectionState {
    Unknown,
    Confirmed,
    Unconfirmed,
}

/// Compatibility of the observed firmware with this generic RNode driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeFirmwareCompatibility {
    Unknown,
    Supported,
    Unsupported,
}

/// Verification state for the configured radio parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeConfigurationState {
    Unknown,
    Verified,
    Mismatch,
}

/// Privacy-safe capability admission state for the active connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeCapabilityState {
    /// Strict capability admission was not requested, or there is no active
    /// admitted connection generation.
    NotRequested,
    /// A validated exact model with a reviewed profile admitted the settings.
    /// Fresh post-init RF echoes are still required for runtime readiness.
    Verified,
    /// EEPROM identity validated, but the exact model is unknown or
    /// quarantined, so only generic bounds were applied. Fresh post-init RF
    /// echoes are still required for runtime readiness.
    Unverified,
    /// No locked EEPROM identity was present, so only generic bounds were
    /// applied and no product or model claim exists. Fresh post-init RF
    /// echoes are still required for runtime readiness.
    Unprovisioned,
}

/// Radio power state observed from the active RNode connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RNodeObservedRadioState {
    Unknown,
    On,
    Off,
}

/// KISS transmit-flow permission observed from the active connection.
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
    CapabilityAdmissionRejected,
}

/// Privacy-safe local observation of one generic RNode driver.
///
/// This type intentionally contains no interface id or label, path, endpoint,
/// device identity, raw error, exact firmware/RF values, telemetry, hashes,
/// EEPROM contents, or frame data.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RNodeRuntimeSnapshot {
    pub transport: RNodeTransportClass,
    pub phase: RNodeRuntimePhase,
    /// Non-zero only while a usable transport connection is active.
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
    pub capability: RNodeCapabilityState,
    pub radio: RNodeObservedRadioState,
    pub transmit_flow: RNodeTransmitFlowState,
    pub reason: Option<RNodeRuntimeReason>,
    /// Set only by a terminal capability admission rejection; identifies the
    /// failure class without carrying any device data.
    pub capability_admission_failure: Option<RNodeCapabilityAdmissionFailureClass>,
}

#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
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
            capability: RNodeCapabilityState::NotRequested,
            radio: RNodeObservedRadioState::Unknown,
            transmit_flow: RNodeTransmitFlowState::Unknown,
            reason: None,
            capability_admission_failure: None,
        }
    }

    fn reset_protocol_observations(&mut self) {
        self.detection = RNodeDetectionState::Unknown;
        self.firmware_compatibility = RNodeFirmwareCompatibility::Unknown;
        self.configuration = RNodeConfigurationState::Unknown;
        self.capability = RNodeCapabilityState::NotRequested;
        self.radio = RNodeObservedRadioState::Unknown;
        self.transmit_flow = RNodeTransmitFlowState::Unknown;
    }
}

#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
fn project_rnode_protocol_state(
    snapshot: &mut RNodeRuntimeSnapshot,
    state: &RNodeProtocolState,
) -> bool {
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

    if evidence.radio_initialisation_fault {
        snapshot.reason = Some(RNodeRuntimeReason::RadioInitialisationFault);
    }

    *snapshot != before
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn sync_rnode_interface_online(online: &AtomicBool, state: &RNodeProtocolState) {
    online.store(
        matches!(state.readiness(), RNodeReadiness::Ready),
        Ordering::SeqCst,
    );
}

#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
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
    project_rnode_protocol_state(snapshot, state);

    match effect {
        RNodeProtocolEffect::Reset => {
            snapshot.reason = Some(RNodeRuntimeReason::DeviceReset);
        }
        RNodeProtocolEffect::RadioInitialisationFault => {
            snapshot.reason = Some(RNodeRuntimeReason::RadioInitialisationFault);
        }
        RNodeProtocolEffect::EvidenceChanged(_) | RNodeProtocolEffect::FlowPermissionChanged(_) => {
            if state.evidence().radio_initialisation_fault {
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

enum RNodeDriverShutdownSignal {
    #[cfg(test)]
    InertTest,
    #[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android", test))]
    StopSender(mpsc::Sender<()>),
    #[cfg(feature = "ble")]
    RunningFlag(Arc<AtomicBool>),
}

struct RNodeDriverShutdownInner {
    requested: AtomicBool,
    signal: RNodeDriverShutdownSignal,
}

/// Exact-instance shutdown request shared by every clone of a driver handle.
///
/// This stays crate-private so observed drivers can expose only the one
/// bounded lifecycle action, never arbitrary RNode controls.
#[derive(Clone)]
pub(crate) struct RNodeDriverShutdown {
    inner: Arc<RNodeDriverShutdownInner>,
}

impl RNodeDriverShutdown {
    #[cfg(test)]
    fn inert_test() -> Self {
        Self::new(RNodeDriverShutdownSignal::InertTest)
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android", test))]
    pub(crate) fn from_stop_sender(stop_tx: mpsc::Sender<()>) -> Self {
        Self::new(RNodeDriverShutdownSignal::StopSender(stop_tx))
    }

    #[cfg(feature = "ble")]
    pub(crate) fn from_running_flag(running: Arc<AtomicBool>) -> Self {
        Self::new(RNodeDriverShutdownSignal::RunningFlag(running))
    }

    #[cfg(any(
        feature = "serial",
        feature = "rnode-tcp",
        feature = "ble",
        target_os = "android",
        test
    ))]
    fn new(signal: RNodeDriverShutdownSignal) -> Self {
        Self {
            inner: Arc::new(RNodeDriverShutdownInner {
                requested: AtomicBool::new(false),
                signal,
            }),
        }
    }

    fn request(&self) {
        if self.inner.requested.swap(true, Ordering::SeqCst) {
            return;
        }
        match &self.inner.signal {
            #[cfg(test)]
            RNodeDriverShutdownSignal::InertTest => {}
            #[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android", test))]
            RNodeDriverShutdownSignal::StopSender(stop_tx) => {
                let _ = stop_tx.try_send(());
            }
            #[cfg(feature = "ble")]
            RNodeDriverShutdownSignal::RunningFlag(running) => {
                running.store(false, Ordering::SeqCst);
            }
            #[cfg(not(any(
                feature = "serial",
                feature = "rnode-tcp",
                feature = "ble",
                target_os = "android",
                test
            )))]
            _ => unreachable!("no RNode driver transport can construct a shutdown primitive"),
        }
    }
}

/// Cloneable, privacy-safe lifecycle handle for one exact RNode driver.
#[derive(Clone)]
pub struct RNodeDriverHandle {
    state: watch::Receiver<Arc<RNodeRuntimeSnapshot>>,
    shutdown: RNodeDriverShutdown,
}

/// Clone-only subscription to generic RNode driver observations.
///
/// The underlying Tokio receiver stays private so callers cannot retain a
/// watch borrow across driver publication. Both accessors return an owned
/// [`Arc`] and release the internal borrow before returning.
#[derive(Clone)]
pub struct RNodeDriverSubscription {
    state: watch::Receiver<Arc<RNodeRuntimeSnapshot>>,
}

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

    /// Request shutdown of this exact spawned driver instance.
    ///
    /// The request is idempotent across every clone. It never resolves an
    /// interface ID or another global registry entry, so later reuse of the
    /// same ID cannot redirect it to a different session. Completion remains
    /// owned by the spawned interface task and its normal join path.
    pub fn request_shutdown(&self) {
        self.shutdown.request();
    }
}

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

impl std::fmt::Debug for RNodeDriverHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RNodeDriverHandle")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

impl std::fmt::Debug for RNodeDriverSubscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RNodeDriverSubscription")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

/// Generic interface handle paired with its local RNode driver observation.
#[non_exhaustive]
pub struct SpawnedRNodeInterface {
    pub interface: InterfaceHandle,
    pub driver: RNodeDriverHandle,
}

#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
pub(crate) struct RNodeSnapshotPublisher {
    state: watch::Sender<Arc<RNodeRuntimeSnapshot>>,
    last_connection_generation: u64,
    terminal: bool,
}

#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
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

    pub(crate) fn connection_established(&mut self) {
        self.last_connection_generation = self.last_connection_generation.saturating_add(1).max(1);
        let generation = self.last_connection_generation;
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::AwaitingReadiness;
            snapshot.connection_generation = generation;
            snapshot.reconnect_attempt = 0;
            snapshot.reason = None;
            snapshot.capability_admission_failure = None;
            snapshot.reset_protocol_observations();
        });
    }

    #[cfg(any(
        feature = "serial",
        feature = "rnode-tcp",
        feature = "ble",
        target_os = "android"
    ))]
    pub(crate) fn capability_connection_established(
        &mut self,
        state: &RNodeProtocolState,
        admission: crate::rnode_capabilities::RNodeRadioAdmission,
    ) {
        self.last_connection_generation = self.last_connection_generation.saturating_add(1).max(1);
        let generation = self.last_connection_generation;
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::AwaitingReadiness;
            snapshot.connection_generation = generation;
            snapshot.reconnect_attempt = 0;
            snapshot.reason = None;
            snapshot.capability_admission_failure = None;
            snapshot.reset_protocol_observations();
            snapshot.capability = match admission {
                crate::rnode_capabilities::RNodeRadioAdmission::Verified { .. } => {
                    RNodeCapabilityState::Verified
                }
                crate::rnode_capabilities::RNodeRadioAdmission::Unverified { .. } => {
                    RNodeCapabilityState::Unverified
                }
                crate::rnode_capabilities::RNodeRadioAdmission::Unprovisioned => {
                    RNodeCapabilityState::Unprovisioned
                }
            };
            project_rnode_protocol_state(snapshot, state);
        });
    }

    #[cfg(any(
        feature = "serial",
        feature = "rnode-tcp",
        feature = "ble",
        target_os = "android"
    ))]
    pub(crate) fn reconnect_started(&self) {
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::Connecting;
            snapshot.connection_generation = 0;
            snapshot.reconnect_attempt = snapshot.reconnect_attempt.saturating_add(1);
            snapshot.reconnect_total = snapshot.reconnect_total.saturating_add(1);
            snapshot.reason = None;
            snapshot.capability_admission_failure = None;
            snapshot.reset_protocol_observations();
        });
    }

    #[cfg(any(
        feature = "serial",
        feature = "rnode-tcp",
        feature = "ble",
        target_os = "android"
    ))]
    pub(crate) fn connection_attempt_failed(&self) {
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::ReconnectBackoff;
            snapshot.connection_generation = 0;
            snapshot.reason = Some(RNodeRuntimeReason::ConnectionAttemptFailed);
            snapshot.reset_protocol_observations();
        });
    }

    #[cfg(any(
        feature = "serial",
        feature = "rnode-tcp",
        feature = "ble",
        target_os = "android"
    ))]
    pub(crate) fn connection_lost(&self) {
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::ReconnectBackoff;
            snapshot.connection_generation = 0;
            snapshot.disconnect_total = snapshot.disconnect_total.saturating_add(1);
            snapshot.reason = Some(RNodeRuntimeReason::ConnectionLost);
            snapshot.reset_protocol_observations();
        });
    }

    pub(crate) fn protocol_effect(
        &self,
        state: &RNodeProtocolState,
        effect: RNodeProtocolEffect,
    ) -> bool {
        if self.terminal {
            return false;
        }
        if matches!(
            effect,
            RNodeProtocolEffect::NoChange | RNodeProtocolEffect::Rejected(_)
        ) {
            return false;
        }
        let mut projection_changed = false;
        let published = self.update(|snapshot| {
            let lifecycle = (snapshot.phase == RNodeRuntimePhase::ShuttingDown)
                .then_some((snapshot.phase, snapshot.reason));
            let before = snapshot.clone();
            project_rnode_protocol_effect(snapshot, state, effect);
            if let Some((phase, reason)) = lifecycle {
                snapshot.phase = phase;
                snapshot.reason = reason;
            }
            projection_changed = *snapshot != before;
        });
        debug_assert_eq!(published, projection_changed);
        published
    }

    /// Publish the current bounded reducer state without replaying raw frames.
    ///
    /// Drivers use this only after a pending handshake becomes an admitted
    /// connection generation. Startup bytes stay private to the pending
    /// reducer and cannot appear in the public observation surface. This
    /// projects durable reducer state, not transient effects.
    #[cfg(feature = "ble")]
    pub(crate) fn sync_protocol_state(&self, state: &RNodeProtocolState) -> bool {
        let mut projection_changed = false;
        let published = self.update(|snapshot| {
            projection_changed = project_rnode_protocol_state(snapshot, state);
        });
        debug_assert_eq!(published, projection_changed);
        published
    }

    pub(crate) fn shutting_down(&self, reason: RNodeRuntimeReason) {
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::ShuttingDown;
            snapshot.reason = Some(reason);
        });
    }

    pub(crate) fn stopped(&mut self, reason: RNodeRuntimeReason) {
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::Stopped;
            snapshot.connection_generation = 0;
            snapshot.reason = Some(reason);
            snapshot.reset_protocol_observations();
        });
        self.terminal = true;
    }

    /// Terminal stop for a rejected capability admission, publishing the
    /// failure class atomically with the phase and reason.
    pub(crate) fn stopped_for_admission_rejection(
        &mut self,
        failure: RNodeCapabilityAdmissionFailureClass,
    ) {
        self.update(|snapshot| {
            snapshot.phase = RNodeRuntimePhase::Stopped;
            snapshot.connection_generation = 0;
            snapshot.reason = Some(RNodeRuntimeReason::CapabilityAdmissionRejected);
            snapshot.capability_admission_failure = Some(failure);
            snapshot.reset_protocol_observations();
        });
        self.terminal = true;
    }
}

#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
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

#[cfg(test)]
pub(crate) fn new_rnode_driver_observation(
    transport: RNodeTransportClass,
) -> (RNodeSnapshotPublisher, RNodeDriverHandle) {
    new_rnode_driver_observation_with_shutdown(transport, RNodeDriverShutdown::inert_test())
}

#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
pub(crate) fn new_rnode_driver_observation_with_shutdown(
    transport: RNodeTransportClass,
    shutdown: RNodeDriverShutdown,
) -> (RNodeSnapshotPublisher, RNodeDriverHandle) {
    let (state_tx, state_rx) = watch::channel(Arc::new(RNodeRuntimeSnapshot::initial(transport)));
    (
        RNodeSnapshotPublisher::new(state_tx),
        RNodeDriverHandle {
            state: state_rx,
            shutdown,
        },
    )
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
    stop_tx: mpsc::Sender<()>,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl Drop for RNodeStopRegistryGuard {
    fn drop(&mut self) {
        let mut registry = rnode_stop_registry()
            .lock()
            .expect("rnode_stop_registry mutex poisoned");
        let owns_entry = registry
            .get(&self.id)
            .is_some_and(|registered| registered.same_channel(&self.stop_tx));
        if owns_entry {
            registry.remove(&self.id);
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn register_rnode_stop(id: InterfaceId, stop_tx: mpsc::Sender<()>) -> RNodeStopRegistryGuard {
    rnode_stop_registry()
        .lock()
        .expect("rnode_stop_registry mutex poisoned")
        .insert(id, stop_tx.clone());
    RNodeStopRegistryGuard { id, stop_tx }
}

/// Compatibility facade requesting shutdown of the currently registered
/// serial/TCP RNode for `id`.
///
/// New owners should retain [`RNodeDriverHandle`] and call
/// [`RNodeDriverHandle::request_shutdown`] so later ID reuse cannot redirect
/// the request. Unknown IDs are ignored.
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
const RNODE_PACKET_WRITE_QUEUE: usize = 256;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_CONTROL_WRITE_QUEUE: usize = 4;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_FLOW_POLL_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_BEACON_POLL_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_IDLE_PROBE_INTERVAL: Duration = Duration::from_millis(3_500);
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_STARTUP_STAGE_DEADLINE: Duration = Duration::from_secs(5);
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_DETACH_DEADLINE: Duration = Duration::from_millis(500);
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_WRITER_JOIN_DEADLINE: Duration = Duration::from_millis(500);

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RNodeWritePhase {
    Detect,
    Capability,
    Initialise,
    Packet,
    Probe,
    Detach,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl RNodeWritePhase {
    const fn label(self) -> &'static str {
        match self {
            Self::Detect => "detect",
            Self::Capability => "capability",
            Self::Initialise => "init",
            Self::Packet => "packet",
            Self::Probe => "probe",
            Self::Detach => "detach",
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Debug)]
enum RNodeWriteFailureKind {
    Write(Arc<std::io::Error>),
    Flush(Arc<std::io::Error>),
    WorkerTerminated,
    QueueClosed,
    AcknowledgementDropped,
    DeadlineElapsed,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Debug)]
struct RNodeWriteFailure {
    phase: RNodeWritePhase,
    kind: RNodeWriteFailureKind,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl std::fmt::Display for RNodeWriteFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            RNodeWriteFailureKind::Write(error) => {
                write!(formatter, "{} write: {error}", self.phase.label())
            }
            RNodeWriteFailureKind::Flush(error) => {
                write!(formatter, "{} flush: {error}", self.phase.label())
            }
            RNodeWriteFailureKind::WorkerTerminated => {
                write!(formatter, "{} writer worker terminated", self.phase.label())
            }
            RNodeWriteFailureKind::QueueClosed => {
                write!(
                    formatter,
                    "{} writer control queue closed",
                    self.phase.label()
                )
            }
            RNodeWriteFailureKind::AcknowledgementDropped => {
                write!(
                    formatter,
                    "{} writer acknowledgement dropped",
                    self.phase.label()
                )
            }
            RNodeWriteFailureKind::DeadlineElapsed => {
                write!(formatter, "{} deadline elapsed", self.phase.label())
            }
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
struct RNodeControlWriteRequest {
    phase: RNodeWritePhase,
    bytes: Vec<u8>,
    acknowledgement: oneshot::Sender<Result<(), RNodeWriteFailure>>,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RNodeWriterExit {
    Detached,
    Cancelled,
    CarrierOffline,
    LanesClosed,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RNodeWriterFinish {
    Quiesced,
    NonQuiesced,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
struct RNodeWriterContext {
    id: InterfaceId,
    flow_control: bool,
    ready: Arc<AtomicBool>,
    /// Physical stream liveness for the active connection generation.
    ///
    /// This deliberately remains separate from `interface_online`: startup
    /// controls must be writable while the public interface is still waiting
    /// for complete protocol evidence.
    carrier_online: Arc<AtomicBool>,
    /// Public/protocol readiness. Packet writes are held until the exact
    /// reducer state is ready, matching upstream's `interface_ready` gate.
    interface_online: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    txb: Arc<AtomicU64>,
    beacon: Option<(Duration, Bytes)>,
    beacon_poll_interval: Duration,
    idle_probe_interval: Option<Duration>,
    idle_probes_enabled: Arc<AtomicBool>,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
struct RNodeWriteInterrupt {
    #[cfg(feature = "serial")]
    serial: Option<Mutex<Box<dyn serialport::SerialPort>>>,
    tcp: Option<std::net::TcpStream>,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl RNodeWriteInterrupt {
    fn none() -> Self {
        Self {
            #[cfg(feature = "serial")]
            serial: None,
            tcp: None,
        }
    }

    fn from_stream(stream: &RNodeStream) -> std::io::Result<Self> {
        match stream {
            #[cfg(feature = "serial")]
            RNodeStream::Serial(stream) => Ok(Self {
                serial: Some(Mutex::new(
                    stream.try_clone().map_err(std::io::Error::other)?,
                )),
                tcp: None,
            }),
            RNodeStream::Tcp(stream) => Ok(Self {
                #[cfg(feature = "serial")]
                serial: None,
                tcp: Some(stream.try_clone()?),
            }),
        }
    }

    fn interrupt(&mut self) {
        #[cfg(feature = "serial")]
        if let Some(stream) = self.serial.take() {
            if let Err(error) = stream
                .into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear(serialport::ClearBuffer::Output)
            {
                tracing::debug!(error = %error, "RNode serial output purge during writer cleanup");
            }
        }
        if let Some(stream) = self.tcp.take() {
            if let Err(error) = stream.shutdown(std::net::Shutdown::Both) {
                tracing::debug!(error = %error, "RNode TCP shutdown during writer cleanup");
            }
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl Drop for RNodeWriteInterrupt {
    fn drop(&mut self) {
        self.interrupt();
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
struct RNodeTaskGuard<T> {
    task: Option<tokio::task::JoinHandle<T>>,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl<T> RNodeTaskGuard<T> {
    fn new(task: tokio::task::JoinHandle<T>) -> Self {
        Self { task: Some(task) }
    }

    fn is_finished(&self) -> bool {
        self.task
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
    }

    #[cfg(test)]
    fn take(&mut self) -> tokio::task::JoinHandle<T> {
        self.task.take().expect("RNode task already taken")
    }

    fn task_mut(&mut self) -> &mut tokio::task::JoinHandle<T> {
        self.task.as_mut().expect("RNode task already taken")
    }

    fn abort(&self) {
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }

    fn disarm(&mut self) {
        let _ = self.task.take();
    }

    async fn abort_and_wait(mut self) {
        self.abort();
        let _ = self.task_mut().await;
        self.disarm();
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl<T> Drop for RNodeTaskGuard<T> {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
struct RNodeGenerationWriter {
    // First field on purpose: cancellation of an owning future interrupts the
    // physical transport before the actor task guard aborts.
    interrupt: RNodeWriteInterrupt,
    packet_tx: mpsc::Sender<Bytes>,
    control_tx: mpsc::Sender<RNodeControlWriteRequest>,
    ready: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    idle_probes_enabled: Arc<AtomicBool>,
    task: RNodeTaskGuard<Result<RNodeWriterExit, RNodeWriteFailure>>,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl RNodeGenerationWriter {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn apply_rnode_ready_permit(ready: &AtomicBool, frame: &[u8], is_ready: bool) {
    // Keep the shared response decoder (also used by BLE) unchanged while the
    // serial/TCP writer accepts operational grants only at the exact width.
    if frame.len() == 1 {
        ready.store(is_ready, Ordering::SeqCst);
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
struct RNodePacketAccounting {
    txb: Arc<AtomicU64>,
    raw_len: u64,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
struct RNodeIdleProbe {
    interval: Duration,
    deadline: tokio::time::Instant,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl RNodeIdleProbe {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            deadline: tokio::time::Instant::now() + interval,
        }
    }

    fn is_overdue(&self) -> bool {
        tokio::time::Instant::now() >= self.deadline
    }

    fn record_completed_write(&mut self, write_completed_at: tokio::time::Instant) {
        self.deadline = write_completed_at + self.interval;
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn write_rnode_operation<W>(
    mut writer: W,
    bytes: Vec<u8>,
    phase: RNodeWritePhase,
    packet_accounting: Option<RNodePacketAccounting>,
    idle_probe: &mut Option<RNodeIdleProbe>,
) -> Result<W, RNodeWriteFailure>
where
    W: std::io::Write + Send + 'static,
{
    let (writer, write_completed_at) = tokio::task::spawn_blocking(move || {
        writer
            .write_all(&bytes)
            .map_err(|error| RNodeWriteFailure {
                phase,
                kind: RNodeWriteFailureKind::Write(Arc::new(error)),
            })?;
        let write_completed_at = tokio::time::Instant::now();
        if let Some(accounting) = packet_accounting {
            accounting
                .txb
                .fetch_add(accounting.raw_len, Ordering::Relaxed);
        }
        writer.flush().map_err(|error| RNodeWriteFailure {
            phase,
            kind: RNodeWriteFailureKind::Flush(Arc::new(error)),
        })?;
        Ok((writer, write_completed_at))
    })
    .await
    .map_err(|_| RNodeWriteFailure {
        phase,
        kind: RNodeWriteFailureKind::WorkerTerminated,
    })??;
    if let Some(idle_probe) = idle_probe {
        idle_probe.record_completed_write(write_completed_at);
    }
    Ok(writer)
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn prepare_rnode_packet(
    data: Bytes,
    context: &RNodeWriterContext,
    first_tx: &mut Option<tokio::time::Instant>,
) -> (Vec<u8>, RNodePacketAccounting) {
    if let Some((_, ref callsign)) = context.beacon {
        if data == *callsign {
            *first_tx = None;
        } else if first_tx.is_none() {
            *first_tx = Some(tokio::time::Instant::now());
        }
    }
    if let Ok((header, _)) = rns_wire::header::PacketHeader::unpack(&data) {
        tracing::debug!(
            id = context.id,
            raw_len = data.len(),
            packet_type = ?header.flags.packet_type,
            context = ?header.context,
            dest = %hex::encode(header.destination_hash),
            "RNode writing packet"
        );
    } else {
        tracing::debug!(
            id = context.id,
            raw_len = data.len(),
            "RNode writing packet"
        );
    }
    let accounting = RNodePacketAccounting {
        txb: context.txb.clone(),
        raw_len: data.len() as u64,
    };
    (kiss::frame(&data), accounting)
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
enum RNodeWriterEvent {
    Control(Option<RNodeControlWriteRequest>),
    Packet(Option<Bytes>),
    ProbePoll,
    FlowPoll,
    BeaconPoll,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn wait_for_rnode_probe_deadline(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn run_rnode_writer<W>(
    mut writer: W,
    mut packet_rx: mpsc::Receiver<Bytes>,
    mut control_rx: mpsc::Receiver<RNodeControlWriteRequest>,
    context: RNodeWriterContext,
) -> Result<RNodeWriterExit, RNodeWriteFailure>
where
    W: std::io::Write + Send + 'static,
{
    let mut pending_packet: Option<Bytes> = None;
    let mut first_tx: Option<tokio::time::Instant> = None;
    let mut packet_lane_open = true;
    let mut control_lane_open = true;
    let mut idle_probe = context.idle_probe_interval.map(RNodeIdleProbe::new);

    loop {
        if context.idle_probes_enabled.load(Ordering::SeqCst) {
            if idle_probe.is_none() {
                idle_probe = context.idle_probe_interval.map(RNodeIdleProbe::new);
            }
        } else {
            idle_probe = None;
        }
        if context.cancelled.load(Ordering::SeqCst) {
            return Ok(RNodeWriterExit::Cancelled);
        }

        if control_lane_open {
            match control_rx.try_recv() {
                Ok(request) => {
                    if context.cancelled.load(Ordering::SeqCst) {
                        return Ok(RNodeWriterExit::Cancelled);
                    }
                    let phase = request.phase;
                    let terminal = phase == RNodeWritePhase::Detach;
                    match write_rnode_operation(writer, request.bytes, phase, None, &mut idle_probe)
                        .await
                    {
                        Ok(next_writer) => {
                            writer = next_writer;
                            let _ = request.acknowledgement.send(Ok(()));
                            if terminal {
                                return Ok(RNodeWriterExit::Detached);
                            }
                        }
                        Err(failure) => {
                            let _ = request.acknowledgement.send(Err(failure.clone()));
                            return Err(failure);
                        }
                    }
                    continue;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    control_lane_open = false;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }

        if pending_packet.is_none() {
            if let Some((interval, ref callsign)) = context.beacon {
                if first_tx.is_some_and(|started| started.elapsed() >= interval) {
                    tracing::debug!(id = context.id, "RNode station-ID beacon is due");
                    pending_packet = Some(callsign.clone());
                }
            }
        }

        let packet_permitted = pending_packet.is_some()
            && context.carrier_online.load(Ordering::SeqCst)
            && context.interface_online.load(Ordering::SeqCst)
            && (!context.flow_control
                || context
                    .ready
                    .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok());
        if packet_permitted {
            if context.cancelled.load(Ordering::SeqCst) {
                return Ok(RNodeWriterExit::Cancelled);
            }
            let packet = pending_packet.take().expect("pending packet checked");
            let (framed, accounting) = prepare_rnode_packet(packet, &context, &mut first_tx);
            let framed_len = framed.len();
            writer = write_rnode_operation(
                writer,
                framed,
                RNodeWritePhase::Packet,
                Some(accounting),
                &mut idle_probe,
            )
            .await?;
            tracing::debug!(id = context.id, framed_len, "RNode packet write complete");
            continue;
        }

        if pending_packet.is_some() && !context.carrier_online.load(Ordering::SeqCst) {
            return Ok(RNodeWriterExit::CarrierOffline);
        }
        if !packet_lane_open && !control_lane_open && pending_packet.is_none() {
            return Ok(RNodeWriterExit::LanesClosed);
        }

        if idle_probe.as_ref().is_some_and(RNodeIdleProbe::is_overdue) {
            if context.cancelled.load(Ordering::SeqCst) {
                return Ok(RNodeWriterExit::Cancelled);
            }
            writer = write_rnode_operation(
                writer,
                build_detect_sequence(),
                RNodeWritePhase::Probe,
                None,
                &mut idle_probe,
            )
            .await?;
            tracing::debug!(id = context.id, "RNode TCP idle probe write complete");
            continue;
        }

        let probe_deadline = idle_probe.as_ref().map(|probe| probe.deadline);
        let event = if pending_packet.is_some() {
            tokio::select! {
                biased;
                request = control_rx.recv(), if control_lane_open => {
                    RNodeWriterEvent::Control(request)
                }
                _ = wait_for_rnode_probe_deadline(probe_deadline) => {
                    RNodeWriterEvent::ProbePoll
                }
                _ = tokio::time::sleep(RNODE_FLOW_POLL_INTERVAL) => {
                    RNodeWriterEvent::FlowPoll
                }
            }
        } else {
            tokio::select! {
                biased;
                request = control_rx.recv(), if control_lane_open => {
                    RNodeWriterEvent::Control(request)
                }
                _ = wait_for_rnode_probe_deadline(probe_deadline) => {
                    RNodeWriterEvent::ProbePoll
                }
                packet = packet_rx.recv(), if packet_lane_open => {
                    RNodeWriterEvent::Packet(packet)
                }
                _ = tokio::time::sleep(context.beacon_poll_interval),
                    if context.beacon.is_some() => {
                    RNodeWriterEvent::BeaconPoll
                }
            }
        };

        if context.cancelled.load(Ordering::SeqCst) {
            return Ok(RNodeWriterExit::Cancelled);
        }

        match event {
            RNodeWriterEvent::Control(Some(request)) => {
                if context.cancelled.load(Ordering::SeqCst) {
                    return Ok(RNodeWriterExit::Cancelled);
                }
                let phase = request.phase;
                let terminal = phase == RNodeWritePhase::Detach;
                match write_rnode_operation(writer, request.bytes, phase, None, &mut idle_probe)
                    .await
                {
                    Ok(next_writer) => {
                        writer = next_writer;
                        let _ = request.acknowledgement.send(Ok(()));
                        if terminal {
                            return Ok(RNodeWriterExit::Detached);
                        }
                    }
                    Err(failure) => {
                        let _ = request.acknowledgement.send(Err(failure.clone()));
                        return Err(failure);
                    }
                }
            }
            RNodeWriterEvent::Control(None) => {
                control_lane_open = false;
            }
            RNodeWriterEvent::Packet(Some(data)) => {
                if context.cancelled.load(Ordering::SeqCst) {
                    return Ok(RNodeWriterExit::Cancelled);
                }
                pending_packet = Some(data);
            }
            RNodeWriterEvent::Packet(None) => {
                packet_lane_open = false;
            }
            RNodeWriterEvent::ProbePoll => {}
            RNodeWriterEvent::FlowPoll => {}
            // Wake the top-of-loop due check even when both input lanes are
            // idle. Checking there also prevents a continuously ready packet
            // lane from starving an elapsed station-ID beacon.
            RNodeWriterEvent::BeaconPoll => {}
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn spawn_rnode_writer<W>(writer: W, context: RNodeWriterContext) -> RNodeGenerationWriter
where
    W: std::io::Write + Send + 'static,
{
    let (packet_tx, packet_rx) = mpsc::channel(RNODE_PACKET_WRITE_QUEUE);
    let (control_tx, control_rx) = mpsc::channel(RNODE_CONTROL_WRITE_QUEUE);
    let ready = context.ready.clone();
    let cancelled = context.cancelled.clone();
    let idle_probes_enabled = context.idle_probes_enabled.clone();
    let carrier_online = context.carrier_online.clone();
    let interface_online = context.interface_online.clone();
    let id = context.id;
    let task = tokio::spawn(async move {
        let result = run_rnode_writer(writer, packet_rx, control_rx, context).await;
        if let Err(ref failure) = result {
            tracing::warn!(
                id,
                phase = failure.phase.label(),
                failure = ?failure.kind,
                "RNode writer failed"
            );
            carrier_online.store(false, Ordering::SeqCst);
            interface_online.store(false, Ordering::SeqCst);
        }
        result
    });
    RNodeGenerationWriter {
        interrupt: RNodeWriteInterrupt::none(),
        packet_tx,
        control_tx,
        ready,
        cancelled,
        idle_probes_enabled,
        task: RNodeTaskGuard::new(task),
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
struct RNodeGenerationWriterOptions {
    id: InterfaceId,
    carrier_online: Arc<AtomicBool>,
    interface_online: Arc<AtomicBool>,
    txb: Arc<AtomicU64>,
    beacon: Option<(Duration, Bytes)>,
    idle_probes_enabled: bool,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn spawn_rnode_generation_writer(
    port: &RNodeStream,
    config: &RNodeConfig,
    options: RNodeGenerationWriterOptions,
) -> std::io::Result<RNodeGenerationWriter> {
    let interrupt = RNodeWriteInterrupt::from_stream(port)?;
    let write_stream = port.try_clone()?;
    let mut writer = spawn_rnode_writer(
        write_stream,
        RNodeWriterContext {
            id: options.id,
            flow_control: config.flow_control,
            // Upstream flow control starts with one permissive packet token;
            // exact-width CMD_READY frames replenish or revoke that token.
            // This token is independent of the exact protocol-readiness gate.
            ready: Arc::new(AtomicBool::new(true)),
            carrier_online: options.carrier_online,
            interface_online: options.interface_online,
            cancelled: Arc::new(AtomicBool::new(false)),
            txb: options.txb,
            beacon: options.beacon,
            beacon_poll_interval: RNODE_BEACON_POLL_INTERVAL,
            idle_probe_interval: port.is_tcp().then_some(RNODE_TCP_IDLE_PROBE_INTERVAL),
            idle_probes_enabled: Arc::new(AtomicBool::new(options.idle_probes_enabled)),
        },
    );
    writer.interrupt = interrupt;
    Ok(writer)
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn finish_rnode_writer(writer: RNodeGenerationWriter) -> RNodeWriterFinish {
    writer.cancel();
    let RNodeGenerationWriter {
        mut interrupt,
        packet_tx,
        control_tx,
        ready: _,
        cancelled: _,
        idle_probes_enabled: _,
        mut task,
    } = writer;
    drop(packet_tx);
    drop(control_tx);
    interrupt.interrupt();

    match tokio::time::timeout(RNODE_WRITER_JOIN_DEADLINE, task.task_mut()).await {
        Ok(Ok(Ok(exit))) => {
            task.disarm();
            tracing::debug!(exit = ?exit, "RNode writer stopped");
            RNodeWriterFinish::Quiesced
        }
        Ok(Ok(Err(failure))) => {
            task.disarm();
            tracing::debug!(
                phase = failure.phase.label(),
                failure = ?failure.kind,
                "RNode writer failure observed during cleanup"
            );
            RNodeWriterFinish::Quiesced
        }
        Ok(Err(error)) => {
            task.disarm();
            tracing::warn!(error = %error, "RNode writer task failed to join");
            RNodeWriterFinish::NonQuiesced
        }
        Err(_) => {
            tracing::warn!("RNode writer did not stop within cleanup deadline");
            task.abort();
            let _ = task.task_mut().await;
            task.disarm();
            RNodeWriterFinish::NonQuiesced
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn rnode_generation_terminal_reason(
    stop_requested: bool,
    transport_closed: bool,
    read_task_failed: bool,
    writer_finish: RNodeWriterFinish,
) -> Option<RNodeRuntimeReason> {
    if stop_requested {
        Some(RNodeRuntimeReason::StopRequested)
    } else if transport_closed {
        Some(RNodeRuntimeReason::TransportConsumerClosed)
    } else if read_task_failed || writer_finish == RNodeWriterFinish::NonQuiesced {
        Some(RNodeRuntimeReason::DriverTerminated)
    } else {
        None
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn request_rnode_control_write(
    control_tx: &mpsc::Sender<RNodeControlWriteRequest>,
    phase: RNodeWritePhase,
    bytes: Vec<u8>,
) -> Result<(), RNodeWriteFailure> {
    let (acknowledgement, result) = oneshot::channel();
    control_tx
        .send(RNodeControlWriteRequest {
            phase,
            bytes,
            acknowledgement,
        })
        .await
        .map_err(|_| RNodeWriteFailure {
            phase,
            kind: RNodeWriteFailureKind::QueueClosed,
        })?;
    result.await.map_err(|_| RNodeWriteFailure {
        phase,
        kind: RNodeWriteFailureKind::AcknowledgementDropped,
    })?
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn request_rnode_control_write_before(
    control_tx: &mpsc::Sender<RNodeControlWriteRequest>,
    phase: RNodeWritePhase,
    bytes: Vec<u8>,
    deadline: tokio::time::Instant,
) -> Result<(), RNodeWriteFailure> {
    tokio::time::timeout_at(
        deadline,
        request_rnode_control_write(control_tx, phase, bytes),
    )
    .await
    .map_err(|_| RNodeWriteFailure {
        phase,
        kind: RNodeWriteFailureKind::DeadlineElapsed,
    })?
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn request_rnode_startup_write(
    control_tx: &mpsc::Sender<RNodeControlWriteRequest>,
    phase: RNodeWritePhase,
    bytes: Vec<u8>,
) -> Result<(), RNodeWriteFailure> {
    debug_assert!(matches!(
        phase,
        RNodeWritePhase::Detect | RNodeWritePhase::Capability | RNodeWritePhase::Initialise
    ));
    request_rnode_control_write_before(
        control_tx,
        phase,
        bytes,
        tokio::time::Instant::now() + RNODE_STARTUP_STAGE_DEADLINE,
    )
    .await
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn initialise_rnode_writer(
    writer: &RNodeGenerationWriter,
    config: &RNodeConfig,
) -> Result<(), RNodeWriteFailure> {
    request_rnode_startup_write(
        &writer.control_tx,
        RNodeWritePhase::Detect,
        build_detect_sequence(),
    )
    .await?;
    request_rnode_startup_write(
        &writer.control_tx,
        RNodeWritePhase::Initialise,
        build_init_sequence(config),
    )
    .await
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RNodeReconnectStartup {
    Complete,
    StopRequested,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn initialise_reconnecting_rnode_writer(
    writer: &RNodeGenerationWriter,
    config: &RNodeConfig,
    stop_rx: &mut mpsc::Receiver<()>,
) -> Result<RNodeReconnectStartup, RNodeWriteFailure> {
    for (phase, bytes) in [
        (RNodeWritePhase::Detect, build_detect_sequence()),
        (RNodeWritePhase::Initialise, build_init_sequence(config)),
    ] {
        let stage = tokio::select! {
            biased;
            _ = stop_rx.recv() => {
                return Ok(RNodeReconnectStartup::StopRequested);
            }
            result = request_rnode_startup_write(&writer.control_tx, phase, bytes) => result,
        };
        stage?;
    }

    if stop_rx.try_recv().is_ok() {
        Ok(RNodeReconnectStartup::StopRequested)
    } else {
        Ok(RNodeReconnectStartup::Complete)
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn send_detach_request(
    control_tx: &mpsc::Sender<RNodeControlWriteRequest>,
    id: InterfaceId,
) -> Result<(), RNodeWriteFailure> {
    let deadline = tokio::time::Instant::now() + RNODE_DETACH_DEADLINE;
    let result = request_rnode_control_write_before(
        control_tx,
        RNodeWritePhase::Detach,
        build_detach_sequence(),
        deadline,
    )
    .await;

    match result {
        Ok(()) => tracing::info!(id, "RNode detach sequence sent"),
        Err(ref failure) => tracing::warn!(
            id,
            failure = ?failure.kind,
            "RNode detach sequence failed"
        ),
    }
    result
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

    Ok(port)
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn start_rnode_generation(
    port: RNodeStream,
    config: &RNodeConfig,
    id: InterfaceId,
    carrier_online: &Arc<AtomicBool>,
    interface_online: &Arc<AtomicBool>,
    txb: &Arc<AtomicU64>,
    beacon: &Option<(Duration, Bytes)>,
) -> Result<(RNodeStream, RNodeGenerationWriter), crate::traits::InterfaceError> {
    let writer = spawn_rnode_generation_writer(
        &port,
        config,
        RNodeGenerationWriterOptions {
            id,
            carrier_online: carrier_online.clone(),
            interface_online: interface_online.clone(),
            txb: txb.clone(),
            beacon: beacon.clone(),
            idle_probes_enabled: true,
        },
    )
    .map_err(|error| {
        crate::traits::InterfaceError::SendFailed(format!("rnode writer clone: {error}"))
    })?;

    if let Err(failure) = initialise_rnode_writer(&writer, config).await {
        carrier_online.store(false, Ordering::SeqCst);
        interface_online.store(false, Ordering::SeqCst);
        finish_rnode_writer(writer).await;
        return Err(crate::traits::InterfaceError::SendFailed(format!(
            "rnode writer startup: {failure}"
        )));
    }

    Ok((port, writer))
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
enum RNodeStrictPreflightError {
    Transport(crate::traits::InterfaceError),
    Capability(RNodeCapabilityAdmissionError),
    StopRequestedBeforeInit,
    StopRequestedAfterInitQueued,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
struct RNodeStrictAdmission {
    port: RNodeStream,
    protocol_state: RNodeProtocolState,
    admission: crate::rnode_capabilities::RNodeRadioAdmission,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
enum RNodeGenerationProtocolSeed {
    Legacy,
    CapabilityAdmitted {
        protocol_state: RNodeProtocolState,
        admission: crate::rnode_capabilities::RNodeRadioAdmission,
    },
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn rnode_preflight_stop_requested(stop_rx: &mut Option<&mut mpsc::Receiver<()>>) -> bool {
    stop_rx
        .as_deref_mut()
        .is_some_and(|receiver| receiver.try_recv().is_ok())
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn request_rnode_preflight_write(
    writer: &RNodeGenerationWriter,
    phase: RNodeWritePhase,
    bytes: Vec<u8>,
    stop_rx: &mut Option<&mut mpsc::Receiver<()>>,
) -> Result<(), RNodeStrictPreflightError> {
    let result = if let Some(receiver) = stop_rx.as_deref_mut() {
        tokio::select! {
            biased;
            _ = receiver.recv() => return Err(RNodeStrictPreflightError::StopRequestedBeforeInit),
            result = request_rnode_startup_write(&writer.control_tx, phase, bytes) => result,
        }
    } else {
        request_rnode_startup_write(&writer.control_tx, phase, bytes).await
    };
    result.map_err(|failure| {
        RNodeStrictPreflightError::Transport(crate::traits::InterfaceError::SendFailed(format!(
            "rnode capability startup: {failure}"
        )))
    })
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn run_rnode_capability_preflight(
    mut port: RNodeStream,
    writer: &RNodeGenerationWriter,
    config: &RNodeConfig,
    mut stop_rx: Option<&mut mpsc::Receiver<()>>,
) -> Result<RNodeStrictAdmission, RNodeStrictPreflightError> {
    request_rnode_preflight_write(
        writer,
        RNodeWritePhase::Detect,
        build_detect_sequence(),
        &mut stop_rx,
    )
    .await?;
    request_rnode_preflight_write(
        writer,
        RNodeWritePhase::Capability,
        crate::rnode_capability_preflight::build_rnode_capability_request(),
        &mut stop_rx,
    )
    .await?;

    let deadline = tokio::time::Instant::now()
        + crate::rnode_capability_preflight::RNODE_CAPABILITY_PREFLIGHT_DEADLINE;
    let mut preflight = crate::rnode_capability_preflight::RNodeCapabilityPreflight::new(
        RNodeRadioSettings::from(config),
    );
    let mut buf = [0u8; crate::rnode_capability_preflight::RNODE_CAPABILITY_READ_BUFFER_BYTES];

    loop {
        if rnode_preflight_stop_requested(&mut stop_rx) {
            return Err(RNodeStrictPreflightError::StopRequestedBeforeInit);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(RNodeStrictPreflightError::Capability(
                RNodeCapabilityAdmissionError::ResponseTimedOut,
            ));
        }

        // Never select or time out away from this task: it owns the sole read
        // stream until it returns. The physical stream already has a bounded
        // 100 ms read timeout, so the absolute deadline is checked around
        // every joined read without abandoning ownership.
        let read = tokio::task::spawn_blocking(move || read_rnode_stream(port, buf))
            .await
            .map_err(|error| {
                RNodeStrictPreflightError::Transport(crate::traits::InterfaceError::SendFailed(
                    format!("rnode capability read task: {error}"),
                ))
            })?;

        let (next_port, next_buf, count) = read.map_err(|(_port, error)| {
            RNodeStrictPreflightError::Transport(crate::traits::InterfaceError::SendFailed(
                format!("rnode capability read: {error}"),
            ))
        })?;
        port = next_port;
        buf = next_buf;
        if rnode_preflight_stop_requested(&mut stop_rx) {
            return Err(RNodeStrictPreflightError::StopRequestedBeforeInit);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(RNodeStrictPreflightError::Capability(
                RNodeCapabilityAdmissionError::ResponseTimedOut,
            ));
        }

        let admission = preflight
            .observe_read(&buf[..count])
            .map_err(RNodeStrictPreflightError::Capability)?;
        let Some(admission) = admission else {
            continue;
        };
        if rnode_preflight_stop_requested(&mut stop_rx) {
            return Err(RNodeStrictPreflightError::StopRequestedBeforeInit);
        }

        // Control writes are writer-priority, so enabling immediately before
        // enqueueing init cannot let a recurring detect probe overtake it. It
        // also prevents the writer from re-entering a no-deadline wait after
        // acknowledging init.
        writer.idle_probes_enabled.store(true, Ordering::SeqCst);
        let init_result = request_rnode_preflight_write(
            writer,
            RNodeWritePhase::Initialise,
            build_init_sequence(config),
            &mut stop_rx,
        )
        .await
        .map_err(|error| match error {
            RNodeStrictPreflightError::StopRequestedBeforeInit => {
                RNodeStrictPreflightError::StopRequestedAfterInitQueued
            }
            other => other,
        });
        if init_result.is_err() {
            writer.idle_probes_enabled.store(false, Ordering::SeqCst);
        }
        init_result?;
        return Ok(RNodeStrictAdmission {
            port,
            protocol_state: preflight.into_protocol_state(),
            admission,
        });
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn start_strict_rnode_generation(
    port: RNodeStream,
    config: &RNodeConfig,
    id: InterfaceId,
    carrier_online: &Arc<AtomicBool>,
    interface_online: &Arc<AtomicBool>,
    txb: &Arc<AtomicU64>,
    beacon: &Option<(Duration, Bytes)>,
) -> Result<(RNodeStrictAdmission, RNodeGenerationWriter), RNodeSpawnError> {
    let writer = spawn_rnode_generation_writer(
        &port,
        config,
        RNodeGenerationWriterOptions {
            id,
            carrier_online: carrier_online.clone(),
            interface_online: interface_online.clone(),
            txb: txb.clone(),
            beacon: beacon.clone(),
            idle_probes_enabled: false,
        },
    )
    .map_err(|error| {
        crate::traits::InterfaceError::SendFailed(format!("rnode writer clone: {error}"))
    })?;

    match run_rnode_capability_preflight(port, &writer, config, None).await {
        Ok(admission) => Ok((admission, writer)),
        Err(error) => {
            carrier_online.store(false, Ordering::SeqCst);
            interface_online.store(false, Ordering::SeqCst);
            let _ = finish_rnode_writer(writer).await;
            Err(match error {
                RNodeStrictPreflightError::Transport(error) => RNodeSpawnError::Interface(error),
                RNodeStrictPreflightError::Capability(error) => {
                    RNodeSpawnError::CapabilityAdmission(error)
                }
                RNodeStrictPreflightError::StopRequestedBeforeInit
                | RNodeStrictPreflightError::StopRequestedAfterInitQueued => {
                    unreachable!("initial strict startup has no stop receiver")
                }
            })
        }
    }
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

/// Transport-independent, non-secret settings for one generic RNode radio.
///
/// This value contains only RF parameters. It deliberately carries no
/// endpoint, interface label, device identity, EEPROM data, or other device
/// configuration, so callers such as `rnodeconf` can validate and encode a
/// reviewed radio configuration without constructing a runtime interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RNodeRadioSettings {
    /// RF centre frequency in hertz.
    pub frequency: u32,
    /// RF bandwidth in hertz.
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    /// Transmit power in dBm.
    pub tx_power: u8,
}

impl RNodeRadioSettings {
    pub const fn new(
        frequency: u32,
        bandwidth: u32,
        spreading_factor: u8,
        coding_rate: u8,
        tx_power: u8,
    ) -> Self {
        Self {
            frequency,
            bandwidth,
            spreading_factor,
            coding_rate,
            tx_power,
        }
    }

    /// Validate all generic RNode RF settings without touching a device.
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
        Ok(())
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

/// Typed failure returned by [`RNodeRadioSettings::validate`] and
/// [`RNodeConfig::validate`].
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
        RNodeRadioSettings::from(self).validate()?;
        validate_airtime(RNodeConfigField::ShortTermAirtime, self.st_alock)?;
        validate_airtime(RNodeConfigField::LongTermAirtime, self.lt_alock)?;
        Ok(())
    }
}

impl From<&RNodeConfig> for RNodeRadioSettings {
    fn from(config: &RNodeConfig) -> Self {
        Self::new(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        )
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

fn u32_to_bytes(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

/// Build the reviewed generic RNode radio-configuration command sequence.
///
/// The returned bytes contain exactly these extended-KISS commands, in order:
/// radio off, frequency, bandwidth, spreading factor, coding rate, transmit
/// power, and radio on. The helper performs no endpoint I/O. Call
/// [`RNodeRadioSettings::validate`] before sending settings obtained from an
/// untrusted source.
pub fn build_radio_configuration_sequence(settings: &RNodeRadioSettings) -> Vec<u8> {
    build_radio_configuration_sequence_before_on(settings, &[])
}

fn build_radio_configuration_sequence_before_on(
    settings: &RNodeRadioSettings,
    before_radio_on: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + before_radio_on.len());
    kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_OFF], &mut out);
    kiss::frame_with_command_into(CMD_FREQUENCY, &u32_to_bytes(settings.frequency), &mut out);
    kiss::frame_with_command_into(CMD_BANDWIDTH, &u32_to_bytes(settings.bandwidth), &mut out);
    kiss::frame_with_command_into(CMD_SF, &[settings.spreading_factor], &mut out);
    kiss::frame_with_command_into(CMD_CR, &[settings.coding_rate], &mut out);
    kiss::frame_with_command_into(CMD_TXPOWER, &[settings.tx_power], &mut out);
    out.extend_from_slice(before_radio_on);
    kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_ON], &mut out);
    out
}

/// KISS init sequence. Order matters: turn the radio off first so persisted
/// TNC startup profiles cannot keep old parameters active, airtime locks
/// precede RADIO_STATE=ON, and RADIO_STATE=ON must be last.
pub fn build_init_sequence(config: &RNodeConfig) -> Vec<u8> {
    let settings = RNodeRadioSettings::from(config);
    let airtime = build_airtime_sequence(config);
    build_radio_configuration_sequence_before_on(&settings, &airtime)
}

#[cfg(any(feature = "ble", test))]
fn build_command_stage(command: u8, payload: &[u8]) -> Vec<u8> {
    let mut stage = Vec::with_capacity(payload.len() + 4);
    kiss::frame_with_command_into(command, payload, &mut stage);
    stage
}

/// Build the independently paced radio-control stages used after a BLE
/// connection becomes usable.
///
/// Unlike [`build_init_sequence`], this sequence deliberately never emits
/// `RADIO_STATE_OFF`. A BLE client can therefore reconnect and reassert the
/// desired RF parameters without tearing down the radio session that remained
/// active while Bluetooth was out of range. The command order mirrors the
/// upstream Android RNode BLE initialization path; callers are responsible for
/// validation and pacing each returned stage.
#[cfg(any(feature = "ble", test))]
pub(crate) fn build_ble_radio_reassertion_stages(config: &RNodeConfig) -> Vec<Vec<u8>> {
    let mut stages = Vec::with_capacity(8);
    stages.push(build_command_stage(
        CMD_FREQUENCY,
        &u32_to_bytes(config.frequency),
    ));
    stages.push(build_command_stage(
        CMD_BANDWIDTH,
        &u32_to_bytes(config.bandwidth),
    ));
    stages.push(build_command_stage(CMD_TXPOWER, &[config.tx_power]));
    stages.push(build_command_stage(CMD_SF, &[config.spreading_factor]));
    stages.push(build_command_stage(CMD_CR, &[config.coding_rate]));

    if let Some(st) = config.st_alock {
        stages.push(build_command_stage(
            CMD_ST_ALOCK,
            &((st * 100.0) as u16).to_be_bytes(),
        ));
    }
    if let Some(lt) = config.lt_alock {
        stages.push(build_command_stage(
            CMD_LT_ALOCK,
            &((lt * 100.0) as u16).to_be_bytes(),
        ));
    }

    stages.push(build_command_stage(CMD_RADIO_STATE, &[RADIO_STATE_ON]));
    stages
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
    spawn_rnode_interface_with_driver_and_options(
        config,
        id,
        transport_tx,
        RNodeStartupOptions::default(),
    )
    .await
    .map_err(RNodeSpawnError::into_legacy_interface_error)
}

/// Spawn a generic serial/RNode-TCP interface with an explicit startup policy.
///
/// Unlike the compatibility facade, this preserves capability-admission
/// failures as typed errors. [`RNodeStartupOptions::default`] retains the
/// historical wire sequence and behavior. Under strict admission, a later
/// deterministic rejection is terminal and publishes
/// [`RNodeRuntimeReason::CapabilityAdmissionRejected`]; transport failures and
/// capability-response timeouts continue through the normal reconnect policy.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub async fn spawn_rnode_interface_with_driver_and_options(
    config: RNodeConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    options: RNodeStartupOptions,
) -> Result<SpawnedRNodeInterface, RNodeSpawnError> {
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

    // The physical stream is already open, but upstream does not expose an
    // RNode as online until detection, firmware, configuration and radio state
    // have all been validated. Keep those two states independent.
    let carrier_online = Arc::new(AtomicBool::new(true));
    let online = Arc::new(AtomicBool::new(false));
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<Bytes>(256);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let name = config.name.clone();
    let mode = config.mode;
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

    // Startup is part of spawn. Legacy uses the historical two acknowledged
    // detect/init write+flush stages; strict mode inserts bounded capability
    // admission after detect and before any init bytes.
    let (port, initial_writer, initial_protocol_seed) = if options.requires_capability_admission() {
        let (admitted, writer) = start_strict_rnode_generation(
            port,
            &config,
            id,
            &carrier_online,
            &online,
            &shared_txb,
            &beacon,
        )
        .await?;
        (
            admitted.port,
            writer,
            RNodeGenerationProtocolSeed::CapabilityAdmitted {
                protocol_state: admitted.protocol_state,
                admission: admitted.admission,
            },
        )
    } else {
        let (port, writer) = start_rnode_generation(
            port,
            &config,
            id,
            &carrier_online,
            &online,
            &shared_txb,
            &beacon,
        )
        .await?;
        (port, writer, RNodeGenerationProtocolSeed::Legacy)
    };

    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
    let (initial_snapshot_publisher, driver) = new_rnode_driver_observation_with_shutdown(
        transport,
        RNodeDriverShutdown::from_stop_sender(stop_tx.clone()),
    );
    let stop_guard = register_rnode_stop(id, stop_tx);
    let online_r = online.clone();
    let carrier_online_r = carrier_online.clone();
    let rxb_r = shared_rxb.clone();
    let txb_r = shared_txb.clone();
    let task_config = config.clone();
    let task_port_cfg = port_cfg.clone();
    let task_name = config.name.clone();
    let read_task = tokio::spawn(async move {
        let mut snapshot_publisher = initial_snapshot_publisher;
        let _stop_guard = stop_guard;
        let mut next_generation = Some((port, initial_writer, initial_protocol_seed));

        loop {
            if next_generation.is_none() && stop_rx.try_recv().is_ok() {
                tracing::info!(name = %task_name, "RNode stop requested before reconnect");
                snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                return;
            }
            let (port_r, generation_writer, protocol_seed) = match next_generation.take() {
                Some(generation) => generation,
                None => {
                    snapshot_publisher.reconnect_started();
                    let open_result = tokio::select! {
                        biased;
                        _ = stop_rx.recv() => {
                            tracing::info!(name = %task_name, "RNode stop requested during reconnect open");
                            snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                            snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                            return;
                        }
                        result = open_configured_rnode_stream(&task_config, &task_port_cfg) => result,
                    };
                    let opened = match open_result {
                        Ok(port) => port,
                        Err(e) => {
                            carrier_online_r.store(false, Ordering::SeqCst);
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
                    };

                    let reconnect_writer = match spawn_rnode_generation_writer(
                        &opened,
                        &task_config,
                        RNodeGenerationWriterOptions {
                            id,
                            carrier_online: carrier_online_r.clone(),
                            interface_online: online_r.clone(),
                            txb: txb_r.clone(),
                            beacon: beacon.clone(),
                            idle_probes_enabled: !options.requires_capability_admission(),
                        },
                    ) {
                        Ok(writer) => writer,
                        Err(e) => {
                            carrier_online_r.store(false, Ordering::SeqCst);
                            online_r.store(false, Ordering::SeqCst);
                            snapshot_publisher.connection_attempt_failed();
                            tracing::warn!(
                                name = %task_name,
                                error = %e,
                                "RNode reconnect startup failed"
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
                    };

                    if options.requires_capability_admission() {
                        match run_rnode_capability_preflight(
                            opened,
                            &reconnect_writer,
                            &task_config,
                            Some(&mut stop_rx),
                        )
                        .await
                        {
                            Ok(admitted) => (
                                admitted.port,
                                reconnect_writer,
                                RNodeGenerationProtocolSeed::CapabilityAdmitted {
                                    protocol_state: admitted.protocol_state,
                                    admission: admitted.admission,
                                },
                            ),
                            Err(RNodeStrictPreflightError::StopRequestedBeforeInit) => {
                                tracing::info!(
                                    name = %task_name,
                                    "RNode stop requested during capability preflight"
                                );
                                snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                                reconnect_writer.cancel();
                                let _ = finish_rnode_writer(reconnect_writer).await;
                                snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                                return;
                            }
                            Err(RNodeStrictPreflightError::StopRequestedAfterInitQueued) => {
                                tracing::info!(
                                    name = %task_name,
                                    "RNode stop requested during admitted reconnect init"
                                );
                                snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                                let _ = send_detach_request(&reconnect_writer.control_tx, id).await;
                                reconnect_writer.cancel();
                                let _ = finish_rnode_writer(reconnect_writer).await;
                                snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                                return;
                            }
                            Err(RNodeStrictPreflightError::Capability(
                                RNodeCapabilityAdmissionError::ResponseTimedOut,
                            )) => {
                                carrier_online_r.store(false, Ordering::SeqCst);
                                online_r.store(false, Ordering::SeqCst);
                                reconnect_writer.cancel();
                                let writer_finish = finish_rnode_writer(reconnect_writer).await;
                                if writer_finish == RNodeWriterFinish::NonQuiesced {
                                    snapshot_publisher
                                        .stopped(RNodeRuntimeReason::DriverTerminated);
                                    return;
                                }
                                snapshot_publisher.connection_attempt_failed();
                                tracing::warn!(
                                    name = %task_name,
                                    admission_failure = "response_timeout",
                                    "RNode reconnect capability response timed out"
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
                            Err(RNodeStrictPreflightError::Capability(error)) => {
                                carrier_online_r.store(false, Ordering::SeqCst);
                                online_r.store(false, Ordering::SeqCst);
                                reconnect_writer.cancel();
                                let writer_finish = finish_rnode_writer(reconnect_writer).await;
                                if writer_finish == RNodeWriterFinish::NonQuiesced {
                                    snapshot_publisher
                                        .stopped(RNodeRuntimeReason::DriverTerminated);
                                    return;
                                }
                                tracing::warn!(
                                    name = %task_name,
                                    admission_failure = error.log_class(),
                                    "RNode reconnect capability admission rejected"
                                );
                                snapshot_publisher
                                    .stopped_for_admission_rejection(error.failure_class());
                                return;
                            }
                            Err(RNodeStrictPreflightError::Transport(error)) => {
                                carrier_online_r.store(false, Ordering::SeqCst);
                                online_r.store(false, Ordering::SeqCst);
                                reconnect_writer.cancel();
                                let writer_finish = finish_rnode_writer(reconnect_writer).await;
                                if writer_finish == RNodeWriterFinish::NonQuiesced {
                                    snapshot_publisher
                                        .stopped(RNodeRuntimeReason::DriverTerminated);
                                    return;
                                }
                                snapshot_publisher.connection_attempt_failed();
                                tracing::warn!(
                                    name = %task_name,
                                    error = %error,
                                    "RNode reconnect capability transport failed"
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
                    } else {
                        match initialise_reconnecting_rnode_writer(
                            &reconnect_writer,
                            &task_config,
                            &mut stop_rx,
                        )
                        .await
                        {
                            Ok(RNodeReconnectStartup::Complete) => (
                                opened,
                                reconnect_writer,
                                RNodeGenerationProtocolSeed::Legacy,
                            ),
                            Ok(RNodeReconnectStartup::StopRequested) => {
                                tracing::info!(
                                    name = %task_name,
                                    "RNode stop requested during reconnect startup"
                                );
                                snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                                let _ = send_detach_request(&reconnect_writer.control_tx, id).await;
                                reconnect_writer.cancel();
                                let _ = finish_rnode_writer(reconnect_writer).await;
                                snapshot_publisher.stopped(RNodeRuntimeReason::StopRequested);
                                return;
                            }
                            Err(failure) => {
                                carrier_online_r.store(false, Ordering::SeqCst);
                                online_r.store(false, Ordering::SeqCst);
                                reconnect_writer.cancel();
                                let writer_finish = finish_rnode_writer(reconnect_writer).await;
                                if writer_finish == RNodeWriterFinish::NonQuiesced {
                                    snapshot_publisher
                                        .stopped(RNodeRuntimeReason::DriverTerminated);
                                    return;
                                }
                                snapshot_publisher.connection_attempt_failed();
                                tracing::warn!(
                                    name = %task_name,
                                    error = %failure,
                                    "RNode reconnect startup failed"
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
                }
            };

            carrier_online_r.store(true, Ordering::SeqCst);
            online_r.store(false, Ordering::SeqCst);
            let mut protocol_state = match protocol_seed {
                RNodeGenerationProtocolSeed::Legacy => {
                    let state = RNodeProtocolState::new(protocol_target);
                    sync_rnode_interface_online(&online_r, &state);
                    snapshot_publisher.connection_established();
                    state
                }
                RNodeGenerationProtocolSeed::CapabilityAdmitted {
                    protocol_state,
                    admission,
                } => {
                    sync_rnode_interface_online(&online_r, &protocol_state);
                    snapshot_publisher
                        .capability_connection_established(&protocol_state, admission);
                    protocol_state
                }
            };
            let mut port_r = port_r;

            let ready = generation_writer.ready.clone();
            let packet_tx = generation_writer.packet_tx.clone();
            let control_tx = generation_writer.control_tx.clone();

            let rx_ref = rx.clone();
            let fwd_handle = RNodeTaskGuard::new(tokio::spawn(async move {
                let mut receiver = rx_ref.lock().await;
                while let Some(data) = receiver.recv().await {
                    if packet_tx.send(data).await.is_err() {
                        break;
                    }
                }
            }));

            let mut deframer = kiss::RawKissDeframer::new();
            let mut buf = [0u8; 1024];
            let mut last_rssi: Option<f32> = None;
            let mut last_snr: Option<f32> = None;
            let mut transport_closed = false;
            let mut stop_requested = false;
            let mut read_task_failed = false;

            loop {
                if stop_rx.try_recv().is_ok() {
                    tracing::info!(name = %task_name, "RNode stop requested");
                    online_r.store(false, Ordering::SeqCst);
                    snapshot_publisher.shutting_down(RNodeRuntimeReason::StopRequested);
                    let _ = send_detach_request(&control_tx, id).await;
                    stop_requested = true;
                    break;
                }
                if generation_writer.task.is_finished() || !carrier_online_r.load(Ordering::SeqCst)
                {
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
                                // Publish Ready only after the public handle and
                                // packet gate reflect the same reducer state.
                                sync_rnode_interface_online(&online_r, &protocol_state);
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
                                        apply_rnode_ready_permit(&ready, &frame, is_ready);
                                    }
                                    RNodeResponse::None => {}
                                }
                            }
                            if transport_closed {
                                break;
                            }
                        }
                    }
                    Ok(Err((_port, e))) => {
                        tracing::warn!(error = %e, "RNode read error");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "RNode read task panicked");
                        read_task_failed = true;
                        break;
                    }
                }
            }

            if transport_closed {
                online_r.store(false, Ordering::SeqCst);
                snapshot_publisher.shutting_down(RNodeRuntimeReason::TransportConsumerClosed);
            }
            carrier_online_r.store(false, Ordering::SeqCst);
            online_r.store(false, Ordering::SeqCst);
            generation_writer.cancel();
            fwd_handle.abort_and_wait().await;
            drop(control_tx);
            drop(ready);
            let writer_finish = finish_rnode_writer(generation_writer).await;

            if let Some(reason) = rnode_generation_terminal_reason(
                stop_requested,
                transport_closed,
                read_task_failed,
                writer_finish,
            ) {
                snapshot_publisher.stopped(reason);
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
    fn admission_failure_classes_keep_legacy_log_tokens() {
        let cases: &[(RNodeCapabilityAdmissionError, &str)] = &[
            (
                RNodeCapabilityAdmissionError::ResponseTimedOut,
                "response_timeout",
            ),
            (
                RNodeCapabilityAdmissionError::ReadLimitExceeded { limit: 1 },
                "read_limit",
            ),
            (
                RNodeCapabilityAdmissionError::InputLimitExceeded { limit: 1 },
                "input_limit",
            ),
            (
                RNodeCapabilityAdmissionError::FrameLimitExceeded { limit: 1 },
                "frame_limit",
            ),
            (
                RNodeCapabilityAdmissionError::MalformedProtocolFrame {
                    rejection: crate::rnode_protocol::RNodeFrameRejection::UnknownCommand,
                },
                "malformed_protocol",
            ),
            (RNodeCapabilityAdmissionError::DeviceError, "device_error"),
            (
                RNodeCapabilityAdmissionError::DetectionRejected,
                "detection_rejected",
            ),
            (
                RNodeCapabilityAdmissionError::UnsupportedFirmware,
                "unsupported_firmware",
            ),
            (
                RNodeCapabilityAdmissionError::DuplicateEepromResponse,
                "duplicate_eeprom",
            ),
            (
                RNodeCapabilityAdmissionError::CapabilityImage(
                    crate::rnode_capabilities::RNodeCapabilityParseError::InfoNotLocked,
                ),
                "invalid_capability_image",
            ),
            (
                RNodeCapabilityAdmissionError::RadioSettings(
                    crate::rnode_capabilities::RNodeRadioAdmissionError::TxPowerExceedsMaximum {
                        requested_dbm: 23,
                        max_dbm: 22,
                    },
                ),
                "radio_settings_rejected",
            ),
        ];
        for (error, token) in cases {
            assert_eq!(error.failure_class().log_class(), *token);
        }
    }

    #[test]
    fn admission_rejection_stop_carries_class_and_ordinary_stops_do_not() {
        let (mut publisher, driver) = new_rnode_driver_observation(RNodeTransportClass::Ble);
        publisher.stopped_for_admission_rejection(
            RNodeCapabilityAdmissionFailureClass::InvalidCapabilityImage,
        );
        let snapshot = driver.snapshot();
        assert_eq!(snapshot.phase, RNodeRuntimePhase::Stopped);
        assert_eq!(
            snapshot.reason,
            Some(RNodeRuntimeReason::CapabilityAdmissionRejected)
        );
        assert_eq!(
            snapshot.capability_admission_failure,
            Some(RNodeCapabilityAdmissionFailureClass::InvalidCapabilityImage)
        );

        let (mut ordinary, driver) = new_rnode_driver_observation(RNodeTransportClass::Ble);
        ordinary.stopped(RNodeRuntimeReason::StopRequested);
        let snapshot = driver.snapshot();
        assert_eq!(snapshot.capability_admission_failure, None);
    }

    // reconnect_started only exists under the transport features.
    #[cfg(any(
        feature = "serial",
        feature = "rnode-tcp",
        feature = "ble",
        target_os = "android"
    ))]
    #[test]
    fn new_generations_clear_a_stale_admission_failure_class() {
        let (mut publisher, driver) = new_rnode_driver_observation(RNodeTransportClass::Ble);
        publisher.update(|snapshot| {
            snapshot.capability_admission_failure =
                Some(RNodeCapabilityAdmissionFailureClass::DeviceError);
        });
        publisher.reconnect_started();
        assert_eq!(driver.snapshot().capability_admission_failure, None);

        publisher.update(|snapshot| {
            snapshot.capability_admission_failure =
                Some(RNodeCapabilityAdmissionFailureClass::DeviceError);
        });
        publisher.connection_established();
        assert_eq!(driver.snapshot().capability_admission_failure, None);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[derive(Default)]
    struct ScriptedWriterState {
        writes: Vec<Vec<u8>>,
        write_calls: usize,
        flush_calls: usize,
        fail_write_at: Option<usize>,
        fail_flush_at: Option<usize>,
        block_flush_at: Option<usize>,
        blocked_flush_entered: bool,
        release_blocked_flush: bool,
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[derive(Clone, Default)]
    struct ScriptedWriter {
        shared: Arc<(std::sync::Mutex<ScriptedWriterState>, std::sync::Condvar)>,
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    impl ScriptedWriter {
        fn failing(fail_write_at: Option<usize>, fail_flush_at: Option<usize>) -> Self {
            let writer = Self::default();
            {
                let mut state = writer.shared.0.lock().expect("scripted writer poisoned");
                state.fail_write_at = fail_write_at;
                state.fail_flush_at = fail_flush_at;
            }
            writer
        }

        fn blocking_flush(call: usize) -> Self {
            let writer = Self::default();
            writer
                .shared
                .0
                .lock()
                .expect("scripted writer poisoned")
                .block_flush_at = Some(call);
            writer
        }

        fn release_flush(&self) {
            let mut state = self.shared.0.lock().expect("scripted writer poisoned");
            state.release_blocked_flush = true;
            self.shared.1.notify_all();
        }

        fn writes(&self) -> Vec<Vec<u8>> {
            self.shared
                .0
                .lock()
                .expect("scripted writer poisoned")
                .writes
                .clone()
        }

        fn flush_calls(&self) -> usize {
            self.shared
                .0
                .lock()
                .expect("scripted writer poisoned")
                .flush_calls
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    impl std::io::Write for ScriptedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let mut state = self.shared.0.lock().expect("scripted writer poisoned");
            state.write_calls += 1;
            let call = state.write_calls;
            if state.fail_write_at == Some(call) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    format!("scripted write failure at call {call}"),
                ));
            }
            state.writes.push(bytes.to_vec());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            let (lock, condition) = &*self.shared;
            let mut state = lock.lock().expect("scripted writer poisoned");
            state.flush_calls += 1;
            let call = state.flush_calls;
            if state.block_flush_at == Some(call) {
                state.blocked_flush_entered = true;
                condition.notify_all();
                while !state.release_blocked_flush {
                    state = condition
                        .wait(state)
                        .expect("scripted writer poisoned while blocked");
                }
            }
            if state.fail_flush_at == Some(call) {
                return Err(std::io::Error::other(format!(
                    "scripted flush failure at call {call}"
                )));
            }
            Ok(())
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn scripted_writer_context(
        flow_control: bool,
        ready: Arc<AtomicBool>,
        carrier_online: Arc<AtomicBool>,
        txb: Arc<AtomicU64>,
        beacon: Option<(Duration, Bytes)>,
        beacon_poll_interval: Duration,
    ) -> RNodeWriterContext {
        RNodeWriterContext {
            id: 0x5C71,
            flow_control,
            ready,
            carrier_online,
            interface_online: Arc::new(AtomicBool::new(true)),
            cancelled: Arc::new(AtomicBool::new(false)),
            txb,
            beacon,
            beacon_poll_interval,
            idle_probe_interval: None,
            idle_probes_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    async fn wait_for_scripted_writer(
        writer: &ScriptedWriter,
        predicate: impl Fn(&ScriptedWriterState) -> bool,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                {
                    let state = writer.shared.0.lock().expect("scripted writer poisoned");
                    if predicate(&state) {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("scripted writer condition timed out");
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    async fn yield_until_rnode_test(mut condition: impl FnMut() -> bool, failure: &'static str) {
        // Keep the paused-clock tests runnable while their real spawn_blocking
        // operations finish. A timer-based wait could let Tokio auto-advance
        // to a later probe deadline before the physical writer is observed.
        for _ in 0..100_000 {
            if condition() {
                return;
            }
            tokio::task::yield_now().await;
        }
        assert!(condition(), "{failure}");
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    async fn yield_to_rnode_tasks() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn assert_scripted_io_failure(
        failure: &RNodeWriteFailure,
        phase: RNodeWritePhase,
        flush: bool,
    ) {
        assert_eq!(failure.phase, phase);
        let error = match (&failure.kind, flush) {
            (RNodeWriteFailureKind::Write(error), false) => {
                assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
                error
            }
            (RNodeWriteFailureKind::Flush(error), true) => {
                assert_eq!(error.kind(), std::io::ErrorKind::Other);
                error
            }
            (kind, _) => panic!("unexpected scripted failure: {kind:?}"),
        };
        assert!(error.to_string().contains("scripted"));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn apply_scripted_ready_frame(ready: &AtomicBool, frame: &[u8]) {
        let mut last_rssi = None;
        let mut last_snr = None;
        let RNodeResponse::Ready(is_ready) =
            process_rnode_response(CMD_READY, frame, 0x5C71, &mut last_rssi, &mut last_snr)
        else {
            panic!("CMD_READY must produce a readiness response");
        };
        apply_rnode_ready_permit(ready, frame, is_ready);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    async fn exercise_scripted_writer_failure(phase: RNodeWritePhase, flush: bool) {
        let scripted = ScriptedWriter::failing((!flush).then_some(1), flush.then_some(1));
        let online = Arc::new(AtomicBool::new(true));
        let txb = Arc::new(AtomicU64::new(0));
        let mut context = scripted_writer_context(
            false,
            Arc::new(AtomicBool::new(true)),
            online.clone(),
            txb.clone(),
            None,
            Duration::from_millis(5),
        );
        if phase == RNodeWritePhase::Probe {
            context.idle_probe_interval = Some(Duration::from_millis(10));
        }
        let writer = spawn_rnode_writer(scripted, context);

        let acknowledged_failure = match phase {
            RNodeWritePhase::Packet => {
                writer
                    .packet_tx
                    .send(Bytes::from_static(b"packet"))
                    .await
                    .unwrap();
                None
            }
            RNodeWritePhase::Probe => None,
            _ => Some(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    request_rnode_control_write(&writer.control_tx, phase, vec![phase as u8]),
                )
                .await
                .expect("scripted control write timed out")
                .expect_err("scripted control write must fail"),
            ),
        };

        let RNodeGenerationWriter { mut task, .. } = writer;
        let actor_failure = tokio::time::timeout(Duration::from_secs(2), task.take())
            .await
            .expect("scripted writer task timed out")
            .expect("scripted writer task panicked")
            .expect_err("scripted writer must report its I/O failure");
        assert_scripted_io_failure(&actor_failure, phase, flush);
        assert!(!online.load(Ordering::SeqCst));

        if let Some(acknowledged_failure) = acknowledged_failure {
            assert_scripted_io_failure(&acknowledged_failure, phase, flush);
            match (&acknowledged_failure.kind, &actor_failure.kind) {
                (RNodeWriteFailureKind::Write(ack), RNodeWriteFailureKind::Write(actor))
                | (RNodeWriteFailureKind::Flush(ack), RNodeWriteFailureKind::Flush(actor)) => {
                    assert!(Arc::ptr_eq(ack, actor));
                }
                _ => panic!("ack and actor failures must describe the same operation"),
            }
        }

        let expected_txb = if phase == RNodeWritePhase::Packet && flush {
            b"packet".len() as u64
        } else {
            0
        };
        assert_eq!(
            txb.load(Ordering::Relaxed),
            expected_txb,
            "only a fully written packet payload is accounted; controls never are"
        );
    }

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

    fn assert_invalid_radio_settings_field(
        settings: &RNodeRadioSettings,
        expected: RNodeConfigField,
    ) {
        let error = settings.validate().expect_err("radio settings must fail");
        assert_eq!(error.field(), expected, "{error}");
    }

    #[test]
    fn test_rnode_radio_settings_validation_accepts_inclusive_boundaries() {
        assert!(
            RNodeRadioSettings::new(
                RNODE_FREQUENCY_MIN_HZ,
                RNODE_BANDWIDTH_MIN_HZ,
                RNODE_SPREADING_FACTOR_MIN,
                RNODE_CODING_RATE_MIN,
                RNODE_TX_POWER_MIN_DBM,
            )
            .validate()
            .is_ok()
        );
        assert!(
            RNodeRadioSettings::new(
                RNODE_FREQUENCY_MAX_HZ,
                RNODE_BANDWIDTH_MAX_HZ,
                RNODE_SPREADING_FACTOR_MAX,
                RNODE_CODING_RATE_MAX,
                RNODE_TX_POWER_MAX_DBM,
            )
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn test_rnode_radio_settings_validation_rejects_each_outside_boundary() {
        let valid = RNodeRadioSettings::new(868_000_000, 125_000, 7, 5, 14);

        for frequency in [RNODE_FREQUENCY_MIN_HZ - 1, RNODE_FREQUENCY_MAX_HZ + 1] {
            assert_invalid_radio_settings_field(
                &RNodeRadioSettings { frequency, ..valid },
                RNodeConfigField::Frequency,
            );
        }
        for bandwidth in [RNODE_BANDWIDTH_MIN_HZ - 1, RNODE_BANDWIDTH_MAX_HZ + 1] {
            assert_invalid_radio_settings_field(
                &RNodeRadioSettings { bandwidth, ..valid },
                RNodeConfigField::Bandwidth,
            );
        }
        for spreading_factor in [
            RNODE_SPREADING_FACTOR_MIN - 1,
            RNODE_SPREADING_FACTOR_MAX + 1,
        ] {
            assert_invalid_radio_settings_field(
                &RNodeRadioSettings {
                    spreading_factor,
                    ..valid
                },
                RNodeConfigField::SpreadingFactor,
            );
        }
        for coding_rate in [RNODE_CODING_RATE_MIN - 1, RNODE_CODING_RATE_MAX + 1] {
            assert_invalid_radio_settings_field(
                &RNodeRadioSettings {
                    coding_rate,
                    ..valid
                },
                RNodeConfigField::CodingRate,
            );
        }
        assert_invalid_radio_settings_field(
            &RNodeRadioSettings {
                tx_power: RNODE_TX_POWER_MAX_DBM + 1,
                ..valid
            },
            RNodeConfigField::TxPower,
        );
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
        assert_eq!(
            seq,
            build_radio_configuration_sequence(&RNodeRadioSettings::from(&cfg)),
            "runtime init without airtime limits must preserve the public radio sequence"
        );

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(
            frames,
            vec![
                (CMD_RADIO_STATE, vec![RADIO_STATE_OFF]),
                (CMD_FREQUENCY, cfg.frequency.to_be_bytes().to_vec()),
                (CMD_BANDWIDTH, cfg.bandwidth.to_be_bytes().to_vec()),
                (CMD_SF, vec![cfg.spreading_factor]),
                (CMD_CR, vec![cfg.coding_rate]),
                (CMD_TXPOWER, vec![cfg.tx_power]),
                (CMD_RADIO_STATE, vec![RADIO_STATE_ON]),
            ]
        );
    }

    #[test]
    fn test_radio_configuration_sequence_has_exact_reviewed_order_and_payloads() {
        let settings = RNodeRadioSettings::new(915_000_000, 250_000, 10, 8, 22);
        let sequence = build_radio_configuration_sequence(&settings);

        let mut deframer = kiss::RawKissDeframer::new();
        assert_eq!(
            deframer.feed(&sequence),
            vec![
                (CMD_RADIO_STATE, vec![RADIO_STATE_OFF]),
                (CMD_FREQUENCY, settings.frequency.to_be_bytes().to_vec()),
                (CMD_BANDWIDTH, settings.bandwidth.to_be_bytes().to_vec()),
                (CMD_SF, vec![settings.spreading_factor]),
                (CMD_CR, vec![settings.coding_rate]),
                (CMD_TXPOWER, vec![settings.tx_power]),
                (CMD_RADIO_STATE, vec![RADIO_STATE_ON]),
            ]
        );
    }

    #[test]
    fn test_ble_radio_reassertion_stages_match_upstream_order_without_radio_off() {
        let mut config = RNodeConfig::new("rnode0", "ble://RNode Test");
        config.frequency = 915_000_000;
        config.bandwidth = 250_000;
        config.spreading_factor = 9;
        config.coding_rate = 5;
        config.tx_power = 17;
        config.st_alock = Some(10.0);
        config.lt_alock = Some(1.0);

        let stages = build_ble_radio_reassertion_stages(&config);
        let mut deframer = kiss::RawKissDeframer::new();
        let frames: Vec<_> = stages
            .iter()
            .flat_map(|stage| deframer.feed(stage))
            .collect();

        assert_eq!(
            frames,
            vec![
                (CMD_FREQUENCY, config.frequency.to_be_bytes().to_vec()),
                (CMD_BANDWIDTH, config.bandwidth.to_be_bytes().to_vec()),
                (CMD_TXPOWER, vec![config.tx_power]),
                (CMD_SF, vec![config.spreading_factor]),
                (CMD_CR, vec![config.coding_rate]),
                (CMD_ST_ALOCK, 1_000u16.to_be_bytes().to_vec()),
                (CMD_LT_ALOCK, 100u16.to_be_bytes().to_vec()),
                (CMD_RADIO_STATE, vec![RADIO_STATE_ON]),
            ]
        );
        assert!(frames.iter().all(|(command, payload)| {
            *command != CMD_RADIO_STATE || payload.as_slice() != [RADIO_STATE_OFF]
        }));
        assert_eq!(
            stages.len(),
            frames.len(),
            "each BLE control command must remain an independently paced stage"
        );
    }

    #[test]
    fn test_ble_radio_reassertion_omits_unconfigured_airtime_stages() {
        let config = RNodeConfig::new("rnode0", "ble://RNode Test");
        let stages = build_ble_radio_reassertion_stages(&config);
        let mut deframer = kiss::RawKissDeframer::new();
        let commands: Vec<_> = stages
            .iter()
            .flat_map(|stage| deframer.feed(stage))
            .map(|(command, _)| command)
            .collect();

        assert_eq!(
            commands,
            vec![
                CMD_FREQUENCY,
                CMD_BANDWIDTH,
                CMD_TXPOWER,
                CMD_SF,
                CMD_CR,
                CMD_RADIO_STATE,
            ]
        );
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
        assert_eq!(
            cmds,
            vec![
                CMD_RADIO_STATE,
                CMD_FREQUENCY,
                CMD_BANDWIDTH,
                CMD_SF,
                CMD_CR,
                CMD_TXPOWER,
                CMD_ST_ALOCK,
                CMD_LT_ALOCK,
                CMD_RADIO_STATE,
            ]
        );
        assert_eq!(frames[0].1, vec![RADIO_STATE_OFF]);
        assert_eq!(frames.last().unwrap().1, vec![RADIO_STATE_ON]);
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
        assert_eq!(
            frames,
            vec![
                (CMD_DETECT, vec![DETECT_REQ]),
                (CMD_FW_VERSION, vec![0x00]),
                (CMD_PLATFORM, vec![0x00]),
                (CMD_MCU, vec![0x00]),
            ]
        );
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

    #[test]
    fn test_driver_shutdown_is_idempotent_across_clones() {
        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(4);
        let (_publisher, driver) = new_rnode_driver_observation_with_shutdown(
            RNodeTransportClass::Tcp,
            RNodeDriverShutdown::from_stop_sender(stop_tx),
        );
        let clone = driver.clone();

        driver.request_shutdown();
        clone.request_shutdown();
        driver.request_shutdown();

        assert!(stop_rx.try_recv().is_ok());
        assert!(
            matches!(stop_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "all handle clones must share one shutdown request"
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

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_exact_shutdown_and_registry_cleanup_resist_same_id_aba() {
        let id = 0x0BAD_5701;
        let (old_tx, mut old_rx) = mpsc::channel::<()>(2);
        let (_old_publisher, old_driver) = new_rnode_driver_observation_with_shutdown(
            RNodeTransportClass::Tcp,
            RNodeDriverShutdown::from_stop_sender(old_tx.clone()),
        );
        let old_guard = register_rnode_stop(id, old_tx);

        let (new_tx, mut new_rx) = mpsc::channel::<()>(2);
        let (_new_publisher, _new_driver) = new_rnode_driver_observation_with_shutdown(
            RNodeTransportClass::Tcp,
            RNodeDriverShutdown::from_stop_sender(new_tx.clone()),
        );
        let new_guard = register_rnode_stop(id, new_tx);

        drop(old_guard);
        old_driver.request_shutdown();
        assert!(old_rx.try_recv().is_ok());
        assert!(
            matches!(new_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "the retired handle must not stop the newer same-ID driver"
        );

        stop_rnode_interface(id);
        assert!(
            new_rx.try_recv().is_ok(),
            "retired guard cleanup must preserve the newer compatibility entry"
        );
        drop(new_guard);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_writer_startup_has_two_flush_acked_stages() {
        let scripted = ScriptedWriter::blocking_flush(1);
        let writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicU64::new(0)),
                None,
                Duration::from_millis(5),
            ),
        );
        assert!(writer.ready.load(Ordering::SeqCst));
        let config = RNodeConfig::new("scripted", "tcp://127.0.0.1:1");
        let startup_config = config.clone();
        let mut startup = tokio::spawn(async move {
            let result = initialise_rnode_writer(&writer, &startup_config).await;
            (result, writer)
        });

        wait_for_scripted_writer(&scripted, |state| state.blocked_flush_entered).await;
        assert_eq!(scripted.writes(), vec![build_detect_sequence()]);
        assert_eq!(scripted.flush_calls(), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut startup)
                .await
                .is_err(),
            "detect must not be acknowledged before its flush completes"
        );

        scripted.release_flush();
        let (result, writer) = tokio::time::timeout(Duration::from_secs(2), startup)
            .await
            .expect("startup task timed out")
            .expect("startup task panicked");
        result.expect("scripted startup must succeed");
        assert_eq!(
            scripted.writes(),
            vec![build_detect_sequence(), build_init_sequence(&config)]
        );
        assert_eq!(scripted.flush_calls(), 2);
        finish_rnode_writer(writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_writer_startup_reports_exact_failed_stage() {
        for (fail_write_at, fail_flush_at, phase) in [
            (Some(1), None, RNodeWritePhase::Detect),
            (None, Some(1), RNodeWritePhase::Detect),
            (Some(2), None, RNodeWritePhase::Initialise),
            (None, Some(2), RNodeWritePhase::Initialise),
        ] {
            let scripted = ScriptedWriter::failing(fail_write_at, fail_flush_at);
            let writer = spawn_rnode_writer(
                scripted,
                scripted_writer_context(
                    false,
                    Arc::new(AtomicBool::new(true)),
                    Arc::new(AtomicBool::new(true)),
                    Arc::new(AtomicU64::new(0)),
                    None,
                    Duration::from_millis(5),
                ),
            );
            let config = RNodeConfig::new("scripted", "tcp://127.0.0.1:1");
            let failure = tokio::time::timeout(
                Duration::from_secs(2),
                initialise_rnode_writer(&writer, &config),
            )
            .await
            .expect("scripted startup timed out")
            .expect_err("scripted startup must fail");
            assert_scripted_io_failure(&failure, phase, fail_flush_at.is_some());
            finish_rnode_writer(writer).await;
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_reconnect_startup_stop_preempts_init_and_retains_writer_for_detach() {
        let scripted = ScriptedWriter::blocking_flush(1);
        let writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicU64::new(0)),
                None,
                Duration::from_millis(5),
            ),
        );
        let config = RNodeConfig::new("scripted-reconnect", "tcp://127.0.0.1:1");
        let startup_config = config.clone();
        let (stop_tx, mut stop_rx) = mpsc::channel(1);
        let startup = tokio::spawn(async move {
            let result =
                initialise_reconnecting_rnode_writer(&writer, &startup_config, &mut stop_rx).await;
            (result, writer)
        });

        wait_for_scripted_writer(&scripted, |state| state.blocked_flush_entered).await;
        stop_tx.send(()).await.unwrap();
        let (result, writer) = tokio::time::timeout(Duration::from_secs(2), startup)
            .await
            .expect("interruptible reconnect startup timed out")
            .expect("interruptible reconnect startup panicked");
        assert_eq!(result.unwrap(), RNodeReconnectStartup::StopRequested);

        let release = scripted.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            release.release_flush();
        });
        send_detach_request(&writer.control_tx, 0x5C71)
            .await
            .expect("retained reconnect writer must detach");
        assert_eq!(
            scripted.writes(),
            vec![build_detect_sequence(), build_detach_sequence()],
            "stop between stages must never enqueue init"
        );
        assert_eq!(
            finish_rnode_writer(writer).await,
            RNodeWriterFinish::Quiesced
        );
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_writer_reports_write_and_flush_errors_for_every_phase() {
        for phase in [
            RNodeWritePhase::Detect,
            RNodeWritePhase::Capability,
            RNodeWritePhase::Initialise,
            RNodeWritePhase::Packet,
            RNodeWritePhase::Probe,
            RNodeWritePhase::Detach,
        ] {
            exercise_scripted_writer_failure(phase, false).await;
            exercise_scripted_writer_failure(phase, true).await;
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_rnode_tcp_idle_probe_interval_matches_driver_contract() {
        assert_eq!(RNODE_TCP_IDLE_PROBE_INTERVAL, Duration::from_millis(3_500));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test(start_paused = true)]
    async fn test_strict_probe_gate_emits_nothing_before_init_then_starts_fresh_deadline() {
        let scripted = ScriptedWriter::default();
        let mut context = scripted_writer_context(
            false,
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicU64::new(0)),
            None,
            Duration::from_millis(5),
        );
        let interval = Duration::from_millis(20);
        context.idle_probe_interval = Some(interval);
        context.idle_probes_enabled.store(false, Ordering::SeqCst);
        let writer = spawn_rnode_writer(scripted.clone(), context);

        yield_to_rnode_tasks().await;
        tokio::time::advance(interval * 4).await;
        yield_to_rnode_tasks().await;
        assert!(
            scripted.writes().is_empty(),
            "strict preflight must not emit recurring detect probes"
        );

        writer.idle_probes_enabled.store(true, Ordering::SeqCst);
        let init = vec![0xA1, 0xA2, 0xA3];
        request_rnode_startup_write(
            &writer.control_tx,
            RNodeWritePhase::Initialise,
            init.clone(),
        )
        .await
        .unwrap();
        assert_eq!(scripted.writes(), vec![init.clone()]);

        tokio::time::advance(interval - Duration::from_millis(1)).await;
        yield_to_rnode_tasks().await;
        assert_eq!(scripted.writes(), vec![init.clone()]);
        tokio::time::advance(Duration::from_millis(1)).await;
        yield_until_rnode_test(
            || scripted.flush_calls() >= 2,
            "post-init idle probe did not start from a fresh deadline",
        )
        .await;
        assert_eq!(scripted.writes(), vec![init, build_detect_sequence()]);

        finish_rnode_writer(writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test(start_paused = true)]
    async fn test_rnode_idle_probe_repeats_without_response_and_bypasses_driver_state() {
        let scripted = ScriptedWriter::default();
        let ready = Arc::new(AtomicBool::new(false));
        let txb = Arc::new(AtomicU64::new(17));
        let mut context = scripted_writer_context(
            true,
            ready.clone(),
            Arc::new(AtomicBool::new(true)),
            txb.clone(),
            None,
            Duration::from_millis(5),
        );
        context.idle_probe_interval = Some(Duration::from_millis(20));
        let writer = spawn_rnode_writer(scripted.clone(), context);

        yield_to_rnode_tasks().await;
        for expected_flushes in 1..=3 {
            tokio::time::advance(Duration::from_millis(20)).await;
            yield_until_rnode_test(
                || scripted.flush_calls() >= expected_flushes,
                "idle probe did not complete after its advanced deadline",
            )
            .await;
        }
        let writes = scripted.writes();
        let detect = build_detect_sequence();
        assert_eq!(writes.len(), 3);
        assert!(writes.iter().all(|write| write == &detect));
        assert!(
            !ready.load(Ordering::SeqCst),
            "idle probes must not consume or manufacture READY permits"
        );
        assert_eq!(
            txb.load(Ordering::Relaxed),
            17,
            "idle probes must not affect payload accounting"
        );

        finish_rnode_writer(writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test(start_paused = true)]
    async fn test_serial_style_scripted_writer_has_no_idle_probe() {
        let scripted = ScriptedWriter::default();
        let context = scripted_writer_context(
            false,
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicU64::new(0)),
            None,
            Duration::from_millis(5),
        );
        assert_eq!(context.idle_probe_interval, None);
        let writer = spawn_rnode_writer(scripted.clone(), context);

        yield_to_rnode_tasks().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        yield_to_rnode_tasks().await;
        assert!(scripted.writes().is_empty());
        assert_eq!(scripted.flush_calls(), 0);

        finish_rnode_writer(writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test(start_paused = true)]
    async fn test_idle_probe_deadline_is_write_relative_and_applied_after_flush() {
        let scripted = ScriptedWriter::blocking_flush(1);
        let mut context = scripted_writer_context(
            false,
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicU64::new(0)),
            None,
            Duration::from_millis(5),
        );
        context.idle_probe_interval = Some(Duration::from_millis(100));
        let writer = spawn_rnode_writer(scripted.clone(), context);
        let control = vec![0xA1, 0xA2];
        let control_tx = writer.control_tx.clone();
        let control_bytes = control.clone();
        let control_task = tokio::spawn(async move {
            request_rnode_control_write(&control_tx, RNodeWritePhase::Initialise, control_bytes)
                .await
        });

        yield_until_rnode_test(
            || {
                scripted
                    .shared
                    .0
                    .lock()
                    .expect("scripted writer poisoned")
                    .blocked_flush_entered
            },
            "control write never entered its blocking flush",
        )
        .await;
        tokio::time::advance(Duration::from_millis(140)).await;
        assert_eq!(scripted.writes(), vec![control.clone()]);
        assert_eq!(scripted.flush_calls(), 1);

        scripted.release_flush();
        yield_until_rnode_test(
            || scripted.flush_calls() >= 2,
            "overdue write-relative probe did not run after flush release",
        )
        .await;
        control_task
            .await
            .expect("blocked control task panicked")
            .expect("blocked control must complete after flush release");
        assert_eq!(
            scripted.writes(),
            vec![control, build_detect_sequence()],
            "the successful flush must apply the already elapsed write-relative deadline"
        );

        finish_rnode_writer(writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test(start_paused = true)]
    async fn test_rnode_startup_completion_resets_idle_probe_deadline() {
        let scripted = ScriptedWriter::default();
        let mut context = scripted_writer_context(
            false,
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicU64::new(0)),
            None,
            Duration::from_millis(5),
        );
        context.idle_probe_interval = Some(Duration::from_millis(100));
        let writer = spawn_rnode_writer(scripted.clone(), context);
        let config = RNodeConfig::new("scripted-probe", "tcp://127.0.0.1:1");
        let startup_config = config.clone();
        let startup = tokio::spawn(async move {
            let result = initialise_rnode_writer(&writer, &startup_config).await;
            (result, writer)
        });

        yield_until_rnode_test(
            || scripted.flush_calls() >= 2,
            "startup writes did not complete",
        )
        .await;
        yield_to_rnode_tasks().await;
        let (startup_result, writer) = startup.await.expect("startup task panicked");
        startup_result.expect("scripted startup must succeed");
        assert_eq!(
            scripted.writes(),
            vec![build_detect_sequence(), build_init_sequence(&config)]
        );
        tokio::time::advance(Duration::from_millis(50)).await;
        yield_to_rnode_tasks().await;
        assert_eq!(scripted.writes().len(), 2);

        tokio::time::advance(Duration::from_millis(50)).await;
        yield_until_rnode_test(
            || scripted.flush_calls() >= 3,
            "startup-relative idle probe did not complete",
        )
        .await;
        assert_eq!(
            scripted.writes(),
            vec![
                build_detect_sequence(),
                build_init_sequence(&config),
                build_detect_sequence(),
            ]
        );
        finish_rnode_writer(writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test(start_paused = true)]
    async fn test_packet_and_station_id_flushes_each_reset_idle_probe_deadline() {
        let scripted = ScriptedWriter::default();
        let txb = Arc::new(AtomicU64::new(0));
        let callsign = Bytes::from_static(b"PROBE-ID");
        let mut context = scripted_writer_context(
            false,
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(true)),
            txb.clone(),
            Some((Duration::from_millis(120), callsign.clone())),
            Duration::from_millis(5),
        );
        context.idle_probe_interval = Some(Duration::from_millis(240));
        let writer = spawn_rnode_writer(scripted.clone(), context);

        yield_to_rnode_tasks().await;
        tokio::time::advance(Duration::from_millis(160)).await;
        yield_to_rnode_tasks().await;
        assert!(scripted.writes().is_empty());
        let payload = Bytes::from_static(b"probe-reset-payload");
        writer.packet_tx.send(payload.clone()).await.unwrap();
        yield_until_rnode_test(
            || scripted.flush_calls() >= 1,
            "payload write did not complete",
        )
        .await;
        assert_eq!(scripted.writes(), vec![kiss::frame(&payload)]);

        // The generation-relative deadline expires here, but the payload
        // write moved it forward. No probe may overtake the later station ID.
        tokio::time::advance(Duration::from_millis(80)).await;
        yield_to_rnode_tasks().await;
        assert_eq!(scripted.writes(), vec![kiss::frame(&payload)]);

        tokio::time::advance(Duration::from_millis(40)).await;
        yield_until_rnode_test(
            || scripted.flush_calls() >= 2,
            "station-ID write did not complete",
        )
        .await;
        assert_eq!(
            scripted.writes(),
            vec![kiss::frame(&payload), kiss::frame(&callsign)],
            "the payload must replace the earlier generation deadline"
        );

        // The payload-relative deadline expires here, but the station-ID
        // write moved it forward independently.
        tokio::time::advance(Duration::from_millis(120)).await;
        yield_to_rnode_tasks().await;
        assert_eq!(
            scripted.writes(),
            vec![kiss::frame(&payload), kiss::frame(&callsign)],
            "the station-ID flush must replace the payload-relative deadline"
        );

        tokio::time::advance(Duration::from_millis(120)).await;
        yield_until_rnode_test(
            || scripted.flush_calls() >= 3,
            "station-ID-relative idle probe did not complete",
        )
        .await;
        assert_eq!(
            scripted.writes(),
            vec![
                kiss::frame(&payload),
                kiss::frame(&callsign),
                build_detect_sequence(),
            ]
        );
        assert_eq!(
            txb.load(Ordering::Relaxed),
            (payload.len() + callsign.len()) as u64
        );
        finish_rnode_writer(writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test(start_paused = true)]
    async fn test_flow_stalled_packet_does_not_block_or_mutate_idle_probe_state() {
        let scripted = ScriptedWriter::default();
        let ready = Arc::new(AtomicBool::new(false));
        let txb = Arc::new(AtomicU64::new(0));
        let callsign = Bytes::from_static(b"STALLED-ID");
        let mut context = scripted_writer_context(
            true,
            ready.clone(),
            Arc::new(AtomicBool::new(true)),
            txb.clone(),
            Some((Duration::from_millis(120), callsign.clone())),
            Duration::from_millis(5),
        );
        context.idle_probe_interval = Some(Duration::from_millis(25));
        let writer = spawn_rnode_writer(scripted.clone(), context);
        let payload = Bytes::from_static(b"flow-stalled-probe-payload");
        let framed_payload = kiss::frame(&payload);
        let framed_callsign = kiss::frame(&callsign);
        writer.packet_tx.send(payload.clone()).await.unwrap();

        yield_until_rnode_test(
            || writer.packet_tx.capacity() == RNODE_PACKET_WRITE_QUEUE,
            "writer did not retain the flow-stalled raw packet",
        )
        .await;
        for expected_flushes in 1..=5 {
            tokio::time::advance(Duration::from_millis(25)).await;
            yield_until_rnode_test(
                || scripted.flush_calls() >= expected_flushes,
                "flow-stalled idle probe did not complete",
            )
            .await;
        }
        let detect = build_detect_sequence();
        let stalled_writes = scripted.writes();
        assert_eq!(stalled_writes.len(), 5);
        assert!(stalled_writes.iter().all(|write| write == &detect));
        assert_eq!(writer.packet_tx.capacity(), RNODE_PACKET_WRITE_QUEUE);
        assert!(!ready.load(Ordering::SeqCst));
        assert_eq!(txb.load(Ordering::Relaxed), 0);

        apply_scripted_ready_frame(&ready, &[0x01]);
        tokio::time::advance(RNODE_FLOW_POLL_INTERVAL).await;
        yield_until_rnode_test(
            || {
                scripted
                    .writes()
                    .iter()
                    .any(|write| write == &framed_payload)
            },
            "permitted flow-stalled payload did not complete",
        )
        .await;
        assert!(!ready.load(Ordering::SeqCst));
        assert_eq!(txb.load(Ordering::Relaxed), payload.len() as u64);

        apply_scripted_ready_frame(&ready, &[0x01]);
        tokio::time::advance(Duration::from_millis(60)).await;
        yield_until_rnode_test(
            || scripted.flush_calls() >= 7,
            "idle probe did not complete while station-ID permit was held",
        )
        .await;
        assert!(
            scripted
                .writes()
                .iter()
                .all(|write| write != &framed_callsign),
            "probes must not arm a station-ID timer before the payload write"
        );
        assert!(
            ready.load(Ordering::SeqCst),
            "idle probes must leave the offered station-ID permit intact"
        );
        assert_eq!(txb.load(Ordering::Relaxed), payload.len() as u64);

        tokio::time::advance(Duration::from_millis(60)).await;
        let expected_txb = (payload.len() + callsign.len()) as u64;
        yield_until_rnode_test(
            || {
                scripted
                    .writes()
                    .iter()
                    .any(|write| write == &framed_callsign)
                    && txb.load(Ordering::Relaxed) == expected_txb
            },
            "station-ID beacon did not complete after its advanced deadline",
        )
        .await;
        assert!(!ready.load(Ordering::SeqCst));
        assert_eq!(txb.load(Ordering::Relaxed), expected_txb);
        let writes = scripted.writes();
        assert_eq!(
            writes
                .iter()
                .filter(|write| *write == &framed_payload)
                .count(),
            1
        );
        assert_eq!(
            writes
                .iter()
                .filter(|write| *write == &framed_callsign)
                .count(),
            1
        );
        assert!(writes.iter().all(|write| {
            write == &detect || write == &framed_payload || write == &framed_callsign
        }));

        finish_rnode_writer(writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test(start_paused = true)]
    async fn test_cancelled_idle_probe_does_not_replay_into_fresh_generation() {
        let scripted = ScriptedWriter::default();
        let mut old_context = scripted_writer_context(
            false,
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicU64::new(0)),
            None,
            Duration::from_millis(5),
        );
        old_context.idle_probe_interval = Some(Duration::from_millis(80));
        let old_writer = spawn_rnode_writer(scripted.clone(), old_context);

        yield_to_rnode_tasks().await;
        tokio::time::advance(Duration::from_millis(30)).await;
        yield_to_rnode_tasks().await;
        old_writer.cancel();
        assert_eq!(
            finish_rnode_writer(old_writer).await,
            RNodeWriterFinish::Quiesced
        );
        tokio::time::advance(Duration::from_millis(100)).await;
        yield_to_rnode_tasks().await;
        assert!(
            scripted.writes().is_empty(),
            "cancelled generations cannot leave a deferred probe behind"
        );

        let mut new_context = scripted_writer_context(
            false,
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicU64::new(0)),
            None,
            Duration::from_millis(5),
        );
        new_context.idle_probe_interval = Some(Duration::from_millis(60));
        let new_writer = spawn_rnode_writer(scripted.clone(), new_context);
        yield_to_rnode_tasks().await;
        tokio::time::advance(Duration::from_millis(30)).await;
        yield_to_rnode_tasks().await;
        assert!(
            scripted.writes().is_empty(),
            "a fresh generation must start with a fresh idle deadline"
        );

        tokio::time::advance(Duration::from_millis(30)).await;
        yield_until_rnode_test(
            || scripted.flush_calls() >= 1,
            "fresh-generation idle probe did not complete",
        )
        .await;
        assert_eq!(scripted.writes(), vec![build_detect_sequence()]);
        finish_rnode_writer(new_writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_writer_flow_permits_saturate_preserve_fifo_and_bypass_control() {
        let scripted = ScriptedWriter::default();
        let ready = Arc::new(AtomicBool::new(true));
        let txb = Arc::new(AtomicU64::new(0));
        let writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                true,
                ready.clone(),
                Arc::new(AtomicBool::new(true)),
                txb.clone(),
                None,
                Duration::from_millis(5),
            ),
        );
        let first = Bytes::from_static(b"first");
        let second = Bytes::from_static(b"second");
        let third = Bytes::from_static(b"third");

        assert!(
            writer.ready.load(Ordering::SeqCst),
            "flow control must start with one permissive packet token"
        );
        writer.packet_tx.send(first.clone()).await.unwrap();
        wait_for_scripted_writer(&scripted, |state| state.flush_calls == 1).await;
        assert_eq!(scripted.writes(), vec![kiss::frame(&first)]);
        assert!(!ready.load(Ordering::SeqCst));
        assert_eq!(txb.load(Ordering::Relaxed), first.len() as u64);

        // Multiple positive readiness frames received before a packet can only
        // saturate the single boolean token; they cannot bank future permits.
        apply_scripted_ready_frame(&ready, &[0x01]);
        apply_scripted_ready_frame(&ready, &[]);
        apply_scripted_ready_frame(&ready, &[0x01, 0x01]);
        assert!(
            ready.load(Ordering::SeqCst),
            "malformed readiness frames must have no operational effect"
        );
        apply_scripted_ready_frame(&ready, &[0x7F]);
        writer.packet_tx.send(second.clone()).await.unwrap();
        writer.packet_tx.send(third.clone()).await.unwrap();
        wait_for_scripted_writer(&scripted, |state| state.flush_calls == 2).await;
        assert!(!ready.load(Ordering::SeqCst));
        assert_eq!(
            scripted.writes(),
            vec![kiss::frame(&first), kiss::frame(&second)]
        );
        assert_eq!(
            txb.load(Ordering::Relaxed),
            (first.len() + second.len()) as u64
        );

        // Give the actor several flow polls to retain the third packet as raw
        // pending data before exercising the independent control lane.
        tokio::time::sleep(RNODE_FLOW_POLL_INTERVAL * 3).await;
        let control = vec![0xAA, 0xBB];
        tokio::time::timeout(
            Duration::from_secs(2),
            request_rnode_control_write(
                &writer.control_tx,
                RNodeWritePhase::Detect,
                control.clone(),
            ),
        )
        .await
        .expect("flow-bypass control write timed out")
        .expect("control must bypass a flow-blocked packet");
        assert_eq!(
            scripted.writes(),
            vec![kiss::frame(&first), kiss::frame(&second), control.clone()]
        );
        assert_eq!(
            txb.load(Ordering::Relaxed),
            (first.len() + second.len()) as u64
        );

        // Malformed frames have no operational effect, while an exact-width
        // zero frame explicitly retains the blocked state.
        apply_scripted_ready_frame(&ready, &[]);
        apply_scripted_ready_frame(&ready, &[0x01, 0x00]);
        apply_scripted_ready_frame(&ready, &[0x00]);
        tokio::time::sleep(RNODE_FLOW_POLL_INTERVAL * 3).await;
        assert_eq!(
            scripted.writes(),
            vec![kiss::frame(&first), kiss::frame(&second), control]
        );
        assert_eq!(
            txb.load(Ordering::Relaxed),
            (first.len() + second.len()) as u64
        );

        apply_scripted_ready_frame(&ready, &[0x01]);
        wait_for_scripted_writer(&scripted, |state| state.flush_calls == 4).await;
        assert_eq!(
            scripted.writes(),
            vec![
                kiss::frame(&first),
                kiss::frame(&second),
                vec![0xAA, 0xBB],
                kiss::frame(&third),
            ]
        );
        assert_eq!(
            txb.load(Ordering::Relaxed),
            (first.len() + second.len() + third.len()) as u64
        );
        assert!(!ready.load(Ordering::SeqCst));

        send_detach_request(&writer.control_tx, 0x5C71)
            .await
            .expect("flow-bypass writer must detach");
        assert_eq!(
            txb.load(Ordering::Relaxed),
            (first.len() + second.len() + third.len()) as u64,
            "control frames must not contribute to payload accounting"
        );
        finish_rnode_writer(writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_flow_stall_arms_beacon_only_at_granted_write_boundary() {
        let scripted = ScriptedWriter::default();
        let ready = Arc::new(AtomicBool::new(false));
        let txb = Arc::new(AtomicU64::new(0));
        let callsign = Bytes::from_static(b"FLOW-ID");
        let beacon_interval = Duration::from_millis(500);
        let writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                true,
                ready.clone(),
                Arc::new(AtomicBool::new(true)),
                txb.clone(),
                Some((beacon_interval, callsign.clone())),
                Duration::from_millis(5),
            ),
        );
        let payload = Bytes::from_static(b"flow-stalled-payload");
        writer.packet_tx.send(payload.clone()).await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            while writer.packet_tx.capacity() != RNODE_PACKET_WRITE_QUEUE {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("writer did not retain the flow-stalled raw packet");
        tokio::time::sleep(beacon_interval + Duration::from_millis(50)).await;
        assert!(scripted.writes().is_empty());
        assert_eq!(
            txb.load(Ordering::Relaxed),
            0,
            "dequeueing a flow-stalled packet must not account or arm its beacon timer"
        );

        apply_scripted_ready_frame(&ready, &[0x01]);
        wait_for_scripted_writer(&scripted, |state| state.flush_calls == 1).await;
        assert_eq!(scripted.writes(), vec![kiss::frame(&payload)]);
        assert_eq!(txb.load(Ordering::Relaxed), payload.len() as u64);
        assert!(!ready.load(Ordering::SeqCst));

        // A token offered immediately after the payload would expose a beacon
        // whose timer was incorrectly armed at dequeue. It must remain unused
        // until the new write-boundary-relative interval has elapsed.
        apply_scripted_ready_frame(&ready, &[0x01]);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(scripted.writes(), vec![kiss::frame(&payload)]);
        assert_eq!(txb.load(Ordering::Relaxed), payload.len() as u64);
        assert!(ready.load(Ordering::SeqCst));
        apply_scripted_ready_frame(&ready, &[0x00]);

        tokio::time::sleep(beacon_interval).await;
        let control = vec![0xD1, 0xD2];
        tokio::time::timeout(
            Duration::from_secs(2),
            request_rnode_control_write(
                &writer.control_tx,
                RNodeWritePhase::Detect,
                control.clone(),
            ),
        )
        .await
        .expect("due-beacon control bypass timed out")
        .expect("control must bypass a flow-stalled due beacon");
        assert_eq!(
            scripted.writes(),
            vec![kiss::frame(&payload), control.clone()]
        );
        assert_eq!(
            txb.load(Ordering::Relaxed),
            payload.len() as u64,
            "a due beacon without a permit remains unaccounted"
        );

        apply_scripted_ready_frame(&ready, &[0x01]);
        wait_for_scripted_writer(&scripted, |state| state.flush_calls == 3).await;
        assert_eq!(
            scripted.writes(),
            vec![kiss::frame(&payload), control, kiss::frame(&callsign)]
        );
        assert_eq!(
            txb.load(Ordering::Relaxed),
            (payload.len() + callsign.len()) as u64
        );
        assert!(!ready.load(Ordering::SeqCst));

        send_detach_request(&writer.control_tx, 0x5C71)
            .await
            .expect("flow/beacon writer must detach");
        finish_rnode_writer(writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_due_beacon_is_not_starved_by_continuously_ready_packet_lane() {
        let scripted = ScriptedWriter::default();
        let txb = Arc::new(AtomicU64::new(0));
        let callsign = Bytes::from_static(b"LANE-ID");
        let writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(true)),
                txb.clone(),
                Some((Duration::ZERO, callsign.clone())),
                Duration::from_millis(2),
            ),
        );
        let packets = [
            Bytes::from_static(b"lane-one"),
            Bytes::from_static(b"lane-two"),
            Bytes::from_static(b"lane-three"),
        ];
        for packet in &packets {
            writer.packet_tx.send(packet.clone()).await.unwrap();
        }

        wait_for_scripted_writer(&scripted, |state| state.flush_calls == 6).await;
        assert_eq!(
            scripted.writes(),
            vec![
                kiss::frame(&packets[0]),
                kiss::frame(&callsign),
                kiss::frame(&packets[1]),
                kiss::frame(&callsign),
                kiss::frame(&packets[2]),
                kiss::frame(&callsign),
            ],
            "elapsed beacons may interleave but must preserve application FIFO"
        );
        assert_eq!(
            txb.load(Ordering::Relaxed),
            packets.iter().map(Bytes::len).sum::<usize>() as u64
                + (callsign.len() * packets.len()) as u64
        );

        send_detach_request(&writer.control_tx, 0x5C71)
            .await
            .expect("continuous-lane writer must detach");
        finish_rnode_writer(writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_writer_detach_is_flush_acked_and_terminal() {
        let scripted = ScriptedWriter::default();
        let writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicU64::new(0)),
                None,
                Duration::from_millis(5),
            ),
        );

        send_detach_request(&writer.control_tx, 0x5C71)
            .await
            .expect("detach must be acknowledged after flush");
        assert_eq!(scripted.flush_calls(), 1);
        assert_eq!(scripted.writes(), vec![build_detach_sequence()]);
        assert!(
            writer
                .packet_tx
                .send(Bytes::from_static(b"after-leave"))
                .await
                .is_err()
        );
        let failure = tokio::time::timeout(
            Duration::from_secs(2),
            request_rnode_control_write(&writer.control_tx, RNodeWritePhase::Detect, vec![0xCC]),
        )
        .await
        .expect("post-detach control request timed out")
        .expect_err("control lane must close after leave");
        assert!(matches!(failure.kind, RNodeWriteFailureKind::QueueClosed));

        let RNodeGenerationWriter { mut task, .. } = writer;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), task.take())
                .await
                .expect("detach writer task timed out")
                .expect("writer task panicked")
                .expect("detach writer failed"),
            RNodeWriterExit::Detached
        );
        assert_eq!(scripted.writes(), vec![build_detach_sequence()]);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_detach_deadline_includes_control_queue_wait() {
        let scripted = ScriptedWriter::blocking_flush(1);
        let writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicU64::new(0)),
                None,
                Duration::from_millis(5),
            ),
        );

        let mut acknowledgements = Vec::new();
        for byte in 0..=RNODE_CONTROL_WRITE_QUEUE {
            let (acknowledgement, result) = oneshot::channel();
            writer
                .control_tx
                .send(RNodeControlWriteRequest {
                    phase: RNodeWritePhase::Detect,
                    bytes: vec![byte as u8],
                    acknowledgement,
                })
                .await
                .unwrap();
            acknowledgements.push(result);
            if byte == 0 {
                wait_for_scripted_writer(&scripted, |state| state.blocked_flush_entered).await;
            }
        }

        let started = tokio::time::Instant::now();
        let failure = tokio::time::timeout(
            Duration::from_secs(2),
            send_detach_request(&writer.control_tx, 0x5C71),
        )
        .await
        .expect("outer detach test timeout elapsed")
        .expect_err("full control lane must consume the detach deadline");
        let elapsed = started.elapsed();
        assert!(matches!(
            failure.kind,
            RNodeWriteFailureKind::DeadlineElapsed
        ));
        assert!(elapsed >= Duration::from_millis(450), "{elapsed:?}");

        scripted.release_flush();
        finish_rnode_writer(writer).await;
        drop(acknowledgements);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_non_quiesced_rnode_writer_finish_is_terminal_not_reconnectable() {
        let scripted = ScriptedWriter::blocking_flush(1);
        let writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicU64::new(0)),
                None,
                Duration::from_millis(5),
            ),
        );
        writer
            .packet_tx
            .send(Bytes::from_static(b"blocked-physical-write"))
            .await
            .unwrap();
        wait_for_scripted_writer(&scripted, |state| state.blocked_flush_entered).await;

        let finish = finish_rnode_writer(writer).await;
        assert_eq!(finish, RNodeWriterFinish::NonQuiesced);
        assert_eq!(
            rnode_generation_terminal_reason(false, false, false, finish),
            Some(RNodeRuntimeReason::DriverTerminated)
        );
        assert_eq!(
            rnode_generation_terminal_reason(true, false, false, finish),
            Some(RNodeRuntimeReason::StopRequested),
            "explicit stop classification must win"
        );
        assert_eq!(
            rnode_generation_terminal_reason(false, true, false, finish),
            Some(RNodeRuntimeReason::TransportConsumerClosed),
            "transport closure classification must win"
        );
        assert_eq!(
            rnode_generation_terminal_reason(false, false, true, RNodeWriterFinish::Quiesced,),
            Some(RNodeRuntimeReason::DriverTerminated),
            "losing the read stream must prevent reconnect"
        );

        // `abort` cannot cancel spawn_blocking. Release the test writer so its
        // physical operation can really finish after the terminal decision.
        scripted.release_flush();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_cancelled_rnode_generation_never_replays_pending_packet() {
        let scripted = ScriptedWriter::blocking_flush(1);
        let old_txb = Arc::new(AtomicU64::new(0));
        let old_writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(true)),
                old_txb.clone(),
                None,
                Duration::from_millis(5),
            ),
        );
        let old_first = Bytes::from_static(b"old-active");
        let old_buffered_one = Bytes::from_static(b"old-buffered-one");
        let old_buffered_two = Bytes::from_static(b"old-buffered-two");
        old_writer.packet_tx.send(old_first.clone()).await.unwrap();
        wait_for_scripted_writer(&scripted, |state| state.blocked_flush_entered).await;
        old_writer
            .packet_tx
            .send(old_buffered_one.clone())
            .await
            .unwrap();
        old_writer
            .packet_tx
            .send(old_buffered_two.clone())
            .await
            .unwrap();

        old_writer.cancel();
        scripted.release_flush();
        assert_eq!(
            finish_rnode_writer(old_writer).await,
            RNodeWriterFinish::Quiesced
        );
        assert_eq!(scripted.writes(), vec![kiss::frame(&old_first)]);
        assert_eq!(
            old_txb.load(Ordering::Relaxed),
            old_first.len() as u64,
            "cancellation must prevent buffered packet preparation/accounting"
        );

        let new_writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicU64::new(0)),
                None,
                Duration::from_millis(5),
            ),
        );
        let new_packet = Bytes::from_static(b"new-generation");
        new_writer.packet_tx.send(new_packet.clone()).await.unwrap();
        wait_for_scripted_writer(&scripted, |state| state.writes.len() == 2).await;
        assert_eq!(
            scripted.writes(),
            vec![kiss::frame(&old_first), kiss::frame(&new_packet)]
        );

        send_detach_request(&new_writer.control_tx, 0x5C71)
            .await
            .expect("new generation writer must detach");
        finish_rnode_writer(new_writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_flow_stalled_cancelled_backlog_does_not_account_or_replay() {
        let scripted = ScriptedWriter::default();
        let txb = Arc::new(AtomicU64::new(0));
        let stalled_writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                true,
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(true)),
                txb.clone(),
                Some((Duration::from_millis(5), Bytes::from_static(b"STALL-ID"))),
                Duration::from_millis(2),
            ),
        );

        // One raw packet can be held by the actor in addition to the entire
        // bounded packet lane. Completing all 257 sends therefore proves that
        // the flow-stalled pending slot has been populated.
        tokio::time::timeout(Duration::from_secs(2), async {
            for index in 0..=RNODE_PACKET_WRITE_QUEUE {
                stalled_writer
                    .packet_tx
                    .send(Bytes::from(vec![
                        (index & 0xFF) as u8,
                        ((index >> 8) & 0xFF) as u8,
                    ]))
                    .await
                    .expect("stalled generation packet lane closed");
            }
        })
        .await
        .expect("stalled generation never populated its pending slot");

        assert!(scripted.writes().is_empty());
        assert_eq!(
            txb.load(Ordering::Relaxed),
            0,
            "raw pending and queued packets must not account before a write attempt"
        );
        stalled_writer.cancel();
        assert_eq!(
            finish_rnode_writer(stalled_writer).await,
            RNodeWriterFinish::Quiesced
        );
        assert!(scripted.writes().is_empty());
        assert_eq!(txb.load(Ordering::Relaxed), 0);

        let next_writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(true)),
                txb.clone(),
                None,
                Duration::from_millis(2),
            ),
        );
        let next_packet = Bytes::from_static(b"next-generation-only");
        next_writer
            .packet_tx
            .send(next_packet.clone())
            .await
            .unwrap();
        wait_for_scripted_writer(&scripted, |state| state.flush_calls == 1).await;
        assert_eq!(scripted.writes(), vec![kiss::frame(&next_packet)]);
        assert_eq!(
            txb.load(Ordering::Relaxed),
            next_packet.len() as u64,
            "only the new generation's attempted payload may account"
        );

        send_detach_request(&next_writer.control_tx, 0x5C71)
            .await
            .expect("next generation writer must detach");
        finish_rnode_writer(next_writer).await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_writer_preserves_packet_accounting_and_beacon_semantics() {
        let scripted = ScriptedWriter::default();
        let txb = Arc::new(AtomicU64::new(0));
        let callsign = Bytes::from_static(b"N0CALL");
        let writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(true)),
                txb.clone(),
                Some((Duration::from_millis(100), callsign.clone())),
                Duration::from_millis(5),
            ),
        );
        let packet = Bytes::from_static(b"payload");
        writer.packet_tx.send(packet.clone()).await.unwrap();
        wait_for_scripted_writer(&scripted, |state| state.flush_calls >= 1).await;
        assert_eq!(scripted.writes(), vec![kiss::frame(&packet)]);
        assert_eq!(
            txb.load(Ordering::Relaxed),
            packet.len() as u64,
            "normal payload accounting uses the raw, unframed length"
        );

        wait_for_scripted_writer(&scripted, |state| state.flush_calls >= 2).await;
        assert_eq!(
            scripted.writes(),
            vec![kiss::frame(&packet), kiss::frame(&callsign)]
        );
        assert_eq!(
            txb.load(Ordering::Relaxed),
            (packet.len() + callsign.len()) as u64
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(scripted.writes().len(), 2, "beacon must disarm itself");

        send_detach_request(&writer.control_tx, 0x5C71)
            .await
            .expect("beacon writer must detach");
        assert_eq!(
            txb.load(Ordering::Relaxed),
            (packet.len() + callsign.len()) as u64,
            "detach control bytes must not affect payload accounting"
        );
        finish_rnode_writer(writer).await;
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
        debug_assert!(
            !kiss::RawKissDeframer::new()
                .feed(&startup)
                .iter()
                .any(|(command, _)| *command == CMD_ROM_READ),
            "legacy startup must never request EEPROM contents"
        );
        startup
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn strict_capability_eeprom(model: u8) -> Vec<u8> {
        use md5::{Digest, Md5};

        let mut bytes = vec![0xFF; 296];
        bytes[0] = 0x03;
        bytes[1] = model;
        bytes[2..11].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let checksum: [u8; 16] = Md5::digest(&bytes[..11]).into();
        bytes[11..27].copy_from_slice(&checksum);
        bytes[100] = kiss::FEND;
        bytes[101] = kiss::FESC;
        bytes[0x9B] = 0x73;
        bytes
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn strict_capability_responses(model: u8) -> Vec<u8> {
        let mut responses = Vec::new();
        kiss::frame_with_command_into(CMD_DETECT, &[DETECT_RESP], &mut responses);
        kiss::frame_with_command_into(
            CMD_FW_VERSION,
            &[REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN],
            &mut responses,
        );
        kiss::frame_with_command_into(
            CMD_ROM_READ,
            &strict_capability_eeprom(model),
            &mut responses,
        );
        responses
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn strict_radio_echoes(config: &RNodeConfig) -> Vec<u8> {
        let mut responses = Vec::new();
        kiss::frame_with_command_into(
            CMD_FREQUENCY,
            &config.frequency.to_be_bytes(),
            &mut responses,
        );
        kiss::frame_with_command_into(
            CMD_BANDWIDTH,
            &config.bandwidth.to_be_bytes(),
            &mut responses,
        );
        kiss::frame_with_command_into(CMD_SF, &[config.spreading_factor], &mut responses);
        kiss::frame_with_command_into(CMD_CR, &[config.coding_rate], &mut responses);
        kiss::frame_with_command_into(CMD_TXPOWER, &[config.tx_power], &mut responses);
        kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_ON], &mut responses);
        responses
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
        assert_eq!(snapshot.capability, RNodeCapabilityState::NotRequested);
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
    #[tokio::test]
    async fn test_strict_rnode_startup_orders_preflight_and_publishes_atomic_admission() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("strict-startup", &format!("tcp://{addr}"));
        let server_config = config.clone();
        let detect = build_detect_sequence();
        let capability_request =
            crate::rnode_capability_preflight::build_rnode_capability_request();
        let init = build_init_sequence(&config);
        let detach = build_detach_sequence();
        let (init_tx, mut init_rx) = tokio::sync::mpsc::unbounded_channel();
        let (echo_tx, echo_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert_eq!(read_exact_tcp(&mut stream, detect.len()), detect);
            assert_eq!(
                read_exact_tcp(&mut stream, capability_request.len()),
                capability_request
            );

            // These matching controls and this packet predate admitted init.
            // They must be reduced/suppressed privately and never make the
            // active generation ready or reach Transport.
            let mut responses = strict_radio_echoes(&server_config);
            kiss::frame_with_command_into(kiss::CMD_DATA, b"preflight-private", &mut responses);
            kiss::frame_with_command_into(CMD_PLATFORM, &[0x80], &mut responses);
            responses.extend_from_slice(&strict_capability_responses(0xB8));
            write_fragmented_tcp(&mut stream, &responses);

            assert_eq!(read_exact_tcp(&mut stream, init.len()), init);
            init_tx.send(()).unwrap();
            if echo_rx.recv_timeout(Duration::from_secs(3)).is_err() {
                return;
            }
            let mut active = strict_radio_echoes(&server_config);
            kiss::frame_with_command_into(kiss::CMD_DATA, b"post-init", &mut active);
            std::io::Write::write_all(&mut stream, &active).unwrap();
            assert_eq!(read_exact_tcp(&mut stream, detach.len()), detach);
        });

        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(8);
        let spawned = spawn_rnode_interface_with_driver_and_options(
            config,
            0xCA91,
            transport_tx,
            RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), init_rx.recv())
            .await
            .unwrap()
            .unwrap();

        let mut state = spawned.driver.watch();
        let admitted =
            wait_for_rnode_snapshot(&mut state, |snapshot| snapshot.connection_generation == 1)
                .await;
        assert_eq!(admitted.capability, RNodeCapabilityState::Verified);
        assert_eq!(admitted.phase, RNodeRuntimePhase::AwaitingReadiness);
        assert_eq!(admitted.detection, RNodeDetectionState::Confirmed);
        assert_eq!(
            admitted.firmware_compatibility,
            RNodeFirmwareCompatibility::Supported
        );
        assert_eq!(admitted.configuration, RNodeConfigurationState::Unknown);
        assert_eq!(admitted.radio, RNodeObservedRadioState::Unknown);
        assert!(transport_rx.try_recv().is_err());

        echo_tx.send(()).unwrap();
        let packet = receive_inbound_packet(&mut transport_rx).await;
        assert_eq!(packet.raw.as_ref(), b"post-init");
        let ready = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.connection_generation == 1 && snapshot.phase == RNodeRuntimePhase::Ready
        })
        .await;
        assert_eq!(ready.capability, RNodeCapabilityState::Verified);

        spawned.driver.request_shutdown();
        wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.phase == RNodeRuntimePhase::Stopped
        })
        .await;
        spawned.interface.read_task.await.unwrap();
        server.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_strict_initial_model_mismatch_is_typed_and_sends_no_init_or_detach() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("strict-mismatch", &format!("tcp://{addr}"));
        let detect = build_detect_sequence();
        let capability_request =
            crate::rnode_capability_preflight::build_rnode_capability_request();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(read_exact_tcp(&mut stream, detect.len()), detect);
            assert_eq!(
                read_exact_tcp(&mut stream, capability_request.len()),
                capability_request
            );
            // 0xB4 is a reviewed 420-520 MHz model; default 868 MHz settings
            // must be rejected before any radio mutation.
            std::io::Write::write_all(&mut stream, &strict_capability_responses(0xB4)).unwrap();
            let mut extra = [0u8; 1024];
            match std::io::Read::read(&mut stream, &mut extra) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::UnexpectedEof
                    ) => {}
                Ok(count) => panic!("strict rejection emitted {count} unexpected bytes"),
                Err(error) => panic!("unexpected strict rejection read error: {error}"),
            }
        });

        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(1);
        let error = match spawn_rnode_interface_with_driver_and_options(
            config,
            0xB401,
            transport_tx,
            RNodeStartupOptions::require_capability_admission(),
        )
        .await
        {
            Ok(_) => panic!("known-model mismatch must reject initial spawn"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            RNodeSpawnError::CapabilityAdmission(RNodeCapabilityAdmissionError::RadioSettings(
                crate::rnode_capabilities::RNodeRadioAdmissionError::FrequencyOutOfRange { .. }
            ))
        ));
        server.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_strict_initial_response_timeout_is_typed_and_sends_no_init_or_detach() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("strict-timeout", &format!("tcp://{addr}"));
        let detect = build_detect_sequence();
        let capability_request =
            crate::rnode_capability_preflight::build_rnode_capability_request();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(read_exact_tcp(&mut stream, detect.len()), detect);
            assert_eq!(
                read_exact_tcp(&mut stream, capability_request.len()),
                capability_request
            );
            let mut extra = [0u8; 1024];
            match std::io::Read::read(&mut stream, &mut extra) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::UnexpectedEof
                    ) => {}
                Ok(count) => panic!("strict timeout emitted {count} unexpected bytes"),
                Err(error) => panic!("unexpected strict timeout read error: {error}"),
            }
        });

        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(1);
        let error = match spawn_rnode_interface_with_driver_and_options(
            config,
            0x710E,
            transport_tx,
            RNodeStartupOptions::require_capability_admission(),
        )
        .await
        {
            Ok(_) => panic!("missing capability response must reject initial spawn"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            RNodeSpawnError::CapabilityAdmission(RNodeCapabilityAdmissionError::ResponseTimedOut)
        ));
        server.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_strict_reconnect_capability_rejection_is_terminal_without_init_or_detach() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("strict-terminal-reconnect", &format!("tcp://{addr}"));
        let detect = build_detect_sequence();
        let capability_request =
            crate::rnode_capability_preflight::build_rnode_capability_request();
        let init = build_init_sequence(&config);
        let (first_tx, mut first_rx) = tokio::sync::mpsc::unbounded_channel();
        let (close_tx, close_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            first
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert_eq!(read_exact_tcp(&mut first, detect.len()), detect);
            assert_eq!(
                read_exact_tcp(&mut first, capability_request.len()),
                capability_request
            );
            std::io::Write::write_all(&mut first, &strict_capability_responses(0xB8)).unwrap();
            assert_eq!(read_exact_tcp(&mut first, init.len()), init);
            first_tx.send(()).unwrap();
            close_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            drop(first);

            let (mut second, _) = listener.accept().unwrap();
            second
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert_eq!(read_exact_tcp(&mut second, detect.len()), detect);
            assert_eq!(
                read_exact_tcp(&mut second, capability_request.len()),
                capability_request
            );
            std::io::Write::write_all(&mut second, &strict_capability_responses(0xB4)).unwrap();
            let mut extra = [0u8; 1024];
            match std::io::Read::read(&mut second, &mut extra) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::UnexpectedEof
                    ) => {}
                Ok(count) => panic!("rejected reconnect emitted {count} unexpected bytes"),
                Err(error) => panic!("unexpected rejected reconnect read error: {error}"),
            }

            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_millis(700);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok(_) => panic!("capability rejection must terminate reconnects"),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("reconnect listener failed: {error}"),
                }
            }
        });

        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(1);
        let spawned = spawn_rnode_interface_with_driver_and_options(
            config,
            0xCA92,
            transport_tx,
            RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .unwrap();
        first_rx.recv().await.unwrap();
        let mut state = spawned.driver.watch();
        wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.connection_generation == 1
                && snapshot.capability == RNodeCapabilityState::Verified
        })
        .await;
        close_tx.send(()).unwrap();
        let stopped = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.phase == RNodeRuntimePhase::Stopped
                && snapshot.reason == Some(RNodeRuntimeReason::CapabilityAdmissionRejected)
        })
        .await;
        assert_eq!(stopped.disconnect_total, 1);
        assert_eq!(stopped.reconnect_total, 1);
        spawned.interface.read_task.await.unwrap();
        server.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[derive(Clone, Copy)]
    enum StrictReconnectTransient {
        Eof,
        ResponseTimeout,
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    async fn assert_strict_reconnect_transient_retries_then_readmits(
        transient: StrictReconnectTransient,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (interface_name, interface_id) = match transient {
            StrictReconnectTransient::Eof => ("strict-eof-reconnect", 0xCA93),
            StrictReconnectTransient::ResponseTimeout => ("strict-timeout-reconnect", 0xCA96),
        };
        let config = RNodeConfig::new(interface_name, &format!("tcp://{addr}"));
        let detect = build_detect_sequence();
        let capability_request =
            crate::rnode_capability_preflight::build_rnode_capability_request();
        let init = build_init_sequence(&config);
        let detach = build_detach_sequence();
        let (first_tx, mut first_rx) = tokio::sync::mpsc::unbounded_channel();
        let (third_tx, mut third_rx) = tokio::sync::mpsc::unbounded_channel();
        let (close_tx, close_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            first
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert_eq!(read_exact_tcp(&mut first, detect.len()), detect);
            assert_eq!(
                read_exact_tcp(&mut first, capability_request.len()),
                capability_request
            );
            std::io::Write::write_all(&mut first, &strict_capability_responses(0xB8)).unwrap();
            assert_eq!(read_exact_tcp(&mut first, init.len()), init);
            first_tx.send(()).unwrap();
            close_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            drop(first);

            // This failed connection receives one ROM request and no init
            // before a fresh retry generation.
            let (mut second, _) = listener.accept().unwrap();
            second
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert_eq!(read_exact_tcp(&mut second, detect.len()), detect);
            assert_eq!(
                read_exact_tcp(&mut second, capability_request.len()),
                capability_request
            );
            if matches!(transient, StrictReconnectTransient::ResponseTimeout) {
                let mut extra = [0u8; 1024];
                match std::io::Read::read(&mut second, &mut extra) {
                    Ok(0) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::UnexpectedEof
                        ) => {}
                    Ok(count) => panic!("timed-out reconnect emitted {count} unexpected bytes"),
                    Err(error) => panic!("unexpected timed-out reconnect read error: {error}"),
                }
            }
            drop(second);

            let (mut third, _) = listener.accept().unwrap();
            third
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert_eq!(read_exact_tcp(&mut third, detect.len()), detect);
            assert_eq!(
                read_exact_tcp(&mut third, capability_request.len()),
                capability_request
            );
            std::io::Write::write_all(&mut third, &strict_capability_responses(0xB8)).unwrap();
            assert_eq!(read_exact_tcp(&mut third, init.len()), init);
            third_tx.send(()).unwrap();
            assert_eq!(read_exact_tcp(&mut third, detach.len()), detach);
        });

        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(1);
        let spawned = spawn_rnode_interface_with_driver_and_options(
            config,
            interface_id,
            transport_tx,
            RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .unwrap();
        first_rx.recv().await.unwrap();
        let mut state = spawned.driver.watch();
        wait_for_rnode_snapshot(&mut state, |snapshot| snapshot.connection_generation == 1).await;
        close_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), third_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let readmitted = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.connection_generation == 2
                && snapshot.capability == RNodeCapabilityState::Verified
        })
        .await;
        assert_eq!(readmitted.disconnect_total, 1);
        assert_eq!(readmitted.reconnect_total, 2);

        spawned.driver.request_shutdown();
        wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.phase == RNodeRuntimePhase::Stopped
        })
        .await;
        spawned.interface.read_task.await.unwrap();
        server.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_strict_reconnect_transport_eof_retries_then_readmits() {
        assert_strict_reconnect_transient_retries_then_readmits(StrictReconnectTransient::Eof)
            .await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_strict_reconnect_response_timeout_retries_then_readmits() {
        assert_strict_reconnect_transient_retries_then_readmits(
            StrictReconnectTransient::ResponseTimeout,
        )
        .await;
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_stop_during_reconnect_preflight_quiesces_without_init_or_detach() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("strict-stop-preflight", &format!("tcp://{addr}"));
        let detect = build_detect_sequence();
        let capability_request =
            crate::rnode_capability_preflight::build_rnode_capability_request();
        let init = build_init_sequence(&config);
        let (first_tx, mut first_rx) = tokio::sync::mpsc::unbounded_channel();
        let (waiting_tx, mut waiting_rx) = tokio::sync::mpsc::unbounded_channel();
        let (close_tx, close_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            first
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert_eq!(read_exact_tcp(&mut first, detect.len()), detect);
            assert_eq!(
                read_exact_tcp(&mut first, capability_request.len()),
                capability_request
            );
            std::io::Write::write_all(&mut first, &strict_capability_responses(0xB8)).unwrap();
            assert_eq!(read_exact_tcp(&mut first, init.len()), init);
            first_tx.send(()).unwrap();
            close_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            drop(first);

            let (mut second, _) = listener.accept().unwrap();
            second
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert_eq!(read_exact_tcp(&mut second, detect.len()), detect);
            assert_eq!(
                read_exact_tcp(&mut second, capability_request.len()),
                capability_request
            );
            waiting_tx.send(()).unwrap();
            let mut extra = [0u8; 1024];
            match std::io::Read::read(&mut second, &mut extra) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::UnexpectedEof
                    ) => {}
                Ok(count) => panic!("pre-init stop emitted {count} unexpected bytes"),
                Err(error) => panic!("unexpected pre-init stop read error: {error}"),
            }
        });

        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(1);
        let spawned = spawn_rnode_interface_with_driver_and_options(
            config,
            0xCA94,
            transport_tx,
            RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .unwrap();
        first_rx.recv().await.unwrap();
        let mut state = spawned.driver.watch();
        wait_for_rnode_snapshot(&mut state, |snapshot| snapshot.connection_generation == 1).await;
        close_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(4), waiting_rx.recv())
            .await
            .unwrap()
            .unwrap();
        spawned.driver.request_shutdown();
        let stopped = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.phase == RNodeRuntimePhase::Stopped
                && snapshot.reason == Some(RNodeRuntimeReason::StopRequested)
        })
        .await;
        assert_eq!(stopped.disconnect_total, 1);
        spawned.interface.read_task.await.unwrap();
        server.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_stop_after_strict_admission_queues_detach_behind_blocked_init() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("strict-init-stop", &format!("tcp://{addr}"));
        let responses = strict_capability_responses(0xB8);
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            std::io::Write::write_all(&mut stream, &responses).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(3));
        });

        let port = RNodeStream::connect_tcp(&addr.to_string()).unwrap();
        let scripted = ScriptedWriter::blocking_flush(3);
        let writer = spawn_rnode_writer(
            scripted.clone(),
            scripted_writer_context(
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicU64::new(0)),
                None,
                Duration::from_millis(5),
            ),
        );
        let (stop_tx, mut stop_rx) = mpsc::channel(1);
        let result = {
            let preflight =
                run_rnode_capability_preflight(port, &writer, &config, Some(&mut stop_rx));
            tokio::pin!(preflight);

            tokio::select! {
                _ = wait_for_scripted_writer(&scripted, |state| state.blocked_flush_entered) => {}
                _ = &mut preflight => panic!("strict preflight ended before init entered its blocked flush"),
            }
            stop_tx.send(()).await.unwrap();
            preflight.await
        };
        assert!(matches!(
            result,
            Err(RNodeStrictPreflightError::StopRequestedAfterInitQueued)
        ));

        scripted.release_flush();
        send_detach_request(&writer.control_tx, 0xCA95)
            .await
            .expect("detach must follow an init that may have reached the radio");
        assert_eq!(
            scripted.writes(),
            vec![
                build_detect_sequence(),
                crate::rnode_capability_preflight::build_rnode_capability_request(),
                build_init_sequence(&config),
                build_detach_sequence(),
            ]
        );
        assert_eq!(
            finish_rnode_writer(writer).await,
            RNodeWriterFinish::Quiesced
        );
        release_tx.send(()).unwrap();
        server.join().unwrap();
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
        let driver = RNodeDriverHandle {
            state: state_rx,
            shutdown: RNodeDriverShutdown::inert_test(),
        };
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
    #[test]
    fn test_rnode_public_online_tracks_exact_ready_and_reset() {
        let mut state = RNodeProtocolState::new(TEST_PROTOCOL_TARGET);
        let online = AtomicBool::new(true);

        sync_rnode_interface_online(&online, &state);
        assert!(
            !online.load(Ordering::SeqCst),
            "an open carrier without protocol evidence is not publicly online"
        );

        for (position, (command, payload)) in protocol_required_frames(TEST_PROTOCOL_TARGET)
            .into_iter()
            .enumerate()
        {
            state.apply_frame(command, &payload);
            sync_rnode_interface_online(&online, &state);
            assert_eq!(
                online.load(Ordering::SeqCst),
                position == 7,
                "public online may change only with exact reducer readiness"
            );
        }

        state.apply_frame(CMD_RESET, &[0xF8]);
        sync_rnode_interface_online(&online, &state);
        assert!(
            !online.load(Ordering::SeqCst),
            "reset must revoke public readiness while the carrier remains open"
        );
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
    async fn test_rnode_driver_stop_immediately_after_spawn_detaches_without_reconnect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("rnode-immediate-stop", &format!("tcp://{addr}"));
        let expected_startup = tcp_startup_bytes(&config);
        let expected_detach = build_detach_sequence();
        let detach_len = expected_detach.len();
        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::unbounded_channel();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(
                read_exact_tcp(&mut stream, expected_startup.len()),
                expected_startup
            );
            let detach = read_exact_tcp(&mut stream, detach_len);

            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_millis(350);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok(_) => panic!("terminal stop must not open a reconnect generation"),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("RNode listener failed: {error}"),
                }
            }
            observed_tx.send(detach).unwrap();
        });

        let id = 0x1A11;
        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(1);
        let spawned = spawn_rnode_interface_with_driver(config, id, transport_tx)
            .await
            .unwrap();
        let mut state = spawned.driver.watch();

        // No yield between spawn completion and stop: this exercises the
        // initial-generation handoff window directly.
        stop_rnode_interface(id);
        let stopped = wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.phase == RNodeRuntimePhase::Stopped
                && snapshot.reason == Some(RNodeRuntimeReason::StopRequested)
        })
        .await;
        assert_eq!(stopped.disconnect_total, 0);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), observed_rx.recv())
                .await
                .expect("immediate-stop server timed out")
                .expect("immediate-stop server ended"),
            expected_detach
        );
        tokio::time::timeout(Duration::from_secs(2), spawned.interface.read_task)
            .await
            .expect("immediate-stop read task timed out")
            .expect("immediate-stop read task panicked");
        server.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_driver_holds_outbound_until_exact_protocol_readiness() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("rnode-awaiting-traffic", &format!("tcp://{addr}"));
        let target = RNodeProtocolTarget::new(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );
        let expected_startup = tcp_startup_bytes(&config);
        let payload = Bytes::from_static(b"traffic-before-protocol-readiness");
        let expected_packet = kiss::frame(&payload);
        let server_expected_packet = expected_packet.clone();
        let expected_detach = build_detach_sequence();
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();
        let (blocked_tx, mut blocked_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(
                read_exact_tcp(&mut stream, expected_startup.len()),
                expected_startup
            );

            stream
                .set_read_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            let mut premature = [0u8; 1];
            match std::io::Read::read(&mut stream, &mut premature) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                result => panic!("RNode wrote application data before protocol Ready: {result:?}"),
            }
            blocked_tx.send(()).unwrap();

            ready_rx.recv().unwrap();
            let mut readiness = Vec::new();
            for (command, payload) in protocol_required_frames(target) {
                kiss::frame_with_command_into(command, &payload, &mut readiness);
            }
            std::io::Write::write_all(&mut stream, &readiness).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            packet_tx
                .send(read_exact_tcp(&mut stream, server_expected_packet.len()))
                .unwrap();
            assert_eq!(
                read_exact_tcp(&mut stream, expected_detach.len()),
                expected_detach
            );
        });

        let id = 0xA417;
        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(1);
        let spawned = spawn_rnode_interface_with_driver(config, id, transport_tx)
            .await
            .unwrap();
        let mut state = spawned.driver.watch();
        wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.connection_generation == 1
                && snapshot.phase == RNodeRuntimePhase::AwaitingReadiness
        })
        .await;

        spawned.interface.tx.send(payload.clone()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), blocked_rx.recv())
            .await
            .expect("pre-readiness packet gate check timed out")
            .expect("pre-readiness packet gate server ended");
        assert!(!spawned.interface.online.load(Ordering::SeqCst));
        assert_eq!(
            spawned
                .interface
                .txb
                .as_ref()
                .expect("RNode TX counter")
                .load(Ordering::Relaxed),
            0,
            "queued data must not be physically written or accounted before Ready"
        );

        ready_tx.send(()).unwrap();
        wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.connection_generation == 1 && snapshot.phase == RNodeRuntimePhase::Ready
        })
        .await;
        assert!(spawned.interface.online.load(Ordering::SeqCst));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), packet_rx.recv())
                .await
                .expect("outbound RNode packet timed out")
                .expect("outbound RNode server ended"),
            expected_packet
        );
        assert_eq!(
            spawned
                .interface
                .txb
                .as_ref()
                .expect("RNode TX counter")
                .load(Ordering::Relaxed),
            payload.len() as u64
        );

        stop_rnode_interface(id);
        wait_for_rnode_snapshot(&mut state, |snapshot| {
            snapshot.phase == RNodeRuntimePhase::Stopped
        })
        .await;
        tokio::time::timeout(Duration::from_secs(2), spawned.interface.read_task)
            .await
            .expect("readiness-gated read task timed out")
            .expect("readiness-gated read task panicked");
        server.join().unwrap();
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
    fn test_tcp_write_interrupt_applies_to_cloned_stream() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut byte = [0u8; 1];
            match std::io::Read::read(&mut stream, &mut byte) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) => {}
                result => panic!("peer did not observe interrupted RNode socket: {result:?}"),
            }
        });

        let stream = RNodeStream::connect_tcp(&addr.to_string()).unwrap();
        let mut write_clone = stream.try_clone().unwrap();
        let interrupt = RNodeWriteInterrupt::from_stream(&stream).unwrap();
        drop(interrupt);
        assert!(
            std::io::Write::write_all(&mut write_clone, b"after-shutdown").is_err(),
            "shutdown on the read stream must interrupt its write clone"
        );
        peer.join().unwrap();
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
        let target = RNodeProtocolTarget::new(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );
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
                    let mut readiness = Vec::new();
                    for (command, payload) in protocol_required_frames(target) {
                        kiss::frame_with_command_into(command, &payload, &mut readiness);
                    }
                    std::io::Write::write_all(&mut stream, &readiness).unwrap();
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
        tokio::time::timeout(Duration::from_secs(2), async {
            while !handle.online.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reconnected RNode did not become online");

        handle.read_task.abort();
        drop(handle.tx);
        server.join().unwrap();
    }
}
