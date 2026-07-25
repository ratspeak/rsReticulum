//! Deterministic state reduction for the generic, single-radio RNode protocol.
//!
//! This module deliberately does not drive an interface. It gives serial, TCP,
//! USB, and BLE implementations one strict grammar and one order-independent
//! readiness decision to adopt in a later integration step. Callers pass
//! already-deframed extended-KISS command payloads to
//! [`RNodeProtocolState::apply_frame`].
//!
//! The reducer is intentionally limited to generic single-radio readiness and
//! flow-control evidence. It must not be used for `RNodeMultiInterface`: multi
//! virtual-port command bytes overlap generic commands (notably `0x90`). It
//! also does not retain opaque errors, EEPROM contents, hashes, Wi-Fi
//! credentials, signatures, or other administration data.

use crate::rnode;

/// Maximum accepted difference between configured and echoed frequency.
///
/// RNode firmware may quantise a requested frequency by a small amount. The
/// Python implementation accepts an absolute difference of up to 100 Hz.
pub const FREQUENCY_TOLERANCE_HZ: u32 = 100;

/// Firmware version reported by a generic RNode.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RNodeFirmwareVersion {
    pub major: u8,
    pub minor: u8,
}

impl RNodeFirmwareVersion {
    pub const fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// The minimum firmware supported by the current generic RNode protocol.
    pub const MINIMUM_SUPPORTED: Self =
        Self::new(rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN);

    pub fn is_supported(self) -> bool {
        self >= Self::MINIMUM_SUPPORTED
    }
}

/// Radio settings whose exact echoes establish that configuration completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RNodeProtocolTarget {
    pub frequency: u32,
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: u8,
}

impl RNodeProtocolTarget {
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
}

/// Generic single-radio commands understood by the reducer.
///
/// Keeping this set closed prevents accidental interpretation of
/// administration or multi-radio virtual-port commands as readiness evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeProtocolCommand {
    Frequency,
    Bandwidth,
    TransmitPower,
    SpreadingFactor,
    CodingRate,
    RadioState,
    Detect,
    FlowReady,
    FirmwareVersion,
    Reset,
    DeviceError,
}

impl RNodeProtocolCommand {
    const fn payload_len(self) -> usize {
        match self {
            Self::Frequency | Self::Bandwidth => 4,
            Self::FirmwareVersion => 2,
            Self::TransmitPower
            | Self::SpreadingFactor
            | Self::CodingRate
            | Self::RadioState
            | Self::Detect
            | Self::FlowReady
            | Self::Reset
            | Self::DeviceError => 1,
        }
    }
}

impl TryFrom<u8> for RNodeProtocolCommand {
    type Error = RNodeFrameRejection;

    fn try_from(command: u8) -> Result<Self, Self::Error> {
        match command {
            rnode::CMD_FREQUENCY => Ok(Self::Frequency),
            rnode::CMD_BANDWIDTH => Ok(Self::Bandwidth),
            rnode::CMD_TXPOWER => Ok(Self::TransmitPower),
            rnode::CMD_SF => Ok(Self::SpreadingFactor),
            rnode::CMD_CR => Ok(Self::CodingRate),
            rnode::CMD_RADIO_STATE => Ok(Self::RadioState),
            rnode::CMD_DETECT => Ok(Self::Detect),
            rnode::CMD_READY => Ok(Self::FlowReady),
            rnode::CMD_FW_VERSION => Ok(Self::FirmwareVersion),
            rnode::CMD_RESET => Ok(Self::Reset),
            rnode::CMD_ERROR => Ok(Self::DeviceError),
            _ => Err(RNodeFrameRejection::UnknownCommand),
        }
    }
}

/// Closed radio-state values accepted from a generic RNode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeRadioState {
    Off,
    On,
}

/// Closed detect-response values. Only [`Self::Confirmed`] is readiness
/// evidence; any other one-byte response actively clears prior confirmation
/// without retaining the device-provided byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeDetection {
    Unconfirmed,
    Confirmed,
}

/// Strictly decoded generic RNode frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeProtocolFrame {
    Frequency(u32),
    Bandwidth(u32),
    TransmitPower(u8),
    SpreadingFactor(u8),
    CodingRate(u8),
    RadioState(RNodeRadioState),
    Detection(RNodeDetection),
    FlowPermission(bool),
    FirmwareVersion(RNodeFirmwareVersion),
    Reset,
    RadioInitialisationError,
}

impl RNodeProtocolFrame {
    /// Decode one already-deframed extended-KISS command payload.
    ///
    /// Every supported command has an exact width. Rejections retain only the
    /// typed command and structural reason, never the rejected payload or
    /// unrestricted device error value.
    pub fn decode(command: u8, payload: &[u8]) -> Result<Self, RNodeFrameRejection> {
        let command = RNodeProtocolCommand::try_from(command)?;
        let expected = command.payload_len();
        if payload.len() != expected {
            return Err(RNodeFrameRejection::InvalidLength {
                command,
                expected,
                actual: payload.len(),
            });
        }

        let frame = match command {
            RNodeProtocolCommand::Frequency => Self::Frequency(u32::from_be_bytes(
                payload.try_into().expect("length checked"),
            )),
            RNodeProtocolCommand::Bandwidth => Self::Bandwidth(u32::from_be_bytes(
                payload.try_into().expect("length checked"),
            )),
            RNodeProtocolCommand::TransmitPower => Self::TransmitPower(payload[0]),
            RNodeProtocolCommand::SpreadingFactor => Self::SpreadingFactor(payload[0]),
            RNodeProtocolCommand::CodingRate => Self::CodingRate(payload[0]),
            RNodeProtocolCommand::RadioState => match payload[0] {
                rnode::RADIO_STATE_OFF => Self::RadioState(RNodeRadioState::Off),
                rnode::RADIO_STATE_ON => Self::RadioState(RNodeRadioState::On),
                _ => return Err(RNodeFrameRejection::InvalidValue { command }),
            },
            RNodeProtocolCommand::Detect => Self::Detection(if payload[0] == rnode::DETECT_RESP {
                RNodeDetection::Confirmed
            } else {
                RNodeDetection::Unconfirmed
            }),
            // Existing single-radio drivers interpret zero as blocked and any
            // non-zero value as permission to release the transmit queue.
            RNodeProtocolCommand::FlowReady => Self::FlowPermission(payload[0] != 0),
            RNodeProtocolCommand::FirmwareVersion => {
                Self::FirmwareVersion(RNodeFirmwareVersion::new(payload[0], payload[1]))
            }
            RNodeProtocolCommand::Reset => {
                if payload[0] != 0xF8 {
                    return Err(RNodeFrameRejection::InvalidValue { command });
                }
                Self::Reset
            }
            RNodeProtocolCommand::DeviceError => {
                if payload[0] != 0x01 {
                    return Err(RNodeFrameRejection::InvalidValue { command });
                }
                Self::RadioInitialisationError
            }
        };

        Ok(frame)
    }
}

/// Why a raw frame was not admitted to the state reducer.
///
/// This type intentionally has no raw command or payload field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeFrameRejection {
    UnknownCommand,
    InvalidLength {
        command: RNodeProtocolCommand,
        expected: usize,
        actual: usize,
    },
    InvalidValue {
        command: RNodeProtocolCommand,
    },
}

/// One category of evidence required for a usable radio session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeReadinessEvidence {
    Detection,
    Firmware,
    Frequency,
    Bandwidth,
    SpreadingFactor,
    CodingRate,
    TransmitPower,
    RadioState,
}

/// The first readiness blocker, evaluated in deterministic safety order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeReadinessBlocker {
    RadioInitialisationFault,
    Missing(RNodeReadinessEvidence),
    UnsupportedFirmware {
        observed: RNodeFirmwareVersion,
        minimum: RNodeFirmwareVersion,
    },
    Mismatch(RNodeReadinessEvidence),
}

/// Derived readiness of the generic RNode session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeReadiness {
    Blocked(RNodeReadinessBlocker),
    Ready,
}

/// Typed evidence retained by the reducer.
///
/// No raw frame, opaque device error, credential, hash, signature, or
/// administration payload can be represented here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RNodeProtocolEvidence {
    pub detected: bool,
    pub firmware: Option<RNodeFirmwareVersion>,
    pub frequency: Option<u32>,
    pub bandwidth: Option<u32>,
    pub spreading_factor: Option<u8>,
    pub coding_rate: Option<u8>,
    pub tx_power: Option<u8>,
    pub radio_state: Option<RNodeRadioState>,
    pub flow_permitted: bool,
    pub radio_initialisation_fault: bool,
}

/// Observable result of reducing one frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RNodeProtocolEffect {
    EvidenceChanged(RNodeReadinessEvidence),
    FlowPermissionChanged(bool),
    Reset,
    RadioInitialisationFault,
    NoChange,
    Rejected(RNodeFrameRejection),
}

/// Pure, order-independent reducer for generic single-radio readiness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RNodeProtocolState {
    target: RNodeProtocolTarget,
    evidence: RNodeProtocolEvidence,
}

impl RNodeProtocolState {
    pub const fn new(target: RNodeProtocolTarget) -> Self {
        Self {
            target,
            evidence: RNodeProtocolEvidence {
                detected: false,
                firmware: None,
                frequency: None,
                bandwidth: None,
                spreading_factor: None,
                coding_rate: None,
                tx_power: None,
                radio_state: None,
                flow_permitted: false,
                radio_initialisation_fault: false,
            },
        }
    }

    pub const fn target(&self) -> RNodeProtocolTarget {
        self.target
    }

    pub const fn evidence(&self) -> RNodeProtocolEvidence {
        self.evidence
    }

    /// Apply one already-deframed command payload.
    ///
    /// The function has no I/O, clock, allocation, or logging dependency.
    /// Rejected frames leave state unchanged.
    pub fn apply_frame(&mut self, command: u8, payload: &[u8]) -> RNodeProtocolEffect {
        match RNodeProtocolFrame::decode(command, payload) {
            Ok(frame) => self.apply_decoded_frame(frame),
            Err(error) => RNodeProtocolEffect::Rejected(error),
        }
    }

    /// Derive readiness in stable blocker order.
    pub fn readiness(&self) -> RNodeReadiness {
        use RNodeReadinessBlocker::{Mismatch, Missing};
        use RNodeReadinessEvidence::{
            Bandwidth, CodingRate, Detection, Firmware, Frequency, RadioState, SpreadingFactor,
            TransmitPower,
        };

        if self.evidence.radio_initialisation_fault {
            return RNodeReadiness::Blocked(RNodeReadinessBlocker::RadioInitialisationFault);
        }
        if !self.evidence.detected {
            return RNodeReadiness::Blocked(Missing(Detection));
        }

        match self.evidence.firmware {
            None => return RNodeReadiness::Blocked(Missing(Firmware)),
            Some(version) if !version.is_supported() => {
                return RNodeReadiness::Blocked(RNodeReadinessBlocker::UnsupportedFirmware {
                    observed: version,
                    minimum: RNodeFirmwareVersion::MINIMUM_SUPPORTED,
                });
            }
            Some(_) => {}
        }

        match self.evidence.frequency {
            None => return RNodeReadiness::Blocked(Missing(Frequency)),
            Some(frequency)
                if frequency.abs_diff(self.target.frequency) > FREQUENCY_TOLERANCE_HZ =>
            {
                return RNodeReadiness::Blocked(Mismatch(Frequency));
            }
            Some(_) => {}
        }
        match self.evidence.bandwidth {
            None => return RNodeReadiness::Blocked(Missing(Bandwidth)),
            Some(bandwidth) if bandwidth != self.target.bandwidth => {
                return RNodeReadiness::Blocked(Mismatch(Bandwidth));
            }
            Some(_) => {}
        }
        match self.evidence.spreading_factor {
            None => return RNodeReadiness::Blocked(Missing(SpreadingFactor)),
            Some(spreading_factor) if spreading_factor != self.target.spreading_factor => {
                return RNodeReadiness::Blocked(Mismatch(SpreadingFactor));
            }
            Some(_) => {}
        }
        match self.evidence.coding_rate {
            None => return RNodeReadiness::Blocked(Missing(CodingRate)),
            Some(coding_rate) if coding_rate != self.target.coding_rate => {
                return RNodeReadiness::Blocked(Mismatch(CodingRate));
            }
            Some(_) => {}
        }
        match self.evidence.tx_power {
            None => return RNodeReadiness::Blocked(Missing(TransmitPower)),
            Some(tx_power) if tx_power != self.target.tx_power => {
                return RNodeReadiness::Blocked(Mismatch(TransmitPower));
            }
            Some(_) => {}
        }
        match self.evidence.radio_state {
            None => return RNodeReadiness::Blocked(Missing(RadioState)),
            Some(RNodeRadioState::Off) => {
                return RNodeReadiness::Blocked(Mismatch(RadioState));
            }
            Some(RNodeRadioState::On) => {}
        }

        RNodeReadiness::Ready
    }

    fn apply_decoded_frame(&mut self, frame: RNodeProtocolFrame) -> RNodeProtocolEffect {
        match frame {
            RNodeProtocolFrame::Frequency(value) => replace(
                &mut self.evidence.frequency,
                value,
                RNodeReadinessEvidence::Frequency,
            ),
            RNodeProtocolFrame::Bandwidth(value) => replace(
                &mut self.evidence.bandwidth,
                value,
                RNodeReadinessEvidence::Bandwidth,
            ),
            RNodeProtocolFrame::TransmitPower(value) => replace(
                &mut self.evidence.tx_power,
                value,
                RNodeReadinessEvidence::TransmitPower,
            ),
            RNodeProtocolFrame::SpreadingFactor(value) => replace(
                &mut self.evidence.spreading_factor,
                value,
                RNodeReadinessEvidence::SpreadingFactor,
            ),
            RNodeProtocolFrame::CodingRate(value) => replace(
                &mut self.evidence.coding_rate,
                value,
                RNodeReadinessEvidence::CodingRate,
            ),
            RNodeProtocolFrame::RadioState(value) => replace(
                &mut self.evidence.radio_state,
                value,
                RNodeReadinessEvidence::RadioState,
            ),
            RNodeProtocolFrame::Detection(value) => {
                let detected = value == RNodeDetection::Confirmed;
                if self.evidence.detected == detected {
                    RNodeProtocolEffect::NoChange
                } else {
                    self.evidence.detected = detected;
                    RNodeProtocolEffect::EvidenceChanged(RNodeReadinessEvidence::Detection)
                }
            }
            RNodeProtocolFrame::FlowPermission(permitted) => {
                if self.evidence.flow_permitted == permitted {
                    RNodeProtocolEffect::NoChange
                } else {
                    self.evidence.flow_permitted = permitted;
                    RNodeProtocolEffect::FlowPermissionChanged(permitted)
                }
            }
            RNodeProtocolFrame::FirmwareVersion(version) => replace(
                &mut self.evidence.firmware,
                version,
                RNodeReadinessEvidence::Firmware,
            ),
            RNodeProtocolFrame::Reset => {
                self.evidence = RNodeProtocolEvidence::default();
                RNodeProtocolEffect::Reset
            }
            RNodeProtocolFrame::RadioInitialisationError => {
                if self.evidence.radio_initialisation_fault {
                    RNodeProtocolEffect::NoChange
                } else {
                    self.evidence.radio_initialisation_fault = true;
                    RNodeProtocolEffect::RadioInitialisationFault
                }
            }
        }
    }
}

fn replace<T: Copy + Eq>(
    slot: &mut Option<T>,
    value: T,
    evidence: RNodeReadinessEvidence,
) -> RNodeProtocolEffect {
    if *slot == Some(value) {
        RNodeProtocolEffect::NoChange
    } else {
        *slot = Some(value);
        RNodeProtocolEffect::EvidenceChanged(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: RNodeProtocolTarget = RNodeProtocolTarget::new(915_000_000, 125_000, 7, 5, 17);

    fn required_frames() -> [(u8, Vec<u8>); 8] {
        [
            (rnode::CMD_DETECT, vec![rnode::DETECT_RESP]),
            (
                rnode::CMD_FW_VERSION,
                vec![rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            ),
            (
                rnode::CMD_FREQUENCY,
                TARGET.frequency.to_be_bytes().to_vec(),
            ),
            (
                rnode::CMD_BANDWIDTH,
                TARGET.bandwidth.to_be_bytes().to_vec(),
            ),
            (rnode::CMD_SF, vec![TARGET.spreading_factor]),
            (rnode::CMD_CR, vec![TARGET.coding_rate]),
            (rnode::CMD_TXPOWER, vec![TARGET.tx_power]),
            (rnode::CMD_RADIO_STATE, vec![rnode::RADIO_STATE_ON]),
        ]
    }

    fn ready_state() -> RNodeProtocolState {
        let mut state = RNodeProtocolState::new(TARGET);
        for (command, payload) in required_frames() {
            state.apply_frame(command, &payload);
        }
        assert_eq!(state.readiness(), RNodeReadiness::Ready);
        state
    }

    fn for_each_permutation<const N: usize>(
        values: &mut [usize; N],
        size: usize,
        callback: &mut impl FnMut(&[usize; N]),
    ) {
        if size == 1 {
            callback(values);
            return;
        }

        for_each_permutation(values, size - 1, callback);
        for index in 0..(size - 1) {
            let swap_index = if size.is_multiple_of(2) { index } else { 0 };
            values.swap(swap_index, size - 1);
            for_each_permutation(values, size - 1, callback);
        }
    }

    #[test]
    fn all_eight_frame_permutations_reach_ready_only_after_complete_evidence() {
        let frames = required_frames();
        let mut order = [0, 1, 2, 3, 4, 5, 6, 7];
        let mut count = 0usize;

        for_each_permutation(&mut order, 8, &mut |permutation| {
            let mut state = RNodeProtocolState::new(TARGET);
            for (position, frame_index) in permutation.iter().copied().enumerate() {
                let (command, payload) = &frames[frame_index];
                state.apply_frame(*command, payload);
                if position < 7 {
                    assert_ne!(state.readiness(), RNodeReadiness::Ready);
                }
            }
            assert_eq!(state.readiness(), RNodeReadiness::Ready);
            count += 1;
        });

        assert_eq!(count, 40_320);
    }

    #[test]
    fn every_supported_command_uses_exact_width() {
        let valid = [
            (
                rnode::CMD_FREQUENCY,
                TARGET.frequency.to_be_bytes().to_vec(),
            ),
            (
                rnode::CMD_BANDWIDTH,
                TARGET.bandwidth.to_be_bytes().to_vec(),
            ),
            (rnode::CMD_TXPOWER, vec![TARGET.tx_power]),
            (rnode::CMD_SF, vec![TARGET.spreading_factor]),
            (rnode::CMD_CR, vec![TARGET.coding_rate]),
            (rnode::CMD_RADIO_STATE, vec![rnode::RADIO_STATE_ON]),
            (rnode::CMD_DETECT, vec![rnode::DETECT_RESP]),
            (rnode::CMD_READY, vec![1]),
            (
                rnode::CMD_FW_VERSION,
                vec![rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            ),
            (rnode::CMD_RESET, vec![0xF8]),
            (rnode::CMD_ERROR, vec![0x01]),
        ];

        for (command, payload) in valid {
            assert!(RNodeProtocolFrame::decode(command, &payload).is_ok());

            let prefix = &payload[..payload.len() - 1];
            assert!(matches!(
                RNodeProtocolFrame::decode(command, prefix),
                Err(RNodeFrameRejection::InvalidLength { .. })
            ));

            let mut with_suffix = payload.clone();
            with_suffix.push(0);
            assert!(matches!(
                RNodeProtocolFrame::decode(command, &with_suffix),
                Err(RNodeFrameRejection::InvalidLength { .. })
            ));
        }
    }

    #[test]
    fn unknown_and_invalid_values_are_rejected_without_state_change() {
        let mut state = ready_state();
        let before = state.clone();

        assert_eq!(
            state.apply_frame(0xAA, b"private opaque payload"),
            RNodeProtocolEffect::Rejected(RNodeFrameRejection::UnknownCommand)
        );
        assert_eq!(
            state.apply_frame(rnode::CMD_RADIO_STATE, &[2]),
            RNodeProtocolEffect::Rejected(RNodeFrameRejection::InvalidValue {
                command: RNodeProtocolCommand::RadioState,
            })
        );
        assert_eq!(
            state.apply_frame(rnode::CMD_RESET, &[0]),
            RNodeProtocolEffect::Rejected(RNodeFrameRejection::InvalidValue {
                command: RNodeProtocolCommand::Reset,
            })
        );
        assert_eq!(
            state.apply_frame(rnode::CMD_ERROR, &[0x7F]),
            RNodeProtocolEffect::Rejected(RNodeFrameRejection::InvalidValue {
                command: RNodeProtocolCommand::DeviceError,
            })
        );
        assert_eq!(state, before);
    }

    #[test]
    fn duplicate_readiness_frames_are_idempotent() {
        let mut state = RNodeProtocolState::new(TARGET);
        for (command, payload) in required_frames() {
            assert_ne!(
                state.apply_frame(command, &payload),
                RNodeProtocolEffect::NoChange
            );
            let once = state.clone();
            assert_eq!(
                state.apply_frame(command, &payload),
                RNodeProtocolEffect::NoChange
            );
            assert_eq!(state, once);
        }
        assert_eq!(state.readiness(), RNodeReadiness::Ready);
    }

    #[test]
    fn frequency_tolerance_is_inclusive_at_one_hundred_hertz() {
        let mut state = ready_state();

        state.apply_frame(
            rnode::CMD_FREQUENCY,
            &(TARGET.frequency + 100).to_be_bytes(),
        );
        assert_eq!(state.readiness(), RNodeReadiness::Ready);

        state.apply_frame(
            rnode::CMD_FREQUENCY,
            &(TARGET.frequency - 100).to_be_bytes(),
        );
        assert_eq!(state.readiness(), RNodeReadiness::Ready);

        state.apply_frame(
            rnode::CMD_FREQUENCY,
            &(TARGET.frequency + 101).to_be_bytes(),
        );
        assert_eq!(
            state.readiness(),
            RNodeReadiness::Blocked(RNodeReadinessBlocker::Mismatch(
                RNodeReadinessEvidence::Frequency
            ))
        );
    }

    #[test]
    fn all_non_frequency_configuration_echoes_are_exact() {
        let cases = [
            (
                rnode::CMD_BANDWIDTH,
                (TARGET.bandwidth + 1).to_be_bytes().to_vec(),
                RNodeReadinessEvidence::Bandwidth,
            ),
            (
                rnode::CMD_SF,
                vec![TARGET.spreading_factor + 1],
                RNodeReadinessEvidence::SpreadingFactor,
            ),
            (
                rnode::CMD_CR,
                vec![TARGET.coding_rate + 1],
                RNodeReadinessEvidence::CodingRate,
            ),
            (
                rnode::CMD_TXPOWER,
                vec![TARGET.tx_power + 1],
                RNodeReadinessEvidence::TransmitPower,
            ),
            (
                rnode::CMD_RADIO_STATE,
                vec![rnode::RADIO_STATE_OFF],
                RNodeReadinessEvidence::RadioState,
            ),
        ];

        for (command, mismatch, evidence) in cases {
            let mut state = ready_state();
            state.apply_frame(command, &mismatch);
            assert_eq!(
                state.readiness(),
                RNodeReadiness::Blocked(RNodeReadinessBlocker::Mismatch(evidence))
            );
        }
    }

    #[test]
    fn firmware_support_threshold_is_lexicographic_and_exact() {
        let mut state = ready_state();

        state.apply_frame(rnode::CMD_FW_VERSION, &[1, 51]);
        assert_eq!(
            state.readiness(),
            RNodeReadiness::Blocked(RNodeReadinessBlocker::UnsupportedFirmware {
                observed: RNodeFirmwareVersion::new(1, 51),
                minimum: RNodeFirmwareVersion::new(1, 52),
            })
        );

        state.apply_frame(rnode::CMD_FW_VERSION, &[1, 52]);
        assert_eq!(state.readiness(), RNodeReadiness::Ready);

        state.apply_frame(rnode::CMD_FW_VERSION, &[2, 0]);
        assert_eq!(state.readiness(), RNodeReadiness::Ready);

        state.apply_frame(rnode::CMD_FW_VERSION, &[0, u8::MAX]);
        assert!(matches!(
            state.readiness(),
            RNodeReadiness::Blocked(RNodeReadinessBlocker::UnsupportedFirmware { .. })
        ));
    }

    #[test]
    fn flow_ready_is_only_transmit_permission() {
        let mut state = RNodeProtocolState::new(TARGET);
        assert_eq!(
            state.apply_frame(rnode::CMD_READY, &[1]),
            RNodeProtocolEffect::FlowPermissionChanged(true)
        );
        assert!(state.evidence().flow_permitted);
        assert_eq!(
            state.readiness(),
            RNodeReadiness::Blocked(RNodeReadinessBlocker::Missing(
                RNodeReadinessEvidence::Detection
            ))
        );

        let mut ready = ready_state();
        assert_eq!(
            ready.apply_frame(rnode::CMD_READY, &[0]),
            RNodeProtocolEffect::NoChange
        );
        assert_eq!(ready.readiness(), RNodeReadiness::Ready);
    }

    #[test]
    fn radio_initialisation_fault_is_first_and_sticky_until_reset() {
        let mut state = ready_state();
        state.apply_frame(rnode::CMD_ERROR, &[0x01]);
        assert_eq!(
            state.readiness(),
            RNodeReadiness::Blocked(RNodeReadinessBlocker::RadioInitialisationFault)
        );

        for (command, payload) in required_frames() {
            state.apply_frame(command, &payload);
        }
        assert_eq!(
            state.apply_frame(rnode::CMD_ERROR, &[0x01]),
            RNodeProtocolEffect::NoChange
        );
        assert_eq!(
            state.readiness(),
            RNodeReadiness::Blocked(RNodeReadinessBlocker::RadioInitialisationFault)
        );

        assert_eq!(
            state.apply_frame(rnode::CMD_RESET, &[0xF8]),
            RNodeProtocolEffect::Reset
        );
        assert_eq!(
            state.evidence(),
            RNodeProtocolEvidence::default(),
            "reset must clear all readiness, flow, and sticky-fault evidence"
        );
        assert_eq!(
            state.readiness(),
            RNodeReadiness::Blocked(RNodeReadinessBlocker::Missing(
                RNodeReadinessEvidence::Detection
            ))
        );
    }

    #[test]
    fn invalid_detect_clears_previous_confirmation_without_retaining_value() {
        let mut state = ready_state();
        assert_eq!(
            state.apply_frame(rnode::CMD_DETECT, &[0x00]),
            RNodeProtocolEffect::EvidenceChanged(RNodeReadinessEvidence::Detection)
        );
        assert!(!state.evidence().detected);
        assert_eq!(
            state.readiness(),
            RNodeReadiness::Blocked(RNodeReadinessBlocker::Missing(
                RNodeReadinessEvidence::Detection
            ))
        );
    }

    #[test]
    fn malformed_and_private_payloads_cannot_be_retained() {
        let mut state = RNodeProtocolState::new(TARGET);
        let initial = state.clone();
        let private = b"wifi-password identity-hash device-signature";

        let unknown = state.apply_frame(0xE7, private);
        let malformed = state.apply_frame(rnode::CMD_FW_VERSION, private);
        let opaque_error = state.apply_frame(rnode::CMD_ERROR, &[0xFE]);

        assert_eq!(state, initial);
        assert!(!format!("{state:?}").contains("wifi-password"));
        assert!(!format!("{unknown:?}").contains("wifi-password"));
        assert!(!format!("{malformed:?}").contains("wifi-password"));
        assert!(!format!("{opaque_error:?}").contains("FE"));
    }

    #[test]
    fn blocker_order_is_stable_and_safety_first() {
        let mut state = RNodeProtocolState::new(TARGET);
        assert_eq!(
            state.readiness(),
            RNodeReadiness::Blocked(RNodeReadinessBlocker::Missing(
                RNodeReadinessEvidence::Detection
            ))
        );

        state.apply_frame(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
        assert_eq!(
            state.readiness(),
            RNodeReadiness::Blocked(RNodeReadinessBlocker::Missing(
                RNodeReadinessEvidence::Firmware
            ))
        );

        state.apply_frame(rnode::CMD_FW_VERSION, &[1, 51]);
        assert!(matches!(
            state.readiness(),
            RNodeReadiness::Blocked(RNodeReadinessBlocker::UnsupportedFirmware { .. })
        ));

        state.apply_frame(rnode::CMD_ERROR, &[0x01]);
        assert_eq!(
            state.readiness(),
            RNodeReadiness::Blocked(RNodeReadinessBlocker::RadioInitialisationFault)
        );
    }
}
