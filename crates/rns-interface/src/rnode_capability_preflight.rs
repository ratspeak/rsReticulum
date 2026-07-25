//! Bounded, transport-independent RNode capability preflight state.
//!
//! Transport owners retain their stream, writer, clock, and cancellation
//! policy. This module owns only strict framing, bounded admission state, and
//! privacy-safe errors so serial/TCP, BLE, and USB can share one policy without
//! sharing transport lifecycle machinery.

use crate::kiss;
use crate::rnode::{CMD_ERROR, CMD_ROM_READ, RNodeCapabilityAdmissionError, RNodeRadioSettings};
use crate::rnode_capabilities::{
    RNodeRadioAdmission, admit_rnode_radio_settings, parse_rnode_capabilities,
};
use crate::rnode_protocol::{
    RNodeFrameRejection, RNodeProtocolEffect, RNodeProtocolState, RNodeProtocolTarget,
};

#[cfg(all(not(test), any(feature = "serial", feature = "rnode-tcp")))]
pub(crate) const RNODE_CAPABILITY_PREFLIGHT_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(5);
#[cfg(all(test, any(feature = "serial", feature = "rnode-tcp")))]
pub(crate) const RNODE_CAPABILITY_PREFLIGHT_DEADLINE: std::time::Duration =
    std::time::Duration::from_millis(500);
pub(crate) const RNODE_CAPABILITY_READ_BUFFER_BYTES: usize = 1024;
const RNODE_CAPABILITY_MAX_READS: usize = 128;
const RNODE_CAPABILITY_MAX_INPUT_BYTES: usize = 4 * 1024;
const RNODE_CAPABILITY_MAX_FRAMES: usize = 128;

pub(crate) fn build_rnode_capability_request() -> Vec<u8> {
    kiss::frame_with_command(CMD_ROM_READ, &[0])
}

pub(crate) struct RNodeCapabilityPreflight {
    deframer: kiss::RawKissDeframer,
    protocol_state: RNodeProtocolState,
    settings: RNodeRadioSettings,
    admission: Option<RNodeRadioAdmission>,
    read_count: usize,
    input_bytes: usize,
    frame_count: usize,
}

impl RNodeCapabilityPreflight {
    pub(crate) fn new(settings: RNodeRadioSettings) -> Self {
        Self {
            deframer: kiss::RawKissDeframer::new(),
            protocol_state: RNodeProtocolState::new(RNodeProtocolTarget::new(
                settings.frequency,
                settings.bandwidth,
                settings.spreading_factor,
                settings.coding_rate,
                settings.tx_power,
            )),
            settings,
            admission: None,
            read_count: 0,
            input_bytes: 0,
            frame_count: 0,
        }
    }

    /// Consume one bounded transport read.
    ///
    /// `CMD_DATA` and EEPROM payloads never leave this state machine. Unknown
    /// non-data controls are ignored after strict deframing; supported generic
    /// controls are reduced into the generation-private protocol state.
    pub(crate) fn observe_read(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<RNodeRadioAdmission>, RNodeCapabilityAdmissionError> {
        self.read_count = self.read_count.saturating_add(1);
        if self.read_count > RNODE_CAPABILITY_MAX_READS {
            return Err(RNodeCapabilityAdmissionError::ReadLimitExceeded {
                limit: RNODE_CAPABILITY_MAX_READS,
            });
        }
        if bytes.len() > RNODE_CAPABILITY_READ_BUFFER_BYTES {
            return Err(RNodeCapabilityAdmissionError::InputLimitExceeded {
                limit: RNODE_CAPABILITY_READ_BUFFER_BYTES,
            });
        }
        self.input_bytes = self.input_bytes.saturating_add(bytes.len());
        if self.input_bytes > RNODE_CAPABILITY_MAX_INPUT_BYTES {
            return Err(RNodeCapabilityAdmissionError::InputLimitExceeded {
                limit: RNODE_CAPABILITY_MAX_INPUT_BYTES,
            });
        }

        for (command, payload) in self.deframer.feed(bytes) {
            self.frame_count = self.frame_count.saturating_add(1);
            if self.frame_count > RNODE_CAPABILITY_MAX_FRAMES {
                return Err(RNodeCapabilityAdmissionError::FrameLimitExceeded {
                    limit: RNODE_CAPABILITY_MAX_FRAMES,
                });
            }

            if command == kiss::CMD_DATA {
                continue;
            }
            if command == CMD_ROM_READ {
                if self.admission.is_some() {
                    return Err(RNodeCapabilityAdmissionError::DuplicateEepromResponse);
                }
                let capabilities = parse_rnode_capabilities(&payload)
                    .map_err(RNodeCapabilityAdmissionError::CapabilityImage)?;
                self.admission = Some(
                    admit_rnode_radio_settings(capabilities, self.settings)
                        .map_err(RNodeCapabilityAdmissionError::RadioSettings)?,
                );
                continue;
            }
            if command == CMD_ERROR {
                return Err(RNodeCapabilityAdmissionError::DeviceError);
            }

            match self.protocol_state.apply_frame(command, &payload) {
                RNodeProtocolEffect::Rejected(RNodeFrameRejection::UnknownCommand) => {}
                RNodeProtocolEffect::Rejected(rejection) => {
                    return Err(RNodeCapabilityAdmissionError::MalformedProtocolFrame {
                        rejection,
                    });
                }
                RNodeProtocolEffect::RadioInitialisationFault => {
                    unreachable!("CMD_ERROR is rejected before protocol reduction")
                }
                RNodeProtocolEffect::EvidenceChanged(_)
                | RNodeProtocolEffect::FlowPermissionChanged(_)
                | RNodeProtocolEffect::Reset
                | RNodeProtocolEffect::NoChange => {}
            }
        }

        let evidence = self.protocol_state.evidence();
        if self.protocol_state.detection_observed() && !evidence.detected {
            return Err(RNodeCapabilityAdmissionError::DetectionRejected);
        }
        if evidence
            .firmware
            .is_some_and(|firmware| !firmware.is_supported())
        {
            return Err(RNodeCapabilityAdmissionError::UnsupportedFirmware);
        }
        Ok((evidence.detected && evidence.firmware.is_some())
            .then_some(self.admission)
            .flatten())
    }

    /// Return the only preflight evidence that may seed active readiness.
    ///
    /// Configuration, radio, and flow frames observed before the runtime sends
    /// its admitted init sequence may be stale. They remain reduced privately
    /// during preflight but never cross the admission boundary.
    pub(crate) fn into_protocol_state(self) -> RNodeProtocolState {
        let target = self.protocol_state.target();
        let evidence = self.protocol_state.evidence();
        let mut admitted = RNodeProtocolState::new(target);
        if evidence.detected {
            admitted.apply_frame(crate::rnode::CMD_DETECT, &[crate::rnode::DETECT_RESP]);
        }
        if let Some(firmware) = evidence.firmware {
            admitted.apply_frame(
                crate::rnode::CMD_FW_VERSION,
                &[firmware.major, firmware.minor],
            );
        }
        admitted
    }
}

#[cfg(test)]
mod tests {
    use md5::{Digest, Md5};

    use super::*;
    use crate::rnode::{
        CMD_DETECT, CMD_FW_VERSION, DETECT_RESP, REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN,
    };

    fn settings(frequency: u32, tx_power: u8) -> RNodeRadioSettings {
        RNodeRadioSettings::new(frequency, 125_000, 7, 5, tx_power)
    }

    fn eeprom(model: u8) -> Vec<u8> {
        let mut bytes = vec![0xFF; 1024];
        bytes[0] = 0x03;
        bytes[1] = model;
        bytes[2..11].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let checksum: [u8; 16] = Md5::digest(&bytes[..11]).into();
        bytes[11..27].copy_from_slice(&checksum);
        // Exercise both extended-KISS escape forms outside the validated
        // identity prefix.
        bytes[100] = kiss::FEND;
        bytes[101] = kiss::FESC;
        bytes[0x9B] = 0x73;
        bytes
    }

    fn observe_chunked(
        preflight: &mut RNodeCapabilityPreflight,
        bytes: &[u8],
    ) -> Result<Option<RNodeRadioAdmission>, RNodeCapabilityAdmissionError> {
        let mut admission = None;
        for chunk in bytes.chunks(257) {
            admission = preflight.observe_read(chunk)?.or(admission);
        }
        Ok(admission)
    }

    fn admitted_frames(model: u8) -> Vec<u8> {
        let mut frames = Vec::new();
        kiss::frame_with_command_into(CMD_DETECT, &[DETECT_RESP], &mut frames);
        kiss::frame_with_command_into(
            CMD_FW_VERSION,
            &[REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN],
            &mut frames,
        );
        kiss::frame_with_command_into(CMD_ROM_READ, &eeprom(model), &mut frames);
        frames
    }

    #[test]
    fn capability_request_is_one_standalone_rom_read_zero_frame() {
        assert_eq!(
            build_rnode_capability_request(),
            kiss::frame_with_command(CMD_ROM_READ, &[0])
        );
    }

    #[test]
    fn fragmented_and_escaped_eeprom_admits_verified_model() {
        let bytes = admitted_frames(0xB8);
        assert!(bytes.contains(&kiss::FESC));
        let mut preflight = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        let result = observe_chunked(&mut preflight, &bytes).unwrap();
        assert!(matches!(result, Some(RNodeRadioAdmission::Verified { .. })));
        assert!(preflight.into_protocol_state().evidence().detected);
    }

    #[test]
    fn validated_unknown_model_is_explicitly_unverified() {
        let mut preflight = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        assert!(matches!(
            observe_chunked(&mut preflight, &admitted_frames(0xFE)).unwrap(),
            Some(RNodeRadioAdmission::Unverified {
                model_code: 0xFE,
                ..
            })
        ));
    }

    #[test]
    fn data_and_wrong_commands_do_not_satisfy_or_escape_preflight() {
        let mut bytes = Vec::new();
        kiss::frame_with_command_into(kiss::CMD_DATA, b"private packet", &mut bytes);
        kiss::frame_with_command_into(crate::rnode::CMD_PLATFORM, &[0x80], &mut bytes);
        kiss::frame_with_command_into(CMD_ROM_READ.wrapping_add(1), &eeprom(0xB8), &mut bytes);
        let mut preflight = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        assert_eq!(observe_chunked(&mut preflight, &bytes).unwrap(), None);
    }

    #[test]
    fn malformed_control_device_error_and_invalid_image_fail_closed() {
        let mut malformed = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        let malformed_frame = kiss::frame_with_command(CMD_FW_VERSION, &[1]);
        assert!(matches!(
            malformed.observe_read(&malformed_frame),
            Err(RNodeCapabilityAdmissionError::MalformedProtocolFrame { .. })
        ));

        let mut device_error = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        assert_eq!(
            device_error.observe_read(&kiss::frame_with_command(CMD_ERROR, &[0x7F])),
            Err(RNodeCapabilityAdmissionError::DeviceError)
        );

        let mut invalid = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        assert!(matches!(
            invalid.observe_read(&kiss::frame_with_command(CMD_ROM_READ, &[0; 8])),
            Err(RNodeCapabilityAdmissionError::CapabilityImage(_))
        ));
    }

    #[test]
    fn known_model_mismatch_and_bounds_are_typed() {
        let mut mismatch = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        let result = observe_chunked(&mut mismatch, &admitted_frames(0xB4));
        assert!(matches!(
            result,
            Err(RNodeCapabilityAdmissionError::RadioSettings(
                crate::rnode_capabilities::RNodeRadioAdmissionError::FrequencyOutOfRange { .. }
            ))
        ));

        let mut bounded = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        for _ in 0..RNODE_CAPABILITY_MAX_READS {
            assert_eq!(bounded.observe_read(&[]).unwrap(), None);
        }
        assert_eq!(
            bounded.observe_read(&[]),
            Err(RNodeCapabilityAdmissionError::ReadLimitExceeded {
                limit: RNODE_CAPABILITY_MAX_READS
            })
        );
    }

    #[test]
    fn negative_detection_unsupported_firmware_and_duplicate_rom_are_typed() {
        let mut detection = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        assert_eq!(
            detection.observe_read(&kiss::frame_with_command(CMD_DETECT, &[0])),
            Err(RNodeCapabilityAdmissionError::DetectionRejected)
        );

        let mut firmware = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        assert_eq!(
            firmware.observe_read(&kiss::frame_with_command(
                CMD_FW_VERSION,
                &[REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN - 1],
            )),
            Err(RNodeCapabilityAdmissionError::UnsupportedFirmware)
        );

        let mut duplicate = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        assert_eq!(
            observe_chunked(
                &mut duplicate,
                &kiss::frame_with_command(CMD_ROM_READ, &eeprom(0xB8)),
            )
            .unwrap(),
            None
        );
        assert_eq!(
            observe_chunked(
                &mut duplicate,
                &kiss::frame_with_command(CMD_ROM_READ, &eeprom(0xB8)),
            ),
            Err(RNodeCapabilityAdmissionError::DuplicateEepromResponse)
        );
    }

    #[test]
    fn cumulative_input_and_frame_limits_fail_closed() {
        let mut input = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        let chunk = vec![0; RNODE_CAPABILITY_READ_BUFFER_BYTES];
        for _ in 0..(RNODE_CAPABILITY_MAX_INPUT_BYTES / chunk.len()) {
            assert_eq!(input.observe_read(&chunk).unwrap(), None);
        }
        assert_eq!(
            input.observe_read(&[0]),
            Err(RNodeCapabilityAdmissionError::InputLimitExceeded {
                limit: RNODE_CAPABILITY_MAX_INPUT_BYTES
            })
        );

        let mut frame_bytes = Vec::new();
        for _ in 0..=RNODE_CAPABILITY_MAX_FRAMES {
            kiss::frame_with_command_into(crate::rnode::CMD_PLATFORM, &[0], &mut frame_bytes);
        }
        let mut frames = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        assert_eq!(
            frames.observe_read(&frame_bytes),
            Err(RNodeCapabilityAdmissionError::FrameLimitExceeded {
                limit: RNODE_CAPABILITY_MAX_FRAMES
            })
        );
    }

    #[test]
    fn partial_frame_never_admits_and_is_not_replayed() {
        let bytes = admitted_frames(0xB8);
        let mut preflight = RNodeCapabilityPreflight::new(settings(868_000_000, 14));
        assert_eq!(
            observe_chunked(&mut preflight, &bytes[..bytes.len() - 1]).unwrap(),
            None
        );
        drop(preflight);

        let mut fresh = kiss::RawKissDeframer::new();
        assert!(fresh.feed(&bytes[bytes.len() - 1..]).is_empty());
    }

    #[test]
    fn stale_pre_init_radio_evidence_cannot_make_admitted_seed_ready() {
        let settings = settings(868_000_000, 14);
        let mut bytes = Vec::new();
        kiss::frame_with_command_into(
            crate::rnode::CMD_FREQUENCY,
            &settings.frequency.to_be_bytes(),
            &mut bytes,
        );
        kiss::frame_with_command_into(
            crate::rnode::CMD_BANDWIDTH,
            &settings.bandwidth.to_be_bytes(),
            &mut bytes,
        );
        kiss::frame_with_command_into(
            crate::rnode::CMD_SF,
            &[settings.spreading_factor],
            &mut bytes,
        );
        kiss::frame_with_command_into(crate::rnode::CMD_CR, &[settings.coding_rate], &mut bytes);
        kiss::frame_with_command_into(crate::rnode::CMD_TXPOWER, &[settings.tx_power], &mut bytes);
        kiss::frame_with_command_into(
            crate::rnode::CMD_RADIO_STATE,
            &[crate::rnode::RADIO_STATE_ON],
            &mut bytes,
        );
        bytes.extend_from_slice(&admitted_frames(0xB8));

        let mut preflight = RNodeCapabilityPreflight::new(settings);
        assert!(observe_chunked(&mut preflight, &bytes).unwrap().is_some());
        let seed = preflight.into_protocol_state();
        assert!(seed.evidence().detected);
        assert!(seed.evidence().firmware.is_some());
        assert_eq!(seed.evidence().frequency, None);
        assert_eq!(seed.evidence().radio_state, None);
        assert!(matches!(
            seed.readiness(),
            crate::rnode_protocol::RNodeReadiness::Blocked(
                crate::rnode_protocol::RNodeReadinessBlocker::Missing(
                    crate::rnode_protocol::RNodeReadinessEvidence::Frequency
                )
            )
        ));
    }
}
