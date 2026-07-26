//! Privacy-bounded, read-only RNode capability parsing.
//!
//! RNode EEPROM identity information contains serial, manufacturing, checksum,
//! signature, and other device-specific bytes. This module validates the
//! immutable identity prefix in place, then returns only copyable product/model
//! codes and reviewed radio limits. It never retains the source image or
//! exposes identity, signature, configuration, or raw EEPROM fields.

use md5::{Digest, Md5};

use crate::rnode::{RNodeConfigValidationError, RNodeRadioSettings};

const PRODUCT_ADDRESS: usize = 0x00;
const MODEL_ADDRESS: usize = 0x01;
const IDENTITY_CHECKSUM_INPUT_END: usize = 0x0B;
const CHECKSUM_ADDRESS: usize = 0x0B;
const CHECKSUM_END: usize = 0x1B;
const INFO_LOCK_ADDRESS: usize = 0x9B;
const REQUIRED_EEPROM_LEN: usize = INFO_LOCK_ADDRESS + 1;
const INFO_LOCK_BYTE: u8 = 0x73;

/// A validated, privacy-bounded RNode capability description.
///
/// The value owns no EEPROM bytes and contains no stable device identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RNodeCapabilities {
    product_code: u8,
    model_code: u8,
    radio: RNodeRadioCapabilities,
}

impl RNodeCapabilities {
    /// The RNode product code stored in the validated identity prefix.
    pub const fn product_code(self) -> u8 {
        self.product_code
    }

    /// A reviewed display name for the product code, when one is known.
    ///
    /// This is a static code-table lookup; no label is read from or retained
    /// from the EEPROM image.
    pub const fn product_name(self) -> Option<&'static str> {
        rnode_product_name(self.product_code)
    }

    /// The exact, unnormalised RNode model code stored in the identity prefix.
    pub const fn model_code(self) -> u8 {
        self.model_code
    }

    /// Reviewed radio limits for the model, or [`RNodeRadioCapabilities::Unknown`].
    pub const fn radio(self) -> RNodeRadioCapabilities {
        self.radio
    }
}

/// Whether a validated model has a reviewed radio capability profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RNodeRadioCapabilities {
    /// The model maps to a reviewed, internally consistent numeric profile.
    Known(RNodeKnownRadioCapabilities),
    /// The model is unknown, ambiguous, or deliberately quarantined.
    Unknown,
}

/// Reviewed numeric limits for a known RNode radio model.
///
/// For a dual-radio product, these limits describe the reviewed generic/main
/// RNode radio profile. They do not claim to span every band supported by each
/// physically present secondary radio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RNodeKnownRadioCapabilities {
    family: RNodeRadioFamily,
    min_frequency_hz: u32,
    max_frequency_hz: u32,
    max_tx_power_dbm: u8,
}

impl RNodeKnownRadioCapabilities {
    /// The radio family associated with the model.
    pub const fn family(self) -> RNodeRadioFamily {
        self.family
    }

    /// The inclusive lower frequency bound in hertz.
    pub const fn min_frequency_hz(self) -> u32 {
        self.min_frequency_hz
    }

    /// The inclusive upper frequency bound in hertz.
    pub const fn max_frequency_hz(self) -> u32 {
        self.max_frequency_hz
    }

    /// The inclusive maximum transmit power in dBm.
    pub const fn max_tx_power_dbm(self) -> u8 {
        self.max_tx_power_dbm
    }

    /// Whether `frequency_hz` lies within the inclusive reviewed bounds.
    pub const fn supports_frequency(self, frequency_hz: u32) -> bool {
        frequency_hz >= self.min_frequency_hz && frequency_hz <= self.max_frequency_hz
    }

    /// Whether `tx_power_dbm` is at or below the inclusive reviewed maximum.
    pub const fn supports_tx_power(self, tx_power_dbm: u8) -> bool {
        tx_power_dbm <= self.max_tx_power_dbm
    }
}

/// Radio families represented by reviewed RNode model profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RNodeRadioFamily {
    Sx1262,
    Sx1268,
    Sx1276,
    Sx1278,
    Sx1280,
    /// A dual-radio product.
    ///
    /// Its numeric capability bounds describe the reviewed generic/main radio
    /// profile, not every band of the physically present secondary radio.
    Sx1262AndSx1280,
}

/// Why a capability image could not be accepted.
///
/// Errors intentionally contain no EEPROM contents, hashes, or identity
/// values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RNodeCapabilityParseError {
    #[error("RNode EEPROM image is too short (need {required} bytes, got {actual})")]
    TooShort { required: usize, actual: usize },
    #[error("RNode identity information is not locked")]
    InfoNotLocked,
    #[error("RNode identity checksum is invalid")]
    ChecksumMismatch,
}

/// Model-specific classification for a validated RNode capability image.
///
/// `Verified` means the exact model has a reviewed capability profile.
/// `Unverified` means the exact stored model is unknown or quarantined, so no
/// model profile was inferred. A `Verified` classification alone does not
/// admit radio settings; use [`admit_rnode_radio_settings`] for that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RNodeRadioAdmission {
    Verified { product_code: u8, model_code: u8 },
    Unverified { product_code: u8, model_code: u8 },
}

impl RNodeRadioAdmission {
    /// Validated EEPROM product code associated with this admission result.
    pub const fn product_code(self) -> u8 {
        match self {
            Self::Verified { product_code, .. } | Self::Unverified { product_code, .. } => {
                product_code
            }
        }
    }

    /// Exact, unnormalised EEPROM model code associated with this result.
    pub const fn model_code(self) -> u8 {
        match self {
            Self::Verified { model_code, .. } | Self::Unverified { model_code, .. } => model_code,
        }
    }

    /// Whether a reviewed model-specific profile was available.
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified { .. })
    }
}

/// Typed failure from model-specific RNode radio admission.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum RNodeRadioAdmissionError {
    #[error("generic RNode radio settings are invalid: {0}")]
    GenericValidation(#[source] RNodeConfigValidationError),
    #[error("frequency {requested_hz} Hz is outside verified model range {min_hz}..={max_hz} Hz")]
    FrequencyOutOfRange {
        requested_hz: u32,
        min_hz: u32,
        max_hz: u32,
    },
    #[error("TX power {requested_dbm} dBm exceeds verified model maximum {max_dbm} dBm")]
    TxPowerExceedsMaximum { requested_dbm: u8, max_dbm: u8 },
}

/// Validate an EEPROM image and retain only non-identifying capability data.
///
/// Validation requires bytes through the identity-information lock at `0x9b`.
/// The MD5 checksum is calculated over the exact stored bytes `0x00..0x0b`;
/// model aliases are deliberately not normalised before validation. Bytes
/// after the identity prefix, including the signature region, are ignored.
pub fn parse_rnode_capabilities(
    eeprom: &[u8],
) -> Result<RNodeCapabilities, RNodeCapabilityParseError> {
    if eeprom.len() < REQUIRED_EEPROM_LEN {
        return Err(RNodeCapabilityParseError::TooShort {
            required: REQUIRED_EEPROM_LEN,
            actual: eeprom.len(),
        });
    }
    if eeprom[INFO_LOCK_ADDRESS] != INFO_LOCK_BYTE {
        return Err(RNodeCapabilityParseError::InfoNotLocked);
    }

    let calculated: [u8; 16] = Md5::digest(&eeprom[..IDENTITY_CHECKSUM_INPUT_END]).into();
    if calculated != eeprom[CHECKSUM_ADDRESS..CHECKSUM_END] {
        return Err(RNodeCapabilityParseError::ChecksumMismatch);
    }

    let product_code = eeprom[PRODUCT_ADDRESS];
    let model_code = eeprom[MODEL_ADDRESS];
    let radio = rnode_model_capabilities(model_code);

    Ok(RNodeCapabilities {
        product_code,
        model_code,
        radio,
    })
}

/// Classify a validated model without admitting radio settings.
///
/// `capabilities` can only be obtained from a successfully validated EEPROM
/// image. Unknown, aliased, ambiguous, and quarantined model codes return
/// [`RNodeRadioAdmission::Unverified`] without normalisation or an inferred
/// profile.
pub fn classify_rnode_radio_capabilities(capabilities: RNodeCapabilities) -> RNodeRadioAdmission {
    let product_code = capabilities.product_code();
    let model_code = capabilities.model_code();
    match capabilities.radio() {
        RNodeRadioCapabilities::Known(_) => RNodeRadioAdmission::Verified {
            product_code,
            model_code,
        },
        RNodeRadioCapabilities::Unknown => RNodeRadioAdmission::Unverified {
            product_code,
            model_code,
        },
    }
}

/// Apply the sole lower-layer RF admission policy to validated capabilities.
///
/// Generic RNode validation runs first. Known exact model codes then enforce
/// their inclusive frequency range and maximum TX power. Unknown, aliased,
/// ambiguous, and quarantined model codes continue as an explicit
/// [`RNodeRadioAdmission::Unverified`] result without normalisation or an
/// inferred profile.
pub fn admit_rnode_radio_settings(
    capabilities: RNodeCapabilities,
    settings: RNodeRadioSettings,
) -> Result<RNodeRadioAdmission, RNodeRadioAdmissionError> {
    settings
        .validate()
        .map_err(RNodeRadioAdmissionError::GenericValidation)?;

    if let RNodeRadioCapabilities::Known(radio) = capabilities.radio() {
        if !radio.supports_frequency(settings.frequency) {
            return Err(RNodeRadioAdmissionError::FrequencyOutOfRange {
                requested_hz: settings.frequency,
                min_hz: radio.min_frequency_hz(),
                max_hz: radio.max_frequency_hz(),
            });
        }
        if !radio.supports_tx_power(settings.tx_power) {
            return Err(RNodeRadioAdmissionError::TxPowerExceedsMaximum {
                requested_dbm: settings.tx_power,
                max_dbm: radio.max_tx_power_dbm(),
            });
        }
    }

    Ok(classify_rnode_radio_capabilities(capabilities))
}

/// Return the reviewed display name for an RNode product code.
///
/// Unknown product codes return `None`. Names are static code-table values and
/// are never read from device-controlled EEPROM data.
pub const fn rnode_product_name(product_code: u8) -> Option<&'static str> {
    Some(match product_code {
        0x03 => "RNode",
        0x10 => "RAK4631",
        0x15 => "LilyGO T-Echo",
        0x20 => "openCom XL",
        0xB0 => "LilyGO LoRa32 v2.0",
        0xB1 => "LilyGO LoRa32 v2.1",
        0xB2 => "LilyGO LoRa32 v1.0",
        0xC0 => "Heltec LoRa32 v2",
        0xC1 => "Heltec LoRa32 v3",
        0xC2 => "Heltec Mesh Node T114",
        0xC3 => "Heltec LoRa32 v4",
        0xD0 => "LilyGO T-Deck",
        0xE0 => "LilyGO T-Beam",
        0xEA => "LilyGO T-Beam Supreme",
        0xEB => "Seeed XIAO ESP32S3 Wio-SX1262",
        0xF0 => "Hombrew RNode",
        _ => return None,
    })
}

/// Return the reviewed radio capabilities for an exact RNode model code.
///
/// Unknown, ambiguous, and quarantined model codes return
/// [`RNodeRadioCapabilities::Unknown`]. In particular, EEPROM aliases are not
/// normalised by this lookup. Model codes `0xA6`, `0xAA`, and `0xC8` remain
/// quarantined because the trusted Rust sources do not establish a single,
/// internally consistent numeric capability profile for them.
pub fn rnode_model_capabilities(model_code: u8) -> RNodeRadioCapabilities {
    KNOWN_RADIOS
        .iter()
        .find_map(|(candidate, profile)| (*candidate == model_code).then_some(*profile))
        .map(RNodeRadioCapabilities::Known)
        .unwrap_or(RNodeRadioCapabilities::Unknown)
}

const fn known(
    family: RNodeRadioFamily,
    min_frequency_hz: u32,
    max_frequency_hz: u32,
    max_tx_power_dbm: u8,
) -> RNodeKnownRadioCapabilities {
    RNodeKnownRadioCapabilities {
        family,
        min_frequency_hz,
        max_frequency_hz,
        max_tx_power_dbm,
    }
}

// Reviewed numeric profiles owned by this lower-core module. Firmware
// filenames and human labels intentionally do not cross this boundary.
// Models with aliases, contradictory ranges, ambiguous evidence, or explicitly
// unknown limits are absent and therefore resolve to Unknown.
const KNOWN_RADIOS: &[(u8, RNodeKnownRadioCapabilities)] = &[
    (
        0xA4,
        known(RNodeRadioFamily::Sx1278, 410_000_000, 525_000_000, 14),
    ),
    (
        0xA9,
        known(RNodeRadioFamily::Sx1276, 820_000_000, 1_020_000_000, 17),
    ),
    (
        0xA1,
        known(RNodeRadioFamily::Sx1268, 410_000_000, 525_000_000, 22),
    ),
    (
        0xA5,
        known(RNodeRadioFamily::Sx1278, 410_000_000, 525_000_000, 17),
    ),
    (
        0xAC,
        known(RNodeRadioFamily::Sx1280, 2_400_000_000, 2_500_000_000, 20),
    ),
    (
        0xA2,
        known(RNodeRadioFamily::Sx1278, 410_000_000, 525_000_000, 17),
    ),
    (
        0xA7,
        known(RNodeRadioFamily::Sx1276, 820_000_000, 1_020_000_000, 17),
    ),
    (
        0xA3,
        known(RNodeRadioFamily::Sx1278, 410_000_000, 525_000_000, 17),
    ),
    (
        0xA8,
        known(RNodeRadioFamily::Sx1276, 820_000_000, 1_020_000_000, 17),
    ),
    (
        0xB3,
        known(RNodeRadioFamily::Sx1278, 420_000_000, 520_000_000, 17),
    ),
    (
        0xB8,
        known(RNodeRadioFamily::Sx1276, 850_000_000, 950_000_000, 17),
    ),
    (
        0xB4,
        known(RNodeRadioFamily::Sx1278, 420_000_000, 520_000_000, 17),
    ),
    (
        0xB9,
        known(RNodeRadioFamily::Sx1276, 850_000_000, 950_000_000, 17),
    ),
    (
        0xBA,
        known(RNodeRadioFamily::Sx1278, 420_000_000, 520_000_000, 17),
    ),
    (
        0xBB,
        known(RNodeRadioFamily::Sx1276, 850_000_000, 950_000_000, 17),
    ),
    (
        0xC4,
        known(RNodeRadioFamily::Sx1278, 420_000_000, 520_000_000, 17),
    ),
    (
        0xC9,
        known(RNodeRadioFamily::Sx1276, 850_000_000, 950_000_000, 17),
    ),
    (
        0xC5,
        known(RNodeRadioFamily::Sx1268, 420_000_000, 520_000_000, 22),
    ),
    (
        0xCA,
        known(RNodeRadioFamily::Sx1262, 850_000_000, 950_000_000, 22),
    ),
    (
        0xC6,
        known(RNodeRadioFamily::Sx1268, 420_000_000, 520_000_000, 22),
    ),
    (
        0xC7,
        known(RNodeRadioFamily::Sx1262, 850_000_000, 950_000_000, 22),
    ),
    (
        0xE4,
        known(RNodeRadioFamily::Sx1278, 420_000_000, 520_000_000, 17),
    ),
    (
        0xE9,
        known(RNodeRadioFamily::Sx1276, 850_000_000, 950_000_000, 17),
    ),
    (
        0xD4,
        known(RNodeRadioFamily::Sx1268, 420_000_000, 520_000_000, 22),
    ),
    (
        0xD9,
        known(RNodeRadioFamily::Sx1262, 850_000_000, 950_000_000, 22),
    ),
    (
        0xDB,
        known(RNodeRadioFamily::Sx1268, 420_000_000, 520_000_000, 22),
    ),
    (
        0xDC,
        known(RNodeRadioFamily::Sx1262, 850_000_000, 950_000_000, 22),
    ),
    (
        0xE3,
        known(RNodeRadioFamily::Sx1268, 420_000_000, 520_000_000, 22),
    ),
    (
        0xE8,
        known(RNodeRadioFamily::Sx1262, 850_000_000, 950_000_000, 22),
    ),
    (
        0x11,
        known(RNodeRadioFamily::Sx1262, 430_000_000, 510_000_000, 22),
    ),
    (
        0x12,
        known(RNodeRadioFamily::Sx1262, 779_000_000, 928_000_000, 22),
    ),
    (
        0x13,
        known(
            RNodeRadioFamily::Sx1262AndSx1280,
            430_000_000,
            510_000_000,
            22,
        ),
    ),
    (
        0x14,
        known(
            RNodeRadioFamily::Sx1262AndSx1280,
            779_000_000,
            928_000_000,
            22,
        ),
    ),
    (
        0x17,
        known(RNodeRadioFamily::Sx1262, 779_000_000, 928_000_000, 22),
    ),
    (
        0x21,
        known(
            RNodeRadioFamily::Sx1262AndSx1280,
            820_000_000,
            960_000_000,
            22,
        ),
    ),
    (
        0xDE,
        known(RNodeRadioFamily::Sx1262, 420_000_000, 520_000_000, 22),
    ),
    (
        0xDD,
        known(RNodeRadioFamily::Sx1262, 850_000_000, 950_000_000, 22),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    const PRODUCT: u8 = 0x03;
    const QUARANTINED_MODELS: &[u8] = &[0x04, 0x09, 0x16, 0xA6, 0xAA, 0xC8, 0xFE, 0xFF];

    fn image(model: u8) -> [u8; REQUIRED_EEPROM_LEN] {
        let mut bytes = [0xA5; REQUIRED_EEPROM_LEN];
        bytes[PRODUCT_ADDRESS] = PRODUCT;
        bytes[MODEL_ADDRESS] = model;
        bytes[0x02] = 0x07;
        bytes[0x03..0x07].copy_from_slice(&0x1122_3344_u32.to_be_bytes());
        bytes[0x07..0x0B].copy_from_slice(&0x5566_7788_u32.to_be_bytes());
        let checksum: [u8; 16] = Md5::digest(&bytes[..IDENTITY_CHECKSUM_INPUT_END]).into();
        bytes[CHECKSUM_ADDRESS..CHECKSUM_END].copy_from_slice(&checksum);
        bytes[INFO_LOCK_ADDRESS] = INFO_LOCK_BYTE;
        bytes
    }

    fn settings(frequency: u32, tx_power: u8) -> RNodeRadioSettings {
        RNodeRadioSettings::new(frequency, 125_000, 7, 5, tx_power)
    }

    #[test]
    fn requires_every_byte_through_info_lock() {
        let short = &image(0xA4)[..REQUIRED_EEPROM_LEN - 1];
        assert_eq!(
            parse_rnode_capabilities(short),
            Err(RNodeCapabilityParseError::TooShort {
                required: 156,
                actual: 155,
            })
        );

        let exact = image(0xA4);
        assert!(parse_rnode_capabilities(&exact).is_ok());
    }

    #[test]
    fn rejects_unlocked_identity_information_before_checksum_validation() {
        let mut bytes = image(0xA4);
        bytes[INFO_LOCK_ADDRESS] = 0x00;
        bytes[CHECKSUM_ADDRESS] ^= 0xFF;

        assert_eq!(
            parse_rnode_capabilities(&bytes),
            Err(RNodeCapabilityParseError::InfoNotLocked)
        );
    }

    #[test]
    fn checksum_covers_exact_identity_prefix_without_model_normalisation() {
        let mut bytes = image(0x04);
        let parsed = parse_rnode_capabilities(&bytes).expect("raw model checksum should validate");
        assert_eq!(parsed.model_code(), 0x04);
        assert_eq!(parsed.radio(), RNodeRadioCapabilities::Unknown);

        // Replacing the raw alias with its nominal model invalidates the exact
        // stored checksum; the parser must not normalise it first.
        bytes[MODEL_ADDRESS] = 0xB4;
        assert_eq!(
            parse_rnode_capabilities(&bytes),
            Err(RNodeCapabilityParseError::ChecksumMismatch)
        );
    }

    #[test]
    fn rejects_any_identity_prefix_checksum_mismatch() {
        for address in 0..IDENTITY_CHECKSUM_INPUT_END {
            let mut bytes = image(0xA4);
            bytes[address] ^= 0x01;
            assert_eq!(
                parse_rnode_capabilities(&bytes),
                Err(RNodeCapabilityParseError::ChecksumMismatch),
                "identity byte {address:#04x} was not covered"
            );
        }
    }

    #[test]
    fn returns_only_reviewed_codes_and_known_numeric_bounds() {
        let parsed = parse_rnode_capabilities(&image(0xAC)).expect("valid known model");
        assert_eq!(parsed.product_code(), PRODUCT);
        assert_eq!(parsed.product_name(), Some("RNode"));
        assert_eq!(parsed.model_code(), 0xAC);
        assert_eq!(
            parsed.radio(),
            RNodeRadioCapabilities::Known(known(
                RNodeRadioFamily::Sx1280,
                2_400_000_000,
                2_500_000_000,
                20,
            ))
        );

        let low_band = parse_rnode_capabilities(&image(0x11)).expect("valid known model");
        assert_eq!(
            low_band.radio(),
            RNodeRadioCapabilities::Known(known(
                RNodeRadioFamily::Sx1262,
                430_000_000,
                510_000_000,
                22,
            ))
        );
    }

    #[test]
    fn capability_support_helpers_include_both_boundaries() {
        let parsed = parse_rnode_capabilities(&image(0x11)).expect("valid known model");
        let RNodeRadioCapabilities::Known(radio) = parsed.radio() else {
            panic!("model 0x11 must have a reviewed profile");
        };

        assert!(radio.supports_frequency(430_000_000));
        assert!(radio.supports_frequency(510_000_000));
        assert!(!radio.supports_frequency(429_999_999));
        assert!(!radio.supports_frequency(510_000_001));

        assert!(radio.supports_tx_power(0));
        assert!(radio.supports_tx_power(22));
        assert!(!radio.supports_tx_power(23));
    }

    #[test]
    fn known_model_admission_includes_frequency_and_power_boundaries() {
        let capabilities = parse_rnode_capabilities(&image(0x11)).expect("valid known model");

        assert_eq!(
            admit_rnode_radio_settings(capabilities, settings(430_000_000, 0)),
            Ok(RNodeRadioAdmission::Verified {
                product_code: PRODUCT,
                model_code: 0x11,
            })
        );
        assert_eq!(
            admit_rnode_radio_settings(capabilities, settings(510_000_000, 22)),
            Ok(RNodeRadioAdmission::Verified {
                product_code: PRODUCT,
                model_code: 0x11,
            })
        );
        assert_eq!(
            classify_rnode_radio_capabilities(capabilities),
            RNodeRadioAdmission::Verified {
                product_code: PRODUCT,
                model_code: 0x11,
            }
        );
    }

    #[test]
    fn known_model_admission_returns_typed_frequency_and_power_mismatches() {
        let capabilities = parse_rnode_capabilities(&image(0x11)).expect("valid known model");

        for (frequency, expected) in [
            (
                429_999_999,
                RNodeRadioAdmissionError::FrequencyOutOfRange {
                    requested_hz: 429_999_999,
                    min_hz: 430_000_000,
                    max_hz: 510_000_000,
                },
            ),
            (
                510_000_001,
                RNodeRadioAdmissionError::FrequencyOutOfRange {
                    requested_hz: 510_000_001,
                    min_hz: 430_000_000,
                    max_hz: 510_000_000,
                },
            ),
        ] {
            assert_eq!(
                admit_rnode_radio_settings(capabilities, settings(frequency, 22)),
                Err(expected)
            );
        }

        let error = admit_rnode_radio_settings(capabilities, settings(430_000_000, 23));
        assert_eq!(
            error,
            Err(RNodeRadioAdmissionError::TxPowerExceedsMaximum {
                requested_dbm: 23,
                max_dbm: 22,
            })
        );
    }

    #[test]
    fn unknown_and_quarantined_admission_is_explicitly_unverified() {
        for model in std::iter::once(0x00).chain(QUARANTINED_MODELS.iter().copied()) {
            let capabilities =
                parse_rnode_capabilities(&image(model)).expect("valid identity image");
            assert_eq!(
                classify_rnode_radio_capabilities(capabilities),
                RNodeRadioAdmission::Unverified {
                    product_code: PRODUCT,
                    model_code: model,
                },
                "model {model:#04x} classification must remain unverified"
            );
            assert_eq!(
                admit_rnode_radio_settings(capabilities, settings(868_000_000, 37)),
                Ok(RNodeRadioAdmission::Unverified {
                    product_code: PRODUCT,
                    model_code: model,
                }),
                "model {model:#04x} must remain unverified"
            );
        }
    }

    #[test]
    fn generic_validation_precedes_known_and_unverified_model_policy() {
        for model in [0x11, 0xA6] {
            let capabilities = parse_rnode_capabilities(&image(model)).expect("valid identity");
            let error = admit_rnode_radio_settings(capabilities, settings(1, 23))
                .expect_err("model policy must not bypass generic validation");
            assert!(
                matches!(error, RNodeRadioAdmissionError::GenericValidation(_)),
                "model {model:#04x} did not fail generic validation first: {error:?}"
            );
        }
    }

    #[test]
    fn product_names_are_closed_static_lookups() {
        const PRODUCTS: &[(u8, &str)] = &[
            (0x03, "RNode"),
            (0x10, "RAK4631"),
            (0x15, "LilyGO T-Echo"),
            (0x20, "openCom XL"),
            (0xB0, "LilyGO LoRa32 v2.0"),
            (0xB1, "LilyGO LoRa32 v2.1"),
            (0xB2, "LilyGO LoRa32 v1.0"),
            (0xC0, "Heltec LoRa32 v2"),
            (0xC1, "Heltec LoRa32 v3"),
            (0xC2, "Heltec Mesh Node T114"),
            (0xC3, "Heltec LoRa32 v4"),
            (0xD0, "LilyGO T-Deck"),
            (0xE0, "LilyGO T-Beam"),
            (0xEA, "LilyGO T-Beam Supreme"),
            (0xEB, "Seeed XIAO ESP32S3 Wio-SX1262"),
            (0xF0, "Hombrew RNode"),
        ];

        for (index, (code, name)) in PRODUCTS.iter().enumerate() {
            assert_eq!(rnode_product_name(*code), Some(*name));
            assert!(
                !PRODUCTS[..index].iter().any(|(earlier, _)| earlier == code),
                "duplicate product code {code:#04x}"
            );
        }
        assert_eq!(rnode_product_name(0x00), None);
        assert_eq!(rnode_product_name(0xFF), None);
    }

    #[test]
    fn unknown_and_quarantined_models_never_invent_limits() {
        for model in std::iter::once(0x00).chain(QUARANTINED_MODELS.iter().copied()) {
            let parsed = parse_rnode_capabilities(&image(model)).expect("valid identity image");
            assert_eq!(parsed.model_code(), model);
            assert_eq!(
                parsed.radio(),
                RNodeRadioCapabilities::Unknown,
                "model {model:#04x} must remain unknown"
            );
        }
    }

    #[test]
    fn direct_model_lookup_is_closed_and_does_not_normalise_quarantine() {
        assert_eq!(
            rnode_model_capabilities(0xA4),
            RNodeRadioCapabilities::Known(known(
                RNodeRadioFamily::Sx1278,
                410_000_000,
                525_000_000,
                14,
            ))
        );

        for model in std::iter::once(0x00).chain(QUARANTINED_MODELS.iter().copied()) {
            assert_eq!(
                rnode_model_capabilities(model),
                RNodeRadioCapabilities::Unknown,
                "model {model:#04x} must remain unknown"
            );
        }
    }

    #[test]
    fn signature_and_other_ignored_bytes_do_not_affect_result() {
        let baseline_image = image(0xA4);
        let baseline = parse_rnode_capabilities(&baseline_image).expect("valid image");
        let mut mutated = baseline_image;

        for (index, byte) in mutated[CHECKSUM_END..INFO_LOCK_ADDRESS]
            .iter_mut()
            .enumerate()
        {
            *byte = index as u8;
        }

        assert_eq!(
            parse_rnode_capabilities(&mutated),
            Ok(baseline),
            "signature and non-capability bytes must be ignored"
        );
    }

    #[test]
    fn known_model_table_is_unique_valid_and_excludes_quarantine() {
        assert_eq!(KNOWN_RADIOS.len(), 37);

        for (index, (model, profile)) in KNOWN_RADIOS.iter().enumerate() {
            assert!(
                !QUARANTINED_MODELS.contains(model),
                "quarantined model {model:#04x} entered the known table"
            );
            assert!(
                profile.min_frequency_hz() < profile.max_frequency_hz(),
                "model {model:#04x} has inverted frequency limits"
            );
            assert!(
                profile.max_tx_power_dbm() > 0,
                "model {model:#04x} has a non-positive maximum TX power"
            );
            assert!(
                !KNOWN_RADIOS[..index]
                    .iter()
                    .any(|(earlier, _)| earlier == model),
                "duplicate model {model:#04x}"
            );
            assert_eq!(
                rnode_model_capabilities(*model),
                RNodeRadioCapabilities::Known(*profile),
                "model {model:#04x} did not round-trip through lookup"
            );
        }
    }
}
