//! Privacy-bounded, read-only RNode capability parsing.
//!
//! RNode EEPROM identity information contains serial, manufacturing, checksum,
//! signature, and other device-specific bytes. This module validates the
//! immutable identity prefix in place, then returns only copyable product/model
//! codes and reviewed radio limits. It never retains the source image or
//! exposes identity, signature, configuration, or raw EEPROM fields.

use md5::{Digest, Md5};

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
/// normalised by this lookup.
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

// Numeric profiles copied from the existing rns-tools RNode model table.
// Firmware filenames and human labels intentionally do not cross this lower
// boundary. Models with aliases, contradictory ranges, or explicitly unknown
// limits are absent and therefore resolve to Unknown.
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
        0xA6,
        known(RNodeRadioFamily::Sx1262, 820_000_000, 1_020_000_000, 22),
    ),
    (
        0xA5,
        known(RNodeRadioFamily::Sx1278, 410_000_000, 525_000_000, 17),
    ),
    (
        0xAA,
        known(RNodeRadioFamily::Sx1276, 820_000_000, 1_020_000_000, 17),
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
        0xC8,
        known(RNodeRadioFamily::Sx1262, 860_000_000, 930_000_000, 28),
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
        for model in [0x00, 0x04, 0x09, 0x16, 0xFE, 0xFF] {
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

        for model in [0x00, 0x04, 0x09, 0x16, 0xFE, 0xFF] {
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
        assert_eq!(KNOWN_RADIOS.len(), 40);

        for (index, (model, profile)) in KNOWN_RADIOS.iter().enumerate() {
            assert!(
                ![0x04, 0x09, 0x16, 0xFE, 0xFF].contains(model),
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
