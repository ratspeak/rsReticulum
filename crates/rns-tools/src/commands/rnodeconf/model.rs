//! RNode platform, product and firmware model metadata.
//!
//! The model and product tables are upstream `rnodeconf` 2.5.0's `models` and
//! `products`, which drive its device info output and firmware selection.

pub const PLATFORM_AVR: u8 = 0x90;
pub const PLATFORM_ESP32: u8 = 0x80;
pub const PLATFORM_NRF52: u8 = 0x70;

pub const MCU_1284P: u8 = 0x91;
pub const MCU_2560: u8 = 0x92;
pub const MCU_ESP32: u8 = 0x81;
pub const MCU_NRF52: u8 = 0x71;

pub const PRODUCT_RNODE: u8 = 0x03;
pub const PRODUCT_RAK4631: u8 = 0x10;
pub const PRODUCT_TECHO: u8 = 0x15;
pub const PRODUCT_OPENCOM_XL: u8 = 0x20;
pub const PRODUCT_T32_20: u8 = 0xB0;
pub const PRODUCT_T32_21: u8 = 0xB1;
pub const PRODUCT_T32_10: u8 = 0xB2;
pub const PRODUCT_H32_V2: u8 = 0xC0;
pub const PRODUCT_H32_V3: u8 = 0xC1;
pub const PRODUCT_HELTEC_T114: u8 = 0xC2;
pub const PRODUCT_H32_V4: u8 = 0xC3;
pub const PRODUCT_TDECK: u8 = 0xD0;
pub const PRODUCT_TBEAM: u8 = 0xE0;
pub const PRODUCT_TBEAM_S_V1: u8 = 0xEA;
pub const PRODUCT_XIAO_S3: u8 = 0xEB;
pub const PRODUCT_HMBRW: u8 = 0xF0;

pub const MODEL_B4_TCXO: u8 = 0x04;
pub const MODEL_B9_TCXO: u8 = 0x09;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelInfo {
    pub model: u8,
    pub min_freq: u64,
    pub max_freq: u64,
    pub max_output: u8,
    pub band: &'static str,
    pub firmware_filename: Option<&'static str>,
    pub modem: &'static str,
}

pub const MODELS: &[ModelInfo] = &[
    model(
        0xA4,
        410000000,
        525000000,
        14,
        "410 - 525 MHz",
        Some("rnode_firmware.hex"),
        "SX1278",
    ),
    model(
        0xA9,
        820000000,
        1020000000,
        17,
        "820 - 1020 MHz",
        Some("rnode_firmware.hex"),
        "SX1276",
    ),
    model(
        0xA1,
        410000000,
        525000000,
        22,
        "410 - 525 MHz",
        Some("rnode_firmware_t3s3.zip"),
        "SX1268",
    ),
    model(
        0xA6,
        820000000,
        1020000000,
        22,
        "820 - 960 MHz",
        Some("rnode_firmware_t3s3.zip"),
        "SX1262",
    ),
    model(
        0xA5,
        410000000,
        525000000,
        17,
        "410 - 525 MHz",
        Some("rnode_firmware_t3s3_sx127x.zip"),
        "SX1278",
    ),
    model(
        0xAA,
        820000000,
        1020000000,
        17,
        "820 - 960 MHz",
        Some("rnode_firmware_t3s3_sx127x.zip"),
        "SX1276",
    ),
    model(
        0xAC,
        2400000000,
        2500000000,
        20,
        "2.4 - 2.5 GHz",
        Some("rnode_firmware_t3s3_sx1280_pa.zip"),
        "SX1280",
    ),
    model(
        0xA2,
        410000000,
        525000000,
        17,
        "410 - 525 MHz",
        Some("rnode_firmware_ng21.zip"),
        "SX1278",
    ),
    model(
        0xA7,
        820000000,
        1020000000,
        17,
        "820 - 1020 MHz",
        Some("rnode_firmware_ng21.zip"),
        "SX1276",
    ),
    model(
        0xA3,
        410000000,
        525000000,
        17,
        "410 - 525 MHz",
        Some("rnode_firmware_ng20.zip"),
        "SX1278",
    ),
    model(
        0xA8,
        820000000,
        1020000000,
        17,
        "820 - 1020 MHz",
        Some("rnode_firmware_ng20.zip"),
        "SX1276",
    ),
    model(
        0xB3,
        420000000,
        520000000,
        17,
        "420 - 520 MHz",
        Some("rnode_firmware_lora32v20.zip"),
        "SX1278",
    ),
    model(
        0xB8,
        850000000,
        950000000,
        17,
        "850 - 950 MHz",
        Some("rnode_firmware_lora32v20.zip"),
        "SX1276",
    ),
    model(
        0xB4,
        420000000,
        520000000,
        17,
        "420 - 520 MHz",
        Some("rnode_firmware_lora32v21.zip"),
        "SX1278",
    ),
    model(
        0xB9,
        850000000,
        950000000,
        17,
        "850 - 950 MHz",
        Some("rnode_firmware_lora32v21.zip"),
        "SX1276",
    ),
    model(
        0x04,
        420000000,
        520000000,
        17,
        "420 - 520 MHz",
        Some("rnode_firmware_lora32v21_tcxo.zip"),
        "SX1278",
    ),
    model(
        0x09,
        850000000,
        950000000,
        17,
        "850 - 950 MHz",
        Some("rnode_firmware_lora32v21_tcxo.zip"),
        "SX1276",
    ),
    model(
        0xBA,
        420000000,
        520000000,
        17,
        "420 - 520 MHz",
        Some("rnode_firmware_lora32v10.zip"),
        "SX1278",
    ),
    model(
        0xBB,
        850000000,
        950000000,
        17,
        "850 - 950 MHz",
        Some("rnode_firmware_lora32v10.zip"),
        "SX1276",
    ),
    model(
        0xC4,
        420000000,
        520000000,
        17,
        "420 - 520 MHz",
        Some("rnode_firmware_heltec32v2.zip"),
        "SX1278",
    ),
    model(
        0xC9,
        850000000,
        950000000,
        17,
        "850 - 950 MHz",
        Some("rnode_firmware_heltec32v2.zip"),
        "SX1276",
    ),
    model(
        0xC5,
        420000000,
        520000000,
        22,
        "420 - 520 MHz",
        Some("rnode_firmware_heltec32v3.zip"),
        "SX1268",
    ),
    model(
        0xCA,
        850000000,
        950000000,
        22,
        "850 - 950 MHz",
        Some("rnode_firmware_heltec32v3.zip"),
        "SX1262",
    ),
    model(
        0xC8,
        860000000,
        930000000,
        28,
        "850 - 950 MHz",
        Some("rnode_firmware_heltec32v4pa.zip"),
        "SX1262",
    ),
    model(
        0xC6,
        420000000,
        520000000,
        22,
        "420 - 520 MHz",
        Some("rnode_firmware_heltec_t114.zip"),
        "SX1268",
    ),
    model(
        0xC7,
        850000000,
        950000000,
        22,
        "850 - 950 MHz",
        Some("rnode_firmware_heltec_t114.zip"),
        "SX1262",
    ),
    model(
        0xE4,
        420000000,
        520000000,
        17,
        "420 - 520 MHz",
        Some("rnode_firmware_tbeam.zip"),
        "SX1278",
    ),
    model(
        0xE9,
        850000000,
        950000000,
        17,
        "850 - 950 MHz",
        Some("rnode_firmware_tbeam.zip"),
        "SX1276",
    ),
    model(
        0xD4,
        420000000,
        520000000,
        22,
        "420 - 520 MHz",
        Some("rnode_firmware_tdeck.zip"),
        "SX1268",
    ),
    model(
        0xD9,
        850000000,
        950000000,
        22,
        "850 - 950 MHz",
        Some("rnode_firmware_tdeck.zip"),
        "SX1262",
    ),
    model(
        0xDB,
        420000000,
        520000000,
        22,
        "420 - 520 MHz",
        Some("rnode_firmware_tbeam_supreme.zip"),
        "SX1268",
    ),
    model(
        0xDC,
        850000000,
        950000000,
        22,
        "850 - 950 MHz",
        Some("rnode_firmware_tbeam_supreme.zip"),
        "SX1262",
    ),
    model(
        0xE3,
        420000000,
        520000000,
        22,
        "420 - 520 MHz",
        Some("rnode_firmware_tbeam_sx1262.zip"),
        "SX1268",
    ),
    model(
        0xE8,
        850000000,
        950000000,
        22,
        "850 - 950 MHz",
        Some("rnode_firmware_tbeam_sx1262.zip"),
        "SX1262",
    ),
    model(
        0x11,
        430000000,
        510000000,
        22,
        "430 - 510 MHz",
        Some("rnode_firmware_rak4631.zip"),
        "SX1262",
    ),
    model(
        0x12,
        779000000,
        928000000,
        22,
        "779 - 928 MHz",
        Some("rnode_firmware_rak4631.zip"),
        "SX1262",
    ),
    model(
        0x13,
        430000000,
        510000000,
        22,
        "430 - 510 MHz",
        Some("rnode_firmware_rak4631_sx1280.zip"),
        "SX1262 + SX1280",
    ),
    model(
        0x14,
        779000000,
        928000000,
        22,
        "779 - 928 MHz",
        Some("rnode_firmware_rak4631_sx1280.zip"),
        "SX1262 + SX1280",
    ),
    model(
        0x16,
        779000000,
        928000000,
        22,
        "430 - 510 Mhz",
        Some("rnode_firmware_techo.zip"),
        "SX1262",
    ),
    model(
        0x17,
        779000000,
        928000000,
        22,
        "779 - 928 Mhz",
        Some("rnode_firmware_techo.zip"),
        "SX1262",
    ),
    model(
        0x21,
        820000000,
        960000000,
        22,
        "820 - 960 MHz",
        Some("rnode_firmware_opencom_xl.zip"),
        "SX1262 + SX1280",
    ),
    model(
        0xDE,
        420000000,
        520000000,
        22,
        "420 - 520 MHz",
        Some("rnode_firmware_xiao_esp32s3.zip"),
        "SX1262",
    ),
    model(
        0xDD,
        850000000,
        950000000,
        22,
        "850 - 950 MHz",
        Some("rnode_firmware_xiao_esp32s3.zip"),
        "SX1262",
    ),
    model(
        0xFE,
        100000000,
        1100000000,
        17,
        "(Band capabilities unknown)",
        None,
        "Unknown",
    ),
    model(
        0xFF,
        100000000,
        1100000000,
        14,
        "(Band capabilities unknown)",
        None,
        "Unknown",
    ),
];

const fn model(
    model: u8,
    min_freq: u64,
    max_freq: u64,
    max_output: u8,
    band: &'static str,
    firmware_filename: Option<&'static str>,
    modem: &'static str,
) -> ModelInfo {
    ModelInfo {
        model,
        min_freq,
        max_freq,
        max_output,
        band,
        firmware_filename,
        modem,
    }
}

pub fn model_info(model: u8) -> Option<&'static ModelInfo> {
    MODELS.iter().find(|entry| entry.model == model)
}

pub fn normalize_eeprom_model(model: u8) -> u8 {
    match model {
        MODEL_B4_TCXO => 0xB4,
        MODEL_B9_TCXO => 0xB9,
        other => other,
    }
}

pub fn product_name(product: u8) -> Option<&'static str> {
    Some(match product {
        PRODUCT_RNODE => "RNode",
        PRODUCT_HMBRW => "Hombrew RNode",
        PRODUCT_TBEAM => "LilyGO T-Beam",
        PRODUCT_TBEAM_S_V1 => "LilyGO T-Beam Supreme",
        PRODUCT_TDECK => "LilyGO T-Deck",
        PRODUCT_T32_10 => "LilyGO LoRa32 v1.0",
        PRODUCT_T32_20 => "LilyGO LoRa32 v2.0",
        PRODUCT_T32_21 => "LilyGO LoRa32 v2.1",
        PRODUCT_H32_V2 => "Heltec LoRa32 v2",
        PRODUCT_H32_V3 => "Heltec LoRa32 v3",
        PRODUCT_H32_V4 => "Heltec LoRa32 v4",
        PRODUCT_TECHO => "LilyGO T-Echo",
        PRODUCT_RAK4631 => "RAK4631",
        PRODUCT_OPENCOM_XL => "openCom XL",
        PRODUCT_HELTEC_T114 => "Heltec Mesh Node T114",
        PRODUCT_XIAO_S3 => "Seeed XIAO ESP32S3 Wio-SX1262",
        _ => return None,
    })
}

pub fn platform_name(platform: u8) -> Option<&'static str> {
    Some(match platform {
        PLATFORM_AVR => "AVR",
        PLATFORM_ESP32 => "ESP32",
        PLATFORM_NRF52 => "NRF52",
        _ => return None,
    })
}

pub fn mcu_name(mcu: u8) -> Option<&'static str> {
    Some(match mcu {
        MCU_1284P => "ATmega1284P",
        MCU_2560 => "ATmega2560",
        MCU_ESP32 => "Espressif Systems ESP32",
        MCU_NRF52 => "Nordic Semiconductor nRF52840",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_table_holds_the_upstream_model_codes() {
        assert_eq!(MODELS.len(), 45);
        assert_eq!(
            model_info(0xA4).unwrap().firmware_filename,
            Some("rnode_firmware.hex")
        );
        assert_eq!(
            model_info(0xAC).unwrap().firmware_filename,
            Some("rnode_firmware_t3s3_sx1280_pa.zip")
        );
        assert_eq!(model_info(0xFE).unwrap().firmware_filename, None);
        assert_eq!(model_info(0xFF).unwrap().firmware_filename, None);
    }

    #[test]
    fn tcxo_models_are_normalized_for_eeprom() {
        assert_eq!(normalize_eeprom_model(MODEL_B4_TCXO), 0xB4);
        assert_eq!(normalize_eeprom_model(MODEL_B9_TCXO), 0xB9);
        assert_eq!(normalize_eeprom_model(0xA4), 0xA4);
    }

    #[test]
    fn platform_and_mcu_names_match_upstream_spellings() {
        assert_eq!(platform_name(PLATFORM_ESP32), Some("ESP32"));
        assert_eq!(mcu_name(MCU_NRF52), Some("Nordic Semiconductor nRF52840"));
    }
}
