//! RNode platform, product and firmware model metadata.
//!
//! Radio families and numeric operating limits belong to
//! `rns_interface::rnode_capabilities`; this tool-local table contains only
//! metadata needed to plan firmware operations.

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
    pub firmware_filename: Option<&'static str>,
}

pub const MODELS: &[ModelInfo] = &[
    model(0xA4, Some("rnode_firmware.hex")),
    model(0xA9, Some("rnode_firmware.hex")),
    model(0xA1, Some("rnode_firmware_t3s3.zip")),
    model(0xA6, Some("rnode_firmware_t3s3.zip")),
    model(0xA5, Some("rnode_firmware_t3s3_sx127x.zip")),
    model(0xAA, Some("rnode_firmware_t3s3_sx127x.zip")),
    model(0xAC, Some("rnode_firmware_t3s3_sx1280_pa.zip")),
    model(0xA2, Some("rnode_firmware_ng21.zip")),
    model(0xA7, Some("rnode_firmware_ng21.zip")),
    model(0xA3, Some("rnode_firmware_ng20.zip")),
    model(0xA8, Some("rnode_firmware_ng20.zip")),
    model(0xB3, Some("rnode_firmware_lora32v20.zip")),
    model(0xB8, Some("rnode_firmware_lora32v20.zip")),
    model(0xB4, Some("rnode_firmware_lora32v21.zip")),
    model(0xB9, Some("rnode_firmware_lora32v21.zip")),
    model(MODEL_B4_TCXO, Some("rnode_firmware_lora32v21_tcxo.zip")),
    model(MODEL_B9_TCXO, Some("rnode_firmware_lora32v21_tcxo.zip")),
    model(0xBA, Some("rnode_firmware_lora32v10.zip")),
    model(0xBB, Some("rnode_firmware_lora32v10.zip")),
    model(0xC4, Some("rnode_firmware_heltec32v2.zip")),
    model(0xC9, Some("rnode_firmware_heltec32v2.zip")),
    model(0xC5, Some("rnode_firmware_heltec32v3.zip")),
    model(0xCA, Some("rnode_firmware_heltec32v3.zip")),
    model(0xC8, Some("rnode_firmware_heltec32v4pa.zip")),
    model(0xC6, Some("rnode_firmware_heltec_t114.zip")),
    model(0xC7, Some("rnode_firmware_heltec_t114.zip")),
    model(0xE4, Some("rnode_firmware_tbeam.zip")),
    model(0xE9, Some("rnode_firmware_tbeam.zip")),
    model(0xD4, Some("rnode_firmware_tdeck.zip")),
    model(0xD9, Some("rnode_firmware_tdeck.zip")),
    model(0xDB, Some("rnode_firmware_tbeam_supreme.zip")),
    model(0xDC, Some("rnode_firmware_tbeam_supreme.zip")),
    model(0xE3, Some("rnode_firmware_tbeam_sx1262.zip")),
    model(0xE8, Some("rnode_firmware_tbeam_sx1262.zip")),
    model(0x11, Some("rnode_firmware_rak4631.zip")),
    model(0x12, Some("rnode_firmware_rak4631.zip")),
    model(0x13, Some("rnode_firmware_rak4631_sx1280.zip")),
    model(0x14, Some("rnode_firmware_rak4631_sx1280.zip")),
    model(0x16, Some("rnode_firmware_techo.zip")),
    model(0x17, Some("rnode_firmware_techo.zip")),
    model(0x21, Some("rnode_firmware_opencom_xl.zip")),
    model(0xDE, Some("rnode_firmware_xiao_esp32s3.zip")),
    model(0xDD, Some("rnode_firmware_xiao_esp32s3.zip")),
    model(0xFE, None),
    model(0xFF, None),
];

const fn model(model: u8, firmware_filename: Option<&'static str>) -> ModelInfo {
    ModelInfo {
        model,
        firmware_filename,
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
    fn model_table_retains_only_firmware_planning_metadata() {
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
