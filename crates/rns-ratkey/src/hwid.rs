//! TOML metadata for a hardware identity. The defined fields contain public
//! keys, device/policy annotations and optional certificates, not a private-key
//! backup. Provisioning writes `<identities_dir>/<hash_hex>/identity.hwid`;
//! the caller chooses that directory.
//!
//! Parsing checks the TOML shape, not key/hash binding, device authenticity,
//! attestation validity or policy enforcement. Strings and status fields are
//! caller-controlled; loaders must perform the checks they rely on.

use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::RatkeyError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HwidConfig {
    pub identity: HwidIdentity,
    pub device: HwidDevice,
    pub keys: HwidKeys,
    pub slots: HwidSlots,
    pub policy: HwidPolicy,
    #[serde(default)]
    pub attestation: HwidAttestation,
    #[serde(default)]
    pub app: HwidApp,
    #[serde(default)]
    pub backup: HwidBackup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HwidIdentity {
    /// 16-byte hash (32 hex chars).
    pub hash: String,
    #[serde(default)]
    pub nickname: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HwidDevice {
    /// Device label, for example "yubikey5", "nitrokey3" or "unknown".
    /// The label alone does not establish firmware or algorithm compatibility.
    #[serde(rename = "type")]
    pub device_type: String,
    pub serial: u32,
    pub firmware: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HwidKeys {
    /// 32-byte hex.
    pub ed25519_pub: String,
    /// 32-byte hex.
    pub x25519_pub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HwidSlots {
    /// PIV slot hex (e.g. "9A").
    pub signing: String,
    /// PIV slot hex (e.g. "9D").
    pub encryption: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HwidPolicy {
    /// Requested PIN-cache duration in seconds; zero conventionally disables
    /// cache reuse. The current PivSession/PCSC identity loader does not apply
    /// this field and uses its own five-minute cache.
    #[serde(default = "default_pin_cache_timeout")]
    pub pin_cache_timeout: u64,
    /// "always" | "cached" | "never".
    #[serde(default = "default_touch_signing")]
    pub touch_signing: String,
    /// "always" | "cached" | "never".
    #[serde(default = "default_touch_encryption")]
    pub touch_encryption: String,
}

fn default_pin_cache_timeout() -> u64 {
    300
}
fn default_touch_signing() -> String {
    "always".to_string()
}
fn default_touch_encryption() -> String {
    "cached".to_string()
}

/// Attestation certificates (base64-encoded DER).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HwidAttestation {
    #[serde(default)]
    pub ed25519_cert: String,
    #[serde(default)]
    pub x25519_cert: String,
    /// Stored attestation-chain verification claim. Metadata extraction alone
    /// must not set it true; reading the TOML does not reverify the claim or
    /// bind these certificates to the configured public keys.
    #[serde(default)]
    pub verified: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HwidApp {
    /// Pre-computed app destination hash (hex).
    #[serde(default)]
    pub app_hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HwidBackup {
    /// Backup annotation: 0=none, 1=device-clone, 2=encrypted-offline.
    /// This field does not create, restore or verify a backup.
    #[serde(default)]
    pub tier: u8,
    /// Tier 1 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_serial: Option<u32>,
    /// Tier 2 only: SHA-256 of encrypted backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_backup_hash: Option<String>,
}

impl HwidConfig {
    pub fn from_file(path: &Path) -> Result<Self, RatkeyError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RatkeyError::InvalidHwid(format!("cannot read file: {e}")))?;
        content.parse()
    }

    pub fn to_file(&self, path: &Path) -> Result<(), RatkeyError> {
        let content = self.to_string()?;
        // Atomic: write tmp, then rename.
        let tmp_path = path.with_extension("hwid.tmp");
        std::fs::write(&tmp_path, content)?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    pub fn to_string(&self) -> Result<String, RatkeyError> {
        let header = "# RATKEY Hardware Identity \u{2014} DO NOT EDIT MANUALLY\n\
                      # This file contains public metadata, not private keys.\n\n";
        let body =
            toml::to_string_pretty(self).map_err(|e| RatkeyError::InvalidHwid(e.to_string()))?;
        Ok(format!("{header}{body}"))
    }

    pub fn ed25519_pub_bytes(&self) -> Result<[u8; 32], RatkeyError> {
        decode_hex_32(&self.keys.ed25519_pub, "ed25519_pub")
    }

    pub fn x25519_pub_bytes(&self) -> Result<[u8; 32], RatkeyError> {
        decode_hex_32(&self.keys.x25519_pub, "x25519_pub")
    }

    pub fn signing_slot(&self) -> Result<u8, RatkeyError> {
        parse_slot(&self.slots.signing)
    }

    pub fn encryption_slot(&self) -> Result<u8, RatkeyError> {
        parse_slot(&self.slots.encryption)
    }
}

impl FromStr for HwidConfig {
    type Err = RatkeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        toml::from_str(s).map_err(|e| RatkeyError::InvalidHwid(e.to_string()))
    }
}

fn decode_hex_32(hex_str: &str, field: &str) -> Result<[u8; 32], RatkeyError> {
    let bytes =
        hex::decode(hex_str).map_err(|e| RatkeyError::InvalidHwid(format!("{field}: {e}")))?;
    if bytes.len() != 32 {
        return Err(RatkeyError::InvalidHwid(format!(
            "{field}: expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_slot(s: &str) -> Result<u8, RatkeyError> {
    u8::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .map_err(|e| RatkeyError::InvalidHwid(format!("invalid slot '{s}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> HwidConfig {
        HwidConfig {
            identity: HwidIdentity {
                hash: "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8".to_string(),
                nickname: "Test YubiKey".to_string(),
                created_at: 1711580400,
            },
            device: HwidDevice {
                device_type: "yubikey5".to_string(),
                serial: 12345678,
                firmware: "5.7.1".to_string(),
            },
            keys: HwidKeys {
                ed25519_pub: "aa".repeat(32),
                x25519_pub: "bb".repeat(32),
            },
            slots: HwidSlots {
                signing: "9A".to_string(),
                encryption: "9D".to_string(),
            },
            policy: HwidPolicy {
                pin_cache_timeout: 300,
                touch_signing: "always".to_string(),
                touch_encryption: "cached".to_string(),
            },
            attestation: HwidAttestation::default(),
            app: HwidApp::default(),
            backup: HwidBackup::default(),
        }
    }

    #[test]
    fn test_round_trip() {
        let config = sample_config();
        let toml_str = config.to_string().unwrap();
        let parsed = toml_str.parse::<HwidConfig>().unwrap();

        assert_eq!(parsed.identity.hash, config.identity.hash);
        assert_eq!(parsed.identity.nickname, config.identity.nickname);
        assert_eq!(parsed.device.device_type, config.device.device_type);
        assert_eq!(parsed.device.serial, config.device.serial);
        assert_eq!(parsed.keys.ed25519_pub, config.keys.ed25519_pub);
        assert_eq!(parsed.keys.x25519_pub, config.keys.x25519_pub);
        assert_eq!(parsed.slots.signing, config.slots.signing);
        assert_eq!(parsed.slots.encryption, config.slots.encryption);
        assert_eq!(
            parsed.policy.pin_cache_timeout,
            config.policy.pin_cache_timeout
        );
        assert_eq!(parsed.policy.touch_signing, config.policy.touch_signing);
        assert_eq!(parsed.backup.tier, 0);
    }

    #[test]
    fn test_decode_public_keys() {
        let config = sample_config();
        let ed_bytes = config.ed25519_pub_bytes().unwrap();
        assert_eq!(ed_bytes, [0xAA; 32]);
        let x_bytes = config.x25519_pub_bytes().unwrap();
        assert_eq!(x_bytes, [0xBB; 32]);
    }

    #[test]
    fn test_parse_slots() {
        let config = sample_config();
        assert_eq!(config.signing_slot().unwrap(), 0x9A);
        assert_eq!(config.encryption_slot().unwrap(), 0x9D);
    }

    #[test]
    fn test_invalid_hex() {
        let mut config = sample_config();
        config.keys.ed25519_pub = "not_hex".to_string();
        assert!(config.ed25519_pub_bytes().is_err());
    }

    #[test]
    fn test_wrong_key_length() {
        let mut config = sample_config();
        config.keys.ed25519_pub = "aa".repeat(16); // 16 bytes instead of 32
        assert!(config.ed25519_pub_bytes().is_err());
    }

    #[test]
    fn test_invalid_slot() {
        let mut config = sample_config();
        config.slots.signing = "ZZ".to_string();
        assert!(config.signing_slot().is_err());
    }

    #[test]
    fn test_toml_contains_header() {
        let config = sample_config();
        let toml_str = config.to_string().unwrap();
        assert!(toml_str.contains("RATKEY Hardware Identity"));
        assert!(toml_str.contains("DO NOT EDIT MANUALLY"));
    }

    #[test]
    fn test_file_round_trip() {
        let config = sample_config();
        let dir = std::env::temp_dir().join("ratkey_test_hwid");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.hwid");

        config.to_file(&path).unwrap();
        let loaded = HwidConfig::from_file(&path).unwrap();

        assert_eq!(loaded.identity.hash, config.identity.hash);
        assert_eq!(loaded.device.serial, config.device.serial);
        assert_eq!(loaded.keys.ed25519_pub, config.keys.ed25519_pub);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_defaults_applied() {
        let minimal = r#"
[identity]
hash = "aabb"
created_at = 1000

[device]
type = "yubikey5"
serial = 1
firmware = "5.7.0"

[keys]
ed25519_pub = "aa"
x25519_pub = "bb"

[slots]
signing = "9A"
encryption = "9D"

[policy]
"#;
        let config = minimal.parse::<HwidConfig>().unwrap();
        assert_eq!(config.policy.pin_cache_timeout, 300);
        assert_eq!(config.policy.touch_signing, "always");
        assert_eq!(config.policy.touch_encryption, "cached");
        assert_eq!(config.backup.tier, 0);
        assert!(config.attestation.ed25519_cert.is_empty());
    }
}
