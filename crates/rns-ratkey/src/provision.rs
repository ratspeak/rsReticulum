//! Generate keys on-device, derive identity hash, write `.hwid`.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rns_crypto::sha::truncated_hash;

use crate::apdu;
use crate::error::RatkeyError;
use crate::hwid::*;
use crate::mock::{MockPivSession, SLOT_9A, SLOT_9D, TouchPolicy};
use crate::seed;
use crate::session::PivSession;
use crate::transport::PivTransport;

#[derive(Debug, Clone)]
pub struct ProvisionResult {
    pub config: HwidConfig,
    pub ed25519_pub: [u8; 32],
    pub x25519_pub: [u8; 32],
    /// 16-byte Reticulum identity hash.
    pub identity_hash: [u8; 16],
    pub identity_hash_hex: String,
    pub hwid_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ProvisionConfig {
    /// PIV PIN (6-8 chars).
    pub pin: String,
    pub touch_signing: TouchPolicy,
    pub touch_encryption: TouchPolicy,
    pub nickname: String,
    /// None = don't write to disk.
    pub identities_dir: Option<PathBuf>,
}

impl Default for ProvisionConfig {
    fn default() -> Self {
        Self {
            pin: String::new(),
            touch_signing: TouchPolicy::Always,
            touch_encryption: TouchPolicy::Cached,
            nickname: String::new(),
            identities_dir: None,
        }
    }
}

pub fn provision_mock(
    session: &mut MockPivSession,
    config: &ProvisionConfig,
) -> Result<ProvisionResult, RatkeyError> {
    session.verify_pin(&config.pin)?;

    let ed25519_pub = session.generate_ed25519(SLOT_9A, config.touch_signing)?;
    let x25519_pub = session.generate_x25519(SLOT_9D, config.touch_encryption)?;

    // Reticulum identity hash: SHA-256(X25519_pub || Ed25519_pub) truncated to 16 bytes.
    let mut pub_key_bytes = [0u8; 64];
    pub_key_bytes[..32].copy_from_slice(&x25519_pub);
    pub_key_bytes[32..].copy_from_slice(&ed25519_pub);
    let identity_hash = truncated_hash(&pub_key_bytes);
    let identity_hash_hex = hex::encode(identity_hash);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let touch_signing_str = match config.touch_signing {
        TouchPolicy::Always => "always",
        TouchPolicy::Cached => "cached",
        TouchPolicy::Never => "never",
    };
    let touch_encryption_str = match config.touch_encryption {
        TouchPolicy::Always => "always",
        TouchPolicy::Cached => "cached",
        TouchPolicy::Never => "never",
    };

    let hwid = HwidConfig {
        identity: HwidIdentity {
            hash: identity_hash_hex.clone(),
            nickname: config.nickname.clone(),
            created_at: now,
        },
        device: HwidDevice {
            device_type: session.device_type.clone(),
            serial: session.serial,
            firmware: session.firmware.clone(),
        },
        keys: HwidKeys {
            ed25519_pub: hex::encode(ed25519_pub),
            x25519_pub: hex::encode(x25519_pub),
        },
        slots: HwidSlots {
            signing: "9A".to_string(),
            encryption: "9D".to_string(),
        },
        policy: HwidPolicy {
            pin_cache_timeout: 300,
            touch_signing: touch_signing_str.to_string(),
            touch_encryption: touch_encryption_str.to_string(),
        },
        attestation: HwidAttestation::default(),
        app: HwidApp::default(),
        backup: HwidBackup::default(),
    };

    let hwid_path = if let Some(ref dir) = config.identities_dir {
        let identity_dir = dir.join(&identity_hash_hex);
        std::fs::create_dir_all(&identity_dir)?;
        let path = identity_dir.join("identity.hwid");
        hwid.to_file(&path)?;
        Some(path)
    } else {
        None
    };

    Ok(ProvisionResult {
        config: hwid,
        ed25519_pub,
        x25519_pub,
        identity_hash,
        identity_hash_hex,
        hwid_path,
    })
}

/// First 16 bytes of `SHA-256(X25519_pub || Ed25519_pub)`. Matches `rns_identity::Identity::hash()`.
pub fn compute_identity_hash(ed25519_pub: &[u8; 32], x25519_pub: &[u8; 32]) -> [u8; 16] {
    let mut pub_key_bytes = [0u8; 64];
    pub_key_bytes[..32].copy_from_slice(x25519_pub);
    pub_key_bytes[32..].copy_from_slice(ed25519_pub);
    truncated_hash(&pub_key_bytes)
}

fn touch_byte(tp: TouchPolicy) -> u8 {
    match tp {
        TouchPolicy::Never => apdu::TOUCH_POLICY_NEVER,
        TouchPolicy::Always => apdu::TOUCH_POLICY_ALWAYS,
        TouchPolicy::Cached => apdu::TOUCH_POLICY_CACHED,
    }
}

fn touch_str(tp: TouchPolicy) -> &'static str {
    match tp {
        TouchPolicy::Never => "never",
        TouchPolicy::Always => "always",
        TouchPolicy::Cached => "cached",
    }
}

/// Recoverable provision / restore: derive the identity from `mnemonic`, import
/// both keys into the token (PIN-once + configured touch policy), and write the
/// `.hwid`. Requires the management key. The session must already be connected.
pub fn import_recoverable_identity<T: PivTransport>(
    session: &mut PivSession<T>,
    mgmt_key: &[u8],
    config: &ProvisionConfig,
    mnemonic: &str,
) -> Result<ProvisionResult, RatkeyError> {
    let derived = seed::derive_identity(mnemonic)?;
    session.authenticate_management_key(mgmt_key)?;
    session.import_ed25519(
        SLOT_9A,
        &derived.ed25519_seed,
        Some(apdu::PIN_POLICY_ONCE),
        Some(touch_byte(config.touch_signing)),
    )?;
    session.import_x25519(
        SLOT_9D,
        &derived.x25519_secret,
        Some(apdu::PIN_POLICY_ONCE),
        Some(touch_byte(config.touch_encryption)),
    )?;

    finalize_provision(session, config, derived.ed25519_pub, derived.x25519_pub)
}

/// On-device provisioning (no seed backup): authenticate, generate both keys on
/// the token, and write the `.hwid`. Requires the management key.
pub fn provision_hardware_only<T: PivTransport>(
    session: &mut PivSession<T>,
    mgmt_key: &[u8],
    config: &ProvisionConfig,
) -> Result<ProvisionResult, RatkeyError> {
    session.authenticate_management_key(mgmt_key)?;
    let ed_pub = session.generate_ed25519(
        SLOT_9A,
        Some(apdu::PIN_POLICY_ONCE),
        Some(touch_byte(config.touch_signing)),
    )?;
    let x_pub = session.generate_x25519(
        SLOT_9D,
        Some(apdu::PIN_POLICY_ONCE),
        Some(touch_byte(config.touch_encryption)),
    )?;
    finalize_provision(session, config, ed_pub, x_pub)
}

/// Register an already-provisioned token: read its slot public keys and write a
/// `.hwid` for it (import-existing). No key material is created; no mgmt key needed.
pub fn read_existing<T: PivTransport>(
    session: &mut PivSession<T>,
    config: &ProvisionConfig,
) -> Result<ProvisionResult, RatkeyError> {
    let ed_pub = session.read_public_key(SLOT_9A)?;
    let x_pub = session.read_public_key(SLOT_9D)?;
    finalize_provision(session, config, ed_pub, x_pub)
}

/// Build the `.hwid` from the provisioned public keys + device metadata, writing
/// it under `config.identities_dir` if set. Shared by all real-hardware flows.
fn finalize_provision<T: PivTransport>(
    session: &PivSession<T>,
    config: &ProvisionConfig,
    ed25519_pub: [u8; 32],
    x25519_pub: [u8; 32],
) -> Result<ProvisionResult, RatkeyError> {
    let identity_hash = compute_identity_hash(&ed25519_pub, &x25519_pub);
    let identity_hash_hex = hex::encode(identity_hash);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let hwid = HwidConfig {
        identity: HwidIdentity {
            hash: identity_hash_hex.clone(),
            nickname: config.nickname.clone(),
            created_at: now,
        },
        device: HwidDevice {
            device_type: session.device_type().as_str().to_string(),
            serial: session.serial().unwrap_or(0),
            firmware: session.firmware().unwrap_or("unknown").to_string(),
        },
        keys: HwidKeys {
            ed25519_pub: hex::encode(ed25519_pub),
            x25519_pub: hex::encode(x25519_pub),
        },
        slots: HwidSlots {
            signing: "9A".to_string(),
            encryption: "9D".to_string(),
        },
        policy: HwidPolicy {
            pin_cache_timeout: 300,
            touch_signing: touch_str(config.touch_signing).to_string(),
            touch_encryption: touch_str(config.touch_encryption).to_string(),
        },
        attestation: HwidAttestation::default(),
        app: HwidApp::default(),
        backup: HwidBackup::default(),
    };

    let hwid_path = if let Some(ref dir) = config.identities_dir {
        let identity_dir = dir.join(&identity_hash_hex);
        std::fs::create_dir_all(&identity_dir)?;
        let path = identity_dir.join("identity.hwid");
        hwid.to_file(&path)?;
        Some(path)
    } else {
        None
    };

    Ok(ProvisionResult {
        config: hwid,
        ed25519_pub,
        x25519_pub,
        identity_hash,
        identity_hash_hex,
        hwid_path,
    })
}

/// Recoverable provisioning: generate a fresh 24-word mnemonic, import the
/// derived identity, and return both the result and the mnemonic to show once.
pub fn provision_recoverable<T: PivTransport>(
    session: &mut PivSession<T>,
    mgmt_key: &[u8],
    config: &ProvisionConfig,
) -> Result<(ProvisionResult, String), RatkeyError> {
    let mnemonic = seed::generate_mnemonic()?;
    let result = import_recoverable_identity(session, mgmt_key, config, &mnemonic)?;
    Ok((result, mnemonic))
}

/// Restore a recoverable identity from an existing 24-word mnemonic onto a token.
pub fn restore<T: PivTransport>(
    session: &mut PivSession<T>,
    mgmt_key: &[u8],
    config: &ProvisionConfig,
    mnemonic: &str,
) -> Result<ProvisionResult, RatkeyError> {
    import_recoverable_identity(session, mgmt_key, config, mnemonic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provision_mock_basic() {
        let mut session = MockPivSession::new();
        let config = ProvisionConfig {
            pin: "123456".to_string(),
            touch_signing: TouchPolicy::Never,
            touch_encryption: TouchPolicy::Never,
            nickname: "test key".to_string(),
            identities_dir: None,
        };

        let result = provision_mock(&mut session, &config).unwrap();

        assert_eq!(result.ed25519_pub.len(), 32);
        assert_eq!(result.x25519_pub.len(), 32);
        assert_eq!(result.identity_hash.len(), 16);
        assert_eq!(result.identity_hash_hex.len(), 32);

        let recomputed = compute_identity_hash(&result.ed25519_pub, &result.x25519_pub);
        assert_eq!(result.identity_hash, recomputed);

        assert_eq!(result.config.identity.hash, result.identity_hash_hex);
        assert_eq!(result.config.identity.nickname, "test key");
        assert_eq!(result.config.device.device_type, "yubikey5");
        assert_eq!(result.config.slots.signing, "9A");
        assert_eq!(result.config.slots.encryption, "9D");

        assert!(result.hwid_path.is_none());
    }

    #[test]
    fn test_provision_writes_hwid_file() {
        let mut session = MockPivSession::new();
        let dir = std::env::temp_dir().join("ratkey_test_provision");
        let _ = std::fs::remove_dir_all(&dir);

        let config = ProvisionConfig {
            pin: "123456".to_string(),
            touch_signing: TouchPolicy::Always,
            touch_encryption: TouchPolicy::Cached,
            nickname: "my yubikey".to_string(),
            identities_dir: Some(dir.clone()),
        };

        let result = provision_mock(&mut session, &config).unwrap();

        let path = result.hwid_path.as_ref().unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("identity.hwid"));

        let loaded = HwidConfig::from_file(path).unwrap();
        assert_eq!(loaded.identity.hash, result.identity_hash_hex);
        assert_eq!(loaded.identity.nickname, "my yubikey");
        assert_eq!(loaded.policy.touch_signing, "always");
        assert_eq!(loaded.policy.touch_encryption, "cached");

        let loaded_ed = loaded.ed25519_pub_bytes().unwrap();
        let loaded_x = loaded.x25519_pub_bytes().unwrap();
        assert_eq!(loaded_ed, result.ed25519_pub);
        assert_eq!(loaded_x, result.x25519_pub);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_provision_and_use_identity() {
        let mut session = MockPivSession::new();
        session.set_pin("mypin1");
        let dir = std::env::temp_dir().join("ratkey_test_provision_use");
        let _ = std::fs::remove_dir_all(&dir);

        let config = ProvisionConfig {
            pin: "mypin1".to_string(),
            touch_signing: TouchPolicy::Never,
            touch_encryption: TouchPolicy::Never,
            nickname: "round-trip test".to_string(),
            identities_dir: Some(dir.clone()),
        };

        let result = provision_mock(&mut session, &config).unwrap();

        let path = result.hwid_path.as_ref().unwrap();
        let mut hw = crate::HardwareIdentity::from_file(path, Box::new(session)).unwrap();

        let message = b"provisioned and loaded";
        let sig = hw.sign(message).unwrap();
        assert!(hw.verify(message, &sig));

        assert_eq!(hw.hash(), &result.identity_hash);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_provision_wrong_pin() {
        let mut session = MockPivSession::new();
        let config = ProvisionConfig {
            pin: "wrong_pin".to_string(),
            ..Default::default()
        };

        let err = provision_mock(&mut session, &config).unwrap_err();
        assert!(matches!(err, RatkeyError::PinFailed { .. }));
    }

    #[test]
    fn test_provision_deterministic_hash() {
        let ed = [0xAA; 32];
        let x = [0xBB; 32];
        let hash1 = compute_identity_hash(&ed, &x);
        let hash2 = compute_identity_hash(&ed, &x);
        assert_eq!(hash1, hash2);

        let hash3 = compute_identity_hash(&[0xCC; 32], &x);
        assert_ne!(hash1, hash3);
    }
}
