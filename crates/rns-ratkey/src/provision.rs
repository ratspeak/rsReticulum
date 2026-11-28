//! Provision fixed slots 9A (Ed25519) and 9D (X25519), then optionally write
//! public `.hwid` metadata. Choose on-device generation or mnemonic-derived
//! key import explicitly.
//!
//! Real-card generation/import can replace existing slot keys. These steps
//! are sequential, with no empty-slot guard or rollback: an error can leave
//! one slot changed, and a later file-write failure does not undo card changes.
//! The caller owns consent, credential handling and recovery of partial work.
//! Once both slots are written, provisioning replaces the management key with a
//! random one it discards, so nothing can overwrite the slots again short of a
//! PIV reset (PIN and PUK blocked; no management key needed). It does not change
//! the card PIN or PUK, or verify attestation. `config.pin` is used only by
//! `provision_mock`.

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
    /// PIN used by `provision_mock`. Real provisioning helpers do not read this
    /// field or verify/change the card PIN. This ordinary `String` is not
    /// automatically wiped; the caller owns its lifetime and input validation.
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

/// Derive private keys from `mnemonic` on the host and import them into
/// 9A/9D with PIN-once and the requested touch policies. Requires a connected
/// session and valid management key, which is then rotated away. Writes
/// `.hwid` only when a directory is configured. Existing keys can be replaced,
/// and partial failure is not rolled back; see the module's provisioning
/// boundary.
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
    session.rotate_management_key()?;

    finalize_provision(session, config, derived.ed25519_pub, derived.x25519_pub)
}

/// Authenticate with the management key, generate new 9A/9D keys on the
/// token without a seed backup, then rotate the management key away. Write
/// `.hwid` only when configured. This can replace existing keys and has no
/// rollback after partial failure.
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
    session.rotate_management_key()?;
    finalize_provision(session, config, ed_pub, x_pub)
}

/// Read fixed 9A/9D public keys and optionally write `.hwid`; no keys are
/// created and no management key is required. The recorded touch policies
/// come from `config`, not a readback of the token's actual policy.
/// This requires the token's public-key metadata extension.
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

/// Generate a 12-word mnemonic and import its derived identity using
/// [`import_recoverable_identity`]. The returned phrase is an ordinary
/// `String`; the caller controls its display, backup and eventual wiping.
pub fn provision_recoverable<T: PivTransport>(
    session: &mut PivSession<T>,
    mgmt_key: &[u8],
    config: &ProvisionConfig,
) -> Result<(ProvisionResult, String), RatkeyError> {
    let mnemonic = seed::generate_mnemonic()?;
    let result = import_recoverable_identity(session, mgmt_key, config, &mnemonic)?;
    Ok((result, mnemonic))
}

/// Restore a recoverable identity from an existing 12-word mnemonic onto a token.
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

    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::detect::DeviceType;
    use crate::session::DeviceMeta;

    const FACTORY_MGMT_KEY: [u8; 24] = [
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ];
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    struct Card {
        alg: u8,
        key: Vec<u8>,
        authenticated: bool,
        writes: Vec<u8>,
    }

    /// The card side of management auth, slot writes and SET MANAGEMENT KEY.
    struct CardTransport(Rc<RefCell<Card>>);

    fn ok(mut data: Vec<u8>) -> Result<Vec<u8>, RatkeyError> {
        data.extend_from_slice(&[0x90, 0x00]);
        Ok(data)
    }

    fn wrap_7c(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x7C, (payload.len() + 2) as u8, tag, payload.len() as u8];
        v.extend_from_slice(payload);
        v
    }

    impl PivTransport for CardTransport {
        fn transmit(&mut self, cmd: &[u8]) -> Result<Vec<u8>, RatkeyError> {
            const WITNESS: [u8; 16] = [0x77; 16];
            let mut card = self.0.borrow_mut();
            let (ins, p2, data) = (cmd[1], cmd[3], cmd.get(5..).unwrap_or(&[]));
            let denied = Ok(vec![0x69, 0x82]);
            match ins {
                apdu::INS_GET_METADATA if p2 == apdu::SLOT_CARD_MANAGEMENT => {
                    ok(vec![0x01, 0x01, card.alg])
                }
                apdu::INS_GENERAL_AUTHENTICATE => {
                    let witness = apdu::parse_auth_witness(data).unwrap();
                    if witness.is_empty() {
                        let enc = crate::mgmt::ecb_encrypt(card.alg, &card.key, &WITNESS).unwrap();
                        ok(wrap_7c(0x80, &enc))
                    } else if witness == WITNESS {
                        card.authenticated = true;
                        let challenge = &data[data.len() - 16..];
                        let enc = crate::mgmt::ecb_encrypt(card.alg, &card.key, challenge).unwrap();
                        ok(wrap_7c(0x82, &enc))
                    } else {
                        denied
                    }
                }
                apdu::INS_GENERATE_ASYMMETRIC
                | apdu::INS_IMPORT_KEY
                | apdu::INS_SET_MANAGEMENT_KEY
                    if !card.authenticated =>
                {
                    denied
                }
                apdu::INS_GENERATE_ASYMMETRIC => {
                    card.writes.push(ins);
                    let mut resp = vec![0x7F, 0x49, 0x22, 0x86, 0x20];
                    resp.extend_from_slice(&[p2; 32]);
                    ok(resp)
                }
                apdu::INS_IMPORT_KEY => {
                    card.writes.push(ins);
                    ok(Vec::new())
                }
                apdu::INS_SET_MANAGEMENT_KEY => {
                    card.writes.push(ins);
                    assert_eq!(&data[..2], &[card.alg, apdu::SLOT_CARD_MANAGEMENT]);
                    card.key = data[3..3 + data[2] as usize].to_vec();
                    ok(Vec::new())
                }
                _ => panic!("unexpected apdu ins=0x{ins:02X}"),
            }
        }

        fn is_connected(&self) -> bool {
            true
        }
    }

    fn factory_card() -> (Rc<RefCell<Card>>, PivSession<CardTransport>) {
        let card = Rc::new(RefCell::new(Card {
            alg: apdu::MGMT_ALG_AES192,
            key: FACTORY_MGMT_KEY.to_vec(),
            authenticated: false,
            writes: Vec::new(),
        }));
        let meta = DeviceMeta {
            device_type: DeviceType::YubiKey5,
            serial: Some(1),
            firmware: Some("5.7.4".to_string()),
        };
        (Rc::clone(&card), PivSession::new(CardTransport(card), meta))
    }

    #[test]
    fn provisioning_leaves_no_known_management_key() {
        type Flow = fn(&mut PivSession<CardTransport>, &ProvisionConfig) -> Result<(), RatkeyError>;
        let flows: [(&str, Flow); 3] = [
            ("hardware only", |s, c| {
                provision_hardware_only(s, &FACTORY_MGMT_KEY, c).map(drop)
            }),
            ("recoverable", |s, c| {
                provision_recoverable(s, &FACTORY_MGMT_KEY, c).map(drop)
            }),
            ("restore", |s, c| {
                restore(s, &FACTORY_MGMT_KEY, c, TEST_MNEMONIC).map(drop)
            }),
        ];
        for (name, flow) in flows {
            let (card, mut session) = factory_card();
            flow(&mut session, &ProvisionConfig::default()).unwrap();

            let card_state = card.borrow();
            assert_eq!(card_state.key.len(), 24, "{name}");
            assert_ne!(card_state.key, FACTORY_MGMT_KEY, "{name}");
            // Rotated once, after both slots were written.
            assert_eq!(card_state.writes.len(), 3, "{name}");
            assert_eq!(card_state.writes[2], apdu::INS_SET_MANAGEMENT_KEY, "{name}");
            drop(card_state);

            card.borrow_mut().authenticated = false;
            assert!(
                matches!(
                    session.authenticate_management_key(&FACTORY_MGMT_KEY),
                    Err(RatkeyError::ManagementAuthFailed)
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn rotating_needs_management_auth() {
        let (card, mut session) = factory_card();
        assert!(session.rotate_management_key().is_err());
        assert_eq!(card.borrow().key, FACTORY_MGMT_KEY);
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
