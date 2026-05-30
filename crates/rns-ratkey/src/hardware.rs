//! `HardwareIdentity`: a public-key-only `Identity` whose private ops are served
//! by an `IdentityBackend` (real PIV session or mock). Wire-compatible with
//! software identities.

use std::path::Path;

use rns_crypto::hkdf::derive_key_64;
use rns_crypto::token;
use rns_identity::identity::Identity;

use crate::apdu::{SLOT_AUTHENTICATION as SLOT_9A, SLOT_KEY_MANAGEMENT as SLOT_9D};
use crate::error::RatkeyError;
use crate::hwid::HwidConfig;
use crate::mock::MockPivSession;
use crate::session::PivSession;
use crate::transport::PivTransport;

/// The private-key operations `HardwareIdentity` needs from a token. Implemented
/// by `PivSession<T>` (any transport) and `MockPivSession`, so the runtime
/// identity is backend-agnostic.
pub trait IdentityBackend {
    fn sign_ed25519(&mut self, slot: u8, message: &[u8]) -> Result<[u8; 64], RatkeyError>;
    fn ecdh_x25519(&mut self, slot: u8, peer_pub: &[u8; 32]) -> Result<[u8; 32], RatkeyError>;
    fn read_ed25519_public(&mut self, slot: u8) -> Result<[u8; 32], RatkeyError>;
    fn read_x25519_public(&mut self, slot: u8) -> Result<[u8; 32], RatkeyError>;
    fn is_connected(&self) -> bool;
    /// Re-lock the session (require PIN again on the next op).
    fn lock(&mut self) -> Result<(), RatkeyError>;
}

// Inherent methods take precedence over trait methods, so these delegate without recursing.
impl<T: PivTransport> IdentityBackend for PivSession<T> {
    fn sign_ed25519(&mut self, slot: u8, message: &[u8]) -> Result<[u8; 64], RatkeyError> {
        self.sign_ed25519(slot, message)
    }
    fn ecdh_x25519(&mut self, slot: u8, peer_pub: &[u8; 32]) -> Result<[u8; 32], RatkeyError> {
        self.ecdh_x25519(slot, peer_pub)
    }
    fn read_ed25519_public(&mut self, slot: u8) -> Result<[u8; 32], RatkeyError> {
        self.read_public_key(slot)
    }
    fn read_x25519_public(&mut self, slot: u8) -> Result<[u8; 32], RatkeyError> {
        self.read_public_key(slot)
    }
    fn is_connected(&self) -> bool {
        self.is_connected()
    }
    fn lock(&mut self) -> Result<(), RatkeyError> {
        self.lock()
    }
}

impl IdentityBackend for MockPivSession {
    fn sign_ed25519(&mut self, slot: u8, message: &[u8]) -> Result<[u8; 64], RatkeyError> {
        self.sign_ed25519(slot, message)
    }
    fn ecdh_x25519(&mut self, slot: u8, peer_pub: &[u8; 32]) -> Result<[u8; 32], RatkeyError> {
        self.ecdh_x25519(slot, peer_pub)
    }
    fn read_ed25519_public(&mut self, slot: u8) -> Result<[u8; 32], RatkeyError> {
        MockPivSession::read_ed25519_public(self, slot)
    }
    fn read_x25519_public(&mut self, slot: u8) -> Result<[u8; 32], RatkeyError> {
        MockPivSession::read_x25519_public(self, slot)
    }
    fn is_connected(&self) -> bool {
        self.is_connected()
    }
    fn lock(&mut self) -> Result<(), RatkeyError> {
        self.lock();
        Ok(())
    }
}

pub struct HardwareIdentity {
    pub identity: Identity,
    pub config: HwidConfig,
    ed25519_pub: [u8; 32],
    x25519_pub: [u8; 32],
    backend: Box<dyn IdentityBackend>,
}

impl HardwareIdentity {
    /// Build from a `.hwid` config + a backend. Fail-closed: the device's slot
    /// public keys must match the published identity.
    pub fn from_hwid(
        config: HwidConfig,
        mut backend: Box<dyn IdentityBackend>,
    ) -> Result<Self, RatkeyError> {
        let ed25519_pub = config.ed25519_pub_bytes()?;
        let x25519_pub = config.x25519_pub_bytes()?;

        let session_ed = backend.read_ed25519_public(SLOT_9A)?;
        let session_x = backend.read_x25519_public(SLOT_9D)?;
        if session_ed != ed25519_pub || session_x != x25519_pub {
            return Err(RatkeyError::KeyMismatch);
        }

        let identity = build_identity(&ed25519_pub, &x25519_pub)?;
        Ok(Self {
            identity,
            config,
            ed25519_pub,
            x25519_pub,
            backend,
        })
    }

    pub fn from_file(path: &Path, backend: Box<dyn IdentityBackend>) -> Result<Self, RatkeyError> {
        let config = HwidConfig::from_file(path)?;
        Self::from_hwid(config, backend)
    }

    /// Test / first-bring-up: build without a `.hwid` and skip the key-mismatch
    /// guard, so sign/ECDH can be validated independently of metadata pubkey
    /// readback.
    pub fn from_keys(
        ed25519_pub: [u8; 32],
        x25519_pub: [u8; 32],
        backend: Box<dyn IdentityBackend>,
    ) -> Result<Self, RatkeyError> {
        let identity = build_identity(&ed25519_pub, &x25519_pub)?;
        let config = HwidConfig {
            identity: crate::hwid::HwidIdentity {
                hash: hex::encode(identity.hash),
                nickname: "test".to_string(),
                created_at: 0,
            },
            device: crate::hwid::HwidDevice {
                device_type: "unknown".to_string(),
                serial: 0,
                firmware: "unknown".to_string(),
            },
            keys: crate::hwid::HwidKeys {
                ed25519_pub: hex::encode(ed25519_pub),
                x25519_pub: hex::encode(x25519_pub),
            },
            slots: crate::hwid::HwidSlots {
                signing: "9A".to_string(),
                encryption: "9D".to_string(),
            },
            policy: crate::hwid::HwidPolicy {
                pin_cache_timeout: 300,
                touch_signing: "never".to_string(),
                touch_encryption: "never".to_string(),
            },
            attestation: Default::default(),
            app: Default::default(),
            backup: Default::default(),
        };

        Ok(Self {
            identity,
            config,
            ed25519_pub,
            x25519_pub,
            backend,
        })
    }

    pub fn hash(&self) -> &[u8; 16] {
        &self.identity.hash
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(self.identity.hash)
    }

    /// 64-byte public key (X25519_pub || Ed25519_pub).
    pub fn get_public_key(&self) -> [u8; 64] {
        self.identity.get_public_key()
    }

    pub fn ed25519_public(&self) -> &[u8; 32] {
        &self.ed25519_pub
    }

    pub fn x25519_public(&self) -> &[u8; 32] {
        &self.x25519_pub
    }

    pub fn as_identity(&self) -> &Identity {
        &self.identity
    }

    pub fn sign(&mut self, message: &[u8]) -> Result<[u8; 64], RatkeyError> {
        self.backend.sign_ed25519(SLOT_9A, message)
    }

    pub fn ecdh(&mut self, peer_pub_bytes: &[u8; 32]) -> Result<[u8; 32], RatkeyError> {
        self.backend.ecdh_x25519(SLOT_9D, peer_pub_bytes)
    }

    /// Ciphertext = ephemeral_pub(32) || AES-256-CBC token. Mirrors `Identity::decrypt`
    /// but does the ECDH on-device.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        ratchets: Option<&[&[u8; 32]]>,
        enforce_ratchets: bool,
    ) -> Result<Vec<u8>, RatkeyError> {
        if ciphertext.len() <= 32 {
            return Err(RatkeyError::EcdhFailed("ciphertext too short".to_string()));
        }

        let ephemeral_pub_bytes: [u8; 32] = ciphertext[..32]
            .try_into()
            .map_err(|_| RatkeyError::EcdhFailed("invalid ephemeral key".to_string()))?;
        let encrypted_token = &ciphertext[32..];

        // PIV cannot store Reticulum ratchet private keys. This backend skips
        // ratchet keys and falls back to identity ECDH; enforced ratchets fail
        // closed.
        if let Some(ratchet_keys) = ratchets {
            for _ratchet_pub in ratchet_keys {}
            if enforce_ratchets {
                return Err(RatkeyError::EcdhFailed(
                    "no valid ratchet key found and ratchets enforced".to_string(),
                ));
            }
        }

        let shared_secret = self.ecdh(&ephemeral_pub_bytes)?;

        // HKDF-SHA256, salt = identity hash. Matches Identity::decrypt.
        let derived = derive_key_64(&shared_secret, &self.identity.hash)
            .map_err(|_| RatkeyError::EcdhFailed("HKDF derivation failed".to_string()))?;

        token::decrypt(encrypted_token, &derived)
            .map_err(|_| RatkeyError::EcdhFailed("decryption failed".to_string()))
    }

    /// Verification is a public-key op; no hardware call.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.identity.verify(message, signature)
    }

    pub fn is_connected(&self) -> bool {
        self.backend.is_connected()
    }

    /// Re-lock the session; the next sign/ECDH will require the PIN again.
    /// The app calls this on its session timeout and on quit.
    pub fn lock(&mut self) -> Result<(), RatkeyError> {
        self.backend.lock()
    }
}

fn build_identity(ed25519_pub: &[u8; 32], x25519_pub: &[u8; 32]) -> Result<Identity, RatkeyError> {
    let mut pub_key_bytes = [0u8; 64];
    pub_key_bytes[..32].copy_from_slice(x25519_pub);
    pub_key_bytes[32..].copy_from_slice(ed25519_pub);
    Identity::from_public_key(&pub_key_bytes)
        .map_err(|e| RatkeyError::InvalidHwid(format!("cannot create identity: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{SLOT_9A as MOCK_9A, SLOT_9D as MOCK_9D};
    use rns_crypto::x25519::{X25519PrivateKey, X25519PublicKey};
    use rns_identity::identity::Identity;

    #[test]
    fn test_from_keys() {
        let session = MockPivSession::with_keys();
        let ed_pub = session.read_ed25519_public(MOCK_9A).unwrap();
        let x_pub = session.read_x25519_public(MOCK_9D).unwrap();

        let hw = HardwareIdentity::from_keys(ed_pub, x_pub, Box::new(session)).unwrap();
        assert_eq!(hw.ed25519_public(), &ed_pub);
        assert_eq!(hw.x25519_public(), &x_pub);
        assert!(!hw.hash_hex().is_empty());
    }

    #[test]
    fn test_sign_and_verify() {
        let session = MockPivSession::with_keys();
        let ed_pub = session.read_ed25519_public(MOCK_9A).unwrap();
        let x_pub = session.read_x25519_public(MOCK_9D).unwrap();
        let mut hw = HardwareIdentity::from_keys(ed_pub, x_pub, Box::new(session)).unwrap();

        let message = b"ratkey hardware identity test";
        let sig = hw.sign(message).unwrap();
        assert!(hw.verify(message, &sig));
    }

    #[test]
    fn test_sign_matches_software_identity() {
        // Load-bearing: Ed25519 is deterministic, hardware and software paths
        // MUST be byte-identical for shared key material.
        let ed_seed = [0x42u8; 32];
        let x_secret = [0x43u8; 32];
        let session = MockPivSession::with_key_bytes(&ed_seed, &x_secret);
        let ed_pub = session.read_ed25519_public(MOCK_9A).unwrap();
        let x_pub = session.read_x25519_public(MOCK_9D).unwrap();
        let mut hw = HardwareIdentity::from_keys(ed_pub, x_pub, Box::new(session)).unwrap();

        let mut prv_bytes = [0u8; 64];
        prv_bytes[..32].copy_from_slice(&x_secret);
        prv_bytes[32..].copy_from_slice(&ed_seed);
        let sw_identity = Identity::from_private_key(&prv_bytes).unwrap();

        let message = b"cross-validation test";

        let hw_sig = hw.sign(message).unwrap();
        let sw_sig = sw_identity.sign(message).unwrap();

        assert_eq!(
            hw_sig, sw_sig,
            "hardware and software signatures must match"
        );
        assert_eq!(hw.identity.hash, sw_identity.hash);
        assert_eq!(hw.get_public_key(), sw_identity.get_public_key());
    }

    #[test]
    fn test_ecdh_with_software_peer() {
        let session = MockPivSession::with_keys();
        let ed_pub = session.read_ed25519_public(MOCK_9A).unwrap();
        let x_pub = session.read_x25519_public(MOCK_9D).unwrap();
        let mut hw = HardwareIdentity::from_keys(ed_pub, x_pub, Box::new(session)).unwrap();

        let peer_prv = X25519PrivateKey::generate();
        let peer_pub = peer_prv.public_key();
        let peer_pub_bytes = peer_pub.to_bytes();

        let hw_shared = hw.ecdh(&peer_pub_bytes).unwrap();

        let hw_pub = X25519PublicKey::from_bytes(&x_pub);
        let sw_shared = peer_prv.exchange(&hw_pub);

        assert_eq!(hw_shared, sw_shared, "ECDH must be symmetric");
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let ed_seed = [0x42u8; 32];
        let x_secret = [0x43u8; 32];
        let session = MockPivSession::with_key_bytes(&ed_seed, &x_secret);
        let ed_pub = session.read_ed25519_public(MOCK_9A).unwrap();
        let x_pub = session.read_x25519_public(MOCK_9D).unwrap();
        let mut hw = HardwareIdentity::from_keys(ed_pub, x_pub, Box::new(session)).unwrap();

        let mut prv_bytes = [0u8; 64];
        prv_bytes[..32].copy_from_slice(&x_secret);
        prv_bytes[32..].copy_from_slice(&ed_seed);
        let sw_identity = Identity::from_private_key(&prv_bytes).unwrap();

        let plaintext = b"secret message for hardware identity";
        let ciphertext = sw_identity.encrypt(plaintext, None).unwrap();

        let decrypted = hw.decrypt(&ciphertext, None, false).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_from_other_identity() {
        let session = MockPivSession::with_keys();
        let ed_pub = session.read_ed25519_public(MOCK_9A).unwrap();
        let x_pub = session.read_x25519_public(MOCK_9D).unwrap();
        let mut hw = HardwareIdentity::from_keys(ed_pub, x_pub, Box::new(session)).unwrap();

        let _sender = Identity::new();

        let ciphertext = hw.identity.encrypt(b"hello from sender", None).unwrap();

        let decrypted = hw.decrypt(&ciphertext, None, false).unwrap();
        assert_eq!(decrypted, b"hello from sender");
    }

    #[test]
    fn test_disconnect_fails_operations() {
        let mut session = MockPivSession::with_keys();
        let ed_pub = session.read_ed25519_public(MOCK_9A).unwrap();
        let x_pub = session.read_x25519_public(MOCK_9D).unwrap();
        session.disconnect();

        let mut hw = HardwareIdentity::from_keys(ed_pub, x_pub, Box::new(session)).unwrap();
        assert!(!hw.is_connected());
        assert!(matches!(hw.sign(b"test"), Err(RatkeyError::Disconnected)));
    }

    #[test]
    fn test_hwid_key_mismatch() {
        let session = MockPivSession::with_keys();
        let config = HwidConfig {
            identity: crate::hwid::HwidIdentity {
                hash: "test".to_string(),
                nickname: "test".to_string(),
                created_at: 0,
            },
            device: crate::hwid::HwidDevice {
                device_type: "yubikey5".to_string(),
                serial: 99999999,
                firmware: "5.7.1".to_string(),
            },
            keys: crate::hwid::HwidKeys {
                ed25519_pub: "ff".repeat(32),
                x25519_pub: "ff".repeat(32),
            },
            slots: crate::hwid::HwidSlots {
                signing: "9A".to_string(),
                encryption: "9D".to_string(),
            },
            policy: crate::hwid::HwidPolicy {
                pin_cache_timeout: 300,
                touch_signing: "never".to_string(),
                touch_encryption: "never".to_string(),
            },
            attestation: Default::default(),
            app: Default::default(),
            backup: Default::default(),
        };

        let result = HardwareIdentity::from_hwid(config, Box::new(session));
        assert!(matches!(result, Err(RatkeyError::KeyMismatch)));
    }

    // --- Real backend path over a canned-APDU transport ---------------------
    // MockPivSession implements IdentityBackend directly and never touches
    // PivSession. These exercise the production path (PivSession ops + its
    // IdentityBackend impl + read_public_key→parse + slot routing) without a
    // device. Caveat: the fake uses the *assumed* metadata layout, so it
    // validates glue, not the real byte layout — that stays hardware-only.

    use crate::detect::DeviceType;
    use crate::session::DeviceMeta;
    use crate::transport::PivTransport;

    struct FakeTransport {
        ed_pub: [u8; 32],
        x_pub: [u8; 32],
        sig: [u8; 64],
        secret: [u8; 32],
    }

    impl FakeTransport {
        fn metadata(key: &[u8; 32]) -> Vec<u8> {
            // 01(algo) 04(pubkey = 86 20 <32>) + SW 90 00
            let mut v = vec![0x01, 0x01, 0xE0, 0x04, 0x22, 0x86, 0x20];
            v.extend_from_slice(key);
            v.extend_from_slice(&[0x90, 0x00]);
            v
        }
    }

    impl PivTransport for FakeTransport {
        fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, RatkeyError> {
            let (ins, p1, p2) = (apdu[1], apdu[2], apdu[3]);
            match ins {
                0xA4 => Ok(vec![0x90, 0x00]), // SELECT (applet / re-lock)
                0x20 => Ok(vec![0x90, 0x00]), // VERIFY PIN
                0x87 if p1 == 0xE0 => {
                    assert_eq!(p2, 0x9A, "sign must target slot 9A");
                    let mut v = vec![0x7C, 0x42, 0x82, 0x40];
                    v.extend_from_slice(&self.sig);
                    v.extend_from_slice(&[0x90, 0x00]);
                    Ok(v)
                }
                0x87 if p1 == 0xE1 => {
                    assert_eq!(p2, 0x9D, "ECDH must target slot 9D");
                    let mut v = vec![0x7C, 0x22, 0x82, 0x20];
                    v.extend_from_slice(&self.secret);
                    v.extend_from_slice(&[0x90, 0x00]);
                    Ok(v)
                }
                0xF7 => {
                    // GET METADATA: key keyed by requested slot, so a wrong-slot
                    // read returns the wrong key.
                    let key = match p2 {
                        0x9A => &self.ed_pub,
                        0x9D => &self.x_pub,
                        other => panic!("unexpected metadata slot 0x{other:02X}"),
                    };
                    Ok(Self::metadata(key))
                }
                other => panic!("unexpected INS 0x{other:02X}"),
            }
        }
        fn is_connected(&self) -> bool {
            true
        }
    }

    fn fake_meta() -> DeviceMeta {
        DeviceMeta {
            device_type: DeviceType::YubiKey5,
            serial: Some(1),
            firmware: Some("5.7.4".to_string()),
        }
    }

    #[test]
    fn test_pivsession_ops_over_fake_transport() {
        let ed_pub = [0x11u8; 32];
        let x_pub = [0x22u8; 32];
        let sig = [0x33u8; 64];
        let secret = [0x44u8; 32];
        let fake = FakeTransport {
            ed_pub,
            x_pub,
            sig,
            secret,
        };
        let mut session = PivSession::new(fake, fake_meta());

        assert_eq!(session.sign_ed25519(SLOT_9A, b"msg").unwrap(), sig);
        assert_eq!(session.ecdh_x25519(SLOT_9D, &[0u8; 32]).unwrap(), secret);
        // read_public_key routes the slot and runs the metadata parser.
        assert_eq!(session.read_public_key(SLOT_9A).unwrap(), ed_pub);
        assert_eq!(session.read_public_key(SLOT_9D).unwrap(), x_pub);
        // lock() re-selects the applet (SELECT APDU) without error.
        session.lock().unwrap();
    }

    #[test]
    fn test_lock_requires_pin_again() {
        // End-to-end session lock on the mock path: sign works, lock, then the
        // next op needs the PIN again.
        let session = MockPivSession::with_keys();
        let ed_pub = session.read_ed25519_public(MOCK_9A).unwrap();
        let x_pub = session.read_x25519_public(MOCK_9D).unwrap();
        let mut hw = HardwareIdentity::from_keys(ed_pub, x_pub, Box::new(session)).unwrap();

        assert!(hw.sign(b"m").is_ok());
        hw.lock().unwrap();
        assert!(matches!(hw.sign(b"m"), Err(RatkeyError::PinRequired)));
    }

    #[test]
    fn test_hardware_identity_from_hwid_over_real_backend() {
        // Closest mock-free representation of the runtime path: HardwareIdentity
        // over a real PivSession backend — guard reads pubkeys via metadata, then
        // sign dispatches to slot 9A.
        let ed_prv = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&[0x42u8; 32]);
        let ed_pub = ed_prv.public_key().to_bytes();
        let x_prv = X25519PrivateKey::from_bytes(&[0x43u8; 32]);
        let x_pub = x_prv.public_key().to_bytes();
        let sig = [0x33u8; 64];

        let fake = FakeTransport {
            ed_pub,
            x_pub,
            sig,
            secret: [0x44u8; 32],
        };
        let session = PivSession::new(fake, fake_meta());

        let config = HwidConfig {
            identity: crate::hwid::HwidIdentity {
                hash: "test".to_string(),
                nickname: "fake".to_string(),
                created_at: 0,
            },
            device: crate::hwid::HwidDevice {
                device_type: "yubikey5".to_string(),
                serial: 1,
                firmware: "5.7.4".to_string(),
            },
            keys: crate::hwid::HwidKeys {
                ed25519_pub: hex::encode(ed_pub),
                x25519_pub: hex::encode(x_pub),
            },
            slots: crate::hwid::HwidSlots {
                signing: "9A".to_string(),
                encryption: "9D".to_string(),
            },
            policy: crate::hwid::HwidPolicy {
                pin_cache_timeout: 300,
                touch_signing: "always".to_string(),
                touch_encryption: "cached".to_string(),
            },
            attestation: Default::default(),
            app: Default::default(),
            backup: Default::default(),
        };

        let mut hw = HardwareIdentity::from_hwid(config, Box::new(session)).unwrap();
        assert_eq!(hw.sign(b"announce").unwrap(), sig);
    }

    // --- Management-key auth over a card-simulating transport ----------------
    // Plays the card side of witness/challenge so the protocol direction (host
    // must DECRYPT the witness, not encrypt it) is exercised without hardware.
    struct MgmtFakeTransport {
        alg: u8,
        key: Vec<u8>,
        witness: [u8; 16],
    }

    fn wrap_7c(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x7C, (payload.len() + 2) as u8, tag, payload.len() as u8];
        v.extend_from_slice(payload);
        v.extend_from_slice(&[0x90, 0x00]); // SW OK
        v
    }

    impl PivTransport for MgmtFakeTransport {
        fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, RatkeyError> {
            let (ins, p2) = (apdu[1], apdu[3]);
            match (ins, p2) {
                (0xF7, 0x9B) => Ok(vec![0x01, 0x01, self.alg, 0x90, 0x00]), // metadata: alg
                (0x87, 0x9B) => {
                    let data = &apdu[5..];
                    let witness_field = crate::apdu::parse_auth_witness(data).unwrap();
                    if witness_field.is_empty() {
                        // witness request → return the witness encrypted with the key
                        let enc =
                            crate::mgmt::ecb_encrypt(self.alg, &self.key, &self.witness).unwrap();
                        Ok(wrap_7c(0x80, &enc))
                    } else if witness_field.as_slice() == self.witness {
                        // correct decrypted witness → encrypt the host's challenge
                        let challenge = &data[data.len() - 16..];
                        let enc = crate::mgmt::ecb_encrypt(self.alg, &self.key, challenge).unwrap();
                        Ok(wrap_7c(0x82, &enc))
                    } else {
                        // wrong witness → card rejects (security status not satisfied)
                        Ok(vec![0x69, 0x82])
                    }
                }
                _ => panic!("unexpected mgmt apdu ins=0x{ins:02X} p2=0x{p2:02X}"),
            }
        }
        fn is_connected(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_authenticate_management_key_success() {
        let key = vec![0x5Au8; 24]; // AES-192
        let fake = MgmtFakeTransport {
            alg: crate::apdu::MGMT_ALG_AES192,
            key: key.clone(),
            witness: [0x77; 16],
        };
        let mut session = PivSession::new(fake, fake_meta());
        session.authenticate_management_key(&key).unwrap();
    }

    #[test]
    fn test_authenticate_management_key_wrong_key() {
        // Host's wrong key → decrypted witness mismatches → card rejects → mapped error.
        let fake = MgmtFakeTransport {
            alg: crate::apdu::MGMT_ALG_AES192,
            key: vec![0x5Au8; 24],
            witness: [0x77; 16],
        };
        let mut session = PivSession::new(fake, fake_meta());
        let wrong = vec![0x00u8; 24];
        assert!(matches!(
            session.authenticate_management_key(&wrong),
            Err(RatkeyError::ManagementAuthFailed)
        ));
    }
}
