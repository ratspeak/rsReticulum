//! In-memory PIV mock with real Ed25519/X25519 crypto; signatures/ECDH are bit-identical
//! to software results for test vector reuse. Simulates PIN retry/lockout, touch policy,
//! disconnect, slot state. Primary dev/validation env until hardware lands.

use std::collections::HashMap;

use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_crypto::x25519::{X25519PrivateKey, X25519PublicKey};
use zeroize::Zeroize;

use crate::error::RatkeyError;

/// Slot 9A: PIV Authentication — Ed25519 signing.
pub const SLOT_9A: u8 = 0x9A;
/// Slot 9D: PIV Key Management — X25519 ECDH.
pub const SLOT_9D: u8 = 0x9D;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPolicy {
    Never,
    Always,
    /// YubiKey ~15s cache.
    Cached,
}

struct SlotState {
    ed25519_prv: Option<Ed25519PrivateKey>,
    ed25519_pub: Option<Ed25519PublicKey>,
    x25519_prv: Option<X25519PrivateKey>,
    x25519_pub: Option<X25519PublicKey>,
    touch_policy: TouchPolicy,
}

impl SlotState {
    fn empty() -> Self {
        Self {
            ed25519_prv: None,
            ed25519_pub: None,
            x25519_prv: None,
            x25519_pub: None,
            touch_policy: TouchPolicy::Never,
        }
    }
}

#[derive(Debug, Clone)]
pub enum MockOperation {
    PinVerify { success: bool },
    PinUnblock { success: bool },
    ResetPiv { success: bool },
    GenerateEd25519 { slot: u8 },
    GenerateX25519 { slot: u8 },
    SignEd25519 { slot: u8, data_len: usize },
    EcdhX25519 { slot: u8 },
    ReadPublicKey { slot: u8 },
}

pub struct MockPivSession {
    slots: HashMap<u8, SlotState>,
    pin: String,
    puk: String,
    pin_verified: bool,
    pin_retries: u8,
    puk_retries: u8,
    max_retries: u8,
    connected: bool,
    /// True: `TouchPolicy::Always` slots reject ops. `simulate_touch()` clears.
    touch_required: bool,
    pub device_type: String,
    pub serial: u32,
    pub firmware: String,
    pub operations: Vec<MockOperation>,
}

impl MockPivSession {
    pub fn new() -> Self {
        let mut slots = HashMap::new();
        slots.insert(SLOT_9A, SlotState::empty());
        slots.insert(SLOT_9D, SlotState::empty());

        Self {
            slots,
            pin: "123456".to_string(),
            puk: "12345678".to_string(),
            pin_verified: false,
            pin_retries: 3,
            puk_retries: 3,
            max_retries: 3,
            connected: true,
            touch_required: true,
            device_type: "yubikey5".to_string(),
            serial: 99999999,
            firmware: "5.7.1".to_string(),
            operations: Vec::new(),
        }
    }

    /// Pre-populated slots 9A/9D; skips provision step for sign/ECDH tests.
    pub fn with_keys() -> Self {
        let mut session = Self::new();
        session.pin_verified = true;
        session.touch_required = false;

        let ed_prv = Ed25519PrivateKey::generate();
        let ed_pub = ed_prv.public_key();
        let slot_9a = session.slots.get_mut(&SLOT_9A).unwrap();
        slot_9a.ed25519_prv = Some(ed_prv);
        slot_9a.ed25519_pub = Some(ed_pub);

        let x_prv = X25519PrivateKey::generate();
        let x_pub = x_prv.public_key();
        let slot_9d = session.slots.get_mut(&SLOT_9D).unwrap();
        slot_9d.x25519_prv = Some(x_prv);
        slot_9d.x25519_pub = Some(x_pub);

        session
    }

    /// Deterministic key material for test vectors.
    pub fn with_key_bytes(ed25519_seed: &[u8; 32], x25519_secret: &[u8; 32]) -> Self {
        let mut session = Self::new();
        session.pin_verified = true;
        session.touch_required = false;

        let ed_prv = Ed25519PrivateKey::from_bytes(ed25519_seed);
        let ed_pub = ed_prv.public_key();
        let slot_9a = session.slots.get_mut(&SLOT_9A).unwrap();
        slot_9a.ed25519_prv = Some(ed_prv);
        slot_9a.ed25519_pub = Some(ed_pub);

        let x_prv = X25519PrivateKey::from_bytes(x25519_secret);
        let x_pub = x_prv.public_key();
        let slot_9d = session.slots.get_mut(&SLOT_9D).unwrap();
        slot_9d.x25519_prv = Some(x_prv);
        slot_9d.x25519_pub = Some(x_pub);

        session
    }

    pub fn set_pin(&mut self, pin: &str) {
        self.pin = pin.to_string();
        self.pin_verified = false;
    }

    pub fn set_puk(&mut self, puk: &str) {
        self.puk = puk.to_string();
    }

    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    pub fn reconnect(&mut self) {
        self.connected = true;
        self.pin_verified = false;
    }

    /// Re-lock: clears PIN verification so the next op needs `verify_pin` again.
    /// Mirrors `PivSession::lock` (which re-selects the applet on real hardware).
    pub fn lock(&mut self) {
        self.pin_verified = false;
    }

    pub fn simulate_touch(&mut self) {
        self.touch_required = false;
    }

    pub fn require_touch(&mut self) {
        self.touch_required = true;
    }

    fn check_connected(&self) -> Result<(), RatkeyError> {
        if !self.connected {
            Err(RatkeyError::Disconnected)
        } else {
            Ok(())
        }
    }

    fn check_pin(&self) -> Result<(), RatkeyError> {
        if !self.pin_verified {
            Err(RatkeyError::PinRequired)
        } else {
            Ok(())
        }
    }

    fn check_touch(&self, slot: u8) -> Result<(), RatkeyError> {
        if let Some(slot_state) = self.slots.get(&slot) {
            if slot_state.touch_policy == TouchPolicy::Always && self.touch_required {
                return Err(RatkeyError::TouchRequired);
            }
        }
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn verify_pin(&mut self, pin: &str) -> Result<(), RatkeyError> {
        self.check_connected()?;

        if self.pin_retries == 0 {
            self.operations
                .push(MockOperation::PinVerify { success: false });
            return Err(RatkeyError::PinLocked);
        }

        if pin == self.pin {
            self.pin_verified = true;
            self.pin_retries = self.max_retries;
            self.operations
                .push(MockOperation::PinVerify { success: true });
            Ok(())
        } else {
            self.pin_retries -= 1;
            self.operations
                .push(MockOperation::PinVerify { success: false });
            if self.pin_retries == 0 {
                Err(RatkeyError::PinLocked)
            } else {
                Err(RatkeyError::PinFailed {
                    remaining: self.pin_retries,
                })
            }
        }
    }

    pub fn unblock_pin(&mut self, puk: &str, new_pin: &str) -> Result<(), RatkeyError> {
        self.check_connected()?;

        if self.puk_retries == 0 {
            self.operations
                .push(MockOperation::PinUnblock { success: false });
            return Err(RatkeyError::PukLocked);
        }

        if puk == self.puk {
            self.pin = new_pin.to_string();
            self.pin_verified = true;
            self.pin_retries = self.max_retries;
            self.puk_retries = self.max_retries;
            self.operations
                .push(MockOperation::PinUnblock { success: true });
            Ok(())
        } else {
            self.puk_retries -= 1;
            self.operations
                .push(MockOperation::PinUnblock { success: false });
            if self.puk_retries == 0 {
                Err(RatkeyError::PukLocked)
            } else {
                Err(RatkeyError::PukFailed {
                    remaining: self.puk_retries,
                })
            }
        }
    }

    pub fn reset_piv(&mut self) -> Result<(), RatkeyError> {
        self.check_connected()?;
        if self.pin_retries != 0 || self.puk_retries != 0 {
            self.operations
                .push(MockOperation::ResetPiv { success: false });
            return Err(RatkeyError::ResetRequiresBlockedPinAndPuk);
        }

        self.slots.insert(SLOT_9A, SlotState::empty());
        self.slots.insert(SLOT_9D, SlotState::empty());
        self.pin = "123456".to_string();
        self.puk = "12345678".to_string();
        self.pin_verified = false;
        self.pin_retries = self.max_retries;
        self.puk_retries = self.max_retries;
        self.touch_required = true;
        self.operations
            .push(MockOperation::ResetPiv { success: true });
        Ok(())
    }

    pub fn generate_ed25519(
        &mut self,
        slot: u8,
        touch_policy: TouchPolicy,
    ) -> Result<[u8; 32], RatkeyError> {
        self.check_connected()?;
        self.check_pin()?;

        let slot_state = self
            .slots
            .get_mut(&slot)
            .ok_or(RatkeyError::InvalidHwid(format!(
                "unknown slot 0x{slot:02X}"
            )))?;

        if slot_state.ed25519_prv.is_some() {
            return Err(RatkeyError::SlotOccupied { slot });
        }

        let prv = Ed25519PrivateKey::generate();
        let pub_key = prv.public_key();
        let pub_bytes = pub_key.to_bytes();

        slot_state.ed25519_prv = Some(prv);
        slot_state.ed25519_pub = Some(pub_key);
        slot_state.touch_policy = touch_policy;

        self.operations
            .push(MockOperation::GenerateEd25519 { slot });
        Ok(pub_bytes)
    }

    pub fn generate_x25519(
        &mut self,
        slot: u8,
        touch_policy: TouchPolicy,
    ) -> Result<[u8; 32], RatkeyError> {
        self.check_connected()?;
        self.check_pin()?;

        let slot_state = self
            .slots
            .get_mut(&slot)
            .ok_or(RatkeyError::InvalidHwid(format!(
                "unknown slot 0x{slot:02X}"
            )))?;

        if slot_state.x25519_prv.is_some() {
            return Err(RatkeyError::SlotOccupied { slot });
        }

        let prv = X25519PrivateKey::generate();
        let pub_key = prv.public_key();
        let pub_bytes = pub_key.to_bytes();

        slot_state.x25519_prv = Some(prv);
        slot_state.x25519_pub = Some(pub_key);
        slot_state.touch_policy = touch_policy;

        self.operations.push(MockOperation::GenerateX25519 { slot });
        Ok(pub_bytes)
    }

    pub fn sign_ed25519(&mut self, slot: u8, data: &[u8]) -> Result<[u8; 64], RatkeyError> {
        self.check_connected()?;
        self.check_pin()?;
        self.check_touch(slot)?;

        let slot_state = self
            .slots
            .get(&slot)
            .ok_or(RatkeyError::InvalidHwid(format!(
                "unknown slot 0x{slot:02X}"
            )))?;

        let prv = slot_state
            .ed25519_prv
            .as_ref()
            .ok_or(RatkeyError::EmptySlot { slot })?;

        let sig = prv.sign(data);

        self.operations.push(MockOperation::SignEd25519 {
            slot,
            data_len: data.len(),
        });
        Ok(sig)
    }

    pub fn ecdh_x25519(
        &mut self,
        slot: u8,
        peer_pub_bytes: &[u8; 32],
    ) -> Result<[u8; 32], RatkeyError> {
        self.check_connected()?;
        self.check_pin()?;
        self.check_touch(slot)?;

        let slot_state = self
            .slots
            .get(&slot)
            .ok_or(RatkeyError::InvalidHwid(format!(
                "unknown slot 0x{slot:02X}"
            )))?;

        let prv = slot_state
            .x25519_prv
            .as_ref()
            .ok_or(RatkeyError::EmptySlot { slot })?;

        let peer_pub = X25519PublicKey::from_bytes(peer_pub_bytes);
        let shared = prv.exchange(&peer_pub);

        self.operations.push(MockOperation::EcdhX25519 { slot });
        Ok(shared)
    }

    pub fn read_ed25519_public(&self, slot: u8) -> Result<[u8; 32], RatkeyError> {
        self.check_connected()?;

        let slot_state = self
            .slots
            .get(&slot)
            .ok_or(RatkeyError::InvalidHwid(format!(
                "unknown slot 0x{slot:02X}"
            )))?;

        let pub_key = slot_state
            .ed25519_pub
            .as_ref()
            .ok_or(RatkeyError::EmptySlot { slot })?;

        Ok(pub_key.to_bytes())
    }

    pub fn read_x25519_public(&self, slot: u8) -> Result<[u8; 32], RatkeyError> {
        self.check_connected()?;

        let slot_state = self
            .slots
            .get(&slot)
            .ok_or(RatkeyError::InvalidHwid(format!(
                "unknown slot 0x{slot:02X}"
            )))?;

        let pub_key = slot_state
            .x25519_pub
            .as_ref()
            .ok_or(RatkeyError::EmptySlot { slot })?;

        Ok(pub_key.to_bytes())
    }
}

impl Default for MockPivSession {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MockPivSession {
    fn drop(&mut self) {
        self.pin.zeroize();
        self.puk.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_verify_success() {
        let mut session = MockPivSession::new();
        assert!(session.verify_pin("123456").is_ok());
        assert!(session.pin_verified);
    }

    #[test]
    fn test_pin_verify_wrong() {
        let mut session = MockPivSession::new();
        let err = session.verify_pin("wrong").unwrap_err();
        match err {
            RatkeyError::PinFailed { remaining } => assert_eq!(remaining, 2),
            other => panic!("expected PinFailed, got {other:?}"),
        }
        assert!(!session.pin_verified);
    }

    #[test]
    fn test_pin_lockout() {
        let mut session = MockPivSession::new();
        let _ = session.verify_pin("wrong");
        let _ = session.verify_pin("wrong");
        let err = session.verify_pin("wrong").unwrap_err();
        assert!(matches!(err, RatkeyError::PinLocked));

        // Locked state survives correct PIN until PUK unlock.
        let err = session.verify_pin("123456").unwrap_err();
        assert!(matches!(err, RatkeyError::PinLocked));
    }

    #[test]
    fn test_pin_unblock_with_puk() {
        let mut session = MockPivSession::new();
        let _ = session.verify_pin("wrong");
        let _ = session.verify_pin("wrong");
        let _ = session.verify_pin("wrong");
        assert!(matches!(
            session.verify_pin("123456"),
            Err(RatkeyError::PinLocked)
        ));

        session.unblock_pin("12345678", "654321").unwrap();
        assert!(session.verify_pin("654321").is_ok());
        assert!(matches!(
            session.verify_pin("123456"),
            Err(RatkeyError::PinFailed { .. })
        ));
    }

    #[test]
    fn test_pin_unblock_wrong_puk_locks_puk() {
        let mut session = MockPivSession::new();
        let _ = session.verify_pin("wrong");
        let _ = session.verify_pin("wrong");
        let _ = session.verify_pin("wrong");

        let err = session.unblock_pin("bad", "654321").unwrap_err();
        assert!(matches!(err, RatkeyError::PukFailed { remaining: 2 }));
        let _ = session.unblock_pin("bad", "654321");
        let err = session.unblock_pin("bad", "654321").unwrap_err();
        assert!(matches!(err, RatkeyError::PukLocked));
        assert!(matches!(
            session.unblock_pin("12345678", "654321"),
            Err(RatkeyError::PukLocked)
        ));
    }

    #[test]
    fn test_reset_piv_requires_blocked_pin_and_puk() {
        let mut session = MockPivSession::with_keys();
        assert!(matches!(
            session.reset_piv(),
            Err(RatkeyError::ResetRequiresBlockedPinAndPuk)
        ));
    }

    #[test]
    fn test_reset_piv_clears_keys_and_restores_defaults() {
        let mut session = MockPivSession::with_keys();
        let _ = session.verify_pin("badpin");
        let _ = session.verify_pin("badpin");
        let _ = session.verify_pin("badpin");
        let _ = session.unblock_pin("badpuk", "654321");
        let _ = session.unblock_pin("badpuk", "654321");
        let _ = session.unblock_pin("badpuk", "654321");

        session.reset_piv().unwrap();
        session.verify_pin("123456").unwrap();
        assert!(matches!(
            session.sign_ed25519(SLOT_9A, b"test"),
            Err(RatkeyError::EmptySlot { slot: SLOT_9A })
        ));
    }

    #[test]
    fn test_pin_retry_reset() {
        let mut session = MockPivSession::new();
        let _ = session.verify_pin("wrong");
        // Success resets retries.
        session.verify_pin("123456").unwrap();
        let _ = session.verify_pin("wrong");
        let _ = session.verify_pin("wrong");
        let err = session.verify_pin("wrong").unwrap_err();
        assert!(matches!(err, RatkeyError::PinLocked));
    }

    #[test]
    fn test_disconnect() {
        let mut session = MockPivSession::with_keys();
        session.disconnect();
        assert!(!session.is_connected());
        assert!(matches!(
            session.sign_ed25519(SLOT_9A, b"test"),
            Err(RatkeyError::Disconnected)
        ));
    }

    #[test]
    fn test_reconnect_requires_pin() {
        let mut session = MockPivSession::with_keys();
        session.disconnect();
        session.reconnect();
        assert!(session.is_connected());
        assert!(matches!(
            session.sign_ed25519(SLOT_9A, b"test"),
            Err(RatkeyError::PinRequired)
        ));
    }

    #[test]
    fn test_generate_ed25519() {
        let mut session = MockPivSession::new();
        session.verify_pin("123456").unwrap();
        let pub_bytes = session
            .generate_ed25519(SLOT_9A, TouchPolicy::Never)
            .unwrap();
        assert_eq!(pub_bytes.len(), 32);

        assert!(matches!(
            session.generate_ed25519(SLOT_9A, TouchPolicy::Never),
            Err(RatkeyError::SlotOccupied { slot: 0x9A })
        ));
    }

    #[test]
    fn test_generate_x25519() {
        let mut session = MockPivSession::new();
        session.verify_pin("123456").unwrap();
        let pub_bytes = session
            .generate_x25519(SLOT_9D, TouchPolicy::Cached)
            .unwrap();
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn test_sign_verify() {
        let mut session = MockPivSession::with_keys();
        let message = b"hello ratkey";
        let sig = session.sign_ed25519(SLOT_9A, message).unwrap();
        assert_eq!(sig.len(), 64);

        let pub_bytes = session.read_ed25519_public(SLOT_9A).unwrap();
        let pub_key = Ed25519PublicKey::from_bytes(&pub_bytes).unwrap();
        assert!(pub_key.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_sign_matches_software() {
        // Load-bearing: mock signatures MUST match software signatures bit-for-bit
        // so test vectors generated on hardware can be replayed here.
        let seed = [0x42u8; 32];
        let secret = [0x43u8; 32];
        let mut session = MockPivSession::with_key_bytes(&seed, &secret);

        let software_key = Ed25519PrivateKey::from_bytes(&seed);
        let message = b"deterministic signature test";

        let hw_sig = session.sign_ed25519(SLOT_9A, message).unwrap();
        let sw_sig = software_key.sign(message);

        assert_eq!(
            hw_sig, sw_sig,
            "mock signature must match software signature"
        );
    }

    #[test]
    fn test_ecdh_symmetric() {
        let mut session = MockPivSession::with_keys();
        let session_x_pub = session.read_x25519_public(SLOT_9D).unwrap();

        let peer_prv = X25519PrivateKey::generate();
        let peer_pub = peer_prv.public_key();
        let peer_pub_bytes = peer_pub.to_bytes();

        let secret_hw = session.ecdh_x25519(SLOT_9D, &peer_pub_bytes).unwrap();

        let session_pub = X25519PublicKey::from_bytes(&session_x_pub);
        let secret_sw = peer_prv.exchange(&session_pub);

        assert_eq!(
            secret_hw, secret_sw,
            "ECDH shared secrets must be identical from both sides"
        );
    }

    #[test]
    fn test_ecdh_deterministic() {
        let seed = [0x42u8; 32];
        let secret = [0x43u8; 32];
        let mut session = MockPivSession::with_key_bytes(&seed, &secret);

        let peer_pub = [0x55u8; 32];

        let software_key = X25519PrivateKey::from_bytes(&secret);
        let peer = X25519PublicKey::from_bytes(&peer_pub);
        let sw_shared = software_key.exchange(&peer);

        let hw_shared = session.ecdh_x25519(SLOT_9D, &peer_pub).unwrap();

        assert_eq!(
            hw_shared, sw_shared,
            "mock ECDH must match software ECDH for same keys"
        );
    }

    #[test]
    fn test_sign_empty_slot() {
        let mut session = MockPivSession::new();
        session.verify_pin("123456").unwrap();
        assert!(matches!(
            session.sign_ed25519(SLOT_9A, b"test"),
            Err(RatkeyError::EmptySlot { slot: 0x9A })
        ));
    }

    #[test]
    fn test_touch_policy_always() {
        let mut session = MockPivSession::new();
        session.verify_pin("123456").unwrap();
        session
            .generate_ed25519(SLOT_9A, TouchPolicy::Always)
            .unwrap();

        session.require_touch();
        assert!(matches!(
            session.sign_ed25519(SLOT_9A, b"test"),
            Err(RatkeyError::TouchRequired)
        ));

        session.simulate_touch();
        assert!(session.sign_ed25519(SLOT_9A, b"test").is_ok());
    }

    #[test]
    fn test_touch_policy_never() {
        let mut session = MockPivSession::new();
        session.verify_pin("123456").unwrap();
        session
            .generate_ed25519(SLOT_9A, TouchPolicy::Never)
            .unwrap();

        // TouchPolicy::Never ignores touch_required.
        session.require_touch();
        assert!(session.sign_ed25519(SLOT_9A, b"test").is_ok());
    }

    #[test]
    fn test_operations_log() {
        let mut session = MockPivSession::new();
        session.verify_pin("123456").unwrap();
        session
            .generate_ed25519(SLOT_9A, TouchPolicy::Never)
            .unwrap();
        session.sign_ed25519(SLOT_9A, b"test").unwrap();

        assert_eq!(session.operations.len(), 3);
        assert!(matches!(
            session.operations[0],
            MockOperation::PinVerify { success: true }
        ));
        assert!(matches!(
            session.operations[1],
            MockOperation::GenerateEd25519 { slot: 0x9A }
        ));
        assert!(matches!(
            session.operations[2],
            MockOperation::SignEd25519 { slot: 0x9A, .. }
        ));
    }

    #[test]
    fn test_without_pin_verify() {
        let mut session = MockPivSession::new();
        assert!(matches!(
            session.generate_ed25519(SLOT_9A, TouchPolicy::Never),
            Err(RatkeyError::PinRequired)
        ));
    }

    #[test]
    fn test_custom_pin() {
        let mut session = MockPivSession::new();
        session.set_pin("mypin123");
        assert!(session.verify_pin("123456").is_err());
        assert!(session.verify_pin("mypin123").is_ok());
    }
}
