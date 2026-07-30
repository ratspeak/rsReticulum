//! Tracks sent packets until they are delivered, time out, or are culled.

use std::time::{Duration, Instant};

pub use crate::constants::{EXPL_LENGTH, IMPL_LENGTH};

/// Lifecycle state of a tracked packet.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReceiptStatus {
    Sent = 0x01,
    Delivered = 0x02,
    Failed = 0x00,
    Culled = 0xFF,
    /// Resource transfer in progress.
    Receiving = 0x06,
}

/// Tracks a sent packet until it is delivered, times out, or is culled.
#[allow(missing_docs)]
pub struct PacketReceipt {
    pub hash: [u8; 32],
    pub truncated_hash: [u8; 16],
    /// Destination this packet was sent to. Proofs are only accepted from the
    /// identity bound to this destination.
    pub destination_hash: Option<[u8; 16]>,
    /// Full Reticulum public key (`X25519 || Ed25519`) captured for the
    /// destination. Keeping the exact identity used for the send prevents an
    /// unrelated signature from concluding the receipt.
    pub destination_public_key: Option<[u8; 64]>,
    pub status: ReceiptStatus,
    pub sent_at: Instant,
    pub concluded_at: Option<Instant>,
    pub timeout: Option<Duration>,
    pub callbacks: ReceiptCallbacks,
}

/// Optional callbacks invoked when a receipt transitions out of `Sent`.
#[allow(missing_docs)]
#[derive(Default)]
pub struct ReceiptCallbacks {
    pub delivery: Option<ReceiptCallback>,
    pub timeout: Option<ReceiptCallback>,
}

/// Callback invoked once when a packet receipt reaches a terminal state.
pub type ReceiptCallback = Box<dyn FnOnce(&PacketReceipt) + Send>;

impl PacketReceipt {
    /// Create a new receipt in the `Sent` state, stamping `sent_at` to now.
    pub fn new(hash: [u8; 32], truncated_hash: [u8; 16], timeout: Option<Duration>) -> Self {
        Self {
            hash,
            truncated_hash,
            destination_hash: None,
            destination_public_key: None,
            status: ReceiptStatus::Sent,
            sent_at: Instant::now(),
            concluded_at: None,
            timeout,
            callbacks: ReceiptCallbacks::default(),
        }
    }

    /// Bind this receipt to the destination identity used for the send.
    ///
    /// The public key may be supplied later when the destination hash is
    /// already known but its validated announce has not yet been recalled.
    pub fn set_destination_identity(
        &mut self,
        destination_hash: [u8; 16],
        public_key: Option<[u8; 64]>,
    ) {
        if self.destination_hash.is_none() {
            self.destination_hash = Some(destination_hash);
        }
        if self.destination_hash == Some(destination_hash)
            && self.destination_public_key.is_none()
            && public_key.is_some()
        {
            self.destination_public_key = public_key;
        }
    }

    /// Transition to `Delivered` and fire the delivery callback.
    pub fn deliver(&mut self) {
        self.status = ReceiptStatus::Delivered;
        self.concluded_at = Some(Instant::now());
        if let Some(cb) = self.callbacks.delivery.take() {
            cb(self);
        }
    }

    /// Transition to `Failed` and fire the timeout callback.
    pub fn fail(&mut self) {
        self.status = ReceiptStatus::Failed;
        self.concluded_at = Some(Instant::now());
        if let Some(cb) = self.callbacks.timeout.take() {
            cb(self);
        }
    }

    /// Transition to `Culled` without firing any callback.
    pub fn cull(&mut self) {
        self.status = ReceiptStatus::Culled;
        self.concluded_at = Some(Instant::now());
    }

    /// Measured round-trip time, if this receipt has concluded.
    pub fn get_rtt(&self) -> Option<Duration> {
        self.concluded_at.map(|t| t.duration_since(self.sent_at))
    }

    /// Whether the configured timeout (if any) has elapsed since `sent_at`.
    pub fn is_timed_out(&self) -> bool {
        match self.timeout {
            Some(timeout) => self.sent_at.elapsed() > timeout,
            None => false,
        }
    }

    /// Register a callback to run once on delivery.
    pub fn set_delivery_callback(&mut self, cb: impl FnOnce(&PacketReceipt) + Send + 'static) {
        self.callbacks.delivery = Some(Box::new(cb));
    }

    /// Register a callback to run once on timeout.
    pub fn set_timeout_callback(&mut self, cb: impl FnOnce(&PacketReceipt) + Send + 'static) {
        self.callbacks.timeout = Some(Box::new(cb));
    }

    /// Validate a PROOF body and mark delivered on match.
    /// Explicit (96): embedded hash must equal receipt hash. Implicit (64):
    /// signature over the receipt hash. `verify` is Ed25519 verify with the
    /// expected identity key.
    pub fn validate_proof<F>(&mut self, proof: &[u8], verify: F) -> bool
    where
        F: FnOnce(&[u8], &[u8]) -> bool,
    {
        if proof.len() == EXPL_LENGTH {
            let proof_hash = &proof[..32];
            let signature = &proof[32..96];
            if proof_hash == self.hash && verify(signature, &self.hash) {
                self.status = ReceiptStatus::Delivered;
                self.concluded_at = Some(Instant::now());
                if let Some(cb) = self.callbacks.delivery.take() {
                    cb(self);
                }
                return true;
            }
        } else if proof.len() == IMPL_LENGTH {
            let signature = &proof[..64];
            if verify(signature, &self.hash) {
                self.status = ReceiptStatus::Delivered;
                self.concluded_at = Some(Instant::now());
                if let Some(cb) = self.callbacks.delivery.take() {
                    cb(self);
                }
                return true;
            }
        }
        false
    }

    /// Validate a PROOF body against the destination identity captured for
    /// this receipt. A receipt without a known identity cannot be concluded by
    /// a proof.
    pub fn validate_proof_from_destination(&mut self, proof: &[u8]) -> bool {
        let Some(public_key) = self.destination_public_key else {
            return false;
        };

        let mut signing_key = [0u8; 32];
        signing_key.copy_from_slice(&public_key[32..]);
        let Ok(verifier) = rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&signing_key) else {
            return false;
        };

        self.validate_proof(proof, |signature, message| {
            let Ok(signature) = <&[u8; 64]>::try_from(signature) else {
                return false;
            };
            verifier.verify(message, signature).is_ok()
        })
    }

    /// If the timeout has elapsed while still in `Sent`, transition to
    /// `Failed` and fire the timeout callback. Returns whether a timeout fired.
    pub fn check_timeout(&mut self) -> bool {
        if self.is_timed_out() && self.status == ReceiptStatus::Sent {
            self.status = ReceiptStatus::Failed;
            self.concluded_at = Some(Instant::now());
            if let Some(cb) = self.callbacks.timeout.take() {
                cb(self);
            }
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::ed25519::Ed25519PrivateKey;

    #[test]
    fn test_initial_state() {
        let receipt = PacketReceipt::new([0; 32], [0; 16], Some(Duration::from_secs(10)));
        assert_eq!(receipt.status, ReceiptStatus::Sent);
        assert!(receipt.concluded_at.is_none());
        assert!(receipt.get_rtt().is_none());
    }

    #[test]
    fn test_deliver() {
        let mut receipt = PacketReceipt::new([0; 32], [0; 16], None);
        receipt.deliver();
        assert_eq!(receipt.status, ReceiptStatus::Delivered);
        assert!(receipt.concluded_at.is_some());
        assert!(receipt.get_rtt().is_some());
    }

    #[test]
    fn test_fail() {
        let mut receipt = PacketReceipt::new([0; 32], [0; 16], None);
        receipt.fail();
        assert_eq!(receipt.status, ReceiptStatus::Failed);
    }

    #[test]
    fn destination_identity_validates_explicit_and_implicit_proofs() {
        let signer = Ed25519PrivateKey::generate();
        let mut public_key = [0u8; 64];
        public_key[32..].copy_from_slice(&signer.public_key().to_bytes());
        let packet_hash = [0xA5; 32];
        let signature = signer.sign(&packet_hash);

        let mut explicit =
            PacketReceipt::new(packet_hash, [0xA5; 16], Some(Duration::from_secs(10)));
        explicit.set_destination_identity([0x11; 16], Some(public_key));
        let mut explicit_proof = Vec::with_capacity(EXPL_LENGTH);
        explicit_proof.extend_from_slice(&packet_hash);
        explicit_proof.extend_from_slice(&signature);
        assert!(explicit.validate_proof_from_destination(&explicit_proof));
        assert_eq!(explicit.status, ReceiptStatus::Delivered);

        let mut implicit =
            PacketReceipt::new(packet_hash, [0xA5; 16], Some(Duration::from_secs(10)));
        implicit.set_destination_identity([0x11; 16], Some(public_key));
        assert!(implicit.validate_proof_from_destination(&signature));
        assert_eq!(implicit.status, ReceiptStatus::Delivered);
    }

    #[test]
    fn destination_identity_rejects_forged_or_unbound_proofs() {
        let expected = Ed25519PrivateKey::generate();
        let attacker = Ed25519PrivateKey::generate();
        let mut public_key = [0u8; 64];
        public_key[32..].copy_from_slice(&expected.public_key().to_bytes());
        let packet_hash = [0xB6; 32];
        let forged_signature = attacker.sign(&packet_hash);

        let mut forged = PacketReceipt::new(packet_hash, [0xB6; 16], None);
        forged.set_destination_identity([0x22; 16], Some(public_key));
        assert!(!forged.validate_proof_from_destination(&forged_signature));
        assert_eq!(forged.status, ReceiptStatus::Sent);

        let valid_signature = expected.sign(&packet_hash);
        let mut unbound = PacketReceipt::new(packet_hash, [0xB6; 16], None);
        assert!(!unbound.validate_proof_from_destination(&valid_signature));
        assert_eq!(unbound.status, ReceiptStatus::Sent);
    }
}
