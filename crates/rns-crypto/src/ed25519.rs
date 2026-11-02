//! Ed25519 signing and verification.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use thiserror::Error;
use zeroize::Zeroize;

/// Errors surfaced by Ed25519 sign/verify.
#[derive(Debug, Error)]
pub enum Ed25519Error {
    /// `verify` rejected the signature.
    #[error("signature verification failed")]
    VerificationFailed,
    /// Public key bytes were not a valid Ed25519 point.
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    /// Retained signature-decoding error variant. The current `verify` method
    /// accepts a fixed 64-byte signature and returns `VerificationFailed` on
    /// verification failure.
    #[error("invalid signature bytes")]
    InvalidSignature,
}

/// Ed25519 private key (32-byte seed).
///
/// Key material is zeroized on drop.
pub struct Ed25519PrivateKey {
    key: SigningKey,
}

impl Zeroize for Ed25519PrivateKey {
    fn zeroize(&mut self) {
        // Assignment drops the prior `SigningKey` (ZeroizeOnDrop), leaving a zero seed.
        self.key = SigningKey::from_bytes(&[0u8; 32]);
    }
}

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Ed25519 public key (32 bytes, compressed Edwards point).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    key: VerifyingKey,
}

impl Ed25519PrivateKey {
    /// Generate a random key from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Construct from a 32-byte seed.
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Return the 32-byte seed.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            key: self.key.verifying_key(),
        }
    }

    /// Produce a 64-byte Ed25519 signature (R || S) over `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sig = self.key.sign(message);
        sig.to_bytes()
    }
}

impl Ed25519PublicKey {
    /// Parse a 32-byte compressed Edwards point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Ed25519Error> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| Ed25519Error::InvalidPublicKey)?;
        Ok(Self { key })
    }

    /// Return the 32-byte encoded public key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// Verify a 64-byte Ed25519 signature over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), Ed25519Error> {
        let sig = Signature::from_bytes(signature);
        self.key
            .verify(message, &sig)
            .map_err(|_| Ed25519Error::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let prv = Ed25519PrivateKey::generate();
        let pub_key = prv.public_key();
        assert_ne!(pub_key.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn test_sign_verify() {
        let prv = Ed25519PrivateKey::generate();
        let pub_key = prv.public_key();
        let msg = b"test message";

        let sig = prv.sign(msg);
        assert!(pub_key.verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_wrong_message() {
        let prv = Ed25519PrivateKey::generate();
        let pub_key = prv.public_key();

        let sig = prv.sign(b"correct");
        assert!(pub_key.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn test_wrong_key() {
        let prv1 = Ed25519PrivateKey::generate();
        let prv2 = Ed25519PrivateKey::generate();
        let msg = b"test";

        let sig = prv1.sign(msg);
        assert!(prv2.public_key().verify(msg, &sig).is_err());
    }

    #[test]
    fn test_deterministic_from_seed() {
        let seed = [42u8; 32];
        let prv1 = Ed25519PrivateKey::from_bytes(&seed);
        let prv2 = Ed25519PrivateKey::from_bytes(&seed);

        let msg = b"deterministic";
        assert_eq!(prv1.sign(msg), prv2.sign(msg));
        assert_eq!(prv1.public_key().to_bytes(), prv2.public_key().to_bytes());
    }

    #[test]
    fn test_seed_roundtrip() {
        let prv = Ed25519PrivateKey::generate();
        let seed = prv.to_bytes();
        let prv2 = Ed25519PrivateKey::from_bytes(&seed);
        assert_eq!(prv.public_key().to_bytes(), prv2.public_key().to_bytes());
    }

    #[test]
    fn test_public_key_roundtrip() {
        let prv = Ed25519PrivateKey::generate();
        let pub_bytes = prv.public_key().to_bytes();
        let pub_key = Ed25519PublicKey::from_bytes(&pub_bytes).unwrap();
        assert_eq!(pub_key.to_bytes(), pub_bytes);

        let msg = b"roundtrip";
        let sig = prv.sign(msg);
        assert!(pub_key.verify(msg, &sig).is_ok());
    }
}
