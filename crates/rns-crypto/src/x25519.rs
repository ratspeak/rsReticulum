//! X25519 Diffie-Hellman primitives.

use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// X25519 private key material (32 bytes). Scalar clamping occurs during
/// public-key derivation and Diffie-Hellman, not when these bytes are stored.
///
/// Key material is zeroized on drop.
pub struct X25519PrivateKey {
    secret: StaticSecret,
}

impl Zeroize for X25519PrivateKey {
    fn zeroize(&mut self) {
        // Assignment drops the prior `StaticSecret` (ZeroizeOnDrop), leaving a zero scalar.
        self.secret = StaticSecret::from([0u8; 32]);
    }
}

impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// X25519 public key (32 bytes, u-coordinate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519PublicKey {
    key: PublicKey,
}

impl X25519PrivateKey {
    /// Generate a random key from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Store 32 bytes of private key material without changing their encoding.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(*bytes),
        }
    }

    /// Return the stored 32-byte private key material.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            key: PublicKey::from(&self.secret),
        }
    }

    /// Compute the shared secret with `peer` via X25519 Diffie-Hellman.
    /// This primitive does not reject an all-zero result; a protocol requiring
    /// a contributory-behavior check must validate the returned secret.
    pub fn exchange(&self, peer: &X25519PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(&peer.key).to_bytes()
    }
}

impl X25519PublicKey {
    /// Store a 32-byte u-coordinate without rejecting low-order public inputs.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: PublicKey::from(*bytes),
        }
    }

    /// Return the 32-byte u-coordinate.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let prv = X25519PrivateKey::generate();
        let pub_key = prv.public_key();
        assert_ne!(pub_key.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn test_key_roundtrip() {
        let prv = X25519PrivateKey::generate();
        let bytes = prv.to_bytes();
        let prv2 = X25519PrivateKey::from_bytes(&bytes);
        assert_eq!(prv.public_key().to_bytes(), prv2.public_key().to_bytes());
    }

    #[test]
    fn test_ecdh_agreement() {
        let alice_prv = X25519PrivateKey::generate();
        let alice_pub = alice_prv.public_key();

        let bob_prv = X25519PrivateKey::generate();
        let bob_pub = bob_prv.public_key();

        let alice_shared = alice_prv.exchange(&bob_pub);
        let bob_shared = bob_prv.exchange(&alice_pub);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_from_known_bytes() {
        let prv_bytes = [42u8; 32];
        let prv = X25519PrivateKey::from_bytes(&prv_bytes);
        let pub_key = prv.public_key();
        let pub_key2 = X25519PrivateKey::from_bytes(&prv_bytes).public_key();
        assert_eq!(pub_key.to_bytes(), pub_key2.to_bytes());
    }
}
