//! BIP-39 recoverable backup: a deterministic Reticulum identity derived from a
//! 24-word mnemonic. Interop-compatible with ratkey-py (derivation scheme v1):
//!
//! ```text
//! mnemonic (24 words)
//!   -> PBKDF2-SHA512 (BIP-39, passphrase="")          -> 64-byte seed
//!   -> HKDF-SHA256(seed, salt="ratkey-ed25519-v1", info) -> 32-byte Ed25519 seed
//!   -> HKDF-SHA256(seed, salt="ratkey-x25519-v1",  info) -> 32-byte X25519 secret
//! ```
//!
//! The seed phrase is a second attack surface (it reconstructs the private keys
//! and is not protected by the device PIN). Callers must surface that tradeoff.

use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::x25519::X25519PrivateKey;

use crate::error::RatkeyError;

const ED25519_SALT: &[u8] = b"ratkey-ed25519-v1";
const X25519_SALT: &[u8] = b"ratkey-x25519-v1";
const HKDF_INFO: &[u8] = b"ratkey identity key derivation";

/// Key material derived from a mnemonic. The two secret fields are zeroized on drop.
pub struct DerivedIdentity {
    pub ed25519_seed: [u8; 32],
    pub x25519_secret: [u8; 32],
    pub ed25519_pub: [u8; 32],
    pub x25519_pub: [u8; 32],
}

impl Drop for DerivedIdentity {
    fn drop(&mut self) {
        self.ed25519_seed.zeroize();
        self.x25519_secret.zeroize();
    }
}

/// Generate a fresh 24-word (256-bit) BIP-39 English mnemonic.
pub fn generate_mnemonic() -> Result<String, RatkeyError> {
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&rns_crypto::random::random_bytes(32));
    let result = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map(|m| m.to_string())
        .map_err(|e| RatkeyError::InvalidHwid(format!("mnemonic generation failed: {e}")));
    entropy.zeroize();
    result
}

/// True for a valid 24-word BIP-39 English mnemonic (wordlist + checksum).
pub fn validate_mnemonic(words: &str) -> bool {
    let w = words.trim();
    w.split_whitespace().count() == 24
        && Mnemonic::parse_in_normalized(Language::English, w).is_ok()
}

/// Derive the Reticulum identity keys from a 24-word mnemonic (scheme v1).
pub fn derive_identity(words: &str) -> Result<DerivedIdentity, RatkeyError> {
    if !validate_mnemonic(words) {
        return Err(RatkeyError::InvalidHwid(
            "invalid seed phrase: expected 24 valid BIP-39 English words".to_string(),
        ));
    }
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, words.trim())
        .map_err(|e| RatkeyError::InvalidHwid(format!("invalid seed phrase: {e}")))?;

    let mut seed = mnemonic.to_seed("");
    let ed25519_seed = hkdf32(&seed, ED25519_SALT)?;
    let x25519_secret = hkdf32(&seed, X25519_SALT)?;
    seed.zeroize();

    let ed25519_pub = Ed25519PrivateKey::from_bytes(&ed25519_seed)
        .public_key()
        .to_bytes();
    let x25519_pub = X25519PrivateKey::from_bytes(&x25519_secret)
        .public_key()
        .to_bytes();

    Ok(DerivedIdentity {
        ed25519_seed,
        x25519_secret,
        ed25519_pub,
        x25519_pub,
    })
}

fn hkdf32(ikm: &[u8], salt: &[u8]) -> Result<[u8; 32], RatkeyError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|_| RatkeyError::InvalidHwid("HKDF expand failed".to_string()))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mnemonic() -> String {
        // Standard BIP-39 all-zero-entropy vector (checksum word "art").
        "abandon ".repeat(23) + "art"
    }

    #[test]
    fn test_derive_matches_python_vector() {
        // Cross-checked against ratkey-py's derivation (scheme v1).
        let d = derive_identity(&test_mnemonic()).unwrap();
        assert_eq!(
            hex::encode(d.ed25519_seed),
            "7263e9dd6caad2ac3e1466898709dbf512bacab7dfcde21faf59b26607802648"
        );
        assert_eq!(
            hex::encode(d.x25519_secret),
            "2d9f476de3ab7a9fda148957c09a3c68e23cca2db4656033cce86766d4383aae"
        );
    }

    #[test]
    fn test_derive_is_deterministic() {
        let a = derive_identity(&test_mnemonic()).unwrap();
        let b = derive_identity(&test_mnemonic()).unwrap();
        assert_eq!(a.ed25519_pub, b.ed25519_pub);
        assert_eq!(a.x25519_pub, b.x25519_pub);
    }

    #[test]
    fn test_validate_rejects_bad_input() {
        assert!(!validate_mnemonic("not a real phrase"));
        assert!(!validate_mnemonic(&"abandon ".repeat(24))); // 24 abandon = bad checksum
        assert!(validate_mnemonic(&test_mnemonic()));
    }

    #[test]
    fn test_generate_roundtrips() {
        let m = generate_mnemonic().unwrap();
        assert_eq!(m.split_whitespace().count(), 24);
        assert!(validate_mnemonic(&m));
        // A generated phrase derives a stable identity.
        let d = derive_identity(&m).unwrap();
        assert_ne!(d.ed25519_pub, [0u8; 32]);
    }
}
