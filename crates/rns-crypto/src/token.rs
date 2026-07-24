//! RNS encryption token: AES-256-CBC + HMAC-SHA256 over an IV-prefixed ciphertext.

use alloc::vec::Vec;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::aes_cbc;
use crate::hmac::{hmac_sha256, hmac_verify};
use crate::pkcs7;
use crate::random::{random_16, random_bytes};

/// IV (16) + HMAC (32). A token is this plus the PKCS7-padded ciphertext.
pub const TOKEN_OVERHEAD: usize = 48;
/// AES-256 token key size: 32-byte signing key + 32-byte encryption key.
pub const KEY_LENGTH: usize = 64;
/// Legacy AES-128 token key size: 16-byte signing key + 16-byte encryption key.
pub const LEGACY_KEY_LENGTH: usize = 32;

/// Errors surfaced by [`encrypt`] and [`decrypt`].
#[derive(Debug, Error)]
pub enum TokenError {
    /// Key must be 32 or 64 bytes.
    #[error("invalid key length: expected 32 or 64, got {0}")]
    InvalidKeyLength(usize),
    /// Token is shorter than [`TOKEN_OVERHEAD`] so cannot contain IV + HMAC.
    #[error("token too short for decryption")]
    TooShort,
    /// HMAC tag did not validate.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// Underlying AES-CBC decrypt returned an error.
    #[error("decryption failed")]
    DecryptionFailed,
    /// Underlying AES-CBC encrypt returned an error.
    #[error("encryption failed")]
    EncryptionFailed,
}

/// Split a token key into `(signing_key, encryption_key)`.
/// 64 → 32/32 (AES-256 + HMAC-SHA256); 32 → 16/16 (AES-128, legacy).
fn split_key(key: &[u8]) -> Result<(&[u8], &[u8]), TokenError> {
    match key.len() {
        KEY_LENGTH => Ok((&key[..32], &key[32..])),
        LEGACY_KEY_LENGTH => Ok((&key[..16], &key[16..])),
        n => Err(TokenError::InvalidKeyLength(n)),
    }
}

/// Generate a fresh AES-256 token key with the operating-system CSPRNG.
pub fn generate_key() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(random_bytes(KEY_LENGTH))
}

/// Token encrypt (Modified Fernet — no version byte, no timestamp).
/// Wire: `IV(16) || AES-CBC(PKCS7(plaintext)) || HMAC-SHA256(IV || ciphertext)(32)`.
pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, TokenError> {
    let (signing_key, encryption_key) = split_key(key)?;

    let iv = random_16();
    let padded = pkcs7::pad(plaintext);

    let ciphertext =
        aes_cbc::encrypt(encryption_key, &iv, &padded).map_err(|_| TokenError::EncryptionFailed)?;

    let mut signed_parts = Vec::with_capacity(16 + ciphertext.len());
    signed_parts.extend_from_slice(&iv);
    signed_parts.extend_from_slice(&ciphertext);

    let mac = hmac_sha256(signing_key, &signed_parts);

    let mut token = signed_parts;
    token.extend_from_slice(&mac);

    Ok(token)
}

/// Token decrypt. All failure modes collapse to `AuthenticationFailed`
/// (padding-oracle defence). HMAC comparison is constant-time.
pub fn decrypt(token: &[u8], key: &[u8]) -> Result<Vec<u8>, TokenError> {
    let (signing_key, encryption_key) = split_key(key)?;

    // Minimum well-formed token: IV(16) + one AES block(16) + HMAC(32).
    if token.len() < 64 {
        return Err(TokenError::AuthenticationFailed);
    }

    let split_point = token.len() - 32;
    let signed_parts = &token[..split_point];
    let received_hmac: &[u8; 32] = token[split_point..].try_into().unwrap();

    if !hmac_verify(signing_key, signed_parts, received_hmac) {
        return Err(TokenError::AuthenticationFailed);
    }

    let iv = &signed_parts[..16];
    let ciphertext = &signed_parts[16..];

    if !aes_cbc::is_nonzero_block_aligned(ciphertext.len()) {
        return Err(TokenError::AuthenticationFailed);
    }

    let padded = aes_cbc::decrypt(encryption_key, iv, ciphertext)
        .map_err(|_| TokenError::AuthenticationFailed)?;

    let plaintext = pkcs7::unpad(&padded).map_err(|_| TokenError::AuthenticationFailed)?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 64];
        let plaintext = b"hello, reticulum!";

        let token = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&token, &key).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn generated_key_is_valid_and_unique() {
        let first = generate_key();
        let second = generate_key();

        assert_eq!(first.len(), KEY_LENGTH);
        assert_eq!(second.len(), KEY_LENGTH);
        assert_ne!(&*first, &*second);
        assert_eq!(
            decrypt(&encrypt(b"generated", &first).unwrap(), &first).unwrap(),
            b"generated"
        );
    }

    #[test]
    fn test_encrypt_produces_correct_structure() {
        let key = [0x42u8; 64];
        let plaintext = b"test";

        let token = encrypt(plaintext, &key).unwrap();
        // IV(16) + ciphertext(16) + HMAC(32) = 64.
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn test_encrypt_empty() {
        let key = [0x42u8; 64];
        let token = encrypt(b"", &key).unwrap();
        assert_eq!(token.len(), 64);
        let decrypted = decrypt(&token, &key).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_block_aligned() {
        let key = [0x42u8; 64];
        // Block-aligned input forces a full extra padding block.
        let plaintext = [0xABu8; 16];
        let token = encrypt(&plaintext, &key).unwrap();
        assert_eq!(token.len(), 80);
        let decrypted = decrypt(&token, &key).unwrap();
        assert_eq!(&decrypted, &plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0x42u8; 64];
        let key2 = [0x43u8; 64];
        let plaintext = b"secret";

        let token = encrypt(plaintext, &key1).unwrap();
        assert!(decrypt(&token, &key2).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; 64];
        let plaintext = b"secret";

        let mut token = encrypt(plaintext, &key).unwrap();
        // Offset 20 lies inside the ciphertext, after the 16-byte IV.
        token[20] ^= 0xFF;
        assert!(decrypt(&token, &key).is_err());
    }

    #[test]
    fn test_tampered_hmac_fails() {
        let key = [0x42u8; 64];
        let plaintext = b"secret";

        let mut token = encrypt(plaintext, &key).unwrap();
        let last = token.len() - 1;
        token[last] ^= 0xFF;
        assert!(decrypt(&token, &key).is_err());
    }

    #[test]
    fn test_too_short_token() {
        let key = [0x42u8; 64];
        assert!(decrypt(&[0u8; 63], &key).is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        assert!(encrypt(b"test", &[0u8; 48]).is_err());
        assert!(decrypt(&[0u8; 64], &[0u8; 48]).is_err());
    }

    #[test]
    fn test_various_lengths() {
        let key = [0x42u8; 64];
        for len in 0..256 {
            let plaintext = vec![0xABu8; len];
            let token = encrypt(&plaintext, &key).unwrap();
            let decrypted = decrypt(&token, &key).unwrap();
            assert_eq!(decrypted, plaintext, "failed for length {len}");
        }
    }

    #[test]
    fn test_unique_ciphertexts() {
        // Random IV must produce distinct ciphertexts for the same input.
        let key = [0x42u8; 64];
        let plaintext = b"same input";
        let t1 = encrypt(plaintext, &key).unwrap();
        let t2 = encrypt(plaintext, &key).unwrap();
        assert_ne!(t1, t2);
    }

    /// Legacy AES-128 round-trip via 32-byte key (Python `Token.py:62-65`).
    #[test]
    fn test_encrypt_decrypt_roundtrip_aes128() {
        let key = [0x42u8; 32];
        let plaintext = b"hello legacy reticulum";

        let token = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&token, &key).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_aes128_structure() {
        let key = [0x42u8; 32];
        let plaintext = b"test";

        let token = encrypt(plaintext, &key).unwrap();
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn test_aes128_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"secret";

        let mut token = encrypt(plaintext, &key).unwrap();
        token[20] ^= 0xFF;
        assert!(decrypt(&token, &key).is_err());
    }

    /// A token under one key size must not decrypt with the other.
    #[test]
    fn test_token_key_size_isolation() {
        let key128 = [0x42u8; 32];
        let key256 = [0x42u8; 64];
        let plaintext = b"isolated";

        let t128 = encrypt(plaintext, &key128).unwrap();
        let t256 = encrypt(plaintext, &key256).unwrap();

        assert!(decrypt(&t128, &key256).is_err());
        assert!(decrypt(&t256, &key128).is_err());
    }
}
