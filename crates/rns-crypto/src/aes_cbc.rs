//! AES-CBC, no padding (callers use [`crate::pkcs7`]). Key length selects:
//! 16 → AES-128, 32 → AES-256. Wire negotiates AES-256; AES-128 kept for
//! legacy Token material.

use aes::{Aes128, Aes256};
use alloc::vec::Vec;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use thiserror::Error;

const AES_BLOCK_SIZE: usize = 16;

/// Block alignment check kept explicit at this cryptographic boundary.
#[inline]
pub(crate) fn is_nonzero_block_aligned(len: usize) -> bool {
    len != 0 && len.is_multiple_of(AES_BLOCK_SIZE)
}

/// Errors surfaced by [`encrypt`] and [`decrypt`].
#[derive(Debug, Error)]
pub enum AesCbcError {
    /// Key must be exactly 16 bytes (AES-128) or 32 bytes (AES-256).
    #[error("invalid key length: expected 16 or 32, got {0}")]
    InvalidKeyLength(usize),
    /// IV must be exactly 16 bytes.
    #[error("invalid IV length: expected 16, got {0}")]
    InvalidIvLength(usize),
    /// Input length is not a non-zero multiple of 16.
    #[error("input not aligned to 16-byte block boundary")]
    NotBlockAligned,
    /// Underlying cipher reported a decrypt failure.
    #[error("decryption failed")]
    DecryptionFailed,
    /// Underlying cipher reported an encrypt failure.
    #[error("encryption failed")]
    EncryptionFailed,
}

/// AES-CBC encrypt. Caller pads; `plaintext.len()` must be a non-zero
/// multiple of 16. IV must be 16 bytes.
pub fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AesCbcError> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(AesCbcError::InvalidIvLength(iv.len()));
    }
    if !is_nonzero_block_aligned(plaintext.len()) {
        return Err(AesCbcError::NotBlockAligned);
    }

    let mut buf = plaintext.to_vec();
    match key.len() {
        16 => {
            let enc = Encryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|_| AesCbcError::InvalidKeyLength(key.len()))?;
            enc.encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(
                &mut buf,
                plaintext.len(),
            )
            .map_err(|_| AesCbcError::EncryptionFailed)?;
        }
        32 => {
            let enc = Encryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|_| AesCbcError::InvalidKeyLength(key.len()))?;
            enc.encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(
                &mut buf,
                plaintext.len(),
            )
            .map_err(|_| AesCbcError::EncryptionFailed)?;
        }
        n => return Err(AesCbcError::InvalidKeyLength(n)),
    }
    Ok(buf)
}

/// AES-CBC decrypt. Output is still PKCS7-padded; caller strips it.
pub fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AesCbcError> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(AesCbcError::InvalidIvLength(iv.len()));
    }
    if !is_nonzero_block_aligned(ciphertext.len()) {
        return Err(AesCbcError::NotBlockAligned);
    }

    let mut buf = ciphertext.to_vec();
    match key.len() {
        16 => {
            let dec = Decryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|_| AesCbcError::InvalidKeyLength(key.len()))?;
            dec.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                .map_err(|_| AesCbcError::DecryptionFailed)?;
        }
        32 => {
            let dec = Decryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|_| AesCbcError::InvalidKeyLength(key.len()))?;
            dec.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                .map_err(|_| AesCbcError::DecryptionFailed)?;
        }
        n => return Err(AesCbcError::InvalidKeyLength(n)),
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 16];
        let plaintext = [0xABu8; 16];

        let ct = encrypt(&key, &iv, &plaintext).unwrap();
        assert_eq!(ct.len(), 16);
        assert_ne!(&ct[..], &plaintext[..]);

        let pt = decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(&pt[..], &plaintext[..]);
    }

    #[test]
    fn test_roundtrip_multi_block() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 16];
        let plaintext = [0xABu8; 48];

        let ct = encrypt(&key, &iv, &plaintext).unwrap();
        assert_eq!(ct.len(), 48);

        let pt = decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(&pt[..], &plaintext[..]);
    }

    #[test]
    fn test_invalid_key_length() {
        // 24-byte (AES-192) keys are not part of the RNS Token spec.
        let key = [0u8; 24];
        let iv = [0u8; 16];
        let data = [0u8; 16];
        assert!(encrypt(&key, &iv, &data).is_err());
    }

    #[test]
    fn test_not_block_aligned() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let data = [0u8; 15];
        assert!(encrypt(&key, &iv, &data).is_err());
    }

    #[test]
    fn test_aes128_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 16];
        let plaintext = [0xABu8; 16];

        let ct = encrypt(&key, &iv, &plaintext).unwrap();
        assert_eq!(ct.len(), 16);
        assert_ne!(&ct[..], &plaintext[..]);

        let pt = decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(&pt[..], &plaintext[..]);
    }

    #[test]
    fn test_aes128_multi_block() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 16];
        let plaintext = [0xABu8; 48];

        let ct = encrypt(&key, &iv, &plaintext).unwrap();
        assert_eq!(ct.len(), 48);

        let pt = decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(&pt[..], &plaintext[..]);
    }

    /// Different key sizes must produce different ciphertexts for the same input.
    #[test]
    fn test_aes128_vs_aes256_distinct_ciphertexts() {
        let key128 = [0x42u8; 16];
        let key256 = [0x42u8; 32];
        let iv = [0x01u8; 16];
        let plaintext = [0xABu8; 16];

        let ct128 = encrypt(&key128, &iv, &plaintext).unwrap();
        let ct256 = encrypt(&key256, &iv, &plaintext).unwrap();
        assert_ne!(ct128, ct256);
    }
}
