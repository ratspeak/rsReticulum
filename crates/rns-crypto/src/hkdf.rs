//! HKDF-SHA256 key derivation (RFC 5869).

use alloc::vec;
use alloc::vec::Vec;
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// Per RFC 5869, HKDF-SHA256 can emit at most 255 * HashLen = 8160 bytes.
const MAX_OUTPUT_LENGTH: usize = 255 * 32;

/// Errors surfaced by [`hkdf_sha256`].
#[derive(Debug, Error)]
pub enum HkdfError {
    /// Requested output length exceeds the RFC 5869 cap (8160 bytes).
    #[error("requested length {0} exceeds maximum HKDF output of {MAX_OUTPUT_LENGTH} bytes")]
    OutputTooLong(usize),
    /// Underlying HKDF expand call returned an error.
    #[error("HKDF expansion failed")]
    ExpansionFailed,
}

/// HKDF-SHA256 key derivation (RFC 5869).
///
/// `length` is capped at 8160 bytes. `salt = None` uses 32 zero bytes as
/// specified by the RFC; `info = None` uses an empty context string. The
/// output is wiped when it is dropped.
pub fn hkdf_sha256(
    length: usize,
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, HkdfError> {
    if length > MAX_OUTPUT_LENGTH {
        return Err(HkdfError::OutputTooLong(length));
    }

    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = Zeroizing::new(vec![0u8; length]);
    hk.expand(info.unwrap_or(b""), &mut okm)
        .map_err(|_| HkdfError::ExpansionFailed)?;
    Ok(okm)
}

/// Derive the 64-byte session key used for RNS link encryption:
/// `HKDF-SHA256(length=64, ikm=shared_secret, salt=identity_hash, info=None)`.
/// The key is expanded straight into its return buffer, which is wiped on drop.
pub fn derive_key_64(shared_secret: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 64]>, HkdfError> {
    let mut okm = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha256>::new(Some(salt), shared_secret)
        .expand(b"", &mut okm[..])
        .map_err(|_| HkdfError::ExpansionFailed)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_rfc5869_vector1() {
        // RFC 5869 Test Case 1.
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let okm = hkdf_sha256(42, &ikm, Some(&salt), Some(&info)).unwrap();
        let expected =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        assert_eq!(hex::encode(&okm), expected);
    }

    #[test]
    fn test_hkdf_max_length_exceeded() {
        let result = hkdf_sha256(MAX_OUTPUT_LENGTH + 1, b"test", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_no_salt() {
        let result = hkdf_sha256(32, b"test_ikm", None, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_derive_key_64() {
        let key = derive_key_64(b"shared_secret", b"salt_value").unwrap();
        assert_eq!(key.len(), 64);
        let cases: [(&[u8], &[u8]); 2] = [(b"shared_secret", b"salt_value"), (&[7; 32], &[9; 16])];
        for (ikm, salt) in cases {
            assert_eq!(
                &derive_key_64(ikm, salt).unwrap()[..],
                &hkdf_sha256(64, ikm, Some(salt), None).unwrap()[..]
            );
        }
    }
}
