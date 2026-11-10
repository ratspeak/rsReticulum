//! HKDF-SHA256 key derivation (RFC 5869).

use alloc::vec;
use alloc::vec::Vec;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

const HASH_LEN: usize = 32;
/// Per RFC 5869, HKDF-SHA256 can emit at most 255 * HashLen = 8160 bytes.
const RFC_MAX_OUTPUT_LENGTH: usize = 255 * HASH_LEN;

type HmacSha256 = Hmac<Sha256>;

/// Errors surfaced by [`hkdf_sha256`].
#[derive(Debug, Error)]
pub enum HkdfError {
    /// Requested output length is zero.
    #[error("invalid HKDF output length 0")]
    InvalidLength,
    /// Underlying HKDF expand call returned an error.
    #[error("HKDF expansion failed")]
    ExpansionFailed,
}

/// HKDF-SHA256 key derivation (RFC 5869).
///
/// `salt = None` uses 32 zero bytes as specified by the RFC; `info = None`
/// uses an empty context string. The output is wiped when it is dropped.
/// Lengths above the RFC's 255-block bound are accepted: the reference
/// implementation wraps its one-byte block counter, and IFAC masks for large
/// frames depend on that.
pub fn hkdf_sha256(
    length: usize,
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, HkdfError> {
    if length == 0 {
        return Err(HkdfError::InvalidLength);
    }
    let info = info.unwrap_or(b"");
    let mut okm = Zeroizing::new(vec![0u8; length]);
    if length <= RFC_MAX_OUTPUT_LENGTH {
        Hkdf::<Sha256>::new(salt, ikm)
            .expand(info, &mut okm)
            .map_err(|_| HkdfError::ExpansionFailed)?;
        return Ok(okm);
    }

    let (prk, _) = Hkdf::<Sha256>::extract(salt, ikm);
    let keyed = HmacSha256::new_from_slice(&prk).map_err(|_| HkdfError::ExpansionFailed)?;
    let mut previous = Zeroizing::new([0u8; HASH_LEN]);
    for (index, chunk) in okm.chunks_mut(HASH_LEN).enumerate() {
        let mut mac = keyed.clone();
        if index > 0 {
            mac.update(&previous[..]);
        }
        mac.update(info);
        mac.update(&[(index as u8).wrapping_add(1)]);
        previous.copy_from_slice(&mac.finalize().into_bytes());
        chunk.copy_from_slice(&previous[..chunk.len()]);
    }
    Ok(okm)
}

/// Derive 64 key bytes with the caller-provided salt:
/// `HKDF-SHA256(length=64, ikm=shared_secret, salt=salt, info=None)`.
/// Identity encryption passes the identity hash. Link key derivation instead
/// selects its key length by mode and uses the Link ID as salt.
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
    fn test_hkdf_rejects_zero_length() {
        assert!(matches!(
            hkdf_sha256(0, b"test", None, None),
            Err(HkdfError::InvalidLength)
        ));
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
