//! PIV management-key crypto: ECB single/multi-block for the witness/challenge
//! mutual authentication. Dispatch is on the management-key *algorithm* byte, not
//! the key length — AES-192 and TDES both use 24-byte keys, but differ in block
//! size (AES 16, TDES 8). TDES (3DES EDE3) is the pre-5.7 YubiKey factory default.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes::{Aes128, Aes192, Aes256};
use des::TdesEde3;

use crate::apdu;
use crate::error::RatkeyError;

const AES_BLOCK: usize = 16;
const DES_BLOCK: usize = 8;

/// Required key length for a management-key algorithm, or `None` if unsupported.
pub fn key_len(alg: u8) -> Option<usize> {
    match alg {
        apdu::MGMT_ALG_TDES => Some(24), // 3DES EDE3: three 8-byte DES subkeys
        apdu::MGMT_ALG_AES128 => Some(16),
        apdu::MGMT_ALG_AES192 => Some(24),
        apdu::MGMT_ALG_AES256 => Some(32),
        _ => None,
    }
}

/// ECB block size (challenge length) for a supported algorithm.
pub fn block_len(alg: u8) -> Option<usize> {
    match alg {
        apdu::MGMT_ALG_TDES => Some(DES_BLOCK),
        apdu::MGMT_ALG_AES128 | apdu::MGMT_ALG_AES192 | apdu::MGMT_ALG_AES256 => Some(AES_BLOCK),
        _ => None,
    }
}

fn check(alg: u8, key: &[u8], data: &[u8]) -> Result<(), RatkeyError> {
    let n = key_len(alg).ok_or_else(|| {
        RatkeyError::UnsupportedDevice(format!("unsupported management-key algorithm 0x{alg:02X}"))
    })?;
    if key.len() != n {
        return Err(RatkeyError::InvalidHwid(format!(
            "management key length {} does not match algorithm 0x{alg:02X} (expected {n})",
            key.len()
        )));
    }
    let block = block_len(alg).expect("supported alg has a block size");
    if data.is_empty() || data.len() % block != 0 {
        return Err(RatkeyError::InvalidHwid(format!(
            "management-key ECB input not block-aligned: {} bytes (block {block})",
            data.len()
        )));
    }
    Ok(())
}

pub fn ecb_encrypt(alg: u8, key: &[u8], data: &[u8]) -> Result<Vec<u8>, RatkeyError> {
    check(alg, key, data)?;
    let mut out = data.to_vec();
    process(alg, key, &mut out, false)?;
    Ok(out)
}

pub fn ecb_decrypt(alg: u8, key: &[u8], data: &[u8]) -> Result<Vec<u8>, RatkeyError> {
    check(alg, key, data)?;
    let mut out = data.to_vec();
    process(alg, key, &mut out, true)?;
    Ok(out)
}

fn process(alg: u8, key: &[u8], buf: &mut [u8], decrypt: bool) -> Result<(), RatkeyError> {
    macro_rules! run {
        ($cipher:ty, $block:expr) => {{
            let cipher = <$cipher>::new_from_slice(key)
                .map_err(|_| RatkeyError::InvalidHwid("invalid management key".to_string()))?;
            for chunk in buf.chunks_mut($block) {
                let block = GenericArray::from_mut_slice(chunk);
                if decrypt {
                    cipher.decrypt_block(block);
                } else {
                    cipher.encrypt_block(block);
                }
            }
        }};
    }
    match alg {
        apdu::MGMT_ALG_TDES => run!(TdesEde3, DES_BLOCK),
        apdu::MGMT_ALG_AES128 => run!(Aes128, AES_BLOCK),
        apdu::MGMT_ALG_AES192 => run!(Aes192, AES_BLOCK),
        apdu::MGMT_ALG_AES256 => run!(Aes256, AES_BLOCK),
        _ => {
            return Err(RatkeyError::UnsupportedDevice(format!(
                "unsupported management-key algorithm 0x{alg:02X}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS-197 Appendix C.2 AES-192 known-answer vector.
    const KAT_KEY: [u8; 24] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];
    const KAT_PT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const KAT_CT: [u8; 16] = [
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71,
        0x91,
    ];

    #[test]
    fn test_aes192_kat_encrypt() {
        assert_eq!(
            ecb_encrypt(apdu::MGMT_ALG_AES192, &KAT_KEY, &KAT_PT).unwrap(),
            KAT_CT.to_vec()
        );
    }

    #[test]
    fn test_aes192_kat_decrypt() {
        assert_eq!(
            ecb_decrypt(apdu::MGMT_ALG_AES192, &KAT_KEY, &KAT_CT).unwrap(),
            KAT_PT.to_vec()
        );
    }

    // 3DES EDE3 with three identical 8-byte subkeys reduces to single-DES, so the
    // canonical FIPS-81 single-DES ECB vector is a known-answer for our EDE3 path:
    //   DES(0x0123456789ABCDEF, "Now is t") = 0x3FA40E8A984D4815.
    const TDES_KAT_KEY: [u8; 24] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
        0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    ];
    const TDES_KAT_PT: [u8; 8] = [0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74];
    const TDES_KAT_CT: [u8; 8] = [0x3F, 0xA4, 0x0E, 0x8A, 0x98, 0x4D, 0x48, 0x15];

    #[test]
    fn test_round_trip_all_aes() {
        for (alg, klen) in [
            (apdu::MGMT_ALG_AES128, 16usize),
            (apdu::MGMT_ALG_AES192, 24),
            (apdu::MGMT_ALG_AES256, 32),
        ] {
            let key = vec![0x5Au8; klen];
            let pt = [0x42u8; 16];
            let ct = ecb_encrypt(alg, &key, &pt).unwrap();
            assert_ne!(ct, pt.to_vec());
            assert_eq!(ecb_decrypt(alg, &key, &ct).unwrap(), pt.to_vec());
        }
    }

    #[test]
    fn test_wrong_key_length_rejected() {
        // AES-192 with a 16-byte key (would silently be AES-128 if not checked).
        assert!(ecb_encrypt(apdu::MGMT_ALG_AES192, &[0u8; 16], &[0u8; 16]).is_err());
    }

    #[test]
    fn test_tdes_kat() {
        assert_eq!(key_len(apdu::MGMT_ALG_TDES), Some(24));
        assert_eq!(block_len(apdu::MGMT_ALG_TDES), Some(8));
        assert_eq!(
            ecb_encrypt(apdu::MGMT_ALG_TDES, &TDES_KAT_KEY, &TDES_KAT_PT).unwrap(),
            TDES_KAT_CT.to_vec()
        );
        assert_eq!(
            ecb_decrypt(apdu::MGMT_ALG_TDES, &TDES_KAT_KEY, &TDES_KAT_CT).unwrap(),
            TDES_KAT_PT.to_vec()
        );
    }

    #[test]
    fn test_tdes_round_trip_distinct_keys() {
        // Three distinct subkeys exercise the real EDE3 / DED3 inverse, not the
        // degenerate single-DES reduction.
        let mut key = [0u8; 24];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        let pt = [0x42u8; 8];
        let ct = ecb_encrypt(apdu::MGMT_ALG_TDES, &key, &pt).unwrap();
        assert_ne!(ct, pt.to_vec());
        assert_eq!(
            ecb_decrypt(apdu::MGMT_ALG_TDES, &key, &ct).unwrap(),
            pt.to_vec()
        );
    }

    #[test]
    fn test_non_block_aligned_rejected() {
        assert!(ecb_encrypt(apdu::MGMT_ALG_AES192, &KAT_KEY, &[0u8; 15]).is_err());
        assert!(ecb_encrypt(apdu::MGMT_ALG_AES192, &KAT_KEY, &[]).is_err());
        // TDES uses an 8-byte block: 8 is valid, 7 is not.
        assert!(ecb_encrypt(apdu::MGMT_ALG_TDES, &TDES_KAT_KEY, &[0u8; 8]).is_ok());
        assert!(ecb_encrypt(apdu::MGMT_ALG_TDES, &TDES_KAT_KEY, &[0u8; 7]).is_err());
    }
}
