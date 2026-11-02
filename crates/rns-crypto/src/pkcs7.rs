//! PKCS7 padding for 16-byte block ciphers (AES-CBC).

use alloc::vec::Vec;
use thiserror::Error;

const BLOCK_SIZE: usize = 16;

/// Errors surfaced by [`unpad`].
#[derive(Debug, Error)]
pub enum Pkcs7Error {
    /// Trailing byte is zero, greater than the 16-byte block size, or greater
    /// than the input length.
    #[error("invalid padding: padding byte value {0} exceeds block size {BLOCK_SIZE}")]
    InvalidPaddingValue(u8),
    /// The declared padding length doesn't match the trailing bytes.
    #[error("invalid padding: inconsistent padding bytes")]
    InconsistentPadding,
    /// Input contained zero bytes.
    #[error("invalid padding: empty input")]
    EmptyInput,
}

/// Apply PKCS7 padding for a 16-byte block size.
///
/// Block-aligned inputs are still padded — a full 0x10 block is appended,
/// per the RFC 5652 construction.
pub fn pad(data: &[u8]) -> Vec<u8> {
    let pad_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    let mut out = Vec::with_capacity(data.len() + pad_len);
    out.extend_from_slice(data);
    out.extend(core::iter::repeat_n(pad_len as u8, pad_len));
    out
}

/// Strip PKCS7 padding for a 16-byte block size.
///
/// All padding bytes are validated; a mismatch returns an error. This helper
/// checks the trailing padding only, not the input's total block alignment.
pub fn unpad(data: &[u8]) -> Result<&[u8], Pkcs7Error> {
    if data.is_empty() {
        return Err(Pkcs7Error::EmptyInput);
    }
    let pad_byte = data[data.len() - 1];
    if pad_byte == 0 || pad_byte as usize > BLOCK_SIZE {
        return Err(Pkcs7Error::InvalidPaddingValue(pad_byte));
    }
    let pad_len = pad_byte as usize;
    if pad_len > data.len() {
        return Err(Pkcs7Error::InvalidPaddingValue(pad_byte));
    }
    let start = data.len() - pad_len;
    for &b in &data[start..] {
        if b != pad_byte {
            return Err(Pkcs7Error::InconsistentPadding);
        }
    }
    Ok(&data[..start])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_pad_block_aligned() {
        // Block-aligned input gets a full 0x10 padding block.
        let input = [0u8; 16];
        let padded = pad(&input);
        assert_eq!(padded.len(), 32);
        assert!(padded[16..].iter().all(|&b| b == 16));
    }

    #[test]
    fn test_pad_one_byte() {
        let padded = pad(b"a");
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[0], b'a');
        assert!(padded[1..].iter().all(|&b| b == 15));
    }

    #[test]
    fn test_pad_fifteen_bytes() {
        let input = [0x41u8; 15];
        let padded = pad(&input);
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[15], 1);
    }

    #[test]
    fn test_roundtrip() {
        for len in 0..64 {
            let data = vec![0xABu8; len];
            let padded = pad(&data);
            let unpadded = unpad(&padded).unwrap();
            assert_eq!(unpadded, &data[..]);
        }
    }

    #[test]
    fn test_unpad_empty() {
        assert!(unpad(b"").is_err());
    }

    #[test]
    fn test_unpad_invalid_zero() {
        let mut data = [0u8; 16];
        data[15] = 0;
        assert!(unpad(&data).is_err());
    }

    #[test]
    fn test_unpad_invalid_too_large() {
        let mut data = [0u8; 16];
        data[15] = 17;
        assert!(unpad(&data).is_err());
    }

    #[test]
    fn test_unpad_inconsistent_padding() {
        // Last byte declares 4 pad bytes, but data[12] is not 4.
        let mut data = vec![0x41u8; 16];
        data[15] = 4;
        data[14] = 4;
        data[13] = 4;
        data[12] = 99;
        assert!(matches!(unpad(&data), Err(Pkcs7Error::InconsistentPadding)));
    }
}
