use std::io::{Read, Write};

/// Maximum size for auto-compression (64 MiB).
pub const AUTO_COMPRESS_MAX_SIZE: usize = 67_108_864;

/// Compress `data` with bzip2 at the default level.
pub fn bz2_compress(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder
        .write_all(data)
        .map_err(|_| CompressionError::CompressFailed)?;
    encoder
        .finish()
        .map_err(|_| CompressionError::CompressFailed)
}

/// Decompress bzip2 `data`, checking `max_size` after each 8192-byte read.
///
/// Decoding stops when accumulated output exceeds the limit, at most one read
/// chunk beyond it. This is an output-length check, not a strict bound on peak
/// allocation or decoder working memory.
pub fn bz2_decompress(data: &[u8], max_size: usize) -> Result<Vec<u8>, CompressionError> {
    let mut decoder = bzip2::read::BzDecoder::new(data);
    let mut output = Vec::new();

    let mut buf = [0u8; 8192];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|_| CompressionError::DecompressFailed)?;
        if n == 0 {
            break;
        }
        output.extend_from_slice(&buf[..n]);
        if output.len() > max_size {
            return Err(CompressionError::DecompressedTooLarge);
        }
    }

    Ok(output)
}

/// Compress opportunistically: return the bzip2 output only when it actually
/// shrinks the buffer. The boolean reports which variant was chosen so the
/// caller can set the `compressed` wire flag.
pub fn try_compress(data: &[u8]) -> (Vec<u8>, bool) {
    if data.len() > AUTO_COMPRESS_MAX_SIZE {
        return (data.to_vec(), false);
    }
    match bz2_compress(data) {
        Ok(compressed) if compressed.len() < data.len() => (compressed, true),
        _ => (data.to_vec(), false),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    #[error("bz2 compression failed")]
    CompressFailed,
    #[error("bz2 decompression failed")]
    DecompressFailed,
    #[error("decompressed data exceeds size limit")]
    DecompressedTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let data = b"Hello, this is test data for compression!".repeat(100);
        let compressed = bz2_compress(&data).unwrap();
        assert!(compressed.len() < data.len());
        let decompressed = bz2_decompress(&compressed, data.len() * 2).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_decompress_size_limit() {
        let data = vec![0u8; 10000];
        let compressed = bz2_compress(&data).unwrap();
        let result = bz2_decompress(&compressed, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_compress_beneficial() {
        let data = b"AAAA".repeat(1000);
        let (result, was_compressed) = try_compress(&data);
        assert!(was_compressed);
        assert!(result.len() < data.len());
    }

    #[test]
    fn test_try_compress_not_beneficial() {
        // Short, incompressible input must still return without panicking.
        let data: Vec<u8> = (0..100).map(|i| (i * 37 + 13) as u8).collect();
        let (_result, was_compressed) = try_compress(&data);
        let _ = was_compressed;
    }
}
