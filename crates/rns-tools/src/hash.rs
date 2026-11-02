/// Trim surrounding whitespace, remove colons, and decode exactly 16 bytes
/// of hex. This checks representation and length, not a destination's identity
/// or application binding; angle brackets and a `0x` prefix are not accepted.
pub fn parse_dest_hash(input: &str) -> Result<[u8; 16], String> {
    let clean = input.trim().replace(':', "");
    let bytes = hex::decode(&clean).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 16 {
        return Err(format!(
            "expected 16 bytes (32 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

pub fn format_dest_hash(hash: &[u8; 16]) -> String {
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dest_hash() {
        let hex_str = "aabbccddaabbccddaabbccddaabbccdd";
        let hash = parse_dest_hash(hex_str).unwrap();
        assert_eq!(
            hash,
            [
                0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb,
                0xcc, 0xdd
            ]
        );
    }

    #[test]
    fn test_parse_dest_hash_with_colons() {
        let hex_str = "aa:bb:cc:dd:aa:bb:cc:dd:aa:bb:cc:dd:aa:bb:cc:dd";
        let hash = parse_dest_hash(hex_str).unwrap();
        assert_eq!(hash[0], 0xaa);
        assert_eq!(hash[15], 0xdd);
    }

    #[test]
    fn test_parse_dest_hash_wrong_length() {
        assert!(parse_dest_hash("aabbcc").is_err());
    }

    #[test]
    fn test_parse_dest_hash_invalid_hex() {
        assert!(parse_dest_hash("gghhiijjkkllmmnnooppqqrrssttaabb").is_err());
    }

    #[test]
    fn test_format_dest_hash() {
        let hash = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb,
            0xcc, 0xdd,
        ];
        assert_eq!(format_dest_hash(&hash), "aabbccddaabbccddaabbccddaabbccdd");
    }
}
