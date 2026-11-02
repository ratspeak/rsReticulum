//! Packet hashes exclude the hop counter and routing-only fields, so forwarding
//! does not change them. These helpers do not validate packet shape: pass a
//! parsed, nonempty packet and its matching header type.

use alloc::vec::Vec;
use rns_crypto::sha::truncated_hash;

use crate::constants::TRUNCATED_HASHLENGTH;
use crate::flags::HeaderType;

/// Extract the portion of a raw packet that contributes to its hash.
///
/// The hop counter, routing-only flag bits, and (for Header2) the transport
/// ID are excluded so a packet's hash is stable across forwarding.
///
/// # Panics
///
/// Panics if `raw` is empty. Short nonempty inputs are hashed without validation.
pub fn get_hashable_part(raw: &[u8], header_type: HeaderType) -> Vec<u8> {
    let mut hashable = Vec::new();

    // Only the lower nibble of flags is hash-stable (upper bits carry routing state).
    hashable.push(raw[0] & 0x0F);

    match header_type {
        HeaderType::Header2 => {
            // Skip flags + hops + transport_id.
            let skip = (TRUNCATED_HASHLENGTH / 8) + 2;
            if raw.len() > skip {
                hashable.extend_from_slice(&raw[skip..]);
            }
        }
        HeaderType::Header1 => {
            // Skip flags + hops.
            if raw.len() > 2 {
                hashable.extend_from_slice(&raw[2..]);
            }
        }
    }

    hashable
}

/// Full SHA-256 hash of the hashable portion of a raw packet.
///
/// Equivalent to `sha256(get_hashable_part(raw, header_type))` but streams
/// directly into the hasher to avoid an intermediate allocation.
///
/// # Panics
///
/// Panics if `raw` is empty. See the module-level input requirements.
pub fn packet_hash(raw: &[u8], header_type: HeaderType) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update([raw[0] & 0x0F]);
    let skip = match header_type {
        HeaderType::Header2 => (TRUNCATED_HASHLENGTH / 8) + 2,
        HeaderType::Header1 => 2,
    };
    if raw.len() > skip {
        hasher.update(&raw[skip..]);
    }
    hasher.finalize().into()
}

/// [`packet_hash`] truncated to the first 16 bytes.
///
/// # Panics
///
/// Panics if `raw` is empty. See the module-level input requirements.
pub fn truncated_packet_hash(raw: &[u8], header_type: HeaderType) -> [u8; 16] {
    let full = packet_hash(raw, header_type);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Return both full and truncated packet hashes from a single SHA-256 pass.
///
/// # Panics
///
/// Panics if `raw` is empty. See the module-level input requirements.
pub fn packet_hash_pair(raw: &[u8], header_type: HeaderType) -> ([u8; 32], [u8; 16]) {
    let full = packet_hash(raw, header_type);
    let mut trunc = [0u8; 16];
    trunc.copy_from_slice(&full[..16]);
    (full, trunc)
}

/// Derive the link id of a link-request packet.
///
/// Hashes the lower flags nibble, destination hash, context, and the first
/// 64 payload bytes (X25519 || Ed25519 public keys), then truncates SHA-256 to
/// 16 bytes. A trailing signalling field does not change the ID.
///
/// This helper does not validate request length or cipher policy. Use
/// [`crate::link_signalling::parse_request_signalling`] to check the payload
/// shape and signalling domain before admitting a request.
///
/// # Panics
///
/// Panics if `raw` is empty. See the module-level input requirements.
pub fn link_id_from_raw(raw: &[u8], header_type: HeaderType) -> [u8; 16] {
    const ECPUBSIZE: usize = 64;
    let mut hashable = get_hashable_part(raw, header_type);
    // Hashable layout: flags_nibble(1) || dest_hash(16) || context(1) || payload.
    let header_in_hashable = 1 + 16 + 1;
    let data_in_hashable = hashable.len().saturating_sub(header_in_hashable);
    if data_in_hashable > ECPUBSIZE {
        let diff = data_in_hashable - ECPUBSIZE;
        hashable.truncate(hashable.len() - diff);
    }
    truncated_hash(&hashable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_hashable_part_header1() {
        let mut raw = vec![0u8; 19];
        raw[0] = 0x71;
        raw[1] = 5;

        let hashable = get_hashable_part(&raw, HeaderType::Header1);
        // Upper nibble of flags is stripped.
        assert_eq!(hashable[0], 0x01);
        assert_eq!(hashable.len(), 1 + 17);
    }

    #[test]
    fn test_hashable_part_header2() {
        let mut raw = vec![0u8; 35];
        raw[0] = 0x50;

        let hashable = get_hashable_part(&raw, HeaderType::Header2);
        assert_eq!(hashable[0], 0x00);
        // dest_hash(16) + context(1) survive; transport_id is skipped.
        assert_eq!(hashable.len(), 1 + 17);
    }

    #[test]
    fn test_same_hash_different_routing() {
        // Hop count is routing metadata and must not influence the hash.
        let dest = [0xAA; 16];
        let context = 0x00u8;
        let data = [0xBB; 10];

        let mut h1_raw = Vec::new();
        h1_raw.push(0x00);
        h1_raw.push(3);
        h1_raw.extend_from_slice(&dest);
        h1_raw.push(context);
        h1_raw.extend_from_slice(&data);

        let mut h1_raw2 = h1_raw.clone();
        h1_raw2[1] = 7;

        let hash1 = packet_hash(&h1_raw, HeaderType::Header1);
        let hash2 = packet_hash(&h1_raw2, HeaderType::Header1);
        assert_eq!(hash1, hash2, "hops should not affect hash");
    }

    #[test]
    fn test_truncated_hash_length() {
        let raw = vec![0u8; 19];
        let hash = truncated_packet_hash(&raw, HeaderType::Header1);
        assert_eq!(hash.len(), 16);
    }
}
