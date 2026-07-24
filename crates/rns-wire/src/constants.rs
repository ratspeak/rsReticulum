//! Shared protocol constants (MTU, hash sizes, header bounds).

/// Maximum Transmission Unit — hard protocol limit.
pub const MTU: usize = 500;

/// Truncated hash length in bits (128 bits = 16 bytes).
pub const TRUNCATED_HASHLENGTH: usize = 128;

/// Full hash length in bits (256 bits = 32 bytes).
pub const HASHLENGTH: usize = 256;

/// Key size in bits (512 bits = 64 bytes: X25519_pub(32) + Ed25519_pub(32)).
pub const KEYSIZE: usize = 512;

/// Signature length in bits (512 bits = 64 bytes).
pub const SIGLENGTH: usize = 512;

/// Token encryption overhead: IV(16) + HMAC(32) = 48 bytes.
pub const TOKEN_OVERHEAD: usize = 48;

/// AES-128 block size.
pub const AES128_BLOCKSIZE: usize = 16;

/// Minimum header size (HEADER_1): flags(1) + hops(1) + dest_hash(16) + context(1) = 19.
pub const HEADER_MINSIZE: usize = 2 + TRUNCATED_HASHLENGTH / 8 + 1;

/// Maximum header size (HEADER_2): flags(1) + hops(1) + transport_id(16) + dest_hash(16) + context(1) = 35.
pub const HEADER_MAXSIZE: usize = 2 + (TRUNCATED_HASHLENGTH / 8) * 2 + 1;

/// Maximum Data Unit: MTU - HEADER_MAXSIZE - IFAC_MIN = 500 - 35 - 1 = 464.
pub const MDU: usize = MTU - HEADER_MAXSIZE - 1;

/// Encrypted link MDU, matching Python `RNS.Link.MDU`:
/// floor((MTU - IFAC_MIN - HEADER_MIN - TOKEN_OVERHEAD) / AES128_BLOCKSIZE)
/// * AES128_BLOCKSIZE - 1 = 431.
pub const LINK_MDU: usize =
    ((MTU - 1 - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1;

/// Maximum plaintext payload for one encrypted packet to a SINGLE destination.
///
/// This is Python `RNS.Packet.ENCRYPTED_MDU`: the general MDU minus identity
/// encryption's ephemeral key and token overhead, rounded to an AES block.
pub const SINGLE_PACKET_ENCRYPTED_MDU: usize =
    ((MDU - TOKEN_OVERHEAD - KEYSIZE / 16) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1;

/// Former name for [`LINK_MDU`].
///
/// Kept as a compatibility alias while downstream users migrate to the
/// unambiguous name.
#[deprecated(since = "1.0.2", note = "use LINK_MDU")]
pub const ENCRYPTED_MDU: usize = LINK_MDU;

/// MDU available to plaintext (unencrypted) payloads.
pub const PLAIN_MDU: usize = MDU;

/// Default per-hop timeout in seconds.
pub const DEFAULT_PER_HOP_TIMEOUT: f64 = 6.0;

/// Name hash length in bytes (80 bits = 10 bytes).
pub const NAME_HASH_LENGTH: usize = 10;

/// Ratchet size in bytes (256 bits = 32 bytes).
pub const RATCHETSIZE: usize = 32;

/// Ratchet count — max retained ratchet keys.
pub const RATCHET_COUNT: usize = 512;

/// Ratchet interval — minimum seconds between rotations.
pub const RATCHET_INTERVAL: u64 = 1800;

/// Ratchet expiry — seconds before received ratchets expire (30 days).
pub const RATCHET_EXPIRY: u64 = 2_592_000;

/// Explicit proof length: packet_hash(32) + signature(64) = 96 bytes.
pub const EXPL_LENGTH: usize = 96;

/// Implicit proof length: signature(64) = 64 bytes.
pub const IMPL_LENGTH: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derived_constants() {
        assert_eq!(HEADER_MINSIZE, 19);
        assert_eq!(HEADER_MAXSIZE, 35);
        assert_eq!(MDU, 464);
        assert_eq!(LINK_MDU, 431);
        assert_eq!(SINGLE_PACKET_ENCRYPTED_MDU, 383);
        assert_eq!(TRUNCATED_HASHLENGTH / 8, 16);
        assert_eq!(HASHLENGTH / 8, 32);
        assert_eq!(KEYSIZE / 8, 64);
        assert_eq!(SIGLENGTH / 8, 64);
    }
}
