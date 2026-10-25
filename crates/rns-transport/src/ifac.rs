//! Interface Access Control (IFAC) signing and verification.
//!
//! IFAC authenticates every packet on a closed-membership interface. A shared
//! interface key drives both an Ed25519 signing key (the tag is the last
//! `ifac_size` bytes of the signature) and an HKDF-XOR mask over the header
//! and payload — the tag itself is left in the clear because receivers need it
//! to regenerate the mask. Packets without a valid tag are dropped before any
//! routing decision, so unauthorised peers can neither send nor decode traffic.
//!
//! Wire layout matches the Python reference (`Transport.transmit` /
//! `Transport.inbound`): `[flags|0x80, hops, tag(ifac_size), payload]` with
//! everything except the tag masked.

use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::hkdf::hkdf_sha256;
use subtle::ConstantTimeEq;

/// Bit 7 of byte 0 signals IFAC presence, regardless of `ifac_size`.
const IFAC_FLAG: u8 = 0x80;

/// RFC5869 SHA256 expansion bound, including the IFAC tag itself.
pub const MAX_IFAC_WIRE_BYTES: usize = 255 * 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IfacSignError {
    #[error("IFAC tag size must be 1..=64")]
    InvalidTagSize,
    #[error("packet is shorter than the two-byte header")]
    ShortPacket,
    #[error("complete IFAC packet exceeds the 8160-byte mask expansion limit")]
    PacketTooLarge,
}

/// Stamp a packet with its IFAC tag and XOR mask.
///
/// `ifac_key` is the 64-byte derived interface key: bytes [32..64) seed the
/// Ed25519 signer, and the full key acts as HKDF salt (Python uses
/// `interface.ifac_key` in both roles, so the split must not change).
///
/// # Panics
///
/// Panics for a tag outside 1..=64, a packet shorter than two bytes, or a
/// complete IFAC packet above 8160 bytes. Use [`try_ifac_sign`] when metadata
/// or packet size is caller-provided. Transport egress uses the checked form.
pub fn ifac_sign(packet: &[u8], ifac_key: &[u8; 64], ifac_size: usize) -> Vec<u8> {
    try_ifac_sign(packet, ifac_key, ifac_size).expect("invalid IFAC signing arguments")
}

/// Checked packet admission, suitable for caller-provided metadata and bytes.
pub fn try_ifac_sign(
    packet: &[u8],
    ifac_key: &[u8; 64],
    ifac_size: usize,
) -> Result<Vec<u8>, IfacSignError> {
    if !(1..=64).contains(&ifac_size) {
        return Err(IfacSignError::InvalidTagSize);
    }
    if packet.len() < 2 {
        return Err(IfacSignError::ShortPacket);
    }
    let mask_len = packet
        .len()
        .checked_add(ifac_size)
        .filter(|len| *len <= MAX_IFAC_WIRE_BYTES)
        .ok_or(IfacSignError::PacketTooLarge)?;

    let signing_seed: &[u8; 32] = ifac_key[32..64]
        .try_into()
        .expect("ifac_key is [u8; 64]; slice [32..64] is always 32 bytes");
    let ed_key = Ed25519PrivateKey::from_bytes(signing_seed);
    let signature = ed_key.sign(packet);
    let tag = &signature[64 - ifac_size..];

    let mask = hkdf_sha256(mask_len, tag, Some(ifac_key), None)
        .map_err(|_| IfacSignError::PacketTooLarge)?;

    let mut new_raw = Vec::with_capacity(2 + ifac_size + packet.len() - 2);
    new_raw.push(packet[0] | IFAC_FLAG);
    new_raw.push(packet[1]);
    new_raw.extend_from_slice(tag);
    new_raw.extend_from_slice(&packet[2..]);

    // Mask header and payload; leave the tag bytes (indices 2..2+ifac_size)
    // in the clear so the receiver can regenerate the same mask. The IFAC
    // flag must survive masking, so it is re-OR'd onto byte 0.
    let mut masked_raw = Vec::with_capacity(new_raw.len());
    for (i, &byte) in new_raw.iter().enumerate() {
        if i == 0 {
            masked_raw.push((byte ^ mask[i]) | IFAC_FLAG);
        } else if i == 1 || i > ifac_size + 1 {
            masked_raw.push(byte ^ mask[i]);
        } else {
            masked_raw.push(byte);
        }
    }

    Ok(masked_raw)
}

/// Strip and authenticate an IFAC-stamped packet, returning the plain inner
/// form when the tag matches. `None` on any failure — callers should drop the
/// packet silently to avoid leaking membership probes.
pub fn ifac_verify(raw: &[u8], ifac_key: &[u8; 64], ifac_size: usize) -> Option<Vec<u8>> {
    if ifac_size == 0 || ifac_size > 64 {
        return None;
    }
    if raw.len() <= 2 + ifac_size {
        return None;
    }

    if raw[0] & IFAC_FLAG == 0 {
        return None;
    }

    let ifac = &raw[2..2 + ifac_size];

    let mask = hkdf_sha256(raw.len(), ifac, Some(ifac_key), None).ok()?;

    let mut unmasked_raw = Vec::with_capacity(raw.len());
    for (i, &byte) in raw.iter().enumerate() {
        if i <= 1 || i > ifac_size + 1 {
            unmasked_raw.push(byte ^ mask[i]);
        } else {
            unmasked_raw.push(byte);
        }
    }

    let new_header = [unmasked_raw[0] & !IFAC_FLAG, unmasked_raw[1]];

    let mut new_raw = Vec::with_capacity(2 + raw.len() - 2 - ifac_size);
    new_raw.extend_from_slice(&new_header);
    new_raw.extend_from_slice(&unmasked_raw[2 + ifac_size..]);

    let signing_seed: &[u8; 32] = ifac_key[32..64]
        .try_into()
        .expect("ifac_key is [u8; 64]; slice [32..64] is always 32 bytes");
    let ed_key = Ed25519PrivateKey::from_bytes(signing_seed);
    let expected_sig = ed_key.sign(&new_raw);
    let expected_ifac = &expected_sig[64 - ifac_size..];

    // Constant-time compare — an early-exit would leak tag prefix bytes.
    if ifac.ct_eq(expected_ifac).into() {
        Some(new_raw)
    } else {
        None
    }
}

/// Whether a raw packet carries the IFAC flag. Cheap pre-check to avoid
/// running the full verify path on clear-interface traffic.
pub fn has_ifac_flag(raw: &[u8]) -> bool {
    !raw.is_empty() && raw[0] & IFAC_FLAG != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_ifac_key() -> [u8; 64] {
        rns_identity::ifac::derive_ifac_key(Some("testnet"), Some("password")).unwrap()
    }

    #[test]
    fn test_ifac_sign_sets_flag() {
        let packet = vec![0x01, 0x00, 0xAA, 0xBB];
        let ifac_key = make_test_ifac_key();
        let ifac_size = 2;

        let signed = ifac_sign(&packet, &ifac_key, ifac_size);

        assert_eq!(signed.len(), ifac_size + packet.len());
        assert!(signed[0] & 0x80 != 0);
    }

    #[test]
    fn test_ifac_roundtrip() {
        let packet = {
            let mut p = vec![0x01, 0x03];
            p.extend_from_slice(&[0xAA; 20]);
            p
        };
        let ifac_key = make_test_ifac_key();
        let ifac_size = 4;

        let signed = ifac_sign(&packet, &ifac_key, ifac_size);
        let verified = ifac_verify(&signed, &ifac_key, ifac_size);

        assert!(verified.is_some());
        assert_eq!(verified.unwrap(), packet);
    }

    /// Asymmetry documentation — `ifac_sign` accepts `packet.len() >= 2`
    /// (header-only packets with no payload), but `ifac_verify` requires
    /// `raw.len() > 2 + ifac_size`, i.e. at least one payload byte after
    /// the tag. Proptest shrank a failing round-trip to this boundary
    /// case. In practice, production packets always carry a destination
    /// hash (≥16 bytes), so the asymmetry is invisible — but it's real
    /// and worth locking in so a later refactor doesn't silently change
    /// behavior.
    #[test]
    fn test_ifac_verify_rejects_header_only_packet() {
        let packet = vec![0u8, 0u8]; // 2-byte "header only" input
        let key = [0u8; 64];
        let signed = ifac_sign(&packet, &key, 1);
        assert_eq!(signed.len(), 2 + 1, "signed = header + tag, no payload");
        // verify's minimum-size gate rejects this before any crypto work.
        assert_eq!(ifac_verify(&signed, &key, 1), None);
    }

    #[test]
    fn test_ifac_verify_wrong_key() {
        let packet = {
            let mut p = vec![0x01, 0x03];
            p.extend_from_slice(&[0xAA; 20]);
            p
        };
        let ifac_key = make_test_ifac_key();
        let wrong_key = rns_identity::ifac::derive_ifac_key(Some("wrong"), Some("key")).unwrap();
        let ifac_size = 4;

        let signed = ifac_sign(&packet, &ifac_key, ifac_size);
        let verified = ifac_verify(&signed, &wrong_key, ifac_size);

        assert!(verified.is_none());
    }

    #[test]
    fn test_ifac_verify_tampered() {
        let packet = {
            let mut p = vec![0x01, 0x03];
            p.extend_from_slice(&[0xAA; 20]);
            p
        };
        let ifac_key = make_test_ifac_key();
        let ifac_size = 4;

        let mut signed = ifac_sign(&packet, &ifac_key, ifac_size);
        if signed.len() > ifac_size + 3 {
            signed[ifac_size + 3] ^= 0xFF;
        }
        let verified = ifac_verify(&signed, &ifac_key, ifac_size);

        assert!(verified.is_none());
    }

    #[test]
    fn test_ifac_verify_no_flag() {
        let packet = vec![0x01, 0x03, 0xAA, 0xBB, 0xCC, 0xDD];
        let ifac_key = make_test_ifac_key();
        let ifac_size = 4;

        let verified = ifac_verify(&packet, &ifac_key, ifac_size);
        assert!(verified.is_none());
    }

    #[test]
    fn test_ifac_verify_too_short() {
        let ifac_key = make_test_ifac_key();
        let ifac_size = 4;

        let verified = ifac_verify(&[0x80, 0x01], &ifac_key, ifac_size);
        assert!(verified.is_none());
    }

    #[test]
    fn test_has_ifac_flag() {
        assert!(!has_ifac_flag(&[0x00, 0x01]));
        assert!(has_ifac_flag(&[0x80, 0x01]));
        assert!(has_ifac_flag(&[0x81, 0x01]));
        assert!(!has_ifac_flag(&[]));
    }

    #[test]
    fn test_ifac_different_sizes() {
        let packet = {
            let mut p = vec![0x01, 0x03];
            p.extend_from_slice(&[0xAA; 20]);
            p
        };
        let ifac_key = make_test_ifac_key();

        for ifac_size in [1, 2, 4, 8, 16] {
            let signed = ifac_sign(&packet, &ifac_key, ifac_size);
            assert_eq!(signed.len(), ifac_size + packet.len());

            let verified = ifac_verify(&signed, &ifac_key, ifac_size);
            assert!(verified.is_some(), "failed for ifac_size={}", ifac_size);
            assert_eq!(verified.unwrap(), packet);
        }
    }

    #[test]
    fn test_ifac_masking_applied() {
        let packet = vec![0x01, 0x03, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ifac_key = make_test_ifac_key();
        let ifac_size = 4;

        let signed = ifac_sign(&packet, &ifac_key, ifac_size);

        let payload_start = 2 + ifac_size;
        let original_payload = &packet[2..];
        let signed_payload = &signed[payload_start..];
        assert_ne!(
            original_payload, signed_payload,
            "masking should change payload bytes"
        );
    }

    #[test]
    fn test_ifac_flag_byte_preserved_after_roundtrip() {
        for flags_byte in [0x00, 0x01, 0x7F, 0x3C, 0x55] {
            let packet = vec![flags_byte, 0x03, 0xAA, 0xBB, 0xCC, 0xDD];
            let ifac_key = make_test_ifac_key();
            let ifac_size = 4;

            let signed = ifac_sign(&packet, &ifac_key, ifac_size);
            let verified = ifac_verify(&signed, &ifac_key, ifac_size).unwrap();
            assert_eq!(
                verified[0], flags_byte,
                "flags byte should be preserved for 0x{:02x}",
                flags_byte
            );
        }
    }

    // Proptest round-trips over arbitrary (packet, key, ifac_size) tuples.
    // Existing tests cover a handful of fixed values; this widens to the
    // interesting axes at once, catching masking / tag-truncation bugs
    // that depend on the interaction between payload bytes and key.
    use proptest::prelude::*;

    // Bit 7 of byte 0 is the IFAC flag on the wire; real packets always
    // have it clear (reserved bit per `flags.rs`). Enforcing this in the
    // proptest generator matches the actual input space — an all-1s first
    // byte would have its flag bit overwritten by `ifac_sign`, violating
    // the round-trip invariant the rest of the protocol guarantees.
    fn any_packet_first_byte() -> impl Strategy<Value = u8> {
        0u8..=0x7F
    }

    proptest! {
        #[test]
        fn proptest_ifac_roundtrip(
            first_byte in any_packet_first_byte(),
            // At least 2 "rest" bytes so raw.len() = 2 + ifac_size + rest.len()
            // > 2 + ifac_size — the verify minimum. See
            // test_ifac_verify_rejects_header_only_packet for the boundary.
            rest in proptest::collection::vec(any::<u8>(), 2..=254),
            ifac_key: [u8; 64],
            ifac_size in 1usize..=32,
        ) {
            let mut packet = Vec::with_capacity(1 + rest.len());
            packet.push(first_byte);
            packet.extend_from_slice(&rest);

            let signed = ifac_sign(&packet, &ifac_key, ifac_size);

            // IFAC flag must be present on the signed output.
            prop_assert!(has_ifac_flag(&signed), "ifac flag must be set after sign");

            // Verify with the same key must recover the exact original bytes.
            let verified = ifac_verify(&signed, &ifac_key, ifac_size)
                .expect("verify with correct key must succeed");
            prop_assert_eq!(verified, packet);
        }

        #[test]
        fn proptest_ifac_wrong_key_rejects(
            first_byte in any_packet_first_byte(),
            rest in proptest::collection::vec(any::<u8>(), 2..=127),
            key_a: [u8; 64],
            key_b: [u8; 64],
            // ifac_size >= 8 gives a 1/2^64 false-accept rate with a
            // random wrong key. Below that (esp. ifac_size=1 = 0.4%),
            // the proptest's 256 cases hit collisions by luck — that's
            // the inherent weakness of a 1-byte MAC, not a verify bug.
            ifac_size in 8usize..=16,
        ) {
            // Reject when any byte of the key differs — if the two generated
            // keys happen to be identical (astronomically rare), the test is
            // meaningless so we skip it.
            prop_assume!(key_a != key_b);

            let mut packet = Vec::with_capacity(1 + rest.len());
            packet.push(first_byte);
            packet.extend_from_slice(&rest);

            let signed = ifac_sign(&packet, &key_a, ifac_size);
            prop_assert!(
                ifac_verify(&signed, &key_b, ifac_size).is_none(),
                "verify with a different key must return None"
            );
        }
    }
}
