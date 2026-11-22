//! The ble-reticulum link protocol, central side: how Columba phones, the
//! ble-reticulum Linux interface and RTNode firmware carry Reticulum packets
//! over the `37145b00-442d-4a94-917f-8f42c5da28e3` GATT service.
//!
//! The protocol is torlando-tech's (<https://github.com/torlando-tech/ble-reticulum>,
//! `BLE_PROTOCOL_v2.2.md`). A peripheral that speaks it has a readable
//! Identity characteristic (`…28e6`) beside RX (`…28e5`) and TX (`…28e4`);
//! the BLE Peer interface uses this module for a central link to such a
//! peripheral and its own framing for every other link.
//!
//! ## Handshake
//!
//! 1. Read the Identity characteristic: the peripheral's 16-byte identity.
//! 2. Subscribe to TX.
//! 3. Write 16 bytes to RX: the central's identity. Until it has them the
//!    peripheral discards what the central writes and sends it nothing.
//!
//! The identity a central sends names the link, not the user: peers key
//! their per-peer state by it and drop an older link that carries the same
//! one. The interface therefore sends a random value made once per interface
//! start ([`session_identity`]), stable across reconnects and unrelated to any
//! Reticulum identity, so the handshake hands a peripheral no lasting
//! identifier.
//!
//! ## Frames
//!
//! Every packet travels as one or more fragments, each one characteristic
//! value: `[type][sequence u16 BE][total u16 BE][data]`, type `01` for the
//! first fragment, `02` for a middle one and `03` for the last. A packet that
//! fits one value is still framed, as `01 0000 0001`. A value of the single
//! byte `00` is a keepalive; each side sends one after 15 s without sending.

use std::time::{Duration, Instant};

/// Length of the identity each side presents.
pub(crate) const IDENTITY_LEN: usize = 16;
pub(crate) type Identity = [u8; IDENTITY_LEN];

/// A characteristic value that only says the link is alive.
pub(crate) const KEEPALIVE_FRAME: [u8; 1] = [0x00];
/// Silence after which a side sends [`KEEPALIVE_FRAME`]. Columba on
/// reticulum-kt drops a peer it has heard nothing from for 45 s.
#[cfg_attr(any(target_os = "ios", target_os = "macos"), allow(dead_code))]
pub(crate) const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

const TYPE_START: u8 = 0x01;
const TYPE_CONTINUE: u8 = 0x02;
const TYPE_END: u8 = 0x03;
const HEADER_LEN: usize = 5;

/// Smallest characteristic value every link carries (ATT MTU 23).
const MIN_VALUE_LEN: usize = 20;
/// Largest characteristic value GATT allows. RTNode truncates a longer write.
const MAX_VALUE_LEN: usize = 512;
/// Largest packet a reassembly may produce: Reticulum packets are at most
/// 500 bytes, and RTNode holds 512.
const MAX_PACKET_LEN: usize = 512;
/// A packet whose fragments stop arriving is dropped after this long.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// The peripheral's identity as its Identity characteristic gives it. Columba
/// reads the same characteristic and carries on without an identity when the
/// value is not 16 bytes, so a malformed one is `None` rather than an error.
#[cfg_attr(any(target_os = "ios", target_os = "macos"), allow(dead_code))]
pub(crate) fn parse_identity(value: &[u8]) -> Option<Identity> {
    let identity: Identity = value.try_into().ok()?;
    identity.iter().any(|byte| *byte != 0).then_some(identity)
}

/// The identity this interface presents to ble-reticulum peripherals until it
/// stops. See the module documentation for why it is random.
#[cfg_attr(any(target_os = "ios", target_os = "macos"), allow(dead_code))]
pub(crate) fn session_identity() -> Identity {
    loop {
        let identity: Identity = rand::random();
        if identity.iter().any(|byte| *byte != 0) {
            return identity;
        }
    }
}

pub(crate) fn is_keepalive(frame: &[u8]) -> bool {
    frame == KEEPALIVE_FRAME
}

/// Fragments of `packet` for a link whose characteristic values hold
/// `value_len` bytes (ATT MTU − 3). Empty when there is nothing to send or the
/// packet cannot be counted in the header's 16 bits.
#[cfg_attr(any(target_os = "ios", target_os = "macos"), allow(dead_code))]
pub(crate) fn fragment_packet(packet: &[u8], value_len: usize) -> Vec<Vec<u8>> {
    let chunk_len = value_len.clamp(MIN_VALUE_LEN, MAX_VALUE_LEN) - HEADER_LEN;
    let Ok(total) = u16::try_from(packet.len().div_ceil(chunk_len)) else {
        return Vec::new();
    };
    packet
        .chunks(chunk_len)
        .zip(0u16..)
        .map(|(chunk, sequence)| {
            let kind = if sequence == 0 {
                TYPE_START
            } else if sequence == total - 1 {
                TYPE_END
            } else {
                TYPE_CONTINUE
            };
            let mut fragment = Vec::with_capacity(HEADER_LEN + chunk.len());
            fragment.push(kind);
            fragment.extend_from_slice(&sequence.to_be_bytes());
            fragment.extend_from_slice(&total.to_be_bytes());
            fragment.extend_from_slice(chunk);
            fragment
        })
        .collect()
}

/// What one received characteristic value was.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    Keepalive,
    /// A fragment of a packet that is not complete yet.
    Partial,
    /// The last fragment of a packet; the packet.
    Packet(Vec<u8>),
    /// Not a frame of this protocol, or one that does not continue the packet
    /// being received. Any packet being received is dropped with it.
    Invalid(&'static str),
}

/// Reassembles the fragments one peer sends. GATT delivers a link's values in
/// order, so a fragment that is not the next one means a lost value or a
/// confused peer, and the packet it belonged to is dropped.
#[derive(Debug, Default)]
pub(crate) struct Reassembler {
    packet: Vec<u8>,
    total: u16,
    next: u16,
    started: Option<Instant>,
}

impl Reassembler {
    pub(crate) fn push(&mut self, frame: &[u8]) -> Frame {
        if is_keepalive(frame) {
            return Frame::Keepalive;
        }
        if frame.len() < HEADER_LEN {
            return self.reject("shorter than a fragment header");
        }
        let kind = frame[0];
        let sequence = u16::from_be_bytes([frame[1], frame[2]]);
        let total = u16::from_be_bytes([frame[3], frame[4]]);
        if !(TYPE_START..=TYPE_END).contains(&kind) || total == 0 || sequence >= total {
            return self.reject("not a fragment header");
        }
        if sequence == 0 {
            self.packet.clear();
            self.total = total;
            self.next = 0;
            self.started = Some(Instant::now());
        } else {
            let continues = self
                .started
                .is_some_and(|started| started.elapsed() < REASSEMBLY_TIMEOUT)
                && total == self.total
                && sequence == self.next;
            if !continues {
                return self.reject("fragment out of sequence");
            }
        }
        let data = &frame[HEADER_LEN..];
        if self.packet.len() + data.len() > MAX_PACKET_LEN {
            return self.reject("packet too long");
        }
        self.packet.extend_from_slice(data);
        self.next += 1;
        if self.next < self.total {
            return Frame::Partial;
        }
        self.started = None;
        if self.packet.is_empty() {
            return Frame::Invalid("empty packet");
        }
        Frame::Packet(std::mem::take(&mut self.packet))
    }

    fn reject(&mut self, reason: &'static str) -> Frame {
        self.packet.clear();
        self.started = None;
        Frame::Invalid(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reassemble(fragments: &[Vec<u8>]) -> Option<Vec<u8>> {
        let mut reassembler = Reassembler::default();
        let (last, earlier) = fragments.split_last()?;
        for fragment in earlier {
            assert_eq!(reassembler.push(fragment), Frame::Partial);
        }
        match reassembler.push(last) {
            Frame::Packet(packet) => Some(packet),
            _ => None,
        }
    }

    #[test]
    fn a_packet_that_fits_one_value_is_a_start_fragment_of_one() {
        let fragments = fragment_packet(b"hello", 20);
        assert_eq!(
            fragments,
            [[&[0x01, 0x00, 0x00, 0x00, 0x01][..], b"hello"].concat()]
        );
    }

    #[test]
    fn fragments_carry_type_sequence_and_total() {
        let packet: Vec<u8> = (0..40).collect();
        let fragments = fragment_packet(&packet, 20);
        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0][..5], [0x01, 0, 0, 0, 3]);
        assert_eq!(fragments[1][..5], [0x02, 0, 1, 0, 3]);
        assert_eq!(fragments[2][..5], [0x03, 0, 2, 0, 3]);
        assert_eq!(fragments[0][5..], packet[..15]);
        assert_eq!(fragments[1][5..], packet[15..30]);
        assert_eq!(fragments[2][5..], packet[30..]);
    }

    #[test]
    fn a_two_fragment_packet_has_no_middle_fragment() {
        let fragments = fragment_packet(&[7; 16], 20);
        assert_eq!(fragments.len(), 2);
        assert_eq!(fragments[0][..5], [0x01, 0, 0, 0, 2]);
        assert_eq!(fragments[1][..5], [0x03, 0, 1, 0, 2]);
    }

    #[test]
    fn every_packet_size_survives_every_value_length() {
        for value_len in [0, 20, 23, 182, 244, 509, 512, 514, 4096] {
            for len in [1, 14, 15, 16, 19, 177, 178, 300, 500] {
                let packet: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
                let fragments = fragment_packet(&packet, value_len);
                let limit = value_len.clamp(MIN_VALUE_LEN, MAX_VALUE_LEN);
                assert!(fragments.iter().all(|fragment| fragment.len() <= limit));
                assert_eq!(
                    reassemble(&fragments).as_deref(),
                    Some(packet.as_slice()),
                    "{len} bytes in {value_len}-byte values"
                );
            }
        }
    }

    #[test]
    fn a_reticulum_packet_fits_one_value_at_the_largest_mtu() {
        assert_eq!(fragment_packet(&[0; 500], 514).len(), 1);
    }

    #[test]
    fn nothing_to_send_is_no_fragments() {
        assert!(fragment_packet(&[], 20).is_empty());
    }

    #[test]
    fn a_keepalive_does_not_disturb_a_packet_being_received() {
        let fragments = fragment_packet(&[9; 30], 20);
        let mut reassembler = Reassembler::default();
        assert_eq!(reassembler.push(&fragments[0]), Frame::Partial);
        assert_eq!(reassembler.push(&KEEPALIVE_FRAME), Frame::Keepalive);
        assert_eq!(reassembler.push(&fragments[1]), Frame::Packet(vec![9; 30]));
    }

    #[test]
    fn a_new_first_fragment_replaces_an_unfinished_packet() {
        let unfinished = fragment_packet(&[1; 30], 20);
        let mut reassembler = Reassembler::default();
        assert_eq!(reassembler.push(&unfinished[0]), Frame::Partial);
        let whole = fragment_packet(b"next", 20);
        assert_eq!(reassembler.push(&whole[0]), Frame::Packet(b"next".to_vec()));
    }

    #[test]
    fn a_gap_drops_the_packet() {
        let fragments = fragment_packet(&[3; 40], 20);
        let mut reassembler = Reassembler::default();
        assert_eq!(reassembler.push(&fragments[0]), Frame::Partial);
        assert!(matches!(reassembler.push(&fragments[2]), Frame::Invalid(_)));
        // The fragment that was skipped no longer continues anything.
        assert!(matches!(reassembler.push(&fragments[1]), Frame::Invalid(_)));
    }

    #[test]
    fn a_fragment_of_another_packet_drops_both() {
        let first = fragment_packet(&[3; 40], 20);
        let other = fragment_packet(&[4; 30], 20);
        let mut reassembler = Reassembler::default();
        assert_eq!(reassembler.push(&first[0]), Frame::Partial);
        assert!(matches!(reassembler.push(&other[1]), Frame::Invalid(_)));
        assert!(matches!(reassembler.push(&first[1]), Frame::Invalid(_)));
    }

    #[test]
    fn a_continuation_without_a_first_fragment_is_invalid() {
        let fragments = fragment_packet(&[3; 40], 20);
        let mut reassembler = Reassembler::default();
        assert!(matches!(reassembler.push(&fragments[1]), Frame::Invalid(_)));
    }

    #[test]
    fn malformed_values_are_invalid() {
        let mut reassembler = Reassembler::default();
        for value in [
            &[][..],
            &[0x01],
            &[0x01, 0, 0, 0],
            // Type 00 with a header is not a keepalive and not a fragment.
            &[0x00, 0, 0, 0, 1, 9],
            &[0x04, 0, 0, 0, 1, 9],
            // Total of zero, and a sequence at or past the total.
            &[0x01, 0, 0, 0, 0, 9],
            &[0x01, 0, 1, 0, 1, 9],
            &[0x03, 0, 2, 0, 2, 9],
        ] {
            assert!(
                matches!(reassembler.push(value), Frame::Invalid(_)),
                "{value:?}"
            );
        }
        // A raw Reticulum packet (Ratspeak's own framing sends small packets
        // bare) is not mistaken for a fragment either.
        let raw = [0x00u8; 19];
        assert!(matches!(reassembler.push(&raw), Frame::Invalid(_)));
    }

    #[test]
    fn a_packet_longer_than_reticulum_allows_is_dropped() {
        let mut reassembler = Reassembler::default();
        let mut first = vec![0x01, 0, 0, 0, 2];
        first.extend_from_slice(&[0; 500]);
        let mut last = vec![0x03, 0, 1, 0, 2];
        last.extend_from_slice(&[0; 13]);
        assert_eq!(reassembler.push(&first), Frame::Partial);
        assert_eq!(reassembler.push(&last), Frame::Invalid("packet too long"));
    }

    #[test]
    fn a_packet_of_no_bytes_is_invalid() {
        let mut reassembler = Reassembler::default();
        assert_eq!(
            reassembler.push(&[0x01, 0, 0, 0, 1]),
            Frame::Invalid("empty packet")
        );
    }

    #[test]
    fn an_identity_is_sixteen_bytes_that_are_not_all_zero() {
        assert_eq!(parse_identity(&[5; 16]), Some([5; 16]));
        assert_eq!(parse_identity(&[5; 15]), None);
        assert_eq!(parse_identity(&[5; 17]), None);
        assert_eq!(parse_identity(&[0; 16]), None);
        assert_eq!(parse_identity(&[]), None);
    }

    #[test]
    fn session_identities_are_valid_and_differ() {
        let first = session_identity();
        assert_eq!(parse_identity(&first), Some(first));
        assert_ne!(first, session_identity());
    }

    #[test]
    fn only_a_single_zero_byte_is_a_keepalive() {
        assert!(is_keepalive(&[0x00]));
        assert!(!is_keepalive(&[]));
        assert!(!is_keepalive(&[0x01]));
        assert!(!is_keepalive(&[0x00, 0x00]));
    }
}
