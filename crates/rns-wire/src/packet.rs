//! Full parsed-packet type: header + payload + cached hashes.

use alloc::vec::Vec;
use thiserror::Error;

use crate::constants::MTU;
use crate::hash::{packet_hash, truncated_packet_hash};
use crate::header::{HeaderError, PacketHeader};

/// Errors surfaced by [`Packet::new`] and [`Packet::from_raw`].
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum PacketError {
    #[error("packet exceeds MTU ({MTU} bytes): {0} bytes")]
    ExceedsMtu(usize),
    #[error("header error: {0}")]
    Header(#[from] HeaderError),
    #[error("packet too short")]
    TooShort,
}

/// A parsed Reticulum packet.
///
/// `raw` is the on-wire representation; the payload is the trailing slice
/// `raw[data_offset..]`, exposed via [`Packet::data`]. `packet_hash` and
/// `truncated_hash` are cached at construction (see [`crate::hash`]). The bytes
/// here exclude interface framing such as an IFAC tag.
///
/// Public fields can be changed without updating the other representations.
/// Reconstruct the packet after changing its header or payload;
/// [`Packet::increment_hops`] is the supported hash-preserving mutation.
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Packet {
    pub header: PacketHeader,
    pub raw: Vec<u8>,
    data_offset: usize,
    pub packet_hash: [u8; 32],
    pub truncated_hash: [u8; 16],
}

impl Packet {
    /// Payload bytes — the slice of `raw` after the original packed header.
    ///
    /// # Panics
    ///
    /// Panics if the public `raw` buffer has been shortened below that offset.
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.raw[self.data_offset..]
    }

    /// Build a packet from a header and payload, precomputing its hashes.
    ///
    /// Rejects packets above [`MTU`]. The header must have consistent fields
    /// (see [`PacketHeader::pack`]); payload encryption is the caller's job.
    pub fn new(header: PacketHeader, data: Vec<u8>) -> Result<Self, PacketError> {
        let mut raw = header.pack();
        let data_offset = raw.len();
        raw.extend_from_slice(&data);

        if raw.len() > MTU {
            return Err(PacketError::ExceedsMtu(raw.len()));
        }

        let hash = packet_hash(&raw, header.flags.header_type);
        let trunc = truncated_packet_hash(&raw, header.flags.header_type);

        Ok(Self {
            header,
            raw,
            data_offset,
            packet_hash: hash,
            truncated_hash: trunc,
        })
    }

    /// Parse a packet from borrowed wire bytes. Allocates one `Vec<u8>` to
    /// own the buffer; callers that already own the buffer should use
    /// [`Packet::from_raw_owned`] instead. Like that method, this checks the
    /// header shape but imposes no MTU or authentication policy.
    pub fn from_raw(raw: &[u8]) -> Result<Self, PacketError> {
        Self::from_raw_owned(raw.to_vec())
    }

    /// Parse a packet from owned wire bytes. Saves one allocation versus
    /// [`Packet::from_raw`] when the caller already owns the buffer.
    ///
    /// Validates the minimum header length, but does not enforce [`MTU`],
    /// authenticate data, or decrypt payloads. The caller must remove IFAC
    /// framing and apply the applicable packet-size policy first.
    pub fn from_raw_owned(raw: Vec<u8>) -> Result<Self, PacketError> {
        if raw.len() < 19 {
            return Err(PacketError::TooShort);
        }

        let (header, data_offset) = PacketHeader::unpack(&raw)?;
        let hash = packet_hash(&raw, header.flags.header_type);
        let trunc = truncated_packet_hash(&raw, header.flags.header_type);

        Ok(Self {
            header,
            raw,
            data_offset,
            packet_hash: hash,
            truncated_hash: trunc,
        })
    }

    /// Increment the hop counter in both the header and the raw bytes.
    ///
    /// Saturates at 255 so a forwarded packet cannot wrap around.
    pub fn increment_hops(&mut self) {
        if self.header.hops < 255 {
            self.header.hops += 1;
            if self.raw.len() > 1 {
                self.raw[1] = self.header.hops;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PacketContext;
    use crate::flags::*;
    use alloc::vec;

    fn make_test_header() -> PacketHeader {
        PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: [0xAA; 16],
            context: PacketContext::None,
        }
    }

    #[test]
    fn test_new_packet() {
        let hdr = make_test_header();
        let data = vec![0x01, 0x02, 0x03];
        let pkt = Packet::new(hdr, data.clone()).unwrap();
        assert_eq!(pkt.data(), data.as_slice());
        assert_eq!(pkt.raw.len(), 19 + 3);
    }

    #[test]
    fn test_from_raw_roundtrip() {
        let hdr = make_test_header();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let pkt1 = Packet::new(hdr, data).unwrap();
        let pkt2 = Packet::from_raw(&pkt1.raw).unwrap();

        assert_eq!(pkt1.header, pkt2.header);
        assert_eq!(pkt1.data(), pkt2.data());
        assert_eq!(pkt1.packet_hash, pkt2.packet_hash);
        assert_eq!(pkt1.truncated_hash, pkt2.truncated_hash);
    }

    #[test]
    fn test_from_raw_owned_matches_borrowed() {
        let hdr = make_test_header();
        let data = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let pkt = Packet::new(hdr, data).unwrap();
        let raw = pkt.raw.clone();
        let owned = Packet::from_raw_owned(raw).unwrap();
        let borrowed = Packet::from_raw(&pkt.raw).unwrap();
        assert_eq!(owned.header, borrowed.header);
        assert_eq!(owned.data(), borrowed.data());
        assert_eq!(owned.packet_hash, borrowed.packet_hash);
        assert_eq!(owned.raw, pkt.raw);
    }

    #[test]
    fn test_exceeds_mtu() {
        let hdr = make_test_header();
        let data = vec![0u8; MTU];
        assert!(Packet::new(hdr, data).is_err());
    }

    #[test]
    fn test_increment_hops() {
        let hdr = make_test_header();
        let mut pkt = Packet::new(hdr, vec![0x01]).unwrap();
        assert_eq!(pkt.header.hops, 0);
        pkt.increment_hops();
        assert_eq!(pkt.header.hops, 1);
        assert_eq!(pkt.raw[1], 1);
    }

    #[test]
    fn test_max_hops() {
        let mut hdr = make_test_header();
        hdr.hops = 255;
        let mut pkt = Packet::new(hdr, vec![0x01]).unwrap();
        pkt.increment_hops();
        assert_eq!(pkt.header.hops, 255);
    }

    #[test]
    fn test_hash_stability() {
        let hdr = make_test_header();
        let pkt1 = Packet::new(hdr.clone(), vec![0x42; 10]).unwrap();
        let pkt2 = Packet::new(hdr, vec![0x42; 10]).unwrap();
        assert_eq!(pkt1.packet_hash, pkt2.packet_hash);
    }
}
