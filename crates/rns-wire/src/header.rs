//! Packet header parsing and serialization.

use alloc::vec::Vec;
use thiserror::Error;

use crate::constants::{HEADER_MAXSIZE, HEADER_MINSIZE, TRUNCATED_HASHLENGTH};
use crate::context::PacketContext;
use crate::flags::{HeaderType, PacketFlags};

/// Errors surfaced by header parsing.
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum HeaderError {
    #[error("raw packet too short: {0} bytes (minimum {HEADER_MINSIZE})")]
    TooShort(usize),
}

/// Packet header. Parsing sets `transport_id` to `Some` exactly for Header2.
/// Callers constructing or changing fields must preserve that relationship.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub flags: PacketFlags,
    pub hops: u8,
    pub transport_id: Option<[u8; 16]>,
    pub destination_hash: [u8; 16],
    pub context: PacketContext,
}

impl PacketHeader {
    /// Serialize the header to wire bytes.
    ///
    /// Writes a transport ID whenever it is `Some`, without checking the
    /// header-type flag. The caller must supply consistent fields.
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_MAXSIZE);
        out.push(self.flags.pack());
        out.push(self.hops);
        if let Some(ref tid) = self.transport_id {
            out.extend_from_slice(tid);
        }
        out.extend_from_slice(&self.destination_hash);
        out.push(self.context.to_byte());
        out
    }

    /// Parse a header from the start of `raw`.
    ///
    /// Returns `(header, data_offset)` where `data_offset` is the first byte
    /// of the payload. This checks header length, not MTU, authentication, or
    /// payload semantics. The input must already have IFAC framing removed.
    pub fn unpack(raw: &[u8]) -> Result<(Self, usize), HeaderError> {
        if raw.len() < HEADER_MINSIZE {
            return Err(HeaderError::TooShort(raw.len()));
        }

        let flags = PacketFlags::unpack(raw[0]).ok_or(HeaderError::TooShort(raw.len()))?;
        let hops = raw[1];
        let hash_len = TRUNCATED_HASHLENGTH / 8;

        match flags.header_type {
            HeaderType::Header1 => {
                let mut dest_hash = [0u8; 16];
                dest_hash.copy_from_slice(&raw[2..2 + hash_len]);

                let context = PacketContext::from_byte(raw[2 + hash_len]);

                let data_offset = 2 + hash_len + 1;

                Ok((
                    Self {
                        flags,
                        hops,
                        transport_id: None,
                        destination_hash: dest_hash,
                        context,
                    },
                    data_offset,
                ))
            }
            HeaderType::Header2 => {
                if raw.len() < HEADER_MAXSIZE {
                    return Err(HeaderError::TooShort(raw.len()));
                }

                let mut transport_id = [0u8; 16];
                transport_id.copy_from_slice(&raw[2..2 + hash_len]);

                let mut dest_hash = [0u8; 16];
                dest_hash.copy_from_slice(&raw[2 + hash_len..2 + hash_len * 2]);

                let context = PacketContext::from_byte(raw[2 + hash_len * 2]);

                let data_offset = 2 + hash_len * 2 + 1;

                Ok((
                    Self {
                        flags,
                        hops,
                        transport_id: Some(transport_id),
                        destination_hash: dest_hash,
                        context,
                    },
                    data_offset,
                ))
            }
        }
    }

    /// Serialized header size.
    pub fn size(&self) -> usize {
        if self.transport_id.is_some() {
            HEADER_MAXSIZE
        } else {
            HEADER_MINSIZE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::*;
    use alloc::vec;

    #[test]
    fn test_pack_header1() {
        let hdr = PacketHeader {
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
        };
        let packed = hdr.pack();
        assert_eq!(packed.len(), HEADER_MINSIZE);
        assert_eq!(packed[0], 0x00);
        assert_eq!(packed[1], 0x00);
        assert_eq!(&packed[2..18], &[0xAA; 16]);
        assert_eq!(packed[18], 0x00);
    }

    #[test]
    fn test_pack_header2() {
        let hdr = PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header2,
                context_flag: false,
                transport_type: TransportType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops: 3,
            transport_id: Some([0xBB; 16]),
            destination_hash: [0xCC; 16],
            context: PacketContext::None,
        };
        let packed = hdr.pack();
        assert_eq!(packed.len(), HEADER_MAXSIZE);
        assert_eq!(&packed[2..18], &[0xBB; 16]);
        assert_eq!(&packed[18..34], &[0xCC; 16]);
    }

    #[test]
    fn test_unpack_header1() {
        let mut raw = vec![0u8; 30];
        raw[0] = 0x01;
        raw[1] = 5;
        raw[2..18].copy_from_slice(&[0xDD; 16]);
        raw[18] = 0x00;

        let (hdr, offset) = PacketHeader::unpack(&raw).unwrap();
        assert_eq!(hdr.flags.packet_type, PacketType::Announce);
        assert_eq!(hdr.hops, 5);
        assert_eq!(hdr.destination_hash, [0xDD; 16]);
        assert_eq!(hdr.transport_id, None);
        assert_eq!(hdr.context, PacketContext::None);
        assert_eq!(offset, 19);
    }

    #[test]
    fn test_roundtrip_header1() {
        let hdr = PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: true,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Plain,
                packet_type: PacketType::Data,
            },
            hops: 42,
            transport_id: None,
            destination_hash: [0x12; 16],
            context: PacketContext::Channel,
        };
        let packed = hdr.pack();
        let (unpacked, _) = PacketHeader::unpack(&packed).unwrap();
        assert_eq!(hdr, unpacked);
    }

    #[test]
    fn test_too_short() {
        assert!(PacketHeader::unpack(&[0u8; 5]).is_err());
    }

    use proptest::prelude::*;

    fn any_packet_flags() -> impl Strategy<Value = PacketFlags> {
        // Bit 7 is reserved; only 0x00..=0x7F decode.
        (0u8..=0x7F).prop_map(|byte| PacketFlags::unpack(byte).unwrap())
    }

    proptest! {
        #[test]
        fn proptest_header_pack_unpack_roundtrip(
            flags in any_packet_flags(),
            hops: u8,
            transport_id: [u8; 16],
            destination_hash: [u8; 16],
            context_byte: u8,
        ) {
            let header = PacketHeader {
                flags,
                hops,
                transport_id: match flags.header_type {
                    HeaderType::Header1 => None,
                    HeaderType::Header2 => Some(transport_id),
                },
                destination_hash,
                context: PacketContext::from_byte(context_byte),
            };
            let packed = header.pack();
            let (unpacked, _offset) = PacketHeader::unpack(&packed).unwrap();
            prop_assert_eq!(&header, &unpacked);
            prop_assert_eq!(unpacked.pack(), packed);
        }

        #[test]
        fn proptest_context_byte_preserving(byte: u8) {
            let ctx = PacketContext::from_byte(byte);
            prop_assert_eq!(ctx.to_byte(), byte);
        }

        #[test]
        fn proptest_flags_byte_preserving(byte in 0u8..=0x7F) {
            let flags = PacketFlags::unpack(byte).unwrap();
            prop_assert_eq!(flags.pack(), byte);
        }
    }
}
