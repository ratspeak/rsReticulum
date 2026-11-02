//! Decoded view of the packet flags byte.

/// Packet type carried in the lower 2 bits of the flags byte.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    Data = 0x00,
    Announce = 0x01,
    LinkRequest = 0x02,
    Proof = 0x03,
}

/// Destination kind carried in bits 3-2 of the flags byte.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DestinationType {
    Single = 0x00,
    Group = 0x01,
    Plain = 0x02,
    Link = 0x03,
}

/// Header layout (bit 6 of flags): single-hash vs. transport-id + dest-hash.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HeaderType {
    Header1 = 0x00,
    Header2 = 0x01,
}

/// Propagation mode (bit 4 of flags): link-local broadcast vs. routed transport.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TransportType {
    Broadcast = 0x00,
    Transport = 0x01,
}

/// Decoded view of the single flags byte at offset 0 of every packet.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlags {
    pub header_type: HeaderType,
    pub context_flag: bool,
    pub transport_type: TransportType,
    pub destination_type: DestinationType,
    pub packet_type: PacketType,
}

impl PacketFlags {
    /// Pack flags into a single byte.
    ///
    /// Bit 7 is left clear here; the interface IFAC layer owns that bit.
    ///
    /// ```text
    /// Bit 6:    header_type
    /// Bit 5:    context_flag
    /// Bit 4:    transport_type
    /// Bits 3-2: destination_type
    /// Bits 1-0: packet_type
    /// ```
    pub fn pack(&self) -> u8 {
        let ht = (self.header_type as u8) << 6;
        let cf = (self.context_flag as u8) << 5;
        let tt = (self.transport_type as u8) << 4;
        let dt = (self.destination_type as u8) << 2;
        let pt = self.packet_type as u8;
        ht | cf | tt | dt | pt
    }

    /// Unpack flags from a single byte.
    ///
    /// Every byte maps to `Some`; bit 7 is ignored. This does not validate or
    /// remove an IFAC tag. Decode IFAC framing before parsing a packet header.
    ///
    /// ```text
    /// header_type      = (flags & 0b01000000) >> 6
    /// context_flag     = (flags & 0b00100000) >> 5
    /// transport_type   = (flags & 0b00010000) >> 4
    /// destination_type = (flags & 0b00001100) >> 2
    /// packet_type      = (flags & 0b00000011)
    /// ```
    pub fn unpack(byte: u8) -> Option<Self> {
        let header_type = match (byte & 0b0100_0000) >> 6 {
            0 => HeaderType::Header1,
            1 => HeaderType::Header2,
            _ => unreachable!(),
        };
        let context_flag = (byte & 0b0010_0000) >> 5 != 0;
        let transport_type = match (byte & 0b0001_0000) >> 4 {
            0 => TransportType::Broadcast,
            1 => TransportType::Transport,
            _ => unreachable!(),
        };
        let destination_type = match (byte & 0b0000_1100) >> 2 {
            0 => DestinationType::Single,
            1 => DestinationType::Group,
            2 => DestinationType::Plain,
            3 => DestinationType::Link,
            _ => unreachable!(),
        };
        let packet_type = match byte & 0b0000_0011 {
            0 => PacketType::Data,
            1 => PacketType::Announce,
            2 => PacketType::LinkRequest,
            3 => PacketType::Proof,
            _ => unreachable!(),
        };

        Some(Self {
            header_type,
            context_flag,
            transport_type,
            destination_type,
            packet_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_roundtrip() {
        let flags = PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
        };
        let byte = flags.pack();
        assert_eq!(byte, 0x00);
        assert_eq!(PacketFlags::unpack(byte), Some(flags));
    }

    #[test]
    fn test_all_ones() {
        let flags = PacketFlags {
            header_type: HeaderType::Header2,
            context_flag: true,
            transport_type: TransportType::Transport,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Proof,
        };
        let byte = flags.pack();
        // Every defined bit set: 0b01111111.
        assert_eq!(byte, 0x7F);
        assert_eq!(PacketFlags::unpack(byte), Some(flags));
    }

    #[test]
    fn test_announce_flags() {
        let flags = PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
        };
        let byte = flags.pack();
        assert_eq!(byte, 0x01);
    }

    #[test]
    fn test_transport_header2() {
        let flags = PacketFlags {
            header_type: HeaderType::Header2,
            context_flag: false,
            transport_type: TransportType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
        };
        let byte = flags.pack();
        // header_type(bit 6) | transport_type(bit 4) = 0x50.
        assert_eq!(byte, 0x50);
    }

    #[test]
    fn test_bit7_ignored_on_unpack() {
        // Bit 7 is reserved; parsing must ignore it.
        let byte = 0x80 | 0x01;
        let flags = PacketFlags::unpack(byte).unwrap();
        assert_eq!(flags.header_type, HeaderType::Header1);
        assert_eq!(flags.packet_type, PacketType::Announce);
    }

    #[test]
    fn test_exhaustive_roundtrip() {
        for byte in 0..=0x7Fu8 {
            let flags = PacketFlags::unpack(byte).unwrap();
            assert_eq!(flags.pack(), byte);
        }
    }
}
