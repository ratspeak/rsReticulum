//! Packet context byte — a one-byte discriminator carried in every header.

/// Context byte carried in the packet header. Unknown bytes are preserved
/// via [`PacketContext::Unknown`] so forward-compatible contexts round-trip.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketContext {
    None,
    Resource,
    ResourceAdv,
    ResourceReq,
    ResourceHmu,
    ResourcePrf,
    ResourceIcl,
    ResourceRcl,
    CacheRequest,
    Request,
    Response,
    PathResponse,
    Command,
    CommandStatus,
    Channel,
    Keepalive,
    LinkIdentify,
    LinkClose,
    LinkProof,
    Lrrtt,
    Lrproof,
    /// Unrecognised context byte; preserved verbatim for forward compatibility.
    Unknown(u8),
}

impl PacketContext {
    /// Decode a context byte.
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => Self::None,
            0x01 => Self::Resource,
            0x02 => Self::ResourceAdv,
            0x03 => Self::ResourceReq,
            0x04 => Self::ResourceHmu,
            0x05 => Self::ResourcePrf,
            0x06 => Self::ResourceIcl,
            0x07 => Self::ResourceRcl,
            0x08 => Self::CacheRequest,
            0x09 => Self::Request,
            0x0A => Self::Response,
            0x0B => Self::PathResponse,
            0x0C => Self::Command,
            0x0D => Self::CommandStatus,
            0x0E => Self::Channel,
            0xFA => Self::Keepalive,
            0xFB => Self::LinkIdentify,
            0xFC => Self::LinkClose,
            0xFD => Self::LinkProof,
            0xFE => Self::Lrrtt,
            0xFF => Self::Lrproof,
            other => Self::Unknown(other),
        }
    }

    /// Encode as the single wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::Resource => 0x01,
            Self::ResourceAdv => 0x02,
            Self::ResourceReq => 0x03,
            Self::ResourceHmu => 0x04,
            Self::ResourcePrf => 0x05,
            Self::ResourceIcl => 0x06,
            Self::ResourceRcl => 0x07,
            Self::CacheRequest => 0x08,
            Self::Request => 0x09,
            Self::Response => 0x0A,
            Self::PathResponse => 0x0B,
            Self::Command => 0x0C,
            Self::CommandStatus => 0x0D,
            Self::Channel => 0x0E,
            Self::Keepalive => 0xFA,
            Self::LinkIdentify => 0xFB,
            Self::LinkClose => 0xFC,
            Self::LinkProof => 0xFD,
            Self::Lrrtt => 0xFE,
            Self::Lrproof => 0xFF,
            Self::Unknown(b) => b,
        }
    }

    /// Whether this context bypasses per-packet payload encryption.
    ///
    /// This is the context classification used by the packet-encryption layer,
    /// not a guarantee that the payload is readable. For example, a Resource
    /// can be encrypted as a whole before its parts are put into packets.
    pub fn is_plaintext_context(self) -> bool {
        matches!(
            self,
            Self::Resource | Self::ResourcePrf | Self::Keepalive | Self::CacheRequest
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_all_known() {
        let known = [
            PacketContext::None,
            PacketContext::Resource,
            PacketContext::ResourceAdv,
            PacketContext::ResourceReq,
            PacketContext::ResourceHmu,
            PacketContext::ResourcePrf,
            PacketContext::ResourceIcl,
            PacketContext::ResourceRcl,
            PacketContext::CacheRequest,
            PacketContext::Request,
            PacketContext::Response,
            PacketContext::PathResponse,
            PacketContext::Command,
            PacketContext::CommandStatus,
            PacketContext::Channel,
            PacketContext::Keepalive,
            PacketContext::LinkIdentify,
            PacketContext::LinkClose,
            PacketContext::LinkProof,
            PacketContext::Lrrtt,
            PacketContext::Lrproof,
        ];
        for ctx in known {
            let byte = ctx.to_byte();
            let parsed = PacketContext::from_byte(byte);
            assert_eq!(parsed, ctx);
        }
    }

    #[test]
    fn test_unknown_byte_preserved() {
        let ctx = PacketContext::from_byte(0x0F);
        assert_eq!(ctx, PacketContext::Unknown(0x0F));
        assert_eq!(ctx.to_byte(), 0x0F);

        let ctx2 = PacketContext::from_byte(0x99);
        assert_eq!(ctx2, PacketContext::Unknown(0x99));
        assert_eq!(ctx2.to_byte(), 0x99);
    }
}
