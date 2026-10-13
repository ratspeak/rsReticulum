//! Checked Link request/proof signalling, independent of endpoint cipher policy.

/// General-Link base packet contract.
pub const BASE_LINK_MTU: u32 = 500;
/// Largest value representable by the 21-bit signalling field.
pub const MAX_SIGNALLED_LINK_MTU: u32 = 0x1f_ffff;
/// The implicit mode of a legacy Link request/proof.
pub const DEFAULT_LINK_MODE: u8 = 1;

/// Invalid handshake shape or unrepresentable protocol budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkSignallingError {
    /// Only the exact legacy or modern payload size is accepted.
    #[error("invalid Link signalling payload length {actual}; expected {legacy} or {modern}")]
    InvalidLength {
        /// Received size.
        actual: usize,
        /// Legacy payload size.
        legacy: usize,
        /// Modern payload size.
        modern: usize,
    },
    /// A nonzero MTU below the qualified base or above the wire field.
    #[error("invalid Link MTU {0}; expected zero or 500..=2097151")]
    InvalidMtu(u32),
    /// Raw mode cannot be represented in three bits.
    #[error("invalid Link mode {0}; expected 0..=7")]
    InvalidMode(u8),
    /// Checked arithmetic could not produce an encrypted data unit.
    #[error("Link budget cannot contain an encrypted data unit")]
    MduUnavailable,
}

/// Validated MTU. Missing and zero signalling use the 500-byte base contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkMtu(u32);
impl LinkMtu {
    /// Qualified base used for legacy and current host endpoint traffic.
    pub const BASE: Self = Self(BASE_LINK_MTU);
    /// Validate protocol domain without truncation or saturation.
    pub fn try_from_signal(signal: Option<u32>) -> Result<Self, LinkSignallingError> {
        match signal {
            None | Some(0) => Ok(Self::BASE),
            Some(value @ BASE_LINK_MTU..=MAX_SIGNALLED_LINK_MTU) => Ok(Self(value)),
            Some(value) => Err(LinkSignallingError::InvalidMtu(value)),
        }
    }
    /// Complete clear packet bytes.
    pub const fn get(self) -> u32 {
        self.0
    }
    /// Checked AES-CBC maximum data unit, including padding reservation.
    pub fn checked_mdu(self) -> Result<usize, LinkSignallingError> {
        let mtu = usize::try_from(self.0).map_err(|_| LinkSignallingError::MduUnavailable)?;
        let overhead = 1usize
            .checked_add(crate::constants::HEADER_MINSIZE)
            .and_then(|n| n.checked_add(crate::constants::TOKEN_OVERHEAD))
            .ok_or(LinkSignallingError::MduUnavailable)?;
        mtu.checked_sub(overhead)
            .map(|n| n / crate::constants::AES128_BLOCKSIZE * crate::constants::AES128_BLOCKSIZE)
            .and_then(|n| n.checked_sub(1))
            .ok_or(LinkSignallingError::MduUnavailable)
    }
}

/// Low-level three-byte representation. `new`/`pack` retain their historical
/// masking behavior; handshake admission must use checked constructors/parsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignallingData {
    /// Raw three-bit cipher mode, independent of the local enabled-mode set.
    pub mode: u8,
    /// Raw 21-bit MTU field; zero is a legacy-compatible base offer.
    pub mtu: u32,
}
impl SignallingData {
    /// Construct a masking representation, not validated endpoint authority.
    pub fn new(mode: u8, mtu: u32) -> Self {
        Self {
            mode: mode & 7,
            mtu: mtu & MAX_SIGNALLED_LINK_MTU,
        }
    }
    /// Construct checked, normalized signalling without truncation.
    pub fn try_new(mode: u8, mtu: u32) -> Result<Self, LinkSignallingError> {
        if mode > 7 {
            return Err(LinkSignallingError::InvalidMode(mode));
        }
        Ok(Self {
            mode,
            mtu: LinkMtu::try_from_signal(Some(mtu))?.get(),
        })
    }
    /// Pack the representation as three big-endian bytes.
    pub fn pack(&self) -> [u8; 3] {
        let value = (self.mtu & MAX_SIGNALLED_LINK_MTU) | (((self.mode & 7) as u32) << 21);
        let bytes = value.to_be_bytes();
        [bytes[1], bytes[2], bytes[3]]
    }
    /// Decode a representation from its first three bytes.
    pub fn unpack(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 {
            return None;
        }
        let value = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32;
        Some(Self {
            mode: ((value >> 21) & 7) as u8,
            mtu: value & MAX_SIGNALLED_LINK_MTU,
        })
    }
}

/// Checked metadata; the original trailer bytes remain in the caller's packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkSignalling {
    /// Raw mode, never coerced to the local default.
    pub mode: u8,
    /// Validated effective MTU offer.
    pub mtu: LinkMtu,
    /// False only for exact legacy payloads without a trailer.
    pub signalling_present: bool,
}
fn parse(data: &[u8], legacy: usize) -> Result<LinkSignalling, LinkSignallingError> {
    if data.len() == legacy {
        return Ok(LinkSignalling {
            mode: DEFAULT_LINK_MODE,
            mtu: LinkMtu::BASE,
            signalling_present: false,
        });
    }
    if data.len() != legacy + 3 {
        return Err(LinkSignallingError::InvalidLength {
            actual: data.len(),
            legacy,
            modern: legacy + 3,
        });
    }
    let signalling = SignallingData::unpack(&data[legacy..]).expect("exact three-byte signalling");
    Ok(LinkSignalling {
        mode: signalling.mode,
        mtu: LinkMtu::try_from_signal(Some(signalling.mtu))?,
        signalling_present: true,
    })
}
/// Parse exactly a legacy 64-byte or modern 67-byte Link request.
pub fn parse_request_signalling(data: &[u8]) -> Result<LinkSignalling, LinkSignallingError> {
    parse(data, 64)
}
/// Parse exactly a legacy 96-byte or modern 99-byte Link proof.
pub fn parse_proof_signalling(data: &[u8]) -> Result<LinkSignalling, LinkSignallingError> {
    parse(data, 96)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mtu_domain_does_not_mask_or_wrap() {
        for invalid in 1..500 {
            assert!(LinkMtu::try_from_signal(Some(invalid)).is_err());
        }
        for value in [500, 501, MAX_SIGNALLED_LINK_MTU] {
            assert_eq!(LinkMtu::try_from_signal(Some(value)).unwrap().get(), value);
        }
        for value in [MAX_SIGNALLED_LINK_MTU + 1, u32::MAX] {
            assert!(LinkMtu::try_from_signal(Some(value)).is_err());
        }
        assert_eq!(LinkMtu::try_from_signal(None).unwrap(), LinkMtu::BASE);
        assert_eq!(LinkMtu::try_from_signal(Some(0)).unwrap(), LinkMtu::BASE);
        assert_eq!(
            LinkMtu::BASE.checked_mdu().unwrap(),
            crate::constants::LINK_MDU
        );
        assert!(SignallingData::try_new(8, 500).is_err());
    }
    #[test]
    fn exact_request_and_proof_shapes_preserve_opaque_modes() {
        for legacy in [64, 96] {
            for len in [0, legacy - 1, legacy + 1, legacy + 2, legacy + 4] {
                assert!(parse(&alloc::vec![0;len], legacy).is_err());
            }
            assert_eq!(
                parse(&alloc::vec![0;legacy], legacy).unwrap().mtu,
                LinkMtu::BASE
            );
            for mode in 0..=7 {
                let mut bytes = alloc::vec![0;legacy];
                bytes.extend_from_slice(&SignallingData::new(mode, 0).pack());
                let parsed = parse(&bytes, legacy).unwrap();
                assert_eq!(parsed.mode, mode);
                assert_eq!(parsed.mtu, LinkMtu::BASE);
                assert!(parsed.signalling_present);
            }
        }
    }
}
