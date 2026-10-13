//! Shared dependency-neutral Link signalling representation and checked budget.
pub use rns_wire::link_signalling::{
    LinkMtu, LinkSignalling, LinkSignallingError, SignallingData, parse_proof_signalling,
    parse_request_signalling,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DEFAULT_MODE, MODE_AES256_CBC, MTU_BYTEMASK};

    #[test]
    fn test_pack_unpack_roundtrip() {
        let sd = SignallingData::new(MODE_AES256_CBC, 500);
        let packed = sd.pack();
        let unpacked = SignallingData::unpack(&packed).unwrap();
        assert_eq!(unpacked.mode, MODE_AES256_CBC);
        assert_eq!(unpacked.mtu, 500);
    }

    #[test]
    fn test_mode_zero_mtu_500() {
        let sd = SignallingData::new(0, 500);
        let packed = sd.pack();
        let unpacked = SignallingData::unpack(&packed).unwrap();
        assert_eq!(unpacked.mode, 0);
        assert_eq!(unpacked.mtu, 500);
    }

    #[test]
    fn test_mode_bits_isolated() {
        // Setting the mode must not corrupt the MTU field.
        let sd = SignallingData::new(1, 500);
        let packed = sd.pack();
        let unpacked = SignallingData::unpack(&packed).unwrap();
        assert_eq!(unpacked.mtu, 500);
        assert_eq!(unpacked.mode, 1);
    }

    #[test]
    fn test_max_mtu_value() {
        let max_mtu = MTU_BYTEMASK;
        let sd = SignallingData::new(7, max_mtu);
        let packed = sd.pack();
        let unpacked = SignallingData::unpack(&packed).unwrap();
        assert_eq!(unpacked.mtu, max_mtu);
        assert_eq!(unpacked.mode, 7);
    }

    #[test]
    fn test_default_mode() {
        let sd = SignallingData::new(DEFAULT_MODE, 500);
        assert_eq!(sd.mode, MODE_AES256_CBC);
    }

    #[test]
    fn test_too_short() {
        assert!(SignallingData::unpack(&[0x00, 0x01]).is_none());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn proptest_signalling_pack_unpack_roundtrip(
            mode in 0u8..=7,
            mtu in 0u32..=MTU_BYTEMASK,
        ) {
            let sd = SignallingData::new(mode, mtu);
            let packed = sd.pack();
            let unpacked = SignallingData::unpack(&packed).unwrap();
            prop_assert_eq!(unpacked.mode, mode);
            prop_assert_eq!(unpacked.mtu, mtu);
            prop_assert_eq!(unpacked.pack(), packed);
        }

        #[test]
        fn proptest_signalling_bytes_canonical(bytes: [u8; 3]) {
            let sd = SignallingData::unpack(&bytes).unwrap();
            prop_assert_eq!(sd.pack(), bytes);
        }
    }
}
