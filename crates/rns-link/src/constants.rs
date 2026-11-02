//! Link-level protocol constants.

/// X25519 public key size in bytes.
pub const KEYSIZE: usize = 32;

/// Combined ephemeral public key size: X25519(32) + Ed25519(32) = 64 bytes.
pub const ECPUBSIZE: usize = 64;

/// MTU signalling field size in bytes.
pub const LINK_MTU_SIZE: usize = 3;

/// Seconds per hop for establishment timeout calculation.
pub const ESTABLISHMENT_TIMEOUT_PER_HOP: f64 = 6.0;

/// Traffic timeout as a multiple of measured RTT.
pub const TRAFFIC_TIMEOUT_FACTOR: f64 = 6.0;

/// RTT ceiling for keepalive scaling.
pub const KEEPALIVE_MAX_RTT: f64 = 1.75;

/// Stale->closed timeout as a multiple of measured RTT.
pub const KEEPALIVE_TIMEOUT_FACTOR: f64 = 4.0;

/// Grace seconds after going stale before teardown.
pub const STALE_GRACE: f64 = 5.0;

pub const KEEPALIVE_MAX: f64 = 360.0;
pub const KEEPALIVE_MIN: f64 = 5.0;
pub const KEEPALIVE_DEFAULT: f64 = 360.0;

/// Stale threshold as a multiple of keepalive interval.
pub const STALE_FACTOR: f64 = 2.0;

pub const STALE_TIME_DEFAULT: f64 = 720.0;

/// Max sleep per watchdog cycle.
pub const WATCHDOG_MAX_SLEEP: f64 = 5.0;

/// Lower bound for traffic timeout; prevents sub-millisecond spins on tiny RTTs.
pub const TRAFFIC_TIMEOUT_FLOOR_MS: u64 = 5;

pub const MODE_AES128_CBC: u8 = 0x00;
/// Default: AES-256-CBC.
pub const MODE_AES256_CBC: u8 = 0x01;
/// Reserved AES-256-GCM identifier; not accepted by current Link endpoints.
pub const MODE_AES256_GCM: u8 = 0x02;
pub const MODE_OTP_RESERVED: u8 = 0x03;
pub const MODE_PQ_RESERVED_1: u8 = 0x04;
pub const MODE_PQ_RESERVED_2: u8 = 0x05;
pub const MODE_PQ_RESERVED_3: u8 = 0x06;
pub const MODE_PQ_RESERVED_4: u8 = 0x07;

/// Encryption modes accepted by [`crate::link::Link`] endpoints. Other mode
/// identifiers are representable on the wire but rejected by those endpoints.
pub const ENABLED_MODES: &[u8] = &[MODE_AES256_CBC];

pub const DEFAULT_MODE: u8 = MODE_AES256_CBC;

pub const TIMEOUT: u8 = 0x01;
pub const INITIATOR_CLOSED: u8 = 0x02;
pub const DESTINATION_CLOSED: u8 = 0x03;

pub const ACCEPT_NONE: u8 = 0x00;
/// Defer acceptance to an application callback.
pub const ACCEPT_APP: u8 = 0x01;
pub const ACCEPT_ALL: u8 = 0x02;

/// Low 21 bits of the 24-bit MTU signalling value carry the MTU.
pub const MTU_BYTEMASK: u32 = 0x001F_FFFF;

/// Mask for mode bits 5–7 of the first signalling byte. In the full 24-bit
/// big-endian signalling value, those are bits 21–23 (mask `0xE00000`).
pub const MODE_BYTEMASK: u32 = 0x00E0;

/// Derived key length for AES-256-CBC: 32-byte HMAC key || 32-byte cipher key.
pub const AES256_DERIVED_KEY_LENGTH: usize = 64;

/// Derived key length for AES-128-CBC: 16-byte HMAC key || 16-byte cipher key.
pub const AES128_DERIVED_KEY_LENGTH: usize = 32;

/// Seconds of slack granted to a response beyond its nominal transfer time.
pub const RESPONSE_MAX_GRACE_TIME: f64 = 10.0;

/// Sentinel byte sent by the initiator.
pub const KEEPALIVE_REQUEST: u8 = 0xFF;

/// Sentinel byte returned by the destination.
pub const KEEPALIVE_RESPONSE: u8 = 0xFE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(ECPUBSIZE, 64);
        assert_eq!(STALE_TIME_DEFAULT, KEEPALIVE_DEFAULT * STALE_FACTOR);
        assert!(ENABLED_MODES.contains(&MODE_AES256_CBC));
        assert!(!ENABLED_MODES.contains(&MODE_AES128_CBC));
    }
}
