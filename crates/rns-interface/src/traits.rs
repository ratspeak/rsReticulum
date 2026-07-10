use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};

use bytes::Bytes;
use tokio::sync::mpsc;

pub type InterfaceId = u64;

/// Handle returned by every `spawn_*`: write channel, status flag, and read task.
pub struct InterfaceHandle {
    pub id: InterfaceId,
    /// Parent interface for dynamically spawned children such as accepted TCP,
    /// Backbone or I2P peers.
    pub parent_id: Option<InterfaceId>,
    pub name: String,
    pub mode: InterfaceMode,
    pub direction: InterfaceDirection,
    pub bitrate: u64,
    pub mtu: u32,
    pub online: Arc<AtomicBool>,
    pub rxb: Option<Arc<AtomicU64>>,
    pub txb: Option<Arc<AtomicU64>>,
    pub tx: mpsc::Sender<Bytes>,
    pub read_task: tokio::task::JoinHandle<()>,
}

/// Interface operating mode. Byte values are on-wire constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum InterfaceMode {
    #[default]
    Full = 0x01,
    PointToPoint = 0x02,
    AccessPoint = 0x03,
    Roaming = 0x04,
    Boundary = 0x05,
    Gateway = 0x06,
}

pub const MODE_FULL: InterfaceMode = InterfaceMode::Full;
pub const MODE_POINT_TO_POINT: InterfaceMode = InterfaceMode::PointToPoint;

/// Python `Interface.DEFAULT_AR_*` announce-rate defaults.
pub const DEFAULT_AR_TARGET: u64 = 3600;
pub const DEFAULT_AR_PENALTY: u64 = 0;
pub const DEFAULT_AR_GRACE: u32 = 5;

/// Modes for which a Transport Node actively discovers paths.
pub const DISCOVER_PATHS_FOR: &[InterfaceMode] = &[
    InterfaceMode::AccessPoint,
    InterfaceMode::Gateway,
    InterfaceMode::Roaming,
];

impl InterfaceMode {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::Full),
            0x02 => Some(Self::PointToPoint),
            0x03 => Some(Self::AccessPoint),
            0x04 => Some(Self::Roaming),
            0x05 => Some(Self::Boundary),
            0x06 => Some(Self::Gateway),
            _ => None,
        }
    }
}

/// Interface direction flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct InterfaceDirection {
    pub inbound: bool,
    pub outbound: bool,
    pub forward: bool,
    pub repeat: bool,
}

/// Select an MTU for the given bitrate; `None` below 62.5 kbps minimum.
pub fn optimise_mtu(bitrate: u64) -> Option<u32> {
    if bitrate >= 1_000_000_000 {
        Some(524_288)
    } else if bitrate > 750_000_000 {
        Some(262_144)
    } else if bitrate > 400_000_000 {
        Some(131_072)
    } else if bitrate > 200_000_000 {
        Some(65_536)
    } else if bitrate > 100_000_000 {
        Some(32_768)
    } else if bitrate > 10_000_000 {
        Some(16_384)
    } else if bitrate > 5_000_000 {
        Some(8_192)
    } else if bitrate > 2_000_000 {
        Some(4_096)
    } else if bitrate > 1_000_000 {
        Some(2_048)
    } else if bitrate > 62_500 {
        Some(1_024)
    } else {
        None
    }
}

/// Length of interface name hash (80 bits / 10 bytes).
pub const NAME_HASH_LENGTH: usize = 10;

// Ingress control constants — must match Reticulum reference.
pub const IA_FREQ_SAMPLES: usize = 48;
pub const OA_FREQ_SAMPLES: usize = 48;
pub const IP_FREQ_SAMPLES: usize = 48;
pub const OP_FREQ_SAMPLES: usize = 48;
pub const AR_MINFREQ_HZ: f64 = 0.1;
pub const PR_MINFREQ_HZ: f64 = 0.1;
pub const AR_FREQ_DECAY: f64 = 1.0 / AR_MINFREQ_HZ;
pub const PR_FREQ_DECAY: f64 = 1.0 / PR_MINFREQ_HZ;
pub const MAX_HELD_ANNOUNCES: usize = 256;
/// Duration a new interface stays in "new" state (seconds).
pub const IC_NEW_TIME: f64 = 7200.0;
/// Burst threshold for new interfaces (announces/sec).
pub const IC_BURST_FREQ_NEW: f64 = 3.0;
/// Burst threshold for established interfaces (announces/sec).
pub const IC_BURST_FREQ: f64 = 10.0;
/// Burst threshold for new interfaces (path requests/sec).
pub const IC_PR_BURST_FREQ_NEW: f64 = 3.0;
/// Burst threshold for established interfaces (path requests/sec).
pub const IC_PR_BURST_FREQ: f64 = 8.0;
/// Burst detection window duration (seconds).
pub const IC_BURST_HOLD: f64 = 15.0;
/// Penalty duration after a detected burst (seconds).
pub const IC_BURST_PENALTY: f64 = 15.0;
/// Interval between released held announces (seconds).
pub const IC_HELD_RELEASE_INTERVAL: f64 = 5.0;
/// Minimum samples required before incoming frequency is considered defined.
pub const IC_DEQUE_MIN_SAMPLE: usize = 2;
/// Minimum samples required for burst clearing / PR egress limiting.
pub const IC_BURST_MIN_SAMPLES: usize = 6;
/// Optional outgoing path-request limiter threshold (requests/sec).
pub const EC_PR_FREQ: f64 = 5.0;
/// Whether outgoing path-request limiting is active by default.
pub const EGRESS_CONTROL: bool = false;

#[derive(Debug, thiserror::Error)]
pub enum InterfaceError {
    #[error("interface offline")]
    Offline,
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("interface detached")]
    Detached,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimise_mtu() {
        assert_eq!(optimise_mtu(1_000_000_000), Some(524_288));
        assert_eq!(optimise_mtu(100_000_001), Some(32_768));
        assert_eq!(optimise_mtu(10_000_001), Some(16_384));
        assert_eq!(optimise_mtu(62_500), None);
        assert_eq!(optimise_mtu(62_501), Some(1_024));
    }

    #[test]
    fn test_interface_mode_repr() {
        assert_eq!(InterfaceMode::Full as u8, 0x01);
        assert_eq!(InterfaceMode::PointToPoint as u8, 0x02);
        assert_eq!(InterfaceMode::AccessPoint as u8, 0x03);
        assert_eq!(InterfaceMode::Roaming as u8, 0x04);
        assert_eq!(InterfaceMode::Boundary as u8, 0x05);
        assert_eq!(InterfaceMode::Gateway as u8, 0x06);
    }

    #[test]
    fn test_interface_mode_from_u8() {
        assert_eq!(InterfaceMode::from_u8(0x01), Some(InterfaceMode::Full));
        assert_eq!(
            InterfaceMode::from_u8(0x02),
            Some(InterfaceMode::PointToPoint)
        );
        assert_eq!(InterfaceMode::from_u8(0x06), Some(InterfaceMode::Gateway));
        assert_eq!(InterfaceMode::from_u8(0x00), None);
        assert_eq!(InterfaceMode::from_u8(0xFF), None);
    }

    #[test]
    fn test_mode_aliases() {
        assert_eq!(MODE_FULL, InterfaceMode::Full);
        assert_eq!(MODE_POINT_TO_POINT, InterfaceMode::PointToPoint);
    }

    #[test]
    fn test_discover_paths_for() {
        assert!(DISCOVER_PATHS_FOR.contains(&InterfaceMode::AccessPoint));
        assert!(DISCOVER_PATHS_FOR.contains(&InterfaceMode::Gateway));
        assert!(DISCOVER_PATHS_FOR.contains(&InterfaceMode::Roaming));
        assert!(!DISCOVER_PATHS_FOR.contains(&InterfaceMode::Full));
    }

    #[test]
    fn test_name_hash_length() {
        assert_eq!(NAME_HASH_LENGTH, 10);
        assert_eq!(NAME_HASH_LENGTH * 8, 80);
    }

    #[test]
    fn test_ingress_control_constants() {
        assert_eq!(IA_FREQ_SAMPLES, 48);
        assert_eq!(OA_FREQ_SAMPLES, 48);
        assert_eq!(IP_FREQ_SAMPLES, 48);
        assert_eq!(OP_FREQ_SAMPLES, 48);
        assert_eq!(AR_MINFREQ_HZ, 0.1);
        assert_eq!(PR_MINFREQ_HZ, 0.1);
        assert_eq!(AR_FREQ_DECAY, 10.0);
        assert_eq!(PR_FREQ_DECAY, 10.0);
        assert_eq!(IC_BURST_FREQ, 10.0);
        assert_eq!(IC_BURST_FREQ_NEW, 3.0);
        assert_eq!(IC_PR_BURST_FREQ, 8.0);
        assert_eq!(IC_PR_BURST_FREQ_NEW, 3.0);
        assert_eq!(IC_BURST_HOLD, 15.0);
        assert_eq!(IC_BURST_PENALTY, 15.0);
        assert_eq!(IC_NEW_TIME, 7200.0);
        assert_eq!(IC_HELD_RELEASE_INTERVAL, 5.0);
        assert_eq!(IC_DEQUE_MIN_SAMPLE, 2);
        assert_eq!(IC_BURST_MIN_SAMPLES, 6);
        assert_eq!(EC_PR_FREQ, 5.0);
        const { assert!(!EGRESS_CONTROL) };
    }
}
