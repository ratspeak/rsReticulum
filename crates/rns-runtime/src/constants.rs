pub const LOCAL_INTERFACE_PORT: u16 = 37428;
pub const LOCAL_CONTROL_PORT: u16 = 37429;

pub const JOB_INTERVAL: u64 = 300;
pub const CLEAN_INTERVAL: u64 = 900;
pub const PERSIST_INTERVAL: u64 = 43200;

/// Minimum spacing between externally-requested persists.
pub const GRACIOUS_PERSIST_INTERVAL: u64 = 300;

pub const RESOURCE_CACHE: u64 = 86400;
pub use rns_transport::constants::MAX_QUEUED_ANNOUNCES;
pub const QUEUED_ANNOUNCE_LIFE: u64 = rns_transport::constants::QUEUED_ANNOUNCE_LIFE as u64;

/// Announce bandwidth cap as a fraction of interface bitrate (2%).
///
/// Python exposes/configures this as `2` percent, then stores `0.02` on live
/// interfaces. Runtime registration must hand the transport actor the stored
/// fraction, because queue spacing is calculated as `tx_time / announce_cap`.
pub const ANNOUNCE_CAP: f64 = 0.02;

pub const MINIMUM_BITRATE: u64 = 5;
pub const IFAC_MIN_SIZE: usize = 1;
pub const LOG_MAXSIZE: u64 = 5_242_880;
pub const DEFAULT_INSTANCE_NAME: &str = "default";

pub const RPC_AUTH_TAG: &[u8] = b"reticulum_rs_rpc_auth_v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(LOCAL_INTERFACE_PORT, 37428);
        assert_eq!(LOCAL_CONTROL_PORT, 37429);
        assert_eq!(JOB_INTERVAL, 300);
        assert_eq!(CLEAN_INTERVAL, 900);
        assert_eq!(PERSIST_INTERVAL, 43200);
        assert_eq!(RESOURCE_CACHE, 86400);
        assert_eq!(LOG_MAXSIZE, 5_242_880);
    }
}
