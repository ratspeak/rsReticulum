pub const LOCAL_INTERFACE_PORT: u16 = 37428;
pub const LOCAL_CONTROL_PORT: u16 = 37429;

pub const JOB_INTERVAL: u64 = 300;
pub const CLEAN_INTERVAL: u64 = 900;
pub const PERSIST_INTERVAL: u64 = 43200;

pub const RESOURCE_CACHE: u64 = 86400;
pub const MINIMUM_BITRATE: u64 = 5;
pub const IFAC_MIN_SIZE: usize = 1;
pub const LOG_MAXSIZE: u64 = 5_242_880;
pub const DEFAULT_INSTANCE_NAME: &str = "default";

pub const RPC_AUTH_TAG: &[u8] = b"reticulum_rs_rpc_auth_v1";

/// The Reticulum release this port follows, where upstream gives
/// `RNS.__version__`. It is distinct from this package's release version.
pub const RETICULUM_COMPAT_VERSION: &str = "1.6.0";

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
