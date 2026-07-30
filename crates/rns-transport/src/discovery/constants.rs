//! Wire-level constants for on-network discovery. Values mirror
//! `RNS/Discovery.py` 1:1; do not renumber.

/// Application name used in the discovery destination
/// `rnstransport.discovery.interface`.
pub const APP_NAME: &str = "rnstransport";

/// Destination aspect path used for discovery announces.
pub const DISCOVERY_ASPECTS: &[&str] = &["discovery", "interface"];

/// `rnstransport.discovery.interface` — joined for `aspect_filter` lookups.
pub const DISCOVERY_ASPECT_FILTER: &str = "rnstransport.discovery.interface";

/// Destination aspect path for the distributed blackhole list service.
pub const BLACKHOLE_ASPECTS: &[&str] = &["info", "blackhole"];

/// `rnstransport.info.blackhole` — joined for `aspect_filter` lookups.
pub const BLACKHOLE_ASPECT_FILTER: &str = "rnstransport.info.blackhole";

/// Announce job tick (seconds). Matches Python `InterfaceAnnouncer.JOB_INTERVAL`.
pub const ANNOUNCE_JOB_INTERVAL_SECS: u64 = 60;

/// Default stamp-value requirement used by both sender (when an interface
/// leaves `discovery_stamp_value` unset) and receiver. Matches Python
/// `InterfaceAnnouncer.DEFAULT_STAMP_VALUE`.
pub const DEFAULT_STAMP_VALUE: u8 = 16;

/// Rounds used when deriving the stamp workblock. Matches Python
/// `InterfaceAnnouncer.WORKBLOCK_EXPAND_ROUNDS`.
pub const WORKBLOCK_EXPAND_ROUNDS: u32 = 20;

/// Fixed stamp length (bytes) emitted by the LXMF stamper. Matches Python
/// `LXStamper.STAMP_SIZE`.
pub const STAMP_SIZE: usize = 32;

/// Discovery app_data is prefixed with one flags byte.
pub const FLAG_SIGNED: u8 = 0b0000_0001;
pub const FLAG_ENCRYPTED: u8 = 0b0000_0010;

/// Interface types that announce themselves via discovery. Mirrors
/// `InterfaceAnnouncer.DISCOVERABLE_INTERFACE_TYPES`.
pub const DISCOVERABLE_INTERFACE_TYPES: &[&str] = &[
    "BackboneInterface",
    "TCPServerInterface",
    "TCPClientInterface",
    "RNodeInterface",
    "WeaveInterface",
    "I2PInterface",
    "KISSInterface",
];

/// Interface types eligible for auto-connect. Mirrors
/// `InterfaceDiscovery.AUTOCONNECT_TYPES`.
pub const AUTOCONNECT_INTERFACE_TYPES: &[&str] = &["BackboneInterface", "TCPServerInterface"];

/// Freshness tiers for discovered interfaces (seconds). Match
/// `InterfaceDiscovery.THRESHOLD_*`.
pub const THRESHOLD_UNKNOWN_SECS: u64 = 24 * 60 * 60;
pub const THRESHOLD_STALE_SECS: u64 = 3 * 24 * 60 * 60;
pub const THRESHOLD_REMOVE_SECS: u64 = 7 * 24 * 60 * 60;

/// Monitor-job cadence and detach threshold (Python
/// `InterfaceDiscovery.MONITOR_INTERVAL` / `DETACH_THRESHOLD`).
pub const MONITOR_INTERVAL_SECS: u64 = 5;
pub const DETACH_THRESHOLD_TICKS: u64 = 12;

/// Blackhole updater timings (`BlackholeUpdater.*`).
pub const BLACKHOLE_INITIAL_WAIT_SECS: u64 = 20;
pub const BLACKHOLE_JOB_INTERVAL_SECS: u64 = 60;
pub const BLACKHOLE_UPDATE_INTERVAL_SECS: u64 = 60 * 60;
pub const BLACKHOLE_SOURCE_TIMEOUT_SECS: u64 = 25;

/// msgpack map keys — byte values, must match Python `Discovery.py` exactly.
/// These ride on the wire; renumbering is a breaking protocol change.
pub mod key {
    pub const NAME: u8 = 0xFF;
    pub const TRANSPORT_ID: u8 = 0xFE;
    pub const INTERFACE_TYPE: u8 = 0x00;
    pub const TRANSPORT: u8 = 0x01;
    pub const REACHABLE_ON: u8 = 0x02;
    pub const LATITUDE: u8 = 0x03;
    pub const LONGITUDE: u8 = 0x04;
    pub const HEIGHT: u8 = 0x05;
    pub const PORT: u8 = 0x06;
    pub const IFAC_NETNAME: u8 = 0x07;
    pub const IFAC_NETKEY: u8 = 0x08;
    pub const FREQUENCY: u8 = 0x09;
    pub const BANDWIDTH: u8 = 0x0A;
    pub const SPREADING_FACTOR: u8 = 0x0B;
    pub const CODING_RATE: u8 = 0x0C;
    pub const MODULATION: u8 = 0x0D;
    pub const CHANNEL: u8 = 0x0E;
}
