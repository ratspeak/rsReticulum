//! Discovery wire identifiers, default work/timing values and local listing
//! policy. Wire key and flag changes affect interoperability; timing defaults
//! and accepted types are separate policy choices.

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

/// Default publication interval in seconds (60), used by the Backbone config helper.
pub const ANNOUNCE_JOB_INTERVAL_SECS: u64 = 60;

/// Default discovery work target/requirement (16 leading zero bits). Sender
/// generation targets and receiver requirements are configured independently.
pub const DEFAULT_STAMP_VALUE: u8 = 16;

/// Discovery stamp-workblock expansion rounds (20). A custom stamper must use
/// the compatible algorithm; the trait does not enforce this constant itself.
pub const WORKBLOCK_EXPAND_ROUNDS: u32 = 20;

/// Fixed discovery stamp length in bytes (32).
pub const STAMP_SIZE: usize = 32;

/// Signed marker in the leading app-data flags byte. Setting it does not
/// create a signature; outer announce authentication is separate.
pub const FLAG_SIGNED: u8 = 0b0000_0001;
/// Marker selecting encrypted body processing after the flags byte.
pub const FLAG_ENCRYPTED: u8 = 0b0000_0010;

/// Types allowed by the announcer's type check and info-map decoder. This
/// list does not establish runtime interface support or listing eligibility;
/// the receiver additionally applies [`DISCOVERED_INTERFACE_TYPES`].
pub const DISCOVERABLE_INTERFACE_TYPES: &[&str] = &[
    "BackboneInterface",
    "TCPServerInterface",
    "TCPClientInterface",
    "RNodeInterface",
    "WeaveInterface",
    "I2PInterface",
    "KISSInterface",
];

/// Types retained by discovery reception and store listing. The store's
/// `list` method attempts to remove records of other types.
pub const DISCOVERED_INTERFACE_TYPES: &[&str] = &[
    "BackboneInterface",
    "TCPServerInterface",
    "I2PInterface",
    "RNodeInterface",
    "WeaveInterface",
    "KISSInterface",
];

/// Types eligible for the auto-connect version filter. Endpoint and other
/// runtime checks are separate.
pub const AUTOCONNECT_INTERFACE_TYPES: &[&str] = &["BackboneInterface"];

/// Implementation name emitted in this stack's discovery info (`0xFD`).
pub const IMPLEMENTATION_NAME: &str = "rsRNS";

/// This transport crate's package version, emitted in discovery info (`0xFC`).
pub const IMPLEMENTATION_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Advertised-version floors for automatic connections. `RNS` has a `1.5.2`
/// floor; `rsRNS` has none and requires the unverified-implementation opt-in.
/// This policy checks sender claims, not authenticated software provenance.
pub const AUTOCONNECT_MINIMUM_VERSIONS: &[(&str, Option<&str>)] =
    &[("RNS", Some("1.5.2")), (IMPLEMENTATION_NAME, None)];

/// Age in seconds above which a record becomes `Unknown` (24 hours).
/// Equality remains `Available`.
pub const THRESHOLD_UNKNOWN_SECS: u64 = 24 * 60 * 60;
/// Age in seconds above which a record becomes `Stale` (three days).
pub const THRESHOLD_STALE_SECS: u64 = 3 * 24 * 60 * 60;
/// Age in seconds above which store listing attempts removal (seven days).
pub const THRESHOLD_REMOVE_SECS: u64 = 7 * 24 * 60 * 60;

/// Exported monitor-interval value in seconds (5). The discovery helpers
/// do not start a monitor or enforce this cadence.
pub const MONITOR_INTERVAL_SECS: u64 = 5;
/// Exported monitor-detachment threshold in ticks (12). The discovery
/// helpers do not implement a detachment monitor.
pub const DETACH_THRESHOLD_TICKS: u64 = 12;

/// Default blackhole subscriber initial wait, in seconds.
pub const BLACKHOLE_INITIAL_WAIT_SECS: u64 = 20;
/// Default blackhole subscriber sweep interval, in seconds.
pub const BLACKHOLE_JOB_INTERVAL_SECS: u64 = 60;
/// Default per-source blackhole update interval, in seconds.
pub const BLACKHOLE_UPDATE_INTERVAL_SECS: u64 = 60 * 60;
/// Default blackhole source-query timeout budget, in seconds.
pub const BLACKHOLE_SOURCE_TIMEOUT_SECS: u64 = 25;

/// Numeric MessagePack map keys for discovery info. These are wire identifiers;
/// renumbering them changes the protocol.
pub mod key {
    pub const NAME: u8 = 0xFF;
    pub const TRANSPORT_ID: u8 = 0xFE;
    pub const TRANSPORT_IMPL: u8 = 0xFD;
    pub const TRANSPORT_VERS: u8 = 0xFC;
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
