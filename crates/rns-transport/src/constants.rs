/// Exclusive upper bound for the on-wire hop count. Inbound packets of every
/// packet type are rejected when their raw hop count is at least 128, before
/// the receiving hop adjustment.
pub const PATHFINDER_M: u8 = 128;

/// Number of retransmit retries for announces.
pub const PATHFINDER_R: u8 = 1;

/// Grace period (seconds) before announce retry.
pub const PATHFINDER_G: f64 = 5.0;

/// Announce rebroadcast jitter window, in seconds.
pub const PATHFINDER_RW: f64 = 0.5;

/// Default path expiry (7 days, in seconds).
pub const PATHFINDER_E: u64 = 604_800;

/// Access Point path expiry (24 hours).
pub const AP_PATH_TIME: u64 = 86_400;

/// Roaming path expiry (6 hours).
pub const ROAMING_PATH_TIME: u64 = 21_600;

/// Default path lifetime, in seconds (7 days), except for interface modes
/// with shorter lifetimes. Announce metadata cleanup also uses this value:
/// steady-state cleanup allows 1.25 times this duration for used, pathless
/// entries, while loading applies the base duration to stale, unretained entries.
pub const DESTINATION_TIMEOUT: u64 = 604_800;

/// Transport link-table timeout for validated links, in seconds (15 minutes).
/// This is transport bookkeeping, not an application-level Link keepalive deadline.
pub const LINK_TIMEOUT: f64 = 900.0;

/// Maximum packets retained for one locally-owned established Link while its
/// exact attached interface is applying backpressure. Exhaustion is terminal
/// for that Link; transport never falls back to another interface.
pub const LINK_ENDPOINT_EGRESS_QUEUE_CAPACITY: usize = 256;

/// Reverse table entry timeout (8 minutes).
pub const REVERSE_TIMEOUT: u64 = 480;

/// Receipt-count ceiling applied during periodic maintenance. Registration can
/// temporarily exceed it; maintenance culls the oldest receipts.
pub const MAX_RECEIPTS: usize = 1024;

/// Rate timestamps per destination.
pub const MAX_RATE_TIMESTAMPS: usize = 16;

/// Random blobs saved to disk per destination.
pub const PERSIST_RANDOM_BLOBS: usize = 32;

/// Random blobs kept in memory per destination.
pub const MAX_RANDOM_BLOBS: usize = 64;

/// Max local rebroadcasts before stopping.
pub const LOCAL_REBROADCASTS_MAX: u32 = 2;

/// Base timeout for recursive path discovery, in seconds. A discovered
/// slow-media return budget can extend the actual admission deadline.
pub const PATH_REQUEST_TIMEOUT: f64 = 15.0;

/// Duplicate inbound path request tag retention (seconds).
pub const PATH_REQUEST_GATE_TIMEOUT: f64 = 120.0;

/// Maximum queued automatic discovery path requests after failed link setup.
pub const MAX_QUEUED_DISCOVERY_PRS: usize = 32;

/// Minimum spacing in seconds between dequeuing automatic discovery requests.
/// One dequeued request can be offered to several eligible interfaces.
pub const DISCOVERY_PR_TX_THROTTLE: f64 = 0.5;

/// Grace before path response (seconds).
pub const PATH_REQUEST_GRACE: f64 = 0.4;

/// Extra grace for roaming interfaces (seconds).
pub const PATH_REQUEST_RG: f64 = 1.5;

/// Minimum interval in seconds used to suppress repeated automatic path
/// requests. Explicit caller requests have their own admission rules.
pub const PATH_REQUEST_MI: f64 = 20.0;

/// Default two-generation duplicate-packet hash capacity used by normal
/// insertion. Restoring saved generations does not enforce this bound.
pub const HASHLIST_MAXSIZE: usize = 2_000_000;

/// Job loop period (250ms).
pub const JOB_INTERVAL_MS: u64 = 250;

/// Maintenance tick period in background mode, in milliseconds (2 seconds),
/// when the `mobile-throttle` feature is enabled. Message channels remain
/// serviced; this constant does not impose a packet-processing rate.
pub const JOB_INTERVAL_BG_MS: u64 = 2000;

/// Minimum interval in seconds between dirty routing-state save requests.
/// Periodic saves cover paths, announce metadata, blackholes and tunnels, but
/// exclude the packet hash list. Saves can run on a blocking worker; requesting
/// one is not confirmation of completion or durability. Shutdown and observed
/// foreground-to-background transitions also request saves. Only the background
/// tick cadence change is gated by `mobile-throttle`.
pub const STATE_SAVE_INTERVAL_SECS: f64 = 300.0;

/// Age in seconds after which never-used, pathless, unretained destinations
/// are eligible for announce-metadata cleanup.
pub const UNUSED_DESTINATION_LINGER: f64 = 360.0;

/// Discovery path-request tag count ceiling applied during maintenance, in
/// addition to time-based expiry. It is not an insertion-time hard bound.
pub const MAX_DISCOVERY_PR_TAGS: usize = 32_000;

/// Traffic-rate sampling interval, in seconds. Despite the name, transport
/// link-table culling uses `TABLES_CULL_INTERVAL`.
pub const LINKS_CHECK_INTERVAL: f64 = 1.0;

/// Receipt timeout and count-limit check interval, in seconds.
pub const RECEIPTS_CHECK_INTERVAL: f64 = 1.0;

/// Announce rebroadcast check interval, in seconds.
pub const ANNOUNCES_CHECK_INTERVAL: f64 = 1.0;

/// Exported pending-path-request interval, in seconds. The current transport
/// actor does not use this constant to schedule cleanup.
pub const PENDING_PRS_CHECK_INTERVAL: f64 = 30.0;

/// In-memory hash rotation and announce-metadata cleanup interval, in seconds
/// (5 minutes), after the interface-startup grace period has completed.
pub const CACHE_CLEAN_INTERVAL: f64 = 300.0;

/// On-disk announce cache sweep interval, in seconds (15 minutes). Scheduling
/// does not require the interface-startup grace period; it requires storage,
/// non-client ownership and no sweep already in flight.
pub const ANNOUNCE_CACHE_SWEEP_INTERVAL: f64 = 900.0;

/// Minimum age in seconds before an unreferenced announce-cache file is
/// eligible for removal. This grace reduces races with a keep-set snapshot;
/// it is not a transaction between cache writers and the sweep.
pub const ANNOUNCE_CACHE_SWEEP_GRACE_SECS: u64 = 300;

/// Routing-table and link-table culling interval, in seconds.
pub const TABLES_CULL_INTERVAL: f64 = 5.0;

/// Exported interface-job interval, in seconds. The current transport actor
/// does not use this constant to schedule interface work.
pub const INTERFACE_JOBS_INTERVAL: f64 = 5.0;

/// Exported management-announce interval, in seconds (2 hours). The current
/// transport actor does not schedule management announces from this constant.
pub const MGMT_ANNOUNCE_INTERVAL: f64 = 7200.0;

/// Blackhole expiry check interval, in seconds.
pub const BLACKHOLE_CHECK_INTERVAL: f64 = 60.0;

/// Default announce bandwidth fraction of the declared interface bitrate
/// (0.02 means 2%). Supply a fraction, not a percentage, to transport APIs.
pub const ANNOUNCE_CAP: f64 = 0.02;

/// Maximum ingress-limited announces to hold per interface.
pub const MAX_HELD_ANNOUNCES: usize = 256;

/// Held announce release interval (seconds).
pub const IC_HELD_RELEASE_INTERVAL: f64 = 5.0;

/// Incoming announce frequency window samples.
pub const IA_FREQ_SAMPLES: usize = 48;

/// Outgoing announce frequency window samples.
pub const OA_FREQ_SAMPLES: usize = 48;

/// Incoming path-request frequency window samples.
pub const IP_FREQ_SAMPLES: usize = 48;

/// Outgoing path-request frequency window samples.
pub const OP_FREQ_SAMPLES: usize = 48;

/// Minimum non-zero announce frequency represented by the decay window.
pub const AR_MINFREQ_HZ: f64 = 0.1;

/// Minimum non-zero path-request frequency represented by the decay window.
pub const PR_MINFREQ_HZ: f64 = 0.1;

/// Frequency decay window for announces (seconds).
pub const AR_FREQ_DECAY: f64 = 1.0 / AR_MINFREQ_HZ;

/// Frequency decay window for path requests (seconds).
pub const PR_FREQ_DECAY: f64 = 1.0 / PR_MINFREQ_HZ;

/// Minimum samples required before frequency is considered defined.
pub const IC_DEQUE_MIN_SAMPLE: usize = 2;

/// Minimum samples required for burst state clearing / egress PR limiting.
pub const IC_BURST_MIN_SAMPLES: usize = 6;

/// Duration interface is treated as "new" (seconds).
pub const IC_NEW_TIME: f64 = 7200.0;

/// Burst threshold for new interfaces (announces/sec).
pub const IC_BURST_FREQ_NEW: f64 = 3.0;

/// Burst threshold for established interfaces (announces/sec).
pub const IC_BURST_FREQ: f64 = 10.0;

/// Path-request burst threshold for new interfaces (requests/sec).
pub const IC_PR_BURST_FREQ_NEW: f64 = 3.0;

/// Path-request burst threshold for established interfaces (requests/sec).
pub const IC_PR_BURST_FREQ: f64 = 8.0;

/// Burst detection active duration (seconds).
pub const IC_BURST_HOLD: f64 = 15.0;

/// Burst penalty delay (seconds).
pub const IC_BURST_PENALTY: f64 = 15.0;

/// Optional outgoing path-request limiter threshold (requests/sec).
pub const EC_PR_FREQ: f64 = 5.0;

/// Whether outgoing path-request limiting is active by default.
pub const EGRESS_CONTROL: bool = false;

/// Tunnel timeout (8 hours, in seconds).
pub const TUNNEL_TIMEOUT: u64 = 28_800;

/// Tunnel path timeout (8 hours, in seconds).
pub const TUNNEL_PATH_TIMEOUT: u64 = 28_800;

/// Exported announce-queue interval, in seconds. The current actor processes
/// interface announce queues on its maintenance tick instead.
pub const ANNOUNCE_QUEUE_INTERVAL: f64 = 1.0;

/// Maximum number of packet-metric cache entries retained by the actor.
pub const LOCAL_CLIENT_CACHE_MAXSIZE: usize = 512;

/// Maximum lifetime for queued announces (24 hours, in seconds).
pub const QUEUED_ANNOUNCE_LIFE: f64 = 86_400.0;

/// Maximum number of queued announces per interface.
pub const MAX_QUEUED_ANNOUNCES: usize = 16_384;

/// Grace period in seconds after the first interface registration before
/// startup-gated in-memory cache cleanup becomes eligible.
pub const STARTUP_GRACE_PERIOD: f64 = 3.0;

/// Wire transport mode carried in the packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportMode {
    Broadcast = 0x00,
    Transport = 0x01,
    Relay = 0x02,
    Tunnel = 0x03,
}

/// Exported reachability labels. The current transport actor does not
/// maintain a value of this enum for each destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reachability {
    Unreachable = 0x00,
    Direct = 0x01,
    Transport = 0x02,
}

/// Locally recorded path response state. A stored value alone does not
/// establish present reachability or authenticate a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PathState {
    Unknown = 0x00,
    Unresponsive = 0x01,
    Responsive = 0x02,
}

/// Local interface policy used for announce forwarding and path discovery.
/// These modes are not a reachability signal transmitted to upstream peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceMode {
    Full,
    PointToPoint,
    Gateway,
    AccessPoint,
    Roaming,
    Boundary,
    /// Internal-interface policy: default path expiry and eligibility for
    /// unknown-path discovery. Interface role separately identifies IPC peers.
    Internal,
}

/// Configured traffic-direction flags. These flags do not open an interface
/// or establish that its driver is online.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceDirection {
    /// Whether inbound traffic is enabled.
    pub inbound: bool,
    /// Whether outbound traffic is enabled.
    pub outbound: bool,
}

impl InterfaceDirection {
    /// Enable both direction flags.
    pub fn bidirectional() -> Self {
        Self {
            inbound: true,
            outbound: true,
        }
    }

    /// Enable inbound traffic and disable outbound traffic.
    pub fn inbound_only() -> Self {
        Self {
            inbound: true,
            outbound: false,
        }
    }

    /// Enable outbound traffic and disable inbound traffic.
    pub fn outbound_only() -> Self {
        Self {
            inbound: false,
            outbound: true,
        }
    }
}
