//! Shared-instance control RPC codecs and clients for TCP loopback or Unix
//! sockets. Frames use Python multiprocessing-compatible lengths and mutual
//! HMAC challenge/response, followed by MessagePack requests and responses.
//! Tagged SHA-256 and legacy MD5 HMAC challenges are supported; pickle is not.
//!
//! Authentication proves possession of the shared RPC key. It does not encrypt
//! request/response frames or authenticate the separate packet-IPC socket.

use rns_transport::inbound_queues::InboundQueueSnapshot;
use rns_transport::messages::{InterfaceIdentity, InterfaceStatRpcEntry};
use rns_transport::tunnel::RemoteTransportInfo;
use serde::{Deserialize, Serialize};

pub(crate) const MP_CHALLENGE: &[u8] = b"#CHALLENGE#";
pub(crate) const MP_WELCOME: &[u8] = b"#WELCOME#";
pub(crate) const MP_FAILURE: &[u8] = b"#FAILURE#";
const MP_DIGEST_PREFIX: &[u8] = b"{sha256}";
const MP_CHALLENGE_RANDOM_LEN: usize = 40;
const MP_LEGACY_CHALLENGE_RANDOM_LEN: usize = 20;
const MAX_MP_FRAME_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PythonAuthProtocol {
    LegacyMd5,
    Sha256,
}

pub(crate) fn detect_python_auth_protocol(challenge: &[u8]) -> PythonAuthProtocol {
    if challenge.starts_with(MP_DIGEST_PREFIX) {
        PythonAuthProtocol::Sha256
    } else {
        PythonAuthProtocol::LegacyMd5
    }
}

#[derive(Debug, Clone, PartialEq)]
enum PyValue {
    None,
    Bool(bool),
    Int(i128),
    Float(f64),
    Bytes(Vec<u8>),
    String(String),
    List(Vec<PyValue>),
    Dict(Vec<(PyDictKey, PyValue)>),
}

#[derive(Debug, Clone, PartialEq)]
enum PyDictKey {
    String(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcRequest {
    GetPathTable {
        max_hops: Option<u8>,
    },
    GetInterfaceStats,
    GetRateTable,
    GetNextHopIfName {
        destination_hash: Vec<u8>,
    },
    GetNextHop {
        destination_hash: Vec<u8>,
    },
    RequestPath {
        destination_hash: Vec<u8>,
        timeout_secs: Option<f64>,
    },
    GetFirstHopTimeout {
        destination_hash: Vec<u8>,
    },
    GetLinkCount,
    GetPacketRssi {
        packet_hash: Vec<u8>,
    },
    GetPacketSnr {
        packet_hash: Vec<u8>,
    },
    GetPacketQ {
        packet_hash: Vec<u8>,
    },
    GetBlackholedIdentities,
    /// Query whether the transport currently blackholes an identity hash.
    IsBlackholed {
        identity_hash: Vec<u8>,
    },
    DropPath {
        destination_hash: Vec<u8>,
    },
    DropAllVia {
        transport_hash: Vec<u8>,
    },
    DropPathTable,
    DropRecentAnnounces,
    DropAnnounceQueues,
    BlackholeIdentity {
        identity_hash: Vec<u8>,
        until: Option<f64>,
        reason: Option<String>,
    },
    UnblackholeIdentity {
        identity_hash: Vec<u8>,
    },
    UseDestination {
        destination_hash: Vec<u8>,
    },
    RetainDestination {
        destination_hash: Vec<u8>,
    },
    RetainIdentity {
        identity_hash: Vec<u8>,
    },
    UnretainDestination {
        destination_hash: Vec<u8>,
    },
    /// Reply: the slowest online interface bitrate, or nil before one exists.
    GetLowestInterfaceBitrate,
    /// Reply: seconds as a float, or integer 0 without a known bitrate.
    GetMediumPathTimeout,
    GetActiveLinkCount,
    /// Reply: `{destination: {"active", "pending", "traffic", "from_ifs"}}`.
    GetLinkDistribution,
    /// Python 1.6.1 `Reticulum.get_known_destinations`; reply:
    /// `{destination: [last_heard, packet_hash, public_key, app_data, used,
    /// stamp, stamp_value, lr_cost]}`.
    GetKnownDestinations,
    /// Reply: profiler results, or nil when no profiler ran.
    GetProfilingResults,
    /// Reply: true, false, or nil when the interface does not exist.
    ManageInterface {
        operation: ManageOperation,
        name: String,
    },
    WantsDestinationType {
        full_name: String,
        requester: Vec<u8>,
        signature: Option<Vec<u8>>,
    },
    UnwantsDestinationType {
        full_name: String,
        requester: Vec<u8>,
        signature: Option<Vec<u8>>,
    },
    UnwantsAllDestinationTypes {
        requester: Vec<u8>,
        signature: Option<Vec<u8>>,
    },
}

/// Interface management operations of the `manage` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManageOperation {
    Attach,
    Detach,
    Reload,
}

impl ManageOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attach => "attach_interface",
            Self::Detach => "detach_interface",
            Self::Reload => "reload_interface",
        }
    }

    fn parse(operation: &str) -> Option<Self> {
        match operation {
            "attach_interface" => Some(Self::Attach),
            "detach_interface" => Some(Self::Detach),
            "reload_interface" => Some(Self::Reload),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcResponse {
    PathTable(Vec<PathTableEntry>),
    InterfaceStats(#[serde(with = "interface_stats_serde")] Vec<InterfaceStatRpcEntry>),
    RateTable(Vec<RateTableEntry>),
    StringResult(Option<String>),
    HashResult(Option<Vec<u8>>),
    FloatResult(Option<f64>),
    IntResult(i64),
    BoolResult(bool),
    /// True, False or None, as upstream's blackhole mutations answer.
    OptBoolResult(Option<bool>),
    BlackholeList(Vec<BlackholeEntry>),
    LinkDistribution(Vec<LinkDistributionEntry>),
    KnownDestinations(Vec<KnownDestinationEntry>),
    Ok,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTableEntry {
    pub hash: Vec<u8>,
    pub timestamp: f64,
    pub via: Option<Vec<u8>>,
    pub hops: u8,
    pub expires: f64,
    /// Destination stamp value: `None` when the destination is unknown, 0 when
    /// known but unstamped (Reticulum.py).
    #[serde(default)]
    pub value: Option<f64>,
    /// Last use in Unix seconds; 0 when never used, `None` from a peer
    /// before 1.6.0.
    #[serde(default)]
    pub used: Option<f64>,
    #[serde(default)]
    pub lr_cost: Option<f64>,
    pub interface: String,
    /// SHA-256 of upstream's `str(interface)`; `None` from a peer before 1.6.1.
    #[serde(default)]
    pub interface_hash: Option<Vec<u8>>,
    /// Path state: 0 unknown, 1 unresponsive, 2 responsive (Transport.py);
    /// `None` from a peer before 1.6.1.
    #[serde(default)]
    pub state: Option<u8>,
}

/// One interface of Python's `get_interface_stats()` (Reticulum.py), field for
/// key. [`InterfaceStatRpcEntry`] is the public form; the two `From` impls
/// below are the only conversion.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct InterfaceStatWire {
    id: u64,
    name: String,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_rate: u64,
    tx_rate: u64,
    online: bool,
    bitrate: u64,
    mtu: u32,
    mode: String,
    role: String,
    announce_queue: Option<u64>,
    held_announces: u64,
    incoming_announce_frequency: f64,
    outgoing_announce_frequency: f64,
    #[serde(default)]
    incoming_pr_frequency: f64,
    #[serde(default)]
    outgoing_pr_frequency: f64,
    #[serde(default)]
    burst_active: bool,
    #[serde(default)]
    burst_activated: f64,
    #[serde(default)]
    pr_burst_active: bool,
    #[serde(default)]
    pr_burst_activated: f64,
    clients: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blocked_ips: Option<u64>,
    announce_rate_target: Option<f64>,
    announce_rate_grace: Option<u32>,
    announce_rate_penalty: Option<f64>,
    announce_cap: f64,
    /// IFAC signature supplied by runtime records. IFAC fields can also be
    /// `None` when the stats provider has no IFAC records; absence is not proof
    /// that the interface has no IFAC protection.
    #[serde(default)]
    ifac_signature: Option<Vec<u8>>,
    #[serde(default)]
    ifac_size: Option<usize>,
    #[serde(default)]
    ifac_netname: Option<String>,
    tx_drops: u64,
    #[serde(default)]
    tx_dropped_bytes: u64,
    /// Count of received announces, encoded as Python-compatible `arxc`.
    /// The following sent-announce and received/sent-path-request counters map
    /// to `atxc`, `prxc` and `ptxc` respectively.
    #[serde(default)]
    announces_received: u64,
    #[serde(default)]
    announces_sent: u64,
    #[serde(default)]
    path_requests_received: u64,
    #[serde(default)]
    path_requests_sent: u64,
    #[serde(default)]
    protocol_violations: u64,
    #[serde(default)]
    ifac_violations: u64,
    #[serde(default)]
    packet_filter_hits: u64,
    #[serde(default)]
    gravity: i64,
    #[serde(default)]
    announces_to_internal: Option<bool>,
    /// Name of the listener that accepted this interface.
    #[serde(default)]
    parent_interface_name: Option<String>,
    /// The network identity, in hex, that announced an auto-connected
    /// interface (Python `autoconnect_source`).
    #[serde(default)]
    autoconnect_source: Option<String>,
    /// Python `interface.name` and `type(interface).__name__`, when known.
    #[serde(default)]
    short_name: Option<String>,
    #[serde(default)]
    class_name: Option<String>,
    /// Python `rxs`, `txs`, `arxs`, `atxs`, `prxs` and `ptxs` in bits per
    /// second; `None` before the interface's first traffic count.
    #[serde(default)]
    speeds: Option<[f64; 6]>,
    #[serde(default)]
    announce_rx_bytes: u64,
    #[serde(default)]
    announce_tx_bytes: u64,
    #[serde(default)]
    path_request_rx_bytes: u64,
    #[serde(default)]
    path_request_tx_bytes: u64,
    #[serde(default)]
    burst_count: Option<u64>,
    #[serde(default)]
    pr_burst_count: Option<u64>,
    #[serde(default)]
    rssi: Option<f64>,
    #[serde(default)]
    snr: Option<f64>,
    #[serde(default)]
    signal_quality: Option<f64>,
    #[serde(default)]
    peers: Option<u64>,
    #[serde(default)]
    i2p_connectable: Option<bool>,
    /// Python `i2p_b32` with its `.b32.i2p` suffix.
    #[serde(default)]
    i2p_b32: Option<String>,
    /// Python `tunnelstate`.
    #[serde(default)]
    tunnel_state: Option<String>,
    #[serde(default)]
    tx_stalled: bool,
    #[serde(default)]
    tx_buffered: u64,
    /// Python 1.6.1 `frxb`, `ftxb` and `afrxc`.
    #[serde(default)]
    filtered_rx_bytes: u64,
    #[serde(default)]
    filtered_tx_bytes: u64,
    #[serde(default)]
    announces_filtered: u64,
    /// Python `frxs` and `ftxs`; `None` before the first traffic count.
    #[serde(default)]
    filtered_speeds: Option<[f64; 2]>,
    #[serde(default)]
    tunnel_id: Option<Vec<u8>>,
    #[serde(default)]
    remote_transport_id: Option<Vec<u8>>,
    /// Python `rem_impl`, `rem_vers`, `rem_is_tn`, `rem_dst_cost` and `rem_pr_cost`.
    #[serde(default)]
    remote_implementation: Option<String>,
    #[serde(default)]
    remote_version: Option<Vec<u64>>,
    #[serde(default)]
    remote_is_transport: Option<bool>,
    #[serde(default)]
    remote_destination_cost: Option<f64>,
    #[serde(default)]
    remote_pr_cost: Option<f64>,
}

impl From<&InterfaceStatRpcEntry> for InterfaceStatWire {
    fn from(e: &InterfaceStatRpcEntry) -> Self {
        let (name, short_name, class_name) = match &e.identity {
            Some(identity) => (
                identity.name.clone(),
                Some(identity.short_name.clone()),
                Some(identity.class_name.clone()),
            ),
            None => (e.name.clone(), None, None),
        };
        Self {
            id: e.id,
            name,
            rx_bytes: e.rx_bytes,
            tx_bytes: e.tx_bytes,
            rx_rate: e.rx_rate,
            tx_rate: e.tx_rate,
            online: e.online,
            bitrate: e.bitrate,
            mtu: e.mtu,
            mode: e.mode.clone(),
            role: e.role.clone(),
            announce_queue: e.announce_queue,
            held_announces: e.held_announces,
            incoming_announce_frequency: e.incoming_announce_frequency,
            outgoing_announce_frequency: e.outgoing_announce_frequency,
            incoming_pr_frequency: e.incoming_pr_frequency,
            outgoing_pr_frequency: e.outgoing_pr_frequency,
            burst_active: e.burst_active,
            burst_activated: e.burst_activated,
            pr_burst_active: e.pr_burst_active,
            pr_burst_activated: e.pr_burst_activated,
            clients: e.clients,
            blocked_ips: e.blocked_ips,
            announce_rate_target: e.announce_rate_target,
            announce_rate_grace: e.announce_rate_grace,
            announce_rate_penalty: e.announce_rate_penalty,
            announce_cap: e.announce_cap,
            ifac_signature: e.ifac_signature.clone(),
            ifac_size: e.ifac_size,
            ifac_netname: e.ifac_netname.clone(),
            tx_drops: e.tx_drops,
            tx_dropped_bytes: e.tx_dropped_bytes,
            announces_received: e.announces_received,
            announces_sent: e.announces_sent,
            path_requests_received: e.path_requests_received,
            path_requests_sent: e.path_requests_sent,
            protocol_violations: e.protocol_violations,
            ifac_violations: e.ifac_violations,
            packet_filter_hits: e.packet_filter_hits,
            gravity: e.gravity,
            announces_to_internal: e.announces_to_internal,
            parent_interface_name: e.parent_interface_name.clone(),
            autoconnect_source: e.autoconnect_source.clone(),
            short_name,
            class_name,
            speeds: e.speeds,
            announce_rx_bytes: e.announce_rx_bytes,
            announce_tx_bytes: e.announce_tx_bytes,
            path_request_rx_bytes: e.path_request_rx_bytes,
            path_request_tx_bytes: e.path_request_tx_bytes,
            burst_count: e.burst_count,
            pr_burst_count: e.pr_burst_count,
            rssi: e.rssi,
            snr: e.snr,
            signal_quality: e.signal_quality,
            peers: e.peers,
            i2p_connectable: e.i2p_connectable,
            i2p_b32: e
                .i2p_b32
                .as_ref()
                .map(|b32| format!("{b32}{I2P_B32_SUFFIX}")),
            tunnel_state: e
                .i2p_tunnel_state
                .map(|state| i2p_tunnel_state_text(state).to_string()),
            tx_stalled: e.tx_stalled,
            tx_buffered: e.tx_buffered,
            filtered_rx_bytes: e.filtered_rx_bytes,
            filtered_tx_bytes: e.filtered_tx_bytes,
            announces_filtered: e.announces_filtered,
            filtered_speeds: e.filtered_speeds,
            tunnel_id: e.tunnel_id.map(|id| id.to_vec()),
            remote_transport_id: e.remote_transport_id.map(|id| id.to_vec()),
            remote_implementation: e
                .remote_transport
                .as_ref()
                .map(|r| r.implementation.clone()),
            remote_version: e.remote_transport.as_ref().map(|r| r.version.clone()),
            remote_is_transport: e.remote_transport.as_ref().map(|r| r.transport),
            remote_destination_cost: e.remote_transport.as_ref().map(|r| r.destination_cost),
            remote_pr_cost: e.remote_transport.as_ref().map(|r| r.pr_cost),
        }
    }
}

impl From<InterfaceStatWire> for InterfaceStatRpcEntry {
    fn from(w: InterfaceStatWire) -> Self {
        let mut e = InterfaceStatRpcEntry::default();
        // Python always sends its class name; with it the three names are known.
        e.identity = w.class_name.map(|class_name| {
            InterfaceIdentity::new(
                w.name.clone(),
                w.short_name.unwrap_or_else(|| w.name.clone()),
                class_name,
            )
        });
        e.id = w.id;
        e.name = w.name;
        e.rx_bytes = w.rx_bytes;
        e.tx_bytes = w.tx_bytes;
        e.rx_rate = w.rx_rate;
        e.tx_rate = w.tx_rate;
        e.online = w.online;
        e.bitrate = w.bitrate;
        e.mtu = w.mtu;
        e.mode = w.mode;
        e.role = w.role;
        e.announce_queue = w.announce_queue;
        e.held_announces = w.held_announces;
        e.incoming_announce_frequency = w.incoming_announce_frequency;
        e.outgoing_announce_frequency = w.outgoing_announce_frequency;
        e.incoming_pr_frequency = w.incoming_pr_frequency;
        e.outgoing_pr_frequency = w.outgoing_pr_frequency;
        e.burst_active = w.burst_active;
        e.burst_activated = w.burst_activated;
        e.pr_burst_active = w.pr_burst_active;
        e.pr_burst_activated = w.pr_burst_activated;
        e.clients = w.clients;
        e.blocked_ips = w.blocked_ips;
        e.announce_rate_target = w.announce_rate_target;
        e.announce_rate_grace = w.announce_rate_grace;
        e.announce_rate_penalty = w.announce_rate_penalty;
        e.announce_cap = w.announce_cap;
        e.ifac_signature = w.ifac_signature;
        e.ifac_size = w.ifac_size;
        e.ifac_netname = w.ifac_netname;
        e.tx_drops = w.tx_drops;
        e.tx_dropped_bytes = w.tx_dropped_bytes;
        e.announces_received = w.announces_received;
        e.announces_sent = w.announces_sent;
        e.path_requests_received = w.path_requests_received;
        e.path_requests_sent = w.path_requests_sent;
        e.protocol_violations = w.protocol_violations;
        e.ifac_violations = w.ifac_violations;
        e.packet_filter_hits = w.packet_filter_hits;
        e.gravity = w.gravity;
        e.announces_to_internal = w.announces_to_internal;
        e.parent_interface_name = w.parent_interface_name;
        e.autoconnect_source = w.autoconnect_source;
        e.speeds = w.speeds;
        e.announce_rx_bytes = w.announce_rx_bytes;
        e.announce_tx_bytes = w.announce_tx_bytes;
        e.path_request_rx_bytes = w.path_request_rx_bytes;
        e.path_request_tx_bytes = w.path_request_tx_bytes;
        e.burst_count = w.burst_count;
        e.pr_burst_count = w.pr_burst_count;
        e.rssi = w.rssi;
        e.snr = w.snr;
        e.signal_quality = w.signal_quality;
        e.peers = w.peers;
        e.i2p_connectable = w.i2p_connectable;
        e.i2p_b32 = w.i2p_b32.map(|b32| match b32.strip_suffix(I2P_B32_SUFFIX) {
            Some(bare) => bare.to_string(),
            None => b32,
        });
        e.i2p_tunnel_state = w.tunnel_state.as_deref().map(i2p_tunnel_state_code);
        e.tx_stalled = w.tx_stalled;
        e.tx_buffered = w.tx_buffered;
        e.filtered_rx_bytes = w.filtered_rx_bytes;
        e.filtered_tx_bytes = w.filtered_tx_bytes;
        e.announces_filtered = w.announces_filtered;
        e.filtered_speeds = w.filtered_speeds;
        e.tunnel_id = w.tunnel_id.and_then(|id| id.try_into().ok());
        e.remote_transport_id = w.remote_transport_id.and_then(|id| id.try_into().ok());
        // Python sets the five together from one synthesis extension (Transport.py).
        e.remote_transport = match (
            w.remote_implementation,
            w.remote_version,
            w.remote_is_transport,
            w.remote_destination_cost,
            w.remote_pr_cost,
        ) {
            (Some(implementation), Some(version), Some(transport), Some(dst), Some(pr)) => Some(
                RemoteTransportInfo::new(implementation, version, transport, dst, pr),
            ),
            _ => None,
        };
        e
    }
}

const I2P_B32_SUFFIX: &str = ".b32.i2p";

/// Python's text for `I2PInterfacePeer.TUNNEL_STATE_*` (Reticulum.py).
fn i2p_tunnel_state_text(state: u8) -> &'static str {
    match state {
        0x01 => "Tunnel Active",
        0x00 => "Creating Tunnel",
        0x02 => "Tunnel Unresponsive",
        _ => "Unknown State",
    }
}

/// The inverse; other text keeps a code that reads back as unknown.
fn i2p_tunnel_state_code(text: &str) -> u8 {
    match text {
        "Tunnel Active" => 0x01,
        "Creating Tunnel" => 0x00,
        "Tunnel Unresponsive" => 0x02,
        _ => 0xFF,
    }
}

fn wire_entries(entries: &[InterfaceStatRpcEntry]) -> Vec<InterfaceStatWire> {
    entries.iter().map(InterfaceStatWire::from).collect()
}

/// `RpcResponse::InterfaceStats` keeps the serde form of the wire entries.
mod interface_stats_serde {
    use super::{InterfaceStatRpcEntry, InterfaceStatWire, wire_entries};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(
        entries: &[InterfaceStatRpcEntry],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        wire_entries(entries).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<InterfaceStatRpcEntry>, D::Error> {
        let entries = Vec::<InterfaceStatWire>::deserialize(deserializer)?;
        Ok(entries.into_iter().map(Into::into).collect())
    }
}

/// What a transport instance adds to its interface stats
/// (Reticulum.py).
#[derive(Debug, Clone, Copy)]
pub(crate) struct TransportStats {
    pub(crate) transport_id: [u8; 16],
    pub(crate) network_id: Option<[u8; 16]>,
    pub(crate) uptime: f64,
    pub(crate) probe_responder: Option<[u8; 16]>,
}

/// Python's top-level traffic, packet, link and path counters
/// (Reticulum.py).
pub(crate) type TrafficTotals = rns_transport::messages::TrafficTotalsRpcEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateTableEntry {
    pub hash: Vec<u8>,
    pub rate: f64,
    pub last: f64,
    pub rate_violations: u32,
    pub blocked_until: f64,
    pub timestamps: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackholeEntry {
    pub identity_hash: Vec<u8>,
    pub source: Option<Vec<u8>>,
    pub until: Option<f64>,
    pub reason: Option<String>,
}

/// Relayed Links toward one destination (Python `Transport.link_distribution`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkDistributionEntry {
    pub destination_hash: Vec<u8>,
    pub active: u64,
    pub pending: u64,
    pub traffic: u64,
    /// `Interface.get_hash()` of each interface a link request arrived on.
    pub from_interfaces: Vec<Vec<u8>>,
}

impl From<&rns_transport::messages::LinkDistributionRpcEntry> for LinkDistributionEntry {
    fn from(e: &rns_transport::messages::LinkDistributionRpcEntry) -> Self {
        Self {
            destination_hash: e.destination_hash.to_vec(),
            active: e.active,
            pending: e.pending,
            traffic: e.traffic,
            from_interfaces: e.from_interfaces.iter().map(|hash| hash.to_vec()).collect(),
        }
    }
}

/// One `Identity.known_destinations` entry under its destination hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnownDestinationEntry {
    pub destination_hash: Vec<u8>,
    pub last_heard: f64,
    pub packet_hash: Option<Vec<u8>>,
    pub public_key: Vec<u8>,
    pub app_data: Option<Vec<u8>>,
    /// 0 never used, -1 retained, otherwise the Unix time of last use.
    pub used: f64,
    pub stamp: Option<Vec<u8>>,
    pub stamp_value: f64,
    pub lr_cost: Option<f64>,
}

impl From<&rns_transport::store::KnownDestinationRow> for KnownDestinationEntry {
    fn from(row: &rns_transport::store::KnownDestinationRow) -> Self {
        Self {
            destination_hash: row.destination_hash.to_vec(),
            last_heard: row.last_heard,
            packet_hash: row.packet_hash.map(|hash| hash.to_vec()),
            public_key: row.public_key.to_vec(),
            app_data: row.app_data.clone(),
            used: row.used,
            stamp: row.stamp.clone(),
            stamp_value: row.stamp_value,
            lr_cost: row.lr_cost,
        }
    }
}

impl KnownDestinationEntry {
    /// The store row, or `None` for a malformed hash or key.
    pub fn to_row(&self) -> Option<rns_transport::store::KnownDestinationRow> {
        let mut row = rns_transport::store::KnownDestinationRow::new(
            self.destination_hash.as_slice().try_into().ok()?,
            self.last_heard,
            self.public_key.as_slice().try_into().ok()?,
        );
        row.packet_hash = match &self.packet_hash {
            Some(hash) => Some(hash.as_slice().try_into().ok()?),
            None => None,
        };
        row.app_data = self.app_data.clone();
        row.used = self.used;
        row.stamp = self.stamp.clone();
        row.stamp_value = self.stamp_value;
        row.lr_cost = self.lr_cost;
        Some(row)
    }
}

pub fn encode_request(req: &RpcRequest) -> Result<Vec<u8>, RpcError> {
    encode_umsgpack(&request_to_py_value(req))
}

pub fn decode_request(data: &[u8]) -> Result<RpcRequest, RpcError> {
    let value = decode_umsgpack(data)?;
    py_value_to_request(&value)
}

pub fn encode_response(resp: &RpcResponse) -> Result<Vec<u8>, RpcError> {
    encode_umsgpack(&response_to_py_value(resp))
}

/// Decode one response by its MessagePack shape. Empty lists are ambiguous
/// and become an empty path table; prefer `decode_response_for_request` when
/// the originating request is known. Trailing bytes are ignored.
pub fn decode_response(data: &[u8]) -> Result<RpcResponse, RpcError> {
    let value = decode_umsgpack(data)?;
    py_value_to_response(&value)
}

/// Decode one MessagePack response using the originating request to select
/// its result type, including empty lists and nil values. Trailing bytes are
/// ignored; the caller owns framing and peer authentication.
pub fn decode_response_for_request(
    data: &[u8],
    request: &RpcRequest,
) -> Result<RpcResponse, RpcError> {
    let value = decode_umsgpack(data)?;
    py_value_to_response_for_request(&value, request)
}

pub fn compute_auth_hmac(key: &[u8], challenge: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key can be any length");
    mac.update(challenge);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

pub fn compute_legacy_auth_hmac(key: &[u8], challenge: &[u8]) -> [u8; 16] {
    use hmac::{Hmac, Mac};
    use md5::Md5;

    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC key can be any length");
    mac.update(challenge);
    let result = mac.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// Compare the computed HMAC-SHA-256 with a fixed 32-byte response using
/// constant-time equality. This is not a timing guarantee for an entire RPC session.
pub fn verify_auth_hmac(key: &[u8], challenge: &[u8], provided: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    let expected = compute_auth_hmac(key, challenge);
    expected.ct_eq(provided).into()
}

/// SHA-256 of the supplied private-key bytes, used as the default shared RPC
/// secret. The caller supplies the correct transport private-key material;
/// this helper does not validate its representation or length.
pub fn derive_rpc_key(identity_private_key: &[u8]) -> [u8; 32] {
    rns_crypto::sha::sha256(identity_private_key)
}

fn request_to_py_value(req: &RpcRequest) -> PyValue {
    match req {
        RpcRequest::GetPathTable { max_hops } => py_dict(vec![
            ("get", PyValue::String("path_table".to_string())),
            (
                "max_hops",
                max_hops
                    .map(|v| PyValue::Int(i128::from(v)))
                    .unwrap_or(PyValue::None),
            ),
        ]),
        RpcRequest::GetInterfaceStats => py_get("interface_stats"),
        RpcRequest::GetRateTable => py_get("rate_table"),
        RpcRequest::GetNextHopIfName { destination_hash } => py_dict(vec![
            ("get", PyValue::String("next_hop_if_name".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::GetNextHop { destination_hash } => py_dict(vec![
            ("get", PyValue::String("next_hop".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::RequestPath {
            destination_hash,
            timeout_secs,
        } => py_dict(vec![
            ("request", PyValue::String("path".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
            (
                "timeout",
                timeout_secs.map(PyValue::Float).unwrap_or(PyValue::None),
            ),
        ]),
        RpcRequest::GetFirstHopTimeout { destination_hash } => py_dict(vec![
            ("get", PyValue::String("first_hop_timeout".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::GetLinkCount => py_get("link_count"),
        RpcRequest::GetPacketRssi { packet_hash } => py_dict(vec![
            ("get", PyValue::String("packet_rssi".to_string())),
            ("packet_hash", PyValue::Bytes(packet_hash.clone())),
        ]),
        RpcRequest::GetPacketSnr { packet_hash } => py_dict(vec![
            ("get", PyValue::String("packet_snr".to_string())),
            ("packet_hash", PyValue::Bytes(packet_hash.clone())),
        ]),
        RpcRequest::GetPacketQ { packet_hash } => py_dict(vec![
            ("get", PyValue::String("packet_q".to_string())),
            ("packet_hash", PyValue::Bytes(packet_hash.clone())),
        ]),
        RpcRequest::GetBlackholedIdentities => py_get("blackholed_identities"),
        RpcRequest::IsBlackholed { identity_hash } => py_dict(vec![
            ("get", PyValue::String("is_blackholed".to_string())),
            ("identity_hash", PyValue::Bytes(identity_hash.clone())),
        ]),
        RpcRequest::DropPath { destination_hash } => py_dict(vec![
            ("drop", PyValue::String("path".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::DropAllVia { transport_hash } => py_dict(vec![
            ("drop", PyValue::String("all_via".to_string())),
            ("destination_hash", PyValue::Bytes(transport_hash.clone())),
        ]),
        RpcRequest::DropPathTable => {
            py_dict(vec![("drop", PyValue::String("path_table".to_string()))])
        }
        RpcRequest::DropRecentAnnounces => py_dict(vec![(
            "drop",
            PyValue::String("recent_announces".to_string()),
        )]),
        RpcRequest::DropAnnounceQueues => py_dict(vec![(
            "drop",
            PyValue::String("announce_queues".to_string()),
        )]),
        RpcRequest::BlackholeIdentity {
            identity_hash,
            until,
            reason,
        } => py_dict(vec![
            ("blackhole_identity", PyValue::Bytes(identity_hash.clone())),
            ("until", until.map(PyValue::Float).unwrap_or(PyValue::None)),
            (
                "reason",
                reason.clone().map(PyValue::String).unwrap_or(PyValue::None),
            ),
        ]),
        RpcRequest::UnblackholeIdentity { identity_hash } => py_dict(vec![(
            "unblackhole_identity",
            PyValue::Bytes(identity_hash.clone()),
        )]),
        RpcRequest::UseDestination { destination_hash } => py_dict(vec![
            ("destination_data", PyValue::String("used".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::RetainDestination { destination_hash } => py_dict(vec![
            ("destination_data", PyValue::String("retain".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::RetainIdentity { identity_hash } => py_dict(vec![
            ("identity_data", PyValue::String("retain".to_string())),
            ("identity_hash", PyValue::Bytes(identity_hash.clone())),
        ]),
        RpcRequest::UnretainDestination { destination_hash } => py_dict(vec![
            ("destination_data", PyValue::String("unretain".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::GetLowestInterfaceBitrate => py_get("lowest_interface_bitrate"),
        RpcRequest::GetMediumPathTimeout => py_get("medium_path_timeout"),
        RpcRequest::GetActiveLinkCount => py_get("active_link_count"),
        RpcRequest::GetLinkDistribution => py_get("link_distribution"),
        RpcRequest::GetKnownDestinations => py_get("known_destinations"),
        RpcRequest::GetProfilingResults => py_get("profiling_results"),
        RpcRequest::ManageInterface { operation, name } => py_dict(vec![
            ("manage", PyValue::String(operation.as_str().to_string())),
            ("name", PyValue::String(name.clone())),
        ]),
        RpcRequest::WantsDestinationType {
            full_name,
            requester,
            signature,
        } => py_dict(vec![
            ("wants_destination_type", PyValue::String(full_name.clone())),
            ("requester", PyValue::Bytes(requester.clone())),
            ("signature", optional_bytes_value(signature)),
        ]),
        RpcRequest::UnwantsDestinationType {
            full_name,
            requester,
            signature,
        } => py_dict(vec![
            (
                "unwants_destination_type",
                PyValue::String(full_name.clone()),
            ),
            ("requester", PyValue::Bytes(requester.clone())),
            ("signature", optional_bytes_value(signature)),
        ]),
        RpcRequest::UnwantsAllDestinationTypes {
            requester,
            signature,
        } => py_dict(vec![
            ("unwants_all_destination_types", PyValue::Bool(true)),
            ("requester", PyValue::Bytes(requester.clone())),
            ("signature", optional_bytes_value(signature)),
        ]),
    }
}

fn optional_bytes_value(value: &Option<Vec<u8>>) -> PyValue {
    value.clone().map(PyValue::Bytes).unwrap_or(PyValue::None)
}

fn py_get(path: &str) -> PyValue {
    py_dict(vec![("get", PyValue::String(path.to_string()))])
}

fn py_dict(entries: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(
        entries
            .into_iter()
            .map(|(k, v)| (PyDictKey::String(k.to_string()), v))
            .collect(),
    )
}

fn py_value_to_request(value: &PyValue) -> Result<RpcRequest, RpcError> {
    let entries = as_dict(value)?;
    if let Some(PyValue::String(path)) = dict_get(entries, "get") {
        return match path.as_str() {
            "path_table" => Ok(RpcRequest::GetPathTable {
                max_hops: dict_get(entries, "max_hops").and_then(py_u8),
            }),
            "interface_stats" => Ok(RpcRequest::GetInterfaceStats),
            "rate_table" => Ok(RpcRequest::GetRateTable),
            "next_hop_if_name" => Ok(RpcRequest::GetNextHopIfName {
                destination_hash: dict_bytes(entries, "destination_hash")?,
            }),
            "next_hop" => Ok(RpcRequest::GetNextHop {
                destination_hash: dict_bytes(entries, "destination_hash")?,
            }),
            "first_hop_timeout" => Ok(RpcRequest::GetFirstHopTimeout {
                destination_hash: dict_bytes(entries, "destination_hash")?,
            }),
            "link_count" => Ok(RpcRequest::GetLinkCount),
            "packet_rssi" => Ok(RpcRequest::GetPacketRssi {
                packet_hash: dict_bytes(entries, "packet_hash")?,
            }),
            "packet_snr" => Ok(RpcRequest::GetPacketSnr {
                packet_hash: dict_bytes(entries, "packet_hash")?,
            }),
            "packet_q" => Ok(RpcRequest::GetPacketQ {
                packet_hash: dict_bytes(entries, "packet_hash")?,
            }),
            "blackholed_identities" => Ok(RpcRequest::GetBlackholedIdentities),
            "is_blackholed" => Ok(RpcRequest::IsBlackholed {
                identity_hash: dict_bytes(entries, "identity_hash")?,
            }),
            "lowest_interface_bitrate" => Ok(RpcRequest::GetLowestInterfaceBitrate),
            "medium_path_timeout" => Ok(RpcRequest::GetMediumPathTimeout),
            "active_link_count" => Ok(RpcRequest::GetActiveLinkCount),
            "link_distribution" => Ok(RpcRequest::GetLinkDistribution),
            "known_destinations" => Ok(RpcRequest::GetKnownDestinations),
            "profiling_results" => Ok(RpcRequest::GetProfilingResults),
            other => Err(RpcError::Deserialize(format!(
                "unknown Python RPC get path: {other}"
            ))),
        };
    }

    if let Some(PyValue::String(operation)) = dict_get(entries, "manage") {
        let operation = ManageOperation::parse(operation).ok_or_else(|| {
            RpcError::Deserialize(format!("unknown Python RPC manage operation: {operation}"))
        })?;
        let name = dict_get(entries, "name")
            .and_then(py_string)
            .ok_or_else(|| RpcError::Deserialize("manage request has no name".to_string()))?;
        return Ok(RpcRequest::ManageInterface { operation, name });
    }

    if let Some(PyValue::String(path)) = dict_get(entries, "drop") {
        return match path.as_str() {
            "path" => Ok(RpcRequest::DropPath {
                destination_hash: dict_bytes(entries, "destination_hash")?,
            }),
            "all_via" => Ok(RpcRequest::DropAllVia {
                transport_hash: dict_bytes(entries, "destination_hash")?,
            }),
            "path_table" => Ok(RpcRequest::DropPathTable),
            "recent_announces" => Ok(RpcRequest::DropRecentAnnounces),
            "announce_queues" => Ok(RpcRequest::DropAnnounceQueues),
            other => Err(RpcError::Deserialize(format!(
                "unknown Python RPC drop path: {other}"
            ))),
        };
    }

    if let Some(PyValue::String(path)) = dict_get(entries, "request") {
        return match path.as_str() {
            "path" => Ok(RpcRequest::RequestPath {
                destination_hash: dict_bytes(entries, "destination_hash")?,
                timeout_secs: dict_get(entries, "timeout").and_then(py_f64),
            }),
            other => Err(RpcError::Deserialize(format!(
                "unknown Python RPC request path: {other}"
            ))),
        };
    }

    if let Some(PyValue::Bytes(identity_hash)) = dict_get(entries, "blackhole_identity") {
        return Ok(RpcRequest::BlackholeIdentity {
            identity_hash: identity_hash.clone(),
            until: dict_get(entries, "until").and_then(py_f64),
            reason: dict_get(entries, "reason").and_then(py_string),
        });
    }

    if let Some(PyValue::Bytes(identity_hash)) = dict_get(entries, "unblackhole_identity") {
        return Ok(RpcRequest::UnblackholeIdentity {
            identity_hash: identity_hash.clone(),
        });
    }

    if let Some(full_name) = dict_get(entries, "wants_destination_type") {
        return Ok(RpcRequest::WantsDestinationType {
            full_name: destination_type_name(full_name)?,
            requester: dict_requester(entries)?,
            signature: dict_signature(entries)?,
        });
    }

    if let Some(full_name) = dict_get(entries, "unwants_destination_type") {
        return Ok(RpcRequest::UnwantsDestinationType {
            full_name: destination_type_name(full_name)?,
            requester: dict_requester(entries)?,
            signature: dict_signature(entries)?,
        });
    }

    if dict_get(entries, "unwants_all_destination_types").is_some() {
        return Ok(RpcRequest::UnwantsAllDestinationTypes {
            requester: dict_requester(entries)?,
            signature: dict_signature(entries)?,
        });
    }

    if let Some(PyValue::String(operation)) = dict_get(entries, "destination_data") {
        let destination_hash = dict_bytes(entries, "destination_hash")?;
        return match operation.as_str() {
            "used" => Ok(RpcRequest::UseDestination { destination_hash }),
            "retain" => Ok(RpcRequest::RetainDestination { destination_hash }),
            "unretain" => Ok(RpcRequest::UnretainDestination { destination_hash }),
            other => Err(RpcError::Deserialize(format!(
                "unknown Python RPC destination_data operation: {other}"
            ))),
        };
    }

    if let Some(PyValue::String(operation)) = dict_get(entries, "identity_data") {
        let identity_hash = dict_bytes(entries, "identity_hash")?;
        return match operation.as_str() {
            "retain" => Ok(RpcRequest::RetainIdentity { identity_hash }),
            other => Err(RpcError::Deserialize(format!(
                "unknown Python RPC identity_data operation: {other}"
            ))),
        };
    }

    Err(RpcError::Deserialize(
        "Python RPC request dictionary has no known operation".to_string(),
    ))
}

fn destination_type_name(value: &PyValue) -> Result<String, RpcError> {
    py_string(value)
        .ok_or_else(|| RpcError::Deserialize("destination type name is not a string".to_string()))
}

/// Python requires the `requester` key and keys requirements by it as sent;
/// a nil requester is kept as an empty one.
fn dict_requester(entries: &[(PyDictKey, PyValue)]) -> Result<Vec<u8>, RpcError> {
    match dict_get(entries, "requester") {
        Some(PyValue::Bytes(requester)) => Ok(requester.clone()),
        Some(PyValue::None) => Ok(Vec::new()),
        _ => Err(RpcError::Deserialize(
            "destination type request has no requester".to_string(),
        )),
    }
}

/// Python requires the `signature` key but never validates its value, so a
/// value other than bytes is kept as `None`.
fn dict_signature(entries: &[(PyDictKey, PyValue)]) -> Result<Option<Vec<u8>>, RpcError> {
    match dict_get(entries, "signature") {
        Some(PyValue::Bytes(signature)) => Ok(Some(signature.clone())),
        Some(_) => Ok(None),
        None => Err(RpcError::Deserialize(
            "destination type request has no signature".to_string(),
        )),
    }
}

/// Python `None`, as `profiling_results` answers when no profiler ran.
pub(crate) fn encode_none() -> Result<Vec<u8>, RpcError> {
    encode_umsgpack(&PyValue::None)
}

/// An integer or `None`, as `lowest_interface_bitrate` answers.
pub(crate) fn encode_optional_int(value: Option<u64>) -> Result<Vec<u8>, RpcError> {
    encode_umsgpack(
        &value
            .map(|v| PyValue::Int(i128::from(v)))
            .unwrap_or(PyValue::None),
    )
}

/// `True`, `False` or `None`, as the `manage` request answers.
pub(crate) fn encode_optional_bool(value: Option<bool>) -> Result<Vec<u8>, RpcError> {
    encode_umsgpack(&value.map(PyValue::Bool).unwrap_or(PyValue::None))
}

/// A float, or integer 0 when the timeout is unknown (Transport.py).
pub(crate) fn encode_medium_path_timeout(seconds: Option<f64>) -> Result<Vec<u8>, RpcError> {
    encode_umsgpack(&seconds.map(PyValue::Float).unwrap_or(PyValue::Int(0)))
}

fn response_to_py_value(resp: &RpcResponse) -> PyValue {
    match resp {
        RpcResponse::PathTable(entries) => PyValue::List(
            entries
                .iter()
                .map(|e| {
                    // A key an older peer lacks stays absent, as in its dict.
                    let mut fields = vec![
                        ("hash", PyValue::Bytes(e.hash.clone())),
                        ("timestamp", PyValue::Float(e.timestamp)),
                        (
                            "via",
                            e.via.clone().map(PyValue::Bytes).unwrap_or(PyValue::None),
                        ),
                        ("hops", PyValue::Int(i128::from(e.hops))),
                        ("expires", PyValue::Float(e.expires)),
                        ("value", e.value.map(py_number).unwrap_or(PyValue::None)),
                    ];
                    fields.extend(e.used.map(|used| ("used", py_number(used))));
                    fields.push((
                        "lr_cost",
                        e.lr_cost.map(PyValue::Float).unwrap_or(PyValue::None),
                    ));
                    fields.push(("interface", PyValue::String(e.interface.clone())));
                    fields.extend(
                        e.interface_hash
                            .clone()
                            .map(|hash| ("interface_hash", PyValue::Bytes(hash))),
                    );
                    fields.extend(
                        e.state
                            .map(|state| ("state", PyValue::Int(i128::from(state)))),
                    );
                    py_dict(fields)
                })
                .collect(),
        ),
        RpcResponse::InterfaceStats(entries) => {
            interface_stats_value(&wire_entries(entries), None, None, None)
        }
        RpcResponse::RateTable(entries) => PyValue::List(
            entries
                .iter()
                .map(|e| {
                    py_dict(vec![
                        ("hash", PyValue::Bytes(e.hash.clone())),
                        ("rate", PyValue::Float(e.rate)),
                        ("last", PyValue::Float(e.last)),
                        (
                            "rate_violations",
                            PyValue::Int(i128::from(e.rate_violations)),
                        ),
                        ("blocked_until", PyValue::Float(e.blocked_until)),
                        (
                            "timestamps",
                            PyValue::List(
                                e.timestamps.iter().copied().map(PyValue::Float).collect(),
                            ),
                        ),
                    ])
                })
                .collect(),
        ),
        RpcResponse::StringResult(v) => v.clone().map(PyValue::String).unwrap_or(PyValue::None),
        RpcResponse::HashResult(v) => v.clone().map(PyValue::Bytes).unwrap_or(PyValue::None),
        RpcResponse::FloatResult(v) => v.map(PyValue::Float).unwrap_or(PyValue::None),
        RpcResponse::IntResult(v) => PyValue::Int(i128::from(*v)),
        RpcResponse::BoolResult(v) => PyValue::Bool(*v),
        RpcResponse::OptBoolResult(v) => v.map(PyValue::Bool).unwrap_or(PyValue::None),
        RpcResponse::BlackholeList(entries) => PyValue::Dict(
            entries
                .iter()
                .map(|e| {
                    (
                        PyDictKey::Bytes(e.identity_hash.clone()),
                        py_dict(vec![
                            (
                                "source",
                                e.source
                                    .clone()
                                    .map(PyValue::Bytes)
                                    .unwrap_or_else(|| PyValue::Bytes(e.identity_hash.clone())),
                            ),
                            (
                                "until",
                                e.until.map(PyValue::Float).unwrap_or(PyValue::None),
                            ),
                            (
                                "reason",
                                e.reason
                                    .clone()
                                    .map(PyValue::String)
                                    .unwrap_or(PyValue::None),
                            ),
                        ]),
                    )
                })
                .collect(),
        ),
        RpcResponse::LinkDistribution(entries) => PyValue::Dict(
            entries
                .iter()
                .map(|e| {
                    let int = |value: u64| PyValue::Int(i128::from(value));
                    (
                        PyDictKey::Bytes(e.destination_hash.clone()),
                        py_dict(vec![
                            ("active", int(e.active)),
                            ("pending", int(e.pending)),
                            ("traffic", int(e.traffic)),
                            (
                                "from_ifs",
                                PyValue::List(
                                    e.from_interfaces
                                        .iter()
                                        .map(|hash| PyValue::Bytes(hash.clone()))
                                        .collect(),
                                ),
                            ),
                        ]),
                    )
                })
                .collect(),
        ),
        RpcResponse::KnownDestinations(entries) => PyValue::Dict(
            entries
                .iter()
                .map(|e| {
                    let bytes = |value: &Option<Vec<u8>>| {
                        value.clone().map(PyValue::Bytes).unwrap_or(PyValue::None)
                    };
                    // Upstream keeps the never-used and retained markers as ints.
                    let used = if e.used == -1.0 {
                        PyValue::Int(-1)
                    } else {
                        py_number(e.used)
                    };
                    (
                        PyDictKey::Bytes(e.destination_hash.clone()),
                        PyValue::List(vec![
                            PyValue::Float(e.last_heard),
                            bytes(&e.packet_hash),
                            PyValue::Bytes(e.public_key.clone()),
                            bytes(&e.app_data),
                            used,
                            bytes(&e.stamp),
                            py_number(e.stamp_value),
                            e.lr_cost.map(PyValue::Float).unwrap_or(PyValue::None),
                        ]),
                    )
                })
                .collect(),
        ),
        RpcResponse::Ok => PyValue::Bool(true),
        RpcResponse::Error(e) => py_dict(vec![("error", PyValue::String(e.clone()))]),
    }
}

pub(crate) fn encode_interface_stats(
    entries: &[InterfaceStatRpcEntry],
    transport: Option<&TransportStats>,
    traffic: Option<&TrafficTotals>,
    queues: Option<&InboundQueueSnapshot>,
) -> Result<Vec<u8>, RpcError> {
    encode_umsgpack(&interface_stats_value(
        &wire_entries(entries),
        transport,
        traffic,
        queues,
    ))
}

/// Remote management's `/status` answer: `[stats]`, then the link count and
/// nil profiling results when asked for, in that order (Transport.py).
pub(crate) fn encode_remote_status(
    entries: &[InterfaceStatRpcEntry],
    transport: Option<&TransportStats>,
    traffic: Option<&TrafficTotals>,
    queues: Option<&InboundQueueSnapshot>,
    link_count: Option<u64>,
    profiling: bool,
) -> Result<Vec<u8>, RpcError> {
    let mut response = vec![interface_stats_value(
        &wire_entries(entries),
        transport,
        traffic,
        queues,
    )];
    if let Some(link_count) = link_count {
        response.push(PyValue::Int(i128::from(link_count)));
    }
    if profiling {
        response.push(PyValue::None);
    }
    encode_umsgpack(&PyValue::List(response))
}

/// The inbound queue keys of `get_interface_stats()` (Reticulum.py).
fn queue_stats(q: &InboundQueueSnapshot) -> Vec<(&'static str, PyValue)> {
    let int = |n: u64| PyValue::Int(i128::from(n));
    let height = |n: usize| int(n as u64);
    // Python divides only a nonzero height, so an idle queue reports int 0.
    let pressure = |height: usize, length: usize| {
        if height == 0 || length == 0 {
            PyValue::Int(0)
        } else {
            PyValue::Float(height as f64 / length as f64)
        }
    };
    let total = q.heights.iter().sum::<usize>();
    let total_length = q.lengths.iter().fold(0usize, |a, n| a.saturating_add(*n));
    let dropped = q.dropped.iter().fold(0u64, |a, n| a.saturating_add(*n));
    vec![
        ("rxqt", height(total)),
        ("rxqd", height(q.heights[0])),
        ("rxqa", height(q.heights[1])),
        ("rxqp", height(q.heights[2])),
        ("rxqil", height(q.heights[3])),
        ("rxqtd", int(dropped)),
        ("rxqdd", int(q.dropped[0])),
        ("rxqad", int(q.dropped[1])),
        ("rxqpd", int(q.dropped[2])),
        ("rxqild", int(q.dropped[3])),
        ("tqpressure", pressure(total, total_length)),
        ("dqpressure", pressure(q.heights[0], q.lengths[0])),
        ("aqpressure", pressure(q.heights[1], q.lengths[1])),
        ("pqpressure", pressure(q.heights[2], q.lengths[2])),
        ("ilqpressure", pressure(q.heights[3], q.lengths[3])),
    ]
}

/// `Reticulum.get_interface_stats()` (Reticulum.py) for the
/// control port and remote management alike.
fn interface_stats_value(
    entries: &[InterfaceStatWire],
    transport: Option<&TransportStats>,
    traffic: Option<&TrafficTotals>,
    queues: Option<&InboundQueueSnapshot>,
) -> PyValue {
    let mut stats = vec![(
        "interfaces",
        PyValue::List(entries.iter().map(interface_stat_value).collect()),
    )];
    match traffic {
        Some(t) => {
            let int = |value: u64| PyValue::Int(i128::from(value));
            // Python's speeds become floats once an interface is measured, and
            // its frequency sums once a frequency is (Transport.py).
            let speed = |value: f64| {
                if t.measured {
                    PyValue::Float(value)
                } else {
                    PyValue::Int(0)
                }
            };
            let frequency = |value: f64| {
                if value != 0.0 {
                    PyValue::Float(value)
                } else {
                    PyValue::Int(0)
                }
            };
            stats.extend([
                ("rxb", int(t.rxb)),
                ("txb", int(t.txb)),
                ("rxs", speed(t.rxs)),
                ("txs", speed(t.txs)),
                ("lrxb", int(t.lrxb)),
                ("ltxb", int(t.ltxb)),
                ("lrxs", speed(t.lrxs)),
                ("ltxs", speed(t.ltxs)),
                ("frxb", int(t.frxb)),
                ("ftxb", int(t.ftxb)),
                ("frxs", speed(t.frxs)),
                ("ftxs", speed(t.ftxs)),
                ("arxb", int(t.arxb)),
                ("atxb", int(t.atxb)),
                ("arxs", speed(t.arxs)),
                ("atxs", speed(t.atxs)),
                ("arxf", frequency(t.arxf)),
                ("atxf", frequency(t.atxf)),
                ("prxb", int(t.prxb)),
                ("ptxb", int(t.ptxb)),
                ("prxs", speed(t.prxs)),
                ("ptxs", speed(t.ptxs)),
                ("prxf", frequency(t.prxf)),
                ("ptxf", frequency(t.ptxf)),
                ("rxpps", int(t.rxpps)),
                ("txpps", int(t.txpps)),
                ("rxpkts", int(t.rx_packets)),
                ("txpkts", int(t.tx_packets)),
                ("arxpkts", int(t.announce_rx_packets)),
                ("atxpkts", int(t.announce_tx_packets)),
                ("prxpkts", int(t.pr_rx_packets)),
                ("ptxpkts", int(t.pr_tx_packets)),
            ]);
        }
        None => {
            let sum = |select: fn(&InterfaceStatWire) -> u64| {
                entries.iter().map(select).fold(0u64, u64::saturating_add)
            };
            stats.extend([
                ("rxb", PyValue::Int(i128::from(sum(|e| e.rx_bytes)))),
                ("txb", PyValue::Int(i128::from(sum(|e| e.tx_bytes)))),
                ("rxs", PyValue::Int(i128::from(sum(|e| e.rx_rate)))),
                ("txs", PyValue::Int(i128::from(sum(|e| e.tx_rate)))),
            ]);
            for key in [
                "lrxb", "ltxb", "lrxs", "ltxs", "frxb", "ftxb", "frxs", "ftxs", "arxb", "atxb",
                "arxs", "atxs", "arxf", "atxf", "prxb", "ptxb", "prxs", "ptxs", "prxf", "ptxf",
                "rxpps", "txpps", "rxpkts", "txpkts", "arxpkts", "atxpkts", "prxpkts", "ptxpkts",
            ] {
                stats.push((key, PyValue::Int(0)));
            }
        }
    }
    stats.extend(queue_stats(&queues.copied().unwrap_or_default()));
    stats.push(("txq", PyValue::None));
    let t = traffic.copied().unwrap_or_default();
    let int = |value: u64| PyValue::Int(i128::from(value));
    stats.extend([
        ("tlinks", int(t.link_count)),
        ("alinks", int(t.active_link_count)),
        (
            "plinks",
            int(t.link_count.saturating_sub(t.active_link_count)),
        ),
        ("tpcount", int(t.path_count)),
        ("unupcount", int(t.unused_path_count)),
        (
            "actpcount",
            int(t.path_count.saturating_sub(t.unused_path_count)),
        ),
    ]);
    if let Some(transport) = transport {
        let hash = |hash: Option<[u8; 16]>| {
            hash.map(|hash| PyValue::Bytes(hash.to_vec()))
                .unwrap_or(PyValue::None)
        };
        stats.push((
            "transport_id",
            PyValue::Bytes(transport.transport_id.to_vec()),
        ));
        stats.push(("network_id", hash(transport.network_id)));
        stats.push(("transport_uptime", PyValue::Float(transport.uptime)));
        stats.push(("probe_responder", hash(transport.probe_responder)));
    }
    stats.push(("rss", PyValue::None));
    py_dict(stats)
}

fn interface_stat_value(e: &InterfaceStatWire) -> PyValue {
    let int = |value: u64| PyValue::Int(i128::from(value));
    let optional = |value: Option<PyValue>| value.unwrap_or(PyValue::None);
    // Python's `current_*_speed` are unset (reported as 0) until the first
    // traffic count, and floats after it (Reticulum.py).
    let speed = |index: usize, fallback: u64| match e.speeds {
        Some(speeds) => PyValue::Float(speeds[index]),
        None => int(fallback),
    };
    let filtered_speed = |index: usize| match e.filtered_speeds {
        Some(speeds) => PyValue::Float(speeds[index]),
        None => int(0),
    };
    let mut fields = vec![
        ("id", int(e.id)),
        ("name", PyValue::String(e.name.clone())),
        (
            "short_name",
            PyValue::String(e.short_name.clone().unwrap_or_else(|| e.name.clone())),
        ),
        (
            "hash",
            PyValue::Bytes(rns_crypto::sha::sha256(e.name.as_bytes()).to_vec()),
        ),
        (
            "type",
            PyValue::String(e.class_name.clone().unwrap_or_else(|| e.role.clone())),
        ),
        ("rxb", int(e.rx_bytes)),
        ("txb", int(e.tx_bytes)),
        ("frxb", int(e.filtered_rx_bytes)),
        ("ftxb", int(e.filtered_tx_bytes)),
        ("rxs", speed(0, e.rx_rate)),
        ("txs", speed(1, e.tx_rate)),
        ("frxs", filtered_speed(0)),
        ("ftxs", filtered_speed(1)),
        ("arxb", int(e.announce_rx_bytes)),
        ("atxb", int(e.announce_tx_bytes)),
        ("arxs", speed(2, 0)),
        ("atxs", speed(3, 0)),
        ("prxb", int(e.path_request_rx_bytes)),
        ("ptxb", int(e.path_request_tx_bytes)),
        ("prxs", speed(4, 0)),
        ("ptxs", speed(5, 0)),
        ("rssi", optional(e.rssi.map(PyValue::Float))),
        ("snr", optional(e.snr.map(PyValue::Float))),
        (
            "signal_quality",
            optional(e.signal_quality.map(PyValue::Float)),
        ),
        ("arxc", int(e.announces_received)),
        ("atxc", int(e.announces_sent)),
        ("afrxc", int(e.announces_filtered)),
        ("prxc", int(e.path_requests_received)),
        ("ptxc", int(e.path_requests_sent)),
        ("status", PyValue::Bool(e.online)),
        (
            "mode",
            PyValue::Int(i128::from(python_interface_mode(&e.mode))),
        ),
        ("bitrate", int(e.bitrate)),
        ("mtu", PyValue::Int(i128::from(e.mtu))),
        (
            "ifac_signature",
            optional(e.ifac_signature.clone().map(PyValue::Bytes)),
        ),
        (
            "ifac_size",
            optional(e.ifac_size.map(|v| PyValue::Int(i128::from(v as u64)))),
        ),
        (
            "ifac_netname",
            optional(e.ifac_netname.clone().map(PyValue::String)),
        ),
        (
            "autoconnect_source",
            optional(e.autoconnect_source.clone().map(PyValue::String)),
        ),
        ("announce_queue", optional(e.announce_queue.map(int))),
        ("held_announces", int(e.held_announces)),
        (
            "incoming_announce_frequency",
            PyValue::Float(e.incoming_announce_frequency),
        ),
        (
            "outgoing_announce_frequency",
            PyValue::Float(e.outgoing_announce_frequency),
        ),
        (
            "incoming_pr_frequency",
            PyValue::Float(e.incoming_pr_frequency),
        ),
        (
            "outgoing_pr_frequency",
            PyValue::Float(e.outgoing_pr_frequency),
        ),
        (
            "announce_rate_target",
            optional(e.announce_rate_target.map(PyValue::Float)),
        ),
        (
            "announce_rate_penalty",
            optional(e.announce_rate_penalty.map(PyValue::Float)),
        ),
        (
            "announce_rate_grace",
            optional(e.announce_rate_grace.map(|v| PyValue::Int(i128::from(v)))),
        ),
        ("burst_active", PyValue::Bool(e.burst_active)),
        ("burst_activated", PyValue::Float(e.burst_activated)),
        ("burst_count", optional(e.burst_count.map(int))),
        ("pr_burst_active", PyValue::Bool(e.pr_burst_active)),
        ("pr_burst_activated", PyValue::Float(e.pr_burst_activated)),
        ("pr_burst_count", optional(e.pr_burst_count.map(int))),
        ("clients", optional(e.clients.map(int))),
        ("txdrp", int(e.tx_drops)),
        ("txdrb", int(e.tx_dropped_bytes)),
        ("txstalled", PyValue::Bool(e.tx_stalled)),
        ("txbuffered", int(e.tx_buffered)),
        ("tx_drops", int(e.tx_drops)),
        ("gravity", PyValue::Int(i128::from(e.gravity))),
        (
            "announces_to_internal",
            optional(e.announces_to_internal.map(PyValue::Bool)),
        ),
        ("protocol_violations", int(e.protocol_violations)),
        ("ifac_violations", int(e.ifac_violations)),
        ("packet_filter_hits", int(e.packet_filter_hits)),
        (
            "tunnel_id",
            optional(e.tunnel_id.clone().map(PyValue::Bytes)),
        ),
        (
            "remote_transport_id",
            optional(e.remote_transport_id.clone().map(PyValue::Bytes)),
        ),
        (
            "rem_impl",
            optional(e.remote_implementation.clone().map(PyValue::String)),
        ),
        (
            "rem_vers",
            optional(e.remote_version.as_ref().map(|version| {
                PyValue::List(
                    version
                        .iter()
                        .map(|v| PyValue::Int(i128::from(*v)))
                        .collect(),
                )
            })),
        ),
        (
            "rem_is_tn",
            optional(e.remote_is_transport.map(PyValue::Bool)),
        ),
        (
            "rem_dst_cost",
            optional(e.remote_destination_cost.map(PyValue::Float)),
        ),
        (
            "rem_pr_cost",
            optional(e.remote_pr_cost.map(PyValue::Float)),
        ),
    ];
    if let Some(parent) = &e.parent_interface_name {
        fields.push(("parent_interface_name", PyValue::String(parent.clone())));
        fields.push((
            "parent_interface_hash",
            PyValue::Bytes(rns_crypto::sha::sha256(parent.as_bytes()).to_vec()),
        ));
    }
    if let Some(blocked_ips) = e.blocked_ips {
        fields.push(("blocked_ips", int(blocked_ips)));
    }
    if let Some(peers) = e.peers {
        fields.push(("peers", int(peers)));
    }
    if let Some(connectable) = e.i2p_connectable {
        fields.push(("i2p_connectable", PyValue::Bool(connectable)));
        fields.push(("i2p_b32", optional(e.i2p_b32.clone().map(PyValue::String))));
    }
    if let Some(state) = &e.tunnel_state {
        fields.push(("tunnelstate", PyValue::String(state.clone())));
    }
    py_dict(fields)
}

fn py_value_to_response(value: &PyValue) -> Result<RpcResponse, RpcError> {
    match value {
        PyValue::Dict(entries) if dict_get(entries, "interfaces").is_some() => {
            Ok(RpcResponse::InterfaceStats(parse_interface_stats(value)?))
        }
        PyValue::Dict(entries) if dict_get(entries, "error").is_some() => Ok(RpcResponse::Error(
            dict_get(entries, "error")
                .and_then(py_string)
                .unwrap_or_else(|| "RPC error".to_string()),
        )),
        PyValue::List(values) => infer_list_response(values),
        PyValue::String(s) => Ok(RpcResponse::StringResult(Some(s.clone()))),
        PyValue::Bytes(b) => Ok(RpcResponse::HashResult(Some(b.clone()))),
        PyValue::Float(f) => Ok(RpcResponse::FloatResult(Some(*f))),
        PyValue::Int(i) => Ok(RpcResponse::IntResult(i64_from_i128(*i)?)),
        PyValue::Bool(b) => Ok(RpcResponse::BoolResult(*b)),
        PyValue::None => Ok(RpcResponse::StringResult(None)),
        PyValue::Dict(_) => Err(RpcError::Deserialize(
            "unrecognised Python RPC response dictionary".to_string(),
        )),
    }
}

fn py_value_to_response_for_request(
    value: &PyValue,
    request: &RpcRequest,
) -> Result<RpcResponse, RpcError> {
    if matches!(value, PyValue::Dict(entries) if dict_get(entries, "error").is_some()) {
        return py_value_to_response(value);
    }

    match request {
        RpcRequest::GetPathTable { .. } => Ok(RpcResponse::PathTable(parse_path_table(value)?)),
        RpcRequest::GetInterfaceStats => {
            Ok(RpcResponse::InterfaceStats(parse_interface_stats(value)?))
        }
        RpcRequest::GetRateTable => Ok(RpcResponse::RateTable(parse_rate_table(value)?)),
        RpcRequest::GetNextHopIfName { .. } => {
            Ok(RpcResponse::StringResult(py_optional_string(value)?))
        }
        RpcRequest::GetNextHop { .. } => Ok(RpcResponse::HashResult(py_optional_bytes(value)?)),
        RpcRequest::RequestPath { .. } => Ok(RpcResponse::BoolResult(match value {
            PyValue::Bool(v) => *v,
            PyValue::None => false,
            _ => py_required_int(value)? != 0,
        })),
        RpcRequest::GetFirstHopTimeout { .. }
        | RpcRequest::GetPacketRssi { .. }
        | RpcRequest::GetPacketSnr { .. }
        | RpcRequest::GetPacketQ { .. } => Ok(RpcResponse::FloatResult(py_optional_float(value)?)),
        RpcRequest::GetLinkCount
        | RpcRequest::DropAllVia { .. }
        | RpcRequest::DropPathTable
        | RpcRequest::DropRecentAnnounces => Ok(RpcResponse::IntResult(py_required_int(value)?)),
        RpcRequest::GetBlackholedIdentities => {
            Ok(RpcResponse::BlackholeList(parse_blackhole_list(value)?))
        }
        RpcRequest::DropPath { .. } => Ok(RpcResponse::BoolResult(match value {
            PyValue::Bool(v) => *v,
            PyValue::None => false,
            _ => py_required_int(value)? != 0,
        })),
        RpcRequest::BlackholeIdentity { .. } | RpcRequest::UnblackholeIdentity { .. } => {
            Ok(RpcResponse::OptBoolResult(match value {
                PyValue::Bool(v) => Some(*v),
                PyValue::None => None,
                _ => Some(py_required_int(value)? != 0),
            }))
        }
        RpcRequest::DropAnnounceQueues => Ok(RpcResponse::Ok),
        RpcRequest::GetLowestInterfaceBitrate => match value {
            PyValue::None => Ok(RpcResponse::StringResult(None)),
            _ => Ok(RpcResponse::IntResult(py_required_int(value)?)),
        },
        RpcRequest::GetMediumPathTimeout => Ok(RpcResponse::FloatResult(Some(
            py_optional_float(value)?.unwrap_or(0.0),
        ))),
        RpcRequest::GetActiveLinkCount => Ok(RpcResponse::IntResult(py_required_int(value)?)),
        RpcRequest::GetLinkDistribution => Ok(RpcResponse::LinkDistribution(
            parse_link_distribution(value)?,
        )),
        RpcRequest::GetKnownDestinations => Ok(RpcResponse::KnownDestinations(
            parse_known_destinations(value)?,
        )),
        // `None` means no profiler ran; results themselves are not decoded.
        RpcRequest::GetProfilingResults => Ok(match value {
            PyValue::None => RpcResponse::StringResult(None),
            _ => RpcResponse::Ok,
        }),
        // `None` (no such interface) decodes as `StringResult(None)`.
        RpcRequest::ManageInterface { .. } => match value {
            PyValue::Bool(v) => Ok(RpcResponse::BoolResult(*v)),
            PyValue::None => Ok(RpcResponse::StringResult(None)),
            _ => Err(RpcError::Deserialize(
                "expected True, False or None".to_string(),
            )),
        },
        RpcRequest::IsBlackholed { .. }
        | RpcRequest::UseDestination { .. }
        | RpcRequest::RetainDestination { .. }
        | RpcRequest::RetainIdentity { .. }
        | RpcRequest::UnretainDestination { .. }
        | RpcRequest::WantsDestinationType { .. }
        | RpcRequest::UnwantsDestinationType { .. }
        | RpcRequest::UnwantsAllDestinationTypes { .. } => {
            Ok(RpcResponse::BoolResult(match value {
                PyValue::Bool(v) => *v,
                PyValue::None => false,
                _ => py_required_int(value)? != 0,
            }))
        }
    }
}

fn infer_list_response(values: &[PyValue]) -> Result<RpcResponse, RpcError> {
    let Some(PyValue::Dict(first)) = values.first() else {
        return Ok(RpcResponse::PathTable(Vec::new()));
    };
    if dict_get(first, "identity_hash").is_some() {
        Ok(RpcResponse::BlackholeList(parse_blackhole_list(
            &PyValue::List(values.to_vec()),
        )?))
    } else if dict_get(first, "rate_violations").is_some() {
        Ok(RpcResponse::RateTable(parse_rate_table(&PyValue::List(
            values.to_vec(),
        ))?))
    } else {
        Ok(RpcResponse::PathTable(parse_path_table(&PyValue::List(
            values.to_vec(),
        ))?))
    }
}

fn parse_path_table(value: &PyValue) -> Result<Vec<PathTableEntry>, RpcError> {
    let PyValue::List(entries) = value else {
        return Err(RpcError::Deserialize(
            "expected path table list".to_string(),
        ));
    };
    entries
        .iter()
        .map(|entry| {
            let m = as_dict(entry)?;
            Ok(PathTableEntry {
                hash: dict_bytes(m, "hash")?,
                timestamp: dict_get(m, "timestamp").and_then(py_f64).unwrap_or(0.0),
                via: match dict_get(m, "via") {
                    Some(PyValue::Bytes(v)) => Some(v.clone()),
                    _ => None,
                },
                hops: dict_get(m, "hops").and_then(py_u8).unwrap_or(0),
                expires: dict_get(m, "expires").and_then(py_f64).unwrap_or(0.0),
                value: dict_get(m, "value").and_then(py_f64),
                used: dict_get(m, "used").and_then(py_f64),
                lr_cost: dict_get(m, "lr_cost").and_then(py_f64),
                interface: dict_get(m, "interface")
                    .and_then(py_string)
                    .unwrap_or_default(),
                interface_hash: match dict_get(m, "interface_hash") {
                    Some(PyValue::Bytes(v)) => Some(v.clone()),
                    _ => None,
                },
                state: dict_get(m, "state").and_then(py_u8),
            })
        })
        .collect()
}

fn parse_interface_stats(value: &PyValue) -> Result<Vec<InterfaceStatRpcEntry>, RpcError> {
    let list = match value {
        PyValue::Dict(entries) => match dict_get(entries, "interfaces") {
            Some(PyValue::List(v)) => v,
            _ => return Ok(Vec::new()),
        },
        PyValue::List(v) => v,
        _ => {
            return Err(RpcError::Deserialize(
                "expected interface stats dictionary".to_string(),
            ));
        }
    };
    list.iter()
        .enumerate()
        .map(|(idx, entry)| {
            let m = as_dict(entry)?;
            Ok(InterfaceStatRpcEntry::from(InterfaceStatWire {
                id: dict_get(m, "id")
                    .and_then(py_u64)
                    .unwrap_or((idx as u64) + 1),
                name: dict_get(m, "name").and_then(py_string).unwrap_or_default(),
                rx_bytes: dict_get(m, "rxb")
                    .or_else(|| dict_get(m, "rx_bytes"))
                    .and_then(py_u64)
                    .unwrap_or(0),
                tx_bytes: dict_get(m, "txb")
                    .or_else(|| dict_get(m, "tx_bytes"))
                    .and_then(py_u64)
                    .unwrap_or(0),
                rx_rate: dict_get(m, "rxs").and_then(py_u64).unwrap_or(0),
                tx_rate: dict_get(m, "txs").and_then(py_u64).unwrap_or(0),
                online: dict_get(m, "status")
                    .or_else(|| dict_get(m, "online"))
                    .and_then(py_bool)
                    .unwrap_or(false),
                bitrate: dict_get(m, "bitrate").and_then(py_u64).unwrap_or(0),
                mtu: dict_get(m, "mtu").and_then(py_u32).unwrap_or(0),
                mode: dict_get(m, "mode")
                    .map(mode_from_py_value)
                    .unwrap_or_else(|| "Full".to_string()),
                role: dict_get(m, "role")
                    .or_else(|| dict_get(m, "type"))
                    .and_then(py_string)
                    .unwrap_or_else(|| "normal".to_string()),
                announce_queue: match dict_get(m, "announce_queue") {
                    Some(PyValue::None) | None => None,
                    Some(value) => py_u64(value),
                },
                held_announces: dict_get(m, "held_announces").and_then(py_u64).unwrap_or(0),
                incoming_announce_frequency: dict_get(m, "incoming_announce_frequency")
                    .and_then(py_f64)
                    .unwrap_or(0.0),
                outgoing_announce_frequency: dict_get(m, "outgoing_announce_frequency")
                    .and_then(py_f64)
                    .unwrap_or(0.0),
                incoming_pr_frequency: dict_get(m, "incoming_pr_frequency")
                    .and_then(py_f64)
                    .unwrap_or(0.0),
                outgoing_pr_frequency: dict_get(m, "outgoing_pr_frequency")
                    .and_then(py_f64)
                    .unwrap_or(0.0),
                burst_active: dict_get(m, "burst_active")
                    .and_then(py_bool)
                    .unwrap_or(false),
                burst_activated: dict_get(m, "burst_activated")
                    .and_then(py_f64)
                    .unwrap_or(0.0),
                pr_burst_active: dict_get(m, "pr_burst_active")
                    .and_then(py_bool)
                    .unwrap_or(false),
                pr_burst_activated: dict_get(m, "pr_burst_activated")
                    .and_then(py_f64)
                    .unwrap_or(0.0),
                clients: match dict_get(m, "clients") {
                    Some(PyValue::None) | None => None,
                    Some(value) => py_u64(value),
                },
                blocked_ips: match dict_get(m, "blocked_ips") {
                    Some(PyValue::None) | None => None,
                    Some(value) => py_u64(value),
                },
                announce_rate_target: dict_get(m, "announce_rate_target").and_then(py_f64),
                announce_rate_grace: dict_get(m, "announce_rate_grace").and_then(py_u32),
                announce_rate_penalty: dict_get(m, "announce_rate_penalty").and_then(py_f64),
                announce_cap: dict_get(m, "announce_cap").and_then(py_f64).unwrap_or(0.0),
                ifac_signature: match dict_get(m, "ifac_signature") {
                    Some(PyValue::Bytes(v)) => Some(v.clone()),
                    _ => None,
                },
                ifac_size: dict_get(m, "ifac_size")
                    .and_then(py_u64)
                    .map(|v| v as usize),
                ifac_netname: dict_get(m, "ifac_netname").and_then(py_string),
                tx_drops: dict_get(m, "txdrp")
                    .or_else(|| dict_get(m, "tx_drops"))
                    .and_then(py_u64)
                    .unwrap_or(0),
                tx_dropped_bytes: dict_get(m, "txdrb").and_then(py_u64).unwrap_or(0),
                announces_received: dict_get(m, "arxc").and_then(py_u64).unwrap_or(0),
                announces_sent: dict_get(m, "atxc").and_then(py_u64).unwrap_or(0),
                path_requests_received: dict_get(m, "prxc").and_then(py_u64).unwrap_or(0),
                path_requests_sent: dict_get(m, "ptxc").and_then(py_u64).unwrap_or(0),
                protocol_violations: dict_get(m, "protocol_violations")
                    .and_then(py_u64)
                    .unwrap_or(0),
                ifac_violations: dict_get(m, "ifac_violations").and_then(py_u64).unwrap_or(0),
                packet_filter_hits: dict_get(m, "packet_filter_hits")
                    .and_then(py_u64)
                    .unwrap_or(0),
                gravity: match dict_get(m, "gravity") {
                    Some(PyValue::Int(v)) => i64::try_from(*v).unwrap_or(0),
                    _ => 0,
                },
                announces_to_internal: match dict_get(m, "announces_to_internal") {
                    Some(PyValue::Bool(v)) => Some(*v),
                    _ => None,
                },
                parent_interface_name: dict_get(m, "parent_interface_name").and_then(py_string),
                autoconnect_source: dict_get(m, "autoconnect_source").and_then(py_string),
                short_name: dict_get(m, "short_name").and_then(py_string),
                class_name: dict_get(m, "type").and_then(py_string),
                speeds: {
                    let speeds: Vec<f64> = ["rxs", "txs", "arxs", "atxs", "prxs", "ptxs"]
                        .iter()
                        .map(|key| dict_get(m, key).and_then(py_f64).unwrap_or(0.0))
                        .collect();
                    matches!(dict_get(m, "rxs"), Some(PyValue::Float(_))).then(|| {
                        [
                            speeds[0], speeds[1], speeds[2], speeds[3], speeds[4], speeds[5],
                        ]
                    })
                },
                announce_rx_bytes: dict_get(m, "arxb").and_then(py_u64).unwrap_or(0),
                announce_tx_bytes: dict_get(m, "atxb").and_then(py_u64).unwrap_or(0),
                path_request_rx_bytes: dict_get(m, "prxb").and_then(py_u64).unwrap_or(0),
                path_request_tx_bytes: dict_get(m, "ptxb").and_then(py_u64).unwrap_or(0),
                burst_count: dict_get(m, "burst_count").and_then(py_u64),
                pr_burst_count: dict_get(m, "pr_burst_count").and_then(py_u64),
                rssi: dict_get(m, "rssi").and_then(py_f64),
                snr: dict_get(m, "snr").and_then(py_f64),
                signal_quality: dict_get(m, "signal_quality").and_then(py_f64),
                peers: dict_get(m, "peers").and_then(py_u64),
                i2p_connectable: dict_get(m, "i2p_connectable").and_then(py_bool),
                i2p_b32: dict_get(m, "i2p_b32").and_then(py_string),
                tunnel_state: dict_get(m, "tunnelstate").and_then(py_string),
                tx_stalled: dict_get(m, "txstalled").and_then(py_bool).unwrap_or(false),
                tx_buffered: dict_get(m, "txbuffered").and_then(py_u64).unwrap_or(0),
                filtered_rx_bytes: dict_get(m, "frxb").and_then(py_u64).unwrap_or(0),
                filtered_tx_bytes: dict_get(m, "ftxb").and_then(py_u64).unwrap_or(0),
                announces_filtered: dict_get(m, "afrxc").and_then(py_u64).unwrap_or(0),
                filtered_speeds: match (dict_get(m, "frxs"), dict_get(m, "ftxs")) {
                    (Some(PyValue::Float(rx)), Some(tx)) => Some([*rx, py_f64(tx).unwrap_or(0.0)]),
                    _ => None,
                },
                tunnel_id: match dict_get(m, "tunnel_id") {
                    Some(PyValue::Bytes(id)) => Some(id.clone()),
                    _ => None,
                },
                remote_transport_id: match dict_get(m, "remote_transport_id") {
                    Some(PyValue::Bytes(id)) => Some(id.clone()),
                    _ => None,
                },
                remote_implementation: dict_get(m, "rem_impl").and_then(py_string),
                remote_version: match dict_get(m, "rem_vers") {
                    Some(PyValue::List(parts)) => parts.iter().map(py_u64).collect(),
                    _ => None,
                },
                remote_is_transport: dict_get(m, "rem_is_tn").and_then(py_bool),
                remote_destination_cost: dict_get(m, "rem_dst_cost").and_then(py_f64),
                remote_pr_cost: dict_get(m, "rem_pr_cost").and_then(py_f64),
            }))
        })
        .collect()
}

fn parse_rate_table(value: &PyValue) -> Result<Vec<RateTableEntry>, RpcError> {
    let PyValue::List(entries) = value else {
        return Err(RpcError::Deserialize(
            "expected rate table list".to_string(),
        ));
    };
    entries
        .iter()
        .map(|entry| {
            let m = as_dict(entry)?;
            let timestamps = match dict_get(m, "timestamps") {
                Some(PyValue::List(v)) => v.iter().filter_map(py_f64).collect(),
                _ => Vec::new(),
            };
            Ok(RateTableEntry {
                hash: dict_bytes(m, "hash")?,
                rate: dict_get(m, "rate").and_then(py_f64).unwrap_or(0.0),
                last: dict_get(m, "last").and_then(py_f64).unwrap_or(0.0),
                rate_violations: dict_get(m, "rate_violations").and_then(py_u32).unwrap_or(0),
                blocked_until: dict_get(m, "blocked_until").and_then(py_f64).unwrap_or(0.0),
                timestamps,
            })
        })
        .collect()
}

fn parse_blackhole_list(value: &PyValue) -> Result<Vec<BlackholeEntry>, RpcError> {
    match value {
        PyValue::List(entries) => entries
            .iter()
            .map(|entry| {
                let m = as_dict(entry)?;
                Ok(BlackholeEntry {
                    identity_hash: dict_bytes(m, "identity_hash")?,
                    source: match dict_get(m, "source") {
                        Some(PyValue::Bytes(v)) => Some(v.clone()),
                        _ => None,
                    },
                    until: dict_get(m, "until").and_then(py_f64),
                    reason: dict_get(m, "reason").and_then(py_string),
                })
            })
            .collect(),
        PyValue::Dict(entries) => entries
            .iter()
            .map(|(key, entry)| {
                let identity_hash = match key {
                    PyDictKey::Bytes(bytes) => bytes.clone(),
                    PyDictKey::String(hex) => hex::decode(hex).map_err(|e| {
                        RpcError::Deserialize(format!("invalid blackhole identity hash key: {e}"))
                    })?,
                };
                let m = as_dict(entry)?;
                Ok(BlackholeEntry {
                    identity_hash,
                    source: match dict_get(m, "source") {
                        Some(PyValue::Bytes(v)) => Some(v.clone()),
                        _ => None,
                    },
                    until: dict_get(m, "until").and_then(py_f64),
                    reason: dict_get(m, "reason").and_then(py_string),
                })
            })
            .collect(),
        _ => Err(RpcError::Deserialize(
            "expected blackhole list or dictionary".to_string(),
        )),
    }
}

/// `{destination: {"active", "pending", "traffic", "from_ifs"}}`; nil, a
/// Python client's failed call, reads as empty.
fn parse_link_distribution(value: &PyValue) -> Result<Vec<LinkDistributionEntry>, RpcError> {
    let entries = match value {
        PyValue::None => return Ok(Vec::new()),
        PyValue::Dict(entries) => entries,
        _ => {
            return Err(RpcError::Deserialize(
                "expected link distribution dictionary".to_string(),
            ));
        }
    };
    entries
        .iter()
        .map(|(key, entry)| {
            let PyDictKey::Bytes(hash) = key else {
                return Err(RpcError::Deserialize(
                    "expected destination hash key".to_string(),
                ));
            };
            let m = as_dict(entry)?;
            let count = |key: &str| dict_get(m, key).and_then(py_u64).unwrap_or(0);
            Ok(LinkDistributionEntry {
                destination_hash: hash.clone(),
                active: count("active"),
                pending: count("pending"),
                traffic: count("traffic"),
                from_interfaces: match dict_get(m, "from_ifs") {
                    Some(PyValue::List(hashes)) => hashes
                        .iter()
                        .filter_map(|hash| match hash {
                            PyValue::Bytes(hash) => Some(hash.clone()),
                            _ => None,
                        })
                        .collect(),
                    _ => Vec::new(),
                },
            })
        })
        .collect()
}

/// `{destination: [last_heard, packet_hash, public_key, app_data, used, stamp,
/// stamp_value, lr_cost]}` (Identity.py); an entry without a key is skipped.
fn parse_known_destinations(value: &PyValue) -> Result<Vec<KnownDestinationEntry>, RpcError> {
    let entries = match value {
        PyValue::None => return Ok(Vec::new()),
        PyValue::Dict(entries) => entries,
        _ => {
            return Err(RpcError::Deserialize(
                "expected known destinations dictionary".to_string(),
            ));
        }
    };
    Ok(entries
        .iter()
        .filter_map(|(key, entry)| {
            let (PyDictKey::Bytes(hash), PyValue::List(fields)) = (key, entry) else {
                return None;
            };
            let field = |index: usize| fields.get(index).unwrap_or(&PyValue::None);
            let bytes = |index: usize| match field(index) {
                PyValue::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            };
            Some(KnownDestinationEntry {
                destination_hash: hash.clone(),
                last_heard: py_f64(field(0)).unwrap_or(0.0),
                packet_hash: bytes(1),
                public_key: bytes(2)?,
                app_data: bytes(3),
                used: py_f64(field(4)).unwrap_or(0.0),
                stamp: bytes(5),
                stamp_value: py_f64(field(6)).unwrap_or(0.0),
                lr_cost: py_f64(field(7)),
            })
        })
        .collect())
}

fn as_dict(value: &PyValue) -> Result<&[(PyDictKey, PyValue)], RpcError> {
    match value {
        PyValue::Dict(entries) => Ok(entries),
        _ => Err(RpcError::Deserialize("expected dictionary".to_string())),
    }
}

fn dict_get<'a>(entries: &'a [(PyDictKey, PyValue)], key: &str) -> Option<&'a PyValue> {
    entries
        .iter()
        .find(|(k, _)| matches!(k, PyDictKey::String(s) if s == key))
        .map(|(_, v)| v)
}

fn dict_bytes(entries: &[(PyDictKey, PyValue)], key: &str) -> Result<Vec<u8>, RpcError> {
    match dict_get(entries, key) {
        Some(PyValue::Bytes(v)) => Ok(v.clone()),
        Some(_) => Err(RpcError::Deserialize(format!("{key} is not bytes"))),
        None => Err(RpcError::Deserialize(format!("missing {key}"))),
    }
}

fn py_string(value: &PyValue) -> Option<String> {
    match value {
        PyValue::String(v) => Some(v.clone()),
        _ => None,
    }
}

fn py_bool(value: &PyValue) -> Option<bool> {
    match value {
        PyValue::Bool(v) => Some(*v),
        _ => None,
    }
}

/// Upstream stores the never-used marker and an unstamped value as the int 0.
fn py_number(value: f64) -> PyValue {
    if value == 0.0 {
        PyValue::Int(0)
    } else {
        PyValue::Float(value)
    }
}

fn py_f64(value: &PyValue) -> Option<f64> {
    match value {
        PyValue::Float(v) => Some(*v),
        PyValue::Int(v) => Some(*v as f64),
        _ => None,
    }
}

fn py_u8(value: &PyValue) -> Option<u8> {
    py_u64(value).and_then(|v| u8::try_from(v).ok())
}

fn py_u32(value: &PyValue) -> Option<u32> {
    py_u64(value).and_then(|v| u32::try_from(v).ok())
}

fn py_u64(value: &PyValue) -> Option<u64> {
    match value {
        PyValue::Int(v) => u64::try_from(*v).ok(),
        _ => None,
    }
}

fn py_optional_string(value: &PyValue) -> Result<Option<String>, RpcError> {
    match value {
        PyValue::None => Ok(None),
        PyValue::String(v) => Ok(Some(v.clone())),
        _ => Err(RpcError::Deserialize(
            "expected optional string".to_string(),
        )),
    }
}

fn py_optional_bytes(value: &PyValue) -> Result<Option<Vec<u8>>, RpcError> {
    match value {
        PyValue::None => Ok(None),
        PyValue::Bytes(v) => Ok(Some(v.clone())),
        _ => Err(RpcError::Deserialize("expected optional bytes".to_string())),
    }
}

fn py_optional_float(value: &PyValue) -> Result<Option<f64>, RpcError> {
    match value {
        PyValue::None => Ok(None),
        PyValue::Float(v) => Ok(Some(*v)),
        PyValue::Int(v) => Ok(Some(*v as f64)),
        _ => Err(RpcError::Deserialize("expected optional float".to_string())),
    }
}

fn py_required_int(value: &PyValue) -> Result<i64, RpcError> {
    match value {
        PyValue::Int(v) => i64_from_i128(*v),
        PyValue::Bool(v) => Ok(i64::from(*v)),
        _ => Err(RpcError::Deserialize("expected integer".to_string())),
    }
}

fn i64_from_i128(v: i128) -> Result<i64, RpcError> {
    i64::try_from(v).map_err(|_| RpcError::Deserialize(format!("integer out of range: {v}")))
}

/// Python `Interface.MODE_*` (Interface.py) for a Debug-formatted mode.
fn python_interface_mode(mode: &str) -> u8 {
    match mode {
        "Full" => 0x01,
        "PointToPoint" => 0x02,
        "Access" | "AccessPoint" => 0x03,
        "Roaming" => 0x04,
        "Boundary" => 0x05,
        "Gateway" => 0x06,
        "Internal" => 0x07,
        _ => 0x01,
    }
}

fn mode_from_py_value(value: &PyValue) -> String {
    match value {
        PyValue::Int(1) => "Full",
        PyValue::Int(2) => "PointToPoint",
        PyValue::Int(3) => "AccessPoint",
        PyValue::Int(4) => "Roaming",
        PyValue::Int(5) => "Boundary",
        PyValue::Int(6) => "Gateway",
        PyValue::Int(7) => "Internal",
        PyValue::String(s) => s.as_str(),
        _ => "Full",
    }
    .to_string()
}

/// Nesting cap for inbound payloads; the recursive decoder must not let a
/// hostile local client blow the stack (umsgpack relies on Python's ~1000
/// recursion limit for the same purpose).
const MAX_MSGPACK_DEPTH: usize = 128;

/// Byte-exact with `RNS.vendor.umsgpack.packb` (1.3.8) for the value tree the
/// RPC vocabulary uses: nil/bool/int/float64/str/bin/array/map.
fn encode_umsgpack(value: &PyValue) -> Result<Vec<u8>, RpcError> {
    let mut out = Vec::new();
    encode_msgpack_value(value, &mut out)?;
    Ok(out)
}

fn encode_msgpack_value(value: &PyValue, out: &mut Vec<u8>) -> Result<(), RpcError> {
    match value {
        PyValue::None => out.push(0xc0),
        PyValue::Bool(true) => out.push(0xc3),
        PyValue::Bool(false) => out.push(0xc2),
        PyValue::Int(v) => encode_msgpack_int(*v, out)?,
        // umsgpack packs Python floats as float64 (`_float_precision = "double"`).
        PyValue::Float(v) => {
            out.push(0xcb);
            out.extend_from_slice(&v.to_be_bytes());
        }
        PyValue::Bytes(bytes) => encode_msgpack_bytes(bytes, out)?,
        PyValue::String(s) => encode_msgpack_string(s, out)?,
        PyValue::List(values) => {
            encode_msgpack_seq_header(values.len(), 0x90, 0xdc, "array", out)?;
            for value in values {
                encode_msgpack_value(value, out)?;
            }
        }
        PyValue::Dict(entries) => {
            encode_msgpack_seq_header(entries.len(), 0x80, 0xde, "map", out)?;
            for (key, value) in entries {
                match key {
                    PyDictKey::String(s) => encode_msgpack_string(s, out)?,
                    PyDictKey::Bytes(bytes) => encode_msgpack_bytes(bytes, out)?,
                }
                encode_msgpack_value(value, out)?;
            }
        }
    }
    Ok(())
}

/// Shared fixarray/fixmap + 16/32-bit header layout (`_pack_array`/`_pack_map`).
fn encode_msgpack_seq_header(
    len: usize,
    fix_base: u8,
    len16_code: u8,
    kind: &str,
    out: &mut Vec<u8>,
) -> Result<(), RpcError> {
    if len < 16 {
        out.push(fix_base | len as u8);
    } else if let Ok(v) = u16::try_from(len) {
        out.push(len16_code);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(len) {
        out.push(len16_code + 1);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        return Err(RpcError::Serialize(format!("huge {kind}")));
    }
    Ok(())
}

/// umsgpack `_pack_integer`: values outside i64::MIN..=u64::MAX raise
/// UnsupportedTypeException — mirror the rejection exactly.
fn encode_msgpack_int(value: i128, out: &mut Vec<u8>) -> Result<(), RpcError> {
    if value < 0 {
        if value >= -32 {
            out.push(value as i8 as u8);
        } else if value >= i128::from(i8::MIN) {
            out.push(0xd0);
            out.push(value as i8 as u8);
        } else if value >= i128::from(i16::MIN) {
            out.push(0xd1);
            out.extend_from_slice(&(value as i16).to_be_bytes());
        } else if value >= i128::from(i32::MIN) {
            out.push(0xd2);
            out.extend_from_slice(&(value as i32).to_be_bytes());
        } else if value >= i128::from(i64::MIN) {
            out.push(0xd3);
            out.extend_from_slice(&(value as i64).to_be_bytes());
        } else {
            return Err(RpcError::Serialize("huge signed int".to_string()));
        }
    } else if value < 128 {
        out.push(value as u8);
    } else if value < 1 << 8 {
        out.push(0xcc);
        out.push(value as u8);
    } else if value < 1 << 16 {
        out.push(0xcd);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 1 << 32 {
        out.push(0xce);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else if value <= i128::from(u64::MAX) {
        out.push(0xcf);
        out.extend_from_slice(&(value as u64).to_be_bytes());
    } else {
        return Err(RpcError::Serialize("huge unsigned int".to_string()));
    }
    Ok(())
}

fn encode_msgpack_string(s: &str, out: &mut Vec<u8>) -> Result<(), RpcError> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len < 32 {
        out.push(0xa0 | len as u8);
    } else if let Ok(v) = u8::try_from(len) {
        out.push(0xd9);
        out.push(v);
    } else if let Ok(v) = u16::try_from(len) {
        out.push(0xda);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(len) {
        out.push(0xdb);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        return Err(RpcError::Serialize("huge string".to_string()));
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_msgpack_bytes(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), RpcError> {
    let len = bytes.len();
    if let Ok(v) = u8::try_from(len) {
        out.push(0xc4);
        out.push(v);
    } else if let Ok(v) = u16::try_from(len) {
        out.push(0xc5);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(len) {
        out.push(0xc6);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        return Err(RpcError::Serialize("huge binary string".to_string()));
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// Like `umsgpack.unpackb`: decodes one object, ignores trailing bytes.
fn decode_umsgpack(data: &[u8]) -> Result<PyValue, RpcError> {
    let mut i = 0usize;
    decode_msgpack_value(data, &mut i, 0)
}

fn decode_msgpack_value(data: &[u8], i: &mut usize, depth: usize) -> Result<PyValue, RpcError> {
    if depth > MAX_MSGPACK_DEPTH {
        return Err(RpcError::Deserialize(
            "msgpack nesting too deep".to_string(),
        ));
    }
    let code = read_u8(data, i)?;
    match code {
        0x00..=0x7f => Ok(PyValue::Int(i128::from(code))),
        0xe0..=0xff => Ok(PyValue::Int(i128::from(code as i8))),
        0x80..=0x8f => decode_msgpack_map(data, i, usize::from(code & 0x0f), depth),
        0x90..=0x9f => decode_msgpack_array(data, i, usize::from(code & 0x0f), depth),
        0xa0..=0xbf => decode_msgpack_str(data, i, usize::from(code & 0x1f)),
        0xc0 => Ok(PyValue::None),
        0xc2 => Ok(PyValue::Bool(false)),
        0xc3 => Ok(PyValue::Bool(true)),
        0xc4 => {
            let len = read_u8(data, i)? as usize;
            Ok(PyValue::Bytes(read_exact(data, i, len)?.to_vec()))
        }
        0xc5 => {
            let len = read_u16_be(data, i)? as usize;
            Ok(PyValue::Bytes(read_exact(data, i, len)?.to_vec()))
        }
        0xc6 => {
            let len = read_u32_be(data, i)? as usize;
            Ok(PyValue::Bytes(read_exact(data, i, len)?.to_vec()))
        }
        0xca => {
            let bytes = read_exact(data, i, 4)?;
            let v = f32::from_be_bytes(bytes.try_into().unwrap());
            Ok(PyValue::Float(f64::from(v)))
        }
        0xcb => {
            let bytes = read_exact(data, i, 8)?;
            let v = f64::from_be_bytes(bytes.try_into().unwrap());
            Ok(PyValue::Float(v))
        }
        0xcc => Ok(PyValue::Int(i128::from(read_u8(data, i)?))),
        0xcd => Ok(PyValue::Int(i128::from(read_u16_be(data, i)?))),
        0xce => Ok(PyValue::Int(i128::from(read_u32_be(data, i)?))),
        0xcf => Ok(PyValue::Int(i128::from(read_u64_be(data, i)?))),
        0xd0 => Ok(PyValue::Int(i128::from(read_u8(data, i)? as i8))),
        0xd1 => Ok(PyValue::Int(i128::from(read_u16_be(data, i)? as i16))),
        0xd2 => Ok(PyValue::Int(i128::from(read_u32_be(data, i)? as i32))),
        0xd3 => Ok(PyValue::Int(i128::from(read_u64_be(data, i)? as i64))),
        0xd9 => {
            let len = read_u8(data, i)? as usize;
            decode_msgpack_str(data, i, len)
        }
        0xda => {
            let len = read_u16_be(data, i)? as usize;
            decode_msgpack_str(data, i, len)
        }
        0xdb => {
            let len = read_u32_be(data, i)? as usize;
            decode_msgpack_str(data, i, len)
        }
        0xdc => {
            let len = read_u16_be(data, i)? as usize;
            decode_msgpack_array(data, i, len, depth)
        }
        0xdd => {
            let len = read_u32_be(data, i)? as usize;
            decode_msgpack_array(data, i, len, depth)
        }
        0xde => {
            let len = read_u16_be(data, i)? as usize;
            decode_msgpack_map(data, i, len, depth)
        }
        0xdf => {
            let len = read_u32_be(data, i)? as usize;
            decode_msgpack_map(data, i, len, depth)
        }
        // Ext/timestamp families (0xc1 reserved, 0xc7-0xc9, 0xd4-0xd8) never
        // appear in the RPC vocabulary.
        other => Err(RpcError::Deserialize(format!(
            "unsupported msgpack type code 0x{other:02x}"
        ))),
    }
}

fn decode_msgpack_str(data: &[u8], i: &mut usize, len: usize) -> Result<PyValue, RpcError> {
    let bytes = read_exact(data, i, len)?;
    // umsgpack default: invalid UTF-8 raises InvalidStringException.
    let s = std::str::from_utf8(bytes)
        .map_err(|_| RpcError::Deserialize("unpacked string is invalid utf-8".to_string()))?;
    Ok(PyValue::String(s.to_string()))
}

fn decode_msgpack_array(
    data: &[u8],
    i: &mut usize,
    len: usize,
    depth: usize,
) -> Result<PyValue, RpcError> {
    let mut values = Vec::with_capacity(len.min(1024));
    for _ in 0..len {
        values.push(decode_msgpack_value(data, i, depth + 1)?);
    }
    Ok(PyValue::List(values))
}

fn decode_msgpack_map(
    data: &[u8],
    i: &mut usize,
    len: usize,
    depth: usize,
) -> Result<PyValue, RpcError> {
    let mut entries = Vec::with_capacity(len.min(1024));
    for _ in 0..len {
        let key = py_key(decode_msgpack_value(data, i, depth + 1)?)?;
        let value = decode_msgpack_value(data, i, depth + 1)?;
        entries.push((key, value));
    }
    Ok(PyValue::Dict(entries))
}

fn py_key(value: PyValue) -> Result<PyDictKey, RpcError> {
    match value {
        PyValue::String(s) => Ok(PyDictKey::String(s)),
        PyValue::Bytes(bytes) => Ok(PyDictKey::Bytes(bytes)),
        _ => Err(RpcError::Deserialize(
            "dictionary key is not a string or bytes".to_string(),
        )),
    }
}

fn read_exact<'a>(data: &'a [u8], index: &mut usize, len: usize) -> Result<&'a [u8], RpcError> {
    let end = index
        .checked_add(len)
        .ok_or_else(|| RpcError::Deserialize("msgpack length overflow".to_string()))?;
    if end > data.len() {
        return Err(RpcError::Deserialize("truncated msgpack".to_string()));
    }
    let out = &data[*index..end];
    *index = end;
    Ok(out)
}

fn read_u8(data: &[u8], index: &mut usize) -> Result<u8, RpcError> {
    Ok(read_exact(data, index, 1)?[0])
}

fn read_u16_be(data: &[u8], index: &mut usize) -> Result<u16, RpcError> {
    let bytes = read_exact(data, index, 2)?;
    Ok(u16::from_be_bytes(bytes.try_into().unwrap()))
}

fn read_u32_be(data: &[u8], index: &mut usize) -> Result<u32, RpcError> {
    let bytes = read_exact(data, index, 4)?;
    Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
}

fn read_u64_be(data: &[u8], index: &mut usize) -> Result<u64, RpcError> {
    let bytes = read_exact(data, index, 8)?;
    Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
}

pub fn compute_python_auth_response(key: &[u8], message: &[u8]) -> Vec<u8> {
    compute_python_auth_response_for(detect_python_auth_protocol(message), key, message)
}

pub(crate) fn compute_python_auth_response_for(
    protocol: PythonAuthProtocol,
    key: &[u8],
    message: &[u8],
) -> Vec<u8> {
    if protocol == PythonAuthProtocol::LegacyMd5 {
        return compute_legacy_auth_hmac(key, message).to_vec();
    }

    let mut response = Vec::with_capacity(MP_DIGEST_PREFIX.len() + 32);
    response.extend_from_slice(MP_DIGEST_PREFIX);
    response.extend_from_slice(&compute_auth_hmac(key, message));
    response
}

pub fn verify_python_auth_response(key: &[u8], message: &[u8], response: &[u8]) -> bool {
    let protocol = if response.starts_with(MP_DIGEST_PREFIX) {
        PythonAuthProtocol::Sha256
    } else {
        PythonAuthProtocol::LegacyMd5
    };
    verify_python_auth_response_for(protocol, key, message, response)
}

pub(crate) fn verify_python_auth_response_for(
    protocol: PythonAuthProtocol,
    key: &[u8],
    message: &[u8],
    response: &[u8],
) -> bool {
    use subtle::ConstantTimeEq;
    if protocol == PythonAuthProtocol::LegacyMd5 {
        let expected = compute_legacy_auth_hmac(key, message);
        return expected.as_slice().ct_eq(response).into();
    }

    if !response.starts_with(MP_DIGEST_PREFIX) {
        return false;
    }
    let mac = &response[MP_DIGEST_PREFIX.len()..];
    let expected = compute_auth_hmac(key, message);
    expected.as_slice().ct_eq(mac).into()
}

pub fn new_python_challenge() -> Vec<u8> {
    new_python_challenge_for(PythonAuthProtocol::Sha256)
}

pub(crate) fn new_python_challenge_for(protocol: PythonAuthProtocol) -> Vec<u8> {
    if protocol == PythonAuthProtocol::LegacyMd5 {
        return rns_crypto::random::random_bytes(MP_LEGACY_CHALLENGE_RANDOM_LEN);
    }

    let mut message = Vec::with_capacity(MP_DIGEST_PREFIX.len() + MP_CHALLENGE_RANDOM_LEN);
    message.extend_from_slice(MP_DIGEST_PREFIX);
    message.extend_from_slice(&rns_crypto::random::random_bytes(MP_CHALLENGE_RANDOM_LEN));
    message
}

/// Write a signed 32-bit big-endian length followed by the payload. Rejects
/// lengths above `i32::MAX`; this helper imposes no I/O timeout.
pub async fn write_mp_frame<S>(stream: &mut S, data: &[u8]) -> Result<(), RpcError>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let len = i32::try_from(data.len())
        .map_err(|_| RpcError::Serialize("frame too large".to_string()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(RpcError::Io)?;
    stream.write_all(data).await.map_err(RpcError::Io)
}

/// Read one multiprocessing frame, accepting the 32-bit length or `-1`
/// followed by a 64-bit length. Reject a length above `max_size` before
/// allocating the payload. The caller supplies any I/O timeout.
pub async fn read_mp_frame<S>(stream: &mut S, max_size: usize) -> Result<Vec<u8>, RpcError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(RpcError::Io)?;
    let len = i32::from_be_bytes(len_buf);
    let len = if len == -1 {
        let mut long_buf = [0u8; 8];
        stream
            .read_exact(&mut long_buf)
            .await
            .map_err(RpcError::Io)?;
        usize::try_from(u64::from_be_bytes(long_buf))
            .map_err(|_| RpcError::Deserialize("frame length out of range".to_string()))?
    } else if len >= 0 {
        len as usize
    } else {
        return Err(RpcError::Deserialize(format!(
            "invalid multiprocessing frame length: {len}"
        )));
    };
    if len > max_size {
        return Err(RpcError::Deserialize(format!(
            "frame too large: {len} > {max_size}"
        )));
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await.map_err(RpcError::Io)?;
    Ok(data)
}

/// Connect to `127.0.0.1:port`, mutually authenticate and issue one request.
/// `timeout` is reapplied to individual connection, handshake and request I/O
/// operations; it is not a total-call deadline. The authentication-failure
/// notification write is currently unbounded. Use an outer timeout when the
/// whole operation needs a deadline.
pub async fn connect_and_request(
    port: u16,
    rpc_key: &[u8],
    request: &RpcRequest,
    timeout: std::time::Duration,
) -> Result<RpcResponse, RpcError> {
    let addr = format!("127.0.0.1:{port}");

    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout",
            ))
        })?
        .map_err(RpcError::Io)?;

    request_over_stream(&mut stream, rpc_key, request, timeout).await
}

#[cfg(unix)]
pub async fn connect_unix_and_request(
    socket_path: &str,
    rpc_key: &[u8],
    request: &RpcRequest,
    timeout: std::time::Duration,
) -> Result<RpcResponse, RpcError> {
    let mut stream = tokio::time::timeout(timeout, connect_unix_stream(socket_path))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout",
            ))
        })?
        .map_err(RpcError::Io)?;

    request_over_stream(&mut stream, rpc_key, request, timeout).await
}

#[cfg(unix)]
pub(crate) async fn connect_unix_stream(
    socket_path: &str,
) -> std::io::Result<tokio::net::UnixStream> {
    if let Some(abstract_name) = socket_path.strip_prefix('\0') {
        return connect_abstract_unix_stream(abstract_name);
    }

    tokio::net::UnixStream::connect(socket_path).await
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
fn connect_abstract_unix_stream(name: &str) -> std::io::Result<tokio::net::UnixStream> {
    use std::os::unix::net::{SocketAddr, UnixStream};

    #[cfg(target_os = "android")]
    use std::os::android::net::SocketAddrExt as _;
    #[cfg(target_os = "linux")]
    use std::os::linux::net::SocketAddrExt as _;

    let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
    let stream = UnixStream::connect_addr(&addr)?;
    stream.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(stream)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn connect_abstract_unix_stream(_name: &str) -> std::io::Result<tokio::net::UnixStream> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "abstract Unix sockets are only available on Linux/Android",
    ))
}

#[cfg(not(unix))]
pub async fn connect_unix_and_request(
    _socket_path: &str,
    _rpc_key: &[u8],
    _request: &RpcRequest,
    _timeout: std::time::Duration,
) -> Result<RpcResponse, RpcError> {
    Err(RpcError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Unix shared-instance RPC is not supported on this platform",
    )))
}

async fn request_over_stream<S>(
    stream: &mut S,
    rpc_key: &[u8],
    request: &RpcRequest,
    timeout: std::time::Duration,
) -> Result<RpcResponse, RpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let resp_buf = request_bytes_over_stream(stream, rpc_key, request, timeout).await?;
    decode_response_for_request(&resp_buf, request)
}

/// Like [`connect_and_request`], returning the undecoded response.
pub async fn connect_and_request_bytes(
    port: u16,
    rpc_key: &[u8],
    request: &RpcRequest,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, RpcError> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout",
            ))
        })?
        .map_err(RpcError::Io)?;
    request_bytes_over_stream(&mut stream, rpc_key, request, timeout).await
}

/// Like [`connect_unix_and_request`], returning the undecoded response.
#[cfg(unix)]
pub async fn connect_unix_and_request_bytes(
    socket_path: &str,
    rpc_key: &[u8],
    request: &RpcRequest,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, RpcError> {
    let mut stream = tokio::time::timeout(timeout, connect_unix_stream(socket_path))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout",
            ))
        })?
        .map_err(RpcError::Io)?;
    request_bytes_over_stream(&mut stream, rpc_key, request, timeout).await
}

#[cfg(not(unix))]
pub async fn connect_unix_and_request_bytes(
    _socket_path: &str,
    _rpc_key: &[u8],
    _request: &RpcRequest,
    _timeout: std::time::Duration,
) -> Result<Vec<u8>, RpcError> {
    Err(RpcError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Unix shared-instance RPC is not supported on this platform",
    )))
}

/// Python's top-level byte totals and packet rates in an `interface_stats`
/// answer (Reticulum.py).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InterfaceStatsTotals {
    pub rxb: u64,
    pub txb: u64,
    pub rxpps: u64,
    pub txpps: u64,
}

/// Read [`InterfaceStatsTotals`] from an `interface_stats` answer; keys a peer
/// leaves out read as zero.
pub fn decode_interface_stats_totals(data: &[u8]) -> Result<InterfaceStatsTotals, RpcError> {
    let value = decode_umsgpack(data)?;
    let PyValue::Dict(entries) = &value else {
        return Err(RpcError::Deserialize(
            "expected interface stats dictionary".to_string(),
        ));
    };
    let get = |key: &str| dict_get(entries, key).and_then(py_u64).unwrap_or(0);
    Ok(InterfaceStatsTotals {
        rxb: get("rxb"),
        txb: get("txb"),
        rxpps: get("rxpps"),
        txpps: get("txpps"),
    })
}

async fn request_bytes_over_stream<S>(
    mut stream: &mut S,
    rpc_key: &[u8],
    request: &RpcRequest,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, RpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let challenge_frame = tokio::time::timeout(timeout, read_mp_frame(&mut stream, 256))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "challenge read timeout",
            ))
        })??;
    if !challenge_frame.starts_with(MP_CHALLENGE) {
        return Err(RpcError::AuthFailed);
    }
    let challenge = &challenge_frame[MP_CHALLENGE.len()..];
    let protocol = detect_python_auth_protocol(challenge);

    let response = compute_python_auth_response_for(protocol, rpc_key, challenge);
    tokio::time::timeout(timeout, write_mp_frame(&mut stream, &response))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "hmac write timeout",
            ))
        })??;

    let welcome = tokio::time::timeout(timeout, read_mp_frame(&mut stream, 256))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "welcome read timeout",
            ))
        })??;
    if welcome != MP_WELCOME {
        return Err(RpcError::AuthFailed);
    }

    let client_challenge = new_python_challenge_for(protocol);
    let mut client_challenge_frame =
        Vec::with_capacity(MP_CHALLENGE.len() + client_challenge.len());
    client_challenge_frame.extend_from_slice(MP_CHALLENGE);
    client_challenge_frame.extend_from_slice(&client_challenge);
    tokio::time::timeout(
        timeout,
        write_mp_frame(&mut stream, &client_challenge_frame),
    )
    .await
    .map_err(|_| {
        RpcError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "client challenge write timeout",
        ))
    })??;

    let server_response = tokio::time::timeout(timeout, read_mp_frame(&mut stream, 256))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "server auth response read timeout",
            ))
        })??;
    if verify_python_auth_response_for(protocol, rpc_key, &client_challenge, &server_response) {
        tokio::time::timeout(timeout, write_mp_frame(&mut stream, MP_WELCOME))
            .await
            .map_err(|_| {
                RpcError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "client welcome write timeout",
                ))
            })??;
    } else {
        let _ = write_mp_frame(&mut stream, MP_FAILURE).await;
        return Err(RpcError::AuthFailed);
    }

    let req_bytes = encode_request(request)?;
    tokio::time::timeout(timeout, write_mp_frame(&mut stream, &req_bytes))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request write timeout",
            ))
        })??;

    let resp_buf = tokio::time::timeout(timeout, read_mp_frame(&mut stream, MAX_MP_FRAME_SIZE))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "response read timeout",
            ))
        })??;

    Ok(resp_buf)
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("deserialization error: {0}")]
    Deserialize(String),
    #[error("authentication failed")]
    AuthFailed,
    #[error("connection error: {0}")]
    Connection(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Keys Python 1.6.1 `get_interface_stats()` gives every interface
/// (Reticulum.py); `rnstatus` indexes most of them unguarded.
#[cfg(test)]
pub(crate) const PYTHON_INTERFACE_KEYS: &[&str] = &[
    "clients",
    "bitrate",
    "rxs",
    "txs",
    "arxs",
    "atxs",
    "prxs",
    "ptxs",
    "ifac_signature",
    "ifac_size",
    "ifac_netname",
    "autoconnect_source",
    "name",
    "short_name",
    "hash",
    "type",
    "mtu",
    "rxb",
    "txb",
    "arxb",
    "atxb",
    "arxc",
    "atxc",
    "prxb",
    "ptxb",
    "prxc",
    "ptxc",
    "txdrp",
    "txdrb",
    "txstalled",
    "txbuffered",
    "incoming_announce_frequency",
    "outgoing_announce_frequency",
    "incoming_pr_frequency",
    "outgoing_pr_frequency",
    "announce_rate_target",
    "announce_rate_penalty",
    "announce_rate_grace",
    "held_announces",
    "burst_active",
    "burst_activated",
    "burst_count",
    "pr_burst_active",
    "pr_burst_activated",
    "pr_burst_count",
    "status",
    "mode",
    "gravity",
    "announces_to_internal",
    "protocol_violations",
    "ifac_violations",
    "packet_filter_hits",
    "frxs",
    "ftxs",
    "frxb",
    "ftxb",
    "afrxc",
    "announce_queue",
    "tunnel_id",
    "remote_transport_id",
    "rem_impl",
    "rem_vers",
    "rem_is_tn",
    "rem_dst_cost",
    "rem_pr_cost",
];

/// Totals in every Python 1.6.1 stats dict (Reticulum.py).
#[cfg(test)]
pub(crate) const PYTHON_TOTAL_KEYS: &[&str] = &[
    "interfaces",
    "rxb",
    "txb",
    "rxs",
    "txs",
    "lrxb",
    "ltxb",
    "lrxs",
    "ltxs",
    "frxb",
    "ftxb",
    "frxs",
    "ftxs",
    "arxb",
    "atxb",
    "arxs",
    "atxs",
    "arxf",
    "atxf",
    "prxb",
    "ptxb",
    "prxs",
    "ptxs",
    "prxf",
    "ptxf",
    "rxpps",
    "txpps",
    "rxqt",
    "rxqd",
    "rxqa",
    "rxqp",
    "rxqil",
    "rxqtd",
    "rxqdd",
    "rxqad",
    "rxqpd",
    "rxqild",
    "tqpressure",
    "dqpressure",
    "aqpressure",
    "pqpressure",
    "ilqpressure",
    "txq",
    "rss",
];

/// Added only by a transport instance (Reticulum.py).
#[cfg(test)]
pub(crate) const PYTHON_TRANSPORT_KEYS: &[&str] = &[
    "transport_id",
    "network_id",
    "transport_uptime",
    "probe_responder",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn contains_string_key(value: &PyValue, expected: &str) -> bool {
        match value {
            PyValue::List(values) => values
                .iter()
                .any(|value| contains_string_key(value, expected)),
            PyValue::Dict(entries) => entries.iter().any(|(key, value)| {
                matches!(key, PyDictKey::String(key) if key == expected)
                    || contains_string_key(value, expected)
            }),
            _ => false,
        }
    }

    #[test]
    fn test_request_roundtrip() {
        let req = RpcRequest::GetPathTable { max_hops: Some(8) };
        let encoded = encode_request(&req).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        match decoded {
            RpcRequest::GetPathTable { max_hops } => assert_eq!(max_hops, Some(8)),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = RpcResponse::IntResult(42);
        let encoded = encode_response(&resp).unwrap();
        let decoded = decode_response(&encoded).unwrap();
        match decoded {
            RpcResponse::IntResult(n) => assert_eq!(n, 42),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_path_table_response() {
        let entry = PathTableEntry {
            hash: vec![0xAA; 16],
            timestamp: 1234567890.0,
            via: Some(vec![0xBB; 16]),
            hops: 3,
            expires: 1234567890.0 + 604800.0,
            value: None,
            used: Some(0.0),
            lr_cost: None,
            interface: "TCPInterface[test]".to_string(),
            interface_hash: None,
            state: None,
        };
        let resp = RpcResponse::PathTable(vec![entry]);
        let encoded = encode_response(&resp).unwrap();
        let decoded = decode_response(&encoded).unwrap();
        match decoded {
            RpcResponse::PathTable(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].hops, 3);
            }
            _ => panic!("wrong variant"),
        }
    }

    fn interface_stat_entry() -> InterfaceStatRpcEntry {
        let mut entry = InterfaceStatRpcEntry::default();
        entry.id = 7;
        entry.name = "TestIf".to_string();
        entry.rx_bytes = 100;
        entry.tx_bytes = 200;
        entry.rx_rate = 10;
        entry.tx_rate = 20;
        entry.online = true;
        entry.bitrate = 115_200;
        entry.mtu = 500;
        entry.mode = "Gateway".to_string();
        entry.role = "normal".to_string();
        entry.announce_queue = Some(2);
        entry.held_announces = 3;
        entry.incoming_announce_frequency = 4.0;
        entry.outgoing_announce_frequency = 5.0;
        entry.incoming_pr_frequency = 6.0;
        entry.outgoing_pr_frequency = 7.0;
        entry.burst_active = true;
        entry.burst_activated = 1_700_000_001.0;
        entry.pr_burst_active = true;
        entry.pr_burst_activated = 1_700_000_002.0;
        entry.clients = Some(4);
        entry.blocked_ips = Some(2);
        entry.announce_rate_target = Some(3600.0);
        entry.announce_rate_grace = Some(5);
        entry.announce_rate_penalty = Some(30.0);
        entry.announce_cap = 0.02;
        entry.tx_drops = 1;
        entry
    }

    fn stats_dict(encoded: &[u8]) -> Vec<(PyDictKey, PyValue)> {
        let PyValue::Dict(stats) = decode_umsgpack(encoded).unwrap() else {
            panic!("interface stats are a dict");
        };
        stats
    }

    fn interface_dicts(stats: &[(PyDictKey, PyValue)]) -> Vec<Vec<(PyDictKey, PyValue)>> {
        let Some(PyValue::List(interfaces)) = dict_get(stats, "interfaces") else {
            panic!("interface stats list their interfaces");
        };
        interfaces
            .iter()
            .map(|interface| as_dict(interface).unwrap().to_vec())
            .collect()
    }

    #[test]
    fn interface_stats_carry_every_python_161_key() {
        let encoded =
            encode_response(&RpcResponse::InterfaceStats(vec![interface_stat_entry()])).unwrap();
        let stats = stats_dict(&encoded);
        for key in PYTHON_TOTAL_KEYS {
            assert!(dict_get(&stats, key).is_some(), "missing total {key}");
        }
        for key in PYTHON_TRANSPORT_KEYS {
            assert!(
                dict_get(&stats, key).is_none(),
                "{key} belongs only to a transport instance"
            );
        }
        let interface = &interface_dicts(&stats)[0];
        for key in PYTHON_INTERFACE_KEYS {
            assert!(dict_get(interface, key).is_some(), "missing {key}");
        }
        assert_eq!(dict_get(interface, "txdrp"), Some(&PyValue::Int(1)));
        assert_eq!(
            dict_get(interface, "txstalled"),
            Some(&PyValue::Bool(false))
        );
        assert_eq!(dict_get(interface, "mtu"), Some(&PyValue::Int(500)));
        assert_eq!(dict_get(&stats, "txq"), Some(&PyValue::None));
    }

    #[test]
    fn interface_stats_without_clients_report_python_none() {
        let mut entry = interface_stat_entry();
        entry.clients = None;
        let encoded = encode_response(&RpcResponse::InterfaceStats(vec![entry])).unwrap();
        let interface = &interface_dicts(&stats_dict(&encoded))[0];
        assert_eq!(
            dict_get(interface, "clients"),
            Some(&PyValue::None),
            "rnstatus reads clients unguarded (rnstatus.py:489)"
        );
    }

    #[test]
    fn interface_stats_report_rust_counters_under_python_keys() {
        let mut entry = interface_stat_entry();
        entry.announces_received = 11;
        entry.announces_sent = 12;
        entry.path_requests_received = 13;
        entry.path_requests_sent = 14;
        entry.protocol_violations = 15;
        entry.ifac_violations = 16;
        entry.packet_filter_hits = 17;
        entry.tx_dropped_bytes = 18;
        entry.gravity = -3;
        let encoded = encode_response(&RpcResponse::InterfaceStats(vec![entry])).unwrap();
        let interface = &interface_dicts(&stats_dict(&encoded))[0];
        for (key, value) in [
            ("gravity", -3),
            ("arxc", 11),
            ("atxc", 12),
            ("prxc", 13),
            ("ptxc", 14),
            ("protocol_violations", 15),
            ("ifac_violations", 16),
            ("packet_filter_hits", 17),
            ("txdrb", 18),
        ] {
            assert_eq!(
                dict_get(interface, key),
                Some(&PyValue::Int(value)),
                "{key}"
            );
        }

        let RpcResponse::InterfaceStats(decoded) =
            decode_response_for_request(&encoded, &RpcRequest::GetInterfaceStats).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(
            (
                decoded[0].announces_received,
                decoded[0].announces_sent,
                decoded[0].path_requests_received,
                decoded[0].path_requests_sent,
                decoded[0].protocol_violations,
                decoded[0].ifac_violations,
                decoded[0].packet_filter_hits,
                decoded[0].tx_drops,
                decoded[0].tx_dropped_bytes,
                decoded[0].gravity,
            ),
            (11, 12, 13, 14, 15, 16, 17, 1, 18, -3)
        );
    }

    #[test]
    fn python_daemon_counters_parse_into_interface_stats() {
        let upstream = py_dict(vec![(
            "interfaces",
            PyValue::List(vec![py_dict(vec![
                (
                    "name",
                    PyValue::String("TCPInterface[Client on Hub]".to_string()),
                ),
                ("status", PyValue::Bool(true)),
                ("arxc", PyValue::Int(21)),
                ("atxc", PyValue::Int(22)),
                ("prxc", PyValue::Int(23)),
                ("ptxc", PyValue::Int(24)),
                ("protocol_violations", PyValue::Int(25)),
                ("ifac_violations", PyValue::Int(26)),
                ("packet_filter_hits", PyValue::Int(27)),
                ("txdrp", PyValue::Int(28)),
                ("txdrb", PyValue::Int(29)),
                (
                    "parent_interface_name",
                    PyValue::String("TCPServerInterface[Hub/0.0.0.0:4242]".to_string()),
                ),
            ])]),
        )]);
        let encoded = encode_umsgpack(&upstream).unwrap();
        let RpcResponse::InterfaceStats(entries) =
            decode_response_for_request(&encoded, &RpcRequest::GetInterfaceStats).unwrap()
        else {
            panic!("wrong variant");
        };
        let entry = &entries[0];
        assert_eq!(
            (
                entry.announces_received,
                entry.announces_sent,
                entry.path_requests_received,
                entry.path_requests_sent,
                entry.protocol_violations,
                entry.ifac_violations,
                entry.packet_filter_hits,
                entry.tx_drops,
                entry.tx_dropped_bytes,
            ),
            (21, 22, 23, 24, 25, 26, 27, 28, 29)
        );
        assert_eq!(
            entry.parent_interface_name.as_deref(),
            Some("TCPServerInterface[Hub/0.0.0.0:4242]")
        );
    }

    #[test]
    fn a_spawned_interface_names_its_parent_like_python() {
        let parent = interface_stat_entry();
        let mut child = interface_stat_entry();
        child.id = 8;
        child.name = "TestIf/client_8".to_string();
        child.parent_interface_name = Some(parent.name.clone());
        let encoded = encode_response(&RpcResponse::InterfaceStats(vec![parent, child])).unwrap();
        let interfaces = interface_dicts(&stats_dict(&encoded));
        assert!(dict_get(&interfaces[0], "parent_interface_name").is_none());
        assert_eq!(
            dict_get(&interfaces[1], "parent_interface_name"),
            Some(&PyValue::String("TestIf".to_string()))
        );
        assert_eq!(
            dict_get(&interfaces[1], "parent_interface_hash"),
            Some(&PyValue::Bytes(rns_crypto::sha::sha256(b"TestIf").to_vec())),
            "Python's get_hash() is the full hash of the interface name (Interface.py:181-183)"
        );
        assert_eq!(
            dict_get(&interfaces[0], "hash"),
            Some(&PyValue::Bytes(rns_crypto::sha::sha256(b"TestIf").to_vec()))
        );
    }

    #[test]
    fn inbound_queue_stats_follow_python_heights_drops_and_pressures() {
        let queues = InboundQueueSnapshot {
            heights: [256, 0, 32, 2],
            dropped: [0, 7, 1, 3],
            lengths: [1024, 128, 128, 8],
        };
        let stats = stats_dict(&encode_interface_stats(&[], None, None, Some(&queues)).unwrap());
        let get = |k| dict_get(&stats, k).cloned().unwrap();
        assert_eq!(get("rxqt"), PyValue::Int(290));
        assert_eq!(get("rxqil"), PyValue::Int(2));
        assert_eq!(get("rxqtd"), PyValue::Int(11));
        assert_eq!(get("rxqad"), PyValue::Int(7));
        assert_eq!(get("tqpressure"), PyValue::Float(290.0 / 1288.0));
        assert_eq!(get("dqpressure"), PyValue::Float(0.25));
        assert_eq!(get("aqpressure"), PyValue::Int(0));
        assert_eq!(get("ilqpressure"), PyValue::Float(0.25));
    }

    #[test]
    fn transport_instance_stats_carry_python_transport_fields() {
        let transport = TransportStats {
            transport_id: [0x11; 16],
            network_id: Some([0x22; 16]),
            uptime: 12.5,
            probe_responder: Some([0x33; 16]),
        };
        let encoded =
            encode_interface_stats(&[interface_stat_entry()], Some(&transport), None, None)
                .unwrap();
        let stats = stats_dict(&encoded);
        assert_eq!(
            dict_get(&stats, "transport_id"),
            Some(&PyValue::Bytes(vec![0x11; 16]))
        );
        assert_eq!(
            dict_get(&stats, "network_id"),
            Some(&PyValue::Bytes(vec![0x22; 16]))
        );
        assert_eq!(
            dict_get(&stats, "transport_uptime"),
            Some(&PyValue::Float(12.5))
        );
        assert_eq!(
            dict_get(&stats, "probe_responder"),
            Some(&PyValue::Bytes(vec![0x33; 16]))
        );

        let bare = TransportStats {
            network_id: None,
            probe_responder: None,
            ..transport
        };
        let stats = stats_dict(&encode_interface_stats(&[], Some(&bare), None, None).unwrap());
        assert_eq!(dict_get(&stats, "network_id"), Some(&PyValue::None));
        assert_eq!(dict_get(&stats, "probe_responder"), Some(&PyValue::None));
    }

    #[test]
    fn interface_modes_map_to_python_mode_constants() {
        for (mode, python) in [
            ("Full", 0x01),
            ("PointToPoint", 0x02),
            ("AccessPoint", 0x03),
            ("Roaming", 0x04),
            ("Boundary", 0x05),
            ("Gateway", 0x06),
            ("Internal", 0x07),
        ] {
            assert_eq!(python_interface_mode(mode), python, "{mode}");
        }
    }

    /// Python publishes IFAC as signature, size and network name, all `None`
    /// without IFAC; clients key off the signature.
    #[test]
    fn interface_stats_carry_python_ifac_fields() {
        let mut ifac = interface_stat_entry();
        ifac.ifac_signature = Some(vec![0xAB; 64]);
        ifac.ifac_size = Some(8);
        ifac.ifac_netname = Some("testnet".to_string());
        let encoded = encode_response(&RpcResponse::InterfaceStats(vec![
            ifac,
            interface_stat_entry(),
        ]))
        .unwrap();
        let raw = decode_umsgpack(&encoded).unwrap();
        assert!(contains_string_key(&raw, "ifac_signature"));
        assert!(contains_string_key(&raw, "ifac_netname"));
        let RpcResponse::InterfaceStats(entries) =
            decode_response_for_request(&encoded, &RpcRequest::GetInterfaceStats).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(entries[0].ifac_signature.as_deref(), Some(&[0xAB; 64][..]));
        assert_eq!(entries[0].ifac_size, Some(8));
        assert_eq!(entries[0].ifac_netname.as_deref(), Some("testnet"));
        assert_eq!(entries[1].ifac_signature, None);
        assert_eq!(entries[1].ifac_size, None);
        assert_eq!(entries[1].ifac_netname, None);
    }

    /// A decoded reply keeps how the owner names an interface and its I2P
    /// state, and encodes to the same keys again.
    #[test]
    fn a_decoded_reply_reencodes_its_names_and_i2p_state_unchanged() {
        let sent = vec![
            (
                "name",
                PyValue::String("I2PInterfacePeer[Connected peer to abc]".to_string()),
            ),
            (
                "short_name",
                PyValue::String("Connected peer to abc".to_string()),
            ),
            ("type", PyValue::String("I2PInterfacePeer".to_string())),
            ("status", PyValue::Bool(true)),
            (
                "parent_interface_name",
                PyValue::String("I2PInterface[Hub]".to_string()),
            ),
            ("autoconnect_source", PyValue::String("5a".repeat(16))),
            ("i2p_connectable", PyValue::Bool(true)),
            ("i2p_b32", PyValue::String("abc.b32.i2p".to_string())),
            (
                "tunnelstate",
                PyValue::String("Tunnel Unresponsive".to_string()),
            ),
        ];
        let upstream = py_dict(vec![(
            "interfaces",
            PyValue::List(vec![py_dict(sent.clone())]),
        )]);
        let decoded = decode_response_for_request(
            &encode_umsgpack(&upstream).unwrap(),
            &RpcRequest::GetInterfaceStats,
        )
        .unwrap();
        let RpcResponse::InterfaceStats(entries) = &decoded else {
            panic!("wrong variant");
        };
        assert_eq!(
            entries[0].identity,
            Some(InterfaceIdentity::new(
                "I2PInterfacePeer[Connected peer to abc]",
                "Connected peer to abc",
                "I2PInterfacePeer",
            ))
        );
        assert_eq!(entries[0].i2p_b32.as_deref(), Some("abc"));
        assert_eq!(entries[0].i2p_tunnel_state, Some(0x02));

        let reencoded = encode_response(&decoded).unwrap();
        let interface = &interface_dicts(&stats_dict(&reencoded))[0];
        for (key, value) in &sent {
            assert_eq!(dict_get(interface, key), Some(value), "{key}");
        }
    }

    /// Python 1.6.1's filtered, tunnel and remote transport keys decode and
    /// encode again unchanged; without a remote transport all `rem_*` are nil.
    #[test]
    fn python_161_tunnel_and_filtered_keys_round_trip() {
        let sent = vec![
            ("name", PyValue::String("TCPInterface[Hub]".to_string())),
            ("type", PyValue::String("TCPInterface".to_string())),
            ("status", PyValue::Bool(true)),
            ("frxb", PyValue::Int(31)),
            ("ftxb", PyValue::Int(0)),
            ("frxs", PyValue::Float(8.5)),
            ("ftxs", PyValue::Float(0.0)),
            ("afrxc", PyValue::Int(3)),
            ("tunnel_id", PyValue::Bytes(vec![0xab; 32])),
            ("remote_transport_id", PyValue::Bytes(vec![0xcd; 16])),
            ("rem_impl", PyValue::String("rns".to_string())),
            (
                "rem_vers",
                PyValue::List(vec![PyValue::Int(1), PyValue::Int(6), PyValue::Int(1)]),
            ),
            ("rem_is_tn", PyValue::Bool(true)),
            ("rem_dst_cost", PyValue::Float(8.0)),
            ("rem_pr_cost", PyValue::Float(0.5)),
        ];
        let upstream = py_dict(vec![(
            "interfaces",
            PyValue::List(vec![py_dict(sent.clone())]),
        )]);
        let decoded = decode_response_for_request(
            &encode_umsgpack(&upstream).unwrap(),
            &RpcRequest::GetInterfaceStats,
        )
        .unwrap();
        let RpcResponse::InterfaceStats(entries) = &decoded else {
            panic!("wrong variant");
        };
        assert_eq!(entries[0].announces_filtered, 3);
        assert_eq!(entries[0].tunnel_id, Some([0xab; 32]));
        assert_eq!(
            entries[0]
                .remote_transport
                .as_ref()
                .map(|r| r.version.clone()),
            Some(vec![1, 6, 1])
        );
        let reencoded = encode_response(&decoded).unwrap();
        let interface = &interface_dicts(&stats_dict(&reencoded))[0];
        for (key, value) in &sent {
            assert_eq!(dict_get(interface, key), Some(value), "{key}");
        }

        let encoded =
            encode_response(&RpcResponse::InterfaceStats(vec![interface_stat_entry()])).unwrap();
        let interface = &interface_dicts(&stats_dict(&encoded))[0];
        for key in [
            "tunnel_id",
            "remote_transport_id",
            "rem_impl",
            "rem_vers",
            "rem_is_tn",
            "rem_dst_cost",
            "rem_pr_cost",
        ] {
            assert_eq!(dict_get(interface, key), Some(&PyValue::None), "{key}");
        }
        assert_eq!(dict_get(interface, "frxs"), Some(&PyValue::Int(0)));
    }

    /// The link and filtered totals follow the transport's counters.
    #[test]
    fn interface_stats_totals_carry_link_and_filtered_traffic() {
        let mut totals = TrafficTotals::default();
        totals.measured = true;
        totals.lrxb = 41;
        totals.ltxb = 42;
        totals.lrxs = 4.5;
        totals.frxb = 43;
        totals.frxs = 1.5;
        totals.rx_packets = 44;
        let encoded = encode_interface_stats(&[], None, Some(&totals), None).unwrap();
        let stats = stats_dict(&encoded);
        for (key, value) in [
            ("lrxb", PyValue::Int(41)),
            ("ltxb", PyValue::Int(42)),
            ("lrxs", PyValue::Float(4.5)),
            ("ltxs", PyValue::Float(0.0)),
            ("frxb", PyValue::Int(43)),
            ("ftxb", PyValue::Int(0)),
            ("frxs", PyValue::Float(1.5)),
            ("ftxs", PyValue::Float(0.0)),
            ("rxpkts", PyValue::Int(44)),
        ] {
            assert_eq!(dict_get(&stats, key), Some(&value), "{key}");
        }
    }

    /// Expected bytes are upstream 1.6.1 `umsgpack.packb` of the same values.
    #[test]
    fn link_distribution_and_known_destinations_round_trip_as_upstream() {
        for (request, hex) in [
            (
                RpcRequest::GetKnownDestinations,
                "81a3676574b26b6e6f776e5f64657374696e6174696f6e73",
            ),
            (
                RpcRequest::GetLinkDistribution,
                "81a3676574b16c696e6b5f646973747269627574696f6e",
            ),
        ] {
            let encoded = encode_request(&request).unwrap();
            assert_eq!(hex::encode(&encoded), hex);
            let decoded = decode_request(&encoded).unwrap();
            assert_eq!(format!("{decoded:?}"), format!("{request:?}"));
        }

        let distribution = vec![LinkDistributionEntry {
            destination_hash: vec![0x11; 16],
            active: 2,
            pending: 1,
            traffic: 4096,
            from_interfaces: vec![vec![0x22; 32]],
        }];
        let encoded =
            encode_response(&RpcResponse::LinkDistribution(distribution.clone())).unwrap();
        assert_eq!(
            hex::encode(&encoded),
            "81c4101111111111111111111111111111111184a661637469766502a770656e64696e6701a77472616666\
             6963cd1000a866726f6d5f69667391c42022222222222222222222222222222222222222222222222222\
             22222222222222"
        );
        match decode_response_for_request(&encoded, &RpcRequest::GetLinkDistribution).unwrap() {
            RpcResponse::LinkDistribution(decoded) => assert_eq!(decoded, distribution),
            other => panic!("unexpected {other:?}"),
        }

        let known = vec![
            KnownDestinationEntry {
                destination_hash: vec![0x33; 16],
                last_heard: 1_700_000_000.5,
                packet_hash: Some(vec![0x44; 32]),
                public_key: vec![0x55; 64],
                app_data: Some(b"app".to_vec()),
                used: 0.0,
                stamp: None,
                stamp_value: 0.0,
                lr_cost: None,
            },
            KnownDestinationEntry {
                destination_hash: vec![0x66; 16],
                last_heard: 1_700_000_001.25,
                packet_hash: None,
                public_key: vec![0x77; 64],
                app_data: None,
                used: -1.0,
                stamp: Some(vec![0x88; 32]),
                stamp_value: 8.5,
                lr_cost: Some(3.25),
            },
        ];
        let encoded = encode_response(&RpcResponse::KnownDestinations(known.clone())).unwrap();
        assert_eq!(
            hex::encode(&encoded),
            "82c4103333333333333333333333333333333398cb41d954fc40200000c420444444444444444444\
             4444444444444444444444444444444444444444444444c440555555555555555555555555555555\
             55555555555555555555555555555555555555555555555555555555555555555555555555555555\
             555555555555555555c40361707000c000c0c4106666666666666666666666666666666698cb41d9\
             54fc40500000c0c44077777777777777777777777777777777777777777777777777777777777777\
             777777777777777777777777777777777777777777777777777777777777777777c0ffc420888888\
             8888888888888888888888888888888888888888888888888888888888cb4021000000000000cb40\
             0a000000000000"
        );
        match decode_response_for_request(&encoded, &RpcRequest::GetKnownDestinations).unwrap() {
            RpcResponse::KnownDestinations(decoded) => assert_eq!(decoded, known),
            other => panic!("unexpected {other:?}"),
        }
        let row = known[1].to_row().unwrap();
        assert_eq!(KnownDestinationEntry::from(&row), known[1]);

        // nil, a Python client's failed call, and an empty table read as empty.
        for (request, bytes) in [
            (RpcRequest::GetLinkDistribution, [0xc0]),
            (RpcRequest::GetKnownDestinations, [0x80]),
        ] {
            let decoded = decode_response_for_request(&bytes, &request).unwrap();
            assert!(
                matches!(
                    decoded,
                    RpcResponse::LinkDistribution(ref e) if e.is_empty()
                ) || matches!(decoded, RpcResponse::KnownDestinations(ref e) if e.is_empty())
            );
        }
    }

    /// Serde sees the wire entry, not the transport type.
    #[test]
    fn interface_stats_serialize_as_the_wire_entry() {
        let mut entry = interface_stat_entry();
        entry.identity = Some(InterfaceIdentity::new(
            "Tcp[TestIf]",
            "TestIf",
            "TCPInterface",
        ));
        entry.i2p_tunnel_state = Some(0x01);
        let json = serde_json::to_value(RpcResponse::InterfaceStats(vec![entry])).unwrap();
        let wire = &json["InterfaceStats"][0];
        assert_eq!(wire["name"], "Tcp[TestIf]");
        assert_eq!(wire["short_name"], "TestIf");
        assert_eq!(wire["class_name"], "TCPInterface");
        assert_eq!(wire["tunnel_state"], "Tunnel Active");
        assert!(wire.get("identity").is_none() && wire.get("parent_id").is_none());

        let RpcResponse::InterfaceStats(back) = serde_json::from_value(json).unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(back[0].name, "Tcp[TestIf]");
        assert_eq!(back[0].i2p_tunnel_state, Some(0x01));
    }

    #[test]
    fn test_interface_stats_response_roundtrip_includes_125_fields() {
        let resp = RpcResponse::InterfaceStats(vec![interface_stat_entry()]);
        let encoded = encode_response(&resp).unwrap();
        let decoded =
            decode_response_for_request(&encoded, &RpcRequest::GetInterfaceStats).unwrap();
        match decoded {
            RpcResponse::InterfaceStats(entries) => {
                assert_eq!(entries.len(), 1);
                let entry = &entries[0];
                assert_eq!(entry.incoming_pr_frequency, 6.0);
                assert_eq!(entry.outgoing_pr_frequency, 7.0);
                assert!(entry.burst_active);
                assert_eq!(entry.burst_activated, 1_700_000_001.0);
                assert!(entry.pr_burst_active);
                assert_eq!(entry.pr_burst_activated, 1_700_000_002.0);
                assert_eq!(entry.blocked_ips, Some(2));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_interface_stats_parser_defaults_missing_125_fields() {
        let legacy = py_dict(vec![(
            "interfaces",
            PyValue::List(vec![py_dict(vec![
                ("name", PyValue::String("LegacyIf".to_string())),
                ("rxb", PyValue::Int(1)),
                ("txb", PyValue::Int(2)),
                ("status", PyValue::Bool(true)),
            ])]),
        )]);
        let encoded = encode_umsgpack(&legacy).unwrap();
        let decoded =
            decode_response_for_request(&encoded, &RpcRequest::GetInterfaceStats).unwrap();
        match decoded {
            RpcResponse::InterfaceStats(entries) => {
                assert_eq!(entries.len(), 1);
                let entry = &entries[0];
                assert_eq!(entry.incoming_pr_frequency, 0.0);
                assert_eq!(entry.outgoing_pr_frequency, 0.0);
                assert!(!entry.burst_active);
                assert_eq!(entry.burst_activated, 0.0);
                assert!(!entry.pr_burst_active);
                assert_eq!(entry.pr_burst_activated, 0.0);
                assert_eq!(entry.blocked_ips, None);
                assert_eq!(entry.mtu, 0, "a legacy dict without MTU reads as 0");
                assert_eq!(entry.ifac_signature, None);
                assert_eq!(entry.ifac_size, None);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn request_specific_decoder_preserves_rpc_errors() {
        let encoded = encode_response(&RpcResponse::Error("transport unavailable".to_string()))
            .expect("encode RPC error");
        for request in [
            RpcRequest::GetPathTable { max_hops: None },
            RpcRequest::DropPath {
                destination_hash: vec![0; 16],
            },
        ] {
            assert!(matches!(
                decode_response_for_request(&encoded, &request),
                Ok(RpcResponse::Error(message)) if message == "transport unavailable"
            ));
        }
    }

    #[test]
    fn interface_stats_omit_absent_blocked_ip_count() {
        let mut entry = interface_stat_entry();
        entry.blocked_ips = None;
        let encoded = encode_response(&RpcResponse::InterfaceStats(vec![entry])).unwrap();
        let raw = decode_umsgpack(&encoded).unwrap();
        assert!(!contains_string_key(&raw, "blocked_ips"));
    }

    #[test]
    fn connect_diagnostics_stay_off_the_python_rpc() {
        let plain = encode_response(&RpcResponse::InterfaceStats(vec![interface_stat_entry()]));
        let mut entry = interface_stat_entry();
        entry.last_connect_error = Some("closed_by_peer".to_string());
        entry.connect_failures = 4;
        let encoded = encode_response(&RpcResponse::InterfaceStats(vec![entry])).unwrap();
        assert_eq!(encoded, plain.unwrap());
    }

    #[test]
    fn interface_stats_ignore_blocked_ip_lists_and_never_reencode_them() {
        let upstream = py_dict(vec![(
            "interfaces",
            PyValue::List(vec![py_dict(vec![
                ("name", PyValue::String("Backbone".to_string())),
                ("rxb", PyValue::Int(1)),
                ("txb", PyValue::Int(2)),
                ("status", PyValue::Bool(true)),
                ("blocked_ips", PyValue::Int(3)),
                (
                    "blocked_ip_list",
                    PyValue::List(vec![PyValue::String("192.0.2.1".to_string())]),
                ),
            ])]),
        )]);
        let encoded = encode_umsgpack(&upstream).unwrap();
        let decoded =
            decode_response_for_request(&encoded, &RpcRequest::GetInterfaceStats).unwrap();
        let RpcResponse::InterfaceStats(entries) = &decoded else {
            panic!("unexpected interface stats response");
        };
        assert_eq!(entries[0].blocked_ips, Some(3));

        let reencoded = encode_response(&decoded).unwrap();
        let raw = decode_umsgpack(&reencoded).unwrap();
        assert!(contains_string_key(&raw, "blocked_ips"));
        assert!(!contains_string_key(&raw, "blocked_ip_list"));
    }

    #[test]
    fn test_python_blackhole_dict_response_shape() {
        let identity_hash = vec![0x42; 16];
        let value = PyValue::Dict(vec![(
            PyDictKey::Bytes(identity_hash.clone()),
            py_dict(vec![
                ("until", PyValue::Float(1234.0)),
                ("reason", PyValue::String("parity".to_string())),
                ("source", PyValue::Bytes(vec![0xAA; 16])),
            ]),
        )]);
        let encoded = encode_umsgpack(&value).unwrap();
        match decode_response_for_request(&encoded, &RpcRequest::GetBlackholedIdentities).unwrap() {
            RpcResponse::BlackholeList(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].identity_hash, identity_hash);
                assert_eq!(entries[0].source.as_deref(), Some(&[0xAA; 16][..]));
                assert_eq!(entries[0].until, Some(1234.0));
                assert_eq!(entries[0].reason.as_deref(), Some("parity"));
            }
            other => panic!("wrong blackhole response variant: {other:?}"),
        }
    }

    #[test]
    fn test_auth_hmac() {
        let key = b"test_rpc_key";
        let challenge = b"random_challenge_bytes_32_bytes!";
        let hmac = compute_auth_hmac(key, challenge);
        assert!(verify_auth_hmac(key, challenge, &hmac));
    }

    #[test]
    fn test_auth_hmac_wrong_key() {
        let key = b"correct_key";
        let wrong_key = b"wrong_key_!";
        let challenge = b"random_challenge_bytes_32_bytes!";
        let hmac = compute_auth_hmac(key, challenge);
        assert!(!verify_auth_hmac(wrong_key, challenge, &hmac));
    }

    #[test]
    fn test_python_legacy_md5_auth_response() {
        let key = b"test_rpc_key";
        let challenge = b"python311challenge";
        let response = compute_python_auth_response(key, challenge);
        assert_eq!(response.len(), 16);
        assert!(verify_python_auth_response(key, challenge, &response));
        assert!(!verify_python_auth_response(
            b"wrong_key",
            challenge,
            &response
        ));
    }

    #[test]
    fn test_python_sha256_auth_response() {
        let key = b"test_rpc_key";
        let challenge = b"{sha256}python312pluschallenge";
        let response = compute_python_auth_response(key, challenge);
        assert!(response.starts_with(MP_DIGEST_PREFIX));
        assert!(verify_python_auth_response(key, challenge, &response));
        assert!(!verify_python_auth_response(
            b"wrong_key",
            challenge,
            &response
        ));
    }

    #[test]
    fn test_derive_rpc_key() {
        let private_key = [0x42u8; 64];
        let key1 = derive_rpc_key(&private_key);
        let key2 = derive_rpc_key(&private_key);
        assert_eq!(key1, key2);
        assert_ne!(key1, [0u8; 32]);
    }

    #[test]
    fn test_all_request_variants() {
        let requests = vec![
            RpcRequest::GetPathTable { max_hops: None },
            RpcRequest::GetInterfaceStats,
            RpcRequest::GetRateTable,
            RpcRequest::GetNextHopIfName {
                destination_hash: vec![0; 16],
            },
            RpcRequest::RequestPath {
                destination_hash: vec![0; 16],
                timeout_secs: Some(0.01),
            },
            RpcRequest::GetLinkCount,
            RpcRequest::DropPath {
                destination_hash: vec![0; 16],
            },
            RpcRequest::DropPathTable,
            RpcRequest::DropRecentAnnounces,
            RpcRequest::DropAnnounceQueues,
            RpcRequest::BlackholeIdentity {
                identity_hash: vec![0; 16],
                until: Some(99999.0),
                reason: Some("test".to_string()),
            },
            RpcRequest::UnblackholeIdentity {
                identity_hash: vec![0; 16],
            },
            RpcRequest::UseDestination {
                destination_hash: vec![0; 16],
            },
            RpcRequest::RetainDestination {
                destination_hash: vec![0; 16],
            },
            RpcRequest::RetainIdentity {
                identity_hash: vec![0; 16],
            },
            RpcRequest::UnretainDestination {
                destination_hash: vec![0; 16],
            },
            RpcRequest::IsBlackholed {
                identity_hash: vec![0; 16],
            },
        ];

        for req in &requests {
            let encoded = encode_request(req).unwrap();
            let _ = decode_request(&encoded).unwrap();
        }
    }

    // Fixtures generated by running the VERBATIM 1.3.8 vendored umsgpack
    // (git show 1.3.8:RNS/vendor/umsgpack.py, packb) over the RPC dict shapes
    // Python 1.3.8 Reticulum.py packs on the shared-instance control socket.
    const FX_REQ_PATH_TABLE_NONE: &str = "82a3676574aa706174685f7461626c65a86d61785f686f7073c0";
    const FX_REQ_PATH_TABLE_8: &str = "82a3676574aa706174685f7461626c65a86d61785f686f707308";
    const FX_REQ_INTERFACE_STATS: &str = "81a3676574af696e746572666163655f7374617473";
    const FX_REQ_IS_BLACKHOLED: &str = "82a3676574ad69735f626c61636b686f6c6564ad6964656e746974795f68617368c410000102030405060708090a0b0c0d0e0f";
    const FX_REQ_NEXT_HOP: &str = "82a3676574a86e6578745f686f70b064657374696e6174696f6e5f68617368c410aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FX_REQ_DROP_PATH: &str = "82a464726f70a470617468b064657374696e6174696f6e5f68617368c410bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const FX_REQ_BLACKHOLE_IDENTITY: &str = "83b2626c61636b686f6c655f6964656e74697479c41042424242424242424242424242424242a5756e74696ccb41d26580b4a00000a6726561736f6ea474657374";
    const FX_REQ_BLACKHOLE_IDENTITY_NONE: &str = "83b2626c61636b686f6c655f6964656e74697479c41042424242424242424242424242424242a5756e74696cc0a6726561736f6ec0";
    const FX_REQ_DESTINATION_DATA_USED: &str = "82b064657374696e6174696f6e5f64617461a475736564b064657374696e6174696f6e5f68617368c410cccccccccccccccccccccccccccccccc";
    const FX_REQ_IDENTITY_DATA_RETAIN: &str = "82ad6964656e746974795f64617461a672657461696ead6964656e746974795f68617368c410dddddddddddddddddddddddddddddddd";
    // Path-table replies: RNS 1.6.0 umsgpack over the dict get_path_table builds
    // (Reticulum.py), unknown and stamped destinations.
    const FX_RESP_PATH_TABLE_160: &str = "9189a468617368c410aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa974696d657374616d70cb41d26580b4800000a3766961c410bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbba4686f707303a765787069726573cb41d267cf54800000a576616c7565c0a47573656400a76c725f636f7374c0a9696e74657266616365b2544350496e746572666163655b746573745d";
    const FX_RESP_PATH_TABLE_STAMPED_160: &str = "9189a468617368c410aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa974696d657374616d70cb41d26580b4800000a3766961c410bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbba4686f707303a765787069726573cb41d267cf54800000a576616c7565cb4018500000000000a475736564cb41d26580cfe00000a76c725f636f7374cb400a000000000000a9696e74657266616365b2544350496e746572666163655b746573745d";
    // The same from RNS 1.6.1, which adds `interface_hash` and `state`:
    // `Reticulum.get_path_table` run on a Transport.path_table entry whose
    // interface prints as "TCPInterface[test]", with path state 0 and 2,
    // packed with RNS.vendor.umsgpack.packb.
    const FX_RESP_PATH_TABLE: &str = "918ba468617368c410aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa974696d657374616d70cb41d26580b4800000a3766961c410bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbba4686f707303a765787069726573cb41d267cf54800000a576616c7565c0a47573656400a76c725f636f7374c0a9696e74657266616365b2544350496e746572666163655b746573745dae696e746572666163655f68617368c4206e5082481873def8612282d21b981c90430ecd80bf5a877711f83dabb06ae938a5737461746500";
    const FX_RESP_PATH_TABLE_STAMPED: &str = "918ba468617368c410aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa974696d657374616d70cb41d26580b4800000a3766961c410bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbba4686f707303a765787069726573cb41d267cf54800000a576616c7565cb4018500000000000a475736564cb41d26580cfe00000a76c725f636f7374cb400a000000000000a9696e74657266616365b2544350496e746572666163655b746573745dae696e746572666163655f68617368c4206e5082481873def8612282d21b981c90430ecd80bf5a877711f83dabb06ae938a5737461746502";
    const FX_RESP_BLACKHOLE_DICT: &str = "81c4104242424242424242424242424242424283a6736f75726365c410aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa5756e74696ccb4093480000000000a6726561736f6ea6706172697479";
    const FX_INT_EDGES: &str = "dc0014007fcc80ccffcd0100cdffffce00010000ceffffffffcf0000000100000000cfffffffffffffffffffe0d0dfd080d1ff7fd18000d2ffff7fffd280000000d3ffffffff7fffffffd38000000000000000";
    const FX_STR_EDGES: &str = "93a0bf61616161616161616161616161616161616161616161616161616161616161d9206161616161616161616161616161616161616161616161616161616161616161";
    const FX_ARRAY_16: &str = "dc0010000102030405060708090a0b0c0d0e0f";

    fn assert_fixture(value: &PyValue, fixture_hex: &str) {
        let encoded = encode_umsgpack(value).unwrap();
        assert_eq!(hex::encode(&encoded), fixture_hex);
        let decoded = decode_umsgpack(&hex::decode(fixture_hex).unwrap()).unwrap();
        assert_eq!(&decoded, value);
    }

    #[test]
    fn requests_are_byte_exact_with_python_138_umsgpack() {
        for (req, fixture) in [
            (
                RpcRequest::GetPathTable { max_hops: None },
                FX_REQ_PATH_TABLE_NONE,
            ),
            (
                RpcRequest::GetPathTable { max_hops: Some(8) },
                FX_REQ_PATH_TABLE_8,
            ),
            (RpcRequest::GetInterfaceStats, FX_REQ_INTERFACE_STATS),
            (
                RpcRequest::IsBlackholed {
                    identity_hash: (0u8..16).collect(),
                },
                FX_REQ_IS_BLACKHOLED,
            ),
            (
                RpcRequest::GetNextHop {
                    destination_hash: vec![0xAA; 16],
                },
                FX_REQ_NEXT_HOP,
            ),
            (
                RpcRequest::DropPath {
                    destination_hash: vec![0xBB; 16],
                },
                FX_REQ_DROP_PATH,
            ),
            (
                RpcRequest::BlackholeIdentity {
                    identity_hash: vec![0x42; 16],
                    until: Some(1234567890.5),
                    reason: Some("test".to_string()),
                },
                FX_REQ_BLACKHOLE_IDENTITY,
            ),
            (
                RpcRequest::BlackholeIdentity {
                    identity_hash: vec![0x42; 16],
                    until: None,
                    reason: None,
                },
                FX_REQ_BLACKHOLE_IDENTITY_NONE,
            ),
            (
                RpcRequest::UseDestination {
                    destination_hash: vec![0xCC; 16],
                },
                FX_REQ_DESTINATION_DATA_USED,
            ),
            (
                RpcRequest::RetainIdentity {
                    identity_hash: vec![0xDD; 16],
                },
                FX_REQ_IDENTITY_DATA_RETAIN,
            ),
        ] {
            let encoded = encode_request(&req).unwrap();
            assert_eq!(hex::encode(&encoded), fixture, "request {req:?}");
            let _ = decode_request(&hex::decode(fixture).unwrap()).unwrap();
        }
    }

    #[test]
    fn scalar_responses_are_byte_exact_with_python_138_umsgpack() {
        assert_fixture(&PyValue::Bool(true), "c3");
        assert_fixture(&PyValue::Bool(false), "c2");
        assert_fixture(&PyValue::None, "c0");
        assert_fixture(&PyValue::Int(42), "2a");
        assert_fixture(&PyValue::Float(12.5), "cb4029000000000000");
    }

    #[test]
    fn path_table_response_is_byte_exact_with_python_umsgpack() {
        let resp = RpcResponse::PathTable(vec![PathTableEntry {
            hash: vec![0xAA; 16],
            timestamp: 1234567890.0,
            via: Some(vec![0xBB; 16]),
            hops: 3,
            expires: 1235172690.0,
            value: None,
            used: Some(0.0),
            lr_cost: None,
            interface: "TCPInterface[test]".to_string(),
            interface_hash: Some(rns_crypto::sha::sha256(b"TCPInterface[test]").to_vec()),
            state: Some(0),
        }]);
        assert_eq!(
            hex::encode(encode_response(&resp).unwrap()),
            FX_RESP_PATH_TABLE
        );
        match decode_response_for_request(
            &hex::decode(FX_RESP_PATH_TABLE).unwrap(),
            &RpcRequest::GetPathTable { max_hops: None },
        )
        .unwrap()
        {
            RpcResponse::PathTable(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].hops, 3);
                assert_eq!(entries[0].interface, "TCPInterface[test]");
                assert_eq!(entries[0].value, None);
                assert_eq!(entries[0].lr_cost, None);
                assert_eq!(entries[0].state, Some(0));
            }
            other => panic!("wrong variant: {other:?}"),
        }
        // A 1.6.0 instance sends neither key.
        for fixture in [FX_RESP_PATH_TABLE_160, FX_RESP_PATH_TABLE_STAMPED_160] {
            match decode_response_for_request(
                &hex::decode(fixture).unwrap(),
                &RpcRequest::GetPathTable { max_hops: None },
            )
            .unwrap()
            {
                RpcResponse::PathTable(entries) => {
                    assert_eq!(entries[0].interface, "TCPInterface[test]");
                    assert_eq!(
                        (&entries[0].interface_hash, entries[0].state),
                        (&None, None)
                    );
                }
                other => panic!("wrong variant: {other:?}"),
            }
        }
    }

    #[test]
    fn stamped_path_table_response_carries_value_used_and_lr_cost() {
        let entry = PathTableEntry {
            hash: vec![0xAA; 16],
            timestamp: 1234567890.0,
            via: Some(vec![0xBB; 16]),
            hops: 3,
            expires: 1235172690.0,
            value: Some(6.078125),
            used: Some(1234567999.5),
            lr_cost: Some(3.25),
            interface: "TCPInterface[test]".to_string(),
            interface_hash: Some(rns_crypto::sha::sha256(b"TCPInterface[test]").to_vec()),
            state: Some(2),
        };
        let resp = RpcResponse::PathTable(vec![entry]);
        assert_eq!(
            hex::encode(encode_response(&resp).unwrap()),
            FX_RESP_PATH_TABLE_STAMPED
        );
        match decode_response_for_request(
            &hex::decode(FX_RESP_PATH_TABLE_STAMPED).unwrap(),
            &RpcRequest::GetPathTable { max_hops: None },
        )
        .unwrap()
        {
            RpcResponse::PathTable(entries) => {
                assert_eq!(entries[0].value, Some(6.078125));
                assert_eq!(entries[0].used, Some(1234567999.5));
                assert_eq!(entries[0].lr_cost, Some(3.25));
                assert_eq!(entries[0].state, Some(2));
                assert_eq!(
                    entries[0].interface_hash.as_deref(),
                    Some(&rns_crypto::sha::sha256(b"TCPInterface[test]")[..])
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn mutation_replies_keep_upstream_true_false_none() {
        let decode = |hex_reply: &str, request: RpcRequest| {
            decode_response_for_request(&hex::decode(hex_reply).unwrap(), &request).unwrap()
        };
        let drop = || RpcRequest::DropPath {
            destination_hash: vec![0; 16],
        };
        let blackhole = || RpcRequest::BlackholeIdentity {
            identity_hash: vec![0; 16],
            until: None,
            reason: None,
        };
        let unblackhole = || RpcRequest::UnblackholeIdentity {
            identity_hash: vec![0; 16],
        };
        assert!(matches!(
            decode("c3", drop()),
            RpcResponse::BoolResult(true)
        ));
        assert!(matches!(
            decode("c2", drop()),
            RpcResponse::BoolResult(false)
        ));
        assert!(matches!(
            decode("c3", blackhole()),
            RpcResponse::OptBoolResult(Some(true))
        ));
        assert!(matches!(
            decode("c0", blackhole()),
            RpcResponse::OptBoolResult(None)
        ));
        assert!(matches!(
            decode("c0", unblackhole()),
            RpcResponse::OptBoolResult(None)
        ));
        assert_eq!(
            hex::encode(encode_response(&RpcResponse::OptBoolResult(None)).unwrap()),
            "c0"
        );
        assert_eq!(
            hex::encode(encode_response(&RpcResponse::BoolResult(false)).unwrap()),
            "c2"
        );
    }

    #[test]
    fn blackhole_dict_response_is_byte_exact_with_python_138_umsgpack() {
        let resp = RpcResponse::BlackholeList(vec![BlackholeEntry {
            identity_hash: vec![0x42; 16],
            source: Some(vec![0xAA; 16]),
            until: Some(1234.0),
            reason: Some("parity".to_string()),
        }]);
        assert_eq!(
            hex::encode(encode_response(&resp).unwrap()),
            FX_RESP_BLACKHOLE_DICT
        );
        match decode_response_for_request(
            &hex::decode(FX_RESP_BLACKHOLE_DICT).unwrap(),
            &RpcRequest::GetBlackholedIdentities,
        )
        .unwrap()
        {
            RpcResponse::BlackholeList(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].identity_hash, vec![0x42; 16]);
                assert_eq!(entries[0].until, Some(1234.0));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn integer_width_boundaries_match_umsgpack() {
        let edges: Vec<i128> = vec![
            0,
            127,
            128,
            255,
            256,
            65535,
            65536,
            4294967295,
            4294967296,
            18446744073709551615,
            -1,
            -32,
            -33,
            -128,
            -129,
            -32768,
            -32769,
            -2147483648,
            -2147483649,
            -9223372036854775808,
        ];
        let value = PyValue::List(edges.into_iter().map(PyValue::Int).collect());
        assert_fixture(&value, FX_INT_EDGES);
    }

    #[test]
    fn string_and_array_length_boundaries_match_umsgpack() {
        let value = PyValue::List(vec![
            PyValue::String(String::new()),
            PyValue::String("a".repeat(31)),
            PyValue::String("a".repeat(32)),
        ]);
        assert_fixture(&value, FX_STR_EDGES);

        let value = PyValue::List((0..16).map(PyValue::Int).collect());
        assert_fixture(&value, FX_ARRAY_16);

        // bin8 → bin16 boundary (c4 ff / c5 0100), matching umsgpack _pack_binary.
        let mut expected = String::from("93c400c4ff");
        expected.push_str(&"01".repeat(255));
        expected.push_str("c50100");
        expected.push_str(&"02".repeat(256));
        let value = PyValue::List(vec![
            PyValue::Bytes(Vec::new()),
            PyValue::Bytes(vec![0x01; 255]),
            PyValue::Bytes(vec![0x02; 256]),
        ]);
        assert_fixture(&value, &expected);
    }

    #[test]
    fn huge_ints_are_rejected_like_umsgpack() {
        assert!(encode_umsgpack(&PyValue::Int(i128::from(u64::MAX) + 1)).is_err());
        assert!(encode_umsgpack(&PyValue::Int(i128::from(i64::MIN) - 1)).is_err());
        // Boundary values still encode.
        assert!(encode_umsgpack(&PyValue::Int(i128::from(u64::MAX))).is_ok());
        assert!(encode_umsgpack(&PyValue::Int(i128::from(i64::MIN))).is_ok());
    }

    #[test]
    fn pickle_frames_no_longer_decode() {
        // Python <=1.3.3 pickle frame for {"get": "link_count"} — the hard
        // cutover (a2ef9782) must reject it rather than fall back.
        let pickle = [
            0x80u8, 0x04, b'}', b'(', 0x8c, 0x03, b'g', b'e', b't', 0x8c, 0x0a, b'l', b'i', b'n',
            b'k', b'_', b'c', b'o', b'u', b'n', b't', b'u', b'.',
        ];
        assert!(decode_request(&pickle).is_err());
    }

    #[test]
    fn msgpack_depth_limit_rejects_hostile_nesting() {
        // 200 nested single-element arrays around a nil.
        let mut data = vec![0x91u8; 200];
        data.push(0xc0);
        assert!(decode_umsgpack(&data).is_err());
    }

    /// Requests upstream RNS 1.6.0 clients send.
    const UPSTREAM_1_6_REQUESTS: &[(&str, &str)] = &[
        (
            "lowest_interface_bitrate",
            "81a3676574b86c6f776573745f696e746572666163655f62697472617465",
        ),
        (
            "medium_path_timeout",
            "81a3676574b36d656469756d5f706174685f74696d656f7574",
        ),
        (
            "active_link_count",
            "81a3676574b16163746976655f6c696e6b5f636f756e74",
        ),
        (
            "link_distribution",
            "81a3676574b16c696e6b5f646973747269627574696f6e",
        ),
        (
            "profiling_results",
            "81a3676574b170726f66696c696e675f726573756c7473",
        ),
        (
            "attach_interface",
            "82a66d616e616765b06174746163685f696e74657266616365a46e616d65ac44697361626c656420544350",
        ),
        (
            "detach_interface",
            "82a66d616e616765b06465746163685f696e74657266616365a46e616d65ac44697361626c656420544350",
        ),
        (
            "reload_interface",
            "82a66d616e616765b072656c6f61645f696e74657266616365a46e616d65ac44697361626c656420544350",
        ),
        (
            "wants_destination_type",
            "83b677616e74735f64657374696e6174696f6e5f74797065ad6c786d662e64656c6976657279a9726571756573746572c41000112233445566778899aabbccddeeffa97369676e6174757265c0",
        ),
        (
            "unwants_destination_type",
            "83b8756e77616e74735f64657374696e6174696f6e5f74797065ad6c786d662e64656c6976657279a9726571756573746572c41000112233445566778899aabbccddeeffa97369676e6174757265c0",
        ),
        (
            "unwants_all_destination_types",
            "83bd756e77616e74735f616c6c5f64657374696e6174696f6e5f7479706573c3a9726571756573746572c41000112233445566778899aabbccddeeffa97369676e6174757265c0",
        ),
    ];

    fn upstream_request(name: &str) -> Vec<u8> {
        let (_, hex) = UPSTREAM_1_6_REQUESTS
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap();
        hex::decode(hex).unwrap()
    }

    #[test]
    fn upstream_1_6_requests_decode_and_reencode_byte_identically() {
        for (name, hex) in UPSTREAM_1_6_REQUESTS {
            let bytes = hex::decode(hex).unwrap();
            let request =
                decode_request(&bytes).unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"));
            assert_eq!(
                hex::encode(encode_request(&request).unwrap()),
                *hex,
                "{name}: re-encoded bytes differ from upstream"
            );
        }
    }

    #[test]
    fn upstream_1_6_requests_decode_to_their_operations() {
        assert!(matches!(
            decode_request(&upstream_request("lowest_interface_bitrate")).unwrap(),
            RpcRequest::GetLowestInterfaceBitrate
        ));
        assert!(matches!(
            decode_request(&upstream_request("medium_path_timeout")).unwrap(),
            RpcRequest::GetMediumPathTimeout
        ));
        assert!(matches!(
            decode_request(&upstream_request("active_link_count")).unwrap(),
            RpcRequest::GetActiveLinkCount
        ));
        assert!(matches!(
            decode_request(&upstream_request("link_distribution")).unwrap(),
            RpcRequest::GetLinkDistribution
        ));
        assert!(matches!(
            decode_request(&upstream_request("profiling_results")).unwrap(),
            RpcRequest::GetProfilingResults
        ));
        for (name, op) in [
            ("attach_interface", ManageOperation::Attach),
            ("detach_interface", ManageOperation::Detach),
            ("reload_interface", ManageOperation::Reload),
        ] {
            match decode_request(&upstream_request(name)).unwrap() {
                RpcRequest::ManageInterface { operation, name } => {
                    assert_eq!(operation, op);
                    assert_eq!(name, "Disabled TCP");
                }
                other => panic!("{name}: decoded as {other:?}"),
            }
        }
        let requester = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        match decode_request(&upstream_request("wants_destination_type")).unwrap() {
            RpcRequest::WantsDestinationType {
                full_name,
                requester: r,
                signature,
            } => {
                assert_eq!(full_name, "lxmf.delivery");
                assert_eq!(r, requester);
                assert_eq!(signature, None);
            }
            other => panic!("decoded as {other:?}"),
        }
        assert!(matches!(
            decode_request(&upstream_request("unwants_destination_type")).unwrap(),
            RpcRequest::UnwantsDestinationType { full_name, .. } if full_name == "lxmf.delivery"
        ));
        assert!(matches!(
            decode_request(&upstream_request("unwants_all_destination_types")).unwrap(),
            RpcRequest::UnwantsAllDestinationTypes { requester: r, .. } if r == requester
        ));
    }

    #[test]
    fn destination_type_request_without_requester_or_signature_is_rejected() {
        // Python's rpc_loop indexes both keys and drops the call without them.
        let no_signature = py_dict(vec![
            ("wants_destination_type", PyValue::String("a.b".to_string())),
            ("requester", PyValue::Bytes(vec![1; 16])),
        ]);
        assert!(decode_request(&encode_umsgpack(&no_signature).unwrap()).is_err());
        let no_requester = py_dict(vec![
            ("unwants_all_destination_types", PyValue::Bool(true)),
            ("signature", PyValue::None),
        ]);
        assert!(decode_request(&encode_umsgpack(&no_requester).unwrap()).is_err());
    }

    #[test]
    fn unknown_manage_operation_is_rejected() {
        let request = py_dict(vec![
            ("manage", PyValue::String("restart_interface".to_string())),
            ("name", PyValue::String("x".to_string())),
        ]);
        assert!(decode_request(&encode_umsgpack(&request).unwrap()).is_err());
    }

    /// Replies upstream 1.6.0 packs, from the same generator.
    #[test]
    fn new_replies_encode_as_upstream_packs_them() {
        assert_eq!(hex::encode(encode_optional_int(None).unwrap()), "c0");
        assert_eq!(
            hex::encode(encode_optional_int(Some(500)).unwrap()),
            "cd01f4"
        );
        assert_eq!(
            hex::encode(encode_optional_int(Some(1200)).unwrap()),
            "cd04b0"
        );
        assert_eq!(hex::encode(encode_optional_int(Some(3)).unwrap()), "03");
        assert_eq!(hex::encode(encode_medium_path_timeout(None).unwrap()), "00");
        assert_eq!(
            hex::encode(encode_medium_path_timeout(Some(22.0)).unwrap()),
            "cb4036000000000000"
        );
        assert_eq!(
            hex::encode(encode_response(&RpcResponse::LinkDistribution(Vec::new())).unwrap()),
            "80"
        );
        assert_eq!(hex::encode(encode_none().unwrap()), "c0");
        assert_eq!(hex::encode(encode_optional_bool(Some(true)).unwrap()), "c3");
        assert_eq!(
            hex::encode(encode_optional_bool(Some(false)).unwrap()),
            "c2"
        );
        assert_eq!(hex::encode(encode_optional_bool(None).unwrap()), "c0");
    }

    #[test]
    fn new_replies_decode_for_their_requests() {
        let decode = |hex: &str, request: RpcRequest| {
            decode_response_for_request(&hex::decode(hex).unwrap(), &request).unwrap()
        };
        assert!(matches!(
            decode("cd01f4", RpcRequest::GetLowestInterfaceBitrate),
            RpcResponse::IntResult(500)
        ));
        assert!(matches!(
            decode("c0", RpcRequest::GetLowestInterfaceBitrate),
            RpcResponse::StringResult(None)
        ));
        assert!(matches!(
            decode("cb4036000000000000", RpcRequest::GetMediumPathTimeout),
            RpcResponse::FloatResult(Some(v)) if v == 22.0
        ));
        assert!(matches!(
            decode("00", RpcRequest::GetMediumPathTimeout),
            RpcResponse::FloatResult(Some(v)) if v == 0.0
        ));
        assert!(matches!(
            decode("01", RpcRequest::GetActiveLinkCount),
            RpcResponse::IntResult(1)
        ));
        assert!(matches!(
            decode("80", RpcRequest::GetLinkDistribution),
            RpcResponse::LinkDistribution(ref e) if e.is_empty()
        ));
        assert!(matches!(
            decode("c0", RpcRequest::GetProfilingResults),
            RpcResponse::StringResult(None)
        ));
        let manage = || RpcRequest::ManageInterface {
            operation: ManageOperation::Attach,
            name: "x".to_string(),
        };
        assert!(matches!(
            decode("c3", manage()),
            RpcResponse::BoolResult(true)
        ));
        assert!(matches!(
            decode("c2", manage()),
            RpcResponse::BoolResult(false)
        ));
        assert!(matches!(
            decode("c0", manage()),
            RpcResponse::StringResult(None)
        ));
        let wants = RpcRequest::UnwantsAllDestinationTypes {
            requester: vec![0; 16],
            signature: None,
        };
        assert!(matches!(decode("c3", wants), RpcResponse::BoolResult(true)));
    }
}
