//! AutoInterface: zero-configuration peering over IPv6 link-local multicast,
//! ported from `RNS/Interfaces/AutoInterface.py`.
//!
//! Every adopted NIC gets a multicast discovery socket, a unicast discovery
//! socket and a data socket bound to its link-local address. Each discovered
//! peer is spawned as its own `AutoInterfacePeer[<ifname>/<addr>]` child
//! interface that sends only to that peer; the parent interface itself never
//! transmits.

mod netif;
mod peers;

pub use netif::{NetworkInterfaceInfo, list_network_interfaces};

use std::collections::{HashMap, HashSet};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use bytes::Bytes;
use rns_transport::messages::{
    InboundPacket, InterfacePacketCapacity, InterfaceTransportSender, TransportMessage,
};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use crate::traits::{InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode};
use peers::{ChildLink, Core, Discovered};

pub const DISCOVERY_PORT: u16 = 29716;
pub const DATA_PORT: u16 = 42671;
pub const BEACON_INTERVAL: f64 = 1.6;
/// Background beacon interval with feature `mobile-throttle`, in seconds.
pub const BEACON_INTERVAL_BG: f64 = 8.0;
pub const PEERING_TIMEOUT: f64 = 22.0;
pub const PEER_EXPIRY: f64 = PEERING_TIMEOUT;
pub const HW_MTU: u32 = 1196;
pub const FIXED_MTU: bool = true;
pub const DEFAULT_GROUP_ID: &str = "reticulum";
pub const UNICAST_DISCOVERY_PORT: u16 = DISCOVERY_PORT + 1;
pub const REVERSE_PEERING_INTERVAL: f64 = BEACON_INTERVAL * 3.25;
pub const PEER_JOB_INTERVAL: f64 = 4.0;
pub const MCAST_ECHO_TIMEOUT: f64 = 6.5;
pub const MULTI_IF_DEQUE_LEN: usize = 48;
pub const MULTI_IF_DEQUE_TTL: f64 = 0.75;
pub const BITRATE_GUESS: u64 = 10_000_000;
/// Peering wait before the interface goes online (`final_init`).
pub const PEERING_WAIT: f64 = BEACON_INTERVAL * 1.2;

pub const ALL_IGNORE_IFS: &[&str] = &["lo0"];
pub const DARWIN_IGNORE_IFS: &[&str] = &["awdl0", "llw0", "lo0", "en5"];
pub const ANDROID_IGNORE_IFS: &[&str] = &[
    "dummy0", "lo", "tun0", "rmnet0", "rmnet1", "rmnet2", "rmnet3", "rmnet4", "rmnet5", "rmnet6",
    "rmnet7",
];

/// `Interface.bitrate` default, kept when no NIC could be adopted.
const UNCONFIGURED_BITRATE: u64 = 62_500;
const DATA_BUFFER: usize = 8192;
const DISCOVERY_BUFFER: usize = 1024;

/// The platform classes AutoInterface treats differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoPlatform {
    Darwin,
    Android,
    Other,
}

impl AutoPlatform {
    pub const CURRENT: Self = if cfg!(target_os = "android") {
        Self::Android
    } else if cfg!(any(target_os = "macos", target_os = "ios")) {
        Self::Darwin
    } else {
        Self::Other
    };
}

/// Whether a system interface is considered for adoption, given the
/// `devices` allow-list and `ignored_devices`.
pub fn interface_selectable(
    platform: AutoPlatform,
    ifname: &str,
    devices: Option<&[String]>,
    ignored_devices: &[String],
) -> bool {
    let allowed = devices.unwrap_or(&[]);
    let explicitly_allowed = allowed.iter().any(|d| d == ifname);
    if platform == AutoPlatform::Darwin
        && DARWIN_IGNORE_IFS.contains(&ifname)
        && !explicitly_allowed
    {
        return false;
    }
    if platform == AutoPlatform::Darwin && ifname == "lo0" {
        return false;
    }
    if platform == AutoPlatform::Android
        && ANDROID_IGNORE_IFS.contains(&ifname)
        && !explicitly_allowed
    {
        return false;
    }
    if ignored_devices.iter().any(|d| d == ifname) || ALL_IGNORE_IFS.contains(&ifname) {
        return false;
    }
    allowed.is_empty() || explicitly_allowed
}

/// Seconds without a beacon or data before a peer is removed.
pub fn peering_timeout(platform: AutoPlatform) -> f64 {
    if platform == AutoPlatform::Android {
        // Low-power modes on many Android chipsets delay beacons.
        PEER_EXPIRY * 1.25
    } else {
        PEERING_TIMEOUT
    }
}

/// IPv6 multicast scope (RFC 4291 §2.7), the low nibble of the `ffTS:` byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryScope {
    Link,
    Admin,
    Site,
    Organisation,
    Global,
}

impl DiscoveryScope {
    pub const fn as_hex_nibble(self) -> u8 {
        match self {
            Self::Link => 0x2,
            Self::Admin => 0x4,
            Self::Site => 0x5,
            Self::Organisation => 0x8,
            Self::Global => 0xe,
        }
    }
}

impl std::str::FromStr for DiscoveryScope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "link" => Ok(Self::Link),
            "admin" => Ok(Self::Admin),
            "site" => Ok(Self::Site),
            "organisation" => Ok(Self::Organisation),
            "global" => Ok(Self::Global),
            _ => Err(format!("unknown discovery scope: {s}")),
        }
    }
}

impl std::fmt::Display for DiscoveryScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Link => "link",
            Self::Admin => "admin",
            Self::Site => "site",
            Self::Organisation => "organisation",
            Self::Global => "global",
        })
    }
}

/// IPv6 multicast transient/permanent flag (RFC 4291 §2.7), the high nibble
/// of the `ffTS:` byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McastAddrType {
    Temporary,
    Permanent,
}

impl McastAddrType {
    pub const fn as_hex_nibble(self) -> u8 {
        match self {
            Self::Temporary => 0x1,
            Self::Permanent => 0x0,
        }
    }

    /// `permanent` (any case) selects Permanent; every other value Temporary.
    pub fn parse(value: &str) -> Self {
        if value.to_lowercase() == "permanent" {
            Self::Permanent
        } else {
            Self::Temporary
        }
    }
}

impl std::str::FromStr for McastAddrType {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

impl std::fmt::Display for McastAddrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Temporary => "temporary",
            Self::Permanent => "permanent",
        })
    }
}

/// Async events from AutoInterface instances for embedding applications.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AutoInterfaceEvent {
    /// `IPV6_JOIN_GROUP` was rejected by the OS. `reason` contains the reported
    /// error; this event alone does not establish a permission or network cause.
    JoinFailed {
        interface_name: String,
        ifname: String,
        reason: String,
    },
    /// The multicast echo state of `ifname` changed. `ok=false` means none of
    /// our own beacons came back within `MCAST_ECHO_TIMEOUT`.
    CarrierState {
        interface_name: String,
        ifname: String,
        ok: bool,
        reason: String,
    },
}

static AUTO_EVENT_TX: OnceLock<broadcast::Sender<AutoInterfaceEvent>> = OnceLock::new();

/// Subscribe to `AutoInterfaceEvent`s emitted by any AutoInterface in this
/// process. Channel is lazy-created; lagged subscribers see `RecvError::Lagged`.
pub fn subscribe_auto_events() -> broadcast::Receiver<AutoInterfaceEvent> {
    AUTO_EVENT_TX
        .get_or_init(|| {
            let (tx, _rx) = broadcast::channel(64);
            tx
        })
        .subscribe()
}

fn dispatch_auto_event(event: AutoInterfaceEvent) {
    if let Some(tx) = AUTO_EVENT_TX.get() {
        let _ = tx.send(event);
    }
}

#[derive(Debug, Clone)]
pub struct AutoInterfaceConfig {
    pub name: String,
    pub group_id: String,
    pub discovery_scope: DiscoveryScope,
    pub discovery_port: u16,
    pub data_port: u16,
    pub multicast_address_type: McastAddrType,
    /// Allow-list of NIC names; `None` or empty allows every NIC.
    pub devices: Option<Vec<String>>,
    /// NIC names never adopted.
    pub ignored_devices: Vec<String>,
    /// Reticulum's `configured_bitrate` (a `bitrate` of at least
    /// `MINIMUM_BITRATE`); `None` uses `BITRATE_GUESS`.
    pub configured_bitrate: Option<u64>,
    pub mode: InterfaceMode,
}

impl Default for AutoInterfaceConfig {
    fn default() -> Self {
        Self {
            name: "AutoInterface".to_string(),
            group_id: DEFAULT_GROUP_ID.to_string(),
            discovery_scope: DiscoveryScope::Link,
            discovery_port: DISCOVERY_PORT,
            data_port: DATA_PORT,
            multicast_address_type: McastAddrType::Temporary,
            devices: None,
            ignored_devices: Vec::new(),
            configured_bitrate: None,
            mode: InterfaceMode::Full,
        }
    }
}

#[derive(Debug, Clone)]
struct DeduplicateEntry {
    hash: [u8; 32],
    timestamp: Instant,
}

/// Dedupes packets seen on multiple NICs at once (e.g. WLAN + wired).
#[derive(Debug, Clone)]
pub struct MultiIfDedup {
    deque: std::collections::VecDeque<DeduplicateEntry>,
    max_len: usize,
    ttl_secs: f64,
}

impl MultiIfDedup {
    pub fn new() -> Self {
        Self {
            deque: std::collections::VecDeque::with_capacity(MULTI_IF_DEQUE_LEN),
            max_len: MULTI_IF_DEQUE_LEN,
            ttl_secs: MULTI_IF_DEQUE_TTL,
        }
    }

    /// Return whether this packet hash is still in the bounded TTL cache. New
    /// hashes are recorded; a duplicate does not refresh its timestamp.
    pub fn is_duplicate(&mut self, data: &[u8]) -> bool {
        let hash = rns_crypto::sha::sha256(data);
        let now = Instant::now();

        while let Some(front) = self.deque.front() {
            if now.duration_since(front.timestamp).as_secs_f64() > self.ttl_secs {
                self.deque.pop_front();
            } else {
                break;
            }
        }

        if self.deque.iter().any(|entry| entry.hash == hash) {
            return true;
        }

        if self.deque.len() >= self.max_len {
            self.deque.pop_front();
        }
        self.deque.push_back(DeduplicateEntry {
            hash,
            timestamp: now,
        });

        false
    }
}

impl Default for MultiIfDedup {
    fn default() -> Self {
        Self::new()
    }
}

/// `SHA-256(group_id || address string)`: the discovery token a node with
/// link-local address `addr` sends.
pub fn discovery_token(group_id: &str, addr: &Ipv6Addr) -> [u8; 32] {
    let mut input = group_id.as_bytes().to_vec();
    input.extend_from_slice(addr.to_string().as_bytes());
    rns_crypto::sha::sha256(&input)
}

/// Compare the first 32 bytes of a discovery packet with the token expected
/// from `peer_addr`. Shorter packets fail; trailing bytes are ignored.
pub fn verify_beacon(beacon: &[u8], group_id: &str, peer_addr: &Ipv6Addr) -> bool {
    beacon.len() >= 32 && beacon[..32] == discovery_token(group_id, peer_addr)
}

/// The name of the child interface spawned for a peer.
pub fn peer_interface_name(ifname: &str, addr: &Ipv6Addr) -> String {
    format!("AutoInterfacePeer[{ifname}/{addr}]")
}

/// Derive `ffTS:0:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX` from the address-type nibble,
/// the scope nibble and bytes 2..14 of `SHA-256(group_id)`.
pub fn derive_multicast_address(
    group_id: &str,
    scope: DiscoveryScope,
    addr_type: McastAddrType,
) -> Ipv6Addr {
    let hash = rns_crypto::sha::sha256(group_id.as_bytes());
    let high =
        0xff00u16 | ((addr_type.as_hex_nibble() as u16) << 4) | (scope.as_hex_nibble() as u16);
    Ipv6Addr::new(
        high,
        0,
        u16::from_be_bytes([hash[2], hash[3]]),
        u16::from_be_bytes([hash[4], hash[5]]),
        u16::from_be_bytes([hash[6], hash[7]]),
        u16::from_be_bytes([hash[8], hash[9]]),
        u16::from_be_bytes([hash[10], hash[11]]),
        u16::from_be_bytes([hash[12], hash[13]]),
    )
}

/// `Link` scope + `Temporary` address type (Python's defaults).
pub fn multicast_group_for(group_id: &str) -> Ipv6Addr {
    derive_multicast_address(group_id, DiscoveryScope::Link, McastAddrType::Temporary)
}

/// One NIC as enumerated: the address it is adopted with (the last
/// link-local listed, as upstream selects) and all of its link-locals.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NicAddrs {
    ifname: String,
    link_local: Ipv6Addr,
    all: Vec<Ipv6Addr>,
    scope_id: u32,
}

fn group_link_locals(addrs: Vec<(String, Ipv6Addr, u32)>) -> Vec<NicAddrs> {
    let mut nics: Vec<NicAddrs> = Vec::new();
    for (ifname, addr, scope_id) in addrs {
        match nics.iter_mut().find(|n| n.ifname == ifname) {
            Some(nic) => {
                nic.link_local = addr;
                nic.all.push(addr);
            }
            None => nics.push(NicAddrs {
                ifname,
                link_local: addr,
                all: vec![addr],
                scope_id,
            }),
        }
    }
    nics
}

enum NicError {
    Discovery(std::io::Error),
    Data(std::io::Error),
}

/// Sockets and tasks of one adopted NIC; dropping it closes them.
struct NicHandle {
    link_local: Ipv6Addr,
    scope_id: u32,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for NicHandle {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn udp_socket_v6(reuse: bool) -> std::io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    if reuse {
        sock.set_reuse_address(true)?;
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
    }
    sock.set_only_v6(true)?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

fn into_tokio(sock: socket2::Socket) -> std::io::Result<UdpSocket> {
    UdpSocket::from_std(sock.into())
}

fn bind_udp(addr: SocketAddrV6, reuse: bool) -> std::io::Result<UdpSocket> {
    let sock = udp_socket_v6(reuse)?;
    sock.bind(&SocketAddr::V6(addr).into())?;
    into_tokio(sock)
}

/// Windows rejects binding to a link-local or multicast address, so upstream
/// binds the discovery sockets to the unspecified address there.
fn discovery_bind_addr(addr: Ipv6Addr, port: u16, scope_id: u32) -> SocketAddrV6 {
    if cfg!(windows) {
        SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)
    } else {
        SocketAddrV6::new(addr, port, 0, scope_id)
    }
}

struct Shared {
    id: InterfaceId,
    name: String,
    mode: InterfaceMode,
    group_id: String,
    mcast_group: Ipv6Addr,
    discovery_scope: DiscoveryScope,
    discovery_port: u16,
    unicast_discovery_port: u16,
    data_port: u16,
    devices: Option<Vec<String>>,
    ignored_devices: Vec<String>,
    peering_timeout: f64,
    bitrate: AtomicU64,
    online: Arc<AtomicBool>,
    final_init_done: AtomicBool,
    rxb: Arc<AtomicU64>,
    txb: Arc<AtomicU64>,
    core: Mutex<Core>,
    nics: Mutex<HashMap<String, NicHandle>>,
    failed_nics: Mutex<HashSet<String>>,
    id_gen: Arc<AtomicU64>,
    parent: InterfaceTransportSender,
    actor_tx: mpsc::Sender<TransportMessage>,
    handle_tx: mpsc::Sender<InterfaceHandle>,
    outbound: Arc<UdpSocket>,
    is_foreground: Arc<AtomicBool>,
}

impl std::fmt::Display for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AutoInterface[{}]", self.name)
    }
}

impl Shared {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: AutoInterfaceConfig,
        id: InterfaceId,
        id_gen: Arc<AtomicU64>,
        actor_tx: mpsc::Sender<TransportMessage>,
        handle_tx: mpsc::Sender<InterfaceHandle>,
        is_foreground: Arc<AtomicBool>,
        outbound: UdpSocket,
    ) -> Self {
        Self {
            id,
            mcast_group: derive_multicast_address(
                &config.group_id,
                config.discovery_scope,
                config.multicast_address_type,
            ),
            name: config.name,
            mode: config.mode,
            group_id: config.group_id,
            discovery_scope: config.discovery_scope,
            discovery_port: config.discovery_port,
            unicast_discovery_port: config.discovery_port.wrapping_add(1),
            data_port: config.data_port,
            devices: config.devices,
            ignored_devices: config.ignored_devices,
            peering_timeout: peering_timeout(AutoPlatform::CURRENT),
            bitrate: AtomicU64::new(UNCONFIGURED_BITRATE),
            online: Arc::new(AtomicBool::new(false)),
            final_init_done: AtomicBool::new(false),
            rxb: Arc::new(AtomicU64::new(0)),
            txb: Arc::new(AtomicU64::new(0)),
            core: Mutex::new(Core::default()),
            nics: Mutex::new(HashMap::new()),
            failed_nics: Mutex::new(HashSet::new()),
            id_gen,
            parent: InterfaceTransportSender::new(id, actor_tx.clone()),
            actor_tx,
            handle_tx,
            outbound: Arc::new(outbound),
            is_foreground,
        }
    }

    fn core(&self) -> std::sync::MutexGuard<'_, Core> {
        self.core.lock().expect("auto core mutex poisoned")
    }

    fn enumerate(&self) -> Vec<NicAddrs> {
        group_link_locals(netif::get_link_local_addrs(
            self.devices.as_deref(),
            &self.ignored_devices,
        ))
    }

    fn running(&self) -> bool {
        self.online.load(Ordering::SeqCst) && self.final_init_done.load(Ordering::SeqCst)
    }

    /// Open the discovery and data sockets of one NIC, adopt it and start its
    /// tasks (AutoInterface.py:253-312, :337-347).
    fn start_nic(self: &Arc<Self>, nic: &NicAddrs) -> Result<NicHandle, NicError> {
        let (unicast, mcast, beacon) = self.discovery_sockets(nic).map_err(NicError::Discovery)?;
        let scope = nic.scope_id;
        // A data listener that cannot bind is fatal in upstream's final_init.
        let data = bind_udp(
            SocketAddrV6::new(nic.link_local, self.data_port, 0, scope),
            false,
        )
        .map_err(|e| {
            NicError::Data(std::io::Error::new(
                e.kind(),
                format!(
                    "data socket bind ({}%{}:{}): {e}",
                    nic.link_local, nic.ifname, self.data_port
                ),
            ))
        })?;

        self.core()
            .adopt(&nic.ifname, nic.link_local, &nic.all, Instant::now());
        tracing::debug!(
            iface = %self,
            nic = %nic.ifname,
            link_local = %nic.link_local,
            group = %self.mcast_group,
            "adopted system interface"
        );

        let tasks = vec![
            tokio::spawn(self.clone().beacon_loop(beacon, nic.link_local, scope)),
            tokio::spawn(
                self.clone()
                    .discovery_loop(mcast, nic.ifname.clone(), scope),
            ),
            tokio::spawn(
                self.clone()
                    .discovery_loop(unicast, nic.ifname.clone(), scope),
            ),
            tokio::spawn(self.clone().data_loop(data)),
        ];
        Ok(NicHandle {
            link_local: nic.link_local,
            scope_id: scope,
            tasks,
        })
    }

    /// Unicast discovery, multicast discovery and beacon sockets of one NIC.
    fn discovery_sockets(
        &self,
        nic: &NicAddrs,
    ) -> std::io::Result<(UdpSocket, UdpSocket, UdpSocket)> {
        let scope = nic.scope_id;
        let unicast = bind_udp(
            discovery_bind_addr(nic.link_local, self.unicast_discovery_port, scope),
            true,
        )?;

        let mcast = udp_socket_v6(true)?;
        mcast.set_multicast_if_v6(scope)?;
        mcast.join_multicast_v6(&self.mcast_group, scope)?;
        let mcast_scope = if self.discovery_scope == DiscoveryScope::Link {
            scope
        } else {
            0
        };
        mcast.bind(
            &SocketAddr::V6(discovery_bind_addr(
                self.mcast_group,
                self.discovery_port,
                mcast_scope,
            ))
            .into(),
        )?;
        let mcast = into_tokio(mcast)?;

        let beacon = udp_socket_v6(false)?;
        beacon.set_multicast_if_v6(scope)?;
        beacon.bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)).into())?;
        Ok((unicast, mcast, into_tokio(beacon)?))
    }

    /// `Ok(false)`: the NIC's discovery sockets failed and it was skipped.
    /// `Err`: its data listener could not bind.
    fn adopt_nic(self: &Arc<Self>, nic: &NicAddrs) -> std::io::Result<bool> {
        match self.start_nic(nic) {
            Ok(handle) => {
                self.failed_nics
                    .lock()
                    .expect("auto failed-nic mutex poisoned")
                    .remove(&nic.ifname);
                self.nics
                    .lock()
                    .expect("auto nic mutex poisoned")
                    .insert(nic.ifname.clone(), handle);
                Ok(true)
            }
            Err(NicError::Data(e)) => {
                self.core().release(&nic.ifname);
                Err(e)
            }
            Err(NicError::Discovery(e)) => {
                self.core().release(&nic.ifname);
                let first = self
                    .failed_nics
                    .lock()
                    .expect("auto failed-nic mutex poisoned")
                    .insert(nic.ifname.clone());
                if first {
                    tracing::error!(
                        "Could not configure the system interface {} for use with {}, skipping it. The contained exception was: {}",
                        nic.ifname,
                        self,
                        e
                    );
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        dispatch_auto_event(AutoInterfaceEvent::JoinFailed {
                            interface_name: self.name.clone(),
                            ifname: nic.ifname.clone(),
                            reason: format!("os_permission_denied: {e}"),
                        });
                    }
                }
                Ok(false)
            }
        }
    }

    fn beacon_interval(&self) -> f64 {
        #[cfg(feature = "mobile-throttle")]
        if !self.is_foreground.load(Ordering::Relaxed) {
            return BEACON_INTERVAL_BG;
        }
        let _ = &self.is_foreground;
        BEACON_INTERVAL
    }

    fn reverse_peering_interval(&self) -> f64 {
        self.beacon_interval() * 3.25
    }

    /// `announce_handler` / `peer_announce` (AutoInterface.py:485-520).
    async fn beacon_loop(self: Arc<Self>, sock: UdpSocket, link_local: Ipv6Addr, scope: u32) {
        let token = discovery_token(&self.group_id, &link_local);
        let dest = SocketAddrV6::new(self.mcast_group, self.discovery_port, 0, scope);
        loop {
            if let Err(e) = sock.send_to(&token, dest).await {
                tracing::warn!(
                    "{} Detected possible carrier loss on scope {}: {}",
                    self,
                    scope,
                    e
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs_f64(self.beacon_interval())).await;
        }
    }

    /// `discovery_handler` (AutoInterface.py:358-374).
    async fn discovery_loop(self: Arc<Self>, sock: UdpSocket, ifname: String, scope: u32) {
        let mut buf = [0u8; DISCOVERY_BUFFER];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, SocketAddr::V6(src))) => {
                    self.on_discovery(&buf[..n], *src.ip(), &ifname, scope)
                        .await;
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(iface = %self, nic = %ifname, error = %e, "discovery receive error");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn on_discovery(self: &Arc<Self>, data: &[u8], src: Ipv6Addr, ifname: &str, scope: u32) {
        if !self.final_init_done.load(Ordering::SeqCst) || data.is_empty() {
            return;
        }
        if !verify_beacon(data, &self.group_id, &src) {
            tracing::debug!(
                "{} received peering packet on {} from {}, but authentication hash was incorrect.",
                self,
                ifname,
                src
            );
            return;
        }
        // Children inherit the parent's registration (IFAC, ingress control).
        if !self.parent.ready().await {
            return;
        }
        self.add_peer(src, ifname, scope).await;
    }

    /// `add_peer` (AutoInterface.py:526-607).
    async fn add_peer(self: &Arc<Self>, addr: Ipv6Addr, ifname: &str, scope: u32) {
        let outcome = self.core().discovered(addr, ifname, scope, Instant::now());
        match outcome {
            Discovered::Echo(_) | Discovered::Refreshed => {}
            Discovered::UnexpectedEcho => {
                tracing::warn!(
                    "{} received multicast echo on unexpected interface {}",
                    self,
                    ifname
                );
            }
            Discovered::Added => {
                let (handle, link) = self.spawn_child(addr, ifname, scope);
                let child_id = link.id;
                if let Ok(Some(stale)) | Err(stale) = self.core().attach(addr, link) {
                    stale.online.store(false, Ordering::SeqCst);
                }
                if crate::traits::handoff_accepted_interface(&self.handle_tx, handle)
                    .await
                    .is_err()
                {
                    self.core().clear_child(addr, child_id);
                    return;
                }
                tracing::debug!("{} added peer {} on {}", self, addr, ifname);
            }
        }
    }

    /// An `AutoInterfacePeer` for one peer: it sends only to that peer and
    /// receives what the parent's data sockets accept from it.
    fn spawn_child(
        &self,
        addr: Ipv6Addr,
        ifname: &str,
        scope: u32,
    ) -> (InterfaceHandle, ChildLink) {
        let id = self.id_gen.fetch_add(1, Ordering::SeqCst);
        let sender = InterfaceTransportSender::new(id, self.actor_tx.clone());
        let owner = sender.owner();
        let online = Arc::new(AtomicBool::new(true));
        let rxb = Arc::new(AtomicU64::new(0));
        let txb = Arc::new(AtomicU64::new(0));
        let (tx, out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        let name = peer_interface_name(ifname, &addr);
        let read_task = tokio::spawn(child_task(ChildTask {
            id,
            name: name.clone(),
            sender,
            online: online.clone(),
            dest: SocketAddrV6::new(addr, self.data_port, 0, scope),
            outbound: self.outbound.clone(),
            txb: txb.clone(),
            parent_txb: self.txb.clone(),
            in_rx,
            out_rx,
        }));
        let handle = InterfaceHandle {
            id,
            owner,
            packet_capacity: InterfacePacketCapacity::new(HW_MTU, HW_MTU, FIXED_MTU),
            parent_id: Some(self.id),
            name,
            mode: self.mode,
            direction: InterfaceDirection {
                inbound: true,
                outbound: true,
                forward: false,
                repeat: false,
            },
            bitrate: self.bitrate.load(Ordering::SeqCst),
            mtu: HW_MTU,
            online: online.clone(),
            rxb: Some(rxb.clone()),
            txb: Some(txb),
            inspection: None,
            tx,
            read_task,
        };
        (
            handle,
            ChildLink {
                id,
                inbound: in_tx,
                online,
                rxb,
            },
        )
    }

    /// The data listener's `process_incoming` (AutoInterface.py:613-615).
    async fn data_loop(self: Arc<Self>, sock: UdpSocket) {
        let mut buf = vec![0u8; DATA_BUFFER];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, SocketAddr::V6(src))) if n > 0 => self.on_data(&buf[..n], *src.ip()),
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(iface = %self, error = %e, "data receive error");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn on_data(&self, data: &[u8], src: Ipv6Addr) {
        if !self.running() {
            return;
        }
        let Some(child) = self.core().inbound(src, data, Instant::now()) else {
            return;
        };
        self.rxb.fetch_add(data.len() as u64, Ordering::Relaxed);
        child.rxb.fetch_add(data.len() as u64, Ordering::Relaxed);
        if child
            .inbound
            .try_send(Bytes::copy_from_slice(data))
            .is_err()
        {
            tracing::debug!(iface = %self, peer = %src, "peer inbound queue full; dropping packet");
        }
    }

    /// `peer_jobs` (AutoInterface.py:376-483).
    async fn run_jobs(self: Arc<Self>) {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs_f64(PEER_JOB_INTERVAL)).await;
            if self.final_init_done.load(Ordering::SeqCst) && !self.online.load(Ordering::SeqCst) {
                break;
            }
            let now = Instant::now();
            self.expire_peers(now);
            self.reverse_peering(now).await;
            self.refresh_nics();
            self.check_echoes(now);
        }
    }

    fn expire_peers(&self, now: Instant) {
        let expired = self.core().expire(now, self.peering_timeout);
        for (addr, peer) in expired {
            if let Some(child) = peer.child {
                child.online.store(false, Ordering::SeqCst);
            }
            tracing::debug!("{} removed peer {} on {}", self, addr, peer.ifname);
        }
    }

    async fn reverse_peering(&self, now: Instant) {
        let due = self
            .core()
            .reverse_due(now, self.reverse_peering_interval());
        for (addr, ifname, scope) in due {
            let Some(link_local) = self.core().adopted(&ifname) else {
                continue;
            };
            let token = discovery_token(&self.group_id, &link_local);
            let dest = SocketAddrV6::new(addr, self.unicast_discovery_port, 0, scope);
            if let Err(e) = self.outbound.send_to(&token, dest).await {
                tracing::error!(
                    "Could not send reverse peering packet to {} on {}: {}",
                    addr,
                    ifname,
                    e
                );
            }
        }
    }

    /// Re-read the link-local addresses. A changed address restarts that
    /// NIC's sockets, as upstream restarts its data listener; NICs that
    /// appear or vanish after startup are adopted or released.
    fn refresh_nics(self: &Arc<Self>) {
        let current = self.enumerate();
        let mut restart = Vec::new();
        {
            let mut nics = self.nics.lock().expect("auto nic mutex poisoned");
            let mut released = Vec::new();
            for (ifname, handle) in nics.iter() {
                match current.iter().find(|n| &n.ifname == ifname) {
                    None => released.push(ifname.clone()),
                    Some(nic)
                        if nic.link_local != handle.link_local
                            || nic.scope_id != handle.scope_id =>
                    {
                        tracing::debug!(
                            "Replacing link-local address {} for {} with {}",
                            handle.link_local,
                            ifname,
                            nic.link_local
                        );
                        released.push(ifname.clone());
                        restart.push(nic.clone());
                    }
                    Some(_) => {}
                }
            }
            for ifname in released {
                nics.remove(&ifname);
                self.core().release(&ifname);
            }
            for nic in &current {
                if !nics.contains_key(&nic.ifname) && !restart.contains(nic) {
                    restart.push(nic.clone());
                }
            }
        }
        for nic in restart {
            if let Err(e) = self.adopt_nic(&nic) {
                tracing::warn!("Could not start new UDP listener for {}: {}", self, e);
            }
        }
    }

    fn check_echoes(&self, now: Instant) {
        let mut core = self.core();
        for ifname in core.adopted_ifnames() {
            let timed_out = core
                .last_echo(&ifname)
                .is_none_or(|t| now.duration_since(t).as_secs_f64() > MCAST_ECHO_TIMEOUT);
            let previous = core.set_timed_out(&ifname, timed_out);
            if timed_out && previous == Some(false) {
                tracing::warn!("Multicast echo timeout for {}. Carrier lost.", ifname);
            } else if !timed_out && previous == Some(true) {
                tracing::warn!("{} Carrier recovered on {}", self, ifname);
            }
            if previous != Some(timed_out) {
                dispatch_auto_event(AutoInterfaceEvent::CarrierState {
                    interface_name: self.name.clone(),
                    ifname: ifname.clone(),
                    ok: !timed_out,
                    reason: if timed_out {
                        format!("no multicast echo for more than {MCAST_ECHO_TIMEOUT}s")
                    } else {
                        "multicast echo within timeout".to_string()
                    },
                });
            }
            if !core.echo_received(&ifname) {
                tracing::error!(
                    "{} No multicast echoes received on {}. The networking hardware or a firewall may be blocking multicast traffic.",
                    self,
                    ifname
                );
            }
        }
    }
}

struct ChildTask {
    id: InterfaceId,
    name: String,
    sender: InterfaceTransportSender,
    online: Arc<AtomicBool>,
    dest: SocketAddrV6,
    outbound: Arc<UdpSocket>,
    txb: Arc<AtomicU64>,
    parent_txb: Arc<AtomicU64>,
    in_rx: mpsc::Receiver<Bytes>,
    out_rx: mpsc::Receiver<Bytes>,
}

/// `AutoInterfacePeer.process_incoming` / `process_outgoing`
/// (AutoInterface.py:652-681). Ends, and deregisters the child, once the
/// parent drops the peer or transport drops the child.
async fn child_task(mut task: ChildTask) {
    loop {
        tokio::select! {
            biased;
            inbound = task.in_rx.recv() => {
                let Some(raw) = inbound else { break };
                let message = TransportMessage::Inbound(InboundPacket {
                    raw,
                    interface_id: task.id,
                    rssi: None,
                    snr: None,
                    q: None,
                });
                if task.sender.send(message).await.is_err() {
                    break;
                }
            }
            outbound = task.out_rx.recv() => {
                let Some(data) = outbound else { break };
                if !task.online.load(Ordering::SeqCst) {
                    continue;
                }
                match task.outbound.send_to(&data, task.dest).await {
                    Ok(_) => {
                        task.txb.fetch_add(data.len() as u64, Ordering::Relaxed);
                        task.parent_txb.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                    Err(e) => tracing::error!(
                        "Could not transmit on {}. The contained exception was: {}",
                        task.name,
                        e
                    ),
                }
            }
        }
    }
    task.online.store(false, Ordering::SeqCst);
    tracing::debug!("The interface {} is being torn down.", task.name);
    let _ = task
        .sender
        .send(TransportMessage::DeregisterInterface { id: task.id })
        .await;
}

/// `detach` (AutoInterface.py:619-632): closes every socket, stops every
/// task and takes the spawned peers down with the parent.
struct Teardown {
    shared: Arc<Shared>,
    jobs: Option<JoinHandle<()>>,
}

impl Drop for Teardown {
    fn drop(&mut self) {
        self.shared.online.store(false, Ordering::SeqCst);
        if let Some(jobs) = self.jobs.take() {
            jobs.abort();
        }
        let nics = std::mem::take(&mut *self.shared.nics.lock().expect("auto nic mutex poisoned"));
        drop(nics);
        for child in self.shared.core().drain_children() {
            child.online.store(false, Ordering::SeqCst);
        }
    }
}

/// Spawn an AutoInterface. Peers discovered later are spawned as child
/// interfaces (with `parent_id` set to `id`, ids taken from `id_gen`) and
/// delivered on `handle_tx` for registration.
///
/// Like upstream's `final_init`, this returns only after the peering wait
/// (`PEERING_WAIT`), and the interface is online from then on.
pub async fn spawn_auto_interface(
    config: AutoInterfaceConfig,
    id: InterfaceId,
    id_gen: Arc<AtomicU64>,
    transport_tx: mpsc::Sender<TransportMessage>,
    handle_tx: mpsc::Sender<InterfaceHandle>,
    is_foreground: Arc<AtomicBool>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let outbound = bind_udp(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0), false)?;
    let configured_bitrate = config.configured_bitrate;
    let shared = Arc::new(Shared::new(
        config,
        id,
        id_gen,
        transport_tx,
        handle_tx,
        is_foreground,
        outbound,
    ));
    let owner = shared.parent.owner();
    let mut teardown = Teardown {
        shared: shared.clone(),
        jobs: None,
    };

    let mut suitable = 0usize;
    for nic in shared.enumerate() {
        if shared.adopt_nic(&nic)? {
            suitable += 1;
        }
    }
    let bitrate = if suitable == 0 {
        tracing::warn!(
            "{} could not autoconfigure. This interface currently provides no connectivity.",
            shared
        );
        UNCONFIGURED_BITRATE
    } else {
        configured_bitrate.unwrap_or(BITRATE_GUESS)
    };
    shared.bitrate.store(bitrate, Ordering::SeqCst);

    teardown.jobs = Some(tokio::spawn(shared.clone().run_jobs()));
    tracing::info!(
        "{} discovering peers for {} seconds...",
        shared,
        (PEERING_WAIT * 100.0).round() / 100.0
    );
    tokio::time::sleep(std::time::Duration::from_secs_f64(PEERING_WAIT)).await;
    shared.online.store(true, Ordering::SeqCst);
    shared.final_init_done.store(true, Ordering::SeqCst);

    // The parent never transmits (`process_outgoing` is a no-op); its queue
    // closing means transport dropped it, which detaches the interface.
    let (tx, mut rx) = mpsc::channel::<Bytes>(64);
    let read_task = tokio::spawn(async move {
        let _teardown = teardown;
        while rx.recv().await.is_some() {}
    });

    Ok(InterfaceHandle {
        id,
        owner,
        packet_capacity: InterfacePacketCapacity::new(HW_MTU, HW_MTU, FIXED_MTU),
        parent_id: None,
        name: shared.name.clone(),
        mode: shared.mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: true,
            forward: false,
            repeat: false,
        },
        bitrate,
        mtu: HW_MTU,
        online: shared.online.clone(),
        rxb: Some(shared.rxb.clone()),
        txb: Some(shared.txb.clone()),
        inspection: None,
        tx,
        read_task,
    })
}

#[cfg(test)]
mod tests;
