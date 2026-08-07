//! Automatic peer discovery over IPv6 link-local multicast.
//!
//! Beacons go to a multicast group derived from `SHA-256(group_id)` every
//! ~1.6 s; data flows over unicast UDP. Peers age out after 22 s of silence.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, broadcast, mpsc};

use crate::traits::{InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

pub const DISCOVERY_PORT: u16 = 29716;
pub const DATA_PORT: u16 = 42671;
pub const BEACON_INTERVAL: f64 = 1.6;
/// Background beacon — slow enough to save battery, still inside expiry window.
pub const BEACON_INTERVAL_BG: f64 = 8.0;
pub const PEER_EXPIRY: f64 = 22.0;
pub const HW_MTU: u32 = 1196;
pub const FIXED_MTU: bool = true;
pub const DEFAULT_GROUP_ID: &str = "reticulum";
pub const UNICAST_DISCOVERY_PORT: u16 = DISCOVERY_PORT + 1;
pub const REVERSE_PEERING_INTERVAL: f64 = BEACON_INTERVAL * 3.25;
pub const PEER_JOB_INTERVAL: f64 = 4.0;
pub const MCAST_ECHO_TIMEOUT: f64 = 6.5;
pub const MULTI_IF_DEQUE_LEN: usize = 48;
pub const MULTI_IF_DEQUE_TTL: f64 = 0.75;

// Per-platform ignores: loopback, Apple AWDL, cellular RIL, VPN tunnels.

#[cfg(target_os = "macos")]
const IGNORED_IFACES: &[&str] = &["awdl0", "llw0", "lo0", "en5"];

#[cfg(target_os = "linux")]
const IGNORED_IFACES: &[&str] = &["lo"];

#[cfg(target_os = "android")]
const IGNORED_IFACES: &[&str] = &[
    "lo",
    "dummy0",
    "rmnet_data0",
    "rmnet_data1",
    "rmnet_data2",
    "rmnet_data3",
    "rmnet_data4",
    "rmnet_data5",
    "rmnet_data6",
    "rmnet_data7",
    "rmnet_ipa0",
    "r_rmnet_data0",
    "v4-rmnet_data0",
];

#[cfg(target_os = "ios")]
const IGNORED_IFACES: &[&str] = &[
    "lo0", "awdl0", "llw0", "ap1", "ipsec0", "utun0", "utun1", "utun2", "utun3", "pdp_ip0",
    "pdp_ip1", "pdp_ip2", "pdp_ip3",
];

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    target_os = "ios"
)))]
const IGNORED_IFACES: &[&str] = &["lo", "lo0"];

/// IPv6 multicast scope (RFC 4291 §2.7) — lower nibble of `ff_S:` byte.
/// `Link` stays on the LAN; `Site`+ require routed multicast configuration.
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
        match s.trim().to_ascii_lowercase().as_str() {
            "link" => Ok(Self::Link),
            "admin" => Ok(Self::Admin),
            "site" => Ok(Self::Site),
            "organisation" | "organization" => Ok(Self::Organisation),
            "global" => Ok(Self::Global),
            other => Err(format!("unknown discovery scope: {other}")),
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

/// IPv6 multicast transient/permanent flag (RFC 4291 §2.7) — upper nibble
/// of `ff_T_:`. Default is `Temporary`.
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
}

impl std::str::FromStr for McastAddrType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "temporary" | "temp" => Ok(Self::Temporary),
            "permanent" | "perm" => Ok(Self::Permanent),
            other => Err(format!("unknown multicast address type: {other}")),
        }
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

/// Async events from `spawn_auto_interface`; forwarded to Tauri broadcasts.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AutoInterfaceEvent {
    /// `IPV6_JOIN_GROUP` was rejected by the OS. On Apple this is the
    /// canonical signal for missing `com.apple.developer.networking.multicast`
    /// entitlement (free dev team can't sign it). On Linux it usually means
    /// the interface vanished between enumeration and join.
    JoinFailed {
        interface_name: String,
        ifname: String,
        reason: String,
    },
    /// Carrier state changed — multicast echoes started or stopped arriving
    /// on `ifname` within `MCAST_ECHO_TIMEOUT`. `ok=false` is the trip-wire
    /// for Windows Public-profile firewall block, bridged-AP reboot, or
    /// general IPv6 multicast suppression. `reason` is human-readable.
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
        // Ignore "no subscribers" errors; events are best-effort and callers
        // may not have started their relay task yet.
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
    /// Whitelist of NIC names. `None` = all (minus IGNORED_IFACES + ignored_devices).
    pub devices: Option<Vec<String>>,
    /// Additional NIC names to skip on top of the platform default IGNORED_IFACES.
    pub ignored_devices: Vec<String>,
    /// Bitrate override in bits per second. `None` = default 10 Mbps guess.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PeerKey {
    ip: Ipv6Addr,
    scope_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerScopeSource {
    Received,
    LocalCandidate,
    UnscopedNonLinkLocal,
}

#[derive(Debug, Clone)]
struct PeerScopeCandidate {
    ifname: String,
    scope_id: u32,
    source: PeerScopeSource,
}

#[derive(Debug, Clone)]
struct Peer {
    ip: Ipv6Addr,
    ifname: String,
    scope_id: u32,
    scope_source: PeerScopeSource,
    addr: SocketAddrV6,
    last_seen: Instant,
    last_reverse: Instant,
}

type PeerTable = Arc<Mutex<HashMap<PeerKey, Peer>>>;

#[derive(Debug, Clone)]
struct DeduplicateEntry {
    hash: [u8; 32],
    timestamp: Instant,
}

/// Dedupes packets seen on multiple NICs at once (e.g. WLAN + wired).
#[derive(Debug, Clone)]
pub struct MultiIfDedup {
    deque: VecDeque<DeduplicateEntry>,
    max_len: usize,
    ttl_secs: f64,
}

impl MultiIfDedup {
    pub fn new() -> Self {
        Self {
            deque: VecDeque::with_capacity(MULTI_IF_DEQUE_LEN),
            max_len: MULTI_IF_DEQUE_LEN,
            ttl_secs: MULTI_IF_DEQUE_TTL,
        }
    }

    /// Record the packet and return whether it was already seen within TTL.
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

        for entry in &self.deque {
            if entry.hash == hash {
                return true;
            }
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

/// Verify a beacon against `SHA-256(group_id + peer_addr_string)`.
pub fn verify_beacon(beacon: &[u8], group_id: &str, peer_addr: &Ipv6Addr) -> bool {
    if beacon.len() < 32 {
        return false;
    }
    let expected = make_beacon(group_id, peer_addr);
    beacon[..32] == expected[..]
}

#[cfg(any(target_os = "macos", test))]
fn normalize_link_local_addr(addr: Ipv6Addr) -> Ipv6Addr {
    if (addr.segments()[0] & 0xffc0) != 0xfe80 {
        return addr;
    }
    let mut segments = addr.segments();
    segments[1] = 0;
    Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    )
}

fn is_link_local_v6(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

fn peer_scope_candidates(
    peer_ip: Ipv6Addr,
    received_scope: u32,
    link_locals: &[(String, Ipv6Addr, u32)],
) -> Vec<PeerScopeCandidate> {
    // Python Reticulum associates AutoInterface peers with the receiving
    // ifname and sends to fe80::peer%ifindex. Some platforms report scope 0
    // from a wildcard-bound socket, so expand link-local peers to scoped local
    // candidates instead of storing an unusable fe80::peer%0 address.
    if received_scope != 0 {
        let ifname = link_locals
            .iter()
            .find(|(_, _, scope_id)| *scope_id == received_scope)
            .map(|(name, _, _)| name.clone())
            .unwrap_or_else(|| format!("ifindex:{received_scope}"));
        return vec![PeerScopeCandidate {
            ifname,
            scope_id: received_scope,
            source: PeerScopeSource::Received,
        }];
    }

    if !is_link_local_v6(peer_ip) {
        return vec![PeerScopeCandidate {
            ifname: String::new(),
            scope_id: 0,
            source: PeerScopeSource::UnscopedNonLinkLocal,
        }];
    }

    let mut candidates = Vec::new();
    for (ifname, _, scope_id) in link_locals {
        if *scope_id == 0
            || candidates
                .iter()
                .any(|c: &PeerScopeCandidate| c.scope_id == *scope_id)
        {
            continue;
        }
        candidates.push(PeerScopeCandidate {
            ifname: ifname.clone(),
            scope_id: *scope_id,
            source: PeerScopeSource::LocalCandidate,
        });
    }
    candidates
}

fn upsert_peer_candidates(
    table: &mut HashMap<PeerKey, Peer>,
    peer_ip: Ipv6Addr,
    data_port: u16,
    received_scope: u32,
    link_locals: &[(String, Ipv6Addr, u32)],
    now: Instant,
    source: &'static str,
) -> usize {
    let candidates = peer_scope_candidates(peer_ip, received_scope, link_locals);
    if candidates.is_empty() {
        tracing::warn!(
            peer = %peer_ip,
            received_scope,
            local_candidates = link_locals.len(),
            source,
            "auto: discovered link-local peer but no usable scope candidates are available"
        );
        return 0;
    }

    let mut inserted = 0usize;
    for candidate in candidates {
        let key = PeerKey {
            ip: peer_ip,
            scope_id: candidate.scope_id,
        };
        let data_addr = SocketAddrV6::new(peer_ip, data_port, 0, candidate.scope_id);
        table
            .entry(key)
            .and_modify(|p| {
                p.ifname = candidate.ifname.clone();
                p.scope_id = candidate.scope_id;
                p.scope_source = candidate.source;
                p.addr = data_addr;
                p.last_seen = now;
            })
            .or_insert_with(|| {
                inserted += 1;
                Peer {
                    ip: peer_ip,
                    ifname: candidate.ifname,
                    scope_id: candidate.scope_id,
                    scope_source: candidate.source,
                    addr: data_addr,
                    last_seen: now,
                    last_reverse: now,
                }
            });
    }
    inserted
}

/// Derive `ff_T_S_:0:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX` from address-type nibble,
/// scope nibble, and bytes 2..14 of `SHA-256(group_id)`.
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

/// `SHA-256(group_id || link_local_addr_string)`, the beacon payload.
fn make_beacon(group_id: &str, link_local: &Ipv6Addr) -> [u8; 32] {
    let mut input = group_id.as_bytes().to_vec();
    input.extend_from_slice(link_local.to_string().as_bytes());
    rns_crypto::sha::sha256(&input)
}

/// One enumerated host NIC, returned by [`list_network_interfaces`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub addr_v4: Option<String>,
    pub addr_v6_link_local: Option<String>,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// Enumerate all host NICs (including loopback / ignored). Callers filter on top.
pub fn list_network_interfaces() -> Result<Vec<NetworkInterfaceInfo>, String> {
    use std::collections::BTreeMap;

    let mut by_name: BTreeMap<String, NetworkInterfaceInfo> = BTreeMap::new();
    let ifaces =
        if_addrs::get_if_addrs().map_err(|e| format!("if_addrs::get_if_addrs() failed: {e}"))?;
    for iface in ifaces {
        let entry = by_name
            .entry(iface.name.clone())
            .or_insert_with(|| NetworkInterfaceInfo {
                name: iface.name.clone(),
                addr_v4: None,
                addr_v6_link_local: None,
                is_up: false,
                is_loopback: iface.is_loopback(),
            });
        entry.is_loopback = entry.is_loopback || iface.is_loopback();
        match iface.addr.ip() {
            std::net::IpAddr::V4(v4) => {
                if entry.addr_v4.is_none() {
                    entry.addr_v4 = Some(v4.to_string());
                }
                entry.is_up = true;
            }
            std::net::IpAddr::V6(v6) => {
                // fe80::/10 — link-local prefix used by AutoInterface discovery.
                if (v6.segments()[0] & 0xffc0) == 0xfe80 && entry.addr_v6_link_local.is_none() {
                    entry.addr_v6_link_local = Some(v6.to_string());
                }
                entry.is_up = true;
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        match darwin_link_local_addrs(None, &[], false) {
            Ok(addrs) => {
                for (name, addr, _) in addrs {
                    let entry =
                        by_name
                            .entry(name.clone())
                            .or_insert_with(|| NetworkInterfaceInfo {
                                name,
                                addr_v4: None,
                                addr_v6_link_local: None,
                                is_up: true,
                                is_loopback: false,
                            });
                    entry.addr_v6_link_local = Some(addr.to_string());
                    entry.is_up = true;
                }
            }
            Err(e) => tracing::debug!(error = %e, "Darwin getifaddrs link-local list failed"),
        }
    }

    Ok(by_name.into_values().collect())
}

fn iface_passes_filters(
    iface_name: &str,
    devices: Option<&[String]>,
    ignored_devices: &[String],
) -> bool {
    if IGNORED_IFACES.contains(&iface_name) {
        return false;
    }
    if ignored_devices.iter().any(|n| n == iface_name) {
        return false;
    }
    if let Some(allowed) = devices {
        if !allowed.iter().any(|n| n == iface_name) {
            return false;
        }
    }
    true
}

/// Enumerate link-local IPv6 addresses, applying device/ignore filters.
/// Drops addresses with unresolvable scope id — `scope_id = 0` silently
/// routes via the default NIC, which is wrong on multi-homed hosts.
fn get_link_local_addrs(
    devices: Option<&[String]>,
    ignored_devices: &[String],
) -> Vec<(String, Ipv6Addr, u32)> {
    // Android's libc getifaddrs() hides IPv6 link-local from app context;
    // must use Java NetworkInterface.getNetworkInterfaces() via JNI.
    #[cfg(target_os = "android")]
    {
        match get_link_local_addrs_android(devices, ignored_devices) {
            Ok(v) if !v.is_empty() => {
                tracing::info!(count = v.len(), "Android JNI link-local enumerate");
                return v;
            }
            Ok(_) => {
                tracing::warn!(
                    "Android JNI link-local enumerate returned 0 — falling back to if_addrs"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "Android JNI link-local enumerate failed");
            }
        }
    }

    let mut result = Vec::new();
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => {
            tracing::debug!(count = ifaces.len(), "if_addrs enumerated interfaces");
            for iface in ifaces {
                tracing::debug!(name = %iface.name, addr = ?iface.addr.ip(), "if_addrs entry");
                if !iface_passes_filters(&iface.name, devices, ignored_devices) {
                    continue;
                }
                if let std::net::IpAddr::V6(addr) = iface.addr.ip() {
                    if (addr.segments()[0] & 0xffc0) == 0xfe80 {
                        let scope_id = iface_scope_id(&iface);
                        if scope_id == 0 {
                            tracing::warn!(
                                iface = %iface.name,
                                addr = %addr,
                                "skipping link-local: could not resolve scope id (would send on wrong NIC)"
                            );
                            continue;
                        }
                        result.push((iface.name.clone(), addr, scope_id));
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "if_addrs::get_if_addrs() failed");
        }
    }

    #[cfg(target_os = "macos")]
    if result.is_empty() {
        match darwin_link_local_addrs(devices, ignored_devices, true) {
            Ok(addrs) if !addrs.is_empty() => {
                tracing::debug!(
                    count = addrs.len(),
                    "Darwin getifaddrs link-local enumerate"
                );
                return addrs;
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "Darwin getifaddrs link-local enumerate failed"),
        }
    }

    result
}

#[cfg(target_os = "macos")]
fn darwin_link_local_addrs(
    devices: Option<&[String]>,
    ignored_devices: &[String],
    apply_filters: bool,
) -> Result<Vec<(String, Ipv6Addr, u32)>, String> {
    use std::ffi::CStr;
    use std::ptr;

    let mut ifap: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs initialises `ifap` on success; the linked list is
    // released with freeifaddrs before return.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    struct IfAddrsGuard(*mut libc::ifaddrs);
    impl Drop for IfAddrsGuard {
        fn drop(&mut self) {
            // SAFETY: pointer came from successful getifaddrs and is released once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = IfAddrsGuard(ifap);

    let mut result = Vec::new();
    let mut cursor = ifap;
    while !cursor.is_null() {
        // SAFETY: cursor walks the null-terminated getifaddrs list.
        let ifa = unsafe { &*cursor };
        cursor = ifa.ifa_next;

        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: getifaddrs provides a nul-terminated interface name.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        if apply_filters && !iface_passes_filters(&name, devices, ignored_devices) {
            continue;
        }
        if ifa.ifa_flags & libc::IFF_UP as u32 == 0 {
            continue;
        }
        let explicitly_allowed = devices.is_some_and(|allowed| allowed.iter().any(|n| n == &name));
        if apply_filters && !explicitly_allowed && ifa.ifa_flags & libc::IFF_POINTOPOINT as u32 != 0
        {
            tracing::debug!(iface = %name, "skipping Darwin point-to-point link-local");
            continue;
        }
        // SAFETY: ifa_addr is non-null and points to a sockaddr for this entry.
        let family = unsafe { (*ifa.ifa_addr).sa_family as i32 };
        if family != libc::AF_INET6 {
            continue;
        }

        // SAFETY: family is AF_INET6, so sockaddr_in6 layout is valid.
        let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
        let addr = normalize_link_local_addr(Ipv6Addr::from(sin6.sin6_addr.s6_addr));
        if (addr.segments()[0] & 0xffc0) != 0xfe80 {
            continue;
        }

        let scope_id = if sin6.sin6_scope_id != 0 {
            sin6.sin6_scope_id
        } else {
            iface_name_to_scope_id(&name)
        };
        if scope_id == 0 {
            tracing::warn!(
                iface = %name,
                addr = %addr,
                "skipping Darwin link-local: could not resolve scope id"
            );
            continue;
        }
        if result.iter().any(|(existing, _, _)| existing == &name) {
            continue;
        }
        tracing::debug!(iface = %name, addr = %addr, scope_id, "Darwin link-local found");
        result.push((name, addr, scope_id));
    }

    Ok(result)
}

#[cfg(target_os = "android")]
fn get_link_local_addrs_android(
    devices: Option<&[String]>,
    ignored_devices: &[String],
) -> Result<Vec<(String, Ipv6Addr, u32)>, String> {
    use jni::objects::JObject;

    let vm = crate::android_usb::java_vm().ok_or("JavaVM not initialized")?;
    let env = vm
        .attach_current_thread()
        .map_err(|e| format!("attach_current_thread: {e}"))?;

    let ni_class = env
        .find_class("java/net/NetworkInterface")
        .map_err(|e| format!("NetworkInterface class: {e}"))?;
    let inet6_class = env
        .find_class("java/net/Inet6Address")
        .map_err(|e| format!("Inet6Address class: {e}"))?;

    let ifaces_enum = env
        .call_static_method(
            ni_class,
            "getNetworkInterfaces",
            "()Ljava/util/Enumeration;",
            &[],
        )
        .map_err(|e| format!("getNetworkInterfaces: {e}"))?
        .l()
        .map_err(|e| format!("getNetworkInterfaces obj: {e}"))?;
    if ifaces_enum.is_null() {
        return Err("getNetworkInterfaces returned null".into());
    }

    let mut result: Vec<(String, Ipv6Addr, u32)> = Vec::new();

    while env
        .call_method(ifaces_enum, "hasMoreElements", "()Z", &[])
        .map_err(|e| format!("hasMoreElements: {e}"))?
        .z()
        .map_err(|e| format!("hasMoreElements bool: {e}"))?
    {
        let iface_obj: JObject = env
            .call_method(ifaces_enum, "nextElement", "()Ljava/lang/Object;", &[])
            .map_err(|e| format!("nextElement (iface): {e}"))?
            .l()
            .map_err(|e| format!("nextElement iface obj: {e}"))?;
        if iface_obj.is_null() {
            continue;
        }

        let is_up = env
            .call_method(iface_obj, "isUp", "()Z", &[])
            .map_err(|e| format!("isUp: {e}"))?
            .z()
            .map_err(|e| format!("isUp bool: {e}"))?;
        if !is_up {
            continue;
        }

        let name_obj: JObject = env
            .call_method(iface_obj, "getName", "()Ljava/lang/String;", &[])
            .map_err(|e| format!("getName: {e}"))?
            .l()
            .map_err(|e| format!("getName obj: {e}"))?;
        let name: String = if name_obj.is_null() {
            String::new()
        } else {
            env.get_string(name_obj.into())
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default()
        };
        if !iface_passes_filters(&name, devices, ignored_devices) {
            continue;
        }

        let scope_id = env
            .call_method(iface_obj, "getIndex", "()I", &[])
            .map_err(|e| format!("getIndex: {e}"))?
            .i()
            .map_err(|e| format!("getIndex int: {e}"))? as u32;
        if scope_id == 0 {
            tracing::warn!(
                iface = %name,
                "skipping JNI link-local: getIndex returned 0 (interface may have just gone down)"
            );
            continue;
        }

        let addrs_enum: JObject = env
            .call_method(
                iface_obj,
                "getInetAddresses",
                "()Ljava/util/Enumeration;",
                &[],
            )
            .map_err(|e| format!("getInetAddresses: {e}"))?
            .l()
            .map_err(|e| format!("getInetAddresses obj: {e}"))?;
        if addrs_enum.is_null() {
            continue;
        }

        while env
            .call_method(addrs_enum, "hasMoreElements", "()Z", &[])
            .map_err(|e| format!("addr hasMoreElements: {e}"))?
            .z()
            .map_err(|e| format!("addr hasMoreElements bool: {e}"))?
        {
            let addr_obj: JObject = env
                .call_method(addrs_enum, "nextElement", "()Ljava/lang/Object;", &[])
                .map_err(|e| format!("nextElement (addr): {e}"))?
                .l()
                .map_err(|e| format!("nextElement addr obj: {e}"))?;
            if addr_obj.is_null() {
                continue;
            }

            let is_v6 = env
                .is_instance_of(addr_obj, inet6_class)
                .map_err(|e| format!("is_instance_of Inet6Address: {e}"))?;
            if !is_v6 {
                continue;
            }

            let is_ll = env
                .call_method(addr_obj, "isLinkLocalAddress", "()Z", &[])
                .map_err(|e| format!("isLinkLocalAddress: {e}"))?
                .z()
                .map_err(|e| format!("isLinkLocalAddress bool: {e}"))?;
            if !is_ll {
                continue;
            }

            let raw_obj: JObject = env
                .call_method(addr_obj, "getAddress", "()[B", &[])
                .map_err(|e| format!("getAddress: {e}"))?
                .l()
                .map_err(|e| format!("getAddress obj: {e}"))?;
            if raw_obj.is_null() {
                continue;
            }
            let raw: Vec<u8> = env
                .convert_byte_array(raw_obj.into_inner())
                .unwrap_or_default();
            if raw.len() != 16 {
                continue;
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&raw);
            let v6 = Ipv6Addr::from(bytes);
            tracing::info!(iface = %name, addr = %v6, scope_id, "JNI link-local found");
            result.push((name.clone(), v6, scope_id));
        }
    }

    Ok(result)
}

fn iface_scope_id(iface: &if_addrs::Interface) -> u32 {
    if let Some(index) = iface.index {
        return index;
    }

    #[cfg(windows)]
    {
        let adapter_index = iface_name_to_scope_id(&iface.adapter_name);
        if adapter_index != 0 {
            return adapter_index;
        }
    }

    iface_name_to_scope_id(&iface.name)
}

/// Convert interface name to scope ID via POSIX/Windows `if_nametoindex`.
/// Returns 0 if the lookup fails; callers must skip the address.
#[cfg(any(unix, windows))]
fn iface_name_to_scope_id(name: &str) -> u32 {
    use std::ffi::CString;
    if let Ok(cname) = CString::new(name) {
        // SAFETY: if_nametoindex takes a NUL-terminated C string and returns
        // an index or 0 on error, with no ownership implications.
        unsafe { libc_if_nametoindex(cname.as_ptr()) }
    } else {
        0
    }
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "if_nametoindex"]
    fn libc_if_nametoindex(ifname: *const std::ffi::c_char) -> u32;
}

#[cfg(windows)]
#[link(name = "iphlpapi")]
unsafe extern "C" {
    #[link_name = "if_nametoindex"]
    fn libc_if_nametoindex(ifname: *const std::ffi::c_char) -> u32;
}

#[cfg(not(any(unix, windows)))]
fn iface_name_to_scope_id(_name: &str) -> u32 {
    0
}

/// Bind UDP/IPv6 with REUSEADDR/REUSEPORT so multicast peers can share the port.
fn bind_reusable_udp_v6(port: u16) -> std::io::Result<UdpSocket> {
    bind_one(port)
}

fn bind_one(port: u16) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    if let Err(e) = sock.set_reuse_address(true) {
        tracing::warn!(port, error = %e, "SO_REUSEADDR failed");
    }
    #[cfg(unix)]
    if let Err(e) = sock.set_reuse_port(true) {
        tracing::warn!(port, error = %e, "SO_REUSEPORT failed");
    }
    // IPv6-only — link-local + scope_ids assume v6 semantics.
    if let Err(e) = sock.set_only_v6(true) {
        tracing::warn!(port, error = %e, "IPV6_V6ONLY failed");
    }
    sock.set_nonblocking(true)?;
    let addr: SocketAddr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into();
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

fn set_multicast_if_v6(sock: &UdpSocket, scope_id: u32) -> std::io::Result<()> {
    let sock_ref = socket2::SockRef::from(sock);
    sock_ref.set_multicast_if_v6(scope_id)
}

/// Diagnostic: probe alternate ports to localize bind failures.
#[cfg(target_os = "android")]
fn probe_alternate_ports(base: u16) {
    let candidates: [u16; 4] = [base.saturating_add(1), base.saturating_add(2), 50000, 0];
    for p in candidates {
        match bind_one(p) {
            Ok(s) => {
                let local = s.local_addr();
                tracing::info!(probe_port = p, ?local, "probe bind succeeded");
                drop(s);
            }
            Err(e) => {
                tracing::warn!(probe_port = p, error = %e, "probe bind failed");
            }
        }
    }
}

fn hex32(bytes: &[u8]) -> String {
    let take = bytes.len().min(32);
    let mut s = String::with_capacity(take * 2);
    for b in &bytes[..take] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_prefix(bytes: &[u8], n: usize) -> String {
    let take = bytes.len().min(n);
    let mut s = String::with_capacity(take * 2);
    for b in &bytes[..take] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Spawn the auto-discovery interface.
pub async fn spawn_auto_interface(
    config: AutoInterfaceConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    is_foreground: Arc<AtomicBool>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let mcast_group = derive_multicast_address(
        &config.group_id,
        config.discovery_scope,
        config.multicast_address_type,
    );
    let initial_link_locals =
        get_link_local_addrs(config.devices.as_deref(), &config.ignored_devices);

    if initial_link_locals.is_empty() {
        tracing::warn!(name = %config.name, "no link-local IPv6 addresses found");
    }

    // Adopted NIC set; jobs task refreshes on link flap. Each iteration snapshots.
    let link_locals: Arc<Mutex<Vec<(String, Ipv6Addr, u32)>>> =
        Arc::new(Mutex::new(initial_link_locals.clone()));

    // Per-NIC last-echo timestamp — updated by discovery RX when it sees our
    // own beacon (multicast carrier confirmed). Read by jobs for carrier check.
    let multicast_echoes: Arc<Mutex<HashMap<String, Instant>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let data_sock = Arc::new(bind_reusable_udp_v6(config.data_port).map_err(|e| {
        #[cfg(target_os = "android")]
        if e.kind() == std::io::ErrorKind::AddrInUse {
            probe_alternate_ports(config.data_port);
        }
        std::io::Error::new(
            e.kind(),
            format!("data socket bind ({}): {e}", config.data_port),
        )
    })?);
    let data_local = data_sock.local_addr()?;
    tracing::info!(name = %config.name, addr = %data_local, "auto data socket bound");

    let disc_sock = Arc::new(bind_reusable_udp_v6(config.discovery_port).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("discovery socket bind ({}): {e}", config.discovery_port),
        )
    })?);
    tracing::info!(name = %config.name, port = config.discovery_port, "auto discovery socket bound");

    for (iface_name, _ll_addr, scope_id) in &initial_link_locals {
        if let Err(e) = set_multicast_if_v6(disc_sock.as_ref(), *scope_id) {
            tracing::warn!(
                iface = %iface_name,
                scope_id,
                error = %e,
                raw_os_error = ?e.raw_os_error(),
                "failed to set IPv6 multicast outbound interface"
            );
        }
        if let Err(e) = disc_sock.join_multicast_v6(&mcast_group, *scope_id) {
            // PermissionDenied (EPERM/EACCES, Windows ERROR_ACCESS_DENIED) on
            // Apple platforms is the canonical signal that the multicast
            // networking entitlement isn't provisioned. Surfaced as an event
            // so UIs can show pending Apple approval.
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                tracing::warn!(
                    iface = %iface_name,
                    error = %e,
                    "multicast join denied by OS — entitlement / firewall / capability missing"
                );
                dispatch_auto_event(AutoInterfaceEvent::JoinFailed {
                    interface_name: config.name.clone(),
                    ifname: iface_name.clone(),
                    reason: format!("os_permission_denied: {e}"),
                });
            } else {
                tracing::debug!(
                    iface = %iface_name,
                    error = %e,
                    "failed to join multicast group"
                );
            }
        }
    }

    let online = Arc::new(AtomicBool::new(true));
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);
    let name = config.name.clone();
    let mode = config.mode;

    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));

    let peers: PeerTable = Arc::new(Mutex::new(HashMap::new()));

    let online_b = online.clone();
    let group_id = config.group_id.clone();
    let disc_sock_send = disc_sock.clone();
    let beacon_link_locals = link_locals.clone();
    let disc_port = config.discovery_port;
    let is_fg_beacon = is_foreground.clone();
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs_f64(BEACON_INTERVAL));
        #[cfg(feature = "mobile-throttle")]
        let mut was_foreground = true;
        #[cfg(not(feature = "mobile-throttle"))]
        let _ = &is_fg_beacon;
        loop {
            interval.tick().await;
            if !online_b.load(Ordering::SeqCst) {
                break;
            }
            // Slow beacons in background to save battery.
            #[cfg(feature = "mobile-throttle")]
            {
                let is_fg = is_fg_beacon.load(Ordering::Relaxed);
                if is_fg != was_foreground {
                    let secs = if is_fg {
                        BEACON_INTERVAL
                    } else {
                        BEACON_INTERVAL_BG
                    };
                    interval = tokio::time::interval(std::time::Duration::from_secs_f64(secs));
                    interval.tick().await;
                    was_foreground = is_fg;
                }
            }
            // Snapshot adopted set; jobs task may have replaced it on link flap.
            let snapshot = { beacon_link_locals.lock().await.clone() };
            for (_name, ll_addr, scope_id) in &snapshot {
                let beacon = make_beacon(&group_id, ll_addr);
                let dest = SocketAddrV6::new(mcast_group, disc_port, 0, *scope_id);
                if let Err(e) = set_multicast_if_v6(disc_sock_send.as_ref(), *scope_id) {
                    tracing::warn!(
                        iface = %_name,
                        ll = %ll_addr,
                        scope_id,
                        error = %e,
                        raw_os_error = ?e.raw_os_error(),
                        "auto: failed to select multicast outbound interface"
                    );
                }
                let res = disc_sock_send.send_to(&beacon, dest).await;
                match res {
                    Ok(n) => tracing::debug!(
                        iface = %_name,
                        ll = %ll_addr,
                        scope_id,
                        dst = %dest,
                        hash = %hex32(&beacon),
                        sent_bytes = n,
                        "auto-instr beacon TX"
                    ),
                    Err(e) => tracing::warn!(
                        iface = %_name,
                        ll = %ll_addr,
                        scope_id,
                        dst = %dest,
                        hash = %hex32(&beacon),
                        error = %e,
                        raw_os_error = ?e.raw_os_error(),
                        "auto: beacon TX failed"
                    ),
                }
            }
        }
    });

    let peers_disc = peers.clone();
    let online_d = online.clone();
    let data_port = config.data_port;
    let auth_group_id = config.group_id.clone();
    let disc_link_locals = link_locals.clone();
    let disc_echoes = multicast_echoes.clone();
    let disc_sock_recv = disc_sock.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 256];
        // Python's read loops swallow exceptions and keep serving; Linux
        // surfaces transient async errors (ICMP unreachable) via recv_from,
        // so only sustained failure may kill the loop.
        let mut consecutive_errors = 0u32;
        loop {
            if !online_d.load(Ordering::SeqCst) {
                break;
            }
            match disc_sock_recv.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    consecutive_errors = 0;
                    if n < 32 {
                        tracing::debug!(src = %src, n, "auto-instr mcast RX too short");
                        continue;
                    }
                    if let SocketAddr::V6(src_v6) = src {
                        let peer_ip = *src_v6.ip();
                        // Match source LL against ours — non-empty means self-echo.
                        let snapshot = { disc_link_locals.lock().await.clone() };
                        let self_iface = {
                            snapshot
                                .iter()
                                .find(|(_, ll, _)| *ll == peer_ip)
                                .map(|(name, _, _)| name.clone())
                        };
                        let is_self = self_iface.is_some();
                        let expected = make_beacon(&auth_group_id, &peer_ip);
                        let match_ok = expected[..] == buf[..32];
                        // Hash hex strings only materialize when debug is on.
                        if tracing::enabled!(tracing::Level::DEBUG) {
                            tracing::debug!(
                                src = %src_v6,
                                scope_id = src_v6.scope_id(),
                                n,
                                is_self,
                                recv_hash = %hex32(&buf[..32]),
                                expected_hash = %hex32(&expected),
                                match_ok,
                                "auto-instr mcast RX"
                            );
                        }
                        if let Some(ifname) = self_iface {
                            // Self-echo: carrier confirmed; record for jobs task.
                            let mut echoes = disc_echoes.lock().await;
                            echoes.insert(ifname, Instant::now());
                            continue;
                        }
                        if !match_ok {
                            continue;
                        }
                        let received_scope = src_v6.scope_id();
                        let now = Instant::now();
                        let mut table = peers_disc.lock().await;
                        let inserted = upsert_peer_candidates(
                            &mut table,
                            peer_ip,
                            data_port,
                            received_scope,
                            &snapshot,
                            now,
                            "multicast",
                        );
                        tracing::debug!(
                            peer = %peer_ip,
                            received_scope,
                            inserted,
                            peer_records = table.len(),
                            "auto: peer discovered/refreshed"
                        );
                    } else {
                        tracing::debug!(src = %src, "auto-instr mcast RX non-v6 source");
                    }
                }
                Err(e) => {
                    consecutive_errors += 1;
                    tracing::warn!(error = %e, consecutive_errors, "auto discovery recv error");
                    if consecutive_errors >= 50 {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    // Unicast + reverse-peering keeps peers reachable on one-way multicast paths.
    let peers_unicast = peers.clone();
    let online_u = online.clone();
    let unicast_group_id = config.group_id.clone();
    let unicast_link_locals = link_locals.clone();
    let unicast_disc_port = config.discovery_port + 1;
    let unicast_sock = match bind_reusable_udp_v6(unicast_disc_port) {
        Ok(sock) => Some(Arc::new(sock)),
        Err(e) => {
            tracing::debug!(
                port = unicast_disc_port,
                error = %e,
                raw_os_error = ?e.raw_os_error(),
                "auto: could not bind unicast discovery port"
            );
            None
        }
    };
    if let Some(unicast_sock) = unicast_sock {
        let urecv_sock = unicast_sock.clone();
        let urecv_peers = peers_unicast.clone();
        let urecv_online = online_u.clone();
        let urecv_group_id = unicast_group_id.clone();
        let urecv_link_locals = unicast_link_locals.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let mut consecutive_errors = 0u32;
            loop {
                if !urecv_online.load(Ordering::SeqCst) {
                    break;
                }
                match urecv_sock.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        consecutive_errors = 0;
                        if n < 32 {
                            continue;
                        }
                        if let SocketAddr::V6(src_v6) = src {
                            let peer_ip = *src_v6.ip();
                            let snapshot = { urecv_link_locals.lock().await.clone() };
                            let is_self = { snapshot.iter().any(|(_, ll, _)| *ll == peer_ip) };
                            if is_self {
                                continue;
                            }
                            if !verify_beacon(&buf[..n], &urecv_group_id, &peer_ip) {
                                continue;
                            }
                            let received_scope = src_v6.scope_id();
                            let now = Instant::now();
                            let mut table = urecv_peers.lock().await;
                            let inserted = upsert_peer_candidates(
                                &mut table,
                                peer_ip,
                                data_port,
                                received_scope,
                                &snapshot,
                                now,
                                "unicast",
                            );
                            tracing::debug!(
                                peer = %peer_ip,
                                received_scope,
                                inserted,
                                peer_records = table.len(),
                                "auto: unicast peer discovered"
                            );
                        }
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        tracing::debug!(
                            error = %e,
                            consecutive_errors,
                            "auto unicast discovery recv error"
                        );
                        if consecutive_errors >= 50 {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });

        let rev_peers = peers_unicast;
        let rev_online = online_u;
        let rev_group_id = unicast_group_id;
        let rev_link_locals = unicast_link_locals;
        let is_fg_rev = is_foreground.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs_f64(REVERSE_PEERING_INTERVAL));
            #[cfg(feature = "mobile-throttle")]
            let mut was_foreground = true;
            #[cfg(not(feature = "mobile-throttle"))]
            let _ = &is_fg_rev;
            loop {
                interval.tick().await;
                if !rev_online.load(Ordering::SeqCst) {
                    break;
                }
                #[cfg(feature = "mobile-throttle")]
                {
                    let is_fg = is_fg_rev.load(Ordering::Relaxed);
                    if is_fg != was_foreground {
                        let secs = if is_fg {
                            REVERSE_PEERING_INTERVAL
                        } else {
                            BEACON_INTERVAL_BG * 3.25
                        };
                        interval = tokio::time::interval(std::time::Duration::from_secs_f64(secs));
                        interval.tick().await;
                        was_foreground = is_fg;
                    }
                }
                let snapshot = { rev_link_locals.lock().await.clone() };
                let now = Instant::now();
                // Snapshot due peers under a short lock; sends happen lock-free
                // so discovery/data tasks aren't stalled by the fan-out.
                let due: Vec<(PeerKey, Peer)> = {
                    let table = rev_peers.lock().await;
                    table
                        .iter()
                        .filter(|(_, peer)| {
                            now.duration_since(peer.last_reverse).as_secs_f64()
                                >= REVERSE_PEERING_INTERVAL
                        })
                        .map(|(key, peer)| (*key, peer.clone()))
                        .collect()
                };
                for (_, peer) in &due {
                    let mut targets: Vec<_> = snapshot
                        .iter()
                        .filter(|(_, _, scope_id)| peer.scope_id == 0 || *scope_id == peer.scope_id)
                        .collect();
                    if targets.is_empty() {
                        targets = snapshot.iter().collect();
                    }
                    for (_name, ll_addr, scope_id) in targets {
                        let beacon = make_beacon(&rev_group_id, ll_addr);
                        let dest =
                            SocketAddrV6::new(*peer.addr.ip(), unicast_disc_port, 0, *scope_id);
                        if let Err(e) = unicast_sock.send_to(&beacon, dest).await {
                            tracing::debug!(
                                peer = %peer.ip,
                                peer_ifname = %peer.ifname,
                                peer_scope_id = peer.scope_id,
                                local_iface = %_name,
                                local_scope_id = scope_id,
                                dst = %dest,
                                error = %e,
                                raw_os_error = ?e.raw_os_error(),
                                "auto: reverse peering TX failed"
                            );
                        }
                    }
                }
                if !due.is_empty() {
                    let mut table = rev_peers.lock().await;
                    for (key, _) in &due {
                        if let Some(peer) = table.get_mut(key) {
                            peer.last_reverse = now;
                        }
                    }
                }
            }
        });
    }

    // Periodic jobs: NIC re-enum, peer aging, carrier detection (every PEER_JOB_INTERVAL).
    // Decoupled from beacon loop to avoid multicast-join thrash on link flap.
    let jobs_link_locals = link_locals.clone();
    let jobs_peers = peers.clone();
    let jobs_online = online.clone();
    let jobs_devices = config.devices.clone();
    let jobs_ignored = config.ignored_devices.clone();
    let jobs_disc_sock = disc_sock.clone();
    let jobs_mcast = mcast_group;
    let jobs_echoes = multicast_echoes.clone();
    let jobs_iface_name = config.name.clone();
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs_f64(PEER_JOB_INTERVAL));
        // Skip immediate first tick — initial joins happened at spawn.
        interval.tick().await;
        let mut carrier_state: HashMap<String, bool> = HashMap::new();
        loop {
            interval.tick().await;
            if !jobs_online.load(Ordering::SeqCst) {
                break;
            }

            // (1) Age out stale peers.
            {
                let now = Instant::now();
                let mut table = jobs_peers.lock().await;
                table.retain(|_ip, peer| {
                    now.duration_since(peer.last_seen).as_secs_f64() < PEER_EXPIRY
                });
            }

            // (2) Re-enumerate; diff against adopted set; join/leave multicast.
            let new_set = get_link_local_addrs(jobs_devices.as_deref(), &jobs_ignored);
            let (added, removed): (Vec<_>, Vec<_>) = {
                let current = jobs_link_locals.lock().await;
                let added: Vec<_> = new_set
                    .iter()
                    .filter(|(_, a, _)| !current.iter().any(|(_, ca, _)| ca == a))
                    .cloned()
                    .collect();
                let removed: Vec<_> = current
                    .iter()
                    .filter(|(_, a, _)| !new_set.iter().any(|(_, ca, _)| ca == a))
                    .cloned()
                    .collect();
                (added, removed)
            };
            if !added.is_empty() || !removed.is_empty() {
                tracing::info!(
                    iface = %jobs_iface_name,
                    added_count = added.len(),
                    removed_count = removed.len(),
                    "AutoInterface link-local set changed"
                );
            }
            for (ifname, addr, scope_id) in &added {
                if let Err(e) = set_multicast_if_v6(jobs_disc_sock.as_ref(), *scope_id) {
                    tracing::warn!(
                        iface = %jobs_iface_name,
                        nic = %ifname,
                        addr = %addr,
                        scope_id,
                        error = %e,
                        raw_os_error = ?e.raw_os_error(),
                        "AutoInterface failed to set multicast interface for new NIC"
                    );
                }
                match jobs_disc_sock.join_multicast_v6(&jobs_mcast, *scope_id) {
                    Ok(()) => tracing::info!(
                        iface = %jobs_iface_name,
                        nic = %ifname,
                        addr = %addr,
                        scope_id,
                        "AutoInterface joined multicast on new NIC"
                    ),
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::PermissionDenied {
                            dispatch_auto_event(AutoInterfaceEvent::JoinFailed {
                                interface_name: jobs_iface_name.clone(),
                                ifname: ifname.clone(),
                                reason: format!("os_permission_denied: {e}"),
                            });
                        }
                        tracing::warn!(
                            iface = %jobs_iface_name,
                            nic = %ifname,
                            error = %e,
                            "AutoInterface multicast join failed on new NIC"
                        );
                    }
                }
            }
            for (ifname, _addr, scope_id) in &removed {
                let _ = jobs_disc_sock.leave_multicast_v6(&jobs_mcast, *scope_id);
                jobs_echoes.lock().await.remove(ifname);
                carrier_state.remove(ifname);
            }
            *jobs_link_locals.lock().await = new_set.clone();

            // (3) Carrier detection: dispatch CarrierState transitions per NIC.
            let now = Instant::now();
            let echoes = jobs_echoes.lock().await.clone();
            for (ifname, _, _) in &new_set {
                let last = echoes.get(ifname);
                let ok = match last {
                    Some(t) => now.duration_since(*t).as_secs_f64() <= MCAST_ECHO_TIMEOUT,
                    None => false,
                };
                let prev = carrier_state.insert(ifname.clone(), ok);
                if prev != Some(ok) {
                    let reason = match (prev, ok) {
                        (None, false) => "initial: no echo seen yet".to_string(),
                        (None, true) => "first multicast echo received".to_string(),
                        (Some(true), false) => format!(
                            "no multicast echo for >{:.1}s (firewall? bridge? AP reboot?)",
                            MCAST_ECHO_TIMEOUT
                        ),
                        (Some(false), true) => "multicast echo recovered".to_string(),
                        _ => unreachable!("prev != Some(ok) was true above"),
                    };
                    let _ = last;
                    if !ok && prev == Some(true) {
                        tracing::warn!(
                            iface = %jobs_iface_name,
                            nic = %ifname,
                            "AutoInterface carrier lost on {ifname}: {reason}"
                        );
                    } else if ok {
                        tracing::info!(
                            iface = %jobs_iface_name,
                            nic = %ifname,
                            "AutoInterface carrier ok on {ifname}: {reason}"
                        );
                    }
                    dispatch_auto_event(AutoInterfaceEvent::CarrierState {
                        interface_name: jobs_iface_name.clone(),
                        ifname: ifname.clone(),
                        ok,
                        reason,
                    });
                }
            }
        }
    });

    let peers_write = peers.clone();
    let data_sock_w = data_sock.clone();
    let task_txb = shared_txb.clone();
    tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            let len = data.len();
            // Hex prefix only materializes when debug logging is active; the
            // error path below recomputes it (errors are rare).
            let debug_enabled = tracing::enabled!(tracing::Level::DEBUG);
            let prefix = if debug_enabled {
                hex_prefix(&data, 16)
            } else {
                String::new()
            };
            // Snapshot under a short lock so the discovery/jobs tasks are not
            // blocked while we await per-peer sends.
            let targets: Vec<Peer> = {
                let table = peers_write.lock().await;
                table.values().cloned().collect()
            };
            let peer_count = targets.len();
            if peer_count == 0 && debug_enabled {
                tracing::debug!(
                    len,
                    prefix = %prefix,
                    "auto-instr data TX skipped: no discovered peers"
                );
            }
            for peer in &targets {
                let res = data_sock_w.send_to(&data, peer.addr).await;
                match res {
                    Ok(n) => {
                        if debug_enabled {
                            tracing::debug!(
                                peer = %peer.ip,
                                ifname = %peer.ifname,
                                scope_id = peer.scope_id,
                                scope_source = ?peer.scope_source,
                                dst = %peer.addr,
                                len,
                                sent_bytes = n,
                                prefix = %prefix,
                                peer_count,
                                "auto-instr data TX"
                            );
                        }
                        task_txb.fetch_add(len as u64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        tracing::warn!(
                            peer = %peer.ip,
                            ifname = %peer.ifname,
                            scope_id = peer.scope_id,
                            scope_source = ?peer.scope_source,
                            dst = %peer.addr,
                            len,
                            prefix = %hex_prefix(&data, 16),
                            peer_count,
                            error = %e,
                            raw_os_error = ?e.raw_os_error(),
                            "auto: data TX failed"
                        );
                    }
                }
            }
        }
    });

    let online_r = online.clone();
    let task_rxb = shared_rxb.clone();
    let dedup = Arc::new(Mutex::new(MultiIfDedup::new()));
    let read_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut consecutive_errors = 0u32;
        loop {
            match data_sock.recv_from(&mut buf).await {
                Ok((n, _src)) => {
                    consecutive_errors = 0;
                    if n == 0 {
                        continue;
                    }
                    tracing::debug!(
                        src = %_src,
                        n,
                        prefix = %hex_prefix(&buf[..n], 16),
                        "auto-instr data RX"
                    );
                    {
                        let mut dd = dedup.lock().await;
                        if dd.is_duplicate(&buf[..n]) {
                            tracing::trace!(id, "auto: dropping duplicate packet");
                            continue;
                        }
                    }
                    task_rxb.fetch_add(n as u64, Ordering::Relaxed);
                    let msg = TransportMessage::Inbound(InboundPacket {
                        raw: Bytes::copy_from_slice(&buf[..n]),
                        interface_id: id,
                        rssi: None,
                        snr: None,
                        q: None,
                    });
                    if transport_tx.send(msg).await.is_err() {
                        tracing::warn!(id, "transport channel closed");
                        break;
                    }
                }
                Err(e) => {
                    consecutive_errors += 1;
                    tracing::warn!(error = %e, consecutive_errors, "auto data recv error");
                    if consecutive_errors >= 50 {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        online_r.store(false, Ordering::SeqCst);
    });

    let bitrate = config.configured_bitrate.unwrap_or(10_000_000);

    Ok(InterfaceHandle {
        id,
        parent_id: None,
        name,
        mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: true,
            forward: false,
            repeat: false,
        },
        bitrate,
        mtu: HW_MTU,
        online,
        rxb: Some(shared_rxb),
        txb: Some(shared_txb),
        inspection: None,
        tx,
        read_task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multicast_group_derivation() {
        let group = multicast_group_for("reticulum");
        assert_eq!(group.segments()[0], 0xff12);
        assert_eq!(group.segments()[1], 0);
        assert_eq!(group.segments()[2], 0xd70b);
        let group2 = multicast_group_for("reticulum");
        assert_eq!(group, group2);
        let group3 = multicast_group_for("other_group");
        assert_ne!(group, group3);
        // ff12:0:d70b:fb1c:16e4:5e39:485e:31e1.
        assert_eq!(group.segments()[3], 0xfb1c);
        assert_eq!(group.segments()[4], 0x16e4);
        assert_eq!(group.segments()[5], 0x5e39);
        assert_eq!(group.segments()[6], 0x485e);
        assert_eq!(group.segments()[7], 0x31e1);
    }

    #[test]
    fn test_derive_multicast_address_all_scopes() {
        // High u16 = 0xff_T_S; bytes 2-13 of SHA-256("reticulum") fill the body.
        let body = [0xd70b, 0xfb1c, 0x16e4, 0x5e39, 0x485e, 0x31e1];

        for (scope, scope_hex) in [
            (DiscoveryScope::Link, 0x2u16),
            (DiscoveryScope::Admin, 0x4u16),
            (DiscoveryScope::Site, 0x5u16),
            (DiscoveryScope::Organisation, 0x8u16),
            (DiscoveryScope::Global, 0xeu16),
        ] {
            for (addr_type, type_hex) in [
                (McastAddrType::Temporary, 0x1u16),
                (McastAddrType::Permanent, 0x0u16),
            ] {
                let group = derive_multicast_address("reticulum", scope, addr_type);
                let expected_high = 0xff00 | (type_hex << 4) | scope_hex;
                assert_eq!(
                    group.segments()[0],
                    expected_high,
                    "scope {scope:?} type {addr_type:?}"
                );
                assert_eq!(group.segments()[1], 0);
                for (i, want) in body.iter().enumerate() {
                    assert_eq!(group.segments()[2 + i], *want);
                }
            }
        }
    }

    #[test]
    fn test_discovery_scope_parse_roundtrip() {
        use std::str::FromStr;
        for s in [
            "link",
            "admin",
            "site",
            "organisation",
            "organization",
            "global",
        ] {
            let parsed = DiscoveryScope::from_str(s).expect("parse");
            // Round-trip through Display (organization → organisation is fine).
            let _back = parsed.to_string();
        }
        assert!(DiscoveryScope::from_str("LINK").is_ok());
        assert!(DiscoveryScope::from_str("nonsense").is_err());
    }

    #[test]
    fn test_mcast_addr_type_parse_roundtrip() {
        use std::str::FromStr;
        assert_eq!(
            McastAddrType::from_str("temporary").unwrap(),
            McastAddrType::Temporary
        );
        assert_eq!(
            McastAddrType::from_str("temp").unwrap(),
            McastAddrType::Temporary
        );
        assert_eq!(
            McastAddrType::from_str("permanent").unwrap(),
            McastAddrType::Permanent
        );
        assert_eq!(
            McastAddrType::from_str("perm").unwrap(),
            McastAddrType::Permanent
        );
        assert!(McastAddrType::from_str("nope").is_err());
    }

    #[test]
    fn test_beacon_deterministic() {
        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let b1 = make_beacon("reticulum", &addr);
        let b2 = make_beacon("reticulum", &addr);
        assert_eq!(b1, b2);
        assert_eq!(b1.len(), 32);
    }

    #[test]
    fn test_beacon_auth() {
        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let beacon = make_beacon("reticulum", &addr);
        assert!(verify_beacon(&beacon, "reticulum", &addr));
        assert!(!verify_beacon(&beacon, "other_group", &addr));
        let other_addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        assert!(!verify_beacon(&beacon, "reticulum", &other_addr));
        assert!(!verify_beacon(&beacon[..16], "reticulum", &addr));
    }

    #[test]
    fn peer_scope_candidates_preserves_received_scope() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let locals = vec![
            ("en0".to_string(), Ipv6Addr::LOCALHOST, 11),
            ("eth0".to_string(), Ipv6Addr::LOCALHOST, 22),
        ];

        let candidates = peer_scope_candidates(peer, 22, &locals);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ifname, "eth0");
        assert_eq!(candidates[0].scope_id, 22);
        assert_eq!(candidates[0].source, PeerScopeSource::Received);
    }

    #[test]
    fn peer_scope_candidates_expands_zero_scope_for_link_local() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let locals = vec![
            ("en0".to_string(), Ipv6Addr::LOCALHOST, 11),
            ("eth0".to_string(), Ipv6Addr::LOCALHOST, 22),
            ("duplicate".to_string(), Ipv6Addr::LOCALHOST, 22),
        ];

        let candidates = peer_scope_candidates(peer, 0, &locals);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].ifname, "en0");
        assert_eq!(candidates[0].scope_id, 11);
        assert_eq!(candidates[0].source, PeerScopeSource::LocalCandidate);
        assert_eq!(candidates[1].ifname, "eth0");
        assert_eq!(candidates[1].scope_id, 22);
    }

    #[test]
    fn upsert_peer_candidates_keys_same_ip_by_scope() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let locals = vec![
            ("en0".to_string(), Ipv6Addr::LOCALHOST, 11),
            ("eth0".to_string(), Ipv6Addr::LOCALHOST, 22),
        ];
        let mut table = HashMap::new();

        let inserted = upsert_peer_candidates(
            &mut table,
            peer,
            DATA_PORT,
            0,
            &locals,
            Instant::now(),
            "test",
        );

        assert_eq!(inserted, 2);
        assert_eq!(table.len(), 2);
        assert!(table.contains_key(&PeerKey {
            ip: peer,
            scope_id: 11,
        }));
        assert!(table.contains_key(&PeerKey {
            ip: peer,
            scope_id: 22,
        }));
        assert_eq!(
            table
                .get(&PeerKey {
                    ip: peer,
                    scope_id: 11,
                })
                .unwrap()
                .addr
                .scope_id(),
            11
        );
    }

    #[test]
    fn test_scope_id_prefers_enumerated_interface_index() {
        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let iface = test_interface("__ratspeak_missing_iface__", addr, Some(1234));
        assert_eq!(iface_scope_id(&iface), 1234);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn if_addrs_link_local_feature_is_enabled() {
        let proc_addrs = std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default();
        let host_has_link_local = proc_addrs.lines().any(|line| {
            line.split_whitespace()
                .nth(3)
                .is_some_and(|scope| scope.eq_ignore_ascii_case("20"))
        });
        if !host_has_link_local {
            return;
        }

        let addrs = if_addrs::get_if_addrs().expect("list network interfaces");
        assert!(
            addrs.iter().any(|iface| {
                matches!(&iface.addr, if_addrs::IfAddr::V6(addr) if addr.is_link_local())
            }),
            "Linux has link-local IPv6 addresses in /proc/net/if_inet6, but if-addrs returned none; \
             keep the workspace if-addrs dependency feature `link-local` enabled"
        );
    }

    fn test_interface(name: &str, ip: Ipv6Addr, index: Option<u32>) -> if_addrs::Interface {
        let addr = if_addrs::IfAddr::V6(if_addrs::Ifv6Addr {
            ip,
            netmask: Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0),
            prefixlen: 64,
            broadcast: None,
        });

        #[cfg(windows)]
        {
            if_addrs::Interface {
                name: name.to_string(),
                addr,
                index,
                adapter_name: name.to_string(),
            }
        }
        #[cfg(not(windows))]
        {
            if_addrs::Interface {
                name: name.to_string(),
                addr,
                index,
            }
        }
    }

    #[test]
    fn test_normalize_link_local_addr_clears_embedded_scope_segment() {
        let addr = Ipv6Addr::new(0xfe80, 0x18, 0, 0, 0, 0, 0, 1);
        let normalized = normalize_link_local_addr(addr);
        assert_eq!(normalized, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));

        let global = Ipv6Addr::new(0xfddd, 0xebe4, 0, 0, 0, 0, 0, 1);
        assert_eq!(normalize_link_local_addr(global), global);
    }

    #[test]
    fn test_constants() {
        assert_eq!(HW_MTU, 1196);
        assert_eq!(DISCOVERY_PORT, 29716);
        assert_eq!(DATA_PORT, 42671);
        assert_eq!(UNICAST_DISCOVERY_PORT, 29717);
    }

    #[test]
    fn test_multi_if_dedup() {
        let mut dedup = MultiIfDedup::new();
        let data1 = b"packet one";
        let data2 = b"packet two";

        assert!(!dedup.is_duplicate(data1));
        assert!(dedup.is_duplicate(data1));
        assert!(!dedup.is_duplicate(data2));
    }

    #[test]
    fn test_dedup_max_capacity() {
        let mut dedup = MultiIfDedup::new();
        for i in 0..MULTI_IF_DEQUE_LEN + 10 {
            let data = format!("packet_{}", i);
            assert!(!dedup.is_duplicate(data.as_bytes()));
        }
        assert!(dedup.deque.len() <= MULTI_IF_DEQUE_LEN);
    }

    #[test]
    fn test_reverse_peering_interval() {
        let expected = BEACON_INTERVAL * 3.25;
        assert!((REVERSE_PEERING_INTERVAL - expected).abs() < 0.001);
    }
}
