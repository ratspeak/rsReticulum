//! Local discovered-interface records, stored as one MessagePack file per
//! [`discovery_hash`]. Files contain advertised fields, including any IFAC
//! passphrase, without storage encryption. Use a dedicated, trusted directory:
//! loading does not revalidate announce signatures or proof of work, and
//! [`DiscoveryStore::list`] may remove records while listing them.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use rmpv::Value;
use thiserror::Error;

use super::address;
use super::app_data::{DiscoveryInfo, DiscoveryModulation, sanitize_name};
use super::constants::{
    DISCOVERED_INTERFACE_TYPES, STAMP_SIZE, THRESHOLD_REMOVE_SECS, THRESHOLD_STALE_SECS,
    THRESHOLD_UNKNOWN_SECS,
};

/// Age bucket for the last heard announce. Even `Available` does not establish
/// a current connection or reachable endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryStatus {
    Stale,
    Unknown,
    Available,
}

impl DiscoveryStatus {
    /// Numeric rank for sorting (higher = better).
    pub fn code(self) -> u32 {
        match self {
            Self::Stale => 0,
            Self::Unknown => 100,
            Self::Available => 1000,
        }
    }

    /// Lowercase status label: `stale`, `unknown` or `available`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stale => "stale",
            Self::Unknown => "unknown",
            Self::Available => "available",
        }
    }
}

/// Advertised interface metadata plus local observation history. Public fields
/// can also be supplied directly; the store does not authenticate their source.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredInterface {
    pub info: DiscoveryInfo,
    /// Source identity used by the receiver's source filter. The receiver uses
    /// the announce event's identity hash when present, otherwise the claimed
    /// `info.transport_id`; the two values need not be equal.
    pub network_id: [u8; 16],
    /// Hop count copied from the announce event; not a current path measurement.
    pub hops: u8,
    /// Fractional stamp value observed on the latest announce.
    pub stamp_value: f64,
    /// The actual stamp bytes last observed (useful for diagnostics).
    pub stamp: Vec<u8>,
    /// Unix seconds — first time this interface was learned.
    pub discovered: f64,
    /// Unix seconds — most recent announce.
    pub last_heard: f64,
    /// Sightings after the first, as upstream counts them: 0 when first
    /// written, then one more per upsert, saturating at `u64::MAX`.
    pub heard_count: u64,
    /// Age status assigned by [`DiscoveryStore::list`]. It is not persisted;
    /// decoded records start with `None`.
    pub status: Option<DiscoveryStatus>,
}

impl DiscoveredInterface {
    /// Raw 32-byte storage key derived from `info.transport_id` and `info.name`.
    /// Use [`Self::filename`] for the hexadecimal filename.
    pub fn discovery_hash(&self) -> [u8; 32] {
        discovery_hash(&self.info.transport_id, &self.info.name)
    }

    /// Hex-form of [`Self::discovery_hash`] — used as the on-disk filename.
    pub fn filename(&self) -> String {
        hex::encode(self.discovery_hash())
    }
}

/// `SHA-256(lowercase_hex(transport_id) || name_utf8)`, with no separator.
/// The name is used exactly as supplied; this helper does not sanitize it.
/// Changing the advertised name gives the same transport a different record key.
pub fn discovery_hash(transport_id: &[u8; 16], name: &str) -> [u8; 32] {
    let mut material = String::with_capacity(32 + name.len());
    material.push_str(&hex::encode(transport_id));
    material.push_str(name);
    rns_crypto::sha::full_hash(material.as_bytes())
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("msgpack decode: {0}")]
    Decode(String),
    #[error("msgpack encode: {0}")]
    Encode(String),
    #[error("unexpected top-level msgpack shape")]
    Shape,
}

/// File store rooted at `<storage_root>/discovery/interfaces/`.
///
/// Writes use a fixed `.tmp` sibling and rename, without fsync or an internal
/// writer lock. Serialize updates to the same key to avoid sidecar and merge
/// races. This is not a crash-durable transaction. Reads trust local field
/// values and load complete files without a size bound.
pub struct DiscoveryStore {
    root: PathBuf,
}

impl DiscoveryStore {
    /// Create the store directory if absent and return its path wrapper.
    /// Existing records are not scanned or validated by this call.
    pub fn open(storage_root: &Path) -> Result<Self, StorageError> {
        let root = storage_root.join("discovery").join("interfaces");
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Directory containing the per-interface files.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Write the record as upstream's `interface_discovered` does: a new file
    /// gets `heard_count` 0; an existing one keeps its `discovered` time and
    /// counts one more, starting again from 0 when it cannot be read.
    /// Other fields replace the old values; `status` is not serialized.
    ///
    /// This does not verify the stamp or prevent an older observation replacing
    /// a newer one. Changing the key leaves any prior record under its old key.
    pub fn upsert(&self, mut record: DiscoveredInterface) -> Result<(), StorageError> {
        let path = self.root.join(record.filename());

        record.heard_count = 0;
        if path.is_file() {
            let existing = std::fs::read(&path)
                .ok()
                .and_then(|bytes| decode_lookup(&bytes).ok())
                .filter(|l| l.contains_key("discovered") && l.contains_key("heard_count"));
            if let Some(existing) = existing {
                let discovered = timestamp(&existing, "discovered");
                if discovered != 0.0 {
                    record.discovered = discovered;
                }
                record.heard_count = u64_opt(&existing, "heard_count").unwrap_or(0);
            }
            record.heard_count = record.heard_count.saturating_add(1);
        }

        let tmp = path.with_extension("tmp");
        let encoded = encode_record(&record)?;
        std::fs::write(&tmp, encoded)?;
        match std::fs::rename(&tmp, &path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e.into())
            }
        }
    }

    /// Delete the exact transport/name record. Returns `false` when absent,
    /// `true` after removal, and an error for other filesystem failures.
    pub fn remove(&self, transport_id: &[u8; 16], name: &str) -> Result<bool, StorageError> {
        let fname = hex::encode(discovery_hash(transport_id, name));
        let path = self.root.join(fname);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// [`Self::list_filtered`] with no blackholed identities.
    pub fn list(
        &self,
        discovery_sources: Option<&[[u8; 16]]>,
    ) -> Result<Vec<DiscoveredInterface>, StorageError> {
        self.list_filtered(discovery_sources, &HashSet::new())
    }

    /// Read and maintain the store as upstream's `list_discovered_interfaces`
    /// does (RNS/Discovery.py), returning records sorted
    /// descending by `(status_code, stamp_value, last_heard)`.
    ///
    /// A record is deleted when it is older than seven days, lacks a transport
    /// or network ID, comes from a source outside `discovery_sources`, has an
    /// unlisted type, names a `blackholed` network or transport identity, or
    /// carries an invalid `reachable_on`. Files that cannot be read are kept
    /// and skipped. Names are sanitized again and `"None"` IFAC values dropped.
    /// `Some(&[])` excludes every source; `None` applies no source filter.
    pub fn list_filtered(
        &self,
        discovery_sources: Option<&[[u8; 16]]>,
        blackholed: &HashSet<[u8; 16]>,
    ) -> Result<Vec<DiscoveredInterface>, StorageError> {
        let now = unix_now();
        let mut out: Vec<DiscoveredInterface> = Vec::new();

        let read = match std::fs::read_dir(&self.root) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };

        for entry in read {
            let entry = entry?;
            let path = entry.path();
            // Skip .tmp sidecars and anything non-file.
            if !path.is_file() {
                continue;
            }
            if path.extension().is_some() {
                continue;
            }
            // Upstream logs and keeps a record it cannot read (Discovery.py).
            let corrupt = |path: &Path| {
                tracing::warn!(path = %path.display(), "discovered interface data file may be corrupt");
            };
            let remove = |path: &Path| {
                let _ = std::fs::remove_file(path);
            };
            let lookup = match std::fs::read(&path)
                .map_err(StorageError::from)
                .and_then(|bytes| decode_lookup(&bytes))
            {
                Ok(lookup) if lookup.contains_key("last_heard") && lookup.contains_key("name") => {
                    lookup
                }
                _ => {
                    corrupt(&path);
                    continue;
                }
            };
            let mut rec = record_from_lookup(&lookup);
            let heard_delta = now - rec.last_heard;
            if heard_delta > THRESHOLD_REMOVE_SECS as f64
                || !id_present(&lookup, "transport_id")
                || !id_present(&lookup, "network_id")
            {
                remove(&path);
                continue;
            }
            // Upstream's order matters: an ID that is not hex raises, which
            // keeps the file, unless an earlier rule already removed it.
            if let Some(sources) = discovery_sources {
                let Some(network_id) = hex16(&lookup, "network_id") else {
                    corrupt(&path);
                    continue;
                };
                if !sources.contains(&network_id) {
                    remove(&path);
                    continue;
                }
            }
            if !DISCOVERED_INTERFACE_TYPES.contains(&rec.info.interface_type.as_str()) {
                remove(&path);
                continue;
            }
            let (Some(network_id), Some(transport_id)) =
                (hex16(&lookup, "network_id"), hex16(&lookup, "transport_id"))
            else {
                corrupt(&path);
                continue;
            };
            if blackholed.contains(&network_id) || blackholed.contains(&transport_id) {
                remove(&path);
                continue;
            }
            if let Some(addr) = rec.info.reachable_on.as_deref() {
                match address::is_valid_address(addr) {
                    Some(true) => {}
                    Some(false) => {
                        remove(&path);
                        continue;
                    }
                    None => {
                        corrupt(&path);
                        continue;
                    }
                }
            }
            rec.info.name = sanitize_name(&rec.info.name);
            for ifac in [&mut rec.info.ifac_netname, &mut rec.info.ifac_netkey] {
                if ifac.as_deref() == Some("None") {
                    *ifac = None;
                }
            }
            rec.status = Some(classify(heard_delta));
            out.push(rec);
        }

        out.sort_by(|a, b| {
            let sa = a.status.map(DiscoveryStatus::code).unwrap_or(0);
            let sb = b.status.map(DiscoveryStatus::code).unwrap_or(0);
            sb.cmp(&sa)
                .then(b.stamp_value.total_cmp(&a.stamp_value))
                .then(b.last_heard.total_cmp(&a.last_heard))
        });

        Ok(out)
    }

    #[cfg(test)]
    fn load_raw(&self, path: &Path) -> Result<DiscoveredInterface, StorageError> {
        let bytes = std::fs::read(path)?;
        decode_record(&bytes)
    }
}

/// Classify elapsed seconds: `Available` through 24 hours, `Unknown` above
/// 24 hours through three days, and `Stale` above three days. This helper does
/// not apply the separate seven-day removal rule or probe an endpoint.
pub fn classify(heard_delta_secs: f64) -> DiscoveryStatus {
    if heard_delta_secs > THRESHOLD_STALE_SECS as f64 {
        DiscoveryStatus::Stale
    } else if heard_delta_secs > THRESHOLD_UNKNOWN_SECS as f64 {
        DiscoveryStatus::Unknown
    } else {
        DiscoveryStatus::Available
    }
}

fn unix_now() -> f64 {
    crate::now_f64()
}

// On-disk msgpack format mirrors Python's key schema for interop.

fn encode_record(rec: &DiscoveredInterface) -> Result<Vec<u8>, StorageError> {
    let mut map: Vec<(Value, Value)> = Vec::new();

    let i = &rec.info;
    map.push((s("type"), Value::from(i.interface_type.clone())));
    if let Some(impl_name) = &i.impl_name {
        map.push((s("impl_name"), Value::from(impl_name.clone())));
    }
    if let Some(impl_version) = &i.impl_version {
        map.push((s("version"), Value::from(impl_version.clone())));
    }
    map.push((s("transport"), Value::from(i.transport_enabled)));
    map.push((s("name"), Value::from(i.name.clone())));
    map.push((s("received"), Value::F64(rec.last_heard)));
    map.push((s("transport_id"), Value::from(hex::encode(i.transport_id))));
    map.push((s("network_id"), Value::from(hex::encode(rec.network_id))));
    map.push((s("hops"), Value::from(rec.hops)));
    map.push((s("value"), Value::F64(rec.stamp_value)));
    map.push((s("dst_cost"), i.dst_cost.map_or(Value::Nil, Value::F64)));
    map.push((s("pr_cost"), i.pr_cost.map_or(Value::Nil, Value::F64)));
    map.push((s("stamp"), Value::Binary(rec.stamp.clone())));
    map.push((s("latitude"), i.latitude.map_or(Value::Nil, Value::F64)));
    map.push((s("longitude"), i.longitude.map_or(Value::Nil, Value::F64)));
    map.push((s("height"), i.height.map_or(Value::Nil, Value::F64)));
    if let Some(addr) = &i.reachable_on {
        map.push((s("reachable_on"), Value::from(addr.clone())));
    }
    if let Some(p) = i.port {
        map.push((s("port"), Value::from(p)));
    }
    if let Some(n) = &i.ifac_netname {
        map.push((s("ifac_netname"), Value::from(n.clone())));
    }
    if let Some(k) = &i.ifac_netkey {
        map.push((s("ifac_netkey"), Value::from(k.clone())));
    }
    if let Some(f) = i.frequency {
        map.push((s("frequency"), Value::from(f)));
    }
    if let Some(b) = i.bandwidth {
        map.push((s("bandwidth"), Value::from(b)));
    }
    if let Some(sf) = i.spreading_factor {
        map.push((s("sf"), Value::from(sf)));
    }
    if let Some(cr) = i.coding_rate {
        map.push((s("cr"), Value::from(cr)));
    }
    if let Some(m) = &i.modulation {
        map.push((s("modulation"), m.to_value()));
    }
    if let Some(ch) = i.channel {
        map.push((s("channel"), Value::from(ch)));
    }
    if let Some(entry) = config_entry(rec) {
        map.push((s("config_entry"), Value::from(entry)));
    }
    map.push((
        s("discovery_hash"),
        Value::Binary(rec.discovery_hash().to_vec()),
    ));
    if let Some(addr) = i.operator_lxmf_address {
        map.push((s("operator_lxmf_address"), Value::from(hex::encode(addr))));
    }
    map.push((s("discovered"), Value::F64(rec.discovered)));
    map.push((s("last_heard"), Value::F64(rec.last_heard)));
    map.push((s("heard_count"), Value::from(rec.heard_count)));

    let value = Value::Map(map);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &value).map_err(|e| StorageError::Encode(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
fn decode_record(bytes: &[u8]) -> Result<DiscoveredInterface, StorageError> {
    decode_lookup(bytes).map(|lookup| record_from_lookup(&lookup))
}

/// Upstream treats a missing or empty ID as absent (RNS/Discovery.py).
fn id_present(lookup: &HashMap<String, Value>, k: &str) -> bool {
    match lookup.get(k) {
        None | Some(Value::Nil) => false,
        Some(Value::String(s)) => !s.as_bytes().is_empty(),
        Some(Value::Binary(b)) => !b.is_empty(),
        Some(_) => true,
    }
}

fn decode_lookup(bytes: &[u8]) -> Result<HashMap<String, Value>, StorageError> {
    let mut cur = std::io::Cursor::new(bytes);
    let value =
        rmpv::decode::read_value(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
    let map = match value {
        Value::Map(m) => m,
        _ => return Err(StorageError::Shape),
    };

    let mut lookup: HashMap<String, Value> = HashMap::new();
    for (k, v) in map {
        if let Some(key) = match &k {
            Value::String(s) => s.as_str().map(str::to_owned),
            _ => None,
        } {
            lookup.insert(key, v);
        }
    }
    Ok(lookup)
}

fn record_from_lookup(lookup: &HashMap<String, Value>) -> DiscoveredInterface {
    let lookup = lookup.clone();
    let info = DiscoveryInfo {
        interface_type: str_or_default(&lookup, "type"),
        impl_name: str_opt(&lookup, "impl_name"),
        impl_version: str_opt(&lookup, "version"),
        dst_cost: f64_optional(&lookup, "dst_cost"),
        pr_cost: f64_optional(&lookup, "pr_cost"),
        transport_enabled: bool_or_default(&lookup, "transport"),
        transport_id: hex16(&lookup, "transport_id").unwrap_or([0; 16]),
        name: str_or_default(&lookup, "name"),
        reachable_on: str_opt(&lookup, "reachable_on"),
        latitude: f64_optional(&lookup, "latitude"),
        longitude: f64_optional(&lookup, "longitude"),
        height: f64_optional(&lookup, "height"),
        port: u64_opt(&lookup, "port").map(|n| n.min(u16::MAX as u64) as u16),
        ifac_netname: str_opt(&lookup, "ifac_netname"),
        ifac_netkey: str_opt(&lookup, "ifac_netkey"),
        frequency: u64_opt(&lookup, "frequency"),
        bandwidth: u64_opt(&lookup, "bandwidth"),
        spreading_factor: u64_opt(&lookup, "sf").map(|n| n.min(u8::MAX as u64) as u8),
        coding_rate: u64_opt(&lookup, "cr").map(|n| n.min(u8::MAX as u64) as u8),
        modulation: lookup
            .get("modulation")
            .and_then(DiscoveryModulation::from_value),
        channel: u64_opt(&lookup, "channel").map(|n| n.min(u16::MAX as u64) as u16),
        operator_lxmf_address: hex16(&lookup, "operator_lxmf_address"),
    };

    let stamp = lookup
        .get("stamp")
        .and_then(|v| match v {
            Value::Binary(b) => Some(b.clone()),
            _ => None,
        })
        .unwrap_or_else(|| vec![0; STAMP_SIZE]);

    DiscoveredInterface {
        info,
        network_id: hex16(&lookup, "network_id").unwrap_or([0; 16]),
        hops: u64_opt(&lookup, "hops").unwrap_or(0).min(u8::MAX as u64) as u8,
        stamp_value: f64_optional(&lookup, "value").unwrap_or(0.0),
        stamp,
        discovered: timestamp(&lookup, "discovered"),
        last_heard: timestamp(&lookup, "last_heard"),
        heard_count: u64_opt(&lookup, "heard_count").unwrap_or(0),
        status: None,
    }
}

/// The configuration snippet upstream stores with each record and
/// `rnstatus -D` prints (RNS/Discovery.py). Unlike upstream, announced strings
/// lose control characters other than tab, and line separators, so none can
/// add a line to the entry; the record's own fields are unchanged.
pub fn config_entry(rec: &DiscoveredInterface) -> Option<String> {
    let i = &rec.info;
    let opt = |v: Option<String>| v.unwrap_or_else(|| "None".to_string());
    let num = |v: Option<u64>| opt(v.map(|n| n.to_string()));
    let netname = i.ifac_netname.as_deref().map_or(String::new(), |n| {
        format!("\n  network_name = {}", config_text(n))
    });
    let netkey = i.ifac_netkey.as_deref().map_or(String::new(), |k| {
        format!("\n  passphrase = {}", config_text(k))
    });
    let identity = format!("\n  transport_identity = {}", hex::encode(i.transport_id));
    let name = config_text(&i.name);
    Some(match i.interface_type.as_str() {
        "BackboneInterface" | "TCPServerInterface" => {
            let (kind, remote) = if cfg!(any(windows, target_vendor = "apple")) {
                ("TCPClientInterface", "target_host")
            } else {
                ("BackboneInterface", "remote")
            };
            format!(
                "[[{name}]]\n  type = {kind}\n  enabled = yes\n  {remote} = {}\n  target_port = {}{identity}{netname}{netkey}",
                opt(i.reachable_on.clone()),
                num(i.port.map(u64::from))
            )
        }
        "I2PInterface" => format!(
            "[[{name}]]\n  type = I2PInterface\n  enabled = yes\n  peers = {}.b32.i2p{identity}{netname}{netkey}",
            opt(i.reachable_on.clone())
        ),
        "RNodeInterface" => format!(
            "[[{name}]]\n  type = RNodeInterface\n  enabled = yes\n  port = \n  frequency = {}\n  bandwidth = {}\n  spreadingfactor = {}\n  codingrate = {}\n  txpower = {netname}{netkey}",
            num(i.frequency),
            num(i.bandwidth),
            num(i.spreading_factor.map(u64::from)),
            num(i.coding_rate.map(u64::from))
        ),
        "WeaveInterface" => format!(
            "[[{name}]]\n  type = WeaveInterface\n  enabled = yes\n  port = {netname}{netkey}"
        ),
        "KISSInterface" => format!(
            "[[{name}]]\n  type = KISSInterface\n  enabled = yes\n  port = \n  # Frequency: {}\n  # Bandwidth: {}\n  # Modulation: {}{identity}{netname}{netkey}",
            num(i.frequency),
            num(i.bandwidth),
            opt(i.modulation.as_ref().map(|m| config_text(&m.to_string())))
        ),
        _ => return None,
    })
}

/// Drops every character Python's `str.splitlines` breaks on, ESC, and the
/// other C0/C1 controls; tab stays, as upstream writes it.
fn config_text(s: &str) -> String {
    s.chars()
        .filter(|&c| c == '\t' || !(c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')))
        .collect()
}

fn s(x: &str) -> Value {
    Value::from(x)
}

fn str_or_default(lookup: &HashMap<String, Value>, k: &str) -> String {
    match lookup.get(k) {
        Some(Value::String(s)) => s.as_str().unwrap_or("").to_string(),
        Some(Value::Binary(b)) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    }
}

fn str_opt(lookup: &HashMap<String, Value>, k: &str) -> Option<String> {
    match lookup.get(k) {
        Some(Value::String(s)) => Some(s.as_str().unwrap_or("").to_string()),
        Some(Value::Binary(b)) => Some(String::from_utf8_lossy(b).into_owned()),
        _ => None,
    }
}

fn bool_or_default(lookup: &HashMap<String, Value>, k: &str) -> bool {
    match lookup.get(k) {
        Some(Value::Boolean(b)) => *b,
        _ => false,
    }
}

fn f64_optional(lookup: &HashMap<String, Value>, k: &str) -> Option<f64> {
    match lookup.get(k) {
        Some(Value::F64(f)) => Some(*f),
        Some(Value::F32(f)) => Some(*f as f64),
        Some(Value::Integer(n)) => n.as_f64(),
        _ => None,
    }
}

/// Python stores `time.time()` floats; integer timestamps from older Rust stores still read.
fn timestamp(lookup: &HashMap<String, Value>, k: &str) -> f64 {
    f64_optional(lookup, k)
        .filter(|t| t.is_finite() && *t > 0.0)
        .unwrap_or(0.0)
}

fn u64_opt(lookup: &HashMap<String, Value>, k: &str) -> Option<u64> {
    lookup.get(k).and_then(|v| v.as_u64())
}

fn hex16(lookup: &HashMap<String, Value>, k: &str) -> Option<[u8; 16]> {
    let hex_str = match lookup.get(k)? {
        Value::String(s) => s.as_str()?.to_string(),
        Value::Binary(b) => {
            if b.len() == 16 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(b);
                return Some(arr);
            }
            String::from_utf8_lossy(b).into_owned()
        }
        _ => return None,
    };
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "reticulum_rs_discovery_{}_{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn record(name: &str, transport_id: [u8; 16]) -> DiscoveredInterface {
        DiscoveredInterface {
            info: DiscoveryInfo {
                name: name.into(),
                transport_id,
                interface_type: "BackboneInterface".into(),
                transport_enabled: true,
                reachable_on: Some("1.2.3.4".into()),
                latitude: Some(0.0),
                longitude: Some(0.0),
                height: Some(0.0),
                port: Some(4965),
                ..Default::default()
            },
            network_id: transport_id,
            hops: 2,
            stamp_value: 14.0,
            stamp: vec![0xAA; STAMP_SIZE],
            discovered: 1_000_000.0,
            last_heard: 1_000_010.0,
            heard_count: 0,
            status: None,
        }
    }

    #[test]
    fn nullable_disk_records_reload_and_update_without_losing_metadata() {
        let dir = tmpdir("nullable_reload");
        let store = DiscoveryStore::open(&dir).unwrap();
        for mask in 0..8 {
            let mut original = record(&format!("mask-{mask}"), [mask; 16]);
            original.last_heard = unix_now();
            original.info.latitude = (mask & 1 != 0).then_some(0.0);
            original.info.longitude = (mask & 2 != 0).then_some(0.0);
            original.info.height = (mask & 4 != 0).then_some(0.0);
            store.upsert(original.clone()).unwrap();
            let reopened = DiscoveryStore::open(&dir).unwrap();
            let read = reopened
                .list(None)
                .unwrap()
                .into_iter()
                .find(|r| r.info.name == original.info.name)
                .unwrap();
            assert_eq!(read.info, original.info);
            assert_eq!(read.discovered, original.discovered);
            assert_eq!(read.last_heard, original.last_heard);
            assert_eq!(read.heard_count, 0);
            assert_eq!(read.network_id, original.network_id);
            let mut update = original.clone();
            update.discovered += 123.0;
            reopened.upsert(update).unwrap();
            let read = reopened
                .load_raw(&reopened.root().join(original.filename()))
                .unwrap();
            assert_eq!(read.discovered, original.discovered);
            assert_eq!(read.heard_count, 1);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn float_timestamps_and_fractional_value_decode() {
        let original = record("floats", [4; 16]);
        let encoded = encode_record(&original).unwrap();
        let Value::Map(mut entries) = rmpv::decode::read_value(&mut &encoded[..]).unwrap() else {
            panic!("map");
        };
        let now = unix_now() + 0.75;
        for (k, v) in &mut entries {
            match k.as_str() {
                Some("discovered") | Some("last_heard") => *v = Value::F64(now),
                Some("value") => *v = Value::F64(8.58203125),
                _ => {}
            }
        }
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).unwrap();
        let read = decode_record(&bytes).unwrap();
        assert_eq!(read.last_heard, now);
        assert_eq!(read.discovered, now);
        assert_eq!(read.stamp_value, 8.58203125);

        let dir = tmpdir("float_records");
        let store = DiscoveryStore::open(&dir).unwrap();
        let path = store.root().join(original.filename());
        std::fs::write(&path, &bytes).unwrap();
        let listed = store.list(None).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].stamp_value, 8.58203125);
        assert!(path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cost_fields_round_trip_and_integer_value_still_decodes() {
        let mut original = record("costs", [5; 16]);
        original.info.dst_cost = Some(23.5);
        original.info.pr_cost = Some(15.80078125);
        original.stamp_value = 16.5;
        let read = decode_record(&encode_record(&original).unwrap()).unwrap();
        assert_eq!(read.info.dst_cost, Some(23.5));
        assert_eq!(read.info.pr_cost, Some(15.80078125));
        assert_eq!(read.stamp_value, 16.5);

        let encoded = encode_record(&record("int", [6; 16])).unwrap();
        let Value::Map(mut entries) = rmpv::decode::read_value(&mut &encoded[..]).unwrap() else {
            panic!("map");
        };
        for (k, v) in &mut entries {
            if k.as_str() == Some("value") {
                *v = Value::from(14u8);
            }
        }
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).unwrap();
        assert_eq!(decode_record(&bytes).unwrap().stamp_value, 14.0);
    }

    #[test]
    fn legacy_disk_nil_missing_and_numeric_zero_are_distinct() {
        let original = record("legacy", [3; 16]);
        let encoded = encode_record(&original).unwrap();
        let Value::Map(mut entries) = rmpv::decode::read_value(&mut &encoded[..]).unwrap() else {
            panic!("map");
        };
        entries.retain(|(k, _)| k.as_str() != Some("height"));
        for (k, v) in &mut entries {
            if k.as_str() == Some("longitude") {
                *v = Value::Nil;
            }
        }
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).unwrap();
        let read = decode_record(&bytes).unwrap();
        assert_eq!(read.info.latitude, Some(0.0));
        assert_eq!(read.info.longitude, None);
        assert_eq!(read.info.height, None);
    }

    #[test]
    fn discovery_hash_is_deterministic() {
        let a = discovery_hash(&[0x11; 16], "alpha");
        let b = discovery_hash(&[0x11; 16], "alpha");
        let c = discovery_hash(&[0x11; 16], "beta");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn upsert_then_list() {
        let dir = tmpdir("upsert");
        let store = DiscoveryStore::open(&dir).unwrap();
        let now = unix_now();
        let mut r = record("alpha", [0x11; 16]);
        r.last_heard = now;
        store.upsert(r.clone()).unwrap();

        let listed = store.list(None).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].heard_count, 0);
        assert_eq!(listed[0].status, Some(DiscoveryStatus::Available));
    }

    #[test]
    fn upsert_merges_discovered_and_heard_count() {
        let dir = tmpdir("merge");
        let store = DiscoveryStore::open(&dir).unwrap();
        let now = unix_now();
        let mut first = record("alpha", [0x11; 16]);
        first.discovered = 42.0;
        first.last_heard = now;
        store.upsert(first.clone()).unwrap();

        let mut second = record("alpha", [0x11; 16]);
        second.discovered = 999.0; // should be ignored on merge
        second.last_heard = now + 1.0;
        store.upsert(second).unwrap();

        let listed = store.list(None).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].discovered, 42.0);
        assert_eq!(listed[0].heard_count, 1);
    }

    #[test]
    fn list_filters_unauthorized_sources() {
        let dir = tmpdir("sources");
        let store = DiscoveryStore::open(&dir).unwrap();
        let now = unix_now();
        let mut a = record("alpha", [0x11; 16]);
        a.last_heard = now;
        let mut b = record("beta", [0x22; 16]);
        b.last_heard = now;
        store.upsert(a).unwrap();
        store.upsert(b).unwrap();

        let allowed: &[[u8; 16]] = &[[0x11; 16]];
        let listed = store.list(Some(allowed)).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].info.transport_id, [0x11; 16]);

        // The non-authorized record should have been removed on read.
        let listed_again = store.list(None).unwrap();
        assert_eq!(listed_again.len(), 1);
    }

    /// Python stores the announcer's stack as `impl_name` and `version`
    /// (Discovery.py).
    #[test]
    fn records_keep_the_announcing_implementation() {
        let dir = tmpdir("implementation");
        let store = DiscoveryStore::open(&dir).unwrap();
        let mut r = record("versioned", [0x31; 16]);
        r.last_heard = unix_now();
        r.info.impl_name = Some("RNS".into());
        r.info.impl_version = Some("1.5.5".into());
        store.upsert(r).unwrap();

        let listed = store.list(None).unwrap();
        assert_eq!(listed[0].info.impl_name.as_deref(), Some("RNS"));
        assert_eq!(listed[0].info.impl_version.as_deref(), Some("1.5.5"));
        let raw = std::fs::read(store.root().join(listed[0].filename())).unwrap();
        let Value::Map(map) = rmpv::decode::read_value(&mut raw.as_slice()).unwrap() else {
            panic!("record is a map");
        };
        let field = |name: &str| {
            map.iter()
                .find(|(k, _)| k.as_str() == Some(name))
                .and_then(|(_, v)| v.as_str().map(str::to_string))
        };
        assert_eq!(field("impl_name").as_deref(), Some("RNS"));
        assert_eq!(field("version").as_deref(), Some("1.5.5"));
    }

    /// Python lists only `InterfaceDiscovery.DISCOVERABLE_TYPES` and removes
    /// other records, such as a KISS TCP client's (Discovery.py).
    #[test]
    fn listing_removes_types_python_does_not_list() {
        let dir = tmpdir("listed_types");
        let store = DiscoveryStore::open(&dir).unwrap();
        let now = unix_now();
        for (id, name, interface_type) in [
            (1, "backbone", "BackboneInterface"),
            (2, "kiss-tcp", "TCPClientInterface"),
            (3, "rnode", "RNodeInterface"),
        ] {
            let mut r = record(name, [id; 16]);
            r.info.interface_type = interface_type.into();
            r.last_heard = now;
            store.upsert(r).unwrap();
        }

        let listed: Vec<String> = store
            .list(None)
            .unwrap()
            .into_iter()
            .map(|r| r.info.name)
            .collect();
        assert_eq!(listed.len(), 2);
        assert!(!listed.contains(&"kiss-tcp".to_string()));
        assert_eq!(
            std::fs::read_dir(store.root()).unwrap().count(),
            2,
            "the unlisted record is removed from disk"
        );
    }

    #[test]
    fn list_removes_expired() {
        let dir = tmpdir("expired");
        let store = DiscoveryStore::open(&dir).unwrap();
        let mut r = record("old", [0x11; 16]);
        r.last_heard = 0.0; // ancient
        store.upsert(r).unwrap();

        let listed = store.list(None).unwrap();
        assert!(listed.is_empty());
    }

    #[test]
    fn list_sorts_by_status_then_value_then_recency() {
        let dir = tmpdir("sort");
        let store = DiscoveryStore::open(&dir).unwrap();
        let now = unix_now();

        // Available, low stamp value, old
        let mut a = record("a", [0x01; 16]);
        a.stamp_value = 10.0;
        a.last_heard = now - 100.0;
        // Available, high stamp value, recent
        let mut b = record("b", [0x02; 16]);
        b.stamp_value = 20.0;
        b.last_heard = now - 10.0;
        // Unknown (freshness bucket)
        let mut c = record("c", [0x03; 16]);
        c.last_heard = now - THRESHOLD_UNKNOWN_SECS as f64 - 1.0;
        c.stamp_value = 30.0;

        store.upsert(a).unwrap();
        store.upsert(b).unwrap();
        store.upsert(c).unwrap();

        let listed = store.list(None).unwrap();
        assert_eq!(listed.len(), 3);
        // b (Available, value 20, recent) before a (Available, value 10), both before c (Unknown)
        assert_eq!(listed[0].info.name, "b");
        assert_eq!(listed[1].info.name, "a");
        assert_eq!(listed[2].info.name, "c");
    }

    #[test]
    fn remove_deletes_record() {
        let dir = tmpdir("remove");
        let store = DiscoveryStore::open(&dir).unwrap();
        let r = record("alpha", [0x11; 16]);
        store.upsert(r.clone()).unwrap();
        assert!(store.remove(&r.info.transport_id, &r.info.name).unwrap());
        assert!(store.list(None).unwrap().is_empty());
        // Second remove is a no-op.
        assert!(!store.remove(&r.info.transport_id, &r.info.name).unwrap());
    }

    #[test]
    fn corrupt_file_is_skipped_and_kept() {
        // Upstream only logs an unreadable record (Discovery.py).
        let dir = tmpdir("corrupt");
        let store = DiscoveryStore::open(&dir).unwrap();
        let garbage = store.root().join(hex::encode([0xAB; 32]));
        std::fs::write(&garbage, b"not valid msgpack").unwrap();
        assert!(store.list(None).unwrap().is_empty());
        assert!(garbage.is_file());
    }

    /// Python `str.splitlines` boundaries, which ConfigObj splits a pasted entry on.
    fn config_lines(entry: &str) -> Vec<&str> {
        entry
            .split([
                '\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}',
                '\u{2029}',
            ])
            .collect()
    }

    /// Announced strings reach `config_entry` after decoding as a receiver
    /// stores them, and none of them can add a line to the pasted entry.
    #[test]
    fn announced_strings_cannot_add_config_lines() {
        use crate::discovery::app_data::{decode_info, encode_info};
        let inject = "\n[[Evil]]\n  type = PipeInterface\n  command = touch /tmp/pwned";
        let breaks = "\r\x0b\x0c\x1c\x1d\x1e\u{85}\u{2028}\u{2029}\x1b[2J\u{9b}31m";
        for interface_type in DISCOVERED_INTERFACE_TYPES {
            let mut benign = record("Relay", [0x41; 16]);
            benign.info.interface_type = interface_type.to_string();
            benign.info.reachable_on = Some("relay.example.org".into());
            benign.info.ifac_netname = Some("net".into());
            benign.info.ifac_netkey = Some("key".into());
            benign.info.frequency = Some(869_525_000);
            benign.info.bandwidth = Some(125_000);
            benign.info.spreading_factor = Some(8);
            benign.info.coding_rate = Some(5);
            benign.info.channel = Some(1);
            benign.info.modulation = Some(DiscoveryModulation::Str("GFSK".into()));

            let mut announced = benign.info.clone();
            announced.name = format!("Relay{inject}{breaks}x");
            announced.ifac_netname = Some(format!("net{inject}{breaks}"));
            announced.ifac_netkey = Some(format!("key{inject}{breaks}"));
            announced.modulation = Some(DiscoveryModulation::Str(format!("GFSK{inject}{breaks}")));
            let mut evil = benign.clone();
            evil.info = decode_info(&encode_info(&announced).unwrap().packed).unwrap();
            assert!(evil.info.name.contains("\n[[Evil]]"), "stored as decoded");

            let benign_entry = config_entry(&benign).unwrap();
            let entry = config_entry(&evil).unwrap();
            let lines = config_lines(&entry);
            assert_eq!(
                lines.len(),
                config_lines(&benign_entry).len(),
                "{interface_type}: {entry:?}"
            );
            assert_eq!(lines.iter().filter(|l| l.starts_with("[[")).count(), 1);
            assert!(
                !entry.chars().any(|c| c != '\n' && c.is_control()),
                "{interface_type}: {entry:?}"
            );
            assert!(lines[0].starts_with("[[Relay[[Evil]] type = PipeInterface"));
        }
    }

    /// Tab is not a line boundary; upstream's entry keeps it (discovery-decode golden).
    #[test]
    fn config_entry_keeps_tabs_as_upstream_does() {
        let mut r = record("A\tB  C (x)", [0x42; 16]);
        r.info.ifac_netkey = Some("k\tv".into());
        let entry = config_entry(&r).unwrap();
        assert!(entry.starts_with("[[A\tB  C (x)]]\n"));
        assert!(entry.ends_with("\n  passphrase = k\tv"));
    }

    #[test]
    fn classify_thresholds() {
        assert_eq!(classify(0.0), DiscoveryStatus::Available);
        assert_eq!(
            classify(THRESHOLD_UNKNOWN_SECS as f64 + 1.0),
            DiscoveryStatus::Unknown
        );
        assert_eq!(
            classify(THRESHOLD_STALE_SECS as f64 + 1.0),
            DiscoveryStatus::Stale
        );
    }
}
