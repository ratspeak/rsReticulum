//! Persistence for discovered interfaces — one msgpack file per learned
//! interface named after `discovery_hash` hex (matches Python `InterfaceDiscovery`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rmpv::Value;
use thiserror::Error;

use super::app_data::DiscoveryInfo;
use super::constants::{
    STAMP_SIZE, THRESHOLD_REMOVE_SECS, THRESHOLD_STALE_SECS, THRESHOLD_UNKNOWN_SECS,
};

/// Freshness status for a learned interface.
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

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stale => "stale",
            Self::Unknown => "unknown",
            Self::Available => "available",
        }
    }
}

/// A single learned interface.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredInterface {
    pub info: DiscoveryInfo,
    /// Source transport ID — lets a reader filter by `interface_discovery_sources`.
    pub network_id: [u8; 16],
    /// Distance hint when the announce was received (0 if unknown).
    pub hops: u8,
    /// Stamp value observed on the latest announce.
    pub stamp_value: u8,
    /// The actual stamp bytes last observed (useful for diagnostics).
    pub stamp: Vec<u8>,
    /// Unix seconds — first time this interface was learned.
    pub discovered: u64,
    /// Unix seconds — most recent announce.
    pub last_heard: u64,
    /// How many announces contributed to this record (includes the first).
    pub heard_count: u64,
    /// Cached status at read time (None until classified).
    pub status: Option<DiscoveryStatus>,
}

impl DiscoveredInterface {
    /// Filename stem on disk: hex of `discovery_hash`.
    pub fn discovery_hash(&self) -> [u8; 32] {
        discovery_hash(&self.info.transport_id, &self.info.name)
    }

    /// Hex-form of [`Self::discovery_hash`] — used as the on-disk filename.
    pub fn filename(&self) -> String {
        hex::encode(self.discovery_hash())
    }
}

/// `SHA-256(transport_id_hex_ascii || name_utf8)`.
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

/// Persistent store rooted at `<storagepath>/discovery/interfaces/`.
///
/// Writes atomically via a `.tmp` sidecar + rename.
pub struct DiscoveryStore {
    root: PathBuf,
}

impl DiscoveryStore {
    /// Open (and create if absent) the store under `storage_root`.
    pub fn open(storage_root: &Path) -> Result<Self, StorageError> {
        let root = storage_root.join("discovery").join("interfaces");
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Directory containing the per-interface files.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Write or update; existing `discovered` + `heard_count` are merged in.
    pub fn upsert(&self, mut record: DiscoveredInterface) -> Result<(), StorageError> {
        let path = self.root.join(record.filename());

        if let Ok(existing) = self.load_raw(&path) {
            record.discovered = existing.discovered;
            record.heard_count = existing.heard_count.saturating_add(1);
        } else {
            record.heard_count = 1;
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

    /// Remove a single record; returns `true` if one was present.
    pub fn remove(&self, transport_id: &[u8; 16], name: &str) -> Result<bool, StorageError> {
        let fname = hex::encode(discovery_hash(transport_id, name));
        let path = self.root.join(fname);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// List records sorted desc by `(status_code, stamp_value, last_heard)`.
    /// Expired entries are culled from disk; `discovery_sources` (when set)
    /// filters out records whose `network_id` is not in the set.
    pub fn list(
        &self,
        discovery_sources: Option<&[[u8; 16]]>,
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
            let rec = match self.load_raw(&path) {
                Ok(r) => r,
                Err(_) => {
                    // Corrupt file: remove so future reads don't keep failing.
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
            };

            let heard_delta = now.saturating_sub(rec.last_heard);
            let mut should_remove = heard_delta > THRESHOLD_REMOVE_SECS;
            if let Some(sources) = discovery_sources {
                if !sources.iter().any(|s| s == &rec.network_id) {
                    should_remove = true;
                }
            }
            if should_remove {
                let _ = std::fs::remove_file(&path);
                continue;
            }

            let status = classify(heard_delta);
            let mut enriched = rec;
            enriched.status = Some(status);
            out.push(enriched);
        }

        out.sort_by(|a, b| {
            let sa = a.status.map(DiscoveryStatus::code).unwrap_or(0);
            let sb = b.status.map(DiscoveryStatus::code).unwrap_or(0);
            sb.cmp(&sa)
                .then(b.stamp_value.cmp(&a.stamp_value))
                .then(b.last_heard.cmp(&a.last_heard))
        });

        Ok(out)
    }

    fn load_raw(&self, path: &Path) -> Result<DiscoveredInterface, StorageError> {
        let bytes = std::fs::read(path)?;
        decode_record(&bytes)
    }
}

/// Classify a (now - last_heard) delta into a status bucket. Exposed so
/// callers that already have a record in hand can avoid a re-read.
pub fn classify(heard_delta_secs: u64) -> DiscoveryStatus {
    if heard_delta_secs > THRESHOLD_STALE_SECS {
        DiscoveryStatus::Stale
    } else if heard_delta_secs > THRESHOLD_UNKNOWN_SECS {
        DiscoveryStatus::Unknown
    } else {
        DiscoveryStatus::Available
    }
}

fn unix_now() -> u64 {
    crate::now_f64() as u64
}

// On-disk msgpack format mirrors Python's key schema for interop.

fn encode_record(rec: &DiscoveredInterface) -> Result<Vec<u8>, StorageError> {
    let mut map: Vec<(Value, Value)> = Vec::new();

    let i = &rec.info;
    map.push((s("type"), Value::from(i.interface_type.clone())));
    map.push((s("transport"), Value::from(i.transport_enabled)));
    map.push((s("name"), Value::from(i.name.clone())));
    map.push((s("transport_id"), Value::from(hex::encode(i.transport_id))));
    map.push((s("network_id"), Value::from(hex::encode(rec.network_id))));
    map.push((s("hops"), Value::from(rec.hops)));
    map.push((s("value"), Value::from(rec.stamp_value)));
    map.push((s("stamp"), Value::Binary(rec.stamp.clone())));
    map.push((s("latitude"), Value::F64(i.latitude)));
    map.push((s("longitude"), Value::F64(i.longitude)));
    map.push((s("height"), Value::F64(i.height)));
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
        map.push((s("modulation"), Value::from(m.clone())));
    }
    if let Some(ch) = i.channel {
        map.push((s("channel"), Value::from(ch)));
    }
    map.push((s("discovered"), Value::from(rec.discovered)));
    map.push((s("last_heard"), Value::from(rec.last_heard)));
    map.push((s("heard_count"), Value::from(rec.heard_count)));

    let value = Value::Map(map);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &value).map_err(|e| StorageError::Encode(e.to_string()))?;
    Ok(buf)
}

fn decode_record(bytes: &[u8]) -> Result<DiscoveredInterface, StorageError> {
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

    let info = DiscoveryInfo {
        interface_type: str_or_default(&lookup, "type"),
        transport_enabled: bool_or_default(&lookup, "transport"),
        transport_id: hex16(&lookup, "transport_id").unwrap_or([0; 16]),
        name: str_or_default(&lookup, "name"),
        reachable_on: str_opt(&lookup, "reachable_on"),
        latitude: f64_or_default(&lookup, "latitude"),
        longitude: f64_or_default(&lookup, "longitude"),
        height: f64_or_default(&lookup, "height"),
        port: u64_opt(&lookup, "port").map(|n| n.min(u16::MAX as u64) as u16),
        ifac_netname: str_opt(&lookup, "ifac_netname"),
        ifac_netkey: str_opt(&lookup, "ifac_netkey"),
        frequency: u64_opt(&lookup, "frequency"),
        bandwidth: u64_opt(&lookup, "bandwidth"),
        spreading_factor: u64_opt(&lookup, "sf").map(|n| n.min(u8::MAX as u64) as u8),
        coding_rate: u64_opt(&lookup, "cr").map(|n| n.min(u8::MAX as u64) as u8),
        modulation: str_opt(&lookup, "modulation"),
        channel: u64_opt(&lookup, "channel").map(|n| n.min(u16::MAX as u64) as u16),
    };

    let stamp = lookup
        .get("stamp")
        .and_then(|v| match v {
            Value::Binary(b) => Some(b.clone()),
            _ => None,
        })
        .unwrap_or_else(|| vec![0; STAMP_SIZE]);

    Ok(DiscoveredInterface {
        info,
        network_id: hex16(&lookup, "network_id").unwrap_or([0; 16]),
        hops: u64_opt(&lookup, "hops").unwrap_or(0).min(u8::MAX as u64) as u8,
        stamp_value: u64_opt(&lookup, "value").unwrap_or(0).min(u8::MAX as u64) as u8,
        stamp,
        discovered: u64_opt(&lookup, "discovered").unwrap_or(0),
        last_heard: u64_opt(&lookup, "last_heard").unwrap_or(0),
        heard_count: u64_opt(&lookup, "heard_count").unwrap_or(0),
        status: None,
    })
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

fn f64_or_default(lookup: &HashMap<String, Value>, k: &str) -> f64 {
    match lookup.get(k) {
        Some(Value::F64(f)) => *f,
        Some(Value::F32(f)) => *f as f64,
        Some(Value::Integer(n)) => n.as_f64().unwrap_or(0.0),
        _ => 0.0,
    }
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
                latitude: 0.0,
                longitude: 0.0,
                height: 0.0,
                port: Some(4965),
                ..Default::default()
            },
            network_id: transport_id,
            hops: 2,
            stamp_value: 14,
            stamp: vec![0xAA; STAMP_SIZE],
            discovered: 1_000_000,
            last_heard: 1_000_010,
            heard_count: 0,
            status: None,
        }
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
        assert_eq!(listed[0].heard_count, 1);
        assert_eq!(listed[0].status, Some(DiscoveryStatus::Available));
    }

    #[test]
    fn upsert_merges_discovered_and_heard_count() {
        let dir = tmpdir("merge");
        let store = DiscoveryStore::open(&dir).unwrap();
        let now = unix_now();
        let mut first = record("alpha", [0x11; 16]);
        first.discovered = 42;
        first.last_heard = now;
        store.upsert(first.clone()).unwrap();

        let mut second = record("alpha", [0x11; 16]);
        second.discovered = 999; // should be ignored on merge
        second.last_heard = now + 1;
        store.upsert(second).unwrap();

        let listed = store.list(None).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].discovered, 42);
        assert_eq!(listed[0].heard_count, 2);
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

    #[test]
    fn list_removes_expired() {
        let dir = tmpdir("expired");
        let store = DiscoveryStore::open(&dir).unwrap();
        let mut r = record("old", [0x11; 16]);
        r.last_heard = 0; // ancient
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
        a.stamp_value = 10;
        a.last_heard = now - 100;
        // Available, high stamp value, recent
        let mut b = record("b", [0x02; 16]);
        b.stamp_value = 20;
        b.last_heard = now - 10;
        // Unknown (freshness bucket)
        let mut c = record("c", [0x03; 16]);
        c.last_heard = now - THRESHOLD_UNKNOWN_SECS - 1;
        c.stamp_value = 30;

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
    fn corrupt_file_is_culled_on_read() {
        let dir = tmpdir("corrupt");
        let store = DiscoveryStore::open(&dir).unwrap();
        let garbage_name = hex::encode([0xAB; 32]);
        std::fs::write(store.root().join(garbage_name), b"not valid msgpack").unwrap();
        assert!(store.list(None).unwrap().is_empty());
    }

    #[test]
    fn classify_thresholds() {
        assert_eq!(classify(0), DiscoveryStatus::Available);
        assert_eq!(
            classify(THRESHOLD_UNKNOWN_SECS + 1),
            DiscoveryStatus::Unknown
        );
        assert_eq!(classify(THRESHOLD_STALE_SECS + 1), DiscoveryStatus::Stale);
    }
}
