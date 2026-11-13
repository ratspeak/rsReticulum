//! One-way importers for the pre-SQLite files. Each function reads one source,
//! writes through the given store, and returns the paths the caller may remove
//! after its own transaction has committed. Nothing is renamed or unlinked here.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rmpv::Value;
use rns_wire::constants::RATCHET_EXPIRY;

use super::{
    AnnounceCacheStore, AnnounceRow, DestHash, KdBatch, KnownDestinationRow, KnownDestinationStore,
    PacketHash, Ratchet, RatchetRow, RejectedTable, StoreError,
};
use crate::persistence::{self, PersistenceError};

/// Rows written from one legacy source, and the files that may now be removed.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct LegacyImport {
    imported: usize,
    rejected: usize,
    removable: Vec<PathBuf>,
}

impl LegacyImport {
    /// Rows the store accepted.
    pub fn imported(&self) -> usize {
        self.imported
    }

    /// Rows the store rejected on its own constraints.
    pub fn rejected(&self) -> usize {
        self.rejected
    }

    /// Source paths safe to remove once the caller's commit has succeeded.
    pub fn removable(&self) -> &[PathBuf] {
        &self.removable
    }
}

/// A known-destination row and optional ratchet from a legacy source, before writing.
struct LegacyRow {
    row: KnownDestinationRow,
    ratchet: Option<RatchetRow>,
}

fn io(e: std::io::Error) -> StoreError {
    StoreError::Io(e)
}

fn corrupt(table: &'static str, reason: impl Into<String>) -> StoreError {
    StoreError::CorruptRow {
        table,
        reason: reason.into(),
    }
}

fn persistence_error(table: &'static str, e: PersistenceError) -> StoreError {
    match e {
        PersistenceError::Io(e) => StoreError::Io(e),
        other => corrupt(table, other.to_string()),
    }
}

fn bin<const N: usize>(value: &Value) -> Option<[u8; N]> {
    match value {
        Value::Binary(bytes) => bytes.as_slice().try_into().ok(),
        _ => None,
    }
}

fn num(value: &Value) -> Option<f64> {
    match value {
        Value::F64(v) => Some(*v),
        Value::F32(v) => Some(f64::from(*v)),
        Value::Integer(v) => v.as_i64().map(|i| i as f64),
        _ => None,
    }
}

/// Writes `rows` (and their ratchets) in one batch. A ratchet is kept only if its
/// destination is among the rows written here.
fn write_rows(
    rows: Vec<LegacyRow>,
    removable: Vec<PathBuf>,
    store: &mut dyn KnownDestinationStore,
) -> Result<LegacyImport, StoreError> {
    let known: HashSet<DestHash> = rows.iter().map(|r| r.row.destination_hash).collect();
    let mut batch = KdBatch::default();
    for legacy in rows {
        if let Some(ratchet) = legacy.ratchet {
            batch.ratchet_upserts.push(ratchet);
        }
        batch.upserts.push(legacy.row);
    }
    let report = store.apply(&batch, &|h| known.contains(h))?;
    let rejected = report
        .rejected
        .iter()
        .filter(|r| r.table == RejectedTable::KnownDestination)
        .count();
    Ok(LegacyImport {
        imported: batch.upserts.len() - rejected,
        rejected,
        removable,
    })
}

/// Imports `storage/known_destinations`, a msgpack map of destination hash to
/// the 8-field entry Python 1.5.x writes, with the padding of upstream `KnownDestinationsStore.import_legacy`.
/// Entries with fewer than five fields, or a public key other than 64 bytes, are
/// skipped. A last-heard time that is missing or not positive becomes `now`.
pub fn import_python_known_destinations(
    path: &Path,
    now: f64,
    store: &mut dyn KnownDestinationStore,
) -> Result<LegacyImport, StoreError> {
    const T: &str = "known_destinations";
    let data = std::fs::read(path).map_err(io)?;
    let root =
        rmpv::decode::read_value(&mut data.as_slice()).map_err(|e| corrupt(T, e.to_string()))?;
    let Value::Map(entries) = root else {
        return Err(corrupt(T, "root is not a map"));
    };

    let mut rows = Vec::new();
    for (key, value) in entries {
        let (Some(dest), Value::Array(fields)) = (bin::<16>(&key), value) else {
            continue;
        };
        if fields.len() < 5 {
            continue;
        }
        let field = |i: usize| fields.get(i).unwrap_or(&Value::Nil);
        let Some(public_key) = bin::<64>(field(2)) else {
            continue;
        };
        let last_heard = num(field(0)).filter(|t| *t > 0.0).unwrap_or(now);
        let mut row = KnownDestinationRow::new(dest, last_heard, public_key);
        row.packet_hash = bin::<32>(field(1));
        row.app_data = match field(3) {
            Value::Binary(b) => Some(b.clone()),
            _ => None,
        };
        row.used = num(field(4)).unwrap_or(0.0);
        row.stamp = match field(5) {
            Value::Binary(b) => Some(b.clone()),
            _ => None,
        };
        row.stamp_value = num(field(6)).unwrap_or(0.0);
        row.lr_cost = num(field(7));
        rows.push(LegacyRow { row, ratchet: None });
    }
    write_rows(rows, vec![path.to_path_buf()], store)
}

/// Imports the ratchets in `storage/ratchets/<hex>` files, with the filter of
/// `KnownDestinationsStore.import_legacy_ratchets`: a 32-byte ratchet, received within `RATCHET_EXPIRY`
/// of `now`, for a destination in `known`. Every regular file in the directory
/// is removable afterwards, imported or not, as upstream removes them.
pub fn import_python_ratchets(
    dir: &Path,
    now: f64,
    known: &HashSet<DestHash>,
    store: &mut dyn KnownDestinationStore,
) -> Result<LegacyImport, StoreError> {
    let cutoff = now - RATCHET_EXPIRY as f64;
    let mut removable = Vec::new();
    let mut ratchets = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(io)? {
        let path = entry.map_err(io)?.path();
        if !path.is_file() {
            continue;
        }
        removable.push(path.clone());
        let Some(dest) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| hex::decode(n).ok())
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
        else {
            continue;
        };
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        let Ok(Value::Map(fields)) = rmpv::decode::read_value(&mut data.as_slice()) else {
            continue;
        };
        let get = |name: &str| {
            fields
                .iter()
                .find(|(k, _)| k.as_str() == Some(name))
                .map(|(_, v)| v)
        };
        let (Some(ratchet), Some(received)) = (
            get("ratchet").and_then(bin::<32>),
            get("received").and_then(num),
        ) else {
            continue;
        };
        if received < cutoff || !known.contains(&dest) {
            continue;
        }
        ratchets.push(RatchetRow::new(dest, ratchet, received));
    }

    let batch = KdBatch {
        ratchet_upserts: ratchets,
        ..KdBatch::default()
    };
    let report = store.apply(&batch, &|h| known.contains(h))?;
    Ok(LegacyImport {
        imported: report.written,
        rejected: report.rejected.len(),
        removable,
    })
}

/// Imports `storage/cache/announces/<hex>` files, each `[raw, interface]`. Every
/// announce gets `received = now`, as `AnnounceCache.import_legacy` does
/// in `RNS/Storage.py`. Files whose name is not a 32-byte hash, or whose
/// content does not decode, are skipped; all regular files are removable.
pub fn import_python_announce_cache(
    dir: &Path,
    now: f64,
    store: &mut dyn AnnounceCacheStore,
) -> Result<LegacyImport, StoreError> {
    let mut removable = Vec::new();
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(io)? {
        let path = entry.map_err(io)?.path();
        if !path.is_file() {
            continue;
        }
        removable.push(path.clone());
        let Some(hash) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| hex::decode(n).ok())
            .and_then(|b| <PacketHash>::try_from(b).ok())
        else {
            continue;
        };
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        let Ok(Value::Array(fields)) = rmpv::decode::read_value(&mut data.as_slice()) else {
            continue;
        };
        let Some(Value::Binary(raw)) = fields.first() else {
            continue;
        };
        let interface = match fields.get(1) {
            Some(Value::String(s)) => s.as_str().map(str::to_string),
            _ => None,
        };
        rows.push(AnnounceRow::new(hash, now, raw.clone(), interface));
    }
    let imported = rows.len();
    store.upsert(&rows)?;
    Ok(LegacyImport {
        imported,
        rejected: 0,
        removable,
    })
}

/// Imports the Rust `announce_cache.msgpack` (version 6, or version 5 through
/// the existing loader). It yields known-destination rows, retained as `used = -1`,
/// and each entry's ratchet with its receive time. Its packet bytes live in
/// separate files and are not imported here.
pub fn import_rust_announce_cache(
    path: &Path,
    now: f64,
    store: &mut dyn KnownDestinationStore,
) -> Result<LegacyImport, StoreError> {
    const T: &str = "announce_cache.msgpack";
    let entries: Vec<RustEntry> = match persistence::load_announce_cache(path) {
        Ok(v6) => v6.into_iter().filter_map(RustEntry::from_v6).collect(),
        Err(PersistenceError::VersionMismatch { .. }) => {
            persistence::load_announce_cache_legacy_v5(path)
                .map_err(|e| persistence_error(T, e))?
                .into_iter()
                .filter_map(RustEntry::from_v5)
                .collect()
        }
        Err(e) => return Err(persistence_error(T, e)),
    };

    let mut rows = Vec::new();
    for e in entries {
        let Some(public_key) = e.public_key else {
            continue;
        };
        let mut row = KnownDestinationRow::new(e.dest, e.timestamp, public_key);
        row.packet_hash = e.packet_hash;
        row.app_data = e.app_data;
        row.used = if e.retained {
            -1.0
        } else {
            e.last_used.unwrap_or(0.0)
        };
        row.stamp = e.stamp;
        row.stamp_value = e.stamp_value;
        row.lr_cost = e.lr_cost;
        let ratchet = e
            .ratchet
            .map(|r| RatchetRow::new(e.dest, r, e.ratchet_received.unwrap_or(now)));
        rows.push(LegacyRow { row, ratchet });
    }
    write_rows(rows, vec![path.to_path_buf()], store)
}

/// Fields common to the version 5 and version 6 Rust cache entries.
struct RustEntry {
    dest: DestHash,
    timestamp: f64,
    public_key: Option<[u8; 64]>,
    app_data: Option<Vec<u8>>,
    retained: bool,
    last_used: Option<f64>,
    packet_hash: Option<PacketHash>,
    stamp: Option<Vec<u8>>,
    stamp_value: f64,
    lr_cost: Option<f64>,
    ratchet: Option<Ratchet>,
    ratchet_received: Option<f64>,
}

impl RustEntry {
    fn from_v6(e: persistence::PersistedAnnounceEntry) -> Option<Self> {
        Some(Self {
            dest: <DestHash>::try_from(e.destination_hash).ok()?,
            timestamp: e.timestamp,
            public_key: e.public_key.and_then(|k| k.try_into().ok()),
            app_data: e.app_data,
            retained: e.retained,
            last_used: e.last_used,
            packet_hash: e.packet_hash.and_then(|h| h.try_into().ok()),
            stamp: e.stamp,
            stamp_value: e.stamp_value,
            lr_cost: e.lr_cost,
            ratchet: e.ratchet.and_then(|r| r.try_into().ok()),
            ratchet_received: e.ratchet_received,
        })
    }

    fn from_v5(e: persistence::LegacyPersistedAnnounceEntryV5) -> Option<Self> {
        Some(Self {
            dest: <DestHash>::try_from(e.destination_hash).ok()?,
            timestamp: e.timestamp,
            public_key: e.public_key.and_then(|k| k.try_into().ok()),
            app_data: e.app_data,
            retained: e.retained,
            last_used: None,
            packet_hash: None,
            stamp: None,
            stamp_value: 0.0,
            lr_cost: None,
            ratchet: e.ratchet.and_then(|r| r.try_into().ok()),
            ratchet_received: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    // Bytes written by RNS 1.6.0 `RNS.vendor.umsgpack.packb`.
    const KD_FILE_HEX: &str = "82c4100101010101010101010101010101010195cb41dabdcff4c00000c4200909090909090909090909090909090909090909090909090909090909090909c44001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101c000c410020202020202020202020202020202029800c0c44002020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202c403617070ffc4057374616d70cb4020000000000000cb400c000000000000";
    const RATCHET_FILE_HEX: &str = "82a772617463686574c4203030303030303030303030303030303030303030303030303030303030303030a87265636569766564cb41dabdcff4c00000";
    const ANNOUNCE_FILE_HEX: &str = "92c42a010005050505050505050505050505050505050505050505050505050505050505050505050505050505a474637030";
    const ANNOUNCE_NONE_FILE_HEX: &str = "92c42a010005050505050505050505050505050505050505050505050505050505050505050505050505050505c0";
    const NOW: f64 = 1_794_588_627.0;

    fn unique_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rns-legacy-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn bytes(hex_text: &str) -> Vec<u8> {
        hex::decode(hex_text).unwrap()
    }

    #[test]
    fn python_known_destinations_pad_short_entries_and_default_last_heard() {
        let dir = unique_dir("kd");
        let path = dir.join("known_destinations");
        std::fs::write(&path, bytes(KD_FILE_HEX)).unwrap();
        let mut store = MemoryStore::new();
        let got = import_python_known_destinations(&path, NOW + 5.0, &mut store).unwrap();
        assert_eq!(got.imported(), 2);
        assert_eq!(got.rejected(), 0);
        assert_eq!(got.removable(), std::slice::from_ref(&path));
        let mut rows = Vec::new();
        store.load_all(&mut |r| rows.push(r)).unwrap();
        rows.sort_by_key(|r| r.destination_hash);
        // Five-field entry: optional fields padded empty, used kept.
        assert_eq!(rows[0].destination_hash, [1; 16]);
        assert_eq!(rows[0].last_heard, NOW);
        assert_eq!(rows[0].packet_hash, Some([9; 32]));
        assert_eq!(rows[0].app_data, None);
        assert_eq!(rows[0].stamp_value, 0.0);
        assert_eq!(rows[0].lr_cost, None);
        // Eight-field entry with last_heard 0 becomes the import time; retained kept.
        assert_eq!(rows[1].destination_hash, [2; 16]);
        assert_eq!(rows[1].last_heard, NOW + 5.0);
        assert_eq!(rows[1].used, -1.0);
        assert_eq!(rows[1].app_data, Some(b"app".to_vec()));
        assert_eq!(rows[1].stamp, Some(b"stamp".to_vec()));
        assert_eq!(rows[1].stamp_value, 8.0);
        assert_eq!(rows[1].lr_cost, Some(3.5));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn python_ratchet_files_keep_only_known_fresh_ratchets_and_remove_all() {
        let dir = unique_dir("ratchets");
        let known_hash = [1u8; 16];
        std::fs::write(dir.join(hex::encode(known_hash)), bytes(RATCHET_FILE_HEX)).unwrap();
        std::fs::write(dir.join(hex::encode([9u8; 16])), bytes(RATCHET_FILE_HEX)).unwrap();
        std::fs::write(dir.join("not-a-hash"), b"junk").unwrap();
        let known: HashSet<DestHash> = [known_hash].into_iter().collect();
        let mut store = MemoryStore::new();
        let got = import_python_ratchets(&dir, NOW, &known, &mut store).unwrap();
        assert_eq!(got.imported(), 1);
        assert_eq!(
            store.fetch_ratchet(&known_hash).unwrap(),
            Some(([0x30; 32], NOW))
        );
        assert_eq!(store.fetch_ratchet(&[9; 16]).unwrap(), None);
        assert_eq!(got.removable().len(), 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn python_ratchet_older_than_expiry_is_not_imported() {
        let dir = unique_dir("ratchet-expired");
        let known_hash = [1u8; 16];
        std::fs::write(dir.join(hex::encode(known_hash)), bytes(RATCHET_FILE_HEX)).unwrap();
        let known: HashSet<DestHash> = [known_hash].into_iter().collect();
        let mut store = MemoryStore::new();
        let later = NOW + RATCHET_EXPIRY as f64 + 1.0;
        let got = import_python_ratchets(&dir, later, &known, &mut store).unwrap();
        assert_eq!(got.imported(), 0);
        assert_eq!(store.fetch_ratchet(&known_hash).unwrap(), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn python_announce_cache_files_get_import_time_and_keep_interface() {
        let dir = unique_dir("announces");
        let with_iface = [7u8; 32];
        let without = [8u8; 32];
        std::fs::write(dir.join(hex::encode(with_iface)), bytes(ANNOUNCE_FILE_HEX)).unwrap();
        std::fs::write(
            dir.join(hex::encode(without)),
            bytes(ANNOUNCE_NONE_FILE_HEX),
        )
        .unwrap();
        let mut store = MemoryStore::new();
        let got = import_python_announce_cache(&dir, NOW, &mut store).unwrap();
        assert_eq!(got.imported(), 2);
        assert_eq!(got.removable().len(), 2);
        let raw = bytes(
            "010005050505050505050505050505050505050505050505050505050505050505050505050505050505",
        );
        assert_eq!(
            store.fetch(&with_iface).unwrap(),
            Some((raw.clone(), Some("tcp0".to_string())))
        );
        assert_eq!(store.fetch(&without).unwrap(), Some((raw, None)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rust_v6_announce_cache_maps_retained_and_ratchet_received() {
        let dir = unique_dir("rust-v6");
        let path = dir.join("announce_cache.msgpack");
        let entry = persistence::PersistedAnnounceEntry {
            destination_hash: vec![4; 16],
            hops: 1,
            app_data: Some(b"v6".to_vec()),
            timestamp: 10.0,
            public_key: Some(vec![4; 64]),
            ratchet: Some(vec![0x40; 32]),
            packet_hash: Some(vec![5; 32]),
            retained: true,
            name_hash: vec![0; 10],
            is_path_response: false,
            last_used: None,
            stamp: None,
            stamp_value: 0.0,
            lr_cost: None,
            ratchet_received: Some(NOW - 3.0),
        };
        let file = persistence::PersistedAnnounceCache {
            entries: vec![entry],
            version: persistence::PersistedAnnounceCache::CURRENT_VERSION,
        };
        std::fs::write(&path, rmp_serde::to_vec(&file).unwrap()).unwrap();
        let mut store = MemoryStore::new();
        let got = import_rust_announce_cache(&path, NOW, &mut store).unwrap();
        assert_eq!(got.imported(), 1);
        assert_eq!(
            store.fetch_ratchet(&[4; 16]).unwrap(),
            Some(([0x40; 32], NOW - 3.0))
        );
        let mut rows = Vec::new();
        store.load_all(&mut |r| rows.push(r)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].used, -1.0);
        assert_eq!(rows[0].packet_hash, Some([5; 32]));
        assert_eq!(got.removable(), std::slice::from_ref(&path));
        std::fs::remove_dir_all(&dir).ok();
    }
}
