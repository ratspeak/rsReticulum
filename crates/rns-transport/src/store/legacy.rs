//! One-way importers for the pre-SQLite files. Each function reads one source,
//! writes through the given store, and returns the paths the caller may remove
//! after its own transaction has committed. Only the announce-cache import
//! removes files itself, chunk by chunk, each after its own commit.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rmpv::Value;
use rns_wire::constants::RATCHET_EXPIRY;

use super::{
    AnnounceCacheStore, AnnounceFacts, AnnounceRow, DestHash, KdBatch, KnownDestinationRow,
    KnownDestinationStore, PacketHash, Ratchet, RatchetRow, RejectedTable, StoreError,
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
        // A file may be older than what the store already holds: upstream
        // imports only into an empty store, this also takes files handed
        // over by lxmd-rs and Ratspeak while the store was in use.
        if store
            .fetch_ratchet(&dest)?
            .is_some_and(|(_, stored)| stored >= received)
        {
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

/// Files per announce-cache import transaction; matches upstream's `executemany` batching.
const ANNOUNCE_CHUNK_FILES: usize = 4096;

/// Imports `storage/cache/announces/<hex>` files, each `[raw, interface]`, as
/// `AnnounceCache.import_legacy` does in `RNS/Storage.py`. Every announce gets
/// `received = now`. Upstream unlinks every file before its one commit; here the
/// files go in chunks of [`ANNOUNCE_CHUNK_FILES`], and a chunk's files are removed
/// only after its transaction has committed, so an interrupted import loses
/// nothing and resumes with the files that remain. A file whose name is not a
/// 32-byte hash, or whose content does not decode, is removed without a row.
pub fn import_python_announce_cache(
    dir: &Path,
    now: f64,
    store: &mut dyn AnnounceCacheStore,
) -> Result<LegacyImport, StoreError> {
    let mut imported = 0usize;
    loop {
        // The directory is listed again for every chunk: removing files under an
        // open listing makes it skip entries on common filesystems.
        let mut rows = Vec::new();
        let mut files = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(io)? {
            let path = entry.map_err(io)?.path();
            if !path.is_file() {
                continue;
            }
            if let Some(row) = read_announce_file(&path, now) {
                rows.push(row);
            }
            files.push(path);
            if files.len() >= ANNOUNCE_CHUNK_FILES {
                break;
            }
        }
        if files.is_empty() {
            break;
        }
        store.upsert(&rows)?;
        imported += rows.len();
        let removed = files
            .iter()
            .filter(|file| std::fs::remove_file(file).is_ok())
            .count();
        // Files that cannot be removed would come back in every listing.
        if removed == 0 {
            break;
        }
    }
    Ok(LegacyImport {
        imported,
        rejected: 0,
        removable: Vec::new(),
    })
}

fn read_announce_file(path: &Path, now: f64) -> Option<AnnounceRow> {
    let hash = path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| hex::decode(n).ok())
        .and_then(|b| <PacketHash>::try_from(b).ok())?;
    let data = std::fs::read(path).ok()?;
    let Ok(Value::Array(fields)) = rmpv::decode::read_value(&mut data.as_slice()) else {
        return None;
    };
    let Some(Value::Binary(raw)) = fields.first() else {
        return None;
    };
    let interface = match fields.get(1) {
        Some(Value::String(s)) => s.as_str().map(str::to_string),
        _ => None,
    };
    Some(AnnounceRow::new(hash, now, raw.clone(), interface))
}

/// Imports the Rust `announce_cache.msgpack` (version 6, or version 5 through
/// the existing loader). It yields known-destination rows, retained as `used = -1`,
/// and each entry's ratchet with its receive time. A cache written before receive
/// times were kept dates each ratchet at its entry's last announce, the latest it
/// can have arrived. Its packet bytes live in separate files and are not imported here.
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
        row.announce_facts = e.facts;
        let received = e.ratchet_received.unwrap_or(e.timestamp.min(now));
        let ratchet = e.ratchet.map(|r| RatchetRow::new(e.dest, r, received));
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
    facts: Option<AnnounceFacts>,
}

/// The cache stored a zero name hash for an entry whose announce it no longer had.
fn stored_facts(hops: u8, name_hash: &[u8], path_response: bool) -> Option<AnnounceFacts> {
    let name_hash: [u8; 10] = name_hash.try_into().ok()?;
    (name_hash != [0u8; 10]).then(|| AnnounceFacts::new(hops, name_hash, path_response))
}

impl RustEntry {
    fn from_v6(e: persistence::PersistedAnnounceEntry) -> Option<Self> {
        Some(Self {
            facts: stored_facts(e.hops, &e.name_hash, e.is_path_response),
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
        // The inline announce is written out as a legacy file under this hash.
        let header = rns_wire::header::PacketHeader::unpack(&e.raw_packet)
            .ok()
            .map(|(header, _)| header);
        let path_response = header
            .as_ref()
            .is_some_and(|h| h.context == rns_wire::context::PacketContext::PathResponse);
        Some(Self {
            facts: stored_facts(e.hops, &e.name_hash, path_response),
            dest: <DestHash>::try_from(e.destination_hash).ok()?,
            timestamp: e.timestamp,
            public_key: e.public_key.and_then(|k| k.try_into().ok()),
            app_data: e.app_data,
            retained: e.retained,
            last_used: None,
            packet_hash: header
                .map(|h| rns_wire::hash::packet_hash(&e.raw_packet, h.flags.header_type)),
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
    fn a_ratchet_file_older_than_the_stored_ratchet_is_not_imported() {
        let dir = unique_dir("ratchet-older");
        let known_hash = [1u8; 16];
        std::fs::write(dir.join(hex::encode(known_hash)), bytes(RATCHET_FILE_HEX)).unwrap();
        let known: HashSet<DestHash> = [known_hash].into_iter().collect();
        let mut store = MemoryStore::new();
        let newer = KdBatch {
            ratchet_upserts: vec![RatchetRow::new(known_hash, [0x77; 32], NOW + 10.0)],
            ..KdBatch::default()
        };
        store.apply(&newer, &|h| known.contains(h)).unwrap();
        let got = import_python_ratchets(&dir, NOW + 20.0, &known, &mut store).unwrap();
        assert_eq!(got.imported(), 0);
        assert_eq!(
            store.fetch_ratchet(&known_hash).unwrap(),
            Some(([0x77; 32], NOW + 10.0))
        );
        assert_eq!(got.removable().len(), 1);
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
        assert!(!dir.join(hex::encode(with_iface)).exists());
        assert!(!dir.join(hex::encode(without)).exists());
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

    /// Fails every write after the first `good` ones, as a crash would end the import.
    struct FailsAfter {
        good: usize,
        inner: MemoryStore,
    }

    impl AnnounceCacheStore for FailsAfter {
        fn upsert(&mut self, rows: &[AnnounceRow]) -> Result<(), StoreError> {
            if self.good == 0 {
                return Err(StoreError::Locked);
            }
            self.good -= 1;
            self.inner.upsert(rows)
        }

        fn fetch(
            &mut self,
            packet_hash: &PacketHash,
        ) -> Result<Option<super::super::CachedAnnounce>, StoreError> {
            self.inner.fetch(packet_hash)
        }

        fn retain_only(&mut self, keep: &HashSet<PacketHash>) -> Result<usize, StoreError> {
            self.inner.retain_only(keep)
        }
    }

    fn files_in(dir: &Path) -> usize {
        std::fs::read_dir(dir).unwrap().count()
    }

    #[test]
    fn an_interrupted_announce_import_keeps_unwritten_files_and_resumes() {
        let dir = unique_dir("announces-chunks");
        let total = ANNOUNCE_CHUNK_FILES + 40;
        let hash = |i: usize| {
            let mut h = [0x5Au8; 32];
            h[..8].copy_from_slice(&(i as u64).to_be_bytes());
            h
        };
        for i in 0..total {
            std::fs::write(dir.join(hex::encode(hash(i))), bytes(ANNOUNCE_FILE_HEX)).unwrap();
        }
        std::fs::write(dir.join("not-a-hash"), b"junk").unwrap();

        // The second chunk's transaction fails: its files stay, the first chunk's are gone.
        let mut store = FailsAfter {
            good: 1,
            inner: MemoryStore::new(),
        };
        assert!(import_python_announce_cache(&dir, NOW, &mut store).is_err());
        assert_eq!(files_in(&dir), total + 1 - ANNOUNCE_CHUNK_FILES);

        store.good = usize::MAX;
        import_python_announce_cache(&dir, NOW, &mut store).unwrap();
        assert_eq!(
            files_in(&dir),
            0,
            "every file, decodable or not, is removed"
        );
        for i in 0..total {
            assert!(store.fetch(&hash(i)).unwrap().is_some(), "announce {i}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Version 6 as 1.0.44 wrote it, before ratchet receive times were kept.
    #[test]
    fn a_cache_ratchet_without_a_receive_time_dates_from_its_last_announce() {
        let dir = unique_dir("rust-v6-unreceived");
        let path = dir.join("announce_cache.msgpack");
        let entry = persistence::PersistedAnnounceEntry {
            destination_hash: vec![6; 16],
            hops: 1,
            app_data: None,
            timestamp: NOW - 3600.0,
            public_key: Some(vec![6; 64]),
            ratchet: Some(vec![0x60; 32]),
            packet_hash: None,
            retained: false,
            name_hash: vec![0; 10],
            is_path_response: false,
            last_used: None,
            stamp: None,
            stamp_value: 0.0,
            lr_cost: None,
            ratchet_received: None,
        };
        let file = persistence::PersistedAnnounceCache {
            entries: vec![entry],
            version: persistence::PersistedAnnounceCache::CURRENT_VERSION,
        };
        std::fs::write(&path, rmp_serde::to_vec(&file).unwrap()).unwrap();
        let mut store = MemoryStore::new();
        import_rust_announce_cache(&path, NOW, &mut store).unwrap();
        assert_eq!(
            store.fetch_ratchet(&[6; 16]).unwrap(),
            Some(([0x60; 32], NOW - 3600.0))
        );
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
