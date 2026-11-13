//! Durable storage for known destinations, received ratchets and the announce
//! cache. The in-memory tables stay authoritative; a store only persists what
//! the caller hands it and reads rows back on demand.

use std::collections::{HashMap, HashSet};

#[cfg(feature = "sqlite-store")]
mod sqlite;

pub mod legacy;

#[cfg(feature = "sqlite-store")]
pub use sqlite::{SqliteAnnounceCache, SqliteKnownDestinations};

/// A 16-byte destination hash.
pub type DestHash = [u8; 16];
/// A 32-byte packet hash.
pub type PacketHash = [u8; 32];
/// A 32-byte X25519 ratchet public key.
pub type Ratchet = [u8; 32];
/// Raw announce bytes and the name of the interface it arrived on.
pub type CachedAnnounce = (Vec<u8>, Option<String>);

/// Known-destination schema version written by this crate; matches upstream's release format.
pub const KNOWN_DESTINATIONS_USER_VERSION: i64 = 0;
/// Announce-cache schema version written by this crate; matches upstream.
pub const ANNOUNCE_CACHE_USER_VERSION: i64 = 1;

/// Rows per transaction chunk; matches upstream's `executemany` batching.
#[cfg(feature = "sqlite-store")]
pub(crate) const CHUNK_ROWS: usize = 4096;

/// One `known_destinations` row.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct KnownDestinationRow {
    /// Destination hash, the primary key.
    pub destination_hash: DestHash,
    /// Unix time of the last announce.
    pub last_heard: f64,
    /// Hash of the packet that carried the announce, if known.
    pub packet_hash: Option<PacketHash>,
    /// Identity public key (X25519 + Ed25519).
    pub public_key: [u8; 64],
    /// Announce application data.
    pub app_data: Option<Vec<u8>>,
    /// `0` never used, `-1` retained, otherwise the Unix time of last use.
    pub used: f64,
    /// Stamp carried by the announce.
    pub stamp: Option<Vec<u8>>,
    /// Value of the stamp.
    pub stamp_value: f64,
    /// Link-request cost, if the announce advertised one.
    pub lr_cost: Option<f64>,
}

impl KnownDestinationRow {
    /// A row with the optional fields empty and `used` = 0.
    pub fn new(destination_hash: DestHash, last_heard: f64, public_key: [u8; 64]) -> Self {
        Self {
            destination_hash,
            last_heard,
            packet_hash: None,
            public_key,
            app_data: None,
            used: 0.0,
            stamp: None,
            stamp_value: 0.0,
            lr_cost: None,
        }
    }
}

/// One `ratchets` row.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct RatchetRow {
    /// Destination the ratchet belongs to.
    pub destination_hash: DestHash,
    /// Ratchet public key.
    pub ratchet: Ratchet,
    /// Unix time the ratchet was received.
    pub received: f64,
}

impl RatchetRow {
    /// A ratchet row.
    pub fn new(destination_hash: DestHash, ratchet: Ratchet, received: f64) -> Self {
        Self {
            destination_hash,
            ratchet,
            received,
        }
    }
}

/// Dirty state flushed to the known-destination store in one transaction.
#[derive(Debug, Default, Clone, PartialEq)]
#[non_exhaustive]
pub struct KdBatch {
    /// Rows to insert or replace, built from the current in-memory entries.
    pub upserts: Vec<KnownDestinationRow>,
    /// Destinations to remove. Applied only if the destination is no longer known.
    pub deletes: Vec<DestHash>,
    /// Ratchets to insert or replace. A ratchet for an unknown destination is removed.
    pub ratchet_upserts: Vec<RatchetRow>,
    /// Ratchets to remove. Applied only if the destination is no longer known.
    pub ratchet_deletes: Vec<DestHash>,
}

impl KdBatch {
    /// True when the batch has nothing to write.
    pub fn is_empty(&self) -> bool {
        self.upserts.is_empty()
            && self.deletes.is_empty()
            && self.ratchet_upserts.is_empty()
            && self.ratchet_deletes.is_empty()
    }
}

/// Which table a rejected row belonged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectedTable {
    /// The `known_destinations` table.
    KnownDestination,
    /// The `ratchets` table.
    Ratchet,
}

/// A row the database refused on its own constraints; it is not written.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rejection {
    /// Destination of the rejected row.
    pub destination_hash: DestHash,
    /// Table the row was going to.
    pub table: RejectedTable,
    /// Database error text.
    pub reason: String,
}

/// Outcome of a successful [`KnownDestinationStore::apply`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ApplyReport {
    /// Number of statements that were written.
    pub written: usize,
    /// Rows the database rejected row by row.
    pub rejected: Vec<Rejection>,
}

/// One cached announce.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct AnnounceRow {
    /// Packet hash, the primary key.
    pub packet_hash: PacketHash,
    /// Unix time the announce was received.
    pub received: f64,
    /// Raw packet bytes.
    pub raw: Vec<u8>,
    /// Name of the interface the announce arrived on.
    pub interface_reference: Option<String>,
}

impl AnnounceRow {
    /// A cached announce.
    pub fn new(
        packet_hash: PacketHash,
        received: f64,
        raw: Vec<u8>,
        interface_reference: Option<String>,
    ) -> Self {
        Self {
            packet_hash,
            received,
            raw,
            interface_reference,
        }
    }
}

/// Errors from the storage layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Another connection held the lock for the whole 5 s wait. Nothing was written; retry later.
    #[error("database is locked")]
    Locked,
    /// The file's `user_version` is newer than this crate knows. It was not opened for writing.
    #[error("database user_version {found} is newer than supported {supported}")]
    NewerVersion {
        /// Version found in the file.
        found: i64,
        /// Highest version this crate writes.
        supported: i64,
    },
    /// A write was attempted on a read-only store.
    #[error("store is open read-only")]
    ReadOnly,
    /// A stored row cannot be decoded.
    #[error("corrupt row in {table}: {reason}")]
    CorruptRow {
        /// Table name.
        table: &'static str,
        /// What is wrong with the row.
        reason: String,
    },
    /// Filesystem error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Any other database error.
    #[error("database error: {0}")]
    Backend(String),
}

/// Persistent known destinations and received ratchets.
pub trait KnownDestinationStore: Send {
    /// Calls `f` for every stored row.
    fn load_all(&mut self, f: &mut dyn FnMut(KnownDestinationRow)) -> Result<(), StoreError>;

    /// Applies a batch in one transaction. `is_known` reports whether the caller's
    /// in-memory table still holds a destination. On error nothing is written, and
    /// the caller still holds `batch` to re-mark.
    fn apply(
        &mut self,
        batch: &KdBatch,
        is_known: &dyn Fn(&DestHash) -> bool,
    ) -> Result<ApplyReport, StoreError>;

    /// Reads one ratchet and its receive time.
    fn fetch_ratchet(
        &mut self,
        destination: &DestHash,
    ) -> Result<Option<(Ratchet, f64)>, StoreError>;

    /// Deletes ratchets received before `cutoff` and returns their destinations.
    fn expire_ratchets(&mut self, cutoff: f64) -> Result<Vec<DestHash>, StoreError>;
}

/// Persistent announce cache keyed by packet hash.
pub trait AnnounceCacheStore: Send {
    /// Inserts or replaces the given announces in one transaction.
    fn upsert(&mut self, rows: &[AnnounceRow]) -> Result<(), StoreError>;

    /// Returns the raw bytes and interface name for a packet hash.
    fn fetch(&mut self, packet_hash: &PacketHash) -> Result<Option<CachedAnnounce>, StoreError>;

    /// Deletes every announce not in `keep` and returns how many were removed.
    fn retain_only(&mut self, keep: &HashSet<PacketHash>) -> Result<usize, StoreError>;
}

/// In-memory store with the same semantics as the SQLite stores. Used when a
/// transport runs without a storage directory.
#[derive(Debug, Default)]
pub struct MemoryStore {
    known: HashMap<DestHash, KnownDestinationRow>,
    ratchets: HashMap<DestHash, RatchetRow>,
    announces: HashMap<PacketHash, AnnounceRow>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl KnownDestinationStore for MemoryStore {
    fn load_all(&mut self, f: &mut dyn FnMut(KnownDestinationRow)) -> Result<(), StoreError> {
        for row in self.known.values() {
            f(row.clone());
        }
        Ok(())
    }

    fn apply(
        &mut self,
        batch: &KdBatch,
        is_known: &dyn Fn(&DestHash) -> bool,
    ) -> Result<ApplyReport, StoreError> {
        let mut written = 0;
        for row in &batch.upserts {
            self.known.insert(row.destination_hash, row.clone());
            written += 1;
        }
        for hash in batch.deletes.iter().filter(|h| !is_known(h)) {
            self.known.remove(hash);
            written += 1;
        }
        for row in &batch.ratchet_upserts {
            if is_known(&row.destination_hash) {
                self.ratchets.insert(row.destination_hash, *row);
            } else {
                self.ratchets.remove(&row.destination_hash);
            }
            written += 1;
        }
        for hash in batch.ratchet_deletes.iter().filter(|h| !is_known(h)) {
            self.ratchets.remove(hash);
            written += 1;
        }
        Ok(ApplyReport {
            written,
            rejected: Vec::new(),
        })
    }

    fn fetch_ratchet(
        &mut self,
        destination: &DestHash,
    ) -> Result<Option<(Ratchet, f64)>, StoreError> {
        Ok(self
            .ratchets
            .get(destination)
            .map(|r| (r.ratchet, r.received)))
    }

    fn expire_ratchets(&mut self, cutoff: f64) -> Result<Vec<DestHash>, StoreError> {
        let expired: Vec<DestHash> = self
            .ratchets
            .iter()
            .filter(|(_, r)| r.received < cutoff)
            .map(|(h, _)| *h)
            .collect();
        for hash in &expired {
            self.ratchets.remove(hash);
        }
        Ok(expired)
    }
}

impl AnnounceCacheStore for MemoryStore {
    fn upsert(&mut self, rows: &[AnnounceRow]) -> Result<(), StoreError> {
        for row in rows {
            self.announces.insert(row.packet_hash, row.clone());
        }
        Ok(())
    }

    fn fetch(&mut self, packet_hash: &PacketHash) -> Result<Option<CachedAnnounce>, StoreError> {
        Ok(self
            .announces
            .get(packet_hash)
            .map(|r| (r.raw.clone(), r.interface_reference.clone())))
    }

    fn retain_only(&mut self, keep: &HashSet<PacketHash>) -> Result<usize, StoreError> {
        let before = self.announces.len();
        self.announces.retain(|h, _| keep.contains(h));
        Ok(before - self.announces.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(h: u8, used: f64) -> KnownDestinationRow {
        let mut r = KnownDestinationRow::new([h; 16], 100.0, [h; 64]);
        r.used = used;
        r
    }

    #[test]
    fn memory_store_deletes_only_unknown_destinations() {
        let mut store = MemoryStore::new();
        let batch = KdBatch {
            upserts: vec![row(1, 0.0), row(2, 0.0)],
            ..KdBatch::default()
        };
        store.apply(&batch, &|_| true).unwrap();
        let del = KdBatch {
            deletes: vec![[1; 16], [2; 16]],
            ..KdBatch::default()
        };
        store.apply(&del, &|h| *h == [2; 16]).unwrap();
        let mut seen = Vec::new();
        store
            .load_all(&mut |r| seen.push(r.destination_hash))
            .unwrap();
        assert_eq!(seen, vec![[2; 16]]);
    }

    #[test]
    fn memory_store_turns_ratchet_for_unknown_destination_into_delete() {
        let mut store = MemoryStore::new();
        let batch = KdBatch {
            ratchet_upserts: vec![RatchetRow::new([3; 16], [9; 32], 50.0)],
            ..KdBatch::default()
        };
        store.apply(&batch, &|_| false).unwrap();
        assert_eq!(store.fetch_ratchet(&[3; 16]).unwrap(), None);
    }

    #[test]
    fn memory_store_expires_only_older_ratchets() {
        let mut store = MemoryStore::new();
        let batch = KdBatch {
            ratchet_upserts: vec![
                RatchetRow::new([4; 16], [1; 32], 10.0),
                RatchetRow::new([5; 16], [2; 32], 90.0),
            ],
            ..KdBatch::default()
        };
        store.apply(&batch, &|_| true).unwrap();
        assert_eq!(store.expire_ratchets(50.0).unwrap(), vec![[4; 16]]);
        assert_eq!(
            store.fetch_ratchet(&[5; 16]).unwrap(),
            Some(([2; 32], 90.0))
        );
    }

    #[test]
    fn memory_store_retain_only_counts_removed_announces() {
        let mut store = MemoryStore::new();
        let rows = [
            AnnounceRow::new([1; 32], 1.0, vec![1], None),
            AnnounceRow::new([2; 32], 1.0, vec![2], None),
        ];
        store.upsert(&rows).unwrap();
        let keep: HashSet<PacketHash> = [[1; 32]].into_iter().collect();
        assert_eq!(store.retain_only(&keep).unwrap(), 1);
        assert_eq!(store.fetch(&[2; 32]).unwrap(), None);
    }
}
