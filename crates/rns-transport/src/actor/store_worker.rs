//! Write-behind for known destinations, received ratchets, and cached announces
//! (Python `KnownDestinationsStore` and `AnnounceCache`). The actor keeps the
//! pending state and builds each batch from it. One thread owns the read-write
//! stores and runs jobs in the order they were sent. The actor reads ratchets and
//! cached announces through its own read-only connections.

use std::collections::{HashMap, HashSet};
use std::path::Path;
#[cfg(feature = "sqlite-store")]
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::sync::mpsc as tokio_mpsc;
use tracing::{debug, error, trace, warn};

use super::RecentAnnounce;
use crate::constants::{ANNOUNCE_CACHE_FLUSH_INTERVAL, ANNOUNCE_CACHE_MAX_PENDING};
use crate::store::{
    AnnounceCacheStore, AnnounceFacts, AnnounceRow, ApplyReport, CachedAnnounce, DestHash, KdBatch,
    KnownDestinationRow, KnownDestinationStore, MemoryStore, PacketHash, Ratchet, RatchetRow,
    RejectedTable, StoreError,
};
#[cfg(feature = "sqlite-store")]
use crate::store::{KeepUnloadable, SqliteAnnounceCache, SqliteKnownDestinations, legacy};

#[derive(Clone)]
enum StoreSource {
    Memory,
    #[cfg(feature = "sqlite-store")]
    Sqlite {
        known: PathBuf,
        announces: PathBuf,
    },
}

enum StoreJob {
    Apply {
        batch: KdBatch,
        /// Destinations the actor still held when the batch was built.
        known: HashSet<DestHash>,
        /// Shutdown waits on this; ordinary flushes report through the actor's channel.
        reply: Option<std_mpsc::Sender<StoreResult>>,
    },
    ExpireRatchets {
        cutoff: f64,
    },
    AnnounceUpsert {
        /// The actor's number for this flush; its rows stay with the actor until answered.
        flush: u64,
        rows: Vec<AnnounceRow>,
        /// Shutdown waits on this; ordinary flushes report through the actor's channel.
        reply: Option<std_mpsc::Sender<StoreResult>>,
    },
    AnnounceClean {
        keep: HashSet<PacketHash>,
    },
    Start {
        owner: bool,
        now: f64,
        reply: std_mpsc::Sender<Started>,
    },
}

/// What the start-up job found.
struct Started {
    rows: Vec<KnownDestinationRow>,
    /// The announce cache is in its database; false keeps it in the actor's memory.
    announces_stored: bool,
    /// A client read the owner's known destinations database.
    loaded: bool,
}

/// Outcome of one job, delivered to the actor.
pub(super) enum StoreResult {
    Applied {
        report: ApplyReport,
    },
    Failed {
        batch: KdBatch,
        error: StoreError,
    },
    Expired {
        removed: usize,
    },
    ExpireFailed(StoreError),
    AnnounceFlushed {
        flush: u64,
    },
    AnnounceFailed {
        flush: u64,
        error: StoreError,
    },
    AnnounceCleaned {
        removed: usize,
    },
    AnnounceCleanFailed(StoreError),
    /// There is no announce database this session; the actor keeps the announces.
    AnnounceStoreUnavailable,
}

/// Bound on the exit flush: three lock waits of the store's five seconds.
const EXIT_FLUSH_DEADLINE: Duration = Duration::from_secs(15);

/// Owns the store thread. Closing the queue lets the thread finish and exit.
struct StoreWorker {
    jobs: Option<std_mpsc::Sender<StoreJob>>,
    thread: Option<JoinHandle<()>>,
}

impl StoreWorker {
    fn spawn(
        source: StoreSource,
        results: tokio_mpsc::UnboundedSender<StoreResult>,
    ) -> Option<Self> {
        let (jobs, rx) = std_mpsc::channel::<StoreJob>();
        match std::thread::Builder::new()
            .name("known-destinations-store".into())
            .spawn(move || run(source, rx, results))
        {
            Ok(thread) => Some(Self {
                jobs: Some(jobs),
                thread: Some(thread),
            }),
            Err(e) => {
                error!("could not start the known-destinations store thread: {e}");
                None
            }
        }
    }

    /// Hands the job to the thread; returns it back when the thread is gone.
    fn send(&self, job: StoreJob) -> Result<(), Box<StoreJob>> {
        match self.jobs.as_ref() {
            Some(tx) => tx.send(job).map_err(|e| Box::new(e.0)),
            None => Err(Box::new(job)),
        }
    }

    /// Stops the thread if it finishes by `deadline`; otherwise detaches it and
    /// returns false so exit can continue.
    fn close_by(&mut self, deadline: Instant) -> bool {
        self.jobs.take();
        let Some(thread) = self.thread.take() else {
            return true;
        };
        while !thread.is_finished() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = thread.join();
        true
    }
}

fn run(
    source: StoreSource,
    jobs: std_mpsc::Receiver<StoreJob>,
    results: tokio_mpsc::UnboundedSender<StoreResult>,
) {
    // An owner opens both stores at start-up. A client never sends a write.
    let mut slot: Option<Box<dyn KnownDestinationStore>> = None;
    let mut announces = AnnounceSlot::default();
    while let Ok(job) = jobs.recv() {
        match job {
            StoreJob::Apply {
                batch,
                known,
                reply,
            } => {
                let is_known = |h: &DestHash| known.contains(h);
                let store = writable(&mut slot, &mut announces, &source);
                let result = match store.apply(&batch, &is_known) {
                    Ok(report) => StoreResult::Applied { report },
                    Err(error) => StoreResult::Failed { batch, error },
                };
                match reply {
                    Some(tx) => {
                        let _ = tx.send(result);
                    }
                    None => {
                        let _ = results.send(result);
                    }
                }
            }
            StoreJob::ExpireRatchets { cutoff } => {
                let store = writable(&mut slot, &mut announces, &source);
                let result = match store.expire_ratchets(cutoff) {
                    Ok(removed) => StoreResult::Expired {
                        removed: removed.len(),
                    },
                    Err(e) => StoreResult::ExpireFailed(e),
                };
                let _ = results.send(result);
            }
            StoreJob::AnnounceClean { keep } => {
                let result = match announces.writable(&source) {
                    Some(store) => match store.retain_only(&keep) {
                        Ok(removed) => StoreResult::AnnounceCleaned { removed },
                        Err(e) => StoreResult::AnnounceCleanFailed(e),
                    },
                    None => StoreResult::AnnounceStoreUnavailable,
                };
                let _ = results.send(result);
            }
            StoreJob::AnnounceUpsert { flush, rows, reply } => {
                let result = match announces.writable(&source) {
                    Some(store) => match store.upsert(&rows) {
                        Ok(()) => StoreResult::AnnounceFlushed { flush },
                        Err(error) => StoreResult::AnnounceFailed { flush, error },
                    },
                    None => StoreResult::AnnounceStoreUnavailable,
                };
                match reply {
                    Some(tx) => {
                        let _ = tx.send(result);
                    }
                    None => {
                        let _ = results.send(result);
                    }
                }
            }
            StoreJob::Start { owner, now, reply } => {
                let started = if owner {
                    start_owner(&mut slot, &mut announces, &source, now)
                } else {
                    let rows = load_for_client(&source);
                    Started {
                        loaded: rows.is_some(),
                        rows: rows.unwrap_or_default(),
                        announces_stored: false,
                    }
                };
                let _ = reply.send(started);
            }
        }
    }
}

/// Owner start-up, in upstream's order: `Identity.load_known_destinations`
/// opens the database, imports the legacy files, and loads every row; then
/// `Transport.init_announce_cache` opens the announce cache and imports its
/// legacy files, which by then include the announces a version 5 Rust cache
/// carried inline.
fn start_owner(
    slot: &mut Option<Box<dyn KnownDestinationStore>>,
    announces: &mut AnnounceSlot,
    source: &StoreSource,
    now: f64,
) -> Started {
    let (mut store, durable) = open_known(source, now);
    let rows = if durable {
        read_rows(store.as_mut()).unwrap_or_else(|e| {
            error!("could not load known destinations: {e}; continuing with an empty table");
            Vec::new()
        })
    } else {
        rows_without_database(source, now)
    };
    *slot = Some(store);
    let announces_stored = announces.writable(source).is_some();
    Started {
        rows,
        announces_stored,
        loaded: true,
    }
}

/// A shared-instance client reads the owner's database once, read-only, and
/// nothing else (`Identity.load_known_destinations`, shared-instance branch);
/// `None` when there is no database to read.
fn load_for_client(source: &StoreSource) -> Option<Vec<KnownDestinationRow>> {
    match source {
        StoreSource::Memory => None,
        #[cfg(feature = "sqlite-store")]
        StoreSource::Sqlite { known, .. } => {
            // A client whose directory is not the owner's has none; the
            // runtime then asks the shared instance (split mode).
            if !known.is_file() {
                debug!("no known destinations database to load as a shared-instance client");
                return None;
            }
            SqliteKnownDestinations::open_ro(known)
                .and_then(|mut reader| read_rows(&mut reader))
                .map_err(|e| {
                    debug!(
                        "could not load known destinations from the shared instance's database: {e}"
                    )
                })
                .ok()
        }
    }
}

/// The rows for a session whose database could not be opened for writing:
/// what a read-only connection still gives, with the legacy files staged over
/// it and left in place (upstream's `load_known_destinations_legacy`).
fn rows_without_database(source: &StoreSource, now: f64) -> Vec<KnownDestinationRow> {
    #[cfg(not(feature = "sqlite-store"))]
    let _ = now;
    match source {
        StoreSource::Memory => Vec::new(),
        #[cfg(feature = "sqlite-store")]
        StoreSource::Sqlite { known, .. } => read_and_stage(known, now),
    }
}

/// Opens the known-destinations store and imports the legacy files. If the file
/// cannot be opened the session continues on a `MemoryStore`, logged once; the
/// flag says whether the store is the database.
fn open_known(source: &StoreSource, now: f64) -> (Box<dyn KnownDestinationStore>, bool) {
    #[cfg(not(feature = "sqlite-store"))]
    let _ = now;
    match source {
        StoreSource::Memory => (Box::new(MemoryStore::new()), false),
        #[cfg(feature = "sqlite-store")]
        StoreSource::Sqlite { known: path, .. } => match SqliteKnownDestinations::open_rw(path) {
            Ok(mut store) => {
                import_known_sources(&LegacyFiles::beside(path), now, &mut store, true);
                (Box::new(store), true)
            }
            Err(e) => {
                error!(
                    path = %path.display(),
                    "could not open the known destinations database, keeping entries in memory for this session: {e}; remove the known_destinations.db* files or update to recover"
                );
                (Box::new(MemoryStore::new()), false)
            }
        },
    }
}

/// The writable store. An owner's start-up has opened it; an actor whose storage
/// was only attached opens it at its first write, imports included.
fn writable<'a>(
    slot: &'a mut Option<Box<dyn KnownDestinationStore>>,
    announces: &mut AnnounceSlot,
    source: &StoreSource,
) -> &'a mut dyn KnownDestinationStore {
    if slot.is_none() {
        *slot = Some(open_known(source, crate::now_f64()).0);
        // A version 5 Rust cache has just written its inline announces out as
        // legacy files; an announce cache that is already open takes them now.
        announces.import_legacy(source);
    }
    slot.as_deref_mut().expect("store opened above")
}

fn read_rows(
    store: &mut dyn KnownDestinationStore,
) -> Result<Vec<KnownDestinationRow>, StoreError> {
    let mut rows = Vec::new();
    store.load_all(&mut |row| rows.push(row))?;
    Ok(rows)
}

#[cfg(feature = "sqlite-store")]
fn has_entries(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

#[cfg_attr(not(feature = "sqlite-store"), allow(dead_code))]
fn rename_imported(path: &Path, suffix: &str) {
    let target = path.with_file_name(format!(
        "{}{suffix}",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    if let Err(e) = std::fs::rename(path, &target) {
        warn!(path = %path.display(), "could not rename imported file: {e}");
    }
}

/// The legacy sources a storage directory may still hold.
#[cfg(feature = "sqlite-store")]
struct LegacyFiles {
    dir: PathBuf,
    rust_cache: PathBuf,
    python_kd: PathBuf,
    ratchet_dir: PathBuf,
}

#[cfg(feature = "sqlite-store")]
impl LegacyFiles {
    fn beside(db: &Path) -> Self {
        let dir = db.parent().unwrap_or(Path::new(".")).to_path_buf();
        Self {
            rust_cache: dir.join("announce_cache.msgpack"),
            python_kd: dir.join("known_destinations"),
            ratchet_dir: dir.join("ratchets"),
            dir,
        }
    }
}

/// Imports the legacy sources into `store`, each in its own commit. With `finish`
/// (the writable store) each source is then renamed or removed, and the ratchet
/// files are imported too; a staged read leaves every file in place.
#[cfg(feature = "sqlite-store")]
fn import_known_sources(
    legacy: &LegacyFiles,
    now: f64,
    store: &mut impl KeepUnloadable,
    finish: bool,
) {
    if legacy.rust_cache.is_file() {
        if finish
            && let Ok(v5) = crate::persistence::load_announce_cache_legacy_v5(&legacy.rust_cache)
        {
            // Version 5 carried the raw announces inline; they go to the packet cache.
            crate::persistence::migrate_legacy_announce_entries(
                v5,
                &legacy.dir.join("cache").join("announces"),
            );
        }
        match legacy::import_rust_announce_cache(&legacy.rust_cache, now, store) {
            Ok(imported) => {
                debug!(
                    rows = imported.imported(),
                    rejected = imported.rejected(),
                    "imported Rust announce cache"
                );
                if finish {
                    rename_imported(&legacy.rust_cache, ".imported");
                }
            }
            Err(e) => error!("could not import {}: {e}", legacy.rust_cache.display()),
        }
    }
    if legacy.python_kd.is_file() {
        match legacy::import_python_known_destinations(&legacy.python_kd, now, store) {
            Ok(imported) => {
                debug!(
                    rows = imported.imported(),
                    rejected = imported.rejected(),
                    unloadable = imported.unloadable().len(),
                    "imported Python known destinations"
                );
                if let Err(e) = store.keep_unloadable(imported.unloadable()) {
                    error!("could not keep the known destinations whose keys do not load: {e}");
                }
                if finish {
                    rename_imported(&legacy.python_kd, ".imported");
                }
            }
            Err(e) => error!("could not import {}: {e}", legacy.python_kd.display()),
        }
    }
    if finish && has_entries(&legacy.ratchet_dir) {
        match read_rows(store) {
            Ok(rows) => {
                let known: HashSet<DestHash> =
                    rows.into_iter().map(|row| row.destination_hash).collect();
                match legacy::import_python_ratchets(&legacy.ratchet_dir, now, &known, store) {
                    Ok(imported) => {
                        for file in imported.removable() {
                            if let Err(e) = std::fs::remove_file(file) {
                                warn!(path = %file.display(), "could not remove imported ratchet file: {e}");
                            }
                        }
                    }
                    Err(e) => error!("could not import ratchet files: {e}"),
                }
            }
            Err(e) => error!("could not read known destinations for the ratchet import: {e}"),
        }
    }
}

/// Rows already in the database, through a read-only connection, with the legacy
/// rows merged over them in memory. Nothing is written or renamed.
#[cfg(feature = "sqlite-store")]
fn read_and_stage(path: &Path, now: f64) -> Vec<KnownDestinationRow> {
    let mut staged = MemoryStore::new();
    if path.is_file() {
        let read = SqliteKnownDestinations::open_ro(path).and_then(|mut reader| {
            let mut loaded = KdBatch::default();
            reader.load_all(&mut |row| loaded.upserts.push(row))?;
            staged.apply(&loaded, &|_| true)
        });
        if let Err(e) = read {
            error!(
                "could not read {}: {e}; continuing without its entries",
                path.display()
            );
        }
    }
    import_known_sources(&LegacyFiles::beside(path), now, &mut staged, false);
    let mut rows = Vec::new();
    if let Err(e) = staged.load_all(&mut |row| rows.push(row)) {
        error!("could not stage legacy known destinations: {e}");
    }
    rows
}

/// Pending known-destination and ratchet marks (Python `KnownDestinationsStore`
/// `_dirty_*`, `_ratchet_*` and quarantine maps). Each mark cancels the opposite one.
#[derive(Debug, Default)]
pub(super) struct KdPending {
    dirty: HashSet<DestHash>,
    deleted: HashSet<DestHash>,
    ratchet_upserts: HashMap<DestHash, (Ratchet, f64)>,
    ratchet_deletes: HashSet<DestHash>,
    quarantine: HashSet<DestHash>,
    ratchet_quarantine: HashSet<DestHash>,
}

impl KdPending {
    pub(super) fn is_empty(&self) -> bool {
        self.dirty.is_empty()
            && self.deleted.is_empty()
            && self.ratchet_upserts.is_empty()
            && self.ratchet_deletes.is_empty()
    }

    /// `KnownDestinationsStore.mark_dirty`.
    pub(super) fn mark_dirty(&mut self, dest: DestHash) {
        self.deleted.remove(&dest);
        self.quarantine.remove(&dest);
        self.dirty.insert(dest);
    }

    /// `Identity._kd_mark_deleted`: the row and its ratchet go.
    pub(super) fn mark_deleted(&mut self, dest: DestHash) {
        self.dirty.remove(&dest);
        self.quarantine.remove(&dest);
        self.deleted.insert(dest);
        self.mark_ratchet_deleted(dest);
    }

    /// `KnownDestinationsStore.mark_ratchet_deleted`.
    fn mark_ratchet_deleted(&mut self, dest: DestHash) {
        self.ratchet_upserts.remove(&dest);
        self.ratchet_deletes.insert(dest);
        self.ratchet_quarantine.remove(&dest);
    }

    /// Drops queued ratchets older than `cutoff` (`expire_ratchets`, pending part).
    fn drop_ratchet_upserts_before(&mut self, cutoff: f64) {
        self.ratchet_upserts
            .retain(|_, (_, received)| *received >= cutoff);
    }

    /// Builds a batch from the current entries of the pending keys and clears the
    /// pending state. Also returns the destinations the actor still holds; the
    /// store deletes only the others.
    fn take_batch(
        &mut self,
        entries: &HashMap<DestHash, RecentAnnounce>,
    ) -> (KdBatch, HashSet<DestHash>) {
        let mut batch = KdBatch::default();
        let mut known = HashSet::new();

        for dest in std::mem::take(&mut self.dirty) {
            if self.quarantine.contains(&dest) {
                continue;
            }
            if let Some(row) = entries.get(&dest).and_then(known_destination_row) {
                known.insert(dest);
                batch.upserts.push(row);
            }
        }
        for dest in std::mem::take(&mut self.deleted) {
            if entries.contains_key(&dest) {
                known.insert(dest);
            }
            batch.deletes.push(dest);
        }
        for (dest, (ratchet, received)) in std::mem::take(&mut self.ratchet_upserts) {
            if self.ratchet_quarantine.contains(&dest) {
                continue;
            }
            if entries.contains_key(&dest) {
                known.insert(dest);
                batch
                    .ratchet_upserts
                    .push(RatchetRow::new(dest, ratchet, received));
            } else {
                // A ratchet for a destination no longer known is removed.
                batch.ratchet_deletes.push(dest);
            }
        }
        for dest in std::mem::take(&mut self.ratchet_deletes) {
            if entries.contains_key(&dest) {
                known.insert(dest);
            }
            batch.ratchet_deletes.push(dest);
        }
        (batch, known)
    }

    /// Re-marks the keys of a batch that was not written, as upstream's
    /// `apply` does on an unhandled error. A ratchet queued while the batch
    /// was out is newer and stays; `KnownDestinationsStore.apply` overwrites
    /// it with the attempted one.
    fn restore(&mut self, batch: KdBatch) {
        self.dirty
            .extend(batch.upserts.iter().map(|row| row.destination_hash));
        self.deleted.extend(batch.deletes);
        for row in batch.ratchet_upserts {
            self.ratchet_upserts
                .entry(row.destination_hash)
                .or_insert((row.ratchet, row.received));
        }
        self.ratchet_deletes.extend(batch.ratchet_deletes);
    }

    /// Quarantines rows the database refused, with one log line each. A later mark clears them.
    fn record_report(&mut self, report: &ApplyReport) {
        for rejection in &report.rejected {
            let dest = rejection.destination_hash;
            match rejection.table {
                RejectedTable::KnownDestination => {
                    error!(
                        destination = %hex::encode(dest),
                        "invalid known destination data at persist: {}", rejection.reason
                    );
                    self.quarantine.insert(dest);
                }
                RejectedTable::Ratchet => {
                    error!(
                        destination = %hex::encode(dest),
                        "invalid ratchet data at persist: {}", rejection.reason
                    );
                    self.ratchet_quarantine.insert(dest);
                }
            }
        }
    }
}

/// Cached announces the actor still holds, keyed by packet hash.
#[derive(Debug, Default)]
pub(super) struct AnnouncePending {
    /// Stored since the last flush (Python `AnnounceCache._pending`).
    rows: HashMap<PacketHash, AnnounceRow>,
    /// Handed to the worker and not yet answered, with the flush they went in.
    /// A fetch still finds them here, as upstream's fetch waits for a running flush.
    in_flight: HashMap<PacketHash, (u64, AnnounceRow)>,
    /// Number of the last flush handed to the worker.
    flushes: u64,
    /// Unix time of the last flush attempt (Python `ac_last_flush`).
    last_flush: f64,
    /// The last flush was not written; the next one waits for the interval.
    flush_failed: bool,
    /// No announce database this session: `rows` is the whole cache and is never flushed.
    in_memory: bool,
    /// Set while a clean is queued or running; another clean waits for it.
    clean_in_flight: bool,
}

impl AnnouncePending {
    fn get(&self, packet_hash: &PacketHash) -> Option<&AnnounceRow> {
        self.rows
            .get(packet_hash)
            .or_else(|| self.in_flight.get(packet_hash).map(|(_, row)| row))
    }

    /// Moves the pending rows to `in_flight` under a new flush number and returns
    /// the number with a copy of the rows for the worker.
    fn take_flush(&mut self) -> (u64, Vec<AnnounceRow>) {
        self.flushes += 1;
        let flush = self.flushes;
        let rows = self.rows.values().cloned().collect();
        for (hash, row) in self.rows.drain() {
            self.in_flight.insert(hash, (flush, row));
        }
        (flush, rows)
    }

    /// The rows of `flush` are stored.
    fn confirm(&mut self, flush: u64) {
        self.in_flight.retain(|_, (sent, _)| *sent != flush);
    }

    /// Re-queues the rows of a flush that was not written. A row stored or sent
    /// since then for the same hash is newer and is kept; upstream's
    /// `AnnounceCache.__apply_pending` overwrites it with the attempted one.
    fn restore(&mut self, flush: u64) {
        let failed: Vec<PacketHash> = self
            .in_flight
            .iter()
            .filter(|(_, (sent, _))| *sent == flush)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in failed {
            if let Some((_, row)) = self.in_flight.remove(&hash) {
                self.rows.entry(hash).or_insert(row);
            }
        }
    }

    /// Keeps the cache in memory for the rest of the session and takes back
    /// every row the worker could not store.
    fn keep_in_memory(&mut self) {
        self.in_memory = true;
        self.clean_in_flight = false;
        for (hash, (_, row)) in self.in_flight.drain() {
            self.rows.entry(hash).or_insert(row);
        }
    }
}

/// The actor's side of the stores: pending state, the worker, and read-only
/// connections for ratchet and cached-announce lookups.
pub(super) struct KdState {
    pub(super) pending: KdPending,
    /// Taken on the first submit, which starts the worker thread.
    source: Option<StoreSource>,
    worker: Option<StoreWorker>,
    results_tx: tokio_mpsc::UnboundedSender<StoreResult>,
    /// Outcomes of ordinary flushes and expiries, drained by the actor loop.
    pub(super) results: tokio_mpsc::UnboundedReceiver<StoreResult>,
    /// Cached announces not yet known to be stored.
    announces: AnnouncePending,
    /// Start-up read a known destinations database.
    pub(super) loaded: bool,
    #[cfg(feature = "sqlite-store")]
    db_path: Option<PathBuf>,
    #[cfg(feature = "sqlite-store")]
    reader: Option<SqliteKnownDestinations>,
    #[cfg(feature = "sqlite-store")]
    announce_db_path: Option<PathBuf>,
    #[cfg(feature = "sqlite-store")]
    announce_reader: Option<SqliteAnnounceCache>,
}

impl KdState {
    /// Pending state over an in-memory store, used when no storage directory is set.
    pub(super) fn new() -> Self {
        let (results_tx, results) = tokio_mpsc::unbounded_channel();
        Self {
            pending: KdPending::default(),
            source: Some(StoreSource::Memory),
            worker: None,
            results_tx,
            results,
            announces: AnnouncePending {
                in_memory: true,
                ..AnnouncePending::default()
            },
            loaded: false,
            #[cfg(feature = "sqlite-store")]
            db_path: None,
            #[cfg(feature = "sqlite-store")]
            reader: None,
            #[cfg(feature = "sqlite-store")]
            announce_db_path: None,
            #[cfg(feature = "sqlite-store")]
            announce_reader: None,
        }
    }

    /// Uses `dir`'s `known_destinations.db` and `cache/announces.db`. Nothing is
    /// opened here; each file is opened by the worker when a job needs it.
    pub(super) fn attach_storage(&mut self, dir: &Path) {
        self.close(Instant::now() + EXIT_FLUSH_DEADLINE);
        self.announces = AnnouncePending::default();
        #[cfg(feature = "sqlite-store")]
        {
            let path = dir.join("known_destinations.db");
            self.reader = None;
            self.db_path = Some(path.clone());
            let announces = dir.join("cache").join("announces.db");
            self.announce_reader = None;
            self.announce_db_path = Some(announces.clone());
            self.source = Some(StoreSource::Sqlite {
                known: path,
                announces,
            });
        }
        #[cfg(not(feature = "sqlite-store"))]
        {
            let _ = dir;
            self.announces.in_memory = true;
            self.source = Some(StoreSource::Memory);
        }
    }

    fn submit(&mut self, job: StoreJob) -> Result<(), Box<StoreJob>> {
        if self.worker.is_none()
            && let Some(source) = self.source.take()
        {
            self.worker = StoreWorker::spawn(source, self.results_tx.clone());
        }
        match self.worker.as_ref() {
            Some(worker) => worker.send(job),
            None => Err(Box::new(job)),
        }
    }

    /// Start-up, before the actor serves anything: an owner opens both stores,
    /// imports the legacy files, and loads every row; a client reads the rows
    /// read-only. Waits for the worker, which does the file work.
    pub(super) fn start(&mut self, owner: bool, now: f64) -> Vec<KnownDestinationRow> {
        let (tx, rx) = std_mpsc::channel();
        let job = StoreJob::Start {
            owner,
            now,
            reply: tx,
        };
        let started = match self.submit(job) {
            Ok(()) => rx.recv().ok(),
            Err(_) => None,
        };
        match started {
            Some(started) => {
                if owner && !started.announces_stored {
                    self.announces.in_memory = true;
                }
                self.loaded = started.loaded;
                started.rows
            }
            None => {
                error!("the store worker is not running; continuing without stored state");
                self.announces.in_memory = true;
                self.loaded = false;
                Vec::new()
            }
        }
    }

    /// Queues the pending marks as one batch without waiting for the store.
    pub(super) fn flush(&mut self, entries: &HashMap<DestHash, RecentAnnounce>) {
        if self.pending.is_empty() {
            return;
        }
        let (batch, known) = self.pending.take_batch(entries);
        let job = StoreJob::Apply {
            batch,
            known,
            reply: None,
        };
        if let Err(job) = self.submit(job)
            && let StoreJob::Apply { batch, .. } = *job
        {
            self.pending.restore(batch);
            error!("known-destinations store is not running; changes stay pending");
        }
    }

    /// Shutdown: writes the pending announces (`Transport.exit_handler`), then
    /// applies the pending marks (`Identity.exit_handler`), waiting for each answer
    /// within one exit deadline, then closes the stores.
    pub(super) fn shutdown(&mut self, entries: &HashMap<DestHash, RecentAnnounce>, write: bool) {
        let deadline = Instant::now() + EXIT_FLUSH_DEADLINE;
        if !write {
            self.pending = KdPending::default();
            self.discard_announces();
            self.close(deadline);
            return;
        }
        self.shutdown_announces(deadline);
        // A failed batch is restored; a few rounds drain what can be written.
        for _ in 0..3 {
            self.drain_results();
            if self.pending.is_empty() {
                break;
            }
            let (batch, known) = self.pending.take_batch(entries);
            let (tx, rx) = std_mpsc::channel();
            let job = StoreJob::Apply {
                batch,
                known,
                reply: Some(tx),
            };
            match self.submit(job) {
                Ok(()) => match rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                {
                    Ok(result) => self.handle(result),
                    Err(std_mpsc::RecvTimeoutError::Timeout) => {
                        error!(
                            "known-destinations flush did not finish before exit; unwritten changes are learned again from the network"
                        );
                        break;
                    }
                    Err(_) => {
                        error!("known-destinations store stopped before the final flush");
                        break;
                    }
                },
                Err(job) => {
                    if let StoreJob::Apply { batch, .. } = *job {
                        self.pending.restore(batch);
                    }
                    error!("known-destinations store is not running; final flush skipped");
                    break;
                }
            }
        }
        self.drain_results();
        self.close(deadline);
    }

    /// Queues an expiry of stored ratchets older than `cutoff`, after the marks
    /// already queued (`Identity.clean_known_destinations`).
    pub(super) fn expire_ratchets(&mut self, cutoff: f64) {
        self.pending.drop_ratchet_upserts_before(cutoff);
        if self.submit(StoreJob::ExpireRatchets { cutoff }).is_err() {
            trace!("known-destinations store is not running; ratchet expiry skipped");
        }
    }

    fn drain_results(&mut self) {
        while let Ok(result) = self.results.try_recv() {
            self.handle(result);
        }
    }

    /// A cached announce (`AnnounceCache.fetch`): the row the actor still holds,
    /// then the stored row. A shared-instance client passes `allow_db = false`
    /// and never opens the database.
    pub(super) fn fetch_announce(
        &mut self,
        packet_hash: &PacketHash,
        allow_db: bool,
    ) -> Option<CachedAnnounce> {
        if let Some(row) = self.announces.get(packet_hash) {
            return Some((row.raw.clone(), row.interface_reference.clone()));
        }
        if !allow_db {
            self.close_announce_reader();
            return None;
        }
        self.fetch_stored_announce(packet_hash)
    }

    #[cfg(feature = "sqlite-store")]
    fn fetch_stored_announce(&mut self, packet_hash: &PacketHash) -> Option<CachedAnnounce> {
        if self.announce_reader.is_none() {
            let path = self.announce_db_path.as_ref()?;
            if !path.is_file() {
                return None;
            }
            self.announce_reader = SqliteAnnounceCache::open_ro(path).ok();
        }
        let reader = self.announce_reader.as_mut()?;
        match reader.fetch(packet_hash) {
            Ok(found) => found,
            Err(e) => {
                trace!("could not read stored announce: {e}");
                None
            }
        }
    }

    #[cfg(not(feature = "sqlite-store"))]
    fn fetch_stored_announce(&mut self, _packet_hash: &PacketHash) -> Option<CachedAnnounce> {
        None
    }

    fn close_announce_reader(&mut self) {
        #[cfg(feature = "sqlite-store")]
        {
            self.announce_reader = None;
        }
    }

    /// `Transport.cache` for an announce: a later store for the same packet hash
    /// replaces the pending row.
    pub(super) fn store_announce(
        &mut self,
        packet_hash: PacketHash,
        raw: &[u8],
        interface: Option<String>,
    ) {
        let row = AnnounceRow::new(packet_hash, crate::now_f64(), raw.to_vec(), interface);
        self.announces.rows.insert(packet_hash, row);
    }

    /// Jobs loop (`Transport.jobs`): flushes when `ac_flush_interval` has passed
    /// since the last attempt or more than `announce_cache_max_pending` rows wait.
    /// Upstream also retries a failed flush on every pass while that many rows
    /// wait; here a failed flush is retried at the interval.
    pub(super) fn flush_announces_due(&mut self, now: f64) {
        let over_limit = self.announces.rows.len() > ANNOUNCE_CACHE_MAX_PENDING;
        let due = now - self.announces.last_flush >= ANNOUNCE_CACHE_FLUSH_INTERVAL
            || (over_limit && !self.announces.flush_failed);
        if !due {
            return;
        }
        self.announces.last_flush = now;
        self.flush_announces();
    }

    /// Queues the pending announces as one write without waiting for the store.
    fn flush_announces(&mut self) {
        if self.announces.in_memory || self.announces.rows.is_empty() {
            return;
        }
        self.send_announces(None);
    }

    /// Hands the pending announces to the worker. False when it is not running;
    /// the cache then stays in memory.
    fn send_announces(&mut self, reply: Option<std_mpsc::Sender<StoreResult>>) -> bool {
        let (flush, rows) = self.announces.take_flush();
        let sent = self
            .submit(StoreJob::AnnounceUpsert { flush, rows, reply })
            .is_ok();
        if !sent {
            self.announce_worker_gone();
        }
        sent
    }

    fn announce_worker_gone(&mut self) {
        error!(
            "announce-cache store is not running; keeping cached announces in memory for this session"
        );
        self.announces.keep_in_memory();
    }

    /// A shared-instance client has no announce cache: drops every announce the
    /// actor holds and any read connection.
    pub(super) fn discard_announces(&mut self) {
        self.announces.rows.clear();
        self.announces.in_flight.clear();
        self.close_announce_reader();
    }

    /// True while a clean is queued or running on the worker.
    pub(super) fn announce_clean_in_flight(&self) -> bool {
        self.announces.clean_in_flight
    }

    /// `AnnounceCache.clean`: after it, only announces in `keep` remain. Upstream
    /// writes the pending rows and then deletes the ones outside `keep`; here a
    /// pending row outside `keep` is dropped unwritten, which leaves the same rows.
    pub(super) fn clean_announces(&mut self, keep: HashSet<PacketHash>) {
        let before = self.announces.rows.len();
        self.announces.rows.retain(|hash, _| keep.contains(hash));
        if self.announces.in_memory {
            let removed = before - self.announces.rows.len();
            debug!(removed, "cleaned cached announces held in memory");
            return;
        }
        self.flush_announces();
        if self.announces.in_memory {
            return;
        }
        if self.submit(StoreJob::AnnounceClean { keep }).is_ok() {
            self.announces.clean_in_flight = true;
        } else {
            self.announce_worker_gone();
        }
    }

    /// Exit (`Transport.exit_handler`): writes the pending announces and waits for
    /// the answer until `deadline`.
    fn shutdown_announces(&mut self, deadline: Instant) {
        self.drain_results();
        if self.announces.in_memory || self.announces.rows.is_empty() {
            return;
        }
        let (tx, rx) = std_mpsc::channel();
        if !self.send_announces(Some(tx)) {
            return;
        }
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(result) => self.handle(result),
            Err(std_mpsc::RecvTimeoutError::Timeout) => error!(
                "announce-cache flush did not finish before exit; unwritten announces are learned again from the network"
            ),
            Err(_) => error!("announce-cache store stopped before the final flush"),
        }
    }

    /// Applies one job's outcome to the pending state.
    pub(super) fn handle(&mut self, result: StoreResult) {
        match result {
            StoreResult::Applied { report } => self.pending.record_report(&report),
            StoreResult::Failed { batch, error } => {
                error!("could not write known destinations: {error}; will retry");
                self.pending.restore(batch);
            }
            StoreResult::Expired { removed } => debug!(removed, "expired stored ratchets"),
            StoreResult::ExpireFailed(error) => error!("could not expire stored ratchets: {error}"),
            StoreResult::AnnounceFlushed { flush } => {
                self.announces.flush_failed = false;
                self.announces.confirm(flush);
            }
            StoreResult::AnnounceFailed { flush, error } => {
                error!("could not write cached announces: {error}; will retry");
                self.announces.flush_failed = true;
                self.announces.restore(flush);
            }
            StoreResult::AnnounceCleaned { removed } => {
                self.announces.clean_in_flight = false;
                debug!(removed, "cleaned cached announces");
            }
            StoreResult::AnnounceCleanFailed(error) => {
                self.announces.clean_in_flight = false;
                error!("could not clean cached announces: {error}");
            }
            StoreResult::AnnounceStoreUnavailable => self.announces.keep_in_memory(),
        }
    }

    fn close(&mut self, deadline: Instant) {
        if let Some(mut worker) = self.worker.take()
            && !worker.close_by(deadline)
        {
            error!(
                "known-destinations store did not stop before exit; the process ends without waiting for it"
            );
        }
    }

    /// `KnownDestinationsStore.remember_ratchet`: the pending upsert, then the
    /// stored row, are checked before a ratchet is queued. Returns the receive
    /// time that stands: the held one for an unchanged ratchet, else `now`.
    pub(super) fn remember_ratchet(&mut self, dest: DestHash, ratchet: Ratchet, now: f64) -> f64 {
        self.pending.ratchet_quarantine.remove(&dest);
        let held = match self.pending.ratchet_upserts.get(&dest) {
            Some(pending) => Some(*pending),
            None => self.fetch_stored_ratchet(&dest),
        };
        self.pending.ratchet_deletes.remove(&dest);
        if let Some((held, received)) = held
            && held == ratchet
        {
            return received;
        }
        self.pending.ratchet_upserts.insert(dest, (ratchet, now));
        now
    }

    /// `Identity.get_ratchet` after the in-memory copy: pending upsert, pending
    /// delete, then the stored row. Expiry is enforced by the caller.
    pub(super) fn stored_ratchet(&mut self, dest: &DestHash) -> Option<(Ratchet, f64)> {
        if let Some(pending) = self.pending.ratchet_upserts.get(dest).copied() {
            return Some(pending);
        }
        if self.pending.ratchet_deletes.contains(dest) {
            return None;
        }
        self.fetch_stored_ratchet(dest)
    }

    #[cfg(feature = "sqlite-store")]
    fn fetch_stored_ratchet(&mut self, dest: &DestHash) -> Option<(Ratchet, f64)> {
        if self.reader.is_none() {
            let path = self.db_path.as_ref()?;
            self.reader = SqliteKnownDestinations::open_ro(path).ok();
        }
        let reader = self.reader.as_mut()?;
        match reader.fetch_ratchet(dest) {
            Ok(found) => found,
            Err(e) => {
                trace!("could not read stored ratchet: {e}");
                None
            }
        }
    }

    #[cfg(not(feature = "sqlite-store"))]
    fn fetch_stored_ratchet(&mut self, _dest: &DestHash) -> Option<(Ratchet, f64)> {
        None
    }
}

/// The worker's announce cache, opened by its first job. `store` stays empty when
/// there is no database to write; the actor then keeps the announces itself.
#[derive(Default)]
struct AnnounceSlot {
    opened: bool,
    store: Option<Box<dyn AnnounceCacheStore>>,
}

impl AnnounceSlot {
    /// The writable store. The first call opens the file and imports any legacy
    /// files. A file that cannot be opened, including one from a newer release, is
    /// left alone and logged once.
    fn writable(&mut self, source: &StoreSource) -> Option<&mut dyn AnnounceCacheStore> {
        if !self.opened {
            self.opened = true;
            self.store = open_announce_store(source);
        }
        match self.store.as_mut() {
            Some(store) => Some(store.as_mut()),
            None => None,
        }
    }

    /// Imports legacy announce files into a store that is already open.
    fn import_legacy(&mut self, source: &StoreSource) {
        if let Some(store) = self.store.as_mut() {
            import_legacy_announces(store.as_mut(), source);
        }
    }
}

/// `Transport.init_announce_cache`: imports `storage/cache/announces` when it holds files.
fn import_legacy_announces(store: &mut dyn AnnounceCacheStore, source: &StoreSource) {
    #[cfg(not(feature = "sqlite-store"))]
    let _ = store;
    match source {
        StoreSource::Memory => {}
        #[cfg(feature = "sqlite-store")]
        StoreSource::Sqlite {
            announces: path, ..
        } => {
            let legacy_dir = path.with_file_name("announces");
            if !has_entries(&legacy_dir) {
                return;
            }
            match legacy::import_python_announce_cache(&legacy_dir, crate::now_f64(), store) {
                Ok(imported) => debug!(rows = imported.imported(), "imported announce files"),
                Err(e) => error!("could not import announce files: {e}"),
            }
        }
    }
}

/// Opens `announces.db`, creating `storage/cache` first as `Reticulum.__init__` does.
#[cfg(feature = "sqlite-store")]
fn open_announce_db(path: &Path) -> Result<SqliteAnnounceCache, StoreError> {
    if let Some(cache_dir) = path.parent() {
        std::fs::create_dir_all(cache_dir)?;
    }
    SqliteAnnounceCache::open_rw(path)
}

fn open_announce_store(source: &StoreSource) -> Option<Box<dyn AnnounceCacheStore>> {
    match source {
        StoreSource::Memory => None,
        #[cfg(feature = "sqlite-store")]
        StoreSource::Sqlite {
            announces: path, ..
        } => match open_announce_db(path) {
            Ok(mut store) => {
                import_legacy_announces(&mut store, source);
                Some(Box::new(store))
            }
            Err(e) => {
                error!(
                    path = %path.display(),
                    "could not open the announce cache database, keeping cached announces in memory for this session: {e}; remove the announces.db* files or update to recover"
                );
                None
            }
        },
    }
}

/// The `known_destinations` row for a live entry, or `None` when the entry has no
/// identity key (the table requires one).
pub(super) fn known_destination_row(entry: &RecentAnnounce) -> Option<KnownDestinationRow> {
    let public_key = entry.public_key?;
    let mut row = KnownDestinationRow::new(entry.dest_hash, entry.timestamp, public_key);
    row.packet_hash = entry.packet_hash;
    row.app_data = entry.app_data.clone();
    row.used = if entry.retained {
        -1.0
    } else {
        entry.last_used.unwrap_or(0.0)
    };
    row.stamp = entry.stamp.map(|s| s.to_vec());
    row.stamp_value = entry.stamp_value;
    row.lr_cost = entry.lr_cost;
    row.announce_facts = entry
        .facts_known
        .then(|| AnnounceFacts::new(entry.hops, entry.name_hash, entry.is_path_response));
    Some(row)
}

/// A table row as the actor holds it. Upstream's table has no column for the
/// hops, the name hash, or the path-response flag: without this crate's side
/// row they are unknown.
pub(super) fn recent_from_row(row: KnownDestinationRow) -> RecentAnnounce {
    let facts = row.announce_facts;
    RecentAnnounce {
        dest_hash: row.destination_hash,
        hops: facts.map_or(0, |f| f.hops),
        app_data: row.app_data,
        timestamp: row.last_heard,
        public_key: Some(row.public_key),
        ratchet: None,
        ratchet_received: None,
        packet_hash: row.packet_hash,
        is_path_response: facts.is_some_and(|f| f.path_response),
        retained: row.used == -1.0,
        last_used: (row.used > 0.0).then_some(row.used),
        name_hash: facts.map_or([0u8; 10], |f| f.name_hash),
        stamp: row.stamp.and_then(|s| s.try_into().ok()),
        stamp_value: row.stamp_value,
        lr_cost: row.lr_cost,
        facts_known: facts.is_some(),
    }
}

impl super::TransportActor {
    /// `Identity._remember_ratchet`: a ratchet already held in memory is not
    /// re-queued; otherwise the store is updated and memory takes the receive
    /// time the store keeps, which a repeated ratchet does not restart.
    pub(super) fn remember_received_ratchet(&mut self, dest: DestHash, ratchet: Option<Ratchet>) {
        let Some(ratchet) = ratchet else {
            return;
        };
        if self
            .recent_announces
            .get(&dest)
            .is_some_and(|entry| entry.ratchet == Some(ratchet))
        {
            return;
        }
        let received = self.kd.remember_ratchet(dest, ratchet, crate::now_f64());
        if let Some(entry) = self.recent_announces.get_mut(&dest) {
            entry.ratchet = Some(ratchet);
            entry.ratchet_received = Some(received);
        }
    }

    /// `Identity.get_ratchet`: the in-memory copy, else the pending or stored
    /// ratchet within its expiry window. A stored hit is kept in memory for an
    /// entry that exists.
    pub(super) fn recall_ratchet(&mut self, dest: &DestHash, now: f64) -> Option<Ratchet> {
        if let Some(ratchet) = self
            .recent_announces
            .get(dest)
            .and_then(|entry| entry.live_ratchet(now))
        {
            return Some(ratchet);
        }
        let (ratchet, received) = self.kd.stored_ratchet(dest)?;
        if now >= received + rns_wire::constants::RATCHET_EXPIRY as f64 {
            return None;
        }
        if let Some(entry) = self.recent_announces.get_mut(dest) {
            entry.ratchet = Some(ratchet);
            entry.ratchet_received = Some(received);
        }
        Some(ratchet)
    }
}

#[cfg(all(test, feature = "sqlite-store"))]
mod tests {
    use super::*;
    use crate::actor::TransportActor;

    fn temp_dir() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rns-kd-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entry(dest: DestHash, used: Option<f64>, retained: bool) -> RecentAnnounce {
        RecentAnnounce {
            dest_hash: dest,
            hops: 2,
            app_data: Some(b"app".to_vec()),
            timestamp: crate::now_f64() - 5.0,
            public_key: Some([dest[0]; 64]),
            ratchet: None,
            ratchet_received: None,
            packet_hash: Some([dest[0]; 32]),
            is_path_response: false,
            retained,
            last_used: used,
            name_hash: [0; 10],
            stamp: None,
            stamp_value: 0.0,
            lr_cost: Some(3.0),
            facts_known: true,
        }
    }

    fn actor_on(dir: &Path) -> TransportActor {
        let (mut actor, _tx) = TransportActor::new();
        actor.initialize_storage(dir.to_path_buf());
        actor
    }

    #[test]
    fn a_failed_batch_does_not_replace_a_newer_pending_ratchet() {
        let mut pending = KdPending::default();
        pending.ratchet_upserts.insert([7; 16], ([2; 32], 200.0));
        let failed = KdBatch {
            ratchet_upserts: vec![
                crate::store::RatchetRow::new([7; 16], [1; 32], 100.0),
                crate::store::RatchetRow::new([8; 16], [3; 32], 100.0),
            ],
            ..KdBatch::default()
        };
        pending.restore(failed);
        assert_eq!(pending.ratchet_upserts[&[7; 16]], ([2; 32], 200.0));
        assert_eq!(pending.ratchet_upserts[&[8; 16]], ([3; 32], 100.0));
    }

    #[test]
    fn a_mark_cancels_the_opposite_mark() {
        let mut p = KdPending::default();
        p.mark_dirty([1; 16]);
        p.mark_deleted([1; 16]);
        assert!(!p.dirty.contains(&[1; 16]) && p.deleted.contains(&[1; 16]));
        assert!(p.ratchet_deletes.contains(&[1; 16]));
        p.mark_dirty([1; 16]);
        assert!(p.dirty.contains(&[1; 16]) && !p.deleted.contains(&[1; 16]));

        let mut entries = HashMap::new();
        entries.insert([1; 16], entry([1; 16], None, false));
        p.ratchet_upserts.insert([2; 16], ([7; 32], 1.0));
        let (batch, known) = p.take_batch(&entries);
        assert_eq!(batch.upserts.len(), 1);
        assert!(known.contains(&[1; 16]) && !known.contains(&[2; 16]));
        assert!(
            batch.ratchet_deletes.contains(&[2; 16]),
            "a ratchet of an unknown destination becomes a delete"
        );
        assert!(p.is_empty());
    }

    #[test]
    fn known_destinations_and_ratchets_survive_a_restart() {
        let dir = temp_dir();
        let mut actor = actor_on(&dir);
        let mut with_facts = entry([3; 16], Some(1000.0), false);
        with_facts.name_hash = [7; 10];
        with_facts.is_path_response = true;
        actor.recent_announces.insert([3; 16], with_facts);
        let mut without_facts = entry([4; 16], None, true);
        without_facts.facts_known = false;
        actor.recent_announces.insert([4; 16], without_facts);
        actor.kd.pending.mark_dirty([3; 16]);
        actor.kd.pending.mark_dirty([4; 16]);
        actor.remember_received_ratchet([3; 16], Some([9; 32]));
        actor.on_shutdown();
        assert!(!dir.join("announce_cache.msgpack").exists());

        let mut restarted = actor_on(&dir);
        let a = &restarted.recent_announces[&[3; 16]];
        assert_eq!(a.public_key, Some([3; 64]));
        assert_eq!(a.app_data.as_deref(), Some(&b"app"[..]));
        assert_eq!(a.last_used, Some(1000.0));
        assert_eq!(a.lr_cost, Some(3.0));
        assert_eq!(a.ratchet, None, "ratchets are not loaded at start-up");
        assert!(
            a.facts_known,
            "the side row restores what upstream's row cannot"
        );
        assert_eq!(
            (a.hops, a.name_hash, a.is_path_response),
            (2, [7; 10], true)
        );
        assert!(restarted.recent_announces[&[4; 16]].retained);
        assert!(
            !restarted.recent_announces[&[4; 16]].facts_known,
            "an entry stored without facts comes back with them unknown"
        );
        let now = crate::now_f64();
        assert_eq!(restarted.recall_ratchet(&[3; 16], now), Some([9; 32]));
        assert_eq!(
            restarted.recent_announces[&[3; 16]].ratchet,
            Some([9; 32]),
            "a ratchet read from the store is kept in memory"
        );
        restarted.on_shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_stored_ratchet_past_its_expiry_is_not_returned() {
        let dir = temp_dir();
        let mut actor = actor_on(&dir);
        actor
            .recent_announces
            .insert([5; 16], entry([5; 16], None, false));
        actor.kd.pending.mark_dirty([5; 16]);
        actor.kd.remember_ratchet([5; 16], [8; 32], 10.0);
        actor.on_shutdown();
        let mut restarted = actor_on(&dir);
        assert_eq!(restarted.recall_ratchet(&[5; 16], crate::now_f64()), None);
        restarted.on_shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_delete_is_skipped_for_a_destination_learned_again() {
        let dir = temp_dir();
        let mut actor = actor_on(&dir);
        actor
            .recent_announces
            .insert([6; 16], entry([6; 16], None, false));
        actor.kd.pending.mark_dirty([6; 16]);
        actor.kd.shutdown(&actor.recent_announces, true);
        actor.kd.attach_storage(&dir);
        actor.kd.pending.mark_deleted([6; 16]);
        actor.on_shutdown();
        let mut restarted = actor_on(&dir);
        assert!(restarted.recent_announces.contains_key(&[6; 16]));
        restarted.recent_announces.remove(&[6; 16]);
        restarted.kd.pending.mark_deleted([6; 16]);
        restarted.on_shutdown();
        let restarted = actor_on(&dir);
        assert!(!restarted.recent_announces.contains_key(&[6; 16]));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_rust_announce_cache_is_imported_once_and_again_after_a_crash() {
        let dir = temp_dir();
        let mut legacy = entry([7; 16], None, true);
        legacy.ratchet = Some([1; 32]);
        legacy.ratchet_received = Some(crate::now_f64() - 60.0);
        let path = dir.join("announce_cache.msgpack");
        crate::persistence::save_announce_cache([&legacy], &path).unwrap();
        let bytes = std::fs::read(&path).unwrap();

        // Start-up runs the import, then renames the source.
        let mut actor = actor_on(&dir);
        assert!(!path.exists());
        assert!(dir.join("announce_cache.msgpack.imported").exists());
        assert!(actor.recent_announces[&[7; 16]].retained);
        actor.on_shutdown();

        let mut restarted = actor_on(&dir);
        assert!(restarted.recent_announces[&[7; 16]].retained);
        assert_eq!(
            restarted.recall_ratchet(&[7; 16], crate::now_f64()),
            Some([1; 32])
        );
        restarted.on_shutdown();

        // Crash between commit and rename: the source is still there and imports to the same rows.
        std::fs::write(&path, &bytes).unwrap();
        let mut again = actor_on(&dir);
        assert_eq!(again.recent_announces.len(), 1);
        again.on_shutdown();
        assert!(!path.exists());
        let again = actor_on(&dir);
        assert_eq!(again.recent_announces.len(), 1);
        assert_eq!(again.recent_announces[&[7; 16]].public_key, Some([7; 64]));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A 1.0.44 cache kept no ratchet receive times. A ratchet file handed over
    /// by lxmd-rs or Ratspeak after the cache's last announce is newer and wins.
    #[test]
    fn a_handed_over_ratchet_newer_than_the_caches_last_announce_wins() {
        let dir = temp_dir();
        let now = crate::now_f64();
        let mut cached = entry([11; 16], None, true);
        cached.timestamp = now - 3600.0;
        cached.ratchet = Some([1; 32]);
        crate::persistence::save_announce_cache([&cached], &dir.join("announce_cache.msgpack"))
            .unwrap();
        rns_identity::ratchet::ReceivedRatchet::new_at([2; 32], now - 60.0)
            .save(&dir.join("ratchets").join(hex::encode([11u8; 16])))
            .unwrap();
        let mut actor = actor_on(&dir);
        assert_eq!(
            actor.kd.stored_ratchet(&[11; 16]),
            Some(([2; 32], now - 60.0))
        );
        actor.on_shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    fn write_python_known_destination(dir: &Path, dest: DestHash, last_heard: f64, app: &[u8]) {
        use rmpv::Value;
        let file = Value::Map(vec![(
            Value::Binary(dest.to_vec()),
            Value::Array(vec![
                Value::F64(last_heard),
                Value::Binary(vec![9; 32]),
                Value::Binary(vec![dest[0]; 64]),
                Value::Binary(app.to_vec()),
                Value::Integer(0.into()),
            ]),
        )]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &file).unwrap();
        std::fs::write(dir.join("known_destinations"), bytes).unwrap();
    }

    /// Both legacy sources beside a new database: an older Python row must not
    /// replace the Rust cache's row, its pin and facts included.
    #[test]
    fn an_older_python_known_destination_does_not_replace_the_rust_cache_row() {
        let dir = temp_dir();
        let now = crate::now_f64();
        let mut cached = entry([12; 16], None, true);
        cached.timestamp = now - 60.0;
        cached.name_hash = [5; 10];
        crate::persistence::save_announce_cache([&cached], &dir.join("announce_cache.msgpack"))
            .unwrap();
        write_python_known_destination(&dir, [12; 16], now - 5.0 * 86_400.0, b"old name");
        let mut actor = actor_on(&dir);
        let restored = &actor.recent_announces[&[12; 16]];
        assert_eq!(restored.app_data.as_deref(), Some(&b"app"[..]));
        assert_eq!(restored.timestamp, now - 60.0);
        assert!(restored.retained && restored.facts_known);
        actor.on_shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A database that is only read still keeps its rows over older legacy files.
    #[test]
    fn a_staged_read_keeps_a_stored_row_heard_after_the_legacy_file() {
        let dir = temp_dir();
        let now = crate::now_f64();
        let db = dir.join("known_destinations.db");
        let mut row = KnownDestinationRow::new([13; 16], now - 60.0, [13; 64]);
        row.app_data = Some(b"stored".to_vec());
        let batch = KdBatch {
            upserts: vec![row],
            ..KdBatch::default()
        };
        SqliteKnownDestinations::open_rw(&db)
            .unwrap()
            .apply(&batch, &|_| true)
            .unwrap();
        write_python_known_destination(&dir, [13; 16], now - 3600.0, b"old name");
        let rows = read_and_stage(&db, now);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].app_data.as_deref(), Some(&b"stored"[..]));
        assert!(dir.join("known_destinations").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_corrupt_database_starts_the_session_in_memory() {
        let dir = temp_dir();
        std::fs::write(
            dir.join("known_destinations.db"),
            b"not a sqlite file at all",
        )
        .unwrap();
        let mut actor = actor_on(&dir);
        actor
            .recent_announces
            .insert([9; 16], entry([9; 16], None, false));
        actor.kd.pending.mark_dirty([9; 16]);
        actor.on_shutdown();
        assert!(
            dir.join("known_destinations.db").is_file(),
            "a corrupt file is left in place"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn an_unwritable_directory_starts_the_session_in_memory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        // Root ignores the mode, so the directory cannot be made unwritable.
        if std::fs::write(dir.join("probe"), b"").is_ok() {
            let _ = std::fs::remove_dir_all(dir);
            return;
        }
        let mut actor = actor_on(&dir);
        actor
            .recent_announces
            .insert([10; 16], entry([10; 16], None, false));
        actor.kd.pending.mark_dirty([10; 16]);
        actor.on_shutdown();
        assert!(!dir.join("known_destinations.db").exists());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Waits for the worker's next answer and applies it, as the actor loop does.
    fn settle(actor: &mut TransportActor) {
        let result = actor
            .kd
            .results
            .blocking_recv()
            .expect("store worker answers");
        actor.kd.handle(result);
    }

    fn announces_db(dir: &Path) -> PathBuf {
        dir.join("cache").join("announces.db")
    }

    fn legacy_file(dir: &Path, hash: &PacketHash) -> PathBuf {
        dir.join("cache").join("announces").join(hex::encode(hash))
    }

    fn write_legacy_announce(dir: &Path, hash: &PacketHash, raw: &[u8]) {
        crate::persistence::write_python_cached_announce(
            &dir.join("cache").join("announces"),
            hash,
            raw,
            Some("legacy0"),
        )
        .unwrap();
    }

    #[test]
    fn a_failed_flush_does_not_replace_a_newer_announce() {
        let old = |h: u8| AnnounceRow::new([h; 32], 100.0, vec![1], None);
        let new = |h: u8| AnnounceRow::new([h; 32], 200.0, vec![2], None);
        let mut p = AnnouncePending::default();
        for h in [1, 2, 3] {
            p.rows.insert([h; 32], old(h));
        }
        let (first, sent) = p.take_flush();
        assert_eq!(sent.len(), 3);
        assert_eq!(p.get(&[1; 32]), Some(&old(1)), "in flight is still fetched");

        // 1 is stored again and still pending; 2 is stored again and sent in a later flush.
        p.rows.insert([2; 32], new(2));
        let (second, _) = p.take_flush();
        p.rows.insert([1; 32], new(1));

        p.restore(first);
        assert_eq!(p.rows[&[1; 32]], new(1), "the newer pending row stays");
        assert!(!p.rows.contains_key(&[2; 32]), "the newer row is in flight");
        assert_eq!(p.get(&[2; 32]), Some(&new(2)));
        assert_eq!(
            p.rows[&[3; 32]],
            old(3),
            "an unwritten row is pending again"
        );

        p.confirm(second);
        assert!(p.in_flight.is_empty());
    }

    #[test]
    fn a_cached_announce_is_fetched_while_pending_and_after_a_restart() {
        let dir = temp_dir();
        let mut actor = actor_on(&dir);
        let hash = [0x21; 32];
        actor
            .kd
            .store_announce(hash, &[1; 40], Some("first".into()));
        actor
            .kd
            .store_announce(hash, &[2; 40], Some("second".into()));
        let latest = Some((vec![2; 40], Some("second".to_string())));
        assert_eq!(actor.kd.fetch_announce(&hash, true), latest);
        let stored = SqliteAnnounceCache::open_ro(&announces_db(&dir))
            .unwrap()
            .fetch(&hash)
            .unwrap();
        assert_eq!(stored, None, "nothing is written before a flush");

        actor.kd.flush_announces_due(crate::now_f64());
        assert_eq!(
            actor.kd.fetch_announce(&hash, true),
            latest,
            "a row on its way to the store is still fetched"
        );
        settle(&mut actor);
        assert!(actor.kd.announces.rows.is_empty() && actor.kd.announces.in_flight.is_empty());
        assert_eq!(actor.kd.fetch_announce(&hash, true), latest);

        // A row stored after the flush is written at exit.
        let late = [0x22; 32];
        actor.kd.store_announce(late, &[3; 40], None);
        actor.on_shutdown();

        let mut restarted = actor_on(&dir);
        assert_eq!(restarted.kd.fetch_announce(&hash, true), latest);
        assert_eq!(
            restarted.kd.fetch_announce(&late, true),
            Some((vec![3; 40], None))
        );
        restarted.on_shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_flush_waits_for_its_interval_unless_too_many_announces_are_pending() {
        let dir = temp_dir();
        let mut actor = actor_on(&dir);
        let start = crate::now_f64();
        actor.kd.store_announce([1; 32], &[1; 40], None);
        actor.kd.flush_announces_due(start);
        settle(&mut actor);

        actor.kd.store_announce([2; 32], &[1; 40], None);
        actor
            .kd
            .flush_announces_due(start + ANNOUNCE_CACHE_FLUSH_INTERVAL - 1.0);
        assert_eq!(actor.kd.announces.rows.len(), 1, "not due yet");

        for i in 0..=ANNOUNCE_CACHE_MAX_PENDING as u32 {
            let mut hash = [3; 32];
            hash[..4].copy_from_slice(&i.to_be_bytes());
            actor.kd.store_announce(hash, &[1; 40], None);
        }
        actor.kd.flush_announces_due(start + 1.0);
        assert!(
            actor.kd.announces.rows.is_empty(),
            "more than the pending limit flushes at once"
        );
        settle(&mut actor);

        // After a failed flush the pending count alone does not start another.
        actor.kd.handle(StoreResult::AnnounceFailed {
            flush: 0,
            error: StoreError::Locked,
        });
        for i in 0..=ANNOUNCE_CACHE_MAX_PENDING as u32 {
            let mut hash = [4; 32];
            hash[..4].copy_from_slice(&i.to_be_bytes());
            actor.kd.store_announce(hash, &[1; 40], None);
        }
        actor.kd.flush_announces_due(start + 2.0);
        assert!(!actor.kd.announces.rows.is_empty());
        actor
            .kd
            .flush_announces_due(start + 1.0 + ANNOUNCE_CACHE_FLUSH_INTERVAL);
        assert!(
            actor.kd.announces.rows.is_empty(),
            "retried at the interval"
        );
        settle(&mut actor);
        assert!(!actor.kd.announces.flush_failed);
        actor.on_shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Runs a session over a storage directory whose announce database cannot be
    /// opened for writing, and checks the cache works from memory.
    fn runs_from_memory(dir: &Path) {
        let mut actor = actor_on(dir);
        assert!(actor.kd.announces.in_memory, "found at start-up");
        let (kept, dropped) = ([0x31; 32], [0x32; 32]);
        actor.kd.store_announce(kept, &[1; 40], Some("if0".into()));
        actor.kd.flush_announces_due(crate::now_f64());
        assert_eq!(
            actor.kd.fetch_announce(&kept, true),
            Some((vec![1; 40], Some("if0".to_string()))),
            "an announce cached this session is still served"
        );

        // Flushes send nothing, so nothing can fail again.
        actor.kd.store_announce(dropped, &[2; 40], None);
        actor
            .kd
            .flush_announces_due(crate::now_f64() + 2.0 * ANNOUNCE_CACHE_FLUSH_INTERVAL);
        assert!(actor.kd.announces.in_flight.is_empty());
        assert!(actor.kd.results.try_recv().is_err());

        actor.kd.clean_announces([kept].into_iter().collect());
        assert!(actor.kd.fetch_announce(&kept, true).is_some());
        assert_eq!(actor.kd.fetch_announce(&dropped, true), None);
        assert!(!actor.kd.announce_clean_in_flight());
        actor.on_shutdown();
    }

    #[test]
    fn a_newer_announce_database_is_left_alone_and_the_cache_runs_from_memory() {
        let dir = temp_dir();
        std::fs::create_dir_all(dir.join("cache")).unwrap();
        {
            let conn = rusqlite::Connection::open(announces_db(&dir)).unwrap();
            conn.execute_batch("PRAGMA user_version = 7; CREATE TABLE cached_announces (x);")
                .unwrap();
        }
        let before = std::fs::read(announces_db(&dir)).unwrap();
        runs_from_memory(&dir);
        assert_eq!(std::fs::read(announces_db(&dir)).unwrap(), before);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_corrupt_announce_database_is_left_alone_and_the_cache_runs_from_memory() {
        let dir = temp_dir();
        std::fs::create_dir_all(dir.join("cache")).unwrap();
        std::fs::write(announces_db(&dir), b"not a sqlite file at all").unwrap();
        runs_from_memory(&dir);
        assert_eq!(
            std::fs::read(announces_db(&dir)).unwrap(),
            b"not a sqlite file at all"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn an_unwritable_cache_directory_runs_the_cache_from_memory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let cache = dir.join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o500)).unwrap();
        // Root ignores the mode, so the directory cannot be made unwritable.
        if std::fs::write(cache.join("probe"), b"").is_ok() {
            let _ = std::fs::remove_dir_all(dir);
            return;
        }
        runs_from_memory(&dir);
        assert!(!announces_db(&dir).exists());
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_owner_imports_legacy_announce_files_at_start() {
        let dir = temp_dir();
        let legacy = [0x41; 32];
        write_legacy_announce(&dir, &legacy, &[9; 40]);
        let mut actor = actor_on(&dir);
        assert!(
            !legacy_file(&dir, &legacy).exists(),
            "start-up imports the file and removes it"
        );
        assert_eq!(
            actor.kd.fetch_announce(&legacy, true),
            Some((vec![9; 40], Some("legacy0".to_string())))
        );
        actor.on_shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A version 5 Rust cache carries its announces inline. They are written
    /// out as legacy files by the known-destinations import and must reach the
    /// announce database in the same session.
    fn write_v5_cache(dir: &Path) -> (DestHash, PacketHash, Vec<u8>) {
        let identity = rns_identity::identity::Identity::new();
        let mut destination = rns_identity::destination::Destination::new(
            Some(&identity),
            rns_identity::destination::Direction::In,
            rns_identity::destination::DestType::Single,
            "store.v5",
        )
        .unwrap();
        let raw = destination
            .announce_packet(&identity, None, None, false, None, crate::now_f64())
            .unwrap();
        let packet_hash = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        let announce = rns_identity::announce::AnnounceData::unpack(&raw[offset..], false).unwrap();
        let entry = rmpv::Value::Map(vec![
            (
                "destination_hash".into(),
                rmpv::Value::Binary(destination.hash.to_vec()),
            ),
            ("hops".into(), 3.into()),
            ("app_data".into(), rmpv::Value::Nil),
            (
                "timestamp".into(),
                rmpv::Value::F64(crate::now_f64() - 30.0),
            ),
            (
                "public_key".into(),
                rmpv::Value::Binary(announce.public_key.to_vec()),
            ),
            ("ratchet".into(), rmpv::Value::Nil),
            ("raw_packet".into(), rmpv::Value::Binary(raw.clone())),
            ("retained".into(), true.into()),
            (
                "name_hash".into(),
                rmpv::Value::Binary(announce.name_hash.to_vec()),
            ),
        ]);
        let cache = rmpv::Value::Map(vec![
            ("entries".into(), rmpv::Value::Array(vec![entry])),
            ("version".into(), 5.into()),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &cache).unwrap();
        std::fs::write(dir.join("announce_cache.msgpack"), bytes).unwrap();
        (destination.hash, packet_hash, raw)
    }

    fn assert_v5_announce_is_stored(dir: &Path, dest: DestHash, hash: PacketHash, raw: &[u8]) {
        assert!(dir.join("announce_cache.msgpack.imported").exists());
        assert!(
            !legacy_file(dir, &hash).exists(),
            "the announce file is imported, not left behind"
        );
        let mut restarted = actor_on(dir);
        assert_eq!(
            restarted.kd.fetch_announce(&hash, true),
            Some((raw.to_vec(), None))
        );
        let known = &restarted.recent_announces[&dest];
        assert_eq!(known.packet_hash, Some(hash));
        assert!(known.facts_known && known.hops == 3);
        restarted.on_shutdown();
    }

    #[test]
    fn a_version_5_cache_reaches_the_announce_database_at_start() {
        let dir = temp_dir();
        let (dest, hash, raw) = write_v5_cache(&dir);
        let mut actor = actor_on(&dir);
        assert_eq!(
            actor.kd.fetch_announce(&hash, true),
            Some((raw.clone(), None)),
            "stored in the session that imported the cache"
        );
        actor.on_shutdown();
        assert_v5_announce_is_stored(&dir, dest, hash, &raw);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_version_5_cache_imported_after_the_announce_database_opened_still_reaches_it() {
        let dir = temp_dir();
        let (dest, hash, raw) = write_v5_cache(&dir);
        // Storage attached without a start: the announce database opens first,
        // at its first write, and the known-destinations import follows.
        let (mut actor, _tx) = TransportActor::new();
        actor.storage_dir = Some(dir.clone());
        actor.kd.attach_storage(&dir);
        actor.kd.store_announce([0x45; 32], &[1; 40], None);
        actor.kd.flush_announces_due(crate::now_f64());
        settle(&mut actor);
        assert!(dir.join("announce_cache.msgpack").exists());
        actor
            .recent_announces
            .insert([9; 16], entry([9; 16], None, false));
        actor.kd.pending.mark_dirty([9; 16]);
        actor.flush_known_destinations();
        settle(&mut actor);
        assert_eq!(
            actor.kd.fetch_announce(&hash, true),
            Some((raw.clone(), None))
        );
        actor.on_shutdown();
        assert_v5_announce_is_stored(&dir, dest, hash, &raw);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn listing(dir: &Path) -> Vec<std::ffi::OsString> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        names
    }

    fn client_on(dir: &Path) -> TransportActor {
        let (mut actor, _tx) = TransportActor::new();
        actor.initialize_storage_as(
            dir.to_path_buf(),
            crate::actor::StorageRole::SharedInstanceClient,
        );
        actor
    }

    #[test]
    fn a_shared_instance_client_leaves_the_announce_cache_alone() {
        let dir = temp_dir();
        let (stored, legacy) = ([0x51; 32], [0x52; 32]);
        crate::store::seed_cached_announce(&dir, &stored, &[1; 40], None).unwrap();
        write_legacy_announce(&dir, &legacy, &[9; 40]);
        let before = (listing(&dir), listing(&dir.join("cache")));

        let mut actor = client_on(&dir);
        actor.cache_announce(&[0x53; 32], &[2; 40], 0);
        actor.flush_cached_announces(crate::now_f64());
        actor.clean_announce_cache();
        assert!(actor.kd.announces.rows.is_empty());
        assert!(!actor.kd.announce_clean_in_flight());
        assert!(
            actor.cached_announce(&stored).is_none() && actor.cached_announce(&legacy).is_none(),
            "a client has no announce cache"
        );
        assert!(actor.kd.announce_reader.is_none());
        actor.on_shutdown();
        assert!(
            legacy_file(&dir, &legacy).exists(),
            "a client imports nothing"
        );
        assert_eq!(
            (listing(&dir), listing(&dir.join("cache"))),
            before,
            "a client opens and creates nothing"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_shared_instance_client_loads_the_owners_rows_and_restores_no_paths() {
        let dir = temp_dir();
        let mut owner = actor_on(&dir);
        owner
            .recent_announces
            .insert([3; 16], entry([3; 16], Some(1000.0), false));
        owner.kd.pending.mark_dirty([3; 16]);
        let now = crate::now_f64();
        let mut path =
            crate::path_table::PathEntry::new(None, 1, 7, crate::constants::InterfaceMode::Full);
        path.timestamp = now;
        path.expires = now + 3600.0;
        path.packet_hash = Some([3; 32]);
        let mut table = crate::path_table::PathTable::new();
        table.insert([3; 16], path);
        let names = HashMap::from([(7u64, "uplink".to_string())]);
        crate::persistence::save_python_destination_table(
            &table,
            &names,
            &dir.join("destination_table"),
        )
        .unwrap();
        owner
            .kd
            .store_announce([3; 32], &[0xFE; 42], Some("uplink".into()));
        owner.on_shutdown();

        let mut client = client_on(&dir);
        let known = &client.recent_announces[&[3; 16]];
        assert_eq!(known.public_key, Some([3; 64]));
        assert_eq!(known.last_used, Some(1000.0));
        assert!(
            client.pending_path_entries.is_empty(),
            "a client restores no paths and reads no cached announce"
        );
        assert!(client.kd.announce_reader.is_none());
        // What a client learns stays in memory.
        client
            .recent_announces
            .insert([4; 16], entry([4; 16], None, false));
        client.kd.pending.mark_dirty([4; 16]);
        client.flush_known_destinations();
        client.on_shutdown();
        let restarted = actor_on(&dir);
        assert!(!restarted.recent_announces.contains_key(&[4; 16]));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_shared_instance_client_reads_a_running_owners_rows() {
        let dir = temp_dir();
        let mut owner = actor_on(&dir);
        owner
            .recent_announces
            .insert([5; 16], entry([5; 16], Some(1000.0), false));
        owner.kd.pending.mark_dirty([5; 16]);
        owner.flush_known_destinations();
        settle(&mut owner);
        // The owner keeps its database open, the rows still in its WAL.
        let client = client_on(&dir);
        assert!(client.recent_announces.contains_key(&[5; 16]));
        drop(client);
        owner.on_shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_shared_instance_client_writes_nothing() {
        let dir = temp_dir();
        let mut actor = client_on(&dir);
        actor
            .recent_announces
            .insert([8; 16], entry([8; 16], None, false));
        actor.kd.pending.mark_dirty([8; 16]);
        actor.flush_known_destinations();
        actor.on_shutdown();
        assert!(!dir.join("known_destinations.db").exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
