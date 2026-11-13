//! Write-behind for known destinations and received ratchets (Python
//! `KnownDestinationsStore`). The actor keeps the pending marks and builds each
//! batch from its live entries. One thread owns the read-write store and runs
//! jobs in the order they were sent. The actor reads ratchets through its own
//! read-only connection.

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
use crate::store::{
    ApplyReport, DestHash, KdBatch, KnownDestinationRow, KnownDestinationStore, MemoryStore,
    Ratchet, RatchetRow, RejectedTable, StoreError,
};
#[cfg(feature = "sqlite-store")]
use crate::store::{SqliteKnownDestinations, legacy};

#[derive(Clone)]
enum StoreSource {
    Memory,
    #[cfg(feature = "sqlite-store")]
    Sqlite(PathBuf),
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
    #[cfg(feature = "sqlite-store")]
    Load {
        now: f64,
        reply: std_mpsc::Sender<Result<Vec<KnownDestinationRow>, StoreError>>,
    },
}

/// Outcome of one job, delivered to the actor.
pub(super) enum StoreResult {
    Applied { report: ApplyReport },
    Failed { batch: KdBatch, error: StoreError },
    Expired { removed: usize },
    ExpireFailed(StoreError),
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
    // Opened on the first write, so a process that only reads never creates or
    // writes the file.
    let mut slot: Option<Box<dyn KnownDestinationStore>> = None;
    while let Ok(job) = jobs.recv() {
        match job {
            StoreJob::Apply {
                batch,
                known,
                reply,
            } => {
                let is_known = |h: &DestHash| known.contains(h);
                let store = writable(&mut slot, &source);
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
                let store = writable(&mut slot, &source);
                let result = match store.expire_ratchets(cutoff) {
                    Ok(removed) => StoreResult::Expired {
                        removed: removed.len(),
                    },
                    Err(e) => StoreResult::ExpireFailed(e),
                };
                let _ = results.send(result);
            }
            #[cfg(feature = "sqlite-store")]
            StoreJob::Load { now, reply } => {
                let out = match &source {
                    StoreSource::Memory => Vec::new(),
                    StoreSource::Sqlite(path) => load_at_start(path, now),
                };
                let _ = reply.send(Ok(out));
            }
        }
    }
}

/// The writable store for the worker. The first write opens the file and runs any
/// pending legacy import; if the file cannot be opened the session continues on a
/// `MemoryStore`, logged once.
fn writable<'a>(
    slot: &'a mut Option<Box<dyn KnownDestinationStore>>,
    source: &StoreSource,
) -> &'a mut dyn KnownDestinationStore {
    if slot.is_none() {
        let store: Box<dyn KnownDestinationStore> = match source {
            StoreSource::Memory => Box::new(MemoryStore::new()),
            #[cfg(feature = "sqlite-store")]
            StoreSource::Sqlite(path) => match SqliteKnownDestinations::open_rw(path) {
                Ok(mut store) => {
                    import_known_sources(
                        &LegacyFiles::beside(path),
                        crate::now_f64(),
                        &mut store,
                        true,
                    );
                    Box::new(store)
                }
                Err(e) => {
                    error!(
                        path = %path.display(),
                        "could not open the known destinations database, keeping entries in memory for this session: {e}; remove the known_destinations.db* files or update to recover"
                    );
                    Box::new(MemoryStore::new())
                }
            },
        };
        *slot = Some(store);
    }
    slot.as_deref_mut().expect("store opened above")
}

// Used by the import, which needs the SQLite store.
#[cfg_attr(not(feature = "sqlite-store"), allow(dead_code))]
fn read_rows(
    store: &mut dyn KnownDestinationStore,
) -> Result<Vec<KnownDestinationRow>, StoreError> {
    let mut rows = Vec::new();
    store.load_all(&mut |row| rows.push(row))?;
    Ok(rows)
}

#[cfg_attr(not(feature = "sqlite-store"), allow(dead_code))]
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
    store: &mut dyn KnownDestinationStore,
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
                    "imported Python known destinations"
                );
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

/// Startup read (Python `Identity.load_known_destinations`). Rows already in the
/// database come through a read-only connection; legacy rows are staged over them in
/// memory. Nothing is written or renamed here: the first write imports the sources,
/// so a shared-instance client that never writes leaves its directory alone.
#[cfg(feature = "sqlite-store")]
fn load_at_start(path: &Path, now: f64) -> Vec<KnownDestinationRow> {
    let mut rows: HashMap<DestHash, KnownDestinationRow> = HashMap::new();
    if path.is_file() {
        let read = SqliteKnownDestinations::open_ro(path).and_then(|mut reader| {
            let mut loaded = Vec::new();
            reader.load_all(&mut |row| loaded.push(row))?;
            Ok::<_, StoreError>(loaded)
        });
        match read {
            Ok(loaded) => rows.extend(loaded.into_iter().map(|r| (r.destination_hash, r))),
            Err(e) => error!(
                "could not read {}: {e}; continuing without its entries",
                path.display()
            ),
        }
    }
    let mut staged = MemoryStore::new();
    import_known_sources(&LegacyFiles::beside(path), now, &mut staged, false);
    if let Err(e) = staged.load_all(&mut |row| {
        rows.insert(row.destination_hash, row);
    }) {
        error!("could not stage legacy known destinations: {e}");
    }
    rows.into_values().collect()
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

/// The actor's side of the store: pending marks, the worker, and a read-only
/// connection for ratchet lookups.
pub(super) struct KdState {
    pub(super) pending: KdPending,
    /// Taken on the first submit, which starts the worker thread.
    source: Option<StoreSource>,
    worker: Option<StoreWorker>,
    results_tx: tokio_mpsc::UnboundedSender<StoreResult>,
    /// Outcomes of ordinary flushes and expiries, drained by the actor loop.
    pub(super) results: tokio_mpsc::UnboundedReceiver<StoreResult>,
    #[cfg(feature = "sqlite-store")]
    db_path: Option<PathBuf>,
    #[cfg(feature = "sqlite-store")]
    reader: Option<SqliteKnownDestinations>,
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
            #[cfg(feature = "sqlite-store")]
            db_path: None,
            #[cfg(feature = "sqlite-store")]
            reader: None,
        }
    }

    /// Uses `dir`'s `known_destinations.db`. Nothing is opened here; the file is
    /// opened by the worker when a job needs it.
    pub(super) fn attach_storage(&mut self, dir: &Path) {
        self.close(Instant::now() + EXIT_FLUSH_DEADLINE);
        #[cfg(feature = "sqlite-store")]
        {
            let path = dir.join("known_destinations.db");
            self.reader = None;
            self.db_path = Some(path.clone());
            self.source = Some(StoreSource::Sqlite(path));
        }
        #[cfg(not(feature = "sqlite-store"))]
        {
            let _ = dir;
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

    /// Startup: runs the legacy imports and loads every stored row. Called from
    /// `initialize_storage`, before the actor loop starts.
    #[cfg(feature = "sqlite-store")]
    pub(super) fn load_at_start(&mut self, now: f64) -> Vec<KnownDestinationRow> {
        let (tx, rx) = std_mpsc::channel();
        if self.submit(StoreJob::Load { now, reply: tx }).is_err() {
            return Vec::new();
        }
        match rx.recv() {
            Ok(Ok(rows)) => rows,
            Ok(Err(e)) => {
                error!("could not load known destinations: {e}; continuing with an empty table");
                Vec::new()
            }
            Err(_) => Vec::new(),
        }
    }

    #[cfg(not(feature = "sqlite-store"))]
    pub(super) fn load_at_start(&mut self, _now: f64) -> Vec<KnownDestinationRow> {
        Vec::new()
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

    /// Shutdown (`Identity.exit_handler`): applies the pending marks and waits for
    /// the answer, then closes the store.
    pub(super) fn shutdown(&mut self, entries: &HashMap<DestHash, RecentAnnounce>, write: bool) {
        if !write {
            self.pending = KdPending::default();
            self.close(Instant::now() + EXIT_FLUSH_DEADLINE);
            return;
        }
        let deadline = Instant::now() + EXIT_FLUSH_DEADLINE;
        // An empty batch still opens the writable store, which runs any pending legacy import.
        let (tx, rx) = std_mpsc::channel();
        let open = StoreJob::Apply {
            batch: KdBatch::default(),
            known: HashSet::new(),
            reply: Some(tx),
        };
        if self.submit(open).is_ok() {
            let _ = rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        }
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
    /// stored row, are checked before a ratchet is queued.
    pub(super) fn remember_ratchet(&mut self, dest: DestHash, ratchet: Ratchet, now: f64) {
        self.pending.ratchet_quarantine.remove(&dest);
        let same_as_pending = self
            .pending
            .ratchet_upserts
            .get(&dest)
            .map(|(pending, _)| *pending == ratchet);
        let unchanged = match same_as_pending {
            Some(same) => same,
            None => self
                .fetch_stored_ratchet(&dest)
                .is_some_and(|(stored, _)| stored == ratchet),
        };
        if unchanged {
            self.pending.ratchet_deletes.remove(&dest);
            return;
        }
        self.pending.ratchet_quarantine.remove(&dest);
        self.pending.ratchet_upserts.insert(dest, (ratchet, now));
        self.pending.ratchet_deletes.remove(&dest);
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

/// The `known_destinations` row for a live entry, or `None` when the entry has no
/// identity key (the table requires one).
fn known_destination_row(entry: &RecentAnnounce) -> Option<KnownDestinationRow> {
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
    Some(row)
}

/// A table row as the actor holds it. Hops and the name hash are not stored
/// upstream either, so they start empty.
#[cfg(feature = "sqlite-store")]
pub(super) fn recent_from_row(row: KnownDestinationRow) -> RecentAnnounce {
    RecentAnnounce {
        dest_hash: row.destination_hash,
        hops: 0,
        app_data: row.app_data,
        timestamp: row.last_heard,
        public_key: Some(row.public_key),
        ratchet: None,
        ratchet_received: None,
        packet_hash: row.packet_hash,
        is_path_response: false,
        retained: row.used == -1.0,
        last_used: (row.used > 0.0).then_some(row.used),
        name_hash: [0u8; 10],
        stamp: row.stamp.and_then(|s| s.try_into().ok()),
        stamp_value: row.stamp_value,
        lr_cost: row.lr_cost,
    }
}

impl super::TransportActor {
    /// `Identity._remember_ratchet`: a ratchet already held in memory is not
    /// re-queued; otherwise memory is filled and the store is updated.
    pub(super) fn remember_received_ratchet(&mut self, dest: DestHash, ratchet: Option<Ratchet>) {
        let Some(ratchet) = ratchet else {
            return;
        };
        let now = crate::now_f64();
        if let Some(entry) = self.recent_announces.get_mut(&dest) {
            if entry.ratchet == Some(ratchet) {
                return;
            }
            entry.ratchet = Some(ratchet);
            entry.ratchet_received = Some(now);
        }
        self.kd.remember_ratchet(dest, ratchet, now);
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
        actor
            .recent_announces
            .insert([3; 16], entry([3; 16], Some(1000.0), false));
        actor
            .recent_announces
            .insert([4; 16], entry([4; 16], None, true));
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
        assert!(restarted.recent_announces[&[4; 16]].retained);
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

        // The first write runs the import, then renames the source.
        let mut actor = actor_on(&dir);
        assert!(path.exists(), "a start-up read does not import");
        actor.kd.pending.mark_dirty([7; 16]);
        actor.on_shutdown();
        assert!(!path.exists());
        assert!(dir.join("announce_cache.msgpack.imported").exists());

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
        again.kd.pending.mark_dirty([7; 16]);
        again.on_shutdown();
        assert!(!path.exists());
        let again = actor_on(&dir);
        assert_eq!(again.recent_announces.len(), 1);
        assert_eq!(again.recent_announces[&[7; 16]].public_key, Some([7; 64]));
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

    #[test]
    fn a_shared_instance_client_writes_nothing() {
        let dir = temp_dir();
        let mut actor = actor_on(&dir);
        actor.shared_instance_client_mode = true;
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
