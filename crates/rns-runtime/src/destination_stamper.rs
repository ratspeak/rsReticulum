//! Destination stamps for announces, generated off the async runtime.
//!
//! Python reference (1.6.0): `Destination.announce`, `_await_stamp` and
//! `_announce` (`RNS/Destination.py:208-213, 266-365`), the stamper queue
//! (`RNS/Transport.py:99-120, 1445-1493`) and stamp persistence
//! (`RNS/Stamps.py:862-930`). One worker thread serves every destination of
//! the process, one job at a time. An announce requested while its stamp is
//! missing or below target is parked and sent when the stamp is ready.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};

use rns_identity::announce::AnnounceStampExt;
use rns_identity::destination::{
    Destination, DestinationError, Direction, load_destination_stamp, store_destination_stamp,
};
use rns_identity::identity::Identity;
use rns_identity::stamps::{NETWORK_STAMP_SIZE, StampControl, generate_stamp};
use rns_transport::stamps::{STAMPER_AN_QUEUE_LENGTH, STAMPER_PR_QUEUE_LENGTH, StampPolicy};
use tokio::sync::mpsc;

/// A destination stamp and its value.
pub type DestinationStamp = ([u8; NETWORK_STAMP_SIZE], f64);

#[derive(Clone, Default)]
struct Settings {
    policy: StampPolicy,
    storage_dir: Option<PathBuf>,
}

static SETTINGS: RwLock<Option<Settings>> = RwLock::new(None);

/// Set the process stamp policy and storage root, as Python keeps them on
/// `Transport` and `Reticulum.storagepath`. `init` calls this; embedders that
/// run without `init` call it themselves before creating destinations.
pub fn configure(policy: StampPolicy, storage_dir: Option<PathBuf>) {
    let mut settings = SETTINGS.write().unwrap_or_else(|e| e.into_inner());
    *settings = Some(Settings {
        policy,
        storage_dir,
    });
}

fn settings() -> Settings {
    SETTINGS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_default()
}

/// The configured process stamp policy, or the 1.6.0 defaults.
pub fn policy() -> StampPolicy {
    settings().policy
}

/// Python constructor behaviour: an inbound destination whose identity holds
/// a private key loads a stored stamp of at least `DESTINATION_COST`.
pub fn load_stored_stamp(destination: &mut Destination, identity: &Identity) {
    let Settings {
        policy,
        storage_dir,
    } = settings();
    if destination.direction != Direction::In
        || !identity.has_private_key()
        || !policy.stamp_destinations
    {
        return;
    }
    let Some(storage_dir) = storage_dir else {
        return;
    };
    let material = destination.stamp_material(&identity.get_public_key());
    if let Some((stamp, value)) = load_destination_stamp(
        &storage_dir,
        &destination.hash,
        &material,
        policy.destination_cost,
    ) {
        destination.set_destination_stamp(stamp, value);
        tracing::debug!(value, dest = %destination, "loaded destination stamp");
    }
}

/// Result of one generation job.
#[derive(Debug, Clone, Copy)]
pub struct StampOutcome {
    pub stamp: Option<DestinationStamp>,
}

struct Job {
    owner: u64,
    destination_hash: [u8; 16],
    material: Vec<u8>,
    target: f64,
    storage_dir: Option<PathBuf>,
    cancel: Arc<AtomicBool>,
    reply: mpsc::UnboundedSender<StampOutcome>,
}

#[derive(Default)]
struct Queues {
    path_responses: VecDeque<Job>,
    announces: VecDeque<Job>,
}

struct Worker {
    queues: Mutex<Queues>,
    ready: Condvar,
}

static WORKER: OnceLock<Arc<Worker>> = OnceLock::new();
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

fn worker() -> &'static Arc<Worker> {
    WORKER.get_or_init(|| {
        let worker = Arc::new(Worker {
            queues: Mutex::new(Queues::default()),
            ready: Condvar::new(),
        });
        let shared = worker.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("rns-destination-stamper".into())
            .spawn(move || run_worker(&shared))
        {
            tracing::error!(%error, "could not start the destination stamp worker");
        }
        worker
    })
}

enum Priority {
    PathResponse,
    Announce,
}

/// Python `WorkerQueues.put`: drop a queued job with the same key, then
/// refuse when the priority's queue is full.
fn submit(job: Job, priority: Priority) -> bool {
    let worker = worker();
    let mut queues = worker.queues.lock().unwrap_or_else(|e| e.into_inner());
    queues
        .path_responses
        .retain(|queued| queued.owner != job.owner);
    queues.announces.retain(|queued| queued.owner != job.owner);
    let (queue, capacity) = match priority {
        Priority::PathResponse => (&mut queues.path_responses, STAMPER_PR_QUEUE_LENGTH),
        Priority::Announce => (&mut queues.announces, STAMPER_AN_QUEUE_LENGTH),
    };
    if queue.len() >= capacity {
        return false;
    }
    queue.push_back(job);
    worker.ready.notify_one();
    true
}

/// Move a queued announce job to the path-response queue, if it is still queued.
fn promote(owner: u64) {
    let worker = worker();
    let mut queues = worker.queues.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(index) = queues.announces.iter().position(|job| job.owner == owner)
        && queues.path_responses.len() < STAMPER_PR_QUEUE_LENGTH
        && let Some(job) = queues.announces.remove(index)
    {
        queues.path_responses.push_back(job);
    }
}

fn run_worker(worker: &Worker) {
    loop {
        let job = {
            let mut queues = worker.queues.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if let Some(job) = queues.path_responses.pop_front() {
                    break job;
                }
                if let Some(job) = queues.announces.pop_front() {
                    break job;
                }
                queues = worker.ready.wait(queues).unwrap_or_else(|e| e.into_inner());
            }
        };
        if job.cancel.load(Ordering::Relaxed) || job.reply.is_closed() {
            continue;
        }
        let stamp = stamp_for(&job);
        let _ = job.reply.send(StampOutcome { stamp });
    }
}

/// The load-or-generate step of `Destination._await_stamp`.
fn stamp_for(job: &Job) -> Option<DestinationStamp> {
    let dest = hex::encode(job.destination_hash);
    if let Some(dir) = job.storage_dir.as_deref()
        && let Some(stamp) =
            load_destination_stamp(dir, &job.destination_hash, &job.material, job.target)
    {
        return Some(stamp);
    }
    let ctl = StampControl {
        cancel: job.cancel.clone(),
        deadline: None,
        threads: std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN),
    };
    let generated = match generate_stamp(&job.material, job.target, 0, NETWORK_STAMP_SIZE, &ctl) {
        Ok(Some((stamp, value))) => {
            let stamp: [u8; NETWORK_STAMP_SIZE] = stamp
                .try_into()
                .expect("generated with the network stamp size");
            (stamp, value)
        }
        Ok(None) => {
            tracing::debug!(%dest, "destination stamp generation failed or was aborted");
            return None;
        }
        Err(error) => {
            tracing::debug!(%dest, %error, "destination stamp generation failed");
            return None;
        }
    };
    match job.storage_dir.as_deref() {
        Some(dir) => {
            if let Err(error) =
                store_destination_stamp(dir, &job.destination_hash, &generated.0, generated.1)
            {
                tracing::warn!(%dest, %error, "an error occurred while persisting destination stamp");
            }
        }
        None => tracing::warn!("no storage path available, destination stamp not persisted"),
    }
    tracing::debug!(%dest, value = generated.1, "generated and persisted destination stamp");
    Some(generated)
}

/// What to do with a requested announce.
pub enum Admission<T> {
    /// Build and send now, with this extension when stamping is on.
    Ready(T, Option<AnnounceStampExt>),
    /// Parked until the stamp is ready.
    Queued,
    /// The stamper queue is full; Python drops the announce.
    Dropped(T),
}

/// Per-destination stamp state for an owner's event loop. Parked path
/// responses are kept in order; ordinary announces coalesce to the latest.
pub struct DestinationStamps<T> {
    owner: u64,
    tx: mpsc::UnboundedSender<StampOutcome>,
    rx: mpsc::UnboundedReceiver<StampOutcome>,
    parked_path_responses: VecDeque<T>,
    parked_announce: Option<T>,
    job: Option<Arc<AtomicBool>>,
}

impl<T> Default for DestinationStamps<T> {
    fn default() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            owner: NEXT_OWNER.fetch_add(1, Ordering::Relaxed),
            tx,
            rx,
            parked_path_responses: VecDeque::new(),
            parked_announce: None,
            job: None,
        }
    }
}

impl<T> DestinationStamps<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Python `Destination.announce` dispatch, without blocking the caller.
    pub fn admit(
        &mut self,
        destination: &Destination,
        identity: &Identity,
        path_response: bool,
        item: T,
    ) -> Admission<T> {
        let Settings {
            policy,
            storage_dir,
        } = settings();
        if !policy.stamp_destinations {
            return Admission::Ready(item, None);
        }
        let target = destination.target_value(policy.destination_value);
        if destination.destination_stamp_meets(target) {
            return Admission::Ready(item, destination.announce_stamp_ext(policy.lr_cost));
        }
        if path_response {
            if self.parked_path_responses.len() >= STAMPER_PR_QUEUE_LENGTH {
                tracing::debug!(dest = %destination, "stamp queue full, dropping announce");
                return Admission::Dropped(item);
            }
            self.parked_path_responses.push_back(item);
        } else {
            self.parked_announce = Some(item);
        }
        if self.job.is_some() {
            if path_response {
                promote(self.owner);
            }
            return Admission::Queued;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let job = Job {
            owner: self.owner,
            destination_hash: destination.hash,
            material: destination
                .stamp_material(&identity.get_public_key())
                .to_vec(),
            target,
            storage_dir,
            cancel: cancel.clone(),
            reply: self.tx.clone(),
        };
        let priority = if self.parked_path_responses.is_empty() {
            Priority::Announce
        } else {
            Priority::PathResponse
        };
        if submit(job, priority) {
            self.job = Some(cancel);
            return Admission::Queued;
        }
        tracing::debug!(dest = %destination, "stamp queue full, dropping announce");
        let dropped = if path_response {
            self.parked_path_responses.pop_back()
        } else {
            self.parked_announce.take()
        };
        Admission::Dropped(dropped.expect("item was parked above"))
    }

    /// Wait for the in-flight job. Cancellation safe.
    pub async fn recv(&mut self) -> StampOutcome {
        match self.rx.recv().await {
            Some(outcome) => outcome,
            // This value holds a sender, so the channel cannot close.
            None => std::future::pending().await,
        }
    }

    pub fn try_recv(&mut self) -> Option<StampOutcome> {
        self.rx.try_recv().ok()
    }

    /// Install a finished stamp and release the parked announces, path
    /// responses first. A failed job cancels them, as `_announce` does.
    pub fn complete(
        &mut self,
        destination: &mut Destination,
        identity: &Identity,
        outcome: StampOutcome,
    ) -> Vec<(T, Option<AnnounceStampExt>)> {
        self.job = None;
        let Some((stamp, value)) = outcome.stamp else {
            let cancelled =
                self.parked_path_responses.len() + usize::from(self.parked_announce.is_some());
            self.parked_path_responses.clear();
            self.parked_announce = None;
            if cancelled > 0 {
                tracing::warn!(dest = %destination,
                    "could not generate destination stamp, announce emission cancelled");
            }
            return Vec::new();
        };
        destination.set_destination_stamp(stamp, value);
        let mut parked: Vec<(T, bool)> = self
            .parked_path_responses
            .drain(..)
            .map(|item| (item, true))
            .collect();
        parked.extend(self.parked_announce.take().map(|item| (item, false)));
        let mut ready = Vec::new();
        for (item, path_response) in parked {
            match self.admit(destination, identity, path_response, item) {
                Admission::Ready(item, ext) => ready.push((item, ext)),
                Admission::Queued | Admission::Dropped(_) => {}
            }
        }
        ready
    }
}

impl<T> Drop for DestinationStamps<T> {
    fn drop(&mut self) {
        if let Some(cancel) = self.job.take() {
            cancel.store(true, Ordering::Relaxed);
        }
    }
}

/// Build an announce packet for an owner without an event loop, waiting for
/// the destination stamp when the policy stamps destinations. `Ok(None)`
/// means emission was cancelled or dropped, as Python's `_announce` returns.
pub async fn announce_packet(
    destination: &mut Destination,
    identity: &Identity,
    app_data: Option<&[u8]>,
    ratchet: Option<&[u8; 32]>,
    path_response: bool,
    tag: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, DestinationError> {
    let mut stamps = DestinationStamps::new();
    let ext = match stamps.admit(destination, identity, path_response, ()) {
        Admission::Ready((), ext) => ext,
        Admission::Dropped(()) => return Ok(None),
        Admission::Queued => {
            let outcome = stamps.recv().await;
            match stamps.complete(destination, identity, outcome).pop() {
                Some(((), ext)) => ext,
                None => return Ok(None),
            }
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let time = rns_identity::destination::AnnounceTime::new(now as u64, now)?;
    destination
        .announce_packet_with_ext_at(
            identity,
            app_data,
            ratchet,
            path_response,
            tag,
            time,
            ext.as_ref(),
        )
        .map(Some)
}
