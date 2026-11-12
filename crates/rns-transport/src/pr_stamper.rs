//! Path-request stamp generation off the actor loop (Transport.py,
//! :4018-4051 at 1.6.0): a bounded, key-coalescing queue served by one worker
//! thread, and the actor-side cache of generated stamps.

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rns_identity::stamps::{NETWORK_STAMP_SIZE, StampControl, generate_stamp};
use tokio::sync::mpsc;

use crate::messages::InterfaceId;
use crate::stamps::STAMPER_PR_QUEUE_LENGTH;

/// Python `pr_stamp_cache_max`.
pub const PR_STAMP_CACHE_MAX: usize = 256;

pub type PathRequestStamp = [u8; NETWORK_STAMP_SIZE];

/// Where a stamped path request goes once its stamp is ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRequestTarget {
    /// One interface (`request_path(on_interface=...)`).
    Interface(InterfaceId),
    /// Every outbound interface except the given one.
    AllExcept(Option<InterfaceId>),
}

/// One queued generation job.
#[derive(Debug, Clone, PartialEq)]
pub struct PathRequestStampJob {
    pub destination_hash: [u8; 16],
    /// At most 16 bytes, as sent.
    pub tag: Vec<u8>,
    pub target: PathRequestTarget,
    pub recursive: bool,
    /// Python `PR_VALUE`.
    pub value: f64,
    /// Python `PR_STAMP_TIMEOUT`, in seconds.
    pub timeout: f64,
}

impl PathRequestStampJob {
    /// Python keys on the destination, plus the interface when one is given.
    fn key(&self) -> ([u8; 16], Option<InterfaceId>) {
        match self.target {
            PathRequestTarget::Interface(id) => (self.destination_hash, Some(id)),
            PathRequestTarget::AllExcept(_) => (self.destination_hash, None),
        }
    }

    /// Python `pr_stamp_material`: destination hash then tag.
    pub fn material(&self) -> Vec<u8> {
        pr_stamp_material(&self.destination_hash, &self.tag)
    }
}

/// A finished job; `stamp` is `None` when generation was cancelled or timed out.
#[derive(Debug, Clone)]
pub struct PathRequestStampResult {
    pub job: PathRequestStampJob,
    pub stamp: Option<PathRequestStamp>,
}

/// Python `pr_stamp_material`: destination hash then tag.
pub fn pr_stamp_material(destination_hash: &[u8; 16], tag: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(16 + tag.len());
    material.extend_from_slice(destination_hash);
    material.extend_from_slice(tag);
    material
}

/// Python `pr_stamp_cache`, insertion ordered.
#[derive(Default)]
struct StampCache {
    stamps: HashMap<Vec<u8>, PathRequestStamp>,
    order: VecDeque<Vec<u8>>,
}

impl StampCache {
    fn insert(&mut self, material: Vec<u8>, stamp: PathRequestStamp) {
        if self.stamps.insert(material.clone(), stamp).is_none() {
            self.order.push_back(material);
        }
        while self.stamps.len() > PR_STAMP_CACHE_MAX {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.stamps.remove(&oldest);
        }
    }
}

#[derive(Default)]
struct Queue {
    jobs: VecDeque<PathRequestStampJob>,
    shutdown: bool,
}

struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
    /// Cancels the job in progress on shutdown.
    cancel: Arc<AtomicBool>,
    /// Read by the actor before enqueueing and by the worker before generating.
    cache: Mutex<StampCache>,
}

/// The actor's handle: queue, worker thread and generated-stamp cache.
pub struct PathRequestStamper {
    shared: Arc<Shared>,
    results_tx: mpsc::UnboundedSender<PathRequestStampResult>,
    results_rx: mpsc::UnboundedReceiver<PathRequestStampResult>,
    worker_started: bool,
}

impl Default for PathRequestStamper {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PathRequestStamper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathRequestStamper")
            .field("worker_started", &self.worker_started)
            .field("cached", &self.cache_len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

impl PathRequestStamper {
    pub fn new() -> Self {
        let (results_tx, results_rx) = mpsc::unbounded_channel();
        Self {
            shared: Arc::new(Shared {
                queue: Mutex::new(Queue::default()),
                ready: Condvar::new(),
                cancel: Arc::new(AtomicBool::new(false)),
                cache: Mutex::new(StampCache::default()),
            }),
            results_tx,
            results_rx,
            worker_started: false,
        }
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, StampCache> {
        self.shared.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Python `pr_stamp_cache.get(material)`.
    pub fn cached(&self, destination_hash: &[u8; 16], tag: &[u8]) -> Option<PathRequestStamp> {
        self.cache()
            .stamps
            .get(&pr_stamp_material(destination_hash, tag))
            .copied()
    }

    pub fn cache_len(&self) -> usize {
        self.cache().stamps.len()
    }

    /// Python `WorkerQueues.put`: drop queued jobs with the same key, then
    /// refuse when the queue is still full.
    pub fn enqueue(&mut self, job: PathRequestStampJob) -> Result<(), QueueFull> {
        {
            let mut queue = self.shared.queue.lock().unwrap_or_else(|e| e.into_inner());
            let key = job.key();
            queue.jobs.retain(|queued| queued.key() != key);
            if queue.jobs.len() >= STAMPER_PR_QUEUE_LENGTH {
                return Err(QueueFull);
            }
            queue.jobs.push_back(job);
        }
        self.shared.ready.notify_one();
        self.ensure_worker();
        Ok(())
    }

    /// Receive the next finished job.
    pub async fn next_result(&mut self) -> Option<PathRequestStampResult> {
        self.results_rx.recv().await
    }

    fn ensure_worker(&mut self) {
        if self.worker_started {
            return;
        }
        let shared = Arc::clone(&self.shared);
        let results_tx = self.results_tx.clone();
        let spawned = std::thread::Builder::new()
            .name("rns-pr-stamper".into())
            .spawn(move || worker(shared, results_tx));
        match spawned {
            Ok(_) => self.worker_started = true,
            Err(e) => tracing::error!(error = %e, "could not start the path request stamper"),
        }
    }
}

impl Drop for PathRequestStamper {
    fn drop(&mut self) {
        self.shared.cancel.store(true, Ordering::Relaxed);
        self.shared
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .shutdown = true;
        self.shared.ready.notify_all();
    }
}

fn worker(shared: Arc<Shared>, results_tx: mpsc::UnboundedSender<PathRequestStampResult>) {
    let threads = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
    loop {
        let job = {
            let mut queue = shared.queue.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if queue.shutdown {
                    return;
                }
                if let Some(job) = queue.jobs.pop_front() {
                    break job;
                }
                queue = shared.ready.wait(queue).unwrap_or_else(|e| e.into_inner());
            }
        };
        let material = job.material();
        let cached = shared
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stamps
            .get(&material)
            .copied();
        if let Some(stamp) = cached {
            if results_tx
                .send(PathRequestStampResult {
                    job,
                    stamp: Some(stamp),
                })
                .is_err()
            {
                return;
            }
            continue;
        }
        let ctl = StampControl {
            cancel: Arc::clone(&shared.cancel),
            deadline: Duration::try_from_secs_f64(job.timeout)
                .ok()
                .and_then(|timeout| Instant::now().checked_add(timeout)),
            threads,
        };
        let stamp: Option<PathRequestStamp> =
            match generate_stamp(&material, job.value, 0, NETWORK_STAMP_SIZE, &ctl) {
                Ok(Some((stamp, _))) => stamp.try_into().ok(),
                Ok(None) => None,
                Err(e) => {
                    tracing::error!(error = %e, "path request stamp generation failed");
                    None
                }
            };
        if let Some(stamp) = stamp {
            shared
                .cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(material, stamp);
        }
        if results_tx
            .send(PathRequestStampResult { job, stamp })
            .is_err()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(dest: u8, target: PathRequestTarget, value: f64) -> PathRequestStampJob {
        PathRequestStampJob {
            destination_hash: [dest; 16],
            tag: vec![0x11; 16],
            target,
            recursive: false,
            value,
            timeout: 15.0,
        }
    }

    #[tokio::test]
    async fn generated_stamp_meets_the_requested_value() {
        let mut stamper = PathRequestStamper::new();
        stamper
            .enqueue(job(1, PathRequestTarget::AllExcept(None), 6.0))
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(20), stamper.next_result())
            .await
            .unwrap()
            .unwrap();
        let stamp = result.stamp.expect("stamp generated");
        assert!(rns_identity::stamps::stamp_valid(&stamp, 6.0, &result.job.material()).unwrap());
    }

    #[tokio::test]
    async fn generation_past_the_timeout_returns_no_stamp() {
        let mut stamper = PathRequestStamper::new();
        let mut slow = job(1, PathRequestTarget::Interface(3), 60.0);
        slow.timeout = 0.05;
        stamper.enqueue(slow).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(20), stamper.next_result())
            .await
            .unwrap()
            .unwrap();
        assert!(result.stamp.is_none());
    }

    #[test]
    fn same_key_jobs_coalesce_and_the_queue_is_bounded() {
        let mut stamper = PathRequestStamper::new();
        // Keep the worker idle so the queue contents are observable.
        stamper.worker_started = true;
        stamper
            .enqueue(job(1, PathRequestTarget::Interface(1), 8.0))
            .unwrap();
        stamper
            .enqueue(job(1, PathRequestTarget::Interface(1), 9.0))
            .unwrap();
        stamper
            .enqueue(job(1, PathRequestTarget::AllExcept(Some(1)), 8.0))
            .unwrap();
        {
            let queue = stamper.shared.queue.lock().unwrap();
            assert_eq!(queue.jobs.len(), 2);
            assert_eq!(queue.jobs[0].value, 9.0);
        }
        for dest in 2..=(STAMPER_PR_QUEUE_LENGTH as u8 - 1) {
            stamper
                .enqueue(job(dest, PathRequestTarget::AllExcept(None), 8.0))
                .unwrap();
        }
        assert_eq!(
            stamper.enqueue(job(0xEE, PathRequestTarget::AllExcept(None), 8.0)),
            Err(QueueFull)
        );
    }

    #[test]
    fn cache_holds_256_stamps_first_in_first_out() {
        let stamper = PathRequestStamper::new();
        for i in 0..=PR_STAMP_CACHE_MAX as u16 {
            let mut dest = [0u8; 16];
            dest[..2].copy_from_slice(&i.to_be_bytes());
            stamper
                .cache()
                .insert(pr_stamp_material(&dest, &[0; 16]), [1; 14]);
        }
        assert_eq!(stamper.cache_len(), PR_STAMP_CACHE_MAX);
        assert_eq!(stamper.cached(&[0; 16], &[0; 16]), None);
        let mut last = [0u8; 16];
        last[..2].copy_from_slice(&(PR_STAMP_CACHE_MAX as u16).to_be_bytes());
        assert_eq!(stamper.cached(&last, &[0; 16]), Some([1; 14]));
    }

    #[tokio::test]
    async fn worker_reuses_a_cached_stamp_for_the_same_material() {
        let mut stamper = PathRequestStamper::new();
        let first = job(1, PathRequestTarget::Interface(1), 6.0);
        stamper.enqueue(first).unwrap();
        let a = tokio::time::timeout(Duration::from_secs(20), stamper.next_result())
            .await
            .unwrap()
            .unwrap();
        stamper
            .enqueue(job(1, PathRequestTarget::Interface(2), 6.0))
            .unwrap();
        let b = tokio::time::timeout(Duration::from_secs(20), stamper.next_result())
            .await
            .unwrap()
            .unwrap();
        assert!(a.stamp.is_some());
        assert_eq!(a.stamp, b.stamp);
        assert_eq!(stamper.cached(&[1; 16], &[0x11; 16]), a.stamp);
    }
}
