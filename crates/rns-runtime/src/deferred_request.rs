//! Bounded authority for completing a Destination request outside the Link loop.
use crate::link_manager::RequestOutcome;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, oneshot};

pub(crate) const LIFETIME: Duration = Duration::from_secs(120);
const JOBS: usize = 4;
const BYTES: usize = 256 * 1024 * 1024;
const SCRATCH: usize = 16 * 1024 * 1024;
pub(crate) const MAX_RESPONSE: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredResponseOutcome {
    Sent,
    Closed,
    Expired,
    Unavailable,
    Dropped,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeferredResponseError {
    #[error("request is no longer live")]
    Closed,
    #[error("response allocation exceeds the admitted byte limit")]
    TooLarge,
}
#[derive(Default, Debug)]
struct Counts {
    jobs: usize,
    bytes: usize,
}
#[derive(Debug)]
pub(crate) struct RequestLease {
    counts: Arc<Mutex<Counts>>,
    bytes: usize,
}
impl Drop for RequestLease {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        counts.jobs -= 1;
        counts.bytes -= self.bytes;
    }
}
#[derive(Debug)]
struct State {
    alive: AtomicBool,
    deadline: Instant,
    limit: usize,
    notify: Arc<Notify>,
    lease: Arc<RequestLease>,
}
/// One-shot completion authority issued only after the manager reserves a job
/// and its bytes. Keep this value inside the actual worker until its I/O ends;
/// dropping a caller's async task must not detach an uncharged blocking job.
///
/// The effective response limit can be lower than the registered ceiling. The
/// reservation includes sixteen times request capacity, eight response buffers and 16 MiB of
/// construction scratch. This is a conservative bound for the current Resource
/// construction path, not a claim that unrelated application allocations are
/// globally capped. Responses must fit by allocation capacity, not just length.
#[derive(Debug)]
pub struct DeferredRequestResponder {
    state: Arc<State>,
    sender: Option<oneshot::Sender<Resolution>>,
}
#[derive(Debug)]
pub(crate) struct Resolution {
    pub outcome: RequestOutcome,
    pub reply: oneshot::Sender<DeferredResponseOutcome>,
}
pub(crate) struct PendingResponse {
    state: Arc<State>,
    receiver: oneshot::Receiver<Resolution>,
}
impl DeferredRequestResponder {
    pub fn response_byte_limit(&self) -> usize {
        self.state.limit
    }
    pub fn is_cancelled(&self) -> bool {
        !self.state.alive.load(Ordering::Acquire) || Instant::now() >= self.state.deadline
    }
    /// Queues one result. `Sent` acknowledges transport queue acceptance or
    /// Resource initiation, not remote delivery. No response is emitted for a
    /// closed/replaced Link, a dropped manager or an expired request.
    pub fn respond(
        mut self,
        outcome: RequestOutcome,
    ) -> Result<oneshot::Receiver<DeferredResponseOutcome>, DeferredResponseError> {
        if self.is_cancelled() {
            return Err(DeferredResponseError::Closed);
        }
        let capacity = match &outcome {
            RequestOutcome::Reply(data) => Some(data.capacity()),
            RequestOutcome::ReplyWithResource {
                ack,
                data,
                metadata,
                ..
            } => ack
                .capacity()
                .checked_add(data.capacity())
                .and_then(|n| n.checked_add(metadata.as_ref().map_or(0, Vec::capacity))),
            RequestOutcome::Drop => Some(0),
        };
        if capacity.is_none_or(|n| n > self.state.limit) {
            return Err(DeferredResponseError::TooLarge);
        }
        let (reply, result) = oneshot::channel();
        self.sender
            .take()
            .ok_or(DeferredResponseError::Closed)?
            .send(Resolution { outcome, reply })
            .map_err(|_| DeferredResponseError::Closed)?;
        self.state.notify.notify_one();
        Ok(result)
    }
}
impl Drop for DeferredRequestResponder {
    fn drop(&mut self) {
        // Close the channel before waking the polling manager. Otherwise the
        // wake can race ahead of field destruction and leave an empty receiver
        // asleep until its deadline.
        self.sender.take();
        self.state.notify.notify_one();
    }
}
impl PendingResponse {
    pub fn try_recv(&mut self) -> Result<Resolution, oneshot::error::TryRecvError> {
        self.receiver.try_recv()
    }
    pub fn deadline(&self) -> Instant {
        self.state.deadline
    }
    pub fn lease(&self) -> Arc<RequestLease> {
        self.state.lease.clone()
    }
    pub fn close(&mut self, outcome: DeferredResponseOutcome) {
        self.state.alive.store(false, Ordering::Release);
        self.receiver.close();
        if let Ok(resolution) = self.receiver.try_recv() {
            let _ = resolution.reply.send(outcome);
        }
    }
}
impl Drop for PendingResponse {
    fn drop(&mut self) {
        self.close(DeferredResponseOutcome::Closed);
    }
}
pub(crate) fn reserve(
    input_capacity: usize,
    requested_limit: usize,
    notify: Arc<Notify>,
) -> Option<(DeferredRequestResponder, PendingResponse)> {
    static GLOBAL: OnceLock<Arc<Mutex<Counts>>> = OnceLock::new();
    reserve_with(
        GLOBAL
            .get_or_init(|| Arc::new(Mutex::new(Counts::default())))
            .clone(),
        input_capacity,
        requested_limit,
        notify,
    )
}
fn reserve_with(
    counts: Arc<Mutex<Counts>>,
    input_capacity: usize,
    requested_limit: usize,
    notify: Arc<Notify>,
) -> Option<(DeferredRequestResponder, PendingResponse)> {
    reserve_with_deadline(
        counts,
        input_capacity,
        requested_limit,
        notify,
        Instant::now() + LIFETIME,
    )
}
fn reserve_with_deadline(
    counts: Arc<Mutex<Counts>>,
    input_capacity: usize,
    requested_limit: usize,
    notify: Arc<Notify>,
    deadline: Instant,
) -> Option<(DeferredRequestResponder, PendingResponse)> {
    let overhead = input_capacity.checked_mul(16)?.checked_add(SCRATCH)?;
    let limit = requested_limit.min(BYTES.checked_sub(overhead)? / 8);
    if limit == 0 {
        return None;
    }
    let bytes = limit.checked_mul(8)?.checked_add(overhead)?;
    {
        let mut counts = counts.lock().unwrap_or_else(|e| e.into_inner());
        if counts.jobs >= JOBS || bytes > BYTES.saturating_sub(counts.bytes) {
            return None;
        }
        counts.jobs += 1;
        counts.bytes += bytes;
    }
    let state = Arc::new(State {
        alive: AtomicBool::new(true),
        deadline,
        limit,
        notify,
        lease: Arc::new(RequestLease { counts, bytes }),
    });
    let (sender, receiver) = oneshot::channel();
    Some((
        DeferredRequestResponder {
            state: state.clone(),
            sender: Some(sender),
        },
        PendingResponse { state, receiver },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_request_keeps_worker_credit_and_rejects_late_response() {
        let counts = Arc::new(Mutex::new(Counts::default()));
        let (worker, mut pending) =
            reserve_with(counts.clone(), 10, 100, Arc::new(Notify::new())).unwrap();
        pending.close(DeferredResponseOutcome::Closed);
        drop(pending);
        assert_eq!(counts.lock().unwrap().jobs, 1);
        assert!(worker.is_cancelled());
        assert_eq!(
            worker.respond(RequestOutcome::Reply(vec![1])).unwrap_err(),
            DeferredResponseError::Closed
        );
        assert_eq!(counts.lock().unwrap().jobs, 0);
    }
    #[test]
    fn allocation_capacity_and_global_admission_are_bounded() {
        let counts = Arc::new(Mutex::new(Counts::default()));
        let mut jobs = Vec::new();
        for _ in 0..4 {
            jobs.push(reserve_with(counts.clone(), 10, 100, Arc::new(Notify::new())).unwrap());
        }
        assert!(reserve_with(counts.clone(), 10, 100, Arc::new(Notify::new())).is_none());
        let (worker, pending) = jobs.pop().unwrap();
        let bytes = Vec::with_capacity(101);
        assert_eq!(
            worker.respond(RequestOutcome::Reply(bytes)).unwrap_err(),
            DeferredResponseError::TooLarge
        );
        drop(pending);
        assert!(reserve_with(counts, 10, 100, Arc::new(Notify::new())).is_some());
    }
    #[test]
    fn expired_and_oversized_requests_never_acquire_send_authority() {
        let counts = Arc::new(Mutex::new(Counts::default()));
        assert!(reserve_with(counts.clone(), usize::MAX, 100, Arc::new(Notify::new())).is_none());
        assert!(reserve_with(counts.clone(), BYTES / 16, 100, Arc::new(Notify::new())).is_none());
        assert_eq!(counts.lock().unwrap().jobs, 0);
        let (worker, pending) = reserve_with_deadline(
            counts.clone(),
            1,
            100,
            Arc::new(Notify::new()),
            Instant::now() - Duration::from_secs(1),
        )
        .unwrap();
        assert!(worker.is_cancelled());
        assert_eq!(
            worker.respond(RequestOutcome::Reply(vec![1])).unwrap_err(),
            DeferredResponseError::Closed
        );
        drop(pending);
        assert_eq!(counts.lock().unwrap().bytes, 0);
    }

    #[test]
    fn queued_result_and_resource_owner_retain_credit() {
        let counts = Arc::new(Mutex::new(Counts::default()));
        let (worker, mut pending) =
            reserve_with(counts.clone(), 10, 100, Arc::new(Notify::new())).unwrap();
        let mut ack = worker.respond(RequestOutcome::Reply(vec![1])).unwrap();
        assert_eq!(counts.lock().unwrap().jobs, 1);
        let resolution = pending.try_recv().unwrap();
        let resource_lease = pending.lease();
        resolution
            .reply
            .send(DeferredResponseOutcome::Sent)
            .unwrap();
        drop(pending);
        assert_eq!(ack.try_recv().unwrap(), DeferredResponseOutcome::Sent);
        assert_eq!(counts.lock().unwrap().jobs, 1);
        drop(resource_lease);
        assert_eq!(counts.lock().unwrap().jobs, 0);
    }
}
