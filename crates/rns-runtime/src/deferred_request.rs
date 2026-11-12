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
/// Largest refusal reply; it always fits one RESPONSE packet on a default Link.
pub const MAX_REFUSAL_REPLY: usize = 256;
const DEFAULT_REQUEST_COPIES: usize = 16;
const DEFAULT_RESPONSE_COPIES: usize = 8;

/// How a deferred handler's job is charged against the process-wide budget
/// (four jobs, 256 MiB), and what a refused requester is told.
///
/// A job is charged `request_copies` times the request capacity, plus 16 MiB of
/// Resource construction scratch, plus `response_copies` times the effective
/// response limit. The defaults (16 and 8, no refusal replies) are the
/// conservative charge for a handler whose reply can be a large in-memory
/// Resource. A handler that holds fewer copies, or whose large replies are
/// file-backed ([`RequestOutcome::ReplyFile`] streams one segment at a time
/// within the scratch allowance), can declare lower counts. Declarations change
/// what one job costs, never the global job count or byte cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredAdmission {
    response_byte_limit: usize,
    request_copies: usize,
    response_copies: usize,
    busy_reply: Option<Vec<u8>>,
    too_large_reply: Option<Vec<u8>>,
}

impl DeferredAdmission {
    /// Today's default accounting with a ceiling for an in-memory reply.
    pub fn new(response_byte_limit: usize) -> Self {
        Self {
            response_byte_limit,
            request_copies: DEFAULT_REQUEST_COPIES,
            response_copies: DEFAULT_RESPONSE_COPIES,
            busy_reply: None,
            too_large_reply: None,
        }
    }
    /// Copies of the request held while the job runs. The manager itself holds
    /// three (reassembled payload, decoded value and byte view) at admission.
    pub fn request_copies(mut self, copies: usize) -> Self {
        self.request_copies = copies;
        self
    }
    /// Response buffers charged per byte of the effective response limit.
    pub fn response_copies(mut self, copies: usize) -> Self {
        self.response_copies = copies;
        self
    }
    /// Bytes sent as the response when the job count or the remaining budget
    /// refuses a job. Without it the request is dropped with no response.
    pub fn busy_reply(mut self, reply: Vec<u8>) -> Self {
        self.busy_reply = Some(reply);
        self
    }
    /// Bytes sent as the response when the request can never fit the budget.
    /// Without it the request is dropped with no response.
    pub fn too_large_reply(mut self, reply: Vec<u8>) -> Self {
        self.too_large_reply = Some(reply);
        self
    }
    pub fn response_byte_limit(&self) -> usize {
        self.response_byte_limit
    }
    pub(crate) fn is_valid(&self) -> bool {
        self.response_byte_limit > 0
            && self.response_byte_limit <= MAX_RESPONSE
            && self.request_copies > 0
            && self.response_copies > 0
            && [&self.busy_reply, &self.too_large_reply]
                .iter()
                .all(|reply| reply.as_ref().is_none_or(|r| r.len() <= MAX_REFUSAL_REPLY))
    }
    pub(crate) fn refusal_reply(&self, refusal: AdmissionRefusal) -> Option<&[u8]> {
        match refusal {
            AdmissionRefusal::Busy => self.busy_reply.as_deref(),
            AdmissionRefusal::TooLarge => self.too_large_reply.as_deref(),
        }
    }
}

/// Why admission refused a deferred job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionRefusal {
    /// All jobs are taken or the remaining budget is too small.
    Busy,
    /// The job exceeds the budget even when nothing else runs.
    TooLarge,
}

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
#[derive(Default, Debug, PartialEq, Eq)]
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
/// reservation follows the handler's [`DeferredAdmission`]: by default sixteen
/// times request capacity, eight response buffers and 16 MiB of construction
/// scratch. This bounds the Resource construction path, not unrelated
/// application allocations. Responses must fit by allocation capacity, not just
/// length.
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
    /// Queues one result. `Sent` acknowledges local response staging in the
    /// transport mailbox or manager retry queue, or Resource initiation. It
    /// does not acknowledge endpoint dispatch or remote delivery. No response
    /// is emitted for a closed/replaced Link, dropped manager or expired request.
    pub fn respond(
        mut self,
        outcome: RequestOutcome,
    ) -> Result<oneshot::Receiver<DeferredResponseOutcome>, DeferredResponseError> {
        if self.is_cancelled() {
            return Err(DeferredResponseError::Closed);
        }
        let capacity = match &outcome {
            RequestOutcome::ReplyBytes(data) | RequestOutcome::ReplyValue(data) => {
                Some(data.capacity())
            }
            // The file source is streamed; only the metadata is held here.
            RequestOutcome::ReplyFile { metadata, .. } => {
                Some(metadata.as_ref().map_or(0, Vec::capacity))
            }
            RequestOutcome::ReplyWithResource { ack, metadata, .. } => ack
                .capacity()
                .checked_add(metadata.as_ref().map_or(0, Vec::capacity)),
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
    admission: &DeferredAdmission,
    notify: Arc<Notify>,
) -> Result<(DeferredRequestResponder, PendingResponse), AdmissionRefusal> {
    static GLOBAL: OnceLock<Arc<Mutex<Counts>>> = OnceLock::new();
    reserve_with(
        GLOBAL
            .get_or_init(|| Arc::new(Mutex::new(Counts::default())))
            .clone(),
        input_capacity,
        admission,
        notify,
    )
}
fn reserve_with(
    counts: Arc<Mutex<Counts>>,
    input_capacity: usize,
    admission: &DeferredAdmission,
    notify: Arc<Notify>,
) -> Result<(DeferredRequestResponder, PendingResponse), AdmissionRefusal> {
    reserve_with_deadline(
        counts,
        input_capacity,
        admission,
        notify,
        Instant::now() + LIFETIME,
    )
}
fn reserve_with_deadline(
    counts: Arc<Mutex<Counts>>,
    input_capacity: usize,
    admission: &DeferredAdmission,
    notify: Arc<Notify>,
    deadline: Instant,
) -> Result<(DeferredRequestResponder, PendingResponse), AdmissionRefusal> {
    let too_large = AdmissionRefusal::TooLarge;
    let response_copies = admission.response_copies.max(1);
    let overhead = input_capacity
        .checked_mul(admission.request_copies.max(1))
        .and_then(|n| n.checked_add(SCRATCH))
        .ok_or(too_large)?;
    let limit = admission
        .response_byte_limit
        .min(BYTES.checked_sub(overhead).ok_or(too_large)? / response_copies);
    if limit == 0 {
        return Err(too_large);
    }
    let bytes = limit
        .checked_mul(response_copies)
        .and_then(|n| n.checked_add(overhead))
        .ok_or(too_large)?;
    {
        let mut counts = counts.lock().unwrap_or_else(|e| e.into_inner());
        if counts.jobs >= JOBS || bytes > BYTES.saturating_sub(counts.bytes) {
            return Err(AdmissionRefusal::Busy);
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
    Ok((
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
        let (worker, mut pending) = reserve_with(
            counts.clone(),
            10,
            &DeferredAdmission::new(100),
            Arc::new(Notify::new()),
        )
        .unwrap();
        pending.close(DeferredResponseOutcome::Closed);
        drop(pending);
        assert_eq!(counts.lock().unwrap().jobs, 1);
        assert!(worker.is_cancelled());
        assert_eq!(
            worker
                .respond(RequestOutcome::ReplyBytes(vec![1]))
                .unwrap_err(),
            DeferredResponseError::Closed
        );
        assert_eq!(counts.lock().unwrap().jobs, 0);
    }
    #[test]
    fn allocation_capacity_and_global_admission_are_bounded() {
        let counts = Arc::new(Mutex::new(Counts::default()));
        let mut jobs = Vec::new();
        for _ in 0..4 {
            jobs.push(
                reserve_with(
                    counts.clone(),
                    10,
                    &DeferredAdmission::new(100),
                    Arc::new(Notify::new()),
                )
                .unwrap(),
            );
        }
        assert!(
            reserve_with(
                counts.clone(),
                10,
                &DeferredAdmission::new(100),
                Arc::new(Notify::new())
            )
            .is_err()
        );
        let (worker, pending) = jobs.pop().unwrap();
        let bytes = Vec::with_capacity(101);
        assert_eq!(
            worker
                .respond(RequestOutcome::ReplyBytes(bytes))
                .unwrap_err(),
            DeferredResponseError::TooLarge
        );
        drop(pending);
        assert!(
            reserve_with(
                counts,
                10,
                &DeferredAdmission::new(100),
                Arc::new(Notify::new())
            )
            .is_ok()
        );
    }
    #[test]
    fn expired_and_oversized_requests_never_acquire_send_authority() {
        let counts = Arc::new(Mutex::new(Counts::default()));
        assert!(
            reserve_with(
                counts.clone(),
                usize::MAX,
                &DeferredAdmission::new(100),
                Arc::new(Notify::new())
            )
            .is_err()
        );
        assert!(
            reserve_with(
                counts.clone(),
                BYTES / 16,
                &DeferredAdmission::new(100),
                Arc::new(Notify::new())
            )
            .is_err()
        );
        assert_eq!(counts.lock().unwrap().jobs, 0);
        let (worker, pending) = reserve_with_deadline(
            counts.clone(),
            1,
            &DeferredAdmission::new(100),
            Arc::new(Notify::new()),
            Instant::now() - Duration::from_secs(1),
        )
        .unwrap();
        assert!(worker.is_cancelled());
        assert_eq!(
            worker
                .respond(RequestOutcome::ReplyBytes(vec![1]))
                .unwrap_err(),
            DeferredResponseError::Closed
        );
        drop(pending);
        assert_eq!(counts.lock().unwrap().bytes, 0);
    }

    #[test]
    fn queued_result_and_resource_owner_retain_credit() {
        let counts = Arc::new(Mutex::new(Counts::default()));
        let (worker, mut pending) = reserve_with(
            counts.clone(),
            10,
            &DeferredAdmission::new(100),
            Arc::new(Notify::new()),
        )
        .unwrap();
        let mut ack = worker.respond(RequestOutcome::ReplyBytes(vec![1])).unwrap();
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

    #[test]
    fn declared_accounting_sets_the_charge_and_default_keeps_todays() {
        let counts = Arc::new(Mutex::new(Counts::default()));
        let input = 1024 * 1024;
        let default = reserve_with(
            counts.clone(),
            input,
            &DeferredAdmission::new(1000),
            Arc::new(Notify::new()),
        )
        .unwrap();
        assert_eq!(
            counts.lock().unwrap().bytes,
            16 * input + SCRATCH + 8 * 1000
        );
        drop(default);
        let declared = DeferredAdmission::new(1000)
            .request_copies(3)
            .response_copies(2);
        let job = reserve_with(counts.clone(), input, &declared, Arc::new(Notify::new())).unwrap();
        assert_eq!(counts.lock().unwrap().bytes, 3 * input + SCRATCH + 2 * 1000);
        drop(job);
        assert_eq!(counts.lock().unwrap().bytes, 0);
        // A 40 MiB request is refused by the default charge and fits as declared.
        let push = 40 * 1024 * 1024;
        assert!(matches!(
            reserve_with(
                counts.clone(),
                push,
                &DeferredAdmission::new(1000),
                Arc::new(Notify::new())
            ),
            Err(AdmissionRefusal::TooLarge)
        ));
        assert!(reserve_with(counts, push, &declared, Arc::new(Notify::new())).is_ok());
    }

    #[test]
    fn declared_accounting_never_exceeds_the_global_bound() {
        let counts = Arc::new(Mutex::new(Counts::default()));
        let light = DeferredAdmission::new(1)
            .request_copies(1)
            .response_copies(1);
        let mut jobs = Vec::new();
        for _ in 0..JOBS {
            jobs.push(reserve_with(counts.clone(), 0, &light, Arc::new(Notify::new())).unwrap());
        }
        assert!(matches!(
            reserve_with(counts.clone(), 0, &light, Arc::new(Notify::new())),
            Err(AdmissionRefusal::Busy)
        ));
        jobs.clear();
        // Two large jobs that each fit alone cannot run together: 130 MiB of
        // request plus scratch is 146 MiB, so the second exceeds 256 MiB.
        let big = 130 * 1024 * 1024;
        let first = reserve_with(counts.clone(), big, &light, Arc::new(Notify::new())).unwrap();
        assert!(matches!(
            reserve_with(counts.clone(), big, &light, Arc::new(Notify::new())),
            Err(AdmissionRefusal::Busy)
        ));
        assert!(counts.lock().unwrap().bytes <= BYTES);
        drop(first);
        assert!(matches!(
            reserve_with(counts.clone(), BYTES, &light, Arc::new(Notify::new())),
            Err(AdmissionRefusal::TooLarge)
        ));
        assert_eq!(*counts.lock().unwrap(), Counts::default());
        // Zero counts are rejected at registration and cannot reach admission as zero.
        assert!(!DeferredAdmission::new(1).request_copies(0).is_valid());
        assert!(!DeferredAdmission::new(1).response_copies(0).is_valid());
    }

    #[test]
    fn refusal_replies_are_bounded_and_matched_to_the_refusal() {
        let admission = DeferredAdmission::new(100)
            .busy_reply(b"busy".to_vec())
            .too_large_reply(b"large".to_vec());
        assert!(admission.is_valid());
        assert_eq!(
            admission.refusal_reply(AdmissionRefusal::Busy),
            Some(&b"busy"[..])
        );
        assert_eq!(
            admission.refusal_reply(AdmissionRefusal::TooLarge),
            Some(&b"large"[..])
        );
        assert_eq!(
            DeferredAdmission::new(100).refusal_reply(AdmissionRefusal::Busy),
            None
        );
        assert!(
            !DeferredAdmission::new(100)
                .busy_reply(vec![0; MAX_REFUSAL_REPLY + 1])
                .is_valid()
        );
    }
}
