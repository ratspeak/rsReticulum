//! Exact local admission receipts for established, locally owned Links.
//!
//! A receipt means the bound interface queue (or in-process peer queue)
//! accepted the packet, never that a modem transmitted it or a peer received
//! it. Legacy mailbox sends can instead return `Queued` while the packet
//! remains in the actor backlog, before interface admission. They return
//! `Sent` when the interface accepts it immediately.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};

use crate::messages::{
    LinkEndpointBindResult, LinkEndpointBinding, LinkEndpointLifecycleEvent,
    LinkEndpointSendResult, OutboundRequest,
};

pub(crate) const DISPATCH_QUEUE_CAPACITY: usize = 64;
/// Maximum future local-admission deadline (120 seconds), independent of
/// network RTT. Expiry is observed when the actor processes or drains work.
pub const LINK_ENDPOINT_ADMISSION_TIMEOUT_MAX: Duration = Duration::from_secs(120);

/// Failure to enqueue a bind/send operation. These errors do not return owned
/// packet bytes; retain a copy before calling if retry needs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkEndpointDispatchError {
    /// The actor generation's 64-slot dispatch-control queue is full.
    Full,
    /// The dispatch-control channel is closed.
    Closed,
    /// The deadline is more than 120 seconds in the future.
    InvalidDeadline,
}

impl std::fmt::Display for LinkEndpointDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Full => "Link dispatch queue full",
            Self::Closed => "Link dispatch owner closed",
            Self::InvalidDeadline => "Link admission deadline exceeds 120 seconds",
        })
    }
}

impl std::error::Error for LinkEndpointDispatchError {}

/// Terminal outcome of one exact packet operation. Local expiry is not
/// evidence of a failed route and must not trigger route invalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkEndpointDispatchOutcome {
    /// The bound interface or in-process peer queue accepted this packet.
    Sent {
        /// Protocol packet hash of the admitted inner packet, before IFAC framing.
        packet_hash: [u8; 32],
        /// Local monotonic time observed immediately after queue admission.
        dispatched_at: Instant,
    },
    /// The actor rejected the packet or its endpoint became terminal.
    Rejected(LinkEndpointSendResult),
    /// The immutable deadline was observed before local admission.
    Expired,
    /// Explicit or receiver cancellation was observed before local admission.
    Cancelled,
}

/// Cloneable cancellation request for one exact queued packet operation.
/// Calling [`Self::cancel`] does not unbind a Link or recall bytes already
/// admitted to its driver. Dropping this handle has no effect.
#[derive(Debug, Clone)]
pub struct LinkEndpointDispatchCancellation {
    requested: Arc<AtomicBool>,
}

impl LinkEndpointDispatchCancellation {
    /// Request cancellation. The actor's final pre-admission check is the
    /// cancellation/admission boundary: a request arriving after that check
    /// cannot retract accepted bytes. The receipt, not this method, confirms
    /// whether the result was Cancelled or already Sent.
    pub fn cancel(&self) {
        self.requested.store(true, Ordering::Release);
    }
}

pub(crate) enum LinkEndpointDispatchRequest {
    Bind {
        binding: LinkEndpointBinding,
        lifecycle_tx: mpsc::UnboundedSender<LinkEndpointLifecycleEvent>,
        publication: Arc<AtomicU8>,
        result_tx: oneshot::Sender<Result<LinkEndpointDispatchToken, LinkEndpointBindResult>>,
    },
    Send {
        binding: LinkEndpointBinding,
        generation: Arc<()>,
        request: OutboundRequest,
        completion: LinkEndpointDispatchCompletion,
    },
}

pub(crate) struct LinkEndpointDispatchCompletion {
    pub deadline: Instant,
    pub result_tx: oneshot::Sender<LinkEndpointDispatchOutcome>,
    cancellation: LinkEndpointDispatchCancellation,
}

impl LinkEndpointDispatchCompletion {
    pub(crate) fn terminal_before_admission(&self) -> Option<LinkEndpointDispatchOutcome> {
        if self.result_tx.is_closed() || self.cancellation.requested.load(Ordering::Acquire) {
            Some(LinkEndpointDispatchOutcome::Cancelled)
        } else if Instant::now() >= self.deadline {
            Some(LinkEndpointDispatchOutcome::Expired)
        } else {
            None
        }
    }
}

/// Cloneable bounded control lane belonging to one actor generation. Obtaining
/// a handle does not start that actor or ensure its continued availability.
#[derive(Debug, Clone)]
pub struct LinkEndpointDispatchHandle {
    pub(crate) tx: mpsc::Sender<LinkEndpointDispatchRequest>,
}

impl LinkEndpointDispatchHandle {
    /// Enqueue a new endpoint binding without waiting for actor admission.
    /// Await the receipt to obtain generation-specific send authority. Existing
    /// bindings are rejected rather than adopted, including identical bindings.
    ///
    /// There is no internal bind deadline. Dropping an unread receipt marks
    /// this unpublished binding for retirement when the actor observes it,
    /// including if the bind already executed.
    pub fn try_bind(
        &self,
        binding: LinkEndpointBinding,
        lifecycle_tx: mpsc::UnboundedSender<LinkEndpointLifecycleEvent>,
    ) -> Result<LinkEndpointDispatchBindReceipt, LinkEndpointDispatchError> {
        let (result_tx, result_rx) = oneshot::channel();
        let publication = Arc::new(AtomicU8::new(0));
        self.tx
            .try_send(LinkEndpointDispatchRequest::Bind {
                binding,
                lifecycle_tx,
                publication: publication.clone(),
                result_tx,
            })
            .map_err(admission_error)?;
        Ok(LinkEndpointDispatchBindReceipt {
            result_rx,
            publication,
            ready: None,
        })
    }
}

/// A bind reply whose cancellation also retires an unpublished endpoint.
/// Receiving the token publishes ownership; later cleanup uses the existing
/// explicit unbind operation. Dropping a published token does not unbind.
pub struct LinkEndpointDispatchBindReceipt {
    result_rx: oneshot::Receiver<Result<LinkEndpointDispatchToken, LinkEndpointBindResult>>,
    publication: Arc<AtomicU8>,
    ready: Option<
        Result<
            Result<LinkEndpointDispatchToken, LinkEndpointBindResult>,
            oneshot::error::RecvError,
        >,
    >,
}

impl LinkEndpointDispatchBindReceipt {
    /// Register a readiness waker without publishing endpoint ownership.
    /// A ready result stays owned by this receipt until `try_recv` or awaiting
    /// consumes it. Dropping even a ready receipt still retires an unpublished
    /// binding, so cancellation between readiness and processing is safe.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.ready.is_none()
            && let Poll::Ready(result) = Pin::new(&mut self.result_rx).poll(cx)
        {
            self.ready = Some(result);
        }
        if self.ready.is_some() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Consume an available reply without waiting. `Empty` keeps ownership
    /// unpublished; consuming a successful token publishes it. Later dropping
    /// the receipt or token does not unbind the endpoint.
    pub fn try_recv(
        &mut self,
    ) -> Result<
        Result<LinkEndpointDispatchToken, LinkEndpointBindResult>,
        oneshot::error::TryRecvError,
    > {
        let result = match self.ready.take() {
            Some(result) => result.map_err(|_| oneshot::error::TryRecvError::Closed)?,
            None => self.result_rx.try_recv()?,
        };
        self.publication.store(1, Ordering::Release);
        Ok(result)
    }
}

impl Future for LinkEndpointDispatchBindReceipt {
    type Output = Result<
        Result<LinkEndpointDispatchToken, LinkEndpointBindResult>,
        oneshot::error::RecvError,
    >;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = match self.ready.take() {
            Some(result) => Poll::Ready(result),
            None => Pin::new(&mut self.result_rx).poll(cx),
        };
        if result.is_ready() {
            self.publication.store(1, Ordering::Release);
        }
        result
    }
}

impl Drop for LinkEndpointDispatchBindReceipt {
    fn drop(&mut self) {
        let _ = self
            .publication
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// Send authority for one immutable endpoint binding generation. A later bind
/// with the same Link ID, role and interface cannot revive an old token.
/// Clones share authority; dropping all token clones does not unbind the endpoint.
#[derive(Debug, Clone)]
pub struct LinkEndpointDispatchToken {
    pub(crate) handle: LinkEndpointDispatchHandle,
    pub(crate) binding: LinkEndpointBinding,
    pub(crate) generation: Arc<()>,
}

impl LinkEndpointDispatchToken {
    /// Copy the binding metadata; this does not check whether it is still active.
    pub fn binding(&self) -> LinkEndpointBinding {
        self.binding
    }

    /// Enqueue a packet operation for the endpoint's bounded FIFO. A returned
    /// receiver is not admission: await its terminal outcome. The actor checks
    /// receiver cancellation immediately before admission; a later drop cannot
    /// recall bytes already accepted by the driver or in-process peer.
    ///
    /// The deadline includes command-queue wait and must be at most 120 seconds
    /// ahead. A past deadline is allowed and expires when actor processing
    /// observes it. Oversized input instead returns an immediately rejected
    /// receipt. Other packet/binding checks happen in the actor.
    ///
    /// At most 256 packets are retained per endpoint, each limited to the
    /// 500-byte inner wire MTU. Exhausting that FIFO terminates the endpoint
    /// and rejects its pending tracked operations. This method consumes the
    /// request even when control-queue admission fails.
    pub fn try_send(
        &self,
        request: OutboundRequest,
        deadline: Instant,
    ) -> Result<oneshot::Receiver<LinkEndpointDispatchOutcome>, LinkEndpointDispatchError> {
        self.try_send_cancellable(request, deadline)
            .map(|(receipt, _cancellation)| receipt)
    }

    /// As [`Self::try_send`], with a separate explicit cancellation handle for
    /// an owner that does not hold the receipt (for example a backchannel
    /// message coordinator). The immutable deadline and exact operation are
    /// shared; the handle cannot select another packet by hash or Link ID.
    pub fn try_send_cancellable(
        &self,
        request: OutboundRequest,
        deadline: Instant,
    ) -> Result<
        (
            oneshot::Receiver<LinkEndpointDispatchOutcome>,
            LinkEndpointDispatchCancellation,
        ),
        LinkEndpointDispatchError,
    > {
        if deadline.saturating_duration_since(Instant::now()) > LINK_ENDPOINT_ADMISSION_TIMEOUT_MAX
        {
            return Err(LinkEndpointDispatchError::InvalidDeadline);
        }
        let (result_tx, result_rx) = oneshot::channel();
        let cancellation = LinkEndpointDispatchCancellation {
            requested: Arc::new(AtomicBool::new(false)),
        };
        // Bound bytes before admitting the private control lane, not only
        // after the actor dequeues and validates the packet.
        if request.raw.len() > rns_wire::constants::MTU {
            let _ = result_tx.send(LinkEndpointDispatchOutcome::Rejected(
                LinkEndpointSendResult::InvalidPacket,
            ));
            return Ok((result_rx, cancellation));
        }
        self.handle
            .tx
            .try_send(LinkEndpointDispatchRequest::Send {
                binding: self.binding,
                generation: self.generation.clone(),
                request,
                completion: LinkEndpointDispatchCompletion {
                    deadline,
                    result_tx,
                    cancellation: cancellation.clone(),
                },
            })
            .map_err(admission_error)?;
        Ok((result_rx, cancellation))
    }
}

fn admission_error<T>(error: mpsc::error::TrySendError<T>) -> LinkEndpointDispatchError {
    match error {
        mpsc::error::TrySendError::Full(_) => LinkEndpointDispatchError::Full,
        mpsc::error::TrySendError::Closed(_) => LinkEndpointDispatchError::Closed,
    }
}
