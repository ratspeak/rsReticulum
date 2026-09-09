//! Exact local admission receipts for established, locally owned Links.
//!
//! A receipt means the bound interface queue (or in-process peer queue)
//! accepted the packet, never that a modem transmitted it or a peer received
//! it. Legacy mailbox sends retain their existing immediate `Queued` result.

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
/// Maximum local admission lifetime, independent of network RTT.
pub const LINK_ENDPOINT_ADMISSION_TIMEOUT_MAX: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkEndpointDispatchError {
    Full,
    Closed,
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
    Sent {
        packet_hash: [u8; 32],
        dispatched_at: Instant,
    },
    Rejected(LinkEndpointSendResult),
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

/// Cloneable control lane belonging to one transport actor generation.
#[derive(Debug, Clone)]
pub struct LinkEndpointDispatchHandle {
    pub(crate) tx: mpsc::Sender<LinkEndpointDispatchRequest>,
}

impl LinkEndpointDispatchHandle {
    /// Bind a new endpoint and obtain exact-generation send authority. Existing
    /// bindings are never adopted. Dropping an unread receipt cancels and
    /// retires only this unpublished binding, including after actor execution.
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
        })
    }
}

/// A bind reply whose cancellation also retires an unpublished endpoint.
/// Receiving the token publishes ownership; later cleanup uses the existing
/// explicit unbind operation. Dropping a published token does not unbind.
pub struct LinkEndpointDispatchBindReceipt {
    result_rx: oneshot::Receiver<Result<LinkEndpointDispatchToken, LinkEndpointBindResult>>,
    publication: Arc<AtomicU8>,
}

impl LinkEndpointDispatchBindReceipt {
    pub fn try_recv(
        &mut self,
    ) -> Result<
        Result<LinkEndpointDispatchToken, LinkEndpointBindResult>,
        oneshot::error::TryRecvError,
    > {
        let result = self.result_rx.try_recv()?;
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
        let result = Pin::new(&mut self.result_rx).poll(cx);
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
/// with the same link ID, role and interface cannot revive an old token.
#[derive(Debug, Clone)]
pub struct LinkEndpointDispatchToken {
    pub(crate) handle: LinkEndpointDispatchHandle,
    pub(crate) binding: LinkEndpointBinding,
    pub(crate) generation: Arc<()>,
}

impl LinkEndpointDispatchToken {
    pub fn binding(&self) -> LinkEndpointBinding {
        self.binding
    }

    /// Retain one packet in the endpoint's existing bounded FIFO until actual
    /// local admission, cancellation or the immutable deadline. The actor checks
    /// receiver cancellation immediately before admission; a concurrent drop
    /// after that check cannot recall bytes accepted by the driver. The deadline
    /// includes mailbox wait and must be no more than 120 seconds in the future.
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
