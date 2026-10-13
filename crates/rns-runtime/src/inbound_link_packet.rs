//! Bounded, one-shot application authority for ordinary Link DATA packets.
use bytes::Bytes;
use rns_link::link::LinkRole;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, oneshot};

pub const APPLICATION_PACKET_LIFETIME: Duration = Duration::from_secs(120);
const GLOBAL_SLOTS: usize = 256;
const GLOBAL_BYTES: usize = 8 * 1024 * 1024;
const LINK_SLOTS: usize = 64;
const LINK_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkPacketReceiptOutcome {
    Sent,
    Expired,
    Closed,
    Dropped,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkPacketRejection {
    InvalidPropagationStamp,
}
#[derive(Debug, thiserror::Error)]
pub enum LinkPacketConfigurationError {
    #[error("application-controlled ordinary proofs require an exact endpoint dispatch handle")]
    ExactDispatchRequired,
    #[error("application-controlled ordinary proofs require the typed bounded inbound channel")]
    TypedChannelRequired,
    #[error("legacy tuple channel cannot carry application-controlled packet receipts")]
    LegacyChannel,
}

#[derive(Default, Debug)]
struct Counts {
    slots: usize,
    bytes: usize,
}
#[derive(Debug)]
pub(crate) struct PacketLease {
    global: Arc<Mutex<Counts>>,
    link: Arc<Mutex<Counts>>,
    bytes: usize,
}
impl Drop for PacketLease {
    fn drop(&mut self) {
        let mut global = self.global.lock().unwrap_or_else(|e| e.into_inner());
        let mut link = self.link.lock().unwrap_or_else(|e| e.into_inner());
        global.slots -= 1;
        global.bytes -= self.bytes;
        link.slots -= 1;
        link.bytes -= self.bytes;
    }
}

/// A private identity object distinguishes re-created Links even if their wire
/// ID or transport generation counter is reused.
#[derive(Debug)]
pub(crate) struct PacketEpoch {
    pub generation: u64,
    pub alive: AtomicBool,
    counts: Arc<Mutex<Counts>>,
}
impl PacketEpoch {
    pub fn new(generation: u64) -> Arc<Self> {
        Arc::new(Self {
            generation,
            alive: AtomicBool::new(true),
            counts: Arc::new(Mutex::new(Counts::default())),
        })
    }
    pub fn reserve(self: &Arc<Self>, bytes: usize) -> Option<Arc<PacketLease>> {
        static GLOBAL: OnceLock<Arc<Mutex<Counts>>> = OnceLock::new();
        let global = GLOBAL
            .get_or_init(|| Arc::new(Mutex::new(Counts::default())))
            .clone();
        reserve(global, self.counts.clone(), bytes)
    }
}
fn reserve(
    global: Arc<Mutex<Counts>>,
    link: Arc<Mutex<Counts>>,
    bytes: usize,
) -> Option<Arc<PacketLease>> {
    {
        let mut g = global.lock().unwrap_or_else(|e| e.into_inner());
        let mut l = link.lock().unwrap_or_else(|e| e.into_inner());
        if g.slots >= GLOBAL_SLOTS
            || l.slots >= LINK_SLOTS
            || bytes > GLOBAL_BYTES.saturating_sub(g.bytes)
            || bytes > LINK_BYTES.saturating_sub(l.bytes)
        {
            return None;
        }
        g.slots += 1;
        g.bytes += bytes;
        l.slots += 1;
        l.bytes += bytes;
    }
    Some(Arc::new(PacketLease {
        global,
        link,
        bytes,
    }))
}

#[derive(Debug)]
pub(crate) enum Decision {
    Accept,
    Drop,
    Close,
    Reject(LinkPacketRejection),
}
#[derive(Debug)]
pub(crate) struct Resolution {
    pub decision: Decision,
    pub reply: Option<oneshot::Sender<LinkPacketReceiptOutcome>>,
}
/// Stored separately from authority: retained payload clones and live workers
/// keep credits even after expiration or Link teardown.
struct LeasedPayload {
    bytes: Vec<u8>,
    _lease: Arc<PacketLease>,
}
impl AsRef<[u8]> for LeasedPayload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug)]
pub struct InboundLinkPacket {
    payload: Bytes,
    link_id: [u8; 16],
    destination_hash: [u8; 16],
    packet_hash: [u8; 32],
    role: LinkRole,
    receipt: Option<LinkPacketReceipt>,
}
impl InboundLinkPacket {
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }
    pub fn link_id(&self) -> [u8; 16] {
        self.link_id
    }
    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination_hash
    }
    pub fn packet_hash(&self) -> [u8; 32] {
        self.packet_hash
    }
    pub fn role(&self) -> LinkRole {
        self.role
    }
    pub fn into_parts(self) -> (Bytes, Option<LinkPacketReceipt>) {
        (self.payload, self.receipt)
    }
    pub(crate) fn new(
        bytes: Vec<u8>,
        link_id: [u8; 16],
        destination_hash: [u8; 16],
        packet_hash: [u8; 32],
        role: LinkRole,
        receipt: Option<LinkPacketReceipt>,
    ) -> Self {
        let payload = match &receipt {
            Some(receipt) => Bytes::from_owner(LeasedPayload {
                bytes,
                _lease: receipt.lease.clone(),
            }),
            None => Bytes::from(bytes),
        };
        Self {
            payload,
            link_id,
            destination_hash,
            packet_hash,
            role,
            receipt,
        }
    }
}

/// Non-cloneable authority for one exact received packet. Resolution does not
/// imply admission until its returned receiver reports `Sent`.
#[derive(Debug)]
pub struct LinkPacketReceipt {
    resolver: Option<oneshot::Sender<Resolution>>,
    notify: Arc<Notify>,
    lease: Arc<PacketLease>,
    pub(crate) state: Arc<AtomicU8>,
}
impl LinkPacketReceipt {
    pub(crate) fn new(
        lease: Arc<PacketLease>,
        notify: Arc<Notify>,
    ) -> (Self, oneshot::Receiver<Resolution>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                resolver: Some(tx),
                notify,
                lease,
                state: Arc::new(AtomicU8::new(0)),
            },
            rx,
        )
    }
    pub fn accept(self) -> oneshot::Receiver<LinkPacketReceiptOutcome> {
        self.resolve(Decision::Accept)
    }
    pub fn reject_and_close(
        self,
        reason: LinkPacketRejection,
    ) -> oneshot::Receiver<LinkPacketReceiptOutcome> {
        self.resolve(Decision::Reject(reason))
    }
    pub fn drop_without_proof(self) {
        drop(self);
    }
    /// Close only this receipt's still-current Link without a delivery proof or
    /// an invalid-stamp error. `Closed` confirms local closure, not peer receipt
    /// of the best-effort teardown. Stale authority cannot close a replacement.
    pub fn close_without_proof(self) -> oneshot::Receiver<LinkPacketReceiptOutcome> {
        self.resolve(Decision::Close)
    }
    fn resolve(mut self, decision: Decision) -> oneshot::Receiver<LinkPacketReceiptOutcome> {
        let (reply, rx) = oneshot::channel();
        let resolution = Resolution {
            decision,
            reply: Some(reply),
        };
        if let Some(tx) = self.resolver.take()
            && let Err(resolution) = tx.send(resolution)
        {
            let outcome = terminal_outcome(&self.state).unwrap_or(LinkPacketReceiptOutcome::Closed);
            if let Some(tx) = resolution.reply {
                let _ = tx.send(outcome);
            }
        }
        self.notify.notify_one();
        rx
    }
}
impl Drop for LinkPacketReceipt {
    fn drop(&mut self) {
        if let Some(tx) = self.resolver.take() {
            let _ = tx.send(Resolution {
                decision: Decision::Drop,
                reply: None,
            });
        }
        self.notify.notify_one();
    }
}
pub(crate) fn set_terminal(state: &AtomicU8, outcome: LinkPacketReceiptOutcome) {
    let value = match outcome {
        LinkPacketReceiptOutcome::Sent => 1,
        LinkPacketReceiptOutcome::Expired => 2,
        LinkPacketReceiptOutcome::Closed => 3,
        LinkPacketReceiptOutcome::Dropped => 4,
        LinkPacketReceiptOutcome::Unavailable => 5,
    };
    state.store(value, Ordering::Release);
}
fn terminal_outcome(state: &AtomicU8) -> Option<LinkPacketReceiptOutcome> {
    match state.load(Ordering::Acquire) {
        1 => Some(LinkPacketReceiptOutcome::Sent),
        2 => Some(LinkPacketReceiptOutcome::Expired),
        3 => Some(LinkPacketReceiptOutcome::Closed),
        4 => Some(LinkPacketReceiptOutcome::Dropped),
        5 => Some(LinkPacketReceiptOutcome::Unavailable),
        _ => None,
    }
}

pub(crate) struct PendingInboundPacket {
    pub link_id: [u8; 16],
    pub packet_hash: [u8; 32],
    pub epoch: Arc<PacketEpoch>,
    pub deadline: Instant,
    pub state: Arc<AtomicU8>,
    pub _lease: Arc<PacketLease>,
    pub resolution: oneshot::Receiver<Resolution>,
    pub dispatch: Option<PacketDispatch>,
}
pub(crate) struct PacketDispatch {
    pub result:
        oneshot::Receiver<rns_transport::link_endpoint_dispatch::LinkEndpointDispatchOutcome>,
    pub cancellation: rns_transport::link_endpoint_dispatch::LinkEndpointDispatchCancellation,
    pub expected_hash: [u8; 32],
    pub payload_len: usize,
    pub rejecting: bool,
    pub ready: Option<
        Result<
            rns_transport::link_endpoint_dispatch::LinkEndpointDispatchOutcome,
            oneshot::error::RecvError,
        >,
    >,
    pub reply: Option<oneshot::Sender<LinkPacketReceiptOutcome>>,
}
impl PendingInboundPacket {
    pub fn finish(&mut self, outcome: LinkPacketReceiptOutcome) {
        set_terminal(&self.state, outcome);
        if let Some(dispatch) = &mut self.dispatch {
            if outcome != LinkPacketReceiptOutcome::Sent {
                dispatch.cancellation.cancel();
            }
            if let Some(reply) = dispatch.reply.take() {
                let _ = reply.send(outcome);
            }
        }
        if let Ok(resolution) = self.resolution.try_recv()
            && let Some(reply) = resolution.reply
        {
            let _ = reply.send(outcome);
        }
    }
}
impl Drop for PendingInboundPacket {
    fn drop(&mut self) {
        if terminal_outcome(&self.state).is_none() {
            self.finish(LinkPacketReceiptOutcome::Closed);
        }
    }
}

// Register completion wakers without detached tasks or another event queue.
pub(crate) async fn wait_dispatch(pending: &mut [PendingInboundPacket]) {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::Poll;
    std::future::poll_fn(|cx| {
        for packet in pending.iter_mut() {
            if let Some(dispatch) = &mut packet.dispatch {
                if dispatch.ready.is_some() {
                    return Poll::Ready(());
                }
                if let Poll::Ready(result) = Pin::new(&mut dispatch.result).poll(cx) {
                    dispatch.ready = Some(result);
                    return Poll::Ready(());
                }
            }
        }
        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn payload_owners_retain_credits_after_authority_closes() {
        let global = Arc::new(Mutex::new(Counts::default()));
        let link = Arc::new(Mutex::new(Counts::default()));
        let lease = reserve(global.clone(), link.clone(), 100).unwrap();
        let (receipt, rx) = LinkPacketReceipt::new(lease.clone(), Arc::new(Notify::new()));
        let event = InboundLinkPacket::new(
            vec![0; 100],
            [1; 16],
            [2; 16],
            [3; 32],
            LinkRole::Responder,
            Some(receipt),
        );
        let payload = event.payload().clone();
        drop(event);
        drop(rx);
        drop(lease);
        assert_eq!(global.lock().unwrap().bytes, 100);
        drop(payload);
        assert_eq!(global.lock().unwrap().bytes, 0);
    }
    #[test]
    fn reservations_are_atomic_and_per_link_isolation_is_bounded() {
        let global = Arc::new(Mutex::new(Counts::default()));
        let link = Arc::new(Mutex::new(Counts::default()));
        let leases: Vec<_> = (0..LINK_SLOTS)
            .map(|_| reserve(global.clone(), link.clone(), 1).unwrap())
            .collect();
        assert!(reserve(global.clone(), link.clone(), 1).is_none());
        assert!(
            reserve(
                global.clone(),
                Arc::new(Mutex::new(Counts::default())),
                LINK_BYTES + 1
            )
            .is_none()
        );
        assert_eq!(global.lock().unwrap().slots, LINK_SLOTS);
        let other = reserve(
            global.clone(),
            Arc::new(Mutex::new(Counts::default())),
            LINK_BYTES,
        )
        .unwrap();
        drop(leases);
        drop(other);
        assert_eq!(global.lock().unwrap().slots, 0);
    }
    #[test]
    fn global_count_and_byte_limits_include_independent_links() {
        let global = Arc::new(Mutex::new(Counts::default()));
        let mut leases = Vec::new();
        for _ in 0..4 {
            let link = Arc::new(Mutex::new(Counts::default()));
            for _ in 0..LINK_SLOTS {
                leases.push(reserve(global.clone(), link.clone(), 1).unwrap());
            }
        }
        assert_eq!(global.lock().unwrap().slots, GLOBAL_SLOTS);
        assert!(reserve(global.clone(), Arc::new(Mutex::new(Counts::default())), 1).is_none());
        drop(leases);
        let leases: Vec<_> = (0..4)
            .map(|_| {
                reserve(
                    global.clone(),
                    Arc::new(Mutex::new(Counts::default())),
                    LINK_BYTES,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(global.lock().unwrap().bytes, GLOBAL_BYTES);
        assert!(reserve(global.clone(), Arc::new(Mutex::new(Counts::default())), 1).is_none());
        drop(leases);
        assert_eq!(global.lock().unwrap().slots, 0);
        assert_eq!(global.lock().unwrap().bytes, 0);
    }
    #[test]
    fn late_resolution_reports_expiration_without_reviving_authority() {
        let epoch = PacketEpoch::new(1);
        let lease = epoch.reserve(1).unwrap();
        let (receipt, rx) = LinkPacketReceipt::new(lease, Arc::new(Notify::new()));
        set_terminal(&receipt.state, LinkPacketReceiptOutcome::Expired);
        drop(rx);
        assert_eq!(
            receipt.accept().try_recv().unwrap(),
            LinkPacketReceiptOutcome::Expired
        );
    }
}
