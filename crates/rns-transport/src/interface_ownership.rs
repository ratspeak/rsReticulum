//! Interface packet budgets and producer-bound registration identities.
use crate::messages::{InterfaceId, TransportMessage};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::sync::{Notify, mpsc};

/// Copyable provenance for a pending handshake. Only comparison with the
/// current registration grants authority; it cannot revive a retired owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceOwnerId {
    epoch: u64,
    revision: u64,
}
impl InterfaceOwnerId {
    pub fn matches(self, owner: &InterfaceOwner) -> bool {
        owner.is_current() && self == owner.id()
    }
}

/// Immutable identity captured before an interface starts producing events.
/// Carrier reconnects retain it; replacement registrations always mint a new one.
#[derive(Debug, Clone)]
pub struct InterfaceOwner {
    epoch: u64,
    revision: u64,
    validity: Arc<RegistrationState>,
}
#[derive(Debug)]
struct RegistrationState {
    retired: AtomicBool,
    revision: AtomicU64,
    registered_revision: AtomicU64,
    changed: Notify,
}
impl PartialEq for InterfaceOwner {
    fn eq(&self, other: &Self) -> bool {
        self.epoch == other.epoch && self.revision == other.revision
    }
}
impl Eq for InterfaceOwner {}
impl InterfaceOwner {
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        // `try_update` is the Rust 1.99 spelling; retain the identical atomic
        // operation available on our Rust 1.89 minimum.
        #[allow(deprecated)]
        let epoch = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .expect("interface registration identity exhausted");
        Self {
            epoch,
            revision: 0,
            validity: Arc::new(RegistrationState {
                retired: AtomicBool::new(false),
                revision: AtomicU64::new(0),
                registered_revision: AtomicU64::new(u64::MAX),
                changed: Notify::new(),
            }),
        }
    }
    pub fn id(&self) -> InterfaceOwnerId {
        InterfaceOwnerId {
            epoch: self.epoch,
            revision: self.revision,
        }
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn is_current(&self) -> bool {
        !self.validity.retired.load(Ordering::Acquire)
            && self.validity.revision.load(Ordering::Acquire) == self.revision
    }
    /// Called after this registration is installed by its transport consumer.
    /// Custom transport/test consumers must acknowledge registration likewise.
    /// This wakes producers; actor admission still checks the exact owner.
    pub fn mark_registered(&self) -> bool {
        if !self.is_current() {
            return false;
        }
        // A slow acknowledgement for an old revision must never overwrite a
        // newer readiness acknowledgement. MAX denotes "never registered".
        // `fetch_update` retains Rust 1.89 support (renamed in Rust 1.99).
        #[allow(deprecated)]
        let _ = self.validity.registered_revision.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |registered| {
                (registered == u64::MAX || registered < self.revision).then_some(self.revision)
            },
        );
        self.validity.changed.notify_waiters();
        self.is_registered()
    }
    pub fn is_registered(&self) -> bool {
        self.is_current()
            && self.validity.registered_revision.load(Ordering::Acquire) == self.revision
    }
    async fn wait_registered(&self) -> bool {
        loop {
            let notified = self.validity.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.is_current() {
                return false;
            }
            if self.is_registered() {
                return true;
            }
            notified.await;
        }
    }
    /// A coordinated capacity/IFAC reconfiguration first invalidates the previous
    /// revision, then binds producers and registers this returned identity.
    pub fn next_revision(&self) -> Option<Self> {
        if !self.is_current() {
            return None;
        }
        let next = self.revision.checked_add(1)?;
        self.validity
            .revision
            .compare_exchange(self.revision, next, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        self.validity.changed.notify_waiters();
        Some(Self {
            epoch: self.epoch,
            revision: next,
            validity: Arc::clone(&self.validity),
        })
    }
    pub(crate) fn retire(&self) {
        self.validity.retired.store(true, Ordering::Release);
        self.validity.changed.notify_waiters();
    }
}
impl Default for InterfaceOwner {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete Reticulum packet guarantees before framing/fragmentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfacePacketCapacity {
    pub max_clear_packet_bytes: u32,
    pub max_wire_packet_bytes: u32,
    pub link_mtu_upgrade: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InterfaceCapacityError {
    #[error("interface packet capacity must be nonzero")]
    Empty,
    #[error("active IFAC size must be 1..=64 bytes")]
    InvalidIfac,
    #[error("IFAC size {ifac_bytes} exceeds wire packet capacity {wire_bytes}")]
    IfacExceedsWire { ifac_bytes: usize, wire_bytes: u32 },
    #[error("interface {interface_id} has {clear_mtu} clear bytes, Links require {required}")]
    LinkCapacityUnavailable {
        interface_id: InterfaceId,
        clear_mtu: u32,
        required: u32,
    },
}
impl InterfacePacketCapacity {
    pub const fn new(clear: u32, wire: u32, upgrade: bool) -> Self {
        Self {
            max_clear_packet_bytes: clear,
            max_wire_packet_bytes: wire,
            link_mtu_upgrade: upgrade,
        }
    }
    pub const fn base(mtu: u32) -> Self {
        Self::new(mtu, mtu, false)
    }
    pub fn effective_clear_mtu(
        self,
        active_ifac_bytes: usize,
    ) -> Result<u32, InterfaceCapacityError> {
        if self.max_clear_packet_bytes == 0 || self.max_wire_packet_bytes == 0 {
            return Err(InterfaceCapacityError::Empty);
        }
        if active_ifac_bytes > 64 {
            return Err(InterfaceCapacityError::InvalidIfac);
        }
        let wire_limit = if active_ifac_bytes > 0 {
            self.max_wire_packet_bytes
                .min(crate::ifac::MAX_IFAC_WIRE_BYTES as u32)
        } else {
            self.max_wire_packet_bytes
        };
        let wire = usize::try_from(wire_limit).map_err(|_| InterfaceCapacityError::Empty)?;
        let remaining =
            wire.checked_sub(active_ifac_bytes)
                .ok_or(InterfaceCapacityError::IfacExceedsWire {
                    ifac_bytes: active_ifac_bytes,
                    wire_bytes: self.max_wire_packet_bytes,
                })?;
        let effective = self.max_clear_packet_bytes.min(remaining as u32);
        if effective == 0 {
            return Err(InterfaceCapacityError::Empty);
        }
        Ok(effective)
    }
    pub fn link_ceiling(
        self,
        interface_id: InterfaceId,
        active_ifac_bytes: usize,
    ) -> Result<u32, InterfaceCapacityError> {
        let clear_mtu = self.effective_clear_mtu(active_ifac_bytes)?;
        if clear_mtu < 500 {
            return Err(InterfaceCapacityError::LinkCapacityUnavailable {
                interface_id,
                clear_mtu,
                required: 500,
            });
        }
        Ok(if self.link_mtu_upgrade {
            clear_mtu.min(rns_wire::link_signalling::MAX_SIGNALLED_LINK_MTU)
        } else {
            500
        })
    }
}

/// Sender owned by one registration. Bind before spawning any producer and keep
/// it through ordinary reconnects. Accepted children bind a fresh owner to the
/// underlying actor sender. The actor, not the sender, validates current ownership.
#[derive(Debug, Clone)]
pub struct InterfaceTransportSender {
    id: InterfaceId,
    owner: InterfaceOwner,
    tx: mpsc::Sender<TransportMessage>,
}
impl InterfaceTransportSender {
    pub fn new(id: InterfaceId, tx: mpsc::Sender<TransportMessage>) -> Self {
        Self::bind(id, InterfaceOwner::new(), tx)
    }
    pub fn bind(
        id: InterfaceId,
        owner: InterfaceOwner,
        tx: mpsc::Sender<TransportMessage>,
    ) -> Self {
        Self { id, owner, tx }
    }
    pub fn owner(&self) -> InterfaceOwner {
        self.owner.clone()
    }
    pub fn interface_id(&self) -> InterfaceId {
        self.id
    }
    /// Only use when creating a child registration with its own producer binding.
    pub fn actor_sender(&self) -> mpsc::Sender<TransportMessage> {
        self.tx.clone()
    }
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
    pub fn capacity(&self) -> usize {
        self.tx.capacity()
    }
    pub fn max_capacity(&self) -> usize {
        self.tx.max_capacity()
    }
    pub async fn closed(&self) {
        self.tx.closed().await
    }
    pub fn event(&self, message: TransportMessage) -> TransportMessage {
        TransportMessage::InterfaceEvent {
            interface_id: self.id,
            owner: self.owner.clone(),
            message: Box::new(message),
        }
    }
    /// Wait for registration without losing the first received frame. Each
    /// producer retains at most its current frame; no extra queue is created.
    pub async fn ready(&self) -> bool {
        tokio::select! {
            biased;
            _ = self.tx.closed() => false,
            ready = self.owner.wait_registered() => ready,
        }
    }
    // Preserve Tokio's by-value failure contract, including the original
    // owned message for retry, without a failure-only heap allocation.
    #[allow(clippy::result_large_err)]
    pub async fn send(
        &self,
        message: TransportMessage,
    ) -> Result<(), mpsc::error::SendError<TransportMessage>> {
        if !self.ready().await {
            return Err(mpsc::error::SendError(message));
        }
        self.tx
            .send(self.event(message))
            .await
            .map_err(|e| mpsc::error::SendError(unwrap_event(e.0)))
    }
    // Match Tokio's by-value failure contract so callers can retry the exact
    // original message without an additional heap allocation on refusal.
    #[allow(clippy::result_large_err)]
    pub fn try_send(
        &self,
        message: TransportMessage,
    ) -> Result<(), mpsc::error::TrySendError<TransportMessage>> {
        if !self.owner.is_current() {
            return Err(mpsc::error::TrySendError::Closed(message));
        }
        if !self.owner.is_registered() {
            return Err(mpsc::error::TrySendError::Full(message));
        }
        self.tx.try_send(self.event(message)).map_err(|e| match e {
            mpsc::error::TrySendError::Full(m) => mpsc::error::TrySendError::Full(unwrap_event(m)),
            mpsc::error::TrySendError::Closed(m) => {
                mpsc::error::TrySendError::Closed(unwrap_event(m))
            }
        })
    }
}
fn unwrap_event(message: TransportMessage) -> TransportMessage {
    match message {
        TransportMessage::InterfaceEvent { message, .. } => *message,
        other => other,
    }
}
