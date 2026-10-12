//! Optional complete-packet background handoff to an interface's final writer.
//!
//! The scheduler retains the bulk backlog. This lane owns at most one offer or
//! started packet, independently of all ordinary packet FIFOs. Drivers apply
//! KISS/BLE framing exactly once after selection. Registration uses weak exact
//! channel identities and does not change exhaustive interface structures.
use bytes::Bytes;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use tokio::sync::{mpsc, oneshot};

const MAX_REGISTERED: usize = 4096;
type Registry = Mutex<Vec<(mpsc::WeakSender<Bytes>, Weak<Shared>)>>;
fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackgroundRegistrationError {
    Capacity,
    Duplicate,
}

struct State {
    offer: Option<Offer>,
    active: bool,
    generation: u64,
}
struct Shared {
    state: Mutex<State>,
    ordinary: mpsc::WeakSender<Bytes>,
}
struct Offer {
    raw: Bytes,
    expires: f64,
    cancelled: Arc<AtomicBool>,
    started: oneshot::Sender<f64>,
    generation: u64,
}

/// Driver-owned final-writer endpoint. Clone only for a joined physical writer;
/// call `retire_generation` before handing a reconnected carrier any offers.
#[derive(Clone)]
pub struct BackgroundAnnounceReceiver {
    shared: Arc<Shared>,
}
#[derive(Clone)]
pub(crate) struct BackgroundAnnounceSender {
    shared: Arc<Shared>,
}

/// Cancels a not-yet-started offer when its scheduler owner goes away.
pub(crate) struct BackgroundOfferReceipt {
    pub started: oneshot::Receiver<f64>,
    cancelled: Arc<AtomicBool>,
}
impl Drop for BackgroundOfferReceipt {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

/// Owns one already-selected complete RNS/IFAC packet. Keep this guard until
/// the whole write/acknowledgement (including an ambiguous retry) retires.
pub struct BackgroundPacket {
    raw: Bytes,
    shared: Arc<Shared>,
}
impl BackgroundPacket {
    pub fn raw(&self) -> &Bytes {
        &self.raw
    }
}
impl Drop for BackgroundPacket {
    fn drop(&mut self) {
        self.shared.state.lock().unwrap().active = false;
    }
}

impl BackgroundAnnounceReceiver {
    /// Attach a background lane to exactly `ordinary`. Failure is explicit;
    /// built-in drivers must fail startup rather than silently omit this lane.
    pub fn register(ordinary: &mpsc::Sender<Bytes>) -> Result<Self, BackgroundRegistrationError> {
        let mut registry = registry().lock().unwrap();
        registry.retain(|(channel, owner)| channel.strong_count() > 0 && owner.strong_count() > 0);
        if registry.iter().any(|(channel, _)| {
            channel
                .upgrade()
                .is_some_and(|old| old.same_channel(ordinary))
        }) {
            return Err(BackgroundRegistrationError::Duplicate);
        }
        if registry.len() >= MAX_REGISTERED {
            return Err(BackgroundRegistrationError::Capacity);
        }
        let shared = Arc::new(Shared {
            ordinary: ordinary.downgrade(),
            state: Mutex::new(State {
                offer: None,
                active: false,
                generation: 0,
            }),
        });
        registry.push((ordinary.downgrade(), Arc::downgrade(&shared)));
        Ok(Self { shared })
    }

    /// Discard unstarted work from the old physical generation. A selected
    /// packet retains its lease until its existing writer finishes or fails.
    pub fn retire_generation(&self) {
        let mut state = self.shared.state.lock().unwrap();
        state.generation = state.generation.wrapping_add(1);
        if state.offer.take().is_some() {
            state.active = false;
        }
    }

    /// Select only after ordinary work, carrier readiness and the radio permit
    /// have been checked, immediately before a complete packet write.
    pub fn try_start(&self, now: f64) -> Option<BackgroundPacket> {
        self.try_start_when(now, || true)
    }

    /// Atomically select a still-valid offer only when the final writer can
    /// consume its permit. A false predicate leaves the offer unstarted.
    pub fn try_start_when(
        &self,
        now: f64,
        permit: impl FnOnce() -> bool,
    ) -> Option<BackgroundPacket> {
        let mut state = self.shared.state.lock().unwrap();
        let offer = state.offer.take()?;
        if !now.is_finite()
            || now >= offer.expires
            || offer.cancelled.load(Ordering::Acquire)
            || offer.generation != state.generation
        {
            state.active = false;
            return None;
        }
        if !permit() {
            state.offer = Some(offer);
            return None;
        }
        let _ = offer.started.send(now);
        Some(BackgroundPacket {
            raw: offer.raw,
            shared: self.shared.clone(),
        })
    }

    /// Ordinary outer-channel backlog has priority over background selection.
    pub fn ordinary_is_empty(&self) -> bool {
        self.shared
            .ordinary
            .upgrade()
            .is_some_and(|tx| tx.capacity() == tx.max_capacity())
    }

    /// Whether a non-cancelled offer exists. Selection still rechecks expiry.
    pub fn has_offer(&self) -> bool {
        self.shared.state.lock().unwrap().offer.is_some()
    }
}

pub(crate) fn lookup(ordinary: &mpsc::Sender<Bytes>) -> Option<BackgroundAnnounceSender> {
    let mut registry = registry().lock().unwrap();
    registry.retain(|(channel, owner)| channel.strong_count() > 0 && owner.strong_count() > 0);
    registry.iter().find_map(|(channel, owner)| {
        channel.upgrade().filter(|old| old.same_channel(ordinary))?;
        Some(BackgroundAnnounceSender {
            shared: owner.upgrade()?,
        })
    })
}

impl BackgroundAnnounceSender {
    pub fn try_offer(&self, raw: Bytes, expires: f64, now: f64) -> Option<BackgroundOfferReceipt> {
        let mut state = self.shared.state.lock().unwrap();
        if state
            .offer
            .as_ref()
            .is_some_and(|offer| now >= offer.expires || offer.cancelled.load(Ordering::Acquire))
        {
            state.offer = None;
            state.active = false;
        }
        if state.active {
            return None;
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let (started, rx) = oneshot::channel();
        state.offer = Some(Offer {
            raw,
            expires,
            cancelled: cancelled.clone(),
            started,
            generation: state.generation,
        });
        state.active = true;
        Some(BackgroundOfferReceipt {
            started: rx,
            cancelled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_channel_generation_and_weak_cleanup() {
        let (tx, _rx) = mpsc::channel(1);
        let driver = BackgroundAnnounceReceiver::register(&tx).unwrap();
        let sender = lookup(&tx).unwrap();
        let (other, _other_rx) = mpsc::channel(1);
        assert!(lookup(&other).is_none());
        let mut old = sender
            .try_offer(Bytes::from_static(b"old"), 100.0, 0.0)
            .unwrap();
        driver.retire_generation();
        assert!(old.started.try_recv().is_err());
        assert!(driver.try_start(1.0).is_none());
        let receipt = sender
            .try_offer(Bytes::from_static(b"new"), 100.0, 1.0)
            .unwrap();
        drop(receipt);
        assert!(driver.try_start(2.0).is_none());
        drop(sender);
        drop(driver);
        assert!(lookup(&tx).is_none());
        assert!(BackgroundAnnounceReceiver::register(&tx).is_ok());
    }
    #[test]
    fn lease_bounds_offer_through_complete_write_and_expiry() {
        let (tx, _rx) = mpsc::channel(1);
        let driver = BackgroundAnnounceReceiver::register(&tx).unwrap();
        let sender = lookup(&tx).unwrap();
        let mut receipt = sender
            .try_offer(Bytes::from_static(b"packet"), 2000.0, 0.0)
            .unwrap();
        for now in 0..1000 {
            assert!(sender.try_offer(Bytes::new(), 2000.0, now as f64).is_none());
            assert_eq!(tx.capacity(), 1);
        }
        let packet = driver.try_start(1000.0).unwrap();
        assert_eq!(receipt.started.try_recv().unwrap(), 1000.0);
        assert!(sender.try_offer(Bytes::new(), 2000.0, 1001.0).is_none());
        drop(packet);
        let _next = sender.try_offer(Bytes::new(), 1002.0, 1001.0).unwrap();
        assert!(driver.try_start(1002.0).is_none());
    }
}
