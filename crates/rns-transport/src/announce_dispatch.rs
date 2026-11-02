//! Bounded admission intents for locally produced announcements.
//!
//! `Admitted` means one interface queue accepted bytes. Results do not report
//! every target, physical transmission or delivery. The actor owns retry state
//! until its deadline or retirement; callers must bound their own reply wait.
use bytes::Bytes;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

pub(crate) const CAPACITY: usize = 256;

/// First reported result for an intent, not a complete per-interface report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnounceDispatchResult {
    /// At least one target's interface queue accepted bytes.
    Admitted,
    /// The intent expired, was coalesced or lost admission eligibility. A
    /// coalesced target can resolve this before other targets are processed,
    /// so it does not prove that no bytes were or will be admitted.
    Expired,
    /// Initial target selection found no eligible interface.
    NoEligibleInterface,
    /// The header could not be parsed or the packet was not an announce.
    Invalid,
}

/// The intent could not enter the actor's bounded dispatch queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnounceDispatchError {
    Full,
    Closed,
}

/// Cloneable handle to the actor's 256-intent admission queue. The actor must
/// be running to process requests; cloning does not create another queue.
#[derive(Clone, Debug)]
pub struct AnnounceDispatchHandle {
    pub(crate) tx: mpsc::Sender<AnnounceDispatchRequest>,
}

pub(crate) struct AnnounceDispatchRequest {
    pub raw: Bytes,
    pub attached_interface: Option<crate::messages::InterfaceId>,
    pub deadline: tokio::time::Instant,
    pub result: oneshot::Sender<AnnounceDispatchResult>,
}

impl AnnounceDispatchHandle {
    /// Queue a complete inner announce packet with a lifetime capped at 120
    /// seconds. The actor checks its header/type, not its announce signature;
    /// callers must construct a valid payload. An attached interface is an
    /// explicit outbound target; otherwise normal announce egress policy applies.
    ///
    /// The first reported result resolves the reply. Refused targets can remain
    /// pending until the original deadline even after another target is admitted.
    /// Accepted targets are not retried by this intent. `Expired` can also mean
    /// one target was coalesced while other targets continue. A dropped receiver
    /// is checked before initial processing and during retries until the first
    /// result; dropping it cannot recall queued bytes or interrupt processing
    /// already underway. Bound the reply wait separately from work lifetime.
    /// On `Full`/`Closed`, the intent was not queued and its input bytes are not
    /// returned; retain a copy if retrying.
    pub fn try_dispatch(
        &self,
        raw: Bytes,
        attached_interface: Option<crate::messages::InterfaceId>,
        lifetime: Duration,
    ) -> Result<oneshot::Receiver<AnnounceDispatchResult>, AnnounceDispatchError> {
        let (result, rx) = oneshot::channel();
        let request = AnnounceDispatchRequest {
            raw,
            attached_interface,
            deadline: tokio::time::Instant::now() + lifetime.min(Duration::from_secs(120)),
            result,
        };
        self.tx.try_send(request).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => AnnounceDispatchError::Full,
            mpsc::error::TrySendError::Closed(_) => AnnounceDispatchError::Closed,
        })?;
        Ok(rx)
    }
}
