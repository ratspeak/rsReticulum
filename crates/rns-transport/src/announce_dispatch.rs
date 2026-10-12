//! Finite, exact-target admission of locally produced announcements.
//!
//! An admitted result means a driver accepted bytes, never radio delivery.
use bytes::Bytes;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

pub(crate) const CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnounceDispatchResult {
    Admitted,
    Expired,
    NoEligibleInterface,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnounceDispatchError {
    Full,
    Closed,
}

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
    /// Queue an admission intent for at most 120 seconds. The reply resolves
    /// on the first driver acceptance; refused targets remain owned until the
    /// original deadline. Accepted targets are never replayed. Dropping the
    /// receiver before its first result cancels unadmitted work.
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
