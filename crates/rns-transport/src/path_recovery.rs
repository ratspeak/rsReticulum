//! Bounded recovery of a locally originated Link's route.
//!
//! The transport records the route actually used at dispatch. Recovery may
//! invalidate that unchanged route, never a replacement learned meanwhile.
//! No interface is suppressed: a fresh response on the same radio is welcome.

use tokio::sync::{mpsc, oneshot};

pub(crate) const RECOVERY_QUEUE_CAPACITY: usize = 64;

/// Result of one serialized recovery operation. Discovery admission is not
/// radio transmission, a learned path, or recipient delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PathRecoveryOutcome {
    pub path_dropped: bool,
    pub has_path: bool,
    pub request_scheduled: bool,
}

/// A recovery operation was not admitted. Retain the failed attempt and retry
/// admission later on `Full`; `Closed` means this transport owner has retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathRecoveryError {
    Full,
    Closed,
}

impl std::fmt::Display for PathRecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Full => "path recovery queue full",
            Self::Closed => "path recovery owner closed",
        })
    }
}

impl std::error::Error for PathRecoveryError {}

pub(crate) struct PathRecoveryRequest {
    pub destination_hash: [u8; 16],
    pub failed_link: Option<[u8; 16]>,
    pub result_tx: oneshot::Sender<PathRecoveryOutcome>,
}

/// Cloneable, transport-generation-owned admission handle. Obtain it before
/// running the actor with [`crate::actor::TransportActor::path_recovery_handle`].
/// This additive control lane does not change the existing exhaustive mailbox
/// enums or the semantics of explicit interface-suppression APIs.
#[derive(Debug, Clone)]
pub struct PathRecoveryHandle {
    pub(crate) tx: mpsc::Sender<PathRecoveryRequest>,
}

impl PathRecoveryHandle {
    /// Admit an atomic failed-route comparison and bounded discovery request.
    /// `failed_link` must identify a Link originated through this actor. An
    /// absent/unobserved Link can request discovery but cannot invalidate a
    /// route. Dropping the returned receiver before execution cancels the
    /// operation. Callers must bound their own reply wait and retain ownership
    /// across queue backpressure; this method never blocks a runtime thread.
    pub fn try_recover(
        &self,
        destination_hash: [u8; 16],
        failed_link: Option<[u8; 16]>,
    ) -> Result<oneshot::Receiver<PathRecoveryOutcome>, PathRecoveryError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.tx
            .try_send(PathRecoveryRequest {
                destination_hash,
                failed_link,
                result_tx,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => PathRecoveryError::Full,
                mpsc::error::TrySendError::Closed(_) => PathRecoveryError::Closed,
            })?;
        Ok(result_rx)
    }
}
