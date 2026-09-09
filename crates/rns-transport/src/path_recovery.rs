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
    pub failed_attempt: Option<FailedRouteAttempt>,
    pub schedule_discovery: bool,
    pub result_tx: oneshot::Sender<PathRecoveryOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FailedRouteAttempt {
    Link([u8; 16]),
    Packet([u8; 32]),
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
        self.try_recover_attempt(
            destination_hash,
            failed_link.map(FailedRouteAttempt::Link),
            true,
        )
    }

    /// Recover only the unchanged route used by an atomically tracked local
    /// `SendPacket` dispatch. An unobserved packet cannot invalidate a route.
    pub fn try_recover_packet(
        &self,
        destination_hash: [u8; 16],
        packet_hash: [u8; 32],
    ) -> Result<oneshot::Receiver<PathRecoveryOutcome>, PathRecoveryError> {
        self.try_recover_attempt(
            destination_hash,
            Some(FailedRouteAttempt::Packet(packet_hash)),
            true,
        )
    }

    /// Invalidate only the unchanged local route used by a tracked packet,
    /// without scheduling discovery. Unknown, consumed, cancelled or replaced
    /// attempts cannot invalidate a route. The returned `path_dropped` flag is
    /// evidence of this local comparison, not permission or an atomic guarantee
    /// for another process' route table.
    ///
    /// Shared-client coordinators can use this before an authenticated owner
    /// reset, then call [`Self::try_recover`] with no failed Link to discover.
    /// Separating these steps avoids querying a stale owner cache before its
    /// reset. Callers must bound the intervening work and handle reset failure;
    /// this method neither contacts the owner nor implicitly retries discovery.
    pub fn try_invalidate_packet(
        &self,
        destination_hash: [u8; 16],
        packet_hash: [u8; 32],
    ) -> Result<oneshot::Receiver<PathRecoveryOutcome>, PathRecoveryError> {
        self.try_recover_attempt(
            destination_hash,
            Some(FailedRouteAttempt::Packet(packet_hash)),
            false,
        )
    }

    /// Invalidate only the unchanged local route used by an observed local
    /// LinkRequest, without scheduling discovery. This is the Link analogue
    /// of [`Self::try_invalidate_packet`]; it neither contacts a shared owner
    /// nor authorizes an unobserved, consumed or replaced attempt to drop a
    /// route. A shared coordinator can reset its authenticated external owner
    /// only after a positive local comparison, then discover normally.
    pub fn try_invalidate_link(
        &self,
        destination_hash: [u8; 16],
        link_id: [u8; 16],
    ) -> Result<oneshot::Receiver<PathRecoveryOutcome>, PathRecoveryError> {
        self.try_recover_attempt(
            destination_hash,
            Some(FailedRouteAttempt::Link(link_id)),
            false,
        )
    }

    fn try_recover_attempt(
        &self,
        destination_hash: [u8; 16],
        failed_attempt: Option<FailedRouteAttempt>,
        schedule_discovery: bool,
    ) -> Result<oneshot::Receiver<PathRecoveryOutcome>, PathRecoveryError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.tx
            .try_send(PathRecoveryRequest {
                destination_hash,
                failed_attempt,
                schedule_discovery,
                result_tx,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => PathRecoveryError::Full,
                mpsc::error::TrySendError::Closed(_) => PathRecoveryError::Closed,
            })?;
        Ok(result_rx)
    }
}
