//! Durable control-plane state for ratcheted announces.
//!
//! The signed Python-compatible ratchet ring contains only private keys. This
//! sidecar deliberately keeps local policy metadata separate: the last wall
//! time used for rotation and the last 40-bit value emitted on the wire.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::announce::ANNOUNCE_TIME_MAX;
use crate::identity::Identity;
use crate::persistence;

const CONTROL_STATE_VERSION: u8 = 1;
const CONTROL_STATE_MAX_BYTES: usize = 4096;

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

/// Signed, identity- and destination-bound state used to plan a ratcheted
/// announce without mutating live state before persistence succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetControlState {
    identity_hash: [u8; 16],
    destination_hash: [u8; 16],
    last_rotation_wall: Option<u64>,
    last_announce_wire: Option<u64>,
}

impl RatchetControlState {
    pub fn new(identity_hash: [u8; 16], destination_hash: [u8; 16]) -> Self {
        Self {
            identity_hash,
            destination_hash,
            last_rotation_wall: None,
            last_announce_wire: None,
        }
    }

    pub fn identity_hash(&self) -> [u8; 16] {
        self.identity_hash
    }

    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination_hash
    }

    pub fn last_rotation_wall(&self) -> Option<u64> {
        self.last_rotation_wall
    }

    pub fn last_announce_wire(&self) -> Option<u64> {
        self.last_announce_wire
    }

    /// Anchor unknown rotation age at the current wall time. Existing age is
    /// never overwritten by this operation.
    pub fn anchor_rotation_if_unknown(&mut self, wall_now: u64) {
        if self.last_rotation_wall.is_none() {
            self.last_rotation_wall = Some(wall_now);
        }
    }

    /// Rotation is due only when a persisted age exists and the wall clock has
    /// advanced by the full interval. Clock rollback never looks elapsed.
    pub fn rotation_due(&self, wall_now: u64, interval_secs: u64) -> bool {
        self.last_rotation_wall
            .is_some_and(|last| wall_now >= last && wall_now.saturating_sub(last) >= interval_secs)
    }

    /// Return a cloned candidate recording a successful rotation.
    pub fn with_rotation_at(&self, wall_now: u64) -> Self {
        let mut candidate = self.clone();
        candidate.last_rotation_wall = Some(wall_now);
        candidate
    }

    /// Prepare the next wire-ordering value without mutating this live state.
    ///
    /// `None` means wall time has not advanced beyond the last durable value;
    /// callers must coalesce/defer instead of inventing `last + 1`, which could
    /// make an announce appear to come from the future.
    pub fn prepare_announce(&self, wall_now: u64) -> std::io::Result<Option<Self>> {
        if wall_now > ANNOUNCE_TIME_MAX {
            return Err(invalid_data(format!(
                "wall time {wall_now} exceeds 40-bit announce field"
            )));
        }
        if self.last_announce_wire.is_some_and(|last| wall_now <= last) {
            return Ok(None);
        }

        let mut candidate = self.clone();
        candidate.last_announce_wire = Some(wall_now);
        Ok(Some(candidate))
    }

    /// Persist this state as a signed, bounded MessagePack envelope.
    pub fn save_verified(&self, path: &Path, identity: &Identity) -> std::io::Result<()> {
        if identity.hash != self.identity_hash {
            return Err(invalid_data("control state identity binding mismatch"));
        }
        self.validate()?;

        let body = ControlStateBody {
            version: CONTROL_STATE_VERSION,
            identity_hash: self.identity_hash.to_vec(),
            destination_hash: self.destination_hash.to_vec(),
            last_rotation_wall: self.last_rotation_wall,
            last_announce_wire: self.last_announce_wire,
        };
        let packed = Zeroizing::new(
            rmp_serde::to_vec_named(&body).map_err(|e| std::io::Error::other(e.to_string()))?,
        );
        let signature = identity.sign(&packed).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "identity cannot sign ratchet control state",
            )
        })?;
        let envelope = ControlStateEnvelope {
            signature: signature.to_vec(),
            state: packed.to_vec(),
        };
        let encoded = Zeroizing::new(
            rmp_serde::to_vec_named(&envelope).map_err(|e| std::io::Error::other(e.to_string()))?,
        );
        if encoded.len() > CONTROL_STATE_MAX_BYTES {
            return Err(invalid_data("ratchet control state exceeds size limit"));
        }
        persistence::atomic_write(path, &encoded)
    }

    /// Load and verify state for exactly `identity` and `destination_hash`.
    pub fn load_verified(
        path: &Path,
        identity: &Identity,
        destination_hash: [u8; 16],
    ) -> std::io::Result<Self> {
        let encoded = Zeroizing::new(
            persistence::read_file_bounded(path, CONTROL_STATE_MAX_BYTES)?
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?,
        );
        let envelope: ControlStateEnvelope =
            rmp_serde::from_slice(&encoded).map_err(|e| std::io::Error::other(e.to_string()))?;
        if envelope.signature.len() != 64 {
            return Err(invalid_data("invalid control-state signature length"));
        }
        let signature: [u8; 64] = envelope
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| invalid_data("invalid control-state signature length"))?;
        let packed = Zeroizing::new(envelope.state);
        if !identity.verify(&packed, &signature) {
            return Err(invalid_data("invalid ratchet control-state signature"));
        }

        let body: ControlStateBody =
            rmp_serde::from_slice(&packed).map_err(|e| std::io::Error::other(e.to_string()))?;
        if body.version != CONTROL_STATE_VERSION {
            return Err(invalid_data(format!(
                "unsupported ratchet control-state version {}",
                body.version
            )));
        }
        let identity_hash: [u8; 16] = body
            .identity_hash
            .as_slice()
            .try_into()
            .map_err(|_| invalid_data("invalid control-state identity hash"))?;
        let stored_destination: [u8; 16] = body
            .destination_hash
            .as_slice()
            .try_into()
            .map_err(|_| invalid_data("invalid control-state destination hash"))?;
        if identity_hash != identity.hash {
            return Err(invalid_data("control state belongs to another identity"));
        }
        if stored_destination != destination_hash {
            return Err(invalid_data("control state belongs to another destination"));
        }

        let state = Self {
            identity_hash,
            destination_hash: stored_destination,
            last_rotation_wall: body.last_rotation_wall,
            last_announce_wire: body.last_announce_wire,
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> std::io::Result<()> {
        if self
            .last_announce_wire
            .is_some_and(|value| value > ANNOUNCE_TIME_MAX)
        {
            return Err(invalid_data("stored announce time exceeds 40-bit field"));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct ControlStateBody {
    version: u8,
    #[serde(with = "serde_bytes")]
    identity_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    destination_hash: Vec<u8>,
    last_rotation_wall: Option<u64>,
    last_announce_wire: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct ControlStateEnvelope {
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    state: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announce_time_never_moves_into_the_future() {
        let identity = Identity::new();
        let destination = [0x22; 16];
        let state = RatchetControlState::new(identity.hash, destination);
        let state = state.prepare_announce(100).unwrap().unwrap();
        assert_eq!(state.last_announce_wire(), Some(100));
        assert!(state.prepare_announce(100).unwrap().is_none());
        assert!(state.prepare_announce(99).unwrap().is_none());
        let next = state.prepare_announce(101).unwrap().unwrap();
        assert_eq!(next.last_announce_wire(), Some(101));
    }

    #[test]
    fn unknown_rotation_age_is_anchored_without_immediate_rotation() {
        let identity = Identity::new();
        let mut state = RatchetControlState::new(identity.hash, [0x33; 16]);
        assert!(!state.rotation_due(100, 30));
        state.anchor_rotation_if_unknown(100);
        assert!(!state.rotation_due(100, 30));
        assert!(!state.rotation_due(99, 30));
        assert!(!state.rotation_due(129, 30));
        assert!(state.rotation_due(130, 30));
    }

    #[test]
    fn signed_state_roundtrip_enforces_identity_and_destination_binding() {
        let dir = std::env::temp_dir().join("reticulum_ratchet_control_state");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control");
        let identity = Identity::new();
        let wrong_identity = Identity::new();
        let destination = [0x44; 16];
        let mut state = RatchetControlState::new(identity.hash, destination);
        state.anchor_rotation_if_unknown(100);
        let state = state.prepare_announce(101).unwrap().unwrap();
        state.save_verified(&path, &identity).unwrap();

        assert_eq!(
            RatchetControlState::load_verified(&path, &identity, destination).unwrap(),
            state
        );
        assert!(RatchetControlState::load_verified(&path, &wrong_identity, destination).is_err());
        assert!(RatchetControlState::load_verified(&path, &identity, [0x55; 16]).is_err());
        assert!(
            path.exists(),
            "rejected state remains available for recovery"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_candidate_persistence_cannot_mutate_live_state() {
        let identity = Identity::new();
        let destination = [0x66; 16];
        let live = RatchetControlState::new(identity.hash, destination);
        let candidate = live.prepare_announce(100).unwrap().unwrap();
        let missing_parent = std::env::temp_dir()
            .join("reticulum_missing_control_parent")
            .join("nested")
            .join("state");
        let _ = std::fs::remove_dir_all(
            missing_parent
                .parent()
                .and_then(Path::parent)
                .unwrap_or_else(|| Path::new("/tmp")),
        );

        assert!(candidate.save_verified(&missing_parent, &identity).is_err());
        assert_eq!(live.last_announce_wire(), None);
    }
}
