use std::collections::HashMap;

use crate::messages::InterfaceId;
use rns_wire::types::DestHash;

/// Rebroadcast state for a single announce.
#[derive(Debug, Clone)]
pub struct AnnounceEntry {
    /// Receive time (Unix seconds).
    pub timestamp: f64,
    /// Next retransmit time (Unix seconds).
    pub retransmit_timeout: f64,
    pub retries: u8,
    /// Transport ID or destination hash that delivered this announce to us.
    pub received_from: [u8; 16],
    /// Hop count as observed on receipt.
    pub hops: u8,
    /// Complete inner announce packet with the actor-adjusted hop count.
    /// Interface IFAC and framing are applied later on egress.
    pub packet_raw: Vec<u8>,
    /// Count of duplicate rebroadcasts heard from neighbours — used to suppress flooding.
    pub local_rebroadcasts: u32,
    pub block_rebroadcast: bool,
    /// Cached-response target when `block_rebroadcast` is true. Ordinary
    /// rebroadcasts use the actor's eligible-interface policy instead.
    pub attached_interface: Option<InterfaceId>,
    /// Receiving interface used by egress policy. Shared IPC peers are excluded
    /// from an echo; an eligible broadcast radio may relay on the same interface.
    pub source_interface: Option<InterfaceId>,
}

/// Destination-keyed rebroadcast records. Insertions replace matching entries;
/// this helper neither sends packets nor validates their contents. Retry updates,
/// interface selection and cleanup are performed by the caller.
pub struct AnnounceTable {
    entries: HashMap<DestHash, AnnounceEntry>,
}

impl AnnounceTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, dest_hash: impl Into<DestHash>, entry: AnnounceEntry) {
        self.entries.insert(dest_hash.into(), entry);
    }

    pub fn get(&self, dest_hash: &[u8; 16]) -> Option<&AnnounceEntry> {
        self.entries.get(dest_hash)
    }

    pub fn get_mut(&mut self, dest_hash: &[u8; 16]) -> Option<&mut AnnounceEntry> {
        self.entries.get_mut(dest_hash)
    }

    pub fn remove(&mut self, dest_hash: &[u8; 16]) -> Option<AnnounceEntry> {
        self.entries.remove(dest_hash)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return hashes with `now >= retransmit_timeout` that are unblocked or
    /// have an attached interface. This does not check retry exhaustion,
    /// interface eligibility or packet validity, and does not update records.
    pub fn due_for_retransmit(&self, now: f64) -> Vec<DestHash> {
        self.entries
            .iter()
            .filter(|(_, entry)| {
                (!entry.block_rebroadcast || entry.attached_interface.is_some())
                    && now >= entry.retransmit_timeout
            })
            .map(|(hash, _)| *hash)
            .collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&DestHash, &AnnounceEntry)> {
        self.entries.iter()
    }

    /// Remove entries whose retry count exceeds `max_retries`; returns the number dropped.
    pub fn cull_exhausted(&mut self, max_retries: u8) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.retries <= max_retries);
        before - self.entries.len()
    }
}

impl Default for AnnounceTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_announce_table_basic() {
        let mut table = AnnounceTable::new();
        let hash = [0xAA; 16];
        table.insert(
            hash,
            AnnounceEntry {
                timestamp: 1000.0,
                retransmit_timeout: 1005.0,
                retries: 0,
                received_from: [0xBB; 16],
                hops: 2,
                packet_raw: vec![0x01, 0x02],
                local_rebroadcasts: 0,
                block_rebroadcast: false,
                attached_interface: None,
                source_interface: None,
            },
        );
        assert_eq!(table.len(), 1);
        assert!(table.get(&hash).is_some());
    }

    #[test]
    fn test_due_for_retransmit() {
        let mut table = AnnounceTable::new();
        table.insert(
            [0x01; 16],
            AnnounceEntry {
                timestamp: 1000.0,
                retransmit_timeout: 1005.0,
                retries: 0,
                received_from: [0; 16],
                hops: 0,
                packet_raw: vec![],
                local_rebroadcasts: 0,
                block_rebroadcast: false,
                attached_interface: None,
                source_interface: None,
            },
        );
        table.insert(
            [0x02; 16],
            AnnounceEntry {
                timestamp: 1000.0,
                retransmit_timeout: 1010.0,
                retries: 0,
                received_from: [0; 16],
                hops: 0,
                packet_raw: vec![],
                local_rebroadcasts: 0,
                block_rebroadcast: false,
                attached_interface: None,
                source_interface: None,
            },
        );

        let due = table.due_for_retransmit(1006.0);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0], DestHash::from([0x01; 16]));
    }
}
