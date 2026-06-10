use std::collections::HashMap;

use crate::constants::REVERSE_TIMEOUT;
use crate::messages::InterfaceId;
use rns_wire::types::TruncatedHash;

/// Record of an in-flight packet so the matching proof can be routed back
/// along the same path. Entries expire after `REVERSE_TIMEOUT` — long enough
/// to tolerate slow links, short enough that stale routes don't accumulate.
#[derive(Debug, Clone)]
pub struct ReverseEntry {
    pub timestamp: f64,
    pub receiving_interface: InterfaceId,
    pub remaining_hops: u8,
    /// Interface we forwarded the packet on, when known. Proofs that come
    /// back on a different interface are rejected — the mismatch means
    /// either a routing change or a spoof attempt.
    pub outbound_interface: Option<InterfaceId>,
}

pub struct ReverseTable {
    entries: HashMap<TruncatedHash, ReverseEntry>,
}

impl ReverseTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        packet_hash: impl Into<TruncatedHash>,
        interface_id: InterfaceId,
        remaining_hops: u8,
    ) {
        self.insert_with_outbound(packet_hash, interface_id, remaining_hops, None);
    }

    /// Insert with explicit outbound-interface tracking. See `ReverseEntry`
    /// for why the outbound interface is pinned.
    pub fn insert_with_outbound(
        &mut self,
        packet_hash: impl Into<TruncatedHash>,
        interface_id: InterfaceId,
        remaining_hops: u8,
        outbound_interface: Option<InterfaceId>,
    ) {
        let now = crate::now_f64();

        self.entries.insert(
            packet_hash.into(),
            ReverseEntry {
                timestamp: now,
                receiving_interface: interface_id,
                remaining_hops,
                outbound_interface,
            },
        );
    }

    pub fn get(&self, packet_hash: &[u8; 16]) -> Option<&ReverseEntry> {
        self.entries.get(packet_hash)
    }

    pub fn remove(&mut self, packet_hash: &[u8; 16]) -> Option<ReverseEntry> {
        self.entries.remove(packet_hash)
    }

    pub fn cull_expired(&mut self) -> usize {
        let now = crate::now_f64();
        let cutoff = now - REVERSE_TIMEOUT as f64;

        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.timestamp > cutoff);
        before - self.entries.len()
    }

    /// Batched cull — bounds per-tick work on large tables.
    pub fn cull_expired_batch(&mut self, limit: usize) -> usize {
        let now = crate::now_f64();
        let cutoff = now - REVERSE_TIMEOUT as f64;

        let to_remove: Vec<TruncatedHash> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.timestamp <= cutoff)
            .take(limit)
            .map(|(hash, _)| *hash)
            .collect();
        let count = to_remove.len();
        for hash in &to_remove {
            self.entries.remove(hash.as_bytes());
        }
        count
    }

    /// Drop entries whose receiving or outbound interface has gone away —
    /// those proofs could never be routed back regardless.
    pub fn cull_dead_interfaces(
        &mut self,
        active_interfaces: &std::collections::HashSet<InterfaceId>,
    ) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            active_interfaces.contains(&entry.receiving_interface)
                && entry
                    .outbound_interface
                    .is_none_or(|id| active_interfaces.contains(&id))
        });
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ReverseTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_get() {
        let mut rt = ReverseTable::new();
        let hash = [0xAA; 16];
        rt.insert(hash, 42, 5);
        let entry = rt.get(&hash).unwrap();
        assert_eq!(entry.receiving_interface, 42);
        assert_eq!(entry.remaining_hops, 5);
        assert_eq!(entry.outbound_interface, None);
    }

    #[test]
    fn test_insert_with_outbound() {
        let mut rt = ReverseTable::new();
        let hash = [0xBB; 16];
        rt.insert_with_outbound(hash, 1, 3, Some(2));
        let entry = rt.get(&hash).unwrap();
        assert_eq!(entry.receiving_interface, 1);
        assert_eq!(entry.remaining_hops, 3);
        assert_eq!(entry.outbound_interface, Some(2));
    }

    #[test]
    fn test_remove() {
        let mut rt = ReverseTable::new();
        let hash = [0xAA; 16];
        rt.insert(hash, 1, 0);
        assert_eq!(rt.len(), 1);
        rt.remove(&hash);
        assert_eq!(rt.len(), 0);
    }

    #[test]
    fn test_cull_dead_interfaces() {
        let mut rt = ReverseTable::new();
        let mut active = std::collections::HashSet::new();
        active.insert(1u64);
        active.insert(2u64);

        rt.insert([0x01; 16], 1, 3);
        rt.insert_with_outbound([0x02; 16], 1, 3, Some(2));
        rt.insert([0x03; 16], 99, 3);
        rt.insert_with_outbound([0x04; 16], 1, 3, Some(99));

        assert_eq!(rt.len(), 4);
        let culled = rt.cull_dead_interfaces(&active);
        assert_eq!(culled, 2);
        assert_eq!(rt.len(), 2);
        assert!(rt.get(&[0x01; 16]).is_some());
        assert!(rt.get(&[0x02; 16]).is_some());
        assert!(rt.get(&[0x03; 16]).is_none());
        assert!(rt.get(&[0x04; 16]).is_none());
    }
}
