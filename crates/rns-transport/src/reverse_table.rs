use std::collections::HashMap;

use crate::constants::REVERSE_TIMEOUT;
use crate::messages::InterfaceId;
use rns_wire::types::TruncatedHash;

/// Record of an in-flight packet so the matching proof can be routed back
/// along the recorded path. Explicit culling removes entries at least
/// `REVERSE_TIMEOUT` seconds old; lookup alone does not enforce that lifetime.
#[derive(Debug, Clone)]
pub struct ReverseEntry {
    pub timestamp: f64,
    pub receiving_interface: InterfaceId,
    /// Interface we forwarded the packet on, when known. Proofs that come
    /// back on a different interface are not forwarded by the actor. This
    /// routing check is separate from cryptographic proof validation.
    pub outbound_interface: Option<InterfaceId>,
}

/// Packet-hash keyed reverse routes. Insertions replace matching entries;
/// lookup includes expired records until explicit culling. The table itself
/// neither validates proofs nor limits the number of entries.
pub struct ReverseTable {
    entries: HashMap<TruncatedHash, ReverseEntry>,
}

impl ReverseTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// See `ReverseEntry` for why the outbound interface is pinned.
    pub fn insert(
        &mut self,
        packet_hash: impl Into<TruncatedHash>,
        interface_id: InterfaceId,
        outbound_interface: Option<InterfaceId>,
    ) {
        let now = crate::now_f64();

        self.entries.insert(
            packet_hash.into(),
            ReverseEntry {
                timestamp: now,
                receiving_interface: interface_id,
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

    /// Remove entries whose receiving interface or specified outbound
    /// interface is absent from the caller-supplied active set.
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

    #[cfg(test)]
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
        rt.insert(hash, 42, None);
        let entry = rt.get(&hash).unwrap();
        assert_eq!(entry.receiving_interface, 42);
        assert_eq!(entry.outbound_interface, None);
    }

    #[test]
    fn test_insert_pins_the_outbound_interface() {
        let mut rt = ReverseTable::new();
        let hash = [0xBB; 16];
        rt.insert(hash, 1, Some(2));
        let entry = rt.get(&hash).unwrap();
        assert_eq!(entry.receiving_interface, 1);
        assert_eq!(entry.outbound_interface, Some(2));
    }

    #[test]
    fn test_remove() {
        let mut rt = ReverseTable::new();
        let hash = [0xAA; 16];
        rt.insert(hash, 1, None);
        assert_eq!(rt.len(), 1);
        rt.remove(&hash);
        assert_eq!(rt.len(), 0);
    }

    /// Transport.py 1.6.1: three minutes, down from eight.
    #[test]
    fn entries_expire_after_three_minutes() {
        let start = 1_000_000.0;
        let clock = crate::test_clock::Clock::at(start);
        let mut rt = ReverseTable::new();
        rt.insert([0x01; 16], 1, None);
        clock.set(start + 179.0);
        assert_eq!(rt.cull_expired(), 0);
        clock.set(start + 181.0);
        assert_eq!(rt.cull_expired(), 1);
    }

    #[test]
    fn test_cull_dead_interfaces() {
        let mut rt = ReverseTable::new();
        let mut active = std::collections::HashSet::new();
        active.insert(1u64);
        active.insert(2u64);

        rt.insert([0x01; 16], 1, None);
        rt.insert([0x02; 16], 1, Some(2));
        rt.insert([0x03; 16], 99, None);
        rt.insert([0x04; 16], 1, Some(99));

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
