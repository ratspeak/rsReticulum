use std::collections::HashMap;

use crate::messages::InterfaceId;
use rns_wire::types::LinkId;

/// Transport-level state for one forwarded or terminated link.
#[derive(Debug, Clone)]
pub struct LinkEntry {
    /// Registration time (Unix seconds).
    pub timestamp: f64,
    /// Next-hop transport id for a routed link; `None` when this node is the endpoint.
    pub next_hop: Option<[u8; 16]>,
    pub interface_id: InterfaceId,
    pub remaining_hops: u8,
    pub destination_hash: [u8; 16],
    /// Handshake complete.
    pub established: bool,
    /// Proof received. Forwarding does not require this — unvalidated links
    /// still forward while `now < proof_timeout` so in-flight traffic is not
    /// stranded during the establishment window.
    pub validated: bool,
    pub proof_timeout: f64,
    /// Interface the initial link request arrived on.
    pub receiving_interface: InterfaceId,
    pub taken_hops: u8,
}

/// Metadata retained when an unvalidated link expires before proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiredLink {
    pub next_hop: Option<[u8; 16]>,
    pub interface_id: InterfaceId,
    pub remaining_hops: u8,
    pub destination_hash: [u8; 16],
    pub receiving_interface: InterfaceId,
    pub taken_hops: u8,
}

impl From<&LinkEntry> for ExpiredLink {
    fn from(entry: &LinkEntry) -> Self {
        Self {
            next_hop: entry.next_hop,
            interface_id: entry.interface_id,
            remaining_hops: entry.remaining_hops,
            destination_hash: entry.destination_hash,
            receiving_interface: entry.receiving_interface,
            taken_hops: entry.taken_hops,
        }
    }
}

/// Absolute deadline for transport bookkeeping that is waiting on a Link proof.
///
/// Retained compatibility helper for local endpoint bookkeeping. Locally owned
/// Link establishment is still governed by the endpoint state machine.
pub(crate) fn pending_link_proof_deadline(now: f64, remaining_hops: u8) -> f64 {
    now + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT * f64::from(remaining_hops.max(1))
}

/// Known rates are bounded below so no reported bitrate grants infinite
/// unvalidated state. Zero/unknown rates retain the existing per-hop base.
/// This is an MTU round-trip allowance, not an exact modem airtime prediction.
pub(crate) fn interface_round_trip_allowance(bitrate: Option<u64>) -> f64 {
    bitrate.filter(|rate| *rate > 0).map_or(0.0, |rate| {
        2.0 * (rns_wire::constants::MTU * 8) as f64 / rate.max(5) as f64
    })
}

/// A relay has received the request, but still has to serialize its outbound
/// request and receive the proof. Sample the local outbound medium once; queue
/// retries, unauthenticated traffic and later rate changes cannot renew it.
pub(crate) fn transit_link_proof_deadline(
    now: f64,
    remaining_hops: u8,
    bitrate: Option<u64>,
) -> f64 {
    pending_link_proof_deadline(now, remaining_hops) + interface_round_trip_allowance(bitrate)
}

/// Peer-created transit entries cannot grow the actor's table past this bound.
/// Privileged callers retain the existing explicit LinkTable::insert API.
pub(crate) const MAX_TRANSIT_LINK_TABLE_ENTRIES: usize = 4096;

pub struct LinkTable {
    entries: HashMap<LinkId, LinkEntry>,
}

impl LinkTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, link_id: impl Into<LinkId>, entry: LinkEntry) {
        self.entries.insert(link_id.into(), entry);
    }

    pub fn get(&self, link_id: &[u8; 16]) -> Option<&LinkEntry> {
        self.entries.get(link_id)
    }

    pub fn get_mut(&mut self, link_id: &[u8; 16]) -> Option<&mut LinkEntry> {
        self.entries.get_mut(link_id)
    }

    pub fn remove(&mut self, link_id: &[u8; 16]) -> Option<LinkEntry> {
        self.entries.remove(link_id)
    }

    pub fn contains(&self, link_id: &[u8; 16]) -> bool {
        self.entries.contains_key(link_id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&LinkId, &LinkEntry)> {
        self.entries.iter()
    }

    /// Cull stale links with two different clocks:
    /// - Validated links drop after `timeout` seconds of inactivity.
    /// - Unvalidated links drop once their own `proof_timeout` elapses, since
    ///   proof never arrived during the establishment window.
    ///
    /// Returns `(total_culled, expired_unvalidated_links)` — the caller can
    /// apply failed-link rediscovery rules using the retained route metadata.
    pub fn cull_stale(&mut self, timeout: f64) -> (usize, Vec<ExpiredLink>) {
        let now = crate::now_f64();
        let cutoff = now - timeout;

        let mut unvalidated_expired = Vec::new();

        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            if entry.validated {
                entry.timestamp > cutoff
            } else if now >= entry.proof_timeout || !entry.proof_timeout.is_finite() {
                unvalidated_expired.push(ExpiredLink::from(&*entry));
                false
            } else {
                true
            }
        });
        (before - self.entries.len(), unvalidated_expired)
    }

    /// Drop entries whose interfaces have gone away. Run with the current
    /// active-interface set during periodic maintenance.
    pub fn cull_dead_interfaces(
        &mut self,
        active_interfaces: &std::collections::HashSet<InterfaceId>,
    ) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            active_interfaces.contains(&entry.interface_id)
                && active_interfaces.contains(&entry.receiving_interface)
        });
        before - self.entries.len()
    }
}

impl Default for LinkTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_link_proof_deadline_uses_the_canonical_per_hop_window() {
        let now = 1_000.25;

        assert_eq!(pending_link_proof_deadline(now, 0), 1_006.25);
        assert_eq!(pending_link_proof_deadline(now, 1), 1_006.25);
        assert_eq!(pending_link_proof_deadline(now, 3), 1_018.25);
        assert_eq!(pending_link_proof_deadline(now, u8::MAX), 2_530.25);
    }

    #[test]
    fn transit_proof_deadline_has_finite_known_rate_and_hop_bounds() {
        let now = 1000.25;
        for rate in [None, Some(0)] {
            assert_eq!(transit_link_proof_deadline(now, 1, rate), now + 6.0);
        }
        for rate in [1, 5] {
            assert_eq!(
                transit_link_proof_deadline(now, 1, Some(rate)),
                now + 1606.0
            );
        }
        assert_eq!(
            transit_link_proof_deadline(now, u8::MAX, Some(1)),
            now + 3130.0
        );
        assert!(
            (transit_link_proof_deadline(now, 1, Some(61)) - now - (8000.0 / 61.0 + 6.0)).abs()
                < 1e-8
        );
        assert!(transit_link_proof_deadline(now, 1, Some(u64::MAX)).is_finite());
    }

    #[test]
    fn test_link_table_basic() {
        let mut table = LinkTable::new();
        let link_id = [0xAA; 16];
        table.insert(
            link_id,
            LinkEntry {
                timestamp: 1000.0,
                next_hop: None,
                interface_id: 1,
                remaining_hops: 0,
                destination_hash: [0xBB; 16],
                established: true,
                validated: true,
                proof_timeout: 0.0,
                receiving_interface: 1,
                taken_hops: 0,
            },
        );
        assert!(table.contains(&link_id));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_link_table_unvalidated_entry() {
        let mut table = LinkTable::new();
        let link_id = [0xCC; 16];
        let _dest_hash = [0xDD; 16];
        table.insert(
            link_id,
            LinkEntry {
                timestamp: 1000.0,
                next_hop: Some([0xDD; 16]),
                interface_id: 1,
                remaining_hops: 3,
                destination_hash: [0xEE; 16],
                established: false,
                validated: false,
                proof_timeout: 1060.0,
                receiving_interface: 2,
                taken_hops: 1,
            },
        );
        let entry = table.get(&link_id).unwrap();
        assert!(!entry.validated);
        assert_eq!(entry.proof_timeout, 1060.0);
    }

    #[test]
    fn test_link_table_unvalidated_cull() {
        let mut table = LinkTable::new();
        let link_id = [0xDD; 16];
        let dest_hash = [0xEE; 16];
        table.insert(
            link_id,
            LinkEntry {
                timestamp: 1000.0,
                next_hop: None,
                interface_id: 1,
                remaining_hops: 1,
                destination_hash: dest_hash,
                established: false,
                validated: false,
                proof_timeout: 500.0,
                receiving_interface: 2,
                taken_hops: 0,
            },
        );
        assert_eq!(table.len(), 1);

        let (culled, expired_dests) = table.cull_stale(900.0);
        assert_eq!(culled, 1);
        assert_eq!(expired_dests.len(), 1);
        assert_eq!(expired_dests[0].destination_hash, dest_hash);
        assert_eq!(expired_dests[0].receiving_interface, 2);
        assert_eq!(expired_dests[0].taken_hops, 0);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_link_table_cull_validated_vs_unvalidated() {
        let now = crate::now_f64();

        let mut table = LinkTable::new();

        table.insert(
            [0x01; 16],
            LinkEntry {
                timestamp: now,
                next_hop: None,
                interface_id: 1,
                remaining_hops: 1,
                destination_hash: [0xA1; 16],
                established: true,
                validated: true,
                proof_timeout: now + 100.0,
                receiving_interface: 2,
                taken_hops: 0,
            },
        );

        table.insert(
            [0x02; 16],
            LinkEntry {
                timestamp: 100.0,
                next_hop: None,
                interface_id: 1,
                remaining_hops: 1,
                destination_hash: [0xA2; 16],
                established: true,
                validated: true,
                proof_timeout: 200.0,
                receiving_interface: 2,
                taken_hops: 0,
            },
        );

        table.insert(
            [0x03; 16],
            LinkEntry {
                timestamp: now,
                next_hop: None,
                interface_id: 1,
                remaining_hops: 1,
                destination_hash: [0xA3; 16],
                established: false,
                validated: false,
                proof_timeout: now + 100.0,
                receiving_interface: 2,
                taken_hops: 0,
            },
        );

        table.insert(
            [0x04; 16],
            LinkEntry {
                timestamp: now,
                next_hop: None,
                interface_id: 1,
                remaining_hops: 1,
                destination_hash: [0xA4; 16],
                established: false,
                validated: false,
                proof_timeout: 500.0,
                receiving_interface: 2,
                taken_hops: 0,
            },
        );

        assert_eq!(table.len(), 4);
        let (culled, expired_dests) = table.cull_stale(900.0);
        assert_eq!(culled, 2);
        assert_eq!(table.len(), 2);
        assert_eq!(expired_dests.len(), 1);
        assert_eq!(expired_dests[0].destination_hash, [0xA4; 16]);
    }

    #[test]
    fn test_link_table_cull_dead_interfaces() {
        let mut table = LinkTable::new();
        let mut active = std::collections::HashSet::new();
        active.insert(1u64);
        active.insert(2u64);

        let now = crate::now_f64();

        table.insert(
            [0x01; 16],
            LinkEntry {
                timestamp: now,
                next_hop: None,
                interface_id: 1,
                remaining_hops: 1,
                destination_hash: [0xA1; 16],
                established: true,
                validated: true,
                proof_timeout: now + 100.0,
                receiving_interface: 2,
                taken_hops: 0,
            },
        );

        table.insert(
            [0x02; 16],
            LinkEntry {
                timestamp: now,
                next_hop: None,
                interface_id: 99,
                remaining_hops: 1,
                destination_hash: [0xA2; 16],
                established: true,
                validated: true,
                proof_timeout: now + 100.0,
                receiving_interface: 1,
                taken_hops: 0,
            },
        );

        assert_eq!(table.len(), 2);
        let culled = table.cull_dead_interfaces(&active);
        assert_eq!(culled, 1);
        assert_eq!(table.len(), 1);
        assert!(table.contains(&[0x01; 16]));
    }
}
