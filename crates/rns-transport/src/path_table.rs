use crate::now_f64;
use std::collections::{HashMap, VecDeque};

use crate::constants::{
    AP_PATH_TIME, DESTINATION_TIMEOUT, InterfaceMode, MAX_RANDOM_BLOBS, PERSIST_RANDOM_BLOBS,
    PathState, ROAMING_PATH_TIME,
};
use crate::messages::InterfaceId;
use rns_wire::types::DestHash;

/// One known path to a destination.
#[derive(Debug, Clone)]
pub struct PathEntry {
    /// Learn time (Unix seconds).
    pub timestamp: f64,
    /// Next-hop transport id; `None` for a directly-connected neighbour.
    pub next_hop: Option<[u8; 16]>,
    pub hops: u8,
    /// Expiry (Unix seconds), derived from interface mode at insert time.
    pub expires: f64,
    /// Recent announce-random blobs, capped at `MAX_RANDOM_BLOBS` to bound
    /// anti-replay memory on long-lived paths.
    pub random_blobs: VecDeque<[u8; 10]>,
    pub interface_id: InterfaceId,
    /// Hash of the cached announce packet — used to satisfy CacheRequest
    /// without holding the full packet bytes.
    pub packet_hash: Option<[u8; 32]>,
}

impl PathEntry {
    pub fn new(
        next_hop: Option<[u8; 16]>,
        hops: u8,
        interface_id: InterfaceId,
        interface_mode: InterfaceMode,
    ) -> Self {
        let now = now_f64();
        let expires = now + path_expiry(interface_mode) as f64;

        Self {
            timestamp: now,
            next_hop,
            hops,
            expires,
            random_blobs: VecDeque::new(),
            interface_id,
            packet_hash: None,
        }
    }

    pub fn add_random_blob(&mut self, blob: [u8; 10]) {
        if self.random_blobs.len() >= MAX_RANDOM_BLOBS {
            self.random_blobs.pop_front();
        }
        self.random_blobs.push_back(blob);
    }

    pub fn has_random_blob(&self, blob: &[u8; 10]) -> bool {
        self.random_blobs.contains(blob)
    }

    pub fn is_expired(&self) -> bool {
        now_f64() > self.expires
    }

    /// Mark an actively used route as live. Reticulum's Python path cull is
    /// timestamp based; Rust stores an explicit expiry, so both clocks must
    /// move together when traffic proves the route is still useful.
    pub fn touch(&mut self) {
        let now = now_f64();
        let lifetime = if self.expires > self.timestamp {
            self.expires - self.timestamp
        } else {
            path_expiry(InterfaceMode::Full) as f64
        };
        self.timestamp = now;
        self.expires = now + lifetime;
    }

    /// Most recent blobs to persist — older entries can be regenerated from
    /// the wire on replay, so we cap the snapshot at `PERSIST_RANDOM_BLOBS`
    /// to keep the on-disk table small.
    pub fn blobs_for_persist(&self) -> Vec<[u8; 10]> {
        let start = self.random_blobs.len().saturating_sub(PERSIST_RANDOM_BLOBS);
        self.random_blobs.iter().skip(start).copied().collect()
    }
}

/// Destination-hash → path mapping plus a parallel liveness state map so we
/// can probe unresponsive paths without rewriting the entries.
#[derive(Clone)]
pub struct PathTable {
    entries: HashMap<DestHash, PathEntry>,
    states: HashMap<DestHash, PathState>,
}

impl PathTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            states: HashMap::new(),
        }
    }

    /// Insert or replace a path entry. The parallel liveness state is
    /// cleared so a fresh/replacement entry never inherits a stale
    /// `Responsive`/`Unresponsive` reading from its predecessor. `get_state`
    /// reads a missing entry as `Unknown`, so clearing is equivalent to
    /// writing `Unknown` but avoids holding an entry we'd only overwrite.
    ///
    /// Python Reticulum 1.1.8 (`8c082b2`) fixes the same bug by clearing state
    /// at the inbound insert sites. The Rust transport has additional insert
    /// sites (announce install, PathResponse install, tunnel path restore, disk
    /// load), so the invariant is enforced here: state is never older than the
    /// entry it describes.
    pub fn insert(&mut self, dest_hash: impl Into<DestHash>, entry: PathEntry) {
        let hash: DestHash = dest_hash.into();
        self.states.remove(&hash);
        self.entries.insert(hash, entry);
    }

    pub fn get(&self, dest_hash: &[u8; 16]) -> Option<&PathEntry> {
        self.entries.get(dest_hash)
    }

    pub fn get_mut(&mut self, dest_hash: &[u8; 16]) -> Option<&mut PathEntry> {
        self.entries.get_mut(dest_hash)
    }

    pub fn get_live(&self, dest_hash: &[u8; 16]) -> Option<&PathEntry> {
        self.entries.get(dest_hash).filter(|e| !e.is_expired())
    }

    pub fn get_live_mut(&mut self, dest_hash: &[u8; 16]) -> Option<&mut PathEntry> {
        self.entries.get_mut(dest_hash).filter(|e| !e.is_expired())
    }

    /// A path exists and has not yet expired. Callers should prefer this
    /// over `get().is_some()` so stale entries are not treated as routable.
    pub fn has_path(&self, dest_hash: &[u8; 16]) -> bool {
        self.get_live(dest_hash).is_some()
    }

    pub fn hops_to(&self, dest_hash: &[u8; 16]) -> Option<u8> {
        self.get_live(dest_hash).map(|e| e.hops)
    }

    pub fn remove(&mut self, dest_hash: &[u8; 16]) -> Option<PathEntry> {
        self.states.remove(dest_hash);
        self.entries.remove(dest_hash)
    }

    /// Drop every path whose interface id matches — used when an interface
    /// goes down so we don't keep routing through a dead transport.
    pub fn drop_all_via(&mut self, interface_id: InterfaceId) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| e.interface_id != interface_id);
        before - self.entries.len()
    }

    pub fn drop_all_via_next_hop(&mut self, next_hop: &[u8; 16]) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| e.next_hop != Some(*next_hop));
        before - self.entries.len()
    }

    /// Force-expire a path and cull immediately. Useful when the caller
    /// already knows the path is bad (e.g. a link proof failed) and
    /// shouldn't wait for the periodic cull cycle.
    pub fn expire(&mut self, dest_hash: &[u8; 16]) -> bool {
        if let Some(entry) = self.entries.get_mut(dest_hash) {
            entry.expires = 0.0;
            self.cull_expired();
            true
        } else {
            false
        }
    }

    pub fn set_state(&mut self, dest_hash: impl Into<DestHash>, state: PathState) {
        self.states.insert(dest_hash.into(), state);
    }

    pub fn get_state(&self, dest_hash: &[u8; 16]) -> PathState {
        self.states
            .get(dest_hash)
            .copied()
            .unwrap_or(PathState::Unknown)
    }

    /// Full cull pass. Prefer `cull_expired_batch` on the hot path to bound
    /// per-tick work.
    pub fn cull_expired(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| !entry.is_expired());
        self.states
            .retain(|hash, _| self.entries.contains_key(hash));
        before - self.entries.len()
    }

    /// Batched cull — removes at most `limit` expired entries so the actor
    /// cannot stall on a very large path table.
    pub fn cull_expired_batch(&mut self, limit: usize) -> usize {
        let to_remove: Vec<DestHash> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .take(limit)
            .map(|(hash, _)| *hash)
            .collect();
        let count = to_remove.len();
        for hash in &to_remove {
            self.entries.remove(hash.as_bytes());
            self.states.remove(hash.as_bytes());
        }
        count
    }

    /// Drop paths whose interface id is no longer active.
    pub fn cull_dead_interfaces(
        &mut self,
        active_interfaces: &std::collections::HashSet<InterfaceId>,
    ) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| active_interfaces.contains(&entry.interface_id));
        self.states
            .retain(|hash, _| self.entries.contains_key(hash));
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&DestHash, &PathEntry)> {
        self.entries.iter()
    }

    pub fn iter_live(&self) -> impl Iterator<Item = (&DestHash, &PathEntry)> {
        self.entries.iter().filter(|(_, entry)| !entry.is_expired())
    }
}

impl Default for PathTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Path lifetime by interface mode — access points and roaming interfaces
/// hold paths for shorter windows because they're expected to churn faster
/// than gateway/boundary links.
fn path_expiry(mode: InterfaceMode) -> u64 {
    match mode {
        InterfaceMode::AccessPoint => AP_PATH_TIME,
        InterfaceMode::Roaming => ROAMING_PATH_TIME,
        _ => DESTINATION_TIMEOUT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_table_basic() {
        let mut table = PathTable::new();
        let hash = [0xAA; 16];
        let entry = PathEntry::new(Some([0xBB; 16]), 3, 1, InterfaceMode::Gateway);
        table.insert(hash, entry);

        assert!(table.has_path(&hash));
        assert_eq!(table.hops_to(&hash), Some(3));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn expired_entries_are_not_live_paths() {
        let mut table = PathTable::new();
        let hash = [0xA1; 16];
        let mut entry = PathEntry::new(None, 1, 1, InterfaceMode::Gateway);
        entry.expires = now_f64() - 1.0;
        table.insert(hash, entry);

        assert!(table.get(&hash).is_some());
        assert!(table.get_live(&hash).is_none());
        assert!(table.get_live_mut(&hash).is_none());
        assert!(!table.has_path(&hash));
        assert_eq!(table.hops_to(&hash), None);
        assert_eq!(table.iter().count(), 1);
        assert_eq!(table.iter_live().count(), 0);
    }

    #[test]
    fn touch_extends_explicit_expiry_with_original_lifetime() {
        let mut entry = PathEntry::new(None, 1, 1, InterfaceMode::Roaming);
        let lifetime = entry.expires - entry.timestamp;
        entry.timestamp -= 10.0;
        entry.expires -= 10.0;

        entry.touch();

        let new_lifetime = entry.expires - entry.timestamp;
        assert!((new_lifetime - lifetime).abs() < 0.001);
        assert!(entry.expires > now_f64());
    }

    #[test]
    fn test_path_table_remove() {
        let mut table = PathTable::new();
        let hash = [0xAA; 16];
        table.insert(hash, PathEntry::new(None, 0, 1, InterfaceMode::Gateway));
        assert!(table.has_path(&hash));
        table.remove(&hash);
        assert!(!table.has_path(&hash));
    }

    #[test]
    fn test_random_blob_dedup() {
        let mut entry = PathEntry::new(None, 0, 1, InterfaceMode::Gateway);
        let blob = [0x42; 10];
        assert!(!entry.has_random_blob(&blob));
        entry.add_random_blob(blob);
        assert!(entry.has_random_blob(&blob));
    }

    #[test]
    fn test_random_blob_max() {
        let mut entry = PathEntry::new(None, 0, 1, InterfaceMode::Gateway);
        for i in 0..MAX_RANDOM_BLOBS + 10 {
            let mut blob = [0u8; 10];
            blob[0] = i as u8;
            entry.add_random_blob(blob);
        }
        assert_eq!(entry.random_blobs.len(), MAX_RANDOM_BLOBS);
    }

    #[test]
    fn test_path_state() {
        let mut table = PathTable::new();
        let hash = [0xAA; 16];
        assert_eq!(table.get_state(&hash), PathState::Unknown);
        table.set_state(hash, PathState::Responsive);
        assert_eq!(table.get_state(&hash), PathState::Responsive);
    }

    /// Regression test for the Python 1.1.8 path-state race (`8c082b2`).
    /// A fresh or replacement `PathEntry` must never inherit a stale
    /// `Responsive`/`Unresponsive` reading from its predecessor, or
    /// probing won't resume after a reroute.
    #[test]
    fn test_insert_clears_path_state() {
        let mut table = PathTable::new();
        let hash = [0xAA; 16];
        table.insert(hash, PathEntry::new(None, 0, 1, InterfaceMode::Gateway));
        table.set_state(hash, PathState::Responsive);
        assert_eq!(table.get_state(&hash), PathState::Responsive);

        // Insert a replacement entry (e.g. a fresh announce through a new
        // next hop). Liveness state must reset to Unknown so the actor
        // probes before trusting the new path.
        table.insert(
            hash,
            PathEntry::new(Some([0xBB; 16]), 2, 2, InterfaceMode::Gateway),
        );
        assert_eq!(table.get_state(&hash), PathState::Unknown);
    }

    #[test]
    fn test_expire_force_cull() {
        let mut table = PathTable::new();
        let hash = [0xBB; 16];
        table.insert(hash, PathEntry::new(None, 0, 1, InterfaceMode::Gateway));
        assert!(table.has_path(&hash));

        let result = table.expire(&hash);
        assert!(result);
        assert!(!table.has_path(&hash));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_expire_nonexistent() {
        let mut table = PathTable::new();
        let result = table.expire(&[0xFF; 16]);
        assert!(!result);
    }

    #[test]
    fn test_cull_dead_interfaces() {
        let mut table = PathTable::new();
        let mut active = std::collections::HashSet::new();
        active.insert(1u64);
        active.insert(2u64);

        table.insert(
            [0xAA; 16],
            PathEntry::new(None, 0, 1, InterfaceMode::Gateway),
        );
        table.insert(
            [0xBB; 16],
            PathEntry::new(None, 1, 2, InterfaceMode::Gateway),
        );
        table.insert(
            [0xCC; 16],
            PathEntry::new(None, 2, 99, InterfaceMode::Gateway),
        );

        assert_eq!(table.len(), 3);
        let culled = table.cull_dead_interfaces(&active);
        assert_eq!(culled, 1);
        assert_eq!(table.len(), 2);
        assert!(table.has_path(&[0xAA; 16]));
        assert!(table.has_path(&[0xBB; 16]));
        assert!(!table.has_path(&[0xCC; 16]));
    }
}
