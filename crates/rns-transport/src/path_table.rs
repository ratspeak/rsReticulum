use crate::now_f64;
use std::collections::{HashMap, VecDeque};

use crate::constants::{
    AP_PATH_TIME, DESTINATION_TIMEOUT, InterfaceMode, MAX_RANDOM_BLOBS, PATH_POOL_UNUSED_TARGET,
    PATH_SLOW_BITRATE, PATH_SLOW_LINGER_FACTOR, PERSIST_RANDOM_BLOBS, PathState, ROAMING_PATH_TIME,
};
use crate::messages::InterfaceId;
use rns_wire::types::DestHash;

/// Stored route metadata for a destination. Fields are caller-writable; this
/// record alone does not establish a live interface or reachable peer.
#[derive(Debug, Clone)]
pub struct PathEntry {
    /// Learn time, or the last liveness proof (Unix seconds).
    pub timestamp: f64,
    /// Next-hop transport id; `None` for a directly-connected neighbour.
    pub next_hop: Option<[u8; 16]>,
    pub hops: u8,
    /// Expiry (Unix seconds). `new` derives it from the supplied interface mode.
    pub expires: f64,
    /// Recent announce-random blobs. Normal `add_random_blob` use from an empty
    /// deque retains at most `MAX_RANDOM_BLOBS`; direct field mutation can
    /// exceed that size. The helper does not authenticate or deduplicate blobs.
    pub random_blobs: VecDeque<[u8; 10]>,
    pub interface_id: InterfaceId,
    /// Hash used to locate a cached announce packet. The record does not own
    /// its bytes, and a corresponding cache file may be unavailable.
    pub packet_hash: Option<[u8; 32]>,
    /// Last use of this path (Unix seconds); 0 when never used.
    pub used: f64,
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
            used: 0.0,
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

    /// Record traffic over this path without renewing its lifetime.
    pub fn mark_used(&mut self) {
        self.used = now_f64();
    }

    /// Return at most the last `PERSIST_RANDOM_BLOBS` entries, preserving their
    /// deque order, for a bounded persistence snapshot. Older blobs are omitted.
    pub fn blobs_for_persist(&self) -> Vec<[u8; 10]> {
        let start = self.random_blobs.len().saturating_sub(PERSIST_RANDOM_BLOBS);
        self.random_blobs.iter().skip(start).copied().collect()
    }
}

/// Destination-keyed routes and separately stored path-state labels. Ordinary
/// lookup/iteration includes expired entries; `get_live`/`iter_live` checks
/// expiry only, not interface health or reachability. State labels are supplied
/// by callers and can exist without a route. This table does not probe peers.
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

    /// Insert or replace a route without validating its fields, and remove the
    /// old state label so `get_state` returns `Unknown`. Mutation through
    /// `get_mut` does not perform this reset.
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
    /// over `get().is_some()` to exclude expired entries. This does not confirm
    /// that the recorded interface or remote destination is currently reachable.
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

    /// Remove every route whose interface ID matches. Associated state labels
    /// remain until separately removed, replaced or cleaned by a full cull.
    pub fn drop_all_via(&mut self, interface_id: InterfaceId) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| e.interface_id != interface_id);
        before - self.entries.len()
    }

    /// Remove routes through this next hop, leaving their state labels intact.
    pub fn drop_all_via_next_hop(&mut self, next_hop: &[u8; 16]) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| e.next_hop != Some(*next_hop));
        before - self.entries.len()
    }

    /// Set a present route's expiry to zero, then run a full expired-route cull
    /// across the table. Return whether the target entry existed before the
    /// operation. The cull uses the current wall clock and can remove other
    /// expired entries too.
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

    /// Scan all routes, remove expired entries and remove every state label
    /// without a remaining route. Return the number of routes removed.
    pub fn cull_expired(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| !entry.is_expired());
        self.states
            .retain(|hash, _| self.entries.contains_key(hash));
        before - self.entries.len()
    }

    /// Remove at most `limit` expired routes and their state labels. The limit
    /// bounds removals, not scanning time: finding those entries can examine
    /// the entire table. Unrelated orphan state labels are not cleaned here.
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

    /// Python `mark_path_responsive` (Transport.py): only a
    /// cryptographic liveness proof renews a path. `mode` is the mode of the
    /// interface the path was learned on. Returns whether a path existed.
    pub fn mark_responsive(&mut self, dest_hash: &[u8; 16], mode: InterfaceMode) -> bool {
        let Some(entry) = self.entries.get_mut(dest_hash) else {
            return false;
        };
        let now = now_f64();
        entry.timestamp = now;
        entry.expires = now + path_expiry(mode) as f64;
        entry.used = now;
        self.states
            .insert((*dest_hash).into(), PathState::Responsive);
        true
    }

    /// Python's path-table cull (Transport.py): drop expired
    /// paths, paths on a missing interface and never-used paths older than
    /// `linger` (x10 on slow interfaces). With `check_unused`, never-used
    /// paths beyond `PATH_POOL_UNUSED_TARGET` are dropped too, fast-interface
    /// and earliest-expiring first. Returns the removed count and, with
    /// `check_unused`, the never-used count before removal.
    pub fn cull(
        &mut self,
        now: f64,
        linger: f64,
        check_unused: bool,
        bitrate_of: impl Fn(InterfaceId) -> Option<u64>,
    ) -> (usize, Option<usize>) {
        let mut stale: Vec<DestHash> = Vec::new();
        let mut unused: Vec<(u8, f64, DestHash)> = Vec::new();
        for (hash, entry) in &self.entries {
            let bitrate = bitrate_of(entry.interface_id);
            let slow = bitrate.is_some_and(|b| b > 0 && b < PATH_SLOW_BITRATE);
            if check_unused && entry.used == 0.0 {
                unused.push((u8::from(slow), entry.expires, *hash));
            }
            let factor = if slow { PATH_SLOW_LINGER_FACTOR } else { 1.0 };
            if now > entry.expires
                || bitrate.is_none()
                || (entry.used == 0.0 && now > entry.timestamp + linger * factor)
            {
                stale.push(*hash);
            }
        }
        let unused_count = check_unused.then_some(unused.len());
        if unused.len() > PATH_POOL_UNUSED_TARGET {
            let cull_count = unused.len() - PATH_POOL_UNUSED_TARGET;
            unused.sort_by(|a, b| {
                a.0.cmp(&b.0)
                    .then(a.1.total_cmp(&b.1))
                    .then(a.2.as_bytes().cmp(b.2.as_bytes()))
            });
            stale.extend(unused.into_iter().take(cull_count).map(|(_, _, hash)| hash));
        }
        let mut removed = 0;
        for hash in &stale {
            if self.entries.remove(hash.as_bytes()).is_some() {
                removed += 1;
            }
            self.states.remove(hash.as_bytes());
        }
        (removed, unused_count)
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
    fn use_leaves_lifetime_and_liveness_proof_renews_it() {
        let mut table = PathTable::new();
        let hash = [0xA2; 16];
        let mut entry = PathEntry::new(None, 1, 1, InterfaceMode::Full);
        entry.timestamp -= 10.0;
        entry.expires -= 10.0;
        let (timestamp, expires) = (entry.timestamp, entry.expires);
        entry.mark_used();
        assert_eq!((entry.timestamp, entry.expires), (timestamp, expires));
        assert!(entry.used > timestamp);
        table.insert(hash, entry);

        assert!(table.mark_responsive(&hash, InterfaceMode::Roaming));
        let entry = table.get(&hash).unwrap();
        assert_eq!(entry.expires - entry.timestamp, ROAMING_PATH_TIME as f64);
        assert_eq!(entry.used, entry.timestamp);
        assert_eq!(table.get_state(&hash), PathState::Responsive);
        assert!(!table.mark_responsive(&[0xA3; 16], InterfaceMode::Full));
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
