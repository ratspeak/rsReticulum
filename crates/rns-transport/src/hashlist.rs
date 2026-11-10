use std::collections::HashSet;

use crate::constants::HASHLIST_MAXSIZE;

/// Two-generation hash set used for packet deduplication.
///
/// The owner calls [`Self::rotate_if_full`] from its periodic job; it moves
/// `current` into `previous` once `current` holds more than `max_size / 2`
/// entries. The window is count-based, with no time expiry, and lookups check
/// both generations. [`Self::load_from`] does not enforce the bound.
#[derive(Clone)]
pub struct PacketHashlist {
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
    max_size: usize,
}

impl PacketHashlist {
    pub fn new() -> Self {
        Self::new_with_capacity(HASHLIST_MAXSIZE)
    }

    /// Set the rotation threshold to `max_size / 2`, without preallocating.
    /// Use at least two for the normal capacity bound; zero does not disable
    /// storage. Restored snapshots are not limited by this setting.
    pub fn new_with_capacity(max_size: usize) -> Self {
        Self {
            current: HashSet::new(),
            previous: HashSet::new(),
            max_size,
        }
    }

    /// Check if a packet hash has been seen (checks both generations).
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.current.contains(hash) || self.previous.contains(hash)
    }

    /// Insert a hash. Returns false if already present (duplicate).
    pub fn insert(&mut self, hash: [u8; 32]) -> bool {
        if self.contains(&hash) {
            return false;
        }
        self.current.insert(hash);
        true
    }

    /// Rotate generations when `current` holds more than `max_size / 2`
    /// entries. Returns whether a rotation happened.
    pub fn rotate_if_full(&mut self) -> bool {
        if self.current.len() > self.max_size / 2 {
            self.force_rotate();
            return true;
        }
        false
    }

    /// Forget a hash from both generations.
    pub fn remove(&mut self, hash: &[u8; 32]) {
        self.current.remove(hash);
        self.previous.remove(hash);
    }

    /// Discard the old previous generation, move current to previous and
    /// begin an empty current generation.
    pub fn force_rotate(&mut self) {
        self.previous = std::mem::take(&mut self.current);
    }

    pub fn len(&self) -> usize {
        self.current.len() + self.previous.len()
    }

    pub fn is_empty(&self) -> bool {
        self.current.is_empty() && self.previous.is_empty()
    }

    pub fn clear(&mut self) {
        self.current.clear();
        self.previous.clear();
    }

    /// Snapshot the current generation in unspecified order for persistence.
    ///
    /// The previous generation is deliberately transient. Persisting both
    /// generations would continually carry already-aged hashes across
    /// restarts instead of letting the normal rotation window expire them.
    pub fn current_hashes(&self) -> Vec<[u8; 32]> {
        self.current.iter().copied().collect()
    }

    /// Snapshot both in-memory generations in unspecified order.
    ///
    /// Use [`Self::current_hashes`] for persistence so the aged previous
    /// generation remains transient across restarts.
    pub fn all_hashes(&self) -> Vec<[u8; 32]> {
        self.current
            .iter()
            .chain(self.previous.iter())
            .copied()
            .collect()
    }

    /// Replace current with the distinct supplied hashes and clear previous.
    /// The restored hashes are included by [`Self::current_hashes`]. This
    /// method does not enforce `max_size`; bound untrusted snapshots before
    /// loading them. A later new insertion can rotate an oversized current
    /// generation into previous, where it remains until another rotation.
    pub fn load_from(&mut self, hashes: Vec<[u8; 32]>) {
        self.current = hashes.into_iter().collect();
        self.previous.clear();
    }
}

impl Default for PacketHashlist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_contains() {
        let mut hl = PacketHashlist::new();
        let hash = [0xAA; 32];
        assert!(!hl.contains(&hash));
        assert!(hl.insert(hash));
        assert!(hl.contains(&hash));
        assert!(!hl.insert(hash));
    }

    #[test]
    fn rotation_happens_only_above_half_capacity() {
        let mut hl = PacketHashlist::new_with_capacity(10);
        for i in 0..5 {
            hl.insert([i; 32]);
        }
        assert!(!hl.rotate_if_full());
        hl.insert([5; 32]);
        assert_eq!(hl.current.len(), 6);
        assert!(hl.rotate_if_full());
        assert_eq!((hl.previous.len(), hl.current.len()), (6, 0));
        assert!(hl.contains(&[0; 32]));
    }

    #[test]
    fn remove_forgets_both_generations() {
        let mut hl = PacketHashlist::new_with_capacity(10);
        hl.insert([1; 32]);
        hl.force_rotate();
        hl.insert([2; 32]);
        hl.remove(&[1; 32]);
        hl.remove(&[2; 32]);
        assert!(hl.is_empty());
        assert!(hl.insert([1; 32]));
    }

    #[test]
    fn test_clear() {
        let mut hl = PacketHashlist::new();
        hl.insert([0x01; 32]);
        hl.insert([0x02; 32]);
        assert_eq!(hl.len(), 2);
        hl.clear();
        assert_eq!(hl.len(), 0);
    }

    #[test]
    fn persisted_snapshot_contains_only_current_generation() {
        let mut hl = PacketHashlist::new_with_capacity(4);
        hl.insert([0x01; 32]);
        hl.insert([0x02; 32]);
        hl.insert([0x04; 32]);
        assert!(hl.rotate_if_full());
        hl.remove(&[0x04; 32]);
        hl.insert([0x03; 32]);

        assert_eq!(hl.current_hashes(), vec![[0x03; 32]]);
        let all = hl.all_hashes();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&[0x01; 32]));
        assert!(all.contains(&[0x02; 32]));
        assert!(all.contains(&[0x03; 32]));
        assert_eq!(hl.len(), 3);
    }

    #[test]
    fn restored_hashes_populate_current_generation_and_deduplicate() {
        let mut hl = PacketHashlist::new_with_capacity(10);
        hl.insert([0x01; 32]);
        hl.force_rotate();

        hl.load_from(vec![[0xAA; 32], [0xAA; 32], [0xBB; 32]]);

        assert_eq!(hl.len(), 2);
        assert!(hl.current_hashes().contains(&[0xAA; 32]));
        assert!(hl.current_hashes().contains(&[0xBB; 32]));
        assert!(!hl.contains(&[0x01; 32]));
    }
}
