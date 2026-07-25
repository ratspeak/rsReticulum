use std::collections::HashSet;

use crate::constants::HASHLIST_MAXSIZE;

/// Two-generation rotating hash set used for packet deduplication.
///
/// When the `current` set fills to `max_size / 2`, it is promoted to
/// `previous` and a new empty `current` begins — giving a bounded, amortised
/// O(1) membership structure with a window of up to `max_size` entries.
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

    /// Build a hashlist with a custom `max_size`, useful when the default
    /// capacity would dominate memory (e.g. in benchmarks).
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

        if self.current.len() >= self.max_size / 2 {
            self.force_rotate();
        }

        self.current.insert(hash);
        true
    }

    /// Rotate: current becomes previous, new empty set becomes current.
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

    /// Snapshot the current generation for persistence.
    ///
    /// The previous generation is deliberately transient. Persisting both
    /// generations would continually carry already-aged hashes across
    /// restarts instead of letting the normal rotation window expire them.
    pub fn current_hashes(&self) -> Vec<[u8; 32]> {
        self.current.iter().copied().collect()
    }

    /// Snapshot both in-memory generations.
    ///
    /// This preserves the pre-1.4 public inspection API. Persistence must use
    /// [`Self::current_hashes`] so the aged previous generation remains
    /// transient.
    pub fn all_hashes(&self) -> Vec<[u8; 32]> {
        self.current
            .iter()
            .chain(self.previous.iter())
            .copied()
            .collect()
    }

    /// Rehydrate the current generation from a persisted snapshot.
    ///
    /// This mirrors Reticulum's canonical `packet_hashlist.raw` lifecycle:
    /// the restored generation remains the one written at the next
    /// persistence boundary, while the previous generation stays ephemeral.
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
    fn test_rotation() {
        let mut hl = PacketHashlist {
            current: HashSet::new(),
            previous: HashSet::new(),
            max_size: 10,
        };

        // Rotation triggers at current.len() >= max_size/2, so the 6th insert
        // promotes the first five into `previous` and lands alone in `current`.
        for i in 0..6 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            hl.insert(hash);
        }

        assert_eq!(hl.previous.len(), 5);
        assert_eq!(hl.current.len(), 1);

        let mut old_hash = [0u8; 32];
        old_hash[0] = 0;
        assert!(hl.contains(&old_hash));
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
        // The third insertion rotates the first two hashes into `previous`.
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
