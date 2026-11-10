//! Destination-type announce filtering, Python `Transport` `blocked_destination_types`,
//! `allowed_destination_types`, `client_destination_types` and
//! `required_destinations_only` (Transport.py:267-272, 4620-4695).

use std::collections::{HashMap, HashSet};

use rns_identity::name_hash::name_hash;

/// Length of an announce name hash, Python `Identity.NAME_HASH_LENGTH // 8`.
pub const NAME_HASH_LEN: usize = 10;

pub type NameHash = [u8; NAME_HASH_LEN];

/// The `[filter]` configuration (Reticulum.py:487-503).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterPolicy {
    pub required_only: bool,
    /// Full destination names, Python `ignored_types`.
    pub ignored_types: Vec<String>,
    /// Full destination names, Python `allowed_types`.
    pub allowed_types: Vec<String>,
    /// Packets arriving with this many wire hops or more are dropped.
    pub hop_limiter: u8,
}

impl Default for FilterPolicy {
    fn default() -> Self {
        Self {
            required_only: false,
            ignored_types: Vec::new(),
            allowed_types: Vec::new(),
            hop_limiter: crate::constants::PATHFINDER_M,
        }
    }
}

impl FilterPolicy {
    /// Python clamps `hop_limiter` to `0..=PATHFINDER_M` (Reticulum.py:503).
    pub fn clamp_hop_limiter(value: i64) -> u8 {
        value.clamp(0, i64::from(crate::constants::PATHFINDER_M)) as u8
    }
}

/// Where an announce arrived from, for the required-only exemptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceSource {
    LocalClient,
    SharedInstance,
    Other,
}

#[derive(Debug, Default)]
pub struct DestinationTypeFilter {
    blocked: HashSet<NameHash>,
    allowed: HashSet<NameHash>,
    client: HashMap<NameHash, HashSet<Vec<u8>>>,
    names: HashMap<NameHash, String>,
    required_only: bool,
}

impl DestinationTypeFilter {
    /// Apply a configuration: `ignored_types` through `block`, `allowed_types`
    /// through `allow`, in Python's order.
    pub fn apply_policy(&mut self, policy: &FilterPolicy) {
        self.required_only = policy.required_only;
        for name in &policy.ignored_types {
            self.block(name);
        }
        for name in &policy.allowed_types {
            self.allow(name);
        }
    }

    pub fn required_only(&self) -> bool {
        self.required_only
    }

    pub fn set_required_only(&mut self, enabled: bool) {
        self.required_only = enabled;
    }

    /// Python `block_destination_type`: a blocked type is no longer wanted.
    pub fn block(&mut self, full_name: &str) {
        let hash = name_hash(full_name);
        self.blocked.insert(hash);
        self.client.remove(&hash);
        self.names.insert(hash, full_name.to_string());
    }

    /// Python `allow_destination_type`.
    pub fn allow(&mut self, full_name: &str) {
        let hash = name_hash(full_name);
        self.allowed.insert(hash);
        self.names.insert(hash, full_name.to_string());
    }

    /// Python `_wants_destination_type`: false only for a blocked type.
    pub fn wants(&mut self, full_name: &str, requester: Vec<u8>) -> bool {
        let hash = name_hash(full_name);
        if self.blocked.contains(&hash) {
            return false;
        }
        self.client.entry(hash).or_default().insert(requester);
        self.names.insert(hash, full_name.to_string());
        true
    }

    /// Python `_unwants_destination_type`: whether the requester was
    /// registered; the type goes once nobody wants it.
    pub fn unwants(&mut self, full_name: &str, requester: &[u8]) -> bool {
        self.unwants_hash(name_hash(full_name), requester)
    }

    fn unwants_hash(&mut self, hash: NameHash, requester: &[u8]) -> bool {
        let Some(requesters) = self.client.get_mut(&hash) else {
            return false;
        };
        let was_registered = requesters.remove(requester);
        if requesters.is_empty() {
            self.client.remove(&hash);
        }
        was_registered
    }

    /// Python `_unwants_all_destination_types`, always true.
    pub fn unwants_all(&mut self, requester: &[u8]) -> bool {
        let hashes: Vec<NameHash> = self.client.keys().copied().collect();
        for hash in hashes {
            self.unwants_hash(hash, requester);
        }
        true
    }

    pub fn is_wanted(&self, hash: &NameHash) -> bool {
        self.client.contains_key(hash)
    }

    /// Python `destination_type_name`.
    pub fn type_name(&self, hash: &NameHash) -> &str {
        self.names.get(hash).map_or("unknown", String::as_str)
    }

    /// The decision inside Python `Transport.inbound` (Transport.py:2035-2041),
    /// given the wire hop count before the inbound increment.
    pub fn admits(&self, hash: &NameHash, source: AnnounceSource, wire_hops: u8) -> bool {
        if self.blocked.contains(hash) {
            return false;
        }
        if !self.required_only {
            return true;
        }
        if self.allowed.contains(hash) || self.client.contains_key(hash) {
            return true;
        }
        match source {
            AnnounceSource::LocalClient | AnnounceSource::SharedInstance => wire_hops == 0,
            AnnounceSource::Other => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_type_cannot_be_wanted_and_drops_existing_requesters() {
        let mut f = DestinationTypeFilter::default();
        assert!(f.wants("a.b", vec![1]));
        f.block("a.b");
        assert!(!f.is_wanted(&name_hash("a.b")));
        assert!(!f.wants("a.b", vec![1]));
    }

    #[test]
    fn unwants_reports_registration_and_last_requester_drops_type() {
        let mut f = DestinationTypeFilter::default();
        assert!(f.wants("a.b", vec![1]));
        assert!(f.wants("a.b", vec![2]));
        assert!(!f.unwants("a.b", &[3]));
        assert!(f.unwants("a.b", &[1]));
        assert!(f.is_wanted(&name_hash("a.b")));
        assert!(f.unwants("a.b", &[2]));
        assert!(!f.is_wanted(&name_hash("a.b")));
        assert!(!f.unwants("a.b", &[2]));
        assert!(f.unwants_all(&[9]));
    }
}
