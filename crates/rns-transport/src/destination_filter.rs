//! Destination-type announce filtering, Python `Transport` `blocked_destination_types`,
//! `allowed_destination_types`, `client_destination_types` and
//! `required_destinations_only` (Transport.py).

use std::collections::{HashMap, HashSet};

use rns_identity::name_hash::name_hash;

/// Length of an announce name hash, Python `Identity.NAME_HASH_LENGTH // 8`.
pub const NAME_HASH_LEN: usize = 10;

pub type NameHash = [u8; NAME_HASH_LEN];

/// The `[filter]` configuration and the config directory's type-name files
/// (Reticulum.py).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterPolicy {
    pub required_only: bool,
    /// Python `ignored_types`: full destination names, or `<hex>` name hashes.
    pub ignored_types: Vec<String>,
    /// Python `allowed_types`: full destination names, or `<hex>` name hashes.
    pub allowed_types: Vec<String>,
    /// Packets arriving with this many wire hops or more are dropped.
    pub hop_limiter: u8,
    /// Full names from `known_destination_types`, for logs only.
    pub known_types: Vec<String>,
    /// Full names from `flagged_destination_types`, for logs only.
    pub flagged_types: Vec<String>,
}

impl Default for FilterPolicy {
    fn default() -> Self {
        Self {
            required_only: false,
            ignored_types: Vec::new(),
            allowed_types: Vec::new(),
            hop_limiter: crate::constants::PATHFINDER_M,
            known_types: Vec::new(),
            flagged_types: Vec::new(),
        }
    }
}

impl FilterPolicy {
    /// Python clamps `hop_limiter` to `0..=PATHFINDER_M` (Reticulum.py).
    pub fn clamp_hop_limiter(value: i64) -> u8 {
        value.clamp(0, i64::from(crate::constants::PATHFINDER_M)) as u8
    }
}

/// Where an announce arrived from, for the required-only exemptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnnounceSource {
    LocalClient,
    SharedInstance,
    Other,
}

#[derive(Debug, Default)]
pub(crate) struct DestinationTypeFilter {
    blocked: HashSet<NameHash>,
    allowed: HashSet<NameHash>,
    client: HashMap<NameHash, HashSet<Vec<u8>>>,
    names: HashMap<NameHash, String>,
    flagged: HashMap<NameHash, String>,
    required_only: bool,
}

/// A type-filter entry as Python's `block_destination_type` and
/// `allow_destination_type` read it: `<…>` takes the next 20 characters as a
/// hex name hash, else hashes those characters as a name. `None` for an empty
/// entry, or hex that is not one name hash long, which upstream stores but can
/// never match.
fn parse_type_entry(full_name: &str) -> Option<(NameHash, String)> {
    if full_name.is_empty() {
        return None;
    }
    if !(full_name.starts_with('<') && full_name.ends_with('>')) {
        return Some((name_hash(full_name), full_name.to_string()));
    }
    let sliced: String = full_name.chars().skip(1).take(NAME_HASH_LEN * 2).collect();
    match py_fromhex(&sliced) {
        Some(bytes) if bytes.len() == NAME_HASH_LEN => {
            Some((bytes.try_into().expect("checked length"), sliced))
        }
        Some(bytes) if !bytes.is_empty() => None,
        _ => Some((name_hash(&sliced), sliced)),
    }
}

/// Python `bytes.fromhex`: hex pairs, with ASCII whitespace allowed between them.
fn py_fromhex(text: &str) -> Option<Vec<u8>> {
    let digit = |c: char| c.to_digit(16).filter(|_| c.is_ascii());
    let mut out = Vec::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r') {
            continue;
        }
        let high = digit(c)?;
        let low = digit(chars.next()?)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

impl DestinationTypeFilter {
    /// Apply a configuration: `ignored_types` through `block`, `allowed_types`
    /// through `allow`, then the type-name files, in Python's order.
    pub fn apply_policy(&mut self, policy: &FilterPolicy) {
        self.required_only = policy.required_only;
        for name in &policy.ignored_types {
            self.block(name);
        }
        for name in &policy.allowed_types {
            self.allow(name);
        }
        for name in &policy.known_types {
            self.names.insert(name_hash(name), name.clone());
        }
        for name in &policy.flagged_types {
            self.flagged.insert(name_hash(name), name.clone());
        }
    }

    pub fn set_required_only(&mut self, enabled: bool) {
        self.required_only = enabled;
    }

    /// Python `block_destination_type`: a blocked type is no longer wanted,
    /// and its name is flagged.
    pub fn block(&mut self, full_name: &str) {
        let Some((hash, name)) = parse_type_entry(full_name) else {
            return;
        };
        self.blocked.insert(hash);
        self.client.remove(&hash);
        self.names.insert(hash, name.clone());
        self.flagged.insert(hash, name);
    }

    /// Python `allow_destination_type`.
    pub fn allow(&mut self, full_name: &str) {
        let Some((hash, name)) = parse_type_entry(full_name) else {
            return;
        };
        self.allowed.insert(hash);
        self.names.insert(hash, name);
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

    #[cfg(test)]
    pub fn is_wanted(&self, hash: &NameHash) -> bool {
        self.client.contains_key(hash)
    }

    /// Python `destination_type_name`: the known name, else the flagged
    /// name, else the hash in hex.
    pub fn type_name(&self, hash: &NameHash) -> String {
        self.names
            .get(hash)
            .or_else(|| self.flagged.get(hash))
            .cloned()
            .unwrap_or_else(|| hex::encode(hash))
    }

    /// Python `prettynamehash`.
    pub fn pretty_name(&self, hash: &NameHash) -> String {
        format!("<{}>", self.type_name(hash))
    }

    /// Python drops a blocked type silently, ahead of the required-only check.
    pub fn is_blocked(&self, hash: &NameHash) -> bool {
        self.blocked.contains(hash)
    }

    /// The decision inside Python `Transport.inbound` (Transport.py),
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

    /// Transport.py 1.6.1 (e96c81c3): `<hex>` is a name hash; anything else
    /// in angle brackets is hashed as the 20 characters after `<`.
    #[test]
    fn angle_bracket_entries_are_name_hashes() {
        let hash: NameHash = hex::decode("c4ace368262d845c9dd3")
            .unwrap()
            .try_into()
            .unwrap();
        for entry in [
            "<c4ace368262d845c9dd3>",
            "<C4ACE368262D845C9DD3>",
            "<c4ace368262d845c9dd3aabbccddeeff00>",
        ] {
            let mut f = DestinationTypeFilter::default();
            f.block(entry);
            assert!(!f.admits(&hash, AnnounceSource::Other, 0), "{entry}");
            assert_eq!(f.type_name(&hash).to_lowercase(), "c4ace368262d845c9dd3");
        }
        let mut f = DestinationTypeFilter::default();
        f.block("<abcd>");
        assert!(!f.admits(&name_hash("abcd>"), AnnounceSource::Other, 0));
        f.set_required_only(true);
        f.allow("<0123456789abcdef0123>");
        let allowed: NameHash = hex::decode("0123456789abcdef0123")
            .unwrap()
            .try_into()
            .unwrap();
        assert!(f.admits(&allowed, AnnounceSource::Other, 0));
        // A client registration hashes the literal text.
        assert!(f.wants("<0011223344556677889a>", vec![1]));
        assert!(f.is_wanted(&name_hash("<0011223344556677889a>")));
        // Whitespace between pairs is skipped, as `bytes.fromhex` does; a
        // short result matches nothing.
        assert_eq!(parse_type_entry("<c4 ac e3 68 26 2d 84 5c 9d d3>"), None);
        assert_eq!(parse_type_entry(""), None);
    }

    /// Transport.py 1.6.1: known name, else flagged name, else bare hex; a
    /// blocked type is flagged, and the name files apply after `[filter]`.
    #[test]
    fn type_names_fall_back_to_flagged_then_hex() {
        let mut f = DestinationTypeFilter::default();
        f.apply_policy(&FilterPolicy {
            ignored_types: vec!["spam.type".into()],
            known_types: vec!["lxmf.delivery".into(), "spam.type".into()],
            flagged_types: vec!["bad.type".into()],
            ..Default::default()
        });
        assert_eq!(f.type_name(&name_hash("lxmf.delivery")), "lxmf.delivery");
        assert_eq!(f.type_name(&name_hash("bad.type")), "bad.type");
        assert_eq!(f.flagged.get(&name_hash("spam.type")).unwrap(), "spam.type");
        let unknown = name_hash("other.type");
        assert_eq!(f.type_name(&unknown), hex::encode(unknown));
        assert_eq!(
            f.pretty_name(&unknown),
            format!("<{}>", hex::encode(unknown))
        );
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
