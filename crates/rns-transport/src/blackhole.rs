use std::collections::HashMap;

use rns_wire::types::IdentityHash;
use serde::{Deserialize, Serialize};

/// Caller-supplied classification for an identity block. `Manual` is the
/// default; [`BlackholeTable::clear_system_entries`] removes all other
/// variants. The value itself is not evidence of a particular violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum BlackholeReason {
    #[default]
    Manual,
    Malformed,
    RateLimit,
    ProtocolViolation,
}

impl BlackholeReason {
    /// Stable string identifier for RPC/wire payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Malformed => "malformed",
            Self::RateLimit => "rate_limit",
            Self::ProtocolViolation => "protocol_violation",
        }
    }

    /// Parse the stable identifier (case-insensitive). Unknown values fall back
    /// to `Manual`. This also accepts `ratelimit` and `protocolviolation`;
    /// whitespace is not trimmed.
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "malformed" => Self::Malformed,
            "rate_limit" | "ratelimit" => Self::RateLimit,
            "protocol_violation" | "protocolviolation" => Self::ProtocolViolation,
            _ => Self::Manual,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlackholeEntry {
    /// Creation time (Unix seconds), supplied by the caller for restored or
    /// source-provided entries.
    pub created: f64,
    /// Lifetime in seconds relative to `created`; `None` has no automatic
    /// expiry. External timestamps and TTLs are not validated by this table.
    pub ttl: Option<f64>,
    pub reason: BlackholeReason,
    /// Optional reason text, used by `reason_str` in preference to the enum.
    pub reason_label: Option<String>,
    /// Caller-supplied publisher identity hash; `None` marks a local entry.
    /// This is metadata, not verified provenance. Entries are keyed by the
    /// blocked identity alone, so different sources do not get separate rows.
    pub source: Option<IdentityHash>,
}

impl BlackholeEntry {
    pub fn reason_str(&self) -> &str {
        self.reason_label
            .as_deref()
            .unwrap_or_else(|| self.reason.as_str())
    }
}

/// In-memory identity block entries. Each insertion replaces any entry for
/// the same identity. Expiry is checked by `is_blackholed`, but expired rows
/// remain in counts and iteration until removed or culled. This table does
/// not authenticate sources, enforce packet policy or persist itself.
#[derive(Clone)]
pub struct BlackholeTable {
    entries: HashMap<IdentityHash, BlackholeEntry>,
}

impl BlackholeTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Add a manually-issued blackhole entry. System-populated drops should
    /// use [`BlackholeTable::add_with_reason`].
    pub fn add(&mut self, identity_hash: impl Into<IdentityHash>, ttl: Option<f64>) {
        self.add_with_reason(identity_hash, ttl, BlackholeReason::Manual);
    }

    pub fn add_with_reason(
        &mut self,
        identity_hash: impl Into<IdentityHash>,
        ttl: Option<f64>,
        reason: BlackholeReason,
    ) {
        let now = crate::now_f64();

        self.entries.insert(
            identity_hash.into(),
            BlackholeEntry {
                created: now,
                ttl,
                reason,
                reason_label: None,
                source: None,
            },
        );
    }

    pub fn add_with_reason_label(
        &mut self,
        identity_hash: impl Into<IdentityHash>,
        ttl: Option<f64>,
        reason: BlackholeReason,
        reason_label: Option<String>,
    ) {
        let now = crate::now_f64();

        self.entries.insert(
            identity_hash.into(),
            BlackholeEntry {
                created: now,
                ttl,
                reason,
                reason_label,
                source: None,
            },
        );
    }

    /// Insert or replace an entry with the supplied source and creation time.
    /// The source is retained as metadata; this method neither authenticates
    /// it nor merges competing claims. Callers must validate external data
    /// and choose their source/override policy before insertion.
    pub fn add_from_source(
        &mut self,
        identity_hash: impl Into<IdentityHash>,
        ttl: Option<f64>,
        reason: BlackholeReason,
        source: IdentityHash,
        created: f64,
    ) {
        self.entries.insert(
            identity_hash.into(),
            BlackholeEntry {
                created,
                ttl,
                reason,
                reason_label: None,
                source: Some(source),
            },
        );
    }

    /// Insert a pre-built entry, preserving its `created`/`ttl`/`reason`.
    /// Used when rehydrating the table from persistence.
    pub fn insert_entry(&mut self, identity_hash: impl Into<IdentityHash>, entry: BlackholeEntry) {
        self.entries.insert(identity_hash.into(), entry);
    }

    /// Check whether an entry has no expiry or its elapsed wall-clock time is
    /// less than its TTL. Expired entries are not removed by this lookup.
    pub fn is_blackholed(&self, identity_hash: &[u8; 16]) -> bool {
        match self.entries.get(identity_hash) {
            Some(entry) => {
                if let Some(ttl) = entry.ttl {
                    let now = crate::now_f64();
                    now - entry.created < ttl
                } else {
                    true
                }
            }
            None => false,
        }
    }

    /// Remove an entry; returns `true` if one was present.
    pub fn remove(&mut self, identity_hash: &[u8; 16]) -> bool {
        self.entries.remove(identity_hash).is_some()
    }

    /// Drop entries whose TTL has elapsed; returns the number removed.
    pub fn cull_expired(&mut self) -> usize {
        let now = crate::now_f64();

        let before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.ttl.is_none_or(|ttl| now - entry.created < ttl));
        before - self.entries.len()
    }

    /// Drop every entry whose reason is not `Manual`; returns the number removed.
    pub fn clear_system_entries(&mut self) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| matches!(entry.reason, BlackholeReason::Manual));
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &IdentityHash> {
        self.entries.keys()
    }

    pub fn iter_entries(&self) -> impl Iterator<Item = (&IdentityHash, &BlackholeEntry)> {
        self.entries.iter()
    }
}

impl Default for BlackholeTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blackhole_permanent() {
        let mut bh = BlackholeTable::new();
        let hash = [0xAA; 16];
        bh.add(hash, None);
        assert!(bh.is_blackholed(&hash));
    }

    #[test]
    fn test_not_blackholed() {
        let bh = BlackholeTable::new();
        assert!(!bh.is_blackholed(&[0xBB; 16]));
    }

    #[test]
    fn test_remove() {
        let mut bh = BlackholeTable::new();
        let hash = [0xAA; 16];
        bh.add(hash, None);
        assert!(bh.remove(&hash));
        assert!(!bh.is_blackholed(&hash));
        assert!(!bh.remove(&hash));
    }

    #[test]
    fn test_default_reason_is_manual() {
        let mut bh = BlackholeTable::new();
        let hash = [0xCC; 16];
        bh.add(hash, None);
        let entry = bh.iter_entries().next().unwrap().1;
        assert_eq!(entry.reason, BlackholeReason::Manual);
    }

    #[test]
    fn test_clear_system_entries_keeps_manual() {
        let mut bh = BlackholeTable::new();
        bh.add_with_reason([0xAA; 16], None, BlackholeReason::Manual);
        bh.add_with_reason([0xBB; 16], None, BlackholeReason::Malformed);
        bh.add_with_reason([0xCC; 16], None, BlackholeReason::RateLimit);
        bh.add_with_reason([0xDD; 16], None, BlackholeReason::ProtocolViolation);

        let cleared = bh.clear_system_entries();
        assert_eq!(cleared, 3);
        assert!(bh.is_blackholed(&[0xAA; 16]));
        assert!(!bh.is_blackholed(&[0xBB; 16]));
        assert!(!bh.is_blackholed(&[0xCC; 16]));
        assert!(!bh.is_blackholed(&[0xDD; 16]));
    }

    #[test]
    fn test_reason_round_trip() {
        for r in [
            BlackholeReason::Manual,
            BlackholeReason::Malformed,
            BlackholeReason::RateLimit,
            BlackholeReason::ProtocolViolation,
        ] {
            assert_eq!(BlackholeReason::parse(r.as_str()), r);
        }
        assert_eq!(BlackholeReason::parse("bogus"), BlackholeReason::Manual);
    }
}
