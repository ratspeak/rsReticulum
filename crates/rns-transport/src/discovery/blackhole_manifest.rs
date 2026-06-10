//! Wire-format codec for the distributed blackhole manifest.
//!
//! Mirrors the msgpack payload served by Python's
//! `rnstransport.info.blackhole` request handler (Transport.py:3243) and
//! consumed by the subscriber side of `BlackholeUpdater` (Discovery.py:658).
//!
//! # Wire shape
//!
//! ```text
//! msgpack::Map {
//!     identity_hash_bytes (16B): msgpack::Map {
//!         "source": source_identity_hash_bytes (16B),
//!         "until":  f64 unix-seconds | nil,
//!         "reason": str | nil,
//!     },
//!     ...
//! }
//! ```
//!
//! Python uses absolute-deadline `until` on the wire; the Rust table keeps
//! relative `ttl`. Conversions happen at the boundary:
//! - **encode**: `until = created + ttl` when `ttl.is_some()`, else `nil`.
//! - **decode**: `created = now`, `ttl = max(0, until - now)`. This mirrors
//!   the semantics in Transport.py:3212 — expired entries are skipped.
//!
//! # Publication filter
//!
//! A node only publishes entries it issued itself. In-memory: entries with
//! `source == None`. Python's equivalent filter (Transport.py:3256) is
//! `source == Transport.identity.hash`; we keep `None` as a marker so the
//! table does not need to know its own identity.

use std::collections::BTreeMap;

use rmpv::Value;
use rns_wire::types::IdentityHash;
use thiserror::Error;

use crate::blackhole::{BlackholeEntry, BlackholeReason, BlackholeTable};

/// A single manifest entry on the wire. `created` is not transmitted —
/// Python stores `until` (absolute deadline) instead.
#[derive(Debug, Clone, PartialEq)]
pub struct BlackholeManifestEntry {
    /// Absolute unix-second deadline, or `None` for permanent entries.
    pub until: Option<f64>,
    /// Stable string identifier (see [`BlackholeReason::as_str`]).
    pub reason: String,
    /// Identity hash of the source that issued this entry.
    pub source: IdentityHash,
}

#[derive(Debug, Error, PartialEq)]
pub enum ManifestError {
    #[error("manifest root is not a map")]
    NotAMap,
    #[error("manifest key is not 16-byte identity hash")]
    BadKey,
    #[error("manifest entry is not a map")]
    EntryNotMap,
    #[error("manifest entry missing required field: {0}")]
    MissingField(&'static str),
    #[error("manifest entry has malformed field: {0}")]
    BadField(&'static str),
    #[error("msgpack decode error: {0}")]
    Decode(String),
    #[error("msgpack encode error: {0}")]
    Encode(String),
}

/// Build the msgpack manifest payload of **locally-issued** blackhole
/// entries. Used by the `/list` request handler on
/// `rnstransport.info.blackhole`.
///
/// `our_identity_hash` is injected into every entry's `source` field so
/// subscribers can correctly key entries by publisher.
///
/// `verified_ids`, when `Some(_)`, restricts the published entries to those
/// whose identity hash is in the set — typically the set of identity hashes
/// derivable from current `recent_announces` public keys. This refuses to
/// republish unverifiable entries (e.g., garbage from a buggy caller, or
/// identities whose announces have been pruned). When `None`, no filtering
/// is applied — used by tests that want to inspect the raw round-trip.
pub fn build_local_manifest(
    table: &BlackholeTable,
    our_identity_hash: IdentityHash,
    verified_ids: Option<&std::collections::HashSet<[u8; 16]>>,
) -> Result<Vec<u8>, ManifestError> {
    let mut map: Vec<(Value, Value)> = Vec::new();

    for (hash, entry) in table.iter_entries() {
        if entry.source.is_some() {
            continue;
        }
        if let Some(set) = verified_ids
            && !set.contains(hash.as_bytes())
        {
            continue;
        }
        let until = entry.ttl.map(|ttl| entry.created + ttl);
        let wire_entry = encode_entry_map(until, entry.reason_str(), our_identity_hash);
        map.push((Value::Binary(hash.as_bytes().to_vec()), wire_entry));
    }

    let root = Value::Map(map);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &root).map_err(|e| ManifestError::Encode(e.to_string()))?;
    Ok(buf)
}

fn encode_entry_map(until: Option<f64>, reason: &str, source: IdentityHash) -> Value {
    let until_v = match until {
        Some(t) => Value::F64(t),
        None => Value::Nil,
    };
    Value::Map(vec![
        (
            Value::String("source".into()),
            Value::Binary(source.as_bytes().to_vec()),
        ),
        (Value::String("until".into()), until_v),
        (
            Value::String("reason".into()),
            Value::String(reason.to_string().into()),
        ),
    ])
}

/// Parse a msgpack manifest payload into `(identity_hash, entry)` pairs.
/// Sorted for deterministic iteration in tests; order is not load-bearing
/// otherwise.
pub fn decode_manifest(
    bytes: &[u8],
) -> Result<Vec<([u8; 16], BlackholeManifestEntry)>, ManifestError> {
    let mut cursor = std::io::Cursor::new(bytes);
    let root =
        rmpv::decode::read_value(&mut cursor).map_err(|e| ManifestError::Decode(e.to_string()))?;

    let map = match root {
        Value::Map(m) => m,
        _ => return Err(ManifestError::NotAMap),
    };

    let mut sorted: BTreeMap<[u8; 16], BlackholeManifestEntry> = BTreeMap::new();
    for (k, v) in map {
        let key = match k {
            Value::Binary(b) if b.len() == 16 => {
                let mut h = [0u8; 16];
                h.copy_from_slice(&b);
                h
            }
            _ => return Err(ManifestError::BadKey),
        };
        let entry = decode_entry_map(v)?;
        sorted.insert(key, entry);
    }

    Ok(sorted.into_iter().collect())
}

fn decode_entry_map(v: Value) -> Result<BlackholeManifestEntry, ManifestError> {
    let map = match v {
        Value::Map(m) => m,
        _ => return Err(ManifestError::EntryNotMap),
    };

    let mut source: Option<IdentityHash> = None;
    let mut until: Option<Option<f64>> = None;
    let mut reason: Option<String> = None;

    for (k, val) in map {
        let key_str = match k {
            Value::String(s) => s.into_str().unwrap_or_default(),
            _ => continue,
        };
        match key_str.as_str() {
            "source" => match val {
                Value::Binary(b) if b.len() == 16 => {
                    let mut h = [0u8; 16];
                    h.copy_from_slice(&b);
                    source = Some(h.into());
                }
                _ => return Err(ManifestError::BadField("source")),
            },
            "until" => match val {
                Value::Nil => until = Some(None),
                Value::F64(t) => until = Some(Some(t)),
                Value::F32(t) => until = Some(Some(t as f64)),
                Value::Integer(i) => {
                    let as_f = i.as_f64().ok_or(ManifestError::BadField("until"))?;
                    until = Some(Some(as_f));
                }
                _ => return Err(ManifestError::BadField("until")),
            },
            "reason" => match val {
                Value::Nil => reason = Some(String::new()),
                Value::String(s) => {
                    reason = Some(s.into_str().unwrap_or_default());
                }
                _ => return Err(ManifestError::BadField("reason")),
            },
            _ => {}
        }
    }

    Ok(BlackholeManifestEntry {
        source: source.ok_or(ManifestError::MissingField("source"))?,
        until: until.ok_or(ManifestError::MissingField("until"))?,
        reason: reason.ok_or(ManifestError::MissingField("reason"))?,
    })
}

/// Merge a decoded manifest into `table`. `source_identity_hash` is the
/// publisher that answered the `/list` request; each entry's inner
/// `source` field is preserved so a chain of republishers stays
/// traceable (Python parity: Discovery.py:672-675).
///
/// Skips:
/// - entries whose local-table source is `None` (locally-issued always wins);
/// - entries whose `until` deadline has already passed (matches
///   Transport.py:3212).
///
/// Returns the number of entries actually inserted or updated.
pub fn apply_manifest(
    table: &mut BlackholeTable,
    manifest: &[([u8; 16], BlackholeManifestEntry)],
    now: f64,
) -> usize {
    let mut applied = 0usize;
    for (id_hash, entry) in manifest {
        if let Some(until) = entry.until {
            if until <= now {
                continue;
            }
        }
        if let Some(existing) = table
            .iter_entries()
            .find(|(h, _)| h.as_bytes() == id_hash)
            .map(|(_, e)| e.clone())
        {
            if existing.source.is_none() {
                continue;
            }
        }

        let ttl = entry.until.map(|u| (u - now).max(0.0));
        let reason = BlackholeReason::parse(&entry.reason);
        table.insert_entry(
            *id_hash,
            BlackholeEntry {
                created: now,
                ttl,
                reason,
                reason_label: Some(entry.reason.clone()),
                source: Some(entry.source),
            },
        );
        applied += 1;
    }
    applied
}

#[cfg(test)]
mod tests {
    use super::*;

    fn our_id() -> IdentityHash {
        [0x11; 16].into()
    }

    fn peer_id() -> IdentityHash {
        [0x22; 16].into()
    }

    #[test]
    fn empty_table_produces_empty_map() {
        let table = BlackholeTable::new();
        let bytes = build_local_manifest(&table, our_id(), None).unwrap();
        let decoded = decode_manifest(&bytes).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn local_entries_are_published_remote_entries_are_filtered() {
        let mut table = BlackholeTable::new();
        table.add([0xAA; 16], None);
        table.add_from_source(
            [0xBB; 16],
            Some(3600.0),
            BlackholeReason::RateLimit,
            peer_id(),
            1000.0,
        );

        let bytes = build_local_manifest(&table, our_id(), None).unwrap();
        let manifest = decode_manifest(&bytes).unwrap();

        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].0, [0xAA; 16]);
        assert_eq!(manifest[0].1.source, our_id());
        assert_eq!(manifest[0].1.until, None);
        assert_eq!(manifest[0].1.reason, "manual");
    }

    #[test]
    fn ttl_roundtrips_as_absolute_until() {
        let mut table = BlackholeTable::new();
        let now_at_add = now_seconds();
        table.add_with_reason([0xCC; 16], Some(600.0), BlackholeReason::Malformed);

        let bytes = build_local_manifest(&table, our_id(), None).unwrap();
        let manifest = decode_manifest(&bytes).unwrap();

        assert_eq!(manifest.len(), 1);
        let until = manifest[0].1.until.expect("until present");
        assert!(until >= now_at_add + 599.0 && until <= now_at_add + 601.0 + 10.0);
    }

    #[test]
    fn apply_manifest_inserts_remote_entries_with_ttl() {
        let mut table = BlackholeTable::new();
        let now = 10_000.0;
        let manifest = vec![(
            [0xDD; 16],
            BlackholeManifestEntry {
                until: Some(now + 500.0),
                reason: "malformed".into(),
                source: peer_id(),
            },
        )];

        let applied = apply_manifest(&mut table, &manifest, now);
        assert_eq!(applied, 1);
        let expected: IdentityHash = [0xDD; 16].into();
        let entry = table
            .iter_entries()
            .find(|(h, _)| **h == expected)
            .unwrap()
            .1
            .clone();
        assert_eq!(entry.source, Some(peer_id()));
        assert_eq!(entry.reason, BlackholeReason::Malformed);
        assert_eq!(entry.created, now);
        assert!((entry.ttl.unwrap() - 500.0).abs() < 0.01);
    }

    #[test]
    fn apply_manifest_skips_expired_entries() {
        let mut table = BlackholeTable::new();
        let now = 10_000.0;
        let manifest = vec![(
            [0xEE; 16],
            BlackholeManifestEntry {
                until: Some(now - 10.0),
                reason: "malformed".into(),
                source: peer_id(),
            },
        )];

        let applied = apply_manifest(&mut table, &manifest, now);
        assert_eq!(applied, 0);
        assert!(table.is_empty());
    }

    #[test]
    fn apply_manifest_preserves_permanent_entries() {
        let mut table = BlackholeTable::new();
        let now = 10_000.0;
        let manifest = vec![(
            [0xFF; 16],
            BlackholeManifestEntry {
                until: None,
                reason: "rate_limit".into(),
                source: peer_id(),
            },
        )];

        let applied = apply_manifest(&mut table, &manifest, now);
        assert_eq!(applied, 1);
        let entry = table.iter_entries().next().unwrap().1.clone();
        assert_eq!(entry.ttl, None);
        assert_eq!(entry.reason, BlackholeReason::RateLimit);
    }

    #[test]
    fn apply_manifest_does_not_overwrite_local_entries() {
        let mut table = BlackholeTable::new();
        table.add_with_reason([0xAB; 16], None, BlackholeReason::Manual);

        let now = 10_000.0;
        let manifest = vec![(
            [0xAB; 16],
            BlackholeManifestEntry {
                until: Some(now + 100.0),
                reason: "malformed".into(),
                source: peer_id(),
            },
        )];

        let applied = apply_manifest(&mut table, &manifest, now);
        assert_eq!(applied, 0);
        let entry = table.iter_entries().next().unwrap().1.clone();
        assert_eq!(entry.source, None, "local source preserved");
        assert_eq!(entry.reason, BlackholeReason::Manual);
    }

    #[test]
    fn apply_manifest_overwrites_existing_remote_entry_from_same_source() {
        let mut table = BlackholeTable::new();
        let now = 10_000.0;
        table.add_from_source(
            [0xCD; 16],
            Some(100.0),
            BlackholeReason::Malformed,
            peer_id(),
            now - 50.0,
        );

        let manifest = vec![(
            [0xCD; 16],
            BlackholeManifestEntry {
                until: Some(now + 3600.0),
                reason: "rate_limit".into(),
                source: peer_id(),
            },
        )];

        let applied = apply_manifest(&mut table, &manifest, now);
        assert_eq!(applied, 1);
        let entry = table.iter_entries().next().unwrap().1.clone();
        assert_eq!(entry.reason, BlackholeReason::RateLimit);
        assert!((entry.ttl.unwrap() - 3600.0).abs() < 0.01);
    }

    #[test]
    fn decode_rejects_bad_key_length() {
        let root = Value::Map(vec![(
            Value::Binary(vec![0; 8]),
            encode_entry_map(None, "manual", peer_id()),
        )]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &root).unwrap();
        let err = decode_manifest(&buf).unwrap_err();
        assert_eq!(err, ManifestError::BadKey);
    }

    #[test]
    fn decode_rejects_missing_source() {
        let root = Value::Map(vec![(
            Value::Binary(vec![0; 16]),
            Value::Map(vec![
                (Value::String("until".into()), Value::Nil),
                (
                    Value::String("reason".into()),
                    Value::String("manual".into()),
                ),
            ]),
        )]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &root).unwrap();
        let err = decode_manifest(&buf).unwrap_err();
        assert_eq!(err, ManifestError::MissingField("source"));
    }

    #[test]
    fn decode_accepts_integer_until_from_python() {
        let root = Value::Map(vec![(
            Value::Binary(vec![0xAA; 16]),
            Value::Map(vec![
                (
                    Value::String("source".into()),
                    Value::Binary(peer_id().as_bytes().to_vec()),
                ),
                (
                    Value::String("until".into()),
                    Value::Integer(12345678i64.into()),
                ),
                (
                    Value::String("reason".into()),
                    Value::String("manual".into()),
                ),
            ]),
        )]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &root).unwrap();
        let decoded = decode_manifest(&buf).unwrap();
        assert_eq!(decoded[0].1.until, Some(12345678.0));
    }

    fn now_seconds() -> f64 {
        crate::now_f64()
    }
}
