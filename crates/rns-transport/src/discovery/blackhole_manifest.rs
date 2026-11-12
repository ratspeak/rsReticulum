//! Wire-format codec for the distributed blackhole manifest.
//!
//! Encodes and decodes the MessagePack body for the
//! `rnstransport.info.blackhole` service's `/list` request. The codec does
//! not authenticate a publisher or verify the truth of its blackhole reasons.
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
//! The wire carries absolute `until` deadlines; the table keeps relative TTLs:
//! - **build**: `until = created + ttl`, or `nil` without a TTL.
//! - **apply**: skip deadlines at or before `now`, then use `created = now`
//!   and `ttl = max(0, until - now)`. Decoding alone does not apply expiry.
//!
//! # Publication
//!
//! [`build_manifest`] publishes the whole table, as upstream does. Applying a
//! manifest preserves its claimed inner source fields; callers must
//! authorize the publisher.

use std::collections::BTreeMap;

use rmpv::Value;
use rns_wire::types::IdentityHash;
use thiserror::Error;

use crate::blackhole::{BlackholeEntry, BlackholeReason, BlackholeTable};

/// One decoded manifest entry. The wire carries an absolute `until` deadline
/// rather than `created`; field decoding does not establish trusted provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct BlackholeManifestEntry {
    /// Absolute unix-second deadline, or `None` for permanent entries.
    pub until: Option<f64>,
    /// Publisher-supplied reason label. Empty represents a wire `nil` reason;
    /// unknown labels remain available alongside the parsed reason enum.
    pub reason: String,
    /// Claimed source identity. The codec does not bind it to the responding
    /// publisher or verify delegation.
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

/// Encode the whole table as upstream's `/list` reply
/// (`Transport.blackhole_list_handler`): every entry, local or learned, with
/// its source (`local_identity_hash` for local entries), absolute `until` and
/// reason, nil when none was given. Expired entries not yet culled are
/// included, as upstream's are.
pub fn build_manifest(
    table: &BlackholeTable,
    local_identity_hash: IdentityHash,
) -> Result<Vec<u8>, ManifestError> {
    let mut map: Vec<(Value, Value)> = Vec::new();

    for (hash, entry) in table.iter_entries() {
        let until = entry.ttl.map(|ttl| entry.created + ttl);
        let source = entry.source.unwrap_or(local_identity_hash);
        let wire_entry = encode_entry_map(until, entry.wire_reason(), source);
        map.push((Value::Binary(hash.as_bytes().to_vec()), wire_entry));
    }

    let root = Value::Map(map);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &root).map_err(|e| ManifestError::Encode(e.to_string()))?;
    Ok(buf)
}

fn encode_entry_map(until: Option<f64>, reason: Option<&str>, source: IdentityHash) -> Value {
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
            reason
                .map(|r| Value::String(r.into()))
                .unwrap_or(Value::Nil),
        ),
    ])
}

/// Decode the first MessagePack map and return entries sorted by identity hash.
/// Required field types and 16-byte hashes are checked; malformed entries fail
/// the whole load. Repeated identities keep their last decoded entry, repeated
/// recognized fields keep their last decoded value, and unknown fields are
/// ignored. Trailing bytes after the map are not rejected.
///
/// This neither authenticates source claims nor filters expired entries.
/// Floating-point deadlines need not be finite; validate that policy before
/// applying untrusted input. No input-size or entry-count bound is imposed here.
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

/// Decode a `/list` reply from `publisher` the way upstream's updater takes
/// it (`Discovery.py`): any map is accepted and each entry is taken
/// as given. Keys that are not 16-byte hashes are skipped, since they can
/// never match an identity. A missing or malformed field reads as nil, and an
/// entry that is not a map is a permanent entry without a reason; a missing
/// source is the publisher.
pub fn decode_published_manifest(
    bytes: &[u8],
    publisher: IdentityHash,
) -> Result<Vec<([u8; 16], BlackholeManifestEntry)>, ManifestError> {
    let mut cursor = std::io::Cursor::new(bytes);
    let root =
        rmpv::decode::read_value(&mut cursor).map_err(|e| ManifestError::Decode(e.to_string()))?;
    let Value::Map(map) = root else {
        return Err(ManifestError::NotAMap);
    };

    let mut sorted: BTreeMap<[u8; 16], BlackholeManifestEntry> = BTreeMap::new();
    for (k, v) in map {
        let Value::Binary(key) = k else {
            continue;
        };
        let Ok(key) = <[u8; 16]>::try_from(key.as_slice()) else {
            continue;
        };
        let mut entry = BlackholeManifestEntry {
            until: None,
            reason: String::new(),
            source: publisher,
        };
        if let Value::Map(fields) = v {
            for (field, value) in fields {
                match (field.as_str(), value) {
                    (Some("source"), Value::Binary(b)) => {
                        if let Ok(source) = <[u8; 16]>::try_from(b.as_slice()) {
                            entry.source = source.into();
                        }
                    }
                    (Some("until"), Value::F64(t)) => entry.until = Some(t),
                    (Some("until"), Value::F32(t)) => entry.until = Some(t as f64),
                    (Some("until"), Value::Integer(i)) => entry.until = i.as_f64(),
                    (Some("reason"), Value::String(r)) => {
                        entry.reason = r.into_str().unwrap_or_default()
                    }
                    _ => {}
                }
            }
        }
        sorted.insert(key, entry);
    }

    Ok(sorted.into_iter().collect())
}

/// Merge entries into `table` as upstream's updater does: an identity that
/// already has an entry, local or learned, expired or not, keeps it; only
/// absent identities are added, with their claimed source and reason (an
/// empty reason is nil). Already-expired entries are added too, as upstream
/// adds them, and fall to the next expiry cull. Entries absent from the
/// manifest are not removed.
///
/// Returns the number of identities added.
pub fn apply_manifest(
    table: &mut BlackholeTable,
    manifest: &[([u8; 16], BlackholeManifestEntry)],
    now: f64,
) -> usize {
    let mut added = 0usize;
    for (id_hash, entry) in manifest {
        if table.contains(id_hash) {
            continue;
        }

        // A past `until` gives a negative lifetime, so the entry is inert until culled.
        let ttl = entry.until.map(|u| u - now);
        let reason = BlackholeReason::parse(&entry.reason);
        table.insert_entry(
            *id_hash,
            BlackholeEntry {
                created: now,
                ttl,
                reason,
                reason_label: (!entry.reason.is_empty()).then(|| entry.reason.clone()),
                source: Some(entry.source),
            },
        );
        added += 1;
    }
    added
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
        let bytes = build_manifest(&table, our_id()).unwrap();
        let decoded = decode_manifest(&bytes).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn manifest_publishes_local_and_learned_entries() {
        let mut table = BlackholeTable::new();
        table.add([0xAA; 16], None);
        table.add_from_source(
            [0xBB; 16],
            Some(3600.0),
            BlackholeReason::RateLimit,
            peer_id(),
            1000.0,
        );

        let bytes = build_manifest(&table, our_id()).unwrap();
        let manifest = decode_published_manifest(&bytes, peer_id()).unwrap();

        assert_eq!(manifest.len(), 2);
        assert_eq!(manifest[0].0, [0xAA; 16]);
        assert_eq!(manifest[0].1.source, our_id());
        assert_eq!(manifest[0].1.until, None);
        assert_eq!(manifest[0].1.reason, "");
        assert_eq!(manifest[1].0, [0xBB; 16]);
        assert_eq!(manifest[1].1.source, peer_id());
        assert_eq!(manifest[1].1.until, Some(4600.0));
        assert_eq!(manifest[1].1.reason, "rate_limit");
    }

    #[test]
    fn ttl_roundtrips_as_absolute_until() {
        let mut table = BlackholeTable::new();
        let now_at_add = now_seconds();
        table.add_with_reason([0xCC; 16], Some(600.0), BlackholeReason::Malformed);

        let bytes = build_manifest(&table, our_id()).unwrap();
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
    fn apply_manifest_keeps_existing_remote_entry() {
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
                source: our_id(),
            },
        )];

        let applied = apply_manifest(&mut table, &manifest, now);
        assert_eq!(applied, 0);
        let entry = table.iter_entries().next().unwrap().1.clone();
        assert_eq!(entry.reason, BlackholeReason::Malformed);
        assert_eq!(entry.source, Some(peer_id()));
    }

    #[test]
    fn decode_rejects_bad_key_length() {
        let root = Value::Map(vec![(
            Value::Binary(vec![0; 8]),
            encode_entry_map(None, Some("manual"), peer_id()),
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
