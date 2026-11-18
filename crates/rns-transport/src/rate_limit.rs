use std::collections::HashMap;

use crate::constants::MAX_RATE_TIMESTAMPS;
use rns_wire::types::DestHash;

/// Python `AnnounceRateTable.PERSIST_MAGIC` and `PERSIST_VERSION` (Storage.py).
const PERSIST_MAGIC: &[u8; 6] = b"RNSART";
const PERSIST_VERSION: u8 = 0x01;
const PERSIST_HEADER_LEN: usize = 16;
const KEY_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct RateEntry {
    /// The last `MAX_RATE_TIMESTAMPS` checks, blocked ones included.
    pub timestamps: Vec<f64>,
    /// Last accepted announce time (Unix seconds). Blocked checks do not
    /// advance it.
    pub last: f64,
    pub violations: u32,
    /// Unix-seconds penalty deadline; zero is the initial value.
    pub blocked_until: f64,
}

impl RateEntry {
    /// Announces per second over the stored timestamps, for display only.
    pub fn rate(&self) -> f64 {
        match (self.timestamps.first(), self.timestamps.last()) {
            (Some(first), Some(last)) if last > first => {
                (self.timestamps.len() - 1) as f64 / (last - first)
            }
            _ => 0.0,
        }
    }
}

/// Python's `AnnounceRateTable` (Storage.py): destination-keyed announce
/// accounting for interfaces with an `announce_rate_target`. Only
/// [`Self::check_interface_rate`] writes entries; [`Self::cull`] expires them.
pub struct RateTable {
    entries: HashMap<DestHash, RateEntry>,
}

impl RateTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub fn is_blocked(&self, dest_hash: &[u8; 16]) -> bool {
        let now = crate::now_f64();
        self.entries
            .get(dest_hash)
            .is_some_and(|e| e.blocked_until > now)
    }

    /// Remove entries whose `last` is older than `now - ttl` and whose penalty
    /// has expired (Storage.py `cull`). Returns the number removed.
    pub fn cull(&mut self, now: f64, ttl: f64) -> usize {
        let horizon = now - ttl;
        let before = self.entries.len();
        self.entries
            .retain(|_, e| !(e.last < horizon && e.blocked_until <= now));
        before - self.entries.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&DestHash, &RateEntry)> {
        self.entries.iter()
    }

    /// Python `AnnounceRateTable.persist` (Storage.py): a 16-byte header, then
    /// every entry in little-endian columns. Each ring is written oldest
    /// first, so the bytes differ from upstream's ring order but load the same.
    pub fn to_bytes(&self) -> Vec<u8> {
        let count = self.entries.len();
        let mut blob = Vec::with_capacity(
            PERSIST_HEADER_LEN + count * (KEY_LEN + 22 + MAX_RATE_TIMESTAMPS * 8),
        );
        blob.extend_from_slice(PERSIST_MAGIC);
        blob.extend_from_slice(&[
            PERSIST_VERSION,
            0,
            MAX_RATE_TIMESTAMPS as u8,
            KEY_LEN as u8,
            0,
            0,
        ]);
        blob.extend_from_slice(&u32::try_from(count).unwrap_or(u32::MAX).to_le_bytes());
        let entries: Vec<_> = self.entries.iter().take(u32::MAX as usize).collect();
        for (key, _) in &entries {
            blob.extend_from_slice(key.as_bytes());
        }
        for (_, entry) in &entries {
            blob.extend_from_slice(&entry.last.to_le_bytes());
        }
        for (_, entry) in &entries {
            blob.extend_from_slice(&entry.blocked_until.to_le_bytes());
        }
        for (_, entry) in &entries {
            let violations = i32::try_from(entry.violations).unwrap_or(i32::MAX);
            blob.extend_from_slice(&violations.to_le_bytes());
        }
        fn ring(entry: &RateEntry) -> &[f64] {
            &entry.timestamps[entry.timestamps.len().saturating_sub(MAX_RATE_TIMESTAMPS)..]
        }
        for (_, entry) in &entries {
            blob.push(ring(entry).len() as u8);
        }
        for (_, entry) in &entries {
            blob.push((ring(entry).len() % MAX_RATE_TIMESTAMPS) as u8);
        }
        for (_, entry) in &entries {
            let ring = ring(entry);
            for slot in 0..MAX_RATE_TIMESTAMPS {
                let timestamp = ring.get(slot).copied().unwrap_or(0.0);
                blob.extend_from_slice(&timestamp.to_le_bytes());
            }
        }
        blob
    }

    /// Python `AnnounceRateTable.load` (Storage.py): `None` for a file it
    /// rejects whole, and also for keys that are not 16-byte destination
    /// hashes, which upstream loads but can never match. A ring of another
    /// size keeps its newest timestamps.
    pub fn from_bytes(blob: &[u8]) -> Option<Self> {
        if blob.len() < PERSIST_HEADER_LEN
            || &blob[..6] != PERSIST_MAGIC
            || blob[6] != PERSIST_VERSION
            || blob[7] != 0
        {
            return None;
        }
        let max_ts = usize::from(blob[8]);
        let keylen = usize::from(blob[9]);
        let count = u32::from_le_bytes(blob[12..16].try_into().ok()?) as usize;
        if max_ts < 1 || keylen != KEY_LEN {
            return None;
        }
        let entry_size = keylen + 22 + max_ts * 8;
        if count
            .checked_mul(entry_size)
            .and_then(|size| size.checked_add(PERSIST_HEADER_LEN))
            != Some(blob.len())
        {
            return None;
        }
        let mut columns = &blob[PERSIST_HEADER_LEN..];
        let mut take = |len: usize| {
            let (column, rest) = columns.split_at(len);
            columns = rest;
            column
        };
        let keys = take(count * keylen);
        let last = take(count * 8);
        let blocked = take(count * 8);
        let violations = take(count * 4);
        let ts_len = take(count);
        let ts_head = take(count);
        let timestamps = take(count * max_ts * 8);
        let f64_at = |column: &[u8], index: usize| {
            f64::from_le_bytes(column[index * 8..index * 8 + 8].try_into().unwrap())
        };

        let mut entries = HashMap::with_capacity(count);
        for slot in 0..count {
            let (len, head) = (usize::from(ts_len[slot]), usize::from(ts_head[slot]));
            if len > max_ts || head >= max_ts {
                return None;
            }
            let ring = |index: usize| f64_at(timestamps, slot * max_ts + index);
            let mut chronological: Vec<f64> = if len < max_ts {
                (0..len).map(ring).collect()
            } else {
                (head..max_ts).chain(0..head).map(ring).collect()
            };
            chronological.drain(..chronological.len().saturating_sub(MAX_RATE_TIMESTAMPS));
            let key: [u8; KEY_LEN] = keys[slot * keylen..(slot + 1) * keylen].try_into().ok()?;
            let violations =
                i32::from_le_bytes(violations[slot * 4..slot * 4 + 4].try_into().ok()?);
            let entry = RateEntry {
                timestamps: chronological,
                last: f64_at(last, slot),
                violations: violations.max(0) as u32,
                blocked_until: f64_at(blocked, slot),
            };
            if entries.insert(DestHash::from(key), entry).is_some() {
                return None;
            }
        }
        Some(Self { entries })
    }

    /// Take loaded entries for destinations this table has not seen.
    pub fn absorb(&mut self, loaded: Self) {
        for (key, entry) in loaded.entries {
            self.entries.entry(key).or_insert(entry);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Python `AnnounceRateTable.check_and_update` with the interface's
    /// `(rate_target, rate_grace, rate_penalty)`. Every call after the first
    /// records its timestamp. Outside a penalty, an interval shorter than
    /// `rate_target` is a violation and a long enough one forgives one;
    /// exceeding the grace count blocks until `last + rate_target +
    /// rate_penalty`. Returns `true` when the announce is rate blocked.
    pub fn check_interface_rate(
        &mut self,
        dest_hash: impl Into<DestHash>,
        rate_target: f64,
        rate_grace: u32,
        rate_penalty: f64,
    ) -> bool {
        let dest_hash = dest_hash.into();
        let now = crate::now_f64();

        let entry = match self.entries.entry(dest_hash) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(RateEntry {
                    timestamps: vec![now],
                    last: now,
                    violations: 0,
                    blocked_until: 0.0,
                });
                return false;
            }
        };

        entry.timestamps.push(now);
        if entry.timestamps.len() > MAX_RATE_TIMESTAMPS {
            entry.timestamps.remove(0);
        }

        if now <= entry.blocked_until {
            return true;
        }

        let current_rate = now - entry.last;
        if current_rate < rate_target {
            entry.violations += 1;
        } else {
            entry.violations = entry.violations.saturating_sub(1);
        }

        if entry.violations > rate_grace {
            entry.blocked_until = entry.last + rate_target + rate_penalty;
            return true;
        }

        entry.last = now;
        false
    }
}

impl Default for RateTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_rate_first_announce_not_blocked() {
        let mut rt = RateTable::new();
        let hash = [0xDD; 16];
        let blocked = rt.check_interface_rate(hash, 300.0, 3, 600.0);
        assert!(!blocked);
    }

    #[test]
    fn test_interface_rate_rapid_fire_triggers_block() {
        let mut rt = RateTable::new();
        let hash = [0xEE; 16];
        rt.check_interface_rate(hash, 300.0, 1, 600.0);
        rt.check_interface_rate(hash, 300.0, 1, 600.0);
        let blocked = rt.check_interface_rate(hash, 300.0, 1, 600.0);
        assert!(blocked);
        assert!(rt.is_blocked(&hash));
    }

    #[test]
    fn test_rate_timestamps_bounded() {
        let mut rt = RateTable::new();
        let hash = [0xAA; 16];
        for _ in 0..MAX_RATE_TIMESTAMPS + 5 {
            rt.check_interface_rate(hash, 300.0, 0, 0.0);
        }
        assert_eq!(
            rt.entries[&DestHash::from(hash)].timestamps.len(),
            MAX_RATE_TIMESTAMPS
        );
    }

    /// Goldens from `tests/fixtures/announce_rate/gen_rate_table.py`, which
    /// calls upstream `AnnounceRateTable.check_and_update` and `cull`.
    fn golden() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/announce_rate/rate_table.json"
        ))
        .unwrap()
    }

    fn now() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    }

    /// When an interface configures `announce_rate_target` (e.g. minimum 1.0s
    /// between announces) and a destination floods past the grace window, the
    /// table flips to blocked. Mirrors Python Transport.py.
    #[test]
    fn rate_limit_per_interface_target_kicks_in_when_configured() {
        let mut rt = RateTable::new();
        let target = 1.0;
        let grace = 2;
        let penalty = 5.0;

        // First call seeds the entry — never blocks.
        let blocked = rt.check_interface_rate([0xAA; 16], target, grace, penalty);
        assert!(!blocked, "first announce must not be blocked");

        // Hammer the table fast enough that current_rate < target every time.
        // After grace + 1 violations it must flip to blocked.
        let mut blocked_anywhere = false;
        for _ in 0..6 {
            if rt.check_interface_rate([0xAA; 16], target, grace, penalty) {
                blocked_anywhere = true;
                break;
            }
        }
        assert!(
            blocked_anywhere,
            "after exceeding grace violations, check_interface_rate must return true (blocked)"
        );
    }

    /// Python appends the timestamp even
    /// when the announce is blocked (Storage.py).
    #[test]
    fn blocked_check_still_appends_timestamp() {
        let g = golden();
        let c = &g["blocked_appends_timestamp"];
        let (t, gr, p) = (
            c["target"].as_f64().unwrap(),
            c["grace"].as_u64().unwrap() as u32,
            c["penalty"].as_f64().unwrap(),
        );
        let d = [0x11u8; 16];
        let mut rt = RateTable::new();
        let mut got = Vec::new();
        for _ in c["steps"].as_array().unwrap() {
            let blocked = rt.check_interface_rate(d, t, gr, p);
            let e = rt.iter().find(|(h, _)| h.as_bytes() == &d).unwrap().1;
            got.push((blocked, e.timestamps.len(), e.violations));
        }
        let want: Vec<(bool, usize, u32)> = c["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                (
                    s["blocked"].as_bool().unwrap(),
                    s["n_timestamps"].as_u64().unwrap() as usize,
                    s["rate_violations"].as_u64().unwrap() as u32,
                )
            })
            .collect();
        assert_eq!(
            got, want,
            "(blocked, n_timestamps, violations) per step vs AnnounceRateTable 1.6.0"
        );
    }

    /// Upstream 1.6.1 `AnnounceRateTable.persist` after `check_and_update` at
    /// 1000, 1010 and 1020 s (target 60, grace 0, penalty 30) for 0x11 × 16.
    const UPSTREAM_SINGLE: &str = "524e5341525401001010000001000000111111111111111111111111111111110000000000408f4000000000000891400100000003030000000000408f400000000000908f400000000000e08f400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    /// The same after 20 checks 100 s apart from 2000 s (target 60, grace 1),
    /// a wrapped ring with its head at 4, for 0x22 × 16.
    const UPSTREAM_WRAPPED: &str = "524e534152540100101000000100000022222222222222222222222222222222000000000078ae400000000000000000000000001004000000000020ac400000000000e8ac400000000000b0ad40000000000078ae400000000000c0a240000000000088a340000000000050a440000000000018a5400000000000e0a5400000000000a8a640000000000070a740000000000038a840000000000000a9400000000000c8a940000000000090aa40000000000058ab40";
    /// `AnnounceRateTable(max_timestamps=4)` after six checks 1 s apart from
    /// 3000 s (target 60, grace 2, penalty 5), for 0x33 × 16.
    const UPSTREAM_RING_OF_FOUR: &str = "524e534152540100041000000100000033333333333333333333333333333333000000000074a7400000000000f6a740030000000402000000000078a74000000000007aa740000000000074a740000000000076a740";

    fn only(table: &RateTable) -> RateEntry {
        assert_eq!(table.len(), 1);
        table.iter().next().unwrap().1.clone()
    }

    #[test]
    fn a_persisted_rate_table_matches_upstream_bytes() {
        let clock = crate::test_clock::Clock::at(1000.0);
        let mut table = RateTable::new();
        for now in [1000.0, 1010.0, 1020.0] {
            clock.set(now);
            table.check_interface_rate([0x11; 16], 60.0, 0, 30.0);
        }
        assert_eq!(hex::encode(table.to_bytes()), UPSTREAM_SINGLE);
    }

    #[test]
    fn upstream_rate_tables_load_oldest_first() {
        let wrapped = RateTable::from_bytes(&hex::decode(UPSTREAM_WRAPPED).unwrap()).unwrap();
        let entry = only(&wrapped);
        let expected: Vec<f64> = (4..20).map(|i| 2000.0 + 100.0 * f64::from(i)).collect();
        assert_eq!(entry.timestamps, expected);
        assert_eq!(
            (entry.last, entry.violations, entry.blocked_until),
            (3900.0, 0, 0.0)
        );

        // Upstream's own load into a ring of 16 gives the same items.
        let four = RateTable::from_bytes(&hex::decode(UPSTREAM_RING_OF_FOUR).unwrap()).unwrap();
        let entry = only(&four);
        assert_eq!(entry.timestamps, vec![3002.0, 3003.0, 3004.0, 3005.0]);
        assert_eq!(
            (entry.last, entry.violations, entry.blocked_until),
            (3002.0, 3, 3067.0)
        );
    }

    #[test]
    fn a_wrapped_ring_round_trips() {
        let clock = crate::test_clock::Clock::at(0.0);
        let mut table = RateTable::new();
        for i in 0..20 {
            clock.set(2000.0 + 100.0 * f64::from(i));
            table.check_interface_rate([0x22; 16], 60.0, 1, 0.0);
            table.check_interface_rate([0x44; 16], 500.0, 1, 50.0);
        }
        let loaded = RateTable::from_bytes(&table.to_bytes()).unwrap();
        assert_eq!(loaded.len(), 2);
        for (key, entry) in table.iter() {
            let got = &loaded.entries[key];
            assert_eq!(got.timestamps, entry.timestamps);
            assert_eq!(
                (got.last, got.violations, got.blocked_until),
                (entry.last, entry.violations, entry.blocked_until)
            );
        }
        assert_eq!(RateTable::new().to_bytes().len(), 16);
        assert_eq!(
            RateTable::from_bytes(&RateTable::new().to_bytes()).map(|t| t.len()),
            Some(0)
        );
    }

    /// Storage.py rejects the whole file on any of these.
    #[test]
    fn a_malformed_rate_table_is_rejected_whole() {
        let good = hex::decode(UPSTREAM_SINGLE).unwrap();
        let altered = |at: usize, byte: u8| {
            let mut blob = good.clone();
            blob[at] = byte;
            blob
        };
        let _clock = crate::test_clock::Clock::at(1000.0);
        let mut pair = RateTable::new();
        pair.check_interface_rate([0x55; 16], 60.0, 0, 0.0);
        pair.check_interface_rate([0x66; 16], 60.0, 0, 0.0);
        let mut twice = pair.to_bytes();
        twice.copy_within(16..32, 32);
        let rejected = [
            good[..15].to_vec(),
            altered(0, b'X'),
            altered(6, 2),
            altered(7, 1),
            altered(8, 0),
            altered(9, 0),
            altered(9, 20),
            altered(12, 2),
            good[..good.len() - 1].to_vec(),
            altered(16 + 16 + 8 + 8 + 4, 17),
            altered(16 + 16 + 8 + 8 + 4 + 1, 16),
        ];
        for (case, blob) in rejected.iter().enumerate() {
            assert!(RateTable::from_bytes(blob).is_none(), "case {case}");
        }
        assert!(RateTable::from_bytes(&good).is_some());
        assert_eq!(
            RateTable::from_bytes(&pair.to_bytes()).map(|t| t.len()),
            Some(2)
        );
        assert!(RateTable::from_bytes(&twice).is_none(), "a key twice");
        for len in 0..good.len() {
            let _ = RateTable::from_bytes(&good[..len]);
        }
    }

    /// Cull removes only entries both older than the retain window and no longer
    /// blocked (Storage.py).
    #[test]
    fn cull_keeps_actively_blocked_entry() {
        let g = golden();
        let ttl = g["RATE_TABLE_RETAIN"].as_f64().unwrap();
        let d = [0x11u8; 16];
        let mut rt = RateTable::new();
        rt.check_interface_rate(d, 60.0, 0, 7200.0);
        assert!(
            rt.check_interface_rate(d, 60.0, 0, 7200.0),
            "precondition: blocked"
        );
        let later = now() + ttl + 100.0;
        rt.cull(later, ttl);
        assert_eq!(
            rt.iter().any(|(h, _)| h.as_bytes() == &d),
            g["cull_keeps_blocked"]["survives"].as_bool().unwrap(),
            "blocked entry past the retain window"
        );
        let mut unblocked = RateTable::new();
        unblocked.check_interface_rate(d, 60.0, 0, 7200.0);
        unblocked.cull(later, ttl);
        assert_eq!(
            unblocked.iter().any(|(h, _)| h.as_bytes() == &d),
            g["cull_removes_unblocked_stale"]["survives"]
                .as_bool()
                .unwrap(),
            "unblocked entry past the retain window"
        );
    }
}
