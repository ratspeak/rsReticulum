use crate::resource::{MAPHASH_LEN, ResourceFlags};

/// Advertisement overhead in bytes (non-hashmap data).
pub const OVERHEAD: usize = 134;

/// Maximum map-hash entries that fit alongside the advertisement overhead in one MDU.
pub fn hashmap_max_len(mdu: usize) -> usize {
    if mdu > OVERHEAD {
        (mdu - OVERHEAD) / MAPHASH_LEN
    } else {
        0
    }
}

/// Space reserved to absorb a burst of out-of-order part requests without
/// churning the main hashmap: `2 * WINDOW_MAX_FAST + hashmap_max_len(mdu)`.
pub fn collision_guard_size(mdu: usize) -> usize {
    2 * crate::resource::WINDOW_MAX_FAST + hashmap_max_len(mdu)
}

/// Msgpack-encoded announcement that precedes a resource transfer.
///
/// Keys in the packed map:
/// - `t`: transfer_size, `d`: data_size, `n`: num_parts
/// - `h`: resource_hash, `r`: random_hash, `o`: original_hash
/// - `i`: segment_index, `l`: total_segments, `q`: request_id
/// - `f`: flags byte, `m`: hashmap
///
/// When `flags.has_metadata` is set the reassembled data begins with a
/// length-prefixed metadata block that the receiver strips before delivering
/// the payload.
#[derive(Debug, Clone)]
pub struct ResourceAdvertisement {
    pub transfer_size: usize,
    pub data_size: usize,
    pub num_parts: usize,
    pub resource_hash: [u8; 32],
    pub random_hash: Vec<u8>,
    pub original_hash: [u8; 32],
    pub segment_index: usize,
    pub total_segments: usize,
    pub request_id: Option<Vec<u8>>,
    pub flags: ResourceFlags,
    pub hashmap: Vec<u8>,
    /// Length of the metadata prefix embedded in the resource data when
    /// `flags.has_metadata` is set. Not transmitted on the wire.
    pub metadata_size: usize,
}

impl ResourceAdvertisement {
    /// Build an advertisement with no metadata prefix. Equivalent to
    /// [`Self::with_metadata_size`] with `metadata_size = 0`.
    // Mirrors the Resource ADV wire fields; grouping these into a builder
    // would hide the packet layout this constructor exists to preserve.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transfer_size: usize,
        data_size: usize,
        num_parts: usize,
        resource_hash: [u8; 32],
        random_hash: Vec<u8>,
        flags: ResourceFlags,
        map_hashes: &[[u8; MAPHASH_LEN]],
        mdu: usize,
    ) -> Self {
        Self::with_metadata_size(
            transfer_size,
            data_size,
            num_parts,
            resource_hash,
            random_hash,
            flags,
            map_hashes,
            mdu,
            0,
        )
    }

    /// Build an advertisement, truncating `map_hashes` to what actually fits in
    /// the MDU. Callers are expected to send the remaining hashes in a
    /// subsequent hashmap-update packet.
    // Same Resource ADV field set as `new`, plus the local metadata prefix
    // size needed to split payload from metadata after receive.
    #[allow(clippy::too_many_arguments)]
    pub fn with_metadata_size(
        transfer_size: usize,
        data_size: usize,
        num_parts: usize,
        resource_hash: [u8; 32],
        random_hash: Vec<u8>,
        flags: ResourceFlags,
        map_hashes: &[[u8; MAPHASH_LEN]],
        mdu: usize,
        metadata_size: usize,
    ) -> Self {
        let max_hashes = hashmap_max_len(mdu);
        let initial_hashes = map_hashes.len().min(max_hashes);

        let mut hashmap = Vec::with_capacity(initial_hashes * MAPHASH_LEN);
        for hash in map_hashes.iter().take(initial_hashes) {
            hashmap.extend_from_slice(hash);
        }

        Self {
            transfer_size,
            data_size,
            num_parts,
            resource_hash,
            random_hash,
            original_hash: resource_hash,
            segment_index: 1,
            total_segments: 1,
            request_id: None,
            flags,
            hashmap,
            metadata_size,
        }
    }

    /// Decode an advertisement produced by [`Self::pack`] or by the Python
    /// reference implementation.
    pub fn unpack(data: &[u8]) -> Result<Self, String> {
        use rmpv::Value;

        let value =
            rmpv::decode::read_value(&mut &data[..]).map_err(|e| format!("msgpack decode: {e}"))?;

        let map = match &value {
            Value::Map(m) => m,
            _ => return Err("expected msgpack map".into()),
        };

        let get = |key: &str| -> Option<&Value> {
            map.iter()
                .find(|(k, _)| matches!(k, Value::String(s) if s.as_str() == Some(key)))
                .map(|(_, v)| v)
        };

        let get_usize = |key: &str| -> Result<usize, String> {
            get(key)
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .ok_or_else(|| format!("missing or invalid key: {key}"))
        };

        let get_bytes = |key: &str, len: usize| -> Result<Vec<u8>, String> {
            let bytes = get(key)
                .and_then(|v| v.as_slice())
                .ok_or_else(|| format!("missing or invalid key: {key}"))?;
            if bytes.len() < len {
                return Err(format!("{key}: expected {len} bytes, got {}", bytes.len()));
            }
            Ok(bytes.to_vec())
        };

        let transfer_size = get_usize("t")?;
        let data_size = get_usize("d")?;
        let num_parts = get_usize("n")?;

        let h_bytes = get_bytes("h", 32)?;
        let mut resource_hash = [0u8; 32];
        resource_hash.copy_from_slice(&h_bytes[..32]);

        // Python sends a 16-byte random tag, but any length >= 4 is acceptable.
        let random_hash = get_bytes("r", 4)?;

        let o_bytes = get_bytes("o", 32)?;
        let mut original_hash = [0u8; 32];
        original_hash.copy_from_slice(&o_bytes[..32]);

        let segment_index = get_usize("i")?;
        let total_segments = get_usize("l")?;

        let request_id = get("q").and_then(|v| {
            if v.is_nil() {
                None
            } else {
                v.as_slice().map(|s| s.to_vec())
            }
        });

        let flags_byte = get("f").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
        let flags = ResourceFlags::from_byte(flags_byte);

        let hashmap = get("m")
            .and_then(|v| v.as_slice())
            .map(|s| s.to_vec())
            .unwrap_or_default();

        Ok(Self {
            transfer_size,
            data_size,
            num_parts,
            resource_hash,
            random_hash,
            original_hash,
            segment_index,
            total_segments,
            request_id,
            flags,
            hashmap,
            metadata_size: 0,
        })
    }

    /// Encode as the msgpack map described on the struct docs.
    pub fn pack(&self) -> Vec<u8> {
        use rmpv::Value;

        let q_val = match &self.request_id {
            Some(id) => Value::Binary(id.clone()),
            None => Value::Nil,
        };

        let pairs: Vec<(Value, Value)> = vec![
            (
                Value::String("t".into()),
                Value::Integer(self.transfer_size.into()),
            ),
            (
                Value::String("d".into()),
                Value::Integer(self.data_size.into()),
            ),
            (
                Value::String("n".into()),
                Value::Integer(self.num_parts.into()),
            ),
            (
                Value::String("h".into()),
                Value::Binary(self.resource_hash.to_vec()),
            ),
            (
                Value::String("r".into()),
                Value::Binary(self.random_hash.to_vec()),
            ),
            (
                Value::String("o".into()),
                Value::Binary(self.original_hash.to_vec()),
            ),
            (
                Value::String("i".into()),
                Value::Integer(self.segment_index.into()),
            ),
            (
                Value::String("l".into()),
                Value::Integer(self.total_segments.into()),
            ),
            (Value::String("q".into()), q_val),
            (
                Value::String("f".into()),
                Value::Integer(self.flags.to_byte().into()),
            ),
            (
                Value::String("m".into()),
                Value::Binary(self.hashmap.clone()),
            ),
        ];

        let value = Value::Map(pairs);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &value).expect("msgpack encode should succeed");
        buf
    }

    /// Split the packed `hashmap` field into fixed-length map-hash entries.
    pub fn get_map_hashes(&self) -> Vec<[u8; MAPHASH_LEN]> {
        self.hashmap
            .chunks_exact(MAPHASH_LEN)
            .map(|chunk| {
                let mut hash = [0u8; MAPHASH_LEN];
                hash.copy_from_slice(chunk);
                hash
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashmap_max_len() {
        // 415 is a typical link MDU on LoRa.
        let max = hashmap_max_len(415);
        assert_eq!(max, (415 - 134) / 4);
        assert_eq!(max, 70);
    }

    #[test]
    fn test_default_link_mdu_matches_python_hashmap_capacity() {
        assert_eq!(rns_wire::constants::LINK_MDU, 431);
        assert_eq!(hashmap_max_len(rns_wire::constants::LINK_MDU), 74);
    }

    #[test]
    fn test_advertisement_creation() {
        let hashes: Vec<[u8; 4]> = (0..100).map(|i| [i as u8; 4]).collect();
        let adv = ResourceAdvertisement::new(
            1000,
            800,
            3,
            [0xAA; 32],
            vec![0xBB; 4],
            ResourceFlags::default(),
            &hashes,
            415,
        );

        let extracted = adv.get_map_hashes();
        // Construction must truncate to whatever fits in the MDU.
        assert_eq!(extracted.len(), 70);
        assert_eq!(extracted[0], [0; 4]);
    }

    #[test]
    fn test_collision_guard() {
        let guard = collision_guard_size(415);
        assert_eq!(guard, 2 * 75 + 70);
        assert_eq!(guard, 220);
    }

    #[test]
    fn test_advertisement_with_metadata() {
        let hashes: Vec<[u8; 4]> = (0..10).map(|i| [i as u8; 4]).collect();
        let flags = ResourceFlags {
            has_metadata: true,
            ..Default::default()
        };
        let adv = ResourceAdvertisement::with_metadata_size(
            1000,
            800,
            3,
            [0xAA; 32],
            vec![0xBB; 4],
            flags,
            &hashes,
            415,
            42,
        );

        assert!(adv.flags.has_metadata);
        assert_eq!(adv.metadata_size, 42);
    }

    #[test]
    fn test_advertisement_default_no_metadata() {
        let hashes: Vec<[u8; 4]> = (0..5).map(|i| [i as u8; 4]).collect();
        let adv = ResourceAdvertisement::new(
            500,
            400,
            2,
            [0xCC; 32],
            vec![0xDD; 4],
            ResourceFlags::default(),
            &hashes,
            415,
        );

        assert!(!adv.flags.has_metadata);
        assert_eq!(adv.metadata_size, 0);
    }

    use proptest::prelude::*;

    proptest! {
        /// ResourceAdvertisement msgpack round-trip. The existing tests
        /// check construction / field-level behavior but not the pack →
        /// unpack cycle. This samples the whole-struct space and locks
        /// in: all top-level fields survive the msgpack round-trip,
        /// including the optional `request_id` variants (Nil vs Binary).
        #[test]
        fn proptest_resource_adv_pack_unpack_roundtrip(
            transfer_size in 0usize..=10_000_000,
            data_size in 0usize..=10_000_000,
            num_parts in 0usize..=10_000,
            resource_hash: [u8; 32],
            // random_hash is a fixed-size RANDOM_HASH_SIZE (4 bytes) field.
            random_hash_bytes: [u8; crate::resource::RANDOM_HASH_SIZE],
            segment_index in 1usize..=256,
            total_segments in 1usize..=256,
            request_id in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..=32)),
            flags_byte: u8,
            hashmap in proptest::collection::vec(any::<u8>(), 0..=256),
        ) {
            let mut adv = ResourceAdvertisement {
                transfer_size,
                data_size,
                num_parts,
                resource_hash,
                random_hash: random_hash_bytes.to_vec(),
                original_hash: resource_hash,
                segment_index,
                total_segments,
                request_id: request_id.clone(),
                flags: ResourceFlags::from_byte(flags_byte),
                hashmap: hashmap.clone(),
                // metadata_size is NOT on the wire — set to 0 before
                // packing so the round-trip comparison is meaningful.
                metadata_size: 0,
            };
            // Trim hashmap to multiples of MAPHASH_LEN so the reader's
            // chunked parse doesn't drop a stray trailing byte.
            let usable = (adv.hashmap.len() / MAPHASH_LEN) * MAPHASH_LEN;
            adv.hashmap.truncate(usable);

            let packed = adv.pack();
            let unpacked = ResourceAdvertisement::unpack(&packed).unwrap();

            prop_assert_eq!(unpacked.transfer_size, adv.transfer_size);
            prop_assert_eq!(unpacked.data_size, adv.data_size);
            prop_assert_eq!(unpacked.num_parts, adv.num_parts);
            prop_assert_eq!(unpacked.resource_hash, adv.resource_hash);
            prop_assert_eq!(unpacked.random_hash.as_slice(), &random_hash_bytes[..]);
            prop_assert_eq!(unpacked.original_hash, adv.original_hash);
            prop_assert_eq!(unpacked.segment_index, adv.segment_index);
            prop_assert_eq!(unpacked.total_segments, adv.total_segments);
            prop_assert_eq!(&unpacked.request_id, &adv.request_id);
            prop_assert_eq!(unpacked.flags.to_byte(), adv.flags.to_byte());
            prop_assert_eq!(&unpacked.hashmap, &adv.hashmap);
        }
    }
}
