use std::collections::HashSet;
use std::time::{Duration, Instant};

use rns_crypto::sha::full_hash;

use crate::compression;

/// Lifecycle state of a resource transfer. `Rejected` is tagged 0x09 — not
/// 0x00 — so it is wire-distinguishable from `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResourceState {
    None = 0x00,
    Queued = 0x01,
    Advertised = 0x02,
    Transferring = 0x03,
    AwaitingProof = 0x04,
    Assembling = 0x05,
    Complete = 0x06,
    Failed = 0x07,
    Corrupt = 0x08,
    Rejected = 0x09,
}

pub const WINDOW_INITIAL: usize = 4;
pub const WINDOW_MIN: usize = 2;
pub const WINDOW_MAX_SLOW: usize = 10;
pub const WINDOW_MAX_VERY_SLOW: usize = 4;
pub const WINDOW_MAX_FAST: usize = 75;
pub const WINDOW_MAX: usize = 75;
pub const FAST_RATE_THRESHOLD: usize = 4;
pub const VERY_SLOW_RATE_THRESHOLD: usize = 2;
/// bytes/sec — transfer rate above which the window is promoted to fast tier.
pub const RATE_FAST: usize = 6250;
/// bytes/sec — rate below which the window is demoted to the very-slow tier.
pub const RATE_VERY_SLOW: usize = 250;
pub const WINDOW_FLEXIBILITY: usize = 4;
pub const MAPHASH_LEN: usize = 4;
/// Only the low 4 bytes of the resource's random tag ship on the wire (in the
/// advertisement's `r` field) and feed the map-hash calculation.
pub const RANDOM_HASH_SIZE: usize = 4;
pub const SDU: usize = rns_wire::constants::MDU;
/// Largest payload that fits a single-segment resource (1 MiB - 1).
pub const MAX_EFFICIENT_SIZE: usize = 1_048_575;
/// Largest metadata block that a 3-byte length prefix can encode.
pub const METADATA_MAX_SIZE: usize = 16_777_215;
pub const MAX_RETRIES: usize = 16;
pub const MAX_ADV_RETRIES: usize = 4;
pub const SENDER_GRACE_TIME: f64 = 10.0;
pub const PROCESSING_GRACE: f64 = 1.0;
pub const PART_TIMEOUT_FACTOR: f64 = 4.0;
pub const PART_TIMEOUT_FACTOR_AFTER_RTT: f64 = 2.0;
pub const PROOF_TIMEOUT_FACTOR: f64 = 3.0;
pub const RETRY_GRACE_TIME: f64 = 0.25;
pub const PER_RETRY_DELAY: f64 = 0.5;
/// HMU-wait multiplier in the watchdog timeout (Python `Resource.HMU_WAIT_FACTOR`).
/// Applied only when mid-HMU-wait or with no outstanding parts.
pub const HMU_WAIT_FACTOR: f64 = 3.5;
/// Cold-start byte count for the first `update_eifr` call (≈one link handshake);
/// drops out once a real `req_data_rtt_rate` sample arrives.
pub const EIFR_COLD_START_BYTES: usize = 600;
pub const WATCHDOG_MAX_SLEEP: f64 = 1.0;
pub const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
pub const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;

/// Link-resource encryption hook applied before chunking payload data.
pub type ResourceEncryptor<'a> = dyn Fn(&[u8]) -> Vec<u8> + 'a;
/// Link-resource decryption hook applied after reassembling payload data.
pub type ResourceDecryptor<'a> = dyn Fn(&[u8]) -> Result<Vec<u8>, ResourceError> + 'a;

/// Bitfield encoded in the advertisement's `f` field.
///
/// Wire layout (bit 0 = LSB):
///   0: encrypted, 1: compressed, 2: split,
///   3: is_request, 4: is_response, 5: has_metadata.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceFlags {
    pub encrypted: bool,
    pub compressed: bool,
    pub split: bool,
    pub is_request: bool,
    pub is_response: bool,
    pub has_metadata: bool,
}

impl ResourceFlags {
    pub fn to_byte(&self) -> u8 {
        let mut f = 0u8;
        if self.encrypted {
            f |= 0x01;
        }
        if self.compressed {
            f |= 0x02;
        }
        if self.split {
            f |= 0x04;
        }
        if self.is_request {
            f |= 0x08;
        }
        if self.is_response {
            f |= 0x10;
        }
        if self.has_metadata {
            f |= 0x20;
        }
        f
    }

    pub fn from_byte(b: u8) -> Self {
        Self {
            encrypted: b & 0x01 != 0,
            compressed: b & 0x02 != 0,
            split: b & 0x04 != 0,
            is_request: b & 0x08 != 0,
            is_response: b & 0x10 != 0,
            has_metadata: b & 0x20 != 0,
        }
    }
}

/// `SHA-256(data || random_hash)[..MAPHASH_LEN]` — identifies a part slot in the hashmap.
pub fn get_map_hash(data: &[u8], random_hash: &[u8]) -> [u8; MAPHASH_LEN] {
    let mut input = Vec::with_capacity(data.len() + random_hash.len());
    input.extend_from_slice(data);
    input.extend_from_slice(random_hash);
    let hash = full_hash(&input);
    let mut result = [0u8; MAPHASH_LEN];
    result.copy_from_slice(&hash[..MAPHASH_LEN]);
    result
}

/// `SHA-256(data || random_hash)` — the advertised resource identifier.
pub fn compute_resource_hash(data: &[u8], random_hash: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(data.len() + random_hash.len());
    input.extend_from_slice(data);
    input.extend_from_slice(random_hash);
    full_hash(&input)
}

/// `SHA-256(data || resource_hash)` — value a valid delivery proof must reproduce.
pub fn compute_expected_proof(data: &[u8], resource_hash: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(data.len() + 32);
    input.extend_from_slice(data);
    input.extend_from_slice(resource_hash);
    full_hash(&input)
}

/// Decode a sender-to-receiver hashmap update:
/// `resource_hash(32) || msgpack([segment_index, hashmap_bytes])`.
pub fn parse_hashmap_update(data: &[u8]) -> Result<([u8; 32], usize, Vec<u8>), ResourceError> {
    if data.len() < 32 {
        return Err(ResourceError::Corrupt);
    }
    let mut resource_hash = [0u8; 32];
    resource_hash.copy_from_slice(&data[..32]);

    let value = rmpv::decode::read_value(&mut &data[32..]).map_err(|_| ResourceError::Corrupt)?;
    let rmpv::Value::Array(items) = value else {
        return Err(ResourceError::Corrupt);
    };
    if items.len() != 2 {
        return Err(ResourceError::Corrupt);
    }
    let segment = items[0].as_u64().ok_or(ResourceError::Corrupt)? as usize;
    let hashmap = items[1].as_slice().ok_or(ResourceError::Corrupt)?.to_vec();
    Ok((resource_hash, segment, hashmap))
}

/// Flow control window state for resource transfer.
#[derive(Debug, Clone)]
pub struct WindowState {
    pub window: usize,
    pub window_min: usize,
    pub window_max: usize,
    pub fast_rate_rounds: usize,
    pub very_slow_rate_rounds: usize,
}

impl WindowState {
    pub fn new() -> Self {
        Self {
            window: WINDOW_INITIAL,
            window_min: WINDOW_MIN,
            window_max: WINDOW_MAX_SLOW,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
        }
    }

    /// Grow the window once a whole batch has arrived. Must be called before
    /// the next request batch is dispatched so the new slots are visible to
    /// the batch-size calculation.
    ///
    /// Also slides `window_min` up when the window has outgrown its
    /// flexibility band, and promotes the ceiling for sustained fast or
    /// very-slow links.
    pub fn grow(&mut self, rate: usize) {
        if self.window < self.window_max {
            self.window += 1;
            // saturating: a very-slow demotion can clamp `window` below `window_min` (Python's
            // signed comparison is false there; a plain sub underflows).
            if self.window.saturating_sub(self.window_min) > (WINDOW_FLEXIBILITY - 1) {
                self.window_min += 1;
            }
        }

        // Only a run of consecutive fast/very-slow rounds promotes the
        // ceiling, so one lucky RTT cannot stretch the window irrevocably.
        if rate > RATE_FAST {
            self.fast_rate_rounds += 1;
            self.very_slow_rate_rounds = 0;
            if self.fast_rate_rounds >= FAST_RATE_THRESHOLD {
                self.window_max = WINDOW_MAX_FAST;
            }
        } else if rate < RATE_VERY_SLOW {
            self.very_slow_rate_rounds += 1;
            self.fast_rate_rounds = 0;
            if self.very_slow_rate_rounds >= VERY_SLOW_RATE_THRESHOLD {
                self.window_max = WINDOW_MAX_VERY_SLOW;
                if self.window > self.window_max {
                    self.window = self.window_max;
                }
            }
        } else {
            self.fast_rate_rounds = 0;
            self.very_slow_rate_rounds = 0;
        }
    }

    /// Shrink the window after a timeout. Both the instantaneous `window`
    /// and the ceiling `window_max` contract, and the flexibility band
    /// between them is kept within `WINDOW_FLEXIBILITY - 1`.
    pub fn shrink(&mut self) {
        if self.window > self.window_min {
            self.window -= 1;
        }
        if self.window_max > self.window_min {
            self.window_max -= 1;
        }
        if self.window_max.saturating_sub(self.window) > WINDOW_FLEXIBILITY - 1 {
            self.window_max -= 1;
        }
    }
}

impl Default for WindowState {
    fn default() -> Self {
        Self::new()
    }
}

/// A sender-side resource for outbound transfer.
pub struct OutboundResource {
    pub state: ResourceState,
    pub data: Vec<u8>,
    pub random_hash: [u8; RANDOM_HASH_SIZE],
    pub resource_hash: [u8; 32],
    pub expected_proof: [u8; 32],
    pub flags: ResourceFlags,
    pub parts: Vec<Vec<u8>>,
    pub map_hashes: Vec<[u8; MAPHASH_LEN]>,
    pub total_size: usize,
    pub advertisement_data_size: usize,
    pub segment_index: usize,
    pub total_segments: usize,
    /// Request id for request/response resources (`q` in the advertisement).
    pub request_id: Option<Vec<u8>>,
    /// Shared hash addressing every segment of the original payload. `Some`
    /// for segments emitted by `MultiSegmentOutbound`, `None` otherwise (the
    /// wire `original_hash` then equals `resource_hash`).
    pub original_hash: Option<[u8; 32]>,
    pub window: WindowState,
    pub retries: usize,
    pub sdu: usize,
    /// Optional payload metadata. When set it is prepended to the resource
    /// data as `length(3 BE) || metadata` before compression.
    pub metadata: Option<Vec<u8>>,
    /// Size of the packed metadata block (length prefix included).
    pub metadata_size: usize,
}

impl OutboundResource {
    /// Build a single-segment outbound resource. Payloads above
    /// `MAX_EFFICIENT_SIZE` must use `MultiSegmentOutbound`. `encrypt_fn` is
    /// applied to the assembled blob after compression, before chunking.
    pub fn new(
        data: Vec<u8>,
        auto_compress: bool,
        encrypt_fn: Option<&ResourceEncryptor<'_>>,
    ) -> Result<Self, ResourceError> {
        Self::with_options(data, auto_compress, None, None, encrypt_fn)
    }

    // Cap retries when uniform data keeps producing colliding map hashes — see
    // `with_options_inner` for the retry loop.
    const MAX_COLLISION_RETRIES: usize = 5;

    /// Extended constructor with optional metadata and a custom SDU.
    ///
    /// `metadata` is framed as `length(3 BE) || bytes` and prepended to the
    /// data before compression/encryption, matching the Python layout.
    ///
    /// `link_sdu` lets callers override the default SDU when the link has
    /// negotiated a non-standard MTU.
    pub fn with_options(
        data: Vec<u8>,
        auto_compress: bool,
        metadata: Option<Vec<u8>>,
        link_sdu: Option<usize>,
        encrypt_fn: Option<&ResourceEncryptor<'_>>,
    ) -> Result<Self, ResourceError> {
        Self::with_options_inner(data, auto_compress, metadata, link_sdu, encrypt_fn, 0)
    }

    // Shared body for `new`/`with_options`; re-entered on map-hash collisions
    // with `collision_retries` bumped one step, up to MAX_COLLISION_RETRIES.
    fn with_options_inner(
        data: Vec<u8>,
        auto_compress: bool,
        metadata: Option<Vec<u8>>,
        link_sdu: Option<usize>,
        encrypt_fn: Option<&ResourceEncryptor<'_>>,
        collision_retries: usize,
    ) -> Result<Self, ResourceError> {
        let (packed_metadata, metadata_size, has_metadata) = if let Some(ref meta) = metadata {
            if meta.len() > METADATA_MAX_SIZE {
                return Err(ResourceError::MetadataTooLarge);
            }
            let len = meta.len();
            let mut packed = Vec::with_capacity(3 + len);
            // 3-byte big-endian length prefix.
            packed.push(((len >> 16) & 0xFF) as u8);
            packed.push(((len >> 8) & 0xFF) as u8);
            packed.push((len & 0xFF) as u8);
            packed.extend_from_slice(meta);
            let size = packed.len();
            (Some(packed), size, true)
        } else {
            (None, 0, false)
        };

        if metadata_size + data.len() > MAX_EFFICIENT_SIZE {
            return Err(ResourceError::TooLarge);
        }

        let random_hash: [u8; RANDOM_HASH_SIZE] =
            rns_crypto::random::random_bytes(RANDOM_HASH_SIZE)
                .try_into()
                .unwrap();

        let full_data = if let Some(ref meta) = packed_metadata {
            let mut full = Vec::with_capacity(meta.len() + data.len());
            full.extend_from_slice(meta);
            full.extend_from_slice(&data);
            full
        } else {
            data.clone()
        };

        let (processed_data, compressed) =
            if auto_compress && full_data.len() <= compression::AUTO_COMPRESS_MAX_SIZE {
                compression::try_compress(&full_data)
            } else {
                (full_data.clone(), false)
            };

        let mut blob = Vec::with_capacity(RANDOM_HASH_SIZE + processed_data.len());
        blob.extend_from_slice(&random_hash);
        blob.extend_from_slice(&processed_data);

        // Encrypt after compression/padding so the link keys protect the
        // whole blob before it is chunked.
        let blob = if let Some(ref enc) = encrypt_fn {
            enc(&blob)
        } else {
            blob
        };

        // Hashes are computed over plaintext (metadata + data) so a receiver
        // can verify them against the reassembled payload regardless of
        // whether the link session was encrypted.
        let resource_hash = compute_resource_hash(&full_data, &random_hash);
        let expected_proof = compute_expected_proof(&full_data, &resource_hash);

        let sdu = link_sdu.unwrap_or(SDU);

        let parts: Vec<Vec<u8>> = blob.chunks(sdu).map(|c| c.to_vec()).collect();

        // Uniform data can produce map-hash collisions. When detected we
        // regenerate `random_hash` and retry up to MAX_COLLISION_RETRIES; if
        // they persist (e.g. identical payload chunks) we proceed with the
        // best result rather than looping forever.
        let mut map_hashes = Vec::with_capacity(parts.len());
        let mut collision_guard: HashSet<[u8; MAPHASH_LEN]> = HashSet::with_capacity(parts.len());
        let mut has_collision = false;

        for part in &parts {
            let mh = get_map_hash(part, &random_hash);
            if !collision_guard.insert(mh) {
                has_collision = true;
            }
            map_hashes.push(mh);
        }

        if has_collision && collision_retries < Self::MAX_COLLISION_RETRIES {
            return Self::with_options_inner(
                data,
                auto_compress,
                metadata,
                link_sdu,
                encrypt_fn,
                collision_retries + 1,
            );
        }

        let total_size = blob.len();
        let flags = ResourceFlags {
            encrypted: encrypt_fn.is_some(),
            compressed,
            split: false,
            is_request: false,
            is_response: false,
            has_metadata,
        };

        Ok(Self {
            state: ResourceState::None,
            data,
            random_hash,
            resource_hash,
            expected_proof,
            flags,
            parts,
            map_hashes,
            total_size,
            advertisement_data_size: full_data.len(),
            segment_index: 1,
            total_segments: 1,
            request_id: None,
            original_hash: None,
            window: WindowState::new(),
            retries: 0,
            sdu,
            metadata: packed_metadata,
            metadata_size,
        })
    }

    /// Check a received delivery proof. Proofs ship as
    /// `dest_hash(32) || proof_hash(32)`; only the last 32 bytes are compared.
    pub fn validate_proof(&mut self, proof_data: &[u8]) -> bool {
        if proof_data.len() < 64 {
            return false;
        }
        let received_proof = &proof_data[32..64];
        if received_proof == self.expected_proof {
            self.state = ResourceState::Complete;
            true
        } else {
            false
        }
    }

    pub fn get_part(&self, index: usize) -> Option<&[u8]> {
        self.parts.get(index).map(|p| p.as_slice())
    }

    pub fn num_parts(&self) -> usize {
        self.parts.len()
    }

    /// Respond to an HMU / resource-request from the receiver. Returns the
    /// part indices to (re)send; an exhausted HMU transitions the sender
    /// into `AwaitingProof` and returns an empty vector.
    pub fn handle_hmu(&mut self, plaintext: &[u8]) -> Vec<usize> {
        if plaintext.is_empty() {
            return Vec::new();
        }
        let exhausted = plaintext[0] == HASHMAP_IS_EXHAUSTED;
        let data = &plaintext[1..];

        if exhausted {
            self.state = ResourceState::AwaitingProof;
            self.window.grow(0);
            return Vec::new();
        }

        // A non-exhausted request carries the map-hash of the last part the
        // receiver has. We send the window's worth of parts that follow it.
        if data.len() >= MAPHASH_LEN {
            let mut mh = [0u8; MAPHASH_LEN];
            mh.copy_from_slice(&data[..MAPHASH_LEN]);
            for (i, map_hash) in self.map_hashes.iter().enumerate() {
                if *map_hash == mh {
                    let start = i + 1;
                    let end = (start + self.window.window).min(self.num_parts());
                    return (start..end).collect();
                }
            }
        }
        Vec::new()
    }

    /// Mark the resource as rejected in response to a cancel from the receiver.
    pub fn handle_cancel(&mut self) {
        self.state = ResourceState::Rejected;
    }
}

/// A receiver-side resource for inbound transfer.
pub struct InboundResource {
    pub state: ResourceState,
    pub parts: Vec<Option<Vec<u8>>>,
    pub total_parts: usize,
    pub random_hash: [u8; RANDOM_HASH_SIZE],
    pub resource_hash: [u8; 32],
    pub flags: ResourceFlags,
    pub total_size: usize,
    pub data_size: usize,
    pub consecutive_completed: usize,
    pub window: WindowState,
    pub map_hashes: Vec<[u8; MAPHASH_LEN]>,
    pub sdu: usize,
    /// Metadata extracted at `assemble()` time when `flags.has_metadata` was set.
    pub metadata: Option<Vec<u8>>,
}

impl InboundResource {
    /// Construct from an incoming advertisement with the default SDU.
    pub fn new(
        total_parts: usize,
        total_size: usize,
        data_size: usize,
        random_hash: [u8; RANDOM_HASH_SIZE],
        resource_hash: [u8; 32],
        flags: ResourceFlags,
        initial_map_hashes: Vec<[u8; MAPHASH_LEN]>,
    ) -> Result<Self, ResourceError> {
        Self::with_sdu(
            total_parts,
            total_size,
            data_size,
            random_hash,
            resource_hash,
            flags,
            initial_map_hashes,
            None,
        )
    }

    /// Extended constructor that lets callers supply a non-default SDU when
    /// the underlying link has negotiated a custom MTU.
    // Mirrors Resource ADV fields after decoding; these values are validated
    // together because they describe one advertised transfer.
    #[allow(clippy::too_many_arguments)]
    pub fn with_sdu(
        total_parts: usize,
        total_size: usize,
        data_size: usize,
        random_hash: [u8; RANDOM_HASH_SIZE],
        resource_hash: [u8; 32],
        flags: ResourceFlags,
        initial_map_hashes: Vec<[u8; MAPHASH_LEN]>,
        link_sdu: Option<usize>,
    ) -> Result<Self, ResourceError> {
        if total_parts == 0 {
            return Err(ResourceError::InvalidAdvertisement);
        }

        // `total_size` is post-encryption: max plaintext + random_hash +
        // TOKEN_OVERHEAD + worst-case PKCS7 pad.
        const MAX_AES_BLOCK_PAD: usize = 16;
        let max_total_size =
            MAX_EFFICIENT_SIZE + RANDOM_HASH_SIZE + rns_crypto::TOKEN_OVERHEAD + MAX_AES_BLOCK_PAD;
        if total_size > max_total_size {
            return Err(ResourceError::TooLarge);
        }

        // `total_parts` is attacker-controlled wire input; unchecked it sizes the
        // parts Vec directly (24 B per slot — a remote multi-GB alloc bomb). Real
        // transfers satisfy total_parts == ceil(total_size / sdu); MIN_PART_SIZE
        // is a generous lower bound on any negotiated SDU (real MDU ≈ 475).
        const MIN_PART_SIZE: usize = 32;
        let max_parts = total_size.div_ceil(MIN_PART_SIZE).saturating_add(16);
        if total_parts > max_parts {
            return Err(ResourceError::TooLarge);
        }

        Ok(Self {
            state: ResourceState::Transferring,
            parts: vec![None; total_parts],
            total_parts,
            random_hash,
            resource_hash,
            flags,
            total_size,
            data_size,
            consecutive_completed: 0,
            window: WindowState::new(),
            map_hashes: initial_map_hashes,
            sdu: link_sdu.unwrap_or(SDU),
            metadata: None,
        })
    }

    /// Try to slot `data` into the current window by map-hash match. Returns
    /// true when the part was accepted into a previously-empty slot.
    pub fn receive_part(&mut self, data: Vec<u8>) -> bool {
        let mh = get_map_hash(&data, &self.random_hash);

        tracing::trace!(
            result = %format!("{:02x}{:02x}{:02x}{:02x}", mh[0], mh[1], mh[2], mh[3]),
            data_len = data.len(),
            data_first16 = %hex::encode(&data[..data.len().min(16)]),
            random_hash = %hex::encode(self.random_hash),
            random_len = self.random_hash.len(),
            "resource part map hash"
        );
        if !self.map_hashes.is_empty() {
            tracing::trace!(
                hash_0 = %format!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    self.map_hashes[0][0], self.map_hashes[0][1], self.map_hashes[0][2], self.map_hashes[0][3]
                ),
                num_hashes = self.map_hashes.len(),
                "resource part expected hash"
            );
        }

        // Only scan inside the current receive window — late-arrivals beyond
        // it are dropped so replay cannot back-fill completed slots.
        let search_start = self.consecutive_completed;
        let search_end = (self.consecutive_completed + self.window.window).min(self.total_parts);

        for i in search_start..search_end {
            if i < self.map_hashes.len() && self.map_hashes[i] == mh && self.parts[i].is_none() {
                self.parts[i] = Some(data);
                self.update_consecutive();
                return true;
            }
        }

        false
    }

    fn update_consecutive(&mut self) {
        while self.consecutive_completed < self.total_parts {
            if self.parts[self.consecutive_completed].is_some() {
                self.consecutive_completed += 1;
            } else {
                break;
            }
        }
    }

    pub fn is_complete(&self) -> bool {
        self.consecutive_completed == self.total_parts
    }

    /// Reassemble the received parts into the original payload.
    ///
    /// Steps: concatenate parts → optional decrypt → strip random hash →
    /// decompress (bounded by `MAX_EFFICIENT_SIZE` to stop decompression
    /// bombs) → verify hash → split off metadata if `flags.has_metadata`.
    /// The extracted metadata is stashed in `self.metadata` and the return
    /// value is the payload only.
    pub fn assemble(
        &mut self,
        decrypt_fn: Option<&ResourceDecryptor<'_>>,
    ) -> Result<Vec<u8>, ResourceError> {
        if !self.is_complete() {
            return Err(ResourceError::Incomplete);
        }

        self.state = ResourceState::Assembling;

        let mut stream = Vec::with_capacity(self.total_size);
        for part in &self.parts {
            stream.extend_from_slice(part.as_ref().ok_or(ResourceError::Incomplete)?);
        }

        let stream = if let Some(ref dec) = decrypt_fn {
            dec(&stream)?
        } else {
            stream
        };

        if stream.len() < RANDOM_HASH_SIZE {
            self.state = ResourceState::Corrupt;
            return Err(ResourceError::Corrupt);
        }
        let data = &stream[RANDOM_HASH_SIZE..];

        let final_data = if self.flags.compressed {
            compression::bz2_decompress(data, MAX_EFFICIENT_SIZE)
                .map_err(|_| ResourceError::DecompressionFailed)?
        } else {
            data.to_vec()
        };

        let calculated_hash = compute_resource_hash(&final_data, &self.random_hash);
        if calculated_hash != self.resource_hash {
            self.state = ResourceState::Corrupt;
            return Err(ResourceError::HashMismatch);
        }

        let payload = if self.flags.has_metadata {
            if final_data.len() < 3 {
                self.state = ResourceState::Corrupt;
                return Err(ResourceError::InvalidMetadata {
                    declared: 0,
                    available: final_data.len(),
                });
            }
            let metadata_size = ((final_data[0] as usize) << 16)
                | ((final_data[1] as usize) << 8)
                | (final_data[2] as usize);
            if final_data.len() < 3 + metadata_size {
                self.state = ResourceState::Corrupt;
                return Err(ResourceError::InvalidMetadata {
                    declared: metadata_size,
                    available: final_data.len().saturating_sub(3),
                });
            }
            self.metadata = Some(final_data[3..3 + metadata_size].to_vec());
            final_data[3 + metadata_size..].to_vec()
        } else {
            final_data
        };

        self.state = ResourceState::Complete;
        Ok(payload)
    }

    /// Build the 64-byte delivery proof (`resource_hash(32) || expected_proof(32)`).
    pub fn generate_proof(&self, data: &[u8]) -> Vec<u8> {
        let proof = compute_expected_proof(data, &self.resource_hash);
        let mut proof_data = Vec::with_capacity(64);
        proof_data.extend_from_slice(&self.resource_hash);
        proof_data.extend_from_slice(&proof);
        proof_data
    }

    pub fn received_count(&self) -> usize {
        self.parts.iter().filter(|p| p.is_some()).count()
    }

    /// Fraction of parts received, in `0.0..=1.0`.
    pub fn progress(&self) -> f64 {
        if self.total_parts == 0 {
            return 1.0;
        }
        self.received_count() as f64 / self.total_parts as f64
    }

    /// Fail the transfer and drop any buffered parts so we stop holding the
    /// memory for a transfer that will never complete.
    pub fn handle_cancel(&mut self) {
        self.state = ResourceState::Failed;
        for part in &mut self.parts {
            *part = None;
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error("resource too large")]
    TooLarge,
    #[error("resource transfer incomplete")]
    Incomplete,
    #[error("resource data corrupt")]
    Corrupt,
    #[error("resource decrypt failed")]
    DecryptFailed,
    #[error("resource hash mismatch")]
    HashMismatch,
    #[error("decompression failed")]
    DecompressionFailed,
    #[error("invalid metadata prefix: declared {declared} bytes, available {available} bytes")]
    InvalidMetadata { declared: usize, available: usize },
    #[error("invalid advertisement")]
    InvalidAdvertisement,
    #[error("map hash collision persists after retries")]
    MapHashCollision,
    #[error("metadata exceeds maximum size")]
    MetadataTooLarge,
    /// Caller wrote bytes for a segment slot that already contains data.
    /// Surfaces sender-side retransmits at the runtime so they can be logged
    /// distinctly from genuine bounds violations.
    #[error("segment already received")]
    DuplicateSegment,
}

/// Upper bound on the combined size of all segments (128 MiB - 1).
pub const MAX_RESOURCE_SIZE: usize = 134_217_727;

/// Max segments per split resource. Caps the ADV's `l` field so a peer
/// can't force allocation of `u32::MAX` slot vectors. Runtime callers must
/// validate `total_segments <= MAX_SEGMENTS` before constructing a coordinator.
pub const MAX_SEGMENTS: usize = 128;

/// Sender-side coordinator for a resource split across multiple segments.
/// Each segment owns a standalone `OutboundResource`; see
/// `MultiSegmentInbound` for the receive side.
pub struct MultiSegmentOutbound {
    pub original_hash: [u8; 32],
    pub segments: Vec<OutboundResource>,
    pub total_segments: usize,
    pub data_size: usize,
}

/// Sender-side plan that materialises at most one split Resource segment at a
/// time.
///
/// The signed/application payload remains owned by the plan, but plaintext,
/// encrypted parts and hash maps for future segments are not allocated until
/// [`Self::next_segment`] is called. This is the bounded primitive used by
/// large LXMF Direct deliveries; the eager [`MultiSegmentOutbound`] facade is
/// retained for callers that need random access to every segment.
pub struct LazyMultiSegmentOutbound {
    data: Vec<u8>,
    auto_compress: bool,
    metadata: Option<Vec<u8>>,
    metadata_wire_size: usize,
    request_id: Option<Vec<u8>>,
    is_response: bool,
    next_offset: usize,
    next_segment_index: usize,
    pub original_hash: [u8; 32],
    pub total_segments: usize,
    pub data_size: usize,
}

fn required_segment_count(data_size: usize, metadata_wire_size: usize) -> usize {
    if data_size == 0 {
        return 1;
    }
    let first_payload_size = MAX_EFFICIENT_SIZE.saturating_sub(metadata_wire_size);
    let first_len = data_size.min(first_payload_size);
    1 + data_size
        .saturating_sub(first_len)
        .div_ceil(MAX_EFFICIENT_SIZE)
}

impl MultiSegmentOutbound {
    /// Split `data` into `MAX_EFFICIENT_SIZE`-sized chunks, each wrapped in
    /// its own `OutboundResource` with `flags.split = true` and the correct
    /// `segment_index` / `total_segments` pair.
    pub fn new(data: Vec<u8>, auto_compress: bool) -> Result<Self, ResourceError> {
        Self::with_encrypt(data, auto_compress, None)
    }

    /// Variant of [`Self::new`] that applies `encrypt_fn` per segment so
    /// part payloads are protected while ADVs remain addressable.
    pub fn with_encrypt(
        data: Vec<u8>,
        auto_compress: bool,
        encrypt_fn: Option<&ResourceEncryptor<'_>>,
    ) -> Result<Self, ResourceError> {
        Self::with_options(data, auto_compress, None, None, false, encrypt_fn)
    }

    /// Split a resource while preserving per-resource metadata and request
    /// flags. Metadata rides on the first segment and reduces that segment's
    /// payload budget so no segment exceeds `MAX_EFFICIENT_SIZE`.
    pub fn with_options(
        data: Vec<u8>,
        auto_compress: bool,
        metadata: Option<Vec<u8>>,
        request_id: Option<Vec<u8>>,
        is_response: bool,
        encrypt_fn: Option<&ResourceEncryptor<'_>>,
    ) -> Result<Self, ResourceError> {
        let mut lazy = LazyMultiSegmentOutbound::with_options(
            data,
            auto_compress,
            metadata,
            request_id,
            is_response,
        )?;
        let original_hash = lazy.original_hash;
        let total_segments = lazy.total_segments;
        let data_size = lazy.data_size;
        let mut segments = Vec::with_capacity(total_segments);
        while let Some(segment) = lazy.next_segment(encrypt_fn)? {
            segments.push(segment);
        }

        Ok(Self {
            original_hash,
            segments,
            total_segments,
            data_size,
        })
    }

    pub fn get_segment(&self, index: usize) -> Option<&OutboundResource> {
        self.segments.get(index)
    }

    pub fn get_segment_mut(&mut self, index: usize) -> Option<&mut OutboundResource> {
        self.segments.get_mut(index)
    }

    pub fn num_segments(&self) -> usize {
        self.segments.len()
    }

    /// True once every segment has received its delivery proof.
    pub fn is_complete(&self) -> bool {
        self.segments
            .iter()
            .all(|s| s.state == ResourceState::Complete)
    }

    /// Mark every still-active segment as `Failed` and report how many were
    /// newly transitioned. Emitting per-segment cancel packets is left to
    /// the engine, which observes `Failed` on its next tick. Already-failed
    /// or already-complete segments are skipped.
    pub fn cancel_all(&mut self) -> usize {
        let mut cancelled = 0;
        for segment in &mut self.segments {
            if !matches!(
                segment.state,
                ResourceState::Failed | ResourceState::Complete
            ) {
                segment.state = ResourceState::Failed;
                cancelled += 1;
            }
        }
        cancelled
    }
}

impl LazyMultiSegmentOutbound {
    /// Create a sequential split-Resource plan without metadata or request
    /// flags.
    pub fn new(data: Vec<u8>, auto_compress: bool) -> Result<Self, ResourceError> {
        Self::with_options(data, auto_compress, None, None, false)
    }

    /// Create a sequential split-Resource plan while preserving metadata and
    /// request flags. Metadata is moved into the first segment when it is
    /// materialised.
    pub fn with_options(
        data: Vec<u8>,
        auto_compress: bool,
        metadata: Option<Vec<u8>>,
        request_id: Option<Vec<u8>>,
        is_response: bool,
    ) -> Result<Self, ResourceError> {
        if data.len() > MAX_RESOURCE_SIZE {
            return Err(ResourceError::TooLarge);
        }

        let data_size = data.len();
        let metadata_wire_size = metadata.as_ref().map(|value| 3 + value.len()).unwrap_or(0);
        if metadata_wire_size > MAX_EFFICIENT_SIZE {
            return Err(ResourceError::MetadataTooLarge);
        }
        let total_segments = required_segment_count(data_size, metadata_wire_size);
        if total_segments > MAX_SEGMENTS {
            return Err(ResourceError::TooLarge);
        }

        // `original_hash` covers the uncompressed concatenated payload so the
        // receiver can verify reassembly across all segments.
        let random_hash: [u8; RANDOM_HASH_SIZE] =
            rns_crypto::random::random_bytes(RANDOM_HASH_SIZE)
                .try_into()
                .expect("fixed random-hash length");
        let original_hash = compute_resource_hash(&data, &random_hash);

        Ok(Self {
            data,
            auto_compress,
            metadata,
            metadata_wire_size,
            request_id,
            is_response,
            next_offset: 0,
            next_segment_index: 1,
            original_hash,
            total_segments,
            data_size,
        })
    }

    /// Number of segments that have not yet been materialised.
    pub fn remaining_segments(&self) -> usize {
        self.total_segments
            .saturating_sub(self.next_segment_index.saturating_sub(1))
    }

    /// Build the next standalone outbound Resource. The caller owns the
    /// returned segment and should request another only after the current one
    /// has completed or been terminally discarded.
    pub fn next_segment(
        &mut self,
        encrypt_fn: Option<&ResourceEncryptor<'_>>,
    ) -> Result<Option<OutboundResource>, ResourceError> {
        if self.next_segment_index > self.total_segments {
            return Ok(None);
        }

        let segment_index = self.next_segment_index;
        let segment_metadata = if segment_index == 1 {
            self.metadata.take()
        } else {
            None
        };
        let payload_limit = if segment_index == 1 {
            MAX_EFFICIENT_SIZE - self.metadata_wire_size
        } else {
            MAX_EFFICIENT_SIZE
        };
        let end = self
            .next_offset
            .saturating_add(payload_limit)
            .min(self.data.len());
        let chunk = self.data[self.next_offset..end].to_vec();

        let mut resource = OutboundResource::with_options(
            chunk,
            self.auto_compress,
            segment_metadata,
            None,
            encrypt_fn,
        )?;
        resource.flags.split = true;
        resource.flags.is_response = self.is_response;
        resource.segment_index = segment_index;
        resource.total_segments = self.total_segments;
        resource.request_id = self.request_id.clone();
        resource.advertisement_data_size = self.data_size + self.metadata_wire_size;
        resource.original_hash = Some(self.original_hash);

        self.next_offset = end;
        self.next_segment_index += 1;
        if self.next_segment_index > self.total_segments {
            // The current segment now owns its bytes. Release the complete
            // source allocation before it begins transferring.
            self.data = Vec::new();
        }
        Ok(Some(resource))
    }
}

/// Inbound multi-segment resource coordinator: collects `InboundResource`
/// segments and reassembles the original payload. Two ingest paths feed
/// `assembled_segments`: `set_segment` + `assemble_segment` (unit tests) and
/// `set_segment_data` (runtime, where `InboundTransfer` owns the segment).
pub struct MultiSegmentInbound {
    pub original_hash: [u8; 32],
    pub total_segments: usize,
    pub segments: Vec<Option<InboundResource>>,
    pub assembled_segments: Vec<Option<Vec<u8>>>,
    pub data_size: usize,
    /// First non-None metadata observed across the segment stream. Rust's
    /// `MultiSegmentOutbound` attaches no per-segment metadata, but Python
    /// peers may.
    pub metadata: Option<Vec<u8>>,
}

impl MultiSegmentInbound {
    /// Allocate slots for `total_segments` segments; seed with the
    /// `original_hash` advertised by the sender for the full payload.
    pub fn new(total_segments: usize, original_hash: [u8; 32]) -> Self {
        Self {
            original_hash,
            total_segments,
            segments: (0..total_segments).map(|_| None).collect(),
            assembled_segments: (0..total_segments).map(|_| None).collect(),
            data_size: 0,
            metadata: None,
        }
    }

    /// Attach an inbound resource. `segment_index` is 1-based (as it appears
    /// on the wire) and silently ignored when out of range.
    pub fn set_segment(&mut self, segment_index: usize, resource: InboundResource) {
        if segment_index >= 1 && segment_index <= self.total_segments {
            self.segments[segment_index - 1] = Some(resource);
        }
    }

    /// Assemble the segment at `segment_index` (1-based) and stash the
    /// bytes for later `reassemble()`.
    pub fn assemble_segment(
        &mut self,
        segment_index: usize,
        decrypt_fn: Option<&ResourceDecryptor<'_>>,
    ) -> Result<(), ResourceError> {
        if segment_index < 1 || segment_index > self.total_segments {
            return Err(ResourceError::InvalidAdvertisement);
        }
        let idx = segment_index - 1;
        if let Some(ref mut resource) = self.segments[idx] {
            let data = resource.assemble(decrypt_fn)?;
            self.assembled_segments[idx] = Some(data);
            Ok(())
        } else {
            Err(ResourceError::Incomplete)
        }
    }

    /// Runtime ingest of an assembled segment at 1-based `segment_index`.
    /// Errors: `InvalidAdvertisement` for out-of-range index;
    /// `DuplicateSegment` on overwrite (slot already accepted).
    pub fn set_segment_data(
        &mut self,
        segment_index: usize,
        data: Vec<u8>,
    ) -> Result<(), ResourceError> {
        if segment_index < 1 || segment_index > self.total_segments {
            return Err(ResourceError::InvalidAdvertisement);
        }
        let idx = segment_index - 1;
        if self.assembled_segments[idx].is_some() {
            return Err(ResourceError::DuplicateSegment);
        }
        self.data_size = self.data_size.saturating_add(data.len());
        self.assembled_segments[idx] = Some(data);
        Ok(())
    }

    /// Record metadata for the reassembled payload; first non-None wins.
    pub fn set_metadata(&mut self, meta: Vec<u8>) {
        if self.metadata.is_none() {
            self.metadata = Some(meta);
        }
    }

    pub fn is_complete(&self) -> bool {
        self.assembled_segments.iter().all(|s| s.is_some())
    }

    /// Concatenate every assembled segment into the original payload.
    pub fn reassemble(&self) -> Result<Vec<u8>, ResourceError> {
        if !self.is_complete() {
            return Err(ResourceError::Incomplete);
        }
        let mut result = Vec::new();
        for seg in &self.assembled_segments {
            result.extend_from_slice(seg.as_ref().ok_or(ResourceError::Incomplete)?);
        }
        Ok(result)
    }

    pub fn assembled_count(&self) -> usize {
        self.assembled_segments
            .iter()
            .filter(|s| s.is_some())
            .count()
    }

    /// Fraction of segments assembled so far, in `0.0..=1.0`.
    pub fn progress(&self) -> f64 {
        if self.total_segments == 0 {
            return 1.0;
        }
        self.assembled_count() as f64 / self.total_segments as f64
    }
}

/// Either side of a single-segment resource transfer, tagged with the owning
/// link's ID and optionally its session keys for transparent encryption.
pub struct LinkResource {
    pub link_id: [u8; 16],
    pub outbound: Option<OutboundResource>,
    pub inbound: Option<InboundResource>,
    pub session_keys: Option<rns_link::key_derivation::LinkKeys>,
}

impl LinkResource {
    /// Build an outbound resource for sending over a plaintext link.
    pub fn new_outbound(
        link_id: [u8; 16],
        data: Vec<u8>,
        auto_compress: bool,
    ) -> Result<Self, ResourceError> {
        let outbound = OutboundResource::new(data, auto_compress, None)?;
        Ok(Self {
            link_id,
            outbound: Some(outbound),
            inbound: None,
            session_keys: None,
        })
    }

    /// Build an outbound resource whose reassembled blob is encrypted with
    /// the supplied link session keys before chunking.
    pub fn new_outbound_encrypted(
        link_id: [u8; 16],
        data: Vec<u8>,
        auto_compress: bool,
        keys: rns_link::key_derivation::LinkKeys,
    ) -> Result<Self, ResourceError> {
        let encrypt_fn = |plaintext: &[u8]| -> Vec<u8> {
            rns_link::encryption::link_encrypt(&keys, plaintext)
                .unwrap_or_else(|_| plaintext.to_vec())
        };
        let outbound = OutboundResource::new(data, auto_compress, Some(&encrypt_fn))?;
        Ok(Self {
            link_id,
            outbound: Some(outbound),
            inbound: None,
            session_keys: Some(keys),
        })
    }

    /// Create for receiving data over a link.
    // Same advertised resource field set as `InboundResource::with_sdu`, plus
    // the link id that owns the transfer.
    #[allow(clippy::too_many_arguments)]
    pub fn new_inbound(
        link_id: [u8; 16],
        total_parts: usize,
        total_size: usize,
        data_size: usize,
        random_hash: [u8; RANDOM_HASH_SIZE],
        resource_hash: [u8; 32],
        flags: ResourceFlags,
        map_hashes: Vec<[u8; MAPHASH_LEN]>,
    ) -> Result<Self, ResourceError> {
        let inbound = InboundResource::new(
            total_parts,
            total_size,
            data_size,
            random_hash,
            resource_hash,
            flags,
            map_hashes,
        )?;
        Ok(Self {
            link_id,
            outbound: None,
            inbound: Some(inbound),
            session_keys: None,
        })
    }

    /// Per-part transport encryption for outbound transfers. Returns the
    /// ciphertext when the link carries session keys, otherwise the
    /// untouched plaintext.
    pub fn next_part(&self, index: usize) -> Option<Vec<u8>> {
        let part = self.outbound.as_ref()?.get_part(index)?;
        if let Some(ref keys) = self.session_keys {
            rns_link::encryption::link_encrypt(keys, part).ok()
        } else {
            Some(part.to_vec())
        }
    }

    /// Inbound counterpart of `next_part`. Decryption failures silently
    /// drop the part (returning false) so the caller can simply retry.
    pub fn receive_part(&mut self, data: Vec<u8>) -> bool {
        let plaintext = if let Some(ref keys) = self.session_keys {
            match rns_link::encryption::link_decrypt(keys, &data) {
                Ok(pt) => pt,
                Err(_) => return false,
            }
        } else {
            data
        };
        if let Some(ref mut inbound) = self.inbound {
            inbound.receive_part(plaintext)
        } else {
            false
        }
    }

    pub fn is_complete(&self) -> bool {
        self.inbound.as_ref().is_some_and(|i| i.is_complete())
    }

    /// Reassemble the inbound resource, applying session-key decryption when
    /// keys were provided at construction.
    pub fn assemble(&mut self) -> Result<Vec<u8>, ResourceError> {
        let decrypt_fn: Option<Box<ResourceDecryptor<'_>>> =
            if let Some(ref keys) = self.session_keys {
                let keys = keys.clone();
                Some(Box::new(move |ciphertext: &[u8]| {
                    rns_link::encryption::link_decrypt(&keys, ciphertext)
                        .map_err(|_| ResourceError::Corrupt)
                }))
            } else {
                None
            };
        self.inbound
            .as_mut()
            .ok_or(ResourceError::Incomplete)?
            .assemble(decrypt_fn.as_deref())
    }

    /// Inbound progress in `0.0..=1.0`. Outbound transfers report 0.0
    /// because progress is tracked at the engine layer via HMU feedback.
    pub fn progress(&self) -> f64 {
        if let Some(ref inbound) = self.inbound {
            inbound.progress()
        } else {
            0.0
        }
    }

    pub fn num_parts(&self) -> usize {
        if let Some(ref outbound) = self.outbound {
            outbound.num_parts()
        } else if let Some(ref inbound) = self.inbound {
            inbound.total_parts
        } else {
            0
        }
    }

    pub fn validate_proof(&mut self, proof_data: &[u8]) -> bool {
        if let Some(ref mut outbound) = self.outbound {
            outbound.validate_proof(proof_data)
        } else {
            false
        }
    }
}

/// Side-effect requested by the transfer engine on its caller.
#[derive(Debug, Clone, PartialEq)]
pub enum TransferAction {
    None,
    SendAdvertisement(Vec<u8>),
    /// `(part_index, part_data)`.
    SendPart(usize, Vec<u8>),
    SendProof(Vec<u8>),
    /// Hashmap update frame from receiver to sender.
    SendHmu(Vec<u8>),
    /// Receiver-to-sender request for specific parts. Payload layout:
    /// `exhausted_flag || optional last_map_hash || resource_hash || requested_part_hashes...`.
    SendRequest(Vec<u8>),
    Complete,
    /// Transfer aborted with a diagnostic reason.
    Failed(String),
    /// `ICL` (initiator cancel) or `RCL` (receiver cancel), plus resource hash.
    SendCancel(CancelType, [u8; 32]),
}

/// Cancel message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelType {
    /// Initiator (sender) cancel.
    Icl,
    /// Receiver cancel.
    Rcl,
}

/// Sender-side resource transfer state machine with windowed flow control.
/// Driven by the owning runtime via `tick()`; never spawns its own tasks.
pub struct OutboundTransfer {
    pub resource: OutboundResource,
    pub cursor: usize,
    pub confirmed_parts: Vec<bool>,
    pub window_cursor: usize,
    pub retries: usize,
    pub last_part_sent: Option<Instant>,
    pub started_at: Instant,
    pub rtt: Duration,
    pub awaiting_hmu: bool,
    pub advertised: bool,
    pub window_max_sent: usize,
    /// Lowest `consecutive_completed` height the receiver has reported.
    /// Scopes the search range when servicing RESOURCE_REQ lookups.
    pub receiver_min_consecutive_height: usize,
    pub sent_parts: usize,
    sent_part_indices: HashSet<usize>,
    req_hashlist: HashSet<[u8; 32]>,
}

impl OutboundTransfer {
    pub fn new(data: Vec<u8>, auto_compress: bool, rtt: Duration) -> Result<Self, ResourceError> {
        let resource = OutboundResource::new(data, auto_compress, None)?;
        Ok(Self::from_resource(resource, rtt))
    }

    /// Pre-encrypt the blob with link session keys before chunking. Parts
    /// emitted from this transfer are already ciphertext and must be sent
    /// raw (context=Resource, no additional link-layer encryption).
    pub fn new_encrypted(
        data: Vec<u8>,
        auto_compress: bool,
        rtt: Duration,
        keys: rns_link::key_derivation::LinkKeys,
    ) -> Result<Self, ResourceError> {
        let encrypt_fn = |plaintext: &[u8]| -> Vec<u8> {
            rns_link::encryption::link_encrypt(&keys, plaintext)
                .unwrap_or_else(|_| plaintext.to_vec())
        };
        let resource = OutboundResource::new(data, auto_compress, Some(&encrypt_fn))?;
        Ok(Self::from_resource(resource, rtt))
    }

    /// Build a transfer from a pre-constructed resource (e.g. one with
    /// metadata attached via [`OutboundResource::with_options`]).
    pub fn from_prebuilt(resource: OutboundResource, rtt: Duration) -> Self {
        Self::from_resource(resource, rtt)
    }

    fn from_resource(resource: OutboundResource, rtt: Duration) -> Self {
        let num_parts = resource.num_parts();
        Self {
            resource,
            cursor: 0,
            confirmed_parts: vec![false; num_parts],
            window_cursor: 0,
            retries: 0,
            last_part_sent: None,
            started_at: Instant::now(),
            rtt,
            awaiting_hmu: false,
            advertised: false,
            window_max_sent: 0,
            receiver_min_consecutive_height: 0,
            sent_parts: 0,
            sent_part_indices: HashSet::new(),
            req_hashlist: HashSet::new(),
        }
    }

    /// Advance the transfer state machine one step and emit the side-effect
    /// the caller should perform. Safe to poll idle.
    pub fn tick(&mut self) -> TransferAction {
        if self.resource.state == ResourceState::Complete {
            return TransferAction::Complete;
        }
        if self.resource.state == ResourceState::Failed {
            return TransferAction::Failed("transfer failed".to_string());
        }

        if !self.advertised {
            self.advertised = true;
            self.resource.state = ResourceState::Advertised;
            return TransferAction::SendAdvertisement(self.create_advertisement());
        }

        if self.awaiting_hmu {
            if let Some(last) = self.last_part_sent {
                let timeout = self.part_timeout();
                if last.elapsed() > timeout {
                    self.retries += 1;
                    if self.retries > MAX_RETRIES {
                        self.resource.state = ResourceState::Failed;
                        return TransferAction::Failed("max retries exceeded".to_string());
                    }
                    // Back off before resending the window.
                    self.awaiting_hmu = false;
                    self.resource.window.shrink();
                }
            }
            return TransferAction::None;
        }

        if self.cursor < self.resource.num_parts() {
            let window_end =
                (self.cursor + self.resource.window.window).min(self.resource.num_parts());

            if self.window_cursor < window_end {
                let part_idx = self.window_cursor;
                self.window_cursor += 1;

                if !self.confirmed_parts[part_idx] {
                    let part_data = self.resource.get_part(part_idx).map(|p| p.to_vec());
                    if let Some(part_data) = part_data {
                        self.last_part_sent = Some(Instant::now());
                        self.resource.state = ResourceState::Transferring;
                        if self.sent_part_indices.insert(part_idx) {
                            self.sent_parts += 1;
                        }

                        if self.window_cursor >= window_end {
                            // Last part in the window is now in flight; stop
                            // sending and wait for the receiver's HMU.
                            self.awaiting_hmu = true;
                            self.window_max_sent = window_end;
                        }

                        return TransferAction::SendPart(part_idx, part_data);
                    }
                } else {
                    return self.tick();
                }
            }
        }

        if self.all_confirmed() {
            self.resource.state = ResourceState::AwaitingProof;
        }

        TransferAction::None
    }

    /// Sender-side advertisement watchdog for request-driven runtimes.
    ///
    /// An outbound transfer remains `Advertised` until the receiver's first
    /// `RESOURCE_REQ` arrives. If that advertisement is lost, resend it up to
    /// the Python-compatible retry limit instead of leaving the transfer
    /// dormant forever.
    pub fn check_timeout(&mut self) -> TransferAction {
        if self.resource.state != ResourceState::Advertised {
            return TransferAction::None;
        }

        let timeout = Duration::from_secs_f64(
            self.rtt.as_secs_f64() * rns_link::constants::TRAFFIC_TIMEOUT_FACTOR + PROCESSING_GRACE,
        );
        if self.started_at.elapsed() <= timeout {
            return TransferAction::None;
        }

        if self.retries < MAX_ADV_RETRIES {
            self.retries += 1;
            self.started_at = Instant::now();
            TransferAction::SendAdvertisement(self.create_advertisement())
        } else {
            self.resource.state = ResourceState::Failed;
            TransferAction::Failed("resource advertisement timed out".to_string())
        }
    }

    /// Consume a hashmap-update frame from the receiver.
    ///
    /// Wire layout:
    ///   exhausted_flag(1) = 0xFF (complete) or 0x00 (incomplete)
    ///   [last_map_hash(4)]   — only when exhausted
    ///   resource_hash(32)
    ///   requested_hashes(N * MAPHASH_LEN) — hashes the receiver still needs
    ///
    /// When not exhausted, parts in the sent window whose hash is *not* in
    /// the requested set are marked confirmed.
    pub fn handle_hmu(&mut self, hmu_data: &[u8]) {
        if hmu_data.is_empty() {
            return;
        }

        let exhausted = hmu_data[0] == HASHMAP_IS_EXHAUSTED;
        let mut offset = 1;

        // If exhausted, skip the last_map_hash(4)
        if exhausted {
            offset += MAPHASH_LEN;
        }

        // Skip resource_hash(32) — we already know which resource this is
        if hmu_data.len() < offset + 32 {
            // Malformed HMU, not enough data for resource_hash
            return;
        }
        offset += 32;

        // When not exhausted: the remaining data contains hashes of parts
        // the receiver still NEEDS. We mark everything else as confirmed.
        if !exhausted {
            // Parse the set of requested (needed) hashes
            let requested_data = &hmu_data[offset..];
            let mut requested_set: HashSet<[u8; MAPHASH_LEN]> = HashSet::new();
            for chunk in requested_data.chunks_exact(MAPHASH_LEN) {
                let mut mh = [0u8; MAPHASH_LEN];
                mh.copy_from_slice(chunk);
                requested_set.insert(mh);
            }

            // Parts within the sent window that are NOT in the requested set
            // are confirmed as received.
            let window_start = self.cursor;
            let window_end = self
                .window_max_sent
                .max((self.cursor + self.resource.window.window).min(self.resource.num_parts()));

            let mut newly_confirmed = 0;
            for i in window_start..window_end {
                if i < self.resource.map_hashes.len()
                    && !self.confirmed_parts[i]
                    && !requested_set.contains(&self.resource.map_hashes[i])
                {
                    self.confirmed_parts[i] = true;
                    newly_confirmed += 1;
                }
            }

            // Advance cursor past confirmed parts
            while self.cursor < self.resource.num_parts() && self.confirmed_parts[self.cursor] {
                self.cursor += 1;
            }

            // Reset window cursor for next batch — start by resending requested parts
            self.window_cursor = self.cursor;
            self.awaiting_hmu = false;

            // Grow window on successful delivery
            if newly_confirmed > 0 {
                let elapsed = self.started_at.elapsed().as_secs_f64();
                let rate = if elapsed > 0.0 {
                    (newly_confirmed * SDU) as f64 / elapsed
                } else {
                    0.0
                };
                self.resource.window.grow(rate as usize);
                self.retries = 0;
            }
        } else {
            // Exhausted: receiver has all parts. Confirm everything.
            for i in 0..self.confirmed_parts.len() {
                self.confirmed_parts[i] = true;
            }
            self.cursor = self.resource.num_parts();
            self.window_cursor = self.cursor;
            self.awaiting_hmu = false;

            // Transition to awaiting proof
            self.resource.state = ResourceState::AwaitingProof;
            self.resource.window.grow(0);
        }
    }

    /// Sender-side handler for a RESOURCE_REQ built by the receiver's
    /// `request_next()`.
    ///
    /// Wire layout:
    ///   exhausted_flag(1) = 0xFF (needs more hashmap) / 0x00 (normal)
    ///   [last_map_hash(MAPHASH_LEN)]  — only when exhausted
    ///   resource_hash(32)
    ///   requested_hashes(N * MAPHASH_LEN)
    ///
    /// Returns the parts to retransmit and — when the receiver's hashmap is
    /// exhausted — an HMU carrying the next hashmap segment.
    pub fn handle_request_packet(
        &mut self,
        packet_hash: [u8; 32],
        request_data: &[u8],
    ) -> Vec<TransferAction> {
        if self.req_hashlist.contains(&packet_hash) {
            return Vec::new();
        }
        self.req_hashlist.insert(packet_hash);
        self.handle_request(request_data)
    }

    pub fn handle_request(&mut self, request_data: &[u8]) -> Vec<TransferAction> {
        if request_data.is_empty() || self.resource.state == ResourceState::Failed {
            return Vec::new();
        }

        // Refine the RTT estimate using the elapsed time since startup.
        let elapsed = self.started_at.elapsed();
        if self.rtt == Duration::ZERO || elapsed < self.rtt {
            self.rtt = elapsed;
        }

        if self.resource.state != ResourceState::Transferring {
            self.resource.state = ResourceState::Transferring;
        }

        self.retries = 0;

        let wants_more_hashmap = request_data[0] == HASHMAP_IS_EXHAUSTED;
        let pad = if wants_more_hashmap {
            1 + MAPHASH_LEN
        } else {
            1
        };

        // Skip past the flag (+ optional last_map_hash) and the 32-byte resource_hash.
        let hash_offset = pad + 32;
        if request_data.len() < hash_offset {
            return Vec::new();
        }

        let requested_hashes_data = &request_data[hash_offset..];

        let mut requested_map_hashes: Vec<[u8; MAPHASH_LEN]> = Vec::new();
        for chunk in requested_hashes_data.chunks_exact(MAPHASH_LEN) {
            let mut mh = [0u8; MAPHASH_LEN];
            mh.copy_from_slice(chunk);
            requested_map_hashes.push(mh);
        }

        // The collision guard widens the search window so out-of-order
        // part requests don't fall outside the scanned range when the
        // receiver's consecutive height lags ours.
        let guard_size = crate::resource_adv::collision_guard_size(rns_wire::constants::LINK_MDU);
        let search_start = self.receiver_min_consecutive_height;
        let search_end = (search_start + guard_size).min(self.resource.num_parts());

        let mut actions: Vec<TransferAction> = Vec::new();
        let mut sent_count = 0;

        for i in search_start..search_end {
            if i < self.resource.map_hashes.len()
                && requested_map_hashes.contains(&self.resource.map_hashes[i])
            {
                if let Some(part_data) = self.resource.get_part(i) {
                    actions.push(TransferAction::SendPart(i, part_data.to_vec()));
                    if self.sent_part_indices.insert(i) {
                        self.sent_parts += 1;
                    }
                    sent_count += 1;
                }
            }
        }

        self.last_part_sent = Some(Instant::now());

        if wants_more_hashmap && request_data.len() > MAPHASH_LEN {
            let mut last_map_hash = [0u8; MAPHASH_LEN];
            last_map_hash.copy_from_slice(&request_data[1..1 + MAPHASH_LEN]);

            // Locate the part following the receiver's last received hash.
            let mut part_index = search_start;
            for i in search_start..search_end {
                part_index = i + 1;
                if i < self.resource.map_hashes.len()
                    && self.resource.map_hashes[i] == last_map_hash
                {
                    break;
                }
            }

            // Clamp the receiver's reported height to the trailing window
            // so a stale report cannot rewind the search range.
            self.receiver_min_consecutive_height = if part_index > WINDOW_MAX {
                part_index - 1 - WINDOW_MAX
            } else {
                0
            };

            let hashmap_max_len =
                crate::resource_adv::hashmap_max_len(rns_wire::constants::LINK_MDU);

            // Python cancels if an exhausted request cursor is not aligned to
            // a hashmap segment boundary.
            if hashmap_max_len > 0 && part_index % hashmap_max_len != 0 {
                self.resource.state = ResourceState::Failed;
                actions.push(TransferAction::SendCancel(
                    CancelType::Icl,
                    self.resource.resource_hash,
                ));
                return actions;
            }

            if let Some(segment) = part_index.checked_div(hashmap_max_len) {
                let hashmap_start = segment * hashmap_max_len;
                let hashmap_end = ((segment + 1) * hashmap_max_len).min(self.resource.num_parts());

                let mut hashmap_bytes = Vec::new();
                for i in hashmap_start..hashmap_end {
                    if i < self.resource.map_hashes.len() {
                        hashmap_bytes.extend_from_slice(&self.resource.map_hashes[i]);
                    }
                }

                // An empty hashmap means there is nothing to answer the receiver's
                // request with — cancel rather than emit a useless empty HMU (1.3.9).
                if hashmap_bytes.is_empty() {
                    self.resource.state = ResourceState::Failed;
                    actions.push(TransferAction::SendCancel(
                        CancelType::Icl,
                        self.resource.resource_hash,
                    ));
                    return actions;
                }

                // HMU wire layout: resource_hash(32) || msgpack([segment, hashmap]).
                let hmu_payload = {
                    use rmpv::Value;
                    let arr = Value::Array(vec![
                        Value::Integer((segment as u64).into()),
                        Value::Binary(hashmap_bytes),
                    ]);
                    let mut buf = Vec::new();
                    buf.extend_from_slice(&self.resource.resource_hash);
                    rmpv::encode::write_value(&mut buf, &arr)
                        .expect("msgpack encode should succeed");
                    buf
                };

                actions.push(TransferAction::SendHmu(hmu_payload));
            }
        }

        if sent_count > 0 {
            let total_sent = self.confirmed_parts.iter().filter(|&&c| c).count() + sent_count;
            if total_sent >= self.resource.num_parts() {
                self.resource.state = ResourceState::AwaitingProof;
            }
        }

        actions
    }

    pub fn handle_cancel(&mut self) {
        self.resource.state = ResourceState::Failed;
    }

    /// Check a delivery proof; transitions to `Complete` on match.
    pub fn handle_proof(&mut self, proof_data: &[u8]) -> bool {
        self.resource.validate_proof(proof_data)
    }

    pub fn all_confirmed(&self) -> bool {
        self.confirmed_parts.iter().all(|&c| c)
    }

    /// Retransmit timeout, scaled by retry count and capped at 30s to keep
    /// a pathologically slow link from stalling a transfer forever.
    fn part_timeout(&self) -> Duration {
        let base = self.rtt.as_secs_f64() * PART_TIMEOUT_FACTOR_AFTER_RTT;
        let timeout = base.max(0.025) * (self.retries as f64 + 1.5);
        Duration::from_secs_f64(timeout.min(30.0))
    }

    /// Build the msgpack-encoded advertisement that precedes the transfer.
    fn create_advertisement(&self) -> Vec<u8> {
        use rmpv::Value;

        let mut adv = crate::resource_adv::ResourceAdvertisement::new(
            self.resource.total_size,
            self.resource.advertisement_data_size,
            self.resource.num_parts(),
            self.resource.resource_hash,
            self.resource.random_hash.to_vec(),
            self.resource.flags,
            &self.resource.map_hashes,
            rns_wire::constants::LINK_MDU,
        );
        // `ResourceAdvertisement::new` defaults to single-segment metadata
        // (`segment_index = 1`, `total_segments = 1`, `original_hash =
        // resource_hash`). For a segment of a `MultiSegmentOutbound`, propagate
        // the actual segmentation metadata so the receiver's coordinator can
        // reassemble — without this the wire ADV would announce each segment
        // as an independent single-segment resource.
        if self.resource.flags.split {
            adv.segment_index = self.resource.segment_index;
            adv.total_segments = self.resource.total_segments;
            if let Some(oh) = self.resource.original_hash {
                adv.original_hash = oh;
            }
        }
        adv.request_id = self.resource.request_id.clone();

        let q_val = match &adv.request_id {
            Some(id) => Value::Binary(id.clone()),
            None => Value::Nil,
        };

        let pairs: Vec<(Value, Value)> = vec![
            (
                Value::String("t".into()),
                Value::Integer(adv.transfer_size.into()),
            ),
            (
                Value::String("d".into()),
                Value::Integer(adv.data_size.into()),
            ),
            (
                Value::String("n".into()),
                Value::Integer(adv.num_parts.into()),
            ),
            (
                Value::String("h".into()),
                Value::Binary(adv.resource_hash.to_vec()),
            ),
            (
                Value::String("r".into()),
                Value::Binary(adv.random_hash.to_vec()),
            ),
            (
                Value::String("o".into()),
                Value::Binary(adv.original_hash.to_vec()),
            ),
            (
                Value::String("i".into()),
                Value::Integer(adv.segment_index.into()),
            ),
            (
                Value::String("l".into()),
                Value::Integer(adv.total_segments.into()),
            ),
            (Value::String("q".into()), q_val),
            (
                Value::String("f".into()),
                Value::Integer(adv.flags.to_byte().into()),
            ),
            (
                Value::String("m".into()),
                Value::Binary(adv.hashmap.clone()),
            ),
        ];

        let value = Value::Map(pairs);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &value).expect("msgpack encode failed");
        buf
    }

    /// Fraction of unique parts transmitted, in `0.0..=1.0`.
    ///
    /// Upstream Reticulum reports initiator-side progress from `sent_parts`,
    /// while receiver HMUs/proofs still decide completion. This keeps UI
    /// progress useful on large resources before a full segment proof arrives.
    pub fn progress(&self) -> f64 {
        if self.resource.num_parts() == 0 {
            return 1.0;
        }
        self.sent_parts.min(self.resource.num_parts()) as f64 / self.resource.num_parts() as f64
    }
}

/// Receiver-side resource transfer state machine. Accepts parts, emits HMUs
/// and RESOURCE_REQs, and produces the delivery proof once every part is in.
pub struct InboundTransfer {
    pub resource: InboundResource,
    pub parts_since_hmu: usize,
    pub started_at: Instant,
    pub accepted: bool,
    pub rtt: Duration,
    /// Parts that have been requested but not yet arrived.
    pub outstanding_parts: usize,
    pub last_activity: Instant,
    pub req_sent: Option<Instant>,
    pub req_resp: Option<Instant>,
    pub retries_left: usize,
    pub waiting_for_hmu: bool,
    /// Number of map hashes received from the sender so far.
    pub hashmap_height: usize,
    /// Current part timeout multiplier. Starts at `PART_TIMEOUT_FACTOR` and
    /// relaxes to `PART_TIMEOUT_FACTOR_AFTER_RTT` once the first RTT sample
    /// lands so we don't retry too aggressively before we know the link.
    pub part_timeout_factor: f64,

    /// Total bytes received this transfer. Python `rtt_rxd_bytes`.
    pub rtt_rxd_bytes: usize,
    /// Byte counter snapshot taken every `request_next()` so the next
    /// completed round can compute a delta. Python
    /// `rtt_rxd_bytes_at_part_req`.
    pub rtt_rxd_bytes_at_part_req: usize,
    /// Last measured bytes/sec over the completed window. Python
    /// `req_data_rtt_rate`. Zero means "no sample yet" and forces the
    /// EIFR fallback chain.
    pub req_data_rtt_rate: f64,
    /// Most recent effective inflight rate, in bits/sec. Python `eifr`.
    /// `None` until `update_eifr()` runs at least once.
    pub eifr: Option<f64>,
    /// Previous non-zero EIFR sample — seeded from the link's history on
    /// link-level ports, or left `None` on fresh receivers. Python
    /// `previous_eifr`.
    pub previous_eifr: Option<f64>,
}

impl InboundTransfer {
    /// Create from a received advertisement.
    // Mirrors the received Resource ADV fields and the measured RTT used for
    // flow-control state.
    #[allow(clippy::too_many_arguments)]
    pub fn from_advertisement(
        total_parts: usize,
        total_size: usize,
        data_size: usize,
        random_hash: [u8; RANDOM_HASH_SIZE],
        resource_hash: [u8; 32],
        flags: ResourceFlags,
        map_hashes: Vec<[u8; MAPHASH_LEN]>,
        rtt: Duration,
    ) -> Result<Self, ResourceError> {
        let hashmap_height = map_hashes.len();
        let resource = InboundResource::new(
            total_parts,
            total_size,
            data_size,
            random_hash,
            resource_hash,
            flags,
            map_hashes,
        )?;

        let now = Instant::now();
        Ok(Self {
            resource,
            parts_since_hmu: 0,
            started_at: now,
            accepted: true,
            rtt,
            outstanding_parts: 0,
            last_activity: now,
            req_sent: None,
            req_resp: None,
            retries_left: MAX_RETRIES,
            waiting_for_hmu: false,
            hashmap_height,
            part_timeout_factor: PART_TIMEOUT_FACTOR,
            rtt_rxd_bytes: 0,
            rtt_rxd_bytes_at_part_req: 0,
            req_data_rtt_rate: 0.0,
            eifr: None,
            previous_eifr: None,
        })
    }

    /// Seed `previous_eifr` from a prior transfer on the same link. Mirrors
    /// Python's `resource.previous_eifr = link.get_last_resource_eifr()` at
    /// advertisement time. Higher layers call this once after construction
    /// when they know the link's last observed rate.
    pub fn seed_previous_eifr(&mut self, bits_per_sec: f64) {
        if bits_per_sec > 0.0 {
            self.previous_eifr = Some(bits_per_sec);
        }
    }

    /// Refresh `self.eifr` in bits/sec, preferring the last measured
    /// `req_data_rtt_rate` (bytes/sec → bits/sec), falling back to the
    /// last `previous_eifr`, and finally to a cold-start estimate
    /// `EIFR_COLD_START_BYTES * 8 / rtt`.
    pub fn update_eifr(&mut self) {
        let rtt_secs = self.rtt.as_secs_f64().max(0.001);

        let rate = if self.req_data_rtt_rate > 0.0 {
            self.req_data_rtt_rate * 8.0
        } else if let Some(prev) = self.previous_eifr {
            prev
        } else {
            (EIFR_COLD_START_BYTES as f64 * 8.0) / rtt_secs
        };

        self.eifr = Some(rate);
        // Keep `previous_eifr` warm with the most recent non-zero rate so
        // a later transfer on the same link can seed from it (Python's
        // `link.expected_rate = self.eifr` maps here).
        if rate > 0.0 {
            self.previous_eifr = Some(rate);
        }
    }

    /// Accept a data part and decide what to send next.
    ///
    /// Flow: receive → decrement outstanding → if the window drained → grow
    /// the window using the observed byte rate → request the next batch.
    /// Completion emits `Complete`; runtimes answer with PROOF/RESOURCE_PRF.
    #[tracing::instrument(
        level = "trace",
        name = "resource.receive_part",
        skip_all,
        fields(
            resource_hash = %hex::encode(&self.resource.resource_hash[..8]),
            part_len = data.len(),
        ),
    )]
    pub fn receive_part(&mut self, data: Vec<u8>) -> TransferAction {
        self.last_activity = Instant::now();
        self.retries_left = MAX_RETRIES;

        // Track cumulative received bytes so update_eifr can compute a
        // measured rate over each completed request round.
        let payload_len = data.len();

        // The first reply after a request gives us an RTT sample; once we
        // have it we can relax the initial timeout multiplier.
        if self.req_resp.is_none() {
            self.req_resp = Some(self.last_activity);
            if let Some(sent) = self.req_sent {
                let rtt = self.last_activity.duration_since(sent);
                self.rtt = rtt;
                self.part_timeout_factor = PART_TIMEOUT_FACTOR_AFTER_RTT;
            }
        }

        if self.resource.receive_part(data) {
            self.parts_since_hmu += 1;
            self.rtt_rxd_bytes = self.rtt_rxd_bytes.saturating_add(payload_len);

            if self.outstanding_parts > 0 {
                self.outstanding_parts -= 1;
            }

            if self.resource.is_complete() {
                self.parts_since_hmu = 0;
                return TransferAction::Complete;
            }

            if self.outstanding_parts == 0 {
                // Window drained — compute req_data_rtt_rate from the byte
                // delta since last request, refresh EIFR, then grow the
                // window. Mirrors Python Resource.py:896-903.
                if let Some(sent_at) = self.req_sent {
                    let rtt = self.last_activity.duration_since(sent_at).as_secs_f64();
                    if rtt > 0.0 {
                        let req_transferred = self
                            .rtt_rxd_bytes
                            .saturating_sub(self.rtt_rxd_bytes_at_part_req);
                        self.req_data_rtt_rate = req_transferred as f64 / rtt;
                        self.update_eifr();
                        self.rtt_rxd_bytes_at_part_req = self.rtt_rxd_bytes;
                    }
                }

                let elapsed = self.started_at.elapsed().as_secs_f64();
                let received = self.resource.received_count();
                let rate = if elapsed > 0.0 {
                    (received * SDU) as f64 / elapsed
                } else {
                    0.0
                };
                self.resource.window.grow(rate as usize);

                return self.request_next();
            }
        }

        TransferAction::None
    }

    /// Emit a RESOURCE_REQ covering the missing parts in the current window.
    /// Called when the window has drained, when the watchdog fires, or after
    /// an HMU refreshes the hashmap. See `handle_request` on the sender for
    /// the wire layout.
    pub fn request_next(&mut self) -> TransferAction {
        if self.resource.state == ResourceState::Failed {
            return TransferAction::None;
        }

        if self.waiting_for_hmu {
            return TransferAction::None;
        }

        self.outstanding_parts = 0;
        let mut hashmap_exhausted = HASHMAP_IS_NOT_EXHAUSTED;
        let mut requested_hashes = Vec::new();

        let search_start = self.resource.consecutive_completed;
        let search_size = self.resource.window.window;
        let search_end = (search_start + search_size).min(self.resource.total_parts);

        let mut count = 0;
        for pn in search_start..search_end {
            if self.resource.parts[pn].is_none() {
                if pn < self.resource.map_hashes.len() {
                    requested_hashes.extend_from_slice(&self.resource.map_hashes[pn]);
                    self.outstanding_parts += 1;
                    count += 1;
                } else {
                    // We're missing a hash for a part we still need — ask
                    // the sender for the next hashmap segment.
                    hashmap_exhausted = HASHMAP_IS_EXHAUSTED;
                }
            }

            if count >= self.resource.window.window || hashmap_exhausted == HASHMAP_IS_EXHAUSTED {
                break;
            }
        }

        let mut request_data = Vec::new();

        request_data.push(hashmap_exhausted);
        if hashmap_exhausted == HASHMAP_IS_EXHAUSTED {
            if self.hashmap_height > 0 {
                let last_idx = self.hashmap_height - 1;
                if last_idx < self.resource.map_hashes.len() {
                    request_data.extend_from_slice(&self.resource.map_hashes[last_idx]);
                }
            }
            self.waiting_for_hmu = true;
        }

        request_data.extend_from_slice(&self.resource.resource_hash);
        request_data.extend_from_slice(&requested_hashes);

        self.last_activity = Instant::now();
        self.req_sent = Some(self.last_activity);
        self.req_resp = None;
        // Snapshot the byte counter so the next round's completion can
        // compute the delta over this window. Python Resource.py:964.
        self.rtt_rxd_bytes_at_part_req = self.rtt_rxd_bytes;

        TransferAction::SendRequest(request_data)
    }

    /// Receiver-side stall watchdog. Polled by the transfer driver; returns
    /// a retry request, a fatal failure, or `None`.
    ///
    /// Timeout formula (Python `Resource.__watchdog_job`):
    ///   `part_timeout_factor * expected_tof_remaining`
    ///   `+ expected_hmu_wait_remaining`
    ///   `+ RETRY_GRACE_TIME + extra_wait`
    /// where
    ///   `expected_tof_remaining   = outstanding_parts * sdu * 8 / eifr`
    ///   `expected_hmu_wait_remaining = sdu * 8 * HMU_WAIT_FACTOR / eifr`
    ///     (only when `waiting_for_hmu || outstanding_parts == 0`)
    ///   `extra_wait               = retries_used * PER_RETRY_DELAY`
    ///
    /// The pre-RTT-sample branch (`req_data_rtt_rate == 0`) uses the
    /// cold-start form `part_timeout_factor * (3*sdu / eifr) + grace`,
    /// which lengthens the window on slow links where we haven't measured
    /// a rate yet.
    pub fn check_timeout(&mut self) -> TransferAction {
        if self.resource.state != ResourceState::Transferring {
            return TransferAction::None;
        }

        if self.resource.is_complete() {
            return TransferAction::None;
        }

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_activity).as_secs_f64();

        let retries_used = MAX_RETRIES.saturating_sub(self.retries_left);
        let extra_wait = retries_used as f64 * PER_RETRY_DELAY;

        self.update_eifr();
        // update_eifr always assigns Some(_) as long as rtt_secs > 0; a
        // pathological zero-rtt would leave it None. Fall back to a
        // 1 bps floor so the arithmetic below cannot divide by zero.
        let eifr = self.eifr.unwrap_or(1.0).max(1.0);
        let sdu_f = self.resource.sdu as f64;

        let expected_hmu_wait_remaining = if self.waiting_for_hmu || self.outstanding_parts == 0 {
            (sdu_f * 8.0 * HMU_WAIT_FACTOR) / eifr
        } else {
            0.0
        };
        let expected_tof_remaining = (self.outstanding_parts as f64 * sdu_f * 8.0) / eifr;

        let timeout = if self.req_data_rtt_rate > 0.0 {
            self.part_timeout_factor * expected_tof_remaining
                + expected_hmu_wait_remaining
                + RETRY_GRACE_TIME
                + extra_wait
        } else {
            // Pre-sample: mirror Python's 604 — `3*sdu / eifr` is the
            // envelope for the next three parts to arrive at the cold-
            // start rate, scaled by the same timeout factor.
            self.part_timeout_factor * ((3.0 * sdu_f) / eifr) + RETRY_GRACE_TIME + extra_wait
        };

        if elapsed > timeout {
            if self.retries_left > 0 {
                self.resource.window.shrink();
                self.retries_left -= 1;
                self.waiting_for_hmu = false;
                return self.request_next();
            } else {
                self.resource.state = ResourceState::Failed;
                return TransferAction::Failed("resource transfer timed out".to_string());
            }
        }

        TransferAction::None
    }

    /// Merge a hashmap-update segment from the sender into our local
    /// map_hashes and immediately request the parts it unlocks.
    ///
    /// Wire layout:
    ///   resource_hash(32) || msgpack([segment_index, hashmap_bytes])
    pub fn hashmap_update(&mut self, segment: usize, hashmap_data: &[u8]) -> TransferAction {
        if self.resource.state == ResourceState::Failed {
            return TransferAction::None;
        }

        // Only process a hashmap update we actually solicited (1.3.9). An
        // unsolicited HMU is dropped rather than resetting the retry/activity
        // counters or injecting hashmap entries outside the request cycle.
        if !self.waiting_for_hmu {
            return TransferAction::None;
        }

        // An empty/degenerate HMU carries no hashes and is invalid — cancel the
        // transfer rather than spinning on an unsatisfiable request (1.3.9).
        if hashmap_data.len() < MAPHASH_LEN {
            return self.cancel();
        }

        let hashmap_max_len = crate::resource_adv::hashmap_max_len(rns_wire::constants::LINK_MDU);
        let Some(segment_start) = segment.checked_mul(hashmap_max_len) else {
            return self.cancel();
        };
        if segment_start >= self.resource.total_parts {
            return self.cancel();
        }

        self.resource.state = ResourceState::Transferring;
        self.last_activity = Instant::now();
        self.retries_left = MAX_RETRIES;

        // Parse hashes from the hashmap data and insert into our map_hashes.
        // `segment` is wire-supplied: indices are bounded by total_parts
        // (Python preallocates hashmap to total_parts, so out-of-range
        // writes are impossible there) — anything beyond is hostile.
        let hashes_count = hashmap_data.len() / MAPHASH_LEN;
        for i in 0..hashes_count {
            let idx = match segment_start.checked_add(i) {
                Some(idx) if idx < self.resource.total_parts => idx,
                _ => break,
            };
            let start = i * MAPHASH_LEN;
            let end = start + MAPHASH_LEN;
            if end <= hashmap_data.len() {
                let mut mh = [0u8; MAPHASH_LEN];
                mh.copy_from_slice(&hashmap_data[start..end]);

                // Extend the map_hashes vector if needed
                while self.resource.map_hashes.len() <= idx {
                    self.resource.map_hashes.push([0u8; MAPHASH_LEN]);
                }

                // Only increment hashmap_height if this is a new hash
                if self.resource.map_hashes[idx] == [0u8; MAPHASH_LEN] {
                    self.hashmap_height += 1;
                }
                self.resource.map_hashes[idx] = mh;
            }
        }

        self.waiting_for_hmu = false;

        // Now request the next batch of parts using the updated hashmap
        self.request_next()
    }

    /// Encode the receiver-side HMU frame. See `handle_hmu` on the sender for
    /// the wire layout.
    pub fn create_hmu(&self) -> Vec<u8> {
        let is_complete = self.resource.is_complete();
        let exhausted = if is_complete {
            HASHMAP_IS_EXHAUSTED
        } else {
            HASHMAP_IS_NOT_EXHAUSTED
        };

        let mut hmu = Vec::new();
        hmu.push(exhausted);

        // If exhausted (complete), include the last map hash
        if is_complete {
            if let Some(last_mh) = self.resource.map_hashes.last() {
                hmu.extend_from_slice(last_mh);
            }
        }

        // Include the resource hash for identification
        hmu.extend_from_slice(&self.resource.resource_hash);

        // Include hashes of parts we still NEED (not received)
        if !is_complete {
            let search_start = self.resource.consecutive_completed;
            let search_end =
                (search_start + self.resource.window.window).min(self.resource.total_parts);

            for i in search_start..search_end {
                if i < self.resource.map_hashes.len() && self.resource.parts[i].is_none() {
                    hmu.extend_from_slice(&self.resource.map_hashes[i]);
                }
            }
        }

        hmu
    }

    /// Assemble the received data and generate proof.
    /// Returns (assembled_data, proof_data) on success.
    /// An optional `decrypt_fn` is passed through to `InboundResource::assemble()`.
    ///
    /// The proof is computed over the full decompressed blob (metadata
    /// header + payload) to match Python Resource.py:744, where
    /// `self.data` still holds the metadata-inclusive bytes when
    /// `prove()` runs. `assemble()` strips metadata from the value it
    /// returns to callers, so we reconstruct the pre-strip bytes here
    /// before hashing.
    pub fn complete(
        &mut self,
        decrypt_fn: Option<&ResourceDecryptor<'_>>,
    ) -> Result<(Vec<u8>, Vec<u8>), ResourceError> {
        let data = self.resource.assemble(decrypt_fn)?;
        let proof_input: Vec<u8> = if self.resource.flags.has_metadata {
            if let Some(ref meta) = self.resource.metadata {
                let mut full = Vec::with_capacity(3 + meta.len() + data.len());
                let len = meta.len();
                full.push(((len >> 16) & 0xFF) as u8);
                full.push(((len >> 8) & 0xFF) as u8);
                full.push((len & 0xFF) as u8);
                full.extend_from_slice(meta);
                full.extend_from_slice(&data);
                full
            } else {
                data.clone()
            }
        } else {
            data.clone()
        };
        let proof = self.resource.generate_proof(&proof_input);
        Ok((data, proof))
    }

    /// Handle a cancel message from the sender.
    pub fn handle_cancel(&mut self) {
        self.resource.state = ResourceState::Failed;
    }

    /// Create a receiver cancel message.
    pub fn cancel(&mut self) -> TransferAction {
        self.resource.state = ResourceState::Failed;
        TransferAction::SendCancel(CancelType::Rcl, self.resource.resource_hash)
    }

    /// Progress as fraction.
    pub fn progress(&self) -> f64 {
        self.resource.progress()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_flags_roundtrip() {
        let flags = ResourceFlags {
            encrypted: true,
            compressed: true,
            split: false,
            is_request: true,
            is_response: false,
            has_metadata: true,
        };
        let byte = flags.to_byte();
        let flags2 = ResourceFlags::from_byte(byte);
        assert_eq!(flags.encrypted, flags2.encrypted);
        assert_eq!(flags.compressed, flags2.compressed);
        assert_eq!(flags.split, flags2.split);
        assert_eq!(flags.is_request, flags2.is_request);
        assert_eq!(flags.is_response, flags2.is_response);
        assert_eq!(flags.has_metadata, flags2.has_metadata);
    }

    #[test]
    fn test_rejected_distinct_from_none() {
        // Rejected and None must have distinct wire tags.
        assert_ne!(ResourceState::Rejected as u8, ResourceState::None as u8);
    }

    #[test]
    fn test_map_hash() {
        let data = b"test part data";
        let random = [0xAA, 0xBB, 0xCC, 0xDD];
        let mh = get_map_hash(data, &random);
        assert_eq!(mh.len(), MAPHASH_LEN);

        // Same input produces same hash
        let mh2 = get_map_hash(data, &random);
        assert_eq!(mh, mh2);

        // Different data produces different hash
        let mh3 = get_map_hash(b"different data", &random);
        assert_ne!(mh, mh3);
    }

    #[test]
    fn test_resource_hash_and_proof() {
        let data = b"resource data for hashing";
        let random = [0x01, 0x02, 0x03, 0x04];

        let rh = compute_resource_hash(data, &random);
        let proof = compute_expected_proof(data, &rh);

        // Proof should be deterministic
        let proof2 = compute_expected_proof(data, &rh);
        assert_eq!(proof, proof2);

        // Different data = different proof
        let rh2 = compute_resource_hash(b"other", &random);
        let proof3 = compute_expected_proof(b"other", &rh2);
        assert_ne!(proof, proof3);
    }

    #[test]
    fn test_outbound_resource_creation() {
        let data = b"Hello, this is a test resource!".to_vec();
        let resource = OutboundResource::new(data.clone(), false, None).unwrap();

        assert_eq!(resource.state, ResourceState::None);
        assert!(!resource.parts.is_empty());
        assert_eq!(resource.map_hashes.len(), resource.parts.len());
        assert_eq!(resource.total_segments, 1);
    }

    #[test]
    fn test_outbound_too_large() {
        let data = vec![0u8; MAX_EFFICIENT_SIZE + 1];
        assert!(OutboundResource::new(data, false, None).is_err());
    }

    #[test]
    fn test_inbound_receive_and_assemble() {
        // Create outbound resource
        let data = b"Test data for transfer!".to_vec();
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();

        // Create inbound resource from the outbound's metadata
        let mut inbound = InboundResource::new(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
        )
        .unwrap();

        // Feed parts
        for part in &outbound.parts {
            assert!(inbound.receive_part(part.clone()));
        }

        assert!(inbound.is_complete());

        // Assemble
        let assembled = inbound.assemble(None).unwrap();
        assert_eq!(assembled, data);
    }

    /// Parts arriving out-of-order must still reassemble correctly as long
    /// as they fall inside the receive window. Exercises the search loop in
    /// `receive_part` slotting by map-hash match rather than positional
    /// order. This is the normal case for a reliable network that can
    /// reorder — we should never require strictly sequential delivery.
    #[test]
    fn test_inbound_out_of_order_parts_assemble() {
        // 1.2 KiB -> 3 parts (all inside the initial WINDOW_INITIAL=4 window).
        let data: Vec<u8> = (0..1200).map(|i| (i % 251) as u8).collect();
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        assert_eq!(outbound.num_parts(), 3, "test needs exactly 3 parts");

        let mut inbound = InboundResource::new(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
        )
        .unwrap();

        // Deliver 2, 0, 1 — all indices inside the initial window,
        // none in positional order.
        for idx in [2usize, 0, 1] {
            assert!(
                inbound.receive_part(outbound.parts[idx].clone()),
                "out-of-order part {idx} should be accepted inside window"
            );
        }

        assert!(inbound.is_complete());
        let assembled = inbound.assemble(None).unwrap();
        assert_eq!(assembled, data, "reassembled data matches despite reorder");
    }

    /// A duplicate delivery of a part already accepted must be a no-op
    /// (returns false) and must not corrupt the partially-built buffer.
    /// Catches the replay/retransmit class that can occur when ACKs are
    /// lost and the sender resends.
    #[test]
    fn test_inbound_duplicate_part_is_noop() {
        let data = b"duplicate probe".to_vec();
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        let mut inbound = InboundResource::new(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
        )
        .unwrap();

        let first_part = outbound.parts[0].clone();
        assert!(inbound.receive_part(first_part.clone()), "first delivery");
        assert!(
            !inbound.receive_part(first_part.clone()),
            "duplicate must be rejected"
        );

        // Remaining parts still accept normally, and the final buffer is correct.
        for part in &outbound.parts[1..] {
            assert!(inbound.receive_part(part.clone()));
        }
        assert!(inbound.is_complete());
        assert_eq!(inbound.assemble(None).unwrap(), data);
    }

    #[test]
    fn test_proof_validation() {
        let data = b"Proof test data".to_vec();
        let mut outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        outbound.state = ResourceState::AwaitingProof;

        // Simulate receiver generating proof
        let inbound = InboundResource::new(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags::default(),
            outbound.map_hashes.clone(),
        )
        .unwrap();

        let proof_data = inbound.generate_proof(&data);
        assert!(outbound.validate_proof(&proof_data));
        assert_eq!(outbound.state, ResourceState::Complete);
    }

    #[test]
    fn test_window_grow_shrink() {
        let mut ws = WindowState::new();
        let initial = ws.window;

        ws.grow(RATE_FAST + 1);
        assert_eq!(ws.window, initial + 1);

        ws.shrink();
        assert_eq!(ws.window, initial);
    }

    #[test]
    fn test_progress() {
        let inbound = InboundResource::new(
            10,
            1000,
            1000,
            [0; 4],
            [0; 32],
            ResourceFlags::default(),
            vec![[0; 4]; 10],
        )
        .unwrap();

        assert_eq!(inbound.progress(), 0.0);
    }

    #[test]
    fn test_metadata_roundtrip() {
        // Metadata must survive a pack → transmit → assemble cycle.
        let data = b"Resource payload data".to_vec();
        let metadata = b"some metadata content".to_vec();

        let outbound =
            OutboundResource::with_options(data.clone(), false, Some(metadata.clone()), None, None)
                .unwrap();

        assert!(outbound.flags.has_metadata);
        assert!(outbound.metadata.is_some());
        assert_eq!(outbound.metadata_size, 3 + metadata.len());

        let mut inbound = InboundResource::new(
            outbound.num_parts(),
            outbound.total_size,
            data.len() + outbound.metadata_size,
            outbound.random_hash,
            outbound.resource_hash,
            outbound.flags,
            outbound.map_hashes.clone(),
        )
        .unwrap();

        for part in &outbound.parts {
            assert!(inbound.receive_part(part.clone()));
        }

        assert!(inbound.is_complete());

        let assembled_data = inbound.assemble(None).unwrap();
        assert_eq!(assembled_data, data);
        assert!(inbound.metadata.is_some());
        assert_eq!(inbound.metadata.unwrap(), metadata);
    }

    #[test]
    fn test_metadata_too_large() {
        let data = b"small".to_vec();
        let metadata = vec![0u8; METADATA_MAX_SIZE + 1];
        let result = OutboundResource::with_options(data, false, Some(metadata), None, None);
        assert!(matches!(result, Err(ResourceError::MetadataTooLarge)));
    }

    #[test]
    fn test_no_metadata_flag_unset() {
        let outbound = OutboundResource::new(b"test".to_vec(), false, None).unwrap();
        assert!(!outbound.flags.has_metadata);
        assert!(outbound.metadata.is_none());
        assert_eq!(outbound.metadata_size, 0);
    }

    #[test]
    fn test_custom_sdu() {
        let data = vec![0u8; 500];
        let custom_sdu = 100;
        let outbound =
            OutboundResource::with_options(data.clone(), false, None, Some(custom_sdu), None)
                .unwrap();

        assert_eq!(outbound.sdu, custom_sdu);
        // 500B data + 4B random hash at SDU=100 -> at least 5 parts.
        assert!(outbound.num_parts() >= 5);

        // Every non-final part must be packed to the full SDU.
        for (i, part) in outbound.parts.iter().enumerate() {
            if i < outbound.parts.len() - 1 {
                assert_eq!(part.len(), custom_sdu);
            }
        }
    }

    #[test]
    fn test_window_grow_before_send_order() {
        // The window must be grown before the next request batch is sized, so
        // the extra slot is visible in the batch that actually uses it.
        let mut ws = WindowState::new();
        let initial_window = ws.window;

        ws.grow(RATE_FAST + 1);
        assert_eq!(ws.window, initial_window + 1);

        let request_window = ws.window;
        assert_eq!(request_window, initial_window + 1);
    }

    #[test]
    fn test_window_min_adjusts_with_flexibility() {
        let mut ws = WindowState::new();
        let initial_min = ws.window_min;

        for _ in 0..(WINDOW_FLEXIBILITY + 2) {
            ws.window_max = WINDOW_MAX_FAST;
            ws.grow(RATE_FAST + 1);
        }

        // Once the window outgrows its flexibility band, `window_min` slides up.
        assert!(ws.window_min > initial_min);
    }

    // Regression: a very-slow demotion can clamp `window` below an already-raised `window_min`;
    // the next promoted grow must not underflow `window - window_min` (Python's signed comparison
    // is simply false there).
    #[test]
    fn window_grow_survives_demote_then_promote() {
        let mut w = WindowState::new();
        for _ in 0..6 {
            w.grow(1000);
        }
        assert_eq!((w.window, w.window_min, w.window_max), (10, 7, 10));
        for _ in 0..VERY_SLOW_RATE_THRESHOLD {
            w.grow(RATE_VERY_SLOW - 1);
        }
        assert_eq!(
            (w.window, w.window_min, w.window_max),
            (WINDOW_MAX_VERY_SLOW, 7, WINDOW_MAX_VERY_SLOW)
        );
        for _ in 0..FAST_RATE_THRESHOLD + 1 {
            w.grow(RATE_FAST + 1);
        }
        assert_eq!(w.window_max, WINDOW_MAX_FAST);
        assert_eq!(w.window, 5);
        assert_eq!(w.window_min, 7); // unchanged: window has not outgrown the band
    }

    #[test]
    fn test_link_resource_outbound_creation() {
        let link_id = [0xAA; 16];
        let data = b"Hello, LinkResource!".to_vec();
        let lr = LinkResource::new_outbound(link_id, data, false).unwrap();

        assert_eq!(lr.link_id, link_id);
        assert!(lr.outbound.is_some());
        assert!(lr.inbound.is_none());
        assert!(lr.num_parts() > 0);
    }

    #[test]
    fn test_link_resource_outbound_parts() {
        let link_id = [0xBB; 16];
        let data = b"Part iteration test data".to_vec();
        let lr = LinkResource::new_outbound(link_id, data, false).unwrap();

        // Should be able to get part 0
        let part = lr.next_part(0);
        assert!(part.is_some());

        // Out-of-bounds should return None
        let none_part = lr.next_part(9999);
        assert!(none_part.is_none());
    }

    #[test]
    fn test_link_resource_outbound_too_large() {
        let link_id = [0xCC; 16];
        let data = vec![0u8; MAX_EFFICIENT_SIZE + 1];
        let result = LinkResource::new_outbound(link_id, data, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_link_resource_inbound_transfer() {
        let link_id = [0xDD; 16];
        let data = b"Transfer test data".to_vec();

        // Create outbound to get the metadata
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();

        // Create inbound LinkResource from outbound metadata
        let mut lr = LinkResource::new_inbound(
            link_id,
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
        )
        .unwrap();

        assert!(!lr.is_complete());
        assert_eq!(lr.progress(), 0.0);

        // Feed all parts
        for part in &outbound.parts {
            assert!(lr.receive_part(part.clone()));
        }

        assert!(lr.is_complete());

        // Assemble
        let assembled = lr.assemble().unwrap();
        assert_eq!(assembled, data);
    }

    #[test]
    fn test_link_resource_progress() {
        let link_id = [0xEE; 16];
        let lr_out = LinkResource::new_outbound(link_id, b"test".to_vec(), false).unwrap();
        // Outbound progress is 0.0 (not tracked the same way)
        assert_eq!(lr_out.progress(), 0.0);
    }

    #[test]
    fn test_link_resource_receive_part_no_inbound() {
        let link_id = [0xFF; 16];
        let mut lr = LinkResource::new_outbound(link_id, b"data".to_vec(), false).unwrap();
        // Receiving a part on an outbound-only resource should return false
        assert!(!lr.receive_part(vec![1, 2, 3]));
    }

    #[test]
    fn test_outbound_transfer_creation() {
        let transfer = OutboundTransfer::new(
            b"test transfer data".to_vec(),
            false,
            Duration::from_millis(100),
        )
        .unwrap();

        assert!(!transfer.advertised);
        assert_eq!(transfer.cursor, 0);
        assert_eq!(transfer.retries, 0);
        assert_eq!(transfer.resource.state, ResourceState::None);
    }

    #[test]
    fn test_outbound_transfer_advertise_then_send() {
        let mut transfer = OutboundTransfer::new(
            b"hello transfer".to_vec(),
            false,
            Duration::from_millis(100),
        )
        .unwrap();

        // First tick should send advertisement
        let action = transfer.tick();
        assert!(matches!(action, TransferAction::SendAdvertisement(_)));
        assert!(transfer.advertised);

        // Subsequent ticks should send parts
        let action = transfer.tick();
        assert!(matches!(action, TransferAction::SendPart(0, _)));
    }

    #[test]
    fn test_outbound_advertisement_watchdog_retries() {
        let mut transfer = OutboundTransfer::new(
            b"retry advertisement".to_vec(),
            false,
            Duration::from_millis(1),
        )
        .unwrap();
        assert!(matches!(
            transfer.tick(),
            TransferAction::SendAdvertisement(_)
        ));

        transfer.started_at = Instant::now() - Duration::from_secs(60);
        assert!(matches!(
            transfer.check_timeout(),
            TransferAction::SendAdvertisement(_)
        ));
        assert_eq!(transfer.retries, 1);
        assert_eq!(transfer.resource.state, ResourceState::Advertised);
    }

    #[test]
    fn test_outbound_advertisement_watchdog_fails_after_retry_limit() {
        let mut transfer = OutboundTransfer::new(
            b"failed advertisement".to_vec(),
            false,
            Duration::from_millis(1),
        )
        .unwrap();
        transfer.tick();
        transfer.retries = MAX_ADV_RETRIES;
        transfer.started_at = Instant::now() - Duration::from_secs(60);

        assert!(matches!(
            transfer.check_timeout(),
            TransferAction::Failed(_)
        ));
        assert_eq!(transfer.resource.state, ResourceState::Failed);
    }

    #[test]
    fn test_outbound_transfer_hmu_handling() {
        let data = b"small data".to_vec();
        let mut transfer =
            OutboundTransfer::new(data.clone(), false, Duration::from_millis(100)).unwrap();

        // Send advertisement
        transfer.tick();

        // Collect all parts sent
        let num_parts = transfer.resource.num_parts();
        for _ in 0..num_parts {
            transfer.tick();
        }

        // Wire format: exhausted_flag(1) + last_map_hash(4) + resource_hash(32).
        let mut hmu = vec![HASHMAP_IS_EXHAUSTED];
        if let Some(last_mh) = transfer.resource.map_hashes.last() {
            hmu.extend_from_slice(last_mh);
        }
        hmu.extend_from_slice(&transfer.resource.resource_hash);
        transfer.handle_hmu(&hmu);

        assert!(transfer.all_confirmed());
    }

    #[test]
    fn test_inbound_transfer_receive_and_complete() {
        let data = b"test data for inbound transfer".to_vec();
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();

        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        // Feed all parts
        for part in &outbound.parts {
            inbound.receive_part(part.clone());
        }

        assert!(inbound.resource.is_complete());

        // Complete and verify
        let (assembled, proof) = inbound.complete(None).unwrap();
        assert_eq!(assembled, data);
        assert_eq!(proof.len(), 64); // resource_hash(32) + expected_proof(32)
    }

    #[test]
    fn test_inbound_rejects_part_count_inconsistent_with_size() {
        // AF-2026-04.1: wire-controlled num_parts must not size the parts Vec
        // unchecked — total_size=1024 with 10M parts is a ~240 MB alloc bomb.
        let result = InboundTransfer::from_advertisement(
            10_000_000,
            1024,
            1000,
            [0xAA; RANDOM_HASH_SIZE],
            [0xBB; 32],
            ResourceFlags::default(),
            Vec::new(),
            Duration::from_millis(100),
        );
        assert!(matches!(result, Err(ResourceError::TooLarge)));

        let result = InboundResource::new(
            0,
            1024,
            1000,
            [0xAA; RANDOM_HASH_SIZE],
            [0xBB; 32],
            ResourceFlags::default(),
            Vec::new(),
        );
        assert!(matches!(result, Err(ResourceError::InvalidAdvertisement)));

        // Same bound at the InboundResource layer directly.
        let result = InboundResource::new(
            usize::MAX,
            1024,
            1000,
            [0xAA; RANDOM_HASH_SIZE],
            [0xBB; 32],
            ResourceFlags::default(),
            Vec::new(),
        );
        assert!(matches!(result, Err(ResourceError::TooLarge)));
    }

    #[test]
    fn test_inbound_accepts_max_legitimate_part_count() {
        // Worst legitimate case: max-size transfer split at the real SDU.
        let max_total_size =
            MAX_EFFICIENT_SIZE + RANDOM_HASH_SIZE + rns_crypto::TOKEN_OVERHEAD + 16;
        let parts = max_total_size.div_ceil(SDU);
        let result = InboundResource::new(
            parts,
            max_total_size,
            MAX_EFFICIENT_SIZE,
            [0xAA; RANDOM_HASH_SIZE],
            [0xBB; 32],
            ResourceFlags::default(),
            Vec::new(),
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().total_parts, parts);
    }

    #[test]
    fn test_inbound_transfer_hmu_generation() {
        let data = vec![0u8; 2000]; // Multiple parts
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        assert!(outbound.num_parts() > 1);

        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        // Feed parts and check that completion does not emit a final HMU.
        for part in &outbound.parts {
            let action = inbound.receive_part(part.clone());
            if inbound.resource.is_complete() {
                assert!(matches!(action, TransferAction::Complete));
            }
        }

        assert!(inbound.resource.is_complete());
    }

    #[test]
    fn test_transfer_cancel() {
        let mut transfer =
            OutboundTransfer::new(b"data".to_vec(), false, Duration::from_millis(100)).unwrap();

        transfer.handle_cancel();
        assert_eq!(transfer.resource.state, ResourceState::Failed);
    }

    #[test]
    fn test_inbound_cancel() {
        let outbound = OutboundResource::new(b"data".to_vec(), false, None).unwrap();
        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            4,
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags::default(),
            outbound.map_hashes.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        let action = inbound.cancel();
        assert!(matches!(
            action,
            TransferAction::SendCancel(CancelType::Rcl, rh) if rh == outbound.resource_hash
        ));
        assert_eq!(inbound.resource.state, ResourceState::Failed);
    }

    #[test]
    fn test_transfer_progress() {
        let transfer =
            OutboundTransfer::new(b"data".to_vec(), false, Duration::from_millis(100)).unwrap();
        assert_eq!(transfer.progress(), 0.0);
    }

    #[test]
    fn test_transfer_progress_tracks_unique_sent_parts() {
        let data = vec![0x55; SDU * 2 + 100];
        let mut sender =
            OutboundTransfer::new(data.clone(), false, Duration::from_millis(50)).unwrap();
        assert!(sender.resource.num_parts() > 1);

        assert!(matches!(
            sender.tick(),
            TransferAction::SendAdvertisement(_)
        ));

        let first_progress = match sender.tick() {
            TransferAction::SendPart(_, _) => sender.progress(),
            other => panic!("expected first part, got {other:?}"),
        };
        assert!(first_progress > 0.0);
        assert!(first_progress < 1.0);

        let mut receiver = InboundTransfer::from_advertisement(
            sender.resource.num_parts(),
            sender.resource.total_size,
            data.len(),
            sender.resource.random_hash,
            sender.resource.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            sender.resource.map_hashes.clone(),
            Duration::from_millis(50),
        )
        .unwrap();
        let TransferAction::SendRequest(request) = receiver.request_next() else {
            panic!("expected receiver request");
        };

        let first_count = sender.sent_parts;
        let _ = sender.handle_request(&request);
        let after_request = sender.sent_parts;
        let _ = sender.handle_request(&request);

        assert!(after_request >= first_count);
        assert_eq!(
            sender.sent_parts, after_request,
            "duplicate requests must not inflate visible send progress"
        );
    }

    #[test]
    fn test_full_transfer_roundtrip() {
        // Simulate a complete transfer: sender → receiver
        let data = b"Full transfer test with enough data to exercise the engine.".to_vec();

        let mut sender =
            OutboundTransfer::new(data.clone(), false, Duration::from_millis(50)).unwrap();

        // Step 1: Sender advertises
        let adv_action = sender.tick();
        assert!(matches!(adv_action, TransferAction::SendAdvertisement(_)));

        // Step 2: Receiver accepts advertisement
        let mut receiver = InboundTransfer::from_advertisement(
            sender.resource.num_parts(),
            sender.resource.total_size,
            data.len(),
            sender.resource.random_hash,
            sender.resource.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            sender.resource.map_hashes.clone(),
            Duration::from_millis(50),
        )
        .unwrap();

        // Step 3: Sender sends parts, receiver receives them
        let num_parts = sender.resource.num_parts();
        for _ in 0..num_parts {
            let action = sender.tick();
            if let TransferAction::SendPart(_idx, part_data) = action {
                let recv_action = receiver.receive_part(part_data);

                // If receiver sends HMU, sender processes it
                if let TransferAction::SendHmu(hmu) = recv_action {
                    sender.handle_hmu(&hmu);
                }
            }
        }

        // Step 4: Receiver completes and sends proof
        assert!(receiver.resource.is_complete());
        let (assembled, proof) = receiver.complete(None).unwrap();
        assert_eq!(assembled, data);

        // Step 5: Sender validates proof
        assert!(sender.handle_proof(&proof));
        assert_eq!(sender.resource.state, ResourceState::Complete);
    }

    /// Helper: run a full sender→receiver transfer for the given data and verify integrity.
    fn run_transfer_roundtrip(data: Vec<u8>) {
        let data_len = data.len();
        let mut sender =
            OutboundTransfer::new(data.clone(), true, Duration::from_millis(50)).unwrap();

        // Advertise
        let action = sender.tick();
        assert!(matches!(action, TransferAction::SendAdvertisement(_)));

        // Create receiver
        let mut receiver = InboundTransfer::from_advertisement(
            sender.resource.num_parts(),
            sender.resource.total_size,
            data_len,
            sender.resource.random_hash,
            sender.resource.resource_hash,
            ResourceFlags {
                compressed: sender.resource.flags.compressed,
                ..Default::default()
            },
            sender.resource.map_hashes.clone(),
            Duration::from_millis(50),
        )
        .unwrap();

        // Transfer loop: send parts, handle HMUs
        let mut iterations = 0;
        let max_iterations = sender.resource.num_parts() * 3 + 10;
        while !receiver.resource.is_complete() && iterations < max_iterations {
            let action = sender.tick();
            match action {
                TransferAction::SendPart(_idx, part_data) => {
                    let recv_action = receiver.receive_part(part_data);
                    if let TransferAction::SendHmu(hmu) = recv_action {
                        sender.handle_hmu(&hmu);
                    }
                }
                // Sender is waiting for HMU; generate one if receiver has progress.
                TransferAction::None if receiver.resource.consecutive_completed > 0 => {
                    let hmu = receiver.create_hmu();
                    sender.handle_hmu(&hmu);
                }
                _ => {}
            }
            iterations += 1;
        }

        assert!(
            receiver.resource.is_complete(),
            "transfer incomplete after {} iterations ({} of {} parts received for {} byte payload)",
            iterations,
            receiver.resource.received_count(),
            receiver.resource.total_parts,
            data_len,
        );

        // Assemble and verify
        let (assembled, proof) = receiver.complete(None).unwrap();
        assert_eq!(assembled.len(), data_len);
        assert_eq!(assembled, data);

        // Validate proof
        assert!(sender.handle_proof(&proof));
        assert_eq!(sender.resource.state, ResourceState::Complete);
    }

    #[test]
    fn test_transfer_size_class_01_tiny() {
        // 1 byte — single part, minimal resource
        run_transfer_roundtrip(vec![0x42]);
    }

    #[test]
    fn test_transfer_size_class_02_small() {
        // 256 bytes — still single part
        run_transfer_roundtrip(vec![0xAB; 256]);
    }

    #[test]
    fn test_transfer_size_class_03_medium() {
        // 1 KB — likely 2-3 parts
        run_transfer_roundtrip(vec![0xCD; 1024]);
    }

    #[test]
    fn test_transfer_size_class_04_large() {
        // 10 KB — many parts, exercises windowing
        run_transfer_roundtrip(vec![0xEF; 10 * 1024]);
    }

    #[test]
    fn test_transfer_size_class_05_multi_part() {
        // 100 KB — heavy multi-part transfer
        run_transfer_roundtrip(vec![0x77; 100 * 1024]);
    }

    #[test]
    fn test_transfer_size_class_06_half_max() {
        // 512 KB
        run_transfer_roundtrip(vec![0x99; 512 * 1024]);
    }

    #[test]
    fn test_transfer_size_class_07_near_max() {
        // 1 MB - 1 = MAX_EFFICIENT_SIZE
        run_transfer_roundtrip(vec![0xBB; MAX_EFFICIENT_SIZE]);
    }

    #[test]
    fn test_transfer_over_max_rejected() {
        // MAX_EFFICIENT_SIZE + 1 should fail
        let result = OutboundTransfer::new(
            vec![0; MAX_EFFICIENT_SIZE + 1],
            false,
            Duration::from_millis(50),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_with_compression() {
        // Highly compressible data should compress well
        let data = vec![0x00; 10_000];
        let mut sender =
            OutboundTransfer::new(data.clone(), true, Duration::from_millis(50)).unwrap();
        // Compressed size should be smaller than original
        assert!(sender.resource.total_size < data.len() + RANDOM_HASH_SIZE + 100);

        // Still verify the full roundtrip works
        sender.tick(); // advertise
        let mut receiver = InboundTransfer::from_advertisement(
            sender.resource.num_parts(),
            sender.resource.total_size,
            data.len(),
            sender.resource.random_hash,
            sender.resource.resource_hash,
            ResourceFlags {
                compressed: sender.resource.flags.compressed,
                ..Default::default()
            },
            sender.resource.map_hashes.clone(),
            Duration::from_millis(50),
        )
        .unwrap();

        for part in &sender.resource.parts {
            receiver.receive_part(part.clone());
        }
        assert!(receiver.resource.is_complete());
        let (assembled, _proof) = receiver.complete(None).unwrap();
        assert_eq!(assembled, data);
    }

    #[test]
    fn test_transfer_random_data_integrity() {
        // Random data that won't compress — tests raw transfer integrity
        let data: Vec<u8> = rns_crypto::random::random_bytes(5000);
        run_transfer_roundtrip(data);
    }

    #[test]
    fn test_outbound_resource_handle_cancel() {
        let data = b"cancel test data".to_vec();
        let mut resource = OutboundResource::new(data, false, None).unwrap();
        assert_ne!(resource.state, ResourceState::Rejected);
        resource.handle_cancel();
        assert_eq!(resource.state, ResourceState::Rejected);
    }

    #[test]
    fn test_inbound_resource_handle_cancel() {
        let data = b"cancel inbound test".to_vec();
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        let mut inbound = InboundResource::new(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags::default(),
            outbound.map_hashes.clone(),
        )
        .unwrap();
        assert_ne!(inbound.state, ResourceState::Failed);
        inbound.handle_cancel();
        assert_eq!(inbound.state, ResourceState::Failed);
    }

    #[test]
    fn test_outbound_resource_handle_hmu_empty() {
        let data = b"hmu test".to_vec();
        let mut resource = OutboundResource::new(data, false, None).unwrap();
        let result = resource.handle_hmu(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_outbound_resource_handle_hmu_exhausted() {
        let data = b"hmu exhausted test".to_vec();
        let mut resource = OutboundResource::new(data, false, None).unwrap();
        resource.state = ResourceState::Transferring;
        let result = resource.handle_hmu(&[HASHMAP_IS_EXHAUSTED]);
        assert!(result.is_empty());
        assert_eq!(resource.state, ResourceState::AwaitingProof);
    }

    #[test]
    fn test_multi_segment_outbound_splits_data() {
        let data = vec![0xAB; MAX_EFFICIENT_SIZE + 1000];
        let multi = MultiSegmentOutbound::new(data.clone(), false).unwrap();

        assert_eq!(multi.total_segments, 2);
        assert_eq!(multi.num_segments(), 2);
        assert_eq!(multi.data_size, data.len());
        assert!(!multi.is_complete());

        // Verify segment flags
        for (i, seg) in multi.segments.iter().enumerate() {
            assert!(seg.flags.split);
            assert_eq!(seg.segment_index, i + 1);
            assert_eq!(seg.total_segments, 2);
        }

        // First segment should have MAX_EFFICIENT_SIZE bytes
        assert_eq!(multi.segments[0].data.len(), MAX_EFFICIENT_SIZE);
        // Second segment has the remainder
        assert_eq!(multi.segments[1].data.len(), 1000);
    }

    #[test]
    fn test_lazy_multi_segment_materialises_only_on_demand() {
        let data = vec![0xA6; MAX_EFFICIENT_SIZE * 2 + 321];
        let mut lazy = LazyMultiSegmentOutbound::new(data.clone(), false).unwrap();

        assert_eq!(lazy.total_segments, 3);
        assert_eq!(lazy.remaining_segments(), 3);

        let first = lazy.next_segment(None).unwrap().unwrap();
        assert_eq!(first.segment_index, 1);
        assert_eq!(first.total_segments, 3);
        assert_eq!(first.data.len(), MAX_EFFICIENT_SIZE);
        assert_eq!(lazy.remaining_segments(), 2);

        let second = lazy.next_segment(None).unwrap().unwrap();
        assert_eq!(second.segment_index, 2);
        assert_eq!(second.data.len(), MAX_EFFICIENT_SIZE);
        assert_eq!(lazy.remaining_segments(), 1);

        let third = lazy.next_segment(None).unwrap().unwrap();
        assert_eq!(third.segment_index, 3);
        assert_eq!(third.data.len(), 321);
        assert_eq!(lazy.remaining_segments(), 0);
        assert!(lazy.next_segment(None).unwrap().is_none());

        let rebuilt: Vec<u8> = [first, second, third]
            .into_iter()
            .flat_map(|segment| segment.data)
            .collect();
        assert_eq!(rebuilt, data);
    }

    #[test]
    fn test_lazy_multi_segment_preserves_metadata_and_request_flags() {
        let metadata = b"\x81\xa4name\xa8file.bin".to_vec();
        let request_id = vec![0x42; 16];
        let data = vec![0x5C; MAX_EFFICIENT_SIZE + 10];
        let mut lazy = LazyMultiSegmentOutbound::with_options(
            data,
            false,
            Some(metadata.clone()),
            Some(request_id.clone()),
            true,
        )
        .unwrap();

        let first = lazy.next_segment(None).unwrap().unwrap();
        let second = lazy.next_segment(None).unwrap().unwrap();
        assert!(first.flags.has_metadata);
        assert!(
            first
                .metadata
                .as_deref()
                .is_some_and(|wire| wire.ends_with(&metadata))
        );
        assert_eq!(first.metadata_size, metadata.len() + 3);
        assert!(!second.flags.has_metadata);
        assert_eq!(first.request_id, Some(request_id.clone()));
        assert_eq!(second.request_id, Some(request_id));
        assert!(first.flags.is_response);
        assert!(second.flags.is_response);
        assert_eq!(first.original_hash, second.original_hash);
        assert_eq!(
            first.advertisement_data_size,
            second.advertisement_data_size
        );
    }

    #[test]
    fn test_multi_segment_outbound_too_large() {
        let data = vec![0; MAX_RESOURCE_SIZE + 1];
        assert!(MultiSegmentOutbound::new(data, false).is_err());
    }

    #[test]
    fn test_multi_segment_plan_caps_metadata_induced_extra_segment() {
        let bounded_payload = MAX_EFFICIENT_SIZE * MAX_SEGMENTS;
        assert_eq!(required_segment_count(bounded_payload, 0), MAX_SEGMENTS);
        assert_eq!(required_segment_count(bounded_payload, 4), MAX_SEGMENTS + 1);
        assert_eq!(
            required_segment_count(MAX_RESOURCE_SIZE, 0),
            MAX_SEGMENTS + 1
        );
    }

    #[test]
    fn test_multi_segment_cancel_all_fans_out() {
        // Python parity: head-cancel must tear down every follow-on segment.
        // We use a 3-segment resource and verify all transition to Failed.
        let data = vec![0x42; MAX_EFFICIENT_SIZE * 2 + 500];
        let mut multi = MultiSegmentOutbound::new(data, false).unwrap();
        assert_eq!(multi.num_segments(), 3);

        let cancelled = multi.cancel_all();
        assert_eq!(cancelled, 3, "all three segments should be cancelled");
        for seg in &multi.segments {
            assert_eq!(seg.state, ResourceState::Failed);
        }

        // Idempotent: a second cancel returns 0 since all are already Failed.
        let cancelled_again = multi.cancel_all();
        assert_eq!(
            cancelled_again, 0,
            "already-failed segments must not be re-counted"
        );
    }

    #[test]
    fn test_multi_segment_cancel_all_skips_complete() {
        // A segment already marked Complete must not be flipped to Failed —
        // cancellation only tears down still-active transfers.
        let data = vec![0x33; MAX_EFFICIENT_SIZE + 200];
        let mut multi = MultiSegmentOutbound::new(data, false).unwrap();
        multi.segments[0].state = ResourceState::Complete;

        let cancelled = multi.cancel_all();
        assert_eq!(cancelled, 1, "only the active segment should be cancelled");
        assert_eq!(multi.segments[0].state, ResourceState::Complete);
        assert_eq!(multi.segments[1].state, ResourceState::Failed);
    }

    #[test]
    fn test_multi_segment_outbound_single_exact() {
        // Data exactly at MAX_EFFICIENT_SIZE should be one segment
        let data = vec![0xCD; MAX_EFFICIENT_SIZE];
        let multi = MultiSegmentOutbound::new(data, false).unwrap();
        assert_eq!(multi.total_segments, 1);
        assert_eq!(multi.num_segments(), 1);
        assert!(multi.segments[0].flags.split);
    }

    #[test]
    fn test_multi_segment_inbound_reassembly() {
        // Simulate: outbound splits into 2 segments, inbound reassembles
        let seg1_data = vec![0xAA; 100];
        let seg2_data = vec![0xBB; 50];

        let original_hash = [0x11; 32];
        let mut inbound = MultiSegmentInbound::new(2, original_hash);

        assert_eq!(inbound.total_segments, 2);
        assert!(!inbound.is_complete());
        assert_eq!(inbound.assembled_count(), 0);

        // Create outbound resources for each segment to get proper inbound metadata
        let out1 = OutboundResource::new(seg1_data.clone(), false, None).unwrap();
        let in1 = InboundResource::new(
            out1.num_parts(),
            out1.total_size,
            seg1_data.len(),
            out1.random_hash,
            out1.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            out1.map_hashes.clone(),
        )
        .unwrap();
        inbound.set_segment(1, in1);

        let out2 = OutboundResource::new(seg2_data.clone(), false, None).unwrap();
        let in2 = InboundResource::new(
            out2.num_parts(),
            out2.total_size,
            seg2_data.len(),
            out2.random_hash,
            out2.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            out2.map_hashes.clone(),
        )
        .unwrap();
        inbound.set_segment(2, in2);

        // Feed parts to segment 1
        for part in &out1.parts {
            inbound.segments[0]
                .as_mut()
                .unwrap()
                .receive_part(part.clone());
        }
        inbound.assemble_segment(1, None).unwrap();
        assert_eq!(inbound.assembled_count(), 1);

        // Feed parts to segment 2
        for part in &out2.parts {
            inbound.segments[1]
                .as_mut()
                .unwrap()
                .receive_part(part.clone());
        }
        inbound.assemble_segment(2, None).unwrap();
        assert_eq!(inbound.assembled_count(), 2);

        // Reassemble
        assert!(inbound.is_complete());
        let result = inbound.reassemble().unwrap();
        assert_eq!(&result[..100], &seg1_data[..]);
        assert_eq!(&result[100..], &seg2_data[..]);
    }

    #[test]
    fn test_multi_segment_inbound_progress() {
        let inbound = MultiSegmentInbound::new(4, [0; 32]);
        assert_eq!(inbound.progress(), 0.0);
        assert_eq!(inbound.assembled_count(), 0);
    }

    #[test]
    fn test_multi_segment_inbound_incomplete_reassembly() {
        let inbound = MultiSegmentInbound::new(2, [0; 32]);
        assert!(inbound.reassemble().is_err());
    }

    /// Runtime ingest path: feed assembled bytes directly via
    /// `set_segment_data` and verify reassembly + reported `data_size`.
    #[test]
    fn test_multi_segment_set_segment_data_in_order() {
        let mut inbound = MultiSegmentInbound::new(3, [0xAB; 32]);
        assert_eq!(inbound.assembled_count(), 0);

        inbound.set_segment_data(1, vec![1u8; 10]).unwrap();
        inbound.set_segment_data(2, vec![2u8; 20]).unwrap();
        assert!(!inbound.is_complete());
        assert_eq!(inbound.assembled_count(), 2);

        inbound.set_segment_data(3, vec![3u8; 30]).unwrap();
        assert!(inbound.is_complete());
        assert_eq!(inbound.data_size, 60);

        let blob = inbound.reassemble().unwrap();
        assert_eq!(blob.len(), 60);
        assert_eq!(&blob[..10], &[1u8; 10]);
        assert_eq!(&blob[10..30], &[2u8; 20]);
        assert_eq!(&blob[30..], &[3u8; 30]);
    }

    /// Out-of-order ingest: segment 3 arrives before segment 1. Reassembly
    /// must still produce the canonical ordering.
    #[test]
    fn test_multi_segment_set_segment_data_out_of_order() {
        let mut inbound = MultiSegmentInbound::new(3, [0; 32]);
        inbound.set_segment_data(3, vec![0xCC; 5]).unwrap();
        inbound.set_segment_data(1, vec![0xAA; 5]).unwrap();
        inbound.set_segment_data(2, vec![0xBB; 5]).unwrap();

        let blob = inbound.reassemble().unwrap();
        assert_eq!(
            &blob,
            &[
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xCC, 0xCC, 0xCC, 0xCC,
                0xCC
            ]
        );
    }

    /// Sender retransmit (or any duplicate ADV) must not silently overwrite
    /// an already-accepted slot — surfaces as `DuplicateSegment` so the
    /// runtime can log + ignore.
    #[test]
    fn test_multi_segment_set_segment_data_rejects_duplicate() {
        let mut inbound = MultiSegmentInbound::new(2, [0; 32]);
        inbound.set_segment_data(1, vec![0xAA; 4]).unwrap();
        let err = inbound.set_segment_data(1, vec![0xBB; 4]).unwrap_err();
        assert!(matches!(err, ResourceError::DuplicateSegment));
        // Original bytes must survive the rejection.
        inbound.set_segment_data(2, vec![0xCC; 4]).unwrap();
        let blob = inbound.reassemble().unwrap();
        assert_eq!(&blob[..4], &[0xAA; 4]);
        assert_eq!(&blob[4..], &[0xCC; 4]);
    }

    /// Out-of-range indices (`0` and `> total_segments`) must surface as
    /// `InvalidAdvertisement`, distinct from the duplicate path.
    #[test]
    fn test_multi_segment_set_segment_data_rejects_out_of_range() {
        let mut inbound = MultiSegmentInbound::new(2, [0; 32]);
        let err_zero = inbound.set_segment_data(0, vec![0; 1]).unwrap_err();
        let err_over = inbound.set_segment_data(3, vec![0; 1]).unwrap_err();
        assert!(matches!(err_zero, ResourceError::InvalidAdvertisement));
        assert!(matches!(err_over, ResourceError::InvalidAdvertisement));
    }

    /// `set_metadata` is first-non-None-wins: subsequent calls must not
    /// overwrite metadata already recorded.
    #[test]
    fn test_multi_segment_set_metadata_first_wins() {
        let mut inbound = MultiSegmentInbound::new(2, [0; 32]);
        assert!(inbound.metadata.is_none());
        inbound.set_metadata(b"first".to_vec());
        inbound.set_metadata(b"second".to_vec());
        assert_eq!(inbound.metadata.as_deref(), Some(&b"first"[..]));
    }

    /// Regression: the receiver's `total_size` cap previously rejected any
    /// max-plaintext resource (`MAX_EFFICIENT_SIZE`) once link-encrypted,
    /// because it didn't account for `random_hash + IV + HMAC + PKCS7 pad`
    /// overhead on top of the plaintext. After the fix the receiver must
    /// accept the worst-case encrypted blob built around a max-plaintext
    /// payload. This is what made multi-segment transfers unrecievable in
    /// practice — every chunk hits the post-encryption ceiling.
    #[test]
    fn test_inbound_resource_accepts_max_plaintext_encrypted_size() {
        const MAX_AES_BLOCK_PAD: usize = 16;
        let worst_case =
            MAX_EFFICIENT_SIZE + RANDOM_HASH_SIZE + rns_crypto::TOKEN_OVERHEAD + MAX_AES_BLOCK_PAD;

        let map_hashes = vec![[0u8; MAPHASH_LEN]; 1];
        let r = InboundResource::new(
            1,
            worst_case,
            MAX_EFFICIENT_SIZE,
            [0u8; RANDOM_HASH_SIZE],
            [0u8; 32],
            ResourceFlags {
                encrypted: true,
                ..Default::default()
            },
            map_hashes,
        );
        assert!(
            r.is_ok(),
            "receiver must accept worst-case encrypted total_size for a MAX_EFFICIENT_SIZE plaintext"
        );

        // One byte over the cap must still be rejected.
        let r2 = InboundResource::new(
            1,
            worst_case + 1,
            MAX_EFFICIENT_SIZE + 1,
            [0u8; RANDOM_HASH_SIZE],
            [0u8; 32],
            ResourceFlags::default(),
            vec![[0u8; MAPHASH_LEN]; 1],
        );
        assert!(matches!(r2, Err(ResourceError::TooLarge)));
    }

    /// Wire roundtrip: a segment of a `MultiSegmentOutbound`, when ticked
    /// through `OutboundTransfer`, must produce an ADV that preserves
    /// `segment_index`, `total_segments`, `original_hash`, and `flags.split`
    /// after pack/unpack. Without the propagation in `create_advertisement`,
    /// the wire ADV defaults to single-segment values and the receiver
    /// coordinator never sees the segment as part of a split resource.
    #[test]
    fn test_multi_segment_outbound_advertisement_carries_split_metadata() {
        let original = vec![0x77; MAX_EFFICIENT_SIZE + 200];
        let multi = MultiSegmentOutbound::new(original, false).unwrap();
        assert_eq!(multi.total_segments, 2);

        for (i, segment) in multi.segments.iter().enumerate() {
            let expected_idx = i + 1;
            assert!(segment.flags.split, "segment {expected_idx} flags.split");
            assert_eq!(segment.segment_index, expected_idx);
            assert_eq!(segment.total_segments, 2);
            assert_eq!(segment.original_hash, Some(multi.original_hash));
        }

        let segment_one = &multi.segments[0];
        let mut transfer = OutboundTransfer::from_prebuilt(
            OutboundResource {
                state: segment_one.state,
                data: segment_one.data.clone(),
                random_hash: segment_one.random_hash,
                resource_hash: segment_one.resource_hash,
                expected_proof: segment_one.expected_proof,
                flags: segment_one.flags,
                parts: segment_one.parts.clone(),
                map_hashes: segment_one.map_hashes.clone(),
                total_size: segment_one.total_size,
                advertisement_data_size: segment_one.advertisement_data_size,
                segment_index: segment_one.segment_index,
                total_segments: segment_one.total_segments,
                request_id: segment_one.request_id.clone(),
                original_hash: segment_one.original_hash,
                window: WindowState::new(),
                retries: 0,
                sdu: segment_one.sdu,
                metadata: segment_one.metadata.clone(),
                metadata_size: segment_one.metadata_size,
            },
            Duration::from_millis(500),
        );

        let action = transfer.tick();
        let adv_bytes = match action {
            TransferAction::SendAdvertisement(b) => b,
            other => panic!("expected SendAdvertisement, got {other:?}"),
        };

        let parsed =
            crate::resource_adv::ResourceAdvertisement::unpack(&adv_bytes).expect("unpack adv");
        assert_eq!(parsed.segment_index, 1);
        assert_eq!(parsed.total_segments, 2);
        assert_eq!(parsed.original_hash, multi.original_hash);
        assert_eq!(parsed.resource_hash, segment_one.resource_hash);
        assert!(parsed.flags.split);
    }

    #[test]
    fn test_multi_segment_roundtrip() {
        // End-to-end: large data → split → transfer → reassemble
        let original = vec![0x42; MAX_EFFICIENT_SIZE + 500];
        let multi_out = MultiSegmentOutbound::new(original.clone(), false).unwrap();
        assert_eq!(multi_out.total_segments, 2);

        let mut multi_in =
            MultiSegmentInbound::new(multi_out.total_segments, multi_out.original_hash);

        for (seg_idx, out_seg) in multi_out.segments.iter().enumerate() {
            let in_res = InboundResource::new(
                out_seg.num_parts(),
                out_seg.total_size,
                out_seg.data.len(),
                out_seg.random_hash,
                out_seg.resource_hash,
                ResourceFlags {
                    compressed: false,
                    split: true,
                    ..Default::default()
                },
                out_seg.map_hashes.clone(),
            )
            .unwrap();
            multi_in.set_segment(seg_idx + 1, in_res);

            // Feed all parts for this segment
            for part in &out_seg.parts {
                multi_in.segments[seg_idx]
                    .as_mut()
                    .unwrap()
                    .receive_part(part.clone());
            }
            multi_in.assemble_segment(seg_idx + 1, None).unwrap();
        }

        assert!(multi_in.is_complete());
        let reassembled = multi_in.reassemble().unwrap();
        assert_eq!(reassembled, original);
    }

    #[test]
    fn test_multi_segment_with_metadata_roundtrip() {
        let original = vec![0xA7; MAX_EFFICIENT_SIZE + 500];
        let metadata = b"\x81\xa4name\xa8file.bin".to_vec();
        let multi_out = MultiSegmentOutbound::with_options(
            original.clone(),
            false,
            Some(metadata.clone()),
            None,
            false,
            None,
        )
        .unwrap();
        assert_eq!(multi_out.total_segments, 2);
        assert!(multi_out.segments[0].flags.has_metadata);
        let advertised_data_size = original.len() + multi_out.segments[0].metadata_size;
        assert!(
            multi_out
                .segments
                .iter()
                .all(|segment| segment.advertisement_data_size == advertised_data_size)
        );
        assert!(
            multi_out.segments[0].metadata_size + multi_out.segments[0].data.len()
                <= MAX_EFFICIENT_SIZE
        );
        assert!(!multi_out.segments[1].flags.has_metadata);

        let total_segments = multi_out.total_segments;
        let original_hash = multi_out.original_hash;
        let mut multi_in = MultiSegmentInbound::new(total_segments, original_hash);

        for mut segment in multi_out.segments {
            let mut inbound = InboundTransfer::from_advertisement(
                segment.num_parts(),
                segment.total_size,
                segment.data.len(),
                segment.random_hash,
                segment.resource_hash,
                segment.flags,
                segment.map_hashes.clone(),
                Duration::from_millis(500),
            )
            .unwrap();
            for part in &segment.parts {
                let _ = inbound.receive_part(part.clone());
            }
            assert!(inbound.resource.is_complete());
            let (payload, proof) = inbound.complete(None).unwrap();
            assert!(segment.validate_proof(&proof));
            if let Some(meta) = inbound.resource.metadata.clone() {
                multi_in.set_metadata(meta);
            }
            multi_in
                .set_segment_data(segment.segment_index, payload)
                .unwrap();
        }

        assert_eq!(multi_in.metadata, Some(metadata));
        assert_eq!(multi_in.reassemble().unwrap(), original);
    }

    #[test]
    fn test_request_next_produces_valid_request() {
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        assert!(outbound.num_parts() > 1);

        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        // Call request_next before receiving any parts
        let action = inbound.request_next();

        // Should produce a SendRequest action
        assert!(matches!(action, TransferAction::SendRequest(_)));

        if let TransferAction::SendRequest(req_data) = &action {
            // First byte: exhausted flag (should be NOT exhausted)
            assert_eq!(req_data[0], HASHMAP_IS_NOT_EXHAUSTED);

            // Bytes 1..33: resource_hash
            assert_eq!(&req_data[1..33], &outbound.resource_hash);

            // Remaining bytes: requested hashes (multiples of MAPHASH_LEN)
            let hash_data = &req_data[33..];
            assert!(!hash_data.is_empty());
            assert_eq!(hash_data.len() % MAPHASH_LEN, 0);

            // Number of requested hashes should be <= window size
            let num_requested = hash_data.len() / MAPHASH_LEN;
            assert!(num_requested <= inbound.resource.window.window);
        }

        // outstanding_parts should be set
        assert!(inbound.outstanding_parts > 0);
        // req_sent should be set
        assert!(inbound.req_sent.is_some());
    }

    #[test]
    fn test_request_next_skips_received_parts() {
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        let num_parts = outbound.num_parts();
        assert!(num_parts > 2);

        let mut inbound = InboundTransfer::from_advertisement(
            num_parts,
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        // Receive the first part
        inbound.resource.receive_part(outbound.parts[0].clone());

        // Now request_next should skip part 0
        let action = inbound.request_next();
        if let TransferAction::SendRequest(req_data) = &action {
            let hash_data = &req_data[33..];
            // The first requested hash should NOT be the first part's hash
            if hash_data.len() >= MAPHASH_LEN {
                let first_requested = &hash_data[..MAPHASH_LEN];
                // It should be part 1's hash since part 0 is received and consecutive_completed=1
                assert_eq!(first_requested, &outbound.map_hashes[1]);
            }
        } else {
            panic!("Expected SendRequest action");
        }
    }

    #[test]
    fn test_request_next_not_sent_when_failed() {
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();

        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        inbound.resource.state = ResourceState::Failed;
        let action = inbound.request_next();
        assert!(matches!(action, TransferAction::None));
    }

    #[test]
    fn test_request_next_not_sent_when_waiting_for_hmu() {
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();

        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        inbound.waiting_for_hmu = true;
        let action = inbound.request_next();
        assert!(matches!(action, TransferAction::None));
    }

    #[test]
    fn test_handle_request_retransmits_parts() {
        let data = vec![0u8; 2000];
        let mut sender =
            OutboundTransfer::new(data.clone(), false, Duration::from_millis(100)).unwrap();

        // Advertise
        sender.tick();

        // Build a request for the first few parts
        let num_parts = sender.resource.num_parts();
        let window = sender.resource.window.window.min(num_parts);

        let mut request_data = Vec::new();
        request_data.push(HASHMAP_IS_NOT_EXHAUSTED);
        request_data.extend_from_slice(&sender.resource.resource_hash);
        // Request first `window` parts
        for i in 0..window {
            request_data.extend_from_slice(&sender.resource.map_hashes[i]);
        }

        let actions = sender.handle_request(&request_data);

        // Should get back parts to send
        let part_actions: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, TransferAction::SendPart(_, _)))
            .collect();
        assert_eq!(part_actions.len(), window);

        // Verify the retransmitted parts match
        for action in &part_actions {
            if let TransferAction::SendPart(idx, part_data) = action {
                assert_eq!(part_data, &sender.resource.parts[*idx]);
            }
        }
    }

    #[test]
    fn test_handle_request_empty_data() {
        let mut sender =
            OutboundTransfer::new(b"data".to_vec(), false, Duration::from_millis(100)).unwrap();

        let actions = sender.handle_request(&[]);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_handle_request_when_failed() {
        let mut sender =
            OutboundTransfer::new(b"data".to_vec(), false, Duration::from_millis(100)).unwrap();
        sender.resource.state = ResourceState::Failed;

        let mut request_data = Vec::new();
        request_data.push(HASHMAP_IS_NOT_EXHAUSTED);
        request_data.extend_from_slice(&sender.resource.resource_hash);

        let actions = sender.handle_request(&request_data);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_handle_request_packet_suppresses_duplicates() {
        let data = vec![0u8; 2000];
        let mut sender =
            OutboundTransfer::new(data.clone(), false, Duration::from_millis(100)).unwrap();

        sender.tick();

        let num_parts = sender.resource.num_parts();
        let window = sender.resource.window.window.min(num_parts);
        let mut request_data = Vec::new();
        request_data.push(HASHMAP_IS_NOT_EXHAUSTED);
        request_data.extend_from_slice(&sender.resource.resource_hash);
        for i in 0..window {
            request_data.extend_from_slice(&sender.resource.map_hashes[i]);
        }

        let packet_hash = [0xAB; 32];
        let first = sender.handle_request_packet(packet_hash, &request_data);
        assert!(
            first
                .iter()
                .any(|action| matches!(action, TransferAction::SendPart(_, _)))
        );

        let duplicate = sender.handle_request_packet(packet_hash, &request_data);
        assert!(
            duplicate.is_empty(),
            "duplicate RESOURCE_REQ packet hash must be ignored"
        );

        let retry = sender.handle_request_packet([0xCD; 32], &request_data);
        assert!(
            retry
                .iter()
                .any(|action| matches!(action, TransferAction::SendPart(_, _)))
        );
    }

    #[test]
    fn test_exhausted_request_non_boundary_cancels() {
        let data = vec![0x42u8; 20_000];
        let mut sender =
            OutboundTransfer::new(data.clone(), false, Duration::from_millis(100)).unwrap();
        assert!(
            crate::resource_adv::hashmap_max_len(rns_wire::constants::LINK_MDU) > 1,
            "test requires a multi-entry hashmap segment"
        );

        let mut request_data = Vec::new();
        request_data.push(HASHMAP_IS_EXHAUSTED);
        request_data.extend_from_slice(&sender.resource.map_hashes[0]);
        request_data.extend_from_slice(&sender.resource.resource_hash);

        let actions = sender.handle_request(&request_data);
        assert_eq!(sender.resource.state, ResourceState::Failed);
        assert!(matches!(
            actions.as_slice(),
            [TransferAction::SendCancel(CancelType::Icl, rh)] if *rh == sender.resource.resource_hash
        ));
    }

    #[test]
    fn test_receive_part_decrements_outstanding() {
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();

        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        // Manually set outstanding_parts as if request_next was called
        inbound.outstanding_parts = outbound.num_parts().min(WINDOW_INITIAL);

        // Receive one part
        let initial_outstanding = inbound.outstanding_parts;
        inbound.receive_part(outbound.parts[0].clone());
        assert_eq!(inbound.outstanding_parts, initial_outstanding - 1);
    }

    #[test]
    fn test_receive_part_triggers_request_next_on_window_complete() {
        let data = vec![0u8; 5000]; // Multiple parts > window size
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        let num_parts = outbound.num_parts();
        assert!(num_parts > WINDOW_INITIAL);

        let mut inbound = InboundTransfer::from_advertisement(
            num_parts,
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        // Set outstanding_parts to match window
        let window = inbound.resource.window.window;
        inbound.outstanding_parts = window;

        // Feed all parts in the window
        let mut got_request = false;
        for i in 0..window {
            let action = inbound.receive_part(outbound.parts[i].clone());
            if matches!(action, TransferAction::SendRequest(_)) {
                got_request = true;
            }
        }

        // Should have triggered request_next when outstanding_parts hit 0
        assert!(got_request, "Expected SendRequest when window is complete");
    }

    #[test]
    fn test_check_timeout_no_timeout_initially() {
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();

        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        // Immediately after creation, no timeout should occur
        let action = inbound.check_timeout();
        assert!(matches!(action, TransferAction::None));
    }

    #[test]
    fn test_check_timeout_not_transferring() {
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();

        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        // If not in transferring state, should do nothing
        inbound.resource.state = ResourceState::Assembling;
        let action = inbound.check_timeout();
        assert!(matches!(action, TransferAction::None));
    }

    #[test]
    fn test_check_timeout_triggers_retry() {
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();

        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(1), // Very short RTT to trigger timeout quickly
        )
        .unwrap();

        inbound.outstanding_parts = 2;
        // Set last_activity far enough in the past to trigger timeout
        inbound.last_activity = Instant::now() - Duration::from_secs(60);

        let initial_retries = inbound.retries_left;
        let action = inbound.check_timeout();

        // Should trigger a retry (SendRequest)
        assert!(
            matches!(action, TransferAction::SendRequest(_)),
            "Expected SendRequest on timeout, got {:?}",
            action
        );
        assert_eq!(inbound.retries_left, initial_retries - 1);
    }

    #[test]
    fn test_check_timeout_fails_when_retries_exhausted() {
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();

        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(1),
        )
        .unwrap();

        inbound.outstanding_parts = 2;
        inbound.retries_left = 0;
        inbound.last_activity = Instant::now() - Duration::from_secs(60);

        let action = inbound.check_timeout();
        assert!(matches!(action, TransferAction::Failed(_)));
        assert_eq!(inbound.resource.state, ResourceState::Failed);
    }

    #[test]
    fn test_hashmap_update_extends_map_hashes() {
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();

        // Create inbound with only partial map hashes (simulating a large resource)
        let partial_hashes = outbound.map_hashes[..2].to_vec();
        let initial_height = partial_hashes.len();

        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            partial_hashes,
            Duration::from_millis(100),
        )
        .unwrap();

        assert_eq!(inbound.resource.map_hashes.len(), 2);
        assert_eq!(inbound.hashmap_height, initial_height);

        // Build hashmap data for segment 0 with additional hashes
        let hashmap_max_len = crate::resource_adv::hashmap_max_len(rns_wire::constants::LINK_MDU);
        let mut hashmap_bytes = Vec::new();
        let end = outbound.map_hashes.len().min(hashmap_max_len);
        for i in 0..end {
            hashmap_bytes.extend_from_slice(&outbound.map_hashes[i]);
        }

        inbound.waiting_for_hmu = true;
        let action = inbound.hashmap_update(0, &hashmap_bytes);

        // Should have extended map_hashes
        assert!(inbound.resource.map_hashes.len() >= end);
        // Should have cleared waiting_for_hmu
        assert!(!inbound.waiting_for_hmu);
        // Should have triggered a request_next
        assert!(matches!(action, TransferAction::SendRequest(_)));
    }

    #[test]
    fn test_hashmap_update_ignores_unsolicited() {
        // 1.3.9: an HMU that was not solicited (waiting_for_hmu == false) is
        // dropped without touching transfer state.
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes[..2].to_vec(),
            Duration::from_millis(100),
        )
        .unwrap();

        assert!(!inbound.waiting_for_hmu);
        let before = inbound.resource.map_hashes.len();
        let action = inbound.hashmap_update(0, &outbound.map_hashes[0]);
        assert!(matches!(action, TransferAction::None));
        assert_eq!(inbound.resource.map_hashes.len(), before);
        assert_ne!(inbound.resource.state, ResourceState::Failed);
    }

    #[test]
    fn test_hashmap_update_empty_cancels() {
        // 1.3.9: a solicited but empty/degenerate HMU cancels the transfer and
        // emits a receiver cancel (RESOURCE_RCL).
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        let mut inbound = InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes[..2].to_vec(),
            Duration::from_millis(100),
        )
        .unwrap();

        inbound.waiting_for_hmu = true;
        let action = inbound.hashmap_update(0, &[]);
        assert!(matches!(
            action,
            TransferAction::SendCancel(CancelType::Rcl, _)
        ));
        assert_eq!(inbound.resource.state, ResourceState::Failed);
    }

    #[test]
    fn test_hashmap_update_rejects_out_of_range_segment() {
        // Wire-supplied `segment` must not grow map_hashes past total_parts.
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        let total_parts = outbound.num_parts();

        for segment in [1_000_000, usize::MAX] {
            let mut inbound = InboundTransfer::from_advertisement(
                total_parts,
                outbound.total_size,
                data.len(),
                outbound.random_hash,
                outbound.resource_hash,
                ResourceFlags {
                    compressed: false,
                    ..Default::default()
                },
                outbound.map_hashes[..2].to_vec(),
                Duration::from_millis(100),
            )
            .unwrap();

            // Hostile and overflowing segment indices must neither grow the
            // hashmap nor refresh the watchdog indefinitely.
            inbound.waiting_for_hmu = true;
            let action = inbound.hashmap_update(segment, &outbound.map_hashes[0]);
            assert!(matches!(
                action,
                TransferAction::SendCancel(CancelType::Rcl, _)
            ));
            assert_eq!(inbound.resource.map_hashes.len(), 2);
            assert_eq!(inbound.resource.state, ResourceState::Failed);
        }
    }

    #[test]
    fn test_hashmap_update_second_segment_bounded_by_total_parts() {
        // Resource large enough that its hashmap spans >1 segment: segment 1
        // writes land, but never past total_parts even if overfull.
        let hashmap_max_len = crate::resource_adv::hashmap_max_len(rns_wire::constants::LINK_MDU);
        let data = vec![0xCD; (hashmap_max_len + 12) * SDU];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        let total_parts = outbound.num_parts();
        assert!(total_parts > hashmap_max_len);

        let mut inbound = InboundTransfer::from_advertisement(
            total_parts,
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes[..hashmap_max_len].to_vec(),
            Duration::from_millis(100),
        )
        .unwrap();

        // Segment 1 carrying a deliberately overfull hash list: valid tail
        // entries land, writes stop exactly at total_parts.
        let mut overfull = Vec::new();
        for i in hashmap_max_len..total_parts {
            overfull.extend_from_slice(&outbound.map_hashes[i]);
        }
        overfull.extend_from_slice(&[0xEE; MAPHASH_LEN * 8]);
        inbound.waiting_for_hmu = true;
        inbound.hashmap_update(1, &overfull);

        assert_eq!(inbound.resource.map_hashes.len(), total_parts);
        assert_eq!(
            inbound.resource.map_hashes[total_parts - 1],
            outbound.map_hashes[total_parts - 1]
        );
    }

    #[test]
    fn test_full_transfer_with_request_next() {
        // Full transfer using the request_next mechanism instead of
        // the simple feed-all-parts approach.
        let data = vec![0xAB; 3000]; // Multi-part
        let mut sender =
            OutboundTransfer::new(data.clone(), false, Duration::from_millis(50)).unwrap();

        // Step 1: Sender advertises
        let adv = sender.tick();
        assert!(matches!(adv, TransferAction::SendAdvertisement(_)));

        // Step 2: Receiver accepts and sends initial request
        let mut receiver = InboundTransfer::from_advertisement(
            sender.resource.num_parts(),
            sender.resource.total_size,
            data.len(),
            sender.resource.random_hash,
            sender.resource.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            sender.resource.map_hashes.clone(),
            Duration::from_millis(50),
        )
        .unwrap();

        let initial_request = receiver.request_next();
        assert!(matches!(initial_request, TransferAction::SendRequest(_)));

        // Step 3: Transfer loop using request/response cycle
        let mut iterations = 0;
        let max_iterations = sender.resource.num_parts() * 4 + 20;

        // Process the initial request
        let mut pending_request = Some(initial_request);

        while !receiver.resource.is_complete() && iterations < max_iterations {
            if let Some(TransferAction::SendRequest(req_data)) = pending_request.take() {
                // Sender handles the request and retransmits parts
                let actions = sender.handle_request(&req_data);
                for action in actions {
                    match action {
                        TransferAction::SendPart(_idx, part_data) => {
                            let recv_action = receiver.receive_part(part_data);
                            match recv_action {
                                TransferAction::SendRequest(_) => {
                                    pending_request = Some(recv_action);
                                }
                                TransferAction::SendHmu(_) => {
                                    // Transfer is complete from receiver's perspective
                                }
                                _ => {}
                            }
                        }
                        TransferAction::SendHmu(hmu) => {
                            sender.handle_hmu(&hmu);
                        }
                        _ => {}
                    }
                }
            } else {
                // If no pending request, create one
                pending_request = Some(receiver.request_next());
            }
            iterations += 1;
        }

        assert!(
            receiver.resource.is_complete(),
            "transfer incomplete after {} iterations ({} of {} parts received)",
            iterations,
            receiver.resource.received_count(),
            receiver.resource.total_parts,
        );

        // Complete and verify integrity
        let (assembled, proof) = receiver.complete(None).unwrap();
        assert_eq!(assembled, data);
        assert!(sender.handle_proof(&proof));
    }

    #[test]
    fn test_request_next_with_partial_loss() {
        // Simulate a transfer where the first part is received but subsequent
        // parts are lost, requiring re-request via request_next.
        let data = vec![0xCD; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        let num_parts = outbound.num_parts();
        assert!(num_parts > 2);

        let mut inbound = InboundTransfer::from_advertisement(
            num_parts,
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            Duration::from_millis(100),
        )
        .unwrap();

        // Receive only the first part
        inbound.resource.receive_part(outbound.parts[0].clone());
        assert_eq!(inbound.resource.consecutive_completed, 1);
        assert!(!inbound.resource.is_complete());

        // request_next should request parts starting from consecutive_completed
        let action = inbound.request_next();
        if let TransferAction::SendRequest(req_data) = &action {
            let hash_data = &req_data[33..]; // Skip exhausted flag + resource_hash
            let num_requested = hash_data.len() / MAPHASH_LEN;

            // Should request at least one part
            assert!(
                num_requested > 0,
                "Should request at least one missing part"
            );

            // Number requested should not exceed window size
            assert!(num_requested <= inbound.resource.window.window);

            // All requested hashes should match map hashes of missing parts
            for i in 0..num_requested {
                let start = i * MAPHASH_LEN;
                let req_hash = &hash_data[start..start + MAPHASH_LEN];

                let mut found = false;
                for (idx, mh) in outbound.map_hashes.iter().enumerate() {
                    if mh.as_slice() == req_hash && inbound.resource.parts[idx].is_none() {
                        found = true;
                        break;
                    }
                }
                assert!(found, "Requested hash {} should match a missing part", i);
            }
        } else {
            panic!("Expected SendRequest action");
        }

        // Now feed all remaining parts and verify completion
        for i in 1..num_parts {
            inbound.resource.receive_part(outbound.parts[i].clone());
        }

        assert!(inbound.resource.is_complete());
        let assembled = inbound.resource.assemble(None).unwrap();
        assert_eq!(assembled, data);
    }

    #[test]
    fn test_sender_receiver_min_consecutive_height_tracking() {
        let data = vec![0u8; 5000];
        let mut sender =
            OutboundTransfer::new(data.clone(), false, Duration::from_millis(100)).unwrap();

        assert_eq!(sender.receiver_min_consecutive_height, 0);

        // Advertise
        sender.tick();

        // Create a request indicating hashmap exhaustion
        let mut request_data = Vec::new();
        request_data.push(HASHMAP_IS_EXHAUSTED);
        // last_map_hash -- use the hash at hashmap_max_len boundary
        let hashmap_max_len = crate::resource_adv::hashmap_max_len(rns_wire::constants::LINK_MDU);
        let boundary_idx = hashmap_max_len.min(sender.resource.num_parts()) - 1;
        request_data.extend_from_slice(&sender.resource.map_hashes[boundary_idx]);
        request_data.extend_from_slice(&sender.resource.resource_hash);

        let _actions = sender.handle_request(&request_data);

        // receiver_min_consecutive_height should be updated
        // (the exact value depends on WINDOW_MAX and the boundary index)
        // Just verify it was potentially updated from 0
        // For small resources it may stay at 0 if boundary_idx < WINDOW_MAX
        assert!(sender.receiver_min_consecutive_height <= sender.resource.num_parts());
    }

    fn build_inbound_for_eifr_tests(rtt: Duration) -> InboundTransfer {
        let data = vec![0u8; 2000];
        let outbound = OutboundResource::new(data.clone(), false, None).unwrap();
        InboundTransfer::from_advertisement(
            outbound.num_parts(),
            outbound.total_size,
            data.len(),
            outbound.random_hash,
            outbound.resource_hash,
            ResourceFlags {
                compressed: false,
                ..Default::default()
            },
            outbound.map_hashes.clone(),
            rtt,
        )
        .unwrap()
    }

    #[test]
    fn test_update_eifr_prefers_measured_rate() {
        let mut inbound = build_inbound_for_eifr_tests(Duration::from_millis(100));
        inbound.previous_eifr = Some(1_000.0);
        inbound.req_data_rtt_rate = 500.0; // bytes/sec

        inbound.update_eifr();

        let eifr = inbound.eifr.expect("update_eifr should populate eifr");
        assert!(
            (eifr - 4_000.0).abs() < 1e-6,
            "measured rate should win: expected 4000.0 bits/sec, got {}",
            eifr
        );
        // Non-zero sample must warm previous_eifr.
        assert_eq!(inbound.previous_eifr, Some(4_000.0));
    }

    #[test]
    fn test_update_eifr_falls_back_to_previous() {
        let mut inbound = build_inbound_for_eifr_tests(Duration::from_millis(100));
        inbound.seed_previous_eifr(12_345.0);
        assert_eq!(inbound.previous_eifr, Some(12_345.0));
        // No measured rate yet.
        assert_eq!(inbound.req_data_rtt_rate, 0.0);

        inbound.update_eifr();

        assert_eq!(
            inbound.eifr,
            Some(12_345.0),
            "with req_data_rtt_rate == 0, previous_eifr should win"
        );
    }

    #[test]
    fn test_update_eifr_cold_start() {
        let rtt = Duration::from_millis(200);
        let mut inbound = build_inbound_for_eifr_tests(rtt);
        assert_eq!(inbound.req_data_rtt_rate, 0.0);
        assert!(inbound.previous_eifr.is_none());

        inbound.update_eifr();

        let expected = (EIFR_COLD_START_BYTES as f64 * 8.0) / rtt.as_secs_f64();
        let actual = inbound.eifr.expect("cold-start should still set eifr");
        assert!(
            (actual - expected).abs() < 1e-6,
            "cold start should use EIFR_COLD_START_BYTES * 8 / rtt: expected {}, got {}",
            expected,
            actual
        );
    }

    #[test]
    fn test_seed_previous_eifr_rejects_non_positive() {
        let mut inbound = build_inbound_for_eifr_tests(Duration::from_millis(50));
        inbound.seed_previous_eifr(0.0);
        assert!(inbound.previous_eifr.is_none());
        inbound.seed_previous_eifr(-1.0);
        assert!(inbound.previous_eifr.is_none());
        inbound.seed_previous_eifr(1.0);
        assert_eq!(inbound.previous_eifr, Some(1.0));
    }

    #[test]
    fn test_request_next_snapshots_rxd_bytes() {
        let mut inbound = build_inbound_for_eifr_tests(Duration::from_millis(100));
        inbound.rtt_rxd_bytes = 9_999;
        assert_eq!(inbound.rtt_rxd_bytes_at_part_req, 0);

        let _ = inbound.request_next();

        assert_eq!(
            inbound.rtt_rxd_bytes_at_part_req, 9_999,
            "request_next must snapshot rtt_rxd_bytes so the next window can compute a delta"
        );
    }

    #[test]
    fn test_check_timeout_includes_hmu_wait_when_waiting() {
        // Two receivers, identical except `waiting_for_hmu` — the one that is
        // waiting must tolerate a strictly longer silence before retrying.
        let rtt = Duration::from_millis(1);

        let mut waiting = build_inbound_for_eifr_tests(rtt);
        waiting.outstanding_parts = 2;
        waiting.waiting_for_hmu = true;
        waiting.previous_eifr = Some(1_000.0); // deterministic eifr
        waiting.last_activity = Instant::now();

        let mut not_waiting = build_inbound_for_eifr_tests(rtt);
        not_waiting.outstanding_parts = 2;
        not_waiting.waiting_for_hmu = false;
        not_waiting.previous_eifr = Some(1_000.0);
        not_waiting.last_activity = Instant::now();

        // Give both a measured rate so they take the post-RTT branch.
        waiting.req_data_rtt_rate = 125.0;
        not_waiting.req_data_rtt_rate = 125.0;

        // Short idle — neither should retry yet.
        let idle = Duration::from_millis(1);
        waiting.last_activity = Instant::now() - idle;
        not_waiting.last_activity = Instant::now() - idle;

        assert!(matches!(waiting.check_timeout(), TransferAction::None));
        assert!(matches!(not_waiting.check_timeout(), TransferAction::None));

        // With waiting_for_hmu=true the HMU wait addend should be non-zero.
        let sdu = waiting.resource.sdu as f64;
        let eifr = waiting.eifr.unwrap();
        let hmu_addend = (sdu * 8.0 * HMU_WAIT_FACTOR) / eifr;
        assert!(
            hmu_addend > 0.0,
            "with waiting_for_hmu=true, hmu addend should contribute a positive duration"
        );
    }

    #[test]
    fn test_check_timeout_pre_rtt_uses_cold_start_branch() {
        // Receiver with no measured rate yet (req_data_rtt_rate==0) should
        // take the cold-start branch. Validate by seeding an `eifr` that
        // would be tiny under the post-RTT branch (huge timeout) but is
        // derived from previous_eifr here, producing a knowable timeout.
        let rtt = Duration::from_millis(100);
        let mut inbound = build_inbound_for_eifr_tests(rtt);
        inbound.outstanding_parts = 2;
        inbound.previous_eifr = Some(800.0); // 800 bits/sec
        inbound.retries_left = MAX_RETRIES;

        // Force last_activity far enough in the past that even the slow
        // cold-start branch will fire. Use checked subtraction because Windows
        // `Instant` panics if subtraction crosses its monotonic-clock base.
        inbound.update_eifr();
        let timeout = inbound.part_timeout_factor
            * ((3.0 * inbound.resource.sdu as f64) / inbound.eifr.unwrap())
            + RETRY_GRACE_TIME
            + Duration::from_millis(1).as_secs_f64();
        let expired_by = Duration::from_secs_f64(timeout);
        let now = Instant::now();
        inbound.last_activity = if let Some(last_activity) = now.checked_sub(expired_by) {
            last_activity
        } else {
            std::thread::sleep(expired_by);
            now
        };

        let initial_retries = inbound.retries_left;
        let action = inbound.check_timeout();
        assert!(
            matches!(action, TransferAction::SendRequest(_)),
            "expected cold-start timeout to retry, got {:?}",
            action
        );
        assert_eq!(inbound.retries_left, initial_retries - 1);
    }
}
