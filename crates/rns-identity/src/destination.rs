use std::collections::HashMap;

use rns_crypto::sha::truncated_hash;
use rns_crypto::token;
use thiserror::Error;

use crate::identity::Identity;
use crate::name_hash::name_hash;

/// Callback invoked on incoming data packets: `fn(plaintext, raw_packet)`.
pub type PacketCallback = Box<dyn Fn(&[u8], &[u8]) + Send + Sync>;
/// Callback invoked when a new link is established: `fn(link_id)`.
pub type LinkEstablishedCallback = Box<dyn Fn([u8; 16]) + Send + Sync>;
/// Callback deciding whether to emit a proof for a given packet.
pub type ProofRequestedCallback = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

pub struct RequestHandler {
    pub path: String,
    pub allow: AllowPolicy,
    /// Identity hashes permitted when `allow == AllowList`.
    pub allowed_list: Vec<[u8; 16]>,
    pub auto_compress: bool,
}

/// Default app data for announces: static bytes or a dynamic generator.
pub enum DefaultAppData {
    Static(Vec<u8>),
    Dynamic(Box<dyn Fn() -> Option<Vec<u8>> + Send + Sync>),
}

struct PathResponseCache {
    timestamp: f64,
    announce_data: Vec<u8>,
    has_ratchet: bool,
}

// Path-response dedup window (seconds). Matches upstream default.
const PR_TAG_WINDOW: f64 = 30.0;

/// Separate clocks used while constructing an announce: a persisted 40-bit
/// ordering value for the wire and a local elapsed-time value for cache expiry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AnnounceTime {
    pub wire: u64,
    pub cache: f64,
}

impl AnnounceTime {
    pub fn new(wire: u64, cache: f64) -> Result<Self, DestinationError> {
        if wire > crate::announce::ANNOUNCE_TIME_MAX || !cache.is_finite() || cache < 0.0 {
            return Err(DestinationError::InvalidAnnounceTime(cache));
        }
        Ok(Self { wire, cache })
    }
}

/// Destination type (matches wire format `DestinationType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestType {
    /// Asymmetric encryption via identity (ECDH + AES-256).
    Single = 0x00,
    /// Symmetric encryption with pre-shared key.
    Group = 0x01,
    /// No encryption (plaintext).
    Plain = 0x02,
    /// Internal per-link ephemeral encryption.
    Link = 0x03,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofStrategy {
    ProveNone = 0x21,
    ProveApp = 0x22,
    ProveAll = 0x23,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AllowPolicy {
    AllowNone = 0x00,
    AllowAll = 0x01,
    AllowList = 0x02,
}

#[derive(Debug, Error)]
pub enum DestinationError {
    #[error("SINGLE destination requires an identity")]
    MissingIdentity,
    #[error("outbound SINGLE destination requires an identity")]
    OutboundMissingIdentity,
    #[error("PLAIN destination cannot have an identity")]
    PlainWithIdentity,
    #[error("encryption not available for this destination type")]
    EncryptionUnavailable,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("only SINGLE destinations can be proved")]
    ProveNotSingle,
    #[error("identity error: {0}")]
    Identity(#[from] crate::identity::IdentityError),
    #[error("invalid announce clock value: {0}")]
    InvalidAnnounceTime(f64),
}

pub struct Destination {
    pub dest_type: DestType,
    pub direction: Direction,
    pub hash: [u8; 16],
    pub name_hash: [u8; 10],
    pub app_name: String,
    pub proof_strategy: ProofStrategy,
    /// If set, incoming data is signature-checked but not decrypted.
    pub only_validate_signature: bool,
    group_key: Option<Vec<u8>>,

    // Identity auto-generated for an IN destination when none was supplied;
    // callers retrieve it via [`auto_identity`] or [`take_auto_identity`].
    auto_identity: Option<Identity>,

    packet_callback: Option<PacketCallback>,
    link_established_callback: Option<LinkEstablishedCallback>,
    proof_requested_callback: Option<ProofRequestedCallback>,

    // Keyed by SHA-256(path)[:16].
    request_handlers: HashMap<[u8; 16], RequestHandler>,

    pub links: Vec<[u8; 16]>,

    pub accept_link_requests: bool,

    default_app_data: Option<DefaultAppData>,

    pub ratchets_enabled: bool,
    /// When set, non-ratchet ciphertexts are rejected.
    pub ratchets_enforced: bool,

    /// OUT: remote peer's most recent ratchet public key, used for forward-secret encryption.
    pub remote_ratchet_pub: Option<[u8; 32]>,
    /// IN: our current ratchet public key, advertised in announces.
    pub local_ratchet_pub: Option<[u8; 32]>,

    path_responses: HashMap<Vec<u8>, PathResponseCache>,
}

impl Destination {
    /// Create a new destination.
    ///
    /// For SINGLE/GROUP inbound destinations, a new identity is generated
    /// automatically when `identity` is `None`; retrieve it via
    /// [`Destination::auto_identity`].
    ///
    /// See [`Destination::compute_hash`] for the hash derivation.
    pub fn new(
        identity: Option<&Identity>,
        direction: Direction,
        dest_type: DestType,
        app_name: &str,
    ) -> Result<Self, DestinationError> {
        match dest_type {
            DestType::Single | DestType::Group => {
                let (id_ref, auto_id, hash_name) = match identity {
                    Some(id) => (id.hash, None, app_name.to_string()),
                    None => {
                        if direction == Direction::In {
                            let new_id = Identity::new();
                            let hash = new_id.hash;
                            let hash_name = format!("{app_name}.{}", hex::encode(hash));
                            (hash, Some(new_id), hash_name)
                        } else {
                            return Err(DestinationError::OutboundMissingIdentity);
                        }
                    }
                };

                let nh = name_hash(&hash_name);
                let hash = Self::compute_hash(&nh, Some(&id_ref));

                Ok(Self {
                    dest_type,
                    direction,
                    hash,
                    name_hash: nh,
                    app_name: app_name.to_string(),
                    proof_strategy: ProofStrategy::ProveNone,
                    only_validate_signature: false,
                    group_key: None,
                    auto_identity: auto_id,
                    packet_callback: None,
                    link_established_callback: None,
                    proof_requested_callback: None,
                    request_handlers: HashMap::new(),
                    links: Vec::new(),
                    accept_link_requests: true,
                    default_app_data: None,
                    ratchets_enabled: false,
                    ratchets_enforced: false,
                    remote_ratchet_pub: None,
                    local_ratchet_pub: None,
                    path_responses: HashMap::new(),
                })
            }
            DestType::Plain => {
                if identity.is_some() {
                    return Err(DestinationError::PlainWithIdentity);
                }
                let nh = name_hash(app_name);
                let hash = Self::compute_hash(&nh, None);

                Ok(Self {
                    dest_type,
                    direction,
                    hash,
                    name_hash: nh,
                    app_name: app_name.to_string(),
                    proof_strategy: ProofStrategy::ProveNone,
                    only_validate_signature: false,
                    group_key: None,
                    auto_identity: None,
                    packet_callback: None,
                    link_established_callback: None,
                    proof_requested_callback: None,
                    request_handlers: HashMap::new(),
                    links: Vec::new(),
                    accept_link_requests: true,
                    default_app_data: None,
                    ratchets_enabled: false,
                    ratchets_enforced: false,
                    remote_ratchet_pub: None,
                    local_ratchet_pub: None,
                    path_responses: HashMap::new(),
                })
            }
            DestType::Link => {
                // LINK destinations are constructed by the link layer itself.
                let nh = name_hash(app_name);
                let hash = Self::compute_hash(&nh, identity.map(|i| &i.hash));

                Ok(Self {
                    dest_type,
                    direction,
                    hash,
                    name_hash: nh,
                    app_name: app_name.to_string(),
                    proof_strategy: ProofStrategy::ProveNone,
                    only_validate_signature: false,
                    group_key: None,
                    auto_identity: None,
                    packet_callback: None,
                    link_established_callback: None,
                    proof_requested_callback: None,
                    request_handlers: HashMap::new(),
                    links: Vec::new(),
                    accept_link_requests: true,
                    default_app_data: None,
                    ratchets_enabled: false,
                    ratchets_enforced: false,
                    remote_ratchet_pub: None,
                    local_ratchet_pub: None,
                    path_responses: HashMap::new(),
                })
            }
        }
    }

    /// Compute a destination hash.
    ///
    /// - SINGLE/GROUP: `SHA-256(name_hash || identity_hash)[:16]`
    /// - PLAIN: `SHA-256(name_hash)[:16]`
    pub fn compute_hash(nh: &[u8; 10], identity_hash: Option<&[u8; 16]>) -> [u8; 16] {
        match identity_hash {
            Some(ih) => {
                let mut material = [0u8; 26];
                material[..10].copy_from_slice(nh);
                material[10..].copy_from_slice(ih);
                truncated_hash(&material)
            }
            None => truncated_hash(nh),
        }
    }

    pub fn hash_from_name_and_identity(
        app_name: &str,
        identity_hash: Option<&[u8; 16]>,
    ) -> [u8; 16] {
        let nh = name_hash(app_name);
        Self::compute_hash(&nh, identity_hash)
    }

    pub fn set_proof_strategy(&mut self, strategy: ProofStrategy) {
        self.proof_strategy = strategy;
    }

    /// Set the pre-shared key used for GROUP encryption.
    pub fn set_group_key(&mut self, key: Vec<u8>) {
        self.group_key = Some(key);
    }

    /// Identity auto-generated at construction (IN + SINGLE/GROUP without a caller-provided identity).
    pub fn auto_identity(&self) -> Option<&Identity> {
        self.auto_identity.as_ref()
    }

    pub fn take_auto_identity(&mut self) -> Option<Identity> {
        self.auto_identity.take()
    }

    pub fn set_only_validate_signature(&mut self, only_validate: bool) {
        self.only_validate_signature = only_validate;
    }

    /// Produce a proof over `packet_hash` for this (SINGLE) destination.
    ///
    /// `implicit_proof = true` emits the 64-byte signature alone; otherwise
    /// the output is `packet_hash || signature`.
    pub fn prove(
        &self,
        packet_hash: &[u8],
        identity: &Identity,
        implicit_proof: bool,
    ) -> Result<Vec<u8>, DestinationError> {
        if self.dest_type != DestType::Single {
            return Err(DestinationError::ProveNotSingle);
        }
        identity
            .prove(packet_hash, implicit_proof)
            .map_err(DestinationError::Identity)
    }

    /// Encrypt data for this destination.
    ///
    /// For SINGLE destinations a `remote_ratchet_pub` replaces the identity's
    /// X25519 key in the ECDH exchange, giving forward secrecy.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        identity: &Identity,
        remote_ratchet_pub: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, DestinationError> {
        match self.dest_type {
            DestType::Plain => Ok(plaintext.to_vec()),
            DestType::Single => identity
                .encrypt(plaintext, remote_ratchet_pub)
                .map_err(DestinationError::Identity),
            DestType::Group => {
                let key = self
                    .group_key
                    .as_ref()
                    .ok_or(DestinationError::EncryptionUnavailable)?;
                token::encrypt(plaintext, key).map_err(|_| DestinationError::DecryptionFailed)
            }
            DestType::Link => Err(DestinationError::EncryptionUnavailable),
        }
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        identity: &Identity,
    ) -> Result<Vec<u8>, DestinationError> {
        self.decrypt_with_ratchets(ciphertext, identity, None)
    }

    /// Decrypt data, trying each ratchet private key before the identity key.
    pub fn decrypt_with_ratchets(
        &self,
        ciphertext: &[u8],
        identity: &Identity,
        ratchet_keys: Option<&[[u8; 32]]>,
    ) -> Result<Vec<u8>, DestinationError> {
        match self.dest_type {
            DestType::Plain => Ok(ciphertext.to_vec()),
            DestType::Single => {
                let ratchet_refs: Option<Vec<&[u8; 32]>> = if self.ratchets_enabled {
                    ratchet_keys.map(|keys| keys.iter().collect())
                } else {
                    None
                };
                let enforce = self.ratchets_enforced;
                identity
                    .decrypt(ciphertext, ratchet_refs.as_deref(), enforce)
                    .map_err(DestinationError::Identity)
            }
            DestType::Group => {
                let key = self
                    .group_key
                    .as_ref()
                    .ok_or(DestinationError::EncryptionUnavailable)?;
                token::decrypt(ciphertext, key).map_err(|_| DestinationError::DecryptionFailed)
            }
            DestType::Link => Err(DestinationError::EncryptionUnavailable),
        }
    }

    /// Record the remote peer's ratchet public key, learnt from an announce.
    pub fn set_remote_ratchet(&mut self, pub_key: [u8; 32]) {
        self.remote_ratchet_pub = Some(pub_key);
    }

    /// Set our outbound ratchet public key from the ratchet ring.
    pub fn set_local_ratchet(&mut self, pub_key: [u8; 32]) {
        self.local_ratchet_pub = Some(pub_key);
    }

    /// Return the local ratchet public key if ratchets are enabled here.
    pub fn get_ratchet_for_announce(&self) -> Option<[u8; 32]> {
        if self.ratchets_enabled {
            self.local_ratchet_pub
        } else {
            None
        }
    }

    pub fn set_packet_callback(&mut self, callback: PacketCallback) {
        self.packet_callback = Some(callback);
    }

    pub fn set_link_established_callback(&mut self, callback: LinkEstablishedCallback) {
        self.link_established_callback = Some(callback);
    }

    /// Callback invoked under `ProveApp` strategy; returning `true` emits a proof.
    pub fn set_proof_requested_callback(&mut self, callback: ProofRequestedCallback) {
        self.proof_requested_callback = Some(callback);
    }

    pub fn on_link_established(&self, link_id: [u8; 16]) {
        if let Some(ref cb) = self.link_established_callback {
            cb(link_id);
        }
    }

    /// Register a request handler. Returns `false` if `path` is empty.
    pub fn register_request_handler(
        &mut self,
        path: &str,
        allow: AllowPolicy,
        allowed_list: Option<Vec<[u8; 16]>>,
        auto_compress: bool,
    ) -> bool {
        if path.is_empty() {
            return false;
        }

        let path_hash = truncated_hash(path.as_bytes());

        self.request_handlers.insert(
            path_hash,
            RequestHandler {
                path: path.to_string(),
                allow,
                allowed_list: allowed_list.unwrap_or_default(),
                auto_compress,
            },
        );

        true
    }

    pub fn deregister_request_handler(&mut self, path: &str) -> bool {
        let path_hash = truncated_hash(path.as_bytes());
        self.request_handlers.remove(&path_hash).is_some()
    }

    pub fn get_request_handler(&self, path_hash: &[u8; 16]) -> Option<&RequestHandler> {
        self.request_handlers.get(path_hash)
    }

    pub fn check_request_allowed(
        &self,
        path_hash: &[u8; 16],
        remote_identity_hash: Option<&[u8; 16]>,
    ) -> bool {
        match self.request_handlers.get(path_hash) {
            None => false,
            Some(handler) => match handler.allow {
                AllowPolicy::AllowNone => false,
                AllowPolicy::AllowAll => true,
                AllowPolicy::AllowList => {
                    if let Some(id_hash) = remote_identity_hash {
                        handler.allowed_list.iter().any(|h| h == id_hash)
                    } else {
                        false
                    }
                }
            },
        }
    }

    /// Decrypt and dispatch an incoming packet.
    ///
    /// LINKREQUEST (`0x02`) bypasses decryption and is handled by
    /// [`Destination::incoming_link_request`]; DATA (`0x00`) packets
    /// additionally fire the packet callback.
    pub fn receive(
        &self,
        packet_type: u8,
        data: &[u8],
        identity: &Identity,
    ) -> Result<Option<Vec<u8>>, DestinationError> {
        if packet_type == 0x02 {
            return Ok(Some(data.to_vec()));
        }

        let plaintext = self.decrypt(data, identity)?;

        if packet_type == 0x00 {
            if let Some(ref cb) = self.packet_callback {
                cb(&plaintext, data);
            }
        }

        Ok(Some(plaintext))
    }

    pub fn should_prove(&self, packet_data: &[u8]) -> bool {
        match self.proof_strategy {
            ProofStrategy::ProveNone => false,
            ProofStrategy::ProveAll => true,
            ProofStrategy::ProveApp => {
                if let Some(ref cb) = self.proof_requested_callback {
                    cb(packet_data)
                } else {
                    false
                }
            }
        }
    }

    pub fn incoming_link_request(&mut self, link_id: [u8; 16]) -> bool {
        if !self.accept_link_requests {
            return false;
        }
        self.links.push(link_id);
        true
    }

    pub fn set_accepts_links(&mut self, accept: bool) {
        self.accept_link_requests = accept;
    }

    /// Enable ratchet forward secrecy. If `enforce`, non-ratchet inbound ciphertext is rejected.
    pub fn enable_ratchets(&mut self, enforce: bool) {
        self.ratchets_enabled = true;
        self.ratchets_enforced = enforce;
    }

    pub fn disable_ratchets(&mut self) {
        self.ratchets_enabled = false;
        self.ratchets_enforced = false;
    }

    pub fn ratchets_active(&self) -> bool {
        self.ratchets_enabled
    }

    pub fn set_default_app_data(&mut self, app_data: DefaultAppData) {
        self.default_app_data = Some(app_data);
    }

    pub fn clear_default_app_data(&mut self) {
        self.default_app_data = None;
    }

    /// Return the current default app data, evaluating a dynamic generator if present.
    pub fn resolve_app_data(&self) -> Option<Vec<u8>> {
        match &self.default_app_data {
            None => None,
            Some(DefaultAppData::Static(data)) => Some(data.clone()),
            Some(DefaultAppData::Dynamic(generator)) => generator(),
        }
    }

    /// Build signed announce data for this destination and return `(announce_bytes, has_ratchet)`.
    ///
    /// Wire layout:
    /// - `announce_data = public_key(64) || name_hash(10) || random_hash(10) || [ratchet(32)] || signature(64) || [app_data]`
    /// - `signed_data   = dest_hash(16) || public_key(64) || name_hash(10) || random_hash(10) || [ratchet(32)] || [app_data]`
    pub fn create_announce(
        &mut self,
        identity: &Identity,
        app_data: Option<&[u8]>,
        ratchet: Option<&[u8; 32]>,
        tag: Option<&[u8]>,
        now: f64,
    ) -> Result<(Vec<u8>, bool), DestinationError> {
        if !now.is_finite() || now < 0.0 || now > crate::announce::ANNOUNCE_TIME_MAX as f64 {
            return Err(DestinationError::InvalidAnnounceTime(now));
        }
        self.create_announce_at(
            identity,
            app_data,
            ratchet,
            tag,
            AnnounceTime::new(now as u64, now)?,
        )
    }

    /// Build announce data with independent wire-ordering and cache clocks.
    pub fn create_announce_at(
        &mut self,
        identity: &Identity,
        app_data: Option<&[u8]>,
        ratchet: Option<&[u8; 32]>,
        tag: Option<&[u8]>,
        time: AnnounceTime,
    ) -> Result<(Vec<u8>, bool), DestinationError> {
        let time = AnnounceTime::new(time.wire, time.cache)?;
        if self.dest_type != DestType::Single {
            return Err(DestinationError::EncryptionUnavailable);
        }
        if self.direction != Direction::In {
            return Err(DestinationError::EncryptionUnavailable);
        }

        self.path_responses
            .retain(|_, v| time.cache <= v.timestamp + PR_TAG_WINDOW);

        if let Some(tag_bytes) = tag {
            if let Some(cached) = self.path_responses.get(tag_bytes) {
                return Ok((cached.announce_data.clone(), cached.has_ratchet));
            }
        }

        let effective_app_data = app_data
            .map(|d| d.to_vec())
            .or_else(|| self.resolve_app_data());

        let public_key = identity.get_public_key();

        let random_bytes: [u8; 5] = rns_crypto::random::random_bytes(5).try_into().unwrap();
        let ts_bytes = &time.wire.to_be_bytes()[3..8];
        let mut random_hash = [0u8; 10];
        random_hash[..5].copy_from_slice(&random_bytes);
        random_hash[5..].copy_from_slice(ts_bytes);

        let has_ratchet = ratchet.is_some();

        let mut signed_data = Vec::with_capacity(16 + 64 + 10 + 10 + 32 + 256);
        signed_data.extend_from_slice(&self.hash);
        signed_data.extend_from_slice(&public_key);
        signed_data.extend_from_slice(&self.name_hash);
        signed_data.extend_from_slice(&random_hash);
        if let Some(r) = ratchet {
            signed_data.extend_from_slice(r);
        }
        if let Some(ref ad) = effective_app_data {
            signed_data.extend_from_slice(ad);
        }

        let signature = identity
            .sign(&signed_data)
            .ok_or(DestinationError::EncryptionUnavailable)?;

        // `dest_hash` lives in the packet header, not the announce body.
        let mut announce_data = Vec::with_capacity(64 + 10 + 10 + 32 + 64 + 256);
        announce_data.extend_from_slice(&public_key);
        announce_data.extend_from_slice(&self.name_hash);
        announce_data.extend_from_slice(&random_hash);
        if let Some(r) = ratchet {
            announce_data.extend_from_slice(r);
        }
        announce_data.extend_from_slice(&signature);
        if let Some(ref ad) = effective_app_data {
            announce_data.extend_from_slice(ad);
        }

        if let Some(tag_bytes) = tag {
            self.path_responses.insert(
                tag_bytes.to_vec(),
                PathResponseCache {
                    timestamp: time.cache,
                    announce_data: announce_data.clone(),
                    has_ratchet,
                },
            );
        }

        Ok((announce_data, has_ratchet))
    }

    pub fn announce_packet(
        &mut self,
        identity: &Identity,
        app_data: Option<&[u8]>,
        ratchet: Option<&[u8; 32]>,
        path_response: bool,
        tag: Option<&[u8]>,
        now: f64,
    ) -> Result<Vec<u8>, DestinationError> {
        if !now.is_finite() || now < 0.0 || now > crate::announce::ANNOUNCE_TIME_MAX as f64 {
            return Err(DestinationError::InvalidAnnounceTime(now));
        }
        self.announce_packet_at(
            identity,
            app_data,
            ratchet,
            path_response,
            tag,
            AnnounceTime::new(now as u64, now)?,
        )
    }

    pub fn announce_packet_at(
        &mut self,
        identity: &Identity,
        app_data: Option<&[u8]>,
        ratchet: Option<&[u8; 32]>,
        path_response: bool,
        tag: Option<&[u8]>,
        time: AnnounceTime,
    ) -> Result<Vec<u8>, DestinationError> {
        let (announce_data, has_ratchet) =
            self.create_announce_at(identity, app_data, ratchet, tag, time)?;

        let context = if path_response {
            rns_wire::context::PacketContext::PathResponse
        } else {
            rns_wire::context::PacketContext::None
        };

        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: has_ratchet,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: self.hash,
            context,
        };

        let mut raw = header.pack();
        raw.extend_from_slice(&announce_data);
        Ok(raw)
    }

    pub fn remove_link(&mut self, link_id: &[u8; 16]) {
        self.links.retain(|id| id != link_id);
    }

    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Hex-encoded destination hash for logging.
    pub fn hex_hash(&self) -> String {
        hex::encode(self.hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_destination() {
        let id = Identity::new();
        let dest =
            Destination::new(Some(&id), Direction::In, DestType::Single, "test.app").unwrap();
        assert_eq!(dest.dest_type, DestType::Single);
        assert_ne!(dest.hash, [0u8; 16]);
    }

    #[test]
    fn test_plain_destination() {
        let dest = Destination::new(None, Direction::In, DestType::Plain, "test.app").unwrap();
        assert_eq!(dest.dest_type, DestType::Plain);
    }

    #[test]
    fn test_plain_with_identity_fails() {
        let id = Identity::new();
        assert!(Destination::new(Some(&id), Direction::In, DestType::Plain, "test.app").is_err());
    }

    #[test]
    fn test_single_in_without_identity_auto_creates() {
        let dest = Destination::new(None, Direction::In, DestType::Single, "test.app").unwrap();
        assert!(dest.auto_identity().is_some());
        assert!(dest.auto_identity().unwrap().has_private_key());
        assert_ne!(dest.hash, [0u8; 16]);

        let auto_hash = dest.auto_identity().unwrap().hash;
        let python_hash_name = format!("test.app.{}", hex::encode(auto_hash));
        let expected_name_hash = name_hash(&python_hash_name);
        assert_eq!(dest.name_hash, expected_name_hash);
        assert_eq!(
            dest.hash,
            Destination::compute_hash(&expected_name_hash, Some(&auto_hash))
        );
        assert_ne!(
            dest.name_hash,
            name_hash("test.app"),
            "Python includes the generated identity hash in the name aspects before hashing"
        );
    }

    #[test]
    fn test_single_out_without_identity_fails() {
        assert!(Destination::new(None, Direction::Out, DestType::Single, "test.app").is_err());
    }

    #[test]
    fn test_dest_hash_deterministic() {
        let id = Identity::new();
        let dest1 =
            Destination::new(Some(&id), Direction::In, DestType::Single, "test.app").unwrap();
        let dest2 =
            Destination::new(Some(&id), Direction::Out, DestType::Single, "test.app").unwrap();
        assert_eq!(dest1.hash, dest2.hash);
    }

    #[test]
    fn test_dest_hash_computation() {
        let id = Identity::new();
        let nh = name_hash("test.app");
        let expected = Destination::compute_hash(&nh, Some(&id.hash));
        let dest =
            Destination::new(Some(&id), Direction::In, DestType::Single, "test.app").unwrap();
        assert_eq!(dest.hash, expected);
    }

    #[test]
    fn test_plain_dest_hash() {
        let nh = name_hash("test.plain");
        let expected = rns_crypto::sha::sha256(&nh);
        let dest = Destination::new(None, Direction::In, DestType::Plain, "test.plain").unwrap();
        assert_eq!(&dest.hash[..], &expected[..16]);
    }

    #[test]
    fn test_different_apps_different_hashes() {
        let id = Identity::new();
        let d1 = Destination::new(Some(&id), Direction::In, DestType::Single, "app.one").unwrap();
        let d2 = Destination::new(Some(&id), Direction::In, DestType::Single, "app.two").unwrap();
        assert_ne!(d1.hash, d2.hash);
    }

    #[test]
    fn test_hash_from_name_and_identity() {
        let id = Identity::new();
        let dest =
            Destination::new(Some(&id), Direction::In, DestType::Single, "test.app").unwrap();
        let computed = Destination::hash_from_name_and_identity("test.app", Some(&id.hash));
        assert_eq!(dest.hash, computed);
    }

    #[test]
    fn test_only_validate_signature_flag() {
        let id = Identity::new();
        let mut dest =
            Destination::new(Some(&id), Direction::In, DestType::Single, "test.app").unwrap();
        assert!(!dest.only_validate_signature);

        dest.set_only_validate_signature(true);
        assert!(dest.only_validate_signature);
    }

    #[test]
    fn test_prove() {
        let id = Identity::new();
        let dest =
            Destination::new(Some(&id), Direction::In, DestType::Single, "test.app").unwrap();
        let packet_hash = rns_crypto::sha::sha256(b"test packet");

        let proof = dest.prove(&packet_hash, &id, true).unwrap();
        assert_eq!(proof.len(), 64);

        let proof = dest.prove(&packet_hash, &id, false).unwrap();
        assert_eq!(proof.len(), 32 + 64);
    }

    #[test]
    fn test_prove_plain_fails() {
        let dest = Destination::new(None, Direction::In, DestType::Plain, "test.app").unwrap();
        let id = Identity::new();
        assert!(dest.prove(b"test", &id, true).is_err());
    }

    #[test]
    fn test_encrypt_with_ratchet() {
        let id = Identity::new();
        let dest =
            Destination::new(Some(&id), Direction::Out, DestType::Single, "test.app").unwrap();

        let ratchet_prv = rns_crypto::x25519::X25519PrivateKey::generate();
        let ratchet_pub = ratchet_prv.public_key().to_bytes();

        let plaintext = b"ratcheted message";
        let ct = dest.encrypt(plaintext, &id, Some(&ratchet_pub)).unwrap();

        assert!(id.decrypt(&ct, None, false).is_err());

        let ratchet_prv_bytes = ratchet_prv.to_bytes();
        let ratchets: Vec<&[u8; 32]> = vec![&ratchet_prv_bytes];
        let pt = id.decrypt(&ct, Some(&ratchets), false).unwrap();
        assert_eq!(&pt[..], plaintext);
    }

    #[test]
    fn test_take_auto_identity() {
        let mut dest = Destination::new(None, Direction::In, DestType::Single, "test.app").unwrap();
        assert!(dest.auto_identity().is_some());

        let taken = dest.take_auto_identity();
        assert!(taken.is_some());
        assert!(taken.unwrap().has_private_key());
        assert!(dest.auto_identity().is_none());
    }

    #[test]
    fn cached_path_response_preserves_ratcheted_announce_context() {
        let identity = Identity::new();
        let mut dest = Destination::new(
            Some(&identity),
            Direction::In,
            DestType::Single,
            "test.path",
        )
        .unwrap();
        let ratchet = [0xA5; 32];
        let tag = b"request-tag";

        let first = dest
            .announce_packet(
                &identity,
                Some(b"app-data"),
                Some(&ratchet),
                true,
                Some(tag),
                100.0,
            )
            .unwrap();
        let replay = dest
            .announce_packet(&identity, Some(b"changed"), None, true, Some(tag), 101.0)
            .unwrap();

        assert_eq!(
            replay, first,
            "a matching tag must replay exact signed bytes"
        );
        let (header, _) = rns_wire::header::PacketHeader::unpack(&replay).unwrap();
        assert!(
            header.flags.context_flag,
            "the cached payload's ratchet flag must not depend on current caller state"
        );
    }

    #[test]
    fn cached_path_response_preserves_unratcheted_announce_context() {
        let identity = Identity::new();
        let mut dest = Destination::new(
            Some(&identity),
            Direction::In,
            DestType::Single,
            "test.path",
        )
        .unwrap();
        let ratchet = [0x5A; 32];
        let tag = b"request-tag";

        let first = dest
            .announce_packet(&identity, None, None, true, Some(tag), 100.0)
            .unwrap();
        let replay = dest
            .announce_packet(&identity, None, Some(&ratchet), true, Some(tag), 101.0)
            .unwrap();

        assert_eq!(
            replay, first,
            "a matching tag must replay exact signed bytes"
        );
        let (header, _) = rns_wire::header::PacketHeader::unpack(&replay).unwrap();
        assert!(
            !header.flags.context_flag,
            "the cached payload's ratchet flag must not depend on current caller state"
        );
    }

    #[test]
    fn announce_wire_time_is_independent_from_path_cache_time() {
        let identity = Identity::new();
        let mut dest = Destination::new(
            Some(&identity),
            Direction::In,
            DestType::Single,
            "test.time",
        )
        .unwrap();
        let wire_time = 0x01_0203_0405;
        let raw = dest
            .announce_packet_at(
                &identity,
                None,
                None,
                false,
                None,
                AnnounceTime::new(wire_time, 9_999_999.0).unwrap(),
            )
            .unwrap();
        let (_, header_len) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        let announce = crate::announce::AnnounceData::unpack(&raw[header_len..], false).unwrap();
        assert_eq!(&announce.random_hash[5..], &wire_time.to_be_bytes()[3..]);

        assert!(matches!(
            dest.announce_packet_at(
                &identity,
                None,
                None,
                false,
                None,
                AnnounceTime {
                    wire: crate::announce::ANNOUNCE_TIME_MAX + 1,
                    cache: 1.0,
                },
            ),
            Err(DestinationError::InvalidAnnounceTime(_))
        ));
    }
}
