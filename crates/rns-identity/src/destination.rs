use std::collections::HashMap;

use rns_crypto::sha::truncated_hash;
use rns_crypto::token;
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::identity::{DecryptionResult, Identity};
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
/// Path-response tag deduplication window, in seconds.
pub const PR_TAG_WINDOW: f64 = 30.0;
/// Default GROUP destination key size, in bytes.
pub const GROUP_KEY_LENGTH: usize = token::KEY_LENGTH;

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
    #[error("name component contains a dot: {0}")]
    InvalidNameComponent(String),
    #[error("operation requires a GROUP destination")]
    NotGroup,
    #[error("invalid GROUP key length: expected 32 or 64, got {0}")]
    InvalidGroupKeyLength(usize),
    #[error("operation requires a SINGLE destination")]
    NotSingle,
    #[error("operation requires an inbound destination")]
    NotInbound,
    #[error("identity does not address this destination")]
    IdentityMismatch,
    #[error("identity cannot sign")]
    SigningUnavailable,
}

/// Wire-shape controls for [`Destination::pack_packet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationPacketOptions {
    /// DATA, ANNOUNCE, LINKREQUEST, or PROOF.
    pub packet_type: rns_wire::flags::PacketType,
    /// One-byte packet context.
    pub context: rns_wire::context::PacketContext,
    /// Context flag bit carried in the packet flags.
    pub context_flag: bool,
    /// Header1 for ordinary packets, Header2 for transport-wrapped packets.
    pub header_type: rns_wire::flags::HeaderType,
    /// Broadcast or transport propagation mode.
    pub transport_type: rns_wire::flags::TransportType,
    /// Required for Header2 packets and ignored for Header1 packets.
    pub transport_id: Option<[u8; 16]>,
}

impl Default for DestinationPacketOptions {
    fn default() -> Self {
        Self {
            packet_type: rns_wire::flags::PacketType::Data,
            context: rns_wire::context::PacketContext::None,
            context_flag: false,
            header_type: rns_wire::flags::HeaderType::Header1,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            transport_id: None,
        }
    }
}

/// Destination-aware packed packet plus outbound ratchet metadata.
#[derive(Debug, Clone)]
pub struct PackedDestinationPacket {
    /// Complete packet with raw bytes and cached hashes.
    pub packet: rns_wire::packet::Packet,
    /// Ratchet used for SINGLE-destination encryption, if any.
    pub ratchet_id: Option<[u8; crate::identity::RATCHET_ID_LENGTH]>,
}

/// Errors from destination-aware packet construction.
#[derive(Debug, Error)]
pub enum DestinationPacketError {
    #[error(transparent)]
    Destination(#[from] DestinationError),
    #[error(transparent)]
    Packet(#[from] rns_wire::packet::PacketError),
    #[error("SINGLE packet encryption requires its destination identity")]
    MissingIdentity,
    #[error("Header2 packets require a transport id")]
    MissingTransportId,
    #[error("ordinary Link packets must use the Link runtime")]
    LinkRuntimeRequired,
    #[error("LRPROOF packets require a Link destination")]
    LrproofRequiresLink,
}

pub struct Destination {
    pub dest_type: DestType,
    pub direction: Direction,
    pub hash: [u8; 16],
    pub name_hash: [u8; 10],
    pub app_name: String,
    /// Human-readable full destination name, including the identity hash.
    pub name: String,
    /// Identity hash bound into this destination address, when applicable.
    pub identity_hash: Option<[u8; 16]>,
    pub proof_strategy: ProofStrategy,
    /// If set, incoming data is signature-checked but not decrypted.
    pub only_validate_signature: bool,
    group_key: Option<Zeroizing<Vec<u8>>>,

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
    pub const PR_TAG_WINDOW: f64 = PR_TAG_WINDOW;
    pub const RATCHET_COUNT: usize = rns_wire::constants::RATCHET_COUNT;
    pub const RATCHET_INTERVAL: u64 = rns_wire::constants::RATCHET_INTERVAL;

    /// Build a full dotted destination name from an app name and aspects.
    ///
    /// App and aspect arguments are individual components and therefore must
    /// not contain dots. An identity hash is appended when supplied.
    pub fn expand_name(
        identity: Option<&Identity>,
        app_name: &str,
        aspects: &[&str],
    ) -> Result<String, DestinationError> {
        if app_name.contains('.') {
            return Err(DestinationError::InvalidNameComponent(app_name.to_string()));
        }
        if let Some(aspect) = aspects.iter().find(|aspect| aspect.contains('.')) {
            return Err(DestinationError::InvalidNameComponent(
                (*aspect).to_string(),
            ));
        }

        let identity_component = usize::from(identity.is_some());
        let mut components = Vec::with_capacity(1 + aspects.len() + identity_component);
        components.push(app_name.to_string());
        components.extend(aspects.iter().map(|aspect| (*aspect).to_string()));
        if let Some(identity) = identity {
            components.push(identity.hexhash());
        }
        Ok(components.join("."))
    }

    /// Split a full dotted name into its app name and remaining aspects.
    pub fn app_and_aspects_from_name(full_name: &str) -> (&str, Vec<&str>) {
        let mut components = full_name.split('.');
        let app_name = components.next().unwrap_or_default();
        (app_name, components.collect())
    }

    /// Create a destination from separate app and aspect components.
    pub fn new_with_aspects(
        identity: Option<&Identity>,
        direction: Direction,
        dest_type: DestType,
        app_name: &str,
        aspects: &[&str],
    ) -> Result<Self, DestinationError> {
        let full_name = Self::expand_name(None, app_name, aspects)?;
        Self::new(identity, direction, dest_type, &full_name)
    }

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
                let name = format!("{hash_name}.{}", hex::encode(id_ref));

                Ok(Self {
                    dest_type,
                    direction,
                    hash,
                    name_hash: nh,
                    app_name: app_name.to_string(),
                    name,
                    identity_hash: Some(id_ref),
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
                    name: app_name.to_string(),
                    identity_hash: None,
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
                    name: identity
                        .map(|identity| format!("{app_name}.{}", identity.hexhash()))
                        .unwrap_or_else(|| app_name.to_string()),
                    identity_hash: identity.map(|identity| identity.hash),
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
        self.group_key = Some(Zeroizing::new(key));
    }

    /// Generate and install a fresh AES-256 GROUP destination key.
    pub fn generate_group_key(&mut self) -> Result<(), DestinationError> {
        if self.dest_type != DestType::Group {
            return Err(DestinationError::NotGroup);
        }
        self.group_key = Some(token::generate_key());
        Ok(())
    }

    /// Validate and install a GROUP destination key.
    ///
    /// The 64-byte AES-256 form is generated by default; the 32-byte legacy
    /// AES-128 form remains accepted for wire compatibility.
    pub fn load_group_key(&mut self, key: &[u8]) -> Result<(), DestinationError> {
        if self.dest_type != DestType::Group {
            return Err(DestinationError::NotGroup);
        }
        if key.len() != token::LEGACY_KEY_LENGTH && key.len() != GROUP_KEY_LENGTH {
            return Err(DestinationError::InvalidGroupKeyLength(key.len()));
        }
        self.group_key = Some(Zeroizing::new(key.to_vec()));
        Ok(())
    }

    /// Borrow the installed GROUP key.
    pub fn group_key(&self) -> Result<&[u8], DestinationError> {
        if self.dest_type != DestType::Group {
            return Err(DestinationError::NotGroup);
        }
        self.group_key
            .as_ref()
            .map(|key| key.as_slice())
            .ok_or(DestinationError::EncryptionUnavailable)
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
        self.ensure_identity(identity)?;
        identity
            .prove(packet_hash, implicit_proof)
            .map_err(DestinationError::Identity)
    }

    /// Sign a message with the identity bound to this SINGLE destination.
    pub fn sign(&self, message: &[u8], identity: &Identity) -> Result<[u8; 64], DestinationError> {
        if self.dest_type != DestType::Single {
            return Err(DestinationError::NotSingle);
        }
        self.ensure_identity(identity)?;
        identity
            .sign(message)
            .ok_or(DestinationError::SigningUnavailable)
    }

    /// Pack one packet with Python-compatible destination encryption rules.
    ///
    /// Announce and LinkRequest packets are plaintext. Resource payload,
    /// Resource proof, keepalive, cache-request, and LRPROOF contexts are also
    /// already protected or intentionally plaintext and therefore bypass
    /// destination encryption. Other SINGLE/GROUP packets are encrypted here.
    ///
    /// Ordinary Link packets remain owned by `LinkSession`; LRPROOF is the
    /// sole Link context accepted by this stateless builder.
    pub fn pack_packet(
        &self,
        data: &[u8],
        identity: Option<&Identity>,
        remote_ratchet_pub: Option<&[u8; 32]>,
        options: DestinationPacketOptions,
    ) -> Result<PackedDestinationPacket, DestinationPacketError> {
        use rns_wire::context::PacketContext;
        use rns_wire::flags::{DestinationType, HeaderType, PacketType};

        if options.context == PacketContext::Lrproof && self.dest_type != DestType::Link {
            return Err(DestinationPacketError::LrproofRequiresLink);
        }
        if self.dest_type == DestType::Link && options.context != PacketContext::Lrproof {
            return Err(DestinationPacketError::LinkRuntimeRequired);
        }

        let bypass_encryption = matches!(
            options.packet_type,
            PacketType::Announce | PacketType::LinkRequest
        ) || (options.packet_type == PacketType::Proof
            && options.context == PacketContext::ResourcePrf)
            || options.context.is_plaintext_context()
            || options.context == PacketContext::Lrproof;

        let selected_ratchet = remote_ratchet_pub.or(self.remote_ratchet_pub.as_ref());
        let (payload, ratchet_id) = if bypass_encryption {
            (data.to_vec(), None)
        } else {
            match self.dest_type {
                DestType::Plain => (data.to_vec(), None),
                DestType::Single => {
                    let identity = identity.ok_or(DestinationPacketError::MissingIdentity)?;
                    self.ensure_identity(identity)?;
                    let ciphertext = identity
                        .encrypt(data, selected_ratchet)
                        .map_err(DestinationError::Identity)?;
                    let ratchet_id = selected_ratchet.map(Identity::ratchet_id);
                    (ciphertext, ratchet_id)
                }
                DestType::Group => {
                    let key = self
                        .group_key
                        .as_ref()
                        .ok_or(DestinationError::EncryptionUnavailable)?;
                    (
                        token::encrypt(data, key)
                            .map_err(|_| DestinationError::DecryptionFailed)?,
                        None,
                    )
                }
                DestType::Link => unreachable!("ordinary Link packets rejected above"),
            }
        };

        let destination_type = if options.context == PacketContext::Lrproof {
            DestinationType::Link
        } else {
            match self.dest_type {
                DestType::Single => DestinationType::Single,
                DestType::Group => DestinationType::Group,
                DestType::Plain => DestinationType::Plain,
                DestType::Link => DestinationType::Link,
            }
        };
        let transport_id = match options.header_type {
            HeaderType::Header1 => None,
            HeaderType::Header2 => Some(
                options
                    .transport_id
                    .ok_or(DestinationPacketError::MissingTransportId)?,
            ),
        };
        let packet = rns_wire::packet::Packet::new(
            rns_wire::header::PacketHeader {
                flags: rns_wire::flags::PacketFlags {
                    header_type: options.header_type,
                    context_flag: options.context_flag,
                    transport_type: options.transport_type,
                    destination_type,
                    packet_type: options.packet_type,
                },
                hops: 0,
                transport_id,
                destination_hash: self.hash,
                context: options.context,
            },
            payload,
        )?;

        Ok(PackedDestinationPacket { packet, ratchet_id })
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
            DestType::Single => {
                self.ensure_identity(identity)?;
                identity
                    .encrypt(plaintext, remote_ratchet_pub)
                    .map_err(DestinationError::Identity)
            }
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
        self.decrypt_with_ratchet_id(ciphertext, identity, ratchet_keys)
            .map(|result| result.plaintext)
    }

    /// Decrypt data and report which retained ratchet authenticated it.
    pub fn decrypt_with_ratchet_id(
        &self,
        ciphertext: &[u8],
        identity: &Identity,
        ratchet_keys: Option<&[[u8; 32]]>,
    ) -> Result<DecryptionResult, DestinationError> {
        match self.dest_type {
            DestType::Plain => Ok(DecryptionResult {
                plaintext: ciphertext.to_vec(),
                ratchet_id: None,
            }),
            DestType::Single => {
                self.ensure_identity(identity)?;
                let ratchet_refs: Option<Vec<&[u8; 32]>> = if self.ratchets_enabled {
                    ratchet_keys.map(|keys| keys.iter().collect())
                } else {
                    None
                };
                let enforce = self.ratchets_enforced;
                identity
                    .decrypt_with_ratchet_id(ciphertext, ratchet_refs.as_deref(), enforce)
                    .map_err(DestinationError::Identity)
            }
            DestType::Group => {
                let key = self
                    .group_key
                    .as_ref()
                    .ok_or(DestinationError::EncryptionUnavailable)?;
                token::decrypt(ciphertext, key)
                    .map(|plaintext| DecryptionResult {
                        plaintext,
                        ratchet_id: None,
                    })
                    .map_err(|_| DestinationError::DecryptionFailed)
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
        self.receive_packet(packet_type, data, data, identity)
    }

    /// Decrypt and dispatch an incoming packet while preserving the complete
    /// raw packet for the packet callback.
    ///
    /// Runtime dispatchers should prefer this over [`Self::receive`]. The
    /// latter remains available for callers that only have the packet payload.
    pub fn receive_packet(
        &self,
        packet_type: u8,
        data: &[u8],
        raw_packet: &[u8],
        identity: &Identity,
    ) -> Result<Option<Vec<u8>>, DestinationError> {
        self.receive_packet_with_ratchets(packet_type, data, raw_packet, identity, None)
    }

    /// Decrypt and dispatch an incoming packet using retained ratchet keys.
    ///
    /// Live destination runtimes use this form when they own a persistent
    /// ratchet ring. LINKREQUEST packets still bypass destination decryption.
    pub fn receive_packet_with_ratchets(
        &self,
        packet_type: u8,
        data: &[u8],
        raw_packet: &[u8],
        identity: &Identity,
        ratchet_keys: Option<&[[u8; 32]]>,
    ) -> Result<Option<Vec<u8>>, DestinationError> {
        if packet_type == 0x02 {
            return Ok(Some(data.to_vec()));
        }

        let plaintext = self.decrypt_with_ratchets(data, identity, ratchet_keys)?;

        if packet_type == 0x00 {
            if let Some(ref cb) = self.packet_callback {
                cb(&plaintext, raw_packet);
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

    pub fn accepts_links(&self) -> bool {
        self.accept_link_requests
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
            return Err(DestinationError::NotSingle);
        }
        if self.direction != Direction::In {
            return Err(DestinationError::NotInbound);
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

        Ok(self.pack_announce_packet(&announce_data, has_ratchet, path_response))
    }

    /// Return an exact cached path-response packet for `tag`, if it is still
    /// inside the local deduplication window.
    ///
    /// This lookup does not create a new announce or consume a new wire-order
    /// value. Durable announce planners can therefore service a repeated path
    /// request before deciding whether a fresh announce may be emitted.
    pub fn cached_path_response_packet(
        &mut self,
        tag: &[u8],
        cache_now: f64,
    ) -> Result<Option<Vec<u8>>, DestinationError> {
        if !cache_now.is_finite() || cache_now < 0.0 {
            return Err(DestinationError::InvalidAnnounceTime(cache_now));
        }

        self.path_responses
            .retain(|_, cached| cache_now <= cached.timestamp + PR_TAG_WINDOW);
        Ok(self.path_responses.get(tag).map(|cached| {
            self.pack_announce_packet(&cached.announce_data, cached.has_ratchet, true)
        }))
    }

    fn pack_announce_packet(
        &self,
        announce_data: &[u8],
        has_ratchet: bool,
        path_response: bool,
    ) -> Vec<u8> {
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
        raw.extend_from_slice(announce_data);
        raw
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

    /// Python-compatible spelling for the destination's hexadecimal hash.
    pub fn hexhash(&self) -> String {
        self.hex_hash()
    }

    fn ensure_identity(&self, identity: &Identity) -> Result<(), DestinationError> {
        if self.identity_hash != Some(identity.hash)
            || Self::compute_hash(&self.name_hash, Some(&identity.hash)) != self.hash
        {
            return Err(DestinationError::IdentityMismatch);
        }
        Ok(())
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<{}:{}>", self.name, self.hex_hash())
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
        assert_eq!(dest.identity_hash, Some(id.hash));
        assert_eq!(dest.name, format!("test.app.{}", id.hexhash()));
        assert_eq!(
            dest.to_string(),
            format!("<test.app.{}:{}>", id.hexhash(), dest.hexhash())
        );
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
    fn name_helpers_match_component_constructor() {
        let id = Identity::new();
        let expanded = Destination::expand_name(Some(&id), "test", &["service", "chat"]).unwrap();
        assert_eq!(expanded, format!("test.service.chat.{}", id.hexhash()));
        assert!(Destination::expand_name(None, "test.app", &[]).is_err());
        assert!(Destination::expand_name(None, "test", &["bad.aspect"]).is_err());

        let (app_name, aspects) = Destination::app_and_aspects_from_name("test.service.chat");
        assert_eq!(app_name, "test");
        assert_eq!(aspects, vec!["service", "chat"]);

        let from_parts = Destination::new_with_aspects(
            Some(&id),
            Direction::Out,
            DestType::Single,
            "test",
            &["service", "chat"],
        )
        .unwrap();
        let from_full = Destination::new(
            Some(&id),
            Direction::Out,
            DestType::Single,
            "test.service.chat",
        )
        .unwrap();
        assert_eq!(from_parts.hash, from_full.hash);
        assert_eq!(from_parts.name, expanded);
    }

    #[test]
    fn group_key_api_generates_valid_keys() {
        let identity = Identity::new();
        let mut group = Destination::new(
            Some(&identity),
            Direction::In,
            DestType::Group,
            "test.group",
        )
        .unwrap();
        group.generate_group_key().unwrap();
        assert_eq!(group.group_key().unwrap().len(), GROUP_KEY_LENGTH);

        let ciphertext = group.encrypt(b"group plaintext", &identity, None).unwrap();
        assert_eq!(
            group.decrypt(&ciphertext, &identity).unwrap(),
            b"group plaintext"
        );

        let legacy = [0xA5; 32];
        group.load_group_key(&legacy).unwrap();
        assert_eq!(group.group_key().unwrap(), legacy);
        assert!(matches!(
            group.load_group_key(&[0u8; 31]),
            Err(DestinationError::InvalidGroupKeyLength(31))
        ));

        let mut plain =
            Destination::new(None, Direction::In, DestType::Plain, "test.plain").unwrap();
        assert!(matches!(
            plain.generate_group_key(),
            Err(DestinationError::NotGroup)
        ));
    }

    #[test]
    fn destination_sign_rejects_unbound_identity() {
        let identity = Identity::new();
        let other = Identity::new();
        let destination = Destination::new(
            Some(&identity),
            Direction::In,
            DestType::Single,
            "test.sign",
        )
        .unwrap();

        let signature = destination.sign(b"signed", &identity).unwrap();
        assert!(identity.verify(b"signed", &signature));
        assert!(matches!(
            destination.sign(b"signed", &other),
            Err(DestinationError::IdentityMismatch)
        ));
    }

    #[test]
    fn accepts_links_can_be_queried_and_changed() {
        let identity = Identity::new();
        let mut destination = Destination::new(
            Some(&identity),
            Direction::In,
            DestType::Single,
            "test.links",
        )
        .unwrap();
        assert!(destination.accepts_links());
        destination.set_accepts_links(false);
        assert!(!destination.accepts_links());
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
    fn receive_packet_dispatches_plaintext_with_complete_raw_packet() {
        use std::sync::{Arc, Mutex};

        let identity = Identity::new();
        let mut inbound = Destination::new(
            Some(&identity),
            Direction::In,
            DestType::Single,
            "test.receive",
        )
        .unwrap();
        let outbound = Destination::new(
            Some(&identity),
            Direction::Out,
            DestType::Single,
            "test.receive",
        )
        .unwrap();
        let plaintext = b"destination callback";
        let ciphertext = outbound.encrypt(plaintext, &identity, None).unwrap();
        let raw_packet = [b"header".as_slice(), ciphertext.as_slice()].concat();
        let observed = Arc::new(Mutex::new(None));
        let callback_observed = Arc::clone(&observed);
        inbound.set_packet_callback(Box::new(move |data, raw| {
            *callback_observed.lock().unwrap() = Some((data.to_vec(), raw.to_vec()));
        }));

        let decrypted = inbound
            .receive_packet(0x00, &ciphertext, &raw_packet, &identity)
            .unwrap()
            .unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(
            *observed.lock().unwrap(),
            Some((plaintext.to_vec(), raw_packet))
        );
    }

    #[test]
    fn proof_strategy_honors_application_decision() {
        let identity = Identity::new();
        let mut destination = Destination::new(
            Some(&identity),
            Direction::In,
            DestType::Single,
            "test.proof",
        )
        .unwrap();

        assert!(!destination.should_prove(b"packet"));
        destination.set_proof_strategy(ProofStrategy::ProveAll);
        assert!(destination.should_prove(b"packet"));
        destination.set_proof_strategy(ProofStrategy::ProveApp);
        assert!(!destination.should_prove(b"packet"));
        destination.set_proof_requested_callback(Box::new(|packet| packet == b"allowed"));
        assert!(destination.should_prove(b"allowed"));
        assert!(!destination.should_prove(b"denied"));
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

        let mut inbound =
            Destination::new(Some(&id), Direction::In, DestType::Single, "test.app").unwrap();
        inbound.enable_ratchets(false);
        let decrypted = inbound
            .decrypt_with_ratchet_id(&ct, &id, Some(&[ratchet_prv_bytes]))
            .unwrap();
        assert_eq!(decrypted.plaintext, plaintext);
        assert_eq!(
            decrypted.ratchet_id,
            Some(Identity::ratchet_id(&ratchet_pub))
        );
    }

    #[test]
    fn destination_packet_builder_encrypts_single_data_and_reports_ratchet() {
        let identity = Identity::new();
        let destination = Destination::new(
            Some(&identity),
            Direction::Out,
            DestType::Single,
            "test.packet-builder",
        )
        .unwrap();
        let ratchet_private = rns_crypto::x25519::X25519PrivateKey::generate();
        let ratchet_public = ratchet_private.public_key().to_bytes();
        let packed = destination
            .pack_packet(
                b"builder payload",
                Some(&identity),
                Some(&ratchet_public),
                DestinationPacketOptions::default(),
            )
            .unwrap();

        assert_eq!(
            packed.packet.header.flags.packet_type,
            rns_wire::flags::PacketType::Data
        );
        assert_eq!(
            packed.packet.header.flags.destination_type,
            rns_wire::flags::DestinationType::Single
        );
        assert_ne!(packed.packet.data(), b"builder payload");
        assert_eq!(
            packed.ratchet_id,
            Some(Identity::ratchet_id(&ratchet_public))
        );
        let private = ratchet_private.to_bytes();
        let plaintext = identity
            .decrypt(packed.packet.data(), Some(&[&private]), false)
            .unwrap();
        assert_eq!(plaintext, b"builder payload");
    }

    #[test]
    fn destination_packet_builder_preserves_python_plaintext_cases() {
        use rns_wire::context::PacketContext;
        use rns_wire::flags::PacketType;

        let identity = Identity::new();
        let destination = Destination::new(
            Some(&identity),
            Direction::Out,
            DestType::Single,
            "test.packet-plaintext",
        )
        .unwrap();
        let cases = [
            (PacketType::Announce, PacketContext::None),
            (PacketType::LinkRequest, PacketContext::None),
            (PacketType::Proof, PacketContext::ResourcePrf),
            (PacketType::Data, PacketContext::Resource),
            (PacketType::Data, PacketContext::Keepalive),
            (PacketType::Data, PacketContext::CacheRequest),
        ];

        for (packet_type, context) in cases {
            let packed = destination
                .pack_packet(
                    b"already protected",
                    None,
                    None,
                    DestinationPacketOptions {
                        packet_type,
                        context,
                        ..DestinationPacketOptions::default()
                    },
                )
                .unwrap();
            assert_eq!(packed.packet.data(), b"already protected");
            assert_eq!(packed.ratchet_id, None);
        }
    }

    #[test]
    fn destination_packet_builder_validates_header2_and_link_ownership() {
        use rns_wire::context::PacketContext;
        use rns_wire::flags::{HeaderType, TransportType};

        let plain =
            Destination::new(None, Direction::Out, DestType::Plain, "test.header2").unwrap();
        assert!(matches!(
            plain.pack_packet(
                b"payload",
                None,
                None,
                DestinationPacketOptions {
                    header_type: HeaderType::Header2,
                    transport_type: TransportType::Transport,
                    ..DestinationPacketOptions::default()
                }
            ),
            Err(DestinationPacketError::MissingTransportId)
        ));
        let transport_id = [0xA5; 16];
        let packed = plain
            .pack_packet(
                b"payload",
                None,
                None,
                DestinationPacketOptions {
                    header_type: HeaderType::Header2,
                    transport_type: TransportType::Transport,
                    transport_id: Some(transport_id),
                    ..DestinationPacketOptions::default()
                },
            )
            .unwrap();
        assert_eq!(packed.packet.header.transport_id, Some(transport_id));
        assert!(matches!(
            plain.pack_packet(
                b"invalid proof",
                None,
                None,
                DestinationPacketOptions {
                    context: PacketContext::Lrproof,
                    ..DestinationPacketOptions::default()
                }
            ),
            Err(DestinationPacketError::LrproofRequiresLink)
        ));

        let link = Destination::new(None, Direction::Out, DestType::Link, "test.link").unwrap();
        assert!(matches!(
            link.pack_packet(b"payload", None, None, DestinationPacketOptions::default()),
            Err(DestinationPacketError::LinkRuntimeRequired)
        ));
        let proof = link
            .pack_packet(
                b"link request proof",
                None,
                None,
                DestinationPacketOptions {
                    context: PacketContext::Lrproof,
                    ..DestinationPacketOptions::default()
                },
            )
            .unwrap();
        assert_eq!(proof.packet.data(), b"link request proof");
        assert_eq!(
            proof.packet.header.flags.destination_type,
            rns_wire::flags::DestinationType::Link
        );
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
    fn cached_path_response_can_be_retrieved_without_creating_an_announce() {
        let identity = Identity::new();
        let mut dest = Destination::new(
            Some(&identity),
            Direction::In,
            DestType::Single,
            "test.path",
        )
        .unwrap();
        let tag = b"request-tag";
        let first = dest
            .announce_packet(&identity, Some(b"app-data"), None, true, Some(tag), 100.0)
            .unwrap();

        assert_eq!(
            dest.cached_path_response_packet(tag, 101.0).unwrap(),
            Some(first),
            "a durable planner must be able to replay the signed packet without advancing time"
        );
        assert_eq!(
            dest.cached_path_response_packet(tag, 131.0).unwrap(),
            None,
            "changing the expiry comparison must not leave stale path responses replayable"
        );
        assert!(dest.cached_path_response_packet(tag, f64::NAN).is_err());
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

    #[test]
    fn announce_rejects_wrong_destination_shape_precisely() {
        let identity = Identity::new();
        let mut group =
            Destination::new(None, Direction::In, DestType::Group, "test.group").unwrap();
        assert!(matches!(
            group.announce_packet(&identity, None, None, false, None, 1.0),
            Err(DestinationError::NotSingle)
        ));

        let mut outbound = Destination::new(
            Some(&identity),
            Direction::Out,
            DestType::Single,
            "test.out",
        )
        .unwrap();
        assert!(matches!(
            outbound.announce_packet(&identity, None, None, false, None, 1.0),
            Err(DestinationError::NotInbound)
        ));
    }
}
