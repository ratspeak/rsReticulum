use std::time::{Duration, Instant};

use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_crypto::sha::truncated_hash;

use crate::constants::*;
use crate::encryption::{LinkCryptoError, link_decrypt, link_encrypt};
use crate::handshake::{
    EphemeralKeys, HandshakeError, LinkProofData, LinkRequestData, compute_link_id,
    perform_handshake,
};
use crate::keepalive::KeepaliveState;
use crate::key_derivation::LinkKeys;
use crate::mtu_discovery::SignallingData;
use crate::request::RequestReceipt;

/// Link lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Link request sent or received, awaiting proof.
    Pending = 0x00,
    /// ECDH complete, awaiting the RTT round-trip that activates the link.
    Handshake = 0x01,
    /// Link fully established; encrypted traffic flows.
    Active = 0x02,
    /// No inbound traffic for `stale_time`.
    Stale = 0x03,
    /// Link torn down and keys purged.
    Closed = 0x04,
}

/// Reason for link closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Timeout,
    InitiatorClosed,
    DestinationClosed,
}

/// Latest physical-layer measurements observed for a Link.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LinkPhyStats {
    pub rssi: Option<f64>,
    pub snr: Option<f64>,
    pub q: Option<f64>,
}

/// Resource acceptance strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourceStrategy {
    #[default]
    AcceptNone,
    AcceptApp,
    AcceptAll,
}

/// Result of checking whether to accept a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceAcceptance {
    Accept,
    Reject,
    /// Application must decide (AcceptApp strategy).
    AskApp,
}

/// Outbound resource state as observed by the link.
///
/// Duplicates a subset of `rns-protocol`'s `ResourceState` so `rns-link` can make
/// readiness decisions without a reverse dependency on `rns-protocol`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundResourceState {
    Transferring,
    /// All parts sent, awaiting the receiver's proof.
    AwaitingProof,
    Complete,
    Failed,
}

/// The result of a `request()` call indicating how the request should be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestSendMode {
    /// Request fits in a single packet (data size <= MDU).
    Packet(Vec<u8>),
    /// Request exceeds MDU and must be sent as a resource transfer.
    /// Contains the packed request data that should be wrapped in a Resource.
    Resource(Vec<u8>),
}

fn msgpack_value_from_bytes_or_binary(data: &[u8]) -> rmpv::Value {
    let mut cursor = std::io::Cursor::new(data);
    match rmpv::decode::read_value(&mut cursor) {
        Ok(value) if cursor.position() as usize == data.len() => value,
        _ => rmpv::Value::Binary(data.to_vec()),
    }
}

fn msgpack_value_to_bytes(value: &rmpv::Value) -> Result<Vec<u8>, LinkCryptoError> {
    if let Some(bytes) = value.as_slice() {
        Ok(bytes.to_vec())
    } else if let Some(text) = value.as_str() {
        Ok(text.as_bytes().to_vec())
    } else {
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, value)
            .map_err(|_| LinkCryptoError::DecryptionFailed)?;
        Ok(encoded)
    }
}

/// An encrypted bidirectional tunnel between two peers.
///
/// The state machine is driven by `tick()` calls from the owning actor/runtime;
/// there is no internal watchdog thread.
pub struct Link {
    /// Truncated SHA-256 of the request's hashable part.
    pub link_id: [u8; 16],
    pub state: LinkState,
    /// Terminal close reason, retained after keys and transient state are
    /// purged. Remains `None` until an orderly or timeout close occurs.
    pub teardown_reason: Option<CloseReason>,
    pub is_initiator: bool,
    pub mode: u8,

    ephemeral_keys: Option<EphemeralKeys>,
    peer_x25519_pub: Option<[u8; 32]>,
    /// Peer's Ed25519 identity key — used to verify the link proof signature.
    peer_ed25519_pub: Option<[u8; 32]>,

    /// Identity signing key for `Link::sign()` and local-side proofs.
    sig_prv: Option<Ed25519PrivateKey>,

    session_keys: Option<LinkKeys>,

    pub request_time: Instant,
    pub rtt: Option<Duration>,
    pub establishment_timeout: Duration,
    pub activated_at: Option<Instant>,
    pub stale_since: Option<Instant>,

    pub keepalive: KeepaliveState,

    pub mtu: u32,
    /// Maximum data unit for encrypted payloads (derived from `mtu`).
    pub mdu: usize,

    pub resource_strategy: ResourceStrategy,
    pub pending_requests: Vec<RequestReceipt>,
    pub incoming_resources: Vec<[u8; 32]>,
    pub outgoing_resources: Vec<[u8; 32]>,
    pub outgoing_resource_states: Vec<OutboundResourceState>,
    pub incoming_resource_count: usize,

    /// Total bytes transferred during handshake establishment.
    pub establishment_cost: usize,
    /// Bytes/sec during establishment: `establishment_cost / rtt`.
    pub establishment_rate: Option<f64>,
    /// Expected in-flight data rate (bits/sec), refreshed after each resource transfer.
    pub expected_rate: Option<f64>,
    /// Path length in hops: initiator sets it at creation (Link.py:282), the
    /// destination side from the LRRTT packet at activation (Link.py:525).
    pub expected_hops: Option<u8>,

    pub destination_hash: [u8; 16],

    remote_identity_pub: Option<[u8; 64]>,
    pub identified: bool,

    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_count: u64,
    pub rx_count: u64,

    /// RSSI in dBm, populated from LoRa/radio interfaces.
    pub rssi: Option<f64>,
    /// Signal-to-noise ratio in dB.
    pub snr: Option<f64>,
    /// Link quality indicator in `[0.0, 1.0]`.
    pub q: Option<f64>,
    track_phy_stats: bool,

    pub has_channel: bool,

    pub packet_callback: Option<PacketCallback>,
    /// Called when a resource transfer begins; returns `true` to accept.
    pub resource_callback: Option<ResourceCallback>,
    pub remote_identified_callback: Option<RemoteIdentifiedCallback>,
    /// Fires when the link transitions to `Active`.
    pub link_established_callback: Option<LinkCallback>,
    pub link_closed_callback: Option<LinkCallback>,
}

/// Callback for decrypted link-packet payloads.
pub type PacketCallback = Box<dyn Fn(&[u8]) + Send + Sync>;
/// Callback for accepting or rejecting an incoming resource transfer.
pub type ResourceCallback = Box<dyn Fn(bool) -> bool + Send + Sync>;
/// Callback fired after the remote peer identifies on the link.
pub type RemoteIdentifiedCallback = Box<dyn Fn(&Link, &[u8; 64]) + Send + Sync>;
/// Callback fired for link lifecycle transitions.
pub type LinkCallback = Box<dyn Fn(&Link) + Send + Sync>;
/// Parsed REQUEST data: `(request_id, path_hash, timestamp, payload)`.
pub type ParsedRequestData = ([u8; 16], [u8; 16], f64, Vec<u8>);

impl Link {
    /// Create an outbound link and return `(link, request_data)` to transmit.
    #[tracing::instrument(
        level = "debug",
        name = "link.handshake",
        skip_all,
        fields(
            destination_hash = %hex::encode(&destination_hash[..8]),
            role = "initiator",
            hops,
        ),
    )]
    pub fn new_initiator(destination_hash: [u8; 16], hops: u8) -> (Self, Vec<u8>) {
        let ephemeral_keys = EphemeralKeys::generate();
        let signalling = SignallingData::new(DEFAULT_MODE, rns_wire::constants::MTU as u32);
        let request_data = LinkRequestData::pack(&ephemeral_keys, signalling);
        let link_id = compute_link_id(&destination_hash, &request_data);

        // Base timeout scales with hops. Callers may extend it via
        // extend_establishment_timeout() once they know the first-hop latency.
        let timeout_secs = ESTABLISHMENT_TIMEOUT_PER_HOP * (hops.max(1) as f64);
        let now = Instant::now();

        let establishment_cost = request_data.len();

        let link = Self {
            link_id,
            state: LinkState::Pending,
            teardown_reason: None,
            is_initiator: true,
            mode: DEFAULT_MODE,
            ephemeral_keys: Some(ephemeral_keys),
            peer_x25519_pub: None,
            peer_ed25519_pub: None,
            // Initiator supplies its signing key later via set_signing_key().
            sig_prv: None,
            session_keys: None,
            request_time: now,
            rtt: None,
            establishment_timeout: Duration::from_secs_f64(timeout_secs),
            activated_at: None,
            stale_since: None,
            keepalive: KeepaliveState::new(true),
            mtu: rns_wire::constants::MTU as u32,
            mdu: rns_wire::constants::LINK_MDU,
            resource_strategy: ResourceStrategy::default(),
            pending_requests: Vec::new(),
            incoming_resources: Vec::new(),
            outgoing_resources: Vec::new(),
            outgoing_resource_states: Vec::new(),
            incoming_resource_count: 0,
            establishment_cost,
            establishment_rate: None,
            expected_rate: None,
            expected_hops: Some(hops),
            destination_hash,
            remote_identity_pub: None,
            identified: false,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_count: 0,
            rx_count: 0,
            rssi: None,
            snr: None,
            q: None,
            track_phy_stats: false,
            has_channel: false,
            packet_callback: None,
            resource_callback: None,
            remote_identified_callback: None,
            link_established_callback: None,
            link_closed_callback: None,
        };

        (link, request_data)
    }

    /// Extend the establishment timeout, typically by the transport's first-hop RTT.
    pub fn extend_establishment_timeout(&mut self, additional_secs: f64) {
        self.establishment_timeout += Duration::from_secs_f64(additional_secs);
    }

    /// Handle a received link proof (initiator side, Message 2).
    ///
    /// Verifies the signature, runs ECDH, derives session keys, and returns the
    /// encrypted RTT measurement (Message 3) to hand back to the responder.
    pub fn validate_proof(
        &mut self,
        proof_data: &[u8],
        identity_verify_key: &Ed25519PublicKey,
        identity_ed25519_pub_bytes: &[u8; 32],
    ) -> Result<Vec<u8>, HandshakeError> {
        if self.state != LinkState::Pending {
            return Err(HandshakeError::InvalidSignature);
        }

        // Python reads the LRPROOF mode byte before validating the exact proof
        // length; a wrong mode closes the pending link even for otherwise odd
        // proof lengths.
        if proof_data.len() > 96 {
            let proof_mode = (proof_data[96] & MODE_BYTEMASK as u8) >> 5;
            if proof_mode != self.mode {
                self.state = LinkState::Closed;
                return Err(HandshakeError::InvalidSignature);
            }
        }

        let proof = LinkProofData::unpack(proof_data)?;

        if proof.signalling.mode != self.mode {
            self.state = LinkState::Closed;
            return Err(HandshakeError::InvalidSignature);
        }

        self.establishment_cost += proof_data.len();

        // Verify the signature before deriving session keys so we never hold keys
        // tied to an unvalidated proof, even transiently.
        if !proof.validate(
            identity_verify_key,
            &self.link_id,
            identity_ed25519_pub_bytes,
        ) {
            self.state = LinkState::Closed;
            return Err(HandshakeError::InvalidSignature);
        }

        self.peer_x25519_pub = Some(proof.responder_x25519_pub);
        self.peer_ed25519_pub = Some(*identity_ed25519_pub_bytes);

        let ephemeral = self
            .ephemeral_keys
            .as_ref()
            .ok_or(HandshakeError::InvalidSignature)?;

        let keys = perform_handshake(
            &ephemeral.x25519_prv,
            &proof.responder_x25519_pub,
            &self.link_id,
            self.mode,
        )?;

        self.session_keys = Some(keys);
        self.state = LinkState::Handshake;
        tracing::debug!(link_id = ?self.link_id, "link state -> Handshake (initiator)");

        let rtt = self.request_time.elapsed();
        self.rtt = Some(rtt);

        self.state = LinkState::Active;
        self.activated_at = Some(Instant::now());
        tracing::debug!(
            link_id = ?self.link_id,
            rtt_ms = rtt.as_millis() as u64,
            "link state -> Active (initiator)"
        );

        // Seed the keepalive baseline so stale detection starts from activation.
        self.keepalive.mark_activated();

        let rtt_secs_val = rtt.as_secs_f64();
        if rtt_secs_val > 0.0 && self.establishment_cost > 0 {
            self.establishment_rate = Some(self.establishment_cost as f64 / rtt_secs_val);
        }

        self.keepalive.update_from_rtt(rtt);

        if proof.signalling.mtu > 0 {
            self.mtu = self.mtu.min(proof.signalling.mtu);
        }
        self.update_mdu();

        // RTT is carried as a msgpack f64 so both ends see the same encoding.
        let rtt_secs = rtt.as_secs_f64();
        let mut rtt_bytes = Vec::new();
        rmpv::encode::write_value(&mut rtt_bytes, &rmpv::Value::F64(rtt_secs))
            .map_err(|_| HandshakeError::InvalidSignature)?;
        let encrypted_rtt = self
            .encrypt(&rtt_bytes)
            .map_err(|_| HandshakeError::InvalidSignature)?;

        Ok(encrypted_rtt)
    }

    /// Create an inbound link (responder side) in response to a LINKREQUEST.
    ///
    /// Runs ECDH eagerly and returns the packed proof bytes to send back.
    #[tracing::instrument(
        level = "debug",
        name = "link.handshake",
        skip_all,
        fields(
            destination_hash = %hex::encode(&destination_hash[..8]),
            role = "responder",
            hops,
        ),
    )]
    pub fn new_responder(
        request_data: &[u8],
        identity_signing_key: &Ed25519PrivateKey,
        destination_hash: [u8; 16],
        hops: u8,
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        let identity_ed25519_pub = identity_signing_key.public_key().to_bytes();
        Self::new_responder_inner(
            request_data,
            &identity_ed25519_pub,
            destination_hash,
            hops,
            Some(identity_signing_key),
            |signed_data| Some(identity_signing_key.sign(signed_data)),
        )
    }

    /// Create an inbound link proof using an external signer (e.g. YubiKey/PIV).
    pub fn new_responder_with<F>(
        request_data: &[u8],
        identity_ed25519_pub: &[u8; 32],
        destination_hash: [u8; 16],
        hops: u8,
        sign_fn: F,
    ) -> Result<(Self, Vec<u8>), HandshakeError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        Self::new_responder_inner(
            request_data,
            identity_ed25519_pub,
            destination_hash,
            hops,
            None,
            sign_fn,
        )
    }

    fn new_responder_inner<F>(
        request_data: &[u8],
        identity_ed25519_pub: &[u8; 32],
        destination_hash: [u8; 16],
        hops: u8,
        identity_signing_key: Option<&Ed25519PrivateKey>,
        sign_fn: F,
    ) -> Result<(Self, Vec<u8>), HandshakeError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        let request = LinkRequestData::unpack(request_data)?;
        let link_id = compute_link_id(&destination_hash, request_data);

        if request.signalling.mode != MODE_AES128_CBC && request.signalling.mode != MODE_AES256_CBC
        {
            return Err(HandshakeError::UnsupportedMode(request.signalling.mode));
        }

        let responder_keys = EphemeralKeys::generate();

        let session_keys = perform_handshake(
            &responder_keys.x25519_prv,
            &request.peer_x25519_pub,
            &link_id,
            request.signalling.mode,
        )?;

        // The proof binds the link to the responder's long-term identity key, not
        // its ephemeral one — that's what lets the initiator authenticate us.
        let signalling =
            SignallingData::new(request.signalling.mode, rns_wire::constants::MTU as u32);
        let responder_x25519_pub = responder_keys.x25519_pub.to_bytes();
        let sig_bytes = signalling.pack();
        let mut signed_data = Vec::with_capacity(16 + 32 + 32 + 3);
        signed_data.extend_from_slice(&link_id);
        signed_data.extend_from_slice(&responder_x25519_pub);
        signed_data.extend_from_slice(identity_ed25519_pub);
        signed_data.extend_from_slice(&sig_bytes);
        let signature = sign_fn(&signed_data).ok_or(HandshakeError::InvalidSignature)?;
        let proof = LinkProofData {
            signature,
            responder_x25519_pub,
            signalling,
        };
        let proof_data = proof.pack();

        let timeout_secs = ESTABLISHMENT_TIMEOUT_PER_HOP * (hops.max(1) as f64) + KEEPALIVE_DEFAULT;
        let now = Instant::now();

        let establishment_cost = request_data.len() + proof_data.len();

        let link = Self {
            link_id,
            state: LinkState::Handshake,
            teardown_reason: None,
            is_initiator: false,
            mode: request.signalling.mode,
            ephemeral_keys: Some(responder_keys),
            peer_x25519_pub: Some(request.peer_x25519_pub),
            peer_ed25519_pub: Some(request.peer_ed25519_pub),
            sig_prv: identity_signing_key.map(|key| Ed25519PrivateKey::from_bytes(&key.to_bytes())),
            session_keys: Some(session_keys),
            request_time: now,
            rtt: None,
            establishment_timeout: Duration::from_secs_f64(timeout_secs),
            activated_at: None,
            stale_since: None,
            keepalive: KeepaliveState::new(false),
            mtu: request.signalling.mtu.min(rns_wire::constants::MTU as u32),
            mdu: rns_wire::constants::LINK_MDU,
            resource_strategy: ResourceStrategy::default(),
            pending_requests: Vec::new(),
            incoming_resources: Vec::new(),
            outgoing_resources: Vec::new(),
            outgoing_resource_states: Vec::new(),
            incoming_resource_count: 0,
            establishment_cost,
            establishment_rate: None,
            expected_rate: None,
            // Populated by the runtime from the LRRTT packet hops (Link.py:525).
            expected_hops: None,
            destination_hash,
            remote_identity_pub: None,
            identified: false,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_count: 0,
            rx_count: 0,
            rssi: None,
            snr: None,
            q: None,
            track_phy_stats: false,
            has_channel: false,
            packet_callback: None,
            resource_callback: None,
            remote_identified_callback: None,
            link_established_callback: None,
            link_closed_callback: None,
        };

        Ok((link, proof_data))
    }

    /// Handle the RTT packet (Message 3) and activate the link.
    pub fn receive_rtt_packet(&mut self, encrypted_data: &[u8]) -> Result<(), HandshakeError> {
        if self.state != LinkState::Handshake {
            return Err(HandshakeError::InvalidSignature);
        }

        self.establishment_cost += encrypted_data.len();

        let plaintext = self
            .decrypt(encrypted_data)
            .map_err(|_| HandshakeError::InvalidSignature)?;

        // RTT is a msgpack f64 — see matching encode in validate_proof().
        if let Ok(value) = rmpv::decode::read_value(&mut &plaintext[..]) {
            if let Some(peer_rtt) = value.as_f64() {
                let local_rtt = self.request_time.elapsed().as_secs_f64();
                let rtt = local_rtt.max(peer_rtt);
                let rtt_dur = Duration::from_secs_f64(rtt);
                self.rtt = Some(rtt_dur);
                self.keepalive.update_from_rtt(rtt_dur);
            }
        }

        self.state = LinkState::Active;
        self.activated_at = Some(Instant::now());
        self.keepalive.mark_activated();
        self.update_mdu();
        tracing::debug!(link_id = ?self.link_id, "link state -> Active (responder)");

        if let Some(rtt) = self.rtt {
            let rtt_secs = rtt.as_secs_f64();
            if rtt_secs > 0.0 && self.establishment_cost > 0 {
                self.establishment_rate = Some(self.establishment_cost as f64 / rtt_secs);
            }
        }

        Ok(())
    }

    /// AES-CBC encrypt with the initiator-to-responder session key.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, LinkCryptoError> {
        let keys = self
            .session_keys
            .as_ref()
            .ok_or(LinkCryptoError::EncryptionFailed)?;
        link_encrypt(keys, plaintext)
    }

    /// AES-CBC decrypt and verify the HMAC tag.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, LinkCryptoError> {
        let keys = self
            .session_keys
            .as_ref()
            .ok_or(LinkCryptoError::DecryptionFailed)?;
        link_decrypt(keys, ciphertext)
    }

    /// Build a LINKIDENTIFY payload that reveals the initiator's identity.
    ///
    /// Wire format (after encryption): `public_key(64) || signature(64)`, where
    /// the signature covers `link_id(16) || public_key(64)`. Send with context
    /// LINKIDENTIFY (0xFB).
    pub fn identify(
        &self,
        identity_pub_key: &[u8; 64],
        identity_signing_key: &Ed25519PrivateKey,
    ) -> Result<Vec<u8>, LinkCryptoError> {
        self.identify_with_fallible(identity_pub_key, |message| {
            Some(identity_signing_key.sign(message))
        })
    }

    /// Identify with an external signer (e.g. hardware identity).
    ///
    /// Variant of [`Link::identify`] for keys that cannot be exported.
    pub fn identify_with<F>(
        &self,
        identity_pub_key: &[u8; 64],
        sign_fn: F,
    ) -> Result<Vec<u8>, LinkCryptoError>
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        self.identify_with_fallible(identity_pub_key, |message| Some(sign_fn(message)))
    }

    /// Identify with an external signer that can be unavailable.
    pub fn identify_with_fallible<F>(
        &self,
        identity_pub_key: &[u8; 64],
        sign_fn: F,
    ) -> Result<Vec<u8>, LinkCryptoError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        if !self.is_initiator || self.state != LinkState::Active {
            return Err(LinkCryptoError::EncryptionFailed);
        }

        let mut signed_data = Vec::with_capacity(16 + 64);
        signed_data.extend_from_slice(&self.link_id);
        signed_data.extend_from_slice(identity_pub_key);

        let signature = sign_fn(&signed_data).ok_or(LinkCryptoError::EncryptionFailed)?;

        let mut proof_data = Vec::with_capacity(128);
        proof_data.extend_from_slice(identity_pub_key);
        proof_data.extend_from_slice(&signature);

        self.encrypt(&proof_data)
    }

    /// Verify a received LINKIDENTIFY and record the remote identity key.
    pub fn handle_identification(
        &mut self,
        encrypted_data: &[u8],
    ) -> Result<[u8; 64], LinkCryptoError> {
        if self.state != LinkState::Active {
            return Err(LinkCryptoError::DecryptionFailed);
        }

        let plaintext = self.decrypt(encrypted_data)?;

        // Exactly one public_key(64) || signature(64) payload.
        if plaintext.len() != 128 {
            return Err(LinkCryptoError::DecryptionFailed);
        }

        let mut public_key = [0u8; 64];
        public_key.copy_from_slice(&plaintext[..64]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&plaintext[64..128]);

        let mut signed_data = Vec::with_capacity(16 + 64);
        signed_data.extend_from_slice(&self.link_id);
        signed_data.extend_from_slice(&public_key);

        // In the 64-byte identity blob, bytes 32..64 are the Ed25519 verifying key.
        let mut ed25519_pub_bytes = [0u8; 32];
        ed25519_pub_bytes.copy_from_slice(&public_key[32..64]);

        let verify_key = Ed25519PublicKey::from_bytes(&ed25519_pub_bytes)
            .map_err(|_| LinkCryptoError::DecryptionFailed)?;
        if verify_key.verify(&signed_data, &signature).is_err() {
            return Err(LinkCryptoError::DecryptionFailed);
        }

        // First-identity-wins (Reticulum 1.3.9): once a verified identity is
        // recorded it is immutable — a later, even validly-signed, identification
        // is ignored rather than overwriting the peer. Callers detect the repeat
        // via `self.identified` being already set and skip re-tracking/callbacks.
        if let Some(existing) = self.remote_identity_pub {
            return Ok(existing);
        }

        self.remote_identity_pub = Some(public_key);
        self.identified = true;

        Ok(public_key)
    }

    /// Remote identity public key, if the peer has identified itself.
    pub fn remote_identity(&self) -> Option<&[u8; 64]> {
        self.remote_identity_pub.as_ref()
    }

    /// Build a REQUEST payload and return `(encrypted, request_id)`.
    ///
    /// Plaintext is msgpack `[timestamp_f64, sha256_trunc(path), data]`. Send with
    /// context REQUEST (0x09); the returned `request_id` matches what the remote
    /// side will compute.
    pub fn request(
        &mut self,
        path: &str,
        data: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<(Vec<u8>, [u8; 16]), LinkCryptoError> {
        let (packed, request_id) = self.prepare_request(path, data, timeout)?;
        match self.encrypt(&packed) {
            Ok(encrypted) => Ok((encrypted, request_id)),
            Err(error) => {
                self.discard_pending_request(&request_id);
                Err(error)
            }
        }
    }

    /// Build the plaintext MsgPack request body and register its receipt.
    ///
    /// Packet-sized callers encrypt the returned body directly. Bodies larger
    /// than the Link MDU are passed to Resource with the returned request ID.
    pub fn prepare_request(
        &mut self,
        path: &str,
        data: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<(Vec<u8>, [u8; 16]), LinkCryptoError> {
        let data_value = data
            .map(msgpack_value_from_bytes_or_binary)
            .unwrap_or(rmpv::Value::Nil);
        self.prepare_request_value(path, data_value, timeout)
    }

    /// Build a REQUEST payload with a MsgPack string body.
    ///
    /// Python Reticulum preserves Python `str` request bodies as MsgPack
    /// strings. Some utilities, including rncp fetch, expect that exact type.
    pub fn request_str(
        &mut self,
        path: &str,
        data: &str,
        timeout: Duration,
    ) -> Result<(Vec<u8>, [u8; 16]), LinkCryptoError> {
        let (packed, request_id) =
            self.prepare_request_value(path, rmpv::Value::String(data.into()), timeout)?;
        match self.encrypt(&packed) {
            Ok(encrypted) => Ok((encrypted, request_id)),
            Err(error) => {
                self.discard_pending_request(&request_id);
                Err(error)
            }
        }
    }

    fn prepare_request_value(
        &mut self,
        path: &str,
        data_value: rmpv::Value,
        timeout: Duration,
    ) -> Result<(Vec<u8>, [u8; 16]), LinkCryptoError> {
        if self.state != LinkState::Active {
            return Err(LinkCryptoError::EncryptionFailed);
        }

        let path_hash = truncated_hash(path.as_bytes());
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let array = rmpv::Value::Array(vec![
            rmpv::Value::F64(timestamp),
            rmpv::Value::Binary(path_hash.to_vec()),
            data_value,
        ]);
        let mut packed = Vec::new();
        rmpv::encode::write_value(&mut packed, &array)
            .map_err(|_| LinkCryptoError::EncryptionFailed)?;

        // request_id is a truncated SHA-256 of the plaintext, so both sides derive
        // the same ID without exchanging it.
        let request_id = truncated_hash(&packed);

        let mut receipt_id = [0u8; 32];
        receipt_id[..16].copy_from_slice(&request_id);
        let receipt = RequestReceipt::new(receipt_id, self.link_id, timeout);
        self.pending_requests.push(receipt);

        Ok((packed, request_id))
    }

    /// Suspend a request's response timeout while its body is sent by Resource.
    pub fn mark_request_resource_sending(&mut self, request_id: &[u8; 16]) -> bool {
        let Some(receipt) = self
            .pending_requests
            .iter_mut()
            .find(|receipt| receipt.request_id[..16] == request_id[..])
        else {
            return false;
        };
        receipt.mark_resource_sending();
        true
    }

    /// Start a Resource-backed request's response timeout after send proof.
    pub fn mark_request_resource_sent(&mut self, request_id: &[u8; 16]) -> bool {
        let Some(receipt) = self
            .pending_requests
            .iter_mut()
            .find(|receipt| receipt.request_id[..16] == request_id[..])
        else {
            return false;
        };
        receipt.mark_resource_sent();
        true
    }

    /// Fail and remove a pending request by its truncated request ID.
    pub fn fail_pending_request(&mut self, request_id: &[u8; 16]) -> bool {
        let Some(receipt) = self
            .pending_requests
            .iter_mut()
            .find(|receipt| receipt.request_id[..16] == request_id[..])
        else {
            return false;
        };
        receipt.fail();
        self.pending_requests
            .retain(|receipt| receipt.request_id[..16] != request_id[..]);
        true
    }

    fn discard_pending_request(&mut self, request_id: &[u8; 16]) {
        self.pending_requests
            .retain(|receipt| receipt.request_id[..16] != request_id[..]);
    }

    /// Replace the initial request id with the packet-hash id used by
    /// Reticulum for packet-sized Link requests.
    pub fn update_pending_request_id(
        &mut self,
        old_request_id: &[u8; 16],
        new_request_id: [u8; 16],
    ) -> bool {
        if let Some(receipt) = self
            .pending_requests
            .iter_mut()
            .find(|r| r.request_id[..16] == old_request_id[..])
        {
            receipt.request_id = [0u8; 32];
            receipt.request_id[..16].copy_from_slice(&new_request_id);
            true
        } else {
            false
        }
    }

    /// Decrypt and parse a REQUEST packet into `(request_id, path_hash, timestamp, data)`.
    pub fn handle_request(
        &self,
        encrypted_data: &[u8],
    ) -> Result<ParsedRequestData, LinkCryptoError> {
        let plaintext = self.decrypt(encrypted_data)?;
        Self::parse_request(&plaintext)
    }

    /// Parse an already-decrypted Link request.
    ///
    /// Packet requests use [`Self::handle_request`]. Request Resources are
    /// decrypted by the Resource transfer before reaching the Link runtime,
    /// so they use this parser directly.
    pub fn parse_request(plaintext: &[u8]) -> Result<ParsedRequestData, LinkCryptoError> {
        // request_id = SHA-256(packed_request)[:16]
        let request_id = truncated_hash(plaintext);

        // Unpack msgpack array: [timestamp, path_hash, data]
        let value = rmpv::decode::read_value(&mut &plaintext[..])
            .map_err(|_| LinkCryptoError::DecryptionFailed)?;

        let array = value.as_array().ok_or(LinkCryptoError::DecryptionFailed)?;
        if array.len() < 3 {
            return Err(LinkCryptoError::DecryptionFailed);
        }

        let timestamp = array[0].as_f64().ok_or(LinkCryptoError::DecryptionFailed)?;

        let path_hash_bytes = array[1]
            .as_slice()
            .ok_or(LinkCryptoError::DecryptionFailed)?;
        if path_hash_bytes.len() != 16 {
            return Err(LinkCryptoError::DecryptionFailed);
        }
        let mut path_hash = [0u8; 16];
        path_hash.copy_from_slice(path_hash_bytes);

        let data = msgpack_value_to_bytes(&array[2])?;

        Ok((request_id, path_hash, timestamp, data))
    }

    /// Build a RESPONSE payload: `encrypt(msgpack([request_id, response_data]))`.
    ///
    /// Send with context RESPONSE (0x0A).
    pub fn create_response(
        &self,
        request_id: &[u8; 16],
        response_data: &[u8],
    ) -> Result<Vec<u8>, LinkCryptoError> {
        let packed = Self::pack_response(request_id, response_data)?;
        self.encrypt(&packed)
    }

    /// Build plaintext msgpack `[request_id, response_data]` for a Link
    /// response packet or response resource.
    pub fn pack_response(
        request_id: &[u8; 16],
        response_data: &[u8],
    ) -> Result<Vec<u8>, LinkCryptoError> {
        let response_value = msgpack_value_from_bytes_or_binary(response_data);
        let array = rmpv::Value::Array(vec![
            rmpv::Value::Binary(request_id.to_vec()),
            response_value,
        ]);
        let mut packed = Vec::new();
        rmpv::encode::write_value(&mut packed, &array)
            .map_err(|_| LinkCryptoError::EncryptionFailed)?;
        Ok(packed)
    }

    /// Decrypt a RESPONSE payload, deliver it to the matching receipt, and return
    /// `(request_id, response_data)`.
    pub fn handle_response(
        &mut self,
        encrypted_data: &[u8],
    ) -> Result<([u8; 16], Vec<u8>), LinkCryptoError> {
        let plaintext = self.decrypt(encrypted_data)?;

        self.handle_response_plaintext(&plaintext)
    }

    /// Deliver a plaintext msgpack `[request_id, response_data]` response.
    ///
    /// This is used for response resources, where the Resource layer has already
    /// reassembled and decrypted the transferred blob.
    pub fn handle_response_plaintext(
        &mut self,
        plaintext: &[u8],
    ) -> Result<([u8; 16], Vec<u8>), LinkCryptoError> {
        let (request_id, response_data) = Self::parse_response_plaintext(plaintext)?;
        self.deliver_response_data(&request_id, response_data.clone());
        Ok((request_id, response_data))
    }

    /// Parse plaintext MsgPack `[request_id, response_data]` without mutating
    /// pending request state.
    pub fn parse_response_plaintext(
        plaintext: &[u8],
    ) -> Result<([u8; 16], Vec<u8>), LinkCryptoError> {
        let value = rmpv::decode::read_value(&mut &plaintext[..])
            .map_err(|_| LinkCryptoError::DecryptionFailed)?;

        let array = value.as_array().ok_or(LinkCryptoError::DecryptionFailed)?;
        if array.len() < 2 {
            return Err(LinkCryptoError::DecryptionFailed);
        }

        let id_bytes = array[0]
            .as_slice()
            .ok_or(LinkCryptoError::DecryptionFailed)?;
        if id_bytes.len() != 16 {
            return Err(LinkCryptoError::DecryptionFailed);
        }
        let mut request_id = [0u8; 16];
        request_id.copy_from_slice(id_bytes);

        let response_data = msgpack_value_to_bytes(&array[1])?;

        Ok((request_id, response_data))
    }

    /// Deliver already-decoded response bytes to a pending request.
    pub fn deliver_response_data(&mut self, request_id: &[u8; 16], response_data: Vec<u8>) -> bool {
        let Some(receipt) = self
            .pending_requests
            .iter_mut()
            .find(|r| r.request_id[..16] == request_id[..])
        else {
            return false;
        };
        receipt.receive_response(response_data);

        self.pending_requests
            .retain(|receipt| receipt.request_id[..16] != request_id[..]);
        true
    }

    /// Update RTT from an LRRTT packet (context 0xFE) received after handshake.
    ///
    /// The initiator sends the first measurement as part of `validate_proof`; this
    /// path handles subsequent updates during the link's lifetime.
    pub fn update_rtt_from_packet(
        &mut self,
        encrypted_data: &[u8],
    ) -> Result<Duration, LinkCryptoError> {
        let plaintext = self.decrypt(encrypted_data)?;

        let value = rmpv::decode::read_value(&mut &plaintext[..])
            .map_err(|_| LinkCryptoError::DecryptionFailed)?;
        let peer_rtt = value.as_f64().ok_or(LinkCryptoError::DecryptionFailed)?;

        // Prefer the larger of peer and local measurements so timeouts are based on
        // the slower path — a one-sided smaller value would understate round-trip.
        let rtt = if let Some(existing) = self.rtt {
            Duration::from_secs_f64(peer_rtt.max(existing.as_secs_f64()))
        } else {
            Duration::from_secs_f64(peer_rtt)
        };

        self.rtt = Some(rtt);
        self.keepalive.update_from_rtt(rtt);

        Ok(rtt)
    }

    /// Build an LRRTT payload containing the current RTT as a msgpack f64.
    pub fn create_rtt_packet(&self) -> Result<Vec<u8>, LinkCryptoError> {
        let rtt_secs = self.rtt.map(|r| r.as_secs_f64()).unwrap_or(0.0);
        let mut rtt_bytes = Vec::new();
        rmpv::encode::write_value(&mut rtt_bytes, &rmpv::Value::F64(rtt_secs))
            .map_err(|_| LinkCryptoError::EncryptionFailed)?;
        self.encrypt(&rtt_bytes)
    }

    /// Sign a received packet hash and return a `packet_hash(32) || signature(64)` proof.
    pub fn prove_packet(
        &self,
        packet_hash: &[u8; 32],
        identity_signing_key: &Ed25519PrivateKey,
    ) -> Result<Vec<u8>, LinkCryptoError> {
        self.prove_packet_with_fallible(packet_hash, |hash| Some(identity_signing_key.sign(hash)))
    }

    /// Sign a received link packet with this link's ephemeral signing key.
    ///
    /// Initiators advertise an ephemeral Ed25519 public key in the LINKREQUEST;
    /// responders validate later link-packet proofs against that key.
    pub fn prove_packet_with_link_key(
        &self,
        packet_hash: &[u8; 32],
    ) -> Result<Vec<u8>, LinkCryptoError> {
        self.prove_packet_with_fallible(packet_hash, |hash| {
            self.sign(hash).or_else(|| {
                self.ephemeral_keys
                    .as_ref()
                    .map(|keys| keys.ed25519_prv.sign(hash))
            })
        })
    }

    /// Variant of [`Link::prove_packet`] for external signers.
    pub fn prove_packet_with<F>(
        &self,
        packet_hash: &[u8; 32],
        sign_fn: F,
    ) -> Result<Vec<u8>, LinkCryptoError>
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        self.prove_packet_with_fallible(packet_hash, |hash| Some(sign_fn(hash)))
    }

    /// Variant of [`Link::prove_packet_with`] for signers that can be unavailable.
    pub fn prove_packet_with_fallible<F>(
        &self,
        packet_hash: &[u8; 32],
        sign_fn: F,
    ) -> Result<Vec<u8>, LinkCryptoError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        if self.state != LinkState::Active && self.state != LinkState::Stale {
            return Err(LinkCryptoError::EncryptionFailed);
        }

        let signature = sign_fn(packet_hash).ok_or(LinkCryptoError::EncryptionFailed)?;

        let mut proof = Vec::with_capacity(96);
        proof.extend_from_slice(packet_hash);
        proof.extend_from_slice(&signature);

        Ok(proof)
    }

    /// Verify a `packet_hash(32) || signature(64)` proof against the peer's identity key.
    pub fn validate_packet_proof(&self, packet_hash: &[u8; 32], proof_data: &[u8]) -> bool {
        if proof_data.len() < 96 {
            return false;
        }

        let received_hash = &proof_data[..32];
        if received_hash != packet_hash {
            return false;
        }

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&proof_data[32..96]);

        if let Some(peer_ed25519_pub) = &self.peer_ed25519_pub {
            match Ed25519PublicKey::from_bytes(peer_ed25519_pub) {
                Ok(verify_key) => verify_key.verify(packet_hash, &signature).is_ok(),
                Err(_) => false,
            }
        } else {
            false
        }
    }

    /// Flag that a channel has been attached.
    ///
    /// `rns-link` does not own the channel type (it lives in `rns-protocol`); this
    /// just records lazy creation so callers don't build two.
    pub fn mark_channel_created(&mut self) {
        self.has_channel = true;
    }

    pub fn set_resource_strategy(&mut self, strategy: ResourceStrategy) {
        self.resource_strategy = strategy;
    }

    /// Evaluate the configured strategy.
    ///
    /// `AskApp` defers to the caller's application callback.
    pub fn should_accept_resource(&self) -> ResourceAcceptance {
        match self.resource_strategy {
            ResourceStrategy::AcceptNone => ResourceAcceptance::Reject,
            ResourceStrategy::AcceptAll => ResourceAcceptance::Accept,
            ResourceStrategy::AcceptApp => ResourceAcceptance::AskApp,
        }
    }

    pub fn track_incoming_resource(&mut self, resource_hash: [u8; 32]) {
        self.incoming_resources.push(resource_hash);
    }

    pub fn track_outgoing_resource(&mut self, resource_hash: [u8; 32]) {
        self.outgoing_resources.push(resource_hash);
    }

    pub fn untrack_resource(&mut self, resource_hash: &[u8; 32]) {
        self.incoming_resources.retain(|h| h != resource_hash);
        self.outgoing_resources.retain(|h| h != resource_hash);
    }

    /// `bytes` is the link payload after the context byte (ciphertext), the
    /// same unit as `record_rx` — Packet.py:291 txbytes += len(ciphertext).
    pub fn record_tx(&mut self, bytes: usize) {
        self.tx_bytes += bytes as u64;
        self.tx_count += 1;
        self.keepalive.record_outbound();
    }

    /// Count an outbound keepalive beat and retain its send time.
    ///
    /// Stale detection deliberately ignores local outbound activity, while the
    /// retained timestamp prevents redundant keepalive traffic.
    pub fn record_tx_keepalive(&mut self, bytes: usize) {
        self.tx_bytes += bytes as u64;
        self.tx_count += 1;
        self.keepalive.record_keepalive_outbound();
    }

    /// Whether this responder should answer a keepalive request.
    ///
    /// Recent outbound traffic already proves the responder can transmit, so
    /// an immediate extra reply would only duplicate that traffic.
    pub fn should_respond_to_keepalive(&self) -> bool {
        self.keepalive
            .should_respond_to_keepalive_at(Instant::now())
    }

    /// `bytes` is the link payload after the context byte (Link.py:929).
    pub fn record_rx(&mut self, bytes: usize) {
        self.rx_bytes += bytes as u64;
        self.rx_count += 1;
    }

    /// Totals as `(tx_bytes, rx_bytes, tx_count, rx_count)`.
    pub fn traffic_stats(&self) -> (u64, u64, u64, u64) {
        (self.tx_bytes, self.rx_bytes, self.tx_count, self.rx_count)
    }

    /// Enable or disable per-packet physical-layer measurement tracking.
    pub fn track_phy_stats(&mut self, track: bool) {
        self.track_phy_stats = track;
    }

    pub fn phy_stats_tracking_enabled(&self) -> bool {
        self.track_phy_stats
    }

    /// Merge measurements when tracking is enabled.
    pub fn update_phy_stats(&mut self, rssi: Option<f64>, snr: Option<f64>, q: Option<f64>) {
        if !self.track_phy_stats {
            return;
        }
        self.update_phy_stats_force(rssi, snr, q);
    }

    /// Merge measurements regardless of the tracking gate.
    ///
    /// Responder Links use this to retain the establishment packet's
    /// measurements, matching Python's forced initial update.
    pub fn update_phy_stats_force(&mut self, rssi: Option<f64>, snr: Option<f64>, q: Option<f64>) {
        if rssi.is_some() {
            self.rssi = rssi;
        }
        if snr.is_some() {
            self.snr = snr;
        }
        if q.is_some() {
            self.q = q;
        }
    }

    /// Current PHY measurements as `(rssi, snr, q)`.
    pub fn phy_stats(&self) -> (Option<f64>, Option<f64>, Option<f64>) {
        let stats = self.phy_stats_snapshot();
        (stats.rssi, stats.snr, stats.q)
    }

    pub fn phy_stats_snapshot(&self) -> LinkPhyStats {
        if self.track_phy_stats {
            LinkPhyStats {
                rssi: self.rssi,
                snr: self.snr,
                q: self.q,
            }
        } else {
            LinkPhyStats::default()
        }
    }

    pub fn get_rssi(&self) -> Option<f64> {
        self.track_phy_stats.then_some(self.rssi).flatten()
    }

    pub fn get_snr(&self) -> Option<f64> {
        self.track_phy_stats.then_some(self.snr).flatten()
    }

    pub fn get_q(&self) -> Option<f64> {
        self.track_phy_stats.then_some(self.q).flatten()
    }

    /// Clone of the session keys, for handing to a Channel or Resource.
    pub fn session_keys(&self) -> Option<LinkKeys> {
        self.session_keys.clone()
    }

    pub fn rtt_secs(&self) -> f64 {
        self.rtt.map(|r| r.as_secs_f64()).unwrap_or(0.0)
    }

    /// Drive the link state machine forward; call periodically from the owning actor.
    #[tracing::instrument(
        level = "trace",
        name = "link.tick",
        skip_all,
        fields(
            link_id = %hex::encode(&self.link_id[..8]),
            state = ?self.state,
        ),
    )]
    pub fn tick(&mut self) -> LinkAction {
        let now = Instant::now();
        for receipt in &mut self.pending_requests {
            receipt.check_timeout();
        }
        self.pending_requests.retain(|receipt| !receipt.concluded());

        match self.state {
            LinkState::Pending | LinkState::Handshake => {
                if now.saturating_duration_since(self.request_time) > self.establishment_timeout {
                    self.close(CloseReason::Timeout);
                    return LinkAction::Closed(CloseReason::Timeout);
                }
                LinkAction::None
            }
            LinkState::Active => {
                // Emit any pending keepalive before checking staleness so a final
                // beat goes out on the same tick the link transitions to STALE.
                if self.keepalive.should_send_keepalive_at(now) {
                    self.keepalive.mark_keepalive_sent_at(now);
                    return LinkAction::SendKeepalive;
                }
                if self.keepalive.is_stale_at(now) {
                    self.state = LinkState::Stale;
                    self.stale_since = Some(now);
                    tracing::debug!(link_id = ?self.link_id, "link state -> Stale");
                    return LinkAction::TransitionedToStale;
                }
                LinkAction::None
            }
            LinkState::Stale => {
                // Encrypt the teardown payload before close() purges the keys —
                // otherwise we'd have nothing to sign the teardown with.
                let rtt = self.rtt.unwrap_or(Duration::from_secs(1));
                let grace = self.keepalive.stale_grace_timeout(rtt);
                if let Some(stale_since) = self.stale_since {
                    if now.saturating_duration_since(stale_since) >= grace {
                        let teardown_data = self.encrypt(&self.link_id).unwrap_or_default();
                        self.close(CloseReason::Timeout);
                        return LinkAction::SendTeardownAndClose(teardown_data);
                    }
                }
                LinkAction::None
            }
            LinkState::Closed => LinkAction::None,
        }
    }

    /// Record that an inbound packet was received; recovers the link from STALE.
    pub fn record_inbound(&mut self) {
        self.keepalive.record_inbound();

        if self.state == LinkState::Stale {
            self.state = LinkState::Active;
            self.stale_since = None;
        }
    }

    /// Initiate link teardown and return the encrypted teardown payload to send.
    pub fn teardown(&mut self, reason: CloseReason) -> Option<Vec<u8>> {
        if self.state == LinkState::Closed {
            return None;
        }

        // Teardown payload is the link ID sealed with the session key — the peer
        // can verify authenticity of the teardown without a separate signature.
        let teardown_data = self.encrypt(&self.link_id).ok();
        self.close(reason);
        teardown_data
    }

    /// Handle a received teardown packet and close the link on success.
    pub fn receive_teardown(&mut self, encrypted_data: &[u8]) -> bool {
        match self.decrypt(encrypted_data) {
            Ok(plaintext) => {
                if plaintext.len() >= 16 && plaintext[..16] == self.link_id {
                    self.close(CloseReason::DestinationClosed);
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    fn close(&mut self, reason: CloseReason) {
        tracing::debug!(link_id = ?self.link_id, ?reason, "link state -> Closed");
        self.teardown_reason = Some(reason);
        for receipt in &mut self.pending_requests {
            receipt.fail();
        }
        self.pending_requests.clear();
        self.state = LinkState::Closed;
        self.purge_keys();
    }

    /// Mark the link closed without emitting a teardown packet.
    ///
    /// Owners use this when an external close notification arrives without a
    /// link-authenticated teardown payload, such as a local manager shutdown.
    pub fn mark_closed(&mut self, reason: CloseReason) {
        if self.state != LinkState::Closed {
            self.close(reason);
        }
    }

    fn purge_keys(&mut self) {
        self.ephemeral_keys = None;
        self.session_keys = None;
        self.peer_x25519_pub = None;
        self.peer_ed25519_pub = None;
        self.sig_prv = None;
    }

    /// Attach the initiator's identity signing key after construction.
    pub fn set_signing_key(&mut self, key: &Ed25519PrivateKey) {
        self.sig_prv = Some(Ed25519PrivateKey::from_bytes(&key.to_bytes()));
    }

    /// Sign a message with the link's identity key, or `None` if no key is set.
    pub fn sign(&self, message: &[u8]) -> Option<[u8; 64]> {
        self.sig_prv.as_ref().map(|key| key.sign(message))
    }

    /// Verify a signature using the peer's Ed25519 identity key.
    pub fn validate(&self, signature: &[u8], message: &[u8]) -> bool {
        if let Some(ref peer_pub_bytes) = self.peer_ed25519_pub {
            if signature.len() != 64 {
                return false;
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(signature);
            if let Ok(pub_key) = Ed25519PublicKey::from_bytes(peer_pub_bytes) {
                pub_key.verify(message, &sig).is_ok()
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn set_packet_callback(&mut self, cb: impl Fn(&[u8]) + Send + Sync + 'static) {
        self.packet_callback = Some(Box::new(cb));
    }

    /// Install a callback invoked for each inbound resource; return `true` to accept.
    pub fn set_resource_callback(&mut self, cb: impl Fn(bool) -> bool + Send + Sync + 'static) {
        self.resource_callback = Some(Box::new(cb));
    }

    pub fn set_remote_identified_callback(
        &mut self,
        cb: impl Fn(&Link, &[u8; 64]) + Send + Sync + 'static,
    ) {
        self.remote_identified_callback = Some(Box::new(cb));
    }

    pub fn set_link_established_callback(&mut self, cb: impl Fn(&Link) + Send + Sync + 'static) {
        self.link_established_callback = Some(Box::new(cb));
    }

    pub fn set_link_closed_callback(&mut self, cb: impl Fn(&Link) + Send + Sync + 'static) {
        self.link_closed_callback = Some(Box::new(cb));
    }

    /// Recompute MDU from the current MTU.
    ///
    /// MDU = `floor((mtu - header - token) / AES block) * AES block - 1`; the
    /// trailing `-1` reserves room for PKCS7 padding worst case.
    fn update_mdu(&mut self) {
        let mtu = self.mtu as usize;
        let overhead =
            1 + rns_wire::constants::HEADER_MINSIZE + rns_wire::constants::TOKEN_OVERHEAD;
        if mtu > overhead {
            self.mdu = ((mtu - overhead) / rns_wire::constants::AES128_BLOCKSIZE)
                * rns_wire::constants::AES128_BLOCKSIZE
                - 1;
        }
    }

    pub fn is_active(&self) -> bool {
        self.state == LinkState::Active
    }

    pub fn has_keys(&self) -> bool {
        self.session_keys.is_some()
    }

    /// Time since the last data packet, excluding keepalives.
    pub fn no_data_for(&self) -> Duration {
        self.keepalive.last_data.elapsed()
    }

    /// Time since the last outbound packet, or `Duration::MAX` if none has been sent.
    pub fn no_outbound_for(&self) -> Duration {
        self.keepalive
            .last_outbound
            .map(|t| t.elapsed())
            .unwrap_or(Duration::MAX)
    }

    /// Time since any inbound activity.
    pub fn no_inbound_for(&self) -> Duration {
        self.keepalive.last_inbound.elapsed()
    }

    /// Time since the last activity in either direction.
    pub fn inactive_for(&self) -> Duration {
        let last_outbound = self
            .keepalive
            .last_outbound
            .unwrap_or(self.keepalive.last_inbound);
        let last = if last_outbound > self.keepalive.last_inbound {
            last_outbound
        } else {
            self.keepalive.last_inbound
        };
        last.elapsed()
    }

    /// Add bytes to the handshake byte counter (divided by RTT to compute the rate).
    pub fn add_establishment_cost(&mut self, bytes: usize) {
        self.establishment_cost += bytes;
    }

    /// Handshake throughput in bits/sec, or `None` before activation.
    pub fn get_establishment_rate(&self) -> Option<f64> {
        self.establishment_rate.map(|rate| rate * 8.0)
    }

    /// Expected in-flight rate in bits/sec for an active link; `None` until the
    /// first resource transfer completes.
    pub fn get_expected_rate(&self) -> Option<f64> {
        if self.state == LinkState::Active {
            self.expected_rate
        } else {
            None
        }
    }

    /// Notify the link that a resource transfer has concluded.
    ///
    /// Refreshes `expected_rate` from the transfer's size and duration, and drops
    /// one entry from the relevant pending-resource tracker.
    pub fn resource_concluded(
        &mut self,
        resource_size: usize,
        transfer_duration_secs: f64,
        is_incoming: bool,
    ) {
        // Clamp the denominator so an essentially instant transfer doesn't divide by zero.
        let duration = transfer_duration_secs.max(0.0001);
        self.expected_rate = Some((resource_size as f64 * 8.0) / duration);

        if is_incoming {
            if self.incoming_resource_count > 0 {
                self.incoming_resource_count -= 1;
            }
        } else if let Some(pos) = self.outgoing_resource_states.iter().position(|s| {
            matches!(
                s,
                OutboundResourceState::AwaitingProof
                    | OutboundResourceState::Complete
                    | OutboundResourceState::Failed
            )
        }) {
            self.outgoing_resource_states.remove(pos);
        }
    }

    pub fn register_outgoing_resource(&mut self) {
        self.outgoing_resource_states
            .push(OutboundResourceState::Transferring);
    }

    pub fn register_incoming_resource(&mut self) {
        self.incoming_resource_count += 1;
    }

    pub fn update_outgoing_resource_state(&mut self, index: usize, state: OutboundResourceState) {
        if index < self.outgoing_resource_states.len() {
            self.outgoing_resource_states[index] = state;
        }
    }

    /// Whether the link can accept a new outbound resource.
    ///
    /// Allows new transfers not just when the queue is empty but also when all
    /// existing transfers have finished sending data and are only waiting on the
    /// receiver's proof — otherwise a single slow proof would block the pipeline.
    pub fn ready_for_new_resource(&self) -> bool {
        if self.outgoing_resource_states.is_empty() {
            return true;
        }
        self.outgoing_resource_states.iter().all(|s| {
            matches!(
                s,
                OutboundResourceState::AwaitingProof
                    | OutboundResourceState::Complete
                    | OutboundResourceState::Failed
            )
        })
    }

    /// Pick the send mode for a packed request: inline packet if it fits the MDU,
    /// otherwise a resource transfer.
    pub fn classify_request(&self, packed_request: Vec<u8>) -> RequestSendMode {
        if packed_request.len() <= self.mdu {
            RequestSendMode::Packet(packed_request)
        } else {
            RequestSendMode::Resource(packed_request)
        }
    }

    /// Default request timeout: `rtt * TRAFFIC_TIMEOUT_FACTOR + 1.125 * RESPONSE_MAX_GRACE_TIME`.
    pub fn default_request_timeout(&self) -> Duration {
        let rtt_secs = self.rtt.map(|r| r.as_secs_f64()).unwrap_or(1.0);
        let timeout =
            rtt_secs * TRAFFIC_TIMEOUT_FACTOR + crate::constants::RESPONSE_MAX_GRACE_TIME * 1.125;
        Duration::from_secs_f64(timeout)
    }
}

/// Outcome of one `tick()`, instructing the owning runtime what to emit.
#[derive(Debug, Clone, PartialEq)]
pub enum LinkAction {
    None,
    /// Initiator should send a keepalive frame.
    SendKeepalive,
    /// Link just entered STALE; initiator should flush a final keepalive.
    TransitionedToStale,
    /// Send the wrapped (already encrypted) teardown payload, then drop the link.
    SendTeardownAndClose(Vec<u8>),
    /// Link closed without an outbound frame (e.g. timeout before handshake).
    Closed(CloseReason),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::ed25519::Ed25519PrivateKey;
    use rns_crypto::sha::full_hash;

    #[test]
    fn test_initiator_creation() {
        let dest_hash = [0xAA; 16];
        let (link, request_data) = Link::new_initiator(dest_hash, 1);

        assert_eq!(link.state, LinkState::Pending);
        assert!(link.is_initiator);
        assert_eq!(link.destination_hash, dest_hash);
        assert_eq!(request_data.len(), ECPUBSIZE + LINK_MTU_SIZE);
    }

    #[test]
    fn test_full_handshake() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut initiator_link, request_data) = Link::new_initiator(dest_hash, 1);
        assert_eq!(initiator_link.state, LinkState::Pending);

        let (mut responder_link, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();
        assert_eq!(responder_link.state, LinkState::Handshake);
        assert_eq!(responder_link.link_id, initiator_link.link_id);

        let rtt_data = initiator_link
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();
        assert_eq!(initiator_link.state, LinkState::Active);
        assert!(initiator_link.rtt.is_some());

        responder_link.receive_rtt_packet(&rtt_data).unwrap();
        assert_eq!(responder_link.state, LinkState::Active);

        let msg = b"Hello over the link!";
        let ct = initiator_link.encrypt(msg).unwrap();
        let pt = responder_link.decrypt(&ct).unwrap();
        assert_eq!(pt, msg);

        let msg2 = b"Response back!";
        let ct2 = responder_link.encrypt(msg2).unwrap();
        let pt2 = initiator_link.decrypt(&ct2).unwrap();
        assert_eq!(pt2, msg2);
    }

    #[test]
    fn test_teardown() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();

        let rtt_data = initiator
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();

        let teardown_data = initiator.teardown(CloseReason::InitiatorClosed);
        assert_eq!(initiator.state, LinkState::Closed);
        assert_eq!(
            initiator.teardown_reason,
            Some(CloseReason::InitiatorClosed)
        );
        assert!(teardown_data.is_some());

        let accepted = responder.receive_teardown(&teardown_data.unwrap());
        assert!(accepted);
        assert_eq!(responder.state, LinkState::Closed);
        assert_eq!(
            responder.teardown_reason,
            Some(CloseReason::DestinationClosed)
        );
    }

    #[test]
    fn test_wrong_proof_identity() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let wrong_identity = Ed25519PrivateKey::generate();
        let wrong_pub = wrong_identity.public_key();

        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);

        let (_, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();

        // Hand the initiator a mismatched public key on proof validation.
        let result = initiator.validate_proof(&proof_data, &wrong_pub, &wrong_pub.to_bytes());
        assert!(result.is_err());
        assert_eq!(initiator.state, LinkState::Closed);
    }

    #[test]
    fn test_responder_accepts_python_request_lengths_only() {
        let dest_hash = [0xA1; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let (_, request_data) = Link::new_initiator(dest_hash, 1);

        assert!(Link::new_responder(&request_data[..63], &identity_key, dest_hash, 1).is_err());
        assert!(Link::new_responder(&request_data[..64], &identity_key, dest_hash, 1).is_ok());
        assert!(Link::new_responder(&request_data[..65], &identity_key, dest_hash, 1).is_err());
        assert!(Link::new_responder(&request_data[..66], &identity_key, dest_hash, 1).is_err());
        assert!(Link::new_responder(&request_data, &identity_key, dest_hash, 1).is_ok());

        let mut over = request_data.clone();
        over.push(0);
        assert!(Link::new_responder(&over, &identity_key, dest_hash, 1).is_err());
    }

    #[test]
    fn test_responder_accepts_python_inbound_modes() {
        let dest_hash = [0xA2; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let (mut request_link, request_data) = Link::new_initiator(dest_hash, 1);

        let mut aes128_request = request_data.clone();
        aes128_request[64] = MODE_AES128_CBC << 5;
        let (responder, proof) =
            Link::new_responder(&aes128_request, &identity_key, dest_hash, 1).unwrap();
        assert_eq!(responder.mode, MODE_AES128_CBC);
        assert_eq!(
            LinkProofData::unpack(&proof).unwrap().signalling.mode,
            MODE_AES128_CBC
        );

        let identity_pub = identity_key.public_key();
        assert!(
            request_link
                .validate_proof(&proof, &identity_pub, &identity_pub.to_bytes())
                .is_err(),
            "initiator requested AES256 and must reject an AES128 proof"
        );
        assert_eq!(request_link.state, LinkState::Closed);

        let mut unsupported_request = request_data;
        unsupported_request[64] = MODE_AES256_GCM << 5;
        assert!(
            matches!(
                Link::new_responder(&unsupported_request, &identity_key, dest_hash, 1),
                Err(HandshakeError::UnsupportedMode(mode)) if mode == MODE_AES256_GCM
            ),
            "Python raises for unsupported inbound mode 2"
        );
    }

    #[test]
    fn test_initiator_rejects_proof_mode_mismatch() {
        let dest_hash = [0xA3; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();
        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (_, mut proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();

        proof_data[96] = MODE_AES128_CBC << 5;
        let result = initiator.validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes());
        assert!(matches!(result, Err(HandshakeError::InvalidSignature)));
        assert_eq!(initiator.state, LinkState::Closed);
    }

    #[test]
    fn test_establishment_timeout() {
        let dest_hash = [0xAA; 16];
        let (mut link, _) = Link::new_initiator(dest_hash, 1);

        link.establishment_timeout = Duration::from_millis(1);
        std::thread::sleep(Duration::from_millis(5));

        let action = link.tick();
        assert_eq!(action, LinkAction::Closed(CloseReason::Timeout));
        assert_eq!(link.state, LinkState::Closed);
    }

    #[test]
    fn test_keys_purged_on_close() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (mut _responder, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();

        initiator
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();

        assert!(initiator.has_keys());
        initiator.teardown(CloseReason::InitiatorClosed);
        assert!(!initiator.has_keys());
    }

    #[test]
    fn test_stale_recovery() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (_, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();

        initiator
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();

        initiator.state = LinkState::Stale;
        initiator.stale_since = Some(Instant::now());

        // Any inbound activity should rescue the link back to ACTIVE.
        initiator.record_inbound();
        assert_eq!(initiator.state, LinkState::Active);
    }

    /// `teardown()` must be safe to call more than once. The second call on
    /// an already-closed link returns `None` without panicking or emitting
    /// a spurious teardown payload (keys are already gone).
    #[test]
    fn test_teardown_idempotent_when_closed() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (_, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();
        initiator
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();

        let first = initiator.teardown(CloseReason::InitiatorClosed);
        assert!(first.is_some(), "first teardown emits a payload");
        assert_eq!(initiator.state, LinkState::Closed);

        let second = initiator.teardown(CloseReason::InitiatorClosed);
        assert!(
            second.is_none(),
            "repeat teardown on Closed is a no-op with no payload"
        );
        assert_eq!(initiator.state, LinkState::Closed);
    }

    /// Stale links past the grace window must emit a `SendTeardownAndClose`
    /// on `tick()` and transition to Closed. Complements `test_stale_recovery`,
    /// which covers the happy path where inbound traffic resurrects the link.
    #[test]
    fn test_stale_grace_timeout_emits_teardown() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (_, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();
        initiator
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();

        initiator.state = LinkState::Stale;
        let rtt = Duration::from_millis(50);
        initiator.rtt = Some(rtt);
        let expired_by = initiator.keepalive.stale_grace_timeout(rtt) + Duration::from_millis(1);
        let now = Instant::now();
        initiator.stale_since = Some(if let Some(stale_since) = now.checked_sub(expired_by) {
            stale_since
        } else {
            std::thread::sleep(expired_by);
            now
        });

        let action = initiator.tick();
        assert!(
            matches!(action, LinkAction::SendTeardownAndClose(_)),
            "stale link past grace must emit teardown, got {action:?}"
        );
        assert_eq!(initiator.state, LinkState::Closed);
        assert!(!initiator.has_keys(), "keys purged after teardown close");
    }

    /// `tick()` on a Closed link is a no-op. Protects against re-entry from
    /// scheduler callbacks that fire after teardown.
    #[test]
    fn test_tick_on_closed_link_is_noop() {
        let dest_hash = [0xAA; 16];
        let (mut link, _) = Link::new_initiator(dest_hash, 1);
        link.close(CloseReason::InitiatorClosed);
        assert_eq!(link.state, LinkState::Closed);

        let action = link.tick();
        assert_eq!(action, LinkAction::None);
        assert_eq!(link.state, LinkState::Closed);
    }

    /// `validate_proof` on an already-Closed link must not resurrect it.
    /// Models a late proof arriving after the initiator timed out.
    #[test]
    fn test_validate_proof_on_closed_link_rejected() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (_, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();

        initiator.close(CloseReason::Timeout);
        assert_eq!(initiator.state, LinkState::Closed);

        let result = initiator.validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes());
        assert!(result.is_err(), "validate_proof on Closed link must reject");
        assert_eq!(initiator.state, LinkState::Closed);
        assert!(!initiator.has_keys(), "keys stay purged");
    }

    /// `record_inbound` must refresh keepalive even on an already-Active
    /// link (not just on Stale→Active recovery). This is the common path:
    /// every received packet resets the inactivity clock.
    #[test]
    fn test_record_inbound_refreshes_keepalive_on_active() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (_, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();
        initiator
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();
        assert_eq!(initiator.state, LinkState::Active);

        std::thread::sleep(Duration::from_millis(5));
        let before = initiator.inactive_for();
        std::thread::sleep(Duration::from_millis(5));

        initiator.record_inbound();
        let after = initiator.inactive_for();
        assert!(
            after < before,
            "record_inbound should reset inactivity clock: before={before:?} after={after:?}"
        );
        assert_eq!(initiator.state, LinkState::Active);
    }

    #[test]
    fn test_establishment_rate_computed() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();

        let rtt_data = initiator
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();

        assert!(initiator.establishment_rate.is_some());
        assert!(responder.establishment_rate.is_some());

        assert!(initiator.establishment_cost > 0);
        assert!(responder.establishment_cost > 0);

        // get_establishment_rate reports bits/sec (byte rate * 8).
        let initiator_rate_bps = initiator.get_establishment_rate().unwrap();
        let initiator_rate_bytes = initiator.establishment_rate.unwrap();
        assert!((initiator_rate_bps - initiator_rate_bytes * 8.0).abs() < 0.001);
    }

    #[test]
    fn test_expected_rate_computed_on_resource_concluded() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut link, request_data) = Link::new_initiator(dest_hash, 1);
        let (_, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();

        link.validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();

        assert!(link.expected_rate.is_none());

        link.register_incoming_resource();
        link.resource_concluded(1000, 0.5, true);

        // (1000 bytes * 8) / 0.5 s = 16000 bits/sec
        assert!(link.expected_rate.is_some());
        let rate = link.expected_rate.unwrap();
        assert!((rate - 16000.0).abs() < 0.1);

        assert_eq!(link.get_expected_rate(), Some(rate));

        // get_expected_rate() suppresses the reading once the link is no longer active.
        link.state = LinkState::Closed;
        assert_eq!(link.get_expected_rate(), None);
    }

    #[test]
    fn test_expected_rate_zero_duration_clamped() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut link, request_data) = Link::new_initiator(dest_hash, 1);
        let (_, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();

        link.validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();

        // Zero-duration transfers must not divide by zero; the implementation clamps to 0.0001 s.
        link.resource_concluded(1000, 0.0, false);
        let rate = link.expected_rate.unwrap();
        let expected = (1000.0 * 8.0) / 0.0001;
        assert!((rate - expected).abs() < 1.0);
    }

    #[test]
    fn test_ready_for_new_resource_empty() {
        let dest_hash = [0xAA; 16];
        let (link, _) = Link::new_initiator(dest_hash, 1);
        assert!(link.ready_for_new_resource());
    }

    #[test]
    fn test_ready_for_new_resource_transferring_blocks() {
        let dest_hash = [0xAA; 16];
        let (mut link, _) = Link::new_initiator(dest_hash, 1);

        link.register_outgoing_resource();
        assert!(!link.ready_for_new_resource());
    }

    #[test]
    fn test_ready_for_new_resource_awaiting_proof_allows() {
        let dest_hash = [0xAA; 16];
        let (mut link, _) = Link::new_initiator(dest_hash, 1);

        link.register_outgoing_resource();
        link.update_outgoing_resource_state(0, OutboundResourceState::AwaitingProof);
        // Once the payload has been sent, queuing the next resource should not block on the proof.
        assert!(link.ready_for_new_resource());
    }

    #[test]
    fn test_ready_for_new_resource_mixed_states() {
        let dest_hash = [0xAA; 16];
        let (mut link, _) = Link::new_initiator(dest_hash, 1);

        link.register_outgoing_resource();
        link.register_outgoing_resource();
        link.update_outgoing_resource_state(0, OutboundResourceState::AwaitingProof);
        // Index 1 is still Transferring, so the pipeline must remain closed.
        assert!(!link.ready_for_new_resource());

        link.update_outgoing_resource_state(1, OutboundResourceState::AwaitingProof);
        assert!(link.ready_for_new_resource());
    }

    #[test]
    fn test_classify_request_packet() {
        let dest_hash = [0xAA; 16];
        let (link, _) = Link::new_initiator(dest_hash, 1);

        let small_data = vec![0u8; 10];
        match link.classify_request(small_data.clone()) {
            RequestSendMode::Packet(data) => assert_eq!(data, small_data),
            RequestSendMode::Resource(_) => panic!("Expected Packet mode"),
        }
    }

    #[test]
    fn test_classify_request_resource() {
        let dest_hash = [0xAA; 16];
        let (link, _) = Link::new_initiator(dest_hash, 1);

        let large_data = vec![0u8; link.mdu + 1];
        match link.classify_request(large_data.clone()) {
            RequestSendMode::Resource(data) => assert_eq!(data, large_data),
            RequestSendMode::Packet(_) => panic!("Expected Resource mode"),
        }
    }

    #[test]
    fn test_classify_request_exact_mdu() {
        let dest_hash = [0xAA; 16];
        let (link, _) = Link::new_initiator(dest_hash, 1);

        // An exactly-MDU-sized payload must still fit in a single packet.
        let exact_data = vec![0u8; link.mdu];
        match link.classify_request(exact_data.clone()) {
            RequestSendMode::Packet(data) => assert_eq!(data, exact_data),
            RequestSendMode::Resource(_) => panic!("Expected Packet mode for exact MDU"),
        }
    }

    #[test]
    fn test_default_request_timeout() {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut link, request_data) = Link::new_initiator(dest_hash, 1);
        let (_, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();

        link.validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();

        let timeout = link.default_request_timeout();
        let rtt_secs = link.rtt.unwrap().as_secs_f64();
        let expected =
            rtt_secs * TRAFFIC_TIMEOUT_FACTOR + crate::constants::RESPONSE_MAX_GRACE_TIME * 1.125;
        assert!((timeout.as_secs_f64() - expected).abs() < 0.001);
    }

    #[test]
    fn test_resource_concluded_removes_outgoing() {
        let dest_hash = [0xAA; 16];
        let (mut link, _) = Link::new_initiator(dest_hash, 1);
        link.state = LinkState::Active;

        link.register_outgoing_resource();
        link.update_outgoing_resource_state(0, OutboundResourceState::AwaitingProof);
        assert_eq!(link.outgoing_resource_states.len(), 1);

        link.resource_concluded(500, 1.0, false);
        assert_eq!(link.outgoing_resource_states.len(), 0);
    }

    #[test]
    fn test_resource_concluded_decrements_incoming() {
        let dest_hash = [0xAA; 16];
        let (mut link, _) = Link::new_initiator(dest_hash, 1);
        link.state = LinkState::Active;

        link.register_incoming_resource();
        link.register_incoming_resource();
        assert_eq!(link.incoming_resource_count, 2);

        link.resource_concluded(500, 1.0, true);
        assert_eq!(link.incoming_resource_count, 1);
    }

    fn make_active_link() -> (Link, Link, Ed25519PrivateKey) {
        let dest_hash = [0xAA; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();

        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();

        let rtt_data = initiator
            .validate_proof(&proof_data, &identity_pub, &identity_pub.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();

        (initiator, responder, identity_key)
    }

    #[test]
    fn test_identify_roundtrip() {
        let (initiator, mut responder, _dest_identity) = make_active_link();

        let initiator_identity = Ed25519PrivateKey::generate();
        let initiator_x25519_pub = [0x11; 32]; // mock X25519 pub
        let mut identity_pub = [0u8; 64];
        identity_pub[..32].copy_from_slice(&initiator_x25519_pub);
        identity_pub[32..].copy_from_slice(&initiator_identity.public_key().to_bytes());

        let identify_data = initiator
            .identify(&identity_pub, &initiator_identity)
            .unwrap();

        let remote_pub = responder.handle_identification(&identify_data).unwrap();
        assert_eq!(remote_pub, identity_pub);
        assert!(responder.identified);
        assert_eq!(responder.remote_identity().unwrap(), &identity_pub);
    }

    #[test]
    fn test_identify_first_wins_ignores_later_identity() {
        // First-identity-wins (Reticulum 1.3.9): once a verified identity is
        // recorded, a second validly-signed LinkIdentify for a DIFFERENT identity
        // must not overwrite the first.
        let (initiator, mut responder, _dest_identity) = make_active_link();

        let first_identity = Ed25519PrivateKey::generate();
        let mut first_pub = [0u8; 64];
        first_pub[..32].copy_from_slice(&[0x11; 32]);
        first_pub[32..].copy_from_slice(&first_identity.public_key().to_bytes());
        let first_data = initiator.identify(&first_pub, &first_identity).unwrap();

        let recorded = responder.handle_identification(&first_data).unwrap();
        assert_eq!(recorded, first_pub);
        assert_eq!(responder.remote_identity().unwrap(), &first_pub);

        // A second, independently valid identification for a different identity.
        let second_identity = Ed25519PrivateKey::generate();
        let mut second_pub = [0u8; 64];
        second_pub[..32].copy_from_slice(&[0x22; 32]);
        second_pub[32..].copy_from_slice(&second_identity.public_key().to_bytes());
        let second_data = initiator.identify(&second_pub, &second_identity).unwrap();
        assert_ne!(first_pub, second_pub);

        // The recorded identity stays the first one; the repeat is ignored.
        let returned = responder.handle_identification(&second_data).unwrap();
        assert_eq!(returned, first_pub);
        assert_eq!(responder.remote_identity().unwrap(), &first_pub);
    }

    #[test]
    fn test_identify_non_initiator_fails() {
        let (_initiator, responder, _identity) = make_active_link();
        let key = Ed25519PrivateKey::generate();
        let pub_key = [0u8; 64];
        // Only the initiator is allowed to reveal its identity.
        assert!(responder.identify(&pub_key, &key).is_err());
    }

    #[test]
    fn test_identify_wrong_signature_fails() {
        let (initiator, mut responder, _) = make_active_link();

        let wrong_key = Ed25519PrivateKey::generate();
        let real_key = Ed25519PrivateKey::generate();
        let mut identity_pub = [0u8; 64];
        identity_pub[32..].copy_from_slice(&real_key.public_key().to_bytes());

        // Claim real_key's public half but sign with a different private key — signature must not verify.
        let identify_data = initiator.identify(&identity_pub, &wrong_key).unwrap();

        assert!(responder.handle_identification(&identify_data).is_err());
        assert!(!responder.identified);
    }

    #[test]
    fn test_request_response_roundtrip() {
        let (mut initiator, responder, _) = make_active_link();

        let (request_data, request_id) = initiator
            .request("test.path", Some(b"request data"), Duration::from_secs(10))
            .unwrap();

        assert!(!initiator.pending_requests.is_empty());

        let (recv_id, path_hash, _ts, data) = responder.handle_request(&request_data).unwrap();
        assert_eq!(recv_id, request_id);
        assert_eq!(data, b"request data");

        let expected_path_hash = truncated_hash("test.path".as_bytes());
        assert_eq!(path_hash, expected_path_hash);

        let response_data = responder
            .create_response(&request_id, b"response data")
            .unwrap();

        let (resp_id, resp_data) = initiator.handle_response(&response_data).unwrap();
        assert_eq!(resp_id, request_id);
        assert_eq!(resp_data, b"response data");

        // handle_response() must drain the receipt on success.
        assert!(initiator.pending_requests.is_empty());
    }

    #[test]
    fn test_parse_plaintext_request_resource_payload() {
        let (mut initiator, responder, _) = make_active_link();

        let (encrypted, request_id) = initiator
            .request(
                "resource.path",
                Some(b"resource request data"),
                Duration::from_secs(10),
            )
            .unwrap();
        let plaintext = responder.decrypt(&encrypted).unwrap();

        let (parsed_id, path_hash, _timestamp, data) = Link::parse_request(&plaintext).unwrap();
        assert_eq!(parsed_id, request_id);
        assert_eq!(path_hash, truncated_hash(b"resource.path"));
        assert_eq!(data, b"resource request data");
    }

    #[test]
    fn test_tick_expires_pending_request_and_fires_callback() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let (mut initiator, _responder, _) = make_active_link();
        initiator
            .request("test.timeout", None, Duration::ZERO)
            .unwrap();

        let fired = Arc::new(AtomicBool::new(false));
        let callback_fired = fired.clone();
        initiator.pending_requests[0].set_failed_callback(move |_| {
            callback_fired.store(true, Ordering::SeqCst);
        });

        initiator.tick();

        assert!(fired.load(Ordering::SeqCst));
        assert!(
            initiator.pending_requests.is_empty(),
            "owning runtime tick must reap concluded request receipts"
        );
    }

    #[test]
    fn test_link_close_fails_pending_request() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let (mut initiator, _responder, _) = make_active_link();
        initiator
            .request("test.close", None, Duration::from_secs(30))
            .unwrap();

        let fired = Arc::new(AtomicBool::new(false));
        let callback_fired = fired.clone();
        initiator.pending_requests[0].set_failed_callback(move |_| {
            callback_fired.store(true, Ordering::SeqCst);
        });

        initiator.mark_closed(CloseReason::DestinationClosed);

        assert!(fired.load(Ordering::SeqCst));
        assert!(initiator.pending_requests.is_empty());
    }

    #[test]
    fn test_request_response_preserves_msgpack_object_bodies() {
        use rmpv::Value;

        let (mut initiator, responder, _) = make_active_link();

        let request_body = Value::Array(vec![Value::Nil, Value::Nil]);
        let mut request_body_bytes = Vec::new();
        rmpv::encode::write_value(&mut request_body_bytes, &request_body).unwrap();

        let (request_data, request_id) = initiator
            .request(
                "lxmf.propagation.get",
                Some(&request_body_bytes),
                Duration::from_secs(10),
            )
            .unwrap();

        let (recv_id, _path_hash, _ts, data) = responder.handle_request(&request_data).unwrap();
        assert_eq!(recv_id, request_id);
        let decoded_request: Value = rmpv::decode::read_value(&mut &data[..]).unwrap();
        assert_eq!(decoded_request, request_body);

        let response_body = Value::Array(vec![Value::Binary(vec![0xAA; 32])]);
        let mut response_body_bytes = Vec::new();
        rmpv::encode::write_value(&mut response_body_bytes, &response_body).unwrap();

        let response_data = responder
            .create_response(&request_id, &response_body_bytes)
            .unwrap();

        let (resp_id, resp_data) = initiator.handle_response(&response_data).unwrap();
        assert_eq!(resp_id, request_id);
        let decoded_response: Value = rmpv::decode::read_value(&mut &resp_data[..]).unwrap();
        assert_eq!(decoded_response, response_body);
        assert!(initiator.pending_requests.is_empty());
    }

    #[test]
    fn test_request_str_roundtrip_as_plain_utf8_body() {
        let (mut initiator, responder, _) = make_active_link();

        let (request_data, request_id) = initiator
            .request_str("fetch_file", "example.bin", Duration::from_secs(10))
            .unwrap();

        let (recv_id, path_hash, _ts, data) = responder.handle_request(&request_data).unwrap();
        assert_eq!(recv_id, request_id);
        assert_eq!(path_hash, truncated_hash("fetch_file".as_bytes()));
        assert_eq!(data, b"example.bin");
    }

    #[test]
    fn test_request_on_inactive_link_fails() {
        let dest_hash = [0xAA; 16];
        let (mut link, _) = Link::new_initiator(dest_hash, 1);
        assert!(link.request("test", None, Duration::from_secs(10)).is_err());
    }

    #[test]
    fn test_prove_packet_roundtrip() {
        let (initiator, responder, dest_identity) = make_active_link();

        let packet_hash = full_hash(b"test packet data");

        let proof = responder
            .prove_packet(&packet_hash, &dest_identity)
            .unwrap();
        assert_eq!(proof.len(), 96);

        assert!(initiator.validate_packet_proof(&packet_hash, &proof));
    }

    #[test]
    fn test_prove_packet_wrong_hash_fails() {
        let (initiator, responder, dest_identity) = make_active_link();

        let packet_hash = full_hash(b"test packet");
        let wrong_hash = full_hash(b"wrong packet");

        let proof = responder
            .prove_packet(&packet_hash, &dest_identity)
            .unwrap();
        assert!(!initiator.validate_packet_proof(&wrong_hash, &proof));
    }

    #[test]
    fn test_rtt_packet_update() {
        let (initiator, mut responder, _) = make_active_link();

        let rtt_packet = initiator.create_rtt_packet().unwrap();
        let rtt = responder.update_rtt_from_packet(&rtt_packet).unwrap();
        assert!(rtt.as_secs_f64() >= 0.0);
    }

    #[test]
    fn test_session_keys_accessible() {
        let (initiator, _, _) = make_active_link();
        assert!(initiator.session_keys().is_some());
        assert!(initiator.rtt_secs() >= 0.0);
    }

    #[test]
    fn test_channel_creation_flag() {
        let (mut initiator, _, _) = make_active_link();
        assert!(!initiator.has_channel);
        initiator.mark_channel_created();
        assert!(initiator.has_channel);
    }

    #[test]
    fn test_resource_strategy() {
        let (mut link, _, _) = make_active_link();

        assert_eq!(link.should_accept_resource(), ResourceAcceptance::Reject);

        link.set_resource_strategy(ResourceStrategy::AcceptAll);
        assert_eq!(link.should_accept_resource(), ResourceAcceptance::Accept);

        link.set_resource_strategy(ResourceStrategy::AcceptApp);
        assert_eq!(link.should_accept_resource(), ResourceAcceptance::AskApp);
    }

    #[test]
    fn test_traffic_stats() {
        let (mut link, _, _) = make_active_link();

        link.record_tx(100);
        link.record_tx(200);
        link.record_rx(50);

        let (tx_b, rx_b, tx_c, rx_c) = link.traffic_stats();
        assert_eq!(tx_b, 300);
        assert_eq!(rx_b, 50);
        assert_eq!(tx_c, 2);
        assert_eq!(rx_c, 1);
    }

    /// Keepalive beats count into traffic stats and refresh the outbound
    /// keepalive clock. Peer-liveness detection remains inbound-only.
    #[test]
    fn test_record_tx_keepalive_counts_and_refreshes_outbound() {
        let (mut link, _, _) = make_active_link();
        assert!(link.keepalive.last_outbound.is_none());

        link.record_tx_keepalive(1);

        let (tx_b, _, tx_c, _) = link.traffic_stats();
        assert_eq!(tx_b, 1);
        assert_eq!(tx_c, 1);
        assert!(link.keepalive.last_outbound.is_some());
        assert!(link.keepalive.last_keepalive_sent.is_some());
    }

    /// Initiator knows expected_hops at creation (Link.py:282); the responder
    /// side stays unset until the runtime observes the LRRTT hops (Link.py:525).
    #[test]
    fn test_expected_hops_initiator_only_at_creation() {
        let dest_hash = [0xAB; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let (initiator, request_data) = Link::new_initiator(dest_hash, 3);
        let (responder, _proof) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 3).unwrap();

        assert_eq!(initiator.expected_hops, Some(3));
        assert_eq!(responder.expected_hops, None);
    }

    #[test]
    fn test_phy_stats() {
        let (mut link, _, _) = make_active_link();

        assert_eq!(link.phy_stats(), (None, None, None));
        link.update_phy_stats(Some(-90.0), Some(5.0), Some(0.5));
        assert_eq!(link.rssi, None);

        link.track_phy_stats(true);
        link.update_phy_stats(Some(-80.0), Some(12.5), Some(0.95));
        assert_eq!(link.rssi, Some(-80.0));
        assert_eq!(link.snr, Some(12.5));
        assert_eq!(link.q, Some(0.95));

        // `None` components must leave the existing reading intact.
        link.update_phy_stats(Some(-75.0), None, None);
        assert_eq!(link.rssi, Some(-75.0));
        assert_eq!(link.snr, Some(12.5));
        assert_eq!(link.get_rssi(), Some(-75.0));

        link.track_phy_stats(false);
        assert_eq!(link.phy_stats(), (None, None, None));
        assert_eq!(link.get_rssi(), None);

        link.update_phy_stats_force(Some(-60.0), None, None);
        link.track_phy_stats(true);
        assert_eq!(link.get_rssi(), Some(-60.0));
    }

    #[test]
    fn test_resource_tracking() {
        let (mut link, _, _) = make_active_link();

        let hash1 = [0x11; 32];
        let hash2 = [0x22; 32];

        link.track_incoming_resource(hash1);
        link.track_outgoing_resource(hash2);

        assert_eq!(link.incoming_resources.len(), 1);
        assert_eq!(link.outgoing_resources.len(), 1);

        link.untrack_resource(&hash1);
        assert_eq!(link.incoming_resources.len(), 0);
        assert_eq!(link.outgoing_resources.len(), 1);
    }

    #[test]
    fn test_sign_validate_roundtrip() {
        let dest_hash = [0xEE; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let (initiator_link, request_data) = Link::new_initiator(dest_hash, 1);
        let (responder_link, _proof) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();

        let message = b"hello from responder";
        let sig = responder_link
            .sign(message)
            .expect("responder should have sig_prv");
        let _ = initiator_link;
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_sign_without_key_returns_none() {
        let dest_hash = [0xFF; 16];
        let (link, _) = Link::new_initiator(dest_hash, 1);
        assert!(link.sign(b"test").is_none());
    }

    #[test]
    fn test_validate_without_peer_key_returns_false() {
        let dest_hash = [0xFF; 16];
        let (link, _) = Link::new_initiator(dest_hash, 1);
        assert!(!link.validate(&[0u8; 64], b"test"));
    }

    #[test]
    fn test_signing_key_purged_on_close() {
        let dest_hash = [0xEE; 16];
        let identity_key = Ed25519PrivateKey::generate();
        let (_, request_data) = Link::new_initiator(dest_hash, 1);
        let (mut link, _proof) =
            Link::new_responder(&request_data, &identity_key, dest_hash, 1).unwrap();
        assert!(link.sign(b"test").is_some());
        link.close(CloseReason::Timeout);
        assert!(link.sign(b"test").is_none());
    }
}
