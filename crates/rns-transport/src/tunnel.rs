use std::collections::HashMap;

use crate::messages::InterfaceId;

/// Retained routes for one transport tunnel. A valid synthesis packet can
/// rebind this path collection to an interface when connectivity returns.
/// Tunnel bookkeeping adds no separate payload encryption.
#[derive(Debug, Clone)]
pub struct TunnelEntry {
    pub tunnel_id: [u8; 32],
    /// Current interface binding; `None` while unbound.
    pub interface_id: Option<InterfaceId>,
    pub tunnel_paths: HashMap<[u8; 16], TunnelPath>,
    pub expires: f64,
}

#[derive(Debug, Clone)]
pub struct TunnelPath {
    pub timestamp: f64,
    pub next_hop: Option<[u8; 16]>,
    pub hops: u8,
    pub expires: f64,
    pub random_blobs: Vec<[u8; 10]>,
    pub packet_hash: Option<[u8; 32]>,
    /// Last use of the path, carried into the path table on restore.
    pub used: f64,
}

/// Tunnel records and cached interface-to-tunnel associations. Lookup does not
/// check expiry. Removing, expiring or rebinding an entry does not clear old
/// interface associations; `void_interface` explicitly forgets one binding.
#[derive(Clone)]
pub struct TunnelTable {
    entries: HashMap<[u8; 32], TunnelEntry>,
    /// Python's `interface.tunnel_id`: the tunnel each interface's latest
    /// synthesis named, which may outlive that tunnel as it does in Python.
    by_interface: HashMap<InterfaceId, [u8; 32]>,
}

impl TunnelTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            by_interface: HashMap::new(),
        }
    }

    /// Insert or replace a record and associate its interface when supplied.
    /// Previous interface associations are not removed, and fields are not
    /// validated by this method.
    pub fn insert(&mut self, entry: TunnelEntry) {
        if let Some(interface_id) = entry.interface_id {
            self.by_interface.insert(interface_id, entry.tunnel_id);
        }
        self.entries.insert(entry.tunnel_id, entry);
    }

    pub fn get(&self, tunnel_id: &[u8; 32]) -> Option<&TunnelEntry> {
        self.entries.get(tunnel_id)
    }

    pub fn get_mut(&mut self, tunnel_id: &[u8; 32]) -> Option<&mut TunnelEntry> {
        self.entries.get_mut(tunnel_id)
    }

    pub fn remove(&mut self, tunnel_id: &[u8; 32]) -> Option<TunnelEntry> {
        self.entries.remove(tunnel_id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &TunnelEntry)> {
        self.entries.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&[u8; 32], &mut TunnelEntry)> {
        self.entries.iter_mut()
    }

    /// Python `interface.tunnel_id`: the tunnel this interface's latest
    /// synthesis named, which may since have moved or expired.
    pub fn interface_tunnel(&self, interface_id: InterfaceId) -> Option<[u8; 32]> {
        self.by_interface.get(&interface_id).copied()
    }

    /// Resolve the cached association for this interface. It can return None
    /// for a removed record, or a record now bound to another interface;
    /// neither current binding nor expiry is checked here.
    pub fn get_mut_by_interface(&mut self, interface_id: InterfaceId) -> Option<&mut TunnelEntry> {
        let tunnel_id = self.by_interface.get(&interface_id)?;
        self.entries.get_mut(tunnel_id)
    }

    /// Forget `interface_id`: it names no tunnel, and the tunnels bound to it
    /// become unbound, keep their paths, and expire after the reconnect window
    /// unless a synthesis rebinds them. Returns how many tunnels were unbound.
    pub fn void_interface(&mut self, interface_id: InterfaceId) -> usize {
        self.by_interface.remove(&interface_id);
        let expires = crate::now_f64() + crate::constants::TUNNEL_RECONNECT_WINDOW as f64;
        let mut voided = 0;
        for entry in self.entries.values_mut() {
            if entry.interface_id == Some(interface_id) {
                entry.interface_id = None;
                entry.expires = expires;
                voided += 1;
            }
        }
        voided
    }

    pub fn tunnel_paths(&self) -> impl Iterator<Item = (&[u8; 16], &TunnelPath)> {
        self.entries
            .values()
            .flat_map(|entry| entry.tunnel_paths.iter())
    }

    /// Remove records whose expiry is at/before now or more than twice the
    /// eight-hour tunnel timeout ahead. This does not cull individual cached
    /// paths or remove interface associations.
    pub fn cull_expired(&mut self) -> usize {
        let now = crate::now_f64();

        let before = self.entries.len();
        self.entries.retain(|_, entry| !is_stale(entry, now));
        before - self.entries.len()
    }

    /// Apply the same expiry test as `cull_expired`, removing at most `limit`
    /// records. The limit does not bound scanning time, and interface
    /// associations remain unchanged.
    pub fn cull_expired_batch(&mut self, limit: usize) -> usize {
        let now = crate::now_f64();

        let to_remove: Vec<[u8; 32]> = self
            .entries
            .iter()
            .filter(|(_, entry)| is_stale(entry, now))
            .take(limit)
            .map(|(hash, _)| *hash)
            .collect();
        let count = to_remove.len();
        for hash in &to_remove {
            self.entries.remove(hash);
        }
        count
    }
}

impl Default for TunnelTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Expired, or set to expire implausibly late (Transport.py).
fn is_stale(entry: &TunnelEntry, now: f64) -> bool {
    entry.expires <= now || entry.expires > now + 2.0 * crate::constants::TUNNEL_TIMEOUT as f64
}

/// Length of the legacy synthesis payload: `public_key(64) || interface_hash(32)
/// || random_hash(16) || signature(64)`.
pub const SYNTHESIS_LEGACY_LEN: usize = 176;
/// Longest synthesis payload Python 1.6.1 accepts (`Packet.MDU`).
pub const SYNTHESIS_MAX_LEN: usize = rns_wire::constants::MDU;

/// A tunnel-synthesis payload, excluding the Reticulum packet header: the
/// legacy 176 bytes, then Python 1.6.1's signed extension when present.
#[derive(Debug, Clone)]
pub struct TunnelSynthesisData {
    /// Transport identity key: `X25519(32) || Ed25519(32)`.
    pub public_key: [u8; 64],
    /// SHA-256 of the interface identifier string.
    pub interface_hash: [u8; 32],
    /// Random bytes included in the signed payload. This type does not track
    /// or reject replayed synthesis packets.
    pub random_hash: [u8; 16],
    /// Ed25519 signature over `public_key || interface_hash || random_hash ||
    /// ext`; it precedes `ext` on the wire.
    pub signature: [u8; 64],
    /// The extension exactly as received; empty in the legacy form.
    pub ext: Vec<u8>,
}

impl TunnelSynthesisData {
    /// `public_key || interface_hash || random_hash || signature || ext`.
    pub fn pack(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(SYNTHESIS_LEGACY_LEN + self.ext.len());
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(&self.interface_hash);
        data.extend_from_slice(&self.random_hash);
        data.extend_from_slice(&self.signature);
        data.extend_from_slice(&self.ext);
        data
    }

    /// Parse 176 to 464 bytes without verifying the signature, as Python
    /// 1.6.1 bounds it (Transport.py:3218-3222). Call [`Self::is_signed`]
    /// before treating the payload as signed.
    pub fn unpack(data: &[u8]) -> Option<Self> {
        if !(SYNTHESIS_LEGACY_LEN..=SYNTHESIS_MAX_LEN).contains(&data.len()) {
            return None;
        }
        let mut public_key = [0u8; 64];
        public_key.copy_from_slice(&data[0..64]);
        let mut interface_hash = [0u8; 32];
        interface_hash.copy_from_slice(&data[64..96]);
        let mut random_hash = [0u8; 16];
        random_hash.copy_from_slice(&data[96..112]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[112..176]);

        Some(Self {
            public_key,
            interface_hash,
            random_hash,
            signature,
            ext: data[SYNTHESIS_LEGACY_LEN..].to_vec(),
        })
    }

    /// Tunnel identifier: `SHA-256(public_key || interface_hash)`.
    pub fn tunnel_id(&self) -> [u8; 32] {
        use rns_crypto::sha::sha256;
        let mut tunnel_id_data = Vec::with_capacity(96);
        tunnel_id_data.extend_from_slice(&self.public_key);
        tunnel_id_data.extend_from_slice(&self.interface_hash);
        sha256(&tunnel_id_data)
    }

    /// The signer's transport identity hash (Python `remote_transport.hash`).
    pub fn transport_identity_hash(&self) -> [u8; 16] {
        rns_crypto::sha::truncated_hash(&self.public_key)
    }

    /// Verify the signature under the Ed25519 half of the embedded public key.
    /// This does not check an external trust policy, replay state or freshness.
    pub fn is_signed(&self) -> bool {
        let Ok(signer) = rns_identity::identity::Identity::from_public_key(&self.public_key) else {
            return false;
        };
        signer.verify(&self.signed_data(), &self.signature)
    }

    fn signed_data(&self) -> Vec<u8> {
        let mut signed = Vec::with_capacity(112 + self.ext.len());
        signed.extend_from_slice(&self.public_key);
        signed.extend_from_slice(&self.interface_hash);
        signed.extend_from_slice(&self.random_hash);
        signed.extend_from_slice(&self.ext);
        signed
    }
}

/// Python 1.6.1 discovery keys of the synthesis extension (Discovery.py:50-57).
const EXT_IMPLEMENTATION: u8 = 0xFD;
const EXT_VERSION: u8 = 0xFC;
const EXT_TRANSPORT: u8 = 0x01;
const EXT_DESTINATION_COST: u8 = 0xFB;
const EXT_PR_COST: u8 = 0xFA;

/// What a synthesis extension says about its sender (Transport.py:3172-3178).
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelExt {
    pub implementation: String,
    pub version: String,
    pub transport: bool,
    pub destination_cost: f64,
    pub pr_cost: f64,
}

impl TunnelExt {
    /// This stack's extension: `rsRNS`, its crate version, and the costs given.
    pub fn local(transport: bool, destination_cost: f64, pr_cost: f64) -> Self {
        Self {
            implementation: crate::discovery::constants::IMPLEMENTATION_NAME.to_string(),
            version: crate::discovery::constants::IMPLEMENTATION_VERSION.to_string(),
            transport,
            destination_cost,
            pr_cost,
        }
    }

    /// Python's `umsgpack.packb(ext_info)`: a map in its insertion order, with
    /// the costs as unquantized float64.
    pub fn encode(&self) -> Vec<u8> {
        use rmpv::Value;
        let map = Value::Map(vec![
            (
                Value::from(EXT_IMPLEMENTATION),
                Value::from(self.implementation.as_str()),
            ),
            (Value::from(EXT_VERSION), Value::from(self.version.as_str())),
            (Value::from(EXT_TRANSPORT), Value::from(self.transport)),
            (
                Value::from(EXT_DESTINATION_COST),
                Value::F64(self.destination_cost),
            ),
            (Value::from(EXT_PR_COST), Value::F64(self.pr_cost)),
        ]);
        let mut encoded = Vec::with_capacity(48);
        rmpv::encode::write_value(&mut encoded, &map).expect("writing to a Vec cannot fail");
        encoded
    }
}

/// A tunnel peer's extension as Python 1.6.1 keeps it: `remote_impl`,
/// `remote_vers`, `remote_is_tn`, and the costs quantized.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct RemoteTransportInfo {
    pub implementation: String,
    pub version: Vec<u64>,
    pub transport: bool,
    pub destination_cost: f64,
    pub pr_cost: f64,
}

/// Why Python 1.6.1 counts an extension as a protocol violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TunnelExtError {
    Undecodable,
    NotAMap,
    MissingKey(u8),
    InvalidImplementation,
    InvalidVersion,
    InvalidCost,
    InvalidTransport,
}

impl RemoteTransportInfo {
    /// The fields as a shared instance's interface stats carry them.
    pub fn new(
        implementation: String,
        version: Vec<u64>,
        transport: bool,
        destination_cost: f64,
        pr_cost: f64,
    ) -> Self {
        Self {
            implementation,
            version,
            transport,
            destination_cost,
            pr_cost,
        }
    }

    /// Python 1.6.1's extension checks (Transport.py:3255-3288), except that
    /// integer costs are accepted: Python sends one for a clamped cost.
    pub fn decode(ext: &[u8]) -> Result<Self, TunnelExtError> {
        use rmpv::Value;
        let value = rns_identity::msgpack::read_value(&mut &ext[..])
            .map_err(|_| TunnelExtError::Undecodable)?;
        if !python_decodable(&value) {
            return Err(TunnelExtError::Undecodable);
        }
        let Value::Map(entries) = value else {
            return Err(TunnelExtError::NotAMap);
        };
        let field = |key: u8| {
            entries
                .iter()
                .find(|(k, _)| k.as_u64() == Some(u64::from(key)))
                .map(|(_, v)| v)
                .ok_or(TunnelExtError::MissingKey(key))
        };
        let (implementation, version, transport, destination_cost, pr_cost) = (
            field(EXT_IMPLEMENTATION)?,
            field(EXT_VERSION)?,
            field(EXT_TRANSPORT)?,
            field(EXT_DESTINATION_COST)?,
            field(EXT_PR_COST)?,
        );
        let version = version
            .as_str()
            .and_then(crate::discovery::autoconnect::version_tuple)
            .ok_or(TunnelExtError::InvalidVersion)?;
        let implementation = implementation
            .as_str()
            .filter(|name| {
                !name.is_empty() && crate::discovery::app_data::sanitize_name(name) == *name
            })
            .ok_or(TunnelExtError::InvalidImplementation)?
            .to_string();
        let cost = |value: &Value| {
            let cost = match value {
                Value::F64(cost) => *cost,
                Value::F32(cost) => f64::from(*cost),
                Value::Integer(cost) => cost.as_f64().ok_or(TunnelExtError::InvalidCost)?,
                _ => return Err(TunnelExtError::InvalidCost),
            };
            rns_identity::stamps::quantize_cost(cost).map_err(|_| TunnelExtError::InvalidCost)
        };
        let (destination_cost, pr_cost) = (cost(destination_cost)?, cost(pr_cost)?);
        let Value::Boolean(transport) = *transport else {
            return Err(TunnelExtError::InvalidTransport);
        };
        Ok(Self {
            implementation,
            version,
            transport,
            destination_cost,
            pr_cost,
        })
    }
}

/// Whether upstream's umsgpack unpacks the value: it rejects invalid UTF-8,
/// unhashable or duplicate map keys, and timestamps of unsupported length.
fn python_decodable(value: &rmpv::Value) -> bool {
    use rmpv::Value;
    fn hashable(key: &Value) -> bool {
        match key {
            Value::Map(_) => false,
            Value::Array(items) => items.iter().all(hashable),
            _ => true,
        }
    }
    // Python's dict equality: `1 == 1.0 == True`.
    fn same_key(a: &Value, b: &Value) -> bool {
        let number = |value: &Value| match value {
            Value::Boolean(b) => Some(f64::from(u8::from(*b))),
            Value::Integer(n) => n.as_f64(),
            Value::F32(f) => Some(f64::from(*f)),
            Value::F64(f) => Some(*f),
            _ => None,
        };
        match (number(a), number(b)) {
            (Some(a), Some(b)) => a == b,
            _ => a == b,
        }
    }
    match value {
        Value::String(s) => s.as_str().is_some(),
        Value::Array(items) => items.iter().all(python_decodable),
        Value::Map(entries) => entries.iter().enumerate().all(|(i, (key, item))| {
            hashable(key)
                && python_decodable(key)
                && python_decodable(item)
                && !entries[..i]
                    .iter()
                    .any(|(earlier, _)| same_key(earlier, key))
        }),
        Value::Ext(-1, data) => matches!(data.len(), 4 | 8 | 12),
        _ => true,
    }
}

/// Python 1.6.1's per-interface synthesis state (Interface.py:132-149),
/// kept by the transport actor.
#[derive(Debug, Clone, Default)]
pub(crate) struct InterfaceTunnel {
    pub(crate) synthesis_received: bool,
    pub(crate) synthesis_emitted: bool,
    /// Python `local_tunnel_id`: this side initiated the tunnel.
    pub(crate) local_tunnel_id: Option<[u8; 32]>,
    /// Python `remote_transport`: the peer's transport identity hash.
    pub(crate) remote_transport: Option<[u8; 16]>,
    /// Python `remote_impl` and the rest, from the peer's extension.
    pub(crate) remote_info: Option<RemoteTransportInfo>,
}

impl InterfaceTunnel {
    /// Python's `connect()`: a new connection starts without a peer, and a
    /// synthesis may arrive again (TCPInterface.py:259-264).
    pub(crate) fn reconnect(&mut self) {
        self.synthesis_received = false;
        self.remote_transport = None;
        self.remote_info = None;
    }
}

/// Classes of upstream interfaces that set `tunnels_allowed` (TCPInterface.py,
/// BackboneInterface.py, I2PInterface.py).
pub const TUNNEL_INTERFACE_CLASSES: &[&str] = &[
    "TCPClientInterface",
    "TCPServerInterface",
    "BackboneInterface",
    "BackboneClientInterface",
    "I2PInterface",
    "I2PInterfacePeer",
];

/// Insert or refresh a tunnel's interface binding and eight-hour expiry,
/// retaining an existing path set. The caller must validate the synthesis
/// packet first; this helper accepts IDs without cryptographic checks. It
/// does not restore routes into the path table or remove old interface
/// associations when rebinding.
pub fn handle_tunnel(
    tunnel_table: &mut TunnelTable,
    tunnel_id: [u8; 32],
    interface_id: crate::messages::InterfaceId,
) {
    let expires = crate::now_f64() + crate::constants::TUNNEL_TIMEOUT as f64;

    if let Some(existing) = tunnel_table.get_mut(&tunnel_id) {
        existing.interface_id = Some(interface_id);
        existing.expires = expires;
        tunnel_table.by_interface.insert(interface_id, tunnel_id);
    } else {
        let entry = TunnelEntry {
            tunnel_id,
            interface_id: Some(interface_id),
            tunnel_paths: std::collections::HashMap::new(),
            expires,
        };
        tunnel_table.insert(entry);
    }
}

/// Build a legacy (176-byte) tunnel-synthesis packet addressed to the
/// well-known tunnel synthesize PLAIN destination, with fresh random bytes
/// and a signature. Return `None` if the identity cannot sign. The result is
/// a complete inner Reticulum packet; IFAC and framing remain separate.
pub fn build_tunnel_synthesis_packet(
    identity: &rns_identity::identity::Identity,
    interface_hash: [u8; 32],
) -> Option<Vec<u8>> {
    build_synthesis(identity, interface_hash, random_hash(), &[])
}

/// Build Python 1.6.1's synthesis: the legacy fields, the signature over
/// them and `ext`, then `ext` (Transport.py:3170-3206).
pub fn build_tunnel_synthesis_packet_with_ext(
    identity: &rns_identity::identity::Identity,
    interface_hash: [u8; 32],
    ext: &TunnelExt,
) -> Option<Vec<u8>> {
    build_synthesis(identity, interface_hash, random_hash(), &ext.encode())
}

fn random_hash() -> [u8; 16] {
    let mut random_hash = [0u8; 16];
    random_hash.copy_from_slice(&rns_crypto::random::random_bytes(16));
    random_hash
}

fn build_synthesis(
    identity: &rns_identity::identity::Identity,
    interface_hash: [u8; 32],
    random_hash: [u8; 16],
    ext: &[u8],
) -> Option<Vec<u8>> {
    let mut synth_data = TunnelSynthesisData {
        public_key: identity.get_public_key(),
        interface_hash,
        random_hash,
        signature: [0; 64],
        ext: ext.to_vec(),
    };
    synth_data.signature = identity.sign(&synth_data.signed_data())?;
    let payload = synth_data.pack();

    let dest_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
        "rnstransport.tunnel.synthesize",
        None,
    );

    let flags = rns_wire::flags::PacketFlags {
        header_type: rns_wire::flags::HeaderType::Header1,
        context_flag: false,
        transport_type: rns_wire::flags::TransportType::Broadcast,
        destination_type: rns_wire::flags::DestinationType::Plain,
        packet_type: rns_wire::flags::PacketType::Data,
    };
    let header = rns_wire::header::PacketHeader {
        flags,
        hops: 0,
        transport_id: None,
        destination_hash: dest_hash,
        context: rns_wire::context::PacketContext::None,
    };

    let mut raw = header.pack();
    raw.extend_from_slice(&payload);
    Some(raw)
}

/// Interface identifier used in tunnel synthesis: `SHA-256(name)`.
pub fn interface_hash(name: &str) -> [u8; 32] {
    rns_crypto::sha::sha256(name.as_bytes())
}

/// Vectors from upstream RNS 1.6.1 (`upstream/candidate/Reticulum`,
/// `cff4d03f`): `Transport.synthesize_tunnel` with `Transport.identity` set to
/// `Identity.from_bytes(sha256(b"k4 synthesis x25519") || sha256(b"k4
/// synthesis ed25519"))`, `Identity.get_random_hash` returning 0x01..=0x10 and
/// `Packet.send` capturing `raw`, on an interface named [`INTERFACE`];
/// `Discovery.IMPLEMENTATION_NAME`, `RNS_VERSION` and the transport switch set
/// per vector. Handler verdicts are `Transport.tunnel_synthesize_handler` on
/// that identity's syntheses, the extension packed by `umsgpack.packb`, with
/// `handle_tunnel`, `synthesize_tunnel` and `_detach_interface` recording.
#[cfg(test)]
pub(crate) mod python_vectors {
    use rns_identity::identity::Identity;

    pub(crate) const INTERFACE: &str = "TCPInterface[Uplink/127.0.0.1:4242]";
    pub(crate) const RANDOM_HASH: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    /// RNS 1.6.1, transport off, costs 23.5 and 15.8.
    pub(crate) const PYTHON_DEFAULT: &str = "080091bf0910267b59b0e864e0d4c91602ca0008f0794e97fbd6eedd9df04166e5c30c198b130c74\
         fdd4895666a40021346a1c9fdd19fff7e6509a77783c1a531009d4f020c2ec2883533db73042a08e\
         51f560e19a67596cb3250476ffe12dc6de8280bab299151bb67904ea30f1585377afec0102030405\
         060708090a0b0c0d0e0f1002ef4f3c52397835b7488f72862f8ea51fc2dcf75e70b6461246d2b549\
         9947cfd7110d6136aa867b2eba7c1fefc0d01a1be201ab41aa384d0656b9bc5bb42f0c85ccfda352\
         4e53ccfca5312e362e3101c2ccfbcb4037800000000000ccfacb402f99999999999a";
    /// `rsRNS` 1.5.1, transport on, costs 23.5 and 15.8: what this crate sends.
    pub(crate) const RUST_FORM: &str = "080091bf0910267b59b0e864e0d4c91602ca0008f0794e97fbd6eedd9df04166e5c30c198b130c74\
         fdd4895666a40021346a1c9fdd19fff7e6509a77783c1a531009d4f020c2ec2883533db73042a08e\
         51f560e19a67596cb3250476ffe12dc6de8280bab299151bb67904ea30f1585377afec0102030405\
         060708090a0b0c0d0e0f1027b84f07dda1787f8c9e7e2db2f5c319c1635b5035387b7fd346fcc212\
         bc7f48c368b4922ab2f06a2069e093d316c1fe656f12d14789f019c89c59c12f1d550e85ccfda572\
         73524e53ccfca5312e352e3101c3ccfbcb4037800000000000ccfacb402f99999999999a";
    /// RNS 1.6.1, transport on, costs clamped to the ints 100 and 0
    /// (Reticulum.py:1082-1087).
    pub(crate) const CLAMPED_INT_COSTS: &str = "080091bf0910267b59b0e864e0d4c91602ca0008f0794e97fbd6eedd9df04166e5c30c198b130c74\
         fdd4895666a40021346a1c9fdd19fff7e6509a77783c1a531009d4f020c2ec2883533db73042a08e\
         51f560e19a67596cb3250476ffe12dc6de8280bab299151bb67904ea30f1585377afec0102030405\
         060708090a0b0c0d0e0f108006150d385d236d44c722337891b3d967dada9dfd3c8bbe5fed1df450\
         fa111f91489bb4396514c41af90c38fce07e94ddc511c93cf32675b77a0c2a10acef0585ccfda352\
         4e53ccfca5312e362e3101c3ccfb64ccfa00";
    /// `(case, Python verdict, extension, SHA-256 of the whole payload)`; the
    /// `bad_signature` payload carries 64 zero bytes as its signature.
    pub(crate) const HANDLER_CASES: &[(&str, &str, &str, &str)] = &[
        (
            "legacy",
            "tunnel,remote",
            "",
            "c27ead28b4079539a2db20cc44fc4ed6faf93ae22b7f486166c8ec956532e635",
        ),
        (
            "extended",
            "reply,tunnel,remote",
            "85ccfda3524e53ccfca5312e362e3101c3ccfbcb4037800000000000ccfacb402f99999999999a",
            "9564e4e54674fcba802649079accbde6a54ad79794cefa24f2a8c4c2f1f30c57",
        ),
        (
            "trailing_bytes",
            "reply,tunnel,remote",
            "85ccfda3524e53ccfca5312e362e3101c3ccfbcb4037800000000000ccfacb402f99999999999a0001",
            "244394deda58b5c26b0cc7329dc71bde7147cc62f0ec0ce2a2c0b1db2fc6edb3",
        ),
        (
            "extra_key",
            "reply,tunnel,remote",
            "86ccfda3524e53ccfca5312e362e3101c3ccfbcb4037800000000000ccfacb402f99999999999a00b2544350536572766572496e74657266616365",
            "2756e2841e6a0eaf6f22ab174f3fd85029f2837af8fb792faaa3d03f7d895766",
        ),
        (
            "missing_pr_cost",
            "violation",
            "84ccfda3524e53ccfca5312e362e3101c3ccfbcb4037800000000000",
            "c23fe2d5db0a45de3ef5c025b19961a409d916e647401f016b05e5b42dad3826",
        ),
        (
            "impl_not_str",
            "violation",
            "85ccfdc403524e53ccfca5312e362e3101c3ccfbcb4037800000000000ccfacb402f99999999999a",
            "7de2e05d50cbfb8b8cb8a182b2d4a323582dd91db1453f5fe4cad0dca66f2249",
        ),
        (
            "impl_unsanitary",
            "violation",
            "85ccfda420524e53ccfca5312e362e3101c3ccfbcb4037800000000000ccfacb402f99999999999a",
            "eb57ca09b1f999f86f3cff0c66ff3fa47a1ff5cc34315ca8ca1475f1da0304ad",
        ),
        (
            "impl_empty",
            "violation",
            "85ccfda0ccfca5312e362e3101c3ccfbcb4037800000000000ccfacb402f99999999999a",
            "424b4b225c5a95c27f14a4b13a171fe7ce796a705b1a06f46bb19749265daa88",
        ),
        (
            "version_unparsable",
            "violation",
            "85ccfda3524e53ccfca2763101c3ccfbcb4037800000000000ccfacb402f99999999999a",
            "ecefeb8e408f6cd8001edccb739ebec9d77bf35973cdf22676421d8a670a63a0",
        ),
        (
            "version_prefix",
            "reply,tunnel,remote",
            "85ccfda3524e53ccfca5322e782e3101c3ccfbcb4037800000000000ccfacb402f99999999999a",
            "e29fe380ed9b4b2f4d218e8c4627847ab1bf3223ec42411acb1b6d166402a82f",
        ),
        (
            "transport_int",
            "violation",
            "85ccfda3524e53ccfca5312e362e310101ccfbcb4037800000000000ccfacb402f99999999999a",
            "978328450f982882147a148fa1be7e7445083249f602edd820e6b7e355df9993",
        ),
        (
            "cost_int",
            "violation",
            "85ccfda3524e53ccfca5312e362e3101c3ccfb64ccfacb402f99999999999a",
            "342ff63da943d29d8e249ee0630b10b9bec646978e080e46c06ca00f72706f56",
        ),
        (
            "cost_nan",
            "violation",
            "85ccfda3524e53ccfca5312e362e3101c3ccfbcb4037800000000000ccfacb7ff8000000000000",
            "decff860b2c53f2b0108f38fcde26d3b5cef7e52641e79e4096bfcc25fe7a2b4",
        ),
        (
            "ext_array",
            "violation",
            "920102",
            "f96f2f2ac2b480f2c01d3d7b74c1489bd9bdc207d0a25bc9da5b36d764d0ad45",
        ),
        (
            "ext_undecodable",
            "violation",
            "c1",
            "465b25e6078af34c7b347667fde8089769eabf58a8583f7111c6e0ebc8fdf154",
        ),
        (
            "duplicate_key",
            "violation",
            "86ccfda3524e53ccfca5312e362e3101c3ccfbcb4037800000000000ccfacb402f99999999999a01c3",
            "61212eecebc63b0abbec51d26dc2be498d34802d063e1a82e14ddaad10d637b6",
        ),
        (
            "bad_signature",
            "detach",
            "85ccfda3524e53ccfca5312e362e3101c3ccfbcb4037800000000000ccfacb402f99999999999a",
            "7db7d644cab200f07440b93c8e0dba96df7988366ebeaecf0e94ad2d99fe0382",
        ),
    ];

    pub(crate) fn identity() -> Identity {
        let key = hex::decode(
            "647aa6ad267afdd5b7e0b7dd5889acd56068f5a2d93579fd37bd9f74c8d1d9e8\
             f56f0cbab4dd8721d77d087e50342fba11c40e481fab8717e83b10ef55fe5330",
        )
        .unwrap();
        Identity::from_private_key(&key).unwrap()
    }

    /// A case's payload as this crate signs it.
    pub(crate) fn payload(name: &str, ext: &str) -> Vec<u8> {
        let mut data = super::TunnelSynthesisData {
            public_key: identity().get_public_key(),
            interface_hash: super::interface_hash(INTERFACE),
            random_hash: RANDOM_HASH,
            signature: [0; 64],
            ext: hex::decode(ext).unwrap(),
        };
        if name != "bad_signature" {
            data.signature = identity().sign(&data.signed_data()).unwrap();
        }
        data.pack()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_table_basic() {
        let mut table = TunnelTable::new();
        let tunnel_id = [0xAA; 32];
        let entry = TunnelEntry {
            tunnel_id,
            interface_id: Some(1),
            tunnel_paths: std::collections::HashMap::new(),
            expires: 99999999.0,
        };
        table.insert(entry);
        assert!(table.get(&tunnel_id).is_some());
        assert_eq!(table.len(), 1);
    }

    fn synthesis(ext: &[u8]) -> TunnelSynthesisData {
        TunnelSynthesisData {
            public_key: [0x42; 64],
            interface_hash: [0xAB; 32],
            random_hash: [0xCD; 16],
            signature: [0xEF; 64],
            ext: ext.to_vec(),
        }
    }

    #[test]
    fn test_tunnel_synthesis_roundtrip() {
        for ext in [&[][..], &[0x80, 0x01, 0x02]] {
            let data = synthesis(ext);
            let packed = data.pack();
            assert_eq!(packed.len(), 176 + ext.len());
            let unpacked = TunnelSynthesisData::unpack(&packed).unwrap();
            assert_eq!(unpacked.public_key, data.public_key);
            assert_eq!(unpacked.interface_hash, data.interface_hash);
            assert_eq!(unpacked.random_hash, data.random_hash);
            assert_eq!(unpacked.signature, data.signature);
            assert_eq!(unpacked.ext, ext);
        }
    }

    /// Python 1.6.1 takes 176 to `Packet.MDU` bytes (Transport.py:3218-3222).
    #[test]
    fn synthesis_payloads_run_from_176_to_464_bytes() {
        let packed = synthesis(&[0; 288]).pack();
        assert_eq!(packed.len(), 464);
        assert!(TunnelSynthesisData::unpack(&packed).is_some());
        assert!(TunnelSynthesisData::unpack(&packed[..176]).is_some());
        assert!(TunnelSynthesisData::unpack(&packed[..175]).is_none());
        let mut long = packed.clone();
        long.push(0);
        assert!(TunnelSynthesisData::unpack(&long).is_none());
    }

    fn packet(hex: &str) -> (rns_wire::header::PacketHeader, TunnelSynthesisData) {
        let raw = hex::decode(hex).unwrap();
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        (header, TunnelSynthesisData::unpack(&raw[offset..]).unwrap())
    }

    /// The signature covers the extension that follows it on the wire.
    #[test]
    fn python_signs_the_extension_it_appends() {
        let (header, mut data) = packet(python_vectors::PYTHON_DEFAULT);
        assert_eq!(
            header.destination_hash,
            rns_identity::destination::Destination::hash_from_name_and_identity(
                "rnstransport.tunnel.synthesize",
                None
            )
        );
        assert_eq!(data.pack().len(), 215);
        assert_eq!(
            hex::encode(&data.ext),
            "85ccfda3524e53ccfca5312e362e3101c2ccfbcb4037800000000000ccfacb402f99999999999a"
        );
        assert!(data.is_signed());
        assert_eq!(
            data.transport_identity_hash(),
            python_vectors::identity().hash
        );
        data.ext.pop();
        assert!(
            !data.is_signed(),
            "a truncated extension breaks the signature"
        );
    }

    /// This crate's synthesis is byte for byte what upstream's encoder and
    /// signer make of the same fields.
    #[test]
    fn rust_builds_the_synthesis_python_builds() {
        let ext = TunnelExt {
            implementation: "rsRNS".into(),
            version: "1.5.1".into(),
            transport: true,
            destination_cost: 23.5,
            pr_cost: 15.8,
        };
        let raw = build_synthesis(
            &python_vectors::identity(),
            interface_hash(python_vectors::INTERFACE),
            python_vectors::RANDOM_HASH,
            &ext.encode(),
        )
        .unwrap();
        assert_eq!(hex::encode(raw), python_vectors::RUST_FORM);
        let python = TunnelExt {
            implementation: "RNS".into(),
            version: "1.6.1".into(),
            transport: false,
            ..ext
        };
        let raw = build_synthesis(
            &python_vectors::identity(),
            interface_hash(python_vectors::INTERFACE),
            python_vectors::RANDOM_HASH,
            &python.encode(),
        )
        .unwrap();
        assert_eq!(hex::encode(raw), python_vectors::PYTHON_DEFAULT);
        assert_eq!(
            TunnelExt::local(true, 1.0, 2.0).implementation,
            crate::discovery::constants::IMPLEMENTATION_NAME
        );
    }

    #[test]
    fn a_python_extension_decodes_to_its_remote_transport() {
        let (_, data) = packet(python_vectors::PYTHON_DEFAULT);
        assert_eq!(
            RemoteTransportInfo::decode(&data.ext).unwrap(),
            RemoteTransportInfo {
                implementation: "RNS".into(),
                version: vec![1, 6, 1],
                transport: false,
                destination_cost: rns_identity::stamps::quantize_cost(23.5).unwrap(),
                pr_cost: rns_identity::stamps::quantize_cost(15.8).unwrap(),
            }
        );
    }

    /// Python rejects the ints its own clamp produces; costs are accepted
    /// either way here (lead decision, logged as a patch candidate).
    #[test]
    fn integer_costs_are_accepted_and_quantized() {
        let (_, data) = packet(python_vectors::CLAMPED_INT_COSTS);
        assert!(data.is_signed());
        let info = RemoteTransportInfo::decode(&data.ext).unwrap();
        assert_eq!((info.destination_cost, info.pr_cost), (100.0, 0.0));
        assert!(info.transport);
    }

    #[test]
    fn test_tunnel_synthesis_id() {
        let data = synthesis(&[]);
        let id = data.tunnel_id();
        assert_eq!(id.len(), 32);
        let id2 = data.tunnel_id();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_handle_tunnel_new() {
        let mut table = TunnelTable::new();
        let tunnel_id = [0xFF; 32];
        handle_tunnel(&mut table, tunnel_id, 1);
        assert!(table.get(&tunnel_id).is_some());
        assert_eq!(table.get(&tunnel_id).unwrap().interface_id, Some(1));
    }

    #[test]
    fn test_handle_tunnel_reappear() {
        let mut table = TunnelTable::new();
        let tunnel_id = [0xFF; 32];
        handle_tunnel(&mut table, tunnel_id, 1);

        handle_tunnel(&mut table, tunnel_id, 2);
        assert_eq!(table.get(&tunnel_id).unwrap().interface_id, Some(2));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn an_interface_keeps_naming_the_tunnel_of_its_latest_synthesis() {
        let mut table = TunnelTable::new();
        let (older, newer) = ([0x0A; 32], [0x0B; 32]);
        handle_tunnel(&mut table, older, 1);
        handle_tunnel(&mut table, newer, 1);
        assert_eq!(
            table.get_mut_by_interface(1).map(|tunnel| tunnel.tunnel_id),
            Some(newer)
        );
        assert_eq!(
            table.get(&older).unwrap().interface_id,
            Some(1),
            "the superseded tunnel keeps its own binding (Transport.py:2827-2834)"
        );

        handle_tunnel(&mut table, newer, 2);
        assert_eq!(
            table.get_mut_by_interface(1).map(|tunnel| tunnel.tunnel_id),
            Some(newer),
            "interface 1 still names the tunnel that moved, as Python's interface.tunnel_id does"
        );

        assert_eq!(table.void_interface(1), 1);
        assert!(table.get_mut_by_interface(1).is_none());
        assert_eq!(table.get(&older).unwrap().interface_id, None);
        assert_eq!(table.get(&newer).unwrap().interface_id, Some(2));
        assert_eq!(
            table.get_mut_by_interface(2).map(|tunnel| tunnel.tunnel_id),
            Some(newer)
        );
    }

    /// Python 1.6.1 gives an orphaned tunnel `TUNNEL_RECONNECT_WINDOW` from
    /// the moment its interface goes, longer or shorter than before
    /// (Transport.py:1285-1288); a synthesis restores the full timeout.
    #[test]
    fn voiding_an_interface_starts_the_reconnect_window() {
        let now = 1_000_000.0;
        let _clock = crate::test_clock::Clock::at(now);
        let window = crate::constants::TUNNEL_RECONNECT_WINDOW as f64;
        let mut table = TunnelTable::new();
        handle_tunnel(&mut table, [0x01; 32], 1);
        table.insert(TunnelEntry {
            tunnel_id: [0x02; 32],
            interface_id: Some(1),
            tunnel_paths: HashMap::new(),
            expires: now + 60.0,
        });
        handle_tunnel(&mut table, [0x03; 32], 2);

        assert_eq!(table.void_interface(1), 2);
        assert_eq!(table.get(&[0x01; 32]).unwrap().expires, now + window);
        assert_eq!(table.get(&[0x02; 32]).unwrap().expires, now + window);
        assert_eq!(
            table.get(&[0x03; 32]).unwrap().expires,
            now + crate::constants::TUNNEL_TIMEOUT as f64,
            "a tunnel on another interface keeps its expiry"
        );

        handle_tunnel(&mut table, [0x01; 32], 3);
        assert_eq!(
            table.get(&[0x01; 32]).unwrap().expires,
            now + crate::constants::TUNNEL_TIMEOUT as f64
        );
    }

    /// Python expires a tunnel TUNNEL_TIMEOUT after its synthesis
    /// (Transport.py), so the next cull keeps it.
    #[test]
    fn a_handled_tunnel_expires_after_tunnel_timeout_and_survives_the_cull() {
        let mut table = TunnelTable::new();
        handle_tunnel(&mut table, [0x0C; 32], 1);
        let expires = table.get(&[0x0C; 32]).unwrap().expires;
        let timeout = crate::constants::TUNNEL_TIMEOUT as f64;
        assert!((expires - crate::now_f64() - timeout).abs() < 5.0);
        assert_eq!(table.cull_expired(), 0);
    }

    #[test]
    fn test_tunnel_cull_expired() {
        let mut table = TunnelTable::new();
        let entry = TunnelEntry {
            tunnel_id: [0xAA; 32],
            interface_id: Some(1),
            tunnel_paths: std::collections::HashMap::new(),
            expires: 0.0,
        };
        table.insert(entry);
        assert_eq!(table.len(), 1);
        table.cull_expired();
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn tunnels_with_excessive_expiry_are_culled() {
        let now = crate::now_f64();
        let limit = 2.0 * crate::constants::TUNNEL_TIMEOUT as f64;
        let culls: [fn(&mut TunnelTable) -> usize; 2] = [TunnelTable::cull_expired, |table| {
            table.cull_expired_batch(usize::MAX)
        }];
        for cull in culls {
            let mut table = TunnelTable::new();
            for (tunnel_id, expires) in [
                ([0x01; 32], now + limit + 60.0),
                ([0x02; 32], now + limit - 60.0),
            ] {
                table.insert(TunnelEntry {
                    tunnel_id,
                    interface_id: None,
                    tunnel_paths: HashMap::new(),
                    expires,
                });
            }
            assert_eq!(cull(&mut table), 1);
            assert!(
                table.get(&[0x01; 32]).is_none(),
                "Python culls an expiry beyond twice TUNNEL_TIMEOUT (Transport.py:1022-1024)"
            );
            assert!(table.get(&[0x02; 32]).is_some());
        }
    }

    #[test]
    fn test_tunnel_iter() {
        let mut table = TunnelTable::new();
        let entry1 = TunnelEntry {
            tunnel_id: [0xAA; 32],
            interface_id: Some(1),
            tunnel_paths: std::collections::HashMap::new(),
            expires: 99999999.0,
        };
        let entry2 = TunnelEntry {
            tunnel_id: [0xBB; 32],
            interface_id: Some(2),
            tunnel_paths: std::collections::HashMap::new(),
            expires: 99999999.0,
        };
        table.insert(entry1);
        table.insert(entry2);
        assert_eq!(table.iter().count(), 2);
    }
}
