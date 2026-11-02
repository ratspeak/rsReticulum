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

    /// Resolve the cached association for this interface. It can return None
    /// for a removed record, or a record now bound to another interface;
    /// neither current binding nor expiry is checked here.
    pub fn get_mut_by_interface(&mut self, interface_id: InterfaceId) -> Option<&mut TunnelEntry> {
        let tunnel_id = self.by_interface.get(&interface_id)?;
        self.entries.get_mut(tunnel_id)
    }

    /// Forget `interface_id`: it names no tunnel, and the tunnels bound to it
    /// become unbound but keep their paths. Returns
    /// how many tunnels were unbound.
    pub fn void_interface(&mut self, interface_id: InterfaceId) -> usize {
        self.by_interface.remove(&interface_id);
        let mut voided = 0;
        for entry in self.entries.values_mut() {
            if entry.interface_id == Some(interface_id) {
                entry.interface_id = None;
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

/// Expired, or set to expire implausibly late (Transport.py:1022-1027).
fn is_stale(entry: &TunnelEntry, now: f64) -> bool {
    entry.expires <= now || entry.expires > now + 2.0 * crate::constants::TUNNEL_TIMEOUT as f64
}

/// The 176-byte tunnel-synthesis payload, excluding the Reticulum packet header.
#[derive(Debug, Clone)]
pub struct TunnelSynthesisData {
    /// Transport identity key: `X25519(32) || Ed25519(32)`.
    pub public_key: [u8; 64],
    /// SHA-256 of the interface identifier string.
    pub interface_hash: [u8; 32],
    /// Random bytes included in the signed payload. This type does not track
    /// or reject replayed synthesis packets.
    pub random_hash: [u8; 16],
    /// Ed25519 signature over `public_key || interface_hash || random_hash`.
    pub signature: [u8; 64],
}

impl TunnelSynthesisData {
    /// `public_key(64) || interface_hash(32) || random_hash(16) || signature(64) = 176 bytes`.
    pub fn pack(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(176);
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(&self.interface_hash);
        data.extend_from_slice(&self.random_hash);
        data.extend_from_slice(&self.signature);
        data
    }

    /// Parse exactly 176 bytes without verifying the signature. Call
    /// [`Self::is_signed`] before treating the payload as signed.
    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() != 176 {
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

    /// Verify the signature under the Ed25519 half of the embedded public key.
    /// This does not check an external trust policy, replay state or freshness.
    pub fn is_signed(&self) -> bool {
        let Ok(signer) = rns_identity::identity::Identity::from_public_key(&self.public_key) else {
            return false;
        };
        let mut signed = Vec::with_capacity(112);
        signed.extend_from_slice(&self.public_key);
        signed.extend_from_slice(&self.interface_hash);
        signed.extend_from_slice(&self.random_hash);
        signer.verify(&signed, &self.signature)
    }
}

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

/// Build a tunnel-synthesis packet addressed to the well-known tunnel
/// synthesize PLAIN destination, with fresh random bytes and a signature.
/// Return `None` if the identity cannot sign. The result is a complete inner
/// Reticulum packet; interface-specific IFAC and framing remain separate.
/// The receiving transport validates the signature before installing the tunnel.
pub fn build_tunnel_synthesis_packet(
    identity: &rns_identity::identity::Identity,
    interface_hash: [u8; 32],
) -> Option<Vec<u8>> {
    let public_key = identity.get_public_key();

    let random_vec = rns_crypto::random::random_bytes(16);
    let mut random_hash = [0u8; 16];
    random_hash.copy_from_slice(&random_vec);

    let mut signed_data = Vec::with_capacity(112);
    signed_data.extend_from_slice(&public_key);
    signed_data.extend_from_slice(&interface_hash);
    signed_data.extend_from_slice(&random_hash);

    let signature = identity.sign(&signed_data)?;

    let synth_data = TunnelSynthesisData {
        public_key,
        interface_hash,
        random_hash,
        signature,
    };
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

    #[test]
    fn test_tunnel_synthesis_roundtrip() {
        let data = TunnelSynthesisData {
            public_key: [0x42; 64],
            interface_hash: [0xAB; 32],
            random_hash: [0xCD; 16],
            signature: [0xEF; 64],
        };
        let packed = data.pack();
        assert_eq!(packed.len(), 176);

        let unpacked = TunnelSynthesisData::unpack(&packed).unwrap();
        assert_eq!(unpacked.public_key, data.public_key);
        assert_eq!(unpacked.interface_hash, data.interface_hash);
        assert_eq!(unpacked.random_hash, data.random_hash);
        assert_eq!(unpacked.signature, data.signature);
    }

    #[test]
    fn synthesis_payload_must_be_exactly_176_bytes() {
        let packed = TunnelSynthesisData {
            public_key: [0x42; 64],
            interface_hash: [0xAB; 32],
            random_hash: [0xCD; 16],
            signature: [0xEF; 64],
        }
        .pack();
        assert!(TunnelSynthesisData::unpack(&packed).is_some());
        assert!(TunnelSynthesisData::unpack(&packed[..175]).is_none());
        let mut trailing = packed.clone();
        trailing.push(0);
        assert!(
            TunnelSynthesisData::unpack(&trailing).is_none(),
            "Python requires exactly 176 bytes (Transport.py:2791)"
        );
    }

    #[test]
    fn test_tunnel_synthesis_id() {
        let data = TunnelSynthesisData {
            public_key: [0x42; 64],
            interface_hash: [0xAB; 32],
            random_hash: [0xCD; 16],
            signature: [0xEF; 64],
        };
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

    /// Python expires a tunnel TUNNEL_TIMEOUT after its synthesis
    /// (Transport.py:2821), so the next cull keeps it.
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
