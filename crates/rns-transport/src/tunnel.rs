use std::collections::HashMap;

use crate::messages::InterfaceId;

/// One virtual-overlay tunnel plus the per-destination paths riding it.
/// Tunnels let transports stitch together routes that cross a network
/// boundary the underlying interface cannot reach directly.
#[derive(Debug, Clone)]
pub struct TunnelEntry {
    pub tunnel_id: [u8; 32],
    pub interface_id: InterfaceId,
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

pub struct TunnelTable {
    entries: HashMap<[u8; 32], TunnelEntry>,
}

impl TunnelTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, entry: TunnelEntry) {
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

    pub fn get_mut_by_interface(&mut self, interface_id: InterfaceId) -> Option<&mut TunnelEntry> {
        self.entries
            .values_mut()
            .find(|entry| entry.interface_id == interface_id)
    }

    pub fn tunnel_paths(&self) -> impl Iterator<Item = (&[u8; 16], &TunnelPath)> {
        self.entries
            .values()
            .flat_map(|entry| entry.tunnel_paths.iter())
    }

    pub fn cull_expired(&mut self) -> usize {
        let now = crate::now_f64();

        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.expires > now);
        before - self.entries.len()
    }

    /// Batched cull — bounds per-tick work on large tables.
    pub fn cull_expired_batch(&mut self, limit: usize) -> usize {
        let now = crate::now_f64();

        let to_remove: Vec<[u8; 32]> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires <= now)
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

/// Payload of a tunnel-synthesis announce. Total wire size = 176 bytes.
#[derive(Debug, Clone)]
pub struct TunnelSynthesisData {
    /// Transport identity key: `X25519(32) || Ed25519(32)`.
    pub public_key: [u8; 64],
    /// SHA-256 of the interface identifier string.
    pub interface_hash: [u8; 32],
    /// Randomness that makes each announce unique for replay protection.
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

    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < 176 {
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
}

/// Install or refresh a tunnel from a validated tunnel-synthesis announce.
/// A reappearing tunnel keeps its existing path set — only the interface
/// binding and expiry move forward, so in-flight routes aren't lost when the
/// underlying link flaps.
pub fn handle_tunnel(
    tunnel_table: &mut TunnelTable,
    tunnel_id: [u8; 32],
    interface_id: crate::messages::InterfaceId,
    destination_timeout: f64,
) {
    let now = crate::now_f64();
    let expires = now + destination_timeout;

    if let Some(existing) = tunnel_table.get_mut(&tunnel_id) {
        existing.interface_id = interface_id;
        existing.expires = expires;
    } else {
        let entry = TunnelEntry {
            tunnel_id,
            interface_id,
            tunnel_paths: std::collections::HashMap::new(),
            expires,
        };
        tunnel_table.insert(entry);
    }
}

/// Build a tunnel-synthesis packet addressed to the well-known tunnel
/// synthesize PLAIN destination. The returned bytes are ready to send on the
/// interface that should host the tunnel; the receiver validates the
/// signature and installs the tunnel via `handle_tunnel`.
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
            interface_id: 1,
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
        handle_tunnel(&mut table, tunnel_id, 1, 604800.0);
        assert!(table.get(&tunnel_id).is_some());
        assert_eq!(table.get(&tunnel_id).unwrap().interface_id, 1);
    }

    #[test]
    fn test_handle_tunnel_reappear() {
        let mut table = TunnelTable::new();
        let tunnel_id = [0xFF; 32];
        handle_tunnel(&mut table, tunnel_id, 1, 604800.0);

        handle_tunnel(&mut table, tunnel_id, 2, 604800.0);
        assert_eq!(table.get(&tunnel_id).unwrap().interface_id, 2);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_tunnel_cull_expired() {
        let mut table = TunnelTable::new();
        let entry = TunnelEntry {
            tunnel_id: [0xAA; 32],
            interface_id: 1,
            tunnel_paths: std::collections::HashMap::new(),
            expires: 0.0,
        };
        table.insert(entry);
        assert_eq!(table.len(), 1);
        table.cull_expired();
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_tunnel_iter() {
        let mut table = TunnelTable::new();
        let entry1 = TunnelEntry {
            tunnel_id: [0xAA; 32],
            interface_id: 1,
            tunnel_paths: std::collections::HashMap::new(),
            expires: 99999999.0,
        };
        let entry2 = TunnelEntry {
            tunnel_id: [0xBB; 32],
            interface_id: 2,
            tunnel_paths: std::collections::HashMap::new(),
            expires: 99999999.0,
        };
        table.insert(entry1);
        table.insert(entry2);
        assert_eq!(table.iter().count(), 2);
    }
}
