//! Tunnel synthesis, binding, persistence, cache replay and the PLAIN/GROUP
//! ingress filter through the production actor paths.
use super::*;
use crate::link_messages::DestinationEvent;
use crate::persistence::{
    PersistedPathEntry, PersistedTunnelEntry, PersistedTunnelPath, PersistedTunnelTable,
};
use crate::tunnel::{
    TunnelPath, TunnelSynthesisData, build_tunnel_synthesis_packet, handle_tunnel,
};
use rns_identity::identity::Identity;
use rns_wire::context::PacketContext;
use rns_wire::flags::{DestinationType, HeaderType, PacketFlags, PacketType, TransportType};
use rns_wire::header::PacketHeader;

fn hub() -> TransportActor {
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    actor.transport_identity_hash = Some([0x42; 16]);
    actor
}

fn attach(actor: &mut TransportActor, id: InterfaceId, name: &str) -> mpsc::Receiver<Bytes> {
    let (entry, rx) = make_test_interface(name);
    actor.interfaces.insert(id, entry);
    rx
}

fn inbound(actor: &mut TransportActor, raw: Bytes, interface_id: InterfaceId) {
    actor.on_inbound(InboundPacket {
        raw,
        interface_id,
        rssi: None,
        snr: None,
        q: None,
    });
}

fn synthesis(identity: &Identity, interface: &str) -> (Bytes, [u8; 32]) {
    let raw =
        build_tunnel_synthesis_packet(identity, crate::tunnel::interface_hash(interface)).unwrap();
    let tunnel_id = TunnelSynthesisData::unpack(&raw[rns_wire::constants::HEADER_MINSIZE..])
        .unwrap()
        .tunnel_id();
    (Bytes::from(raw), tunnel_id)
}

fn carries(actor: &TransportActor, tunnel_id: &[u8; 32], dest: &[u8; 16]) -> bool {
    actor
        .tunnel_table
        .get(tunnel_id)
        .is_some_and(|tunnel| tunnel.tunnel_paths.contains_key(dest))
}

fn cache_announce(dir: &std::path::Path, raw: &[u8], interface: Option<&str>) -> [u8; 32] {
    let packet_hash = rns_wire::hash::packet_hash(raw, HeaderType::Header1);
    crate::persistence::write_python_cached_announce_if_absent(
        &dir.join("cache").join("announces"),
        &packet_hash,
        raw,
        interface,
    )
    .unwrap();
    packet_hash
}

#[test]
fn valid_synthesis_installs_a_tunnel_that_collects_announces() {
    let mut actor = hub();
    let _rx = attach(&mut actor, 1, "hub/client_1");
    let (raw, tunnel_id) = synthesis(&Identity::new(), "TCPInterface[Uplink/127.0.0.1:4242]");
    inbound(&mut actor, raw, 1);
    assert!(
        actor.tunnel_table.get(&tunnel_id).is_some(),
        "a valid synthesis installs its tunnel"
    );

    let (announce, dest) = make_valid_announce("tunnel.collect", 0);
    inbound(&mut actor, announce, 1);
    assert!(
        carries(&actor, &tunnel_id, &dest),
        "announces on the tunnel's interface join the tunnel"
    );
}

#[test]
fn synthesis_with_a_bad_signature_or_extra_bytes_installs_nothing() {
    let mut actor = hub();
    let _rx: Vec<_> = (1..=3)
        .map(|id| attach(&mut actor, id, &format!("hub/client_{id}")))
        .collect();
    let (valid, valid_id) = synthesis(&Identity::new(), "uplink-a");
    inbound(&mut actor, valid, 1);
    assert!(
        actor.tunnel_table.get(&valid_id).is_some(),
        "control: a valid synthesis installs"
    );

    let (raw, tampered_id) = synthesis(&Identity::new(), "uplink-b");
    let mut tampered = raw.to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;
    inbound(&mut actor, Bytes::from(tampered), 2);
    assert!(
        actor.tunnel_table.get(&tampered_id).is_none(),
        "a flipped signature bit is rejected"
    );

    let (raw, trailing_id) = synthesis(&Identity::new(), "uplink-c");
    let mut trailing = raw.to_vec();
    trailing.push(0);
    inbound(&mut actor, Bytes::from(trailing), 3);
    assert!(
        actor.tunnel_table.get(&trailing_id).is_none(),
        "a payload longer than 176 bytes is rejected (Transport.py:2791)"
    );
    assert_eq!(actor.tunnel_table.len(), 1);
}

#[test]
fn the_newer_synthesis_on_an_interface_takes_its_later_announces() {
    let mut actor = hub();
    let _rx = attach(&mut actor, 1, "hub/client_1");
    let (older, older_id) = synthesis(&Identity::new(), "uplink");
    let (newer, newer_id) = synthesis(&Identity::new(), "uplink");
    inbound(&mut actor, older, 1);
    inbound(&mut actor, newer, 1);
    assert!(
        actor.tunnel_table.get(&older_id).is_some() && actor.tunnel_table.get(&newer_id).is_some(),
        "both syntheses install"
    );

    let (announce, dest) = make_valid_announce("tunnel.newer", 0);
    inbound(&mut actor, announce, 1);
    assert!(
        carries(&actor, &newer_id, &dest),
        "the last synthesis owns the interface (Transport.py:2827, :2834)"
    );
    assert!(
        !carries(&actor, &older_id, &dest),
        "the superseded tunnel takes no new paths"
    );
}

#[test]
fn losing_a_tunnel_interface_keeps_paths_through_other_interfaces() {
    let mut actor = hub();
    let _tunnel_rx = attach(&mut actor, 1, "hub/client_1");
    let _uplink_rx = attach(&mut actor, 2, "uplink");
    let tunnel_id = [0x77; 32];
    handle_tunnel(&mut actor.tunnel_table, tunnel_id, 1);

    let identity = Identity::new();
    let emitted = now_f64() as u64;
    let (via_tunnel, dest) = make_announce_for_with_random_blob(
        &identity,
        "tunnel.elsewhere",
        1,
        random_blob(1, emitted - 10),
    );
    inbound(&mut actor, via_tunnel, 1);
    assert!(carries(&actor, &tunnel_id, &dest));
    let (fresher, _) = make_announce_for_with_random_blob(
        &identity,
        "tunnel.elsewhere",
        1,
        random_blob(2, emitted),
    );
    inbound(&mut actor, fresher, 2);
    assert_eq!(
        actor.path_table.get(&dest).map(|path| path.interface_id),
        Some(2)
    );

    actor.deregister_interface(1);
    assert_eq!(
        actor
            .path_table
            .get_live(&dest)
            .map(|path| path.interface_id),
        Some(2),
        "losing the tunnel's interface only unbinds the tunnel (Transport.py:1031-1033)"
    );
    assert!(
        carries(&actor, &tunnel_id, &dest),
        "the tunnel keeps its paths for the next synthesis"
    );
}

#[test]
fn a_replacement_registration_does_not_inherit_the_tunnel_binding() {
    let mut actor = hub();
    let (entry, _old_rx) = make_test_interface("hub/client_4");
    actor.handle_message(TransportMessage::RegisterInterface { id: 4, entry });
    let tunnel_id = [0x66; 32];
    handle_tunnel(&mut actor.tunnel_table, tunnel_id, 4);

    let (replacement, _new_rx) = make_test_interface("hub/client_4");
    actor.handle_message(TransportMessage::RegisterInterface {
        id: 4,
        entry: replacement,
    });
    let (announce, dest) = make_valid_announce("tunnel.replaced", 0);
    inbound(&mut actor, announce, 4);
    assert!(
        actor.path_table.has_path(&dest),
        "control: the replacement is live"
    );
    assert!(
        !carries(&actor, &tunnel_id, &dest),
        "a replacement interface starts without a tunnel (Interface.py:127)"
    );
}

#[test]
fn an_unbound_tunnel_persists_without_an_interface_hash() {
    let dir = unique_temp_dir("unbound-tunnel");
    let mut actor = hub();
    actor.storage_dir = Some(dir.clone());
    // Id 0 used to be both the shared-instance listener and "unbound".
    let _listener_rx = attach(&mut actor, 0, "SharedInstanceServer");
    let _client_rx = attach(&mut actor, 7, "hub/client_7");
    let tunnel_id = [0x55; 32];
    handle_tunnel(&mut actor.tunnel_table, tunnel_id, 7);
    actor.deregister_interface(7);
    actor.save_routing_state();

    let saved = crate::persistence::load_python_tunnel_table(&dir.join("tunnels")).unwrap();
    let tunnel = saved
        .iter()
        .find(|tunnel| tunnel.tunnel_id == tunnel_id)
        .expect("the unbound tunnel is persisted");
    assert_eq!(
        tunnel.interface_hash, None,
        "Python writes an unbound tunnel with a nil interface (Transport.py:3912-3913)"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cache_request_replays_on_the_interface_its_cache_file_names() {
    let dir = unique_temp_dir("cache-replay-interface");
    let mut actor = hub();
    actor.storage_dir = Some(dir.clone());
    let _rx = attach(&mut actor, 3, "radio");
    let (announce, dest) = make_valid_announce("cache.interface", 1);
    let packet_hash = cache_announce(&dir, &announce, Some("radio"));

    actor.handle_message(TransportMessage::CacheRequest {
        packet_hash,
        destination_hash: dest,
    });
    assert_eq!(
        actor.path_table.get(&dest).map(|path| path.interface_id),
        Some(3),
        "Python replays a cached packet on its recorded interface (Transport.py:3119)"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cache_request_never_replays_on_an_accepted_client() {
    let dir = unique_temp_dir("cache-replay-child");
    let mut actor = hub();
    actor.storage_dir = Some(dir.clone());
    let (mut entry, _rx) = make_test_interface("hub/client_3");
    entry.parent_id = Some(2);
    actor.interfaces.insert(3, entry);
    let (announce, dest) = make_valid_announce("cache.child", 1);
    let packet_hash = cache_announce(&dir, &announce, Some("hub/client_3"));

    actor.handle_message(TransportMessage::CacheRequest {
        packet_hash,
        destination_hash: dest,
    });
    assert!(
        actor.recent_announces.contains_key(&dest),
        "control: the replay was processed"
    );
    assert_ne!(
        actor.path_table.get(&dest).map(|path| path.interface_id),
        Some(3),
        "an accepted client's name may belong to another peer by now"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cache_request_replay_adds_no_tunnel_path() {
    let dir = unique_temp_dir("cache-replay-tunnel");
    let mut actor = hub();
    actor.storage_dir = Some(dir.clone());
    let _rx = attach(&mut actor, 1, "hub/client_1");
    let tunnel_id = [0x44; 32];
    handle_tunnel(&mut actor.tunnel_table, tunnel_id, 1);
    actor.deregister_interface(1);

    let (announce, dest) = make_valid_announce("cache.tunnel", 1);
    let packet_hash = cache_announce(&dir, &announce, None);
    actor.handle_message(TransportMessage::CacheRequest {
        packet_hash,
        destination_hash: dest,
    });
    assert!(
        actor.recent_announces.contains_key(&dest),
        "control: the replay was processed"
    );
    assert!(
        !carries(&actor, &tunnel_id, &dest),
        "a replay without a live interface joins no tunnel"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn persisted_tunnels_load_unbound_even_when_their_interface_returns() {
    let dir = unique_temp_dir("tunnels-load-unbound");
    let tunnel_id = [0x33; 32];
    {
        let mut writer = hub();
        writer.storage_dir = Some(dir.clone());
        let _rx = attach(&mut writer, 5, "uplink");
        handle_tunnel(&mut writer.tunnel_table, tunnel_id, 5);
        let (announce, dest) = make_valid_announce("load.unbound", 0);
        inbound(&mut writer, announce, 5);
        assert!(carries(&writer, &tunnel_id, &dest));
        writer.save_routing_state();
    }

    let mut reader = hub();
    reader.handle_message(TransportMessage::SetStoragePaths {
        storage_dir: dir.clone(),
    });
    assert!(
        reader.tunnel_table.get(&tunnel_id).is_some(),
        "tunnels load before any interface registers (Transport.py:462-499)"
    );

    let (entry, _rx) = make_test_interface("uplink");
    reader.handle_message(TransportMessage::RegisterInterface { id: 9, entry });
    let (announce, later) = make_valid_announce("load.unbound.later", 0);
    inbound(&mut reader, announce, 9);
    assert!(
        !carries(&reader, &tunnel_id, &later),
        "an interface name never rebinds a loaded tunnel; only a synthesis does"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn tunnels_without_an_interface_survive_a_reload() {
    let dir = unique_temp_dir("nil-tunnel");
    let tunnel_id = [0x22; 32];
    let (announce, dest) = make_valid_announce("load.nil", 0);
    let packet_hash = cache_announce(&dir, &announce, None);
    {
        let mut writer = hub();
        writer.storage_dir = Some(dir.clone());
        let _rx = attach(&mut writer, 5, "hub/client_5");
        handle_tunnel(&mut writer.tunnel_table, tunnel_id, 5);
        let now = now_f64();
        writer
            .tunnel_table
            .get_mut(&tunnel_id)
            .unwrap()
            .tunnel_paths
            .insert(
                dest,
                TunnelPath {
                    timestamp: now,
                    next_hop: None,
                    hops: 1,
                    expires: now + 600.0,
                    random_blobs: vec![[0x11; 10]],
                    packet_hash: Some(packet_hash),
                },
            );
        writer.deregister_interface(5);
        writer.save_routing_state();
    }
    let saved = crate::persistence::load_python_tunnel_table(&dir.join("tunnels")).unwrap();
    assert!(
        saved
            .iter()
            .any(|tunnel| tunnel.tunnel_id == tunnel_id && tunnel.interface_hash.is_none()),
        "precondition: the canonical file holds an unbound tunnel"
    );

    let mut reader = hub();
    reader.handle_message(TransportMessage::SetStoragePaths {
        storage_dir: dir.clone(),
    });
    assert!(
        carries(&reader, &tunnel_id, &dest),
        "a nil-interface tunnel is valid Python state, not legacy"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn legacy_sidecar_tunnels_without_an_interface_survive_a_reload() {
    let dir = unique_temp_dir("sidecar-tunnel");
    let tunnel_id = [0x21; 32];
    let now = now_f64();
    let table = PersistedTunnelTable {
        entries: vec![PersistedTunnelEntry {
            tunnel_id: tunnel_id.to_vec(),
            interface_id: 3,
            expires: now + 600.0,
            paths: vec![PersistedTunnelPath {
                destination_hash: vec![0x31; 16],
                next_hop: None,
                hops: 1,
                expires: now + 600.0,
                timestamp: now,
                random_blobs: vec![vec![0x11; 10]],
                packet_hash: Some(vec![0x41; 32]),
            }],
            interface_name: None,
            interface_hash: None,
        }],
        version: PersistedTunnelTable::CURRENT_VERSION,
    };
    std::fs::write(
        dir.join("tunnel_table.msgpack"),
        rmp_serde::to_vec(&table).unwrap(),
    )
    .unwrap();

    let mut reader = hub();
    reader.handle_message(TransportMessage::SetStoragePaths {
        storage_dir: dir.clone(),
    });
    assert!(
        reader.tunnel_table.get(&tunnel_id).is_some(),
        "tunnels need no interface name to load"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn pending_paths_are_culled_once_they_expire() {
    let start = now_f64();
    let clock = crate::test_clock::Clock::at(start);
    let mut actor = hub();
    for (dest, expires) in [([0x21; 16], start + 10.0), ([0x22; 16], start + 1000.0)] {
        actor.pending_path_entries.push(PersistedPathEntry {
            destination_hash: dest.to_vec(),
            timestamp: start,
            next_hop: None,
            hops: 1,
            expires,
            random_blobs: Vec::new(),
            interface_id: 0,
            interface_name: Some("never-returns".into()),
            interface_hash: None,
            packet_hash: None,
        });
    }
    clock.set(start + 10.0 + TABLES_CULL_INTERVAL);
    actor.on_tick();
    let remaining: Vec<&[u8]> = actor
        .pending_path_entries
        .iter()
        .map(|entry| entry.destination_hash.as_slice())
        .collect();
    assert_eq!(
        remaining,
        vec![&[0x22; 16][..]],
        "only the expired pending path is dropped"
    );
}

fn named_hash(app: &str) -> [u8; 16] {
    rns_identity::destination::Destination::hash_from_name_and_identity(app, None)
}

fn data_packet(
    dest: [u8; 16],
    destination_type: DestinationType,
    hops: u8,
    context: PacketContext,
) -> Bytes {
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type,
            packet_type: PacketType::Data,
        },
        hops,
        transport_id: None,
        destination_hash: dest,
        context,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(b"filter payload");
    Bytes::from(raw)
}

fn local_destination(
    actor: &mut TransportActor,
    app: &str,
) -> ([u8; 16], mpsc::Receiver<DestinationEvent>) {
    let hash = named_hash(app);
    let (tx, rx) = mpsc::channel(8);
    actor.handle_message(TransportMessage::RegisterDestination {
        hash,
        app_name: app.to_string(),
        delivery_tx: Some(tx),
    });
    (hash, rx)
}

fn delivered(rx: &mut mpsc::Receiver<DestinationEvent>) -> bool {
    while let Ok(event) = rx.try_recv() {
        if matches!(event, DestinationEvent::InboundPacket { .. }) {
            return true;
        }
    }
    false
}

#[test]
fn plain_and_group_packets_beyond_one_hop_are_dropped_before_dedup() {
    for destination_type in [DestinationType::Plain, DestinationType::Group] {
        let mut actor = hub();
        let _rx = attach(&mut actor, 1, "radio");
        let (dest, mut deliveries) = local_destination(&mut actor, "filter.hops");
        inbound(
            &mut actor,
            data_packet(dest, destination_type, 2, PacketContext::None),
            1,
        );
        assert!(
            !delivered(&mut deliveries),
            "{destination_type:?} with two wire hops is dropped (Transport.py:1642-1667)"
        );
        inbound(
            &mut actor,
            data_packet(dest, destination_type, 0, PacketContext::None),
            1,
        );
        assert!(
            delivered(&mut deliveries),
            "{destination_type:?}: the dropped copy must not reserve its packet hash"
        );
    }
}

#[test]
fn one_hop_plain_and_group_packets_are_delivered() {
    for destination_type in [DestinationType::Plain, DestinationType::Group] {
        let mut actor = hub();
        let _rx = attach(&mut actor, 1, "radio");
        let (dest, mut deliveries) = local_destination(&mut actor, "filter.one");
        inbound(
            &mut actor,
            data_packet(dest, destination_type, 1, PacketContext::None),
            1,
        );
        assert!(delivered(&mut deliveries), "{destination_type:?}");
    }
}

#[test]
fn plain_and_group_typed_announces_are_dropped() {
    for destination_type in [DestinationType::Plain, DestinationType::Group] {
        let mut actor = hub();
        let _rx = attach(&mut actor, 1, "radio");
        let (announce, dest) = make_valid_announce("filter.announce", 0);
        let (mut header, offset) = PacketHeader::unpack(&announce).unwrap();
        header.flags.destination_type = destination_type;
        let mut retyped = header.pack();
        retyped.extend_from_slice(&announce[offset..]);
        inbound(&mut actor, Bytes::from(retyped), 1);
        assert!(
            !actor.path_table.has_path(&dest),
            "{destination_type:?}-typed announces are invalid (Transport.py:1650-1653, :1663-1666)"
        );
        assert!(!actor.recent_announces.contains_key(&dest));
    }
}

#[test]
fn exempt_contexts_bypass_the_plain_hop_filter() {
    let mut actor = hub();
    let _rx = attach(&mut actor, 1, "radio");
    let (dest, mut deliveries) = local_destination(&mut actor, "filter.exempt");
    for context in [
        PacketContext::Keepalive,
        PacketContext::Resource,
        PacketContext::Channel,
    ] {
        inbound(
            &mut actor,
            data_packet(dest, DestinationType::Plain, 3, context),
            1,
        );
        assert!(
            delivered(&mut deliveries),
            "{context:?} passes before the PLAIN rule (Transport.py:1635-1640)"
        );
    }
}

#[test]
fn shared_owner_ingress_bypasses_the_plain_hop_filter() {
    let (mut actor, _) = TransportActor::new();
    actor.is_shared_instance = true;
    let (mut entry, _rx) = make_test_interface("SharedInstanceClient");
    entry.role = InterfaceRole::SharedInstancePeer;
    actor.interfaces.insert(1, entry);
    let (dest, mut deliveries) = local_destination(&mut actor, "filter.shared");
    inbound(
        &mut actor,
        data_packet(dest, DestinationType::Plain, 2, PacketContext::None),
        1,
    );
    assert!(
        delivered(&mut deliveries),
        "the shared instance already filtered this packet (Transport.py:1627)"
    );
}
