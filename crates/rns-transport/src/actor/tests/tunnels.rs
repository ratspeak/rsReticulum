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

/// Closes an actor's stores; Windows will not delete a file they hold open.
fn stop(mut actor: TransportActor) {
    actor.on_shutdown();
}

fn cache_announce(dir: &std::path::Path, raw: &[u8], interface: Option<&str>) -> [u8; 32] {
    let packet_hash = rns_wire::hash::packet_hash(raw, HeaderType::Header1);
    crate::store::seed_cached_announce(dir, &packet_hash, raw, interface).unwrap();
    packet_hash
}

/// A hub-side child of a TCP listener, which Python lets take a synthesis.
fn attach_child(actor: &mut TransportActor, id: InterfaceId, name: &str) -> mpsc::Receiver<Bytes> {
    attach_class(actor, id, name, "TCPClientInterface")
}

fn attach_class(
    actor: &mut TransportActor,
    id: InterfaceId,
    name: &str,
    class: &str,
) -> mpsc::Receiver<Bytes> {
    let (mut entry, rx) = make_test_interface(name);
    entry.inspection = Some(InterfaceInspectionSource::identified(
        crate::messages::InterfaceIdentity::new(name, name, class),
    ));
    actor.interfaces.insert(id, entry);
    rx
}

/// A node whose wire identity can sign, with a control channel for detaches.
fn signing(
    mut actor: TransportActor,
) -> (
    TransportActor,
    Arc<Identity>,
    mpsc::UnboundedReceiver<crate::messages::InterfaceControl>,
) {
    let identity = Arc::new(Identity::new());
    actor.transport_identity_hash = Some(identity.hash);
    actor.handle_message(TransportMessage::SetTunnelIdentity {
        identity: identity.clone(),
    });
    let (tx, rx) = mpsc::unbounded_channel();
    actor.handle_message(TransportMessage::SetInterfaceControl { tx });
    (actor, identity, rx)
}

fn extended(identity: &Identity, interface: &str) -> (Bytes, [u8; 32]) {
    let ext = crate::tunnel::TunnelExt::local(true, 8.0, 4.5);
    let raw = crate::tunnel::build_tunnel_synthesis_packet_with_ext(
        identity,
        crate::tunnel::interface_hash(interface),
        &ext,
    )
    .unwrap();
    let tunnel_id = TunnelSynthesisData::unpack(&raw[rns_wire::constants::HEADER_MINSIZE..])
        .unwrap()
        .tunnel_id();
    (Bytes::from(raw), tunnel_id)
}

/// A PLAIN broadcast to `rnstransport.tunnel.synthesize` carrying `payload`.
fn synthesis_packet(payload: &[u8]) -> Bytes {
    let mut raw = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Plain,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: named_hash("rnstransport.tunnel.synthesize"),
        context: PacketContext::None,
    }
    .pack();
    raw.extend_from_slice(payload);
    Bytes::from(raw)
}

/// The synthesis in a frame the actor sent, if it is one.
fn sent_synthesis(frame: &[u8]) -> Option<TunnelSynthesisData> {
    let (header, offset) = PacketHeader::unpack(frame).ok()?;
    (header.destination_hash == named_hash("rnstransport.tunnel.synthesize"))
        .then(|| TunnelSynthesisData::unpack(&frame[offset..]))
        .flatten()
}

fn violations(actor: &TransportActor, id: InterfaceId) -> u64 {
    actor.interfaces[&id].protocol_violations
}

#[test]
fn valid_synthesis_installs_a_tunnel_that_collects_announces() {
    let mut actor = hub();
    let _rx = attach_child(&mut actor, 1, "hub/client_1");
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

/// Python 1.6.1 runs the handler on its own verdict table; each case is
/// signed here and must hash to Python's payload (Transport.py:3208-3297).
#[test]
fn the_handler_reaches_python_verdicts() {
    use crate::tunnel::python_vectors::{HANDLER_CASES, identity, payload};
    for (name, verdict, ext, digest) in HANDLER_CASES {
        let data = payload(name, ext);
        assert_eq!(
            hex::encode(rns_crypto::sha::sha256(&data)),
            *digest,
            "{name}: signed as Python signs it"
        );
        let (mut actor, _, mut control) = signing(hub());
        let mut rx = attach_child(&mut actor, 1, "hub/client_1");
        inbound(&mut actor, synthesis_packet(&data), 1);

        let tunnel_id = TunnelSynthesisData::unpack(&data[..176])
            .unwrap()
            .tunnel_id();
        let mut outcome = Vec::new();
        if rx
            .try_recv()
            .ok()
            .as_deref()
            .and_then(sent_synthesis)
            .is_some()
        {
            outcome.push("reply");
        }
        if actor.tunnel_table.get(&tunnel_id).is_some() {
            outcome.push("tunnel");
        }
        if control.try_recv().is_ok() {
            outcome.push("detach");
        }
        if actor
            .interfaces
            .get(&1)
            .is_some_and(|entry| entry.protocol_violations > 0)
        {
            outcome.push("violation");
        }
        if actor
            .interfaces
            .get(&1)
            .is_some_and(|entry| entry.tunnel.remote_transport == Some(identity().hash))
        {
            outcome.push("remote");
        }
        let expected = match *name {
            // Lead decision: costs may be ints.
            "cost_int" => "reply,tunnel,remote",
            _ => verdict,
        };
        assert_eq!(outcome.join(","), expected, "{name}");
    }
}

/// UDP, RNode, serial, KISS, pipe, AX.25, Auto and local interfaces never
/// take a synthesis (Transport.py:3211-3212).
#[test]
fn an_interface_without_tunnels_ignores_a_synthesis() {
    let mut actor = hub();
    let _rx = attach_class(&mut actor, 1, "udp", "UDPInterface");
    let (raw, tunnel_id) = extended(&Identity::new(), "uplink");
    inbound(&mut actor, raw, 1);
    assert!(actor.tunnel_table.get(&tunnel_id).is_none());
    assert_eq!(violations(&actor, 1), 0, "ignored silently");
    assert!(actor.interfaces[&1].tunnel.remote_transport.is_none());
}

/// One synthesis per connection: a second is a violation whether or not the
/// first established a tunnel, and a malformed first one uses up the chance.
#[test]
fn a_connection_takes_one_synthesis() {
    let mut actor = hub();
    let _rx: Vec<_> = (1..=2)
        .map(|id| attach_child(&mut actor, id, &format!("hub/client_{id}")))
        .collect();
    let (first, first_id) = synthesis(&Identity::new(), "uplink");
    let (second, second_id) = synthesis(&Identity::new(), "uplink");
    inbound(&mut actor, first, 1);
    inbound(&mut actor, second, 1);
    assert!(actor.tunnel_table.get(&first_id).is_some());
    assert!(actor.tunnel_table.get(&second_id).is_none());
    assert_eq!(violations(&actor, 1), 1, "already established");

    inbound(&mut actor, synthesis_packet(&[0; 175]), 2);
    assert_eq!(violations(&actor, 2), 1, "undersize");
    let (valid, valid_id) = synthesis(&Identity::new(), "uplink-b");
    inbound(&mut actor, valid, 2);
    assert_eq!(violations(&actor, 2), 2, "the chance is spent");
    assert!(actor.tunnel_table.get(&valid_id).is_none());
}

/// A bad signature tears the interface down (Transport.py:3245-3248); with no
/// one to ask, the actor drops it itself.
#[test]
fn a_bad_signature_tears_the_interface_down() {
    let (mut actor, _, mut control) = signing(hub());
    let _rx = attach_child(&mut actor, 1, "hub/client_1");
    let (raw, tunnel_id) = extended(&Identity::new(), "uplink");
    let mut tampered = raw.to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;
    inbound(&mut actor, Bytes::from(tampered), 1);
    assert_eq!(
        control.try_recv().unwrap(),
        crate::messages::InterfaceControl::Detach {
            interface_id: 1,
            reason: crate::messages::DetachReason::InvalidSynthesis,
        }
    );
    assert!(actor.tunnel_table.get(&tunnel_id).is_none());

    let (announce, dest) = make_valid_announce("tunnel.detaching", 0);
    inbound(&mut actor, announce, 1);
    assert!(
        !actor.path_table.has_path(&dest),
        "frames from a detaching interface are dropped"
    );
    actor.deregister_interface(1);
    assert!(!actor.is_detaching(1));

    let mut alone = hub();
    let _rx = attach_child(&mut alone, 2, "hub/client_2");
    let (raw, _) = synthesis(&Identity::new(), "uplink");
    let mut tampered = raw.to_vec();
    tampered[rns_wire::constants::HEADER_MINSIZE + 120] ^= 0x01;
    inbound(&mut alone, Bytes::from(tampered), 2);
    assert!(!alone.interfaces.contains_key(&2));
}

/// A blackholed transport node is torn down at its synthesis, and when it is
/// blackholed later (Transport.py:3249-3252, :4832-4839).
#[test]
fn a_blackholed_tunnel_peer_is_torn_down() {
    let (mut actor, _, mut control) = signing(hub());
    let _rx: Vec<_> = (1..=3)
        .map(|id| attach_child(&mut actor, id, &format!("hub/client_{id}")))
        .collect();
    let blackholed = Identity::new();
    actor.blackhole_table.add(blackholed.hash, None);
    let (raw, tunnel_id) = extended(&blackholed, "uplink");
    inbound(&mut actor, raw, 1);
    assert_eq!(
        control.try_recv().unwrap(),
        crate::messages::InterfaceControl::Detach {
            interface_id: 1,
            reason: crate::messages::DetachReason::BlackholedTransport,
        }
    );
    assert!(actor.tunnel_table.get(&tunnel_id).is_none());

    let (later, other) = (Identity::new(), Identity::new());
    inbound(&mut actor, extended(&later, "uplink-2").0, 2);
    inbound(&mut actor, extended(&other, "uplink-3").0, 3);
    assert!(control.try_recv().is_err());
    actor.handle_query(crate::messages::TransportQuery::BlackholeIdentity {
        hash: later.hash,
        ttl: None,
        reason: crate::blackhole::BlackholeReason::Manual,
        reason_label: None,
    });
    assert_eq!(
        control.try_recv().unwrap(),
        crate::messages::InterfaceControl::Detach {
            interface_id: 2,
            reason: crate::messages::DetachReason::BlackholedTransport,
        }
    );
    assert!(control.try_recv().is_err(), "only the blackholed peer");
}

/// A receiver answers an extended synthesis once, signed with its own wire
/// identity and with its own costs; a legacy synthesis gets no answer
/// (Transport.py:3286).
#[test]
fn a_receiver_answers_an_extended_synthesis_once() {
    let (mut actor, hub_identity, _control) = signing(hub());
    let mut rx = attach_child(&mut actor, 1, "hub/client_1");
    actor.interfaces.get_mut(&1).unwrap().destination_cost = Some(12.0);
    let client = Identity::new();
    let (raw, tunnel_id) = extended(&client, "uplink");
    inbound(&mut actor, raw, 1);
    let reply = sent_synthesis(&rx.try_recv().unwrap()).expect("a reverse synthesis");
    assert!(reply.is_signed());
    assert_eq!(reply.transport_identity_hash(), hub_identity.hash);
    assert_eq!(
        reply.interface_hash,
        crate::tunnel::interface_hash("hub/client_1")
    );
    let info = crate::tunnel::RemoteTransportInfo::decode(&reply.ext).unwrap();
    assert_eq!(info.implementation, "rsRNS");
    assert!(info.transport);
    assert_eq!(info.destination_cost, 12.0);
    assert_eq!(
        info.pr_cost,
        rns_identity::stamps::quantize_cost(15.8).unwrap()
    );
    assert!(actor.tunnel_table.get(&tunnel_id).is_some());
    assert!(rx.try_recv().is_err(), "answered once");

    let stats = interface_stats(&mut actor, 1);
    assert_eq!(stats.tunnel_id, Some(tunnel_id));
    assert_eq!(stats.remote_transport_id, Some(client.hash));
    let remote = stats.remote_transport.expect("the client's extension");
    assert_eq!(
        (remote.implementation.as_str(), remote.version.clone()),
        (
            "rsRNS",
            crate::discovery::constants::IMPLEMENTATION_VERSION
                .split('.')
                .map(|part| part.parse().unwrap())
                .collect::<Vec<u64>>()
        )
    );
    assert_eq!((remote.destination_cost, remote.pr_cost), (8.0, 4.5));

    let mut legacy_rx = attach_child(&mut actor, 2, "hub/client_2");
    inbound(&mut actor, synthesis(&Identity::new(), "uplink").0, 2);
    assert!(
        legacy_rx.try_recv().is_err(),
        "no answer to the legacy form"
    );
    let legacy = interface_stats(&mut actor, 2);
    assert!(legacy.remote_transport_id.is_some() && legacy.remote_transport.is_none());
}

/// An initiator sends the extended form, names its tunnel, records the hub's
/// answer without binding a tunnel or answering back, and forgets the hub on
/// its next connection (Transport.py:3205, :3290-3292).
#[test]
fn an_initiator_records_its_hub_without_binding_a_tunnel() {
    let (mut actor, client_identity, _control) = signing(hub());
    let name = "TCPInterface[Uplink/127.0.0.1:4242]";
    let mut rx = attach_class(&mut actor, 1, name, "TCPClientInterface");
    actor.interfaces.get_mut(&1).unwrap().online =
        Some(Arc::new(std::sync::atomic::AtomicBool::new(false)));
    actor.handle_message(TransportMessage::SynthesizeTunnel { interface_id: 1 });
    let sent = sent_synthesis(&rx.try_recv().unwrap())
        .expect("queued before the interface reports online");
    assert!(sent.is_signed());
    assert_eq!(sent.transport_identity_hash(), client_identity.hash);
    assert_eq!(sent.interface_hash, crate::tunnel::interface_hash(name));
    let info = crate::tunnel::RemoteTransportInfo::decode(&sent.ext).unwrap();
    assert_eq!(
        (info.destination_cost, info.pr_cost),
        (23.5, rns_identity::stamps::quantize_cost(15.8).unwrap())
    );
    assert_eq!(
        interface_stats(&mut actor, 1).tunnel_id,
        Some(sent.tunnel_id())
    );

    let hub_identity = Identity::new();
    let (reply, reply_tunnel) =
        extended(&hub_identity, "TCPInterface[Client on Hub/10.0.0.1:5000]");
    inbound(&mut actor, reply, 1);
    assert!(rx.try_recv().is_err(), "an initiator never answers");
    assert!(actor.tunnel_table.get(&reply_tunnel).is_none());
    assert!(actor.tunnel_table.is_empty());
    let stats = interface_stats(&mut actor, 1);
    assert_eq!(stats.remote_transport_id, Some(hub_identity.hash));
    assert_eq!(stats.tunnel_id, Some(sent.tunnel_id()));

    actor.handle_message(TransportMessage::SynthesizeTunnel { interface_id: 1 });
    assert!(
        rx.try_recv()
            .ok()
            .as_deref()
            .and_then(sent_synthesis)
            .is_some()
    );
    assert!(interface_stats(&mut actor, 1).remote_transport_id.is_none());
    let (again, _) = extended(&hub_identity, "TCPInterface[Client on Hub/10.0.0.1:5001]");
    inbound(&mut actor, again, 1);
    assert_eq!(
        violations(&actor, 1),
        0,
        "a new connection takes a new answer"
    );
    assert_eq!(
        interface_stats(&mut actor, 1).remote_transport_id,
        Some(hub_identity.hash)
    );
}

/// Python skips a synthesis without `Transport.identity`; the actor also
/// refuses to sign with an identity that is not its visible one.
#[test]
fn no_synthesis_without_the_wire_identity() {
    let mut actor = hub();
    let mut rx = attach_child(&mut actor, 1, "uplink");
    actor.handle_message(TransportMessage::SynthesizeTunnel { interface_id: 1 });
    assert!(rx.try_recv().is_err());
    actor.handle_message(TransportMessage::SetTunnelIdentity {
        identity: Arc::new(Identity::new()),
    });
    actor.handle_message(TransportMessage::SynthesizeTunnel { interface_id: 1 });
    assert!(rx.try_recv().is_err(), "its hash is not the transport hash");
}

fn interface_stats(
    actor: &mut TransportActor,
    id: InterfaceId,
) -> crate::messages::InterfaceStatRpcEntry {
    let crate::messages::TransportQueryResponse::InterfaceStats(entries) =
        actor.handle_query(crate::messages::TransportQuery::GetInterfaceStats)
    else {
        panic!("unexpected interface stats response");
    };
    entries.into_iter().find(|entry| entry.id == id).unwrap()
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
        role: crate::actor::StorageRole::Owner,
        done: None,
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
    stop(reader);
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
                    used: 0.0,
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
        role: crate::actor::StorageRole::Owner,
        done: None,
    });
    assert!(
        carries(&reader, &tunnel_id, &dest),
        "a nil-interface tunnel is valid Python state, not legacy"
    );
    stop(reader);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Python 1.6.1 caps a loaded tunnel's expiry at the reconnect window
/// (Transport.py:636-637).
#[test]
fn loaded_tunnels_expire_within_the_reconnect_window() {
    let dir = unique_temp_dir("tunnel-reconnect-window");
    let now = now_f64();
    let window = crate::constants::TUNNEL_RECONNECT_WINDOW as f64;
    let path = |dest: u8| PersistedTunnelPath {
        used: None,
        destination_hash: vec![dest; 16],
        next_hop: None,
        hops: 1,
        expires: now + 600.0,
        timestamp: now,
        random_blobs: vec![vec![0x11; 10]],
        packet_hash: Some(vec![0x41; 32]),
    };
    let entry = |tunnel: u8, expires: f64| PersistedTunnelEntry {
        tunnel_id: vec![tunnel; 32],
        interface_id: 3,
        expires,
        paths: vec![path(tunnel)],
        interface_name: None,
        interface_hash: None,
    };
    let table = PersistedTunnelTable {
        entries: vec![
            entry(0x01, now + crate::constants::TUNNEL_TIMEOUT as f64),
            entry(0x02, now + 120.0),
        ],
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
        role: crate::actor::StorageRole::Owner,
        done: None,
    });
    let long = reader.tunnel_table.get(&[0x01; 32]).unwrap().expires;
    assert!(
        long <= now_f64() + window && long > now + window - 5.0,
        "an eight-hour expiry loads capped at the window: {}",
        long - now
    );
    assert_eq!(
        reader.tunnel_table.get(&[0x02; 32]).unwrap().expires,
        now + 120.0,
        "a sooner expiry is kept"
    );
    stop(reader);
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
                used: None,
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
        role: crate::actor::StorageRole::Owner,
        done: None,
    });
    assert!(
        reader.tunnel_table.get(&tunnel_id).is_some(),
        "tunnels need no interface name to load"
    );
    stop(reader);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn pending_paths_are_culled_once_they_expire() {
    let start = now_f64();
    let clock = crate::test_clock::Clock::at(start);
    let mut actor = hub();
    for (dest, expires) in [([0x21; 16], start + 10.0), ([0x22; 16], start + 1000.0)] {
        actor.pending_path_entries.push(PersistedPathEntry {
            used: None,
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

/// The answer leaves through transport, so it carries the interface's IFAC
/// (Transport.py `packet.send()`).
#[test]
fn a_reverse_synthesis_carries_ifac() {
    let (mut actor, _, _control) = signing(hub());
    let mut rx = attach_child(&mut actor, 1, "hub/client_1");
    let key = rns_identity::ifac::IfacKey::derive(Some("tunnels"), Some("ifac")).unwrap();
    let entry = actor.interfaces.get_mut(&1).unwrap();
    entry.ifac_key = Some(key.clone());
    entry.ifac_size = 16;
    let (raw, tunnel_id) = extended(&Identity::new(), "uplink");
    let masked = crate::ifac::try_ifac_sign(&raw, &key, 16).unwrap();
    inbound(&mut actor, Bytes::from(masked), 1);
    assert!(actor.tunnel_table.get(&tunnel_id).is_some());
    let reply = rx.try_recv().unwrap();
    let clear = crate::ifac::ifac_verify(&reply, &key, 16).expect("IFAC-valid");
    assert!(sent_synthesis(&clear).is_some_and(|synthesis| synthesis.is_signed()));
}
