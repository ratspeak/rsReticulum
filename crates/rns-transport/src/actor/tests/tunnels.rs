//! Tunnel binding, persistence and cache replay through the production actor
//! paths.
use super::*;
use crate::tunnel::handle_tunnel;
use rns_wire::flags::HeaderType;

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
fn an_unbound_tunnel_persists_without_an_interface_hash() {
    let dir = unique_temp_dir("wp4-unbound-tunnel");
    let mut actor = hub();
    actor.storage_dir = Some(dir.clone());
    // Id 0 used to be both the shared-instance listener and "unbound".
    let _listener_rx = attach(&mut actor, 0, "SharedInstanceServer");
    let _client_rx = attach(&mut actor, 7, "hub/client_7");
    let tunnel_id = [0x55; 32];
    handle_tunnel(&mut actor.tunnel_table, tunnel_id, 7, TUNNEL_TIMEOUT as f64);
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
    let dir = unique_temp_dir("wp4-cache-replay-interface");
    let mut actor = hub();
    actor.storage_dir = Some(dir.clone());
    let _rx = attach(&mut actor, 3, "radio");
    let (announce, dest) = make_valid_announce("wp4.cache.interface", 1);
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
fn a_cache_request_replay_adds_no_tunnel_path() {
    let dir = unique_temp_dir("wp4-cache-replay-tunnel");
    let mut actor = hub();
    actor.storage_dir = Some(dir.clone());
    let _rx = attach(&mut actor, 1, "hub/client_1");
    let tunnel_id = [0x44; 32];
    handle_tunnel(&mut actor.tunnel_table, tunnel_id, 1, TUNNEL_TIMEOUT as f64);
    actor.deregister_interface(1);

    let (announce, dest) = make_valid_announce("wp4.cache.tunnel", 1);
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
