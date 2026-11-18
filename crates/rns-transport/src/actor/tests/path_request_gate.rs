//! The path-request in-flight gate (Transport.py `inflight_path_requests`):
//! a request that leaves nothing pending releases it.
use super::*;
use rns_wire::header::PacketHeader;

fn relay() -> TransportActor {
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    actor.transport_identity_hash = Some([0x44; 16]);
    actor
}

fn network(
    actor: &mut TransportActor,
    id: InterfaceId,
    mode: InterfaceMode,
) -> mpsc::Receiver<Bytes> {
    let (mut entry, rx) = make_test_interface(&format!("if{id}"));
    entry.mode = mode;
    entry.ingress = crate::ingress::IngressController::disabled();
    actor.interfaces.insert(id, entry);
    rx
}

fn request(actor: &mut TransportActor, dest: [u8; 16], tag: u8, interface: InterfaceId) {
    actor.handle_inbound_path_request(
        &make_path_request_payload_with_tag(dest, None, [tag; 16]),
        interface,
    );
}

fn pr_dest() -> [u8; 16] {
    rns_identity::destination::Destination::hash_from_name_and_identity(
        "rnstransport.path.request",
        None,
    )
}

/// Drains `rx`; whether it carried a path request for `dest`.
fn requested(rx: &mut mpsc::Receiver<Bytes>, dest: [u8; 16]) -> bool {
    let mut seen = false;
    while let Ok(raw) = rx.try_recv() {
        let (header, offset) = PacketHeader::unpack(&raw).unwrap();
        seen |= header.destination_hash == pr_dest() && raw[offset..offset + 16] == dest;
    }
    seen
}

/// Drains `rx`; whether it carried a path response for `dest`.
fn answered(rx: &mut mpsc::Receiver<Bytes>, dest: [u8; 16]) -> bool {
    let mut seen = false;
    while let Ok(raw) = rx.try_recv() {
        let (header, _) = PacketHeader::unpack(&raw).unwrap();
        seen |= header.destination_hash == dest
            && header.context == rns_wire::context::PacketContext::PathResponse;
    }
    seen
}

/// A live path via interface 2, its cached announce edited by `cached`;
/// returns the destination and the announce as received.
fn known_path(
    actor: &mut TransportActor,
    tag: &str,
    cached: impl FnOnce(&mut Vec<u8>),
) -> ([u8; 16], Vec<u8>) {
    let dir = unique_temp_dir(tag);
    actor.storage_dir = Some(dir.clone());
    actor.kd.attach_storage(&dir);
    let (raw, dest) = make_valid_announce(&format!("test.pr_gate.{tag}"), 1);
    let mut stored = raw.to_vec();
    cached(&mut stored);
    crate::store::seed_cached_announce(&dir, &cache_key(&raw), &stored, None).unwrap();
    let mut path = PathEntry::new(Some([0xAB; 16]), 2, 2, InterfaceMode::Full);
    path.packet_hash = Some(cache_key(&raw));
    actor.path_table.insert(dest, path);
    (dest, raw.to_vec())
}

fn cache_key(raw: &[u8]) -> [u8; 32] {
    rns_wire::hash::packet_hash(raw, rns_wire::flags::HeaderType::Header1)
}

/// Transport.py:4178-4179@1.6.1 ignores a request for an unknown
/// destination on an interface that does not search, leaving it in flight
/// (:2242-2243), so a gateway requester was batched instead of searched for.
#[test]
fn an_ignored_request_releases_the_gate() {
    let mut actor = relay();
    let _full = network(&mut actor, 1, InterfaceMode::Full);
    let _gateway = network(&mut actor, 2, InterfaceMode::Gateway);
    let mut other = network(&mut actor, 3, InterfaceMode::Full);
    let dest = [0x51; 16];
    request(&mut actor, dest, 1, 1);
    assert!(
        !requested(&mut other, dest),
        "a Full interface does not search"
    );
    request(&mut actor, dest, 2, 2);
    assert!(requested(&mut other, dest), "a gateway requester searches");
    assert!(
        actor.inflight_path_requests.contains_key(&dest),
        "searching"
    );
}

/// Transport.py:4120-4123@1.6.1 aborts the search of an ingress-limited
/// request and leaves it in flight.
#[test]
fn an_ingress_limited_abort_releases_the_gate() {
    let mut actor = relay();
    let _limited = network(&mut actor, 1, InterfaceMode::Gateway);
    actor.interfaces.get_mut(&1).unwrap().ingress = crate::ingress::IngressController::new();
    prime_ingress_pr_burst(&mut actor, 1);
    let _gateway = network(&mut actor, 2, InterfaceMode::Gateway);
    let mut other = network(&mut actor, 3, InterfaceMode::Full);
    let dest = [0x52; 16];
    request(&mut actor, dest, 1, 1);
    drain_ingress_limited(&mut actor);
    assert!(
        !requested(&mut other, dest),
        "a limited request does not search"
    );
    request(&mut actor, dest, 2, 2);
    assert!(requested(&mut other, dest), "a gateway requester searches");
}

/// A requester that cannot be admitted starts no search (RNS-D0133 (2)), so
/// nothing is pending.
#[test]
fn an_unadmitted_requester_releases_the_gate() {
    let mut actor = relay();
    let _inbound_only = network(&mut actor, 1, InterfaceMode::Gateway);
    actor.interfaces.get_mut(&1).unwrap().direction.outbound = false;
    let _gateway = network(&mut actor, 2, InterfaceMode::Gateway);
    let mut other = network(&mut actor, 3, InterfaceMode::Full);
    let dest = [0x53; 16];
    request(&mut actor, dest, 1, 1);
    assert!(!requested(&mut other, dest));
    request(&mut actor, dest, 2, 2);
    assert!(requested(&mut other, dest), "a gateway requester searches");
}

/// Transport.py:4038@1.6.1 returns before the pop when the cached announce
/// does not unpack, so a repaired cache went unused while the gate held.
#[test]
fn an_unreadable_cached_announce_releases_the_gate() {
    let mut actor = relay();
    let mut requester = network(&mut actor, 1, InterfaceMode::Gateway);
    let _route = network(&mut actor, 2, InterfaceMode::Full);
    let (dest, raw) = known_path(&mut actor, "unreadable", |raw| raw[1] = PATHFINDER_M);
    for tag in [1, 2] {
        request(&mut actor, dest, tag, 1);
        assert!(actor.announce_table.get(&dest).is_none());
    }
    let dir = actor.storage_dir.clone().unwrap();
    crate::store::seed_cached_announce(&dir, &cache_key(&raw), &raw, None).unwrap();
    request(&mut actor, dest, 3, 1);
    actor.flush_pending_announces();
    assert!(answered(&mut requester, dest), "answered once readable");
    assert!(!actor.discovery_path_requests.contains_key(&dest));
    let _ = std::fs::remove_dir_all(dir);
}
