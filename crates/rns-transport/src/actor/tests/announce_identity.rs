//! Python remembers the identity of every validated announce before it decides
//! whether the announce changes a path (Transport.py:2172, Identity.py:511-589):
//! a replay teaches the identity but leaves the path and the handlers alone.
use super::*;
use rns_wire::context::PacketContext;

fn hub() -> TransportActor {
    let (mut actor, _) = TransportActor::new();
    let (mut entry, _rx) = make_test_interface("identity");
    entry.ingress = crate::ingress::IngressController::disabled();
    actor.interfaces.insert(1, entry);
    actor
}

fn inbound(actor: &mut TransportActor, raw: &Bytes) {
    actor.on_inbound(crate::messages::InboundPacket {
        raw: raw.clone(),
        interface_id: 1,
        rssi: None,
        snr: None,
        q: None,
    });
}

fn recalled_key(actor: &mut TransportActor, dest: [u8; 16]) -> Option<[u8; 64]> {
    let TransportQueryResponse::RecalledDestination(entry) =
        actor.handle_query(TransportQuery::RecallDestination { dest })
    else {
        panic!("unexpected recall response");
    };
    entry.map(|entry| entry.public_key)
}

fn subscribe(actor: &mut TransportActor) -> mpsc::Receiver<crate::messages::AnnounceHandlerEvent> {
    let (tx, rx) = mpsc::channel(8);
    actor.announce_handlers.push(AnnounceHandlerRegistration {
        id: crate::messages::AnnounceHandlerId(7),
        ownership: AnnounceHandlerOwnership::Subscription,
        aspect_filter: None,
        receive_path_responses: true,
        tx,
        dropped_events: Arc::new(AtomicU64::new(0)),
    });
    rx
}

/// The same announce answered as a path response, as a transport hub replays
/// it from its cache.
fn as_path_response(announce: &Bytes) -> Bytes {
    let mut replay = announce.to_vec();
    replay[2 + 16] = PacketContext::PathResponse.to_byte();
    Bytes::from(replay)
}

/// A node that kept a path but not its identity learns the identity back from
/// the next replay, even through a handler registered after the original
/// arrived. The replay refreshes neither the path nor any handler.
#[test]
fn a_replayed_announce_still_teaches_its_identity() {
    let mut actor = hub();
    let identity = rns_identity::identity::Identity::new();
    let (announce, dest) =
        make_announce_for_context(&identity, "identity.replay", 1, PacketContext::None);
    inbound(&mut actor, &announce);
    let path = actor.path_table.get(&dest).cloned().expect("path learned");
    actor.recent_announces.remove(&dest);
    assert_eq!(recalled_key(&mut actor, dest), None);
    let mut events = subscribe(&mut actor);

    inbound(&mut actor, &as_path_response(&announce));

    assert_eq!(
        recalled_key(&mut actor, dest),
        Some(identity.get_public_key())
    );
    let replayed = actor.path_table.get(&dest).expect("path kept");
    assert_eq!(
        (replayed.timestamp, replayed.expires, &replayed.random_blobs),
        (path.timestamp, path.expires, &path.random_blobs),
        "a replay must not refresh the path"
    );
    assert!(events.try_recv().is_err(), "a replay reaches no handler");
}

/// Python's `Identity.remember` refreshes the remembered entry's time and
/// app data on every validated announce (Identity.py:108-113), which keeps a
/// pathless destination from being culled.
#[test]
fn a_replay_refreshes_the_remembered_identity() {
    let mut actor = hub();
    let identity = rns_identity::identity::Identity::new();
    let (announce, dest) =
        make_announce_for_context(&identity, "identity.refresh", 1, PacketContext::None);
    inbound(&mut actor, &announce);
    let remembered = actor.recent_announces.get_mut(&dest).unwrap();
    remembered.timestamp = 1.0;
    remembered.app_data = Some(b"older".to_vec());
    let (hops, packet_hash) = (remembered.hops, remembered.packet_hash);

    inbound(&mut actor, &as_path_response(&announce));

    let remembered = &actor.recent_announces[&dest];
    assert!(remembered.timestamp > 1.0);
    assert_eq!(remembered.app_data, None);
    assert_eq!(
        (remembered.hops, remembered.packet_hash),
        (hops, packet_hash)
    );
}
