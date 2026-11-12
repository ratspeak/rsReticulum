//! Python remembers the identity of every validated announce before it decides
//! whether the announce changes a path (Transport.py, Identity.py):
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
        paused: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
/// app data on every validated announce (Identity.py), which keeps a
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

/// A paused handler is skipped (Transport.py) while the announce
/// still updates the path table; resuming takes effect for the next announce.
#[test]
fn a_paused_handler_skips_announces_but_paths_are_learned() {
    let mut actor = hub();
    let mut events = subscribe(&mut actor);
    let paused = Arc::clone(&actor.announce_handlers[0].paused);
    paused.store(true, std::sync::atomic::Ordering::Relaxed);
    let (first, first_dest) = make_announce_for_context(
        &rns_identity::identity::Identity::new(),
        "handler.pause",
        1,
        PacketContext::None,
    );
    inbound(&mut actor, &first);
    assert!(events.try_recv().is_err());
    assert!(actor.path_table.get(&first_dest).is_some());

    paused.store(false, std::sync::atomic::Ordering::Relaxed);
    let (second, second_dest) = make_announce_for_context(
        &rns_identity::identity::Identity::new(),
        "handler.pause",
        1,
        PacketContext::None,
    );
    inbound(&mut actor, &second);
    assert_eq!(events.try_recv().unwrap().destination_hash, second_dest);
}

fn announce_at(
    identity: &rns_identity::identity::Identity,
    app_name: &str,
    ratchet: Option<&[u8; 32]>,
    wire_time: u64,
) -> (Bytes, [u8; 16]) {
    let data = rns_identity::announce::AnnounceData::create_at(
        identity, app_name, None, ratchet, wire_time,
    )
    .unwrap();
    let dest = rns_identity::destination::Destination::hash_from_name_and_identity(
        app_name,
        Some(&identity.hash),
    );
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: ratchet.is_some(),
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        },
        hops: 1,
        transport_id: None,
        destination_hash: dest,
        context: PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(&data.pack());
    (Bytes::from(raw), dest)
}

/// Python remembers a ratchet only from an announce that carries one
/// (Identity.py), so a newer ratchet-less announce keeps the old ratchet.
#[test]
fn a_ratchetless_announce_keeps_the_remembered_ratchet() {
    let mut actor = hub();
    let identity = rns_identity::identity::Identity::new();
    let now = crate::now_f64() as u64;
    let ratchet = [0x5A; 32];
    let (first, dest) = announce_at(&identity, "ratchet.keep", Some(&ratchet), now - 10);
    inbound(&mut actor, &first);
    assert_eq!(actor.recent_announces[&dest].ratchet, Some(ratchet));

    let (second, _) = announce_at(&identity, "ratchet.keep", None, now);
    inbound(&mut actor, &second);

    assert_eq!(
        actor.recent_announces[&dest].packet_hash,
        Some(rns_wire::hash::packet_hash(
            &second,
            rns_wire::flags::HeaderType::Header1
        )),
        "the second announce updated the path"
    );
    assert_eq!(actor.recent_announces[&dest].ratchet, Some(ratchet));
}

fn recalled_ratchet(actor: &mut TransportActor, dest: [u8; 16]) -> Option<[u8; 32]> {
    let TransportQueryResponse::RecalledDestination(entry) =
        actor.handle_query(TransportQuery::RecallDestination { dest })
    else {
        panic!("unexpected recall response");
    };
    entry.and_then(|entry| entry.ratchet)
}

/// Identity.clean_known_destinations expires remembered ratchets older than
/// RATCHET_EXPIRY (Identity.py) and get_ratchet refuses them
/// (Identity.py); the destination itself is kept.
#[test]
fn remembered_ratchets_expire_after_thirty_days() {
    let mut actor = hub();
    let identity = rns_identity::identity::Identity::new();
    let now = crate::now_f64();
    let ratchet = [0x33; 32];
    let (announce, dest) = announce_at(&identity, "ratchet.expiry", Some(&ratchet), now as u64);
    inbound(&mut actor, &announce);
    let entry = actor.recent_announces.get_mut(&dest).unwrap();
    entry.retained = true;

    entry.ratchet_received = Some(now - 29.0 * 86_400.0);
    assert_eq!(recalled_ratchet(&mut actor, dest), Some(ratchet));
    actor.cleanup_known_destinations(now);
    assert_eq!(actor.recent_announces[&dest].ratchet, Some(ratchet));

    actor
        .recent_announces
        .get_mut(&dest)
        .unwrap()
        .ratchet_received = Some(now - 31.0 * 86_400.0);
    assert_eq!(recalled_ratchet(&mut actor, dest), None);
    actor.cleanup_known_destinations(now);
    assert!(actor.recent_announces.contains_key(&dest));
    assert_eq!(actor.recent_announces[&dest].ratchet, None);
    assert_eq!(
        recalled_key(&mut actor, dest),
        Some(identity.get_public_key())
    );
}

/// Re-receiving the same ratchet does not restart its expiry (Identity.py).
#[test]
fn a_repeated_ratchet_keeps_its_first_receive_time() {
    let mut actor = hub();
    let identity = rns_identity::identity::Identity::new();
    let now = crate::now_f64() as u64;
    let ratchet = [0x44; 32];
    let (first, dest) = announce_at(&identity, "ratchet.repeat", Some(&ratchet), now - 10);
    inbound(&mut actor, &first);
    actor
        .recent_announces
        .get_mut(&dest)
        .unwrap()
        .ratchet_received = Some(1000.0);
    let (second, _) = announce_at(&identity, "ratchet.repeat", Some(&ratchet), now);
    inbound(&mut actor, &second);
    assert_eq!(actor.recent_announces[&dest].ratchet_received, Some(1000.0));
}
