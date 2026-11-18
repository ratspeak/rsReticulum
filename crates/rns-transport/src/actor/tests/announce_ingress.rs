//! Python 1.6.1 announce ingress (Transport.py `preprocess_inbound`): the size
//! gates, the type filters, the prefilter that drops announces which cannot
//! update a known path before their signature is checked, the filtered count
//! `afrxc`, and the accounting of held announces (Interface.py).
//!
//! Expected prefilter verdicts were checked against upstream 1.6.1
//! `Transport.announce_prefilter`, called directly on stand-in packets and
//! path entries (older False, newer True, same emission False, higher
//! gravity True, unresponsive True, path interface `None` True).
use super::*;
use crate::announce_validation::CachedAnnounce;
use crate::ingress::{HeldAnnounce, IngressController, IngressOverrides};
use rns_wire::context::PacketContext;

const NOW: f64 = 1_800_000_000.0;
const APP: &str = "prefilter.test";

struct Node {
    actor: TransportActor,
    _rx: Vec<mpsc::Receiver<Bytes>>,
}

fn node(transport: bool) -> Node {
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = transport;
    actor.transport_identity_hash = Some([0x42; 16]);
    let mut receivers = Vec::new();
    for id in [1, 2] {
        let (mut entry, rx) = make_test_interface(&format!("prefilter_{id}"));
        entry.ingress = IngressController::disabled();
        actor.interfaces.insert(id, entry);
        receivers.push(rx);
    }
    Node {
        actor,
        _rx: receivers,
    }
}

struct Announce {
    raw: Bytes,
    destination: [u8; 16],
}

/// A signed announce emitted at `emitted` (Unix seconds).
fn signed(
    identity: &rns_identity::identity::Identity,
    emitted: u64,
    hops: u8,
    context: PacketContext,
    app_data: &[u8],
    transport_id: Option<[u8; 16]>,
) -> Announce {
    let app_data = (!app_data.is_empty()).then_some(app_data);
    let data =
        rns_identity::announce::AnnounceData::create_at(identity, APP, app_data, None, emitted)
            .unwrap();
    let destination = rns_identity::destination::Destination::hash_from_name_and_identity(
        APP,
        Some(&identity.hash),
    );
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: if transport_id.is_some() {
                rns_wire::flags::HeaderType::Header2
            } else {
                rns_wire::flags::HeaderType::Header1
            },
            context_flag: false,
            transport_type: if transport_id.is_some() {
                rns_wire::flags::TransportType::Transport
            } else {
                rns_wire::flags::TransportType::Broadcast
            },
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        },
        hops,
        transport_id,
        destination_hash: destination,
        context,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(&data.pack());
    Announce {
        raw: Bytes::from(raw),
        destination,
    }
}

fn plain(identity: &rns_identity::identity::Identity, emitted: u64) -> Announce {
    signed(identity, emitted, 1, PacketContext::None, &[], None)
}

fn inbound(actor: &mut TransportActor, raw: &Bytes, interface_id: InterfaceId) {
    actor.on_inbound(InboundPacket {
        raw: raw.clone(),
        interface_id,
        rssi: None,
        snr: None,
        q: None,
    });
}

fn stats(actor: &mut TransportActor, id: InterfaceId) -> crate::messages::InterfaceStatRpcEntry {
    let TransportQueryResponse::InterfaceStats(entries) =
        actor.handle_query(TransportQuery::GetInterfaceStats)
    else {
        panic!("unexpected interface stats response");
    };
    entries
        .into_iter()
        .find(|entry| entry.id == id)
        .expect("interface is listed")
}

fn totals(actor: &mut TransportActor) -> crate::messages::TrafficTotalsRpcEntry {
    let TransportQueryResponse::TrafficTotals(totals) =
        actor.handle_query(TransportQuery::GetTrafficTotals)
    else {
        panic!("unexpected traffic totals response");
    };
    totals
}

fn hash(raw: &Bytes) -> [u8; 32] {
    let (header, _) = rns_wire::header::PacketHeader::unpack(raw).unwrap();
    rns_wire::hash::packet_hash(raw, header.flags.header_type)
}

/// `(arxc, arxb, afrxc)` on an interface.
fn counts(actor: &mut TransportActor, id: InterfaceId) -> (u64, u64, u64) {
    let entry = stats(actor, id);
    (
        entry.announces_received,
        entry.announce_rx_bytes,
        entry.announces_filtered,
    )
}

#[test]
fn an_older_copy_of_a_known_path_is_dropped_before_validation() {
    let clock = crate::test_clock::Clock::at(NOW);
    let mut node = node(false);
    let identity = rns_identity::identity::Identity::new();
    let current = plain(&identity, 200);
    inbound(&mut node.actor, &current.raw, 1);
    assert!(node.actor.path_table.get(&current.destination).is_some());
    let remembered_at = node.actor.recent_announces[&current.destination].timestamp;
    let (arxc, arxb, afrxc) = counts(&mut node.actor, 1);
    let before = totals(&mut node.actor);

    clock.set(NOW + 5.0);
    let older = plain(&identity, 199);
    inbound(&mut node.actor, &older.raw, 1);

    assert_eq!(
        counts(&mut node.actor, 1),
        (arxc + 1, arxb, afrxc + 1),
        "received_announce(size=0) and filtered_announce()"
    );
    let after = totals(&mut node.actor);
    assert_eq!(after.announce_rx_packets, before.announce_rx_packets);
    assert_eq!(
        after.announce_filtered_packets,
        before.announce_filtered_packets + 1
    );
    assert!(matches!(
        node.actor
            .announce_validation
            .lookup(&hash(&older.raw), 0.0, false),
        CachedAnnounce::Miss
    ));
    assert!(!node.actor.packet_hashlist.contains(&hash(&older.raw)));
    assert_eq!(
        node.actor.recent_announces[&current.destination].timestamp, remembered_at,
        "a prefiltered copy is never remembered"
    );
}

#[test]
fn a_same_emission_copy_needs_more_gravity_or_an_unresponsive_path() {
    let _clock = crate::test_clock::Clock::at(NOW);
    let mut node = node(false);
    node.actor.interfaces.get_mut(&2).unwrap().gravity = 1;
    let identity = rns_identity::identity::Identity::new();
    let announce = plain(&identity, 300);
    inbound(&mut node.actor, &announce.raw, 1);

    inbound(&mut node.actor, &announce.raw, 2);
    assert_eq!(counts(&mut node.actor, 2).2, 0, "higher gravity is kept");
    assert_eq!(
        node.actor
            .path_table
            .get(&announce.destination)
            .unwrap()
            .interface_id,
        2
    );

    inbound(&mut node.actor, &announce.raw, 1);
    let (arxc, arxb, afrxc) = counts(&mut node.actor, 1);
    assert_eq!(afrxc, 1, "lower gravity is filtered");

    node.actor.path_table.set_state(
        announce.destination,
        crate::constants::PathState::Unresponsive,
    );
    inbound(&mut node.actor, &announce.raw, 1);
    assert_eq!(
        counts(&mut node.actor, 1),
        (arxc + 1, arxb + announce.raw.len() as u64, afrxc),
        "an unresponsive path is kept"
    );
}

#[test]
fn path_responses_awaited_and_queued_destinations_skip_the_prefilter() {
    let _clock = crate::test_clock::Clock::at(NOW);
    let mut node = node(true);
    let identity = rns_identity::identity::Identity::new();
    let current = plain(&identity, 400);
    let destination = current.destination;
    inbound(&mut node.actor, &current.raw, 1);
    let older = plain(&identity, 399);
    let older_response = signed(&identity, 398, 1, PacketContext::PathResponse, &[], None);
    let filtered = |node: &mut Node| counts(&mut node.actor, 2).2;

    assert!(node.actor.announce_table.get(&destination).is_some());
    inbound(&mut node.actor, &older.raw, 2);
    assert_eq!(filtered(&mut node), 0, "a queued rebroadcast");

    node.actor.announce_table.remove(&destination);
    inbound(&mut node.actor, &older_response.raw, 2);
    assert_eq!(filtered(&mut node), 0, "a path response");

    node.actor.path_requests.insert(destination, NOW);
    inbound(&mut node.actor, &older.raw, 2);
    assert_eq!(filtered(&mut node), 0, "an awaited path");
    node.actor.path_requests.remove(&destination);

    node.actor.path_table.get_mut(&destination).unwrap().expires = 0.0;
    inbound(&mut node.actor, &older.raw, 2);
    assert_eq!(
        filtered(&mut node),
        1,
        "an expired path not yet culled still counts"
    );

    node.actor
        .request_recursive_discovery(destination, 1)
        .expect("discovery for the expired path");
    inbound(&mut node.actor, &older.raw, 2);
    assert_eq!(filtered(&mut node), 1, "a discovery request");
}

#[test]
fn a_path_on_a_detached_interface_takes_any_announce() {
    let _clock = crate::test_clock::Clock::at(NOW);
    let mut node = node(false);
    let identity = rns_identity::identity::Identity::new();
    let current = plain(&identity, 500);
    inbound(&mut node.actor, &current.raw, 1);
    node.actor
        .path_table
        .get_mut(&current.destination)
        .unwrap()
        .interface_id = 9;

    inbound(&mut node.actor, &plain(&identity, 499).raw, 2);

    assert_eq!(counts(&mut node.actor, 2).2, 0);
}

/// Python 1.6.1: a frame over the MTU, a HEADER_1 announce that leaves no
/// room for a transport id, and a payload under 84 bytes are protocol
/// violations, checked before the type filters (Transport.py). 317 bytes of
/// app data is upstream's largest HEADER_1 announce: `Packet.pack` built a
/// 484-byte frame and refused 318 bytes (`RNS.Packet(...).pack()`, 1.6.1).
#[test]
fn announce_size_gates_come_before_the_type_filters() {
    let _clock = crate::test_clock::Clock::at(NOW);
    let mut node = node(false);
    let violations = |node: &Node| node.actor.interfaces[&1].protocol_violations;

    let fits = signed(
        &rns_identity::identity::Identity::new(),
        600,
        1,
        PacketContext::None,
        &[0xA5; 317],
        None,
    );
    assert_eq!(fits.raw.len(), 484);
    inbound(&mut node.actor, &fits.raw, 1);
    assert!(node.actor.path_table.get(&fits.destination).is_some());

    let too_long = signed(
        &rns_identity::identity::Identity::new(),
        600,
        1,
        PacketContext::None,
        &[0xA5; 318],
        None,
    );
    inbound(&mut node.actor, &too_long.raw, 1);
    assert!(node.actor.path_table.get(&too_long.destination).is_none());
    assert_eq!(violations(&node), 1);

    let relayed = signed(
        &rns_identity::identity::Identity::new(),
        600,
        1,
        PacketContext::None,
        &[0xA5; 317],
        Some([0x77; 16]),
    );
    assert_eq!(relayed.raw.len(), 500);
    inbound(&mut node.actor, &relayed.raw, 1);
    assert!(node.actor.path_table.get(&relayed.destination).is_some());
    assert_eq!(violations(&node), 1);

    node.actor.destination_filter.block("blocked.type");
    let mut short = rns_wire::header::PacketHeader::unpack(&fits.raw).unwrap().0;
    short.destination_hash = [0x31; 16];
    let mut short = short.pack();
    short.extend_from_slice(&[0x11; 64]);
    short.extend_from_slice(&rns_identity::name_hash::name_hash("blocked.type"));
    short.extend_from_slice(&[0x22; 9]);
    inbound(&mut node.actor, &Bytes::from(short), 1);
    assert_eq!(violations(&node), 2, "83 bytes of payload");
    assert_eq!(counts(&mut node.actor, 1).2, 0);
}

/// A blocked type is dropped silently; an unrequired one counts as filtered
/// (Transport.py).
#[test]
fn only_an_unrequired_type_counts_as_filtered() {
    let _clock = crate::test_clock::Clock::at(NOW);
    let mut node = node(false);
    let identity = rns_identity::identity::Identity::new();
    node.actor.destination_filter.block(APP);
    inbound(&mut node.actor, &plain(&identity, 700).raw, 1);
    assert_eq!(counts(&mut node.actor, 1), (0, 0, 0));

    let mut node = self::node(false);
    node.actor.destination_filter.set_required_only(true);
    inbound(&mut node.actor, &plain(&identity, 700).raw, 1);
    assert_eq!(counts(&mut node.actor, 1), (0, 0, 1));
    assert_eq!(node.actor.interfaces[&1].protocol_violations, 0);
}

fn bursting(actor: &mut TransportActor, overrides: IngressOverrides) {
    let ingress = &mut actor.interfaces.get_mut(&1).unwrap().ingress;
    *ingress = IngressController::try_with_overrides(&overrides).unwrap();
    for _ in 0..50 {
        ingress.received_announce();
    }
    assert!(ingress.should_ingress_limit(), "precondition: a burst");
}

/// A held announce counts with no bytes and no transport count; its release
/// counts its bytes once (Transport.py, Interface.py).
#[test]
fn a_held_announce_counts_its_bytes_only_when_released() {
    let _clock = crate::test_clock::Clock::at(NOW);
    let mut node = node(false);
    bursting(&mut node.actor, IngressOverrides::default());
    let (arxc, arxb, _) = counts(&mut node.actor, 1);
    let rx_packets = totals(&mut node.actor).announce_rx_packets;
    let announce = plain(&rns_identity::identity::Identity::new(), 800);

    inbound(&mut node.actor, &announce.raw, 1);

    assert_eq!(node.actor.interfaces[&1].ingress.held_count(), 1);
    assert_eq!(counts(&mut node.actor, 1), (arxc + 1, arxb, 0));
    assert_eq!(totals(&mut node.actor).announce_rx_packets, rx_packets);

    let held = std::mem::take(&mut node.actor.interfaces.get_mut(&1).unwrap().ingress)
        .cull_and_release(&[])
        .unwrap();
    node.actor.on_released_announce(held);
    assert!(node.actor.path_table.get(&announce.destination).is_some());
    assert_eq!(
        counts(&mut node.actor, 1),
        (1, announce.raw.len() as u64, 0),
        "a calm interface releases and counts the bytes"
    );
    assert_eq!(totals(&mut node.actor).announce_rx_packets, rx_packets + 1);
}

/// Interface.py `hold_announce`: a replaced held entry and a refused one are
/// both filtered.
#[test]
fn refused_and_replaced_holds_count_as_filtered() {
    let _clock = crate::test_clock::Clock::at(NOW);
    let mut node = node(false);
    bursting(
        &mut node.actor,
        IngressOverrides {
            max_held: Some(1),
            ..Default::default()
        },
    );
    let first = rns_identity::identity::Identity::new();
    inbound(&mut node.actor, &plain(&first, 900).raw, 1);
    assert_eq!(counts(&mut node.actor, 1).2, 0);
    inbound(
        &mut node.actor,
        &plain(&rns_identity::identity::Identity::new(), 900).raw,
        1,
    );
    assert_eq!(
        counts(&mut node.actor, 1).2,
        1,
        "refused: the buffer is full"
    );
    inbound(&mut node.actor, &plain(&first, 901).raw, 1);
    assert_eq!(counts(&mut node.actor, 1).2, 2, "replaced");
    assert_eq!(node.actor.interfaces[&1].ingress.held_count(), 1);
}

fn learned_path(actor: &mut TransportActor, destination: [u8; 16], emitted: u64) {
    let mut path = crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Gateway);
    path.random_blobs.push_back(random_blob(0x99, emitted));
    actor.path_table.insert(destination, path);
}

fn hold(actor: &mut TransportActor, announce: &Announce) {
    actor
        .interfaces
        .get_mut(&1)
        .unwrap()
        .ingress
        .hold_announce(HeldAnnounce {
            raw: announce.raw.clone(),
            destination_hash: announce.destination,
            hops: 2,
            receiving_interface_id: 1,
        });
}

fn released(actor: &mut TransportActor) -> usize {
    actor.last_held_announce_check = 0.0;
    actor.on_tick();
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut count = 0;
    while actor
        .inbound_rx
        .poll_recv(&mut cx, &actor.inbound_queues)
        .is_ready()
    {
        count += 1;
    }
    count
}

/// Interface.py culls held announces the prefilter rejects, but only on a
/// pass where a release is due, and leaves them out of the release.
#[test]
fn a_held_announce_a_newer_path_outdates_is_culled_when_a_release_is_due() {
    let _clock = crate::test_clock::Clock::at(NOW);
    let mut node = node(false);
    node.actor.interfaces.get_mut(&1).unwrap().ingress = IngressController::new();
    let outdated = plain(&rns_identity::identity::Identity::new(), 1000);
    let useful = plain(&rns_identity::identity::Identity::new(), 1000);
    hold(&mut node.actor, &outdated);
    hold(&mut node.actor, &useful);
    learned_path(&mut node.actor, outdated.destination, 1001);
    learned_path(&mut node.actor, useful.destination, 999);

    assert_eq!(released(&mut node.actor), 1);
    let ingress = &node.actor.interfaces[&1].ingress;
    assert_eq!(ingress.held_count(), 0, "the outdated one is culled");
}

#[test]
fn held_announces_are_not_culled_while_no_release_is_due() {
    let _clock = crate::test_clock::Clock::at(NOW);
    let mut node = node(false);
    bursting(&mut node.actor, IngressOverrides::default());
    let outdated = plain(&rns_identity::identity::Identity::new(), 1100);
    hold(&mut node.actor, &outdated);
    learned_path(&mut node.actor, outdated.destination, 1101);

    assert_eq!(released(&mut node.actor), 0);
    assert_eq!(node.actor.interfaces[&1].ingress.held_count(), 1);
}

/// A release re-enters `preprocess_inbound` (Interface.py), so the
/// prefilter applies to it.
#[test]
fn a_released_announce_for_a_newer_path_is_prefiltered() {
    let _clock = crate::test_clock::Clock::at(NOW);
    let mut node = node(false);
    let announce = plain(&rns_identity::identity::Identity::new(), 1200);
    learned_path(&mut node.actor, announce.destination, 1201);

    node.actor.on_released_announce(HeldAnnounce {
        raw: announce.raw.clone(),
        destination_hash: announce.destination,
        hops: 2,
        receiving_interface_id: 1,
    });

    assert_eq!(counts(&mut node.actor, 1), (1, 0, 1));
}
