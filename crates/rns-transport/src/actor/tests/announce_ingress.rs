//! Python 1.6.1 announce ingress (Transport.py `preprocess_inbound`): the size
//! gates, the type filters, the filtered count `afrxc`, and the accounting
//! of held announces (Interface.py).
use super::*;
use crate::ingress::{IngressController, IngressOverrides};
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

/// `(arxc, arxb, afrxc)` on an interface.
fn counts(actor: &mut TransportActor, id: InterfaceId) -> (u64, u64, u64) {
    let entry = stats(actor, id);
    (
        entry.announces_received,
        entry.announce_rx_bytes,
        entry.announces_filtered,
    )
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
