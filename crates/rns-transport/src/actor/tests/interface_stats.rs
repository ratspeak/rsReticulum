//! Python 1.5.5 per-interface counters in interface stats: announce and path
//! request counts, protocol and IFAC violations, packet filter hits and
//! dropped transmit bytes (Interface.py, Reticulum.py).
use super::*;
use rns_wire::context::PacketContext;
use rns_wire::flags::{DestinationType, HeaderType, PacketFlags, PacketType, TransportType};
use rns_wire::header::PacketHeader;

fn hub() -> TransportActor {
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    actor.transport_identity_hash = Some([0x42; 16]);
    actor
}

fn attach(actor: &mut TransportActor, id: InterfaceId) -> mpsc::Receiver<Bytes> {
    let (entry, rx) = make_test_interface(&format!("stats_{id}"));
    actor.interfaces.insert(id, entry);
    rx
}

fn attach_ifac(actor: &mut TransportActor, id: InterfaceId, ifac_key: [u8; 64]) {
    let (mut entry, _rx) = make_test_interface(&format!("ifac_{id}"));
    entry.ifac_key = Some(ifac_key.into());
    entry.ifac_size = 8;
    actor.interfaces.insert(id, entry);
}

fn inbound(actor: &mut TransportActor, raw: impl Into<Bytes>, interface_id: InterfaceId) {
    actor.on_inbound(InboundPacket {
        raw: raw.into(),
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

fn packet(
    destination_type: DestinationType,
    packet_type: PacketType,
    hops: u8,
    transport_id: Option<[u8; 16]>,
    destination_hash: [u8; 16],
    payload: &[u8],
) -> Bytes {
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: if transport_id.is_some() {
                HeaderType::Header2
            } else {
                HeaderType::Header1
            },
            context_flag: false,
            transport_type: if transport_id.is_some() {
                TransportType::Transport
            } else {
                TransportType::Broadcast
            },
            destination_type,
            packet_type,
        },
        hops,
        transport_id,
        destination_hash,
        context: PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(payload);
    Bytes::from(raw)
}

/// `rest` follows the destination: a tag, or a requestor transport id and a
/// tag (Transport.py).
fn path_request(destination: [u8; 16], rest: &[u8]) -> Bytes {
    let pr_destination = rns_identity::destination::Destination::hash_from_name_and_identity(
        "rnstransport.path.request",
        None,
    );
    let mut payload = destination.to_vec();
    payload.extend_from_slice(rest);
    packet(
        DestinationType::Plain,
        PacketType::Data,
        0,
        None,
        pr_destination,
        &payload,
    )
}

#[test]
fn stats_count_the_announces_and_path_requests_an_interface_carries() {
    let mut actor = hub();
    let _rx = attach(&mut actor, 1);

    let (announce, _) = make_valid_announce("stats.counts", 1);
    inbound(&mut actor, announce, 1);
    inbound(&mut actor, path_request([0x51; 16], &[0xA1; 16]), 1);
    let before = stats(&mut actor, 1);
    assert_eq!(before.announces_received, 1, "arxc");
    assert_eq!(before.path_requests_received, 1, "prxc");

    let ingress = &mut actor.interfaces.get_mut(&1).unwrap().ingress;
    ingress.sent_announce();
    ingress.sent_announce();
    ingress.sent_path_request();
    let after = stats(&mut actor, 1);
    assert_eq!(after.announces_sent, before.announces_sent + 2, "atxc");
    assert_eq!(
        after.path_requests_sent,
        before.path_requests_sent + 1,
        "ptxc"
    );
}

#[test]
fn ifac_failures_count_as_ifac_violations_on_their_interface() {
    let mut actor = hub();
    let ifac_key = rns_identity::ifac::derive_ifac_key(Some("stats"), Some("counters")).unwrap();
    let wrong_key = rns_identity::ifac::derive_ifac_key(Some("wrong"), Some("key")).unwrap();
    attach_ifac(&mut actor, 1, ifac_key);
    let _clear = attach(&mut actor, 2);

    let (valid, valid_dest) = make_valid_announce("stats.ifac.valid", 0);
    inbound(&mut actor, crate::ifac::ifac_sign(&valid, &ifac_key, 8), 1);
    assert!(actor.path_table.has_path(&valid_dest));
    assert_eq!(
        stats(&mut actor, 1).ifac_violations,
        0,
        "a valid IFAC is no violation"
    );

    let (announce, _) = make_valid_announce("stats.ifac.bad", 0);
    inbound(
        &mut actor,
        crate::ifac::ifac_sign(&announce, &wrong_key, 8),
        1,
    );
    inbound(&mut actor, announce.clone(), 1);
    let mut short = crate::ifac::ifac_sign(&announce, &ifac_key, 8);
    short.truncate(2 + 8);
    inbound(&mut actor, short, 1);
    assert_eq!(
        stats(&mut actor, 1).ifac_violations,
        3,
        "invalid IFAC, missing IFAC flag and an IFAC packet too short (Transport.py:1715-1777)"
    );

    inbound(
        &mut actor,
        crate::ifac::ifac_sign(&announce, &ifac_key, 8),
        2,
    );
    assert_eq!(
        stats(&mut actor, 2).ifac_violations,
        1,
        "an IFAC flag on an interface without IFAC (Transport.py:1784)"
    );
    assert_eq!(stats(&mut actor, 1).protocol_violations, 0);
}

#[test]
fn filtered_packets_count_as_packet_filter_hits() {
    let mut actor = hub();
    let _rx = attach(&mut actor, 1);

    inbound(
        &mut actor,
        packet(
            DestinationType::Plain,
            PacketType::Data,
            1,
            None,
            [0x61; 16],
            &[1; 8],
        ),
        1,
    );
    let (announce, _) = make_valid_announce("stats.filter.single", 0);
    inbound(&mut actor, announce.clone(), 1);
    inbound(&mut actor, announce, 1);
    assert_eq!(
        stats(&mut actor, 1).packet_filter_hits,
        0,
        "a one-hop PLAIN packet and a repeated SINGLE announce pass the filter"
    );

    let plain_two_hops = packet(
        DestinationType::Plain,
        PacketType::Data,
        2,
        None,
        [0x62; 16],
        &[2; 8],
    );
    let group_two_hops = packet(
        DestinationType::Group,
        PacketType::Data,
        2,
        None,
        [0x63; 16],
        &[3; 8],
    );
    let plain_announce = packet(
        DestinationType::Plain,
        PacketType::Announce,
        0,
        None,
        [0x64; 16],
        &[4; 8],
    );
    let foreign = packet(
        DestinationType::Single,
        PacketType::Data,
        1,
        Some([0x99; 16]),
        [0x65; 16],
        &[5; 8],
    );
    let repeated = make_data_packet([0x66; 16], 0);
    for raw in [
        plain_two_hops,
        group_two_hops,
        plain_announce,
        foreign,
        repeated.clone(),
    ] {
        inbound(&mut actor, raw, 1);
    }
    inbound(&mut actor, repeated, 1);
    assert_eq!(
        stats(&mut actor, 1).packet_filter_hits,
        5,
        "every packet_filter rejection: multi-hop PLAIN and GROUP, a PLAIN announce, \
         another transport's packet and a duplicate (Transport.py:1624-1679, :1795)"
    );
    assert_eq!(stats(&mut actor, 1).protocol_violations, 0);
}

#[test]
fn malformed_and_invalid_packets_count_as_protocol_violations() {
    let mut actor = hub();
    let _rx = attach(&mut actor, 1);

    inbound(&mut actor, vec![0x00], 1);
    inbound(&mut actor, vec![0u8; 501], 1);
    let mut too_many_hops = make_data_packet([0x71; 16], 0).to_vec();
    too_many_hops[1] = PATHFINDER_M;
    inbound(&mut actor, too_many_hops, 1);
    let (announce, _) = make_valid_announce("stats.violation", 0);
    let mut forged = announce.to_vec();
    *forged.last_mut().unwrap() ^= 0x01;
    inbound(&mut actor, forged, 1);
    inbound(&mut actor, path_request([0x72; 16], &[]), 1);
    assert_eq!(
        stats(&mut actor, 1).protocol_violations,
        5,
        "a malformed packet, an oversized frame, an invalid hop count, a forged \
         announce and a tagless path request (Transport.py:1786-1840)"
    );

    inbound(&mut actor, announce, 1);
    let mut requestor_and_long_tag = vec![0xC3; 16];
    requestor_and_long_tag.extend_from_slice(&[0xB2; 20]);
    inbound(
        &mut actor,
        path_request([0x73; 16], &requestor_and_long_tag),
        1,
    );
    assert_eq!(
        stats(&mut actor, 1).protocol_violations,
        6,
        "a 36-byte request is outside the 32/48/64 whitelist (Transport.py:2084-2086@1.6.0)"
    );
    assert_eq!(stats(&mut actor, 1).packet_filter_hits, 0);
    assert_eq!(stats(&mut actor, 1).ifac_violations, 0);
}

#[test]
fn a_full_transmit_queue_counts_dropped_bytes() {
    let mut actor = hub();
    let (entry, _rx) = make_test_interface_with_capacity("narrow", 1);
    actor.interfaces.insert(1, entry);

    actor.send_to_interface(1, &[0x01; 10]);
    actor.send_to_interface(1, &[0x02; 20]);
    actor.send_to_interface(1, &[0x03; 30]);

    let entry = stats(&mut actor, 1);
    assert_eq!(entry.tx_drops, 2, "txdrp");
    assert_eq!(entry.tx_dropped_bytes, 50, "txdrb");
}

/// Python counts a path request once its destination and tag pass the
/// duplicate gate (Transport.py), so a repeat sent through another
/// requestor neither counts nor brings the ingress limit closer.
#[test]
fn a_repeated_path_request_tag_is_not_counted() {
    let mut actor = hub();
    let _rx = attach(&mut actor, 1);
    let request = |requestor: u8| {
        let mut rest = vec![requestor; 16];
        rest.extend_from_slice(&[0xA1; 16]);
        path_request([0x51; 16], &rest)
    };

    inbound(&mut actor, request(0xC1), 1);
    inbound(&mut actor, request(0xC2), 1);

    assert_eq!(stats(&mut actor, 1).path_requests_received, 1, "prxc");
}

/// A realtime Link packet dropped at a full transmit queue is a transmit
/// drop like any other, bytes included.
#[test]
fn a_dropped_realtime_link_packet_counts_its_bytes() {
    let mut actor = hub();
    let (entry, _rx) = make_test_interface_with_capacity("media", 1);
    entry.tx.try_send(Bytes::from_static(b"occupied")).unwrap();
    actor.interfaces.insert(1, entry);
    let link_id = [0xBB; 16];
    let (lifecycle_tx, _lifecycle_rx) = mpsc::unbounded_channel();
    assert_eq!(
        actor.bind_link_endpoint(
            crate::messages::LinkEndpointBinding {
                interface_owner: actor.interfaces.get(&1).map(|entry| entry.owner.id()),
                link_id,
                interface_id: 1,
                role: crate::messages::LinkEndpointRole::Responder,
            },
            lifecycle_tx,
        ),
        crate::messages::LinkEndpointBindResult::Bound
    );
    let media = make_link_data_packet_with_context(link_id, 0, PacketContext::None);

    assert_eq!(
        actor.send_link_endpoint_best_effort(
            link_id,
            crate::messages::LinkEndpointRole::Responder,
            OutboundRequest {
                raw: media.clone(),
                destination_hash: link_id,
            },
        ),
        crate::messages::LinkEndpointSendResult::DroppedBackpressure
    );
    let entry = stats(&mut actor, 1);
    assert_eq!(entry.tx_drops, 1, "txdrp");
    assert_eq!(entry.tx_dropped_bytes, media.len() as u64, "txdrb");
}

#[test]
fn an_accepted_client_names_its_listener() {
    let mut actor = hub();
    let _server = attach(&mut actor, 1);
    let (mut child, _rx) = make_test_interface("stats_1/client_2");
    child.parent_id = Some(1);
    actor.interfaces.insert(2, child);

    assert_eq!(stats(&mut actor, 2).parent_id, Some(1));
    assert_eq!(stats(&mut actor, 1).parent_id, None);
    assert_eq!(
        stats(&mut actor, 2).parent_interface_name.as_deref(),
        Some("stats_1")
    );
    assert_eq!(stats(&mut actor, 1).parent_interface_name, None);
}

/// Python publishes an interface's IFAC only when it has one: the size,
/// signature, and network name together, and none of them for a size that
/// is configured without a key (Reticulum.py).
#[test]
fn stats_report_ifac_only_for_an_interface_that_has_it() {
    let mut actor = hub();
    attach_ifac(&mut actor, 1, [0x5a; 64]);
    actor.interfaces.get_mut(&1).unwrap().ifac_netname = Some("testnet".into());
    let (mut plain, _rx) = make_test_interface("plain");
    plain.ifac_size = 16;
    plain.ifac_netname = Some("unused".into());
    actor.interfaces.insert(2, plain);

    let with = stats(&mut actor, 1);
    assert_eq!(with.ifac_size, Some(8));
    assert_eq!(
        with.ifac_signature,
        rns_identity::ifac::ifac_signature(&[0x5a; 64]).map(Vec::from)
    );
    assert!(with.ifac_signature.is_some());
    assert_eq!(with.ifac_netname.as_deref(), Some("testnet"));

    let without = stats(&mut actor, 2);
    assert_eq!(
        (
            without.ifac_size,
            without.ifac_signature,
            without.ifac_netname
        ),
        (None, None, None)
    );
}

/// The signature follows the key when an interface is given another.
#[test]
fn the_ifac_signature_follows_a_changed_key() {
    let mut actor = hub();
    attach_ifac(&mut actor, 1, [0x5a; 64]);
    let first = stats(&mut actor, 1).ifac_signature;
    assert_eq!(stats(&mut actor, 1).ifac_signature, first);
    actor.interfaces.get_mut(&1).unwrap().ifac_key = Some([0x6b; 64].into());
    assert_eq!(
        stats(&mut actor, 1).ifac_signature,
        rns_identity::ifac::ifac_signature(&[0x6b; 64]).map(Vec::from)
    );
    assert_ne!(stats(&mut actor, 1).ifac_signature, first);
}

/// An auto-connected interface names the network identity that announced it.
#[test]
fn stats_carry_the_autoconnect_source() {
    let mut actor = hub();
    let _rx = attach(&mut actor, 1);
    actor.interfaces.get_mut(&1).unwrap().autoconnect_source = Some("5a".repeat(16));
    let _other = attach(&mut actor, 2);
    assert_eq!(
        stats(&mut actor, 1).autoconnect_source,
        Some("5a".repeat(16))
    );
    assert_eq!(stats(&mut actor, 2).autoconnect_source, None);
}

fn totals(actor: &mut TransportActor) -> crate::messages::TrafficTotalsRpcEntry {
    let TransportQueryResponse::TrafficTotals(totals) =
        actor.handle_query(TransportQuery::GetTrafficTotals)
    else {
        panic!("unexpected traffic totals response");
    };
    totals
}

/// Spawned children add their announce bytes and samples, not counts, to the
/// parent (Interface.py, TCPInterface.py).
#[test]
fn a_parent_takes_its_childrens_announce_bytes_but_not_their_counts() {
    let mut actor = hub();
    let _parent = attach(&mut actor, 1);
    for id in [2, 3] {
        let (mut child, _rx) = make_test_interface(&format!("stats_1/client_{id}"));
        child.parent_id = Some(1);
        actor.interfaces.insert(id, child);
    }
    let mut sizes = 0;
    for (id, name) in [(2, "stats.rollup.a"), (3, "stats.rollup.b")] {
        let (announce, _) = make_valid_announce(name, 0);
        sizes += announce.len() as u64;
        inbound(&mut actor, announce, id);
    }
    let parent = stats(&mut actor, 1);
    assert_eq!(parent.announce_rx_bytes, sizes, "arxb");
    assert_eq!(parent.announces_received, 0, "arxc");
    assert_eq!(stats(&mut actor, 2).announces_received, 1);
}

/// Totals sum top-level interfaces other than the shared-instance server and
/// keep what they counted when an interface leaves (Transport.py).
#[test]
fn traffic_totals_are_cumulative_over_top_level_interfaces() {
    let mut actor = hub();
    let counters: Vec<Arc<AtomicU64>> = (0..3).map(|_| Arc::new(AtomicU64::new(0))).collect();
    for (id, role) in [
        (1, InterfaceRole::Normal),
        (2, InterfaceRole::Normal),
        (3, InterfaceRole::SharedServer),
    ] {
        let (mut entry, _rx) = make_test_interface(&format!("totals_{id}"));
        entry.role = role;
        entry.rxb = Some(counters[id as usize - 1].clone());
        if id == 2 {
            entry.parent_id = Some(1);
        }
        actor.interfaces.insert(id, entry);
    }
    actor.count_traffic(1_000.0);
    for counter in &counters {
        counter.fetch_add(100, std::sync::atomic::Ordering::Relaxed);
    }
    std::thread::sleep(Duration::from_millis(5));
    actor.count_traffic(1_001.0);
    let measured = totals(&mut actor);
    assert!(measured.measured);
    assert_eq!(measured.rxb, 100, "only the top-level non-shared interface");
    assert!(measured.rxs > 0.0);

    actor.deregister_interface(1);
    actor.count_traffic(1_002.0);
    assert_eq!(totals(&mut actor).rxb, 100, "totals survive deregistration");
}

/// `unupcount` counts paths never used and `actpcount` the rest
/// (Transport.py, Reticulum.py).
#[test]
fn traffic_totals_count_never_used_paths() {
    let mut actor = hub();
    for (byte, used) in [(1u8, 0.0), (2, 0.0), (3, 1_000.0)] {
        let mut entry =
            crate::path_table::PathEntry::new(None, 1, 1, crate::constants::InterfaceMode::Full);
        entry.used = used;
        actor.path_table.insert([byte; 16], entry);
    }
    let measured = totals(&mut actor);
    assert_eq!(measured.path_count, 3);
    assert_eq!(measured.unused_path_count, 2);
}
