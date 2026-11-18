//! Per-class inbound queues (Transport.py).
use super::*;
use crate::inbound_queues::{InboundQueueLengths, Queued, TrafficClass};

fn lengths(data: usize, announce: usize, pr: usize, il: usize) -> InboundQueueLengths {
    InboundQueueLengths {
        data,
        announce,
        pr,
        il,
    }
}

fn registered(
    queue_lengths: InboundQueueLengths,
) -> (TransportActor, crate::InterfaceTransportSender) {
    let (mut actor, tx) = TransportActor::new_with_queues(64, 1024, queue_lengths);
    let (entry, _wire) = make_test_interface("flooded");
    let sender = crate::InterfaceTransportSender::bind(1, entry.owner.clone(), tx);
    actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry });
    (actor, sender)
}

fn inbound(raw: Bytes) -> TransportMessage {
    TransportMessage::Inbound(InboundPacket {
        raw,
        interface_id: 1,
        rssi: None,
        snr: None,
        q: None,
    })
}

fn path_request(tag: u8) -> Bytes {
    path_request_for(&make_path_request_payload_with_tag(
        [0x77; 16], None, [tag; 16],
    ))
}

fn path_request_for(payload: &[u8]) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Plain,
            packet_type: rns_wire::flags::PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: rns_identity::destination::Destination::hash_from_name_and_identity(
            "rnstransport.path.request",
            None,
        ),
        context: rns_wire::context::PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(payload);
    Bytes::from(raw)
}

fn next(actor: &mut TransportActor) -> Option<(TrafficClass, Queued)> {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match actor.inbound_rx.poll_recv(&mut cx, &actor.inbound_queues) {
        std::task::Poll::Ready(item) => Some(item),
        std::task::Poll::Pending => None,
    }
}

#[test]
fn a_full_announce_queue_drops_and_counts_while_other_classes_keep_room() {
    let (actor, sender) = registered(lengths(4, 2, 2, 1));
    for i in 0..5u8 {
        sender
            .try_send(inbound(make_announce_packet_for_identity([i; 16], 0, None)))
            .unwrap();
    }
    sender
        .try_send(inbound(make_data_packet([9; 16], 0)))
        .unwrap();
    let snapshot = actor.inbound_queues.snapshot();
    assert_eq!(snapshot.heights, [1, 2, 0, 0]);
    assert_eq!(snapshot.dropped, [0, 3, 0, 0]);
    assert_eq!(snapshot.lengths, [4, 2, 2, 1]);
}

#[tokio::test]
async fn a_full_data_queue_waits_instead_of_dropping() {
    let (mut actor, sender) = registered(lengths(2, 2, 2, 1));
    for i in 0..2u8 {
        sender
            .try_send(inbound(make_data_packet([i; 16], 0)))
            .unwrap();
    }
    assert!(matches!(
        sender.try_send(inbound(make_data_packet([2; 16], 0))),
        Err(mpsc::error::TrySendError::Full(_))
    ));
    let blocked = tokio::spawn({
        let sender = sender.clone();
        async move { sender.send(inbound(make_data_packet([3; 16], 0))).await }
    });
    tokio::task::yield_now().await;
    assert!(!blocked.is_finished());
    assert!(next(&mut actor).is_some());
    assert!(blocked.await.unwrap().is_ok());
    assert_eq!(actor.inbound_queues.snapshot().dropped, [0; 4]);
    assert_eq!(actor.inbound_queues.snapshot().heights[0], 2);
}

#[test]
fn queued_classes_drain_data_first_then_announce_then_path_request() {
    let (mut actor, sender) = registered(InboundQueueLengths::default());
    sender.try_send(inbound(path_request(1))).unwrap();
    sender
        .try_send(inbound(make_announce_packet_for_identity([1; 16], 0, None)))
        .unwrap();
    sender
        .try_send(inbound(make_data_packet([1; 16], 0)))
        .unwrap();
    let order: Vec<_> = std::iter::from_fn(|| next(&mut actor).map(|(c, _)| c)).collect();
    assert_eq!(
        order,
        [
            TrafficClass::Data,
            TrafficClass::Announce,
            TrafficClass::PathRequest
        ]
    );
}

#[test]
fn path_requests_during_a_path_request_burst_wait_behind_every_other_class() {
    let (mut actor, sender) = registered(lengths(8, 8, 8, 1));
    prime_ingress_pr_burst(&mut actor, 1);
    for dest in 1..=3u8 {
        let payload = make_path_request_payload_with_tag([dest; 16], None, [dest; 16]);
        sender
            .try_send(inbound(path_request_for(&payload)))
            .unwrap();
    }
    // Each path request passes its gates, then waits in the one-slot IL queue.
    for _ in 0..3 {
        let (class, msg) = next(&mut actor).unwrap();
        assert_eq!(class, TrafficClass::PathRequest);
        actor.handle_inbound_event(msg);
    }
    let snapshot = actor.inbound_queues.snapshot();
    assert_eq!(snapshot.heights, [0, 0, 0, 1]);
    assert_eq!(snapshot.dropped, [0, 0, 0, 2]);
    sender
        .try_send(inbound(make_data_packet([1; 16], 0)))
        .unwrap();
    assert_eq!(next(&mut actor).unwrap().0, TrafficClass::Data);
    assert_eq!(next(&mut actor).unwrap().0, TrafficClass::IngressLimited);
    assert!(next(&mut actor).is_none());
    assert_eq!(actor.inbound_queues.snapshot().heights[3], 0);
}

/// Transport.py classifies after the size, tag, and stamp gates, so a
/// rejected request never takes an ingress-limited slot.
#[test]
fn a_rejected_path_request_takes_no_ingress_limited_slot() {
    let (mut actor, sender) = registered(lengths(8, 8, 8, 1));
    prime_ingress_pr_burst(&mut actor, 1);
    sender
        .try_send(inbound(path_request_for(&[0x31; 16])))
        .unwrap();
    let payload = make_path_request_payload_with_tag([0x32; 16], None, [0x32; 16]);
    sender
        .try_send(inbound(path_request_for(&payload)))
        .unwrap();
    while let Some((_, msg)) = next(&mut actor) {
        actor.handle_inbound_event(msg);
        if actor.inbound_queues.snapshot().heights[3] == 1 {
            break;
        }
    }
    let snapshot = actor.inbound_queues.snapshot();
    assert_eq!(snapshot.heights, [0, 0, 0, 1]);
    assert_eq!(snapshot.dropped, [0; 4]);
    assert!(actor.inflight_path_requests.contains_key(&[0x32; 16]));
    assert!(!actor.inflight_path_requests.contains_key(&[0x31; 16]));
}

/// Transport.py registers a request as in flight on receipt, so a second
/// request during the burst is dropped instead of queued behind the first.
#[test]
fn a_queued_ingress_limited_path_request_is_already_in_flight() {
    let (mut actor, sender) = registered(lengths(8, 8, 8, 8));
    actor.is_transport_enabled = true;
    prime_ingress_pr_burst(&mut actor, 1);
    for tag in [1u8, 2] {
        sender.try_send(inbound(path_request(tag))).unwrap();
        let (_, msg) = next(&mut actor).unwrap();
        actor.handle_inbound_event(msg);
    }
    assert!(actor.inflight_path_requests.contains_key(&[0x77; 16]));
    assert_eq!(actor.inbound_queues.snapshot().heights[3], 1);
    assert!(
        !actor.discovery_path_requests.contains_key(&[0x77; 16]),
        "an ingress-limited duplicate is not batched"
    );
}

/// Python decides at preprocess time and passes `ingress_limited` into
/// `path_request`, so a queued ingress-limited request is never forwarded
/// recursively even if the burst ended meanwhile (Transport.py).
#[test]
fn an_ingress_limited_path_request_is_not_forwarded_recursively() {
    for limited in [false, true] {
        let (mut actor, tx) = TransportActor::new_with_queues(64, 1024, lengths(8, 8, 8, 8));
        actor.is_transport_enabled = true;
        let (mut entry, _wire) = make_test_interface("requestor");
        entry.mode = InterfaceMode::Gateway;
        let sender = crate::InterfaceTransportSender::bind(1, entry.owner.clone(), tx);
        actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry });
        let (outbound, mut outbound_rx) = make_test_interface("outbound");
        actor.interfaces.insert(2, outbound);
        if limited {
            prime_ingress_pr_burst(&mut actor, 1);
        }
        sender.try_send(inbound(path_request(1))).unwrap();
        let (_, item) = next(&mut actor).unwrap();
        actor.handle_inbound_event(item);
        if limited {
            assert!(outbound_rx.try_recv().is_err(), "deferred");
            actor.interfaces.get_mut(&1).unwrap().ingress =
                crate::ingress::IngressController::new();
            let (class, item) = next(&mut actor).unwrap();
            assert_eq!(class, TrafficClass::IngressLimited);
            actor.handle_inbound_event(item);
        }
        assert_eq!(
            outbound_rx.try_recv().is_ok(),
            !limited,
            "limited={limited}"
        );
    }
}
