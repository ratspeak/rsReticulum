use super::*;
use crate::{InterfaceOwner, InterfacePacketCapacity};
use rns_wire::link_signalling::{SignallingData, parse_request_signalling};

fn ingress(actor: &mut TransportActor, interface_id: InterfaceId, raw: Bytes) {
    actor.on_inbound(InboundPacket {
        raw,
        interface_id,
        rssi: None,
        snr: None,
        q: None,
    });
}
fn capacity(clear: u32, wire: u32, upgrade: bool) -> InterfaceEntry {
    let (mut entry, _rx) = make_test_interface("capacity");
    entry.packet_capacity = InterfacePacketCapacity::new(clear, wire, upgrade);
    entry
}
fn payload(mode: u8, mtu: u32) -> Vec<u8> {
    let mut body = vec![0x42; 64];
    body.extend_from_slice(&SignallingData::new(mode, mtu).pack());
    body
}

#[test]
fn packet_capacity_attenuates_two_relays_without_changing_key_body() {
    let input = capacity(10_000, 10_000, true);
    let mut middle = capacity(1500, 1500, true);
    middle.ifac_key = Some([1; 64]);
    middle.ifac_size = 16;
    let output = capacity(1000, 1000, true);
    let original = payload(1, 4096);
    let (first, mode, ceiling) =
        crate::link_transit::attenuate_request(&original, 1, &input, 2, &middle).unwrap();
    assert_eq!((mode, ceiling), (1, 1484));
    assert_eq!(&first[..64], &original[..64]);
    let (second, _, ceiling) =
        crate::link_transit::attenuate_request(&first, 2, &middle, 3, &output).unwrap();
    assert_eq!(ceiling, 1000);
    assert_eq!(parse_request_signalling(&second).unwrap().mtu.get(), 1000);
    let base = capacity(500, 508, false);
    let (legacy, _, ceiling) =
        crate::link_transit::attenuate_request(&second, 3, &output, 4, &base).unwrap();
    assert_eq!(ceiling, 500);
    assert_eq!(legacy, &original[..64]);
    let (unchanged, _, ceiling) =
        crate::link_transit::attenuate_request(&legacy, 4, &base, 1, &input).unwrap();
    assert_eq!(unchanged, legacy);
    assert_eq!(ceiling, 500);
}

#[test]
fn packet_capacity_opaque_modes_only_transit_with_exact_supported_shape() {
    let high = capacity(1500, 1500, true);
    let base = capacity(500, 508, false);
    for mode in [0, 2, 3, 4, 5, 6, 7] {
        let exact = payload(mode, 500);
        assert_eq!(
            crate::link_transit::attenuate_request(&exact, 1, &high, 2, &base)
                .unwrap()
                .0,
            exact
        );
        assert!(
            crate::link_transit::attenuate_request(&payload(mode, 501), 1, &high, 2, &base)
                .is_err()
        );
        assert!(
            crate::link_transit::attenuate_request(&payload(mode, 0), 1, &high, 2, &base).is_err()
        );
    }
    for mtu in [1, 499] {
        assert!(
            crate::link_transit::attenuate_request(&payload(1, mtu), 1, &high, 2, &base).is_err()
        );
    }
    let mut narrow = capacity(500, 508, false);
    narrow.ifac_key = Some([1; 64]);
    narrow.ifac_size = 9;
    assert_eq!(narrow.effective_clear_mtu().unwrap(), 499);
    assert!(
        crate::link_transit::attenuate_request(&payload(1, 500), 1, &high, 2, &narrow).is_err()
    );
}

#[test]
fn packet_capacity_checks_clear_and_wire_with_ifac_before_admission() {
    let (mut actor, _) = TransportActor::new();
    let (mut entry, mut rx) = make_test_interface("radio");
    entry.packet_capacity = InterfacePacketCapacity::new(500, 508, false);
    entry.ifac_key = Some([5; 64]);
    entry.ifac_size = 8;
    actor.interfaces.insert(1, entry);
    let mut raw = make_data_packet([9; 16], 0).to_vec();
    raw.resize(500, 0x42);
    assert!(actor.send_to_interface(1, &raw));
    let wire = rx.try_recv().unwrap();
    assert_eq!(wire.len(), 508);
    raw.push(0);
    assert!(!actor.send_to_interface(1, &raw));
    assert!(rx.try_recv().is_err());
    let dest = [8; 16];
    let (tx, mut messages) = mpsc::channel(4);
    actor.local_destinations.insert(dest);
    actor.destination_channels.insert(dest, tx);
    let mut clear = make_data_packet(dest, 0).to_vec();
    clear.resize(500, 0);
    ingress(
        &mut actor,
        1,
        Bytes::from(crate::ifac::ifac_sign(&clear, &[5; 64], 8)),
    );
    assert!(messages.try_recv().is_ok());
    clear.push(0);
    ingress(
        &mut actor,
        1,
        Bytes::from(crate::ifac::ifac_sign(&clear, &[5; 64], 8)),
    );
    assert!(messages.try_recv().is_err());
}

#[test]
fn packet_capacity_stale_interface_events_cannot_retire_replacement() {
    let (mut actor, tx) = TransportActor::new();
    let (old, _) = make_test_interface("old");
    let old_sender = crate::InterfaceTransportSender::bind(1, old.owner.clone(), tx.clone());
    actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry: old });
    let (new, _) = make_test_interface("new");
    let current = new.owner.id();
    actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry: new });
    actor.handle_message(old_sender.event(TransportMessage::DeregisterInterface { id: 1 }));
    assert_eq!(actor.interfaces[&1].owner.id(), current);
    actor.handle_message(TransportMessage::DeregisterInterface { id: 1 });
    assert_eq!(actor.interfaces[&1].owner.id(), current);
    let current_sender =
        crate::InterfaceTransportSender::bind(1, actor.interfaces[&1].owner.clone(), tx);
    actor.handle_message(current_sender.event(TransportMessage::DeregisterInterface { id: 1 }));
    assert!(!actor.interfaces.contains_key(&1));
}

#[test]
fn packet_capacity_revision_invalidates_old_producer_and_binding() {
    let old = InterfaceOwner::new();
    let next = old.next_revision().unwrap();
    assert!(!old.is_current());
    assert!(next.is_current());
    assert!(!old.id().matches(&next));
    assert!(old.next_revision().is_none());
    let (mut actor, _) = TransportActor::new();
    let (mut entry, _) = make_test_interface("changed");
    entry.owner = next;
    actor.interfaces.insert(1, entry);
    let (tx, _) = mpsc::unbounded_channel();
    assert_eq!(
        actor.bind_link_endpoint(
            LinkEndpointBinding {
                interface_owner: Some(old.id()),
                link_id: [3; 16],
                interface_id: 1,
                role: LinkEndpointRole::Initiator
            },
            tx
        ),
        crate::messages::LinkEndpointBindResult::InterfaceUnavailable
    );
}

#[test]
fn packet_capacity_pending_local_proof_requires_original_admitted_owner() {
    let (mut actor, _) = TransportActor::new();
    let (entry, mut wire) = make_test_interface("original");
    let owner = entry.owner.id();
    actor.interfaces.insert(1, entry);
    let destination = [7; 16];
    actor
        .path_table
        .insert(destination, PathEntry::new(None, 1, 1, InterfaceMode::Full));
    let request = make_link_request_packet(destination, 0);
    let link_id = rns_wire::hash::link_id_from_raw(&request, rns_wire::flags::HeaderType::Header1);
    let (events, mut rx) = mpsc::channel(4);
    actor.local_destinations.insert(link_id);
    actor.destination_channels.insert(link_id, events);
    actor.on_outbound(OutboundRequest {
        raw: request,
        destination_hash: destination,
    });
    assert!(wire.try_recv().is_ok());
    assert_eq!(actor.pending_local_link_requests[&link_id][&1], owner);
    let proof = make_lrproof_packet_with_payload(link_id, 0, &[0; 96]);
    ingress(&mut actor, 1, proof.clone());
    assert!(
        matches!(rx.try_recv().unwrap(),crate::link_messages::DestinationEvent::InboundPacket{interface_owner:Some(o),..} if o==owner)
    );
    let (replacement, _) = make_test_interface("replacement");
    actor.handle_message(TransportMessage::RegisterInterface {
        id: 1,
        entry: replacement,
    });
    ingress(&mut actor, 1, proof);
    assert!(rx.try_recv().is_err());
}

#[test]
fn packet_capacity_authenticated_proof_obeys_request_ceiling_and_keeps_original_bytes() {
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    let (mut first, mut first_rx) = make_test_interface("first");
    first.packet_capacity = InterfacePacketCapacity::new(1500, 1500, true);
    let (mut second, mut second_rx) = make_test_interface("second");
    second.packet_capacity = first.packet_capacity;
    let first_owner = first.owner.clone();
    let second_owner = second.owner.clone();
    actor.interfaces.insert(1, first);
    actor.interfaces.insert(2, second);
    let destination = [8; 16];
    let id = [7; 16];
    let identity = rns_identity::identity::Identity::new();
    insert_announce_for(&mut actor, destination, &identity);
    actor.link_table.insert(
        id,
        crate::link_table::LinkEntry {
            timestamp: now_f64(),
            next_hop: None,
            interface_id: 2,
            remaining_hops: 1,
            destination_hash: destination,
            established: false,
            validated: false,
            proof_timeout: now_f64() + 60.,
            receiving_interface: 1,
            taken_hops: 1,
            interface_owner: Some(second_owner),
            receiving_owner: Some(first_owner),
            requested_mode: 1,
            accepted_mtu_ceiling: 1000,
        },
    );
    for signal in [
        SignallingData::new(2, 500),
        SignallingData::new(1, 1001),
        SignallingData::new(1, 499),
    ] {
        ingress(
            &mut actor,
            2,
            make_lrproof_packet(id, 0, &identity, Some(signal.pack())),
        );
        assert!(!actor.link_table.get(&id).unwrap().validated);
        assert!(first_rx.try_recv().is_err());
    }
    let valid = make_lrproof_packet(id, 0, &identity, Some(SignallingData::new(1, 900).pack()));
    ingress(&mut actor, 2, valid.clone());
    let forwarded = first_rx.try_recv().unwrap();
    assert_eq!(&forwarded[2..], &valid[2..]);
    assert_eq!(actor.link_table.get(&id).unwrap().accepted_mtu_ceiling, 900);
    // Transit packets may exceed500 when both registrations and this proof allow it.
    let mut data = make_link_data_packet(id, 0).to_vec();
    data.resize(800, 0);
    ingress(&mut actor, 1, data.into());
    assert_eq!(second_rx.try_recv().unwrap().len(), 800);
    let mut large = make_link_data_packet(id, 0).to_vec();
    large.resize(901, 1);
    ingress(&mut actor, 1, large.into());
    assert!(second_rx.try_recv().is_err());
    ingress(
        &mut actor,
        2,
        make_lrproof_packet(id, 0, &identity, Some(SignallingData::new(1, 800).pack())),
    );
    assert!(first_rx.try_recv().is_err());
    assert_eq!(actor.link_table.get(&id).unwrap().accepted_mtu_ceiling, 900);
}

#[test]
fn packet_capacity_ifac_mask_frontier_is_checked_without_panicking() {
    let high = InterfacePacketCapacity::new(262144, 262144, true);
    assert_eq!(high.effective_clear_mtu(0).unwrap(), 262144);
    for tag in [1, 8, 16, 64] {
        let clear = 8160 - tag;
        assert_eq!(high.effective_clear_mtu(tag).unwrap() as usize, clear);
        let wire = crate::ifac::try_ifac_sign(&vec![0; clear], &[9; 64], tag).unwrap();
        assert_eq!(wire.len(), 8160);
        assert_eq!(
            crate::ifac::ifac_verify(&wire, &[9; 64], tag)
                .unwrap()
                .len(),
            clear
        );
        assert_eq!(
            crate::ifac::try_ifac_sign(&vec![0; clear + 1], &[9; 64], tag),
            Err(crate::ifac::IfacSignError::PacketTooLarge)
        );
    }
    assert!(crate::ifac::try_ifac_sign(&[1, 2], &[0; 64], 0).is_err());
    assert!(crate::ifac::try_ifac_sign(&[1], &[0; 64], 1).is_err());
}

#[tokio::test]
async fn packet_capacity_first_producer_frame_waits_for_exact_registration() {
    let (mut actor, tx) = TransportActor::new();
    let (entry, _wire) = make_test_interface("pending");
    let sender = crate::InterfaceTransportSender::bind(1, entry.owner.clone(), tx);
    let owner = sender.owner();
    let pending = tokio::spawn(async move {
        sender
            .send(TransportMessage::Inbound(InboundPacket {
                raw: make_data_packet([1; 16], 0),
                interface_id: 1,
                rssi: None,
                snr: None,
                q: None,
            }))
            .await
    });
    tokio::task::yield_now().await;
    assert!(!pending.is_finished());
    actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry });
    assert!(owner.is_registered());
    assert!(pending.await.unwrap().is_ok());
    let event = actor.rx.try_recv().unwrap();
    assert!(matches!(event,TransportMessage::InterfaceEvent{owner:o,..} if o==owner));
}

#[test]
fn packet_capacity_background_rechecks_owner_at_actual_start() {
    let (tx, _rx) = mpsc::channel(1);
    let driver = crate::background_egress::BackgroundAnnounceReceiver::register(&tx).unwrap();
    let sender = crate::background_egress::lookup(&tx).unwrap();
    let owner = InterfaceOwner::new();
    let mut receipt = sender
        .try_offer_owned(
            Bytes::from_static(b"already admitted shape"),
            100.,
            0.,
            owner.clone(),
        )
        .unwrap();
    let _next = owner.next_revision().unwrap();
    assert!(driver.try_start(1.).is_none());
    assert!(receipt.started.try_recv().is_err());
}

#[tokio::test]
async fn packet_capacity_unregistered_producer_exits_when_actor_closes() {
    let (tx, rx) = mpsc::channel(1);
    let sender = crate::InterfaceTransportSender::new(1, tx);
    let blocked = tokio::spawn(async move { sender.ready().await });
    tokio::task::yield_now().await;
    assert!(!blocked.is_finished());
    drop(rx);
    assert!(
        !tokio::time::timeout(Duration::from_secs(1), blocked)
            .await
            .unwrap()
            .unwrap()
    );
}

#[test]
fn packet_capacity_readiness_is_monotonic_across_revisions() {
    let first = InterfaceOwner::new();
    assert!(first.mark_registered());
    let next = first.next_revision().unwrap();
    assert!(!next.is_registered());
    assert!(next.mark_registered());
    assert!(!first.mark_registered());
    assert!(next.is_registered());
}

#[test]
fn packet_capacity_link_request_reports_exact_capacity_error_before_emission() {
    let (mut actor, _) = TransportActor::new();
    let (mut entry, mut wire) = make_test_interface("below-base");
    entry.packet_capacity = InterfacePacketCapacity::new(499, 564, false);
    actor.interfaces.insert(7, entry);
    let destination = [0x72; 16];
    actor
        .path_table
        .insert(destination, PathEntry::new(None, 1, 7, InterfaceMode::Full));
    let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
    actor.handle_message(TransportMessage::SendLinkRequest {
        request: OutboundRequest {
            raw: make_link_request_packet(destination, 0),
            destination_hash: destination,
        },
        result_tx,
    });
    assert_eq!(
        result_rx.try_recv().unwrap(),
        Err(crate::link_messages::LinkRequestDispatchError::Capacity(
            crate::InterfaceCapacityError::LinkCapacityUnavailable {
                interface_id: 7,
                clear_mtu: 499,
                required: 500
            }
        ))
    );
    assert!(wire.try_recv().is_err());
    assert!(actor.pending_local_link_requests.is_empty());
}

#[test]
fn packet_capacity_cancelled_request_attempt_cannot_emit_delayed_packet() {
    let (mut actor, _) = TransportActor::new();
    let (entry, mut wire) = make_test_interface("available");
    actor.interfaces.insert(1, entry);
    let destination = [0x73; 16];
    actor
        .path_table
        .insert(destination, PathEntry::new(None, 1, 1, InterfaceMode::Full));
    let raw = make_link_request_packet(destination, 0);
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    drop(result_rx);
    actor.handle_message(TransportMessage::SendLinkRequest {
        request: OutboundRequest {
            raw: raw.clone(),
            destination_hash: destination,
        },
        result_tx,
    });
    assert!(wire.try_recv().is_err());
    let (result_tx, mut replacement_rx) = tokio::sync::oneshot::channel();
    actor.handle_message(TransportMessage::SendLinkRequest {
        request: OutboundRequest {
            raw,
            destination_hash: destination,
        },
        result_tx,
    });
    assert_eq!(replacement_rx.try_recv().unwrap(), Ok(()));
    assert!(wire.try_recv().is_ok());
    assert!(wire.try_recv().is_err());
}

#[test]
fn packet_capacity_refused_transit_request_can_retry_without_hash_poisoning() {
    for queue_full in [false, true] {
        let (mut actor, _) = TransportActor::new();
        actor.is_transport_enabled = true;
        let transport_id = [0x91; 16];
        actor.transport_identity_hash = Some(transport_id);
        let (first, _first_rx) = make_test_interface("ingress");
        let (mut second, mut rx) = make_test_interface("egress");
        second.packet_capacity =
            InterfacePacketCapacity::new(if queue_full { 500 } else { 499 }, 564, false);
        if queue_full {
            while second.tx.try_send(Bytes::from_static(b"occupied")).is_ok() {}
        }
        actor.interfaces.insert(1, first);
        actor.interfaces.insert(2, second);
        let destination = [0x92; 16];
        actor
            .path_table
            .insert(destination, PathEntry::new(None, 1, 2, InterfaceMode::Full));
        let raw = make_header2_link_request_packet(transport_id, destination, 0, &[0x42; 64]);
        let link_id = rns_wire::hash::link_id_from_raw(&raw, rns_wire::flags::HeaderType::Header2);
        ingress(&mut actor, 1, raw.clone());
        assert!(!actor.link_table.contains(&link_id));
        if queue_full {
            while let Ok(frame) = rx.try_recv() {
                assert_eq!(&frame[..], b"occupied");
            }
        } else {
            assert!(rx.try_recv().is_err());
            actor.interfaces.get_mut(&2).unwrap().packet_capacity =
                InterfacePacketCapacity::new(500, 564, false);
        }
        ingress(&mut actor, 1, raw.clone());
        assert!(
            rx.try_recv().is_ok(),
            "retry refused after recovery queue_full={queue_full}"
        );
        assert!(actor.link_table.contains(&link_id));
        let deadline = actor.link_table.get(&link_id).unwrap().proof_timeout;
        ingress(&mut actor, 1, raw);
        assert!(rx.try_recv().is_err());
        assert_eq!(
            actor.link_table.get(&link_id).unwrap().proof_timeout,
            deadline
        );
    }
}
