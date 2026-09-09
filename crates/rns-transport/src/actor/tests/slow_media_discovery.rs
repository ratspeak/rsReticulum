//! Controlled-clock tests run the production ingress/maintenance handlers.
//! Timing fixtures are software airtime models, not physical radio evidence.
use super::*;

fn relay() -> TransportActor {
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    actor.transport_identity_hash = Some([0x44; 16]);
    actor
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

fn request(actor: &mut TransportActor, dest: [u8; 16], tag: u8, interface: InterfaceId) {
    actor.handle_inbound_path_request(
        &make_path_request_payload_with_tag(dest, None, [tag; 16]),
        interface,
    );
}

fn assert_response(raw: Bytes, dest: [u8; 16]) {
    let (header, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
    assert_eq!(header.destination_hash, dest);
    assert_eq!(
        header.context,
        rns_wire::context::PacketContext::PathResponse
    );
    rns_identity::announce::AnnounceData::unpack(&raw[offset..], header.flags.context_flag)
        .unwrap()
        .validate(&dest)
        .unwrap();
}

#[test]
fn recursive_slow_discovery_retains_authenticated_response_after_fifteen_seconds() {
    // Corrected Semtech/handheld timing from the September 6 lifetime audit:
    // RNode request67 + signed announce167, with LongModerate busy-medium wait.
    for (bitrate, busy, request_airtime, announce_airtime) in [
        (335, 7.902, 2.592768, 5.476352),
        (61, 0.0, 13.983632, 29.712146),
    ] {
        let start = now_f64();
        let clock = crate::test_clock::Clock::at(start);
        let mut actor = relay();
        let (requester, mut response_rx) = make_test_interface("requester");
        let (mut radio, mut radio_rx) = make_test_interface("slow radio");
        radio.bitrate = bitrate;
        actor.interfaces.insert(1, requester);
        actor.interfaces.insert(2, radio);
        let (announce, dest) = make_valid_announce("test.slow.discovery", 0);
        request(&mut actor, dest, 1, 1);
        assert_eq!(radio_rx.try_recv().unwrap().len(), 67);
        let deadline = actor.discovery_path_requests[&dest].timeout;
        let return_at = start + busy + request_airtime + announce_airtime;
        assert!(return_at > start + PATH_REQUEST_TIMEOUT && return_at < deadline);
        clock.set(return_at);
        actor.on_tick();
        inbound(&mut actor, announce, 2);
        assert_response(response_rx.try_recv().unwrap(), dest);
        assert!(actor.path_table.has_path(&dest));
        assert!(!actor.discovery_path_requests.contains_key(&dest));
        assert!(!actor.recursive_discovery_waiters.contains_key(&dest));
    }
}

#[test]
fn recursive_timeout_samples_only_known_online_useful_egress_and_stays_bounded() {
    for (rate, online, outbound, closed, expected) in [
        (0, true, true, false, 15.0),
        (115200, true, true, false, 15.0),
        (335, true, true, false, 8000.0 / 335.0 + 6.0),
        (61, true, true, false, 8000.0 / 61.0 + 6.0),
        (1, true, true, false, 1606.0),
        (5, true, true, false, 1606.0),
        (u64::MAX, true, true, false, 15.0),
        (1, false, true, false, 15.0),
        (1, true, false, false, 15.0),
        (1, true, true, true, 15.0),
    ] {
        let mut actor = relay();
        let (mut requester, _rx) = make_test_interface("slow requester is not recursive egress");
        requester.bitrate = 1;
        actor.interfaces.insert(1, requester);
        let (mut medium, rx) = make_test_interface("sampled medium");
        medium.bitrate = rate;
        medium.direction.outbound = outbound;
        medium.online = Some(Arc::new(AtomicBool::new(online)));
        actor.interfaces.insert(2, medium);
        let _rx = if closed {
            drop(rx);
            None
        } else {
            Some(rx)
        };
        assert!((actor.recursive_discovery_timeout(1) - expected).abs() < 1e-8);
    }
}

#[test]
fn recursive_requesters_share_one_fanout_and_response_reaches_same_radio() {
    for (mode, same_response) in [(InterfaceMode::Full, true), (InterfaceMode::Roaming, false)] {
        let start = now_f64();
        let clock = crate::test_clock::Clock::at(start);
        let mut actor = relay();
        let (first, mut first_rx) = make_test_interface("first requester");
        let (mut second, mut second_rx) = make_test_interface("radio requester");
        second.mode = mode;
        second.recursive_prs = true;
        second.bitrate = 61;
        actor.interfaces.insert(1, first);
        actor.interfaces.insert(2, second);
        let (announce, dest) = make_valid_announce("test.discovery.waiters", 0);
        request(&mut actor, dest, 1, 1);
        second_rx.try_recv().unwrap();
        let owner = actor.discovery_path_requests[&dest];
        request(&mut actor, dest, 1, 2); // Same tag is a loop, not a new waiter.
        request(&mut actor, dest, 2, 2);
        assert!(first_rx.try_recv().is_err() && second_rx.try_recv().is_err());
        clock.set(start + PATH_REQUEST_GATE_TIMEOUT + 0.001);
        actor.on_tick();
        request(&mut actor, dest, 3, 2);
        assert_eq!(actor.discovery_path_requests[&dest].timeout, owner.timeout);
        assert_eq!(actor.discovery_path_requests[&dest].requesting_interface, 1);
        assert!(second_rx.try_recv().is_err());
        inbound(&mut actor, announce.clone(), 2);
        assert_response(first_rx.try_recv().unwrap(), dest);
        if same_response {
            assert_response(second_rx.try_recv().unwrap(), dest);
        } else {
            assert!(second_rx.try_recv().is_err());
        }
        inbound(&mut actor, announce, 2);
        assert!(first_rx.try_recv().is_err() && second_rx.try_recv().is_err());
        assert!(actor.discovery_path_requests.is_empty());
    }
}

#[test]
fn recursive_expiry_and_signature_are_admission_boundaries_without_tick() {
    for remaining in [0.001, 0.0, -0.001] {
        let start = now_f64();
        let clock = crate::test_clock::Clock::at(start);
        let mut actor = relay();
        let (first, mut first_rx) = make_test_interface("requester");
        let (other, _other_rx) = make_test_interface("upstream");
        actor.interfaces.insert(1, first);
        actor.interfaces.insert(2, other);
        let (announce, dest) = make_valid_announce("test.discovery.expiry", 0);
        request(&mut actor, dest, 1, 1);
        let deadline = actor.discovery_path_requests[&dest].timeout;
        let mut forged = announce.to_vec();
        forged[103] ^= 1;
        inbound(&mut actor, Bytes::from(forged), 2);
        assert!(first_rx.try_recv().is_err());
        assert!(actor.discovery_path_requests.contains_key(&dest));
        clock.set(deadline - remaining);
        inbound(&mut actor, announce, 2);
        assert_eq!(first_rx.try_recv().is_ok(), remaining > 0.0);
        assert!(actor.discovery_path_requests.is_empty());
        assert!(
            actor.path_table.has_path(&dest),
            "late authentic announcements still learn paths"
        );
    }
}

#[test]
fn recursive_primary_replacement_keeps_other_waiters_and_legacy_records_retire() {
    let mut actor = relay();
    let (first, _first_rx) = make_test_interface("old first requester");
    let (second, mut second_rx) = make_test_interface("other requester");
    let (upstream, _upstream_rx) = make_test_interface("upstream");
    actor.interfaces.insert(1, first);
    actor.interfaces.insert(2, second);
    actor.interfaces.insert(3, upstream);
    let (announce, dest) = make_valid_announce("test.discovery.replacement", 0);
    request(&mut actor, dest, 1, 1);
    second_rx.try_recv().unwrap();
    request(&mut actor, dest, 2, 2);
    let deadline = actor.discovery_path_requests[&dest].timeout;
    actor.discovery_path_requests.insert(
        [0xEF; 16],
        DiscoveryPathRequest {
            requesting_interface: 1,
            timeout: deadline,
        },
    );
    let (replacement, mut replacement_rx) = make_test_interface("new first requester");
    actor.handle_message(TransportMessage::RegisterInterface {
        id: 1,
        entry: replacement,
    });
    assert_eq!(actor.discovery_path_requests[&dest].timeout, deadline);
    assert!(!actor.discovery_path_requests.contains_key(&[0xEF; 16]));
    inbound(&mut actor, announce, 3);
    assert_response(second_rx.try_recv().unwrap(), dest);
    assert!(replacement_rx.try_recv().is_err());
    assert!(actor.discovery_path_requests.is_empty());
}

#[test]
fn recursive_coverage_review_failed_response_target_does_not_block_other_waiter_or_keep_fanout() {
    for close_first in [false, true] {
        let start = now_f64();
        let _clock = crate::test_clock::Clock::at(start);
        let mut actor = relay();
        let (first, first_rx) = make_test_interface_with_capacity("first requester", 1);
        let (healthy, mut healthy_rx) = make_test_interface("healthy requester");
        let (upstream, mut upstream_rx) = make_test_interface_with_capacity("full upstream", 1);
        upstream
            .tx
            .try_send(Bytes::from_static(b"upstream occupied"))
            .unwrap();
        actor.interfaces.insert(1, first);
        actor.interfaces.insert(2, healthy);
        actor.interfaces.insert(3, upstream);
        let (announce, dest) = make_valid_announce("test.discovery.partial-response", 0);
        request(&mut actor, dest, 1, 1);
        healthy_rx.try_recv().unwrap(); // The original recursive fanout.
        request(&mut actor, dest, 2, 2);
        assert!(actor.has_pending_path_request_admission(dest));
        actor.interfaces[&1]
            .tx
            .try_send(Bytes::from_static(b"requester occupied"))
            .unwrap();
        let mut first_rx = if close_first {
            drop(first_rx);
            None
        } else {
            Some(first_rx)
        };

        // A valid incoming response can arrive even while that interface's
        // outbound queue is blocked. Failure to answer the first requester
        // must not steal the healthy waiter's response or retain its owner.
        inbound(&mut actor, announce.clone(), 3);
        assert_response(healthy_rx.try_recv().unwrap(), dest);
        assert!(actor.path_table.has_path(&dest));
        assert!(!actor.discovery_path_requests.contains_key(&dest));
        assert!(!actor.recursive_discovery_waiters.contains_key(&dest));
        assert_eq!(
            upstream_rx.try_recv().unwrap(),
            Bytes::from_static(b"upstream occupied")
        );
        actor.process_pending_path_request_admissions(start + 1.0);
        assert!(!actor.has_pending_path_request_admission(dest));
        assert!(
            upstream_rx.try_recv().is_err(),
            "completed discovery cannot later emit its queued request"
        );

        if let Some(rx) = &mut first_rx {
            assert_eq!(
                rx.try_recv().unwrap(),
                Bytes::from_static(b"requester occupied")
            );
        }
        inbound(&mut actor, announce, 3);
        actor.process_pending_path_request_admissions(start + 2.0);
        assert!(
            healthy_rx.try_recv().is_err(),
            "response ownership is consumed once"
        );
        assert!(
            first_rx.as_mut().is_none_or(|rx| rx.try_recv().is_err()),
            "this owner does not invent a response retransmission queue"
        );
    }
}

#[test]
fn recursive_surviving_requester_retains_refused_egress_until_its_original_deadline() {
    let mut actor = relay();
    let (first, _first_rx) = make_test_interface("first");
    let (second, mut second_rx) = make_test_interface("second");
    let (blocked, mut blocked_rx) = make_test_interface_with_capacity("blocked upstream", 1);
    blocked
        .tx
        .try_send(Bytes::from_static(b"occupied"))
        .unwrap();
    actor.interfaces.insert(1, first);
    actor.interfaces.insert(2, second);
    actor.interfaces.insert(3, blocked);
    let dest = [0xE1; 16];
    request(&mut actor, dest, 1, 1);
    second_rx.try_recv().unwrap();
    request(&mut actor, dest, 2, 2);
    assert!(actor.has_pending_path_request_admission(dest));
    let deadline = actor.discovery_path_requests[&dest].timeout;
    actor.handle_message(TransportMessage::DeregisterInterface { id: 1 });
    assert_eq!(actor.discovery_path_requests[&dest].timeout, deadline);
    blocked_rx.try_recv().unwrap();
    actor.process_pending_path_request_admissions(now_f64() + 1.0);
    assert!(blocked_rx.try_recv().is_ok());
    assert!(!actor.has_pending_path_request_admission(dest));
    actor.handle_message(TransportMessage::DeregisterInterface { id: 2 });
    assert!(actor.discovery_path_requests.is_empty());
}

#[test]
fn recursive_capacity_is_bounded_without_evicting_or_renewing_owners() {
    let now = now_f64();
    let mut actor = relay();
    let mut receivers = Vec::new();
    for id in 1..=65 {
        let (entry, rx) = make_test_interface("requester");
        actor.interfaces.insert(id, entry);
        receivers.push(rx);
    }
    let dest = [0xE2; 16];
    assert!(actor.begin_or_join_recursive_discovery(dest, 1, now));
    let deadline = actor.discovery_path_requests[&dest].timeout;
    for id in 2..=65 {
        assert!(!actor.begin_or_join_recursive_discovery(dest, id, now + 1.0));
    }
    assert_eq!(actor.discovery_path_requests[&dest].timeout, deadline);
    actor.finish_recursive_discovery(dest, b"response fixture", 99, now + 2.0);
    for rx in receivers.iter_mut().take(64) {
        assert!(rx.try_recv().is_ok());
    }
    assert!(receivers[64].try_recv().is_err());
    for id in 0u64..1024 {
        let mut key = [0xE3; 16];
        key[..8].copy_from_slice(&id.to_le_bytes());
        assert!(actor.begin_or_join_recursive_discovery(key, 1, now));
    }
    assert!(!actor.begin_or_join_recursive_discovery([0xFF; 16], 1, now));
    assert_eq!(actor.discovery_path_requests.len(), 1024);
    assert_eq!(actor.recursive_discovery_waiters.len(), 1024);
    actor.cull_recursive_discovery(now + 1607.0);
    assert!(
        actor.discovery_path_requests.is_empty() && actor.recursive_discovery_waiters.is_empty()
    );
}

#[test]
fn recursive_reset_retires_public_private_and_unadmitted_work_together() {
    for shared_reset in [false, true] {
        let mut actor = relay();
        let (first, _first_rx) = make_test_interface("first");
        let (blocked, mut blocked_rx) = make_test_interface_with_capacity("blocked", 1);
        blocked
            .tx
            .try_send(Bytes::from_static(b"occupied"))
            .unwrap();
        actor.interfaces.insert(1, first);
        actor.interfaces.insert(2, blocked);
        let dest = [0xE6; 16];
        request(&mut actor, dest, 1, 1);
        assert!(!actor.recursive_discovery_waiters.is_empty());
        assert!(actor.has_pending_path_request_admission(dest));
        if shared_reset {
            actor.clear_shared_connection_state();
        } else {
            actor.handle_query(crate::messages::TransportQuery::DropPathTable);
        }
        assert!(actor.discovery_path_requests.is_empty());
        assert!(actor.recursive_discovery_waiters.is_empty());
        assert!(!actor.has_pending_path_request_admission(dest));
        blocked_rx.try_recv().unwrap();
        actor.process_pending_path_request_admissions(now_f64() + 1.0);
        assert!(blocked_rx.try_recv().is_err());
    }
}

#[test]
fn disabling_transport_revokes_recursive_work_but_preserves_leaf_discovery() {
    let mut actor = relay();
    let (first, _first_rx) = make_test_interface("requester");
    let (blocked, mut blocked_rx) = make_test_interface_with_capacity("blocked", 1);
    blocked
        .tx
        .try_send(Bytes::from_static(b"occupied"))
        .unwrap();
    actor.interfaces.insert(1, first);
    actor.interfaces.insert(2, blocked);
    let remote = [0xE7; 16];
    let local = [0xE8; 16];
    let queued_local = [0xE9; 16];
    request(&mut actor, remote, 1, 1);
    actor.on_path_request(local);
    actor.queue_discovery_path_request(queued_local, None, now_f64());
    actor.handle_message(TransportMessage::RegisterLink {
        link_id: [0xEA; 16],
        destination_hash: [0xEB; 16],
        interface_id: 1,
        next_hop: None,
        remaining_hops: 1,
        initiator: false,
    });
    assert!(actor.has_pending_path_request_admission(remote));
    assert!(actor.has_pending_path_request_admission(local));
    actor.handle_message(TransportMessage::SetTransportEnabled { enabled: false });
    assert!(
        actor.discovery_path_requests.is_empty() && actor.recursive_discovery_waiters.is_empty()
    );
    assert!(!actor.has_pending_path_request_admission(remote));
    assert!(actor.has_pending_path_request_admission(local));
    assert_eq!(actor.pending_discovery_prs.len(), 1);
    assert!(actor.link_table.get(&[0xEA; 16]).unwrap().validated);
    blocked_rx.try_recv().unwrap();
    let assert_requested = |raw: Bytes, expected: [u8; 16]| {
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        assert_eq!(&raw[offset..offset + 16], &expected);
    };
    actor.process_pending_path_request_admissions(now_f64() + 1.0);
    assert_requested(blocked_rx.try_recv().unwrap(), local);
    actor.process_pending_discovery_path_requests(now_f64() + 1.0);
    assert_requested(blocked_rx.try_recv().unwrap(), queued_local);
    let automatic = [0xEC; 16];
    actor.on_automatic_path_request(automatic);
    assert_requested(blocked_rx.try_recv().unwrap(), automatic);
    request(&mut actor, remote, 2, 1);
    assert!(blocked_rx.try_recv().is_err());
    assert!(actor.discovery_path_requests.is_empty());
}

#[test]
fn transit_slow_proof_survives_its_actual_serialization_but_not_invalid_or_expired_state() {
    for (bitrate, exchange_seconds) in [(335, 3.510 + 4.035), (61, 19.489 + 21.848)] {
        for expired in [false, true] {
            let start = now_f64();
            let clock = crate::test_clock::Clock::at(start);
            let mut actor = relay();
            let (first, mut first_rx) = make_test_interface("initiator");
            let (mut radio, mut radio_rx) = make_test_interface("slow responder radio");
            radio.bitrate = bitrate;
            actor.interfaces.insert(1, first);
            actor.interfaces.insert(2, radio);
            let identity = rns_identity::identity::Identity::new();
            let (announce, dest) =
                make_announce_for_with_random_blob(&identity, "test.slow.link", 0, [0x22; 10]);
            inbound(&mut actor, announce, 2);
            let raw = make_header2_link_request_packet([0x44; 16], dest, 0, &[0x42; 64]);
            let link_id =
                rns_wire::hash::link_id_from_raw(&raw, rns_wire::flags::HeaderType::Header2);
            inbound(&mut actor, raw, 1);
            radio_rx.try_recv().unwrap();
            let deadline = actor.link_table.get(&link_id).unwrap().proof_timeout;
            assert!(start + exchange_seconds < deadline && exchange_seconds > 6.0);
            // Changing the advertised rate after admission cannot renew state.
            actor.interfaces.get_mut(&2).unwrap().bitrate = 1;
            clock.set(if expired {
                deadline
            } else {
                start + exchange_seconds
            });
            let proof = make_lrproof_packet(link_id, 0, &identity, None);
            let mut forged = proof.to_vec();
            forged[19] ^= 1;
            inbound(&mut actor, Bytes::from(forged), 2);
            assert!(!actor.link_table.get(&link_id).unwrap().validated);
            assert_eq!(
                actor.link_table.get(&link_id).unwrap().proof_timeout,
                deadline
            );
            assert!(first_rx.try_recv().is_err());
            inbound(&mut actor, proof, 2);
            assert_eq!(first_rx.try_recv().is_ok(), !expired);
            assert_eq!(actor.link_table.get(&link_id).unwrap().validated, !expired);
            if expired {
                inbound(&mut actor, make_link_data_packet(link_id, 0), 1);
                assert!(radio_rx.try_recv().is_err());
                let (removed, pending) = actor.link_table.cull_stale(LINK_TIMEOUT);
                assert_eq!((removed, pending.len()), (1, 1));
            } else {
                clock.set(deadline + 1.0);
                inbound(&mut actor, make_link_data_packet(link_id, 0), 1);
                assert!(
                    radio_rx.try_recv().is_ok(),
                    "validated Links use their independent idle clock"
                );
            }
        }
    }
}

#[test]
fn transit_table_capacity_and_driver_refusal_do_not_create_untracked_forwarding() {
    for full_table in [false, true] {
        let mut actor = relay();
        let (first, _first_rx) = make_test_interface("initiator");
        let (radio, mut radio_rx) = make_test_interface_with_capacity("radio", 1);
        if !full_table {
            radio.tx.try_send(Bytes::from_static(b"occupied")).unwrap();
        }
        actor.interfaces.insert(1, first);
        actor.interfaces.insert(2, radio);
        let dest = [0xE4; 16];
        actor
            .path_table
            .insert(dest, PathEntry::new(None, 1, 2, InterfaceMode::Full));
        if full_table {
            for id in 0..crate::link_table::MAX_TRANSIT_LINK_TABLE_ENTRIES {
                let mut key = [0xA0; 16];
                key[..8].copy_from_slice(&(id as u64).to_le_bytes());
                actor.link_table.insert(
                    key,
                    crate::link_table::LinkEntry {
                        timestamp: now_f64(),
                        next_hop: None,
                        interface_id: 2,
                        remaining_hops: 1,
                        destination_hash: dest,
                        established: false,
                        validated: false,
                        proof_timeout: now_f64() + 1000.0,
                        receiving_interface: 1,
                        taken_hops: 1,
                    },
                );
            }
        }
        let before = actor.link_table.len();
        inbound(
            &mut actor,
            make_header2_link_request_packet([0x44; 16], dest, 0, &[0x43; 64]),
            1,
        );
        assert_eq!(actor.link_table.len(), before);
        if !full_table {
            assert_eq!(radio_rx.try_recv().unwrap().as_ref(), b"occupied");
        }
        assert!(radio_rx.try_recv().is_err());
    }
}

#[test]
fn transit_signalling_variants_cannot_renew_or_downgrade_the_same_link_owner() {
    for validated in [false, true] {
        let start = now_f64();
        let clock = crate::test_clock::Clock::at(start);
        let mut actor = relay();
        let (first, _first_rx) = make_test_interface("initiator");
        let (mut radio, mut radio_rx) = make_test_interface("radio");
        radio.bitrate = 61;
        actor.interfaces.insert(1, first);
        actor.interfaces.insert(2, radio);
        let dest = [0xE5; 16];
        actor
            .path_table
            .insert(dest, PathEntry::new(None, 1, 2, InterfaceMode::Full));
        let first = make_header2_link_request_packet([0x44; 16], dest, 0, &[0x43; 64]);
        let mut variant = first.to_vec();
        variant.extend_from_slice(&[0x00, 0x01, 0x02]);
        let link_id =
            rns_wire::hash::link_id_from_raw(&first, rns_wire::flags::HeaderType::Header2);
        assert_eq!(
            link_id,
            rns_wire::hash::link_id_from_raw(&variant, rns_wire::flags::HeaderType::Header2)
        );
        assert_ne!(
            rns_wire::hash::packet_hash(&first, rns_wire::flags::HeaderType::Header2),
            rns_wire::hash::packet_hash(&variant, rns_wire::flags::HeaderType::Header2)
        );
        inbound(&mut actor, first, 1);
        radio_rx.try_recv().unwrap();
        let deadline = actor.link_table.get(&link_id).unwrap().proof_timeout;
        actor.link_table.get_mut(&link_id).unwrap().validated = validated;
        clock.set(start + 20.0);
        inbound(&mut actor, Bytes::from(variant), 1);
        assert!(radio_rx.try_recv().is_err());
        assert_eq!(
            actor.link_table.get(&link_id).unwrap().proof_timeout,
            deadline
        );
        assert_eq!(actor.link_table.get(&link_id).unwrap().validated, validated);
    }
}
