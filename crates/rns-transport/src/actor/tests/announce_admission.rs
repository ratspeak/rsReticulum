//! Saturated real actor admission and generation ownership regressions.
use super::*;
use crate::announce_dispatch::{AnnounceDispatchRequest, AnnounceDispatchResult};
use crate::background_egress::BackgroundAnnounceReceiver;
use std::sync::atomic::Ordering;

fn limited() -> (InterfaceEntry, mpsc::Receiver<Bytes>) {
    let (mut entry, _) = make_test_interface("arbitrary name");
    let (tx, rx) = mpsc::channel(1);
    entry.tx = tx;
    (entry, rx)
}

#[test]
fn announce_admission_full_does_not_charge_or_drop_background() {
    let (mut actor, _) = TransportActor::new();
    let (entry, mut rx) = limited();
    entry.tx.try_send(Bytes::from_static(b"ordinary")).unwrap();
    actor.interfaces.insert(1, entry);
    let (raw, dest) = make_valid_announce("admission.full", 0);
    actor.local_destinations.insert(dest);
    actor.broadcast_announce_on_interfaces(&raw, None);
    let now = now_f64();
    for _ in 0..1000 {
        actor.process_announce_queues(now);
    }
    assert_eq!(actor.interfaces[&1].announce_queue.len(), 1);
    assert_eq!(actor.interfaces[&1].announce_allowed_at, 0.0);
    assert_eq!(actor.interfaces[&1].tx_drops.load(Ordering::Relaxed), 0);
    assert_eq!(rx.try_recv().unwrap(), Bytes::from_static(b"ordinary"));
    actor.process_announce_queues(now);
    assert_eq!(rx.try_recv().unwrap(), raw);
    assert!(actor.interfaces[&1].announce_queue.is_empty());
    assert!(actor.interfaces[&1].announce_allowed_at > now);
}

#[tokio::test(start_paused = true)]
async fn announce_admission_partial_targets_keep_exact_wire_without_replay() {
    let (mut actor, _) = TransportActor::new();
    let (first, mut first_rx) = limited();
    let (mut second, mut second_rx) = limited();
    second.ifac_key = Some([9; 64]);
    second.ifac_size = 16;
    second.tx.try_send(Bytes::from_static(b"ordinary")).unwrap();
    actor.interfaces.insert(1, first);
    actor.interfaces.insert(2, second);
    let (raw, dest) = make_valid_announce("admission.local", 0);
    actor.local_destinations.insert(dest);
    let expected = crate::ifac::ifac_sign(&raw, &[9; 64], 16);
    let (result, mut reply) = tokio::sync::oneshot::channel();
    actor.handle_announce_dispatch(AnnounceDispatchRequest {
        raw: raw.clone(),
        attached_interface: None,
        deadline: tokio::time::Instant::now() + Duration::from_secs(120),
        result,
    });
    assert_eq!(reply.try_recv().unwrap(), AnnounceDispatchResult::Admitted);
    assert_eq!(first_rx.try_recv().unwrap(), raw);
    assert_eq!(actor.pending_announce_admissions.len(), 1);
    assert!(actor.packet_hashlist.contains(&rns_wire::hash::packet_hash(
        &raw,
        rns_wire::flags::HeaderType::Header1
    )));
    actor.interfaces.get_mut(&2).unwrap().ifac_key = Some([7; 64]);
    second_rx.try_recv().unwrap();
    actor.process_pending_announce_admissions();
    assert_eq!(second_rx.try_recv().unwrap().as_ref(), expected);
    actor.process_pending_announce_admissions();
    assert!(first_rx.try_recv().is_err());
    assert!(second_rx.try_recv().is_err());
    assert!(actor.pending_announce_admissions.is_empty());
}

fn cache_entry(raw: &Bytes, timestamp: f64, attached: bool) -> crate::announce::AnnounceEntry {
    crate::announce::AnnounceEntry {
        timestamp,
        retransmit_timeout: timestamp,
        retries: 0,
        received_from: [0; 16],
        hops: 1,
        packet_raw: raw.to_vec(),
        local_rebroadcasts: 0,
        block_rebroadcast: attached,
        attached_interface: attached.then_some(1),
        source_interface: Some(2),
    }
}

#[tokio::test(start_paused = true)]
async fn announce_admission_cached_full_restores_only_after_acceptance_or_original_expiry() {
    for expire in [false, true] {
        let (mut actor, _) = TransportActor::new();
        let (mut entry, mut rx) = limited();
        entry.mode = InterfaceMode::AccessPoint;
        entry.tx.try_send(Bytes::from_static(b"control")).unwrap();
        actor.interfaces.insert(1, entry);
        let (raw, dest) = make_valid_announce("admission.cached", 1);
        let response = Bytes::from(
            actor
                .path_response_from_cached_announce(&raw, dest, 1)
                .unwrap(),
        );
        let timestamp = now_f64();
        actor
            .announce_table
            .insert(dest, cache_entry(&response, timestamp, true));
        actor
            .held_announces
            .insert(dest, cache_entry(&raw, timestamp, false));
        actor.admit_cached_response(dest, 1, &response, timestamp);
        for _ in 0..100 {
            actor.admit_cached_response(dest, 1, &response, timestamp);
        }
        assert_eq!(actor.pending_announce_admissions.len(), 1);
        assert!(actor.announce_table.get(&dest).unwrap().block_rebroadcast);
        assert!(actor.held_announces.contains_key(&dest));
        if expire {
            tokio::time::advance(Duration::from_secs(121)).await;
        }
        rx.try_recv().unwrap();
        actor.process_pending_announce_admissions();
        if expire {
            assert!(rx.try_recv().is_err());
        } else {
            assert_eq!(rx.try_recv().unwrap(), response);
        }
        assert!(!actor.announce_table.get(&dest).unwrap().block_rebroadcast);
        assert_eq!(actor.announce_table.get(&dest).unwrap().packet_raw, raw);
        assert!(!actor.held_announces.contains_key(&dest));
    }
}

#[tokio::test(start_paused = true)]
async fn announce_admission_replaced_channel_and_cancelled_publisher_cannot_replay() {
    for cancel in [true, false] {
        let (mut actor, _) = TransportActor::new();
        let (entry, mut old_rx) = limited();
        entry.tx.try_send(Bytes::from_static(b"control")).unwrap();
        actor.interfaces.insert(1, entry);
        let (raw, dest) = make_valid_announce("admission.owner", 0);
        actor.local_destinations.insert(dest);
        let (result, reply) = tokio::sync::oneshot::channel();
        actor.handle_announce_dispatch(AnnounceDispatchRequest {
            raw,
            attached_interface: None,
            deadline: tokio::time::Instant::now() + Duration::from_secs(120),
            result,
        });
        let mut replacement_rx = None;
        if cancel {
            drop(reply);
        } else {
            let (entry, rx) = limited();
            actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry });
            replacement_rx = Some(rx);
            assert_eq!(reply.await.unwrap(), AnnounceDispatchResult::Expired);
        }
        old_rx.try_recv().unwrap();
        actor.process_pending_announce_admissions();
        assert!(old_rx.try_recv().is_err());
        assert!(
            replacement_rx
                .as_mut()
                .is_none_or(|rx| rx.try_recv().is_err())
        );
        assert!(actor.pending_announce_admissions.is_empty());
    }
}

#[test]
fn announce_admission_background_generation_and_route_retire_before_selection() {
    let (mut actor, _) = TransportActor::new();
    let (entry, _rx) = limited();
    let lane = BackgroundAnnounceReceiver::register(&entry.tx).unwrap();
    actor.interfaces.insert(1, entry);
    let (raw, dest) = make_valid_announce("admission.route", 1);
    let mut path = PathEntry::new(Some([1; 16]), 1, 1, InterfaceMode::Full);
    path.packet_hash = Some(rns_wire::hash::packet_hash(
        &raw,
        rns_wire::flags::HeaderType::Header1,
    ));
    actor.path_table.insert(dest, path.clone());
    actor.broadcast_announce_on_interfaces(&raw, None);
    actor.process_announce_queues(now_f64());
    assert!(lane.has_offer());
    lane.retire_generation();
    assert!(lane.try_start(now_f64()).is_none());
    actor.process_background_starts();
    actor.process_announce_queues(now_f64());
    assert!(lane.has_offer());
    path.next_hop = Some([2; 16]);
    actor.path_table.insert(dest, path);
    actor.process_background_starts();
    assert!(lane.try_start(now_f64()).is_none());
    assert!(actor.interfaces[&1].announce_queue.is_empty());
    assert_eq!(actor.interfaces[&1].announce_allowed_at, 0.0);
}

#[tokio::test]
async fn announce_admission_old_cached_generation_cannot_retire_a_replacement() {
    let (mut actor, _) = TransportActor::new();
    let (entry, mut rx) = limited();
    entry.tx.try_send(Bytes::from_static(b"control")).unwrap();
    actor.interfaces.insert(1, entry);
    let (raw, dest) = make_valid_announce("admission.cached.generation", 1);
    let response = Bytes::from(
        actor
            .path_response_from_cached_announce(&raw, dest, 1)
            .unwrap(),
    );
    let timestamp = now_f64();
    actor
        .announce_table
        .insert(dest, cache_entry(&response, timestamp, true));
    actor.admit_cached_response(dest, 1, &response, timestamp);
    // A new requester operation can legitimately reuse identical signed bytes.
    actor
        .announce_table
        .insert(dest, cache_entry(&response, timestamp + 0.5, true));
    rx.try_recv().unwrap();
    actor.process_pending_announce_admissions();
    assert!(rx.try_recv().is_err());
    assert_eq!(
        actor.announce_table.get(&dest).unwrap().timestamp,
        timestamp + 0.5
    );
    actor.admit_cached_response(dest, 1, &response, timestamp + 0.5);
    assert_eq!(rx.try_recv().unwrap(), response);
    assert!(actor.announce_table.get(&dest).is_none());
}

#[test]
fn announce_admission_offer_policy_change_and_coalescing_keep_original_queue_ownership() {
    let (mut actor, _) = TransportActor::new();
    let (entry, _rx) = limited();
    let lane = BackgroundAnnounceReceiver::register(&entry.tx).unwrap();
    actor.interfaces.insert(1, entry);
    let identity = rns_identity::identity::Identity::new();
    let (raw, dest) =
        make_announce_for_with_random_blob(&identity, "admission.coalesce", 1, random_blob(1, 20));
    actor.local_destinations.insert(dest);
    actor.broadcast_announce_on_interfaces(&raw, None);
    actor.process_announce_queues(now_f64());
    let original_time = actor.interfaces[&1].announce_queue[0].time;
    actor.interfaces.get_mut(&1).unwrap().bitrate = 61;
    actor.interfaces.get_mut(&1).unwrap().announce_cap = 0.01;
    actor.process_background_starts();
    assert!(lane.try_start(now_f64()).is_none());
    assert_eq!(actor.interfaces[&1].announce_queue[0].time, original_time);
    actor.process_announce_queues(now_f64());
    let (new, _) =
        make_announce_for_with_random_blob(&identity, "admission.coalesce", 1, random_blob(2, 21));
    actor.broadcast_announce_on_interfaces(&new, None);
    actor.process_background_starts();
    assert!(lane.try_start(now_f64()).is_none());
    actor.process_announce_queues(now_f64());
    let started = now_f64();
    let packet = lane.try_start(started).unwrap();
    assert_eq!(packet.raw(), &new);
    actor.process_background_starts();
    assert!(
        (actor.interfaces[&1].announce_allowed_at - started - new.len() as f64 * 8.0 / 61.0 / 0.01)
            .abs()
            < 1e-6
    );
    assert!(actor.interfaces[&1].announce_queue.is_empty());
}

#[test]
fn announce_admission_retry_limit_keeps_cached_table_owner_and_original_deadline() {
    let (mut actor, _) = TransportActor::new();
    let (entry, mut rx) = limited();
    entry.tx.try_send(Bytes::from_static(b"ordinary")).unwrap();
    actor.interfaces.insert(1, entry);
    for value in 0u8..=255 {
        actor.send_or_retain_announce(1, &[value], true);
    }
    assert_eq!(actor.pending_announce_admissions.len(), 256);
    let (raw, dest) = make_valid_announce("admission.pending.limit", 0);
    let timestamp = now_f64();
    actor
        .announce_table
        .insert(dest, cache_entry(&raw, timestamp, true));
    actor.admit_cached_response(dest, 1, &raw, timestamp);
    assert_eq!(actor.pending_announce_admissions.len(), 256);
    assert_eq!(
        actor.announce_table.get(&dest).unwrap().timestamp,
        timestamp
    );
    rx.try_recv().unwrap();
    actor.process_pending_announce_admissions();
    actor.admit_cached_response(dest, 1, &raw, timestamp);
    let mut delivered = false;
    for _ in 0..512 {
        if let Ok(packet) = rx.try_recv() {
            delivered |= packet == raw;
        }
        actor.process_pending_announce_admissions();
    }
    assert!(delivered);
    assert!(actor.announce_table.get(&dest).is_none());
    assert!(actor.pending_announce_admissions.is_empty());
}

#[tokio::test]
async fn announce_admission_old_local_registration_cannot_send_after_same_hash_replacement() {
    let (mut actor, _) = TransportActor::new();
    let (entry, mut rx) = limited();
    entry.tx.try_send(Bytes::from_static(b"ordinary")).unwrap();
    actor.interfaces.insert(1, entry);
    let (raw, dest) = make_valid_announce("admission.registration.generation", 0);
    let (old, _old_events) = mpsc::channel(1);
    actor.local_destinations.insert(dest);
    actor.destination_channels.insert(dest, old);
    let (result, response) = tokio::sync::oneshot::channel();
    actor.handle_announce_dispatch(AnnounceDispatchRequest {
        raw,
        attached_interface: None,
        deadline: tokio::time::Instant::now() + Duration::from_secs(120),
        result,
    });
    let (replacement, _new_events) = mpsc::channel(1);
    actor.destination_channels.insert(dest, replacement);
    rx.try_recv().unwrap();
    actor.process_pending_announce_admissions();
    assert_eq!(response.await.unwrap(), AnnounceDispatchResult::Expired);
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn announce_admission_rpc_revokes_unstarted_offer_before_acknowledgement() {
    for operation in 0..4 {
        let (mut actor, _) = TransportActor::new();
        let (entry, _rx) = limited();
        let lane = BackgroundAnnounceReceiver::register(&entry.tx).unwrap();
        actor.interfaces.insert(1, entry);
        let (raw, dest) = make_valid_announce("admission.rpc.revocation", 1);
        actor.path_table.insert(
            dest,
            PathEntry::new(Some([1; 16]), 1, 1, InterfaceMode::Full),
        );
        actor.broadcast_announce_on_interfaces(&raw, None);
        actor.process_announce_queues(now_f64());
        assert!(lane.has_offer());
        let query = match operation {
            0 => TransportQuery::DropAnnounceQueues,
            1 => TransportQuery::DropPath { dest },
            2 => TransportQuery::DropPathTable,
            _ => TransportQuery::DropAllVia { next_hop: [1; 16] },
        };
        let (response_tx, response) = tokio::sync::oneshot::channel();
        actor.handle_message(TransportMessage::Rpc { query, response_tx });
        response.await.unwrap();
        assert!(
            lane.try_start(now_f64()).is_none(),
            "RPC operation {operation} must revoke without another tick"
        );
    }
}

#[test]
fn announce_admission_disable_transport_preserves_local_announcement_progress() {
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    let (entry, mut rx) = limited();
    let lane = BackgroundAnnounceReceiver::register(&entry.tx).unwrap();
    actor.interfaces.insert(1, entry);
    let (raw, dest) = make_valid_announce("admission.disable", 0);
    actor.local_destinations.insert(dest);
    actor.broadcast_announce_on_interfaces(&raw, None);
    actor.process_announce_queues(now_f64());
    actor.handle_message(TransportMessage::SetTransportEnabled { enabled: false });
    assert!(lane.try_start(now_f64()).is_none());
    assert!(actor.send_or_retain_announce(1, &raw, false));
    assert_eq!(rx.try_recv().unwrap(), raw);
}

#[tokio::test]
async fn announce_admission_failed_route_recovery_revokes_before_result() {
    let (mut actor, _) = TransportActor::new();
    let (entry, _rx) = limited();
    let lane = BackgroundAnnounceReceiver::register(&entry.tx).unwrap();
    actor.interfaces.insert(1, entry);
    let (raw, dest) = make_valid_announce("admission.recovery.revocation", 1);
    actor.path_table.insert(
        dest,
        PathEntry::new(Some([1; 16]), 1, 1, InterfaceMode::Full),
    );
    let attempt = crate::path_recovery::FailedRouteAttempt::Link([9; 16]);
    actor.record_route_attempt(attempt, dest);
    actor.broadcast_announce_on_interfaces(&raw, None);
    actor.process_announce_queues(now_f64());
    let (result_tx, result) = tokio::sync::oneshot::channel();
    actor.recover_local_link_path(crate::path_recovery::PathRecoveryRequest {
        destination_hash: dest,
        failed_attempt: Some(attempt),
        schedule_discovery: false,
        result_tx,
    });
    assert!(result.await.unwrap().path_dropped);
    assert!(lane.try_start(now_f64()).is_none());
}

#[test]
fn announce_admission_cache_replay_reconciles_route_before_early_return() {
    let directory = unique_temp_dir("announce-cache-revocation");
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    actor.transport_identity_hash = Some([0x55; 16]);
    actor.storage_dir = Some(directory.clone());
    let (entry, _rx) = limited();
    let lane = BackgroundAnnounceReceiver::register(&entry.tx).unwrap();
    actor.interfaces.insert(1, entry);
    let identity = rns_identity::identity::Identity::new();
    let emitted = now_f64() as u64;
    let (old, dest) = make_announce_for_with_random_blob(
        &identity,
        "admission.cache.revocation",
        1,
        random_blob(1, emitted - 1),
    );
    actor.path_table.insert(
        dest,
        PathEntry::new(Some([1; 16]), 1, 1, InterfaceMode::Full),
    );
    actor.broadcast_announce_on_interfaces(&old, None);
    actor.process_announce_queues(now_f64());
    let (fresh, _) = make_announce_for_with_random_blob(
        &identity,
        "admission.cache.revocation",
        1,
        random_blob(2, emitted),
    );
    let packet_hash = rns_wire::hash::packet_hash(&fresh, rns_wire::flags::HeaderType::Header1);
    crate::persistence::write_python_cached_announce_if_absent(
        &directory.join("cache").join("announces"),
        &packet_hash,
        &fresh,
        None,
    )
    .unwrap();
    actor.handle_message(TransportMessage::CacheRequest {
        packet_hash,
        destination_hash: dest,
    });
    assert_eq!(
        actor.path_table.get_live(&dest).unwrap().packet_hash,
        Some(packet_hash)
    );
    assert!(lane.try_start(now_f64()).is_none());
    std::fs::remove_dir_all(directory).unwrap();
}
