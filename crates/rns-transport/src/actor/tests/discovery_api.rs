//! Deterministic deadlines and production lifecycle around the public API.
use super::*;
use crate::path_discovery::DiscoveryError;

fn relay() -> (TransportActor, Vec<mpsc::Receiver<Bytes>>) {
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    let mut receivers = Vec::new();
    for id in 1..=3 {
        let (mut entry, rx) = make_test_interface("discovery API");
        entry.recursive_prs = true;
        actor.interfaces.insert(id, entry);
        receivers.push(rx);
    }
    (actor, receivers)
}

#[test]
fn snapshot_expiry_and_stale_cancellation_need_no_tick() {
    let clock = crate::test_clock::Clock::at(1000.0);
    let (mut actor, _rx) = relay();
    let dest = [1; 16];
    let admitted = actor.request_recursive_discovery(dest, 1).unwrap();
    let snapshot = actor.discovery_path_request(&dest).unwrap();
    clock.set(snapshot.deadline() - 0.001);
    assert!(actor.discovery_path_request(&dest).is_some());
    clock.set(snapshot.deadline());
    assert!(actor.discovery_path_request(&dest).is_none());
    assert!(actor.discovery_path_requests().is_empty());
    assert!(!actor.cancel_discovery_requester(admitted.requester()));
    let next = actor.request_recursive_discovery(dest, 1).unwrap();
    assert!(next.started());
    assert_ne!(next.requester(), admitted.requester());
    assert!(!actor.cancel_discovery_requester(admitted.requester()));
    assert_eq!(snapshot.requesters(), &[admitted.requester().clone()]);
}

#[test]
fn replacement_snapshot_and_cancellation_keep_only_surviving_generations() {
    let (mut actor, _rx) = relay();
    let dest = [2; 16];
    let first = actor.request_recursive_discovery(dest, 1).unwrap();
    let second = actor.request_recursive_discovery(dest, 2).unwrap();
    let before = actor.discovery_path_request(&dest).unwrap();
    let (mut replacement, mut replacement_rx) = make_test_interface("replacement");
    replacement.recursive_prs = true;
    actor.handle_message(TransportMessage::RegisterInterface {
        id: 1,
        entry: replacement,
    });
    let after = actor.discovery_path_request(&dest).unwrap();
    assert_eq!(after.requesters(), &[second.requester().clone()]);
    assert_eq!(after.deadline(), before.deadline());
    assert_eq!(before.requesters().len(), 2);
    assert!(!actor.cancel_discovery_requester(first.requester()));
    let new = actor.request_recursive_discovery(dest, 1).unwrap();
    assert!(!new.started());
    assert_ne!(first.requester(), new.requester());
    assert!(!actor.cancel_discovery_requester(first.requester()));
    assert!(replacement_rx.try_recv().is_err());
    assert!(actor.cancel_discovery_requester(new.requester()));
    assert_eq!(
        actor.discovery_path_request(&dest).unwrap().requesters(),
        &[second.requester().clone()]
    );
}

#[test]
fn cancellation_and_rejoin_cannot_reuse_old_token_in_same_operation() {
    let (mut actor, _rx) = relay();
    let dest = [3; 16];
    let first = actor.request_recursive_discovery(dest, 1).unwrap();
    let _second = actor.request_recursive_discovery(dest, 2).unwrap();
    let deadline = actor.discovery_path_request(&dest).unwrap().deadline();
    assert!(actor.cancel_discovery_requester(first.requester()));
    let rejoined = actor.request_recursive_discovery(dest, 1).unwrap();
    assert!(!rejoined.started());
    assert_ne!(first.requester(), rejoined.requester());
    assert!(!actor.cancel_discovery_requester(first.requester()));
    assert_eq!(
        actor.discovery_path_request(&dest).unwrap().deadline(),
        deadline
    );
    assert_eq!(
        actor
            .discovery_path_request(&dest)
            .unwrap()
            .requesters()
            .len(),
        2
    );
}

#[test]
fn last_cancellation_retires_unadmitted_fanout_without_touching_leaf_work() {
    let (mut actor, _rx) = relay();
    let (blocked, mut blocked_rx) = make_test_interface_with_capacity("blocked", 1);
    blocked
        .tx
        .try_send(Bytes::from_static(b"occupied"))
        .unwrap();
    actor.interfaces.insert(3, blocked);
    let dest = [4; 16];
    let first = actor.request_recursive_discovery(dest, 1).unwrap();
    let second = actor.request_recursive_discovery(dest, 2).unwrap();
    let leaf = [5; 16];
    actor.on_path_request(leaf);
    assert!(actor.has_pending_path_request_admission(dest));
    assert!(actor.has_pending_path_request_admission(leaf));
    assert!(actor.cancel_discovery_requester(first.requester()));
    assert!(actor.has_pending_path_request_admission(dest));
    assert!(actor.cancel_discovery_requester(second.requester()));
    assert!(!actor.has_pending_path_request_admission(dest));
    assert!(actor.has_pending_path_request_admission(leaf));
    blocked_rx.try_recv().unwrap();
    actor.process_pending_path_request_admissions(now_f64() + 1.0);
    let leaf_raw = blocked_rx.try_recv().unwrap();
    assert!(leaf_raw.windows(16).any(|window| window == leaf));
    assert!(blocked_rx.try_recv().is_err());
}

#[test]
fn public_capacity_errors_do_not_evict_or_renew_owners() {
    let now = now_f64();
    let (mut actor, mut receivers) = relay();
    let dest = [6; 16];
    for id in 4..=65 {
        let (mut entry, rx) = make_test_interface("requester");
        entry.recursive_prs = true;
        actor.interfaces.insert(id, entry);
        receivers.push(rx);
    }
    for id in 1..=64 {
        actor.begin_or_join_recursive_discovery(dest, id, now);
    }
    let before = actor.discovery_path_request(&dest).unwrap();
    assert_eq!(
        actor.request_recursive_discovery(dest, 65).unwrap_err(),
        DiscoveryError::Capacity
    );
    assert_eq!(
        actor.discovery_path_request(&dest).unwrap().deadline(),
        before.deadline()
    );
    assert_eq!(
        actor.discovery_path_request(&dest).unwrap().requesters(),
        before.requesters()
    );
    for n in 1u64..1024 {
        let mut key = [0; 16];
        key[..8].copy_from_slice(&n.to_le_bytes());
        assert!(actor.begin_or_join_recursive_discovery(key, 1, now));
    }
    assert_eq!(
        actor
            .request_recursive_discovery([0xff; 16], 65)
            .unwrap_err(),
        DiscoveryError::Capacity
    );
    assert_eq!(actor.discovery_path_requests().len(), 1024);
}

#[test]
fn invalid_clock_cannot_admit_or_renew_discovery() {
    let clock = crate::test_clock::Clock::at(1000.0);
    let (mut actor, _rx) = relay();
    let dest = [7; 16];
    let first = actor.request_recursive_discovery(dest, 1).unwrap();
    let deadline = actor.discovery_path_request(&dest).unwrap().deadline();
    for invalid in [f64::NAN, f64::INFINITY, f64::MAX] {
        clock.set(invalid);
        assert_eq!(
            actor.request_recursive_discovery([8; 16], 2).unwrap_err(),
            DiscoveryError::InvalidClock
        );
    }
    clock.set(1001.0);
    assert_eq!(
        actor.discovery_path_request(&dest).unwrap().deadline(),
        deadline
    );
    assert!(actor.cancel_discovery_requester(first.requester()));
}
