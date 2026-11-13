//! Discovery ownership through the actor's public methods, on an actor that is not running.
use super::*;
use crate::path_discovery::DiscoveryError;

fn actor() -> (TransportActor, Vec<mpsc::Receiver<Bytes>>) {
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    let mut receivers = Vec::new();
    for id in 1..=3 {
        let (tx, rx) = mpsc::channel(64);
        let mut entry = InterfaceEntry::new(
            "public discovery".into(),
            InterfaceMode::Full,
            InterfaceDirection::bidirectional(),
            61,
            500,
            tx,
        );
        entry.recursive_prs = true;
        actor.interfaces.insert(id, entry);
        receivers.push(rx);
    }
    (actor, receivers)
}

#[test]
fn detached_snapshot_is_complete_and_coalescing_emits_one_fanout() {
    let (mut actor, mut rx) = actor();
    let dest = [0x21; 16];
    let first = actor.request_recursive_discovery(dest, 1).unwrap();
    assert!(first.started());
    assert!(rx[0].try_recv().is_err());
    let raw = rx[1].try_recv().unwrap();
    assert_eq!(raw, rx[2].try_recv().unwrap());
    let snapshot: DiscoveryPathRequest = actor.discovery_path_request(&dest).unwrap();
    let second = actor.request_recursive_discovery(dest, 2).unwrap();
    assert!(!second.started());
    assert_eq!(snapshot.requesters().len(), 1);
    let current = actor.discovery_path_request(&dest).unwrap();
    assert_eq!(current.destination_hash(), dest);
    assert_eq!(current.deadline(), snapshot.deadline());
    assert_eq!(
        current.requesters(),
        &[first.requester().clone(), second.requester().clone()]
    );
    assert!(rx.iter_mut().all(|rx| rx.try_recv().is_err()));
    let again = actor.request_recursive_discovery(dest, 2).unwrap();
    assert!(!again.started());
    assert_eq!(again.requester(), second.requester());
    assert!(actor.cancel_discovery_requester(first.requester()));
    assert_eq!(
        actor.discovery_path_request(&dest).unwrap().requesters(),
        &[second.requester().clone()]
    );
    assert_eq!(
        current.requesters().len(),
        2,
        "retained snapshot is detached"
    );
}

#[test]
fn old_or_foreign_tokens_cannot_cancel_new_owner() {
    let (mut first, _rx) = actor();
    let (mut other, _other_rx) = actor();
    let dest = [0x22; 16];
    let old = first.request_recursive_discovery(dest, 1).unwrap();
    let foreign = other.request_recursive_discovery(dest, 1).unwrap();
    assert!(!first.cancel_discovery_requester(foreign.requester()));
    assert!(first.cancel_discovery_requester(old.requester()));
    let new = first.request_recursive_discovery(dest, 1).unwrap();
    assert!(new.started());
    assert!(!first.cancel_discovery_requester(old.requester()));
    assert!(first.cancel_discovery_requester(new.requester()));
    assert!(first.discovery_path_requests().is_empty());
    assert!(other.discovery_path_request(&dest).is_some());
}

#[test]
fn public_admission_reports_disabled_missing_and_unavailable_interfaces() {
    let (mut actor, mut rx) = actor();
    let dest = [0x23; 16];
    actor.is_transport_enabled = false;
    assert_eq!(
        actor.request_recursive_discovery(dest, 1).unwrap_err(),
        DiscoveryError::TransportDisabled
    );
    actor.is_transport_enabled = true;
    assert_eq!(
        actor.request_recursive_discovery(dest, 99).unwrap_err(),
        DiscoveryError::UnknownInterface
    );
    actor.interfaces.get_mut(&1).unwrap().direction.outbound = false;
    assert_eq!(
        actor.request_recursive_discovery(dest, 1).unwrap_err(),
        DiscoveryError::InterfaceUnavailable
    );
    rx.remove(1);
    assert_eq!(
        actor.request_recursive_discovery(dest, 2).unwrap_err(),
        DiscoveryError::InterfaceUnavailable
    );
    assert!(actor.discovery_path_requests().is_empty());
    assert!(rx.iter_mut().all(|rx| rx.try_recv().is_err()));
}

#[test]
fn no_local_destination_or_ipc_discovery_bypass() {
    let (mut actor, _rx) = actor();
    let dest = [0x24; 16];
    actor.local_destinations.insert(dest);
    assert_eq!(
        actor.request_recursive_discovery(dest, 1).unwrap_err(),
        DiscoveryError::KnownDestination
    );
    actor.local_destinations.remove(&dest);
    actor.interfaces.get_mut(&1).unwrap().role = InterfaceRole::LocalClient;
    assert_eq!(
        actor.request_recursive_discovery(dest, 1).unwrap_err(),
        DiscoveryError::PolicyDenied
    );
    assert!(actor.discovery_path_requests().is_empty());
}

#[test]
fn direct_interface_replacement_cannot_retarget_an_old_token() {
    let (mut actor, _rx) = actor();
    let dest = [0x25; 16];
    let old = actor.request_recursive_discovery(dest, 1).unwrap();
    let second = actor.request_recursive_discovery(dest, 2).unwrap();
    // Advanced owners can still change interface entries; discovery must not
    // rely solely on cooperative registration hooks to reject ID reuse.
    let (tx, _replacement_rx) = mpsc::channel(4);
    actor.interfaces.get_mut(&1).unwrap().tx = tx;
    assert_eq!(
        actor.discovery_path_request(&dest).unwrap().requesters(),
        &[second.requester().clone()]
    );
    let replacement = actor.request_recursive_discovery(dest, 1).unwrap();
    assert!(!actor.cancel_discovery_requester(old.requester()));
    assert!(actor.cancel_discovery_requester(replacement.requester()));
    assert_eq!(
        actor.discovery_path_request(&dest).unwrap().requesters(),
        &[second.requester().clone()]
    );
}
