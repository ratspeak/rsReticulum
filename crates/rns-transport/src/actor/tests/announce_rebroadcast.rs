//! Python 1.6.1 rebroadcast rules (Transport.py): a queued announce heard
//! again on an interface off a shared medium is not sent back there
//! (`IDX_AT_DEDUP_IFS`, `blocked_interfaces`), and an unresponsive path
//! replaced by the same emission is not rebroadcast (`table_insertion_only`).
use super::*;

const APP: &str = "rebroadcast.test";

struct Hub {
    actor: TransportActor,
    rx: HashMap<InterfaceId, mpsc::Receiver<Bytes>>,
}

/// A transport node with interfaces 1–3; `shared` marks shared-medium ones.
fn hub(shared: &[InterfaceId]) -> Hub {
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    actor.transport_identity_hash = Some([0x42; 16]);
    let mut rx = HashMap::new();
    for id in [1, 2, 3] {
        let (mut entry, receiver) = make_test_interface(&format!("rebroadcast_{id}"));
        entry.ingress = crate::ingress::IngressController::disabled();
        entry.shared_medium = shared.contains(&id);
        actor.interfaces.insert(id, entry);
        rx.insert(id, receiver);
    }
    Hub { actor, rx }
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

impl Hub {
    /// Frames sent on an interface since the last call.
    fn sent(&mut self, id: InterfaceId) -> usize {
        let rx = self.rx.get_mut(&id).unwrap();
        let mut sent = 0;
        while rx.try_recv().is_ok() {
            sent += 1;
        }
        sent
    }

    fn drain(&mut self) {
        for id in [1, 2, 3] {
            self.sent(id);
        }
    }
}

fn announce(hops: u8) -> (Bytes, [u8; 16]) {
    let identity = rns_identity::identity::Identity::new();
    make_announce_for_with_random_blob(&identity, APP, hops, random_blob(0x3C, 5000))
}

#[test]
fn a_queued_announce_heard_again_off_a_shared_medium_skips_that_interface() {
    let _clock = crate::test_clock::Clock::at(1_800_000_000.0);
    let mut hub = hub(&[]);
    let (raw, destination) = announce(0);
    inbound(&mut hub.actor, &raw, 1);
    inbound(&mut hub.actor, &raw, 2);
    assert_eq!(
        hub.actor
            .announce_table
            .get(&destination)
            .unwrap()
            .dedup_interfaces,
        vec![2]
    );
    hub.drain();

    hub.actor.flush_pending_announces();

    assert_eq!(hub.sent(2), 0, "interface 2 already has it");
    assert_eq!((hub.sent(1), hub.sent(3)), (1, 1));
}

#[test]
fn a_copy_heard_on_a_shared_medium_is_still_rebroadcast_there() {
    let _clock = crate::test_clock::Clock::at(1_800_000_000.0);
    let mut hub = hub(&[2]);
    let (raw, destination) = announce(0);
    inbound(&mut hub.actor, &raw, 1);
    inbound(&mut hub.actor, &raw, 2);
    assert!(
        hub.actor
            .announce_table
            .get(&destination)
            .unwrap()
            .dedup_interfaces
            .is_empty()
    );
    hub.drain();

    hub.actor.flush_pending_announces();

    assert_eq!((hub.sent(1), hub.sent(2), hub.sent(3)), (1, 1, 1));
}

/// Only a copy of the queued packet itself counts (Transport.py compares
/// packet hashes).
#[test]
fn a_different_announce_for_the_destination_is_not_a_copy() {
    let _clock = crate::test_clock::Clock::at(1_800_000_000.0);
    let mut hub = hub(&[]);
    let identity = rns_identity::identity::Identity::new();
    let (current, destination) =
        make_announce_for_with_random_blob(&identity, APP, 0, random_blob(0x01, 5000));
    let (older, _) = make_announce_for_with_random_blob(&identity, APP, 0, random_blob(0x02, 4999));
    inbound(&mut hub.actor, &current, 1);
    inbound(&mut hub.actor, &older, 2);
    assert!(
        hub.actor
            .announce_table
            .get(&destination)
            .unwrap()
            .dedup_interfaces
            .is_empty()
    );
}

/// The path response retransmits on its attached interface whatever the
/// dedup set says (Transport.py `outbound` with `attached_interface`).
#[tokio::test(start_paused = true)]
async fn an_attached_path_response_ignores_the_dedup_set() {
    let mut hub = hub(&[]);
    let (raw, destination) = announce(1);
    let response = Bytes::from(
        hub.actor
            .path_response_from_cached_announce(&raw, destination, 1)
            .unwrap(),
    );
    let now = now_f64();
    hub.actor.announce_table.insert(
        destination,
        crate::announce::AnnounceEntry {
            timestamp: now,
            retransmit_timeout: now - 1.0,
            retries: PATHFINDER_R,
            hops: 1,
            packet_raw: response.to_vec(),
            local_rebroadcasts: 0,
            block_rebroadcast: true,
            attached_interface: Some(2),
            source_interface: None,
            packet_hash: [0; 32],
            dedup_interfaces: vec![2],
        },
    );
    hub.actor.last_announces_check = 0.0;

    hub.actor.on_tick();

    assert_eq!(hub.rx.get_mut(&2).unwrap().try_recv().unwrap(), response);
}

/// Transport.py `table_insertion_only`: the same emission with more hops
/// replaces an unresponsive path but queues no rebroadcast.
#[test]
fn an_unresponsive_path_taken_by_the_same_emission_is_not_rebroadcast() {
    let _clock = crate::test_clock::Clock::at(1_800_000_000.0);
    let mut hub = hub(&[]);
    let identity = rns_identity::identity::Identity::new();
    let blob = random_blob(0xA4, 6000);
    let (current, destination) = make_announce_for_with_random_blob(&identity, APP, 1, blob);
    let (replay, _) = make_announce_for_with_random_blob(&identity, APP, 5, blob);
    inbound(&mut hub.actor, &current, 1);
    hub.actor.announce_table.remove(&destination);
    hub.actor
        .path_table
        .set_state(destination, crate::constants::PathState::Unresponsive);

    inbound(&mut hub.actor, &replay, 2);

    let path = hub.actor.path_table.get(&destination).unwrap();
    assert_eq!((path.hops, path.interface_id), (6, 2));
    assert!(hub.actor.announce_table.get(&destination).is_none());
}
