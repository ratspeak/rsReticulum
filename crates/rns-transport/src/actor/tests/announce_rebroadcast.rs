//! Python 1.6.1 rebroadcast rules (Transport.py): an unresponsive path
//! replaced by the same emission is not rebroadcast (`table_insertion_only`).
use super::*;

const APP: &str = "rebroadcast.test";

fn inbound(actor: &mut TransportActor, raw: &Bytes, interface_id: InterfaceId) {
    actor.on_inbound(InboundPacket {
        raw: raw.clone(),
        interface_id,
        rssi: None,
        snr: None,
        q: None,
    });
}

/// Transport.py `table_insertion_only`: the same emission with more hops
/// replaces an unresponsive path but queues no rebroadcast.
#[test]
fn an_unresponsive_path_taken_by_the_same_emission_is_not_rebroadcast() {
    let _clock = crate::test_clock::Clock::at(1_800_000_000.0);
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    actor.transport_identity_hash = Some([0x42; 16]);
    let mut rx = Vec::new();
    for id in [1, 2] {
        let (entry, receiver) = make_test_interface(&format!("rebroadcast_{id}"));
        actor.interfaces.insert(id, entry);
        rx.push(receiver);
    }
    let identity = rns_identity::identity::Identity::new();
    let blob = random_blob(0xA4, 6000);
    let (current, destination) = make_announce_for_with_random_blob(&identity, APP, 1, blob);
    let (replay, _) = make_announce_for_with_random_blob(&identity, APP, 5, blob);
    inbound(&mut actor, &current, 1);
    actor.announce_table.remove(&destination);
    actor
        .path_table
        .set_state(destination, crate::constants::PathState::Unresponsive);

    inbound(&mut actor, &replay, 2);

    let path = actor.path_table.get(&destination).unwrap();
    assert_eq!((path.hops, path.interface_id), (6, 2));
    assert!(actor.announce_table.get(&destination).is_none());
}
