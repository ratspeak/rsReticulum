//! Held and cached announces re-enter inbound processing as Python
//! re-injects them: past IFAC, without counting their bytes again
//! (Interface.py:296, Transport.py:3107-3119).
use super::*;
use crate::ingress::HeldAnnounce;

fn ifac_hub() -> (TransportActor, mpsc::Receiver<Bytes>) {
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    actor.transport_identity_hash = Some([0x42; 16]);
    let (mut entry, rx) = make_test_interface("held_ifac");
    entry.ifac_key =
        Some(rns_identity::ifac::derive_ifac_key(Some("held"), Some("announces")).unwrap());
    entry.ifac_size = 8;
    actor.interfaces.insert(1, entry);
    (actor, rx)
}

fn rx_bytes(actor: &TransportActor, id: InterfaceId) -> u64 {
    actor.traffic.get(&id).map_or(0, |traffic| traffic.rx_bytes)
}

/// The interface keeps the announce it held as it was after IFAC, so its
/// release must not verify IFAC again.
fn hold(actor: &mut TransportActor, raw: Bytes, destination_hash: [u8; 16]) {
    actor
        .interfaces
        .get_mut(&1)
        .unwrap()
        .ingress
        .hold_announce(HeldAnnounce {
            raw,
            destination_hash,
            hops: 1,
            receiving_interface_id: 1,
        });
}

fn release_held(actor: &mut TransportActor) {
    actor.last_held_announce_check = 0.0;
    actor.on_tick();
}

#[test]
fn a_released_held_announce_on_an_ifac_interface_installs_its_path() {
    let (mut actor, _rx) = ifac_hub();
    let (announce, destination) = make_valid_announce("held.ifac.release", 1);
    hold(&mut actor, announce, destination);
    let received_before = actor.interfaces[&1].ingress.announces_received();

    release_held(&mut actor);

    assert!(
        actor.path_table.has_path(&destination),
        "the released announce installs its path"
    );
    assert_eq!(actor.interfaces[&1].ingress.held_count(), 0);
    assert_eq!(
        actor.interfaces[&1].ingress.announces_received(),
        received_before + 1,
        "Python runs received_announce again on release (Transport.py:1811)"
    );
    assert_eq!(actor.interfaces[&1].ifac_violations, 0);
}

#[test]
fn a_released_held_announce_is_not_counted_as_received_traffic() {
    let (mut actor, _rx) = ifac_hub();
    let (announce, destination) = make_valid_announce("held.ifac.traffic", 1);
    hold(&mut actor, announce, destination);
    let before = rx_bytes(&actor, 1);

    release_held(&mut actor);

    assert!(actor.path_table.has_path(&destination));
    assert_eq!(rx_bytes(&actor, 1), before, "the held bytes arrived once");
}

/// IFAC runs before the ingress hold, so a wire announce without valid IFAC
/// is dropped even during a burst, and never held for a release that skips
/// IFAC.
#[test]
fn a_wire_announce_without_valid_ifac_is_dropped_and_never_held() {
    let (mut actor, _rx) = ifac_hub();
    let ingress = &mut actor.interfaces.get_mut(&1).unwrap().ingress;
    for _ in 0..50 {
        ingress.received_announce();
    }
    assert!(ingress.should_ingress_limit(), "precondition: a burst");
    let ifac_key = actor.interfaces[&1].ifac_key.unwrap();
    let (signed, signed_destination) = make_valid_announce("held.ifac.signed", 1);
    let (unsigned, unsigned_destination) = make_valid_announce("held.ifac.unsigned", 1);

    for raw in [
        Bytes::from(crate::ifac::ifac_sign(&signed, &ifac_key, 8)),
        unsigned,
    ] {
        actor.on_inbound(InboundPacket {
            raw,
            interface_id: 1,
            rssi: None,
            snr: None,
            q: None,
        });
    }

    assert_eq!(
        actor.interfaces[&1].ingress.held_count(),
        1,
        "only the announce with valid IFAC is held"
    );
    assert_eq!(actor.interfaces[&1].ifac_violations, 1);
    assert!(
        !actor.path_table.has_path(&signed_destination),
        "held, not processed"
    );
    assert!(!actor.path_table.has_path(&unsigned_destination));
}

#[test]
fn a_replayed_cached_announce_is_not_counted_as_received_traffic() {
    let (mut actor, _) = TransportActor::new();
    let (entry, _rx) = make_test_interface("cache_replay");
    actor.interfaces.insert(1, entry);
    let (announce, destination) = make_valid_announce("held.cache.replay", 1);

    actor.on_cached_announce(InboundPacket {
        raw: announce,
        interface_id: 1,
        rssi: None,
        snr: None,
        q: None,
    });

    assert!(actor.path_table.has_path(&destination));
    assert_eq!(
        rx_bytes(&actor, 1),
        0,
        "a cached announce never crossed the wire"
    );
}
