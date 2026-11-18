//! Held and cached announces re-enter inbound processing as Python
//! re-injects them: past IFAC (Interface.py, Transport.py).
use super::*;
use crate::ingress::HeldAnnounce;

fn ifac_hub() -> (TransportActor, mpsc::Receiver<Bytes>) {
    let (mut actor, _) = TransportActor::new();
    actor.is_transport_enabled = true;
    actor.transport_identity_hash = Some([0x42; 16]);
    let (mut entry, rx) = make_test_interface("held_ifac");
    entry.ifac_key =
        Some(rns_identity::ifac::IfacKey::derive(Some("held"), Some("announces")).unwrap());
    entry.ifac_size = 8;
    actor.interfaces.insert(1, entry);
    (actor, rx)
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

/// The tick queues the release as ingress limited; the actor then drains it.
fn release_held(actor: &mut TransportActor) {
    actor.last_held_announce_check = 0.0;
    actor.on_tick();
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    while let std::task::Poll::Ready((class, item)) =
        actor.inbound_rx.poll_recv(&mut cx, &actor.inbound_queues)
    {
        assert_eq!(class, crate::inbound_queues::TrafficClass::IngressLimited);
        actor.handle_inbound_event(item);
    }
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
    let ifac_key = actor.interfaces[&1].ifac_key.clone().unwrap();
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

/// Python's 5 s interface job re-evaluates the limiter (Transport.py),
/// so a burst clears on a quiet interface without another announce.
#[test]
fn interface_job_clears_a_burst_on_a_quiet_interface() {
    let (mut actor, _) = TransportActor::new();
    let (mut entry, _rx) = make_test_interface("quiet");
    entry.ingress =
        crate::ingress::IngressController::try_with_overrides(&crate::ingress::IngressOverrides {
            burst_freq_new: Some(100.0),
            burst_freq: Some(100.0),
            burst_hold: Some(0.2),
            ..Default::default()
        })
        .unwrap();
    actor.interfaces.insert(1, entry);
    let ingress = &mut actor.interfaces.get_mut(&1).unwrap().ingress;
    for _ in 0..4 {
        ingress.received_announce();
    }
    assert!(ingress.should_ingress_limit(), "precondition: a burst");
    std::thread::sleep(std::time::Duration::from_millis(300));

    actor.last_held_announce_check = 0.0;
    actor.on_tick();

    assert!(!actor.interfaces[&1].ingress.is_burst_active());
}
