//! Per-interface hop limits and the path-table getter (Transport.py 1.6.1).

use super::*;

/// The interface's limit applies before the instance-wide one, on wire hops;
/// 0 is off, as `None` is.
#[test]
fn interface_hop_limiter_drops_at_its_limit() {
    let (mut actor, _tx) = TransportActor::new();
    let mut keep = Vec::new();
    for (id, limit) in [(1, Some(1)), (2, Some(0)), (3, None)] {
        let (mut entry, rx) = make_test_interface(&format!("iface{id}"));
        entry.hop_limiter = limit;
        actor.interfaces.insert(id, entry);
        keep.push(rx);
    }
    let mut learned = Vec::new();
    for id in 1..=3 {
        for hops in [0, 1] {
            let (raw, dest) = make_valid_announce(&format!("hoplimit.i{id}.h{hops}"), hops);
            actor.on_inbound(InboundPacket {
                raw,
                interface_id: id,
                rssi: None,
                snr: None,
                q: None,
            });
            learned.push(actor.path_table.has_path(&dest));
        }
    }
    assert_eq!(learned, [true, false, true, true, true, true]);
}

/// Reticulum.py 1.6.1 (c90a5d58, 41260ea1): each path names its interface's
/// hash, as interface stats do, and its state.
#[test]
fn path_table_entries_carry_interface_hash_and_state() {
    let (mut actor, _tx) = TransportActor::new();
    let (mut named, _named_rx) = make_test_interface("radio");
    named.inspection = Some(
        crate::messages::InterfaceInspectionSource::new(Default::default).with_identity(
            crate::messages::InterfaceIdentity::new(
                "TCPInterface[radio/127.0.0.1:4242]",
                "radio",
                "TCPInterface",
            ),
        ),
    );
    actor.interfaces.insert(1, named);
    let (plain, _plain_rx) = make_test_interface("plain");
    actor.interfaces.insert(2, plain);
    let (a, b) = ([0x61; 16], [0x62; 16]);
    actor
        .path_table
        .insert(a, PathEntry::new(None, 1, 1, InterfaceMode::Full));
    actor
        .path_table
        .insert(b, PathEntry::new(None, 1, 2, InterfaceMode::Full));
    actor.mark_path_responsive(&a);

    let TransportQueryResponse::PathTable(entries) =
        actor.handle_query(TransportQuery::GetPathTable)
    else {
        panic!("expected a path table");
    };
    let entry = |hash| entries.iter().find(|e| e.hash == hash).unwrap();
    assert_eq!(
        entry(a).interface_hash,
        rns_crypto::sha::sha256(b"TCPInterface[radio/127.0.0.1:4242]")
    );
    assert_eq!(entry(a).state, PathState::Responsive);
    assert_eq!(entry(b).interface_hash, rns_crypto::sha::sha256(b"plain"));
    assert_eq!(entry(b).state, PathState::Unknown);
}
