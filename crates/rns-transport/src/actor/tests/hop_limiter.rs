//! Per-interface hop limits on inbound packets (Transport.py 1.6.1, bb63dd44).

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
