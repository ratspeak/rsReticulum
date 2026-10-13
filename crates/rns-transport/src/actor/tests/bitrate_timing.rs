use super::*;
use crate::messages::{TransportQuery, TransportQueryResponse};

fn timeout(actor: &mut TransportActor, query: TransportQuery) -> f64 {
    let TransportQueryResponse::FloatResult(Some(value)) = actor.handle_query(query) else {
        panic!("expected timeout result");
    };
    assert!(value.is_finite());
    value
}

#[test]
fn unknown_and_zero_bitrates_use_finite_timeout_defaults() {
    let (mut actor, _) = TransportActor::new();
    let dest = [0x42; 16];
    let first = TransportQuery::FirstHopTimeout { dest };
    assert_eq!(
        timeout(&mut actor, first),
        rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT
    );
    assert_eq!(
        timeout(
            &mut actor,
            TransportQuery::ExtraLinkProofTimeout { interface_id: 7 }
        ),
        0.0
    );
    actor.path_table.insert(
        dest,
        crate::path_table::PathEntry {
            timestamp: crate::now_f64(),
            next_hop: None,
            hops: 1,
            expires: crate::now_f64() + 600.0,
            random_blobs: std::collections::VecDeque::new(),
            interface_id: 7,
            packet_hash: None,
        },
    );
    let (mut interface, _rx) = make_test_interface("unknown bitrate");
    interface.bitrate = 0;
    actor.interfaces.insert(7, interface);
    assert_eq!(
        timeout(&mut actor, TransportQuery::FirstHopTimeout { dest }),
        rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT
    );
    assert_eq!(
        timeout(
            &mut actor,
            TransportQuery::ExtraLinkProofTimeout { interface_id: 7 }
        ),
        0.0
    );
    for (bitrate, extra) in [
        (500, 8.0),
        (1_000_000, 0.004),
        (u64::MAX, 4000.0 / u64::MAX as f64),
    ] {
        actor.interfaces.get_mut(&7).unwrap().bitrate = bitrate;
        assert_eq!(
            timeout(
                &mut actor,
                TransportQuery::ExtraLinkProofTimeout { interface_id: 7 }
            ),
            extra
        );
        assert_eq!(
            timeout(&mut actor, TransportQuery::FirstHopTimeout { dest }),
            extra + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT
        );
    }
}
