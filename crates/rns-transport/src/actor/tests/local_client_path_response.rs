//! A local client's path response to a pending external request against
//! upstream RNS 1.6.0. Expected values come from
//! `tests/fixtures/local_client_path_response/generate.py`.

use super::*;
use crate::InterfaceTransportSender;
use rns_wire::{context::PacketContext, flags::HeaderType, header::PacketHeader};
use serde_json::Value;

/// An actor that keeps the hash from `SetTransportIdentity` on the wire while
/// forwarding is off.
fn fixed_identity_actor() -> (TransportActor, mpsc::Sender<TransportMessage>) {
    let options = TransportActorOptions {
        static_transport_identity: true,
        ..Default::default()
    };
    TransportActor::new_with_options(
        4096,
        crate::constants::HASHLIST_MAXSIZE,
        Default::default(),
        options,
    )
}

fn golden() -> Value {
    let v: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/local_client_path_response/local_client_path_response.json"
    ))
    .unwrap();
    assert_eq!(v["provenance"]["rns_version"], "1.6.0");
    v
}

fn hexv(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn iface(name: &str, tx: mpsc::Sender<Bytes>) -> InterfaceEntry {
    InterfaceEntry::new(
        name.into(),
        InterfaceMode::Full,
        InterfaceDirection::bidirectional(),
        1_000_000,
        500,
        tx,
    )
}

/// A local client's path response to a pending external request enters the
/// announce table and is rebroadcast once, context NONE, on every interface.
#[tokio::test]
async fn local_client_path_response_is_rebroadcast_once_everywhere() {
    let g = golden();
    let lp = &g["local_pr"];
    assert_eq!(lp["pending_cleared"], true);
    assert!(lp["ext_a_sent_before_jobs"].as_array().unwrap().is_empty());
    let none_ctx = g["consts"]["NONE"].as_u64().unwrap() as u8;
    let raw = Bytes::from(hexv(&lp["announce_raw"]));
    let dest: [u8; 16] = hexv(&lp["destination_hash"]).try_into().unwrap();

    let (mut actor, tx) = fixed_identity_actor();
    let transport_id = [0x77; 16];
    tx.try_send(TransportMessage::SetTransportIdentity {
        identity_hash: transport_id,
    })
    .unwrap();
    let (a_tx, mut a_rx) = mpsc::channel(64);
    let (b_tx, mut b_rx) = mpsc::channel(64);
    let (lc_tx, _lc_rx) = mpsc::channel(64);
    let entry = iface("ext-a", a_tx);
    tx.try_send(TransportMessage::RegisterInterface { id: 1, entry })
        .unwrap();
    let entry = iface("ext-b", b_tx);
    tx.try_send(TransportMessage::RegisterInterface { id: 2, entry })
        .unwrap();
    let lc = iface("local-client", lc_tx).with_role(InterfaceRole::LocalClient);
    let lc_owner = lc.owner.clone();
    tx.try_send(TransportMessage::RegisterInterface { id: 3, entry: lc })
        .unwrap();
    lc_owner.mark_registered();
    actor.pending_local_path_requests.insert(dest, 1);
    let running = tokio::spawn(actor.run());
    let producer = InterfaceTransportSender::bind(3, lc_owner, tx.clone());
    producer
        .actor_sender()
        .send(producer.event(TransportMessage::Inbound(InboundPacket {
            raw,
            interface_id: 3,
            rssi: None,
            snr: None,
            q: None,
        })))
        .await
        .unwrap();
    // Several announce-table passes (one per second).
    tokio::time::sleep(Duration::from_millis(2600)).await;

    for (name, rx) in [("ext-a", &mut a_rx), ("ext-b", &mut b_rx)] {
        let expected = lp["after_jobs"][name].as_array().unwrap();
        let mut seen = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            let (h, _) = PacketHeader::unpack(&frame).unwrap();
            if h.destination_hash == dest {
                seen.push((h.flags.header_type, h.context.to_byte(), h.transport_id));
            }
        }
        assert_eq!(seen.len(), expected.len(), "{name}: {seen:?}");
        assert_eq!(
            seen[0],
            (HeaderType::Header2, none_ctx, Some(transport_id)),
            "{name}"
        );
        assert_eq!(expected[0]["context"].as_u64(), Some(u64::from(none_ctx)));
        assert_ne!(seen[0].1, PacketContext::PathResponse.to_byte());
    }
    tx.send(TransportMessage::Shutdown).await.unwrap();
    running.await.unwrap();
}

fn inbound(actor: &mut TransportActor, raw: Bytes, interface_id: InterfaceId) {
    actor.on_inbound(InboundPacket {
        raw,
        interface_id,
        rssi: None,
        snr: None,
        q: None,
    });
}

/// Transport.py 1.6.1 (833f6cf2): a local client's announce leaves its path
/// responsive and used, also when the rate limit holds it back; another
/// announce leaves the path unknown and unused.
#[test]
fn local_client_announce_marks_its_path_responsive() {
    let (mut actor, _tx) = TransportActor::new();
    let (external, _external_rx) = make_test_interface("external");
    let (mut client, _client_rx) = make_test_interface("local-client");
    client.role = InterfaceRole::LocalClient;
    client = client.with_announce_rate(3600.0, 0, 0.0);
    actor.interfaces.insert(1, external);
    actor.interfaces.insert(2, client);

    let (remote, remote_dest) = make_valid_announce("t16.remote", 0);
    inbound(&mut actor, remote, 1);
    assert_eq!(actor.path_table.get_state(&remote_dest), PathState::Unknown);
    assert_eq!(actor.path_table.get(&remote_dest).unwrap().used, 0.0);

    let identity = rns_identity::identity::Identity::new();
    let mut queued = None;
    for emitted in [1_000, 2_000] {
        let (raw, dest) =
            make_announce_for_with_random_blob(&identity, "t16.local", 0, random_blob(1, emitted));
        inbound(&mut actor, raw, 2);
        // The second is rate-blocked: its rebroadcast is not queued.
        let entry = actor.announce_table.get(&dest).unwrap().packet_raw.clone();
        assert_eq!(*queued.get_or_insert_with(|| entry.clone()), entry);
        let path = actor.path_table.get(&dest).unwrap();
        assert!(path.has_random_blob(&random_blob(1, emitted)));
        assert_eq!(path.hops, 0);
        assert!(path.used > 0.0, "emitted {emitted}");
        assert_eq!(
            actor.path_table.get_state(&dest),
            PathState::Responsive,
            "emitted {emitted}"
        );
    }
}
