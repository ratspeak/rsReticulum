//! HEADER_2 wrapping on a send against upstream RNS 1.6.0: only beyond one
//! hop or behind a shared instance (Transport.py).
//! Vectors come from `tests/fixtures/outbound_wrap/generate.py`.

use super::*;
use crate::messages::OutboundDispatchResult;
use serde_json::Value;
use tokio::sync::oneshot;

fn golden() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/outbound_wrap/outbound_wrap.json"
    ))
    .unwrap()
}

fn hexv(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}

fn h16(b: &[u8]) -> [u8; 16] {
    b[..16].try_into().unwrap()
}

fn dest_of(raw: &[u8]) -> [u8; 16] {
    if raw[0] & 0x40 != 0 {
        h16(&raw[18..])
    } else {
        h16(&raw[2..])
    }
}

fn iface(name: &str, bitrate: u64, tx: mpsc::Sender<Bytes>) -> InterfaceEntry {
    InterfaceEntry::new(
        name.into(),
        InterfaceMode::Full,
        InterfaceDirection::bidirectional(),
        bitrate,
        500,
        tx,
    )
}

async fn barrier(tx: &mpsc::Sender<TransportMessage>) {
    let (response_tx, response_rx) = oneshot::channel();
    tx.send(TransportMessage::Rpc {
        query: TransportQuery::GetPathTable,
        response_tx,
    })
    .await
    .unwrap();
    response_rx.await.unwrap();
}

fn drain(rx: &mut mpsc::Receiver<Bytes>) -> Vec<Bytes> {
    let mut v = Vec::new();
    while let Ok(b) = rx.try_recv() {
        v.push(b);
    }
    v
}

async fn send_packet(tx: &mpsc::Sender<TransportMessage>, raw: &[u8]) -> OutboundDispatchResult {
    let (result_tx, result_rx) = oneshot::channel();
    tx.send(TransportMessage::SendPacket {
        request: OutboundRequest {
            raw: Bytes::copy_from_slice(raw),
            destination_hash: dest_of(raw),
        },
        attached_interface: None,
        receipt: None,
        result_tx,
    })
    .await
    .unwrap();
    result_rx.await.unwrap()
}

async fn stop(tx: mpsc::Sender<TransportMessage>, running: tokio::task::JoinHandle<()>) {
    tx.send(TransportMessage::Shutdown).await.unwrap();
    running.await.unwrap();
}

#[tokio::test]
async fn known_paths_wrap_beyond_one_hop_or_behind_a_shared_instance() {
    let g = golden();
    assert_eq!(g["rns_version"], "1.6.0");
    let next_hop = [0xAB; 16];
    for case in g["wrap"].as_array().unwrap() {
        let hops = case["path_hops"].as_u64().unwrap() as u8;
        let packed = hexv(&case["packed"]);
        let emitted: Vec<Vec<u8>> = case["emitted"]
            .as_array()
            .unwrap()
            .iter()
            .map(hexv)
            .collect();
        let (raw, expected) = if case["already_header2"].as_bool().unwrap() {
            // Upstream hands an already-wrapped packet on unchanged or not at all.
            assert!(emitted.iter().all(|e| *e == packed), "{case}");
            let mut raw = vec![0x40 | 0x10 | (packed[0] & 0x0F), packed[1]];
            raw.extend_from_slice(&next_hop);
            raw.extend_from_slice(&packed[2..]);
            let expected = emitted.iter().map(|_| raw.clone()).collect::<Vec<_>>();
            (raw, expected)
        } else {
            (packed, emitted)
        };
        let (mut actor, tx) = TransportActor::new();
        let (itx, mut irx) = mpsc::channel(16);
        let entry = iface("a", 10_000_000, itx);
        tx.try_send(TransportMessage::RegisterInterface { id: 1, entry })
            .unwrap();
        actor.is_shared_instance = case["shared_client"].as_bool().unwrap();
        actor.path_table.insert(
            dest_of(&raw),
            PathEntry::new(Some(next_hop), hops, 1, InterfaceMode::Full),
        );
        let running = tokio::spawn(actor.run());
        let result = send_packet(&tx, &raw).await;
        barrier(&tx).await;
        let frames: Vec<String> = drain(&mut irx).iter().map(hex::encode).collect();
        stop(tx, running).await;
        assert_eq!(
            frames,
            expected.iter().map(hex::encode).collect::<Vec<_>>(),
            "{case}"
        );
        assert_eq!(
            result == OutboundDispatchResult::Sent,
            case["sent"].as_bool().unwrap(),
            "{case}"
        );
    }
}
