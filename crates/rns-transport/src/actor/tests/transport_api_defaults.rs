//! Transport API defaults against upstream RNS 1.6.0: the default packet
//! receipt timeout and the next-hop hardware MTU gate. Expected values come
//! from `tests/fixtures/transport_api_defaults/generate.py`.

use super::*;
use crate::InterfacePacketCapacity;
use crate::messages::{ReceiptUpdate, TrackedReceiptRegistration};
use rns_wire::context::PacketContext;
use rns_wire::flags::{DestinationType, HeaderType, PacketFlags, PacketType, TransportType};
use rns_wire::header::PacketHeader;
use serde_json::Value;
use tokio::sync::{oneshot, watch};

fn golden() -> Value {
    let v: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/transport_api_defaults/transport_api_defaults.json"
    ))
    .unwrap();
    assert_eq!(v["provenance"]["rns_version"], "1.6.0");
    v
}

struct Rig {
    tx: mpsc::Sender<TransportMessage>,
    _rx: mpsc::Receiver<Bytes>,
    running: tokio::task::JoinHandle<()>,
}

fn rig(mtu: u32, capacity: Option<InterfacePacketCapacity>, paths: &[([u8; 16], u8)]) -> Rig {
    let (mut actor, tx) = TransportActor::new();
    let (if_tx, rx) = mpsc::channel(1024);
    let mut entry = InterfaceEntry::new(
        "medium".into(),
        InterfaceMode::Full,
        InterfaceDirection::bidirectional(),
        10_000_000,
        mtu,
        if_tx,
    );
    if let Some(capacity) = capacity {
        entry.packet_capacity = capacity;
    }
    let owner = entry.owner.clone();
    tx.try_send(TransportMessage::RegisterInterface { id: 1, entry })
        .unwrap();
    owner.mark_registered();
    for (dest, hops) in paths {
        actor
            .path_table
            .insert(*dest, PathEntry::new(None, *hops, 1, InterfaceMode::Full));
    }
    let running = tokio::spawn(actor.run());
    Rig {
        tx,
        _rx: rx,
        running,
    }
}

impl Rig {
    async fn shutdown(self) {
        let _ = self.tx.send(TransportMessage::Shutdown).await;
        let _ = self.running.await;
    }
}

/// A receipt registered without a timeout gets `first_hop_timeout + 6 * hops`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipt_without_timeout_uses_the_hop_based_default() {
    let g = golden();
    let want = g["receipt"]["timeout"].as_f64().unwrap();
    let dest = [0x47u8; 16];
    let r = rig(
        500,
        None,
        &[(dest, g["receipt"]["hops"].as_u64().unwrap() as u8)],
    );
    let mut raw = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: dest,
        context: PacketContext::None,
    }
    .pack();
    raw.extend_from_slice(&[0xAB; 64]);
    let (full, trunc) = rns_wire::hash::packet_hash_pair(&raw, HeaderType::Header1);
    let (status_tx, status_rx) = watch::channel(ReceiptUpdate::Sent);
    let (result_tx, result_rx) = oneshot::channel();
    r.tx.send(TransportMessage::SendPacket {
        request: OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: dest,
        },
        attached_interface: None,
        receipt: Some(TrackedReceiptRegistration {
            truncated_hash: trunc,
            full_hash: full,
            destination_hash: dest,
            destination_public_key: [0u8; 64],
            timeout: None,
            status_tx,
        }),
        result_tx,
    })
    .await
    .unwrap();
    let _ = result_rx.await.unwrap();
    tokio::time::sleep(Duration::from_secs_f64(want - 1.5)).await;
    assert_eq!(*status_rx.borrow(), ReceiptUpdate::Sent, "timed out early");
    // The receipt sweep runs once a second.
    tokio::time::sleep(Duration::from_secs_f64(3.5)).await;
    assert_eq!(*status_rx.borrow(), ReceiptUpdate::TimedOut);
    r.shutdown().await;
}

/// Only interfaces that may carry a larger Link MTU report their hardware MTU.
#[tokio::test]
async fn next_hop_hardware_mtu_only_for_mtu_capable_interfaces() {
    let g = golden();
    let dest = [0x22u8; 16];
    for (name, upgrade) in [("udp", false), ("tcp", true)] {
        let want = &g["next_hop_hw_mtu"][name];
        let mtu = want["hw_mtu"].as_u64().unwrap() as u32;
        let clear = if upgrade { mtu } else { 500 };
        let r = rig(
            mtu,
            Some(InterfacePacketCapacity::new(clear, mtu, upgrade)),
            &[(dest, 1)],
        );
        let (response_tx, response_rx) = oneshot::channel();
        r.tx.send(TransportMessage::Rpc {
            query: TransportQuery::GetNextHopHardwareMtu { dest },
            response_tx,
        })
        .await
        .unwrap();
        let got = match response_rx.await.unwrap() {
            TransportQueryResponse::IntResult(v) => v,
            other => panic!("unexpected {other:?}"),
        };
        r.shutdown().await;
        assert_eq!(got, want["result"].as_i64().unwrap_or(-1), "{name}");
    }
}
