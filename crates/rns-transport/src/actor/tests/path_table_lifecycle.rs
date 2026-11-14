//! Path-table lifetime against upstream RNS 1.6.0: never-used linger on a
//! leaf and a transport node, the never-used pool cap, traffic marking use
//! without renewing a path, and rediscovery after a local Link that never
//! established.
//!
//! Expected values come from `tests/fixtures/path_table_lifecycle/path_table_lifecycle.json`,
//! which `generate.py` beside it reads back from upstream `Transport.jobs()`
//! and `Transport.outbound()`.

use super::*;
use crate::messages::PathTableRpcEntry;
use serde_json::Value;
use tokio::sync::oneshot;

fn golden() -> Value {
    let v: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/path_table_lifecycle/path_table_lifecycle.json"
    ))
    .unwrap();
    assert_eq!(v["provenance"]["version"], "1.6.0");
    v
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

fn h16(i: u64) -> [u8; 16] {
    (i as u128).to_be_bytes()
}

fn iface(name: &str, bitrate: u64, mode: InterfaceMode) -> (InterfaceEntry, mpsc::Receiver<Bytes>) {
    let (tx, rx) = mpsc::channel(256);
    let entry = InterfaceEntry::new(
        name.into(),
        mode,
        InterfaceDirection::bidirectional(),
        bitrate,
        500,
        tx,
    );
    (entry, rx)
}

fn bitrate(kind: &str) -> u64 {
    match kind {
        "fast" => 10_000_000,
        "slow" => 9600,
        "edge" => 25_000,
        "zero" | "none" => 0,
        other => panic!("interface kind {other}"),
    }
}

async fn path_table(tx: &mpsc::Sender<TransportMessage>) -> HashMap<[u8; 16], PathTableRpcEntry> {
    let (response_tx, rx) = oneshot::channel();
    tx.send(TransportMessage::Rpc {
        query: TransportQuery::GetPathTable,
        response_tx,
    })
    .await
    .unwrap();
    match rx.await.unwrap() {
        TransportQueryResponse::PathTable(v) => v.into_iter().map(|e| (e.hash, e)).collect(),
        other => panic!("unexpected {other:?}"),
    }
}

/// Run the actor until its first table cull has happened.
async fn run(
    actor: TransportActor,
    tx: &mpsc::Sender<TransportMessage>,
) -> HashMap<[u8; 16], PathTableRpcEntry> {
    tokio::spawn(actor.run());
    tokio::time::sleep(Duration::from_millis(1500)).await;
    path_table(tx).await
}

async fn linger_case(case: &Value) {
    let transport = case["transport_enabled"].as_bool().unwrap();
    let (mut actor, tx) = TransportActor::new();
    tx.try_send(TransportMessage::SetTransportEnabled { enabled: transport })
        .unwrap();
    let mut ids = HashMap::new();
    let mut keep = Vec::new();
    for (i, kind) in ["fast", "slow", "zero", "none", "edge"]
        .into_iter()
        .enumerate()
    {
        let (entry, rx) = iface(kind, bitrate(kind), InterfaceMode::Full);
        tx.try_send(TransportMessage::RegisterInterface {
            id: i as u64 + 1,
            entry,
        })
        .unwrap();
        ids.insert(kind, i as u64 + 1);
        keep.push(rx);
    }
    let t = now();
    let entries = case["entries"].as_array().unwrap();
    for (i, e) in entries.iter().enumerate() {
        let mut p = PathEntry::new(
            None,
            1,
            ids[e["iface"].as_str().unwrap()],
            InterfaceMode::Full,
        );
        p.timestamp = t - e["age_s"].as_f64().unwrap();
        p.expires = t + e["expires_rel_s"].as_f64().unwrap();
        p.used = e["used_age_s"].as_f64().map_or(0.0, |age| t - age);
        actor.path_table.insert(h16(i as u64 + 1), p);
    }
    let live = run(actor, &tx).await;
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(
            live.contains_key(&h16(i as u64 + 1)),
            e["survives"].as_bool().unwrap(),
            "transport={transport} {}: upstream cull (Transport.py:1118-1160@1.6.0)",
            e["label"]
        );
    }
}

#[tokio::test]
async fn never_used_paths_linger_as_upstream_on_a_leaf_and_a_transport_node() {
    let g = golden();
    linger_case(&g["linger_leaf"]).await;
    linger_case(&g["linger_transport"]).await;
}

#[tokio::test]
async fn never_used_pool_is_culled_to_the_upstream_target() {
    let g = golden();
    let c = &g["pool_cap"];
    let (mut actor, tx) = TransportActor::new();
    tx.try_send(TransportMessage::SetTransportEnabled { enabled: true })
        .unwrap();
    actor.path_pool_last_checked = 0.0;
    let (fast, _fast_rx) = iface("fast", 10_000_000, InterfaceMode::Full);
    let (slow, _slow_rx) = iface("slow", 9600, InterfaceMode::Full);
    tx.try_send(TransportMessage::RegisterInterface { id: 1, entry: fast })
        .unwrap();
    tx.try_send(TransportMessage::RegisterInterface { id: 2, entry: slow })
        .unwrap();
    let t = now();
    let count = c["count"].as_u64().unwrap();
    let field = |k: &str| c[k].as_u64().unwrap();
    for i in 0..count {
        let id = if i % field("slow_every") == 0 { 2 } else { 1 };
        let expires_rel =
            field("expiry_base_s") + ((i * 7919) % field("expiry_mod")) * field("expiry_step_s");
        let mut p = PathEntry::new(None, 1, id, InterfaceMode::Full);
        p.timestamp = t - 30.0;
        p.expires = t + expires_rel as f64;
        actor.path_table.insert(h16(i + 1), p);
    }
    for j in 0..field("used_count") {
        let mut p = PathEntry::new(None, 1, 1, InterfaceMode::Full);
        p.timestamp = t - 30.0;
        p.expires = t + 60.0;
        p.used = t - 1.0;
        actor.path_table.insert(h16(count + j + 1), p);
    }
    let live = run(actor, &tx).await;
    let removed: Vec<u64> = (0..count)
        .filter(|i| !live.contains_key(&h16(i + 1)))
        .collect();
    let want: Vec<u64> = c["removed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    assert_eq!(
        removed, want,
        "PATH_POOL_UNUSED_TARGET cull (Transport.py:1150-1156@1.6.0)"
    );
    assert_eq!(
        (0..field("used_count")).all(|j| live.contains_key(&h16(count + j + 1))),
        c["used_survive"].as_bool().unwrap()
    );
}

#[tokio::test]
async fn outbound_traffic_marks_use_without_renewing_the_path() {
    let g = golden();
    for case in g["outbound"].as_array().unwrap() {
        let hops = case["hops"].as_u64().unwrap() as u8;
        let (mut actor, tx) = TransportActor::new();
        let (entry, mut rx) = iface("a", 10_000_000, InterfaceMode::Full);
        tx.try_send(TransportMessage::RegisterInterface { id: 1, entry })
            .unwrap();
        let dest = [0x57u8; 16];
        let t = now();
        let mut p = PathEntry::new(
            (hops > 1).then_some([0x99; 16]),
            hops,
            1,
            InterfaceMode::Full,
        );
        p.timestamp = t - case["age_s"].as_f64().unwrap();
        p.expires = p.timestamp + 604_800.0;
        let (ts0, exp0) = (p.timestamp, p.expires);
        actor.path_table.insert(dest, p);
        tokio::spawn(actor.run());
        let mut raw = vec![0x00u8, 0x00];
        raw.extend_from_slice(&dest);
        raw.push(0x00);
        raw.extend_from_slice(b"hello");
        let before = now();
        tx.send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: dest,
        }))
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let e = path_table(&tx).await.remove(&dest).expect("path present");
        let got = serde_json::json!({
            "hops": hops, "age_s": case["age_s"], "sent": rx.try_recv().is_ok(),
            "timestamp_unchanged": e.timestamp == ts0, "expires_unchanged": e.expires == exp0,
            "used_is_send_time": e.used >= before,
        });
        assert_eq!(&got, case, "Transport.py:1618@1.6.0");
    }
}

/// A local initiator Link request is sent, then its temporary destination is
/// released without the Link being bound: upstream's CLOSED pending link.
#[tokio::test]
async fn link_never_established_expires_the_path_and_rediscovers_as_upstream() {
    let g = golden();
    for case in g["pending_link_rediscovery"].as_array().unwrap() {
        let (mut actor, tx) = TransportActor::new();
        tx.try_send(TransportMessage::SetTransportEnabled {
            enabled: case["transport_enabled"].as_bool().unwrap(),
        })
        .unwrap();
        actor.shared_instance_client_mode = case["shared_client"].as_bool().unwrap();
        let (entry, mut rx) = iface("a", 10_000_000, InterfaceMode::Full);
        tx.try_send(TransportMessage::RegisterInterface { id: 1, entry })
            .unwrap();
        let dest = h16(7);
        let t = now();
        let mut p = PathEntry::new(None, 1, 1, InterfaceMode::Full);
        p.timestamp = t - 10.0;
        p.used = t - 1.0;
        actor.path_table.insert(dest, p);
        if let Some(age) = case["last_request_age_s"].as_f64() {
            actor.path_requests.insert(dest, t - age);
        }
        tokio::spawn(actor.run());

        let (_, request_data) = rns_link::link::Link::new_initiator(dest, 1);
        let header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Single,
                packet_type: rns_wire::flags::PacketType::LinkRequest,
            },
            hops: 0,
            transport_id: None,
            destination_hash: dest,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&request_data);
        let link_id = rns_wire::hash::link_id_from_raw(&raw, rns_wire::flags::HeaderType::Header1);
        let (delivery_tx, _delivery_rx) = mpsc::channel(8);
        tx.send(TransportMessage::RegisterDestination {
            hash: link_id,
            app_name: "pathlifecycle.link".into(),
            delivery_tx: Some(delivery_tx),
        })
        .await
        .unwrap();
        tx.send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: dest,
        }))
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sent = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("no outbound path response within 10 s")
            .unwrap();
        assert_eq!(
            sent[0] & 0x03,
            0x02,
            "precondition: link request transmitted"
        );
        tx.send(TransportMessage::DeregisterDestination { hash: link_id })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let mut requested = false;
        while let Ok(frame) = rx.try_recv() {
            let (header, offset) = rns_wire::header::PacketHeader::unpack(&frame).unwrap();
            if header.flags.destination_type == rns_wire::flags::DestinationType::Plain
                && frame.len() >= offset + 16
                && frame[offset..offset + 16] == dest
            {
                requested = true;
            }
        }
        let got = serde_json::json!({
            "transport_enabled": case["transport_enabled"], "shared_client": case["shared_client"],
            "last_request_age_s": case["last_request_age_s"],
            "path_kept": path_table(&tx).await.contains_key(&dest),
            "rediscovery_queued": requested,
        });
        assert_eq!(&got, case, "Transport.py:839-866@1.6.0");
    }
}
