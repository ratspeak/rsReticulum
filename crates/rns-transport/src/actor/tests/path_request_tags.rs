//! Path-request tags against upstream RNS 1.6.0: one tag across a
//! blocked-interface rediscovery, and a tag memory with no time expiry that
//! rotates above `max_pr_tags` (Transport.py).
//! Goldens come from `tests/fixtures/path_request_tags/gen_*.py`.

use super::*;
use crate::InterfaceTransportSender;
use crate::link_messages::DestinationEvent;
use crate::link_table::LinkEntry;
use crate::messages::{InterfaceStatRpcEntry, TimerTick};
use rns_wire::header::PacketHeader;
use serde_json::Value;
use tokio::sync::oneshot;

fn h16(v: &Value) -> [u8; 16] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn pr_dest() -> [u8; 16] {
    rns_identity::destination::Destination::hash_from_name_and_identity(
        "rnstransport.path.request",
        None,
    )
}

/// Wrap a PR payload in a Header1/Broadcast/Plain/Data packet.
fn pr_raw(payload: &[u8]) -> Vec<u8> {
    let header = PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Plain,
            packet_type: rns_wire::flags::PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: pr_dest(),
        context: rns_wire::context::PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(payload);
    raw
}

/// Returns the PR payload if `raw` is a path request.
fn pr_payload(raw: &[u8]) -> Option<Vec<u8>> {
    let (header, offset) = PacketHeader::unpack(raw).ok()?;
    (header.destination_hash == pr_dest()).then(|| raw[offset..].to_vec())
}

struct Fixture {
    tx: mpsc::Sender<TransportMessage>,
    radios: Vec<mpsc::Receiver<Bytes>>,
    producers: Vec<InterfaceTransportSender>,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    /// Interfaces get ids 1..=n; `setup` seeds tables before the actor runs.
    fn new(
        transport: bool,
        transport_id: [u8; 16],
        n: u64,
        setup: impl FnOnce(&mut TransportActor),
    ) -> Self {
        // The fixed identity stays on the wire with forwarding off.
        let options = TransportActorOptions {
            static_transport_identity: true,
            ..Default::default()
        };
        let (mut actor, tx) = TransportActor::new_with_options(
            4096,
            crate::constants::HASHLIST_MAXSIZE,
            Default::default(),
            options,
        );
        tx.try_send(TransportMessage::SetTransportIdentity {
            identity_hash: transport_id,
        })
        .unwrap();
        tx.try_send(TransportMessage::SetTransportEnabled { enabled: transport })
            .unwrap();
        let mut radios = Vec::new();
        let mut producers = Vec::new();
        for id in 1..=n {
            let (radio_tx, radio_rx) = mpsc::channel(64);
            let entry = InterfaceEntry::new(
                format!("prw inert radio {id}"),
                InterfaceMode::Full,
                InterfaceDirection::bidirectional(),
                1_000_000_000,
                500,
                radio_tx,
            );
            let owner = entry.owner.clone();
            tx.try_send(TransportMessage::RegisterInterface { id, entry })
                .unwrap();
            producers.push(InterfaceTransportSender::bind(id, owner, tx.clone()));
            radios.push(radio_rx);
        }
        setup(&mut actor);
        Self {
            tx,
            radios,
            producers,
            task: tokio::spawn(actor.run()),
        }
    }

    async fn inbound(&self, raw: Vec<u8>, interface_id: u64) {
        self.producers[(interface_id - 1) as usize]
            .actor_sender()
            .send(
                self.producers[(interface_id - 1) as usize].event(TransportMessage::Inbound(
                    InboundPacket {
                        raw: Bytes::from(raw),
                        interface_id,
                        rssi: None,
                        snr: None,
                        q: None,
                    },
                )),
            )
            .await
            .unwrap();
        self.stats().await; // mailbox barrier
    }

    async fn stats(&self) -> Vec<InterfaceStatRpcEntry> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(TransportMessage::Rpc {
                query: TransportQuery::GetInterfaceStats,
                response_tx,
            })
            .await
            .unwrap();
        match response_rx.await.unwrap() {
            TransportQueryResponse::InterfaceStats(s) => s,
            other => panic!("unexpected {other:?}"),
        }
    }

    async fn register(&self, hash: [u8; 16]) -> mpsc::Receiver<DestinationEvent> {
        let (delivery_tx, mut rx) = mpsc::channel(16);
        self.tx
            .send(TransportMessage::RegisterDestination {
                hash,
                app_name: "prw.local".into(),
                delivery_tx: Some(delivery_tx),
            })
            .await
            .unwrap();
        self.stats().await;
        while rx.try_recv().is_ok() {}
        rx
    }

    /// Drain path-request payloads queued on radio `id`.
    fn prs_on(&mut self, id: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Ok(raw) = self.radios[(id - 1) as usize].try_recv() {
            if let Some(p) = pr_payload(&raw) {
                out.push(p);
            }
        }
        out
    }

    async fn stop(self) {
        let _ = self.tx.send(TransportMessage::Shutdown).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), self.task).await;
    }
}

/// PR tag = trailing 16 bytes of a canonical 32/48-byte payload.
fn tag_of(payload: &[u8]) -> Vec<u8> {
    match payload.len() {
        32 => payload[16..32].to_vec(),
        48 | 64 => payload[32..48].to_vec(),
        _ => payload[16..].to_vec(),
    }
}

#[tokio::test]
async fn blocked_interface_rediscovery_shares_one_tag() {
    let g: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/path_request_tags/blocked_rediscovery.json"
    ))
    .unwrap();
    let br = &g["blocked_rediscovery"];
    assert_eq!(br["same_tag_on_all_unblocked"], true, "golden sanity");
    let dest = h16(&br["destination_hash"]);
    // A stale unvalidated transit link (taken_hops 1, 1-hop path) makes the
    // maintenance tick queue rediscovery with the receiving interface 1 blocked.
    let mut fx = Fixture::new(true, [0x99; 16], 3, |a| {
        a.path_table.insert(
            dest,
            PathEntry::new(Some([0x11; 16]), 1, 2, InterfaceMode::Full),
        );
        a.link_table.insert(
            [0x4c; 16],
            LinkEntry {
                timestamp: 0.0,
                next_hop: Some([0x11; 16]),
                interface_id: 2,
                remaining_hops: 1,
                destination_hash: dest,
                validated: false,
                proof_timeout: 1.0,
                receiving_interface: 1,
                taken_hops: 1,
                interface_owner: None,
                receiving_owner: None,
                requested_mode: 0,
                accepted_mtu_ceiling: 500,
            },
        );
    });
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let a = fx.prs_on(1);
    let b = fx.prs_on(2);
    let c = fx.prs_on(3);
    fx.stop().await;
    assert!(
        a.iter().all(|p| p[..16] != dest),
        "blocked interface must not get the rediscovery PR"
    );
    let b: Vec<_> = b.into_iter().filter(|p| p[..16] == dest).collect();
    let c: Vec<_> = c.into_iter().filter(|p| p[..16] == dest).collect();
    assert!(
        !b.is_empty() && !c.is_empty(),
        "rediscovery PR not observed on both unblocked interfaces: b={b:?} c={c:?}"
    );
    let tb = hex::encode(tag_of(&b[0]));
    let tc = hex::encode(tag_of(&c[0]));
    assert_eq!(
        tb, tc,
        "upstream 1.6.0 handle_disovery_path_requests generates ONE \
         request_tag and sends it on every non-blocked interface (Transport.py:4071-4080@1.6.0; golden \
         blocked_rediscovery.json b_tags==c_tags). Rust sent different tags per interface: {tb} vs {tc}"
    );
}

/// Tag memory has no time expiry and rotates into a previous generation above
/// `max_pr_tags` (Transport.py). Golden tag_memory.json.
#[tokio::test]
async fn path_request_tag_memory_matches_upstream() {
    let g: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/path_request_tags/tag_memory.json"
    ))
    .unwrap();
    assert_eq!(g["rns_version"], "1.6.0");
    let max = g["max_pr_tags"].as_u64().unwrap() as usize;
    let dest = h16(&g["local_destination_hash"]);
    let filler = |byte: u8, i: usize| {
        let mut k = [byte; 32];
        k[28..].copy_from_slice(&(i as u32).to_be_bytes());
        k
    };
    let mut failures = Vec::new();
    for case in g["tag_cases"].as_array().unwrap() {
        let label = case["case"].as_str().unwrap();
        let tag = h16(&case["tag"]);
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&dest);
        key[16..].copy_from_slice(&tag);
        let fx = Fixture::new(false, [0x36; 16], 1, |a| match label {
            "replay_after_121s_and_jobs" => {
                a.discovery_pr_tags.insert(key);
            }
            "at_max_no_rotation" | "above_max_rotates" => {
                a.discovery_pr_tags.insert(key);
                let n = case["seeded_tags"].as_u64().unwrap() as usize - 1;
                a.discovery_pr_tags.extend((0..n).map(|i| filler(0xA0, i)));
            }
            "second_rotation_forgets" => {
                a.discovery_pr_tags.insert(key);
                a.discovery_pr_tags_prev
                    .extend((0..max).map(|i| filler(0xA1, i)));
                a.discovery_pr_tags_prev.insert(key);
                a.discovery_pr_tags.clear();
                a.discovery_pr_tags
                    .extend((0..=max).map(|i| filler(0xA2, i)));
            }
            _ => {}
        });
        let mut rx = fx.register(dest).await;
        fx.tx.send(TransportMessage::Tick(TimerTick)).await.unwrap();
        fx.inbound(pr_raw(&[&dest[..], &tag[..]].concat()), 1).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let answered = std::iter::from_fn(|| rx.try_recv().ok())
            .any(|e| matches!(e, DestinationEvent::AnnounceRequested(_)));
        fx.stop().await;
        if answered != case["answered"].as_bool().unwrap() {
            failures.push(format!(
                "{label}: upstream answered={} Rust {answered}",
                case["answered"]
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
