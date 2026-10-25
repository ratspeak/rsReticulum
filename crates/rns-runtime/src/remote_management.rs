//! Authenticated RPC over Reticulum links (`rnstatus -R`, `rnpath -R`).
//! Registers `rnstransport.remote.management` with `/status` + `/path`.
//!
//! Auth: requires prior `LinkIdentify`, then checks identity against
//! `remote_management_allowed`. This mirrors Python `Destination.ALLOW_LIST`:
//! an empty allow-list denies all peers.
//!
//! REQUIRES a multi-threaded Tokio runtime — sync handler calls
//! `block_in_place`. Tests must use `#[tokio::test(flavor = "multi_thread")]`.

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use rns_crypto::sha::truncated_hash;
use rns_identity::destination::Destination;
use rns_identity::identity::Identity;
use rns_transport::messages::{TransportMessage, TransportQuery, TransportQueryResponse};

use crate::reticulum::InterfaceIfacStats;
use crate::rpc::{self, RpcResponse};
use crate::rpc_server::{TransportStatsSource, stat_entries};

const STATUS_PATH: &str = "/status";
const PATH_PATH: &str = "/path";

/// Python registers this destination on `Transport.identity`
/// (Transport.py:367-368), so `rnstatus -R` and `rnpath -R` find it from the
/// transport identity hash. Empty `allowed_identities` denies all peers,
/// matching Python's `Destination.ALLOW_LIST` semantics.
pub async fn start_remote_management(
    transport_tx: mpsc::Sender<TransportMessage>,
    identity: &Identity,
    allowed_identities: Vec<[u8; 16]>,
) -> Result<[u8; 16], String> {
    start_remote_management_with_stats(transport_tx, identity, allowed_identities, None, None).await
}

/// As [`start_remote_management`], with the runtime's IFAC records and
/// transport instance, so status replies carry every field of Python's.
pub(crate) async fn start_remote_management_with_stats(
    transport_tx: mpsc::Sender<TransportMessage>,
    identity: &Identity,
    allowed_identities: Vec<[u8; 16]>,
    ifac: Option<InterfaceIfacStats>,
    transport: Option<TransportStatsSource>,
) -> Result<[u8; 16], String> {
    let signing_key = identity
        .get_signing_key()
        .ok_or_else(|| "No signing key available for remote management".to_string())?;

    let app_name = "rnstransport.remote.management";
    let dest_hash = Destination::hash_from_name_and_identity(app_name, Some(&identity.hash));
    let event_rx = crate::link_manager::register_destination(&transport_tx, dest_hash, app_name);
    let mut lm = crate::link_manager::LinkManager::with_destination(
        transport_tx.clone(),
        event_rx,
        identity,
        app_name,
        Some(signing_key),
    );

    let status_hash: [u8; 16] = truncated_hash(STATUS_PATH.as_bytes());
    let paths_hash: [u8; 16] = truncated_hash(PATH_PATH.as_bytes());

    let link_identities = lm.link_identities_handle();
    let allowed = Arc::new(allowed_identities);
    let tx = transport_tx.clone();

    lm.set_request_handler(move |link_id, path_hash, data| {
        let peer = match link_identities.lock() {
            Ok(guard) => guard.get(&link_id).copied(),
            Err(_) => None,
        };
        let peer = match peer {
            Some(p) => p,
            None => {
                tracing::debug!(
                    link_id = %hex::encode(link_id),
                    "remote management: request before identification — dropping"
                );
                return None;
            }
        };

        if !peer_allowed(&allowed, &peer) {
            tracing::warn!(
                link_id = %hex::encode(link_id),
                peer = %hex::encode(peer),
                "remote management: peer not in allowed list — rejecting"
            );
            return None;
        }

        if path_hash == status_hash {
            handle_status(&tx, &data, ifac.as_ref(), transport.as_ref())
        } else if path_hash == paths_hash {
            handle_path(&tx, &data)
        } else {
            tracing::debug!(
                link_id = %hex::encode(link_id),
                path_hash = %hex::encode(path_hash),
                "remote management: unknown request path — dropping"
            );
            None
        }
    });

    let dest_hash = lm.destination_hash;

    tokio::spawn(async move {
        lm.run().await;
    });

    tracing::info!(
        dest = %hex::encode(dest_hash),
        "remote management destination registered"
    );

    Ok(dest_hash)
}

fn peer_allowed(allowed: &[[u8; 16]], peer: &[u8; 16]) -> bool {
    allowed.iter().any(|a| a == peer)
}

/// Request: `[include_link_count: bool]`.
/// Response: `[stats_dict]` or `[stats_dict, link_count]`, where the stats
/// dict is the control port's (Transport.py:3325-3337).
fn handle_status(
    tx: &mpsc::Sender<TransportMessage>,
    data: &[u8],
    ifac: Option<&InterfaceIfacStats>,
    transport: Option<&TransportStatsSource>,
) -> Option<Vec<u8>> {
    let include_link_count = parse_status_request(data).unwrap_or(false);

    let iface_stats = match blocking_query(tx, TransportQuery::GetInterfaceStats)? {
        TransportQueryResponse::InterfaceStats(v) => v,
        _ => return None,
    };

    let link_count = if include_link_count {
        match blocking_query(tx, TransportQuery::GetLinkCount)? {
            TransportQueryResponse::IntResult(n) => Some(n.max(0) as u64),
            _ => None,
        }
    } else {
        None
    };

    rpc::encode_remote_status(
        &stat_entries(iface_stats, ifac),
        transport.map(TransportStatsSource::snapshot).as_ref(),
        link_count,
    )
    .ok()
}

/// Request: `[command: "table"|"rates", destination?: bytes, max_hops?: int]`.
/// Response: the control port's path or rate table, filtered
/// (Transport.py:3346-3371).
fn handle_path(tx: &mpsc::Sender<TransportMessage>, data: &[u8]) -> Option<Vec<u8>> {
    let (command, destination, max_hops) = parse_path_request(data)?;

    let response = match command.as_str() {
        "table" => {
            let entries = match blocking_query(tx, TransportQuery::GetPathTable)? {
                TransportQueryResponse::PathTable(v) => v,
                _ => return None,
            };
            RpcResponse::PathTable(
                entries
                    .into_iter()
                    .filter(|e| destination.is_none_or(|d| e.hash == d))
                    .filter(|e| max_hops.is_none_or(|m| e.hops <= m))
                    .map(|e| rpc::PathTableEntry {
                        hash: e.hash.to_vec(),
                        timestamp: e.timestamp,
                        via: e.via.map(|v| v.to_vec()),
                        hops: e.hops,
                        expires: e.expires,
                        interface: e.interface,
                    })
                    .collect(),
            )
        }
        "rates" => {
            let entries = match blocking_query(tx, TransportQuery::GetRateTable)? {
                TransportQueryResponse::RateTable(v) => v,
                _ => return None,
            };
            RpcResponse::RateTable(
                entries
                    .into_iter()
                    .filter(|e| destination.is_none_or(|d| e.hash == d))
                    .map(|e| rpc::RateTableEntry {
                        hash: e.hash.to_vec(),
                        rate: e.rate,
                        last: e.last,
                        rate_violations: e.rate_violations,
                        blocked_until: e.blocked_until,
                        timestamps: e.timestamps,
                    })
                    .collect(),
            )
        }
        _ => return None,
    };
    rpc::encode_response(&response).ok()
}

fn parse_status_request(data: &[u8]) -> Option<bool> {
    let v: rmpv::Value = rmp_serde::from_slice(data).ok()?;
    v.as_array()?.first()?.as_bool()
}

fn parse_path_request(data: &[u8]) -> Option<(String, Option<[u8; 16]>, Option<u8>)> {
    let v: rmpv::Value = rmp_serde::from_slice(data).ok()?;
    let args = v.as_array()?;
    let command = args.first()?.as_str()?.to_string();
    let destination = args
        .get(1)
        .and_then(|v| v.as_slice())
        .and_then(|s| s.try_into().ok());
    let max_hops = args.get(2).and_then(|v| v.as_u64()).map(|n| n as u8);
    Some((command, destination, max_hops))
}

/// `block_in_place` requires multi-threaded runtime; single-threaded
/// test runtimes panic.
fn blocking_query(
    tx: &mpsc::Sender<TransportMessage>,
    query: TransportQuery,
) -> Option<TransportQueryResponse> {
    let (resp_tx, resp_rx) = oneshot::channel();
    if tx
        .try_send(TransportMessage::Rpc {
            query,
            response_tx: resp_tx,
        })
        .is_err()
    {
        return None;
    }
    tokio::task::block_in_place(|| resp_rx.blocking_recv().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_management_allow_list_denies_empty() {
        let peer = [0x42; 16];
        assert!(
            !peer_allowed(&[], &peer),
            "empty ACL must match Python Destination.ALLOW_LIST and deny all"
        );
    }

    #[test]
    fn remote_management_allow_list_accepts_explicit_peer() {
        let peer = [0x42; 16];
        let other = [0x24; 16];
        assert!(peer_allowed(&[peer], &peer));
        assert!(!peer_allowed(&[peer], &other));
    }

    #[test]
    fn parse_status_request_decodes_bool_array() {
        let data_true = rmp_serde::to_vec(&(true,)).unwrap();
        assert_eq!(parse_status_request(&data_true), Some(true));

        let data_false = rmp_serde::to_vec(&(false,)).unwrap();
        assert_eq!(parse_status_request(&data_false), Some(false));

        let data_empty = rmp_serde::to_vec::<Vec<bool>>(&vec![]).unwrap();
        assert_eq!(parse_status_request(&data_empty), None);
    }

    #[test]
    fn parse_path_request_table_no_filters() {
        let data = rmp_serde::to_vec(&("table",)).unwrap();
        let (cmd, dest, max_hops) = parse_path_request(&data).unwrap();
        assert_eq!(cmd, "table");
        assert_eq!(dest, None);
        assert_eq!(max_hops, None);
    }

    #[test]
    fn parse_path_request_rates_with_destination_and_max_hops() {
        // Python wire: `["rates", msgpack_bin(dest), max_hops]`.
        let dest_bytes = [0xCC; 16];
        let value = rmpv::Value::Array(vec![
            rmpv::Value::from("rates"),
            rmpv::Value::Binary(dest_bytes.to_vec()),
            rmpv::Value::from(3u64),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &value).unwrap();
        let (cmd, dest, max_hops) = parse_path_request(&buf).unwrap();
        assert_eq!(cmd, "rates");
        assert_eq!(dest, Some(dest_bytes));
        assert_eq!(max_hops, Some(3));
    }

    use rns_transport::messages::{InterfaceStatRpcEntry, PathTableRpcEntry, RateTableRpcEntry};

    // RNode-like: a default IFAC size is configured, IFAC itself is off.
    fn mock_stat_entry() -> InterfaceStatRpcEntry {
        InterfaceStatRpcEntry {
            id: 1,
            name: "MockIf".to_string(),
            rx_bytes: 100,
            tx_bytes: 200,
            rx_rate: 10,
            tx_rate: 20,
            online: true,
            bitrate: 12_000,
            mtu: 512,
            mode: "Gateway".to_string(),
            role: "normal".to_string(),
            announce_queue: Some(2),
            held_announces: 1,
            incoming_announce_frequency: 0.5,
            outgoing_announce_frequency: 0.25,
            incoming_pr_frequency: 3.0,
            outgoing_pr_frequency: 1.5,
            burst_active: true,
            burst_activated: 1_700_000_001.0,
            pr_burst_active: true,
            pr_burst_activated: 1_700_000_002.0,
            clients: None,
            blocked_ips: Some(3),
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,
            announce_cap: 0.02,
            ifac_size: 8,
            tx_drops: 0,
            ..Default::default()
        }
    }

    fn spawn_mock_transport() -> mpsc::Sender<TransportMessage> {
        spawn_mock_transport_with(vec![mock_stat_entry()])
    }

    fn spawn_mock_transport_with(
        interfaces: Vec<InterfaceStatRpcEntry>,
    ) -> mpsc::Sender<TransportMessage> {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(16);
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let TransportMessage::Rpc { query, response_tx } = msg {
                    let resp = match query {
                        TransportQuery::GetInterfaceStats => {
                            TransportQueryResponse::InterfaceStats(interfaces.clone())
                        }
                        TransportQuery::GetLinkCount => TransportQueryResponse::IntResult(3),
                        TransportQuery::GetPathTable => {
                            let entries = vec![PathTableRpcEntry {
                                hash: [0x11; 16],
                                timestamp: 1_700_000_000.0,
                                via: Some([0x22; 16]),
                                hops: 2,
                                expires: 1_700_100_000.0,
                                interface: "MockIf".to_string(),
                                interface_id: 1,
                                interface_mode: rns_transport::constants::InterfaceMode::Full,
                                interface_role: rns_transport::messages::InterfaceRole::Normal,
                            }];
                            TransportQueryResponse::PathTable(entries)
                        }
                        TransportQuery::GetRateTable => {
                            let entries = vec![RateTableRpcEntry {
                                hash: [0x33; 16],
                                rate: 1.25,
                                last: 1_700_000_000.0,
                                rate_violations: 2,
                                blocked_until: 0.0,
                                timestamps: vec![1_700_000_000.0],
                            }];
                            TransportQueryResponse::RateTable(entries)
                        }
                        _ => TransportQueryResponse::Ok,
                    };
                    let _ = response_tx.send(resp);
                }
            }
        });
        tx
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_status_end_to_end() {
        let tx = spawn_mock_transport();

        let req = rmp_serde::to_vec(&(true,)).unwrap();
        let resp = handle_status(&tx, &req, None, None).expect("handler produced a response");

        let decoded: rmpv::Value = rmp_serde::from_slice(&resp).unwrap();
        let arr = decoded.as_array().expect("response is an array");
        assert_eq!(arr.len(), 2, "response is [stats_dict, link_count]");
        assert_eq!(arr[1].as_u64(), Some(3), "link count is 3");

        let stats_map = arr[0].as_map().expect("stats is a map");
        let rxb = stats_map
            .iter()
            .find(|(k, _)| k.as_str() == Some("rxb"))
            .unwrap()
            .1
            .as_u64();
        assert_eq!(rxb, Some(100));
        let txb = stats_map
            .iter()
            .find(|(k, _)| k.as_str() == Some("txb"))
            .unwrap()
            .1
            .as_u64();
        assert_eq!(txb, Some(200));

        let ifaces = stats_map
            .iter()
            .find(|(k, _)| k.as_str() == Some("interfaces"))
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert_eq!(ifaces.len(), 1);
        let iface_map = ifaces[0].as_map().unwrap();
        let name = iface_map
            .iter()
            .find(|(k, _)| k.as_str() == Some("name"))
            .unwrap()
            .1
            .as_str();
        assert_eq!(name, Some("MockIf"));
        let mode = iface_map
            .iter()
            .find(|(k, _)| k.as_str() == Some("mode"))
            .unwrap()
            .1
            .as_u64();
        assert_eq!(
            mode,
            Some(0x06),
            "Gateway mode maps to Python MODE_GATEWAY=0x06"
        );
        let incoming_pr = iface_map
            .iter()
            .find(|(k, _)| k.as_str() == Some("incoming_pr_frequency"))
            .unwrap()
            .1
            .as_f64();
        assert_eq!(incoming_pr, Some(3.0));
        let outgoing_pr = iface_map
            .iter()
            .find(|(k, _)| k.as_str() == Some("outgoing_pr_frequency"))
            .unwrap()
            .1
            .as_f64();
        assert_eq!(outgoing_pr, Some(1.5));
        let burst_active = iface_map
            .iter()
            .find(|(k, _)| k.as_str() == Some("burst_active"))
            .unwrap()
            .1
            .as_bool();
        assert_eq!(burst_active, Some(true));
        let pr_burst_active = iface_map
            .iter()
            .find(|(k, _)| k.as_str() == Some("pr_burst_active"))
            .unwrap()
            .1
            .as_bool();
        assert_eq!(pr_burst_active, Some(true));
        let blocked_ips = iface_map
            .iter()
            .find(|(key, _)| key.as_str() == Some("blocked_ips"))
            .and_then(|(_, value)| value.as_u64());
        assert_eq!(blocked_ips, Some(3));
        assert!(
            !iface_map
                .iter()
                .any(|(key, _)| key.as_str() == Some("blocked_ip_list"))
        );
    }

    fn map_get<'a>(map: &'a [(rmpv::Value, rmpv::Value)], key: &str) -> Option<&'a rmpv::Value> {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v)
    }

    fn remote_interfaces(
        stats: &[(rmpv::Value, rmpv::Value)],
    ) -> Vec<Vec<(rmpv::Value, rmpv::Value)>> {
        map_get(stats, "interfaces")
            .and_then(rmpv::Value::as_array)
            .expect("stats list their interfaces")
            .iter()
            .map(|interface| interface.as_map().expect("interface is a map").clone())
            .collect()
    }

    /// Python's `/status` answers with `get_interface_stats()` itself
    /// (Transport.py:3325-3337), so `rnstatus -R` needs the full 1.5.5 key set.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_status_carries_every_python_155_key() {
        let tx = spawn_mock_transport();
        let resp = handle_status(&tx, &rmp_serde::to_vec(&(true,)).unwrap(), None, None).unwrap();
        let decoded: rmpv::Value = rmp_serde::from_slice(&resp).unwrap();
        let stats = decoded.as_array().unwrap()[0].as_map().unwrap();
        for key in crate::rpc::PYTHON_TOTAL_KEYS {
            assert!(map_get(stats, key).is_some(), "missing total {key}");
        }
        let interface = &remote_interfaces(stats)[0];
        for key in crate::rpc::PYTHON_INTERFACE_KEYS {
            assert!(map_get(interface, key).is_some(), "missing {key}");
        }
        assert_eq!(
            map_get(interface, "mtu").and_then(rmpv::Value::as_u64),
            Some(512),
            "rnstatus -R prints the MTU beside the bitrate (rnstatus.py:542-543)"
        );
        assert!(
            map_get(interface, "clients").is_some_and(rmpv::Value::is_nil),
            "rnstatus reads clients unguarded (rnstatus.py:489)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_and_local_stats_map_the_internal_mode_alike() {
        let mut internal = mock_stat_entry();
        internal.mode = "Internal".to_string();
        let tx = spawn_mock_transport_with(vec![internal]);
        let resp = handle_status(&tx, &rmp_serde::to_vec(&(false,)).unwrap(), None, None).unwrap();
        let decoded: rmpv::Value = rmp_serde::from_slice(&resp).unwrap();
        let interface = &remote_interfaces(decoded.as_array().unwrap()[0].as_map().unwrap())[0];
        assert_eq!(
            map_get(interface, "mode").and_then(rmpv::Value::as_u64),
            Some(0x07),
            "Python MODE_INTERNAL (Interface.py:51), as the local RPC reports it"
        );
    }

    /// `rnpath -R -r` sorts the remote rate table on `last` and reads every
    /// rate field (rnpath.py:327-370); Python returns whole rate-table entries
    /// (Transport.py:3364-3369, Reticulum.py:1747-1766).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_rates_return_whole_python_rate_entries() {
        let tx = spawn_mock_transport();
        let resp = handle_path(&tx, &rmp_serde::to_vec(&("rates",)).unwrap()).unwrap();
        let decoded: rmpv::Value = rmp_serde::from_slice(&resp).unwrap();
        let entry = decoded.as_array().unwrap()[0].as_map().unwrap();
        assert_eq!(
            map_get(entry, "hash").and_then(rmpv::Value::as_slice),
            Some(&[0x33; 16][..])
        );
        assert_eq!(
            map_get(entry, "last").and_then(rmpv::Value::as_f64),
            Some(1_700_000_000.0)
        );
        assert_eq!(
            map_get(entry, "rate_violations").and_then(rmpv::Value::as_u64),
            Some(2)
        );
        assert_eq!(
            map_get(entry, "blocked_until").and_then(rmpv::Value::as_f64),
            Some(0.0)
        );
        let timestamps = map_get(entry, "timestamps")
            .and_then(rmpv::Value::as_array)
            .expect("timestamps list");
        assert_eq!(timestamps[0].as_f64(), Some(1_700_000_000.0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_status_without_link_count() {
        let tx = spawn_mock_transport();

        let req = rmp_serde::to_vec(&(false,)).unwrap();
        let resp = handle_status(&tx, &req, None, None).unwrap();
        let decoded: rmpv::Value = rmp_serde::from_slice(&resp).unwrap();
        let arr = decoded.as_array().unwrap();
        assert_eq!(arr.len(), 1, "response is [stats_dict] with no link count");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_path_table_end_to_end() {
        let tx = spawn_mock_transport();

        let req = rmp_serde::to_vec(&("table",)).unwrap();
        let resp = handle_path(&tx, &req).expect("handler produced a response");
        let decoded: rmpv::Value = rmp_serde::from_slice(&resp).unwrap();
        let arr = decoded.as_array().expect("response is an array");
        assert_eq!(arr.len(), 1);

        let entry = arr[0].as_map().unwrap();
        let hops = entry
            .iter()
            .find(|(k, _)| k.as_str() == Some("hops"))
            .unwrap()
            .1
            .as_u64();
        assert_eq!(hops, Some(2));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_path_rates_end_to_end() {
        let tx = spawn_mock_transport();

        let req = rmp_serde::to_vec(&("rates",)).unwrap();
        let resp = handle_path(&tx, &req).expect("handler produced a response");
        let decoded: rmpv::Value = rmp_serde::from_slice(&resp).unwrap();
        let arr = decoded.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let entry = arr[0].as_map().unwrap();
        let rate = entry
            .iter()
            .find(|(k, _)| k.as_str() == Some("rate"))
            .unwrap()
            .1
            .as_f64();
        assert_eq!(rate, Some(1.25));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_path_unknown_command_returns_none() {
        let tx = spawn_mock_transport();
        let req = rmp_serde::to_vec(&("wat",)).unwrap();
        assert!(handle_path(&tx, &req).is_none());
    }
}
