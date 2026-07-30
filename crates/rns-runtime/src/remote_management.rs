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
use rns_transport::messages::{
    InterfaceStatRpcEntry, PathTableRpcEntry, RateTableRpcEntry, TransportMessage, TransportQuery,
    TransportQueryResponse,
};

use crate::remote_management_schema as schema;

const STATUS_PATH: &str = "/status";
const PATH_PATH: &str = "/path";

/// `identity` must be stable across restarts so clients can cache the dest
/// hash. Empty `allowed_identities` denies all peers, matching Python's
/// `Destination.ALLOW_LIST` semantics.
pub async fn start_remote_management(
    transport_tx: mpsc::Sender<TransportMessage>,
    identity: &Identity,
    allowed_identities: Vec<[u8; 16]>,
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
            handle_status(&tx, &data)
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
/// Response: `[stats_dict]` or `[stats_dict, link_count]`.
fn handle_status(tx: &mpsc::Sender<TransportMessage>, data: &[u8]) -> Option<Vec<u8>> {
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

    let stats = build_transport_stats(iface_stats);

    let bytes = if let Some(lc) = link_count {
        rmp_serde::to_vec_named(&(&stats, lc)).ok()?
    } else {
        rmp_serde::to_vec_named(&(&stats,)).ok()?
    };
    Some(bytes)
}

/// Request: `[command: "table"|"rates", destination?: bytes, max_hops?: int]`.
/// Response: list of path-entry or rate-entry dicts.
fn handle_path(tx: &mpsc::Sender<TransportMessage>, data: &[u8]) -> Option<Vec<u8>> {
    let (command, destination, max_hops) = parse_path_request(data)?;

    match command.as_str() {
        "table" => {
            let entries = match blocking_query(tx, TransportQuery::GetPathTable)? {
                TransportQueryResponse::PathTable(v) => v,
                _ => return None,
            };
            let filtered: Vec<schema::PathEntry> = entries
                .into_iter()
                .filter(|e| destination.is_none_or(|d| e.hash == d))
                .filter(|e| max_hops.is_none_or(|m| e.hops <= m))
                .map(path_entry_from_rpc)
                .collect();
            rmp_serde::to_vec_named(&filtered).ok()
        }
        "rates" => {
            let entries = match blocking_query(tx, TransportQuery::GetRateTable)? {
                TransportQueryResponse::RateTable(v) => v,
                _ => return None,
            };
            let filtered: Vec<schema::RateEntry> = entries
                .into_iter()
                .filter(|e| destination.is_none_or(|d| e.hash == d))
                .map(rate_entry_from_rpc)
                .collect();
            rmp_serde::to_vec_named(&filtered).ok()
        }
        _ => None,
    }
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

fn build_transport_stats(entries: Vec<InterfaceStatRpcEntry>) -> schema::TransportStats {
    let (total_rxb, total_txb) = entries
        .iter()
        .fold((0u64, 0u64), |(r, t), e| (r + e.rx_bytes, t + e.tx_bytes));
    let (total_rxs, total_txs) = entries
        .iter()
        .fold((0u64, 0u64), |(r, t), e| (r + e.rx_rate, t + e.tx_rate));

    let interfaces = entries.into_iter().map(interface_stats_from_rpc).collect();

    schema::TransportStats {
        interfaces,
        rxb: total_rxb,
        txb: total_txb,
        rxs: total_rxs,
        txs: total_txs,
        transport_id: None,
        network_id: None,
        transport_uptime: None,
        probe_responder: None,
        rss: None,
    }
}

fn interface_stats_from_rpc(e: InterfaceStatRpcEntry) -> schema::InterfaceStats {
    let mode = mode_from_debug_string(&e.mode);
    let ifac_size = if e.ifac_size > 0 {
        Some(e.ifac_size as u64)
    } else {
        None
    };
    schema::InterfaceStats {
        name: e.name.clone(),
        short_name: e.name,
        hash: None,
        type_: "Interface".to_string(),
        rxb: e.rx_bytes,
        txb: e.tx_bytes,
        incoming_announce_frequency: e.incoming_announce_frequency,
        outgoing_announce_frequency: e.outgoing_announce_frequency,
        incoming_pr_frequency: e.incoming_pr_frequency,
        outgoing_pr_frequency: e.outgoing_pr_frequency,
        held_announces: e.held_announces,
        burst_active: e.burst_active,
        burst_activated: e.burst_activated,
        pr_burst_active: e.pr_burst_active,
        pr_burst_activated: e.pr_burst_activated,
        status: e.online,
        mode,
        bitrate: Some(e.bitrate),
        rxs: e.rx_rate,
        txs: e.tx_rate,
        announce_queue: e.announce_queue,
        clients: e.clients,
        blocked_ips: e.blocked_ips,
        ifac_signature: None,
        ifac_size,
        ifac_netname: None,
    }
}

fn path_entry_from_rpc(e: PathTableRpcEntry) -> schema::PathEntry {
    schema::PathEntry {
        hash: e.hash.to_vec(),
        timestamp: e.timestamp,
        via: e.via.map(|v| v.to_vec()),
        hops: e.hops,
        expires: e.expires,
        interface: e.interface,
    }
}

fn rate_entry_from_rpc(e: RateTableRpcEntry) -> schema::RateEntry {
    schema::RateEntry {
        hash: e.hash.to_vec(),
        rate: e.rate,
    }
}

/// Maps Debug-formatted InterfaceMode to Python `Interface.MODE_*` integers.
fn mode_from_debug_string(s: &str) -> u8 {
    match s {
        "Full" => 0x01,
        "PointToPoint" => 0x02,
        "Access" | "AccessPoint" => 0x03,
        "Roaming" => 0x04,
        "Boundary" => 0x05,
        "Gateway" => 0x06,
        _ => 0x01,
    }
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
    fn status_response_is_python_compatible_list() {
        let stats = schema::TransportStats {
            interfaces: vec![schema::InterfaceStats {
                name: "TestIf".to_string(),
                short_name: "TestIf".to_string(),
                hash: None,
                type_: "Interface".to_string(),
                rxb: 42,
                txb: 7,
                incoming_announce_frequency: 0.0,
                outgoing_announce_frequency: 0.0,
                incoming_pr_frequency: 0.0,
                outgoing_pr_frequency: 0.0,
                held_announces: 0,
                burst_active: false,
                burst_activated: 0.0,
                pr_burst_active: false,
                pr_burst_activated: 0.0,
                status: true,
                mode: 0x01,
                bitrate: Some(1_000_000),
                rxs: 0,
                txs: 0,
                announce_queue: None,
                clients: None,
                blocked_ips: None,
                ifac_signature: None,
                ifac_size: None,
                ifac_netname: None,
            }],
            rxb: 42,
            txb: 7,
            rxs: 0,
            txs: 0,
            transport_id: None,
            network_id: None,
            transport_uptime: None,
            probe_responder: None,
            rss: None,
        };

        let encoded = rmp_serde::to_vec_named(&(&stats, 5u64)).unwrap();
        let decoded: rmpv::Value = rmp_serde::from_slice(&encoded).unwrap();
        let arr = decoded.as_array().expect("top level is an array");
        assert_eq!(arr.len(), 2, "response is [stats_dict, link_count]");

        let stats_map = arr[0].as_map().expect("first element is map");
        let has_interfaces = stats_map
            .iter()
            .any(|(k, _)| k.as_str() == Some("interfaces"));
        assert!(has_interfaces, "stats dict has 'interfaces' key");

        let interface_map = stats_map
            .iter()
            .find(|(key, _)| key.as_str() == Some("interfaces"))
            .and_then(|(_, value)| value.as_array())
            .and_then(|interfaces| interfaces.first())
            .and_then(rmpv::Value::as_map)
            .expect("first interface is a map");
        assert!(
            !interface_map
                .iter()
                .any(|(key, _)| key.as_str() == Some("blocked_ips")),
            "absent aggregate count is omitted"
        );
        assert_eq!(arr[1].as_u64(), Some(5));
    }

    #[test]
    fn status_response_serializes_only_aggregate_blocked_ip_count() {
        let stats = schema::InterfaceStats {
            name: "Backbone".to_string(),
            short_name: "Backbone".to_string(),
            hash: None,
            type_: "Interface".to_string(),
            rxb: 0,
            txb: 0,
            incoming_announce_frequency: 0.0,
            outgoing_announce_frequency: 0.0,
            incoming_pr_frequency: 0.0,
            outgoing_pr_frequency: 0.0,
            held_announces: 0,
            burst_active: false,
            burst_activated: 0.0,
            pr_burst_active: false,
            pr_burst_activated: 0.0,
            status: true,
            mode: 0x01,
            bitrate: Some(1_000_000),
            rxs: 0,
            txs: 0,
            announce_queue: None,
            clients: Some(2),
            blocked_ips: Some(3),
            ifac_signature: None,
            ifac_size: None,
            ifac_netname: None,
        };
        let encoded = rmp_serde::to_vec_named(&stats).unwrap();
        let decoded: rmpv::Value = rmp_serde::from_slice(&encoded).unwrap();
        let map = decoded.as_map().expect("interface stats are a map");
        assert_eq!(
            map.iter()
                .find(|(key, _)| key.as_str() == Some("blocked_ips"))
                .and_then(|(_, value)| value.as_u64()),
            Some(3)
        );
        assert!(
            !map.iter()
                .any(|(key, _)| key.as_str() == Some("blocked_ip_list"))
        );
    }

    #[test]
    fn path_response_is_list_of_dicts() {
        let entry = schema::PathEntry {
            hash: vec![0xAA; 16],
            timestamp: 1_700_000_000.0,
            via: Some(vec![0xBB; 16]),
            hops: 2,
            expires: 1_700_001_000.0,
            interface: "TestIf".to_string(),
        };
        let encoded = rmp_serde::to_vec_named(&vec![entry]).unwrap();
        let decoded: rmpv::Value = rmp_serde::from_slice(&encoded).unwrap();
        let arr = decoded.as_array().expect("top-level array");
        assert_eq!(arr.len(), 1);

        let m = arr[0].as_map().expect("each entry is a map");
        let keys: Vec<&str> = m.iter().filter_map(|(k, _)| k.as_str()).collect();
        for expected in ["hash", "timestamp", "via", "hops", "expires", "interface"] {
            assert!(
                keys.contains(&expected),
                "missing key {expected} in {keys:?}"
            );
        }

        // hash/via are msgpack bin, not arrays-of-ints
        let hash_val = m
            .iter()
            .find(|(k, _)| k.as_str() == Some("hash"))
            .map(|(_, v)| v)
            .unwrap();
        assert_eq!(
            hash_val.as_slice(),
            Some(&[0xAA; 16][..]),
            "hash is msgpack bin"
        );
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

    fn spawn_mock_transport() -> mpsc::Sender<TransportMessage> {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(16);
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let TransportMessage::Rpc { query, response_tx } = msg {
                    let resp = match query {
                        TransportQuery::GetInterfaceStats => {
                            let stats = vec![InterfaceStatRpcEntry {
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
                                ifac_size: 0,
                                tx_drops: 0,
                            }];
                            TransportQueryResponse::InterfaceStats(stats)
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
        let resp = handle_status(&tx, &req).expect("handler produced a response");

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_status_without_link_count() {
        let tx = spawn_mock_transport();

        let req = rmp_serde::to_vec(&(false,)).unwrap();
        let resp = handle_status(&tx, &req).unwrap();
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

    #[test]
    fn mode_mapping_matches_python_constants() {
        assert_eq!(mode_from_debug_string("Full"), 0x01);
        assert_eq!(mode_from_debug_string("PointToPoint"), 0x02);
        assert_eq!(mode_from_debug_string("Access"), 0x03);
        assert_eq!(mode_from_debug_string("Roaming"), 0x04);
        assert_eq!(mode_from_debug_string("Boundary"), 0x05);
        assert_eq!(mode_from_debug_string("Gateway"), 0x06);
        assert_eq!(mode_from_debug_string("Unknown"), 0x01);
    }
}
