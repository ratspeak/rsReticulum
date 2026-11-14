//! Auto-connecting discovered interfaces as Python's `InterfaceDiscovery`
//! does (Discovery.py).
use super::*;
use rns_transport::discovery::app_data::DiscoveryInfo;

fn config_dir(tag: &str, config: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "rns-autoconnect-{tag}-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config"), config).unwrap();
    dir
}

async fn start(dir: &Path) -> ReticulumHandle {
    init(
        Some(dir.to_str().unwrap()),
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
    )
    .await
    .unwrap()
}

async fn unused_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// A Backbone interface a Python 1.6.0 transport node announced.
fn discovered(name: &str, host: &str, port: u16) -> DiscoveredInterface {
    DiscoveredInterface {
        info: DiscoveryInfo {
            name: name.into(),
            transport_id: rns_crypto::sha::truncated_hash(name.as_bytes()),
            impl_name: Some("RNS".into()),
            impl_version: Some("1.6.0".into()),
            interface_type: "BackboneInterface".into(),
            transport_enabled: true,
            reachable_on: Some(host.into()),
            port: Some(port),
            ..Default::default()
        },
        network_id: [0x5a; 16],
        hops: 1,
        stamp_value: 16.0,
        stamp: Vec::new(),
        discovered: 0.0,
        last_heard: 0.0,
        heard_count: 1,
        status: None,
    }
}

async fn autoconnected(handle: &ReticulumHandle) -> usize {
    handle.discovery.autoconnected.lock().await.len()
}

fn hub_config(uplink_port: u16) -> String {
    format!(
        "[reticulum]\n  share_instance = No\n  enable_transport = Yes\n  autoconnect_discovered_interfaces = 4\n\n[interfaces]\n  [[Uplink]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = localhost\n    target_port = {uplink_port}\n"
    )
}

/// Python never auto-connects to an onion address, nor to the literal
/// addresses 127.0.0.1 and 0.0.0.0 (Discovery.py).
#[tokio::test]
async fn autoconnect_refuses_onion_and_local_addresses() {
    let port = unused_port().await;
    let dir = config_dir("refused", &hub_config(unused_port().await));
    let handle = start(&dir).await;

    for host in [
        "hiddenservicexyz.onion",
        "HiddenServiceXYZ.ONION",
        "127.0.0.1",
        "0.0.0.0",
    ] {
        maybe_autoconnect_discovered(&handle, discovered(host, host, port)).await;
    }
    assert_eq!(autoconnected(&handle).await, 0);

    maybe_autoconnect_discovered(&handle, discovered("control", "localhost", port)).await;
    assert_eq!(
        autoconnected(&handle).await,
        1,
        "control: a hostname connects"
    );

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// Python connects once per endpoint, and never beside a client interface
/// already aimed at it (`interface_exists`, Discovery.py), however
/// many announcers name the endpoint.
#[tokio::test]
async fn autoconnect_connects_once_per_endpoint() {
    let (uplink_port, port) = (unused_port().await, unused_port().await);
    let dir = config_dir("endpoints", &hub_config(uplink_port));
    let handle = start(&dir).await;

    maybe_autoconnect_discovered(&handle, discovered("the uplink", "localhost", uplink_port)).await;
    assert_eq!(
        autoconnected(&handle).await,
        0,
        "the configured client already reaches it"
    );

    for name in ["first", "second", "third"] {
        maybe_autoconnect_discovered(&handle, discovered(name, "localhost", port)).await;
    }
    assert_eq!(autoconnected(&handle).await, 1);

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// Python names the network that announced an auto-connected interface in
/// its stats, as the announcer's identity hash in hex (Discovery.py,
/// Reticulum.py), and `rnstatus` prints it (rnstatus.py).
#[tokio::test]
async fn an_autoconnected_interface_names_its_source() {
    let (uplink_port, port) = (unused_port().await, unused_port().await);
    let dir = config_dir("source", &hub_config(uplink_port));
    let handle = start(&dir).await;
    maybe_autoconnect_discovered(&handle, discovered("sourced", "localhost", port)).await;
    let id = handle
        .discovery
        .autoconnected
        .lock()
        .await
        .values()
        .next()
        .and_then(|entry| entry.id)
        .expect("the interface auto-connected");

    let Some(TransportQueryResponse::InterfaceStats(stats)) = handle
        .query_transport(TransportQuery::GetInterfaceStats)
        .await
    else {
        panic!("no interface stats");
    };
    let source = |name: &str| {
        stats
            .iter()
            .find(|entry| {
                entry.name == name
                    || entry
                        .identity
                        .as_ref()
                        .is_some_and(|identity| identity.short_name == name)
            })
            .unwrap_or_else(|| panic!("{name} is listed"))
            .autoconnect_source
            .clone()
    };
    let autoconnected_name = stats
        .iter()
        .find(|entry| entry.id == id)
        .expect("the auto-connected interface is listed")
        .name
        .clone();
    assert_eq!(source(&autoconnected_name), Some(hex::encode([0x5a; 16])));
    assert_eq!(source("Uplink"), None);

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

fn decisions() -> serde_json::Value {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/discovery_autoconnect/decisions.json"
    ))
    .unwrap();
    assert_eq!(fixture["rns_version"], "1.6.0");
    fixture
}

/// rsRNS releases in the fixture that Rust auto-connects without the opt-in
/// and upstream refuses: a deliberate difference, as upstream trusts only RNS.
const RSRNS_TRUSTED_ONLY_HERE: &[&str] = &["1.5.0", "1.6.0"];

/// Upstream's discovery admission and announce decisions, recorded by
/// `tests/fixtures/discovery_autoconnect/gen_decisions.py`.
#[test]
fn autoconnect_and_announce_decisions_match_upstream() {
    let fixture = decisions();
    let mut differences = Vec::new();
    for case in fixture["qualified"].as_array().unwrap() {
        let mut record = discovered("hub", "relay.example.org", 4242);
        record.info.impl_name = case["impl_name"].as_str().map(Into::into);
        record.info.impl_version = case["version"].as_str().map(Into::into);
        record.info.transport_enabled = case["transport"].as_bool().unwrap();
        let allow_unverified = case["allow_unverified"].as_bool().unwrap();
        let config = ReticulumConfig {
            autoconnect_unverified_implementations: allow_unverified,
            ..ReticulumConfig::default()
        };
        let (rust, upstream) = (
            autoconnect_admits(&record, &config),
            case["qualified"].as_bool().unwrap(),
        );
        let version = case["version"].as_str().unwrap();
        if case["impl_name"] == "rsRNS"
            && record.info.transport_enabled
            && !allow_unverified
            && RSRNS_TRUSTED_ONLY_HERE.contains(&version)
        {
            assert!(!upstream, "upstream refuses rsRNS: {case}");
            assert!(rust, "rsRNS 1.5.0 or later is trusted here: {case}");
            differences.push(version);
        } else {
            assert_eq!(rust, upstream, "{case}");
        }
    }
    assert_eq!(differences, RSRNS_TRUSTED_ONLY_HERE);
    for case in fixture["costs"].as_array().unwrap() {
        let mut record = discovered("hub", "relay.example.org", 4242);
        record.info.dst_cost = case["dst_cost"].as_f64();
        record.info.pr_cost = case["pr_cost"].as_f64();
        let stamps = rns_transport::stamps::StampPolicy {
            destination_value: case["dst_value"].as_f64().unwrap(),
            pr_value: case["pr_value"].as_f64().unwrap(),
            ..Default::default()
        };
        assert_eq!(
            autoconnect_costs_acceptable(&record, &stamps),
            case["accepted"].as_bool().unwrap(),
            "{case}"
        );
    }
    for case in fixture["hosts"].as_array().unwrap() {
        let value = case["value"].as_str().unwrap();
        assert_eq!(
            is_ip_address(value) || is_hostname(value),
            case["valid"].as_bool().unwrap(),
            "{case}"
        );
    }
    for case in fixture["locations"].as_array().unwrap() {
        let output = case["output"].as_str().unwrap();
        let sanitized = output.replace(['\n', '\r'], "").trim().to_string();
        let expected = case["location"].as_array().map(|v| {
            (
                v[0].as_f64().unwrap(),
                v[1].as_f64().unwrap(),
                v[2].as_f64().unwrap(),
            )
        });
        assert_eq!(
            parse_discovery_location(&sanitized).ok(),
            expected,
            "{case}"
        );
    }
    for (alias, mode) in fixture["modes"].as_object().unwrap() {
        assert_eq!(
            parse_autoconnect_interface_mode(alias).map(|mode| mode as u64),
            mode.as_u64(),
            "{alias}"
        );
    }
    for case in fixture["names"].as_array().unwrap() {
        let names = case["existing"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            unique_interface_name(&names, case["name"].as_str().unwrap()),
            case["result"].as_str().unwrap()
        );
    }
}

async fn interface_names(handle: &ReticulumHandle) -> Vec<String> {
    match handle
        .query_transport(TransportQuery::GetInterfaceStats)
        .await
    {
        Some(TransportQueryResponse::InterfaceStats(entries)) => {
            entries.into_iter().map(|entry| entry.name).collect()
        }
        _ => Vec::new(),
    }
}

async fn wait_names(
    handle: &ReticulumHandle,
    secs: u64,
    done: impl Fn(&[String]) -> bool,
) -> Vec<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let names = interface_names(handle).await;
        if done(&names) || std::time::Instant::now() > deadline {
            return names;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Python's monitor keeps bootstrap interfaces while no auto-connected
/// interface is online, detaches one that stays down for 12 s, and
/// re-enables bootstrap interfaces once none is attached
/// (Discovery.py).
#[tokio::test(flavor = "multi_thread")]
async fn autoconnect_monitor_detaches_dead_interfaces_and_restores_bootstrap() {
    let bootstrap_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap_port = bootstrap_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = bootstrap_listener.accept().await {
            held.push(socket);
        }
    });
    let dead_port = unused_port().await;
    let dir = config_dir(
        "monitor",
        &format!(
            "[reticulum]\n  share_instance = No\n  enable_transport = Yes\n  autoconnect_discovered_interfaces = 1\n\n[interfaces]\n  [[Seed]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = 127.0.0.1\n    target_port = {bootstrap_port}\n    bootstrap_only = yes\n"
        ),
    );
    let handle = start(&dir).await;
    maybe_autoconnect_discovered(&handle, discovered("Seed", "localhost", dead_port)).await;
    let names = interface_names(&handle).await;
    assert!(
        names.contains(&"Seed (2)".to_string()),
        "a colliding name gets a suffix: {names:?}"
    );

    let names = wait_names(&handle, 30, |names| {
        !names.iter().any(|name| name == "Seed (2)")
    })
    .await;
    assert!(
        !names.iter().any(|name| name == "Seed (2)"),
        "an interface down for 12 s is detached: {names:?}"
    );
    assert!(
        names.contains(&"Seed".to_string()),
        "bootstrap stays while nothing auto-connected is online: {names:?}"
    );
    assert_eq!(autoconnected(&handle).await, 0);

    let seed = handle.discovery.bootstrap_interfaces.lock().await[0];
    teardown_interface(&handle, seed).await;
    let names = wait_names(&handle, 15, |names| names.contains(&"Seed".to_string())).await;
    assert!(
        names.contains(&"Seed".to_string()),
        "bootstrap is re-enabled when no interface is online: {names:?}"
    );

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// Python tears bootstrap interfaces down only once the target number of
/// auto-connected interfaces is online, and gives them `configured_bitrate`
/// 5 Mbit/s (Discovery.py).
#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_interfaces_yield_to_an_online_autoconnected_interface() {
    let listeners = [
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
    ];
    let ports: Vec<u16> = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect();
    for listener in listeners {
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
    }
    let dir = config_dir(
        "yield",
        &format!(
            "[reticulum]\n  share_instance = No\n  enable_transport = Yes\n  autoconnect_discovered_interfaces = 1\n\n[interfaces]\n  [[Seed]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = 127.0.0.1\n    target_port = {}\n    bootstrap_only = yes\n",
            ports[0]
        ),
    );
    let handle = start(&dir).await;
    maybe_autoconnect_discovered(&handle, discovered("Hub", "localhost", ports[1])).await;
    let Some(TransportQueryResponse::InterfaceStats(entries)) = handle
        .query_transport(TransportQuery::GetInterfaceStats)
        .await
    else {
        panic!("no interface stats");
    };
    let hub = entries.iter().find(|entry| entry.name == "Hub").unwrap();
    assert_eq!(hub.bitrate, 5_000_000);
    assert!(
        interface_names(&handle).await.contains(&"Seed".to_string()),
        "bootstrap is not torn down at spawn"
    );
    let names = wait_names(&handle, 15, |names| !names.contains(&"Seed".to_string())).await;
    assert!(
        !names.contains(&"Seed".to_string()) && names.contains(&"Hub".to_string()),
        "{names:?}"
    );

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// Python makes a non-transport instance with a discoverable interface keep
/// a static transport identity (Reticulum.py).
#[test]
fn a_discoverable_interface_makes_the_transport_identity_static() {
    let parse =
        |text: &str| ReticulumConfig::try_from_config(&Config::parse(text).unwrap()).unwrap();
    let iface = "[interfaces]\n  [[Hub]]\n    type = BackboneInterface\n    listen_on = 127.0.0.1\n    port = 4242\n";
    let leaf = parse(&format!(
        "[reticulum]\n  enable_transport = No\n{iface}    discoverable = Yes\n"
    ));
    assert!(leaf.static_transport_identity);
    assert!(!uses_ephemeral_transport_identity(&leaf));
    let quiet = parse(&format!(
        "[reticulum]\n  enable_transport = No\n{iface}    discoverable = No\n"
    ));
    assert!(!quiet.static_transport_identity);
}

/// Python runs an executable `reachable_on` and announces its output only
/// when it is an address or hostname; otherwise the announce is skipped
/// (Discovery.py).
#[cfg(unix)]
#[tokio::test]
async fn an_executable_reachable_on_is_evaluated_and_validated() {
    use std::os::unix::fs::PermissionsExt;
    let dir = config_dir("reachable", "");
    let script = |name: &str, body: &str| {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    };
    let config = |reachable_on: String| {
        let mut config = DiscoveryInterfaceConfig::backbone(Some("Hub".into()), reachable_on, 4242);
        config.interface_type = "TCPServerInterface".into();
        config
    };
    let resolved = resolve_discovery_inputs(config(script("good", "echo relay.example.org")), None)
        .await
        .expect("a valid script output is announced");
    assert_eq!(resolved.reachable_on.as_deref(), Some("relay.example.org"));
    for body in ["echo 'not a host!'", "echo relay.example.org; exit 1"] {
        assert!(
            resolve_discovery_inputs(config(script("bad", body)), None)
                .await
                .is_none(),
            "{body}"
        );
    }
    assert!(
        resolve_discovery_inputs(config("not a host!".into()), None)
            .await
            .is_none()
    );
    let located = resolve_discovery_inputs(
        config("10.0.0.1".into()),
        Some(&script("where", "echo 51.5,-0.1,30")),
    )
    .await
    .unwrap();
    assert_eq!(
        (located.latitude, located.longitude, located.height),
        (Some(51.5), Some(-0.1), Some(30.0))
    );
    let _ = std::fs::remove_dir_all(dir);
}
