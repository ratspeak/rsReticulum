//! Auto-connecting discovered interfaces as Python's `InterfaceDiscovery`
//! does (Discovery.py:747-870).
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

/// A Backbone interface a Python 1.5.5 transport node announced.
fn discovered(name: &str, host: &str, port: u16) -> DiscoveredInterface {
    DiscoveredInterface {
        info: DiscoveryInfo {
            name: name.into(),
            transport_id: rns_crypto::sha::truncated_hash(name.as_bytes()),
            impl_name: Some("RNS".into()),
            impl_version: Some("1.5.5".into()),
            interface_type: "BackboneInterface".into(),
            transport_enabled: true,
            reachable_on: Some(host.into()),
            port: Some(port),
            ..Default::default()
        },
        network_id: [0x5a; 16],
        hops: 1,
        stamp_value: 16,
        stamp: Vec::new(),
        discovered: 0,
        last_heard: 0,
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
/// addresses 127.0.0.1 and 0.0.0.0 (Discovery.py:814-825, :982).
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
/// already aimed at it (`interface_exists`, Discovery.py:747-770), however
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
/// its stats, as the announcer's identity hash in hex (Discovery.py:865,
/// Reticulum.py:1611-1612), and `rnstatus` prints it (rnstatus.py:525-526).
#[tokio::test]
async fn an_autoconnected_interface_names_its_source() {
    let (uplink_port, port) = (unused_port().await, unused_port().await);
    let dir = config_dir("source", &hub_config(uplink_port));
    let handle = start(&dir).await;
    maybe_autoconnect_discovered(&handle, discovered("sourced", "localhost", port)).await;
    let id = *handle
        .discovery
        .autoconnected
        .lock()
        .await
        .values()
        .next()
        .expect("the interface auto-connected");

    let Some(TransportQueryResponse::InterfaceStats(entries)) = handle
        .query_transport(TransportQuery::GetInterfaceStats)
        .await
    else {
        panic!("no interface stats");
    };
    let records = InterfaceIfacStats(handle.interface_controls.clone());
    let stats = crate::rpc_server::stat_entries(entries, Some(&records));
    let source = |name: &str| {
        stats
            .iter()
            .find(|entry| entry.name == name)
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
