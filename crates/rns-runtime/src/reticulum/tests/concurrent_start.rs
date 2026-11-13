//! `InitOptions::start_interfaces_concurrently`: start-up time, ids, listing
//! order, and failure handling against the default one-at-a-time start.
use super::*;
use rns_interface::tcp::INITIAL_CONNECT_TIMEOUT;

/// TEST-NET-1 is unrouted, so a connect to it hangs until its timeout.
const UNROUTED: &str = "192.0.2.1";

fn config_dir(tag: &str, config: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("rns-together-{tag}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config"), config).unwrap();
    dir
}

async fn start(dir: &Path, options: InitOptions) -> Result<ReticulumHandle, ReticulumError> {
    init_with_options(
        Some(dir.to_str().unwrap()),
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
        options,
    )
    .await
}

async fn listed(handle: &ReticulumHandle) -> Vec<(u64, String)> {
    match handle
        .query_control_result(TransportQuery::GetInterfaceStats)
        .await
    {
        Ok(TransportQueryResponse::InterfaceStats(stats)) => stats
            .into_iter()
            .map(|entry| (entry.id, entry.name))
            .collect(),
        other => panic!("interface stats: {other:?}"),
    }
}

/// A network without a route refuses TEST-NET-1 at once and leaves no wait to
/// measure.
async fn unrouted_connect_hangs() -> bool {
    tokio::time::timeout(
        Duration::from_secs(1),
        tokio::net::TcpStream::connect((UNROUTED, 4242)),
    )
    .await
    .is_err()
}

/// Two clients whose first connect times out, then one that connects at once.
async fn start_two_unreachable_clients(
    options: InitOptions,
) -> (Duration, Vec<(u64, String)>, bool) {
    let hangs = unrouted_connect_hangs().await;
    let reachable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reachable.local_addr().unwrap().port();
    let client = |name: &str, host: &str, port: u16| {
        format!(
            "[[{name}]]\ntype = TCPClientInterface\nenabled = Yes\ntarget_host = {host}\ntarget_port = {port}\n"
        )
    };
    let dir = config_dir(
        "unreachable",
        &format!(
            "[reticulum]\nshare_instance = No\nenable_transport = No\n\n[interfaces]\n{}{}{}",
            client("Unreachable A", UNROUTED, 4242),
            client("Unreachable B", UNROUTED, 4242),
            client("Reachable", "127.0.0.1", port),
        ),
    );
    let started = std::time::Instant::now();
    let handle = start(&dir, options)
        .await
        .expect("unreachable servers do not fail start-up");
    let elapsed = started.elapsed();
    assert!(
        handle.startup_interface_failures().is_empty(),
        "{:?}",
        handle.startup_interface_failures()
    );
    let listed = listed(&handle).await;
    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
    (elapsed, listed, hangs)
}

fn in_config_order() -> Vec<(u64, String)> {
    vec![
        (1, "Unreachable A".to_string()),
        (2, "Unreachable B".to_string()),
        (3, "Reachable".to_string()),
    ]
}

#[tokio::test]
async fn unreachable_clients_started_together_cost_one_connect_timeout() {
    let (elapsed, listed, hangs) = start_two_unreachable_clients(InitOptions {
        start_interfaces_concurrently: true,
        ..InitOptions::default()
    })
    .await;
    // The reachable client registers first, yet ids and listing follow the config.
    assert_eq!(listed, in_config_order());
    if !hangs {
        eprintln!("{UNROUTED} is refused at once here: start-up time not measured");
        return;
    }
    let one = Duration::from_secs(INITIAL_CONNECT_TIMEOUT);
    assert!(
        elapsed >= one && elapsed < one * 2 - Duration::from_secs(1),
        "start-up took {elapsed:?}, expected about {one:?}"
    );
}

#[tokio::test]
async fn unreachable_clients_started_one_at_a_time_cost_a_connect_timeout_each() {
    let (elapsed, listed, hangs) = start_two_unreachable_clients(InitOptions::default()).await;
    assert_eq!(listed, in_config_order());
    if !hangs {
        eprintln!("{UNROUTED} is refused at once here: start-up time not measured");
        return;
    }
    let two = Duration::from_secs(INITIAL_CONNECT_TIMEOUT * 2);
    assert!(
        elapsed >= two && elapsed < two + Duration::from_secs(4),
        "start-up took {elapsed:?}, expected about {two:?}"
    );
}

/// A listener, an interface on an occupied port, and a second listener.
fn one_failing_interface() -> (PathBuf, std::net::UdpSocket, [u16; 2]) {
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_port = occupied.local_addr().unwrap().port();
    let free_port = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let ports = [free_port(), free_port()];
    let server = |name: &str, port: u16| {
        format!(
            "[[{name}]]\ntype = TCPServerInterface\nenabled = Yes\nlisten_ip = 127.0.0.1\nlisten_port = {port}\n"
        )
    };
    let dir = config_dir(
        "failing",
        &format!(
            "[reticulum]\nshare_instance = No\n\n[interfaces]\n{}[[LAN]]\ntype = UDPInterface\nenabled = Yes\nlisten_ip = 127.0.0.1\nlisten_port = {udp_port}\nforward_ip = 127.0.0.1\nforward_port = {udp_port}\n{}",
            server("Before", ports[0]),
            server("After", ports[1]),
        ),
    );
    (dir, occupied, ports)
}

async fn listening(port: u16) -> bool {
    tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .is_ok()
}

#[tokio::test]
async fn a_failed_interface_stops_a_concurrent_start_as_it_stops_a_sequential_one() {
    let (dir, _occupied, ports) = one_failing_interface();
    let sequential = start(&dir, InitOptions::default())
        .await
        .err()
        .expect("an occupied port fails start-up")
        .to_string();
    let concurrent = start(
        &dir,
        InitOptions {
            start_interfaces_concurrently: true,
            ..InitOptions::default()
        },
    )
    .await
    .err()
    .expect("an occupied port fails a concurrent start-up")
    .to_string();
    assert_eq!(concurrent, sequential);
    for port in ports {
        assert!(!listening(port).await, "every started listener is closed");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_failed_interface_is_recorded_and_the_rest_start_together() {
    let (dir, _occupied, ports) = one_failing_interface();
    let handle = start(
        &dir,
        InitOptions {
            start_interfaces_concurrently: true,
            keep_starting_after_interface_failure: true,
            ..InitOptions::default()
        },
    )
    .await
    .expect("the failure is recorded");
    let failures = handle.startup_interface_failures();
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(failures[0].0, "LAN");
    // The failed interface keeps the id a sequential start gives it.
    assert_eq!(
        listed(&handle).await,
        vec![(1, "Before".to_string()), (3, "After".to_string())]
    );
    for port in ports {
        assert!(listening(port).await);
    }
    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ids_are_reserved_for_every_interface_a_section_starts() {
    let config = Config::parse(
        "[reticulum]\n\n[interfaces]\n[[Peered]]\ntype = I2PInterface\nenabled = Yes\nconnectable = Yes\npeers = aaaa.b32.i2p, bbbb.b32.i2p\n[[Peers Only]]\ntype = I2PInterface\nenabled = Yes\npeers = cccc.b32.i2p\n[[Plain]]\ntype = TCPClientInterface\nenabled = Yes\ntarget_host = 127.0.0.1\ntarget_port = 4242\n",
    )
    .unwrap();
    let interfaces = synthesize_interfaces(&config, None).unwrap();
    let id_gen = Arc::new(AtomicU64::new(1));
    let reserved: Vec<_> = interfaces
        .iter()
        .map(|interface| reserve_interface_ids(interface, &id_gen))
        .collect();
    assert_eq!(
        reserved,
        vec![(1, vec![2, 3]), (4, vec![]), (5, vec![])],
        "a server and its peers, a lone peer, then the next interface"
    );
}
