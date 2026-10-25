//! Runtime wiring for server interface ids and accepted clients' routing
//! state, observed from the public handle.
use super::*;
use rns_transport::messages::InterfaceStatRpcEntry;
use rns_transport::path_table::{PathEntry, PathTable};
use rns_wire::flags::HeaderType;
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

fn nonce() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn config_dir(tag: &str, config: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rns-wp4-{tag}-{}-{}", std::process::id(), nonce()));
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

async fn start_unix_owner(dir: &Path) -> ReticulumHandle {
    let socket_dir = std::env::temp_dir().join(format!("wp4s{}", nonce() % 1_000_000));
    std::fs::create_dir_all(&socket_dir).unwrap();
    init_with_options(
        Some(dir.to_str().unwrap()),
        Some(socket_dir),
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
        InitOptions {
            shared_instance_type: Some(SharedInstanceType::Unix),
            ..InitOptions::default()
        },
    )
    .await
    .unwrap()
}

async fn unused_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn interfaces(handle: &ReticulumHandle) -> Vec<InterfaceStatRpcEntry> {
    match handle
        .query_transport(TransportQuery::GetInterfaceStats)
        .await
    {
        Some(TransportQueryResponse::InterfaceStats(entries)) => entries,
        other => panic!("unexpected interface stats response: {other:?}"),
    }
}

async fn wait_for_interface(
    handle: &ReticulumHandle,
    matches: impl Fn(&InterfaceStatRpcEntry) -> bool,
) -> Option<InterfaceStatRpcEntry> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(entry) = interfaces(handle)
            .await
            .into_iter()
            .find(|entry| matches(entry))
        {
            return Some(entry);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Minimal SAM v3.1 bridge. Completes HELLO, SESSION CREATE and every STREAM
/// CONNECT, plus the first `accepts` STREAM ACCEPTs, handing each data socket
/// to the test; later accepts stay pending.
async fn fake_sam(
    accepts: usize,
) -> (u16, mpsc::UnboundedReceiver<(String, BufReader<TcpStream>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    let remaining = Arc::new(AtomicUsize::new(accepts));
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let tx = tx.clone();
            let remaining = remaining.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(socket);
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let _ = reader
                    .get_mut()
                    .write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n")
                    .await;
                line.clear();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let command = line.trim().to_string();
                let accepted = command.starts_with("STREAM ACCEPT")
                    && remaining
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok();
                if command.starts_with("SESSION CREATE") {
                    let _ = reader
                        .get_mut()
                        .write_all(b"SESSION STATUS RESULT=OK DESTINATION=wp4fakesamsession\n")
                        .await;
                } else if command.starts_with("STREAM CONNECT") || accepted {
                    let reply: &[u8] = if accepted {
                        b"STREAM STATUS RESULT=OK\nwp4peerdestination0123456789\n"
                    } else {
                        b"STREAM STATUS RESULT=OK\n"
                    };
                    let _ = reader.get_mut().write_all(reply).await;
                    let _ = tx.send((command, reader));
                    return;
                }
                let mut held = Vec::new();
                let _ = reader.read_to_end(&mut held).await;
            });
        }
    });
    (port, rx)
}

#[tokio::test]
async fn the_unix_shared_listener_and_a_connectable_i2p_interface_both_register() {
    let sam_port = unused_port().await;
    let dir = config_dir(
        "unix-i2p",
        &format!(
            "[reticulum]\n  share_instance = Yes\n  shared_instance_type = unix\n  instance_name = wp4u{}\n  enable_transport = No\n\n[interfaces]\n  [[Golden I2P]]\n    type = I2PInterface\n    enabled = yes\n    connectable = yes\n    i2p_sam_host = 127.0.0.1\n    i2p_sam_port = {sam_port}\n",
            nonce() % 1_000_000
        ),
    );
    let handle = start_unix_owner(&dir).await;
    assert_eq!(handle.instance_mode, InstanceMode::Shared);
    assert!(
        handle.startup_interface_failures().is_empty(),
        "{:?}",
        handle.startup_interface_failures()
    );
    let registered = interfaces(&handle).await;
    let id_of = |name: &str| {
        registered
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.id)
    };
    let (listener, i2p) = (id_of("SharedInstanceServer"), id_of("Golden I2P"));
    assert!(
        listener.is_some() && i2p.is_some() && listener != i2p,
        "{registered:?}"
    );

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn two_connectable_i2p_interfaces_both_register() {
    let sam_port = unused_port().await;
    let dir = config_dir(
        "two-i2p",
        &format!(
            "[reticulum]\n  share_instance = No\n\n[interfaces]\n  [[Golden I2P A]]\n    type = I2PInterface\n    enabled = yes\n    connectable = yes\n    i2p_sam_host = 127.0.0.1\n    i2p_sam_port = {sam_port}\n  [[Golden I2P B]]\n    type = I2PInterface\n    enabled = yes\n    connectable = yes\n    i2p_sam_host = 127.0.0.1\n    i2p_sam_port = {sam_port}\n"
        ),
    );
    let handle = start(&dir).await;
    assert!(
        handle.startup_interface_failures().is_empty(),
        "{:?}",
        handle.startup_interface_failures()
    );

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn an_i2p_interface_runs_its_server_and_every_peer() {
    let (sam_port, mut streams) = fake_sam(0).await;
    let peers = ["peeraaaaaaaaaaaa.b32.i2p", "peerbbbbbbbbbbbb.b32.i2p"];
    let dir = config_dir(
        "i2p-every-peer",
        &format!(
            "[reticulum]\n  share_instance = No\n\n[interfaces]\n  [[Golden I2P]]\n    type = I2PInterface\n    enabled = yes\n    connectable = yes\n    peers = {}, {}\n    i2p_sam_host = 127.0.0.1\n    i2p_sam_port = {sam_port}\n",
            peers[0], peers[1]
        ),
    );
    let handle = start(&dir).await;
    assert!(
        handle.startup_interface_failures().is_empty(),
        "{:?}",
        handle.startup_interface_failures()
    );

    let mut commands = Vec::new();
    while commands.len() < peers.len() {
        let (command, _stream) = tokio::time::timeout(Duration::from_secs(10), streams.recv())
            .await
            .expect("every peer opens a SAM stream")
            .unwrap();
        commands.push(command);
    }
    for peer in peers {
        assert!(
            commands
                .iter()
                .any(|command| command.contains(&format!("DESTINATION={peer} "))),
            "{peer}: {commands:?}"
        );
        assert!(
            wait_for_interface(&handle, |entry| entry.name
                == format!("Golden I2P to {peer}"))
            .await
            .is_some(),
            "Python runs one `<name> to <peer>` interface per peer (I2PInterface.py:811-819)"
        );
    }
    assert!(
        interfaces(&handle)
            .await
            .iter()
            .any(|entry| entry.name == "Golden I2P"),
        "the server runs alongside its peers"
    );

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn i2p_server_peers_register_under_their_server() {
    let (sam_port, mut streams) = fake_sam(1).await;
    let dir = config_dir(
        "i2p-peers",
        &format!(
            "[reticulum]\n  share_instance = Yes\n  shared_instance_type = unix\n  instance_name = wp4p{}\n  enable_transport = No\n\n[interfaces]\n  [[Golden I2P]]\n    type = I2PInterface\n    enabled = yes\n    connectable = yes\n    network_name = wp4net\n    i2p_sam_host = 127.0.0.1\n    i2p_sam_port = {sam_port}\n",
            nonce() % 1_000_000
        ),
    );
    let handle = start_unix_owner(&dir).await;

    let (command, _stream) = tokio::time::timeout(Duration::from_secs(10), streams.recv())
        .await
        .expect("the I2P server accepts a SAM stream")
        .unwrap();
    assert!(command.starts_with("STREAM ACCEPT"), "{command}");
    let peer = wait_for_interface(&handle, |entry| entry.name.starts_with("Golden I2P/peer_"))
        .await
        .expect("the accepted peer registers");
    let server = interfaces(&handle)
        .await
        .into_iter()
        .find(|entry| entry.name == "Golden I2P")
        .expect("the I2P server is registered");
    assert_eq!(
        peer.role, "normal",
        "a peer of the I2P server is no shared-instance client"
    );
    assert!(server.ifac_size > 0);
    assert_eq!(
        peer.ifac_size, server.ifac_size,
        "the peer inherits its server's IFAC"
    );

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

async fn path_state_within(
    handle: &ReticulumHandle,
    dest: [u8; 16],
    expected: bool,
    within: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if handle.has_path(dest).await.unwrap() == expected {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn wait_for_path(handle: &ReticulumHandle, dest: [u8; 16]) -> bool {
    path_state_within(handle, dest, true, Duration::from_secs(5)).await
}

fn announce(app: &str) -> (Vec<u8>, [u8; 16]) {
    let identity = Identity::new();
    let mut destination =
        Destination::new(Some(&identity), Direction::In, DestType::Single, app).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let raw = destination
        .announce_packet(&identity, None, None, false, None, now)
        .unwrap();
    (raw, destination.hash)
}

fn hub_config(port: u16, uplink_port: u16) -> String {
    format!(
        "[reticulum]\n  share_instance = No\n  enable_transport = Yes\n\n[interfaces]\n  [[Hub]]\n    type = TCPServerInterface\n    enabled = yes\n    listen_ip = 127.0.0.1\n    listen_port = {port}\n  [[Uplink]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = 127.0.0.1\n    target_port = {uplink_port}\n"
    )
}

/// Persist `paths` the way a previous run would: Python `destination_table`
/// entries plus their cached announces, keyed by interface name.
fn persist_paths(storage: &Path, paths: &[(&[u8], [u8; 16], &str)]) {
    let mut table = PathTable::new();
    let mut names = HashMap::new();
    for (index, (raw, dest, interface)) in paths.iter().enumerate() {
        let id = 900 + index as u64;
        names.insert(id, interface.to_string());
        let packet_hash = rns_wire::hash::packet_hash(raw, HeaderType::Header1);
        rns_transport::persistence::write_python_cached_announce_if_absent(
            &storage.join("cache").join("announces"),
            &packet_hash,
            raw,
            Some(interface),
        )
        .unwrap();
        let mut entry = PathEntry::new(None, 1, id, rns_transport::constants::InterfaceMode::Full);
        entry.packet_hash = Some(packet_hash);
        table.insert(*dest, entry);
    }
    rns_transport::persistence::save_python_destination_table(
        &table,
        &names,
        &storage.join("destination_table"),
    )
    .unwrap();
}

#[tokio::test]
async fn a_persisted_path_never_rebinds_to_an_accepted_client() {
    let uplink_port = unused_port().await;
    let port = unused_port().await;
    let config = hub_config(port, uplink_port);

    // Learn the name this configuration gives its first accepted client.
    let probe_dir = config_dir("child-name", &config);
    let probe = start(&probe_dir).await;
    let first_client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let child_name = wait_for_interface(&probe, |entry| entry.name.starts_with("Hub/client_"))
        .await
        .expect("the first client registers")
        .name;
    probe.shutdown_and_wait().await;
    drop(first_client);
    let _ = std::fs::remove_dir_all(probe_dir);

    let dir = config_dir("child-rebind", &config);
    let storage = dir.join("storage");
    std::fs::create_dir_all(&storage).unwrap();
    let (old_client_announce, old_client_dest) = announce("wp4.child.rebind");
    let (uplink_announce, uplink_dest) = announce("wp4.child.uplink");
    persist_paths(
        &storage,
        &[
            (&old_client_announce, old_client_dest, &child_name),
            (&uplink_announce, uplink_dest, "Uplink"),
        ],
    );

    let handle = start(&dir).await;
    let _other_client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let child = wait_for_interface(&handle, |entry| entry.name.starts_with("Hub/client_"))
        .await
        .expect("the new client registers");
    assert_eq!(child.name, child_name, "precondition: the name is recycled");
    assert!(
        handle.has_path(uplink_dest).await.unwrap(),
        "control: a configured interface rebinds its persisted path"
    );
    assert!(
        !handle.has_path(old_client_dest).await.unwrap(),
        "a recycled client name must not inherit another client's path"
    );

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn accepted_client_paths_are_not_persisted() {
    let uplink_port = unused_port().await;
    let port = unused_port().await;
    let dir = config_dir("child-persist", &hub_config(port, uplink_port));
    let handle = start(&dir).await;

    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (raw, dest) = announce("wp4.child.persist");
    client
        .write_all(&rns_interface::hdlc::frame(&raw))
        .await
        .unwrap();
    assert!(
        wait_for_path(&handle, dest).await,
        "precondition: the hub learns the path"
    );
    handle.shutdown_and_wait().await;
    drop(client);

    let saved = rns_transport::persistence::load_python_destination_table(
        &dir.join("storage").join("destination_table"),
    )
    .unwrap();
    assert!(
        !saved.iter().any(|entry| entry.destination_hash == dest),
        "a path through an accepted client is not persisted"
    );
    let _ = std::fs::remove_dir_all(dir);
}
