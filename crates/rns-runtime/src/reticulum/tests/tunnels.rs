//! Runtime wiring for tunnel synthesis, server interface ids and accepted
//! clients' routing state, observed from the wire and the public handle.
use super::*;
use rns_transport::messages::InterfaceStatRpcEntry;
use rns_transport::path_table::{PathEntry, PathTable};
use rns_transport::tunnel::TunnelSynthesisData;
use rns_wire::context::PacketContext;
use rns_wire::flags::{DestinationType, HeaderType, PacketFlags, PacketType, TransportType};
use rns_wire::header::PacketHeader;
use std::collections::VecDeque;
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
    let dir = std::env::temp_dir().join(format!(
        "rns-tunnels-{tag}-{}-{}",
        std::process::id(),
        nonce()
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

#[cfg(unix)]
async fn start_unix_owner(dir: &Path) -> ReticulumHandle {
    let socket_dir = std::env::temp_dir().join(format!("tuns{}", nonce() % 1_000_000));
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
                        .write_all(b"SESSION STATUS RESULT=OK DESTINATION=fakesamsession\n")
                        .await;
                } else if command.starts_with("STREAM CONNECT") || accepted {
                    let reply: &[u8] = if accepted {
                        b"STREAM STATUS RESULT=OK\npeerdestination0123456789\n"
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

// Off Unix the shared listener binds a fixed TCP port.
#[cfg(unix)]
#[tokio::test]
async fn the_unix_shared_listener_and_a_connectable_i2p_interface_both_register() {
    let sam_port = unused_port().await;
    let dir = config_dir(
        "unix-i2p",
        &format!(
            "[reticulum]\n  share_instance = Yes\n  shared_instance_type = unix\n  instance_name = tunu{}\n  enable_transport = No\n\n[interfaces]\n  [[Golden I2P]]\n    type = I2PInterface\n    enabled = yes\n    connectable = yes\n    i2p_sam_host = 127.0.0.1\n    i2p_sam_port = {sam_port}\n",
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

    let mut openings = HashMap::new();
    while openings.len() < peers.len() {
        let (command, stream) = tokio::time::timeout(Duration::from_secs(10), streams.recv())
            .await
            .expect("every peer opens a SAM stream")
            .unwrap();
        let peer = peers
            .into_iter()
            .find(|peer| command.contains(&format!("DESTINATION={peer} ")))
            .unwrap_or_else(|| panic!("unexpected stream: {command}"));
        let opening = Frames::new(stream, false)
            .next(Duration::from_secs(5))
            .await
            .and_then(|frame| synthesis_in(&frame))
            .expect("every peer connection opens with a tunnel synthesis");
        openings.insert(peer, opening.interface_hash);
    }
    for peer in peers {
        assert_eq!(
            openings[peer],
            python_interface_hash(&format!("I2PInterfacePeer[Golden I2P to {peer}]")),
            "each peer synthesizes under its own Python name"
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

#[cfg(unix)]
#[tokio::test]
async fn i2p_server_peers_register_under_their_server() {
    let (sam_port, mut streams) = fake_sam(1).await;
    let dir = config_dir(
        "i2p-peers",
        &format!(
            "[reticulum]\n  share_instance = Yes\n  shared_instance_type = unix\n  instance_name = tunp{}\n  enable_transport = No\n\n[interfaces]\n  [[Golden I2P]]\n    type = I2PInterface\n    enabled = yes\n    connectable = yes\n    network_name = tunnelnet\n    i2p_sam_host = 127.0.0.1\n    i2p_sam_port = {sam_port}\n",
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
    let (old_client_announce, old_client_dest) = announce("child.rebind");
    let (uplink_announce, uplink_dest) = announce("child.uplink");
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
    let (raw, dest) = announce("child.persist");
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

/// Forwards connections to `upstream`; `cut` drops every live connection.
struct Proxy {
    port: u16,
    cut: watch::Sender<u64>,
}

impl Proxy {
    async fn start(upstream: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (cut, cut_rx) = watch::channel(0u64);
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                let mut cut_rx = cut_rx.clone();
                cut_rx.borrow_and_update();
                tokio::spawn(async move {
                    let Ok(mut outbound) = TcpStream::connect(("127.0.0.1", upstream)).await else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {}
                        _ = cut_rx.changed() => {}
                    }
                });
            }
        });
        Self { port, cut }
    }

    fn cut(&self) {
        self.cut.send_modify(|generation| *generation += 1);
    }
}

/// Frames a hub reads from one client connection, in arrival order.
struct Frames {
    reader: BufReader<TcpStream>,
    kiss: bool,
    hdlc: rns_interface::hdlc::HdlcDeframer,
    kiss_frames: rns_interface::kiss::KissDeframer,
    ready: VecDeque<Vec<u8>>,
}

impl Frames {
    fn new(reader: BufReader<TcpStream>, kiss: bool) -> Self {
        Self {
            reader,
            kiss,
            hdlc: rns_interface::hdlc::HdlcDeframer::new(),
            kiss_frames: rns_interface::kiss::KissDeframer::new(),
            ready: VecDeque::new(),
        }
    }

    async fn accept(listener: &TcpListener, kiss: bool) -> Self {
        let (stream, _) = tokio::time::timeout(Duration::from_secs(20), listener.accept())
            .await
            .expect("the client connects")
            .unwrap();
        Self::new(BufReader::new(stream), kiss)
    }

    async fn next(&mut self, within: Duration) -> Option<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Some(frame);
            }
            let mut buf = [0u8; 4096];
            let n = match tokio::time::timeout_at(deadline, self.reader.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return None,
            };
            if self.kiss {
                let frames = self.kiss_frames.feed(&buf[..n]);
                self.ready.extend(
                    frames
                        .into_iter()
                        .filter(|(command, _)| *command == 0)
                        .map(|(_, frame)| frame),
                );
            } else {
                self.ready.extend(self.hdlc.feed(&buf[..n]));
            }
            self.ready.retain(|frame| !frame.is_empty());
        }
    }

    async fn collect(&mut self, within: Duration) -> Vec<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + within;
        let mut frames = Vec::new();
        while let Some(frame) = self
            .next(deadline.saturating_duration_since(tokio::time::Instant::now()))
            .await
        {
            frames.push(frame);
        }
        frames
    }
}

fn synthesis_in(frame: &[u8]) -> Option<TunnelSynthesisData> {
    let (header, offset) = PacketHeader::unpack(frame).ok()?;
    let synthesize =
        Destination::hash_from_name_and_identity("rnstransport.tunnel.synthesize", None);
    let shape = header.destination_hash == synthesize
        && header.flags.header_type == HeaderType::Header1
        && header.flags.transport_type == TransportType::Broadcast
        && header.flags.destination_type == DestinationType::Plain
        && header.flags.packet_type == PacketType::Data
        && header.hops == 0
        && header.context == PacketContext::None
        && frame.len() == offset + 176;
    shape
        .then(|| TunnelSynthesisData::unpack(&frame[offset..]))
        .flatten()
}

fn assert_signed(synthesis: &TunnelSynthesisData) {
    let signer = Identity::from_public_key(&synthesis.public_key).unwrap();
    let mut signed = synthesis.public_key.to_vec();
    signed.extend_from_slice(&synthesis.interface_hash);
    signed.extend_from_slice(&synthesis.random_hash);
    assert!(
        signer.verify(&signed, &synthesis.signature),
        "the synthesis verifies under its own Ed25519 key"
    );
}

/// Python `Interface.get_hash()`: the full hash of `str(interface)`.
fn python_interface_hash(python_str: &str) -> [u8; 32] {
    rns_transport::tunnel::interface_hash(python_str)
}

/// Queue a PLAIN broadcast for every interface; returns its wire bytes.
async fn send_plain_marker(handle: &ReticulumHandle, app: &str) -> Vec<u8> {
    let destination_hash = Destination::hash_from_name_and_identity(app, None);
    let mut marker = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Plain,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash,
        context: PacketContext::None,
    }
    .pack();
    marker.extend_from_slice(app.as_bytes());
    handle
        .transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(marker.clone()),
            destination_hash,
        }))
        .await
        .unwrap();
    marker
}

#[tokio::test]
async fn a_tcp_client_opens_every_connection_with_its_tunnel_synthesis() {
    let hub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = hub.local_addr().unwrap().port();
    let dir = config_dir(
        "tcp-synthesis",
        &format!(
            "[reticulum]\n  share_instance = No\n\n[interfaces]\n  [[Uplink]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = 127.0.0.1\n    target_port = {port}\n"
        ),
    );
    let handle = start(&dir).await;

    let mut first = Frames::accept(&hub, false).await;
    let opening = first
        .next(Duration::from_secs(5))
        .await
        .and_then(|frame| synthesis_in(&frame))
        .expect("a new connection opens with a tunnel synthesis (TCPInterface.py:178-179)");
    assert_eq!(
        opening.public_key,
        handle.transport_identity.get_public_key(),
        "signed with the per-process transport identity (Transport.py:2767)"
    );
    assert_eq!(
        opening.interface_hash,
        python_interface_hash(&format!("TCPInterface[Uplink/127.0.0.1:{port}]")),
        "the interface hash is Python's get_hash() of str(TCPClientInterface)"
    );
    assert_signed(&opening);

    drop(first);
    let mut second = Frames::accept(&hub, false).await;
    let reopening = second
        .next(Duration::from_secs(5))
        .await
        .and_then(|frame| synthesis_in(&frame))
        .expect("a reconnect opens with a fresh synthesis (TCPInterface.py:298-299)");
    assert_eq!(reopening.tunnel_id(), opening.tunnel_id());
    assert_ne!(reopening.random_hash, opening.random_hash);
    assert_signed(&reopening);

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_tcp_client_drops_traffic_queued_while_it_was_disconnected() {
    let hub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = hub.local_addr().unwrap().port();
    let dir = config_dir(
        "tcp-backlog",
        &format!(
            "[reticulum]\n  share_instance = No\n\n[interfaces]\n  [[Uplink]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = 127.0.0.1\n    target_port = {port}\n"
        ),
    );
    let handle = start(&dir).await;

    drop(Frames::accept(&hub, false).await);
    assert!(
        wait_for_interface(&handle, |entry| entry.name == "Uplink" && !entry.online)
            .await
            .is_some(),
        "the client notices the lost connection"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;

    let marker = send_plain_marker(&handle, "backlog").await;

    let mut second = Frames::accept(&hub, false).await;
    let frames = second.collect(Duration::from_secs(2)).await;
    assert!(
        !frames.contains(&marker),
        "Python drops packets while offline (TCPInterface.py:314-315)"
    );

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// A failed connection attempt is an outage too: traffic queued while a
/// client's first attempts fail is dropped, so however much was queued the
/// synthesis opens the connection (Python drops traffic while offline,
/// TCPInterface.py:314-315).
async fn assert_failed_first_attempts_drop_their_backlog(tag: &str, port: u16, interface: &str) {
    let dir = config_dir(
        tag,
        &format!("[reticulum]\n  share_instance = No\n\n[interfaces]\n{interface}"),
    );
    let handle = start(&dir).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut markers = Vec::new();
    for n in 0..1100 {
        markers.push(send_plain_marker(&handle, &format!("backlog.{tag}.{n}")).await);
    }
    let hub = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let mut connection = Frames::accept(&hub, false).await;
    let first = connection
        .next(Duration::from_secs(5))
        .await
        .expect("the connection carries a frame");
    assert!(
        synthesis_in(&first).is_some(),
        "the synthesis opens the connection despite the backlog"
    );
    let rest = connection.collect(Duration::from_secs(2)).await;
    assert!(
        !rest.iter().any(|frame| markers.contains(frame)),
        "traffic queued while the first attempts failed is dropped"
    );

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_tcp_client_drops_traffic_queued_while_its_first_attempts_fail() {
    let port = unused_port().await;
    assert_failed_first_attempts_drop_their_backlog(
        "tcp-first-backlog",
        port,
        &format!("  [[Uplink]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = 127.0.0.1\n    target_port = {port}\n"),
    )
    .await;
}

#[tokio::test]
async fn a_backbone_client_drops_traffic_queued_while_its_first_attempts_fail() {
    let port = unused_port().await;
    assert_failed_first_attempts_drop_their_backlog(
        "backbone-first-backlog",
        port,
        &format!("  [[Backbone Up]]\n    type = BackboneInterface\n    enabled = yes\n    target_host = 127.0.0.1\n    port = {port}\n"),
    )
    .await;
}

#[test]
fn the_shared_instance_client_never_synthesizes() {
    assert!(
        shared_tcp_client_config(37428).tunnel_identity.is_none(),
        "Python's LocalInterface never synthesizes"
    );
}

#[tokio::test]
async fn a_kiss_framed_tcp_client_never_synthesizes() {
    let hub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = hub.local_addr().unwrap().port();
    let dir = config_dir(
        "tcp-kiss",
        &format!(
            "[reticulum]\n  share_instance = No\n\n[interfaces]\n  [[KISS Uplink]]\n    type = TCPClientInterface\n    enabled = yes\n    kiss_framing = yes\n    target_host = 127.0.0.1\n    target_port = {port}\n"
        ),
    );
    let handle = start(&dir).await;

    let mut connection = Frames::accept(&hub, true).await;
    let frames = connection.collect(Duration::from_secs(2)).await;
    assert!(
        frames.iter().all(|frame| synthesis_in(frame).is_none()),
        "Python never synthesizes on KISS framing (TCPInterface.py:178-179, :298-299)"
    );

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_backbone_client_opens_with_its_tunnel_synthesis() {
    let hub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = hub.local_addr().unwrap().port();
    let dir = config_dir(
        "backbone-synthesis",
        &format!(
            "[reticulum]\n  share_instance = No\n\n[interfaces]\n  [[Backbone Up]]\n    type = BackboneInterface\n    enabled = yes\n    target_host = 127.0.0.1\n    port = {port}\n"
        ),
    );
    let handle = start(&dir).await;

    let mut connection = Frames::accept(&hub, false).await;
    let opening = connection
        .next(Duration::from_secs(5))
        .await
        .and_then(|frame| synthesis_in(&frame))
        .expect("a Backbone connection opens with a tunnel synthesis (BackboneInterface.py:922)");
    assert_eq!(
        opening.public_key,
        handle.transport_identity.get_public_key()
    );
    assert_eq!(
        opening.interface_hash,
        python_interface_hash(&format!("BackboneInterface[Backbone Up/127.0.0.1:{port}]"))
    );
    assert_signed(&opening);

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn an_i2p_client_opens_with_its_tunnel_synthesis() {
    let (sam_port, mut streams) = fake_sam(0).await;
    let peer = "abcdefghijklmnop.b32.i2p";
    let dir = config_dir(
        "i2p-synthesis",
        &format!(
            "[reticulum]\n  share_instance = No\n\n[interfaces]\n  [[Golden I2P]]\n    type = I2PInterface\n    enabled = yes\n    peers = {peer}\n    i2p_sam_host = 127.0.0.1\n    i2p_sam_port = {sam_port}\n"
        ),
    );
    let handle = start(&dir).await;

    let (command, stream) = tokio::time::timeout(Duration::from_secs(10), streams.recv())
        .await
        .expect("the client opens a SAM stream")
        .unwrap();
    assert!(command.starts_with("STREAM CONNECT"), "{command}");
    let mut connection = Frames::new(stream, false);
    let opening = connection
        .next(Duration::from_secs(5))
        .await
        .and_then(|frame| synthesis_in(&frame))
        .expect("an I2P peer connection opens with a tunnel synthesis (I2PInterface.py:503)");
    assert_eq!(
        opening.public_key,
        handle.transport_identity.get_public_key()
    );
    assert_eq!(
        opening.interface_hash,
        python_interface_hash(&format!("I2PInterfacePeer[Golden I2P to {peer}]"))
    );
    assert_signed(&opening);

    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_rust_hub_restores_a_reconnecting_rust_clients_paths() {
    let uplink_port = unused_port().await;
    let hub_port = unused_port().await;
    let hub_dir = config_dir("rust-hub", &hub_config(hub_port, uplink_port));
    let hub = start(&hub_dir).await;
    let proxy = Proxy::start(hub_port).await;
    let client_dir = config_dir(
        "rust-client",
        &format!(
            "[reticulum]\n  share_instance = No\n\n[interfaces]\n  [[Hub Uplink]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = 127.0.0.1\n    target_port = {}\n",
            proxy.port
        ),
    );
    let client = start(&client_dir).await;
    // An interface reports online once its synthesis is queued; Python's
    // startup likewise synthesizes before applications announce.
    assert!(
        wait_for_interface(&client, |entry| entry.name == "Hub Uplink" && entry.online)
            .await
            .is_some(),
        "the client connects"
    );
    let destination = client
        .register_destination(
            Identity::new(),
            "tunnel.rust",
            crate::destination_runtime::DestinationRuntimeOptions::default(),
        )
        .await
        .unwrap();
    destination
        .handle
        .announce(crate::link_manager::DestinationAnnounceOptions::default())
        .await
        .unwrap();
    let dest = destination.handle.destination_hash();

    assert!(
        wait_for_path(&hub, dest).await,
        "the hub learns the client's announce"
    );
    proxy.cut();
    assert!(
        path_state_within(&hub, dest, false, Duration::from_secs(10)).await,
        "the hub drops the lost connection's paths"
    );
    assert!(
        path_state_within(&hub, dest, true, Duration::from_secs(20)).await,
        "the client's reconnect synthesis restores its path without a new announce"
    );

    client.shutdown_and_wait().await;
    hub.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(client_dir);
    let _ = std::fs::remove_dir_all(hub_dir);
}
