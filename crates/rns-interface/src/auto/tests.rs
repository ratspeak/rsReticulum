use super::*;

/// A free run of `n` consecutive UDP ports.
fn free_ports(n: u16) -> u16 {
    loop {
        let probe = std::net::UdpSocket::bind("[::]:0").unwrap();
        let base = probe.local_addr().unwrap().port();
        drop(probe);
        if base.checked_add(n).is_some()
            && (0..n).all(|i| std::net::UdpSocket::bind(("::", base + i)).is_ok())
        {
            return base;
        }
    }
}

#[test]
fn beacon_is_deterministic_and_bound_to_group_and_address() {
    let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let token = discovery_token("reticulum", &addr);
    assert_eq!(token, discovery_token("reticulum", &addr));
    assert!(verify_beacon(&token, "reticulum", &addr));
    assert!(!verify_beacon(&token, "other_group", &addr));
    assert!(!verify_beacon(
        &token,
        "reticulum",
        &Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)
    ));
    assert!(!verify_beacon(&token[..16], "reticulum", &addr));
}

#[test]
fn link_locals_group_per_interface_selecting_the_last() {
    let a: Ipv6Addr = "fe80::1".parse().unwrap();
    let b: Ipv6Addr = "fe80::2".parse().unwrap();
    let c: Ipv6Addr = "fe80::3".parse().unwrap();
    let nics = group_link_locals(vec![
        ("eth0".into(), a, 2),
        ("wlan0".into(), c, 3),
        ("eth0".into(), b, 2),
    ]);
    assert_eq!(nics.len(), 2);
    assert_eq!(nics[0].ifname, "eth0");
    assert_eq!(nics[0].link_local, b);
    assert_eq!(nics[0].all, vec![a, b]);
    assert_eq!(nics[1].link_local, c);
}

#[test]
fn multi_if_dedup_drops_repeats_and_stays_bounded() {
    let mut dedup = MultiIfDedup::new();
    assert!(!dedup.is_duplicate(b"packet one"));
    assert!(dedup.is_duplicate(b"packet one"));
    assert!(!dedup.is_duplicate(b"packet two"));
    for i in 0..MULTI_IF_DEQUE_LEN + 10 {
        dedup.is_duplicate(format!("packet_{i}").as_bytes());
    }
    assert!(dedup.deque.len() <= MULTI_IF_DEQUE_LEN);
}

mod peer_children {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    struct Rig {
        shared: Arc<Shared>,
        transport_rx: mpsc::Receiver<TransportMessage>,
        handle_rx: mpsc::Receiver<InterfaceHandle>,
    }

    async fn rig(data_port: u16) -> Rig {
        let (transport_tx, transport_rx) = mpsc::channel(64);
        let (handle_tx, handle_rx) = mpsc::channel(8);
        let config = AutoInterfaceConfig {
            name: "unit".into(),
            data_port,
            ..AutoInterfaceConfig::default()
        };
        let outbound = bind_udp(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0), false).unwrap();
        let shared = Arc::new(Shared::new(
            config,
            40,
            Arc::new(AtomicU64::new(100)),
            transport_tx,
            handle_tx,
            Arc::new(AtomicBool::new(true)),
            outbound,
        ));
        shared.parent.owner().mark_registered();
        shared.online.store(true, Ordering::SeqCst);
        shared.final_init_done.store(true, Ordering::SeqCst);
        Rig {
            shared,
            transport_rx,
            handle_rx,
        }
    }

    async fn next_child(rig: &mut Rig) -> InterfaceHandle {
        let child = timeout(Duration::from_secs(2), rig.handle_rx.recv())
            .await
            .expect("child handed off")
            .unwrap();
        child.owner.mark_registered();
        child
    }

    async fn next_inbound(rig: &mut Rig) -> Option<(InterfaceId, Bytes)> {
        match timeout(Duration::from_millis(300), rig.transport_rx.recv()).await {
            Ok(Some(TransportMessage::InterfaceEvent { message, .. })) => match *message {
                TransportMessage::Inbound(p) => Some((p.interface_id, p.raw)),
                _ => None,
            },
            _ => None,
        }
    }

    #[tokio::test]
    async fn each_peer_becomes_its_own_child_interface() {
        let mut rig = rig(DATA_PORT).await;
        let a: Ipv6Addr = "fe80::dead:beef:cafe:1234".parse().unwrap();
        let b: Ipv6Addr = "fe80::dead:beef:cafe:5678".parse().unwrap();
        rig.shared.add_peer(a, "eth0", 2).await;
        rig.shared.add_peer(b, "eth0", 2).await;
        rig.shared.add_peer(a, "eth0", 2).await;
        let ca = next_child(&mut rig).await;
        let cb = next_child(&mut rig).await;
        assert!(
            rig.handle_rx.try_recv().is_err(),
            "a refresh spawns no child"
        );
        assert_eq!(ca.parent_id, Some(40));
        assert_eq!(ca.name, "AutoInterfacePeer[eth0/fe80::dead:beef:cafe:1234]");
        assert_eq!(cb.name, "AutoInterfacePeer[eth0/fe80::dead:beef:cafe:5678]");
        assert_ne!(ca.id, cb.id);
        assert_eq!(ca.mtu, HW_MTU);
    }

    #[tokio::test]
    async fn data_is_delivered_on_the_senders_child_only() {
        let mut rig = rig(DATA_PORT).await;
        let peer = Ipv6Addr::LOCALHOST;
        rig.shared.add_peer(peer, "lo", 0).await;
        let child = next_child(&mut rig).await;

        rig.shared
            .on_data(b"from a stranger", "fe80::9".parse().unwrap());
        assert!(next_inbound(&mut rig).await.is_none());

        rig.shared.on_data(b"from the peer", peer);
        let (id, raw) = next_inbound(&mut rig).await.expect("delivered");
        assert_eq!(id, child.id);
        assert_eq!(&raw[..], b"from the peer");

        rig.shared.on_data(b"from the peer", peer);
        assert!(
            next_inbound(&mut rig).await.is_none(),
            "multi-NIC duplicate"
        );
    }

    #[tokio::test]
    async fn nothing_is_delivered_before_final_init_or_after_detach() {
        let mut rig = rig(DATA_PORT).await;
        rig.shared.add_peer(Ipv6Addr::LOCALHOST, "lo", 0).await;
        let _child = next_child(&mut rig).await;
        rig.shared.final_init_done.store(false, Ordering::SeqCst);
        rig.shared.on_data(b"early", Ipv6Addr::LOCALHOST);
        assert!(next_inbound(&mut rig).await.is_none());
        rig.shared.final_init_done.store(true, Ordering::SeqCst);
        rig.shared.online.store(false, Ordering::SeqCst);
        rig.shared.on_data(b"late", Ipv6Addr::LOCALHOST);
        assert!(next_inbound(&mut rig).await.is_none());
    }

    #[tokio::test]
    async fn discovery_is_ignored_until_final_init() {
        let mut rig = rig(DATA_PORT).await;
        let peer: Ipv6Addr = "fe80::77".parse().unwrap();
        let token = discovery_token(&rig.shared.group_id, &peer);
        rig.shared.final_init_done.store(false, Ordering::SeqCst);
        rig.shared.on_discovery(&token, peer, "eth0", 2).await;
        assert!(rig.handle_rx.try_recv().is_err());
        rig.shared.final_init_done.store(true, Ordering::SeqCst);
        rig.shared.on_discovery(&token[..31], peer, "eth0", 2).await;
        assert!(rig.handle_rx.try_recv().is_err());
        rig.shared.on_discovery(&token, peer, "eth0", 2).await;
        next_child(&mut rig).await;
    }

    #[tokio::test]
    async fn a_child_sends_only_to_its_own_peer() {
        let listener = UdpSocket::bind("[::1]:0").await.unwrap();
        let mut rig = rig(listener.local_addr().unwrap().port()).await;
        rig.shared.add_peer(Ipv6Addr::LOCALHOST, "lo", 0).await;
        rig.shared
            .add_peer("fe80::dead:1".parse().unwrap(), "eth0", 2)
            .await;
        let to_loopback = next_child(&mut rig).await;
        let other = next_child(&mut rig).await;
        to_loopback
            .tx
            .send(Bytes::from_static(b"unicast"))
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = timeout(Duration::from_secs(2), listener.recv_from(&mut buf))
            .await
            .expect("datagram from the child")
            .unwrap();
        assert_eq!(&buf[..n], b"unicast");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(to_loopback.txb.as_ref().unwrap().load(Ordering::SeqCst), 7);
        assert_eq!(other.txb.as_ref().unwrap().load(Ordering::SeqCst), 0);
        assert_eq!(rig.shared.txb.load(Ordering::SeqCst), 7);
    }

    #[tokio::test]
    async fn expired_peer_deregisters_its_child() {
        let mut rig = rig(DATA_PORT).await;
        rig.shared.add_peer(Ipv6Addr::LOCALHOST, "lo", 0).await;
        let child = next_child(&mut rig).await;
        let later = Instant::now() + Duration::from_secs_f64(PEERING_TIMEOUT + 1.0);
        rig.shared.expire_peers(later);
        assert!(!child.online.load(Ordering::SeqCst));
        drop(child.tx);
        let mut deregistered = false;
        while let Ok(Some(m)) = timeout(Duration::from_secs(1), rig.transport_rx.recv()).await {
            if let TransportMessage::InterfaceEvent { message, .. } = m
                && matches!(*message, TransportMessage::DeregisterInterface { .. })
            {
                deregistered = true;
                break;
            }
        }
        assert!(deregistered);
        rig.shared.on_data(b"after expiry", Ipv6Addr::LOCALHOST);
        assert!(next_inbound(&mut rig).await.is_none());
    }

    #[tokio::test]
    async fn detaching_the_parent_takes_children_offline() {
        let mut rig = rig(DATA_PORT).await;
        rig.shared.add_peer(Ipv6Addr::LOCALHOST, "lo", 0).await;
        let child = next_child(&mut rig).await;
        drop(Teardown {
            shared: rig.shared.clone(),
            jobs: None,
        });
        assert!(!rig.shared.online.load(Ordering::SeqCst));
        assert!(!child.online.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn spawn_waits_out_the_peering_wait_before_going_online() {
        let (transport_tx, _rx) = mpsc::channel(8);
        let base = free_ports(3);
        let config = AutoInterfaceConfig {
            discovery_port: base,
            data_port: base + 2,
            ..AutoInterfaceConfig::default()
        };
        let started = Instant::now();
        let handle = spawn_auto_interface(
            config,
            1,
            Arc::new(AtomicU64::new(10)),
            transport_tx,
            mpsc::channel(1).0,
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .unwrap();
        assert!(started.elapsed().as_secs_f64() >= PEERING_WAIT);
        assert!(handle.online.load(Ordering::SeqCst));
        handle.online.store(false, Ordering::SeqCst);
        handle.read_task.abort();
    }
}

mod loopback_nic {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    fn exclusive_bind_ok(port: u16) -> bool {
        std::net::UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)).is_ok()
    }

    fn lo_index() -> Option<u32> {
        let index = netif::scope_id_of("lo");
        (index != 0).then_some(index)
    }

    async fn rig(
        base: u16,
    ) -> Option<(
        Arc<Shared>,
        mpsc::Receiver<TransportMessage>,
        mpsc::Receiver<InterfaceHandle>,
        NicAddrs,
    )> {
        let scope_id = lo_index()?;
        let (transport_tx, transport_rx) = mpsc::channel(64);
        let (handle_tx, handle_rx) = mpsc::channel(8);
        let config = AutoInterfaceConfig {
            name: "lo-unit".into(),
            group_id: format!("lo-unit-{base}-{}", std::process::id()),
            discovery_port: base,
            data_port: base + 2,
            ..AutoInterfaceConfig::default()
        };
        let outbound = bind_udp(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0), false).ok()?;
        let shared = Arc::new(Shared::new(
            config,
            50,
            Arc::new(AtomicU64::new(500)),
            transport_tx,
            handle_tx,
            Arc::new(AtomicBool::new(true)),
            outbound,
        ));
        shared.parent.owner().mark_registered();
        let nic = NicAddrs {
            ifname: "lo".into(),
            link_local: Ipv6Addr::LOCALHOST,
            all: vec![Ipv6Addr::LOCALHOST],
            scope_id,
        };
        Some((shared, transport_rx, handle_rx, nic))
    }

    #[tokio::test]
    async fn detach_releases_every_nic_socket() {
        let base = free_ports(3);
        let Some((shared, _trx, _hrx, nic)) = rig(base).await else {
            eprintln!("skipped: no loopback interface index");
            return;
        };
        if !shared.adopt_nic(&nic).unwrap_or(false) {
            eprintln!("skipped: loopback multicast unavailable");
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !exclusive_bind_ok(base + 2),
            "data socket held while running"
        );
        drop(Teardown {
            shared: shared.clone(),
            jobs: None,
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        for port in [base, base + 1, base + 2] {
            assert!(
                exclusive_bind_ok(port),
                "port {port} still held after detach"
            );
        }
    }

    #[tokio::test]
    async fn own_address_is_an_echo_and_stranger_data_is_dropped() {
        let base = free_ports(3);
        let Some((shared, mut trx, mut hrx, nic)) = rig(base).await else {
            return;
        };
        if !shared.adopt_nic(&nic).unwrap_or(false) {
            return;
        }
        shared.online.store(true, Ordering::SeqCst);
        shared.final_init_done.store(true, Ordering::SeqCst);
        let peer = UdpSocket::bind("[::1]:0").await.unwrap();
        let data_dest = SocketAddrV6::new(Ipv6Addr::LOCALHOST, base + 2, 0, 0);

        // A stranger's data is dropped.
        peer.send_to(b"before peering", data_dest).await.unwrap();
        assert!(
            timeout(Duration::from_millis(300), trx.recv())
                .await
                .is_err()
        );

        shared
            .add_peer(Ipv6Addr::LOCALHOST, "lo", nic.scope_id)
            .await;
        assert!(
            hrx.try_recv().is_err(),
            "own address must not become a peer"
        );
        assert!(shared.core().echo_received("lo"));
    }
}
