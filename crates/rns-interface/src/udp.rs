use rns_transport::messages::{InterfacePacketCapacity, InterfaceTransportSender};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::traits::{InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

pub const HW_MTU: u32 = 1064;

#[derive(Debug, Clone)]
pub struct UdpInterfaceConfig {
    pub name: String,
    pub listen_ip: Option<String>,
    pub listen_port: Option<u16>,
    pub forward_ip: Option<String>,
    pub forward_port: Option<u16>,
    pub device: Option<String>,
    pub mode: InterfaceMode,
}

impl UdpInterfaceConfig {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            listen_ip: None,
            listen_port: None,
            forward_ip: None,
            forward_port: None,
            device: None,
            mode: InterfaceMode::Full,
        }
    }

    pub fn listen(mut self, ip: &str, port: u16) -> Self {
        self.listen_ip = Some(ip.to_string());
        self.listen_port = Some(port);
        self
    }

    pub fn forward(mut self, ip: &str, port: u16) -> Self {
        self.forward_ip = Some(ip.to_string());
        self.forward_port = Some(port);
        self
    }
}

/// Python `get_broadcast_for_if`: the network broadcast of the device's first
/// IPv4 address, computed from its prefix (UDPInterface.py, netinfo.py).
fn broadcast_for_device(device: &str) -> Option<std::net::Ipv4Addr> {
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) if i.name == device => {
                Some((u32::from(v4.ip) | !u32::from(v4.netmask)).into())
            }
            _ => None,
        })
}

/// Spawn a UDP interface — datagrams are unframed (1 send/recv = 1 packet).
pub async fn spawn_udp_interface(
    config: UdpInterfaceConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    // Python UDPInterface `device =`: fill unset listen/forward IPs with the
    // NIC's IPv4 broadcast address; a device that can't be resolved is a
    // config error, not a silent fallback to wildcard.
    let mut listen_ip_cfg = config.listen_ip.clone();
    let mut forward_ip_cfg = config.forward_ip.clone();
    if let Some(device) = config.device.as_deref()
        && (listen_ip_cfg.is_none() || forward_ip_cfg.is_none())
    {
        let bcast = broadcast_for_device(device).ok_or_else(|| {
            crate::traits::InterfaceError::SendFailed(format!(
                "UDP device '{device}' not found or has no IPv4 broadcast address"
            ))
        })?;
        if listen_ip_cfg.is_none() {
            listen_ip_cfg = Some(bcast.to_string());
        }
        if forward_ip_cfg.is_none() {
            forward_ip_cfg = Some(bcast.to_string());
        }
    }

    // Python listens only when both the address and the port are known, and
    // otherwise stays offline, so transport never sends on it (UDPInterface.py).
    let socket = match (listen_ip_cfg.as_deref(), config.listen_port) {
        (Some(ip), Some(port)) => {
            let socket = UdpSocket::bind((ip, port)).await?;
            tracing::info!(name = %config.name, addr = %socket.local_addr()?, "UDP interface bound");
            Some(socket)
        }
        _ => None,
    };
    let listening = socket.is_some();

    let online = Arc::new(AtomicBool::new(listening));
    let online2 = online.clone();
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);
    let name = config.name.clone();
    // UDPInterface.py renders the bind address as configured.
    let shown_port = match &socket {
        Some(socket) => socket.local_addr()?.port(),
        None => config.listen_port.unwrap_or(0),
    };
    let python_identity = rns_transport::messages::InterfaceIdentity::new(
        format!(
            "UDPInterface[{}/{}:{}]",
            name,
            listen_ip_cfg.as_deref().unwrap_or(""),
            shown_port
        ),
        &name,
        "UDPInterface",
    );
    let mode = config.mode;
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let task_rxb = shared_rxb.clone();
    let task_txb = shared_txb.clone();

    let forward_addr: Option<SocketAddr> = match (&forward_ip_cfg, config.forward_port) {
        (Some(ip), Some(port)) => {
            let addr_str = format!("{}:{}", ip, port);
            match addr_str.parse() {
                Ok(a) => Some(a),
                Err(e) => {
                    tracing::warn!(error = %e, "invalid forward address, trying DNS");
                    tokio::net::lookup_host(&addr_str)
                        .await
                        .ok()
                        .and_then(|mut addrs| addrs.next())
                }
            }
        }
        _ => None,
    };

    // Sends use their own broadcast socket, as Python's per-send socket does,
    // so send errors never reach the listener (UDPInterface.py).
    // Transport skips an offline interface (Transport.py), so a
    // forward-only interface never transmits either.
    let send_socket = match forward_addr {
        Some(_) if listening => {
            let send_socket = UdpSocket::bind("0.0.0.0:0").await?;
            send_socket.set_broadcast(true)?;
            Some(send_socket)
        }
        _ => None,
    };
    let send_name = config.name.clone();
    tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if let (Some(socket), Some(addr)) = (&send_socket, forward_addr) {
                let len = data.len();
                if let Err(e) = socket.send_to(&data, addr).await {
                    tracing::error!(
                        "Could not transmit on UDPInterface[{send_name}]. The contained exception was: {e}"
                    );
                } else {
                    task_txb.fetch_add(len as u64, Ordering::Relaxed);
                }
            } else {
                tracing::debug!("UDP write: no forward address configured, dropping packet");
            }
        }
    });

    let read_task = tokio::spawn(async move {
        let Some(socket) = socket else {
            return;
        };
        let mut buf = [0u8; 2048];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    if n == 0 {
                        continue;
                    }
                    task_rxb.fetch_add(n as u64, Ordering::Relaxed);
                    let raw = Bytes::copy_from_slice(&buf[..n]);
                    tracing::debug!(
                        interface_id = id,
                        from = %src,
                        len = n,
                        "UDP read: received packet"
                    );
                    let msg = TransportMessage::Inbound(InboundPacket {
                        raw,
                        interface_id: id,
                        rssi: None,
                        snr: None,
                        q: None,
                    });
                    if transport_tx.send(msg).await.is_err() {
                        tracing::warn!(id, "transport channel closed");
                        break;
                    }
                }
                // Python's serve_forever survives a failed recvfrom.
                Err(e) => {
                    tracing::warn!(error = %e, "UDP recv_from error");
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
        online2.store(false, Ordering::SeqCst);
    });

    Ok(InterfaceHandle {
        id,
        owner,
        packet_capacity: InterfacePacketCapacity::new(500, 1064, false),
        parent_id: None,
        name,
        mode,
        direction: InterfaceDirection {
            inbound: listening,
            outbound: true,
            forward: false,
            repeat: false,
        },
        bitrate: 10_000_000,
        mtu: HW_MTU,
        online,
        rxb: Some(shared_rxb),
        txb: Some(shared_txb),
        inspection: Some(
            rns_transport::messages::InterfaceInspectionSource::identified(python_identity),
        ),
        tx,
        read_task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_config() {
        let config = UdpInterfaceConfig::new("udp0")
            .listen("0.0.0.0", 4242)
            .forward("192.168.1.1", 4243);

        assert_eq!(config.listen_ip.as_deref(), Some("0.0.0.0"));
        assert_eq!(config.listen_port, Some(4242));
        assert_eq!(config.forward_ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(config.forward_port, Some(4243));
    }

    #[test]
    fn test_hw_mtu() {
        assert_eq!(HW_MTU, 1064);
    }

    /// T1-11: `device =` was parsed then silently ignored. A device that
    /// cannot be resolved must now fail the spawn with a clear error.
    #[tokio::test]
    async fn test_udp_device_unresolvable_errors() {
        let (transport_tx, _rx) = mpsc::channel::<TransportMessage>(8);
        let mut cfg = UdpInterfaceConfig::new("udp-dev");
        cfg.device = Some("definitely-not-a-real-interface-zzz".to_string());
        let err = match spawn_udp_interface(cfg, 1, transport_tx).await {
            Err(e) => e,
            Ok(_) => panic!("unresolvable device must error"),
        };
        assert!(
            err.to_string()
                .contains("definitely-not-a-real-interface-zzz")
        );
    }

    /// Explicit listen/forward IPs take precedence — the device is not
    /// resolved at all, so the spawn succeeds regardless of the NIC name.
    #[tokio::test]
    async fn test_udp_device_ignored_when_ips_explicit() {
        let (transport_tx, _rx) = mpsc::channel::<TransportMessage>(8);
        let mut cfg = UdpInterfaceConfig::new("udp-dev-explicit")
            .listen("127.0.0.1", 0)
            .forward("127.0.0.1", 19999);
        cfg.device = Some("definitely-not-a-real-interface-zzz".to_string());
        let handle = spawn_udp_interface(cfg, 2, transport_tx)
            .await
            .expect("explicit IPs bypass device resolution");
        handle.owner.mark_registered();
        handle.read_task.abort();
    }

    #[test]
    fn test_udp_config_defaults() {
        let cfg = UdpInterfaceConfig::new("udp0");
        assert_eq!(cfg.name, "udp0");
        assert!(cfg.listen_ip.is_none());
        assert!(cfg.listen_port.is_none());
        assert!(cfg.forward_ip.is_none());
        assert!(cfg.forward_port.is_none());
        assert_eq!(cfg.mode, InterfaceMode::Full);
    }

    #[test]
    fn test_udp_config_listen_only() {
        let cfg = UdpInterfaceConfig::new("udp-rx").listen("0.0.0.0", 5555);
        assert_eq!(cfg.listen_ip.as_deref(), Some("0.0.0.0"));
        assert_eq!(cfg.listen_port, Some(5555));
        assert!(cfg.forward_ip.is_none());
        assert!(cfg.forward_port.is_none());
    }

    #[test]
    fn test_udp_config_builder_chain() {
        let cfg = UdpInterfaceConfig::new("udp-bidir")
            .listen("0.0.0.0", 4242)
            .forward("10.0.0.1", 6666);
        assert_eq!(cfg.listen_ip.as_deref(), Some("0.0.0.0"));
        assert_eq!(cfg.listen_port, Some(4242));
        assert_eq!(cfg.forward_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(cfg.forward_port, Some(6666));
    }

    #[tokio::test]
    async fn test_udp_loopback() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(64);

        let cfg_a = UdpInterfaceConfig::new("udp-a").listen("127.0.0.1", 0);
        let handle_a = spawn_udp_interface(cfg_a, 10, transport_tx.clone())
            .await
            .unwrap();
        handle_a.owner.mark_registered();

        // Reserve two free ports via bind-drop; handle doesn't expose its addr.
        let sock_tmp1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port_a = sock_tmp1.local_addr().unwrap().port();
        let sock_tmp2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port_b = sock_tmp2.local_addr().unwrap().port();
        drop(sock_tmp1);
        drop(sock_tmp2);
        handle_a.read_task.abort();

        let cfg_a = UdpInterfaceConfig::new("udp-a")
            .listen("127.0.0.1", port_a)
            .forward("127.0.0.1", port_b);
        let cfg_b = UdpInterfaceConfig::new("udp-b")
            .listen("127.0.0.1", port_b)
            .forward("127.0.0.1", port_a);

        let handle_a = spawn_udp_interface(cfg_a, 10, transport_tx.clone())
            .await
            .unwrap();
        handle_a.owner.mark_registered();
        let handle_b = spawn_udp_interface(cfg_b, 20, transport_tx.clone())
            .await
            .unwrap();
        handle_b.owner.mark_registered();

        // A → B's listen port; inbound carries B's interface_id (20).
        let payload = Bytes::from_static(b"udp test data");
        handle_a.tx.send(payload.clone()).await.unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        match crate::traits::test_event_for_handle(msg, &handle_b) {
            TransportMessage::Inbound(pkt) => {
                assert_eq!(pkt.raw, payload);
                assert_eq!(pkt.interface_id, 20);
            }
            other => panic!("unexpected: {:?}", other),
        }

        let reply = Bytes::from_static(b"udp reply");
        handle_b.tx.send(reply.clone()).await.unwrap();

        let msg2 = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        match crate::traits::test_event_for_handle(msg2, &handle_a) {
            TransportMessage::Inbound(pkt) => {
                assert_eq!(pkt.raw, reply);
                assert_eq!(pkt.interface_id, 10);
            }
            other => panic!("unexpected: {:?}", other),
        }

        handle_a.read_task.abort();
        handle_b.read_task.abort();
    }
}
