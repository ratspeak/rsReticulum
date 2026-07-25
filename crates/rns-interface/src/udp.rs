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

/// Spawn a UDP interface — datagrams are unframed (1 send/recv = 1 packet).
pub async fn spawn_udp_interface(
    config: UdpInterfaceConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    // Python UDPInterface `device =`: fill unset listen/forward IPs with the
    // NIC's IPv4 broadcast address; a device that can't be resolved is a
    // config error, not a silent fallback to wildcard.
    let mut listen_ip_cfg = config.listen_ip.clone();
    let mut forward_ip_cfg = config.forward_ip.clone();
    if let Some(device) = config.device.as_deref() {
        if listen_ip_cfg.is_none() || forward_ip_cfg.is_none() {
            let bcast = crate::socket_tuning::iface_broadcast_for(device).ok_or_else(|| {
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
    }

    let listen_ip = listen_ip_cfg.as_deref().unwrap_or("0.0.0.0");
    let listen_port = config.listen_port.unwrap_or(0);
    let bind_addr = format!("{}:{}", listen_ip, listen_port);
    let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);
    // Needed for directed broadcasts (255.255.255.255).
    socket.set_broadcast(true)?;
    let local_addr = socket.local_addr()?;
    tracing::info!(name = %config.name, addr = %local_addr, "UDP interface bound");

    let online = Arc::new(AtomicBool::new(true));
    let online2 = online.clone();
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);
    let name = config.name.clone();
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

    let socket_w = socket.clone();
    tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if let Some(addr) = forward_addr {
                let len = data.len();
                if let Err(e) = socket_w.send_to(&data, addr).await {
                    tracing::warn!(error = %e, "UDP send_to failed");
                } else {
                    task_txb.fetch_add(len as u64, Ordering::Relaxed);
                }
            } else {
                tracing::debug!("UDP write: no forward address configured, dropping packet");
            }
        }
    });

    let read_task = tokio::spawn(async move {
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
                Err(e) => {
                    tracing::warn!(error = %e, "UDP recv_from error");
                    break;
                }
            }
        }
        online2.store(false, Ordering::SeqCst);
    });

    Ok(InterfaceHandle {
        id,
        parent_id: None,
        name,
        mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: true,
            forward: false,
            repeat: false,
        },
        bitrate: 10_000_000,
        mtu: HW_MTU,
        online,
        rxb: Some(shared_rxb),
        txb: Some(shared_txb),
        inspection: None,
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
        let handle_b = spawn_udp_interface(cfg_b, 20, transport_tx.clone())
            .await
            .unwrap();

        // A → B's listen port; inbound carries B's interface_id (20).
        let payload = Bytes::from_static(b"udp test data");
        handle_a.tx.send(payload.clone()).await.unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        match msg {
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

        match msg2 {
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
