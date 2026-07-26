//! Link-layer message types routed between the transport actor and the
//! destinations that own registered identities. Kept in their own module so
//! the main `messages.rs` actor enum stays focused on transport primitives.

use bytes::Bytes;
use tokio::sync::oneshot;

use crate::messages::InterfaceId;

/// Physical-layer measurements attached to one received packet.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PacketMetrics {
    pub rssi: Option<f32>,
    pub snr: Option<f32>,
    pub q: Option<f32>,
}

#[derive(Debug, Clone)]
pub struct AnnounceRequest {
    pub app_name: String,
    pub path_response: bool,
    pub tag: Option<Vec<u8>>,
    pub attached_interface: Option<InterfaceId>,
}

impl AnnounceRequest {
    pub fn normal(app_name: String) -> Self {
        Self {
            app_name,
            path_response: false,
            tag: None,
            attached_interface: None,
        }
    }
}

/// Events the transport actor pushes out to a registered destination.
#[derive(Debug)]
pub enum DestinationEvent {
    InboundPacket {
        raw: Bytes,
        interface_id: InterfaceId,
        metrics: PacketMetrics,
    },
    LinkRequest {
        raw: Bytes,
        interface_id: InterfaceId,
        metrics: PacketMetrics,
    },
    LinkEstablished {
        link_id: [u8; 16],
    },
    LinkClosed {
        link_id: [u8; 16],
    },
    DeliveryProof {
        msg_id: String,
        rtt: Option<std::time::Duration>,
    },
    /// Transport asks the destination to announce itself — used when a shared
    /// instance connects and needs the peer's current identity map.
    AnnounceRequested(AnnounceRequest),
}

/// Request a new link to `dest_hash`. `result_tx` delivers either the link
/// id or a diagnostic message explaining why establishment failed.
#[derive(Debug)]
pub struct EstablishLinkRequest {
    pub dest_hash: [u8; 16],
    pub result_tx: oneshot::Sender<Result<[u8; 16], String>>,
}

#[derive(Debug)]
pub struct LinkDataRequest {
    pub link_id: [u8; 16],
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_destination_event_variants() {
        let evt1 = DestinationEvent::InboundPacket {
            raw: Bytes::from_static(&[1, 2, 3]),
            interface_id: 42,
            metrics: PacketMetrics::default(),
        };
        assert!(matches!(evt1, DestinationEvent::InboundPacket { .. }));

        let evt2 = DestinationEvent::LinkRequest {
            raw: Bytes::from_static(&[4, 5, 6]),
            interface_id: 99,
            metrics: PacketMetrics::default(),
        };
        assert!(matches!(evt2, DestinationEvent::LinkRequest { .. }));

        let evt3 = DestinationEvent::LinkEstablished {
            link_id: [0xAA; 16],
        };
        assert!(matches!(evt3, DestinationEvent::LinkEstablished { .. }));

        let evt4 = DestinationEvent::LinkClosed {
            link_id: [0xBB; 16],
        };
        assert!(matches!(evt4, DestinationEvent::LinkClosed { .. }));
    }

    #[test]
    fn test_establish_link_request() {
        let (tx, rx) = oneshot::channel();
        let req = EstablishLinkRequest {
            dest_hash: [0xCC; 16],
            result_tx: tx,
        };
        assert_eq!(req.dest_hash, [0xCC; 16]);

        drop(req.result_tx);
        assert!(rx.blocking_recv().is_err());
    }

    #[test]
    fn test_establish_link_request_success() {
        let (tx, rx) = oneshot::channel();
        let req = EstablishLinkRequest {
            dest_hash: [0xDD; 16],
            result_tx: tx,
        };
        let link_id = [0xEE; 16];
        req.result_tx.send(Ok(link_id)).unwrap();
        let result = rx.blocking_recv().unwrap();
        assert_eq!(result.unwrap(), link_id);
    }

    #[test]
    fn test_establish_link_request_failure() {
        let (tx, rx) = oneshot::channel();
        let req = EstablishLinkRequest {
            dest_hash: [0xFF; 16],
            result_tx: tx,
        };
        req.result_tx.send(Err("no path".to_string())).unwrap();
        let result = rx.blocking_recv().unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "no path");
    }

    #[test]
    fn test_link_data_request() {
        let req = LinkDataRequest {
            link_id: [0xAA; 16],
            data: vec![10, 20, 30, 40, 50],
        };
        assert_eq!(req.link_id, [0xAA; 16]);
        assert_eq!(req.data.len(), 5);
    }
}
