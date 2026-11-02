//! Destination events and Link request records used between transport and
//! destination owners. Data records alone perform no networking; the dispatch
//! helper reports local request admission, separately from Link establishment.

use bytes::Bytes;
use tokio::sync::oneshot;

use crate::messages::InterfaceId;

/// Optional interface-supplied measurements for one received packet. This
/// record performs no normalization, range validation or freshness check.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PacketMetrics {
    pub rssi: Option<f32>,
    pub snr: Option<f32>,
    /// Interface-defined quality value; do not assume a normalized 0–1 range.
    pub q: Option<f32>,
}

/// Metadata for asking a destination owner to construct an announce.
#[derive(Debug, Clone)]
pub struct AnnounceRequest {
    pub app_name: String,
    pub path_response: bool,
    pub tag: Option<Vec<u8>>,
    pub attached_interface: Option<InterfaceId>,
}

impl AnnounceRequest {
    /// Request an ordinary announce with no path-response flag, tag or attached interface.
    pub fn normal(app_name: String) -> Self {
        Self {
            app_name,
            path_response: false,
            tag: None,
            attached_interface: None,
        }
    }
}

/// Messages delivered to a registered destination owner. Packet bytes and
/// events still require the destination/Link handler's protocol processing;
/// constructing an event does not validate its contents.
#[derive(Debug)]
pub enum DestinationEvent {
    InboundPacket {
        interface_owner: Option<crate::InterfaceOwnerId>,
        raw: Bytes,
        interface_id: InterfaceId,
        metrics: PacketMetrics,
    },
    LinkRequest {
        interface_owner: Option<crate::InterfaceOwnerId>,
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
    /// Ask the owner to construct an announce, including ordinary announcements
    /// or path responses. This is a request, not proof of publication.
    AnnounceRequested(AnnounceRequest),
}

/// Request record carrying a destination and a caller-owned establishment
/// reply channel. Constructing it does not send a request; the consuming
/// runtime must perform establishment and report the Link ID or an error.
#[derive(Debug)]
pub struct EstablishLinkRequest {
    pub dest_hash: [u8; 16],
    pub result_tx: oneshot::Sender<Result<[u8; 16], String>>,
}

/// Plain data record for a Link owner to process. It performs no encryption,
/// framing or transmission by itself.
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
            interface_owner: None,
            raw: Bytes::from_static(&[1, 2, 3]),
            interface_id: 42,
            metrics: PacketMetrics::default(),
        };
        assert!(matches!(evt1, DestinationEvent::InboundPacket { .. }));

        let evt2 = DestinationEvent::LinkRequest {
            interface_owner: None,
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

/// Failure to submit or locally admit one Link request. A successful dispatch
/// means local egress acceptance, not successful Link establishment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkRequestDispatchError {
    #[error(transparent)]
    Capacity(#[from] crate::InterfaceCapacityError),
    #[error("invalid local Link request or unsupported endpoint signalling")]
    InvalidRequest,
    #[error("no eligible interface accepted the Link request")]
    NoInterface,
    #[error("transport is unavailable")]
    TransportUnavailable,
}

/// Submit one Link request and await its exact attempt's local admission result.
/// The actor checks the request header and supported endpoint signalling before
/// egress. Success does not wait for a remote proof or Link establishment.
///
/// This future has no internal timeout; use the caller's establishment deadline
/// around both submission and reply. Dropping it closes the reply receiver; the
/// actor checks that before starting dispatch, but cannot recall bytes already
/// admitted. The owned request is not returned on failure.
pub async fn dispatch_link_request(
    transport: &tokio::sync::mpsc::Sender<crate::messages::TransportMessage>,
    request: crate::messages::OutboundRequest,
) -> Result<(), LinkRequestDispatchError> {
    let (result_tx, result_rx) = oneshot::channel();
    transport
        .send(crate::messages::TransportMessage::SendLinkRequest { request, result_tx })
        .await
        .map_err(|_| LinkRequestDispatchError::TransportUnavailable)?;
    result_rx
        .await
        .map_err(|_| LinkRequestDispatchError::TransportUnavailable)?
}
