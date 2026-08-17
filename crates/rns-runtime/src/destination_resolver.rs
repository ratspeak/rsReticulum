//! Deadline-aware, handler-free destination identity resolution.
//!
//! Python applications resolve finite destinations through validated identity
//! recall and path requests. They do not install temporary announce handlers.

use std::time::Duration;

use rns_transport::messages::{
    RecalledDestinationRpcEntry, TransportMessage, TransportQuery, TransportQueryResponse,
};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep_until, timeout_at};

const RECALL_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationResolveOptions {
    /// Complete command admission, path request and recall before this budget.
    pub timeout: Duration,
    /// Remove an existing route before requesting a fresh path response when
    /// the validated identity is not already cached.
    pub drop_existing_path: bool,
    /// Request a path refresh even when validated identity data is cached.
    /// The cached identity remains immediately usable, matching upstream
    /// applications that refresh routing separately from identity recall.
    pub refresh_cached_path: bool,
}

impl DestinationResolveOptions {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            drop_existing_path: false,
            refresh_cached_path: false,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DestinationResolveError {
    #[error("destination resolution timed out")]
    Timeout,
    #[error("Reticulum transport is unavailable")]
    TransportUnavailable,
    #[error("Reticulum transport returned an unexpected response during {0}")]
    UnexpectedResponse(&'static str),
}

/// Resolve one validated destination without installing an announce handler.
///
/// A missing identity always emits an explicit path request. This deliberately
/// covers the state where a route exists but its validated announce metadata
/// is absent: `AwaitPath` alone would return immediately and never repair the
/// identity cache.
pub async fn resolve_destination_on_transport(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
    options: DestinationResolveOptions,
) -> Result<RecalledDestinationRpcEntry, DestinationResolveError> {
    let deadline = Instant::now()
        .checked_add(options.timeout)
        .ok_or(DestinationResolveError::Timeout)?;

    if let Some(recalled) = recall_destination(transport_tx, destination_hash, deadline).await? {
        if options.refresh_cached_path {
            send_before_deadline(
                transport_tx,
                TransportMessage::RequestPath { destination_hash },
                deadline,
            )
            .await?;
        }
        return Ok(recalled);
    }

    if options.drop_existing_path {
        match query_before_deadline(
            transport_tx,
            TransportQuery::DropPath {
                dest: destination_hash,
            },
            deadline,
        )
        .await?
        {
            TransportQueryResponse::Ok => {}
            _ => return Err(DestinationResolveError::UnexpectedResponse("path drop")),
        }
    }

    send_before_deadline(
        transport_tx,
        TransportMessage::RequestPath { destination_hash },
        deadline,
    )
    .await?;

    loop {
        if let Some(recalled) = recall_destination(transport_tx, destination_hash, deadline).await?
        {
            return Ok(recalled);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(DestinationResolveError::Timeout);
        }
        sleep_until(std::cmp::min(deadline, now + RECALL_POLL_INTERVAL)).await;
    }
}

async fn recall_destination(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
    deadline: Instant,
) -> Result<Option<RecalledDestinationRpcEntry>, DestinationResolveError> {
    match query_before_deadline(
        transport_tx,
        TransportQuery::RecallDestination {
            dest: destination_hash,
        },
        deadline,
    )
    .await?
    {
        TransportQueryResponse::RecalledDestination(Some(recalled))
            if recalled.dest_hash != destination_hash =>
        {
            Err(DestinationResolveError::UnexpectedResponse(
                "destination recall",
            ))
        }
        TransportQueryResponse::RecalledDestination(recalled) => Ok(recalled),
        _ => Err(DestinationResolveError::UnexpectedResponse(
            "destination recall",
        )),
    }
}

async fn query_before_deadline(
    transport_tx: &mpsc::Sender<TransportMessage>,
    query: TransportQuery,
    deadline: Instant,
) -> Result<TransportQueryResponse, DestinationResolveError> {
    let (response_tx, response_rx) = oneshot::channel();
    send_before_deadline(
        transport_tx,
        TransportMessage::Rpc { query, response_tx },
        deadline,
    )
    .await?;
    timeout_at(deadline, response_rx)
        .await
        .map_err(|_| DestinationResolveError::Timeout)?
        .map_err(|_| DestinationResolveError::TransportUnavailable)
}

async fn send_before_deadline(
    transport_tx: &mpsc::Sender<TransportMessage>,
    message: TransportMessage,
    deadline: Instant,
) -> Result<(), DestinationResolveError> {
    timeout_at(deadline, transport_tx.send(message))
        .await
        .map_err(|_| DestinationResolveError::Timeout)?
        .map_err(|_| DestinationResolveError::TransportUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recalled(destination_hash: [u8; 16], public_key: [u8; 64]) -> RecalledDestinationRpcEntry {
        RecalledDestinationRpcEntry {
            dest_hash: destination_hash,
            public_key,
            app_data: None,
            ratchet: None,
            hops: 2,
            timestamp: 1.0,
        }
    }

    #[tokio::test]
    async fn cache_hit_returns_without_network_discovery() {
        let destination_hash = [0x11; 16];
        let public_key = [0x22; 64];
        let (transport_tx, mut transport_rx) = mpsc::channel(4);
        let responder = tokio::spawn(async move {
            let TransportMessage::Rpc { query, response_tx } = transport_rx.recv().await.unwrap()
            else {
                panic!("expected destination recall");
            };
            assert!(
                matches!(query, TransportQuery::RecallDestination { dest } if dest == destination_hash)
            );
            response_tx
                .send(TransportQueryResponse::RecalledDestination(Some(recalled(
                    destination_hash,
                    public_key,
                ))))
                .unwrap();
            assert!(transport_rx.try_recv().is_err());
        });

        let resolved = resolve_destination_on_transport(
            &transport_tx,
            destination_hash,
            DestinationResolveOptions::new(Duration::from_secs(1)),
        )
        .await
        .unwrap();
        assert_eq!(resolved.public_key, public_key);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn missing_identity_requests_path_without_announce_registration() {
        let destination_hash = [0x33; 16];
        let public_key = [0x44; 64];
        let (transport_tx, mut transport_rx) = mpsc::channel(8);
        let responder = tokio::spawn(async move {
            let mut recalls = 0;
            while let Some(message) = transport_rx.recv().await {
                match message {
                    TransportMessage::Rpc { query, response_tx } => {
                        assert!(
                            matches!(query, TransportQuery::RecallDestination { dest } if dest == destination_hash)
                        );
                        recalls += 1;
                        let result = if recalls >= 2 {
                            Some(recalled(destination_hash, public_key))
                        } else {
                            None
                        };
                        response_tx
                            .send(TransportQueryResponse::RecalledDestination(result))
                            .unwrap();
                        if recalls >= 2 {
                            break;
                        }
                    }
                    TransportMessage::RequestPath {
                        destination_hash: dest,
                    } => {
                        assert_eq!(dest, destination_hash);
                    }
                    other => panic!("unexpected finite discovery message: {other:?}"),
                }
            }
        });

        let resolved = resolve_destination_on_transport(
            &transport_tx,
            destination_hash,
            DestinationResolveOptions::new(Duration::from_secs(1)),
        )
        .await
        .unwrap();
        assert_eq!(resolved.public_key, public_key);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn cached_identity_can_refresh_path_without_waiting_for_announce() {
        let destination_hash = [0x45; 16];
        let public_key = [0x46; 64];
        let (transport_tx, mut transport_rx) = mpsc::channel(4);
        let responder = tokio::spawn(async move {
            let TransportMessage::Rpc { query, response_tx } = transport_rx.recv().await.unwrap()
            else {
                panic!("expected destination recall");
            };
            assert!(matches!(query, TransportQuery::RecallDestination { .. }));
            response_tx
                .send(TransportQueryResponse::RecalledDestination(Some(recalled(
                    destination_hash,
                    public_key,
                ))))
                .unwrap();
            assert!(matches!(
                transport_rx.recv().await.unwrap(),
                TransportMessage::RequestPath { destination_hash: dest } if dest == destination_hash
            ));
        });

        let resolved = resolve_destination_on_transport(
            &transport_tx,
            destination_hash,
            DestinationResolveOptions {
                timeout: Duration::from_secs(1),
                drop_existing_path: false,
                refresh_cached_path: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(resolved.public_key, public_key);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn telephony_policy_drops_stale_path_before_request() {
        let destination_hash = [0x55; 16];
        let public_key = [0x66; 64];
        let (transport_tx, mut transport_rx) = mpsc::channel(8);
        let responder = tokio::spawn(async move {
            let TransportMessage::Rpc { query, response_tx } = transport_rx.recv().await.unwrap()
            else {
                panic!("expected initial recall");
            };
            assert!(matches!(query, TransportQuery::RecallDestination { .. }));
            response_tx
                .send(TransportQueryResponse::RecalledDestination(None))
                .unwrap();

            let TransportMessage::Rpc { query, response_tx } = transport_rx.recv().await.unwrap()
            else {
                panic!("expected path drop");
            };
            assert!(matches!(query, TransportQuery::DropPath { dest } if dest == destination_hash));
            response_tx.send(TransportQueryResponse::Ok).unwrap();
            assert!(matches!(
                transport_rx.recv().await.unwrap(),
                TransportMessage::RequestPath { destination_hash: dest } if dest == destination_hash
            ));
            let TransportMessage::Rpc { query, response_tx } = transport_rx.recv().await.unwrap()
            else {
                panic!("expected recall after path request");
            };
            assert!(matches!(query, TransportQuery::RecallDestination { .. }));
            response_tx
                .send(TransportQueryResponse::RecalledDestination(Some(recalled(
                    destination_hash,
                    public_key,
                ))))
                .unwrap();
        });

        let resolved = resolve_destination_on_transport(
            &transport_tx,
            destination_hash,
            DestinationResolveOptions {
                timeout: Duration::from_secs(1),
                drop_existing_path: true,
                refresh_cached_path: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(resolved.public_key, public_key);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn one_deadline_bounds_blocked_command_admission() {
        let destination_hash = [0x77; 16];
        let (transport_tx, _transport_rx) = mpsc::channel(1);
        transport_tx
            .send(TransportMessage::RequestPath { destination_hash })
            .await
            .unwrap();

        let error = resolve_destination_on_transport(
            &transport_tx,
            destination_hash,
            DestinationResolveOptions::new(Duration::from_millis(5)),
        )
        .await
        .unwrap_err();
        assert_eq!(error, DestinationResolveError::Timeout);
    }
}
