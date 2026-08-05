//! Wait for a destination's path to be learned (or time out).
//!
//! Mirrors Python `Transport.await_path(destination_hash, timeout=None)`
//! (RNS/Transport.py:2524). The helper sends an [`AwaitPath`] actor
//! message and applies one caller-supplied deadline to both actor submission
//! and the oneshot reply. The actor emits the upstream-compatible path request
//! before parking the waiter.
//!
//! [`AwaitPath`]: crate::messages::TransportMessage::AwaitPath

use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use crate::messages::TransportMessage;

/// Error returned by [`await_path`] when the path cannot be resolved.
#[derive(Debug, Error, PartialEq)]
pub enum AwaitPathError {
    /// The transport actor's receive channel closed before we could
    /// submit the request — the actor has shut down.
    #[error("transport actor is not running")]
    TransportDown,
    /// The caller's timeout fired before the actor answered, or the
    /// actor's internal 15s sweep expired the waiter first (returns
    /// `Ok(false)` on the reply channel).
    #[error("timed out waiting for path")]
    Timeout,
}

/// Wait up to `timeout` for the transport actor to resolve (or already
/// know) a path to `destination_hash`.
///
/// Returns `Ok(())` as soon as the actor confirms the path exists. A
/// dropped reply sender without a preceding `true` is indistinguishable
/// from a timeout, so both surface as `Err(Timeout)`.
pub async fn await_path(
    tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
    timeout: Duration,
) -> Result<(), AwaitPathError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    let operation = async {
        tx.send(TransportMessage::AwaitPath {
            dest: destination_hash,
            reply: reply_tx,
        })
        .await
        .map_err(|_| AwaitPathError::TransportDown)?;

        match reply_rx.await {
            Ok(true) => Ok(()),
            // Actor responded `false` → its own internal timer expired.
            Ok(false) => Err(AwaitPathError::Timeout),
            // Actor dropped the reply sender without replying — treat as timeout.
            Err(_) => Err(AwaitPathError::Timeout),
        }
    };

    match tokio::time::timeout(timeout, operation).await {
        Ok(result) => result,
        // The deadline covers both actor-channel admission and the reply.
        Err(_) => Err(AwaitPathError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn resolves_when_actor_replies_true() {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(4);
        tokio::spawn(async move {
            match rx.recv().await {
                Some(TransportMessage::AwaitPath { dest: _, reply }) => {
                    let _ = reply.send(true);
                }
                other => panic!("unexpected message: {:?}", other),
            }
        });

        let out = await_path(&tx, [0x11; 16], Duration::from_secs(1)).await;
        assert!(out.is_ok());
    }

    #[tokio::test]
    async fn timeouts_when_actor_replies_false() {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(4);
        tokio::spawn(async move {
            if let Some(TransportMessage::AwaitPath { reply, .. }) = rx.recv().await {
                let _ = reply.send(false);
            }
        });

        let out = await_path(&tx, [0x22; 16], Duration::from_secs(1)).await;
        assert_eq!(out, Err(AwaitPathError::Timeout));
    }

    #[tokio::test]
    async fn timeouts_when_caller_deadline_fires() {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(4);
        // Drain the message but never reply — caller's tokio::time::timeout
        // must fire.
        tokio::spawn(async move {
            let _ = rx.recv().await;
            // Hold the reply sender forever by moving it into a never-ending
            // task.
            std::future::pending::<()>().await;
        });

        let out = await_path(&tx, [0x33; 16], Duration::from_millis(50)).await;
        assert_eq!(out, Err(AwaitPathError::Timeout));
    }

    #[tokio::test]
    async fn transport_down_when_channel_closed() {
        let (tx, rx) = mpsc::channel::<TransportMessage>(1);
        drop(rx);
        let out = await_path(&tx, [0x44; 16], Duration::from_millis(50)).await;
        assert_eq!(out, Err(AwaitPathError::TransportDown));
    }

    #[tokio::test]
    async fn treats_dropped_reply_sender_as_timeout() {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(4);
        tokio::spawn(async move {
            // Consume the AwaitPath message, then drop the reply sender
            // without sending anything.
            if let Some(TransportMessage::AwaitPath { reply, .. }) = rx.recv().await {
                drop(reply);
            }
        });

        let out = await_path(&tx, [0x55; 16], Duration::from_millis(200)).await;
        assert_eq!(out, Err(AwaitPathError::Timeout));
    }

    #[tokio::test]
    async fn timeout_includes_actor_channel_submission() {
        let (tx, rx) = mpsc::channel::<TransportMessage>(1);
        tx.send(TransportMessage::Shutdown)
            .await
            .expect("prefill actor channel");

        let out = await_path(&tx, [0x66; 16], Duration::from_millis(50)).await;
        assert_eq!(out, Err(AwaitPathError::Timeout));
        drop(rx);
    }
}
