//! HDLC-framed data over a subprocess's stdin/stdout; respawns on exit.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::hdlc;
use crate::traits::{InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

pub const BITRATE_GUESS: u64 = 1_000_000;
pub const HW_MTU: u32 = 1064;
pub const DEFAULT_RESPAWN_DELAY: f64 = 5.0;

#[derive(Debug, Clone)]
pub struct PipeInterfaceConfig {
    pub name: String,
    pub command: String,
    /// Seconds before respawning after subprocess exit.
    pub respawn_delay: f64,
    pub mode: InterfaceMode,
}

impl PipeInterfaceConfig {
    pub fn new(name: &str, command: &str) -> Self {
        Self {
            name: name.to_string(),
            command: command.to_string(),
            respawn_delay: DEFAULT_RESPAWN_DELAY,
            mode: InterfaceMode::Full,
        }
    }
}

pub async fn spawn_pipe_interface(
    config: PipeInterfaceConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let online = Arc::new(AtomicBool::new(true));
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<Bytes>(256);
    let name = config.name.clone();
    let mode = config.mode;

    // Outbound rx must survive respawns; share across write loops.
    let rx = Arc::new(tokio::sync::Mutex::new(rx));

    let online_task = online.clone();
    let rxb_task = shared_rxb.clone();
    let txb_task = shared_txb.clone();

    let read_task = tokio::spawn(async move {
        loop {
            if !online_task.load(Ordering::SeqCst) {
                break;
            }

            let parts: Vec<&str> = config.command.split_whitespace().collect();
            if parts.is_empty() {
                tracing::error!("PipeInterface: empty command");
                break;
            }

            let child = Command::new(parts[0])
                .args(&parts[1..])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn();

            let mut child = match child {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "PipeInterface: failed to spawn subprocess");
                    tokio::time::sleep(std::time::Duration::from_secs_f64(config.respawn_delay))
                        .await;
                    continue;
                }
            };

            tracing::info!(name = %config.name, cmd = %config.command, "PipeInterface: subprocess spawned");

            let mut stdout = match child.stdout.take() {
                Some(s) => s,
                None => {
                    tracing::error!("PipeInterface: no stdout from subprocess");
                    break;
                }
            };
            let mut stdin = match child.stdin.take() {
                Some(s) => s,
                None => {
                    tracing::error!("PipeInterface: no stdin for subprocess");
                    break;
                }
            };

            // Per-subprocess writer channel; outer rx forwards into conn_tx.
            let (conn_tx, mut conn_rx) = mpsc::channel::<Bytes>(256);
            let online_w = online_task.clone();
            let txb_w = txb_task.clone();
            let write_handle = tokio::spawn(async move {
                while let Some(data) = conn_rx.recv().await {
                    if !online_w.load(Ordering::SeqCst) {
                        break;
                    }
                    let framed = hdlc::frame(&data);
                    txb_w.fetch_add(framed.len() as u64, Ordering::Relaxed);
                    if let Err(e) = stdin.write_all(&framed).await {
                        tracing::warn!(error = %e, "PipeInterface: write error");
                        break;
                    }
                    if let Err(e) = stdin.flush().await {
                        tracing::warn!(error = %e, "PipeInterface: flush error");
                        break;
                    }
                }
            });

            let rx_ref = rx.clone();
            let fwd_handle = tokio::spawn(async move {
                let mut guard = rx_ref.lock().await;
                while let Some(data) = guard.recv().await {
                    if conn_tx.send(data).await.is_err() {
                        break;
                    }
                }
            });

            let mut deframer = hdlc::HdlcDeframer::new();
            let mut buf = [0u8; 2048];
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) => {
                        tracing::info!("PipeInterface: subprocess stdout EOF");
                        break;
                    }
                    Ok(n) => {
                        rxb_task.fetch_add(n as u64, Ordering::Relaxed);
                        for frame in deframer.feed(&buf[..n]) {
                            if frame.is_empty() {
                                continue;
                            }
                            let msg = TransportMessage::Inbound(InboundPacket {
                                raw: Bytes::from(frame),
                                interface_id: id,
                                rssi: None,
                                snr: None,
                                q: None,
                            });
                            if transport_tx.send(msg).await.is_err() {
                                tracing::warn!(id, "transport channel closed");
                                online_task.store(false, Ordering::SeqCst);
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "PipeInterface: read error");
                        break;
                    }
                }
            }

            fwd_handle.abort();
            let _ = fwd_handle.await;
            write_handle.abort();
            let _ = write_handle.await;

            let _ = child.kill().await;

            if !online_task.load(Ordering::SeqCst) {
                break;
            }

            tracing::info!(
                name = %config.name,
                delay = config.respawn_delay,
                "PipeInterface: respawning subprocess"
            );
            tokio::time::sleep(std::time::Duration::from_secs_f64(config.respawn_delay)).await;
        }
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
        bitrate: BITRATE_GUESS,
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
    fn test_pipe_config() {
        let cfg = PipeInterfaceConfig::new("pipe0", "cat");
        assert_eq!(cfg.command, "cat");
        assert_eq!(cfg.respawn_delay, DEFAULT_RESPAWN_DELAY);
        assert_eq!(cfg.mode, InterfaceMode::Full);
    }

    #[test]
    fn test_constants() {
        assert_eq!(BITRATE_GUESS, 1_000_000);
        assert_eq!(HW_MTU, 1064);
    }

    #[test]
    fn test_pipe_config_custom_command() {
        let cfg = PipeInterfaceConfig::new("pipe1", "socat - TCP:10.0.0.1:4242");
        assert_eq!(cfg.command, "socat - TCP:10.0.0.1:4242");
        assert_eq!(cfg.name, "pipe1");
    }

    #[test]
    fn test_pipe_config_respawn_delay() {
        assert_eq!(DEFAULT_RESPAWN_DELAY, 5.0);
        let mut cfg = PipeInterfaceConfig::new("pipe0", "cat");
        assert_eq!(cfg.respawn_delay, 5.0);
        cfg.respawn_delay = 10.0;
        assert_eq!(cfg.respawn_delay, 10.0);
    }

    #[test]
    fn test_pipe_config_mode() {
        let mut cfg = PipeInterfaceConfig::new("pipe0", "cat");
        assert_eq!(cfg.mode, InterfaceMode::Full);
        cfg.mode = InterfaceMode::PointToPoint;
        assert_eq!(cfg.mode, InterfaceMode::PointToPoint);
    }
}
