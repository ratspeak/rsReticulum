//! HDLC-framed data over a subprocess's stdin/stdout, matching upstream
//! `PipeInterface`. The command is split like Python `shlex.split` and run
//! directly, without a shell. The first spawn happens while the interface is
//! created and its failure fails creation; after the child exits the
//! interface is offline, drops outbound traffic, and respawns every
//! `respawn_delay` seconds until a spawn succeeds.

use rns_transport::messages::{InterfacePacketCapacity, InterfaceTransportSender};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
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
    /// Seconds before each respawn attempt; must be finite and non-negative.
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

/// Split `command` like Python `shlex.split(command)` (POSIX mode, no
/// comments). Returns `None` for an unterminated quote or trailing escape.
pub fn split_command(command: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Space,
        Word,
        Quote(char),
        Escape(Option<char>),
    }
    let mut words = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut state = State::Space;
    for c in command.chars() {
        let whitespace = matches!(c, ' ' | '\t' | '\r' | '\n');
        match state {
            State::Space | State::Word => {
                if whitespace {
                    if state == State::Word || quoted {
                        words.push(std::mem::take(&mut token));
                        quoted = false;
                    }
                    state = State::Space;
                } else if c == '\\' {
                    state = State::Escape(None);
                } else if c == '\'' || c == '"' {
                    state = State::Quote(c);
                } else {
                    token.push(c);
                    state = State::Word;
                }
            }
            State::Quote(q) => {
                quoted = true;
                if c == q {
                    state = State::Word;
                } else if c == '\\' && q == '"' {
                    state = State::Escape(Some(q));
                } else {
                    token.push(c);
                }
            }
            State::Escape(inside) => {
                // Inside double quotes only the quote and backslash are escapable.
                if inside.is_some_and(|q| c != '\\' && c != q) {
                    token.push('\\');
                }
                token.push(c);
                state = inside.map_or(State::Word, State::Quote);
            }
        }
    }
    match state {
        State::Quote(_) | State::Escape(_) => None,
        State::Word => {
            words.push(token);
            Some(words)
        }
        State::Space => {
            if quoted {
                words.push(token);
            }
            Some(words)
        }
    }
}

fn spawn_child(argv: &[String]) -> std::io::Result<(Child, ChildStdin, ChildStdout)> {
    let Some((program, args)) = argv.split_first() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty PipeInterface command",
        ));
    };
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let stdin = child.stdin.take().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "subprocess has no stdin")
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "subprocess has no stdout")
    })?;
    Ok((child, stdin, stdout))
}

pub async fn spawn_pipe_interface(
    config: PipeInterfaceConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    if !config.respawn_delay.is_finite() || config.respawn_delay < 0.0 {
        return Err(crate::traits::InterfaceError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid PipeInterface respawn_delay {}",
                config.respawn_delay
            ),
        )));
    }
    let argv = split_command(&config.command).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "PipeInterface command has an unterminated quote or escape",
        )
    })?;
    let first = spawn_child(&argv)?;
    tracing::info!(name = %config.name, cmd = %config.command, "PipeInterface: subprocess spawned");

    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    let online = Arc::new(AtomicBool::new(true));
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);
    let name = config.name.clone();
    let mode = config.mode;
    let respawn_delay = Duration::from_secs_f64(config.respawn_delay);

    let online_task = online.clone();
    let rxb_task = shared_rxb.clone();
    let txb_task = shared_txb.clone();

    let read_task = tokio::spawn(async move {
        let (mut child, mut stdin, mut stdout) = first;
        loop {
            let mut deframer = hdlc::HdlcDeframer::new();
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    read = stdout.read(&mut buf) => match read {
                        Ok(0) => {
                            tracing::info!(name = %config.name, "PipeInterface: subprocess terminated");
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
                            tracing::error!(name = %config.name, error = %e, "PipeInterface: pipe error");
                            break;
                        }
                    },
                    outbound = rx.recv() => {
                        let Some(data) = outbound else {
                            online_task.store(false, Ordering::SeqCst);
                            return;
                        };
                        let framed = hdlc::frame(&data);
                        let written = async {
                            stdin.write_all(&framed).await?;
                            stdin.flush().await
                        }
                        .await;
                        match written {
                            Ok(()) => {
                                txb_task.fetch_add(framed.len() as u64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                tracing::warn!(name = %config.name, error = %e, "PipeInterface: write error");
                            }
                        }
                    }
                }
            }

            online_task.store(false, Ordering::SeqCst);
            let _ = child.kill().await;

            // Offline until a respawn succeeds; outbound traffic is dropped.
            loop {
                let wake = tokio::time::sleep(respawn_delay);
                tokio::pin!(wake);
                loop {
                    tokio::select! {
                        _ = &mut wake => break,
                        outbound = rx.recv() => {
                            if outbound.is_none() {
                                return;
                            }
                        }
                    }
                }
                tracing::debug!(name = %config.name, "PipeInterface: attempting to respawn subprocess");
                match spawn_child(&argv) {
                    Ok(spawned) => {
                        (child, stdin, stdout) = spawned;
                        while rx.try_recv().is_ok() {}
                        online_task.store(true, Ordering::SeqCst);
                        tracing::info!(name = %config.name, "PipeInterface: reconnected pipe");
                        break;
                    }
                    Err(e) => {
                        tracing::error!(name = %config.name, error = %e, "PipeInterface: error while spawning subprocess");
                    }
                }
            }
        }
    });

    Ok(InterfaceHandle {
        id,
        owner,
        packet_capacity: InterfacePacketCapacity::new(500, 1064, false),
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
