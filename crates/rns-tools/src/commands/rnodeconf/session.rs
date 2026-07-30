//! Framing and deadline ownership for staged RNode administration sessions.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

use rns_interface::{kiss, rnode_admin};

/// Small transaction surface used by the mutation executor and deterministic
/// tests. Implementations must preserve inbound framing state between calls.
pub trait FrameSession {
    fn send(&mut self, frame: &rnode_admin::AdminFrame) -> Result<(), String>;

    /// Return the next complete frame, or `None` once `deadline` expires.
    fn receive_until(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<rnode_admin::AdminFrame>, String>;
}

pub struct SerialFrameSession {
    port: Box<dyn serialport::SerialPort>,
    inbox: FrameInbox,
}

impl SerialFrameSession {
    pub fn new(port: Box<dyn serialport::SerialPort>) -> Self {
        Self {
            port,
            inbox: FrameInbox::default(),
        }
    }
}

impl FrameSession for SerialFrameSession {
    fn send(&mut self, frame: &rnode_admin::AdminFrame) -> Result<(), String> {
        let encoded = rnode_admin::encode_frame(frame.command, &frame.payload);
        self.port
            .write_all(&encoded)
            .map_err(|error| format!("serial write failed: {error}"))?;
        self.port
            .flush()
            .map_err(|error| format!("serial flush failed: {error}"))
    }

    fn receive_until(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<rnode_admin::AdminFrame>, String> {
        if let Some(frame) = self.inbox.pop() {
            return Ok(Some(frame));
        }

        let mut buffer = [0u8; 512];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let remaining = deadline.saturating_duration_since(now);
            let read_timeout = remaining.min(Duration::from_millis(100));
            self.port
                .set_timeout(read_timeout)
                .map_err(|error| format!("could not set serial read timeout: {error}"))?;

            match self.port.read(&mut buffer) {
                Ok(0) => {}
                Ok(count) => {
                    self.inbox.feed(&buffer[..count]);
                    if let Some(frame) = self.inbox.pop() {
                        return Ok(Some(frame));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(format!("serial read failed: {error}")),
            }
        }
    }
}

#[derive(Default)]
struct FrameInbox {
    deframer: kiss::RawKissDeframer,
    frames: VecDeque<rnode_admin::AdminFrame>,
}

impl FrameInbox {
    fn feed(&mut self, bytes: &[u8]) {
        self.frames.extend(
            self.deframer
                .feed(bytes)
                .into_iter()
                .map(|(command, payload)| rnode_admin::AdminFrame { command, payload }),
        );
    }

    fn pop(&mut self) -> Option<rnode_admin::AdminFrame> {
        self.frames.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use rns_interface::{kiss, rnode};

    use super::*;

    #[test]
    fn one_deframer_survives_fragmented_and_escaped_input_across_stages() {
        let first =
            rnode_admin::encode_frame(rnode::CMD_CFG_READ, &[0x11, kiss::FEND, 0x22, kiss::FESC]);
        let second = rnode_admin::encode_frame(rnode::CMD_FREQUENCY, &868_000_000u32.to_be_bytes());
        let split = first.len() - 2;
        let mut inbox = FrameInbox::default();

        inbox.feed(&first[..3]);
        assert!(inbox.pop().is_none());
        inbox.feed(&first[3..split]);
        assert!(inbox.pop().is_none());
        inbox.feed(&first[split..]);
        assert_eq!(
            inbox.pop(),
            Some(rnode_admin::AdminFrame {
                command: rnode::CMD_CFG_READ,
                payload: vec![0x11, kiss::FEND, 0x22, kiss::FESC],
            })
        );

        for chunk in second.chunks(2) {
            inbox.feed(chunk);
        }
        assert_eq!(inbox.pop(), rnode_admin::decode_frames(&second).pop());
    }

    #[test]
    fn inbox_queues_multiple_frames_without_reframing_between_reads() {
        let mut wire = rnode_admin::encode_frame(rnode::CMD_READY, &[1]);
        wire.extend(rnode_admin::encode_frame(rnode::CMD_RADIO_STATE, &[1]));
        let mut inbox = FrameInbox::default();
        inbox.feed(&wire);

        assert_eq!(inbox.pop().unwrap().command, rnode::CMD_READY);
        assert_eq!(inbox.pop().unwrap().command, rnode::CMD_RADIO_STATE);
        assert!(inbox.pop().is_none());
    }
}
