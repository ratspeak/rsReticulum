//! Serial session with an RNode, modelled on upstream `rnodeconf`'s `RNode`
//! class: writes go out as upstream builds them, and replies are folded into
//! device state while the caller waits out upstream's fixed delays.

use std::collections::VecDeque;
use std::io::{BufRead, Read, Write};
use std::time::{Duration, Instant};

use rns_interface::{kiss, rnode, rnode_admin};

use super::{log, model};

pub struct RNode {
    /// `None` once upstream would have closed the serial port.
    port: Option<Box<dyn serialport::SerialPort>>,
    inbox: FrameInbox,
    pub name: String,
    pub usb_serial_id: Option<String>,
    pub detected: Option<bool>,
    pub platform: Option<u8>,
    pub mcu: Option<u8>,
    pub board: Option<u8>,
    pub major_version: Option<u8>,
    pub minor_version: Option<u8>,
    pub eeprom: Option<Vec<u8>>,
    pub cfg_sector: Option<Vec<u8>>,
    pub firmware_hash: Option<Vec<u8>>,
    pub firmware_hash_target: Option<Vec<u8>>,
    pub device_hash: Option<[u8; 32]>,
}

impl RNode {
    pub fn new(port: Box<dyn serialport::SerialPort>, name: String) -> Self {
        Self {
            port: Some(port),
            inbox: FrameInbox::default(),
            name,
            usb_serial_id: None,
            detected: None,
            platform: None,
            mcu: None,
            board: None,
            major_version: None,
            minor_version: None,
            eeprom: None,
            cfg_sector: None,
            firmware_hash: None,
            firmware_hash_target: None,
            device_hash: None,
        }
    }

    /// Upstream `updateVersion`: a one-digit minor version is zero-padded.
    pub fn version(&self) -> Option<String> {
        Some(format!(
            "{}.{:02}",
            self.major_version?, self.minor_version?
        ))
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        // pyserial's `PortNotOpenError` text, which upstream logs.
        let port = self
            .port
            .as_mut()
            .ok_or_else(|| "Attempting to use a port that is not open".to_string())?;
        port.write_all(bytes)
            .and_then(|()| port.flush())
            .map_err(|error| format!("serial write failed: {error}"))
    }

    /// Upstream `serial.close()`: its reader thread stops with the port.
    pub fn close(&mut self) {
        self.port = None;
        self.inbox = FrameInbox::default();
    }

    /// Upstream assigns a newly opened port and starts a new reader thread.
    pub fn reopen(&mut self, port: Box<dyn serialport::SerialPort>, name: String) {
        self.port = Some(port);
        self.name = name;
    }

    pub fn send(&mut self, command: u8, payload: &[u8]) -> Result<(), String> {
        self.write(&rnode_admin::encode_frame(command, payload))
    }

    pub fn send_frame(&mut self, frame: &rnode_admin::AdminFrame) -> Result<(), String> {
        self.send(frame.command, &frame.payload)
    }

    /// Upstream's `input()` while its reader thread keeps applying replies.
    pub fn wait_for_enter(&mut self) -> Result<(), String> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = tx.send(std::io::stdin().lock().read_line(&mut line));
        });
        loop {
            match rx.try_recv() {
                Ok(Ok(0)) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err("EOF when reading a line".to_string());
                }
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(error)) => return Err(error.to_string()),
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pump(Duration::from_millis(50))?;
                }
            }
        }
    }

    /// Read and apply replies for `duration`, as upstream's reader thread does
    /// while the main thread sleeps.
    pub fn pump(&mut self, duration: Duration) -> Result<(), String> {
        let deadline = Instant::now() + duration;
        let mut buffer = [0u8; 512];
        loop {
            while let Some(frame) = self.inbox.pop() {
                self.apply(&frame);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(());
            }
            let wait = deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(50));
            let Some(port) = self.port.as_mut() else {
                std::thread::sleep(deadline.saturating_duration_since(now));
                return Ok(());
            };
            port.set_timeout(wait)
                .map_err(|error| format!("could not set serial read timeout: {error}"))?;
            match port.read(&mut buffer) {
                Ok(count) => self.inbox.feed(&buffer[..count]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(format!("serial read failed: {error}")),
            }
        }
    }

    fn apply(&mut self, frame: &rnode_admin::AdminFrame) {
        let payload = frame.payload.as_slice();
        match frame.command {
            rnode::CMD_ROM_READ => self.eeprom = Some(payload.to_vec()),
            rnode::CMD_CFG_READ => self.cfg_sector = Some(payload.to_vec()),
            rnode::CMD_FREQUENCY if payload.len() >= 4 => log(format!(
                "Radio reporting frequency is {} MHz",
                py_float(f64::from(be_u32(payload)) / 1_000_000.0)
            )),
            rnode::CMD_BANDWIDTH if payload.len() >= 4 => log(format!(
                "Radio reporting bandwidth is {} KHz",
                py_float(f64::from(be_u32(payload)) / 1000.0)
            )),
            rnode::CMD_BT_PIN if payload.len() >= 4 => {
                log(format!("Bluetooth pairing PIN is: {:06}", be_u32(payload)))
            }
            rnode::CMD_DEV_HASH if payload.len() >= 32 => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&payload[..32]);
                self.device_hash = Some(hash);
            }
            rnode::CMD_HASHES if payload.len() >= 33 => match payload[0] {
                0x01 => self.firmware_hash_target = Some(payload[1..33].to_vec()),
                0x02 => self.firmware_hash = Some(payload[1..33].to_vec()),
                _ => {}
            },
            rnode::CMD_FW_VERSION if payload.len() >= 2 => {
                self.major_version = Some(payload[0]);
                self.minor_version = Some(payload[1]);
            }
            rnode::CMD_BOARD => self.board = payload.last().copied().or(self.board),
            rnode::CMD_PLATFORM => self.platform = payload.last().copied().or(self.platform),
            rnode::CMD_MCU => self.mcu = payload.last().copied().or(self.mcu),
            rnode::CMD_TXPOWER => {
                for byte in payload {
                    log(format!("Radio reporting TX power is {byte} dBm"));
                }
            }
            rnode::CMD_SF => {
                for byte in payload {
                    log(format!("Radio reporting spreading factor is {byte}"));
                }
            }
            rnode::CMD_CR => {
                for byte in payload {
                    log(format!("Radio reporting coding rate is {byte}"));
                }
            }
            rnode::CMD_ERROR => {
                for &byte in payload {
                    let kind = match byte {
                        rnode::ERROR_INITRADIO => "hardware initialisation error",
                        rnode::ERROR_TXFAILED => "hardware TX error",
                        _ => "hardware error",
                    };
                    log(format!("RNode {kind} (code {byte:02x})"));
                }
            }
            rnode::CMD_DETECT => {
                if let Some(&byte) = payload.last() {
                    self.detected = Some(byte == rnode::DETECT_RESP);
                }
            }
            _ => {}
        }
    }

    /// Upstream `detect`: the whole query batch in one write, FEND-separated.
    pub fn detect(&mut self) -> Result<(), String> {
        let fend = kiss::FEND;
        self.write(&[
            fend,
            rnode::CMD_DETECT,
            rnode::DETECT_REQ,
            fend,
            rnode::CMD_FW_VERSION,
            0x00,
            fend,
            rnode::CMD_PLATFORM,
            0x00,
            fend,
            rnode::CMD_MCU,
            0x00,
            fend,
            rnode::CMD_BOARD,
            0x00,
            fend,
            rnode::CMD_DEV_HASH,
            0x01,
            fend,
            rnode::CMD_HASHES,
            0x01,
            fend,
            rnode::CMD_HASHES,
            0x02,
            fend,
        ])
    }

    /// Upstream `device_probe`; the error is the text upstream prints.
    pub fn device_probe(&mut self) -> Result<(), String> {
        self.pump(Duration::from_millis(2500))?;
        self.detect()?;
        self.pump(Duration::from_millis(750))?;
        if self.detected != Some(true) {
            return Err("Got invalid response while detecting device".to_string());
        }
        log("Device connected");
        let version = self
            .version()
            .ok_or_else(|| "can only concatenate str (not \"NoneType\") to str".to_string())?;
        log(format!("Current firmware version: {version}"));
        Ok(())
    }

    pub fn leave(&mut self) -> Result<(), String> {
        self.send(rnode::CMD_LEAVE, &[0xFF])?;
        self.pump(Duration::from_secs(1))
    }

    pub fn download_eeprom(&mut self) -> Result<(), String> {
        self.eeprom = None;
        self.send(rnode::CMD_ROM_READ, &[0x00])?;
        self.pump(Duration::from_millis(600))
    }

    pub fn download_cfg_sector(&mut self) -> Result<(), String> {
        self.cfg_sector = None;
        self.send(rnode::CMD_CFG_READ, &[0x00])?;
        self.pump(Duration::from_millis(600))
    }

    pub fn set_normal_mode(&mut self) -> Result<(), String> {
        self.send(rnode::CMD_CONF_DELETE, &[0x00])
    }

    pub fn set_tnc_mode(&mut self) -> Result<(), String> {
        self.send(rnode::CMD_CONF_SAVE, &[0x00])?;
        if self.platform == Some(model::PLATFORM_ESP32) {
            self.hard_reset()?;
        }
        Ok(())
    }

    pub fn hard_reset(&mut self) -> Result<(), String> {
        self.send(rnode::CMD_RESET, &[0xF8])?;
        self.pump(Duration::from_secs(2))
    }

    pub fn wipe_eeprom(&mut self) -> Result<(), String> {
        self.send(rnode::CMD_ROM_WIPE, &[0xF8])?;
        self.pump(Duration::from_secs(13))?;
        if self.board == Some(model::BOARD_RAK4631) {
            self.pump(Duration::from_secs(10))?;
        }
        Ok(())
    }

    pub fn write_eeprom(&mut self, address: usize, value: u8) -> Result<(), String> {
        let address = u8::try_from(address).map_err(|_| "byte must be in range(0, 256)")?;
        self.send(rnode::CMD_ROM_WRITE, &[address, value])
    }
}

fn be_u32(payload: &[u8]) -> u32 {
    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
}

/// Python `repr(float)`.
pub fn py_float(value: f64) -> String {
    if !value.is_finite() {
        return if value.is_nan() {
            "nan".to_string()
        } else if value > 0.0 {
            "inf".to_string()
        } else {
            "-inf".to_string()
        };
    }
    let magnitude = value.abs();
    if magnitude >= 1e16 || (magnitude != 0.0 && magnitude < 1e-4) {
        let formatted = format!("{value:e}");
        let (mantissa, exponent) = formatted.split_once('e').expect("exponent format");
        let exponent: i32 = exponent.parse().expect("exponent digits");
        let sign = if exponent < 0 { '-' } else { '+' };
        return format!("{mantissa}e{sign}{:02}", exponent.abs());
    }
    let formatted = format!("{value}");
    if formatted.contains('.') {
        formatted
    } else {
        format!("{formatted}.0")
    }
}

/// Python `round(value, digits)` for display.
pub fn py_round(value: f64, digits: usize) -> f64 {
    format!("{value:.digits$}").parse().unwrap_or(value)
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
