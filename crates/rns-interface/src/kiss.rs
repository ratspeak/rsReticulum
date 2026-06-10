//! KISS TNC framing — used by KISS, AX.25-KISS, RNode, RNodeMulti, TCP/I2P.
//! Wire: `[FEND][CMD][escaped_payload][FEND]`.

pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;

pub const CMD_DATA: u8 = 0x00;
pub const CMD_TXDELAY: u8 = 0x01;
pub const CMD_P: u8 = 0x02;
pub const CMD_SLOTTIME: u8 = 0x03;
pub const CMD_TXTAIL: u8 = 0x04;
pub const CMD_FULLDUPLEX: u8 = 0x05;
pub const CMD_SETHARDWARE: u8 = 0x06;
pub const CMD_READY: u8 = 0x0F;
pub const CMD_RETURN: u8 = 0xFF;
pub const CMD_UNKNOWN: u8 = 0xFE;

/// High nibble of command byte = TNC port.
pub const PORT_MASK: u8 = 0xF0;
/// Low nibble of command byte = command.
pub const CMD_MASK: u8 = 0x0F;

/// Sized for full resource transfers on TCP/Local MTUs.
const MAX_FRAME_SIZE: usize = 524288;

/// Pre-allocated capacity for the deframer accumulator.
const DEFRAME_BUF_CAPACITY: usize = 2048;

/// Append the KISS-escape-encoded form of `data` to `out`.
pub fn escape_into(data: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < data.len() {
        match data[i..].iter().position(|&b| b == FESC || b == FEND) {
            Some(rel) => {
                let hit = i + rel;
                out.extend_from_slice(&data[i..hit]);
                out.push(FESC);
                out.push(if data[hit] == FEND { TFEND } else { TFESC });
                i = hit + 1;
            }
            None => {
                out.extend_from_slice(&data[i..]);
                return;
            }
        }
    }
}

/// Append the unescaped form of `data` to `out`. Unknown escape sequences and
/// a trailing lone FESC byte are passed through unchanged — matching the
/// previous implementation byte-for-byte.
pub fn unescape_into(data: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < data.len() {
        match data[i..].iter().position(|&b| b == FESC) {
            Some(rel) => {
                let hit = i + rel;
                out.extend_from_slice(&data[i..hit]);
                if hit + 1 < data.len() {
                    match data[hit + 1] {
                        TFEND => out.push(FEND),
                        TFESC => out.push(FESC),
                        other => {
                            out.push(FESC);
                            out.push(other);
                        }
                    }
                    i = hit + 2;
                } else {
                    out.push(FESC);
                    return;
                }
            }
            None => {
                out.extend_from_slice(&data[i..]);
                return;
            }
        }
    }
}

/// Append a complete KISS data-frame for `data` to `out`.
pub fn frame_into(data: &[u8], out: &mut Vec<u8>) {
    out.push(FEND);
    out.push(CMD_DATA);
    escape_into(data, out);
    out.push(FEND);
}

/// Append a KISS frame with an explicit command byte to `out`.
pub fn frame_with_command_into(cmd: u8, data: &[u8], out: &mut Vec<u8>) {
    out.push(FEND);
    out.push(cmd);
    escape_into(data, out);
    out.push(FEND);
}

pub fn escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 8);
    escape_into(data, &mut out);
    out
}

pub fn unescape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    unescape_into(data, &mut out);
    out
}

pub fn frame(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 8 + 3);
    frame_into(data, &mut out);
    out
}

pub fn frame_with_command(cmd: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 8 + 3);
    frame_with_command_into(cmd, data, &mut out);
    out
}

/// Classic KISS deframer: high nibble of the command byte is a TNC port, so
/// frames are returned as `(command & CMD_MASK, data)`. Thin wrapper over
/// [`RawKissDeframer`], which owns the framing state machine.
pub struct KissDeframer {
    inner: RawKissDeframer,
}

impl KissDeframer {
    pub fn new() -> Self {
        Self {
            inner: RawKissDeframer::new(),
        }
    }

    /// Returns complete frames as (command, data) pairs.
    pub fn feed(&mut self, data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut frames = self.inner.feed(data);
        for frame in &mut frames {
            frame.0 &= CMD_MASK;
        }
        frames
    }

    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

impl Default for KissDeframer {
    fn default() -> Self {
        Self::new()
    }
}

/// Extended-KISS deframer that preserves the full command byte.
///
/// Classic KISS uses the high nibble as a TNC port and the low nibble as the
/// command, so [`KissDeframer`] returns `command & CMD_MASK`. RNode admin
/// commands use the complete byte (`0x50`, `0x62`, `0x84`, ...), so they must
/// use this deframer instead.
pub struct RawKissDeframer {
    buffer: Vec<u8>,
    in_frame: bool,
    command: u8,
    /// Reusable scratch for unescape output.
    unescape_scratch: Vec<u8>,
}

impl RawKissDeframer {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(DEFRAME_BUF_CAPACITY),
            in_frame: false,
            command: CMD_UNKNOWN,
            unescape_scratch: Vec::with_capacity(DEFRAME_BUF_CAPACITY),
        }
    }

    /// Returns complete frames as (full_command, data) pairs.
    pub fn feed(&mut self, data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut frames = Vec::new();
        let mut i = 0;
        while i < data.len() {
            match data[i..].iter().position(|&b| b == FEND) {
                Some(rel) => {
                    let hit = i + rel;
                    if self.in_frame {
                        self.append_in_frame(&data[i..hit]);
                        if !self.buffer.is_empty() {
                            self.unescape_scratch.clear();
                            unescape_into(&self.buffer, &mut self.unescape_scratch);
                            let frame_data = std::mem::replace(
                                &mut self.unescape_scratch,
                                Vec::with_capacity(DEFRAME_BUF_CAPACITY),
                            );
                            frames.push((self.command, frame_data));
                        }
                        self.buffer.clear();
                    }
                    self.in_frame = true;
                    self.command = CMD_UNKNOWN;
                    i = hit + 1;
                }
                None => {
                    if self.in_frame {
                        self.append_in_frame(&data[i..]);
                    }
                    return frames;
                }
            }
        }
        frames
    }

    /// Append `chunk` to the in-frame buffer. The first byte after a FEND is
    /// the command byte (consumed separately); subsequent bytes are payload
    /// up to `MAX_FRAME_SIZE`. Overflow drops the in-progress frame and waits
    /// for the next FEND to resync — matching the previous byte-loop.
    fn append_in_frame(&mut self, chunk: &[u8]) {
        let mut chunk = chunk;
        if self.command == CMD_UNKNOWN {
            if let Some((&first, rest)) = chunk.split_first() {
                self.command = first;
                chunk = rest;
            } else {
                return;
            }
        }
        if self.buffer.len() + chunk.len() > MAX_FRAME_SIZE {
            self.buffer.clear();
            self.in_frame = false;
            self.command = CMD_UNKNOWN;
            return;
        }
        self.buffer.extend_from_slice(chunk);
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.in_frame = false;
        self.command = CMD_UNKNOWN;
    }
}

impl Default for RawKissDeframer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_unescape_roundtrip() {
        let data = vec![0x00, FEND, FESC, 0xFF, FEND, FESC, 0x42];
        let escaped = escape(&data);
        let unescaped = unescape(&escaped);
        assert_eq!(unescaped, data);
    }

    #[test]
    fn test_escape_no_special_bytes() {
        let data = b"hello";
        let escaped = escape(data);
        assert_eq!(escaped, data);
    }

    #[test]
    fn test_escape_fend() {
        let data = vec![FEND];
        let escaped = escape(&data);
        assert_eq!(escaped, vec![FESC, TFEND]);
    }

    #[test]
    fn test_escape_fesc() {
        let data = vec![FESC];
        let escaped = escape(&data);
        assert_eq!(escaped, vec![FESC, TFESC]);
    }

    #[test]
    fn test_frame_and_deframe() {
        let data = b"test kiss data";
        let framed = frame(data);

        let mut deframer = KissDeframer::new();
        let frames = deframer.feed(&framed);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, CMD_DATA);
        assert_eq!(frames[0].1, data);
    }

    #[test]
    fn test_deframer_multiple_frames() {
        let f1 = frame(b"first");
        let f2 = frame(b"second");

        let mut combined = f1;
        combined.extend_from_slice(&f2);

        let mut deframer = KissDeframer::new();
        let frames = deframer.feed(&combined);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].1, b"first");
        assert_eq!(frames[1].1, b"second");
    }

    #[test]
    fn test_port_nibble_stripped() {
        // High nibble = TNC port, must be masked.
        let mut framed = Vec::new();
        framed.push(FEND);
        framed.push(0x10 | CMD_DATA);
        framed.extend_from_slice(b"data");
        framed.push(FEND);

        let mut deframer = KissDeframer::new();
        let frames = deframer.feed(&framed);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, CMD_DATA);
    }

    #[test]
    fn test_raw_deframer_preserves_extended_commands() {
        let mut deframer = RawKissDeframer::new();
        let mut bytes = Vec::new();
        frame_with_command_into(0x50, &[0x00], &mut bytes);
        frame_with_command_into(0x62, &[0x00, 0x01, 0xE2, 0x40], &mut bytes);
        frame_with_command_into(0x84, &[192, 168, 1, 10], &mut bytes);

        let frames = deframer.feed(&bytes);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].0, 0x50);
        assert_eq!(frames[1].0, 0x62);
        assert_eq!(frames[1].1, vec![0x00, 0x01, 0xE2, 0x40]);
        assert_eq!(frames[2].0, 0x84);
    }

    #[test]
    fn test_deframer_streaming() {
        let framed = frame(b"stream");
        let mid = framed.len() / 2;

        let mut deframer = KissDeframer::new();
        let f1 = deframer.feed(&framed[..mid]);
        assert!(f1.is_empty());

        let f2 = deframer.feed(&framed[mid..]);
        assert_eq!(f2.len(), 1);
        assert_eq!(f2[0].1, b"stream");
    }

    #[test]
    fn test_frame_with_command() {
        let data = b"hardware config";
        let framed = frame_with_command(CMD_SETHARDWARE, data);

        let mut deframer = KissDeframer::new();
        let frames = deframer.feed(&framed);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, CMD_SETHARDWARE);
        assert_eq!(frames[0].1, data);
    }

    #[test]
    fn test_into_variants_match_allocating() {
        let inputs: &[&[u8]] = &[
            b"",
            b"plain",
            &[FEND, FESC, 0x00, 0xFF, FEND],
            &[FESC, FESC, FESC],
            &[0x00; 1024],
        ];
        for data in inputs {
            let mut buf = Vec::new();
            escape_into(data, &mut buf);
            assert_eq!(buf, escape(data));

            let escaped = escape(data);
            let mut buf2 = Vec::new();
            unescape_into(&escaped, &mut buf2);
            assert_eq!(buf2, unescape(&escaped));

            let mut buf3 = Vec::new();
            frame_into(data, &mut buf3);
            assert_eq!(buf3, frame(data));

            let mut buf4 = Vec::new();
            frame_with_command_into(CMD_SETHARDWARE, data, &mut buf4);
            assert_eq!(buf4, frame_with_command(CMD_SETHARDWARE, data));
        }
    }

    #[test]
    fn test_deframer_streaming_command_byte_boundary() {
        // Command byte arrives in a separate feed() chunk from the payload.
        let framed = frame(b"split");
        let mut deframer = KissDeframer::new();
        // Feed just [FEND] first — no command byte yet.
        let f1 = deframer.feed(&framed[..1]);
        assert!(f1.is_empty());
        // Feed just the command byte — still no full frame.
        let f2 = deframer.feed(&framed[1..2]);
        assert!(f2.is_empty());
        // Feed the payload + closing FEND.
        let f3 = deframer.feed(&framed[2..]);
        assert_eq!(f3.len(), 1);
        assert_eq!(f3[0].0, CMD_DATA);
        assert_eq!(f3[0].1, b"split");
    }

    #[test]
    fn test_deframer_oversized_drops_then_resyncs() {
        let mut deframer = KissDeframer::new();
        let mut oversized = vec![FEND, CMD_DATA];
        oversized.extend(std::iter::repeat_n(0x55, MAX_FRAME_SIZE + 100));
        oversized.push(FEND);
        let frames = deframer.feed(&oversized);
        assert!(frames.is_empty());

        let small = frame(b"after-overflow");
        let frames = deframer.feed(&small);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].1, b"after-overflow");
    }
}
