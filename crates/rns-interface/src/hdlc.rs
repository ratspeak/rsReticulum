//! HDLC-like framing shared by TCP, Serial, I2P, Local, Pipe, and Backbone.
//! Wire: `[FLAG][escaped_payload][FLAG]`. Payload FLAG and ESC bytes are
//! prefixed with ESC and XORed with [`ESC_MASK`].

/// HDLC frame delimiter.
pub const FLAG: u8 = 0x7E;

/// HDLC escape byte.
pub const ESC: u8 = 0x7D;

/// XOR mask applied to escaped bytes.
pub const ESC_MASK: u8 = 0x20;

/// Default MTU of [`HdlcDeframer::new`]; partial frames are bounded at twice this.
const DEFAULT_MTU: usize = 262144;

/// Pre-allocated capacity for the deframer accumulator. Covers typical HW_MTUs
/// with headroom; larger frames grow the Vec normally.
const DEFRAME_BUF_CAPACITY: usize = 2048;

/// Append the escape-encoded form of `data` to `out`. No allocation is needed
/// when `out` has enough spare capacity for the escaped output.
pub fn escape_into(data: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < data.len() {
        match data[i..].iter().position(|&b| b == ESC || b == FLAG) {
            Some(rel) => {
                let hit = i + rel;
                out.extend_from_slice(&data[i..hit]);
                out.push(ESC);
                out.push(data[hit] ^ ESC_MASK);
                i = hit + 1;
            }
            None => {
                out.extend_from_slice(&data[i..]);
                return;
            }
        }
    }
}

/// Append the unescaped form of `data` to `out` as two global replacements,
/// `ESC 5E` to FLAG and then `ESC 5D` to ESC, so malformed sequences decode as
/// upstream `HDLC.unescape` does.
pub fn unescape_into(data: &[u8], out: &mut Vec<u8>) {
    let start = out.len();
    let mut i = 0;
    while i < data.len() {
        match data[i..].iter().position(|&b| b == ESC) {
            Some(rel) => {
                let hit = i + rel;
                out.extend_from_slice(&data[i..hit]);
                if data.get(hit + 1) == Some(&(FLAG ^ ESC_MASK)) {
                    out.push(FLAG);
                    i = hit + 2;
                } else {
                    out.push(ESC);
                    i = hit + 1;
                }
            }
            None => {
                out.extend_from_slice(&data[i..]);
                break;
            }
        }
    }
    let end = out.len();
    let (mut r, mut w) = (start, start);
    while r < end {
        let b = out[r];
        out[w] = b;
        w += 1;
        r += if b == ESC && r + 1 < end && out[r + 1] == (ESC ^ ESC_MASK) {
            2
        } else {
            1
        };
    }
    out.truncate(w);
}

/// Append a complete HDLC frame for `data` to `out`.
pub fn frame_into(data: &[u8], out: &mut Vec<u8>) {
    out.push(FLAG);
    escape_into(data, out);
    out.push(FLAG);
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
    let mut out = Vec::with_capacity(data.len() + data.len() / 8 + 2);
    frame_into(data, &mut out);
    out
}

/// Stream deframer with upstream `HDLC.ReceiveBuffer` semantics: a flag closes
/// one frame and opens the next, a frame is delivered only when its unescaped
/// length is above `min_frame_len` and at most `max_frame_len`, and an
/// unterminated partial frame longer than twice the MTU is dropped.
pub struct HdlcDeframer {
    buffer: Vec<u8>,
    in_frame: bool,
    /// Reusable scratch for unescape output to avoid per-frame allocation.
    unescape_scratch: Vec<u8>,
    /// Bytes before the opening flag that upstream keeps in its buffer.
    lead: usize,
    mtu: usize,
    min_frame_len: usize,
    max_frame_len: Option<usize>,
}

impl HdlcDeframer {
    /// Equivalent to `ReceiveBuffer(262144, 0, None)`: every non-empty frame is delivered.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MTU, 0, None)
    }

    /// Equivalent to `ReceiveBuffer(mtu, min_frame_len, max_frame_len)`.
    pub fn with_limits(mtu: usize, min_frame_len: usize, max_frame_len: Option<usize>) -> Self {
        Self {
            buffer: Vec::with_capacity(DEFRAME_BUF_CAPACITY),
            in_frame: false,
            unescape_scratch: Vec::with_capacity(DEFRAME_BUF_CAPACITY),
            lead: 0,
            mtu,
            min_frame_len,
            max_frame_len,
        }
    }

    /// Update the delivery bound, for example after the interface IFAC size changes.
    pub fn set_max_frame_len(&mut self, max_frame_len: Option<usize>) {
        self.max_frame_len = max_frame_len;
    }

    pub fn feed(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut i = 0;
        while i < data.len() {
            match data[i..].iter().position(|&b| b == FLAG) {
                Some(rel) => {
                    let hit = i + rel;
                    if self.in_frame {
                        self.buffer.extend_from_slice(&data[i..hit]);
                        self.finish_frame(&mut frames);
                        self.lead = 0;
                    } else {
                        self.lead = hit - i;
                    }
                    self.in_frame = true;
                    i = hit + 1;
                }
                None => {
                    if self.in_frame {
                        self.buffer.extend_from_slice(&data[i..]);
                        if self.lead + 1 + self.buffer.len() > self.mtu.saturating_mul(2) {
                            self.reset();
                        }
                    }
                    return frames;
                }
            }
        }
        frames
    }

    fn finish_frame(&mut self, frames: &mut Vec<Vec<u8>>) {
        if !self.buffer.is_empty() {
            self.unescape_scratch.clear();
            unescape_into(&self.buffer, &mut self.unescape_scratch);
            let len = self.unescape_scratch.len();
            if len > self.min_frame_len && self.max_frame_len.is_none_or(|max| len <= max) {
                frames.push(std::mem::replace(
                    &mut self.unescape_scratch,
                    Vec::with_capacity(DEFRAME_BUF_CAPACITY),
                ));
            } else if len > 0 {
                tracing::debug!(
                    frame_len = len,
                    "invalid HDLC frame received, dropping frame"
                );
            }
        }
        self.buffer.clear();
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.in_frame = false;
        self.lead = 0;
    }
}

impl Default for HdlcDeframer {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-byte deframer of the upstream serial, pipe and I2P read loops. Bytes past
/// `hw_mtu` are dropped but the frame is still delivered, an unknown escape keeps
/// only the escaped byte, the escape state carries across frames, and the flag
/// that closes a frame does not open the next one.
pub struct HdlcByteDeframer {
    buffer: Vec<u8>,
    in_frame: bool,
    escape: bool,
    /// Length of the last delivered frame, which upstream keeps buffered.
    held: usize,
    hw_mtu: usize,
}

impl HdlcByteDeframer {
    pub fn new(hw_mtu: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(DEFRAME_BUF_CAPACITY.min(hw_mtu)),
            in_frame: false,
            escape: false,
            held: 0,
            hw_mtu,
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        for &byte in data {
            if self.in_frame && byte == FLAG {
                self.in_frame = false;
                self.held = self.buffer.len();
                if !self.buffer.is_empty() {
                    frames.push(std::mem::take(&mut self.buffer));
                }
            } else if byte == FLAG {
                self.in_frame = true;
                self.buffer.clear();
                self.held = 0;
            } else if self.in_frame && self.buffer.len() < self.hw_mtu {
                if byte == ESC {
                    self.escape = true;
                } else {
                    let mut byte = byte;
                    if self.escape {
                        if byte == FLAG ^ ESC_MASK {
                            byte = FLAG;
                        } else if byte == ESC ^ ESC_MASK {
                            byte = ESC;
                        }
                        self.escape = false;
                    }
                    self.buffer.push(byte);
                }
            }
        }
        frames
    }

    /// Bytes upstream holds in its data buffer. Upstream drivers reset after an
    /// idle read timeout only while this is non-zero.
    pub fn buffered(&self) -> usize {
        if self.in_frame {
            self.buffer.len()
        } else {
            self.held
        }
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.held = 0;
        self.in_frame = false;
        self.escape = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_unescape_roundtrip() {
        let data = vec![0x00, FLAG, ESC, 0xFF, FLAG, ESC, 0x42];
        let escaped = escape(&data);
        let unescaped = unescape(&escaped);
        assert_eq!(unescaped, data);
    }

    #[test]
    fn test_escape_no_special_bytes() {
        let data = b"hello world";
        let escaped = escape(data);
        assert_eq!(escaped, data);
    }

    #[test]
    fn test_escape_flag_byte() {
        let data = vec![FLAG];
        let escaped = escape(&data);
        assert_eq!(escaped, vec![ESC, FLAG ^ ESC_MASK]);
    }

    #[test]
    fn test_escape_esc_byte() {
        let data = vec![ESC];
        let escaped = escape(&data);
        assert_eq!(escaped, vec![ESC, ESC ^ ESC_MASK]);
    }

    #[test]
    fn test_frame_and_deframe() {
        let data = b"test packet data";
        let framed = frame(data);

        let mut deframer = HdlcDeframer::new();
        let frames = deframer.feed(&framed);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], data);
    }

    #[test]
    fn test_deframer_multiple_frames() {
        let f1 = frame(b"first");
        let f2 = frame(b"second");

        let mut combined = f1;
        combined.extend_from_slice(&f2);

        let mut deframer = HdlcDeframer::new();
        let frames = deframer.feed(&combined);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], b"first");
        assert_eq!(frames[1], b"second");
    }

    #[test]
    fn test_deframer_streaming() {
        let framed = frame(b"streamed");

        let mut deframer = HdlcDeframer::new();

        let mid = framed.len() / 2;
        let frames1 = deframer.feed(&framed[..mid]);
        assert!(frames1.is_empty());

        let frames2 = deframer.feed(&framed[mid..]);
        assert_eq!(frames2.len(), 1);
        assert_eq!(frames2[0], b"streamed");
    }

    #[test]
    fn test_tricky_sequence() {
        // ESC, FLAG^MASK must decode to a single FLAG byte.
        let data = vec![ESC, 0x5E];
        let unescaped = unescape(&data);
        assert_eq!(unescaped, vec![FLAG]);
    }

    #[test]
    fn test_into_variants_match_allocating() {
        // The allocating wrappers must produce byte-identical output.
        let inputs: &[&[u8]] = &[
            b"",
            b"plain",
            &[FLAG, ESC, 0x00, 0xFF, FLAG],
            &[ESC, ESC, ESC],
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
        }
    }

    #[test]
    fn test_deframer_partial_over_twice_mtu_drops_then_resyncs() {
        let mut deframer = HdlcDeframer::with_limits(64, 0, None);
        let mut partial = vec![FLAG];
        partial.extend(std::iter::repeat_n(0x55, 128));
        assert!(deframer.feed(&partial).is_empty());

        let mut rest = vec![0x55, FLAG];
        rest.extend(frame(b"after-overflow"));
        let frames = deframer.feed(&rest);
        assert_eq!(frames, vec![b"after-overflow".to_vec()]);
    }
}
