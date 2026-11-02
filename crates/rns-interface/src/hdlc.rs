//! HDLC-like framing shared by TCP, Serial, I2P, Local, Pipe, and Backbone.
//! Wire: `[FLAG][escaped_payload][FLAG]`. Payload FLAG and ESC bytes are
//! prefixed with ESC and XORed with [`ESC_MASK`].

/// HDLC frame delimiter.
pub const FLAG: u8 = 0x7E;

/// HDLC escape byte.
pub const ESC: u8 = 0x7D;

/// XOR mask applied to escaped bytes.
pub const ESC_MASK: u8 = 0x20;

/// Upper bound on a single HDLC frame (sized for full resource transfers on TCP/Local MTUs).
const MAX_FRAME_SIZE: usize = 524288;

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

/// Append the unescaped form of `data` to `out`. Unknown escape sequences and a
/// trailing lone ESC byte are passed through unchanged — matching the previous
/// implementation so any consumer relying on length/CRC rejection still sees
/// the same bytes.
pub fn unescape_into(data: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < data.len() {
        match data[i..].iter().position(|&b| b == ESC) {
            Some(rel) => {
                let hit = i + rel;
                out.extend_from_slice(&data[i..hit]);
                if hit + 1 < data.len() {
                    let next = data[hit + 1];
                    if next == (FLAG ^ ESC_MASK) {
                        out.push(FLAG);
                    } else if next == (ESC ^ ESC_MASK) {
                        out.push(ESC);
                    } else {
                        out.push(ESC);
                        out.push(next);
                    }
                    i = hit + 2;
                } else {
                    out.push(ESC);
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

pub struct HdlcDeframer {
    buffer: Vec<u8>,
    in_frame: bool,
    /// Reusable scratch for unescape output to avoid per-frame allocation.
    unescape_scratch: Vec<u8>,
}

impl HdlcDeframer {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(DEFRAME_BUF_CAPACITY),
            in_frame: false,
            unescape_scratch: Vec::with_capacity(DEFRAME_BUF_CAPACITY),
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut i = 0;
        while i < data.len() {
            match data[i..].iter().position(|&b| b == FLAG) {
                Some(rel) => {
                    let hit = i + rel;
                    if self.in_frame {
                        self.append_in_frame(&data[i..hit]);
                        if !self.buffer.is_empty() {
                            self.unescape_scratch.clear();
                            unescape_into(&self.buffer, &mut self.unescape_scratch);
                            if !self.unescape_scratch.is_empty() {
                                frames.push(std::mem::take(&mut self.unescape_scratch));
                                // Restore capacity for the next frame.
                                self.unescape_scratch = Vec::with_capacity(DEFRAME_BUF_CAPACITY);
                            }
                        }
                        self.buffer.clear();
                    }
                    self.in_frame = true;
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

    /// Append `chunk` to `self.buffer` while enforcing `MAX_FRAME_SIZE`. On
    /// overflow the in-progress frame is dropped and we wait for the next FLAG
    /// to resync — matching the previous byte-loop behavior.
    fn append_in_frame(&mut self, chunk: &[u8]) {
        if self.buffer.len() + chunk.len() > MAX_FRAME_SIZE {
            self.buffer.clear();
            self.in_frame = false;
            return;
        }
        self.buffer.extend_from_slice(chunk);
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.in_frame = false;
    }
}

impl Default for HdlcDeframer {
    fn default() -> Self {
        Self::new()
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
    fn test_deframer_oversized_drops_then_resyncs() {
        // A frame body larger than MAX_FRAME_SIZE must drop and resync on the
        // next FLAG, exactly like the per-byte implementation.
        let mut deframer = HdlcDeframer::new();
        let mut oversized = vec![FLAG];
        oversized.extend(std::iter::repeat_n(0x55, MAX_FRAME_SIZE + 100));
        oversized.push(FLAG);
        let frames = deframer.feed(&oversized);
        assert!(frames.is_empty());

        let small = frame(b"after-overflow");
        let frames = deframer.feed(&small);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], b"after-overflow");
    }
}
