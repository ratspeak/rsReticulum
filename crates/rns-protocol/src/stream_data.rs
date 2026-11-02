use crate::buffer::MAX_CHUNK_LEN;
use crate::channel_message::{ChannelMessageError, MessageBase, SMT_STREAM_DATA};
use crate::compression;

/// Maximum stream ID value (14 bits).
pub const STREAM_ID_MAX: u16 = 0x3FFF;

/// StreamDataMessage overhead: 2-byte header + 6-byte channel envelope = 8 bytes.
pub const OVERHEAD: usize = 8;

/// Stream frame for the Buffer protocol.
///
/// Wire layout (two-byte big-endian header followed by payload):
/// - bit 15: EOF
/// - bit 14: bzip2-compressed payload
/// - bits 13..0: stream ID (`0..=16_383`)
///
/// `MessageBase::unpack` decompresses into `data` but retains the received
/// `compressed` flag. `pack` only serializes the fields; before repacking a
/// decoded compressed frame, clear the flag or recompress its data.
#[derive(Debug, Clone)]
pub struct StreamDataMessage {
    pub stream_id: u16,
    pub eof: bool,
    pub compressed: bool,
    pub data: Vec<u8>,
}

impl StreamDataMessage {
    pub fn new(stream_id: u16, data: Vec<u8>, eof: bool) -> Self {
        Self {
            stream_id: stream_id & STREAM_ID_MAX,
            eof,
            compressed: false,
            data,
        }
    }

    fn header_value(&self) -> u16 {
        let mut val = self.stream_id & STREAM_ID_MAX;
        if self.eof {
            val |= 0x8000;
        }
        if self.compressed {
            val |= 0x4000;
        }
        val
    }

    fn parse_header(val: u16) -> (u16, bool, bool) {
        let eof = (val & 0x8000) != 0;
        let compressed = (val & 0x4000) != 0;
        let stream_id = val & STREAM_ID_MAX;
        (stream_id, eof, compressed)
    }
}

impl MessageBase for StreamDataMessage {
    fn msg_type(&self) -> u16 {
        SMT_STREAM_DATA
    }

    fn pack(&self) -> Vec<u8> {
        let header = self.header_value();
        let header_bytes = header.to_be_bytes();
        let mut result = Vec::with_capacity(2 + self.data.len());
        result.extend_from_slice(&header_bytes);
        result.extend_from_slice(&self.data);
        result
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
        if raw.len() < 2 {
            return Err(ChannelMessageError::TooShort);
        }

        let header_val = u16::from_be_bytes([raw[0], raw[1]]);
        let (stream_id, eof, compressed) = Self::parse_header(header_val);

        self.stream_id = stream_id;
        self.eof = eof;
        self.compressed = compressed;

        let payload = &raw[2..];
        if compressed && !payload.is_empty() {
            // Mirror Python `Buffer.py:96`: cap decompression at MAX_CHUNK_LEN
            // (16 KiB) so a malicious peer can't expand a tiny bz2 payload into
            // a large allocation. The streaming hard-cap in `bz2_decompress`
            // returns an error rather than completing the allocation.
            self.data = compression::bz2_decompress(payload, MAX_CHUNK_LEN)
                .map_err(|_| ChannelMessageError::UnpackFailed)?;
        } else {
            self.data = payload.to_vec();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_roundtrip() {
        let msg = StreamDataMessage::new(42, b"hello stream".to_vec(), false);
        let packed = msg.pack();

        let mut msg2 = StreamDataMessage::new(0, Vec::new(), false);
        msg2.unpack(&packed).unwrap();

        assert_eq!(msg2.stream_id, 42);
        assert!(!msg2.eof);
        assert!(!msg2.compressed);
        assert_eq!(msg2.data, b"hello stream");
    }

    #[test]
    fn test_eof_flag() {
        let msg = StreamDataMessage::new(1, Vec::new(), true);
        let packed = msg.pack();

        let mut msg2 = StreamDataMessage::new(0, Vec::new(), false);
        msg2.unpack(&packed).unwrap();

        assert!(msg2.eof);
        assert_eq!(msg2.stream_id, 1);
    }

    #[test]
    fn test_stream_id_mask() {
        // IDs above 14 bits must wrap, not overflow into the flag bits.
        let msg = StreamDataMessage::new(0xFFFF, b"test".to_vec(), false);
        assert_eq!(msg.stream_id, STREAM_ID_MAX);
    }

    #[test]
    fn test_header_bits() {
        let msg = StreamDataMessage {
            stream_id: 100,
            eof: true,
            compressed: true,
            data: Vec::new(),
        };
        let packed = msg.pack();
        let header = u16::from_be_bytes([packed[0], packed[1]]);
        assert_eq!(header & 0x3FFF, 100);
        assert!(header & 0x8000 != 0);
        assert!(header & 0x4000 != 0);
    }

    #[test]
    fn test_too_short() {
        let mut msg = StreamDataMessage::new(0, Vec::new(), false);
        assert!(msg.unpack(&[0x00]).is_err());
    }

    /// Regression for A2026-04.P-01: Buffer-protocol decompression must cap at
    /// `MAX_CHUNK_LEN` (16 KiB), matching Python `Buffer.py:96`. A bz2 payload
    /// that decompresses past that bound is a compression-bomb attack and must
    /// be rejected rather than amplified into a large allocation.
    #[test]
    fn test_decompression_bounded_at_max_chunk_len() {
        // Build a payload that bz2-compresses small but expands past the cap.
        let big = vec![0u8; MAX_CHUNK_LEN + 1024];
        let compressed = compression::bz2_compress(&big).expect("compress");
        assert!(
            compressed.len() < big.len(),
            "test premise: compressed < raw"
        );

        // Hand-pack: header with compressed=true, stream_id=1.
        let header_val: u16 = 0x4000 | 0x0001;
        let mut packed = Vec::with_capacity(2 + compressed.len());
        packed.extend_from_slice(&header_val.to_be_bytes());
        packed.extend_from_slice(&compressed);

        let mut msg = StreamDataMessage::new(0, Vec::new(), false);
        let result = msg.unpack(&packed);
        assert!(
            result.is_err(),
            "compressed payload that decompresses past MAX_CHUNK_LEN must be rejected"
        );
    }

    /// Companion: a compressed payload that fits inside `MAX_CHUNK_LEN` after
    /// decompression must round-trip cleanly. Guards against an over-tight bound.
    #[test]
    fn test_decompression_under_bound_succeeds() {
        let small = vec![0u8; MAX_CHUNK_LEN - 256];
        let compressed = compression::bz2_compress(&small).expect("compress");

        let header_val: u16 = 0x4000 | 0x0007;
        let mut packed = Vec::with_capacity(2 + compressed.len());
        packed.extend_from_slice(&header_val.to_be_bytes());
        packed.extend_from_slice(&compressed);

        let mut msg = StreamDataMessage::new(0, Vec::new(), false);
        msg.unpack(&packed)
            .expect("payload within bound must decode");
        assert_eq!(msg.data.len(), small.len());
        assert_eq!(msg.stream_id, 7);
        assert!(msg.compressed);
    }
}
