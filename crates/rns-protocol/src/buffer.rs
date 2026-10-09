use std::collections::VecDeque;

use crate::compression;
use crate::stream_data::{STREAM_ID_MAX, StreamDataMessage};

/// Upper bound on a single chunk before the writer splits (16 KiB).
pub const MAX_CHUNK_LEN: usize = 16384;

/// Number of progressively smaller segments the writer will try when
/// compressing a chunk before giving up and sending it uncompressed.
pub const COMPRESSION_TRIES: usize = 4;

/// Accumulates inbound [`StreamDataMessage`] payloads into a byte queue and
/// tracks explicit EOF.
pub struct StreamReader {
    stream_id: u16,
    buffer: VecDeque<u8>,
    eof: bool,
}

impl StreamReader {
    pub fn new(stream_id: u16) -> Self {
        Self {
            stream_id: stream_id & STREAM_ID_MAX,
            buffer: VecDeque::new(),
            eof: false,
        }
    }

    /// Append `msg` to the buffer. Returns `false` (and ignores the payload)
    /// if the message belongs to a different stream.
    pub fn feed(&mut self, msg: &StreamDataMessage) -> bool {
        if msg.stream_id != self.stream_id {
            return false;
        }

        if !msg.data.is_empty() {
            self.buffer.extend(&msg.data);
        }

        if msg.eof {
            self.eof = true;
        }

        true
    }

    /// Pop up to `size` bytes off the front of the buffer.
    ///
    /// Returns `None` when the buffer is empty and EOF has not yet arrived,
    /// and `Some(Vec::new())` once it has — letting callers distinguish "wait"
    /// from "end of stream".
    pub fn read(&mut self, size: usize) -> Option<Vec<u8>> {
        if self.buffer.is_empty() {
            if self.eof {
                return Some(Vec::new());
            }
            return None;
        }

        let n = size.min(self.buffer.len());
        let data: Vec<u8> = self.buffer.drain(..n).collect();
        Some(data)
    }

    /// Drain the entire buffer. Same empty/`None` semantics as [`Self::read`].
    pub fn read_all(&mut self) -> Option<Vec<u8>> {
        if self.buffer.is_empty() {
            if self.eof {
                return Some(Vec::new());
            }
            return None;
        }
        let data: Vec<u8> = self.buffer.drain(..).collect();
        Some(data)
    }

    pub fn available(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_eof(&self) -> bool {
        self.eof
    }

    /// True once EOF has been received *and* all buffered data has been drained.
    pub fn is_done(&self) -> bool {
        self.eof && self.buffer.is_empty()
    }
}

/// Chunks outbound bytes into [`StreamDataMessage`]s sized for the underlying
/// channel, opportunistically compressing each chunk with bzip2.
pub struct StreamWriter {
    stream_id: u16,
    max_data_len: usize,
    closed: bool,
}

impl StreamWriter {
    pub fn new(stream_id: u16, max_data_len: usize) -> Self {
        Self {
            stream_id: stream_id & STREAM_ID_MAX,
            max_data_len,
            closed: false,
        }
    }

    /// Slice `data` into channel-sized frames. Each frame is sent compressed
    /// if bzip2 would fit a larger source segment into `max_data_len` than the
    /// uncompressed alternative; otherwise the chunk is sent raw.
    pub fn write(&mut self, data: &[u8]) -> Result<Vec<StreamDataMessage>, BufferError> {
        if self.closed {
            return Err(BufferError::WriterClosed);
        }

        if data.is_empty() {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let remaining = &data[offset..];

            let chunk_len = remaining.len().min(MAX_CHUNK_LEN);
            let chunk = &remaining[..chunk_len];

            let (msg_data, consumed, compressed) = self.try_compress_chunk(chunk);

            let mut msg = StreamDataMessage::new(self.stream_id, msg_data, false);
            msg.compressed = compressed;
            messages.push(msg);
            offset += consumed;
        }

        Ok(messages)
    }

    /// Compress `chunk` at progressively smaller prefixes (chunk/1, chunk/2, …)
    /// until the bzip2 output fits within `max_data_len` and is actually
    /// shorter than the source, returning the first match. Falls back to a raw
    /// send when no prefix benefits from compression.
    fn try_compress_chunk(&self, chunk: &[u8]) -> (Vec<u8>, usize, bool) {
        if chunk.len() <= 32 {
            // bzip2 overhead dominates for very small inputs.
            let send_len = chunk.len().min(self.max_data_len);
            return (chunk[..send_len].to_vec(), send_len, false);
        }

        for comp_try in 1..COMPRESSION_TRIES {
            let segment_len = chunk.len() / comp_try;
            if segment_len <= 32 {
                break;
            }
            if let Ok(compressed) = compression::bz2_compress(&chunk[..segment_len])
                && compressed.len() < self.max_data_len
                && compressed.len() < segment_len
            {
                return (compressed, segment_len, true);
            }
        }

        let send_len = chunk.len().min(self.max_data_len);
        (chunk[..send_len].to_vec(), send_len, false)
    }

    /// Close the writer and return the EOF frame paired with a drain contract:
    /// the caller must ensure every message produced by prior `write()` calls
    /// has been sent (and acknowledged) before transmitting `eof_message`.
    pub fn close(&mut self) -> DrainClose {
        self.closed = true;
        DrainClose {
            eof_message: StreamDataMessage::new(self.stream_id, Vec::new(), true),
        }
    }

    /// Close the writer and return a bare EOF frame. Use when the caller
    /// already manages ordering with the underlying channel.
    pub fn close_simple(&mut self) -> StreamDataMessage {
        self.closed = true;
        StreamDataMessage::new(self.stream_id, Vec::new(), true)
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

/// EOF frame handed back by [`StreamWriter::close`]. Must be sent only after
/// every earlier frame produced by the writer has been delivered.
pub struct DrainClose {
    pub eof_message: StreamDataMessage,
}

#[derive(Debug, thiserror::Error)]
pub enum BufferError {
    #[error("writer is closed")]
    WriterClosed,
}

/// Bidirectional convenience wrapper that pairs a [`StreamWriter`] and
/// [`StreamReader`] on the same stream ID.
pub struct ChannelBuffer {
    writer: StreamWriter,
    reader: StreamReader,
    stream_id: u16,
}

impl ChannelBuffer {
    pub fn new(stream_id: u16, max_data_len: usize) -> Self {
        Self {
            writer: StreamWriter::new(stream_id, max_data_len),
            reader: StreamReader::new(stream_id),
            stream_id,
        }
    }

    pub fn write(&mut self, data: &[u8]) -> Result<Vec<StreamDataMessage>, BufferError> {
        self.writer.write(data)
    }

    /// Close the write side, returning a bare EOF frame. Send after prior
    /// write output has flowed through the channel.
    pub fn close_writer(&mut self) -> StreamDataMessage {
        self.writer.close_simple()
    }

    /// Close the write side with the stricter drain contract — see
    /// [`StreamWriter::close`].
    pub fn drain_and_close_writer(&mut self) -> DrainClose {
        self.writer.close()
    }

    pub fn feed_reader(&mut self, msg: &StreamDataMessage) -> bool {
        self.reader.feed(msg)
    }

    pub fn read(&mut self, size: usize) -> Option<Vec<u8>> {
        self.reader.read(size)
    }

    pub fn read_all(&mut self) -> Option<Vec<u8>> {
        self.reader.read_all()
    }

    pub fn is_done(&self) -> bool {
        self.reader.is_done()
    }

    pub fn is_writer_closed(&self) -> bool {
        self.writer.is_closed()
    }

    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }

    pub fn available(&self) -> usize {
        self.reader.available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reader_basic() {
        let mut reader = StreamReader::new(1);
        assert!(!reader.is_eof());
        assert!(reader.read(100).is_none());

        let msg = StreamDataMessage::new(1, b"hello".to_vec(), false);
        assert!(reader.feed(&msg));
        assert_eq!(reader.available(), 5);

        let data = reader.read(3).unwrap();
        assert_eq!(data, b"hel");
        assert_eq!(reader.available(), 2);
    }

    #[test]
    fn test_reader_eof() {
        let mut reader = StreamReader::new(1);

        let msg1 = StreamDataMessage::new(1, b"data".to_vec(), false);
        reader.feed(&msg1);

        let msg2 = StreamDataMessage::new(1, Vec::new(), true);
        reader.feed(&msg2);

        assert!(reader.is_eof());
        let data = reader.read(100).unwrap();
        assert_eq!(data, b"data");

        // Once the buffer is drained, further reads must yield an explicit EOF marker.
        let eof = reader.read(100).unwrap();
        assert!(eof.is_empty());
        assert!(reader.is_done());
    }

    #[test]
    fn test_reader_wrong_stream() {
        let mut reader = StreamReader::new(1);
        let msg = StreamDataMessage::new(2, b"wrong".to_vec(), false);
        assert!(!reader.feed(&msg));
        assert_eq!(reader.available(), 0);
    }

    #[test]
    fn test_writer_basic() {
        let mut writer = StreamWriter::new(1, 10);

        let msgs = writer.write(b"hello world, this is a test").unwrap();
        // 27-byte input split at 10 bytes per frame must produce multiple messages.
        assert!(msgs.len() >= 2);

        for msg in &msgs {
            assert_eq!(msg.stream_id, 1);
            assert!(!msg.eof);
        }
    }

    #[test]
    fn test_writer_close() {
        let mut writer = StreamWriter::new(1, 100);
        let drain = writer.close();
        assert!(drain.eof_message.eof);
        assert!(drain.eof_message.data.is_empty());
        assert!(writer.is_closed());
        assert!(writer.write(b"after close").is_err());
    }

    #[test]
    fn test_writer_close_simple() {
        let mut writer = StreamWriter::new(1, 100);
        let eof_msg = writer.close_simple();
        assert!(eof_msg.eof);
        assert!(eof_msg.data.is_empty());
        assert!(writer.is_closed());
    }

    #[test]
    fn test_roundtrip() {
        let mut writer = StreamWriter::new(42, 50);
        let mut reader = StreamReader::new(42);

        let data = b"Hello, this is a complete stream test with some data!";
        let msgs = writer.write(data).unwrap();
        let eof = writer.close_simple();

        for msg in &msgs {
            reader.feed(msg);
        }
        reader.feed(&eof);

        let received = reader.read_all().unwrap();
        assert_eq!(received, data);
        assert!(reader.is_eof());
    }

    #[test]
    fn test_writer_compression_roundtrip() {
        // Decompression lives in StreamDataMessage::unpack, so the roundtrip must
        // go through pack/unpack — feeding the writer's output directly would skip it.
        use crate::channel_message::MessageBase;

        let mut writer = StreamWriter::new(1, 500);
        let mut reader = StreamReader::new(1);

        let data = b"AAAA".repeat(500);
        let msgs = writer.write(&data).unwrap();

        let any_compressed = msgs.iter().any(|m| m.compressed);
        assert!(any_compressed, "Expected at least one compressed message");

        for msg in &msgs {
            let packed = msg.pack();
            let mut received_msg = StreamDataMessage::new(0, Vec::new(), false);
            received_msg.unpack(&packed).unwrap();
            reader.feed(&received_msg);
        }

        let received = reader.read_all().unwrap();
        assert_eq!(received, data);
    }

    #[test]
    fn test_writer_small_data_no_compression() {
        // bzip2 overhead dominates below 32 bytes, so short inputs must be sent raw.
        let mut writer = StreamWriter::new(1, 500);

        let data = b"tiny";
        let msgs = writer.write(data).unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(!msgs[0].compressed);
        assert_eq!(msgs[0].data, b"tiny");
    }

    #[test]
    fn test_writer_empty_write() {
        let mut writer = StreamWriter::new(1, 100);
        let msgs = writer.write(b"").unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn test_drain_close_semantics() {
        let mut writer = StreamWriter::new(1, 100);
        let _msgs = writer.write(b"some data").unwrap();
        let drain = writer.close();
        assert!(drain.eof_message.eof);
        assert!(drain.eof_message.data.is_empty());
    }

    #[test]
    fn test_channel_buffer_write_read() {
        let stream_id = 7;
        let mut buf = ChannelBuffer::new(stream_id, 100);

        assert_eq!(buf.stream_id(), 7);
        assert!(!buf.is_done());
        assert!(!buf.is_writer_closed());

        let msgs = buf.write(b"hello buffer").unwrap();
        assert!(!msgs.is_empty());

        for msg in &msgs {
            assert!(buf.feed_reader(msg));
        }

        assert_eq!(buf.available(), 12);

        let data = buf.read_all().unwrap();
        assert_eq!(data, b"hello buffer");
    }

    #[test]
    fn test_channel_buffer_roundtrip() {
        let mut buf = ChannelBuffer::new(99, 20);

        let input = b"This is a channel buffer roundtrip test with enough data to split";
        let msgs = buf.write(input).unwrap();
        let eof_msg = buf.close_writer();
        assert!(buf.is_writer_closed());

        for msg in &msgs {
            buf.feed_reader(msg);
        }
        buf.feed_reader(&eof_msg);

        let output = buf.read_all().unwrap();
        assert_eq!(output, input);
        assert!(buf.is_done());
    }

    #[test]
    fn test_channel_buffer_partial_read() {
        let mut buf = ChannelBuffer::new(5, 100);

        let msgs = buf.write(b"abcdefghij").unwrap();
        for msg in &msgs {
            buf.feed_reader(msg);
        }

        let partial = buf.read(5).unwrap();
        assert_eq!(partial, b"abcde");
        assert_eq!(buf.available(), 5);

        let rest = buf.read_all().unwrap();
        assert_eq!(rest, b"fghij");
    }

    #[test]
    fn test_channel_buffer_no_data() {
        // Reads before any frames arrive must distinguish "wait" (None) from EOF.
        let mut buf = ChannelBuffer::new(1, 100);
        assert!(buf.read(10).is_none());
        assert!(buf.read_all().is_none());
    }

    #[test]
    fn test_channel_buffer_close_then_write_fails() {
        let mut buf = ChannelBuffer::new(1, 100);
        buf.close_writer();
        assert!(buf.write(b"after close").is_err());
    }

    #[test]
    fn test_channel_buffer_drain_and_close() {
        let mut buf = ChannelBuffer::new(1, 100);
        let _msgs = buf.write(b"data to drain").unwrap();
        let drain = buf.drain_and_close_writer();
        assert!(drain.eof_message.eof);
        assert!(buf.is_writer_closed());
    }
}
