//! Async byte streams carried by a reliable Reticulum Link channel.
//!
//! The protocol framing and compression live in `rns-protocol`; this module
//! wires them to the actor-owned [`LinkSessionChannelHandle`] and presents
//! Tokio [`AsyncRead`] / [`AsyncWrite`] implementations.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use rns_protocol::buffer::{MAX_CHUNK_LEN, StreamReader, StreamWriter};
use rns_protocol::channel::ChannelError;
use rns_protocol::channel_message::{MessageBase, SMT_STREAM_DATA};
use rns_protocol::stream_data::{STREAM_ID_MAX, StreamDataMessage};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::link_session::{LinkSessionChannelError, LinkSessionChannelHandle};

/// Maximum unread data retained by the default channel Buffer reader.
pub const DEFAULT_READER_CAPACITY: usize = 1024 * 1024;

/// Maximum time an orderly writer shutdown waits for channel headroom.
pub const DEFAULT_CLOSE_TIMEOUT: Duration = Duration::from_secs(15);

const CHANNEL_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const STREAM_HEADER_LEN: usize = 2;

type IoFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'static>>;

#[derive(Debug, thiserror::Error)]
pub enum LinkSessionBufferError {
    #[error("stream id {0} exceeds the 14-bit Buffer stream-id range")]
    InvalidStreamId(u16),
    #[error("reader capacity must be greater than zero")]
    InvalidReaderCapacity,
    #[error("channel MDU {0} is too small for a Buffer frame")]
    ChannelMduTooSmall(usize),
    #[error(transparent)]
    Channel(#[from] LinkSessionChannelError),
}

#[derive(Debug, Clone, Copy)]
enum ReaderFailure {
    InvalidFrame,
    CapacityExceeded,
}

impl ReaderFailure {
    fn into_io_error(self) -> io::Error {
        match self {
            Self::InvalidFrame => {
                io::Error::new(io::ErrorKind::InvalidData, "invalid channel Buffer frame")
            }
            Self::CapacityExceeded => io::Error::new(
                io::ErrorKind::OutOfMemory,
                "channel Buffer reader capacity exceeded",
            ),
        }
    }
}

struct ReaderState {
    stream_id: u16,
    reader: StreamReader,
    capacity: usize,
    failure: Option<ReaderFailure>,
    closed: bool,
    waker: Option<Waker>,
}

impl ReaderState {
    fn wake(&mut self) -> Option<Waker> {
        self.waker.take()
    }

    fn remember_waker(&mut self, waker: &Waker) {
        if self
            .waker
            .as_ref()
            .is_none_or(|current| !current.will_wake(waker))
        {
            self.waker = Some(waker.clone());
        }
    }
}

/// Read half of a channel-backed Reticulum Buffer stream.
///
/// Dropping the reader performs best-effort handler deregistration. Call
/// [`Self::close`] when deterministic deregistration is required.
pub struct LinkSessionBufferReader {
    channel: LinkSessionChannelHandle,
    handler_id: Option<rns_protocol::channel::HandlerId>,
    state: Arc<Mutex<ReaderState>>,
}

impl LinkSessionBufferReader {
    pub fn stream_id(&self) -> u16 {
        self.state.lock().map(|state| state.stream_id).unwrap_or(0)
    }

    pub fn available(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.reader.available())
            .unwrap_or(0)
    }

    pub fn is_eof(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.reader.is_eof() || state.closed)
            .unwrap_or(true)
    }

    pub async fn close(&mut self) -> Result<(), LinkSessionBufferError> {
        mark_reader_closed(&self.state);
        if let Some(handler_id) = self.handler_id.take() {
            let _ = self.channel.remove_message_handler(handler_id).await?;
        }
        Ok(())
    }
}

impl AsyncRead for LinkSessionBufferReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return Poll::Ready(Err(io::Error::other(
                    "channel Buffer reader state is poisoned",
                )));
            }
        };

        if let Some(failure) = state.failure {
            return Poll::Ready(Err(failure.into_io_error()));
        }

        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if let Some(data) = state.reader.read(buffer.remaining()) {
            buffer.put_slice(&data);
            return Poll::Ready(Ok(()));
        }

        if state.closed || state.reader.is_done() {
            return Poll::Ready(Ok(()));
        }

        state.remember_waker(cx.waker());
        Poll::Pending
    }
}

impl Drop for LinkSessionBufferReader {
    fn drop(&mut self) {
        mark_reader_closed(&self.state);
        if let Some(handler_id) = self.handler_id.take() {
            self.channel.try_remove_message_handler(handler_id);
        }
    }
}

enum WriterState {
    Open,
    Sending { accepted: usize, future: IoFuture },
    Closing { future: IoFuture },
    Closed,
    Failed(String),
}

/// Write half of a channel-backed Reticulum Buffer stream.
///
/// Writes are split and compressed by the protocol layer. Shutdown queues EOF
/// only after all earlier writer frames have entered the reliable channel
/// sequence and the channel has headroom for EOF.
pub struct LinkSessionBufferWriter {
    channel: LinkSessionChannelHandle,
    writer: StreamWriter,
    state: WriterState,
    close_timeout: Duration,
}

impl LinkSessionBufferWriter {
    pub fn with_close_timeout(mut self, timeout: Duration) -> Self {
        self.close_timeout = timeout;
        self
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.state, WriterState::Closed)
    }

    fn start_write(&mut self, data: &[u8]) -> io::Result<usize> {
        let accepted = data.len().min(MAX_CHUNK_LEN);
        let messages = self
            .writer
            .write(&data[..accepted])
            .map_err(io::Error::other)?;
        self.state = WriterState::Sending {
            accepted,
            future: send_messages(self.channel.clone(), messages),
        };
        Ok(accepted)
    }
}

impl AsyncWrite for LinkSessionBufferWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                WriterState::Open => {
                    if buffer.is_empty() {
                        return Poll::Ready(Ok(0));
                    }
                    if let Err(error) = this.start_write(buffer) {
                        return Poll::Ready(Err(error));
                    }
                }
                WriterState::Sending { accepted, future } => {
                    let accepted = *accepted;
                    match future.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => {
                            this.state = WriterState::Open;
                            return Poll::Ready(Ok(accepted));
                        }
                        Poll::Ready(Err(error)) => {
                            let message = error.to_string();
                            this.state = WriterState::Failed(message);
                            return Poll::Ready(Err(error));
                        }
                    }
                }
                WriterState::Closing { .. } | WriterState::Closed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "channel Buffer writer is closed",
                    )));
                }
                WriterState::Failed(message) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        message.clone(),
                    )));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                WriterState::Sending { future, .. } => match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => this.state = WriterState::Open,
                    Poll::Ready(Err(error)) => {
                        let message = error.to_string();
                        this.state = WriterState::Failed(message);
                        return Poll::Ready(Err(error));
                    }
                },
                WriterState::Open | WriterState::Closed => return Poll::Ready(Ok(())),
                WriterState::Closing { future } => match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => {
                        this.state = WriterState::Closed;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(error)) => {
                        let message = error.to_string();
                        this.state = WriterState::Failed(message);
                        return Poll::Ready(Err(error));
                    }
                },
                WriterState::Failed(message) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        message.clone(),
                    )));
                }
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                WriterState::Sending { future, .. } => match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => this.state = WriterState::Open,
                    Poll::Ready(Err(error)) => {
                        let message = error.to_string();
                        this.state = WriterState::Failed(message);
                        return Poll::Ready(Err(error));
                    }
                },
                WriterState::Open => {
                    let eof = this.writer.close_simple();
                    this.state = WriterState::Closing {
                        future: drain_then_send_eof(this.channel.clone(), eof, this.close_timeout),
                    };
                }
                WriterState::Closing { future } => match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => {
                        this.state = WriterState::Closed;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(error)) => {
                        let message = error.to_string();
                        this.state = WriterState::Failed(message);
                        return Poll::Ready(Err(error));
                    }
                },
                WriterState::Closed => return Poll::Ready(Ok(())),
                WriterState::Failed(message) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        message.clone(),
                    )));
                }
            }
        }
    }
}

/// Bidirectional channel Buffer with independent receive and send stream IDs.
pub struct LinkSessionBuffer {
    reader: LinkSessionBufferReader,
    writer: LinkSessionBufferWriter,
}

impl LinkSessionBuffer {
    pub fn reader(&self) -> &LinkSessionBufferReader {
        &self.reader
    }

    pub fn writer(&self) -> &LinkSessionBufferWriter {
        &self.writer
    }

    pub async fn close_reader(&mut self) -> Result<(), LinkSessionBufferError> {
        self.reader.close().await
    }

    pub fn into_split(self) -> (LinkSessionBufferReader, LinkSessionBufferWriter) {
        (self.reader, self.writer)
    }
}

impl AsyncRead for LinkSessionBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buffer)
    }
}

impl AsyncWrite for LinkSessionBuffer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

impl LinkSessionChannelHandle {
    pub async fn create_reader(
        &self,
        stream_id: u16,
    ) -> Result<LinkSessionBufferReader, LinkSessionBufferError> {
        self.create_reader_with_capacity(stream_id, DEFAULT_READER_CAPACITY)
            .await
    }

    pub async fn create_reader_with_capacity(
        &self,
        stream_id: u16,
        capacity: usize,
    ) -> Result<LinkSessionBufferReader, LinkSessionBufferError> {
        validate_stream_id(stream_id)?;
        if capacity == 0 {
            return Err(LinkSessionBufferError::InvalidReaderCapacity);
        }

        self.register_system_type(SMT_STREAM_DATA).await?;
        let state = Arc::new(Mutex::new(ReaderState {
            stream_id,
            reader: StreamReader::new(stream_id),
            capacity,
            failure: None,
            closed: false,
            waker: None,
        }));
        let weak_state = Arc::downgrade(&state);
        let handler_id = self
            .add_message_handler(move |msg_type, payload| {
                handle_stream_message(&weak_state, stream_id, msg_type, payload)
            })
            .await?;

        Ok(LinkSessionBufferReader {
            channel: self.clone(),
            handler_id: Some(handler_id),
            state,
        })
    }

    pub fn create_writer(
        &self,
        stream_id: u16,
    ) -> Result<LinkSessionBufferWriter, LinkSessionBufferError> {
        validate_stream_id(stream_id)?;
        let max_data_len = self.mdu().saturating_sub(STREAM_HEADER_LEN);
        if max_data_len == 0 {
            return Err(LinkSessionBufferError::ChannelMduTooSmall(self.mdu()));
        }
        Ok(LinkSessionBufferWriter {
            channel: self.clone(),
            writer: StreamWriter::new(stream_id, max_data_len),
            state: WriterState::Open,
            close_timeout: DEFAULT_CLOSE_TIMEOUT,
        })
    }

    pub async fn create_bidirectional_buffer(
        &self,
        receive_stream_id: u16,
        send_stream_id: u16,
    ) -> Result<LinkSessionBuffer, LinkSessionBufferError> {
        validate_stream_id(receive_stream_id)?;
        validate_stream_id(send_stream_id)?;
        let reader = self.create_reader(receive_stream_id).await?;
        let writer = self.create_writer(send_stream_id)?;
        Ok(LinkSessionBuffer { reader, writer })
    }
}

fn validate_stream_id(stream_id: u16) -> Result<(), LinkSessionBufferError> {
    if stream_id > STREAM_ID_MAX {
        return Err(LinkSessionBufferError::InvalidStreamId(stream_id));
    }
    Ok(())
}

fn mark_reader_closed(state: &Arc<Mutex<ReaderState>>) {
    let wake = state.lock().ok().and_then(|mut state| {
        state.closed = true;
        state.wake()
    });
    if let Some(waker) = wake {
        waker.wake();
    }
}

fn handle_stream_message(
    weak_state: &Weak<Mutex<ReaderState>>,
    stream_id: u16,
    msg_type: u16,
    payload: &[u8],
) -> bool {
    if msg_type != SMT_STREAM_DATA || payload.len() < STREAM_HEADER_LEN {
        return false;
    }
    let encoded_stream_id = u16::from_be_bytes([payload[0], payload[1]]) & STREAM_ID_MAX;
    if encoded_stream_id != stream_id {
        return false;
    }
    let Some(state) = weak_state.upgrade() else {
        return false;
    };

    let mut message = StreamDataMessage::new(0, Vec::new(), false);
    let decoded = message.unpack(payload);
    let wake = match state.lock() {
        Ok(mut state) => {
            if state.closed {
                return false;
            }
            if state.failure.is_some() {
                return true;
            } else if decoded.is_err() {
                state.failure = Some(ReaderFailure::InvalidFrame);
            } else if message.data.len() > state.capacity.saturating_sub(state.reader.available()) {
                state.failure = Some(ReaderFailure::CapacityExceeded);
            } else {
                state.reader.feed(&message);
            }
            state.wake()
        }
        Err(_) => return true,
    };
    if let Some(waker) = wake {
        waker.wake();
    }
    true
}

fn send_messages(channel: LinkSessionChannelHandle, messages: Vec<StreamDataMessage>) -> IoFuture {
    Box::pin(async move {
        for message in messages {
            let msg_type = message.msg_type();
            let payload = message.pack();
            loop {
                match channel.send_raw(msg_type, payload.clone()).await {
                    Ok(_) => break,
                    Err(LinkSessionChannelError::Channel(ChannelError::NotReady)) => {
                        tokio::time::sleep(CHANNEL_RETRY_INTERVAL).await;
                    }
                    Err(error) => return Err(io::Error::other(error)),
                }
            }
        }
        Ok(())
    })
}

fn drain_then_send_eof(
    channel: LinkSessionChannelHandle,
    eof: StreamDataMessage,
    close_timeout: Duration,
) -> IoFuture {
    Box::pin(async move {
        tokio::time::timeout(close_timeout, send_messages(channel, vec![eof]))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out draining channel Buffer writer",
                )
            })?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader_state(stream_id: u16, capacity: usize) -> Arc<Mutex<ReaderState>> {
        Arc::new(Mutex::new(ReaderState {
            stream_id,
            reader: StreamReader::new(stream_id),
            capacity,
            failure: None,
            closed: false,
            waker: None,
        }))
    }

    #[test]
    fn handler_routes_only_the_matching_stream() {
        let state = reader_state(7, 128);
        let weak = Arc::downgrade(&state);

        let wrong = StreamDataMessage::new(8, b"wrong".to_vec(), false).pack();
        assert!(!handle_stream_message(&weak, 7, SMT_STREAM_DATA, &wrong));
        assert_eq!(state.lock().unwrap().reader.available(), 0);

        let matching = StreamDataMessage::new(7, b"hello".to_vec(), true).pack();
        assert!(handle_stream_message(&weak, 7, SMT_STREAM_DATA, &matching));
        let mut state = state.lock().unwrap();
        assert_eq!(state.reader.read_all().unwrap(), b"hello");
        assert!(state.reader.is_done());
    }

    #[test]
    fn handler_fails_closed_at_reader_capacity() {
        let state = reader_state(1, 4);
        let weak = Arc::downgrade(&state);
        let oversized = StreamDataMessage::new(1, b"12345".to_vec(), false).pack();

        assert!(handle_stream_message(&weak, 1, SMT_STREAM_DATA, &oversized));
        let state = state.lock().unwrap();
        assert!(matches!(
            state.failure,
            Some(ReaderFailure::CapacityExceeded)
        ));
        assert_eq!(state.reader.available(), 0);
    }

    #[test]
    fn handler_reports_invalid_compressed_payload() {
        let state = reader_state(2, 128);
        let weak = Arc::downgrade(&state);
        let mut malformed = (0x4000_u16 | 2).to_be_bytes().to_vec();
        malformed.extend_from_slice(b"not bzip2");

        assert!(handle_stream_message(&weak, 2, SMT_STREAM_DATA, &malformed));
        assert!(matches!(
            state.lock().unwrap().failure,
            Some(ReaderFailure::InvalidFrame)
        ));
    }

    #[test]
    fn validates_the_full_stream_id_range() {
        assert!(validate_stream_id(STREAM_ID_MAX).is_ok());
        assert!(matches!(
            validate_stream_id(STREAM_ID_MAX + 1),
            Err(LinkSessionBufferError::InvalidStreamId(_))
        ));
    }
}
