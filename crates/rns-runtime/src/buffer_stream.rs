//! Async byte streams carried by a reliable Reticulum Link channel, as
//! Python `RNS.Buffer` provides them.
//!
//! The protocol framing and compression live in `rns-protocol`. Streams run
//! on an initiator [`LinkSessionChannelHandle`] or on a responder Link owned
//! by a [`DestinationHandle`], and present Tokio [`AsyncRead`] /
//! [`AsyncWrite`] implementations.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use rns_protocol::buffer::{StreamReader, StreamWriter};
use rns_protocol::channel::{ChannelError, HandlerId};
use rns_protocol::channel_message::{ChannelMessageError, MessageBase, SMT_STREAM_DATA};
use rns_protocol::stream_data::{STREAM_ID_MAX, StreamDataMessage};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use crate::destination_runtime::DestinationHandle;
use crate::link_manager::{ChannelSendError, LinkManagerCommand};
use crate::link_session::{LinkSessionChannelError, LinkSessionChannelHandle};

/// Python `io.DEFAULT_BUFFER_SIZE`, the `BufferedWriter` size `Buffer.create_writer` uses.
pub const WRITER_BUFFER_SIZE: usize = 8192;

const CHANNEL_RETRY_INTERVAL: Duration = Duration::from_millis(10);
/// `RawChannelWriter.close` polls `is_ready_to_send` every 50 ms.
const CLOSE_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// `RawChannelWriter.close` waits 15 s when `rtt * len(tx_ring)` cannot be computed.
const CLOSE_FALLBACK_WAIT: Duration = Duration::from_secs(15);
const STREAM_HEADER_LEN: usize = 2;

type IoFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'static>>;

#[derive(Debug, thiserror::Error)]
pub enum BufferError {
    #[error("stream id {0} exceeds the 14-bit Buffer stream-id range")]
    InvalidStreamId(u16),
    #[error("reader capacity must be greater than zero")]
    InvalidReaderCapacity,
    #[error("channel MDU {0} is too small for a Buffer frame")]
    ChannelMduTooSmall(usize),
    #[error(transparent)]
    Session(#[from] LinkSessionChannelError),
    #[error(transparent)]
    Link(#[from] ChannelSendError),
    #[error("destination manager is no longer available")]
    ManagerUnavailable,
}

/// The Channel a stream runs on.
#[derive(Clone)]
enum StreamChannel {
    Session(LinkSessionChannelHandle),
    Link {
        command_tx: mpsc::Sender<LinkManagerCommand>,
        link_id: [u8; 16],
    },
}

enum SendOutcome {
    Sent,
    NotReady,
    Failed(io::Error),
}

struct StreamFrame(Vec<u8>);

impl MessageBase for StreamFrame {
    fn msg_type(&self) -> u16 {
        SMT_STREAM_DATA
    }

    fn pack(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
        self.0 = raw.to_vec();
        Ok(())
    }
}

impl StreamChannel {
    /// Open the Channel for stream frames and return its MDU.
    async fn open(&self) -> Result<usize, BufferError> {
        match self {
            Self::Session(channel) => {
                channel.register_system_type(SMT_STREAM_DATA).await?;
                Ok(channel.mdu())
            }
            Self::Link {
                command_tx,
                link_id,
            } => {
                let (result_tx, result_rx) = oneshot::channel();
                command_tx
                    .send(LinkManagerCommand::OpenStreamChannel {
                        link_id: *link_id,
                        result_tx,
                    })
                    .await
                    .map_err(|_| BufferError::ManagerUnavailable)?;
                Ok(result_rx
                    .await
                    .map_err(|_| BufferError::ManagerUnavailable)??)
            }
        }
    }

    async fn add_handler<F>(&self, handler: F) -> Result<HandlerId, BufferError>
    where
        F: Fn(u16, &[u8]) -> bool + Send + 'static,
    {
        match self {
            Self::Session(channel) => Ok(channel.add_message_handler(handler).await?),
            Self::Link {
                command_tx,
                link_id,
            } => {
                let (result_tx, result_rx) = oneshot::channel();
                command_tx
                    .send(LinkManagerCommand::AddChannelHandler {
                        link_id: *link_id,
                        handler: Box::new(handler),
                        result_tx,
                    })
                    .await
                    .map_err(|_| BufferError::ManagerUnavailable)?;
                Ok(result_rx
                    .await
                    .map_err(|_| BufferError::ManagerUnavailable)??)
            }
        }
    }

    async fn remove_handler(&self, id: HandlerId) -> Result<(), BufferError> {
        match self {
            Self::Session(channel) => {
                channel.remove_message_handler(id).await?;
            }
            Self::Link {
                command_tx,
                link_id,
            } => {
                let (result_tx, result_rx) = oneshot::channel();
                command_tx
                    .send(LinkManagerCommand::RemoveChannelHandler {
                        link_id: *link_id,
                        id,
                        result_tx: Some(result_tx),
                    })
                    .await
                    .map_err(|_| BufferError::ManagerUnavailable)?;
                let _ = result_rx.await;
            }
        }
        Ok(())
    }

    fn try_remove_handler(&self, id: HandlerId) {
        match self {
            Self::Session(channel) => channel.try_remove_message_handler(id),
            Self::Link {
                command_tx,
                link_id,
            } => {
                let _ = command_tx.try_send(LinkManagerCommand::RemoveChannelHandler {
                    link_id: *link_id,
                    id,
                    result_tx: None,
                });
            }
        }
    }

    async fn send_frame(&self, payload: Vec<u8>) -> SendOutcome {
        match self {
            Self::Session(channel) => match channel.send_raw(SMT_STREAM_DATA, payload).await {
                Ok(_) => SendOutcome::Sent,
                Err(
                    LinkSessionChannelError::Channel(ChannelError::NotReady)
                    | LinkSessionChannelError::LinkNotActive,
                ) => SendOutcome::NotReady,
                Err(error) => SendOutcome::Failed(io::Error::other(error)),
            },
            Self::Link {
                command_tx,
                link_id,
            } => {
                let (result_tx, result_rx) = oneshot::channel();
                if command_tx
                    .send(LinkManagerCommand::SendChannelMessage {
                        link_id: *link_id,
                        message: Box::new(StreamFrame(payload)),
                        result_tx: Some(result_tx),
                    })
                    .await
                    .is_err()
                {
                    return SendOutcome::Failed(io::Error::other(BufferError::ManagerUnavailable));
                }
                match result_rx.await {
                    Ok(Ok(_)) => SendOutcome::Sent,
                    Ok(Err(
                        ChannelSendError::Channel(ChannelError::NotReady)
                        | ChannelSendError::LinkNotActive
                        | ChannelSendError::TransportUnavailable,
                    )) => SendOutcome::NotReady,
                    Ok(Err(error)) => SendOutcome::Failed(io::Error::other(error)),
                    Err(_) => {
                        SendOutcome::Failed(io::Error::other(BufferError::ManagerUnavailable))
                    }
                }
            }
        }
    }

    /// Channel readiness and `link.rtt * len(tx_ring)`; `None` once the Link is gone.
    async fn close_wait(&self) -> Option<(bool, Duration)> {
        match self {
            Self::Session(channel) => channel.close_wait().await.ok(),
            Self::Link {
                command_tx,
                link_id,
            } => {
                let (result_tx, result_rx) = oneshot::channel();
                command_tx
                    .send(LinkManagerCommand::ChannelCloseWait {
                        link_id: *link_id,
                        result_tx,
                    })
                    .await
                    .ok()?;
                let (ready, wait) = result_rx.await.ok()??;
                Some((
                    ready,
                    Duration::try_from_secs_f64(wait).unwrap_or(CLOSE_FALLBACK_WAIT),
                ))
            }
        }
    }
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
    capacity: Option<usize>,
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
/// Like Python's `RawChannelReader`, unread data is not bounded unless the
/// reader was created with a capacity. Dropping the reader performs
/// best-effort handler deregistration; call [`Self::close`] when
/// deterministic deregistration is required.
pub struct BufferReader {
    channel: StreamChannel,
    handler_id: Option<HandlerId>,
    state: Arc<Mutex<ReaderState>>,
}

impl BufferReader {
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

    pub async fn close(&mut self) -> Result<(), BufferError> {
        mark_reader_closed(&self.state);
        if let Some(handler_id) = self.handler_id.take() {
            self.channel.remove_handler(handler_id).await?;
        }
        Ok(())
    }

    async fn open(
        channel: StreamChannel,
        stream_id: u16,
        capacity: Option<usize>,
    ) -> Result<Self, BufferError> {
        validate_stream_id(stream_id)?;
        if capacity == Some(0) {
            return Err(BufferError::InvalidReaderCapacity);
        }
        channel.open().await?;
        let state = Arc::new(Mutex::new(ReaderState {
            stream_id,
            reader: StreamReader::new(stream_id),
            capacity,
            failure: None,
            closed: false,
            waker: None,
        }));
        let weak_state = Arc::downgrade(&state);
        let handler_id = channel
            .add_handler(move |msg_type, payload| {
                handle_stream_message(&weak_state, stream_id, msg_type, payload)
            })
            .await?;
        Ok(Self {
            channel,
            handler_id: Some(handler_id),
            state,
        })
    }
}

impl AsyncRead for BufferReader {
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

impl Drop for BufferReader {
    fn drop(&mut self) {
        mark_reader_closed(&self.state);
        if let Some(handler_id) = self.handler_id.take() {
            self.channel.try_remove_handler(handler_id);
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

/// Write half of a channel-backed Reticulum Buffer stream: Python
/// `BufferedWriter(RawChannelWriter)`.
///
/// Writes are held in a [`WRITER_BUFFER_SIZE`] buffer and framed, split and
/// compressed when it overflows, on flush and on shutdown. Flush waits for
/// local channel admission, not remote delivery. Shutdown flushes, waits up
/// to `link.rtt * len(tx_ring)` for window headroom and then attempts the
/// EOF frame once; like Python it does not report an EOF the window refused.
pub struct BufferWriter {
    channel: StreamChannel,
    writer: StreamWriter,
    pending: Vec<u8>,
    state: WriterState,
}

impl BufferWriter {
    fn new(
        channel: StreamChannel,
        stream_id: u16,
        channel_mdu: usize,
    ) -> Result<Self, BufferError> {
        validate_stream_id(stream_id)?;
        let max_data_len = channel_mdu.saturating_sub(STREAM_HEADER_LEN);
        if max_data_len == 0 {
            return Err(BufferError::ChannelMduTooSmall(channel_mdu));
        }
        Ok(Self {
            channel,
            writer: StreamWriter::new(stream_id, max_data_len),
            pending: Vec::with_capacity(WRITER_BUFFER_SIZE),
            state: WriterState::Open,
        })
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.state, WriterState::Closed)
    }

    /// Frames `RawChannelWriter.write` sends for `data`, one call per frame.
    fn frames(&mut self, data: &[u8]) -> io::Result<Vec<StreamDataMessage>> {
        let mut frames = Vec::new();
        let mut offset = 0;
        while let Some((frame, consumed)) = self
            .writer
            .write_once(&data[offset..])
            .map_err(io::Error::other)?
        {
            frames.push(frame);
            offset += consumed;
        }
        Ok(frames)
    }

    /// CPython `BufferedWriter.write`: buffer what fits; otherwise flush the
    /// buffer, write directly while more than a buffer remains, and buffer the rest.
    fn start_write(&mut self, data: &[u8]) -> io::Result<Option<usize>> {
        if data.len() <= WRITER_BUFFER_SIZE - self.pending.len() {
            self.pending.extend_from_slice(data);
            return Ok(Some(data.len()));
        }
        let pending = std::mem::take(&mut self.pending);
        let mut frames = self.frames(&pending)?;
        let mut offset = 0;
        while data.len() - offset > WRITER_BUFFER_SIZE {
            let Some((frame, consumed)) = self
                .writer
                .write_once(&data[offset..])
                .map_err(io::Error::other)?
            else {
                break;
            };
            frames.push(frame);
            offset += consumed;
        }
        self.pending.extend_from_slice(&data[offset..]);
        self.state = WriterState::Sending {
            accepted: data.len(),
            future: send_messages(self.channel.clone(), frames),
        };
        Ok(None)
    }

    fn start_flush(&mut self) -> io::Result<()> {
        let pending = std::mem::take(&mut self.pending);
        let frames = self.frames(&pending)?;
        self.state = WriterState::Sending {
            accepted: 0,
            future: send_messages(self.channel.clone(), frames),
        };
        Ok(())
    }

    fn fail(&mut self, error: io::Error) -> io::Error {
        self.state = WriterState::Failed(error.to_string());
        error
    }
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "channel Buffer writer is closed")
}

impl AsyncWrite for BufferWriter {
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
                    match this.start_write(buffer) {
                        Ok(Some(accepted)) => return Poll::Ready(Ok(accepted)),
                        Ok(None) => {}
                        Err(error) => return Poll::Ready(Err(this.fail(error))),
                    }
                }
                WriterState::Sending { accepted, future } => {
                    let accepted = *accepted;
                    match future.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => {
                            this.state = WriterState::Open;
                            if accepted > 0 {
                                return Poll::Ready(Ok(accepted));
                            }
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(this.fail(error))),
                    }
                }
                WriterState::Closing { .. } | WriterState::Closed => {
                    return Poll::Ready(Err(closed_error()));
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
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(this.fail(error))),
                },
                WriterState::Open => {
                    if this.pending.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    if let Err(error) = this.start_flush() {
                        return Poll::Ready(Err(this.fail(error)));
                    }
                }
                WriterState::Closed => return Poll::Ready(Ok(())),
                WriterState::Closing { future } => match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => {
                        this.state = WriterState::Closed;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(this.fail(error))),
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
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(this.fail(error))),
                },
                WriterState::Open => {
                    if !this.pending.is_empty() {
                        if let Err(error) = this.start_flush() {
                            return Poll::Ready(Err(this.fail(error)));
                        }
                        continue;
                    }
                    let eof = this.writer.close_simple().pack();
                    this.state = WriterState::Closing {
                        future: close_stream(this.channel.clone(), eof),
                    };
                }
                WriterState::Closing { future } => match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => {
                        this.state = WriterState::Closed;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(this.fail(error))),
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

/// Bidirectional channel Buffer with independent receive and send stream IDs
/// (Python `BufferedRWPair`).
pub struct BidirectionalBuffer {
    reader: BufferReader,
    writer: BufferWriter,
}

impl BidirectionalBuffer {
    pub fn reader(&self) -> &BufferReader {
        &self.reader
    }

    pub fn writer(&self) -> &BufferWriter {
        &self.writer
    }

    pub async fn close_reader(&mut self) -> Result<(), BufferError> {
        self.reader.close().await
    }

    pub fn into_split(self) -> (BufferReader, BufferWriter) {
        (self.reader, self.writer)
    }
}

impl AsyncRead for BidirectionalBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buffer)
    }
}

impl AsyncWrite for BidirectionalBuffer {
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
    pub async fn create_reader(&self, stream_id: u16) -> Result<BufferReader, BufferError> {
        BufferReader::open(StreamChannel::Session(self.clone()), stream_id, None).await
    }

    /// As [`Self::create_reader`], but fail the stream once more than
    /// `capacity` bytes are unread.
    pub async fn create_reader_with_capacity(
        &self,
        stream_id: u16,
        capacity: usize,
    ) -> Result<BufferReader, BufferError> {
        BufferReader::open(
            StreamChannel::Session(self.clone()),
            stream_id,
            Some(capacity),
        )
        .await
    }

    pub fn create_writer(&self, stream_id: u16) -> Result<BufferWriter, BufferError> {
        BufferWriter::new(StreamChannel::Session(self.clone()), stream_id, self.mdu())
    }

    pub async fn create_bidirectional_buffer(
        &self,
        receive_stream_id: u16,
        send_stream_id: u16,
    ) -> Result<BidirectionalBuffer, BufferError> {
        validate_stream_id(send_stream_id)?;
        let reader = self.create_reader(receive_stream_id).await?;
        let writer = self.create_writer(send_stream_id)?;
        Ok(BidirectionalBuffer { reader, writer })
    }
}

/// Streams on responder Links. Open them when the Link is established: a
/// peer's stream frames are not proved until the Link's Channel is open.
impl DestinationHandle {
    fn stream_channel(&self, link_id: [u8; 16]) -> StreamChannel {
        StreamChannel::Link {
            command_tx: self.command_tx().clone(),
            link_id,
        }
    }

    pub async fn create_reader(
        &self,
        link_id: [u8; 16],
        stream_id: u16,
    ) -> Result<BufferReader, BufferError> {
        BufferReader::open(self.stream_channel(link_id), stream_id, None).await
    }

    /// As [`Self::create_reader`], but fail the stream once more than
    /// `capacity` bytes are unread.
    pub async fn create_reader_with_capacity(
        &self,
        link_id: [u8; 16],
        stream_id: u16,
        capacity: usize,
    ) -> Result<BufferReader, BufferError> {
        BufferReader::open(self.stream_channel(link_id), stream_id, Some(capacity)).await
    }

    pub async fn create_writer(
        &self,
        link_id: [u8; 16],
        stream_id: u16,
    ) -> Result<BufferWriter, BufferError> {
        validate_stream_id(stream_id)?;
        let channel = self.stream_channel(link_id);
        let mdu = channel.open().await?;
        BufferWriter::new(channel, stream_id, mdu)
    }

    pub async fn create_bidirectional_buffer(
        &self,
        link_id: [u8; 16],
        receive_stream_id: u16,
        send_stream_id: u16,
    ) -> Result<BidirectionalBuffer, BufferError> {
        validate_stream_id(send_stream_id)?;
        let reader = self.create_reader(link_id, receive_stream_id).await?;
        let writer = self.create_writer(link_id, send_stream_id).await?;
        Ok(BidirectionalBuffer { reader, writer })
    }
}

fn validate_stream_id(stream_id: u16) -> Result<(), BufferError> {
    if stream_id > STREAM_ID_MAX {
        return Err(BufferError::InvalidStreamId(stream_id));
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
            } else if state.capacity.is_some_and(|capacity| {
                message.data.len() > capacity.saturating_sub(state.reader.available())
            }) {
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

fn send_messages(channel: StreamChannel, messages: Vec<StreamDataMessage>) -> IoFuture {
    Box::pin(async move {
        for message in messages {
            let payload = message.pack();
            loop {
                match channel.send_frame(payload.clone()).await {
                    SendOutcome::Sent => break,
                    SendOutcome::NotReady => tokio::time::sleep(CHANNEL_RETRY_INTERVAL).await,
                    SendOutcome::Failed(error) => return Err(error),
                }
            }
        }
        Ok(())
    })
}

/// Python `RawChannelWriter.close`: wait at most `link.rtt * len(tx_ring)` for
/// window headroom, then attempt the EOF frame once.
fn close_stream(channel: StreamChannel, eof: Vec<u8>) -> IoFuture {
    Box::pin(async move {
        let wait = match channel.close_wait().await {
            Some((_, wait)) => wait,
            None => CLOSE_FALLBACK_WAIT,
        };
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            match channel.close_wait().await {
                Some((false, _)) => tokio::time::sleep(CLOSE_POLL_INTERVAL).await,
                _ => break,
            }
        }
        match channel.send_frame(eof).await {
            SendOutcome::Sent | SendOutcome::NotReady => Ok(()),
            SendOutcome::Failed(error) => Err(error),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader_state(stream_id: u16, capacity: Option<usize>) -> Arc<Mutex<ReaderState>> {
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
        let state = reader_state(7, None);
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
        let state = reader_state(1, Some(4));
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
    fn default_reader_buffers_without_limit() {
        let state = reader_state(3, None);
        let weak = Arc::downgrade(&state);
        let chunk = vec![0x55; 16 * 1024];
        for _ in 0..80 {
            let frame = StreamDataMessage::new(3, chunk.clone(), false).pack();
            assert!(handle_stream_message(&weak, 3, SMT_STREAM_DATA, &frame));
        }
        let state = state.lock().unwrap();
        assert!(state.failure.is_none());
        assert_eq!(state.reader.available(), 80 * chunk.len());
    }

    #[test]
    fn handler_reports_invalid_compressed_payload() {
        let state = reader_state(2, None);
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
            Err(BufferError::InvalidStreamId(_))
        ));
    }
}
