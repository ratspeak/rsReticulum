use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::channel_message::{
    ChannelMessageError, MessageBase, MessageState, SYSTEM_MESSAGE_TYPE_MIN,
};

// Flow-control constants, matching the Python Channel reference.

pub const WINDOW_INITIAL: usize = 2;
pub const WINDOW_MIN: usize = 2;
pub const WINDOW_MIN_LIMIT_SLOW: usize = 2;
pub const WINDOW_MIN_LIMIT_MEDIUM: usize = 5;
pub const WINDOW_MIN_LIMIT_FAST: usize = 16;
pub const WINDOW_MAX_SLOW: usize = 5;
pub const WINDOW_MAX_MEDIUM: usize = 12;
pub const WINDOW_MAX_FAST: usize = 48;
/// Upper ceiling on `window_max` across all tiers; also sizes pre-allocated guard regions.
pub const WINDOW_MAX: usize = WINDOW_MAX_FAST;
/// Consecutive rounds at a tier's RTT before `window_max` is promoted to that tier.
pub const FAST_RATE_THRESHOLD: usize = 10;
/// RTT at or below which a link is considered "fast" (seconds).
pub const RTT_FAST: f64 = 0.18;
/// RTT at or below which a link is considered "medium" (seconds).
pub const RTT_MEDIUM: f64 = 0.75;
/// RTT above which a fresh window starts at a single slot.
pub const RTT_SLOW: f64 = 1.45;
/// Minimum gap `shrink()` will leave between `window_max` and `window_min`.
pub const WINDOW_FLEXIBILITY: usize = 4;

pub const SEQ_MAX: u16 = 0xFFFF;
pub const SEQ_MODULUS: u32 = 0x10000;

/// Envelope header: `msgtype(2) || sequence(2) || length(2)`.
pub const ENVELOPE_HEADER_SIZE: usize = 6;

/// Retransmissions an envelope may absorb before the channel is torn down.
pub const MAX_TRIES: usize = 5;

/// Floor for the `rtt * 2.5` term used as the base of the retransmit backoff.
pub const MIN_TIMEOUT_BASE: f64 = 0.025;

/// One outgoing or incoming channel frame.
///
/// Wire format: `msgtype(2 BE) || sequence(2 BE) || length(2 BE) || data`.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub msg_type: u16,
    pub sequence: u16,
    pub raw: Vec<u8>,
    pub packed: bool,
    pub tries: usize,
    pub state: MessageState,
    last_sent: Option<Instant>,
}

impl Envelope {
    /// Serialize `msg` into a fresh envelope at the given sequence number.
    pub fn pack(msg: &dyn MessageBase, sequence: u16) -> Self {
        let data = msg.pack();
        let msg_type = msg.msg_type();
        let length = data.len() as u16;

        let mut raw = Vec::with_capacity(ENVELOPE_HEADER_SIZE + data.len());
        raw.extend_from_slice(&msg_type.to_be_bytes());
        raw.extend_from_slice(&sequence.to_be_bytes());
        raw.extend_from_slice(&length.to_be_bytes());
        raw.extend_from_slice(&data);

        Self {
            msg_type,
            sequence,
            raw,
            packed: true,
            tries: 0,
            state: MessageState::New,
            last_sent: None,
        }
    }

    /// Parse an envelope from the wire.
    ///
    /// Python Reticulum ignores the declared length while unpacking and hands
    /// all bytes after the six-byte header to the message decoder.
    pub fn unpack(raw: &[u8]) -> Result<Self, ChannelMessageError> {
        if raw.len() < ENVELOPE_HEADER_SIZE {
            return Err(ChannelMessageError::TooShort);
        }

        let msg_type = u16::from_be_bytes([raw[0], raw[1]]);
        let sequence = u16::from_be_bytes([raw[2], raw[3]]);

        Ok(Self {
            msg_type,
            sequence,
            raw: raw.to_vec(),
            packed: true,
            tries: 0,
            state: MessageState::New,
            last_sent: None,
        })
    }

    pub fn payload(&self) -> &[u8] {
        if self.raw.len() > ENVELOPE_HEADER_SIZE {
            &self.raw[ENVELOPE_HEADER_SIZE..]
        } else {
            &[]
        }
    }
}

/// Flow-control window state for a single channel.
///
/// Holds both fast- and medium-tier counters so a link's window size tracks
/// sustained RTT rather than any single measurement.
#[derive(Debug, Clone)]
pub struct ChannelWindow {
    pub window: usize,
    pub window_min: usize,
    pub window_max: usize,
    pub window_flexibility: usize,
    pub fast_rate_rounds: usize,
    pub medium_rate_rounds: usize,
}

impl ChannelWindow {
    /// Build a window sized to the initial `rtt`. Links slower than
    /// `RTT_SLOW` start pinned at a single slot with zero flexibility so we
    /// don't spray bursts onto a marginal path.
    pub fn new(rtt: f64) -> Self {
        if rtt > RTT_SLOW {
            Self {
                window: 1,
                window_min: 1,
                window_max: 1,
                window_flexibility: 1,
                fast_rate_rounds: 0,
                medium_rate_rounds: 0,
            }
        } else {
            Self {
                window: WINDOW_INITIAL,
                window_min: WINDOW_MIN,
                window_max: WINDOW_MAX_SLOW,
                window_flexibility: WINDOW_FLEXIBILITY,
                fast_rate_rounds: 0,
                medium_rate_rounds: 0,
            }
        }
    }

    /// Record a successful delivery at `rtt` and open the window one notch.
    ///
    /// Only after `FAST_RATE_THRESHOLD` *consecutive* rounds at the same tier
    /// does the ceiling (`window_max`) get promoted — a single fast RTT can't
    /// unlock the fast tier. Any measurement that falls out of a tier resets
    /// that tier's counter.
    pub fn grow(&mut self, rtt: f64) {
        if self.window < self.window_max {
            self.window += 1;
        }

        if rtt == 0.0 {
            return;
        }

        if rtt > RTT_FAST {
            self.fast_rate_rounds = 0;

            if rtt > RTT_MEDIUM {
                self.medium_rate_rounds = 0;
            } else {
                self.medium_rate_rounds += 1;
                if self.window_max < WINDOW_MAX_MEDIUM
                    && self.medium_rate_rounds == FAST_RATE_THRESHOLD
                {
                    self.window_max = WINDOW_MAX_MEDIUM;
                    self.window_min = WINDOW_MIN_LIMIT_MEDIUM;
                }
            }
        } else {
            self.fast_rate_rounds += 1;
            if self.window_max < WINDOW_MAX_FAST && self.fast_rate_rounds == FAST_RATE_THRESHOLD {
                self.window_max = WINDOW_MAX_FAST;
                self.window_min = WINDOW_MIN_LIMIT_FAST;
            }
        }
    }

    /// Pull the window in on retransmit. Also walks `window_max` downwards so
    /// long-term packet loss actually demotes the link tier, stopping at the
    /// configured `window_flexibility` gap above `window_min`.
    pub fn shrink(&mut self) {
        if self.window > self.window_min {
            self.window -= 1;

            if self.window_max > (self.window_min + self.window_flexibility) {
                self.window_max -= 1;
            }
        }
    }
}

/// Handler for inbound messages on a channel.
///
/// Invoked with `(msg_type, payload)`. Return `true` to consume the message
/// (subsequent handlers are skipped) or `false` to fall through.
pub type MessageCallback = Box<dyn Fn(u16, &[u8]) -> bool + Send>;

/// Opaque token for removing one registered message handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandlerId(u64);

/// Sequenced, reliable message pipe over a Reticulum link.
///
/// The channel is passive: the owning runtime calls `send`/`receive`/
/// `timeout`/`delivered` to step the state machine. When one or more message
/// types are registered, inbound envelopes carrying an unregistered type are
/// rejected rather than silently dropped.
pub struct Channel {
    next_tx_sequence: u16,
    next_rx_sequence: u16,
    tx_ring: VecDeque<Envelope>,
    rx_ring: VecDeque<Envelope>,
    pub window: ChannelWindow,
    pub active: bool,
    current_rtt: f64,
    /// When non-empty, only these types are accepted on `receive`.
    registered_types: Vec<u16>,
    /// Called in registration order on each delivered message; the first
    /// handler that returns `true` stops the chain.
    message_handlers: Vec<(HandlerId, MessageCallback)>,
    next_handler_id: u64,
}

impl Channel {
    pub fn new(rtt: f64) -> Self {
        Self {
            next_tx_sequence: 0,
            next_rx_sequence: 0,
            tx_ring: VecDeque::new(),
            rx_ring: VecDeque::new(),
            window: ChannelWindow::new(rtt),
            active: true,
            current_rtt: rtt,
            registered_types: Vec::new(),
            message_handlers: Vec::new(),
            next_handler_id: 0,
        }
    }

    /// Register a user-visible type (`< 0xF000`) for reception.
    /// Types at or above `SYSTEM_MESSAGE_TYPE_MIN` must go through
    /// [`Self::register_system_type`] to prevent applications from stomping on
    /// reserved IDs.
    pub fn register_message_type(&mut self, msg_type: u16) -> Result<(), ChannelError> {
        if msg_type >= SYSTEM_MESSAGE_TYPE_MIN {
            return Err(ChannelError::InvalidMessageType(msg_type));
        }
        if !self.registered_types.contains(&msg_type) {
            self.registered_types.push(msg_type);
        }
        Ok(())
    }

    /// Register a reserved system type (`>= 0xF000`) for reception.
    pub fn register_system_type(&mut self, msg_type: u16) {
        if !self.registered_types.contains(&msg_type) {
            self.registered_types.push(msg_type);
        }
    }

    /// Append `handler` to the end of the callback chain and return its token.
    pub fn add_message_handler(&mut self, handler: MessageCallback) -> HandlerId {
        let id = HandlerId(self.next_handler_id);
        self.next_handler_id = self.next_handler_id.wrapping_add(1);
        self.message_handlers.push((id, handler));
        id
    }

    /// Remove exactly one previously registered handler.
    pub fn remove_message_handler(&mut self, id: HandlerId) -> bool {
        let Some(index) = self
            .message_handlers
            .iter()
            .position(|(candidate, _)| *candidate == id)
        else {
            return false;
        };
        let (_id, handler) = self.message_handlers.remove(index);
        drop(handler);
        true
    }

    pub fn clear_message_handlers(&mut self) {
        self.message_handlers.clear();
    }

    fn run_callbacks(&self, msg_type: u16, payload: &[u8]) -> bool {
        for (_, handler) in &self.message_handlers {
            if handler(msg_type, payload) {
                return true;
            }
        }
        false
    }

    fn is_type_registered(&self, msg_type: u16) -> bool {
        self.registered_types.contains(&msg_type)
    }

    /// True when the channel has window headroom to accept a new outbound message.
    pub fn is_ready_to_send(&self) -> bool {
        if !self.active {
            return false;
        }
        let outstanding = self
            .tx_ring
            .iter()
            .filter(|e| e.state != MessageState::Delivered)
            .count();
        outstanding < self.window.window
    }

    /// True when every outbound envelope has been acknowledged and removed.
    pub fn is_drained(&self) -> bool {
        self.tx_ring.is_empty()
    }

    /// Pack `msg`, push it onto the TX ring, and return the raw envelope for
    /// the transport to send. Fails when the channel is closed or its window
    /// is already saturated.
    pub fn send(&mut self, msg: &dyn MessageBase) -> Result<Vec<u8>, ChannelError> {
        self.send_tracked(msg).map(|(_, raw)| raw)
    }

    /// As [`Self::send`], but also returns the assigned sequence number.
    pub fn send_tracked(&mut self, msg: &dyn MessageBase) -> Result<(u16, Vec<u8>), ChannelError> {
        self.send_tracked_with_max_envelope(msg, None)
    }

    fn send_tracked_with_max_envelope(
        &mut self,
        msg: &dyn MessageBase,
        max_envelope_size: Option<usize>,
    ) -> Result<(u16, Vec<u8>), ChannelError> {
        if !self.active {
            return Err(ChannelError::ChannelClosed);
        }
        if !self.is_ready_to_send() {
            return Err(ChannelError::NotReady);
        }

        let seq = self.next_tx_sequence;
        let mut envelope = Envelope::pack(msg, seq);
        if let Some(max) = max_envelope_size {
            if envelope.raw.len() > max {
                return Err(ChannelError::MessageTooLarge {
                    actual: envelope.raw.len(),
                    max,
                });
            }
        }
        self.next_tx_sequence = ((self.next_tx_sequence as u32 + 1) % SEQ_MODULUS) as u16;
        envelope.state = MessageState::Sent;
        envelope.tries = 1;
        envelope.last_sent = Some(Instant::now());

        let raw = envelope.raw.clone();
        self.tx_ring.push_back(envelope);
        Ok((seq, raw))
    }

    /// Mark a TX envelope as acknowledged and drain any in-order delivered
    /// frames off the front of the ring, then open the window.
    pub fn delivered(&mut self, sequence: u16, rtt: f64) {
        if let Some(env) = self.tx_ring.iter_mut().find(|e| e.sequence == sequence) {
            env.state = MessageState::Delivered;
        }
        while self
            .tx_ring
            .front()
            .is_some_and(|e| e.state == MessageState::Delivered)
        {
            self.tx_ring.pop_front();
        }
        self.window.grow(rtt);
    }

    /// Bump the try count for `sequence`. Returns the envelope bytes to
    /// retransmit, or an error once `MAX_TRIES` has been exceeded (the channel
    /// is marked inactive at that point).
    pub fn timeout(&mut self, sequence: u16) -> Result<Option<Vec<u8>>, ChannelError> {
        if let Some(env) = self.tx_ring.iter_mut().find(|e| e.sequence == sequence) {
            env.tries += 1;
            if env.tries > MAX_TRIES {
                self.active = false;
                return Err(ChannelError::MaxRetriesExceeded);
            }
            env.last_sent = Some(Instant::now());
            self.window.shrink();
            return Ok(Some(env.raw.clone()));
        }
        Ok(None)
    }

    /// Return the sequences whose delivery proof timers have expired.
    pub fn timed_out_sequences(&self) -> Vec<u16> {
        self.tx_ring
            .iter()
            .filter(|env| {
                env.state != MessageState::Delivered
                    && env
                        .last_sent
                        .is_some_and(|sent| sent.elapsed() >= self.timeout_duration(env.tries))
            })
            .map(|env| env.sequence)
            .collect()
    }

    /// Duration until the next outstanding envelope should be retransmitted.
    pub fn next_timeout_duration(&self) -> Option<Duration> {
        self.tx_ring
            .iter()
            .filter(|env| env.state != MessageState::Delivered)
            .filter_map(|env| {
                let sent = env.last_sent?;
                let timeout = self.timeout_duration(env.tries);
                Some(timeout.saturating_sub(sent.elapsed()))
            })
            .min()
    }

    /// Process an inbound envelope and return every newly in-order
    /// `(msg_type, payload)` tuple freed by its arrival. Empty payloads are
    /// legitimate. Out-of-range or duplicate sequence numbers are silently
    /// dropped; registered callbacks fire in order on each delivered message.
    pub fn receive(&mut self, raw: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, ChannelError> {
        if !self.active {
            return Err(ChannelError::ChannelClosed);
        }
        let envelope = Envelope::unpack(raw).map_err(|_| ChannelError::InvalidEnvelope)?;

        if !self.is_type_registered(envelope.msg_type) {
            return Err(ChannelError::UnknownMessageType(envelope.msg_type));
        }

        if !self.is_acceptable_sequence(envelope.sequence) {
            return Ok(Vec::new());
        }

        self.emplace_envelope(envelope);

        let mut delivered = Vec::new();
        loop {
            let found = self
                .rx_ring
                .iter()
                .position(|e| e.sequence == self.next_rx_sequence);
            if let Some(idx) = found {
                let env = self.rx_ring.remove(idx).unwrap();
                let payload = env.payload().to_vec();

                self.run_callbacks(env.msg_type, &payload);

                delivered.push((env.msg_type, payload));
                self.next_rx_sequence = ((self.next_rx_sequence as u32 + 1) % SEQ_MODULUS) as u16;
            } else {
                break;
            }
        }

        Ok(delivered)
    }

    /// Match Python's receive guard: future sequence numbers are buffered
    /// without a window-distance cap, while old sequence numbers are only
    /// accepted when the current receive window wraps past zero.
    fn is_acceptable_sequence(&self, seq: u16) -> bool {
        if seq >= self.next_rx_sequence {
            return true;
        }

        let window_overflow =
            ((self.next_rx_sequence as u32 + WINDOW_MAX as u32) % SEQ_MODULUS) as u16;
        window_overflow < self.next_rx_sequence && seq <= window_overflow
    }

    /// Insert `envelope` into the reorder buffer in ascending sequence order
    /// (accounting for wraparound), ignoring duplicates.
    fn emplace_envelope(&mut self, envelope: Envelope) {
        if self.rx_ring.iter().any(|e| e.sequence == envelope.sequence) {
            return;
        }
        let pos = self.rx_ring.iter().position(|e| {
            let diff_new = if envelope.sequence >= self.next_rx_sequence {
                (envelope.sequence - self.next_rx_sequence) as u32
            } else {
                SEQ_MODULUS - self.next_rx_sequence as u32 + envelope.sequence as u32
            };
            let diff_existing = if e.sequence >= self.next_rx_sequence {
                (e.sequence - self.next_rx_sequence) as u32
            } else {
                SEQ_MODULUS - self.next_rx_sequence as u32 + e.sequence as u32
            };
            diff_new < diff_existing
        });
        match pos {
            Some(idx) => self.rx_ring.insert(idx, envelope),
            None => self.rx_ring.push_back(envelope),
        }
    }

    /// Count of TX envelopes not yet marked `Delivered`.
    pub fn outstanding_count(&self) -> usize {
        self.tx_ring
            .iter()
            .filter(|e| e.state != MessageState::Delivered)
            .count()
    }

    /// Retransmit timeout uses the Python-compatible exponential backoff,
    /// based on the latest Link RTT supplied by the owning runtime.
    pub fn compute_timeout(&self, tries: usize) -> f64 {
        let rtt = self.current_rtt;
        let backoff = 1.5_f64.powi(tries.saturating_sub(1) as i32);
        let base = (rtt * 2.5).max(MIN_TIMEOUT_BASE);
        let outstanding = self.outstanding_count() as f64 + 1.5;
        backoff * base * outstanding
    }

    fn timeout_duration(&self, tries: usize) -> Duration {
        Duration::from_secs_f64(self.compute_timeout(tries).max(MIN_TIMEOUT_BASE))
    }

    /// Update the live Link RTT used by subsequent retransmit deadlines.
    pub fn update_rtt(&mut self, rtt: f64) {
        if rtt.is_finite() && rtt >= 0.0 {
            self.current_rtt = rtt;
        }
    }

    /// Mark the channel inactive and drop every buffered envelope and
    /// handler. Idempotent.
    pub fn shutdown(&mut self) {
        self.active = false;
        self.tx_ring.clear();
        self.rx_ring.clear();
        self.message_handlers.clear();
    }

    /// Convert a link MDU into the payload budget per envelope: subtract the
    /// header and cap at `0xFFFF` (the length field is a `u16`).
    pub fn channel_mdu(link_mdu: usize) -> usize {
        let mdu = link_mdu.saturating_sub(ENVELOPE_HEADER_SIZE);
        mdu.min(0xFFFF)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("channel is closed")]
    ChannelClosed,
    #[error("channel not ready to send")]
    NotReady,
    #[error("max retries exceeded")]
    MaxRetriesExceeded,
    #[error("invalid envelope")]
    InvalidEnvelope,
    #[error("unknown message type: 0x{0:04X}")]
    UnknownMessageType(u16),
    #[error("invalid message type: 0x{0:04X} (reserved for system use)")]
    InvalidMessageType(u16),
    #[error("packed channel message is {actual} bytes; Link MDU is {max}")]
    MessageTooLarge { actual: usize, max: usize },
}

/// A [`Channel`] paired with its link ID and (optionally) link session keys,
/// so the caller can hand raw bytes in and out without threading the
/// encryption layer through themselves.
pub struct LinkChannel {
    channel: Channel,
    link_id: [u8; 16],
    link_mdu: usize,
    session_keys: Option<rns_link::key_derivation::LinkKeys>,
    outbound_packet_hashes: HashMap<[u8; 32], u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedChannelData {
    pub sequence: u16,
    pub data: Vec<u8>,
}

impl LinkChannel {
    /// Plain-text channel (no transport-side encryption).
    pub fn new(link_id: [u8; 16], rtt: f64) -> Self {
        Self::new_with_mdu(link_id, rtt, rns_wire::constants::LINK_MDU)
    }

    /// Plain-text channel with an explicit Link MDU.
    pub fn new_with_mdu(link_id: [u8; 16], rtt: f64, link_mdu: usize) -> Self {
        Self {
            channel: Channel::new(rtt),
            link_id,
            link_mdu,
            session_keys: None,
            outbound_packet_hashes: HashMap::new(),
        }
    }

    /// Channel that transparently encrypts outbound frames and decrypts
    /// inbound ones with the supplied link session keys.
    pub fn new_encrypted(
        link_id: [u8; 16],
        rtt: f64,
        keys: rns_link::key_derivation::LinkKeys,
    ) -> Self {
        Self::new_encrypted_with_mdu(link_id, rtt, rns_wire::constants::LINK_MDU, keys)
    }

    /// Encrypted channel with an explicit Link MDU.
    pub fn new_encrypted_with_mdu(
        link_id: [u8; 16],
        rtt: f64,
        link_mdu: usize,
        keys: rns_link::key_derivation::LinkKeys,
    ) -> Self {
        Self {
            channel: Channel::new(rtt),
            link_id,
            link_mdu,
            session_keys: Some(keys),
            outbound_packet_hashes: HashMap::new(),
        }
    }

    /// Pack `msg`, encrypt with the session keys if present, and return the
    /// wire bytes.
    pub fn prepare_send(&mut self, msg: &dyn MessageBase) -> Result<Vec<u8>, ChannelError> {
        self.prepare_send_tracked(msg).map(|prepared| prepared.data)
    }

    /// As [`Self::prepare_send`], but also returns the channel sequence number
    /// so the caller can map the final packet hash back to the channel window.
    pub fn prepare_send_tracked(
        &mut self,
        msg: &dyn MessageBase,
    ) -> Result<PreparedChannelData, ChannelError> {
        let (sequence, raw) = self
            .channel
            .send_tracked_with_max_envelope(msg, Some(self.link_mdu))?;
        if let Some(ref keys) = self.session_keys {
            let data = rns_link::encryption::link_encrypt(keys, &raw)
                .map_err(|_| ChannelError::ChannelClosed)?;
            Ok(PreparedChannelData { sequence, data })
        } else {
            Ok(PreparedChannelData {
                sequence,
                data: raw,
            })
        }
    }

    /// Decrypt if session keys are present, then hand the payload to the
    /// underlying channel and return any newly deliverable messages.
    pub fn receive_data(&mut self, raw: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, ChannelError> {
        let plaintext = if let Some(ref keys) = self.session_keys {
            rns_link::encryption::link_decrypt(keys, raw)
                .map_err(|_| ChannelError::ChannelClosed)?
        } else {
            raw.to_vec()
        };
        self.channel.receive(&plaintext)
    }

    pub fn delivered(&mut self, sequence: u16, rtt: f64) {
        self.channel.update_rtt(rtt);
        self.channel.delivered(sequence, rtt);
    }

    pub fn track_outbound_packet_hash(&mut self, packet_hash: [u8; 32], sequence: u16) {
        self.outbound_packet_hashes.insert(packet_hash, sequence);
    }

    pub fn delivered_by_packet_hash(&mut self, packet_hash: &[u8; 32], rtt: f64) -> Option<u16> {
        let sequence = self.outbound_packet_hashes.remove(packet_hash)?;
        self.outbound_packet_hashes
            .retain(|_, tracked_sequence| *tracked_sequence != sequence);
        self.delivered(sequence, rtt);
        Some(sequence)
    }

    pub fn is_ready_to_send(&self) -> bool {
        self.channel.is_ready_to_send()
    }

    pub fn is_drained(&self) -> bool {
        self.channel.is_drained()
    }

    /// Maximum payload bytes available to one channel message.
    pub fn mdu(&self) -> usize {
        Channel::channel_mdu(self.link_mdu)
    }

    pub fn register_message_type(&mut self, msg_type: u16) -> Result<(), ChannelError> {
        self.channel.register_message_type(msg_type)
    }

    pub fn register_system_type(&mut self, msg_type: u16) {
        self.channel.register_system_type(msg_type);
    }

    pub fn add_message_handler(&mut self, handler: MessageCallback) -> HandlerId {
        self.channel.add_message_handler(handler)
    }

    pub fn remove_message_handler(&mut self, id: HandlerId) -> bool {
        self.channel.remove_message_handler(id)
    }

    pub fn clear_message_handlers(&mut self) {
        self.channel.clear_message_handlers();
    }

    pub fn link_id(&self) -> &[u8; 16] {
        &self.link_id
    }

    pub fn shutdown(&mut self) {
        self.channel.shutdown();
        self.outbound_packet_hashes.clear();
    }

    pub fn is_active(&self) -> bool {
        self.channel.active
    }

    pub fn timeout(&mut self, sequence: u16) -> Result<Option<Vec<u8>>, ChannelError> {
        let Some(raw) = self.channel.timeout(sequence)? else {
            return Ok(None);
        };
        if let Some(ref keys) = self.session_keys {
            let data = rns_link::encryption::link_encrypt(keys, &raw)
                .map_err(|_| ChannelError::ChannelClosed)?;
            Ok(Some(data))
        } else {
            Ok(Some(raw))
        }
    }

    pub fn outstanding_count(&self) -> usize {
        self.channel.outstanding_count()
    }

    pub fn timed_out_sequences(&self) -> Vec<u16> {
        self.channel.timed_out_sequences()
    }

    pub fn next_timeout_duration(&self) -> Option<Duration> {
        self.channel.next_timeout_duration()
    }

    pub fn update_rtt(&mut self, rtt: f64) {
        self.channel.update_rtt(rtt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestMessage {
        data: Vec<u8>,
    }

    impl TestMessage {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
            }
        }
    }

    impl MessageBase for TestMessage {
        fn msg_type(&self) -> u16 {
            0x0001
        }
        fn pack(&self) -> Vec<u8> {
            self.data.clone()
        }
        fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
            self.data = raw.to_vec();
            Ok(())
        }
    }

    #[test]
    fn test_envelope_pack_unpack() {
        let msg = TestMessage::new(b"hello channel");
        let env = Envelope::pack(&msg, 42);

        assert_eq!(env.msg_type, 0x0001);
        assert_eq!(env.sequence, 42);

        let env2 = Envelope::unpack(&env.raw).unwrap();
        assert_eq!(env2.msg_type, 0x0001);
        assert_eq!(env2.sequence, 42);
        assert_eq!(env2.payload(), b"hello channel");
    }

    #[test]
    fn test_envelope_length_field_is_not_enforced_on_unpack() {
        let msg = TestMessage::new(b"test");
        let mut env = Envelope::pack(&msg, 0);

        // Python reads the length field but gives the full post-header payload
        // to the message decoder, even when the declared length is wrong.
        env.raw[4] = 0xFF;
        env.raw[5] = 0xFF;

        let result = Envelope::unpack(&env.raw).unwrap();
        assert_eq!(result.payload(), b"test");

        env.raw[4] = 0x00;
        env.raw[5] = 0x01;

        let result = Envelope::unpack(&env.raw).unwrap();
        assert_eq!(result.payload(), b"test");
    }

    #[test]
    fn test_envelope_too_short() {
        assert!(Envelope::unpack(&[0, 1, 2]).is_err());
    }

    #[test]
    fn test_channel_send_receive() {
        let mut tx_channel = Channel::new(0.1);
        let mut rx_channel = Channel::new(0.1);
        rx_channel.register_message_type(0x0001).unwrap();

        let msg = TestMessage::new(b"hello");
        let raw = tx_channel.send(&msg).unwrap();

        let delivered = rx_channel.receive(&raw).unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].0, 0x0001);
        assert_eq!(delivered[0].1, b"hello");
    }

    #[test]
    fn test_channel_ordering() {
        let mut tx = Channel::new(0.1);
        let mut rx = Channel::new(0.1);
        rx.register_message_type(0x0001).unwrap();

        let msg1 = TestMessage::new(b"first");
        let msg2 = TestMessage::new(b"second");
        let msg3 = TestMessage::new(b"third");

        let raw1 = tx.send(&msg1).unwrap();
        let raw2 = tx.send(&msg2).unwrap();

        // Receive seq 1 before seq 0; it must buffer rather than deliver.
        let d2 = rx.receive(&raw2).unwrap();
        assert!(d2.is_empty());

        // Once seq 0 arrives, both messages drain in order.
        let d1 = rx.receive(&raw1).unwrap();
        assert_eq!(d1.len(), 2);
        assert_eq!(d1[0].1, b"first");
        assert_eq!(d1[1].1, b"second");

        tx.delivered(0, 0.1);
        tx.delivered(1, 0.1);

        let raw3 = tx.send(&msg3).unwrap();
        let d3 = rx.receive(&raw3).unwrap();
        assert_eq!(d3.len(), 1);
        assert_eq!(d3[0].1, b"third");
    }

    #[test]
    fn test_channel_flow_control() {
        let mut ch = Channel::new(0.1);
        assert!(ch.is_ready_to_send());
        assert!(ch.is_drained());

        let msg = TestMessage::new(b"a");
        // `WINDOW_INITIAL` = 2 slots, so two sends saturate the window.
        ch.send(&msg).unwrap();
        ch.send(&msg).unwrap();

        assert!(!ch.is_ready_to_send());
        assert!(!ch.is_drained());

        ch.delivered(0, 0.1);
        assert!(ch.is_ready_to_send());
        assert!(!ch.is_drained());
        ch.delivered(1, 0.1);
        assert!(ch.is_drained());
    }

    #[test]
    fn test_channel_max_retries() {
        let mut ch = Channel::new(0.1);
        let msg = TestMessage::new(b"retry");
        ch.send(&msg).unwrap();

        for _ in 0..MAX_TRIES - 1 {
            let result = ch.timeout(0);
            assert!(result.is_ok());
        }
        // Crossing MAX_TRIES must tear the channel down.
        let result = ch.timeout(0);
        assert!(result.is_err());
        assert!(!ch.active);
    }

    #[test]
    fn test_duplicate_rejection() {
        let mut tx = Channel::new(0.1);
        let mut rx = Channel::new(0.1);
        rx.register_message_type(0x0001).unwrap();

        let msg = TestMessage::new(b"once");
        let raw = tx.send(&msg).unwrap();

        let d1 = rx.receive(&raw).unwrap();
        assert_eq!(d1.len(), 1);

        // Replay of the same envelope must not re-deliver.
        let d2 = rx.receive(&raw).unwrap();
        assert!(d2.is_empty());
    }

    #[test]
    fn test_window_growth_fast() {
        let mut w = ChannelWindow::new(0.1);
        assert_eq!(w.window, WINDOW_INITIAL);
        assert_eq!(w.window_max, WINDOW_MAX_SLOW);

        for _ in 0..FAST_RATE_THRESHOLD {
            w.grow(0.05);
        }
        assert_eq!(w.window_max, WINDOW_MAX_FAST);
        assert_eq!(w.window_min, WINDOW_MIN_LIMIT_FAST);
    }

    #[test]
    fn test_window_growth_medium() {
        let mut w = ChannelWindow::new(0.1);
        assert_eq!(w.window_max, WINDOW_MAX_SLOW);

        for _ in 0..FAST_RATE_THRESHOLD {
            w.grow(0.5);
        }
        assert_eq!(w.window_max, WINDOW_MAX_MEDIUM);
        assert_eq!(w.window_min, WINDOW_MIN_LIMIT_MEDIUM);
        // Moving into the medium tier must zero out the fast counter.
        assert_eq!(w.fast_rate_rounds, 0);
    }

    #[test]
    fn test_window_growth_slow_resets_counters() {
        let mut w = ChannelWindow::new(0.1);

        // Build up fast rounds
        for _ in 0..5 {
            w.grow(0.05);
        }
        assert_eq!(w.fast_rate_rounds, 5);

        // Slow RTT resets both counters
        w.grow(1.0);
        assert_eq!(w.fast_rate_rounds, 0);
        assert_eq!(w.medium_rate_rounds, 0);
    }

    #[test]
    fn test_window_shrink_reduces_window_max() {
        // Shrinking must pull the ceiling down, not just the instantaneous window.
        let mut w = ChannelWindow::new(0.1);
        w.window = 5;
        w.window_max = WINDOW_MAX_SLOW + WINDOW_FLEXIBILITY + 2;
        let old_max = w.window_max;

        w.shrink();
        assert_eq!(w.window, 4);
        assert_eq!(w.window_max, old_max - 1);
    }

    #[test]
    fn test_window_shrink_respects_flexibility() {
        let mut w = ChannelWindow::new(0.1);
        w.window = 4;
        w.window_max = w.window_min + w.window_flexibility; // exactly at flexibility limit

        w.shrink();
        assert_eq!(w.window, 3);
        // Dropping window_max further would violate the flexibility floor.
        assert_eq!(w.window_max, w.window_min + w.window_flexibility);
    }

    #[test]
    fn test_window_slow_rtt_init() {
        // RTT past RTT_SLOW must start pinned at a single slot with no flex.
        let w = ChannelWindow::new(2.0);
        assert_eq!(w.window, 1);
        assert_eq!(w.window_max, 1);
        assert_eq!(w.window_min, 1);
        assert_eq!(w.window_flexibility, 1);
    }

    #[test]
    fn test_channel_shutdown() {
        let mut ch = Channel::new(0.1);
        let msg = TestMessage::new(b"test");
        ch.send(&msg).unwrap();

        ch.shutdown();
        assert!(!ch.active);
        assert!(ch.send(&msg).is_err());
        assert!(matches!(
            ch.receive(&Envelope::pack(&msg, 0).raw),
            Err(ChannelError::ChannelClosed)
        ));
    }

    #[test]
    fn test_channel_mdu_computation() {
        assert_eq!(Channel::channel_mdu(464), 464 - ENVELOPE_HEADER_SIZE);
        assert_eq!(Channel::channel_mdu(415), 415 - ENVELOPE_HEADER_SIZE);
        // link_mdu smaller than the envelope header must not underflow.
        assert_eq!(Channel::channel_mdu(3), 0);
        // Length field is u16, so values past 0xFFFF must saturate.
        assert_eq!(Channel::channel_mdu(0x20000), 0xFFFF);
    }

    #[test]
    fn test_sequence_wrapping() {
        let mut ch = Channel::new(0.1);
        ch.next_tx_sequence = SEQ_MAX;
        let msg = TestMessage::new(b"wrap");
        let _raw = ch.send(&msg).unwrap();
        assert_eq!(ch.next_tx_sequence, 0);
    }

    #[test]
    fn test_envelope_zero_length() {
        // An empty payload is a valid envelope, not an error.
        let msg = TestMessage::new(b"");
        let env = Envelope::pack(&msg, 0);
        let env2 = Envelope::unpack(&env.raw).unwrap();
        assert_eq!(env2.payload(), b"");
        assert_eq!(env2.msg_type, 0x0001);
    }

    #[test]
    fn test_unknown_message_type_rejected() {
        // Once any type is registered, the whitelist is enforced.
        let mut ch = Channel::new(0.1);
        ch.register_message_type(0x0001).unwrap();

        let mut raw = Vec::new();
        raw.extend_from_slice(&0x0002u16.to_be_bytes());
        raw.extend_from_slice(&0x0000u16.to_be_bytes());
        raw.extend_from_slice(&0x0004u16.to_be_bytes());
        raw.extend_from_slice(b"test");

        let result = ch.receive(&raw);
        assert!(matches!(
            result,
            Err(ChannelError::UnknownMessageType(0x0002))
        ));
    }

    #[test]
    fn test_registered_type_accepted() {
        let mut ch = Channel::new(0.1);
        ch.register_message_type(0x0001).unwrap();

        let mut raw = Vec::new();
        raw.extend_from_slice(&0x0001u16.to_be_bytes());
        raw.extend_from_slice(&0x0000u16.to_be_bytes());
        raw.extend_from_slice(&0x0004u16.to_be_bytes());
        raw.extend_from_slice(b"test");

        let result = ch.receive(&raw);
        assert!(result.is_ok());
    }

    #[test]
    fn test_no_registered_types_rejects_all() {
        // Python requires every inbound user or system type to be registered.
        let mut ch = Channel::new(0.1);

        let mut raw = Vec::new();
        raw.extend_from_slice(&0x1234u16.to_be_bytes());
        raw.extend_from_slice(&0x0000u16.to_be_bytes());
        raw.extend_from_slice(&0x0004u16.to_be_bytes());
        raw.extend_from_slice(b"test");

        let result = ch.receive(&raw);
        assert!(matches!(
            result,
            Err(ChannelError::UnknownMessageType(0x1234))
        ));
    }

    #[test]
    fn test_system_type_registration() {
        let mut ch = Channel::new(0.1);
        // User types in the system range must be rejected via the public API.
        assert!(ch.register_message_type(0xFF00).is_err());
        // The internal register_system_type bypasses the range check.
        ch.register_system_type(0xFF00);
        assert!(ch.registered_types.contains(&0xFF00));
    }

    #[test]
    fn test_multiple_handlers() {
        // Handlers run in registration order until one returns true, so the
        // third handler here must never see the frame.
        use std::sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        };

        let mut ch = Channel::new(0.1);
        let counter = Arc::new(AtomicU32::new(0));

        let c1 = counter.clone();
        ch.add_message_handler(Box::new(move |_msg_type, _payload| {
            c1.fetch_add(1, Ordering::SeqCst);
            false
        }));

        let c2 = counter.clone();
        ch.add_message_handler(Box::new(move |_msg_type, _payload| {
            c2.fetch_add(10, Ordering::SeqCst);
            true
        }));

        let c3 = counter.clone();
        ch.add_message_handler(Box::new(move |_msg_type, _payload| {
            c3.fetch_add(100, Ordering::SeqCst);
            false
        }));

        let msg = TestMessage::new(b"multi");
        let raw = ch.send(&msg).unwrap();

        let mut rx = Channel::new(0.1);
        rx.register_message_type(0x0001).unwrap();
        let counter2 = counter.clone();
        let c4 = counter2.clone();
        rx.add_message_handler(Box::new(move |_msg_type, _payload| {
            c4.fetch_add(1, Ordering::SeqCst);
            false
        }));
        let c5 = counter2.clone();
        rx.add_message_handler(Box::new(move |_msg_type, _payload| {
            c5.fetch_add(10, Ordering::SeqCst);
            true
        }));
        let c6 = counter2.clone();
        rx.add_message_handler(Box::new(move |_msg_type, _payload| {
            c6.fetch_add(100, Ordering::SeqCst);
            false
        }));

        rx.receive(&raw).unwrap();
        assert_eq!(counter2.load(Ordering::SeqCst), 11);
    }

    #[test]
    fn test_remove_message_handler_removes_only_its_token() {
        use std::sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        };

        let mut tx = Channel::new(0.1);
        let raw = tx.send(&TestMessage::new(b"handler tokens")).unwrap();
        let mut rx = Channel::new(0.1);
        rx.register_message_type(0x0001).unwrap();
        let counter = Arc::new(AtomicU32::new(0));

        let first_counter = counter.clone();
        let first = rx.add_message_handler(Box::new(move |_, _| {
            first_counter.fetch_add(1, Ordering::SeqCst);
            false
        }));
        let second_counter = counter.clone();
        let _second = rx.add_message_handler(Box::new(move |_, _| {
            second_counter.fetch_add(10, Ordering::SeqCst);
            false
        }));

        assert!(rx.remove_message_handler(first));
        assert!(!rx.remove_message_handler(first));
        rx.receive(&raw).unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn test_live_rtt_updates_retransmit_timeout() {
        let mut channel = Channel::new(0.1);
        channel.send(&TestMessage::new(b"rtt")).unwrap();
        let initial = channel.compute_timeout(1);
        channel.update_rtt(1.0);
        assert!(channel.compute_timeout(1) > initial);
    }

    #[test]
    fn test_link_channel_send_receive() {
        let link_id = [0xAA; 16];
        let mut tx_lc = LinkChannel::new(link_id, 0.1);
        let mut rx_lc = LinkChannel::new(link_id, 0.1);
        rx_lc.register_message_type(0x0001).unwrap();

        assert_eq!(*tx_lc.link_id(), link_id);
        assert!(tx_lc.is_active());
        assert!(tx_lc.is_ready_to_send());

        let msg = TestMessage::new(b"link channel test");
        let raw = tx_lc.prepare_send(&msg).unwrap();

        let delivered = rx_lc.receive_data(&raw).unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].0, 0x0001);
        assert_eq!(delivered[0].1, b"link channel test");
    }

    #[test]
    fn test_link_channel_roundtrip() {
        let link_id = [0xBB; 16];
        let mut tx_lc = LinkChannel::new(link_id, 0.1);
        let mut rx_lc = LinkChannel::new(link_id, 0.1);
        rx_lc.register_message_type(0x0001).unwrap();

        // Send two messages
        let msg1 = TestMessage::new(b"first");
        let msg2 = TestMessage::new(b"second");

        let raw1 = tx_lc.prepare_send(&msg1).unwrap();
        let raw2 = tx_lc.prepare_send(&msg2).unwrap();

        let d1 = rx_lc.receive_data(&raw1).unwrap();
        assert_eq!(d1.len(), 1);
        assert_eq!(d1[0].1, b"first");

        let d2 = rx_lc.receive_data(&raw2).unwrap();
        assert_eq!(d2.len(), 1);
        assert_eq!(d2[0].1, b"second");

        tx_lc.delivered(0, 0.1);
        tx_lc.delivered(1, 0.1);
        assert_eq!(tx_lc.outstanding_count(), 0);
        assert!(tx_lc.is_drained());
    }

    #[test]
    fn test_link_channel_shutdown() {
        let link_id = [0xCC; 16];
        let mut lc = LinkChannel::new(link_id, 0.1);

        assert!(lc.is_active());
        lc.shutdown();
        assert!(!lc.is_active());

        let msg = TestMessage::new(b"after shutdown");
        assert!(lc.prepare_send(&msg).is_err());
    }

    #[test]
    fn test_link_channel_timeout() {
        let link_id = [0xDD; 16];
        let mut lc = LinkChannel::new(link_id, 0.1);

        let msg = TestMessage::new(b"timeout test");
        lc.prepare_send(&msg).unwrap();

        // An unacknowledged envelope must be handed back for resend.
        let resend = lc.timeout(0).unwrap();
        assert!(resend.is_some());
    }

    #[test]
    fn test_channel_delivery_clears_retransmission_hashes_for_sequence() {
        let mut channel = LinkChannel::new([0xDF; 16], 0.1);
        channel
            .prepare_send_tracked(&TestMessage::new(b"tracked"))
            .unwrap();
        let first_hash = [1u8; 32];
        let retry_hash = [2u8; 32];
        channel.track_outbound_packet_hash(first_hash, 0);
        channel.track_outbound_packet_hash(retry_hash, 0);

        assert_eq!(channel.delivered_by_packet_hash(&retry_hash, 0.1), Some(0));
        assert!(channel.outbound_packet_hashes.is_empty());
        assert_eq!(channel.delivered_by_packet_hash(&first_hash, 0.1), None);
    }

    #[test]
    fn test_link_channel_enforces_message_mdu_without_consuming_sequence() {
        let link_id = [0xDE; 16];
        let mut channel = LinkChannel::new_with_mdu(link_id, 0.1, 32);
        assert_eq!(channel.mdu(), 32 - ENVELOPE_HEADER_SIZE);

        let oversized = TestMessage::new(&vec![0u8; channel.mdu() + 1]);
        assert!(matches!(
            channel.prepare_send_tracked(&oversized),
            Err(ChannelError::MessageTooLarge {
                actual: 33,
                max: 32
            })
        ));
        assert_eq!(channel.outstanding_count(), 0);

        let prepared = channel
            .prepare_send_tracked(&TestMessage::new(b"fits"))
            .unwrap();
        assert_eq!(prepared.sequence, 0);
    }

    #[test]
    fn test_encrypted_link_channel_roundtrip() {
        use rns_crypto::x25519::X25519PrivateKey;
        use rns_link::constants::MODE_AES256_CBC;
        use rns_link::key_derivation::LinkKeys;

        let prv_a = X25519PrivateKey::generate();
        let pub_a = prv_a.public_key();
        let prv_b = X25519PrivateKey::generate();
        let pub_b = prv_b.public_key();
        let link_id = [0xEE; 16];

        let keys_a = LinkKeys::derive(&prv_a, &pub_b, &link_id, MODE_AES256_CBC).unwrap();
        let keys_b = LinkKeys::derive(&prv_b, &pub_a, &link_id, MODE_AES256_CBC).unwrap();

        let mut tx_lc = LinkChannel::new_encrypted(link_id, 0.1, keys_a);
        let mut rx_lc = LinkChannel::new_encrypted(link_id, 0.1, keys_b);
        rx_lc.register_message_type(0x0001).unwrap();

        let msg = TestMessage::new(b"encrypted hello");
        let raw = tx_lc.prepare_send(&msg).unwrap();

        // Encrypted output must not match the plaintext envelope produced
        // by a non-encrypted channel carrying the same message.
        let plain_msg = TestMessage::new(b"encrypted hello");
        let mut plain_ch = LinkChannel::new(link_id, 0.1);
        let plain_raw = plain_ch.prepare_send(&plain_msg).unwrap();
        assert_ne!(raw, plain_raw);

        let delivered = rx_lc.receive_data(&raw).unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].1, b"encrypted hello");
    }

    #[test]
    fn test_mismatched_keys_fail() {
        use rns_crypto::x25519::X25519PrivateKey;
        use rns_link::constants::MODE_AES256_CBC;
        use rns_link::key_derivation::LinkKeys;

        let prv_a = X25519PrivateKey::generate();
        let pub_b = X25519PrivateKey::generate().public_key();
        let link_id = [0xFF; 16];

        let keys_a = LinkKeys::derive(&prv_a, &pub_b, &link_id, MODE_AES256_CBC).unwrap();

        // Keys derived from an unrelated pair must not decrypt A's output.
        let prv_c = X25519PrivateKey::generate();
        let pub_d = X25519PrivateKey::generate().public_key();
        let keys_wrong = LinkKeys::derive(&prv_c, &pub_d, &link_id, MODE_AES256_CBC).unwrap();

        let mut tx_lc = LinkChannel::new_encrypted(link_id, 0.1, keys_a);
        let mut rx_lc = LinkChannel::new_encrypted(link_id, 0.1, keys_wrong);

        let msg = TestMessage::new(b"secret");
        let raw = tx_lc.prepare_send(&msg).unwrap();

        assert!(rx_lc.receive_data(&raw).is_err());
    }
}
