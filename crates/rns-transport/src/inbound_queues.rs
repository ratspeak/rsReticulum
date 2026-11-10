//! Per-class inbound queues in front of transport processing
//! (Transport.py:50-97, :2165-2170). Announce, path-request and
//! ingress-limited packets are dropped and counted when their queue is full;
//! data waits for room instead of being dropped.
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::sync::mpsc;

use crate::messages::TransportMessage;

/// Python `Transport.TC_*` (Transport.py:155-158), drained in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficClass {
    Data = 0,
    Announce = 1,
    PathRequest = 2,
    IngressLimited = 3,
}

/// Python `Transport.INBOUND_*_QUEUE_LENGTH` (Transport.py:186-189),
/// overridden by `[reticulum] qlen_in_*`. Zero selects the default, as
/// `Transport.start` does (Transport.py:420-423).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundQueueLengths {
    pub data: usize,
    pub announce: usize,
    pub pr: usize,
    pub il: usize,
}

impl Default for InboundQueueLengths {
    fn default() -> Self {
        Self {
            data: 1024,
            announce: 128,
            pr: 128,
            il: 8,
        }
    }
}

impl InboundQueueLengths {
    fn normalized(self) -> Self {
        let default = Self::default();
        let or = |value: usize, default: usize| {
            if value == 0 {
                default
            } else {
                value.min(tokio::sync::Semaphore::MAX_PERMITS)
            }
        };
        Self {
            data: or(self.data, default.data),
            announce: or(self.announce, default.announce),
            pr: or(self.pr, default.pr),
            il: or(self.il, default.il),
        }
    }
}

/// Python `InboundQueues.snapshot()` plus the configured lengths, indexed by
/// [`TrafficClass`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InboundQueueSnapshot {
    pub heights: [usize; 4],
    pub dropped: [u64; 4],
    pub lengths: [usize; 4],
}

/// Producer side of the inbound queues and their live counters. The actor
/// owns the receivers and the ingress-limited queue.
#[derive(Debug)]
pub struct InboundQueues {
    lengths: InboundQueueLengths,
    data: mpsc::Sender<TransportMessage>,
    announce: mpsc::Sender<TransportMessage>,
    path_request: mpsc::Sender<TransportMessage>,
    ingress_limited_height: AtomicUsize,
    dropped: [AtomicU64; 4],
}

/// An item taken from the inbound queues.
pub(crate) enum Queued {
    Message(Box<TransportMessage>),
    /// A held announce the interface released (Interface.py:300).
    ReleasedAnnounce(crate::ingress::HeldAnnounce),
}

pub(crate) struct InboundReceivers {
    data: mpsc::Receiver<TransportMessage>,
    announce: mpsc::Receiver<TransportMessage>,
    path_request: mpsc::Receiver<TransportMessage>,
    ingress_limited: std::collections::VecDeque<Queued>,
}

impl InboundReceivers {
    /// The next queued event and its class, in Python's drain order
    /// (Transport.py:73-84).
    pub(crate) fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
        queues: &InboundQueues,
    ) -> std::task::Poll<(TrafficClass, Queued)> {
        for (class, rx) in [
            (TrafficClass::Data, &mut self.data),
            (TrafficClass::Announce, &mut self.announce),
            (TrafficClass::PathRequest, &mut self.path_request),
        ] {
            if let std::task::Poll::Ready(Some(message)) = rx.poll_recv(cx) {
                return std::task::Poll::Ready((class, Queued::Message(Box::new(message))));
            }
        }
        match self.ingress_limited.pop_front() {
            Some(message) => {
                queues.set_ingress_limited_height(self.ingress_limited.len());
                std::task::Poll::Ready((TrafficClass::IngressLimited, message))
            }
            None => std::task::Poll::Pending,
        }
    }

    /// Queue an item as ingress limited, dropping and counting it when that
    /// queue is full (Transport.py:2133-2134, :2165-2169).
    pub(crate) fn push_ingress_limited(&mut self, queues: &InboundQueues, event: Queued) {
        if self.ingress_limited.len() >= queues.lengths.il {
            queues.count_drop(TrafficClass::IngressLimited);
        } else {
            self.ingress_limited.push_back(event);
            queues.set_ingress_limited_height(self.ingress_limited.len());
        }
    }
}

impl InboundQueues {
    pub(crate) fn new(lengths: InboundQueueLengths) -> (Arc<Self>, InboundReceivers) {
        let lengths = lengths.normalized();
        let (data, data_rx) = mpsc::channel(lengths.data);
        let (announce, announce_rx) = mpsc::channel(lengths.announce);
        let (path_request, path_request_rx) = mpsc::channel(lengths.pr);
        (
            Arc::new(Self {
                lengths,
                data,
                announce,
                path_request,
                ingress_limited_height: AtomicUsize::new(0),
                dropped: Default::default(),
            }),
            InboundReceivers {
                data: data_rx,
                announce: announce_rx,
                path_request: path_request_rx,
                ingress_limited: Default::default(),
            },
        )
    }

    /// Lengths as applied, with zero replaced by the default.
    pub fn lengths(&self) -> InboundQueueLengths {
        self.lengths
    }

    pub fn snapshot(&self) -> InboundQueueSnapshot {
        let height = |tx: &mpsc::Sender<TransportMessage>| tx.max_capacity() - tx.capacity();
        InboundQueueSnapshot {
            heights: [
                height(&self.data),
                height(&self.announce),
                height(&self.path_request),
                self.ingress_limited_height.load(Ordering::Relaxed),
            ],
            dropped: std::array::from_fn(|i| self.dropped[i].load(Ordering::Relaxed)),
            lengths: [
                self.lengths.data,
                self.lengths.announce,
                self.lengths.pr,
                self.lengths.il,
            ],
        }
    }

    pub(crate) fn count_drop(&self, class: TrafficClass) {
        self.dropped[class as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn set_ingress_limited_height(&self, height: usize) {
        self.ingress_limited_height.store(height, Ordering::Relaxed);
    }

    /// Queue an interface event; a full announce or path-request queue drops
    /// and counts it, a full data queue waits.
    pub(crate) async fn send(
        &self,
        class: TrafficClass,
        event: TransportMessage,
    ) -> Result<(), mpsc::error::SendError<TransportMessage>> {
        match class {
            TrafficClass::Data | TrafficClass::IngressLimited => self.data.send(event).await,
            _ => self.try_send(class, event).map_err(|e| match e {
                mpsc::error::TrySendError::Full(m) | mpsc::error::TrySendError::Closed(m) => {
                    mpsc::error::SendError(m)
                }
            }),
        }
    }

    /// As [`Self::send`], but a full data queue refuses instead of waiting.
    // Keep Tokio's by-value failure so the sender can hand back the original message.
    #[allow(clippy::result_large_err)]
    pub(crate) fn try_send(
        &self,
        class: TrafficClass,
        event: TransportMessage,
    ) -> Result<(), mpsc::error::TrySendError<TransportMessage>> {
        let tx = match class {
            TrafficClass::Data | TrafficClass::IngressLimited => {
                return self.data.try_send(event);
            }
            TrafficClass::Announce => &self.announce,
            TrafficClass::PathRequest => &self.path_request,
        };
        match tx.try_send(event) {
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.count_drop(class);
                Ok(())
            }
            other => other,
        }
    }
}

/// What a registered interface's producers need to queue its frames.
#[derive(Debug, Clone)]
pub(crate) struct InboundIntake {
    pub(crate) queues: Arc<InboundQueues>,
    pub(crate) ifac: Option<(rns_identity::ifac::IfacKey, usize)>,
    /// The actor mailbox; weak so producers never keep a stopped actor's mailbox open.
    pub(crate) mailbox: mpsc::WeakSender<TransportMessage>,
}

impl InboundIntake {
    /// Only producers bound to this actor's own mailbox use its class queues.
    pub(crate) fn serves(&self, tx: &mpsc::Sender<TransportMessage>) -> bool {
        self.mailbox.upgrade().is_some_and(|m| m.same_channel(tx))
    }

    pub(crate) fn traffic_class(&self, raw: &[u8]) -> TrafficClass {
        traffic_class(raw, self.ifac.as_ref().map(|(key, size)| (&**key, *size)))
    }
}

fn path_request_destination() -> &'static [u8; 16] {
    static HASH: OnceLock<[u8; 16]> = OnceLock::new();
    HASH.get_or_init(|| {
        rns_identity::destination::Destination::hash_from_name_and_identity(
            "rnstransport.path.request",
            None,
        )
    })
}

/// The class `Transport.preprocess_inbound` gives a frame before ingress
/// limiting: announces, then anything addressed to the path-request
/// destination, then data (Transport.py:2024-2072). With the receiving
/// interface's IFAC key, only the header is unmasked; the tag is verified
/// later. Frames that cannot be read are data; the actor rejects them.
pub fn traffic_class(raw: &[u8], ifac: Option<(&[u8; 64], usize)>) -> TrafficClass {
    use rns_wire::constants::HEADER_MAXSIZE;
    let mut header = [0u8; HEADER_MAXSIZE];
    let len = match ifac {
        Some((key, size)) if raw.first().is_some_and(|b| b & 0x80 != 0) => {
            if size == 0 || size > 64 || raw.len() <= 2 + size {
                return TrafficClass::Data;
            }
            let body = &raw[2 + size..];
            let take = body.len().min(HEADER_MAXSIZE - 2);
            // HKDF output is prefix-stable, so the header mask needs no full-length expansion.
            let Ok(mask) =
                rns_crypto::hkdf::hkdf_sha256(2 + size + take, &raw[2..2 + size], Some(key), None)
            else {
                return TrafficClass::Data;
            };
            header[0] = (raw[0] ^ mask[0]) & 0x7f;
            header[1] = raw[1] ^ mask[1];
            for (i, byte) in body[..take].iter().enumerate() {
                header[2 + i] = byte ^ mask[2 + size + i];
            }
            2 + take
        }
        _ => {
            let len = raw.len().min(HEADER_MAXSIZE);
            header[..len].copy_from_slice(&raw[..len]);
            len
        }
    };
    let header = &header[..len];
    let Some(&flags) = header.first() else {
        return TrafficClass::Data;
    };
    if flags & 0x03 == rns_wire::flags::PacketType::Announce as u8 {
        return TrafficClass::Announce;
    }
    let destination = if flags & 0x40 == 0 {
        header.get(2..18)
    } else {
        header.get(18..34)
    };
    if destination == Some(&path_request_destination()[..]) {
        TrafficClass::PathRequest
    } else {
        TrafficClass::Data
    }
}
