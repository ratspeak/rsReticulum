//! Bounded native TX admission. A packet is admitted in full or refused before
//! any of its frames are sent. Callers serialize this queue and native writes
//! under the same lock, including readiness callbacks and connection retirement.
use std::collections::VecDeque;

const PACKET_CAPACITY: usize = 128;
const MAX_PACKET_FRAMES: usize = 64;
const MAX_PACKET_BYTES: usize = 4096;

#[derive(Default)]
pub(crate) struct PacketQueue {
    packets: VecDeque<VecDeque<Vec<u8>>>,
    accepted: u64,
    rejected: u64,
    sent_frames: u64,
    sent_bytes: u64,
    blocked: u64,
    high_water: usize,
    reported: (u64, u64),
}

impl PacketQueue {
    pub(crate) fn enqueue(&mut self, frames: Vec<Vec<u8>>) -> bool {
        if self.packets.len() >= PACKET_CAPACITY
            || frames.is_empty()
            || frames.len() > MAX_PACKET_FRAMES
            || frames.iter().map(Vec::len).sum::<usize>() > MAX_PACKET_BYTES
        {
            self.rejected = self.rejected.saturating_add(1);
            return false;
        }
        self.packets.push_back(frames.into());
        self.accepted = self.accepted.saturating_add(1);
        self.high_water = self.high_water.max(self.packets.len());
        true
    }

    /// Sends only the oldest frame. A refusal leaves it in place. Returns
    /// true only when one frame was accepted by the native stack.
    pub(crate) fn drain_one(&mut self, mut send: impl FnMut(&[u8]) -> bool) -> bool {
        let Some(packet) = self.packets.front_mut() else {
            return false;
        };
        let frame = packet.front().expect("admitted nonempty packet");
        if !send(frame) {
            self.blocked = self.blocked.saturating_add(1);
            return false;
        }
        self.sent_bytes = self.sent_bytes.saturating_add(frame.len() as u64);
        self.sent_frames = self.sent_frames.saturating_add(1);
        packet.pop_front();
        if packet.is_empty() {
            self.packets.pop_front();
        }
        true
    }

    pub(crate) fn len(&self) -> usize {
        self.packets.len()
    }

    pub(crate) fn report(&mut self, role: &'static str, value_limit: usize) {
        // Closed schema: no addresses, identifiers, payloads or native errors.
        // Sample admission milestones and exponentially spaced refusals.
        if (self.accepted != self.reported.0
            && (self.accepted == 1 || self.accepted.is_multiple_of(64)))
            || (self.rejected != self.reported.1 && self.rejected.is_power_of_two())
        {
            self.reported = (self.accepted, self.rejected);
            tracing::debug!(
                target: "rns_interface::ble_peer::transfer",
                role, value_limit, queued_packets = self.len(),
                high_water = self.high_water, accepted_packets = self.accepted,
                rejected_packets = self.rejected, sent_frames = self.sent_frames,
                sent_bytes = self.sent_bytes, backpressure = self.blocked,
                "BLE transmit queue counters"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backpressure_keeps_middle_frame_ahead_of_later_packets() {
        let mut q = PacketQueue::default();
        assert!(q.enqueue(vec![vec![0], vec![1], vec![2]]));
        let mut sent = Vec::new();
        assert!(q.drain_one(|f| {
            sent.push(f[0]);
            true
        }));
        assert!(!q.drain_one(|_| false));
        assert!(q.enqueue(vec![vec![3], vec![4]]));
        while q.drain_one(|f| {
            sent.push(f[0]);
            true
        }) {}
        assert_eq!(sent, [0, 1, 2, 3, 4]);
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn overflow_refuses_entire_new_packet_without_evicting_old_frames() {
        let mut q = PacketQueue::default();
        for n in 0..PACKET_CAPACITY {
            assert!(q.enqueue(vec![vec![n as u8], vec![0xff]]));
        }
        assert!(!q.enqueue(vec![vec![0xee]; 3]));
        let mut sent = Vec::new();
        while q.drain_one(|f| {
            sent.push(f[0]);
            true
        }) {}
        let expected: Vec<_> = (0..PACKET_CAPACITY).flat_map(|n| [n as u8, 0xff]).collect();
        assert_eq!(sent, expected);
        assert_eq!(q.rejected, 1);
    }

    #[test]
    fn bounds_and_retirement_do_not_replay_partial_packets() {
        let mut q = PacketQueue::default();
        assert!(!q.enqueue(vec![]));
        assert!(!q.enqueue(vec![vec![0]; MAX_PACKET_FRAMES + 1]));
        assert!(!q.enqueue(vec![vec![0; MAX_PACKET_BYTES + 1]]));
        assert!(q.enqueue(vec![vec![0], vec![1]]));
        assert!(q.drain_one(|_| true));
        q = PacketQueue::default(); // New connection owns a new queue.
        assert!(!q.drain_one(|_| panic!("retired frame replayed")));
        assert!(q.enqueue(vec![vec![9]]));
        assert!(q.drain_one(|f| {
            assert_eq!(f, [9]);
            true
        }));
    }
}
