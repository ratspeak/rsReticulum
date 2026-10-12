//! Bounded ownership of announcements refused before driver admission.
use super::*;
use crate::announce_dispatch::{AnnounceDispatchRequest, AnnounceDispatchResult};
use tokio::sync::oneshot;

const MAX_PENDING: usize = 256;
const MAX_POLL: usize = 32;
type Reply = Arc<std::sync::Mutex<Option<oneshot::Sender<AnnounceDispatchResult>>>>;

pub(super) struct PendingAnnounce {
    interface: InterfaceId,
    channel: mpsc::Sender<Bytes>,
    raw: Bytes,
    wire: Bytes,
    local_owner: Option<LocalAnnounceOwner>,
    route: Option<path_recovery::RouteVersion>,
    deadline: tokio::time::Instant,
    reply: Option<Reply>,
    attached: bool,
    cached: Option<([u8; 16], f64)>,
}

struct LocalAnnounceOwner {
    hash: [u8; 16],
    channel: Option<mpsc::WeakSender<crate::link_messages::DestinationEvent>>,
}

#[derive(Default)]
pub(super) struct AnnouncePressure {
    pub queued: u64,
    pub offered: u64,
    pub started: u64,
    pub expired: u64,
    pub coalesced: u64,
    pub retained: u64,
    pub retired: u64,
    last_report: f64,
}

pub(super) struct OfferedAnnounce {
    pub channel: mpsc::Sender<Bytes>,
    pub raw: Bytes,
    pub destination: [u8; 16],
    pub route: Option<path_recovery::RouteVersion>,
    pub policy: (u64, u64, Option<[u8; 64]>, usize),
    pub receipt: crate::background_egress::BackgroundOfferReceipt,
}

impl TransportActor {
    pub(super) fn cancel_background_announcements(&mut self) {
        // Retire starts already committed to a writer before revoking offers.
        self.process_background_starts();
        self.offered_announces.clear();
        for entry in self.interfaces.values_mut() {
            entry.announce_queue.clear();
        }
        let normal: Vec<_> = self
            .announce_table
            .iter()
            .filter_map(|(hash, entry)| (!entry.block_rebroadcast).then_some(*hash.as_bytes()))
            .collect();
        for hash in normal {
            self.announce_table.remove(&hash);
        }
        self.held_announces.clear();
    }

    pub(super) fn report_announce_pressure(&mut self, now: f64) {
        if now - self.announce_pressure.last_report < 60.0 {
            return;
        }
        self.announce_pressure.last_report = now;
        let queued: usize = self
            .interfaces
            .values()
            .map(|entry| entry.announce_queue.len())
            .sum();
        let oldest_age = self
            .interfaces
            .values()
            .flat_map(|entry| &entry.announce_queue)
            .map(|queued| (now - queued.time).max(0.0))
            .fold(0.0, f64::max);
        debug!(
            queued,
            offered = self.offered_announces.len(),
            retained = self.pending_announce_admissions.len(),
            oldest_age,
            queued_total = self.announce_pressure.queued,
            offered_total = self.announce_pressure.offered,
            started_total = self.announce_pressure.started,
            expired_total = self.announce_pressure.expired,
            coalesced_total = self.announce_pressure.coalesced,
            retained_total = self.announce_pressure.retained,
            retired_total = self.announce_pressure.retired,
            "announce admission pressure"
        );
    }

    /// Additive finite local-announcement admission lane. Obtain before run.
    pub fn announce_dispatch_handle(&self) -> crate::announce_dispatch::AnnounceDispatchHandle {
        crate::announce_dispatch::AnnounceDispatchHandle {
            tx: self.announce_dispatch_tx.clone(),
        }
    }

    pub(super) fn handle_announce_dispatch(&mut self, request: AnnounceDispatchRequest) {
        if request.result.is_closed() {
            return;
        }
        let Ok((header, _)) = rns_wire::header::PacketHeader::unpack(&request.raw) else {
            let _ = request.result.send(AnnounceDispatchResult::Invalid);
            return;
        };
        if header.flags.packet_type != rns_wire::flags::PacketType::Announce {
            let _ = request.result.send(AnnounceDispatchResult::Invalid);
            return;
        }
        if tokio::time::Instant::now() >= request.deadline {
            let _ = request.result.send(AnnounceDispatchResult::Expired);
            return;
        }
        self.traffic.record_tx(0, request.raw.len() as u64);
        self.packet_hashlist.insert(rns_wire::hash::packet_hash(
            &request.raw,
            header.flags.header_type,
        ));
        let targets: Vec<_> = if let Some(id) = request.attached_interface {
            self.interfaces
                .get(&id)
                .filter(|entry| entry.direction.outbound)
                .map(|_| vec![id])
                .unwrap_or_default()
        } else {
            self.interfaces
                .keys()
                .copied()
                .filter(|id| self.interface_allows_announce(*id, &header.destination_hash, None))
                .collect()
        };
        if targets.is_empty() {
            let _ = request
                .result
                .send(AnnounceDispatchResult::NoEligibleInterface);
            return;
        }
        let reply = Arc::new(std::sync::Mutex::new(Some(request.result)));
        let attached = request.attached_interface.is_some();
        for id in targets {
            let raw = if self.should_apply_delta(&header, id) {
                Bytes::from(self.mangle_hops(
                    &request.raw,
                    &header,
                    header.flags.header_type == rns_wire::flags::HeaderType::Header1,
                ))
            } else {
                request.raw.clone()
            };
            self.admit_announce(
                id,
                raw,
                request.deadline,
                Some(reply.clone()),
                attached,
                None,
            );
        }
        if Arc::strong_count(&reply) == 1 {
            Self::complete_announce_reply(&Some(reply), AnnounceDispatchResult::Expired);
        }
    }

    fn complete_announce_reply(reply: &Option<Reply>, outcome: AnnounceDispatchResult) {
        if let Some(reply) = reply {
            let mut sender = reply.lock().unwrap();
            if let Some(sender) = sender.take() {
                let _ = sender.send(outcome);
            }
        }
    }

    pub(super) fn send_or_retain_announce(
        &mut self,
        id: InterfaceId,
        raw: &[u8],
        attached: bool,
    ) -> bool {
        self.admit_announce(
            id,
            Bytes::copy_from_slice(raw),
            tokio::time::Instant::now() + Duration::from_secs(120),
            None,
            attached,
            None,
        )
    }

    pub(super) fn admit_cached_response(
        &mut self,
        hash: [u8; 16],
        id: InterfaceId,
        raw: &[u8],
        timestamp: f64,
    ) {
        let remaining = (timestamp + PATH_REQUEST_GATE_TIMEOUT - now_f64())
            .clamp(0.0, PATH_REQUEST_GATE_TIMEOUT);
        let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(remaining);
        self.admit_announce(
            id,
            Bytes::copy_from_slice(raw),
            deadline,
            None,
            true,
            Some((hash, timestamp)),
        );
    }

    fn finish_cached_response(
        &mut self,
        cached: Option<([u8; 16], f64)>,
        raw: &[u8],
        id: InterfaceId,
    ) {
        if let Some((hash, timestamp)) = cached
            && self.announce_table.get(&hash).is_some_and(|entry| {
                entry.block_rebroadcast
                    && entry.attached_interface == Some(id)
                    && entry.packet_raw == raw
                    && entry.timestamp.to_bits() == timestamp.to_bits()
            })
        {
            self.announce_table.remove(&hash);
            if let Some(held) = self.held_announces.remove(&hash) {
                self.announce_table.insert(hash, held);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_announce(
        &mut self,
        id: InterfaceId,
        raw: Bytes,
        deadline: tokio::time::Instant,
        reply: Option<Reply>,
        attached: bool,
        cached: Option<([u8; 16], f64)>,
    ) -> bool {
        if self.pending_announce_admissions.iter().any(|pending| {
            pending.interface == id
                && pending.raw == raw
                && pending.cached == cached
                && self
                    .interfaces
                    .get(&id)
                    .is_some_and(|entry| entry.tx.same_channel(&pending.channel))
        }) {
            // An explicit owner gets its own reply, but never a second runnable copy.
            if reply.is_some() {
                Self::complete_announce_reply(&reply, AnnounceDispatchResult::Expired);
            }
            return false;
        }
        if tokio::time::Instant::now() >= deadline {
            self.finish_cached_response(cached, &raw, id);
            return false;
        }
        let Some(entry) = self.interfaces.get(&id) else {
            self.finish_cached_response(cached, &raw, id);
            return false;
        };
        let wire = if let Some(key) = &entry.ifac_key {
            Bytes::from(crate::ifac::ifac_sign(&raw, key, entry.ifac_size))
        } else {
            raw.clone()
        };
        let destination = rns_wire::header::PacketHeader::unpack(&raw)
            .ok()
            .map(|(header, _)| header.destination_hash);
        let local_owner = destination
            .filter(|hash| self.local_destinations.contains(hash))
            .map(|hash| LocalAnnounceOwner {
                hash,
                channel: self
                    .destination_channels
                    .get(&hash)
                    .map(mpsc::Sender::downgrade),
            });
        let route = destination
            .and_then(|hash| self.path_table.get_live(&hash))
            .map(path_recovery::RouteVersion::from_path);
        let outcome = Self::try_prepared_announce(entry, &wire);
        let terminal_reason = match outcome {
            InterfaceSendOutcome::Closed => {
                Some(crate::messages::LinkEndpointTerminalReason::InterfaceClosed)
            }
            InterfaceSendOutcome::Offline if entry.role == InterfaceRole::LocalClient => {
                Some(crate::messages::LinkEndpointTerminalReason::InterfaceOffline)
            }
            _ => None,
        };
        if let Some(reason) = terminal_reason {
            self.finish_cached_response(cached, &raw, id);
            self.deregister_interface_with_link_reason(id, reason);
            return false;
        }
        if outcome == InterfaceSendOutcome::Sent {
            if let Some(entry) = self.interfaces.get_mut(&id) {
                entry.ingress.sent_announce();
            }
            Self::complete_announce_reply(&reply, AnnounceDispatchResult::Admitted);
            self.finish_cached_response(cached, &raw, id);
            return true;
        }
        if matches!(
            outcome,
            InterfaceSendOutcome::Full | InterfaceSendOutcome::Offline
        ) && self.pending_announce_admissions.len() < MAX_PENDING
            && let Some(entry) = self.interfaces.get(&id)
        {
            self.announce_pressure.retained += 1;
            self.pending_announce_admissions.push_back(PendingAnnounce {
                interface: id,
                channel: entry.tx.clone(),
                raw,
                wire,
                local_owner,
                route,
                deadline,
                reply,
                attached,
                cached,
            });
            return false;
        }
        // Cached responses already have a bounded-lifetime owner in the
        // announce table. If the shared retry lane is full, leave that owner
        // intact for the next announce job; its timestamp is never renewed.
        if cached.is_some()
            && matches!(
                outcome,
                InterfaceSendOutcome::Full | InterfaceSendOutcome::Offline
            )
        {
            return false;
        }
        self.announce_pressure.retired += 1;
        self.finish_cached_response(cached, &raw, id);
        false
    }

    fn try_prepared_announce(entry: &InterfaceEntry, wire: &Bytes) -> InterfaceSendOutcome {
        if !entry.direction.outbound {
            return InterfaceSendOutcome::NotOutbound;
        }
        if interface_marked_offline(entry) {
            return InterfaceSendOutcome::Offline;
        }
        match entry.tx.try_send(wire.clone()) {
            Ok(()) => InterfaceSendOutcome::Sent,
            Err(mpsc::error::TrySendError::Full(_)) => InterfaceSendOutcome::Full,
            Err(mpsc::error::TrySendError::Closed(_)) => InterfaceSendOutcome::Closed,
        }
    }

    pub(super) fn retire_announce_interface(&mut self, id: InterfaceId) {
        self.offered_announces.remove(&id);
        let mut retained = VecDeque::new();
        while let Some(pending) = self.pending_announce_admissions.pop_front() {
            if pending.interface == id {
                self.finish_cached_response(pending.cached, &pending.raw, id);
                if pending
                    .reply
                    .as_ref()
                    .is_some_and(|reply| Arc::strong_count(reply) == 1)
                {
                    Self::complete_announce_reply(&pending.reply, AnnounceDispatchResult::Expired);
                }
            } else {
                retained.push_back(pending);
            }
        }
        self.pending_announce_admissions = retained;
    }

    pub(super) fn process_pending_announce_admissions(&mut self) {
        for _ in 0..MAX_POLL.min(self.pending_announce_admissions.len()) {
            let Some(pending) = self.pending_announce_admissions.pop_front() else {
                break;
            };
            let terminal = self
                .interfaces
                .get(&pending.interface)
                .filter(|entry| entry.tx.same_channel(&pending.channel))
                .and_then(|entry| {
                    if entry.tx.is_closed() {
                        Some(crate::messages::LinkEndpointTerminalReason::InterfaceClosed)
                    } else if entry.role == InterfaceRole::LocalClient
                        && interface_marked_offline(entry)
                    {
                        Some(crate::messages::LinkEndpointTerminalReason::InterfaceOffline)
                    } else {
                        None
                    }
                });
            if let Some(reason) = terminal {
                self.finish_cached_response(pending.cached, &pending.raw, pending.interface);
                if pending
                    .reply
                    .as_ref()
                    .is_some_and(|reply| Arc::strong_count(reply) == 1)
                {
                    Self::complete_announce_reply(&pending.reply, AnnounceDispatchResult::Expired);
                }
                self.deregister_interface_with_link_reason(pending.interface, reason);
                continue;
            }
            let cancelled = pending.reply.as_ref().is_some_and(|reply| {
                reply
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(oneshot::Sender::is_closed)
            });
            let current = self
                .interfaces
                .get(&pending.interface)
                .is_some_and(|entry| {
                    entry.tx.same_channel(&pending.channel)
                        && entry.direction.outbound
                        && !entry.tx.is_closed()
                });
            let eligible = pending.attached
                || rns_wire::header::PacketHeader::unpack(&pending.raw)
                    .ok()
                    .is_some_and(|(header, _)| {
                        self.interface_allows_announce(
                            pending.interface,
                            &header.destination_hash,
                            None,
                        )
                    });
            let owner_live = pending.local_owner.as_ref().is_none_or(|owner| {
                self.local_destinations.contains(&owner.hash)
                    && match &owner.channel {
                        Some(channel) => channel.upgrade().is_some_and(|old| {
                            self.destination_channels
                                .get(&owner.hash)
                                .is_some_and(|current| current.same_channel(&old))
                        }),
                        None => !self.destination_channels.contains_key(&owner.hash),
                    }
            });
            let cached_current = pending.cached.is_none_or(|(hash, timestamp)| {
                self.announce_table.get(&hash).is_some_and(|entry| {
                    entry.block_rebroadcast
                        && entry.attached_interface == Some(pending.interface)
                        && entry.packet_raw == pending.raw
                        && entry.timestamp.to_bits() == timestamp.to_bits()
                }) && self
                    .path_table
                    .get_live(&hash)
                    .map(path_recovery::RouteVersion::from_path)
                    == pending.route
            });
            let route_current = pending.local_owner.is_some()
                || pending.route.is_none()
                || rns_wire::header::PacketHeader::unpack(&pending.raw)
                    .ok()
                    .is_some_and(|(header, _)| {
                        self.path_table
                            .get_live(&header.destination_hash)
                            .map(path_recovery::RouteVersion::from_path)
                            == pending.route
                    });
            if cancelled
                || !route_current
                || !current
                || !eligible
                || !owner_live
                || !cached_current
                || tokio::time::Instant::now() >= pending.deadline
            {
                if tokio::time::Instant::now() >= pending.deadline {
                    self.announce_pressure.expired += 1;
                } else {
                    self.announce_pressure.retired += 1;
                }
                self.finish_cached_response(pending.cached, &pending.raw, pending.interface);
                if pending
                    .reply
                    .as_ref()
                    .is_some_and(|reply| Arc::strong_count(reply) == 1)
                {
                    Self::complete_announce_reply(&pending.reply, AnnounceDispatchResult::Expired);
                }
                continue;
            }
            if self
                .interfaces
                .get(&pending.interface)
                .is_some_and(interface_marked_offline)
            {
                self.pending_announce_admissions.push_back(pending);
                continue;
            }
            match Self::try_prepared_announce(&self.interfaces[&pending.interface], &pending.wire) {
                InterfaceSendOutcome::Sent => {
                    if let Some(entry) = self.interfaces.get_mut(&pending.interface) {
                        entry.ingress.sent_announce();
                    }
                    Self::complete_announce_reply(&pending.reply, AnnounceDispatchResult::Admitted);
                    self.finish_cached_response(pending.cached, &pending.raw, pending.interface);
                }
                InterfaceSendOutcome::Full | InterfaceSendOutcome::Offline => {
                    self.pending_announce_admissions.push_back(pending)
                }
                _ => {
                    self.finish_cached_response(pending.cached, &pending.raw, pending.interface);
                    if pending
                        .reply
                        .as_ref()
                        .is_some_and(|reply| Arc::strong_count(reply) == 1)
                    {
                        Self::complete_announce_reply(
                            &pending.reply,
                            AnnounceDispatchResult::Expired,
                        );
                    }
                }
            }
        }
    }

    pub(super) fn process_background_starts(&mut self) {
        let ids: Vec<_> = self.offered_announces.keys().copied().collect();
        for id in ids {
            let mut offered = self.offered_announces.remove(&id).unwrap();
            match offered.receipt.started.try_recv() {
                Ok(started) => {
                    self.announce_pressure.started += 1;
                    if let Some(entry) = self
                        .interfaces
                        .get_mut(&id)
                        .filter(|entry| entry.tx.same_channel(&offered.channel))
                    {
                        let delay = offered.raw.len() as f64 * 8.0
                            / entry.bitrate.max(1) as f64
                            / entry.announce_cap.max(0.001);
                        entry.announce_allowed_at = entry.announce_allowed_at.max(started + delay);
                        entry
                            .announce_queue
                            .retain(|queued| queued.raw != offered.raw);
                        entry.ingress.sent_announce();
                    }
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    let current = self.interfaces.get(&id).is_some_and(|entry| {
                        entry.tx.same_channel(&offered.channel)
                            && entry
                                .announce_queue
                                .iter()
                                .any(|queued| queued.raw == offered.raw)
                    });
                    let route = self
                        .path_table
                        .get_live(&offered.destination)
                        .map(path_recovery::RouteVersion::from_path);
                    let eligible = self.interface_allows_announce(id, &offered.destination, None);
                    let policy_current = self.interfaces.get(&id).is_some_and(|entry| {
                        (
                            entry.bitrate,
                            entry.announce_cap.to_bits(),
                            entry.ifac_key,
                            entry.ifac_size,
                        ) == offered.policy
                            && now_f64() >= entry.announce_allowed_at
                            && !interface_marked_offline(entry)
                    });
                    if current && route == offered.route && eligible && policy_current {
                        self.offered_announces.insert(id, offered);
                    } else if current
                        && (route != offered.route || !eligible)
                        && let Some(entry) = self.interfaces.get_mut(&id)
                    {
                        entry
                            .announce_queue
                            .retain(|queued| queued.raw != offered.raw);
                        self.announce_pressure.retired += 1;
                    }
                }
                Err(oneshot::error::TryRecvError::Closed) => {}
            }
        }
    }
}
