use super::*;
use crate::now_f64;

impl TransportActor {
    pub(super) fn on_tick(&mut self) {
        let now = now_f64();

        self.process_background_starts();

        // Established-Link packets that encountered temporary interface
        // backpressure are retained per Link and retried in FIFO order.
        self.drain_link_endpoint_egress();
        self.process_pending_announce_admissions();
        self.report_announce_pressure(now);

        // Startup grace delays cache cleanup so freshly restored entries
        // aren't immediately aged out before the first traffic arrives.
        if !self.startup_complete
            && self.startup_time > 0.0
            && now - self.startup_time >= STARTUP_GRACE_PERIOD
        {
            self.startup_complete = true;
            debug!("startup grace period complete, cache cleaning enabled");
        }

        // Periodic routing-state flush. Gated on `state_dirty`. Required in
        // addition to `on_shutdown` because mobile force-quit kills the
        // process without delivering Shutdown. Hashlist is saved separately.
        if self.storage_dir.is_some()
            && self.state_dirty
            && now - self.last_state_save >= STATE_SAVE_INTERVAL_SECS
        {
            // Async: the fsync chain (F_FULLFSYNC per file on macOS) stalls
            // the actor for seconds if run inline, starving control queries
            // and inbound routing.
            self.save_routing_state_async();
        }

        if now - self.last_known_destinations_flush >= KD_FLUSH_INTERVAL {
            self.flush_known_destinations();
        }

        self.flush_cached_announces(now);

        if now - self.last_tables_cull >= TABLES_CULL_INTERVAL {
            self.cull_path_table(now);
            self.reverse_table.cull_expired();
            self.tunnel_table.cull_expired();
            self.cull_stale_tunnel_paths(now);
            self.cull_path_interface_suppressions(now);
            self.cull_local_link_route_attempts(now);
            // A persisted path whose interface never returns expires too.
            self.pending_path_entries
                .retain(|entry| entry.expires > now);

            // Drop entries pointing to interfaces that have gone away —
            // those routes could never be used anyway.
            let active_interfaces: HashSet<InterfaceId> = self.interfaces.keys().copied().collect();
            self.reverse_table.cull_dead_interfaces(&active_interfaces);
            self.link_table.cull_dead_interfaces(&active_interfaces);

            // Failed link establishment can mean either a stale path or a
            // topology change. Queue rediscovery so automated path requests
            // are bounded and throttled like upstream Reticulum.
            let (_, expired_links) = self.link_table.cull_stale(LINK_TIMEOUT);
            let mut queued_dests = HashSet::new();
            for expired_link in expired_links {
                if let Some(request) = self.rediscovery_request_for_expired_link(expired_link, now)
                    && queued_dests.insert(request.destination_hash)
                {
                    self.queue_discovery_path_request(
                        request.destination_hash,
                        request.blocked_interface,
                        now,
                    );
                }
            }

            // Cull may have removed path/tunnel entries — flag for save so
            // the on-disk file reflects the current routing state. False
            // positives (cull found nothing) cost one no-op file rewrite at
            // the next periodic flush.
            self.state_dirty = true;
            self.last_tables_cull = now;
        }

        if now - self.last_announces_check >= ANNOUNCES_CHECK_INTERVAL {
            let due = self.announce_table.due_for_retransmit(now);
            for hash in due {
                let send_info = self.announce_table.get(&hash).map(|e| {
                    (
                        e.packet_raw.clone(),
                        e.source_interface,
                        e.attached_interface,
                        e.block_rebroadcast,
                    )
                });
                if let Some((raw, _source_iface, Some(attached_interface), true)) = send_info {
                    let timestamp = self.announce_table.get(&hash).unwrap().timestamp;
                    self.admit_cached_response(
                        *hash.as_bytes(),
                        attached_interface,
                        &raw,
                        timestamp,
                    );
                    continue;
                }
                if let Some(entry) = self.announce_table.get_mut(&hash) {
                    entry.retries += 1;
                    entry.retransmit_timeout = now + PATHFINDER_G + PATHFINDER_RW;
                }
                // The helper excludes an exact shared IPC peer and applies
                // mode policy. A broadcast radio may need same-interface
                // retransmission to reach a different physical neighbor.
                if let Some((raw, source_iface, _, _)) = send_info {
                    self.broadcast_announce_on_interfaces(&raw, source_iface);
                }
            }
            self.announce_table.cull_exhausted(PATHFINDER_R);
            self.last_announces_check = now;
        }

        if now - self.last_held_announce_check >= IC_HELD_RELEASE_INTERVAL {
            self.process_held_announces(now);
            self.last_held_announce_check = now;
        }

        self.cull_announce_queues(now);

        if now - self.last_blackhole_check >= BLACKHOLE_CHECK_INTERVAL {
            if self.blackhole_table.cull_expired() > 0 {
                self.publish_blackhole_snapshot();
            }
            self.state_dirty = true;
            self.last_blackhole_check = now;
        }

        if now - self.last_rate_cull >= RATE_TABLE_CULL_INTERVAL {
            self.rate_table.cull(now, self.rate_table_retain);
            self.last_rate_cull = now;
        }

        self.count_traffic(now);

        if now - self.last_links_check >= LINKS_CHECK_INTERVAL {
            self.traffic.update_speeds();
            self.last_links_check = now;
        }

        if now - self.last_receipts_check >= RECEIPTS_CHECK_INTERVAL {
            let mut concluded = Vec::new();
            for (key, receipt) in &mut self.receipt_table {
                let timed_out = receipt.status == ReceiptStatus::Sent && receipt.is_timed_out();
                if timed_out {
                    receipt.fail();
                }
                if receipt.status != ReceiptStatus::Sent {
                    let update = if timed_out {
                        crate::messages::ReceiptUpdate::TimedOut
                    } else {
                        match receipt.status {
                            ReceiptStatus::Delivered => receipt.get_rtt().map_or(
                                crate::messages::ReceiptUpdate::Failed,
                                |rtt| crate::messages::ReceiptUpdate::Delivered {
                                    rtt,
                                    proof_hash: None,
                                    metrics: Default::default(),
                                },
                            ),
                            ReceiptStatus::Culled => crate::messages::ReceiptUpdate::Culled,
                            ReceiptStatus::Failed | ReceiptStatus::Receiving => {
                                crate::messages::ReceiptUpdate::Failed
                            }
                            ReceiptStatus::Sent => continue,
                        }
                    };
                    concluded.push((*key, update));
                }
            }
            // Only in-flight (Sent) receipts are worth keeping; concluded
            // ones (Delivered/Failed/Culled) were already signalled out.
            for (key, update) in concluded {
                self.receipt_table.remove(&key);
                self.receipt_msg_ids.remove(&key);
                self.receipt_proof_txs.remove(&key);
                if let Some(status_tx) = self.receipt_updates.remove(&key) {
                    status_tx.send_replace(update);
                }
            }
            let excess = self.receipt_table.len().saturating_sub(MAX_RECEIPTS);
            if excess > 0 {
                // Cull the oldest in one sorted pass — a min-scan per
                // eviction is O(n·k) on burst overflow.
                let mut by_age: Vec<([u8; 16], std::time::Instant)> = self
                    .receipt_table
                    .iter()
                    .map(|(k, r)| (*k, r.sent_at))
                    .collect();
                by_age.sort_unstable_by_key(|(_, sent_at)| *sent_at);
                for (key, _) in by_age.into_iter().take(excess) {
                    if let Some(mut receipt) = self.receipt_table.remove(&key) {
                        receipt.cull();
                    }
                    self.receipt_msg_ids.remove(&key);
                    self.receipt_proof_txs.remove(&key);
                    if let Some(status_tx) = self.receipt_updates.remove(&key) {
                        status_tx.send_replace(crate::messages::ReceiptUpdate::Culled);
                    }
                }
            }
            self.last_receipts_check = now;
        }

        self.packet_hashlist.rotate_if_full();

        if now - self.last_known_destinations_clean >= KNOWN_DESTINATIONS_INTERVAL {
            self.cleanup_known_destinations(now);
            self.last_known_destinations_clean = now;
        }

        // Cached-announce clean. Outside the startup_complete gate, as Python's
        // jobs thread runs it unconditionally; storage init defers the first one.
        // Stamped before the clean, so one that is skipped waits a full interval.
        if now - self.last_announce_cache_sweep >= ANNOUNCE_CACHE_SWEEP_INTERVAL {
            self.last_announce_cache_sweep = now;
            self.clean_announce_cache();
        }

        self.expire_path_waiters(now);

        // Drop pending path-request markers after the upstream gate timeout.
        self.path_requests
            .retain(|_, last| now - *last < PATH_REQUEST_GATE_TIMEOUT);
        self.inflight_path_requests
            .retain(|_, since| now <= *since + PATH_REQUEST_GATE_TIMEOUT);
        self.cull_recursive_discovery(now);
        if self.discovery_pr_tags.len() > MAX_DISCOVERY_PR_TAGS {
            self.discovery_pr_tags_prev = std::mem::take(&mut self.discovery_pr_tags);
        }

        self.process_pending_discovery_path_requests(now);
        self.process_pending_path_request_admissions(now);
        self.process_announce_queues(now);
    }

    /// Transport.py A leaf or shared-instance client lingers
    /// never-used paths for 12 minutes, a transport node for 1.75 hours
    /// (Transport.py).
    fn cull_path_table(&mut self, now: f64) {
        let linger = if !self.is_transport_enabled || self.shared_instance_client_mode {
            UNUSED_PATH_LINGER_LEAF
        } else {
            UNUSED_PATH_LINGER
        };
        let check_unused = now > self.path_pool_last_checked + PATH_POOL_CHECK_INTERVAL;
        let interfaces = &self.interfaces;
        let (removed, unused) = self.path_table.cull(now, linger, check_unused, |id| {
            interfaces.get(&id).map(|entry| entry.bitrate)
        });
        if let Some(unused) = unused {
            self.path_pool_last_checked = now;
            if unused > PATH_POOL_UNUSED_TARGET {
                debug!(
                    culled = unused - PATH_POOL_UNUSED_TARGET,
                    "culled never-used paths to reach the pool size target"
                );
            }
        }
        if removed > 0 {
            pathing!(removed, "removed stale paths");
        }
    }

    pub(super) fn queue_discovery_path_request(
        &mut self,
        destination_hash: [u8; 16],
        blocked_interface: Option<InterfaceId>,
        now: f64,
    ) -> bool {
        // Transport.py: a destination is queued once.
        if self
            .pending_discovery_prs
            .iter()
            .any(|queued| queued.destination_hash == destination_hash)
        {
            return false;
        }
        if self.pending_discovery_prs.len() >= MAX_QUEUED_DISCOVERY_PRS {
            trace!(
                dest = hex::encode(destination_hash),
                "dropping queued discovery path request because queue is full"
            );
            return false;
        }

        let was_empty = self.pending_discovery_prs.is_empty();
        self.pending_discovery_prs
            .push_back(PendingDiscoveryPathRequest {
                destination_hash,
                blocked_interface,
            });
        if was_empty {
            self.last_discovery_pr_tx = now;
        }
        true
    }

    pub(super) fn process_pending_discovery_path_requests(&mut self, now: f64) {
        if self.pending_discovery_prs.is_empty() {
            return;
        }
        if now - self.last_discovery_pr_tx < DISCOVERY_PR_TX_THROTTLE {
            return;
        }

        let Some(request) = self.pending_discovery_prs.pop_front() else {
            return;
        };
        self.last_discovery_pr_tx = now;

        // Transport.py: one tag, stamped once when stamping is on,
        // on every interface but the blocked one.
        let request_tag = rns_crypto::random::random_bytes(16);
        self.forward_path_request(
            request.destination_hash,
            request.blocked_interface,
            Some(&request_tag),
            false,
        );
    }

    #[cfg(test)]
    pub(super) fn handle_expired_unvalidated_link(
        &mut self,
        expired_link: crate::link_table::ExpiredLink,
        now: f64,
    ) {
        if let Some(request) = self.rediscovery_request_for_expired_link(expired_link, now) {
            self.queue_discovery_path_request(
                request.destination_hash,
                request.blocked_interface,
                now,
            );
        }
    }

    fn rediscovery_request_for_expired_link(
        &mut self,
        expired_link: crate::link_table::ExpiredLink,
        now: f64,
    ) -> Option<PendingDiscoveryPathRequest> {
        let destination_hash = expired_link.destination_hash;
        let last_path_request = self
            .path_requests
            .get(&destination_hash)
            .copied()
            .unwrap_or(0.0);
        let path_request_throttle = now - last_path_request < PATH_REQUEST_MI;

        let mut blocked_interface = None;
        let mut should_request = false;

        if !self.path_table.has_path(&destination_hash) {
            should_request = true;
        } else if !path_request_throttle {
            if expired_link.taken_hops == 0 {
                should_request = true;
            } else if self.path_table.hops_to(&destination_hash) == Some(1)
                || expired_link.taken_hops == 1
            {
                should_request = true;
                blocked_interface = Some(expired_link.receiving_interface);
                self.mark_failed_link_path_unresponsive(&expired_link);
            }
        }

        if !should_request {
            return None;
        }

        if !self.is_transport_enabled {
            self.path_table.expire(&destination_hash);
        }

        pathing!(
            dest = hex::encode(destination_hash),
            blocked_interface,
            "unvalidated link expired -- queued re-discovery"
        );

        Some(PendingDiscoveryPathRequest {
            destination_hash,
            blocked_interface,
        })
    }

    fn mark_failed_link_path_unresponsive(
        &mut self,
        expired_link: &crate::link_table::ExpiredLink,
    ) {
        if !self.is_transport_enabled {
            return;
        }
        let receiving_is_boundary = self
            .interfaces
            .get(&expired_link.receiving_interface)
            .is_some_and(|entry| entry.mode == InterfaceMode::Boundary);
        if !receiving_is_boundary {
            self.path_table
                .set_state(expired_link.destination_hash, PathState::Unresponsive);
        }
    }

    /// Called on background → foreground. Resets every `last_*_check` so the
    /// next `on_tick` runs all maintenance paths in one go.
    pub(super) fn on_resume(&mut self) {
        debug!("transport actor resume — forcing maintenance pass");
        self.last_tables_cull = 0.0;
        self.last_links_check = 0.0;
        self.last_receipts_check = 0.0;
        self.last_announces_check = 0.0;
        self.last_announce_cache_sweep = 0.0;
        self.last_known_destinations_clean = 0.0;
        self.last_blackhole_check = 0.0;
        self.last_rate_cull = 0.0;
        self.last_held_announce_check = 0.0;
    }

    /// Python `Interface.process_announce_queue` (Interface.py):
    /// drop stale entries, send the fewest-hops, oldest entry, and consume it
    /// whatever the send outcome. Python re-arms a timer at each `wait_time`;
    /// here each tick sends every entry whose slot has passed, chaining slots
    /// from the previous one, up to `MAX_ANNOUNCE_DRAIN_PER_TICK`. A zero
    /// bitrate empties the queue, as Python's ZeroDivisionError handler does.
    pub(super) fn process_announce_queues(&mut self, now: f64) {
        let iface_ids: Vec<InterfaceId> = self.interfaces.keys().copied().collect();
        for iface_id in iface_ids {
            for _ in 0..MAX_ANNOUNCE_DRAIN_PER_TICK {
                if !self.drain_one_queued_announce(iface_id, now) {
                    break;
                }
            }
        }
    }

    /// Send at most one queued announce; `true` when another may follow now.
    fn drain_one_queued_announce(&mut self, iface_id: InterfaceId, now: f64) -> bool {
        let Some(entry) = self.interfaces.get_mut(&iface_id) else {
            return false;
        };
        if entry.announce_queue.is_empty()
            || now < entry.announce_allowed_at
            || self.offered_announces.contains_key(&iface_id)
        {
            return false;
        }
        let before = entry.announce_queue.len();
        entry
            .announce_queue
            .retain(|a| now - a.time < QUEUED_ANNOUNCE_LIFE);
        self.announce_pressure.expired += (before - entry.announce_queue.len()) as u64;
        if entry.announce_queue.is_empty() {
            return false;
        }
        if entry.bitrate == 0 {
            tracing::error!(
                interface = %entry.name,
                "announce queue cleared: interface bitrate is zero"
            );
            entry.announce_queue.clear();
            return false;
        }

        let min_hops = entry
            .announce_queue
            .iter()
            .map(|e| e.hops)
            .min()
            .unwrap_or(0);
        let Some((idx, _)) = entry
            .announce_queue
            .iter()
            .enumerate()
            .filter(|(_, e)| e.hops == min_hops)
            .min_by(|(_, a), (_, b)| a.time.total_cmp(&b.time))
        else {
            return false;
        };
        // A background lane keeps the entry queued until its writer starts it;
        // the start then consumes it and opens the cap window.
        if let Some(background) = crate::background_egress::lookup(&entry.tx) {
            let queued = &entry.announce_queue[idx];
            let raw = queued.raw.clone();
            if !entry.accepts_clear_packet(raw.len()) {
                entry.announce_queue.remove(idx);
                return true;
            }
            let bytes = if let Some(key) = &entry.ifac_key {
                let Ok(wire) = crate::ifac::try_ifac_sign(&raw, key, entry.ifac_size) else {
                    entry.announce_queue.remove(idx);
                    return true;
                };
                Bytes::from(wire)
            } else {
                raw.clone()
            };
            let expires = queued.time + QUEUED_ANNOUNCE_LIFE;
            let destination = queued.destination_hash;
            if let Some(receipt) =
                background.try_offer_owned(bytes, expires, now, entry.owner.clone())
            {
                self.announce_pressure.offered += 1;
                let policy = (
                    entry.bitrate,
                    entry.announce_cap.to_bits(),
                    entry.ifac_key.clone(),
                    entry.ifac_size,
                );
                let channel = entry.tx.clone();
                let route = self
                    .path_table
                    .get_live(&destination)
                    .map(path_recovery::RouteVersion::from_path);
                self.offered_announces.insert(
                    iface_id,
                    announce_admission::OfferedAnnounce {
                        channel,
                        raw,
                        destination,
                        route,
                        policy,
                        receipt,
                    },
                );
            }
            return false;
        }

        let raw = entry.announce_queue.remove(idx).raw;
        // Chain from the previous slot within one tick so throughput follows
        // Python's timer; an idle queue starts from now.
        let slot = if now - entry.announce_allowed_at < JOB_INTERVAL_MS as f64 / 1000.0 {
            entry.announce_allowed_at
        } else {
            now
        };
        entry.announce_allowed_at = slot + announce_wait_time(entry, raw.len());

        self.send_queued_announce(iface_id, &raw);
        now >= self
            .interfaces
            .get(&iface_id)
            .map_or(f64::INFINITY, |entry| entry.announce_allowed_at)
    }

    /// Python's interface job (Transport.py): re-evaluate both burst
    /// limiters, then release at most one held announce per interface.
    fn process_held_announces(&mut self, _now: f64) {
        let iface_ids: Vec<InterfaceId> = self.interfaces.keys().copied().collect();
        for iface_id in iface_ids {
            let released = self.interfaces.get_mut(&iface_id).and_then(|iface| {
                iface.ingress.should_ingress_limit();
                iface.ingress.should_ingress_limit_pr();
                iface.ingress.try_release_held()
            });

            if let Some(announce) = released {
                pathing!(
                    dest = hex::encode(announce.destination_hash),
                    interface = iface_id,
                    "releasing held announce"
                );

                // Released announces re-enter as ingress limited (Interface.py).
                self.inbound_rx.push_ingress_limited(
                    &self.inbound_queues,
                    crate::inbound_queues::Queued::ReleasedAnnounce(announce),
                );
            }
        }
    }

    pub(super) fn cull_stale_tunnel_paths(&mut self, now: f64) {
        let mut removed = 0usize;
        for (tunnel_id, tunnel) in self.tunnel_table.iter_mut() {
            let stale: Vec<[u8; 16]> = tunnel
                .tunnel_paths
                .iter()
                .filter_map(|(dest_hash, tunnel_path)| {
                    if now > tunnel_path.timestamp + TUNNEL_PATH_TIMEOUT as f64 {
                        return Some(*dest_hash);
                    }

                    let active = self.path_table.get_live(dest_hash)?;
                    let current_timebase =
                        path_timebase_from_random_blobs(active.random_blobs.iter());
                    let tunnel_timebase =
                        path_timebase_from_random_blobs(tunnel_path.random_blobs.iter());
                    (current_timebase > tunnel_timebase).then_some(*dest_hash)
                })
                .collect();

            for dest_hash in stale {
                tunnel.tunnel_paths.remove(&dest_hash);
                removed += 1;
                debug!(
                    dest = hex::encode(dest_hash),
                    tunnel = hex::encode(&tunnel_id[..16]),
                    "removed stale tunnel path"
                );
            }
        }

        if removed > 0 {
            self.state_dirty = true;
        }
    }

    /// Sweep `recent_announces`, mirroring Python
    /// `Identity.clean_known_destinations`: retained + pathed entries are
    /// kept; a pathless entry is stale when never used and announced more than
    /// `UNUSED_DESTINATION_LINGER` ago, or when more than
    /// `DESTINATION_TIMEOUT * 1.25` has passed since its use marker. A
    /// never-used entry's marker is 0, so it is stale on any pass.
    pub(super) fn cleanup_known_destinations(&mut self, now: f64) {
        let used_threshold = DESTINATION_TIMEOUT as f64 * 1.25;

        let before = self.recent_announces.len();
        // Python loads persisted paths at start; Rust stages them until their
        // interface registers, so a staged path counts as a path here.
        let pending: HashSet<&[u8]> = self
            .pending_path_entries
            .iter()
            .map(|pe| pe.destination_hash.as_slice())
            .collect();
        // Collect into a Vec; the has-path borrow on path_table fights an
        // in-place `retain` closure on recent_announces.
        let to_drop: Vec<[u8; 16]> = self
            .recent_announces
            .values()
            .filter_map(|a| {
                if a.retained {
                    return None;
                }
                if self.path_table.has_path(&a.dest_hash)
                    || pending.contains(a.dest_hash.as_slice())
                {
                    return None;
                }
                let unused_for = now - a.last_used.unwrap_or(0.0);
                let stale = (a.last_used.is_none()
                    && now - a.timestamp > UNUSED_DESTINATION_LINGER)
                    || unused_for > used_threshold;
                if stale { Some(a.dest_hash) } else { None }
            })
            .collect();

        if !to_drop.is_empty() {
            for hash in &to_drop {
                self.recent_announces.remove(hash);
                self.kd.pending.mark_deleted(*hash);
            }
            self.state_dirty = true;
            pathing!(
                removed = to_drop.len(),
                remaining = self.recent_announces.len(),
                before,
                "known-destinations cleanup swept pathless entries"
            );
        }

        // Identity.clean_known_destinations: expire stored ratchets, evict them
        // from memory, then flush.
        let cutoff = now - rns_wire::constants::RATCHET_EXPIRY as f64;
        let mut expired = 0usize;
        for announce in self.recent_announces.values_mut() {
            if announce.ratchet.is_some() && announce.ratchet_received.unwrap_or(now) < cutoff {
                announce.ratchet = None;
                announce.ratchet_received = None;
                expired += 1;
            }
        }
        if expired > 0 {
            debug!(
                expired,
                "known-destinations cleanup evicted expired ratchets"
            );
        }
        if !self.shared_instance_client_mode {
            self.kd.expire_ratchets(cutoff);
            self.flush_known_destinations();
        }
    }

    /// Drop queued announces older than QUEUED_ANNOUNCE_LIFE.
    pub(super) fn cull_announce_queues(&mut self, now: f64) {
        for iface in self.interfaces.values_mut() {
            let before = iface.announce_queue.len();
            iface
                .announce_queue
                .retain(|entry| now - entry.time < QUEUED_ANNOUNCE_LIFE);
            self.announce_pressure.expired += (before - iface.announce_queue.len()) as u64;
        }
    }

    /// On interface drop the interface names no tunnel, and the tunnels
    /// bound to it keep their paths for their next synthesis.
    pub(super) fn void_tunnel_interface(&mut self, interface_id: InterfaceId) {
        let voided = self.tunnel_table.void_interface(interface_id);
        if voided > 0 {
            debug!(interface_id, voided, "voided tunnel interface");
            self.state_dirty = true;
        }
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use crate::actor::RecentAnnounce;
    use crate::path_table::PathEntry;

    fn insert_entry_with_last_used(
        actor: &mut TransportActor,
        hash: u8,
        timestamp: f64,
        retained: bool,
        last_used: Option<f64>,
    ) {
        let entry = RecentAnnounce {
            dest_hash: [hash; 16],
            hops: 0,
            app_data: None,
            timestamp,
            public_key: None,
            ratchet: None,
            ratchet_received: None,
            packet_hash: None,
            is_path_response: false,
            retained,
            last_used,
            name_hash: [0u8; 10],
            stamp: None,
            stamp_value: 0.0,
            lr_cost: None,
        };
        actor.recent_announces.insert(entry.dest_hash, entry);
    }

    fn insert_entry(actor: &mut TransportActor, hash: u8, timestamp: f64, retained: bool) {
        insert_entry_with_last_used(actor, hash, timestamp, retained, None);
    }

    fn insert_used_entry(actor: &mut TransportActor, hash: u8, timestamp: f64, last_used: f64) {
        insert_entry_with_last_used(actor, hash, timestamp, false, Some(last_used));
    }

    #[test]
    fn retained_survives_cleanup() {
        let (mut actor, _tx) = TransportActor::new();
        let now = 10_000.0;
        insert_entry(&mut actor, 0x01, 0.0, /*retained=*/ true);
        actor.cleanup_known_destinations(now);
        assert_eq!(actor.recent_announces.len(), 1);
    }

    #[test]
    fn pathed_entry_survives_cleanup() {
        let (mut actor, _tx) = TransportActor::new();
        let now = 10_000.0;
        let dest = [0x02; 16];
        insert_entry(&mut actor, 0x02, 0.0, /*retained=*/ false);
        actor
            .path_table
            .insert(dest, PathEntry::new(None, 1, 0, InterfaceMode::Gateway));
        actor.cleanup_known_destinations(now);
        assert_eq!(actor.recent_announces.len(), 1);
    }

    #[test]
    fn staged_persisted_path_keeps_entry_through_cleanup() {
        let (mut actor, _tx) = TransportActor::new();
        let now = 10_000_000.0;
        insert_entry(&mut actor, 0x04, 0.0, /*retained=*/ false);
        actor
            .pending_path_entries
            .push(crate::persistence::PersistedPathEntry {
                used: None,
                destination_hash: vec![0x04; 16],
                timestamp: now,
                next_hop: None,
                hops: 1,
                expires: now + 1_000.0,
                random_blobs: Vec::new(),
                interface_id: 0,
                interface_name: Some("not yet registered".into()),
                interface_hash: None,
                packet_hash: None,
            });
        actor.cleanup_known_destinations(now);
        assert_eq!(actor.recent_announces.len(), 1);
    }

    #[test]
    fn pathless_never_used_kept_inside_linger() {
        let (mut actor, _tx) = TransportActor::new();
        let now = 10_000.0;
        insert_entry(
            &mut actor,
            0x03,
            now - UNUSED_DESTINATION_LINGER + 1.0,
            /*retained=*/ false,
        );

        actor.cleanup_known_destinations(now);
        assert_eq!(actor.recent_announces.len(), 1);
    }

    #[test]
    fn pathless_never_used_reaped_after_linger() {
        let (mut actor, _tx) = TransportActor::new();
        let now = 10_000.0;
        insert_entry(
            &mut actor,
            0x05,
            now - UNUSED_DESTINATION_LINGER - 1.0,
            /*retained=*/ false,
        );

        actor.cleanup_known_destinations(now);
        assert!(actor.recent_announces.is_empty());
    }

    /// Transport.py: a destination already waiting in the
    /// discovery queue is not queued again.
    #[test]
    fn discovery_queue_holds_a_destination_once() {
        let (mut actor, _tx) = TransportActor::new();
        assert!(actor.queue_discovery_path_request([0x31; 16], None, 1.0));
        assert!(!actor.queue_discovery_path_request([0x31; 16], Some(2), 2.0));
        assert!(actor.queue_discovery_path_request([0x32; 16], None, 3.0));
        assert_eq!(actor.pending_discovery_prs.len(), 2);
    }

    /// Transport.py: one cull pass removes every
    /// reverse entry past REVERSE_TIMEOUT, with no batch cap.
    #[test]
    fn one_cull_removes_every_stale_reverse_entry() {
        let start = now_f64();
        let clock = crate::test_clock::Clock::at(start);
        let (mut actor, _tx) = TransportActor::new();
        let (iface_tx, _iface_rx) = tokio::sync::mpsc::channel(1);
        actor.interfaces.insert(
            1,
            InterfaceEntry::new(
                "a".into(),
                InterfaceMode::Full,
                crate::constants::InterfaceDirection::bidirectional(),
                1_000_000,
                500,
                iface_tx,
            ),
        );
        for i in 0..10_000u32 {
            let mut hash = [0u8; 16];
            hash[..4].copy_from_slice(&i.to_be_bytes());
            actor.reverse_table.insert(hash, 1, 1);
        }
        clock.set(start + REVERSE_TIMEOUT as f64 + 1.0);
        actor.reverse_table.insert([0xFF; 16], 1, 1);
        actor.last_tables_cull = 0.0;
        actor.on_tick();
        assert_eq!(actor.reverse_table.len(), 1);
    }

    #[test]
    fn pathless_used_survives_destination_timeout_idle() {
        let (mut actor, _tx) = TransportActor::new();
        let now = 10_000_000.0;
        let timeout = DESTINATION_TIMEOUT as f64;
        // Announce far past linger; 7 d idle since use is inside the
        // 7 d * 1.25 window, so the use pin keeps it alive.
        insert_used_entry(&mut actor, 0x07, now - timeout * 2.0, now - timeout);

        actor.cleanup_known_destinations(now);
        assert_eq!(actor.recent_announces.len(), 1);
    }

    #[test]
    fn pathless_used_reaped_past_destination_timeout_x125() {
        let (mut actor, _tx) = TransportActor::new();
        let now = 10_000_000.0;
        let threshold = DESTINATION_TIMEOUT as f64 * 1.25;
        insert_used_entry(
            &mut actor,
            0x09,
            now - threshold - 2.0,
            now - threshold - 1.0,
        );

        actor.cleanup_known_destinations(now);
        assert!(actor.recent_announces.is_empty());
    }

    #[test]
    fn discovery_pr_tags_rotate_generations_above_max() {
        let (mut actor, _tx) = TransportActor::new();
        let tag = |i: usize| {
            let mut tag = [0u8; 32];
            tag[24..].copy_from_slice(&(i as u64).to_be_bytes());
            tag
        };
        actor
            .discovery_pr_tags
            .extend((0..MAX_DISCOVERY_PR_TAGS).map(tag));
        actor.on_tick();
        assert_eq!(actor.discovery_pr_tags.len(), MAX_DISCOVERY_PR_TAGS);
        assert!(actor.discovery_pr_tags_prev.is_empty());

        actor.discovery_pr_tags.insert(tag(MAX_DISCOVERY_PR_TAGS));
        actor.on_tick();
        assert!(actor.discovery_pr_tags.is_empty());
        assert_eq!(
            actor.discovery_pr_tags_prev.len(),
            MAX_DISCOVERY_PR_TAGS + 1
        );
        assert!(actor.discovery_pr_tags_prev.contains(&tag(0)));

        let next = MAX_DISCOVERY_PR_TAGS + 1;
        actor
            .discovery_pr_tags
            .extend((next..=next + MAX_DISCOVERY_PR_TAGS).map(tag));
        actor.on_tick();
        assert!(!actor.discovery_pr_tags_prev.contains(&tag(0)));
        assert!(actor.discovery_pr_tags_prev.contains(&tag(next)));
    }
}
