use super::*;
use crate::now_f64;

impl TransportActor {
    pub(super) fn on_tick(&mut self) {
        let now = now_f64();

        // Established-Link packets that encountered temporary interface
        // backpressure are retained per Link and retried in FIFO order.
        self.drain_link_endpoint_egress();

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

        if now - self.last_tables_cull >= TABLES_CULL_INTERVAL {
            // Batched culls bound per-tick work; on large tables a single
            // sweep would stall the actor and back up the inbound channel.
            self.path_table.cull_expired_batch(100);
            self.reverse_table.cull_expired_batch(100);
            self.tunnel_table.cull_expired_batch(50);
            self.cull_stale_tunnel_paths(now);
            self.cull_path_interface_suppressions(now);

            // Drop entries pointing to interfaces that have gone away —
            // those routes could never be used anyway.
            let active_interfaces: HashSet<InterfaceId> = self.interfaces.keys().copied().collect();
            self.path_table.cull_dead_interfaces(&active_interfaces);
            self.reverse_table.cull_dead_interfaces(&active_interfaces);
            self.link_table.cull_dead_interfaces(&active_interfaces);

            // Failed link establishment can mean either a stale path or a
            // topology change. Queue rediscovery so automated path requests
            // are bounded and throttled like upstream Reticulum 1.2.5.
            let (_, expired_links) = self.link_table.cull_stale(LINK_TIMEOUT);
            let mut queued_dests = HashSet::new();
            for expired_link in expired_links {
                if let Some(request) = self.rediscovery_request_for_expired_link(expired_link, now)
                {
                    if queued_dests.insert(request.destination_hash) {
                        self.queue_discovery_path_request(
                            request.destination_hash,
                            request.blocked_interface,
                            now,
                        );
                    }
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
                    self.send_to_interface(attached_interface, &raw);
                    self.announce_table.remove(&hash);
                    if let Some(held_entry) = self.held_announces.remove(hash.as_bytes()) {
                        self.announce_table.insert(*hash.as_bytes(), held_entry);
                    }
                    continue;
                }
                if let Some(entry) = self.announce_table.get_mut(&hash) {
                    entry.retries += 1;
                    entry.retransmit_timeout = now + PATHFINDER_G + rand_window();
                }
                // Never retransmit back out the interface the announce came
                // in on — that's just loopback and will cause dedup churn.
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

        // IngressController is self-maintaining (bounded deque + held cap),
        // so only the rate table needs a periodic sweep.
        if now - self.last_rate_cull >= BLACKHOLE_CHECK_INTERVAL {
            self.rate_table.cull(now - 3600.0);
            self.last_rate_cull = now;
        }

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
                            ReceiptStatus::Delivered => receipt
                                .get_rtt()
                                .map_or(crate::messages::ReceiptUpdate::Failed, |rtt| {
                                    crate::messages::ReceiptUpdate::Delivered { rtt }
                                }),
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

        if self.startup_complete && now - self.last_cache_clean >= CACHE_CLEAN_INTERVAL {
            self.packet_hashlist.force_rotate();
            self.cleanup_known_destinations(now);
            self.last_cache_clean = now;
        }

        // On-disk announce-cache prune. Deliberately outside the
        // startup_complete gate: that gate is stamped on first interface
        // registration, and a node with no interfaces must still collect
        // backlog (Python's jobs thread cleans unconditionally). Safe before
        // interfaces exist — pending re-registration entries are in the
        // keep-set and the mtime grace covers fresh writes. First sweep runs
        // on the first tick after storage init, then every 15 minutes.
        if now - self.last_announce_cache_sweep >= ANNOUNCE_CACHE_SWEEP_INTERVAL
            && self.maybe_sweep_announce_cache()
        {
            self.last_announce_cache_sweep = now;
        }

        self.expire_path_waiters(now);

        // Drop pending path-request markers after the upstream gate timeout.
        self.path_requests
            .retain(|_, last| now - *last < PATH_REQUEST_GATE_TIMEOUT);
        self.discovery_path_requests
            .retain(|_, request| now < request.timeout);
        self.discovery_pr_tags
            .retain(|_, last| now - *last < PATH_REQUEST_GATE_TIMEOUT);
        // Python `max_pr_tags` hard cap on top of the time gate: a tag storm
        // inside the gate window must not grow the map without bound.
        if self.discovery_pr_tags.len() > MAX_DISCOVERY_PR_TAGS {
            let mut by_age: Vec<(Vec<u8>, f64)> = self
                .discovery_pr_tags
                .iter()
                .map(|(tag, last)| (tag.clone(), *last))
                .collect();
            by_age.sort_unstable_by(|a, b| a.1.total_cmp(&b.1));
            let excess = self.discovery_pr_tags.len() - MAX_DISCOVERY_PR_TAGS;
            for (tag, _) in by_age.into_iter().take(excess) {
                self.discovery_pr_tags.remove(&tag);
            }
        }

        self.process_pending_discovery_path_requests(now);
        self.process_announce_queues(now);
    }

    pub(super) fn queue_discovery_path_request(
        &mut self,
        destination_hash: [u8; 16],
        blocked_interface: Option<InterfaceId>,
        now: f64,
    ) -> bool {
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

        if let Some(blocked_interface) = request.blocked_interface {
            let ids: Vec<InterfaceId> = self
                .interfaces
                .iter()
                .filter_map(|(&id, entry)| {
                    if id == blocked_interface || !entry.direction.outbound {
                        None
                    } else {
                        Some(id)
                    }
                })
                .collect();
            for id in ids {
                self.send_path_request(request.destination_hash, id, None, false);
            }
        } else {
            let mut request_tag = [0u8; 16];
            {
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut request_tag);
            }
            let ids: Vec<InterfaceId> = self
                .interfaces
                .iter()
                .filter_map(|(&id, entry)| entry.direction.outbound.then_some(id))
                .collect();
            for id in ids {
                self.send_path_request(request.destination_hash, id, Some(&request_tag), false);
            }
        }
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

        debug!(
            dest = hex::encode(destination_hash),
            blocked_interface, "unvalidated link expired -- queued re-discovery"
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
        self.last_cache_clean = 0.0;
        self.last_announce_cache_sweep = 0.0;
        self.last_blackhole_check = 0.0;
        self.last_rate_cull = 0.0;
        self.last_held_announce_check = 0.0;
    }

    /// Drain per-interface announce queues one entry per spacing window
    /// (shortest hops, oldest among ties). Spacing comes from
    /// `packet_time / announce_cap`; stale entries past QUEUED_ANNOUNCE_LIFE drop.
    pub(super) fn process_announce_queues(&mut self, now: f64) {
        let iface_ids: Vec<InterfaceId> = self.interfaces.keys().copied().collect();
        for iface_id in iface_ids {
            let should_process = if let Some(entry) = self.interfaces.get(&iface_id) {
                !entry.announce_queue.is_empty()
                    && now >= entry.announce_allowed_at
                    && entry.direction.outbound
            } else {
                false
            };

            if !should_process {
                continue;
            }

            if let Some(entry) = self.interfaces.get_mut(&iface_id) {
                entry
                    .announce_queue
                    .retain(|a| now - a.time < QUEUED_ANNOUNCE_LIFE);
            }

            let selected = if let Some(entry) = self.interfaces.get(&iface_id) {
                if entry.announce_queue.is_empty() {
                    None
                } else {
                    let min_hops = entry
                        .announce_queue
                        .iter()
                        .map(|e| e.hops)
                        .min()
                        .unwrap_or(0);
                    entry
                        .announce_queue
                        .iter()
                        .enumerate()
                        .filter(|(_, e)| e.hops == min_hops)
                        .min_by(|(_, a), (_, b)| {
                            a.time
                                .partial_cmp(&b.time)
                                .unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .map(|(idx, e)| (idx, e.raw.clone()))
                }
            } else {
                None
            };

            if let Some((idx, raw)) = selected {
                self.send_to_interface(iface_id, &raw);

                if let Some(entry) = self.interfaces.get_mut(&iface_id) {
                    let bitrate = entry.bitrate.max(1) as f64;
                    let packet_time = (raw.len() as f64 * 8.0) / bitrate;
                    let announce_delay = packet_time / entry.announce_cap.max(0.001);
                    entry.announce_allowed_at = now + announce_delay;

                    if idx < entry.announce_queue.len() {
                        entry.announce_queue.remove(idx);
                    }
                }
            }
        }
    }

    /// Release held announces with hop-priority and frequency checks; the
    /// per-interface `IngressController` owns the selection logic.
    fn process_held_announces(&mut self, _now: f64) {
        let iface_ids: Vec<InterfaceId> = self.interfaces.keys().copied().collect();
        for iface_id in iface_ids {
            let released = self
                .interfaces
                .get_mut(&iface_id)
                .and_then(|iface| iface.ingress.try_release_held());

            if let Some(announce) = released {
                debug!(
                    dest = hex::encode(announce.destination_hash),
                    interface = iface_id,
                    "releasing held announce"
                );

                self.on_inbound(crate::messages::InboundPacket {
                    raw: announce.raw,
                    interface_id: announce.receiving_interface_id,
                    rssi: None,
                    snr: None,
                    q: None,
                });
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
    /// kept; pathless never-used entries die after `UNUSED_DESTINATION_LINGER`
    /// (6 min); pathless used entries die after `DESTINATION_TIMEOUT * 1.25`
    /// idle since last use.
    pub(super) fn cleanup_known_destinations(&mut self, now: f64) {
        let used_threshold = DESTINATION_TIMEOUT as f64 * 1.25;

        let before = self.recent_announces.len();
        // Collect into a Vec; the has-path borrow on path_table fights an
        // in-place `retain` closure on recent_announces.
        let to_drop: Vec<[u8; 16]> = self
            .recent_announces
            .values()
            .filter_map(|a| {
                if a.retained {
                    return None;
                }
                if self.path_table.has_path(&a.dest_hash) {
                    return None;
                }
                let stale = match a.last_used {
                    None => now - a.timestamp > UNUSED_DESTINATION_LINGER,
                    Some(last_used) => now - last_used.max(a.timestamp) > used_threshold,
                };
                if stale { Some(a.dest_hash) } else { None }
            })
            .collect();

        if !to_drop.is_empty() {
            for hash in &to_drop {
                self.recent_announces.remove(hash);
            }
            debug!(
                removed = to_drop.len(),
                remaining = self.recent_announces.len(),
                before,
                "known-destinations cleanup swept pathless entries"
            );
        }
    }

    /// Trim announce queues to age (QUEUED_ANNOUNCE_LIFE) and size
    /// (MAX_QUEUED_ANNOUNCES). Oldest entries are dropped first so a burst
    /// of fresh announces isn't starved by a backlog of stale ones.
    pub(super) fn cull_announce_queues(&mut self, now: f64) {
        for iface in self.interfaces.values_mut() {
            iface
                .announce_queue
                .retain(|entry| now - entry.time < QUEUED_ANNOUNCE_LIFE);
            if iface.announce_queue.len() > MAX_QUEUED_ANNOUNCES {
                let excess = iface.announce_queue.len() - MAX_QUEUED_ANNOUNCES;
                iface.announce_queue.drain(..excess);
            }
        }
    }

    /// On interface drop: remove tunnel-bound paths and re-announce the
    /// affected local destinations on remaining interfaces.
    pub(super) fn void_tunnel_interface(&mut self, interface_id: InterfaceId) {
        let mut voided_destinations: Vec<[u8; 16]> = Vec::new();

        let tunnel_ids: Vec<[u8; 32]> = self
            .tunnel_table
            .iter()
            .filter(|(_, entry)| entry.interface_id == interface_id)
            .map(|(id, _)| *id)
            .collect();

        for tunnel_id in &tunnel_ids {
            if let Some(tunnel) = self.tunnel_table.get(tunnel_id) {
                for dest_hash in tunnel.tunnel_paths.keys() {
                    voided_destinations.push(*dest_hash);
                    self.path_table.remove(dest_hash);
                    self.state_dirty = true;
                }
            }
            if let Some(tunnel) = self.tunnel_table.get_mut(tunnel_id) {
                // Sentinel 0 marks the tunnel as bound to no interface until
                // a fresh synthesis arrives and rebinds it.
                tunnel.interface_id = 0;
                debug!(
                    tunnel_id = hex::encode(&tunnel_id[..16]),
                    "voided tunnel interface"
                );
            }
        }

        for dest_hash in &voided_destinations {
            if self.local_destinations.contains(dest_hash) {
                if let Some(tx) = self.destination_channels.get(dest_hash) {
                    if let Err(e) =
                        tx.try_send(crate::link_messages::DestinationEvent::AnnounceRequested(
                            crate::link_messages::AnnounceRequest::normal(String::new()),
                        ))
                    {
                        self.channel_drops += 1;
                        warn!(dest = hex::encode(dest_hash), drops = self.channel_drops, err = %e,
                                "failed to send re-announce after tunnel void (channel full)");
                    }
                }
            }
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
            packet_hash: None,
            is_path_response: false,
            retained,
            last_used,
            name_hash: [0u8; 10],
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
    fn discovery_pr_tags_capped_at_max() {
        let (mut actor, _tx) = TransportActor::new();
        let now = crate::now_f64();
        // All inside PATH_REQUEST_GATE_TIMEOUT, so only the count cap trims.
        for i in 0..=MAX_DISCOVERY_PR_TAGS {
            let tag = (i as u64).to_be_bytes().to_vec();
            actor.discovery_pr_tags.insert(tag, now - (i as f64) * 1e-4);
        }
        assert_eq!(actor.discovery_pr_tags.len(), MAX_DISCOVERY_PR_TAGS + 1);

        actor.on_tick();

        assert_eq!(actor.discovery_pr_tags.len(), MAX_DISCOVERY_PR_TAGS);
        let oldest = (MAX_DISCOVERY_PR_TAGS as u64).to_be_bytes().to_vec();
        assert!(!actor.discovery_pr_tags.contains_key(&oldest));
        let newest = 0u64.to_be_bytes();
        assert!(actor.discovery_pr_tags.contains_key(newest.as_slice()));
    }
}
