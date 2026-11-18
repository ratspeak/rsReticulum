use super::*;
use tracing::info;

/// Python's `storagepath/announce_rate_table` (Transport.py).
const ANNOUNCE_RATE_TABLE_FILE: &str = "announce_rate_table";

/// Python `save_announce_rate_table`: write through a temporary file and a
/// rename, logging a failure (Transport.py, Storage.py).
fn save_announce_rate_table(dir: &std::path::Path, blob: &[u8]) {
    let path = dir.join(ANNOUNCE_RATE_TABLE_FILE);
    if let Err(e) = rns_identity::persistence::atomic_write(&path, blob) {
        tracing::warn!(path = %path.display(), error = %e, "could not persist announce rate table");
    }
}

/// Wall-clock helper kept here so tests can inject a fake clock without
/// dragging it through the actor.
fn now() -> f64 {
    crate::now_f64()
}

fn recent_announce_from_cached_packet(
    dest_hash: [u8; 16],
    hops: u8,
    timestamp: f64,
    raw_packet: Vec<u8>,
    destination_cost: f64,
) -> RecentAnnounce {
    let mut recent = RecentAnnounce {
        dest_hash,
        hops,
        app_data: None,
        timestamp,
        public_key: None,
        ratchet: None,
        ratchet_received: None,
        packet_hash: None,
        is_path_response: false,
        retained: false,
        last_used: None,
        name_hash: [0u8; 10],
        stamp: None,
        stamp_value: 0.0,
        lr_cost: None,
        facts_known: false,
    };

    if let Ok((header, offset)) = rns_wire::header::PacketHeader::unpack(&raw_packet)
        && header.flags.packet_type == rns_wire::flags::PacketType::Announce
        && header.destination_hash == dest_hash
        && raw_packet.len() >= offset
    {
        recent.packet_hash = Some(rns_wire::hash::packet_hash(
            &raw_packet,
            header.flags.header_type,
        ));
        recent.is_path_response = header.context == rns_wire::context::PacketContext::PathResponse;
        if let Ok(announce) = rns_identity::announce::AnnounceData::unpack(
            &raw_packet[offset..],
            header.flags.context_flag,
        ) {
            // Python validates without a receiving interface against the global cost.
            let stamp = announce.check_stamp(&dest_hash, destination_cost);
            recent.app_data = super::inbound::remembered_app_data(&announce, &stamp);
            recent.stamp = stamp.stamp;
            recent.stamp_value = stamp.value.unwrap_or(0.0);
            recent.lr_cost = stamp.lr_cost;
            recent.public_key = Some(announce.public_key);
            // The packet may predate a stored rotation; the store answers the ratchet.
            recent.name_hash = announce.name_hash;
            recent.facts_known = true;
        }
    }

    recent
}

/// Owned copy of everything `write_routing_snapshot` persists, so the disk
/// I/O (fsync-heavy on macOS: F_FULLFSYNC per file + dir) can run on the
/// blocking pool without borrowing the actor.
pub(super) struct RoutingSnapshot {
    pub path_table: crate::path_table::PathTable,
    pub tunnel_table: crate::tunnel::TunnelTable,
    pub blackhole_table: crate::blackhole::BlackholeTable,
    pub interface_names: std::collections::HashMap<u64, String>,
    pub transport_identity_hash: Option<[u8; 16]>,
}

/// Persist a routing snapshot. Runs on the blocking pool for periodic saves
/// and inline for shutdown; must not touch the actor.
pub(super) fn write_routing_snapshot(dir: &std::path::Path, snapshot: &RoutingSnapshot) {
    let interface_names = &snapshot.interface_names;

    let path_table_path = dir.join("path_table.msgpack");
    if let Err(e) =
        crate::persistence::save_path_table(&snapshot.path_table, interface_names, &path_table_path)
    {
        trace!("failed to save path table: {}", e);
    } else {
        debug!("saved path table ({} entries)", snapshot.path_table.len());
    }

    let destination_table_path = dir.join("destination_table");
    if let Err(e) = crate::persistence::save_python_destination_table(
        &snapshot.path_table,
        interface_names,
        &destination_table_path,
    ) {
        trace!("failed to save Python destination_table: {}", e);
    }

    let blackhole_path = dir.join("blackhole_table.msgpack");
    if let Err(e) =
        crate::persistence::save_blackhole_table(&snapshot.blackhole_table, &blackhole_path)
    {
        trace!("failed to save blackhole table: {}", e);
    } else {
        debug!(
            "saved blackhole table ({} entries)",
            snapshot.blackhole_table.len()
        );
    }

    // Publisher files are written only when fetched (Discovery.py).
    if let Some(local_identity_hash) = snapshot.transport_identity_hash {
        let blackhole_dir = dir.join("blackhole");
        if let Err(e) = crate::persistence::save_local_blackhole_file(
            &snapshot.blackhole_table,
            local_identity_hash,
            &blackhole_dir,
        ) {
            trace!("failed to save Python blackhole files: {}", e);
        }
    }

    // Per-announce Python cache files are written event-driven at receive
    // (`cache_announce_to_disk`), not re-serialized here every cycle.

    let tunnel_path = dir.join("tunnel_table.msgpack");
    if let Err(e) =
        crate::persistence::save_tunnel_table(&snapshot.tunnel_table, interface_names, &tunnel_path)
    {
        trace!("failed to save tunnel table: {}", e);
    } else {
        debug!(
            "saved tunnel table ({} entries)",
            snapshot.tunnel_table.len()
        );
    }

    let python_tunnels_path = dir.join("tunnels");
    if let Err(e) = crate::persistence::save_python_tunnel_table(
        &snapshot.tunnel_table,
        interface_names,
        &python_tunnels_path,
    ) {
        trace!("failed to save Python tunnels table: {}", e);
    }

    debug!(
        paths = snapshot.path_table.len(),
        tunnels = snapshot.tunnel_table.len(),
        blackhole = snapshot.blackhole_table.len(),
        "flushed routing state"
    );
}

impl TransportActor {
    /// Raw bytes of a cached announce (Python `Transport.get_cached_packet`).
    /// Misses are normal: a cleaned announce, or shared-instance client mode.
    pub(super) fn cached_announce_raw(&mut self, packet_hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.cached_announce(packet_hash)
            .map(|cached| cached.raw_packet)
    }

    /// The cached announce with the interface it was received on.
    pub(super) fn cached_announce(
        &mut self,
        packet_hash: &[u8; 32],
    ) -> Option<crate::persistence::PythonCachedAnnounce> {
        let allow_db = !self.storage_client();
        let (raw_packet, interface_reference) = self.kd.fetch_announce(packet_hash, allow_db)?;
        Some(crate::persistence::PythonCachedAnnounce {
            raw_packet,
            interface_reference,
        })
    }

    /// Announce cache write at receive (Python `Transport.cache(packet,
    /// force_cache=True)` on announce ingest), which upstream skips on a
    /// shared-instance client. Pending until the next flush; a later store for
    /// the same packet hash replaces it.
    pub(super) fn cache_announce(
        &mut self,
        packet_hash: &[u8; 32],
        raw: &[u8],
        interface_id: InterfaceId,
    ) {
        if self.storage_client() || self.storage_dir.is_none() {
            return;
        }
        // Transport.cache stores `str(packet.receiving_interface)`.
        let interface_name = self
            .interfaces
            .get(&interface_id)
            .map(|entry| entry.upstream_name().to_string());
        self.kd.store_announce(*packet_hash, raw, interface_name);
    }

    fn routing_snapshot(&self) -> RoutingSnapshot {
        RoutingSnapshot {
            path_table: self.path_table.clone(),
            tunnel_table: self.tunnel_table.clone(),
            blackhole_table: self.blackhole_table.clone(),
            // Accepted clients' names recur across restarts for other peers.
            interface_names: self
                .interfaces
                .iter()
                .filter(|(_, entry)| !entry.accepted)
                .map(|(&id, entry)| (id, entry.upstream_name().to_string()))
                .collect(),
            transport_identity_hash: self.transport_identity_hash,
        }
    }

    /// `Identity.flush_known_destinations`: hand the pending marks to the store
    /// worker without waiting. Shared-instance clients write nothing.
    pub(super) fn flush_known_destinations(&mut self) {
        self.last_known_destinations_flush = now();
        if self.storage_client() {
            self.kd.pending = store_worker::KdPending::default();
            return;
        }
        self.kd.flush(&self.recent_announces);
    }

    /// Full persist of routing state, known destinations and the hashlist
    /// (Python `Reticulum.__persist_data`), off-actor.
    pub(super) fn persist_data_async(&mut self) {
        // Reticulum.py: a persist already running skips this one untimed.
        if self
            .routing_save_in_flight
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        self.save_state_async();
        self.flush_known_destinations();
        self.last_data_persist = now();
    }

    /// Python `Reticulum._should_persist_data`, called when a local client
    /// disconnects: persist unless one ran within `GRACIOUS_PERSIST_INTERVAL`.
    pub(super) fn maybe_gracious_persist(&mut self) {
        if now() > self.last_data_persist + GRACIOUS_PERSIST_INTERVAL {
            self.persist_data_async();
        }
    }

    /// Periodic flush used by `on_tick`: snapshot on the actor (cheap clones)
    /// and push the fsync-heavy writes to the blocking pool. A save already
    /// in flight keeps `state_dirty` set so the next tick retries — two
    /// writers would race on the shared `<file>.tmp` names.
    pub(super) fn save_routing_state_async(&mut self) {
        if self.storage_client() {
            trace!("skipping routing-state save in shared-instance client mode");
            self.state_dirty = false;
            self.last_state_save = now();
            return;
        }
        let Some(dir) = self.storage_dir.clone() else {
            self.state_dirty = false;
            self.last_state_save = now();
            return;
        };
        if self
            .routing_save_in_flight
            .load(std::sync::atomic::Ordering::Acquire)
        {
            trace!("routing-state save already in flight; retry next interval");
            return;
        }
        self.routing_save_in_flight
            .store(true, std::sync::atomic::Ordering::Release);
        let snapshot = self.routing_snapshot();
        let generation = self
            .routing_save_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1);
        let latest_generation = self.routing_save_generation.clone();
        let write_lock = self.routing_save_lock.clone();
        let in_flight = self.routing_save_in_flight.clone();
        let write = move || {
            let _guard = write_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if latest_generation.load(std::sync::atomic::Ordering::Acquire) == generation {
                write_routing_snapshot(&dir, &snapshot);
            } else {
                trace!(generation, "skipping superseded routing-state snapshot");
            }
            in_flight.store(false, std::sync::atomic::Ordering::Release);
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(write);
            }
            Err(_) => {
                // No runtime (tests, exotic embedders): write inline.
                write();
            }
        }
        self.state_dirty = false;
        self.last_state_save = now();
    }

    /// Jobs-loop flush of the pending announces (Python `Transport.jobs`). A
    /// shared-instance client has no announce cache and writes nothing.
    pub(super) fn flush_cached_announces(&mut self, now: f64) {
        if self.storage_dir.is_none() {
            return;
        }
        if self.storage_client() {
            self.kd.discard_announces();
            return;
        }
        self.kd.flush_announces_due(now);
    }

    /// Reference-counted clean of the cached announces (Python `Transport.clean_cache`
    /// and `clean_announce_cache`). Keeps the packet hash of every path and every
    /// tunnel path, as upstream does, and of every restored path still waiting for
    /// its interface: upstream binds those at load, this actor when the interface
    /// registers, and the announce must still be there then.
    pub(super) fn clean_announce_cache(&mut self) {
        // Transport.clean_cache: never on a shared-instance client, never two at once.
        if self.storage_client() || self.storage_dir.is_none() {
            return;
        }
        if self.kd.announce_clean_in_flight() {
            debug!("announce-cache clean still running, postponing until the next interval");
            return;
        }
        let mut keep: HashSet<[u8; 32]> = HashSet::new();
        keep.extend(self.path_table.iter().filter_map(|(_, e)| e.packet_hash));
        keep.extend(
            self.tunnel_table
                .tunnel_paths()
                .filter_map(|(_, p)| p.packet_hash),
        );
        keep.extend(
            self.pending_path_entries
                .iter()
                .filter_map(|e| e.packet_hash.as_deref())
                .filter_map(|h| <[u8; 32]>::try_from(h).ok()),
        );
        self.kd.clean_announces(keep);
    }

    /// Wait (bounded) for an older asynchronous hashlist snapshot before a
    /// synchronous flush takes its newer snapshot. Without this ordering, an
    /// already-queued background writer could replace the shutdown file with
    /// stale state after the synchronous write completed.
    pub(super) fn wait_for_hashlist_save(&self) -> bool {
        self.wait_for_hashlist_save_until(
            std::time::Instant::now() + std::time::Duration::from_secs(15),
        )
    }

    pub(super) fn wait_for_hashlist_save_until(&self, deadline: std::time::Instant) -> bool {
        while self
            .hashlist_save_in_flight
            .load(std::sync::atomic::Ordering::Acquire)
        {
            if std::time::Instant::now() >= deadline {
                tracing::warn!("in-flight hashlist save did not finish before sync save");
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        true
    }

    /// Flush the small/critical routing-state files: path_table,
    /// announce_cache, blackhole_table, tunnel_table. Hashlist is excluded —
    /// it can be multiple MB and is rebuildable from in-flight traffic, so it
    /// is persisted independently on the scheduled `PersistData` command,
    /// background falling edges, and shutdown.
    /// Synchronous: used by shutdown / falling-edge / RPC-forced saves where
    /// completion must be guaranteed before proceeding.
    pub(super) fn save_routing_state(&mut self) {
        if self.storage_client() {
            trace!("skipping routing-state save in shared-instance client mode");
            self.state_dirty = false;
            self.last_state_save = now();
            return;
        }

        if let Some(dir) = self.storage_dir.clone() {
            let snapshot = self.routing_snapshot();
            self.routing_save_generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let _guard = self
                .routing_save_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            write_routing_snapshot(&dir, &snapshot);
        }
        self.state_dirty = false;
        self.last_state_save = now();
    }

    /// Flush every persisted table including the (potentially large) packet
    /// hashlist, synchronously. Shutdown-only: the process is exiting, so
    /// blocking the actor is fine and completion must be guaranteed.
    pub(super) fn save_state(&mut self) {
        // Routing state first so the order matches the periodic-save shape.
        self.save_routing_state();
        if !self.owns_persistent_hashlist() {
            return;
        }

        if let Some(ref dir) = self.storage_dir {
            if !self.wait_for_hashlist_save() {
                return;
            }
            let hashlist_path = dir.join("packet_hashlist.raw");
            let hashes = self.packet_hashlist.current_hashes();
            if let Err(e) = crate::persistence::save_raw_hashes(&hashes, &hashlist_path) {
                trace!("failed to save hashlist: {}", e);
            } else {
                info!(entries = hashes.len(), "flushed hashlist");
            }
            save_announce_rate_table(dir, &self.rate_table.to_bytes());
        }
    }

    /// Falling-edge (foreground→background) flush. Same coverage as
    /// `save_state` but entirely off-actor: on desktop the edge fires on
    /// every window focus loss, and the inline fsync chain (F_FULLFSYNC per
    /// file on macOS) stalls routing + control queries for seconds.
    pub(super) fn save_state_async(&mut self) {
        self.save_routing_state_async();
        if !self.owns_persistent_hashlist() {
            return;
        }
        let Some(dir) = self.storage_dir.clone() else {
            return;
        };
        if self
            .hashlist_save_in_flight
            .load(std::sync::atomic::Ordering::Acquire)
        {
            trace!("hashlist save already in flight; skipping");
            return;
        }
        self.hashlist_save_in_flight
            .store(true, std::sync::atomic::Ordering::Release);
        let hashes = self.packet_hashlist.current_hashes();
        let rate_table = self.rate_table.to_bytes();
        let in_flight = self.hashlist_save_in_flight.clone();
        let entries = hashes.len();
        let write = move || {
            let hashlist_path = dir.join("packet_hashlist.raw");
            if let Err(e) = crate::persistence::save_raw_hashes(&hashes, &hashlist_path) {
                trace!("failed to save hashlist: {}", e);
            } else {
                info!(entries, "flushed hashlist");
            }
            save_announce_rate_table(&dir, &rate_table);
            in_flight.store(false, std::sync::atomic::Ordering::Release);
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(write);
            }
            Err(_) => write(),
        }
    }

    pub(super) fn on_shutdown(&mut self) {
        self.terminate_all_link_endpoints(
            crate::messages::LinkEndpointTerminalReason::TransportShutdown,
        );
        self.save_state();
        // Transport.exit_handler, then Identity.exit_handler: flush, apply, close.
        let write = !self.storage_client();
        self.kd.shutdown(&self.recent_announces, write);
    }

    fn owns_persistent_hashlist(&self) -> bool {
        self.is_transport_enabled && !self.storage_client()
    }

    /// Python `Transport.start` loads the table with the hashlist; a file it
    /// rejects leaves the table empty (Transport.py).
    fn load_announce_rate_table(&mut self, dir: &std::path::Path) {
        let path = dir.join(ANNOUNCE_RATE_TABLE_FILE);
        if !path.is_file() {
            return;
        }
        match std::fs::read(&path)
            .ok()
            .and_then(|blob| crate::rate_limit::RateTable::from_bytes(&blob))
        {
            Some(loaded) => {
                let entries = loaded.len();
                self.rate_table.absorb(loaded);
                debug!(entries, "loaded announce rate table from storage");
            }
            None => tracing::warn!(
                path = %path.display(),
                "could not load announce rate table from storage, initialized empty"
            ),
        }
    }

    /// Restore the canonical packet hashlist once both storage and the
    /// actor's transport authority are known. Shared-instance clients and
    /// non-transport leaves must never load or overwrite the authoritative
    /// transport node's deduplication state.
    pub(super) fn maybe_load_hashlist(&mut self) {
        if self.hashlist_load_attempted || !self.owns_persistent_hashlist() {
            return;
        }
        let Some(dir) = self.storage_dir.clone() else {
            return;
        };
        self.hashlist_load_attempted = true;
        self.load_announce_rate_table(&dir);

        let raw_path = dir.join("packet_hashlist.raw");
        if raw_path.exists() {
            match crate::persistence::load_hashlist_raw(&raw_path) {
                Ok(loaded) => {
                    let count = loaded.hashes.len();
                    if loaded.partial_tail_bytes > 0 {
                        tracing::warn!(
                            path = %raw_path.display(),
                            ignored_bytes = loaded.partial_tail_bytes,
                            "ignored partial packet hash at end of canonical hashlist"
                        );
                    }
                    if loaded.duplicate_count > 0 {
                        debug!(
                            duplicates = loaded.duplicate_count,
                            "deduplicated canonical packet hashlist"
                        );
                    }
                    self.packet_hashlist.load_from(loaded.hashes);
                    debug!(count, "loaded canonical packet hashlist from disk");
                }
                Err(e) => {
                    // The canonical file is authoritative when present. Do
                    // not mask damage by silently falling back to stale
                    // legacy state.
                    tracing::warn!(
                        path = %raw_path.display(),
                        error = %e,
                        "failed to load canonical packet hashlist"
                    );
                }
            }
            return;
        }

        let legacy_paths = [dir.join("packet_hashlist"), dir.join("hashlist.msgpack")];
        for legacy_path in legacy_paths {
            if !legacy_path.exists() {
                continue;
            }
            match crate::persistence::load_hashlist_legacy(&legacy_path) {
                Ok(hashes) => {
                    let count = hashes.len();
                    self.packet_hashlist.load_from(hashes.clone());
                    match crate::persistence::save_raw_hashes(&hashes, &raw_path) {
                        Ok(()) => {
                            info!(
                                source = %legacy_path.display(),
                                destination = %raw_path.display(),
                                count,
                                "migrated legacy packet hashlist"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                source = %legacy_path.display(),
                                destination = %raw_path.display(),
                                error = %e,
                                "loaded legacy packet hashlist but failed canonical migration"
                            );
                        }
                    }
                    return;
                }
                Err(e) => {
                    tracing::warn!(
                        path = %legacy_path.display(),
                        error = %e,
                        "failed to load legacy packet hashlist"
                    );
                }
            }
        }
    }

    /// Restore on-disk transport state. Paths can't bind to a concrete
    /// `interface_id` until the matching interface re-registers, so they're
    /// staged in `pending_path_entries` and drained by `RegisterInterface`;
    /// path entries lacking an interface name or hash (pre-v3) are dropped.
    /// Tunnels load unbound.
    pub(super) fn load_state(&mut self) {
        let destination_cost = self.stamp_policy.destination_cost;
        let Some(dir) = self.storage_dir.clone() else {
            return;
        };
        let now_ts = now();
        // Python defers the first announce-cache clean (Transport.py).
        self.last_announce_cache_sweep = now_ts + ANNOUNCE_CACHE_SWEEP_DEFER;

        // Transport.start restores paths and tunnels only on an instance that
        // is not connected to a shared instance.
        let owner = !self.storage_client();

        // Python destination_table — canonical interop shape. Defer interface
        // hash remap until matching interfaces register.
        let destination_table_path = dir.join("destination_table");
        let loaded_python_destination_table = if owner && destination_table_path.exists() {
            match crate::persistence::load_python_destination_table(&destination_table_path) {
                Ok(entries) => {
                    let total = entries.len();
                    let mut expired = 0usize;
                    let mut missing_cache = 0usize;
                    let mut pending = 0usize;
                    for pe in entries {
                        if pe.expires <= now_ts {
                            expired += 1;
                            continue;
                        }
                        let cached = match self.cached_announce(&pe.packet_hash) {
                            Some(cached) => cached,
                            None => {
                                missing_cache += 1;
                                continue;
                            }
                        };
                        let next_hop = if pe.received_from == pe.destination_hash {
                            None
                        } else {
                            Some(pe.received_from.to_vec())
                        };
                        self.pending_path_entries
                            .push(crate::persistence::PersistedPathEntry {
                                destination_hash: pe.destination_hash.to_vec(),
                                timestamp: pe.timestamp,
                                next_hop,
                                hops: pe.hops,
                                expires: pe.expires,
                                random_blobs: pe
                                    .random_blobs
                                    .iter()
                                    .map(|blob| blob.to_vec())
                                    .collect(),
                                interface_id: 0,
                                interface_name: cached.interface_reference.clone(),
                                interface_hash: Some(pe.interface_hash.to_vec()),
                                packet_hash: Some(pe.packet_hash.to_vec()),
                                // Transport.py: a legacy row loads as used now.
                                used: Some(pe.used.unwrap_or(now_ts)),
                            });
                        self.recent_announces
                            .entry(pe.destination_hash)
                            .or_insert_with(|| {
                                recent_announce_from_cached_packet(
                                    pe.destination_hash,
                                    pe.hops,
                                    pe.timestamp,
                                    cached.raw_packet,
                                    destination_cost,
                                )
                            });
                        pending += 1;
                    }
                    debug!(
                        total,
                        pending, expired, missing_cache, "staged Python destination_table entries"
                    );
                    pending > 0
                }
                Err(e) => {
                    trace!("failed to load Python destination_table: {}", e);
                    false
                }
            }
        } else {
            false
        };

        // path_table — legacy Rust sidecar fallback, defer remap.
        let path_table_path = dir.join("path_table.msgpack");
        if owner && !loaded_python_destination_table && path_table_path.exists() {
            match crate::persistence::load_path_table(&path_table_path) {
                Ok(entries) => {
                    let total = entries.len();
                    let mut expired = 0usize;
                    let mut legacy = 0usize;
                    let mut pending = 0usize;
                    for pe in entries {
                        if pe.destination_hash.len() != 16 {
                            continue;
                        }
                        if pe.expires <= now_ts {
                            expired += 1;
                            continue;
                        }
                        if pe.interface_name.is_none() && pe.interface_hash.is_none() {
                            legacy += 1;
                            continue;
                        }
                        let mut pe = pe;
                        pe.used.get_or_insert(now_ts);
                        self.pending_path_entries.push(pe);
                        pending += 1;
                    }
                    debug!(
                        total,
                        pending, expired, legacy, "staged path entries from disk"
                    );
                }
                Err(e) => {
                    trace!("failed to load path table: {}", e);
                }
            }
        }

        // blackhole_table — bind directly, no interface dependency.
        let blackhole_path = dir.join("blackhole_table.msgpack");
        if blackhole_path.exists() {
            match crate::persistence::load_blackhole_table(&blackhole_path) {
                Ok(entries) => {
                    let count = entries.len();
                    for be in entries {
                        if be.identity_hash.len() == 16 {
                            let mut hash = [0u8; 16];
                            hash.copy_from_slice(&be.identity_hash);
                            self.blackhole_table.insert_entry(
                                hash,
                                crate::blackhole::BlackholeEntry {
                                    created: be.created,
                                    ttl: be.ttl,
                                    reason: be.reason,
                                    reason_label: be.reason_label,
                                    source: None,
                                },
                            );
                        }
                    }
                    self.publish_blackhole_snapshot();
                    debug!("loaded {} blackhole entries from disk", count);
                }
                Err(e) => {
                    trace!("failed to load blackhole table: {}", e);
                }
            }
        }
        self.load_python_blackhole_if_ready();

        // Python tunnels — canonical interop shape. A path loads only when
        // its cached announce is present, and every tunnel loads unbound
        // until a synthesis rebinds it (Transport.py).
        let python_tunnels_path = dir.join("tunnels");
        let loaded_python_tunnel_table = if owner && python_tunnels_path.exists() {
            match crate::persistence::load_python_tunnel_table(&python_tunnels_path) {
                Ok(entries) => {
                    let total = entries.len();
                    let mut expired = 0usize;
                    let mut missing_cache = 0usize;
                    let mut loaded = 0usize;
                    for te in entries {
                        if te.expires <= now_ts {
                            expired += 1;
                            continue;
                        }

                        let mut paths = Vec::new();
                        for tp in te.paths {
                            if tp.expires <= now_ts {
                                expired += 1;
                                continue;
                            }
                            let cached = match self.cached_announce(&tp.packet_hash) {
                                Some(cached) => cached,
                                None => {
                                    missing_cache += 1;
                                    continue;
                                }
                            };
                            let next_hop = if tp.received_from == tp.destination_hash {
                                None
                            } else {
                                Some(tp.received_from.to_vec())
                            };
                            paths.push(crate::persistence::PersistedTunnelPath {
                                destination_hash: tp.destination_hash.to_vec(),
                                next_hop,
                                hops: tp.hops,
                                expires: tp.expires,
                                timestamp: tp.timestamp,
                                random_blobs: tp
                                    .random_blobs
                                    .iter()
                                    .map(|blob| blob.to_vec())
                                    .collect(),
                                packet_hash: Some(tp.packet_hash.to_vec()),
                                // Transport.py: a legacy row loads as used now.
                                used: Some(tp.used.unwrap_or(now_ts)),
                            });
                            self.recent_announces
                                .entry(tp.destination_hash)
                                .or_insert_with(|| {
                                    recent_announce_from_cached_packet(
                                        tp.destination_hash,
                                        tp.hops,
                                        tp.timestamp,
                                        cached.raw_packet,
                                        destination_cost,
                                    )
                                });
                        }

                        if self.load_unbound_tunnel(&te.tunnel_id, te.expires, &paths) {
                            loaded += 1;
                        }
                    }
                    debug!(
                        total,
                        loaded, expired, missing_cache, "loaded Python tunnel entries"
                    );
                    loaded > 0
                }
                Err(e) => {
                    trace!("failed to load Python tunnels table: {}", e);
                    false
                }
            }
        } else {
            false
        };

        // tunnel_table — legacy Rust sidecar fallback.
        let tunnel_path = dir.join("tunnel_table.msgpack");
        if owner && !loaded_python_tunnel_table && tunnel_path.exists() {
            match crate::persistence::load_tunnel_table(&tunnel_path) {
                Ok(entries) => {
                    let total = entries.len();
                    let mut expired = 0usize;
                    let mut loaded = 0usize;
                    for te in entries {
                        if te.expires <= now_ts {
                            expired += 1;
                            continue;
                        }
                        if self.load_unbound_tunnel(&te.tunnel_id, te.expires, &te.paths) {
                            loaded += 1;
                        }
                    }
                    debug!(total, loaded, expired, "loaded tunnel entries from disk");
                }
                Err(e) => {
                    trace!("failed to load tunnel table: {}", e);
                }
            }
        }
    }

    /// Fill the known-destination table with the rows loaded at start-up
    /// (`Identity.load_known_destinations`). Ratchets stay in the store and are
    /// read on demand.
    pub(super) fn merge_known_destinations(
        &mut self,
        rows: Vec<crate::store::KnownDestinationRow>,
    ) {
        let count = rows.len();
        for row in rows {
            let mut loaded = store_worker::recent_from_row(row);
            match self.recent_announces.entry(loaded.dest_hash) {
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    // The store flushes far more often than the routing snapshot:
                    // the row wins, and the path's cached announce fills in only
                    // the facts the row lacks.
                    let e = o.get_mut();
                    if !loaded.facts_known {
                        loaded.hops = e.hops;
                        loaded.name_hash = e.name_hash;
                        loaded.is_path_response = e.is_path_response;
                        loaded.facts_known = e.facts_known;
                    }
                    loaded.packet_hash = loaded.packet_hash.or(e.packet_hash);
                    *e = loaded;
                }
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(loaded);
                }
            }
        }
        debug!(count, "loaded known destinations from storage");
    }

    /// Write `blackhole/local` now, as upstream does on every local change
    /// (Transport.py).
    pub(super) fn persist_local_blackhole(&mut self) {
        if self.storage_client() {
            return;
        }
        let (Some(dir), Some(local_identity_hash)) =
            (self.storage_dir.as_ref(), self.transport_identity_hash)
        else {
            return;
        };
        let _guard = self
            .routing_save_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = crate::persistence::save_local_blackhole_file(
            &self.blackhole_table,
            local_identity_hash,
            &dir.join("blackhole"),
        ) {
            warn!("failed to persist local blackhole list: {}", e);
        }
    }

    /// Store a publisher's fetched `/list` reply as its blackhole file.
    pub(super) fn persist_blackhole_source(&mut self, publisher: [u8; 16], payload: &[u8]) {
        if self.storage_client() {
            return;
        }
        let Some(dir) = self.storage_dir.as_ref() else {
            return;
        };
        if let Err(e) = crate::persistence::save_blackhole_source_file(
            publisher,
            payload,
            &dir.join("blackhole"),
        ) {
            warn!(
                publisher = hex::encode(publisher),
                "failed to persist blackhole list: {}", e
            );
        }
    }

    pub(super) fn load_python_blackhole_if_ready(&mut self) {
        let (Some(dir), Some(local_identity_hash)) =
            (self.storage_dir.as_ref(), self.transport_identity_hash)
        else {
            return;
        };
        let blackhole_dir = dir.join("blackhole");
        match crate::persistence::load_python_blackhole_dir(
            &blackhole_dir,
            local_identity_hash,
            &self.blackhole_sources,
            now(),
        ) {
            Ok(entries) => {
                let count = entries.len();
                for entry in entries {
                    let source = if entry.source == local_identity_hash {
                        None
                    } else {
                        Some(entry.source.into())
                    };
                    self.blackhole_table.insert_entry(
                        entry.identity_hash,
                        crate::blackhole::BlackholeEntry {
                            created: entry.created,
                            ttl: entry.ttl,
                            reason: entry.reason,
                            reason_label: entry.reason_label,
                            source,
                        },
                    );
                }
                if count > 0 {
                    self.publish_blackhole_snapshot();
                    debug!(count, "loaded Python blackhole files");
                }
            }
            Err(e) => {
                trace!("failed to load Python blackhole files: {}", e);
            }
        }
    }

    /// Load a persisted tunnel unbound, within the reconnect window; only a
    /// later synthesis binds it. Python keeps a tunnel only when one of its
    /// paths loads.
    fn load_unbound_tunnel(
        &mut self,
        tunnel_id: &[u8],
        expires: f64,
        paths: &[crate::persistence::PersistedTunnelPath],
    ) -> bool {
        let Ok(tunnel_id) = <[u8; 32]>::try_from(tunnel_id) else {
            return false;
        };
        let tunnel_paths: std::collections::HashMap<_, _> = paths
            .iter()
            .filter_map(|tp| {
                let dest = <[u8; 16]>::try_from(tp.destination_hash.as_slice()).ok()?;
                let path = crate::tunnel::TunnelPath {
                    timestamp: tp.timestamp,
                    next_hop: tp
                        .next_hop
                        .as_deref()
                        .and_then(|next_hop| <[u8; 16]>::try_from(next_hop).ok()),
                    hops: tp.hops,
                    expires: tp.expires,
                    random_blobs: tp
                        .random_blobs
                        .iter()
                        .filter_map(|blob| <[u8; 10]>::try_from(blob.as_slice()).ok())
                        .collect(),
                    packet_hash: tp
                        .packet_hash
                        .as_deref()
                        .and_then(|packet_hash| <[u8; 32]>::try_from(packet_hash).ok()),
                    used: tp.used.unwrap_or_else(now_f64),
                };
                Some((dest, path))
            })
            .collect();
        if tunnel_paths.is_empty() {
            return false;
        }
        let window = now_f64() + crate::constants::TUNNEL_RECONNECT_WINDOW as f64;
        self.tunnel_table.insert(crate::tunnel::TunnelEntry {
            tunnel_id,
            interface_id: None,
            tunnel_paths,
            expires: expires.min(window),
        });
        true
    }

    /// Drain pending path entries whose interface name or hash matches the
    /// just-registered interface. Bound to `RegisterInterface` so each entry
    /// rebinds to whatever `interface_id` the runtime allocated this boot.
    ///
    /// A table names its interface by the hash of upstream's `str(interface)`
    /// (`Transport.find_interface_from_hash`); one written before this crate
    /// did the same hashes the registered name. Both are accepted.
    pub(super) fn drain_pending_for_interface(
        &mut self,
        id: InterfaceId,
        name: &str,
        upstream_name: &str,
    ) {
        if !self.pending_path_entries.is_empty() {
            let mut promoted = 0usize;
            let hashes = [
                crate::persistence::interface_hash_from_name(upstream_name),
                crate::persistence::interface_hash_from_name(name),
            ];
            self.pending_path_entries.retain(|pe| {
                let name_matches = pe
                    .interface_name
                    .as_deref()
                    .is_some_and(|saved| saved == upstream_name || saved == name);
                let hash_matches = pe
                    .interface_hash
                    .as_deref()
                    .is_some_and(|hash| hashes.iter().any(|h| h.as_slice() == hash));
                if !name_matches && !hash_matches {
                    return true;
                }
                if pe.destination_hash.len() != 16 {
                    return false;
                }
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&pe.destination_hash);
                let next_hop = pe.next_hop.as_ref().and_then(|h| {
                    if h.len() == 16 {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(h);
                        Some(arr)
                    } else {
                        None
                    }
                });
                let entry = crate::path_table::PathEntry {
                    timestamp: pe.timestamp,
                    next_hop,
                    hops: pe.hops,
                    expires: pe.expires,
                    random_blobs: pe
                        .random_blobs
                        .iter()
                        .filter_map(|b| {
                            if b.len() == 10 {
                                let mut arr = [0u8; 10];
                                arr.copy_from_slice(b);
                                Some(arr)
                            } else {
                                None
                            }
                        })
                        .collect(),
                    interface_id: id,
                    packet_hash: pe.packet_hash.as_ref().and_then(|h| {
                        if h.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(h);
                            Some(arr)
                        } else {
                            None
                        }
                    }),
                    used: pe.used.unwrap_or_else(now_f64),
                };
                if !self.path_table.has_path(&hash) {
                    self.path_table.insert(hash, entry);
                    promoted += 1;
                }
                false
            });
            if promoted > 0 {
                debug!(
                    interface_id = id,
                    name = %name,
                    promoted,
                    "rebound persisted path entries to live interface"
                );
            }
        }

        // Path waiters that were registered before the rebind can now fire.
        let loaded_dests: Vec<[u8; 16]> = self
            .path_waiters
            .keys()
            .filter(|dest| self.path_table.has_path(dest))
            .copied()
            .collect();
        for dest in loaded_dests {
            self.fire_path_waiters(&dest);
        }
    }
}

#[cfg(all(test, feature = "sqlite-store"))]
mod announce_clean_tests {
    use super::*;

    fn temp_storage(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rns-announce-clean-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn settle(actor: &mut TransportActor) {
        let result = actor
            .kd
            .results
            .blocking_recv()
            .expect("store worker answers");
        actor.kd.handle(result);
    }

    /// The keep-set is every path, every tunnel path, and every restored path
    /// still waiting for its interface. Everything else goes, whatever its age,
    /// a retained destination's announce and a not yet flushed one included.
    #[test]
    fn clean_keeps_every_reference_source_and_removes_the_rest() {
        let storage = temp_storage("keepset");
        let path_hash = [0x33; 32];
        let tunnel_hash = [0x44; 32];
        let pin_hash = [0x55; 32];
        let pending_path_hash = [0x66; 32];
        let unflushed_path_hash = [0x77; 32];
        let orphan_hash = [0x88; 32];
        let unflushed_orphan_hash = [0x99; 32];
        for hash in [
            path_hash,
            tunnel_hash,
            pin_hash,
            pending_path_hash,
            orphan_hash,
        ] {
            crate::store::seed_cached_announce(&storage, &hash, &[0x01; 40], None).unwrap();
        }

        let (mut actor, _tx) = TransportActor::new();
        actor.initialize_storage(storage.clone());
        let now = crate::now_f64();
        for (dest, hash) in [([0x11; 16], path_hash), ([0x14; 16], unflushed_path_hash)] {
            actor.path_table.insert(
                dest,
                crate::path_table::PathEntry {
                    used: 0.0,
                    timestamp: now,
                    next_hop: Some([0x22; 16]),
                    hops: 1,
                    expires: now + 600.0,
                    random_blobs: std::collections::VecDeque::new(),
                    interface_id: 7,
                    packet_hash: Some(hash),
                },
            );
        }
        actor.tunnel_table.insert(crate::tunnel::TunnelEntry {
            tunnel_id: [0xAB; 32],
            interface_id: Some(7),
            tunnel_paths: std::collections::HashMap::from([(
                [0x12; 16],
                crate::tunnel::TunnelPath {
                    used: 0.0,
                    timestamp: now,
                    next_hop: None,
                    hops: 2,
                    expires: now + 600.0,
                    random_blobs: Vec::new(),
                    packet_hash: Some(tunnel_hash),
                },
            )]),
            expires: now + 600.0,
        });
        actor.recent_announces.insert(
            [0x01; 16],
            super::super::RecentAnnounce {
                dest_hash: [0x01; 16],
                hops: 1,
                app_data: None,
                timestamp: now,
                public_key: None,
                ratchet: None,
                ratchet_received: None,
                packet_hash: Some(pin_hash),
                is_path_response: false,
                retained: true,
                last_used: None,
                name_hash: [0u8; 10],
                stamp: None,
                stamp_value: 0.0,
                lr_cost: None,
                facts_known: true,
            },
        );
        actor
            .pending_path_entries
            .push(crate::persistence::PersistedPathEntry {
                used: None,
                destination_hash: vec![0x13; 16],
                timestamp: now,
                next_hop: None,
                hops: 1,
                expires: now + 600.0,
                random_blobs: Vec::new(),
                interface_id: 9,
                interface_name: None,
                interface_hash: None,
                packet_hash: Some(pending_path_hash.to_vec()),
            });
        actor.cache_announce(&unflushed_path_hash, &[0x02; 40], 7);
        actor.cache_announce(&unflushed_orphan_hash, &[0x02; 40], 7);

        actor.clean_announce_cache();
        assert!(actor.kd.announce_clean_in_flight());
        // The flush of the pending rows, then the clean.
        settle(&mut actor);
        settle(&mut actor);
        assert!(!actor.kd.announce_clean_in_flight());

        for (hash, why) in [
            (path_hash, "path"),
            (tunnel_hash, "tunnel path"),
            (pending_path_hash, "restored path waiting for its interface"),
            (unflushed_path_hash, "path whose announce was still pending"),
        ] {
            assert!(
                actor.cached_announce(&hash).is_some(),
                "the announce of a {why} must survive the clean"
            );
        }
        for (hash, why) in [
            (orphan_hash, "orphan"),
            (pin_hash, "retained destination"),
            (unflushed_orphan_hash, "pending orphan"),
        ] {
            assert!(
                actor.cached_announce(&hash).is_none(),
                "the announce of a {why} must be removed"
            );
        }
        actor.on_shutdown();
        let _ = std::fs::remove_dir_all(&storage);
    }

    #[test]
    fn a_second_clean_waits_for_the_one_in_flight() {
        let storage = temp_storage("in-flight");
        let (mut actor, _tx) = TransportActor::new();
        actor.initialize_storage(storage.clone());
        actor.clean_announce_cache();
        actor.clean_announce_cache();
        settle(&mut actor);
        assert!(
            actor.kd.results.try_recv().is_err(),
            "only one clean was queued"
        );
        actor.on_shutdown();
        let _ = std::fs::remove_dir_all(&storage);
    }

    #[test]
    fn clean_is_not_queued_without_storage() {
        let (mut actor, _tx) = TransportActor::new();
        actor.clean_announce_cache();
        assert!(!actor.kd.announce_clean_in_flight());
    }

    /// Only legacy files and a persisted path: start-up imports the file, then
    /// restores the path from the database (`Transport.init_announce_cache`
    /// runs before the path table is loaded).
    #[test]
    fn a_path_whose_announce_is_a_legacy_file_is_restored_at_start() {
        let storage = temp_storage("legacy-restore");
        let now = crate::now_f64();
        let dest = [0xCA; 16];
        let packet_hash = [0x11; 32];
        let mut entry =
            crate::path_table::PathEntry::new(None, 1, 7, crate::constants::InterfaceMode::Gateway);
        entry.timestamp = now;
        entry.expires = now + 3600.0;
        entry.packet_hash = Some(packet_hash);
        let mut table = crate::path_table::PathTable::new();
        table.insert(dest, entry);
        let names = std::collections::HashMap::from([(7u64, "Border_TCP".to_string())]);
        crate::persistence::save_python_destination_table(
            &table,
            &names,
            &storage.join("destination_table"),
        )
        .unwrap();
        let legacy_dir = storage.join("cache").join("announces");
        crate::persistence::write_python_cached_announce(
            &legacy_dir,
            &packet_hash,
            &[0xFE; 42],
            Some("Border_TCP"),
        )
        .unwrap();

        let (mut actor, _tx) = TransportActor::new();
        actor.initialize_storage(storage.clone());
        assert_eq!(actor.pending_path_entries.len(), 1);
        assert_eq!(
            actor.pending_path_entries[0].destination_hash,
            dest.to_vec()
        );
        assert_eq!(
            actor.pending_path_entries[0].interface_name.as_deref(),
            Some("Border_TCP")
        );
        assert!(storage.join("cache").join("announces.db").is_file());
        assert!(
            !legacy_dir.join(hex::encode(packet_hash)).exists(),
            "the file was imported before the restore"
        );

        actor.on_shutdown();
        let _ = std::fs::remove_dir_all(&storage);
    }
}

#[cfg(test)]
mod async_save_tests {
    use super::*;

    fn temp_storage() -> std::path::PathBuf {
        static NEXT_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rns-async-save-{}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn dirty_actor(dir: &std::path::Path) -> TransportActor {
        let (mut actor, _tx) = TransportActor::new();
        actor.storage_dir = Some(dir.to_path_buf());
        let (interface_tx, _interface_rx) = tokio::sync::mpsc::channel(1);
        actor.interfaces.insert(
            7,
            crate::messages::InterfaceEntry::new(
                "persisted-test-interface".to_string(),
                crate::constants::InterfaceMode::Gateway,
                crate::constants::InterfaceDirection::bidirectional(),
                1_000_000,
                rns_wire::constants::MTU as u32,
                interface_tx,
            ),
        );
        actor.path_table.insert(
            [0x11; 16],
            crate::path_table::PathEntry {
                used: 0.0,
                timestamp: crate::now_f64(),
                next_hop: Some([0x22; 16]),
                hops: 1,
                expires: crate::now_f64() + 600.0,
                random_blobs: std::collections::VecDeque::new(),
                interface_id: 7,
                packet_hash: Some([0x33; 32]),
            },
        );
        actor.state_dirty = true;
        actor
    }

    /// Pending known-destination marks are handed to the store on the 10 s cadence,
    /// without waiting for the routing tables' periodic save.
    #[test]
    fn known_destinations_flush_on_their_own_cadence() {
        let dir = temp_storage();
        let mut actor = dirty_actor(&dir);
        actor.recent_announces.insert(
            [0x11; 16],
            RecentAnnounce {
                dest_hash: [0x11; 16],
                hops: 1,
                app_data: None,
                timestamp: crate::now_f64(),
                public_key: Some([0x25; 64]),
                ratchet: None,
                ratchet_received: None,
                packet_hash: None,
                is_path_response: false,
                retained: false,
                last_used: None,
                name_hash: [0u8; 10],
                stamp: None,
                stamp_value: 0.0,
                lr_cost: None,
                facts_known: true,
            },
        );
        let now = crate::now_f64();
        actor.last_state_save = now;
        actor.kd.pending.mark_dirty([0x11; 16]);
        actor.last_known_destinations_flush = now;
        actor.on_tick();
        assert!(
            !actor.kd.pending.is_empty(),
            "marks wait until the flush interval has passed"
        );
        actor.last_known_destinations_flush = now - KD_FLUSH_INTERVAL - 1.0;
        actor.on_tick();
        assert!(
            actor.kd.pending.is_empty(),
            "the tick hands the marks to the store"
        );
        assert!(
            !dir.join("path_table.msgpack").exists(),
            "routing tables wait for their own interval"
        );
        actor.last_state_save = now - STATE_SAVE_INTERVAL_SECS - 1.0;
        actor.on_tick();
        assert!(dir.join("path_table.msgpack").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A departing local client triggers a full persist once
    /// `GRACIOUS_PERSIST_INTERVAL` has passed since the last one.
    #[test]
    fn local_client_disconnect_persists_after_gracious_interval() {
        let dir = temp_storage();
        let mut actor = dirty_actor(&dir);
        for id in [8, 9] {
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            let mut client = crate::messages::InterfaceEntry::new(
                "local client".to_string(),
                crate::constants::InterfaceMode::Gateway,
                crate::constants::InterfaceDirection::bidirectional(),
                1_000_000,
                rns_wire::constants::MTU as u32,
                tx,
            );
            client.role = InterfaceRole::LocalClient;
            actor.interfaces.insert(id, client);
        }
        let path = dir.join("path_table.msgpack");

        actor.last_data_persist = crate::now_f64() - GRACIOUS_PERSIST_INTERVAL + 5.0;
        actor.deregister_interface(8);
        assert!(
            !path.exists(),
            "inside the gracious interval nothing persists"
        );

        let late = crate::now_f64() - GRACIOUS_PERSIST_INTERVAL - 1.0;
        actor.last_data_persist = late;
        actor
            .routing_save_in_flight
            .store(true, std::sync::atomic::Ordering::Release);
        actor.deregister_interface(9);
        assert_eq!(
            actor.last_data_persist, late,
            "a persist skipped behind a running one is not timed"
        );
        actor
            .routing_save_in_flight
            .store(false, std::sync::atomic::Ordering::Release);
        actor.maybe_gracious_persist();
        assert!(path.exists(), "a late disconnect persists");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Storage init defers the first announce-cache sweep by 60 s.
    #[test]
    fn storage_init_defers_the_first_announce_cache_sweep() {
        let dir = temp_storage();
        let (mut actor, _tx) = TransportActor::new();
        let before = crate::now_f64();
        actor.initialize_storage(dir.clone());
        assert!(actor.last_announce_cache_sweep >= before + ANNOUNCE_CACHE_SWEEP_DEFER);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The periodic save must never run the fsync chain on the actor: the
    /// tick path schedules to the blocking pool and returns immediately,
    /// clearing the dirty flag; the files appear once the pool task runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn periodic_save_writes_off_actor_and_clears_dirty() {
        let dir = temp_storage();
        let mut actor = dirty_actor(&dir);

        actor.save_routing_state_async();
        assert!(!actor.state_dirty, "dirty clears at scheduling time");

        let path = dir.join("path_table.msgpack");
        // Generous: the blocking pool competes with the whole suite's fsync
        // traffic on first run; the loop exits as soon as the file lands.
        // Write errors are swallowed by design (trace-logged, self-healed by
        // the next tick), so a transient CI failure (AV racing the tmp
        // rename, fsync storm) would leave a one-shot write unlanded forever
        // — model the periodic tick and reschedule after a failed attempt.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !path.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if !path.exists()
                && !actor
                    .routing_save_in_flight
                    .load(std::sync::atomic::Ordering::Acquire)
            {
                actor.state_dirty = true;
                actor.save_routing_state_async();
            }
        }
        assert!(path.exists(), "blocking-pool save must land on disk");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A save already in flight must NOT be raced by a second scheduling —
    /// the tmp-file names are shared. The skipped attempt keeps state_dirty
    /// set so the next interval retries.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn in_flight_save_skips_and_keeps_dirty() {
        let dir = temp_storage();
        let mut actor = dirty_actor(&dir);
        actor
            .routing_save_in_flight
            .store(true, std::sync::atomic::Ordering::Release);

        actor.save_routing_state_async();
        assert!(
            actor.state_dirty,
            "skipped save must leave state_dirty for retry"
        );
        assert!(!dir.join("path_table.msgpack").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The synchronous path (shutdown / falling edge) serializes behind an
    /// in-flight publication, then completes inline.
    #[test]
    fn sync_save_waits_for_in_flight_then_writes() {
        let dir = temp_storage();
        let mut actor = dirty_actor(&dir);

        let write_lock = actor.routing_save_lock.clone();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let release = std::thread::spawn(move || {
            let _guard = write_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            acquired_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(150));
        });
        acquired_rx.recv().unwrap();

        let started = std::time::Instant::now();
        actor.save_routing_state();
        release.join().unwrap();

        assert!(
            started.elapsed() >= std::time::Duration::from_millis(140),
            "sync save must serialize behind the active writer"
        );
        assert!(dir.join("path_table.msgpack").exists());
        assert!(!actor.state_dirty);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A queued periodic snapshot that loses the generation race must not
    /// publish after a newer synchronous snapshot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn superseded_periodic_snapshot_cannot_replace_sync_state() {
        let dir = temp_storage();
        let path = dir.join("path_table.msgpack");
        let mut actor = dirty_actor(&dir);
        let write_lock = actor.routing_save_lock.clone();
        let guard = write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        actor.save_routing_state_async();
        let generation = actor.routing_save_generation.clone();
        let sync_writer = std::thread::spawn(move || {
            actor.path_table.insert(
                [0x44; 16],
                crate::path_table::PathEntry {
                    used: 0.0,
                    timestamp: crate::now_f64(),
                    next_hop: Some([0x55; 16]),
                    hops: 2,
                    expires: crate::now_f64() + 600.0,
                    random_blobs: std::collections::VecDeque::new(),
                    interface_id: 7,
                    packet_hash: Some([0x66; 32]),
                },
            );
            actor.save_routing_state();
            actor
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while generation.load(std::sync::atomic::Ordering::Acquire) < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "sync writer did not claim a newer generation"
            );
            std::thread::yield_now();
        }
        drop(guard);
        let actor = sync_writer.join().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while actor
            .routing_save_in_flight
            .load(std::sync::atomic::Ordering::Acquire)
        {
            assert!(
                std::time::Instant::now() < deadline,
                "superseded periodic writer did not retire"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let entries = crate::persistence::load_path_table(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .any(|entry| entry.destination_hash == [0x44; 16])
        );
        assert!(
            !actor
                .routing_save_in_flight
                .load(std::sync::atomic::Ordering::Acquire)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Python 1.6.1 saves and loads `announce_rate_table` only on a transport
    /// instance that owns its storage (Transport.py).
    #[test]
    fn a_transport_instance_keeps_its_announce_rate_table_across_restarts() {
        let dir = temp_storage();
        let file = dir.join(ANNOUNCE_RATE_TABLE_FILE);
        let (mut leaf, _) = TransportActor::new();
        leaf.storage_dir = Some(dir.clone());
        leaf.rate_table
            .check_interface_rate([0x31; 16], 60.0, 0, 0.0);
        leaf.save_state();
        assert!(!file.exists(), "a leaf persists no rate table");

        let (mut actor, _) = TransportActor::new();
        actor.is_transport_enabled = true;
        actor.storage_dir = Some(dir.clone());
        for _ in 0..2 {
            actor
                .rate_table
                .check_interface_rate([0x31; 16], 60.0, 0, 0.0);
        }
        actor.save_state();
        assert!(file.exists());

        let (mut restarted, _) = TransportActor::new();
        restarted.is_transport_enabled = true;
        restarted.initialize_storage(dir.clone());
        let (_, entry) = restarted.rate_table.iter().next().expect("loaded");
        let (_, saved) = actor.rate_table.iter().next().unwrap();
        assert_eq!(
            (&entry.timestamps, entry.violations, entry.blocked_until),
            (&saved.timestamps, 1, saved.blocked_until)
        );

        std::fs::write(&file, b"RNSART").unwrap();
        let (mut damaged, _) = TransportActor::new();
        damaged.is_transport_enabled = true;
        damaged.initialize_storage(dir.clone());
        assert_eq!(damaged.rate_table.len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
