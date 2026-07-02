use super::*;
use tracing::info;

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
) -> RecentAnnounce {
    let mut recent = RecentAnnounce {
        dest_hash,
        hops,
        app_data: None,
        timestamp,
        public_key: None,
        ratchet: None,
        packet_hash: None,
        is_path_response: false,
        retained: false,
        last_used: None,
        name_hash: [0u8; 10],
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
            recent.app_data = announce.app_data;
            recent.public_key = Some(announce.public_key);
            recent.ratchet = announce.ratchet;
            recent.name_hash = announce.name_hash;
        }
    }

    recent
}

fn python_announce_cache_index(
    announce_cache_dir: &std::path::Path,
) -> Option<std::collections::HashSet<String>> {
    match std::fs::read_dir(announce_cache_dir) {
        Ok(entries) => {
            let mut names = std::collections::HashSet::new();
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str()
                    && name.len() == 64
                    && name.as_bytes().iter().all(u8::is_ascii_hexdigit)
                {
                    names.insert(name.to_ascii_lowercase());
                }
            }
            Some(names)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Some(std::collections::HashSet::new())
        }
        Err(_) => None,
    }
}

fn load_indexed_python_cached_announce(
    announce_cache_dir: &std::path::Path,
    cache_index: Option<&std::collections::HashSet<String>>,
    packet_hash: &[u8; 32],
) -> Result<Option<crate::persistence::PythonCachedAnnounce>, crate::persistence::PersistenceError>
{
    if let Some(index) = cache_index {
        let name = hex::encode(packet_hash);
        if !index.contains(&name) {
            return Ok(None);
        }
    }

    crate::persistence::load_python_cached_announce(announce_cache_dir, packet_hash)
}

/// Owned copy of everything `write_routing_snapshot` persists, so the disk
/// I/O (fsync-heavy on macOS: F_FULLFSYNC per file + dir) can run on the
/// blocking pool without borrowing the actor.
pub(super) struct RoutingSnapshot {
    pub path_table: crate::path_table::PathTable,
    pub tunnel_table: crate::tunnel::TunnelTable,
    pub blackhole_table: crate::blackhole::BlackholeTable,
    pub recent_announces: Vec<RecentAnnounce>,
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

    if let Some(local_identity_hash) = snapshot.transport_identity_hash {
        let blackhole_dir = dir.join("blackhole");
        if let Err(e) = crate::persistence::save_python_blackhole_files(
            &snapshot.blackhole_table,
            local_identity_hash,
            &blackhole_dir,
        ) {
            trace!("failed to save Python blackhole files: {}", e);
        }
    }

    let announce_path = dir.join("announce_cache.msgpack");
    if let Err(e) =
        crate::persistence::save_announce_cache(snapshot.recent_announces.iter(), &announce_path)
    {
        trace!("failed to save announce cache: {}", e);
    } else {
        debug!(
            "saved announce cache ({} entries)",
            snapshot.recent_announces.len()
        );
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
        announces = snapshot.recent_announces.len(),
        tunnels = snapshot.tunnel_table.len(),
        blackhole = snapshot.blackhole_table.len(),
        "flushed routing state"
    );
}

impl TransportActor {
    /// Fetch raw announce bytes from the disk announce cache
    /// (`cache/announces/<packet_hash>`). Misses are normal: legacy entries,
    /// cleaned cache files, or shared-instance client mode.
    pub(super) fn cached_announce_raw(&self, packet_hash: &[u8; 32]) -> Option<Vec<u8>> {
        let dir = self.storage_dir.as_ref()?;
        let announce_cache_dir = dir.join("cache").join("announces");
        match crate::persistence::load_python_cached_announce(&announce_cache_dir, packet_hash) {
            Ok(Some(cached)) => Some(cached.raw_packet),
            Ok(None) => None,
            Err(e) => {
                trace!("failed to load cached announce: {}", e);
                None
            }
        }
    }

    /// Event-driven announce cache write at receive (Python parity:
    /// `Transport.cache(packet, force_cache=True)` on announce ingest).
    /// One file per announce packet; skipped when the file already exists
    /// (SINGLE announces are retransmitted byte-identical). No fsync — the
    /// cache is best-effort and rebuilt from live traffic, and an fsync
    /// chain here would stall the actor on every announce.
    pub(super) fn cache_announce_to_disk(
        &self,
        packet_hash: &[u8; 32],
        raw: &[u8],
        interface_id: InterfaceId,
    ) {
        if self.shared_instance_client_mode {
            return;
        }
        let Some(dir) = self.storage_dir.as_ref() else {
            return;
        };
        let announce_cache_dir = dir.join("cache").join("announces");
        let interface_name = self
            .interfaces
            .get(&interface_id)
            .map(|entry| entry.name.clone());
        if let Err(e) = crate::persistence::write_python_cached_announce_if_absent(
            &announce_cache_dir,
            packet_hash,
            raw,
            interface_name.as_deref(),
        ) {
            trace!("failed to write announce cache file: {}", e);
        }
    }

    fn routing_snapshot(&self) -> RoutingSnapshot {
        RoutingSnapshot {
            path_table: self.path_table.clone(),
            tunnel_table: self.tunnel_table.clone(),
            blackhole_table: self.blackhole_table.clone(),
            recent_announces: self.recent_announces.values().cloned().collect(),
            interface_names: self
                .interfaces
                .iter()
                .map(|(&id, entry)| (id, entry.name.clone()))
                .collect(),
            transport_identity_hash: self.transport_identity_hash,
        }
    }

    /// Periodic flush used by `on_tick`: snapshot on the actor (cheap clones)
    /// and push the fsync-heavy writes to the blocking pool. A save already
    /// in flight keeps `state_dirty` set so the next tick retries — two
    /// writers would race on the shared `<file>.tmp` names.
    pub(super) fn save_routing_state_async(&mut self) {
        if self.shared_instance_client_mode {
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
        let in_flight = self.routing_save_in_flight.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(move || {
                    write_routing_snapshot(&dir, &snapshot);
                    in_flight.store(false, std::sync::atomic::Ordering::Release);
                });
            }
            Err(_) => {
                // No runtime (tests, exotic embedders): write inline.
                write_routing_snapshot(&dir, &snapshot);
                in_flight.store(false, std::sync::atomic::Ordering::Release);
            }
        }
        self.state_dirty = false;
        self.last_state_save = now();
    }

    /// Wait (bounded) for an in-flight async save so a synchronous save
    /// can't race it on the shared `<file>.tmp` paths.
    pub(super) fn wait_for_routing_save(&self) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while self
            .routing_save_in_flight
            .load(std::sync::atomic::Ordering::Acquire)
        {
            if std::time::Instant::now() >= deadline {
                tracing::warn!("in-flight routing-state save did not finish before sync save");
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Flush the small/critical routing-state files: path_table,
    /// announce_cache, blackhole_table, tunnel_table. Hashlist is excluded —
    /// it can be multiple MB and is rebuildable from in-flight traffic, so
    /// we save it only on shutdown / falling-edge via `save_state`.
    /// Synchronous: used by shutdown / falling-edge / RPC-forced saves where
    /// completion must be guaranteed before proceeding.
    pub(super) fn save_routing_state(&mut self) {
        if self.shared_instance_client_mode {
            trace!("skipping routing-state save in shared-instance client mode");
            self.state_dirty = false;
            self.last_state_save = now();
            return;
        }

        self.wait_for_routing_save();
        if let Some(dir) = self.storage_dir.clone() {
            let snapshot = self.routing_snapshot();
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
        if self.shared_instance_client_mode {
            return;
        }

        if let Some(ref dir) = self.storage_dir {
            let hashlist_path = dir.join("packet_hashlist");
            if let Err(e) = crate::persistence::save_hashlist(&self.packet_hashlist, &hashlist_path)
            {
                trace!("failed to save hashlist: {}", e);
            } else {
                info!(entries = self.packet_hashlist.len(), "flushed hashlist");
            }
        }
    }

    /// Falling-edge (foreground→background) flush. Same coverage as
    /// `save_state` but entirely off-actor: on desktop the edge fires on
    /// every window focus loss, and the inline fsync chain (F_FULLFSYNC per
    /// file on macOS) stalls routing + control queries for seconds.
    pub(super) fn save_state_async(&mut self) {
        self.save_routing_state_async();
        if self.shared_instance_client_mode {
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
        let hashlist = self.packet_hashlist.clone();
        let in_flight = self.hashlist_save_in_flight.clone();
        let entries = hashlist.len();
        let write = move || {
            let hashlist_path = dir.join("packet_hashlist");
            if let Err(e) = crate::persistence::save_hashlist(&hashlist, &hashlist_path) {
                trace!("failed to save hashlist: {}", e);
            } else {
                info!(entries, "flushed hashlist");
            }
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
        self.save_state();
    }

    /// Restore on-disk transport state. Entries can't bind to a concrete
    /// `interface_id` until the matching interface re-registers, so they're
    /// staged in `pending_path_entries` / `pending_tunnel_entries` and
    /// drained by `RegisterInterface`. Entries lacking `interface_name`
    /// (pre-v3) are dropped — `interface_id` is volatile across boots.
    pub(super) fn load_state(&mut self) {
        let Some(dir) = self.storage_dir.clone() else {
            return;
        };
        let now_ts = now();

        // packet_hashlist — Python-compatible canonical shape. Fall back to
        // the old Rust sidecar so existing local development state still loads.
        let hashlist_path = dir.join("packet_hashlist");
        let legacy_hashlist_path = dir.join("hashlist.msgpack");
        let hashlist_path = if hashlist_path.exists() {
            Some(hashlist_path)
        } else if legacy_hashlist_path.exists() {
            Some(legacy_hashlist_path)
        } else {
            None
        };
        if let Some(hashlist_path) = hashlist_path {
            match crate::persistence::load_hashlist(&hashlist_path) {
                Ok(hashes) => {
                    let count = hashes.len();
                    self.packet_hashlist.load_from(hashes);
                    debug!(count, "loaded packet hashlist from disk");
                }
                Err(e) => {
                    trace!("failed to load packet hashlist: {}", e);
                }
            }
        }

        // Python destination_table — canonical interop shape. Defer interface
        // hash remap until matching interfaces register.
        let destination_table_path = dir.join("destination_table");
        let loaded_python_destination_table = if destination_table_path.exists() {
            match crate::persistence::load_python_destination_table(&destination_table_path) {
                Ok(entries) => {
                    let total = entries.len();
                    let mut expired = 0usize;
                    let mut missing_cache = 0usize;
                    let mut pending = 0usize;
                    let announce_cache_dir = dir.join("cache").join("announces");
                    let announce_cache_index = python_announce_cache_index(&announce_cache_dir);
                    for pe in entries {
                        if pe.expires <= now_ts {
                            expired += 1;
                            continue;
                        }
                        let cached = match load_indexed_python_cached_announce(
                            &announce_cache_dir,
                            announce_cache_index.as_ref(),
                            &pe.packet_hash,
                        ) {
                            Ok(Some(cached)) => cached,
                            Ok(None) => {
                                missing_cache += 1;
                                continue;
                            }
                            Err(_) => {
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
                            });
                        self.recent_announces
                            .entry(pe.destination_hash)
                            .or_insert_with(|| {
                                recent_announce_from_cached_packet(
                                    pe.destination_hash,
                                    pe.hops,
                                    pe.timestamp,
                                    cached.raw_packet,
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
        if !loaded_python_destination_table && path_table_path.exists() {
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
                    debug!("loaded {} blackhole entries from disk", count);
                }
                Err(e) => {
                    trace!("failed to load blackhole table: {}", e);
                }
            }
        }
        self.load_python_blackhole_if_ready();

        // Python tunnels — canonical interop shape. Each path is only staged
        // when its cached announce packet is present, mirroring upstream's
        // dependency between tunnel paths and the announce cache.
        let python_tunnels_path = dir.join("tunnels");
        let loaded_python_tunnel_table = if python_tunnels_path.exists() {
            match crate::persistence::load_python_tunnel_table(&python_tunnels_path) {
                Ok(entries) => {
                    let total = entries.len();
                    let mut expired = 0usize;
                    let mut missing_cache = 0usize;
                    let mut legacy = 0usize;
                    let mut pending = 0usize;
                    let announce_cache_dir = dir.join("cache").join("announces");
                    let announce_cache_index = python_announce_cache_index(&announce_cache_dir);
                    for te in entries {
                        if te.expires <= now_ts {
                            expired += 1;
                            continue;
                        }

                        let mut paths = Vec::new();
                        let mut interface_name = None;
                        let mut interface_hash =
                            te.interface_hash.as_ref().map(|hash| hash.to_vec());

                        for tp in te.paths {
                            if tp.expires <= now_ts {
                                expired += 1;
                                continue;
                            }
                            if interface_hash.is_none() {
                                interface_hash =
                                    tp.interface_hash.as_ref().map(|hash| hash.to_vec());
                            }
                            let cached = match load_indexed_python_cached_announce(
                                &announce_cache_dir,
                                announce_cache_index.as_ref(),
                                &tp.packet_hash,
                            ) {
                                Ok(Some(cached)) => cached,
                                Ok(None) | Err(_) => {
                                    missing_cache += 1;
                                    continue;
                                }
                            };
                            if interface_name.is_none() {
                                interface_name = cached.interface_reference.clone();
                            }
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
                            });
                            self.recent_announces
                                .entry(tp.destination_hash)
                                .or_insert_with(|| {
                                    recent_announce_from_cached_packet(
                                        tp.destination_hash,
                                        tp.hops,
                                        tp.timestamp,
                                        cached.raw_packet,
                                    )
                                });
                        }

                        if paths.is_empty() {
                            continue;
                        }
                        if interface_name.is_none() && interface_hash.is_none() {
                            legacy += 1;
                            continue;
                        }
                        self.pending_tunnel_entries.push(
                            crate::persistence::PersistedTunnelEntry {
                                tunnel_id: te.tunnel_id.to_vec(),
                                interface_id: 0,
                                expires: te.expires,
                                paths,
                                interface_name,
                                interface_hash,
                            },
                        );
                        pending += 1;
                    }
                    debug!(
                        total,
                        pending, expired, missing_cache, legacy, "staged Python tunnel entries"
                    );
                    pending > 0
                }
                Err(e) => {
                    trace!("failed to load Python tunnels table: {}", e);
                    false
                }
            }
        } else {
            false
        };

        // tunnel_table — legacy Rust sidecar fallback, defer remap.
        let tunnel_path = dir.join("tunnel_table.msgpack");
        if !loaded_python_tunnel_table && tunnel_path.exists() {
            match crate::persistence::load_tunnel_table(&tunnel_path) {
                Ok(entries) => {
                    let total = entries.len();
                    let mut expired = 0usize;
                    let mut legacy = 0usize;
                    let mut pending = 0usize;
                    for te in entries {
                        if te.tunnel_id.len() != 32 {
                            continue;
                        }
                        if te.expires <= now_ts {
                            expired += 1;
                            continue;
                        }
                        if te.interface_name.is_none() && te.interface_hash.is_none() {
                            legacy += 1;
                            continue;
                        }
                        self.pending_tunnel_entries.push(te);
                        pending += 1;
                    }
                    debug!(
                        total,
                        pending, expired, legacy, "staged tunnel entries from disk"
                    );
                }
                Err(e) => {
                    trace!("failed to load tunnel table: {}", e);
                }
            }
        }

        // announce_cache — no interface dependency, bind directly.
        let announce_path = dir.join("announce_cache.msgpack");
        if announce_path.exists() {
            let loaded = match crate::persistence::load_announce_cache(&announce_path) {
                Ok(entries) => Some(entries),
                Err(v6_err) => {
                    // Pre-v6 caches carried raw announce bytes inline. Migrate
                    // them into per-packet disk cache files once, then proceed
                    // with the slim v6 metadata shape.
                    match crate::persistence::load_announce_cache_legacy_v5(&announce_path) {
                        Ok(legacy) => {
                            let announce_cache_dir = dir.join("cache").join("announces");
                            let migrated = crate::persistence::migrate_legacy_announce_entries(
                                legacy,
                                &announce_cache_dir,
                            );
                            debug!(
                                count = migrated.len(),
                                "migrated legacy announce cache to disk-backed v6"
                            );
                            Some(migrated)
                        }
                        Err(_) => {
                            trace!("failed to load announce cache: {}", v6_err);
                            None
                        }
                    }
                }
            };
            if let Some(entries) = loaded {
                let count = entries.len();
                let mut expired = 0usize;
                for ae in entries {
                    if ae.destination_hash.len() == 16 {
                        let mut hash = [0u8; 16];
                        hash.copy_from_slice(&ae.destination_hash);
                        let stale_pathless = !ae.retained
                            && !self.recent_announces.contains_key(&hash)
                            && now_ts - ae.timestamp > DESTINATION_TIMEOUT as f64;
                        if stale_pathless {
                            expired += 1;
                            continue;
                        }
                        let public_key = ae.public_key.and_then(|k| {
                            if k.len() == 64 {
                                let mut arr = [0u8; 64];
                                arr.copy_from_slice(&k);
                                Some(arr)
                            } else {
                                None
                            }
                        });
                        let ratchet = ae.ratchet.and_then(|r| {
                            if r.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&r);
                                Some(arr)
                            } else {
                                None
                            }
                        });
                        let name_hash = if ae.name_hash.len() == 10 {
                            let mut nh = [0u8; 10];
                            nh.copy_from_slice(&ae.name_hash);
                            nh
                        } else {
                            [0u8; 10]
                        };
                        let packet_hash = ae.packet_hash.and_then(|h| {
                            if h.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&h);
                                Some(arr)
                            } else {
                                None
                            }
                        });
                        self.recent_announces
                            .entry(hash)
                            .or_insert_with(|| RecentAnnounce {
                                dest_hash: hash,
                                hops: ae.hops,
                                app_data: ae.app_data,
                                timestamp: ae.timestamp,
                                public_key,
                                ratchet,
                                packet_hash,
                                is_path_response: ae.is_path_response,
                                retained: ae.retained,
                                last_used: ae.last_used,
                                name_hash,
                            });
                    }
                }
                debug!(count, expired, "loaded announce cache entries from disk");
            }
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
                    debug!(count, "loaded Python blackhole files");
                }
            }
            Err(e) => {
                trace!("failed to load Python blackhole files: {}", e);
            }
        }
    }

    /// Drain pending path/tunnel entries whose `interface_name` matches the
    /// just-registered interface. Bound to `RegisterInterface` so each entry
    /// rebinds to whatever `interface_id` the runtime allocated this boot.
    pub(super) fn drain_pending_for_interface(&mut self, id: InterfaceId, name: &str) {
        if !self.pending_path_entries.is_empty() {
            let mut promoted = 0usize;
            self.pending_path_entries.retain(|pe| {
                let name_matches = pe.interface_name.as_deref() == Some(name);
                let hash_matches = pe.interface_hash.as_deref().is_some_and(|hash| {
                    hash == crate::persistence::interface_hash_from_name(name).as_slice()
                });
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

        if !self.pending_tunnel_entries.is_empty() {
            let mut promoted = 0usize;
            self.pending_tunnel_entries.retain(|te| {
                let name_matches = te.interface_name.as_deref() == Some(name);
                let hash_matches = te.interface_hash.as_deref().is_some_and(|hash| {
                    hash == crate::persistence::interface_hash_from_name(name).as_slice()
                });
                if !name_matches && !hash_matches {
                    return true;
                }
                if te.tunnel_id.len() != 32 {
                    return false;
                }
                let mut tunnel_id = [0u8; 32];
                tunnel_id.copy_from_slice(&te.tunnel_id);
                let mut tunnel_paths = std::collections::HashMap::new();
                for tp in &te.paths {
                    if tp.destination_hash.len() == 16 {
                        let mut dest = [0u8; 16];
                        dest.copy_from_slice(&tp.destination_hash);
                        let next_hop = tp.next_hop.as_ref().and_then(|next_hop| {
                            if next_hop.len() == 16 {
                                let mut arr = [0u8; 16];
                                arr.copy_from_slice(next_hop);
                                Some(arr)
                            } else {
                                None
                            }
                        });
                        let packet_hash = tp.packet_hash.as_ref().and_then(|packet_hash| {
                            if packet_hash.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(packet_hash);
                                Some(arr)
                            } else {
                                None
                            }
                        });
                        let random_blobs = tp
                            .random_blobs
                            .iter()
                            .filter_map(|blob| {
                                if blob.len() == 10 {
                                    let mut arr = [0u8; 10];
                                    arr.copy_from_slice(blob);
                                    Some(arr)
                                } else {
                                    None
                                }
                            })
                            .collect();
                        tunnel_paths.insert(
                            dest,
                            crate::tunnel::TunnelPath {
                                timestamp: tp.timestamp,
                                next_hop,
                                hops: tp.hops,
                                expires: tp.expires,
                                random_blobs,
                                packet_hash,
                            },
                        );
                    }
                }
                let entry = crate::tunnel::TunnelEntry {
                    tunnel_id,
                    interface_id: id,
                    tunnel_paths,
                    expires: te.expires,
                };
                self.tunnel_table.insert(entry);
                promoted += 1;
                false
            });
            if promoted > 0 {
                debug!(
                    interface_id = id,
                    name = %name,
                    promoted,
                    "rebound persisted tunnel entries to live interface"
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

#[cfg(test)]
mod async_save_tests {
    use super::*;

    fn temp_storage() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rns-async-save-{}-{}",
            std::process::id(),
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
        actor.path_table.insert(
            [0x11; 16],
            crate::path_table::PathEntry {
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

    /// The synchronous path (shutdown / falling edge) waits for an in-flight
    /// async save before writing, then completes inline.
    #[test]
    fn sync_save_waits_for_in_flight_then_writes() {
        let dir = temp_storage();
        let mut actor = dirty_actor(&dir);

        let flag = actor.routing_save_in_flight.clone();
        flag.store(true, std::sync::atomic::Ordering::Release);
        let release = std::thread::spawn({
            let flag = flag.clone();
            move || {
                std::thread::sleep(std::time::Duration::from_millis(150));
                flag.store(false, std::sync::atomic::Ordering::Release);
            }
        });

        let started = std::time::Instant::now();
        actor.save_routing_state();
        release.join().unwrap();

        assert!(
            started.elapsed() >= std::time::Duration::from_millis(140),
            "sync save must wait out the in-flight writer"
        );
        assert!(dir.join("path_table.msgpack").exists());
        assert!(!actor.state_dirty);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
