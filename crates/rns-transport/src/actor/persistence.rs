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
        raw_packet,
        retained: false,
        name_hash: [0u8; 10],
    };

    if let Ok((header, offset)) = rns_wire::header::PacketHeader::unpack(&recent.raw_packet)
        && header.flags.packet_type == rns_wire::flags::PacketType::Announce
        && header.destination_hash == dest_hash
        && recent.raw_packet.len() >= offset
        && let Ok(announce) = rns_identity::announce::AnnounceData::unpack(
            &recent.raw_packet[offset..],
            header.flags.context_flag,
        )
    {
        recent.app_data = announce.app_data;
        recent.public_key = Some(announce.public_key);
        recent.ratchet = announce.ratchet;
        recent.name_hash = announce.name_hash;
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

impl TransportActor {
    /// Flush the small/critical routing-state files: path_table,
    /// announce_cache, blackhole_table, tunnel_table. Hashlist is excluded —
    /// it can be multiple MB and is rebuildable from in-flight traffic, so
    /// we save it only on shutdown / falling-edge via `save_state`.
    /// Called from the periodic `on_tick` save (every
    /// `STATE_SAVE_INTERVAL_SECS`, gated on `state_dirty`). Clears
    /// `state_dirty` and bumps `last_state_save` so the periodic trigger
    /// doesn't double-fire.
    pub(super) fn save_routing_state(&mut self) {
        if self.shared_instance_client_mode {
            trace!("skipping routing-state save in shared-instance client mode");
            self.state_dirty = false;
            self.last_state_save = now();
            return;
        }

        if let Some(ref dir) = self.storage_dir {
            let interface_names: std::collections::HashMap<u64, String> = self
                .interfaces
                .iter()
                .map(|(&id, entry)| (id, entry.name.clone()))
                .collect();

            let path_table_path = dir.join("path_table.msgpack");
            if let Err(e) = crate::persistence::save_path_table(
                &self.path_table,
                &interface_names,
                &path_table_path,
            ) {
                trace!("failed to save path table: {}", e);
            } else {
                debug!("saved path table ({} entries)", self.path_table.len());
            }

            let destination_table_path = dir.join("destination_table");
            if let Err(e) = crate::persistence::save_python_destination_table(
                &self.path_table,
                &interface_names,
                &destination_table_path,
            ) {
                trace!("failed to save Python destination_table: {}", e);
            }

            let blackhole_path = dir.join("blackhole_table.msgpack");
            if let Err(e) =
                crate::persistence::save_blackhole_table(&self.blackhole_table, &blackhole_path)
            {
                trace!("failed to save blackhole table: {}", e);
            } else {
                debug!(
                    "saved blackhole table ({} entries)",
                    self.blackhole_table.len()
                );
            }

            if let Some(local_identity_hash) = self.transport_identity_hash {
                let blackhole_dir = dir.join("blackhole");
                if let Err(e) = crate::persistence::save_python_blackhole_files(
                    &self.blackhole_table,
                    local_identity_hash,
                    &blackhole_dir,
                ) {
                    trace!("failed to save Python blackhole files: {}", e);
                }
            }

            let announce_path = dir.join("announce_cache.msgpack");
            if let Err(e) = crate::persistence::save_announce_cache(
                self.recent_announces.values(),
                &announce_path,
            ) {
                trace!("failed to save announce cache: {}", e);
            } else {
                debug!(
                    "saved announce cache ({} entries)",
                    self.recent_announces.len()
                );
            }

            let announce_cache_dir = dir.join("cache").join("announces");
            if let Err(e) = crate::persistence::save_python_announce_cache_for_paths_and_tunnels(
                &self.path_table,
                Some(&self.tunnel_table),
                self.recent_announces.values(),
                &interface_names,
                &announce_cache_dir,
            ) {
                trace!("failed to save Python announce cache files: {}", e);
            }

            let tunnel_path = dir.join("tunnel_table.msgpack");
            if let Err(e) = crate::persistence::save_tunnel_table(
                &self.tunnel_table,
                &interface_names,
                &tunnel_path,
            ) {
                trace!("failed to save tunnel table: {}", e);
            } else {
                debug!("saved tunnel table ({} entries)", self.tunnel_table.len());
            }

            let python_tunnels_path = dir.join("tunnels");
            if let Err(e) = crate::persistence::save_python_tunnel_table(
                &self.tunnel_table,
                &interface_names,
                &python_tunnels_path,
            ) {
                trace!("failed to save Python tunnels table: {}", e);
            }

            // Single-line summary for diagnosing periodic routing-state saves
            // without surfacing normal flushes at default log levels.
            debug!(
                paths = self.path_table.len(),
                announces = self.recent_announces.len(),
                tunnels = self.tunnel_table.len(),
                blackhole = self.blackhole_table.len(),
                "flushed routing state"
            );
        }
        self.state_dirty = false;
        self.last_state_save = now();
    }

    /// Flush every persisted table including the (potentially large) packet
    /// hashlist. Called on `on_shutdown` and the foreground→background
    /// falling edge — both are infrequent and worth the full snapshot.
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
            match crate::persistence::load_announce_cache(&announce_path) {
                Ok(entries) => {
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
                            self.recent_announces
                                .entry(hash)
                                .or_insert_with(|| RecentAnnounce {
                                    dest_hash: hash,
                                    hops: ae.hops,
                                    app_data: ae.app_data,
                                    timestamp: ae.timestamp,
                                    public_key,
                                    ratchet,
                                    raw_packet: ae.raw_packet,
                                    retained: ae.retained,
                                    name_hash,
                                });
                        }
                    }
                    debug!(count, expired, "loaded announce cache entries from disk");
                }
                Err(e) => {
                    trace!("failed to load announce cache: {}", e);
                }
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
