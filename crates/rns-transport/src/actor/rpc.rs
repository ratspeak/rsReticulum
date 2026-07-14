use super::*;
use crate::now_f64;

impl TransportActor {
    pub(super) fn handle_query(
        &mut self,
        query: crate::messages::TransportQuery,
    ) -> crate::messages::TransportQueryResponse {
        use crate::messages::*;
        match query {
            TransportQuery::GetPathTable => {
                let entries: Vec<PathTableRpcEntry> = self
                    .path_table
                    .iter_live()
                    .map(|(hash, entry)| {
                        let iface_name = self
                            .interfaces
                            .get(&entry.interface_id)
                            .map(|e| e.name.clone())
                            .unwrap_or_else(|| format!("interface_{}", entry.interface_id));
                        PathTableRpcEntry {
                            hash: hash.into_bytes(),
                            timestamp: entry.timestamp,
                            via: entry.next_hop,
                            hops: entry.hops,
                            expires: entry.expires,
                            interface: iface_name,
                            interface_id: entry.interface_id,
                            interface_mode: self
                                .interfaces
                                .get(&entry.interface_id)
                                .map(|e| e.mode)
                                .unwrap_or(crate::constants::InterfaceMode::Full),
                            interface_role: self
                                .interfaces
                                .get(&entry.interface_id)
                                .map(|e| e.role)
                                .unwrap_or_default(),
                        }
                    })
                    .collect();
                TransportQueryResponse::PathTable(entries)
            }
            TransportQuery::GetInterfaceStats => {
                let now = now_f64();
                let stats: Vec<InterfaceStatRpcEntry> = self
                    .interfaces
                    .iter()
                    .map(|(&iface_id, entry)| {
                        let online = entry
                            .online
                            .as_ref()
                            .map(|o| o.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(true);
                        let rx_bytes = entry
                            .rxb
                            .as_ref()
                            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(0);
                        let tx_bytes = entry
                            .txb
                            .as_ref()
                            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(0);
                        InterfaceStatRpcEntry {
                            id: iface_id,
                            name: entry.name.clone(),
                            rx_bytes,
                            tx_bytes,
                            rx_rate: 0,
                            tx_rate: 0,
                            online,
                            bitrate: entry.bitrate,
                            mtu: entry.mtu,
                            mode: format!("{:?}", entry.mode),
                            role: entry.role.as_str().to_string(),
                            announce_queue: Some(entry.announce_queue.len() as u64),
                            held_announces: entry.ingress.held_count() as u64,
                            incoming_announce_frequency: entry
                                .ingress
                                .incoming_announce_frequency(),
                            outgoing_announce_frequency: entry
                                .ingress
                                .outgoing_announce_frequency(),
                            incoming_pr_frequency: entry.ingress.incoming_pr_frequency(),
                            outgoing_pr_frequency: entry.ingress.outgoing_pr_frequency(),
                            burst_active: entry.ingress.is_burst_active(),
                            burst_activated: activation_epoch(
                                now,
                                entry.ingress.is_burst_active(),
                                entry.ingress.burst_activated(),
                            ),
                            pr_burst_active: entry.ingress.is_pr_burst_active(),
                            pr_burst_activated: activation_epoch(
                                now,
                                entry.ingress.is_pr_burst_active(),
                                entry.ingress.pr_burst_activated(),
                            ),
                            clients: None,
                            announce_rate_target: entry.announce_rate_target,
                            announce_rate_grace: entry.announce_rate_grace,
                            announce_rate_penalty: entry.announce_rate_penalty,
                            announce_cap: entry.announce_cap,
                            ifac_size: entry.ifac_size,
                            tx_drops: entry.tx_drops.load(std::sync::atomic::Ordering::Relaxed),
                        }
                    })
                    .collect();
                TransportQueryResponse::InterfaceStats(stats)
            }
            TransportQuery::GetRateTable => {
                let entries: Vec<RateTableRpcEntry> = self
                    .rate_table
                    .iter()
                    .map(|(hash, entry)| RateTableRpcEntry {
                        hash: hash.into_bytes(),
                        rate: entry.rate,
                        last: entry.last,
                        rate_violations: entry.violations,
                        blocked_until: entry.blocked_until,
                        timestamps: entry.timestamps.clone(),
                    })
                    .collect();
                TransportQueryResponse::RateTable(entries)
            }
            TransportQuery::GetLinkCount => {
                TransportQueryResponse::IntResult(self.link_table.len() as i64)
            }
            TransportQuery::GetRecentAnnounces => {
                let mut entries: Vec<AnnounceRpcEntry> = self
                    .recent_announces
                    .values()
                    .map(|a| {
                        let is_path_response = a.is_path_response;
                        AnnounceRpcEntry {
                            dest_hash: a.dest_hash,
                            hops: a.hops,
                            app_data: a.app_data.clone(),
                            timestamp: a.timestamp,
                            public_key: a.public_key,
                            ratchet: a.ratchet,
                            name_hash: a.name_hash,
                            is_path_response,
                            retained: a.retained,
                        }
                    })
                    .collect();
                // HashMap iteration order is unspecified; sort newest-first
                // so the wire response is deterministic for consumers that
                // may key off ordering.
                entries.sort_by(|a, b| {
                    b.timestamp
                        .partial_cmp(&a.timestamp)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                TransportQueryResponse::Announces(entries)
            }
            TransportQuery::GetNextHop { dest } => {
                let next_hop = self.path_table.get_live(&dest).and_then(|e| e.next_hop);
                TransportQueryResponse::HashResult(next_hop)
            }
            TransportQuery::GetNextHopIfName { dest } => {
                let name = self
                    .path_table
                    .get_live(&dest)
                    .and_then(|e| self.interfaces.get(&e.interface_id).map(|i| i.name.clone()));
                TransportQueryResponse::StringResult(name)
            }
            TransportQuery::GetPacketRssi { packet_hash } => TransportQueryResponse::FloatResult(
                self.packet_metrics
                    .get(&packet_hash)
                    .and_then(|m| m.rssi)
                    .map(|v| v as f64),
            ),
            TransportQuery::GetPacketSnr { packet_hash } => TransportQueryResponse::FloatResult(
                self.packet_metrics
                    .get(&packet_hash)
                    .and_then(|m| m.snr)
                    .map(|v| v as f64),
            ),
            TransportQuery::GetPacketQ { packet_hash } => TransportQueryResponse::FloatResult(
                self.packet_metrics
                    .get(&packet_hash)
                    .and_then(|m| m.q)
                    .map(|v| v as f64),
            ),
            TransportQuery::DropPath { dest } => {
                // expire() forces immediate cull — plain `remove` would leave
                // observers racing against the next maintenance tick.
                self.path_table.expire(&dest);
                self.state_dirty = true;
                TransportQueryResponse::Ok
            }
            TransportQuery::SuppressPathInterface {
                dest,
                interface_id,
                duration,
            } => TransportQueryResponse::BoolResult(self.suppress_path_interface(
                dest,
                interface_id,
                duration,
            )),
            TransportQuery::SuppressCurrentPathInterface { dest, duration } => {
                let interface_id = self
                    .path_table
                    .get_live(&dest)
                    .map(|entry| entry.interface_id);
                TransportQueryResponse::BoolResult(interface_id.is_some_and(|interface_id| {
                    self.suppress_path_interface(dest, interface_id, duration)
                }))
            }
            TransportQuery::DropAnnounceQueues => {
                for entry in self.interfaces.values_mut() {
                    entry.announce_queue.clear();
                }
                TransportQueryResponse::Ok
            }
            TransportQuery::DropPathTable => {
                let cleared = self.path_table.len();
                self.path_table = crate::path_table::PathTable::new();
                self.pending_path_entries.clear();
                self.discovery_path_requests.clear();
                self.pending_local_path_requests.clear();
                self.pending_discovery_prs.clear();
                self.state_dirty = true;
                self.save_routing_state();
                TransportQueryResponse::IntResult(cleared as i64)
            }
            TransportQuery::DropRecentAnnounces => {
                let cleared = self.recent_announces.len();
                self.recent_announces.clear();
                self.state_dirty = true;
                self.save_routing_state();
                TransportQueryResponse::IntResult(cleared as i64)
            }
            TransportQuery::GetBlackholedIdentities => {
                // Snapshot of identity hashes we have a current announce for —
                // used to decorate each entry with `verified`.
                let verified_ids: std::collections::HashSet<[u8; 16]> = self
                    .recent_announces
                    .values()
                    .filter_map(|e| e.public_key.map(|pk| rns_crypto::sha::truncated_hash(&pk)))
                    .collect();
                let entries: Vec<BlackholeRpcEntry> = self
                    .blackhole_table
                    .iter_entries()
                    .map(|(hash, entry)| {
                        let id_bytes = hash.into_bytes();
                        BlackholeRpcEntry {
                            identity_hash: id_bytes,
                            source: entry
                                .source
                                .map(|source| source.into_bytes())
                                .or(self.transport_identity_hash),
                            created: entry.created,
                            ttl: entry.ttl,
                            reason: entry.reason,
                            reason_label: entry.reason_label.clone(),
                            verified: verified_ids.contains(&id_bytes),
                        }
                    })
                    .collect();
                TransportQueryResponse::BlackholeList(entries)
            }
            TransportQuery::BlackholeIdentity {
                hash,
                ttl,
                reason,
                reason_label,
            } => {
                self.blackhole_table
                    .add_with_reason_label(hash, ttl, reason, reason_label);
                // Mirror Python `Transport.remove_blackholed_paths`: walk the
                // path table and drop any entry whose destination is owned by
                // the freshly blackholed identity. Without this, existing
                // paths stay valid until the standard expiry window so the
                // blackholed peer's data packets keep arriving for ~15 min.
                let dropped: Vec<[u8; 16]> = self
                    .path_table
                    .iter()
                    .filter_map(|(dest, _)| {
                        let dest_bytes = dest.into_bytes();
                        let entry = self.recent_announces.get(&dest_bytes)?;
                        let public_key = entry.public_key?;
                        let owner = rns_crypto::sha::truncated_hash(&public_key);
                        if owner == hash {
                            Some(dest_bytes)
                        } else {
                            None
                        }
                    })
                    .collect();
                for dest in dropped {
                    self.path_table.remove(&dest);
                }
                self.state_dirty = true;
                TransportQueryResponse::Ok
            }
            TransportQuery::UnblackholeIdentity { hash } => {
                let removed = self.blackhole_table.remove(&hash);
                if removed {
                    self.state_dirty = true;
                }
                TransportQueryResponse::BoolResult(removed)
            }
            TransportQuery::IsBlackholed { hash } => {
                TransportQueryResponse::BoolResult(self.blackhole_table.is_blackholed(&hash))
            }
            TransportQuery::ClearSystemBlackholes => {
                let cleared = self.blackhole_table.clear_system_entries();
                if cleared > 0 {
                    self.state_dirty = true;
                }
                TransportQueryResponse::IntResult(cleared as i64)
            }
            TransportQuery::BuildBlackholeManifest { publisher } => {
                // Quarantine unverifiable entries from publication. Pre-fix
                // garbage (LXMF-dest-as-identity bytes) and identities whose
                // announce has been pruned both fail this check; we refuse to
                // republish either.
                let verified_ids: std::collections::HashSet<[u8; 16]> = self
                    .recent_announces
                    .values()
                    .filter_map(|e| e.public_key.map(|pk| rns_crypto::sha::truncated_hash(&pk)))
                    .collect();
                match crate::discovery::build_local_manifest(
                    &self.blackhole_table,
                    publisher.into(),
                    Some(&verified_ids),
                ) {
                    Ok(payload) => TransportQueryResponse::Data(payload),
                    Err(e) => TransportQueryResponse::Error(e.to_string()),
                }
            }
            TransportQuery::ApplyBlackholeManifest { payload } => {
                match crate::discovery::decode_manifest(&payload) {
                    Ok(manifest) => {
                        let applied = crate::discovery::apply_manifest(
                            &mut self.blackhole_table,
                            &manifest,
                            now_f64(),
                        );
                        if applied > 0 {
                            self.state_dirty = true;
                        }
                        TransportQueryResponse::IntResult(applied as i64)
                    }
                    Err(e) => TransportQueryResponse::Error(e.to_string()),
                }
            }
            TransportQuery::RemoteStatus { include_link_count } => {
                // Wire shape: `(interface_stats,)` or `(interface_stats, link_count)` —
                // a tuple so the msgpack decoder on the other side sees a fixed arity.
                let stats: Vec<Vec<(String, String)>> = self
                    .interfaces
                    .values()
                    .map(|entry| {
                        let online = entry
                            .online
                            .as_ref()
                            .map(|o| o.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(true);
                        let rx = entry
                            .rxb
                            .as_ref()
                            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(0);
                        let tx = entry
                            .txb
                            .as_ref()
                            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(0);
                        vec![
                            ("name".to_string(), entry.name.clone()),
                            ("online".to_string(), online.to_string()),
                            ("rxb".to_string(), rx.to_string()),
                            ("txb".to_string(), tx.to_string()),
                            ("bitrate".to_string(), entry.bitrate.to_string()),
                        ]
                    })
                    .collect();
                let response = if include_link_count {
                    let link_count = self.link_table.len();
                    rmp_serde::to_vec(&(stats, link_count)).unwrap_or_default()
                } else {
                    rmp_serde::to_vec(&(stats,)).unwrap_or_default()
                };
                TransportQueryResponse::Data(response)
            }
            TransportQuery::RemotePath {
                command: _,
                destination,
                max_hops,
            } => {
                let entries: Vec<_> = self
                    .path_table
                    .iter()
                    .filter(|(hash, _)| {
                        if let Some(dest) = destination {
                            *hash.as_bytes() == dest
                        } else {
                            true
                        }
                    })
                    .filter(|(_, entry)| {
                        if let Some(max) = max_hops {
                            entry.hops <= max
                        } else {
                            true
                        }
                    })
                    .map(|(hash, entry)| {
                        let iface = self
                            .interfaces
                            .get(&entry.interface_id)
                            .map(|e| e.name.clone())
                            .unwrap_or_default();
                        (
                            hex::encode(hash.as_bytes()),
                            entry.hops,
                            entry.timestamp,
                            iface,
                        )
                    })
                    .collect();
                let response = rmp_serde::to_vec(&entries).unwrap_or_default();
                TransportQueryResponse::Data(response)
            }
            TransportQuery::HaltInterface { id } => {
                if let Some(entry) = self.interfaces.get_mut(&id) {
                    if let Some(ref online) = entry.online {
                        online.store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                    debug!(id, "interface halted via RPC");
                    TransportQueryResponse::Ok
                } else {
                    TransportQueryResponse::Error(format!("interface {} not found", id))
                }
            }
            TransportQuery::ResumeInterface { id } => {
                if let Some(entry) = self.interfaces.get_mut(&id) {
                    if let Some(ref online) = entry.online {
                        online.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    debug!(id, "interface resumed via RPC");
                    TransportQueryResponse::Ok
                } else {
                    TransportQueryResponse::Error(format!("interface {} not found", id))
                }
            }
            TransportQuery::DropAllVia { next_hop } => {
                let dropped = self.path_table.drop_all_via_next_hop(&next_hop);
                debug!(next_hop = %hex::encode(next_hop), dropped, "dropped paths via next hop");
                TransportQueryResponse::IntResult(dropped as i64)
            }
            TransportQuery::GetNextHopBitrate { dest } => {
                let bitrate = self
                    .path_table
                    .get_live(&dest)
                    .and_then(|e| self.interfaces.get(&e.interface_id))
                    .map(|iface| iface.bitrate as f64);
                TransportQueryResponse::FloatResult(bitrate)
            }
            TransportQuery::GetNextHopInterfaceId { dest } => {
                let id = self
                    .path_table
                    .get_live(&dest)
                    .map(|e| e.interface_id as i64);
                TransportQueryResponse::IntResult(id.unwrap_or(-1))
            }
            TransportQuery::FirstHopTimeout { dest } => {
                let timeout = self
                    .path_table
                    .get_live(&dest)
                    .and_then(|e| self.interfaces.get(&e.interface_id))
                    .map(|iface| {
                        let per_byte_latency = 8.0 / iface.bitrate as f64;
                        rns_wire::constants::MTU as f64 * per_byte_latency
                            + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT
                    })
                    .unwrap_or(rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT);
                TransportQueryResponse::FloatResult(Some(timeout))
            }
            TransportQuery::ExtraLinkProofTimeout { interface_id } => {
                let timeout = self
                    .interfaces
                    .get(&interface_id)
                    .map(|iface| {
                        let per_byte_latency = 8.0 / iface.bitrate as f64;
                        rns_wire::constants::MTU as f64 * per_byte_latency
                    })
                    .unwrap_or(0.0);
                TransportQueryResponse::FloatResult(Some(timeout))
            }
            TransportQuery::SetPathState { dest, state } => {
                if self.path_table.has_path(&dest) {
                    self.path_table.set_state(dest, state);
                    TransportQueryResponse::BoolResult(true)
                } else {
                    TransportQueryResponse::BoolResult(false)
                }
            }
            TransportQuery::GetPathState { dest } => {
                let state = self.path_table.get_state(&dest);
                TransportQueryResponse::PathStateResult(state)
            }
            TransportQuery::PathIsUnresponsive { dest } => {
                let is_unresponsive =
                    self.path_table.get_state(&dest) == crate::constants::PathState::Unresponsive;
                TransportQueryResponse::BoolResult(is_unresponsive)
            }
            TransportQuery::RetainDestination { dest } => {
                TransportQueryResponse::BoolResult(self.retain_destination(&dest))
            }
            TransportQuery::RetainIdentity { identity_hash } => {
                TransportQueryResponse::BoolResult(self.retain_identity(&identity_hash))
            }
            TransportQuery::UseDestination { dest } => {
                TransportQueryResponse::BoolResult(self.use_destination(&dest))
            }
            TransportQuery::UnretainDestination { dest } => {
                TransportQueryResponse::BoolResult(self.unretain_destination(&dest))
            }
            TransportQuery::CleanKnownDestinations => {
                self.cleanup_known_destinations(crate::actor::now_f64());
                TransportQueryResponse::IntResult(self.recent_announces.len() as i64)
            }
            TransportQuery::ResolveIdentityHash { input } => {
                // First treat input as a destination hash.
                if let Some(entry) = self.recent_announces.get(&input)
                    && let Some(public_key) = entry.public_key
                {
                    let id_hash = rns_crypto::sha::truncated_hash(&public_key);
                    return TransportQueryResponse::HashResult(Some(id_hash));
                }
                // Fall back to treating input as an identity hash already.
                for entry in self.recent_announces.values() {
                    let Some(public_key) = entry.public_key else {
                        continue;
                    };
                    let id_hash = rns_crypto::sha::truncated_hash(&public_key);
                    if id_hash == input {
                        return TransportQueryResponse::HashResult(Some(input));
                    }
                }
                TransportQueryResponse::HashResult(None)
            }
            TransportQuery::RecallDestinationPublicKey { dest } => {
                let public_key = self
                    .recent_announces
                    .get(&dest)
                    .and_then(|entry| entry.public_key);
                TransportQueryResponse::PublicKeyResult(public_key)
            }
            TransportQuery::FilterBlackholedDests { dests } => {
                let mut hits = Vec::new();
                for dest in &dests {
                    let Some(entry) = self.recent_announces.get(dest) else {
                        continue;
                    };
                    let Some(public_key) = entry.public_key else {
                        continue;
                    };
                    let id_hash = rns_crypto::sha::truncated_hash(&public_key);
                    if self.blackhole_table.is_blackholed(&id_hash) {
                        hits.push(*dest);
                    }
                }
                TransportQueryResponse::BlackholedDests(hits)
            }
            TransportQuery::PurgeUnverifiedBlackholes => {
                let verified_ids: std::collections::HashSet<[u8; 16]> = self
                    .recent_announces
                    .values()
                    .filter_map(|e| e.public_key.map(|pk| rns_crypto::sha::truncated_hash(&pk)))
                    .collect();
                let unverified: Vec<[u8; 16]> = self
                    .blackhole_table
                    .iter_entries()
                    .filter_map(|(id, entry)| {
                        if entry.reason != crate::blackhole::BlackholeReason::Manual {
                            return None;
                        }
                        let bytes = id.into_bytes();
                        if verified_ids.contains(&bytes) {
                            None
                        } else {
                            Some(bytes)
                        }
                    })
                    .collect();
                let purged = unverified.len();
                for id in unverified {
                    self.blackhole_table.remove(&id);
                }
                if purged > 0 {
                    self.state_dirty = true;
                }
                TransportQueryResponse::IntResult(purged as i64)
            }
        }
    }
}

fn activation_epoch(now: f64, active: bool, activated: std::time::Instant) -> f64 {
    if active {
        now - activated.elapsed().as_secs_f64()
    } else {
        0.0
    }
}
