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
                        let hash = hash.into_bytes();
                        let known = self.recent_announces.get(&hash);
                        PathTableRpcEntry {
                            hash,
                            timestamp: entry.timestamp,
                            via: Some(entry.next_hop.unwrap_or(hash)),
                            hops: entry.hops,
                            expires: entry.expires,
                            value: known.map(|k| k.stamp_value),
                            used: entry.used,
                            lr_cost: known.and_then(|k| k.lr_cost),
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
                // Reticulum.py: stats follow Transport.interfaces, bitrate order.
                let mut stats: Vec<InterfaceStatRpcEntry> = self
                    .prioritized_interface_ids()
                    .into_iter()
                    .filter_map(|iface_id| {
                        let entry = self.interfaces.get_mut(&iface_id)?;
                        let online = entry
                            .online
                            .as_ref()
                            .map(|o| o.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(true);
                        let rx_bytes = entry.received.accepted;
                        let tx_bytes = entry
                            .txb
                            .as_ref()
                            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(0);
                        let inspection = entry
                            .inspection
                            .as_ref()
                            .map(|source| {
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    source.snapshot()
                                }))
                                .unwrap_or_else(|_| {
                                    tracing::warn!(
                                        interface_id = iface_id,
                                        "interface inspection callback panicked",
                                    );
                                    InterfaceInspectionSnapshot::default()
                                })
                            })
                            .unwrap_or_default();
                        let (arxb, atxb, prxb, ptxb) =
                            entry.ingress.announce_and_path_request_bytes();
                        let signal = self
                            .traffic_count
                            .signal
                            .get(&iface_id)
                            .copied()
                            .unwrap_or_default();
                        let speeds = self.traffic_count.speeds.get(&iface_id).copied();
                        // Python publishes IFAC only for an interface that has it.
                        let ifac_signature = entry.ifac_signature();
                        let has_ifac = entry.ifac_key.is_some();
                        Some(InterfaceStatRpcEntry {
                            id: iface_id,
                            name: entry.name.clone(),
                            rx_bytes,
                            tx_bytes,
                            filtered_rx_bytes: entry.received.filtered,
                            filtered_tx_bytes: 0,
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
                            outgoing_pr_frequency: entry.ingress.outgoing_pr_frequency(false),
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
                            clients: inspection.active_clients,
                            blocked_ips: inspection.blocked_ips,
                            announce_rate_target: entry.announce_rate_target,
                            announce_rate_grace: entry.announce_rate_grace,
                            announce_rate_penalty: entry.announce_rate_penalty,
                            announce_cap: entry.announce_cap,
                            ifac_size: has_ifac.then_some(entry.ifac_size),
                            ifac_signature: ifac_signature.map(Vec::from),
                            ifac_netname: entry.ifac_netname.clone().filter(|_| has_ifac),
                            tx_drops: entry.tx_drops.load(std::sync::atomic::Ordering::Relaxed),
                            tx_dropped_bytes: entry.tx_dropped_bytes,
                            announces_received: entry.ingress.announces_received(),
                            announces_sent: entry.ingress.announces_sent(),
                            path_requests_received: entry.ingress.path_requests_received(),
                            path_requests_sent: entry.ingress.path_requests_sent(),
                            announces_filtered: entry.ingress.announces_filtered(),
                            protocol_violations: entry.protocol_violations,
                            ifac_violations: entry.ifac_violations,
                            packet_filter_hits: entry.packet_filter_hits,
                            gravity: entry.gravity,
                            announces_to_internal: entry.announces_to_internal,
                            parent_id: entry.parent_id,
                            parent_interface_name: None,
                            autoconnect_source: entry.autoconnect_source.clone(),
                            identity: entry
                                .inspection
                                .as_ref()
                                .and_then(|source| source.identity().cloned()),
                            speeds: speeds.map(|s| [s[0], s[1], s[2], s[3], s[4], s[5]]),
                            filtered_speeds: speeds.map(|s| [s[6], s[7]]),
                            announce_rx_bytes: arxb,
                            announce_tx_bytes: atxb,
                            path_request_rx_bytes: prxb,
                            path_request_tx_bytes: ptxb,
                            burst_count: None,
                            pr_burst_count: None,
                            rssi: signal.rssi.map(f64::from),
                            snr: signal.snr.map(f64::from),
                            signal_quality: signal.q.map(f64::from),
                            peers: inspection.peers,
                            i2p_connectable: inspection.i2p_connectable,
                            i2p_b32: inspection.i2p_b32,
                            i2p_tunnel_state: inspection.i2p_tunnel_state,
                            tx_stalled: inspection.tx_stalled,
                            tx_buffered: inspection.tx_buffered,
                            radio: inspection.radio,
                            last_connect_error: inspection.last_connect_error.map(str::to_string),
                            connect_failures: inspection.connect_failures,
                        })
                    })
                    .collect();
                aggregate_backbone_bursts(&mut stats);
                name_parents(&mut stats);
                TransportQueryResponse::InterfaceStats(stats)
            }
            TransportQuery::GetTrafficTotals => {
                TransportQueryResponse::TrafficTotals(self.traffic_totals())
            }
            TransportQuery::GetLinkDistribution => {
                TransportQueryResponse::LinkDistribution(self.link_distribution())
            }
            TransportQuery::GetRateTable => {
                let entries: Vec<RateTableRpcEntry> = self
                    .rate_table
                    .iter()
                    .map(|(hash, entry)| RateTableRpcEntry {
                        hash: hash.into_bytes(),
                        rate: entry.rate(),
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
            // Counts validated links. Python 1.6.0 means to, but indexes the
            // link id instead of the entry (Transport.py).
            TransportQuery::GetActiveLinkCount => TransportQueryResponse::IntResult(
                self.link_table
                    .iter()
                    .filter(|(_, entry)| entry.validated)
                    .count() as i64,
            ),
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
                            facts_known: a.facts_known,
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
            TransportQuery::RecallDestination { dest } => {
                let now = crate::actor::now_f64();
                let ratchet = self.recall_ratchet(&dest, now);
                let recalled = self.recent_announces.get(&dest).and_then(|entry| {
                    Some(RecalledDestinationRpcEntry {
                        dest_hash: entry.dest_hash,
                        public_key: entry.public_key?,
                        app_data: entry.app_data.clone(),
                        ratchet,
                        hops: entry.hops,
                        timestamp: entry.timestamp,
                        hops_known: entry.facts_known,
                    })
                });
                // Identity.py: fall back to a registered local destination.
                let recalled = recalled.or_else(|| {
                    self.local_destination_keys.get(&dest).map(|public_key| {
                        RecalledDestinationRpcEntry {
                            dest_hash: dest,
                            public_key: *public_key,
                            app_data: None,
                            ratchet: None,
                            hops: 0,
                            timestamp: now_f64(),
                            hops_known: true,
                        }
                    })
                });
                TransportQueryResponse::RecalledDestination(recalled)
            }
            TransportQuery::RecallStampValue { dest } => TransportQueryResponse::FloatResult(
                self.recent_announces
                    .get(&dest)
                    .map(|entry| entry.stamp_value),
            ),
            TransportQuery::RecallLinkCost { dest } => TransportQueryResponse::FloatResult(
                self.recent_announces
                    .get(&dest)
                    .and_then(|entry| entry.lr_cost),
            ),
            TransportQuery::HasPath { dest } => {
                TransportQueryResponse::BoolResult(self.path_table.has_path(&dest))
            }
            TransportQuery::HopsTo { dest } => TransportQueryResponse::IntResult(i64::from(
                self.path_table
                    .hops_to(&dest)
                    .unwrap_or(crate::constants::PATHFINDER_M),
            )),
            TransportQuery::GetNextHop { dest } => {
                // Python 1.3.8 Transport.py: local destinations
                // resolve to Transport.identity.hash.
                let next_hop = self
                    .path_table
                    .get_live(&dest)
                    .map(|e| e.next_hop.unwrap_or(dest))
                    .or_else(|| {
                        self.local_destinations
                            .contains(&dest)
                            .then_some(self.transport_identity_hash)
                            .flatten()
                    });
                TransportQueryResponse::HashResult(next_hop)
            }
            TransportQuery::GetNextHopIfName { dest } => {
                // Python 1.3.8 Transport.py: local destinations
                // resolve to the shared-instance interface (None off shared hosts).
                let name = self
                    .path_table
                    .get_live(&dest)
                    .map(|e| e.interface_id)
                    .or_else(|| self.local_destination_interface_id(&dest))
                    .and_then(|id| self.interfaces.get(&id))
                    .map(|i| {
                        // Python answers `str(interface)` (Reticulum.py), as stats name it.
                        i.inspection
                            .as_ref()
                            .and_then(|source| source.identity())
                            .map_or_else(|| i.name.clone(), |identity| identity.name.clone())
                    });
                TransportQueryResponse::StringResult(name)
            }
            TransportQuery::GetPacketRssi { packet_hash } => TransportQueryResponse::FloatResult(
                first_packet_metric(&self.packet_rssi_cache, &packet_hash),
            ),
            TransportQuery::GetPacketSnr { packet_hash } => TransportQueryResponse::FloatResult(
                first_packet_metric(&self.packet_snr_cache, &packet_hash),
            ),
            TransportQuery::GetPacketQ { packet_hash } => TransportQueryResponse::FloatResult(
                first_packet_metric(&self.packet_q_cache, &packet_hash),
            ),
            TransportQuery::DropPath { dest } => {
                // expire() forces immediate cull — plain `remove` would leave
                // observers racing against the next maintenance tick.
                let existed = self.path_table.expire(&dest);
                if existed {
                    self.state_dirty = true;
                }
                TransportQueryResponse::BoolResult(existed)
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
                self.pending_path_request_admissions.clear();
                self.state_dirty = true;
                self.save_routing_state();
                TransportQueryResponse::IntResult(cleared as i64)
            }
            TransportQuery::DropRecentAnnounces => {
                let cleared = self.recent_announces.len();
                for (dest, _) in self.recent_announces.drain() {
                    self.kd.pending.mark_deleted(dest);
                }
                self.state_dirty = true;
                self.flush_known_destinations();
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
                // Transport.py: an existing entry is left untouched.
                if self.blackhole_table.contains(&hash) {
                    return TransportQueryResponse::OptBoolResult(None);
                }
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
                self.persist_local_blackhole();
                for dest in dropped {
                    self.path_table.remove(&dest);
                }
                self.state_dirty = true;
                self.publish_blackhole_snapshot();
                TransportQueryResponse::OptBoolResult(Some(true))
            }
            TransportQuery::UnblackholeIdentity { hash } => {
                let removed = self.blackhole_table.remove(&hash);
                if removed {
                    self.persist_local_blackhole();
                    self.state_dirty = true;
                    self.publish_blackhole_snapshot();
                }
                TransportQueryResponse::OptBoolResult(removed.then_some(true))
            }
            TransportQuery::IsBlackholed { hash } => {
                TransportQueryResponse::BoolResult(self.blackhole_table.is_blackholed(&hash))
            }
            TransportQuery::ClearSystemBlackholes => {
                let cleared = self.blackhole_table.clear_system_entries();
                if cleared > 0 {
                    self.persist_local_blackhole();
                    self.state_dirty = true;
                    self.publish_blackhole_snapshot();
                }
                TransportQueryResponse::IntResult(cleared as i64)
            }
            TransportQuery::BuildBlackholeManifest { publisher } => {
                match crate::discovery::build_manifest(&self.blackhole_table, publisher.into()) {
                    Ok(payload) => TransportQueryResponse::Data(payload),
                    Err(e) => TransportQueryResponse::Error(e.to_string()),
                }
            }
            TransportQuery::ApplyBlackholeManifest { publisher, payload } => {
                match crate::discovery::decode_published_manifest(&payload, publisher.into()) {
                    Ok(manifest) => {
                        let added = crate::discovery::apply_manifest(
                            &mut self.blackhole_table,
                            &manifest,
                            now_f64(),
                        );
                        if added > 0 {
                            self.persist_blackhole_source(publisher, &payload);
                            self.publish_blackhole_snapshot();
                        }
                        TransportQueryResponse::IntResult(added as i64)
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
                        let rx = entry.received.accepted;
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
                    .map(|e| e.interface_id)
                    .or_else(|| self.local_destination_interface_id(&dest))
                    .and_then(|id| self.interfaces.get(&id))
                    .map(|iface| iface.bitrate as f64);
                TransportQueryResponse::FloatResult(bitrate)
            }
            TransportQuery::GetNextHopHardwareMtu { dest } => {
                let mtu = self
                    .path_table
                    .get_live(&dest)
                    .map(|e| e.interface_id)
                    .or_else(|| self.local_destination_interface_id(&dest))
                    .and_then(|id| self.interfaces.get(&id))
                    .filter(|iface| iface.packet_capacity.link_mtu_upgrade)
                    .map(|iface| i64::from(iface.mtu));
                TransportQueryResponse::IntResult(mtu.unwrap_or(-1))
            }
            TransportQuery::GetNextHopInterfaceId { dest } => {
                let id = self
                    .path_table
                    .get_live(&dest)
                    .map(|e| e.interface_id)
                    .or_else(|| self.local_destination_interface_id(&dest))
                    .map(|id| id as i64);
                TransportQueryResponse::IntResult(id.unwrap_or(-1))
            }
            TransportQuery::FirstHopTimeout { dest } => {
                TransportQueryResponse::FloatResult(Some(self.first_hop_timeout(&dest)))
            }
            TransportQuery::ExtraLinkProofTimeout { interface_id } => {
                let timeout = self
                    .interfaces
                    .get(&interface_id)
                    .filter(|iface| iface.bitrate != 0)
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
                    self.publish_blackhole_snapshot();
                }
                TransportQueryResponse::IntResult(purged as i64)
            }
            TransportQuery::SetRequiredOnly { enabled } => {
                self.destination_filter.set_required_only(enabled);
                debug!(enabled, "required-only announce filtering");
                TransportQueryResponse::BoolResult(true)
            }
            TransportQuery::WantsDestinationType {
                full_name,
                requester,
            } => {
                let wanted = self.destination_filter.wants(&full_name, requester.clone());
                if wanted {
                    debug!(
                        "Registered <{full_name}> destinations requirement for {}",
                        hex::encode(&requester)
                    );
                }
                TransportQueryResponse::BoolResult(wanted)
            }
            TransportQuery::UnwantsDestinationType {
                full_name,
                requester,
            } => TransportQueryResponse::BoolResult(
                self.destination_filter.unwants(&full_name, &requester),
            ),
            TransportQuery::UnwantsAllDestinationTypes { requester } => {
                debug!(
                    "Deregistered all destination requirements for {}",
                    hex::encode(&requester)
                );
                TransportQueryResponse::BoolResult(self.destination_filter.unwants_all(&requester))
            }
        }
    }

    /// Next-hop interface for a local destination: the shared-instance server
    /// interface, mirroring Python 1.3.8 Transport.next_hop_interface's
    /// destinations_map fallback (Transport.py).
    fn local_destination_interface_id(
        &self,
        dest: &[u8; 16],
    ) -> Option<crate::messages::InterfaceId> {
        if !self.local_destinations.contains(dest) {
            return None;
        }
        self.interfaces
            .iter()
            .find(|(_, e)| e.role == crate::messages::InterfaceRole::SharedServer)
            .map(|(&id, _)| id)
    }
}

/// An announce or path request an interface received or sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InterfaceEvent {
    ReceivedAnnounce,
    SentAnnounce,
    ReceivedPathRequest,
    SentPathRequest,
}

/// Byte counters the traffic count samples: Python's `rxb`, `txb`, `arxb`,
/// `atxb`, `prxb`, `ptxb`, `frxb` and `ftxb`.
const SAMPLED: usize = 8;

#[derive(Debug, Clone, Copy)]
struct TrafficSample {
    at: std::time::Instant,
    bytes: [u64; SAMPLED],
}

/// Python `Transport.count_traffic_loop` state and the packet counters it
/// reports (Transport.py).
#[derive(Debug)]
pub(super) struct TrafficCount {
    started: std::time::Instant,
    totals: TrafficTotalsRpcEntry,
    samples: HashMap<InterfaceId, TrafficSample>,
    speeds: HashMap<InterfaceId, [f64; SAMPLED]>,
    /// Python `r_stat_rssi`, `r_stat_snr` and `r_stat_q` per interface.
    signal: HashMap<InterfaceId, PacketMetrics>,
    last_pps: Option<(std::time::Instant, u64, u64)>,
    /// `link_rxb` and `link_txb` at `last_pps`.
    last_link_bytes: (u64, u64),
    last_count: f64,
}

impl Default for TrafficCount {
    fn default() -> Self {
        Self {
            started: std::time::Instant::now(),
            totals: TrafficTotalsRpcEntry::default(),
            samples: HashMap::new(),
            speeds: HashMap::new(),
            signal: HashMap::new(),
            last_pps: None,
            last_link_bytes: (0, 0),
            last_count: 0.0,
        }
    }
}

use crate::messages::TrafficTotalsRpcEntry;

impl TransportActor {
    /// Python `Interface.received_announce` and siblings: count on the
    /// interface, then the bytes and a frequency sample on its parent
    /// (Interface.py, TCPInterface.py).
    pub(super) fn record_interface_event(
        &mut self,
        id: InterfaceId,
        event: InterfaceEvent,
        size: usize,
    ) {
        let Some(entry) = self.interfaces.get_mut(&id) else {
            return;
        };
        match event {
            InterfaceEvent::ReceivedAnnounce => entry.ingress.received_announce_bytes(size),
            InterfaceEvent::SentAnnounce => entry.ingress.sent_announce_bytes(size),
            InterfaceEvent::ReceivedPathRequest => entry.ingress.received_path_request_bytes(size),
            InterfaceEvent::SentPathRequest => entry.ingress.sent_path_request_bytes(size),
        }
        let Some(parent) = entry
            .parent_id
            .and_then(|parent| self.interfaces.get_mut(&parent))
        else {
            return;
        };
        match event {
            InterfaceEvent::ReceivedAnnounce => parent.ingress.spawned_received_announce(size),
            InterfaceEvent::SentAnnounce => parent.ingress.spawned_sent_announce(size),
            InterfaceEvent::ReceivedPathRequest => {
                parent.ingress.spawned_received_path_request(size)
            }
            InterfaceEvent::SentPathRequest => parent.ingress.spawned_sent_path_request(size),
        }
    }

    /// Python `Interface.filtered_announce`: the interface, its parent and the
    /// transport total (Interface.py).
    pub(super) fn filtered_announce(&mut self, id: InterfaceId) {
        let Some(entry) = self.interfaces.get_mut(&id) else {
            return;
        };
        entry.ingress.filtered_announce();
        let parent_id = entry.parent_id;
        self.traffic_count.totals.announce_filtered_packets += 1;
        if let Some(parent) = parent_id.and_then(|parent| self.interfaces.get_mut(&parent)) {
            parent.ingress.filtered_announce();
        }
    }

    /// Python 1.6.1 `Transport.rx_packets += 1` once a packet passes
    /// preprocessing (Transport.py:2266).
    pub(super) fn count_rx_packet(&mut self) {
        self.traffic_count.totals.rx_packets += 1;
    }

    /// Python 1.6.1 `link_rxb` and `link_txb` (Transport.py, Link.py, Packet.py).
    pub(super) fn count_link_bytes(&mut self, rx: usize, tx: usize) {
        let totals = &mut self.traffic_count.totals;
        totals.lrxb = totals.lrxb.saturating_add(rx as u64);
        totals.ltxb = totals.ltxb.saturating_add(tx as u64);
    }

    /// Python `Transport.link_distribution()`: every link table entry is a
    /// relayed Link (Transport.py:3786-3814).
    fn link_distribution(&self) -> Vec<crate::messages::LinkDistributionRpcEntry> {
        let mut by_destination: HashMap<[u8; 16], crate::messages::LinkDistributionRpcEntry> =
            HashMap::new();
        for (_, link) in self.link_table.iter() {
            let entry = by_destination
                .entry(link.destination_hash)
                .or_insert_with(|| crate::messages::LinkDistributionRpcEntry {
                    destination_hash: link.destination_hash,
                    ..Default::default()
                });
            entry.traffic = entry.traffic.saturating_add(link.traffic);
            if link.validated {
                entry.active += 1;
            } else {
                entry.pending += 1;
            }
            if let Some(interface) = self.interfaces.get(&link.receiving_interface) {
                let hash = rns_crypto::sha::sha256(interface.upstream_name().as_bytes());
                if !entry.from_interfaces.contains(&hash) {
                    entry.from_interfaces.push(hash);
                }
            }
        }
        let mut entries: Vec<_> = by_destination.into_values().collect();
        for entry in &mut entries {
            entry.from_interfaces.sort_unstable();
        }
        entries.sort_unstable_by_key(|entry| entry.destination_hash);
        entries
    }

    /// Python `Transport.tx_packets += 1` per `Transport.transmit` (Transport.py).
    pub(super) fn count_tx_packet(&mut self) {
        self.traffic_count.totals.tx_packets += 1;
    }

    /// Python `Transport.announce_rxc`, `announce_txc`, `pr_rxc` and `pr_txc`.
    pub(super) fn count_transport_event(&mut self, event: InterfaceEvent) {
        let totals = &mut self.traffic_count.totals;
        match event {
            InterfaceEvent::ReceivedAnnounce => totals.announce_rx_packets += 1,
            InterfaceEvent::SentAnnounce => totals.announce_tx_packets += 1,
            InterfaceEvent::ReceivedPathRequest => totals.pr_rx_packets += 1,
            InterfaceEvent::SentPathRequest => totals.pr_tx_packets += 1,
        }
    }

    pub(super) fn record_interface_signal(&mut self, id: InterfaceId, metrics: PacketMetrics) {
        if metrics.rssi.is_some() || metrics.snr.is_some() || metrics.q.is_some() {
            let signal = self.traffic_count.signal.entry(id).or_default();
            signal.rssi = metrics.rssi.or(signal.rssi);
            signal.snr = metrics.snr.or(signal.snr);
            signal.q = metrics.q.or(signal.q);
        }
    }

    /// One pass of Python's once-a-second traffic count over top-level
    /// interfaces other than the shared-instance server.
    pub(super) fn count_traffic(&mut self, now: f64) {
        if now - self.traffic_count.last_count < 1.0 {
            return;
        }
        self.traffic_count.last_count = now;
        let at = std::time::Instant::now();
        let load = |counter: &Option<Arc<AtomicU64>>| {
            counter
                .as_ref()
                .map_or(0, |c| c.load(std::sync::atomic::Ordering::Relaxed))
        };
        let count = &mut self.traffic_count;
        count
            .samples
            .retain(|id, _| self.interfaces.contains_key(id));
        count
            .speeds
            .retain(|id, _| self.interfaces.contains_key(id));
        count
            .signal
            .retain(|id, _| self.interfaces.contains_key(id));
        let mut deltas = [0u64; SAMPLED];
        let mut speeds = [0f64; SAMPLED];
        let mut freqs = [0f64; 4];
        let mut measured = false;
        for (&id, entry) in &mut self.interfaces {
            if entry.parent_id.is_some() || entry.role == InterfaceRole::SharedServer {
                continue;
            }
            let (arxb, atxb, prxb, ptxb) = entry.ingress.announce_and_path_request_bytes();
            let bytes = [
                entry.received.accepted,
                load(&entry.txb),
                arxb,
                atxb,
                prxb,
                ptxb,
                entry.received.filtered,
                0,
            ];
            let Some(previous) = count.samples.insert(id, TrafficSample { at, bytes }) else {
                continue;
            };
            let elapsed = at.duration_since(previous.at).as_secs_f64();
            if elapsed <= 0.0 {
                continue;
            }
            let mut interface_speeds = [0f64; SAMPLED];
            for i in 0..SAMPLED {
                let delta = bytes[i].saturating_sub(previous.bytes[i]);
                deltas[i] += delta;
                interface_speeds[i] = (delta as f64 * 8.0) / elapsed;
                speeds[i] += interface_speeds[i];
            }
            count.speeds.insert(id, interface_speeds);
            freqs[0] += entry.ingress.incoming_announce_frequency();
            freqs[1] += entry.ingress.outgoing_announce_frequency();
            freqs[2] += entry.ingress.incoming_pr_frequency();
            freqs[3] += entry.ingress.outgoing_pr_frequency(false);
            measured = true;
        }
        let totals = &mut count.totals;
        let (since, rxp, txp) = count.last_pps.unwrap_or((count.started, 0, 0));
        let elapsed = at.duration_since(since).as_secs_f64();
        if elapsed > 0.0 {
            totals.rxpps =
                ((totals.rx_packets.saturating_sub(rxp)) as f64 / elapsed).round() as u64;
            totals.txpps =
                ((totals.tx_packets.saturating_sub(txp)) as f64 / elapsed).round() as u64;
            let (lrxb, ltxb) = count.last_link_bytes;
            totals.lrxs = totals.lrxb.saturating_sub(lrxb) as f64 * 8.0 / elapsed;
            totals.ltxs = totals.ltxb.saturating_sub(ltxb) as f64 * 8.0 / elapsed;
        }
        count.last_pps = Some((at, totals.rx_packets, totals.tx_packets));
        count.last_link_bytes = (totals.lrxb, totals.ltxb);
        totals.measured = measured;
        totals.rxb += deltas[0];
        totals.txb += deltas[1];
        totals.arxb += deltas[2];
        totals.atxb += deltas[3];
        totals.prxb += deltas[4];
        totals.ptxb += deltas[5];
        totals.frxb += deltas[6];
        totals.ftxb += deltas[7];
        [
            totals.rxs,
            totals.txs,
            totals.arxs,
            totals.atxs,
            totals.prxs,
            totals.ptxs,
            totals.frxs,
            totals.ftxs,
        ] = speeds;
        [totals.arxf, totals.atxf, totals.prxf, totals.ptxf] = freqs;
    }

    fn traffic_totals(&self) -> TrafficTotalsRpcEntry {
        let link_count = self.link_table.len() as u64;
        let path_count = self.path_table.len() as u64;
        TrafficTotalsRpcEntry {
            link_count,
            active_link_count: self
                .link_table
                .iter()
                .filter(|(_, entry)| entry.validated)
                .count() as u64,
            path_count,
            unused_path_count: self
                .path_table
                .iter()
                .filter(|(_, entry)| entry.used == 0.0)
                .count() as u64,
            ..self.traffic_count.totals
        }
    }
}

/// Python's `parent_interface_name`: `str()` of the listener that accepted
/// an interface (Reticulum.py).
fn name_parents(stats: &mut [crate::messages::InterfaceStatRpcEntry]) {
    let names: HashMap<InterfaceId, String> = stats
        .iter()
        .map(|entry| {
            let name = entry
                .identity
                .as_ref()
                .map_or_else(|| entry.name.clone(), |identity| identity.name.clone());
            (entry.id, name)
        })
        .collect();
    for entry in stats.iter_mut() {
        entry.parent_interface_name = entry.parent_id.and_then(|id| names.get(&id).cloned());
    }
}

/// A Backbone listener reports its children's bursts: whether any is active,
/// the earliest activation, and how many (BackboneInterface.py).
fn aggregate_backbone_bursts(stats: &mut [crate::messages::InterfaceStatRpcEntry]) {
    let listeners: Vec<InterfaceId> = stats
        .iter()
        .filter(|entry| {
            entry.parent_id.is_none()
                && entry
                    .identity
                    .as_ref()
                    .is_some_and(|identity| identity.class_name == "BackboneInterface")
        })
        .map(|entry| entry.id)
        .collect();
    for listener in listeners {
        let children = stats
            .iter()
            .filter(|entry| entry.parent_id == Some(listener));
        let (mut count, mut activated, mut pr_count, mut pr_activated) =
            (0u64, None::<f64>, 0u64, None::<f64>);
        for child in children {
            if child.burst_active {
                count += 1;
                activated = Some(
                    activated.map_or(child.burst_activated, |a: f64| a.min(child.burst_activated)),
                );
            }
            if child.pr_burst_active {
                pr_count += 1;
                pr_activated = Some(pr_activated.map_or(child.pr_burst_activated, |a: f64| {
                    a.min(child.pr_burst_activated)
                }));
            }
        }
        if let Some(entry) = stats.iter_mut().find(|entry| entry.id == listener) {
            entry.burst_count = Some(count);
            entry.burst_active = count > 0;
            entry.burst_activated = activated.unwrap_or(0.0);
            entry.pr_burst_count = Some(pr_count);
            entry.pr_burst_active = pr_count > 0;
            entry.pr_burst_activated = pr_activated.unwrap_or(0.0);
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

impl TransportActor {
    /// Python `Transport.first_hop_timeout` (Transport.py).
    pub(super) fn first_hop_timeout(&self, dest: &[u8; 16]) -> f64 {
        self.path_table
            .get_live(dest)
            .and_then(|e| self.interfaces.get(&e.interface_id))
            .filter(|iface| iface.bitrate != 0)
            .map(|iface| {
                let per_byte_latency = 8.0 / iface.bitrate as f64;
                rns_wire::constants::MTU as f64 * per_byte_latency
                    + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT
            })
            .unwrap_or(rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT)
    }

    /// Python's receipt timeout for a non-Link destination:
    /// `first_hop_timeout + TIMEOUT_PER_HOP * hops_to` (Packet.py).
    pub(super) fn default_receipt_timeout(&self, dest: &[u8; 16]) -> std::time::Duration {
        let hops = self
            .path_table
            .hops_to(dest)
            .unwrap_or(crate::constants::PATHFINDER_M);
        std::time::Duration::from_secs_f64(
            self.first_hop_timeout(dest)
                + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT * f64::from(hops),
        )
    }
}

/// Python returns the first matching cache entry (Reticulum.py).
fn first_packet_metric(cache: &VecDeque<([u8; 32], f32)>, packet_hash: &[u8; 32]) -> Option<f64> {
    cache
        .iter()
        .find(|(hash, _)| hash == packet_hash)
        .map(|(_, value)| f64::from(*value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{TransportQuery, TransportQueryResponse};

    fn link_entry() -> crate::link_table::LinkEntry {
        crate::link_table::LinkEntry {
            timestamp: now_f64(),
            next_hop: None,
            interface_id: 1,
            remaining_hops: 1,
            destination_hash: [0xCC; 16],
            validated: true,
            proof_timeout: now_f64() + 120.0,
            receiving_interface: 1,
            taken_hops: 0,
            interface_owner: None,
            receiving_owner: None,
            requested_mode: 1,
            accepted_mtu_ceiling: 500,
            traffic: 0,
        }
    }

    #[test]
    fn active_link_count_counts_validated_links() {
        let (mut actor, _tx) = TransportActor::new();
        let mut unvalidated = link_entry();
        unvalidated.validated = false;
        actor.link_table.insert([0u8; 16], link_entry());
        actor.link_table.insert([1u8; 16], unvalidated);
        assert!(matches!(
            actor.handle_query(TransportQuery::GetActiveLinkCount),
            TransportQueryResponse::IntResult(1)
        ));
        assert!(matches!(
            actor.handle_query(TransportQuery::GetLinkCount),
            TransportQueryResponse::IntResult(2)
        ));
    }
}
