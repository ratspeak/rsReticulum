use super::*;
use crate::now_f64;

/// Python 1.3.8 Transport.PR_LOGLEVEL (Transport.py:220/306): path-request
/// chatter logs at DEBUG on transport nodes, EXTREME (trace) on leaf nodes.
macro_rules! pr_log {
    ($actor:expr, $($arg:tt)*) => {
        if $actor.is_transport_enabled {
            debug!($($arg)*);
        } else {
            trace!($($arg)*);
        }
    };
}

impl TransportActor {
    pub(super) fn on_outbound(&mut self, request: crate::messages::OutboundRequest) {
        let _ = self.on_outbound_with_receipt_policy(request, true);
    }

    pub(super) fn on_outbound_with_receipt_policy(
        &mut self,
        request: crate::messages::OutboundRequest,
        create_receipt: bool,
    ) -> bool {
        self.traffic.record_tx(0, request.raw.len() as u64); // interface 0 = local

        let parsed = match rns_wire::header::PacketHeader::unpack(&request.raw) {
            Ok((header, _)) => header,
            Err(_) => return false,
        };

        // Seed the dedup set with our own packet hash so echoes looped back
        // from the fabric aren't re-processed.
        let pkt_hash = rns_wire::hash::packet_hash(&request.raw, parsed.flags.header_type);
        self.packet_hashlist.insert(pkt_hash);

        // Generate a general-purpose receipt for every outbound Data packet to a
        // non-Plain destination so callers can observe delivery / timeout.
        // Link- and resource-level contexts manage their own receipts.
        if create_receipt
            && parsed.flags.packet_type == rns_wire::flags::PacketType::Data
            && parsed.flags.destination_type != rns_wire::flags::DestinationType::Plain
        {
            let trunc_hash =
                rns_wire::hash::truncated_packet_hash(&request.raw, parsed.flags.header_type);
            let destination_public_key = self
                .recent_announces
                .get(&request.destination_hash)
                .and_then(|announce| announce.public_key);
            match self.receipt_table.entry(trunc_hash) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let full_hash =
                        rns_wire::hash::packet_hash(&request.raw, parsed.flags.header_type);
                    let mut receipt = PacketReceipt::new(
                        full_hash,
                        trunc_hash,
                        Some(std::time::Duration::from_secs(180)),
                    );
                    receipt
                        .set_destination_identity(request.destination_hash, destination_public_key);
                    entry.insert(receipt);
                    trace!(
                        trunc = hex::encode(trunc_hash),
                        "generated receipt for outbound packet"
                    );
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    // Explicit receipt registration may arrive before the
                    // outbound packet (for example rnprobe). Complete its
                    // destination binding here without discarding its timeout
                    // or application message id.
                    entry
                        .get_mut()
                        .set_destination_identity(request.destination_hash, destination_public_key);
                }
            }
        }

        tracing::info!(
            pkt_type = ?parsed.flags.packet_type,
            dest = %hex::encode(request.destination_hash),
            has_path = self.path_table.has_path(&request.destination_hash),
            num_interfaces = self.interfaces.len(),
            "outbound packet routing"
        );

        if parsed.flags.packet_type == rns_wire::flags::PacketType::Announce {
            let has_outbound_interface = self
                .interfaces
                .values()
                .any(|interface| interface.direction.outbound);
            self.broadcast_local_announce_on_interfaces(&request.raw, None);
            return has_outbound_interface;
        }

        match parsed.flags.destination_type {
            rns_wire::flags::DestinationType::Plain | rns_wire::flags::DestinationType::Group => {
                self.broadcast_on_interfaces(&request.raw, None)
            }
            rns_wire::flags::DestinationType::Single | rns_wire::flags::DestinationType::Link => {
                if let Some(path) = self.path_table.get_live(&request.destination_hash) {
                    let target_interface = path.interface_id;
                    let path_hops = path.hops;
                    let path_next_hop = path.next_hop;
                    let iface_name = self
                        .interfaces
                        .get(&target_interface)
                        .map(|e| e.name.as_str())
                        .unwrap_or("unknown");
                    tracing::info!(
                        dest = %hex::encode(request.destination_hash),
                        interface_id = target_interface,
                        interface_name = %iface_name,
                        hops = path_hops,
                        next_hop = ?path_next_hop.map(hex::encode),
                        "outbound: routed via path"
                    );

                    // Python 1.3.8 Transport.py:1153/1186: local_hops_delta
                    // replaces the zero hops byte on the way out.
                    let apply_delta = self.should_apply_delta(&parsed, target_interface);

                    // Transport nodes only forward Header2 packets whose transport_id
                    // matches their identity — Python hubs silently drop Header1 —
                    // so every directed send through a relay must be wrapped.
                    let sent = if let Some(next_hop) = path_next_hop {
                        if parsed.flags.header_type == rns_wire::flags::HeaderType::Header1 {
                            let new_flags = rns_wire::flags::PacketFlags {
                                header_type: rns_wire::flags::HeaderType::Header2,
                                transport_type: rns_wire::flags::TransportType::Transport,
                                ..parsed.flags
                            };
                            let new_header = rns_wire::header::PacketHeader {
                                flags: new_flags,
                                hops: if apply_delta {
                                    self.local_hops_delta
                                } else {
                                    parsed.hops
                                },
                                transport_id: Some(next_hop),
                                destination_hash: parsed.destination_hash,
                                context: parsed.context,
                            };
                            let mut new_raw = new_header.pack();
                            new_raw.extend_from_slice(
                                &request.raw[rns_wire::constants::HEADER_MINSIZE..],
                            );
                            tracing::debug!(
                                original_len = request.raw.len(),
                                new_len = new_raw.len(),
                                transport_id = %hex::encode(next_hop),
                                "outbound: wrapped Header1 -> Header2 for transport"
                            );
                            self.send_to_interface(target_interface, &new_raw)
                        } else if apply_delta {
                            let mangled = self.mangle_hops(&request.raw, &parsed, false);
                            self.send_to_interface(target_interface, &mangled)
                        } else {
                            self.send_to_interface(target_interface, &request.raw)
                        }
                    } else if apply_delta {
                        let mangled = self.mangle_hops(&request.raw, &parsed, false);
                        self.send_to_interface(target_interface, &mangled)
                    } else {
                        self.send_to_interface(target_interface, &request.raw)
                    };

                    // Touch the path so an actively-used route isn't culled
                    // for staleness while traffic is still flowing on it.
                    if sent {
                        if let Some(path) = self.path_table.get_live_mut(&request.destination_hash)
                        {
                            path.touch();
                        }
                    }
                    sent
                } else {
                    let iface_names: Vec<&str> = self
                        .interfaces
                        .values()
                        .filter(|e| e.direction.outbound)
                        .map(|e| e.name.as_str())
                        .collect();
                    tracing::info!(
                        dest = %hex::encode(request.destination_hash),
                        broadcast_to = ?iface_names,
                        "outbound: no path, broadcasting"
                    );
                    let sent = self.broadcast_on_interfaces(&request.raw, None);
                    if parsed.flags.packet_type != rns_wire::flags::PacketType::Proof {
                        self.on_automatic_path_request(request.destination_hash);
                    }
                    sent
                }
            }
        }
    }

    pub(super) fn on_outbound_attached(
        &mut self,
        request: crate::messages::OutboundRequest,
        interface_id: InterfaceId,
    ) -> bool {
        self.traffic.record_tx(0, request.raw.len() as u64);

        if let Ok((parsed, _)) = rns_wire::header::PacketHeader::unpack(&request.raw) {
            let pkt_hash = rns_wire::hash::packet_hash(&request.raw, parsed.flags.header_type);
            self.packet_hashlist.insert(pkt_hash);
            // Python's outbound applies should_apply_delta on attached-
            // interface sends too (Transport.py:1342-1345).
            let sent = if self.should_apply_delta(&parsed, interface_id) {
                let transport_insert = parsed.flags.packet_type
                    == rns_wire::flags::PacketType::Announce
                    && parsed.flags.header_type == rns_wire::flags::HeaderType::Header1;
                let mangled = self.mangle_hops(&request.raw, &parsed, transport_insert);
                self.send_to_interface(interface_id, &mangled)
            } else {
                self.send_to_interface(interface_id, &request.raw)
            };
            if sent && parsed.flags.packet_type == rns_wire::flags::PacketType::Announce {
                if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                    entry.ingress.sent_announce();
                }
            }
            sent
        } else {
            false
        }
    }

    /// Payload is a 32-byte packet hash identifying a cached announce. Look
    /// up the destination via `path_table.packet_hash`, fetch the stored raw
    /// announce in `recent_announces`, and rebroadcast it so the requester
    /// can resume an interrupted route.
    pub(super) fn handle_cache_request(
        &mut self,
        raw: &[u8],
        header: &rns_wire::header::PacketHeader,
        _interface_id: InterfaceId,
    ) {
        let payload_start = match self.data_payload_offset(raw, header) {
            Some(offset) => offset,
            None => {
                trace!("cache request: packet too short for header");
                return;
            }
        };
        let payload = &raw[payload_start..];

        if payload.len() != 32 {
            trace!(
                len = payload.len(),
                "cache request: payload is not 32 bytes (expected packet hash), ignoring"
            );
            return;
        }

        let mut requested_hash = [0u8; 32];
        requested_hash.copy_from_slice(payload);

        let dest_and_hops: Option<([u8; 16], u8)> = self
            .path_table
            .iter()
            .find(|(_, entry)| entry.packet_hash == Some(requested_hash))
            .map(|(dest, entry)| (*dest.as_bytes(), entry.hops));

        let Some((dest, cached_hops)) = dest_and_hops else {
            trace!(
                hash = %hex::encode(requested_hash),
                "cache request miss — no path entry with matching packet hash"
            );
            return;
        };

        let Some(cached_raw) = self.cached_announce_raw(&requested_hash) else {
            trace!(
                dest = %hex::encode(dest),
                "cache request: path entry found but no cached announce on disk"
            );
            return;
        };

        // Python 1.3.8 Transport.py:2164: a cached packet that fails to unpack
        // (incl. hops >= PATHFINDER_M, Packet.py:247-248) is a miss — never
        // replay the raw bytes.
        if rns_wire::header::PacketHeader::unpack(&cached_raw)
            .map_or(true, |(h, _)| h.hops >= PATHFINDER_M)
        {
            trace!(
                dest = %hex::encode(dest),
                "cache request: cached announce failed to parse, treating as miss"
            );
            return;
        }

        debug!(
            dest = %hex::encode(dest),
            hops = cached_hops,
            hash = %hex::encode(requested_hash),
            "cache request hit — replaying cached announce"
        );
        if self.is_transport_enabled {
            self.broadcast_announce_on_interfaces(&cached_raw, None);
        }
    }

    pub(super) fn data_payload_offset(
        &self,
        raw: &[u8],
        header: &rns_wire::header::PacketHeader,
    ) -> Option<usize> {
        let offset = match header.flags.header_type {
            rns_wire::flags::HeaderType::Header1 => rns_wire::constants::HEADER_MINSIZE, // 19
            rns_wire::flags::HeaderType::Header2 => rns_wire::constants::HEADER_MAXSIZE, // 35
        };
        if offset <= raw.len() {
            Some(offset)
        } else {
            None
        }
    }

    /// Local destination -> fire waiters so the owner re-announces.
    /// Known path + transport enabled -> replay the cached announce.
    /// Otherwise, on a transport node, forward the request on other interfaces.
    pub(super) fn handle_inbound_path_request(&mut self, data: &[u8], interface_id: InterfaceId) {
        if data.len() < 16 {
            return;
        }

        let is_from_local_client = self.is_local_client_interface(interface_id);

        let mut requested_dest = [0u8; 16];
        requested_dest.copy_from_slice(&data[..16]);

        // Python transport nodes send destination(16) + requestor transport
        // id(16) + tag(16). Leaf nodes normally send destination(16) + tag(16).
        // On receive, Python treats payloads longer than 32 bytes as transport
        // requests and truncates any remaining tag bytes to 16.
        let requestor_transport_id = if data.len() > 32 {
            let mut id = [0u8; 16];
            id.copy_from_slice(&data[16..32]);
            Some(id)
        } else {
            None
        };
        let tag_bytes = if data.len() > 32 {
            Some(&data[32..data.len().min(48)])
        } else if data.len() > 16 {
            Some(&data[16..data.len().min(32)])
        } else {
            None
        };

        let Some(tag) = tag_bytes else {
            pr_log!(
                self,
                dest = %hex::encode(requested_dest),
                "ignoring tagless path request"
            );
            return;
        };

        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            entry.ingress.received_path_request();
        }

        let now = now_f64();
        let mut unique_tag = Vec::with_capacity(32);
        unique_tag.extend_from_slice(&requested_dest);
        unique_tag.extend_from_slice(tag);
        if let Some(last) = self.discovery_pr_tags.get(&unique_tag) {
            if now - last < PATH_REQUEST_GATE_TIMEOUT {
                trace!(dest = %hex::encode(requested_dest), "ignoring duplicate path request");
                return;
            }
        }
        self.discovery_pr_tags.insert(unique_tag, now);

        if self.local_destinations.contains(&requested_dest) {
            debug!(
                dest = %hex::encode(requested_dest),
                "answering path request — destination is local"
            );
            if let Some(tx) = self.destination_channels.get(&requested_dest) {
                if let Err(e) =
                    tx.try_send(crate::link_messages::DestinationEvent::AnnounceRequested(
                        crate::link_messages::AnnounceRequest {
                            app_name: String::new(),
                            path_response: true,
                            tag: Some(tag.to_vec()),
                            attached_interface: Some(interface_id),
                        },
                    ))
                {
                    self.channel_drops += 1;
                    warn!(dest = hex::encode(requested_dest), drops = self.channel_drops, err = %e,
                        "failed to send AnnounceRequested for local path request");
                }
            }
            self.fire_path_waiters(&requested_dest);
            return;
        }

        if !is_from_local_client {
            if let Some(path) = self.path_table.get_live(&requested_dest) {
                if self.is_local_client_interface(path.interface_id) {
                    self.pending_local_path_requests
                        .insert(requested_dest, interface_id);
                }
            }
        }

        // Python Transport.py: local shared clients are allowed to use the
        // shared instance's path cache even when the instance is not a transport
        // node. Ordinary peers still require transport mode.
        if let Some(path) = (self.is_transport_enabled || is_from_local_client)
            .then(|| self.path_table.get_live(&requested_dest))
            .flatten()
        {
            let requestor_is_next_hop =
                requestor_transport_id.is_some_and(|requestor| path.next_hop == Some(requestor));
            let same_roaming_interface = self
                .interfaces
                .get(&interface_id)
                .is_some_and(|iface| iface.mode == InterfaceMode::Roaming)
                && path.interface_id == interface_id;

            if requestor_is_next_hop {
                debug!(
                    dest = %hex::encode(requested_dest),
                    "not answering path request — requester is our next hop"
                );
                return;
            }
            if same_roaming_interface {
                debug!(
                    dest = %hex::encode(requested_dest),
                    "not answering path request on roaming interface learned from same interface"
                );
                return;
            }

            let cached_raw: Option<(u8, Vec<u8>)> = path
                .packet_hash
                .and_then(|hash| self.cached_announce_raw(&hash))
                .map(|raw| (path.hops, raw));
            if let Some((hops, raw)) = cached_raw {
                // Python 1.3.8 Transport.py:2984: unparseable cached announce
                // aborts the answer entirely (no fall-through to discovery).
                let Some(response) =
                    self.path_response_from_cached_announce(&raw, requested_dest, hops)
                else {
                    return;
                };
                pr_log!(
                    self,
                    dest = %hex::encode(requested_dest),
                    hops,
                    "answering path request — path is known, queueing path response"
                );
                let now = now_f64();
                let path_on_local_client = self.is_local_client_interface(path.interface_id);
                let response_delay = if is_from_local_client || path_on_local_client {
                    0.0
                } else {
                    let roaming_extra = if self
                        .interfaces
                        .get(&interface_id)
                        .is_some_and(|iface| iface.mode == InterfaceMode::Roaming)
                    {
                        PATH_REQUEST_RG
                    } else {
                        0.0
                    };
                    PATH_REQUEST_GRACE + roaming_extra
                };
                if let Some(held_entry) = self.announce_table.remove(&requested_dest) {
                    self.held_announces.insert(requested_dest, held_entry);
                }
                self.announce_table.insert(
                    requested_dest,
                    crate::announce::AnnounceEntry {
                        timestamp: now,
                        retransmit_timeout: now + response_delay,
                        retries: 0,
                        received_from: requestor_transport_id.unwrap_or([0; 16]),
                        hops,
                        packet_raw: response,
                        local_rebroadcasts: 0,
                        block_rebroadcast: true,
                        attached_interface: Some(interface_id),
                        source_interface: None,
                    },
                );
                return;
            }
        }

        // Python 1.3.8 Transport.py:2946-2947: recursive_prs forces discovery
        // independent of interface mode (flag checked first).
        let should_search_unknown = self
            .interfaces
            .get(&interface_id)
            .is_some_and(|iface| iface.recursive_prs || mode_discovers_unknown_paths(iface.mode));

        if is_from_local_client {
            pr_log!(
                self,
                dest = %hex::encode(requested_dest),
                "forwarding path request from local shared client"
            );
            self.forward_path_request(requested_dest, Some(interface_id), tag_bytes, false);
        } else if self.is_transport_enabled && should_search_unknown {
            if self.discovery_path_requests.contains_key(&requested_dest) {
                debug!(
                    dest = %hex::encode(requested_dest),
                    "not forwarding path request — discovery request is already waiting"
                );
                return;
            }

            let ingress_limited = self
                .interfaces
                .get_mut(&interface_id)
                .is_some_and(|iface| iface.ingress.should_ingress_limit_pr());
            if ingress_limited {
                debug!(
                    dest = %hex::encode(requested_dest),
                    interface_id,
                    "not forwarding recursive path request — ingress PR burst active"
                );
                return;
            }

            debug!(
                dest = %hex::encode(requested_dest),
                "forwarding path request on other interfaces"
            );
            self.discovery_path_requests.insert(
                requested_dest,
                DiscoveryPathRequest {
                    requesting_interface: interface_id,
                    timeout: now + PATH_REQUEST_TIMEOUT,
                },
            );
            self.forward_path_request(requested_dest, Some(interface_id), tag_bytes, true);
        } else if self.has_local_client_interfaces() {
            pr_log!(
                self,
                dest = %hex::encode(requested_dest),
                "forwarding path request to local shared clients"
            );
            for local_id in self.local_client_interface_ids_except(Some(interface_id)) {
                self.send_path_request(requested_dest, local_id, None, false);
            }
        } else {
            pr_log!(
                self,
                dest = %hex::encode(requested_dest),
                interface_id,
                "ignoring unknown path request on non-discovery interface"
            );
        }
    }

    fn build_path_request_packet(&self, destination_hash: [u8; 16], tag: Option<&[u8]>) -> Vec<u8> {
        let mut request_data = Vec::with_capacity(48);
        request_data.extend_from_slice(&destination_hash);
        if self.is_transport_enabled {
            if let Some(identity_hash) = self.transport_identity_hash {
                request_data.extend_from_slice(&identity_hash);
            }
        }
        if let Some(tag) = tag {
            request_data.extend_from_slice(&tag[..tag.len().min(16)]);
        } else {
            request_data.extend_from_slice(&rns_crypto::random::random_bytes(16));
        }

        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Plain,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let pr_dest = rns_identity::destination::Destination::hash_from_name_and_identity(
            "rnstransport.path.request",
            None,
        );
        let pr_header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: pr_dest,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = pr_header.pack();
        raw.extend_from_slice(&request_data);
        raw
    }

    pub(super) fn send_path_request(
        &mut self,
        destination_hash: [u8; 16],
        interface_id: InterfaceId,
        tag: Option<&[u8]>,
        recursive: bool,
    ) {
        let raw = self.build_path_request_packet(destination_hash, tag);
        let now = now_f64();
        {
            let Some(entry) = self.interfaces.get_mut(&interface_id) else {
                return;
            };
            if !entry.direction.outbound {
                return;
            }

            if recursive {
                if entry.ingress.should_egress_limit_pr() {
                    trace!(
                        dest = %hex::encode(destination_hash),
                        interface_id,
                        "skipping recursive path request — egress PR limit active"
                    );
                    return;
                }
                if !entry.announce_queue.is_empty() {
                    trace!(
                        dest = %hex::encode(destination_hash),
                        interface_id,
                        "skipping recursive path request — announce queue is not empty"
                    );
                    return;
                }
                if now < entry.announce_allowed_at {
                    trace!(
                        dest = %hex::encode(destination_hash),
                        interface_id,
                        "skipping recursive path request — announce cap window active"
                    );
                    return;
                }

                let bitrate = entry.bitrate.max(1) as f64;
                let tx_time = (raw.len() as f64 * 8.0) / bitrate;
                let wait_time = tx_time / entry.announce_cap.max(0.001);
                entry.announce_allowed_at = now + wait_time;
            }
        }

        self.send_to_interface(interface_id, &raw);
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            entry.ingress.sent_path_request();
        }
        self.path_requests.insert(destination_hash, now);
    }

    fn forward_path_request(
        &mut self,
        destination_hash: [u8; 16],
        except: Option<InterfaceId>,
        tag: Option<&[u8]>,
        recursive: bool,
    ) {
        let ids: Vec<InterfaceId> = self
            .interfaces
            .iter()
            .filter_map(|(&id, entry)| {
                if except == Some(id) || !entry.direction.outbound {
                    None
                } else {
                    Some(id)
                }
            })
            .collect();
        for id in ids {
            self.send_path_request(destination_hash, id, tag, recursive);
        }
    }

    pub(super) fn on_path_request(&mut self, destination_hash: [u8; 16]) {
        self.broadcast_path_request(destination_hash);
    }

    pub(super) fn on_path_request_with_options(
        &mut self,
        destination_hash: [u8; 16],
        options: crate::messages::PathRequestOptions,
    ) {
        let request_tag = options
            .tag
            .unwrap_or_else(|| rns_crypto::random::random_bytes(16));
        if let Some(interface_id) = options.on_interface {
            self.send_path_request(
                destination_hash,
                interface_id,
                Some(&request_tag),
                options.recursive,
            );
        } else {
            // Python only applies recursive announce-cap gating when an
            // interface is explicitly attached.
            self.forward_path_request(destination_hash, None, Some(&request_tag), false);
        }
        debug!(
            dest = hex::encode(destination_hash),
            interface = ?options.on_interface,
            recursive = options.recursive,
            "explicit path request sent"
        );
    }

    pub(super) fn on_automatic_path_request(&mut self, destination_hash: [u8; 16]) {
        if self.path_table.has_path(&destination_hash) {
            return;
        }
        if let Some(last) = self.path_requests.get(&destination_hash) {
            if now_f64() - last < PATH_REQUEST_MI {
                return;
            }
        }
        self.broadcast_path_request(destination_hash);
    }

    fn broadcast_path_request(&mut self, destination_hash: [u8; 16]) {
        let mut request_tag = [0u8; 16];
        {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut request_tag);
        }

        self.forward_path_request(destination_hash, None, Some(&request_tag), false);

        debug!(
            dest = hex::encode(destination_hash),
            "path request broadcast"
        );
    }

    /// On tunnel reappearance, reinstall any still-valid cached paths into the
    /// path table so in-flight routes survive a link flap. Paths already
    /// superseded by a shorter live route, or expired, are discarded.
    pub(super) fn restore_tunnel_paths(&mut self, tunnel_id: &[u8; 32], interface_id: InterfaceId) {
        let now = now_f64();
        let mut deprecated_paths: Vec<[u8; 16]> = Vec::new();

        let paths: Vec<([u8; 16], crate::tunnel::TunnelPath)> =
            if let Some(tunnel) = self.tunnel_table.get(tunnel_id) {
                tunnel
                    .tunnel_paths
                    .iter()
                    .map(|(dest, tp)| (*dest, tp.clone()))
                    .collect()
            } else {
                return;
            };

        for (dest_hash, tunnel_path) in &paths {
            let mut should_add = false;

            if let Some(existing) = self.path_table.get(dest_hash) {
                let old_hops = existing.hops;
                let old_expires = existing.expires;
                if tunnel_path.hops <= old_hops || now > old_expires {
                    let current_timebase =
                        path_timebase_from_random_blobs(existing.random_blobs.iter());
                    let tunnel_timebase =
                        path_timebase_from_random_blobs(tunnel_path.random_blobs.iter());
                    if tunnel_timebase >= current_timebase {
                        should_add = true;
                    } else {
                        debug!(
                            dest = hex::encode(dest_hash),
                            "did not restore tunnel path: existing path is more recent"
                        );
                    }
                } else {
                    debug!(
                        dest = hex::encode(dest_hash),
                        "did not restore tunnel path: newer path with fewer hops exists"
                    );
                }
            } else if now < tunnel_path.expires {
                should_add = true;
            } else {
                debug!(
                    dest = hex::encode(dest_hash),
                    "did not restore tunnel path: expired"
                );
            }

            if should_add {
                let entry = crate::path_table::PathEntry {
                    timestamp: now,
                    next_hop: tunnel_path.next_hop,
                    hops: tunnel_path.hops,
                    expires: tunnel_path.expires,
                    random_blobs: tunnel_path.random_blobs.iter().copied().collect(),
                    interface_id,
                    packet_hash: tunnel_path.packet_hash,
                };
                self.path_table.insert(*dest_hash, entry);
                self.state_dirty = true;
                self.fire_path_waiters(dest_hash);
                debug!(
                    dest = hex::encode(dest_hash),
                    hops = tunnel_path.hops,
                    "restored tunnel path"
                );
            } else {
                deprecated_paths.push(*dest_hash);
            }
        }

        if !deprecated_paths.is_empty() {
            if let Some(tunnel) = self.tunnel_table.get_mut(tunnel_id) {
                for dest_hash in &deprecated_paths {
                    tunnel.tunnel_paths.remove(dest_hash);
                    debug!(
                        dest = hex::encode(dest_hash),
                        tunnel = hex::encode(&tunnel_id[..16]),
                        "removed deprecated path from tunnel"
                    );
                }
            }
            self.state_dirty = true;
        }
    }
}
