use super::*;
use crate::now_f64;

/// Bound on the in-memory resource proof cache; Python keeps one file per proof.
const PROOF_CACHE_MAX_ENTRIES: usize = 1024;

/// Path-request lengths (Transport.py).
pub(super) const PR_LEGACY_LENGTH: usize = 32;
pub(super) const PR_LENGTH: usize = 48;
pub(super) const PR_STAMPED_LENGTH: usize = 64;
pub(super) const PR_EXT_HEADER_LENGTH: usize = 2;
pub(super) const PR_EXT_PAYLOAD_LENGTH: usize = 16;

/// Transport.validate_pr_stamp (Transport.py): material `dst || tag`.
/// `0xC1 0x00` followed by the stamp (Transport.py).
fn stamped_path_request_ext(
    stamp: &crate::pr_stamper::PathRequestStamp,
) -> [u8; PR_EXT_PAYLOAD_LENGTH] {
    let mut ext = [0u8; PR_EXT_PAYLOAD_LENGTH];
    ext[0] = rns_identity::announce::ANNOUNCE_EXT_MARKER;
    ext[PR_EXT_HEADER_LENGTH..].copy_from_slice(stamp);
    ext
}

/// Transport.py: marks a relayed unstamped request from a stamping node.
const LENIENT_PATH_REQUEST_EXT: [u8; PR_EXT_PAYLOAD_LENGTH] = {
    let mut ext = [0u8; PR_EXT_PAYLOAD_LENGTH];
    ext[0] = rns_identity::announce::ANNOUNCE_EXT_MARKER;
    ext[1] = 0xFF;
    ext
};

fn path_request_stamp_valid(destination: &[u8; 16], tag: &[u8], stamp: &[u8], cost: f64) -> bool {
    if stamp.len() != rns_identity::stamps::NETWORK_STAMP_SIZE {
        return false;
    }
    let mut material = [0u8; 32];
    material[..16].copy_from_slice(destination);
    material[16..].copy_from_slice(tag);
    rns_identity::stamps::stamp_valid(stamp, cost, &material).unwrap_or(false)
}

impl TransportActor {
    pub(super) fn dispatch_link_request_checked(
        &mut self,
        request: crate::messages::OutboundRequest,
    ) -> Result<(), crate::link_messages::LinkRequestDispatchError> {
        use crate::link_messages::LinkRequestDispatchError;
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&request.raw)
            .map_err(|_| LinkRequestDispatchError::InvalidRequest)?;
        if header.destination_hash != request.destination_hash
            || header.flags.packet_type != rns_wire::flags::PacketType::LinkRequest
            || header.flags.destination_type != rns_wire::flags::DestinationType::Single
            || !rns_wire::link_signalling::parse_request_signalling(&request.raw[offset..])
                .is_ok_and(|signal| signal.mode == rns_wire::link_signalling::DEFAULT_LINK_MODE)
        {
            return Err(LinkRequestDispatchError::InvalidRequest);
        }
        if !self.local_destinations.contains(&request.destination_hash) {
            if let Some(path) = self.path_table.get_live(&request.destination_hash) {
                let entry = self
                    .interfaces
                    .get(&path.interface_id)
                    .ok_or(LinkRequestDispatchError::NoInterface)?;
                entry
                    .packet_capacity
                    .link_ceiling(path.interface_id, entry.active_ifac_bytes())?;
            } else {
                let mut first_error = None;
                let mut eligible = false;
                for (id, entry) in &self.interfaces {
                    if !entry.direction.outbound
                        || !entry.owner.is_current()
                        || entry.tx.is_closed()
                    {
                        continue;
                    }
                    match entry
                        .packet_capacity
                        .link_ceiling(*id, entry.active_ifac_bytes())
                    {
                        Ok(_) => eligible = true,
                        Err(error) => {
                            first_error.get_or_insert(error);
                        }
                    }
                }
                if !eligible {
                    return Err(first_error
                        .map(LinkRequestDispatchError::Capacity)
                        .unwrap_or(LinkRequestDispatchError::NoInterface));
                }
            }
        }
        let attempt = self.local_link_attempt(&request);
        let sent = self.on_outbound_with_receipt_policy(request, false);
        self.record_local_link_attempt(attempt, sent);
        if sent {
            Ok(())
        } else {
            Err(LinkRequestDispatchError::NoInterface)
        }
    }

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
        if parsed.hops >= PATHFINDER_M {
            return false;
        }

        if parsed.flags.packet_type == rns_wire::flags::PacketType::LinkRequest
            && !rns_wire::link_signalling::parse_request_signalling(&request.raw[parsed.size()..])
                .is_ok_and(|signal| signal.mode == rns_wire::link_signalling::DEFAULT_LINK_MODE)
        {
            return false;
        }

        // A Link can be initiated to another destination registered on this
        // same actor (for example, Ratspeak joining the RRC hub it hosts).
        // Route that traffic through two private logical edges so initiator
        // and responder never overwrite each other's `link_id` channel.
        if let Some(sent) = self.dispatch_local_link_outbound(&request, &parsed) {
            return sent;
        }

        // Seed the dedup set with our own packet hash so echoes looped back
        // from the fabric aren't re-processed.
        let pkt_hash = rns_wire::hash::packet_hash(&request.raw, parsed.flags.header_type);
        self.packet_hashlist.insert(pkt_hash);

        let mut new_receipt = None;
        // Generate a general-purpose receipt for every outbound Data packet to a
        // non-Plain destination so callers can observe delivery / timeout.
        // Link- and resource-level contexts manage their own receipts.
        if create_receipt
            && parsed.flags.packet_type == rns_wire::flags::PacketType::Data
            && parsed.flags.destination_type != rns_wire::flags::DestinationType::Plain
            && parsed.flags.destination_type != rns_wire::flags::DestinationType::Link
        {
            let trunc_hash =
                rns_wire::hash::truncated_packet_hash(&request.raw, parsed.flags.header_type);
            let destination_public_key = self
                .recent_announces
                .get(&request.destination_hash)
                .and_then(|announce| announce.public_key);
            let receipt_timeout = self.default_receipt_timeout(&request.destination_hash);
            match self.receipt_table.entry(trunc_hash) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let full_hash =
                        rns_wire::hash::packet_hash(&request.raw, parsed.flags.header_type);
                    let mut receipt =
                        PacketReceipt::new(full_hash, trunc_hash, Some(receipt_timeout));
                    receipt
                        .set_destination_identity(request.destination_hash, destination_public_key);
                    entry.insert(receipt);
                    new_receipt = Some(trunc_hash);
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

        tracing::debug!(
            pkt_type = ?parsed.flags.packet_type,
            dest = %hex::encode(request.destination_hash),
            has_path = self.path_table.has_path(&request.destination_hash),
            num_interfaces = self.interfaces.len(),
            "outbound packet routing"
        );

        if parsed.flags.packet_type == rns_wire::flags::PacketType::Announce {
            return self.broadcast_local_announce_on_interfaces(&request.raw, None);
        }

        let sent = match parsed.flags.destination_type {
            rns_wire::flags::DestinationType::Plain | rns_wire::flags::DestinationType::Group => {
                self.broadcast_on_interfaces(&request.raw, None)
            }
            rns_wire::flags::DestinationType::Single => {
                if let Some(path) = self.path_table.get_live(&request.destination_hash) {
                    let target_interface = path.interface_id;
                    let path_hops = path.hops;
                    let path_next_hop = path.next_hop;
                    let iface_name = self
                        .interfaces
                        .get(&target_interface)
                        .map(|e| e.name.as_str())
                        .unwrap_or("unknown");
                    tracing::debug!(
                        dest = %hex::encode(request.destination_hash),
                        interface_id = target_interface,
                        interface_name = %iface_name,
                        hops = path_hops,
                        next_hop = ?path_next_hop.map(hex::encode),
                        "outbound: routed via path"
                    );

                    // Python 1.3.8 Transport.py/1186: local_hops_delta
                    // replaces the zero hops byte on the way out.
                    let apply_delta = self.should_apply_delta(&parsed, target_interface);

                    // Transport.py: wrap beyond one hop, or at one hop
                    // when this node sits behind a shared instance.
                    let wrap = path_hops > 1 || (path_hops == 1 && self.is_shared_instance);
                    let sent = if let Some(next_hop) = path_next_hop.filter(|_| wrap) {
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
                        } else {
                            // Transport.py: an already-wrapped packet is not sent.
                            false
                        }
                    } else if apply_delta {
                        let mangled = self.mangle_hops(&request.raw, &parsed, false);
                        self.send_to_interface(target_interface, &mangled)
                    } else {
                        self.send_to_interface(target_interface, &request.raw)
                    };

                    // Transport.py: traffic marks use, never liveness.
                    if let Some(path) = self.path_table.get_live_mut(&request.destination_hash) {
                        path.mark_used();
                    }
                    sent
                } else {
                    let iface_names: Vec<&str> = self
                        .interfaces
                        .values()
                        .filter(|e| e.direction.outbound)
                        .map(|e| e.name.as_str())
                        .collect();
                    tracing::debug!(
                        dest = %hex::encode(request.destination_hash),
                        broadcast_to = ?iface_names,
                        "outbound: no path, broadcasting"
                    );
                    self.broadcast_on_interfaces(&request.raw, None)
                }
            }
            rns_wire::flags::DestinationType::Link => {
                // Established Links are interface-bound sessions, not
                // ordinary destinations. Their 16-byte link id has no
                // path-table meaning and must never trigger discovery or a
                // broadcast fallback. In-process Links were already handled
                // above; network owners must use SendLinkEndpoint (or the
                // temporary OutboundAttached migration bridge).
                warn!(
                    link_id = %hex::encode(request.destination_hash),
                    "dropping unattached locally-originated Link packet"
                );
                false
            }
        };
        // Packet.py: a packet that went nowhere keeps no receipt.
        if !sent && let Some(hash) = new_receipt {
            self.receipt_table.remove(&hash);
        }
        sent
    }

    pub(super) fn on_outbound_attached(
        &mut self,
        request: crate::messages::OutboundRequest,
        interface_id: InterfaceId,
    ) -> bool {
        self.traffic.record_tx(0, request.raw.len() as u64);

        if let Some(sent) = self.dispatch_local_link_attached(&request, interface_id) {
            return sent;
        }
        // Transport.py: an attached interface is used only while online.
        if self
            .interfaces
            .get(&interface_id)
            .is_some_and(offline_for_send)
        {
            return false;
        }

        if let Ok((parsed, _)) = rns_wire::header::PacketHeader::unpack(&request.raw) {
            if parsed.hops >= PATHFINDER_M {
                return false;
            }
            if parsed.flags.destination_type == rns_wire::flags::DestinationType::Link {
                let current = self.interfaces.get(&interface_id).map(|entry| &entry.owner);
                let table_owned =
                    self.link_table
                        .get(&parsed.destination_hash)
                        .is_some_and(|entry| {
                            entry.interface_id == interface_id
                                && entry.interface_owner.as_ref().zip(current).is_some_and(
                                    |(owned, current)| owned == current && current.is_current(),
                                )
                        });
                let endpoint_owned = self.link_endpoints.values().any(|entry| {
                    entry.binding.link_id == parsed.destination_hash
                        && entry.binding.interface_id == interface_id
                        && entry
                            .binding
                            .interface_owner
                            .zip(current)
                            .is_some_and(|(owned, current)| owned.matches(current))
                });
                if !table_owned && !endpoint_owned {
                    return false;
                }
            }

            let pkt_hash = rns_wire::hash::packet_hash(&request.raw, parsed.flags.header_type);
            self.packet_hashlist.insert(pkt_hash);
            // Python's outbound applies should_apply_delta on attached-
            // interface sends too (Transport.py).
            if self.should_apply_delta(&parsed, interface_id) {
                let transport_insert = parsed.flags.packet_type
                    == rns_wire::flags::PacketType::Announce
                    && parsed.flags.header_type == rns_wire::flags::HeaderType::Header1;
                let mangled = self.mangle_hops(&request.raw, &parsed, transport_insert);
                if parsed.flags.packet_type == rns_wire::flags::PacketType::Announce {
                    self.send_or_retain_announce(interface_id, &mangled, true)
                } else {
                    self.send_to_interface(interface_id, &mangled)
                }
            } else if parsed.flags.packet_type == rns_wire::flags::PacketType::Announce {
                self.send_or_retain_announce(interface_id, &request.raw, true)
            } else {
                self.send_to_interface(interface_id, &request.raw)
            }
        } else {
            false
        }
    }

    fn dispatch_local_link_outbound(
        &mut self,
        request: &crate::messages::OutboundRequest,
        header: &rns_wire::header::PacketHeader,
    ) -> Option<bool> {
        if header.flags.packet_type == rns_wire::flags::PacketType::LinkRequest
            && self.local_destinations.contains(&request.destination_hash)
        {
            let link_id = rns_wire::hash::link_id_from_raw(&request.raw, header.flags.header_type);
            let initiator_tx = self.destination_channels.get(&link_id)?.clone();
            let responder_tx = self
                .destination_channels
                .get(&request.destination_hash)?
                .clone();
            self.local_link_routes.insert(
                link_id,
                LocalLinkRoute {
                    initiator_tx,
                    responder_tx: responder_tx.clone(),
                },
            );
            let delivered =
                responder_tx.try_send(crate::link_messages::DestinationEvent::LinkRequest {
                    interface_owner: None,
                    raw: request.raw.clone(),
                    interface_id: LOCAL_LINK_RESPONDER_INTERFACE,
                    metrics: PacketMetrics::default(),
                });
            if let Err(error) = delivered {
                self.local_link_routes.remove(&link_id);
                self.channel_drops += 1;
                warn!(
                    link_id = %hex::encode(link_id),
                    drops = self.channel_drops,
                    err = %error,
                    "failed to deliver in-process Link request"
                );
                return Some(false);
            }
            self.traffic.record_rx(0, request.raw.len() as u64);
            debug!(
                link_id = %hex::encode(link_id),
                dest = %hex::encode(request.destination_hash),
                "in-process Link request routed to local destination"
            );
            return Some(true);
        }

        // LinkManager responder traffic uses ordinary Outbound messages.
        // Initiator traffic is pinned with OutboundAttached below, so the
        // message shape itself supplies the side without changing public APIs.
        let route = self.local_link_routes.get(&request.destination_hash)?;
        let delivered =
            route
                .initiator_tx
                .try_send(crate::link_messages::DestinationEvent::InboundPacket {
                    interface_owner: None,
                    raw: request.raw.clone(),
                    interface_id: LOCAL_LINK_INITIATOR_INTERFACE,
                    metrics: PacketMetrics::default(),
                });
        if let Err(error) = delivered {
            self.channel_drops += 1;
            warn!(
                link_id = %hex::encode(request.destination_hash),
                drops = self.channel_drops,
                err = %error,
                "failed to deliver in-process responder Link packet"
            );
            return Some(false);
        }
        self.traffic.record_rx(0, request.raw.len() as u64);
        Some(true)
    }

    fn dispatch_local_link_attached(
        &mut self,
        request: &crate::messages::OutboundRequest,
        interface_id: InterfaceId,
    ) -> Option<bool> {
        let route = self.local_link_routes.get(&request.destination_hash)?;
        let (target, target_interface, direction) = match interface_id {
            LOCAL_LINK_INITIATOR_INTERFACE => (
                &route.responder_tx,
                LOCAL_LINK_RESPONDER_INTERFACE,
                "initiator",
            ),
            LOCAL_LINK_RESPONDER_INTERFACE => (
                &route.initiator_tx,
                LOCAL_LINK_INITIATOR_INTERFACE,
                "responder",
            ),
            _ => return None,
        };
        let delivered = target.try_send(crate::link_messages::DestinationEvent::InboundPacket {
            interface_owner: self
                .interfaces
                .get(&target_interface)
                .map(|entry| entry.owner.id()),
            raw: request.raw.clone(),
            interface_id: target_interface,
            metrics: PacketMetrics::default(),
        });
        if let Err(error) = delivered {
            self.channel_drops += 1;
            warn!(
                link_id = %hex::encode(request.destination_hash),
                side = direction,
                drops = self.channel_drops,
                err = %error,
                "failed to deliver in-process attached Link packet"
            );
            return Some(false);
        }
        self.traffic.record_rx(0, request.raw.len() as u64);
        Some(true)
    }

    /// Python's packet cache holds only the resource proofs this instance
    /// sent; files expire after `PATH_TIMEOUT` (Reticulum.py).
    pub(super) fn cache_proof(&mut self, packet_hash: [u8; 32], raw: Bytes) {
        if self
            .proof_cache
            .insert(packet_hash, (raw, now_f64()))
            .is_none()
        {
            self.proof_cache_order.push_back(packet_hash);
        }
        while self.proof_cache_order.len() > PROOF_CACHE_MAX_ENTRIES {
            if let Some(oldest) = self.proof_cache_order.pop_front() {
                self.proof_cache.remove(&oldest);
            }
        }
    }

    /// Python `Transport.get_cached_packet(packet_hash)` (Transport.py).
    fn cached_proof(&self, packet_hash: &[u8; 32]) -> Option<Bytes> {
        self.proof_cache
            .get(packet_hash)
            .filter(|(_, stored)| now_f64() - stored <= PATHFINDER_E as f64)
            .map(|(raw, _)| raw.clone())
    }

    fn bound_link_role(&self, link_id: &[u8; 16]) -> Option<crate::messages::LinkEndpointRole> {
        use crate::messages::LinkEndpointRole;
        [LinkEndpointRole::Initiator, LinkEndpointRole::Responder]
            .into_iter()
            .find(|role| self.link_endpoints.contains_key(&(*link_id, *role)))
    }

    /// A CACHE_REQUEST for one of our established Links is answered by
    /// re-sending the cached packet's data on that Link, and dropped on a
    /// miss (Transport.py). Any other request replays a cache hit
    /// through inbound when transport handling applies, and otherwise returns
    /// false so normal processing continues (Transport.py).
    pub(super) fn handle_cache_request(
        &mut self,
        raw: &[u8],
        header: &rns_wire::header::PacketHeader,
        interface_id: InterfaceId,
        transport_handling: bool,
    ) -> bool {
        let requested = self
            .data_payload_offset(raw, header)
            .and_then(|offset| <[u8; 32]>::try_from(&raw[offset..]).ok());
        let link_id = header.destination_hash;
        let local_link = (header.flags.destination_type == rns_wire::flags::DestinationType::Link)
            .then(|| self.bound_link_role(&link_id))
            .flatten();
        let Some(role) = local_link else {
            let Some(cached) = requested
                .filter(|_| transport_handling)
                .and_then(|hash| self.cached_proof(&hash))
            else {
                return false;
            };
            self.replay_cached_packet(cached);
            return true;
        };
        if self.link_packet_on_unbound_interface(header, interface_id) {
            return true;
        }
        let Some(cached) = requested.and_then(|hash| self.cached_proof(&hash)) else {
            trace!(link_id = %hex::encode(link_id), "cache request miss");
            return true;
        };
        let Ok((cached_header, offset)) = rns_wire::header::PacketHeader::unpack(&cached) else {
            return true;
        };
        let mut answer = link_packet_header(
            link_id,
            cached_header.flags.packet_type,
            cached_header.context,
        )
        .pack();
        answer.extend_from_slice(&cached[offset..]);
        debug!(link_id = %hex::encode(link_id), "cache request hit, re-sending cached packet");
        self.send_link_endpoint(
            link_id,
            role,
            crate::messages::OutboundRequest {
                raw: Bytes::from(answer),
                destination_hash: link_id,
            },
        );
        true
    }

    /// Python `Transport.cache_request`: replay a local hit, otherwise send
    /// a CACHE_REQUEST to the destination (Transport.py).
    pub(super) fn send_cache_request(&mut self, packet_hash: [u8; 32], destination_hash: [u8; 16]) {
        if let Some(cached) = self.cached_proof(&packet_hash) {
            self.replay_cached_packet(cached);
            return;
        }
        let Some(role) = self.bound_link_role(&destination_hash) else {
            trace!(dest = %hex::encode(destination_hash), "cache request for an unbound Link");
            return;
        };
        let mut raw = link_packet_header(
            destination_hash,
            rns_wire::flags::PacketType::Data,
            rns_wire::context::PacketContext::CacheRequest,
        )
        .pack();
        raw.extend_from_slice(&packet_hash);
        self.send_link_endpoint(
            destination_hash,
            role,
            crate::messages::OutboundRequest {
                raw: Bytes::from(raw),
                destination_hash,
            },
        );
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
    #[cfg(test)]
    pub(super) fn handle_inbound_path_request(&mut self, data: &[u8], interface_id: InterfaceId) {
        let raw_len = data.len() + rns_wire::constants::HEADER_MINSIZE;
        self.handle_inbound_path_request_sized(data, interface_id, raw_len);
    }

    /// `raw_len` is the whole packet's size, which Python counts in `prxb`.
    pub(super) fn handle_inbound_path_request_sized(
        &mut self,
        data: &[u8],
        interface_id: InterfaceId,
        raw_len: usize,
    ) {
        if data.len() < 16 {
            return;
        }

        let is_from_local_client = self.is_local_client_interface(interface_id);

        // Transport.py and parse_path_request.
        if data.len() > PR_STAMPED_LENGTH {
            self.protocol_violation(interface_id);
            return;
        }
        let mut requested_dest = [0u8; 16];
        requested_dest.copy_from_slice(&data[..16]);
        if data.len() == 16 {
            pathing!(
                dest = %hex::encode(requested_dest),
                "ignoring tagless path request"
            );
            self.protocol_violation(interface_id);
            return;
        }
        if !matches!(data.len(), PR_LEGACY_LENGTH | PR_LENGTH | PR_STAMPED_LENGTH) {
            self.protocol_violation(interface_id);
            return;
        }
        let (requestor_transport_id, tag, ext) = if data.len() == PR_LEGACY_LENGTH {
            (None, &data[16..32], None)
        } else {
            let mut id = [0u8; 16];
            id.copy_from_slice(&data[16..32]);
            let ext: Option<[u8; PR_EXT_PAYLOAD_LENGTH]> =
                data.get(PR_LENGTH..).and_then(|ext| ext.try_into().ok());
            (Some(id), &data[32..48], ext)
        };
        let tag_bytes = Some(tag);

        let now = now_f64();
        let mut unique_tag = [0u8; 32];
        unique_tag[..16].copy_from_slice(&requested_dest);
        unique_tag[16..].copy_from_slice(tag);
        if self.discovery_pr_tags_prev.contains(&unique_tag)
            || !self.discovery_pr_tags.insert(unique_tag)
        {
            trace!(dest = %hex::encode(requested_dest), "ignoring duplicate path request");
            return;
        }
        // Transport.py: the flags byte is not consulted, so the
        // lenient 0xC1 0xFF marker fails like any invalid stamp.
        if self.stamp_policy.stamps_enabled {
            let required_value = self.interface_pr_cost(interface_id);
            let stamp_ok = ext.as_ref().is_some_and(|ext| {
                ext[0] == rns_identity::announce::ANNOUNCE_EXT_MARKER
                    && path_request_stamp_valid(
                        &requested_dest,
                        tag,
                        &ext[PR_EXT_HEADER_LENGTH..],
                        required_value,
                    )
            });
            if !stamp_ok {
                if ext.is_some() {
                    pathing!(
                        dest = %hex::encode(requested_dest),
                        lenient = ext.as_ref().is_some_and(|ext| ext[1] == 0xFF),
                        "path request without a valid stamp"
                    );
                } else {
                    trace!(dest = %hex::encode(requested_dest), "unstamped path request");
                }
                if self.stamp_policy.stamps_enforced {
                    return;
                }
            }
        }
        // Python counts a path request once its tag and stamp pass these gates
        // (Transport.py).
        self.record_interface_event(interface_id, InterfaceEvent::ReceivedPathRequest, raw_len);
        self.count_transport_event(InterfaceEvent::ReceivedPathRequest);

        // Transport.py: a request for a destination already
        // in flight joins the waiting requesters instead of being processed.
        if self.inflight_path_requests.contains_key(&requested_dest) {
            // A leaf answers batched requesters only for its local clients;
            // upstream would also emit PATH_RESPONSEs naming the leaf as relay.
            if (self.is_transport_enabled || is_from_local_client)
                && !self.processing_ingress_limited
            {
                pathing!(
                    dest = %hex::encode(requested_dest),
                    interface_id,
                    "path request already in flight, batching to existing"
                );
                self.batch_inflight_requester(requested_dest, interface_id, now);
            }
            return;
        }
        self.inflight_path_requests.insert(requested_dest, now);

        if self.local_destinations.contains(&requested_dest) {
            pathing!(
                dest = %hex::encode(requested_dest),
                "answering path request — destination is local"
            );
            self.inflight_path_requests.remove(&requested_dest);
            if let Some(tx) = self.destination_channels.get(&requested_dest)
                && let Err(e) =
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
            self.fire_path_waiters(&requested_dest);
            return;
        }

        if !is_from_local_client
            && let Some(path) = self.path_table.get_live(&requested_dest)
            && self.is_local_client_interface(path.interface_id)
        {
            self.pending_local_path_requests
                .insert(requested_dest, interface_id);
            self.use_destination(&requested_dest);
        }

        // Python Transport.py: local shared clients are allowed to use the
        // shared instance's path cache even when the instance is not a transport
        // node. Ordinary peers still require transport mode.
        if let Some(path) = (self.is_transport_enabled || is_from_local_client)
            .then(|| self.path_table.get_live(&requested_dest).cloned())
            .flatten()
        {
            let requestor_is_next_hop =
                requestor_transport_id.is_some_and(|requestor| path.next_hop == Some(requestor));
            let same_roaming_interface = self
                .interfaces
                .get(&interface_id)
                .is_some_and(|iface| iface.mode == InterfaceMode::Roaming)
                && path.interface_id == interface_id;

            if requestor_is_next_hop || same_roaming_interface {
                // Transport.py: answered, even when declined.
                self.inflight_path_requests.remove(&requested_dest);
            }
            if requestor_is_next_hop {
                pathing!(
                    dest = %hex::encode(requested_dest),
                    "not answering path request — requester is our next hop"
                );
                return;
            }
            if same_roaming_interface {
                pathing!(
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
                // Python 1.3.8 Transport.py: unparseable cached announce
                // aborts the answer entirely (no fall-through to discovery).
                let Some(response) =
                    self.path_response_from_cached_announce(&raw, requested_dest, hops)
                else {
                    return;
                };
                pathing!(
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
                if !self.shared_instance_client_mode {
                    self.use_destination(&requested_dest);
                }
                self.inflight_path_requests.remove(&requested_dest);
                return;
            }
        }

        // Python 1.3.8 Transport.py: recursive_prs forces discovery
        // independent of interface mode (flag checked first).
        let search = self
            .interfaces
            .get(&interface_id)
            .and_then(|iface| path_search_modes(iface.recursive_prs, iface.mode));
        let should_search_unknown = search.is_some();

        if is_from_local_client {
            pathing!(
                dest = %hex::encode(requested_dest),
                "forwarding path request from local shared client"
            );
            self.forward_path_request_ext(
                requested_dest,
                Some(interface_id),
                tag_bytes,
                ext.as_ref(),
                false,
                None,
            );
        } else if self.is_transport_enabled && should_search_unknown {
            let ingress_limited = self.processing_ingress_limited
                || self
                    .interfaces
                    .get_mut(&interface_id)
                    .is_some_and(|iface| iface.ingress.should_ingress_limit_pr());
            if ingress_limited {
                pathing!(
                    dest = %hex::encode(requested_dest),
                    interface_id,
                    "not forwarding recursive path request — ingress PR burst active"
                );
                return;
            }

            // Transport.py: never reached while enforcement drops
            // unstamped requests above.
            if ext.is_none() && self.stamp_policy.stamps_enforced {
                tracing::error!(
                    dest = %hex::encode(requested_dest),
                    "reached rebroadcast decision for unstamped path request under stamp enforcement"
                );
                return;
            }
            if self.begin_or_join_recursive_discovery(requested_dest, interface_id, now) {
                let ext = self.lenient_relay_ext(ext);
                self.forward_path_request_ext(
                    requested_dest,
                    Some(interface_id),
                    tag_bytes,
                    ext.as_ref(),
                    true,
                    search.flatten(),
                );
            }
        } else if self.has_local_client_interfaces() {
            pathing!(
                dest = %hex::encode(requested_dest),
                "forwarding path request to local shared clients"
            );
            let ext = self.lenient_relay_ext(ext);
            for local_id in self.local_client_interface_ids_except(Some(interface_id)) {
                self.send_path_request_ext(
                    requested_dest,
                    local_id,
                    Some(tag),
                    ext.as_ref(),
                    false,
                );
            }
        } else {
            pathing!(
                dest = %hex::encode(requested_dest),
                interface_id,
                "ignoring unknown path request on non-discovery interface"
            );
        }
    }

    /// Transport.py: a stamping node relays someone
    /// else's unstamped request with the lenient marker instead of a stamp.
    fn lenient_relay_ext(
        &self,
        ext: Option<[u8; PR_EXT_PAYLOAD_LENGTH]>,
    ) -> Option<[u8; PR_EXT_PAYLOAD_LENGTH]> {
        match ext {
            None if self.stamp_policy.stamp_prs => Some(LENIENT_PATH_REQUEST_EXT),
            ext => ext,
        }
    }

    /// Transport.py: destination, transport id, tag, then any
    /// received extension unchanged.
    fn build_path_request_packet(
        &self,
        destination_hash: [u8; 16],
        tag: Option<&[u8]>,
        ext: Option<&[u8; PR_EXT_PAYLOAD_LENGTH]>,
    ) -> Vec<u8> {
        let mut request_data = Vec::with_capacity(PR_STAMPED_LENGTH);
        request_data.extend_from_slice(&destination_hash);
        // Leaves use their ephemeral identity; only a bare actor has none.
        if let Some(identity_hash) = self.transport_identity_hash {
            request_data.extend_from_slice(&identity_hash);
        }
        if let Some(tag) = tag {
            request_data.extend_from_slice(&tag[..tag.len().min(16)]);
        } else {
            request_data.extend_from_slice(&rns_crypto::random::random_bytes(16));
        }
        if let Some(ext) = ext {
            request_data.extend_from_slice(ext);
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
        self.send_path_request_ext(destination_hash, interface_id, tag, None, recursive);
    }

    /// Python `request_path` on one interface (Transport.py): a
    /// supplied extension is sent unchanged; otherwise, under `stamp_prs`, a
    /// cached stamp is appended or generation is queued and nothing is sent yet.
    pub(super) fn send_path_request_ext(
        &mut self,
        destination_hash: [u8; 16],
        interface_id: InterfaceId,
        tag: Option<&[u8]>,
        ext: Option<&[u8; PR_EXT_PAYLOAD_LENGTH]>,
        recursive: bool,
    ) {
        let Some((tag, ext)) = self.stamp_path_request_or_queue(
            destination_hash,
            tag,
            ext,
            crate::pr_stamper::PathRequestTarget::Interface(interface_id),
            recursive,
        ) else {
            return;
        };
        let raw = self.build_path_request_packet(destination_hash, Some(&tag), ext.as_ref());
        self.admit_path_request(destination_hash, interface_id, raw, recursive);
    }

    /// Resolve the request tag and extension. `None` means the request waits
    /// for the stamper (Transport.py).
    #[allow(clippy::type_complexity)]
    fn stamp_path_request_or_queue(
        &mut self,
        destination_hash: [u8; 16],
        tag: Option<&[u8]>,
        ext: Option<&[u8; PR_EXT_PAYLOAD_LENGTH]>,
        target: crate::pr_stamper::PathRequestTarget,
        recursive: bool,
    ) -> Option<(Vec<u8>, Option<[u8; PR_EXT_PAYLOAD_LENGTH]>)> {
        let tag = match tag {
            Some(tag) => tag[..tag.len().min(16)].to_vec(),
            None => rns_crypto::random::random_bytes(16),
        };
        if let Some(ext) = ext {
            return Some((tag, Some(*ext)));
        }
        if !self.stamp_policy.stamp_prs {
            return Some((tag, None));
        }
        if let Some(stamp) = self.pr_stamper.cached(&destination_hash, &tag) {
            return Some((tag, Some(stamped_path_request_ext(&stamp))));
        }
        self.path_requests.insert(destination_hash, now_f64());
        let job = crate::pr_stamper::PathRequestStampJob {
            destination_hash,
            tag,
            target,
            recursive,
            value: self.stamp_policy.pr_value,
            timeout: self.stamp_policy.pr_stamp_timeout,
        };
        if self.pr_stamper.enqueue(job).is_err() {
            debug!(
                dest = hex::encode(destination_hash),
                "stamp queue full, dropping path request"
            );
        }
        None
    }

    /// Python `stamp_path_request` after generation (Transport.py).
    pub(super) fn on_path_request_stamp_ready(
        &mut self,
        result: crate::pr_stamper::PathRequestStampResult,
    ) {
        let job = result.job;
        let Some(stamp) = result.stamp else {
            warn!(
                dest = hex::encode(job.destination_hash),
                "could not generate path request stamp, path request emission cancelled"
            );
            return;
        };
        let ext = stamped_path_request_ext(&stamp);
        match job.target {
            crate::pr_stamper::PathRequestTarget::Interface(interface_id) => self
                .send_path_request_ext(
                    job.destination_hash,
                    interface_id,
                    Some(&job.tag),
                    Some(&ext),
                    job.recursive,
                ),
            crate::pr_stamper::PathRequestTarget::AllExcept(except) => self
                .forward_path_request_ext(
                    job.destination_hash,
                    except,
                    Some(&job.tag),
                    Some(&ext),
                    job.recursive,
                    None,
                ),
        }
    }

    pub(super) fn forward_path_request(
        &mut self,
        destination_hash: [u8; 16],
        except: Option<InterfaceId>,
        tag: Option<&[u8]>,
        recursive: bool,
    ) {
        self.forward_path_request_ext(destination_hash, except, tag, None, recursive, None);
    }

    /// One request, stamped once, offered on every outbound interface but
    /// `except`, limited to `modes` when given (Transport.py).
    pub(super) fn forward_path_request_ext(
        &mut self,
        destination_hash: [u8; 16],
        except: Option<InterfaceId>,
        tag: Option<&[u8]>,
        ext: Option<&[u8; PR_EXT_PAYLOAD_LENGTH]>,
        recursive: bool,
        modes: Option<&[InterfaceMode]>,
    ) {
        if let Some(modes) = modes {
            let ids: Vec<InterfaceId> = self
                .prioritized_interface_ids()
                .into_iter()
                .filter(|id| {
                    let entry = &self.interfaces[id];
                    except != Some(*id) && entry.direction.outbound && modes.contains(&entry.mode)
                })
                .collect();
            let tag = tag.map_or_else(|| rns_crypto::random::random_bytes(16), <[u8]>::to_vec);
            for id in ids {
                self.send_path_request_ext(destination_hash, id, Some(&tag), ext, recursive);
            }
            return;
        }
        let Some((tag, ext)) = self.stamp_path_request_or_queue(
            destination_hash,
            tag,
            ext,
            crate::pr_stamper::PathRequestTarget::AllExcept(except),
            recursive,
        ) else {
            return;
        };
        let ids: Vec<InterfaceId> = self
            .prioritized_interface_ids()
            .into_iter()
            .filter(|id| except != Some(*id) && self.interfaces[id].direction.outbound)
            .collect();
        for id in ids {
            self.send_path_request_ext(destination_hash, id, Some(&tag), ext.as_ref(), recursive);
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
            "explicit path request processed for driver admission"
        );
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
                        pathing!(
                            dest = hex::encode(dest_hash),
                            "did not restore tunnel path: existing path is more recent"
                        );
                    }
                } else {
                    pathing!(
                        dest = hex::encode(dest_hash),
                        "did not restore tunnel path: newer path with fewer hops exists"
                    );
                }
            } else if now < tunnel_path.expires {
                should_add = true;
            } else {
                pathing!(
                    dest = hex::encode(dest_hash),
                    "did not restore tunnel path: expired"
                );
            }

            if should_add {
                // Transport.py keeps the saved timestamp and use.
                let entry = crate::path_table::PathEntry {
                    timestamp: tunnel_path.timestamp,
                    next_hop: tunnel_path.next_hop,
                    hops: tunnel_path.hops,
                    expires: tunnel_path.expires,
                    random_blobs: tunnel_path.random_blobs.iter().copied().collect(),
                    interface_id,
                    packet_hash: tunnel_path.packet_hash,
                    used: tunnel_path.used,
                };
                self.path_table.insert(*dest_hash, entry);
                self.state_dirty = true;
                self.fire_path_waiters(dest_hash);
                pathing!(
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
                    pathing!(
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

/// The header Python's `RNS.Packet(link, ...)` packs (Packet.py).
fn link_packet_header(
    link_id: [u8; 16],
    packet_type: rns_wire::flags::PacketType,
    context: rns_wire::context::PacketContext,
) -> rns_wire::header::PacketHeader {
    rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type,
        },
        hops: 0,
        transport_id: None,
        destination_hash: link_id,
        context,
    }
}

#[cfg(test)]
mod cache_miss_tests {
    use super::*;
    use crate::constants::InterfaceDirection;
    use crate::messages::InterfaceEntry;
    use crate::path_table::PathEntry;

    #[test]
    fn live_path_without_cached_announce_uses_normal_discovery_gates() {
        // A Boundary requester searches only Boundary and Gateway interfaces
        // (Transport.py), so the Full route gets no request.
        for (mode, discovers, sent) in [
            (InterfaceMode::Gateway, true, true),
            (InterfaceMode::Boundary, true, false),
            (InterfaceMode::Full, false, false),
        ] {
            let (mut actor, _actor_tx) = TransportActor::new();
            actor.is_transport_enabled = true;
            actor.transport_identity_hash = Some([0x42; 16]);
            let (ingress_tx, _ingress_rx) = tokio::sync::mpsc::channel(4);
            let (egress_tx, mut egress_rx) = tokio::sync::mpsc::channel(4);
            actor.interfaces.insert(
                1,
                InterfaceEntry::new(
                    "requester".into(),
                    mode,
                    InterfaceDirection::bidirectional(),
                    1_000_000,
                    500,
                    ingress_tx,
                ),
            );
            actor.interfaces.insert(
                2,
                InterfaceEntry::new(
                    "route".into(),
                    InterfaceMode::Full,
                    InterfaceDirection::bidirectional(),
                    1_000_000,
                    500,
                    egress_tx,
                ),
            );
            let requested = [0x77; 16];
            let mut path = PathEntry::new(None, 1, 2, InterfaceMode::Full);
            path.packet_hash = Some([0x33; 32]);
            actor.path_table.insert(requested, path);
            // A live route without a storage directory exactly exercises unavailable
            // signed cache material, without touching the filesystem or Python oracle.
            assert!(actor.path_table.get_live(&requested).is_some());
            assert!(actor.cached_announce_raw(&[0x33; 32]).is_none());
            let mut request = requested.to_vec();
            request.extend_from_slice(&[0x55; 16]);
            actor.handle_inbound_path_request(&request, 1);
            assert_eq!(egress_rx.try_recv().is_ok(), sent);
            assert_eq!(
                actor.discovery_path_requests.contains_key(&requested),
                discovers
            );
            assert!(actor.announce_table.is_empty());
        }
    }
}

#[cfg(test)]
mod path_request_stamp_tests {
    use super::*;
    use crate::constants::InterfaceDirection;
    use crate::messages::InterfaceEntry;

    // Upstream 1.6.0 `Transport.stamp_path_request` output ("stamped tag-1", value 17.0).
    const STAMPED_TAG_1: &str = "2d4bc0819eb94f7589f484fe08c644d9efbbc5b835ded256c2da654648f0abf43e5555f7572f4391cc8a6af12c94c36ec100a01772d007a30bd60135e4c63127";

    fn actor_with_two_interfaces(
        transport: bool,
    ) -> (
        TransportActor,
        tokio::sync::mpsc::Receiver<bytes::Bytes>,
        tokio::sync::mpsc::Receiver<bytes::Bytes>,
    ) {
        let (mut actor, _tx) = TransportActor::new();
        actor.is_transport_enabled = transport;
        actor.transport_identity_hash = Some([0x42; 16]);
        let (a_tx, a_rx) = tokio::sync::mpsc::channel(8);
        let (b_tx, b_rx) = tokio::sync::mpsc::channel(8);
        for (id, tx) in [(1, a_tx), (2, b_tx)] {
            let mut entry = InterfaceEntry::new(
                format!("if{id}"),
                InterfaceMode::Gateway,
                InterfaceDirection::bidirectional(),
                1_000_000_000,
                500,
                tx,
            );
            entry.ingress = crate::ingress::IngressController::disabled();
            actor.interfaces.insert(id, entry);
        }
        (actor, a_rx, b_rx)
    }

    fn received(actor: &TransportActor, id: InterfaceId) -> u64 {
        actor.interfaces[&id].ingress.path_requests_received()
    }

    fn violations(actor: &TransportActor, id: InterfaceId) -> u64 {
        actor.interfaces[&id].protocol_violations
    }

    fn payload(frame: &[u8]) -> Vec<u8> {
        frame[rns_wire::constants::HEADER_MINSIZE..].to_vec()
    }

    fn with_ext(ext: &[u8]) -> Vec<u8> {
        let mut data = hex::decode(STAMPED_TAG_1).unwrap();
        data.truncate(PR_LENGTH);
        data.extend_from_slice(ext);
        data
    }

    #[test]
    fn enforcement_drops_unstamped_lenient_and_invalid_requests_silently() {
        let mut lenient = vec![0xC1, 0xFF];
        lenient.extend_from_slice(&[0; 14]);
        let mut zero = vec![0xC1, 0x00];
        zero.extend_from_slice(&[0; 14]);
        let mut unknown = hex::decode(STAMPED_TAG_1).unwrap()[PR_LENGTH..].to_vec();
        unknown[0] = 0xC2;
        let unstamped = hex::decode(STAMPED_TAG_1).unwrap()[..PR_LENGTH].to_vec();
        for data in [
            unstamped,
            with_ext(&lenient),
            with_ext(&zero),
            with_ext(&unknown),
        ] {
            let (mut actor, _a, mut b) = actor_with_two_interfaces(true);
            actor.stamp_policy.enforce();
            actor.handle_inbound_path_request(&data, 1);
            assert_eq!(received(&actor, 1), 0);
            assert_eq!(violations(&actor, 1), 0);
            assert!(b.try_recv().is_err(), "dropped request must not be relayed");
            assert!(actor.discovery_path_requests.is_empty());
        }
    }

    #[test]
    fn enforcement_accepts_a_valid_stamp_and_relays_it_unchanged() {
        let (mut actor, _a, mut b) = actor_with_two_interfaces(true);
        actor.stamp_policy.enforce();
        let data = hex::decode(STAMPED_TAG_1).unwrap();
        actor.handle_inbound_path_request(&data, 1);
        assert_eq!(received(&actor, 1), 1);
        assert_eq!(violations(&actor, 1), 0);
        let mut expected = data.clone();
        expected[16..32].copy_from_slice(&[0x42; 16]);
        assert_eq!(payload(&b.try_recv().expect("relayed")), expected);
    }

    #[test]
    fn receiving_interface_pr_cost_decides_validity() {
        let data = hex::decode(STAMPED_TAG_1).unwrap();
        for (cost, accepted) in [(Some(20.0), false), (Some(17.0), true), (None, true)] {
            let (mut actor, _a, _b) = actor_with_two_interfaces(true);
            actor.stamp_policy.enforce();
            actor.stamp_policy.pr_cost = 30.0;
            actor.interfaces.get_mut(&1).unwrap().pr_cost = cost;
            if cost.is_none() {
                actor.stamp_policy.pr_cost = 15.8;
            }
            actor.handle_inbound_path_request(&data, 1);
            assert_eq!(received(&actor, 1), u64::from(accepted), "cost {cost:?}");
        }
    }

    #[test]
    fn without_enforcement_unstamped_requests_are_counted_and_relayed_as_received() {
        let (mut actor, _a, mut b) = actor_with_two_interfaces(true);
        let data = hex::decode(STAMPED_TAG_1).unwrap()[..PR_LENGTH].to_vec();
        actor.handle_inbound_path_request(&data, 1);
        assert_eq!(received(&actor, 1), 1);
        assert_eq!(payload(&b.try_recv().expect("relayed")).len(), PR_LENGTH);
    }

    #[test]
    fn a_stamping_transport_relays_unstamped_requests_with_the_lenient_marker() {
        let (mut actor, _a, mut b) = actor_with_two_interfaces(true);
        actor.stamp_policy.stamp_prs = true;
        let data = hex::decode(STAMPED_TAG_1).unwrap()[..PR_LENGTH].to_vec();
        actor.handle_inbound_path_request(&data, 1);
        let relayed = payload(&b.try_recv().expect("relayed without waiting for a stamp"));
        assert_eq!(relayed.len(), PR_STAMPED_LENGTH);
        assert_eq!(&relayed[32..48], &data[32..48]);
        assert_eq!(&relayed[48..], &LENIENT_PATH_REQUEST_EXT[..]);
        assert!(actor.pr_stamper.cache_len() == 0);
    }

    #[test]
    fn unstamped_emission_carries_the_transport_id_on_a_leaf() {
        let (mut actor, mut a, _b) = actor_with_two_interfaces(false);
        actor.on_path_request([0x77; 16]);
        let sent = payload(&a.try_recv().expect("sent"));
        assert_eq!(sent.len(), PR_LENGTH);
        assert_eq!(&sent[16..32], &[0x42; 16]);
    }

    #[test]
    fn stamped_emission_waits_for_the_stamper_then_uses_the_cached_stamp() {
        let (mut actor, mut a, _b) = actor_with_two_interfaces(false);
        actor.stamp_policy.stamp_prs = true;
        actor.stamp_policy.pr_value = 4.0;
        let dest = [0x77; 16];
        let tag = [0x55; 16];
        actor.forward_path_request(dest, None, Some(&tag), false);
        assert!(
            a.try_recv().is_err(),
            "nothing is sent before the stamp exists"
        );
        assert!(actor.path_requests.contains_key(&dest));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let result = rt
            .block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(20),
                    actor.pr_stamper.next_result(),
                )
                .await
            })
            .unwrap()
            .unwrap();
        actor.on_path_request_stamp_ready(result);
        let sent = payload(&a.try_recv().expect("stamped request sent"));
        assert_eq!(sent.len(), PR_STAMPED_LENGTH);
        assert_eq!(&sent[32..48], &tag);
        assert_eq!(&sent[48..50], &[0xC1, 0x00]);
        assert!(path_request_stamp_valid(&dest, &tag, &sent[50..], 4.0));
        // A second request with the same tag reuses the cached stamp at once.
        actor.send_path_request(dest, 1, Some(&tag), false);
        assert_eq!(payload(&a.try_recv().expect("sent from cache")), sent);
    }

    #[test]
    fn stamp_generation_failure_sends_nothing() {
        let (mut actor, mut a, _b) = actor_with_two_interfaces(false);
        actor.on_path_request_stamp_ready(crate::pr_stamper::PathRequestStampResult {
            job: crate::pr_stamper::PathRequestStampJob {
                destination_hash: [0x77; 16],
                tag: vec![0x55; 16],
                target: crate::pr_stamper::PathRequestTarget::AllExcept(None),
                recursive: false,
                value: 15.8,
                timeout: 15.0,
            },
            stamp: None,
        });
        assert!(a.try_recv().is_err());
    }
}
