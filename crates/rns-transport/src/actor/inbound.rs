use super::*;
use crate::announce_validation::{CachedAnnounce, InvalidAnnounce, ValidatedAnnounce};
use crate::now_f64;

/// Where an inbound packet comes from. Python re-injects held announces and
/// cached packets with `ifac_handled=True` (Interface.py:296, Transport.py:3460),
/// and its byte counters live in the interface drivers, so neither passes
/// IFAC or counts as received traffic again.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InboundOrigin {
    Wire,
    HeldAnnounce,
    CachedPacket,
}

/// A transit link proof's verdict; only a bad signature is a protocol
/// violation (Transport.py:2668).
#[derive(PartialEq, Eq)]
enum TransitProof {
    Valid,
    InvalidSignature,
    Refused,
}

/// The app_data upstream remembers: `b""` for a ratchet announce with nothing
/// after the signature, since its `None` threshold ignores the ratchet
/// (Identity.py:815-834), and `None` once a valid stamp strip leaves nothing (:867).
pub(super) fn remembered_app_data(
    announce: &rns_identity::announce::AnnounceData,
    stamp: &rns_identity::announce::AnnounceStampCheck,
) -> Option<Vec<u8>> {
    match announce.app_data.as_deref() {
        None if announce.ratchet.is_some() => Some(Vec::new()),
        raw => stamp.app_data(raw).map(<[u8]>::to_vec),
    }
}

impl TransportActor {
    #[tracing::instrument(
        level = "trace",
        name = "actor.on_inbound",
        skip_all,
        fields(interface_id = packet.interface_id, raw_len = packet.raw.len()),
    )]
    pub(super) fn on_inbound(&mut self, packet: crate::messages::InboundPacket) {
        self.on_inbound_inner(packet, InboundOrigin::Wire);
    }

    /// An announce the ingress controller held, released for processing; it
    /// can be held again (Interface.py:278-297).
    pub(super) fn on_released_announce(&mut self, announce: crate::ingress::HeldAnnounce) {
        self.on_inbound_inner(
            crate::messages::InboundPacket {
                raw: announce.raw,
                interface_id: announce.receiving_interface_id,
                rssi: None,
                snr: None,
                q: None,
            },
            InboundOrigin::HeldAnnounce,
        );
    }

    /// Python `Interface.protocol_violation`, `ifac_violation` and
    /// `packet_filter_hit` (Interface.py:327-338).
    pub(super) fn protocol_violation(&mut self, interface_id: InterfaceId) {
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            entry.protocol_violations = entry.protocol_violations.saturating_add(1);
        }
    }

    /// Upstream drops stamp and blackhole rejections silently; anything else
    /// is a protocol violation (Transport.py:2046-2051, :2450-2451).
    fn reject_announce(
        &mut self,
        header: &rns_wire::header::PacketHeader,
        interface_id: InterfaceId,
        packet_hash: [u8; 32],
        reason: InvalidAnnounce,
        cache: bool,
    ) {
        if cache {
            self.announce_validation.insert_invalid(packet_hash, reason);
        }
        trace!(
            dest = hex::encode(header.destination_hash),
            ?reason,
            "announce rejected"
        );
        if reason == InvalidAnnounce::Invalid {
            self.protocol_violation(interface_id);
        }
    }

    /// Python `Interface.destination_cost`, or the global without an interface.
    pub(super) fn interface_destination_cost(&self, interface_id: InterfaceId) -> f64 {
        self.stamp_policy.interface_destination_cost(
            self.interfaces
                .get(&interface_id)
                .and_then(|entry| entry.destination_cost),
        )
    }

    /// Python `Interface.pr_cost`, or the global without an interface.
    pub(super) fn interface_pr_cost(&self, interface_id: InterfaceId) -> f64 {
        self.stamp_policy.interface_pr_cost(
            self.interfaces
                .get(&interface_id)
                .and_then(|entry| entry.pr_cost),
        )
    }

    fn ifac_violation(&mut self, interface_id: InterfaceId) {
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            entry.ifac_violations = entry.ifac_violations.saturating_add(1);
        }
    }

    fn packet_filter_hit(&mut self, interface_id: InterfaceId) {
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            entry.packet_filter_hits = entry.packet_filter_hits.saturating_add(1);
        }
    }

    /// Python `Transport.inbound(cached.raw, cached.receiving_interface)`
    /// for a locally cached packet; a sent packet has no receiving interface.
    pub(super) fn replay_cached_packet(&mut self, raw: Bytes) {
        if raw.len() > 500 {
            return;
        }
        self.on_inbound_inner(
            crate::messages::InboundPacket {
                raw,
                interface_id: 0,
                rssi: None,
                snr: None,
                q: None,
            },
            InboundOrigin::CachedPacket,
        );
    }

    fn on_inbound_inner(&mut self, packet: crate::messages::InboundPacket, origin: InboundOrigin) {
        if origin == InboundOrigin::Wire {
            self.traffic
                .record_rx(packet.interface_id, packet.raw.len() as u64);
        }

        // Transport.py:1990-2010: frames of two bytes or less are protocol
        // violations before any IFAC handling.
        if packet.raw.len() <= 2 {
            self.protocol_violation(packet.interface_id);
            return;
        }
        // Upstream bounds the frame only after IFAC (Transport.py:2014,
        // HW_MTU + ifac_size, the default IFAC size without IFAC).
        let clear_limit = if origin == InboundOrigin::CachedPacket {
            500
        } else {
            let Some(entry) = self.interfaces.get(&packet.interface_id) else {
                return;
            };
            if !entry.owner.is_current() {
                return;
            }
            if entry.effective_clear_mtu().is_err() {
                return;
            }
            let limit = entry.packet_capacity.max_wire_packet_bytes as usize + entry.ifac_size;
            // Allocation guard before IFAC unmasks a copy; drivers deframe far below it.
            if packet.raw.len() > 2 * limit {
                self.protocol_violation(packet.interface_id);
                return;
            }
            limit
        };

        // Strip the IFAC tag if the interface gates membership on one; packets
        // that fail verification are dropped so a misconfigured peer can't
        // leak into a closed access group.
        let ifac = if origin != InboundOrigin::Wire {
            None
        } else {
            self.interfaces
                .get(&packet.interface_id)
                .map(|entry| (entry.ifac_key.clone(), entry.ifac_size))
        };
        let raw: bytes::Bytes = match ifac {
            Some((Some(ifac_key), ifac_size)) => {
                match crate::ifac::ifac_verify(&packet.raw, &ifac_key, ifac_size) {
                    Some(stripped) => bytes::Bytes::from(stripped),
                    None => {
                        trace!(
                            interface_id = packet.interface_id,
                            "IFAC verification failed, dropping packet"
                        );
                        self.ifac_violation(packet.interface_id);
                        return;
                    }
                }
            }
            Some((None, _)) if crate::ifac::has_ifac_flag(&packet.raw) => {
                trace!(
                    interface_id = packet.interface_id,
                    "IFAC packet received on clear interface, dropping packet"
                );
                self.ifac_violation(packet.interface_id);
                return;
            }
            _ => packet.raw.clone(),
        };

        if raw.len() > clear_limit {
            self.protocol_violation(packet.interface_id);
            return;
        }

        let (mut parsed, data_offset) = match rns_wire::header::PacketHeader::unpack(&raw) {
            Ok((header, offset)) => (header, offset),
            Err(e) => {
                tracing::warn!(
                    interface_id = packet.interface_id,
                    raw_len = raw.len(),
                    first_byte = format!("0x{:02x}", raw.first().copied().unwrap_or(0)),
                    error = %e,
                    "inbound packet dropped: header parse failed"
                );
                self.protocol_violation(packet.interface_id);
                return;
            }
        };

        // Python 1.3.8 Packet.py:247-248: unpack() rejects on-wire hop counts
        // >= PATHFINDER_M for every packet type. Checked on the RAW hops byte,
        // before the inbound hop adjustment; kept at the inbound boundary so
        // locally built packets and vector tooling are unaffected.
        if parsed.hops >= PATHFINDER_M {
            debug!(
                hops = parsed.hops,
                interface_id = packet.interface_id,
                "inbound packet dropped: invalid hop count"
            );
            self.protocol_violation(packet.interface_id);
            return;
        }

        // Packet.unpack rejects a zero-length data field (Packet.py:275).
        if data_offset >= raw.len() {
            debug!(
                interface_id = packet.interface_id,
                "inbound packet dropped: zero-length data field"
            );
            self.protocol_violation(packet.interface_id);
            return;
        }

        // Transport.HOP_LIMITER, on wire hops (Transport.py:2022).
        if parsed.hops >= self.hop_limiter {
            trace!(
                hops = parsed.hops,
                interface_id = packet.interface_id,
                "inbound packet dropped by hop limiter"
            );
            return;
        }

        // The canonical packet hash excludes the next-hop transport address
        // and survives final-hop H2-to-H1 rewriting. An overheard packet for
        // another transport must therefore not enter our accepted hashlist:
        // its later, correctly routed copy has exactly the same hash. Keep
        // this admission before repeat-context and known-Link exceptions too.
        // Only ingress from our attached shared owner delegates this filter;
        // a local client or an unrelated radio is not that trust boundary.
        let from_shared_owner =
            self.is_shared_instance && self.is_shared_instance_peer_interface(packet.interface_id);
        if parsed.flags.packet_type != rns_wire::flags::PacketType::Announce
            && parsed.transport_id.is_some()
            && parsed.transport_id != self.transport_identity_hash
            && !from_shared_owner
        {
            trace!(
                interface_id = packet.interface_id,
                "packet for another transport dropped before hash admission"
            );
            self.packet_filter_hit(packet.interface_id);
            return;
        }

        // A handful of contexts legitimately repeat (keepalives, resource
        // transfer frames, channel traffic): they bypass Python's packet
        // filter and the hashlist (Transport.py:1635-1640).
        let skip_hashlist = matches!(
            parsed.context,
            rns_wire::context::PacketContext::Keepalive
                | rns_wire::context::PacketContext::Resource
                | rns_wire::context::PacketContext::ResourceReq
                | rns_wire::context::PacketContext::ResourcePrf
                | rns_wire::context::PacketContext::CacheRequest
                | rns_wire::context::PacketContext::Channel
        );

        // PLAIN and GROUP packets travel one hop at most and are never
        // announced (Transport.py:1642-1666). Checked on wire hops before
        // the hashlist, so a dropped copy reserves no hash; the shared
        // owner already filtered its ingress (:1627).
        if !skip_hashlist
            && !from_shared_owner
            && matches!(
                parsed.flags.destination_type,
                rns_wire::flags::DestinationType::Plain | rns_wire::flags::DestinationType::Group
            )
            && (parsed.flags.packet_type == rns_wire::flags::PacketType::Announce
                || parsed.hops > 1)
        {
            debug!(
                interface_id = packet.interface_id,
                hops = parsed.hops,
                destination_type = ?parsed.flags.destination_type,
                packet_type = ?parsed.flags.packet_type,
                "PLAIN or GROUP packet filtered"
            );
            self.packet_filter_hit(packet.interface_id);
            return;
        }

        // A malformed request must not reserve a hash or reach a destination.
        if parsed.flags.packet_type == rns_wire::flags::PacketType::LinkRequest {
            let Ok(signal) =
                rns_wire::link_signalling::parse_request_signalling(&raw[data_offset..])
            else {
                return;
            };
            let Some(ingress) = self.interfaces.get(&packet.interface_id) else {
                return;
            };
            // A relay has no capacity refusal (Transport.py:2331-2375).
            if self.local_destinations.contains(&parsed.destination_hash)
                && ingress
                    .packet_capacity
                    .link_ceiling(packet.interface_id, ingress.active_ifac_bytes())
                    .is_err()
            {
                return;
            }
            if self.local_destinations.contains(&parsed.destination_hash)
                && signal.mode != rns_wire::link_signalling::DEFAULT_LINK_MODE
            {
                return;
            }
        }

        // Dedup via the packet hashlist.
        let pkt_hash = rns_wire::hash::packet_hash(&raw, parsed.flags.header_type);
        let packet_metrics = PacketMetrics {
            rssi: packet.rssi,
            snr: packet.snr,
            q: packet.q,
        };
        self.record_interface_signal(packet.interface_id, packet_metrics);

        // On shared media (e.g. LoRa) we overhear our own forwards and link
        // traffic; if we dedup against that, legitimate copies disappear.
        // Defer the hashlist check for packets owned by the link table or
        // carrying link-proof context.
        // A LinkRequest has not reserved anything until its exact LinkID is
        // admitted. Queue/capacity refusals must leave an identical retry usable;
        // the pending/established Link table already suppresses owned requests.
        let defer_hashlist = self.link_table.contains(&parsed.destination_hash)
            || parsed.flags.packet_type == rns_wire::flags::PacketType::LinkRequest
            || parsed.context == rns_wire::context::PacketContext::Lrproof;

        let check_hashlist = !skip_hashlist && !defer_hashlist;
        if check_hashlist && self.packet_hashlist.contains(&pkt_hash) {
            // SINGLE announces are retransmitted to refresh paths, so an
            // exact duplicate is expected and must not be dropped.
            if parsed.flags.packet_type == rns_wire::flags::PacketType::Announce
                && parsed.flags.destination_type == rns_wire::flags::DestinationType::Single
            {
            } else {
                trace!("duplicate packet dropped");
                self.packet_filter_hit(packet.interface_id);
                return;
            }
        }

        if origin != InboundOrigin::CachedPacket {
            self.count_rx_packet();
        }

        // Destination-type filtering runs after the packet filter and before
        // the hash is remembered (Transport.py:2030-2041, :2235).
        if parsed.flags.packet_type == rns_wire::flags::PacketType::Announce
            && !self.admit_announce_type(&raw[data_offset..], parsed.hops, packet.interface_id)
        {
            return;
        }
        // Transport.py:2044: announce frames above the base MTU.
        if parsed.flags.packet_type == rns_wire::flags::PacketType::Announce
            && raw.len() > rns_wire::constants::MTU
        {
            self.protocol_violation(packet.interface_id);
            return;
        }

        if check_hashlist {
            self.packet_hashlist.insert(pkt_hash);
        }
        // Python records PHY stats in `_inbound`, after the packet filter (Transport.py:2192-2209).
        self.record_packet_metrics(pkt_hash, packet_metrics);

        parsed.hops = self.adjusted_inbound_hops(parsed.hops, packet.interface_id);

        tracing::debug!(
            pkt_type = ?parsed.flags.packet_type,
            dest = %hex::encode(parsed.destination_hash),
            hops = parsed.hops,
            interface_id = packet.interface_id,
            raw_len = raw.len(),
            "inbound packet received"
        );

        match parsed.flags.packet_type {
            rns_wire::flags::PacketType::Announce => {
                self.process_announce(&raw, &parsed, data_offset, packet.interface_id);
            }
            rns_wire::flags::PacketType::LinkRequest => {
                self.process_link_request(&raw, &parsed, packet.interface_id, packet_metrics);
            }
            rns_wire::flags::PacketType::Proof => {
                self.process_proof(&raw, &parsed, packet.interface_id, packet_metrics);
            }
            rns_wire::flags::PacketType::Data => {
                self.process_data(&raw, &parsed, packet.interface_id, packet_metrics);
            }
        }
    }

    /// Python's announce ingress filter: a short name hash is a protocol
    /// violation, blocked and unrequired types are dropped silently.
    fn admit_announce_type(
        &mut self,
        payload: &[u8],
        wire_hops: u8,
        interface_id: InterfaceId,
    ) -> bool {
        use crate::destination_filter::{AnnounceSource, NAME_HASH_LEN, NameHash};
        const KEYSIZE: usize = 64;
        let Some(name_hash) = payload
            .get(KEYSIZE..KEYSIZE + NAME_HASH_LEN)
            .and_then(|bytes| NameHash::try_from(bytes).ok())
        else {
            debug!(
                interface_id,
                size = payload.len(),
                "malformed announce packet"
            );
            self.protocol_violation(interface_id);
            return false;
        };
        let source = if self.is_local_client_interface(interface_id) {
            AnnounceSource::LocalClient
        } else if self.is_shared_instance_peer_interface(interface_id) {
            AnnounceSource::SharedInstance
        } else {
            AnnounceSource::Other
        };
        let admitted = self
            .destination_filter
            .admits(&name_hash, source, wire_hops);
        if !admitted {
            trace!(
                interface_id,
                destination_type = self.destination_filter.type_name(&name_hash),
                "announce dropped by destination type filter"
            );
        }
        admitted
    }

    fn process_announce(
        &mut self,
        raw: &[u8],
        header: &rns_wire::header::PacketHeader,
        data_offset: usize,
        interface_id: InterfaceId,
    ) {
        let is_from_local_client = self.is_local_client_interface(interface_id);

        if data_offset >= raw.len() {
            tracing::warn!(
                dest = hex::encode(header.destination_hash),
                "announce missing payload, dropping"
            );
            self.protocol_violation(interface_id);
            return;
        }
        let payload = &raw[data_offset..];
        let has_ratchet = header.flags.context_flag;
        let announce_data = match rns_identity::announce::AnnounceData::unpack(payload, has_ratchet)
        {
            Ok(announce_data) => announce_data,
            Err(e) => {
                tracing::warn!(
                    dest = hex::encode(header.destination_hash),
                    payload_len = payload.len(),
                    has_ratchet = has_ratchet,
                    error = %e,
                    "announce unpack failed, dropping"
                );
                self.protocol_violation(interface_id);
                return;
            }
        };

        // Identity.validate_announce (Identity.py:749-889): the cache, then
        // the stamp, then the blackhole check, then the signature.
        let announce_packet_hash = rns_wire::hash::packet_hash(raw, header.flags.header_type);
        let stamps_enabled = self.stamp_policy.stamps_enabled;
        let stamps_enforced = stamps_enabled && self.stamp_policy.stamps_enforced;
        let cost_target = self.interface_destination_cost(interface_id);
        let cached =
            self.announce_validation
                .lookup(&announce_packet_hash, cost_target, stamps_enforced);
        let (validated, validated_identity, cache_hit) = match cached {
            CachedAnnounce::Rejected(reason) => {
                self.reject_announce(header, interface_id, announce_packet_hash, reason, false);
                return;
            }
            CachedAnnounce::Valid(validated) => (validated, None, true),
            CachedAnnounce::Miss => {
                let stamp = if stamps_enabled {
                    announce_data.check_stamp(&header.destination_hash, cost_target)
                } else {
                    rns_identity::announce::AnnounceStampCheck::default()
                };
                if stamps_enforced {
                    let reason = if !stamp.stamped {
                        Some(InvalidAnnounce::NoStamp)
                    } else if !stamp.validated {
                        Some(InvalidAnnounce::InvalidStamp(stamp.value))
                    } else {
                        None
                    };
                    if let Some(reason) = reason {
                        self.reject_announce(
                            header,
                            interface_id,
                            announce_packet_hash,
                            reason,
                            true,
                        );
                        return;
                    }
                }
                let Ok(announced_identity) =
                    rns_identity::identity::Identity::from_public_key(&announce_data.public_key)
                else {
                    self.reject_announce(
                        header,
                        interface_id,
                        announce_packet_hash,
                        InvalidAnnounce::Invalid,
                        true,
                    );
                    return;
                };
                if self.blackhole_table.is_blackholed(&announced_identity.hash) {
                    self.reject_announce(
                        header,
                        interface_id,
                        announce_packet_hash,
                        InvalidAnnounce::Blackholed,
                        true,
                    );
                    return;
                }
                let validated_identity =
                    match announce_data.verify_signature(&header.destination_hash) {
                        Ok(identity) => identity,
                        Err(e) => {
                            tracing::warn!(
                                dest = hex::encode(header.destination_hash),
                                payload_len = payload.len(),
                                error = %e,
                                "announce validation failed, dropping"
                            );
                            self.reject_announce(
                                header,
                                interface_id,
                                announce_packet_hash,
                                InvalidAnnounce::Invalid,
                                true,
                            );
                            return;
                        }
                    };
                let validated = ValidatedAnnounce {
                    public_key: announce_data.public_key,
                    identity_hash: validated_identity.hash,
                    app_data: remembered_app_data(&announce_data, &stamp),
                    ratchet: announce_data.ratchet,
                    stamp: stamp.stamp,
                    stamp_value: stamp.value,
                    lr_cost: stamp.lr_cost,
                };
                (validated, Some(validated_identity), false)
            }
        };

        // Python validates the announce signature before ingress accounting,
        // and only holds still-unknown destinations. Known re-announces and
        // path responses for paths we already know must continue refreshing
        // route state during an ingress burst.
        let announced_destination_known = self.path_table.get(&header.destination_hash).is_some();
        let answers_path_request = self.path_requests.contains_key(&header.destination_hash)
            || self
                .discovery_path_requests
                .get(&header.destination_hash)
                .is_some_and(|request| now_f64() < request.timeout);
        self.record_interface_event(interface_id, InterfaceEvent::ReceivedAnnounce, raw.len());
        self.count_transport_event(InterfaceEvent::ReceivedAnnounce);
        if let Some(entry) = self.interfaces.get_mut(&interface_id)
            && !is_from_local_client
            && !announced_destination_known
            && !answers_path_request
            && entry.ingress.should_ingress_limit()
        {
            entry.ingress.hold_announce(crate::ingress::HeldAnnounce {
                raw: bytes::Bytes::copy_from_slice(raw),
                destination_hash: header.destination_hash,
                hops: header.hops,
                receiving_interface_id: interface_id,
            });
            debug!(
                dest = hex::encode(header.destination_hash),
                interface = interface_id,
                "announce held by ingress controller (burst active)"
            );
            return;
        }

        if let Some(validated_identity) = validated_identity.as_ref() {
            let known_public_key = self
                .recent_announces
                .get(&header.destination_hash)
                .and_then(|entry| entry.public_key);
            if let Err(e) = announce_data.validate_destination_binding(
                &header.destination_hash,
                validated_identity,
                known_public_key.as_ref(),
            ) {
                tracing::warn!(
                    dest = hex::encode(header.destination_hash),
                    error = %e,
                    "announce validation failed, dropping"
                );
                self.reject_announce(
                    header,
                    interface_id,
                    announce_packet_hash,
                    InvalidAnnounce::Invalid,
                    true,
                );
                return;
            }
        }

        tracing::debug!(
            dest = hex::encode(header.destination_hash),
            app_data_present = validated.app_data.is_some(),
            stamp_value = ?validated.stamp_value,
            cache_hit,
            "announce validated"
        );
        if !cache_hit {
            self.announce_validation
                .insert_valid(announce_packet_hash, validated.clone());
        }

        let announce_app_data = validated.app_data.clone();
        let announce_public_key = Some(validated.public_key);
        let announce_ratchet = announce_data.ratchet;
        let announce_name_hash = announce_data.name_hash;
        let announce_identity_hash = Some(validated.identity_hash);
        let announce_random_hash = announce_data.random_hash;
        let announce_stamp_value = validated.stamp_value.unwrap_or(0.0);

        // Python remembers every freshly validated announce, replays included,
        // before it decides whether the path changes; a validation-cache hit
        // only re-remembers a destination that was forgotten
        // (Identity.py:109-126, :717-727).
        match self.recent_announces.entry(header.destination_hash) {
            std::collections::hash_map::Entry::Occupied(mut o) if !cache_hit => {
                let e = o.get_mut();
                e.timestamp = now_f64();
                e.public_key = announce_public_key;
                e.app_data = announce_app_data.clone();
                e.remember_ratchet(announce_ratchet, now_f64());
                e.stamp = validated.stamp;
                e.stamp_value = announce_stamp_value;
                e.lr_cost = validated.lr_cost;
            }
            std::collections::hash_map::Entry::Occupied(_) => {}
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(RecentAnnounce {
                    dest_hash: header.destination_hash,
                    hops: header.hops,
                    app_data: announce_app_data.clone(),
                    timestamp: now_f64(),
                    public_key: announce_public_key,
                    ratchet: announce_ratchet,
                    ratchet_received: announce_ratchet.map(|_| now_f64()),
                    packet_hash: None,
                    is_path_response: header.context
                        == rns_wire::context::PacketContext::PathResponse,
                    retained: false,
                    last_used: None,
                    name_hash: announce_name_hash,
                    stamp: validated.stamp,
                    stamp_value: announce_stamp_value,
                    lr_cost: validated.lr_cost,
                });
                self.state_dirty = true;
            }
        }

        // Own announces are validated and remembered but route nothing (Transport.py:2453-2454).
        if self.local_destinations.contains(&header.destination_hash) {
            debug!("not routing own announce");
            return;
        }

        if header.hops >= PATHFINDER_M {
            debug!(hops = header.hops, "announce exceeded hop limit");
            return;
        }

        let iface_mode = self
            .interfaces
            .get(&interface_id)
            .map(|e| e.mode)
            .unwrap_or(InterfaceMode::Gateway);

        let announce_emitted = announce_timebase(&announce_random_hash);

        // Cancel our queued rebroadcast when a neighbor already carried it.
        // Same-hop neighbor rebroadcast counts toward the local cap;
        // strict hops+1 forward drops our queued copy outright.
        // Only HEADER_2 copies come from a rebroadcasting transport node
        // (Transport.py:2454); copies heard before our first send count too.
        if self.is_transport_enabled
            && header.transport_id.is_some()
            && let Some(existing) = self.announce_table.get(&header.destination_hash)
        {
            let existing_hops = existing.hops;
            let existing_retries = existing.retries;
            if header.hops > 0 && header.hops - 1 == existing_hops {
                let existing_local_rebroadcasts = existing.local_rebroadcasts + 1;
                if existing_retries > 0 && existing_local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
                    trace!(
                        dest = hex::encode(header.destination_hash),
                        "announce dedup: local rebroadcast limit reached, removing from table"
                    );
                    self.announce_table.remove(&header.destination_hash);
                } else if let Some(ae) = self.announce_table.get_mut(&header.destination_hash) {
                    ae.local_rebroadcasts = existing_local_rebroadcasts;
                }
            }
            if header.hops > 0 && header.hops - 1 == existing_hops + 1 && existing_retries > 0 {
                let now = now_f64();
                if let Some(ae) = self.announce_table.get(&header.destination_hash)
                    && now < ae.retransmit_timeout
                {
                    trace!(
                        dest = hex::encode(header.destination_hash),
                        "announce dedup: passed on by another node, cancelling rebroadcast"
                    );
                    self.announce_table.remove(&header.destination_hash);
                }
            }
        }

        let mut random_blobs = self
            .path_table
            .get(&header.destination_hash)
            .map(|entry| entry.random_blobs.clone())
            .unwrap_or_default();
        let suppressed =
            self.is_path_interface_suppressed(header.destination_hash, interface_id, now_f64());
        let should_add = if suppressed {
            false
        } else if let Some(existing) = self.path_table.get(&header.destination_hash) {
            let random_seen = existing.has_random_blob(&announce_random_hash);
            let path_timebase = path_timebase_from_random_blobs(existing.random_blobs.iter());
            if header.hops <= existing.hops {
                if !random_seen && announce_emitted > path_timebase {
                    true
                } else if announce_emitted != path_timebase {
                    false
                } else {
                    // Transport.py:2522-2532: the same emission heard on a
                    // higher-gravity interface replaces the path.
                    let gravity = |id| self.interfaces.get(&id).map(|entry| entry.gravity);
                    matches!(
                        (gravity(interface_id), gravity(existing.interface_id)),
                        (Some(announce), Some(current)) if announce > current
                    )
                }
            } else if existing.is_expired() || announce_emitted > path_timebase {
                !random_seen
            } else if announce_emitted == path_timebase {
                self.path_table.get_state(&header.destination_hash)
                    == crate::constants::PathState::Unresponsive
            } else {
                false
            }
        } else {
            true
        };

        if should_add {
            // Only path-updating announces on interfaces with a rate target
            // touch the rate table (Transport.py:2578-2591).
            let rate_limit = (header.context != rns_wire::context::PacketContext::PathResponse)
                .then(|| self.interfaces.get(&interface_id))
                .flatten()
                .and_then(|entry| {
                    entry.announce_rate_target.map(|target| {
                        (
                            target,
                            entry.announce_rate_grace.unwrap_or(0),
                            entry.announce_rate_penalty.unwrap_or(0.0),
                        )
                    })
                });
            let rate_blocked = rate_limit.is_some_and(|(target, grace, penalty)| {
                self.rate_table.check_interface_rate(
                    header.destination_hash,
                    target,
                    grace,
                    penalty,
                )
            });
            if rate_blocked {
                pathing!(
                    dest = hex::encode(header.destination_hash),
                    interface = interface_id,
                    "announce blocked by per-interface rate limit"
                );
            }

            // Announce-table update MUST precede path-table update — the dedup
            // check above compares against our own queued copy. Non-transport
            // nodes never queue (would amplify the announce per hub).
            if !rate_blocked
                && (self.is_transport_enabled || is_from_local_client)
                && header.context != rns_wire::context::PacketContext::PathResponse
                && header.hops < PATHFINDER_M
            {
                let now = now_f64();
                let rebroadcast_raw = self.transport_announce_from_raw(
                    raw,
                    header.destination_hash,
                    header.hops,
                    rns_wire::context::PacketContext::None,
                );
                let announce_entry = crate::announce::AnnounceEntry {
                    timestamp: now,
                    retransmit_timeout: if is_from_local_client {
                        now
                    } else {
                        now + rand_window()
                    },
                    retries: if is_from_local_client {
                        PATHFINDER_R
                    } else {
                        0
                    },
                    received_from: header.transport_id.unwrap_or(header.destination_hash),
                    hops: header.hops,
                    packet_raw: rebroadcast_raw,
                    local_rebroadcasts: 0,
                    block_rebroadcast: false,
                    attached_interface: None,
                    source_interface: Some(interface_id),
                };
                self.announce_table
                    .insert(header.destination_hash, announce_entry);
            }

            // For Header2 announces via a transport node, next_hop is the relay's
            // hash from transport_id; for Header1 announces the destination is
            // directly reachable and next_hop stays None.
            let mut entry = crate::path_table::PathEntry::new(
                header.transport_id,
                header.hops,
                interface_id,
                iface_mode,
            );
            // Transport.py:2510,2726@1.6.0: a replacement keeps the path's use.
            entry.used = self
                .path_table
                .get(&header.destination_hash)
                .map_or(0.0, |existing| existing.used);
            if !random_blobs.contains(&announce_random_hash) {
                if random_blobs.len() >= MAX_RANDOM_BLOBS {
                    random_blobs.pop_front();
                }
                random_blobs.push_back(announce_random_hash);
            }
            entry.random_blobs = random_blobs;
            // Store the announce packet hash so a later CacheRequest for this
            // destination can replay the exact announce bytes.
            let announce_packet_hash = rns_wire::hash::packet_hash(raw, header.flags.header_type);
            entry.packet_hash = Some(announce_packet_hash);
            if rate_blocked {
                // Rate-blocked announces update routing fields only, never
                // liveness, and create no entry (Transport.py:2712-2724).
                if let Some(existing) = self.path_table.get_mut(&header.destination_hash) {
                    existing.next_hop = entry.next_hop;
                    existing.hops = entry.hops;
                    existing.random_blobs = entry.random_blobs;
                    existing.interface_id = entry.interface_id;
                    existing.packet_hash = entry.packet_hash;
                    self.path_table.set_state(
                        header.destination_hash,
                        crate::constants::PathState::Unknown,
                    );
                }
            } else {
                let tunnel_path = crate::tunnel::TunnelPath {
                    timestamp: entry.timestamp,
                    next_hop: entry.next_hop,
                    hops: entry.hops,
                    expires: entry.expires,
                    random_blobs: entry.random_blobs.iter().copied().collect(),
                    packet_hash: entry.packet_hash,
                    used: entry.used,
                };
                self.path_table.insert(header.destination_hash, entry);
                if let Some(tunnel) = self.tunnel_table.get_mut_by_interface(interface_id) {
                    tunnel
                        .tunnel_paths
                        .insert(header.destination_hash, tunnel_path);
                    tunnel.expires = now_f64() + TUNNEL_TIMEOUT as f64;
                }
            }
            self.state_dirty = true;
            if self.path_requests.contains_key(&header.destination_hash) {
                self.use_destination(&header.destination_hash);
            }
            // Wake any callers waiting on a path for this destination.
            self.fire_path_waiters(&header.destination_hash);
            // Transport.py:2751-2754@1.6.0.
            self.inflight_path_requests.remove(&header.destination_hash);

            if self
                .discovery_path_requests
                .contains_key(&header.destination_hash)
                && let Some(response) = self.path_response_from_cached_announce(
                    raw,
                    header.destination_hash,
                    header.hops,
                )
            {
                self.finish_recursive_discovery(
                    header.destination_hash,
                    &response,
                    interface_id,
                    now_f64(),
                );
            }

            pathing!(
                dest = hex::encode(header.destination_hash),
                hops = header.hops,
                next_hop = ?header.transport_id.map(hex::encode),
                "path learned from announce"
            );
        } else {
            debug!(
                dest = hex::encode(header.destination_hash),
                hops = header.hops,
                announce_emitted,
                interface_id,
                suppressed,
                "ignoring replayed or stale announce"
            );
            return;
        }

        // The remembered announce takes this path's metadata (raw bytes go to
        // the disk announce cache below, Python `Transport.cache` parity).
        // `retained` pins survive re-announce so a fresh announce never
        // silently un-pins an RPC-retained destination. Swept by
        // `cleanup_known_destinations` (linger + 7-day eviction).
        let is_path_response = header.context == rns_wire::context::PacketContext::PathResponse;
        self.cache_announce_to_disk(&announce_packet_hash, raw, interface_id);
        if let Some(e) = self.recent_announces.get_mut(&header.destination_hash) {
            e.hops = header.hops;
            e.remember_ratchet(announce_ratchet, now_f64());
            e.packet_hash = Some(announce_packet_hash);
            e.is_path_response = is_path_response;
        }
        let app_data_for_handlers = announce_app_data;

        // The desiring interface is unused: the response rebroadcasts once
        // everywhere through the announce table (Transport.py:2626-2648).
        if is_from_local_client
            && header.context == rns_wire::context::PacketContext::PathResponse
            && self
                .pending_local_path_requests
                .remove(&header.destination_hash)
                .is_some()
        {
            let now = now_f64();
            let rebroadcast_raw = self.transport_announce_from_raw(
                raw,
                header.destination_hash,
                header.hops,
                rns_wire::context::PacketContext::None,
            );
            self.announce_table.insert(
                header.destination_hash,
                crate::announce::AnnounceEntry {
                    timestamp: now,
                    retransmit_timeout: now,
                    retries: PATHFINDER_R,
                    received_from: header.transport_id.unwrap_or(header.destination_hash),
                    hops: header.hops,
                    packet_raw: rebroadcast_raw,
                    local_rebroadcasts: 0,
                    block_rebroadcast: false,
                    attached_interface: None,
                    source_interface: Some(interface_id),
                },
            );
        }

        self.send_announce_to_local_clients(
            raw,
            header.destination_hash,
            header.hops,
            Some(interface_id),
            rns_wire::context::PacketContext::None,
        );

        // Aspect-filtered handler dispatch: for handlers with a non-None
        // `aspect_filter`, fire only when
        // `hash_from_name_and_identity(filter, identity_hash) == destination_hash`.
        // Without a validated identity, filtered handlers are skipped.
        if !self.announce_handlers.is_empty() {
            let handler_app_data = app_data_for_handlers;
            let is_path_response = header.context == rns_wire::context::PacketContext::PathResponse;
            for registration in &self.announce_handlers {
                if registration
                    .paused
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    continue;
                }
                if is_path_response && !registration.receive_path_responses {
                    continue;
                }
                if let Some(filter) = &registration.aspect_filter {
                    let Some(ref ih) = announce_identity_hash else {
                        continue;
                    };
                    let expected =
                        rns_identity::destination::Destination::hash_from_name_and_identity(
                            filter,
                            Some(ih),
                        );
                    if expected != header.destination_hash {
                        continue;
                    }
                }
                let send_result = registration
                    .tx
                    .try_send(crate::messages::AnnounceHandlerEvent {
                        destination_hash: header.destination_hash,
                        identity_hash: announce_identity_hash,
                        announce_packet_hash,
                        is_path_response,
                        hops: header.hops,
                        app_data: handler_app_data.clone(),
                        public_key: announce_public_key,
                        ratchet: announce_ratchet,
                        name_hash: announce_name_hash,
                    });
                if matches!(
                    send_result,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_))
                ) {
                    registration
                        .dropped_events
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            self.announce_handlers
                .retain(|registration| !registration.tx.is_closed());
        }
    }

    /// Well-known PLAIN destination hash for tunnel-synthesis announces.
    fn tunnel_synthesize_dest_hash() -> [u8; 16] {
        rns_identity::destination::Destination::hash_from_name_and_identity(
            "rnstransport.tunnel.synthesize",
            None,
        )
    }

    /// Well-known PLAIN destination hash for path-request packets.
    fn path_request_dest_hash() -> [u8; 16] {
        rns_identity::destination::Destination::hash_from_name_and_identity(
            "rnstransport.path.request",
            None,
        )
    }

    fn process_data(
        &mut self,
        raw: &bytes::Bytes,
        header: &rns_wire::header::PacketHeader,
        interface_id: InterfaceId,
        metrics: PacketMetrics,
    ) {
        let from_local_client = self.is_local_client_interface(interface_id);
        let for_local_client = self
            .path_table
            .get_live(&header.destination_hash)
            .is_some_and(|path| self.is_local_client_interface(path.interface_id));
        // Python 1.3.8 Transport.py:1550-1551: to_local_client also covers
        // proofs whose reverse entry came in from a local client.
        let proof_for_local_client = self
            .reverse_table
            .get(&header.destination_hash)
            .is_some_and(|entry| self.is_local_client_interface(entry.receiving_interface));
        let to_local_client = for_local_client || proof_for_local_client;

        let path_request_dest = Self::path_request_dest_hash();
        let tunnel_synth_dest = Self::tunnel_synthesize_dest_hash();
        let is_control_plain = header.destination_hash == path_request_dest
            || header.destination_hash == tunnel_synth_dest;

        if !is_control_plain
            && header.flags.destination_type == rns_wire::flags::DestinationType::Plain
            && header.flags.transport_type == rns_wire::flags::TransportType::Broadcast
        {
            if from_local_client {
                self.broadcast_on_interfaces(raw, Some(interface_id));
            } else {
                for id in self.local_client_interface_ids_except(Some(interface_id)) {
                    self.send_to_interface(id, raw);
                }
            }
        }

        if self.route_link_packet_via_link_table(raw, header, interface_id, "data") {
            return;
        }

        if header.destination_hash == path_request_dest {
            if let Some(payload_start) = self.data_payload_offset(raw, header) {
                let payload = &raw[payload_start..];
                self.handle_inbound_path_request_sized(payload, interface_id, raw.len());
            }
            return;
        }

        // Tunnel synthesis: install the tunnel, and replay its cached paths,
        // once the signature verifies (Transport.py:2788-2805).
        if header.destination_hash == tunnel_synth_dest {
            if let Some(payload_start) = self.data_payload_offset(raw, header) {
                match crate::tunnel::TunnelSynthesisData::unpack(&raw[payload_start..])
                    .filter(crate::tunnel::TunnelSynthesisData::is_signed)
                {
                    Some(synthesis) => {
                        let tunnel_id = synthesis.tunnel_id();
                        debug!(
                            tunnel_id = hex::encode(&tunnel_id[..16]),
                            interface_id, "tunnel synthesis request validated"
                        );
                        crate::tunnel::handle_tunnel(
                            &mut self.tunnel_table,
                            tunnel_id,
                            interface_id,
                        );
                        self.state_dirty = true;
                        self.restore_tunnel_paths(&tunnel_id, interface_id);
                    }
                    // Wrong length or a bad signature is a silent drop
                    // (Transport.py:3067-3084).
                    None => debug!(interface_id, "invalid tunnel synthesis"),
                }
            }
            return;
        }

        if header.context == rns_wire::context::PacketContext::CacheRequest
            && self.handle_cache_request(
                raw,
                header,
                interface_id,
                self.is_transport_enabled || from_local_client || to_local_client,
            )
        {
            return;
        }

        tracing::debug!(
            dest = %hex::encode(header.destination_hash),
            is_local = self.local_destinations.contains(&header.destination_hash),
            has_channel = self.destination_channels.contains_key(&header.destination_hash),
            registered_dests = ?self.local_destinations.iter().map(hex::encode).collect::<Vec<_>>(),
            "data packet routing"
        );
        if self.local_destinations.contains(&header.destination_hash) {
            if self.link_packet_on_unbound_interface(header, interface_id) {
                // Transport.py:2858-2866: un-claim the hash so the copy arriving
                // over the Link's attached interface is still accepted.
                self.packet_hashlist
                    .remove(&rns_wire::hash::packet_hash(raw, header.flags.header_type));
                return;
            }
            if let Some(tx) = self.destination_channels.get(&header.destination_hash)
                && let Err(e) = tx.try_send(crate::link_messages::DestinationEvent::InboundPacket {
                    interface_owner: self
                        .interfaces
                        .get(&interface_id)
                        .map(|entry| entry.owner.id()),
                    raw: raw.clone(),
                    interface_id,
                    metrics,
                })
            {
                self.channel_drops += 1;
                warn!(dest = hex::encode(header.destination_hash), drops = self.channel_drops, err = %e,
                        "failed to deliver InboundPacket to local destination (channel full)");
            }
            return;
        }

        if let Some((target_interface, forwarded)) = self.transport_forward_candidate(
            raw,
            header,
            from_local_client,
            for_local_client,
            to_local_client,
        ) {
            let pkt_hash = rns_wire::hash::truncated_packet_hash(raw, header.flags.header_type);
            self.reverse_table.insert_with_outbound(
                pkt_hash,
                interface_id,
                header.hops,
                Some(target_interface),
            );
            self.send_to_interface(target_interface, &forwarded);
            if let Some(path) = self.path_table.get_live_mut(&header.destination_hash) {
                path.mark_used();
            }
            trace!(
                dest = hex::encode(header.destination_hash),
                via_interface = target_interface,
                "data packet forwarded"
            );
        }
    }

    fn process_link_request(
        &mut self,
        raw: &bytes::Bytes,
        header: &rns_wire::header::PacketHeader,
        interface_id: InterfaceId,
        metrics: PacketMetrics,
    ) {
        let from_local_client = self.is_local_client_interface(interface_id);
        let for_local_client = self
            .path_table
            .get_live(&header.destination_hash)
            .is_some_and(|path| self.is_local_client_interface(path.interface_id));
        let proof_for_local_client = self
            .reverse_table
            .get(&header.destination_hash)
            .is_some_and(|entry| self.is_local_client_interface(entry.receiving_interface));
        let to_local_client = for_local_client || proof_for_local_client;

        // on_inbound already established transport ownership (or the exact
        // attached shared-owner ingress). Exact LinkID ownership is committed
        // only after successful egress admission below.
        if self.local_destinations.contains(&header.destination_hash) {
            if let Some(tx) = self.destination_channels.get(&header.destination_hash)
                && let Err(e) = tx.try_send(crate::link_messages::DestinationEvent::LinkRequest {
                    interface_owner: self
                        .interfaces
                        .get(&interface_id)
                        .map(|entry| entry.owner.id()),
                    raw: raw.clone(),
                    interface_id,
                    metrics,
                })
            {
                self.channel_drops += 1;
                error!(dest = hex::encode(header.destination_hash), drops = self.channel_drops, err = %e,
                        "failed to deliver LinkRequest; link establishment will fail");
            }
            return;
        }

        if let Some((target_interface, mut forwarded)) = self.transport_forward_candidate(
            raw,
            header,
            from_local_client,
            for_local_client,
            to_local_client,
        ) {
            let Some(path) = self.path_table.get_live(&header.destination_hash) else {
                return;
            };
            let remaining_hops = path.hops;
            let next_hop = path.next_hop;
            let link_id = rns_wire::hash::link_id_from_raw(raw, header.flags.header_type);
            // Optional signalling is excluded from Link IDs but included in
            // packet hashes. Changing it cannot renew or downgrade the same
            // already-owned Link, even when ordinary packet dedup admits it.
            if self.link_table.contains(&link_id) {
                trace!("Link request already has a transport owner");
                return;
            }
            if self.link_table.len() >= crate::link_table::MAX_TRANSIT_LINK_TABLE_ENTRIES {
                debug!("transit Link table capacity exhausted; request not forwarded");
                return;
            }
            let Some(ingress) = self.interfaces.get(&interface_id) else {
                return;
            };
            let Some(egress) = self.interfaces.get(&target_interface) else {
                return;
            };
            let (payload, requested_mode, accepted_mtu_ceiling) =
                match crate::link_transit::attenuate_request(
                    &raw[header.size()..],
                    interface_id,
                    ingress,
                    target_interface,
                    egress,
                ) {
                    Ok(attenuated) => attenuated,
                    // Python cannot re-encode a clamped MTU for a disabled
                    // mode and counts it (Transport.py:2354-2361).
                    Err(crate::link_transit::LinkTransitError::UnsupportedTransitModeTransform) => {
                        self.protocol_violation(interface_id);
                        return;
                    }
                    Err(_) => return,
                };
            let interface_owner = Some(egress.owner.clone());
            let receiving_owner = Some(ingress.owner.clone());
            let Ok((forwarded_header, _)) = rns_wire::header::PacketHeader::unpack(&forwarded)
            else {
                return;
            };
            forwarded.truncate(forwarded_header.size());
            forwarded.extend_from_slice(&payload);
            let bitrate = self
                .interfaces
                .get(&target_interface)
                .filter(|entry| !interface_marked_offline(entry))
                .map(|entry| entry.bitrate);
            if !self.send_to_interface(target_interface, &forwarded) {
                return;
            }
            if let Some(path) = self.path_table.get_live_mut(&header.destination_hash) {
                path.mark_used();
            }

            // Cache the relay so the matching LRPROOF can be routed back to
            // the initiator without a fresh path lookup. The transport table
            // adds a bounded MTU round trip on this outbound medium to its
            // per-hop proof window; it never renews for unvalidated traffic.
            let now = now_f64();
            let proof_timeout =
                crate::link_table::transit_link_proof_deadline(now, remaining_hops, bitrate);
            let link_entry = crate::link_table::LinkEntry {
                timestamp: now,
                next_hop,
                interface_id: target_interface,
                remaining_hops,
                destination_hash: header.destination_hash,
                established: false,
                validated: false,
                proof_timeout,
                receiving_interface: interface_id,
                taken_hops: header.hops,
                interface_owner,
                receiving_owner,
                requested_mode,
                accepted_mtu_ceiling,
            };
            self.link_table.insert(link_id, link_entry);

            debug!(
                link_id = hex::encode(link_id),
                dest = hex::encode(header.destination_hash),
                receiving = interface_id,
                outbound = target_interface,
                remaining_hops,
                "link table relay entry created"
            );

            trace!(
                dest = hex::encode(header.destination_hash),
                via_interface = target_interface,
                "link request forwarded"
            );
        }
    }

    fn transport_forward_candidate(
        &self,
        raw: &[u8],
        header: &rns_wire::header::PacketHeader,
        from_local_client: bool,
        for_local_client: bool,
        to_local_client: bool,
    ) -> Option<(InterfaceId, Vec<u8>)> {
        let path = self.path_table.get_live(&header.destination_hash)?;

        let may_forward_for_shared_client = from_local_client || for_local_client;
        let addressed_to_us = header
            .transport_id
            .zip(self.transport_identity_hash)
            .is_some_and(|(packet_transport_id, our_transport_id)| {
                packet_transport_id == our_transport_id
            });

        // Upstream Transport only relays in-transport packets when the Header2
        // transport id names this instance. Shared-instance local-client edges
        // are the exception: they are allowed to use the local path cache even
        // when packets arrive without normal transport wrapping.
        if may_forward_for_shared_client && header.transport_id.is_some() && !addressed_to_us {
            return None;
        }

        if !may_forward_for_shared_client && (!self.is_transport_enabled || !addressed_to_us) {
            return None;
        }

        // One broadcast interface can reach multiple neighbors that cannot
        // hear each other. Once routing ownership is established, the next
        // hop may legitimately use the ingress radio. Deduplication and the
        // next-hop address, not interface inequality, prevent packet loops.
        let mut forwarded =
            self.rewrite_forwarded_transport_packet(raw, header, path, to_local_client)?;
        // Python 1.3.8 Transport.py:1687: substitute the delta for
        // local-client-originated packets leaving the shared instance.
        if self.local_hops_delta != 0 && from_local_client && !to_local_client {
            forwarded[1] = self.local_hops_delta;
        }
        Some((path.interface_id, forwarded))
    }

    fn rewrite_forwarded_transport_packet(
        &self,
        raw: &[u8],
        header: &rns_wire::header::PacketHeader,
        path: &crate::path_table::PathEntry,
        to_local_client: bool,
    ) -> Option<Vec<u8>> {
        let payload_offset = header.size();
        if raw.len() < payload_offset {
            return None;
        }

        if path.hops > 1 {
            let next_hop = path.next_hop?;
            let mut flags = header.flags;
            flags.header_type = rns_wire::flags::HeaderType::Header2;
            flags.transport_type = rns_wire::flags::TransportType::Transport;
            let new_header = rns_wire::header::PacketHeader {
                flags,
                hops: header.hops,
                transport_id: Some(next_hop),
                destination_hash: header.destination_hash,
                context: header.context,
            };
            let mut forwarded = new_header.pack();
            forwarded.extend_from_slice(&raw[payload_offset..]);
            Some(forwarded)
        } else if path.hops == 1
            || (to_local_client
                && self.local_hops_delta != 0
                && header.flags.header_type == rns_wire::flags::HeaderType::Header2)
        {
            // Python 1.3.8 Transport.py:1613-1619: with the delta active,
            // HEADER_2 frames delivered to local shared clients get their
            // transport headers stripped, same as the one-hop case.
            let mut flags = header.flags;
            flags.header_type = rns_wire::flags::HeaderType::Header1;
            flags.transport_type = rns_wire::flags::TransportType::Broadcast;
            let new_header = rns_wire::header::PacketHeader {
                flags,
                hops: header.hops,
                transport_id: None,
                destination_hash: header.destination_hash,
                context: header.context,
            };
            let mut forwarded = new_header.pack();
            forwarded.extend_from_slice(&raw[payload_offset..]);
            Some(forwarded)
        } else {
            let mut forwarded = raw.to_vec();
            if forwarded.len() >= 2 {
                forwarded[1] = header.hops;
            }
            Some(forwarded)
        }
    }

    fn process_proof(
        &mut self,
        raw: &bytes::Bytes,
        header: &rns_wire::header::PacketHeader,
        _interface_id: InterfaceId,
        metrics: PacketMetrics,
    ) {
        let from_local_client = self.is_local_client_interface(_interface_id);
        let for_local_client_link =
            self.link_table
                .get(&header.destination_hash)
                .is_some_and(|entry| {
                    self.is_local_client_interface(entry.receiving_interface)
                        || self.is_local_client_interface(entry.interface_id)
                });
        let proof_for_local_client = self
            .reverse_table
            .get(&header.destination_hash)
            .is_some_and(|entry| self.is_local_client_interface(entry.receiving_interface));

        if header.context != rns_wire::context::PacketContext::Lrproof
            && self.receipt_table.contains_key(&header.destination_hash)
        {
            let payload_offset = header.size();
            let Some(proof) = raw.get(payload_offset..) else {
                return;
            };

            // Python PacketReceipt retains the destination identity used for
            // the send and validates every explicit or implicit proof against
            // it. If registration preceded outbound binding, fill the key from
            // the validated announce cache before attempting verification.
            let destination_hash = self
                .receipt_table
                .get(&header.destination_hash)
                .and_then(|receipt| receipt.destination_hash);
            let recalled_public_key = destination_hash.and_then(|destination_hash| {
                self.recent_announces
                    .get(&destination_hash)
                    .and_then(|announce| announce.public_key)
            });
            let (validated, rtt) = {
                let receipt = self
                    .receipt_table
                    .get_mut(&header.destination_hash)
                    .expect("receipt existence checked above");
                if receipt.destination_public_key.is_none()
                    && let Some(destination_hash) = receipt.destination_hash
                {
                    receipt.set_destination_identity(destination_hash, recalled_public_key);
                }
                let validated = receipt.validate_proof_from_destination(proof);
                (validated, receipt.get_rtt())
            };

            if !validated {
                warn!(
                    trunc = %hex::encode(header.destination_hash),
                    proof_len = proof.len(),
                    identity_known = recalled_public_key.is_some(),
                    "invalid delivery proof rejected"
                );
                return;
            }

            if let Some(status_tx) = self.receipt_updates.remove(&header.destination_hash) {
                let update = rtt.map_or(crate::messages::ReceiptUpdate::Failed, |rtt| {
                    crate::messages::ReceiptUpdate::Delivered { rtt }
                });
                status_tx.send_replace(update);
            }

            if let Some(msg_id) = self.receipt_msg_ids.remove(&header.destination_hash) {
                debug!(
                    msg_id = %msg_id,
                    trunc = hex::encode(header.destination_hash),
                    "delivery proof received for outbound message"
                );
                if let Some(proof_tx) = self.receipt_proof_txs.remove(&header.destination_hash) {
                    if proof_tx
                        .send(crate::link_messages::DestinationEvent::DeliveryProof {
                            msg_id: msg_id.clone(),
                            rtt,
                        })
                        .is_err()
                    {
                        error!(msg_id = %msg_id,
                            "direct delivery-proof owner closed before confirmation");
                    }
                } else {
                    // Legacy receipts predate direct proof ownership. Preserve
                    // their broadcast behavior for compatibility.
                    for (dest_hash, tx) in &self.destination_channels {
                        if let Err(e) =
                            tx.try_send(crate::link_messages::DestinationEvent::DeliveryProof {
                                msg_id: msg_id.clone(),
                                rtt,
                            })
                        {
                            self.channel_drops += 1;
                            error!(dest = hex::encode(dest_hash), msg_id = %msg_id, drops = self.channel_drops, err = %e,
                                "failed to deliver legacy DeliveryProof; sender will not receive confirmation");
                        }
                    }
                }
            }
            self.receipt_table.remove(&header.destination_hash);
            return;
        }

        // Link-request proofs route back via the link_table to the interface
        // the original request arrived on.
        //
        // Proofs start at hops=0 at the destination. We normalise inbound
        // hops before dispatch, matching Python Transport's increment-on-
        // receive rule, so the proof must equal the remaining hops recorded
        // when the request was forwarded.
        if header.context == rns_wire::context::PacketContext::Lrproof {
            // Local initiators may only adopt a proof from a registration to
            // which this exact request was actually admitted. This gate runs
            // before delivery; a later bind never looks up a replacement by ID.
            if self.local_destinations.contains(&header.destination_hash) {
                let admitted = self
                    .pending_local_link_requests
                    .get(&header.destination_hash)
                    .and_then(|owners| owners.get(&_interface_id))
                    .is_some_and(|owner| {
                        self.interfaces
                            .get(&_interface_id)
                            .is_some_and(|entry| owner.matches(&entry.owner))
                    });
                let signal_valid =
                    rns_wire::link_signalling::parse_proof_signalling(&raw[header.size()..])
                        .is_ok_and(|signal| {
                            signal.mode == rns_wire::link_signalling::DEFAULT_LINK_MODE
                                && signal.mtu.get() <= 500
                        });
                if !admitted || !signal_valid {
                    return;
                }
                self.rebalance_at_link_terminus(raw, header);
                if let Some(tx) = self.destination_channels.get(&header.destination_hash) {
                    let _ = tx.try_send(crate::link_messages::DestinationEvent::InboundPacket {
                        raw: raw.clone(),
                        interface_id: _interface_id,
                        metrics,
                        interface_owner: self
                            .interfaces
                            .get(&_interface_id)
                            .map(|entry| entry.owner.id()),
                    });
                }
                return;
            }
            if (self.is_transport_enabled || from_local_client || for_local_client_link)
                && let Some(mut link_entry) = self.link_table.get(&header.destination_hash).cloned()
            {
                if !link_entry.validated
                    && (now_f64() >= link_entry.proof_timeout
                        || !link_entry.proof_timeout.is_finite())
                {
                    trace!("expired pending transit Link cannot accept a late proof");
                    return;
                }
                // Python re-balances the path from a validly signed proof that
                // took a different number of hops (Transport.py:2886-2912).
                if header.hops != link_entry.remaining_hops
                    && _interface_id == link_entry.interface_id
                    && !link_entry.validated
                    && self.validate_transit_lrproof(raw, header, &link_entry)
                        == TransitProof::Valid
                {
                    pathing!(
                        dest = hex::encode(link_entry.destination_hash),
                        from = link_entry.remaining_hops,
                        to = header.hops,
                        "re-balancing path from link request proof"
                    );
                    link_entry.remaining_hops = header.hops;
                    if let Some(entry) = self.link_table.get_mut(&header.destination_hash) {
                        entry.remaining_hops = header.hops;
                    }
                    if let Some(path) = self.path_table.get_mut(&link_entry.destination_hash) {
                        path.hops = header.hops;
                    }
                    self.mark_path_responsive(&link_entry.destination_hash);
                }
                let link_entry = &link_entry;
                let expected_hops = link_entry.remaining_hops;
                let outbound_interface = link_entry.interface_id;
                let target_interface = link_entry.receiving_interface;
                let destination_hash = link_entry.destination_hash;
                // Python 1.3.8 Transport.py:1552/2222: instance-local
                // links are exempt from delta mangling (1.3.7 eacff56f).
                let instance_local_link = self.is_local_client_interface(link_entry.interface_id)
                    && self.is_local_client_interface(link_entry.receiving_interface);

                // Require that the proof arrived on the same interface we
                // forwarded the request to; a mismatch is either a routing
                // change or a spoof and must not be relayed.
                let hops_match = header.hops == expected_hops;
                if hops_match && _interface_id == outbound_interface {
                    match self.validate_transit_lrproof(raw, header, link_entry) {
                        TransitProof::Valid => {}
                        TransitProof::InvalidSignature => {
                            self.protocol_violation(_interface_id);
                            return;
                        }
                        TransitProof::Refused => return,
                    }
                    let pkt_hash = rns_wire::hash::packet_hash(raw, header.flags.header_type);
                    if !self.packet_hashlist.insert(pkt_hash) {
                        trace!(
                            link_id = hex::encode(header.destination_hash),
                            "duplicate LRPROOF dropped after link-table claim"
                        );
                        return;
                    }
                    let mut forwarded = raw.to_vec();
                    if forwarded.len() >= 2 {
                        forwarded[1] = if !from_local_client
                            || instance_local_link
                            || self.local_hops_delta == 0
                        {
                            header.hops
                        } else {
                            self.local_hops_delta
                        };
                    }
                    if !self.send_to_interface(target_interface, &forwarded) {
                        return;
                    }
                    if let Some(entry) = self.link_table.get_mut(&header.destination_hash) {
                        entry.validated = true;
                        entry.accepted_mtu_ceiling =
                            rns_wire::link_signalling::parse_proof_signalling(
                                &raw[header.size()..],
                            )
                            .expect("validated proof")
                            .mtu
                            .get();
                    }
                    if !self.is_shared_instance {
                        self.use_destination(&destination_hash);
                        self.mark_path_responsive(&destination_hash);
                    }
                    debug!(
                        link_id = hex::encode(header.destination_hash),
                        via_interface = target_interface,
                        hops = header.hops,
                        "link proof (LRPROOF) routed via link table"
                    );
                    return;
                } else if !hops_match {
                    warn!(
                        link_id = hex::encode(header.destination_hash),
                        expected_hops,
                        actual_hops = header.hops,
                        "link proof hop mismatch, not transporting"
                    );
                } else {
                    warn!(
                        link_id = hex::encode(header.destination_hash),
                        expected_interface = outbound_interface,
                        actual_interface = _interface_id,
                        "link proof received on wrong interface, not transporting"
                    );
                }
            }

            // Fall through to local-pending-link delivery when link_table
            // didn't claim the proof.
            if let Some(tx) = self.destination_channels.get(&header.destination_hash) {
                let delivered =
                    tx.try_send(crate::link_messages::DestinationEvent::InboundPacket {
                        interface_owner: self
                            .interfaces
                            .get(&_interface_id)
                            .map(|entry| entry.owner.id()),
                        raw: raw.clone(),
                        interface_id: _interface_id,
                        metrics,
                    });
                if let Err(e) = delivered {
                    self.channel_drops += 1;
                    warn!(dest = hex::encode(header.destination_hash), drops = self.channel_drops, err = %e,
                        "failed to deliver LRPROOF to local pending link (channel full)");
                } else {
                    let pkt_hash = rns_wire::hash::packet_hash(raw, header.flags.header_type);
                    self.packet_hashlist.insert(pkt_hash);
                }
            }
            return;
        }

        if self.route_link_packet_via_link_table(raw, header, _interface_id, "proof") {
            return;
        }

        // Data-packet proofs route back via the reverse_table. When the
        // entry records the outbound interface we forwarded on, enforce the
        // match — a proof on the wrong interface means a routing change or
        // a spoof. Older entries without that field route unconditionally.
        if self.is_transport_enabled || from_local_client || proof_for_local_client {
            // Python 1.3.8 Transport.py:2287: delta for local-client-origin
            // proofs; proofs headed to local clients exempt (1.3.7 eacff56f).
            let proof_hops =
                if !from_local_client || proof_for_local_client || self.local_hops_delta == 0 {
                    header.hops
                } else {
                    self.local_hops_delta
                };
            if let Some(reverse_entry) = self.reverse_table.remove(&header.destination_hash) {
                if let Some(expected_outbound) = reverse_entry.outbound_interface {
                    if _interface_id != expected_outbound {
                        debug!(
                            dest = hex::encode(header.destination_hash),
                            expected = expected_outbound,
                            actual = _interface_id,
                            "proof arrived on wrong interface, not routing via reverse table"
                        );
                    } else {
                        let target_interface = reverse_entry.receiving_interface;
                        let mut forwarded = raw.to_vec();
                        if forwarded.len() >= 2 {
                            forwarded[1] = proof_hops;
                        }
                        self.send_to_interface(target_interface, &forwarded);
                        trace!(
                            dest = hex::encode(header.destination_hash),
                            via_interface = target_interface,
                            "proof routed via reverse table"
                        );
                        return;
                    }
                } else {
                    let target_interface = reverse_entry.receiving_interface;
                    let mut forwarded = raw.to_vec();
                    if forwarded.len() >= 2 {
                        forwarded[1] = proof_hops;
                    }
                    self.send_to_interface(target_interface, &forwarded);
                    trace!(
                        dest = hex::encode(header.destination_hash),
                        via_interface = target_interface,
                        "proof routed via reverse table"
                    );
                    return;
                }
            }
        }

        if let Some(tx) = self.destination_channels.get(&header.destination_hash)
            && let Err(e) = tx.try_send(crate::link_messages::DestinationEvent::InboundPacket {
                interface_owner: self
                    .interfaces
                    .get(&_interface_id)
                    .map(|entry| entry.owner.id()),
                raw: raw.clone(),
                interface_id: _interface_id,
                metrics,
            })
        {
            self.channel_drops += 1;
            error!(dest = hex::encode(header.destination_hash), drops = self.channel_drops, err = %e,
                    "failed to deliver link proof to local link");
        }
    }

    fn route_link_packet_via_link_table(
        &mut self,
        raw: &[u8],
        header: &rns_wire::header::PacketHeader,
        interface_id: InterfaceId,
        packet_kind: &'static str,
    ) -> bool {
        if header.flags.destination_type != rns_wire::flags::DestinationType::Link
            || self.local_destinations.contains(&header.destination_hash)
        {
            return false;
        }

        let Some(entry) = self.link_table.get(&header.destination_hash).cloned() else {
            return false;
        };

        let from_local_client = self.is_local_client_interface(interface_id);
        // Python 1.3.8 Transport.py:1548-1553 (the 1.3.7 eacff56f fix): links
        // between two local clients of this shared instance are exempt from
        // delta mangling.
        let instance_local_link = self.is_local_client_interface(entry.interface_id)
            && self.is_local_client_interface(entry.receiving_interface);
        let shared_client_path = from_local_client
            || self.is_local_client_interface(entry.receiving_interface)
            || self.is_local_client_interface(entry.interface_id);
        if !self.is_transport_enabled && !shared_client_path {
            return false;
        }
        // Transport.py:2396-2402: nothing but the proof may cross before validation.
        if !entry.validated {
            debug!(
                link_id = hex::encode(header.destination_hash),
                interface_id, "link packet received before link validation"
            );
            self.protocol_violation(interface_id);
            return true;
        }
        if !self.link_registration_is_current(&entry)
            || raw.len() > entry.accepted_mtu_ceiling as usize
        {
            return true;
        }

        let target_interface = if entry.interface_id == entry.receiving_interface {
            if header.hops == entry.remaining_hops || header.hops == entry.taken_hops {
                entry.interface_id
            } else {
                trace!(
                    link_id = hex::encode(header.destination_hash),
                    actual_hops = header.hops,
                    remaining_hops = entry.remaining_hops,
                    taken_hops = entry.taken_hops,
                    "link packet hop mismatch, not transporting"
                );
                return true;
            }
        } else if interface_id == entry.receiving_interface {
            if header.hops == entry.taken_hops {
                entry.interface_id
            } else {
                trace!(
                    link_id = hex::encode(header.destination_hash),
                    actual_hops = header.hops,
                    expected_hops = entry.taken_hops,
                    "link packet initiator-side hop mismatch, not transporting"
                );
                return true;
            }
        } else if interface_id == entry.interface_id {
            if header.hops == entry.remaining_hops {
                entry.receiving_interface
            } else {
                trace!(
                    link_id = hex::encode(header.destination_hash),
                    actual_hops = header.hops,
                    expected_hops = entry.remaining_hops,
                    "link packet destination-side hop mismatch, not transporting"
                );
                return true;
            }
        } else {
            warn!(
                link_id = hex::encode(header.destination_hash),
                interface_id,
                receiving_interface = entry.receiving_interface,
                outbound_interface = entry.interface_id,
                "link packet arrived on interface outside link table path, not transporting"
            );
            return true;
        };

        let mut forwarded = raw.to_vec();
        if forwarded.len() >= 2 {
            // Python 1.3.8 Transport.py:1731: delta for local-client link
            // traffic leaving the instance; instance-local links exempt.
            forwarded[1] =
                if !from_local_client || instance_local_link || self.local_hops_delta == 0 {
                    header.hops
                } else {
                    self.local_hops_delta
                };
        }
        let skip_hashlist = matches!(
            header.context,
            rns_wire::context::PacketContext::Keepalive
                | rns_wire::context::PacketContext::Resource
                | rns_wire::context::PacketContext::ResourceReq
                | rns_wire::context::PacketContext::ResourcePrf
                | rns_wire::context::PacketContext::CacheRequest
                | rns_wire::context::PacketContext::Channel
        );
        if !skip_hashlist {
            let pkt_hash = rns_wire::hash::packet_hash(raw, header.flags.header_type);
            if !self.packet_hashlist.insert(pkt_hash) {
                trace!(
                    link_id = hex::encode(header.destination_hash),
                    packet_kind, "duplicate link-table packet dropped after claim"
                );
                return true;
            }
        }
        if let Some(entry) = self.link_table.get_mut(&header.destination_hash) {
            entry.timestamp = now_f64();
        }
        self.send_to_interface(target_interface, &forwarded);
        // Transport.py:2438-2440@1.6.0.
        if let Some(path) = self.path_table.get_mut(&entry.destination_hash) {
            path.mark_used();
        }
        trace!(
            link_id = hex::encode(header.destination_hash),
            via_interface = target_interface,
            hops = header.hops,
            packet_kind,
            "link packet routed via link table"
        );
        true
    }

    fn link_registration_is_current(&self, entry: &crate::link_table::LinkEntry) -> bool {
        [
            (entry.interface_id, &entry.interface_owner),
            (entry.receiving_interface, &entry.receiving_owner),
        ]
        .into_iter()
        .all(|(id, owner)| {
            owner.as_ref().is_some_and(|owner| {
                owner.is_current()
                    && self
                        .interfaces
                        .get(&id)
                        .is_some_and(|current| current.owner == *owner)
            })
        })
    }

    fn validate_transit_lrproof(
        &self,
        raw: &[u8],
        header: &rns_wire::header::PacketHeader,
        link_entry: &crate::link_table::LinkEntry,
    ) -> TransitProof {
        let payload_offset = header.size();
        if raw.len() < payload_offset {
            warn!(
                link_id = hex::encode(header.destination_hash),
                raw_len = raw.len(),
                "link proof missing payload, not transporting"
            );
            return TransitProof::Refused;
        }

        let proof_data = &raw[payload_offset..];
        if proof_data.len() != 96 && proof_data.len() != 99 {
            warn!(
                link_id = hex::encode(header.destination_hash),
                proof_len = proof_data.len(),
                "malformed link request proof length, not transporting"
            );
            return TransitProof::Refused;
        }

        let Ok(signal) = rns_wire::link_signalling::parse_proof_signalling(proof_data) else {
            return TransitProof::Refused;
        };
        if signal.mode != link_entry.requested_mode
            || signal.mtu.get() > link_entry.accepted_mtu_ceiling
            || (link_entry.validated && signal.mtu.get() != link_entry.accepted_mtu_ceiling)
            || !self.link_registration_is_current(link_entry)
        {
            return TransitProof::Refused;
        }

        match self.lrproof_signature_valid(
            proof_data,
            &header.destination_hash,
            &link_entry.destination_hash,
        ) {
            Some(true) => TransitProof::Valid,
            Some(false) => {
                warn!(
                    link_id = hex::encode(header.destination_hash),
                    destination = hex::encode(link_entry.destination_hash),
                    "invalid link request proof signature, not transporting"
                );
                TransitProof::InvalidSignature
            }
            None => TransitProof::Refused,
        }
    }

    /// Python's terminus re-balance (Transport.py:2954-2984): the first validly
    /// signed proof for a pending local Link ends its pending state and, when
    /// its hops differ from the path hops at request time, rewrites the path
    /// hops and marks the path responsive.
    fn rebalance_at_link_terminus(&mut self, raw: &[u8], header: &rns_wire::header::PacketHeader) {
        let Some(&(destination_hash, expected_hops)) =
            self.pending_local_link_hops.get(&header.destination_hash)
        else {
            return;
        };
        if self.lrproof_signature_valid(
            &raw[header.size()..],
            &header.destination_hash,
            &destination_hash,
        ) != Some(true)
        {
            return;
        }
        // A valid proof ends the pending state, so a replay cannot re-balance (Transport.py:2954).
        self.pending_local_link_hops
            .remove(&header.destination_hash);
        if expected_hops == Some(header.hops) {
            return;
        }
        pathing!(
            dest = hex::encode(destination_hash),
            from = ?expected_hops,
            to = header.hops,
            "re-balancing path at link terminus"
        );
        if let Some(path) = self.path_table.get_mut(&destination_hash) {
            path.hops = header.hops;
        }
        self.mark_path_responsive(&destination_hash);
    }

    /// Verify an LRPROOF signature against the destination's announced key;
    /// `None` when the length or identity is unusable.
    fn lrproof_signature_valid(
        &self,
        proof_data: &[u8],
        link_id: &[u8; 16],
        destination_hash: &[u8; 16],
    ) -> Option<bool> {
        if proof_data.len() != 96 && proof_data.len() != 99 {
            return None;
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&proof_data[..64]);
        let responder_x25519_pub = &proof_data[64..96];
        let signalling = if proof_data.len() == 99 {
            &proof_data[96..99]
        } else {
            &[]
        };

        let Some(destination_public_key) = self
            .recent_announces
            .get(destination_hash)
            .and_then(|announce| announce.public_key)
        else {
            warn!(
                link_id = hex::encode(link_id),
                destination = hex::encode(destination_hash),
                "link request proof has no known destination identity"
            );
            return None;
        };

        let mut destination_ed25519 = [0u8; 32];
        destination_ed25519.copy_from_slice(&destination_public_key[32..64]);
        let verify_key =
            match rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&destination_ed25519) {
                Ok(key) => key,
                Err(err) => {
                    warn!(
                        link_id = hex::encode(link_id),
                        destination = hex::encode(destination_hash),
                        error = %err,
                        "link request proof destination identity is invalid"
                    );
                    return None;
                }
            };

        let mut signed_data = Vec::with_capacity(16 + 32 + 32 + signalling.len());
        signed_data.extend_from_slice(link_id);
        signed_data.extend_from_slice(responder_x25519_pub);
        signed_data.extend_from_slice(&destination_ed25519);
        signed_data.extend_from_slice(signalling);

        Some(verify_key.verify(&signed_data, &signature).is_ok())
    }
}
