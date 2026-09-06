use super::*;
use crate::path_recovery::{FailedRouteAttempt, PathRecoveryOutcome, PathRecoveryRequest};

const MAX_LOCAL_LINK_ROUTES: usize = 1024;
const LOCAL_LINK_ROUTE_LIFETIME: f64 = 3600.0;

/// The signed announce version plus forwarding choice, not the path's traffic
/// touch time. A locally admitted packet must not make its own route look new.
#[derive(Clone, PartialEq)]
struct RouteVersion {
    interface_id: InterfaceId,
    next_hop: Option<[u8; 16]>,
    hops: u8,
    packet_hash: Option<[u8; 32]>,
    latest_blob: Option<[u8; 10]>,
    // Synthetic/legacy routes without signed provenance are compared more
    // conservatively. A later touch may preserve them, never delete a new one.
    unversioned_timestamp: Option<f64>,
}

impl RouteVersion {
    fn from_path(path: &crate::path_table::PathEntry) -> Self {
        Self {
            interface_id: path.interface_id,
            next_hop: path.next_hop,
            hops: path.hops,
            packet_hash: path.packet_hash,
            latest_blob: path.random_blobs.back().copied(),
            unversioned_timestamp: (path.packet_hash.is_none() && path.random_blobs.is_empty())
                .then_some(path.timestamp),
        }
    }
}

pub(super) struct LocalLinkRouteAttempt {
    destination_hash: [u8; 16],
    route: RouteVersion,
    observed_at: f64,
}

impl TransportActor {
    pub(super) fn cull_local_link_route_attempts(&mut self, now: f64) {
        self.local_link_route_attempts
            .retain(|_, entry| now - entry.observed_at < LOCAL_LINK_ROUTE_LIFETIME);
    }

    /// Enable bounded local-Link route observations and obtain an owned
    /// recovery handle. A handle from a retired actor cannot mutate its
    /// replacement. Explicit legacy suppression operations are unaffected.
    pub fn path_recovery_handle(&mut self) -> crate::path_recovery::PathRecoveryHandle {
        self.observe_local_link_routes = true;
        crate::path_recovery::PathRecoveryHandle {
            tx: self.path_recovery_tx.clone(),
        }
    }

    pub(super) fn local_link_attempt(
        &self,
        request: &crate::messages::OutboundRequest,
    ) -> Option<([u8; 16], [u8; 16])> {
        if !self.observe_local_link_routes {
            return None;
        }
        let (header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).ok()?;
        if header.flags.packet_type != rns_wire::flags::PacketType::LinkRequest
            || header.destination_hash != request.destination_hash
        {
            return None;
        }
        let link_id = rns_wire::hash::link_id_from_raw(&request.raw, header.flags.header_type);
        self.local_destinations
            .contains(&link_id)
            .then_some((link_id, request.destination_hash))
    }

    pub(super) fn record_local_link_attempt(
        &mut self,
        attempt: Option<([u8; 16], [u8; 16])>,
        sent: bool,
    ) {
        let Some((link_id, destination_hash)) = attempt.filter(|_| sent) else {
            return;
        };
        self.record_route_attempt(FailedRouteAttempt::Link(link_id), destination_hash);
    }

    pub(super) fn record_route_attempt(
        &mut self,
        link_id: FailedRouteAttempt,
        destination_hash: [u8; 16],
    ) {
        let now = now_f64();
        self.cull_local_link_route_attempts(now);
        // Never refresh an old attempt with the route used by a replay.
        if self.local_link_route_attempts.contains_key(&link_id) {
            return;
        }
        let Some(path) = self.path_table.get_live(&destination_hash) else {
            return;
        };
        let route = RouteVersion::from_path(path);
        if self.local_link_route_attempts.len() >= MAX_LOCAL_LINK_ROUTES {
            if let Some(oldest) = self
                .local_link_route_attempts
                .iter()
                .min_by(|a, b| a.1.observed_at.total_cmp(&b.1.observed_at))
                .map(|(key, _)| *key)
            {
                self.local_link_route_attempts.remove(&oldest);
            }
        }
        self.local_link_route_attempts.insert(
            link_id,
            LocalLinkRouteAttempt {
                destination_hash,
                route,
                observed_at: now,
            },
        );
    }

    pub(super) fn recover_local_link_path(&mut self, request: PathRecoveryRequest) {
        if request.result_tx.is_closed() {
            return;
        }
        let now = now_f64();
        let mut path_dropped = false;
        let mut observed = false;
        if let Some(attempt) = request.failed_attempt.and_then(|link_id| {
            // A mismatched destination must not consume another attempt's
            // ownership. Records survive destination deregistration so the
            // Link manager can tear down before reporting the failed attempt.
            let matches = self
                .local_link_route_attempts
                .get(&link_id)
                .is_some_and(|entry| entry.destination_hash == request.destination_hash);
            matches
                .then(|| self.local_link_route_attempts.remove(&link_id))
                .flatten()
        }) {
            observed = now - attempt.observed_at < LOCAL_LINK_ROUTE_LIFETIME;
            if observed
                && self
                    .path_table
                    .get_live(&request.destination_hash)
                    .is_some_and(|path| RouteVersion::from_path(path) == attempt.route)
            {
                self.path_table.expire(&request.destination_hash);
                self.state_dirty = true;
                path_dropped = true;
            }
        }

        let has_path = self.path_table.has_path(&request.destination_hash);
        // A failed attempt's fresh replacement needs no new discovery flood.
        // Unknown attempts and explicit discovery can ask even if a cached
        // route exists, but all callers share the destination throttle/FIFO.
        let should_request = path_dropped || !has_path || !observed;
        let recent = self
            .path_requests
            .get(&request.destination_hash)
            .is_some_and(|last| now - last < PATH_REQUEST_MI);
        let queued = self.pending_discovery_prs.iter().any(|pending| {
            pending.destination_hash == request.destination_hash
                && pending.blocked_interface.is_none()
        });
        let request_scheduled = should_request
            && (queued
                || (!recent
                    && self.queue_discovery_path_request(request.destination_hash, None, now)));
        let _ = request.result_tx.send(PathRecoveryOutcome {
            path_dropped,
            has_path,
            request_scheduled,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{InterfaceEntry, OutboundRequest, TransportMessage};
    use crate::path_recovery::{PathRecoveryError, PathRecoveryHandle};

    fn fixture() -> (TransportActor, PathRecoveryHandle, mpsc::Receiver<Bytes>) {
        let (mut actor, _) = TransportActor::new();
        let handle = actor.path_recovery_handle();
        let (tx, rx) = mpsc::channel(8);
        actor.interfaces.insert(
            1,
            InterfaceEntry::new(
                "synthetic radio".into(),
                InterfaceMode::Full,
                InterfaceDirection::bidirectional(),
                300,
                500,
                tx,
            ),
        );
        actor.path_table.insert([0xDD; 16], path(1, 1));
        (actor, handle, rx)
    }

    fn path(interface: u64, version: u8) -> crate::path_table::PathEntry {
        let mut path = crate::path_table::PathEntry::new(None, 1, interface, InterfaceMode::Full);
        path.packet_hash = Some([version; 32]);
        path.add_random_blob([version; 10]);
        path
    }

    fn dispatch(actor: &mut TransportActor) -> [u8; 16] {
        use rns_wire::flags::*;
        let header = rns_wire::header::PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::LinkRequest,
            },
            hops: 0,
            transport_id: None,
            destination_hash: [0xDD; 16],
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[0x11; 64]);
        let link = rns_wire::hash::link_id_from_raw(&raw, HeaderType::Header1);
        actor.local_destinations.insert(link);
        actor.handle_message(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: [0xDD; 16],
        }));
        link
    }

    fn recover(
        actor: &mut TransportActor,
        handle: &PathRecoveryHandle,
        dest: [u8; 16],
        link: Option<[u8; 16]>,
    ) -> PathRecoveryOutcome {
        let mut reply = handle.try_recover(dest, link).unwrap();
        let request = actor.path_recovery_rx.try_recv().unwrap();
        actor.recover_local_link_path(request);
        reply.try_recv().unwrap()
    }

    #[test]
    fn failed_local_attempt_expires_only_unchanged_route_without_quarantine() {
        let (mut actor, handle, mut radio) = fixture();
        let link = dispatch(&mut actor);
        radio.try_recv().unwrap();
        // A traffic touch is not a replacement announcement.
        actor.path_table.get_live_mut(&[0xDD; 16]).unwrap().touch();
        let result = recover(&mut actor, &handle, [0xDD; 16], Some(link));
        assert!(result.path_dropped && !result.has_path && result.request_scheduled);
        assert!(actor.path_interface_suppressions.is_empty());
        assert_eq!(
            actor
                .pending_discovery_prs
                .front()
                .unwrap()
                .blocked_interface,
            None
        );
        actor.path_table.insert([0xDD; 16], path(1, 2));
        let again = recover(&mut actor, &handle, [0xDD; 16], Some(link));
        assert!(!again.path_dropped && again.has_path);
    }

    #[test]
    fn old_link_failure_preserves_fresh_same_radio_and_alternate_routes() {
        for interface in [1, 2] {
            let (mut actor, handle, _radio) = fixture();
            let link = dispatch(&mut actor);
            let mut replacement = path(interface, 2);
            replacement.next_hop = Some([0xAA; 16]);
            replacement.hops = 2;
            actor.path_table.insert([0xDD; 16], replacement);
            let result = recover(&mut actor, &handle, [0xDD; 16], Some(link));
            assert!(!result.path_dropped && result.has_path && !result.request_scheduled);
            assert_eq!(
                actor.path_table.get_live(&[0xDD; 16]).unwrap().interface_id,
                interface
            );
        }
    }

    #[test]
    fn wrong_destination_and_cancelled_request_cannot_invalidate_or_consume_attempt() {
        let (mut actor, handle, _radio) = fixture();
        let link = dispatch(&mut actor);
        let wrong = recover(&mut actor, &handle, [0xCC; 16], Some(link));
        assert!(!wrong.path_dropped);
        assert!(
            actor
                .local_link_route_attempts
                .contains_key(&FailedRouteAttempt::Link(link))
        );
        drop(handle.try_recover([0xDD; 16], Some(link)).unwrap());
        let request = actor.path_recovery_rx.try_recv().unwrap();
        actor.recover_local_link_path(request);
        assert!(actor.path_table.has_path(&[0xDD; 16]));
        assert!(recover(&mut actor, &handle, [0xDD; 16], Some(link)).path_dropped);
    }

    #[test]
    fn repeated_recoveries_coalesce_and_full_queue_is_retryable() {
        let (mut actor, handle, _radio) = fixture();
        let mut replies = Vec::new();
        for _ in 0..crate::path_recovery::RECOVERY_QUEUE_CAPACITY {
            replies.push(handle.try_recover([0xCC; 16], None).unwrap());
        }
        assert!(matches!(
            handle.try_recover([0xCC; 16], None),
            Err(PathRecoveryError::Full)
        ));
        while let Ok(request) = actor.path_recovery_rx.try_recv() {
            actor.recover_local_link_path(request);
        }
        assert_eq!(actor.pending_discovery_prs.len(), 1);
        assert!(recover(&mut actor, &handle, [0xCC; 16], None).request_scheduled);
        drop(actor);
        assert!(matches!(
            handle.try_recover([0xCC; 16], None),
            Err(PathRecoveryError::Closed)
        ));
    }

    #[test]
    fn failed_interface_admission_does_not_claim_a_route_attempt() {
        let (mut actor, handle, radio) = fixture();
        drop(radio);
        let link = dispatch(&mut actor);
        assert!(
            !actor
                .local_link_route_attempts
                .contains_key(&FailedRouteAttempt::Link(link))
        );
        // Reinstall a route after the dead interface was removed.
        actor.path_table.insert([0xDD; 16], path(1, 2));
        assert!(!recover(&mut actor, &handle, [0xDD; 16], Some(link)).path_dropped);
    }

    #[test]
    fn route_attempt_records_are_bounded_and_old_records_cannot_drop_paths() {
        let (mut actor, handle, _radio) = fixture();
        for value in 0..(MAX_LOCAL_LINK_ROUTES + 8) {
            let mut link = [0; 16];
            link[..8].copy_from_slice(&(value as u64).to_le_bytes());
            actor.record_local_link_attempt(Some((link, [0xDD; 16])), true);
        }
        assert_eq!(actor.local_link_route_attempts.len(), MAX_LOCAL_LINK_ROUTES);
        let link = *actor.local_link_route_attempts.keys().next().unwrap();
        actor
            .local_link_route_attempts
            .get_mut(&link)
            .unwrap()
            .observed_at = now_f64() - LOCAL_LINK_ROUTE_LIFETIME;
        let FailedRouteAttempt::Link(link) = link else {
            panic!("expected Link attempt")
        };
        assert!(!recover(&mut actor, &handle, [0xDD; 16], Some(link)).path_dropped);
    }

    #[test]
    fn tracked_packet_recovery_preserves_replacement_and_is_separate_from_links() {
        for replace in [false, true] {
            let (mut actor, handle, mut radio) = fixture();
            use rns_wire::flags::*;
            let raw = rns_wire::header::PacketHeader {
                flags: PacketFlags {
                    header_type: HeaderType::Header1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    destination_type: DestinationType::Single,
                    packet_type: PacketType::Data,
                },
                hops: 0,
                transport_id: None,
                destination_hash: [0xDD; 16],
                context: rns_wire::context::PacketContext::None,
            }
            .pack();
            let (full_hash, truncated_hash) =
                rns_wire::hash::packet_hash_pair(&raw, HeaderType::Header1);
            let (status_tx, _status) =
                tokio::sync::watch::channel(crate::messages::ReceiptUpdate::Sent);
            let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
            actor.handle_message(TransportMessage::SendPacket {
                request: OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: [0xDD; 16],
                },
                attached_interface: None,
                receipt: Some(crate::messages::TrackedReceiptRegistration {
                    truncated_hash,
                    full_hash,
                    destination_hash: [0xDD; 16],
                    destination_public_key: [0; 64],
                    timeout: Some(Duration::from_secs(120)),
                    status_tx,
                }),
                result_tx,
            });
            assert_eq!(
                result_rx.try_recv().unwrap(),
                crate::messages::OutboundDispatchResult::Sent
            );
            radio.try_recv().unwrap();
            // A Link-id collision cannot consume a packet's route owner.
            assert!(!recover(&mut actor, &handle, [0xDD; 16], Some(truncated_hash)).path_dropped);
            if replace {
                actor.path_table.insert([0xDD; 16], path(1, 2));
            }
            let mut reply = handle.try_recover_packet([0xDD; 16], full_hash).unwrap();
            let request = actor.path_recovery_rx.try_recv().unwrap();
            actor.recover_local_link_path(request);
            assert_eq!(reply.try_recv().unwrap().path_dropped, !replace);
            assert!(actor.path_interface_suppressions.is_empty());
        }
    }
}
