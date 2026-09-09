//! Bounded ownership of path requests refused by a full driver channel.
//!
//! This is not an RF retry queue: only bytes never admitted to that exact
//! interface generation are retained. Tags/deadlines never refresh on retry.
use super::path_recovery::RouteVersion;
use super::*;

const MAX_PENDING_ADMISSIONS: usize = 256;
const MAX_ADMISSION_POLL: usize = 32;

pub(super) struct PendingAdmission {
    destination: [u8; 16],
    interface: InterfaceId,
    generation: mpsc::Sender<Bytes>,
    raw: Vec<u8>,
    recursive: bool,
    deadline: f64,
    next_try: f64,
    initial_route: Option<RouteVersion>,
    discovery_owner: Option<DiscoveryPathRequest>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(
        actor: &mut TransportActor,
        id: InterfaceId,
        capacity: usize,
    ) -> mpsc::Receiver<Bytes> {
        let (tx, rx) = mpsc::channel(capacity);
        actor.interfaces.insert(
            id,
            InterfaceEntry::new(
                format!("radio-{id}"),
                InterfaceMode::Full,
                InterfaceDirection::bidirectional(),
                300,
                500,
                tx,
            ),
        );
        rx
    }

    fn fill(actor: &TransportActor, id: InterfaceId) {
        actor.interfaces[&id]
            .tx
            .try_send(Bytes::from_static(b"existing work"))
            .unwrap();
    }

    #[test]
    fn full_driver_preserves_tag_without_spending_path_or_airtime_budget() {
        let (mut actor, _) = TransportActor::new();
        let mut radio = interface(&mut actor, 1, 1);
        fill(&actor, 1);
        let dest = [0xD1; 16];
        let tag = [0x55; 16];
        actor.send_path_request(dest, 1, Some(&tag), true);
        assert!(!actor.path_requests.contains_key(&dest));
        assert_eq!(actor.interfaces[&1].announce_allowed_at, 0.0);
        assert_eq!(actor.pending_path_request_admissions.len(), 1);
        let raw = actor.pending_path_request_admissions[0].raw.clone();
        let due = actor.pending_path_request_admissions[0].next_try;
        assert!(raw.ends_with(&tag));
        // A second intent cannot replace the old tag/deadline or spend another
        // pending slot while the exact target is still unadmitted.
        let deadline = actor.pending_path_request_admissions[0].deadline;
        actor.send_path_request(dest, 1, Some(&[0x66; 16]), true);
        assert_eq!(actor.pending_path_request_admissions.len(), 1);
        assert_eq!(actor.pending_path_request_admissions[0].deadline, deadline);
        radio.try_recv().unwrap();
        actor.process_pending_path_request_admissions(due);
        assert_eq!(&radio.try_recv().unwrap()[..], raw.as_slice());
        assert!(actor.pending_path_request_admissions.is_empty());
        assert_eq!(actor.path_requests[&dest], due);
        assert!(actor.interfaces[&1].announce_allowed_at > due);
    }

    #[test]
    fn partial_admission_retries_only_failed_interface() {
        let (mut actor, _) = TransportActor::new();
        let mut blocked = interface(&mut actor, 1, 1);
        let mut ready = interface(&mut actor, 2, 8);
        fill(&actor, 1);
        let dest = [0xD2; 16];
        actor.on_path_request(dest);
        let raw = ready.try_recv().unwrap();
        let due = actor.pending_path_request_admissions[0].next_try;
        actor.on_automatic_path_request(dest);
        assert!(ready.try_recv().is_err());
        blocked.try_recv().unwrap();
        actor.process_pending_path_request_admissions(due);
        assert_eq!(blocked.try_recv().unwrap(), raw);
        assert!(ready.try_recv().is_err());
        actor.process_pending_path_request_admissions(due + 1.0);
        assert!(blocked.try_recv().is_err());
    }

    #[test]
    fn refused_target_does_not_extend_healthy_automatic_discovery_cooldown() {
        let (mut actor, _) = TransportActor::new();
        let mut blocked = interface(&mut actor, 1, 1);
        let mut ready = interface(&mut actor, 2, 8);
        fill(&actor, 1);
        let dest = [0xDA; 16];
        actor.on_automatic_path_request(dest);
        let first = ready.try_recv().unwrap();
        let deadline = actor.pending_path_request_admissions[0].deadline;
        let pending_raw = actor.pending_path_request_admissions[0].raw.clone();
        assert_eq!(first.as_ref(), pending_raw.as_slice());

        actor.on_automatic_path_request(dest);
        assert!(
            ready.try_recv().is_err(),
            "an immediate repeat is throttled"
        );
        // Model elapsed Sent cooldown without changing the blocked target's
        // immutable request owner. Its first attempt is still unadmitted.
        actor
            .path_requests
            .insert(dest, now_f64() - PATH_REQUEST_MI - 1.0);
        actor.on_automatic_path_request(dest);
        let second = ready.try_recv().unwrap();
        assert_ne!(second, first, "a later discovery intent gets a fresh tag");
        assert_eq!(actor.pending_path_request_admissions.len(), 1);
        assert_eq!(actor.pending_path_request_admissions[0].raw, pending_raw);
        assert_eq!(actor.pending_path_request_admissions[0].deadline, deadline);
        actor.on_automatic_path_request(dest);
        assert!(ready.try_recv().is_err());

        blocked.try_recv().unwrap();
        let due = actor.pending_path_request_admissions[0].next_try;
        actor.process_pending_path_request_admissions(due);
        assert_eq!(blocked.try_recv().unwrap(), first);
        assert!(ready.try_recv().is_err());
        assert!(actor.pending_path_request_admissions.is_empty());
    }

    #[test]
    fn refused_target_does_not_extend_healthy_recovery_discovery_cooldown() {
        let (mut actor, _) = TransportActor::new();
        let handle = actor.path_recovery_handle();
        let mut blocked = interface(&mut actor, 1, 1);
        let mut ready = interface(&mut actor, 2, 8);
        fill(&actor, 1);
        let dest = [0xDB; 16];
        actor.on_path_request(dest);
        let first = ready.try_recv().unwrap();
        let deadline = actor.pending_path_request_admissions[0].deadline;
        let pending_raw = actor.pending_path_request_admissions[0].raw.clone();
        let recover = |actor: &mut TransportActor| {
            let mut reply = handle.try_recover(dest, None).unwrap();
            let request = actor.path_recovery_rx.try_recv().unwrap();
            actor.recover_local_link_path(request);
            assert!(reply.try_recv().unwrap().request_scheduled);
        };

        recover(&mut actor);
        assert!(actor.pending_discovery_prs.is_empty());
        assert!(ready.try_recv().is_err());
        actor
            .path_requests
            .insert(dest, now_f64() - PATH_REQUEST_MI - 1.0);
        recover(&mut actor);
        recover(&mut actor);
        assert_eq!(
            actor.pending_discovery_prs.len(),
            1,
            "FIFO coalesces repeats"
        );
        actor.process_pending_discovery_path_requests(now_f64() + 1.0);
        let second = ready.try_recv().unwrap();
        assert_ne!(second, first);
        assert_eq!(actor.pending_path_request_admissions.len(), 1);
        assert_eq!(actor.pending_path_request_admissions[0].raw, pending_raw);
        assert_eq!(actor.pending_path_request_admissions[0].deadline, deadline);
        recover(&mut actor);
        assert!(actor.pending_discovery_prs.is_empty());
        assert!(ready.try_recv().is_err());

        blocked.try_recv().unwrap();
        let due = actor.pending_path_request_admissions[0].next_try;
        actor.process_pending_path_request_admissions(due);
        assert_eq!(blocked.try_recv().unwrap(), first);
        assert!(ready.try_recv().is_err());
        assert!(actor.pending_path_request_admissions.is_empty());
    }

    #[test]
    fn deadline_and_new_signed_route_retire_unadmitted_bytes() {
        for new_route in [false, true] {
            let (mut actor, _) = TransportActor::new();
            let mut radio = interface(&mut actor, 1, 1);
            fill(&actor, 1);
            let dest = [0xD3; 16];
            actor.on_path_request(dest);
            let due = if new_route {
                let mut path = crate::path_table::PathEntry::new(None, 1, 1, InterfaceMode::Full);
                path.packet_hash = Some([0x42; 32]);
                actor.path_table.insert(dest, path);
                actor.pending_path_request_admissions[0].next_try
            } else {
                actor.pending_path_request_admissions[0].deadline
            };
            radio.try_recv().unwrap();
            actor.process_pending_path_request_admissions(due);
            assert!(radio.try_recv().is_err());
            assert!(actor.pending_path_request_admissions.is_empty());
            assert!(!actor.path_requests.contains_key(&dest));
        }
    }

    #[test]
    fn replacement_or_closed_interface_cannot_inherit_old_queued_request() {
        for replace in [false, true] {
            let (mut actor, _) = TransportActor::new();
            let radio = interface(&mut actor, 1, 1);
            fill(&actor, 1);
            actor.on_path_request([0xD4; 16]);
            let due = actor.pending_path_request_admissions[0].next_try;
            drop(radio);
            let mut replacement = replace.then(|| interface(&mut actor, 1, 4));
            actor.process_pending_path_request_admissions(due);
            assert!(actor.pending_path_request_admissions.is_empty());
            assert!(!actor.path_requests.contains_key(&[0xD4; 16]));
            if let Some(rx) = &mut replacement {
                assert!(rx.try_recv().is_err());
            } else {
                assert!(!actor.interfaces.contains_key(&1));
            }
        }
    }

    #[test]
    fn recursive_operation_retirement_cancels_pending_egress() {
        let (mut actor, _) = TransportActor::new();
        let mut radio = interface(&mut actor, 1, 1);
        fill(&actor, 1);
        let dest = [0xD5; 16];
        actor.discovery_path_requests.insert(
            dest,
            DiscoveryPathRequest {
                requesting_interface: 2,
                timeout: now_f64() + 10.0,
            },
        );
        actor.send_path_request(dest, 1, Some(&[0x55; 16]), true);
        let due = actor.pending_path_request_admissions[0].next_try;
        actor.discovery_path_requests.remove(&dest);
        radio.try_recv().unwrap();
        actor.process_pending_path_request_admissions(due);
        assert!(radio.try_recv().is_err());
        assert!(actor.pending_path_request_admissions.is_empty());
    }

    #[test]
    fn admission_inventory_is_bounded_and_clear_shared_retires_it() {
        let (mut actor, _) = TransportActor::new();
        let _radio = interface(&mut actor, 1, 1);
        fill(&actor, 1);
        for i in 0..MAX_PENDING_ADMISSIONS + 32 {
            let mut dest = [0xD6; 16];
            dest[..8].copy_from_slice(&(i as u64).to_le_bytes());
            actor.on_path_request(dest);
        }
        assert_eq!(
            actor.pending_path_request_admissions.len(),
            MAX_PENDING_ADMISSIONS
        );
        assert!(actor.path_requests.is_empty());
        actor.clear_shared_connection_state();
        assert!(actor.pending_path_request_admissions.is_empty());
    }

    #[test]
    fn initial_policy_veto_and_missing_target_do_not_create_retry_or_sent_state() {
        let (mut actor, _) = TransportActor::new();
        let mut radio = interface(&mut actor, 1, 1);
        actor.interfaces.get_mut(&1).unwrap().announce_allowed_at = now_f64() + 120.0;
        actor.send_path_request([0xD7; 16], 1, None, true);
        actor.send_path_request([0xD8; 16], 2, None, false);
        actor.interfaces.get_mut(&1).unwrap().direction.outbound = false;
        actor.send_path_request([0xD9; 16], 1, None, false);
        assert!(radio.try_recv().is_err());
        assert!(actor.path_requests.is_empty());
        assert!(actor.pending_path_request_admissions.is_empty());
    }
}

#[derive(PartialEq, Eq)]
enum Admission {
    Sent,
    Full,
    PolicyWait,
    Retired,
}

impl TransportActor {
    pub(super) fn retire_recursive_path_request_admissions(&mut self) {
        self.pending_path_request_admissions
            .retain(|pending| pending.discovery_owner.is_none());
    }

    pub(super) fn retire_path_request_admissions(&mut self, interface: InterfaceId) {
        self.pending_path_request_admissions.retain(|pending| {
            // The original requester may retire while other coalesced
            // requesters still own the same operation. Its validity is
            // checked against discovery_path_requests on the next poll.
            pending.interface != interface
        });
    }

    pub(super) fn has_pending_path_request_admission(&self, destination: [u8; 16]) -> bool {
        self.pending_path_request_admissions
            .iter()
            .any(|pending| pending.destination == destination)
    }

    pub(super) fn admit_path_request(
        &mut self,
        destination: [u8; 16],
        interface: InterfaceId,
        raw: Vec<u8>,
        recursive: bool,
    ) {
        if self
            .pending_path_request_admissions
            .iter()
            .any(|pending| pending.destination == destination && pending.interface == interface)
        {
            return;
        }
        let now = now_f64();
        if self.try_admit_path_request(destination, interface, &raw, recursive, now)
            != Admission::Full
        {
            return;
        }
        if self.pending_path_request_admissions.len() >= MAX_PENDING_ADMISSIONS {
            warn!(
                interface_id = interface,
                reason = "path_request_admission_capacity",
                "path request not admitted; bounded retry inventory full"
            );
            return;
        }
        let Some(entry) = self.interfaces.get(&interface) else {
            return;
        };
        let discovery_owner = recursive
            .then(|| self.discovery_path_requests.get(&destination).copied())
            .flatten();
        let deadline = discovery_owner.map_or(now + PATH_REQUEST_GATE_TIMEOUT, |owner| {
            owner.timeout.min(now + PATH_REQUEST_GATE_TIMEOUT)
        });
        self.pending_path_request_admissions
            .push_back(PendingAdmission {
                destination,
                interface,
                generation: entry.tx.clone(),
                raw,
                recursive,
                deadline,
                next_try: now + DISCOVERY_PR_TX_THROTTLE,
                initial_route: self
                    .path_table
                    .get_live(&destination)
                    .map(RouteVersion::from_path),
                discovery_owner,
            });
        trace!(
            interface_id = interface,
            "path request retained after driver backpressure; not transmitted"
        );
    }

    fn try_admit_path_request(
        &mut self,
        destination: [u8; 16],
        interface: InterfaceId,
        raw: &[u8],
        recursive: bool,
        now: f64,
    ) -> Admission {
        let Some(entry) = self.interfaces.get_mut(&interface) else {
            return Admission::Retired;
        };
        if !entry.direction.outbound {
            return Admission::Retired;
        }
        if recursive
            && (entry.ingress.should_egress_limit_pr()
                || !entry.announce_queue.is_empty()
                || now < entry.announce_allowed_at)
        {
            return Admission::PolicyWait;
        }
        match self.try_send_to_interface(interface, raw) {
            InterfaceSendOutcome::Sent => {
                if let Some(entry) = self.interfaces.get_mut(&interface) {
                    entry.ingress.sent_path_request();
                    if recursive {
                        let tx_time = raw.len() as f64 * 8.0 / entry.bitrate.max(1) as f64;
                        entry.announce_allowed_at = now + tx_time / entry.announce_cap.max(0.001);
                    }
                }
                self.path_requests.insert(destination, now);
                Admission::Sent
            }
            InterfaceSendOutcome::Full => Admission::Full,
            InterfaceSendOutcome::Closed | InterfaceSendOutcome::Offline => {
                let reason = if self
                    .interfaces
                    .get(&interface)
                    .is_some_and(interface_marked_offline)
                {
                    crate::messages::LinkEndpointTerminalReason::InterfaceOffline
                } else {
                    crate::messages::LinkEndpointTerminalReason::InterfaceClosed
                };
                self.deregister_interface_with_link_reason(interface, reason);
                Admission::Retired
            }
            InterfaceSendOutcome::Missing | InterfaceSendOutcome::NotOutbound => Admission::Retired,
        }
    }

    pub(super) fn process_pending_path_request_admissions(&mut self, now: f64) {
        let count = self
            .pending_path_request_admissions
            .len()
            .min(MAX_ADMISSION_POLL);
        for _ in 0..count {
            let Some(mut pending) = self.pending_path_request_admissions.pop_front() else {
                break;
            };
            let same_interface = self
                .interfaces
                .get(&pending.interface)
                .is_some_and(|entry| {
                    entry.direction.outbound && entry.tx.same_channel(&pending.generation)
                });
            let same_discovery = pending.discovery_owner.is_none_or(|owner| {
                self.discovery_path_requests
                    .get(&pending.destination)
                    .is_some_and(|current| {
                        current.requesting_interface == owner.requesting_interface
                            && current.timeout == owner.timeout
                            && now < current.timeout
                    })
            });
            let fresh_path = self
                .path_table
                .get_live(&pending.destination)
                .is_some_and(|path| Some(RouteVersion::from_path(path)) != pending.initial_route);
            if now >= pending.deadline || !same_interface || !same_discovery || fresh_path {
                trace!(
                    interface_id = pending.interface,
                    reason = "path_request_admission_retired",
                    "retiring unadmitted path request"
                );
                continue;
            }
            if now < pending.next_try {
                self.pending_path_request_admissions.push_back(pending);
                continue;
            }
            match self.try_admit_path_request(
                pending.destination,
                pending.interface,
                &pending.raw,
                pending.recursive,
                now,
            ) {
                Admission::Full | Admission::PolicyWait => {
                    pending.next_try = now + DISCOVERY_PR_TX_THROTTLE;
                    self.pending_path_request_admissions.push_back(pending);
                }
                Admission::Sent | Admission::Retired => {}
            }
        }
    }
}
