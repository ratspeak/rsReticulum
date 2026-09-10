//! One bounded owner for recursive discovery and its exact requester tokens.
use super::*;
use crate::path_discovery::{DiscoveryAdmission, DiscoveryError, DiscoveryRequester};

const MAX_DISCOVERY_DESTINATIONS: usize = 1024;
const MAX_DISCOVERY_REQUESTERS: usize = 64;

pub(super) struct DiscoveryOperation {
    pub(super) id: Arc<()>,
    pub(super) timeout: f64,
    requesters: Vec<Waiter>,
}

struct Waiter {
    token: DiscoveryRequester,
    channel: mpsc::Sender<Bytes>,
}

impl TransportActor {
    /// Detached snapshot of one unexpired operation. No maintenance tick is
    /// required to exclude expired operations or replaced requester channels.
    pub fn discovery_path_request(&self, destination: &[u8; 16]) -> Option<DiscoveryPathRequest> {
        let operation = self.discovery_path_requests.get(destination)?;
        let now = now_f64();
        if !now.is_finite() || now >= operation.timeout {
            return None;
        }
        let requesters: Vec<_> = operation
            .requesters
            .iter()
            .filter(|waiter| self.discovery_waiter_registered(waiter))
            .map(|waiter| waiter.token.clone())
            .collect();
        if requesters.is_empty() {
            return None;
        }
        Some(DiscoveryPathRequest {
            destination: *destination,
            timeout: operation.timeout,
            requesters,
        })
    }

    /// Detached snapshots ordered by destination hash. Admission is bounded to
    /// 1,024 operations and 64 requester registrations per operation.
    pub fn discovery_path_requests(&self) -> Vec<DiscoveryPathRequest> {
        let mut snapshots: Vec<_> = self
            .discovery_path_requests
            .keys()
            .filter_map(|destination| self.discovery_path_request(destination))
            .collect();
        snapshots.sort_by_key(DiscoveryPathRequest::destination_hash);
        snapshots
    }

    /// Start/join discovery on behalf of an eligible network interface.
    ///
    /// For advanced synchronous actor owners, not normal application lookups.
    /// Validates transport, unknown destination, interface role/mode and ingress
    /// policy. Native inbound requests keep their existing wire-tag loop checks;
    /// this method generates a fresh tag for the one new fanout. Joining neither
    /// refans out nor renews the deadline. Admission is not proof of transmission
    /// or delivery. Cancellation is explicit using the returned requester token.
    pub fn request_recursive_discovery(
        &mut self,
        destination: [u8; 16],
        requester: InterfaceId,
    ) -> Result<DiscoveryAdmission, DiscoveryError> {
        let now = now_f64();
        if !now.is_finite() || now + PATH_REQUEST_TIMEOUT <= now {
            return Err(DiscoveryError::InvalidClock);
        }
        if !self.is_transport_enabled {
            return Err(DiscoveryError::TransportDisabled);
        }
        if self.local_destinations.contains(&destination) || self.path_table.has_path(&destination)
        {
            return Err(DiscoveryError::KnownDestination);
        }
        let entry = self
            .interfaces
            .get_mut(&requester)
            .ok_or(DiscoveryError::UnknownInterface)?;
        if !entry.direction.outbound || entry.tx.is_closed() || interface_marked_offline(entry) {
            return Err(DiscoveryError::InterfaceUnavailable);
        }
        entry.ingress.received_path_request();
        if entry.role != InterfaceRole::Normal
            || !(entry.recursive_prs || mode_discovers_unknown_paths(entry.mode))
            || entry.ingress.should_ingress_limit_pr()
        {
            return Err(DiscoveryError::PolicyDenied);
        }
        let admission = self.admit_discovery_requester(destination, requester, now)?;
        if admission.started {
            let tag = rns_crypto::random::random_bytes(16);
            let mut unique_tag = destination.to_vec();
            unique_tag.extend_from_slice(&tag);
            self.discovery_pr_tags.insert(unique_tag, now);
            self.forward_path_request(destination, Some(requester), Some(&tag), true);
        }
        Ok(admission)
    }

    /// Cancel only the exact live requester. False means stale, expired,
    /// replaced or foreign-actor ownership. Other requesters retain the original
    /// deadline/fanout. Last-owner cancellation retires unadmitted search bytes,
    /// never bytes already sent. Dropping a token alone does not cancel it.
    pub fn cancel_discovery_requester(&mut self, token: &DiscoveryRequester) -> bool {
        self.cull_recursive_discovery(now_f64());
        let Some(operation) = self.discovery_path_requests.get_mut(&token.destination) else {
            return false;
        };
        if !Arc::ptr_eq(&operation.id, &token.operation) {
            return false;
        }
        let old_len = operation.requesters.len();
        operation.requesters.retain(|waiter| waiter.token != *token);
        let removed = old_len != operation.requesters.len();
        if operation.requesters.is_empty() {
            self.discovery_path_requests.remove(&token.destination);
            self.retire_orphaned_discovery_admissions();
        }
        removed
    }

    fn discovery_waiter_registered(&self, waiter: &Waiter) -> bool {
        self.interfaces
            .get(&waiter.token.interface)
            .is_some_and(|entry| {
                entry.direction.outbound
                    && !entry.tx.is_closed()
                    && entry.tx.same_channel(&waiter.channel)
            })
    }

    pub(super) fn cancel_recursive_discovery(&mut self) {
        self.discovery_path_requests.clear();
        self.retire_recursive_path_request_admissions();
    }

    /// Useful first-hop request/response allowance, not arbitrary multi-hop RF.
    pub(super) fn recursive_discovery_timeout(&self, requester: InterfaceId) -> f64 {
        let slowest = self
            .interfaces
            .iter()
            .filter(|(id, entry)| {
                **id != requester
                    && entry.direction.outbound
                    && !entry.tx.is_closed()
                    && !interface_marked_offline(entry)
                    && entry.bitrate > 0
            })
            .map(|(_, entry)| entry.bitrate)
            .min();
        (crate::link_table::interface_round_trip_allowance(slowest)
            + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT)
            .max(PATH_REQUEST_TIMEOUT)
    }

    pub(super) fn begin_or_join_recursive_discovery(
        &mut self,
        destination: [u8; 16],
        requester: InterfaceId,
        now: f64,
    ) -> bool {
        self.admit_discovery_requester(destination, requester, now)
            .is_ok_and(|admission| admission.started)
    }

    fn admit_discovery_requester(
        &mut self,
        destination: [u8; 16],
        requester: InterfaceId,
        now: f64,
    ) -> Result<DiscoveryAdmission, DiscoveryError> {
        if !now.is_finite() {
            return Err(DiscoveryError::InvalidClock);
        }
        // Normal ingress only examines this destination's <=64 registrations;
        // do not scan the whole inventory for every received request.
        if self
            .discovery_path_requests
            .get_mut(&destination)
            .is_some_and(|operation| !retain_live_requesters(operation, &self.interfaces, now))
        {
            self.discovery_path_requests.remove(&destination);
            self.retire_orphaned_discovery_admissions();
        }
        let entry = self
            .interfaces
            .get(&requester)
            .ok_or(DiscoveryError::UnknownInterface)?;
        if !entry.direction.outbound || entry.tx.is_closed() || interface_marked_offline(entry) {
            return Err(DiscoveryError::InterfaceUnavailable);
        }
        let channel = entry.tx.clone();
        if let Some(operation) = self.discovery_path_requests.get_mut(&destination) {
            if let Some(waiter) = operation.requesters.iter().find(|waiter| {
                waiter.token.interface == requester && waiter.channel.same_channel(&channel)
            }) {
                return Ok(DiscoveryAdmission {
                    requester: waiter.token.clone(),
                    started: false,
                });
            }
            if operation.requesters.len() >= MAX_DISCOVERY_REQUESTERS {
                return Err(DiscoveryError::Capacity);
            }
            let token = DiscoveryRequester {
                destination,
                interface: requester,
                operation: operation.id.clone(),
                registration: Arc::new(()),
            };
            operation.requesters.push(Waiter {
                token: token.clone(),
                channel,
            });
            return Ok(DiscoveryAdmission {
                requester: token,
                started: false,
            });
        }
        if self.discovery_path_requests.len() >= MAX_DISCOVERY_DESTINATIONS {
            self.cull_recursive_discovery(now);
            if self.discovery_path_requests.len() >= MAX_DISCOVERY_DESTINATIONS {
                return Err(DiscoveryError::Capacity);
            }
        }
        let timeout = now + self.recursive_discovery_timeout(requester);
        if !timeout.is_finite() || timeout <= now {
            return Err(DiscoveryError::InvalidClock);
        }
        let id = Arc::new(());
        let token = DiscoveryRequester {
            destination,
            interface: requester,
            operation: id.clone(),
            registration: Arc::new(()),
        };
        self.discovery_path_requests.insert(
            destination,
            DiscoveryOperation {
                id,
                timeout,
                requesters: vec![Waiter {
                    token: token.clone(),
                    channel,
                }],
            },
        );
        Ok(DiscoveryAdmission {
            requester: token,
            started: true,
        })
    }

    pub(super) fn finish_recursive_discovery(
        &mut self,
        destination: [u8; 16],
        response: &[u8],
        incoming: InterfaceId,
        now: f64,
    ) {
        let Some(operation) = self.discovery_path_requests.remove(&destination) else {
            return;
        };
        self.retire_orphaned_discovery_admissions();
        if !now.is_finite() || now >= operation.timeout {
            return;
        }
        for waiter in operation.requesters {
            let id = waiter.token.interface;
            let eligible = self.discovery_waiter_registered(&waiter)
                && self.interfaces.get(&id).is_some_and(|entry| {
                    !interface_marked_offline(entry)
                        // A radio can serve hidden peers; an IPC edge is one peer.
                        && (id != incoming || (entry.role == InterfaceRole::Normal
                            && entry.mode != InterfaceMode::Roaming))
                });
            if eligible {
                self.send_to_interface(id, response);
            }
        }
    }

    pub(super) fn retire_recursive_discovery_interface(&mut self, interface: InterfaceId) {
        self.discovery_path_requests.retain(|_, operation| {
            operation
                .requesters
                .retain(|waiter| waiter.token.interface != interface);
            !operation.requesters.is_empty()
        });
        self.retire_orphaned_discovery_admissions();
    }

    pub(super) fn cull_recursive_discovery(&mut self, now: f64) {
        let interfaces = &self.interfaces;
        self.discovery_path_requests
            .retain(|_, operation| retain_live_requesters(operation, interfaces, now));
        self.retire_orphaned_discovery_admissions();
    }
}

fn retain_live_requesters(
    operation: &mut DiscoveryOperation,
    interfaces: &HashMap<InterfaceId, InterfaceEntry>,
    now: f64,
) -> bool {
    operation.requesters.retain(|waiter| {
        interfaces
            .get(&waiter.token.interface)
            .is_some_and(|entry| {
                entry.direction.outbound
                    && !entry.tx.is_closed()
                    && entry.tx.same_channel(&waiter.channel)
            })
    });
    now.is_finite() && now < operation.timeout && !operation.requesters.is_empty()
}
