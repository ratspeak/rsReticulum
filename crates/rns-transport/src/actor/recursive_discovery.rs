//! Compatible, bounded ownership for coalesced recursive path discovery.
//!
//! The public Copy record retains the first requester for compatibility. This
//! private ledger owns the actual live requester generations; coalescing never
//! changes the original operation's deadline or emits another recursive fanout.
use super::*;

const MAX_DISCOVERY_DESTINATIONS: usize = 1024;
const MAX_DISCOVERY_REQUESTERS: usize = 64;

pub(super) struct RecursiveDiscoveryWaiters {
    owner: DiscoveryPathRequest,
    interfaces: Vec<(InterfaceId, mpsc::Sender<Bytes>)>,
}

fn same_owner(left: DiscoveryPathRequest, right: DiscoveryPathRequest) -> bool {
    left.requesting_interface == right.requesting_interface && left.timeout == right.timeout
}

impl TransportActor {
    pub(super) fn cancel_recursive_discovery(&mut self) {
        self.discovery_path_requests.clear();
        self.recursive_discovery_waiters.clear();
        self.retire_recursive_path_request_admissions();
    }

    /// This clock covers the request/response on a useful outbound medium, not
    /// caller timeout, queued frame age, or a promised multi-hop RF duration.
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

    /// Return true only for a new admitted operation that needs its one fanout.
    pub(super) fn begin_or_join_recursive_discovery(
        &mut self,
        destination: [u8; 16],
        requester: InterfaceId,
        now: f64,
    ) -> bool {
        if self
            .discovery_path_requests
            .get(&destination)
            .is_some_and(|owner| now >= owner.timeout || !owner.timeout.is_finite())
        {
            self.discovery_path_requests.remove(&destination);
            self.recursive_discovery_waiters.remove(&destination);
        }
        let Some(requester_tx) = self
            .interfaces
            .get(&requester)
            .filter(|entry| entry.direction.outbound && !entry.tx.is_closed())
            .map(|entry| entry.tx.clone())
        else {
            return false;
        };
        if let Some(owner) = self.discovery_path_requests.get(&destination).copied() {
            if !self.recursive_discovery_waiters.contains_key(&destination)
                && self.recursive_discovery_waiters.len() >= MAX_DISCOVERY_DESTINATIONS
            {
                self.cull_recursive_discovery(now);
                if self.recursive_discovery_waiters.len() >= MAX_DISCOVERY_DESTINATIONS {
                    debug!("recursive discovery private requester inventory exhausted");
                    return false;
                }
            }
            // Externally inserted legacy records remain usable. Their first
            // requester is adopted only from the currently registered channel;
            // replacement/removal hooks retire legacy records before ID reuse.
            if self
                .recursive_discovery_waiters
                .get(&destination)
                .is_none_or(|waiters| !same_owner(waiters.owner, owner))
            {
                let interfaces = self
                    .interfaces
                    .get(&owner.requesting_interface)
                    .map(|entry| vec![(owner.requesting_interface, entry.tx.clone())])
                    .unwrap_or_default();
                self.recursive_discovery_waiters
                    .insert(destination, RecursiveDiscoveryWaiters { owner, interfaces });
            }
            let waiters = self
                .recursive_discovery_waiters
                .get_mut(&destination)
                .unwrap();
            if !waiters
                .interfaces
                .iter()
                .any(|(id, tx)| *id == requester && tx.same_channel(&requester_tx))
            {
                if waiters.interfaces.len() < MAX_DISCOVERY_REQUESTERS {
                    waiters.interfaces.push((requester, requester_tx));
                } else {
                    debug!(
                        requester,
                        "recursive discovery requester capacity exhausted"
                    );
                }
            }
            return false;
        }
        if self.discovery_path_requests.len() >= MAX_DISCOVERY_DESTINATIONS {
            self.cull_recursive_discovery(now);
            if self.discovery_path_requests.len() >= MAX_DISCOVERY_DESTINATIONS {
                debug!("recursive discovery destination capacity exhausted");
                return false;
            }
        }
        let owner = DiscoveryPathRequest {
            requesting_interface: requester,
            timeout: now + self.recursive_discovery_timeout(requester),
        };
        self.discovery_path_requests.insert(destination, owner);
        self.recursive_discovery_waiters.insert(
            destination,
            RecursiveDiscoveryWaiters {
                owner,
                interfaces: vec![(requester, requester_tx)],
            },
        );
        true
    }

    pub(super) fn finish_recursive_discovery(
        &mut self,
        destination: [u8; 16],
        response: &[u8],
        incoming: InterfaceId,
        now: f64,
    ) {
        let Some(owner) = self.discovery_path_requests.remove(&destination) else {
            self.recursive_discovery_waiters.remove(&destination);
            return;
        };
        let waiters = self.recursive_discovery_waiters.remove(&destination);
        if now >= owner.timeout || !owner.timeout.is_finite() {
            return;
        }
        let interfaces = match waiters {
            Some(waiters) if same_owner(waiters.owner, owner) => waiters.interfaces,
            _ => self
                .interfaces
                .get(&owner.requesting_interface)
                .map(|entry| vec![(owner.requesting_interface, entry.tx.clone())])
                .unwrap_or_default(),
        };
        for (id, generation) in interfaces {
            let eligible = self.interfaces.get(&id).is_some_and(|entry| {
                entry.direction.outbound && !interface_marked_offline(entry)
                    && entry.tx.same_channel(&generation)
                    // An IPC edge names one peer. A radio can name hidden
                    // neighbors; retain only the explicit same-Roaming veto.
                    && (id != incoming || (entry.role == InterfaceRole::Normal
                        && entry.mode != InterfaceMode::Roaming))
            });
            if eligible {
                self.send_to_interface(id, response);
            }
        }
    }

    pub(super) fn retire_recursive_discovery_interface(&mut self, interface: InterfaceId) {
        let mut retired = Vec::new();
        for (destination, owner) in &self.discovery_path_requests {
            match self.recursive_discovery_waiters.get_mut(destination) {
                Some(waiters) if same_owner(waiters.owner, *owner) => {
                    waiters.interfaces.retain(|(id, _)| *id != interface);
                    if waiters.interfaces.is_empty() {
                        retired.push(*destination);
                    }
                }
                _ if owner.requesting_interface == interface => retired.push(*destination),
                _ => {}
            }
        }
        for destination in retired {
            self.discovery_path_requests.remove(&destination);
            self.recursive_discovery_waiters.remove(&destination);
        }
    }

    pub(super) fn cull_recursive_discovery(&mut self, now: f64) {
        self.discovery_path_requests
            .retain(|_, owner| owner.timeout.is_finite() && now < owner.timeout);
        self.recursive_discovery_waiters
            .retain(|destination, waiters| {
                self.discovery_path_requests
                    .get(destination)
                    .is_some_and(|owner| same_owner(waiters.owner, *owner))
            });
    }
}
