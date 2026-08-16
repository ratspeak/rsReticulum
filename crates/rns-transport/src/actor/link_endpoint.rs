use super::*;

impl TransportActor {
    pub(super) fn bind_link_endpoint(
        &mut self,
        binding: crate::messages::LinkEndpointBinding,
        lifecycle_tx: mpsc::UnboundedSender<crate::messages::LinkEndpointLifecycleEvent>,
    ) -> crate::messages::LinkEndpointBindResult {
        use crate::messages::LinkEndpointBindResult;

        let key = (binding.link_id, binding.role);
        if let Some(existing) = self.link_endpoints.get(&key) {
            return if existing.binding == binding {
                LinkEndpointBindResult::AlreadyBound
            } else {
                LinkEndpointBindResult::Conflict {
                    interface_id: existing.binding.interface_id,
                    role: existing.binding.role,
                }
            };
        }

        if !self.link_endpoint_interface_available(binding) {
            return LinkEndpointBindResult::InterfaceUnavailable;
        }

        self.link_endpoints.insert(
            key,
            LinkEndpointEntry {
                binding,
                lifecycle_tx,
                egress: VecDeque::new(),
                unbind_after_drain: false,
            },
        );
        debug!(
            link_id = %hex::encode(binding.link_id),
            interface_id = binding.interface_id,
            role = ?binding.role,
            "bound established Link endpoint"
        );
        LinkEndpointBindResult::Bound
    }

    pub(super) fn unbind_link_endpoint(
        &mut self,
        link_id: [u8; 16],
        role: crate::messages::LinkEndpointRole,
    ) -> crate::messages::LinkEndpointUnbindResult {
        use crate::messages::LinkEndpointUnbindResult;

        let key = (link_id, role);
        if let Some(entry) = self.link_endpoints.remove(&key) {
            self.notify_link_endpoint_terminal(
                entry,
                crate::messages::LinkEndpointTerminalReason::Unbound,
                0,
            );
            LinkEndpointUnbindResult::Unbound
        } else if self
            .link_endpoints
            .keys()
            .any(|(candidate, _)| candidate == &link_id)
        {
            LinkEndpointUnbindResult::RoleMismatch
        } else {
            LinkEndpointUnbindResult::NotBound
        }
    }

    pub(super) fn send_link_endpoint(
        &mut self,
        link_id: [u8; 16],
        role: crate::messages::LinkEndpointRole,
        request: crate::messages::OutboundRequest,
    ) -> crate::messages::LinkEndpointSendResult {
        use crate::messages::{LinkEndpointSendResult, LinkEndpointTerminalReason};

        let key = (link_id, role);
        if !self.link_endpoints.contains_key(&key) {
            return if self
                .link_endpoints
                .keys()
                .any(|(candidate, _)| candidate == &link_id)
            {
                LinkEndpointSendResult::RoleMismatch
            } else {
                LinkEndpointSendResult::NotBound
            };
        }
        if self.link_endpoints[&key].unbind_after_drain {
            return LinkEndpointSendResult::Terminated(LinkEndpointTerminalReason::Unbound);
        }

        let interface_id = self.link_endpoints[&key].binding.interface_id;
        // Give previously admitted packets first claim on newly available
        // interface capacity before considering the new packet.
        if !self.link_endpoints[&key].egress.is_empty() {
            if let Err(reason) = self.drain_one_link_endpoint(key) {
                return LinkEndpointSendResult::Terminated(reason);
            }
        }

        if self.link_endpoints[&key].egress.len() >= LINK_ENDPOINT_EGRESS_QUEUE_CAPACITY {
            self.terminate_link_endpoint(key, LinkEndpointTerminalReason::EgressQueueExhausted, 0);
            return LinkEndpointSendResult::Terminated(
                LinkEndpointTerminalReason::EgressQueueExhausted,
            );
        }

        let Some(raw) = self.prepare_link_endpoint_packet(link_id, interface_id, request) else {
            return LinkEndpointSendResult::InvalidPacket;
        };

        if !self.link_endpoints.contains_key(&key) {
            return LinkEndpointSendResult::NotBound;
        }

        if !self.link_endpoints[&key].egress.is_empty() {
            return self.enqueue_link_endpoint_packet(key, raw);
        }

        match self.try_send_link_endpoint_raw(interface_id, link_id, role, &raw) {
            InterfaceSendOutcome::Sent => LinkEndpointSendResult::Sent,
            InterfaceSendOutcome::Full => self.enqueue_link_endpoint_packet(key, raw),
            outcome => {
                let reason = terminal_reason_for_interface_outcome(outcome)
                    .expect("non-full, non-sent interface outcome must be terminal");
                if matches!(
                    outcome,
                    InterfaceSendOutcome::Closed | InterfaceSendOutcome::Offline
                ) && interface_id != LOCAL_LINK_INITIATOR_INTERFACE
                    && interface_id != LOCAL_LINK_RESPONDER_INTERFACE
                {
                    self.deregister_interface_with_link_reason(interface_id, reason);
                } else {
                    self.terminate_link_endpoint(key, reason, 0);
                }
                LinkEndpointSendResult::Terminated(reason)
            }
        }
    }

    pub(super) fn send_link_endpoint_and_unbind(
        &mut self,
        link_id: [u8; 16],
        role: crate::messages::LinkEndpointRole,
        request: crate::messages::OutboundRequest,
    ) -> crate::messages::LinkEndpointSendResult {
        use crate::messages::{LinkEndpointSendResult, LinkEndpointTerminalReason};

        let result = self.send_link_endpoint(link_id, role, request);
        let key = (link_id, role);
        match result {
            LinkEndpointSendResult::Sent => {
                if let Some(entry) = self.link_endpoints.remove(&key) {
                    self.notify_link_endpoint_terminal(
                        entry,
                        LinkEndpointTerminalReason::Unbound,
                        0,
                    );
                }
            }
            LinkEndpointSendResult::Queued { .. } => {
                if let Some(entry) = self.link_endpoints.get_mut(&key) {
                    entry.unbind_after_drain = true;
                }
            }
            _ => {}
        }
        result
    }

    pub(super) fn send_link_endpoint_best_effort(
        &mut self,
        link_id: [u8; 16],
        role: crate::messages::LinkEndpointRole,
        request: crate::messages::OutboundRequest,
    ) -> crate::messages::LinkEndpointSendResult {
        use crate::messages::{LinkEndpointSendResult, LinkEndpointTerminalReason};

        let key = (link_id, role);
        if !self.link_endpoints.contains_key(&key) {
            return if self
                .link_endpoints
                .keys()
                .any(|(candidate, _)| candidate == &link_id)
            {
                LinkEndpointSendResult::RoleMismatch
            } else {
                LinkEndpointSendResult::NotBound
            };
        }
        if self.link_endpoints[&key].unbind_after_drain {
            return LinkEndpointSendResult::Terminated(LinkEndpointTerminalReason::Unbound);
        }

        // Realtime media must never jump ahead of retained signalling or
        // teardown, and it must not enlarge that reliable FIFO.
        if !self.link_endpoints[&key].egress.is_empty() {
            return LinkEndpointSendResult::DroppedBackpressure;
        }

        let interface_id = self.link_endpoints[&key].binding.interface_id;
        let Some(raw) = self.prepare_link_endpoint_packet(link_id, interface_id, request) else {
            return LinkEndpointSendResult::InvalidPacket;
        };
        if !self.link_endpoints.contains_key(&key) {
            return LinkEndpointSendResult::NotBound;
        }

        match self.try_send_link_endpoint_raw(interface_id, link_id, role, &raw) {
            InterfaceSendOutcome::Sent => LinkEndpointSendResult::Sent,
            InterfaceSendOutcome::Full => {
                if let Some(entry) = self.interfaces.get(&interface_id) {
                    entry
                        .tx_drops
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                LinkEndpointSendResult::DroppedBackpressure
            }
            outcome => {
                let reason = terminal_reason_for_interface_outcome(outcome)
                    .expect("non-full, non-sent interface outcome must be terminal");
                if matches!(
                    outcome,
                    InterfaceSendOutcome::Closed | InterfaceSendOutcome::Offline
                ) && interface_id != LOCAL_LINK_INITIATOR_INTERFACE
                    && interface_id != LOCAL_LINK_RESPONDER_INTERFACE
                {
                    self.deregister_interface_with_link_reason(interface_id, reason);
                } else {
                    self.terminate_link_endpoint(key, reason, 0);
                }
                LinkEndpointSendResult::Terminated(reason)
            }
        }
    }

    fn prepare_link_endpoint_packet(
        &mut self,
        link_id: [u8; 16],
        interface_id: InterfaceId,
        request: crate::messages::OutboundRequest,
    ) -> Option<Bytes> {
        // The packet-count FIFO is also a hard byte bound because every
        // admitted packet must fit Reticulum's wire MTU. Do not let a caller
        // smuggle an arbitrarily large allocation into an established-Link
        // queue through the raw transport API.
        if request.raw.len() > rns_wire::constants::MTU {
            return None;
        }
        if request.destination_hash != link_id {
            return None;
        }
        let (header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).ok()?;
        if header.destination_hash != link_id
            || header.flags.destination_type != rns_wire::flags::DestinationType::Link
        {
            return None;
        }

        self.traffic.record_tx(0, request.raw.len() as u64);
        let packet_hash = rns_wire::hash::packet_hash(&request.raw, header.flags.header_type);
        self.packet_hashlist.insert(packet_hash);

        if interface_id != LOCAL_LINK_INITIATOR_INTERFACE
            && interface_id != LOCAL_LINK_RESPONDER_INTERFACE
            && self.should_apply_delta(&header, interface_id)
        {
            Some(Bytes::from(self.mangle_hops(&request.raw, &header, false)))
        } else {
            Some(request.raw)
        }
    }

    fn enqueue_link_endpoint_packet(
        &mut self,
        key: ([u8; 16], crate::messages::LinkEndpointRole),
        raw: Bytes,
    ) -> crate::messages::LinkEndpointSendResult {
        use crate::messages::{LinkEndpointSendResult, LinkEndpointTerminalReason};

        let entry = self
            .link_endpoints
            .get_mut(&key)
            .expect("validated Link endpoint disappeared before enqueue");
        if entry.egress.len() >= LINK_ENDPOINT_EGRESS_QUEUE_CAPACITY {
            self.terminate_link_endpoint(key, LinkEndpointTerminalReason::EgressQueueExhausted, 0);
            return LinkEndpointSendResult::Terminated(
                LinkEndpointTerminalReason::EgressQueueExhausted,
            );
        }
        entry.egress.push_back(raw);
        LinkEndpointSendResult::Queued {
            depth: entry.egress.len(),
        }
    }

    pub(super) fn drain_link_endpoint_egress(&mut self) {
        let keys: Vec<_> = self.link_endpoints.keys().copied().collect();
        for key in keys {
            let _ = self.drain_one_link_endpoint(key);
        }
    }

    /// Returns the terminal reason if the endpoint became terminal while
    /// draining. `Ok(())` means the FIFO is either empty or still waiting for
    /// interface capacity.
    fn drain_one_link_endpoint(
        &mut self,
        key: ([u8; 16], crate::messages::LinkEndpointRole),
    ) -> Result<(), crate::messages::LinkEndpointTerminalReason> {
        let Some(mut entry) = self.link_endpoints.remove(&key) else {
            return Err(crate::messages::LinkEndpointTerminalReason::InterfaceRemoved);
        };

        while let Some(raw) = entry.egress.front() {
            match self.try_send_link_endpoint_raw(
                entry.binding.interface_id,
                entry.binding.link_id,
                entry.binding.role,
                raw,
            ) {
                InterfaceSendOutcome::Sent => {
                    entry.egress.pop_front();
                }
                InterfaceSendOutcome::Full => {
                    self.link_endpoints.insert(key, entry);
                    return Ok(());
                }
                outcome => {
                    let reason = terminal_reason_for_interface_outcome(outcome)
                        .expect("non-full, non-sent interface outcome must be terminal");
                    let interface_id = entry.binding.interface_id;
                    self.notify_link_endpoint_terminal(entry, reason, 0);
                    if matches!(
                        outcome,
                        InterfaceSendOutcome::Closed | InterfaceSendOutcome::Offline
                    ) && interface_id != LOCAL_LINK_INITIATOR_INTERFACE
                        && interface_id != LOCAL_LINK_RESPONDER_INTERFACE
                    {
                        // The endpoint has already been removed. Remove every
                        // sibling endpoint attached to the failed interface.
                        self.deregister_interface_with_link_reason(interface_id, reason);
                    }
                    return Err(reason);
                }
            }
        }

        if entry.unbind_after_drain {
            self.notify_link_endpoint_terminal(
                entry,
                crate::messages::LinkEndpointTerminalReason::Unbound,
                0,
            );
        } else {
            self.link_endpoints.insert(key, entry);
        }
        Ok(())
    }

    fn try_send_link_endpoint_raw(
        &mut self,
        interface_id: InterfaceId,
        link_id: [u8; 16],
        role: crate::messages::LinkEndpointRole,
        raw: &[u8],
    ) -> InterfaceSendOutcome {
        use crate::messages::LinkEndpointRole;

        let local_target = match (interface_id, role) {
            (LOCAL_LINK_INITIATOR_INTERFACE, LinkEndpointRole::Initiator) => self
                .local_link_routes
                .get(&link_id)
                .map(|route| (&route.responder_tx, LOCAL_LINK_RESPONDER_INTERFACE)),
            (LOCAL_LINK_RESPONDER_INTERFACE, LinkEndpointRole::Responder) => self
                .local_link_routes
                .get(&link_id)
                .map(|route| (&route.initiator_tx, LOCAL_LINK_INITIATOR_INTERFACE)),
            (LOCAL_LINK_INITIATOR_INTERFACE | LOCAL_LINK_RESPONDER_INTERFACE, _) => {
                return InterfaceSendOutcome::Missing;
            }
            _ => return self.try_send_to_interface(interface_id, raw),
        };

        let Some((target, target_interface)) = local_target else {
            return InterfaceSendOutcome::Missing;
        };
        let event = crate::link_messages::DestinationEvent::InboundPacket {
            raw: Bytes::copy_from_slice(raw),
            interface_id: target_interface,
            metrics: PacketMetrics::default(),
        };
        match target.try_send(event) {
            Ok(()) => {
                self.traffic.record_rx(0, raw.len() as u64);
                InterfaceSendOutcome::Sent
            }
            Err(mpsc::error::TrySendError::Full(_)) => InterfaceSendOutcome::Full,
            Err(mpsc::error::TrySendError::Closed(_)) => InterfaceSendOutcome::Closed,
        }
    }

    fn link_endpoint_interface_available(
        &self,
        binding: crate::messages::LinkEndpointBinding,
    ) -> bool {
        use crate::messages::LinkEndpointRole;

        match (binding.interface_id, binding.role) {
            (LOCAL_LINK_INITIATOR_INTERFACE, LinkEndpointRole::Initiator)
            | (LOCAL_LINK_RESPONDER_INTERFACE, LinkEndpointRole::Responder) => {
                self.local_link_routes.contains_key(&binding.link_id)
            }
            (LOCAL_LINK_INITIATOR_INTERFACE | LOCAL_LINK_RESPONDER_INTERFACE, _) => false,
            (interface_id, _) => self.interfaces.get(&interface_id).is_some_and(|entry| {
                entry.direction.outbound
                    && !entry.tx.is_closed()
                    && !(entry.role == InterfaceRole::LocalClient
                        && interface_marked_offline(entry))
            }),
        }
    }

    pub(super) fn terminate_link_endpoints_for_interface(
        &mut self,
        interface_id: InterfaceId,
        reason: crate::messages::LinkEndpointTerminalReason,
    ) {
        let keys: Vec<_> = self
            .link_endpoints
            .iter()
            .filter_map(|(key, entry)| (entry.binding.interface_id == interface_id).then_some(*key))
            .collect();
        for key in keys {
            self.terminate_link_endpoint(key, reason, 0);
        }
    }

    pub(super) fn terminate_link_endpoints_for_link(
        &mut self,
        link_id: [u8; 16],
        reason: crate::messages::LinkEndpointTerminalReason,
    ) {
        let keys: Vec<_> = self
            .link_endpoints
            .keys()
            .filter(|(candidate, _)| *candidate == link_id)
            .copied()
            .collect();
        for key in keys {
            self.terminate_link_endpoint(key, reason, 0);
        }
    }

    pub(super) fn terminate_shared_peer_link_endpoints(&mut self) {
        let interface_ids: Vec<_> = self
            .interfaces
            .iter()
            .filter_map(|(id, entry)| {
                (entry.role == InterfaceRole::SharedInstancePeer).then_some(*id)
            })
            .collect();
        for interface_id in interface_ids {
            self.terminate_link_endpoints_for_interface(
                interface_id,
                crate::messages::LinkEndpointTerminalReason::InterfaceOffline,
            );
        }
    }

    pub(super) fn terminate_all_link_endpoints(
        &mut self,
        reason: crate::messages::LinkEndpointTerminalReason,
    ) {
        let keys: Vec<_> = self.link_endpoints.keys().copied().collect();
        for key in keys {
            self.terminate_link_endpoint(key, reason, 0);
        }
    }

    fn terminate_link_endpoint(
        &mut self,
        key: ([u8; 16], crate::messages::LinkEndpointRole),
        reason: crate::messages::LinkEndpointTerminalReason,
        extra_dropped: usize,
    ) {
        if let Some(entry) = self.link_endpoints.remove(&key) {
            self.notify_link_endpoint_terminal(entry, reason, extra_dropped);
        }
    }

    fn notify_link_endpoint_terminal(
        &self,
        entry: LinkEndpointEntry,
        reason: crate::messages::LinkEndpointTerminalReason,
        extra_dropped: usize,
    ) {
        let event = crate::messages::LinkEndpointLifecycleEvent {
            binding: entry.binding,
            reason,
            dropped_packets: entry.egress.len().saturating_add(extra_dropped),
        };
        let _ = entry.lifecycle_tx.send(event);
        debug!(
            link_id = %hex::encode(entry.binding.link_id),
            interface_id = entry.binding.interface_id,
            role = ?entry.binding.role,
            ?reason,
            dropped_packets = event.dropped_packets,
            "terminated established Link endpoint"
        );
    }
}

fn terminal_reason_for_interface_outcome(
    outcome: InterfaceSendOutcome,
) -> Option<crate::messages::LinkEndpointTerminalReason> {
    use crate::messages::LinkEndpointTerminalReason;
    match outcome {
        InterfaceSendOutcome::Sent | InterfaceSendOutcome::Full => None,
        InterfaceSendOutcome::Missing => Some(LinkEndpointTerminalReason::InterfaceRemoved),
        InterfaceSendOutcome::Closed => Some(LinkEndpointTerminalReason::InterfaceClosed),
        InterfaceSendOutcome::Offline => Some(LinkEndpointTerminalReason::InterfaceOffline),
        InterfaceSendOutcome::NotOutbound => Some(LinkEndpointTerminalReason::InterfaceNotOutbound),
    }
}
