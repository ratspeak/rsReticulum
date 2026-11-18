use super::*;
use crate::messages::{DetachReason, InterfaceControl};
use crate::tunnel::{RemoteTransportInfo, TunnelExt, TunnelSynthesisData};

impl TransportActor {
    /// Python 1.6.1 `Transport.synthesize_tunnel` (Transport.py:3170-3206). An
    /// initiator sends while still offline and names its tunnel; a receiver's
    /// reverse synthesis answers a peer's extension.
    pub(super) fn synthesize_tunnel(&mut self, interface_id: InterfaceId, reverse: bool) {
        let Some(identity) = self
            .tunnel_identity
            .clone()
            .filter(|identity| Some(identity.hash) == self.transport_identity_hash)
        else {
            debug!(
                interface_id,
                "no transport identity to sign a tunnel synthesis"
            );
            return;
        };
        let Some(entry) = self.interfaces.get(&interface_id) else {
            return;
        };
        let interface_hash = crate::tunnel::interface_hash(entry.upstream_name());
        let ext = TunnelExt::local(
            self.is_transport_enabled,
            self.interface_destination_cost(interface_id),
            self.interface_pr_cost(interface_id),
        );
        let Some(raw) =
            crate::tunnel::build_tunnel_synthesis_packet_with_ext(&identity, interface_hash, &ext)
        else {
            return;
        };
        let tunnel_id = TunnelSynthesisData::unpack(&raw[rns_wire::constants::HEADER_MINSIZE..])
            .map(|synthesis| synthesis.tunnel_id());
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            entry.tunnel.synthesis_emitted = true;
            if !reverse {
                entry.tunnel.local_tunnel_id = tunnel_id;
            }
        }
        debug!(
            interface_id,
            reverse,
            len = raw.len(),
            "sending tunnel synthesis"
        );
        if reverse {
            self.send_to_interface(interface_id, &raw);
        } else {
            // The driver queues it just before the interface reports online.
            self.send_to_interface_unchecked(interface_id, &raw);
        }
    }

    /// Python 1.6.1 `Transport.tunnel_synthesize_handler` (Transport.py:3208-3297).
    pub(super) fn tunnel_synthesize_handler(&mut self, data: &[u8], interface_id: InterfaceId) {
        let Some(entry) = self.interfaces.get_mut(&interface_id) else {
            return;
        };
        if !entry.tunnels_allowed() {
            return;
        }
        if entry.tunnel.remote_transport.is_some() || entry.tunnel.synthesis_received {
            debug!(interface_id, "additional tunnel synthesis");
            self.protocol_violation(interface_id);
            return;
        }
        // One chance per connection, spent before any check.
        entry.tunnel.synthesis_received = true;
        let Some(synthesis) = TunnelSynthesisData::unpack(data) else {
            debug!(
                interface_id,
                len = data.len(),
                "tunnel synthesis of invalid size"
            );
            self.protocol_violation(interface_id);
            return;
        };
        if !synthesis.is_signed() {
            self.request_detach(interface_id, DetachReason::InvalidSynthesis);
            return;
        }
        let remote_transport = synthesis.transport_identity_hash();
        if self.blackhole_table.is_blackholed(&remote_transport) {
            self.request_detach(interface_id, DetachReason::BlackholedTransport);
            return;
        }
        let remote_info = if synthesis.ext.is_empty() {
            None
        } else {
            match RemoteTransportInfo::decode(&synthesis.ext) {
                Ok(info) => Some(info),
                Err(error) => {
                    debug!(interface_id, ?error, "invalid tunnel synthesis extension");
                    self.protocol_violation(interface_id);
                    return;
                }
            }
        };
        // Only an extension asks for an answer; the answer never asks again.
        if remote_info.is_some()
            && self
                .interfaces
                .get(&interface_id)
                .is_some_and(|entry| !entry.tunnel.synthesis_emitted)
        {
            self.synthesize_tunnel(interface_id, true);
        }
        let Some(entry) = self.interfaces.get_mut(&interface_id) else {
            return;
        };
        entry.tunnel.remote_transport = Some(remote_transport);
        entry.tunnel.remote_info = remote_info;
        // An initiator learns its peer; only a receiver binds the tunnel.
        if entry.tunnel.local_tunnel_id.is_some() {
            return;
        }
        let tunnel_id = synthesis.tunnel_id();
        debug!(
            tunnel_id = hex::encode(&tunnel_id[..16]),
            interface_id, "tunnel synthesis validated"
        );
        crate::tunnel::handle_tunnel(&mut self.tunnel_table, tunnel_id, interface_id);
        self.state_dirty = true;
        self.restore_tunnel_paths(&tunnel_id, interface_id);
    }

    /// Python `_detach_interface(None, interface_instance=..., internal_forced=True)`.
    /// The embedder stops the driver; without one, the actor drops the
    /// interface itself. Frames from it are ignored until it is gone.
    pub(super) fn request_detach(&mut self, interface_id: InterfaceId, reason: DetachReason) {
        if !self.interfaces.contains_key(&interface_id) || !self.detaching.insert(interface_id) {
            return;
        }
        tracing::info!(interface_id, ?reason, "tearing down tunnel interface");
        let sent = self.interface_control.as_ref().is_some_and(|control| {
            control
                .send(InterfaceControl::Detach {
                    interface_id,
                    reason,
                })
                .is_ok()
        });
        if !sent {
            self.deregister_interface(interface_id);
        }
    }

    /// Python 1.6.1 `remove_blackholed_paths` also tears down every interface
    /// whose tunnel peer is blackholed (Transport.py:4832-4839).
    pub(super) fn detach_blackholed_tunnel_peers(&mut self) {
        let blackholed: Vec<InterfaceId> = self
            .interfaces
            .iter()
            .filter(|(_, entry)| {
                entry
                    .tunnel
                    .remote_transport
                    .is_some_and(|remote| self.blackhole_table.is_blackholed(&remote))
            })
            .map(|(id, _)| *id)
            .collect();
        for interface_id in blackholed {
            self.request_detach(interface_id, DetachReason::BlackholedTransport);
        }
    }

    /// Frames from an interface transport asked to detach.
    pub(super) fn is_detaching(&self, interface_id: InterfaceId) -> bool {
        self.detaching.contains(&interface_id)
    }
}
