//! External-consumer compile contract for canonical and retained Reticulum paths.

/// Advanced actor ownership uses detached discovery snapshots, never map edits.
pub mod recursive_discovery {
    use rns_transport::actor::{DiscoveryPathRequest, TransportActor};
    use rns_transport::messages::InterfaceId;
    use rns_transport::path_discovery::{DiscoveryAdmission, DiscoveryError};

    pub fn request(
        actor: &mut TransportActor,
        destination: [u8; 16],
        interface: InterfaceId,
    ) -> Result<DiscoveryAdmission, DiscoveryError> {
        actor.request_recursive_discovery(destination, interface)
    }

    pub fn observe_and_cancel(actor: &mut TransportActor, destination: &[u8; 16]) {
        if let Some(snapshot) = actor.discovery_path_request(destination) {
            let _: DiscoveryPathRequest = snapshot.clone(); // retained import
            let _ = (snapshot.destination_hash(), snapshot.deadline());
            for requester in snapshot.requesters() {
                let _ = (requester.interface_id(), requester.destination_hash());
                actor.cancel_discovery_requester(requester);
            }
        }
        let _ = actor.discovery_path_requests();
    }
}

pub mod canonical {
    use rns_runtime::prelude::{
        AnnounceSubscription, DestinationResolveError, DestinationResolveOptions,
        LinkSessionHandle, PacketReceiptHandle, RecalledDestination, ReticulumHandle,
        resolve_destination_on_transport,
    };

    pub fn compile_surface() {
        let _ = resolve_destination_on_transport;
        let _ = std::mem::size_of::<DestinationResolveOptions>();
        let _ = std::mem::size_of::<DestinationResolveError>();
        let _ = std::mem::size_of::<ReticulumHandle>();
        let _ = std::mem::size_of::<RecalledDestination>();
        let _ = std::mem::size_of::<AnnounceSubscription>();
        let _ = std::mem::size_of::<PacketReceiptHandle>();
        let _ = std::mem::size_of::<LinkSessionHandle>();
        let _ = ReticulumHandle::path_recovery_handle;
        let _ = ReticulumHandle::link_endpoint_dispatch_handle;
        let _ = rns_runtime::prelude::PathRecoveryHandle::try_invalidate_packet;
        let _ = rns_runtime::prelude::PathRecoveryHandle::try_invalidate_link;
        let _ = std::mem::size_of::<rns_runtime::prelude::PathRecoveryHandle>();
        let _ = std::mem::size_of::<rns_runtime::prelude::PathRecoveryOutcome>();
        let _ = std::mem::size_of::<rns_runtime::prelude::PathRecoveryError>();
    }
}

/// Advanced ownership remains opt-in and module-qualified.
pub mod delivery_ownership {
    use rns_runtime::link_manager::{LinkManager, LinkManagerAccountingEvent};
    use rns_runtime::prelude::ReticulumHandle;

    pub fn install_dispatch(runtime: &ReticulumHandle, manager: &mut LinkManager) {
        manager.set_link_endpoint_dispatch_handle(runtime.link_endpoint_dispatch_handle());
    }

    pub fn observe_wait(event: &LinkManagerAccountingEvent) {
        match event {
            LinkManagerAccountingEvent::OutboundPacketWait {
                receipt,
                started_at,
                timeout,
                awaiting_admission,
                cancellation,
            } => {
                let _ = (
                    receipt.link_id,
                    receipt.packet_hash,
                    started_at,
                    timeout,
                    awaiting_admission,
                    cancellation,
                );
            }
            LinkManagerAccountingEvent::OutboundResourceWait {
                link_id,
                resource_id,
                started_at,
                timeout,
            } => {
                let _ = (link_id, resource_id, started_at, timeout);
            }
            _ => {}
        }
    }
}

pub mod legacy {
    use rns_runtime::destination_resolver::{
        DestinationResolveError, DestinationResolveOptions, resolve_destination_on_transport,
    };
    use rns_runtime::link_session::LinkSessionHandle;
    use rns_runtime::reticulum::{
        AnnounceSubscription, PacketReceiptHandle, RecalledDestination, ReticulumHandle,
    };

    pub fn compile_surface() {
        let _ = resolve_destination_on_transport;
        let _ = std::mem::size_of::<DestinationResolveOptions>();
        let _ = std::mem::size_of::<DestinationResolveError>();
        let _ = std::mem::size_of::<ReticulumHandle>();
        let _ = std::mem::size_of::<RecalledDestination>();
        let _ = std::mem::size_of::<AnnounceSubscription>();
        let _ = std::mem::size_of::<PacketReceiptHandle>();
        let _ = std::mem::size_of::<LinkSessionHandle>();
    }
}

/// Strict application ownership is additive; legacy imports above remain valid.
pub mod shared_ownership {
    use rns_runtime::shared_instance::{
        InstancePolicy, SharedInstanceCredentials, SharedInstanceEndpoint,
    };

    pub fn compile_surface() {
        let endpoint = SharedInstanceEndpoint::Tcp {
            packet_port: 37428,
            control_port: 37429,
        };
        let credentials = SharedInstanceCredentials::new(endpoint.clone(), vec![1; 17]).unwrap();
        let _ = InstancePolicy::SharedClient(credentials);
        let _ = InstancePolicy::SharedOwnerAt(endpoint);
        let _ = rns_runtime::reticulum::init_with_policy;
        let _ = rns_runtime::reticulum::ReticulumHandle::shared_instance_state;
        let _ = rns_runtime::reticulum::ReticulumHandle::startup_interface_failures;
    }
}
