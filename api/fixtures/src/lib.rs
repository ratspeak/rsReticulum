//! External-consumer compile contract for canonical and retained Reticulum paths.

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
        let _ = std::mem::size_of::<rns_runtime::prelude::PathRecoveryHandle>();
        let _ = std::mem::size_of::<rns_runtime::prelude::PathRecoveryOutcome>();
        let _ = std::mem::size_of::<rns_runtime::prelude::PathRecoveryError>();
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
