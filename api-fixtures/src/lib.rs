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
