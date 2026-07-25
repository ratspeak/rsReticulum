//! Reticulum runtime: config, lifecycle, RPC, and the [`reticulum::ReticulumHandle`]
//! that user code holds. Python reference: `RNS/Reticulum.py`.

pub mod buffer_stream;
pub mod config;
pub mod constants;
pub mod destination_runtime;
pub mod interface_factory;
pub mod jobs;
pub mod lifecycle;
pub mod link_client;
pub mod link_manager;
pub mod link_session;
pub mod platform;
pub mod probe;
pub mod remote_management;
pub mod remote_management_schema;
pub mod resource_source;
pub mod reticulum;
pub mod rncp;
pub mod rnsh;
pub mod rpc;
pub mod rpc_server;

/// Common application-facing types for Reticulum programs.
///
/// This is additive convenience; module-qualified paths remain supported.
pub mod prelude {
    pub use crate::destination_runtime::{
        DestinationEvents, DestinationHandle, DestinationPacket, DestinationRuntimeError,
        DestinationRuntimeOptions, RegisteredDestination,
    };
    pub use crate::lifecycle::ShutdownSignal;
    pub use crate::link_manager::{DestinationAnnounceOptions, DestinationRequest, RequestOutcome};
    pub use crate::link_session::{
        LinkSession, LinkSessionChannelError, LinkSessionChannelHandle, LinkSessionCloseReason,
        LinkSessionError, LinkSessionEvent, LinkSessionHandle, LinkSessionResourceError,
        LinkSessionResourceOffer, LinkSessionResponse,
    };
    pub use crate::resource_source::{ResourceOptions, ResourceSource};
    pub use crate::reticulum::{
        AnnounceSubscription, ControlError, InitOptions, InterfaceStats, LinkConnectError,
        LinkConnectOptions, OutboundPacket, PacketReceiptHandle, PacketReceiptStatus,
        RecalledDestination, ReceiptError, ReticulumError, ReticulumHandle, SendError, SendOptions,
        SendResult, init, init_with_options,
    };
    pub use rns_identity::destination::{
        AllowPolicy, DestType, Destination, Direction, ProofStrategy,
    };
    pub use rns_identity::identity::Identity;
    pub use rns_link::link::{CloseReason, ResourceStrategy};
}
