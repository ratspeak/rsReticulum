//! Bounded recursive discovery observations for advanced transport owners.
//!
//! Applications normally use the runtime path request and finite resolver APIs.
//! These types support synchronous [`crate::actor::TransportActor`] owners;
//! they create no second worker, shared-instance RPC or delivery promise.
use crate::messages::InterfaceId;
use std::sync::Arc;

/// Exact requester registration in one discovery operation and actor.
/// Clones refer to the same registration. Dropping a token does not cancel it;
/// use [`crate::actor::TransportActor::cancel_discovery_requester`]. It cannot
/// cancel a later registration, replacement interface or another actor's work.
/// It contains no interface sender and cannot send bytes.
#[derive(Debug, Clone)]
pub struct DiscoveryRequester {
    pub(crate) destination: [u8; 16],
    pub(crate) interface: InterfaceId,
    pub(crate) operation: Arc<()>,
    pub(crate) registration: Arc<()>,
}

impl DiscoveryRequester {
    /// Destination being sought.
    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination
    }
    /// Numeric ID at registration, not authority over a replacement interface.
    pub fn interface_id(&self) -> InterfaceId {
        self.interface
    }
}

impl PartialEq for DiscoveryRequester {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.operation, &other.operation)
            && Arc::ptr_eq(&self.registration, &other.registration)
    }
}
impl Eq for DiscoveryRequester {}

/// Detached read-only snapshot of one pending recursive search.
///
/// Since 1.3, replaces the legacy single-requester public fields and `Copy`
/// contract. Accessors describe the observation instant, not a live view.
/// Changing/dropping a snapshot cannot modify the actor. The historical first
/// requester is deliberately not privileged.
///
/// ```compile_fail
/// use rns_transport::actor::TransportActor;
/// let (mut actor, _) = TransportActor::new();
/// actor.discovery_path_requests.clear(); // the canonical map is private
/// ```
///
/// ```compile_fail
/// use rns_transport::actor::DiscoveryPathRequest;
/// fn renew(snapshot: &mut DiscoveryPathRequest) {
///     snapshot.timeout = f64::INFINITY; // no mutable deadline authority
/// }
/// ```
///
/// ```compile_fail
/// use rns_transport::actor::DiscoveryPathRequest;
/// fn requires_copy<T: Copy>() {}
/// requires_copy::<DiscoveryPathRequest>(); // snapshot ownership is explicit
/// ```
#[derive(Debug, Clone)]
pub struct DiscoveryPathRequest {
    pub(crate) destination: [u8; 16],
    pub(crate) timeout: f64,
    pub(crate) requesters: Vec<DiscoveryRequester>,
}

impl DiscoveryPathRequest {
    /// Destination being sought.
    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination
    }
    /// Original absolute expiry in Unix seconds using the transport timebase.
    /// Joining never renews it. Not a caller or arbitrary multi-hop RF deadline.
    pub fn deadline(&self) -> f64 {
        self.timeout
    }
    /// All still-registered, open outbound requester generations at observation.
    /// Offline registrations can remain pending but receive no response while
    /// offline. Multiple radio peers may share one interface registration.
    pub fn requesters(&self) -> &[DiscoveryRequester] {
        &self.requesters
    }
}

/// Successful local ownership admission, not transmission/delivery evidence.
#[derive(Debug, Clone)]
pub struct DiscoveryAdmission {
    pub(crate) requester: DiscoveryRequester,
    pub(crate) started: bool,
}
impl DiscoveryAdmission {
    /// Exact registration; repeating a join returns the same token.
    pub fn requester(&self) -> &DiscoveryRequester {
        &self.requester
    }
    /// A new operation was created and its one fanout requested. Driver policy
    /// and backpressure may still prevent or defer actual transmission.
    pub fn started(&self) -> bool {
        self.started
    }
}

/// Recursive search could not acquire ownership; no requester was admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// Recursive transport forwarding is disabled.
    TransportDisabled,
    /// Selected interface is not registered.
    UnknownInterface,
    /// Interface is closed, offline or input-only.
    InterfaceUnavailable,
    /// Interface role, discovery mode or ingress policy forbids the operation.
    PolicyDenied,
    /// Use normal path resolution/requests for a known or local destination.
    KnownDestination,
    /// Bounded destination or requester inventory is full.
    Capacity,
    /// The clock cannot supply a finite operation deadline.
    InvalidClock,
}
impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TransportDisabled => "recursive transport forwarding is disabled",
            Self::UnknownInterface => "discovery requester interface is not registered",
            Self::InterfaceUnavailable => "discovery requester interface is unavailable",
            Self::PolicyDenied => "recursive discovery denied by interface policy",
            Self::KnownDestination => "destination is already known or local",
            Self::Capacity => "recursive discovery capacity exhausted",
            Self::InvalidClock => "recursive discovery requires a finite clock",
        })
    }
}
impl std::error::Error for DiscoveryError {}
