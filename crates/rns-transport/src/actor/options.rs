use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Settings an actor takes at construction and keeps for its lifetime.
/// `Default` is a foreground actor with a per-boot identity policy and no
/// hop offset.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct TransportActorOptions {
    /// Foreground flag shared with the embedder; `None` keeps a private flag
    /// that stays true.
    pub is_foreground: Option<Arc<AtomicBool>>,
    /// Keep the hash from `SetTransportIdentity` as the wire-facing identity
    /// while forwarding is disabled.
    pub static_transport_identity: bool,
    /// Hop byte for eligible locally originated egress; zero disables it.
    pub local_hops_delta: u8,
    /// Wire-facing hash used while forwarding and the static identity are
    /// both disabled; `None` generates one on first use.
    pub ephemeral_identity_hash: Option<[u8; 16]>,
}
