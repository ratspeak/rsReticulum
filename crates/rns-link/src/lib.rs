//! Encrypted point-to-point Links between two Reticulum destinations.
//! LR/LRPROOF handshake, AES-256-CBC + HMAC-SHA256 sessions, checked MTU
//! signalling, keepalives, and request/response. Current [`link::Link`] endpoints
//! use the 500-byte base MTU; representable signalling offers are a wider domain.
//! The owning runtime sends packets, drives ticks, and dispatches Link callbacks.

pub mod clock;
pub mod constants;
pub mod encryption;
pub mod handshake;
pub mod keepalive;
pub mod key_derivation;
pub mod link;
pub mod mtu_discovery;
pub mod request;
