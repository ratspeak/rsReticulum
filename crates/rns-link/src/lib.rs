//! Encrypted point-to-point Links between two Reticulum destinations.
//! LR/LRPROOF handshake → AES-256 + HMAC-SHA256 session, MTU discovery,
//! keepalives, request/response. Python reference: `RNS/Link.py`.

pub mod clock;
pub mod constants;
pub mod encryption;
pub mod handshake;
pub mod keepalive;
pub mod key_derivation;
pub mod link;
pub mod mtu_discovery;
pub mod request;
