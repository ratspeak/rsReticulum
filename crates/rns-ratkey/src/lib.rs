//! Hardware-backed identity (YubiKey 5, Nitrokey 3) via PIV. Ed25519 sign + X25519
//! ECDH keys live on-device; only public keys and results leave the token.
//! Wire-compatible with software identities.
//!
//! The PIV protocol logic (`PivSession`, `apdu`) is transport-agnostic; the
//! `PivTransport` seam isolates platform access. The `hardware` feature adds the
//! PC/SC transport (`PcscTransport`) and its `connect()` entry points. Mobile
//! NFC/USB transports implement `PivTransport` from the application layer.

pub mod apdu;
pub mod attestation;
#[cfg(feature = "hardware")]
pub mod backend;
pub mod detect;
pub mod error;
pub mod hardware;
pub mod hwid;
pub mod mgmt;
pub mod mock;
pub mod pin;
pub mod provision;
pub mod seed;
pub mod session;
pub mod transport;

pub use error::RatkeyError;
pub use hardware::{HardwareIdentity, IdentityBackend};
pub use hwid::HwidConfig;
pub use mock::MockPivSession;
pub use pin::PinCache;
pub use provision::{ProvisionConfig, ProvisionResult};
pub use session::{DeviceMeta, PivSession};
pub use transport::PivTransport;

#[cfg(feature = "hardware")]
pub use backend::{HardwareBackend, load_hardware_identity};
#[cfg(feature = "hardware")]
pub use session::PcscPivSession;
#[cfg(feature = "hardware")]
pub use transport::PcscTransport;
