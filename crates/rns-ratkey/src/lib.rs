//! PIV-backed Reticulum identities using Ed25519 signing and X25519 ECDH.
//! The token performs private-key operations; ECDH results and derived token
//! keys are processed on the host. Recoverable provisioning also derives
//! private keys on the host before importing them; on-device generation does
//! not provide a seed backup. Both produce ordinary Reticulum identities.
//!
//! A device needs both algorithms and the PIV extensions used by the selected
//! workflow. Standard non-FIPS YubiKey 5 firmware 5.7+ provides these algorithms.
//! Recognizing a Nitrokey reader name does not establish workflow compatibility.
//! See [Yubico PIV algorithms](https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html)
//! and [Nitrokey algorithm support](https://docs.nitrokey.com/nitrokeys/nitrokey3/faq).
//!
//! [`PivSession`] uses a caller-supplied [`PivTransport`]. The `hardware` feature
//! adds desktop PC/SC and its connection helpers; applications can supply other
//! transports. The default build includes codecs and mocks, not a PC/SC driver.

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
