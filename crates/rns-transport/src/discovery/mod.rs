//! On-network interface discovery — Rust port of Python `RNS/Discovery.py`.
//!
//! The announcer periodically posts PoW-stamped discovery announces on
//! `rnstransport.discovery.interface`. The receiver validates stamps, stores
//! learned interfaces, and (optionally) auto-connects to eligible transport
//! nodes. A separate blackhole updater fetches blackhole manifests from
//! configured sources via link request.
//!
//! # Stamper indirection
//!
//! Python imports `LXMF.LXStamper` at startup. rsReticulum avoids an upward
//! dependency on rsLXMF, so discovery takes a [`DiscoveryStamper`] trait object;
//! the concrete implementation lives in `lxmf-core::discovery_stamper`.
//! Without a stamper installed, discovery is silent.

pub mod announcer;
pub mod app_data;
pub mod autoconnect;
pub mod blackhole_manifest;
pub mod blackhole_subscriber;
pub mod constants;
pub mod receiver;
pub mod stamper;
pub mod storage;

pub use announcer::{AnnounceRequest, Announcer, DiscoveryInterfaceConfig, SkipReason};
pub use blackhole_manifest::{
    BlackholeManifestEntry, ManifestError, apply_manifest, build_local_manifest, decode_manifest,
};
pub use blackhole_subscriber::{
    INITIAL_WAIT as BLACKHOLE_INITIAL_WAIT, JOB_INTERVAL as BLACKHOLE_JOB_INTERVAL,
    SOURCE_TIMEOUT as BLACKHOLE_SOURCE_TIMEOUT, SubscriberState as BlackholeSubscriberState,
    UPDATE_INTERVAL as BLACKHOLE_UPDATE_INTERVAL,
};
pub use constants::*;
pub use receiver::{DiscoveryDecryptor, Outcome, Reason, ReceiverConfig};
pub use stamper::{DiscoveryStamper, NullStamper};
pub use storage::{DiscoveredInterface, DiscoveryStatus, DiscoveryStore, discovery_hash};
