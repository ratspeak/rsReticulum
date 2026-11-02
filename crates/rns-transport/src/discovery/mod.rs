//! Interface-discovery metadata, publication scheduling and reception.
//!
//! The announcer prepares stamped app-data for
//! `rnstransport.discovery.interface`; its runtime owner supplies the timer,
//! signed outer announce and transmission. The receiver validates work and
//! stores observations. Auto-connect helpers check advertised eligibility;
//! the runtime owns actual connections. Blackhole manifest codecs and update
//! cursors support the separate `rnstransport.info.blackhole` service.
//!
//! Discovery accepts a [`DiscoveryStamper`] so transport need not depend on
//! LXMF. An embedding application can supply the concrete implementation from
//! `lxmf-core::discovery_stamper`. [`NullStamper`] generates no work and rejects
//! inbound stamps; it does not disable the separate blackhole helpers or erase
//! previously stored discovery records.

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
