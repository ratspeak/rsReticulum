//! Network interface implementations for Reticulum.
//! Each module provides a spawn function returning a Tokio task driving a
//! concrete transport; [`traits::InterfaceHandle`] is the common handle the
//! runtime registers with the transport actor.

#[cfg(target_os = "android")]
pub mod android_usb;
#[cfg(any(target_os = "android", test))]
mod android_usb_lifecycle;
pub mod auto;
pub mod ax25kiss;
pub mod backbone;
#[cfg(all(feature = "ble", any(target_os = "ios", target_os = "macos")))]
pub mod ble_central_apple;
#[cfg(all(feature = "ble", any(target_os = "ios", target_os = "macos")))]
pub mod ble_central_apple_connect;
#[cfg(feature = "ble")]
pub mod ble_central_lifecycle;
#[cfg(feature = "ble")]
pub mod ble_peer;
#[cfg(feature = "ble")]
pub mod ble_peer_lifecycle;
#[cfg(feature = "ble")]
pub mod ble_rnode;
pub mod hdlc;
pub mod i2p;
pub mod kiss;
#[cfg(feature = "serial")]
pub mod kiss_iface;
pub mod local;
pub mod pipe;
pub mod rnode;
pub mod rnode_admin;
pub mod rnode_capabilities;
#[cfg(feature = "serial")]
pub mod rnode_multi;
pub mod rnode_protocol;
#[cfg(feature = "serial")]
pub mod serial;
#[cfg(feature = "serial")]
mod serial_io;
pub mod socket_tuning;
pub mod tcp;
pub mod traits;
pub mod udp;
pub mod weave;
