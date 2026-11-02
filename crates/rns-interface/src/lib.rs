//! Network interface implementations and framing helpers for Reticulum.
//! Transport drivers expose [`traits::InterfaceHandle`] for registration with
//! the transport actor; helper modules provide codecs, settings, and lifecycle
//! state. Serial, BLE, and Android USB APIs have feature or platform gates.

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
#[cfg(all(feature = "ble", any(target_os = "windows", target_os = "linux", test)))]
mod ble_connect;
#[cfg(feature = "ble")]
pub mod ble_peer;
#[cfg(feature = "ble")]
pub mod ble_peer_lifecycle;
#[cfg(feature = "ble")]
pub mod ble_rnode;
#[cfg(all(feature = "ble", any(target_os = "ios", target_os = "macos", test)))]
mod ble_tx_queue;
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
#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
mod rnode_capability_preflight;
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

mod background_announce;
