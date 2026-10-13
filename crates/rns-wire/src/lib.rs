//! Reticulum wire format: packets, headers, flags, receipts, proofs.
//!
//! Source of truth for packet bit-packing — must match the Python reference
//! ([`Packet.py`](https://github.com/markqvist/Reticulum/blob/master/RNS/Packet.py))
//! exactly. `no_std + alloc` when `std` is off; `receipt` is `std`-only.
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
extern crate alloc;

pub mod constants;
pub mod context;
pub mod flags;
pub mod hash;
pub mod header;
pub mod link_signalling;
pub mod packet;
pub mod proof;
#[cfg(feature = "std")]
pub mod receipt;
pub mod types;
