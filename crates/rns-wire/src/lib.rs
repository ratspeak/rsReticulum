//! Reticulum wire format: packets, headers, flags, receipts, proofs.
//!
//! Defines Reticulum packet encodings and the checked Link signalling parser.
//! These low-level types do not authenticate packets or apply endpoint policy.
//!
//! Disabling `std` makes this crate use `no_std + alloc` and omits `receipt`;
//! it does not disable default features in the dependency graph.
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
