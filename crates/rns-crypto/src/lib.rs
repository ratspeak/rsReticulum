//! Cryptographic primitives used by Reticulum identities, Links and Tokens.
//! This crate exposes low-level ciphers, hashes, key derivation and key types;
//! callers supply the protocol-specific salts, authentication and key lifecycle.
//!
//! Disabling this crate's `std` feature selects `no_std + alloc` for its code.
//! Workspace dependencies retain their own default features, and random/key
//! generation still requires an operating-system entropy source. This setting
//! alone does not make the crate a bare-metal cryptographic backend.
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
extern crate alloc;

pub mod aes_cbc;
pub mod ed25519;
pub mod hkdf;
pub mod hmac;
pub mod pkcs7;
pub mod random;
pub mod sha;
pub mod token;
pub mod x25519;

pub use token::TOKEN_OVERHEAD;
/// The wiping types in this crate's API, such as the output of
/// [`hkdf::hkdf_sha256`], for crates that hold secrets without depending on
/// `zeroize` themselves.
pub use zeroize;

use alloc::string::String;
use core::fmt::Write;

/// Lower-case hex encoding of `bytes`.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}
