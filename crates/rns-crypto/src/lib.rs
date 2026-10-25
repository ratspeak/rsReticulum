//! Cryptographic primitives for Reticulum. Constants, derivation inputs, and
//! wire-visible byte layouts match the Python reference (`RNS/Cryptography/`)
//! exactly — downstream interop depends on it. `no_std + alloc` when `std` is off.
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
