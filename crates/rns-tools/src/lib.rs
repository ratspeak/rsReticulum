//! Shared utility code for Reticulum CLI tools.

pub mod format;
pub mod hash;

/// rsReticulum package version printed by CLI `--version` output.
pub const RS_RETICULUM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Python Reticulum version these tools track for CLI/protocol parity.
pub const RETICULUM_COMPAT_VERSION: &str = "1.2.5";
