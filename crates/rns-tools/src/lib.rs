//! Shared utility code for Reticulum CLI tools.

pub mod format;
pub mod hash;

/// Python Reticulum version these tools track; printed by every `--version`.
pub const RETICULUM_COMPAT_VERSION: &str = "1.2.5";
