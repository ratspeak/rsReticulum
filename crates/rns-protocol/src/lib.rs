//! Higher-level protocol layers over Links: resource transfer, channels,
//! buffers, and stream I/O. Python reference: `RNS/Resource.py`,
//! `RNS/Channel.py`, `RNS/Buffer.py`.

pub mod buffer;
pub mod channel;
pub mod channel_message;
pub mod compression;
pub mod resource;
pub mod resource_adv;
pub mod rnsh;
pub mod stream_data;

/// Exact Resource control-packet admission using the production encoders.
pub mod resource_control;
