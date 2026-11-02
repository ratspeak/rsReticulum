//! Resource transfer, Channels and byte streams over Reticulum Links.
//!
//! The state machines are passive: their owner supplies packet I/O, Link keys,
//! proof routing and timeout polling. Use [`resource::OutboundTransfer`] and
//! [`resource::InboundTransfer`] for request-driven Resource transfer,
//! [`channel::LinkChannel`] for sequenced messages, and [`buffer::ChannelBuffer`]
//! for byte-stream framing on a Channel. Codec helpers do not establish Links
//! or authorize application actions.
//!
//! Python reference formats: `RNS/Resource.py`, `RNS/Channel.py`, `RNS/Buffer.py`.

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
