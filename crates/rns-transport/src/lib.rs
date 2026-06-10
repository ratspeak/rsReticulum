//! Reticulum transport: routing actor, path tables, announces, blackhole,
//! rate limiting. The Rust replacement for Python's static `Transport` class
//! ([Transport.py](https://github.com/markqvist/Reticulum/blob/master/RNS/Transport.py)).
//! [`actor::TransportActor`] owns all mutable state; other crates send typed
//! [`messages::TransportMessage`]s over a Tokio mpsc channel.

/// Unix time as f64 seconds — Python `time.time()` equivalent, the timebase
/// used across path/reverse/rate/blackhole/tunnel tables.
pub fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub mod actor;
pub mod announce;
pub mod await_path;
pub mod blackhole;
pub mod constants;
pub mod discovery;
pub mod hashlist;
pub mod ifac;
pub mod ingress;
pub mod link_messages;
pub mod link_table;
pub mod messages;
pub mod path_table;
pub mod persistence;
pub mod rate_limit;
pub mod reverse_table;
pub mod traffic;
pub mod tunnel;
