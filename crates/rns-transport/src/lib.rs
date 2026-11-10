//! Reticulum routing, announces, path tables, interface access control and
//! traffic accounting. [`actor::TransportActor`] drives routing through typed
//! [`messages::TransportMessage`]s on a Tokio mpsc channel. Queue admission
//! alone does not confirm command completion or packet delivery; use each
//! message's reply or protocol proof where available. Public helper tables can
//! also be used independently of the actor.

/// Wall-clock Unix time in fractional seconds, used by the transport tables.
/// This is not monotonic: clock adjustments affect time comparisons. Returns
/// zero when the system clock is before the Unix epoch.
pub fn now_f64() -> f64 {
    #[cfg(test)]
    if let Some(now) = test_clock::NOW.with(std::cell::Cell::get) {
        return now;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Events Python logs at `LOG_PATHING` (7): debug events on the `rns::pathing` target.
macro_rules! pathing {
    ($($arg:tt)*) => { tracing::debug!(target: "rns::pathing", $($arg)*) };
}

/// Events Python logs at `LOG_NOTICE` (3): info events on the `rns::notice`
/// target, which the tools show from loglevel 3 while plain `info!` needs 4.
#[macro_export]
macro_rules! notice {
    ($($arg:tt)*) => { $crate::__tracing::info!(target: "rns::notice", $($arg)*) };
}

#[doc(hidden)]
pub use tracing as __tracing;

pub mod actor;
pub mod announce;
pub mod announce_validation;
pub mod await_path;
pub mod blackhole;
pub mod constants;
pub mod destination_filter;
pub mod discovery;
pub mod hashlist;
pub mod ifac;
pub mod inbound_queues;
pub mod ingress;
pub mod interface_ownership;
pub use interface_ownership::{
    InterfaceCapacityError, InterfaceOwner, InterfaceOwnerId, InterfacePacketCapacity,
    InterfaceTransportSender,
};
pub mod link_endpoint_dispatch;
pub mod link_messages;
pub mod link_table;
pub mod messages;
pub mod path_discovery;
pub mod path_recovery;
pub mod path_table;
pub mod persistence;
pub mod pr_stamper;
pub mod rate_limit;
pub mod reverse_table;
pub mod stamps;
pub mod traffic;
pub mod tunnel;

#[cfg(test)]
pub(crate) mod test_clock {
    use std::cell::Cell;
    thread_local! { pub(super) static NOW: Cell<Option<f64>> = const { Cell::new(None) }; }

    /// Synchronous actor tests have independent clocks under parallel runners.
    pub(crate) struct Clock(Option<f64>);
    impl Clock {
        pub(crate) fn at(now: f64) -> Self {
            Self(NOW.with(|clock| clock.replace(Some(now))))
        }
        pub(crate) fn set(&self, now: f64) {
            NOW.with(|clock| clock.set(Some(now)));
        }
    }
    impl Drop for Clock {
        fn drop(&mut self) {
            NOW.with(|clock| clock.set(self.0));
        }
    }
}

pub mod announce_dispatch;
pub mod background_egress;

pub mod link_transit;
