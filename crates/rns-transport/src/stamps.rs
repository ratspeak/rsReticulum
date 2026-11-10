//! Network stamp policy: the switches and costs Python keeps on `Transport`.
//!
//! Python reference: `RNS/Transport.py:191-210` and the `[stamps]` parser in
//! `RNS/Reticulum.py:505-551` (1.6.0).

pub use rns_identity::stamps::{LINK_COST_CAP, STAMP_COST_CAP};

/// Lower bound for `lr_stamp_timeout` and `pr_stamp_timeout`, in seconds.
pub const STAMP_TIMEOUT_FLOOR: f64 = 0.020;
/// Not configurable in Python 1.6.0.
pub const STAMPER_PR_QUEUE_LENGTH: usize = 32;
/// Not configurable in Python 1.6.0.
pub const STAMPER_AN_QUEUE_LENGTH: usize = 32;

/// Effective stamp generation and enforcement policy for one instance.
#[derive(Debug, Clone, PartialEq)]
pub struct StampPolicy {
    /// Python `STAMPS_ENABLED`: check for and validate stamps.
    pub stamps_enabled: bool,
    /// Python `STAMPS_ENFORCED`.
    pub stamps_enforced: bool,
    /// Python `LR_STAMPS_ENFORCED`.
    pub lr_stamps_enforced: bool,
    /// Python `STAMP_DESTINATIONS`.
    pub stamp_destinations: bool,
    /// Python `STAMP_PRS`.
    pub stamp_prs: bool,
    /// Python `STAMP_LRS`.
    pub stamp_lrs: bool,
    /// Python `ALWAYS_STAMP_LRS`.
    pub always_stamp_lrs: bool,
    /// Python `DESTINATION_COST`.
    pub destination_cost: f64,
    /// Python `DESTINATION_VALUE`.
    pub destination_value: f64,
    /// Python `PR_COST`.
    pub pr_cost: f64,
    /// Python `PR_VALUE`.
    pub pr_value: f64,
    /// Python `LR_COST`.
    pub lr_cost: f64,
    /// Python `LINK_STAMP_TIMEOUT`, in seconds.
    pub lr_stamp_timeout: f64,
    /// Python `PR_STAMP_TIMEOUT`, in seconds.
    pub pr_stamp_timeout: f64,
}

impl Default for StampPolicy {
    fn default() -> Self {
        Self {
            stamps_enabled: true,
            stamps_enforced: false,
            lr_stamps_enforced: false,
            stamp_destinations: false,
            stamp_prs: false,
            stamp_lrs: true,
            always_stamp_lrs: false,
            destination_cost: 23.5,
            destination_value: 25.0,
            pr_cost: 15.8,
            pr_value: 15.8,
            lr_cost: 12.5,
            lr_stamp_timeout: 15.0,
            pr_stamp_timeout: 15.0,
        }
    }
}

impl StampPolicy {
    /// Python `max(0, min(v, STAMP_COST_CAP))`, including its NaN result of 0.
    pub fn clamp_cost(value: f64) -> f64 {
        clamp_to_cap(value, STAMP_COST_CAP)
    }

    /// Python `max(0, min(v, LINK_COST_CAP))`.
    pub fn clamp_link_cost(value: f64) -> f64 {
        clamp_to_cap(value, LINK_COST_CAP)
    }

    /// Python `max(0.020, v)`, including its NaN result of 0.020.
    pub fn clamp_timeout(value: f64) -> f64 {
        if value.is_nan() || value < STAMP_TIMEOUT_FLOOR {
            STAMP_TIMEOUT_FLOOR
        } else {
            value
        }
    }

    /// The `enable_stamping` constructor switch.
    pub fn enable_stamping(&mut self) {
        self.stamp_destinations = true;
        self.stamp_prs = true;
        self.stamp_lrs = true;
    }

    /// The `enforce_stamps` constructor switch and config key.
    pub fn enforce(&mut self) {
        self.stamps_enforced = true;
        self.lr_stamps_enforced = true;
    }

    /// Python `Interface.destination_cost`: the interface value, else the global.
    pub fn interface_destination_cost(&self, interface_cost: Option<f64>) -> f64 {
        interface_cost.unwrap_or(self.destination_cost)
    }

    /// Python `Interface.pr_cost`: the interface value, else the global.
    pub fn interface_pr_cost(&self, interface_cost: Option<f64>) -> f64 {
        interface_cost.unwrap_or(self.pr_cost)
    }
}

fn clamp_to_cap(value: f64, cap: f64) -> f64 {
    // Python's min(nan, cap) is nan and max(0, nan) is 0.
    if value.is_nan() || value < 0.0 {
        0.0
    } else if value > cap {
        cap
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_python_transport_defaults() {
        let p = StampPolicy::default();
        assert!(p.stamps_enabled);
        assert!(!p.stamps_enforced);
        assert!(!p.lr_stamps_enforced);
        assert!(!p.stamp_destinations);
        assert!(!p.stamp_prs);
        assert!(p.stamp_lrs);
        assert!(!p.always_stamp_lrs);
        assert_eq!(p.destination_cost, 23.5);
        assert_eq!(p.destination_value, 25.0);
        assert_eq!(p.pr_cost, 15.8);
        assert_eq!(p.pr_value, 15.8);
        assert_eq!(p.lr_cost, 12.5);
        assert_eq!(p.lr_stamp_timeout, 15.0);
        assert_eq!(p.pr_stamp_timeout, 15.0);
    }

    #[test]
    fn clamps_follow_python_min_max() {
        assert_eq!(StampPolicy::clamp_cost(f64::NAN), 0.0);
        assert_eq!(StampPolicy::clamp_cost(f64::INFINITY), 100.0);
        assert_eq!(StampPolicy::clamp_cost(f64::NEG_INFINITY), 0.0);
        assert_eq!(StampPolicy::clamp_cost(-5.0), 0.0);
        assert_eq!(StampPolicy::clamp_cost(150.0), 100.0);
        assert_eq!(StampPolicy::clamp_cost(7.25), 7.25);
        assert_eq!(StampPolicy::clamp_link_cost(41.0), 40.0);
        assert_eq!(StampPolicy::clamp_link_cost(f64::NAN), 0.0);
        assert_eq!(StampPolicy::clamp_timeout(f64::NAN), 0.02);
        assert_eq!(StampPolicy::clamp_timeout(0.001), 0.02);
        assert_eq!(StampPolicy::clamp_timeout(-1.0), 0.02);
        assert_eq!(StampPolicy::clamp_timeout(1e6), 1e6);
        assert_eq!(StampPolicy::clamp_timeout(f64::INFINITY), f64::INFINITY);
    }

    #[test]
    fn switches_set_python_flags() {
        let mut p = StampPolicy::default();
        p.enable_stamping();
        assert!(p.stamp_destinations && p.stamp_prs && p.stamp_lrs);
        assert!(!p.stamps_enforced && !p.lr_stamps_enforced);
        let mut p = StampPolicy::default();
        p.enforce();
        assert!(p.stamps_enforced && p.lr_stamps_enforced);
        assert!(!p.stamp_destinations && !p.stamp_prs);
    }

    #[test]
    fn interface_costs_fall_back_to_current_global() {
        let mut p = StampPolicy::default();
        assert_eq!(p.interface_destination_cost(None), 23.5);
        assert_eq!(p.interface_pr_cost(Some(7.25)), 7.25);
        p.destination_cost = 30.0;
        assert_eq!(p.interface_destination_cost(None), 30.0);
    }
}
