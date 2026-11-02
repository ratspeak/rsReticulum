use std::collections::HashMap;

use crate::messages::InterfaceId;

/// Accumulated byte counts and the most recently sampled byte deltas for one
/// interface. The speed fields assume a one-second sampling interval.
#[derive(Debug, Clone, Default)]
pub struct InterfaceTraffic {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Previous sample, retained so `update_speeds` can compute a delta
    /// without keeping a ring buffer of samples.
    pub rx_bytes_prev: u64,
    pub tx_bytes_prev: u64,
    /// Received-byte delta from the last `update_speeds` call. This represents
    /// bytes per second only when calls are one second apart.
    pub rx_speed: f64,
    /// Transmitted-byte delta, with the same sampling assumption as `rx_speed`.
    pub tx_speed: f64,
}

/// Per-interface counters updated explicitly by the caller. Records remain
/// until this counter is dropped; this type does not measure elapsed time.
pub struct TrafficCounter {
    interfaces: HashMap<InterfaceId, InterfaceTraffic>,
}

impl TrafficCounter {
    pub fn new() -> Self {
        Self {
            interfaces: HashMap::new(),
        }
    }

    pub fn record_rx(&mut self, interface_id: InterfaceId, bytes: u64) {
        let entry = self.interfaces.entry(interface_id).or_default();
        entry.rx_bytes += bytes;
    }

    pub fn record_tx(&mut self, interface_id: InterfaceId, bytes: u64) {
        let entry = self.interfaces.entry(interface_id).or_default();
        entry.tx_bytes += bytes;
    }

    /// Store the byte-count deltas since the last call and advance the samples.
    /// No division by elapsed time is performed. Call once per second if the
    /// speed fields are to represent bytes per second; delayed or background
    /// ticks represent a longer interval instead.
    pub fn update_speeds(&mut self) {
        for entry in self.interfaces.values_mut() {
            entry.rx_speed = (entry.rx_bytes - entry.rx_bytes_prev) as f64;
            entry.tx_speed = (entry.tx_bytes - entry.tx_bytes_prev) as f64;
            entry.rx_bytes_prev = entry.rx_bytes;
            entry.tx_bytes_prev = entry.tx_bytes;
        }
    }

    pub fn get(&self, interface_id: &InterfaceId) -> Option<&InterfaceTraffic> {
        self.interfaces.get(interface_id)
    }

    pub fn all(&self) -> &HashMap<InterfaceId, InterfaceTraffic> {
        &self.interfaces
    }
}

impl Default for TrafficCounter {
    fn default() -> Self {
        Self::new()
    }
}
