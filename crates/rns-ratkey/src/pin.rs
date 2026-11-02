//! Host-side PIN cache backed by `Zeroizing<String>`. Replacing, clearing or
//! dropping the stored value wipes it. Expiry only makes `get` return `None`;
//! it does not clear the allocation or relock a card. The owner must call
//! `clear` and perform any required card-session lock.

use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub struct PinCache {
    pin: Option<Zeroizing<String>>,
    verified_at: Option<Instant>,
    timeout: Duration,
}

impl PinCache {
    /// `Duration::ZERO` disables cache reuse. `cache` still stores the PIN until
    /// clear/replacement/drop; this setting does not force an already-authorized
    /// card to require a PIN for each operation.
    pub fn new(timeout: Duration) -> Self {
        Self {
            pin: None,
            verified_at: None,
            timeout,
        }
    }

    /// 5-minute default.
    pub fn default_timeout() -> Self {
        Self::new(Duration::from_secs(300))
    }

    pub fn cache(&mut self, pin: &str) {
        self.pin = Some(Zeroizing::new(pin.to_string()));
        self.verified_at = Some(Instant::now());
    }

    pub fn get(&self) -> Option<&str> {
        let pin = self.pin.as_ref()?;
        let verified_at = self.verified_at?;

        if self.timeout == Duration::ZERO {
            return None;
        }

        if verified_at.elapsed() < self.timeout {
            Some(pin.as_str())
        } else {
            None
        }
    }

    pub fn is_cached(&self) -> bool {
        self.get().is_some()
    }

    pub fn remaining(&self) -> Option<Duration> {
        let verified_at = self.verified_at?;
        if self.pin.is_none() || self.timeout == Duration::ZERO {
            return None;
        }
        self.timeout.checked_sub(verified_at.elapsed())
    }

    pub fn clear(&mut self) {
        self.pin = None;
        self.verified_at = None;
    }
}

impl Drop for PinCache {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_cache_and_retrieve() {
        let mut cache = PinCache::new(Duration::from_secs(60));
        assert!(!cache.is_cached());
        assert!(cache.get().is_none());

        cache.cache("123456");
        assert!(cache.is_cached());
        assert_eq!(cache.get(), Some("123456"));
    }

    #[test]
    fn test_cache_expiry() {
        let mut cache = PinCache::new(Duration::from_millis(50));
        cache.cache("123456");
        assert!(cache.is_cached());

        sleep(Duration::from_millis(60));
        assert!(!cache.is_cached());
        assert!(cache.get().is_none());
    }

    #[test]
    fn test_zero_timeout_never_caches() {
        let mut cache = PinCache::new(Duration::ZERO);
        cache.cache("123456");
        assert!(!cache.is_cached());
        assert!(cache.get().is_none());
    }

    #[test]
    fn test_clear() {
        let mut cache = PinCache::new(Duration::from_secs(60));
        cache.cache("123456");
        assert!(cache.is_cached());

        cache.clear();
        assert!(!cache.is_cached());
    }

    #[test]
    fn test_remaining() {
        let mut cache = PinCache::new(Duration::from_secs(60));
        assert!(cache.remaining().is_none());

        cache.cache("123456");
        let remaining = cache.remaining().unwrap();
        assert!(remaining.as_secs() >= 59);
    }

    #[test]
    fn test_default_timeout() {
        let cache = PinCache::default_timeout();
        assert_eq!(cache.timeout, Duration::from_secs(300));
    }
}
