//! Poll-driven scheduling of cache cleaning at start and every 15 minutes, and
//! persistence after 12 hours. The transport actor owns the gracious persist on
//! local client disconnect. Callers must poll `tick` and execute the returned
//! jobs; this module starts no timer or I/O.

use std::time::{Duration, Instant};

use crate::constants::*;

pub struct JobScheduler {
    /// `None` until the first clean, as Python's `last_cache_clean = 0`.
    last_clean: Option<Instant>,
    last_persist: Instant,
}

impl JobScheduler {
    pub fn new() -> Self {
        Self {
            last_clean: None,
            last_persist: Instant::now(),
        }
    }

    pub fn tick(&mut self) -> Vec<Job> {
        self.tick_at(Instant::now())
    }

    fn tick_at(&mut self, now: Instant) -> Vec<Job> {
        let mut jobs = Vec::new();

        if self
            .last_clean
            .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(CLEAN_INTERVAL))
        {
            jobs.push(Job::CleanCache);
            self.last_clean = Some(now);
        }

        if now.duration_since(self.last_persist) >= Duration::from_secs(PERSIST_INTERVAL) {
            jobs.push(Job::PersistData);
            self.last_persist = now;
        }

        jobs
    }
}

impl Default for JobScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Job {
    CleanCache,
    PersistData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_initial_tick_cleans_caches() {
        let mut scheduler = JobScheduler::new();
        assert_eq!(scheduler.tick(), vec![Job::CleanCache]);
        assert!(scheduler.tick().is_empty());
    }

    #[test]
    fn test_scheduler_clean_due() {
        let mut scheduler = JobScheduler::new();
        let now = Instant::now();
        scheduler.last_clean = Some(now);
        let jobs = scheduler.tick_at(now + Duration::from_secs(CLEAN_INTERVAL + 1));
        assert!(jobs.contains(&Job::CleanCache));
    }
}
