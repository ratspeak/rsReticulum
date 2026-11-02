//! Poll-driven scheduling of cache cleaning after 15 minutes and persistence
//! after 12 hours. Explicit persistence requests can emit a job once five
//! minutes have elapsed since the last gracious persist. Callers must poll
//! `tick` and execute the returned jobs; this module starts no timer or I/O.

use std::time::{Duration, Instant};

use crate::constants::*;

pub struct JobScheduler {
    last_clean: Instant,
    last_persist: Instant,
    persist_requested: bool,
    last_gracious_persist: Instant,
}

impl JobScheduler {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            last_clean: now,
            last_persist: now,
            persist_requested: false,
            last_gracious_persist: now,
        }
    }

    pub fn tick(&mut self) -> Vec<Job> {
        self.tick_at(Instant::now())
    }

    fn tick_at(&mut self, now: Instant) -> Vec<Job> {
        let mut jobs = Vec::new();

        if now.duration_since(self.last_clean) >= Duration::from_secs(CLEAN_INTERVAL) {
            jobs.push(Job::CleanCache);
            self.last_clean = now;
        }

        if now.duration_since(self.last_persist) >= Duration::from_secs(PERSIST_INTERVAL) {
            jobs.push(Job::PersistData);
            self.last_persist = now;
            self.persist_requested = false;
        }

        if self.persist_requested
            && now.duration_since(self.last_gracious_persist)
                >= Duration::from_secs(GRACIOUS_PERSIST_INTERVAL)
        {
            jobs.push(Job::PersistData);
            self.last_gracious_persist = now;
            self.persist_requested = false;
        }

        jobs
    }

    pub fn request_persist(&mut self) {
        self.persist_requested = true;
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
    fn test_scheduler_initial_tick() {
        let mut scheduler = JobScheduler::new();
        let jobs = scheduler.tick();
        assert!(jobs.is_empty());
    }

    #[test]
    fn test_scheduler_persist_request() {
        let mut scheduler = JobScheduler::new();
        assert!(!scheduler.persist_requested);
        scheduler.request_persist();
        assert!(scheduler.persist_requested);
    }

    #[test]
    fn test_scheduler_forced_persist() {
        let mut scheduler = JobScheduler::new();
        let now = Instant::now();
        scheduler.last_gracious_persist = now;
        scheduler.request_persist();

        let jobs = scheduler.tick_at(now + Duration::from_secs(GRACIOUS_PERSIST_INTERVAL + 1));
        assert!(jobs.contains(&Job::PersistData));
        assert!(!scheduler.persist_requested);
    }

    #[test]
    fn test_scheduler_clean_due() {
        let mut scheduler = JobScheduler::new();
        let now = Instant::now();
        scheduler.last_clean = now;
        let jobs = scheduler.tick_at(now + Duration::from_secs(CLEAN_INTERVAL + 1));
        assert!(jobs.contains(&Job::CleanCache));
    }
}
