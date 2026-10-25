//! A monotonic clock that keeps counting while the system is suspended.
//!
//! `std::time::Instant` stops while Apple, Linux and Android systems sleep,
//! so a deadline measured on it ends late by the whole sleep. This clock
//! counts that time: `CLOCK_BOOTTIME` on Linux and Android,
//! `CLOCK_MONOTONIC_RAW` (`mach_continuous_time`) on Apple platforms, and the
//! performance counter on Windows. On other targets it is best effort,
//! `std::time::Instant` from the first reading in the process.
//!
//! Timers do not run on this clock: tokio and the operating system's waits
//! count awake time only. Check a deadline against [`ContinuousInstant::now`]
//! on a regular tick instead of arming a timer for it.

use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::time::Duration;

/// A reading of the suspend-counting clock, in signed nanoseconds from the
/// platform's origin, usually boot.
///
/// Readings are process-local: never persist one or send it to another
/// process, which is what wall time is for. They do not convert to or from
/// `std::time::Instant`, so the two clocks never mix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContinuousInstant(i64);

impl ContinuousInstant {
    /// The current reading.
    ///
    /// # Panics
    ///
    /// If the platform clock fails, as `std::time::Instant::now` does.
    pub fn now() -> Self {
        Self(backend::now_nanos())
    }

    /// The time from `earlier` to `self`, or zero if `earlier` is later.
    pub fn duration_since(self, earlier: Self) -> Duration {
        self.saturating_duration_since(earlier)
    }

    /// The time from `earlier` to `self`, or zero if `earlier` is later.
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.checked_duration_since(earlier).unwrap_or_default()
    }

    /// The time from `earlier` to `self`, or `None` if `earlier` is later.
    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        let nanos = i128::from(self.0) - i128::from(earlier.0);
        u64::try_from(nanos).ok().map(Duration::from_nanos)
    }

    /// The time since this reading, including time the system was suspended.
    pub fn elapsed(self) -> Duration {
        Self::now().duration_since(self)
    }

    /// `self + duration`, or `None` beyond the clock's range, about 292 years
    /// either side of its origin.
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        Self::from_nanos(i128::from(self.0) + nanos(duration)?)
    }

    /// `self - duration`, or `None` beyond the clock's range, about 292 years
    /// either side of its origin.
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        Self::from_nanos(i128::from(self.0) - nanos(duration)?)
    }

    fn from_nanos(nanos: i128) -> Option<Self> {
        i64::try_from(nanos).ok().map(Self)
    }
}

fn nanos(duration: Duration) -> Option<i128> {
    i128::try_from(duration.as_nanos()).ok()
}

/// # Panics
///
/// Beyond the clock's range, as `std::time::Instant` does.
impl Add<Duration> for ContinuousInstant {
    type Output = Self;

    fn add(self, duration: Duration) -> Self {
        self.checked_add(duration)
            .expect("overflow when adding duration to instant")
    }
}

impl AddAssign<Duration> for ContinuousInstant {
    fn add_assign(&mut self, duration: Duration) {
        *self = *self + duration;
    }
}

/// # Panics
///
/// Beyond the clock's range, as `std::time::Instant` does.
impl Sub<Duration> for ContinuousInstant {
    type Output = Self;

    fn sub(self, duration: Duration) -> Self {
        self.checked_sub(duration)
            .expect("overflow when subtracting duration from instant")
    }
}

impl SubAssign<Duration> for ContinuousInstant {
    fn sub_assign(&mut self, duration: Duration) {
        *self = *self - duration;
    }
}

/// The time from `earlier` to `self`, or zero if `earlier` is later.
impl Sub for ContinuousInstant {
    type Output = Duration;

    fn sub(self, earlier: Self) -> Duration {
        self.duration_since(earlier)
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
mod backend {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const CLOCK: libc::clockid_t = libc::CLOCK_BOOTTIME;
    #[cfg(target_vendor = "apple")]
    const CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC_RAW;

    // `time_t` and `c_long` are 32 bits wide on some of these targets.
    #[allow(clippy::useless_conversion)]
    pub(super) fn now_nanos() -> i64 {
        let mut now = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: `now` is valid for writes of a timespec for the whole call.
        let result = unsafe { libc::clock_gettime(CLOCK, now.as_mut_ptr()) };
        assert_eq!(
            result,
            0,
            "clock_gettime failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: a successful `clock_gettime` filled in `now`.
        let now = unsafe { now.assume_init() };
        i64::from(now.tv_sec) * 1_000_000_000 + i64::from(now.tv_nsec)
    }
}

#[cfg(windows)]
mod backend {
    use std::sync::OnceLock;
    use windows_sys::Win32::System::Performance::{
        QueryPerformanceCounter, QueryPerformanceFrequency,
    };

    fn frequency() -> i64 {
        static FREQUENCY: OnceLock<i64> = OnceLock::new();
        *FREQUENCY.get_or_init(|| {
            let mut frequency = 0;
            // SAFETY: `frequency` is a valid, writable i64 for the whole call.
            let succeeded = unsafe { QueryPerformanceFrequency(&mut frequency) } != 0;
            assert!(
                succeeded && frequency > 0,
                "QueryPerformanceFrequency failed"
            );
            frequency
        })
    }

    pub(super) fn now_nanos() -> i64 {
        let mut counter = 0;
        // SAFETY: `counter` is a valid, writable i64 for the whole call.
        let succeeded = unsafe { QueryPerformanceCounter(&mut counter) } != 0;
        assert!(succeeded, "QueryPerformanceCounter failed");
        let nanos = i128::from(counter) * 1_000_000_000 / i128::from(frequency());
        i64::try_from(nanos).expect("performance counter beyond the clock's range")
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
)))]
mod backend {
    use std::sync::OnceLock;
    use std::time::Instant;

    pub(super) fn now_nanos() -> i64 {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        let origin = *ORIGIN.get_or_init(Instant::now);
        i64::try_from(origin.elapsed().as_nanos()).expect("clock beyond its range")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn readings_never_go_backwards() {
        let mut last = ContinuousInstant::now();
        for _ in 0..10_000 {
            let now = ContinuousInstant::now();
            assert!(now >= last, "{now:?} after {last:?}");
            last = now;
        }
    }

    /// While the system is awake the clock keeps `Instant`'s rate, which
    /// catches a backend's unit or scaling mistake. Each reading is bracketed
    /// by two `Instant` readings, so a preemption widens the bounds instead of
    /// failing the check.
    #[test]
    fn it_runs_at_instants_rate_while_awake() {
        let bracketed = || {
            let before = std::time::Instant::now();
            let reading = ContinuousInstant::now();
            (before, reading, std::time::Instant::now())
        };
        let (start_before, start, start_after) = bracketed();
        std::thread::sleep(Duration::from_millis(200));
        let (end_before, end, end_after) = bracketed();
        let advance = (end - start).as_secs_f64();
        let shortest = end_before.duration_since(start_after).as_secs_f64();
        let longest = end_after.duration_since(start_before).as_secs_f64();
        assert!(
            (shortest * 0.95..=longest * 1.05).contains(&advance),
            "advanced {advance}s while Instant advanced {shortest}s to {longest}s"
        );
    }

    #[test]
    fn backdating_never_underflows() {
        let now = ContinuousInstant::now();
        let century = Duration::from_secs(100 * 365 * 24 * 3600);
        let past = now - century;
        assert!(past < now);
        assert_eq!(now.duration_since(past), century);
        let later = ContinuousInstant::now();
        assert_eq!(later - past - (later - now), century);
    }

    #[test]
    fn a_later_earlier_reading_saturates() {
        let (earlier, later) = (ContinuousInstant(-5), ContinuousInstant(7));
        assert_eq!(later - earlier, Duration::from_nanos(12));
        assert_eq!(earlier - later, Duration::ZERO);
        assert_eq!(earlier.duration_since(later), Duration::ZERO);
        assert_eq!(earlier.saturating_duration_since(later), Duration::ZERO);
        assert_eq!(earlier.checked_duration_since(later), None);
        assert_eq!(later.checked_duration_since(later), Some(Duration::ZERO));
    }

    #[test]
    fn arithmetic_beyond_the_range_is_none() {
        let (min, max) = (ContinuousInstant(i64::MIN), ContinuousInstant(i64::MAX));
        assert_eq!(max.checked_add(Duration::from_nanos(1)), None);
        assert_eq!(min.checked_sub(Duration::from_nanos(1)), None);
        assert_eq!(ContinuousInstant(0).checked_add(Duration::MAX), None);
        assert_eq!(ContinuousInstant(0).checked_sub(Duration::MAX), None);
        assert_eq!(
            max.checked_duration_since(min),
            Some(Duration::from_nanos(u64::MAX))
        );
    }

    #[test]
    #[should_panic(expected = "overflow when adding duration to instant")]
    fn adding_beyond_the_range_panics() {
        let _ = ContinuousInstant(i64::MAX) + Duration::from_nanos(1);
    }

    #[test]
    #[should_panic(expected = "overflow when subtracting duration from instant")]
    fn subtracting_beyond_the_range_panics() {
        let _ = ContinuousInstant(i64::MIN) - Duration::from_nanos(1);
    }

    #[test]
    fn assigning_operators_match_the_plain_ones() {
        let start = ContinuousInstant(1_000);
        let mut moved = start;
        moved += Duration::from_nanos(250);
        assert_eq!(moved, start + Duration::from_nanos(250));
        moved -= Duration::from_nanos(500);
        assert_eq!(moved, start - Duration::from_nanos(250));
    }

    proptest! {
        #[test]
        fn a_duration_added_is_the_duration_measured(origin in any::<i64>(), nanos in any::<u64>()) {
            let start = ContinuousInstant(origin);
            let duration = Duration::from_nanos(nanos);
            match start.checked_add(duration) {
                Some(end) => {
                    prop_assert_eq!(end - start, duration);
                    prop_assert_eq!(end.checked_sub(duration), Some(start));
                    prop_assert_eq!(start.saturating_duration_since(end), Duration::ZERO);
                    prop_assert_eq!(
                        start.checked_duration_since(end),
                        (nanos == 0).then_some(Duration::ZERO)
                    );
                }
                None => prop_assert!(i128::from(origin) + i128::from(nanos) > i128::from(i64::MAX)),
            }
        }

        #[test]
        fn a_duration_subtracted_is_the_duration_measured(origin in any::<i64>(), nanos in any::<u64>()) {
            let end = ContinuousInstant(origin);
            let duration = Duration::from_nanos(nanos);
            match end.checked_sub(duration) {
                Some(start) => {
                    prop_assert_eq!(end.duration_since(start), duration);
                    prop_assert_eq!(start.checked_add(duration), Some(end));
                }
                None => prop_assert!(i128::from(origin) - i128::from(nanos) < i128::from(i64::MIN)),
            }
        }
    }
}
