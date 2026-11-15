//! The Unix calls rngit makes, and what other platforms do in their place.

use std::path::Path;

/// `os.access(path, os.X_OK)`. Windows has no execute permission (upstream's
/// check passes for any file there and the run then fails), so nothing is
/// treated as executable and permission files and templates are read as text.
pub(crate) fn executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Any execute bit in `meta`'s mode; never on platforms without one.
pub(crate) fn mode_executable(meta: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        false
    }
}

/// `os.makedirs(path, mode=0o755)`; the mode applies only on Unix, as in Python.
pub(crate) fn create_dir_all_755(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o755);
    }
    builder.create(path)
}

/// Copy the symbolic link `from` as a link at `to`, as `copytree(symlinks=True)`.
/// Windows needs the link's kind, which follows what `from` names (a file
/// link when it names nothing).
pub(crate) fn copy_symlink(from: &Path, to: &Path) -> std::io::Result<()> {
    let target = std::fs::read_link(from)?;
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, to)
    }
    #[cfg(windows)]
    {
        if std::fs::metadata(from).is_ok_and(|m| m.is_dir()) {
            std::os::windows::fs::symlink_dir(target, to)
        } else {
            std::os::windows::fs::symlink_file(target, to)
        }
    }
}

/// A finished process's return code as Python reports it: negative for the
/// signal that ended it on Unix.
pub(crate) fn return_code(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status
            .code()
            .unwrap_or_else(|| -status.signal().unwrap_or(0))
    }
    #[cfg(not(unix))]
    {
        status.code().unwrap_or(0)
    }
}

/// Broken-down local time, as `time.localtime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalTime {
    pub year: i32,
    /// 1 to 12.
    pub month: i32,
    pub day: i32,
    pub hour: i32,
    pub minute: i32,
    pub second: i32,
}

/// `time.localtime(secs)`; `None` where the C library refuses the time.
#[cfg(unix)]
pub(crate) fn localtime(secs: i64) -> Option<LocalTime> {
    let time = secs as nix::libc::time_t;
    let mut tm = std::mem::MaybeUninit::<nix::libc::tm>::zeroed();
    // SAFETY: both pointers are valid for the call; localtime_r is reentrant.
    if unsafe { nix::libc::localtime_r(&time, tm.as_mut_ptr()) }.is_null() {
        return None;
    }
    // SAFETY: localtime_r filled `tm` when it returned non-null.
    let tm = unsafe { tm.assume_init() };
    Some(LocalTime {
        year: tm.tm_year + 1900,
        month: tm.tm_mon + 1,
        day: tm.tm_mday,
        hour: tm.tm_hour,
        minute: tm.tm_min,
        second: tm.tm_sec,
    })
}

/// `time.localtime(secs)` through the C runtime's `localtime_s`.
#[cfg(windows)]
pub(crate) fn localtime(secs: i64) -> Option<LocalTime> {
    let time = secs as libc::time_t;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::zeroed();
    // SAFETY: both pointers are valid for the call; localtime_s writes only `tm`.
    if unsafe { libc::localtime_s(tm.as_mut_ptr(), &time) } != 0 {
        return None;
    }
    // SAFETY: localtime_s filled `tm` when it returned zero.
    let tm = unsafe { tm.assume_init() };
    Some(LocalTime {
        year: tm.tm_year + 1900,
        month: tm.tm_mon + 1,
        day: tm.tm_mday,
        hour: tm.tm_hour,
        minute: tm.tm_min,
        second: tm.tm_sec,
    })
}

/// `time.mktime` of local midnight on `year-month-day`, a day past the month's
/// end rolling over as C's `mktime` does.
#[cfg(unix)]
pub(crate) fn local_midnight(year: i32, month: i32, day: i32) -> i64 {
    // SAFETY: an all-zero `tm` is a valid value of the C struct.
    let mut tm: nix::libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_isdst = -1;
    // SAFETY: `tm` is initialised; mktime reads and normalises it in place.
    let secs = unsafe { nix::libc::mktime(&mut tm) };
    secs as i64
}

/// `time.mktime` of local midnight on `year-month-day`: the Windows C runtime
/// offers no `mktime` binding here, so the time is found from `localtime`,
/// correcting once for an offset that differs at the result.
#[cfg(windows)]
pub(crate) fn local_midnight(year: i32, month: i32, day: i32) -> i64 {
    let wall = days_from_civil(i64::from(year), i64::from(month), i64::from(day)) * 86_400;
    let offset = |secs: i64| {
        localtime(secs).map_or(0, |t| {
            days_from_civil(i64::from(t.year), i64::from(t.month), i64::from(t.day)) * 86_400
                + i64::from(t.hour) * 3600
                + i64::from(t.minute) * 60
                + i64::from(t.second)
                - secs
        })
    };
    let first = wall - offset(wall);
    wall - offset(first)
}

/// Days since 1970-01-01 of a proleptic Gregorian date; linear in `day`.
#[cfg(windows)]
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
