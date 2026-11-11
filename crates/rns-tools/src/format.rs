//! Human-readable CLI formatting for byte counts, bit rates, elapsed time,
//! frequencies and hexadecimal values. Size/rate prefixes use powers of 1000.
//! Python reference functions: `prettyspeed`, `prettysize` and `prettytime`
//! in `RNS/__init__.py`; this module defines its own output precision/layout.

/// Format bytes with decimal prefixes (`1000` becomes `1.00 KB`, not `KiB`).
pub fn pretty_size(num: u64) -> String {
    let units = ["", "K", "M", "G", "T", "P", "E", "Z"];
    let mut val = num as f64;
    for unit in &units {
        if val.abs() < 1000.0 {
            return if unit.is_empty() {
                format!("{val:.0} B")
            } else {
                format!("{val:.2} {unit}B")
            };
        }
        val /= 1000.0;
    }
    format!("{val:.2}YB")
}

/// Format bits per second with decimal prefixes. Convert byte rates before calling.
pub fn pretty_speed(bps: u64) -> String {
    let units = ["", "K", "M", "G", "T", "P", "E", "Z"];
    let mut val = bps as f64;
    for unit in &units {
        if val.abs() < 1000.0 {
            return if unit.is_empty() {
                format!("{val:.0} bps")
            } else {
                format!("{val:.2} {unit}bps")
            };
        }
        val /= 1000.0;
    }
    format!("{val:.2}Ybps")
}

/// Format finite seconds using seconds, minutes/seconds, hours/minutes or
/// days/hours. Fractional seconds are truncated; negative input returns `unknown`.
pub fn pretty_time(seconds: f64) -> String {
    if seconds < 0.0 {
        return "unknown".to_string();
    }
    let s = seconds as u64;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {}s", s / 60, s % 60)
    } else if s < 86400 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}d {}h", s / 86400, (s % 86400) / 3600)
    }
}

pub fn pretty_frequency(hz: f64) -> String {
    if hz >= 1_000_000_000.0 {
        format!("{:.3} GHz", hz / 1_000_000_000.0)
    } else if hz >= 1_000_000.0 {
        format!("{:.3} MHz", hz / 1_000_000.0)
    } else if hz >= 1_000.0 {
        format!("{:.3} KHz", hz / 1_000.0)
    } else {
        format!("{hz:.1} Hz")
    }
}

pub fn hex_rep(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn pretty_hex_rep(data: &[u8]) -> String {
    format!("<{}>", hex::encode(data))
}

// Python-format helpers: byte-identical to the RNS/__init__.py functions each one names.

/// A MessagePack number as Python holds it: `int` and `float` print differently.
#[derive(Debug, Clone, Copy)]
pub enum PyNum {
    Int(i64),
    Float(f64),
}

impl PyNum {
    pub fn f(self) -> f64 {
        match self {
            PyNum::Int(i) => i as f64,
            PyNum::Float(f) => f,
        }
    }

    pub fn i(self) -> i64 {
        match self {
            PyNum::Int(i) => i,
            PyNum::Float(f) => f as i64,
        }
    }

    pub fn py_str(self) -> String {
        match self {
            PyNum::Int(i) => i.to_string(),
            PyNum::Float(f) => py_float_repr(f),
        }
    }
}

/// Python `round(x, n)` for a float.
pub fn py_round(value: f64, digits: usize) -> f64 {
    format!("{value:.digits$}").parse().unwrap_or(value)
}

/// Python `repr(float)`: shortest round-trip digits, scientific notation
/// outside `1e-4 <= |x| < 1e16`.
pub fn py_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    let sci = format!("{value:e}");
    let (mantissa, exponent) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    if value == 0.0 || (-4..16).contains(&exponent) {
        let fixed = format!("{value}");
        if fixed.contains('.') {
            fixed
        } else {
            format!("{fixed}.0")
        }
    } else {
        let sign = if exponent < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exponent.abs())
    }
}

/// `RNS.prettysize`.
pub fn prettysize(num: f64, suffix: &str) -> String {
    let mut num = num;
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"] {
        if num.abs() < 1000.0 {
            return if unit.is_empty() {
                format!("{num:.0} {unit}{suffix}")
            } else {
                format!("{num:.2} {unit}{suffix}")
            };
        }
        num /= 1000.0;
    }
    format!("{num:.2}Y{suffix}")
}

/// `RNS.prettyspeed`: `prettysize(num/8, suffix="b")+"ps"`.
pub fn prettyspeed(num: f64) -> String {
    format!("{}ps", prettysize(num, "b"))
}

/// `RNS.prettyfrequency`.
pub fn prettyfrequency(hz: PyNum, suffix: &str, d: usize, lpf: bool) -> String {
    if hz.f() == 0.0 {
        return "0 Hz".to_string();
    }
    let mut num = if lpf { hz } else { PyNum::Float(hz.f() * 1e6) };
    let units: &[&str] = if lpf {
        &["", "K", "M", "G", "T", "P", "E", "Z"]
    } else {
        &["µ", "m", "", "K", "M", "G", "T", "P", "E", "Z"]
    };
    for unit in units {
        if num.f().abs() < 1000.0 {
            return if d == 2 {
                format!("{:.2} {unit}{suffix}", num.f())
            } else {
                let rounded = match num {
                    PyNum::Int(i) => PyNum::Int(i),
                    PyNum::Float(f) => PyNum::Float(py_round(f, d)),
                };
                format!("{} {unit}{suffix}", rounded.py_str())
            };
        }
        num = PyNum::Float(num.f() / 1000.0);
    }
    format!("{:.2}Y{suffix}", num.f())
}

/// `RNS.prettytime(t, compact=...)`, not verbose.
pub fn prettytime(time: PyNum, compact: bool) -> String {
    let neg = time.f() < 0.0;
    let (days, hours, minutes, seconds) = match time {
        PyNum::Int(t) => {
            let t = t.abs();
            let rest = t % 86400;
            (
                t / 86400,
                rest / 3600,
                (rest % 3600) / 60,
                PyNum::Int(rest % 3600 % 60),
            )
        }
        PyNum::Float(t) => {
            let t = t.abs();
            let days = (t / 86400.0).floor();
            let mut rest = t % 86400.0;
            let hours = (rest / 3600.0).floor();
            rest %= 3600.0;
            let minutes = (rest / 60.0).floor();
            rest %= 60.0;
            let seconds = if compact {
                PyNum::Int(rest as i64)
            } else {
                PyNum::Float(py_round(rest, 2))
            };
            (days as i64, hours as i64, minutes as i64, seconds)
        }
    };
    let mut components = Vec::new();
    for (value, unit) in [(days, "d"), (hours, "h"), (minutes, "m")] {
        if value > 0 && (!compact || components.len() < 2) {
            components.push(format!("{value}{unit}"));
        }
    }
    if seconds.f() > 0.0 && (!compact || components.len() < 2) {
        components.push(format!("{}s", seconds.py_str()));
    }
    let count = components.len();
    let mut out = String::new();
    for (i, c) in components.iter().enumerate() {
        if i > 0 {
            out.push_str(if i + 1 < count { ", " } else { " and " });
        }
        out.push_str(c);
    }
    if out.is_empty() {
        "0s".to_string()
    } else if neg {
        format!("-{out}")
    } else {
        out
    }
}

/// `RNS.prettyshorttime(t, tight=True)`.
pub fn prettyshorttime(time: f64) -> String {
    let neg = time < 0.0;
    let mut time = (time * 1e6).abs();
    let seconds = (time / 1e6).floor() as i64;
    time %= 1e6;
    let millis = (time / 1e3).floor() as i64;
    time %= 1e3;
    let micros = py_round(time, 2);
    let mut components = Vec::new();
    if seconds > 0 {
        components.push(format!("{seconds}s"));
    }
    if millis > 0 {
        components.push(format!("{millis}ms"));
    }
    if micros > 0.0 {
        components.push(format!("{}µs", py_float_repr(micros)));
    }
    let out = components.join(" ");
    if out.is_empty() {
        "0us".to_string()
    } else if neg {
        format!("-{out}")
    } else {
        out
    }
}

/// `RNS.prettycost`: the quantized cost to three decimals, `n` for
/// anything but a number.
pub fn pretty_cost(cost: Option<f64>) -> String {
    match cost.map(rns_identity::stamps::quantize_cost) {
        Some(Ok(cost)) => format!("{cost:.3}"),
        _ => "n".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pretty_size() {
        assert_eq!(pretty_size(0), "0 B");
        assert_eq!(pretty_size(100), "100 B");
        assert_eq!(pretty_size(999), "999 B");
        assert_eq!(pretty_size(1000), "1.00 KB");
        assert_eq!(pretty_size(1024), "1.02 KB");
        assert_eq!(pretty_size(1536), "1.54 KB");
        assert_eq!(pretty_size(1048576), "1.05 MB");
        assert_eq!(pretty_size(1073741824), "1.07 GB");
    }

    #[test]
    fn test_pretty_speed() {
        assert_eq!(pretty_speed(0), "0 bps");
        assert_eq!(pretty_speed(115200), "115.20 Kbps");
        assert_eq!(pretty_speed(1000000), "1.00 Mbps");
        assert_eq!(pretty_speed(1000000000), "1.00 Gbps");
    }

    #[test]
    fn test_pretty_time() {
        assert_eq!(pretty_time(30.0), "30s");
        assert_eq!(pretty_time(90.0), "1m 30s");
        assert_eq!(pretty_time(3661.0), "1h 1m");
        assert_eq!(pretty_time(90061.0), "1d 1h");
        assert_eq!(pretty_time(-1.0), "unknown");
    }

    #[test]
    fn test_pretty_frequency() {
        assert_eq!(pretty_frequency(433_000_000.0), "433.000 MHz");
        assert_eq!(pretty_frequency(868_000_000.0), "868.000 MHz");
        assert_eq!(pretty_frequency(2_400_000_000.0), "2.400 GHz");
    }

    #[test]
    fn test_hex_rep() {
        assert_eq!(hex_rep(&[0xAA, 0xBB, 0xCC]), "aa:bb:cc");
    }

    #[test]
    fn test_pretty_hex_rep() {
        assert_eq!(pretty_hex_rep(&[0xAA, 0xBB]), "<aabb>");
    }
}
