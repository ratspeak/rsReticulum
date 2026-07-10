//! Python ref: `RNS/__init__.py` (`prettyspeed`, `prettysize`, `prettytime`).

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
