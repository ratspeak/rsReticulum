//! Endpoint checks upstream applies to `reachable_on`: `is_ip_address` and
//! `is_hostname` (RNS/Discovery.py:982-1007@1.6.0). Upstream uses them on
//! receive, before announcing and when listing stored records.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Python `ipaddress.ip_address(s)` accepts the string: IPv4 without leading
/// zeros, or IPv6 with an optional non-empty `%scope` suffix.
pub fn is_ip_address(s: &str) -> bool {
    if s.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    let addr = match s.split_once('%') {
        Some((_, scope)) if scope.is_empty() || scope.contains('%') => return false,
        Some((addr, _)) => addr,
        None => s,
    };
    addr.parse::<Ipv6Addr>().is_ok()
}

/// Python `is_hostname`. `None` where upstream raises instead of answering,
/// which is an empty string.
pub fn is_hostname(hostname: &str) -> Option<bool> {
    let hostname = match hostname.chars().last()? {
        '.' => &hostname[..hostname.len() - 1],
        _ => hostname,
    };
    if hostname.chars().count() > 253 {
        return Some(false);
    }
    let components: Vec<&str> = hostname.split('.').collect();
    let last = before_final_newline(components[components.len() - 1]);
    if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
        return Some(false);
    }
    Some(components.iter().all(|label| valid_label(label)))
}

/// `is_ip_address(s) or is_hostname(s)`, `None` where upstream raises.
pub fn is_valid_address(s: &str) -> Option<bool> {
    if is_ip_address(s) {
        Some(true)
    } else {
        is_hostname(s)
    }
}

/// A regex `$` also matches just before a final newline.
fn before_final_newline(s: &str) -> &str {
    s.strip_suffix('\n').unwrap_or(s)
}

/// `(?!-)[a-z0-9-]{1,63}(?<!-)$` with `re.IGNORECASE`, which also folds four
/// non-ASCII letters onto `i`, `s` and `k`.
fn valid_label(label: &str) -> bool {
    let label = before_final_newline(label);
    let count = label.chars().count();
    (1..=63).contains(&count)
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || c == '-'
                || matches!(c, '\u{130}' | '\u{131}' | '\u{17f}' | '\u{212a}')
        })
}
