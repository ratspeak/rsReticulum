//! Python `str()`/`repr()` rendering of msgpack values, as printed by
//! `rnid -V <file>.rsm --meta` (`RNS/Utilities/rnid.py`),
//! and of the exceptions the rsg tools print.

use rmpv::Value;

/// Python `str(value)`: strings unquoted, containers use member `repr`.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => match s.as_str() {
            Some(s) => s.to_string(),
            None => py_bytes_repr(s.as_bytes()),
        },
        _ => py_repr(value),
    }
}

/// Python `repr(value)` of the object umsgpack would unpack.
pub fn py_repr(value: &Value) -> String {
    match value {
        Value::Nil => "None".to_string(),
        Value::Boolean(b) => if *b { "True" } else { "False" }.to_string(),
        Value::Integer(i) => format!("{i}"),
        Value::F32(f) => py_float(f64::from(*f)),
        Value::F64(f) => py_float(*f),
        Value::String(s) => match s.as_str() {
            Some(s) => py_str_repr(s),
            None => py_bytes_repr(s.as_bytes()),
        },
        Value::Binary(b) => py_bytes_repr(b),
        Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", rendered.join(", "))
        }
        Value::Map(entries) => {
            let rendered: Vec<String> = entries
                .iter()
                .map(|(k, v)| format!("{}: {}", py_repr(k), py_repr(v)))
                .collect();
            format!("{{{}}}", rendered.join(", "))
        }
        Value::Ext(kind, data) => {
            let mut s = format!("Ext Object (Type: {kind}, Data: ");
            let shown: Vec<String> = data.iter().take(8).map(|b| format!("0x{b:02}")).collect();
            s.push_str(&shown.join(" "));
            if data.len() > 8 {
                s.push_str(" ...");
            }
            s.push(')');
            s
        }
    }
}

fn quote_for(has_single: bool, has_double: bool) -> char {
    if has_single && !has_double { '"' } else { '\'' }
}

fn py_printable(c: char) -> bool {
    !(c.is_control()
        || matches!(
            c,
            '\u{a0}' | '\u{ad}' | '\u{1680}' | '\u{2000}'..='\u{200f}' | '\u{2028}'..='\u{202f}'
                | '\u{205f}'..='\u{206f}' | '\u{3000}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}'
                | '\u{e000}'..='\u{f8ff}' | '\u{f0000}'..='\u{10ffff}'
        ))
}

/// Python `repr(str)`.
pub fn py_str_repr(s: &str) -> String {
    let quote = quote_for(s.contains('\''), s.contains('"'));
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if py_printable(c) => out.push(c),
            c if (c as u32) < 0x100 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push(quote);
    out
}

/// Python `repr(bytes)`.
pub fn py_bytes_repr(b: &[u8]) -> String {
    let quote = quote_for(b.contains(&b'\''), b.contains(&b'"'));
    let mut out = String::from("b");
    out.push(quote);
    for &byte in b {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            c if c as char == quote => {
                out.push('\\');
                out.push(c as char);
            }
            0x20..=0x7e => out.push(byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push(quote);
    out
}

/// Python `repr(float)`: shortest round-trip digits, exponent form outside
/// `1e-4 <= |x| < 1e16`.
pub fn py_float(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    let sci = format!("{value:e}");
    let (mantissa, exp) = sci.split_once('e').expect("exponent form");
    let exp: i32 = exp.parse().expect("exponent");
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if negative { "-" } else { "" };
    if (-4..16).contains(&exp) {
        let point = exp + 1;
        let body = if point <= 0 {
            format!("0.{}{}", "0".repeat((-point) as usize), digits)
        } else if point as usize >= digits.len() {
            format!("{}{}.0", digits, "0".repeat(point as usize - digits.len()))
        } else {
            let (int, frac) = digits.split_at(point as usize);
            format!("{int}.{frac}")
        };
        format!("{sign}{body}")
    } else {
        let mut m = digits[..1].to_string();
        if digits.len() > 1 {
            m.push('.');
            m.push_str(&digits[1..]);
        }
        let esign = if exp < 0 { '-' } else { '+' };
        format!("{sign}{m}e{esign}{:02}", exp.abs())
    }
}

/// `bytes.fromhex`.
pub fn py_fromhex(text: &str) -> Result<Vec<u8>, String> {
    let chars: Vec<char> = text.chars().collect();
    let err =
        |pos: usize| format!("non-hexadecimal number found in fromhex() arg at position {pos}");
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if matches!(chars[i], ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r') {
            i += 1;
            continue;
        }
        let hi = chars[i].to_digit(16).ok_or_else(|| err(i))?;
        let lo = chars
            .get(i + 1)
            .and_then(|c| c.to_digit(16))
            .ok_or_else(|| err(i + 1))?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Ok(out)
}

/// Python `str(OSError)` for a failed file operation.
pub fn py_os_error(error: &std::io::Error, path: &str) -> String {
    match error.raw_os_error() {
        Some(code) => format!(
            "[Errno {code}] {}: {}",
            nix::errno::Errno::from_raw(code).desc(),
            py_str_repr(path)
        ),
        None => error.to_string(),
    }
}

/// Text of the `UnicodeDecodeError` CPython raises for `data.decode("utf-8")`.
pub fn py_utf8_error(data: &[u8]) -> Option<String> {
    let err = std::str::from_utf8(data).err()?;
    let start = err.valid_up_to();
    let (len, reason) = match err.error_len() {
        None => (data.len() - start, "unexpected end of data"),
        Some(n) => {
            let lead = data[start];
            let invalid_start = (0x80..=0xc1).contains(&lead) || lead >= 0xf5;
            (
                n,
                if invalid_start {
                    "invalid start byte"
                } else {
                    "invalid continuation byte"
                },
            )
        }
    };
    Some(if len == 1 {
        format!(
            "'utf-8' codec can't decode byte 0x{:02x} in position {start}: {reason}",
            data[start]
        )
    } else {
        format!(
            "'utf-8' codec can't decode bytes in position {start}-{}: {reason}",
            start + len - 1
        )
    })
}
