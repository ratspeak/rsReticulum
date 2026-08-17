//! INI parser compatible with the ConfigObj subset used by Python Reticulum:
//! nested sections, quoted keys/sections/values, ConfigObj list values,
//! multiline values, `#` comments outside quotes, and boolean variants
//! `True`/`Yes`/`On`/`1`.

use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
    #[error("missing required key: [{section}] {key}")]
    MissingKey { section: String, key: String },
    #[error("invalid value for [{section}] {key}: {message}")]
    InvalidValue {
        section: String,
        key: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValue {
    Scalar(String),
    List(Vec<String>),
}

impl ConfigValue {
    fn as_str(&self) -> Option<&str> {
        match self {
            ConfigValue::Scalar(value) => Some(value.as_str()),
            ConfigValue::List(_) => None,
        }
    }

    fn as_list(&self) -> Vec<String> {
        match self {
            ConfigValue::Scalar(value) => vec![value.clone()],
            ConfigValue::List(values) => values.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConfigSection {
    pub values: HashMap<String, ConfigValue>,
    value_order: Vec<String>,
    pub subsections: HashMap<String, ConfigSection>,
    subsection_order: Vec<String>,
}

impl ConfigSection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).and_then(ConfigValue::as_str)
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        let v = self.get(key)?;
        parse_bool(v)
    }

    pub fn get_bool_or(&self, key: &str, default: bool) -> bool {
        self.get_bool(key).unwrap_or(default)
    }

    pub fn get_int(&self, key: &str) -> Option<i64> {
        let v = self.get(key)?;
        v.parse().ok()
    }

    pub fn get_uint(&self, key: &str) -> Option<u64> {
        let v = self.get(key)?;
        v.parse().ok()
    }

    pub fn get_float(&self, key: &str) -> Option<f64> {
        let v = self.get(key)?;
        v.parse().ok()
    }

    pub fn get_list(&self, key: &str) -> Option<Vec<String>> {
        let v = self.values.get(key)?;
        Some(v.as_list())
    }

    pub fn get_hex(&self, key: &str) -> Option<Vec<u8>> {
        let v = self.get(key)?;
        hex_decode(v.trim())
    }

    pub fn has(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    pub fn set(&mut self, key: &str, value: &str) {
        self.set_value(key.to_string(), ConfigValue::Scalar(value.to_string()));
    }

    pub fn set_list(&mut self, key: &str, value: Vec<String>) {
        self.set_value(key.to_string(), ConfigValue::List(value));
    }

    fn set_value(&mut self, key: String, value: ConfigValue) {
        if !self.values.contains_key(&key) {
            self.value_order.push(key.clone());
        }
        self.values.insert(key, value);
    }

    fn insert_value(
        &mut self,
        key: String,
        value: ConfigValue,
        line: usize,
    ) -> Result<(), ConfigError> {
        if self.values.contains_key(&key) {
            return Err(ConfigError::Parse {
                line,
                message: "duplicate keyword name".to_string(),
            });
        }
        self.value_order.push(key.clone());
        self.values.insert(key, value);
        Ok(())
    }

    fn insert_subsection(
        &mut self,
        name: String,
        line: usize,
    ) -> Result<&mut ConfigSection, ConfigError> {
        if self.subsections.contains_key(&name) {
            return Err(ConfigError::Parse {
                line,
                message: "duplicate section name".to_string(),
            });
        }
        self.subsection_order.push(name.clone());
        self.subsections.insert(name.clone(), ConfigSection::new());
        Ok(self.subsections.get_mut(&name).unwrap())
    }
}

/// Keys before any `[section]` header land under the empty-string section.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub sections: HashMap<String, ConfigSection>,
    section_order: Vec<String>,
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mirrors Python ConfigObj file loading, including normal OS symlink
    /// following. Security policy for config paths must be enforced by callers.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let mut config = Self::parse(&content)?;
        config.prepare_loaded_reticulum_config(path)?;
        Ok(config)
    }

    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let mut config = Config::new();
        let mut current_section: Option<String> = None;
        let mut current_path: Vec<String> = Vec::new();
        let lines: Vec<&str> = input.lines().collect();
        let mut index = 0;

        while index < lines.len() {
            let line_num = index + 1;
            let raw_line = lines[index];
            let line = strip_comment(raw_line).trim().to_string();

            if line.is_empty() {
                index += 1;
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                let open_depth = line.chars().take_while(|&ch| ch == '[').count();
                let close_depth = line.chars().rev().take_while(|&ch| ch == ']').count();
                if open_depth != close_depth {
                    return Err(ConfigError::Parse {
                        line: line_num,
                        message: "mismatched section brackets".to_string(),
                    });
                }

                let name = unquote_token(line[open_depth..line.len() - close_depth].trim())
                    .map_err(|message| ConfigError::Parse {
                        line: line_num,
                        message,
                    })?;
                if name.is_empty() {
                    return Err(ConfigError::Parse {
                        line: line_num,
                        message: if open_depth == 1 {
                            "empty section name".to_string()
                        } else {
                            "empty subsection name".to_string()
                        },
                    });
                }

                if open_depth == 1 {
                    if config.sections.contains_key(&name) {
                        return Err(ConfigError::Parse {
                            line: line_num,
                            message: "duplicate section name".to_string(),
                        });
                    }
                    current_section = Some(name.clone());
                    current_path.clear();
                    config.section_order.push(name.clone());
                    config.sections.insert(name, ConfigSection::new());
                } else {
                    if current_section.is_none() {
                        return Err(ConfigError::Parse {
                            line: line_num,
                            message: "subsection without parent section".to_string(),
                        });
                    }

                    let parent_depth = open_depth - 2;
                    if current_path.len() < parent_depth {
                        return Err(ConfigError::Parse {
                            line: line_num,
                            message: "section too nested".to_string(),
                        });
                    }
                    let section_name = current_section.as_ref().unwrap();
                    let section = config.sections.get_mut(section_name).unwrap();
                    let parent = section_for_path_mut(section, &current_path[..parent_depth]);
                    parent.insert_subsection(name.clone(), line_num)?;

                    current_path.truncate(parent_depth);
                    current_path.push(name);
                }
                index += 1;
                continue;
            }

            if let Some(eq_pos) = line.find('=') {
                let key =
                    unquote_token(line[..eq_pos].trim()).map_err(|message| ConfigError::Parse {
                        line: line_num,
                        message,
                    })?;
                let (value, consumed_index) =
                    parse_config_value(line[eq_pos + 1..].trim(), &lines, index)?;

                if key.is_empty() {
                    return Err(ConfigError::Parse {
                        line: line_num,
                        message: "empty key".to_string(),
                    });
                }

                match &current_section {
                    Some(sec) => {
                        let section = config.sections.get_mut(sec).unwrap();
                        section_for_path_mut(section, &current_path)
                            .insert_value(key, value, line_num)?;
                    }
                    None => {
                        config
                            .root_section_mut()
                            .insert_value(key, value, line_num)?;
                    }
                }
                index = consumed_index + 1;
                continue;
            }

            return Err(ConfigError::Parse {
                line: line_num,
                message: format!("unrecognized line: {line}"),
            });
        }

        Ok(config)
    }

    pub fn section(&self, name: &str) -> Option<&ConfigSection> {
        self.sections.get(name)
    }

    pub fn section_mut(&mut self, name: &str) -> Option<&mut ConfigSection> {
        self.sections.get_mut(name)
    }

    pub fn subsection(&self, section: &str, subsection: &str) -> Option<&ConfigSection> {
        self.sections
            .get(section)
            .and_then(|s| s.subsections.get(subsection))
    }

    pub fn subsections(&self, section: &str) -> Vec<(&str, &ConfigSection)> {
        match self.sections.get(section) {
            Some(s) => s
                .subsection_order
                .iter()
                .filter_map(|k| s.subsections.get_key_value(k))
                .map(|(k, v)| (k.as_str(), v))
                .collect(),
            None => Vec::new(),
        }
    }

    pub fn default_config() -> &'static str {
        DEFAULT_CONFIG
    }

    pub fn write_default(path: &Path) -> Result<(), ConfigError> {
        std::fs::write(path, DEFAULT_CONFIG)?;
        Ok(())
    }

    fn prepare_loaded_reticulum_config(&mut self, _config_path: &Path) -> Result<(), ConfigError> {
        let Some(section) = self.section_mut("reticulum") else {
            return Ok(());
        };

        validate_identity_hash_list(section, "remote_management_allowed")?;
        validate_identity_hash_list(section, "blackhole_sources")?;
        validate_identity_hash_list(section, "interface_discovery_sources")?;

        Ok(())
    }

    fn root_section_mut(&mut self) -> &mut ConfigSection {
        if !self.sections.contains_key("") {
            self.section_order.push(String::new());
            self.sections.insert(String::new(), ConfigSection::new());
        }
        self.sections.get_mut("").unwrap()
    }
}

fn section_for_path_mut<'a>(
    mut section: &'a mut ConfigSection,
    path: &[String],
) -> &'a mut ConfigSection {
    for part in path {
        section = section
            .subsections
            .get_mut(part)
            .expect("current subsection path was not initialised");
    }
    section
}

fn unquote_token(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("empty quoted value".to_string());
    }
    let Some(first) = value.chars().next() else {
        return Err("empty quoted value".to_string());
    };
    if first == '"' || first == '\'' {
        if !value.ends_with(first) || value.len() < 2 {
            return Err("parse error in value".to_string());
        }
        Ok(value[1..value.len() - 1].to_string())
    } else {
        Ok(value.to_string())
    }
}

fn parse_config_value(
    raw: &str,
    lines: &[&str],
    index: usize,
) -> Result<(ConfigValue, usize), ConfigError> {
    if raw.starts_with("\"\"\"") || raw.starts_with("'''") {
        return parse_multiline_value(raw, lines, index);
    }

    parse_single_line_value(raw)
        .map(|value| (value, index))
        .map_err(|message| ConfigError::Parse {
            line: index + 1,
            message,
        })
}

fn parse_multiline_value(
    raw: &str,
    lines: &[&str],
    index: usize,
) -> Result<(ConfigValue, usize), ConfigError> {
    let quote = &raw[..3];
    let rest = &raw[3..];
    if let Some(end) = rest.find(quote) {
        return Ok((ConfigValue::Scalar(rest[..end].to_string()), index));
    }

    let mut value = rest.to_string();
    let mut current = index;
    while current + 1 < lines.len() {
        current += 1;
        value.push('\n');
        let line = lines[current];
        if let Some(end) = line.find(quote) {
            value.push_str(&line[..end]);
            return Ok((ConfigValue::Scalar(value), current));
        }
        value.push_str(line);
    }

    Err(ConfigError::Parse {
        line: index + 1,
        message: "unterminated multiline value".to_string(),
    })
}

fn parse_single_line_value(raw: &str) -> Result<ConfigValue, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(ConfigValue::Scalar(String::new()));
    }
    if value == "," {
        return Ok(ConfigValue::List(Vec::new()));
    }

    let (mut parts, saw_comma) = split_value_parts(value)?;
    if saw_comma {
        if parts.last().is_some_and(|part| part.trim().is_empty()) {
            parts.pop();
        }
        let mut values = Vec::with_capacity(parts.len());
        for part in parts {
            let part = part.trim();
            if part.is_empty() {
                return Err("parse error in value".to_string());
            }
            values.push(unquote_token(part)?);
        }
        return Ok(ConfigValue::List(values));
    }

    Ok(ConfigValue::Scalar(unquote_token(value)?))
}

fn split_value_parts(value: &str) -> Result<(Vec<String>, bool), String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut quoted_item_closed = false;
    let mut item_started = false;
    let mut saw_comma = false;

    for ch in value.chars() {
        if let Some(q) = quote {
            current.push(ch);
            if ch == q {
                quote = None;
                quoted_item_closed = true;
            }
            continue;
        }

        if quoted_item_closed {
            if ch == ',' {
                parts.push(current.trim().to_string());
                current.clear();
                quoted_item_closed = false;
                item_started = false;
                saw_comma = true;
            } else if ch.is_whitespace() {
                current.push(ch);
            } else {
                return Err("parse error in value".to_string());
            }
            continue;
        }

        if ch == ',' {
            parts.push(current.trim().to_string());
            current.clear();
            item_started = false;
            saw_comma = true;
        } else if (ch == '"' || ch == '\'') && !item_started {
            quote = Some(ch);
            item_started = true;
            current.push(ch);
        } else {
            if !ch.is_whitespace() {
                item_started = true;
            }
            current.push(ch);
        }
    }

    if quote.is_some() {
        return Err("parse error in value".to_string());
    }

    if saw_comma {
        parts.push(current.trim().to_string());
    }

    Ok((parts, saw_comma))
}

/// Truncate at the first `#` outside a quoted string.
fn strip_comment(line: &str) -> &str {
    let mut in_quote = false;
    let mut quote_char = ' ';
    for (i, ch) in line.char_indices() {
        if in_quote {
            if ch == quote_char {
                in_quote = false;
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = true;
            quote_char = ch;
        } else if ch == '#' {
            return &line[..i];
        }
    }
    line
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

fn validate_identity_hash_list(section: &ConfigSection, key: &str) -> Result<(), ConfigError> {
    let Some(values) = section.get_list(key) else {
        return Ok(());
    };

    for value in values {
        let hexhash = value.trim();
        if hexhash.len() != 32 {
            return Err(ConfigError::InvalidValue {
                section: "reticulum".to_string(),
                key: key.to_string(),
                message: format!(
                    "identity hash {hexhash} must be 32 hexadecimal characters (16 bytes)"
                ),
            });
        }
        if hex_decode(hexhash).is_none() {
            return Err(ConfigError::InvalidValue {
                section: "reticulum".to_string(),
                key: key.to_string(),
                message: format!("invalid identity hash: {hexhash}"),
            });
        }
    }

    Ok(())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

const DEFAULT_CONFIG: &str = r#"# This is the default Reticulum config file.

[reticulum]
enable_transport = False
share_instance = Yes
instance_name = default

[logging]
loglevel = 4

[interfaces]

[[Default Interface]]
type = AutoInterface
enabled = Yes
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_empty() {
        let config = Config::parse("").unwrap();
        assert!(config.sections.is_empty());
    }

    #[test]
    fn test_parse_section() {
        let config = Config::parse("[reticulum]\nshare_instance = Yes\n").unwrap();
        let sec = config.section("reticulum").unwrap();
        assert_eq!(sec.get_bool("share_instance"), Some(true));
    }

    #[test]
    fn test_parse_subsection() {
        let input = r#"
[interfaces]

[[My UDP Interface]]
type = UDPInterface
enabled = yes
listen_port = 4242
"#;
        let config = Config::parse(input).unwrap();
        let subs = config.subsections("interfaces");
        assert_eq!(subs.len(), 1);
        let (name, sub) = &subs[0];
        assert_eq!(*name, "My UDP Interface");
        assert_eq!(sub.get("type"), Some("UDPInterface"));
        assert_eq!(sub.get_bool("enabled"), Some(true));
        assert_eq!(sub.get_uint("listen_port"), Some(4242));
    }

    #[test]
    fn test_parse_nested_subsection() {
        let input = r#"
[interfaces]

[[OpenCom XL]]
type = RNodeMultiInterface
port = /dev/ttyACM0

[[[High Datarate]]]
enabled = yes
vport = 1
frequency = 2400000000

[[[Low Datarate]]]
enabled = no
vport = 0
frequency = 865600000
"#;
        let config = Config::parse(input).unwrap();
        let iface = config.section("interfaces").unwrap();
        let rnode = iface.subsections.get("OpenCom XL").unwrap();
        assert_eq!(rnode.get("type"), Some("RNodeMultiInterface"));
        assert_eq!(rnode.get("port"), Some("/dev/ttyACM0"));

        let high = rnode.subsections.get("High Datarate").unwrap();
        assert_eq!(high.get_bool("enabled"), Some(true));
        assert_eq!(high.get_uint("vport"), Some(1));
        assert_eq!(high.get_uint("frequency"), Some(2_400_000_000));

        let low = rnode.subsections.get("Low Datarate").unwrap();
        assert_eq!(low.get_bool("enabled"), Some(false));
        assert_eq!(low.get_uint("vport"), Some(0));
        assert_eq!(low.get_uint("frequency"), Some(865_600_000));
    }

    #[test]
    fn test_parse_comments() {
        let input = "# Full line comment\n[sec]\nkey = value # inline comment\n";
        let config = Config::parse(input).unwrap();
        let sec = config.section("sec").unwrap();
        assert_eq!(sec.get("key"), Some("value"));
    }

    #[test]
    fn test_parse_bool_variants() {
        assert_eq!(parse_bool("True"), Some(true));
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("YES"), Some(true));
        assert_eq!(parse_bool("yes"), Some(true));
        assert_eq!(parse_bool("On"), Some(true));
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("False"), Some(false));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("NO"), Some(false));
        assert_eq!(parse_bool("no"), Some(false));
        assert_eq!(parse_bool("Off"), Some(false));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
    }

    #[test]
    fn test_get_list() {
        let input = "[sec]\nitems = one, two, three\n";
        let config = Config::parse(input).unwrap();
        let sec = config.section("sec").unwrap();
        let list = sec.get_list("items").unwrap();
        assert_eq!(list, vec!["one", "two", "three"]);
    }

    #[test]
    fn test_get_hex() {
        let input = "[sec]\nkey = aabbccdd\n";
        let config = Config::parse(input).unwrap();
        let sec = config.section("sec").unwrap();
        let bytes = sec.get_hex("key").unwrap();
        assert_eq!(bytes, vec![0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn test_get_float() {
        let input = "[sec]\nval = 1.25\n";
        let config = Config::parse(input).unwrap();
        let sec = config.section("sec").unwrap();
        assert!((sec.get_float("val").unwrap() - 1.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_keys_preserve_case_like_configobj() {
        let input = "[sec]\nMyKey = hello\n";
        let config = Config::parse(input).unwrap();
        let sec = config.section("sec").unwrap();
        assert_eq!(sec.get("MyKey"), Some("hello"));
        assert_eq!(sec.get("mykey"), None);
    }

    #[test]
    fn test_configobj_quoted_values_and_lists() {
        let input = r#"
[sec]
empty =
empty_list = ,
quoted_empty = ""
quoted_hash = "value # kept" # dropped
quoted_comma = "one,two"
items = "one", "two,three", four,
"quoted key" = "quoted value"
"#;
        let config = Config::parse(input).unwrap();
        let sec = config.section("sec").unwrap();
        assert_eq!(sec.get("empty"), Some(""));
        assert_eq!(sec.get_list("empty"), Some(vec![String::new()]));
        assert_eq!(sec.get_list("empty_list"), Some(Vec::new()));
        assert_eq!(sec.get("quoted_empty"), Some(""));
        assert_eq!(sec.get("quoted_hash"), Some("value # kept"));
        assert_eq!(sec.get("quoted_comma"), Some("one,two"));
        assert_eq!(
            sec.get_list("items").unwrap(),
            vec!["one", "two,three", "four"]
        );
        assert_eq!(sec.get("quoted key"), Some("quoted value"));
    }

    #[test]
    fn test_configobj_quoted_sections_and_multiline_values() {
        let input = "[interfaces]\n[[\"My Interface\"]]\ntype = AutoInterface\nnotes = \"\"\"first\nsecond\"\"\"\n";
        let config = Config::parse(input).unwrap();
        let iface = config.subsection("interfaces", "My Interface").unwrap();
        assert_eq!(iface.get("type"), Some("AutoInterface"));
        assert_eq!(iface.get("notes"), Some("first\nsecond"));
    }

    #[test]
    fn test_duplicate_keys_and_sections_fail_like_configobj() {
        assert!(Config::parse("[sec]\nkey = one\nkey = two\n").is_err());
        assert!(Config::parse("[sec]\nkey = one\n[sec]\nkey = two\n").is_err());
        assert!(Config::parse("[interfaces]\n[[iface]]\ntype = A\n[[iface]]\ntype = B\n").is_err());
    }

    #[test]
    fn test_malformed_configobj_values_fail() {
        assert!(Config::parse("[sec]\nkey = \"unterminated\n").is_err());
        assert!(Config::parse("[sec]\nkey = one,,two\n").is_err());
        assert!(Config::parse("[sec]\nkey = one, , two\n").is_err());
        assert!(Config::parse("[sec]\nkey = \"\"\"unterminated\n").is_err());
    }

    #[test]
    fn test_multiple_sections() {
        let input = "[reticulum]\nkey1 = v1\n[logging]\nkey2 = v2\n";
        let config = Config::parse(input).unwrap();
        assert_eq!(config.section("reticulum").unwrap().get("key1"), Some("v1"));
        assert_eq!(config.section("logging").unwrap().get("key2"), Some("v2"));
    }

    #[test]
    fn test_multiple_subsections() {
        let input = r#"
[interfaces]
[[iface1]]
type = TCPClientInterface
[[iface2]]
type = UDPInterface
"#;
        let config = Config::parse(input).unwrap();
        let subs = config.subsections("interfaces");
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].0, "iface1");
        assert_eq!(subs[1].0, "iface2");
    }

    #[test]
    fn test_named_subsection_lookup() {
        let input = r#"
[interfaces]
[[iface1]]
type = TCPClientInterface
[[iface2]]
type = UDPInterface
"#;
        let config = Config::parse(input).unwrap();
        assert_eq!(
            config
                .subsection("interfaces", "iface2")
                .and_then(|s| s.get("type")),
            Some("UDPInterface")
        );
        assert!(config.subsection("interfaces", "missing").is_none());
    }

    #[test]
    fn test_subsection_without_section_fails() {
        let result = Config::parse("[[orphan]]\nkey = val\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_nested_subsection_without_parent_fails() {
        let result = Config::parse("[interfaces]\n[[[orphan]]]\nkey = val\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_section_name_fails() {
        let result = Config::parse("[]\nkey = val\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_default_config_parses() {
        let config = Config::parse(Config::default_config()).unwrap();
        let ret = config.section("reticulum").unwrap();
        assert_eq!(ret.get_bool("share_instance"), Some(true));
        assert_eq!(ret.get_bool("enable_transport"), Some(false));
        assert_eq!(ret.get("instance_name"), Some("default"));
        assert_eq!(ret.get_uint("shared_instance_port"), None);
    }

    #[test]
    fn test_loaded_config_rejects_malformed_identity_hash_lists() {
        let dir = unique_test_dir("hash-list-validation");
        let path = dir.join("config");
        std::fs::write(&path, "[reticulum]\nremote_management_allowed = deadbeef\n").unwrap();

        assert!(matches!(
            Config::from_file(&path),
            Err(ConfigError::InvalidValue { key, .. }) if key == "remote_management_allowed"
        ));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_loaded_config_preserves_network_identity_value_without_side_effect() {
        let dir = unique_test_dir("network-identity");
        let identity = dir.join("network.identity");
        let path = dir.join("config");
        std::fs::write(
            &path,
            format!(
                "[reticulum]\nnetwork_identity = {}\n",
                identity.file_name().unwrap().to_string_lossy()
            ),
        )
        .unwrap();

        let config = Config::from_file(&path).unwrap();
        assert!(!identity.is_file());
        let expected = identity.file_name().unwrap().to_string_lossy();
        assert_eq!(
            config
                .section("reticulum")
                .and_then(|section| section.get("network_identity")),
            Some(expected.as_ref())
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_from_file_follows_symlink_like_configobj() {
        let dir = unique_test_dir("symlink-config");
        let target = dir.join("target_config");
        let link = dir.join("config");
        std::fs::write(&target, "[reticulum]\nshare_instance = No\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let config = Config::from_file(&link).unwrap();
        assert_eq!(
            config
                .section("reticulum")
                .and_then(|section| section.get_bool("share_instance")),
            Some(false)
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_get_bool_or_default() {
        let sec = ConfigSection::new();
        assert!(sec.get_bool_or("missing", true));
        assert!(!sec.get_bool_or("missing", false));
    }

    #[test]
    fn test_strip_comment_in_quotes() {
        let result = strip_comment(r#"key = "value # with hash""#);
        assert_eq!(result, r#"key = "value # with hash""#);
    }

    fn unique_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "reticulum_config_test_{name}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
