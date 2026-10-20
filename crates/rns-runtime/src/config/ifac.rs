//! Explicit IFAC units and surgical, owner-selected legacy migration.
//!
//! Runtime sizes remain bytes. File `ifac_size` is bits; ambiguous old values
//! require an explicit migration choice, never an inferred producer/version.

use super::{
    Config, ConfigError, ConfigSection, ConfigValue, parse_config_value, strip_comment,
    unquote_token,
};
use rns_crypto::sha::sha256;
use std::collections::HashSet;
use std::ops::Range;

pub const SIZE_KEYS: &[&str] = &["ifac_size", "ifac_size_unit", "ifac_size_bytes"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IfacConfigError {
    #[error("ifac_size has ambiguous units; choose the existing byte size or Python bit size")]
    IfacUnitsRequired,
    #[error("{field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
}

fn invalid(field: &'static str, reason: &'static str) -> IfacConfigError {
    IfacConfigError::Invalid { field, reason }
}
fn scalar<'a>(
    section: &'a ConfigSection,
    key: &'static str,
) -> Result<Option<&'a str>, IfacConfigError> {
    match section.values.get(key) {
        None => Ok(None),
        Some(ConfigValue::Scalar(v)) => Ok(Some(v.as_str())),
        Some(_) => Err(invalid(key, "must be one integer scalar")),
    }
}
fn integer(section: &ConfigSection, key: &'static str) -> Result<Option<usize>, IfacConfigError> {
    scalar(section, key)?
        .map(|v| {
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid(key, "must be an unsigned decimal integer"));
            }
            v.parse::<usize>()
                .map_err(|_| invalid(key, "integer overflow"))
        })
        .transpose()
}

/// Decode file units without changing credential activation or class defaults.
/// A legacy byte escape must be diagnosed by the caller when present.
pub fn parse_ifac_size(section: &ConfigSection) -> Result<Option<usize>, IfacConfigError> {
    let has_bits = section.has("ifac_size");
    let has_unit = section.has("ifac_size_unit");
    if section.has("ifac_size_bytes") {
        if has_bits || has_unit {
            return Err(invalid(
                "ifac_size_bytes",
                "cannot coexist with ifac_size or ifac_size_unit",
            ));
        }
        let bytes = integer(section, "ifac_size_bytes")?.expect("present scalar");
        return if (1..=64).contains(&bytes) {
            Ok(Some(bytes))
        } else {
            Err(invalid("ifac_size_bytes", "must be in 1..64 bytes"))
        };
    }
    let unit = scalar(section, "ifac_size_unit")?;
    if unit.is_some_and(|u| u != "bits") {
        return Err(invalid("ifac_size_unit", "must be exactly bits"));
    }
    if !has_bits {
        return if has_unit {
            Err(invalid("ifac_size_unit", "requires ifac_size"))
        } else {
            Ok(None)
        };
    }
    let bits = integer(section, "ifac_size")?.expect("present scalar");
    if unit.is_none() && (1..=64).contains(&bits) {
        return Err(IfacConfigError::IfacUnitsRequired);
    }
    if !(8..=512).contains(&bits) || bits % 8 != 0 {
        return Err(invalid(
            "ifac_size",
            "must be 8..512 bits and divisible by 8",
        ));
    }
    Ok(Some(bits / 8))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfacSourceUnits {
    Bytes,
    Bits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfacUnitChange {
    pub interface: String,
    pub previous_value: usize,
    pub effective_bytes: usize,
}

/// Proposed content is private to avoid leaking credentials through Debug output.
pub struct IfacMigrationPlan {
    source_hash: [u8; 32],
    proposed: String,
    changes: Vec<IfacUnitChange>,
}
impl std::fmt::Debug for IfacMigrationPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IfacMigrationPlan")
            .field("changes", &self.changes)
            .finish_non_exhaustive()
    }
}
impl IfacMigrationPlan {
    pub fn source_hash(&self) -> [u8; 32] {
        self.source_hash
    }
    pub fn proposed_config(&self) -> &str {
        &self.proposed
    }
    pub fn changes(&self) -> &[IfacUnitChange] {
        &self.changes
    }
    pub fn is_unchanged(&self) -> bool {
        self.changes.is_empty()
    }
    pub fn source_matches(&self, content: &str) -> bool {
        sha256(content.as_bytes()) == self.source_hash
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IfacMigrationError {
    #[error("configuration syntax is invalid")]
    Syntax(#[source] ConfigError),
    #[error("select at least one exact interface name")]
    EmptySelection,
    #[error("selected interface not found: {0}")]
    NotFound(String),
    #[error("interface {interface}: {error}")]
    Invalid {
        interface: String,
        error: IfacConfigError,
    },
    #[error("configuration source span does not match its parsed declaration")]
    SourceMismatch,
}

/// Authoritative-parser source ranges. Multiline values are consumed by the same
/// parser, so apparent headers/keywords inside them can never become edit targets.
#[derive(Debug, Clone)]
pub struct PropertySpan {
    pub section: String,
    pub path: Vec<String>,
    pub key: String,
    pub range: Range<usize>,
}
#[derive(Debug, Clone)]
pub struct SectionSpan {
    pub section: String,
    pub path: Vec<String>,
    pub range: Range<usize>,
    pub header_end: usize,
}
pub fn section_spans(input: &str) -> Result<Vec<SectionSpan>, ConfigError> {
    scan_spans(input).map(|(_, sections)| sections)
}
pub fn property_spans(input: &str) -> Result<Vec<PropertySpan>, ConfigError> {
    scan_spans(input).map(|(properties, _)| properties)
}
fn scan_spans(input: &str) -> Result<(Vec<PropertySpan>, Vec<SectionSpan>), ConfigError> {
    Config::parse(input)?;
    let raw: Vec<&str> = input.split_inclusive('\n').collect();
    let lines: Vec<&str> = input.lines().collect();
    let mut offsets = Vec::with_capacity(raw.len() + 1);
    offsets.push(0);
    for line in &raw {
        offsets.push(offsets.last().copied().unwrap() + line.len());
    }
    let mut spans = Vec::new();
    let mut sections: Vec<SectionSpan> = Vec::new();
    let mut section = String::new();
    let mut path = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = strip_comment(lines[index]).trim();
        if line.is_empty() {
            index += 1;
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let depth = line.chars().take_while(|&c| c == '[').count();
            let name =
                unquote_token(line[depth..line.len() - depth].trim()).map_err(|message| {
                    ConfigError::Parse {
                        line: index + 1,
                        message,
                    }
                })?;
            if depth == 1 {
                section = name;
                path.clear();
            } else {
                path.truncate(depth - 2);
                path.push(name);
            }
            for previous in sections.iter_mut().rev() {
                if previous.range.end == input.len() && previous.path.len() >= depth - 1 {
                    previous.range.end = offsets[index];
                }
            }
            sections.push(SectionSpan {
                section: section.clone(),
                path: path.clone(),
                range: offsets[index]..input.len(),
                header_end: offsets[index + 1],
            });
            index += 1;
            continue;
        }
        let eq = line.find('=').expect("validated property");
        let key = unquote_token(line[..eq].trim()).map_err(|message| ConfigError::Parse {
            line: index + 1,
            message,
        })?;
        let (_, end) = parse_config_value(line[eq + 1..].trim(), &lines, index)?;
        spans.push(PropertySpan {
            section: section.clone(),
            path: path.clone(),
            key,
            range: offsets[index]..offsets[end + 1],
        });
        index = end + 1;
    }
    Ok((spans, sections))
}

/// Validate syntax and changed IFAC semantics. Unchanged pre-existing errors may
/// stay blocked while the user migrates another interface; no new error is hidden.
pub fn validate_ifac_update(
    previous: Option<&str>,
    proposed: &str,
) -> Result<(), IfacMigrationError> {
    let next = Config::parse(proposed).map_err(IfacMigrationError::Syntax)?;
    let old = previous
        .map(Config::parse)
        .transpose()
        .map_err(IfacMigrationError::Syntax)?;
    for (name, section) in next.subsections("interfaces") {
        if let Err(error) = parse_ifac_size(section) {
            let unchanged = old
                .as_ref()
                .and_then(|c| c.subsection("interfaces", name))
                .is_some_and(|prev| {
                    SIZE_KEYS
                        .iter()
                        .all(|key| prev.values.get(*key) == section.values.get(*key))
                        && parse_ifac_size(prev).as_ref().err() == Some(&error)
                        && (!section.interface_enabled() || prev.interface_enabled())
                });
            if !unchanged {
                return Err(IfacMigrationError::Invalid {
                    interface: name.into(),
                    error,
                });
            }
        }
    }
    Ok(())
}

pub fn plan_ifac_unit_migration(
    content: &str,
    selected: &[String],
    units: IfacSourceUnits,
) -> Result<IfacMigrationPlan, IfacMigrationError> {
    if selected.is_empty() {
        return Err(IfacMigrationError::EmptySelection);
    }
    let config = Config::parse(content).map_err(IfacMigrationError::Syntax)?;
    let spans = property_spans(content).map_err(IfacMigrationError::Syntax)?;
    let mut changes = Vec::new();
    let mut replacements = Vec::new();
    let mut seen = HashSet::new();
    for name in selected {
        if !seen.insert(name) {
            continue;
        }
        let section = config
            .subsection("interfaces", name)
            .ok_or_else(|| IfacMigrationError::NotFound(name.clone()))?;
        match parse_ifac_size(section) {
            Ok(_) => continue,
            Err(IfacConfigError::IfacUnitsRequired) => (),
            Err(error) => {
                return Err(IfacMigrationError::Invalid {
                    interface: name.clone(),
                    error,
                });
            }
        }
        let value = integer(section, "ifac_size")
            .map_err(|error| IfacMigrationError::Invalid {
                interface: name.clone(),
                error,
            })?
            .unwrap();
        let bytes = match units {
            IfacSourceUnits::Bytes => value,
            IfacSourceUnits::Bits if (8..=64).contains(&value) && value % 8 == 0 => value / 8,
            IfacSourceUnits::Bits => {
                return Err(IfacMigrationError::Invalid {
                    interface: name.clone(),
                    error: invalid("ifac_size", "selected bit size must be a multiple of 8"),
                });
            }
        };
        let span = spans
            .iter()
            .find(|span| {
                span.section == "interfaces"
                    && span.path == [name.clone()]
                    && span.key == "ifac_size"
            })
            .ok_or(IfacMigrationError::SourceMismatch)?;
        let raw = &content[span.range.clone()];
        let stripped = raw.trim_end_matches(['\r', '\n']);
        let code = strip_comment(stripped);
        let comment = &stripped[code.len()..];
        let indent = &stripped[..stripped.len() - stripped.trim_start().len()];
        let ending = if raw.ends_with("\r\n") { "\r\n" } else { "\n" };
        let comment = if comment.is_empty() {
            String::new()
        } else {
            format!(" {comment}")
        };
        let replacement = format!(
            "{indent}ifac_size = {}{comment}{ending}{indent}ifac_size_unit = bits{ending}",
            bytes * 8
        );
        replacements.push((span.range.clone(), replacement));
        changes.push(IfacUnitChange {
            interface: name.clone(),
            previous_value: value,
            effective_bytes: bytes,
        });
    }
    replacements.sort_by_key(|(range, _)| range.start);
    let mut proposed = content.to_string();
    for (range, replacement) in replacements.into_iter().rev() {
        proposed.replace_range(range, &replacement);
    }
    validate_ifac_update(Some(content), &proposed)?;
    Ok(IfacMigrationPlan {
        source_hash: sha256(content.as_bytes()),
        proposed,
        changes,
    })
}

/// Redacted status consumed by configuration editors. Credentials never enter it.
pub fn migration_candidates(config: &Config) -> Vec<IfacUnitChange> {
    config
        .subsections("interfaces")
        .into_iter()
        .filter_map(|(name, section)| {
            if parse_ifac_size(section) != Err(IfacConfigError::IfacUnitsRequired) {
                return None;
            }
            Some(IfacUnitChange {
                interface: name.into(),
                previous_value: integer(section, "ifac_size").ok().flatten()?,
                effective_bytes: integer(section, "ifac_size").ok().flatten()?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn section(body: &str) -> ConfigSection {
        Config::parse(&format!("[interfaces]\n[[x]]\n{body}"))
            .unwrap()
            .subsection("interfaces", "x")
            .unwrap()
            .clone()
    }
    #[test]
    fn ifac_units_exact_decoder() {
        for bytes in 1..=64 {
            assert_eq!(
                parse_ifac_size(&section(&format!(
                    "ifac_size={}\nifac_size_unit=bits",
                    bytes * 8
                ))),
                Ok(Some(bytes))
            );
            assert_eq!(
                parse_ifac_size(&section(&format!("ifac_size_bytes={bytes}"))),
                Ok(Some(bytes))
            );
            assert_eq!(
                parse_ifac_size(&section(&format!("ifac_size={bytes}"))),
                Err(IfacConfigError::IfacUnitsRequired)
            );
        }
        assert_eq!(parse_ifac_size(&section("ifac_size=72")), Ok(Some(9)));
        assert_eq!(parse_ifac_size(&section("ifac_size=128")), Ok(Some(16)));
        assert_eq!(parse_ifac_size(&section("")), Ok(None));
        for body in [
            "ifac_size=0",
            "ifac_size=-1",
            "ifac_size=8.0",
            "ifac_size=+8",
            "ifac_size=999999999999999999999999",
            "ifac_size=513",
            "ifac_size=65",
            "ifac_size=8,16",
            "ifac_size_unit=bits",
            "ifac_size=128\nifac_size_unit=bytes",
            "ifac_size_bytes=16\nifac_size=128",
            "ifac_size_bytes=16\nifac_size_unit=bits",
            "ifac_size_bytes=65",
        ] {
            assert!(parse_ifac_size(&section(body)).is_err(), "{body}");
        }
    }
    #[test]
    fn ifac_migration_preserves_other_bytes_and_is_idempotent() {
        let input = "[interfaces]\r\n  [[\"a\"]]\r\n  passphrase = 'not for diagnostics'\r\n  'ifac_size' = 16 # keep this\r\n  type=TCPClientInterface\r\n  [[b]]\r\n  ifac_size=64\r\n";
        let plan = plan_ifac_unit_migration(input, &["a".into()], IfacSourceUnits::Bytes).unwrap();
        assert_eq!(plan.changes()[0].effective_bytes, 16);
        assert_eq!(
            plan.proposed_config(),
            input.replace(
                "'ifac_size' = 16 # keep this\r\n",
                "ifac_size = 128 # keep this\r\n  ifac_size_unit = bits\r\n"
            )
        );
        assert!(plan.source_matches(input));
        assert!(!format!("{plan:?}").contains("not for diagnostics"));
        assert!(
            plan_ifac_unit_migration(
                plan.proposed_config(),
                &["a".into()],
                IfacSourceUnits::Bytes
            )
            .unwrap()
            .is_unchanged()
        );
        let bits =
            plan_ifac_unit_migration(plan.proposed_config(), &["b".into()], IfacSourceUnits::Bits)
                .unwrap();
        assert_eq!(bits.changes()[0].effective_bytes, 8);
    }
    #[test]
    fn ifac_migration_never_edits_fake_headers_inside_multiline_values() {
        let input = "[other]\ntext = '''\n[interfaces]\n[[a]]\nifac_size=64\n'''\n[interfaces]\n[[a]]\nifac_size=16\n";
        let plan = plan_ifac_unit_migration(input, &["a".into()], IfacSourceUnits::Bytes).unwrap();
        assert!(plan.proposed_config().contains("[[a]]\nifac_size=64\n'''"));
        assert!(
            plan.proposed_config()
                .ends_with("ifac_size = 128\nifac_size_unit = bits\n")
        );
        assert!(
            plan_ifac_unit_migration(
                "[interfaces]\n[[a]]\nifac_size=7",
                &["a".into()],
                IfacSourceUnits::Bits
            )
            .is_err()
        );
        assert!(
            plan_ifac_unit_migration(
                "[interfaces]\n[[a]]\nifac_size=8\nifac_size=8",
                &["a".into()],
                IfacSourceUnits::Bits
            )
            .is_err()
        );
    }
    #[test]
    fn ifac_update_preserves_only_unchanged_old_errors() {
        let old = "[interfaces]\n[[a]]\ntype=TCPClientInterface\nifac_size=16\n";
        assert!(
            validate_ifac_update(Some(old), &old.replace("type=", "host=localhost\ntype=")).is_ok()
        );
        assert!(
            validate_ifac_update(Some(old), &old.replace("ifac_size=16", "ifac_size=32")).is_err()
        );
        assert!(validate_ifac_update(None, old).is_err());
    }
}
