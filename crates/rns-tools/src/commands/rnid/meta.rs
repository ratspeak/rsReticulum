//! RSM metadata embedding: ConfigObj-subset INI parsing plus the Validator
//! subset used for `--meta-spec` (string/integer/float/boolean with min/max/
//! default; unknown checks fail validation, matching upstream behavior where
//! Validator returns a failed result for unrecognized check names).
//!
//! Python ref: 1.3.8 `RNS/Utilities/rnid.py:566-586` (`rsg_meta_from_file`,
//! commit f0824fd7) with `RNS/vendor/configobj.py` + `RNS/vendor/validate.py`.
//! Like upstream, spec check expressions containing commas are unusable: the
//! INI list division splits them before check parsing (upstream raises inside
//! Validator; here it is a validation error on the same rnid error path).

use std::path::Path;

use rmpv::Value;

#[derive(Debug, Clone, PartialEq)]
pub enum MetaValue {
    Str(String),
    List(Vec<String>),
    Int(i64),
    Float(f64),
    Bool(bool),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MetaSection {
    pub scalars: Vec<(String, MetaValue)>,
    pub sections: Vec<(String, MetaSection)>,
}

impl MetaSection {
    fn scalar_mut(&mut self, key: &str) -> Option<&mut MetaValue> {
        self.scalars
            .iter_mut()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    fn has_scalar(&self, key: &str) -> bool {
        self.scalars.iter().any(|(k, _)| k == key)
    }

    fn has_section(&self, name: &str) -> bool {
        self.sections.iter().any(|(k, _)| k == name)
    }
}

/// Load and parse a metadata file, optionally validating against a spec file.
/// Mirrors `rsg_meta_from_file` (1.3.8 rnid.py:566-575).
pub fn rsg_meta_from_file(
    path: &Path,
    spec_path: Option<&Path>,
) -> Result<Vec<(String, Value)>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut meta = parse_ini(&content)?;
    if let Some(spec_path) = spec_path {
        let spec_content = std::fs::read_to_string(spec_path).map_err(|e| e.to_string())?;
        let spec = parse_ini(&spec_content)?;
        validate_section(&mut meta, &spec)
            .map_err(|_| "Metadata did not pass spec validation".to_string())?;
    }
    Ok(section_to_values(&meta))
}

/// Convert a parsed section to ordered `(key, msgpack value)` pairs, scalars
/// first then subsections — the same ordering ConfigObj `.dict()` yields.
pub fn section_to_values(section: &MetaSection) -> Vec<(String, Value)> {
    let mut out = Vec::with_capacity(section.scalars.len() + section.sections.len());
    for (key, value) in &section.scalars {
        out.push((key.clone(), meta_value_to_rmpv(value)));
    }
    for (name, sub) in &section.sections {
        let entries = section_to_values(sub)
            .into_iter()
            .map(|(k, v)| (Value::from(k.as_str()), v))
            .collect();
        out.push((name.clone(), Value::Map(entries)));
    }
    out
}

fn meta_value_to_rmpv(value: &MetaValue) -> Value {
    match value {
        MetaValue::Str(s) => Value::from(s.as_str()),
        MetaValue::List(items) => {
            Value::Array(items.iter().map(|s| Value::from(s.as_str())).collect())
        }
        MetaValue::Int(i) => Value::from(*i),
        MetaValue::Float(f) => Value::F64(*f),
        MetaValue::Bool(b) => Value::Boolean(*b),
    }
}

pub fn parse_ini(content: &str) -> Result<MetaSection, String> {
    let mut root = MetaSection::default();
    let mut path: Vec<String> = Vec::new();

    for (index, raw_line) in content.lines().enumerate() {
        let line_num = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') {
            let depth = line.chars().take_while(|&c| c == '[').count();
            let closing = line.chars().rev().take_while(|&c| c == ']').count();
            if depth != closing || line.len() < depth + closing {
                return Err(format!("line {line_num}: malformed section header"));
            }
            let name = unquote(line[depth..line.len() - closing].trim());
            if name.is_empty() {
                return Err(format!("line {line_num}: empty section name"));
            }
            if depth > path.len() + 1 {
                return Err(format!("line {line_num}: section nested too deep"));
            }
            path.truncate(depth - 1);
            let parent = section_for_path(&mut root, &path);
            if parent.has_section(&name) || parent.has_scalar(&name) {
                return Err(format!("line {line_num}: duplicate section name"));
            }
            parent.sections.push((name.clone(), MetaSection::default()));
            path.push(name);
            continue;
        }

        let Some(eq_pos) = line.find('=') else {
            return Err(format!("line {line_num}: unrecognized line"));
        };
        let key = unquote(line[..eq_pos].trim());
        if key.is_empty() {
            return Err(format!("line {line_num}: empty key"));
        }
        let value =
            parse_value(line[eq_pos + 1..].trim()).map_err(|e| format!("line {line_num}: {e}"))?;
        let section = section_for_path(&mut root, &path);
        if section.has_scalar(&key) || section.has_section(&key) {
            return Err(format!("line {line_num}: duplicate keyword name"));
        }
        section.scalars.push((key, value));
    }

    Ok(root)
}

fn section_for_path<'a>(root: &'a mut MetaSection, path: &[String]) -> &'a mut MetaSection {
    let mut current = root;
    for name in path {
        let index = current
            .sections
            .iter()
            .position(|(k, _)| k == name)
            .expect("section path always points at existing sections");
        current = &mut current.sections[index].1;
    }
    current
}

/// ConfigObj value semantics: inline comments outside quotes are stripped;
/// commas outside quotes divide the value into a list of strings; a lone
/// comma is the empty-list marker; members are unquoted.
fn parse_value(input: &str) -> Result<MetaValue, String> {
    let stripped = strip_inline_comment(input);
    let trimmed = stripped.trim();
    if trimmed.starts_with("\"\"\"") || trimmed.starts_with("'''") {
        return Err("multiline values are not supported".to_string());
    }
    if trimmed == "," {
        return Ok(MetaValue::List(Vec::new()));
    }

    let members = split_unquoted_commas(trimmed)?;
    if members.len() == 1 {
        return Ok(MetaValue::Str(unquote(members[0].trim())));
    }

    let mut items = Vec::new();
    for (index, member) in members.iter().enumerate() {
        let member = member.trim();
        if member.is_empty() {
            if index == members.len() - 1 {
                continue; // trailing comma
            }
            return Err("empty list member".to_string());
        }
        items.push(unquote(member));
    }
    Ok(MetaValue::List(items))
}

fn strip_inline_comment(input: &str) -> &str {
    let mut quote: Option<char> = None;
    for (pos, ch) in input.char_indices() {
        match quote {
            Some(q) if ch == q => quote = None,
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None if ch == '#' => return &input[..pos],
            _ => {}
        }
    }
    input
}

fn split_unquoted_commas(input: &str) -> Result<Vec<&str>, String> {
    let mut members = Vec::new();
    let mut quote: Option<char> = None;
    let mut start = 0;
    for (pos, ch) in input.char_indices() {
        match quote {
            Some(q) if ch == q => quote = None,
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None if ch == ',' => {
                members.push(&input[start..pos]);
                start = pos + 1;
            }
            _ => {}
        }
    }
    if quote.is_some() {
        return Err("unterminated quote".to_string());
    }
    members.push(&input[start..]);
    Ok(members)
}

fn unquote(token: &str) -> String {
    let bytes = token.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        if (first == b'\'' || first == b'"') && bytes[bytes.len() - 1] == first {
            return token[1..token.len() - 1].to_string();
        }
    }
    token.to_string()
}

/// Walk the spec, coercing matching meta values in place. Missing keys take
/// the check's `default` when present and fail validation otherwise; unknown
/// check names fail; keys absent from the spec pass through untouched.
fn validate_section(meta: &mut MetaSection, spec: &MetaSection) -> Result<(), ()> {
    for (key, check) in &spec.scalars {
        let MetaValue::Str(check) = check else {
            // A list here means the check expression contained commas, which
            // ConfigObj list division splits before Validator ever runs.
            return Err(());
        };
        let check = parse_check(check)?;
        match meta.scalar_mut(key) {
            Some(value) => *value = apply_check(&check, value)?,
            None => {
                let default = check.default.as_ref().ok_or(())?;
                let coerced = apply_check(&check, &MetaValue::Str(default.clone()))?;
                meta.scalars.push((key.clone(), coerced));
            }
        }
    }
    for (name, sub_spec) in &spec.sections {
        if !meta.has_section(name) {
            meta.sections.push((name.clone(), MetaSection::default()));
        }
        let sub = meta
            .sections
            .iter_mut()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
            .expect("section ensured above");
        validate_section(sub, sub_spec)?;
    }
    Ok(())
}

struct Check {
    name: String,
    min: Option<String>,
    max: Option<String>,
    default: Option<String>,
}

fn parse_check(expr: &str) -> Result<Check, ()> {
    let expr = expr.trim();
    let (name, arg) = match expr.find('(') {
        Some(open) => {
            if !expr.ends_with(')') {
                return Err(());
            }
            (
                expr[..open].trim(),
                Some(expr[open + 1..expr.len() - 1].trim()),
            )
        }
        None => (expr, None),
    };
    let mut check = Check {
        name: name.to_string(),
        min: None,
        max: None,
        default: None,
    };
    if let Some(arg) = arg.filter(|a| !a.is_empty()) {
        match arg.split_once('=') {
            Some((kw, value)) => match kw.trim() {
                "min" => check.min = Some(unquote(value.trim())),
                "max" => check.max = Some(unquote(value.trim())),
                "default" => check.default = Some(unquote(value.trim())),
                _ => return Err(()),
            },
            // Single positional argument is `min` (validate.py `('min', 'max')`).
            None => check.min = Some(unquote(arg)),
        }
    }
    Ok(check)
}

fn apply_check(check: &Check, value: &MetaValue) -> Result<MetaValue, ()> {
    match check.name.as_str() {
        "string" => {
            let MetaValue::Str(s) = value else {
                return Err(());
            };
            let min = parse_bound_int(&check.min)?;
            let max = parse_bound_int(&check.max)?;
            let len = s.chars().count() as i64;
            if min.is_some_and(|m| len < m) || max.is_some_and(|m| len > m) {
                return Err(());
            }
            Ok(MetaValue::Str(s.clone()))
        }
        "integer" => {
            let MetaValue::Str(s) = value else {
                return Err(());
            };
            let parsed: i64 = s.trim().parse().map_err(|_| ())?;
            let min = parse_bound_int(&check.min)?;
            let max = parse_bound_int(&check.max)?;
            if min.is_some_and(|m| parsed < m) || max.is_some_and(|m| parsed > m) {
                return Err(());
            }
            Ok(MetaValue::Int(parsed))
        }
        "float" => {
            let MetaValue::Str(s) = value else {
                return Err(());
            };
            let parsed: f64 = s.trim().parse().map_err(|_| ())?;
            let min = parse_bound_float(&check.min)?;
            let max = parse_bound_float(&check.max)?;
            if min.is_some_and(|m| parsed < m) || max.is_some_and(|m| parsed > m) {
                return Err(());
            }
            Ok(MetaValue::Float(parsed))
        }
        "boolean" => {
            if check.min.is_some() || check.max.is_some() {
                return Err(());
            }
            let MetaValue::Str(s) = value else {
                return Err(());
            };
            match s.to_lowercase().as_str() {
                "on" | "1" | "true" | "yes" => Ok(MetaValue::Bool(true)),
                "off" | "0" | "false" | "no" => Ok(MetaValue::Bool(false)),
                _ => Err(()),
            }
        }
        _ => Err(()),
    }
}

fn parse_bound_int(bound: &Option<String>) -> Result<Option<i64>, ()> {
    bound
        .as_ref()
        .map(|s| s.trim().parse().map_err(|_| ()))
        .transpose()
}

fn parse_bound_float(bound: &Option<String>) -> Result<Option<f64>, ()> {
    bound
        .as_ref()
        .map(|s| s.trim().parse().map_err(|_| ()))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_validate(ini: &str, spec: &str) -> Result<MetaSection, ()> {
        let mut meta = parse_ini(ini).map_err(|_| ())?;
        let spec = parse_ini(spec).map_err(|_| ())?;
        validate_section(&mut meta, &spec)?;
        Ok(meta)
    }

    #[test]
    fn parses_scalars_lists_and_nested_sections_in_order() {
        // Semantics cross-checked against the vendored ConfigObj: comment
        // stripping, quote handling, list division, trailing comma.
        let meta = parse_ini(concat!(
            "title = Test Release\n",
            "tags = alpha, beta, gamma\n",
            "empty =\n",
            "quoted = \"hello # world\"\n",
            "inline = value # trailing comment\n",
            "single_item_list = one,\n",
            "[origin]\n",
            "name = Origins\n",
            "[[nested]]\n",
            "deep = yes\n",
        ))
        .unwrap();

        assert_eq!(
            meta.scalars,
            vec![
                ("title".into(), MetaValue::Str("Test Release".into())),
                (
                    "tags".into(),
                    MetaValue::List(vec!["alpha".into(), "beta".into(), "gamma".into()])
                ),
                ("empty".into(), MetaValue::Str(String::new())),
                ("quoted".into(), MetaValue::Str("hello # world".into())),
                ("inline".into(), MetaValue::Str("value".into())),
                (
                    "single_item_list".into(),
                    MetaValue::List(vec!["one".into()])
                ),
            ]
        );
        assert_eq!(meta.sections.len(), 1);
        let (name, origin) = &meta.sections[0];
        assert_eq!(name, "origin");
        assert_eq!(
            origin.scalars,
            vec![("name".into(), MetaValue::Str("Origins".into()))]
        );
        assert_eq!(origin.sections[0].0, "nested");
        assert_eq!(
            origin.sections[0].1.scalars,
            vec![("deep".into(), MetaValue::Str("yes".into()))]
        );
    }

    #[test]
    fn rejects_duplicates_and_bad_nesting() {
        assert!(parse_ini("a = 1\na = 2\n").is_err());
        assert!(parse_ini("[s]\n[s]\n").is_err());
        assert!(parse_ini("[[deep]]\n").is_err());
        assert!(parse_ini("no equals sign\n").is_err());
    }

    #[test]
    fn spec_coerces_types_and_fills_defaults() {
        let meta = parse_and_validate(
            "name = pkg\nversion = 7\nweight = 2.5\nactive = yes\n",
            "name = string(max=64)\nversion = integer(max=100)\nweight = float(min=0)\nactive = boolean\nextra = string(default=filled)\n",
        )
        .unwrap();
        assert_eq!(
            meta.scalars,
            vec![
                ("name".into(), MetaValue::Str("pkg".into())),
                ("version".into(), MetaValue::Int(7)),
                ("weight".into(), MetaValue::Float(2.5)),
                ("active".into(), MetaValue::Bool(true)),
                ("extra".into(), MetaValue::Str("filled".into())),
            ]
        );
    }

    #[test]
    fn spec_failures_match_upstream_validator() {
        // Out of range.
        assert!(parse_and_validate("version = 200\n", "version = integer(max=100)\n").is_err());
        // Missing key without default.
        assert!(parse_and_validate("name = pkg\n", "name = string\ncount = integer\n").is_err());
        // Unknown check name.
        assert!(parse_and_validate("name = pkg\n", "name = ip_addr_list\n").is_err());
        // Comma'd check expressions break upstream too (list division).
        assert!(parse_and_validate("version = 7\n", "version = integer(1, 100)\n").is_err());
        // Non-boolean value for boolean check.
        assert!(parse_and_validate("active = maybe\n", "active = boolean\n").is_err());
        // Single positional argument is min.
        assert!(parse_and_validate("version = 3\n", "version = integer(5)\n").is_err());
        assert!(parse_and_validate("version = 7\n", "version = integer(5)\n").is_ok());
    }

    #[test]
    fn spec_validates_nested_sections_and_ignores_extra_keys() {
        let meta = parse_and_validate(
            "extra = untouched\n[sec]\nport = 8\n",
            "[sec]\nport = integer\n",
        )
        .unwrap();
        assert_eq!(
            meta.scalars,
            vec![("extra".into(), MetaValue::Str("untouched".into()))]
        );
        assert_eq!(
            meta.sections[0].1.scalars,
            vec![("port".into(), MetaValue::Int(8))]
        );
    }

    #[test]
    fn converts_to_ordered_msgpack_values() {
        let meta = parse_ini("title = t\ntags = a, b\n[origin]\nname = o\n").unwrap();
        let values = section_to_values(&meta);
        assert_eq!(values[0], ("title".to_string(), Value::from("t")));
        assert_eq!(
            values[1],
            (
                "tags".to_string(),
                Value::Array(vec![Value::from("a"), Value::from("b")])
            )
        );
        let (key, origin) = &values[2];
        assert_eq!(key, "origin");
        assert_eq!(
            origin,
            &Value::Map(vec![(Value::from("name"), Value::from("o"))])
        );
    }
}
