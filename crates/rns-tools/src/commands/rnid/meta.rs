//! RSM metadata loading for `rnid -S -E`: a port of `rsg_meta_from_file`
//! (`RNS/Utilities/rnid.py:566-575@1.6.0`) over the vendored ConfigObj
//! (`RNS/vendor/configobj.py@1.6.0`: parse, `%(name)s` interpolation,
//! validate, dict) and Validator (`RNS/vendor/validate.py@1.6.0`). Error
//! strings are the text of the Python exception rnid prints.

use std::path::Path;

use rmpv::Value;

use super::pyfmt;
use super::pyre::{Regex, group_str, is_py_space};

/// Python object produced by ConfigObj/Validator.
#[derive(Debug, Clone)]
pub enum Obj {
    Str(String),
    List(Vec<Obj>),
    Tuple(Vec<Obj>),
    Int(i128),
    /// Integer outside `i128`, kept as its decimal text.
    BigInt(String),
    Float(f64),
    Bool(bool),
    None,
    Dict(Vec<(String, Obj)>),
    Section(usize),
}

impl Obj {
    fn type_name(&self) -> &'static str {
        match self {
            Obj::Str(_) => "str",
            Obj::List(_) => "list",
            Obj::Tuple(_) => "tuple",
            Obj::Int(_) | Obj::BigInt(_) => "int",
            Obj::Float(_) => "float",
            Obj::Bool(_) => "bool",
            Obj::None => "NoneType",
            Obj::Dict(_) => "dict",
            Obj::Section(_) => "Section",
        }
    }

    fn repr(&self) -> String {
        match self {
            Obj::Str(s) => pyfmt::py_str_repr(s),
            Obj::List(items) => format!(
                "[{}]",
                items.iter().map(Obj::repr).collect::<Vec<_>>().join(", ")
            ),
            Obj::Tuple(items) if items.len() == 1 => format!("({},)", items[0].repr()),
            Obj::Tuple(items) => format!(
                "({})",
                items.iter().map(Obj::repr).collect::<Vec<_>>().join(", ")
            ),
            Obj::Int(i) => i.to_string(),
            Obj::BigInt(s) => s.clone(),
            Obj::Float(f) => pyfmt::py_float(*f),
            Obj::Bool(b) => if *b { "True" } else { "False" }.to_string(),
            Obj::None => "None".to_string(),
            Obj::Dict(_) | Obj::Section(_) => "{...}".to_string(),
        }
    }

    /// Python `str()`.
    fn str(&self) -> String {
        match self {
            Obj::Str(s) => s.clone(),
            other => other.repr(),
        }
    }

    fn num(&self) -> Option<f64> {
        match self {
            Obj::Int(i) => Some(*i as f64),
            Obj::Float(f) => Some(*f),
            Obj::Bool(b) => Some(f64::from(u8::from(*b))),
            _ => None,
        }
    }

    /// Python `==`.
    fn py_eq(&self, other: &Obj) -> bool {
        match (self, other) {
            (Obj::Str(a), Obj::Str(b)) => a == b,
            (Obj::List(a), Obj::List(b)) | (Obj::Tuple(a), Obj::Tuple(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.py_eq(y))
            }
            (Obj::BigInt(a), Obj::BigInt(b)) => a == b,
            (Obj::None, Obj::None) => true,
            (Obj::Int(a), Obj::Int(b)) => a == b,
            (a, b) => match (a.num(), b.num()) {
                (Some(x), Some(y)) => x == y,
                _ => false,
            },
        }
    }
}

/// One `Section` of a parsed file; index 0 is the `ConfigObj` itself.
#[derive(Debug, Clone)]
struct Node {
    name: Option<String>,
    parent: usize,
    depth: usize,
    scalars: Vec<String>,
    sections: Vec<String>,
    values: Vec<(String, Obj)>,
    configspec: Option<usize>,
}

#[derive(Debug, Clone)]
struct Tree {
    nodes: Vec<Node>,
}

impl Tree {
    fn new() -> Self {
        Self {
            nodes: vec![Node {
                name: None,
                parent: 0,
                depth: 0,
                scalars: Vec::new(),
                sections: Vec::new(),
                values: Vec::new(),
                configspec: None,
            }],
        }
    }

    fn raw(&self, node: usize, key: &str) -> Option<&Obj> {
        self.nodes[node]
            .values
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    fn contains(&self, node: usize, key: &str) -> bool {
        self.raw(node, key).is_some()
    }

    /// `Section.__setitem__` for a scalar value.
    fn set(&mut self, node: usize, key: &str, value: Obj) {
        let n = &mut self.nodes[node];
        if let Some(slot) = n.values.iter_mut().find(|(k, _)| k == key) {
            slot.1 = value;
        } else {
            n.scalars.push(key.to_string());
            n.values.push((key.to_string(), value));
        }
    }

    fn add_section(&mut self, parent: usize, depth: usize, name: &str) -> usize {
        let index = self.nodes.len();
        self.nodes.push(Node {
            name: Some(name.to_string()),
            parent,
            depth,
            scalars: Vec::new(),
            sections: Vec::new(),
            values: Vec::new(),
            configspec: None,
        });
        let p = &mut self.nodes[parent];
        p.sections.push(name.to_string());
        p.values.push((name.to_string(), Obj::Section(index)));
        index
    }

    fn keys(&self, node: usize) -> Vec<String> {
        let n = &self.nodes[node];
        n.scalars.iter().chain(&n.sections).cloned().collect()
    }

    /// `Section.__getitem__` with interpolation.
    fn get(&self, node: usize, key: &str) -> Result<Option<Obj>, String> {
        let Some(value) = self.raw(node, key) else {
            return Ok(None);
        };
        Ok(Some(match value {
            Obj::Str(s) => Obj::Str(self.interpolate(node, key, s)?),
            Obj::List(items) => Obj::List(
                items
                    .iter()
                    .map(|item| match item {
                        Obj::Str(s) => self.interpolate(node, key, s).map(Obj::Str),
                        other => Ok(other.clone()),
                    })
                    .collect::<Result<_, _>>()?,
            ),
            other => other.clone(),
        }))
    }

    fn interpolate(&self, owner: usize, key: &str, value: &str) -> Result<String, String> {
        if !value.contains('%') {
            return Ok(value.to_string());
        }
        let mut backtrail = Vec::new();
        self.recursive_interpolate(
            owner,
            key,
            &Obj::Str(value.to_string()),
            owner,
            &mut backtrail,
        )
    }

    fn recursive_interpolate(
        &self,
        owner: usize,
        key: &str,
        value: &Obj,
        section: usize,
        backtrail: &mut Vec<(String, Option<String>)>,
    ) -> Result<String, String> {
        let marker = (key.to_string(), self.nodes[section].name.clone());
        if backtrail.contains(&marker) {
            return Err(format!("interpolation loop detected in value \"{key}\"."));
        }
        backtrail.push(marker.clone());
        let Obj::Str(value) = value else {
            return Err(format!(
                "expected string or bytes-like object, got '{}'",
                value.type_name()
            ));
        };
        let keycre = Regex::new(r"%\(([^)]*)\)s");
        let mut text: Vec<char> = value.chars().collect();
        let mut found = keycre.search(&text, 0);
        while let Some(caps) = found {
            let name = group_str(&text, &caps, 0).unwrap_or_default();
            let (fetched, fetched_section) = self.fetch(owner, &name)?;
            let replacement =
                self.recursive_interpolate(owner, &name, &fetched, fetched_section, backtrail)?;
            let (start, end) = caps[1].expect("whole match");
            let replacement: Vec<char> = replacement.chars().collect();
            text.splice(start..end, replacement.iter().copied());
            found = keycre.search(&text, start + replacement.len());
        }
        backtrail.retain(|m| m != &marker);
        Ok(text.into_iter().collect())
    }

    /// `InterpolationEngine._fetch`: raw lookup in the owning section, its
    /// DEFAULT, then each parent.
    fn fetch(&self, owner: usize, key: &str) -> Result<(Obj, usize), String> {
        let usable =
            |v: &Option<Obj>| matches!(v, Some(v) if !matches!(v, Obj::Section(_) | Obj::None));
        let mut current = owner;
        let mut val;
        loop {
            val = self.raw(current, key).cloned();
            if usable(&val) {
                break;
            }
            val = match self.raw(current, "DEFAULT") {
                None => None,
                Some(Obj::Section(default)) => self.raw(*default, key).cloned(),
                Some(other) => {
                    return Err(format!(
                        "'{}' object has no attribute 'get'",
                        other.type_name()
                    ));
                }
            };
            if usable(&val) {
                break;
            }
            if self.nodes[current].parent == current {
                break;
            }
            current = self.nodes[current].parent;
        }
        match val {
            None | Some(Obj::None) => Err(format!("missing option \"{key}\" in interpolation.")),
            Some(v) => Ok((v, current)),
        }
    }

    /// `Section.dict()`.
    fn dict(&self, node: usize) -> Result<Vec<(String, Obj)>, String> {
        let mut out = Vec::new();
        for key in self.keys(node) {
            let value = match self.get(node, &key)?.expect("listed key") {
                Obj::Section(sub) => Obj::Dict(self.dict(sub)?),
                other => other,
            };
            out.push((key, value));
        }
        Ok(out)
    }
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

struct ParseErr {
    text: String,
    line: usize,
}

struct Patterns {
    keyword: Regex,
    sectionmarker: Regex,
    valueexp: Regex,
    listvalueexp: Regex,
    single_single: Regex,
    single_double: Regex,
    multi_single: Regex,
    multi_double: Regex,
}

impl Patterns {
    fn new() -> Self {
        Self {
            keyword: Regex::new(r#"^(\s*)((?:".*?")|(?:'.*?')|(?:[^'"=].*?))\s*=\s*(.*)$"#),
            sectionmarker: Regex::new(
                r#"^(\s*)((?:\[\s*)+)((?:"\s*\S.*?\s*")|(?:'\s*\S.*?\s*')|(?:[^'"\s].*?))((?:\s*\])+)\s*(#.*)?$"#,
            ),
            valueexp: Regex::new(
                r#"^(?:(?:((?:(?:(?:".*?")|(?:'.*?')|(?:[^'",#][^,#]*?))\s*,\s*)*)((?:".*?")|(?:'.*?')|(?:[^'",#\s][^,]*?)|(?:(?<!,)))?)|(,))\s*(#.*)?$"#,
            ),
            listvalueexp: Regex::new(r#"((?:".*?")|(?:'.*?')|(?:[^'",#]?.*?))\s*,\s*"#),
            single_single: Regex::new(r"^'''(.*?)'''\s*(#.*)?$"),
            single_double: Regex::new(r#"^"""(.*?)"""\s*(#.*)?$"#),
            multi_single: Regex::new(r"^(.*?)'''\s*(#.*)?$"),
            multi_double: Regex::new(r#"^(.*?)"""\s*(#.*)?$"#),
        }
    }
}

/// `ConfigObj._unquote`; `None` stands for the SyntaxError it raises.
fn unquote(value: &str) -> Option<String> {
    let chars: Vec<char> = value.chars().collect();
    let first = *chars.first()?;
    if first == chars[chars.len() - 1] && (first == '"' || first == '\'') {
        Some(chars[1..chars.len() - 1].iter().collect())
    } else {
        Some(value.to_string())
    }
}

/// `ConfigObj._handle_value`; `None` is the SyntaxError.
fn handle_value(p: &Patterns, value: &str) -> Option<Obj> {
    let text: Vec<char> = value.chars().collect();
    let caps = p.valueexp.match_at(&text, 0)?;
    let list_values = group_str(&text, &caps, 0);
    let mut single = group_str(&text, &caps, 1);
    let empty_list = group_str(&text, &caps, 2);
    if list_values.as_deref() == Some("") && single.is_none() {
        return None;
    }
    if empty_list.is_some() {
        return Some(Obj::List(Vec::new()));
    }
    if let Some(s) = single.take() {
        if list_values.as_deref().is_some_and(|l| !l.is_empty()) && s.is_empty() {
            single = None;
        } else {
            let s = if s.is_empty() { "\"\"".to_string() } else { s };
            single = Some(unquote(&s)?);
        }
    }
    let list_values = list_values.unwrap_or_default();
    if list_values.is_empty() {
        return Some(Obj::Str(single.unwrap_or_default()));
    }
    let lv: Vec<char> = list_values.chars().collect();
    let mut items = Vec::new();
    for member in p.listvalueexp.findall(&lv) {
        items.push(Obj::Str(unquote(&member)?));
    }
    if let Some(s) = single {
        items.push(Obj::Str(s));
    }
    Some(Obj::List(items))
}

/// `ConfigObj._multiline`: `(value, next index)`, `None` on SyntaxError.
fn multiline(
    p: &Patterns,
    value: &str,
    lines: &[String],
    mut index: usize,
) -> Option<(String, usize)> {
    let quot: String = value.chars().take(3).collect();
    let newvalue_start: String = value.chars().skip(3).collect();
    let (single, multi) = if quot == "'''" {
        (&p.single_single, &p.multi_single)
    } else {
        (&p.single_double, &p.multi_double)
    };
    let text: Vec<char> = value.chars().collect();
    if let Some(caps) = single.match_at(&text, 0) {
        return Some((group_str(&text, &caps, 0).unwrap_or_default(), index));
    }
    if newvalue_start.contains(&quot) {
        return None;
    }
    let mut newvalue = newvalue_start;
    let mut line = None;
    while index + 1 < lines.len() {
        index += 1;
        newvalue.push('\n');
        if !lines[index].contains(&quot) {
            newvalue.push_str(&lines[index]);
        } else {
            line = Some(&lines[index]);
            break;
        }
    }
    let line: Vec<char> = line?.chars().collect();
    let caps = multi.match_at(&line, 0)?;
    newvalue.push_str(&group_str(&line, &caps, 0).unwrap_or_default());
    Some((newvalue, index))
}

/// Python `repr(str)` for the "Invalid line" message.
fn line_repr(line: &str) -> String {
    pyfmt::py_str_repr(line)
}

/// `ConfigObj._load` + `_parse` for a file's bytes.
fn parse_config(content: &[u8]) -> Result<Tree, String> {
    let mut lines: Vec<String> = Vec::new();
    let mut data = content;
    if data.starts_with(b"\xef\xbb\xbf") {
        data = &data[3..];
    }
    for raw in data.split_inclusive(|b| *b == b'\n') {
        let text =
            std::str::from_utf8(raw).map_err(|_| pyfmt::py_utf8_error(raw).unwrap_or_default())?;
        lines.push(text.trim_end_matches(['\r', '\n']).to_string());
    }

    let p = Patterns::new();
    let mut tree = Tree::new();
    let mut errors: Vec<ParseErr> = Vec::new();
    let mut this_section = 0usize;
    let mut index = 0usize;
    while index < lines.len() {
        let line = lines[index].clone();
        let sline = py_strip(&line);
        if sline.is_empty() || sline.starts_with('#') {
            index += 1;
            continue;
        }
        let text: Vec<char> = line.chars().collect();
        if let Some(caps) = p.sectionmarker.match_at(&text, 0) {
            let open = group_str(&text, &caps, 1).unwrap_or_default();
            let close = group_str(&text, &caps, 3).unwrap_or_default();
            let name = group_str(&text, &caps, 2).unwrap_or_default();
            let depth = open.matches('[').count();
            let current_depth = tree.nodes[this_section].depth;
            let error = |text: &str| ParseErr {
                text: text.to_string(),
                line: index + 1,
            };
            if depth != close.matches(']').count() {
                errors.push(error("Cannot compute the section depth"));
                index += 1;
                continue;
            }
            let parent = if depth < current_depth {
                let mut sect = this_section;
                while depth < tree.nodes[sect].depth && tree.nodes[sect].parent != sect {
                    sect = tree.nodes[sect].parent;
                }
                if tree.nodes[sect].depth != depth {
                    errors.push(error("Cannot compute nesting level"));
                    index += 1;
                    continue;
                }
                tree.nodes[sect].parent
            } else if depth == current_depth {
                tree.nodes[this_section].parent
            } else if depth == current_depth + 1 {
                this_section
            } else {
                errors.push(error("Section too nested"));
                index += 1;
                continue;
            };
            let name = unquote(&name).unwrap_or_default();
            if tree.contains(parent, &name) {
                errors.push(error("Duplicate section name"));
                index += 1;
                continue;
            }
            this_section = tree.add_section(parent, depth, &name);
            index += 1;
            continue;
        }

        let Some(caps) = p.keyword.match_at(&text, 0) else {
            errors.push(ParseErr {
                text: format!(
                    "Invalid line ({}) (matched as neither section nor keyword)",
                    line_repr(&line)
                ),
                line: index + 1,
            });
            index += 1;
            continue;
        };
        let key = group_str(&text, &caps, 1).unwrap_or_default();
        let value = group_str(&text, &caps, 2).unwrap_or_default();
        let parsed = if value.starts_with("\"\"\"") || value.starts_with("'''") {
            match multiline(&p, &value, &lines, index) {
                Some((v, next)) => {
                    index = next;
                    Obj::Str(v)
                }
                None => {
                    errors.push(ParseErr {
                        text: "Parse error in multiline value".to_string(),
                        line: index + 1,
                    });
                    index += 1;
                    continue;
                }
            }
        } else {
            match handle_value(&p, &value) {
                Some(v) => v,
                None => {
                    errors.push(ParseErr {
                        text: "Parse error in value".to_string(),
                        line: index + 1,
                    });
                    index += 1;
                    continue;
                }
            }
        };
        let key = unquote(&key).unwrap_or_default();
        if tree.contains(this_section, &key) {
            errors.push(ParseErr {
                text: "Duplicate keyword name".to_string(),
                line: index + 1,
            });
            index += 1;
            continue;
        }
        tree.set(this_section, &key, parsed);
        index += 1;
    }

    match errors.len() {
        0 => Ok(tree),
        1 => Err(format!("{} at line {}.", errors[0].text, errors[0].line)),
        _ => Err(format!(
            "Parsing failed with several errors.\nFirst error at line {}.",
            errors[0].line
        )),
    }
}

/// Validator failure: `Caught` is a `ValidateError` (the entry fails),
/// `Raised` propagates out of `rsg_meta_from_file`.
enum VErr {
    Caught,
    Raised(String),
}

struct Check {
    name: String,
    args: Vec<Obj>,
    kwargs: Vec<(String, Obj)>,
    default: Option<Obj>,
}

fn v_unquote(val: &str) -> String {
    let chars: Vec<char> = val.chars().collect();
    if chars.len() >= 2
        && (chars[0] == '\'' || chars[0] == '"')
        && chars[0] == chars[chars.len() - 1]
    {
        chars[1..chars.len() - 1].iter().collect()
    } else {
        val.to_string()
    }
}

const UNQUOTED_ITEM: &str = r#"(?:".*?")|(?:'.*?')|(?:[^'",\s\)][^,\)]*?)"#;
const UNQUOTED_ARG: &str = r#"(?:".*?")|(?:'.*?')|(?:[^'",\s=][^,=]*?)"#;

/// `Validator._parse_check`.
fn parse_check(check: &str) -> Check {
    let func_re = Regex::dotall(r"([^\(\)]+?)\((.*)\)");
    let text: Vec<char> = check.chars().collect();
    let Some(caps) = func_re.match_at(&text, 0) else {
        return Check {
            name: check.to_string(),
            args: Vec::new(),
            kwargs: Vec::new(),
            default: None,
        };
    };
    let name = group_str(&text, &caps, 0).unwrap_or_default();
    let arg_string: Vec<char> = group_str(&text, &caps, 1)
        .unwrap_or_default()
        .chars()
        .collect();
    let list_body = format!(r"(?:\s*(?:{UNQUOTED_ITEM})\s*,\s*)*(?:{UNQUOTED_ITEM})?");
    let paramfinder = Regex::dotall(&format!(
        r"(?:((?:[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*list\({list_body}\))|(?:{UNQUOTED_ARG}|(?:[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*(?:{UNQUOTED_ARG}))))(?:(?:\s*,\s*)|(?:\s*$)))"
    ));
    let list_arg = Regex::dotall(&format!(
        r"(?:([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*list\(({list_body})\))"
    ));
    let list_members = Regex::dotall(&format!(r"({UNQUOTED_ARG})(?:(?:\s*,\s*)|(?:\s*$))"));
    let key_arg = Regex::dotall(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.*)$");

    let mut args = Vec::new();
    let mut kwargs: Vec<(String, Obj)> = Vec::new();
    let set_kw = |kwargs: &mut Vec<(String, Obj)>, key: String, value: Obj| {
        if let Some(slot) = kwargs.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            kwargs.push((key, value));
        }
    };
    for arg in paramfinder.findall(&arg_string) {
        let arg: Vec<char> = py_strip(&arg).chars().collect();
        if let Some(caps) = list_arg.match_at(&arg, 0) {
            let key = group_str(&arg, &caps, 0).unwrap_or_default();
            let body: Vec<char> = group_str(&arg, &caps, 1)
                .unwrap_or_default()
                .chars()
                .collect();
            let members = list_members
                .findall(&body)
                .iter()
                .map(|m| Obj::Str(v_unquote(m)))
                .collect();
            set_kw(&mut kwargs, key, Obj::List(members));
            continue;
        }
        if let Some(caps) = key_arg.match_at(&arg, 0) {
            let key = group_str(&arg, &caps, 0).unwrap_or_default();
            let mut val = group_str(&arg, &caps, 1).unwrap_or_default();
            if val != "'None'" && val != "\"None\"" {
                val = v_unquote(&val);
            }
            set_kw(&mut kwargs, key, Obj::Str(val));
            continue;
        }
        args.push(Obj::Str(v_unquote(&arg.iter().collect::<String>())));
    }
    let default = kwargs
        .iter()
        .position(|(k, _)| k == "default")
        .map(|i| kwargs.remove(i).1);
    Check {
        name,
        args,
        kwargs,
        default,
    }
}

/// `Validator._handle_none`.
fn handle_none(value: Obj) -> Option<Obj> {
    match value {
        Obj::Str(s) if s == "None" => None,
        Obj::Str(s) if s == "'None'" || s == "\"None\"" => Some(Obj::Str(v_unquote(&s))),
        other => Some(other),
    }
}

fn valid_underscores(s: &str) -> bool {
    let b = s.as_bytes();
    b.iter().enumerate().all(|(i, c)| {
        *c != b'_'
            || (i > 0 && i + 1 < b.len() && b[i - 1].is_ascii_digit() && b[i + 1].is_ascii_digit())
    })
}

/// Python `int(str)`.
pub fn py_int(s: &str) -> Option<Obj> {
    let s = py_strip(s);
    let (sign, digits) = match s.as_bytes().first() {
        Some(b'+') => ("", &s[1..]),
        Some(b'-') => ("-", &s[1..]),
        _ => ("", s),
    };
    if digits.is_empty()
        || !digits.bytes().all(|c| c.is_ascii_digit() || c == b'_')
        || !valid_underscores(digits)
    {
        return None;
    }
    let clean = format!("{sign}{}", digits.replace('_', ""));
    Some(match clean.parse::<i128>() {
        Ok(v) => Obj::Int(v),
        Err(_) => {
            let trimmed = clean.trim_start_matches('-').trim_start_matches('0');
            Obj::BigInt(format!("{sign}{trimmed}"))
        }
    })
}

/// Python `float(str)`.
pub fn py_float(s: &str) -> Option<f64> {
    let s = py_strip(s);
    let lower = s.to_ascii_lowercase();
    let body = lower.trim_start_matches(['+', '-']);
    if matches!(body, "inf" | "infinity" | "nan") {
        let v: f64 = if body == "nan" {
            f64::NAN
        } else {
            f64::INFINITY
        };
        return Some(if lower.starts_with('-') { -v } else { v });
    }
    if !valid_underscores(s)
        || s.chars()
            .any(|c| !c.is_ascii_alphanumeric() && !"+-._".contains(c))
    {
        return None;
    }
    let clean = s.replace('_', "");
    if clean.to_ascii_lowercase().contains("inf") || clean.to_ascii_lowercase().contains("nan") {
        return None;
    }
    clean.parse::<f64>().ok()
}

fn int_cmp(a: &Obj, b: &Obj) -> std::cmp::Ordering {
    let big = |o: &Obj| match o {
        Obj::BigInt(s) if s.starts_with('-') => -1,
        Obj::BigInt(_) => 1,
        _ => 0,
    };
    match (a, b) {
        (Obj::Int(x), Obj::Int(y)) => x.cmp(y),
        _ => big(a).cmp(&big(b)),
    }
}

fn num_param(name: &str, val: Option<&Obj>, to_float: bool) -> Result<Option<Obj>, VErr> {
    let Some(val) = val else { return Ok(None) };
    let bad = || {
        VErr::Raised(format!(
            "passed an incorrect value \"{}\" for parameter \"{name}\".",
            val.str()
        ))
    };
    match val {
        Obj::None => Ok(None),
        Obj::Str(s) => {
            if to_float {
                py_float(s).map(|f| Some(Obj::Float(f))).ok_or_else(bad)
            } else {
                py_int(s).map(Some).ok_or_else(bad)
            }
        }
        _ => Err(bad()),
    }
}

fn is_integer(value: &Obj, min: Option<&Obj>, max: Option<&Obj>) -> Result<Obj, VErr> {
    let min = num_param("min", min, false)?;
    let max = num_param("max", max, false)?;
    let value = match value {
        Obj::Str(s) => py_int(s).ok_or(VErr::Caught)?,
        Obj::Int(_) | Obj::BigInt(_) => value.clone(),
        Obj::Bool(b) => Obj::Int(i128::from(*b)),
        _ => return Err(VErr::Caught),
    };
    if min.is_some_and(|m| int_cmp(&value, &m).is_lt())
        || max.is_some_and(|m| int_cmp(&value, &m).is_gt())
    {
        return Err(VErr::Caught);
    }
    Ok(value)
}

fn is_float(value: &Obj, min: Option<&Obj>, max: Option<&Obj>) -> Result<Obj, VErr> {
    let min = num_param("min", min, true)?.and_then(|m| m.num());
    let max = num_param("max", max, true)?.and_then(|m| m.num());
    let value = match value {
        Obj::Float(f) => *f,
        Obj::Str(s) => py_float(s).ok_or(VErr::Caught)?,
        Obj::Int(i) => *i as f64,
        Obj::Bool(b) => f64::from(u8::from(*b)),
        _ => return Err(VErr::Caught),
    };
    if min.is_some_and(|m| value < m) || max.is_some_and(|m| value > m) {
        return Err(VErr::Caught);
    }
    Ok(Obj::Float(value))
}

fn is_boolean(value: &Obj) -> Result<Obj, VErr> {
    match value {
        Obj::Str(s) => match s.to_lowercase().as_str() {
            "on" | "1" | "true" | "yes" => Ok(Obj::Bool(true)),
            "off" | "0" | "false" | "no" => Ok(Obj::Bool(false)),
            _ => Err(VErr::Caught),
        },
        other if other.py_eq(&Obj::Bool(false)) => Ok(Obj::Bool(false)),
        other if other.py_eq(&Obj::Bool(true)) => Ok(Obj::Bool(true)),
        _ => Err(VErr::Caught),
    }
}

/// glibc `inet_aton` acceptance (1 to 4 parts, decimal/octal/hex).
fn inet_aton(s: &str) -> bool {
    let s = s.split([' ', '\t', '\n']).next().unwrap_or("");
    let parts: Vec<&str> = s.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return false;
    }
    let mut values = Vec::new();
    for part in &parts {
        let v = if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            if hex.is_empty() {
                Some(0)
            } else {
                u64::from_str_radix(hex, 16).ok()
            }
        } else if part.len() > 1 && part.starts_with('0') {
            u64::from_str_radix(&part[1..], 8).ok()
        } else {
            part.parse::<u64>().ok()
        };
        let Some(v) = v.filter(|_| !part.is_empty()) else {
            return false;
        };
        values.push(v);
    }
    let last_max: u64 = match values.len() {
        1 => 0xffff_ffff,
        2 => 0xff_ffff,
        3 => 0xffff,
        _ => 0xff,
    };
    values[..values.len() - 1].iter().all(|v| *v <= 0xff) && values[values.len() - 1] <= last_max
}

fn is_ip_addr(value: &Obj) -> Result<Obj, VErr> {
    let Obj::Str(s) = value else {
        return Err(VErr::Caught);
    };
    let s = py_strip(s);
    if !inet_aton(s) {
        return Err(VErr::Caught);
    }
    Ok(Obj::Str(s.to_string()))
}

fn len_checks(len: usize, min: Option<&Obj>, max: Option<&Obj>) -> Result<(), VErr> {
    let min = num_param("min", min, false)?;
    let max = num_param("max", max, false)?;
    let len = Obj::Int(len as i128);
    if min.is_some_and(|m| int_cmp(&len, &m).is_lt())
        || max.is_some_and(|m| int_cmp(&len, &m).is_gt())
    {
        return Err(VErr::Caught);
    }
    Ok(())
}

fn is_list(value: &Obj, min: Option<&Obj>, max: Option<&Obj>) -> Result<Vec<Obj>, VErr> {
    let items = match value {
        Obj::List(items) | Obj::Tuple(items) => items.clone(),
        _ => {
            // String values are rejected after the parameters are checked.
            num_param("min", min, false)?;
            num_param("max", max, false)?;
            return Err(VErr::Caught);
        }
    };
    len_checks(items.len(), min, max)?;
    Ok(items)
}

fn is_string(value: &Obj, min: Option<&Obj>, max: Option<&Obj>) -> Result<Obj, VErr> {
    let Obj::Str(s) = value else {
        return Err(VErr::Caught);
    };
    len_checks(s.chars().count(), min, max)?;
    Ok(value.clone())
}

fn type_error(msg: String) -> VErr {
    VErr::Raised(msg)
}

/// Bind `(value, min=None, max=None)` like a Python call.
fn bind_min_max<'a>(
    func: &str,
    args: &'a [Obj],
    kwargs: &'a [(String, Obj)],
) -> Result<(Option<&'a Obj>, Option<&'a Obj>), VErr> {
    if args.len() > 2 {
        return Err(type_error(format!(
            "{func}() takes from 1 to 3 positional arguments but {} were given",
            args.len() + 1
        )));
    }
    let mut min = args.first();
    let mut max = args.get(1);
    for (k, v) in kwargs {
        let slot = match k.as_str() {
            "min" => &mut min,
            "max" => &mut max,
            _ => {
                return Err(type_error(format!(
                    "{func}() got an unexpected keyword argument '{k}'"
                )));
            }
        };
        if slot.is_some() {
            return Err(type_error(format!(
                "{func}() got multiple values for argument '{k}'"
            )));
        }
        *slot = Some(v);
    }
    Ok((min, max))
}

fn no_extra(func: &str, total: usize, args: &[Obj], kwargs: &[(String, Obj)]) -> Result<(), VErr> {
    if !args.is_empty() {
        let plural = if total == 1 { "argument" } else { "arguments" };
        return Err(type_error(format!(
            "{func}() takes {total} positional {plural} but {} were given",
            args.len() + total
        )));
    }
    if let Some((k, _)) = kwargs.first() {
        return Err(type_error(format!(
            "{func}() got an unexpected keyword argument '{k}'"
        )));
    }
    Ok(())
}

/// `Validator._check_value`.
fn check_value(value: &Obj, check: &Check) -> Result<Obj, VErr> {
    let (args, kwargs) = (&check.args[..], &check.kwargs[..]);
    let list_of = |func: &str, each: &dyn Fn(&Obj) -> Result<Obj, VErr>| -> Result<Obj, VErr> {
        let (min, max) = bind_min_max(func, args, kwargs)?;
        is_list(value, min, max)?
            .iter()
            .map(each)
            .collect::<Result<_, _>>()
            .map(Obj::List)
    };
    match check.name.as_str() {
        "" | "pass" => {
            no_extra("Validator._pass", 2, args, kwargs)?;
            Ok(value.clone())
        }
        "integer" => {
            let (min, max) = bind_min_max("is_integer", args, kwargs)?;
            is_integer(value, min, max)
        }
        "float" => {
            let (min, max) = bind_min_max("is_float", args, kwargs)?;
            is_float(value, min, max)
        }
        "boolean" => {
            no_extra("is_boolean", 1, args, kwargs)?;
            is_boolean(value)
        }
        "ip_addr" => {
            no_extra("is_ip_addr", 1, args, kwargs)?;
            is_ip_addr(value)
        }
        "string" => {
            let (min, max) = bind_min_max("is_string", args, kwargs)?;
            is_string(value, min, max)
        }
        "list" => {
            let (min, max) = bind_min_max("is_list", args, kwargs)?;
            is_list(value, min, max).map(Obj::List)
        }
        "tuple" => {
            let (min, max) = bind_min_max("is_tuple", args, kwargs)?;
            is_list(value, min, max).map(Obj::Tuple)
        }
        "int_list" => list_of("is_int_list", &|m| is_integer(m, None, None)),
        "float_list" => list_of("is_float_list", &|m| is_float(m, None, None)),
        "bool_list" => list_of("is_bool_list", &is_boolean),
        "ip_addr_list" => list_of("is_ip_addr_list", &is_ip_addr),
        "string_list" => {
            if matches!(value, Obj::Str(_)) {
                return Err(VErr::Caught);
            }
            list_of("is_string_list", &|m| is_string(m, None, None))
        }
        "force_list" => {
            let (min, max) = bind_min_max("force_list", args, kwargs)?;
            let wrapped = match value {
                Obj::List(_) | Obj::Tuple(_) => value.clone(),
                other => Obj::List(vec![other.clone()]),
            };
            is_list(&wrapped, min, max).map(Obj::List)
        }
        "mixed_list" => {
            if let Some((k, _)) = kwargs.first() {
                return Err(type_error(format!(
                    "is_mixed_list() got an unexpected keyword argument '{k}'"
                )));
            }
            let members: Vec<Obj> = match value {
                Obj::List(items) | Obj::Tuple(items) => items.clone(),
                Obj::Str(s) => s.chars().map(|c| Obj::Str(c.to_string())).collect(),
                _ => return Err(VErr::Caught),
            };
            if members.len() != args.len() {
                return Err(VErr::Caught);
            }
            members
                .iter()
                .zip(args)
                .map(|(member, arg)| match arg.str().as_str() {
                    "int" | "integer" => is_integer(member, None, None),
                    "float" => is_float(member, None, None),
                    "ip_addr" => is_ip_addr(member),
                    "str" | "string" => is_string(member, None, None),
                    "bool" | "boolean" => is_boolean(member),
                    other => Err(VErr::Raised(format!(
                        "passed an incorrect value \"'{other}'\" for parameter \"mixed_list\"."
                    ))),
                })
                .collect::<Result<_, _>>()
                .map(Obj::List)
        }
        "option" => {
            if let Some((k, _)) = kwargs.first() {
                return Err(type_error(format!(
                    "is_option() got an unexpected keyword argument '{k}'"
                )));
            }
            let Obj::Str(_) = value else {
                return Err(VErr::Caught);
            };
            if args.iter().any(|a| a.py_eq(value)) {
                Ok(value.clone())
            } else {
                Err(VErr::Caught)
            }
        }
        _ => Err(VErr::Caught),
    }
}

/// `Validator._parse_with_caching` precondition: the check must be a string.
fn check_text(spec: &Obj) -> Result<String, VErr> {
    match spec {
        Obj::Str(s) => Ok(s.clone()),
        other => Err(VErr::Raised(format!(
            "unhashable type: '{}'",
            other.type_name()
        ))),
    }
}

/// `Validator.check`: `Ok(None)` is a missing value with `default=None`.
fn validator_check(spec: &Obj, value: Option<&Obj>, missing: bool) -> Result<Option<Obj>, VErr> {
    let check = parse_check(&check_text(spec)?);
    let value = if missing {
        let Some(default) = check.default.clone() else {
            return Err(VErr::Caught);
        };
        match handle_none(default) {
            None => return Ok(None),
            Some(v) => v,
        }
    } else {
        value.cloned().unwrap_or(Obj::None)
    };
    if matches!(value, Obj::None) {
        return Ok(None);
    }
    check_value(&value, &check).map(Some)
}

/// `Validator.get_default_value`, keeping only what can raise past ConfigObj.
fn probe_default(spec: &Obj) -> Result<(), String> {
    let check = parse_check(&check_text(spec).map_err(|e| match e {
        VErr::Raised(m) => m,
        VErr::Caught => String::new(),
    })?);
    let Some(default) = check.default.clone() else {
        return Ok(());
    };
    let Some(value) = handle_none(default) else {
        return Ok(());
    };
    match check_value(&value, &check) {
        Err(VErr::Raised(m)) => Err(m),
        _ => Ok(()),
    }
}

/// `ConfigObj._set_configspec`.
fn set_configspec(tree: &mut Tree, spec: &Tree, section: usize) {
    let Some(cs) = tree.nodes[section].configspec else {
        return;
    };
    if let Some(Obj::Section(many)) = spec.raw(cs, "__many__") {
        let many = *many;
        for name in tree.nodes[section].sections.clone() {
            if !spec.contains(cs, &name)
                && let Some(Obj::Section(sub)) = tree.raw(section, &name).cloned()
            {
                tree.nodes[sub].configspec = Some(many);
            }
        }
    }
    for name in spec.nodes[cs].sections.clone() {
        if name == "__many__" {
            continue;
        }
        if !tree.contains(section, &name) {
            let depth = tree.nodes[section].depth + 1;
            tree.add_section(section, depth, &name);
        }
        if let (Some(Obj::Section(sub)), Some(Obj::Section(spec_sub))) =
            (tree.raw(section, &name).cloned(), spec.raw(cs, &name))
        {
            tree.nodes[sub].configspec = Some(*spec_sub);
        }
    }
}

/// `ConfigObj.validate(Validator())`; `Ok(true)` when every check passed.
fn validate(tree: &mut Tree, spec: &Tree, section: usize) -> Result<bool, String> {
    let cs = tree.nodes[section].configspec.expect("configspec set");
    set_configspec(tree, spec, section);
    let mut ret_true = true;

    let validate_entry = |tree: &mut Tree,
                          entry: &str,
                          check_spec: &Obj,
                          val: Option<Obj>,
                          missing: bool|
     -> Result<bool, String> {
        probe_default(check_spec)?;
        match validator_check(check_spec, val.as_ref(), missing) {
            Err(VErr::Caught) => Ok(false),
            Err(VErr::Raised(m)) => Err(m),
            Ok(check) => {
                let check = check.unwrap_or(Obj::None);
                if missing || !val.as_ref().is_some_and(|v| v.py_eq(&check)) {
                    tree.set(section, entry, check);
                }
                Ok(true)
            }
        }
    };

    let scalars = tree.nodes[section].scalars.clone();
    let mut unvalidated: Vec<String> = scalars
        .iter()
        .filter(|k| !spec.contains(cs, k))
        .cloned()
        .collect();
    let incorrect = spec.nodes[cs].sections.iter().any(|k| scalars.contains(k))
        || spec.nodes[cs]
            .scalars
            .iter()
            .any(|k| tree.nodes[section].sections.contains(k));

    for entry in spec.nodes[cs].scalars.clone() {
        if entry == "__many__" || entry == "___many___" {
            continue;
        }
        let check_spec = spec.get(cs, &entry)?.expect("spec scalar");
        let (missing, val) = if tree.nodes[section].scalars.contains(&entry) {
            (false, tree.get(section, &entry)?)
        } else {
            (true, None)
        };
        if !validate_entry(tree, &entry, &check_spec, val, missing)? {
            ret_true = false;
        }
    }

    let many = if spec.nodes[cs].scalars.iter().any(|k| k == "__many__") {
        spec.get(cs, "__many__")?
    } else if spec.nodes[cs].scalars.iter().any(|k| k == "___many___") {
        spec.get(cs, "___many___")?
    } else {
        None
    };
    if let Some(many) = many {
        for entry in std::mem::take(&mut unvalidated) {
            let val = tree.get(section, &entry)?;
            if !validate_entry(tree, &entry, &many, val, false)? {
                ret_true = false;
            }
        }
    }
    if incorrect {
        ret_true = false;
    }

    for entry in tree.nodes[section].sections.clone() {
        if section == 0 && entry == "DEFAULT" {
            continue;
        }
        let Some(Obj::Section(sub)) = tree.raw(section, &entry).cloned() else {
            continue;
        };
        if tree.nodes[sub].configspec.is_none() {
            continue;
        }
        if !validate(tree, spec, sub)? {
            ret_true = false;
        }
    }
    Ok(ret_true)
}

fn read_config(path: &Path) -> Result<Tree, String> {
    if !path.is_file() {
        return Ok(Tree::new());
    }
    let content = std::fs::read(path).map_err(|e| e.to_string())?;
    parse_config(&content)
}

/// `rsg_meta_from_file(path, spec_path)`.
pub fn rsg_meta_from_file(
    path: &Path,
    spec_path: Option<&Path>,
) -> Result<Vec<(String, Obj)>, String> {
    let spec = spec_path.map(read_config).transpose()?;
    let mut parsed = read_config(path)?;
    if let Some(spec) = spec {
        parsed.nodes[0].configspec = Some(0);
        if !validate(&mut parsed, &spec, 0)? {
            return Err("Metadata did not pass spec validation".to_string());
        }
    }
    parsed.dict(0)
}

/// Pack a metadata object as umsgpack would; errors are umsgpack's text.
pub fn to_msgpack(obj: &Obj) -> Result<Value, String> {
    Ok(match obj {
        Obj::Str(s) => Value::from(s.as_str()),
        Obj::List(items) | Obj::Tuple(items) => {
            Value::Array(items.iter().map(to_msgpack).collect::<Result<_, _>>()?)
        }
        Obj::Int(i) if *i < 0 => {
            Value::from(i64::try_from(*i).map_err(|_| "huge signed int".to_string())?)
        }
        Obj::Int(i) => Value::from(u64::try_from(*i).map_err(|_| "huge unsigned int".to_string())?),
        Obj::BigInt(s) if s.starts_with('-') => return Err("huge signed int".to_string()),
        Obj::BigInt(_) => return Err("huge unsigned int".to_string()),
        Obj::Float(f) => Value::F64(*f),
        Obj::Bool(b) => Value::Boolean(*b),
        Obj::None => Value::Nil,
        Obj::Dict(entries) => Value::Map(
            entries
                .iter()
                .map(|(k, v)| Ok((Value::from(k.as_str()), to_msgpack(v)?)))
                .collect::<Result<_, String>>()?,
        ),
        Obj::Section(_) => unreachable!("dict() replaces sections"),
    })
}

/// The meta keys for `create_rsg`, packed.
pub fn meta_entries(meta: &[(String, Obj)]) -> Result<Vec<(String, Value)>, String> {
    meta.iter()
        .map(|(k, v)| Ok((k.clone(), to_msgpack(v)?)))
        .collect()
}
