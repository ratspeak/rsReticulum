//! Micron syntax highlighting: a port of `RNS/Utilities/rngit/highlight.py@1.6.0`.
//!
//! Upstream colours code only when the optional Pygments package is
//! installed (`highlight.py:141-154`, `:178-202`). This port has no lexer and
//! always takes upstream's path without Pygments (`highlight.py:156-176`):
//! a Micron literal block. [`MicronFormatter`] is ported for token streams
//! from any lexer that names its tokens the way Pygments does.

use std::collections::HashMap;

/// Theme key to `rrggbb` colour; `None` means no colour tag.
pub type Theme = HashMap<String, Option<String>>;

/// Python `SyntaxHighlighter._get_default_theme` (`highlight.py:44-139`).
pub fn default_theme() -> Theme {
    DEFAULT_THEME
        .iter()
        .map(|(k, v)| (k.to_string(), v.map(str::to_string)))
        .collect()
}

/// Python `SyntaxHighlighter` (`highlight.py:35-209`) without Pygments.
#[derive(Debug, Clone)]
pub struct SyntaxHighlighter {
    pub theme: Theme,
}

impl Default for SyntaxHighlighter {
    fn default() -> Self {
        Self::new(None)
    }
}

impl SyntaxHighlighter {
    pub fn new(theme: Option<Theme>) -> Self {
        Self {
            theme: theme.unwrap_or_else(default_theme),
        }
    }

    /// Always false: no Pygments-compatible lexer is built in.
    pub fn pygments_available(&self) -> bool {
        false
    }

    /// Python `highlight` (`highlight.py:156-176`). Upstream doubles
    /// backslashes on every path except empty content.
    pub fn highlight(
        &self,
        content: &str,
        _filename: Option<&str>,
        _language: Option<&str>,
    ) -> String {
        if content.is_empty() {
            return plain_text(content);
        }
        plain_text(content).replace('\\', "\\\\")
    }
}

/// Python `highlight_code` (`highlight.py:312-314`).
pub fn highlight_code(
    content: &str,
    filename: Option<&str>,
    language: Option<&str>,
    theme: Option<Theme>,
) -> String {
    SyntaxHighlighter::new(theme).highlight(content, filename, language)
}

/// Python `_plain_text` (`highlight.py:204-206`).
fn plain_text(content: &str) -> String {
    format!("`=\n{}\n`=", content.replace('`', "\\`"))
}

/// Python `MicronFormatter` (`highlight.py:212-309`).
#[derive(Debug, Clone)]
pub struct MicronFormatter {
    pub theme: Theme,
}

impl MicronFormatter {
    pub fn new(theme: Theme) -> Self {
        Self { theme }
    }

    /// Python `format` (`highlight.py:217-278`). A token type is its dotted
    /// Pygments name, such as `Token.Name.Function`.
    pub fn format<'a>(&self, tokens: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
        let mut out = String::new();
        let mut prev_was_dot = false;
        let mut last_ended_with_break = true;
        for (ttype, value) in tokens {
            let is_dot = ttype == "Token.Operator" && value == ".";
            let ends_with_break = value.ends_with('\n');
            let escaped = escape_value(value);
            if prev_was_dot && ttype.starts_with("Token.Name") && !value.is_empty() {
                match self.color_from_key(Some("attribute_call")) {
                    Some(color) => out.push_str(&format!("`FT{color}{escaped}`f")),
                    None => out.push_str(&escaped),
                }
            } else if let Some(color) = self
                .color_from_key(color_key_for_token(ttype))
                .filter(|_| !value.is_empty())
            {
                let mut inner = escaped.as_str();
                let ilb = if let Some(s) = inner.strip_prefix('\n') {
                    inner = s;
                    "\n"
                } else {
                    ""
                };
                let tlb = if let Some(s) = inner.strip_suffix('\n') {
                    inner = s;
                    "\n"
                } else {
                    ""
                };
                if inner.is_empty() {
                    out.push_str(&format!("{ilb}{tlb}"));
                } else {
                    out.push_str(&format!("{ilb}`FT{color}{inner}`f{tlb}"));
                }
            } else if escaped.contains('\n') {
                let lines = py_splitlines(&escaped);
                if lines.len() > 1 {
                    let parts: Vec<String> = lines.iter().map(|l| escape_line_start(l)).collect();
                    out.push_str(&parts.join("\n"));
                    if escaped.ends_with('\n') {
                        out.push('\n');
                    }
                } else {
                    out.push_str(&escaped);
                }
            } else if last_ended_with_break {
                out.push_str(&escape_line_start(&escaped));
            } else {
                out.push_str(&escaped);
            }
            prev_was_dot = is_dot;
            last_ended_with_break = ends_with_break;
        }
        out
    }

    fn color_from_key(&self, key: Option<&str>) -> Option<&str> {
        self.theme.get(key?)?.as_deref()
    }
}

/// Python `_get_color_key_for_token` (`highlight.py:280-297`): the nearest
/// mapped ancestor of the token type.
fn color_key_for_token(ttype: &str) -> Option<&'static str> {
    let mut current = Some(ttype);
    while let Some(t) = current {
        if let Some((_, key)) = GRANULAR_TOKEN_MAP.iter().find(|(name, _)| *name == t) {
            return Some(key);
        }
        current = t.rsplit_once('.').map(|(parent, _)| parent);
    }
    None
}

/// Python `_escape_value` (`highlight.py:303-305`).
fn escape_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('`', "\\`")
}

fn escape_line_start(line: &str) -> String {
    if line.starts_with(['-', '>', '<']) {
        format!("\\{line}")
    } else {
        line.to_string()
    }
}

/// Python `str.splitlines()`.
fn py_splitlines(s: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let boundary = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if boundary {
            lines.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' && it.peek().map(|p| p.1) == Some('\n') {
                it.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < s.len() {
        lines.push(&s[start..]);
    }
    lines
}

const DEFAULT_THEME: [(&str, Option<&str>); 58] = [
    ("keyword", Some("ff7b72")),
    ("keyword_constant", Some("ff7b72")),
    ("keyword_control", Some("ff7b72")),
    ("keyword_declaration", Some("ff7b72")),
    ("function_def", Some("79c0ff")),
    ("function_magic", Some("ff7b72")),
    ("function_call", Some("d2a8ff")),
    ("function_builtin", Some("ffa657")),
    ("class_def", Some("7ee787")),
    ("class_ref", Some("56d364")),
    ("self", Some("ff9bce")),
    ("cls", Some("ff9bce")),
    ("string", Some("a5d6ff")),
    ("string_quoted", Some("a5d6ff")),
    ("string_doc", Some("8b949e")),
    ("string_interpol", Some("ffd700")),
    ("string_escape", Some("ffea00")),
    ("number", Some("79c0ff")),
    ("number_float", Some("79c0ff")),
    ("number_integer", Some("79c0ff")),
    ("number_hex", Some("79c0ff")),
    ("comment", Some("8b949e")),
    ("comment_doc", Some("8b949e")),
    ("comment_preproc", Some("ff7b72")),
    ("operator", Some("ff7b72")),
    ("operator_arithmetic", Some("ff7b72")),
    ("operator_comparison", Some("ff7b72")),
    ("operator_assignment", Some("ff7b72")),
    ("operator_word", Some("ff7b72")),
    ("operator_dot", Some("c9d1d9")),
    ("punctuation", Some("b4b4b4")),
    ("punctuation_brace", Some("b4b4b4")),
    ("punctuation_paren", Some("b4b4b4")),
    ("punctuation_colon", Some("b4b4b4")),
    ("punctuation_comma", Some("8b949e")),
    ("decorator", Some("f0883e")),
    ("constant", Some("ff7b72")),
    ("constant_builtin", Some("ff7b72")),
    ("type_hint", Some("ffa657")),
    ("type_builtin", Some("ffa657")),
    ("exception", Some("f85149")),
    ("exception_builtin", Some("f85149")),
    ("name", Some("e6edf3")),
    ("attribute", Some("e6edf3")),
    ("attribute_call", Some("d2a8ff")),
    ("variable", Some("e6edf3")),
    ("parameter", Some("e6edf3")),
    ("namespace", Some("7ee787")),
    ("module", Some("a5d6ff")),
    ("generic_heading", Some("c9d1d9")),
    ("generic_subheading", Some("c9d1d9")),
    ("generic_prompt", Some("8b949e")),
    ("generic_error", Some("f85149")),
    ("generic_deleted", Some("f85149")),
    ("generic_inserted", Some("7ee787")),
    ("generic_output", Some("e6edf3")),
    ("text", None),
    ("whitespace", None),
];

const GRANULAR_TOKEN_MAP: [(&str, &str); 78] = [
    ("Token.Keyword", "keyword"),
    ("Token.Keyword.Constant", "keyword_constant"),
    ("Token.Keyword.Declaration", "keyword_declaration"),
    ("Token.Keyword.Namespace", "keyword_control"),
    ("Token.Keyword.Pseudo", "keyword_control"),
    ("Token.Keyword.Reserved", "keyword_control"),
    ("Token.Keyword.Type", "type_builtin"),
    ("Token.Name.Function", "function_call"),
    ("Token.Name.Function.Magic", "function_magic"),
    ("Token.Name.Class", "class_ref"),
    ("Token.Name.Builtin", "function_builtin"),
    ("Token.Name.Builtin.Pseudo", "constant_builtin"),
    ("Token.Name.Exception", "exception_builtin"),
    ("Token.Name.Decorator", "decorator"),
    ("Token.Name.Namespace", "namespace"),
    ("Token.Name.Attribute", "attribute"),
    ("Token.Name.Variable", "variable"),
    ("Token.Name.Variable.Magic", "function_magic"),
    ("Token.Name.Other", "name"),
    ("Token.Name", "name"),
    ("Token.Name.Tag", "keyword"),
    ("Token.Name.Constant", "constant"),
    ("Token.Name.Label", "name"),
    ("Token.Name.Entity", "name"),
    ("Token.Literal.String", "string"),
    ("Token.Literal.String.Affix", "string"),
    ("Token.Literal.String.Backtick", "string"),
    ("Token.Literal.String.Char", "string"),
    ("Token.Literal.String.Delimiter", "string"),
    ("Token.Literal.String.Doc", "string_doc"),
    ("Token.Literal.String.Double", "string_quoted"),
    ("Token.Literal.String.Escape", "string_escape"),
    ("Token.Literal.String.Heredoc", "string"),
    ("Token.Literal.String.Interpol", "string_interpol"),
    ("Token.Literal.String.Other", "string"),
    ("Token.Literal.String.Regex", "string"),
    ("Token.Literal.String.Single", "string_quoted"),
    ("Token.Literal.String.Symbol", "string"),
    ("Token.Literal.Number", "number"),
    ("Token.Literal.Number.Bin", "number"),
    ("Token.Literal.Number.Float", "number_float"),
    ("Token.Literal.Number.Hex", "number_hex"),
    ("Token.Literal.Number.Integer", "number_integer"),
    ("Token.Literal.Number.Integer.Long", "number_integer"),
    ("Token.Literal.Number.Oct", "number"),
    ("Token.Literal", "string"),
    ("Token.Literal.Date", "string"),
    ("Token.Operator", "operator"),
    ("Token.Operator.Word", "operator_word"),
    ("Token.Operator.Comparison", "operator_comparison"),
    ("Token.Operator.Assignment", "operator_assignment"),
    ("Token.Operator.Arithmetic", "operator_arithmetic"),
    ("Token.Punctuation", "punctuation"),
    ("Token.Punctuation.Marker", "punctuation"),
    ("Token.Punctuation.Brace", "punctuation_brace"),
    ("Token.Punctuation.Bracket", "punctuation_brace"),
    ("Token.Punctuation.Parenthesis", "punctuation_paren"),
    ("Token.Punctuation.Colon", "punctuation_colon"),
    ("Token.Punctuation.Comma", "punctuation_comma"),
    ("Token.Comment", "comment"),
    ("Token.Comment.Hashbang", "comment"),
    ("Token.Comment.Multiline", "comment_doc"),
    ("Token.Comment.Preproc", "comment_preproc"),
    ("Token.Comment.Single", "comment"),
    ("Token.Comment.Special", "comment"),
    ("Token.Generic.Deleted", "generic_deleted"),
    ("Token.Generic.Emph", "text"),
    ("Token.Generic.Error", "generic_error"),
    ("Token.Generic.Heading", "generic_heading"),
    ("Token.Generic.Inserted", "generic_inserted"),
    ("Token.Generic.Output", "generic_output"),
    ("Token.Generic.Prompt", "generic_prompt"),
    ("Token.Generic.Strong", "text"),
    ("Token.Generic.Subheading", "generic_subheading"),
    ("Token.Generic.Traceback", "generic_error"),
    ("Token.Generic", "text"),
    ("Token.Text", "text"),
    ("Token.Text.Whitespace", "whitespace"),
];
