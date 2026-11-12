//! Markdown to Micron conversion: a port of `MarkdownToMicron` and
//! `convert_markdown_to_micron` from `RNS/Utilities/rngit/util.py@1.6.0`
//! (`:79-816`).
//!
//! Upstream's regular expressions are matched by hand with the same Python
//! `re` semantics: `\s` is Python's Unicode whitespace, `\d` any Unicode
//! decimal digit. Display width is the character count, which is what
//! upstream uses when the optional `wcwidth` module is absent
//! (`util.py:150-156`). Input lines never contain `\n`: `format_block`
//! splits on it first, as upstream does.

use std::convert::Infallible;
use std::fmt;

use crate::highlight::SyntaxHighlighter;

/// A Python exception upstream raises while converting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkdownError {
    /// Python `IndexError`: the input holds a `\0LINKn\0` or `\0CODEn\0`
    /// placeholder naming a link or code span that does not exist.
    PlaceholderIndex,
    /// Python `ValueError`: a placeholder index longer than the 4300 digits
    /// Python `int()` accepts.
    PlaceholderDigits,
}

impl fmt::Display for MarkdownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlaceholderIndex => f.write_str("placeholder index out of range"),
            Self::PlaceholderDigits => f.write_str("placeholder index has too many digits"),
        }
    }
}

impl std::error::Error for MarkdownError {}

/// Column alignment parsed from a table separator row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Center,
    Right,
}

/// Python `MarkdownToMicron` (`util.py:79-811`).
#[derive(Debug, Clone)]
pub struct MarkdownToMicron {
    pub max_width: usize,
    pub local_url_scope: String,
    initial_url_scope: String,
    pub syntax_highlighter: Option<SyntaxHighlighter>,
    pub bold_links: bool,
    pub underline_links: bool,
    pub link_color: Option<String>,
}

impl Default for MarkdownToMicron {
    fn default() -> Self {
        Self::new(100, None, None)
    }
}

/// Python `convert_markdown_to_micron` (`util.py:814-816`).
pub fn convert_markdown_to_micron(text: &str) -> Result<String, MarkdownError> {
    MarkdownToMicron::default().format_block(text)
}

impl MarkdownToMicron {
    pub const BOLD: &'static str = "`!";
    pub const BOLD_END: &'static str = "`!";
    pub const ITALIC: &'static str = "`*";
    pub const ITALIC_END: &'static str = "`*";
    pub const UNDERLINE: &'static str = "`_";
    pub const UNDERLINE_END: &'static str = "`_";
    pub const CODE_BG: &'static str = "`BT282828";
    pub const CODE_BG_INLINE: &'static str = "`BT383838";
    pub const CODE_FG: &'static str = "`Fddd";
    pub const CODE_RESET: &'static str = "`f`b";
    pub const LITERAL_START: &'static str = "`=";
    pub const LITERAL_END: &'static str = "`=";
    pub const BULLET: &'static str = "•";
    pub const TABLE_H: char = '─';
    pub const TABLE_V: char = '│';
    pub const TABLE_TL: char = '┌';
    pub const TABLE_TR: char = '┐';
    pub const TABLE_BL: char = '└';
    pub const TABLE_BR: char = '┘';
    pub const TABLE_ML: char = '├';
    pub const TABLE_MR: char = '┤';
    pub const TABLE_TM: char = '┬';
    pub const TABLE_BM: char = '┴';
    pub const TABLE_MM: char = '┼';
    pub const TABLE_MIN_COL_WIDTH: usize = 3;

    /// An empty or absent `url_scope` selects `:/page/`, as upstream's
    /// `url_scope or ":/page/"` does (`util.py:130-145`).
    pub fn new(
        max_width: usize,
        syntax_highlighter: Option<SyntaxHighlighter>,
        url_scope: Option<&str>,
    ) -> Self {
        let scope = match url_scope {
            Some(s) if !s.is_empty() => s,
            _ => ":/page/",
        };
        Self {
            max_width,
            local_url_scope: scope.to_string(),
            initial_url_scope: scope.to_string(),
            syntax_highlighter,
            bold_links: true,
            underline_links: true,
            link_color: None,
        }
    }

    pub fn set_url_scope(&mut self, url_scope: &str) {
        self.local_url_scope = url_scope.to_string();
    }

    /// Back to the scope given at construction (`util.py:148`).
    pub fn restore_url_scope(&mut self) {
        self.local_url_scope = self.initial_url_scope.clone();
    }

    pub fn display_width(&self, text: &[char]) -> usize {
        text.len()
    }

    /// Python `format_block` (`util.py:158-302`).
    pub fn format_block(&self, text: &str) -> Result<String, MarkdownError> {
        let mut st = BlockState::default();
        for line in text.split('\n') {
            if let Some(lang_hint) = detect_code_fence(line) {
                st.flush_quote(self)?;
                st.flush_table(self)?;
                if !st.in_code_block {
                    st.in_code_block = true;
                    st.code_block_lang =
                        (!lang_hint.is_empty()).then(|| py_strip(lang_hint).to_string());
                    st.code_buffer.clear();
                } else {
                    st.flush_code(self);
                    st.in_code_block = false;
                    st.code_block_lang = None;
                }
            } else if st.in_code_block {
                st.code_buffer.push(line.to_string());
            } else if let Some(quoted) = quote_match(line) {
                if !st.in_quote {
                    st.flush_table(self)?;
                    st.in_quote = true;
                    st.quote_buffer.clear();
                }
                st.quote_buffer.push(quoted.to_string());
            } else if st.in_quote {
                st.flush_quote(self)?;
                if !py_strip(line).is_empty() {
                    if is_table_row(line) {
                        st.in_table = true;
                        st.table_buffer = vec![line.to_string()];
                    } else {
                        st.out.push(self.format_line(line)?);
                    }
                } else {
                    st.out.push(String::new());
                }
            } else if is_table_row(line) {
                if !st.in_table {
                    st.in_table = true;
                    st.table_buffer = vec![line.to_string()];
                } else {
                    st.table_buffer.push(line.to_string());
                }
            } else {
                if st.in_table {
                    st.flush_table(self)?;
                }
                st.out.push(self.format_line(line)?);
            }
        }
        if st.in_quote {
            st.flush_quote(self)?;
        }
        if st.in_table {
            st.flush_table(self)?;
        }
        if st.in_code_block {
            st.flush_code(self);
        }
        Ok(st.out.join("\n"))
    }

    /// Python `format_line(line)` (`util.py:304-322`).
    pub fn format_line(&self, line: &str) -> Result<String, MarkdownError> {
        let mut line = line.replace('\\', "\\\\");
        if line.starts_with('-') && !line.starts_with("---") && !line.starts_with("- ") {
            line = format!("\\{line}");
        }
        if line.starts_with('<') {
            line = format!("\\{line}");
        }
        let c: Vec<char> = line.chars().collect();
        if is_horizontal_rule(&c) {
            return Ok("-".to_string());
        }
        if let Some((level, content)) = match_header(&c) {
            let content: String = content.iter().collect();
            return Ok(format!(
                "{}{}",
                ">".repeat(level.min(6)),
                self.format_inline(&content)?
            ));
        }
        if let Some((indent, content)) = match_list_item(&c) {
            let indent: String = indent.iter().collect();
            let content: String = content.iter().collect();
            return Ok(format!(
                "{indent} {} {}",
                Self::BULLET,
                self.format_inline(&content)?
            ));
        }
        self.format_inline(&line)
    }

    /// Python `format_line(line, mode="codeblock")` (`util.py:305`).
    pub fn format_codeblock_line(&self, line: &str) -> String {
        escape_literals(line)
    }

    /// Python `_format_inline` (`util.py:324-371`).
    pub fn format_inline(&self, text: &str) -> Result<String, MarkdownError> {
        let mut links: Vec<(String, String)> = Vec::new();
        let mut codes: Vec<String> = Vec::new();
        let c: Vec<char> = text.chars().collect();
        let text = sub_links(&c, &mut links);
        let c: Vec<char> = text.chars().collect();
        let text = sub_inline_code(&c, &mut codes);
        let c: Vec<char> = text.chars().collect();
        let text = sub_emphasis(&c, '*', 2, Self::BOLD, Self::BOLD_END);
        let c: Vec<char> = text.chars().collect();
        let text = sub_emphasis(&c, '*', 1, Self::ITALIC, Self::ITALIC_END);

        let c: Vec<char> = text.chars().collect();
        let text = sub_placeholders(&c, "LINK", |idx| {
            let (text, url) = links.get(idx).ok_or(MarkdownError::PlaceholderIndex)?;
            Ok(self.restore_link(text, url))
        })?;
        let c: Vec<char> = text.chars().collect();
        sub_placeholders(&c, "CODE", |idx| {
            let content = codes.get(idx).ok_or(MarkdownError::PlaceholderIndex)?;
            Ok(format!(
                "{}{}{}{}",
                Self::CODE_BG_INLINE,
                Self::CODE_FG,
                content.replace('`', "\\`"),
                Self::CODE_RESET
            ))
        })
    }

    fn restore_link(&self, text: &str, url: &str) -> String {
        let mut components = url.split('#');
        let mut url = components.next().unwrap_or("").to_string();
        let anchor = components.next().unwrap_or("");
        if !url.contains(":/") {
            url = format!("{}{url}", self.local_url_scope);
            if !anchor.is_empty() {
                url = format!("{url}|anchor={anchor}");
            }
        }
        let undl = if self.underline_links { "`_" } else { "" };
        let bold = if self.bold_links { "`!" } else { "" };
        let text = text.replace('`', "");
        let link = format!("{undl}{bold}`[{text}`{url}]{bold}{undl}");
        match self.link_color.as_deref() {
            Some(c) if c.chars().count() == 3 => format!("`F{c}{link}`f"),
            Some(c) if c.chars().count() == 6 => format!("`FT{c}{link}`f"),
            _ => link,
        }
    }

    /// Python `format_table` (`util.py:423-528`); `align` empty means none.
    pub fn format_table(&self, rows: &[String], align: &str) -> Result<Vec<String>, MarkdownError> {
        self.table(rows, align, false, |cell| self.format_inline(cell))
    }

    /// Python `format_table_raw` (`util.py:530-631`): cells are not formatted
    /// and the header row is not escaped.
    pub fn format_table_raw(&self, rows: &[String], align: &str) -> Vec<String> {
        let Ok(lines) = self.table(rows, align, true, |cell| {
            Ok::<_, Infallible>(cell.to_string())
        });
        lines
    }

    fn table<E>(
        &self,
        rows: &[String],
        align: &str,
        raw: bool,
        fmt: impl Fn(&str) -> Result<String, E>,
    ) -> Result<Vec<String>, E> {
        if rows.len() < 2 {
            return Ok(rows.to_vec());
        }
        let header_cells = parse_table_row(&rows[0]);
        let num_cols = header_cells.len();
        let mut alignments = parse_table_alignments(&rows[1]);
        alignments.resize(num_cols, Align::Left);
        let data_rows: Vec<Vec<String>> = rows[2..]
            .iter()
            .map(|row| {
                let mut cells = parse_table_row(row);
                cells.resize(num_cols, String::new());
                cells
            })
            .collect();

        let mut col_widths = vec![0usize; num_cols];
        for row in std::iter::once(&header_cells).chain(data_rows.iter()) {
            for (i, cell) in row.iter().enumerate() {
                let formatted: Vec<char> = fmt(cell)?.chars().collect();
                col_widths[i] = col_widths[i].max(self.visible_width(&formatted));
            }
        }
        for w in &mut col_widths {
            *w = (*w).max(Self::TABLE_MIN_COL_WIDTH);
        }

        let total_width = col_widths.iter().sum::<usize>() + num_cols * 3 + 1;
        if total_width > self.max_width {
            let mut excess = total_width - self.max_width;
            let mut indexed: Vec<(usize, usize)> = col_widths.iter().copied().enumerate().collect();
            indexed.sort_by_key(|&(_, w)| std::cmp::Reverse(w));
            for (i, w) in indexed {
                if excess == 0 {
                    break;
                }
                let reduction = excess.min(w - Self::TABLE_MIN_COL_WIDTH);
                col_widths[i] -= reduction;
                excess -= reduction;
            }
        }

        let border = |left: char, mid: char, right: char| {
            let mut s = String::from(left);
            for (i, w) in col_widths.iter().enumerate() {
                s.extend(std::iter::repeat_n(Self::TABLE_H, w + 2));
                s.push(if i < num_cols - 1 { mid } else { right });
            }
            escape_literals(&s)
        };

        let mut result = Vec::new();
        if !align.is_empty() {
            result.push(format!("`{align}"));
        }
        result.push(border(Self::TABLE_TL, Self::TABLE_TM, Self::TABLE_TR));

        let mut header_line = String::from(Self::TABLE_V);
        for (i, cell) in header_cells.iter().enumerate() {
            let padded = self.pad_cell(&fmt(cell)?, col_widths[i], Align::Left);
            header_line.push_str(&format!(" {padded} {}", Self::TABLE_V));
        }
        result.push(if raw {
            header_line
        } else {
            escape_literals(&header_line)
        });

        result.push(border(Self::TABLE_ML, Self::TABLE_MM, Self::TABLE_MR));

        for row in &data_rows {
            let mut row_line = String::from(Self::TABLE_V);
            for (i, cell) in row.iter().enumerate() {
                let padded = self.pad_cell(&fmt(cell)?, col_widths[i], alignments[i]);
                row_line.push_str(&format!(" {padded} {}", Self::TABLE_V));
            }
            result.push(row_line);
        }

        result.push(border(Self::TABLE_BL, Self::TABLE_BM, Self::TABLE_BR));
        if !align.is_empty() {
            result.push("`a".to_string());
        }
        Ok(result)
    }

    /// Python `_visible_width` (`util.py:667-674`): the six tag patterns are
    /// removed one pass each, in upstream's order.
    fn visible_width(&self, text: &[char]) -> usize {
        let hex = |c: &[char], from: usize, n: usize| {
            c.len() >= from + n && c[from..from + n].iter().all(|x| x.is_ascii_hexdigit())
        };
        let is = |c: &[char], i: usize, s: &str| {
            s.chars().enumerate().all(|(k, x)| c.get(i + k) == Some(&x))
        };
        let mut s = remove_matches(text, |c, i| {
            (c[i] == '`' && matches!(c.get(i + 1), Some('F' | 'B')) && hex(c, i + 2, 3))
                .then_some(5)
        });
        s = remove_matches(&s, |c, i| {
            (c[i] == '`'
                && matches!(c.get(i + 1), Some('F' | 'B'))
                && c.get(i + 2) == Some(&'T')
                && hex(c, i + 3, 6))
            .then_some(9)
        });
        s = remove_matches(&s, |c, i| {
            (c[i] == '`' && matches!(c.get(i + 1), Some('!' | '*' | '_' | '='))).then_some(2)
        });
        s = remove_matches(&s, |c, i| is(c, i, "`f`b").then_some(4));
        s = remove_matches(&s, |c, i| is(c, i, "`f").then_some(2));
        s = remove_matches(&s, |c, i| is(c, i, "`b").then_some(2));
        self.display_width(&s)
    }

    /// Python `_pad_cell` (`util.py:676-688`).
    fn pad_cell(&self, text: &str, width: usize, align: Align) -> String {
        let text = self.truncate_cell(text, width);
        let c: Vec<char> = text.chars().collect();
        let padding = width.saturating_sub(self.visible_width(&c));
        match align {
            Align::Right => format!("{}{text}", " ".repeat(padding)),
            Align::Center => {
                let left = padding / 2;
                format!("{}{text}{}", " ".repeat(left), " ".repeat(padding - left))
            }
            Align::Left => format!("{text}{}", " ".repeat(padding)),
        }
    }

    /// Python `_truncate_cell` (`util.py:690-746`). Upstream appends the open
    /// toggle closers in `set` order, which varies per process; this emits
    /// them in `!*_=` order, one of upstream's possible outputs.
    fn truncate_cell(&self, text: &str, width: usize) -> String {
        let c: Vec<char> = text.chars().collect();
        if self.visible_width(&c) <= width {
            return text.to_string();
        }
        let mut point = c.len();
        while point > 0 && self.visible_width(&c[..point]) >= width {
            point -= 1;
        }
        let t = &c[..point];

        const TOGGLES: [char; 4] = ['!', '*', '_', '='];
        let mut active = [false; 4];
        let mut fg_active = false;
        let mut bg_active = false;
        let mut i = 0;
        while i < t.len() {
            if t[i] == '`' && i + 1 < t.len() {
                let tag = t[i + 1];
                if let Some(k) = TOGGLES.iter().position(|&x| x == tag) {
                    active[k] = !active[k];
                    i += 2;
                    continue;
                }
                match tag {
                    'f' | 'b' => {
                        if tag == 'f' {
                            fg_active = false;
                        } else {
                            bg_active = false;
                        }
                        i += 2;
                        continue;
                    }
                    'F' | 'B' => {
                        if tag == 'F' {
                            fg_active = true;
                        } else {
                            bg_active = true;
                        }
                        i += if t.get(i + 2) == Some(&'T') { 8 } else { 5 };
                        continue;
                    }
                    _ => {}
                }
            }
            i += 1;
        }

        let mut out: String = t.iter().collect();
        if fg_active {
            out.push_str("`f");
        }
        if bg_active {
            out.push_str("`b");
        }
        for (k, on) in active.iter().enumerate() {
            if *on {
                out.push('`');
                out.push(TOGGLES[k]);
            }
        }
        out.push('…');
        out
    }

    /// Python `_wrap_text` (`util.py:748-811`).
    fn wrap_text(&self, text: &str, width: usize) -> Vec<String> {
        if text.is_empty() {
            return vec![String::new()];
        }
        let mut lines = Vec::new();
        let mut current_line = String::new();
        let mut current_width = 0;
        for word in text.split(' ') {
            if word.is_empty() {
                continue;
            }
            let wc: Vec<char> = word.chars().collect();
            let word_width = self.visible_width(&wc);
            if word_width > width {
                if !current_line.is_empty() {
                    lines.push(std::mem::take(&mut current_line));
                    current_width = 0;
                }
                let mut remaining: &[char] = &wc;
                while !remaining.is_empty() {
                    let (mut low, mut high) = (1usize, remaining.len());
                    let mut fit = 0;
                    while low <= high {
                        let mid = (low + high) / 2;
                        if self.visible_width(&remaining[..mid]) <= width {
                            fit = mid;
                            low = mid + 1;
                        } else {
                            high = mid - 1;
                        }
                    }
                    if fit == 0 {
                        fit = 1;
                    }
                    lines.push(remaining[..fit].iter().collect());
                    remaining = &remaining[fit..];
                }
                continue;
            }
            let space_width = usize::from(!current_line.is_empty());
            if current_width + space_width + word_width <= width {
                if !current_line.is_empty() {
                    current_line.push(' ');
                    current_line.push_str(word);
                    current_width += space_width + word_width;
                } else {
                    current_line = word.to_string();
                    current_width = word_width;
                }
            } else {
                lines.push(std::mem::replace(&mut current_line, word.to_string()));
                current_width = word_width;
            }
        }
        if !current_line.is_empty() {
            lines.push(current_line);
        }
        if lines.is_empty() {
            vec![String::new()]
        } else {
            lines
        }
    }
}

#[derive(Default)]
struct BlockState {
    out: Vec<String>,
    in_code_block: bool,
    code_block_lang: Option<String>,
    code_buffer: Vec<String>,
    in_table: bool,
    table_buffer: Vec<String>,
    in_quote: bool,
    quote_buffer: Vec<String>,
}

impl BlockState {
    fn flush_quote(&mut self, m: &MarkdownToMicron) -> Result<(), MarkdownError> {
        if self.quote_buffer.is_empty() {
            self.in_quote = false;
            return Ok(());
        }
        let formatted = m.format_inline(&self.quote_buffer.join(" "))?;
        let width = m.max_width.saturating_sub(3).max(1);
        for line in m.wrap_text(&formatted, width) {
            self.out.push(format!(" │ {line}"));
        }
        self.quote_buffer.clear();
        self.in_quote = false;
        Ok(())
    }

    fn flush_table(&mut self, m: &MarkdownToMicron) -> Result<(), MarkdownError> {
        if self.table_buffer.is_empty() {
            self.in_table = false;
            return Ok(());
        }
        let rows = std::mem::take(&mut self.table_buffer);
        if rows.len() >= 2 && is_table_separator(&rows[1]) {
            self.out.extend(m.format_table(&rows, "c")?);
        } else {
            for line in &rows {
                self.out.push(m.format_line(line)?);
            }
        }
        self.in_table = false;
        Ok(())
    }

    /// Upstream's `except Exception` fallback (`util.py:218-224`) has no
    /// counterpart: the highlighter here cannot fail.
    fn flush_code(&mut self, m: &MarkdownToMicron) {
        if self.code_buffer.is_empty() {
            return;
        }
        let code = self.code_buffer.join("\n");
        let lang = self.code_block_lang.as_deref().filter(|l| !l.is_empty());
        match (&m.syntax_highlighter, lang) {
            (Some(_), Some(lang)) if lang.to_lowercase() == "rawmu" => self.out.push(code),
            (Some(hl), Some(lang)) => {
                self.out.push(format!(
                    "{}{}",
                    MarkdownToMicron::CODE_BG,
                    MarkdownToMicron::CODE_FG
                ));
                self.out.push(hl.highlight(&code, None, Some(lang)));
                self.out.push(MarkdownToMicron::CODE_RESET.to_string());
            }
            _ => {
                self.out.push(format!(
                    "{}{}",
                    MarkdownToMicron::CODE_BG,
                    MarkdownToMicron::CODE_FG
                ));
                self.out.push(MarkdownToMicron::LITERAL_START.to_string());
                self.out.push(escape_literals(&code));
                self.out.push(MarkdownToMicron::LITERAL_END.to_string());
                self.out.push(MarkdownToMicron::CODE_RESET.to_string());
            }
        }
        self.code_buffer.clear();
    }
}

/// Python `re` `\s` and `str.isspace()`: Unicode White_Space plus U+001C..U+001F.
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(py_space)
}

fn escape_literals(text: &str) -> String {
    text.replace('`', "\\`")
}

fn leading_space(c: &[char]) -> usize {
    c.iter().take_while(|x| py_space(**x)).count()
}

/// `\s+(.+)$` on `rest`: the `(.+)` group.
fn spaced_tail(rest: &[char]) -> Option<&[char]> {
    let k = leading_space(rest);
    if k == 0 || rest.len() < 2 {
        return None;
    }
    Some(&rest[k.min(rest.len() - 1)..])
}

/// `HEADER_RE = ^(#{1,6})\s+(.+)$`.
fn match_header(c: &[char]) -> Option<(usize, &[char])> {
    let n = c.iter().take_while(|x| **x == '#').count();
    if n == 0 || n > 6 {
        return None;
    }
    spaced_tail(&c[n..]).map(|t| (n, t))
}

/// `UNORDERED_LIST_RE = ^(\s*)([-*+])\s+(.+)$`.
fn match_list_item(c: &[char]) -> Option<(&[char], &[char])> {
    let w = leading_space(c);
    if !matches!(c.get(w), Some('-' | '*' | '+')) {
        return None;
    }
    spaced_tail(&c[w + 1..]).map(|t| (&c[..w], t))
}

/// `HORIZONTAL_RULE_RE = ^(\s*)(---+|===+|\*\*\*+|___+)\s*$`.
fn is_horizontal_rule(c: &[char]) -> bool {
    let w = leading_space(c);
    let Some(&ch) = c.get(w) else { return false };
    if !matches!(ch, '-' | '=' | '*' | '_') {
        return false;
    }
    let run = c[w..].iter().take_while(|x| **x == ch).count();
    run >= 3 && c[w + run..].iter().all(|x| py_space(*x))
}

/// `CODE_FENCE_RE = ^(\s*)```(.*)$`: the language hint (group 2).
fn detect_code_fence(line: &str) -> Option<&str> {
    line.trim_start_matches(py_space).strip_prefix("```")
}

/// `QUOTE_RE = ^>\s?(.*)$`: group 1.
fn quote_match(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('>')?;
    let mut chars = rest.chars();
    match chars.next() {
        Some(c) if py_space(c) => Some(chars.as_str()),
        _ => Some(rest),
    }
}

/// Group 1 of `TABLE_ROW_RE = ^\s*\|?(.+?)\|?\s*$`.
fn table_row_group(c: &[char]) -> Option<&[char]> {
    let trail = c.len() - c.iter().rev().take_while(|x| py_space(**x)).count();
    let suffix_from = if trail > 0 && c[trail - 1] == '|' {
        trail - 1
    } else {
        trail
    };
    let w = leading_space(c);
    for ws in (0..=w).rev() {
        let pipe = c.get(ws) == Some(&'|');
        for start in [ws + usize::from(pipe), ws] {
            if start < c.len() {
                return Some(&c[start..(start + 1).max(suffix_from)]);
            }
            if !pipe {
                break;
            }
        }
    }
    None
}

/// Python `_is_table_row` (`util.py:408-413`).
fn is_table_row(line: &str) -> bool {
    if !line.contains('|') {
        return false;
    }
    let c: Vec<char> = line.chars().collect();
    let Some(content) = table_row_group(&c) else {
        return false;
    };
    content.contains(&'|') || py_strip(line).starts_with('|')
}

/// `TABLE_SEP_RE = ^\s*\|?(?:\s*:?-+:?\s*\|)+\s*$`.
fn is_table_separator(line: &str) -> bool {
    let c: Vec<char> = line.chars().collect();
    let mut i = leading_space(&c);
    if c.get(i) == Some(&'|') {
        i += 1;
    }
    let group = |mut j: usize| -> Option<usize> {
        j += leading_space(&c[j..]);
        if c.get(j) == Some(&':') {
            j += 1;
        }
        let dashes = c[j..].iter().take_while(|x| **x == '-').count();
        if dashes == 0 {
            return None;
        }
        j += dashes;
        if c.get(j) == Some(&':') {
            j += 1;
        }
        j += leading_space(&c[j..]);
        (c.get(j) == Some(&'|')).then_some(j + 1)
    };
    let Some(mut j) = group(i) else { return false };
    while let Some(next) = group(j) {
        j = next;
    }
    c[j..].iter().all(|x| py_space(*x))
}

/// Python `_parse_table_row` (`util.py:633-654`).
fn parse_table_row(line: &str) -> Vec<String> {
    let line = py_strip(line);
    let line = line.strip_prefix('|').unwrap_or(line);
    let line = line.strip_suffix('|').unwrap_or(line);
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '|' {
            cells.push(py_strip(&current).to_string());
            current.clear();
        } else {
            current.push(ch);
        }
    }
    cells.push(py_strip(&current).to_string());
    cells
}

/// Python `_parse_table_alignments` (`util.py:656-665`).
fn parse_table_alignments(line: &str) -> Vec<Align> {
    parse_table_row(line)
        .iter()
        .map(|cell| {
            let cell = py_strip(cell);
            if cell.starts_with(':') && cell.ends_with(':') {
                Align::Center
            } else if cell.ends_with(':') {
                Align::Right
            } else {
                Align::Left
            }
        })
        .collect()
}

/// One left-to-right `re.sub(pattern, '', text)` pass.
fn remove_matches(c: &[char], matcher: impl Fn(&[char], usize) -> Option<usize>) -> Vec<char> {
    let mut out = Vec::with_capacity(c.len());
    let mut i = 0;
    while i < c.len() {
        if let Some(n) = matcher(c, i) {
            i += n;
        } else {
            out.push(c[i]);
            i += 1;
        }
    }
    out
}

/// `LINK_RE = \[([^\]]+)\]\(([^)]+)\)` replaced by `\0LINKn\0`.
fn sub_links(c: &[char], links: &mut Vec<(String, String)>) -> String {
    let find = |from: usize, ch: char| c[from..].iter().position(|x| *x == ch).map(|p| from + p);
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '[' {
            let m = find(i + 1, ']')
                .filter(|&j| j > i + 1 && c.get(j + 1) == Some(&'('))
                .and_then(|j| find(j + 2, ')').filter(|&k| k > j + 2).map(|k| (j, k)));
            if let Some((j, k)) = m {
                links.push((c[i + 1..j].iter().collect(), c[j + 2..k].iter().collect()));
                out.push_str(&format!("\0LINK{}\0", links.len() - 1));
                i = k + 1;
                continue;
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

/// `INLINE_CODE_RE = `([^`]+)`` replaced by `\0CODEn\0`.
fn sub_inline_code(c: &[char], codes: &mut Vec<String>) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '`'
            && let Some(p) = c[i + 1..].iter().position(|x| *x == '`')
            && p > 0
        {
            codes.push(c[i + 1..i + 1 + p].iter().collect());
            out.push_str(&format!("\0CODE{}\0", codes.len() - 1));
            i += p + 2;
            continue;
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

/// `BOLD_RE = \*\*(.+?)\*\*|__(.+?)__` (`n == 2`) and
/// `ITALIC_RE = \*(.+?)\*|_(.+?)_` (`n == 1`).
fn sub_emphasis(c: &[char], star: char, n: usize, open: &str, close: &str) -> String {
    let delim_at = |i: usize, d: char| c.len() >= i + n && c[i..i + n].iter().all(|x| *x == d);
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        let delim = [star, '_'].into_iter().find(|&d| delim_at(i, d));
        if let Some(d) = delim {
            let end = (i + n + 1..c.len())
                .take_while(|&j| c[j - 1] != '\n')
                .find(|&j| delim_at(j, d));
            if let Some(j) = end {
                out.push_str(open);
                out.extend(&c[i + n..j]);
                out.push_str(close);
                i = j + n;
                continue;
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

/// `re.sub(r'\x00TAG(\d+)\x00', f, text)`; the index goes through Python
/// `int()`, which accepts any Unicode decimal digit and at most 4300 of them.
fn sub_placeholders(
    c: &[char],
    tag: &str,
    mut f: impl FnMut(usize) -> Result<String, MarkdownError>,
) -> Result<String, MarkdownError> {
    let tag: Vec<char> = tag.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '\0' && c[i + 1..].starts_with(&tag) {
            let d0 = i + 1 + tag.len();
            let digits = c[d0..]
                .iter()
                .take_while(|x| py_decimal(**x).is_some())
                .count();
            if digits > 0 && c.get(d0 + digits) == Some(&'\0') {
                if digits > 4300 {
                    return Err(MarkdownError::PlaceholderDigits);
                }
                let idx = c[d0..d0 + digits].iter().try_fold(0usize, |acc, x| {
                    acc.checked_mul(10)?.checked_add(py_decimal(*x)? as usize)
                });
                out.push_str(&f(idx.unwrap_or(usize::MAX))?);
                i = d0 + digits + 1;
                continue;
            }
        }
        out.push(c[i]);
        i += 1;
    }
    Ok(out)
}

/// Digit zeros of every Unicode decimal-digit run in Python 3.13's Unicode
/// 15.1 database; each run holds the ten digits zero..nine.
const DECIMAL_ZEROS: [u32; 68] = [
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66,
    0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650,
    0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16A60, 0x16AC0,
    0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E950,
    0x1FBF0,
];

fn py_decimal(c: char) -> Option<u32> {
    let c = c as u32;
    DECIMAL_ZEROS
        .iter()
        .find(|&&z| (z..=z + 9).contains(&c))
        .map(|z| c - z)
}
