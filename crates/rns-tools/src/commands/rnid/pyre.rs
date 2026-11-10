//! Minimal backtracking matcher for the fixed regular expressions used by the
//! vendored ConfigObj and Validator (`RNS/vendor/configobj.py`,
//! `RNS/vendor/validate.py`). Supports the subset those patterns use: groups,
//! non-capturing groups, alternation, greedy and lazy `* + ?`, character
//! classes, `\s`/`\S`, `.`, `^`, `$` and a single-character negative
//! lookbehind. Semantics follow Python's `re` (leftmost, first alternative,
//! backtracking).

#[derive(Debug, Clone)]
enum ClassItem {
    Char(char),
    Range(char, char),
    Space,
    NotSpace,
}

#[derive(Debug, Clone)]
enum Node {
    Char(char),
    Any,
    Class {
        items: Vec<ClassItem>,
        negated: bool,
    },
    Space,
    NotSpace,
    Start,
    End,
    Group(Box<Node>, Option<usize>),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat {
        node: Box<Node>,
        min: usize,
        max: Option<usize>,
        greedy: bool,
    },
    NotPrecededBy(char),
}

pub struct Regex {
    node: Node,
    groups: usize,
    dotall: bool,
}

pub type Caps = Vec<Option<(usize, usize)>>;

/// Python `str.isspace` for the characters `\s` matches in `re`.
pub fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

struct Parser<'a> {
    chars: Vec<char>,
    pos: usize,
    groups: usize,
    _src: &'a str,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn alt(&mut self) -> Node {
        let mut branches = vec![self.concat()];
        while self.peek() == Some('|') {
            self.pos += 1;
            branches.push(self.concat());
        }
        if branches.len() == 1 {
            branches.pop().unwrap()
        } else {
            Node::Alt(branches)
        }
    }

    fn concat(&mut self) -> Node {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom();
            items.push(self.quantified(atom));
        }
        Node::Concat(items)
    }

    fn quantified(&mut self, atom: Node) -> Node {
        let (min, max) = match self.peek() {
            Some('*') => (0, None),
            Some('+') => (1, None),
            Some('?') => (0, Some(1)),
            _ => return atom,
        };
        self.pos += 1;
        let greedy = if self.peek() == Some('?') {
            self.pos += 1;
            false
        } else {
            true
        };
        Node::Repeat {
            node: Box::new(atom),
            min,
            max,
            greedy,
        }
    }

    fn escape(&mut self) -> char {
        let c = self.chars[self.pos];
        self.pos += 1;
        c
    }

    fn atom(&mut self) -> Node {
        let c = self.chars[self.pos];
        self.pos += 1;
        match c {
            '^' => Node::Start,
            '$' => Node::End,
            '.' => Node::Any,
            '\\' => match self.escape() {
                's' => Node::Space,
                'S' => Node::NotSpace,
                other => Node::Char(other),
            },
            '[' => self.class(),
            '(' => {
                if self.peek() == Some('?') {
                    self.pos += 1;
                    let kind = self.escape();
                    if kind == ':' {
                        let inner = self.alt();
                        self.pos += 1;
                        Node::Group(Box::new(inner), None)
                    } else {
                        // `(?<!c)`
                        assert_eq!(kind, '<');
                        assert_eq!(self.escape(), '!');
                        let ch = self.escape();
                        assert_eq!(self.escape(), ')');
                        Node::NotPrecededBy(ch)
                    }
                } else {
                    let index = self.groups;
                    self.groups += 1;
                    let inner = self.alt();
                    self.pos += 1;
                    Node::Group(Box::new(inner), Some(index))
                }
            }
            other => Node::Char(other),
        }
    }

    fn class(&mut self) -> Node {
        let mut negated = false;
        if self.peek() == Some('^') {
            negated = true;
            self.pos += 1;
        }
        let mut items = Vec::new();
        loop {
            let c = self.chars[self.pos];
            self.pos += 1;
            if c == ']' {
                break;
            }
            let item = if c == '\\' {
                match self.escape() {
                    's' => ClassItem::Space,
                    'S' => ClassItem::NotSpace,
                    other => ClassItem::Char(other),
                }
            } else if self.peek() == Some('-') && self.chars.get(self.pos + 1) != Some(&']') {
                self.pos += 1;
                let end = self.chars[self.pos];
                self.pos += 1;
                ClassItem::Range(c, end)
            } else {
                ClassItem::Char(c)
            };
            items.push(item);
        }
        Node::Class { items, negated }
    }
}

impl Regex {
    pub fn new(pattern: &str) -> Self {
        Self::build(pattern, false)
    }

    pub fn dotall(pattern: &str) -> Self {
        Self::build(pattern, true)
    }

    fn build(pattern: &str, dotall: bool) -> Self {
        let mut parser = Parser {
            chars: pattern.chars().collect(),
            pos: 0,
            groups: 0,
            _src: pattern,
        };
        let node = parser.alt();
        assert_eq!(parser.pos, parser.chars.len(), "unbalanced pattern");
        Self {
            node,
            groups: parser.groups,
            dotall,
        }
    }

    /// Python `re.match`: anchored at `start`, not required to reach the end.
    pub fn match_at(&self, text: &[char], start: usize) -> Option<Caps> {
        self.try_at(text, start, None)
    }

    fn try_at(&self, text: &[char], start: usize, forbid_empty: Option<usize>) -> Option<Caps> {
        let mut caps: Caps = vec![None; self.groups + 1];
        let mut result = None;
        let mut k = |end: usize, caps: &mut Caps| {
            if forbid_empty == Some(start) && end == start {
                return false;
            }
            let mut out = caps.clone();
            out[self.groups] = Some((start, end));
            result = Some(out);
            true
        };
        if self.m(&self.node, text, start, &mut caps, &mut k) {
            result
        } else {
            None
        }
    }

    /// Python `re.search` from `from`; the whole match is in the last slot.
    pub fn search(&self, text: &[char], from: usize) -> Option<Caps> {
        self.search_inner(text, from, None)
    }

    fn search_inner(&self, text: &[char], from: usize, forbid: Option<usize>) -> Option<Caps> {
        (from..=text.len()).find_map(|start| self.try_at(text, start, forbid))
    }

    /// Python `re.findall` for a pattern with exactly one group.
    pub fn findall(&self, text: &[char]) -> Vec<String> {
        let mut out = Vec::new();
        let mut pos = 0;
        let mut forbid = None;
        while pos <= text.len() {
            let Some(caps) = self.search_inner(text, pos, forbid) else {
                break;
            };
            out.push(group_str(text, &caps, 0).unwrap_or_default());
            let (start, end) = caps[self.groups].unwrap();
            forbid = (start == end).then_some(end);
            pos = end;
        }
        out
    }

    fn m(
        &self,
        node: &Node,
        text: &[char],
        pos: usize,
        caps: &mut Caps,
        k: &mut dyn FnMut(usize, &mut Caps) -> bool,
    ) -> bool {
        match node {
            Node::Char(c) => text.get(pos) == Some(c) && k(pos + 1, caps),
            Node::Any => match text.get(pos) {
                Some(&c) if self.dotall || c != '\n' => k(pos + 1, caps),
                _ => false,
            },
            Node::Space => text.get(pos).is_some_and(|&c| is_py_space(c)) && k(pos + 1, caps),
            Node::NotSpace => text.get(pos).is_some_and(|&c| !is_py_space(c)) && k(pos + 1, caps),
            Node::Class { items, negated } => match text.get(pos) {
                Some(&c) if class_matches(items, c) != *negated => k(pos + 1, caps),
                _ => false,
            },
            Node::Start => pos == 0 && k(pos, caps),
            Node::End => {
                (pos == text.len() || (pos + 1 == text.len() && text[pos] == '\n')) && k(pos, caps)
            }
            Node::NotPrecededBy(c) => !(pos > 0 && text[pos - 1] == *c) && k(pos, caps),
            Node::Group(inner, index) => match index {
                None => self.m(inner, text, pos, caps, k),
                Some(i) => {
                    let i = *i;
                    self.m(inner, text, pos, caps, &mut |end, caps: &mut Caps| {
                        let old = caps[i];
                        caps[i] = Some((pos, end));
                        if k(end, caps) {
                            true
                        } else {
                            caps[i] = old;
                            false
                        }
                    })
                }
            },
            Node::Concat(items) => self.concat(items, text, pos, caps, k),
            Node::Alt(branches) => branches
                .iter()
                .any(|branch| self.m(branch, text, pos, caps, k)),
            Node::Repeat {
                node,
                min,
                max,
                greedy,
            } => self.repeat(node, *min, *max, *greedy, 0, text, pos, caps, k),
        }
    }

    fn concat(
        &self,
        items: &[Node],
        text: &[char],
        pos: usize,
        caps: &mut Caps,
        k: &mut dyn FnMut(usize, &mut Caps) -> bool,
    ) -> bool {
        match items.split_first() {
            None => k(pos, caps),
            Some((first, rest)) => self.m(first, text, pos, caps, &mut |next, caps: &mut Caps| {
                self.concat(rest, text, next, caps, k)
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn repeat(
        &self,
        node: &Node,
        min: usize,
        max: Option<usize>,
        greedy: bool,
        count: usize,
        text: &[char],
        pos: usize,
        caps: &mut Caps,
        k: &mut dyn FnMut(usize, &mut Caps) -> bool,
    ) -> bool {
        let can_more = max.is_none_or(|max| count < max);
        let more = |caps: &mut Caps, k: &mut dyn FnMut(usize, &mut Caps) -> bool| {
            can_more
                && self.m(node, text, pos, caps, &mut |next, caps: &mut Caps| {
                    // Like Python's sre, accept one zero-width iteration but never loop on it.
                    if next == pos && count + 1 >= min {
                        return k(next, caps);
                    }
                    self.repeat(node, min, max, greedy, count + 1, text, next, caps, k)
                })
        };
        // The operands backtrack through `k`, so their order is the greediness.
        #[allow(clippy::if_same_then_else)]
        if greedy {
            more(caps, k) || (count >= min && k(pos, caps))
        } else {
            (count >= min && k(pos, caps)) || more(caps, k)
        }
    }
}

fn class_matches(items: &[ClassItem], c: char) -> bool {
    items.iter().any(|item| match item {
        ClassItem::Char(x) => *x == c,
        ClassItem::Range(a, b) => (*a..=*b).contains(&c),
        ClassItem::Space => is_py_space(c),
        ClassItem::NotSpace => !is_py_space(c),
    })
}

/// Text of capture group `index` (0-based over the pattern's groups).
pub fn group_str(text: &[char], caps: &Caps, index: usize) -> Option<String> {
    caps[index].map(|(a, b)| text[a..b].iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    #[test]
    fn lazy_and_greedy_follow_python_preference() {
        let re = Regex::new(r"^(.*?)=(.*)$");
        let t = chars("a=b=c");
        let caps = re.match_at(&t, 0).unwrap();
        assert_eq!(group_str(&t, &caps, 0).unwrap(), "a");
        assert_eq!(group_str(&t, &caps, 1).unwrap(), "b=c");
    }

    #[test]
    fn findall_returns_first_group_per_match() {
        let re = Regex::new(r#"((?:".*?")|(?:'.*?')|(?:[^'",\#]?.*?))\s*,\s*"#);
        assert_eq!(
            re.findall(&chars("a, \"b,c\" , d,")),
            vec!["a", "\"b,c\"", "d"]
        );
    }

    #[test]
    fn negative_lookbehind_blocks_after_comma() {
        let re = Regex::new(r"^a,(?:(?<!,))b?$");
        assert!(re.match_at(&chars("a,"), 0).is_none());
        assert!(re.match_at(&chars("a,b"), 0).is_none());
    }
}
