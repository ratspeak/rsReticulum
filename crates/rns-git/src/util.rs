//! Request validators from `RNS/Utilities/rngit/util.py@1.6.0`.

use rns_tools::rsg::pyfmt::py_fromhex;

/// Python `san_ref` (`util.py:36-63`): the ref when it passes upstream's
/// subset of `git check-ref-format`. A ref without `/` (`HEAD`, `main`) and
/// any character below `(` are rejected, as upstream does.
pub fn san_ref(reference: &str) -> Option<&str> {
    let r = reference;
    if r.starts_with('-') || r.starts_with('/') || r.ends_with('/') || r.ends_with('.') {
        return None;
    }
    if [" ", "..", "/.", "//", "\\"].iter().any(|s| r.contains(s)) || !r.contains('/') {
        return None;
    }
    if r.split('/').any(|component| component.ends_with(".lock")) {
        return None;
    }
    if r.chars().any(|c| (c as u32) < 40) {
        return None;
    }
    if ["\x7f", "~", "^", ":", "?", "*", "[", "@{"]
        .iter()
        .any(|s| r.contains(s))
        || r == "@"
    {
        return None;
    }
    Some(reference)
}

/// Python `san_refs` (`util.py:65-70`) for a list: the list when every ref
/// passes [`san_ref`]. Upstream returns an empty list unchanged, which its
/// callers then treat as a failure because it is falsy.
pub fn san_refs<S: AsRef<str>>(refs: &[S]) -> Option<&[S]> {
    refs.iter()
        .all(|r| san_ref(r.as_ref()).is_some())
        .then_some(refs)
}

/// Python `san_sha` (`util.py:73-77`): at least 40 characters that
/// `bytes.fromhex` accepts. There is no upper bound, and `fromhex` skips
/// whitespace between byte pairs.
pub fn san_sha(sha: &str) -> Option<&str> {
    if sha.chars().count() < 40 {
        return None;
    }
    py_fromhex(sha).ok().map(|_| sha)
}
