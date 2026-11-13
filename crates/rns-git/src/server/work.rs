//! `/mgmt/work`: work documents on the server
//! (`handle_work` and `resolve_doc_permission`, `server.py`,
//! `3789-4441`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

use rmpv::Value;
use rns_identity::identity::Identity;

use super::handlers::{get, identity_text, log_request, status, truthy};
use super::layout::{Repositories, parse_repository_path};
use super::perms::{Perm, PermList, Permissions, Target, resolve_repository};
use super::perms_mgmt::invalid_line;
use super::{
    IDX_REPOSITORY, RES_DISALLOWED, RES_INVALID_REQ, RES_NOT_FOUND, RES_OK, RES_REMOTE_FAIL,
};

/// `WORK_DOC_LIMIT` (`server.py`), counted in code points.
pub const WORK_DOC_LIMIT: usize = 256 * 1024;

/// Upstream raised inside its `try`, replying "Remote error".
struct Raised;

const SCOPES: [&str; 3] = ["active", "completed", "proposed"];

/// Deferred jobs run in parallel; ids are picked from the directory listing,
/// so concurrent creates would otherwise share an id.
static WORK_LOCK: Mutex<()> = Mutex::new(());

/// Python `str.isspace()`.
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(py_space)
}

/// A request map, read by string key as upstream's `data.get(...)`.
struct Request<'a>(&'a [(Value, Value)]);

impl Request<'_> {
    fn get(&self, key: &str) -> Option<&Value> {
        get(self.0, &Value::from(key))
    }

    /// `data.get(key, default)` where only a `str` can equal the names it is
    /// compared with; `None` is a value that matches no name.
    fn name(&self, key: &str, default: &str) -> Option<String> {
        match self.get(key) {
            None => Some(default.to_string()),
            Some(Value::String(s)) => s.as_str().map(str::to_string),
            Some(_) => None,
        }
    }

    /// `data.get(key, "")` followed by a `str` method: anything else raises.
    fn text(&self, key: &str) -> Result<String, Raised> {
        match self.get(key) {
            None => Ok(String::new()),
            Some(Value::String(s)) => s.as_str().map(str::to_string).ok_or(Raised),
            Some(_) => Err(Raised),
        }
    }
}

fn valid_scope(scope: &Option<String>) -> bool {
    scope
        .as_deref()
        .is_some_and(|s| SCOPES.contains(&s) || s == "all")
}

/// Python `int()` on an unpacked value; `Err` where it raises.
fn py_int(value: &Value) -> Result<i128, Raised> {
    match value {
        Value::Integer(i) => i
            .as_i64()
            .map(i128::from)
            .or_else(|| i.as_u64().map(i128::from))
            .ok_or(Raised),
        Value::F32(f) if f.is_finite() => Ok(*f as i128),
        Value::F64(f) if f.is_finite() => Ok(*f as i128),
        Value::Boolean(b) => Ok(i128::from(*b)),
        Value::String(s) => s.as_str().ok_or(Raised).and_then(py_int_str),
        Value::Binary(b) => std::str::from_utf8(b)
            .map_err(|_| Raised)
            .and_then(py_int_str),
        _ => Err(Raised),
    }
}

fn py_int_str(text: &str) -> Result<i128, Raised> {
    let trimmed = py_strip(text);
    let (negative, digits) = match trimmed.strip_prefix(['+', '-']) {
        Some(rest) => (trimmed.starts_with('-'), rest),
        None => (false, trimmed),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return Err(Raised);
    }
    let mut value: i128 = 0;
    for c in digits.chars().filter(|c| *c != '_') {
        let digit = i128::from(c.to_digit(10).ok_or(Raised)?);
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(Raised)?;
    }
    Ok(if negative { -value } else { value })
}

fn int_value(n: i128) -> Value {
    match (i64::try_from(n), u64::try_from(n)) {
        (Ok(v), _) => Value::from(v),
        (_, Ok(v)) => Value::from(v),
        _ => Value::Nil,
    }
}

/// `doc_id = data.get("doc_id")`, the `is None` check and `int(doc_id)`.
fn doc_id(data: &Request) -> Result<i128, Vec<u8>> {
    match data.get("doc_id") {
        None | Some(Value::Nil) => Err(status(RES_INVALID_REQ, "No document ID specified")),
        Some(value) => py_int(value).map_err(|_| status(RES_INVALID_REQ, "Invalid document ID")),
    }
}

/// The first scope holding `<scope>/<id>` as a directory.
fn find_doc(
    work_path: &Path,
    doc_id: i128,
    scopes: &[&'static str],
) -> Option<(&'static str, PathBuf)> {
    scopes.iter().find_map(|scope| {
        let dir = work_path.join(scope).join(doc_id.to_string());
        dir.is_dir().then_some((*scope, dir))
    })
}

fn allowed_path(work_path: &Path, doc_id: i128) -> PathBuf {
    PathBuf::from(format!("{}/{doc_id}.allowed", work_path.display()))
}

/// `resolve_doc_permission` (`server.py`): the document's
/// `.allowed` file decides first, then the repository and group as
/// `resolve_permission` does. Upstream runs it without the block list.
pub fn resolve_doc_permission(
    repos: &Repositories,
    hash: &[u8; 16],
    path: Option<(&str, &str)>,
    doc_id: i128,
    perm: Perm,
) -> bool {
    if repos.is_blocked(hash) {
        return false;
    }
    let Some((group_name, repository_name)) = path else {
        return false;
    };
    let Some(group) = repos.groups.get(group_name) else {
        return false;
    };
    let Some(repository) = group.repositories.get(repository_name) else {
        return false;
    };
    let list = match perm {
        Perm::Read => PermList::Read,
        Perm::Write => PermList::Write,
        Perm::Create => PermList::Create,
        Perm::Interact => PermList::Interact,
        Perm::Propose => PermList::Propose,
        Perm::Admin => PermList::Admin,
        Perm::ReadWrite | Perm::Stats | Perm::Release => return false,
    };
    let work_path = PathBuf::from(format!("{}.work", repository.path.display()));
    let allowed = allowed_path(&work_path, doc_id);
    let mut input = String::new();
    if work_path.is_dir() && allowed.is_file() {
        match std::fs::read_to_string(&allowed) {
            Ok(text) => input = text,
            Err(e) => tracing::error!(
                "Error while resolving document permission for {group_name}/{repository_name}/{doc_id}: {e}"
            ),
        }
    }
    let doc = Permissions::from_allowed_input(&input, &repos.aliases);
    let me = Target::Identity(hash.to_vec());
    let doc_list = doc.get(list);
    if doc_list.contains(&Target::None) {
        return false;
    }
    if doc_list.contains(&Target::All)
        || doc_list.contains(&me)
        || doc.get(PermList::Admin).contains(&me)
    {
        return true;
    }
    resolve_repository(&group.permissions, &repository.permissions, hash, perm)
}

/// Python's text-mode read: UTF-8, with `\r\n` and `\r` read as `\n`.
pub(crate) fn read_text(path: &Path) -> std::io::Result<String> {
    let text = std::fs::read_to_string(path)?;
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

/// `_work_load_document`: any read or decode failure is None.
pub(crate) fn load_document(path: &Path) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    rmpv::decode::read_value(&mut &bytes[..]).ok()
}

/// `_work_save_document` (`server.py`).
fn save_document(path: &Path, document: &Value) -> bool {
    let saved = (|| -> std::io::Result<()> {
        let dir = path.parent().unwrap_or(Path::new("."));
        if !dir.is_dir() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = append_suffix(path, ".tmp");
        std::fs::File::create(&tmp)?.write_all(&pack(document))?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = &saved {
        tracing::error!("Error persisting work document: {e}");
    }
    saved.is_ok()
}

/// Write `text` through `<path>.tmp` and a rename, as upstream's permission writers.
fn write_replacing(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = append_suffix(path, ".tmp");
    std::fs::File::create(&tmp)?.write_all(text.as_bytes())?;
    std::fs::rename(&tmp, path)
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn pack(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).expect("msgpack write to memory");
    bytes
}

fn ok_with(value: Value) -> Vec<u8> {
    let mut reply = vec![RES_OK];
    reply.extend_from_slice(&pack(&value));
    reply
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::from(k), v))
            .collect(),
    )
}

/// Numeric entry names of a directory, as `[int(d) for d in listdir if d.isdigit()]`.
fn numeric_entries(dir: &Path) -> Vec<(i128, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let numeric = !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit());
            numeric
                .then(|| name.parse::<i128>().ok())
                .flatten()
                .map(|id| (id, e.path()))
        })
        .collect()
}

/// `_work_get_next_id` and `_work_get_next_comment_id`: one past the highest
/// numeric entry, minimum 1. Entries of any type count.
fn next_in(dir: &Path) -> i128 {
    numeric_entries(dir)
        .iter()
        .map(|(id, _)| id + 1)
        .max()
        .unwrap_or(1)
}

fn next_id(work_path: &Path) -> i128 {
    SCOPES
        .iter()
        .map(|s| next_in(&work_path.join(s)))
        .max()
        .unwrap_or(1)
}

fn meta_of(document: &Value) -> &[(Value, Value)] {
    let meta = match document {
        Value::Map(entries) => get(entries, &Value::from("meta")),
        _ => None,
    };
    match meta {
        Some(Value::Map(entries)) => entries,
        _ => &[],
    }
}

/// `meta.get(key, default)`.
fn meta_get(meta: &[(Value, Value)], key: &str, default: Value) -> Value {
    get(meta, &Value::from(key)).cloned().unwrap_or(default)
}

fn doc_get(document: &Value, key: &str, default: Value) -> Value {
    match document {
        Value::Map(entries) => get(entries, &Value::from(key)).cloned().unwrap_or(default),
        _ => default,
    }
}

/// `RNS.hexrep(meta.get("author"), delimit=False) if meta.get("author") else ""`.
fn author_text(meta: &[(Value, Value)]) -> Value {
    match get(meta, &Value::from("author")) {
        Some(Value::Binary(b)) if !b.is_empty() => Value::from(hex::encode(b)),
        _ => Value::from(""),
    }
}

fn is_author(document: &Value, hash: &[u8; 16]) -> bool {
    matches!(get(meta_of(document), &Value::from("author")), Some(Value::Binary(b)) if b.as_slice() == hash)
}

/// The stored format: the value when it is one of the two names, else markdown.
fn stored_format(format: Option<&Value>) -> Value {
    match format.and_then(Value::as_str) {
        Some(f @ ("markdown" | "micron")) => Value::from(f),
        _ => Value::from("markdown"),
    }
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Python `len()` of an unpacked value; `Err` where it raises.
fn py_len_of(value: &Value) -> Result<usize, Raised> {
    match value {
        Value::String(s) => s.as_str().map(super::py_len).ok_or(Raised),
        Value::Binary(b) => Ok(b.len()),
        Value::Array(a) => Ok(a.len()),
        Value::Map(m) => Ok(m.len()),
        _ => Err(Raised),
    }
}

/// The signature checks shared by create, propose and edit. `Ok(None)` passes.
fn check_signature(
    signature: Option<&Value>,
    identity: &Identity,
    signed: &[u8],
) -> Result<Option<Vec<u8>>, Raised> {
    let Some(signature) = signature.filter(|s| truthy(s)) else {
        return Ok(Some(status(RES_INVALID_REQ, "No signature provided")));
    };
    if py_len_of(signature)? != 64 {
        return Ok(Some(status(RES_INVALID_REQ, "Invalid signature length")));
    }
    let valid = match signature {
        Value::Binary(b) => {
            <[u8; 64]>::try_from(b.as_slice()).is_ok_and(|sig| identity.verify(signed, &sig))
        }
        _ => false,
    };
    Ok((!valid).then(|| status(RES_INVALID_REQ, "Invalid signature")))
}

/// `_work_list` (`server.py`).
fn work_list(
    work_path: &Path,
    data: &Request,
    repos: &Repositories,
    hash: &[u8; 16],
    path: Option<(&str, &str)>,
) -> Vec<u8> {
    let scope = data.name("scope", "active");
    let mut result = Vec::new();
    for folder in SCOPES {
        let mut docs: Vec<(f64, Value)> = Vec::new();
        let folder_path = work_path.join(folder);
        let listed = scope.as_deref().is_some_and(|s| s == folder || s == "all");
        let entries = if listed && folder_path.is_dir() {
            std::fs::read_dir(&folder_path)
                .map(|e| e.filter_map(|e| e.ok()).collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        for entry in entries {
            let doc_dir = entry.path();
            if !doc_dir.is_dir() {
                continue;
            }
            let Ok(doc_id) = py_int_str(&entry.file_name().to_string_lossy()) else {
                continue;
            };
            if !resolve_doc_permission(repos, hash, path, doc_id, Perm::Read) {
                continue;
            }
            let root = doc_dir.join("root");
            if !root.is_file() {
                continue;
            }
            let Some(doc) = load_document(&root).filter(truthy) else {
                continue;
            };
            let meta = meta_of(&doc);
            let comments = numeric_entries(&doc_dir)
                .iter()
                .filter(|(_, p)| p.is_file())
                .count();
            let created = meta_get(meta, "created", Value::from(0));
            let sort_key = created
                .as_f64()
                .or_else(|| created.as_i64().map(|v| v as f64))
                .unwrap_or(0.0);
            docs.push((
                sort_key,
                map(vec![
                    ("id", int_value(doc_id)),
                    ("title", meta_get(meta, "title", Value::from("Untitled"))),
                    ("created", created),
                    ("edited", meta_get(meta, "edited", Value::from(0))),
                    ("author", author_text(meta)),
                    ("format", meta_get(meta, "format", Value::from("markdown"))),
                    ("comments", Value::from(comments as u64)),
                ]),
            ));
        }
        // Newest first; a stable sort keeps the listing order of ties.
        docs.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        result.push((
            folder,
            Value::Array(docs.into_iter().map(|(_, v)| v).collect()),
        ));
    }
    ok_with(map(result))
}

/// `_work_view` (`server.py`).
fn work_view(work_path: &Path, data: &Request) -> Vec<u8> {
    if !valid_scope(&data.name("scope", "all")) {
        return status(RES_INVALID_REQ, "Invalid request");
    }
    let doc_id = match doc_id(data) {
        Ok(id) => id,
        Err(reply) => return reply,
    };
    let Some((scope, doc_dir)) = find_doc(work_path, doc_id, &SCOPES) else {
        return status(RES_NOT_FOUND, "Not found");
    };
    let root = doc_dir.join("root");
    if !root.is_file() {
        return status(RES_NOT_FOUND, "Document not found");
    }
    let Some(doc) = load_document(&root).filter(truthy) else {
        return status(RES_REMOTE_FAIL, "Error loading document");
    };
    let mut comments: Vec<(i128, Value)> = numeric_entries(&doc_dir)
        .into_iter()
        .filter(|(_, p)| p.is_file())
        .filter_map(|(id, p)| {
            let comment = load_document(&p).filter(truthy)?;
            let meta = meta_of(&comment);
            Some((
                id,
                map(vec![
                    ("id", int_value(id)),
                    ("content", doc_get(&comment, "content", Value::from(""))),
                    ("created", meta_get(meta, "created", Value::from(0))),
                    ("edited", meta_get(meta, "edited", Value::from(0))),
                    ("author", author_text(meta)),
                    ("format", meta_get(meta, "format", Value::from("markdown"))),
                ]),
            ))
        })
        .collect();
    comments.sort_by_key(|(id, _)| *id);
    let meta = meta_of(&doc);
    ok_with(map(vec![
        ("id", int_value(doc_id)),
        ("scope", Value::from(scope)),
        ("content", doc_get(&doc, "content", Value::from(""))),
        (
            "comments",
            Value::Array(comments.into_iter().map(|(_, v)| v).collect()),
        ),
        (
            "meta",
            map(vec![
                ("title", meta_get(meta, "title", Value::from("Untitled"))),
                ("created", meta_get(meta, "created", Value::from(0))),
                ("edited", meta_get(meta, "edited", Value::from(0))),
                ("author", author_text(meta)),
                ("identity", meta_get(meta, "identity", Value::Nil)),
                ("signature", meta_get(meta, "signature", Value::Nil)),
                ("format", meta_get(meta, "format", Value::from("markdown"))),
            ]),
        ),
    ]))
}

/// `_work_create` and `_work_propose` (`server.py`), which differ
/// in the scope they store under and the ownership file propose writes.
fn work_new(
    work_path: &Path,
    data: &Request,
    identity: &Identity,
    scope: &str,
) -> Result<Vec<u8>, Raised> {
    let title = py_strip(&data.text("title")?).to_string();
    let content = py_strip(&data.text("content")?).to_string();
    let format = data
        .get("format")
        .cloned()
        .unwrap_or(Value::from("markdown"));
    if let Some(reply) = check_signature(data.get("signature"), identity, content.as_bytes())? {
        return Ok(reply);
    }
    if super::py_len(&title) + super::py_len(&content) + py_len_of(&format)? > WORK_DOC_LIMIT {
        return Ok(status(RES_INVALID_REQ, "Content limit exceeded"));
    }
    if title.is_empty() {
        return Ok(status(RES_INVALID_REQ, "Title is required"));
    }
    if content.is_empty() {
        return Ok(status(RES_INVALID_REQ, "Content is required"));
    }
    let doc_id = next_id(work_path);
    let doc_dir = work_path.join(scope).join(doc_id.to_string());
    let now = now();
    let document = map(vec![
        ("content", Value::from(content.as_str())),
        (
            "meta",
            map(vec![
                ("format", stored_format(Some(&format))),
                ("title", Value::from(title.as_str())),
                ("created", Value::F64(now)),
                ("edited", Value::F64(now)),
                ("author", Value::Binary(identity.hash.to_vec())),
                (
                    "signature",
                    data.get("signature").cloned().unwrap_or(Value::Nil),
                ),
                (
                    "identity",
                    Value::Binary(identity.get_public_key().to_vec()),
                ),
            ]),
        ),
    ]);
    if !save_document(&doc_dir.join("root"), &document) {
        return Ok(status(RES_REMOTE_FAIL, "Error saving document"));
    }
    if scope == "proposed" {
        let owner = hex::encode(identity.hash);
        if let Err(e) = write_replacing(
            &allowed_path(work_path, doc_id),
            &format!("i:{owner}\nw:{owner}\n"),
        ) {
            tracing::error!("Error setting permissions: {e}");
            return Ok(status(RES_REMOTE_FAIL, "Error setting document ownership"));
        }
    }
    Ok(ok_with(map(vec![
        ("id", int_value(doc_id)),
        ("scope", Value::from(scope)),
    ])))
}

/// `_work_edit` (`server.py`).
fn work_edit(work_path: &Path, data: &Request, identity: &Identity) -> Result<Vec<u8>, Raised> {
    let scope = data.name("scope", "active");
    let content = data.text("content")?;
    let title = match data.get("title") {
        None => String::new(),
        Some(Value::String(s)) => s.as_str().ok_or(Raised)?.to_string(),
        Some(v) if !truthy(v) => String::new(),
        Some(_) => return Err(Raised),
    };
    let size = super::py_len(&title) + super::py_len(&content);
    if !valid_scope(&scope) {
        return Ok(status(RES_INVALID_REQ, "Invalid request"));
    }
    if let Some(reply) = check_signature(data.get("signature"), identity, content.as_bytes())? {
        return Ok(reply);
    }
    if size > WORK_DOC_LIMIT {
        return Ok(status(RES_INVALID_REQ, "Content limit exceeded"));
    }
    if content.is_empty() && title.is_empty() {
        return Ok(status(RES_INVALID_REQ, "No changes specified"));
    }
    let Some(raw_id) = data.get("doc_id").filter(|v| truthy(v)) else {
        return Ok(status(RES_INVALID_REQ, "No document ID specified"));
    };
    let Ok(doc_id) = py_int(raw_id) else {
        return Ok(status(RES_INVALID_REQ, "Invalid document ID"));
    };
    let Some((_, doc_dir)) = find_doc(work_path, doc_id, &SCOPES) else {
        return Ok(status(RES_NOT_FOUND, "Not found"));
    };
    let root = doc_dir.join("root");
    if !root.is_file() {
        return Ok(status(RES_NOT_FOUND, "Document not found"));
    }
    let Some(mut doc) = load_document(&root).filter(truthy) else {
        return Ok(status(RES_REMOTE_FAIL, "Error loading document"));
    };
    if !is_author(&doc, &identity.hash) {
        return Ok(status(RES_DISALLOWED, "No access, not author"));
    }
    let Value::Map(entries) = &mut doc else {
        return Err(Raised);
    };
    fn put(entries: &mut Vec<(Value, Value)>, key: &str, value: Value) {
        match entries.iter_mut().find(|(k, _)| k.as_str() == Some(key)) {
            Some((_, slot)) => *slot = value,
            None => entries.push((Value::from(key), value)),
        }
    }
    let Some(Value::Map(meta)) = entries
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("meta"))
        .map(|(_, v)| v)
    else {
        return Err(Raised);
    };
    if !title.is_empty() {
        put(meta, "title", Value::from(py_strip(&title)));
    }
    put(meta, "edited", Value::F64(now()));
    put(
        meta,
        "signature",
        data.get("signature").cloned().unwrap_or(Value::Nil),
    );
    put(
        meta,
        "identity",
        Value::Binary(identity.get_public_key().to_vec()),
    );
    if !content.is_empty() {
        put(entries, "content", Value::from(py_strip(&content)));
    }
    if !save_document(&root, &doc) {
        return Ok(status(RES_REMOTE_FAIL, "Error saving document"));
    }
    Ok(vec![RES_OK])
}

/// `_work_delete` (`server.py`).
fn work_delete(
    work_path: &Path,
    data: &Request,
    repos: &Repositories,
    hash: &[u8; 16],
    path: Option<(&str, &str)>,
) -> Result<Vec<u8>, Raised> {
    if !valid_scope(&data.name("scope", "active")) {
        return Ok(status(RES_INVALID_REQ, "Invalid request"));
    }
    let doc_id = match doc_id(data) {
        Ok(id) => id,
        Err(reply) => return Ok(reply),
    };
    // Upstream joins `None` into the path when no scope holds the document.
    let (_, doc_dir) = find_doc(work_path, doc_id, &SCOPES).ok_or(Raised)?;
    let root = doc_dir.join("root");
    if !root.is_file() {
        return Ok(status(RES_NOT_FOUND, "Document not found"));
    }
    let Some(doc) = load_document(&root).filter(truthy) else {
        return Ok(status(RES_REMOTE_FAIL, "Error loading document"));
    };
    if !(is_author(&doc, hash) || resolve_doc_permission(repos, hash, path, doc_id, Perm::Admin)) {
        return Ok(status(RES_DISALLOWED, "No access, not author"));
    }
    if let Err(e) = std::fs::remove_file(allowed_path(work_path, doc_id)) {
        tracing::error!(
            "Error while deleting permissions file for {}/{doc_id}: {e}",
            work_path.display()
        );
        return Ok(status(RES_REMOTE_FAIL, "Remote error"));
    }
    if let Err(e) = std::fs::remove_dir_all(&doc_dir) {
        tracing::error!("Error deleting work document: {e}");
        return Ok(status(RES_REMOTE_FAIL, "Remote error"));
    }
    Ok(vec![RES_OK])
}

/// `_work_comment` (`server.py`).
fn work_comment(work_path: &Path, data: &Request, identity: &Identity) -> Result<Vec<u8>, Raised> {
    let scope = data.name("scope", "active");
    let content = py_strip(&data.text("content")?).to_string();
    if !valid_scope(&scope) {
        return Ok(status(RES_INVALID_REQ, "Invalid request"));
    }
    if super::py_len(&content) > WORK_DOC_LIMIT {
        return Ok(status(RES_INVALID_REQ, "Content limit exceeded"));
    }
    let doc_id = match doc_id(data) {
        Ok(id) => id,
        Err(reply) => return Ok(reply),
    };
    if content.is_empty() {
        return Ok(status(RES_INVALID_REQ, "Content is required"));
    }
    let (_, doc_dir) = find_doc(work_path, doc_id, &SCOPES).ok_or(Raised)?;
    if !doc_dir.join("root").is_file() {
        return Ok(status(RES_NOT_FOUND, "Document not found"));
    }
    let comment_id = next_in(&doc_dir);
    let now = now();
    let comment = map(vec![
        ("content", Value::from(content.as_str())),
        (
            "meta",
            map(vec![
                ("format", stored_format(data.get("format"))),
                ("title", Value::Nil),
                ("created", Value::F64(now)),
                ("edited", Value::F64(now)),
                (
                    "signature",
                    data.get("signature").cloned().unwrap_or(Value::Nil),
                ),
                ("author", Value::Binary(identity.hash.to_vec())),
            ]),
        ),
    ]);
    if !save_document(&doc_dir.join(comment_id.to_string()), &comment) {
        return Ok(status(RES_REMOTE_FAIL, "Error saving comment"));
    }
    Ok(ok_with(map(vec![("id", int_value(comment_id))])))
}

/// `shutil.move(src, dst)` for a directory: into `dst` when it is an existing
/// directory, creating missing parents.
fn move_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    let dst = if dst.is_dir() {
        dst.join(src.file_name().unwrap_or_default())
    } else {
        dst.to_path_buf()
    };
    if dst.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "Destination path already exists",
        ));
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(src, &dst)
}

/// `_work_complete` and `_work_activate` (`server.py`).
fn work_move(
    work_path: &Path,
    data: &Request,
    repos: &Repositories,
    hash: &[u8; 16],
    path: Option<(&str, &str)>,
    to: &'static str,
) -> Vec<u8> {
    let doc_id = match doc_id(data) {
        Ok(id) => id,
        Err(reply) => return reply,
    };
    let from: &[&'static str] = if to == "completed" {
        &["active"]
    } else {
        &["completed", "proposed"]
    };
    let Some((_, doc_dir)) = find_doc(work_path, doc_id, from) else {
        return status(RES_NOT_FOUND, "Document not found");
    };
    let Some(doc) = load_document(&doc_dir.join("root")).filter(truthy) else {
        return status(RES_REMOTE_FAIL, "Error loading document");
    };
    if !is_author(&doc, hash) && !resolve_doc_permission(repos, hash, path, doc_id, Perm::Admin) {
        return status(RES_DISALLOWED, "Not allowed");
    }
    if let Err(e) = move_dir(&doc_dir, &work_path.join(to).join(doc_id.to_string())) {
        tracing::error!("Error moving work document: {e}");
        return status(RES_REMOTE_FAIL, "Remote error");
    }
    ok_with(map(vec![
        ("id", int_value(doc_id)),
        ("scope", Value::from(to)),
    ]))
}

/// `_work_perms` and its get/set steps (`server.py`).
fn work_perms(
    work_path: &Path,
    data: &Request,
    repos: &Repositories,
    hash: &[u8; 16],
    path: Option<(&str, &str)>,
) -> Result<Vec<u8>, Raised> {
    let (group, repo) = path.unwrap_or(("", ""));
    let resolve = |perm| path.is_some() && repos.resolve_permission(hash, group, repo, perm);
    let manage = resolve(Perm::Interact) && resolve(Perm::Write);
    if !resolve(Perm::Read) {
        return Ok(status(RES_NOT_FOUND, "Not found"));
    }
    if !manage {
        return Ok(status(RES_DISALLOWED, "Not allowed"));
    }
    let step = data.get("step").filter(|s| truthy(s));
    let set = match step.map(Value::as_str) {
        None => return Ok(status(RES_INVALID_REQ, "Invalid request")),
        Some(Some("get")) => false,
        Some(Some("set")) => true,
        Some(_) => return Ok(status(RES_INVALID_REQ, "Invalid step")),
    };
    // `content` is read before the document checks; `splitlines` raises later.
    let content = data.get("content").cloned();
    let doc_id = match doc_id(data) {
        Ok(id) => id,
        Err(reply) => return Ok(reply),
    };
    let Some((_, doc_dir)) = find_doc(work_path, doc_id, &SCOPES) else {
        return Ok(status(RES_NOT_FOUND, "Document not found"));
    };
    let Some(doc) = load_document(&doc_dir.join("root")).filter(truthy) else {
        return Ok(status(RES_REMOTE_FAIL, "Error loading document"));
    };
    let admin = resolve_doc_permission(repos, hash, path, doc_id, Perm::Admin);
    if !((is_author(&doc, hash) && manage) || admin) {
        return Ok(status(RES_DISALLOWED, "Not allowed"));
    }
    let allowed = allowed_path(work_path, doc_id);
    if !set {
        let text = if allowed.is_file() {
            match read_text(&allowed) {
                Ok(text) => text,
                Err(e) => {
                    tracing::error!("Error getting document permissions: {e}");
                    return Ok(status(RES_REMOTE_FAIL, "Error getting permissions"));
                }
            }
        } else {
            String::new()
        };
        return Ok(ok_with(map(vec![("content", Value::from(text))])));
    }
    let content = match content {
        None => String::new(),
        Some(Value::String(s)) => s.as_str().ok_or(Raised)?.to_string(),
        Some(_) => return Err(Raised),
    };
    if let Some(message) = invalid_line(&content, &repos.aliases) {
        return Ok(status(RES_INVALID_REQ, &message));
    }
    if let Err(e) = write_replacing(&allowed, &content) {
        tracing::error!("Error setting permissions: {e}");
        return Ok(status(RES_REMOTE_FAIL, "Error setting permissions"));
    }
    Ok(vec![RES_OK])
}

/// `handle_work` (`server.py`). `None` sends no response.
pub fn handle_work(
    repos: &RwLock<Repositories>,
    identity: Option<&Identity>,
    data: &Value,
) -> Option<Vec<u8>> {
    let repos = repos.read().unwrap_or_else(|e| e.into_inner());
    let hash = identity.map(|i| i.hash);
    log_request(
        &repos,
        &format!("Work request from remote {}", identity_text(hash.as_ref())),
        hash.as_ref(),
    );
    let Some(identity) = identity else {
        return Some(status(RES_DISALLOWED, "Not identified"));
    };
    let hash = identity.hash;
    let Value::Map(entries) = data else {
        return Some(status(RES_INVALID_REQ, "Invalid request"));
    };
    let Some(repository) = get(entries, &Value::from(IDX_REPOSITORY)) else {
        return Some(status(RES_INVALID_REQ, "No repository specified"));
    };
    let request = Request(entries);
    let Some(operation) = request.get("operation").filter(|v| truthy(v)) else {
        return Some(status(RES_INVALID_REQ, "Invalid request"));
    };
    // `parse_request_repository_path` raises outside any try: no response.
    let path = parse_repository_path(repository.as_str()?);
    let operation = operation.as_str().unwrap_or("");
    let (group, repo) = path.unwrap_or(("", ""));
    let resolve = |perm| path.is_some() && repos.resolve_permission(&hash, group, repo, perm);
    let mut read = resolve(Perm::Read);
    let mut write = resolve(Perm::Write);
    let mut interact = resolve(Perm::Interact);
    let propose = resolve(Perm::Propose);
    let admin = resolve(Perm::Admin);
    if !read {
        return Some(status(RES_NOT_FOUND, "Not found"));
    }
    if let Some(raw_id) = request.get("doc_id").filter(|v| truthy(v))
        && ["read", "view", "comment", "edit", "delete", "perms"].contains(&operation)
    {
        let Ok(doc_id) = py_int(raw_id) else {
            return Some(status(RES_INVALID_REQ, "Invalid request"));
        };
        let doc = |perm| resolve_doc_permission(&repos, &hash, path, doc_id, perm);
        read = doc(Perm::Read) || admin;
        if !read {
            return Some(status(RES_NOT_FOUND, "Document not found"));
        }
        if operation == "comment" || operation == "edit" {
            interact |= doc(Perm::Interact);
        }
        if operation == "edit" {
            write |= doc(Perm::Write);
        }
    }
    let comment_access = interact && (read || write);
    let manage_access = interact && write;
    let access = match operation {
        "list" | "view" => read,
        "comment" => comment_access,
        "propose" => propose,
        "create" | "edit" | "delete" | "complete" | "activate" => manage_access,
        "perms" => admin,
        _ => false,
    };
    if !access {
        return Some(status(RES_DISALLOWED, "Not allowed"));
    }
    let repository = repos.repository(group, repo)?;
    let _serial = WORK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let work_path = PathBuf::from(format!("{}.work", repository.path.display()));
    let reply = match operation {
        "list" => Ok(work_list(&work_path, &request, &repos, &hash, path)),
        "view" => Ok(work_view(&work_path, &request)),
        "comment" => work_comment(&work_path, &request, identity),
        "create" => work_new(&work_path, &request, identity, "active"),
        "propose" => work_new(&work_path, &request, identity, "proposed"),
        "edit" => work_edit(&work_path, &request, identity),
        "delete" => work_delete(&work_path, &request, &repos, &hash, path),
        "complete" => Ok(work_move(
            &work_path,
            &request,
            &repos,
            &hash,
            path,
            "completed",
        )),
        "activate" => Ok(work_move(
            &work_path, &request, &repos, &hash, path, "active",
        )),
        "perms" => work_perms(&work_path, &request, &repos, &hash, path),
        _ => Ok(status(RES_INVALID_REQ, "Invalid request")),
    };
    Some(reply.unwrap_or_else(|Raised| {
        tracing::error!("Error while handling work request for {group}/{repo}");
        status(RES_REMOTE_FAIL, "Remote error")
    }))
}
