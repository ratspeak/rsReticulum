//! `/mgmt/release` and the on-disk release tree (`server.py:3368-3788`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::RwLock;

use rmpv::Value;
use rns_tools::rsg::meta::Obj;

use super::handlers::{Reply, identity_text, log_request};
use super::layout::{Repositories, parse_repository_path};
use super::perms::Perm;
use super::{IDX_REPOSITORY, RES_DISALLOWED, RES_INVALID_REQ, RES_NOT_FOUND, RES_REMOTE_FAIL};

fn status(code: u8, message: &str) -> Vec<u8> {
    let mut reply = vec![code];
    reply.extend_from_slice(message.as_bytes());
    reply
}

/// Python truthiness of an unpacked request value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Nil => false,
        Value::Boolean(b) => *b,
        Value::Integer(i) => i.as_i64() != Some(0) && i.as_u64() != Some(0),
        Value::F32(f) => *f != 0.0,
        Value::F64(f) => *f != 0.0,
        Value::String(s) => !s.as_bytes().is_empty(),
        Value::Binary(b) => !b.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Map(m) => !m.is_empty(),
        Value::Ext(_, d) => !d.is_empty(),
    }
}

/// `data.get(key)` on a request map.
fn get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
}

/// Upstream raised; the caller answers `Remote error` when it is inside a try.
struct Raised;

/// `umsgpack.packb`.
fn pack(value: &Value) -> Result<Vec<u8>, Raised> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Raised)?;
    Ok(out)
}

fn prepend(code: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(code);
    out.extend_from_slice(body);
    out
}

/// Python `"/" in value`: a string tests for the substring, a list or map
/// for an element; anything else raises.
fn contains_slash(value: &Value) -> Result<bool, Raised> {
    let slash = Value::from("/");
    match value {
        Value::String(s) => s.as_str().map(|s| s.contains('/')).ok_or(Raised),
        Value::Array(items) => Ok(items.contains(&slash)),
        Value::Map(entries) => Ok(entries.iter().any(|(k, _)| *k == slash)),
        _ => Err(Raised),
    }
}

/// `os.path.basename(tag)`, which raises for anything but a string.
fn basename_of(value: &Value) -> Result<String, Raised> {
    let text = value.as_str().ok_or(Raised)?;
    Ok(py_basename(text).to_string())
}

/// A tag that names the releases directory or its parent. Upstream refuses
/// these only on create; elsewhere `..` reaches the repository group.
fn is_dot_tag(tag: &str) -> bool {
    matches!(tag, "." | "..")
}

/// `posixpath.basename`: everything after the last `/`, so `"a/"` gives `""`.
pub(crate) fn py_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `os.path.join(base, name)` for one component. A component keeps its own
/// separators and leading slashes do not escape `base`, as in Python.
fn join(base: &Path, name: &str) -> PathBuf {
    if name.starts_with('/') {
        return PathBuf::from(name);
    }
    base.join(name)
}

/// `.strip()` of the `latest` file.
fn read_latest(releases_path: &Path) -> String {
    let path = releases_path.join("latest");
    if !path.is_file() {
        return String::new();
    }
    match std::fs::read(&path) {
        Ok(data) => String::from_utf8_lossy(&data).trim().to_string(),
        Err(e) => {
            tracing::error!(
                "Could not determine latest release for {}: {e}",
                releases_path.display()
            );
            String::new()
        }
    }
}

/// The `RELEASE.md`, `RELEASE.mu` or `RELEASE.txt` of a release directory.
fn notes_file(release_dir: &Path) -> Option<(PathBuf, &'static str)> {
    for (name, format) in [
        ("RELEASE.md", "markdown"),
        ("RELEASE.mu", "micron"),
        ("RELEASE.txt", "text"),
    ] {
        let path = release_dir.join(name);
        if path.is_file() {
            return Some((path, format));
        }
    }
    None
}

/// Python `str.splitlines()`.
pub(crate) fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
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
            lines.push(&text[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' && chars.peek().is_some_and(|&(_, n)| n == '\n') {
                chars.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `open(path, "r", encoding="utf-8").read()`: universal newlines.
fn read_text(path: &Path) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let text = String::from_utf8(data).ok()?;
    Some(text.replace("\r\n", "\n").replace('\r', "\n"))
}

/// `ConfigObj(path)`: an empty config when the file is absent, `Err` when
/// it cannot be parsed. Keys keep their file order, which a rewrite keeps.
fn read_meta(path: &Path) -> Result<Vec<(String, String)>, Raised> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read(path)
        .map_err(|_| Raised)
        .and_then(|data| String::from_utf8(data).map_err(|_| Raised))?;
    let config = rns_runtime::config::Config::parse(&text).map_err(|_| Raised)?;
    let Some(section) = config.section("") else {
        return Ok(Vec::new());
    };
    // The section's own key order is private; recover it from the lines.
    let mut keys: Vec<String> = Vec::new();
    for line in text.lines() {
        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches(|c| c == '"' || c == '\'');
        if section.values.contains_key(key) && !keys.iter().any(|k| k == key) {
            keys.push(key.to_string());
        }
    }
    Ok(keys
        .into_iter()
        .map(|key| {
            let text = match &section.values[&key] {
                rns_runtime::config::ConfigValue::Scalar(text) => text.clone(),
                rns_runtime::config::ConfigValue::List(items) => items.join(", "),
            };
            (key, text)
        })
        .collect())
}

/// `meta.get(key, default)`.
fn meta_get<'a>(meta: &'a [(String, String)], key: &str, default: &'a str) -> &'a str {
    meta.iter()
        .find(|(k, _)| k == key)
        .map_or(default, |(_, v)| v.as_str())
}

/// `meta.as_int("created") if "created" in meta else 0`; a bad value raises.
fn meta_int(meta: &[(String, String)], key: &str) -> Result<i64, Raised> {
    let Some((_, text)) = meta.iter().find(|(k, _)| k == key) else {
        return Ok(0);
    };
    match rns_tools::rsg::meta::py_int(text) {
        Some(Obj::Int(v)) => i64::try_from(v).map_err(|_| Raised),
        Some(Obj::BigInt(_)) => Ok(i64::MAX),
        _ => Err(Raised),
    }
}

/// `ConfigObj._quote` (`configobj.py:1749-1837`) without the triple-quote
/// path, which no release key needs.
fn quote_value(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("\"\"".to_string());
    }
    let wspace = |c: char| matches!(c, ' ' | '\r' | '\n' | '\x0b' | '\t' | '\'' | '"');
    let needs_quotes = value.contains('\n')
        || wspace(value.chars().next().unwrap_or(' '))
        || wspace(value.chars().last().unwrap_or(' '))
        || value.contains(',')
        || value.contains('#')
        || value.contains('\'')
        || value.contains('"');
    if !needs_quotes {
        return Some(value.to_string());
    }
    if value.contains('\n') || (value.contains('\'') && value.contains('"')) {
        return None;
    }
    if value.contains('"') {
        Some(format!("'{value}'"))
    } else {
        Some(format!("\"{value}\""))
    }
}

/// `ConfigObj.write()` of a flat `key = value` file.
fn write_meta(path: &Path, entries: &[(String, String)]) -> Result<(), Raised> {
    let mut text = String::new();
    for (key, value) in entries {
        let Some(value) = quote_value(value) else {
            tracing::error!("Value {value:?} cannot be safely quoted");
            return Err(Raised);
        };
        text.push_str(&format!("{key} = {value}\n"));
    }
    std::fs::write(path, text).map_err(|_| Raised)
}

fn set_meta(meta: &mut Vec<(String, String)>, key: &str, value: &str) {
    match meta.iter_mut().find(|(k, _)| k == key) {
        Some((_, existing)) => *existing = value.to_string(),
        None => meta.push((key.to_string(), value.to_string())),
    }
}

/// `time.time()` as an int.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// `releases_list_data` for the page node: `None` where upstream returns `(None, None)`.
pub(crate) fn list_for_pages(releases_path: &Path) -> Option<(Vec<Value>, Option<String>)> {
    releases_list_data(releases_path).ok()
}

/// `release_data` for the page node: `None` on a missing or unreadable release.
pub(crate) fn data_for_pages(release_dir: &Path, tag: &str) -> Option<Value> {
    release_data(release_dir, tag).ok().flatten()
}

/// One list entry (`server.py:3425-3450`), in insertion order.
fn list_entry(release_dir: &Path, entry: &str) -> Result<Value, Raised> {
    let meta = read_meta(&release_dir.join("META"))?;
    let created = meta_int(&meta, "created")?;
    let mut notes_preview = String::new();
    let mut notes_format = "markdown";
    if let Some((notes_path, format)) = notes_file(release_dir)
        && let Some(notes_full) = read_text(&notes_path)
    {
        for line in splitlines(&notes_full) {
            if !line.starts_with('#') && !line.starts_with('>') {
                notes_preview.push_str(line);
                notes_preview.push('\n');
            }
        }
        notes_preview = notes_preview.trim().to_string();
        notes_format = format;
    }
    let artifacts_dir = release_dir.join("artifacts");
    let artifacts = if artifacts_dir.is_dir() {
        std::fs::read_dir(&artifacts_dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|e| e.path().is_file())
                    .count()
            })
            .unwrap_or(0)
    } else {
        0
    };
    let s = |v: &str| Value::from(v);
    Ok(Value::Map(vec![
        (s("tag"), s(meta_get(&meta, "tag", entry))),
        (s("hash"), s(meta_get(&meta, "hash", ""))),
        (s("created"), Value::from(created)),
        (s("status"), s(meta_get(&meta, "status", "unknown"))),
        (s("created_by"), s(meta_get(&meta, "created_by", ""))),
        (s("preview"), s(&notes_preview)),
        (s("format"), s(notes_format)),
        (s("artifacts"), Value::from(artifacts as i64)),
    ]))
}

/// `releases_list_data` (`server.py:3406-3480`): the entries, newest first,
/// and the published tag the `latest` file names.
fn releases_list_data(releases_path: &Path) -> Result<(Vec<Value>, Option<String>), Raised> {
    if !releases_path.is_dir() {
        return Ok((Vec::new(), None));
    }
    let mut releases = Vec::new();
    let mut published: Vec<(String, bool)> = Vec::new();
    let mut created: Vec<i64> = Vec::new();
    let entries = std::fs::read_dir(releases_path).map_err(|_| Raised)?;
    for entry in entries.filter_map(Result::ok) {
        let release_dir = entry.path();
        if !release_dir.is_dir() || !release_dir.join("META").is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        match list_entry(&release_dir, &name) {
            Ok(info) => {
                let Value::Map(fields) = &info else {
                    unreachable!()
                };
                let field = |key: &str| {
                    fields
                        .iter()
                        .find(|(k, _)| k.as_str() == Some(key))
                        .map(|(_, v)| v.clone())
                        .unwrap_or(Value::Nil)
                };
                published.push((
                    field("tag").as_str().unwrap_or_default().to_string(),
                    field("status").as_str() == Some("published"),
                ));
                created.push(field("created").as_i64().unwrap_or(0));
                releases.push(info);
            }
            Err(_) => {
                tracing::debug!("Error reading release metadata for {name}");
            }
        }
    }
    let latest = read_latest(releases_path);
    let latest_release = published
        .iter()
        .rev()
        .find(|(tag, _)| *tag == latest)
        .filter(|(_, is_published)| *is_published)
        .map(|(tag, _)| tag.clone());
    // `releases.sort(key=created, reverse=True)` keeps the listdir order of
    // equal timestamps; a stable sort on the negative key does the same.
    let mut order: Vec<usize> = (0..releases.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(created[i]));
    let releases = order.into_iter().map(|i| releases[i].clone()).collect();
    Ok((releases, latest_release))
}

/// `release_data` (`server.py:3492-3547`).
fn release_data(release_dir: &Path, tag: &str) -> Result<Option<Value>, Raised> {
    let meta_path = release_dir.join("META");
    if !meta_path.is_file() {
        tracing::error!(
            "Release metadata missing for {}/{tag}",
            release_dir.display()
        );
        return Ok(None);
    }
    let result = (|| -> Result<Value, Raised> {
        let meta = read_meta(&meta_path)?;
        let created = meta_int(&meta, "created")?;
        let mut notes_content = String::new();
        let mut notes_format = "text";
        for (name, format) in [("RELEASE.md", "markdown"), ("RELEASE.mu", "micron")] {
            let notes_path = release_dir.join(name);
            if notes_path.is_file() {
                if let Some(text) = read_text(&notes_path) {
                    notes_content = text;
                    notes_format = format;
                } else {
                    tracing::debug!("Error reading release notes");
                }
                break;
            }
        }
        let mut artifacts = Vec::new();
        let artifacts_dir = release_dir.join("artifacts");
        if artifacts_dir.is_dir()
            && let Ok(entries) = std::fs::read_dir(&artifacts_dir)
        {
            for artifact in entries.filter_map(Result::ok) {
                let path = artifact.path();
                if path.is_file() {
                    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    artifacts.push(Value::Map(vec![
                        (
                            Value::from("name"),
                            Value::from(artifact.file_name().to_string_lossy().as_ref()),
                        ),
                        (Value::from("size"), Value::from(size as i64)),
                    ]));
                }
            }
        }
        let thanks_count = match std::fs::read(release_dir.join("THANKS")) {
            Ok(data) => match rns_tools::rsg::unpackb(&data) {
                Some(Value::Map(entries)) => entries
                    .iter()
                    .find(|(k, _)| k.as_str() == Some("count"))
                    .map_or(Value::from(0), |(_, v)| v.clone()),
                _ => Value::from(0),
            },
            Err(_) => Value::from(0),
        };
        let s = |v: &str| Value::from(v);
        Ok(Value::Map(vec![
            (s("tag"), s(meta_get(&meta, "tag", tag))),
            (s("hash"), s(meta_get(&meta, "hash", ""))),
            (s("created"), Value::from(created)),
            (s("status"), s(meta_get(&meta, "status", "unknown"))),
            (s("created_by"), s(meta_get(&meta, "created_by", ""))),
            (s("notes"), s(&notes_content)),
            (s("notes_format"), s(notes_format)),
            (s("artifacts"), Value::Array(artifacts)),
            (s("thanks"), thanks_count),
        ]))
    })();
    match result {
        Ok(info) => Ok(Some(info)),
        Err(_) => {
            tracing::error!(
                "Error while getting release data for {}/{tag}",
                release_dir.display()
            );
            Ok(None)
        }
    }
}

/// The `tag` checks of `fetch`, which takes the basename after its artifact
/// checks. `Ok(None)` is "Invalid tag specified".
fn lookup_tag_unresolved(data: &[(Value, Value)]) -> Result<Option<Value>, Raised> {
    let tag = get(data, "tag").cloned().unwrap_or_else(|| Value::from(""));
    if contains_slash(&tag)? || !truthy(&tag) || tag.as_str().is_some_and(is_dot_tag) {
        return Ok(None);
    }
    Ok(Some(tag))
}

/// `view`: `"/" in tag` before the empty check, then basename.
/// `Ok(None)` is "Invalid tag specified".
fn lookup_tag(data: &[(Value, Value)]) -> Result<Option<String>, Raised> {
    let tag = get(data, "tag").cloned().unwrap_or_else(|| Value::from(""));
    if contains_slash(&tag)? || !truthy(&tag) {
        return Ok(None);
    }
    Ok(Some(basename_of(&tag)?).filter(|tag| !is_dot_tag(tag)))
}

/// `tag == "latest"` resolution shared by `view` and `fetch`: the reply on
/// failure, or the tag.
fn resolve_latest(releases_path: &Path, tag: &str) -> Result<String, Vec<u8>> {
    if tag != "latest" {
        return Ok(tag.to_string());
    }
    let latest = read_latest(releases_path);
    if latest.is_empty() || is_dot_tag(&latest) {
        Err(status(RES_NOT_FOUND, "No latest release found"))
    } else {
        Ok(latest)
    }
}

fn release_dir_of(releases_path: &Path, tag: &str) -> Result<PathBuf, Vec<u8>> {
    let release_dir = join(releases_path, tag);
    if !release_dir.is_dir() {
        return Err(status(RES_NOT_FOUND, "Release not found"));
    }
    Ok(release_dir)
}

/// `_release_list` (`server.py:3482-3490`).
fn release_list(releases_path: &Path) -> Vec<u8> {
    if !releases_path.is_dir() {
        return prepend(0, &pack(&Value::Array(Vec::new())).unwrap_or_default());
    }
    let Ok((releases, latest)) = releases_list_data(releases_path) else {
        return status(RES_REMOTE_FAIL, "Error listing releases");
    };
    let latest = latest.map_or(Value::Nil, Value::from);
    let data = Value::Map(vec![
        (Value::from("releases"), Value::Array(releases)),
        (Value::from("latest"), latest),
    ]);
    match pack(&data) {
        Ok(body) => prepend(0, &body),
        Err(_) => status(RES_REMOTE_FAIL, "Error listing releases"),
    }
}

/// `_release_view` (`server.py:3549-3575`).
fn release_view(releases_path: &Path, data: &[(Value, Value)]) -> Vec<u8> {
    let tag = match lookup_tag(data) {
        Ok(Some(tag)) => tag,
        Ok(None) => return status(RES_INVALID_REQ, "Invalid tag specified"),
        Err(_) => return status(RES_REMOTE_FAIL, "Remote error"),
    };
    let tag = match resolve_latest(releases_path, &tag) {
        Ok(tag) => tag,
        Err(reply) => return reply,
    };
    let release_dir = match release_dir_of(releases_path, &tag) {
        Ok(dir) => dir,
        Err(reply) => return reply,
    };
    match release_data(&release_dir, &tag) {
        Ok(Some(info)) => match pack(&info) {
            Ok(body) => prepend(0, &body),
            Err(_) => status(RES_REMOTE_FAIL, "Error getting release data"),
        },
        _ => status(RES_REMOTE_FAIL, "Error getting release data"),
    }
}

/// `_release_fetch` (`server.py:3577-3608`).
fn release_fetch(releases_path: &Path, data: &[(Value, Value)]) -> Result<Reply, Raised> {
    let Some(tag) = lookup_tag_unresolved(data)? else {
        return Ok(Reply::Bytes(status(
            RES_INVALID_REQ,
            "Invalid tag specified",
        )));
    };
    let artifact = get(data, "artifact")
        .cloned()
        .unwrap_or_else(|| Value::from(""));
    if contains_slash(&artifact)? || !truthy(&artifact) {
        return Ok(Reply::Bytes(status(
            RES_INVALID_REQ,
            "Invalid artifact specified",
        )));
    }
    let tag = basename_of(&tag)?;
    let artifact = basename_of(&artifact)?;
    let tag = match resolve_latest(releases_path, &tag) {
        Ok(tag) => tag,
        Err(reply) => return Ok(Reply::Bytes(reply)),
    };
    let release_dir = match release_dir_of(releases_path, &tag) {
        Ok(dir) => dir,
        Err(reply) => return Ok(Reply::Bytes(reply)),
    };
    let artifact_path = join(&release_dir.join("artifacts"), &artifact);
    if !artifact_path.is_file() {
        return Ok(Reply::Bytes(status(RES_NOT_FOUND, "Artifact not found")));
    }
    let file = std::fs::File::open(&artifact_path).map_err(|_| Raised)?;
    let metadata = Value::Map(vec![(
        Value::from("name"),
        Value::Binary(artifact.into_bytes()),
    )]);
    Ok(Reply::File {
        file,
        metadata: pack(&metadata)?,
        tmpdir: tempfile::TempDir::new().map_err(|_| Raised)?,
    })
}

/// `not tag` first, then `"/" in tag`, then basename (`finalize`, `delete`,
/// `latest`). Every raise lands in `handle_release`'s try: `Remote error`.
fn checked_tag(data: &[(Value, Value)], missing: &str) -> Result<String, Vec<u8>> {
    let remote_error = |_| status(RES_REMOTE_FAIL, "Remote error");
    let tag = get(data, "tag").cloned().unwrap_or_else(|| Value::from(""));
    if !truthy(&tag) {
        return Err(status(RES_INVALID_REQ, missing));
    }
    if contains_slash(&tag).map_err(remote_error)? {
        return Err(status(RES_INVALID_REQ, "Invalid tag specified"));
    }
    let tag = basename_of(&tag).map_err(remote_error)?;
    if is_dot_tag(&tag) {
        return Err(status(RES_INVALID_REQ, "Invalid tag name"));
    }
    Ok(tag)
}

/// `git rev-parse --verify refs/tags/<tag>` in the repository.
fn tag_exists(repository_path: &Path, tag: &str) -> Result<bool, Raised> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", &format!("refs/tags/{tag}")])
        .current_dir(repository_path)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|_| Raised)?;
    Ok(output.status.success())
}

/// `_release_create_init` (`server.py:3619-3667`).
fn release_create_init(
    releases_path: &Path,
    repository_path: &Path,
    data: &[(Value, Value)],
    identity: &[u8; 16],
) -> Vec<u8> {
    let tag = match checked_tag(data, "Invalid tag specified") {
        Ok(tag) => tag,
        Err(reply) => return reply,
    };
    if tag.is_empty() {
        return status(RES_INVALID_REQ, "Invalid tag name");
    }
    let result = (|| -> Result<Vec<u8>, Raised> {
        if !tag_exists(repository_path, &tag)? {
            return Ok(status(
                RES_INVALID_REQ,
                &format!("Tag '{tag}' does not exist in repository"),
            ));
        }
        if !releases_path.is_dir() {
            create_dir(releases_path)?;
        }
        let release_dir = releases_path.join(&tag);
        if release_dir.is_dir() {
            return Ok(status(RES_DISALLOWED, "Release already exists"));
        }
        create_dir(&release_dir)?;
        create_dir(&release_dir.join("artifacts"))?;

        let mut meta = Vec::new();
        meta.push(("tag".to_string(), tag.clone()));
        if let Some(hash) = get(data, "hash").filter(|h| truthy(h)) {
            meta.push(("hash".to_string(), hash_text(hash)?));
        }
        meta.push(("created".to_string(), now().to_string()));
        meta.push(("status".to_string(), "draft".to_string()));
        meta.push(("created_by".to_string(), hex::encode(identity)));
        write_meta(&release_dir.join("META"), &meta)?;

        let notes = get(data, "notes")
            .cloned()
            .unwrap_or_else(|| Value::from(""));
        if truthy(&notes) {
            let notes_format = get(data, "notes_format").cloned().unwrap_or(Value::Nil);
            let name = if notes_format.as_str() == Some("micron") {
                "RELEASE.mu"
            } else {
                "RELEASE.md"
            };
            let notes_path = release_dir.join(name);
            match &notes {
                Value::String(s) => {
                    let text = s.as_str().ok_or(Raised)?;
                    write_text(&notes_path, text)?;
                }
                _ => {
                    // The file is opened for writing before `f.write` raises.
                    std::fs::File::create(&notes_path).map_err(|_| Raised)?;
                    return Err(Raised);
                }
            }
        }
        write_thanks(&release_dir.join("THANKS"))?;
        tracing::debug!("Created release {tag} in draft status");
        Ok(vec![0])
    })();
    match result {
        Ok(reply) => reply,
        Err(_) => {
            tracing::error!("Error creating release");
            status(RES_REMOTE_FAIL, "Remote error")
        }
    }
}

/// A value as `str()` gives it, which `ConfigObj(stringify=True)` writes.
fn hash_text(value: &Value) -> Result<String, Raised> {
    match value {
        Value::Nil => Err(Raised),
        other => Ok(rns_tools::rsg::pyfmt::py_str(other)),
    }
}

fn create_dir(path: &Path) -> Result<(), Raised> {
    std::fs::create_dir_all(path).map_err(|_| Raised)
}

fn write_text(path: &Path, text: &str) -> Result<(), Raised> {
    std::fs::write(path, text).map_err(|_| Raised)
}

/// `open(thanks_path, "wb").write(mp.packb({"count": 0}))`.
fn write_thanks(path: &Path) -> Result<(), Raised> {
    let value = Value::Map(vec![(Value::from("count"), Value::from(0))]);
    std::fs::write(path, pack(&value)?).map_err(|_| Raised)
}

/// `_release_create_artifact` (`server.py:3669-3704`).
fn release_create_artifact(releases_path: &Path, data: &[(Value, Value)]) -> Vec<u8> {
    let tag = get(data, "tag").cloned().unwrap_or_else(|| Value::from(""));
    let artifact_name = get(data, "artifact_name").cloned().unwrap_or(Value::Nil);
    let artifact_data = get(data, "artifact_data").cloned().unwrap_or(Value::Nil);
    let remote_error = || status(RES_REMOTE_FAIL, "Remote error");
    if !truthy(&tag) || !truthy(&artifact_name) {
        return status(RES_INVALID_REQ, "Missing tag or artifact name");
    }
    match contains_slash(&tag) {
        Ok(true) => return status(RES_INVALID_REQ, "Invalid tag specified"),
        Ok(false) => {}
        Err(_) => return remote_error(),
    }
    if matches!(artifact_data, Value::Nil) {
        return status(RES_INVALID_REQ, "No artifact data");
    }
    let (Ok(tag), Ok(artifact_name)) = (basename_of(&tag), basename_of(&artifact_name)) else {
        return remote_error();
    };
    if is_dot_tag(&tag) {
        return status(RES_INVALID_REQ, "Invalid tag name");
    }
    let result = (|| -> Result<Vec<u8>, Raised> {
        let release_dir = releases_path.join(&tag);
        if !release_dir.is_dir() {
            return Ok(status(RES_NOT_FOUND, "Release not found"));
        }
        let meta = read_meta(&release_dir.join("META"))?;
        if meta_get(&meta, "status", "") != "draft" {
            return Ok(status(
                RES_DISALLOWED,
                "Release was finalized and is not writable",
            ));
        }
        let artifacts_dir = release_dir.join("artifacts");
        let artifact_path = artifacts_dir.join(&artifact_name);
        if !artifacts_dir.is_dir() {
            create_dir(&artifacts_dir)?;
        }
        let mut file = std::fs::File::create(&artifact_path).map_err(|_| Raised)?;
        use std::io::Write;
        match &artifact_data {
            Value::Binary(bytes) => file.write_all(bytes).map_err(|_| Raised)?,
            Value::String(s) => file
                .write_all(s.as_str().ok_or(Raised)?.as_bytes())
                .map_err(|_| Raised)?,
            // The file is created and truncated before `f.write` raises.
            _ => return Err(Raised),
        }
        tracing::debug!("Added artifact {artifact_name} to release {tag}");
        Ok(vec![0])
    })();
    match result {
        Ok(reply) => reply,
        Err(_) => {
            tracing::error!("Error adding artifact");
            status(RES_REMOTE_FAIL, "Remote error")
        }
    }
}

/// `_release_create_finalize` (`server.py:3706-3741`).
fn release_create_finalize(releases_path: &Path, data: &[(Value, Value)]) -> Vec<u8> {
    let tag = match checked_tag(data, "No tag specified") {
        Ok(tag) => tag,
        Err(reply) => return reply,
    };
    let result = (|| -> Result<Vec<u8>, Raised> {
        let release_dir = releases_path.join(&tag);
        if !release_dir.is_dir() {
            return Ok(status(RES_NOT_FOUND, "Release not found"));
        }
        let mut meta = read_meta(&release_dir.join("META"))?;
        if meta_get(&meta, "status", "") != "draft" {
            return Ok(status(
                RES_DISALLOWED,
                "Release was finalized and is not writable",
            ));
        }
        set_meta(&mut meta, "status", "published");
        let published_at = now().to_string();
        set_meta(&mut meta, "published_at", &published_at);
        write_meta(&release_dir.join("META"), &meta)?;
        if write_latest(releases_path, &tag).is_err() {
            tracing::error!(
                "Error setting latest release for {}",
                releases_path.display()
            );
        }
        tracing::debug!("Finalized release {tag} for {}", releases_path.display());
        Ok(vec![0])
    })();
    match result {
        Ok(reply) => reply,
        Err(_) => {
            tracing::error!("Error finalizing release");
            status(RES_REMOTE_FAIL, "Remote error")
        }
    }
}

fn write_latest(releases_path: &Path, tag: &str) -> Result<(), Raised> {
    let latest_path = releases_path.join("latest");
    let tmp_path = PathBuf::from(format!("{}.tmp", latest_path.display()));
    std::fs::write(&tmp_path, tag).map_err(|_| Raised)?;
    std::fs::rename(&tmp_path, &latest_path).map_err(|_| Raised)
}

/// `_release_delete` (`server.py:3743-3761`).
fn release_delete(releases_path: &Path, data: &[(Value, Value)]) -> Vec<u8> {
    let tag = match checked_tag(data, "No tag specified") {
        Ok(tag) => tag,
        Err(reply) => return reply,
    };
    let release_dir = releases_path.join(&tag);
    if !release_dir.is_dir() {
        return status(RES_NOT_FOUND, "Release not found");
    }
    match std::fs::remove_dir_all(&release_dir) {
        Ok(()) => {
            tracing::debug!("Deleted release {tag} from {}", releases_path.display());
            vec![0]
        }
        Err(e) => {
            tracing::error!(
                "Error deleting release from {}: {e}",
                releases_path.display()
            );
            status(RES_REMOTE_FAIL, "Remote error")
        }
    }
}

/// `_release_latest` (`server.py:3763-3788`).
fn release_latest(releases_path: &Path, data: &[(Value, Value)]) -> Vec<u8> {
    let tag = match checked_tag(data, "No tag specified") {
        Ok(tag) => tag,
        Err(reply) => return reply,
    };
    if !releases_path.join(&tag).is_dir() {
        return status(RES_NOT_FOUND, "Release not found");
    }
    match write_latest(releases_path, &tag) {
        Ok(()) => {
            tracing::debug!(
                "Set {tag} as latest release for {}",
                releases_path.display()
            );
            vec![0]
        }
        Err(_) => {
            tracing::error!(
                "Error setting latest release for {}",
                releases_path.display()
            );
            status(RES_REMOTE_FAIL, "Remote error")
        }
    }
}

/// `_release_create` (`server.py:3610-3617`).
fn release_create(
    releases_path: &Path,
    repository_path: &Path,
    data: &[(Value, Value)],
    identity: &[u8; 16],
) -> Vec<u8> {
    let Some(step) = get(data, "step") else {
        return status(RES_INVALID_REQ, "Invalid request");
    };
    match step.as_str() {
        Some("init") => release_create_init(releases_path, repository_path, data, identity),
        Some("artifact") => release_create_artifact(releases_path, data),
        Some("finalize") => release_create_finalize(releases_path, data),
        _ => status(RES_INVALID_REQ, "Invalid request"),
    }
}

/// `handle_release` (`server.py:3368-3404`). `None` when upstream raises
/// before its try (key 0 not a string: no response is sent).
pub fn handle_release(
    repos: &RwLock<Repositories>,
    identity: Option<&[u8; 16]>,
    data: &Value,
) -> Option<Reply> {
    let repos = repos.read().unwrap_or_else(|e| e.into_inner());
    log_request(
        &repos,
        &format!("Release request from remote {}", identity_text(identity)),
        identity,
    );
    let Some(identity) = identity else {
        return Some(Reply::Bytes(status(RES_DISALLOWED, "Not identified")));
    };
    let Value::Map(data) = data else {
        return Some(Reply::Bytes(status(RES_INVALID_REQ, "Invalid request")));
    };
    let Some(repository) = data.iter().find(|(k, _)| *k == Value::from(IDX_REPOSITORY)) else {
        return Some(Reply::Bytes(status(
            RES_INVALID_REQ,
            "No repository specified",
        )));
    };
    let Some(operation) = get(data, "operation").filter(|o| truthy(o)) else {
        return Some(Reply::Bytes(status(RES_INVALID_REQ, "Invalid request")));
    };
    let Some(path) = repository.1.as_str() else {
        // `parse_request_repository_path` raises before the try: no response.
        return None;
    };
    let path = parse_repository_path(path);
    let (group_name, repository_name) = path.unwrap_or(("", ""));
    let read_access = path.is_some()
        && repos.resolve_permission(identity, group_name, repository_name, Perm::Read);
    let release_access = path.is_some()
        && repos.resolve_permission(identity, group_name, repository_name, Perm::Release);
    if !read_access {
        return Some(Reply::Bytes(status(RES_NOT_FOUND, "Not found")));
    }
    let operation = operation.as_str().unwrap_or("");
    let allowed = match operation {
        "create" | "delete" | "latest" => release_access && read_access,
        "list" | "view" | "fetch" => read_access,
        _ => false,
    };
    if !allowed {
        return Some(Reply::Bytes(status(RES_DISALLOWED, "Not allowed")));
    }
    let repository_path = repos
        .repository(group_name, repository_name)
        .expect("resolved")
        .path
        .clone();
    let releases_path = PathBuf::from(format!("{}.releases", repository_path.display()));
    let reply = match operation {
        "list" => release_list(&releases_path),
        "view" => release_view(&releases_path, data),
        "fetch" => match release_fetch(&releases_path, data) {
            Ok(reply) => return Some(reply),
            Err(_) => status(RES_REMOTE_FAIL, "Remote error"),
        },
        "create" => release_create(&releases_path, &repository_path, data, identity),
        "delete" => release_delete(&releases_path, data),
        "latest" => release_latest(&releases_path, data),
        _ => status(RES_INVALID_REQ, "Invalid request"),
    };
    Some(Reply::Bytes(reply))
}
