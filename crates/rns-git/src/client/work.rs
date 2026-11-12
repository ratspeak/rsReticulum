//! `rngit work` (`ReticulumGitClient.work_*` and the editor helpers,
//! `server.py:1347-1923@1.6.0`).

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rmpv::Value;
use rns_identity::identity::Identity;
use rns_runtime::lifecycle::ShutdownSignal;

use super::releases::{Connect, Fail, Remote, Response};
use crate::server::client::{ClientConfig, client_config_dir};
use crate::server::{APP_NAME, IDX_REPOSITORY};

/// `COMMENT_TEMPLATE`, `CREATE_DOC_TEMPLATE` and `PERMISSIONS_TEMPLATE` (`server.py:5086-5088`).
pub const COMMENT_TEMPLATE: &str = "# Remove this line and enter your update. Save and exit when done, or save an empty document to abort abort.";
pub const CREATE_DOC_TEMPLATE: &str = "# Remove this line and enter your document content. Save and exit when done, or save an empty document to abort abort.";
pub const PERMISSIONS_TEMPLATE: &str = "# No permissions are currently defined for this entity. Add them below, and save and exit when you are done.";

/// The `rngit work` operations (`server.py:112-122`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkOp {
    List,
    View,
    Create,
    Propose,
    Edit,
    Delete,
    Update,
    Complete,
    Activate,
    Perms,
}

impl WorkOp {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "list" => WorkOp::List,
            "view" => WorkOp::View,
            "create" => WorkOp::Create,
            "propose" => WorkOp::Propose,
            "edit" => WorkOp::Edit,
            "delete" => WorkOp::Delete,
            "update" => WorkOp::Update,
            "complete" => WorkOp::Complete,
            "activate" => WorkOp::Activate,
            "perms" => WorkOp::Perms,
            _ => return None,
        })
    }
}

/// What `rngit work` was given on the command line.
#[derive(Debug, Clone, Default)]
pub struct WorkArgs {
    pub remote: Option<String>,
    pub scope: String,
    pub doc_id: Option<i64>,
    pub title: Option<String>,
}

fn abort<T>(message: impl Into<String>) -> Result<T, Fail> {
    Err(Fail::Abort(message.into()))
}

fn s(v: &str) -> Value {
    Value::from(v)
}

pub(crate) fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v),
        _ => None,
    }
}

fn py_str(value: &Value) -> String {
    rns_tools::rsg::pyfmt::py_str(value)
}

/// `send_request` and the shared reply checks: the body after a zero status.
pub(crate) fn exchange(
    remote: &mut dyn Remote,
    data: Value,
    timeout: u64,
    prefix: &str,
) -> Result<Vec<u8>, Fail> {
    let Some(response) = remote.request(data, Duration::from_secs(timeout)) else {
        return abort("Request failed or timed out");
    };
    let Response::Bytes(bytes) = response else {
        return abort("No response from remote");
    };
    if bytes.is_empty() {
        return abort("No response from remote");
    }
    if bytes[0] != 0 {
        let text: String = bytes[1..].utf8_chunks().map(|c| c.valid()).collect();
        return abort(format!("{prefix}{text}"));
    }
    Ok(bytes[1..].to_vec())
}

pub(crate) fn unpack(body: &[u8], context: &str) -> Result<Value, Fail> {
    rmpv::decode::read_value(&mut &body[..]).map_err(|e| Fail::Abort(format!("{context}: {e}")))
}

/// Python `str.capitalize()`.
fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first
            .to_uppercase()
            .chain(chars.flat_map(char::to_lowercase))
            .collect(),
        None => String::new(),
    }
}

/// Python `f"{text:<width}"`.
fn pad(text: &str, width: usize) -> String {
    format!(
        "{text}{}",
        " ".repeat(width.saturating_sub(text.chars().count()))
    )
}

fn timestamp(value: Option<&Value>) -> f64 {
    match value {
        Some(Value::F64(f)) => *f,
        Some(Value::F32(f)) => f64::from(*f),
        Some(Value::Integer(i)) => i.as_f64().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// `time.strftime("%Y-%m-%d %H:%M[:%S]", time.localtime(ts))`.
fn strftime(ts: f64, seconds: bool) -> String {
    let time = ts.floor() as nix::libc::time_t;
    let mut tm = std::mem::MaybeUninit::<nix::libc::tm>::zeroed();
    // SAFETY: both pointers are valid for the call; localtime_r is reentrant.
    if unsafe { nix::libc::localtime_r(&time, tm.as_mut_ptr()) }.is_null() {
        return String::new();
    }
    // SAFETY: localtime_r filled `tm` when it returned non-null.
    let tm = unsafe { tm.assume_init() };
    let mut out = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min
    );
    if seconds {
        out.push_str(&format!(":{:02}", tm.tm_sec));
    }
    out
}

/// The editor `_edit_work_content` and `_edit_permissions` run: `$EDITOR`,
/// else the first of nano, vim and vi that `which` finds.
fn find_editor(out: &mut dyn Write) -> Option<String> {
    let editor = std::env::var("EDITOR").unwrap_or_default();
    if !editor.is_empty() {
        return Some(editor);
    }
    let found = ["nano", "vim", "vi"].into_iter().find(|fallback| {
        std::process::Command::new("which")
            .arg(fallback)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    });
    if found.is_none() {
        let _ = writeln!(
            out,
            "No editor found. Please set $EDITOR environment variable."
        );
    }
    found.map(str::to_string)
}

/// Write `template` to a kept temporary file, run `[editor, path]` and read
/// the file back. A file the editor could not be started on is left behind.
fn run_editor(
    out: &mut dyn Write,
    editor: &str,
    template: &str,
    suffix: &str,
) -> Result<Option<String>, String> {
    let file = tempfile::Builder::new()
        .prefix("tmp")
        .suffix(suffix)
        .tempfile()
        .map_err(|e| e.to_string())?;
    let (mut file, path) = file.keep().map_err(|e| e.to_string())?;
    file.write_all(template.as_bytes())
        .map_err(|e| e.to_string())?;
    drop(file);
    let _ = out.flush();
    let status = std::process::Command::new(editor)
        .arg(&path)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        let code = status.code().unwrap_or_else(|| {
            use std::os::unix::process::ExitStatusExt;
            -status.signal().unwrap_or(0)
        });
        let _ = writeln!(out, "Editor exited with error code {code}");
        let _ = std::fs::remove_file(&path);
        return Ok(None);
    }
    let edited = crate::server::work::read_text(&path).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&path);
    Ok(Some(edited))
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// `_edit_work_content` (`server.py:1844-1887`): template lines are dropped,
/// the rest stripped; empty is None.
pub fn edit_work_content(out: &mut dyn Write, content: &str, is_comment: bool) -> Option<String> {
    let editor = find_editor(out)?;
    let template = if !content.is_empty() {
        content
    } else if is_comment {
        COMMENT_TEMPLATE
    } else {
        CREATE_DOC_TEMPLATE
    };
    match run_editor(out, &editor, template, ".md") {
        Ok(edited) => {
            let edited = edited?;
            let lines: Vec<&str> = edited
                .split('\n')
                .filter(|line| {
                    let line = py_strip(line);
                    !(line.starts_with(COMMENT_TEMPLATE) || line.starts_with(CREATE_DOC_TEMPLATE))
                })
                .collect();
            let result = py_strip(&lines.join("\n")).to_string();
            (!result.is_empty()).then_some(result)
        }
        Err(e) => {
            tracing::error!("Error editing work content: {e}");
            None
        }
    }
}

/// `_edit_permissions` (`server.py:1889-1923`): the file as saved, even empty.
pub fn edit_permissions(out: &mut dyn Write, content: &str) -> Option<String> {
    let editor = find_editor(out)?;
    let template = if content.is_empty() {
        PERMISSIONS_TEMPLATE
    } else {
        content
    };
    match run_editor(out, &editor, template, ".txt") {
        Ok(edited) => edited,
        Err(e) => {
            tracing::error!("Error editing permissions: {e}");
            None
        }
    }
}

fn request(repo_path: &str, fields: Vec<(&str, Value)>) -> Value {
    let mut map = vec![(Value::from(IDX_REPOSITORY), s(repo_path))];
    map.extend(fields.into_iter().map(|(k, v)| (s(k), v)));
    Value::Map(map)
}

const CLEAR: &str = "\r                       \r";

/// `work_list` after the Link is up (`server.py:1359-1402`).
fn work_list(
    out: &mut dyn Write,
    remote: &mut dyn Remote,
    repo_path: &str,
    scope: &str,
) -> Result<(), Fail> {
    let data = request(
        repo_path,
        vec![("operation", s("list")), ("scope", s(scope))],
    );
    let sent = exchange(remote, data, 120, "Remote error: ");
    let _ = write!(out, "{CLEAR}");
    let body = sent?;
    let result = if body.is_empty() {
        Value::Map(vec![
            (s("active"), Value::Array(vec![])),
            (s("completed"), Value::Array(vec![])),
        ])
    } else {
        unpack(&body, "Error listing work documents")?
    };
    let docs_of = |name: &str| -> Vec<Value> {
        match field(&result, name) {
            Some(Value::Array(items)) => items.clone(),
            _ => Vec::new(),
        }
    };
    let shown: Vec<&str> = if scope == "all" {
        vec!["active", "completed", "proposed"]
    } else {
        vec![scope]
    };
    for name in shown {
        let docs = docs_of(name);
        if docs.is_empty() {
            if scope != "all" {
                let _ = writeln!(out, "No {name} work documents found.");
            }
            continue;
        }
        let header = format!("\n{} documents", capitalize(name));
        let _ = writeln!(out, "{header}");
        let _ = writeln!(out, "{}\n", "=".repeat(header.chars().count()));
        let _ = writeln!(
            out,
            "{} {} {} {} Comments",
            pad("ID", 4),
            pad("Title", 30),
            pad("Author", 17),
            pad("Created", 18)
        );
        let _ = writeln!(out, "{}", "-".repeat(80));
        for doc in &docs {
            let id = field(doc, "id").map_or("?".to_string(), py_str);
            let mut title = field(doc, "title").map_or("Untitled".to_string(), py_str);
            if title.chars().count() > 29 {
                title = format!("{}…", title.chars().take(29).collect::<String>());
            }
            let author: String = field(doc, "author")
                .map(py_str)
                .unwrap_or_default()
                .chars()
                .take(16)
                .collect();
            let created_ts = timestamp(field(doc, "created"));
            let created = if created_ts != 0.0 {
                strftime(created_ts, false)
            } else {
                "unknown".into()
            };
            let comments = field(doc, "comments").map_or("0".to_string(), py_str);
            let _ = writeln!(
                out,
                "{} {} {} {} {comments}",
                pad(&id, 4),
                pad(&title, 30),
                pad(&format!("{author}…"), 17),
                pad(&created, 18)
            );
        }
        let _ = writeln!(out);
    }
    if scope == "all"
        && ["active", "completed", "proposed"]
            .iter()
            .all(|n| docs_of(n).is_empty())
    {
        let _ = writeln!(out, "No work documents found.");
    }
    Ok(())
}

/// `work_view` after the Link is up (`server.py:1416-1477`).
fn work_view(
    out: &mut dyn Write,
    remote: &mut dyn Remote,
    repo_path: &str,
    doc_id: i64,
    scope: &str,
) -> Result<(), Fail> {
    let data = request(
        repo_path,
        vec![
            ("operation", s("view")),
            ("doc_id", Value::from(doc_id)),
            ("scope", s(scope)),
        ],
    );
    let sent = exchange(remote, data, 120, "Remote error: ");
    let _ = write!(out, "{CLEAR}");
    let body = sent?;
    if body.is_empty() {
        return abort("Empty response from remote");
    }
    let doc = unpack(&body, "Error viewing work document")?;
    let missing = |key: &str| Fail::Abort(format!("Error viewing work document: '{key}'"));
    let meta = field(&doc, "meta").ok_or_else(|| missing("meta"))?;
    let meta_field = |key: &str| field(meta, key).ok_or_else(|| missing(key));
    let content = field(&doc, "content").map(py_str).unwrap_or_default();
    let mut author = format!("{} (not locally validated)", py_str(meta_field("author")?));
    let mut signature_text = "Document not signed";
    if let (Some(Value::Binary(sig)), Some(Value::Binary(key))) =
        (field(meta, "signature"), field(meta, "identity"))
        && sig.len() == 64
        && key.len() == 64
    {
        signature_text = "Not valid";
        if let (Ok(identity), Ok(sig)) = (
            Identity::from_public_key(key),
            <[u8; 64]>::try_from(sig.as_slice()),
        ) && identity.verify(content.as_bytes(), &sig)
        {
            signature_text = "Valid";
            author = format!("<{}>", hex::encode(identity.hash));
        }
    }
    let heading = format!(
        "{} (#{})",
        py_str(meta_field("title")?),
        py_str(field(&doc, "id").ok_or_else(|| missing("id"))?)
    );
    let comments = match field(&doc, "comments") {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    let _ = writeln!(out, "{heading}");
    let _ = writeln!(out, "{}", "=".repeat(heading.chars().count()));
    let _ = writeln!(out, "Author    : {author}");
    let _ = writeln!(out, "Signature : {signature_text}");
    let _ = writeln!(out, "Status    : {}", capitalize(scope));
    let _ = writeln!(
        out,
        "Created   : {}",
        strftime(timestamp(Some(meta_field("created")?)), true)
    );
    let _ = writeln!(
        out,
        "Edited    : {}",
        strftime(timestamp(Some(meta_field("edited")?)), true)
    );
    let _ = writeln!(out, "Format    : {}", py_str(meta_field("format")?));
    let _ = writeln!(out, "Updates   : {}", comments.len());
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{}",
        py_str(field(&doc, "content").ok_or_else(|| missing("content"))?)
    );
    if !comments.is_empty() {
        let _ = writeln!(out, "\nUpdates\n=======");
        for c in &comments {
            let get = |key: &str| field(c, key).ok_or_else(|| missing(key));
            let line = format!(
                "#{} by {} at {}",
                py_str(get("id")?),
                py_str(get("author")?),
                strftime(timestamp(Some(get("created")?)), true)
            );
            let _ = writeln!(out, "\n{line}");
            let _ = writeln!(out, "{}", "-".repeat(line.chars().count()));
            let _ = writeln!(out, "{}", py_str(get("content")?));
        }
    }
    let _ = writeln!(out);
    Ok(())
}

fn sign(identity: &Identity, content: &str) -> Result<Value, Fail> {
    match identity.sign(content.as_bytes()) {
        Some(sig) => Ok(Value::Binary(sig.to_vec())),
        None => abort("Could not sign work document"),
    }
}

fn result_field(body: &[u8], key: &str, context: &str) -> Result<String, Fail> {
    let value = unpack(body, context)?;
    field(&value, key)
        .map(py_str)
        .ok_or_else(|| Fail::Abort(format!("{context}: '{key}'")))
}

/// `work_create` and `work_propose` after the Link is up (`server.py:1491-1567`).
fn work_new(
    out: &mut dyn Write,
    remote: &mut dyn Remote,
    identity: &Identity,
    repo_path: &str,
    title: &str,
    propose: bool,
) -> Result<(), Fail> {
    let Some(content) = edit_work_content(out, "", false) else {
        let _ = writeln!(
            out,
            "{}",
            if propose {
                "Proposal cancelled"
            } else {
                "Creation cancelled"
            }
        );
        return Ok(());
    };
    let signature = sign(identity, &content)?;
    let operation = if propose { "propose" } else { "create" };
    let data = request(
        repo_path,
        vec![
            ("operation", s(operation)),
            ("title", s(title)),
            ("content", s(&content)),
            ("format", s("markdown")),
            ("signature", signature),
        ],
    );
    let body = exchange(remote, data, 600, "Server error: ")?;
    if body.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            if propose {
                "Work document proposed"
            } else {
                "Work document created"
            }
        );
    } else {
        let context = "Error creating work document";
        let scope = result_field(&body, "scope", context)?;
        let id = result_field(&body, "id", context)?;
        let _ = writeln!(out, "Work document created as {scope} #{id}");
    }
    Ok(())
}

/// `work_edit` after the Link is up (`server.py:1581-1621`).
fn work_edit(
    out: &mut dyn Write,
    remote: &mut dyn Remote,
    identity: &Identity,
    repo_path: &str,
    args: &WorkArgs,
    doc_id: i64,
) -> Result<(), Fail> {
    let scope = args.scope.as_str();
    let view = request(
        repo_path,
        vec![
            ("operation", s("view")),
            ("doc_id", Value::from(doc_id)),
            ("scope", s(scope)),
        ],
    );
    let body = exchange(remote, view, 600, "Remote error: ")?;
    let doc = unpack(&body, "Error editing work document")?;
    let missing = |key: &str| Fail::Abort(format!("Error editing work document: '{key}'"));
    let current_content = py_str(field(&doc, "content").ok_or_else(|| missing("content"))?);
    let meta = field(&doc, "meta").ok_or_else(|| missing("meta"))?;
    let current_title = field(meta, "title")
        .ok_or_else(|| missing("title"))?
        .clone();
    let Some(content) = edit_work_content(out, &current_content, false) else {
        let _ = writeln!(out, "Edit cancelled");
        return Ok(());
    };
    let signature = sign(identity, &content)?;
    let title = match args.title.as_deref().filter(|t| !t.is_empty()) {
        Some(title) => s(title),
        None => current_title,
    };
    let data = request(
        repo_path,
        vec![
            ("operation", s("edit")),
            ("doc_id", Value::from(doc_id)),
            ("scope", s(scope)),
            ("content", s(&content)),
            ("title", title),
            ("signature", signature),
        ],
    );
    exchange(remote, data, 600, "Remote error: ")?;
    let _ = writeln!(out, "Work document {scope} #{doc_id} updated");
    Ok(())
}

/// `work_delete` after the Link is up (`server.py:1635-1661`).
fn work_delete(
    out: &mut dyn Write,
    input: &mut dyn BufRead,
    remote: &mut dyn Remote,
    repo_path: &str,
    doc_id: i64,
    scope: &str,
) -> Result<(), Fail> {
    let _ = write!(
        out,
        "Are you sure you want to delete {scope} work document #{doc_id}? [y/N]: "
    );
    let _ = out.flush();
    let mut line = String::new();
    let confirm = match input.read_line(&mut line) {
        Ok(0) | Err(_) => "n".to_string(),
        Ok(_) => py_strip(line.trim_end_matches('\n')).to_lowercase(),
    };
    if confirm != "y" {
        let _ = writeln!(out, "Deletion cancelled");
        return Ok(());
    }
    let data = request(
        repo_path,
        vec![
            ("operation", s("delete")),
            ("doc_id", Value::from(doc_id)),
            ("scope", s(scope)),
        ],
    );
    exchange(remote, data, 120, "Remote error: ")?;
    let _ = writeln!(out, "Work document {scope} #{doc_id} deleted");
    Ok(())
}

/// `work_comment` after the Link is up (`server.py:1675-1704`).
fn work_comment(
    out: &mut dyn Write,
    remote: &mut dyn Remote,
    repo_path: &str,
    doc_id: i64,
    scope: &str,
) -> Result<(), Fail> {
    let Some(content) = edit_work_content(out, "", true) else {
        let _ = writeln!(out, "Update cancelled");
        return Ok(());
    };
    let data = request(
        repo_path,
        vec![
            ("operation", s("comment")),
            ("doc_id", Value::from(doc_id)),
            ("scope", s(scope)),
            ("content", s(&content)),
            ("format", s("markdown")),
        ],
    );
    let body = exchange(remote, data, 600, "Remote error: ")?;
    if body.is_empty() {
        let _ = writeln!(out, "Update added");
    } else {
        let id = result_field(&body, "id", "Error adding comment")?;
        let _ = writeln!(out, "Update #{id} added to {scope} document #{doc_id}");
    }
    Ok(())
}

/// `work_complete` and `work_activate` after the Link is up (`server.py:1718-1782`).
fn work_move(
    out: &mut dyn Write,
    remote: &mut dyn Remote,
    repo_path: &str,
    doc_id: i64,
    activate: bool,
) -> Result<(), Fail> {
    let (operation, done, context) = if activate {
        ("activate", "activated", "Error activating work document")
    } else {
        ("complete", "completed", "Error completing work document")
    };
    let data = request(
        repo_path,
        vec![("operation", s(operation)), ("doc_id", Value::from(doc_id))],
    );
    let body = exchange(remote, data, 120, "Remote error: ")?;
    if body.is_empty() {
        let _ = writeln!(out, "Work document {done}");
    } else {
        let id = result_field(&body, "id", context)?;
        let _ = writeln!(out, "Work document #{id} {done}");
    }
    Ok(())
}

/// The get, edit and set round of every permissions command
/// (`server.py:1255-1287`, `1796-1834`).
pub(crate) fn edit_remote_permissions(
    out: &mut dyn Write,
    remote: &mut dyn Remote,
    get: Value,
    set: impl FnOnce(String) -> Value,
) -> Result<bool, Fail> {
    let body = exchange(remote, get, 120, "Remote error: ")?;
    let current = if body.is_empty() {
        String::new()
    } else {
        let result = unpack(&body, "Error editing permissions")?;
        field(&result, "content").map(py_str).unwrap_or_default()
    };
    let Some(content) = edit_permissions(out, &current) else {
        let _ = writeln!(out, "Edit cancelled");
        return Ok(false);
    };
    exchange(remote, set(content), 120, "Remote error: ")?;
    Ok(true)
}

/// `rngit work <repository> <operation>` once Reticulum is up
/// (`server.py:106-122`, `1347-1838`). `Ok` is the exit code.
pub fn run_work(
    out: &mut dyn Write,
    input: &mut dyn BufRead,
    config: &ClientConfig,
    connect: &mut Connect<'_>,
    identity: &Identity,
    operation: Option<&str>,
    args: &WorkArgs,
) -> Result<i32, Fail> {
    let Some(op) = operation.and_then(WorkOp::parse) else {
        let _ = writeln!(out, "Invalid operation");
        return Ok(1);
    };
    let Some(remote) = args.remote.as_deref().filter(|r| !r.is_empty()) else {
        return abort("No remote specified");
    };
    let needs_id = !matches!(op, WorkOp::List | WorkOp::Create | WorkOp::Propose);
    if needs_id && args.doc_id.is_none() {
        return abort("No document ID specified");
    }
    let title = args.title.as_deref().filter(|t| !t.is_empty());
    if matches!(op, WorkOp::Create | WorkOp::Propose) && title.is_none() {
        return abort("No title specified");
    }
    let failed = if matches!(op, WorkOp::List | WorkOp::View) {
        "Link establishment failed"
    } else {
        "Failed to establish link"
    };
    let mut link = connect(remote, failed)?;
    if !matches!(op, WorkOp::List | WorkOp::View) {
        let _ = write!(out, "{CLEAR}");
    }
    let (_, group, repo) = config.parse_remote_url(remote).map_err(Fail::Abort)?;
    let repo_path = format!("{group}/{repo}");
    let remote = link.as_mut();
    let doc_id = args.doc_id.unwrap_or_default();
    let scope = args.scope.as_str();
    match op {
        WorkOp::List => work_list(out, remote, &repo_path, scope)?,
        WorkOp::View => work_view(out, remote, &repo_path, doc_id, scope)?,
        WorkOp::Create => work_new(
            out,
            remote,
            identity,
            &repo_path,
            title.unwrap_or_default(),
            false,
        )?,
        WorkOp::Propose => work_new(
            out,
            remote,
            identity,
            &repo_path,
            title.unwrap_or_default(),
            true,
        )?,
        WorkOp::Edit => work_edit(out, remote, identity, &repo_path, args, doc_id)?,
        WorkOp::Delete => work_delete(out, input, remote, &repo_path, doc_id, scope)?,
        WorkOp::Update => work_comment(out, remote, &repo_path, doc_id, scope)?,
        WorkOp::Complete => work_move(out, remote, &repo_path, doc_id, false)?,
        WorkOp::Activate => work_move(out, remote, &repo_path, doc_id, true)?,
        WorkOp::Perms => {
            let get = request(
                &repo_path,
                vec![
                    ("operation", s("perms")),
                    ("doc_id", Value::from(doc_id)),
                    ("step", s("get")),
                ],
            );
            let set = |content: String| {
                request(
                    &repo_path,
                    vec![
                        ("operation", s("perms")),
                        ("doc_id", Value::from(doc_id)),
                        ("step", s("set")),
                        ("content", s(&content)),
                    ],
                )
            };
            if edit_remote_permissions(out, remote, get, set)? {
                let _ = writeln!(out, "Permissions updated for work document #{doc_id}");
            }
        }
    }
    Ok(0)
}

/// Requests over an established Link; the Link closes when this is dropped,
/// as upstream's `finally: link.teardown()`.
struct SessionRemote {
    runtime: tokio::runtime::Handle,
    session: rns_runtime::link_session::LinkSessionHandle,
    path: &'static str,
}

impl Remote for SessionRemote {
    fn request(&mut self, data: Value, timeout: Duration) -> Option<Response> {
        let options = rns_runtime::link_session::RequestOptions {
            timeout: Some(timeout),
            ..Default::default()
        };
        let request = self.session.request_with_options(self.path, data, options);
        let response = self
            .runtime
            .block_on(async {
                tokio::time::timeout(timeout + Duration::from_secs(30), request).await
            })
            .ok()?
            .ok()?;
        Some(match response.value {
            Value::Binary(bytes) => Response::Bytes(bytes),
            other => Response::Other(other),
        })
    }
}

impl Drop for SessionRemote {
    fn drop(&mut self) {
        self.runtime.block_on(self.session.close());
    }
}

/// The options every `rngit` client subcommand shares.
#[derive(Debug, Clone, Default)]
pub struct CommonArgs {
    pub config: Option<String>,
    pub rnsconfig: Option<String>,
    pub identity: Option<String>,
    pub verbose: u8,
    pub quiet: u8,
}

/// The body of a client subcommand, run on the blocking pool once Reticulum,
/// the identity and the client config are ready.
pub type ClientBody = Box<
    dyn FnOnce(
            &mut dyn Write,
            &mut dyn BufRead,
            &ClientConfig,
            &mut Connect<'_>,
            &Identity,
        ) -> Result<i32, Fail>
        + Send,
>;

/// `program_setup` and `ReticulumGitClient.__init__` for a client task, then
/// `body` with a `connect_remote` whose requests go to `path`; never returns.
pub async fn run_client(common: CommonArgs, path: &'static str, body: ClientBody) -> ! {
    let non_empty = |v: Option<String>| v.filter(|v| !v.is_empty());
    let configdir = client_config_dir(non_empty(common.config).map(PathBuf::from).as_deref());
    let rnsconfig = non_empty(common.rnsconfig);
    let rns_dir = rns_runtime::platform::resolve_config_dir(rnsconfig.as_deref());
    let configured = rns_runtime::config::Config::from_file(&rns_dir.join("config"))
        .ok()
        .and_then(|c| c.section("logging")?.get_int("loglevel"));
    let level = rns_tools::Utility::Rnir.loglevel(configured, common.verbose, common.quiet, false);
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&rns_dir),
        true,
        std::io::stdout,
    );
    let handle = match rns_runtime::reticulum::init(
        rnsconfig.as_deref(),
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
    )
    .await
    {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("failed to start reticulum: {e}");
            std::process::exit(1);
        }
    };
    handle.wants_destination_type(APP_NAME).await;
    if let Err(e) = std::fs::create_dir_all(&configdir) {
        println!("Could not create {}: {e}", configdir.display());
        rns_tools::exit(&handle, 1).await;
    }
    let identity_path = non_empty(common.identity)
        .map(PathBuf::from)
        .unwrap_or_else(|| configdir.join("client_identity"));
    let identity = if identity_path.is_file() {
        Identity::from_file(&identity_path).ok()
    } else {
        let id = Identity::new();
        id.to_file(&identity_path).ok().map(|_| id)
    };
    let Some(identity) = identity else {
        println!("Could not initialize client identity");
        rns_tools::exit(&handle, 1).await;
    };
    let config = match ClientConfig::load_or_create(&configdir) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!(
                "Could not parse the configuration at {}",
                configdir.join("client_config").display()
            );
            tracing::error!("Check your configuration file for errors! ({e})");
            rns_tools::exit(&handle, 255).await;
        }
    };
    let runtime = tokio::runtime::Handle::current();
    let link_handle = handle.clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut out = std::io::stdout();
        let mut input = std::io::stdin().lock();
        let link_identity = identity.clone();
        let mut connect = |remote: &str, failure: &str| -> Result<Box<dyn Remote>, Fail> {
            let destination = config
                .parse_remote_destination_url(remote)
                .map_err(Fail::Abort)?;
            let Ok(destination) = <[u8; 16]>::try_from(destination.as_slice()) else {
                return abort("Invalid destination hash length");
            };
            let path_timeout = runtime
                .block_on(rns_tools::medium_path_timeout(&link_handle))
                .max(15.0);
            print!("Requesting path... ");
            let _ = std::io::stdout().flush();
            if runtime
                .block_on(
                    link_handle.await_path(destination, Duration::from_secs_f64(path_timeout)),
                )
                .is_err()
            {
                println!();
                return abort(format!(
                    "Could not resolve path to <{}>",
                    hex::encode(destination)
                ));
            }
            print!("\rPath resolved      ");
            print!("\rEstablishing link... ");
            let _ = std::io::stdout().flush();
            let hops = runtime
                .block_on(link_handle.hops_to(destination))
                .unwrap_or(1);
            let first_hop = runtime
                .block_on(link_handle.first_hop_timeout(destination))
                .map_or(rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT, |d| {
                    d.as_secs_f64()
                });
            let establishment =
                first_hop + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT * f64::from(hops.max(1));
            let options = rns_runtime::reticulum::LinkConnectOptions {
                path_timeout: Duration::from_secs_f64(path_timeout),
                establishment_timeout: Some(Duration::from_secs_f64(establishment.max(15.0))),
                client_label: "rngit".to_string(),
                identify: true,
                ..Default::default()
            };
            let session = runtime
                .block_on(link_handle.connect_link(destination, link_identity.clone(), options))
                .map_err(|_| Fail::Abort(failure.to_string()))?;
            print!("\rLink established     ");
            let _ = std::io::stdout().flush();
            Ok(Box::new(SessionRemote {
                runtime: runtime.clone(),
                session: session.handle,
                path,
            }))
        };
        let result = body(&mut out, &mut input, &config, &mut connect, &identity);
        let _ = out.flush();
        result
    })
    .await
    .unwrap_or_else(|e| Err(Fail::Raised(format!("client task failed: {e}"))));
    match result {
        Ok(code) => rns_tools::exit(&handle, code).await,
        Err(Fail::Abort(message)) => {
            println!("{message}");
            rns_tools::exit(&handle, 1).await
        }
        Err(Fail::Raised(message)) => {
            eprintln!("{message}");
            rns_tools::exit(&handle, 1).await
        }
    }
}
