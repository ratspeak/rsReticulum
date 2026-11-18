//! The Nomad Network page node (`RNS/Utilities/rngit/pages.py`).

mod chart;
mod files;
pub mod git;
mod views;

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use rmpv::Value;

use crate::highlight::SyntaxHighlighter;
use crate::md2micron::MarkdownToMicron;
use crate::server::layout::Repositories;
use crate::server::perms::Perm;
use crate::server::stats::Stats;

pub use chart::{render_chart, render_combined_chart};

/// `NomadNetworkNode.APP_NAME` plus the aspect.
pub const APP_NAME: &str = "nomadnetwork.node";
/// `JOBS_INTERVAL`, seconds.
pub const JOBS_INTERVAL: u64 = 5;
/// What the pages render as `{VERSION}`: this crate's version, as `rngit-rs --version` prints it.
/// Differs from `pages.py`, which renders `RNS._version.__version__`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const PATH_INDEX: &str = "/page/index.mu";
pub const PATH_GROUP: &str = "/page/group.mu";
pub const PATH_REPO: &str = "/page/repo.mu";
pub const PATH_TREE: &str = "/page/tree.mu";
pub const PATH_BLOB: &str = "/page/blob.mu";
pub const PATH_COMMITS: &str = "/page/commits.mu";
pub const PATH_COMMIT: &str = "/page/commit.mu";
pub const PATH_REFS: &str = "/page/refs.mu";
pub const PATH_STATS: &str = "/page/stats.mu";
pub const PATH_RELEASES: &str = "/page/releases.mu";
pub const PATH_RELEASE: &str = "/page/release.mu";
pub const PATH_WORK: &str = "/page/work.mu";
pub const PATH_WORK_DOC: &str = "/page/work_doc.mu";
pub const PATH_MEDIA: &str = "/media";
pub const FILE_ARTIFACT: &str = "/file/artifact";
pub const FILE_DOWNLOAD: &str = "/file/download";
pub const FILE_WORKDOC: &str = "/file/workdoc";

/// Every request path the node registers, in upstream's order.
pub const PATHS: [&str; 17] = [
    PATH_INDEX,
    PATH_GROUP,
    PATH_REPO,
    PATH_TREE,
    PATH_BLOB,
    PATH_COMMITS,
    PATH_COMMIT,
    PATH_REFS,
    PATH_STATS,
    PATH_RELEASES,
    PATH_RELEASE,
    PATH_WORK,
    PATH_WORK_DOC,
    PATH_MEDIA,
    FILE_ARTIFACT,
    FILE_DOWNLOAD,
    FILE_WORKDOC,
];

pub(crate) const BLOB_SIZE_LIMIT: u64 = 256 * 1024;
/// Largest file `/file/download` converts to Micron in memory.
pub(crate) const CONVERT_SIZE_LIMIT: u64 = 4 * 1024 * 1024;
pub(crate) const TREE_ENTRIES_PER_PAGE: usize = 1000;
pub(crate) const COMMITS_PER_PAGE: usize = 100;
pub(crate) const MAX_RENDER_WIDTH: usize = 100;
pub(crate) const TAB_WIDTH: &str = "   ";

pub(crate) const CLR_FOLDER: &str = "`Ffe6";
pub(crate) const CLR_FILE: &str = "`F66d";
pub(crate) const CLR_DIM: &str = "`F666";
pub(crate) const CLR_DIM_H: &str = "`F444";
pub(crate) const CLR_OK_DIM: &str = "`FT537855";
pub(crate) const CLR_DIFF_A: &str = "`F0a0";
pub(crate) const CLR_DIFF_R: &str = "`F900";
pub(crate) const CLR_DIFF_P: &str = "`F0aa";

pub(crate) const RCLR_PUSH: &str = "B9A810";
pub(crate) const RCLR_PUSH_G: &str = "791212";
pub(crate) const RCLR_FETCH: &str = "10b981";
pub(crate) const RCLR_FETCH_G: &str = "1c5e71";
pub(crate) const RCLR_VIEW: &str = "3b82f6";
pub(crate) const RCLR_VIEW_G: &str = "13428A";
pub(crate) const RCLR_DOWNLOAD: &str = "7831E0";
pub(crate) const RCLR_DOWNLOAD_G: &str = "c5754d";

pub(crate) const CONVERTABLE_EXTS: [&str; 1] = [".md"];
pub(crate) const RENDERABLE_EXTS: [&str; 2] = [".md", ".mu"];
pub(crate) const RENDER_DEFAULT: [&str; 2] = [".md", ".mu"];
pub(crate) const IMAGE_EXTS: [&str; 8] = [
    ".webp", ".png", ".jpg", ".jpeg", ".gif", ".tiff", ".tif", ".bmp",
];

// Names `rngit-rs`, where `DEFAULT_BASE_TEMPLATE` (`pages.py`) names `rngit`.
const DEFAULT_BASE_TEMPLATE: &str = "#!c=0\n> {NODE_NAME}\n\n{NAVIGATION}\n{PAGE_CONTENT}\n<\n-\n`a`F666`[Served by rngit-rs {VERSION}`:/page/index.mu] - {GEN_TIME}`f";
const DEFAULT_FRONT_TEMPLATE: &str = "> Groups\n\n{PAGE_CONTENT}";
const DEFAULT_NO_IDENT_TEMPLATE: &str =
    ">>No Identity\n\nThis page requires identification, and none was received.\n";
/// Templates whose default is the page content alone.
const PLAIN_TEMPLATES: [&str; 12] = [
    "group", "repo", "releases", "release", "tree", "blob", "commits", "commit", "refs", "stats",
    "work", "work_doc",
];

/// The `[pages]` keys `NomadNetworkNode.__init__` reads (`pages.py`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PageOptions {
    pub use_nerdfonts: bool,
    pub media_conversion: bool,
    /// Quantized; applied to the node destination only when above 0.
    pub stamp_value: Option<f64>,
    /// Quantized announced link request cost.
    pub link_cost: f64,
}

impl Default for PageOptions {
    fn default() -> Self {
        Self {
            use_nerdfonts: true,
            media_conversion: true,
            stamp_value: None,
            link_cost: crate::server::config::DEFAULT_LINK_COST,
        }
    }
}

impl PageOptions {
    /// Read the `[pages]` keys from the node config text; a value `as_bool`
    /// or `as_float` rejects is an error, as upstream raises.
    pub fn from_config_text(text: &str) -> Result<Self, rns_runtime::config::ConfigError> {
        let mut options = Self::default();
        let config = rns_runtime::config::Config::parse(text)?;
        let Some(section) = config.section("pages") else {
            return Ok(options);
        };
        let as_bool = |key: &str| {
            section
                .get_bool(key)
                .ok_or_else(|| rns_runtime::config::ConfigError::InvalidValue {
                    section: "pages".to_string(),
                    key: key.to_string(),
                    message: "not a boolean".to_string(),
                })
        };
        if section.has("unicode_icons") && as_bool("unicode_icons")? {
            options.use_nerdfonts = false;
        }
        if section.has("media_conversion") {
            options.media_conversion = as_bool("media_conversion")?;
        }
        if section.has("link_cost") {
            options.link_cost = crate::server::config::as_cost(section, "pages", "link_cost")?;
        }
        if section.has("stamp_value") {
            options.stamp_value = Some(crate::server::config::as_cost(
                section,
                "pages",
                "stamp_value",
            )?);
        }
        Ok(options)
    }
}

/// What a page handler answers, as upstream's handler return values.
pub enum PageReply {
    /// Rendered Micron bytes.
    Page(Vec<u8>),
    /// One packed MessagePack value: `False` or the work-document list.
    Value(Vec<u8>),
    /// A file response with its `{"name": bytes}` metadata.
    File { file: std::fs::File, name: String },
    /// `None`, or an exception in the handler thread: nothing is sent.
    Drop,
}

/// The packed `{"name": name.encode("utf-8")}` metadata of a file response.
pub fn file_metadata(name: &str) -> Vec<u8> {
    let value = Value::Map(vec![(
        Value::from("name"),
        Value::Binary(name.as_bytes().to_vec()),
    )]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).expect("writing to a Vec");
    out
}

/// Identity hash of the source repository's announced node, by destination hash.
pub type Recall = Box<dyn Fn([u8; 16]) -> Option<[u8; 16]> + Send + Sync>;

/// The page node's state (`NomadNetworkNode`).
pub struct PageNode {
    pub repos: Arc<RwLock<Repositories>>,
    pub stats: Arc<Stats>,
    pub node_name: String,
    /// The repositories destination, shown in each repository's `rns://` URL.
    pub repositories_destination: [u8; 16],
    pub templates_dir: PathBuf,
    pub options: PageOptions,
    pub recall: Option<Recall>,
    null_hash: [u8; 16],
    highlighter: SyntaxHighlighter,
    mdc: MarkdownToMicron,
    thanks: Mutex<VecDeque<Vec<u8>>>,
}

/// A request as the handlers see it.
pub struct PageRequest<'a> {
    pub path: &'a str,
    pub data: &'a Value,
    pub link_id: [u8; 16],
    pub identity: Option<[u8; 16]>,
}

impl PageNode {
    /// Creates `<configdir>/templates` as upstream does.
    pub fn new(
        repos: Arc<RwLock<Repositories>>,
        stats: Arc<Stats>,
        node_name: String,
        repositories_destination: [u8; 16],
        configdir: &Path,
        options: PageOptions,
    ) -> Self {
        let templates_dir = configdir.join("templates");
        if !templates_dir.is_dir()
            && let Err(e) = std::fs::create_dir_all(&templates_dir)
        {
            tracing::error!(
                "Could not create templates directory {}: {e}",
                templates_dir.display()
            );
        }
        let null_hash = rns_identity::identity::Identity::from_private_key(&[0u8; 64])
            .expect("64-byte key")
            .hash;
        let highlighter = SyntaxHighlighter::default();
        Self {
            repos,
            stats,
            node_name,
            repositories_destination,
            templates_dir,
            options,
            recall: None,
            null_hash,
            mdc: MarkdownToMicron::new(MAX_RENDER_WIDTH, Some(highlighter.clone()), None),
            highlighter,
            thanks: Mutex::new(VecDeque::new()),
        }
    }

    /// Dispatch a request to its handler by path.
    pub fn handle(&self, request: &PageRequest<'_>) -> PageReply {
        let page = |r: Option<Vec<u8>>| r.map_or(PageReply::Drop, PageReply::Page);
        match request.path {
            PATH_INDEX => page(self.serve_front_page(request)),
            PATH_GROUP => page(self.serve_group_page(request)),
            PATH_REPO => page(self.serve_repo_page(request)),
            PATH_TREE => page(self.serve_tree_page(request)),
            PATH_BLOB => page(self.serve_blob_page(request)),
            PATH_COMMITS => page(self.serve_commits_page(request)),
            PATH_COMMIT => page(self.serve_commit_page(request)),
            PATH_REFS => page(self.serve_refs_page(request)),
            PATH_STATS => page(self.serve_stats_page(request)),
            PATH_RELEASES => page(self.serve_releases_page(request)),
            PATH_RELEASE => page(self.serve_release_page(request)),
            PATH_WORK => page(self.serve_work_page(request)),
            PATH_WORK_DOC => page(self.serve_work_doc_page(request)),
            PATH_MEDIA => self.serve_media(request),
            FILE_ARTIFACT => self.serve_artifact(request),
            FILE_DOWNLOAD => self.serve_download(request),
            FILE_WORKDOC => self.serve_wd_download(request),
            _ => PageReply::Drop,
        }
    }

    pub(crate) fn icon(&self, name: &str) -> &'static str {
        let nf = self.options.use_nerdfonts;
        match (name, nf) {
            ("sep", _) => "\u{2022}",
            ("folder", true) => "\u{F0256}",
            ("file", true) => "\u{F0F6}",
            ("branch", true) => "\u{F062C}",
            ("commits", true) => "\u{F02DA}",
            ("tag", true) => "\u{F04FC}",
            ("stats", true) => "\u{F201}",
            ("heart", true) => "\u{F02D1}",
            ("package", true) => "\u{F03D7}",
            ("work", true) => "\u{F1323}",
            ("folder", false) => "\u{1F5C0}",
            ("file", false) => "\u{1F5CE}",
            ("branch", false) => "\u{2443}",
            ("commits", false) => "\u{1F5B9}",
            ("tag", false) => "\u{2306}",
            ("stats", false) => "\u{1F5E0}",
            ("heart", false) => "\u{2665}",
            ("package", false) => "\u{25C7}",
            ("work", false) => "\u{2638}",
            _ => "",
        }
    }

    /// The caller, or the null identity when it has not identified.
    pub(crate) fn caller(&self, identity: Option<[u8; 16]>) -> [u8; 16] {
        identity.unwrap_or(self.null_hash)
    }

    /// The no-identity check every page makes for an unidentified, blocked caller.
    pub(crate) fn blocked_unidentified(&self, identity: Option<[u8; 16]>) -> bool {
        identity.is_none()
            && self
                .read_repos()
                .blocked
                .iter()
                .any(|b| b[..] == self.null_hash)
    }

    pub(crate) fn read_repos(&self) -> std::sync::RwLockReadGuard<'_, Repositories> {
        self.repos.read().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn resolve_permission(
        &self,
        identity: Option<[u8; 16]>,
        group: &str,
        repo: &str,
        perm: Perm,
    ) -> bool {
        self.read_repos()
            .resolve_permission(&self.caller(identity), group, repo, perm)
    }

    pub(crate) fn resolve_doc_permission(
        &self,
        identity: Option<[u8; 16]>,
        group: &str,
        repo: &str,
        doc_id: i128,
        perm: Perm,
    ) -> bool {
        crate::server::work::resolve_doc_permission(
            &self.read_repos(),
            &self.caller(identity),
            Some((group, repo)),
            doc_id,
            perm,
        )
    }

    /// `get_accessible_repository`: the repository's path when the caller may read it.
    pub(crate) fn accessible_repository(
        &self,
        identity: Option<[u8; 16]>,
        group: &str,
        repo: &str,
    ) -> Option<crate::server::layout::Repository> {
        let repos = self.read_repos();
        let repository = repos.repository(group, repo)?.clone();
        repos
            .resolve_permission(&self.caller(identity), group, repo, Perm::Read)
            .then_some(repository)
    }

    /// `get_template`: `<templates>/<name>.mu`, run when executable.
    fn get_template(&self, name: &str) -> Option<String> {
        let path = self.templates_dir.join(format!("{name}.mu"));
        let meta = std::fs::metadata(&path).ok().filter(|m| m.is_file())?;
        if crate::platform::mode_executable(&meta) {
            let argv = [path.to_string_lossy().into_owned()];
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            let output = std::process::Command::new(argv[0])
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit())
                .output();
            match output.ok().and_then(|o| String::from_utf8(o.stdout).ok()) {
                Some(text) => Some(text.trim_end_matches(py_space).to_string()),
                None => {
                    tracing::error!(
                        "Could not get dynamic template content from {}",
                        path.display()
                    );
                    None
                }
            }
        } else {
            match std::fs::read(&path)
                .ok()
                .and_then(|d| String::from_utf8(d).ok())
            {
                Some(text) => Some(text.trim_end_matches(py_space).to_string()),
                None => {
                    tracing::error!(
                        "Could not get static template content from {}",
                        path.display()
                    );
                    None
                }
            }
        }
    }

    fn builtin_template(name: &str) -> Option<&'static str> {
        match name {
            "front" => Some(DEFAULT_FRONT_TEMPLATE),
            "no_ident" => Some(DEFAULT_NO_IDENT_TEMPLATE),
            n if PLAIN_TEMPLATES.contains(&n) => Some("{PAGE_CONTENT}"),
            _ => None,
        }
    }

    /// `render_template` (`pages.py`).
    pub(crate) fn render(
        &self,
        page_content: &str,
        nav: Option<&str>,
        template: Option<&str>,
        started: std::time::Instant,
    ) -> Vec<u8> {
        let mut content = page_content.replace('\t', TAB_WIDTH);
        if let Some(name) = template {
            let custom = self.get_template(name).filter(|t| !t.is_empty());
            if let Some(custom) = custom {
                content = custom.replace("{PAGE_CONTENT}", &content);
            } else if let Some(builtin) = Self::builtin_template(name) {
                content = builtin.replace("{PAGE_CONTENT}", &content);
            }
        }
        let base = self
            .get_template("base")
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_TEMPLATE.to_string());
        let gen_time = format!(
            "Generated in {}",
            rns_tools::format::prettytime(
                rns_tools::format::PyNum::Float(started.elapsed().as_secs_f64()),
                false
            )
        );
        base.replace("{NODE_NAME}", &self.node_name)
            .replace("{VERSION}", VERSION)
            .replace("{NAVIGATION}", nav.unwrap_or(""))
            .replace("{GEN_TIME}", &gen_time)
            .replace("{PAGE_CONTENT}", &content)
            .into_bytes()
    }

    pub(crate) fn mdc_scoped(&self, url_scope: &str) -> MarkdownToMicron {
        MarkdownToMicron::new(
            MAX_RENDER_WIDTH,
            Some(self.highlighter.clone()),
            Some(url_scope),
        )
    }

    /// `repository_thanks` and `release_thanks`: the count in `thanks_path`,
    /// once per link and path. The request that creates the file reads 0, as upstream.
    pub(crate) fn thanks(
        &self,
        key_path: &str,
        thanks_path: &Path,
        add: bool,
        link_id: [u8; 16],
    ) -> i64 {
        let mut add = add;
        if add {
            let mut key = link_id.to_vec();
            key.extend_from_slice(key_path.as_bytes());
            let mut seen = self.thanks.lock().unwrap_or_else(|e| e.into_inner());
            if seen.contains(&key) {
                add = false;
            } else {
                if seen.len() == 256 {
                    seen.pop_front();
                }
                seen.push_back(key);
            }
        }
        let write = |count: i64| {
            let value = Value::Map(vec![(Value::from("count"), Value::from(count))]);
            let mut out = Vec::new();
            rmpv::encode::write_value(&mut out, &value).expect("writing to a Vec");
            std::fs::write(thanks_path, out)
        };
        let result = (|| -> Result<i64, String> {
            if !thanks_path.is_file() {
                write(i64::from(add)).map_err(|e| e.to_string())?;
                return Ok(0);
            }
            let data = std::fs::read(thanks_path).map_err(|e| e.to_string())?;
            let value = rmpv::decode::read_value(&mut &data[..]).map_err(|e| e.to_string())?;
            let count = match &value {
                Value::Map(entries) => entries
                    .iter()
                    .find(|(k, _)| k.as_str() == Some("count"))
                    .map(|(_, v)| v.clone()),
                _ => None,
            }
            .ok_or("Invalid data in thanks file")?;
            let mut count = count.as_i64().ok_or("Invalid data in thanks file")?;
            if add {
                count += 1;
            }
            write(count).map_err(|e| e.to_string())?;
            Ok(count)
        })();
        result.unwrap_or_else(|e| {
            tracing::error!("Error while processing thanks for {key_path}: {e}");
            0
        })
    }
}

/// The request map as upstream reads it: `{}` for anything that is not a map.
pub(crate) struct Data<'a>(&'a [(Value, Value)]);

impl<'a> Data<'a> {
    pub fn of(value: &'a Value) -> Self {
        match value {
            Value::Map(entries) => Data(entries),
            _ => Data(&[]),
        }
    }

    pub fn raw(&self, key: &str) -> Option<&'a Value> {
        self.0
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v)
    }

    pub fn has(&self, key: &str) -> bool {
        self.raw(key).is_some()
    }

    /// `data.get(key, default)` used as text.
    pub fn text(&self, key: &str, default: &str) -> String {
        match self.raw(key) {
            None => default.to_string(),
            Some(value) => rns_tools::rsg::pyfmt::py_str(value),
        }
    }

    /// Python truthiness of `data.get(key, "")`.
    pub fn truthy(&self, key: &str) -> bool {
        match self.raw(key) {
            None | Some(Value::Nil) => false,
            Some(Value::Boolean(b)) => *b,
            Some(Value::Integer(i)) => i.as_i64() != Some(0),
            Some(Value::F32(f)) => *f != 0.0,
            Some(Value::F64(f)) => *f != 0.0,
            Some(Value::String(s)) => !s.as_bytes().is_empty(),
            Some(Value::Binary(b)) => !b.is_empty(),
            Some(Value::Array(a)) => !a.is_empty(),
            Some(Value::Map(m)) => !m.is_empty(),
            Some(Value::Ext(..)) => true,
        }
    }

    /// `max(0, int(data.get(key, "0")))`, 0 where `int` raises.
    pub fn page(&self, key: &str) -> usize {
        let n = match self.raw(key) {
            None => Some(0),
            Some(Value::Integer(i)) => i.as_i64().map(i128::from),
            Some(Value::F64(f)) if f.is_finite() => Some(*f as i128),
            Some(Value::F32(f)) if f.is_finite() => Some(*f as i128),
            Some(Value::Boolean(b)) => Some(i128::from(*b)),
            Some(Value::String(s)) => s.as_str().and_then(py_int),
            _ => None,
        };
        n.map_or(0, |n| n.clamp(0, usize::MAX as i128 / 2) as usize)
    }
}

/// Python `str.isspace()` for one character.
pub(crate) fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

pub(crate) fn py_strip(s: &str) -> &str {
    s.trim_matches(py_space)
}

/// Python `int(text)` for a decimal string; `None` where it raises.
pub(crate) fn py_int(text: &str) -> Option<i128> {
    let t = py_strip(text);
    let (negative, digits) = match t.strip_prefix(['+', '-']) {
        Some(rest) => (t.starts_with('-'), rest),
        None => (false, t),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    let mut value: i128 = 0;
    for c in digits.chars().filter(|c| *c != '_') {
        value = value
            .checked_mul(10)?
            .checked_add(i128::from(c.to_digit(10)?))?;
    }
    Some(if negative { -value } else { value })
}

/// `str[:n]` in code points.
pub(crate) fn chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// `urllib.parse.quote_plus(str(value).encode("utf-8"))`.
pub fn quote_plus(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `urllib.parse.unquote_plus`: invalid UTF-8 becomes U+FFFD.
pub fn unquote_plus(value: &str) -> String {
    let bytes = value.replace('+', " ").into_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn sanitize_label(label: &str) -> String {
    label.replace(['[', ']', '`'], "")
}

fn field_str(fields: &[(&str, &str)]) -> String {
    if fields.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{k}={}", quote_plus(v)))
        .collect();
    format!("`{}", parts.join("|"))
}

/// `m_link`: a bold link.
pub fn m_link(label: &str, path: &str, fields: &[(&str, &str)]) -> String {
    format!(
        "`!`[{}`:{path}{}]`!",
        sanitize_label(label),
        field_str(fields)
    )
}

/// `m_link_r`: a plain link.
pub fn m_link_r(label: &str, path: &str, fields: &[(&str, &str)]) -> String {
    format!("`[{}`:{path}{}]", sanitize_label(label), field_str(fields))
}

/// `m_link_e`: a bold link to another node.
pub fn m_link_e(label: &str, remote: &str, path: &str, fields: &[(&str, &str)]) -> String {
    format!(
        "`!`[{}`{remote}:{path}{}]`!",
        sanitize_label(label),
        field_str(fields)
    )
}

pub fn m_heading(text: &str, level: usize) -> String {
    format!("{}{text}\n", ">".repeat(level))
}

pub fn m_italic(text: &str) -> String {
    format!("`*{text}`*")
}

pub fn m_divider() -> String {
    "-\u{2500}\n".to_string()
}

pub fn m_escape(text: &str) -> String {
    text.replace('`', "\\`")
}

/// `os.path.basename`.
pub(crate) fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `os.path.splitext(path)[1]`.
pub(crate) fn extension(path: &str) -> &str {
    let name = basename(path);
    let stem_start = name.len() - name.trim_start_matches('.').len();
    match name[stem_start..].rfind('.') {
        Some(i) => &name[stem_start + i..],
        None => "",
    }
}

/// `os.path.splitext(name)[0]`.
pub(crate) fn stem(name: &str) -> &str {
    let ext = extension(name);
    &name[..name.len() - ext.len()]
}

/// `RNS.prettyhexrep`.
pub(crate) fn prettyhexrep(hash: &[u8]) -> String {
    format!("<{}>", hex::encode(hash))
}

pub(crate) fn prettysize(size: u64) -> String {
    rns_tools::format::prettysize(size as f64, "B")
}

/// `time.strftime` with `%Y-%m-%d`, then `%H:%M` and `:%S` as asked.
pub(crate) fn local_time(ts: f64, minutes: bool, seconds: bool) -> String {
    let Some(tm) = crate::platform::localtime(ts.floor() as i64) else {
        return String::new();
    };
    let mut out = format!("{:04}-{:02}-{:02}", tm.year, tm.month, tm.day);
    if minutes {
        out.push_str(&format!(" {:02}:{:02}", tm.hour, tm.minute));
    }
    if seconds {
        out.push_str(&format!(":{:02}", tm.second));
    }
    out
}

pub(crate) fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// `format_relative_time`.
pub(crate) fn relative_time(timestamp: i64) -> String {
    let diff = now() - timestamp as f64;
    let unit = |n: i64, word: &str| format!("{n} {word}{} ago", if n != 1 { "s" } else { "" });
    if diff < 60.0 {
        "just now".to_string()
    } else if diff < 3600.0 {
        unit((diff / 60.0) as i64, "minute")
    } else if diff < 86400.0 {
        unit((diff / 3600.0) as i64, "hour")
    } else if diff < 604800.0 {
        unit((diff / 86400.0) as i64, "day")
    } else if diff < 2592000.0 {
        unit((diff / 604800.0) as i64, "week")
    } else if diff < 31536000.0 {
        unit((diff / 2592000.0) as i64, "month")
    } else {
        unit((diff / 31536000.0) as i64, "year")
    }
}

/// A release tag or artifact name that names an entry inside its directory.
pub(crate) fn plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

/// A map field of an unpacked value.
pub(crate) fn field<'v>(value: &'v Value, key: &str) -> Option<&'v Value> {
    match value {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v),
        _ => None,
    }
}

pub(crate) fn field_str_or(value: &Value, key: &str, default: &str) -> String {
    match field(value, key) {
        None => default.to_string(),
        Some(v) => rns_tools::rsg::pyfmt::py_str(v),
    }
}

/// A number field as Python holds it; non-numbers are 0.
pub(crate) fn field_num(value: &Value, key: &str) -> f64 {
    match field(value, key) {
        Some(Value::Integer(i)) => i.as_f64().unwrap_or(0.0),
        Some(Value::F64(f)) => *f,
        Some(Value::F32(f)) => f64::from(*f),
        Some(Value::Boolean(b)) => f64::from(u8::from(*b)),
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::PageOptions;

    #[test]
    fn page_stamp_keys_follow_upstream() {
        let options = PageOptions::from_config_text("[pages]\nserve_nomadnet = yes\n").unwrap();
        assert_eq!((options.stamp_value, options.link_cost), (None, 18.0));
        let options =
            PageOptions::from_config_text("[pages]\nstamp_value = 27.5\nlink_cost = 18.7\n")
                .unwrap();
        assert_eq!(
            (options.stamp_value, options.link_cost),
            (Some(27.5), 4787.0 / 256.0)
        );
        assert!(PageOptions::from_config_text("[pages]\nlink_cost = x\n").is_err());
    }
}
