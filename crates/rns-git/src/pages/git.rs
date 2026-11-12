//! Git data extraction for the page node (`pages.py:2043-2616@1.6.0`).

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::py_strip;

/// `GIT_COMMAND_TIMEOUT`.
pub const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(8);

/// Most output kept from one command. Upstream keeps all of it; anyone who can
/// reach the page node could otherwise make it hold a whole blob in memory.
const CAPTURE_LIMIT: u64 = 16 * 1024 * 1024;

/// What `get_blob_info` looks at to tell text from binary.
const SAMPLE_BYTES: u64 = 8192;

pub(crate) struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }
}

#[derive(Debug)]
pub enum RunError {
    /// `subprocess.TimeoutExpired`.
    Timeout,
    /// Any other exception: spawn failure or undecodable text output.
    Failed,
}

/// `subprocess.run(argv, cwd=cwd, capture_output=True, timeout=timeout)`;
/// the child is killed when the deadline passes or its output passes
/// `CAPTURE_LIMIT`.
pub(crate) fn run(
    argv: &[&str],
    cwd: &Path,
    timeout: Option<Duration>,
) -> Result<Output, RunError> {
    let (out, truncated) = run_capped(argv, cwd, timeout, CAPTURE_LIMIT)?;
    if truncated {
        tracing::warn!("Output of {} is over the capture limit", argv.join(" "));
        return Err(RunError::Failed);
    }
    Ok(out)
}

/// The first `limit` bytes of a command's output. A command cut off at the
/// limit is killed and counts as successful.
fn run_capped(
    argv: &[&str],
    cwd: &Path,
    timeout: Option<Duration>,
    limit: u64,
) -> Result<(Output, bool), RunError> {
    let mut child = Command::new(argv[0])
        .args(&argv[1..])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| RunError::Failed)?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let full = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader_full = full.clone();
    let out_reader = std::thread::spawn(move || {
        let mut data = Vec::new();
        let _ = (&mut stdout).take(limit).read_to_end(&mut data);
        // One more byte tells a command that ended at the limit from one cut off by it.
        if data.len() as u64 == limit && matches!(stdout.read(&mut [0u8; 1]), Ok(1)) {
            reader_full.store(true, std::sync::atomic::Ordering::Release);
        }
        data
    });
    let err_reader = std::thread::spawn(move || {
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
    });
    let deadline = timeout.map(|t| Instant::now() + t);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => return Err(RunError::Failed),
        }
        if full.load(std::sync::atomic::Ordering::Acquire) {
            let _ = child.kill();
            let _ = child.wait();
            let stdout = out_reader.join().unwrap_or_default();
            let _ = err_reader.join();
            return Ok((
                Output {
                    code: Some(0),
                    stdout,
                },
                true,
            ));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_reader.join();
            let _ = err_reader.join();
            return Err(RunError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let stdout = out_reader.join().unwrap_or_default();
    let _ = err_reader.join();
    // A command cut off at the limit may also have died writing to the closed pipe.
    let truncated = full.load(std::sync::atomic::Ordering::Acquire);
    let code = if truncated { Some(0) } else { status.code() };
    Ok((Output { code, stdout }, truncated))
}

/// `text=True` decoding: strict UTF-8 with universal newlines.
pub(crate) fn text(data: &[u8]) -> Result<String, RunError> {
    let text = std::str::from_utf8(data).map_err(|_| RunError::Failed)?;
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

/// `run` with text output.
pub(crate) fn run_text(
    argv: &[&str],
    cwd: &Path,
    timeout: Option<Duration>,
) -> Result<(bool, String), RunError> {
    let out = run(argv, cwd, timeout)?;
    Ok((out.ok(), text(&out.stdout)?))
}

fn timed() -> Option<Duration> {
    Some(GIT_COMMAND_TIMEOUT)
}

fn path_str(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `get_repository_description`.
pub fn repository_description(repo_path: &Path) -> Option<String> {
    let result = (|| -> Result<Option<String>, RunError> {
        let (ok, out) = run_text(
            &["git", "config", "--get", "repository.description"],
            repo_path,
            None,
        )?;
        if ok && !py_strip(&out).is_empty() {
            return Ok(Some(py_strip(&out).to_string()));
        }
        let desc_path = format!("{}.description", path_str(repo_path));
        if Path::new(&desc_path).is_file() {
            let data = std::fs::read(&desc_path).map_err(|_| RunError::Failed)?;
            let desc = text(&data)?;
            let desc = py_strip(&desc);
            if !desc.is_empty() {
                return Ok(Some(desc.to_string()));
            }
        }
        Ok(None)
    })();
    result.unwrap_or_else(|e| {
        tracing::debug!("Error getting repository description: {e:?}");
        None
    })
}

/// `get_repository_refs`, reduced to the branch and tag counts the repository page shows.
pub fn repository_ref_counts(repo_path: &Path) -> (usize, usize) {
    let Ok((ok, out)) = run_text(
        &[
            "git",
            "for-each-ref",
            "--format",
            "%(objectname) %(refname) %(refname:short)",
            "refs/heads",
            "refs/tags",
        ],
        repo_path,
        None,
    ) else {
        return (0, 0);
    };
    if !ok {
        return (0, 0);
    }
    let (mut heads, mut tags) = (0, 0);
    for line in py_strip(&out).split('\n') {
        if py_strip(line).is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            if parts[1].starts_with("refs/heads/") {
                heads += 1;
            } else if parts[1].starts_with("refs/tags/") {
                tags += 1;
            }
        }
    }
    (heads, tags)
}

/// `resolve_ref`. `--end-of-options` keeps a ref from being read as an option.
pub fn resolve_ref(repo_path: &Path, reference: &str) -> Option<String> {
    match run_text(
        &[
            "git",
            "rev-parse",
            "--verify",
            "--end-of-options",
            reference,
        ],
        repo_path,
        timed(),
    ) {
        Ok((true, out)) => {
            let hash = py_strip(&out).to_lowercase();
            crate::util::san_sha(&hash).map(str::to_string)
        }
        Ok(_) => None,
        Err(RunError::Timeout) => {
            tracing::warn!("Timeout resolving ref '{reference}'");
            None
        }
        Err(e) => {
            tracing::warn!("Error resolving ref: {e:?}");
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct TreeEntry {
    pub name: String,
    /// `blob`, `tree`, `commit` or `link`.
    pub kind: String,
    pub size: u64,
    pub link_target: Option<String>,
}

/// `get_tree_entries`; `None` when the path is not a tree.
pub fn tree_entries(repo_path: &Path, reference: &str, path: &str) -> Option<Vec<TreeEntry>> {
    let tree_path = path.trim_matches('/');
    let ls_tree_path = if tree_path.is_empty() {
        reference.to_string()
    } else {
        format!("{reference}:{tree_path}")
    };
    let result = (|| -> Result<Option<Vec<TreeEntry>>, RunError> {
        let (ok, out) = run_text(&["git", "ls-tree", "-l", &ls_tree_path], repo_path, timed())?;
        if !ok {
            let (ok, kind) = run_text(
                &["git", "cat-file", "-t", &ls_tree_path],
                repo_path,
                timed(),
            )?;
            if !ok || py_strip(&kind) != "tree" {
                return Ok(None);
            }
            return Ok(Some(Vec::new()));
        }
        let mut entries = Vec::new();
        for line in py_strip(&out).split('\n') {
            if py_strip(line).is_empty() {
                continue;
            }
            let Some((meta, name)) = line.split_once('\t') else {
                continue;
            };
            let meta: Vec<&str> = meta.split_whitespace().collect();
            if meta.len() < 3 {
                continue;
            }
            let size = meta.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
            let mut entry = TreeEntry {
                name: name.to_string(),
                kind: meta[1].to_string(),
                size,
                link_target: None,
            };
            if meta[0] == "120000" {
                entry.kind = "link".to_string();
                let spec = if tree_path.is_empty() {
                    format!("{reference}:{name}")
                } else {
                    format!("{reference}:{tree_path}/{name}")
                };
                if let Ok((true, target)) = run_text(&["git", "show", &spec], repo_path, timed()) {
                    entry.link_target = Some(py_strip(&target).to_string());
                }
            }
            entries.push(entry);
        }
        Ok(Some(entries))
    })();
    match result {
        Ok(entries) => entries,
        Err(RunError::Timeout) => {
            tracing::warn!("Timeout listing tree contents");
            None
        }
        Err(e) => {
            tracing::warn!("Error getting tree entries: {e:?}");
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlobInfo {
    pub size: u64,
    pub is_tree: bool,
    pub is_binary: bool,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
}

/// `get_blob_info`.
pub fn blob_info(repo_path: &Path, reference: &str, path: &str) -> Option<BlobInfo> {
    let file_path = path.trim_matches('/');
    let spec = format!("{reference}:{file_path}");
    let result = (|| -> Result<Option<BlobInfo>, RunError> {
        let (ok, out) = run_text(&["git", "cat-file", "-s", &spec], repo_path, timed())?;
        if !ok {
            return Ok(None);
        }
        let size: u64 = py_strip(&out).parse().map_err(|_| RunError::Failed)?;
        let tree_spec = if file_path.is_empty() {
            reference.to_string()
        } else {
            spec.clone()
        };
        let is_tree = run(&["git", "ls-tree", &tree_spec], repo_path, timed())?.ok();
        let (parent, filename) = match file_path.rsplit_once('/') {
            Some((parent, name)) => (parent, name),
            None => ("", file_path),
        };
        let parent_spec = if parent.is_empty() {
            reference.to_string()
        } else {
            format!("{reference}:{parent}")
        };
        let (ok, listing) = run_text(&["git", "ls-tree", &parent_spec], repo_path, timed())?;
        let needle = format!("\t{filename}");
        let is_symlink = ok
            && py_strip(&listing)
                .split('\n')
                .any(|line| line.contains(&needle) && line.starts_with("120000"));
        let mut symlink_target = None;
        if is_symlink {
            let (ok, target) = run_text(&["git", "show", &spec], repo_path, timed())?;
            if ok {
                symlink_target = Some(py_strip(&target).to_string());
            }
        }
        let mut is_binary = false;
        if !is_symlink {
            // Upstream reads the whole blob and looks at its first 8192 bytes.
            let (sample, _) =
                run_capped(&["git", "show", &spec], repo_path, timed(), SAMPLE_BYTES)?;
            if sample.ok() {
                let head = &sample.stdout[..];
                if head.contains(&0) {
                    is_binary = true;
                } else {
                    // Upstream's second check; `<ref>:<path>` is not a file, so it never matches.
                    let out = run(
                        &[
                            "git",
                            "diff",
                            "--numstat",
                            "--no-index",
                            "--",
                            "/dev/null",
                            &spec,
                        ],
                        repo_path,
                        timed(),
                    )?;
                    let first = text(&out.stdout)?;
                    if out.code == Some(1)
                        && py_strip(&first)
                            .split('\n')
                            .next()
                            .unwrap_or("")
                            .starts_with('-')
                    {
                        is_binary = true;
                    }
                }
            }
        }
        Ok(Some(BlobInfo {
            size,
            is_tree,
            is_binary,
            is_symlink,
            symlink_target,
        }))
    })();
    result.unwrap_or_else(|e| {
        tracing::debug!("Error getting blob info: {e:?}");
        None
    })
}

/// `get_blob_content`.
pub fn blob_content(repo_path: &Path, reference: &str, path: &str) -> Option<String> {
    let spec = format!("{reference}:{}", path.trim_matches('/'));
    match run_text(&["git", "show", &spec], repo_path, timed()) {
        Ok((true, content)) => Some(content),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!("Error getting blob content: {e:?}");
            None
        }
    }
}

/// `get_blob_stream`: `git show` spooled to an anonymous file, as upstream's
/// Resource proxies a pipe into a temporary file before sending it.
pub fn blob_stream(repo_path: &Path, reference: &str, path: &str) -> Option<std::fs::File> {
    use std::io::Seek;
    let spec = format!("{reference}:{}", path.trim_matches('/'));
    let result = (|| -> std::io::Result<std::fs::File> {
        let mut spool = tempfile::tempfile()?;
        let mut child = Command::new("git")
            .args(["show", &spec])
            .current_dir(repo_path)
            .stdin(Stdio::null())
            .stdout(spool.try_clone()?)
            .stderr(Stdio::null())
            .spawn()?;
        child.wait()?;
        spool.rewind()?;
        Ok(spool)
    })();
    result
        .map_err(|e| tracing::warn!("Error getting blob content handle: {e}"))
        .ok()
}

#[derive(Debug, Clone)]
pub struct RefInfo {
    pub name: String,
    pub short_hash: String,
    pub commit_subject: String,
    pub is_default: bool,
    pub is_annotated: bool,
    pub tag_message: Option<String>,
}

/// `get_refs_info`: heads and tags.
pub fn refs_info(repo_path: &Path, default_branch: Option<&str>) -> (Vec<RefInfo>, Vec<RefInfo>) {
    let mut heads = Vec::new();
    let mut tags = Vec::new();
    let result = (|| -> Result<(), RunError> {
        let (ok, out) = run_text(
            &[
                "git",
                "for-each-ref",
                "--format=%(objectname)|%(refname)|%(refname:short)|%(subject)",
                "refs/heads",
                "refs/tags",
            ],
            repo_path,
            timed(),
        )?;
        if !ok {
            return Ok(());
        }
        for line in py_strip(&out).split('\n') {
            if py_strip(line).is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(4, '|').collect();
            if parts.len() < 3 {
                continue;
            }
            let mut info = RefInfo {
                name: parts[2].to_string(),
                short_hash: parts[0].chars().take(7).collect(),
                commit_subject: parts.get(3).unwrap_or(&"").to_string(),
                is_default: Some(parts[2]) == default_branch,
                is_annotated: false,
                tag_message: None,
            };
            if parts[1].starts_with("refs/heads/") {
                heads.push(info);
            } else if parts[1].starts_with("refs/tags/") {
                if let Ok((true, tag)) = run_text(
                    &[
                        "git",
                        "for-each-ref",
                        "--format=%(objecttype)|%(contents:subject)",
                        parts[1],
                    ],
                    repo_path,
                    timed(),
                ) && let Some((kind, message)) = py_strip(&tag).split_once('|')
                    && kind == "tag"
                {
                    info.is_annotated = true;
                    info.tag_message = Some(message.to_string());
                }
                tags.push(info);
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        tracing::warn!("Error getting refs info: {e:?}");
    }
    (heads, tags)
}

/// `get_commit_count`.
pub fn commit_count(repo_path: &Path, reference: &str) -> u64 {
    match run_text(
        &["git", "rev-list", "--count", reference],
        repo_path,
        timed(),
    ) {
        Ok((true, out)) => py_strip(&out).parse().unwrap_or(0),
        _ => 0,
    }
}

#[derive(Debug, Clone)]
pub struct CommitEntry {
    pub hash: String,
    pub subject: String,
    pub author: String,
    pub timestamp: i64,
}

/// `get_commits`.
pub fn commits(
    repo_path: &Path,
    reference: &str,
    file_path: &str,
    skip: u64,
    limit: u64,
) -> Option<Vec<CommitEntry>> {
    const SEP: &str = "|_SEP_|";
    let format = format!("--format=%H{SEP}%s{SEP}%an{SEP}%ae{SEP}%at");
    let (skip, limit) = (skip.to_string(), limit.to_string());
    let mut argv = vec![
        "git", "log", &format, "--skip", &skip, "-n", &limit, reference,
    ];
    if !file_path.is_empty() {
        argv.extend(["--", file_path]);
    }
    let result = (|| -> Result<Option<Vec<CommitEntry>>, RunError> {
        let (ok, out) = run_text(&argv, repo_path, timed())?;
        if !ok {
            return Ok(None);
        }
        let mut commits = Vec::new();
        for line in py_strip(&out).split('\n') {
            if py_strip(line).is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(5, SEP).collect();
            if parts.len() >= 5 {
                commits.push(CommitEntry {
                    hash: parts[0].to_string(),
                    subject: parts[1].to_string(),
                    author: parts[2].to_string(),
                    timestamp: super::py_int(parts[4]).ok_or(RunError::Failed)? as i64,
                });
            }
        }
        Ok(Some(commits))
    })();
    result.unwrap_or_else(|e| {
        tracing::debug!("Error getting commits: {e:?}");
        None
    })
}

#[derive(Debug, Clone)]
pub struct ChangedFile {
    pub path: String,
    pub status: &'static str,
    pub additions: i64,
    pub deletions: i64,
}

#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub parents: Vec<String>,
    pub author_name: String,
    pub author_email: String,
    pub author_date: String,
    pub committer_name: String,
    pub committer_email: String,
    pub committer_date: String,
    pub message: String,
    pub files: Vec<ChangedFile>,
    pub diff: Option<String>,
}

/// `get_commit_info`.
pub fn commit_info(repo_path: &Path, hash: &str) -> Option<CommitInfo> {
    let result = (|| -> Result<Option<CommitInfo>, RunError> {
        let (ok, out) = run_text(
            &[
                "git",
                "show",
                "--no-patch",
                "--format=%P%n%an%n%ae%n%aI%n%cn%n%ce%n%cI%n%B",
                hash,
            ],
            repo_path,
            timed(),
        )?;
        if !ok {
            return Ok(None);
        }
        let lines: Vec<&str> = out.split('\n').collect();
        if lines.len() < 7 {
            return Ok(None);
        }
        let mut info = CommitInfo {
            parents: lines[0].split_whitespace().map(str::to_string).collect(),
            author_name: lines[1].to_string(),
            author_email: lines[2].to_string(),
            author_date: lines[3].to_string(),
            committer_name: lines[4].to_string(),
            committer_email: lines[5].to_string(),
            committer_date: lines[6].to_string(),
            message: py_strip(&lines[7..].join("\n")).to_string(),
            files: Vec::new(),
            diff: None,
        };
        let (ok, stats) = run_text(
            &["git", "diff-tree", "--numstat", "-r", hash],
            repo_path,
            timed(),
        )?;
        if ok {
            for line in py_strip(&stats).split('\n') {
                if py_strip(line).is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() < 3 {
                    continue;
                }
                let (mut additions, mut deletions) = (parts[0], parts[1]);
                let file_path = parts[2];
                let mut status = "M";
                if additions == "-" && deletions == "-" {
                    status = "R";
                    additions = "0";
                    deletions = "0";
                }
                if let Some(parent) = info.parents.first() {
                    let in_parent = run(
                        &["git", "cat-file", "-e", &format!("{parent}:{file_path}")],
                        repo_path,
                        timed(),
                    )?;
                    if !in_parent.ok() {
                        status = "A";
                    } else {
                        let in_current = run(
                            &["git", "cat-file", "-e", &format!("{hash}:{file_path}")],
                            repo_path,
                            timed(),
                        )?;
                        if !in_current.ok() {
                            status = "D";
                        }
                    }
                }
                let count = |s: &str| if s == "-" { Some(0) } else { super::py_int(s) };
                let (additions, deletions) = match (count(additions), count(deletions)) {
                    (Some(a), Some(d)) => (a as i64, d as i64),
                    _ => (0, 0),
                };
                info.files.push(ChangedFile {
                    path: file_path.to_string(),
                    status,
                    additions,
                    deletions,
                });
            }
        }
        let (ok, diff) = run_text(&["git", "show", "--format=", hash], repo_path, timed())?;
        if ok {
            info.diff = Some(diff);
        }
        Ok(Some(info))
    })();
    result.unwrap_or_else(|e| {
        tracing::warn!("Error getting commit info: {e:?}");
        None
    })
}

/// The `cat-file -t` check of the commit page: `Ok(true)` for a commit.
pub fn is_commit(repo_path: &Path, hash: &str) -> Result<bool, RunError> {
    let (ok, kind) = run_text(&["git", "cat-file", "-t", hash], repo_path, timed())?;
    Ok(ok && py_strip(&kind) == "commit")
}

/// The commit page's signature status (`get_commit_signature`).
pub struct SignatureStatus {
    pub signed: bool,
    pub valid: bool,
    pub author_match: bool,
    pub message: String,
}

pub fn commit_signature(repo_path: &Path, hash: &str) -> SignatureStatus {
    let status = |signed, valid, author_match, message: &str| SignatureStatus {
        signed,
        valid,
        author_match,
        message: message.to_string(),
    };
    let (ok, content) = match run_text(&["git", "cat-file", "-p", hash], repo_path, timed()) {
        Ok(result) => result,
        Err(RunError::Timeout) => return status(false, false, false, "Timeout"),
        Err(RunError::Failed) => return status(false, false, false, "Error"),
    };
    if !ok {
        return status(false, false, false, "Could not read commit object");
    }
    let mut sig_lines: Vec<&str> = Vec::new();
    let mut signed_lines: Vec<&str> = Vec::new();
    let mut in_signature = false;
    for line in content.split('\n') {
        if line.starts_with("gpgsig ") || line.starts_with("gpgsig-sha256 ") {
            in_signature = true;
            let start = line.find(' ').map_or(0, |i| i + 1);
            sig_lines.push(&line[start..]);
        } else if in_signature {
            if let Some(rest) = line.strip_prefix(' ') {
                sig_lines.push(rest);
            } else {
                in_signature = false;
                signed_lines.push(line);
            }
        } else {
            signed_lines.push(line);
        }
    }
    if sig_lines.is_empty() {
        return status(false, false, false, "Not signed");
    }
    let armored = sig_lines.join("\n");
    let signed_content = signed_lines.join("\n").into_bytes();
    let Ok(sig_data) = crate::commitsigs::unarmor_ssh_signature(&armored) else {
        return status(true, false, false, "Signature validation error");
    };
    let rsg = match crate::commitsigs::parse_ssh_signature(&sig_data) {
        Ok(sig) => sig.signature_data,
        Err(_) => return status(true, false, false, "Malformed SSH wrapping for RSG data"),
    };
    let message = rmpv::Value::Binary(signed_content.clone());
    let valid =
        match rns_tools::rsg::validate_rsg(&rsg, rns_tools::rsg::Message::Unpacked(&message), None)
        {
            Ok(Some(valid)) => valid,
            Ok(None) => return status(true, false, false, "Invalid signature"),
            Err(_) => return status(true, false, false, "Signature validation error"),
        };
    let signer = hex::encode(valid.signer_hash);
    let author = match crate::commitsigs::extract_commit_author(&signed_content) {
        crate::commitsigs::HeaderEmail::Email(email) => email,
        crate::commitsigs::HeaderEmail::DecodeError => "1".to_string(),
    };
    if author.is_empty() {
        return status(true, true, false, "Could not verify author");
    }
    if author == signer {
        status(true, true, true, &format!("Valid, signed by <{signer}>"))
    } else {
        status(
            true,
            true,
            false,
            &format!("Invalid signer <{signer}>, author is <{author}>"),
        )
    }
}

/// `get_readme_content`: always read from `HEAD`, as upstream does.
pub fn readme_content(repo_path: &Path) -> Option<(String, bool)> {
    const NAMES: [(&str, bool); 11] = [
        ("README.mu", false),
        ("Readme.mu", false),
        ("readme.mu", false),
        ("README", false),
        ("readme", false),
        ("README.md", true),
        ("readme.md", true),
        ("README.rst", false),
        ("README.txt", false),
        ("readme.rst", false),
        ("readme.txt", false),
    ];
    for (name, is_markdown) in NAMES {
        if let Ok((true, content)) =
            run_text(&["git", "show", &format!("HEAD:{name}")], repo_path, None)
        {
            return Some((content, is_markdown));
        }
    }
    None
}

/// The refs page's default branch (`git symbolic-ref HEAD`).
pub fn default_branch(repo_path: &Path) -> Option<String> {
    match run_text(&["git", "symbolic-ref", "HEAD"], repo_path, timed()) {
        Ok((true, out)) => Some(py_strip(&out).replace("refs/heads/", "")),
        Err(RunError::Timeout) => {
            tracing::warn!("Git command execution timed out");
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_output_is_bounded() {
        let cwd = std::env::temp_dir();
        let endless = ["sh", "-c", "while :; do printf '%4096s' x; done"];
        // A sample takes its bytes and stops the command.
        let (sample, truncated) = run_capped(&endless, &cwd, timed(), SAMPLE_BYTES).unwrap();
        assert!(sample.ok() && truncated);
        assert_eq!(sample.stdout.len() as u64, SAMPLE_BYTES);
        // A full capture refuses instead of growing without bound.
        assert!(matches!(
            run(&endless, &cwd, timed()),
            Err(RunError::Failed)
        ));
        // Output that ends exactly at the limit is whole.
        let exact = ["sh", "-c", "printf '%8192s' x"];
        let (out, truncated) = run_capped(&exact, &cwd, timed(), SAMPLE_BYTES).unwrap();
        assert!(out.ok() && !truncated && out.stdout.len() as u64 == SAMPLE_BYTES);
    }
}
