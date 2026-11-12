//! `/media` and the `/file/*` handlers (`pages.py`).

use std::io::{Read, Seek, Write};
use std::path::PathBuf;

use rmpv::Value;

use super::git;
use super::views::{doc_dir, doc_id_of};
use super::*;
use crate::server::perms::Perm;

fn packed(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).expect("writing to a Vec");
    out
}

fn false_reply() -> PageReply {
    PageReply::Value(packed(&Value::Boolean(false)))
}

impl PageNode {
    pub(crate) fn serve_artifact(&self, req: &PageRequest<'_>) -> PageReply {
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        let mut tag = data.text("var_t", "");
        let artifact = unquote_plus(&data.text("var_a", ""));
        if artifact.contains('/') {
            return PageReply::Drop;
        }
        let Some(repo) = self.accessible_repository(req.identity, &group, &name) else {
            tracing::debug!(
                "Repository not found or no access for artifact request {group}/{name}/{tag}/{artifact}"
            );
            return PageReply::Drop;
        };
        let releases_path = PathBuf::from(format!("{}.releases", repo.path.to_string_lossy()));
        if tag == "latest" {
            let Some((releases, latest)) = crate::server::releases::list_for_pages(&releases_path)
                .filter(|(r, _)| !r.is_empty())
            else {
                return PageReply::Drop;
            };
            tag = latest.unwrap_or_else(|| field_str_or(&releases[0], "tag", ""));
        }
        // Upstream joins the tag and name unchecked; only plain names stay inside the release.
        if !plain_name(&tag) || !plain_name(&artifact) {
            tracing::warn!("Refused artifact request {group}/{name}/{tag}/{artifact}");
            return PageReply::Drop;
        }
        let release_dir = releases_path.join(&tag);
        let artifacts_dir = release_dir.join("artifacts");
        let artifact_path = artifacts_dir.join(&artifact);
        let Some(info) = crate::server::releases::data_for_pages(&release_dir, &tag) else {
            tracing::warn!(
                "Could not resolve release info for artifact request {group}/{name}/{tag}/{artifact}"
            );
            return PageReply::Drop;
        };
        if field(&info, "status").and_then(Value::as_str) != Some("published") {
            tracing::warn!("Attempt to fetch unpublished artifact {group}/{name}/{tag}/{artifact}");
            return PageReply::Drop;
        }
        if !release_dir.is_dir() || !artifacts_dir.is_dir() || !artifact_path.is_file() {
            tracing::warn!(
                "Artifact not found for artifact request {group}/{name}/{tag}/{artifact}"
            );
            return PageReply::Drop;
        }
        let Ok(file) = std::fs::File::open(&artifact_path) else {
            return PageReply::Drop;
        };
        self.stats
            .release_download_succeeded(&group, &name, req.identity.as_ref());
        PageReply::File {
            file,
            name: artifact,
        }
    }

    pub(crate) fn serve_media(&self, req: &PageRequest<'_>) -> PageReply {
        let data = Data::of(req.data);
        if !data.has("key") {
            tracing::debug!("Missing request key in media request");
            return false_reply();
        }
        let media_path = data.text("path", "");
        if !data.truthy("path") {
            tracing::debug!("Missing path in media request");
            return false_reply();
        }
        let rest = media_path.strip_prefix("/media").unwrap_or(&media_path);
        let comps: Vec<&str> = rest.trim_start_matches('/').split('/').collect();
        if comps.len() < 4 {
            tracing::debug!("Insufficient path components in media request");
            return false_reply();
        }
        let (group, name, reference) = (comps[0], comps[1], comps[2]);
        let file_path = unquote_plus(&comps[3..].join("/"));
        let file_name = basename(&file_path).to_string();
        let Some(repo) = self.accessible_repository(req.identity, group, name) else {
            tracing::debug!(
                "Repository not found or no access for media request {group}/{name}/{reference}/{file_path}"
            );
            return false_reply();
        };
        let Some(resolved) = git::resolve_ref(&repo.path, reference) else {
            tracing::warn!(
                "Ref not found for media request {group}/{name}/{reference}/{file_path}"
            );
            return false_reply();
        };
        if file_path.is_empty() {
            return false_reply();
        }
        if git::blob_info(&repo.path, &resolved, &file_path).is_none() {
            tracing::warn!(
                "File not found at ref for media request {group}/{name}/{reference}/{file_path}"
            );
            return false_reply();
        }
        let ext = extension(&file_path).to_lowercase();
        if self.options.media_conversion
            && IMAGE_EXTS.contains(&ext.as_str())
            && ext != ".webp"
            && let Some(file) = self.webp_stream(&repo.path, &resolved, &file_path)
        {
            let response_name = format!("{}.webp", stem(basename(file_path.trim_matches('/'))));
            return PageReply::File {
                file,
                name: response_name,
            };
        }
        match git::blob_stream(&repo.path, &resolved, &file_path) {
            Some(file) => PageReply::File {
                file,
                name: file_name,
            },
            None => PageReply::Drop,
        }
    }

    /// `get_webp_stream`: the converted image, opened before its spool directory goes.
    fn webp_stream(
        &self,
        repo_path: &std::path::Path,
        resolved: &str,
        file_path: &str,
    ) -> Option<std::fs::File> {
        let file_path = file_path.trim_matches('/');
        let tmpdir = tempfile::TempDir::new().ok()?;
        let stem = stem(basename(file_path)).to_string();
        let spool = tempfile::Builder::new()
            .prefix(&format!("{stem}."))
            .suffix(".webp")
            .tempfile_in(tmpdir.path())
            .ok()?;
        let spool_path = spool.path().to_path_buf();
        let spec = format!("{resolved}:{file_path}");
        if !crate::media::convert_to_webp(
            &["git", "show", &spec],
            &spool_path,
            Some(repo_path),
            extension(file_path),
        ) {
            return None;
        }
        std::fs::File::open(&spool_path).ok()
    }

    pub(crate) fn serve_download(&self, req: &PageRequest<'_>) -> PageReply {
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        let reference = data.text("var_ref", "HEAD");
        let fmt = data.text("var_fmt", "");
        let fmt_set = data.truthy("var_fmt");
        let file_path = unquote_plus(&data.text("var_path", ""));
        let file_name = basename(&file_path).to_string();
        let ext = extension(&file_path).to_lowercase();
        if fmt_set && !CONVERTABLE_EXTS.contains(&ext.as_str()) {
            tracing::debug!("Download conversion request for non-convertable file");
            return PageReply::Drop;
        }
        let Some(repo) = self.accessible_repository(req.identity, &group, &name) else {
            return PageReply::Drop;
        };
        let Some(resolved) = git::resolve_ref(&repo.path, &reference) else {
            tracing::warn!(
                "Ref not found for download request {group}/{name}/{reference}/{file_path}"
            );
            return PageReply::Drop;
        };
        let info = (!file_path.is_empty())
            .then(|| git::blob_info(&repo.path, &resolved, &file_path))
            .flatten();
        let Some(info) = info else {
            return PageReply::Drop;
        };
        // The conversion holds the file in memory; upstream converts any size.
        if fmt_set && info.size > CONVERT_SIZE_LIMIT {
            tracing::warn!("Refused conversion of {file_path}: {} bytes", info.size);
            return PageReply::Drop;
        }
        let Some(mut stream) = git::blob_stream(&repo.path, &resolved, &file_path) else {
            return PageReply::Drop;
        };
        self.stats
            .download_succeeded(&group, &name, req.identity.as_ref());
        if !fmt_set {
            return PageReply::File {
                file: stream,
                name: file_name,
            };
        }
        if fmt != "mu" {
            return PageReply::Drop;
        }
        let converted = (|| -> Option<std::fs::File> {
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).ok()?;
            let text = String::from_utf8(raw).ok()?;
            let components: Vec<&str> = file_path.trim_matches('/').split('/').collect();
            let dir = if components.len() > 1 {
                format!("{}/", components[..components.len() - 1].join("/"))
            } else {
                String::new()
            };
            let scope = format!(":/page/blob.mu`g={group}|r={name}|ref={reference}|path={dir}");
            let mu = match self.mdc_scoped(&scope).format_block(&text) {
                Ok(mu) => mu,
                Err(e) => {
                    tracing::warn!("Error during file conversion of {file_path}: {e}");
                    return None;
                }
            };
            let mu = mu.trim_end_matches(py_space);
            if mu.is_empty() {
                return None;
            }
            let mut spool = tempfile::tempfile().ok()?;
            spool.write_all(mu.as_bytes()).ok()?;
            spool.rewind().ok()?;
            Some(spool)
        })();
        match converted {
            Some(file) => PageReply::File {
                file,
                name: format!("{}.mu", stem(&file_name)),
            },
            None => PageReply::Drop,
        }
    }

    pub(crate) fn serve_wd_download(&self, req: &PageRequest<'_>) -> PageReply {
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        let mut scope = data.text("var_scope", "all");
        if !["active", "completed", "all"].contains(&scope.as_str()) {
            scope = "active".to_string();
        }
        if group.is_empty() || name.is_empty() || !data.truthy("var_id") {
            return PageReply::Drop;
        }
        let Some(doc_id) = doc_id_of(data.raw("var_id")) else {
            return PageReply::Drop;
        };
        let Some(repo) = self.accessible_repository(req.identity, &group, &name) else {
            return PageReply::Drop;
        };
        if !self.resolve_doc_permission(req.identity, &group, &name, doc_id, Perm::Read) {
            return PageReply::Drop;
        }
        let work_path = PathBuf::from(format!("{}.work", repo.path.to_string_lossy()));
        let (dir, _) = doc_dir(&work_path, doc_id, &scope);
        let root = dir.join("root");
        if !root.is_file() {
            return PageReply::Drop;
        }
        let Some(doc) = crate::server::work::load_document(&root) else {
            return PageReply::Drop;
        };
        let empty = Value::Map(Vec::new());
        let meta = field(&doc, "meta").unwrap_or(&empty);
        let fmt = field_str_or(meta, "format", "markdown");
        let title = chars(&field_str_or(meta, "title", "Untitled"), 256);
        let content = field_str_or(&doc, "content", "");
        let content = py_strip(&content);
        if content.is_empty() {
            return PageReply::Drop;
        }
        let file_name = if fmt == "micron" {
            format!("{title}.mu")
        } else {
            format!("{title}.md")
        };
        self.stats
            .download_succeeded(&group, &name, req.identity.as_ref());
        PageReply::Value(packed(&Value::Array(vec![
            Value::from(file_name),
            Value::Binary(content.as_bytes().to_vec()),
        ])))
    }
}
