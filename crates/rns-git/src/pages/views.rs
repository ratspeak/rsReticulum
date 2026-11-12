//! The `/page/*.mu` handlers (`pages.py`).

use std::path::{Path, PathBuf};
use std::time::Instant;

use rmpv::Value;

use super::git;
use super::*;
use crate::server::perms::Perm;

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn rstrip(s: &str) -> &str {
    s.trim_end_matches(py_space)
}

fn lstrip(s: &str) -> &str {
    s.trim_start_matches(py_space)
}

/// `str.capitalize()` for ASCII words.
fn capitalize(s: &str) -> String {
    let lower = s.to_lowercase();
    let mut chars = lower.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// `format_diff` (`pages.py`).
fn format_diff(diff: &str) -> String {
    let doubled = diff.replace('\\', "\\\\");
    let mut lines = Vec::new();
    for line in doubled.split('\n') {
        if line.starts_with('+') {
            if line.starts_with("+++") {
                lines.push(m_escape(line));
            } else {
                lines.push(format!("{CLR_DIFF_A}{}`f", m_escape(line)));
            }
        } else if line.starts_with('-') {
            if line.starts_with("---") {
                lines.push(m_escape(&format!("\\{line}")));
            } else {
                lines.push(format!("{CLR_DIFF_R}{}`f", m_escape(line)));
            }
        } else if line.starts_with("@@") {
            lines.push(format!("{CLR_DIFF_P}{}`f", m_escape(line)));
        } else if line.starts_with("diff ")
            || line.starts_with("index ")
            || line.starts_with("new file")
            || line.starts_with("deleted file")
        {
            if line.starts_with("diff --git a") {
                lines.push(String::new());
            }
            lines.push(format!("{CLR_DIM}{}`f", m_escape(line)));
        } else {
            lines.push(m_escape(line));
        }
    }
    lines.join("\n")
}

/// `format_commit` (`pages.py`).
fn format_commit(message: &str) -> String {
    message
        .replace('\\', "\\\\")
        .split('\n')
        .map(|line| {
            if line.starts_with('-') {
                m_escape(&format!("\\{line}"))
            } else {
                m_escape(line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Directory entries named by a decimal number, as `int(entry)` accepts them.
fn numeric_entries(dir: &Path) -> Vec<(i128, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            py_int(&name).map(|n| (n, e.path()))
        })
        .collect()
}

/// Entries whose name is all digits (`str.isdigit()`).
fn digit_entries(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .filter(|(name, _)| !name.is_empty() && name.chars().all(|c| c.is_numeric()))
        .collect()
}

fn hex_of(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::Binary(b)) if !b.is_empty() => Some(prettyhexrep(b)),
        Some(Value::String(s)) if !s.as_bytes().is_empty() => Some(prettyhexrep(s.as_bytes())),
        _ => None,
    }
}

impl PageNode {
    fn error_page(
        &self,
        heading: &str,
        level: usize,
        text: &str,
        nav: Option<&str>,
        st: Instant,
    ) -> Option<Vec<u8>> {
        Some(self.render(
            &format!("{}{text}", m_heading(heading, level)),
            nav,
            None,
            st,
        ))
    }

    fn no_ident(&self, nav: Option<&str>, st: Instant) -> Option<Vec<u8>> {
        Some(self.render("", nav, Some("no_ident"), st))
    }

    fn format_block(&self, mdc: &crate::md2micron::MarkdownToMicron, text: &str) -> Option<String> {
        match mdc.format_block(text) {
            Ok(out) => Some(out),
            Err(e) => {
                tracing::error!("Error while converting Markdown for a page: {e}");
                None
            }
        }
    }

    pub(crate) fn serve_front_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        let caller = self.caller(req.identity);
        let mut groups: Vec<(String, usize)> = Vec::new();
        {
            let repos = self.read_repos();
            for (name, group) in &repos.groups {
                let count = group
                    .repositories
                    .keys()
                    .filter(|r| repos.resolve_permission(&caller, name, r, Perm::Read))
                    .count();
                if count > 0 {
                    groups.push((name.clone(), count));
                }
            }
        }
        let nav = format!(">>\n{} /\n", m_link("Node", PATH_INDEX, &[]));
        let mut content = String::new();
        if groups.is_empty() {
            content.push_str(">>\nNo groups available\n");
        }
        for (name, count) in &groups {
            let word = if *count == 1 {
                "repository"
            } else {
                "repositories"
            };
            let link = m_link(&format!("  \u{2022} {name}"), PATH_GROUP, &[("g", name)]);
            content.push_str(&format!("{link} ({count} {word})\n"));
        }
        self.stats.view_succeeded(None, None, req.identity.as_ref());
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(Some(&nav), st);
        }
        Some(self.render(&content, Some(&nav), Some("front"), st))
    }

    pub(crate) fn serve_group_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        if group.is_empty() {
            return self.error_page("Error", 2, "\nInvalid request\n", None, st);
        }
        let nav = format!(">>\n{} / {group}\n", m_link("Node", PATH_INDEX, &[]));
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(Some(&nav), st);
        }
        let caller = self.caller(req.identity);
        let accessible: Vec<(String, PathBuf)> = {
            let repos = self.read_repos();
            repos
                .groups
                .get(&group)
                .map(|g| {
                    g.repositories
                        .iter()
                        .filter(|(r, _)| repos.resolve_permission(&caller, &group, r, Perm::Read))
                        .map(|(r, repo)| (r.clone(), repo.path.clone()))
                        .collect()
                })
                .unwrap_or_default()
        };
        if accessible.is_empty() {
            return self.error_page(
                "Group Not Found",
                2,
                "\nThe requested group was not found\n",
                Some(&nav),
                st,
            );
        }
        let mut content = m_heading(" Repositories", 1);
        content.push('\n');
        for (name, path) in &accessible {
            let link = m_link(
                &format!("  \u{2022} {name}"),
                PATH_REPO,
                &[("g", &group), ("r", name)],
            );
            content.push_str(&link);
            match git::repository_description(path) {
                Some(desc) => content.push_str(&format!(" - {desc}\n")),
                None => content.push('\n'),
            }
        }
        self.stats
            .view_succeeded(Some(&group), None, req.identity.as_ref());
        Some(self.render(&content, Some(&nav), Some("group"), st))
    }

    pub(crate) fn serve_repo_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        let reference = data.text("var_ref", "HEAD");
        let thanks = data.truthy("var_thanks");
        if group.is_empty() || name.is_empty() {
            return self.error_page("Error", 2, "\nInvalid request\n", None, st);
        }
        let repo_url = format!(
            "{CLR_DIM}rns://{}/{group}/{name}`f",
            hex::encode(self.repositories_destination)
        );
        let mut nav = format!(
            ">>\n{} / {} / {name} {repo_url}\n",
            m_link("Node", PATH_INDEX, &[]),
            m_link(&group, PATH_GROUP, &[("g", &group)])
        );
        let repo = self.accessible_repository(req.identity, &group, &name);
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(Some(&nav), st);
        }
        let Some(repo) = repo else {
            return self.error_page(
                "Not Found",
                1,
                "\nThe requested repository was not found.\n",
                Some(&nav),
                st,
            );
        };
        let repo_path = repo.path.clone();
        let repo_path_text = path_text(&repo_path);
        if repo.fork.is_some() || repo.mirror.is_some() {
            let (kind, mut source_url) = match (&repo.fork, &repo.mirror) {
                (Some(url), _) => ("fork", url.clone()),
                (None, Some(url)) => ("mirror", url.clone()),
                _ => ("retriev", "unknown source".to_string()),
            };
            let mut source_link = String::new();
            if source_url.to_lowercase().starts_with("rns://") {
                let parts: Vec<&str> = source_url.split('/').collect();
                if parts.len() == 5
                    && parts[2].chars().count() == 32
                    && let Ok(dest) = hex::decode(parts[2])
                    && let Some(recall) = &self.recall
                    && let Some(page_dest) = recall(dest.try_into().expect("16 bytes"))
                {
                    source_link = m_link_e(
                        &source_url,
                        &hex::encode(page_dest),
                        PATH_REPO,
                        &[("g", parts[3]), ("r", parts[4])],
                    );
                }
            }
            let synced = crate::server::forks::mirror_synced(&repo_path);
            let ago = (now() - synced as f64).max(0.0);
            let sync_time =
                rns_tools::format::prettytime(rns_tools::format::PyNum::Float(ago), true);
            let sync_time = sync_time.split(' ').next().unwrap_or("").to_string();
            let sync_str = format!(" `*{CLR_DIM_H}synced {sync_time} ago`f`*\n");
            let desc = format!("{kind}ed from");
            let width = format!("Node / {group} / {name}").chars().count();
            let indent = " ".repeat(width.saturating_sub(desc.chars().count()));
            if !source_link.is_empty() {
                source_url = source_link;
            }
            nav.push_str(&format!(
                "{CLR_DIM}{}{indent} {source_url}`f{sync_str}\n",
                capitalize(&desc)
            ));
        }
        let mut content = String::new();
        if let Some(desc) = git::repository_description(&repo_path) {
            content.push_str(&format!("{desc}\n\n"));
        }
        let thanks_count = self.thanks(
            &repo_path_text,
            Path::new(&format!("{repo_path_text}.thanks")),
            thanks,
            req.link_id,
        );
        let (branch_count, tag_count) = git::repository_ref_counts(&repo_path);
        let commits_count = git::resolve_ref(&repo_path, &reference)
            .map_or(0, |r| git::commit_count(&repo_path, &r));
        let active = PathBuf::from(format!("{repo_path_text}.work/active"));
        let work_count = digit_entries(&active)
            .iter()
            .filter(|(_, p)| p.is_dir())
            .count();
        let releases_path = PathBuf::from(format!("{repo_path_text}.releases"));
        let releases_count =
            crate::server::releases::list_for_pages(&releases_path).map_or(0, |(releases, _)| {
                releases
                    .iter()
                    .filter(|r| field(r, "status").and_then(Value::as_str) == Some("published"))
                    .count()
            });
        let sep = self.icon("sep");
        let gr: [(&str, &str); 2] = [("g", &group), ("r", &name)];
        content.push_str(&format!(
            "{} {sep} ",
            m_link_r(
                &format!("{} Files", self.icon("folder")),
                PATH_TREE,
                &[gr[0], gr[1], ("ref", "HEAD")]
            )
        ));
        if releases_count > 0 {
            content.push_str(&format!(
                "{} {sep} ",
                m_link_r(
                    &format!("{} Releases ({releases_count})", self.icon("package")),
                    PATH_RELEASES,
                    &gr
                )
            ));
        }
        content.push_str(&format!(
            "{} {sep} ",
            m_link_r(
                &format!("{} Work ({work_count})", self.icon("work")),
                PATH_WORK,
                &gr
            )
        ));
        content.push_str(&format!(
            "{} {sep} ",
            m_link_r(
                &format!("{} Commits ({commits_count})", self.icon("commits")),
                PATH_COMMITS,
                &[gr[0], gr[1], ("ref", "HEAD")]
            )
        ));
        content.push_str(&format!(
            "{} {sep} ",
            m_link_r(
                &format!("{} Branches ({branch_count})", self.icon("branch")),
                PATH_REFS,
                &[gr[0], gr[1], ("type", "heads")]
            )
        ));
        content.push_str(&format!(
            "{} {sep} ",
            m_link_r(
                &format!("{} Tags ({tag_count})", self.icon("tag")),
                PATH_REFS,
                &[gr[0], gr[1], ("type", "tags")]
            )
        ));
        content.push_str(&m_link_r(
            &format!("{} Thanks ({thanks_count})", self.icon("heart")),
            PATH_REPO,
            &[gr[0], gr[1], ("thanks", "y")],
        ));
        if self.resolve_permission(req.identity, &group, &name, Perm::Stats) {
            content.push_str(&format!(
                " {sep} {}",
                m_link_r(&format!("{} Stats", self.icon("stats")), PATH_STATS, &gr)
            ));
        }
        content.push_str("\n\n<");
        match git::readme_content(&repo_path) {
            Some((readme, is_markdown)) => {
                let lead = lstrip(&readme);
                if !lead.starts_with('#') && !lead.starts_with('>') {
                    content.push_str(&m_divider());
                }
                if is_markdown {
                    let scope = format!(":/page/blob.mu`g={group}|r={name}|ref={reference}|path=");
                    content.push_str(&self.format_block(&self.mdc_scoped(&scope), &readme)?);
                } else {
                    content.push_str(&format!("\n{}\n", rstrip(&readme)));
                }
            }
            None => {
                content.push_str(&m_divider());
                content.push('\n');
                content.push_str(&m_italic("No README file found in this repository."));
                content.push('\n');
            }
        }
        self.stats
            .view_succeeded(Some(&group), Some(&name), req.identity.as_ref());
        Some(self.render(&content, Some(&nav), Some("repo"), st))
    }

    pub(crate) fn serve_tree_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        let reference = data.text("var_ref", "HEAD");
        let tree_path = unquote_plus(&data.text("var_path", ""));
        let page = data.page("var_page");
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(None, st);
        }
        let Some(repo) = self.accessible_repository(req.identity, &group, &name) else {
            return self.error_page(
                "Not Found",
                1,
                "\n\nThe requested repository does not exist or you do not have access to it.\n",
                None,
                st,
            );
        };
        let repo_path = repo.path;
        let Some(resolved) = git::resolve_ref(&repo_path, &reference) else {
            let text = format!(
                "\n\nThe ref '{reference}' does not exist in this repository.\n\n{}\n",
                m_link("View All Refs", PATH_REFS, &[("g", &group), ("r", &name)])
            );
            return self.error_page("Error", 2, &text, None, st);
        };
        let mut crumbs = vec![
            m_link("Node", PATH_INDEX, &[]),
            m_link(&group, PATH_GROUP, &[("g", &group)]),
            m_link(&name, PATH_REPO, &[("g", &group), ("r", &name)]),
            m_link("files", PATH_TREE, &[("g", &group), ("r", &name)]),
        ];
        if !tree_path.is_empty() {
            let components: Vec<&str> = tree_path.trim_matches('/').split('/').collect();
            let mut current = String::new();
            for (i, component) in components.iter().enumerate() {
                current = if current.is_empty() {
                    component.to_string()
                } else {
                    format!("{current}/{component}")
                };
                if i == components.len() - 1 {
                    crumbs.push(component.to_string());
                } else {
                    crumbs.push(m_link(
                        component,
                        PATH_TREE,
                        &[
                            ("g", &group),
                            ("r", &name),
                            ("ref", &reference),
                            ("path", &current),
                        ],
                    ));
                }
            }
        } else {
            crumbs.push(String::new());
        }
        let nav = format!(">>\n{}\n", crumbs.join(" / "));
        let mut parts: Vec<String> = Vec::new();
        match git::tree_entries(&repo_path, &resolved, &tree_path) {
            None => parts.push("Error reading directory contents.\n".to_string()),
            Some(entries) if entries.is_empty() => parts.push("Empty directory.\n".to_string()),
            Some(mut entries) => {
                let i_file = self.icon("file");
                let i_folder = self.icon("folder");
                entries.sort_by_cached_key(|e| {
                    (
                        !(e.kind == "tree" || e.kind == "commit"),
                        e.name.to_lowercase(),
                    )
                });
                let total = entries.len();
                let start = page.saturating_mul(TREE_ENTRIES_PER_PAGE);
                let end = start.saturating_add(TREE_ENTRIES_PER_PAGE);
                let page_entries = entries.get(start.min(total)..end.min(total)).unwrap_or(&[]);
                parts.push(m_heading(
                    &format!("Contents: {reference} ({})", chars(&resolved, 8)),
                    2,
                ));
                parts.push("\n".to_string());
                if total > TREE_ENTRIES_PER_PAGE {
                    parts.push(format!(
                        "{CLR_DIM}Showing {}-{} of {total} entries`f\n\n",
                        start + 1,
                        end.min(total)
                    ));
                }
                let gr = |path: &str| -> Vec<(String, String)> {
                    vec![
                        ("g".into(), group.clone()),
                        ("r".into(), name.clone()),
                        ("ref".into(), reference.clone()),
                        ("path".into(), path.to_string()),
                    ]
                };
                let link_r = |label: &str, path: &str, target: &str| {
                    let f = gr(target);
                    let f: Vec<(&str, &str)> =
                        f.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                    m_link_r(label, path, &f)
                };
                if !tree_path.is_empty() {
                    let trimmed = tree_path.trim_end_matches('/');
                    let mut segs: Vec<&str> = trimmed.split('/').collect();
                    segs.pop();
                    let parent = segs.join("/");
                    parts.push(format!(
                        "{CLR_FOLDER}{}`f{}\n",
                        link_r(i_folder, PATH_TREE, &parent),
                        link_r(" ../", PATH_TREE, &parent)
                    ));
                }
                for entry in page_entries {
                    let subpath = if tree_path.is_empty() {
                        entry.name.clone()
                    } else {
                        format!("{tree_path}/{}", entry.name)
                    };
                    match entry.kind.as_str() {
                        "tree" => parts.push(format!(
                            "{CLR_FOLDER}{}`f{}\n",
                            link_r(i_folder, PATH_TREE, &subpath),
                            link_r(&format!(" {}/", entry.name), PATH_TREE, &subpath)
                        )),
                        "commit" => parts.push(format!(
                            "{CLR_FOLDER}⧉`f {} `F666(submodule)`f\n",
                            entry.name
                        )),
                        "link" => parts.push(format!(
                            "{CLR_FILE}↳`f {} `F666→ {}`f\n",
                            entry.name,
                            m_escape(entry.link_target.as_deref().unwrap_or("unknown"))
                        )),
                        _ => parts.push(format!(
                            "{CLR_FILE}{}`f{} `F666({})`f\n",
                            link_r(i_file, PATH_BLOB, &subpath),
                            link_r(&format!(" {}", entry.name), PATH_BLOB, &subpath),
                            prettysize(entry.size)
                        )),
                    }
                }
                parts.push("\n".to_string());
                if total > TREE_ENTRIES_PER_PAGE {
                    let mut links = Vec::new();
                    let fields = |p: usize| -> Vec<(String, String)> {
                        let mut f = gr(&tree_path);
                        f.push(("page".into(), p.to_string()));
                        f
                    };
                    let link = |label: &str, p: usize| {
                        let f = fields(p);
                        let f: Vec<(&str, &str)> =
                            f.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                        m_link(label, PATH_TREE, &f)
                    };
                    if page > 0 {
                        links.push(link("« Previous", page - 1));
                    }
                    let pages = total.div_ceil(TREE_ENTRIES_PER_PAGE);
                    links.push(format!("Page {} of {pages}", page + 1));
                    if end < total {
                        links.push(link("Next »", page + 1));
                    }
                    parts.push(format!("{}\n", links.join(" | ")));
                }
            }
        }
        if parts.last().is_some_and(|p| p == "\n") {
            parts.pop();
        }
        self.stats
            .view_succeeded(Some(&group), Some(&name), req.identity.as_ref());
        Some(self.render(&parts.concat(), Some(&nav), Some("tree"), st))
    }

    pub(crate) fn serve_blob_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        // No dict guard upstream: falsy data reads as empty, any other non-map raises.
        let falsy = match req.data {
            Value::Nil => true,
            Value::Boolean(b) => !b,
            Value::String(s) => s.as_bytes().is_empty(),
            Value::Binary(b) => b.is_empty(),
            Value::Array(a) => a.is_empty(),
            Value::Integer(i) => i.as_i64() == Some(0),
            _ => false,
        };
        if !falsy && !matches!(req.data, Value::Map(_)) {
            return None;
        }
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        let reference = data.text("var_ref", "HEAD");
        let mut render = data.truthy("var_render");
        let mut raw = data.truthy("var_raw");
        let file_path = unquote_plus(&data.text("var_path", ""));
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(None, st);
        }
        let Some(repo) = self.accessible_repository(req.identity, &group, &name) else {
            return self.error_page(
                "Not Found",
                1,
                "\n\nThe requested repository does not exist or you do not have access to it.\n",
                None,
                st,
            );
        };
        let repo_path = repo.path;
        let Some(resolved) = git::resolve_ref(&repo_path, &reference) else {
            let text = format!("\n\nThe ref '{reference}' does not exist in this repository.\n");
            return self.error_page("Ref Not Found", 1, &text, None, st);
        };
        if file_path.is_empty() {
            return self.error_page("Invalid Path", 1, "\n\nNo file path specified.\n", None, st);
        }
        let file_path = file_path
            .strip_prefix("./")
            .unwrap_or(&file_path)
            .replace("/./", "/");
        let ext = extension(&file_path).to_lowercase();
        let renderable = RENDERABLE_EXTS.contains(&ext.as_str());
        let convertable = CONVERTABLE_EXTS.contains(&ext.as_str());
        if !renderable {
            raw = true;
            render = false;
        } else if raw {
            render = false;
        } else if !render && RENDER_DEFAULT.contains(&ext.as_str()) {
            render = true;
        }
        let _ = raw;
        let mut crumbs = vec![
            m_link("Node", PATH_INDEX, &[]),
            m_link(&group, PATH_GROUP, &[("g", &group)]),
            m_link(&name, PATH_REPO, &[("g", &group), ("r", &name)]),
            m_link("files", PATH_TREE, &[("g", &group), ("r", &name)]),
        ];
        let components: Vec<&str> = file_path.trim_matches('/').split('/').collect();
        let mut current = String::new();
        for (i, component) in components.iter().enumerate() {
            current = if current.is_empty() {
                component.to_string()
            } else {
                format!("{current}/{component}")
            };
            if i == components.len() - 1 {
                crumbs.push(component.to_string());
            } else {
                crumbs.push(m_link(
                    component,
                    PATH_TREE,
                    &[
                        ("g", &group),
                        ("r", &name),
                        ("ref", &reference),
                        ("path", &current),
                    ],
                ));
            }
        }
        let mut nav = format!(">>\n{}\n", crumbs.join(" / "));
        let sep = self.icon("sep");
        let base = [
            ("g", group.as_str()),
            ("r", name.as_str()),
            ("ref", reference.as_str()),
            ("path", file_path.as_str()),
        ];
        let with = |extra: (&'static str, &'static str)| {
            let mut f = base.to_vec();
            f.push(extra);
            f
        };
        let dl_link = m_link("Download", FILE_DOWNLOAD, &base);
        if !renderable {
            nav.push_str(&format!("\nDisplaying Raw {sep} {dl_link}\n"));
        } else {
            let rnd = m_link("View rendered", PATH_BLOB, &with(("render", "y")));
            let raw_link = m_link("View raw", PATH_BLOB, &with(("raw", "y")));
            let mu = m_link("as micron", FILE_DOWNLOAD, &with(("fmt", "mu")));
            let controls = if render {
                format!("Displaying Rendered {sep} {raw_link}")
            } else {
                format!("Displaying Raw {sep} {rnd}")
            };
            if convertable {
                nav.push_str(&format!("\n{controls} {sep} {dl_link} {CLR_DIM}{mu}`f\n"));
            } else {
                nav.push_str(&format!("\n{controls} {sep} {dl_link}\n"));
            }
        }
        let mut content = String::new();
        match git::blob_info(&repo_path, &resolved, &file_path) {
            None => content.push_str("File not found at this ref.\n"),
            Some(info) => {
                if info.is_tree {
                    return self.serve_tree_page(req);
                }
                let type_str = if info.is_binary { "Binary" } else { "Text" };
                let symlink_str = if info.is_symlink {
                    format!(
                        " | Symlink → {}",
                        m_escape(info.symlink_target.as_deref().unwrap_or("unknown"))
                    )
                } else {
                    String::new()
                };
                content.push_str(&m_heading(
                    &format!(
                        "{file_path} {CLR_DIM_H}{reference} ({}) {type_str}, {}{symlink_str}`f\n",
                        chars(&resolved, 8),
                        prettysize(info.size)
                    ),
                    2,
                ));
                if info.is_symlink {
                    content.push_str(&format!(
                        "`*{}`*\n",
                        m_escape(info.symlink_target.as_deref().unwrap_or("unknown"))
                    ));
                } else if info.is_binary {
                    if IMAGE_EXTS.contains(&ext.as_str()) {
                        content.push_str(&format!(
                            "`(Image file`w=n`a=c`:/media/{group}/{name}/{reference}/{})\n",
                            quote_plus(&file_path)
                        ));
                    } else {
                        content.push_str(
                            "This file appears to be binary and cannot be displayed as text.\n",
                        );
                    }
                } else if info.size > BLOB_SIZE_LIMIT {
                    content.push_str(&format!(
                        "This file is {}, which exceeds the display limit of {}.\n",
                        prettysize(info.size),
                        prettysize(BLOB_SIZE_LIMIT)
                    ));
                } else {
                    match git::blob_content(&repo_path, &resolved, &file_path) {
                        Some(text) if renderable && render => {
                            if ext == ".mu" {
                                content.push_str(&format!("{}\n", rstrip(&text)));
                            } else {
                                let dir = if components.len() > 1 {
                                    format!("{}/", components[..components.len() - 1].join("/"))
                                } else {
                                    String::new()
                                };
                                let scope = format!(
                                    ":/page/blob.mu`g={group}|r={name}|ref={reference}|path={dir}"
                                );
                                let out = self.format_block(&self.mdc_scoped(&scope), &text)?;
                                content.push_str(&format!("{}\n", rstrip(&out)));
                            }
                        }
                        Some(text) => {
                            let highlighted =
                                self.highlighter.highlight(&text, Some(&file_path), None);
                            content.push_str(&format!("{}\n", rstrip(&highlighted)));
                        }
                        None => content.push_str("Error reading file content.\n"),
                    }
                }
            }
        }
        self.stats
            .view_succeeded(Some(&group), Some(&name), req.identity.as_ref());
        Some(self.render(&content, Some(&nav), Some("blob"), st))
    }

    pub(crate) fn serve_commits_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        let reference = data.text("var_ref", "HEAD");
        let file_path = unquote_plus(&data.text("var_path", ""));
        let page = data.page("var_page");
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(None, st);
        }
        let Some(repo) = self.accessible_repository(req.identity, &group, &name) else {
            return self.error_page(
                "Not Found",
                1,
                "\n\nThe requested repository does not exist or you do not have access to it.\n",
                None,
                st,
            );
        };
        let repo_path = repo.path;
        let Some(resolved) = git::resolve_ref(&repo_path, &reference) else {
            let text = format!("\n\nThe ref '{reference}' does not exist in this repository.\n");
            return self.error_page("Ref Not Found", 1, &text, None, st);
        };
        let mut crumbs = vec![
            m_link("Node", PATH_INDEX, &[]),
            m_link(&group, PATH_GROUP, &[("g", &group)]),
            m_link(&name, PATH_REPO, &[("g", &group), ("r", &name)]),
            "commits".to_string(),
        ];
        if !file_path.is_empty() {
            crumbs.insert(3, m_escape(&file_path));
        }
        let nav = format!(">>\n{}\n", crumbs.join(" / "));
        let suffix = if file_path.is_empty() {
            String::new()
        } else {
            format!(" for {file_path}")
        };
        let skip = (page as u64).saturating_mul(COMMITS_PER_PAGE as u64);
        let mut content = String::new();
        match git::commits(
            &repo_path,
            &resolved,
            &file_path,
            skip,
            COMMITS_PER_PAGE as u64,
        ) {
            None => content.push_str("Error reading commit history.\n"),
            Some(commits) if commits.is_empty() => content.push_str("No commits found.\n"),
            Some(commits) => {
                content.push_str(&m_heading(
                    &format!(
                        "Commits{suffix} {CLR_DIM_H}{reference} ({})`f",
                        chars(&resolved, 8)
                    ),
                    2,
                ));
                content.push('\n');
                for commit in &commits {
                    let date = format!(
                        "{} - {}",
                        local_time(commit.timestamp as f64, true, true),
                        relative_time(commit.timestamp)
                    );
                    let link = m_link(
                        &chars(&commit.hash, 7),
                        PATH_COMMIT,
                        &[
                            ("g", &group),
                            ("r", &name),
                            ("ref", &reference),
                            ("h", &commit.hash),
                        ],
                    );
                    content.push_str(&format!(
                        "`F66d{link}`f {} {CLR_DIM}{date}`f\n",
                        m_escape(&commit.author)
                    ));
                    content.push_str(&format!("{}\n\n", m_escape(&commit.subject)));
                }
                let has_more = commits.len() == COMMITS_PER_PAGE;
                if page > 0 || has_more {
                    let link = |label: &str, p: usize| {
                        let p = p.to_string();
                        m_link(
                            label,
                            PATH_COMMITS,
                            &[
                                ("g", &group),
                                ("r", &name),
                                ("ref", &reference),
                                ("path", &file_path),
                                ("page", &p),
                            ],
                        )
                    };
                    let mut links = Vec::new();
                    if page > 0 {
                        links.push(link("« Newer", page - 1));
                    }
                    links.push(format!("Page {}", page + 1));
                    if has_more {
                        links.push(link("Older »", page + 1));
                    }
                    content.push_str(&format!("{}\n", links.join(" | ")));
                }
            }
        }
        self.stats
            .view_succeeded(Some(&group), Some(&name), req.identity.as_ref());
        Some(self.render(&content, Some(&nav), Some("commits"), st))
    }

    pub(crate) fn serve_commit_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        let reference = data.text("var_ref", "HEAD");
        let commit_hash = data.text("var_h", "");
        if group.is_empty() || name.is_empty() {
            return self.error_page("Error", 2, "\nInvalid request\n", None, st);
        }
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(None, st);
        }
        let Some(repo) = self.accessible_repository(req.identity, &group, &name) else {
            return self.error_page(
                "Error",
                2,
                "\nThe requested repository was not found.\n",
                None,
                st,
            );
        };
        let repo_path = repo.path;
        if git::resolve_ref(&repo_path, &reference).is_none() {
            let text = format!("\n\nThe ref '{reference}' does not exist in this repository.\n");
            return self.error_page("Ref Not Found", 1, &text, None, st);
        }
        if commit_hash.chars().count() < 7 {
            return self.error_page("Error", 2, "\nNo valid commit hash specified.\n", None, st);
        }
        let Some(resolved) = git::resolve_ref(&repo_path, &commit_hash) else {
            let text = format!("\nThe commit {commit_hash} does not exist in this repository.\n");
            return self.error_page("Error", 2, &text, None, st);
        };
        let nav = format!(
            ">>\n{} / {} / {} / {} / {}\n",
            m_link("Node", PATH_INDEX, &[]),
            m_link(&group, PATH_GROUP, &[("g", &group)]),
            m_link(&name, PATH_REPO, &[("g", &group), ("r", &name)]),
            m_link(
                "commits",
                PATH_COMMITS,
                &[("g", &group), ("r", &name), ("ref", &reference)]
            ),
            chars(&resolved, 7)
        );
        match git::is_commit(&repo_path, &resolved) {
            Ok(true) => {}
            Ok(false) => {
                let text = format!("\nThe hash {commit_hash} does not refer to a commit.\n");
                return self.error_page("Error", 2, &text, None, st);
            }
            Err(git::RunError::Timeout) => tracing::warn!("Git command execution timed out"),
            Err(git::RunError::Failed) => {
                return self.error_page(
                    "Error",
                    2,
                    "\nCould not verify commit object.\n",
                    None,
                    st,
                );
            }
        }
        let Some(info) = git::commit_info(&repo_path, &resolved) else {
            return self.error_page(
                "Error",
                2,
                "\n\nCould not retrieve commit information.\n",
                None,
                st,
            );
        };
        let mut content = m_heading(&format!("Commit {resolved}"), 2);
        content.push('\n');
        content.push_str(&format!(
            "{}\n\n",
            m_link(
                &format!("{} Browse tree at this commit", self.icon("folder")),
                PATH_TREE,
                &[("g", &group), ("r", &name), ("ref", &resolved)]
            )
        ));
        let sig = git::commit_signature(&repo_path, &resolved);
        let sig_text = if !sig.signed {
            None
        } else if sig.valid && sig.author_match {
            Some("`FT66BB85Valid, signed by author`f".to_string())
        } else if sig.valid {
            Some(format!("`Faa0{}`f", m_escape(&sig.message)))
        } else {
            Some(format!("`F900{}`f", m_escape(&sig.message)))
        };
        if !info.parents.is_empty() {
            let links: Vec<String> = info
                .parents
                .iter()
                .map(|p| {
                    m_link(
                        &chars(p, 7),
                        PATH_COMMIT,
                        &[("g", &group), ("r", &name), ("ref", &reference), ("h", p)],
                    )
                })
                .collect();
            content.push_str(&format!("Parents    : {}\n", links.join(" ")));
        }
        content.push_str(&format!(
            "Author     : {} <{}>\n",
            m_escape(&info.author_name),
            m_escape(&info.author_email)
        ));
        if let Some(sig_text) = sig_text {
            content.push_str(&format!("Signature  : {sig_text}\n"));
        }
        content.push_str(&format!("Date       : {}\n", info.author_date));
        if info.committer_name != info.author_name {
            content.push_str(&format!(
                "Committer : {} <{}>\n",
                m_escape(&info.committer_name),
                m_escape(&info.committer_email)
            ));
            content.push_str(&format!("Date      : {}\n", info.committer_date));
        }
        content.push('\n');
        if !info.message.is_empty() {
            content.push_str(&format!("{}\n\n", format_commit(&info.message)));
        }
        if !info.files.is_empty() {
            content.push_str(&m_heading("Changes", 2));
            content.push('\n');
            let adds: i64 = info.files.iter().map(|f| f.additions).sum();
            let dels: i64 = info.files.iter().map(|f| f.deletions).sum();
            content.push_str(&format!(
                "  {} files changed, {adds} insertions(+), {dels} deletions(-)\n\n",
                info.files.len()
            ));
            for file in &info.files {
                let status = match file.status {
                    "A" => "`F0a0A`f",
                    "D" => "`F900D`f",
                    "M" => "`Faa0M`f",
                    "R" => "`F0aaR`f",
                    other => other,
                };
                let link = m_link(
                    &m_escape(&file.path),
                    PATH_BLOB,
                    &[
                        ("g", &group),
                        ("r", &name),
                        ("ref", &resolved),
                        ("path", &file.path),
                    ],
                );
                let mut stats = Vec::new();
                if file.additions > 0 {
                    stats.push(format!("`F0a0+{}`f", file.additions));
                }
                if file.deletions > 0 {
                    stats.push(format!("`F900-{}`f", file.deletions));
                }
                content.push_str(&format!("  {status} {link} {}\n", stats.join(" ")));
            }
            content.push('\n');
        }
        if let Some(diff) = info.diff.as_deref().filter(|d| !d.is_empty()) {
            content.push_str(&m_heading("Diff", 2));
            content.push('\n');
            content.push_str(lstrip(&format_diff(diff)));
        }
        self.stats
            .view_succeeded(Some(&group), Some(&name), req.identity.as_ref());
        Some(self.render(&content, Some(&nav), Some("commit"), st))
    }

    pub(crate) fn serve_refs_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        let ref_type = data.text("var_type", "");
        let nav = format!(
            ">>\n{} / {} / {} / refs\n",
            m_link("Node", PATH_INDEX, &[]),
            m_link(&group, PATH_GROUP, &[("g", &group)]),
            m_link(&name, PATH_REPO, &[("g", &group), ("r", &name)])
        );
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(None, st);
        }
        if group.is_empty() || name.is_empty() {
            return self.error_page("Error", 2, "\nInvalid request\n", None, st);
        }
        let Some(repo) = self.accessible_repository(req.identity, &group, &name) else {
            return self.error_page(
                "Error",
                2,
                "\nThe requested repository was not found.\n",
                Some(&nav),
                st,
            );
        };
        let repo_path = repo.path;
        let sep = self.icon("sep");
        let gr = [("g", group.as_str()), ("r", name.as_str())];
        let mut content = format!(
            "{}\n\n",
            [
                m_link("All", PATH_REFS, &gr),
                m_link(
                    "Branches only",
                    PATH_REFS,
                    &[gr[0], gr[1], ("type", "heads")]
                ),
                m_link("Tags only", PATH_REFS, &[gr[0], gr[1], ("type", "tags")]),
            ]
            .join(&format!(" {sep} "))
        );
        let default_branch = git::default_branch(&repo_path);
        let show_heads = ref_type.is_empty() || ref_type == "heads";
        let show_tags = ref_type.is_empty() || ref_type == "tags";
        let (heads, tags) = git::refs_info(&repo_path, default_branch.as_deref());
        if show_heads && !heads.is_empty() {
            content.push_str(&m_heading(&format!("Branches ({})", heads.len()), 2));
            content.push('\n');
            for info in &heads {
                let display = if info.is_default {
                    format!("`F0a0{}`f", info.name)
                } else {
                    info.name.clone()
                };
                let marker = if info.is_default {
                    " `F0a0(default)`f"
                } else {
                    ""
                };
                let at = [gr[0], gr[1], ("ref", info.name.as_str())];
                content.push_str(&format!(
                    "{display}{marker} [{}] [{}]\n",
                    m_link("tree", PATH_TREE, &at),
                    m_link("commits", PATH_COMMITS, &at)
                ));
                content.push_str(&format!(
                    "{}: {}\n\n",
                    info.short_hash,
                    m_escape(&info.commit_subject)
                ));
            }
        }
        if show_tags && !tags.is_empty() {
            content.push_str(&m_heading(&format!("Tags ({})", tags.len()), 2));
            content.push('\n');
            for info in tags.iter().rev() {
                let marker = if info.is_annotated {
                    " `Faa0(annotated)`f"
                } else {
                    ""
                };
                let at = [gr[0], gr[1], ("ref", info.name.as_str())];
                content.push_str(&format!(
                    "{}{marker} {CLR_DIM}{}`f [{}] [{}]\n",
                    info.name,
                    info.short_hash,
                    m_link("tree", PATH_TREE, &at),
                    m_link("commits", PATH_COMMITS, &at)
                ));
                match info
                    .tag_message
                    .as_deref()
                    .filter(|m| info.is_annotated && !m.is_empty())
                {
                    Some(message) => {
                        content.push_str(&format!("{}\n\n", m_escape(&chars(message, 512))))
                    }
                    None => content.push_str(&format!("{}\n\n", m_escape(&info.commit_subject))),
                }
            }
        }
        if (show_heads && heads.is_empty()) && (show_tags && tags.is_empty()) {
            content.push_str("No refs found in this repository.\n");
        }
        self.stats
            .view_succeeded(Some(&group), Some(&name), req.identity.as_ref());
        let content = format!("{}\n", rstrip(&content));
        Some(self.render(&content, Some(&nav), Some("refs"), st))
    }

    pub(crate) fn serve_stats_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        if group.is_empty() || name.is_empty() {
            return self.error_page("Error", 2, "\nInvalid request\n", None, st);
        }
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(None, st);
        }
        let nav = format!(
            ">>\n{} / {} / {} / stats\n",
            m_link("Node", PATH_INDEX, &[]),
            m_link(&group, PATH_GROUP, &[("g", &group)]),
            m_link(&name, PATH_REPO, &[("g", &group), ("r", &name)])
        );
        let repo = self.accessible_repository(req.identity, &group, &name);
        let permitted = self.resolve_permission(req.identity, &group, &name, Perm::Stats);
        if repo.is_none() || !permitted {
            return self.error_page(
                "Error",
                2,
                "\nThe requested repository was not found.\n",
                Some(&nav),
                st,
            );
        }
        let stats = {
            let repos = self.read_repos();
            self.stats
                .repository_stats(&repos, &self.caller(req.identity), &group, &name, 90)
        };
        let Some(stats) = stats else {
            return self.error_page(
                "Stats Unavailable",
                2,
                "\nCould not retrieve statistics for this repository.\n",
                Some(&nav),
                st,
            );
        };
        let (act_color, act_label) = match stats.activity_level {
            "inactive" => ("`F666", "No activity"),
            "low" => ("`F66d", "Low activity"),
            "moderate" => ("`Faa0", "Moderate activity"),
            "high" => ("`F0a0", "High activity"),
            _ => ("`F666", "Unknown"),
        };
        let today = |s: &crate::server::stats::Series| *s.daily.last().unwrap_or(&0);
        let (v, f, p, d) = (
            &stats.views,
            &stats.fetches,
            &stats.pushes,
            &stats.downloads_combined,
        );
        let mut content = m_heading(&format!("Stats for {name}"), 2);
        content.push_str(&format!(
            "\n`FT{RCLR_FETCH}Fetches`f   : {:>5}  total {CLR_DIM}  today: {:>3}  peak: {:>3} \n`f",
            f.total,
            today(f),
            f.peak
        ));
        content.push_str(&format!(
            "`FT{RCLR_PUSH}Pushes`f    : {:>5}  total {CLR_DIM}  today: {:>3}  peak: {:>3} \n`f",
            p.total,
            today(p),
            p.peak
        ));
        content.push_str(&format!(
            "`FT{RCLR_VIEW}Views`f     : {:>5}  total {CLR_DIM}  today: {:>3}  peak: {:>3} `f\n",
            v.total,
            today(v),
            v.peak
        ));
        content.push_str(&format!(
            "`FT{RCLR_DOWNLOAD}Downloads`f : {:>5}  total {CLR_DIM}  today: {:>3}  peak: {:>3} `f\n",
            d.total,
            today(d),
            d.peak
        ));
        content.push_str(&format!(
            "`F0aaActivity`f  : {:>5} points\n\n",
            stats.activity_score
        ));
        content.push_str(&format!(
            "{act_color}{act_label}`f over the last {} days ({})\n\n",
            stats.actual_days, stats.date_range
        ));
        let labels = &stats.timeline_labels;
        let charts: [(&str, &crate::server::stats::Series, &str, &str, Option<f64>); 4] = [
            ("Fetches", f, RCLR_FETCH, RCLR_FETCH_G, None),
            ("Pushes", p, RCLR_PUSH, RCLR_PUSH_G, None),
            ("Views", v, RCLR_VIEW, RCLR_VIEW_G, None),
            ("Downloads", d, RCLR_DOWNLOAD, RCLR_DOWNLOAD_G, Some(1.7)),
        ];
        for (title, series, color, secondary, factor) in charts {
            if series.total > 0 {
                content.push_str(&m_heading(title, 2));
                content.push('\n');
                content.push_str(&render_chart(
                    &series.daily,
                    labels,
                    color,
                    Some(secondary),
                    factor,
                ));
                content.push('\n');
            }
        }
        if stats.activity_score > 0 {
            content.push_str(&m_heading("Combined Activity", 2));
            content.push('\n');
            content.push_str(&render_combined_chart(
                &v.daily, &f.daily, &p.daily, &d.daily, labels,
            ));
        } else {
            content.push_str(&m_italic(
                "\nNo development activity recorded for this repository in the selected time period.\n\n",
            ));
        }
        Some(self.render(&content, Some(&nav), Some("stats"), st))
    }

    pub(crate) fn serve_releases_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        if group.is_empty() || name.is_empty() {
            return self.error_page("Error", 2, "\nInvalid request\n", None, st);
        }
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(None, st);
        }
        let Some(repo) = self.accessible_repository(req.identity, &group, &name) else {
            return self.error_page(
                "Error",
                2,
                "\nThe requested repository was not found.\n",
                None,
                st,
            );
        };
        let nav = format!(
            ">>\n{} / {} / {} / releases\n",
            m_link("Node", PATH_INDEX, &[]),
            m_link(&group, PATH_GROUP, &[("g", &group)]),
            m_link(&name, PATH_REPO, &[("g", &group), ("r", &name)])
        );
        let releases_path = PathBuf::from(format!("{}.releases", path_text(&repo.path)));
        let (releases, latest) =
            crate::server::releases::list_for_pages(&releases_path).unwrap_or((Vec::new(), None));
        if releases.is_empty() {
            let content = format!(
                "{}\nNo releases available for this repository.\n",
                m_heading("Releases", 2)
            );
            return Some(self.render(&content, Some(&nav), Some("repo"), st));
        }
        let published: Vec<&Value> = releases
            .iter()
            .filter(|r| field(r, "status").and_then(Value::as_str) == Some("published"))
            .collect();
        let mut content = m_heading(&format!("Releases ({})", published.len()), 2);
        content.push('\n');
        let sep = self.icon("sep");
        for rel in published {
            let tag = field_str_or(rel, "tag", "unknown");
            let created = field_num(rel, "created");
            let date = if created != 0.0 {
                local_time(created, false, false)
            } else {
                "unknown".to_string()
            };
            let artifacts = field_num(rel, "artifacts") as i64;
            let format = field_str_or(rel, "format", "markdown");
            let full = field_str_or(rel, "preview", "");
            // Upstream raises IndexError on an empty preview and sends nothing.
            let first = *crate::server::releases::splitlines(&full).first()?;
            let mut preview = chars(first, 2048);
            if first.chars().count() > preview.chars().count() {
                preview.push('…');
            }
            let link = m_link(
                &tag,
                PATH_RELEASE,
                &[("g", &group), ("r", &name), ("t", &tag)],
            );
            let latest_str = if latest.as_deref() == Some(tag.as_str()) {
                format!(" {sep} {CLR_OK_DIM}`*Latest`*`f")
            } else {
                String::new()
            };
            let plural = if artifacts != 1 { "s" } else { "" };
            content.push_str(&format!(
                "{link} {CLR_DIM}{date} {sep} `*{artifacts} artifact{plural}`*{latest_str}`f\n"
            ));
            if !preview.is_empty() {
                match format.as_str() {
                    "markdown" => {
                        content.push_str(&format!("{}\n", self.format_block(&self.mdc, &preview)?))
                    }
                    "micron" => content.push_str(&format!("{preview}\n")),
                    _ => content.push_str(&format!("{}\n", m_escape(&preview))),
                }
            }
            content.push('\n');
        }
        self.stats
            .view_succeeded(Some(&group), Some(&name), req.identity.as_ref());
        let content = format!("{}\n", rstrip(&content));
        Some(self.render(&content, Some(&nav), Some("releases"), st))
    }

    pub(crate) fn serve_release_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        let mut tag = data.text("var_t", "");
        if group.is_empty() || name.is_empty() || tag.is_empty() {
            return self.error_page("Error", 2, "\nInvalid request\n", None, st);
        }
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(None, st);
        }
        let Some(repo) = self.accessible_repository(req.identity, &group, &name) else {
            return self.error_page(
                "Error",
                2,
                "\nThe requested repository was not found.\n",
                None,
                st,
            );
        };
        let nav = format!(
            ">>\n{} / {} / {} / {} / {tag}\n",
            m_link("Node", PATH_INDEX, &[]),
            m_link(&group, PATH_GROUP, &[("g", &group)]),
            m_link(&name, PATH_REPO, &[("g", &group), ("r", &name)]),
            m_link("releases", PATH_RELEASES, &[("g", &group), ("r", &name)])
        );
        let releases_path = PathBuf::from(format!("{}.releases", path_text(&repo.path)));
        if tag == "latest" {
            let (releases, latest) = crate::server::releases::list_for_pages(&releases_path)
                .unwrap_or((Vec::new(), None));
            if releases.is_empty() {
                return self.error_page(
                    "Release Not Found",
                    2,
                    "\nNo releases exist.\n",
                    Some(&nav),
                    st,
                );
            }
            tag = match latest {
                Some(latest) => latest,
                None => field_str_or(&releases[0], "tag", ""),
            };
        }
        let missing = format!("\nThe release {tag} does not exist.\n");
        // A tag that is not a plain name would leave the releases directory.
        let release_dir = releases_path.join(&tag);
        if !plain_name(&tag) || !release_dir.is_dir() {
            return self.error_page("Release Not Found", 2, &missing, Some(&nav), st);
        }
        let Some(info) = crate::server::releases::data_for_pages(&release_dir, &tag) else {
            return self.error_page(
                "Error",
                2,
                "\nCould not load release data.\n",
                Some(&nav),
                st,
            );
        };
        if field(&info, "status").and_then(Value::as_str) != Some("published") {
            return self.error_page("Release Not Found", 2, &missing, Some(&nav), st);
        }
        let sep = self.icon("sep");
        let release_text = path_text(&release_dir);
        let thanks = self.thanks(
            &release_text,
            &release_dir.join("THANKS"),
            data.truthy("var_thanks"),
            req.link_id,
        );
        let mut content = format!(
            "{}\n\n",
            m_link_r(
                &format!("{} Thanks ({thanks})", self.icon("heart")),
                PATH_RELEASE,
                &[("g", &group), ("r", &name), ("t", &tag), ("thanks", "y")]
            )
        );
        let created = field_num(&info, "created");
        let ts = if created != 0.0 {
            format!(" {sep} {}", local_time(created, true, true))
        } else {
            String::new()
        };
        content.push_str(&m_heading(&format!("Release {tag}{ts}"), 2));
        content.push('\n');
        let notes = field_str_or(&info, "notes", "");
        if !notes.is_empty() {
            match field_str_or(&info, "notes_format", "text").as_str() {
                "micron" => content.push_str(&format!("{notes}\n")),
                "markdown" => {
                    content.push_str(&format!("{}\n", self.format_block(&self.mdc, &notes)?))
                }
                _ => content.push_str(&format!("`={notes}`=\n")),
            }
            content.push('\n');
        }
        let mut artifacts: Vec<(String, u64)> = match field(&info, "artifacts") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|a| {
                    (
                        field_str_or(a, "name", "unknown"),
                        field_num(a, "size") as u64,
                    )
                })
                .collect(),
            _ => Vec::new(),
        };
        if artifacts.is_empty() {
            content.push_str(&m_heading("Artifacts", 2));
            content.push_str("\n`*No artifacts for this release`*\n");
        } else {
            artifacts.sort_by(|a, b| a.0.cmp(&b.0));
            content.push_str(&m_heading(&format!("Artifacts ({})", artifacts.len()), 2));
            content.push('\n');
            for (art, size) in &artifacts {
                let fields = [
                    ("g", group.as_str()),
                    ("r", name.as_str()),
                    ("t", tag.as_str()),
                    ("a", art.as_str()),
                ];
                let l1 = m_link_r(
                    &format!("{} {}", self.icon("file"), m_escape(art)),
                    FILE_ARTIFACT,
                    &fields,
                );
                let l2 = m_link_r(&format!("({})", prettysize(*size)), FILE_ARTIFACT, &fields);
                content.push_str(&format!("{l1} {CLR_DIM}{l2}`f\n"));
            }
        }
        self.stats
            .view_succeeded(Some(&group), Some(&name), req.identity.as_ref());
        Some(self.render(&content, Some(&nav), Some("release"), st))
    }

    pub(crate) fn serve_work_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        let mut scope = data.text("var_scope", "active");
        if !["active", "completed", "proposed", "all"].contains(&scope.as_str()) {
            scope = "active".to_string();
        }
        if group.is_empty() || name.is_empty() {
            return self.error_page("Error", 2, "\nInvalid request\n", None, st);
        }
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(None, st);
        }
        let Some(repo) = self.accessible_repository(req.identity, &group, &name) else {
            return self.error_page(
                "Error",
                2,
                "\nThe requested repository was not found.\n",
                None,
                st,
            );
        };
        let work_path = PathBuf::from(format!("{}.work", path_text(&repo.path)));
        let scopes: Vec<&str> = if scope == "all" {
            vec!["active", "completed", "proposed"]
        } else {
            vec![scope.as_str()]
        };
        let nav = format!(
            ">>\n{} / {} / {} / work\n",
            m_link("Node", PATH_INDEX, &[]),
            m_link(&group, PATH_GROUP, &[("g", &group)]),
            m_link(&name, PATH_REPO, &[("g", &group), ("r", &name)])
        );
        let sep = self.icon("sep");
        let mut counts = [0usize; 3];
        for (i, s) in ["active", "completed", "proposed"].iter().enumerate() {
            for (doc_id, dir) in numeric_entries(&work_path.join(s)) {
                if dir.is_dir()
                    && self.resolve_doc_permission(req.identity, &group, &name, doc_id, Perm::Read)
                    && dir.join("root").is_file()
                {
                    counts[i] += 1;
                }
            }
        }
        let total: usize = counts.iter().sum();
        let filter = |label: &str, s: &str, count: usize| {
            let u = if scope == s { "`_" } else { "" };
            format!(
                "{u}{}{u} ({count})",
                m_link(
                    label,
                    PATH_WORK,
                    &[("g", &group), ("r", &name), ("scope", s)]
                )
            )
        };
        let mut parts = vec![format!(
            "{}\n\n",
            [
                filter("Active", "active", counts[0]),
                filter("Completed", "completed", counts[1]),
                filter("Proposed", "proposed", counts[2]),
                filter("All", "all", total),
            ]
            .join(&format!(" {sep} "))
        )];
        struct Doc {
            id: i128,
            title: String,
            created: f64,
            edited: f64,
            author: Option<String>,
            comments: usize,
        }
        for s in scopes {
            let mut docs = Vec::new();
            for (doc_id, dir) in numeric_entries(&work_path.join(s)) {
                if !dir.is_dir()
                    || !self.resolve_doc_permission(req.identity, &group, &name, doc_id, Perm::Read)
                {
                    continue;
                }
                let root = dir.join("root");
                if !root.is_file() {
                    continue;
                }
                let Some(doc) = crate::server::work::load_document(&root) else {
                    continue;
                };
                let empty = Value::Map(Vec::new());
                let meta = field(&doc, "meta").unwrap_or(&empty);
                let comments = digit_entries(&dir)
                    .iter()
                    .filter(|(_, p)| p.is_file())
                    .count();
                docs.push(Doc {
                    id: doc_id,
                    title: field_str_or(meta, "title", "Untitled"),
                    created: field_num(meta, "created"),
                    edited: field_num(meta, "edited"),
                    author: hex_of(field(meta, "author")),
                    comments,
                });
            }
            docs.sort_by(|a, b| {
                b.created
                    .max(b.edited)
                    .partial_cmp(&a.created.max(a.edited))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            let heading = m_heading(&capitalize(s), 2);
            if docs.is_empty() {
                parts.push(format!("{heading}\n`*No {s} work documents`*\n"));
                parts.push("\n".to_string());
                continue;
            }
            parts.push(heading);
            parts.push("\n".to_string());
            for doc in &docs {
                let mut title = chars(&doc.title, 92);
                if title.chars().count() < doc.title.chars().count() {
                    title.push('…');
                }
                let id = doc.id.to_string();
                let link = m_link(
                    &format!("{} {title}", self.icon("file")),
                    PATH_WORK_DOC,
                    &[("g", &group), ("r", &name), ("id", &id), ("scope", s)],
                );
                let date = if doc.created != 0.0 {
                    local_time(doc.created, false, false)
                } else {
                    String::new()
                };
                parts.push(format!("{link} {CLR_DIM}#{id}`f\n"));
                parts.push(format!(
                    "{CLR_DIM}{date} by {}`f\n",
                    doc.author.as_deref().unwrap_or("unknown")
                ));
                if doc.comments > 0 {
                    parts.push(format!("{CLR_DIM}{} updates`f\n", doc.comments));
                }
                parts.push("\n".to_string());
            }
        }
        if parts.last().is_some_and(|p| p == "\n") {
            parts.pop();
        }
        self.stats
            .view_succeeded(Some(&group), Some(&name), req.identity.as_ref());
        Some(self.render(&parts.concat(), Some(&nav), Some("work"), st))
    }

    pub(crate) fn serve_work_doc_page(&self, req: &PageRequest<'_>) -> Option<Vec<u8>> {
        let st = Instant::now();
        let data = Data::of(req.data);
        let group = data.text("var_g", "");
        let name = data.text("var_r", "");
        let mut scope = data.text("var_scope", "all");
        if !["active", "completed", "proposed", "all"].contains(&scope.as_str()) {
            scope = "active".to_string();
        }
        if group.is_empty() || name.is_empty() || !data.truthy("var_id") {
            return self.error_page("Error", 2, "\nInvalid request\n", None, st);
        }
        if self.blocked_unidentified(req.identity) {
            return self.no_ident(None, st);
        }
        let Some(doc_id) = doc_id_of(data.raw("var_id")) else {
            return self.error_page("Error", 2, "\nInvalid document ID\n", None, st);
        };
        let Some(repo) = self.accessible_repository(req.identity, &group, &name) else {
            return self.error_page(
                "Error",
                2,
                "\nThe requested repository was not found\n",
                None,
                st,
            );
        };
        if !self.resolve_doc_permission(req.identity, &group, &name, doc_id, Perm::Read) {
            return self.error_page(
                "Error",
                2,
                "\nThe requested work document was not found\n",
                None,
                st,
            );
        }
        let work_path = PathBuf::from(format!("{}.work", path_text(&repo.path)));
        let (doc_dir, scope) = doc_dir(&work_path, doc_id, &scope);
        let root = doc_dir.join("root");
        if !root.is_file() {
            return self.error_page(
                "Not Found",
                2,
                "\nThe requested work document was not found\n",
                None,
                st,
            );
        }
        let Some(doc) = crate::server::work::load_document(&root) else {
            return self.error_page("Error", 2, "\nCould not load work document\n", None, st);
        };
        // `doc['meta']` raises when the document has no meta map.
        let meta = field(&doc, "meta").filter(|m| matches!(m, Value::Map(_)))?;
        let id = doc_id.to_string();
        let nav = format!(
            ">>\n{} / {} / {} / {} / #{id}\n\n{}\n",
            m_link("Node", PATH_INDEX, &[]),
            m_link(&group, PATH_GROUP, &[("g", &group)]),
            m_link(&name, PATH_REPO, &[("g", &group), ("r", &name)]),
            m_link("work", PATH_WORK, &[("g", &group), ("r", &name)]),
            m_link(
                "Download",
                FILE_WORKDOC,
                &[("g", &group), ("r", &name), ("id", &id)]
            )
        );
        let full_title = field_str_or(meta, "title", "Untitled");
        let mut title = chars(&full_title, 256);
        if title.chars().count() < full_title.chars().count() {
            title.push('…');
        }
        let author = hex_of(field(meta, "author")).unwrap_or_else(|| "Unknown".to_string());
        let created = field_num(meta, "created");
        let edited = field_num(meta, "edited");
        let format = field_str_or(meta, "format", "markdown");
        let body = field_str_or(&doc, "content", "");
        let mut signature_str = "Document not signed";
        if let Some(Value::Binary(sig)) = field(meta, "signature")
            && sig.len() == 64
            && let Some(Value::Binary(key)) = field(meta, "identity")
            && key.len() == 64
        {
            signature_str = "Not valid";
            if let Ok(identity) = rns_identity::identity::Identity::from_public_key(key)
                && identity.verify(
                    body.as_bytes(),
                    sig.as_slice().try_into().expect("64 bytes"),
                )
            {
                signature_str = "Valid";
            }
        }
        let mut content = m_heading(&title, 2);
        content.push_str(&format!("\n{CLR_DIM}Author    : {author}`f\n"));
        content.push_str(&format!("{CLR_DIM}Signature : {signature_str}`f\n"));
        let created_str = if created != 0.0 {
            local_time(created, true, false)
        } else {
            "unknown".to_string()
        };
        content.push_str(&format!("{CLR_DIM}Created   : {created_str}`f\n"));
        if edited != 0.0 && edited != created {
            content.push_str(&format!(
                "{CLR_DIM}Edited    : {}`f\n",
                local_time(edited, true, false)
            ));
        }
        content.push_str(&format!(
            "{CLR_DIM}Status    : {}`f\n\n",
            capitalize(&scope)
        ));
        let body = py_strip(&body);
        if !body.is_empty() {
            if format == "micron" {
                content.push_str(body);
            } else {
                content.push_str(&self.format_block(&self.mdc, body)?);
            }
            content.push('\n');
        }
        let mut comments = Vec::new();
        if doc_dir.is_dir() {
            for (entry, path) in digit_entries(&doc_dir) {
                if !path.is_file() {
                    continue;
                }
                let (Some(cid), Some(comment)) =
                    (py_int(&entry), crate::server::work::load_document(&path))
                else {
                    continue;
                };
                let empty = Value::Map(Vec::new());
                let cmeta = field(&comment, "meta").unwrap_or(&empty);
                comments.push((
                    cid,
                    field_str_or(&comment, "format", "markdown"),
                    field_str_or(&comment, "content", ""),
                    field_num(cmeta, "created"),
                    hex_of(field(cmeta, "author")),
                ));
            }
        }
        comments.sort_by_key(|c| c.0);
        if !comments.is_empty() {
            content.push_str(&format!(
                "\n{}",
                m_heading(&format!("Updates ({})", comments.len()), 2)
            ));
            for (cid, fmt, text, created, author) in &comments {
                let text = if fmt == "markdown" {
                    self.format_block(&self.mdc, text)?
                } else {
                    text.clone()
                };
                let date = if *created != 0.0 {
                    local_time(*created, true, false)
                } else {
                    "unknown".to_string()
                };
                content.push_str(&format!(
                    "\n{CLR_DIM}#{cid} by {} on {date}`f\n",
                    author.as_deref().unwrap_or("Unknown")
                ));
                content.push_str(&format!("{text}\n"));
            }
        }
        self.stats
            .view_succeeded(Some(&group), Some(&name), req.identity.as_ref());
        Some(self.render(&content, Some(&nav), Some("work_doc"), st))
    }
}

/// `int(doc_id)` on the request value.
pub(crate) fn doc_id_of(value: Option<&Value>) -> Option<i128> {
    match value? {
        Value::Integer(i) => i.as_i64().map(i128::from),
        Value::Boolean(b) => Some(i128::from(*b)),
        Value::F64(f) if f.is_finite() => Some(*f as i128),
        Value::F32(f) if f.is_finite() => Some(*f as i128),
        Value::String(s) => s.as_str().and_then(py_int),
        Value::Binary(b) => std::str::from_utf8(b).ok().and_then(py_int),
        _ => None,
    }
}

/// The document directory for a scope; `all` takes the first scope holding it.
pub(crate) fn doc_dir(work_path: &Path, doc_id: i128, scope: &str) -> (PathBuf, String) {
    let dir = |s: &str| work_path.join(s).join(doc_id.to_string());
    match scope {
        "all" => {
            for s in ["active", "completed"] {
                if dir(s).is_dir() {
                    return (dir(s), s.to_string());
                }
            }
            (dir("proposed"), "proposed".to_string())
        }
        s => (dir(s), s.to_string()),
    }
}
