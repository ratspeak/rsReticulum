//! Node statistics: the stats file, the recording gates and the repository
//! summary (`server.py`).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rmpv::Value;

/// `stats_job_interval` (`server.py`), seconds between writes of the file.
pub const STATS_JOB_INTERVAL: u64 = 180;

/// A node of the stats tree. Maps refer to children by index, so one child can
/// sit under several keys, as Python objects do.
#[derive(Debug, Clone)]
enum Node {
    Map(Vec<(Value, usize)>),
    Leaf(Value),
}

/// The stats tree in an arena.
///
/// Upstream creates missing groups and repositories from the class attributes
/// `STATS_INIT_GROUP` and `STATS_INIT_REPO` without copying them
/// (`server.py`), so every group and repository first recorded in a
/// process is the same object, and counts recorded under one show under all.
#[derive(Debug)]
struct Tree {
    nodes: Vec<Node>,
    root: usize,
    init_group: usize,
    init_repo: usize,
}

const REPO_METRICS: [&str; 5] = ["view", "fetch", "push", "download", "release_download"];

impl Tree {
    fn new() -> Self {
        let mut tree = Tree {
            nodes: Vec::new(),
            root: 0,
            init_group: 0,
            init_repo: 0,
        };
        let front = tree.empty_map();
        let pages = tree.map_of(vec![("front", front)]);
        let groups = tree.empty_map();
        tree.root = tree.map_of(vec![("pages", pages), ("groups", groups)]);
        let view = tree.empty_map();
        let repositories = tree.empty_map();
        tree.init_group = tree.map_of(vec![("view", view), ("repositories", repositories)]);
        let metrics: Vec<(&str, usize)> = REPO_METRICS
            .iter()
            .map(|name| (*name, tree.empty_map()))
            .collect();
        tree.init_repo = tree.map_of(metrics);
        tree
    }

    fn push(&mut self, node: Node) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    fn empty_map(&mut self) -> usize {
        self.push(Node::Map(Vec::new()))
    }

    fn map_of(&mut self, entries: Vec<(&str, usize)>) -> usize {
        let entries = entries
            .into_iter()
            .map(|(k, v)| (Value::from(k), v))
            .collect();
        self.push(Node::Map(entries))
    }

    /// The file's content replaces the root; the init objects stay fresh.
    fn load(&mut self, value: &Value) {
        self.root = self.insert(value);
    }

    fn insert(&mut self, value: &Value) -> usize {
        match value {
            Value::Map(entries) => {
                let children = entries
                    .iter()
                    .map(|(k, v)| (k.clone(), self.insert(v)))
                    .collect();
                self.push(Node::Map(children))
            }
            other => self.push(Node::Leaf(other.clone())),
        }
    }

    fn to_value(&self, id: usize) -> Value {
        match &self.nodes[id] {
            Node::Map(entries) => Value::Map(
                entries
                    .iter()
                    .map(|(k, child)| (k.clone(), self.to_value(*child)))
                    .collect(),
            ),
            Node::Leaf(value) => value.clone(),
        }
    }

    /// `node[key]`; `None` when the key is missing or `node` is not a map.
    fn get(&self, id: usize, key: &str) -> Option<usize> {
        let Node::Map(entries) = &self.nodes[id] else {
            return None;
        };
        entries
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, child)| *child)
    }

    /// `node[key]`, raising `KeyError` when missing.
    fn index(&self, id: usize, key: &str) -> Result<usize, String> {
        self.get(id, key).ok_or_else(|| format!("'{key}'"))
    }

    /// `if not key in node: node[key] = child()`.
    fn setdefault(
        &mut self,
        id: usize,
        key: &str,
        child: impl FnOnce(&mut Self) -> usize,
    ) -> Result<usize, String> {
        if let Some(existing) = self.get(id, key) {
            return Ok(existing);
        }
        if !matches!(self.nodes[id], Node::Map(_)) {
            return Err("argument of this type is not iterable".into());
        }
        let new = child(self);
        let Node::Map(entries) = &mut self.nodes[id] else {
            unreachable!()
        };
        entries.push((Value::from(key), new));
        Ok(new)
    }

    /// `if not day in stats: stats[day] = 0` then `stats[day] += 1`.
    fn increment(&mut self, counters: usize, day: &str) -> Result<(), String> {
        let leaf = self.setdefault(counters, day, |t| t.push(Node::Leaf(Value::from(0))))?;
        match &mut self.nodes[leaf] {
            Node::Leaf(Value::Integer(count)) => {
                let next = count
                    .as_i64()
                    .and_then(|c| c.checked_add(1))
                    .ok_or("integer out of range")?;
                *count = next.into();
                Ok(())
            }
            Node::Leaf(Value::F64(count)) => {
                *count += 1.0;
                Ok(())
            }
            _ => Err("unsupported operand type(s) for +=: 'int'".into()),
        }
    }

    /// A day's count as `stats.get(day, 0)`; non-numbers count as 0 here.
    fn count(&self, counters: Option<usize>, day: &str) -> i64 {
        let Some(leaf) = counters.and_then(|c| self.get(c, day)) else {
            return 0;
        };
        match &self.nodes[leaf] {
            Node::Leaf(Value::Integer(i)) => i.as_i64().unwrap_or_default(),
            Node::Leaf(Value::Boolean(b)) => i64::from(*b),
            _ => 0,
        }
    }

    /// The days of a counters map whose count is above 0.
    fn active_days(&self, counters: Option<usize>) -> Vec<String> {
        let Some(Node::Map(entries)) = counters.map(|c| &self.nodes[c]) else {
            return Vec::new();
        };
        entries
            .iter()
            .filter_map(|(k, _)| {
                let day = k.as_str()?;
                (self.count(counters, day) > 0).then(|| day.to_string())
            })
            .collect()
    }

    fn record(&mut self, gate: Gate, group: &str, repo: &str, day: &str) -> Result<(), String> {
        let init_group = self.init_group;
        let init_repo = self.init_repo;
        let pages = |t: &Self| t.index(t.root, "pages").and_then(|p| t.index(p, "front"));
        let group_node = |t: &mut Self| {
            let groups = t.index(t.root, "groups")?;
            t.setdefault(groups, group, |_| init_group)
        };
        let counters = match gate {
            Gate::PageView => pages(self)?,
            Gate::GroupView => {
                let g = group_node(self)?;
                self.setdefault(g, "view", Self::empty_map)?
            }
            Gate::Repo(metric) => {
                let g = group_node(self)?;
                let repos = self.index(g, "repositories")?;
                let r = self.setdefault(repos, repo, |_| init_repo)?;
                self.setdefault(r, metric, Self::empty_map)?
            }
        };
        self.increment(counters, day)
    }
}

#[derive(Debug, Clone, Copy)]
enum Gate {
    PageView,
    GroupView,
    Repo(&'static str),
}

impl Gate {
    fn label(self) -> &'static str {
        match self {
            Gate::PageView => "page view",
            Gate::GroupView => "group view",
            Gate::Repo("view") => "repository view",
            Gate::Repo("release_download") => "release download",
            Gate::Repo(metric) => metric,
        }
    }
}

/// The stats file, its ignore lists and the recording gates
/// (`server.py`).
#[derive(Debug)]
pub struct Stats {
    tree: Mutex<Tree>,
    path: PathBuf,
    enabled: bool,
    ignored: Vec<Vec<u8>>,
}

impl Stats {
    /// `__load_stats` (`server.py`). A missing file is written with
    /// the initial value; a file that cannot be read leaves the initial value.
    /// `ignored` is `stats_ignore_identities`; upstream parses
    /// `stats_push_ignore_identities` too but never reads it.
    pub fn load(path: PathBuf, enabled: bool, ignored: Vec<Vec<u8>>) -> Self {
        let mut tree = Tree::new();
        if !path.is_file() {
            let bytes = encode(&tree.to_value(tree.root));
            if let Err(e) = std::fs::write(&path, bytes) {
                tracing::error!("Could not persist stats to {}: {e}", path.display());
            }
        } else {
            let read = std::fs::read(&path)
                .map_err(|e| e.to_string())
                .and_then(|b| {
                    rmpv::decode::read_value(&mut b.as_slice()).map_err(|e| e.to_string())
                });
            match read {
                Ok(value) => tree.load(&value),
                Err(e) => tracing::error!("Could not read stats file {}: {e}", path.display()),
            }
        }
        Stats {
            tree: Mutex::new(tree),
            path,
            enabled,
            ignored,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `__persist_stats` (`server.py`): `stats.tmp`, renamed over the file.
    pub fn persist(&self) {
        let tree = self.tree.lock().unwrap_or_else(|e| e.into_inner());
        let bytes = encode(&tree.to_value(tree.root));
        let tmp = PathBuf::from(format!("{}.tmp", self.path.display()));
        if let Err(e) = std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, &self.path))
        {
            tracing::error!("Could not write stats file to {}: {e}", self.path.display());
        }
    }

    fn ignores(&self, identity: Option<&[u8; 16]>) -> bool {
        identity.is_some_and(|h| self.ignored.iter().any(|i| i.as_slice() == h))
    }

    fn record(&self, gate: Gate, group: &str, repo: &str) {
        let day = local_day(now_secs());
        let mut tree = self.tree.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = tree.record(gate, group, repo, &day) {
            tracing::error!("Error while recording {} stats: {e}", gate.label());
        }
    }

    /// `view_succeeded` (`server.py`): the front page, a group, or a repository.
    pub fn view_succeeded(
        &self,
        group: Option<&str>,
        repo: Option<&str>,
        identity: Option<&[u8; 16]>,
    ) {
        if self.ignores(identity) || !self.enabled {
            return;
        }
        match (group, repo) {
            (None, None) => self.record(Gate::PageView, "", ""),
            (Some(g), None) => self.record(Gate::GroupView, g, ""),
            (g, Some(r)) => self.record(Gate::Repo("view"), g.unwrap_or_default(), r),
        }
    }

    /// `fetch_succeeded` (`server.py`).
    pub fn fetch_succeeded(&self, group: &str, repo: &str, identity: Option<&[u8; 16]>) {
        self.repo_event(Gate::Repo("fetch"), group, repo, identity, true);
    }

    /// `push_succeeded` (`server.py`): no ignore list is consulted.
    pub fn push_succeeded(&self, group: &str, repo: &str) {
        self.repo_event(Gate::Repo("push"), group, repo, None, false);
    }

    /// `download_succeeded` (`server.py`).
    pub fn download_succeeded(&self, group: &str, repo: &str, identity: Option<&[u8; 16]>) {
        self.repo_event(Gate::Repo("download"), group, repo, identity, true);
    }

    /// `release_download_succeeded` (`server.py`).
    pub fn release_download_succeeded(&self, group: &str, repo: &str, identity: Option<&[u8; 16]>) {
        self.repo_event(Gate::Repo("release_download"), group, repo, identity, true);
    }

    fn repo_event(
        &self,
        gate: Gate,
        group: &str,
        repo: &str,
        identity: Option<&[u8; 16]>,
        check_ignored: bool,
    ) {
        if check_ignored && self.ignores(identity) {
            return;
        }
        if self.enabled && !group.is_empty() && !repo.is_empty() {
            self.record(gate, group, repo);
        }
    }

    /// `repository_stats` (`server.py`): `None` without the stats permission.
    pub fn repository_stats(
        &self,
        repos: &super::layout::Repositories,
        identity: &[u8; 16],
        group: &str,
        repo: &str,
        lookback_days: u32,
    ) -> Option<RepositoryStats> {
        if !repos.resolve_permission(identity, group, repo, super::perms::Perm::Stats) {
            return None;
        }
        let tree = self.tree.lock().unwrap_or_else(|e| e.into_inner());
        Some(summarise(&tree, group, repo, lookback_days, now_secs()))
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).expect("writing to a Vec");
    out
}

/// One metric of the summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Series {
    pub daily: Vec<i64>,
    pub total: i64,
    pub peak: i64,
    pub peak_day: Option<String>,
}

impl Series {
    fn over(days: &[String], count: impl Fn(&str) -> i64) -> Self {
        let mut series = Series {
            daily: Vec::new(),
            total: 0,
            peak: 0,
            peak_day: None,
        };
        for day in days {
            let n = count(day);
            series.daily.push(n);
            series.total += n;
            if n > series.peak {
                series.peak = n;
                series.peak_day = Some(day.clone());
            }
        }
        series
    }
}

/// The dict `repository_stats` returns.
#[derive(Debug, Clone, PartialEq)]
pub struct RepositoryStats {
    pub group: String,
    pub repository: String,
    pub lookback_days: u32,
    pub date_range: String,
    pub days: Vec<String>,
    pub day_labels: Vec<String>,
    pub timeline_labels: [String; 2],
    pub views: Series,
    pub fetches: Series,
    pub pushes: Series,
    pub downloads: Series,
    pub release_downloads: Series,
    pub downloads_combined: Series,
    pub activity_score: i64,
    pub actual_days: i64,
    pub activity_level: &'static str,
}

fn summarise(tree: &Tree, group: &str, repo: &str, lookback: u32, now: i64) -> RepositoryStats {
    const DAY: i64 = 86_400;
    let stamps: Vec<i64> = (0..i64::from(lookback))
        .rev()
        .map(|i| now - i * DAY)
        .collect();
    let days: Vec<String> = stamps.iter().map(|&t| local_day(t)).collect();
    let day_labels: Vec<String> = stamps.iter().map(|&t| local_day_label(t)).collect();
    let repo_node = tree
        .get(tree.root, "groups")
        .and_then(|g| tree.get(g, group))
        .and_then(|g| tree.get(g, "repositories"))
        .and_then(|r| tree.get(r, repo));
    let metric = |name: &str| repo_node.and_then(|r| tree.get(r, name));
    let (view, fetch, push) = (metric("view"), metric("fetch"), metric("push"));
    let (download, release) = (metric("download"), metric("release_download"));
    let series = |node| Series::over(&days, |d| tree.count(node, d));
    let views = series(view);
    let fetches = series(fetch);
    let pushes = series(push);
    let downloads = series(download);
    let release_downloads = series(release);
    let downloads_combined =
        Series::over(&days, |d| tree.count(download, d) + tree.count(release, d));
    let view_total = views.total + downloads.total + release_downloads.total;
    let score = view_total as f64 * 0.2 + fetches.total as f64 * 2.0 + (pushes.total * 5) as f64;
    let mut actual_days = i64::from(lookback);
    let earliest = [view, fetch, push]
        .into_iter()
        .flat_map(|node| tree.active_days(node))
        .min();
    if let Some(earliest_ts) = earliest.as_deref().and_then(local_midnight) {
        actual_days = ((now - earliest_ts).div_euclid(DAY) + 1).max(1);
    }
    actual_days = actual_days.min(i64::from(lookback));
    let daily = if actual_days > 0 {
        score / actual_days as f64
    } else {
        0.0
    };
    let activity_level = if daily == 0.0 {
        "inactive"
    } else if daily < 3.0 {
        "low"
    } else if daily < 10.0 {
        "moderate"
    } else {
        "high"
    };
    RepositoryStats {
        group: group.to_string(),
        repository: repo.to_string(),
        lookback_days: lookback,
        date_range: format!(
            "{} - {}",
            day_labels.first().cloned().unwrap_or_default(),
            day_labels.last().cloned().unwrap_or_default()
        ),
        days,
        day_labels,
        timeline_labels: [format!("{lookback} days ago"), "Today".to_string()],
        views,
        fetches,
        pushes,
        downloads,
        release_downloads,
        downloads_combined,
        activity_score: score as i64,
        actual_days,
        activity_level,
    }
}

/// Seconds since the epoch, as `time.time()` truncated.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Local calendar time, as Python's `time.localtime`: year, month, day.
fn local_date(secs: i64) -> (i64, i64, i64) {
    let time = secs as nix::libc::time_t;
    let mut tm = std::mem::MaybeUninit::<nix::libc::tm>::zeroed();
    // SAFETY: both pointers are valid for the call; localtime_r is reentrant.
    let result = unsafe { nix::libc::localtime_r(&time, tm.as_mut_ptr()) };
    if result.is_null() {
        return (1970, 1, 1);
    }
    // SAFETY: localtime_r filled `tm` when it returned non-null.
    let tm = unsafe { tm.assume_init() };
    (
        i64::from(tm.tm_year) + 1900,
        i64::from(tm.tm_mon) + 1,
        i64::from(tm.tm_mday),
    )
}

/// `_get_day` (`server.py`): `%Y-%m-%d` in local time.
pub fn local_day(secs: i64) -> String {
    let (year, month, day) = local_date(secs);
    format!("{year:04}-{month:02}-{day:02}")
}

/// `%b %d` in local time (C locale month names).
fn local_day_label(secs: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (_, month, day) = local_date(secs);
    format!("{} {day:02}", MONTHS[(month.clamp(1, 12) - 1) as usize])
}

/// `time.mktime(time.strptime(day, "%Y-%m-%d"))`; `None` where strptime raises.
fn local_midnight(day: &str) -> Option<i64> {
    let mut parts = day.split('-');
    let field = |p: Option<&str>, max: usize| {
        p.filter(|s| !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<nix::libc::c_int>().ok())
    };
    let year = field(parts.next(), 4)?;
    let month = field(parts.next(), 2).filter(|m| (1..=12).contains(m))?;
    let mday = field(parts.next(), 2).filter(|d| (1..=31).contains(d))?;
    if parts.next().is_some() {
        return None;
    }
    // SAFETY: an all-zero `tm` is a valid value of the C struct.
    let mut tm: nix::libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = mday;
    tm.tm_isdst = -1;
    // SAFETY: `tm` is initialised; mktime reads and normalises it in place.
    let secs = unsafe { nix::libc::mktime(&mut tm) };
    Some(secs as i64)
}
