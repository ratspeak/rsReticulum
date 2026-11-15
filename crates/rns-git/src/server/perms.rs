//! Permission statements, `.allowed` files and the permission decision
//! (`server.py`).

use std::collections::BTreeMap;
use std::path::Path;

use super::py_len;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Perm {
    Read,
    Write,
    ReadWrite,
    Create,
    Stats,
    Release,
    Interact,
    Propose,
    Admin,
}

impl Perm {
    /// The wire value (`PERM_*`, `server.py`).
    pub fn code(self) -> u8 {
        match self {
            Perm::Read => 0x01,
            Perm::Write => 0x02,
            Perm::ReadWrite => 0x03,
            Perm::Create => 0x04,
            Perm::Stats => 0x05,
            Perm::Release => 0x06,
            Perm::Interact => 0x07,
            Perm::Propose => 0x08,
            Perm::Admin => 0xFE,
        }
    }

    fn from_word(word: &str) -> Option<Perm> {
        Some(match word {
            "r" | "read" => Perm::Read,
            "w" | "write" => Perm::Write,
            "rw" | "readwrite" => Perm::ReadWrite,
            "c" | "create" => Perm::Create,
            "s" | "stats" => Perm::Stats,
            "rel" | "release" => Perm::Release,
            "i" | "interact" => Perm::Interact,
            "p" | "propose" => Perm::Propose,
            "adm" | "admin" => Perm::Admin,
            _ => return None,
        })
    }

    /// The permission list this perm reads; `None` for read-write, which
    /// the resolvers reject.
    fn list(self) -> Option<PermList> {
        Some(match self {
            Perm::Read => PermList::Read,
            Perm::Write => PermList::Write,
            Perm::Create => PermList::Create,
            Perm::Stats => PermList::Stats,
            Perm::Release => PermList::Release,
            Perm::Interact => PermList::Interact,
            Perm::Propose => PermList::Propose,
            Perm::Admin => PermList::Admin,
            Perm::ReadWrite => return None,
        })
    }
}

/// One of the eight stored lists (`ALL_PERMS`, `server.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PermList {
    Read,
    Write,
    Create,
    Stats,
    Release,
    Interact,
    Propose,
    Admin,
}

impl PermList {
    pub const ALL: [PermList; 8] = [
        PermList::Read,
        PermList::Write,
        PermList::Create,
        PermList::Stats,
        PermList::Release,
        PermList::Interact,
        PermList::Propose,
        PermList::Admin,
    ];

    pub fn name(self) -> &'static str {
        match self {
            PermList::Read => "read",
            PermList::Write => "write",
            PermList::Create => "create",
            PermList::Stats => "stats",
            PermList::Release => "release",
            PermList::Interact => "interact",
            PermList::Propose => "propose",
            PermList::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    None,
    All,
    /// Identity hash bytes; `bytes.fromhex` can yield fewer than 16, which
    /// upstream stores and never matches.
    Identity(Vec<u8>),
}

impl Target {
    /// The wire value (`TGT_NONE`/`TGT_ALL`, `server.py`).
    pub fn code(&self) -> Option<u8> {
        match self {
            Target::None => Some(0x01),
            Target::All => Some(0x02),
            Target::Identity(_) => None,
        }
    }
}

pub const TGT_NONE_SMPHR: [&str; 3] = ["n", "none", "nobody"];
pub const TGT_ALL_SMPHR: [&str; 3] = ["a", "all", "everyone"];
pub const ALL_TGTS: [&str; 6] = ["n", "none", "nobody", "a", "all", "everyone"];

/// `__resolve_identity_alias` (`server.py`).
pub fn resolve_identity_alias(alias: &str, aliases: &BTreeMap<String, String>) -> String {
    if ALL_TGTS.contains(&alias.to_lowercase().as_str()) {
        return alias.to_string();
    }
    let is_hash = py_len(alias) == 32
        && rns_tools::rsg::pyfmt::py_fromhex(alias).is_ok_and(|h| !h.is_empty());
    if is_hash {
        return alias.to_string();
    }
    aliases
        .get(alias)
        .cloned()
        .unwrap_or_else(|| alias.to_string())
}

/// `parse_permission` (`server.py`): either half is `None` when
/// it does not parse.
pub fn parse_permission(
    statement: &str,
    aliases: &BTreeMap<String, String>,
) -> (Option<Perm>, Option<Target>) {
    let comps: Vec<&str> = statement.split(':').collect();
    if comps.len() != 2 {
        return (None, None);
    }
    let perm = Perm::from_word(&comps[0].to_lowercase());
    let target = resolve_identity_alias(comps[1], aliases);
    let target = if TGT_NONE_SMPHR.contains(&target.as_str()) {
        Some(Target::None)
    } else if TGT_ALL_SMPHR.contains(&target.as_str()) {
        Some(Target::All)
    } else if py_len(&target) == 32 {
        match rns_tools::rsg::pyfmt::py_fromhex(&target) {
            Ok(hash) => Some(Target::Identity(hash)),
            Err(e) => {
                tracing::error!("Invalid identity hash \"{target}\" in access permissions: {e}");
                None
            }
        }
    } else {
        None
    };
    (perm, target)
}

/// The eight permission lists of a group or repository.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Permissions {
    lists: BTreeMap<PermList, Vec<Target>>,
}

impl Permissions {
    pub fn get(&self, list: PermList) -> &[Target] {
        self.lists.get(&list).map(Vec::as_slice).unwrap_or(&[])
    }

    fn add(&mut self, list: PermList, target: &Target) {
        let entries = self.lists.entry(list).or_default();
        if !entries.contains(target) {
            entries.push(target.clone());
        }
    }

    /// Add one parsed statement; `rw` adds to both read and write.
    pub fn add_statement(&mut self, statement: &str, aliases: &BTreeMap<String, String>) {
        let (Some(perm), Some(target)) = parse_permission(statement, aliases) else {
            return;
        };
        match perm.list() {
            Some(list) => self.add(list, &target),
            None => {
                self.add(PermList::Read, &target);
                self.add(PermList::Write, &target);
            }
        }
    }

    /// `permissions_from_allowed_input` (`server.py`).
    pub fn from_allowed_input(input: &str, aliases: &BTreeMap<String, String>) -> Self {
        let mut perms = Permissions::default();
        for line in py_splitlines(input) {
            let statement = line.trim();
            if !statement.starts_with('#') {
                perms.add_statement(statement, aliases);
            }
        }
        perms
    }
}

/// Python `str.splitlines`.
pub(crate) fn py_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut iter = text.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        let end = match c {
            '\r' => {
                if let Some((_, '\n')) = iter.peek() {
                    iter.next();
                    i + 2
                } else {
                    i + 1
                }
            }
            '\n' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}'
            | '\u{2029}' => i + c.len_utf8(),
            _ => continue,
        };
        lines.push(&text[start..i]);
        start = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// Error from reading an `.allowed` file; upstream raises here.
#[derive(Debug)]
pub enum AllowedError {
    Io(std::io::Error),
    NotUtf8,
}

/// `load_allowed_permissions` (`server.py`): an executable file is
/// run with no arguments and its stdout parsed (the exit status is
/// ignored); the flag says whether it was run.
pub fn load_allowed_permissions(
    path: &Path,
    aliases: &BTreeMap<String, String>,
) -> Result<(Permissions, bool), AllowedError> {
    if !path.is_file() {
        return Ok((Permissions::default(), false));
    }
    let executable = crate::platform::executable(path);
    let (raw, dynamic) = if executable {
        let output = std::process::Command::new(path)
            .stdin(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .output()
            .map_err(AllowedError::Io)?;
        (output.stdout, true)
    } else {
        (std::fs::read(path).map_err(AllowedError::Io)?, false)
    };
    let input = String::from_utf8(raw).map_err(|_| AllowedError::NotUtf8)?;
    Ok((Permissions::from_allowed_input(&input, aliases), dynamic))
}

fn decide(list: &[Target], admins: &[Target], hash: &[u8; 16]) -> Option<bool> {
    let me = Target::Identity(hash.to_vec());
    if list.contains(&Target::None) {
        Some(false)
    } else if list.contains(&Target::All) || list.contains(&me) || admins.contains(&me) {
        Some(true)
    } else {
        None
    }
}

/// `resolve_permission`'s decision once group and repository are known
/// (`server.py`); the blocklist is checked by the caller.
pub fn resolve_repository(
    group: &Permissions,
    repository: &Permissions,
    hash: &[u8; 16],
    perm: Perm,
) -> bool {
    let Some(list) = perm.list() else {
        return false;
    };
    let repo_list = repository.get(list);
    if let Some(decision) = decide(repo_list, repository.get(PermList::Admin), hash) {
        return decision;
    }
    if !repo_list.is_empty() {
        return false;
    }
    decide(group.get(list), group.get(PermList::Admin), hash).unwrap_or(false)
}

/// `resolve_group_permission`'s decision (`server.py`); upstream
/// does not check the blocklist here.
pub fn resolve_group(group: &Permissions, hash: &[u8; 16], perm: Perm) -> bool {
    let Some(list) = perm.list() else {
        return false;
    };
    decide(group.get(list), group.get(PermList::Admin), hash).unwrap_or(false)
}
