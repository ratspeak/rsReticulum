//! Lexical `ntpath`: both separators, drive letters, and UNC shares. Plain
//! string functions, so every host runs their tests.

const SEPS: [char; 2] = ['\\', '/'];

/// `ntpath.splitroot`: drive, root and tail.
pub(crate) fn splitroot(path: &str) -> (&str, &str, &str) {
    let unified = path.replace('/', "\\");
    if unified.starts_with("\\\\") {
        // `\\server\share`, `\\?\UNC\server\share`, or a `\\?\` device.
        let start = if unified
            .get(..8)
            .is_some_and(|head| head.eq_ignore_ascii_case("\\\\?\\UNC\\"))
        {
            8
        } else {
            2
        };
        let Some(server) = unified[start..].find('\\').map(|i| start + i) else {
            return (path, "", "");
        };
        let Some(share) = unified[server + 1..].find('\\').map(|i| server + 1 + i) else {
            return (path, "", "");
        };
        (&path[..share], &path[share..share + 1], &path[share + 1..])
    } else if unified.starts_with('\\') {
        ("", &path[..1], &path[1..])
    } else if let Some((colon, ':')) = path.char_indices().nth(1) {
        let drive = colon + 1;
        if unified[drive..].starts_with('\\') {
            (&path[..drive], &path[drive..drive + 1], &path[drive + 1..])
        } else {
            (&path[..drive], "", &path[drive..])
        }
    } else {
        ("", "", path)
    }
}

/// `ntpath.isabs` as of Python 3.13: a drive with a root, or a UNC or
/// device path. A rooted `\x` takes the working drive, as Windows does.
fn isabs(path: &str) -> bool {
    let head: String = path.chars().take(3).collect::<String>().replace('/', "\\");
    head.starts_with("\\\\") || head.chars().skip(1).eq([':', '\\'])
}

fn fold(name: &str) -> String {
    name.replace('/', "\\").to_lowercase()
}

/// `ntpath.join` of two paths.
fn join<'a>(base: &'a str, path: &'a str) -> String {
    let (mut drive, mut root, base_tail) = splitroot(base);
    let mut tail = base_tail.to_string();
    let (path_drive, path_root, path_tail) = splitroot(path);
    if !path_root.is_empty() {
        if !path_drive.is_empty() || drive.is_empty() {
            drive = path_drive;
        }
        root = path_root;
        tail = path_tail.to_string();
    } else if !path_drive.is_empty() && fold(path_drive) != fold(drive) {
        (drive, root, tail) = (path_drive, path_root, path_tail.to_string());
    } else {
        if !path_drive.is_empty() {
            drive = path_drive;
        }
        if !tail.is_empty() && !tail.ends_with(SEPS) {
            tail.push('\\');
        }
        tail.push_str(path_tail);
    }
    if !tail.is_empty()
        && root.is_empty()
        && !drive.is_empty()
        && !drive.ends_with([':', '\\', '/'])
    {
        return format!("{drive}\\{tail}");
    }
    format!("{drive}{root}{tail}")
}

/// `ntpath.normpath`.
pub(crate) fn normpath(path: &str) -> String {
    let unified = path.replace('/', "\\");
    let (drive, root, tail) = splitroot(&unified);
    let mut comps: Vec<&str> = Vec::new();
    for comp in tail.split('\\') {
        match comp {
            "" | "." => {}
            ".." if comps.last().is_some_and(|last| *last != "..") => {
                comps.pop();
            }
            ".." if comps.is_empty() && !root.is_empty() => {}
            _ => comps.push(comp),
        }
    }
    let prefix = format!("{drive}{root}");
    if prefix.is_empty() && comps.is_empty() {
        return ".".into();
    }
    format!("{prefix}{}", comps.join("\\"))
}

/// `ntpath.abspath`, lexical only: a path on another drive without a
/// root stays relative to that drive's own directory.
pub(crate) fn abspath(path: &str, cwd: &str) -> String {
    if isabs(path) {
        normpath(path)
    } else {
        normpath(&join(cwd, path))
    }
}

/// `ntpath.expanduser` for `~` and `~\...`; `~user` is left unchanged.
pub(crate) fn expanduser(path: &str, home: Option<&str>) -> String {
    match (path.strip_prefix('~'), home) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with(SEPS) => {
            format!("{home}{rest}")
        }
        _ => path.to_string(),
    }
}

/// `ntpath.basename`.
pub(crate) fn basename(path: &str) -> &str {
    let (_, _, tail) = splitroot(path);
    tail.rsplit(SEPS).next().unwrap_or(tail)
}

/// What `path` names below `dir`, comparing drives and components
/// case-insensitively as Windows does; `None` unless strictly below.
pub(crate) fn below(path: &str, dir: &str) -> Option<String> {
    let (path_drive, path_root, path_tail) = splitroot(path);
    let (dir_drive, dir_root, dir_tail) = splitroot(dir);
    if fold(path_drive) != fold(dir_drive) || path_root.is_empty() != dir_root.is_empty() {
        return None;
    }
    let mut comps = path_tail.split(SEPS).filter(|comp| !comp.is_empty());
    for dir_comp in dir_tail.split(SEPS).filter(|comp| !comp.is_empty()) {
        if fold(comps.next()?) != fold(dir_comp) {
            return None;
        }
    }
    let rest: Vec<&str> = comps.collect();
    (!rest.is_empty()).then(|| rest.join("\\"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_drives_shares_and_devices() {
        for (path, split) in [
            (r"C:\a\b", ("C:", r"\", r"a\b")),
            ("C:/a", ("C:", "/", "a")),
            ("C:a", ("C:", "", "a")),
            (r"\\server\share\a", (r"\\server\share", r"\", "a")),
            ("//server/share/a", ("//server/share", "/", "a")),
            (r"\\?\C:\a", (r"\\?\C:", r"\", "a")),
            (
                r"\\?\UNC\server\share\a",
                (r"\\?\UNC\server\share", r"\", "a"),
            ),
            (r"\\server", (r"\\server", "", "")),
            (r"\a", ("", r"\", "a")),
            ("a", ("", "", "a")),
        ] {
            assert_eq!(splitroot(path), split, "{path}");
        }
    }

    #[test]
    fn resolves_against_the_working_directory() {
        let cwd = r"D:\work\dir";
        for (path, expected) in [
            ("file.bin", r"D:\work\dir\file.bin"),
            ("sub/./x/../file.bin", r"D:\work\dir\sub\file.bin"),
            (r"..\..\..\up", r"D:\up"),
            (r"\rooted", r"D:\rooted"),
            ("C:/Temp/.tmpX", r"C:\Temp\.tmpX"),
            (r"C:\..\x", r"C:\x"),
            ("d:rel", r"d:\work\dir\rel"),
            ("C:rel", "C:rel"),
            (r"\\server\share\..\x", r"\\server\share\x"),
        ] {
            assert_eq!(abspath(path, cwd), expected, "{path}");
        }
        assert_eq!(abspath("x", r"\\server\share\dir"), r"\\server\share\dir\x");
        assert_eq!(normpath(""), ".");
        assert_eq!(normpath(r"a\..\..\b"), r"..\b");
    }

    #[test]
    fn expands_the_windows_home() {
        let home = Some(r"C:\Users\me");
        assert_eq!(expanduser("~", home), r"C:\Users\me");
        assert_eq!(expanduser(r"~\files", home), r"C:\Users\me\files");
        assert_eq!(expanduser("~/files", home), r"C:\Users\me/files");
        assert_eq!(expanduser(r"~other\files", home), r"~other\files");
        assert_eq!(expanduser(r"~\files", None), r"~\files");
    }

    #[test]
    fn basename_takes_the_last_name_after_either_separator() {
        for (path, name) in [
            (r"C:\jail\file.bin", "file.bin"),
            (r"dir/sub\file.bin", "file.bin"),
            (r"..\..\evil.bin", "evil.bin"),
            ("C:evil.bin", "evil.bin"),
            (r"\\server\share", ""),
            ("plain.bin", "plain.bin"),
        ] {
            assert_eq!(basename(path), name, "{path}");
        }
    }
}
