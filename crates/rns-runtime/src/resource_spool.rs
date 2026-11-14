//! An inbound Resource assembled into a file, as `Resource.assemble` appends
//! each verified segment to `Resource.storagepath` (Resource.py).

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

const NONCE_LEN: usize = 8;
const HASH_HEX_LEN: usize = 64;

/// The file one inbound Resource is assembled into. Dropping it removes the
/// file unless [`ResourceSpool::finish`] handed it over.
pub(crate) struct ResourceSpool {
    path: PathBuf,
    file: Option<File>,
    len: u64,
    keep: bool,
}

impl ResourceSpool {
    /// Name a spool for `resource_id` in `dir`. The file is created by the
    /// first [`Self::append`], as upstream opens it when a segment is assembled.
    pub(crate) fn new(dir: &Path, resource_id: &[u8; 32]) -> Self {
        // The id is chosen by the peer and the directory may be shared: the
        // suffix keeps two transfers of one Resource in separate files.
        let nonce = rns_crypto::random::random_bytes(NONCE_LEN);
        Self {
            path: dir.join(format!(
                "{}-{}",
                hex::encode(resource_id),
                hex::encode(nonce)
            )),
            file: None,
            len: 0,
            keep: false,
        }
    }

    /// Append one verified segment. An error leaves the spool unusable; the
    /// owner drops it, which removes the partial file.
    pub(crate) fn append(&mut self, data: &[u8]) -> std::io::Result<()> {
        if self.file.is_none() {
            let mut options = std::fs::OpenOptions::new();
            // Never reuse or follow an existing entry.
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            self.file = Some(options.open(&self.path)?);
        }
        let file = self.file.as_mut().expect("spool file was just opened");
        file.write_all(data)?;
        self.len = self.len.saturating_add(data.len() as u64);
        Ok(())
    }

    /// Payload bytes written so far.
    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// Close the file and hand it to the caller, who then owns and removes it.
    pub(crate) fn finish(mut self) -> (PathBuf, u64) {
        self.keep = true;
        self.file = None;
        (std::mem::take(&mut self.path), self.len)
    }
}

impl Drop for ResourceSpool {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        // Close before removing: an open file cannot be removed on Windows.
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// `Reticulum.resourcepath` when it exists, else the system temporary
/// directory (a session or manager used without a runtime).
pub(crate) fn spool_dir(resource_dir: Option<&Path>) -> PathBuf {
    resource_dir
        .filter(|dir| dir.is_dir())
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir)
}

/// Whether `name` is a spool file name, `<64 hex>-<16 hex>`. The cache cleaner
/// removes stale ones a crash left behind, as it does upstream's hash-named
/// files.
pub(crate) fn is_spool_name(name: &[u8]) -> bool {
    let hex = |bytes: &[u8]| bytes.iter().all(u8::is_ascii_hexdigit);
    name.len() == HASH_HEX_LEN + 1 + NONCE_LEN * 2
        && name[HASH_HEX_LEN] == b'-'
        && hex(&name[..HASH_HEX_LEN])
        && hex(&name[HASH_HEX_LEN + 1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(dir: &Path) -> usize {
        std::fs::read_dir(dir).unwrap().count()
    }

    #[test]
    fn finished_spool_holds_the_segments_in_order_and_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = ResourceSpool::new(dir.path(), &[7; 32]);
        assert_eq!(
            entries(dir.path()),
            0,
            "nothing is created before a segment"
        );
        spool.append(b"first ").unwrap();
        spool.append(b"second").unwrap();
        assert_eq!(spool.len(), 12);
        let (path, len) = spool.finish();
        assert_eq!(len, 12);
        assert_eq!(std::fs::read(&path).unwrap(), b"first second");
        assert!(is_spool_name(path.file_name().unwrap().as_encoded_bytes()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn dropped_spool_leaves_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = ResourceSpool::new(dir.path(), &[7; 32]);
        spool.append(&[1; 4096]).unwrap();
        assert_eq!(entries(dir.path()), 1);
        drop(spool);
        assert_eq!(entries(dir.path()), 0);
    }

    #[test]
    fn missing_directory_fails_the_first_segment_and_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent");
        let mut spool = ResourceSpool::new(&missing, &[7; 32]);
        assert!(spool.append(b"data").is_err());
        drop(spool);
        assert_eq!(entries(dir.path()), 0);
    }

    #[test]
    fn two_spools_for_one_resource_use_separate_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = ResourceSpool::new(dir.path(), &[7; 32]);
        let mut second = ResourceSpool::new(dir.path(), &[7; 32]);
        first.append(b"a").unwrap();
        second.append(b"b").unwrap();
        assert_eq!(entries(dir.path()), 2);
    }

    #[test]
    fn spool_names_are_recognised_and_other_names_are_not() {
        let name = format!("{}-{}", "ab".repeat(32), "cd".repeat(8));
        assert!(is_spool_name(name.as_bytes()));
        assert!(!is_spool_name("ab".repeat(32).as_bytes()));
        assert!(!is_spool_name(
            format!("{}.{}", "ab".repeat(32), "cd".repeat(8)).as_bytes()
        ));
        assert!(!is_spool_name(
            format!("{}-{}", "zz".repeat(32), "cd".repeat(8)).as_bytes()
        ));
    }
}
