//! Acknowledged native storage barriers for application transactions.
//!
//! These receipts attest successful native calls and exact readback, not a
//! guarantee against dishonest hardware or later modification. Callers own
//! private directories, exclude concurrent external writers, and journal any
//! multi-file transaction. Every filesystem is accepted, as in Python
//! Reticulum: a barrier the filesystem lacks is skipped and logged once, and
//! [`storage_risk`] reports network or RAM-backed storage.

use super::{ATOMIC_WRITE_LOCK, atomic_replace, read_retrying, unique_temp_path, verify_bytes};
use rns_crypto::sha::sha256;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableCommitPhase {
    NotCommitted,
    CommitUncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableErrorKind {
    Io,
    Verification,
    InvalidInput,
    DurabilityUnsupported,
}

/// A failed operation never grants acceptance authority. Preserve the listed
/// candidate/witness paths and the caller's journal on an uncertain result.
#[derive(Debug, thiserror::Error)]
#[error("durable storage {phase:?} ({kind:?}): {source}")]
pub struct DurableWriteError {
    pub phase: DurableCommitPhase,
    pub kind: DurableErrorKind,
    pub recovery_paths: Vec<PathBuf>,
    #[source]
    source: io::Error,
}

/// Privately constructed proof of acknowledged native barriers for exact bytes.
#[derive(Debug)]
pub struct DurableFileReceipt {
    path: PathBuf,
    content_hash: [u8; 32],
    len: usize,
}

impl DurableFileReceipt {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn content_hash(&self) -> [u8; 32] {
        self.content_hash
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Directory transitions require an independently committed outside journal.
#[derive(Debug)]
pub struct DurableDirectoryReceipt {
    path: PathBuf,
}
impl DurableDirectoryReceipt {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableCleanupOutcome {
    Removed,
    AlreadyAbsent,
}

fn error(
    phase: DurableCommitPhase,
    kind: DurableErrorKind,
    paths: &[&Path],
    source: io::Error,
) -> DurableWriteError {
    DurableWriteError {
        phase,
        kind,
        recovery_paths: paths.iter().map(|p| p.to_path_buf()).collect(),
        source,
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
#[cfg(windows)]
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
fn kind(err: &io::Error) -> DurableErrorKind {
    match err.kind() {
        io::ErrorKind::Unsupported => DurableErrorKind::DurabilityUnsupported,
        io::ErrorKind::InvalidData => DurableErrorKind::Verification,
        io::ErrorKind::InvalidInput => DurableErrorKind::InvalidInput,
        _ => DurableErrorKind::Io,
    }
}
// Resolve only the parent, never follow a target symlink. The private directory
// ownership/external-writer exclusion requirement remains the caller's duty.
fn target_path(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid("target has no file name"))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    note_storage(&parent)?;
    let result = parent.join(name);
    match fs::symlink_metadata(&result) {
        Ok(m) if !m.is_file() || m.file_type().is_symlink() => {
            return Err(invalid("target must be a regular file, not a symlink"));
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(result)
}

/// Storage that cannot promise crash safety. Writes still run every barrier the
/// filesystem supports; applications may surface this to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageRisk {
    /// Network or user-space filesystem; flushes may not reach stable storage.
    Remote,
    /// RAM-backed filesystem; contents do not survive a restart.
    Volatile,
}

impl std::fmt::Display for StorageRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Remote => "network or user-space filesystem",
            Self::Volatile => "RAM-backed filesystem",
        })
    }
}

/// Classify the filesystem holding `path`; `None` is ordinary local storage.
pub fn storage_risk(path: &Path) -> io::Result<Option<StorageRisk>> {
    filesystem_risk(&fs::canonicalize(path)?)
}

fn note_storage(path: &Path) -> io::Result<()> {
    if let Some(risk) = filesystem_risk(path)? {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(path = %path.display(), %risk, "storage cannot guarantee crash safety");
        });
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn filesystem_risk(path: &Path) -> io::Result<Option<StorageRisk>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid("NUL in path"))?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    Ok((stat.f_flags & (libc::MNT_LOCAL as u32) == 0).then_some(StorageRisk::Remote))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn filesystem_risk(path: &Path) -> io::Result<Option<StorageRisk>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid("NUL in path"))?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    // Magic numbers are 32-bit; a signed 32-bit f_type must not sign-extend.
    #[allow(clippy::unnecessary_cast)]
    let magic = stat.f_type as u32;
    Ok(match magic {
        // tmpfs, ramfs
        0x0102_1994 | 0x8584_58f6 => Some(StorageRisk::Volatile),
        // NFS, SMB, CIFS, SMB2, 9P, Ceph, AFS, Coda, FUSE
        0x6969 | 0x517b | 0xff53_4d42 | 0xfe53_4d42 | 0x0102_1997 | 0x00c3_6400 | 0x5346_414f
        | 0x7375_7245 | 0x6573_5546 => Some(StorageRisk::Remote),
        _ => None,
    })
}

#[cfg(windows)]
fn filesystem_risk(path: &Path) -> io::Result<Option<StorageRisk>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumePathNameW};
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut root = vec![0u16; 32768];
    if unsafe { GetVolumePathNameW(path.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // DRIVE_REMOTE, DRIVE_RAMDISK
    Ok(match unsafe { GetDriveTypeW(root.as_ptr()) } {
        4 => Some(StorageRisk::Remote),
        6 => Some(StorageRisk::Volatile),
        _ => None,
    })
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    windows
)))]
fn filesystem_risk(_: &Path) -> io::Result<Option<StorageRisk>> {
    Ok(None)
}

/// A barrier the filesystem does not implement is skipped and logged once;
/// every other failure still fails the operation.
fn supported_barrier(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if barrier_unsupported(&e) => {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::warn!(error = %e, "filesystem lacks a storage barrier; using the ones it supports");
            });
            Ok(())
        }
        result => result,
    }
}

fn barrier_unsupported(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error().is_some_and(|code| {
            [libc::ENOTSUP, libc::EOPNOTSUPP, libc::EINVAL, libc::ENOSYS].contains(&code)
        })
    }
    #[cfg(not(unix))]
    {
        error.kind() == io::ErrorKind::Unsupported
    }
}

fn file_barrier(file: &File) -> io::Result<()> {
    supported_barrier(file.sync_all())?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == -1 {
            supported_barrier(Err(io::Error::last_os_error()))?;
        }
    }
    Ok(())
}

fn parent_barrier(_path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    supported_barrier(
        File::open(_path.parent().ok_or_else(|| invalid("missing parent"))?)?.sync_all(),
    )?;
    // On Windows the checked WRITE_THROUGH native publication and subsequent
    // writable-file flush are the selected acknowledgement, not directory fsync.
    Ok(())
}

/// Check that a private storage directory is a real directory, logging risky
/// storage once. This is a read-only eligibility check, never a commit receipt.
pub fn validate_durable_storage_directory(path: &Path) -> Result<(), DurableWriteError> {
    let result = (|| {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid("storage directory must be a real directory"));
        }
        note_storage(&fs::canonicalize(path)?)
    })();
    result.map_err(|cause| {
        error(
            DurableCommitPhase::NotCommitted,
            kind(&cause),
            &[path],
            cause,
        )
    })
}

/// Atomically publish exact bytes and acknowledge every barrier the filesystem
/// supports. The parent must exist. Candidates are private (0600 on Unix);
/// errors preserve recovery paths, never return a receipt.
pub fn durable_write(path: &Path, data: &[u8]) -> Result<DurableFileReceipt, DurableWriteError> {
    let _guard = ATOMIC_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let target = target_path(path)
        .map_err(|e| error(DurableCommitPhase::NotCommitted, kind(&e), &[path], e))?;
    let candidate = unique_temp_path(&target)
        .map_err(|e| error(DurableCommitPhase::NotCommitted, kind(&e), &[&target], e))?;
    let mut phase = DurableCommitPhase::NotCommitted;
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).read(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&candidate)?;
        file.write_all(data)?;
        file.flush()?;
        file_barrier(&file)?;
        verify_bytes(&candidate, data)?;
        // A native publication failure can be ambiguous; retain both paths.
        phase = DurableCommitPhase::CommitUncertain;
        #[cfg(windows)]
        drop(file);
        atomic_replace(&candidate, &target)?;
        parent_barrier(&target)?;
        #[cfg(windows)]
        let file = OpenOptions::new().read(true).write(true).open(&target)?;
        file_barrier(&file)?;
        verify_bytes(&target, data)?;
        Ok(())
    })();
    result.map_err(|e| error(phase, kind(&e), &[&target, &candidate], e))?;
    Ok(DurableFileReceipt {
        path: target,
        content_hash: sha256(data),
        len: data.len(),
    })
}

/// Reconcile an uncertain publication by exact readback *and* renewed barriers.
/// This never silently rewrites mismatched content to claim the old commit.
pub fn durable_reconcile(
    path: &Path,
    data: &[u8],
) -> Result<DurableFileReceipt, DurableWriteError> {
    let _guard = ATOMIC_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let result = (|| {
        let path = target_path(path)?;
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        verify_bytes(&path, data)?;
        file_barrier(&file)?;
        parent_barrier(&path)?;
        file_barrier(&file)?;
        verify_bytes(&path, data)?;
        Ok(DurableFileReceipt {
            path,
            content_hash: sha256(data),
            len: data.len(),
        })
    })();
    result.map_err(|e: io::Error| error(DurableCommitPhase::CommitUncertain, kind(&e), &[path], e))
}

fn verify_hash(path: &Path, expected: [u8; 32], maximum_len: usize) -> io::Result<usize> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut len: usize = 0;
    let mut chunk = [0u8; 8192];
    loop {
        let count = read_retrying(&mut file, &mut chunk)?;
        if count == 0 {
            break;
        }
        len = len
            .checked_add(count)
            .filter(|len| *len <= maximum_len)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "durable file exceeds its reconciliation bound",
                )
            })?;
        digest.update(&chunk[..count]);
    }
    let hash: [u8; 32] = digest.finalize().into();
    if hash != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable file hash mismatch",
        ));
    }
    Ok(len)
}

/// Reconcile a journal-recorded hash using bounded streaming readback and all
/// required native barriers. The caller supplies trusted transaction metadata;
/// a receipt does not establish the provenance or validity of message contents.
pub fn durable_reconcile_hash(
    path: &Path,
    expected_sha256: [u8; 32],
    maximum_len: usize,
) -> Result<DurableFileReceipt, DurableWriteError> {
    let _guard = ATOMIC_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let result = (|| {
        let path = target_path(path)?;
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        let len = verify_hash(&path, expected_sha256, maximum_len)?;
        file_barrier(&file)?;
        parent_barrier(&path)?;
        file_barrier(&file)?;
        if verify_hash(&path, expected_sha256, maximum_len)? != len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable file length changed",
            ));
        }
        Ok(DurableFileReceipt {
            path,
            content_hash: expected_sha256,
            len,
        })
    })();
    result.map_err(|cause: io::Error| {
        error(
            DurableCommitPhase::CommitUncertain,
            kind(&cause),
            &[path],
            cause,
        )
    })
}

fn open_witness(witness: &DurableFileReceipt, parent: &Path) -> io::Result<File> {
    let path = target_path(&witness.path)?;
    let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
    let mut digest = Sha256::new();
    let mut remaining = witness.len;
    let mut chunk = [0u8; 8192];
    loop {
        let count = read_retrying(&mut file, &mut chunk)?;
        if count == 0 {
            break;
        }
        remaining = remaining
            .checked_sub(count)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "committed witness grew"))?;
        digest.update(&chunk[..count]);
    }
    let hash: [u8; 32] = digest.finalize().into();
    if remaining != 0 || hash != witness.content_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "committed witness changed",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fs::metadata(parent)?.dev() != fs::metadata(&path)?.dev() {
            return Err(invalid("witness must be on the same filesystem"));
        }
    }
    #[cfg(windows)]
    {
        // Volume roots are compared by the native volume-path API, not drive
        // letters alone (mounted volumes are valid private application paths).
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetVolumePathNameW;
        let volume = |p: &Path| -> io::Result<Vec<u16>> {
            let p = p
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let mut root = vec![0u16; 32768];
            if unsafe { GetVolumePathNameW(p.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0
            {
                return Err(io::Error::last_os_error());
            }
            root.truncate(root.iter().position(|c| *c == 0).unwrap_or(root.len()));
            Ok(root)
        };
        if volume(parent)? != volume(&path)? {
            return Err(invalid("witness must be on the same filesystem"));
        }
    }
    Ok(file)
}

// Re-establish the directory chain on both the first attempt and a restart
// after some or all creations succeeded. The witness roots the transaction;
// synchronize through the nearest shared ancestor, including sibling trees.
#[cfg(not(windows))]
fn directory_chain_barrier(path: &Path, witness: &DurableFileReceipt) -> io::Result<()> {
    let witness_parent = witness
        .path
        .parent()
        .ok_or_else(|| invalid("witness has no parent"))?;
    let common = path
        .ancestors()
        .find(|ancestor| witness_parent.starts_with(ancestor))
        .ok_or_else(|| invalid("directory and witness have no common ancestor"))?;
    #[cfg(unix)]
    for directory in path.ancestors() {
        supported_barrier(File::open(directory)?.sync_all())?;
        if directory == common {
            break;
        }
    }
    #[cfg(not(unix))]
    let _ = common;
    Ok(())
}

/// Re-establish an existing journal-owned directory transition after restart.
/// The caller must first verify the journal's expected paths, entries and hashes;
/// this receipt acknowledges only the renewed native directory/witness barriers.
pub fn durable_reconcile_directory(
    path: &Path,
    witness: &DurableFileReceipt,
) -> Result<DurableDirectoryReceipt, DurableWriteError> {
    #[cfg(windows)]
    return Err(error(
        DurableCommitPhase::CommitUncertain,
        DurableErrorKind::DurabilityUnsupported,
        &[path, &witness.path],
        unsupported(
            "directory rename recovery requires a journaled fresh sibling WRITE_THROUGH transition on Windows",
        ),
    ));
    #[cfg(not(windows))]
    {
        let _guard = ATOMIC_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let result = (|| {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid("directory must be a real directory"));
            }
            let path = fs::canonicalize(path)?;
            note_storage(&path)?;
            if witness.path.starts_with(&path) {
                return Err(invalid("directory witness must be outside the tree"));
            }
            let journal = open_witness(witness, &path)?;
            directory_chain_barrier(&path, witness)?;
            file_barrier(&journal)?;
            Ok(DurableDirectoryReceipt { path })
        })();
        result.map_err(|cause: io::Error| {
            error(
                DurableCommitPhase::CommitUncertain,
                kind(&cause),
                &[path, &witness.path],
                cause,
            )
        })
    }
}

/// Remove a transaction artifact after a separate committed witness exists.
/// An error after deletion is cleanup-pending, never permission to roll back or
/// destroy the witness. Windows acknowledges deletion and witness flush without
/// claiming a separate directory-fsync guarantee.
pub fn durable_remove(
    path: &Path,
    witness: &DurableFileReceipt,
) -> Result<DurableCleanupOutcome, DurableWriteError> {
    let _guard = ATOMIC_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut phase = DurableCommitPhase::NotCommitted;
    let result = (|| {
        let target = target_path(path)?;
        if target == witness.path {
            return Err(invalid("cannot remove the commit witness"));
        }
        let file = open_witness(witness, target.parent().unwrap())?;
        phase = DurableCommitPhase::CommitUncertain;
        let outcome = match fs::remove_file(&target) {
            Ok(()) => DurableCleanupOutcome::Removed,
            Err(e) if e.kind() == io::ErrorKind::NotFound => DurableCleanupOutcome::AlreadyAbsent,
            Err(e) => return Err(e),
        };
        parent_barrier(&target)?;
        file_barrier(&file)?;
        Ok(outcome)
    })();
    result.map_err(|e: io::Error| error(phase, kind(&e), &[path, &witness.path], e))
}

/// Move a directory to a fresh sibling under an already durable outside intent.
/// The caller enforces the offline writer fence and records every phase.
pub fn durable_rename_directory(
    source: &Path,
    destination: &Path,
    witness: &DurableFileReceipt,
) -> Result<DurableDirectoryReceipt, DurableWriteError> {
    let _guard = ATOMIC_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut phase = DurableCommitPhase::NotCommitted;
    let result = (|| {
        let source_parent = fs::canonicalize(
            source
                .parent()
                .ok_or_else(|| invalid("source has no parent"))?,
        )?;
        let destination_parent = fs::canonicalize(
            destination
                .parent()
                .ok_or_else(|| invalid("destination has no parent"))?,
        )?;
        if source_parent != destination_parent {
            return Err(invalid(
                "directory migration requires siblings on one volume",
            ));
        }
        note_storage(&source_parent)?;
        let source = source_parent.join(
            source
                .file_name()
                .ok_or_else(|| invalid("source has no name"))?,
        );
        let destination = source_parent.join(
            destination
                .file_name()
                .ok_or_else(|| invalid("destination has no name"))?,
        );
        let metadata = fs::symlink_metadata(&source)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid("source must be a real directory"));
        }
        match fs::symlink_metadata(&destination) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(invalid("archive destination already exists")),
            Err(e) => return Err(e),
        }
        if witness.path.starts_with(&source) || witness.path.starts_with(&destination) {
            return Err(invalid("migration witness must be outside both trees"));
        }
        let journal = open_witness(witness, &source_parent)?;
        phase = DurableCommitPhase::CommitUncertain;
        #[cfg(not(windows))]
        fs::rename(&source, &destination)?;
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
            let from = source
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let to = destination
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        parent_barrier(&destination)?;
        file_barrier(&journal)?;
        if !fs::symlink_metadata(&destination)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "directory publication readback failed",
            ));
        }
        Ok(DurableDirectoryReceipt { path: destination })
    })();
    result.map_err(|e: io::Error| error(phase, kind(&e), &[source, destination, &witness.path], e))
}

/// Create the journal-described directory tree, checking native barriers on
/// every new ancestor. The caller must subsequently publish its format marker
/// and phase record; this receipt alone is not a completed migration.
pub fn durable_create_dir_all(
    path: &Path,
    witness: &DurableFileReceipt,
) -> Result<DurableDirectoryReceipt, DurableWriteError> {
    #[cfg(windows)]
    return publish_directory_tree(path, witness);
    #[cfg(not(windows))]
    {
        let _guard = ATOMIC_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut phase = DurableCommitPhase::NotCommitted;
        let result = (|| {
            let mut missing = Vec::new();
            let mut cursor = path;
            loop {
                match fs::symlink_metadata(cursor) {
                    Ok(m) if m.is_dir() && !m.file_type().is_symlink() => break,
                    Ok(_) => return Err(invalid("directory ancestor is not a real directory")),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        let name = cursor
                            .file_name()
                            .ok_or_else(|| invalid("invalid directory component"))?
                            .to_os_string();
                        missing.push(name);
                        cursor = cursor
                            .parent()
                            .filter(|p| !p.as_os_str().is_empty())
                            .unwrap_or(Path::new("."));
                    }
                    Err(e) => return Err(e),
                }
            }
            let mut current = fs::canonicalize(cursor)?;
            note_storage(&current)?;
            let journal = open_witness(witness, &current)?;
            for name in missing.into_iter().rev() {
                current.push(name);
                phase = DurableCommitPhase::CommitUncertain;
                let builder = fs::DirBuilder::new();
                #[cfg(unix)]
                let builder = {
                    use std::os::unix::fs::DirBuilderExt;
                    let mut builder = builder;
                    builder.mode(0o700);
                    builder
                };
                builder.create(&current)?;
            }
            // Existing paths may be left by an interrupted earlier attempt.
            // Existence alone is never acknowledgement of its directory barriers.
            phase = DurableCommitPhase::CommitUncertain;
            directory_chain_barrier(&current, witness)?;
            file_barrier(&journal)?;
            Ok(DurableDirectoryReceipt { path: current })
        })();
        result.map_err(|e: io::Error| error(phase, kind(&e), &[path, &witness.path], e))
    }
}

// A directory already existing after a crash is not proof of its publication.
// Windows uses an outside durable journal and fresh WRITE_THROUGH sibling move;
// the committed marker avoids repeatedly renaming a live directory. The caller
// initializes this boundary before allowing concurrent users of the tree.
#[cfg(any(windows, test))]
#[derive(serde::Serialize, serde::Deserialize)]
struct DirectoryPublicationJournal {
    version: u8,
    target: PathBuf,
    staging: PathBuf,
    committed: bool,
}
#[cfg(any(windows, test))]
fn publish_directory_tree(
    path: &Path,
    witness: &DurableFileReceipt,
) -> Result<DurableDirectoryReceipt, DurableWriteError> {
    let result = (|| -> Result<PathBuf, DurableWriteError> {
        let ioe = |e: io::Error| {
            error(
                DurableCommitPhase::CommitUncertain,
                kind(&e),
                &[path, &witness.path],
                e,
            )
        };
        let mut missing = Vec::new();
        let mut cursor = path;
        loop {
            match fs::symlink_metadata(cursor) {
                Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => break,
                Ok(_) => return Err(ioe(invalid("directory ancestor is not a real directory"))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    missing.push(
                        cursor
                            .file_name()
                            .ok_or_else(|| ioe(invalid("invalid directory name")))?
                            .to_os_string(),
                    );
                    cursor = cursor
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or(Path::new("."));
                }
                Err(e) => return Err(ioe(e)),
            }
        }
        let mut current = fs::canonicalize(cursor).map_err(ioe)?;
        note_storage(&current).map_err(ioe)?;
        // Validate the exact outside transaction authority, then close its
        // handle before a Windows directory containing it could be renamed.
        drop(open_witness(witness, &current).map_err(ioe)?);
        if missing.is_empty() {
            publish_one_directory(&current)?;
        } else {
            for name in missing.into_iter().rev() {
                current.push(name);
                publish_one_directory(&current)?;
            }
        }
        Ok(current)
    })();
    result.map(|path| DurableDirectoryReceipt { path })
}
#[cfg(any(windows, test))]
fn publish_one_directory(target: &Path) -> Result<(), DurableWriteError> {
    use std::io::Read;

    let ioe = |e: io::Error| error(DurableCommitPhase::CommitUncertain, kind(&e), &[target], e);
    let sibling = |suffix: &str| -> io::Result<PathBuf> {
        let mut name = target
            .file_name()
            .ok_or_else(|| invalid("directory has no name"))?
            .to_os_string();
        name.push(suffix);
        Ok(target.with_file_name(name))
    };
    let journal_path = sibling(".rns-directory").map_err(ioe)?;
    let lock_path = sibling(".rns-directory-lock").map_err(ioe)?;
    target_path(&lock_path).map_err(ioe)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(ioe)?;
    super::try_lock_exclusive(&lock).map_err(ioe)?;
    let mut journal = match fs::symlink_metadata(&journal_path) {
        Ok(meta) => {
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 8192 {
                return Err(ioe(invalid("invalid directory publication journal")));
            }
            let mut bytes = Vec::new();
            File::open(&journal_path)
                .map_err(ioe)?
                .take(8193)
                .read_to_end(&mut bytes)
                .map_err(ioe)?;
            if bytes.len() > 8192 {
                return Err(ioe(invalid("oversized directory publication journal")));
            }
            let record: DirectoryPublicationJournal =
                rmp_serde::from_slice(&bytes).map_err(|e| ioe(io::Error::other(e)))?;
            if record.version != 1
                || record.target != target
                || record.staging.parent() != target.parent()
                || record.staging == target
                || record.staging == journal_path
                || record.staging == lock_path
            {
                return Err(ioe(invalid("directory publication paths mismatch")));
            }
            let mut prefix = target.file_name().unwrap().to_os_string();
            prefix.push(".rns-publish-");
            if !record.staging.file_name().is_some_and(|n| {
                n.to_string_lossy()
                    .starts_with(prefix.to_string_lossy().as_ref())
            }) {
                return Err(ioe(invalid("directory staging name mismatch")));
            }
            if record.committed {
                let meta = fs::symlink_metadata(target).map_err(ioe)?;
                if !meta.is_dir() || meta.file_type().is_symlink() {
                    return Err(ioe(invalid("committed directory missing or replaced")));
                }
                durable_reconcile(&journal_path, &bytes)?;
                return Ok(());
            }
            record
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => DirectoryPublicationJournal {
            version: 1,
            target: target.to_owned(),
            staging: sibling(&format!(
                ".rns-publish-{}",
                hex::encode(rand::random::<[u8; 16]>())
            ))
            .map_err(ioe)?,
            committed: false,
        },
        Err(e) => return Err(ioe(e)),
    };
    let encode = |record: &DirectoryPublicationJournal| {
        rmp_serde::to_vec_named(record).map_err(|e| ioe(io::Error::other(e)))
    };
    let mut receipt = durable_write(&journal_path, &encode(&journal)?)?;
    let source_exists = fs::symlink_metadata(target).is_ok();
    let staging_exists = fs::symlink_metadata(&journal.staging).is_ok();
    if source_exists && staging_exists {
        return Err(ioe(invalid("both directory publication locations exist")));
    }
    if source_exists {
        // A final move could have succeeded before its committed marker. Repeat
        // through a fresh journaled sibling, never infer success from existence.
        journal.staging = sibling(&format!(
            ".rns-publish-{}",
            hex::encode(rand::random::<[u8; 16]>())
        ))
        .map_err(ioe)?;
        receipt = durable_write(&journal_path, &encode(&journal)?)?;
        durable_rename_directory(target, &journal.staging, &receipt)?;
    } else if !staging_exists {
        fs::create_dir(&journal.staging).map_err(ioe)?;
    }
    durable_rename_directory(&journal.staging, target, &receipt)?;
    journal.committed = true;
    durable_write(&journal_path, &encode(&journal)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn hash_verification_retries_an_interrupted_read() {
        let data = vec![0x3c; 64];
        let expected = sha256(&data);
        let result = super::super::tests::read_through_a_signal(
            "verify-hash-interrupted",
            &data,
            move |path| verify_hash(path, expected, 64),
        );
        assert_eq!(result.unwrap(), 64);
    }

    fn dir() -> PathBuf {
        let path = super::super::tests::unique_test_dir("durable");
        fs::create_dir(&path).unwrap();
        path
    }

    fn assert_directory_reconciliation(path: &Path, witness: &DurableFileReceipt) {
        let result = durable_reconcile_directory(path, witness);
        #[cfg(not(windows))]
        result.unwrap();
        #[cfg(windows)]
        assert_eq!(
            result.unwrap_err().kind,
            DurableErrorKind::DurabilityUnsupported
        );
    }

    #[test]
    fn risky_storage_is_reported_and_still_written() {
        let local = dir();
        #[cfg(target_os = "macos")]
        assert_eq!(storage_risk(&local).unwrap(), None);
        assert!(storage_risk(&local).is_ok());
        #[cfg(target_os = "linux")]
        {
            let shm = Path::new("/dev/shm");
            if shm.is_dir() {
                assert_eq!(storage_risk(shm).unwrap(), Some(StorageRisk::Volatile));
                let path = shm.join(format!("rns-durable-{}", std::process::id()));
                durable_write(&path, b"volatile").unwrap();
                assert_eq!(fs::read(&path).unwrap(), b"volatile");
                fs::remove_file(path).unwrap();
            }
        }
        fs::remove_dir_all(local).unwrap();
    }

    #[test]
    fn strict_write_receipt_reconcile_and_cleanup() {
        let dir = dir();
        let path = dir.join("state");
        let receipt = durable_write(&path, b"committed").unwrap();
        assert_eq!(receipt.content_hash(), sha256(b"committed"));
        assert_eq!(receipt.len(), 9);
        assert_eq!(fs::read(receipt.path()).unwrap(), b"committed");
        assert!(durable_reconcile(&path, b"wrong").is_err());
        assert_eq!(
            durable_reconcile(&path, b"committed")
                .unwrap()
                .content_hash(),
            receipt.content_hash()
        );
        let old = dir.join("old");
        durable_write(&old, b"old").unwrap();
        assert_eq!(
            durable_remove(&old, &receipt).unwrap(),
            DurableCleanupOutcome::Removed
        );
        assert_eq!(
            durable_remove(&old, &receipt).unwrap(),
            DurableCleanupOutcome::AlreadyAbsent
        );
        assert!(durable_remove(&path, &receipt).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn strict_write_into_a_missing_directory_commits_nothing() {
        let root = dir();
        let missing = root.join("missing");
        let failure = durable_write(&missing.join("state"), b"new").unwrap_err();
        assert_eq!(failure.phase, DurableCommitPhase::NotCommitted);
        assert!(!missing.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn strict_write_rejects_a_directory_at_the_target() {
        let root = dir();
        let target = root.join("state");
        fs::create_dir(&target).unwrap();
        let failure = durable_write(&target, b"new").unwrap_err();
        assert_eq!(failure.phase, DurableCommitPhase::NotCommitted);
        assert_eq!(failure.kind, DurableErrorKind::InvalidInput);
        assert!(target.is_dir());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn strict_write_in_a_read_only_directory_keeps_the_previous_file() {
        use std::os::unix::fs::PermissionsExt;
        if super::super::tests::is_root() {
            return;
        }
        let root = dir();
        let target = root.join("state");
        durable_write(&target, b"old").unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();

        let result = durable_write(&target, b"new");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let failure = result.unwrap_err();
        assert_eq!(failure.phase, DurableCommitPhase::NotCommitted);
        assert_eq!(failure.kind, DurableErrorKind::Io);
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn strict_write_onto_an_immutable_target_is_uncertain_and_recoverable() {
        let root = dir();
        let target = root.join("state");
        durable_write(&target, b"old").unwrap();
        let immutable = super::super::tests::Immutable::new(&target);

        let result = durable_write(&target, b"new");
        drop(immutable);

        let failure = result.unwrap_err();
        assert_eq!(failure.phase, DurableCommitPhase::CommitUncertain);
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert!(
            failure.recovery_paths.iter().any(|path| {
                path != &target && fs::read(path).is_ok_and(|bytes| bytes == b"new")
            })
        );
        assert!(durable_reconcile(&target, b"new").is_err());
        durable_write(&target, b"new").unwrap();
        durable_reconcile(&target, b"new").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn strict_directory_journal_and_changed_witness() {
        let dir = dir();
        let journal = durable_write(&dir.join("journal"), b"phase one").unwrap();
        let source = dir.join("old");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("item"), b"payload").unwrap();
        let archive = dir.join("archive");
        durable_rename_directory(&source, &archive, &journal).unwrap();
        assert_eq!(fs::read(archive.join("item")).unwrap(), b"payload");
        assert!(durable_rename_directory(&archive, &archive, &journal).is_err());
        durable_write(&source, b"migrated tombstone").unwrap();
        let tree = dir.join("v2").join("objects");
        durable_create_dir_all(&tree, &journal).unwrap();
        durable_create_dir_all(&tree, &journal).unwrap();
        assert_directory_reconciliation(&archive, &journal);
        assert!(tree.is_dir());
        fs::write(journal.path(), b"replaced").unwrap();
        assert!(durable_remove(&source, &journal).is_err());
        assert!(source.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn strict_directory_retry_supports_sibling_journal_and_readonly_qualification() {
        let dir = dir();
        let state = dir.join("state");
        fs::create_dir(&state).unwrap();
        let journal = durable_write(&state.join("journal"), b"intent").unwrap();
        let tree = dir.join("messages").join("objects");
        let first = durable_create_dir_all(&tree, &journal).unwrap();
        assert_eq!(first.path(), fs::canonicalize(&tree).unwrap());
        assert_directory_reconciliation(&tree, &journal);
        durable_create_dir_all(&tree, &journal).unwrap();
        validate_durable_storage_directory(&tree).unwrap();
        assert_eq!(fs::read_dir(&tree).unwrap().count(), 0);
        assert!(validate_durable_storage_directory(journal.path()).is_err());
        assert!(validate_durable_storage_directory(&dir.join("missing")).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn strict_witness_length_and_content_changes_never_authorize_cleanup() {
        let dir = dir();
        for bytes in [b"abc".as_slice(), b"abcde", b"xbcd"] {
            let witness = durable_write(&dir.join("journal"), b"abcd").unwrap();
            let target = dir.join("obsolete");
            fs::write(&target, b"keep").unwrap();
            fs::write(witness.path(), bytes).unwrap();
            let error = durable_remove(&target, &witness).unwrap_err();
            assert_eq!(error.phase, DurableCommitPhase::NotCommitted);
            assert_eq!(error.kind, DurableErrorKind::Verification);
            assert_eq!(fs::read(&target).unwrap(), b"keep");
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn strict_hash_reconciliation_enforces_hash_and_length_bound() {
        let dir = dir();
        let data = vec![0x5a; 65537];
        let receipt = durable_write(&dir.join("archive"), &data).unwrap();
        let restored =
            durable_reconcile_hash(receipt.path(), receipt.content_hash(), data.len()).unwrap();
        assert_eq!(restored.len(), data.len());
        assert!(
            durable_reconcile_hash(receipt.path(), receipt.content_hash(), data.len() - 1).is_err()
        );
        assert!(durable_reconcile_hash(receipt.path(), [0; 32], data.len()).is_err());
        assert_eq!(fs::read(receipt.path()).unwrap(), data);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_sharing_violation_preserves_old_target_and_recoverable_candidate() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        let root = dir();
        let target = root.join("state");
        durable_write(&target, b"old").unwrap();
        // Permit readers and writers but refuse deletion/rename while this
        // Windows handle is open.
        let held = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&target)
            .unwrap();
        let failure = durable_write(&target, b"new").unwrap_err();
        assert_eq!(failure.phase, DurableCommitPhase::CommitUncertain);
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert!(
            failure.recovery_paths.iter().any(|path| {
                path != &target && fs::read(path).is_ok_and(|bytes| bytes == b"new")
            })
        );
        drop(held);
        assert!(durable_reconcile(&target, b"new").is_err());
        let receipt = durable_write(&target, b"new").unwrap();
        assert_eq!(receipt.content_hash(), sha256(b"new"));
        durable_reconcile(&target, b"new").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_cleanup_sharing_violation_retains_witness_and_retries() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        let root = dir();
        let witness = durable_write(&root.join("commit"), b"committed").unwrap();
        let obsolete = root.join("obsolete");
        durable_write(&obsolete, b"recovery copy").unwrap();
        let held = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&obsolete)
            .unwrap();
        let failure = durable_remove(&obsolete, &witness).unwrap_err();
        assert_eq!(failure.phase, DurableCommitPhase::CommitUncertain);
        assert_eq!(fs::read(&obsolete).unwrap(), b"recovery copy");
        assert_eq!(fs::read(witness.path()).unwrap(), b"committed");
        drop(held);
        assert_eq!(
            durable_remove(&obsolete, &witness).unwrap(),
            DurableCleanupOutcome::Removed
        );
        durable_reconcile(witness.path(), b"committed").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn strict_targets_and_directories_reject_symlinks_and_preserve_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = dir();
        let receipt = durable_write(&dir.join("journal"), b"intent").unwrap();
        assert_eq!(
            fs::metadata(receipt.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = dir.join("link");
        symlink(receipt.path(), &link).unwrap();
        assert!(durable_write(&link, b"replace").is_err());
        assert!(durable_remove(&link, &receipt).is_err());
        let directory_link = dir.join("directory-link");
        symlink(&dir, &directory_link).unwrap();
        assert!(validate_durable_storage_directory(&directory_link).is_err());
        assert!(durable_create_dir_all(&directory_link, &receipt).is_err());
        assert!(durable_reconcile_directory(&directory_link, &receipt).is_err());
        assert_eq!(fs::read(receipt.path()).unwrap(), b"intent");
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn directory_publication_recovers_every_crash_state() {
        // A journal left uncommitted by a crash, with the tree where that crash
        // left it. The first and third leave the same files behind, so
        // publication cannot tell them apart and repeats the move.
        for (state, at_target, at_staging, has_contents) in [
            ("intent written", true, false, true),
            ("tree moved to staging", false, true, true),
            ("final move done without committed", true, false, true),
            ("intent written for a new tree", false, false, false),
            ("new tree staged", false, true, false),
        ] {
            let root = fs::canonicalize(dir()).unwrap();
            let witness = durable_write(&root.join("intent"), b"outside transaction").unwrap();
            let tree = root.join("tree");
            let staging = root.join("tree.rns-publish-00112233445566778899aabbccddeeff");
            let journal = root.join("tree.rns-directory");
            if at_target || at_staging {
                let location = if at_target { &tree } else { &staging };
                fs::create_dir(location).unwrap();
                if has_contents {
                    fs::write(location.join("retained"), b"original").unwrap();
                }
            }
            let record = DirectoryPublicationJournal {
                version: 1,
                target: tree.clone(),
                staging,
                committed: false,
            };
            durable_write(&journal, &rmp_serde::to_vec_named(&record).unwrap()).unwrap();

            publish_directory_tree(&tree, &witness).unwrap();

            let recorded: DirectoryPublicationJournal =
                rmp_serde::from_slice(&fs::read(&journal).unwrap()).unwrap();
            assert!(recorded.committed, "{state}");
            assert_eq!(
                fs::read_dir(&tree).unwrap().count(),
                usize::from(has_contents),
                "{state}"
            );
            if has_contents {
                assert_eq!(fs::read(tree.join("retained")).unwrap(), b"original");
            }
            assert!(
                fs::read_dir(&root).unwrap().all(|entry| {
                    !entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .contains(".rns-publish-")
                }),
                "{state}: staging left behind"
            );
            publish_directory_tree(&tree, &witness).unwrap();
            assert_eq!(
                fs::read_dir(&tree).unwrap().count(),
                usize::from(has_contents),
                "{state}"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn directory_publication_creates_nested_trees_and_rejects_missing_committed_target() {
        let root = dir();
        let witness = durable_write(&root.join("intent"), b"outside transaction").unwrap();
        let tree = root.join("parent").join("child");
        publish_directory_tree(&tree, &witness).unwrap();
        assert!(tree.is_dir());
        fs::remove_dir(&tree).unwrap();
        assert!(publish_directory_tree(&tree, &witness).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
