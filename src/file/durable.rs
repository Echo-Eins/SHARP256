//! Writing so that a power cut leaves the old state or the new one, never
//! a mixture, and never a promise that is not kept.
//!
//! What the system guarantees after a crash is only what was flushed to
//! disk: a file's data and its metadata by `fsync` of the file, the name a
//! file has in a directory — its creation, a rename, a removal — by `fsync`
//! of the directory. Without the second, a file renamed into place may be
//! back under its old name after the crash, or gone; with the first alone,
//! a file renamed over another may be there under the new name and empty
//! (ext4, XFS and btrfs each have ways to show this).
//!
//! So everything this program keeps goes through here: [`replace`] for
//! state and identity files, [`sync_dir`] after anything is created, moved
//! into place or removed where it matters, and [`remove`]. Windows has no
//! way to flush a directory and journals its renames; there `sync_dir` does
//! nothing.

use rand::RngCore;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The directory `path` is in (`.` for a bare name).
pub fn parent_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Replaces the file at `path` (or creates it) with `bytes`, so that after
/// a crash at any moment it is either the old file or the new one, whole:
/// written beside it under a name of its own, flushed, renamed over it, and
/// the directory flushed so that the rename is on disk too. The file is
/// readable by its owner only.
pub fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = parent_of(path);
    let mut name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?
        .to_os_string();
    name.push(format!(".{:016x}.tmp", rand::rngs::OsRng.next_u64()));
    let tmp = dir.join(name);
    let result = (|| {
        create_private(&tmp, bytes)?;
        fs::rename(&tmp, path)?;
        sync_dir(&dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Creates `path`, readable by its owner only, with `bytes`, and flushes
/// it; refuses if something is there. (Its name in the directory is the
/// caller's to flush.)
pub fn create_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Flushes the names in a directory — files created, renamed or removed in
/// it — to disk. Nothing to do on Windows (see the module's notes).
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Removes the file at `path` and flushes its directory, so that it does
/// not come back after a crash. A file that is not there is no error.
pub fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => sync_dir(&parent_of(path)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_creates_replaces_and_leaves_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        replace(&path, b"one").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");
        replace(&path, b"two, longer").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two, longer");
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("state.json")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        remove(&path).unwrap();
        assert!(!path.exists());
        remove(&path).unwrap();
    }

    /// A replacement that cannot be written leaves the old file as it was
    /// and no temporary file behind.
    #[test]
    fn a_failed_replace_leaves_the_old_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        replace(&path, b"old").unwrap();
        // A directory where the file should go: the rename fails.
        let blocked = dir.path().join("blocked");
        fs::create_dir(&blocked).unwrap();
        fs::write(blocked.join("x"), b"").unwrap();
        assert!(replace(&blocked, b"new").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"old");
        let left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(left.is_empty(), "{:?}", left);
    }
}
