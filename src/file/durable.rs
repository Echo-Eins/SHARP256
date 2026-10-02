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
//! state and identity files, [`rename`] for results moved into place,
//! [`sync_dir`] after anything is created, moved into place or removed
//! where it matters, and [`remove`]. Windows has no documented way to flush
//! a directory; there a move is asked to be on disk when it returns
//! (`MOVEFILE_WRITE_THROUGH`), and `sync_dir` flushes the directory as far
//! as NTFS takes it — neither checked by a power cut (docs/THREAT_MODEL.md,
//! Р23).

use rand::RngCore;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// `o`, made to open a received file without going through a symbolic link
/// at its name. Anybody else who can write the directory — a shared
/// download folder — could otherwise put a link where a partial file is
/// about to be, and have the transfer written into, and truncated to its
/// size, whatever file the link names. On Unix the open fails
/// (`O_NOFOLLOW`); on Windows the link itself is opened, which
/// [`not_a_link`] refuses.
pub fn no_follow(o: &mut fs::OpenOptions) -> &mut fs::OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        o.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    o
}

/// `f`, opened at `path` with [`no_follow`], unless it is a link after all.
pub fn not_a_link(f: fs::File, path: &Path) -> io::Result<fs::File> {
    if f.metadata()?.file_type().is_symlink() {
        return Err(link_refused(path));
    }
    Ok(f)
}

fn link_refused(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{} is a symbolic link where a received file is to be: not written through",
            path.display()
        ),
    )
}

/// Which file is at `path` — itself, not where a link would lead — when it
/// is a regular file: to check, before a partial file is moved into place,
/// that it is still the one written and hashed (see [`still_the_same`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    /// Device and inode on Unix, volume serial number and file index on
    /// Windows.
    #[cfg(any(unix, windows))]
    volume: u64,
    #[cfg(any(unix, windows))]
    index: u64,
    len: u64,
}

pub fn file_id(path: &Path) -> io::Result<FileId> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() {
        return Err(link_refused(path));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(FileId {
            volume: m.dev(),
            index: m.ino(),
            len: m.len(),
        })
    }
    #[cfg(windows)]
    {
        let (volume, index) = windows_file_index(path)?;
        Ok(FileId {
            volume,
            index,
            len: m.len(),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(FileId { len: m.len() })
    }
}

/// The volume serial number and file index of what is at `path` — not of
/// where a link there leads. (The standard library's accessors for them
/// are not stable.)
#[cfg(windows)]
#[allow(unsafe_code)] // GetFileInformationByHandle (docs/UNSAFE.md)
fn windows_file_index(path: &Path) -> io::Result<(u64, u64)> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use winapi::um::fileapi::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    // No access asked for: what the standard library opens a file with to
    // read its metadata.
    let f = fs::OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    // SAFETY: a plain C struct of integers and times, for which all zeroes
    // is a valid value.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a handle alive for the call, and that struct to fill.
    let ok = unsafe { GetFileInformationByHandle(f.as_raw_handle().cast(), &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        info.dwVolumeSerialNumber as u64,
        (info.nFileIndexHigh as u64) << 32 | info.nFileIndexLow as u64,
    ))
}

/// An error unless `path` is still the file `id` was taken of.
pub fn still_the_same(path: &Path, id: FileId) -> io::Result<()> {
    if file_id(path)? != id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} was replaced while it was being finished: not moved into place",
                path.display()
            ),
        ));
    }
    Ok(())
}

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
        rename(&tmp, path)?;
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

/// Renames `from` to `to`, over whatever is there. The rename reaches the
/// disk with [`sync_dir`] of the directory on Unix; on Windows the move is
/// itself asked to be on disk before it returns.
pub fn rename(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
        match move_file(from, to, MOVEFILE_REPLACE_EXISTING) {
            // A target someone holds open is not replaced by MoveFileEx;
            // the standard library's rename can (POSIX semantics), only
            // without the write-through.
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => fs::rename(from, to),
            r => r,
        }
    }
    #[cfg(not(windows))]
    {
        fs::rename(from, to)
    }
}

/// `MoveFileExW` with `flags` and `MOVEFILE_WRITE_THROUGH`: documented not to
/// return until the move is on disk.
#[cfg(windows)]
#[allow(unsafe_code)] // MoveFileExW (docs/UNSAFE.md)
pub(crate) fn move_file(from: &Path, to: &Path, flags: u32) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let wide = |p: &Path| -> io::Result<Vec<u16>> {
        Ok(long_path(p)?
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect())
    };
    let (f, t) = (wide(from)?, wide(to)?);
    // SAFETY: two NUL-terminated wide paths, alive for the call.
    let ok = unsafe {
        winapi::um::winbase::MoveFileExW(f.as_ptr(), t.as_ptr(), flags | MOVEFILE_WRITE_THROUGH)
    };
    if ok != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `p` in the form Windows takes a path longer than `MAX_PATH` in, when it
/// is that long: absolute, and verbatim (`\\?\C:\…`, `\\?\UNC\server\…`).
/// The standard library does this for its own calls; one made directly
/// has to.
#[cfg(windows)]
fn long_path(p: &Path) -> io::Result<PathBuf> {
    /// `MAX_PATH` less room for an 8.3 name, as the standard library has it.
    const SHORT: usize = 248;
    if p.as_os_str().len() < SHORT {
        return Ok(p.to_path_buf());
    }
    let full = std::path::absolute(p)?;
    let Some(s) = full.to_str() else {
        return Ok(full);
    };
    Ok(PathBuf::from(
        if s.starts_with(r"\\?\") || s.starts_with(r"\\.\") {
            s.to_string()
        } else if let Some(unc) = s.strip_prefix(r"\\") {
            format!(r"\\?\UNC\{}", unc)
        } else {
            format!(r"\\?\{}", s)
        },
    ))
}

/// Flushes the names in a directory — files created, renamed or removed in
/// it — to disk. On Windows only as far as NTFS takes a flush of a
/// directory handle, and never an error (see the module's notes).
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        if let Ok(d) = fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)
        {
            let _ = d.sync_all();
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
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

    /// A path longer than Windows' `MAX_PATH` is moved to and from like any
    /// other (the standard library makes such paths verbatim for its own
    /// calls; `move_file` has to itself).
    #[cfg(windows)]
    #[test]
    fn long_paths_are_moved() {
        let dir = tempfile::tempdir().unwrap();
        let mut deep = dir.path().to_path_buf();
        while deep.as_os_str().len() < 300 {
            deep.push("a-directory-with-a-long-name");
        }
        fs::create_dir_all(&deep).unwrap();
        let (from, to) = (deep.join("x.sharp-part"), deep.join("x"));
        fs::write(&from, b"long").unwrap();
        rename(&from, &to).unwrap();
        assert_eq!(fs::read(&to).unwrap(), b"long");
        fs::write(&from, b"again").unwrap();
        assert_eq!(
            move_file(&from, &to, 0).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists,
            "without MOVEFILE_REPLACE_EXISTING"
        );
    }

    /// A file is known by itself, not by its name: replaced under the same
    /// name — another file renamed over it, a link put in its place — it is
    /// another, and is not moved into place.
    #[test]
    fn a_file_replaced_under_its_name_is_found_out() {
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("x.sharp-part");
        fs::write(&part, b"written and hashed").unwrap();
        let id = file_id(&part).unwrap();
        still_the_same(&part, id).unwrap();
        let other = dir.path().join("other");
        fs::write(&other, b"written and hashed").unwrap();
        fs::rename(&other, &part).unwrap();
        assert!(still_the_same(&part, id).is_err(), "a file renamed over it");
        #[cfg(unix)]
        {
            fs::remove_file(&part).unwrap();
            std::os::unix::fs::symlink(dir.path().join("elsewhere"), &part).unwrap();
            assert!(file_id(&part).is_err(), "a link is no file of ours");
        }
    }

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
