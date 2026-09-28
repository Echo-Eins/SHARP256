//! Directory transfers.
//!
//! A directory travels as one byte stream, so that the transport's
//! reliability, flow control, resume and end-to-end verification apply to it
//! unchanged:
//!
//! ```text
//! [ manifest ][ contents of file 1 ][ contents of file 2 ] ... [ file n ]
//! ```
//!
//! The manifest lists every directory and regular file below the root:
//! parents before their children, siblings in byte order of their names,
//! each with its size, Unix permission bits and modification time. File
//! contents follow in manifest order; directories and empty files occupy no
//! bytes of the stream. The whole-stream BLAKE3 hash that concludes every
//! transfer therefore covers names, structure, metadata and contents.
//!
//! Symbolic links and special files are not transferred; the sender skips
//! them and reports what it skipped.
//!
//! # Manifest encoding
//!
//! ```text
//! manifest = version:u8 (1)  reserved:u8 (0)  root  count:varint  entry*
//! root     = head  meta
//! entry    = head  parent:varint  name_len:varint  name  [size:varint]  meta
//! head     = u8: bit 0 directory, bit 1 mode present, bit 2 mtime present
//! meta     = [mode:varint]  [seconds:zigzag varint  nanoseconds:varint]
//! ```
//!
//! `parent` is 0 for the root, otherwise one plus the index of an earlier
//! directory entry; `size` is present for files only. Varints are minimal
//! unsigned LEB128. A decoder rejects everything else: unknown bits, a parent
//! that is not an earlier directory, names that are not single valid path
//! components, siblings out of order or repeated, excessive depth or path
//! length, and trailing bytes.
//!
//! # Receiving safely
//!
//! Names are single path components by construction; the receiver maps each
//! one to what its file system can store (on Windows: reserved characters
//! and device names) and builds the tree inside a fresh, private staging
//! directory. Every entry is created with "create new" semantics, so two
//! names that the local file system considers equal (case-insensitive file
//! systems) are reported as a collision instead of one overwriting the
//! other. Nothing outside the staging directory is written, no symbolic
//! link is created inside it, and set-id bits are never applied. The
//! finished tree is moved to its final name with a single rename.

use super::{read_exact_at, write_all_at};
use crate::protocol::constants::{
    MAX_FILE_NAME_LEN, MAX_MANIFEST_ENTRIES, MAX_MANIFEST_LEN, MAX_TREE_DEPTH, MAX_TREE_PATH,
};
use crate::protocol::wire::TreeInfo;
use parking_lot::Mutex;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MANIFEST_VERSION: u8 = 1;
const HEAD_DIR: u8 = 0x1;
const HEAD_MODE: u8 = 0x2;
const HEAD_MTIME: u8 = 0x4;
const HEAD_KNOWN: u8 = HEAD_DIR | HEAD_MODE | HEAD_MTIME;

/// Files kept open at once by a reader or writer of a tree.
const MAX_OPEN_FILES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
}

/// Metadata carried for every entry and the root.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Meta {
    /// Unix permission bits (at most `0o7777`).
    pub mode: Option<u32>,
    /// Modification time: seconds and nanoseconds since the Unix epoch.
    pub mtime: Option<(i64, u32)>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    /// 0 for the root, otherwise one plus the index of the parent entry.
    pub parent: u32,
    name_at: u32,
    name_len: u16,
    pub kind: EntryKind,
    /// Size of a file (0 for directories).
    pub size: u64,
    /// Offset of a file's first byte in the transfer stream.
    pub start: u64,
    pub meta: Meta,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid directory manifest: {0}")]
pub struct ManifestError(pub String);

/// A decoded (receiver) or scanned (sender) directory tree.
#[derive(Debug, Clone)]
pub struct Manifest {
    root: Meta,
    entries: Vec<Entry>,
    /// All names, concatenated.
    names: String,
    /// Files with contents, in stream order.
    data_files: Vec<u32>,
    data_len: u64,
    files: u64,
    dirs: u64,
    /// Length of the encoded manifest: the stream offset of the first byte
    /// of file contents.
    encoded_len: u64,
}

impl Manifest {
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn root_meta(&self) -> Meta {
        self.root
    }

    /// Name of entry `i` as sent (a single path component).
    pub fn name(&self, i: usize) -> &str {
        let e = &self.entries[i];
        let at = e.name_at as usize;
        &self.names[at..at + e.name_len as usize]
    }

    pub fn files(&self) -> u64 {
        self.files
    }

    pub fn dirs(&self) -> u64 {
        self.dirs
    }

    /// Total size of all files.
    pub fn data_len(&self) -> u64 {
        self.data_len
    }

    pub fn encoded_len(&self) -> u64 {
        self.encoded_len
    }

    /// Length of the whole transfer stream.
    pub fn stream_len(&self) -> u64 {
        self.encoded_len + self.data_len
    }

    /// Files with contents, in stream order.
    pub fn data_files(&self) -> &[u32] {
        &self.data_files
    }

    /// Indices of the entries from the top of the tree down to `i`.
    fn chain(&self, i: usize) -> Vec<usize> {
        let mut chain = vec![i];
        let mut parent = self.entries[i].parent;
        while parent != 0 {
            chain.push(parent as usize - 1);
            parent = self.entries[parent as usize - 1].parent;
        }
        chain.reverse();
        chain
    }

    /// Path of entry `i` relative to the root, with `/` separators, as the
    /// sender named it (for messages).
    pub fn path(&self, i: usize) -> String {
        let mut out = String::new();
        for j in self.chain(i) {
            if !out.is_empty() {
                out.push('/');
            }
            out.push_str(self.name(j));
        }
        out
    }

    /// Where entry `i` lives below `root` on this system (names mapped by
    /// [`local_name`]).
    pub fn local_path(&self, root: &Path, i: usize) -> PathBuf {
        let mut path = root.to_path_buf();
        for j in self.chain(i) {
            path.push(&*local_name(self.name(j)));
        }
        path
    }

    /// The file whose contents hold stream offset `offset`.
    pub fn file_at(&self, offset: u64) -> Option<u32> {
        let n = self
            .data_files
            .partition_point(|&i| self.entries[i as usize].start <= offset);
        let i = *self.data_files.get(n.checked_sub(1)?)?;
        let e = &self.entries[i as usize];
        (offset < e.start + e.size).then_some(i)
    }

    /// The HELLO description of this tree, given its encoding.
    pub fn info(&self, encoded: &[u8]) -> TreeInfo {
        TreeInfo {
            manifest_len: encoded.len() as u64,
            manifest_hash: *blake3::hash(encoded).as_bytes(),
            files: self.files,
            dirs: self.dirs,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.names.len() + 8 * self.entries.len());
        out.push(MANIFEST_VERSION);
        out.push(0);
        out.push(head(EntryKind::Dir, &self.root));
        put_meta(&mut out, &self.root);
        put_varint(&mut out, self.entries.len() as u64);
        for (i, e) in self.entries.iter().enumerate() {
            out.push(head(e.kind, &e.meta));
            put_varint(&mut out, e.parent as u64);
            let name = self.name(i);
            put_varint(&mut out, name.len() as u64);
            out.extend_from_slice(name.as_bytes());
            if e.kind == EntryKind::File {
                put_varint(&mut out, e.size);
            }
            put_meta(&mut out, &e.meta);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Manifest, ManifestError> {
        let bad = |m: &str| ManifestError(m.to_string());
        if bytes.len() as u64 > MAX_MANIFEST_LEN {
            return Err(bad("too large"));
        }
        let mut r = Cursor { buf: bytes, pos: 0 };
        if r.u8()? != MANIFEST_VERSION {
            return Err(bad("unsupported version"));
        }
        if r.u8()? != 0 {
            return Err(bad("reserved byte is set"));
        }
        let root_head = r.u8()?;
        if root_head & !HEAD_KNOWN != 0 || root_head & HEAD_DIR == 0 {
            return Err(bad("malformed root"));
        }
        let root = r.meta(root_head)?;
        let count = r.varint()?;
        if count > MAX_MANIFEST_ENTRIES {
            return Err(bad("too many entries"));
        }
        let mut b = Builder::new(root, (count as usize).min(r.remaining() / 4));
        for _ in 0..count {
            let h = r.u8()?;
            if h & !HEAD_KNOWN != 0 {
                return Err(bad("unknown entry flags"));
            }
            let parent = u32::try_from(r.varint()?).map_err(|_| bad("bad parent"))?;
            let len = r.varint()?;
            if len > MAX_FILE_NAME_LEN as u64 {
                return Err(bad("name too long"));
            }
            let name =
                std::str::from_utf8(r.take(len as usize)?).map_err(|_| bad("name is not UTF-8"))?;
            let kind = if h & HEAD_DIR != 0 {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let size = match kind {
                EntryKind::File => r.varint()?,
                EntryKind::Dir => 0,
            };
            let meta = r.meta(h)?;
            b.push(parent, name, kind, size, meta)
                .map_err(ManifestError)?;
        }
        if r.remaining() != 0 {
            return Err(bad("trailing bytes"));
        }
        b.finish(bytes.len() as u64).map_err(ManifestError)
    }
}

fn head(kind: EntryKind, meta: &Meta) -> u8 {
    let mut h = 0;
    if kind == EntryKind::Dir {
        h |= HEAD_DIR;
    }
    if meta.mode.is_some() {
        h |= HEAD_MODE;
    }
    if meta.mtime.is_some() {
        h |= HEAD_MTIME;
    }
    h
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn put_meta(out: &mut Vec<u8>, meta: &Meta) {
    if let Some(mode) = meta.mode {
        put_varint(out, mode as u64);
    }
    if let Some((secs, nanos)) = meta.mtime {
        put_varint(out, ((secs << 1) ^ (secs >> 63)) as u64);
        put_varint(out, nanos as u64);
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ManifestError> {
        if self.remaining() < n {
            return Err(ManifestError("truncated".into()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, ManifestError> {
        Ok(self.take(1)?[0])
    }

    /// Minimal unsigned LEB128.
    fn varint(&mut self) -> Result<u64, ManifestError> {
        let mut v: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            if shift == 63 && b > 1 {
                return Err(ManifestError("varint overflows".into()));
            }
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                if b == 0 && shift > 0 {
                    return Err(ManifestError("varint is not minimal".into()));
                }
                return Ok(v);
            }
            shift += 7;
            if shift > 63 {
                return Err(ManifestError("varint overflows".into()));
            }
        }
    }

    fn meta(&mut self, head: u8) -> Result<Meta, ManifestError> {
        let mode = if head & HEAD_MODE != 0 {
            let m = self.varint()?;
            if m > 0o7777 {
                return Err(ManifestError("invalid mode".into()));
            }
            Some(m as u32)
        } else {
            None
        };
        let mtime = if head & HEAD_MTIME != 0 {
            let z = self.varint()?;
            let secs = ((z >> 1) as i64) ^ -((z & 1) as i64);
            let nanos = self.varint()?;
            if nanos >= 1_000_000_000 {
                return Err(ManifestError("invalid modification time".into()));
            }
            Some((secs, nanos as u32))
        } else {
            None
        };
        Ok(Meta { mode, mtime })
    }
}

/// Collects entries and enforces every rule of the format, for decoding as
/// well as for scanning (so a sender never produces a manifest a receiver
/// would refuse).
struct Builder {
    m: Manifest,
    /// Per slot (0 = root, i + 1 = entry i): slot of the last child so far
    /// (0 = none), nesting depth, and length of the relative path.
    last_child: Vec<u32>,
    depth: Vec<u16>,
    path_len: Vec<u16>,
}

impl Builder {
    fn new(root: Meta, capacity: usize) -> Self {
        let mut b = Self {
            m: Manifest {
                root,
                entries: Vec::with_capacity(capacity),
                names: String::new(),
                data_files: Vec::new(),
                data_len: 0,
                files: 0,
                dirs: 0,
                encoded_len: 0,
            },
            last_child: Vec::with_capacity(capacity + 1),
            depth: Vec::with_capacity(capacity + 1),
            path_len: Vec::with_capacity(capacity + 1),
        };
        b.last_child.push(0);
        b.depth.push(0);
        b.path_len.push(0);
        b
    }

    /// Appends an entry; returns its slot (to be used as `parent` of its
    /// children).
    fn push(
        &mut self,
        parent: u32,
        name: &str,
        kind: EntryKind,
        size: u64,
        meta: Meta,
    ) -> Result<u32, String> {
        let n = self.m.entries.len();
        if n as u64 >= MAX_MANIFEST_ENTRIES {
            return Err(format!("more than {} entries", MAX_MANIFEST_ENTRIES));
        }
        let p = parent as usize;
        if p > n || (p > 0 && self.m.entries[p - 1].kind != EntryKind::Dir) {
            return Err(format!(
                "parent of {:?} is not a directory listed before it",
                name
            ));
        }
        if !valid_name(name) {
            return Err(format!("{:?} is not a valid name", name));
        }
        let depth = self.depth[p] as usize + 1;
        if depth > MAX_TREE_DEPTH {
            return Err(format!(
                "{:?} is nested deeper than {} levels",
                name, MAX_TREE_DEPTH
            ));
        }
        let path_len = if p == 0 {
            name.len()
        } else {
            self.path_len[p] as usize + 1 + name.len()
        };
        if path_len > MAX_TREE_PATH {
            return Err(format!(
                "the path of {:?} is longer than {} bytes",
                name, MAX_TREE_PATH
            ));
        }
        let last = self.last_child[p];
        if last != 0 && name <= self.m.name(last as usize - 1) {
            return Err(format!(
                "{:?} is repeated or out of order in its directory",
                name
            ));
        }
        if meta.mode.is_some_and(|m| m > 0o7777)
            || meta.mtime.is_some_and(|(_, ns)| ns >= 1_000_000_000)
        {
            return Err(format!("invalid metadata for {:?}", name));
        }
        match kind {
            EntryKind::File => {
                self.m.data_len = self
                    .m
                    .data_len
                    .checked_add(size)
                    .ok_or_else(|| "total size overflows".to_string())?;
                self.m.files += 1;
            }
            EntryKind::Dir => {
                if size != 0 {
                    return Err(format!("directory {:?} has a size", name));
                }
                self.m.dirs += 1;
            }
        }
        let name_at =
            u32::try_from(self.m.names.len()).map_err(|_| "names too long".to_string())?;
        self.m.names.push_str(name);
        self.m.entries.push(Entry {
            parent,
            name_at,
            name_len: name.len() as u16,
            kind,
            size,
            start: 0,
            meta,
        });
        let slot = n as u32 + 1;
        self.last_child[p] = slot;
        self.last_child.push(0);
        self.depth.push(depth as u16);
        self.path_len.push(path_len as u16);
        Ok(slot)
    }

    /// Lays out the stream: file contents start after `encoded_len` bytes
    /// of manifest.
    fn finish(mut self, encoded_len: u64) -> Result<Manifest, String> {
        encoded_len
            .checked_add(self.m.data_len)
            .ok_or_else(|| "total size overflows".to_string())?;
        let mut at = encoded_len;
        for (i, e) in self.m.entries.iter_mut().enumerate() {
            if e.kind == EntryKind::File {
                e.start = at;
                at += e.size;
                if e.size > 0 {
                    self.m.data_files.push(i as u32);
                }
            }
        }
        self.m.encoded_len = encoded_len;
        Ok(self.m)
    }
}

/// A single path component that every system can at least represent.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FILE_NAME_LEN
        && name != "."
        && name != ".."
        && !name.bytes().any(|b| b == b'/' || b == 0)
}

// ---------------------------------------------------------------------------
// Local names
// ---------------------------------------------------------------------------

/// Maps an entry name to one the local file system can store. On Windows,
/// reserved characters become `_`, trailing dots and spaces (which Windows
/// would silently drop) are removed and device names get a `_` prefix; other
/// systems store every valid name as it is.
pub fn local_name(name: &str) -> Cow<'_, str> {
    #[cfg(windows)]
    {
        windows_name(name)
    }
    #[cfg(not(windows))]
    {
        Cow::Borrowed(name)
    }
}

/// The Windows mapping of [`local_name`] (available everywhere for tests).
pub fn windows_name(name: &str) -> Cow<'_, str> {
    let bad = |c: char| {
        matches!(
            c,
            '\0'..='\x1f' | '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
        )
    };
    if !name.chars().any(bad) && !name.ends_with(['.', ' ']) && !is_windows_reserved(name) {
        return Cow::Borrowed(name);
    }
    let mapped: String = name.chars().map(|c| if bad(c) { '_' } else { c }).collect();
    let trimmed = mapped.trim_end_matches(['.', ' ']);
    let mut out = if trimmed.is_empty() {
        "_".to_string()
    } else {
        trimmed.to_string()
    };
    if is_windows_reserved(&out) {
        out.insert(0, '_');
    }
    Cow::Owned(out)
}

/// Device names Windows reserves in every directory, with or without an
/// extension (`CON`, `nul.txt`, `COM1`, `LPT²`, ...).
pub fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    (upper.starts_with("COM") || upper.starts_with("LPT"))
        && matches!(
            &stem[3..],
            "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

/// A directory scanned for sending.
pub struct Scan {
    pub manifest: Manifest,
    pub bytes: Vec<u8>,
    /// Symbolic links and special files, which are not sent.
    pub skipped: Vec<PathBuf>,
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// Walks the tree below `root` (without following symbolic links) and
/// builds its manifest.
pub fn scan(root: &Path) -> io::Result<Scan> {
    let md = fs::metadata(root)?;
    if !md.is_dir() {
        return Err(invalid(format!("{} is not a directory", root.display())));
    }
    let mut b = Builder::new(meta_of(&md), 64);
    let mut skipped = Vec::new();
    scan_dir(&mut b, root, 0, &mut skipped)?;
    let bytes = b.m.encode();
    if bytes.len() as u64 > MAX_MANIFEST_LEN {
        return Err(invalid(format!(
            "{} holds too many entries: its listing takes {} bytes, at most {} are allowed",
            root.display(),
            bytes.len(),
            MAX_MANIFEST_LEN
        )));
    }
    let manifest = b.finish(bytes.len() as u64).map_err(invalid)?;
    Ok(Scan {
        manifest,
        bytes,
        skipped,
    })
}

fn scan_dir(b: &mut Builder, dir: &Path, slot: u32, skipped: &mut Vec<PathBuf>) -> io::Result<()> {
    let context = |e: io::Error| io::Error::new(e.kind(), format!("{}: {}", dir.display(), e));
    let mut children = Vec::new();
    for entry in fs::read_dir(dir).map_err(context)? {
        let entry = entry.map_err(context)?;
        let path = entry.path();
        let name = entry.file_name().into_string().map_err(|_| {
            invalid(format!(
                "{}: the name is not valid Unicode; rename it to send this directory",
                path.display()
            ))
        })?;
        children.push((name, path));
    }
    children.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, path) in children {
        // The entry's own metadata, not the copy in the directory listing
        // (`DirEntry::metadata`): on Windows that copy is what the parent
        // directory's index says, which NTFS brings up to date lazily, so
        // a directory's time — or even a file's size — could go out stale.
        // Neither follows symbolic links.
        let md = fs::symlink_metadata(&path)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {}", path.display(), e)))?;
        let file_type = md.file_type();
        if file_type.is_symlink() || !(file_type.is_dir() || file_type.is_file()) {
            skipped.push(path);
            continue;
        }
        let err = |e: String| invalid(format!("{}: {}", path.display(), e));
        if file_type.is_dir() {
            let child = b
                .push(slot, &name, EntryKind::Dir, 0, meta_of(&md))
                .map_err(err)?;
            scan_dir(b, &path, child, skipped)?;
        } else {
            b.push(slot, &name, EntryKind::File, md.len(), meta_of(&md))
                .map_err(err)?;
        }
    }
    Ok(())
}

fn meta_of(md: &fs::Metadata) -> Meta {
    Meta {
        mode: mode_of(md),
        mtime: md.modified().ok().map(unix_time),
    }
}

#[cfg(unix)]
fn mode_of(md: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(md.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn mode_of(_md: &fs::Metadata) -> Option<u32> {
    None
}

/// Seconds and nanoseconds since the Unix epoch (nanoseconds always count
/// forward, also before 1970).
pub fn unix_time(t: SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs().min(i64::MAX as u64) as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            let secs = d.as_secs().min(i64::MAX as u64 - 1) as i64;
            match d.subsec_nanos() {
                0 => (-secs, 0),
                n => (-secs - 1, 1_000_000_000 - n),
            }
        }
    }
}

fn system_time((secs, nanos): (i64, u32)) -> Option<SystemTime> {
    let t = if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))?
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))?
    };
    t.checked_add(Duration::from_nanos(nanos as u64))
}

/// Reads the transfer stream of a directory: the manifest, then the files.
pub struct TreeSource {
    root: PathBuf,
    manifest: Manifest,
    bytes: Vec<u8>,
    info: TreeInfo,
    skipped: Vec<PathBuf>,
    open: Mutex<VecDeque<(u32, File)>>,
}

impl TreeSource {
    /// Scans `root`; this reads the metadata of the whole tree.
    pub fn open(root: &Path) -> io::Result<Self> {
        let scan = scan(root)?;
        let info = scan.manifest.info(&scan.bytes);
        Ok(Self {
            root: root.to_path_buf(),
            manifest: scan.manifest,
            bytes: scan.bytes,
            info,
            skipped: scan.skipped,
            open: Mutex::new(VecDeque::new()),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn size(&self) -> u64 {
        self.manifest.stream_len()
    }

    pub fn info(&self) -> TreeInfo {
        self.info
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn skipped(&self) -> &[PathBuf] {
        &self.skipped
    }

    /// Reads exactly `buf.len()` bytes of the stream at `offset`.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.size() {
            return Err(invalid("read beyond end of stream".into()));
        }
        let mut off = offset;
        let mut out = buf;
        let m = self.bytes.len() as u64;
        if off < m {
            let n = (out.len() as u64).min(m - off) as usize;
            out[..n].copy_from_slice(&self.bytes[off as usize..off as usize + n]);
            off += n as u64;
            out = &mut std::mem::take(&mut out)[n..];
        }
        let mut open = self.open.lock();
        while !out.is_empty() {
            let i = self
                .manifest
                .file_at(off)
                .ok_or_else(|| invalid("offset outside the stream".into()))?;
            let e = &self.manifest.entries()[i as usize];
            let within = off - e.start;
            let n = (out.len() as u64).min(e.size - within) as usize;
            let path = || self.manifest.local_path(&self.root, i as usize);
            let file = cached(&mut open, i, || {
                let p = path();
                File::open(&p)
                    .map_err(|e| io::Error::new(e.kind(), format!("{}: {}", p.display(), e)))
            })?;
            read_exact_at(file, &mut out[..n], within).map_err(|e| {
                let p = path();
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    io::Error::new(
                        e.kind(),
                        format!(
                            "{} changed while being sent (it is shorter now)",
                            p.display()
                        ),
                    )
                } else {
                    io::Error::new(e.kind(), format!("{}: {}", p.display(), e))
                }
            })?;
            off += n as u64;
            out = &mut std::mem::take(&mut out)[n..];
        }
        Ok(())
    }

    /// BLAKE3 of the whole stream, as the receiver computes it.
    pub fn hash(&self) -> io::Result<[u8; 32]> {
        hash_tree(&self.root, &self.manifest, &self.bytes)
    }
}

/// The open handle of file `i`, most recently used first.
fn cached(
    lru: &mut VecDeque<(u32, File)>,
    i: u32,
    open: impl FnOnce() -> io::Result<File>,
) -> io::Result<&File> {
    match lru.iter().position(|(j, _)| *j == i) {
        Some(0) => {}
        Some(pos) => {
            let h = lru.remove(pos).expect("position is in range");
            lru.push_front(h);
        }
        None => {
            let f = open()?;
            lru.push_front((i, f));
            lru.truncate(MAX_OPEN_FILES);
        }
    }
    Ok(&lru[0].1)
}

/// BLAKE3 of a tree's transfer stream: the manifest bytes followed by the
/// contents of every file below `root`.
pub fn hash_tree(root: &Path, m: &Manifest, manifest_bytes: &[u8]) -> io::Result<[u8; 32]> {
    let mut h = blake3::Hasher::new();
    h.update(manifest_bytes);
    for &i in m.data_files() {
        let path = m.local_path(root, i as usize);
        let want = m.entries()[i as usize].size;
        let len = fs::metadata(&path)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {}", path.display(), e)))?
            .len();
        if len != want {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is {} bytes long, expected {}",
                    path.display(),
                    len,
                    want
                ),
            ));
        }
        h.update_mmap_rayon(&path)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {}", path.display(), e)))?;
    }
    Ok(*h.finalize().as_bytes())
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

const CREATED: u8 = 0x1;
/// File data written since the last sync.
const DIRTY: u8 = 0x2;
/// Directory gained entries since the last sync.
const DIR_DIRTY: u8 = 0x4;

/// Writes the files of a tree below a staging root, for the writer thread.
/// Entries are created when first needed (directories when something inside
/// them is created); [`TreeSink::finish`] creates the rest.
pub(crate) struct TreeSink {
    root: PathBuf,
    plan: Arc<Manifest>,
    /// The root holds entries of an earlier attempt of the same transfer,
    /// which are reused instead of being reported as collisions.
    resume: bool,
    flags: Vec<u8>,
    root_dirty: bool,
    open: VecDeque<(u32, File)>,
    dirty_files: Vec<u32>,
    dirty_dirs: Vec<u32>,
}

impl TreeSink {
    pub(crate) fn new(root: PathBuf, plan: Arc<Manifest>, resume: bool) -> Self {
        let n = plan.entries().len();
        Self {
            root,
            plan,
            resume,
            flags: vec![0; n],
            root_dirty: false,
            open: VecDeque::new(),
            dirty_files: Vec::new(),
            dirty_dirs: Vec::new(),
        }
    }

    /// Writes stream bytes (at or beyond the manifest) into the files that
    /// hold them.
    pub(crate) fn write_at(&mut self, mut off: u64, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let i = self.plan.file_at(off).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "write outside the files of the directory",
                )
            })?;
            let (start, size) = {
                let e = &self.plan.entries()[i as usize];
                (e.start, e.size)
            };
            let within = off - start;
            let n = (buf.len() as u64).min(size - within) as usize;
            self.handle(i)?;
            if let Err(e) = write_all_at(&self.open[0].1, &buf[..n], within) {
                return Err(self.context(i, e));
            }
            let f = &mut self.flags[i as usize];
            if *f & DIRTY == 0 {
                *f |= DIRTY;
                self.dirty_files.push(i);
            }
            off += n as u64;
            buf = &buf[n..];
        }
        Ok(())
    }

    fn context(&self, i: u32, e: io::Error) -> io::Error {
        let path = self.plan.local_path(&self.root, i as usize);
        io::Error::new(e.kind(), format!("{}: {}", path.display(), e))
    }

    /// Makes file `i` the front of the open-file cache.
    fn handle(&mut self, i: u32) -> io::Result<()> {
        match self.open.iter().position(|(j, _)| *j == i) {
            Some(0) => {}
            Some(pos) => {
                let h = self.open.remove(pos).expect("position is in range");
                self.open.push_front(h);
            }
            None => {
                let f = self.open_file(i)?;
                self.open.push_front((i, f));
                self.open.truncate(MAX_OPEN_FILES);
            }
        }
        Ok(())
    }

    /// Opens file `i` for writing, creating it (at its full size) first if
    /// this is its first use.
    fn open_file(&mut self, i: u32) -> io::Result<File> {
        let idx = i as usize;
        let path = self.plan.local_path(&self.root, idx);
        let (parent, size) = {
            let e = &self.plan.entries()[idx];
            (e.parent, e.size)
        };
        if self.flags[idx] & CREATED != 0 {
            return OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|e| self.context(i, e));
        }
        self.ensure_dir(parent)?;
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => {
                if size > 0 {
                    f.set_len(size).map_err(|e| self.context(i, e))?;
                }
                self.flags[idx] |= CREATED;
                self.note_new_entry(parent);
                Ok(f)
            }
            Err(e)
                if self.resume
                    && e.kind() == io::ErrorKind::AlreadyExists
                    && fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) =>
            {
                let f = OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .map_err(|e| self.context(i, e))?;
                if f.metadata()?.len() != size {
                    f.set_len(size).map_err(|e| self.context(i, e))?;
                }
                self.flags[idx] |= CREATED;
                Ok(f)
            }
            Err(e) => Err(self.creation_error(idx, &path, e)),
        }
    }

    /// Creates the directory with the given slot (and its parents) unless
    /// it exists already.
    fn ensure_dir(&mut self, slot: u32) -> io::Result<()> {
        if slot == 0 {
            return Ok(());
        }
        let idx = slot as usize - 1;
        if self.flags[idx] & CREATED != 0 {
            return Ok(());
        }
        let parent = self.plan.entries()[idx].parent;
        self.ensure_dir(parent)?;
        let path = self.plan.local_path(&self.root, idx);
        match fs::create_dir(&path) {
            Ok(()) => {
                self.flags[idx] |= CREATED;
                self.note_new_entry(parent);
                Ok(())
            }
            Err(e)
                if self.resume
                    && e.kind() == io::ErrorKind::AlreadyExists
                    && fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) =>
            {
                self.flags[idx] |= CREATED;
                Ok(())
            }
            Err(e) => Err(self.creation_error(idx, &path, e)),
        }
    }

    fn creation_error(&self, idx: usize, path: &Path, e: io::Error) -> io::Error {
        if fs::symlink_metadata(path).is_ok() {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "'{}' collides with another entry that has the same name on this system",
                    self.plan.path(idx)
                ),
            )
        } else {
            io::Error::new(e.kind(), format!("{}: {}", path.display(), e))
        }
    }

    /// Remembers that the directory with this slot gained an entry.
    fn note_new_entry(&mut self, parent: u32) {
        if parent == 0 {
            self.root_dirty = true;
            return;
        }
        let p = parent as usize - 1;
        if self.flags[p] & DIR_DIRTY == 0 {
            self.flags[p] |= DIR_DIRTY;
            self.dirty_dirs.push(p as u32);
        }
    }

    /// Makes everything written so far durable: the files written since
    /// the last sync and (on Unix) the directories that gained entries.
    pub(crate) fn sync(&mut self, all: bool) -> io::Result<()> {
        let files = std::mem::take(&mut self.dirty_files);
        for &i in &files {
            self.flags[i as usize] &= !DIRTY;
        }
        let dirs = std::mem::take(&mut self.dirty_dirs);
        for &d in &dirs {
            self.flags[d as usize] &= !DIR_DIRTY;
        }
        let root_dirty = std::mem::replace(&mut self.root_dirty, false);
        let (open, plan, root) = (&self.open, &self.plan, &self.root);
        parallel_try(&files, |&i| {
            let path = || plan.local_path(root, i as usize);
            let r = match open.iter().find(|(j, _)| *j == i) {
                Some((_, f)) => sync_file(f, all),
                None => OpenOptions::new()
                    .write(true)
                    .open(path())
                    .and_then(|f| sync_file(&f, all)),
            };
            r.map_err(|e| io::Error::new(e.kind(), format!("{}: {}", path().display(), e)))
        })?;
        #[cfg(unix)]
        {
            let mut paths: Vec<PathBuf> = dirs
                .iter()
                .map(|&d| plan.local_path(root, d as usize))
                .collect();
            if root_dirty {
                paths.push(root.clone());
            }
            parallel_try(&paths, |p| File::open(p).and_then(|f| f.sync_all()))?;
        }
        #[cfg(not(unix))]
        let _ = (dirs, root_dirty);
        Ok(())
    }

    /// Creates the entries that no write created (directories, empty
    /// files) once all data is in.
    pub(crate) fn finish(&mut self) -> io::Result<()> {
        for idx in 0..self.flags.len() {
            if self.flags[idx] & CREATED != 0 {
                continue;
            }
            match self.plan.entries()[idx].kind {
                EntryKind::Dir => self.ensure_dir(idx as u32 + 1)?,
                EntryKind::File => {
                    self.open_file(idx as u32)?;
                }
            }
        }
        Ok(())
    }

    /// Closes every open file.
    pub(crate) fn close_files(&mut self) {
        self.open.clear();
    }
}

fn sync_file(f: &File, all: bool) -> io::Result<()> {
    if all {
        f.sync_all()
    } else {
        f.sync_data()
    }
}

/// Runs `f` on every item, spread over a few threads when there are many
/// (file system syncs of many small files are latency bound). Returns the
/// first error.
fn parallel_try<T: Sync>(items: &[T], f: impl Fn(&T) -> io::Result<()> + Sync) -> io::Result<()> {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(8);
    if items.len() < 16 || threads < 2 {
        return items.iter().try_for_each(&f);
    }
    let per_thread = items.len().div_ceil(threads);
    std::thread::scope(|s| {
        let workers: Vec<_> = items
            .chunks(per_thread)
            .map(|chunk| s.spawn(|| chunk.iter().try_for_each(&f)))
            .collect();
        let mut result = Ok(());
        for w in workers {
            let r = w
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("sync worker panicked")));
            if result.is_ok() {
                result = r;
            }
        }
        result
    })
}

/// Creates a directory only its owner can enter (Unix), for staging.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::DirBuilder::new().create(path)
    }
}

/// `dir/name`, or `dir/name (n)` with the smallest free `n`, for a directory
/// that must not replace anything.
pub fn unique_dir_path(dir: &Path, name: &str) -> PathBuf {
    let free = |p: &Path| fs::symlink_metadata(p).is_err();
    let candidate = dir.join(name);
    if free(&candidate) {
        return candidate;
    }
    for n in 1..10_000 {
        let p = dir.join(format!("{} ({})", name, n));
        if free(&p) {
            return p;
        }
    }
    dir.join(format!("{}-{:08x}", name, rand::random::<u32>()))
}

/// Removes a partial file or staging directory.
pub fn remove_partial(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// The process's file creation mask, observed by creating a probe file in
/// `dir` (reading the mask directly would briefly change it for every
/// thread).
#[cfg(unix)]
pub fn local_umask(dir: &Path) -> u32 {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let probe = dir.join(format!(".sharp-umask-{:016x}", rand::random::<u64>()));
    let mode = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o777)
        .open(&probe)
        .and_then(|f| f.metadata())
        .map(|m| m.permissions().mode() & 0o777);
    let _ = fs::remove_file(&probe);
    mode.map(|m| 0o777 & !m).unwrap_or(0o022)
}

#[cfg(not(unix))]
pub fn local_umask(_dir: &Path) -> u32 {
    0
}

/// Applies modification times and permission bits to every entry below
/// `root` (not to `root` itself), deepest entries first so that each
/// directory is done after everything in it. Permission bits are masked
/// with `umask` and never include set-id bits. Failures are logged and
/// counted, not fatal: the data itself is complete and verified.
pub fn apply_metadata(root: &Path, m: &Manifest, umask: u32) -> usize {
    let mut failures = 0;
    for i in (0..m.entries().len()).rev() {
        let e = &m.entries()[i];
        let path = m.local_path(root, i);
        if let Err(err) = set_meta(&path, e.kind == EntryKind::Dir, &e.meta, umask) {
            failures += 1;
            if failures <= 5 {
                tracing::warn!("cannot set metadata of {}: {}", path.display(), err);
            }
        }
    }
    failures
}

/// Applies the root's metadata to the finished tree at `root`. Without a
/// mode from the sender the (private) staging mode is replaced by the
/// default for new directories.
pub fn apply_root_metadata(root: &Path, m: &Manifest, umask: u32) -> io::Result<()> {
    let meta = Meta {
        mode: m.root_meta().mode.or(Some(0o777)),
        ..m.root_meta()
    };
    set_meta(root, true, &meta, umask)
}

fn set_meta(path: &Path, dir: bool, meta: &Meta, umask: u32) -> io::Result<()> {
    if let Some(t) = meta.mtime.and_then(system_time) {
        open_for_times(path, dir)?.set_modified(t)?;
    }
    #[cfg(unix)]
    if let Some(mode) = meta.mode {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777 & !umask))?;
    }
    #[cfg(not(unix))]
    let _ = umask;
    Ok(())
}

#[cfg(unix)]
fn open_for_times(path: &Path, _dir: bool) -> io::Result<File> {
    // The owner may set times through any descriptor.
    File::open(path)
}

#[cfg(windows)]
fn open_for_times(path: &Path, dir: bool) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let mut o = OpenOptions::new();
    o.access_mode(FILE_WRITE_ATTRIBUTES);
    if dir {
        o.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }
    o.open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_for_times(path: &Path, _dir: bool) -> io::Result<File> {
    OpenOptions::new().write(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(mode: u32, secs: i64) -> Meta {
        Meta {
            mode: Some(mode),
            mtime: Some((secs, 123)),
        }
    }

    fn sample() -> (Manifest, Vec<u8>) {
        let mut b = Builder::new(meta(0o755, 1_700_000_000), 8);
        let docs = b
            .push(0, "docs", EntryKind::Dir, 0, meta(0o750, 5))
            .unwrap();
        b.push(docs, "a.txt", EntryKind::File, 10, meta(0o644, -5))
            .unwrap();
        b.push(docs, "b.txt", EntryKind::File, 0, Meta::default())
            .unwrap();
        let deep = b
            .push(docs, "deep", EntryKind::Dir, 0, Meta::default())
            .unwrap();
        b.push(deep, "z", EntryKind::File, 3, meta(0o600, 0))
            .unwrap();
        b.push(0, "empty", EntryKind::Dir, 0, meta(0o700, 1))
            .unwrap();
        b.push(0, "отчёт.bin", EntryKind::File, 7, meta(0o755, 2))
            .unwrap();
        let bytes = b.m.encode();
        let m = b.finish(bytes.len() as u64).unwrap();
        (m, bytes)
    }

    #[test]
    fn manifest_roundtrip_and_layout() {
        let (m, bytes) = sample();
        let d = Manifest::decode(&bytes).unwrap();
        assert_eq!(d.encode(), bytes);
        assert_eq!(d.files(), 4);
        assert_eq!(d.dirs(), 3);
        assert_eq!(d.data_len(), 20);
        assert_eq!(d.stream_len(), bytes.len() as u64 + 20);
        assert_eq!(d.root_meta(), m.root_meta());
        let paths: Vec<String> = (0..d.entries().len()).map(|i| d.path(i)).collect();
        assert_eq!(
            paths,
            [
                "docs",
                "docs/a.txt",
                "docs/b.txt",
                "docs/deep",
                "docs/deep/z",
                "empty",
                "отчёт.bin"
            ]
        );
        assert_eq!(d.entries()[1].meta, meta(0o644, -5));
        // Contents follow the manifest in entry order; empty files take no
        // room.
        let m0 = bytes.len() as u64;
        assert_eq!(d.data_files(), &[1, 4, 6]);
        assert_eq!(d.entries()[1].start, m0);
        assert_eq!(d.entries()[4].start, m0 + 10);
        assert_eq!(d.entries()[6].start, m0 + 13);
        assert_eq!(d.file_at(m0 - 1), None);
        assert_eq!(d.file_at(m0), Some(1));
        assert_eq!(d.file_at(m0 + 9), Some(1));
        assert_eq!(d.file_at(m0 + 10), Some(4));
        assert_eq!(d.file_at(m0 + 19), Some(6));
        assert_eq!(d.file_at(m0 + 20), None);
        let info = d.info(&bytes);
        assert_eq!(info.manifest_len, m0);
        assert_eq!(info.files, 4);
        assert_eq!(info.dirs, 3);
    }

    /// Encodes entries without any validation: (head, parent, name, size).
    fn raw(entries: &[(u8, u64, &[u8], Option<u64>)]) -> Vec<u8> {
        let mut out = vec![MANIFEST_VERSION, 0, HEAD_DIR];
        put_varint(&mut out, entries.len() as u64);
        for &(h, parent, name, size) in entries {
            out.push(h);
            put_varint(&mut out, parent);
            put_varint(&mut out, name.len() as u64);
            out.extend_from_slice(name);
            if let Some(s) = size {
                put_varint(&mut out, s);
            }
        }
        out
    }

    #[test]
    fn hostile_manifests_are_rejected() {
        let ok = raw(&[(HEAD_DIR, 0, b"a", None), (0, 1, b"f", Some(1))]);
        Manifest::decode(&ok).unwrap();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("dot-dot", raw(&[(0, 0, b"..", Some(1))])),
            ("dot", raw(&[(HEAD_DIR, 0, b".", None)])),
            ("empty name", raw(&[(0, 0, b"", Some(1))])),
            ("separator", raw(&[(0, 0, b"a/b", Some(1))])),
            ("absolute", raw(&[(0, 0, b"/etc", Some(1))])),
            ("nul", raw(&[(0, 0, b"a\0b", Some(1))])),
            ("not utf-8", raw(&[(0, 0, b"\xff", Some(1))])),
            (
                "long name",
                raw(&[(0, 0, "x".repeat(256).as_bytes(), Some(1))]),
            ),
            (
                "parent is a file",
                raw(&[(0, 0, b"f", Some(1)), (0, 1, b"g", Some(1))]),
            ),
            (
                "parent later",
                raw(&[(0, 2, b"f", Some(1)), (HEAD_DIR, 0, b"d", None)]),
            ),
            ("parent self", raw(&[(HEAD_DIR, 1, b"d", None)])),
            (
                "duplicate",
                raw(&[(0, 0, b"f", Some(1)), (0, 0, b"f", Some(1))]),
            ),
            (
                "unsorted",
                raw(&[(0, 0, b"g", Some(1)), (0, 0, b"f", Some(1))]),
            ),
            (
                "dir and file with one name",
                raw(&[(HEAD_DIR, 0, b"f", None), (0, 0, b"f", Some(1))]),
            ),
            ("unknown flags", raw(&[(0x08, 0, b"f", Some(1))])),
            (
                "size overflow",
                raw(&[(0, 0, b"f", Some(u64::MAX)), (0, 0, b"g", Some(2))]),
            ),
        ];
        for (what, bytes) in cases {
            assert!(Manifest::decode(&bytes).is_err(), "{} accepted", what);
        }
        // Truncations and trailing bytes.
        for n in 0..ok.len() {
            assert!(Manifest::decode(&ok[..n]).is_err(), "prefix {} accepted", n);
        }
        let mut long = ok.clone();
        long.push(0);
        assert!(Manifest::decode(&long).is_err());
        // Wrong version, reserved byte, root that is not a directory,
        // non-minimal varint, a count far beyond the data.
        for (at, v) in [(0usize, 2u8), (1, 1), (2, 0)] {
            let mut b = ok.clone();
            b[at] = v;
            assert!(Manifest::decode(&b).is_err());
        }
        let mut b = vec![MANIFEST_VERSION, 0, HEAD_DIR, 0x80, 0x00];
        assert!(Manifest::decode(&b).is_err());
        b = vec![MANIFEST_VERSION, 0, HEAD_DIR];
        put_varint(&mut b, MAX_MANIFEST_ENTRIES + 1);
        assert!(Manifest::decode(&b).is_err());
        b = vec![MANIFEST_VERSION, 0, HEAD_DIR];
        put_varint(&mut b, 1_000_000);
        assert!(Manifest::decode(&b).is_err());
        // Bad metadata values.
        let mut b = vec![MANIFEST_VERSION, 0, HEAD_DIR | HEAD_MODE];
        put_varint(&mut b, 0o10000);
        b.push(0);
        assert!(Manifest::decode(&b).is_err());
        let mut b = vec![MANIFEST_VERSION, 0, HEAD_DIR | HEAD_MTIME, 0];
        put_varint(&mut b, 1_000_000_000);
        b.push(0);
        assert!(Manifest::decode(&b).is_err());
    }

    #[test]
    fn depth_and_path_length_are_bounded() {
        let mut b = Builder::new(Meta::default(), 0);
        let mut slot = 0;
        for _ in 0..MAX_TREE_DEPTH {
            slot = b
                .push(slot, "d", EntryKind::Dir, 0, Meta::default())
                .unwrap();
        }
        assert!(b
            .push(slot, "d", EntryKind::Dir, 0, Meta::default())
            .is_err());
        let mut b = Builder::new(Meta::default(), 0);
        let long = "n".repeat(MAX_FILE_NAME_LEN);
        let mut slot = 0;
        let mut len = 0;
        while len + 1 + long.len() <= MAX_TREE_PATH {
            slot = b
                .push(slot, &long, EntryKind::Dir, 0, Meta::default())
                .unwrap();
            len += long.len() + 1;
        }
        assert!(b
            .push(slot, &long, EntryKind::File, 1, Meta::default())
            .is_err());
    }

    #[test]
    fn windows_names_are_mapped() {
        assert_eq!(windows_name("plain.txt"), "plain.txt");
        assert!(matches!(windows_name("plain.txt"), Cow::Borrowed(_)));
        assert_eq!(windows_name("a:b*c?.txt"), "a_b_c_.txt");
        assert_eq!(windows_name("C:"), "C_");
        assert_eq!(windows_name("x\\y"), "x_y");
        assert_eq!(windows_name("name. . "), "name");
        assert_eq!(windows_name("..."), "_");
        assert_eq!(windows_name("CON"), "_CON");
        assert_eq!(windows_name("con.txt"), "_con.txt");
        assert_eq!(windows_name("Lpt1.log"), "_Lpt1.log");
        assert_eq!(windows_name("COM²"), "_COM²");
        assert_eq!(windows_name("COM10"), "COM10");
        assert_eq!(windows_name("CONSOLE"), "CONSOLE");
        assert_eq!(windows_name("nul."), "_nul");
        assert_eq!(windows_name("отчёт|2026"), "отчёт_2026");
        // Idempotent, so mapping twice changes nothing.
        for n in ["a:b", "CON", "x. ", "..."] {
            let once = windows_name(n).into_owned();
            assert_eq!(windows_name(&once), once);
        }
    }

    fn write(path: &Path, data: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn scanned_tree_streams_and_hashes_consistently() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        write(&root.join("b/big.bin"), &pattern(300_000, 1));
        write(&root.join("a.txt"), b"hello");
        write(&root.join("b/c/empty"), b"");
        write(&root.join("b/c/d/x"), &pattern(5000, 2));
        write(&root.join("документ.txt"), &pattern(77, 3));
        fs::create_dir_all(root.join("zz-empty-dir")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", root.join("link")).unwrap();

        let src = TreeSource::open(&root).unwrap();
        let m = src.manifest();
        #[cfg(unix)]
        assert_eq!(src.skipped(), &[root.join("link")]);
        assert_eq!(m.files(), 5);
        assert_eq!(m.dirs(), 4);
        let order: Vec<String> = (0..m.entries().len()).map(|i| m.path(i)).collect();
        assert_eq!(
            order,
            [
                "a.txt",
                "b",
                "b/big.bin",
                "b/c",
                "b/c/d",
                "b/c/d/x",
                "b/c/empty",
                "zz-empty-dir",
                "документ.txt"
            ]
        );
        // The stream is the manifest followed by the files in entry order.
        let mut expected = src.bytes.clone();
        for p in ["a.txt", "b/big.bin", "b/c/d/x", "документ.txt"] {
            expected.extend(fs::read(root.join(p)).unwrap());
        }
        assert_eq!(src.size(), expected.len() as u64);
        let mut all = vec![0u8; expected.len()];
        src.read_at(0, &mut all).unwrap();
        assert!(all == expected);
        // Reads that straddle files and the manifest.
        for (off, len) in [(0usize, 7usize), (src.bytes.len() - 3, 20), (1000, 299_999)] {
            let mut buf = vec![0u8; len];
            src.read_at(off as u64, &mut buf).unwrap();
            assert_eq!(&buf[..], &expected[off..off + len]);
        }
        assert!(src
            .read_at(expected.len() as u64 - 1, &mut [0u8; 2])
            .is_err());
        assert_eq!(src.hash().unwrap(), *blake3::hash(&expected).as_bytes());
        assert_eq!(
            Manifest::decode(&src.bytes).unwrap().encode(),
            src.bytes,
            "the receiver decodes exactly what was scanned"
        );
    }

    #[test]
    fn sink_builds_the_tree_and_detects_collisions() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("src");
        write(&root.join("d/one"), &pattern(4000, 7));
        write(&root.join("d/two"), &pattern(10, 8));
        write(&root.join("e/empty"), b"");
        fs::create_dir_all(root.join("f/g")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("d/two"), fs::Permissions::from_mode(0o751)).unwrap();
        }
        let src = TreeSource::open(&root).unwrap();
        let mut stream = vec![0u8; src.size() as usize];
        src.read_at(0, &mut stream).unwrap();
        let plan = Arc::new(Manifest::decode(&src.bytes).unwrap());
        let m0 = src.bytes.len();

        let staging = tmp.path().join("out.sharp-part");
        create_private_dir(&staging).unwrap();
        let mut sink = TreeSink::new(staging.clone(), plan.clone(), false);
        // Out of order, across file boundaries.
        sink.write_at(m0 as u64 + 3000, &stream[m0 + 3000..])
            .unwrap();
        sink.write_at(m0 as u64, &stream[m0..m0 + 3000]).unwrap();
        assert!(sink.write_at(0, &stream[..10]).is_err(), "manifest region");
        sink.sync(false).unwrap();
        sink.finish().unwrap();
        sink.sync(true).unwrap();
        sink.close_files();
        assert_eq!(
            hash_tree(&staging, &plan, &src.bytes).unwrap(),
            src.hash().unwrap()
        );
        let umask = local_umask(&staging);
        assert_eq!(apply_metadata(&staging, &plan, umask), 0);
        apply_root_metadata(&staging, &plan, umask).unwrap();
        assert!(staging.join("e/empty").is_file());
        assert!(staging.join("f/g").is_dir());
        for p in ["d/one", "d/two", "e/empty"] {
            let a = fs::metadata(root.join(p)).unwrap();
            let b = fs::metadata(staging.join(p)).unwrap();
            assert_eq!(a.len(), b.len());
            assert_eq!(a.modified().unwrap(), b.modified().unwrap(), "{}", p);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    b.permissions().mode() & 0o777,
                    a.permissions().mode() & 0o777 & !umask,
                    "{}",
                    p
                );
            }
        }
        assert_eq!(
            fs::metadata(root.join("f")).unwrap().modified().unwrap(),
            fs::metadata(staging.join("f")).unwrap().modified().unwrap()
        );

        // Something already occupying a name is a collision, not a target.
        let staging2 = tmp.path().join("again.sharp-part");
        create_private_dir(&staging2).unwrap();
        write(&staging2.join("d/one"), b"not ours");
        let mut sink = TreeSink::new(staging2.clone(), plan.clone(), false);
        let err = sink.write_at(m0 as u64, &stream[m0..]).unwrap_err();
        assert!(err.to_string().contains("collides"), "{}", err);
        assert_eq!(fs::read(staging2.join("d/one")).unwrap(), b"not ours");
        // ...unless it is the same transfer's own earlier work.
        let mut sink = TreeSink::new(staging2.clone(), plan.clone(), true);
        sink.write_at(m0 as u64, &stream[m0..]).unwrap();
        sink.finish().unwrap();
        sink.sync(true).unwrap();
        sink.close_files();
        assert_eq!(
            hash_tree(&staging2, &plan, &src.bytes).unwrap(),
            src.hash().unwrap()
        );
        remove_partial(&staging2).unwrap();
        assert!(!staging2.exists());
    }

    #[test]
    fn times_convert_both_ways() {
        for t in [
            UNIX_EPOCH,
            UNIX_EPOCH + Duration::new(1_700_000_000, 999_999_999),
            UNIX_EPOCH - Duration::new(86_400, 250_000_000),
            UNIX_EPOCH - Duration::from_secs(3),
        ] {
            let (s, n) = unix_time(t);
            assert!(n < 1_000_000_000);
            assert_eq!(system_time((s, n)), Some(t));
        }
        // Just before the epoch is the previous second plus a fraction.
        // 100 ns, not 1: Windows keeps time in 100 ns ticks, and one
        // nanosecond before the epoch is the epoch there.
        assert_eq!(
            unix_time(UNIX_EPOCH - Duration::new(0, 100)),
            (-1, 999_999_900)
        );
    }

    #[test]
    fn unique_dir_names_never_reuse_existing_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let first = unique_dir_path(tmp.path(), "my.photos");
        assert_eq!(first, tmp.path().join("my.photos"));
        fs::create_dir(&first).unwrap();
        assert_eq!(
            unique_dir_path(tmp.path(), "my.photos"),
            tmp.path().join("my.photos (1)")
        );
        // A dangling symbolic link occupies its name too.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/nonexistent", tmp.path().join("x")).unwrap();
            assert_eq!(unique_dir_path(tmp.path(), "x"), tmp.path().join("x (1)"));
        }
    }
}
