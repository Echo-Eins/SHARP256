//! File access for the transfer engines: positional reads for the sender
//! (of a file, or of a directory's stream, see [`tree`]), a dedicated
//! coalescing writer thread for the receiver, whole-file hashing, disk-space
//! queries and file-name hygiene.

pub mod tree;

use crate::protocol::wire::TreeInfo;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver as MpscReceiver, SyncSender, TryRecvError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::oneshot;

/// Suffix of partially received files.
pub const PART_SUFFIX: &str = ".sharp-part";

// ---------------------------------------------------------------------------
// Positional I/O helpers (cross-platform)
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_read(buf, offset)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected end of file",
            ));
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(unix)]
fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, offset)
}

#[cfg(windows)]
fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_write(buf, offset)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"));
        }
        buf = &buf[n..];
        offset += n as u64;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Read-only random access to the file being sent.
pub struct FileReader {
    file: File,
    size: u64,
    path: PathBuf,
    mtime_unix: i64,
}

impl FileReader {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let meta = file.metadata()?;
        if meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path is a directory",
            ));
        }
        let mtime_unix = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Ok(Self {
            file,
            size: meta.len(),
            path: path.to_path_buf(),
            mtime_unix,
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn mtime_unix(&self) -> i64 {
        self.mtime_unix
    }

    /// Reads exactly `buf.len()` bytes at `offset`.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read beyond end of file",
            ));
        }
        read_exact_at(&self.file, buf, offset)
    }
}

/// What a sender transfers: one file, or the stream of a directory tree.
pub enum Source {
    File(FileReader),
    Tree(Box<tree::TreeSource>),
}

impl Source {
    /// Opens a file, or scans a directory (which reads the metadata of the
    /// whole tree, so call it off the async runtime).
    pub fn open(path: &Path) -> io::Result<Self> {
        if std::fs::metadata(path)?.is_dir() {
            Ok(Source::Tree(Box::new(tree::TreeSource::open(path)?)))
        } else {
            Ok(Source::File(FileReader::open(path)?))
        }
    }

    /// Length of the transfer stream.
    pub fn size(&self) -> u64 {
        match self {
            Source::File(f) => f.size(),
            Source::Tree(t) => t.size(),
        }
    }

    pub fn path(&self) -> &Path {
        match self {
            Source::File(f) => f.path(),
            Source::Tree(t) => t.root(),
        }
    }

    /// Reads exactly `buf.len()` bytes of the stream at `offset`.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        match self {
            Source::File(f) => f.read_at(offset, buf),
            Source::Tree(t) => t.read_at(offset, buf),
        }
    }

    /// Modification time announced in HELLO (a tree is identified by its
    /// manifest instead).
    pub fn mtime_unix(&self) -> i64 {
        match self {
            Source::File(f) => f.mtime_unix(),
            Source::Tree(_) => 0,
        }
    }

    pub fn tree(&self) -> Option<&tree::TreeSource> {
        match self {
            Source::File(_) => None,
            Source::Tree(t) => Some(t),
        }
    }

    pub fn tree_info(&self) -> Option<TreeInfo> {
        self.tree().map(|t| t.info())
    }

    /// BLAKE3 of the whole stream (blocking).
    pub fn hash(&self) -> io::Result<[u8; 32]> {
        match self {
            Source::File(f) => hash_file(f.path()),
            Source::Tree(t) => t.hash(),
        }
    }
}

// ---------------------------------------------------------------------------
// Writer thread
// ---------------------------------------------------------------------------

enum WriteCmd {
    /// Write `data[start..start + len]` at `offset`.
    Write {
        offset: u64,
        data: Vec<u8>,
        start: usize,
        len: usize,
    },
    Flush(oneshot::Sender<io::Result<()>>),
    /// Write everything, sync and stop; `complete` also finishes a tree
    /// (creates the entries no write created).
    Close {
        reply: oneshot::Sender<io::Result<()>>,
        complete: bool,
    },
}

/// Statistics shared between the writer thread and its owner.
#[derive(Default)]
struct WriterShared {
    queued_bytes: AtomicU64,
    written_bytes: AtomicU64,
    write_calls: AtomicU64,
    /// First error the writer ran into. It keeps draining its queue so the
    /// owner never wedges, but nothing it is given afterwards is written.
    error: parking_lot::Mutex<Option<(io::ErrorKind, String)>>,
}

/// Where the writer thread puts the bytes.
enum Target {
    File(File),
    Tree(Box<tree::TreeSink>),
}

impl Target {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        match self {
            Target::File(f) => write_all_at(f, buf, offset),
            Target::Tree(t) => t.write_at(offset, buf),
        }
    }

    fn sync(&mut self, all: bool) -> io::Result<()> {
        match self {
            Target::File(f) if all => f.sync_all(),
            Target::File(f) => f.sync_data(),
            Target::Tree(t) => t.sync(all),
        }
    }

    fn finish(&mut self) -> io::Result<()> {
        match self {
            Target::File(_) => Ok(()),
            Target::Tree(t) => t.finish(),
        }
    }

    fn close_files(&mut self) {
        if let Target::Tree(t) = self {
            t.close_files();
        }
    }
}

/// Handle to a background thread that applies positional writes, coalescing
/// contiguous chunks into large writes and running `fsync` on demand. It
/// writes one file, or the files of a directory tree (whose stream offsets
/// it maps to files).
pub struct FileWriter {
    tx: Option<SyncSender<WriteCmd>>,
    shared: Arc<WriterShared>,
    capacity_bytes: u64,
    thread: Option<JoinHandle<()>>,
}

/// Returned by `enqueue` when the writer is saturated; the caller should
/// treat the packet as not received (flow control slows the sender down).
#[derive(Debug)]
pub struct WriterFull;

impl FileWriter {
    /// Opens (or creates) `path`, sizes it to `size` bytes and starts the
    /// writer thread. `capacity_bytes` bounds the amount of queued,
    /// not-yet-written data.
    pub fn open(path: &Path, size: u64, capacity_bytes: u64) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        if file.metadata()?.len() != size {
            file.set_len(size)?;
        }
        Self::start(Target::File(file), capacity_bytes, || {})
    }

    /// Starts a writer for the files of a directory tree below the staging
    /// directory `root`; stream offsets below the manifest's end are not
    /// its business. `resume` lets it reuse entries an earlier attempt of
    /// the same transfer created. Before anything else the thread stores
    /// `keep_manifest` (path, bytes), if given, so that any later
    /// successful flush implies the manifest is durable too.
    pub fn open_tree(
        root: PathBuf,
        plan: Arc<tree::Manifest>,
        resume: bool,
        keep_manifest: Option<(PathBuf, Arc<Vec<u8>>)>,
        capacity_bytes: u64,
    ) -> io::Result<Self> {
        let sink = tree::TreeSink::new(root, plan, resume);
        Self::start(Target::Tree(Box::new(sink)), capacity_bytes, move || {
            if let Some((path, bytes)) = keep_manifest {
                if let Err(e) = write_file_atomic(&path, &bytes) {
                    tracing::warn!(
                        "cannot keep the directory manifest for resume ({}): {}",
                        path.display(),
                        e
                    );
                }
            }
        })
    }

    fn start(
        target: Target,
        capacity_bytes: u64,
        prelude: impl FnOnce() + Send + 'static,
    ) -> io::Result<Self> {
        let shared = Arc::new(WriterShared::default());
        // The channel is bounded by message count as a safety net; the real
        // bound is `capacity_bytes`, enforced in `enqueue_slice`.
        let (tx, rx) = sync_channel::<WriteCmd>(65_536);
        let thread_shared = shared.clone();
        let thread = std::thread::Builder::new()
            .name("sharp-writer".into())
            .spawn(move || {
                prelude();
                writer_loop(target, rx, thread_shared)
            })?;
        Ok(Self {
            tx: Some(tx),
            shared,
            capacity_bytes: capacity_bytes.max(1 << 20),
            thread: Some(thread),
        })
    }

    /// The first error the writer ran into, if any; nothing queued after it
    /// is written. `AlreadyExists` means two entries of a directory map to
    /// the same local name, which no retry can fix.
    pub fn error(&self) -> Option<(io::ErrorKind, String)> {
        self.shared.error.lock().clone()
    }

    pub fn queued_bytes(&self) -> u64 {
        self.shared.queued_bytes.load(Ordering::Acquire)
    }

    pub fn written_bytes(&self) -> u64 {
        self.shared.written_bytes.load(Ordering::Relaxed)
    }

    pub fn write_calls(&self) -> u64 {
        self.shared.write_calls.load(Ordering::Relaxed)
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    /// Bytes the writer can still absorb without exceeding its capacity.
    pub fn available(&self) -> u64 {
        self.capacity_bytes.saturating_sub(self.queued_bytes())
    }

    /// Queues a write of the whole buffer. Never blocks the caller.
    pub fn enqueue(&self, offset: u64, data: Vec<u8>) -> Result<(), WriterFull> {
        let len = data.len();
        self.enqueue_slice(offset, data, 0, len)
    }

    /// Queues a write of `data[start..start + len]` at `offset` without
    /// copying it first (typically `data` is a whole received datagram and
    /// the range is its payload). Never blocks the caller.
    pub fn enqueue_slice(
        &self,
        offset: u64,
        data: Vec<u8>,
        start: usize,
        len: usize,
    ) -> Result<(), WriterFull> {
        let end = start
            .checked_add(len)
            .filter(|&e| e <= data.len())
            .expect("enqueue_slice: range outside the buffer");
        let _ = end;
        let l = len as u64;
        if self.queued_bytes() + l > self.capacity_bytes {
            return Err(WriterFull);
        }
        let tx = self.tx.as_ref().ok_or(WriterFull)?;
        self.shared.queued_bytes.fetch_add(l, Ordering::AcqRel);
        match tx.try_send(WriteCmd::Write {
            offset,
            data,
            start,
            len,
        }) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.shared.queued_bytes.fetch_sub(l, Ordering::AcqRel);
                Err(WriterFull)
            }
        }
    }

    /// Requests an `fsync` after everything queued so far has been written.
    /// The returned receiver resolves when the data is durable.
    pub fn flush(&self) -> oneshot::Receiver<io::Result<()>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let gone = || io::Error::new(io::ErrorKind::BrokenPipe, "writer thread is gone");
        match &self.tx {
            Some(tx) => {
                if let Err(e) = tx.send(WriteCmd::Flush(reply_tx)) {
                    if let WriteCmd::Flush(reply_tx) = e.0 {
                        let _ = reply_tx.send(Err(gone()));
                    }
                }
            }
            None => {
                let _ = reply_tx.send(Err(gone()));
            }
        }
        reply_rx
    }

    /// Writes everything queued, fsyncs, and stops the thread.
    pub async fn close(self) -> io::Result<()> {
        self.shutdown(false).await
    }

    /// Like [`FileWriter::close`], for a transfer whose data is complete: a
    /// tree also gets the entries no write created (directories, empty
    /// files).
    pub async fn finish(self) -> io::Result<()> {
        self.shutdown(true).await
    }

    async fn shutdown(mut self, complete: bool) -> io::Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(WriteCmd::Close {
                reply: reply_tx,
                complete,
            });
        }
        let result = match reply_rx.await {
            Ok(r) => r,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "writer thread ended without reply",
            )),
        };
        if let Some(t) = self.thread.take() {
            let _ = tokio::task::spawn_blocking(move || t.join()).await;
        }
        result
    }
}

impl Drop for FileWriter {
    fn drop(&mut self) {
        // Dropping the sender ends the thread loop; the thread writes what it
        // has, syncs and exits. We do not join here (Drop may run inside an
        // async runtime).
        self.tx.take();
    }
}

/// Maximum bytes merged into a single positional write.
const COALESCE_LIMIT: usize = 4 << 20;

struct WriterState {
    target: Target,
    shared: Arc<WriterShared>,
    buf: Vec<u8>,
    buf_offset: u64,
    error: Option<io::Error>,
}

fn copy_error(e: &io::Error) -> io::Error {
    io::Error::new(e.kind(), e.to_string())
}

impl WriterState {
    fn append(&mut self, offset: u64, bytes: &[u8]) {
        let contiguous = self.buf_offset + self.buf.len() as u64 == offset;
        if !self.buf.is_empty() && (!contiguous || self.buf.len() + bytes.len() > COALESCE_LIMIT) {
            self.flush_buf();
        }
        if self.buf.is_empty() {
            self.buf_offset = offset;
        }
        self.buf.extend_from_slice(bytes);
    }

    fn flush_buf(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        if self.error.is_none() {
            match self.target.write_at(self.buf_offset, &self.buf) {
                Ok(()) => {
                    self.shared
                        .written_bytes
                        .fetch_add(self.buf.len() as u64, Ordering::Relaxed);
                    self.shared.write_calls.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => self.fail(e),
            }
        }
        // Release capacity even on error so the session cannot wedge; the
        // error is reported by the next flush/close.
        self.shared
            .queued_bytes
            .fetch_sub(self.buf.len() as u64, Ordering::AcqRel);
        self.buf.clear();
    }

    fn fail(&mut self, e: io::Error) {
        if self.error.is_none() {
            *self.shared.error.lock() = Some((e.kind(), e.to_string()));
            self.error = Some(e);
        }
    }

    fn sync(&mut self, all: bool) -> io::Result<()> {
        self.flush_buf();
        if let Some(e) = &self.error {
            return Err(copy_error(e));
        }
        self.target.sync(all).map_err(|e| {
            let copy = copy_error(&e);
            self.fail(e);
            copy
        })
    }

    fn close(&mut self, complete: bool) -> io::Result<()> {
        self.flush_buf();
        if complete && self.error.is_none() {
            if let Err(e) = self.target.finish() {
                self.fail(e);
            }
        }
        let result = self.sync(true);
        self.target.close_files();
        result
    }
}

fn writer_loop(target: Target, rx: MpscReceiver<WriteCmd>, shared: Arc<WriterShared>) {
    let mut st = WriterState {
        target,
        shared,
        buf: Vec::with_capacity(COALESCE_LIMIT),
        buf_offset: 0,
        error: None,
    };
    loop {
        // Keep absorbing commands while they are immediately available so
        // that sequential arrivals become one large write; write out the
        // buffer before blocking.
        let cmd = match rx.try_recv() {
            Ok(c) => c,
            Err(TryRecvError::Empty) => {
                st.flush_buf();
                match rx.recv() {
                    Ok(c) => c,
                    Err(_) => break,
                }
            }
            Err(TryRecvError::Disconnected) => break,
        };
        match cmd {
            WriteCmd::Write {
                offset,
                data,
                start,
                len,
            } => st.append(offset, &data[start..start + len]),
            WriteCmd::Flush(reply) => {
                let r = st.sync(false);
                let _ = reply.send(r);
            }
            WriteCmd::Close { reply, complete } => {
                let r = st.close(complete);
                let _ = reply.send(r);
                return;
            }
        }
    }
    let _ = st.close(false);
}

/// Replaces `path` with `bytes` durably (temporary file, fsync, rename).
pub(crate) fn write_file_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// BLAKE3-256 of a whole file, using memory mapping and all cores.
pub fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update_mmap_rayon(path)?;
    Ok(*hasher.finalize().as_bytes())
}

pub fn hash_to_hex(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ---------------------------------------------------------------------------
// Disk space
// ---------------------------------------------------------------------------

/// Free space available to this process on the file system holding `dir`.
pub fn available_space(dir: &Path) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(dir.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        // SAFETY: statvfs fills a zero-initialised POD struct for a valid
        // NUL-terminated path.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // The field types differ between platforms (u32 on some, u64 on others).
        #[allow(clippy::unnecessary_cast)]
        let free = (st.f_bavail as u64).saturating_mul(st.f_frsize as u64);
        Ok(free)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use winapi::shared::ntdef::ULARGE_INTEGER;
        use winapi::um::fileapi::GetDiskFreeSpaceExW;
        let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: GetDiskFreeSpaceExW writes into a zero-initialised
        // ULARGE_INTEGER for a valid NUL-terminated wide path.
        let mut free: ULARGE_INTEGER = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut free,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { *free.QuadPart() })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
        Ok(u64::MAX)
    }
}

// ---------------------------------------------------------------------------
// Names and paths
// ---------------------------------------------------------------------------

/// Reduces a file name received from the network to a plain base name that
/// is safe to join onto the output directory on every platform.
pub fn sanitize_file_name(name: &str) -> Option<String> {
    // Keep only the last path component, whatever separator the peer used.
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .map(|c| match c {
            '\0'..='\x1f' | '\x7f' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim().trim_end_matches('.').to_string();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return None;
    }
    if trimmed.len() > crate::protocol::constants::MAX_FILE_NAME_LEN {
        return None;
    }
    if tree::is_windows_reserved(&trimmed) {
        return Some(format!("_{}", trimmed));
    }
    Some(trimmed)
}

/// Returns `dir/name` or, if it exists, `dir/name (n).ext` with the smallest
/// free `n`.
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 1..10_000 {
        let p = dir.join(format!("{} ({}){}", stem, n, ext));
        if !p.exists() {
            return p;
        }
    }
    dir.join(format!("{}-{:08x}{}", stem, rand::random::<u32>(), ext))
}

/// Path of the partial file for a given final path.
pub fn part_path_for(final_path: &Path) -> PathBuf {
    let mut s = final_path.as_os_str().to_owned();
    s.push(PART_SUFFIX);
    PathBuf::from(s)
}

/// Renames with a few retries on "permission denied" (on Windows, antivirus
/// scanners and indexers briefly hold freshly written files open).
pub fn rename_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    let mut delay = Duration::from_millis(20);
    let mut attempt = 0;
    loop {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 5 && e.kind() == io::ErrorKind::PermissionDenied => {
                std::thread::sleep(delay);
                delay *= 2;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_paths_and_bad_chars() {
        assert_eq!(sanitize_file_name("report.bin"), Some("report.bin".into()));
        assert_eq!(
            sanitize_file_name("../../etc/passwd"),
            Some("passwd".into())
        );
        assert_eq!(
            sanitize_file_name("C:\\Users\\x\\a.txt"),
            Some("a.txt".into())
        );
        assert_eq!(sanitize_file_name("dir/"), None);
        assert_eq!(sanitize_file_name(".."), None);
        assert_eq!(sanitize_file_name("   "), None);
        assert_eq!(sanitize_file_name("a:b*c?.txt"), Some("a_b_c_.txt".into()));
        assert_eq!(sanitize_file_name("CON"), Some("_CON".into()));
        assert_eq!(sanitize_file_name("con.txt"), Some("_con.txt".into()));
        assert_eq!(sanitize_file_name("name."), Some("name".into()));
        assert_eq!(sanitize_file_name("отчёт.bin"), Some("отчёт.bin".into()));
    }

    #[test]
    fn unique_path_appends_counter() {
        let dir = tempfile::tempdir().unwrap();
        let first = unique_path(dir.path(), "a.txt");
        assert_eq!(first, dir.path().join("a.txt"));
        std::fs::write(&first, b"x").unwrap();
        let second = unique_path(dir.path(), "a.txt");
        assert_eq!(second, dir.path().join("a (1).txt"));
        std::fs::write(&second, b"x").unwrap();
        assert_eq!(
            unique_path(dir.path(), "a.txt"),
            dir.path().join("a (2).txt")
        );
        assert_eq!(unique_path(dir.path(), "noext"), dir.path().join("noext"));
    }

    #[tokio::test]
    async fn writer_coalesces_and_flushes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        let writer = FileWriter::open(&path, 10_000, 1 << 20).unwrap();
        // Out of order, sequential, and a slice of a larger buffer.
        writer.enqueue(5000, vec![2u8; 5000]).unwrap();
        writer.enqueue(0, vec![1u8; 2500]).unwrap();
        let mut datagram = vec![9u8; 100];
        datagram.extend(std::iter::repeat_n(1u8, 2500));
        datagram.extend(vec![9u8; 50]);
        writer.enqueue_slice(2500, datagram, 100, 2500).unwrap();
        writer.flush().await.unwrap().unwrap();
        assert_eq!(writer.queued_bytes(), 0);
        assert_eq!(writer.written_bytes(), 10_000);
        writer.close().await.unwrap();
        let data = std::fs::read(&path).unwrap();
        assert_eq!(data.len(), 10_000);
        assert!(data[..5000].iter().all(|&b| b == 1));
        assert!(data[5000..].iter().all(|&b| b == 2));
        assert_eq!(hash_file(&path).unwrap(), *blake3::hash(&data).as_bytes());
    }

    #[test]
    fn writer_respects_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        let writer = FileWriter::open(&path, 4 << 20, 1 << 20).unwrap();
        // A single write larger than the capacity is always refused.
        assert!(writer.enqueue(0, vec![0u8; (1 << 20) + 1]).is_err());
        assert!(writer.available() <= 1 << 20);
    }

    #[test]
    fn reader_reads_ranges() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("in.bin");
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let r = FileReader::open(&path).unwrap();
        assert_eq!(r.size(), 5000);
        let mut buf = vec![0u8; 100];
        r.read_at(4900, &mut buf).unwrap();
        assert_eq!(&buf[..], &data[4900..]);
        assert!(r.read_at(4950, &mut buf).is_err());
        assert!(available_space(dir.path()).unwrap() > 0);
        assert_eq!(hash_file(&path).unwrap(), *blake3::hash(&data).as_bytes());
        // Empty file hashes like empty input.
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(hash_file(&empty).unwrap(), *blake3::hash(b"").as_bytes());
    }
}
