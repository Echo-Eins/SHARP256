//! Memory for keys: kept out of swap and out of core dumps while it is in
//! use, wiped when it is given back, and never printed.
//!
//! A key that the system writes to swap outlives the process on disk, and
//! a session key found there undoes forward secrecy for whatever was
//! recorded of that session. So every place a key is kept for longer than
//! a computation — the identity, the pre-shared key, the state of a
//! handshake in progress, the keys of each session, the secrets of cookies
//! and tokens — is a [`Locked`] value: on the heap, its pages locked in RAM
//! (`mlock`, `VirtualLock`) and, on Linux and FreeBSD, left out of core
//! dumps (`MADV_DONTDUMP`, `MADV_NOCORE`); wiped with `zeroize` when
//! dropped. [`SecretKey`] is the common case, 32 bytes shared by reference.
//!
//! Locking works on whole pages and does not count: unlocking a page
//! unlocks it for everything on it. Keys are small and share pages with
//! each other, so the pages are counted here — a page is locked when the
//! first key on it arrives and unlocked when the last one leaves.
//!
//! The system may refuse to lock (`RLIMIT_MEMLOCK`, which is 8 MiB on
//! current Linux but 64 KiB on older systems; the working set on Windows).
//! Keys then still work and are still wiped, and the first refusal is
//! reported once, with what to do about it ([`locking`] tells the program
//! what happened).
//!
//! What this cannot do: values the compiler copies while it builds or
//! moves one — onto the stack, into registers — are out of reach, as they
//! are for every Rust program; such copies are made in the course of a
//! computation and are not kept. Hibernation writes all of memory to disk,
//! locked or not.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use zeroize::Zeroize;

/// A value that holds key material, alone in a heap allocation whose pages
/// are locked in memory for as long as it lives; wiped when dropped.
///
/// Build it in place where the value can be ([`Locked::with`]): whatever is
/// built elsewhere and moved in leaves the copy it was built in behind.
pub struct Locked<T: Zeroize> {
    value: Box<T>,
}

impl<T: Zeroize> Locked<T> {
    /// Moves `value` into locked memory. The place it was built in is not
    /// wiped; prefer [`Locked::with`] where `T` has a default.
    pub fn new(value: T) -> Self {
        let value = Box::new(value);
        pages::acquire(range_of(&*value));
        Self { value }
    }

    /// A default `T` in locked memory, handed to `fill` to be made into
    /// the real thing where it lies.
    pub fn with(fill: impl FnOnce(&mut T)) -> Self
    where
        T: Default,
    {
        let mut locked = Self::new(T::default());
        fill(&mut locked.value);
        locked
    }
}

fn range_of<T>(value: &T) -> (usize, usize) {
    (value as *const T as usize, std::mem::size_of::<T>())
}

impl<T: Zeroize> Drop for Locked<T> {
    fn drop(&mut self) {
        self.value.zeroize();
        pages::release(range_of(&*self.value));
    }
}

impl<T: Zeroize> Deref for Locked<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: Zeroize> DerefMut for Locked<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

/// A copy made in its own locked place.
impl<T: Zeroize + Default + Clone> Clone for Locked<T> {
    fn clone(&self) -> Self {
        Self::with(|copy| copy.clone_from(&self.value))
    }
}

/// Never shows what is inside.
impl<T: Zeroize> fmt::Debug for Locked<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Locked(..)")
    }
}

/// A 32-byte secret key in locked memory, shared by reference: copies are
/// handles to the one locked place, which is wiped when the last goes.
/// Never printed, and compared only in constant time.
#[derive(Clone)]
pub struct SecretKey(Arc<Locked<[u8; 32]>>);

impl SecretKey {
    /// A key made where it will stay by `fill`.
    pub fn with(fill: impl FnOnce(&mut [u8; 32])) -> Self {
        let key = Self(Arc::new(Locked::with(fill)));
        #[cfg(test)]
        keylog::note(key.expose());
        key
    }

    /// A copy of `bytes`. The caller's own copy is the caller's to wipe.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self::with(|k| k.copy_from_slice(bytes))
    }

    /// A fresh random key.
    pub fn random() -> Self {
        use rand::RngCore;
        Self::with(|k| rand::rngs::OsRng.fill_bytes(k))
    }

    /// A key derived with BLAKE3's key derivation, written straight into
    /// its place (see `crypto::derive_secret`).
    pub fn derive(context: &str, material: &[&[u8]]) -> Self {
        Self::with(|k| k.copy_from_slice(&*super::derive_secret(context, material)))
    }

    /// The key's bytes, for the computation that needs them.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.expose().ct_eq(other.expose()))
    }
}

impl Eq for SecretKey {}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// Text with a secret in it — a passphrase, a TURN server's
/// `USER:PASSWORD@HOST` — in a string that is wiped when dropped and never
/// printed: `{:?}` shows `SecretText(..)`, so a structure holding one (the
/// programs' command-line arguments) can derive `Debug` without giving it
/// away.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretText(zeroize::Zeroizing<String>);

impl SecretText {
    pub fn new(text: String) -> Self {
        Self(zeroize::Zeroizing::new(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for SecretText {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText(..)")
    }
}

/// Reads text with a secret in it from the command line (a `clap` value
/// parser). What the system keeps of the command line and the environment
/// is beyond reach: what is given as an argument is visible in the list of
/// processes, what is in an environment variable only to the same user.
pub fn secret_text(s: &str) -> Result<SecretText, std::convert::Infallible> {
    Ok(SecretText::new(s.to_string()))
}

/// For the tests only: every key made while recording is on, so that a
/// test can look for each of them where none may be (the log;
/// `transport::log_hygiene`). Keys made outside [`SecretKey`] note
/// themselves here too. Only on the threads that test marked as its own:
/// the other tests of the process make keys of their own meanwhile —
/// tens of thousands, some runs — and looking for each of them in the log
/// took minutes, without saying anything of the transfers it is about.
#[cfg(test)]
pub(crate) mod keylog {
    use parking_lot::Mutex;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering};

    static ON: AtomicBool = AtomicBool::new(false);
    static KEYS: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
    thread_local! {
        static MINE: Cell<bool> = const { Cell::new(false) };
    }

    /// Marks the calling thread as one whose keys are noted.
    pub(crate) fn this_thread() {
        MINE.with(|m| m.set(true));
    }

    pub(crate) fn note(key: &[u8]) {
        if ON.load(Ordering::Relaxed) && MINE.with(Cell::get) {
            KEYS.lock().push(key.to_vec());
        }
    }

    pub(crate) fn record(on: bool) {
        ON.store(on, Ordering::Relaxed);
    }

    pub(crate) fn take() -> Vec<Vec<u8>> {
        std::mem::take(&mut *KEYS.lock())
    }
}

/// Whether keys could be locked in memory so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locking {
    /// Nothing has asked yet.
    Unused,
    /// Every page asked for was locked.
    Locked,
    /// The system refused at least one page: some keys may reach swap.
    Refused,
    /// This system has no way to lock memory that is supported here.
    Unsupported,
}

static STATE: AtomicU8 = AtomicU8::new(0);

/// What has happened to requests to lock keys in memory so far.
pub fn locking() -> Locking {
    match STATE.load(Ordering::Relaxed) {
        0 => Locking::Unused,
        1 => Locking::Locked,
        2 => Locking::Refused,
        _ => Locking::Unsupported,
    }
}

fn note(outcome: Locking, why: impl FnOnce() -> String) {
    let code = match outcome {
        Locking::Unused => 0,
        Locking::Locked => 1,
        Locking::Refused => 2,
        Locking::Unsupported => 3,
    };
    // Refused and unsupported are sticky, and told once.
    let before = STATE.fetch_max(code, Ordering::Relaxed);
    if code >= 2 && before < 2 {
        tracing::warn!("{}", why());
    }
}

/// How many keys lie on each page: a page is to be locked when its first
/// key arrives and unlocked when its last one leaves.
struct PageCounts {
    size: usize,
    holders: HashMap<usize, usize>,
}

impl PageCounts {
    /// The pages `(start, len)` touches.
    fn pages(&self, (start, len): (usize, usize)) -> Vec<usize> {
        if len == 0 {
            return Vec::new();
        }
        let size = self.size;
        let first = start & !(size - 1);
        let last = (start + len - 1) & !(size - 1);
        (first..=last).step_by(size).collect()
    }

    /// Counts a key on `range`; returns the pages that had none before.
    fn acquire(&mut self, range: (usize, usize)) -> Vec<usize> {
        let mut new = Vec::new();
        for page in self.pages(range) {
            let count = self.holders.entry(page).or_insert(0);
            if *count == 0 {
                new.push(page);
            }
            *count += 1;
        }
        new
    }

    /// Takes a key off `range`; returns the pages that now have none.
    fn release(&mut self, range: (usize, usize)) -> Vec<usize> {
        let mut empty = Vec::new();
        for page in self.pages(range) {
            let Some(count) = self.holders.get_mut(&page) else {
                continue;
            };
            *count -= 1;
            if *count == 0 {
                self.holders.remove(&page);
                empty.push(page);
            }
        }
        empty
    }
}

/// The pages holding keys in this process, and the calls that lock them.
mod pages {
    use super::*;

    static COUNTS: OnceLock<Mutex<PageCounts>> = OnceLock::new();

    fn counts() -> &'static Mutex<PageCounts> {
        COUNTS.get_or_init(|| {
            let size = os::page_size()
                .filter(|s| s.is_power_of_two())
                .unwrap_or(4096);
            Mutex::new(PageCounts {
                size,
                holders: HashMap::new(),
            })
        })
    }

    pub(super) fn acquire(range: (usize, usize)) {
        let mut counts = counts().lock();
        let size = counts.size;
        // Locked while the count is held, so that no page is unlocked by one
        // thread between another's counting and locking it.
        for page in counts.acquire(range) {
            match os::lock(page, size) {
                Ok(()) => note(Locking::Locked, String::new),
                Err(os::Error::Unsupported) => note(Locking::Unsupported, || {
                    "keys cannot be locked in memory on this system; they may be written to swap"
                        .to_string()
                }),
                Err(os::Error::Refused(e)) => note(Locking::Refused, || {
                    format!(
                        "the system refused to lock keys in memory ({}); they may be written to swap. {}",
                        e,
                        os::HOW_TO_ALLOW
                    )
                }),
            }
            os::keep_out_of_dumps(page, size, true);
        }
    }

    pub(super) fn release(range: (usize, usize)) {
        let mut counts = counts().lock();
        let size = counts.size;
        for page in counts.release(range) {
            os::unlock(page, size);
            os::keep_out_of_dumps(page, size, false);
        }
    }
}

// Miri runs none of these system calls; under it keys are kept as on a
// system that cannot lock them, and everything else is checked.
#[cfg(all(unix, not(miri)))]
#[allow(unsafe_code)] // sysconf(3), mlock(2), munlock(2), madvise(2) (docs/UNSAFE.md)
mod os {
    pub enum Error {
        Unsupported,
        Refused(std::io::Error),
    }

    pub const HOW_TO_ALLOW: &str =
        "Raise the limit on locked memory (ulimit -l; LimitMEMLOCK= for a systemd service).";

    pub fn page_size() -> Option<usize> {
        // SAFETY: sysconf reads a system constant; it has no preconditions.
        let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(n).ok()
    }

    pub fn lock(page: usize, len: usize) -> Result<(), Error> {
        // SAFETY: mlock changes only whether the pages may be swapped out,
        // never what they hold; `page` is a page of memory this process has
        // mapped (it holds a live allocation), so the call cannot fault.
        let rc = unsafe { libc::mlock(page as *const libc::c_void, len) };
        if rc == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        Err(match e.raw_os_error() {
            Some(libc::ENOSYS) => Error::Unsupported,
            _ => Error::Refused(e),
        })
    }

    pub fn unlock(page: usize, len: usize) {
        // SAFETY: as for mlock; unlocking a page that is not locked is not
        // an error.
        unsafe { libc::munlock(page as *const libc::c_void, len) };
    }

    #[allow(unused_variables)]
    pub fn keep_out_of_dumps(page: usize, len: usize, out: bool) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let advice = if out {
            libc::MADV_DONTDUMP
        } else {
            libc::MADV_DODUMP
        };
        #[cfg(target_os = "freebsd")]
        let advice = if out {
            libc::MADV_NOCORE
        } else {
            libc::MADV_CORE
        };
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
        // SAFETY: this advice changes only whether the page is written into
        // a core dump, never its contents or mapping; the page is mapped (a
        // live allocation is on it) and page-aligned. A failure costs only
        // that, so it is not checked.
        unsafe {
            libc::madvise(page as *mut libc::c_void, len, advice);
        }
    }
}

#[cfg(all(windows, not(miri)))]
#[allow(unsafe_code)] // GetSystemInfo, VirtualLock and the working set (docs/UNSAFE.md)
mod os {
    use winapi::shared::winerror::ERROR_WORKING_SET_QUOTA;
    use winapi::um::memoryapi::{VirtualLock, VirtualUnlock};

    pub enum Error {
        #[allow(dead_code)]
        Unsupported,
        Refused(std::io::Error),
    }

    pub const HOW_TO_ALLOW: &str =
        "The process's minimum working set could not be raised to make room.";

    pub fn page_size() -> Option<usize> {
        // SAFETY: SYSTEM_INFO is plain data; all zeroes is a value of it.
        let mut info: winapi::um::sysinfoapi::SYSTEM_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: GetSystemInfo fills the structure it is given and has no
        // other effect.
        unsafe { winapi::um::sysinfoapi::GetSystemInfo(&mut info) };
        Some(info.dwPageSize as usize)
    }

    fn virtual_lock(page: usize, len: usize) -> Result<(), std::io::Error> {
        // SAFETY: VirtualLock changes only whether the pages stay in the
        // working set; `page` is committed memory of this process (a live
        // allocation is on it).
        if unsafe { VirtualLock(page as *mut _, len) } != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Windows lets a process lock only as much as its minimum working set
    /// allows beyond what it needs anyway — by default a few dozen pages.
    /// Once that is used up the minimum is raised (as far as the system
    /// agrees, which needs no privilege for a few MiB) and the lock tried
    /// again.
    pub fn lock(page: usize, len: usize) -> Result<(), Error> {
        match virtual_lock(page, len) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(ERROR_WORKING_SET_QUOTA as i32) => {
                grow_working_set();
                virtual_lock(page, len).map_err(Error::Refused)
            }
            Err(e) => Err(Error::Refused(e)),
        }
    }

    fn grow_working_set() {
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::winbase::{GetProcessWorkingSetSize, SetProcessWorkingSetSize};
        const MORE: usize = 4 << 20;
        let (mut min, mut max) = (0usize, 0usize);
        // SAFETY: the process's pseudo-handle for itself, which needs no
        // closing.
        let me = unsafe { GetCurrentProcess() };
        // SAFETY: this process's own working set limits, into two places of
        // ours.
        if unsafe { GetProcessWorkingSetSize(me, &mut min, &mut max) } != 0 {
            // SAFETY: new limits for this process's own working set; the
            // system refuses what it will not allow, and a refusal shows
            // as VirtualLock's.
            unsafe { SetProcessWorkingSetSize(me, min + MORE, max.max(min + MORE) + MORE) };
        }
    }

    pub fn unlock(page: usize, len: usize) {
        // SAFETY: as for VirtualLock; a page that is not locked makes this
        // fail harmlessly.
        unsafe { VirtualUnlock(page as *mut _, len) };
    }

    pub fn keep_out_of_dumps(_page: usize, _len: usize, _out: bool) {}
}

#[cfg(any(miri, not(any(unix, windows))))]
mod os {
    pub enum Error {
        Unsupported,
        #[allow(dead_code)]
        Refused(std::io::Error),
    }
    pub const HOW_TO_ALLOW: &str = "";
    pub fn page_size() -> Option<usize> {
        None
    }
    pub fn lock(_page: usize, _len: usize) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    pub fn unlock(_page: usize, _len: usize) {}
    pub fn keep_out_of_dumps(_page: usize, _len: usize, _out: bool) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A page is locked when its first key arrives and unlocked only when
    /// its last one leaves, whatever order they come and go in; a key
    /// across a page boundary holds both pages.
    #[test]
    fn a_page_is_unlocked_by_its_last_key_only() {
        let mut c = PageCounts {
            size: 4096,
            holders: HashMap::new(),
        };
        assert_eq!(c.acquire((8192 + 100, 32)), vec![8192]);
        assert_eq!(c.acquire((8192 + 200, 32)), Vec::<usize>::new());
        assert_eq!(c.acquire((8192 + 4090, 32)), vec![12288]);
        assert_eq!(c.release((8192 + 100, 32)), Vec::<usize>::new());
        assert_eq!(c.release((8192 + 4090, 32)), vec![12288]);
        assert_eq!(c.release((8192 + 200, 32)), vec![8192]);
        assert!(c.holders.is_empty());
        // A value of no size touches no page; one that ends exactly at a
        // page boundary does not touch the next.
        assert_eq!(c.acquire((8192, 0)), Vec::<usize>::new());
        assert_eq!(c.acquire((8192, 4096)), vec![8192]);
        assert_eq!(c.release((8192, 4096)), vec![8192]);
        // Releasing what was never counted changes nothing.
        assert_eq!(c.release((40960, 32)), Vec::<usize>::new());
    }

    /// Copies of a key are the same locked place; they compare equal in
    /// constant time; none of it is ever printed.
    #[test]
    fn a_key_is_shared_compared_and_never_shown() {
        let a = SecretKey::from_bytes(&[0x5a; 32]);
        let b = a.clone();
        assert!(std::ptr::eq(a.expose(), b.expose()));
        assert_eq!(a, SecretKey::from_bytes(&[0x5a; 32]));
        assert_ne!(a, SecretKey::random());
        let shown = format!("{:?} {:?}", a, Locked::new([0x5au8; 32]));
        assert!(!shown.contains("90") && !shown.contains("5a"), "{}", shown);
        let derived = SecretKey::derive("sharp256 test", &[b"x", b"y"]);
        assert_eq!(
            derived.expose(),
            &blake3::derive_key("sharp256 test", b"xy")
        );
    }

    #[test]
    fn secret_text_is_never_shown() {
        let t = secret_text("alice:hunter2@turn.example.org").unwrap();
        assert_eq!(format!("{:?}", t), "SecretText(..)");
        assert_eq!(&*t, "alice:hunter2@turn.example.org");
    }

    /// On this machine keys are locked: the test environment has room for
    /// a few pages (RLIMIT_MEMLOCK is 64 KiB even on old systems).
    #[cfg(all(unix, not(miri)))]
    #[test]
    fn keys_are_locked_here() {
        let _k = SecretKey::random();
        assert_eq!(
            locking(),
            Locking::Locked,
            "RLIMIT_MEMLOCK too small for the tests?"
        );
        // And the kernel says so: the page is in the process's locked set.
        #[cfg(target_os = "linux")]
        {
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            let locked_kb: u64 = status
                .lines()
                .find_map(|l| l.strip_prefix("VmLck:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
                .unwrap();
            assert!(locked_kb >= 4, "VmLck is {} kB", locked_kb);
        }
    }
}
