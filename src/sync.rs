//! The synchronisation that the crate's shared invariants rest on, through
//! one door: the standard library's atomics and parking_lot's lock in a
//! build, loom's in the tests built with `--cfg sharp_loom`
//! (`scripts/loom.sh`), which run each model in every interleaving of its
//! threads that can differ. What goes through here: the keys of a
//! session's epochs (`crypto::transport`), the receiver's memory budget
//! (`transport::receiver`) and the handshake timestamps
//! (`crypto::handshake`).

#[cfg(all(test, sharp_loom))]
pub(crate) use loom::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(all(test, sharp_loom)))]
pub(crate) use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(all(test, sharp_loom)))]
pub(crate) use parking_lot::RwLock;

/// loom's lock, with parking_lot's way of handing out its guards (no
/// poisoning to unwrap).
#[cfg(all(test, sharp_loom))]
#[derive(Default)]
pub(crate) struct RwLock<T>(loom::sync::RwLock<T>);

#[cfg(all(test, sharp_loom))]
impl<T> RwLock<T> {
    pub(crate) fn read(&self) -> loom::sync::RwLockReadGuard<'_, T> {
        self.0.read().unwrap()
    }

    pub(crate) fn write(&self) -> loom::sync::RwLockWriteGuard<'_, T> {
        self.0.write().unwrap()
    }

    pub(crate) fn get_mut(&mut self) -> &mut T {
        self.0.get_mut().unwrap()
    }
}

/// Replaces the value of `a` with `f` of it, unless `f` says `None`;
/// whether it did. What `AtomicU64::fetch_update` does — spelled out,
/// because newer compilers deprecate that name for one that does not exist
/// yet at the oldest compiler this crate supports.
pub(crate) fn update_atomic(a: &AtomicU64, mut f: impl FnMut(u64) -> Option<u64>) -> bool {
    let mut current = a.load(Ordering::Acquire);
    while let Some(new) = f(current) {
        match a.compare_exchange_weak(current, new, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(seen) => current = seen,
        }
    }
    false
}
