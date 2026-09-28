//! Packet encryption and decryption on worker threads.
//!
//! One core seals or opens AES-256-GCM packets at roughly 8 Gbit/s
//! (ChaCha20-Poly1305: about 3), which is about half of the work per packet
//! of a transfer engine. So the engines hand whole batches of packets to a
//! few worker threads and carry on; the results come back through a channel
//! and are used in order. The workers block while idle: they cost nothing
//! when there is no work, and they are separate from the threads that hash
//! files, so a running hash never delays packets.

use parking_lot::Mutex;
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};

/// Most worker threads.
const MAX_THREADS: usize = 4;

type Job = Box<dyn FnOnce() + Send>;

/// A pool of worker threads that run jobs in the order they are given
/// (several at once).
pub struct Pool {
    tx: mpsc::Sender<Job>,
    threads: usize,
}

impl Pool {
    fn new(threads: usize) -> Option<Self> {
        let (tx, rx) = mpsc::channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..threads {
            let rx = rx.clone();
            std::thread::Builder::new()
                .name(format!("sharp-crypto-{}", i))
                .spawn(move || loop {
                    let job = rx.lock().recv();
                    match job {
                        Ok(job) => job(),
                        Err(_) => return,
                    }
                })
                .ok()?;
        }
        Some(Self { tx, threads })
    }

    pub fn threads(&self) -> usize {
        self.threads
    }

    /// Runs `job` on a worker thread.
    pub fn spawn(&self, job: impl FnOnce() + Send + 'static) {
        // The workers never exit while the pool exists, so this cannot fail.
        let _ = self.tx.send(Box::new(job));
    }
}

/// Worker threads to use: `SHARP256_CRYPTO_THREADS` if set (0 turns the
/// pool off), otherwise two less than the cores available (one for the
/// engine, one for the network stack), at most [`MAX_THREADS`].
fn pool_threads() -> usize {
    if let Some(n) = std::env::var("SHARP256_CRYPTO_THREADS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        return n.min(64);
    }
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    cores.saturating_sub(2).min(MAX_THREADS)
}

/// The process-wide crypto pool, or `None` when the machine has too few
/// cores for it to pay off (the engines then encrypt on their own thread).
pub fn pool() -> Option<&'static Pool> {
    static POOL: OnceLock<Option<Pool>> = OnceLock::new();
    POOL.get_or_init(|| {
        let threads = pool_threads();
        if threads == 0 {
            return None;
        }
        let pool = Pool::new(threads);
        if let Some(p) = &pool {
            tracing::debug!("packet crypto on {} worker thread(s)", p.threads());
        }
        pool
    })
    .as_ref()
}

/// Splits `buf` into consecutive mutable slices of the given lengths.
pub fn split_lengths(mut buf: &mut [u8], lengths: impl Iterator<Item = usize>) -> Vec<&mut [u8]> {
    let mut out = Vec::new();
    for len in lengths {
        let (head, tail) = std::mem::take(&mut buf).split_at_mut(len);
        out.push(head);
        buf = tail;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn pool_runs_every_job() {
        let pool = Pool::new(3).unwrap();
        let (tx, rx) = mpsc::channel();
        for i in 0..100u32 {
            let tx = tx.clone();
            pool.spawn(move || tx.send(i * 2).unwrap());
        }
        let mut got: Vec<u32> = (0..100)
            .map(|_| rx.recv_timeout(Duration::from_secs(5)).unwrap())
            .collect();
        got.sort_unstable();
        assert!(got.iter().enumerate().all(|(i, &v)| v == 2 * i as u32));
    }

    #[test]
    fn splits_a_buffer_into_packets() {
        let mut buf: Vec<u8> = (0..10).collect();
        let parts = split_lengths(&mut buf, [3, 3, 4].into_iter());
        assert_eq!(parts.len(), 3);
        assert_eq!(&*parts[0], &[0, 1, 2]);
        assert_eq!(&*parts[2], &[6, 7, 8, 9]);
    }
}
