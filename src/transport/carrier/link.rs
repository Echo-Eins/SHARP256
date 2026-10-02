//! A stream that carries frames: what is read goes to a handler, what is
//! sent is written, in order, by a task of its own.

use super::frame::{self, Frame, MAX_DATAGRAM};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Datagrams a link holds for writing. Past that, sending more is refused,
/// as a full socket buffer drops what it will not take.
const QUEUE: usize = 4096;
/// What the reading and the writing side each buffer.
const BUFFER: usize = 64 << 10;

/// What is known of a stream while it runs.
#[derive(Debug, Default)]
pub struct StreamStats {
    queued: AtomicU64,
    closed: AtomicBool,
    sent: AtomicU64,
    received: AtomicU64,
}

impl StreamStats {
    /// Bytes handed over to be sent and not yet written to the stream.
    pub fn queued(&self) -> u64 {
        self.queued.load(Ordering::Relaxed)
    }

    /// Whether the stream still runs.
    pub fn alive(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
    }

    /// Datagram bytes written so far.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Datagram bytes read so far.
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

enum Out {
    Datagram(u16, Vec<u8>),
    Own(Vec<u8>),
}

impl Out {
    fn len(&self) -> usize {
        match self {
            Out::Datagram(_, d) | Out::Own(d) => d.len(),
        }
    }
}

/// Where datagrams are sent on a stream.
#[derive(Clone)]
pub struct Link {
    tx: mpsc::Sender<Out>,
    stats: Arc<StreamStats>,
    cancel: CancellationToken,
}

impl Link {
    /// Queues `data` to be written on `port`. False, and dropped, when the
    /// queue is full, the datagram longer than a frame takes, or the stream
    /// gone: what UDP would do with it.
    pub fn send(&self, port: u16, data: &[u8]) -> bool {
        if data.len() > MAX_DATAGRAM || data.is_empty() {
            return false;
        }
        self.queue(Out::Datagram(port, data.to_vec()))
    }

    /// Queues a datagram as `send` does, waiting up to `within` for room
    /// when the queue is full.
    pub async fn send_within(&self, port: u16, data: &[u8], within: Duration) -> bool {
        if data.len() > MAX_DATAGRAM || data.is_empty() {
            return false;
        }
        let Ok(Ok(permit)) = tokio::time::timeout(within, self.tx.reserve()).await else {
            return false;
        };
        let out = Out::Datagram(port, data.to_vec());
        self.stats
            .queued
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        permit.send(out);
        true
    }

    /// Queues a frame of the carrier's own.
    pub fn send_own(&self, data: &[u8]) -> bool {
        if data.len() > MAX_DATAGRAM {
            return false;
        }
        self.queue(Out::Own(data.to_vec()))
    }

    fn queue(&self, out: Out) -> bool {
        let len = out.len() as u64;
        self.stats.queued.fetch_add(len, Ordering::Relaxed);
        if self.tx.try_send(out).is_ok() {
            return true;
        }
        self.stats.queued.fetch_sub(len, Ordering::Relaxed);
        false
    }

    pub fn stats(&self) -> &Arc<StreamStats> {
        &self.stats
    }

    /// Ends the stream, both ways.
    pub fn close(&self) {
        self.cancel.cancel();
    }

    /// Waits until the stream has ended.
    pub async fn closed(&self) {
        self.cancel.cancelled().await
    }

    pub fn is_closed(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

/// Runs `stream`: every frame read is handed to `on_frame`, and what is
/// sent on the link returned is written, in order. The next frame is read
/// once the future `on_frame` returns is done: a handler that has nowhere to
/// put a frame holds the stream up, and the stream's own flow control holds
/// up its sender, where a datagram would have been dropped. Ends — and the
/// link with it — when either direction fails, when the other side closes,
/// and when `cancel` fires (as closing the link does).
pub fn run<S, F>(
    stream: S,
    on_frame: impl FnMut(Frame) -> F + Send + 'static,
    cancel: CancellationToken,
) -> Link
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    F: std::future::Future<Output = ()> + Send + 'static,
{
    run_with(stream, on_frame, cancel, |_| {})
}

/// [`run`], with `before` given the link before the first frame is read:
/// where the answer to that frame is to go back on the link, the link must
/// be found there by then.
pub fn run_with<S, F>(
    stream: S,
    on_frame: impl FnMut(Frame) -> F + Send + 'static,
    cancel: CancellationToken,
    before: impl FnOnce(&Link),
) -> Link
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let (rd, wr) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel(QUEUE);
    let stats = Arc::new(StreamStats::default());
    let link = Link {
        tx,
        stats: stats.clone(),
        cancel: cancel.clone(),
    };
    before(&link);
    tokio::spawn(read_loop(rd, on_frame, stats.clone(), cancel.clone()));
    tokio::spawn(write_loop(wr, rx, stats, cancel));
    link
}

async fn read_loop<R: AsyncRead + Unpin, F: std::future::Future<Output = ()>>(
    rd: R,
    mut on_frame: impl FnMut(Frame) -> F,
    stats: Arc<StreamStats>,
    cancel: CancellationToken,
) {
    let mut rd = BufReader::with_capacity(BUFFER, rd);
    loop {
        let next = tokio::select! {
            f = frame::read_frame(&mut rd) => f,
            _ = cancel.cancelled() => break,
        };
        match next {
            Ok(Some(f)) => {
                if let Frame::Datagram { data, .. } = &f {
                    stats
                        .received
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                tokio::select! {
                    _ = on_frame(f) => {}
                    _ = cancel.cancelled() => break,
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("carrier: stream read failed: {}", e);
                break;
            }
        }
    }
    stats.close();
    cancel.cancel();
}

async fn write_loop<W: AsyncWrite + Unpin>(
    wr: W,
    mut rx: mpsc::Receiver<Out>,
    stats: Arc<StreamStats>,
    cancel: CancellationToken,
) {
    let mut wr = BufWriter::with_capacity(BUFFER, wr);
    loop {
        let first = tokio::select! {
            m = rx.recv() => match m {
                Some(m) => m,
                None => break,
            },
            _ = cancel.cancelled() => break,
        };
        // Whatever is already queued goes out with it, in one flush. A
        // peer that stops reading must not hold this task for ever: the
        // writes give way to the stream ending.
        let written = tokio::select! {
            r = write_queued(&mut wr, first, &mut rx, &stats) => r,
            _ = cancel.cancelled() => break,
        };
        if let Err(e) = written {
            tracing::debug!("carrier: stream write failed: {}", e);
            break;
        }
    }
    stats.close();
    cancel.cancel();
    let _ = wr.shutdown().await;
}

async fn write_queued<W: AsyncWrite + Unpin>(
    wr: &mut BufWriter<W>,
    first: Out,
    rx: &mut mpsc::Receiver<Out>,
    stats: &StreamStats,
) -> io::Result<()> {
    let mut next = Some(first);
    while let Some(out) = next.take() {
        let len = out.len();
        let r = match &out {
            Out::Datagram(port, data) => {
                wr.write_all(&frame::header(data.len(), *port)).await?;
                wr.write_all(data).await
            }
            Out::Own(data) => {
                wr.write_all(&frame::own_header(data.len())).await?;
                wr.write_all(data).await
            }
        };
        stats.queued.fetch_sub(len as u64, Ordering::Relaxed);
        r?;
        if matches!(out, Out::Datagram(..)) {
            stats.sent.fetch_add(len as u64, Ordering::Relaxed);
        }
        next = rx.try_recv().ok();
    }
    wr.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn datagrams_cross_a_stream_both_ways_in_order() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (to_a, mut at_a) = mpsc::unbounded_channel();
        let (to_b, mut at_b) = mpsc::unbounded_channel();
        let la = run(
            a,
            move |f| {
                let _ = to_a.send(f);
                std::future::ready(())
            },
            CancellationToken::new(),
        );
        let lb = run(
            b,
            move |f| {
                let _ = to_b.send(f);
                std::future::ready(())
            },
            CancellationToken::new(),
        );
        for i in 0..200u16 {
            assert!(la.send(i, &vec![i as u8; 1 + i as usize * 7]));
        }
        assert!(lb.send_own(b"own"));
        for i in 0..200u16 {
            assert_eq!(
                at_b.recv().await.unwrap(),
                Frame::Datagram {
                    port: i,
                    data: vec![i as u8; 1 + i as usize * 7]
                }
            );
        }
        assert_eq!(at_a.recv().await.unwrap(), Frame::Own(b"own".to_vec()));
        assert_eq!(la.stats().queued(), 0);
        // Closing one end ends both.
        la.close();
        tokio::time::timeout(Duration::from_secs(5), lb.closed())
            .await
            .expect("the other end sees the stream end");
        assert!(!lb.stats().alive());
        assert!(
            !lb.send(0, b"late"),
            "nothing goes onto a stream that ended"
        );
    }

    #[tokio::test]
    async fn a_full_queue_refuses_and_says_so() {
        // A peer that never reads: the queue fills, and then sending fails
        // rather than piling up.
        let (a, _b) = tokio::io::duplex(1024);
        let la = run(a, |_| std::future::ready(()), CancellationToken::new());
        // What the writer has taken into its buffer is out of the queue;
        // what is left is held to the queue's size.
        let tries = QUEUE + 2000;
        let accepted = (0..tries).filter(|_| la.send(0, &[1u8; 100])).count();
        assert!(accepted < tries, "some were refused");
        assert!(
            accepted <= QUEUE + BUFFER / 100 + 16,
            "{} accepted",
            accepted
        );
        assert!(
            !la.send(0, &vec![0u8; MAX_DATAGRAM + 1]),
            "too long for a frame"
        );
        assert!(!la.send(0, b""), "an empty datagram is no datagram");
    }
}
