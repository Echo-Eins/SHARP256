//! End-to-end tests: real sender and receiver over loopback, optionally
//! through a UDP proxy that drops, duplicates and reorders datagrams.

use sharp256::{
    AcceptPolicy, Receiver, ReceiverConfig, SendError, Sender, SenderConfig, TransferEvent,
    TransferSummary, TransportConfig,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

fn make_file(dir: &Path, name: &str, size: usize, seed: u64) -> PathBuf {
    let mut rng = Rng(seed | 1);
    let mut data = vec![0u8; size];
    for chunk in data.chunks_mut(8) {
        let v = rng.next().to_le_bytes();
        let n = chunk.len();
        chunk.copy_from_slice(&v[..n]);
    }
    let path = dir.join(name);
    std::fs::write(&path, &data).unwrap();
    path
}

fn init_test_logging() {
    if let Ok(filter) = std::env::var("SHARP_TEST_LOG") {
        sharp256::init_logging(&filter);
    }
}

fn fast_transport() -> TransportConfig {
    TransportConfig {
        stall_timeout: Duration::from_millis(800),
        give_up_timeout: Duration::from_secs(90),
        handshake_timeout: Duration::from_secs(20),
        persist_interval: Duration::from_millis(200),
        progress_interval: Duration::from_millis(100),
        ..TransportConfig::default()
    }
}

struct TestReceiver {
    addr: SocketAddr,
    cancel: CancellationToken,
    events: mpsc::UnboundedReceiver<TransferEvent>,
    task: tokio::task::JoinHandle<()>,
}

async fn start_receiver(
    out: &Path,
    state: &Path,
    mut cfg_fn: impl FnMut(&mut ReceiverConfig),
) -> TestReceiver {
    let mut cfg = ReceiverConfig::new("127.0.0.1:0".parse().unwrap(), out.to_path_buf());
    cfg.state_dir = Some(state.to_path_buf());
    cfg.transport = fast_transport();
    let (tx, rx) = mpsc::unbounded_channel();
    cfg.events = Some(Arc::new(move |ev| {
        let _ = tx.send(ev);
    }));
    cfg_fn(&mut cfg);
    let receiver = Receiver::new(cfg).await.expect("receiver");
    let addr = receiver.local_addr().unwrap();
    let cancel = receiver.cancel_token();
    let task = tokio::spawn(async move {
        receiver.run().await.expect("receiver run");
    });
    TestReceiver {
        addr,
        cancel,
        events: rx,
        task,
    }
}

async fn stop_receiver(r: TestReceiver) {
    r.cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(15), r.task).await;
}

fn sender_cfg(file: &Path, peer: SocketAddr, state: &Path) -> SenderConfig {
    let mut cfg = SenderConfig::new(peer, file.to_path_buf());
    cfg.bind = "127.0.0.1:0".parse().unwrap();
    cfg.state_dir = Some(state.to_path_buf());
    cfg.transport = fast_transport();
    cfg
}

async fn run_sender(cfg: SenderConfig) -> Result<TransferSummary, SendError> {
    Sender::new(cfg).await?.run().await
}

async fn wait_completed(
    rx: &mut mpsc::UnboundedReceiver<TransferEvent>,
    timeout: Duration,
) -> TransferEvent {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        assert!(now < deadline, "receiver did not report completion in time");
        match tokio::time::timeout(deadline - now, rx.recv()).await {
            Ok(Some(ev @ TransferEvent::Completed { .. })) => return ev,
            Ok(Some(TransferEvent::Failed { error, .. })) => panic!("receiver failed: {}", error),
            Ok(Some(_)) => continue,
            Ok(None) => panic!("receiver event channel closed"),
            Err(_) => panic!("timeout waiting for receiver completion"),
        }
    }
}

fn assert_same(a: &Path, b: &Path) {
    let da = std::fs::read(a).unwrap();
    let db = std::fs::read(b).unwrap();
    assert_eq!(da.len(), db.len(), "size differs");
    assert!(da == db, "content differs");
}

// ---------------------------------------------------------------------------
// lossy proxy
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Impairment {
    drop: f64,
    dup: f64,
    reorder: f64,
    reorder_delay: Duration,
    seed: u64,
    /// When set, `drop` applies only to DATA datagrams whose index (counted
    /// from the first DATA datagram) lies in `[start, start + count)`.
    data_loss_window: Option<(u64, u64)>,
    /// Extra one-way delay for everything travelling back to the sender.
    reverse_delay: Duration,
    /// Drop every datagram of this message type.
    drop_type: Option<u8>,
    /// Drop the first `n` datagrams of this message type.
    drop_first: Option<(u8, u32)>,
}

impl Impairment {
    fn none() -> Self {
        Self {
            drop: 0.0,
            dup: 0.0,
            reorder: 0.0,
            reorder_delay: Duration::ZERO,
            seed: 1,
            data_loss_window: None,
            reverse_delay: Duration::ZERO,
            drop_type: None,
            drop_first: None,
        }
    }
}

/// Message type byte of a SHARP-256 datagram (see docs/PROTOCOL.md).
fn is_data(pkt: &[u8]) -> bool {
    pkt.len() > 3 && pkt[0..2] == *b"SH" && pkt[3] == 3
}

struct Proxy {
    addr: SocketAddr,
    target: Arc<parking_lot::Mutex<SocketAddr>>,
    blackhole: Arc<AtomicBool>,
    to_target_bytes: Arc<AtomicU64>,
    _task: tokio::task::JoinHandle<()>,
}

async fn start_proxy(target: SocketAddr, imp: Impairment) -> Proxy {
    let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = a.local_addr().unwrap();
    let target = Arc::new(parking_lot::Mutex::new(target));
    let blackhole = Arc::new(AtomicBool::new(false));
    let to_target_bytes = Arc::new(AtomicU64::new(0));

    let (t_target, t_black, t_bytes) = (target.clone(), blackhole.clone(), to_target_bytes.clone());
    let task = tokio::spawn(async move {
        let mut rng = Rng(imp.seed | 1);
        let mut client: Option<SocketAddr> = None;
        let mut data_index: u64 = 0;
        let mut dropped_first: u32 = 0;
        let mut buf_a = vec![0u8; 65536];
        let mut buf_b = vec![0u8; 65536];
        loop {
            let (pkt, to_target) = tokio::select! {
                r = a.recv_from(&mut buf_a) => {
                    let Ok((n, from)) = r else { continue };
                    client = Some(from);
                    (buf_a[..n].to_vec(), true)
                }
                r = b.recv_from(&mut buf_b) => {
                    let Ok((n, _)) = r else { continue };
                    (buf_b[..n].to_vec(), false)
                }
            };
            if t_black.load(Ordering::Relaxed) {
                continue;
            }
            if imp.drop_type.is_some_and(|t| pkt.len() > 3 && pkt[3] == t) {
                continue;
            }
            if let Some((t, n)) = imp.drop_first {
                if pkt.len() > 3 && pkt[3] == t && dropped_first < n {
                    dropped_first += 1;
                    continue;
                }
            }
            let drop_applies = match imp.data_loss_window {
                None => true,
                Some((start, count)) => {
                    if to_target && is_data(&pkt) {
                        data_index += 1;
                        (start..start + count).contains(&(data_index - 1))
                    } else {
                        false
                    }
                }
            };
            if drop_applies && rng.f64() < imp.drop {
                continue;
            }
            let copies = if rng.f64() < imp.dup { 2 } else { 1 };
            let mut delay = if rng.f64() < imp.reorder {
                Some(imp.reorder_delay)
            } else {
                None
            };
            if !to_target && imp.reverse_delay > Duration::ZERO {
                delay = Some(delay.unwrap_or(Duration::ZERO) + imp.reverse_delay);
            }
            for _ in 0..copies {
                let (sock, dest) = if to_target {
                    t_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    (b.clone(), *t_target.lock())
                } else {
                    match client {
                        Some(c) => (a.clone(), c),
                        None => continue,
                    }
                };
                let data = pkt.clone();
                match delay {
                    Some(d) => {
                        tokio::spawn(async move {
                            tokio::time::sleep(d).await;
                            let _ = sock.send_to(&data, dest).await;
                        });
                    }
                    None => {
                        let _ = sock.send_to(&data, dest).await;
                    }
                }
            }
        }
    });
    Proxy {
        addr,
        target,
        blackhole,
        to_target_bytes,
        _task: task,
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfers_of_many_sizes_are_byte_exact() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let mut r = start_receiver(&out, &state, |_| {}).await;

    for (i, size) in [0usize, 1, 1431, 1432, 1433, 100_000, 3 * 1024 * 1024 + 7]
        .into_iter()
        .enumerate()
    {
        let name = format!("f{}.bin", i);
        let path = make_file(&src, &name, size, 77 + i as u64);
        let summary = run_sender(sender_cfg(&path, r.addr, &state))
            .await
            .expect("send");
        assert_eq!(summary.file_size, size as u64);
        let ev = wait_completed(&mut r.events, Duration::from_secs(30)).await;
        if let TransferEvent::Completed {
            path: Some(p),
            peer_confirmed,
            file_hash_hex,
            ..
        } = ev
        {
            assert!(peer_confirmed, "receiver must get FIN_ACK");
            assert_eq!(file_hash_hex, summary.file_hash_hex);
            assert_eq!(PathBuf::from(&p), out.join(&name));
            assert_same(&path, Path::new(&p));
        } else {
            panic!("unexpected event");
        }
    }
    // Nothing left in the state directory.
    let leftover = std::fs::read_dir(&state).unwrap().count();
    assert_eq!(leftover, 0, "state files must be removed after success");
    stop_receiver(r).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn survives_loss_duplication_and_reordering() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let proxy = start_proxy(
        r.addr,
        Impairment {
            drop: 0.03,
            dup: 0.02,
            reorder: 0.05,
            reorder_delay: Duration::from_millis(3),
            seed: 42,
            data_loss_window: None,
            reverse_delay: Duration::ZERO,
            drop_type: None,
            drop_first: None,
        },
    )
    .await;
    let path = make_file(&src, "lossy.bin", 2 * 1024 * 1024 + 123, 9);
    let summary = run_sender(sender_cfg(&path, proxy.addr, &state))
        .await
        .expect("send");
    assert!(
        summary.retransmitted_bytes > 0,
        "loss must have caused retransmissions"
    );
    let ev = wait_completed(&mut r.events, Duration::from_secs(60)).await;
    if let TransferEvent::Completed {
        path: Some(p),
        peer_confirmed,
        ..
    } = ev
    {
        assert!(peer_confirmed);
        assert_same(&path, Path::new(&p));
    } else {
        panic!("unexpected event");
    }
    stop_receiver(r).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn survives_heavy_loss() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let proxy = start_proxy(
        r.addr,
        Impairment {
            drop: 0.15,
            dup: 0.0,
            reorder: 0.1,
            reorder_delay: Duration::from_millis(5),
            seed: 7,
            data_loss_window: None,
            reverse_delay: Duration::ZERO,
            drop_type: None,
            drop_first: None,
        },
    )
    .await;
    let path = make_file(&src, "heavy.bin", 700_000, 3);
    let summary = tokio::time::timeout(
        Duration::from_secs(120),
        run_sender(sender_cfg(&path, proxy.addr, &state)),
    )
    .await
    .expect("finished in time")
    .expect("send");
    assert!(summary.loss_events > 0);
    let ev = wait_completed(&mut r.events, Duration::from_secs(60)).await;
    if let TransferEvent::Completed { path: Some(p), .. } = ev {
        assert_same(&path, Path::new(&p));
    } else {
        panic!("unexpected event");
    }
    stop_receiver(r).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resumes_after_receiver_restart_during_outage() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let size = 6 * 1024 * 1024;
    let path = make_file(&src, "resume.bin", size, 5);

    let r1 = start_receiver(&out, &state, |_| {}).await;
    let proxy = start_proxy(r1.addr, Impairment::none()).await;

    // Slow the sender down so that we can interrupt in the middle.
    let mut cfg = sender_cfg(&path, proxy.addr, &state);
    cfg.transport.max_rate_bytes = Some(2_500_000); // 2.5 MB/s
    let sender_task = tokio::spawn(run_sender(cfg));

    // Wait until roughly a third has passed the proxy, then cut the link and
    // "crash" the receiver.
    let deadline = Instant::now() + Duration::from_secs(20);
    while proxy.to_target_bytes.load(Ordering::Relaxed) < (size / 3) as u64 {
        assert!(Instant::now() < deadline, "transfer did not progress");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    proxy.blackhole.store(true, Ordering::Relaxed);
    stop_receiver(r1).await;

    // The partial file and its state must exist.
    let part = out.join("resume.bin.sharp-part");
    assert!(part.exists(), "partial file kept for resume");
    assert!(
        std::fs::read_dir(&state).unwrap().count() >= 1,
        "state persisted"
    );

    // Keep the outage a bit longer than the sender's stall timeout, then
    // bring up a new receiver on a new port and reconnect the proxy.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let mut r2 = start_receiver(&out, &state, |_| {}).await;
    *proxy.target.lock() = r2.addr;
    proxy.blackhole.store(false, Ordering::Relaxed);

    let summary = tokio::time::timeout(Duration::from_secs(90), sender_task)
        .await
        .expect("sender finished in time")
        .unwrap()
        .expect("send");
    // Wait for the new receiver: it must report a resumed start and completion.
    let mut resumed_from = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout(deadline - Instant::now(), r2.events.recv()).await {
            Ok(Some(TransferEvent::Started {
                resumed_from: rf, ..
            })) => resumed_from = Some(rf),
            Ok(Some(TransferEvent::Completed {
                path: Some(p),
                peer_confirmed,
                ..
            })) => {
                assert!(peer_confirmed);
                assert_same(&path, Path::new(&p));
                break;
            }
            Ok(Some(TransferEvent::Failed { error, .. })) => panic!("receiver failed: {}", error),
            Ok(Some(_)) => {}
            _ => panic!("no completion from restarted receiver"),
        }
    }
    let resumed_from = resumed_from.expect("started event");
    assert!(
        resumed_from > 0,
        "second receiver must resume from saved state"
    );
    assert!(
        summary.bytes_sent < (size as u64) + (size as u64) / 2,
        "resume must not resend everything (sent {} of {})",
        summary.bytes_sent,
        size
    );
    assert!(!part.exists());
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
    stop_receiver(r2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resumes_after_sender_cancel_and_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let size = 4 * 1024 * 1024;
    let path = make_file(&src, "cancel.bin", size, 11);
    let mut r = start_receiver(&out, &state, |_| {}).await;

    let mut cfg = sender_cfg(&path, r.addr, &state);
    cfg.transport.max_rate_bytes = Some(2_000_000);
    let sender = Sender::new(cfg).await.unwrap();
    let cancel = sender.cancel_token();
    let task = tokio::spawn(sender.run());
    tokio::time::sleep(Duration::from_millis(900)).await;
    cancel.cancel();
    let res = task.await.unwrap();
    assert!(
        matches!(res, Err(SendError::Cancelled)),
        "got {:?}",
        res.map(|_| ())
    );

    // Let the receiver notice the abort and persist.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let summary = run_sender(sender_cfg(&path, r.addr, &state))
        .await
        .expect("second attempt");
    assert!(
        summary.resumed_from > 0,
        "second sender must resume (resumed_from = 0)"
    );
    assert!(summary.bytes_sent < size as u64);
    let mut done = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done {
        match tokio::time::timeout(deadline - Instant::now(), r.events.recv()).await {
            Ok(Some(TransferEvent::Completed { path: Some(p), .. })) => {
                assert_same(&path, Path::new(&p));
                done = true;
            }
            Ok(Some(_)) => {}
            _ => panic!("no completion"),
        }
    }
    stop_receiver(r).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changed_source_is_not_resumed_onto_stale_data() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let size = 4 * 1024 * 1024;
    let path = make_file(&src, "changed.bin", size, 21);
    let mut r = start_receiver(&out, &state, |_| {}).await;

    // Interrupt a first attempt so that both sides keep resume state.
    let mut cfg = sender_cfg(&path, r.addr, &state);
    cfg.transport.max_rate_bytes = Some(2_000_000);
    let sender = Sender::new(cfg).await.unwrap();
    let cancel = sender.cancel_token();
    let task = tokio::spawn(sender.run());
    tokio::time::sleep(Duration::from_millis(900)).await;
    cancel.cancel();
    assert!(matches!(task.await.unwrap(), Err(SendError::Cancelled)));
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The source is rewritten with the same size but other content.
    let path = make_file(&src, "changed.bin", size, 22);
    let f = std::fs::File::options().write(true).open(&path).unwrap();
    f.set_modified(std::time::SystemTime::now() + Duration::from_secs(120))
        .unwrap();
    drop(f);

    let summary = run_sender(sender_cfg(&path, r.addr, &state))
        .await
        .expect("a changed source must be sent afresh, not fail the hash check");
    assert_eq!(
        summary.resumed_from, 0,
        "stale partial data must not be reused"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout(deadline - Instant::now(), r.events.recv()).await {
            Ok(Some(TransferEvent::Completed { path: Some(p), .. })) => {
                assert_same(&path, Path::new(&p));
                break;
            }
            // The cancelled first attempt is reported as a resumable failure;
            // a hash mismatch would be a final one.
            Ok(Some(TransferEvent::Failed {
                error,
                resumable: false,
                ..
            })) => panic!("receiver failed: {}", error),
            Ok(Some(_)) => {}
            _ => panic!("no completion"),
        }
    }
    stop_receiver(r).await;
}

/// FIN_DONE only lets the sender skip its linger; if it is lost, the sender
/// lingers and both sides still report a confirmed transfer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_fin_done_falls_back_to_the_linger() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let path = make_file(&src, "close.bin", 300_000, 41);
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let proxy = start_proxy(
        r.addr,
        Impairment {
            drop_type: Some(12), // FIN_DONE
            ..Impairment::none()
        },
    )
    .await;
    let summary = run_sender(sender_cfg(&path, proxy.addr, &state))
        .await
        .expect("transfer");
    assert_eq!(summary.file_size, 300_000);
    let ev = wait_completed(&mut r.events, Duration::from_secs(20)).await;
    if let TransferEvent::Completed {
        path: Some(p),
        peer_confirmed,
        ..
    } = ev
    {
        assert!(peer_confirmed);
        assert_same(&path, Path::new(&p));
    } else {
        panic!("unexpected event");
    }
    stop_receiver(r).await;
}

/// Lost verdicts: the receiver repeats FIN (after 200 ms, then 400 ms more)
/// and the sender must still be there to answer, so both sides confirm.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_verdicts_are_answered_again() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let path = make_file(&src, "verdict.bin", 300_000, 43);
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let proxy = start_proxy(
        r.addr,
        Impairment {
            drop_first: Some((6, 2)), // the first two FIN_ACKs
            ..Impairment::none()
        },
    )
    .await;
    run_sender(sender_cfg(&path, proxy.addr, &state))
        .await
        .expect("transfer");
    let ev = wait_completed(&mut r.events, Duration::from_secs(20)).await;
    if let TransferEvent::Completed {
        path: Some(p),
        peer_confirmed,
        ..
    } = ev
    {
        assert!(peer_confirmed, "the third FIN_ACK must reach the receiver");
        assert_same(&path, Path::new(&p));
    } else {
        panic!("unexpected event");
    }
    stop_receiver(r).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_transfers_to_one_receiver() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let files: Vec<PathBuf> = (0..3)
        .map(|i| {
            make_file(
                &src,
                &format!("par{}.bin", i),
                1_500_000 + i * 333,
                100 + i as u64,
            )
        })
        .collect();
    let mut tasks = Vec::new();
    for f in &files {
        tasks.push(tokio::spawn(run_sender(sender_cfg(f, r.addr, &state))));
    }
    for t in tasks {
        t.await.unwrap().expect("send");
    }
    for _ in 0..3 {
        let ev = wait_completed(&mut r.events, Duration::from_secs(30)).await;
        if let TransferEvent::Completed {
            path: Some(p),
            file_name,
            ..
        } = ev
        {
            assert_same(&src.join(&file_name), Path::new(&p));
        }
    }
    stop_receiver(r).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declined_transfer_is_reported_to_sender() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let r = start_receiver(&out, &state, |cfg| {
        cfg.accept = AcceptPolicy::Ask(Arc::new(|_req, reply| {
            let _ = reply.send(false);
        }));
    })
    .await;
    let path = make_file(&src, "nope.bin", 10_000, 1);
    let res = run_sender(sender_cfg(&path, r.addr, &state)).await;
    match res {
        Err(SendError::Rejected { reason, .. }) => {
            assert!(reason.contains("declined"), "{}", reason)
        }
        other => panic!("expected rejection, got {:?}", other.map(|_| ())),
    }
    assert!(!out.join("nope.bin").exists());
    stop_receiver(r).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn existing_file_is_not_overwritten_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let path = make_file(&src, "dup.bin", 50_000, 2);
    for expected in ["dup.bin", "dup (1).bin"] {
        run_sender(sender_cfg(&path, r.addr, &state))
            .await
            .expect("send");
        let ev = wait_completed(&mut r.events, Duration::from_secs(30)).await;
        if let TransferEvent::Completed { path: Some(p), .. } = ev {
            assert_eq!(PathBuf::from(&p), out.join(expected));
            assert_same(&path, Path::new(&p));
        }
    }
    stop_receiver(r).await;
}

/// A burst loss that leaves far more holes than one ACK can list must not make
/// the sender treat unlisted holes as delivered (regression: this used to
/// stall until the receiver's session expired).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn burst_loss_with_hundreds_of_holes_recovers_quickly() {
    init_test_logging();
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let proxy = start_proxy(
        r.addr,
        Impairment {
            drop: 0.3,
            data_loss_window: Some((0, 1200)),
            // ACKs come back late, as behind a deep queue, so that hundreds
            // of holes exist before the sender hears about the first one.
            reverse_delay: Duration::from_millis(40),
            seed: 1234,
            ..Impairment::none()
        },
    )
    .await;
    let path = make_file(&src, "holes.bin", 3 * 1024 * 1024, 21);
    let mut cfg = sender_cfg(&path, proxy.addr, &state);
    cfg.transport.initial_cwnd_chunks = 1024; // one huge first flight
    let started = Instant::now();
    let summary = tokio::time::timeout(Duration::from_secs(30), run_sender(cfg))
        .await
        .expect("must not stall")
        .expect("send");
    assert!(
        summary.retransmitted_bytes > 64 * 1432,
        "the burst must have caused many retransmissions"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
    let ev = wait_completed(&mut r.events, Duration::from_secs(20)).await;
    if let TransferEvent::Completed {
        path: Some(p),
        peer_confirmed,
        ..
    } = ev
    {
        assert!(peer_confirmed);
        assert_same(&path, Path::new(&p));
    } else {
        panic!("unexpected event");
    }
    stop_receiver(r).await;
}

// ---------------------------------------------------------------------------
// Benchmarks (run with: cargo test --release --test e2e -- --ignored --nocapture)
// ---------------------------------------------------------------------------

async fn bench_profile(name: &str, size: usize, imp: Impairment, cap: Option<u64>) {
    // SHARP_BENCH=<substring> runs only the matching profiles.
    if let Ok(filter) = std::env::var("SHARP_BENCH") {
        if !name.contains(filter.as_str()) {
            return;
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let proxy = start_proxy(r.addr, imp).await;
    let path = make_file(&src, "bench.bin", size, 99);
    let mut cfg = sender_cfg(&path, proxy.addr, &state);
    cfg.transport.max_rate_bytes = cap;
    let started = Instant::now();
    let summary = tokio::time::timeout(Duration::from_secs(300), run_sender(cfg))
        .await
        .expect("bench timed out")
        .expect("send");
    let secs = started.elapsed().as_secs_f64();
    let ev = wait_completed(&mut r.events, Duration::from_secs(60)).await;
    if let TransferEvent::Completed { path: Some(p), .. } = ev {
        assert_same(&path, Path::new(&p));
    }
    println!(
        "BENCH {:<34} {:>7.1} Mbit/s  ({:.2} s, retx {:.1}%, loss events {}, rto {})",
        name,
        size as f64 * 8.0 / secs / 1e6,
        secs,
        summary.retransmitted_bytes as f64 * 100.0 / size as f64,
        summary.loss_events,
        summary.rto_events
    );
    stop_receiver(r).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_link_profiles() {
    init_test_logging();
    let mb = 1024 * 1024;
    let rtt = |ms| Impairment {
        reverse_delay: Duration::from_millis(ms),
        ..Impairment::none()
    };
    let lossy = |p: f64, ms| Impairment {
        drop: p,
        reverse_delay: Duration::from_millis(ms),
        seed: 5,
        ..Impairment::none()
    };
    bench_profile("clean, rtt 20 ms", 64 * mb, rtt(20), None).await;
    bench_profile("0.1% loss, rtt 100 ms", 32 * mb, lossy(0.001, 100), None).await;
    bench_profile("1% loss, rtt 20 ms", 32 * mb, lossy(0.01, 20), None).await;
    bench_profile("5% loss, rtt 20 ms", 16 * mb, lossy(0.05, 20), None).await;
    bench_profile(
        "1% loss, rtt 20 ms, cap 100 Mbit/s",
        16 * mb,
        lossy(0.01, 20),
        Some(12_500_000),
    )
    .await;
}

const FAKE_CONN: u32 = 77;

/// Performs a hand-made handshake for `name` and returns the socket of the
/// "sender" together with the key of the transfer.
async fn fake_handshake(
    receiver: SocketAddr,
    tid: [u8; 16],
    name: &str,
) -> (UdpSocket, sharp256::protocol::wire::TagKey) {
    use sharp256::protocol::constants::*;
    use sharp256::protocol::wire::{self, Header, Hello, Message, MsgType, TagKey};
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let key = TagKey::derive(&tid);
    let hello = Hello {
        transfer_id: tid,
        timestamp: 1,
        file_size: 10_000_000,
        file_mtime: 0,
        max_chunk: DEFAULT_CHUNK,
        capabilities: CAP_NONE,
        file_name: name.into(),
    };
    let bytes = wire::encode(
        &Header::new(MsgType::Hello, FAKE_CONN),
        &Message::Hello(hello),
        &key,
    );
    sock.send_to(&bytes, receiver).await.unwrap();
    let mut buf = vec![0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("HELLO_ACK")
        .unwrap();
    assert!(matches!(
        wire::decode(&buf[..n], &key).unwrap().1,
        Message::HelloAck(_)
    ));
    (sock, key)
}

/// Waits for the receiver's `Failed` event and returns (error, resumable).
async fn wait_failed(
    rx: &mut mpsc::UnboundedReceiver<TransferEvent>,
    timeout: Duration,
) -> (String, bool) {
    let deadline = Instant::now() + timeout;
    loop {
        match tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            rx.recv(),
        )
        .await
        {
            Ok(Some(TransferEvent::Failed {
                error, resumable, ..
            })) => return (error, resumable),
            Ok(Some(TransferEvent::Completed { .. })) => panic!("unexpected completion"),
            Ok(Some(_)) => {}
            _ => panic!("no failure reported within {:?}", timeout),
        }
    }
}

/// A HELLO that is never followed by data must not hold a session slot and an
/// empty partial file for long.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_session_after_handshake_is_dropped() {
    let tmp = tempfile::tempdir().unwrap();
    let (out, state) = (tmp.path().join("out"), tmp.path().join("state"));
    let mut r = start_receiver(&out, &state, |cfg| {
        cfg.transport.handshake_timeout = Duration::from_secs(2);
    })
    .await;
    // A "sender" that goes silent right after the handshake.
    let (_sock, _key) = fake_handshake(r.addr, [0x5a; 16], "ghost.bin").await;
    let part = out.join("ghost.bin.sharp-part");
    assert!(part.exists(), "partial file is created on accept");
    // After the (shortened) handshake timeout the session is gone.
    let (error, resumable) = wait_failed(&mut r.events, Duration::from_secs(10)).await;
    assert!(error.contains("no data"), "{}", error);
    assert!(!resumable);
    assert!(!part.exists(), "empty partial file removed");
    assert_eq!(
        std::fs::read_dir(&state).unwrap().count(),
        0,
        "no state left"
    );
    stop_receiver(r).await;
}

/// ABORT before any data releases the session at once, without waiting for
/// the idle timeout, and leaves nothing behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abort_before_data_releases_the_session_at_once() {
    use sharp256::protocol::constants::*;
    use sharp256::protocol::wire::{self, Abort, Header, Message, MsgType};
    let tmp = tempfile::tempdir().unwrap();
    let (out, state) = (tmp.path().join("out"), tmp.path().join("state"));
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let (sock, key) = fake_handshake(r.addr, [0x6b; 16], "early.bin").await;
    let part = out.join("early.bin.sharp-part");
    assert!(part.exists());
    let abort = wire::encode(
        &Header::new(MsgType::Abort, FAKE_CONN),
        &Message::Abort(Abort {
            code: ABORT_CANCELLED,
            reason: "changed my mind".into(),
        }),
        &key,
    );
    sock.send_to(&abort, r.addr).await.unwrap();
    let (error, resumable) = wait_failed(&mut r.events, Duration::from_secs(2)).await;
    assert!(error.contains("changed my mind"), "{}", error);
    assert!(!resumable);
    assert!(!part.exists(), "empty partial file removed");
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
    stop_receiver(r).await;
}

/// A sender that disappears without a word (crash, lost network) is reported
/// once the session times out, and the partial file stays resumable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vanished_sender_is_reported_and_resumable() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    let size = 4 * 1024 * 1024;
    let path = make_file(&src, "vanish.bin", size, 31);
    let mut r = start_receiver(&out, &state, |cfg| {
        cfg.transport.session_ttl = Duration::from_millis(1500);
    })
    .await;
    let mut cfg = sender_cfg(&path, r.addr, &state);
    cfg.transport.max_rate_bytes = Some(2_000_000);
    let task = tokio::spawn(run_sender(cfg));
    tokio::time::sleep(Duration::from_millis(900)).await;
    task.abort(); // no ABORT reaches the receiver
    let _ = task.await;
    let (error, resumable) = wait_failed(&mut r.events, Duration::from_secs(10)).await;
    assert!(resumable, "{}", error);
    assert!(error.contains("kept for resume"), "{}", error);
    assert!(out.join("vanish.bin.sharp-part").exists());

    // The next attempt continues where the first one stopped.
    let summary = run_sender(sender_cfg(&path, r.addr, &state))
        .await
        .expect("second attempt");
    assert!(summary.resumed_from > 0);
    let done = wait_completed(&mut r.events, Duration::from_secs(30)).await;
    if let TransferEvent::Completed { path: Some(p), .. } = done {
        assert_same(&path, Path::new(&p));
    }
    stop_receiver(r).await;
}
