//! End-to-end tests: real sender and receiver over loopback, optionally
//! through a UDP proxy that drops, duplicates and reorders datagrams.

use sharp256::crypto::{Identity, SharpId};
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
    /// SHARP ID senders must use.
    id: SharpId,
    identity: Identity,
    cancel: CancellationToken,
    events: mpsc::UnboundedReceiver<TransferEvent>,
    task: tokio::task::JoinHandle<()>,
}

async fn start_receiver(
    out: &Path,
    state: &Path,
    mut cfg_fn: impl FnMut(&mut ReceiverConfig),
) -> TestReceiver {
    init_test_logging();
    let mut cfg = ReceiverConfig::new("127.0.0.1:0".parse().unwrap(), out.to_path_buf());
    cfg.state_dir = Some(state.to_path_buf());
    cfg.transport = fast_transport();
    cfg.identity = Some(Identity::generate());
    let (tx, rx) = mpsc::unbounded_channel();
    cfg.events = Some(Arc::new(move |ev| {
        let _ = tx.send(ev);
    }));
    cfg_fn(&mut cfg);
    let identity = cfg.identity.clone().expect("identity");
    let receiver = Receiver::new(cfg).await.expect("receiver");
    let addr = receiver.local_addr().unwrap();
    let cancel = receiver.cancel_token();
    let task = tokio::spawn(async move {
        receiver.run().await.expect("receiver run");
    });
    TestReceiver {
        addr,
        id: identity.id(),
        identity,
        cancel,
        events: rx,
        task,
    }
}

async fn stop_receiver(r: TestReceiver) {
    r.cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(15), r.task).await;
}

/// Identity of the test senders (stable, so that resume works across runs).
fn sender_identity() -> Identity {
    static ID: std::sync::OnceLock<Identity> = std::sync::OnceLock::new();
    ID.get_or_init(Identity::generate).clone()
}

fn sender_cfg(file: &Path, peer: SocketAddr, receiver: SharpId, state: &Path) -> SenderConfig {
    let mut cfg = SenderConfig::new(peer, receiver, file.to_path_buf());
    cfg.bind = "127.0.0.1:0".parse().unwrap();
    cfg.state_dir = Some(state.to_path_buf());
    cfg.transport = fast_transport();
    cfg.identity = Some(sender_identity());
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
    /// Drop every datagram of this length.
    drop_len: Option<usize>,
    /// Drop the first `n` datagrams of this length.
    drop_first_len: Option<(usize, u32)>,
    /// Flip one random bit in this fraction of datagrams.
    corrupt: f64,
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
            drop_len: None,
            drop_first_len: None,
            corrupt: 0.0,
        }
    }
}

/// Packet types are masked on the wire (header protection), so the proxy can
/// only tell packets apart by size: full-sized ones towards the receiver are
/// DATA (or path probes).
fn is_data(pkt: &[u8]) -> bool {
    pkt.len() >= 1000
}

/// Sizes of some encrypted packets: 33 bytes of packet overhead plus the
/// frame body.
const FIN_DONE_LEN: usize = 33 + 1;
const FIN_ACK_LEN: usize = 33 + 1 + 32;

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
            if imp.drop_len == Some(pkt.len()) {
                continue;
            }
            if let Some((len, n)) = imp.drop_first_len {
                if pkt.len() == len && dropped_first < n {
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
            let mut pkt = pkt;
            if rng.f64() < imp.corrupt && !pkt.is_empty() {
                let bit = (rng.next() % (pkt.len() as u64 * 8)) as usize;
                pkt[bit / 8] ^= 1 << (bit % 8);
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
        let summary = run_sender(sender_cfg(&path, r.addr, r.id, &state))
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
            drop_len: None,
            drop_first_len: None,
            corrupt: 0.0,
        },
    )
    .await;
    let path = make_file(&src, "lossy.bin", 2 * 1024 * 1024 + 123, 9);
    let summary = run_sender(sender_cfg(&path, proxy.addr, r.id, &state))
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
            drop_len: None,
            drop_first_len: None,
            corrupt: 0.0,
        },
    )
    .await;
    let path = make_file(&src, "heavy.bin", 700_000, 3);
    let summary = tokio::time::timeout(
        Duration::from_secs(120),
        run_sender(sender_cfg(&path, proxy.addr, r.id, &state)),
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
    // The restarted receiver keeps its identity.
    let identity = r1.identity.clone();

    // Slow the sender down so that we can interrupt in the middle.
    let mut cfg = sender_cfg(&path, proxy.addr, r1.id, &state);
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
    let mut r2 = start_receiver(&out, &state, |c| c.identity = Some(identity.clone())).await;
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

    let mut cfg = sender_cfg(&path, r.addr, r.id, &state);
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

    let summary = run_sender(sender_cfg(&path, r.addr, r.id, &state))
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
    let mut cfg = sender_cfg(&path, r.addr, r.id, &state);
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

    let summary = run_sender(sender_cfg(&path, r.addr, r.id, &state))
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
            drop_len: Some(FIN_DONE_LEN),
            ..Impairment::none()
        },
    )
    .await;
    let summary = run_sender(sender_cfg(&path, proxy.addr, r.id, &state))
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
            drop_first_len: Some((FIN_ACK_LEN, 2)), // the first two FIN_ACKs
            ..Impairment::none()
        },
    )
    .await;
    run_sender(sender_cfg(&path, proxy.addr, r.id, &state))
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
        tasks.push(tokio::spawn(run_sender(sender_cfg(
            f, r.addr, r.id, &state,
        ))));
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
    let res = run_sender(sender_cfg(&path, r.addr, r.id, &state)).await;
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
        run_sender(sender_cfg(&path, r.addr, r.id, &state))
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
    let mut cfg = sender_cfg(&path, proxy.addr, r.id, &state);
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
    let mut cfg = sender_cfg(&path, proxy.addr, r.id, &state);
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

/// A hand-driven sender: performs a real handshake, then sends single frames.
struct FakeSender {
    sock: UdpSocket,
    to: SocketAddr,
    keys: sharp256::crypto::SessionKeys,
    peer_cid: u64,
    next_pn: u64,
}

fn fake_hello(tid: [u8; 16], name: &str) -> sharp256::protocol::wire::Hello {
    use sharp256::protocol::constants::*;
    sharp256::protocol::wire::Hello {
        transfer_id: tid,
        timestamp: 1,
        file_size: 10_000_000,
        file_mtime: 0,
        max_chunk: DEFAULT_CHUNK,
        capabilities: CAP_NONE,
        tree: None,
        file_name: name.into(),
    }
}

/// Builds an initiation for `receiver` and returns it with its attempt.
fn fake_initiation(
    receiver: SharpId,
    tid: [u8; 16],
    name: &str,
) -> (sharp256::crypto::handshake::Initiator, Vec<u8>) {
    fake_initiation_with(receiver, fake_hello(tid, name))
}

fn fake_initiation_with(
    receiver: SharpId,
    hello: sharp256::protocol::wire::Hello,
) -> (sharp256::crypto::handshake::Initiator, Vec<u8>) {
    use sharp256::crypto::handshake::{initiation_timestamp, Initiator};
    use sharp256::crypto::{Suite, NO_PSK};
    use sharp256::protocol::wire;
    let mut init = Initiator::new(&Identity::generate(), &receiver, &NO_PSK).unwrap();
    let payload = wire::encode_initiation(&wire::Initiation {
        timestamp: initiation_timestamp(),
        suites: Suite::ALL_BITS,
        hardware_aes: false,
        hello_flags: 0,
        hello,
    });
    let pkt = init.initiation(&payload, None).unwrap();
    (init, pkt)
}

impl FakeSender {
    async fn connect(r: &TestReceiver, tid: [u8; 16], name: &str) -> (Self, u8) {
        Self::connect_with(r, fake_hello(tid, name)).await
    }

    async fn connect_with(r: &TestReceiver, hello: sharp256::protocol::wire::Hello) -> (Self, u8) {
        use sharp256::crypto::{SessionKeys, Suite};
        use sharp256::protocol::wire;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (init, pkt) = fake_initiation_with(r.id, hello);
        sock.send_to(&pkt, r.addr).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("handshake response")
            .unwrap();
        let (peer_cid, payload, split) = init.read_response(&buf[..n]).expect("valid response");
        let resp = wire::decode_response(&payload).unwrap();
        let suite = Suite::from_u8(resp.suite).expect("suite");
        let s = Self {
            sock,
            to: r.addr,
            keys: SessionKeys::derive(&split, true, suite),
            peer_cid,
            next_pn: 0,
        };
        (s, resp.ack.status)
    }

    async fn send(&mut self, msg: &sharp256::protocol::wire::Message<'_>) {
        use sharp256::crypto::transport::begin_packet;
        use sharp256::protocol::wire;
        let mut buf = Vec::new();
        begin_packet(
            &mut buf,
            self.peer_cid,
            wire::type_byte(msg.msg_type(), 0),
            self.next_pn,
        );
        self.next_pn += 1;
        wire::encode_body(msg, &mut buf, usize::MAX);
        self.keys.send.seal(&mut buf).unwrap();
        self.sock.send_to(&buf, self.to).await.unwrap();
    }
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
    let (_sender, status) = FakeSender::connect(&r, [0x5a; 16], "ghost.bin").await;
    assert_eq!(status, sharp256::protocol::constants::HELLO_ACCEPTED);
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
    use sharp256::protocol::wire::{Abort, Message};
    let tmp = tempfile::tempdir().unwrap();
    let (out, state) = (tmp.path().join("out"), tmp.path().join("state"));
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let (mut sender, _) = FakeSender::connect(&r, [0x6b; 16], "early.bin").await;
    let part = out.join("early.bin.sharp-part");
    assert!(part.exists());
    sender
        .send(&Message::Abort(Abort {
            code: ABORT_CANCELLED,
            reason: "changed my mind".into(),
        }))
        .await;
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
    let mut cfg = sender_cfg(&path, r.addr, r.id, &state);
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
    let summary = run_sender(sender_cfg(&path, r.addr, r.id, &state))
        .await
        .expect("second attempt");
    assert!(summary.resumed_from > 0);
    let done = wait_completed(&mut r.events, Duration::from_secs(30)).await;
    if let TransferEvent::Completed { path: Some(p), .. } = done {
        assert_same(&path, Path::new(&p));
    }
    stop_receiver(r).await;
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

fn dirs(tmp: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf) {
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    std::fs::create_dir_all(&src).unwrap();
    (src, out, state)
}

/// A receiver with a list of allowed senders refuses everybody else, and
/// says so; listed senders get through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthorized_sender_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let friend = Identity::generate();
    let friend_id = friend.id();
    let mut r = start_receiver(&out, &state, |cfg| {
        cfg.allowed_senders = Some([friend_id].into_iter().collect());
    })
    .await;
    let path = make_file(&src, "private.bin", 50_000, 61);
    match run_sender(sender_cfg(&path, r.addr, r.id, &state)).await {
        Err(SendError::Rejected { reason, .. }) => {
            assert!(reason.contains("not authorized"), "{}", reason)
        }
        other => panic!("expected rejection, got {:?}", other.map(|_| ())),
    }
    assert!(!out.join("private.bin").exists());
    let mut cfg = sender_cfg(&path, r.addr, r.id, &state);
    cfg.identity = Some(friend);
    run_sender(cfg).await.expect("allowed sender");
    let ev = wait_completed(&mut r.events, Duration::from_secs(20)).await;
    if let TransferEvent::Completed { path: Some(p), .. } = ev {
        assert_same(&path, Path::new(&p));
    }
    stop_receiver(r).await;
}

/// Without the receiver's ID nothing gets an answer: not a sender with a
/// wrong ID, not random probes. The receiver does not even notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strangers_get_no_answer() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let path = make_file(&src, "x.bin", 1000, 62);
    let mut cfg = sender_cfg(&path, r.addr, Identity::generate().id(), &state);
    cfg.transport.handshake_timeout = Duration::from_secs(2);
    let res = run_sender(cfg).await;
    assert!(
        matches!(res, Err(SendError::HandshakeTimeout)),
        "got {:?}",
        res.map(|_| ())
    );
    // Probes of every size, including ones shaped like an initiation.
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut rng = Rng(63);
    for len in [0usize, 1, 8, 33, 64, 136, 200, 400, 1200, 1472] {
        let junk: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        sock.send_to(&junk, r.addr).await.unwrap();
    }
    let mut buf = [0u8; 2048];
    let answer = tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await;
    assert!(answer.is_err(), "the receiver answered a stranger");
    assert!(
        r.events.try_recv().is_err(),
        "the receiver reacted to a stranger"
    );
    stop_receiver(r).await;
}

/// Sender and receiver with different shared secrets never complete the
/// handshake, and the sender says why; matching secrets work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mismatched_secret_fails_cleanly() {
    use sharp256::crypto::psk_from_passphrase_with_cost;
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let identity = Identity::generate();
    let rid = identity.id();
    let psk = |s: &str| psk_from_passphrase_with_cost(s, &rid, 64, 1);
    let receiver_psk = psk("correct horse battery staple");
    let mut r = start_receiver(&out, &state, |cfg| {
        cfg.identity = Some(identity.clone());
        cfg.psk = Some(receiver_psk);
    })
    .await;
    let path = make_file(&src, "secret.bin", 100_000, 64);
    let mut cfg = sender_cfg(&path, r.addr, r.id, &state);
    cfg.psk = Some(psk("correct horse battery stapler"));
    cfg.transport.handshake_timeout = Duration::from_secs(3);
    match run_sender(cfg).await {
        Err(SendError::Handshake(msg)) => assert!(msg.contains("secret"), "{}", msg),
        other => panic!("expected a handshake failure, got {:?}", other.map(|_| ())),
    }
    let mut cfg = sender_cfg(&path, r.addr, r.id, &state);
    cfg.psk = Some(psk("correct horse battery staple"));
    run_sender(cfg).await.expect("same secret");
    let ev = wait_completed(&mut r.events, Duration::from_secs(20)).await;
    if let TransferEvent::Completed { path: Some(p), .. } = ev {
        assert_same(&path, Path::new(&p));
    }
    stop_receiver(r).await;
}

/// Flipped bits anywhere in any packet are caught by the AEAD tag; the
/// transfer repairs the damage by retransmission and stays byte-exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_packets_are_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let proxy = start_proxy(
        r.addr,
        Impairment {
            corrupt: 0.05,
            seed: 65,
            ..Impairment::none()
        },
    )
    .await;
    let path = make_file(&src, "tamper.bin", 2 * 1024 * 1024 + 5, 66);
    let summary = run_sender(sender_cfg(&path, proxy.addr, r.id, &state))
        .await
        .expect("send");
    assert!(
        summary.retransmitted_bytes > 0,
        "corrupted packets were resent"
    );
    let ev = wait_completed(&mut r.events, Duration::from_secs(30)).await;
    if let TransferEvent::Completed { path: Some(p), .. } = ev {
        assert_same(&path, Path::new(&p));
    }
    stop_receiver(r).await;
}

/// A receiver under load first makes senders prove their address with a
/// cookie; honest senders get through transparently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cookie_challenge_under_load() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let mut r = start_receiver(&out, &state, |cfg| {
        cfg.handshake_load_threshold = 0; // permanently "under load"
    })
    .await;
    let path = make_file(&src, "cookie.bin", 200_000, 67);
    run_sender(sender_cfg(&path, r.addr, r.id, &state))
        .await
        .expect("send through the cookie challenge");
    let ev = wait_completed(&mut r.events, Duration::from_secs(20)).await;
    if let TransferEvent::Completed { path: Some(p), .. } = ev {
        assert_same(&path, Path::new(&p));
    }
    // Without the cookie an initiation only earns a cookie reply.
    let (_init, pkt) = fake_initiation(r.id, [0x77; 16], "no-cookie.bin");
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&pkt, r.addr).await.unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .expect("cookie reply")
        .unwrap();
    assert_eq!(n, sharp256::crypto::handshake::COOKIE_REPLY_LEN);
    stop_receiver(r).await;
}

/// A recorded initiation replayed later is ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_initiation_is_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let (_src, out, state) = dirs(&tmp);
    let r = start_receiver(&out, &state, |_| {}).await;
    let (_init, pkt) = fake_initiation(r.id, [0x88; 16], "replay.bin");
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&pkt, r.addr).await.unwrap();
    let mut buf = [0u8; 2048];
    tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .expect("first initiation is answered")
        .unwrap();
    // The eavesdropper replays it, from the same and from another address.
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for s in [&sock, &other] {
        s.send_to(&pkt, r.addr).await.unwrap();
        let answer = tokio::time::timeout(Duration::from_millis(400), s.recv_from(&mut buf)).await;
        assert!(answer.is_err(), "a replayed initiation was answered");
    }
    stop_receiver(r).await;
}

/// Only the sender that started a partial file can continue it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_requires_the_same_sender() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 4 * 1024 * 1024;
    let path = make_file(&src, "mine.bin", size, 68);
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let owner = Identity::generate();

    // The owner starts and is interrupted.
    let mut cfg = sender_cfg(&path, r.addr, r.id, &state);
    cfg.identity = Some(owner.clone());
    cfg.transport.max_rate_bytes = Some(2_000_000);
    let sender = Sender::new(cfg).await.unwrap();
    let cancel = sender.cancel_token();
    let task = tokio::spawn(sender.run());
    tokio::time::sleep(Duration::from_millis(900)).await;
    cancel.cancel();
    assert!(matches!(task.await.unwrap(), Err(SendError::Cancelled)));
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Somebody else with the same file does not get the owner's progress
    // (it uses its own state directory, as another machine would).
    let other_state = tmp.path().join("other-state");
    let mut cfg = sender_cfg(&path, r.addr, r.id, &other_state);
    cfg.identity = Some(Identity::generate());
    let other = run_sender(cfg).await.expect("other sender");
    assert_eq!(
        other.resumed_from, 0,
        "another sender must start from scratch"
    );

    // The owner continues where it stopped.
    let mut cfg = sender_cfg(&path, r.addr, r.id, &state);
    cfg.identity = Some(owner);
    let again = run_sender(cfg).await.expect("owner resumes");
    assert!(again.resumed_from > 0, "the owner must resume");
    // Both transfers complete; the interrupted first attempt was only
    // suspended (a resumable failure).
    let mut completed = 0;
    let deadline = Instant::now() + Duration::from_secs(30);
    while completed < 2 {
        match tokio::time::timeout(deadline - Instant::now(), r.events.recv()).await {
            Ok(Some(TransferEvent::Completed { path: Some(p), .. })) => {
                assert_same(&path, Path::new(&p));
                completed += 1;
            }
            Ok(Some(TransferEvent::Failed {
                error,
                resumable: false,
                ..
            })) => panic!("receiver failed: {}", error),
            Ok(Some(_)) => {}
            _ => panic!("transfers did not complete"),
        }
    }
    stop_receiver(r).await;
}

/// While the receiver's user decides, the sender waits; the transfer starts
/// as soon as it is accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfer_waits_for_the_users_decision() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let mut r = start_receiver(&out, &state, |cfg| {
        cfg.accept = AcceptPolicy::Ask(Arc::new(|req, reply| {
            assert!(req.sender_id.to_string().starts_with("sh-"));
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                let _ = reply.send(true);
            });
        }));
    })
    .await;
    let path = make_file(&src, "later.bin", 300_000, 69);
    let started = Instant::now();
    run_sender(sender_cfg(&path, r.addr, r.id, &state))
        .await
        .expect("accepted after a while");
    assert!(started.elapsed() >= Duration::from_millis(1400));
    let ev = wait_completed(&mut r.events, Duration::from_secs(20)).await;
    if let TransferEvent::Completed { path: Some(p), .. } = ev {
        assert_same(&path, Path::new(&p));
    }
    stop_receiver(r).await;
}

// ---------------------------------------------------------------------------
// Directories
// ---------------------------------------------------------------------------

/// Builds a tree with nested and empty directories, empty, small and larger
/// files, a non-ASCII name and (on Unix) an executable and a symbolic link.
fn make_tree(dir: &Path, name: &str, seed: u64, big: usize, many: usize) -> PathBuf {
    let root = dir.join(name);
    std::fs::create_dir_all(root.join("empty-dir")).unwrap();
    std::fs::create_dir_all(root.join("a/b/c")).unwrap();
    make_file(&root, "top.bin", big, seed);
    make_file(&root.join("a"), "empty.txt", 0, seed + 1);
    make_file(&root.join("a/b"), "middle.bin", big / 3, seed + 2);
    make_file(&root.join("a/b/c"), "отчёт 2026.txt", 777, seed + 3);
    let dir_many = root.join("many");
    std::fs::create_dir_all(&dir_many).unwrap();
    for i in 0..many {
        make_file(
            &dir_many,
            &format!("f{:04}.dat", i),
            (i * 37) % 5000,
            seed + 10 + i as u64,
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let script = make_file(&root, "run.sh", 100, seed + 4);
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("top.bin", root.join("link-to-top")).unwrap();
    }
    root
}

/// Names in `dir` that a directory transfer carries (no symbolic links).
fn tree_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| !e.file_type().unwrap().is_symlink())
        .map(|e| e.file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// `b` holds the same tree as `a`: names, kinds, contents, modification
/// times and (on Unix) the owner's permission bits.
fn assert_same_tree(a: &Path, b: &Path) {
    assert_eq!(tree_names(a), tree_names(b), "entries of {}", b.display());
    for name in tree_names(a) {
        let (pa, pb) = (a.join(&name), b.join(&name));
        let (ma, mb) = (
            std::fs::symlink_metadata(&pa).unwrap(),
            std::fs::symlink_metadata(&pb).unwrap(),
        );
        assert_eq!(ma.is_dir(), mb.is_dir(), "kind of {}", pb.display());
        if ma.is_dir() {
            assert_same_tree(&pa, &pb);
        } else {
            assert_same(&pa, &pb);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                ma.permissions().mode() & 0o700,
                mb.permissions().mode() & 0o700,
                "mode of {}",
                pb.display()
            );
        }
    }
    assert_eq!(
        std::fs::metadata(a).unwrap().modified().unwrap(),
        std::fs::metadata(b).unwrap().modified().unwrap(),
        "modification time of {}",
        b.display()
    );
}

fn partial_leftovers(out: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(out)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().contains(".sharp-part"))
        .collect()
}

/// A tree with every kind of entry crosses a lossy, reordering link intact,
/// next to (never into) an existing directory of the same name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn directory_tree_arrives_intact() {
    init_test_logging();
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let root = make_tree(&src, "project", 100, 3 << 20, 300);
    std::fs::create_dir_all(out.join("project")).unwrap();
    std::fs::write(out.join("project/keep.txt"), b"mine").unwrap();

    let mut r = start_receiver(&out, &state, |_| {}).await;
    let proxy = start_proxy(
        r.addr,
        Impairment {
            drop: 0.02,
            dup: 0.01,
            reorder: 0.02,
            reorder_delay: Duration::from_millis(3),
            ..Impairment::none()
        },
    )
    .await;
    let summary = run_sender(sender_cfg(&root, proxy.addr, r.id, &state))
        .await
        .expect("send");
    let ev = wait_completed(&mut r.events, Duration::from_secs(30)).await;
    let TransferEvent::Completed {
        path: Some(p),
        peer_confirmed,
        file_hash_hex,
        ..
    } = ev
    else {
        panic!("unexpected event {:?}", ev)
    };
    assert!(peer_confirmed);
    assert_eq!(file_hash_hex, summary.file_hash_hex);
    assert_eq!(Path::new(&p), out.join("project (1)"));
    assert_same_tree(&root, Path::new(&p));
    assert!(
        !Path::new(&p).join("link-to-top").exists(),
        "links are not sent"
    );
    assert_eq!(
        std::fs::read(out.join("project/keep.txt")).unwrap(),
        b"mine"
    );
    assert!(partial_leftovers(&out).is_empty());
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
    stop_receiver(r).await;
}

/// Data that overtakes the directory listing (because the listing's first
/// packets were lost) is kept and written once the listing is complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn directory_data_overtaking_its_listing_is_kept() {
    init_test_logging();
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let root = make_tree(&src, "overtake", 200, 1 << 20, 200);
    let mut r = start_receiver(&out, &state, |_| {}).await;
    // Datagram 0 is the path probe; 1 and 2 carry the start of the listing.
    let proxy = start_proxy(
        r.addr,
        Impairment {
            drop: 1.0,
            data_loss_window: Some((1, 2)),
            ..Impairment::none()
        },
    )
    .await;
    let summary = run_sender(sender_cfg(&root, proxy.addr, r.id, &state))
        .await
        .expect("send");
    assert!(summary.retransmitted_bytes > 0, "the listing was resent");
    let ev = wait_completed(&mut r.events, Duration::from_secs(30)).await;
    if let TransferEvent::Completed { path: Some(p), .. } = ev {
        assert_same_tree(&root, Path::new(&p));
    }
    stop_receiver(r).await;
}

/// A receiver that crashes in the middle of a directory resumes it after a
/// restart from the saved listing and the files already on disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn directory_resumes_after_receiver_restart() {
    init_test_logging();
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let root = make_tree(&src, "photos", 300, 3 << 20, 50);
    let r1 = start_receiver(&out, &state, |_| {}).await;
    let proxy = start_proxy(r1.addr, Impairment::none()).await;
    let identity = r1.identity.clone();

    let mut cfg = sender_cfg(&root, proxy.addr, r1.id, &state);
    cfg.transport.max_rate_bytes = Some(2_000_000);
    let sender_task = tokio::spawn(run_sender(cfg));
    let deadline = Instant::now() + Duration::from_secs(20);
    while proxy.to_target_bytes.load(Ordering::Relaxed) < 2 << 20 {
        assert!(Instant::now() < deadline, "transfer did not progress");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    proxy.blackhole.store(true, Ordering::Relaxed);
    stop_receiver(r1).await;
    assert!(out.join("photos.sharp-part").is_dir(), "staging kept");
    let kept: Vec<_> = std::fs::read_dir(&state)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".manifest"))
        .collect();
    assert_eq!(kept.len(), 1, "listing kept for resume");

    tokio::time::sleep(Duration::from_millis(1500)).await;
    let mut r2 = start_receiver(&out, &state, |c| c.identity = Some(identity.clone())).await;
    *proxy.target.lock() = r2.addr;
    proxy.blackhole.store(false, Ordering::Relaxed);
    let summary = tokio::time::timeout(Duration::from_secs(90), sender_task)
        .await
        .expect("sender finished in time")
        .unwrap()
        .expect("send");
    let mut resumed_from = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    let path = loop {
        match tokio::time::timeout(deadline - Instant::now(), r2.events.recv()).await {
            Ok(Some(TransferEvent::Started {
                resumed_from: rf,
                directory,
                ..
            })) => {
                assert!(directory.is_some());
                resumed_from = Some(rf);
            }
            Ok(Some(TransferEvent::Completed { path: Some(p), .. })) => break p,
            Ok(Some(TransferEvent::Failed { error, .. })) => panic!("receiver failed: {}", error),
            Ok(Some(_)) => {}
            _ => panic!("no completion from restarted receiver"),
        }
    };
    assert!(resumed_from.expect("started") >= 1 << 20);
    let total = summary.file_size;
    assert!(
        summary.bytes_sent < total + total / 3,
        "resume must not resend everything (sent {} of {})",
        summary.bytes_sent,
        total
    );
    assert_eq!(Path::new(&path), out.join("photos"));
    assert_same_tree(&root, Path::new(&path));
    assert!(partial_leftovers(&out).is_empty());
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
    stop_receiver(r2).await;
}

/// A cancelled directory transfer continues where it stopped when the
/// sender tries again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn directory_resumes_after_sender_cancel() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let root = make_tree(&src, "docs", 400, 2 << 20, 20);
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let mut cfg = sender_cfg(&root, r.addr, r.id, &state);
    cfg.transport.max_rate_bytes = Some(1_500_000);
    let sender = Sender::new(cfg).await.unwrap();
    let cancel = sender.cancel_token();
    let task = tokio::spawn(sender.run());
    tokio::time::sleep(Duration::from_millis(900)).await;
    cancel.cancel();
    assert!(matches!(task.await.unwrap(), Err(SendError::Cancelled)));
    tokio::time::sleep(Duration::from_millis(500)).await;

    let summary = run_sender(sender_cfg(&root, r.addr, r.id, &state))
        .await
        .expect("second attempt");
    assert!(summary.resumed_from > 0, "second attempt must resume");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout(deadline - Instant::now(), r.events.recv()).await {
            Ok(Some(TransferEvent::Completed { path: Some(p), .. })) => {
                assert_same_tree(&root, Path::new(&p));
                break;
            }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_directory_is_transferred() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let root = src.join("nothing-here");
    std::fs::create_dir_all(&root).unwrap();
    let mut r = start_receiver(&out, &state, |_| {}).await;
    run_sender(sender_cfg(&root, r.addr, r.id, &state))
        .await
        .expect("send");
    let ev = wait_completed(&mut r.events, Duration::from_secs(20)).await;
    if let TransferEvent::Completed { path: Some(p), .. } = ev {
        assert_eq!(Path::new(&p), out.join("nothing-here"));
        assert_same_tree(&root, Path::new(&p));
    }
    stop_receiver(r).await;
}

/// Sends `listing` as a directory (with `data` after it) from a hand-driven
/// sender and returns the receiver's failure.
async fn send_listing(
    r: &mut TestReceiver,
    listing: &[u8],
    announced_hash: [u8; 32],
    data: &[u8],
) -> (String, bool) {
    use sharp256::protocol::wire::{Data, Message, TreeInfo};
    let hello = sharp256::protocol::wire::Hello {
        file_size: (listing.len() + data.len()) as u64,
        tree: Some(TreeInfo {
            manifest_len: listing.len() as u64,
            manifest_hash: announced_hash,
            files: 1,
            dirs: 0,
        }),
        ..fake_hello(rand::random(), "evil")
    };
    let (mut fake, status) = FakeSender::connect_with(r, hello).await;
    assert_eq!(status, sharp256::protocol::constants::HELLO_ACCEPTED);
    let mut stream = listing.to_vec();
    stream.extend_from_slice(data);
    fake.send(&Message::Data(Data {
        offset: 0,
        timestamp: 1,
        payload: &stream,
    }))
    .await;
    wait_failed(&mut r.events, Duration::from_secs(10)).await
}

/// A listing that tries to escape the output directory, or that does not
/// match the hash announced in HELLO, ends the transfer; nothing is
/// written anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostile_directory_listings_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (_src, out, state) = dirs(&tmp);
    let mut r = start_receiver(&out, &state, |_| {}).await;
    // version, reserved, root head (directory), one entry: a file named
    // "..", "/etc/x" or "a\0b" of five bytes.
    for name in [&b".."[..], b"/etc/x", b"a\0b", b"."] {
        let mut listing = vec![1u8, 0, 1, 1, 0, 0, name.len() as u8];
        listing.extend_from_slice(name);
        listing.push(5);
        let hash = *blake3::hash(&listing).as_bytes();
        let (error, resumable) = send_listing(&mut r, &listing, hash, b"owned").await;
        assert!(error.contains("invalid directory manifest"), "{}", error);
        assert!(!resumable);
    }
    // A well-formed listing that is not the announced one.
    let mut listing = vec![1u8, 0, 1, 1, 0, 0, 1, b'f', 5];
    let hash = *blake3::hash(&listing).as_bytes();
    listing[7] = b'g';
    let (error, _) = send_listing(&mut r, &listing, hash, b"12345").await;
    assert!(error.contains("announced hash"), "{}", error);

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        std::fs::read_dir(&out).unwrap().count(),
        0,
        "nothing may remain in the output directory"
    );
    let mut top: Vec<String> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    top.sort();
    assert_eq!(top, ["out", "src", "state"], "nothing written outside");
    stop_receiver(r).await;
}
