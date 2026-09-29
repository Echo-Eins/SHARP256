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

/// Resume state files in `state`. The sender also keeps its newest
/// handshake timestamp there, which is not resume state and outlives every
/// transfer by design.
fn resume_files(state: &Path) -> usize {
    std::fs::read_dir(state)
        .unwrap()
        .filter(|e| e.as_ref().unwrap().file_name() != "initiation.stamp")
        .count()
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
    /// From this long after the proxy starts, silently drop every datagram
    /// longer than this: a path MTU that shrank, with no ICMP to say so.
    mtu_after: Option<(Duration, usize)>,
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
            mtu_after: None,
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
        let started = Instant::now();
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
            if let Some((after, len)) = imp.mtu_after {
                if pkt.len() > len && started.elapsed() >= after {
                    continue;
                }
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
    let leftover = resume_files(&state);
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
            mtu_after: None,
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
            mtu_after: None,
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
    assert!(resume_files(&state) >= 1, "state persisted");

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
    assert_eq!(resume_files(&state), 0);
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
    // The third FIN goes out 600 ms after the first, and the usual test stall
    // timeout of 800 ms leaves a busy CI runner (a Windows one, with a slow
    // file system) no room to hear the answer: it gives up on the sender and
    // reports the transfer unconfirmed. Nothing here needs it that short.
    let mut r = start_receiver(&out, &state, |c| {
        c.transport.stall_timeout = Duration::from_secs(3)
    })
    .await;
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
    use sharp256::crypto::{no_psk, Suite};
    use sharp256::protocol::wire;
    let mut init = Initiator::new(&Identity::generate(), &receiver, &no_psk()).unwrap();
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
        let (mut init, pkt) = fake_initiation_with(r.id, hello);
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

    /// Every ACK that arrives within `within`.
    async fn acks(&mut self, within: Duration) -> Vec<sharp256::protocol::wire::Ack> {
        use sharp256::protocol::wire::{self, Message};
        let mut out = Vec::new();
        let mut buf = vec![0u8; 65536];
        let deadline = Instant::now() + within;
        while let Ok(Ok((n, _))) = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            self.sock.recv_from(&mut buf),
        )
        .await
        {
            let Ok((type_byte, _, body)) = self.keys.recv.open(&mut buf[..n]) else {
                continue;
            };
            let Ok((t, _)) = wire::parse_type_byte(type_byte) else {
                continue;
            };
            if let Ok(Message::Ack(ack)) = wire::decode_body(t, body) {
                out.push(ack);
            }
        }
        out
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

/// A sender that scatters one-byte pieces across a file makes the receiver
/// keep one entry for each — to hold, to persist for resume and to walk on
/// every ACK. Past a fixed number of pieces, only data that joins what is
/// already there is taken, so the cost is bounded whatever the sender does,
/// and a transfer filling its holes in keeps going.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sender_cannot_shatter_the_receivers_bookkeeping() {
    use sharp256::protocol::wire::{Data, Message};
    // The receiver's limit on separate pieces per transfer.
    const CAP: u64 = 1 << 16;
    // Twice as many as it keeps apart, so that it reaches its limit even
    // where some are dropped on the way: on the macOS CI runner a quarter
    // of them were.
    const PIECES: u64 = 2 * CAP;

    let tmp = tempfile::tempdir().unwrap();
    let (_src, out, state) = dirs(&tmp);
    let r = start_receiver(&out, &state, |_| {}).await;
    let hello = sharp256::protocol::wire::Hello {
        file_size: 4 * PIECES,
        ..fake_hello(rand::random(), "shards.bin")
    };
    let (mut fake, status) = FakeSender::connect_with(&r, hello).await;
    assert_eq!(status, sharp256::protocol::constants::HELLO_ACCEPTED);
    // One byte at every other odd offset: no two pieces touch.
    let piece = |i: u64| Data {
        offset: 4 * i + 1,
        timestamp: 1,
        payload: b"x",
    };
    // What the receiver holds once it has dealt with `prompt`, asked
    // afresh: whatever it acknowledged earlier may be stale, and while a
    // flood comes in its last word can be lost in our own full socket
    // buffer. A marker follows the prompt — the first piece again, with a
    // timestamp of its own, which the receiver takes whatever its limits:
    // it holds that piece already (or, early on, is far from them) — and
    // the ACK that echoes it was sent after the prompt was dealt with,
    // since the receiver deals with datagrams in the order they arrive,
    // however long it takes over a flood. (The largest figure acknowledged
    // within half a second used to stand for this, and a receiver slower
    // than that, with the other tests running beside it, made it 0.)
    async fn now_held(fake: &mut FakeSender, prompt: Data<'_>, marker: u32) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            // Both again, until the marker's echo comes: a receiver still
            // busy with the flood may find no room for either. The prompt
            // changes nothing the second time.
            fake.send(&Message::Data(prompt.clone())).await;
            fake.send(&Message::Data(Data {
                offset: 1,
                timestamp: marker,
                payload: b"x",
            }))
            .await;
            let acks = fake.acks(Duration::from_millis(500)).await;
            if let Some(ack) = acks.iter().find(|a| a.echo_ts == marker) {
                return ack.received_bytes;
            }
        }
        panic!("the receiver never acknowledged the marker {}", marker);
    }

    // The two pieces that [2, 5) is going to join, made sure of first: at
    // the limit, data that joins nothing is refused, and one of these lost
    // on the way would make the last check fail for the wrong reason.
    let mut first = 0;
    for attempt in 0..20 {
        fake.send(&Message::Data(piece(0))).await;
        first = now_held(&mut fake, piece(1), 1000 + attempt).await;
        if first == 2 {
            break;
        }
    }
    assert_eq!(first, 2, "the first two pieces never arrived");

    for i in 2..PIECES {
        fake.send(&Message::Data(piece(i))).await;
        // Slowly enough that the receiver's queue drops few of them.
        if i % 256 == 255 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    // Let the flood and its acknowledgements drain.
    let _ = fake.acks(Duration::from_secs(1)).await;

    // The start of the file is taken, since nothing precedes it; it joins
    // the piece at 1, so the count of pieces stays where it was.
    let with_start = now_held(
        &mut fake,
        Data {
            offset: 0,
            timestamp: 1,
            payload: b"z",
        },
        2001,
    )
    .await;
    let held = with_start - 1;
    assert!(
        held <= CAP,
        "the receiver kept {} separate pieces; the cap is {}",
        held,
        CAP
    );
    // At the limit, a piece that joins nothing is refused: [4003, 4004)
    // is two bytes from the pieces at 4001 and 4005.
    let lone = now_held(
        &mut fake,
        Data {
            offset: 4003,
            timestamp: 1,
            payload: b"w",
        },
        2002,
    )
    .await;
    assert_eq!(
        lone, with_start,
        "the receiver took a piece joining nothing with {} held: it never reached its limit",
        held
    );
    // Data that joins pieces already there is still taken: [2, 5) touches
    // the pieces at 1 and 5, so it grows nothing and fills a hole.
    let joined = now_held(
        &mut fake,
        Data {
            offset: 2,
            timestamp: 1,
            payload: b"yyy",
        },
        2003,
    )
    .await;
    assert_eq!(
        joined,
        lone + 3,
        "data that joins existing pieces was refused"
    );
    stop_receiver(r).await;
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
    assert_eq!(resume_files(&state), 0, "no state left");
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
    assert_eq!(resume_files(&state), 0);
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
        cfg.psk = Some(receiver_psk.clone());
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
            mtu_after: None,
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
    assert_eq!(resume_files(&state), 0);
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
    assert_eq!(resume_files(&state), 0);
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

/// An encrypted PATH_CHALLENGE datagram: 33 bytes of packet overhead plus
/// the 8-byte token. Nothing else the receiver sends is this size.
const PATH_CHALLENGE_LEN: usize = 33 + 8;

/// An attacker on the path that repeats an authentic packet with a forged
/// source address must not be able to point the session anywhere it likes:
/// that would turn every transfer into a redirection weapon aimed at a third
/// party. The receiver may only *ask* the new address to prove itself with a
/// PATH_CHALLENGE; until that is answered, every byte keeps going to the
/// address the peer has already proven, and the transfer finishes normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_source_address_never_redirects_the_session() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 3 << 20;
    let file = make_file(&src, "redirect.bin", size, 0x51DE);
    let mut r = start_receiver(&out, &state, |_| {}).await;

    // The sender talks to `relay`, which forwards both ways; the receiver
    // knows the transfer at `relay_out`'s address. `forger` is the address
    // the attacker would like the transfer pointed at.
    let relay_in = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_out = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let forger = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_addr = relay_in.local_addr().unwrap();
    let target = r.addr;

    let attacker = forger.clone();
    let relay = tokio::spawn(async move {
        let mut client: Option<SocketAddr> = None;
        let mut from_sender = vec![0u8; 65536];
        let mut from_receiver = vec![0u8; 65536];
        let mut data_seen: u64 = 0;
        loop {
            tokio::select! {
                res = relay_in.recv_from(&mut from_sender) => {
                    let Ok((n, from)) = res else { continue };
                    client = Some(from);
                    let pkt = &from_sender[..n];
                    if is_data(pkt) {
                        data_seen += 1;
                        // Race the original: the copy leaves from the forged
                        // address first, so it is new to the replay window
                        // and the receiver has to decide what to believe.
                        if data_seen % 100 == 40 && data_seen < 800 {
                            let _ = attacker.send_to(pkt, target).await;
                        }
                    }
                    let _ = relay_out.send_to(pkt, target).await;
                }
                res = relay_out.recv_from(&mut from_receiver) => {
                    let Ok((n, _)) = res else { continue };
                    if let Some(c) = client {
                        let _ = relay_in.send_to(&from_receiver[..n], c).await;
                    }
                }
            }
        }
    });

    // Everything the receiver sends to the forged address.
    let seen: Arc<parking_lot::Mutex<Vec<usize>>> = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let collected = seen.clone();
    let listener = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, _)) = forger.recv_from(&mut buf).await {
            collected.lock().push(n);
        }
    });

    let summary = run_sender(sender_cfg(&file, relay_addr, r.id, &state))
        .await
        .expect("the transfer completes despite the forged packets");
    assert_eq!(summary.file_size, size as u64);
    wait_completed(&mut r.events, Duration::from_secs(30)).await;
    assert_same(&file, &out.join("redirect.bin"));

    relay.abort();
    listener.abort();
    let lens = seen.lock().clone();
    // The property under test: nothing but challenges ever left for an
    // address that never proved itself.
    for len in &lens {
        assert_eq!(
            *len, PATH_CHALLENGE_LEN,
            "the receiver sent session traffic ({} B) to an address that never proved itself; \
             it was redirected",
            len
        );
    }
    // And the attack really did reach the receiver, so the check above is
    // not vacuous.
    assert!(
        !lens.is_empty(),
        "the receiver never challenged the forged address, so this test proved nothing"
    );
    stop_receiver(r).await;
}

/// A name that resolves to several addresses — a stale record, a broken IPv6
/// path, or an answer someone forged — must not strand the transfer.
/// Handshake attempts rotate through every candidate, and completing one
/// takes the receiver's private key, so the impostor that answers with noise
/// gets nowhere while the real receiver is found.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_first_address_does_not_strand_the_transfer() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 512 << 10;
    let file = make_file(&src, "candidates.bin", size, 0xC0FE);
    let mut r = start_receiver(&out, &state, |_| {}).await;

    // Bound so the port stays taken, but nothing ever reads it: the classic
    // address that resolves and goes nowhere.
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();

    // Something that does answer, but is not the receiver.
    let impostor = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let impostor_addr = impostor.local_addr().unwrap();
    let liar = impostor.clone();
    let noise = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = liar.recv_from(&mut buf).await {
            let mut reply = buf[..n].to_vec();
            for b in reply.iter_mut() {
                *b ^= 0x5A;
            }
            let _ = liar.send_to(&reply, from).await;
        }
    });

    let mut cfg = sender_cfg(&file, dead_addr, r.id, &state);
    cfg.alternate_peers = vec![impostor_addr, r.addr];
    let summary = run_sender(cfg)
        .await
        .expect("the real receiver is found among the candidates");
    assert_eq!(summary.file_size, size as u64);
    wait_completed(&mut r.events, Duration::from_secs(30)).await;
    assert_same(&file, &out.join("candidates.bin"));

    noise.abort();
    drop(dead);
    stop_receiver(r).await;
}

/// Performs a handshake as `identity` and returns the receiver's answer,
/// which may be a rejection (and then carries no session keys). The socket
/// is returned so the caller can keep the session's path alive.
async fn handshake_as(
    r: &TestReceiver,
    identity: &Identity,
    tid: [u8; 16],
    name: &str,
) -> (UdpSocket, sharp256::protocol::wire::Response) {
    use sharp256::crypto::handshake::{initiation_timestamp, Initiator};
    use sharp256::crypto::{no_psk, Suite};
    use sharp256::protocol::wire;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut init = Initiator::new(identity, &r.id, &no_psk()).unwrap();
    let payload = wire::encode_initiation(&wire::Initiation {
        timestamp: initiation_timestamp(),
        suites: Suite::ALL_BITS,
        hardware_aes: false,
        hello_flags: 0,
        hello: fake_hello(tid, name),
    });
    let pkt = init.initiation(&payload, None).unwrap();
    sock.send_to(&pkt, r.addr).await.unwrap();
    let mut buf = vec![0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("the receiver answers the handshake")
        .unwrap();
    let (_, answer, _) = init.read_response(&buf[..n]).expect("a valid response");
    (sock, wire::decode_response(&answer).unwrap())
}

/// The session limit must be shared, not first-come-first-served. One
/// authenticated sender opening transfer after transfer would otherwise take
/// every slot and lock everybody else out — and being on the allow-list
/// would not make that any better.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_sender_cannot_take_every_session_slot() {
    use sharp256::protocol::constants::{HELLO_ACCEPTED, HELLO_REJECTED, REASON_BUSY};
    let tmp = tempfile::tempdir().unwrap();
    let (_src, out, state) = dirs(&tmp);
    let r = start_receiver(&out, &state, |cfg| {
        cfg.max_sessions = 6;
        cfg.max_sessions_per_sender = 2;
    })
    .await;

    let greedy = Identity::generate();
    let mut held = Vec::new();
    for i in 0..2u8 {
        let (sock, answer) = handshake_as(&r, &greedy, [i; 16], &format!("greedy{}.bin", i)).await;
        assert_eq!(answer.ack.status, HELLO_ACCEPTED, "slot {} refused", i);
        held.push(sock);
    }
    // Its share is spent, although four of the six slots are free.
    let (sock, answer) = handshake_as(&r, &greedy, [9; 16], "greedy9.bin").await;
    assert_eq!(answer.ack.status, HELLO_REJECTED);
    assert_eq!(answer.ack.reason, REASON_BUSY);
    held.push(sock);

    // Another sender is unaffected.
    let other = Identity::generate();
    let (sock, answer) = handshake_as(&r, &other, [7; 16], "other.bin").await;
    assert_eq!(
        answer.ack.status, HELLO_ACCEPTED,
        "a greedy sender locked out an unrelated one"
    );
    held.push(sock);

    drop(held);
    stop_receiver(r).await;
}

/// A relay that forwards both ways, delaying each direction on its own.
/// The delays let a test decide exactly which handshake answer arrives
/// first, which is what the rule about superseded attempts turns on.
async fn delayed_relay(
    target: SocketAddr,
    request_delay: Duration,
    response_delay: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let inbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let outbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = inbound.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let client: Arc<parking_lot::Mutex<Option<SocketAddr>>> =
            Arc::new(parking_lot::Mutex::new(None));
        let mut from_sender = vec![0u8; 65536];
        let mut from_receiver = vec![0u8; 65536];
        loop {
            tokio::select! {
                res = inbound.recv_from(&mut from_sender) => {
                    let Ok((n, from)) = res else { continue };
                    *client.lock() = Some(from);
                    let (pkt, out) = (from_sender[..n].to_vec(), outbound.clone());
                    tokio::spawn(async move {
                        if !request_delay.is_zero() {
                            tokio::time::sleep(request_delay).await;
                        }
                        let _ = out.send_to(&pkt, target).await;
                    });
                }
                res = outbound.recv_from(&mut from_receiver) => {
                    let Ok((n, _)) = res else { continue };
                    let Some(to) = *client.lock() else { continue };
                    let (pkt, back) = (from_receiver[..n].to_vec(), inbound.clone());
                    tokio::spawn(async move {
                        if !response_delay.is_zero() {
                            tokio::time::sleep(response_delay).await;
                        }
                        let _ = back.send_to(&pkt, to).await;
                    });
                }
            }
        }
    });
    (addr, task)
}

/// With several candidate addresses in flight, both ends have to agree on
/// which handshake won. The receiver's replay guard already decides it —
/// initiation timestamps must increase, so it keeps the newest it accepted.
/// The sender follows the same rule and adopts only its newest attempt.
///
/// Here the answer to the *first* attempt comes back after the second has
/// already gone out, and the second reaches the receiver later still.
/// Adopting the first answer would leave the two sides holding different
/// keys and connection ids: every packet the sender sent would be dropped
/// unrouted until the stall timer fired and a new handshake repaired it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_newest_handshake_wins_on_both_sides() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 400 << 10;
    let file = make_file(&src, "candidates2.bin", size, 0x7A11);
    let mut r = start_receiver(&out, &state, |_| {}).await;

    // First candidate: reaches the receiver at once, but its answers crawl.
    let (first, t1) = delayed_relay(r.addr, Duration::ZERO, Duration::from_millis(400)).await;
    // Second: its answers are quick, but requests take a long way round, so
    // it moves the receiver on well after the first answer has landed.
    let (second, t2) = delayed_relay(r.addr, Duration::from_millis(700), Duration::ZERO).await;

    let (tx, mut events) = mpsc::unbounded_channel();
    let mut cfg = sender_cfg(&file, first, r.id, &state);
    cfg.alternate_peers = vec![second];
    cfg.events = Some(Arc::new(move |ev| {
        let _ = tx.send(ev);
    }));
    // Whichever handshake wins, the session then runs over a path with a
    // round trip of 400 or 700 ms, and the usual test stall timeout of
    // 800 ms leaves a busy CI runner no room: a pause that is merely slow
    // reads as a stall. A session that is really lost stalls however long
    // the timeout — nothing gets through until a new handshake — so a
    // longer one still catches what this test is after.
    cfg.transport.stall_timeout = Duration::from_secs(3);

    let summary = run_sender(cfg).await.expect("the transfer completes");
    assert_eq!(summary.file_size, size as u64);
    wait_completed(&mut r.events, Duration::from_secs(30)).await;
    assert_same(&file, &out.join("candidates2.bin"));

    t1.abort();
    t2.abort();
    // Adopting the superseded answer would have left the sender talking to
    // connection ids the receiver had already retired, and the only way out
    // of that is the stall timer.
    let mut stalls = 0;
    while let Ok(ev) = events.try_recv() {
        if matches!(ev, TransferEvent::Stalled { .. }) {
            stalls += 1;
        }
    }
    assert_eq!(stalls, 0, "the sender lost the session and had to recover");
    stop_receiver(r).await;
}

#[cfg(feature = "nat-traversal")]
/// One mapping of a NAT that hands out a port per destination: it belongs
/// to one inside host and one outside address, and lets nothing else
/// through in either direction. The inside address is learned from whoever
/// first sends through it, exactly as a NAT learns it.
///
/// This is what leaves a receiver unreachable no matter what it publishes,
/// and the reason relays exist. The counter records datagrams turned away,
/// which is how a test can tell a direct attempt was made and refused.
async fn one_way_mapping(
    only_from: SocketAddr,
) -> (SocketAddr, Arc<AtomicU64>, tokio::task::JoinHandle<()>) {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let refused = Arc::new(AtomicU64::new(0));
    let counter = refused.clone();
    let task = tokio::spawn(async move {
        let mut inside: Option<SocketAddr> = None;
        let mut buf = vec![0u8; 65536];
        loop {
            // An error is not the end of the mapping: on Windows an ICMP
            // "port unreachable" for what it forwarded to a relay that is not
            // there yet comes back as a receive error, once.
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            };
            if from == only_from {
                // Inbound, and only from the address this mapping was
                // opened towards.
                if let Some(inside) = inside {
                    let _ = sock.send_to(&buf[..n], inside).await;
                }
                continue;
            }
            match inside {
                // Outbound from the host this mapping belongs to.
                Some(known) if known == from => {
                    let _ = sock.send_to(&buf[..n], only_from).await;
                }
                // Somebody else entirely: a stranger who learned the
                // address and tried it. This is the case that makes the
                // address worthless to publish.
                Some(_) => {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    inside = Some(from);
                    let _ = sock.send_to(&buf[..n], only_from).await;
                }
            }
        }
    });
    (addr, refused, task)
}

/// When neither end can be reached from the other — both behind NATs that
/// give out a different port for every destination, which nothing either
/// side can fix — a relay is what is left. It introduces the two and then
/// carries the transfer, without being trusted with any of it: the traffic
/// stays sealed end to end and the sender is still admitted on the strength
/// of its identity.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_carries_the_transfer_when_no_direct_path_works() {
    use sharp256::relay::server::{Config, Relay};

    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 512 << 10;
    let file = make_file(&src, "through-a-relay.bin", size, 0xBEEF);

    let cancel = CancellationToken::new();
    let relay = Relay::bind(
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            ..Config::default()
        },
        cancel.clone(),
    )
    .await
    .expect("the relay binds");
    let relay_addr = relay.local_addr().unwrap();
    let relay_id = relay.id();
    let relay_task = tokio::spawn(async move {
        let _ = relay.run().await;
    });

    // The receiver talks to the relay only through a mapping that lets
    // nothing else back in, so the address the relay sees it at is worth
    // nothing to anybody but the relay.
    let (receiver_mapping, refused, mapping_task) = one_way_mapping(relay_addr).await;
    let r = start_receiver(&out, &state, |cfg| {
        cfg.relays = vec![format!("{}@{}", relay_id, receiver_mapping)];
    })
    .await;
    // Let the registration, which travels through the mapping, complete.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The sender is given an address that leads nowhere, plus the relay.
    // Anything that reaches the receiver has to have come through it.
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let mut scfg = sender_cfg(&file, dead_addr, r.id, &state);
    scfg.relays = vec![relay_addr.to_string()];

    let summary = tokio::time::timeout(Duration::from_secs(60), run_sender(scfg))
        .await
        .expect("the relay path is found in time")
        .expect("the transfer completes through the relay");
    assert_eq!(summary.file_size, size as u64);
    assert_same(&file, &out.join("through-a-relay.bin"));

    // The relay told the sender where the receiver appeared to be, the
    // sender tried it, and the mapping turned it away — so what completed
    // the transfer was the relay carrying it, not a direct path.
    assert!(
        refused.load(Ordering::Relaxed) > 0,
        "the direct address was never tried, so this proved nothing"
    );

    mapping_task.abort();
    cancel.cancel();
    relay_task.abort();
    stop_receiver(r).await;
}

/// Two people starting at about the same time: the sender asks the relay for
/// a receiver that is not registered yet, and is put through when it is.
/// Giving up on the relay at the first "unknown" left a sender with nothing
/// but the receiver's address, which the receiver's NAT turns away until
/// the receiver has been introduced to it.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sender_that_starts_before_its_receiver_is_put_through_when_it_registers() {
    use sharp256::relay::server::{Config, Relay};

    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 256 << 10;
    let file = make_file(&src, "early-bird.bin", size, 0xEA51);

    let cancel = CancellationToken::new();
    let relay = Relay::bind(
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            ..Config::default()
        },
        cancel.clone(),
    )
    .await
    .expect("the relay binds");
    let relay_addr = relay.local_addr().unwrap();
    let relay_id = relay.id();
    let relay_task = tokio::spawn(async move {
        let _ = relay.run().await;
    });
    let (receiver_mapping, refused, mapping_task) = one_way_mapping(relay_addr).await;

    // The receiver's identity is known before it runs, as a published ID is.
    let receiver_identity = Identity::generate();
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let mut scfg = sender_cfg(&file, dead_addr, receiver_identity.id(), &state);
    scfg.relays = vec![relay_addr.to_string()];
    let sender = tokio::spawn(run_sender(scfg));

    // Long enough for the sender to have been told, at least once, that the
    // relay knows nobody by that ID.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        !sender.is_finished(),
        "the sender is still waiting for its receiver"
    );
    let r = start_receiver(&out, &state, |cfg| {
        cfg.identity = Some(receiver_identity.clone());
        cfg.relays = vec![format!("{}@{}", relay_id, receiver_mapping)];
    })
    .await;

    let summary = tokio::time::timeout(Duration::from_secs(60), sender)
        .await
        .expect("put through in time")
        .expect("the sender task ends")
        .expect("the transfer completes through the relay");
    assert_eq!(summary.file_size, size as u64);
    assert_same(&file, &out.join("early-bird.bin"));
    assert!(
        refused.load(Ordering::Relaxed) > 0,
        "the direct address was never tried, so this proved nothing"
    );

    mapping_task.abort();
    cancel.cancel();
    relay_task.abort();
    stop_receiver(r).await;
}

/// The relay is not up when the sender starts (it is restarting, or the
/// network is coming up): a relay that does not answer is asked again, and
/// used once it does — with the receiver reachable only through it.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_that_comes_up_after_the_sender_started_is_used_when_it_does() {
    use sharp256::relay::server::{Config, Relay};

    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 256 << 10;
    let file = make_file(&src, "late-relay.bin", size, 0x1A7E);

    // The relay's address and identity are settled before it runs.
    let relay_identity = Identity::generate();
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = probe.local_addr().unwrap();
    drop(probe);
    let (receiver_mapping, refused, mapping_task) = one_way_mapping(relay_addr).await;
    let r = start_receiver(&out, &state, |cfg| {
        cfg.relays = vec![format!("{}@{}", relay_identity.id(), receiver_mapping)];
    })
    .await;

    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let mut scfg = sender_cfg(&file, dead_addr, r.id, &state);
    scfg.relays = vec![relay_addr.to_string()];
    scfg.transport.handshake_timeout = Duration::from_secs(45);
    let sender = tokio::spawn(run_sender(scfg));

    // Long enough for the sender's first round of asks to have gone
    // unanswered (a round is a few seconds).
    tokio::time::sleep(Duration::from_millis(4500)).await;
    assert!(
        !sender.is_finished(),
        "the sender is still waiting for its relay"
    );
    let cancel = CancellationToken::new();
    let relay = Relay::bind(
        Config {
            bind: relay_addr,
            identity: relay_identity.clone(),
            ..Config::default()
        },
        cancel.clone(),
    )
    .await
    .expect("the relay binds");
    let relay_task = tokio::spawn(async move {
        let _ = relay.run().await;
    });

    let summary = tokio::time::timeout(Duration::from_secs(60), sender)
        .await
        .expect("put through in time")
        .expect("the sender task ends")
        .expect("the transfer completes through the relay");
    assert_eq!(summary.file_size, size as u64);
    assert_same(&file, &out.join("late-relay.bin"));
    assert!(
        refused.load(Ordering::Relaxed) > 0,
        "the direct address was never tried, so this proved nothing"
    );

    mapping_task.abort();
    cancel.cancel();
    relay_task.abort();
    stop_receiver(r).await;
}

/// A relay is a fallback, not a toll gate. Configuring one — even several
/// that do not answer at all — must not slow down a transfer whose direct
/// path works, because the introduction runs alongside the connectivity
/// checks instead of before them.
///
/// Asking the relays first, and waiting for each in turn, cost roughly two
/// and a quarter seconds per relay before a single packet went to the
/// receiver.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dead_relays_do_not_slow_down_a_direct_transfer() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let file = make_file(&src, "direct.bin", 256 << 10, 0xD1EC);
    let r = start_receiver(&out, &state, |_| {}).await;

    // Three addresses with nothing behind them.
    let mut dead = Vec::new();
    for _ in 0..3 {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        dead.push(s.local_addr().unwrap().to_string());
    }

    let mut cfg = sender_cfg(&file, r.addr, r.id, &state);
    cfg.relays = dead;
    let started = Instant::now();
    let summary = run_sender(cfg).await.expect("the direct path is used");
    let elapsed = started.elapsed();
    assert_eq!(summary.file_size, (256 << 10) as u64);
    assert_same(&file, &out.join("direct.bin"));
    assert!(
        elapsed < Duration::from_secs(2),
        "three unanswering relays cost {:?}; they should cost nothing",
        elapsed
    );
    stop_receiver(r).await;
}

/// A cookie reply is sealed under a key derived from the receiver's
/// *public* key, with the initiation's own mac1 as associated data — so
/// anybody who receives one initiation can mint a convincing one. This test
/// mints them holding nothing but the published ID.
///
/// Acting on one immediately, as the sender used to, meant a 64-byte
/// forgery bought a fresh Noise initiation: a few hundred bytes and a
/// static-static Diffie-Hellman, as fast as the forger cared to send. The
/// cookie is now kept for the next scheduled attempt, which is what
/// WireGuard does and for this reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_cookie_replies_cannot_spin_the_sender() {
    use sharp256::crypto::handshake::CookieJar;

    let tmp = tempfile::tempdir().unwrap();
    let (src, _out, state) = dirs(&tmp);
    let file = make_file(&src, "cookies.bin", 64 << 10, 0xC00C);

    // All the attacker has is the identity a receiver publishes.
    let victim = Identity::generate().id();
    let trap = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let trap_addr = trap.local_addr().unwrap();
    let initiations = Arc::new(AtomicU64::new(0));

    let counter = initiations.clone();
    let liar = trap.clone();
    let forger = tokio::spawn(async move {
        let mut jar = CookieJar::new(&victim);
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = liar.recv_from(&mut buf).await {
            counter.fetch_add(1, Ordering::Relaxed);
            if let Some(reply) = jar.reply(&buf[..n], from, Instant::now()) {
                let _ = liar.send_to(&reply, from).await;
            }
        }
    });

    let mut cfg = sender_cfg(&file, trap_addr, victim, &state);
    cfg.transport.handshake_timeout = Duration::from_secs(2);
    // Nobody can complete a handshake there, so this is expected to fail.
    let started = Instant::now();
    let err = run_sender(cfg).await.expect_err("nothing there can answer");
    let elapsed = started.elapsed();
    assert!(
        matches!(err, SendError::HandshakeTimeout | SendError::Handshake(_)),
        "unexpected: {}",
        err
    );
    forger.abort();

    // On its own schedule the sender makes a handful of attempts in two
    // seconds. Answering each forgery with a new one made it thousands.
    let sent = initiations.load(Ordering::Relaxed);
    assert!(
        sent <= 20,
        "{} initiations in {:?}: a forged cookie is still buying a handshake",
        sent,
        elapsed
    );
}

/// The relay introduces a receiver exactly once when a sender arrives. If
/// that datagram is lost the receiver never learns to bind its side, and
/// the transfer used to fail with nothing anywhere to show why — no error,
/// no retry, just a relay port nobody ever came to. The relay now repeats
/// the introduction until the side binds.
///
/// Here every introduction but the last is thrown away on the way in.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_introduction_is_repeated() {
    use sharp256::relay::server::{Config, Relay};
    use sharp256::relay::Message;

    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 256 << 10;
    let file = make_file(&src, "reintroduced.bin", size, 0x2E12);

    let cancel = CancellationToken::new();
    let relay = Relay::bind(
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            ..Config::default()
        },
        cancel.clone(),
    )
    .await
    .expect("the relay binds");
    let relay_addr = relay.local_addr().unwrap();
    let relay_id = relay.id();
    let relay_task = tokio::spawn(async move {
        let _ = relay.run().await;
    });

    // A mapping that also swallows the first few introductions.
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mapping = sock.local_addr().unwrap();
    let dropped = Arc::new(AtomicU64::new(0));
    let counter = dropped.clone();
    let mapping_task = tokio::spawn(async move {
        let mut inside: Option<SocketAddr> = None;
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            if from == relay_addr {
                let is_introduction =
                    matches!(Message::decode(&buf[..n]), Some(Message::Incoming { .. }));
                if is_introduction && counter.fetch_add(1, Ordering::Relaxed) < 3 {
                    continue;
                }
                if let Some(inside) = inside {
                    let _ = sock.send_to(&buf[..n], inside).await;
                }
                continue;
            }
            match inside {
                Some(known) if known == from => {
                    let _ = sock.send_to(&buf[..n], relay_addr).await;
                }
                Some(_) => {}
                None => {
                    inside = Some(from);
                    let _ = sock.send_to(&buf[..n], relay_addr).await;
                }
            }
        }
    });

    let r = start_receiver(&out, &state, |cfg| {
        cfg.relays = vec![format!("{}@{}", relay_id, mapping)];
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let mut scfg = sender_cfg(&file, dead_addr, r.id, &state);
    scfg.relays = vec![relay_addr.to_string()];

    let summary = tokio::time::timeout(Duration::from_secs(60), run_sender(scfg))
        .await
        .expect("the repeated introduction gets through in time")
        .expect("the transfer completes");
    assert_eq!(summary.file_size, size as u64);
    assert_same(&file, &out.join("reintroduced.bin"));
    assert!(
        dropped.load(Ordering::Relaxed) > 3,
        "no introduction was ever thrown away, so this proved nothing"
    );

    mapping_task.abort();
    cancel.cancel();
    relay_task.abort();
    stop_receiver(r).await;
}

/// With one address to try, the handshake used to keep re-sending every
/// quarter of a second for ever: a single address never counted as tried,
/// so it never backed off. On a path slower than that — intercontinental,
/// satellite, a loaded mobile link — every answer arrived after a newer
/// attempt had replaced the one it answered, only the newest may be
/// adopted, and the handshake timed out every time. Retries now wait at
/// least as long as an answer has shown the round trip to take.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_path_slower_than_the_retry_interval_still_completes_the_handshake() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let file = make_file(&src, "far-away.bin", 64 << 10, 0x51_0E);
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let proxy = start_proxy(
        r.addr,
        Impairment {
            reverse_delay: Duration::from_millis(400),
            ..Impairment::none()
        },
    )
    .await;
    let cfg = sender_cfg(&file, proxy.addr, r.id, &state);
    let summary = tokio::time::timeout(Duration::from_secs(40), run_sender(cfg))
        .await
        .expect("the transfer finishes")
        .expect("the handshake completes over a slow path");
    assert_eq!(summary.file_size, 64 << 10);
    wait_completed(&mut r.events, Duration::from_secs(10)).await;
    assert_same(&file, &out.join("far-away.bin"));
    stop_receiver(r).await;
}

/// The connection id a handshake answer is addressed to travels in the
/// clear, so anyone who sees an initiation can send something to it. The
/// sender used to use its attempt up on whatever arrived first, so one junk
/// datagram per attempt — no dropping, no keys, just being on the path —
/// stopped the handshake for good. Now only an authentic answer counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn junk_addressed_to_a_handshake_attempt_does_not_stop_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let file = make_file(&src, "junk.bin", 64 << 10, 0x7A_4C);
    let mut r = start_receiver(&out, &state, |_| {}).await;

    // A forwarder that, for every datagram from the sender, first sends the
    // sender a datagram of rubbish addressed to the same connection id —
    // which, for an initiation, is the attempt's own.
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let front_addr = front.local_addr().unwrap();
    let target = r.addr;
    let injected = Arc::new(AtomicU64::new(0));
    let count = injected.clone();
    let task = tokio::spawn(async move {
        let mut client = None;
        let mut up = vec![0u8; 65536];
        let mut down = vec![0u8; 65536];
        let mut rng = Rng(0x7A_4C);
        loop {
            tokio::select! {
                r = front.recv_from(&mut up) => {
                    let Ok((n, from)) = r else { continue };
                    client = Some(from);
                    if n >= 8 {
                        let mut junk = up[..8].to_vec();
                        junk.extend((0..142).map(|_| rng.next() as u8));
                        let _ = front.send_to(&junk, from).await;
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                    let _ = back.send_to(&up[..n], target).await;
                }
                r = back.recv_from(&mut down) => {
                    let Ok((n, _)) = r else { continue };
                    if let Some(c) = client {
                        let _ = front.send_to(&down[..n], c).await;
                    }
                }
            }
        }
    });

    let cfg = sender_cfg(&file, front_addr, r.id, &state);
    let summary = tokio::time::timeout(Duration::from_secs(30), run_sender(cfg))
        .await
        .expect("the transfer finishes")
        .expect("junk does not stop the handshake");
    assert_eq!(summary.file_size, 64 << 10);
    wait_completed(&mut r.events, Duration::from_secs(10)).await;
    assert_same(&file, &out.join("junk.bin"));
    assert!(injected.load(Ordering::Relaxed) > 0, "nothing was injected");
    task.abort();
    stop_receiver(r).await;
}

/// A receiver that asked its relay to keep its address to itself publishes
/// none either, and is written as its ID alone: the sender is given no
/// address at all, only the relay, and the transfer goes through it.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_can_be_reached_by_its_id_and_a_relay_alone() {
    use sharp256::relay::server::{Config, Relay};

    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 256 << 10;
    let file = make_file(&src, "hidden.bin", size, 0x41DE);

    let cancel = CancellationToken::new();
    let relay = Relay::bind(
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            ..Config::default()
        },
        cancel.clone(),
    )
    .await
    .expect("the relay binds");
    let relay_addr = relay.local_addr().unwrap();
    let relay_id = relay.id();
    let relay_task = tokio::spawn(async move {
        let _ = relay.run().await;
    });

    let mut r = start_receiver(&out, &state, |cfg| {
        cfg.relays = vec![format!("{}@{}", relay_id, relay_addr)];
        cfg.relay_private = true;
    })
    .await;
    // Registered, and said so.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            r.events.recv(),
        )
        .await
        {
            Ok(Some(TransferEvent::RelayRegistered { private, .. })) => {
                assert!(private);
                break;
            }
            Ok(Some(_)) => continue,
            _ => panic!("the receiver never registered with the relay"),
        }
    }

    // The address the sender is given: the ID, and nothing after it.
    let (id, hosts) = sharp256::address::parse_peer(&r.id.to_string()).unwrap();
    assert!(hosts.is_empty());
    let mut scfg = sender_cfg(&file, "0.0.0.0:0".parse().unwrap(), id, &state);
    scfg.relays = vec![relay_addr.to_string()];
    let summary = tokio::time::timeout(Duration::from_secs(60), run_sender(scfg))
        .await
        .expect("the transfer finishes in time")
        .expect("the transfer completes through the relay");
    assert_eq!(summary.file_size, size as u64);
    wait_completed(&mut r.events, Duration::from_secs(10)).await;
    assert_same(&file, &out.join("hidden.bin"));

    cancel.cancel();
    relay_task.abort();
    stop_receiver(r).await;
}

// ---------------------------------------------------------------------------
// Tests that change the network under a transfer. They run only inside a
// private network namespace (scripts/netns-tests.sh), where changing the
// loopback interface disturbs nothing else.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod netns {
    use std::ffi::CString;

    fn ioctl_ifreq(name: &str, request: libc::c_ulong, fill: impl FnOnce(&mut libc::ifreq)) {
        let name = CString::new(name).unwrap();
        // SAFETY: an ifreq is plain data; zeroed is a valid value for it,
        // and the name fits (interface names are short and NUL-terminated).
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        for (d, s) in req.ifr_name.iter_mut().zip(name.as_bytes_with_nul()) {
            *d = *s as libc::c_char;
        }
        fill(&mut req);
        // SAFETY: a datagram socket used only for interface ioctls, with a
        // fully initialised ifreq.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            assert!(fd >= 0, "socket");
            let rc = libc::ioctl(fd, request as _, &mut req);
            libc::close(fd);
            assert_eq!(rc, 0, "ioctl {:#x} on {}", request, name.to_str().unwrap());
        }
    }

    /// Whether the test runs inside the namespace `scripts/netns-tests.sh`
    /// makes.
    pub fn active() -> bool {
        std::env::var_os("SHARP_NETNS").is_some()
    }

    pub fn set_up(name: &str, up: bool) {
        let flags = if up {
            libc::IFF_UP | libc::IFF_RUNNING | libc::IFF_LOOPBACK
        } else {
            libc::IFF_LOOPBACK
        };
        ioctl_ifreq(name, libc::SIOCSIFFLAGS as _, |r| {
            r.ifr_ifru.ifru_flags = flags as libc::c_short;
        });
    }

    pub fn set_mtu(name: &str, mtu: i32) {
        ioctl_ifreq(name, libc::SIOCSIFMTU as _, |r| r.ifr_ifru.ifru_mtu = mtu);
    }

    pub fn set_addr(name: &str, ip: std::net::Ipv4Addr) {
        ioctl_ifreq(name, libc::SIOCSIFADDR as _, |r| {
            // SAFETY: sockaddr_in fits in the sockaddr of the union.
            let sin = unsafe {
                &mut *(&mut r.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in)
            };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_addr.s_addr = u32::from(ip).to_be();
        });
    }
}

/// The path MTU drops under a running transfer. The sockets take the path
/// MTU from nothing but acknowledged PROBEs, so what reports a drop here is
/// the interface refusing the size: that is one step down for everything
/// built at the old size, never one step per batch — which used to walk the
/// chunk to the floor on a single event, and then end the transfer.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "changes the network: run with scripts/netns-tests.sh"]
async fn netns_a_smaller_mtu_mid_transfer_only_costs_throughput() {
    assert!(netns::active(), "run with scripts/netns-tests.sh");
    netns::set_up("lo", true);
    netns::set_mtu("lo", 1500);
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 96 << 20;
    let file = make_file(&src, "mtu-drop.bin", size, 7);
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let mut cfg = sender_cfg(&file, r.addr, r.id, &state);
    cfg.transport.max_rate_bytes = Some(64 << 20);
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        netns::set_mtu("lo", 1400);
    });
    let summary = tokio::time::timeout(Duration::from_secs(120), run_sender(cfg))
        .await
        .expect("the transfer finishes")
        .expect("a smaller MTU does not end the transfer");
    assert_eq!(summary.file_size, size as u64);
    assert!(
        summary.chunk_size >= SAFE_CHUNK_FOR_TESTS,
        "one drop walked the chunk down to {}",
        summary.chunk_size
    );
    wait_completed(&mut r.events, Duration::from_secs(30)).await;
    assert_same(&file, &out.join("mtu-drop.bin"));
    stop_receiver(r).await;
}

/// The chunk every path carries (1232-byte datagrams); what a single MTU
/// drop to 1400 must leave the transfer at.
#[cfg(target_os = "linux")]
const SAFE_CHUNK_FOR_TESTS: u16 = sharp256::protocol::constants::SAFE_CHUNK;

/// The address the transfer runs over disappears for two and a half
/// seconds, as when Wi-Fi drops, and comes back. Sends fail meanwhile with
/// "network unreachable"; the transfer used to end on the first one and
/// delete its resume state. It now waits, as it would for any silence.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "changes the network: run with scripts/netns-tests.sh"]
async fn netns_a_brief_outage_does_not_end_the_transfer() {
    assert!(netns::active(), "run with scripts/netns-tests.sh");
    let ip: std::net::Ipv4Addr = "10.9.9.9".parse().unwrap();
    netns::set_up("lo", true);
    netns::set_mtu("lo", 65536);
    netns::set_addr("lo:1", ip);
    netns::set_up("lo:1", true);
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 48 << 20;
    let file = make_file(&src, "outage.bin", size, 8);
    let mut r = start_receiver(&out, &state, |cfg| {
        cfg.bind = "0.0.0.0:0".parse().unwrap();
    })
    .await;
    let peer: SocketAddr = format!("{}:{}", ip, r.addr.port()).parse().unwrap();
    let mut cfg = sender_cfg(&file, peer, r.id, &state);
    cfg.bind = "0.0.0.0:0".parse().unwrap();
    cfg.transport.max_rate_bytes = Some(8 << 20);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        netns::set_up("lo:1", false);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        netns::set_addr("lo:1", ip);
        netns::set_up("lo:1", true);
    });
    let summary = tokio::time::timeout(Duration::from_secs(120), run_sender(cfg))
        .await
        .expect("the transfer finishes")
        .expect("a brief outage does not end the transfer");
    assert_eq!(summary.file_size, size as u64);
    wait_completed(&mut r.events, Duration::from_secs(30)).await;
    assert_same(&file, &out.join("outage.bin"));
    stop_receiver(r).await;
}

/// The path MTU shrinks with nothing to say so: every datagram above 1300
/// bytes simply vanishes, as behind a tunnel whose ICMP is filtered — and
/// the sockets ignore ICMP anyway, so that a forged one cannot shrink a
/// transfer. What gives the drop away is full-size packets being lost while
/// the receiver's small ones keep arriving; the sender takes that as its
/// cue to step down, instead of retransmitting into the hole until it gives
/// up (RFC 8899, section 4.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_path_that_silently_stops_carrying_full_packets_is_stepped_down_from() {
    use sharp256::protocol::constants::SAFE_CHUNK;
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 8 << 20;
    let file = make_file(&src, "black-hole.bin", size, 0xB1AC);
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let proxy = start_proxy(
        r.addr,
        Impairment {
            mtu_after: Some((Duration::from_millis(300), 1300)),
            ..Impairment::none()
        },
    )
    .await;
    let mut cfg = sender_cfg(&file, proxy.addr, r.id, &state);
    cfg.transport.max_rate_bytes = Some(8 << 20);
    let summary = tokio::time::timeout(Duration::from_secs(60), run_sender(cfg))
        .await
        .expect("the transfer does not stall in the black hole")
        .expect("the transfer completes");
    assert_eq!(summary.file_size, size as u64);
    assert!(
        summary.chunk_size <= SAFE_CHUNK,
        "still sending {} byte chunks into a 1300-byte path",
        summary.chunk_size
    );
    wait_completed(&mut r.events, Duration::from_secs(20)).await;
    assert_same(&file, &out.join("black-hole.bin"));
    stop_receiver(r).await;
}

/// A NAT in front of the sender, `one_way` of delay each way, that gives
/// the sender a new outside port at `rebind_at` and drops the old mapping.
async fn rebinding_nat(
    target: SocketAddr,
    one_way: Duration,
    rebind_at: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let inside = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let before = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let after = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = inside.local_addr().unwrap();
    let started = Instant::now();
    let task = tokio::spawn(async move {
        let mut client = None;
        let (mut bi, mut bb, mut ba) = (vec![0u8; 65536], vec![0u8; 65536], vec![0u8; 65536]);
        let delayed = |sock: Arc<UdpSocket>, pkt: Vec<u8>, to: SocketAddr| {
            tokio::spawn(async move {
                tokio::time::sleep(one_way).await;
                let _ = sock.send_to(&pkt, to).await;
            });
        };
        loop {
            let rebound = started.elapsed() >= rebind_at;
            tokio::select! {
                r = inside.recv_from(&mut bi) => {
                    let Ok((n, from)) = r else { continue };
                    client = Some(from);
                    let out = if rebound { after.clone() } else { before.clone() };
                    delayed(out, bi[..n].to_vec(), target);
                }
                r = before.recv_from(&mut bb) => {
                    let Ok((n, _)) = r else { continue };
                    // The old mapping is gone once the NAT has rebound.
                    if let (false, Some(c)) = (rebound, client) {
                        delayed(inside.clone(), bb[..n].to_vec(), c);
                    }
                }
                r = after.recv_from(&mut ba) => {
                    let Ok((n, _)) = r else { continue };
                    if let Some(c) = client {
                        delayed(inside.clone(), ba[..n].to_vec(), c);
                    }
                }
            }
        }
    });
    (addr, task)
}

/// The sender's NAT gives it a new port in the middle of a transfer over a
/// path with a round trip of over a second. The receiver challenges the new
/// address before following it — but its challenges used to give up after
/// a second, and every new attempt drew a new token, so the answer, which
/// takes longer than that to come back, never matched anything: the
/// transfer went on sending its ACKs to the dead mapping for ever.
/// Challenges now back off with the round trip, and a slow answer to any
/// of them still counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rebinding_nat_is_followed_on_a_slow_path() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 1 << 20;
    let file = make_file(&src, "rebind.bin", size, 0x2EB1);
    let mut r = start_receiver(&out, &state, |_| {}).await;
    let (nat, task) =
        rebinding_nat(r.addr, Duration::from_millis(550), Duration::from_secs(3)).await;
    let mut cfg = sender_cfg(&file, nat, r.id, &state);
    // Long enough that the sender does not simply start over.
    cfg.transport.stall_timeout = Duration::from_secs(30);
    cfg.transport.probe_mtu = false;
    cfg.transport.max_rate_bytes = Some(128 << 10);
    let summary = tokio::time::timeout(Duration::from_secs(90), run_sender(cfg))
        .await
        .expect("the transfer follows the new mapping and finishes")
        .expect("the transfer completes");
    assert_eq!(summary.file_size, size as u64);
    wait_completed(&mut r.events, Duration::from_secs(20)).await;
    assert_same(&file, &out.join("rebind.bin"));
    task.abort();
    stop_receiver(r).await;
}

/// A receiver restarts in the middle of a transfer, and its new instance
/// asks its user whether to take it — who answers `decide`. Returns how many
/// times the user was asked, and how the sender finished.
async fn restart_into_a_decision(decide: bool) -> (u64, Result<TransferSummary, SendError>) {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let first = start_receiver(&out, &state, |_| {}).await;
    let identity = first.identity.clone();
    let proxy = start_proxy(first.addr, Impairment::none()).await;
    let file = make_file(&src, "restart.bin", 8 << 20, 0xDEC1);
    let mut cfg = sender_cfg(&file, proxy.addr, first.id, &state);
    cfg.transport.max_rate_bytes = Some(2 << 20);
    let sender = tokio::spawn(run_sender(cfg));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    stop_receiver(first).await;

    let asked = Arc::new(AtomicU64::new(0));
    let count = asked.clone();
    let second = start_receiver(&out, &state, move |cfg| {
        cfg.identity = Some(identity.clone());
        let count = count.clone();
        cfg.accept = AcceptPolicy::Ask(Arc::new(move |_req, reply| {
            count.fetch_add(1, Ordering::Relaxed);
            let _ = reply.send(decide);
        }));
    })
    .await;
    *proxy.target.lock() = second.addr;
    let result = tokio::time::timeout(Duration::from_secs(40), sender)
        .await
        .expect("the sender finishes")
        .unwrap();
    stop_receiver(second).await;
    (asked.load(Ordering::Relaxed), result)
}

/// The receiver restarted and its user declined: the sender used to ignore
/// the refusal, keep re-handshaking into a session that took nothing, and
/// have the user asked again every few seconds for as long as it ran. Now
/// the user is asked once, and the sender stops with their answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_receiver_that_declines_is_asked_once_and_heard() {
    let (asked, result) = restart_into_a_decision(false).await;
    assert!(
        matches!(result, Err(SendError::Rejected { .. })),
        "the refusal was not heard: {:?}",
        result.map(|s| s.file_size)
    );
    assert_eq!(asked, 1, "the user was asked {} times", asked);
}

/// And when the user accepts, the transfer carries on from where the
/// restarted receiver's state says it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_receiver_that_accepts_carries_on() {
    let (asked, result) = restart_into_a_decision(true).await;
    let summary = result.expect("the transfer completes after the user accepts");
    assert_eq!(summary.file_size, 8 << 20);
    assert_eq!(asked, 1, "the user was asked {} times", asked);
}

/// The receive window a session offers after taking a little data.
async fn rwnd_of(fake: &mut FakeSender) -> u64 {
    use sharp256::protocol::wire::{Data, Message};
    fake.send(&Message::Data(Data {
        offset: 0,
        timestamp: 1,
        payload: &[7u8; 1000],
    }))
    .await;
    fake.acks(Duration::from_millis(400))
        .await
        .last()
        .map(|a| a.rwnd)
        .expect("an ACK")
}

/// Memory for data not yet on disk is shared by all transfers together.
/// With a small budget, a transfer is offered no more than its share — and
/// less once another transfer starts receiving beside it — however much
/// its own writer could take.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfers_share_one_memory_budget() {
    let tmp = tempfile::tempdir().unwrap();
    let (_src, out, state) = dirs(&tmp);
    let budget: u64 = 8 << 20;
    let r = start_receiver(&out, &state, move |cfg| {
        cfg.memory_budget = budget;
    })
    .await;
    let share = budget / 4 * 3;

    let (mut first, status) = FakeSender::connect(&r, rand::random(), "first.bin").await;
    assert_eq!(status, sharp256::protocol::constants::HELLO_ACCEPTED);
    let alone = rwnd_of(&mut first).await;
    assert!(
        alone <= share,
        "offered {} with a share of {}",
        alone,
        share
    );
    let (mut second, status) = FakeSender::connect(&r, rand::random(), "second.bin").await;
    assert_eq!(status, sharp256::protocol::constants::HELLO_ACCEPTED);
    let _ = rwnd_of(&mut second).await;
    let shared = rwnd_of(&mut first).await;
    assert!(
        shared <= share / 2,
        "offered {} with two transfers sharing {}",
        shared,
        share
    );
    stop_receiver(r).await;
}

// ----- IPv6 ----------------------------------------------------------------

/// Whether this host can do IPv6 at all. Where it cannot — some containers
/// boot with IPv6 switched off in the kernel — the IPv6 tests have nothing
/// to run on and say so. With `SHARP_REQUIRE_IPV6` set, as CI sets it, that
/// is a failure instead of a skip: a runner that lost IPv6 must not make
/// these tests pass by not running them.
fn ipv6_or_skip(test: &str) -> bool {
    let ok = std::net::UdpSocket::bind("[::1]:0").is_ok();
    if !ok {
        assert!(
            std::env::var_os("SHARP_REQUIRE_IPV6").is_none(),
            "{}: this host has no IPv6, and SHARP_REQUIRE_IPV6 is set",
            test
        );
        eprintln!("{}: SKIPPED, this host has no IPv6", test);
    }
    ok
}

/// A transfer over IPv6 from end to end, in packets sized for IPv6: its
/// header is 20 bytes longer than IPv4's, so the default chunk — which
/// fills a 1500-byte MTU over IPv4 — would not fit one over IPv6.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_runs_over_ipv6_in_packets_sized_for_it() {
    use sharp256::protocol::constants::DEFAULT_CHUNK_V6;
    if !ipv6_or_skip("a_transfer_runs_over_ipv6_in_packets_sized_for_it") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 4 << 20;
    let file = make_file(&src, "over-ipv6.bin", size, 0x6666);
    let mut r = start_receiver(&out, &state, |cfg| {
        cfg.bind = "[::1]:0".parse().unwrap();
    })
    .await;
    assert!(r.addr.is_ipv6(), "{}", r.addr);
    let mut cfg = sender_cfg(&file, r.addr, r.id, &state);
    cfg.bind = "[::1]:0".parse().unwrap();
    let summary = tokio::time::timeout(Duration::from_secs(60), run_sender(cfg))
        .await
        .expect("finishes in time")
        .expect("completes");
    assert_eq!(summary.file_size, size as u64);
    assert_eq!(summary.chunk_size, DEFAULT_CHUNK_V6);
    wait_completed(&mut r.events, Duration::from_secs(20)).await;
    assert_same(&file, &out.join("over-ipv6.bin"));
    stop_receiver(r).await;
}

/// One dual-stack receiver serves an IPv4 sender and an IPv6 sender at the
/// same time: IPv4 peers reach its socket under their mapped addresses, and
/// everything that compares or screens addresses sees them for what they
/// are.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_dual_stack_receiver_serves_both_families_at_once() {
    if !ipv6_or_skip("one_dual_stack_receiver_serves_both_families_at_once") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 2 << 20;
    let a = make_file(&src, "from-ipv4.bin", size, 0x44);
    let b = make_file(&src, "from-ipv6.bin", size, 0x66);
    let mut r = start_receiver(&out, &state, |cfg| {
        cfg.bind = "[::]:0".parse().unwrap();
    })
    .await;
    assert!(r.addr.is_ipv6(), "not dual-stack: {}", r.addr);
    let port = r.addr.port();
    let mut via4 = sender_cfg(
        &a,
        format!("127.0.0.1:{}", port).parse().unwrap(),
        r.id,
        &state,
    );
    via4.bind = "127.0.0.1:0".parse().unwrap();
    let mut via6 = sender_cfg(&b, format!("[::1]:{}", port).parse().unwrap(), r.id, &state);
    via6.bind = "[::1]:0".parse().unwrap();
    let (x, y) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(60), run_sender(via4)),
        tokio::time::timeout(Duration::from_secs(60), run_sender(via6)),
    );
    x.expect("IPv4 in time").expect("IPv4 completes");
    y.expect("IPv6 in time").expect("IPv6 completes");
    wait_completed(&mut r.events, Duration::from_secs(20)).await;
    wait_completed(&mut r.events, Duration::from_secs(20)).await;
    assert_same(&a, &out.join("from-ipv4.bin"));
    assert_same(&b, &out.join("from-ipv6.bin"));
    stop_receiver(r).await;
}

/// A relay carries a pair across the families: the sender reaches it over
/// IPv6, the receiver over IPv4, and the relay's dual-stack ports put the
/// two together.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_carries_a_pair_across_address_families() {
    use sharp256::relay::server::{Config, Relay};
    if !ipv6_or_skip("a_relay_carries_a_pair_across_address_families") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 512 << 10;
    let file = make_file(&src, "across-families.bin", size, 0x46);
    let cancel = CancellationToken::new();
    let relay = Relay::bind(
        Config {
            bind: "[::]:0".parse().unwrap(),
            ..Config::default()
        },
        cancel.clone(),
    )
    .await
    .expect("the relay binds");
    let port = relay.local_addr().unwrap().port();
    let relay_id = relay.id();
    let relay_task = tokio::spawn(async move {
        let _ = relay.run().await;
    });
    // The receiver is on IPv4 only and registers over IPv4.
    let r = start_receiver(&out, &state, |cfg| {
        cfg.relays = vec![format!("{}@127.0.0.1:{}", relay_id, port)];
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The sender is on IPv6 only: the receiver's own (IPv4) address is of
    // no use to it, and the relay's IPv6 address is all it has.
    let dead = std::net::UdpSocket::bind("[::1]:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let mut scfg = sender_cfg(&file, dead_addr, r.id, &state);
    scfg.bind = "[::1]:0".parse().unwrap();
    scfg.relays = vec![format!("[::1]:{}", port)];
    let summary = tokio::time::timeout(Duration::from_secs(60), run_sender(scfg))
        .await
        .expect("the relay path is found in time")
        .expect("the transfer completes through the relay");
    assert_eq!(summary.file_size, size as u64);
    assert_same(&file, &out.join("across-families.bin"));
    cancel.cancel();
    relay_task.abort();
    stop_receiver(r).await;
}

/// A receiver given by name: the sender resolves it while the handshake is
/// already running, both families at once (RFC 8305), and gets through on
/// whichever the host has. Runs on any host: `[::]` falls back to IPv4
/// where there is no IPv6, and the name resolves to what there is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_given_by_name_is_found_while_the_handshake_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 1 << 20;
    let file = make_file(&src, "by-name.bin", size, 0x4e);
    let mut r = start_receiver(&out, &state, |cfg| {
        cfg.bind = "[::]:0".parse().unwrap();
    })
    .await;
    let hosts = vec![format!("localhost:{}", r.addr.port())];
    let mut cfg = SenderConfig::for_hosts(&hosts, r.id, file.clone());
    cfg.state_dir = Some(state.clone());
    cfg.transport = fast_transport();
    cfg.identity = Some(sender_identity());
    assert!(cfg.alternate_peers.is_empty());
    assert_eq!(cfg.peer_names, hosts);
    let summary = tokio::time::timeout(Duration::from_secs(60), run_sender(cfg))
        .await
        .expect("finishes in time")
        .expect("completes");
    assert_eq!(summary.file_size, size as u64);
    wait_completed(&mut r.events, Duration::from_secs(20)).await;
    assert_same(&file, &out.join("by-name.bin"));
    stop_receiver(r).await;
}

/// A name that resolves to nothing, and nothing else to try: the sender
/// says so at once, with the name server's answer, instead of waiting out
/// the whole handshake timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_that_does_not_resolve_fails_fast_and_says_why() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, _out, state) = dirs(&tmp);
    let file = make_file(&src, "nowhere.bin", 1024, 1);
    let hosts = vec!["no-such-receiver.invalid:5555".to_string()];
    let mut cfg = SenderConfig::for_hosts(&hosts, Identity::generate().id(), file);
    cfg.state_dir = Some(state.clone());
    cfg.transport = fast_transport();
    cfg.transport.handshake_timeout = Duration::from_secs(60);
    cfg.identity = Some(sender_identity());
    let started = Instant::now();
    let err = tokio::time::timeout(Duration::from_secs(30), run_sender(cfg))
        .await
        .expect("fails well before the handshake timeout")
        .expect_err("nothing to reach");
    assert!(
        matches!(&err, SendError::Unreachable(why) if why.contains("no-such-receiver.invalid")),
        "{}",
        err
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
}

// ----- NAT keepalive -------------------------------------------------------

/// A NAT between one inside host and one outside address that forgets its
/// mapping `idle` after the last datagram out: the next one out gets a new
/// outside port, and whatever arrives for the old one is lost — the way a
/// home router or carrier-grade NAT with a short UDP timeout behaves. The
/// inside host sends to the returned address as if it were the outside
/// one; the counter says how many mappings were made.
#[cfg(feature = "nat-traversal")]
async fn forgetful_nat(
    outside: SocketAddr,
    idle: Duration,
) -> (SocketAddr, Arc<AtomicU64>, tokio::task::JoinHandle<()>) {
    let inner = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = inner.local_addr().unwrap();
    let mappings = Arc::new(AtomicU64::new(0));
    let made = mappings.clone();
    let task = tokio::spawn(async move {
        let (in_tx, mut in_rx) = mpsc::unbounded_channel::<(u64, Vec<u8>)>();
        let mut inside: Option<SocketAddr> = None;
        // The current mapping: its outside socket, its number, when it was
        // last used outbound, and the task reading it.
        let mut mapping: Option<(Arc<UdpSocket>, u64, Instant, tokio::task::JoinHandle<()>)> = None;
        let mut buf = vec![0u8; 65536];
        loop {
            tokio::select! {
                r = inner.recv_from(&mut buf) => {
                    let Ok((n, from)) = r else { return };
                    inside = Some(from);
                    let now = Instant::now();
                    if mapping.as_ref().is_some_and(|m| now.duration_since(m.2) > idle) {
                        if let Some((_, _, _, reader)) = mapping.take() {
                            reader.abort();
                        }
                    }
                    if mapping.is_none() {
                        let ext = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                        let id = made.fetch_add(1, Ordering::Relaxed) + 1;
                        let reader = {
                            let ext = ext.clone();
                            let tx = in_tx.clone();
                            tokio::spawn(async move {
                                let mut b = vec![0u8; 65536];
                                while let Ok((n, from)) = ext.recv_from(&mut b).await {
                                    // Address-and-port filtering: only the
                                    // outside address this mapping is for.
                                    if from == outside {
                                        let _ = tx.send((id, b[..n].to_vec()));
                                    }
                                }
                            })
                        };
                        mapping = Some((ext, id, now, reader));
                    }
                    let m = mapping.as_mut().expect("just made");
                    m.2 = now;
                    let _ = m.0.send_to(&buf[..n], outside).await;
                }
                Some((id, pkt)) = in_rx.recv() => {
                    let now = Instant::now();
                    let alive = mapping
                        .as_ref()
                        .is_some_and(|m| m.1 == id && now.duration_since(m.2) <= idle);
                    if let (true, Some(inside)) = (alive, inside) {
                        let _ = inner.send_to(&pkt, inside).await;
                    }
                }
            }
        }
    });
    (addr, mappings, task)
}

/// A receiver behind a NAT that forgets idle mappings within a second stays
/// reachable through its relay, because its registration is refreshed more
/// often than that (RFC 8445 section 11) — while an identical receiver that
/// refreshes only every half minute, as a lease alone would ask, has become
/// unreachable by the time a sender comes along. And a receiver whose
/// refreshes are too far apart for its NAT notices the mapping change, and
/// brings them closer together until the mapping holds.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keepalives_keep_a_receiver_behind_a_forgetful_nat_reachable() {
    use sharp256::relay::server::{Config, Relay};
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let file = make_file(&src, "kept-alive.bin", 256 << 10, 0x4b41);
    let cancel = CancellationToken::new();
    let relay = Relay::bind(
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            lease: Duration::from_secs(60),
            ..Config::default()
        },
        cancel.clone(),
    )
    .await
    .expect("the relay binds");
    let relay_addr = relay.local_addr().unwrap();
    let relay_id = relay.id();
    let relay_task = tokio::spawn(async move {
        let _ = relay.run().await;
    });
    let idle = Duration::from_millis(800);
    let (nat_a, made_a, task_a) = forgetful_nat(relay_addr, idle).await;
    let (nat_b, made_b, task_b) = forgetful_nat(relay_addr, idle).await;
    let (nat_c, made_c, task_c) = forgetful_nat(relay_addr, idle).await;
    let behind = |nat: SocketAddr, keepalive: Duration| {
        move |cfg: &mut ReceiverConfig| {
            cfg.relays = vec![format!("{}@{}", relay_id, nat)];
            cfg.nat_keepalive = keepalive;
        }
    };
    let out_a = out.join("a");
    let out_b = out.join("b");
    let out_c = out.join("c");
    let a = start_receiver(&out_a, &state, behind(nat_a, Duration::from_millis(250))).await;
    let b = start_receiver(&out_b, &state, behind(nat_b, Duration::from_secs(30))).await;
    let mut c = start_receiver(&out_c, &state, behind(nat_c, Duration::from_millis(1200))).await;

    // Long enough idle for every mapping that is not kept alive to lapse.
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Kept alive: a sender given nothing but the relay gets through.
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let mut to_a = sender_cfg(&file, dead_addr, a.id, &state);
    to_a.relays = vec![relay_addr.to_string()];
    tokio::time::timeout(Duration::from_secs(30), run_sender(to_a))
        .await
        .expect("in time")
        .expect("a receiver kept alive is reachable through its relay");
    assert_same(&file, &out_a.join("kept-alive.bin"));
    assert_eq!(made_a.load(Ordering::Relaxed), 1, "A's mapping lapsed");

    // Not kept alive: the relay introduces the sender to a mapping that is
    // gone, and nothing comes of it.
    let mut to_b = sender_cfg(&file, dead_addr, b.id, &state);
    to_b.relays = vec![relay_addr.to_string()];
    to_b.transport.handshake_timeout = Duration::from_secs(3);
    let failed = tokio::time::timeout(Duration::from_secs(30), run_sender(to_b))
        .await
        .expect("gives up in time");
    assert!(
        failed.is_err(),
        "B was reachable although its mapping had lapsed"
    );

    // Refreshed too rarely for its NAT: the relay saw C at a new address,
    // the refreshes came closer together, and then the mapping held.
    let mut changes = 0;
    while let Ok(ev) = c.events.try_recv() {
        if matches!(ev, TransferEvent::RelayRegistered { .. }) {
            changes += 1;
        }
    }
    assert!(
        changes >= 2,
        "C's mapping never lapsed: {} registration(s)",
        changes
    );
    let settled = made_c.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        made_c.load(Ordering::Relaxed),
        settled,
        "C's refreshes never came close enough together to keep its mapping"
    );
    let _ = made_b;

    for t in [task_a, task_b, task_c] {
        t.abort();
    }
    stop_receiver(a).await;
    stop_receiver(b).await;
    stop_receiver(c).await;
    cancel.cancel();
    relay_task.abort();
}

// ----- Relay access and quotas ---------------------------------------------

/// Starts a relay with `cfg` (bound to loopback) and a receiver that only
/// the relay can reach — behind a mapping that turns everything else away —
/// registered with it. Returns the relay's address and identity, the
/// receiver, and what to stop afterwards.
#[cfg(feature = "nat-traversal")]
async fn relay_only_receiver(
    cfg: sharp256::relay::server::Config,
    out: &Path,
    state: &Path,
) -> (
    SocketAddr,
    SharpId,
    TestReceiver,
    CancellationToken,
    Vec<tokio::task::JoinHandle<()>>,
) {
    use sharp256::relay::server::Relay;
    let cancel = CancellationToken::new();
    let relay = Relay::bind(cfg, cancel.clone())
        .await
        .expect("the relay binds");
    let relay_addr = relay.local_addr().unwrap();
    let relay_id = relay.id();
    let relay_task = tokio::spawn(async move {
        let _ = relay.run().await;
    });
    let (mapping, _refused, mapping_task) = one_way_mapping(relay_addr).await;
    let r = start_receiver(out, state, |cfg| {
        cfg.relays = vec![format!("{}@{}", relay_id, mapping)];
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    (
        relay_addr,
        relay_id,
        r,
        cancel,
        vec![relay_task, mapping_task],
    )
}

/// A relay polices what it carries: a client gets the rate it is allowed
/// and no more, and the transfer still completes, its congestion control
/// settling on what the relay lets through.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_carries_a_client_at_its_rate_and_no_faster() {
    use sharp256::relay::server::{Config, Quotas};
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let size = 3 << 20;
    let file = make_file(&src, "policed.bin", size, 0x9011);
    let rate = 1_000_000;
    let (relay_addr, _relay_id, mut r, cancel, tasks) = relay_only_receiver(
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            quotas: Quotas {
                client_rate: rate,
                ..Quotas::default()
            },
            ..Config::default()
        },
        &out,
        &state,
    )
    .await;
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let mut cfg = sender_cfg(&file, dead_addr, r.id, &state);
    cfg.relays = vec![relay_addr.to_string()];
    let started = Instant::now();
    let summary = tokio::time::timeout(Duration::from_secs(90), run_sender(cfg))
        .await
        .expect("the policed transfer finishes")
        .expect("and completes");
    let took = started.elapsed();
    assert_eq!(summary.file_size, size as u64);
    // Three megabytes at one megabyte a second, less the quarter-second
    // burst: no less than about two and a half seconds.
    assert!(
        took >= Duration::from_millis(2300),
        "carried {} bytes in {:?}: faster than the relay allows",
        size,
        took
    );
    wait_completed(&mut r.events, Duration::from_secs(20)).await;
    assert_same(&file, &out.join("policed.bin"));
    stop_receiver(r).await;
    cancel.cancel();
    for t in tasks {
        t.abort();
    }
}

/// A relay that puts through only listed senders: one given the relay with
/// its identity proves who it is and gets through; one given the address
/// alone cannot, and is turned away.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_puts_through_only_the_senders_it_lists() {
    use sharp256::relay::server::Config;
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    let file = make_file(&src, "listed.bin", 256 << 10, 0x5e);
    let (relay_addr, relay_id, mut r, cancel, tasks) = relay_only_receiver(
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_senders: Some([sender_identity().id()].into_iter().collect()),
            ..Config::default()
        },
        &out,
        &state,
    )
    .await;
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let mut anonymous = sender_cfg(&file, dead_addr, r.id, &state);
    anonymous.relays = vec![relay_addr.to_string()];
    anonymous.transport.handshake_timeout = Duration::from_secs(3);
    let refused = tokio::time::timeout(Duration::from_secs(30), run_sender(anonymous))
        .await
        .expect("gives up in time");
    assert!(refused.is_err(), "put through without saying who it is");

    let mut named = sender_cfg(&file, dead_addr, r.id, &state);
    named.relays = vec![format!("{}@{}", relay_id, relay_addr)];
    tokio::time::timeout(Duration::from_secs(30), run_sender(named))
        .await
        .expect("in time")
        .expect("a listed sender that proves itself is put through");
    wait_completed(&mut r.events, Duration::from_secs(20)).await;
    assert_same(&file, &out.join("listed.bin"));
    stop_receiver(r).await;
    cancel.cancel();
    for t in tasks {
        t.abort();
    }
}

/// What a person has when there is no card: an `IP:PORT` read off the other
/// side's screen. Handed to the running receiver it is sent at, with no NAT
/// hints to go by, from the receiver's own socket — the one a NAT in front
/// of it would have to see the packet leave from.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_receiver_sends_at_a_bare_address_it_is_given() {
    use sharp256::relay::Message;

    init_test_logging();
    let tmp = tempfile::tempdir().unwrap();
    let (_src, out, state) = dirs(&tmp);
    let mut cfg = ReceiverConfig::new("127.0.0.1:0".parse().unwrap(), out);
    cfg.state_dir = Some(state);
    cfg.transport = fast_transport();
    cfg.identity = Some(Identity::generate());
    let receiver = Receiver::new(cfg).await.expect("receiver");
    let receiver_addr = receiver.local_addr().unwrap();
    let addrs = receiver.peer_addrs();
    let cancel = receiver.cancel_token();
    let task = tokio::spawn(async move { receiver.run().await });

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    addrs.send(peer.local_addr().unwrap()).unwrap();
    let mut buf = [0u8; 2048];
    let (n, from) = tokio::time::timeout(Duration::from_secs(10), peer.recv_from(&mut buf))
        .await
        .expect("something was sent at the address")
        .unwrap();
    assert_eq!(from, receiver_addr, "sent from the receiver's own socket");
    assert!(
        matches!(Message::decode(&buf[..n]), Some(Message::Punch)),
        "what arrived is a punch packet"
    );

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(15), task).await;
}

/// A sender given the receiver's address by hand and asked to give its own
/// in return (`give_card`, `sharp-sender --card`) punches at the address:
/// the receiver's side punches back once it is handed ours, and a meeting
/// takes both. Not asked, it only tries the address with handshakes.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sender_meeting_by_hand_punches_at_the_address_it_was_given() {
    use sharp256::relay::Message;

    init_test_logging();
    let tmp = tempfile::tempdir().unwrap();
    let (src, _out, state) = dirs(&tmp);
    let file = make_file(&src, "meet.bin", 4096, 0x3EE7);
    for give_card in [true, false] {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = sender_cfg(
            &file,
            peer.local_addr().unwrap(),
            Identity::generate().id(),
            &state,
        );
        cfg.give_card = give_card;
        cfg.transport.handshake_timeout = Duration::from_secs(2);
        let sender = tokio::spawn(run_sender(cfg));
        let mut punched = false;
        let mut buf = [0u8; 2048];
        let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
        while let Ok(Ok((n, _))) = tokio::time::timeout_at(deadline, peer.recv_from(&mut buf)).await
        {
            if matches!(Message::decode(&buf[..n]), Some(Message::Punch)) {
                punched = true;
                break;
            }
        }
        assert_eq!(punched, give_card, "give_card = {}", give_card);
        // Nobody answers there: the sender gives up after its handshake
        // timeout, and the punching stops with it.
        let result = tokio::time::timeout(Duration::from_secs(10), sender)
            .await
            .expect("the sender ends")
            .expect("the sender task");
        assert!(result.is_err(), "nobody was there to receive");
    }
}

/// Forwards datagrams between one client and `target`, counting the punches
/// (a relay's `Punch` message, which is what punching sends) the client
/// sends towards the target.
#[cfg(feature = "nat-traversal")]
async fn counting_forwarder(
    target: SocketAddr,
) -> (SocketAddr, Arc<AtomicU64>, tokio::task::JoinHandle<()>) {
    use sharp256::relay::Message;

    let outer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let inner = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = outer.local_addr().unwrap();
    let punches = Arc::new(AtomicU64::new(0));
    let count = punches.clone();
    let task = tokio::spawn(async move {
        let mut client: Option<SocketAddr> = None;
        let (mut a, mut b) = (vec![0u8; 65536], vec![0u8; 65536]);
        loop {
            // A receive error (an ICMP "port unreachable" on Windows) is
            // not the end of the forwarding.
            tokio::select! {
                r = outer.recv_from(&mut a) => {
                    let Ok((n, from)) = r else { continue };
                    client = Some(from);
                    if matches!(Message::decode(&a[..n]), Some(Message::Punch)) {
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                    let _ = inner.send_to(&a[..n], target).await;
                }
                r = inner.recv_from(&mut b) => {
                    let Ok((n, _)) = r else { continue };
                    if let Some(c) = client {
                        let _ = outer.send_to(&b[..n], c).await;
                    }
                }
            }
        }
    });
    (addr, punches, task)
}

/// Punching that meets a receiver stops once the session runs directly to
/// it: it has done its work, and a transfer that lasts is not accompanied by
/// punches at the receiver all the way.
#[cfg(feature = "nat-traversal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_meeting_stops_punching_once_the_session_is_direct() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = dirs(&tmp);
    // Long enough to outlast the first round of punches (6 s): 1 MiB at
    // 1.5 Mbit/s takes about 5.6 s, and the window below ends before it.
    let file = make_file(&src, "unhurried.bin", 1 << 20, 0x5709);
    let r = start_receiver(&out, &state, |_| {}).await;
    let (via, punches, forwarding) = counting_forwarder(r.addr).await;
    let mut cfg = sender_cfg(&file, via, r.id, &state);
    cfg.give_card = true;
    cfg.transport.max_rate_bytes = Some(1_500_000 / 8);
    let sender = tokio::spawn(run_sender(cfg));
    let deadline = Instant::now() + Duration::from_secs(3);
    while punches.load(Ordering::Relaxed) == 0 {
        assert!(Instant::now() < deadline, "no punch was sent at all");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The session is up on loopback in a moment; the punching stops at the
    // engine's next look round.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let before = punches.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !sender.is_finished(),
        "the transfer ended before the window did, so this proved nothing"
    );
    assert_eq!(
        punches.load(Ordering::Relaxed),
        before,
        "punches went on after the session ran directly"
    );
    tokio::time::timeout(Duration::from_secs(30), sender)
        .await
        .expect("in time")
        .expect("the sender task")
        .expect("the transfer completes");
    assert_same(&file, &out.join("unhurried.bin"));
    forwarding.abort();
    stop_receiver(r).await;
}
