//! No key and no byte of what is transferred may reach the log.
//!
//! A log is written to places keys never should be — terminals, journald,
//! files other people are sent when something goes wrong. So transfers are
//! run with everything the program logs, at the most detailed level,
//! captured the way its own subscriber would print it: one directly, with
//! a shared secret, and one that only a relay can carry. Every key made
//! meanwhile is noted as it is made (`crypto::secret::keylog`: identities,
//! the pre-shared key and the passphrase it came from, ephemeral keys,
//! every chaining key and cipher key of the handshakes, the split, traffic
//! secrets, header protection and epoch keys, cookie and token secrets,
//! the relay's keys), and the log is searched for each of them written in
//! every way a program writes bytes: hex in either case, `{:?}` and
//! `{:x?}` of the bytes, base64, base32 — and every eight-byte stretch of
//! each in hex, in case something prints a key cut short. The file is
//! searched for too: a line of text planted in it, and stretches of its
//! random bytes.
//!
//! And a control: a key logged on purpose, the way a careless `{:02x?}`
//! would, must be found. A search that found nothing there would prove
//! nothing here.

use crate::config::{ReceiverConfig, SenderConfig, TransportConfig};
use crate::crypto::secret::keylog;
use crate::crypto::{psk_from_passphrase_with_cost, Identity};
use crate::progress::TransferEvent;
use crate::transport::{Receiver, Sender};
use parking_lot::Mutex;
use rand::RngCore;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

static LOGGING: AtomicBool = AtomicBool::new(false);
static LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct Capture;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        Capture
    }
}

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        LOG.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A subscriber for the whole process, formatting as the program's own does
/// (`init_logging`) at every level, but only while `LOGGING` is on — the
/// other tests of this process log through it meanwhile, which does no harm:
/// their keys are noted too, and none may appear either.
fn capture_everything() {
    use tracing_subscriber::prelude::*;
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(Capture)
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::dynamic_filter_fn(|_, _| {
                LOGGING.load(Ordering::Relaxed)
            }));
        tracing_subscriber::registry()
            .with(layer)
            .try_init()
            .expect("no other subscriber in the tests' process");
    });
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn base64(bytes: &[u8], alphabet: &[u8; 64]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| n << 8 | *b as u32) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(alphabet[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// The ways `secret` might be written into a log, each long enough that it
/// cannot turn up by chance.
fn spellings(secret: &[u8]) -> Vec<String> {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = Vec::new();
    // Eight times the same byte is no key's, and is what a log is full of
    // ("0000000000000000" turned up in one on Windows).
    for window in secret.windows(8).filter(|w| w.iter().any(|b| *b != w[0])) {
        s.push(hex(window));
        s.push(hex(window).to_uppercase());
    }
    let head = &secret[..secret.len().min(8)];
    // `{:?}` and `{:x?}` of the bytes, and of an array of them: "[12, 250, ..."
    let debug = format!("{:?}", head);
    s.push(debug[..debug.len() - 1].to_string());
    let debug_hex = format!("{:x?}", head);
    s.push(debug_hex[..debug_hex.len() - 1].to_string());
    let debug_hex2 = format!("{:02x?}", head);
    s.push(debug_hex2[..debug_hex2.len() - 1].to_string());
    // base64 and base32 of the whole, the first 16 characters of each.
    s.push(base64(secret, STD)[..16].to_string());
    s.push(base64(secret, URL)[..16].to_string());
    s.push(crate::crypto::identity::base32_encode(secret)[..16].to_string());
    s
}

/// Where `secret` shows in `log`, if it does.
fn found(log: &str, secret: &[u8]) -> Option<String> {
    spellings(secret)
        .into_iter()
        .find(|s| log.contains(s.as_str()))
}

fn transport() -> TransportConfig {
    TransportConfig {
        stall_timeout: Duration::from_millis(800),
        handshake_timeout: Duration::from_secs(20),
        persist_interval: Duration::from_millis(200),
        progress_interval: Duration::from_millis(100),
        ..TransportConfig::default()
    }
}

/// A file of random bytes with a line of text planted in the middle.
fn make_file(path: &Path, canary: &str) -> Vec<u8> {
    let mut data = vec![0u8; 3 << 20];
    rand::thread_rng().fill_bytes(&mut data);
    let at = data.len() / 2;
    data[at..at + canary.len()].copy_from_slice(canary.as_bytes());
    std::fs::write(path, &data).unwrap();
    data
}

async fn receive_one(cfg: ReceiverConfig, mut send: impl FnMut(SocketAddr) -> SenderConfig) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut cfg = cfg;
    cfg.events = Some(Arc::new(move |ev| {
        let _ = tx.send(ev);
    }));
    let receiver = Receiver::new(cfg).await.expect("receiver");
    let addr = receiver.local_addr().unwrap();
    let cancel = receiver.cancel_token();
    let task = tokio::spawn(async move { receiver.run().await });
    let summary = tokio::time::timeout(Duration::from_secs(60), async {
        Sender::new(send(addr)).await?.run().await
    })
    .await
    .expect("the transfer ends in time")
    .expect("the transfer completes");
    assert!(summary.file_size > 0);
    loop {
        match tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
            Ok(Some(TransferEvent::Completed { .. })) => break,
            Ok(Some(_)) => continue,
            _ => panic!("the receiver did not report completion"),
        }
    }
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
}

/// On a runtime of its own, whose threads (and this one) note the keys
/// they make (see `crypto::secret::keylog`).
#[test]
fn no_key_and_no_content_reaches_the_log() {
    keylog::this_thread();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .on_thread_start(keylog::this_thread)
        .build()
        .unwrap()
        .block_on(transfers_leave_no_key_in_the_log());
}

async fn transfers_leave_no_key_in_the_log() {
    capture_everything();
    let tmp = tempfile::tempdir().unwrap();
    let (src, out, state) = (
        tmp.path().join("src"),
        tmp.path().join("out"),
        tmp.path().join("state"),
    );
    for d in [&src, &out, &state] {
        std::fs::create_dir_all(d).unwrap();
    }
    let mut canary_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut canary_bytes);
    let canary = format!("SHARP-CANARY-{}", hex(&canary_bytes));
    let file = src.join("contents.bin");
    let data = make_file(&file, &canary);
    let passphrase = format!("log hygiene passphrase {}", hex(&canary_bytes[..4]));

    LOG.lock().clear();
    keylog::take();
    keylog::record(true);
    LOGGING.store(true, Ordering::Relaxed);

    // Directly, with a shared secret.
    let receiver_identity = Identity::generate();
    let rid = receiver_identity.id();
    let mut rcfg = ReceiverConfig::new("127.0.0.1:0".parse().unwrap(), out.clone());
    rcfg.state_dir = Some(state.clone());
    rcfg.transport = transport();
    rcfg.identity = Some(receiver_identity.clone());
    rcfg.psk = Some(psk_from_passphrase_with_cost(&passphrase, &rid, 64, 1));
    rcfg.nat_traversal = false;
    let sender_identity = Identity::generate();
    receive_one(rcfg, |addr| {
        let mut cfg = SenderConfig::new(addr, rid, file.clone());
        cfg.bind = "127.0.0.1:0".parse().unwrap();
        cfg.state_dir = Some(state.clone());
        cfg.transport = transport();
        cfg.identity = Some(sender_identity.clone());
        cfg.psk = Some(psk_from_passphrase_with_cost(&passphrase, &rid, 64, 1));
        cfg
    })
    .await;

    // Through a relay, which alone knows where the receiver is.
    #[cfg(feature = "nat-traversal")]
    {
        use crate::relay::server::{Config, Relay};
        let cancel = tokio_util::sync::CancellationToken::new();
        let relay = Relay::bind(
            Config {
                bind: "127.0.0.1:0".parse().unwrap(),
                ..Config::default()
            },
            cancel.clone(),
        )
        .await
        .expect("the relay binds");
        let (relay_addr, relay_id) = (relay.local_addr().unwrap(), relay.id());
        let relay_task = tokio::spawn(async move {
            let _ = relay.run().await;
        });
        let out2 = tmp.path().join("out2");
        std::fs::create_dir_all(&out2).unwrap();
        let receiver_identity = Identity::generate();
        let rid = receiver_identity.id();
        let mut rcfg = ReceiverConfig::new("127.0.0.1:0".parse().unwrap(), out2);
        rcfg.state_dir = Some(tmp.path().join("state2"));
        rcfg.transport = transport();
        rcfg.identity = Some(receiver_identity);
        rcfg.relays = vec![format!("{}@{}", relay_id, relay_addr)];
        rcfg.relay_private = true;
        let state3 = tmp.path().join("state3");
        receive_one(rcfg, |_| {
            let mut cfg = SenderConfig::new("0.0.0.0:0".parse().unwrap(), rid, file.clone());
            cfg.bind = "127.0.0.1:0".parse().unwrap();
            cfg.state_dir = Some(state3.clone());
            cfg.transport = transport();
            cfg.identity = Some(Identity::generate());
            cfg.relays = vec![relay_addr.to_string()];
            cfg
        })
        .await;
        cancel.cancel();
        relay_task.abort();
    }

    // The control: a key logged on purpose is found.
    let control = crate::crypto::SecretKey::random();
    tracing::debug!("a careless line: {:02x?}", control.expose());

    LOGGING.store(false, Ordering::Relaxed);
    keylog::record(false);
    let keys = keylog::take();
    let log = String::from_utf8_lossy(&LOG.lock()).into_owned();
    if let Ok(path) = std::env::var("SHARP_LOG_HYGIENE_DUMP") {
        std::fs::write(path, &log).unwrap();
    }

    assert!(
        found(&log, control.expose()).is_some(),
        "the search does not find a key logged on purpose"
    );
    // Both transfers were logged, in detail: each says at debug level that
    // its session was established. (How many debug lines there are besides
    // goes with how long they take — the progress, every 100 ms — and two
    // transfers done in 66 and 100 ms left ten, one short of the eleven
    // this used to ask for, under MemorySanitizer in CI.)
    assert!(
        log.lines()
            .filter(|l| l.contains(" DEBUG ") && l.contains(" established ("))
            .count()
            == 2
            && log.matches("whole-file hash matches").count() == 2,
        "the transfers were not logged in detail:\n{}",
        log
    );
    assert!(
        keys.len() > 50,
        "hardly any keys were noted: {}",
        keys.len()
    );
    let mut leaks = Vec::new();
    // An all-zero key is none: it is what a transfer without a shared secret
    // uses as its PSK, which anybody may know.
    for key in keys
        .iter()
        .filter(|k| k[..] != control.expose()[..] && k.iter().any(|b| *b != 0))
    {
        if let Some(how) = found(&log, key) {
            leaks.push(format!("a key, written as {}", how));
        }
    }
    for secret in [passphrase.as_bytes(), canary.as_bytes()] {
        if log.contains(std::str::from_utf8(secret).unwrap()) {
            leaks.push(format!("{:?}", std::str::from_utf8(secret).unwrap()));
        }
    }
    let mut rng = rand::thread_rng();
    for _ in 0..256 {
        let at = (rng.next_u64() as usize) % (data.len() - 12);
        if let Some(how) = found(&log, &data[at..at + 12]) {
            leaks.push(format!("the file's bytes at {}, written as {}", at, how));
        }
    }
    assert!(
        leaks.is_empty(),
        "in {} lines of log, {} keys searched: {:?}",
        log.lines().count(),
        keys.len(),
        leaks
    );
    println!(
        "{} lines of log searched for {} keys, the passphrase, the planted text and 256 stretches of the file: none found; the control was",
        log.lines().count(),
        keys.len()
    );
}
