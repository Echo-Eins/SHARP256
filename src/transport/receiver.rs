//! Receiving side: one `Receiver` serves many concurrent transfers.
//!
//! The socket is read by a single dispatcher task that drains all queued
//! datagrams. Transport packets are routed by their connection id to
//! per-transfer session tasks. Anything else must be a handshake initiation
//! made by someone who knows this receiver's ID (its mac1 proves it);
//! everything that is not is dropped without an answer, so the receiver is
//! invisible to scanners. Initiations are rate limited per source, answered
//! with cookies when the receiver is under load, checked for replays, and
//! then authorised by the sender's identity.
//!
//! A session:
//!
//! * decides on the transfer (policy, or the application's decision, during
//!   which the sender is told "pending") and answers the handshake with
//!   accurate resume information computed from what is already durable;
//! * decrypts every transport packet and hands DATA payloads, without
//!   copying them again, to a coalescing writer thread at their absolute
//!   offsets; received bytes are tracked in a `RangeSet`;
//! * sends selective ACKs whose hole list always describes the acknowledged
//!   interval completely (the interval is shortened when the list is full);
//! * persists durable progress periodically (after fsync) for resume;
//! * when every byte is present, closes, hashes and renames the file in a
//!   background task while it keeps answering the sender, then exchanges
//!   FIN / FIN_ACK / FIN_DONE.

use crate::config::{AcceptPolicy, IncomingRequest, ReceiverConfig, TransportConfig};
use crate::crypto::handshake::{self as hs, CookieJar, HandshakeLimiter, ReplayGuard, Responder};
use crate::crypto::replay::ReplayWindow;
use crate::crypto::transport::{
    begin_packet, peek_cid, SessionKeys, Suite, HEADER_LEN, OVERHEAD, TAG_LEN,
};
use crate::crypto::{Identity, SharpId, NO_PSK};
use crate::file::{
    available_space, hash_file, hash_to_hex, part_path_for, rename_with_retry, sanitize_file_name,
    unique_path, FileWriter,
};
use crate::progress::{emit, EventCallback, TransferEvent, TransferStats};
use crate::protocol::constants::*;
use crate::protocol::wire::{
    self, parse_type_byte, type_byte, Ack, Fin, Hello, HelloAck, Message, MsgType, Pong, ProbeAck,
    MAX_CONTROL_BODY,
};
use crate::protocol::RangeSet;
use crate::state::{hex16, ReceiverState, StateStore};
use crate::transport::socket::bind_udp;
use rand::RngCore;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub enum RecvError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("identity: {0}")]
    Identity(String),
}

/// Resume state older than this is deleted when a receiver starts.
const STATE_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);

/// Datagrams a session may have queued before the dispatcher drops more.
const SESSION_QUEUE: usize = 16_384;
/// Messages a session handles per wakeup before it checks its timers.
const SESSION_BATCH: usize = 256;
/// Senders whose last initiation timestamp is remembered (replay guard).
const REPLAY_GUARD_CAPACITY: usize = 100_000;

/// A transfer is identified by who sends it and its transfer id.
type TransferKey = (SharpId, [u8; 16]);

/// An authenticated initiation routed to the session it belongs to.
struct Handshake {
    incoming: hs::Incoming,
    init: wire::Initiation,
    suite: Suite,
    /// Connection id the dispatcher assigned to the session for it.
    cid: u64,
    from: SocketAddr,
    at: Instant,
}

/// Messages delivered to a session task.
enum Incoming {
    Packet {
        data: Vec<u8>,
        from: SocketAddr,
        at: Instant,
    },
    Handshake(Box<Handshake>),
    /// The writer finished an fsync requested for persistence.
    FlushDone(io::Result<()>),
    /// Background close + hash + rename finished.
    Verified(Result<([u8; 32], PathBuf), String>),
}

struct SessionHandle {
    tx: mpsc::Sender<Incoming>,
    /// The session's current connection id.
    cid: u64,
    task: tokio::task::JoinHandle<()>,
}

struct Shared {
    cfg: ReceiverConfig,
    socket: Arc<UdpSocket>,
    store: Option<StateStore>,
    cancel: CancellationToken,
    identity: Identity,
}

pub struct Receiver {
    shared: Arc<Shared>,
}

impl Receiver {
    pub async fn new(cfg: ReceiverConfig) -> Result<Self, RecvError> {
        let cfg = ReceiverConfig {
            transport: cfg.transport.normalized(),
            ..cfg
        };
        let identity = match &cfg.identity {
            Some(id) => id.clone(),
            None => {
                let path = Identity::default_path()
                    .ok_or_else(|| RecvError::Identity("no per-user data directory".into()))?;
                Identity::load_or_create(&path)
                    .map_err(|e| RecvError::Identity(format!("{}: {}", path.display(), e)))?
            }
        };
        std::fs::create_dir_all(&cfg.output_dir)?;
        let socket = bind_udp(cfg.bind, cfg.transport.socket_buffer_bytes)?;
        tracing::info!(
            "receiver {} listening on {}, output {}",
            identity.id(),
            socket.local_addr()?,
            cfg.output_dir.display()
        );
        let store = match StateStore::open(cfg.state_dir.clone()) {
            Ok(s) => {
                // Resume state of transfers abandoned long ago is useless.
                if let Ok(n) = s.cleanup_older_than(STATE_MAX_AGE) {
                    if n > 0 {
                        tracing::info!("removed {} stale resume state file(s)", n);
                    }
                }
                Some(s)
            }
            Err(e) => {
                tracing::warn!("resume state disabled: {}", e);
                None
            }
        };
        Ok(Self {
            shared: Arc::new(Shared {
                cfg,
                socket: Arc::new(socket),
                store,
                cancel: CancellationToken::new(),
                identity,
            }),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shared.socket.local_addr()
    }

    /// Our identity: senders need it to reach us.
    pub fn id(&self) -> SharpId {
        self.shared.identity.id()
    }

    /// Token that stops the receiver (sessions persist their state first).
    pub fn cancel_token(&self) -> CancellationToken {
        self.shared.cancel.clone()
    }

    /// Serves transfers until cancelled.
    pub async fn run(self) -> Result<(), RecvError> {
        let shared = self.shared;

        // NAT discovery runs in the background; its STUN responses arrive on
        // this socket and are handed over below.
        #[cfg(feature = "nat-traversal")]
        let nat = if shared.cfg.nat_traversal {
            let events = shared.cfg.events.clone();
            crate::nat::spawn_receiver_discovery(
                shared.socket.clone(),
                crate::nat::NatConfig::default(),
                shared.cancel.clone(),
                move |r| {
                    emit(
                        &events,
                        TransferEvent::Reachability {
                            advertised: r.advertised().map(|a| a.to_string()),
                            summary: r.describe(),
                        },
                    )
                },
            )
        } else {
            None
        };

        let socket = shared.socket.clone();
        let cancel = shared.cancel.clone();
        let (done_tx, mut done_rx) = mpsc::channel::<TransferKey>(256);
        let mut d = Dispatcher::new(shared.clone(), done_tx);
        let mut buf = vec![0u8; MAX_DATAGRAM];

        loop {
            tokio::select! {
                r = socket.readable() => {
                    if let Err(e) = r {
                        tracing::debug!("socket readiness error: {}", e);
                        continue;
                    }
                    loop {
                        let (n, from) = match socket.try_recv_from(&mut buf) {
                            Ok(v) => v,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => {
                                tracing::debug!("recv error: {}", e);
                                break;
                            }
                        };
                        let pkt = &buf[..n];
                        #[cfg(feature = "nat-traversal")]
                        if let Some(nat) = &nat {
                            if crate::nat::stun::is_stun_response(pkt) {
                                let _ = nat.stun_responses.try_send(pkt.to_vec());
                                continue;
                            }
                        }
                        d.on_datagram(pkt, from, Instant::now());
                    }
                }
                Some(key) = done_rx.recv() => d.forget(&key),
                _ = cancel.cancelled() => {
                    tracing::info!("receiver shutting down; {} active session(s)", d.sessions.len());
                    // Sessions observe the same token; wait until each one has
                    // flushed its file and persisted its resume state.
                    let handles: Vec<_> = d.sessions.drain().map(|(_, s)| s.task).collect();
                    for h in handles {
                        let _ = tokio::time::timeout(Duration::from_secs(10), h).await;
                    }
                    // The NAT task observes the same token and removes its
                    // UPnP port forward.
                    #[cfg(feature = "nat-traversal")]
                    if let Some(nat) = nat {
                        let _ = tokio::time::timeout(Duration::from_secs(5), nat.task).await;
                    }
                    return Ok(());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

struct Dispatcher {
    shared: Arc<Shared>,
    responder: Responder,
    cookies: CookieJar,
    limiter: HandshakeLimiter,
    replays: ReplayGuard,
    sessions: HashMap<TransferKey, SessionHandle>,
    by_cid: HashMap<u64, TransferKey>,
    done_tx: mpsc::Sender<TransferKey>,
    dropped: u64,
}

impl Dispatcher {
    fn new(shared: Arc<Shared>, done_tx: mpsc::Sender<TransferKey>) -> Self {
        let cfg = &shared.cfg;
        let responder = Responder::new(shared.identity.clone(), cfg.psk.unwrap_or(NO_PSK));
        let cookies = CookieJar::new(&shared.identity.id());
        let limiter = HandshakeLimiter::new(
            cfg.handshake_rate,
            cfg.handshake_burst,
            cfg.handshake_load_threshold,
        );
        Self {
            shared,
            responder,
            cookies,
            limiter,
            replays: ReplayGuard::new(REPLAY_GUARD_CAPACITY),
            sessions: HashMap::new(),
            by_cid: HashMap::new(),
            done_tx,
            dropped: 0,
        }
    }

    fn on_datagram(&mut self, pkt: &[u8], from: SocketAddr, now: Instant) {
        if let Some(cid) = peek_cid(pkt) {
            if let Some(key) = self.by_cid.get(&cid) {
                if pkt.len() < OVERHEAD {
                    return;
                }
                if let Some(s) = self.sessions.get(key) {
                    let msg = Incoming::Packet {
                        data: pkt.to_vec(),
                        from,
                        at: now,
                    };
                    if s.tx.try_send(msg).is_err() {
                        self.dropped += 1;
                        if self.dropped.is_power_of_two() {
                            tracing::debug!(
                                "session queue full: {} datagrams dropped so far",
                                self.dropped
                            );
                        }
                    }
                }
                return;
            }
        }
        // Not for a known connection: an initiation by someone who knows our
        // ID, or nothing we ever answer.
        if self.responder.is_initiation(pkt) {
            self.on_initiation(pkt, from, now);
        }
    }

    fn on_initiation(&mut self, pkt: &[u8], from: SocketAddr, now: Instant) {
        let under_load = self.limiter.note_initiation(now);
        if under_load && !self.cookies.mac2_ok(pkt, from, now) {
            // Make the sender prove it receives at its address before we
            // spend public-key operations on it.
            if let Some(reply) = self.cookies.reply(pkt, from, now) {
                let _ = self.shared.socket.try_send_to(&reply, from);
            }
            return;
        }
        if !self.limiter.allow(from.ip(), now) {
            return;
        }
        let incoming = match self.responder.read_initiation(pkt) {
            Ok(i) => i,
            Err(e) => {
                tracing::debug!("initiation from {} rejected: {}", from, e);
                return;
            }
        };
        let init = match wire::decode_initiation(&incoming.payload) {
            Ok(i) => i,
            Err(e) => {
                tracing::debug!("malformed initiation payload from {}: {}", from, e);
                return;
            }
        };
        if !self.replays.accept(&incoming.sender, init.timestamp) {
            tracing::debug!("replayed initiation from {} ignored", from);
            return;
        }
        let sender = incoming.sender;
        if let Some(allowed) = &self.shared.cfg.allowed_senders {
            if !allowed.contains(&sender) {
                tracing::info!(
                    "transfer from {} ({}) refused: sender not allowed",
                    from,
                    sender
                );
                self.reject(
                    incoming,
                    &init,
                    from,
                    REASON_UNAUTHORIZED,
                    "sender not authorized",
                );
                return;
            }
        }
        let Some(suite) = Suite::choose(init.suites, init.hardware_aes) else {
            self.reject(
                incoming,
                &init,
                from,
                REASON_NO_SUITE,
                "no cipher in common",
            );
            return;
        };
        let key = (sender, init.hello.transfer_id);
        let cid = self.new_cid();
        let handshake = Box::new(Handshake {
            incoming,
            init,
            suite,
            cid,
            from,
            at: now,
        });

        // A new handshake of a transfer we already serve (the sender lost the
        // session after an outage, or restarted): move the session over.
        if let Some(s) = self.sessions.get_mut(&key) {
            if !s.task.is_finished() {
                self.by_cid.remove(&s.cid);
                s.cid = cid;
                self.by_cid.insert(cid, key);
                let _ = s.tx.try_send(Incoming::Handshake(handshake));
                return;
            }
            let old = self.sessions.remove(&key).expect("present");
            self.by_cid.remove(&old.cid);
        }

        self.prune();
        if self.sessions.len() >= self.shared.cfg.max_sessions {
            let Handshake { incoming, init, .. } = *handshake;
            self.reject(
                incoming,
                &init,
                from,
                REASON_BUSY,
                "too many concurrent transfers",
            );
            return;
        }
        let (tx, rx) = mpsc::channel::<Incoming>(SESSION_QUEUE);
        let _ = tx.try_send(Incoming::Handshake(handshake));
        let shared = self.shared.clone();
        let done_tx = self.done_tx.clone();
        let session_tx = tx.clone();
        let task = tokio::spawn(async move {
            let session = Session::new(shared, key, from, session_tx);
            let key = session.run(rx).await;
            let _ = done_tx.send(key).await;
        });
        self.by_cid.insert(cid, key);
        self.sessions.insert(key, SessionHandle { tx, cid, task });
    }

    /// Answers an authenticated initiation with a rejection; no session is
    /// created.
    fn reject(
        &self,
        incoming: hs::Incoming,
        init: &wire::Initiation,
        to: SocketAddr,
        reason: u8,
        message: &str,
    ) {
        let payload = wire::encode_response(&wire::Response {
            suite: 0,
            ack_flags: 0,
            ack: rejection(init.hello.timestamp, reason, message),
        });
        if let Ok((pkt, _)) = incoming.respond(self.new_cid(), &payload) {
            let _ = self.shared.socket.try_send_to(&pkt, to);
        }
    }

    fn new_cid(&self) -> u64 {
        loop {
            let c = rand::rngs::OsRng.next_u64();
            if c != 0 && !self.by_cid.contains_key(&c) {
                return c;
            }
        }
    }

    /// Drops the routing of a session whose task ended.
    fn forget(&mut self, key: &TransferKey) {
        if self.sessions.get(key).is_some_and(|s| s.task.is_finished()) {
            if let Some(s) = self.sessions.remove(key) {
                self.by_cid.remove(&s.cid);
            }
        }
    }

    fn prune(&mut self) {
        let finished: Vec<TransferKey> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.task.is_finished())
            .map(|(k, _)| *k)
            .collect();
        for k in finished {
            if let Some(s) = self.sessions.remove(&k) {
                self.by_cid.remove(&s.cid);
            }
        }
    }
}

fn rejection(echo_ts: u32, reason: u8, message: &str) -> HelloAck {
    HelloAck {
        status: HELLO_REJECTED,
        reason,
        max_chunk: 0,
        capabilities: 0,
        echo_ts,
        max_ack_delay_us: 0,
        rwnd: 0,
        resume_upto: 0,
        known_end: 0,
        holes: Vec::new(),
        message: message.to_string(),
    }
}

/// Closes the writer (fsync), hashes the partial file and moves it to its
/// final name. Runs outside the session task so the session stays responsive.
async fn finish_file(
    writer: FileWriter,
    part: PathBuf,
    final_path: PathBuf,
    overwrite: bool,
) -> Result<([u8; 32], PathBuf), String> {
    writer
        .close()
        .await
        .map_err(|e| format!("cannot finish writing file: {}", e))?;
    let p = part.clone();
    let hash = tokio::task::spawn_blocking(move || hash_file(&p))
        .await
        .map_err(|e| format!("hash task failed: {}", e))?
        .map_err(|e| format!("cannot hash file: {}", e))?;
    let target = tokio::task::spawn_blocking(move || -> io::Result<PathBuf> {
        let mut target = final_path;
        if target.exists() {
            if overwrite {
                let _ = std::fs::remove_file(&target);
            } else {
                let name = target
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let dir = target
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."));
                target = unique_path(&dir, &name);
            }
        }
        rename_with_retry(&part, &target)?;
        Ok(target)
    })
    .await
    .map_err(|e| format!("rename task failed: {}", e))?
    .map_err(|e| format!("cannot rename partial file: {}", e))?;
    Ok((hash, target))
}

/// Resolves when the application decided, or never without a pending
/// decision.
async fn decided(rx: &mut Option<oneshot::Receiver<bool>>) -> bool {
    match rx {
        Some(r) => r.await.unwrap_or(false),
        None => std::future::pending().await,
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

enum Phase {
    /// Waiting for the application to accept or decline.
    Pending {
        deadline: Instant,
    },
    Receiving,
    /// All bytes present; closing, hashing and renaming in the background.
    Verifying,
    /// FIN sent; waiting for the sender's verdict.
    Finishing {
        hash: [u8; 32],
        next_fin_at: Instant,
        fin_delay: Duration,
        started_at: Instant,
    },
}

/// Keys and packet state of the session's current handshake.
struct Secure {
    keys: SessionKeys,
    /// Our connection id: the sender addresses its packets to it.
    local_cid: u64,
    /// The sender's connection id: our packets are addressed to it.
    peer_cid: u64,
    next_pn: u64,
    replay: ReplayWindow,
    auth_failures: u64,
}

struct Session {
    shared: Arc<Shared>,
    cfg: TransportConfig,
    events: Option<EventCallback>,
    self_tx: mpsc::Sender<Incoming>,

    transfer_id: [u8; 16],
    sender: SharpId,
    peer: SocketAddr,
    secure: Option<Secure>,
    tx_buf: Vec<u8>,

    file_name: String,
    file_size: u64,
    file_mtime: i64,
    max_chunk: u16,
    final_path: PathBuf,
    part_path: PathBuf,
    writer: Option<FileWriter>,
    received: RangeSet,
    highest: u64,
    resumed_from: u64,

    pkts_since_ack: u32,
    last_ack_at: Instant,
    immediate_ack_at: Option<Instant>,
    last_data_ts: u32,
    last_data_at: Instant,

    persist_dirty: bool,
    last_persist_at: Instant,
    flush_in_progress: bool,
    flush_snapshot: Option<RangeSet>,

    start: Instant,
    last_rx: Instant,
    stalled: bool,
    last_progress_at: Instant,
    last_progress_bytes: u64,
    retransmitted_bytes: u64,
    writer_full_drops: u64,
    /// Whether this session stored any new data (idle sessions expire early).
    got_data: bool,
    phase: Phase,
}

impl Session {
    fn new(
        shared: Arc<Shared>,
        key: TransferKey,
        peer: SocketAddr,
        self_tx: mpsc::Sender<Incoming>,
    ) -> Self {
        let now = Instant::now();
        let cfg = shared.cfg.transport.clone();
        let events = shared.cfg.events.clone();
        Self {
            shared,
            cfg,
            events,
            self_tx,
            transfer_id: key.1,
            sender: key.0,
            peer,
            secure: None,
            tx_buf: Vec::with_capacity(MAX_CONTROL_DATAGRAM),
            file_name: String::new(),
            file_size: 0,
            file_mtime: 0,
            max_chunk: DEFAULT_CHUNK,
            final_path: PathBuf::new(),
            part_path: PathBuf::new(),
            writer: None,
            received: RangeSet::new(),
            highest: 0,
            resumed_from: 0,
            pkts_since_ack: 0,
            last_ack_at: now,
            immediate_ack_at: None,
            last_data_ts: 0,
            last_data_at: now,
            persist_dirty: false,
            last_persist_at: now,
            flush_in_progress: false,
            flush_snapshot: None,
            start: now,
            last_rx: now,
            stalled: false,
            last_progress_at: now,
            last_progress_bytes: 0,
            retransmitted_bytes: 0,
            writer_full_drops: 0,
            got_data: false,
            phase: Phase::Receiving,
        }
    }

    fn tid_hex(&self) -> String {
        hex16(&self.transfer_id)
    }

    fn key(&self) -> TransferKey {
        (self.sender, self.transfer_id)
    }

    /// Encrypts `msg` as a transport packet to the sender.
    fn send(&mut self, flags: u8, msg: &Message<'_>) {
        let Some(sec) = self.secure.as_mut() else {
            return;
        };
        let pn = sec.next_pn;
        sec.next_pn += 1;
        begin_packet(
            &mut self.tx_buf,
            sec.peer_cid,
            type_byte(msg.msg_type(), flags),
            pn,
        );
        wire::encode_body(msg, &mut self.tx_buf, MAX_CONTROL_BODY);
        if sec.keys.send.seal(&mut self.tx_buf).is_err() {
            return;
        }
        if let Err(e) = self.shared.socket.try_send_to(&self.tx_buf, self.peer) {
            if e.kind() != io::ErrorKind::WouldBlock {
                tracing::debug!("send {:?} failed: {}", msg.msg_type(), e);
            }
        }
    }

    // ----- lifecycle -------------------------------------------------------

    /// Runs the session; returns its key when it ends.
    async fn run(mut self, mut rx: mpsc::Receiver<Incoming>) -> TransferKey {
        // The session was created for its first handshake.
        let first = loop {
            match rx.recv().await {
                Some(Incoming::Handshake(h)) => break h,
                Some(_) => {}
                None => return self.key(),
            }
        };
        let Some(mut decision) = self.start(*first) else {
            return self.key();
        };

        let cancel = self.shared.cancel.clone();
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut progress = tokio::time::interval(self.cfg.progress_interval);
        progress.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            let ack_wait = self.next_ack_delay(Instant::now());
            tokio::select! {
                msg = rx.recv() => {
                    let Some(msg) = msg else {
                        self.stop(&mut rx, "dispatcher dropped the session").await;
                        return self.key();
                    };
                    if self.handle(msg).await.is_break() {
                        return self.key();
                    }
                    // Drain what is already queued before looking at timers.
                    for _ in 0..SESSION_BATCH {
                        let Ok(msg) = rx.try_recv() else { break };
                        if self.handle(msg).await.is_break() {
                            return self.key();
                        }
                    }
                }
                accepted = decided(&mut decision) => {
                    decision = None;
                    if self.on_decision(accepted).is_break() {
                        return self.key();
                    }
                }
                _ = tokio::time::sleep(ack_wait.unwrap_or(Duration::from_secs(3600))), if ack_wait.is_some() => {
                    self.send_ack(Instant::now());
                }
                _ = tick.tick() => {
                    if self.housekeeping(Instant::now()).await.is_break() {
                        return self.key();
                    }
                }
                _ = progress.tick() => {
                    self.emit_progress(Instant::now());
                }
                _ = cancel.cancelled() => {
                    self.stop(&mut rx, "receiver shutting down").await;
                    return self.key();
                }
            }
        }
    }

    /// Ends the session from outside (shutdown): a transfer in progress is
    /// suspended for resume, a complete file is kept and reported as such.
    async fn stop(&mut self, rx: &mut mpsc::Receiver<Incoming>, why: &str) {
        match &self.phase {
            Phase::Verifying => {
                // Let the verification finish so the file ends up in place.
                while let Some(msg) = rx.recv().await {
                    if let Incoming::Verified(r) = msg {
                        match r {
                            Ok((hash, path)) => {
                                self.final_path = path;
                                self.complete(hash, false);
                            }
                            Err(e) => self.report_failure(e, true),
                        }
                        break;
                    }
                }
            }
            // The file is complete, verified and in place; only the sender's
            // confirmation is missing.
            Phase::Finishing { hash, .. } => {
                let hash = *hash;
                self.complete(hash, false);
            }
            Phase::Pending { .. } => self.emit_failed(why.to_string(), false),
            Phase::Receiving => self.suspend(why).await,
        }
    }

    async fn handle(&mut self, msg: Incoming) -> ControlFlow<()> {
        match msg {
            Incoming::Packet { data, from, at } => self.on_packet(data, from, at).await,
            Incoming::Handshake(h) => {
                // The sender performed a new handshake (after an outage or a
                // restart): answer with our current state under new keys.
                self.last_rx = h.at;
                self.respond(*h);
                ControlFlow::Continue(())
            }
            Incoming::FlushDone(result) => {
                self.on_flush_done(result);
                ControlFlow::Continue(())
            }
            Incoming::Verified(result) => self.on_verified(result),
        }
    }

    /// Decides on the transfer and answers its first handshake. Returns the
    /// pending decision (if the application has to decide), or `None` when
    /// the transfer was rejected.
    fn start(&mut self, h: Handshake) -> Option<Option<oneshot::Receiver<bool>>> {
        self.peer = h.from;
        self.last_rx = h.at;
        let hello = h.init.hello.clone();
        if let Err((reason, message)) = self.prepare(&hello) {
            self.reject_handshake(h, reason, &message);
            return None;
        }
        emit(
            &self.events,
            TransferEvent::IncomingRequest {
                transfer_id: self.tid_hex(),
                peer: self.peer.to_string(),
                sender_id: self.sender.to_string(),
                file_name: self.file_name.clone(),
                file_size: self.file_size,
                resumed_bytes: self.received.total(),
            },
        );
        match self.shared.cfg.accept.clone() {
            AcceptPolicy::AcceptAll => {
                if let Err(message) = self.create_file() {
                    self.reject_handshake(h, REASON_INTERNAL, &message);
                    return None;
                }
                self.phase = Phase::Receiving;
                self.respond(h);
                self.on_accepted();
                Some(None)
            }
            AcceptPolicy::Ask(cb) => {
                let (tx, rx) = oneshot::channel();
                cb(
                    IncomingRequest {
                        transfer_id: self.tid_hex(),
                        peer: self.peer,
                        sender_id: self.sender,
                        file_name: self.file_name.clone(),
                        file_size: self.file_size,
                        resumed_bytes: self.received.total(),
                    },
                    tx,
                );
                self.phase = Phase::Pending {
                    deadline: Instant::now() + self.cfg.handshake_timeout,
                };
                self.respond(h);
                Some(Some(rx))
            }
        }
    }

    /// The application accepted or declined a pending transfer.
    fn on_decision(&mut self, accepted: bool) -> ControlFlow<()> {
        if !matches!(self.phase, Phase::Pending { .. }) {
            return ControlFlow::Continue(());
        }
        if !accepted {
            self.send_rejection(REASON_DECLINED, "declined by user");
            self.emit_failed("declined by user".into(), false);
            return ControlFlow::Break(());
        }
        if let Err(message) = self.create_file() {
            self.send_rejection(REASON_INTERNAL, &message);
            self.report_failure(message, false);
            return ControlFlow::Break(());
        }
        self.phase = Phase::Receiving;
        // Tell the sender right away instead of at its next poll.
        let (ack, flags) = self.current_ack(0, SUPPORTED_CAPS);
        self.send(flags, &Message::HelloAck(ack));
        self.on_accepted();
        ControlFlow::Continue(())
    }

    fn on_accepted(&mut self) {
        let cipher = self
            .secure
            .as_ref()
            .map(|s| s.keys.suite.name())
            .unwrap_or("none");
        tracing::info!(
            "transfer {} from {} ({}): {} ({} bytes) -> {}, {}",
            self.tid_hex(),
            self.peer,
            self.sender,
            self.file_name,
            self.file_size,
            self.final_path.display(),
            cipher
        );
        emit(
            &self.events,
            TransferEvent::Started {
                transfer_id: self.tid_hex(),
                peer: self.peer.to_string(),
                peer_id: self.sender.to_string(),
                cipher: cipher.to_string(),
                file_name: self.file_name.clone(),
                file_size: self.file_size,
                resumed_from: self.resumed_from,
                chunk_size: self.max_chunk,
            },
        );
        if self.received.total() >= self.file_size {
            self.begin_finishing();
        }
    }

    /// Validates the request and resolves resume state and paths. The file
    /// itself is created by [`Session::create_file`] once accepted.
    fn prepare(&mut self, hello: &Hello) -> Result<(), (u8, String)> {
        let Some(name) = sanitize_file_name(&hello.file_name) else {
            return Err((REASON_BAD_FILE_NAME, "file name is not acceptable".into()));
        };
        self.file_name = name.clone();
        self.file_size = hello.file_size;
        self.file_mtime = hello.file_mtime;
        self.max_chunk = hello.max_chunk.min(self.cfg.max_chunk).max(MIN_CHUNK);
        let out_dir = self.shared.cfg.output_dir.clone();

        // Resume: by transfer id first, then by file identity (name, size and
        // source modification time, so that a changed source starts afresh
        // instead of failing the whole-file check at the very end). Only the
        // sender that started a partial file may continue it.
        let tid_hex = self.tid_hex();
        let sender = self.sender.to_string();
        let saved = self.shared.store.as_ref().and_then(|st| {
            st.load_receiver(&tid_hex)
                .filter(|s| {
                    s.sender == sender
                        && s.file_size == hello.file_size
                        && s.file_mtime == hello.file_mtime
                        && s.part_path.exists()
                })
                .or_else(|| {
                    st.find_receiver_by_file(&sender, &name, hello.file_size, hello.file_mtime)
                })
        });
        let mut durable = RangeSet::new();
        if let Some(saved) = &saved {
            let ok_len = std::fs::metadata(&saved.part_path)
                .map(|m| m.len() == hello.file_size)
                .unwrap_or(false);
            if ok_len {
                durable = saved.durable_set();
                self.part_path = saved.part_path.clone();
                self.final_path = saved.final_path.clone();
                if saved.transfer_id != tid_hex {
                    if let Some(st) = &self.shared.store {
                        st.remove_receiver(&saved.transfer_id);
                    }
                }
                tracing::info!(
                    "resuming {}: {} of {} bytes already on disk",
                    name,
                    durable.total(),
                    hello.file_size
                );
            }
        }
        if self.part_path.as_os_str().is_empty() {
            let final_path = if self.shared.cfg.overwrite {
                out_dir.join(&name)
            } else {
                unique_path(&out_dir, &name)
            };
            let mut part = part_path_for(&final_path);
            if part.exists() {
                // An unrelated leftover; do not clobber it.
                part = unique_path(&out_dir, &format!("{}{}", name, crate::file::PART_SUFFIX));
            }
            self.final_path = final_path;
            self.part_path = part;
        }

        let needed = hello.file_size.saturating_sub(durable.total());
        match available_space(&out_dir) {
            Ok(avail) if avail < needed.saturating_add(1 << 20) => {
                return Err((
                    REASON_DISK_SPACE,
                    format!("need {} bytes, {} available", needed, avail),
                ));
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("cannot query free space: {}", e),
        }
        self.received = durable;
        self.highest = self.received.last_end().unwrap_or(0);
        self.resumed_from = self.received.total();
        Ok(())
    }

    /// Opens (creates or reopens) the partial file.
    fn create_file(&mut self) -> Result<(), String> {
        let writer = FileWriter::open(
            &self.part_path,
            self.file_size,
            self.cfg.writer_capacity_bytes,
        )
        .map_err(|e| format!("cannot open output file: {}", e))?;
        self.writer = Some(writer);
        self.persist_state_now();
        Ok(())
    }

    /// The HELLO_ACK describing our current state.
    fn current_ack(&self, echo_ts: u32, offered_caps: u32) -> (HelloAck, u8) {
        let max_ack_delay_us = self.cfg.ack_interval.as_micros().min(u32::MAX as u128) as u32;
        if matches!(self.phase, Phase::Pending { .. }) {
            let ack = HelloAck {
                status: HELLO_PENDING,
                reason: REASON_NONE,
                max_chunk: self.max_chunk,
                capabilities: offered_caps & SUPPORTED_CAPS,
                echo_ts,
                max_ack_delay_us,
                rwnd: 0,
                resume_upto: 0,
                known_end: 0,
                holes: Vec::new(),
                message: String::new(),
            };
            return (ack, 0);
        }
        let contiguous = self.received.contiguous_from(0);
        let last = self.received.last_end().unwrap_or(0).max(contiguous);
        let (holes, known_end) = self.describe(contiguous, last);
        let ack = HelloAck {
            status: HELLO_ACCEPTED,
            reason: REASON_NONE,
            max_chunk: self.max_chunk,
            capabilities: offered_caps & SUPPORTED_CAPS,
            echo_ts,
            max_ack_delay_us,
            rwnd: self.rwnd(),
            resume_upto: contiguous,
            known_end,
            holes,
            message: String::new(),
        };
        let flags = if self.resumed_from > 0 {
            HELLO_ACK_FLAG_RESUMED
        } else {
            0
        };
        (ack, flags)
    }

    /// Answers a handshake with our current state and switches to its keys.
    fn respond(&mut self, h: Handshake) {
        let hello = &h.init.hello;
        let (ack, ack_flags) = self.current_ack(hello.timestamp, hello.capabilities);
        let payload = wire::encode_response(&wire::Response {
            suite: h.suite as u8,
            ack_flags,
            ack,
        });
        let sender_cid = h.incoming.sender_cid;
        match h.incoming.respond(h.cid, &payload) {
            Ok((pkt, split)) => {
                self.secure = Some(Secure {
                    keys: SessionKeys::derive(&split, false, h.suite),
                    local_cid: h.cid,
                    peer_cid: sender_cid,
                    next_pn: 0,
                    replay: ReplayWindow::new(),
                    auth_failures: 0,
                });
                self.peer = h.from;
                if let Err(e) = self.shared.socket.try_send_to(&pkt, h.from) {
                    tracing::debug!("sending handshake response failed: {}", e);
                }
            }
            Err(e) => tracing::warn!("cannot answer handshake: {}", e),
        }
    }

    /// Rejects the transfer in the handshake response (no session keys).
    fn reject_handshake(&mut self, h: Handshake, reason: u8, message: &str) {
        tracing::info!("rejected transfer from {}: {}", h.from, message);
        let payload = wire::encode_response(&wire::Response {
            suite: 0,
            ack_flags: 0,
            ack: rejection(h.init.hello.timestamp, reason, message),
        });
        if let Ok((pkt, _)) = h.incoming.respond(h.cid, &payload) {
            let _ = self.shared.socket.try_send_to(&pkt, h.from);
        }
    }

    /// Rejects the transfer over the established session.
    fn send_rejection(&mut self, reason: u8, message: &str) {
        tracing::info!("rejected transfer {}: {}", self.tid_hex(), message);
        let ack = rejection(0, reason, message);
        for _ in 0..2 {
            self.send(0, &Message::HelloAck(ack.clone()));
        }
    }

    /// Holes in `[from, to)`, complete for the (possibly shortened)
    /// interval they describe; see [`wire::describe_holes`].
    fn describe(&self, from: u64, to: u64) -> (Vec<(u64, u64)>, u64) {
        wire::describe_holes(&self.received, from, to)
    }

    fn rwnd(&self) -> u64 {
        match &self.writer {
            Some(w) => w.available(),
            None if matches!(self.phase, Phase::Receiving | Phase::Pending { .. }) => {
                self.cfg.writer_capacity_bytes
            }
            None => 0,
        }
    }

    /// Answers a HELLO frame (a state query or a decision poll).
    fn answer_hello(&mut self, hello: &Hello) {
        let (ack, flags) = self.current_ack(hello.timestamp, hello.capabilities);
        self.send(flags, &Message::HelloAck(ack));
    }

    // ----- packets ---------------------------------------------------------

    async fn on_packet(
        &mut self,
        mut data: Vec<u8>,
        from: SocketAddr,
        at: Instant,
    ) -> ControlFlow<()> {
        let Some(sec) = self.secure.as_mut() else {
            return ControlFlow::Continue(());
        };
        // Packets for a connection id we replaced are stale.
        if peek_cid(&data) != Some(sec.local_cid) {
            return ControlFlow::Continue(());
        }
        let tb = match sec.keys.recv.open(&mut data) {
            Ok((tb, pn, _)) => {
                if !sec.replay.accept(pn) {
                    return ControlFlow::Continue(());
                }
                tb
            }
            Err(_) => {
                sec.auth_failures += 1;
                return ControlFlow::Continue(());
            }
        };
        let Ok((msg_type, flags)) = parse_type_byte(tb) else {
            return ControlFlow::Continue(());
        };
        let body_end = data.len() - TAG_LEN;
        self.last_rx = at;
        if self.stalled {
            self.stalled = false;
            emit(
                &self.events,
                TransferEvent::Recovered {
                    transfer_id: self.tid_hex(),
                },
            );
        }
        if from != self.peer {
            tracing::info!("sender address changed {} -> {}", self.peer, from);
            self.peer = from;
        }

        // DATA: hand the datagram over by value so the payload goes to the
        // writer without another copy.
        if msg_type == MsgType::Data {
            let body = &data[HEADER_LEN..body_end];
            if body.len() < DATA_FIXED_LEN {
                return ControlFlow::Continue(());
            }
            let offset = u64::from_be_bytes(body[..8].try_into().unwrap());
            let ts = u32::from_be_bytes(body[8..12].try_into().unwrap());
            let len = body.len() - DATA_FIXED_LEN;
            if flags & DATA_FLAG_RETRANSMIT != 0 {
                self.retransmitted_bytes += len as u64;
            }
            self.on_data(offset, ts, data, HEADER_LEN + DATA_FIXED_LEN, len, at);
            return ControlFlow::Continue(());
        }

        let decoded = match wire::decode_body(msg_type, &data[HEADER_LEN..body_end]) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("malformed {:?}: {}", msg_type, e);
                return ControlFlow::Continue(());
            }
        };
        match decoded {
            Message::Hello(h) => {
                if h.transfer_id == self.transfer_id {
                    self.answer_hello(&h);
                }
            }
            Message::Ping(p) => {
                self.send(0, &Message::Pong(Pong { echo: p.timestamp }));
            }
            Message::Probe(_) => {
                let size = data.len().min(u16::MAX as usize) as u16;
                self.send(0, &Message::ProbeAck(ProbeAck { size }));
            }
            Message::FinAck(f) => {
                if let Phase::Finishing { hash, .. } = &self.phase {
                    let hash = *hash;
                    // Lets the sender exit now instead of lingering for a
                    // repeated FIN; if this is lost, it lingers as before.
                    self.send(0, &Message::FinDone(wire::FinDone { verdict: f.verdict }));
                    if f.verdict == VERDICT_OK {
                        self.complete(hash, true);
                    } else {
                        self.fail_mismatch(hash, f.file_hash);
                    }
                    return ControlFlow::Break(());
                }
            }
            Message::Abort(a) => {
                tracing::warn!(
                    "sender aborted transfer {}: {} ({})",
                    self.tid_hex(),
                    a.reason,
                    a.code
                );
                let why = format!("aborted by sender: {}", a.reason);
                match self.phase {
                    Phase::Receiving => {
                        if self.got_data {
                            self.suspend(&why).await;
                        } else {
                            self.abandon_idle(&why).await;
                        }
                        return ControlFlow::Break(());
                    }
                    Phase::Pending { .. } => {
                        self.emit_failed(why, false);
                        return ControlFlow::Break(());
                    }
                    Phase::Verifying | Phase::Finishing { .. } => {}
                }
            }
            Message::Data(_)
            | Message::HelloAck(_)
            | Message::Ack(_)
            | Message::Fin(_)
            | Message::Pong(_)
            | Message::ProbeAck(_)
            | Message::FinDone(_) => {}
        }
        ControlFlow::Continue(())
    }

    /// Handles a DATA payload `datagram[start..start + len]` for `offset`.
    fn on_data(
        &mut self,
        offset: u64,
        ts: u32,
        datagram: Vec<u8>,
        start: usize,
        len: usize,
        at: Instant,
    ) {
        if !matches!(self.phase, Phase::Receiving) {
            return;
        }
        let len64 = len as u64;
        let end = match offset.checked_add(len64) {
            Some(end) if len > 0 && len64 <= MAX_CHUNK as u64 && end <= self.file_size => end,
            _ => {
                tracing::debug!("ignoring DATA outside file: offset {} len {}", offset, len);
                return;
            }
        };
        let prev_highest = self.highest;
        let missing = self.received.holes(offset, end, usize::MAX);
        if !missing.is_empty() {
            let Some(writer) = &self.writer else { return };
            let need: u64 = missing.iter().map(|&(s, e)| e - s).sum();
            if writer.available() < need {
                // Writer saturated: drop the packet without recording it; the
                // shrinking receive window slows the sender down.
                self.writer_full_drops += 1;
                return;
            }
            if missing.len() == 1 && missing[0] == (offset, end) {
                if writer.enqueue_slice(offset, datagram, start, len).is_err() {
                    self.writer_full_drops += 1;
                    return;
                }
                self.received.insert(offset, end);
            } else {
                // Partly known already (resent after a chunk-size change):
                // write only the new sub-ranges.
                for (s, e) in missing {
                    let a = start + (s - offset) as usize;
                    let b = start + (e - offset) as usize;
                    if writer.enqueue(s, datagram[a..b].to_vec()).is_err() {
                        self.writer_full_drops += 1;
                        break;
                    }
                    self.received.insert(s, e);
                }
            }
            self.persist_dirty = true;
            self.got_data = true;
        }
        self.highest = self.highest.max(end);
        self.last_data_ts = ts;
        self.last_data_at = at;
        self.pkts_since_ack += 1;
        if offset > prev_highest && self.immediate_ack_at.is_none() {
            // A gap appeared: ACK soon so the sender can retransmit quickly,
            // but leave a moment for reordered packets to arrive.
            self.immediate_ack_at = Some(at + Duration::from_millis(2));
        }
        if self.pkts_since_ack >= self.cfg.ack_every_packets {
            self.send_ack(at);
        }
        if self.received.total() >= self.file_size {
            self.send_ack(at);
            self.begin_finishing();
        }
    }

    fn next_ack_delay(&self, now: Instant) -> Option<Duration> {
        if !matches!(self.phase, Phase::Receiving) {
            return None;
        }
        let mut deadline: Option<Instant> = self.immediate_ack_at;
        if self.pkts_since_ack > 0 {
            let t = self.last_ack_at + self.cfg.ack_interval;
            deadline = Some(deadline.map_or(t, |d| d.min(t)));
        }
        // Holes below the highest offset: keep reporting them so that lost
        // retransmissions are requested again even when no new data arrives.
        if self.received.contiguous_from(0) < self.highest {
            let t = self.last_ack_at + Duration::from_millis(200);
            deadline = Some(deadline.map_or(t, |d| d.min(t)));
        }
        deadline.map(|d| d.saturating_duration_since(now))
    }

    fn send_ack(&mut self, now: Instant) {
        let contiguous = self.received.contiguous_from(0);
        let (holes, described) = self.describe(contiguous, self.highest.max(contiguous));
        let ack_delay_us = if self.last_data_ts != 0 {
            now.saturating_duration_since(self.last_data_at)
                .as_micros()
                .min(u32::MAX as u128) as u32
        } else {
            0
        };
        let ack = Ack {
            contiguous_upto: contiguous,
            highest: described,
            received_bytes: self.received.total(),
            echo_ts: self.last_data_ts,
            ack_delay_us,
            rwnd: self.rwnd(),
            holes,
        };
        self.send(0, &Message::Ack(ack));
        self.pkts_since_ack = 0;
        self.last_ack_at = now;
        self.immediate_ack_at = None;
        // Echo each timestamp once: a later ACK must not reuse it, otherwise
        // the sender would compute an inflated RTT.
        self.last_data_ts = 0;
    }

    // ----- persistence -----------------------------------------------------

    fn state(&self, durable: &RangeSet) -> ReceiverState {
        ReceiverState {
            format: 0,
            transfer_id: self.tid_hex(),
            file_name: self.file_name.clone(),
            file_size: self.file_size,
            file_mtime: self.file_mtime,
            part_path: self.part_path.clone(),
            final_path: self.final_path.clone(),
            peer: self.peer.to_string(),
            sender: self.sender.to_string(),
            durable: durable.to_vec(),
            updated_unix: 0,
        }
    }

    /// Persists `received` as durable. Only valid when everything in it is
    /// known to be on disk (right after open, or after the writer closed).
    fn persist_state_now(&mut self) {
        if let Some(store) = &self.shared.store {
            if let Err(e) = store.save_receiver(&self.state(&self.received)) {
                tracing::warn!("cannot save resume state: {}", e);
            }
        }
        self.last_persist_at = Instant::now();
        self.persist_dirty = false;
    }

    fn request_flush(&mut self) {
        let Some(writer) = &self.writer else { return };
        let rx = writer.flush();
        self.flush_in_progress = true;
        self.flush_snapshot = Some(self.received.clone());
        self.persist_dirty = false;
        let tx = self.self_tx.clone();
        tokio::spawn(async move {
            let result = match rx.await {
                Ok(r) => r,
                Err(_) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "writer gone")),
            };
            let _ = tx.send(Incoming::FlushDone(result)).await;
        });
    }

    fn on_flush_done(&mut self, result: io::Result<()>) {
        self.flush_in_progress = false;
        let snapshot = self.flush_snapshot.take();
        match (result, snapshot) {
            (Ok(()), Some(snapshot)) => {
                if matches!(self.phase, Phase::Receiving) {
                    if let Some(store) = &self.shared.store {
                        if let Err(e) = store.save_receiver(&self.state(&snapshot)) {
                            tracing::warn!("cannot save resume state: {}", e);
                        }
                    }
                }
                self.last_persist_at = Instant::now();
            }
            (Err(e), _) => tracing::warn!("fsync failed: {}", e),
            _ => {}
        }
    }

    // ----- housekeeping ----------------------------------------------------

    async fn housekeeping(&mut self, now: Instant) -> ControlFlow<()> {
        let since_rx = now.saturating_duration_since(self.last_rx);
        match &mut self.phase {
            Phase::Receiving => {
                if self.persist_dirty
                    && !self.flush_in_progress
                    && now.saturating_duration_since(self.last_persist_at)
                        >= self.cfg.persist_interval
                {
                    self.request_flush();
                }
            }
            Phase::Finishing {
                hash,
                next_fin_at,
                fin_delay,
                started_at,
            } => {
                let hash = *hash;
                let waited = now.saturating_duration_since(*started_at);
                // The file is complete and verified locally; stop waiting for
                // the sender's verdict once it has gone quiet (or after the
                // overall limit).
                if since_rx >= self.cfg.stall_timeout || waited >= self.cfg.give_up_timeout {
                    tracing::warn!("no FIN_ACK from sender; file is complete and verified locally");
                    self.complete(hash, false);
                    return ControlFlow::Break(());
                }
                if now >= *next_fin_at {
                    *fin_delay = (*fin_delay * 2).min(Duration::from_secs(3));
                    *next_fin_at = now + *fin_delay;
                    self.send(0, &Message::Fin(Fin { file_hash: hash }));
                }
                return ControlFlow::Continue(());
            }
            Phase::Pending { deadline } => {
                if now >= *deadline {
                    self.send_rejection(REASON_TIMEOUT, "no decision in time");
                    self.emit_failed("no decision in time".into(), false);
                    return ControlFlow::Break(());
                }
                return ControlFlow::Continue(());
            }
            Phase::Verifying => return ControlFlow::Continue(()),
        }

        if since_rx >= self.cfg.stall_timeout && !self.stalled {
            self.stalled = true;
            tracing::warn!("no packets from {} for {:?}", self.peer, since_rx);
            emit(
                &self.events,
                TransferEvent::Stalled {
                    transfer_id: self.tid_hex(),
                    since: since_rx,
                },
            );
            if !self.flush_in_progress {
                self.request_flush();
            }
        }
        // A session that never received data (sender vanished right after
        // the handshake, or a spoofed HELLO) must not hold a slot for long.
        if !self.got_data && since_rx >= self.cfg.handshake_timeout {
            self.abandon_idle("sender sent no data after the handshake")
                .await;
            return ControlFlow::Break(());
        }
        if since_rx >= self.cfg.session_ttl {
            self.suspend("sender silent for too long").await;
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }

    /// Ends a session that received no data. A partial file created for it
    /// is removed; one resumed from an earlier attempt is kept for resume.
    async fn abandon_idle(&mut self, why: &str) {
        if self.resumed_from > 0 {
            self.suspend(why).await;
            return;
        }
        tracing::info!(
            "transfer {} from {}: {}; dropping the empty session",
            self.tid_hex(),
            self.peer,
            why
        );
        if let Some(writer) = self.writer.take() {
            let _ = writer.close().await;
        }
        let _ = std::fs::remove_file(&self.part_path);
        if let Some(store) = &self.shared.store {
            store.remove_receiver(&self.tid_hex());
        }
        self.emit_failed(why.to_string(), false);
    }

    // ----- completion ------------------------------------------------------

    fn begin_finishing(&mut self) {
        if !matches!(self.phase, Phase::Receiving) {
            return;
        }
        let Some(writer) = self.writer.take() else {
            return;
        };
        self.phase = Phase::Verifying;
        tracing::info!(
            "transfer {}: all {} bytes received; verifying",
            self.tid_hex(),
            self.file_size
        );
        let part = self.part_path.clone();
        let final_path = self.final_path.clone();
        let overwrite = self.shared.cfg.overwrite;
        let tx = self.self_tx.clone();
        tokio::spawn(async move {
            let result = finish_file(writer, part, final_path, overwrite).await;
            let _ = tx.send(Incoming::Verified(result)).await;
        });
    }

    fn on_verified(&mut self, result: Result<([u8; 32], PathBuf), String>) -> ControlFlow<()> {
        if !matches!(self.phase, Phase::Verifying) {
            return ControlFlow::Continue(());
        }
        match result {
            Ok((hash, path)) => {
                self.final_path = path;
                let now = Instant::now();
                tracing::info!(
                    "transfer {} stored as {} (BLAKE3 {}); confirming with sender",
                    self.tid_hex(),
                    self.final_path.display(),
                    hash_to_hex(&hash)
                );
                self.send(0, &Message::Fin(Fin { file_hash: hash }));
                self.phase = Phase::Finishing {
                    hash,
                    next_fin_at: now + Duration::from_millis(200),
                    fin_delay: Duration::from_millis(200),
                    started_at: now,
                };
                ControlFlow::Continue(())
            }
            Err(msg) => {
                self.send(
                    0,
                    &Message::Abort(wire::Abort {
                        code: ABORT_IO_ERROR,
                        reason: msg.clone(),
                    }),
                );
                self.report_failure(msg, true);
                ControlFlow::Break(())
            }
        }
    }

    fn complete(&mut self, hash: [u8; 32], peer_confirmed: bool) {
        if let Some(store) = &self.shared.store {
            store.remove_receiver(&self.tid_hex());
        }
        let stats = self.stats(Instant::now());
        tracing::info!(
            "transfer {} finished{}: {} in {:.2?}, avg {:.1} Mbit/s",
            self.tid_hex(),
            if peer_confirmed {
                ""
            } else {
                " (unconfirmed by sender)"
            },
            self.final_path.display(),
            stats.elapsed,
            stats.avg_rate_bps / 1e6
        );
        emit(
            &self.events,
            TransferEvent::Completed {
                transfer_id: self.tid_hex(),
                file_name: self.file_name.clone(),
                path: Some(self.final_path.display().to_string()),
                file_hash_hex: hash_to_hex(&hash),
                peer_confirmed,
                stats,
            },
        );
    }

    fn fail_mismatch(&mut self, ours: [u8; 32], theirs: [u8; 32]) {
        if let Some(store) = &self.shared.store {
            store.remove_receiver(&self.tid_hex());
        }
        let msg = format!(
            "whole-file hash mismatch: receiver {}, sender {}",
            hash_to_hex(&ours),
            hash_to_hex(&theirs)
        );
        tracing::error!("transfer {}: {}", self.tid_hex(), msg);
        let bad = {
            let mut s = self.final_path.as_os_str().to_owned();
            s.push(".mismatch");
            PathBuf::from(s)
        };
        let _ = std::fs::rename(&self.final_path, &bad);
        self.report_failure(msg, false);
    }

    fn report_failure(&self, error: String, resumable: bool) {
        tracing::error!("transfer {}: {}", self.tid_hex(), error);
        self.emit_failed(error, resumable);
    }

    fn emit_failed(&self, error: String, resumable: bool) {
        emit(
            &self.events,
            TransferEvent::Failed {
                transfer_id: self.tid_hex(),
                error,
                resumable,
            },
        );
    }

    /// Stops the session but keeps the partial file and its state for resume,
    /// and reports that to the application.
    async fn suspend(&mut self, why: &str) {
        tracing::info!("transfer {} suspended: {}", self.tid_hex(), why);
        if self.writer_full_drops > 0 {
            tracing::debug!(
                "transfer {}: {} packets dropped because the writer was saturated",
                self.tid_hex(),
                self.writer_full_drops
            );
        }
        if let Some(writer) = self.writer.take() {
            match writer.close().await {
                Ok(()) => {
                    if matches!(self.phase, Phase::Receiving) {
                        // Everything in `received` is now written and synced.
                        self.persist_state_now();
                    }
                }
                Err(e) => tracing::warn!("closing partial file failed: {}", e),
            }
        }
        self.emit_failed(format!("{}; partial file kept for resume", why), true);
    }

    // ----- stats -----------------------------------------------------------

    fn stats(&mut self, now: Instant) -> TransferStats {
        let done = self.received.total();
        let elapsed = now.saturating_duration_since(self.start);
        let dt = now
            .saturating_duration_since(self.last_progress_at)
            .as_secs_f64();
        let delta = done.saturating_sub(self.last_progress_bytes);
        let rate = if dt > 0.0 {
            delta as f64 * 8.0 / dt
        } else {
            0.0
        };
        let moved = done.saturating_sub(self.resumed_from);
        let avg = if elapsed.as_secs_f64() > 0.0 {
            moved as f64 * 8.0 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let remaining = self.file_size.saturating_sub(done);
        TransferStats {
            transfer_id: self.tid_hex(),
            bytes_done: done,
            total_bytes: self.file_size,
            rate_bps: rate,
            avg_rate_bps: avg,
            rtt_ms: 0.0,
            cwnd_bytes: 0,
            inflight_bytes: 0,
            chunk_size: self.max_chunk,
            retransmitted_bytes: self.retransmitted_bytes,
            loss_events: 0,
            elapsed,
            eta: if rate > 0.0 {
                Some(Duration::from_secs_f64(remaining as f64 * 8.0 / rate))
            } else {
                None
            },
            stalled: self.stalled,
        }
    }

    fn emit_progress(&mut self, now: Instant) {
        if !matches!(self.phase, Phase::Receiving) {
            return;
        }
        let stats = self.stats(now);
        self.last_progress_at = now;
        self.last_progress_bytes = stats.bytes_done;
        emit(&self.events, TransferEvent::Progress(stats));
    }
}
