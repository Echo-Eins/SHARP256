//! Sending side of a SHARP-256 transfer.
//!
//! One `Sender` moves one file to one receiver. The engine is a single-owner
//! state machine. Each turn of its loop drains every datagram already queued
//! on the socket, runs timers, and then sends as much as the congestion
//! window, the receiver window and the pacer allow:
//!
//! * `pending` — byte ranges that still have to be (re)sent;
//! * `inflight` — ranges sent but not yet acknowledged, with send times;
//! * selective ACKs retire in-flight ranges, report holes (fast retransmit)
//!   and carry RTT samples; holes that are neither in flight nor queued are
//!   re-queued, so the sender's bookkeeping heals itself;
//! * RTO expiry returns stale in-flight ranges to `pending`;
//! * after a few seconds of silence the sender performs a new handshake,
//!   whose answer tells exactly what a live receiver holds and lets a
//!   restarted receiver resume from its saved state;
//! * the transfer completes when the receiver's whole-file BLAKE3 hash
//!   matches the sender's own.
//!
//! Every datagram after the handshake is an encrypted transport packet
//! (`crypto::transport`); the handshake authenticates the receiver by the
//! SHARP ID the sender was given.

use crate::config::{SenderConfig, TransportConfig};
use crate::crypto::handshake::{self as hs, Initiator, COOKIE_REPLY_LEN};
use crate::crypto::replay::ReplayWindow;
use crate::crypto::transport::{begin_packet, peek_cid, SessionKeys, Suite};
use crate::crypto::{CryptoError, Identity, SharpId, NO_PSK};
use crate::file::{hash_file, hash_to_hex, sanitize_file_name, FileReader};
use crate::progress::{emit, EventCallback, TransferEvent, TransferStats};
use crate::protocol::constants::*;
use crate::protocol::wire::{
    self, type_byte, Abort, Hello, HelloAck, Message, MsgType, Ping, Probe, MAX_CONTROL_BODY,
};
use crate::protocol::RangeSet;
use crate::state::{hex16, parse_hex16, SenderState, StateStore};
use crate::transport::congestion::{burst_for_rate, Cubic, Pacer, RttEstimator};
use crate::transport::socket::{bind_udp, is_msgsize_error, Clock};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid file name: {0}")]
    BadFileName(String),
    #[error("receiver rejected the transfer ({reason}): {message}")]
    Rejected { reason: String, message: String },
    #[error(
        "no answer from receiver within the handshake timeout (wrong address or receiver ID?)"
    )]
    HandshakeTimeout,
    #[error("handshake with the receiver failed: {0}")]
    Handshake(String),
    #[error("identity: {0}")]
    Identity(String),
    #[error("receiver unreachable for {0:?}; transfer state kept for resume")]
    PeerUnreachable(Duration),
    #[error("whole-file hash mismatch: sender {sender}, receiver {receiver}")]
    HashMismatch { sender: String, receiver: String },
    #[error("cancelled")]
    Cancelled,
    #[error("aborted by receiver (code {code}): {reason}")]
    Aborted { code: u16, reason: String },
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Result of a successful transfer.
#[derive(Debug, Clone)]
pub struct TransferSummary {
    pub transfer_id: String,
    pub file_size: u64,
    pub resumed_from: u64,
    pub bytes_sent: u64,
    pub retransmitted_bytes: u64,
    pub loss_events: u64,
    pub rto_events: u64,
    pub chunk_size: u16,
    pub elapsed: Duration,
    pub avg_rate_bps: f64,
    pub file_hash_hex: String,
}

pub struct Sender {
    cfg: SenderConfig,
    identity: Identity,
    socket: Arc<UdpSocket>,
    reader: Arc<FileReader>,
    cancel: CancellationToken,
    store: Option<StateStore>,
}

impl Sender {
    /// Binds the socket and opens the file. Nothing is sent yet.
    pub async fn new(cfg: SenderConfig) -> Result<Self, SendError> {
        let cfg = SenderConfig {
            transport: cfg.transport.normalized(),
            ..cfg
        };
        let identity = match &cfg.identity {
            Some(id) => id.clone(),
            None => {
                let path = Identity::default_path()
                    .ok_or_else(|| SendError::Identity("no per-user data directory".into()))?;
                Identity::load_or_create(&path)
                    .map_err(|e| SendError::Identity(format!("{}: {}", path.display(), e)))?
            }
        };
        let reader = FileReader::open(&cfg.file_path)?;
        let socket = bind_udp(cfg.bind, cfg.transport.socket_buffer_bytes)?;
        tracing::info!(
            "sender bound to {}, file {} ({} bytes)",
            socket.local_addr()?,
            cfg.file_path.display(),
            reader.size()
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
            cfg,
            identity,
            socket: Arc::new(socket),
            reader: Arc::new(reader),
            cancel: CancellationToken::new(),
            store,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Our identity, as the receiver will see it.
    pub fn id(&self) -> SharpId {
        self.identity.id()
    }

    /// Token that cancels the transfer when triggered.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Runs the transfer to completion.
    pub async fn run(self) -> Result<TransferSummary, SendError> {
        let file_name = self
            .cfg
            .file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .and_then(|n| sanitize_file_name(&n))
            .ok_or_else(|| SendError::BadFileName(self.cfg.file_path.display().to_string()))?;

        let size = self.reader.size();
        let mtime = self.reader.mtime_unix();
        // Resume state is kept per receiver identity, not per address.
        let peer_str = self.cfg.receiver_id.to_string();
        // Present the id of an interrupted attempt so the receiver resumes
        // it, unless the file changed since (its data would not match).
        let transfer_id = self
            .store
            .as_ref()
            .and_then(|s| s.load_sender(&self.cfg.file_path, size, &peer_str))
            .filter(|st| st.file_mtime == mtime)
            .and_then(|st| parse_hex16(&st.transfer_id))
            .unwrap_or_else(rand::random::<[u8; 16]>);

        // Whole-file hash in the background; it is only needed at the end.
        let hash_path = self.cfg.file_path.clone();
        let hash_task: JoinHandle<io::Result<[u8; 32]>> =
            tokio::task::spawn_blocking(move || hash_file(&hash_path));

        let mut engine = Engine::new(
            self.cfg.transport.clone(),
            self.socket.clone(),
            self.cfg.peer,
            Peer {
                identity: self.identity.clone(),
                receiver: self.cfg.receiver_id,
                psk: self.cfg.psk.unwrap_or(NO_PSK),
            },
            self.reader.clone(),
            file_name,
            transfer_id,
            self.cfg.events.clone(),
            self.cancel.clone(),
        );

        let result = engine.run(hash_task).await;

        // Tell the receiver why the transfer ends, so that it releases the
        // session (keeping its resume state) at once instead of timing out.
        if let Err(err) = &result {
            let code = match err {
                SendError::Cancelled => Some(ABORT_CANCELLED),
                SendError::Io(_) => Some(ABORT_IO_ERROR),
                SendError::Protocol(_) => Some(ABORT_PROTOCOL),
                SendError::PeerUnreachable(_) | SendError::HandshakeTimeout => Some(ABORT_TIMEOUT),
                // The receiver decided these itself, already knows, or no
                // session exists to tell it through.
                SendError::BadFileName(_)
                | SendError::Rejected { .. }
                | SendError::HashMismatch { .. }
                | SendError::Aborted { .. }
                | SendError::Handshake(_)
                | SendError::Identity(_) => None,
            };
            if let Some(code) = code {
                engine.send_abort(code, &err.to_string());
            }
        }

        if let Some(store) = &self.store {
            match &result {
                Err(SendError::PeerUnreachable(_)) | Err(SendError::Cancelled) => {
                    let st = SenderState {
                        format: 0,
                        transfer_id: hex16(&transfer_id),
                        file_path: self.cfg.file_path.clone(),
                        file_size: size,
                        file_mtime: mtime,
                        peer: peer_str.clone(),
                        updated_unix: 0,
                    };
                    if let Err(e) = store.save_sender(&st) {
                        tracing::warn!("could not save sender state: {}", e);
                    }
                }
                _ => store.remove_sender(&self.cfg.file_path, size, &peer_str),
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Builds and seals a DATA packet in `out`.
fn seal_data(
    sec: &mut Secure,
    out: &mut Vec<u8>,
    flags: u8,
    offset: u64,
    timestamp: u32,
    payload: &[u8],
) -> Result<(), CryptoError> {
    let pn = sec.next_pn;
    sec.next_pn += 1;
    begin_packet(out, sec.peer_cid, type_byte(MsgType::Data, flags), pn);
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(payload);
    sec.keys.send.seal(out)
}

#[derive(Debug)]
struct Inflight {
    end: u64,
    sent_at: Instant,
    seq: u64,
}

enum SendBlock {
    /// Nothing left to send right now.
    Idle,
    /// Window (cwnd/rwnd) is full; wait for ACKs.
    Window,
    /// Pacer says wait this long.
    Pacer(Duration),
    /// Socket buffer full; wait for writability.
    Socket,
    /// Sent a large batch; let other work run, then continue.
    Yield,
}

/// Where the payload of the next DATA packet lives.
enum PayloadSrc {
    Cache(usize, usize),
    Buf,
}

/// Resume state older than this is deleted when a sender starts.
const STATE_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);

/// Datagrams sent in one uninterrupted batch before input is processed again.
const MAX_BATCH: usize = 256;
/// Housekeeping (RTO, liveness) period.
const TICK: Duration = Duration::from_millis(5);
/// Without FIN_DONE the sender waits this long after its last FIN_ACK
/// (plus four RTTs, at most `FIN_LINGER_MAX`) before it ends: the receiver
/// repeats FIN after 200 ms and again 400 ms later if the verdict was lost,
/// and the sender must still be there to answer both.
const FIN_LINGER_BASE: Duration = Duration::from_millis(1000);
const FIN_LINGER_MAX: Duration = Duration::from_secs(3);
/// ACK summaries kept for diagnostics.
const ACK_LOG_LEN: usize = 24;
/// Losses in one round beyond this rate always count as congestion.
const LOSS_CEILING: f64 = 0.20;
/// Weight the background-loss counters keep per completed round (a memory
/// of about ten rounds).
const BG_DECAY: f64 = 0.9;
/// Highest loss rate ever accepted as background (non-congestive) loss.
const BASE_LOSS_MAX: f64 = 0.15;
/// Tail loss probes sent before falling back to the retransmission timeout.
const MAX_TAIL_PROBES: u32 = 2;
/// Upper bound for the ACK delay a receiver may announce.
const MAX_PEER_ACK_DELAY: Duration = Duration::from_secs(1);

/// Handshake attempts kept alive at once (a response may answer any of them).
const MAX_ATTEMPTS: usize = 4;
/// While the receiver's user decides, ask for the decision this often.
const DECISION_POLL: Duration = Duration::from_secs(1);

/// Who we are, whom we talk to, and the shared secret.
struct Peer {
    identity: Identity,
    receiver: SharpId,
    psk: [u8; 32],
}

/// An established encrypted session with the receiver.
struct Secure {
    keys: SessionKeys,
    /// Our connection id: the receiver addresses its packets to it.
    local_cid: u64,
    /// The receiver's connection id: our packets are addressed to it.
    peer_cid: u64,
    next_pn: u64,
    replay: ReplayWindow,
    auth_failures: u64,
}

/// Compact record of a received ACK, kept for diagnostics.
#[derive(Debug, Clone, Copy)]
struct AckRecord {
    at: Instant,
    received: u64,
    contiguous: u64,
    highest: u64,
    holes: usize,
    first_hole: Option<(u64, u64)>,
    last_hole: Option<(u64, u64)>,
    stale: bool,
}

struct Engine {
    cfg: TransportConfig,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    reader: Arc<FileReader>,
    size: u64,
    file_name: String,
    transfer_id: [u8; 16],
    clock: Clock,
    events: Option<EventCallback>,
    cancel: CancellationToken,

    auth: Peer,
    secure: Option<Secure>,
    /// Handshake attempts waiting for an answer, with their send times.
    attempts: VecDeque<(Initiator, Instant)>,
    /// Latest cookie from the receiver (it asked us to prove our address).
    cookie: Option<([u8; 16], Instant)>,
    /// Answer to a handshake or to a state query, not yet acted upon.
    answer: Option<HelloAck>,
    /// Still negotiating: every HELLO_ACK counts, including the one the
    /// receiver sends on its own once its user decided.
    negotiating: bool,
    /// Responses whose authentication failed (a different shared secret).
    handshake_failures: u32,
    /// Sizes acknowledged by PROBE_ACK.
    probe_acks: Vec<u16>,

    chunk: u16,
    pending: RangeSet,
    inflight: BTreeMap<u64, Inflight>,
    inflight_bytes: u64,
    send_log: VecDeque<(Instant, u64, u64)>,
    seq: u64,
    highest_sent: u64,

    rtt: RttEstimator,
    cc: Cubic,
    pacer: Pacer,
    rwnd: u64,

    received_bytes: u64,
    max_ack_received: u64,
    resumed_from: u64,
    ack_log: VecDeque<AckRecord>,
    /// Last time an ACK acknowledged new data (restarts the RTO, RFC 6298 5.3).
    last_ack_progress: Instant,
    /// Send time of the most recently sent packet known to be delivered
    /// (RACK, RFC 8985): anything sent noticeably earlier and still missing
    /// is lost.
    rack_sent_at: Option<Instant>,

    // Loss classification: bytes sent and declared lost in the current round
    // (about one RTT), and the smoothed loss rate of completed rounds.
    round_start: Instant,
    round_sent: u64,
    round_lost: u64,
    /// Fast-moving loss rate of recent rounds (diagnostics).
    loss_rate: f64,
    /// Bytes sent and lost in recent rounds without a congestion signal,
    /// decayed per round; their ratio is the path's background
    /// (non-congestive) loss rate. Pooling counts instead of averaging
    /// per-round rates lets large rounds weigh more, so the estimate
    /// converges within a few rounds.
    bg_sent: f64,
    bg_lost: f64,
    /// Whether the current round already saw a congestion signal.
    round_congestive: bool,
    random_loss_events: u64,

    // Tail loss probes (RFC 8985 section 7).
    last_send_at: Instant,
    tail_probes: u32,
    tail_probe_count: u64,
    /// When the last tail probe went out; the RTO waits for its answer.
    last_tail_probe_at: Instant,
    last_idle_probe: Option<Instant>,

    start: Instant,
    last_rx: Instant,
    last_ping: Instant,
    probe_ts: Vec<u32>,
    stalled: bool,
    ping_backoff: u32,

    bytes_sent: u64,
    retransmitted_bytes: u64,
    healed_bytes: u64,
    rto_events: u64,
    last_progress_at: Instant,
    last_progress_bytes: u64,

    my_hash: Option<[u8; 32]>,
    pending_fin: Option<[u8; 32]>,
    fin_verdict: Option<(u8, Instant, [u8; 32])>,
    /// The receiver confirmed that it got the verdict (FIN_DONE).
    fin_confirmed: bool,

    cache_start: u64,
    cache: Vec<u8>,
    read_buf: Vec<u8>,
    tx_buf: Vec<u8>,
    ctl_buf: Vec<u8>,
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    fn new(
        cfg: TransportConfig,
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        auth: Peer,
        reader: Arc<FileReader>,
        file_name: String,
        transfer_id: [u8; 16],
        events: Option<EventCallback>,
        cancel: CancellationToken,
    ) -> Self {
        let now = Instant::now();
        let chunk = cfg.max_chunk;
        let cc = Cubic::new(chunk, cfg.initial_cwnd_chunks, cfg.max_cwnd_bytes);
        let mut rtt = RttEstimator::new(cfg.min_rto, cfg.max_rto);
        // Until the receiver announces its own, assume it ACKs like we would.
        rtt.set_max_ack_delay(cfg.ack_interval);
        let rate = cc.pacing_rate(rtt.srtt(), cfg.max_rate_bytes);
        let pacer = Pacer::new(now, rate, burst_for_rate(rate, chunk));
        let size = reader.size();
        Self {
            cfg,
            socket,
            peer,
            reader,
            size,
            file_name,
            transfer_id,
            clock: Clock::new(),
            events,
            cancel,
            auth,
            secure: None,
            attempts: VecDeque::new(),
            cookie: None,
            answer: None,
            negotiating: true,
            handshake_failures: 0,
            probe_acks: Vec::new(),
            chunk,
            pending: RangeSet::new(),
            inflight: BTreeMap::new(),
            inflight_bytes: 0,
            send_log: VecDeque::new(),
            seq: 0,
            highest_sent: 0,
            rtt,
            cc,
            pacer,
            rwnd: u64::MAX,
            received_bytes: 0,
            max_ack_received: 0,
            resumed_from: 0,
            ack_log: VecDeque::new(),
            last_ack_progress: now,
            rack_sent_at: None,
            round_start: now,
            round_sent: 0,
            round_lost: 0,
            loss_rate: 0.0,
            bg_sent: 0.0,
            bg_lost: 0.0,
            round_congestive: false,
            random_loss_events: 0,
            last_send_at: now,
            tail_probes: 0,
            tail_probe_count: 0,
            last_tail_probe_at: now,
            last_idle_probe: None,
            start: now,
            last_rx: now,
            last_ping: now,
            probe_ts: Vec::new(),
            stalled: false,
            ping_backoff: 0,
            bytes_sent: 0,
            retransmitted_bytes: 0,
            healed_bytes: 0,
            rto_events: 0,
            last_progress_at: now,
            last_progress_bytes: 0,
            my_hash: None,
            pending_fin: None,
            fin_verdict: None,
            fin_confirmed: false,
            cache_start: 0,
            cache: Vec::new(),
            read_buf: Vec::new(),
            tx_buf: Vec::with_capacity(MAX_CHUNK as usize + DATA_OVERHEAD),
            ctl_buf: Vec::with_capacity(MAX_CONTROL_DATAGRAM),
        }
    }

    fn tid_hex(&self) -> String {
        hex16(&self.transfer_id)
    }

    fn send_datagram(&self, bytes: &[u8]) -> io::Result<()> {
        match self.socket.try_send_to(bytes, self.peer) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Encrypts `msg` as a transport packet and sends it. Without an
    /// established session there is nobody to send it to.
    fn send_frame(&mut self, flags: u8, msg: &Message<'_>) -> io::Result<()> {
        let Some(sec) = self.secure.as_mut() else {
            return Ok(());
        };
        let pn = sec.next_pn;
        sec.next_pn += 1;
        begin_packet(
            &mut self.ctl_buf,
            sec.peer_cid,
            type_byte(msg.msg_type(), flags),
            pn,
        );
        wire::encode_body(msg, &mut self.ctl_buf, MAX_CONTROL_BODY);
        sec.keys
            .send
            .seal(&mut self.ctl_buf)
            .map_err(io::Error::other)?;
        match self.socket.try_send_to(&self.ctl_buf, self.peer) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Best-effort notice to the receiver that the transfer is over (sent
    /// twice, as nothing acknowledges it).
    fn send_abort(&mut self, code: u16, reason: &str) {
        let msg = Message::Abort(Abort {
            code,
            reason: reason.to_string(),
        });
        for _ in 0..2 {
            let _ = self.send_frame(0, &msg);
        }
    }

    /// Starts a new handshake attempt: a fresh ephemeral key and connection
    /// id, carrying HELLO. The receiver answers with its current state.
    fn send_initiation(&mut self) -> Result<(), SendError> {
        let now = Instant::now();
        let mut attempt = Initiator::new(&self.auth.identity, &self.auth.receiver, &self.auth.psk)
            .map_err(|e| SendError::Handshake(e.to_string()))?;
        let ts = self.clock.now_us().max(1);
        let payload = wire::encode_initiation(&wire::Initiation {
            timestamp: hs::initiation_timestamp(),
            suites: Suite::ALL_BITS,
            hardware_aes: Suite::hardware_aes(),
            hello_flags: HELLO_FLAG_RESUME,
            hello: self.hello(ts),
        });
        let cookie = self
            .cookie
            .filter(|(_, at)| now.saturating_duration_since(*at) < hs::COOKIE_LIFETIME)
            .map(|(c, _)| c);
        let pkt = attempt
            .initiation(&payload, cookie.as_ref())
            .map_err(|e| SendError::Handshake(e.to_string()))?;
        self.send_datagram(&pkt)?;
        if self.attempts.len() >= MAX_ATTEMPTS {
            self.attempts.pop_front();
        }
        self.attempts.push_back((attempt, now));
        tracing::debug!(
            "handshake initiation sent to {} ({})",
            self.peer,
            self.auth.receiver.short()
        );
        Ok(())
    }

    /// A datagram addressed to one of our handshake attempts: a response or
    /// a cookie reply.
    fn on_handshake_reply(
        &mut self,
        idx: usize,
        pkt: &[u8],
        from: SocketAddr,
    ) -> Result<(), SendError> {
        if pkt.len() == COOKIE_REPLY_LEN {
            if let Some(cookie) = self.attempts[idx].0.read_cookie_reply(pkt) {
                tracing::debug!("receiver is under load and asked for a cookie; retrying");
                self.cookie = Some((cookie, Instant::now()));
                self.send_initiation()?;
            }
            return Ok(());
        }
        let (attempt, sent_at) = self.attempts.remove(idx).expect("index in range");
        let cid = attempt.cid();
        match attempt.read_response(pkt) {
            Ok((receiver_cid, payload, split)) => {
                let resp = wire::decode_response(&payload)
                    .map_err(|e| SendError::Protocol(format!("bad handshake response: {}", e)))?;
                let now = Instant::now();
                self.rtt.on_sample(now.saturating_duration_since(sent_at));
                self.note_alive(now, from);
                if resp.ack.status == HELLO_REJECTED {
                    return Err(SendError::Rejected {
                        reason: reason_name(resp.ack.reason).to_string(),
                        message: resp.ack.message,
                    });
                }
                let suite = Suite::from_u8(resp.suite).ok_or_else(|| {
                    SendError::Protocol("receiver chose an unknown cipher".into())
                })?;
                self.secure = Some(Secure {
                    keys: SessionKeys::derive(&split, true, suite),
                    local_cid: cid,
                    peer_cid: receiver_cid,
                    next_pn: 0,
                    replay: ReplayWindow::new(),
                    auth_failures: 0,
                });
                // Older attempts are obsolete now.
                self.attempts.clear();
                tracing::debug!(
                    "session with {} established ({})",
                    self.auth.receiver.short(),
                    suite.name()
                );
                self.answer = Some(resp.ack);
            }
            // Not made by the receiver we talk to; ignore.
            Err(CryptoError::Mac) | Err(CryptoError::Malformed) => {}
            Err(e) => {
                // The receiver authenticated our initiation but its response
                // does not decrypt: it mixes in a different pre-shared key.
                self.handshake_failures += 1;
                tracing::debug!("handshake response rejected: {}", e);
            }
        }
        Ok(())
    }

    fn hello(&self, ts: u32) -> Hello {
        Hello {
            transfer_id: self.transfer_id,
            timestamp: ts,
            file_size: self.size,
            file_mtime: self.reader.mtime_unix(),
            max_chunk: self.cfg.max_chunk,
            capabilities: SUPPORTED_CAPS,
            file_name: self.file_name.clone(),
        }
    }

    // ----- handshake -------------------------------------------------------

    async fn handshake(&mut self) -> Result<HelloAck, SendError> {
        let deadline = Instant::now() + self.cfg.handshake_timeout;
        let mut delay = Duration::from_millis(250);
        let mut next_attempt = Instant::now();
        let mut next_poll: Option<Instant> = None;
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let socket = self.socket.clone();
        let cancel = self.cancel.clone();
        loop {
            if cancel.is_cancelled() {
                return Err(SendError::Cancelled);
            }
            let now = Instant::now();
            if let Some(ack) = self.answer.take() {
                match ack.status {
                    HELLO_ACCEPTED => {
                        if ack.capabilities & !SUPPORTED_CAPS != 0 {
                            return Err(SendError::Protocol(format!(
                                "receiver confirmed capabilities {:#x} that were not offered",
                                ack.capabilities & !SUPPORTED_CAPS
                            )));
                        }
                        return Ok(ack);
                    }
                    HELLO_REJECTED => {
                        return Err(SendError::Rejected {
                            reason: reason_name(ack.reason).to_string(),
                            message: ack.message,
                        })
                    }
                    _ => {
                        // The receiver's user is deciding; keep asking.
                        if next_poll.is_none() {
                            tracing::info!("waiting for the receiver to accept the transfer");
                        }
                        next_poll.get_or_insert(now + DECISION_POLL);
                    }
                }
            }
            if now >= deadline {
                return Err(if next_poll.is_some() {
                    SendError::Rejected {
                        reason: reason_name(REASON_TIMEOUT).to_string(),
                        message: "no decision in time".into(),
                    }
                } else if self.handshake_failures > 0 {
                    SendError::Handshake(
                        "the receiver answered, but its keys do not match ours \
                         (different shared secret?)"
                            .into(),
                    )
                } else {
                    SendError::HandshakeTimeout
                });
            }
            if self.secure.is_none() && now >= next_attempt {
                self.send_initiation()?;
                next_attempt = now + delay;
                delay = (delay * 2).min(Duration::from_secs(4));
            }
            if let Some(at) = next_poll {
                if now >= at {
                    let ts = self.clock.now_us().max(1);
                    self.probe_ts.push(ts);
                    let hello = Message::Hello(self.hello(ts));
                    self.send_frame(HELLO_FLAG_RESUME, &hello)?;
                    next_poll = Some(now + DECISION_POLL);
                }
            }

            let mut wake = deadline;
            if self.secure.is_none() {
                wake = wake.min(next_attempt);
            }
            if let Some(at) = next_poll {
                wake = wake.min(at);
            }
            tokio::select! {
                r = socket.readable() => { let _ = r; }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {}
                _ = cancel.cancelled() => return Err(SendError::Cancelled),
            }
            loop {
                match socket.try_recv_from(&mut buf) {
                    Ok((n, from)) => self.on_datagram(&mut buf[..n], from)?,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        tracing::debug!("recv error during handshake: {}", e);
                        break;
                    }
                }
            }
        }
    }

    /// Rebuilds `pending` from the receiver's description of what it holds
    /// (HELLO_ACK), discarding all in-flight bookkeeping.
    fn apply_receiver_state(&mut self, ack: &HelloAck) {
        self.rwnd = ack.rwnd.max(2 * self.chunk as u64);
        self.rtt.set_max_ack_delay(
            Duration::from_micros(ack.max_ack_delay_us as u64).min(MAX_PEER_ACK_DELAY),
        );
        let mut pending = RangeSet::new();
        for &(s, e) in &ack.holes {
            let e = e.min(self.size);
            if s < e {
                pending.insert(s, e);
            }
        }
        if ack.known_end < self.size {
            pending.insert(ack.known_end, self.size);
        }
        self.pending = pending;
        self.inflight.clear();
        self.inflight_bytes = 0;
        self.send_log.clear();
        self.highest_sent = self.highest_sent.max(ack.known_end.min(self.size));
        let have = self.size - self.pending.total();
        self.received_bytes = have;
        self.max_ack_received = have;
        self.last_ack_progress = Instant::now();
    }

    /// Applies the handshake answer: negotiated chunk, receive window and
    /// what to send.
    fn apply_hello_ack(&mut self, ack: &HelloAck) {
        let negotiated = ack.max_chunk.min(self.cfg.max_chunk).max(MIN_CHUNK);
        self.set_chunk(negotiated);
        self.apply_receiver_state(ack);
        self.resumed_from = self.received_bytes;
        tracing::info!(
            "transfer {} accepted by {}: chunk {} B, {} B already at receiver, {} B to send",
            self.tid_hex(),
            self.peer,
            self.chunk,
            self.resumed_from,
            self.pending.total()
        );
    }

    /// Re-synchronises with the receiver after silence (answer to a probe HELLO).
    fn resync(&mut self, ack: &HelloAck, now: Instant) {
        let before = self.pending.total() + self.inflight_bytes;
        self.apply_receiver_state(ack);
        // Keep the probed chunk size: the path may not carry the negotiated one.
        let chunk = self.chunk.min(ack.max_chunk.max(MIN_CHUNK));
        if chunk != self.chunk {
            self.set_chunk(chunk);
        }
        self.cc.on_rto(now);
        self.rtt.reset_backoff();
        self.update_pacer();
        tracing::info!(
            "re-synchronised with receiver: {} B outstanding (was {} B)",
            self.pending.total(),
            before
        );
    }

    fn set_chunk(&mut self, chunk: u16) {
        self.chunk = chunk;
        self.cc.set_mss(chunk);
        self.update_pacer();
    }

    fn update_pacer(&mut self) {
        let rate = self
            .cc
            .pacing_rate(self.rtt.srtt(), self.cfg.max_rate_bytes);
        self.pacer.set_rate(rate);
        self.pacer.set_burst(burst_for_rate(rate, self.chunk));
    }

    // ----- path MTU probe --------------------------------------------------

    async fn probe_mtu(&mut self) -> Result<(), SendError> {
        if !self.cfg.probe_mtu {
            return Ok(());
        }
        let mut candidates: Vec<u16> = vec![self.chunk, DEFAULT_CHUNK, SAFE_CHUNK];
        candidates.retain(|&c| c <= self.chunk && c >= MIN_CHUNK);
        candidates.sort_unstable_by(|a, b| b.cmp(a));
        candidates.dedup();

        let mut buf = vec![0u8; MAX_DATAGRAM];
        let socket = self.socket.clone();
        let wait = (self.rtt.srtt() * 3).clamp(Duration::from_millis(150), Duration::from_secs(2));
        for cand in candidates {
            let size = (cand as usize + DATA_OVERHEAD) as u16;
            let mut acked = false;
            'attempts: for _ in 0..2 {
                match self.send_frame(0, &Message::Probe(Probe { size })) {
                    Ok(()) => {}
                    Err(e) if is_msgsize_error(&e) => {
                        tracing::debug!("probe {} B rejected locally (EMSGSIZE)", size);
                        break 'attempts;
                    }
                    Err(e) => {
                        tracing::debug!("probe send error: {}", e);
                        break 'attempts;
                    }
                }
                let deadline = Instant::now() + wait;
                loop {
                    if self.probe_acks.contains(&size) {
                        acked = true;
                        break 'attempts;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    let r = tokio::select! {
                        r = socket.recv_from(&mut buf) => r,
                        _ = tokio::time::sleep(deadline - now) => break,
                        _ = self.cancel.cancelled() => return Err(SendError::Cancelled),
                    };
                    if let Ok((n, from)) = r {
                        self.on_datagram(&mut buf[..n], from)?;
                    }
                }
            }
            if acked {
                if cand != self.chunk {
                    tracing::info!("path MTU probe: using {} byte chunks", cand);
                }
                self.set_chunk(cand);
                return Ok(());
            }
        }
        // Nothing answered; fall back to the safe size and let the transfer
        // itself discover whether the path works at all.
        let fallback = SAFE_CHUNK.min(self.chunk);
        tracing::warn!(
            "no probe answered; falling back to {} byte chunks",
            fallback
        );
        self.set_chunk(fallback);
        Ok(())
    }

    // ----- main loop -------------------------------------------------------

    async fn run(
        &mut self,
        hash_task: JoinHandle<io::Result<[u8; 32]>>,
    ) -> Result<TransferSummary, SendError> {
        let ack = self.handshake().await?;
        self.negotiating = false;
        self.apply_hello_ack(&ack);
        self.probe_mtu().await?;
        self.start = Instant::now();
        self.last_progress_at = self.start;
        self.last_progress_bytes = self.received_bytes;
        let cipher = self
            .secure
            .as_ref()
            .map(|s| s.keys.suite.name())
            .unwrap_or("none");
        tracing::info!(
            "sending to {} ({}), encrypted with {}",
            self.peer,
            self.auth.receiver,
            cipher
        );
        emit(
            &self.events,
            TransferEvent::Started {
                transfer_id: self.tid_hex(),
                peer: self.peer.to_string(),
                peer_id: self.auth.receiver.to_string(),
                cipher: cipher.to_string(),
                file_name: self.file_name.clone(),
                file_size: self.size,
                resumed_from: self.resumed_from,
                chunk_size: self.chunk,
            },
        );

        let mut hash_task = Some(hash_task);
        let socket = self.socket.clone();
        let cancel = self.cancel.clone();
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut next_tick = Instant::now() + TICK;
        let mut next_progress = Instant::now() + self.cfg.progress_interval;

        loop {
            if cancel.is_cancelled() {
                return Err(SendError::Cancelled);
            }

            // 1. Input: everything that is already queued on the socket.
            loop {
                match socket.try_recv_from(&mut buf) {
                    Ok((n, from)) => self.on_datagram(&mut buf[..n], from)?,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        tracing::debug!("recv error: {}", e);
                        break;
                    }
                }
            }
            // An answer to a re-handshake or state query: adopt the
            // receiver's view of what it holds.
            if let Some(ack) = self.answer.take() {
                match ack.status {
                    HELLO_ACCEPTED => self.resync(&ack, Instant::now()),
                    HELLO_REJECTED => {
                        return Err(SendError::Rejected {
                            reason: reason_name(ack.reason).to_string(),
                            message: ack.message,
                        })
                    }
                    _ => {}
                }
            }

            // 2. Local whole-file hash finished?
            if hash_task.as_ref().is_some_and(|h| h.is_finished()) {
                let task = hash_task.take().expect("checked above");
                let hash = task
                    .await
                    .map_err(|e| SendError::Protocol(format!("hash task failed: {}", e)))??;
                self.my_hash = Some(hash);
                if let Some(theirs) = self.pending_fin.take() {
                    self.answer_fin(theirs, Instant::now())?;
                }
            }

            // 3. Timers.
            let now = Instant::now();
            if now >= next_tick {
                self.housekeeping(now)?;
                next_tick = now + TICK;
            }
            if now >= next_progress {
                self.emit_progress(now);
                next_progress = now + self.cfg.progress_interval;
            }
            if let Some(summary) = self.finished(now)? {
                return Ok(summary);
            }

            // 4. Output.
            let block = self.fill_window(now)?;

            // 5. Wait for the next event.
            let mut deadline = next_tick.min(next_progress);
            let mut want_write = false;
            match block {
                SendBlock::Yield => {
                    tokio::task::yield_now().await;
                    continue;
                }
                SendBlock::Pacer(d) => deadline = deadline.min(now + d),
                SendBlock::Socket => want_write = true,
                SendBlock::Idle | SendBlock::Window => {}
            }
            tokio::select! {
                r = socket.readable() => { let _ = r; }
                r = socket.writable(), if want_write => { let _ = r; }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
                _ = cancel.cancelled() => {}
            }
        }
    }

    /// Checks whether the transfer has reached a terminal state.
    fn finished(&mut self, now: Instant) -> Result<Option<TransferSummary>, SendError> {
        let Some((verdict, at, receiver_hash)) = self.fin_verdict else {
            return Ok(None);
        };
        // Until the receiver confirms the verdict (FIN_DONE), stay to answer
        // a repeated FIN in case our FIN_ACK was lost. This only costs time
        // when FIN_ACK or FIN_DONE was actually lost.
        let linger = (FIN_LINGER_BASE + self.rtt.srtt() * 4).min(FIN_LINGER_MAX);
        if !self.fin_confirmed && now.saturating_duration_since(at) < linger {
            return Ok(None);
        }
        let my_hash = self.my_hash.unwrap_or([0u8; 32]);
        if verdict == VERDICT_OK {
            let elapsed = self.start.elapsed();
            let moved = self.size.saturating_sub(self.resumed_from);
            let summary = TransferSummary {
                transfer_id: self.tid_hex(),
                file_size: self.size,
                resumed_from: self.resumed_from,
                bytes_sent: self.bytes_sent,
                retransmitted_bytes: self.retransmitted_bytes,
                loss_events: self.cc.loss_events(),
                rto_events: self.rto_events,
                chunk_size: self.chunk,
                elapsed,
                avg_rate_bps: if elapsed.as_secs_f64() > 0.0 {
                    moved as f64 * 8.0 / elapsed.as_secs_f64()
                } else {
                    0.0
                },
                file_hash_hex: hash_to_hex(&my_hash),
            };
            let stats = self.stats(now);
            emit(
                &self.events,
                TransferEvent::Completed {
                    transfer_id: self.tid_hex(),
                    file_name: self.file_name.clone(),
                    path: None,
                    file_hash_hex: summary.file_hash_hex.clone(),
                    peer_confirmed: true,
                    stats,
                },
            );
            return Ok(Some(summary));
        }
        let err = SendError::HashMismatch {
            sender: hash_to_hex(&my_hash),
            receiver: hash_to_hex(&receiver_hash),
        };
        emit(
            &self.events,
            TransferEvent::Failed {
                transfer_id: self.tid_hex(),
                error: err.to_string(),
                resumable: false,
            },
        );
        Err(err)
    }

    // ----- sending ---------------------------------------------------------

    fn window(&self) -> u64 {
        self.cc.cwnd().min(self.rwnd).max(2 * self.chunk as u64)
    }

    /// Makes the payload for `[s, e)` available, from the read-ahead block
    /// for new data or with a direct read for retransmissions.
    fn load_payload(&mut self, s: u64, e: u64, retransmit: bool) -> io::Result<PayloadSrc> {
        let cache_end = self.cache_start + self.cache.len() as u64;
        if !self.cache.is_empty() && s >= self.cache_start && e <= cache_end {
            return Ok(PayloadSrc::Cache(
                (s - self.cache_start) as usize,
                (e - self.cache_start) as usize,
            ));
        }
        if !retransmit {
            let end = s.saturating_add(BLOCK_SIZE).min(self.size).max(e);
            self.cache.resize((end - s) as usize, 0);
            if let Err(err) = self.reader.read_at(s, &mut self.cache) {
                self.cache.clear();
                return Err(err);
            }
            self.cache_start = s;
            return Ok(PayloadSrc::Cache(0, (e - s) as usize));
        }
        self.read_buf.resize((e - s) as usize, 0);
        self.reader.read_at(s, &mut self.read_buf)?;
        Ok(PayloadSrc::Buf)
    }

    fn fill_window(&mut self, now: Instant) -> Result<SendBlock, SendError> {
        if self.stalled
            || self.fin_verdict.is_some()
            || self.pending_fin.is_some()
            || self.secure.is_none()
        {
            return Ok(SendBlock::Idle);
        }
        self.pacer.refill(now);
        let mut sent_in_call = 0usize;
        loop {
            if self.pending.is_empty() {
                return Ok(SendBlock::Idle);
            }
            let chunk = self.chunk as u64;
            if self.inflight_bytes > 0 && self.inflight_bytes + chunk > self.window() {
                return Ok(SendBlock::Window);
            }
            if !self.pacer.try_take(chunk) {
                return Ok(SendBlock::Pacer(self.pacer.delay_for(chunk)));
            }
            let (s, e) = match self.pending.take_first(chunk) {
                Some(r) => r,
                None => return Ok(SendBlock::Idle),
            };
            let retransmit = s < self.highest_sent;
            let src = match self.load_payload(s, e, retransmit) {
                Ok(src) => src,
                Err(err) => {
                    self.pending.insert(s, e);
                    return Err(SendError::Io(err));
                }
            };
            let ts = self.clock.now_us().max(1);
            let flags = if retransmit { DATA_FLAG_RETRANSMIT } else { 0 };
            {
                let sec = self.secure.as_mut().expect("checked above");
                let payload: &[u8] = match src {
                    PayloadSrc::Cache(a, b) => &self.cache[a..b],
                    PayloadSrc::Buf => &self.read_buf[..],
                };
                seal_data(sec, &mut self.tx_buf, flags, s, ts, payload)
                    .map_err(|e| SendError::Protocol(e.to_string()))?;
            }
            match self.socket.try_send_to(&self.tx_buf, self.peer) {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.pending.insert(s, e);
                    self.pacer.refund(chunk);
                    return Ok(SendBlock::Socket);
                }
                Err(err) if is_msgsize_error(&err) => {
                    // The path shrank under us: fall back to the safe chunk.
                    self.pending.insert(s, e);
                    self.pacer.refund(chunk);
                    let smaller = SAFE_CHUNK.min(self.chunk);
                    if smaller < self.chunk {
                        tracing::warn!("EMSGSIZE: reducing chunk {} -> {}", self.chunk, smaller);
                        self.set_chunk(smaller);
                        continue;
                    }
                    return Err(SendError::Io(err));
                }
                Err(err) => {
                    self.pending.insert(s, e);
                    return Err(SendError::Io(err));
                }
            }
            let len = e - s;
            self.seq += 1;
            self.inflight.insert(
                s,
                Inflight {
                    end: e,
                    sent_at: now,
                    seq: self.seq,
                },
            );
            self.send_log.push_back((now, s, self.seq));
            self.inflight_bytes += len;
            self.bytes_sent += len;
            self.round_sent += len;
            self.last_send_at = now;
            self.retransmitted_bytes += e.min(self.highest_sent).saturating_sub(s);
            self.highest_sent = self.highest_sent.max(e);
            sent_in_call += 1;
            if sent_in_call >= MAX_BATCH {
                return Ok(SendBlock::Yield);
            }
        }
    }

    // ----- incoming --------------------------------------------------------

    /// Routes a datagram by its connection id: transport packets of the
    /// session, or answers to a handshake attempt. Anything else is dropped.
    fn on_datagram(&mut self, pkt: &mut [u8], from: SocketAddr) -> Result<(), SendError> {
        let Some(dcid) = peek_cid(pkt) else {
            return Ok(());
        };
        if self.secure.as_ref().is_some_and(|s| s.local_cid == dcid) {
            return self.on_transport(pkt, from);
        }
        if let Some(i) = self.attempts.iter().position(|(a, _)| a.cid() == dcid) {
            return self.on_handshake_reply(i, pkt, from);
        }
        Ok(())
    }

    fn on_transport(&mut self, pkt: &mut [u8], from: SocketAddr) -> Result<(), SendError> {
        let sec = self.secure.as_mut().expect("caller checked the session");
        let (tb, pn, body) = match sec.keys.recv.open(pkt) {
            Ok(v) => v,
            Err(_) => {
                sec.auth_failures += 1;
                return Ok(());
            }
        };
        if !sec.replay.accept(pn) {
            return Ok(());
        }
        let msg = match wire::parse_type_byte(tb).and_then(|(t, _)| wire::decode_body(t, body)) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("malformed frame from {}: {}", from, e);
                return Ok(());
            }
        };
        let now = Instant::now();
        self.note_alive(now, from);
        match msg {
            Message::Ack(ack) => self.on_ack(ack, now),
            Message::Fin(fin) => {
                // Every byte is at the receiver: nothing left to (re)send.
                self.pending = RangeSet::new();
                self.inflight.clear();
                self.inflight_bytes = 0;
                self.send_log.clear();
                self.received_bytes = self.size;
                if self.my_hash.is_some() {
                    self.answer_fin(fin.file_hash, now)?;
                } else {
                    if self.pending_fin.is_none() {
                        tracing::info!("receiver finished; waiting for the local hash");
                    }
                    self.pending_fin = Some(fin.file_hash);
                    // Tell the receiver we are alive; it answers with PONG
                    // and keeps retrying FIN until the verdict arrives.
                    let ts = self.clock.now_us().max(1);
                    let _ = self.send_frame(0, &Message::Ping(Ping { timestamp: ts }));
                }
            }
            Message::Pong(p) => {
                let sample = self.clock.since_us(p.echo);
                self.rtt.on_sample(Duration::from_micros(sample as u64));
                self.update_pacer();
            }
            Message::HelloAck(ack) => {
                // While negotiating every answer counts; later only answers
                // to our own state queries do (late duplicates are ignored).
                if self.negotiating || self.probe_ts.contains(&ack.echo_ts) {
                    self.probe_ts.clear();
                    self.answer = Some(ack);
                }
            }
            Message::Abort(a) => {
                return Err(SendError::Aborted {
                    code: a.code,
                    reason: a.reason,
                })
            }
            Message::FinDone(_) => {
                // Only meaningful once our verdict is out; nothing is left to
                // answer, so the transfer can end without lingering.
                if self.fin_verdict.is_some() {
                    self.fin_confirmed = true;
                }
            }
            Message::ProbeAck(p) => {
                if self.probe_acks.len() < 16 {
                    self.probe_acks.push(p.size);
                }
            }
            Message::Ping(_) => {}
            Message::Hello(_) | Message::Data(_) | Message::FinAck(_) | Message::Probe(_) => {}
        }
        Ok(())
    }

    fn answer_fin(&mut self, receiver_hash: [u8; 32], now: Instant) -> Result<(), SendError> {
        let my_hash = self
            .my_hash
            .ok_or_else(|| SendError::Protocol("local hash unavailable".into()))?;
        let verdict = if receiver_hash == my_hash {
            VERDICT_OK
        } else {
            VERDICT_MISMATCH
        };
        self.send_frame(
            0,
            &Message::FinAck(wire::FinAck {
                verdict,
                file_hash: my_hash,
            }),
        )?;
        if self.fin_verdict.is_none() {
            tracing::info!(
                "receiver reported completion; whole-file hash {}",
                if verdict == VERDICT_OK {
                    "matches"
                } else {
                    "MISMATCH"
                }
            );
        }
        // A repeated FIN means our FIN_ACK was lost: wait for FIN_DONE anew.
        self.fin_verdict = Some((verdict, now, receiver_hash));
        Ok(())
    }

    fn note_alive(&mut self, now: Instant, from: SocketAddr) {
        self.last_rx = now;
        self.ping_backoff = 0;
        if from != self.peer {
            tracing::info!("receiver address changed {} -> {}", self.peer, from);
            self.peer = from;
        }
        if self.stalled {
            self.stalled = false;
            self.rtt.reset_backoff();
            tracing::info!("receiver is back; resuming");
            emit(
                &self.events,
                TransferEvent::Recovered {
                    transfer_id: self.tid_hex(),
                },
            );
        }
    }

    fn remove_inflight(&mut self, key: u64) -> Option<Inflight> {
        let inf = self.inflight.remove(&key)?;
        self.inflight_bytes = self.inflight_bytes.saturating_sub(inf.end - key);
        Some(inf)
    }

    fn on_ack(&mut self, ack: wire::Ack, now: Instant) {
        // The receiver's byte count never shrinks within a session, so an ACK
        // reporting less than an earlier one was reordered on the path; its
        // holes are outdated.
        self.ack_log.push_back(AckRecord {
            at: now,
            received: ack.received_bytes,
            contiguous: ack.contiguous_upto,
            highest: ack.highest,
            holes: ack.holes.len(),
            first_hole: ack.holes.first().copied(),
            last_hole: ack.holes.last().copied(),
            stale: ack.received_bytes < self.max_ack_received,
        });
        if self.ack_log.len() > ACK_LOG_LEN {
            self.ack_log.pop_front();
        }
        if ack.received_bytes < self.max_ack_received {
            return;
        }
        if ack.received_bytes > self.max_ack_received {
            // The receiver got new data (possibly beyond the interval this
            // ACK can describe): the path is alive, so restart the RTO.
            self.last_ack_progress = now;
            self.tail_probes = 0;
        }
        self.max_ack_received = ack.received_bytes;
        self.rwnd = ack.rwnd;
        self.received_bytes = self.received_bytes.max(ack.received_bytes.min(self.size));
        if ack.echo_ts != 0 {
            let raw = self.clock.since_us(ack.echo_ts);
            if raw < 60_000_000 {
                let sample = raw.saturating_sub(ack.ack_delay_us).max(1);
                self.rtt.on_sample(Duration::from_micros(sample as u64));
            }
        }

        // Anything the receiver confirms must not be sent again, even if it
        // was queued for retransmission before the original arrived late.
        self.pending.remove(0, ack.contiguous_upto);
        let mut acked: u64 = 0;
        let mut newest_delivered: Option<Instant> = None;
        let mut note_delivered = |t: Instant| {
            newest_delivered = Some(newest_delivered.map_or(t, |n: Instant| n.max(t)));
        };
        // Cumulative part.
        while let Some((off, end, sent_at)) = self
            .inflight
            .iter()
            .next()
            .map(|(&k, inf)| (k, inf.end, inf.sent_at))
        {
            if end > ack.contiguous_upto {
                break;
            }
            acked += end - off;
            note_delivered(sent_at);
            self.remove_inflight(off);
        }

        // Selective part. The receiver guarantees that `holes` lists every
        // gap in [contiguous_upto, highest), so everything else in that
        // interval has arrived.
        if ack.highest > ack.contiguous_upto {
            let mut received = RangeSet::new();
            received.insert(ack.contiguous_upto, ack.highest);
            for &(s, e) in &ack.holes {
                received.remove(s, e);
            }
            for (s, e) in received.iter() {
                self.pending.remove(s, e);
            }
            let keys: Vec<(u64, u64, Instant)> = self
                .inflight
                .range(ack.contiguous_upto..ack.highest)
                .map(|(&k, inf)| (k, inf.end, inf.sent_at))
                .collect();
            for (k, end, sent_at) in keys {
                if received.contains(k, end) {
                    acked += end - k;
                    note_delivered(sent_at);
                    self.remove_inflight(k);
                }
            }
        }
        if let Some(t) = newest_delivered {
            self.rack_sent_at = Some(self.rack_sent_at.map_or(t, |r| r.max(t)));
        }

        let mut lost: Vec<(u64, u64)> = Vec::new();
        if ack.highest > ack.contiguous_upto {
            // Loss detection (RACK): a packet in a reported hole is lost when
            // a packet sent sufficiently later has been delivered, or when it
            // has been outstanding longer than an RTT plus the reordering
            // window. Send order, not file offset, decides, so a fresh
            // retransmission is not condemned by ACKs that predate it.
            let reo_wnd = (self.rtt.min_rtt() / 4)
                .clamp(Duration::from_millis(1), Duration::from_millis(250));
            let time_threshold = self.rtt.srtt().max(self.rtt.latest()) + reo_wnd;
            let rack = self.rack_sent_at;
            for &(hs, he) in &ack.holes {
                let first_key = self
                    .inflight
                    .range(..hs)
                    .next_back()
                    .map(|(&k, _)| k)
                    .unwrap_or(hs);
                let candidates: Vec<(u64, u64, Instant)> = self
                    .inflight
                    .range(first_key..he)
                    .filter(|(&k, inf)| inf.end > hs && k < he)
                    .map(|(&k, inf)| (k, inf.end, inf.sent_at))
                    .collect();
                for (k, end, sent_at) in candidates {
                    let by_order = rack.is_some_and(|r| sent_at + reo_wnd <= r);
                    let by_time = now.saturating_duration_since(sent_at) >= time_threshold;
                    if by_order || by_time {
                        self.remove_inflight(k);
                        lost.push((k, end));
                    }
                }
            }
        }
        for &(s, e) in &lost {
            self.pending.insert(s, e);
        }

        // Self-healing: a reported hole that is neither in flight nor queued
        // would never be sent again; queue it.
        let mut healed = 0u64;
        for &(hs, he) in &ack.holes {
            let he = he.min(self.size);
            if hs >= he {
                continue;
            }
            let mut missing = RangeSet::from_ranges([(hs, he)]);
            let first_key = self
                .inflight
                .range(..hs)
                .next_back()
                .map(|(&k, _)| k)
                .unwrap_or(hs);
            for (&k, inf) in self.inflight.range(first_key..he) {
                if inf.end > hs {
                    missing.remove(k, inf.end);
                }
            }
            for (s, e) in self.pending.intersecting(hs, he) {
                missing.remove(s, e);
            }
            for (s, e) in missing.iter() {
                healed += e - s;
                self.pending.insert(s, e);
            }
        }
        if healed > 0 {
            self.healed_bytes += healed;
            tracing::debug!("re-queued {} B reported missing but not tracked", healed);
        }

        if acked > 0 {
            self.cc.on_ack(acked, now, &self.rtt);
            self.rtt.reset_backoff();
            self.last_ack_progress = now;
            self.tail_probes = 0;
        }
        if !lost.is_empty() {
            let lost_bytes: u64 = lost.iter().map(|&(s, e)| e - s).sum();
            self.round_lost += lost_bytes;
            self.end_round_if_due(now);
            if self.loss_is_congestive() {
                self.round_congestive = true;
                if self.cc.on_loss(now, self.rtt.srtt()) {
                    tracing::debug!(
                        "congestive loss ({} ranges, standing queue {:?}, loss rate {:.1}%); cwnd -> {} B",
                        lost.len(),
                        self.rtt.standing_queue(),
                        self.current_loss_rate() * 100.0,
                        self.cc.cwnd()
                    );
                }
            } else {
                self.random_loss_events += 1;
            }
        } else {
            self.end_round_if_due(now);
        }
        self.update_pacer();
    }

    /// Closes the current measurement round once it spans about one RTT.
    fn end_round_if_due(&mut self, now: Instant) {
        let len = self.rtt.srtt().max(Duration::from_millis(5));
        if now.saturating_duration_since(self.round_start) < len {
            return;
        }
        // Only rounds with enough packets say something about the loss rate.
        if self.round_sent >= 16 * self.chunk as u64 {
            let rate = (self.round_lost as f64 / self.round_sent as f64).min(1.0);
            self.loss_rate = 0.5 * self.loss_rate + 0.5 * rate;
            if !self.round_congestive {
                self.bg_sent = self.bg_sent * BG_DECAY + self.round_sent as f64;
                self.bg_lost = self.bg_lost * BG_DECAY + self.round_lost as f64;
            }
        }
        self.round_start = now;
        self.round_sent = 0;
        self.round_lost = 0;
        self.round_congestive = false;
    }

    /// Background (non-congestive) loss rate of the path.
    fn base_loss_rate(&self) -> f64 {
        if self.bg_sent > 0.0 {
            (self.bg_lost / self.bg_sent).min(BASE_LOSS_MAX)
        } else {
            0.0
        }
    }

    fn current_loss_rate(&self) -> f64 {
        let partial = if self.round_sent >= 16 * self.chunk as u64 {
            (self.round_lost as f64 / self.round_sent as f64).min(1.0)
        } else {
            0.0
        };
        self.loss_rate.max(partial)
    }

    /// A loss is taken as a congestion signal when a queue has built up (the
    /// minimum RTT of a whole round is elevated, which jitter alone never
    /// causes), or when the loss rate rises clearly above the path's
    /// background level (which is what overdriving a shallow buffer looks
    /// like). Losses at the background level on an otherwise empty path
    /// (radio links, noisy lines) are repaired without slowing down.
    fn loss_is_congestive(&self) -> bool {
        let min_rtt = self.rtt.min_rtt();
        let queue_threshold = (min_rtt / 4).max(Duration::from_millis(2));
        if self.rtt.standing_queue() >= queue_threshold {
            return true;
        }
        let chunk = self.chunk.max(1) as f64;
        let sent = self.round_sent as f64 / chunk;
        let lost = self.round_lost as f64 / chunk;
        if sent >= 20.0 && lost / sent >= LOSS_CEILING {
            return true;
        }
        // More losses in this round than the background rate explains, by a
        // clear margin (about three standard deviations of a Poisson count):
        // one or two stray losses in a small round never qualify.
        let expected = self.base_loss_rate() * sent;
        lost > expected + 3.0 * (expected + 1.0).sqrt() + 1.0
    }

    /// Tail loss probe: when data is in flight but nothing was sent and no
    /// ACK made progress for about two RTTs, resend the last packet to
    /// provoke an ACK that reveals which packets were lost, instead of
    /// waiting for the RTO. ACKs without progress (the receiver repeating its
    /// holes) do not postpone the probe, and the probe fires no later than
    /// the RTO would, which it then postpones (RFC 8985 section 7.2): a lost
    /// tail is repaired with the current window instead of a collapsed one.
    fn maybe_send_tail_probe(&mut self, now: Instant) -> Result<(), SendError> {
        if self.inflight.is_empty()
            || self.stalled
            || self.tail_probes >= MAX_TAIL_PROBES
            || self.secure.is_none()
        {
            return Ok(());
        }
        let pto = (self.rtt.srtt() * 2 + self.rtt.max_ack_delay())
            .min(self.rtt.rto())
            .max(Duration::from_millis(10));
        let quiet_since = self.last_send_at.max(self.last_ack_progress);
        if now.saturating_duration_since(quiet_since) < pto {
            return Ok(());
        }
        let Some((s, e)) = self
            .inflight
            .iter()
            .next_back()
            .map(|(&k, inf)| (k, inf.end))
        else {
            return Ok(());
        };
        self.read_buf.resize((e - s) as usize, 0);
        self.reader.read_at(s, &mut self.read_buf)?;
        let ts = self.clock.now_us().max(1);
        {
            let sec = self.secure.as_mut().expect("checked above");
            seal_data(
                sec,
                &mut self.tx_buf,
                DATA_FLAG_RETRANSMIT,
                s,
                ts,
                &self.read_buf,
            )
            .map_err(|e| SendError::Protocol(e.to_string()))?;
        }
        match self.socket.try_send_to(&self.tx_buf, self.peer) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(err) => return Err(SendError::Io(err)),
        }
        self.seq += 1;
        if let Some(inf) = self.inflight.get_mut(&s) {
            inf.sent_at = now;
            inf.seq = self.seq;
        }
        self.send_log.push_back((now, s, self.seq));
        self.retransmitted_bytes += e - s;
        self.bytes_sent += e - s;
        self.last_send_at = now;
        self.last_tail_probe_at = now;
        self.tail_probes += 1;
        self.tail_probe_count += 1;
        tracing::debug!("tail loss probe #{} for {}..{}", self.tail_probes, s, e);
        Ok(())
    }

    // ----- timers ----------------------------------------------------------

    fn housekeeping(&mut self, now: Instant) -> Result<(), SendError> {
        self.maybe_send_tail_probe(now)?;
        // Retransmission timeout.
        let rto = self.rtt.rto();
        let mut expired: Vec<u64> = Vec::new();
        while let Some(&(sent_at, off, seq)) = self.send_log.front() {
            match self.inflight.get(&off) {
                Some(inf) if inf.seq == seq => {
                    // As long as ACKs keep acknowledging new data the path
                    // is alive; unacknowledged packets are then either
                    // reported as holes or simply not described yet. A tail
                    // probe gets its answer before the timer may expire.
                    let since = sent_at
                        .max(self.last_ack_progress)
                        .max(self.last_tail_probe_at);
                    if now.saturating_duration_since(since) >= rto {
                        expired.push(off);
                        self.send_log.pop_front();
                    } else {
                        break;
                    }
                }
                _ => {
                    self.send_log.pop_front();
                }
            }
        }
        if !expired.is_empty() {
            let mut bytes = 0;
            for off in expired {
                if let Some(inf) = self.remove_inflight(off) {
                    bytes += inf.end - off;
                    self.pending.insert(off, inf.end);
                }
            }
            self.rto_events += 1;
            self.cc.on_rto(now);
            self.rtt.backoff();
            self.update_pacer();
            tracing::debug!(
                "RTO ({:?}): {} B back to pending, cwnd {} B",
                rto,
                bytes,
                self.cc.cwnd()
            );
        }

        // Nothing queued or in flight, yet the receiver still misses bytes:
        // the bookkeeping disagrees with the receiver. Ask it what it holds.
        let idle = self.pending.is_empty()
            && self.inflight.is_empty()
            && self.fin_verdict.is_none()
            && self.pending_fin.is_none()
            && self.max_ack_received < self.size;
        if idle {
            let wait = (self.rtt.srtt() * 4).max(Duration::from_millis(200));
            let due = self
                .last_idle_probe
                .is_none_or(|t| now.saturating_duration_since(t) >= wait);
            if due {
                if self.last_idle_probe.is_none() {
                    self.log_inconsistency();
                }
                self.last_idle_probe = Some(now);
                self.send_state_query();
            }
        } else if !self.pending.is_empty() || !self.inflight.is_empty() {
            self.last_idle_probe = None;
        }

        // Liveness.
        let since_rx = now.saturating_duration_since(self.last_rx);
        if since_rx >= self.cfg.stall_timeout && !self.stalled {
            self.stalled = true;
            tracing::warn!(
                "no packets from {} for {:?}; pausing and probing",
                self.peer,
                since_rx
            );
            emit(
                &self.events,
                TransferEvent::Stalled {
                    transfer_id: self.tid_hex(),
                    since: since_rx,
                },
            );
        }
        if self.stalled && since_rx >= self.cfg.give_up_timeout {
            emit(
                &self.events,
                TransferEvent::Failed {
                    transfer_id: self.tid_hex(),
                    error: format!("receiver unreachable for {:?}", since_rx),
                    resumable: true,
                },
            );
            return Err(SendError::PeerUnreachable(since_rx));
        }
        let ping_interval = if self.stalled {
            Duration::from_secs(1 << self.ping_backoff.min(2))
        } else {
            (self.rtt.rto() * 2).clamp(Duration::from_millis(500), Duration::from_secs(3))
        };
        if since_rx >= ping_interval
            && now.saturating_duration_since(self.last_ping) >= ping_interval
        {
            self.last_ping = now;
            if self.stalled {
                self.ping_backoff += 1;
            }
            let ts = self.clock.now_us().max(1);
            let _ = self.send_frame(0, &Message::Ping(Ping { timestamp: ts }));
            // After a few seconds of silence also perform a new handshake: a
            // live session answers with its current state, and a restarted
            // receiver (which lost the session keys) resumes from its saved
            // state.
            let resync_after = self.cfg.stall_timeout.min(Duration::from_secs(3));
            if since_rx >= resync_after && self.fin_verdict.is_none() {
                self.send_initiation()?;
            }
        }
        Ok(())
    }

    /// Sends HELLO over the session; the receiver answers with its exact
    /// current state, which `resync` then adopts.
    fn send_state_query(&mut self) {
        let ts = self.clock.now_us().max(1);
        if self.probe_ts.len() >= 16 {
            self.probe_ts.remove(0);
        }
        self.probe_ts.push(ts);
        let hello = Message::Hello(self.hello(ts));
        let _ = self.send_frame(HELLO_FLAG_RESUME, &hello);
    }

    /// Logs the evidence when the sender believes everything is delivered but
    /// the receiver reports otherwise. This indicates a bug; the transfer
    /// recovers through a resync, but the details are needed to fix it.
    fn log_inconsistency(&self) {
        tracing::warn!(
            "sender idle but receiver incomplete: receiver reports {} of {} B; resynchronising",
            self.max_ack_received,
            self.size
        );
        let base = self
            .ack_log
            .back()
            .map(|r| r.at)
            .unwrap_or_else(Instant::now);
        for r in &self.ack_log {
            tracing::warn!(
                "  ack -{:>6.1} ms: received {} contiguous {} highest {} holes {} first {:?} last {:?}{}",
                base.saturating_duration_since(r.at).as_secs_f64() * 1000.0,
                r.received,
                r.contiguous,
                r.highest,
                r.holes,
                r.first_hole,
                r.last_hole,
                if r.stale { " STALE" } else { "" }
            );
        }
    }

    fn stats(&mut self, now: Instant) -> TransferStats {
        let elapsed = now.saturating_duration_since(self.start);
        let dt = now
            .saturating_duration_since(self.last_progress_at)
            .as_secs_f64();
        let delta = self.received_bytes.saturating_sub(self.last_progress_bytes);
        let rate = if dt > 0.0 {
            delta as f64 * 8.0 / dt
        } else {
            0.0
        };
        let moved = self.received_bytes.saturating_sub(self.resumed_from);
        let avg = if elapsed.as_secs_f64() > 0.0 {
            moved as f64 * 8.0 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let remaining = self.size.saturating_sub(self.received_bytes);
        let eta = if rate > 0.0 {
            Some(Duration::from_secs_f64(remaining as f64 * 8.0 / rate))
        } else {
            None
        };
        TransferStats {
            transfer_id: self.tid_hex(),
            bytes_done: self.received_bytes,
            total_bytes: self.size,
            rate_bps: rate,
            avg_rate_bps: avg,
            rtt_ms: self.rtt.srtt().as_secs_f64() * 1000.0,
            cwnd_bytes: self.cc.cwnd(),
            inflight_bytes: self.inflight_bytes,
            chunk_size: self.chunk,
            retransmitted_bytes: self.retransmitted_bytes,
            loss_events: self.cc.loss_events(),
            elapsed,
            eta,
            stalled: self.stalled,
        }
    }

    fn emit_progress(&mut self, now: Instant) {
        let stats = self.stats(now);
        self.last_progress_at = now;
        self.last_progress_bytes = self.received_bytes;
        tracing::debug!(
            "progress {}/{} B, {:.1} Mbit/s, rtt {:.2} ms (min {:.2}), cwnd {} B, inflight {} B, \
             pending {} B, retx {} B, healed {} B, rto {}, delay exits {}, loss rate {:.2}%, \
             base {:.2}%, random losses {}, tail probes {}",
            stats.bytes_done,
            stats.total_bytes,
            stats.rate_bps / 1e6,
            stats.rtt_ms,
            self.rtt.min_rtt().as_secs_f64() * 1000.0,
            stats.cwnd_bytes,
            stats.inflight_bytes,
            self.pending.total(),
            stats.retransmitted_bytes,
            self.healed_bytes,
            self.rto_events,
            self.cc.delay_exits(),
            self.loss_rate * 100.0,
            self.base_loss_rate() * 100.0,
            self.random_loss_events,
            self.tail_probe_count
        );
        emit(&self.events, TransferEvent::Progress(stats));
    }
}

pub fn reason_name(code: u8) -> &'static str {
    match code {
        REASON_NONE => "none",
        REASON_DISK_SPACE => "not enough disk space",
        REASON_BAD_FILE_NAME => "bad file name",
        REASON_BUSY => "receiver busy",
        REASON_DECLINED => "declined by user",
        REASON_CONN_CONFLICT => "connection id conflict",
        REASON_INTERNAL => "internal error",
        REASON_TIMEOUT => "decision timeout",
        REASON_UNAUTHORIZED => "sender not authorized",
        REASON_NO_SUITE => "no cipher in common",
        _ => "unknown",
    }
}
