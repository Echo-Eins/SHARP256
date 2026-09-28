//! Configuration for the sender and receiver engines.

use crate::progress::EventCallback;
use crate::protocol::constants::*;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Tunables shared by both ends of a transfer. Defaults are chosen for a
/// wide range of paths (LAN through lossy WAN) and can be tightened per use.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Largest file-bytes-per-packet the endpoint is willing to use. The
    /// effective chunk is negotiated and (on the sender) probed.
    pub max_chunk: u16,
    /// Probe the path for the largest working datagram before sending data.
    pub probe_mtu: bool,
    /// Sender: initial congestion window in chunks.
    pub initial_cwnd_chunks: u32,
    /// Sender: upper bound for the congestion window in bytes.
    pub max_cwnd_bytes: u64,
    /// Sender: optional hard cap on the send rate, in bytes per second.
    pub max_rate_bytes: Option<u64>,
    /// Receiver: send an ACK at least this often while data is arriving.
    pub ack_interval: Duration,
    /// Receiver: send an ACK after this many DATA packets.
    pub ack_every_packets: u32,
    /// Lower and upper bounds for the retransmission timeout.
    pub min_rto: Duration,
    pub max_rto: Duration,
    /// No packet from the peer for this long: the transfer is "stalled"
    /// (sending pauses, liveness probes continue).
    pub stall_timeout: Duration,
    /// Stalled for this long: give up (state is kept for resume).
    pub give_up_timeout: Duration,
    /// Total time allowed for the handshake (HELLO retries with backoff).
    pub handshake_timeout: Duration,
    /// Kernel socket buffer size requested for send and receive.
    pub socket_buffer_bytes: usize,
    /// Receiver: persist resume state at most this often.
    pub persist_interval: Duration,
    /// Receiver: bytes of not-yet-written data the writer thread may hold.
    pub writer_capacity_bytes: u64,
    /// Receiver: how long an idle session is kept in memory before it is
    /// dropped (its state stays on disk for resume).
    pub session_ttl: Duration,
    /// Emit a progress event at most this often.
    pub progress_interval: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_chunk: DEFAULT_CHUNK,
            probe_mtu: true,
            initial_cwnd_chunks: 32,
            max_cwnd_bytes: 256 << 20,
            max_rate_bytes: None,
            ack_interval: Duration::from_millis(20),
            ack_every_packets: 8,
            min_rto: Duration::from_millis(100),
            max_rto: Duration::from_secs(30),
            stall_timeout: Duration::from_secs(20),
            give_up_timeout: Duration::from_secs(300),
            handshake_timeout: Duration::from_secs(60),
            socket_buffer_bytes: 8 << 20,
            persist_interval: Duration::from_secs(2),
            writer_capacity_bytes: 64 << 20,
            session_ttl: Duration::from_secs(600),
            progress_interval: Duration::from_millis(250),
        }
    }
}

impl TransportConfig {
    /// Clamps values into ranges the protocol can carry.
    pub fn normalized(mut self) -> Self {
        self.max_chunk = self.max_chunk.clamp(MIN_CHUNK, MAX_CHUNK);
        self.initial_cwnd_chunks = self.initial_cwnd_chunks.clamp(2, 1024);
        self.ack_every_packets = self.ack_every_packets.max(1);
        if self.ack_interval < Duration::from_millis(1) {
            self.ack_interval = Duration::from_millis(1);
        }
        if self.max_rto < self.min_rto {
            self.max_rto = self.min_rto;
        }
        self
    }
}

/// Who may start a transfer on a receiver.
#[derive(Clone)]
pub enum AcceptPolicy {
    /// Accept every well-formed request (default for headless operation).
    AcceptAll,
    /// Ask the application; it answers through the oneshot channel. No answer
    /// within the handshake timeout means "declined".
    Ask(std::sync::Arc<dyn Fn(IncomingRequest, tokio::sync::oneshot::Sender<bool>) + Send + Sync>),
}

impl std::fmt::Debug for AcceptPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptPolicy::AcceptAll => f.write_str("AcceptAll"),
            AcceptPolicy::Ask(_) => f.write_str("Ask(..)"),
        }
    }
}

/// Description of an incoming transfer offered to an `AcceptPolicy::Ask`.
#[derive(Debug, Clone)]
pub struct IncomingRequest {
    pub transfer_id: String,
    pub peer: SocketAddr,
    pub file_name: String,
    pub file_size: u64,
    /// Bytes already stored from an earlier attempt (resume).
    pub resumed_bytes: u64,
}

#[derive(Clone)]
pub struct SenderConfig {
    pub bind: SocketAddr,
    pub peer: SocketAddr,
    pub file_path: PathBuf,
    pub transport: TransportConfig,
    /// Directory for resume state; `None` = per-user data directory.
    pub state_dir: Option<PathBuf>,
    pub events: Option<EventCallback>,
}

impl std::fmt::Debug for SenderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderConfig")
            .field("bind", &self.bind)
            .field("peer", &self.peer)
            .field("file_path", &self.file_path)
            .field("transport", &self.transport)
            .field("state_dir", &self.state_dir)
            .field("events", &self.events.is_some())
            .finish()
    }
}

impl SenderConfig {
    pub fn new(peer: SocketAddr, file_path: PathBuf) -> Self {
        Self {
            bind: "0.0.0.0:0".parse().unwrap(),
            peer,
            file_path,
            transport: TransportConfig::default(),
            state_dir: None,
            events: None,
        }
    }
}

#[derive(Clone)]
pub struct ReceiverConfig {
    pub bind: SocketAddr,
    pub output_dir: PathBuf,
    /// Replace an existing complete file with the same name instead of
    /// writing `name (1).ext`.
    pub overwrite: bool,
    pub max_sessions: usize,
    pub transport: TransportConfig,
    pub state_dir: Option<PathBuf>,
    /// Discover the public address (STUN) and ask the router for a port
    /// forward (UPnP) in the background. Requires the `nat-traversal` feature.
    pub nat_traversal: bool,
    pub accept: AcceptPolicy,
    pub events: Option<EventCallback>,
}

impl std::fmt::Debug for ReceiverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiverConfig")
            .field("bind", &self.bind)
            .field("output_dir", &self.output_dir)
            .field("overwrite", &self.overwrite)
            .field("max_sessions", &self.max_sessions)
            .field("transport", &self.transport)
            .field("state_dir", &self.state_dir)
            .field("nat_traversal", &self.nat_traversal)
            .field("accept", &self.accept)
            .field("events", &self.events.is_some())
            .finish()
    }
}

impl ReceiverConfig {
    pub fn new(bind: SocketAddr, output_dir: PathBuf) -> Self {
        Self {
            bind,
            output_dir,
            overwrite: false,
            max_sessions: 16,
            transport: TransportConfig::default(),
            state_dir: None,
            nat_traversal: false,
            accept: AcceptPolicy::AcceptAll,
            events: None,
        }
    }
}
