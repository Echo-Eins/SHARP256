//! Configuration for the sender and receiver engines.

use crate::crypto::{Identity, SharpId};
use crate::progress::{DirectoryInfo, EventCallback};
use crate::protocol::constants::*;
use std::collections::HashSet;
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
            socket_buffer_bytes: 32 << 20,
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
    /// Authenticated identity of the sender.
    pub sender_id: SharpId,
    /// Name of the file, or of the directory.
    pub file_name: String,
    pub file_size: u64,
    /// Set for a directory transfer.
    pub directory: Option<DirectoryInfo>,
    /// Bytes already stored from an earlier attempt (resume).
    pub resumed_bytes: u64,
}

#[derive(Clone)]
pub struct SenderConfig {
    pub bind: SocketAddr,
    pub peer: SocketAddr,
    /// Further addresses the same receiver may answer at. A name usually
    /// resolves to several (see `address::resolve_all`), and only one of
    /// them may be reachable. Handshake attempts rotate through `peer` and
    /// these until one is answered; the handshake itself decides which
    /// address is really the receiver, so a wrong or forged one costs time
    /// rather than safety.
    pub alternate_peers: Vec<SocketAddr>,
    /// Identity of the receiver. Only the holder of its private key can
    /// answer the handshake, so this authenticates the receiver.
    pub receiver_id: SharpId,
    /// The file to send, or a directory to send with everything below it.
    pub file_path: PathBuf,
    pub transport: TransportConfig,
    /// Directory for resume state; `None` = per-user data directory.
    pub state_dir: Option<PathBuf>,
    /// Our identity; `None` = load (or create) the per-user identity file.
    pub identity: Option<Identity>,
    /// Pre-shared key (see `crypto::psk_from_passphrase`), if the receiver
    /// requires one.
    pub psk: Option<[u8; 32]>,
    /// Relays to ask for an introduction when the receiver's own addresses
    /// do not answer. Each adds two more candidates: where the receiver
    /// appears to be, and the relay's own port for the pair.
    pub relays: Vec<String>,
    pub events: Option<EventCallback>,
}

impl std::fmt::Debug for SenderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderConfig")
            .field("bind", &self.bind)
            .field("peer", &self.peer)
            .field("alternate_peers", &self.alternate_peers)
            .field("receiver_id", &self.receiver_id)
            .field("file_path", &self.file_path)
            .field("transport", &self.transport)
            .field("state_dir", &self.state_dir)
            .field("identity", &self.identity)
            .field("psk", &self.psk.is_some())
            .field("relays", &self.relays)
            .field("events", &self.events.is_some())
            .finish()
    }
}

impl SenderConfig {
    pub fn new(peer: SocketAddr, receiver_id: SharpId, file_path: PathBuf) -> Self {
        Self {
            bind: "0.0.0.0:0".parse().unwrap(),
            peer,
            alternate_peers: Vec::new(),
            receiver_id,
            file_path,
            transport: TransportConfig::default(),
            state_dir: None,
            identity: None,
            psk: None,
            relays: Vec::new(),
            events: None,
        }
    }
}

#[derive(Clone)]
pub struct ReceiverConfig {
    pub bind: SocketAddr,
    pub output_dir: PathBuf,
    /// Replace an existing complete file with the same name instead of
    /// writing `name (1).ext`. Directories are never replaced (nor merged):
    /// a received directory whose name is taken is stored as `name (1)`.
    pub overwrite: bool,
    pub max_sessions: usize,
    /// Memory all transfers together may hold for data not yet on disk:
    /// datagrams waiting to be processed (a quarter of it) and file data
    /// waiting to be written (the rest, shared among the transfers that
    /// are receiving). Each transfer's own limits still apply within it;
    /// this is what bounds them all together, whatever senders do.
    pub memory_budget: u64,
    /// Concurrent transfers one sender identity may hold. Without this the
    /// session limit is first-come-first-served: a single authenticated
    /// sender could take every slot and lock everybody else out, which the
    /// allow-list does not help with when the sender is on it.
    pub max_sessions_per_sender: usize,
    pub transport: TransportConfig,
    pub state_dir: Option<PathBuf>,
    /// Discover the public address (STUN), measure what the NAT does and
    /// ask the router for a port forward in the background. Requires the
    /// `nat-traversal` feature.
    pub nat_traversal: bool,
    /// Relays to register with, as `host:port`. A relay introduces a sender
    /// and this receiver to each other, and carries the transfer when they
    /// cannot meet directly — the case where both are behind NATs that give
    /// out a different port per destination, which nothing either end can
    /// do anything about. It is not trusted with anything: the traffic is
    /// sealed end to end, and a sender is still admitted on the strength of
    /// its identity.
    pub relays: Vec<String>,
    /// Ask the relays not to tell senders where this receiver is. Everything
    /// then goes through the relay: it costs its bandwidth and gives up the
    /// direct path, and it is the only arrangement in which a relay actually
    /// hides anyone.
    pub relay_private: bool,
    pub accept: AcceptPolicy,
    /// Our identity; `None` = load (or create) the per-user identity file.
    pub identity: Option<Identity>,
    /// Pre-shared key every sender must also use, if any.
    pub psk: Option<[u8; 32]>,
    /// Senders allowed to start transfers; `None` admits any sender that
    /// knows this receiver's ID.
    pub allowed_senders: Option<HashSet<SharpId>>,
    /// Handshakes per second (and burst) accepted from one source address.
    pub handshake_rate: f64,
    pub handshake_burst: f64,
    /// Handshakes per second (all sources) beyond which senders must first
    /// prove their address with a cookie.
    pub handshake_load_threshold: u32,
    pub events: Option<EventCallback>,
}

impl std::fmt::Debug for ReceiverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiverConfig")
            .field("bind", &self.bind)
            .field("output_dir", &self.output_dir)
            .field("overwrite", &self.overwrite)
            .field("max_sessions", &self.max_sessions)
            .field("memory_budget", &self.memory_budget)
            .field("max_sessions_per_sender", &self.max_sessions_per_sender)
            .field("transport", &self.transport)
            .field("state_dir", &self.state_dir)
            .field("nat_traversal", &self.nat_traversal)
            .field("relays", &self.relays)
            .field("relay_private", &self.relay_private)
            .field("accept", &self.accept)
            .field("identity", &self.identity)
            .field("psk", &self.psk.is_some())
            .field("allowed_senders", &self.allowed_senders)
            .field("handshake_rate", &self.handshake_rate)
            .field("handshake_load_threshold", &self.handshake_load_threshold)
            .field("events", &self.events.is_some())
            .finish()
    }
}

impl ReceiverConfig {
    /// Whether this receiver is to be reached only through its relays: it
    /// asked them to keep its address to themselves, so it publishes none
    /// of its own either — no NAT discovery, no port forward, no direct
    /// candidates — or the relay would be hiding what the receiver itself
    /// hands out.
    pub fn relay_only(&self) -> bool {
        self.relay_private && !self.relays.is_empty()
    }

    /// How a sender should be told to reach this receiver, before anything
    /// has been discovered about the network.
    pub fn contact_hint(&self, id: &crate::crypto::SharpId) -> String {
        if self.relay_only() {
            let relays: Vec<String> = self
                .relays
                .iter()
                .map(|r| {
                    // Senders need only the address part.
                    let host = r.rsplit_once('@').map_or(r.as_str(), |(_, h)| h);
                    format!("--relay {}", host)
                })
                .collect();
            format!("{} {}", id, relays.join(" "))
        } else {
            format!("{}@<this host>:{}", id, self.bind.port())
        }
    }

    pub fn new(bind: SocketAddr, output_dir: PathBuf) -> Self {
        Self {
            bind,
            output_dir,
            overwrite: false,
            max_sessions: 16,
            memory_budget: 512 << 20,
            max_sessions_per_sender: 8,
            transport: TransportConfig::default(),
            state_dir: None,
            nat_traversal: false,
            relays: Vec::new(),
            relay_private: false,
            accept: AcceptPolicy::AcceptAll,
            identity: None,
            psk: None,
            allowed_senders: None,
            handshake_rate: 20.0,
            handshake_burst: 40.0,
            handshake_load_threshold: 200,
            events: None,
        }
    }
}
