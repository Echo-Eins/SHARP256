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
    /// Names the receiver is published under (`host:port`), resolved while
    /// the addresses above are already being tried: each family is asked
    /// for separately and its addresses join the attempts as they arrive,
    /// the way RFC 8305 (Happy Eyeballs) describes, so a name server that
    /// is slow to answer one family holds nothing up.
    pub peer_names: Vec<String>,
    /// Identity of the receiver. Only the holder of its private key can
    /// answer the handshake, so this authenticates the receiver.
    pub receiver_id: SharpId,
    /// The protocol version to speak to it, as its ID or card names it
    /// (`sh4-`: version 4, and never version 3 — nobody on the way can talk
    /// the sender down by dropping what it sends).
    pub receiver_version: crate::crypto::handshake::Version,
    /// The file to send, or a directory to send with everything below it.
    pub file_path: PathBuf,
    pub transport: TransportConfig,
    /// Directory for resume state; `None` = per-user data directory.
    pub state_dir: Option<PathBuf>,
    /// Our identity; `None` = load (or create) the per-user identity file.
    pub identity: Option<Identity>,
    /// Pre-shared key (see `crypto::psk_from_passphrase`), if the receiver
    /// requires one.
    pub psk: Option<crate::crypto::SecretKey>,
    /// Relays to ask for an introduction when the receiver's own addresses
    /// do not answer. Each adds two more candidates: where the receiver
    /// appears to be, and the relay's own port for the pair.
    pub relays: Vec<String>,
    /// Find out what this host's NAT does (RFC 5780), so that a relay can
    /// tell the receiver how to aim its punches and ours can be aimed in
    /// return. Only done when there are relays to tell.
    pub nat_traversal: bool,
    /// Servers for those tests; empty = the built-in list. A
    /// `sharp-relay --stun` is one.
    pub stun_servers: Vec<String>,
    /// The receiver's contact card, when the sender was given one instead
    /// of an address (see `nat::card`): the sender then also punches
    /// towards every address on it, aimed by what it says the receiver's
    /// NAT does, for as long as it takes the receiver's user to be handed
    /// the sender's own.
    #[cfg(feature = "nat-traversal")]
    pub peer_card: Option<crate::nat::card::Card>,
    /// Give the receiver's user this sender's contact card and addresses
    /// even though the receiver was given by address (which says nothing of
    /// this side): the NAT tests are run, the router is asked for a port, and
    /// the result is reported as [`crate::TransferEvent::ContactCard`].
    /// Done anyway with the receiver's card, a TURN server or the DHT. The
    /// receiver's addresses are then punched at as a card's are, and for as
    /// long, since its user will be punching back at ours.
    ///
    /// The card is made of what the NAT tests find, so it needs
    /// `nat_traversal`; the punching does not, as with the receiver's card.
    pub give_card: bool,
    /// Ask the local network for the receiver with multicast DNS, once, at
    /// the start (it has to announce itself: `ReceiverConfig::announce_lan`).
    /// A question tells everybody on the network whom this sender is
    /// looking for, so it is not asked unless asked for.
    pub find_lan: bool,
    /// TURN servers this sender may be reached through, and may reach the
    /// receiver through: `USER:PASSWORD@HOST[:PORT]` (see `nat::turn`). The
    /// address each gives is on the sender's card, and the receiver's
    /// addresses are tried through each as well.
    pub turn_servers: Vec<String>,
    /// Find the receiver's address through the Mainline DHT (see
    /// `nat::dht`): announce this sender and look for the receiver under
    /// infohashes derived from the receiver's ID and the shared secret.
    /// Tells every DHT node asked this host's address, and — without a
    /// shared secret — lets anybody who knows the receiver's ID see it.
    pub dht: bool,
    /// DHT nodes to start from, `host:port`; empty means the well-known ones.
    pub dht_bootstrap: Vec<String>,
    /// When UDP does not answer within `transport::carrier::CARRIER_DELAY`,
    /// or stops in the middle of a transfer, try the receiver over TCP as
    /// well — the same datagrams, framed on a stream — and go back to UDP
    /// when it answers again (see `transport::carrier`).
    pub carriers: bool,
    /// The port the relays take TLS on (see `relay::tls`), tried alongside
    /// TCP at their own port when streams are: 443, where a network lets
    /// little but HTTPS out.
    pub relay_tls_port: u16,
    pub events: Option<EventCallback>,
}

impl std::fmt::Debug for SenderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderConfig")
            .field("bind", &self.bind)
            .field("peer", &self.peer)
            .field("alternate_peers", &self.alternate_peers)
            .field("peer_names", &self.peer_names)
            .field("receiver_id", &self.receiver_id)
            .field("receiver_version", &self.receiver_version)
            .field("file_path", &self.file_path)
            .field("transport", &self.transport)
            .field("state_dir", &self.state_dir)
            .field("identity", &self.identity)
            .field("psk", &self.psk.is_some())
            .field("relays", &self.relays)
            .field("nat_traversal", &self.nat_traversal)
            .field("stun_servers", &self.stun_servers)
            .field("find_lan", &self.find_lan)
            .field("turn_servers", &self.turn_servers.len())
            .field("dht", &self.dht)
            .field("carriers", &self.carriers)
            .field("relay_tls_port", &self.relay_tls_port)
            .field("events", &self.events.is_some())
            .finish()
    }
}

impl SenderConfig {
    /// A sender for a receiver published under `hosts` (see
    /// `address::parse_peer`): the literal addresses become `peer` and
    /// `alternate_peers`, in the order RFC 6724 would try them with the
    /// families taking turns (RFC 8305 section 4), and the names become
    /// `peer_names`, resolved while the literals are already being tried.
    /// With no literal address at all, `peer` is unspecified — "none yet".
    pub fn for_hosts(hosts: &[String], receiver_id: SharpId, file_path: PathBuf) -> Self {
        let targets = crate::address::targets(hosts);
        let peer = targets
            .addrs
            .first()
            .copied()
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let mut cfg = Self::new(peer, receiver_id, file_path);
        cfg.alternate_peers = targets.addrs.get(1..).unwrap_or_default().to_vec();
        cfg.peer_names = targets.names;
        cfg
    }

    pub fn new(peer: SocketAddr, receiver_id: SharpId, file_path: PathBuf) -> Self {
        Self {
            // Both families where the system has them (see
            // `transport::socket::bind_udp`), IPv4 alone where it does not.
            bind: "[::]:0".parse().unwrap(),
            peer,
            alternate_peers: Vec::new(),
            peer_names: Vec::new(),
            receiver_id,
            receiver_version: crate::crypto::handshake::Version::V3,
            file_path,
            transport: TransportConfig::default(),
            state_dir: None,
            identity: None,
            psk: None,
            relays: Vec::new(),
            nat_traversal: false,
            stun_servers: Vec::new(),
            #[cfg(feature = "nat-traversal")]
            peer_card: None,
            give_card: false,
            find_lan: false,
            turn_servers: Vec::new(),
            dht: false,
            dht_bootstrap: Vec::new(),
            carriers: true,
            relay_tls_port: 443,
            events: None,
        }
    }

    /// A sender for the receiver a contact card describes: its identity,
    /// every address on it in the order the card lists them, and the relays
    /// it names (which need no address of their own to be asked).
    #[cfg(feature = "nat-traversal")]
    pub fn for_card(card: crate::nat::card::Card, file_path: PathBuf) -> Self {
        let addrs: Vec<SocketAddr> = card.punch_targets().into_iter().map(|(a, _)| a).collect();
        let peer = addrs
            .first()
            .copied()
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let mut cfg = Self::new(peer, card.id, file_path);
        cfg.receiver_version = card.version;
        cfg.alternate_peers = addrs.get(1..).unwrap_or_default().to_vec();
        cfg.relays = card
            .relays
            .iter()
            .map(|r| format!("{}@{}", r.id, r.addr))
            .collect();
        cfg.peer_card = Some(card);
        // The receiver's user may take a while to be handed ours.
        cfg.transport.handshake_timeout = crate::nat::punch::MEET_DURATION;
        cfg
    }
}

#[derive(Clone)]
pub struct ReceiverConfig {
    pub bind: SocketAddr,
    /// Take senders over TCP too, at the port number the UDP socket has:
    /// for those whose network lets no UDP out (see `transport::carrier`).
    /// The same datagrams, framed on a stream; nothing else changes.
    pub tcp: bool,
    /// The port the relays take TLS on (see `relay::tls`): what a
    /// registration is made over, alongside TCP at their own port, when no
    /// registration gets through over UDP.
    pub relay_tls_port: u16,
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
    /// Publish this host's addresses on the local network — private IPv4,
    /// unique-local IPv6 — among the receiver's candidates. They let a
    /// sender on the same network in directly; they also tell whoever is
    /// given the receiver's address how that network is laid out. Off, only
    /// addresses the internet routes are published.
    pub publish_lan_addresses: bool,
    /// How often, at most, something is sent to keep this receiver's NAT
    /// mapping alive while nothing else flows: a keepalive to the STUN
    /// server behind a published address, and each relay registration.
    /// RFC 8445 (section 11) suggests 15 seconds, which is the default;
    /// the receiver sends less often once it has measured that its NAT
    /// keeps mappings longer, and more often when it sees one lapse.
    pub nat_keepalive: Duration,
    /// STUN servers (`host:port`) that tell this receiver how it is seen
    /// from outside and what its NAT does. Empty: the built-in public ones.
    /// A relay run with `--stun` is one, and the only kind that can carry
    /// out every behaviour test.
    pub stun_servers: Vec<String>,
    /// Announce this receiver on the local network with multicast DNS, so
    /// that a sender there that knows its ID can find it without being told
    /// an address. Off unless asked for: the announcement tells everybody on
    /// the network that this host receives SHARP-256 transfers.
    pub announce_lan: bool,
    /// Answer version 4 handshakes (the hybrid one, `sh4-` IDs) as well as
    /// version 3 ones. On; off only to stand in for a receiver that knows
    /// no version 4 (the tests do).
    pub speak_v4: bool,
    /// TURN servers this receiver is reached through when nothing direct
    /// works: `USER:PASSWORD@HOST[:PORT]` (see `nat::turn`). The address
    /// each gives is published with the others, and a sender is let in once
    /// its address is known (from its card or a relay's introduction).
    pub turn_servers: Vec<String>,
    /// Announce this receiver in the Mainline DHT and look there for the
    /// sender (see `nat::dht`), so that the two find each other's addresses
    /// with nothing but the receiver's ID (and the shared secret) to go by.
    /// Tells every DHT node asked this host's address, and — without a
    /// shared secret — lets anybody who knows the receiver's ID see it.
    pub dht: bool,
    /// DHT nodes to start from, `host:port`; empty means the well-known ones.
    pub dht_bootstrap: Vec<String>,
    pub accept: AcceptPolicy,
    /// Our identity; `None` = load (or create) the per-user identity file.
    pub identity: Option<Identity>,
    /// Pre-shared key every sender must also use, if any.
    pub psk: Option<crate::crypto::SecretKey>,
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
            .field("tcp", &self.tcp)
            .field("relay_tls_port", &self.relay_tls_port)
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
            .field("publish_lan_addresses", &self.publish_lan_addresses)
            .field("nat_keepalive", &self.nat_keepalive)
            .field("stun_servers", &self.stun_servers)
            .field("announce_lan", &self.announce_lan)
            .field("speak_v4", &self.speak_v4)
            .field("turn_servers", &self.turn_servers.len())
            .field("dht", &self.dht)
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
            format!("{} {}", self.id_text(id), relays.join(" "))
        } else {
            format!("{}@<this host>:{}", self.id_text(id), self.bind.port())
        }
    }

    /// The receiver's ID in the form senders are to use: `sh4-` when it
    /// speaks version 4, so that they speak nothing older to it.
    pub fn id_text(&self, id: &crate::crypto::SharpId) -> String {
        id.text(if self.speak_v4 {
            crate::crypto::handshake::Version::V4
        } else {
            crate::crypto::handshake::Version::V3
        })
    }

    pub fn new(bind: SocketAddr, output_dir: PathBuf) -> Self {
        Self {
            bind,
            tcp: true,
            relay_tls_port: 443,
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
            publish_lan_addresses: true,
            nat_keepalive: Duration::from_secs(15),
            stun_servers: Vec::new(),
            announce_lan: false,
            speak_v4: true,
            turn_servers: Vec::new(),
            dht: false,
            dht_bootstrap: Vec::new(),
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
