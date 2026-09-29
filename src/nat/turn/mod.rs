//! A TURN client (RFC 8656, and RFC 6156 for IPv6): a relay run by somebody
//! else, for when two NATs will not let a direct path open.
//!
//! **What it is for.** A relayed address is a public address on the TURN
//! server: whatever is sent to it is passed to us, and the NAT we are
//! behind needs to know nothing about the sender. So a receiver that holds
//! one can be reached by a sender behind any NAT at all, and a sender that
//! holds one can reach a receiver whose NAT would otherwise have to guess
//! its port — two symmetric NATs, the case nothing else here can punch.
//!
//! **What it costs.** The server sees, and carries, every datagram, at its
//! own bandwidth and its own price; it cannot read or change them (they are
//! sealed end to end, as through any relay). It also has to be told who may
//! send: a permission is per IP address, and until it exists the server
//! drops what arrives, so the other end's address has to be known first —
//! from a contact card, or from a relay's introduction.
//!
//! **How it meets the transfer.** The engine talks plain UDP and is left
//! alone. Each allocation has its own socket, and for every peer a small
//! loopback socket, the *shim*: the engine sends to the shim as if it were
//! the peer, and what arrives from the peer through the server is handed to
//! the engine from the shim's address. A peer is one address on loopback as
//! far as the engine is concerned, and TURN framing never reaches it.
//!
//! Only UDP to the server is spoken: TURN over TCP or TLS is a carrier, not
//! a NAT technique, and belongs with the other carriers.

pub mod wire;

#[cfg(test)]
mod tests;

use crate::address::canonical;
use crate::nat::stun::transaction_id;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use wire::{
    Builder, Class, Credentials, ALLOCATE, ATTR_CHANNEL_NUMBER, ATTR_DATA, ATTR_LIFETIME,
    ATTR_NONCE, ATTR_REALM, ATTR_REQUESTED_ADDRESS_FAMILY, ATTR_REQUESTED_TRANSPORT,
    ATTR_XOR_PEER_ADDRESS, ATTR_XOR_RELAYED_ADDRESS, BINDING, CHANNEL_BIND, CHANNEL_MAX,
    CHANNEL_MIN, CREATE_PERMISSION, DATA, FAMILY_IPV4, FAMILY_IPV6, REFRESH, SEND, TRANSPORT_UDP,
};

/// The port a TURN server listens on unless told otherwise (RFC 8656).
pub const DEFAULT_PORT: u16 = 3478;

/// How long a request is retransmitted, with each gap: a lost datagram
/// costs half a second, and a server that has gone is known in a few.
const RETRANSMIT: [Duration; 4] = [
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];
/// How often a Binding request keeps the NAT's mapping towards the server
/// alive, and shows when it has changed. Shorter than the shortest UDP
/// timeout worth designing for (RFC 4787 asks for two minutes; RFC 5382
/// style deployments are known to use 30 seconds).
const KEEPALIVE: Duration = Duration::from_secs(25);
/// Permissions live five minutes (RFC 8656 section 9) and are renewed a
/// minute early; channel bindings live ten (section 12).
const PERMISSION_REFRESH: Duration = Duration::from_secs(240);
const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
const CHANNEL_REFRESH: Duration = Duration::from_secs(540);
/// A peer nothing has been said to or heard from for this long is let go.
const ROUTE_IDLE: Duration = Duration::from_secs(300);
/// One that has been quiet this long is let go early, to make room.
const ROUTE_QUIET: Duration = Duration::from_secs(10);
/// Peers carried at once. A session has one peer; a few more are for a
/// peer that is at more than one address.
const MAX_ROUTES: usize = 16;
/// Permissions asked for in one request.
const PERMISSIONS_PER_REQUEST: usize = 8;
/// Largest datagram sent through: the size every path carries (the
/// engine's own floor, `UDP_PAYLOAD_SAFE`), so that it can always fall back
/// to it. The framing adds up to 48 bytes on the way to the server, which
/// any link of the usual 1500 bytes has room for. A larger datagram is
/// dropped, which is also how the engine finds out that its path is smaller
/// than the loopback's.
pub const MAX_DATAGRAM: usize = crate::protocol::constants::UDP_PAYLOAD_SAFE;
/// Where the wait between allocation attempts starts and ends.
const RETRY_FIRST: Duration = Duration::from_secs(3);
const RETRY_LAST: Duration = Duration::from_secs(60);
/// Datagrams from the engine waiting to go out. More than this is dropped:
/// it is UDP, and the sender's congestion control is the answer to a queue.
const OUTBOUND_QUEUE: usize = 512;
/// The shortest allocation lifetime believed, and the longest. A server that
/// says less would have us refreshing in a tight loop; more is not to be
/// trusted to still be there.
#[cfg(not(test))]
const MIN_LIFETIME: u32 = 60;
#[cfg(test)]
const MIN_LIFETIME: u32 = 2;
const MAX_LIFETIME: u32 = 3600;

/// A TURN server and the long-term credentials for it.
#[derive(Clone, PartialEq, Eq)]
pub struct Server {
    /// `host:port`, resolved when it is used.
    pub address: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

/// What can be said of a server without giving its password away.
impl std::fmt::Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.username, self.address)
    }
}

impl std::str::FromStr for Server {
    type Err = String;

    /// `USER:PASSWORD@HOST[:PORT]`, with `turn:` or `turn://` in front if
    /// that is how it was written. The password may contain `:` and `@`
    /// (the host is what follows the last `@`); a user name with a colon in
    /// it is written as a URL writes it, `%3A`, and so is a literal `%`
    /// (`%25`) in either.
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.starts_with("turns:") {
            return Err(
                "turns: (TURN over TLS) is not spoken: only TURN over UDP is; \
                 use turn: and a UDP port"
                    .to_string(),
            );
        }
        let s = s
            .strip_prefix("turn://")
            .or_else(|| s.strip_prefix("turn:"))
            .unwrap_or(s);
        let (creds, host) = s
            .rsplit_once('@')
            .ok_or_else(|| "a TURN server is written USER:PASSWORD@HOST[:PORT]".to_string())?;
        let (username, password) = creds
            .split_once(':')
            .ok_or_else(|| "a TURN server is written USER:PASSWORD@HOST[:PORT]".to_string())?;
        if username.is_empty() || host.is_empty() {
            return Err("a TURN server needs a user name and a host".to_string());
        }
        // A time-limited credential (the "TURN REST API" kind) has a colon
        // in its user name, and a URL writes that as %3A.
        let username = percent_decode(username)?;
        let password = percent_decode(password)?;
        // Without a port the well-known one is meant. An IPv6 literal has
        // colons of its own, so only `]:` or a single colon says there is one.
        let has_port = if host.starts_with('[') {
            host.contains("]:")
        } else {
            host.matches(':').count() == 1
        };
        let address = if has_port {
            host.to_string()
        } else if host.starts_with('[') {
            format!("{}:{}", host, DEFAULT_PORT)
        } else {
            // A bare IPv6 address (`2001:db8::1`) is not written this way.
            if host.contains(':') {
                return Err(
                    "an IPv6 address is written in brackets: [2001:db8::1]:3478".to_string()
                );
            }
            format!("{}:{}", host, DEFAULT_PORT)
        };
        Ok(Self {
            address,
            username,
            password,
        })
    }
}

/// `%XX` escapes undone, as in a URL; anything else is taken as it is.
fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| "a % in a user name or password is followed by two hexadecimal digits (write a literal one as %25)".to_string())?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "a user name or password that is not text".to_string())
}

/// The family of the address a server is asked to allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn wire(self) -> u8 {
        match self {
            Family::V4 => FAMILY_IPV4,
            Family::V6 => FAMILY_IPV6,
        }
    }

    fn of(ip: IpAddr) -> Self {
        if canonical(SocketAddr::new(ip, 0)).is_ipv6() {
            Family::V6
        } else {
            Family::V4
        }
    }
}

/// What the allocations of one [`Turn`] share, and what the engine reads.
struct Shared {
    relayed: parking_lot::Mutex<HashMap<u8, SocketAddr>>,
    /// Counts changes to `relayed`, so that whoever cares can wait for one.
    epoch: watch::Sender<u64>,
    /// The loopback addresses handed to the engine, one per peer.
    shims: parking_lot::RwLock<HashSet<SocketAddr>>,
}

/// A TURN allocation (or two: one for each family asked for) and the peers
/// it carries.
#[derive(Clone)]
pub struct Turn {
    shared: Arc<Shared>,
    commands: Arc<Vec<(Family, mpsc::UnboundedSender<Command>)>>,
    tasks: Arc<parking_lot::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

enum Command {
    Permit(IpAddr),
    Dial(SocketAddr, oneshot::Sender<Option<SocketAddr>>),
}

impl Turn {
    /// Starts allocating on `server`, one allocation for each of
    /// `families`, until `cancel` fires (when they are given back).
    ///
    /// `engine` is where the engine's socket can be reached from this host:
    /// a loopback address and its port when it is bound to a wildcard.
    /// Nothing is waited for here: the allocation is made in the
    /// background, retried while the server cannot be reached, and its
    /// relayed address appears in [`Turn::relayed`] when there is one.
    pub fn start(
        server: Server,
        engine: SocketAddr,
        families: &[Family],
        cancel: CancellationToken,
    ) -> Self {
        let (epoch, _) = watch::channel(0u64);
        let shared = Arc::new(Shared {
            relayed: parking_lot::Mutex::new(HashMap::new()),
            epoch,
            shims: parking_lot::RwLock::new(HashSet::new()),
        });
        let mut commands = Vec::new();
        let mut tasks = Vec::new();
        for &family in families {
            let (tx, rx) = mpsc::unbounded_channel();
            commands.push((family, tx));
            let alloc = Allocation::new(
                server.clone(),
                family,
                engine,
                shared.clone(),
                rx,
                cancel.clone(),
            );
            tasks.push(tokio::spawn(alloc.run()));
        }
        Self {
            shared,
            commands: Arc::new(commands),
            tasks: Arc::new(parking_lot::Mutex::new(tasks)),
        }
    }

    /// Waits, for no longer than `within`, for the allocations to have been
    /// given back after the token they were started with was cancelled.
    /// Without it a process that ends at once leaves them to run out on the
    /// server.
    pub async fn finished(&self, within: Duration) {
        let handles = std::mem::take(&mut *self.tasks.lock());
        let _ = tokio::time::timeout(within, async {
            for h in handles {
                let _ = h.await;
            }
        })
        .await;
    }

    /// The addresses on the server that reach us, IPv4 first. Empty until
    /// an allocation has been made, and again if it is lost.
    pub fn relayed(&self) -> Vec<SocketAddr> {
        let map = self.shared.relayed.lock();
        let mut out: Vec<SocketAddr> = [FAMILY_IPV4, FAMILY_IPV6]
            .iter()
            .filter_map(|f| map.get(f).copied())
            .collect();
        out.dedup();
        out
    }

    /// Follows [`Turn::relayed`]: the value counts its changes.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.shared.epoch.subscribe()
    }

    /// Lets `ip` send to our relayed address. Until it is asked for the
    /// server drops what comes from there; a permission is per address, not
    /// per port, and is kept up until we are cancelled.
    pub fn permit(&self, ip: IpAddr) {
        let family = Family::of(ip);
        for (f, tx) in self.commands.iter() {
            if *f == family {
                let _ = tx.send(Command::Permit(ip));
            }
        }
    }

    /// An address on this host that reaches `peer` through the server: what
    /// is sent there goes to `peer` from our relayed address, and what
    /// `peer` sends to that address comes back from it. `None` when there
    /// is no allocation for the peer's family, or too many peers.
    ///
    /// Also permits the peer's address: without that the server would drop
    /// what it sends back.
    pub async fn dial(&self, peer: SocketAddr) -> Option<SocketAddr> {
        let peer = canonical(peer);
        let family = Family::of(peer.ip());
        // Nothing to go through until the server has given an address, and
        // an allocation still being made is not listening for requests.
        self.shared.relayed.lock().get(&family.wire())?;
        let (_, tx) = self.commands.iter().find(|(f, _)| *f == family)?;
        let (reply, answer) = oneshot::channel();
        tx.send(Command::Dial(peer, reply)).ok()?;
        tokio::time::timeout(Duration::from_secs(3), answer)
            .await
            .ok()?
            .ok()
            .flatten()
    }

    /// Whether `addr` is one of the loopback addresses [`Turn::dial`] and
    /// the peers reaching us through the server are given. The engine has to
    /// know them: they are the only addresses on this host it may be told a
    /// peer is at.
    pub fn is_shim(&self, addr: SocketAddr) -> bool {
        self.shared.shims.read().contains(&canonical(addr))
    }
}

/// Where a datagram sent from this host reaches `socket`: its own address,
/// or loopback when it is bound to a wildcard. This is what the shims
/// deliver to.
pub fn engine_address(socket: &UdpSocket) -> Option<SocketAddr> {
    let local = socket.local_addr().ok()?;
    if !local.ip().is_unspecified() {
        return Some(local);
    }
    // A wildcard IPv6 socket takes IPv4 loopback as well, unless it was made
    // to take IPv6 alone.
    let ip: IpAddr = if crate::address::Reach::of(socket).v4() {
        std::net::Ipv4Addr::LOCALHOST.into()
    } else {
        std::net::Ipv6Addr::LOCALHOST.into()
    };
    Some(SocketAddr::new(ip, local.port()))
}

/// Starts an allocation on each of `servers` for the transfer socket,
/// written as [`Server`] says. One for IPv6 too where this host has a global
/// address there: a server that has none to give says so, and that is not
/// worth more than a line.
pub fn start_all(servers: &[String], socket: &UdpSocket, cancel: &CancellationToken) -> Vec<Turn> {
    let Some(engine) = engine_address(socket) else {
        return Vec::new();
    };
    let has_v6 = socket
        .local_addr()
        .map(|l| {
            crate::nat::host_addresses(l, false)
                .iter()
                .any(IpAddr::is_ipv6)
        })
        .unwrap_or(false);
    let families: &[Family] = if has_v6 {
        &[Family::V4, Family::V6]
    } else {
        &[Family::V4]
    };
    servers
        .iter()
        .filter_map(|s| match s.parse::<Server>() {
            Ok(server) => Some(Turn::start(server, engine, families, cancel.clone())),
            Err(e) => {
                tracing::warn!("TURN server ignored: {}", e);
                None
            }
        })
        .collect()
}

/// Where the shims hand what the engine sends to a peer.
type Outbound = mpsc::Sender<(SocketAddr, Vec<u8>)>;

/// A peer carried through an allocation.
struct Route {
    shim: Arc<UdpSocket>,
    shim_addr: SocketAddr,
    /// The channel the peer is bound to, once the server has said so.
    channel: Option<u16>,
    /// The number asked for while the answer is outstanding.
    binding: Option<u16>,
    channel_refresh_at: Instant,
    last_used: Instant,
    cancel: CancellationToken,
}

struct Permission {
    /// Asked for again at this time (soon, until the server has said yes).
    due: Instant,
    /// Confirmed until this time.
    until: Option<Instant>,
}

enum TxKind {
    Refresh,
    Permission(Vec<IpAddr>),
    Bind(u16, SocketAddr),
    Binding,
}

struct Tx {
    kind: TxKind,
    bytes: Vec<u8>,
    sent: usize,
    next: Instant,
    /// Rebuilt with a new nonce at most this often for one request.
    renewed: u8,
}

/// Why an allocation ended or could not begin.
enum Failure {
    /// Asking again could change nothing: the server refused who we are.
    Fatal(String),
    Transient(String),
}

struct Allocation {
    server: Server,
    family: Family,
    engine: SocketAddr,
    shared: Arc<Shared>,
    commands: mpsc::UnboundedReceiver<Command>,
    cancel: CancellationToken,
    outbound: (Outbound, mpsc::Receiver<(SocketAddr, Vec<u8>)>),
    // What exists while there is an allocation.
    sock: Option<Arc<UdpSocket>>,
    server_addr: Option<SocketAddr>,
    cred: Option<Credentials>,
    lifetime: Duration,
    refresh_at: Instant,
    keepalive_at: Instant,
    pending: HashMap<[u8; 12], Tx>,
    permissions: HashMap<IpAddr, Permission>,
    routes: HashMap<SocketAddr, Route>,
    by_channel: HashMap<u16, SocketAddr>,
    next_channel: u16,
    told_full: bool,
}

/// Why the steady state ended.
enum Exit {
    Cancelled,
    /// The allocation is gone (the server forgot it, or stopped answering).
    Lost(String),
}

impl Allocation {
    fn new(
        server: Server,
        family: Family,
        engine: SocketAddr,
        shared: Arc<Shared>,
        commands: mpsc::UnboundedReceiver<Command>,
        cancel: CancellationToken,
    ) -> Self {
        let now = Instant::now();
        Self {
            server,
            family,
            engine,
            shared,
            commands,
            cancel,
            outbound: mpsc::channel(OUTBOUND_QUEUE),
            sock: None,
            server_addr: None,
            cred: None,
            lifetime: Duration::from_secs(600),
            refresh_at: now,
            keepalive_at: now,
            pending: HashMap::new(),
            permissions: HashMap::new(),
            routes: HashMap::new(),
            by_channel: HashMap::new(),
            next_channel: CHANNEL_MIN,
            told_full: false,
        }
    }

    async fn run(mut self) {
        let mut wait = RETRY_FIRST;
        loop {
            match self.connect().await {
                Ok(relayed) => {
                    wait = RETRY_FIRST;
                    self.publish(Some(relayed));
                    tracing::info!("TURN {}: relaying at {}", self.server, relayed);
                    let exit = self.steady().await;
                    self.publish(None);
                    match exit {
                        Exit::Cancelled => break,
                        Exit::Lost(why) => {
                            tracing::warn!(
                                "TURN {}: allocation lost ({}); asking again",
                                self.server,
                                why
                            )
                        }
                    }
                }
                Err(Failure::Fatal(why)) => {
                    tracing::warn!("TURN {}: {}", self.server, why);
                    return;
                }
                Err(Failure::Transient(why)) => {
                    tracing::info!("TURN {}: {}; trying again in {:?}", self.server, why, wait);
                }
            }
            self.forget_allocation();
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = self.cancel.cancelled() => break,
            }
            wait = (wait * 2).min(RETRY_LAST);
        }
        self.release().await;
    }

    fn publish(&self, relayed: Option<SocketAddr>) {
        {
            let mut map = self.shared.relayed.lock();
            match relayed {
                Some(a) => map.insert(self.family.wire(), canonical(a)),
                None => map.remove(&self.family.wire()),
            };
        }
        self.shared.epoch.send_modify(|n| *n += 1);
    }

    /// Everything that belonged to an allocation that is gone.
    fn forget_allocation(&mut self) {
        self.pending.clear();
        for (_, route) in self.routes.drain() {
            route.cancel.cancel();
            self.shared.shims.write().remove(&route.shim_addr);
        }
        self.by_channel.clear();
        self.permissions.clear();
        self.cred = None;
        self.sock = None;
        self.server_addr = None;
    }

    /// Resolves the server, binds a socket for it and makes the allocation:
    /// once without credentials, to be told the realm and a nonce, and again
    /// with them. Returns the relayed address.
    async fn connect(&mut self) -> Result<SocketAddr, Failure> {
        let addrs = tokio::time::timeout(
            Duration::from_secs(8),
            crate::address::resolve_all(&self.server.address),
        )
        .await
        .map_err(|_| Failure::Transient("the name did not resolve in time".to_string()))?
        .map_err(|e| {
            Failure::Transient(format!("cannot resolve {}: {}", self.server.address, e))
        })?;
        // The server's own family first when it has both, and the one this
        // host has a route for otherwise: a datagram to the other kind
        // simply fails to send.
        let mut last = Failure::Transient("no address".to_string());
        for addr in addrs {
            let bind = if addr.is_ipv6() {
                SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)
            } else {
                SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0)
            };
            let sock = match UdpSocket::bind(bind).await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    last = Failure::Transient(format!("cannot bind for {}: {}", addr, e));
                    continue;
                }
            };
            self.sock = Some(sock);
            self.server_addr = Some(addr);
            match self.allocate().await {
                Ok(relayed) => return Ok(relayed),
                Err(Failure::Fatal(e)) => return Err(Failure::Fatal(e)),
                Err(Failure::Transient(e)) => {
                    last = Failure::Transient(format!("{}: {}", addr, e));
                    self.cred = None;
                }
            }
        }
        Err(last)
    }

    fn socket(&self) -> Result<(&Arc<UdpSocket>, SocketAddr), Failure> {
        match (&self.sock, self.server_addr) {
            (Some(s), Some(a)) => Ok((s, a)),
            _ => Err(Failure::Transient("no socket".to_string())),
        }
    }

    /// Sends `bytes` and waits for the answer to `tid`, retransmitting.
    async fn exchange(&self, bytes: &[u8], tid: &[u8; 12]) -> Result<Vec<u8>, Failure> {
        let (sock, server) = self.socket()?;
        let mut buf = vec![0u8; 2048];
        for gap in RETRANSMIT {
            sock.send_to(bytes, server)
                .await
                .map_err(|e| Failure::Transient(format!("cannot send: {}", e)))?;
            let deadline = Instant::now() + gap;
            loop {
                tokio::select! {
                    _ = self.cancel.cancelled() => return Err(Failure::Transient("cancelled".to_string())),
                    _ = tokio::time::sleep_until(deadline) => break,
                    r = sock.recv_from(&mut buf) => {
                        let Ok((n, from)) = r else { continue };
                        if canonical(from) != canonical(server) {
                            continue;
                        }
                        if let Some(m) = wire::parse(&buf[..n]) {
                            if m.tid == *tid {
                                return Ok(buf[..n].to_vec());
                            }
                        }
                    }
                }
            }
        }
        Err(Failure::Transient("the server did not answer".to_string()))
    }

    async fn allocate(&mut self) -> Result<SocketAddr, Failure> {
        // At most: a first try that is told to authenticate, one that is
        // told the nonce has gone stale, and one that works.
        for _ in 0..4 {
            let tid = transaction_id();
            let mut b = Builder::new(ALLOCATE, Class::Request, &tid)
                .attr(ATTR_REQUESTED_TRANSPORT, &[TRANSPORT_UDP, 0, 0, 0]);
            if self.family == Family::V6 {
                b = b.attr(ATTR_REQUESTED_ADDRESS_FAMILY, &[FAMILY_IPV6, 0, 0, 0]);
            }
            let bytes = match &self.cred {
                Some(c) => b.finish_authenticated(c),
                None => b.finish(),
            };
            let reply = self.exchange(&bytes, &tid).await?;
            let m = wire::parse(&reply)
                .ok_or_else(|| Failure::Transient("an unreadable answer".to_string()))?;
            match m.class {
                Class::Success => {
                    if let Some(c) = &self.cred {
                        if !m.integrity_is_good(c.key()) {
                            return Err(Failure::Transient(
                                "an answer that does not carry our credentials' proof".to_string(),
                            ));
                        }
                    }
                    let relayed = m.xor_address(ATTR_XOR_RELAYED_ADDRESS).ok_or_else(|| {
                        Failure::Transient("no relayed address in the answer".to_string())
                    })?;
                    let lifetime = Duration::from_secs(
                        m.lifetime()
                            .unwrap_or(600)
                            .clamp(MIN_LIFETIME, MAX_LIFETIME) as u64,
                    );
                    self.lifetime = lifetime;
                    let now = Instant::now();
                    self.refresh_at = now + lifetime / 2;
                    self.keepalive_at = now + KEEPALIVE;
                    return Ok(relayed);
                }
                Class::Error => {
                    let (code, reason) = m.error().unwrap_or((0, String::new()));
                    match code {
                        401 | 438 => {
                            if code == 401 && self.cred.is_some() {
                                return Err(Failure::Fatal(format!(
                                    "the server did not accept the user name and password ({})",
                                    reason
                                )));
                            }
                            let (Some(realm), Some(nonce)) =
                                (m.text(ATTR_REALM), m.attr(ATTR_NONCE))
                            else {
                                return Err(Failure::Transient(
                                    "asked for credentials without a realm and nonce".to_string(),
                                ));
                            };
                            self.cred = Some(Credentials::new(
                                &self.server.username,
                                &realm,
                                &self.server.password,
                                nonce,
                            ));
                        }
                        _ => return Err(refusal(code, &reason)),
                    }
                }
                _ => return Err(Failure::Transient("an answer that is not one".to_string())),
            }
        }
        Err(Failure::Transient(
            "the server kept asking for credentials".to_string(),
        ))
    }

    /// The allocation as it goes on: datagrams both ways, and what keeps
    /// them possible up to date.
    async fn steady(&mut self) -> Exit {
        let Ok((sock, server)) = self.socket().map(|(s, a)| (s.clone(), a)) else {
            return Exit::Lost("no socket".to_string());
        };
        let mut buf = vec![0u8; 2048];
        loop {
            let deadline = self.next_deadline();
            tokio::select! {
                _ = self.cancel.cancelled() => return Exit::Cancelled,
                r = sock.recv_from(&mut buf) => {
                    let Ok((n, from)) = r else { continue };
                    if canonical(from) != canonical(server) {
                        continue;
                    }
                    if let Some(lost) = self.on_datagram(&buf[..n]).await {
                        return Exit::Lost(lost);
                    }
                }
                cmd = self.commands.recv() => {
                    match cmd {
                        Some(Command::Permit(ip)) => self.permit(ip),
                        Some(Command::Dial(peer, reply)) => {
                            let _ = reply.send(self.dial(peer));
                        }
                        None => return Exit::Cancelled,
                    }
                }
                out = self.outbound.1.recv() => {
                    if let Some((peer, data)) = out {
                        self.send_to_peer(&sock, server, peer, &data).await;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    if let Some(lost) = self.on_timer(&sock, server).await {
                        return Exit::Lost(lost);
                    }
                }
            }
        }
    }

    fn next_deadline(&self) -> Instant {
        let mut at = self.refresh_at.min(self.keepalive_at);
        for tx in self.pending.values() {
            at = at.min(tx.next);
        }
        for p in self.permissions.values() {
            at = at.min(p.due);
        }
        for r in self.routes.values() {
            at = at.min(r.channel_refresh_at).min(r.last_used + ROUTE_IDLE);
        }
        at
    }

    fn permit(&mut self, ip: IpAddr) {
        if Family::of(ip) != self.family {
            return;
        }
        self.permissions.entry(ip).or_insert_with(|| Permission {
            due: Instant::now(),
            until: None,
        });
    }

    fn permitted(&self, ip: IpAddr) -> bool {
        self.permissions
            .get(&ip)
            .and_then(|p| p.until)
            .is_some_and(|u| u > Instant::now())
    }

    /// A route for `peer`: the shim the engine talks to.
    fn route(&mut self, peer: SocketAddr) -> Option<&mut Route> {
        let now = Instant::now();
        if !self.routes.contains_key(&peer) {
            if self.routes.len() >= MAX_ROUTES {
                // Room is made by letting go of the peer that has been quiet
                // longest, if it has been quiet a while: a server only passes
                // what comes from addresses it was told to, but one of them
                // may send from many ports.
                let stale = self
                    .routes
                    .iter()
                    .filter(|(_, r)| now.saturating_duration_since(r.last_used) >= ROUTE_QUIET)
                    .min_by_key(|(_, r)| r.last_used)
                    .map(|(p, _)| *p);
                match stale {
                    Some(old) => self.drop_route(old),
                    None => {
                        if !self.told_full {
                            self.told_full = true;
                            tracing::warn!(
                                "TURN {}: already carrying {} peers; not adding {}",
                                self.server,
                                MAX_ROUTES,
                                peer
                            );
                        }
                        return None;
                    }
                }
            }
            let shim = match make_shim(self.engine) {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    tracing::warn!(
                        "TURN {}: cannot make a local address for {}: {}",
                        self.server,
                        peer,
                        e
                    );
                    return None;
                }
            };
            let shim_addr = canonical(shim.local_addr().ok()?);
            self.shared.shims.write().insert(shim_addr);
            let cancel = self.cancel.child_token();
            tokio::spawn(read_shim(
                shim.clone(),
                peer,
                self.outbound.0.clone(),
                cancel.clone(),
            ));
            self.routes.insert(
                peer,
                Route {
                    shim,
                    shim_addr,
                    channel: None,
                    binding: None,
                    channel_refresh_at: now + CHANNEL_REFRESH,
                    last_used: now,
                    cancel,
                },
            );
            tracing::debug!("TURN {}: {} is carried at {}", self.server, peer, shim_addr);
        }
        self.routes.get_mut(&peer)
    }

    fn dial(&mut self, peer: SocketAddr) -> Option<SocketAddr> {
        if Family::of(peer.ip()) != self.family {
            return None;
        }
        self.permit(peer.ip());
        Some(self.route(peer)?.shim_addr)
    }

    /// From the engine, for `peer`: through the server, in the cheapest
    /// framing that has been set up.
    async fn send_to_peer(
        &mut self,
        sock: &UdpSocket,
        server: SocketAddr,
        peer: SocketAddr,
        data: &[u8],
    ) {
        let Some(route) = self.routes.get_mut(&peer) else {
            return;
        };
        route.last_used = Instant::now();
        let channel = route.channel;
        let want_channel = channel.is_none() && route.binding.is_none();
        let bytes = match channel {
            Some(ch) => wire::channel_data(ch, data),
            None => Builder::new(SEND, Class::Indication, &transaction_id())
                .xor_address(ATTR_XOR_PEER_ADDRESS, peer)
                .attr(ATTR_DATA, data)
                .finish(),
        };
        let _ = sock.send_to(&bytes, server).await;
        // The server drops what it is asked to send to an address that has
        // no permission, so a peer that was never permitted is asked for now.
        if !self.permitted(peer.ip()) {
            self.permit(peer.ip());
        }
        if want_channel && self.cred.is_some() {
            self.bind_channel(sock, server, peer).await;
        }
    }

    async fn bind_channel(&mut self, sock: &UdpSocket, server: SocketAddr, peer: SocketAddr) {
        if self.next_channel > CHANNEL_MAX {
            return;
        }
        let ch = self.next_channel;
        self.next_channel += 1;
        if let Some(r) = self.routes.get_mut(&peer) {
            r.binding = Some(ch);
        }
        self.request(sock, server, TxKind::Bind(ch, peer)).await;
    }

    /// Builds and sends a request, and remembers it until it is answered.
    async fn request(&mut self, sock: &UdpSocket, server: SocketAddr, kind: TxKind) {
        let Some(bytes) = self.build(&kind) else {
            return;
        };
        let tid: [u8; 12] = bytes[8..20]
            .try_into()
            .expect("a header has a transaction id");
        let _ = sock.send_to(&bytes, server).await;
        self.pending.insert(
            tid,
            Tx {
                kind,
                bytes,
                sent: 1,
                next: Instant::now() + RETRANSMIT[0],
                renewed: 0,
            },
        );
    }

    fn build(&self, kind: &TxKind) -> Option<Vec<u8>> {
        let tid = transaction_id();
        let unauthenticated = |m| Builder::new(m, Class::Request, &tid);
        Some(match kind {
            TxKind::Binding => unauthenticated(BINDING).finish(),
            TxKind::Refresh => unauthenticated(REFRESH)
                .attr(
                    ATTR_LIFETIME,
                    &(self.lifetime.as_secs() as u32).to_be_bytes(),
                )
                .finish_authenticated(self.cred.as_ref()?),
            TxKind::Permission(ips) => {
                let mut b = unauthenticated(CREATE_PERMISSION);
                for ip in ips {
                    b = b.xor_address(ATTR_XOR_PEER_ADDRESS, SocketAddr::new(*ip, 0));
                }
                b.finish_authenticated(self.cred.as_ref()?)
            }
            TxKind::Bind(ch, peer) => unauthenticated(CHANNEL_BIND)
                .attr(ATTR_CHANNEL_NUMBER, &[(*ch >> 8) as u8, *ch as u8, 0, 0])
                .xor_address(ATTR_XOR_PEER_ADDRESS, *peer)
                .finish_authenticated(self.cred.as_ref()?),
        })
    }

    /// A datagram from the server. Returns why the allocation is lost, if
    /// this says so.
    async fn on_datagram(&mut self, pkt: &[u8]) -> Option<String> {
        if wire::looks_like_channel_data(pkt) {
            if let Some((ch, data)) = wire::parse_channel_data(pkt) {
                if let Some(&peer) = self.by_channel.get(&ch) {
                    self.deliver(peer, data).await;
                }
            }
            return None;
        }
        let m = wire::parse(pkt)?;
        match (m.method, m.class) {
            (DATA, Class::Indication) => {
                if let (Some(peer), Some(data)) =
                    (m.xor_address(ATTR_XOR_PEER_ADDRESS), m.attr(ATTR_DATA))
                {
                    self.deliver(canonical(peer), data).await;
                }
                None
            }
            (_, Class::Success) | (_, Class::Error) => self.on_response(&m).await,
            _ => None,
        }
    }

    /// From a peer, for the engine.
    async fn deliver(&mut self, peer: SocketAddr, data: &[u8]) {
        let Some(route) = self.route(peer) else {
            return;
        };
        route.last_used = Instant::now();
        let shim = route.shim.clone();
        // A datagram the engine's socket has no room for is lost, as the
        // network would lose it. (Not `try_send`: a socket made a moment ago
        // is not yet known to be writable, and would drop the first one.)
        let _ = shim.send(data).await;
    }

    async fn on_response(&mut self, m: &wire::Message<'_>) -> Option<String> {
        let mut tx = self.pending.remove(&m.tid)?;
        let (sock, server) = match self.socket() {
            Ok((s, a)) => (s.clone(), a),
            Err(_) => return None,
        };
        // Everything but a Binding answer is proven with our credentials.
        if !matches!(tx.kind, TxKind::Binding) {
            match &self.cred {
                Some(c) if m.class == Class::Success && !m.integrity_is_good(c.key()) => {
                    return None
                }
                _ => {}
            }
        }
        let now = Instant::now();
        match m.class {
            Class::Success => {
                match tx.kind {
                    TxKind::Refresh => {
                        let lifetime = Duration::from_secs(
                            m.lifetime()
                                .unwrap_or(600)
                                .clamp(MIN_LIFETIME, MAX_LIFETIME)
                                as u64,
                        );
                        self.lifetime = lifetime;
                        self.refresh_at = now + lifetime / 2;
                    }
                    TxKind::Permission(ips) => {
                        for ip in ips {
                            if let Some(p) = self.permissions.get_mut(&ip) {
                                p.until = Some(now + PERMISSION_LIFETIME);
                                p.due = now + PERMISSION_REFRESH;
                            }
                        }
                    }
                    TxKind::Bind(ch, peer) => {
                        if let Some(r) = self.routes.get_mut(&peer) {
                            r.channel = Some(ch);
                            r.binding = None;
                            r.channel_refresh_at = now + CHANNEL_REFRESH;
                            self.by_channel.insert(ch, peer);
                        }
                        // The binding made a permission of its own.
                        if let Some(p) = self.permissions.get_mut(&peer.ip()) {
                            p.until = Some(now + PERMISSION_LIFETIME);
                        }
                    }
                    TxKind::Binding => {}
                }
                None
            }
            Class::Error => {
                let (code, reason) = m.error().unwrap_or((0, String::new()));
                if (code == 438 || code == 401) && tx.renewed < 2 {
                    // The nonce has gone stale: take the new one and ask again.
                    if let (Some(realm), Some(nonce)) = (m.text(ATTR_REALM), m.attr(ATTR_NONCE)) {
                        self.cred = Some(Credentials::new(
                            &self.server.username,
                            &realm,
                            &self.server.password,
                            nonce,
                        ));
                    } else if let Some(nonce) = m.attr(ATTR_NONCE) {
                        if let Some(c) = &self.cred {
                            self.cred = Some(Credentials::new(
                                &c.username.clone(),
                                &c.realm.clone(),
                                &self.server.password,
                                nonce,
                            ));
                        }
                    }
                    if let Some(bytes) = self.build(&tx.kind) {
                        let tid: [u8; 12] = bytes[8..20]
                            .try_into()
                            .expect("a header has a transaction id");
                        let _ = sock.send_to(&bytes, server).await;
                        tx.bytes = bytes;
                        tx.sent = 1;
                        tx.next = now + RETRANSMIT[0];
                        tx.renewed += 1;
                        self.pending.insert(tid, tx);
                    }
                    return None;
                }
                match tx.kind {
                    // The server has no allocation for us any more (it was
                    // restarted, or its lifetime ran out): begin again.
                    TxKind::Refresh => Some(format!("{}: {}", code, reason)),
                    TxKind::Permission(ips) => {
                        tracing::debug!(
                            "TURN {}: no permission for {:?}: {} {}",
                            self.server,
                            ips,
                            code,
                            reason
                        );
                        for ip in ips {
                            if let Some(p) = self.permissions.get_mut(&ip) {
                                p.due = now + Duration::from_secs(30);
                            }
                        }
                        None
                    }
                    TxKind::Bind(_, peer) => {
                        tracing::debug!(
                            "TURN {}: no channel for {}: {} {}",
                            self.server,
                            peer,
                            code,
                            reason
                        );
                        if let Some(r) = self.routes.get_mut(&peer) {
                            // Send indications carry on; asking again would
                            // only be asking the same.
                            r.binding = Some(0);
                        }
                        None
                    }
                    TxKind::Binding => None,
                }
            }
            _ => None,
        }
    }

    async fn on_timer(&mut self, sock: &UdpSocket, server: SocketAddr) -> Option<String> {
        let now = Instant::now();
        // Requests that have gone unanswered: again, or given up on.
        let due: Vec<[u8; 12]> = self
            .pending
            .iter()
            .filter(|(_, t)| t.next <= now)
            .map(|(k, _)| *k)
            .collect();
        for tid in due {
            let Some(tx) = self.pending.get_mut(&tid) else {
                continue;
            };
            if tx.sent >= RETRANSMIT.len() {
                let tx = self.pending.remove(&tid)?;
                match tx.kind {
                    TxKind::Refresh => return Some("the server stopped answering".to_string()),
                    TxKind::Permission(ips) => {
                        for ip in ips {
                            if let Some(p) = self.permissions.get_mut(&ip) {
                                p.due = now + Duration::from_secs(10);
                            }
                        }
                    }
                    TxKind::Bind(_, peer) => {
                        if let Some(r) = self.routes.get_mut(&peer) {
                            r.binding = None;
                            r.channel_refresh_at = now + Duration::from_secs(30);
                        }
                    }
                    TxKind::Binding => {}
                }
                continue;
            }
            let _ = sock.send_to(&tx.bytes, server).await;
            tx.next = now + RETRANSMIT[tx.sent];
            tx.sent += 1;
        }
        if now >= self.refresh_at {
            self.refresh_at = now + self.lifetime / 2;
            if !self
                .pending
                .values()
                .any(|t| matches!(t.kind, TxKind::Refresh))
            {
                self.request(sock, server, TxKind::Refresh).await;
            }
        }
        if now >= self.keepalive_at {
            self.keepalive_at = now + KEEPALIVE;
            self.request(sock, server, TxKind::Binding).await;
        }
        // Permissions to ask for, a few at a time.
        let asking: HashSet<IpAddr> = self
            .pending
            .values()
            .filter_map(|t| match &t.kind {
                TxKind::Permission(ips) => Some(ips.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        let mut wanted: Vec<IpAddr> = self
            .permissions
            .iter()
            .filter(|(ip, p)| p.due <= now && !asking.contains(ip))
            .map(|(ip, _)| *ip)
            .collect();
        wanted.sort();
        for chunk in wanted.chunks(PERMISSIONS_PER_REQUEST) {
            for ip in chunk {
                // Until the answer says otherwise, look again in a moment.
                if let Some(p) = self.permissions.get_mut(ip) {
                    p.due = now + Duration::from_secs(10);
                }
            }
            self.request(sock, server, TxKind::Permission(chunk.to_vec()))
                .await;
        }
        // Channels to renew, and peers to let go of.
        let renew: Vec<(SocketAddr, u16)> = self
            .routes
            .iter()
            .filter(|(_, r)| r.channel_refresh_at <= now)
            .filter_map(|(p, r)| r.channel.map(|c| (*p, c)))
            .collect();
        for (peer, ch) in renew {
            if let Some(r) = self.routes.get_mut(&peer) {
                r.channel_refresh_at = now + CHANNEL_REFRESH;
            }
            self.request(sock, server, TxKind::Bind(ch, peer)).await;
        }
        let idle: Vec<SocketAddr> = self
            .routes
            .iter()
            .filter(|(_, r)| now.saturating_duration_since(r.last_used) >= ROUTE_IDLE)
            .map(|(p, _)| *p)
            .collect();
        for peer in idle {
            self.drop_route(peer);
        }
        None
    }

    fn drop_route(&mut self, peer: SocketAddr) {
        if let Some(r) = self.routes.remove(&peer) {
            r.cancel.cancel();
            self.shared.shims.write().remove(&r.shim_addr);
            if let Some(ch) = r.channel {
                self.by_channel.remove(&ch);
            }
            tracing::debug!("TURN {}: {} let go", self.server, peer);
        }
    }

    /// Gives the allocation back, as far as one datagram can: without it
    /// the server keeps the relayed address for the rest of its lifetime.
    async fn release(&mut self) {
        let (Ok((sock, server)), Some(cred)) = (
            self.socket().map(|(s, a)| (s.clone(), a)),
            self.cred.clone(),
        ) else {
            self.forget_allocation();
            return;
        };
        let bye = Builder::new(REFRESH, Class::Request, &transaction_id())
            .attr(ATTR_LIFETIME, &0u32.to_be_bytes())
            .finish_authenticated(&cred);
        let _ = sock.send_to(&bye, server).await;
        self.forget_allocation();
    }
}

/// What a refusal to allocate means, in a few words.
fn refusal(code: u16, reason: &str) -> Failure {
    let why = match code {
        300 => "the server sends us elsewhere (an alternate server), which is not followed",
        400 => "the server did not understand the request",
        403 => "the server forbids it",
        440 => "the server has no address of that family to give",
        441 => "the server does not accept those credentials",
        442 => "the server does not relay UDP",
        486 => "the server has given us all the allocations it allows",
        508 => "the server has no capacity left",
        _ => "the server refused",
    };
    let text = if reason.is_empty() {
        format!("{} ({})", why, code)
    } else {
        format!("{} ({} {})", why, code, reason)
    };
    match code {
        403 | 441 | 442 | 440 => Failure::Fatal(text),
        _ => Failure::Transient(text),
    }
}

/// A loopback socket for one peer, connected to the engine's.
fn make_shim(engine: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind = SocketAddr::new(engine.ip(), 0);
    let std_sock = std::net::UdpSocket::bind(bind)?;
    std_sock.connect(engine)?;
    std_sock.set_nonblocking(true)?;
    UdpSocket::from_std(std_sock)
}

/// Hands what the engine sends to a peer's shim to the allocation, for the
/// server.
async fn read_shim(
    shim: Arc<UdpSocket>,
    peer: SocketAddr,
    out: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    cancel: CancellationToken,
) {
    // One byte more than can be sent, to tell "as large as allowed" from
    // "larger".
    let mut buf = vec![0u8; MAX_DATAGRAM + 1];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            r = shim.recv(&mut buf) => match r {
                Ok(n) if n <= MAX_DATAGRAM => {
                    let _ = out.try_send((peer, buf[..n].to_vec()));
                }
                // Too large for the way through: as good as lost, and the
                // engine, which probes for what fits, learns from that.
                Ok(_) => {}
                // An ICMP error from the engine's port (it has not bound it
                // yet, or has gone) is reported on the next call; nothing to
                // do about it.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                Err(_) => return,
            }
        }
    }
}
