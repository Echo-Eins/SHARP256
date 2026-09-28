//! The relay itself: a small UDP service that introduces two peers to each
//! other and, if that is not enough, copies datagrams between them.
//!
//! It is deliberately dull. It holds no keys belonging to anyone, reads
//! nothing it forwards, and decides nothing about who may talk to whom — a
//! transfer is admitted or refused by the receiver, on the strength of the
//! sender's identity, exactly as it would be over a direct path. The relay's
//! whole job is to be an address both ends can reach.
//!
//! What it does have to defend is itself, and the strangers it could be
//! aimed at:
//!
//! * a registration from a forged source address would point the relay's
//!   traffic at somebody who never asked for it, so a registration is only
//!   accepted once it echoes a token the relay derived from the address it
//!   saw. The token is a keyed hash of that address, so no table of pending
//!   registrations exists to fill up;
//! * registrations, allocations and the rate at which either is asked for
//!   are all capped;
//! * an allocated port carries traffic only between the two addresses that
//!   presented its tickets, and forgets it when it goes quiet.

use super::{is_control, Message, Refusal, TOKEN_LEN};
use crate::crypto::{Identity, SharpId};
use rand::RngCore;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// How long a registration lives without a keepalive.
pub const DEFAULT_LEASE: Duration = Duration::from_secs(120);
/// How long an allocation survives with nothing flowing through it.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(60);
/// How often the token secret is replaced. Two are kept, so a token is good
/// for between one and two of these.
const TOKEN_LIFETIME: Duration = Duration::from_secs(120);
/// Datagram buffer: enough for a jumbo frame.
const BUF_LEN: usize = 9216;

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    /// The relay's own long-term identity. Receivers are given its public
    /// half in the relay's address and prove ownership of theirs against
    /// it; it authenticates nothing else, and the relay is trusted with
    /// nothing else.
    pub identity: Identity,
    /// Identities that may be registered at once.
    pub max_registrations: usize,
    /// Pairs that may be carried at once.
    pub max_allocations: usize,
    /// Requests per second accepted from one address, and the burst.
    pub rate: f64,
    pub burst: f64,
    pub lease: Duration,
    pub idle: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind", &self.bind)
            .field("id", &self.identity.id())
            .field("max_registrations", &self.max_registrations)
            .field("max_allocations", &self.max_allocations)
            .field("rate", &self.rate)
            .field("lease", &self.lease)
            .field("idle", &self.idle)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:5560".parse().expect("valid address"),
            identity: Identity::generate(),
            max_registrations: 4096,
            max_allocations: 256,
            rate: 10.0,
            burst: 20.0,
            lease: DEFAULT_LEASE,
            idle: DEFAULT_IDLE,
        }
    }
}

/// Tokens proving a peer receives at the address it claims.
///
/// A keyed hash of the address rather than a stored value, so a flood of
/// forged registrations has nothing to fill up.
struct TokenJar {
    secrets: [[u8; 32]; 2],
    born: Instant,
}

impl TokenJar {
    fn new() -> Self {
        Self {
            secrets: [random_key(), random_key()],
            born: Instant::now(),
        }
    }

    fn rotate(&mut self, now: Instant) {
        if now.saturating_duration_since(self.born) >= TOKEN_LIFETIME {
            self.secrets.swap(0, 1);
            self.secrets[0] = random_key();
            self.born = now;
        }
    }

    fn make(secret: &[u8; 32], addr: SocketAddr) -> [u8; TOKEN_LEN] {
        let mut data = Vec::with_capacity(18);
        match addr.ip() {
            std::net::IpAddr::V4(v4) => data.extend_from_slice(&v4.to_ipv6_mapped().octets()),
            std::net::IpAddr::V6(v6) => data.extend_from_slice(&v6.octets()),
        }
        data.extend_from_slice(&addr.port().to_be_bytes());
        let mut out = [0u8; TOKEN_LEN];
        out.copy_from_slice(&blake3::keyed_hash(secret, &data).as_bytes()[..TOKEN_LEN]);
        out
    }

    fn issue(&mut self, addr: SocketAddr, now: Instant) -> [u8; TOKEN_LEN] {
        self.rotate(now);
        Self::make(&self.secrets[0], addr)
    }

    fn accepts(&mut self, token: &[u8; TOKEN_LEN], addr: SocketAddr, now: Instant) -> bool {
        self.rotate(now);
        self.secrets
            .iter()
            .any(|s| constant_time_eq(&Self::make(s, addr), token))
    }
}

fn constant_time_eq(a: &[u8; TOKEN_LEN], b: &[u8; TOKEN_LEN]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

fn random_token() -> [u8; TOKEN_LEN] {
    let mut t = [0u8; TOKEN_LEN];
    rand::rngs::OsRng.fill_bytes(&mut t);
    t
}

/// Addresses the rate limiter will track at once. Without a cap the table
/// grows by one entry for every packet from a new source, and pruning only
/// runs every few seconds: a spray of forged source addresses would fill
/// memory in between, and then stall the relay while it walked what it had
/// built.
const MAX_TRACKED_ADDRESSES: usize = 65_536;

/// A token bucket per source address.
struct RateLimiter {
    per_ip: HashMap<std::net::IpAddr, (f64, Instant)>,
    rate: f64,
    burst: f64,
}

impl RateLimiter {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            per_ip: HashMap::new(),
            rate,
            burst: burst.max(1.0),
        }
    }

    /// Takes a token for `from`; false when it has had too many.
    fn allow(&mut self, from: SocketAddr, now: Instant) -> bool {
        let (rate, burst) = (self.rate, self.burst);
        if self.per_ip.len() >= MAX_TRACKED_ADDRESSES && !self.per_ip.contains_key(&from.ip()) {
            // Full. Make room from entries whose budget has refilled, and if
            // there is none, refuse rather than grow.
            self.prune(now);
            if self.per_ip.len() >= MAX_TRACKED_ADDRESSES {
                return false;
            }
        }
        let (tokens, at) = self.per_ip.entry(from.ip()).or_insert((burst, now));
        *tokens = (*tokens + now.saturating_duration_since(*at).as_secs_f64() * rate).min(burst);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Forgets addresses whose budget is full again, so the table cannot
    /// grow without bound.
    fn prune(&mut self, now: Instant) {
        let (rate, burst) = (self.rate, self.burst);
        self.per_ip.retain(|_, (tokens, at)| {
            *tokens + now.saturating_duration_since(*at).as_secs_f64() * rate < burst
        });
    }
}

struct Registration {
    addr: SocketAddr,
    expires: Instant,
    /// The owner asked not to have its address handed out. Senders are then
    /// told nothing about where it is and everything goes through the relay,
    /// which costs bandwidth and gives up the direct path — and is the only
    /// arrangement in which the relay actually hides anyone.
    private: bool,
}

impl Registration {
    fn fresh(&self, now: Instant) -> bool {
        self.expires > now
    }
}

/// A port carrying one pair, and what it knows about the two sides.
struct Allocation {
    port: u16,
    task: tokio::task::JoinHandle<()>,
    /// Who asked for it. A global limit alone would be
    /// first-come-first-served, so one client could take every port and
    /// shut everybody else out — the same mistake as an unshared session
    /// limit, and just as easy to make.
    requested_by: std::net::IpAddr,
    /// The pair it was set aside for, and their tickets. Kept so that a
    /// sender whose answer went missing and asked again is handed the same
    /// port back instead of burning another one.
    sender: SocketAddr,
    receiver: SocketAddr,
    /// Whether the two were told about each other; a port is only handed
    /// back on the same terms it was made.
    disclose: bool,
    sender_ticket: [u8; TOKEN_LEN],
    receiver_ticket: [u8; TOKEN_LEN],
}

/// What one side is told about the other: the address, or nothing at all
/// when the receiver asked to stay hidden.
fn shown(addr: SocketAddr, disclose: bool) -> SocketAddr {
    if disclose {
        return addr;
    }
    let ip: std::net::IpAddr = if addr.is_ipv6() {
        std::net::Ipv6Addr::UNSPECIFIED.into()
    } else {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    };
    SocketAddr::new(ip, 0)
}

/// A running relay.
pub struct Relay {
    socket: Arc<UdpSocket>,
    identity: Identity,
    cfg: Config,
    cancel: CancellationToken,
    tokens: TokenJar,
    registrations: HashMap<SharpId, Registration>,
    allocations: Vec<Allocation>,
    /// Ports we have set aside. A carried pair refuses to treat one of them
    /// as a peer, which is what stops two allocations being pointed at each
    /// other and bouncing a datagram between them for ever.
    ports: Arc<parking_lot::Mutex<std::collections::HashSet<u16>>>,
    limiter: RateLimiter,
    last_prune: Instant,
}

impl Relay {
    pub async fn bind(cfg: Config, cancel: CancellationToken) -> io::Result<Self> {
        let socket = UdpSocket::bind(cfg.bind).await?;
        let now = Instant::now();
        let (cfg_rate, cfg_burst) = (cfg.rate, cfg.burst);
        Ok(Self {
            socket: Arc::new(socket),
            identity: cfg.identity.clone(),
            cfg,
            cancel,
            tokens: TokenJar::new(),
            registrations: HashMap::new(),
            allocations: Vec::new(),
            ports: Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new())),
            limiter: RateLimiter::new(cfg_rate, cfg_burst),
            last_prune: now,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// What receivers write to register here: `ID@host:port`.
    pub fn id(&self) -> SharpId {
        self.identity.id()
    }

    /// Serves until cancelled.
    pub async fn run(mut self) -> io::Result<()> {
        tracing::info!("relay listening on {}", self.socket.local_addr()?);
        let socket = self.socket.clone();
        let cancel = self.cancel.clone();
        let mut buf = vec![0u8; BUF_LEN];
        let mut errors = 0u32;
        loop {
            tokio::select! {
                r = socket.recv_from(&mut buf) => {
                    let (n, from) = match r {
                        Ok(v) => {
                            errors = 0;
                            v
                        }
                        // One is not worth stopping for; a stream of them
                        // would otherwise spin this loop at full speed,
                        // which is the whole relay's only thread.
                        Err(e) => {
                            errors += 1;
                            if errors >= MAX_ERRORS {
                                tracing::error!("relay: receive keeps failing: {}", e);
                                return Err(e);
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                    };
                    let now = Instant::now();
                    self.prune(now);
                    // Anything that is not a control message on the control
                    // port is not ours; the relay never answers it, so it
                    // cannot be used to probe for one.
                    let Some(msg) = Message::decode(&buf[..n]) else { continue };
                    if !self.limiter.allow(from, now) {
                        continue;
                    }
                    self.on_message(msg, from, &buf[..n], now).await;
                }
                _ = cancel.cancelled() => {
                    for a in self.allocations.drain(..) {
                        a.task.abort();
                    }
                    tracing::info!("relay shutting down");
                    return Ok(());
                }
            }
        }
    }

    async fn reply(&self, to: SocketAddr, msg: Message) {
        let _ = self.socket.send_to(&msg.encode(), to).await;
    }

    /// Whether a message carries a proof that only the identity's owner
    /// could have made. Both sides work the key out from their long-term
    /// keys alone, so there is nothing to exchange and nothing to store.
    fn owns(&self, id: &SharpId, raw: &[u8]) -> bool {
        let Some(key) = super::auth_key(&self.identity, id, id, &self.identity.id()) else {
            return false;
        };
        super::proof_is_good(&key, raw)
    }

    async fn on_message(&mut self, msg: Message, from: SocketAddr, raw: &[u8], now: Instant) {
        match msg {
            Message::Register {
                id,
                token,
                flags,
                proof: _,
            } => {
                // An unproven address gets a token and nothing else: a
                // registration from a forged source would otherwise point
                // this relay's traffic at somebody who never asked for it.
                if !self.tokens.accepts(&token, from, now) {
                    let token = self.tokens.issue(from, now);
                    self.reply(from, Message::Challenge { token }).await;
                    return;
                }
                // And an unproven *identity* gets nothing at all. Without
                // this, anyone who knew a receiver's published ID could
                // register it here and have senders put through to them
                // instead — the handshake would fail, but the transfer
                // would fail with it.
                if !self.owns(&id, raw) {
                    tracing::debug!("relay: {} cannot prove it owns {}", from, id.short());
                    self.reply(
                        from,
                        Message::Error {
                            code: Refusal::BadToken,
                        },
                    )
                    .await;
                    return;
                }
                let known = self
                    .registrations
                    .get(&id)
                    .is_some_and(|r| r.addr == from && r.fresh(now));
                if !known {
                    // The same share ports get, and for the same reason. An
                    // identity costs nothing to invent — the id is read
                    // straight off the wire — so without this one address
                    // could register thousands and leave room for nobody.
                    let share = (self.cfg.max_registrations / 8).max(4);
                    let mine = self
                        .registrations
                        .values()
                        .filter(|r| r.addr.ip() == from.ip() && r.fresh(now))
                        .count();
                    if self.registrations.len() >= self.cfg.max_registrations || mine >= share {
                        if mine >= share {
                            tracing::info!(
                                "relay: {} already holds {} of {} registrations",
                                from.ip(),
                                mine,
                                self.cfg.max_registrations
                            );
                        }
                        self.reply(
                            from,
                            Message::Error {
                                code: Refusal::Busy,
                            },
                        )
                        .await;
                        return;
                    }
                }
                self.registrations.insert(
                    id,
                    Registration {
                        addr: from,
                        expires: now + self.cfg.lease,
                        private: flags & super::REGISTER_PRIVATE != 0,
                    },
                );
                if !known {
                    tracing::info!("relay: {} registered at {}", id.short(), from);
                }
                self.reply(
                    from,
                    Message::Registered {
                        lease: self.cfg.lease.as_secs().min(u32::MAX as u64) as u32,
                        observed: from,
                    },
                )
                .await;
            }
            Message::Connect { target, token } => {
                if !self.tokens.accepts(&token, from, now) {
                    let token = self.tokens.issue(from, now);
                    self.reply(from, Message::Challenge { token }).await;
                    return;
                }
                let Some(reg) = self.registrations.get(&target) else {
                    self.reply(
                        from,
                        Message::Error {
                            code: Refusal::Unknown,
                        },
                    )
                    .await;
                    return;
                };
                let receiver = reg.addr;
                // An owner that asked to stay hidden is not described to
                // the caller; there is then no direct path to try and the
                // pair meets at the relay's port.
                let disclose = !reg.private;
                // The same pair asking again means our answer went missing,
                // not that they want a second port. That has to be settled
                // before the limits: a sender that already holds its whole
                // share would otherwise be refused the very port it has.
                let granted = match self.existing(from, receiver, disclose) {
                    Some(granted) => Some(granted),
                    None => {
                        let share = (self.cfg.max_allocations / 4).max(2);
                        let mine = self
                            .allocations
                            .iter()
                            .filter(|a| a.requested_by == from.ip() && !a.task.is_finished())
                            .count();
                        let live = self
                            .allocations
                            .iter()
                            .filter(|a| !a.task.is_finished())
                            .count();
                        if live >= self.cfg.max_allocations || mine >= share {
                            if mine >= share {
                                tracing::info!(
                                    "relay: {} already holds {} of {} ports",
                                    from.ip(),
                                    mine,
                                    self.cfg.max_allocations
                                );
                            }
                            self.reply(
                                from,
                                Message::Error {
                                    code: Refusal::Busy,
                                },
                            )
                            .await;
                            return;
                        }
                        self.allocate(from, receiver, disclose).await
                    }
                };
                match granted {
                    Some((port, sender_ticket, receiver_ticket)) => {
                        // Each side is told where the other appears to be,
                        // so they can try a direct path first and leave the
                        // relay carrying nothing.
                        self.reply(
                            from,
                            Message::Allocated {
                                port,
                                peer: shown(receiver, disclose),
                                ticket: sender_ticket,
                            },
                        )
                        .await;
                        self.reply(
                            receiver,
                            Message::Incoming {
                                port,
                                peer: shown(from, disclose),
                                ticket: receiver_ticket,
                            },
                        )
                        .await;
                        tracing::info!(
                            "relay: port {} carries {} <-> {} ({})",
                            port,
                            from,
                            receiver,
                            target.short()
                        );
                    }
                    None => {
                        self.reply(
                            from,
                            Message::Error {
                                code: Refusal::Busy,
                            },
                        )
                        .await
                    }
                }
            }
            Message::Bye { id, token, .. } => {
                // Only from the address that holds the registration, with a
                // token proving that address and a proof of the identity:
                // otherwise anyone who knew an identity could evict its
                // owner.
                if !self.tokens.accepts(&token, from, now) || !self.owns(&id, raw) {
                    return;
                }
                if self.registrations.get(&id).is_some_and(|r| r.addr == from) {
                    self.registrations.remove(&id);
                    tracing::info!("relay: {} has gone", id.short());
                }
            }
            // Only a relay sends these; an Open belongs to an allocated
            // port, and a Punch goes between peers and never here.
            Message::Challenge { .. }
            | Message::Registered { .. }
            | Message::Allocated { .. }
            | Message::Incoming { .. }
            | Message::Error { .. }
            | Message::Open { .. }
            | Message::Punch => {}
        }
    }

    /// The port this pair already holds, if it still does. Only one made
    /// under the same terms counts: a receiver that has since asked to stay
    /// hidden gets a port that repeats nothing about where it is.
    fn existing(
        &self,
        sender: SocketAddr,
        receiver: SocketAddr,
        disclose: bool,
    ) -> Option<(u16, [u8; TOKEN_LEN], [u8; TOKEN_LEN])> {
        self.allocations
            .iter()
            .find(|a| {
                a.sender == sender
                    && a.receiver == receiver
                    && a.disclose == disclose
                    && !a.task.is_finished()
            })
            .map(|a| (a.port, a.sender_ticket, a.receiver_ticket))
    }

    /// Sets a port aside for one pair and starts carrying it.
    async fn allocate(
        &mut self,
        sender: SocketAddr,
        receiver: SocketAddr,
        disclose: bool,
    ) -> Option<(u16, [u8; TOKEN_LEN], [u8; TOKEN_LEN])> {
        let bind = SocketAddr::new(self.cfg.bind.ip(), 0);
        let sock = Arc::new(UdpSocket::bind(bind).await.ok()?);
        let port = sock.local_addr().ok()?.port();
        let sender_ticket = random_token();
        let receiver_ticket = random_token();
        self.ports.lock().insert(port);
        let task = tokio::spawn(carry(Carried {
            sock,
            control: self.socket.clone(),
            ports: self.ports.clone(),
            port,
            sender_ticket,
            receiver_ticket,
            sender_shown: shown(sender, disclose),
            receiver_control: receiver,
            idle: self.cfg.idle,
            cancel: self.cancel.clone(),
        }));
        self.allocations.push(Allocation {
            port,
            task,
            requested_by: sender.ip(),
            sender,
            receiver,
            disclose,
            sender_ticket,
            receiver_ticket,
        });
        Some((port, sender_ticket, receiver_ticket))
    }

    fn prune(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_prune) < Duration::from_secs(5) {
            return;
        }
        self.last_prune = now;
        self.registrations.retain(|_, r| r.expires > now);
        let ports = self.ports.clone();
        self.allocations.retain(|a| {
            if a.task.is_finished() {
                tracing::debug!("relay: port {} released", a.port);
                ports.lock().remove(&a.port);
                return false;
            }
            true
        });
        self.limiter.prune(now);
    }
}

/// Everything one carried pair needs.
struct Carried {
    sock: Arc<UdpSocket>,
    /// The control socket, for repeating an introduction that went missing.
    control: Arc<UdpSocket>,
    /// Every port this relay has set aside, so a pair can refuse to treat
    /// another one as a peer.
    ports: Arc<parking_lot::Mutex<std::collections::HashSet<u16>>>,
    port: u16,
    sender_ticket: [u8; TOKEN_LEN],
    receiver_ticket: [u8; TOKEN_LEN],
    /// What the receiver is told about the sender when the introduction is
    /// repeated: exactly what the first one said, so a private registration
    /// learns no more the second time than the first.
    sender_shown: SocketAddr,
    /// Where the control exchange reached the receiver. Used to repeat the
    /// introduction, and never as a peer address: what counts here is
    /// whichever address presents the ticket.
    receiver_control: SocketAddr,
    idle: Duration,
    cancel: CancellationToken,
}

/// How often an unanswered introduction is repeated, and how many times.
/// The relay sends `Incoming` once when a sender arrives; if that datagram
/// is lost, the receiver never learns to bind its side and the transfer
/// fails with nothing anywhere to show why.
const INTRODUCE_EVERY: Duration = Duration::from_millis(400);
const INTRODUCE_TIMES: u32 = 8;
/// Consecutive receive errors before a pair gives up. One is not worth
/// tearing an allocation down for: Windows reports WSAECONNRESET on an
/// unconnected UDP socket when an ICMP port-unreachable comes back, so a
/// single peer going quiet would otherwise kill the pair.
const MAX_ERRORS: u32 = 16;

/// Copies datagrams between the two sides of one allocation.
///
/// Each side binds itself by presenting its ticket, which is also what opens
/// the way back through its NAT. Until a side has done that, nothing is sent
/// to it; afterwards, only datagrams from the two bound addresses are
/// carried, so knowing the port is not enough to join in.
async fn carry(c: Carried) {
    let Carried {
        sock,
        control,
        ports,
        port,
        sender_ticket,
        receiver_ticket,
        sender_shown,
        receiver_control,
        idle,
        cancel,
    } = c;
    let mut a: Option<SocketAddr> = None;
    let mut b: Option<SocketAddr> = None;
    let mut buf = vec![0u8; BUF_LEN];
    let mut last = Instant::now();
    let mut errors = 0u32;
    let mut introduced = 1u32;
    let mut next_introduce = Instant::now() + INTRODUCE_EVERY;
    let local = sock.local_addr().ok();

    // An address is only worth carrying to if it is one we would send to at
    // all, and never one of our own ports: two allocations pointed at each
    // other would bounce a single datagram between them for ever, each hop
    // refreshing the idle timer that should have reclaimed them.
    let acceptable = |addr: SocketAddr| -> bool {
        let Some(local) = local else { return false };
        if addr.ip() == local.ip() && ports.lock().contains(&addr.port()) {
            return false;
        }
        crate::nat::stun::is_usable_server_address(addr, local)
    };

    loop {
        let now = Instant::now();
        let quiet = idle.saturating_sub(now.saturating_duration_since(last));
        let wake = if b.is_none() && introduced < INTRODUCE_TIMES {
            quiet.min(next_introduce.saturating_duration_since(now))
        } else {
            quiet
        };
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let (n, from) = match r {
                    Ok(v) => {
                        errors = 0;
                        v
                    }
                    Err(_) => {
                        errors += 1;
                        if errors >= MAX_ERRORS {
                            return;
                        }
                        continue;
                    }
                };
                let pkt = &buf[..n];
                if is_control(pkt) {
                    // A side saying which one it is. The address it comes
                    // from is the one to use, whatever the control port saw.
                    if let Some(Message::Open { ticket }) = Message::decode(pkt) {
                        let is_a = constant_time_eq(&ticket, &sender_ticket);
                        let is_b = constant_time_eq(&ticket, &receiver_ticket);
                        if !is_a && !is_b {
                            continue;
                        }
                        if !acceptable(from) {
                            tracing::debug!("relay: port {} will not carry to {}", port, from);
                            continue;
                        }
                        // The two sides have to be two. One address holding
                        // both tickets is a pair talking to itself, and a
                        // datagram put into it would never stop going round.
                        if (is_a && b == Some(from)) || (is_b && a == Some(from)) {
                            tracing::debug!("relay: port {} refuses {} as both sides", port, from);
                            continue;
                        }
                        if is_a {
                            a = Some(from);
                        } else {
                            b = Some(from);
                        }
                        last = Instant::now();
                    }
                    continue;
                }
                // Traffic, carried only between the two bound addresses.
                let to = if Some(from) == a {
                    b
                } else if Some(from) == b {
                    a
                } else {
                    continue;
                };
                if let Some(to) = to {
                    last = Instant::now();
                    let _ = sock.send_to(pkt, to).await;
                }
            }
            _ = tokio::time::sleep(wake) => {
                let now = Instant::now();
                if now.saturating_duration_since(last) >= idle {
                    tracing::debug!("relay: port {} idle; releasing", port);
                    return;
                }
                // The receiver has not shown up. Its introduction may simply
                // have been lost, and nothing else would ever repeat it.
                if b.is_none() && introduced < INTRODUCE_TIMES && now >= next_introduce {
                    introduced += 1;
                    next_introduce = now + INTRODUCE_EVERY;
                    let msg = Message::Incoming {
                        port,
                        peer: sender_shown,
                        ticket: receiver_ticket,
                    };
                    let _ = control.send_to(&msg.encode(), receiver_control).await;
                }
            }
            _ = cancel.cancelled() => return,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_proves_one_address_and_no_other() {
        let mut jar = TokenJar::new();
        let now = Instant::now();
        let a: SocketAddr = "198.51.100.5:4000".parse().unwrap();
        let b: SocketAddr = "198.51.100.5:4001".parse().unwrap();
        let c: SocketAddr = "198.51.100.6:4000".parse().unwrap();
        let t = jar.issue(a, now);
        assert!(jar.accepts(&t, a, now));
        // A different port, and a different host, are different addresses.
        assert!(!jar.accepts(&t, b, now));
        assert!(!jar.accepts(&t, c, now));
        assert!(!jar.accepts(&[0; TOKEN_LEN], a, now));

        // Still good across one rotation, gone after two.
        let later = now + TOKEN_LIFETIME;
        assert!(jar.accepts(&t, a, later));
        assert!(!jar.accepts(&t, a, later + TOKEN_LIFETIME + TOKEN_LIFETIME));
    }

    #[test]
    fn the_rate_limiter_lets_a_burst_through_and_then_holds() {
        let mut l = RateLimiter::new(1.0, 3.0);
        let now = Instant::now();
        let peer: SocketAddr = "203.0.113.1:1000".parse().unwrap();
        assert!(l.allow(peer, now) && l.allow(peer, now) && l.allow(peer, now));
        assert!(!l.allow(peer, now), "the burst should be spent");
        assert!(l.allow(peer, now + Duration::from_millis(1100)));
        // Another address has its own budget.
        let other: SocketAddr = "203.0.113.2:1000".parse().unwrap();
        assert!(l.allow(other, now));
        // An address that has stopped asking is forgotten, so the table
        // cannot be grown without bound by walking through addresses.
        l.prune(now + Duration::from_secs(10));
        assert!(l.per_ip.is_empty());
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    use crate::crypto::Identity;
    use crate::relay::Message;

    /// Sends `msg` to the relay and returns the first relay message that
    /// comes back, or `None` if nothing does.
    async fn ask(sock: &UdpSocket, relay: SocketAddr, msg: Message) -> Option<Message> {
        sock.send_to(&msg.encode(), relay).await.ok()?;
        recv_message(sock, Duration::from_secs(2)).await
    }

    async fn recv_message(sock: &UdpSocket, within: Duration) -> Option<Message> {
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(within, sock.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        Message::decode(&buf[..n])
    }

    /// Registers or connects, answering the relay's challenge.
    async fn with_token(
        sock: &UdpSocket,
        relay: SocketAddr,
        make: impl Fn([u8; TOKEN_LEN]) -> Message,
    ) -> Option<Message> {
        match ask(sock, relay, make([0; TOKEN_LEN])).await? {
            Message::Challenge { token } => ask(sock, relay, make(token)).await,
            other => Some(other),
        }
    }

    async fn start_relay() -> (SocketAddr, SharpId, CancellationToken) {
        start_relay_with(Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            idle: Duration::from_secs(5),
            ..Config::default()
        })
        .await
    }

    async fn start_relay_with(cfg: Config) -> (SocketAddr, SharpId, CancellationToken) {
        let cancel = CancellationToken::new();
        let relay = Relay::bind(cfg, cancel.clone()).await.expect("binds");
        let addr = relay.local_addr().unwrap();
        let id = relay.id();
        tokio::spawn(async move {
            let _ = relay.run().await;
        });
        (addr, id, cancel)
    }

    /// Encodes a message and fills in its proof.
    fn signed(key: &[u8; 32], msg: Message) -> Vec<u8> {
        let mut bytes = msg.encode();
        let split = bytes.len() - crate::relay::PROOF_LEN;
        let proof = crate::relay::proof_for(key, &bytes[..split]);
        bytes[split..].copy_from_slice(&proof);
        bytes
    }

    /// Asks for a fresh address token, ignoring anything else already
    /// queued on the socket — an introduction, say, which arrives unbidden
    /// and would otherwise be mistaken for the answer.
    async fn token_for(sock: &UdpSocket, relay: SocketAddr, id: SharpId) -> [u8; TOKEN_LEN] {
        let ask = Message::Register {
            id,
            token: [0; TOKEN_LEN],
            flags: 0,
            proof: [0; crate::relay::PROOF_LEN],
        };
        sock.send_to(&ask.encode(), relay).await.expect("send");
        for _ in 0..8 {
            match recv_message(sock, Duration::from_secs(2)).await {
                Some(Message::Challenge { token }) => return token,
                Some(_) => continue,
                None => break,
            }
        }
        panic!("the relay never issued a token");
    }

    /// Registers, answering the relay's challenge and proving ownership.
    async fn register(
        sock: &UdpSocket,
        relay: SocketAddr,
        relay_id: &SharpId,
        identity: &Identity,
        flags: u8,
    ) -> Option<Message> {
        let id = identity.id();
        let key = crate::relay::auth_key(identity, relay_id, &id, relay_id).unwrap();
        let mut token = [0u8; TOKEN_LEN];
        for _ in 0..2 {
            let msg = signed(
                &key,
                Message::Register {
                    id,
                    token,
                    flags,
                    proof: [0; crate::relay::PROOF_LEN],
                },
            );
            sock.send_to(&msg, relay).await.ok()?;
            match recv_message(sock, Duration::from_secs(2)).await? {
                Message::Challenge { token: t } => token = t,
                other => return Some(other),
            }
        }
        None
    }

    /// The addresses a pair uses on an allocated port are not the ones the
    /// control port saw — a NAT that gives out a port per destination is
    /// exactly what a relay is for. So each side says which one it is with
    /// the ticket it was given, and that is what binds it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_side_binds_itself_with_its_ticket_from_wherever_it_is() {
        let (relay, relay_id, cancel) = start_relay().await;
        let owner = Identity::generate();
        let id = owner.id();

        // The two control sockets: as far as the relay can see, this is
        // where the peers are.
        let rc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // A registration is only accepted once it echoes a token bound to
        // the address the relay saw, so a forged source gets nowhere.
        let key = crate::relay::auth_key(&owner, &relay_id, &id, &relay_id).unwrap();
        let first = ask(
            &rc,
            relay,
            Message::Register {
                id,
                token: [0; TOKEN_LEN],
                flags: 0,
                proof: crate::relay::proof_for(&key, &[]),
            },
        )
        .await;
        assert!(matches!(first, Some(Message::Challenge { .. })));
        let registered = register(&rc, relay, &relay_id, &owner, 0).await;
        let Some(Message::Registered { observed, .. }) = registered else {
            panic!("expected a registration, got {:?}", registered);
        };
        assert_eq!(observed, rc.local_addr().unwrap());

        // A sender asks to be put through.
        let allocated =
            with_token(&sc, relay, |token| Message::Connect { target: id, token }).await;
        let Some(Message::Allocated {
            port,
            peer,
            ticket: sender_ticket,
        }) = allocated
        else {
            panic!("expected an allocation, got {:?}", allocated);
        };
        assert_eq!(
            peer,
            rc.local_addr().unwrap(),
            "the sender is told where to try directly"
        );

        // The receiver is told at the same time, so both push outwards at
        // once.
        let Some(Message::Incoming {
            port: rport,
            peer: speer,
            ticket: receiver_ticket,
        }) = recv_message(&rc, Duration::from_secs(2)).await
        else {
            panic!("the receiver was not introduced");
        };
        assert_eq!(rport, port);
        assert_eq!(speer, sc.local_addr().unwrap());
        assert_ne!(sender_ticket, receiver_ticket);

        // Now the part that matters: the two sides show up at the allocated
        // port from *different* sockets than the ones the relay knows.
        let allocated_addr = SocketAddr::new(relay.ip(), port);
        let rd = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sd = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_ne!(rd.local_addr().unwrap(), rc.local_addr().unwrap());
        rd.send_to(
            &Message::Open {
                ticket: receiver_ticket,
            }
            .encode(),
            allocated_addr,
        )
        .await
        .unwrap();
        sd.send_to(
            &Message::Open {
                ticket: sender_ticket,
            }
            .encode(),
            allocated_addr,
        )
        .await
        .unwrap();

        // Traffic now crosses, in both directions, between exactly those two.
        let mut buf = vec![0u8; 2048];
        sd.send_to(b"from the sender", allocated_addr)
            .await
            .unwrap();
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), rd.recv_from(&mut buf))
            .await
            .expect("the relay carries it")
            .unwrap();
        assert_eq!(&buf[..n], b"from the sender");
        assert_eq!(from, allocated_addr);
        rd.send_to(b"and back", allocated_addr).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), sd.recv_from(&mut buf))
            .await
            .expect("and the other way")
            .unwrap();
        assert_eq!(&buf[..n], b"and back");

        // Knowing the port is not enough to join in: without a ticket,
        // nothing of yours is carried.
        let intruder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        intruder
            .send_to(b"let me in", allocated_addr)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(400), rd.recv_from(&mut buf))
                .await
                .is_err(),
            "the relay carried traffic from an address that never presented a ticket"
        );
        // A wrong ticket does not bind a side either.
        intruder
            .send_to(
                &Message::Open {
                    ticket: [0xAB; TOKEN_LEN],
                }
                .encode(),
                allocated_addr,
            )
            .await
            .unwrap();
        intruder
            .send_to(b"let me in", allocated_addr)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(400), rd.recv_from(&mut buf))
                .await
                .is_err()
        );

        cancel.cancel();
    }

    /// Nobody registered, so there is nothing to put a sender through to —
    /// and saying so beats leaving it to a timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connecting_to_an_unregistered_identity_is_refused() {
        let (relay, _relay_id, cancel) = start_relay().await;
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = Identity::generate().id();
        let answer = with_token(&sc, relay, |token| Message::Connect { target, token }).await;
        assert!(
            matches!(
                answer,
                Some(Message::Error {
                    code: Refusal::Unknown
                })
            ),
            "got {:?}",
            answer
        );
        cancel.cancel();
    }

    /// Anything that is not a relay message gets no answer at all, so the
    /// control port cannot be used to find out what is listening.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rubbish_on_the_control_port_is_not_answered() {
        let (relay, _relay_id, cancel) = start_relay().await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for junk in [&b""[..], b"hello?", b"SHRELAY1", &[0u8; 64][..]] {
            sock.send_to(junk, relay).await.unwrap();
        }
        let mut buf = vec![0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(400), sock.recv_from(&mut buf))
                .await
                .is_err(),
            "the relay answered something that was not a message"
        );
        cancel.cancel();
    }

    /// A receiver that goes away says so, and the relay stops sending
    /// people to an address nothing answers at. Without it, senders would
    /// keep being pointed there until the lease ran out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_receiver_that_says_goodbye_is_forgotten() {
        let (relay, relay_id, cancel) = start_relay().await;
        let owner = Identity::generate();
        let id = owner.id();
        let rc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            register(&rc, relay, &relay_id, &owner, 0).await,
            Some(Message::Registered { .. })
        ));

        // Somebody who merely knows the identity cannot end its
        // registration: the proof is the owner's to make.
        let impostor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wrong_key =
            crate::relay::auth_key(&Identity::generate(), &relay_id, &id, &relay_id).unwrap();
        let stolen = token_for(&impostor, relay, Identity::generate().id()).await;
        let forged = signed(
            &wrong_key,
            Message::Bye {
                id,
                token: stolen,
                proof: [0; crate::relay::PROOF_LEN],
            },
        );
        impostor.send_to(&forged, relay).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let still_there =
            with_token(&sc, relay, |token| Message::Connect { target: id, token }).await;
        assert!(
            matches!(still_there, Some(Message::Allocated { .. })),
            "a stranger ended somebody else's registration: {:?}",
            still_there
        );

        // The owner's own goodbye is taken.
        let key = crate::relay::auth_key(&owner, &relay_id, &id, &relay_id).unwrap();
        let token = token_for(&rc, relay, id).await;
        let bye = signed(
            &key,
            Message::Bye {
                id,
                token,
                proof: [0; crate::relay::PROOF_LEN],
            },
        );
        rc.send_to(&bye, relay).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gone = with_token(&sc, relay, |token| Message::Connect { target: id, token }).await;
        assert!(
            matches!(
                gone,
                Some(Message::Error {
                    code: Refusal::Unknown
                })
            ),
            "got {:?}",
            gone
        );
        cancel.cancel();
    }

    /// Registering an identity is the owner's to do. Without a proof of it,
    /// anyone who knew a published ID could register it here and have
    /// senders put through to them: the handshake would fail, but the
    /// transfer would fail with it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_identity_can_only_be_registered_by_its_owner() {
        let (relay, relay_id, cancel) = start_relay().await;
        let owner = Identity::generate();
        let id = owner.id();

        // The attacker knows the published identity and nothing else.
        let impostor = Identity::generate();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wrong = crate::relay::auth_key(&impostor, &relay_id, &id, &relay_id).unwrap();
        let mut token = [0u8; TOKEN_LEN];
        for _ in 0..2 {
            let msg = signed(
                &wrong,
                Message::Register {
                    id,
                    token,
                    flags: 0,
                    proof: [0; crate::relay::PROOF_LEN],
                },
            );
            sock.send_to(&msg, relay).await.unwrap();
            match recv_message(&sock, Duration::from_secs(2)).await {
                Some(Message::Challenge { token: t }) => token = t,
                other => {
                    assert!(
                        matches!(
                            other,
                            Some(Message::Error {
                                code: Refusal::BadToken
                            })
                        ),
                        "an identity was registered without proof: {:?}",
                        other
                    );
                    break;
                }
            }
        }
        // Nobody can be put through to it, because nobody registered it.
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let answer = with_token(&sc, relay, |token| Message::Connect { target: id, token }).await;
        assert!(
            matches!(
                answer,
                Some(Message::Error {
                    code: Refusal::Unknown
                })
            ),
            "got {:?}",
            answer
        );

        // The owner registers it without trouble.
        let rc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            register(&rc, relay, &relay_id, &owner, 0).await,
            Some(Message::Registered { .. })
        ));
        cancel.cancel();
    }

    /// A small-order point is an identity nobody holds and anybody can
    /// claim: the exchange with it comes out the same whatever the relay's
    /// secret, so the "proof" is one anyone can make. It is never taken.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_identity_nobody_holds_cannot_be_registered() {
        let (relay, relay_id, cancel) = start_relay().await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // One token proves the address for all of them; asking for one each
        // time would run into the relay's rate limit instead.
        let token = token_for(&sock, relay, Identity::generate().id()).await;
        for point in crate::crypto::identity::tests::low_order_points() {
            let id = SharpId::from_public(point);
            // What anybody could compute for it: the exchange is all zeros.
            let mut material = [0u8; 96];
            material[32..64].copy_from_slice(id.as_bytes());
            material[64..].copy_from_slice(relay_id.as_bytes());
            let key = blake3::derive_key("sharp256 relay v1 registration", &material);
            let msg = signed(
                &key,
                Message::Register {
                    id,
                    token,
                    flags: 0,
                    proof: [0; crate::relay::PROOF_LEN],
                },
            );
            sock.send_to(&msg, relay).await.unwrap();
            let answer = recv_message(&sock, Duration::from_secs(2)).await;
            assert!(
                matches!(
                    answer,
                    Some(Message::Error {
                        code: Refusal::BadToken
                    })
                ),
                "{:02x?} was registered by somebody who holds nothing: {:?}",
                point,
                answer
            );
        }
        cancel.cancel();
    }

    /// A receiver that asks to stay hidden is not described to the caller:
    /// there is then no direct path to try, and the pair meets at the
    /// relay's port. It costs the relay's bandwidth, and it is the only
    /// arrangement in which a relay actually hides anyone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_private_registration_does_not_disclose_where_it_is() {
        let (relay, relay_id, cancel) = start_relay().await;
        let owner = Identity::generate();
        let id = owner.id();
        let rc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            register(
                &rc,
                relay,
                &relay_id,
                &owner,
                crate::relay::REGISTER_PRIVATE
            )
            .await,
            Some(Message::Registered { .. })
        ));

        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let answer = with_token(&sc, relay, |token| Message::Connect { target: id, token }).await;
        let Some(Message::Allocated { peer, port, .. }) = answer else {
            panic!("expected an allocation, got {:?}", answer);
        };
        assert!(port != 0, "a port is still set aside");
        assert!(
            peer.ip().is_unspecified() && peer.port() == 0,
            "the caller was told where the receiver is: {}",
            peer
        );
        // And the receiver is told nothing about the caller either.
        let Some(Message::Incoming { peer, .. }) = recv_message(&rc, Duration::from_secs(2)).await
        else {
            panic!("the receiver was not introduced");
        };
        assert!(peer.ip().is_unspecified() && peer.port() == 0);

        // Nor when the introduction is repeated, which it is for as long as
        // the receiver has not shown up at the port. A repeat that said more
        // than the first would give away exactly what was asked to be kept.
        let mut repeats = 0;
        while let Some(msg) = recv_message(&rc, Duration::from_secs(1)).await {
            if let Message::Incoming { peer, .. } = msg {
                repeats += 1;
                assert!(
                    peer.ip().is_unspecified() && peer.port() == 0,
                    "a repeated introduction disclosed the caller: {}",
                    peer
                );
            }
            if repeats >= 2 {
                break;
            }
        }
        assert!(repeats >= 2, "the introduction was never repeated");
        cancel.cancel();
    }

    /// A sender whose answer went missing asks again, and must get the port
    /// it already holds — even when that port is the last of its share. A
    /// relay that checked the limits first would refuse it the very thing
    /// it has, and the transfer would fail on one lost datagram.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn asking_again_returns_the_same_port_even_at_the_limit() {
        let (relay, relay_id, cancel) = start_relay_with(Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            idle: Duration::from_secs(5),
            // A share of two ports per address.
            max_allocations: 8,
            ..Config::default()
        })
        .await;
        let owner = Identity::generate();
        let id = owner.id();
        let rc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            register(&rc, relay, &relay_id, &owner, 0).await,
            Some(Message::Registered { .. })
        ));

        // Two senders on the same host take its whole share.
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let Some(Message::Allocated { port, ticket, .. }) = with_token(&first, relay, |token| {
            Message::Connect { target: id, token }
        })
        .await
        else {
            panic!("the first sender got no port");
        };
        assert!(matches!(
            with_token(&second, relay, |token| Message::Connect {
                target: id,
                token
            })
            .await,
            Some(Message::Allocated { .. })
        ));
        // A third is over the share.
        let third = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            with_token(&third, relay, |token| Message::Connect {
                target: id,
                token
            })
            .await,
            Some(Message::Error {
                code: Refusal::Busy
            })
        ));

        // The first asks again and is handed back what it already has.
        let again = with_token(&first, relay, |token| Message::Connect {
            target: id,
            token,
        })
        .await;
        let Some(Message::Allocated {
            port: again_port,
            ticket: again_ticket,
            ..
        }) = again
        else {
            panic!("a sender was refused the port it holds: {:?}", again);
        };
        assert_eq!((again_port, again_ticket), (port, ticket));
        cancel.cancel();
    }

    /// One address holding both tickets is a pair talking to itself. A
    /// datagram put into that would be forwarded back to where it came
    /// from, and each hop would refresh the idle timer that should have
    /// reclaimed the port — one packet, carried for ever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_address_cannot_hold_both_sides() {
        let (relay, relay_id, cancel) = start_relay().await;
        let owner = Identity::generate();
        let id = owner.id();
        let rc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            register(&rc, relay, &relay_id, &owner, 0).await,
            Some(Message::Registered { .. })
        ));
        let Some(Message::Allocated {
            port,
            ticket: sender_ticket,
            ..
        }) = with_token(&sc, relay, |token| Message::Connect { target: id, token }).await
        else {
            panic!("expected an allocation");
        };
        let Some(Message::Incoming {
            ticket: receiver_ticket,
            ..
        }) = recv_message(&rc, Duration::from_secs(2)).await
        else {
            panic!("the receiver was not introduced");
        };

        // One socket presents both tickets.
        let both = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let allocated = SocketAddr::new(relay.ip(), port);
        for ticket in [sender_ticket, receiver_ticket] {
            both.send_to(&Message::Open { ticket }.encode(), allocated)
                .await
                .unwrap();
        }
        both.send_to(b"round and round", allocated).await.unwrap();

        let mut buf = vec![0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(500), both.recv_from(&mut buf))
                .await
                .is_err(),
            "the relay carried a datagram back to where it came from"
        );
        cancel.cancel();
    }
}
