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
use crate::nat::card::NatHints;
use crate::transport::io::PktSocket;
use rand::RngCore;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// How long a registration lives without a keepalive.
pub const DEFAULT_LEASE: Duration = Duration::from_secs(120);
/// How long an allocation survives with nothing flowing through it.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(60);
/// How often the token secret is replaced. Two are kept, so a token is good
/// for between one and two of these — measured on the clock, whether or not
/// anyone asks for a token in between.
const TOKEN_LIFETIME: Duration = Duration::from_secs(120);
/// How long the relay remembers the newest stamp of an identity that is no
/// longer registered. A captured message is only good while its address
/// token is, which is at most two token lifetimes; after that it is
/// refused for its token, and there is nothing left to remember.
const STAMP_MEMORY: Duration = Duration::from_secs(2 * 120);
/// Socket buffers for the control port and for each carried pair.
const CONTROL_BUFFER: usize = 1 << 20;
const PAIR_BUFFER: usize = 2 << 20;
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
    /// How many of those one client may hold. A client is an IPv4 address,
    /// or an IPv6 /64 — the block one subscriber is usually given, and so
    /// what one of them can put addresses in at no cost. Without a share,
    /// the limits above are first come, first served, and a few clients
    /// could take everything. Set higher where many receivers sit behind
    /// one carrier-grade NAT.
    pub registrations_per_client: usize,
    pub allocations_per_client: usize,
    /// Requests per second accepted from one client, and the burst.
    pub rate: f64,
    pub burst: f64,
    pub lease: Duration,
    pub idle: Duration,
    /// Identities that may register here; `None` lets any identity that
    /// proves itself register. A relay run for one's own receivers should
    /// list them: otherwise anyone may make it their rendezvous, and have
    /// their transfers carried on its bandwidth.
    pub allowed_receivers: Option<std::collections::HashSet<SharpId>>,
    /// Identities that may ask to be put through; `None` lets anyone ask —
    /// a sender needs no identity of its own then, and with registrations
    /// limited, nobody can be put through to anyone but those listed.
    /// With a list, a sender has to say who it is and prove it
    /// (`Message::ConnectAs`).
    pub allowed_senders: Option<std::collections::HashSet<SharpId>>,
    /// Limits on what is carried.
    pub quotas: Quotas,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind", &self.bind)
            .field("id", &self.identity.id())
            .field("max_registrations", &self.max_registrations)
            .field("max_allocations", &self.max_allocations)
            .field("registrations_per_client", &self.registrations_per_client)
            .field("allocations_per_client", &self.allocations_per_client)
            .field("rate", &self.rate)
            .field("lease", &self.lease)
            .field("idle", &self.idle)
            .field(
                "allowed_receivers",
                &self.allowed_receivers.as_ref().map(|l| l.len()),
            )
            .field(
                "allowed_senders",
                &self.allowed_senders.as_ref().map(|l| l.len()),
            )
            .field("quotas", &self.quotas)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "[::]:5560".parse().expect("valid address"),
            identity: Identity::generate(),
            max_registrations: 4096,
            max_allocations: 256,
            registrations_per_client: 128,
            allocations_per_client: 16,
            rate: 10.0,
            burst: 20.0,
            lease: DEFAULT_LEASE,
            idle: DEFAULT_IDLE,
            allowed_receivers: None,
            allowed_senders: None,
            quotas: Quotas::default(),
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

    /// Brings the secrets up to date with the clock. The periods are
    /// counted from when the jar was made, not from when it was last asked:
    /// rotating only on use, one step at a time, let a token outlive its
    /// lifetime by as long as the relay happened to be quiet — hours, on a
    /// quiet relay — and a token is the only thing fresh in a registration.
    fn rotate(&mut self, now: Instant) {
        let age = now.saturating_duration_since(self.born);
        let periods = age.as_nanos() / TOKEN_LIFETIME.as_nanos();
        if periods == 0 {
            return;
        }
        if periods >= 2 {
            // Both current secrets are too old to honour anything made
            // with them.
            self.secrets = [random_key(), random_key()];
        } else {
            self.secrets.swap(0, 1);
            self.secrets[0] = random_key();
        }
        self.born += TOKEN_LIFETIME * periods.min(u32::MAX as u128) as u32;
    }

    fn make(secret: &[u8; 32], addr: SocketAddr) -> [u8; TOKEN_LEN] {
        let mut data = Vec::with_capacity(18);
        match crate::address::canonical(addr).ip() {
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

/// What an allocated port sends a side to prove it receives at `from`: a
/// keyed hash of the side's ticket and that address, under a key only this
/// pair knows.
fn confirmation(key: &[u8; 32], ticket: &[u8; TOKEN_LEN], from: SocketAddr) -> [u8; TOKEN_LEN] {
    let from = crate::address::canonical(from);
    let mut data = Vec::with_capacity(TOKEN_LEN + 18);
    data.extend_from_slice(ticket);
    match from.ip() {
        std::net::IpAddr::V4(v4) => data.extend_from_slice(&v4.to_ipv6_mapped().octets()),
        std::net::IpAddr::V6(v6) => data.extend_from_slice(&v6.octets()),
    }
    data.extend_from_slice(&from.port().to_be_bytes());
    let mut out = [0u8; TOKEN_LEN];
    out.copy_from_slice(&blake3::keyed_hash(key, &data).as_bytes()[..TOKEN_LEN]);
    out
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

use crate::address::client_key;

/// How often a full rate limiter may walk its table looking for room. A
/// spray of forged sources keeps it full; walking the whole table for every
/// one of their packets would make each one cost the relay a scan.
const FULL_PRUNE_EVERY: Duration = Duration::from_millis(250);

/// A token bucket per client (see [`client_key`]).
pub(crate) struct RateLimiter {
    per_ip: HashMap<std::net::IpAddr, (f64, Instant)>,
    rate: f64,
    burst: f64,
    last_full_prune: Option<Instant>,
}

impl RateLimiter {
    pub(crate) fn new(rate: f64, burst: f64) -> Self {
        Self {
            per_ip: HashMap::new(),
            rate,
            burst: burst.max(1.0),
            last_full_prune: None,
        }
    }

    /// Takes a token for `from`; false when it has had too many.
    pub(crate) fn allow(&mut self, from: SocketAddr, now: Instant) -> bool {
        let (rate, burst) = (self.rate, self.burst);
        let key = client_key(from);
        if self.per_ip.len() >= MAX_TRACKED_ADDRESSES && !self.per_ip.contains_key(&key) {
            // Full. Make room from entries whose budget has refilled — but
            // not on every packet — and if there is none, refuse rather
            // than grow.
            let due = self
                .last_full_prune
                .is_none_or(|t| now.saturating_duration_since(t) >= FULL_PRUNE_EVERY);
            if due {
                self.last_full_prune = Some(now);
                self.prune(now);
            }
            if self.per_ip.len() >= MAX_TRACKED_ADDRESSES {
                return false;
            }
        }
        let (tokens, at) = self.per_ip.entry(key).or_insert((burst, now));
        *tokens = (*tokens + now.saturating_duration_since(*at).as_secs_f64() * rate).min(burst);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Forgets clients whose budget is full again, so the table cannot
    /// grow without bound.
    fn prune(&mut self, now: Instant) {
        let (rate, burst) = (self.rate, self.burst);
        self.per_ip.retain(|_, (tokens, at)| {
            *tokens + now.saturating_duration_since(*at).as_secs_f64() * rate < burst
        });
    }
}

/// Limits on what a relay carries, so that whoever can reach it cannot
/// simply have its bandwidth. Zero means no limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quotas {
    /// Bytes per second carried from one client (an IPv4 address, or an
    /// IPv6 /64: see `address::client_key`).
    pub client_rate: u64,
    /// Bytes one client may have carried in any hour or so: a bucket of
    /// this size, refilled at this much per hour.
    pub client_hourly: u64,
    /// Bytes per second carried for everybody together — what the relay's
    /// own link can spare.
    pub total_rate: u64,
    /// Bytes one pair may carry in all before its port is closed.
    pub pair_bytes: u64,
}

impl Default for Quotas {
    /// 100 Mbit/s per client, the rest open. A relay is the path of last
    /// resort, and its operator's bandwidth is what it spends; the operator
    /// sets the rest (see `sharp-relay --help`).
    fn default() -> Self {
        Self {
            client_rate: 100_000_000 / 8,
            client_hourly: 0,
            total_rate: 0,
            pair_bytes: 0,
        }
    }
}

/// A token bucket over bytes.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    rate: f64,
    cap: f64,
    at: Instant,
}

impl Bucket {
    /// Full, refilling at `rate` bytes per second up to `cap`.
    fn new(rate: f64, cap: f64, now: Instant) -> Self {
        Self {
            tokens: cap,
            rate,
            cap,
            at: now,
        }
    }

    /// A bucket for a rate limit: a quarter of a second's worth of burst,
    /// and never less than a few jumbo datagrams.
    fn for_rate(bytes_per_sec: u64, now: Instant) -> Self {
        let rate = bytes_per_sec as f64;
        Self::new(rate, (rate / 4.0).max(64.0 * 1024.0), now)
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + dt * self.rate).min(self.cap);
        self.at = now;
    }

    fn full(&self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens + dt * self.rate >= self.cap
    }
}

/// What one client has had carried.
struct ClientMeter {
    rate: Option<Bucket>,
    hourly: Option<Bucket>,
}

/// Clients whose use is tracked at once. Past this, a client whose budget
/// has refilled completely is forgotten (nothing is lost by that); if none
/// has, a new client is refused rather than let the table grow — or let one
/// who spent its budget be forgotten, and so start afresh.
const MAX_METERED: usize = 65_536;

/// The relay's account of what it carries, shared by every pair.
pub(crate) struct Meter {
    quotas: Quotas,
    total: Option<Bucket>,
    clients: HashMap<std::net::IpAddr, ClientMeter>,
    last_full_prune: Option<Instant>,
    /// Datagrams not carried because of a limit, since the start.
    pub(crate) refused: u64,
}

impl Meter {
    pub(crate) fn new(quotas: Quotas) -> Self {
        let now = Instant::now();
        Self {
            quotas,
            total: (quotas.total_rate > 0).then(|| Bucket::for_rate(quotas.total_rate, now)),
            clients: HashMap::new(),
            last_full_prune: None,
            refused: 0,
        }
    }

    /// Whether `bytes` more from `from` may be carried now; if so, they are
    /// counted. All limits or none: a datagram refused by one limit costs
    /// nothing against the others.
    pub(crate) fn allow(&mut self, from: SocketAddr, bytes: usize, now: Instant) -> bool {
        let q = self.quotas;
        let key = client_key(from);
        if (q.client_rate > 0 || q.client_hourly > 0)
            && !self.clients.contains_key(&key)
            && self.clients.len() >= MAX_METERED
        {
            let due = self
                .last_full_prune
                .is_none_or(|t| now.saturating_duration_since(t) >= FULL_PRUNE_EVERY);
            if due {
                self.last_full_prune = Some(now);
                self.clients.retain(|_, c| {
                    !(c.rate.is_none_or(|b| b.full(now)) && c.hourly.is_none_or(|b| b.full(now)))
                });
            }
            if self.clients.len() >= MAX_METERED {
                self.refused += 1;
                return false;
            }
        }
        let n = bytes as f64;
        let client = if q.client_rate > 0 || q.client_hourly > 0 {
            Some(self.clients.entry(key).or_insert_with(|| ClientMeter {
                rate: (q.client_rate > 0).then(|| Bucket::for_rate(q.client_rate, now)),
                hourly: (q.client_hourly > 0).then(|| {
                    let h = q.client_hourly as f64;
                    Bucket::new(h / 3600.0, h, now)
                }),
            }))
        } else {
            None
        };
        let mut buckets: Vec<&mut Bucket> = Vec::with_capacity(3);
        if let Some(t) = self.total.as_mut() {
            buckets.push(t);
        }
        if let Some(c) = client {
            if let Some(b) = c.rate.as_mut() {
                buckets.push(b);
            }
            if let Some(b) = c.hourly.as_mut() {
                buckets.push(b);
            }
        }
        for b in buckets.iter_mut() {
            b.refill(now);
        }
        if buckets.iter().any(|b| b.tokens < n) {
            self.refused += 1;
            return false;
        }
        for b in buckets {
            b.tokens -= n;
        }
        true
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
    /// The newest stamp taken from the owner. Anything not newer is a
    /// replay, or an owner whose clock went backwards.
    stamp: u64,
    /// What the owner says its NAT does, for the senders it is introduced
    /// to. Kept only as advice to pass on.
    hints: NatHints,
    /// The relay address the registration was sent to, which is where what
    /// is sent to the owner later — an introduction — has to come from.
    via: Option<std::net::IpAddr>,
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
    // As the other side would write it: a dual-stack relay sees IPv4
    // clients in their mapped form, which an IPv4 client cannot use.
    let addr = crate::address::canonical(addr);
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
    socket: Arc<PktSocket>,
    /// The address the datagram being handled was sent to: what the answer
    /// to it comes from.
    via: Option<std::net::IpAddr>,
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
    /// What has been carried, per client and in all; every pair counts
    /// against it.
    meter: Arc<parking_lot::Mutex<Meter>>,
    last_prune: Instant,
    /// The newest stamp of identities that were registered and are not any
    /// more, and until when it matters (see [`STAMP_MEMORY`]). Without it,
    /// the goodbye that ended a registration would also end the memory of
    /// what came before it, and an older registration captured from the
    /// same address could be sent again and taken.
    forgotten: HashMap<SharpId, (u64, Instant)>,
}

impl Relay {
    pub async fn bind(cfg: Config, cancel: CancellationToken) -> io::Result<Self> {
        // Through the transfer sockets' own set-up: on Windows that is what
        // stops an ICMP error from a vanished peer surfacing as a receive
        // error on this socket — and enough of those would stop the relay.
        let socket = crate::transport::socket::bind_udp(cfg.bind, CONTROL_BUFFER)?;
        let socket = PktSocket::new(Arc::new(socket))?;
        let now = Instant::now();
        let (cfg_rate, cfg_burst) = (cfg.rate, cfg.burst);
        let meter = Arc::new(parking_lot::Mutex::new(Meter::new(cfg.quotas)));
        Ok(Self {
            socket: Arc::new(socket),
            via: None,
            identity: cfg.identity.clone(),
            cfg,
            cancel,
            tokens: TokenJar::new(),
            registrations: HashMap::new(),
            allocations: Vec::new(),
            ports: Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new())),
            limiter: RateLimiter::new(cfg_rate, cfg_burst),
            meter,
            last_prune: now,
            forgotten: HashMap::new(),
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
                r = socket.recv(&mut buf) => {
                    let got = match r {
                        Ok(v) => {
                            errors = 0;
                            v
                        }
                        // Never a reason to stop: the relay is a service,
                        // and a receive error is at worst something the
                        // network did — which on some systems others can
                        // cause from outside. A stream of them is waited
                        // out, backing off so it cannot spin this loop,
                        // which is the whole relay's only thread.
                        Err(e) => {
                            errors = errors.saturating_add(1);
                            if errors.is_power_of_two() {
                                tracing::warn!("relay: receive failed ({} in a row): {}", errors, e);
                            }
                            let pause = Duration::from_millis(10 * errors.min(100) as u64);
                            tokio::select! {
                                _ = tokio::time::sleep(pause) => {}
                                _ = cancel.cancelled() => {}
                            }
                            continue;
                        }
                    };
                    let from = got.from;
                    self.via = got.dst;
                    // One datagram, or a run the system handed over together.
                    for pkt in buf[..got.len].chunks(got.stride.max(1)) {
                        let now = Instant::now();
                        self.prune(now);
                        // Anything that is not a control message on the control
                        // port is not ours; the relay never answers it, so it
                        // cannot be used to probe for one.
                        let Some(msg) = Message::decode(pkt) else { continue };
                        if !self.limiter.allow(from, now) {
                            continue;
                        }
                        self.on_message(msg, from, pkt, now).await;
                    }
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
        let _ = self.socket.send(to, self.via, &msg.encode()).await;
    }

    /// [`Relay::reply`] to somebody other than who asked, from the address
    /// it knows the relay by.
    async fn reply_via(&self, to: SocketAddr, via: Option<std::net::IpAddr>, msg: Message) {
        let _ = self.socket.send(to, via, &msg.encode()).await;
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
                stamp,
                hints,
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
                // And a proven identity that is not one this relay serves
                // gets told so. Only after the proof: whether an identity
                // is on the list is nothing to tell someone who does not
                // hold it.
                if self
                    .cfg
                    .allowed_receivers
                    .as_ref()
                    .is_some_and(|l| !l.contains(&id))
                {
                    tracing::info!("relay: {} is not on the list of receivers", id.short());
                    self.reply(
                        from,
                        Message::Error {
                            code: Refusal::Forbidden,
                        },
                    )
                    .await;
                    return;
                }
                // Only something newer than what we already took from this
                // identity. The proof ties the message to its owner but not
                // to a moment; the stamp does, and without it a registration
                // captured on its way here could be sent again from the same
                // address — to move a registration back to where it used to
                // be, or to make a private one public.
                let newest = self
                    .registrations
                    .get(&id)
                    .map(|r| r.stamp)
                    .or_else(|| self.forgotten.get(&id).map(|(s, _)| *s));
                if newest.is_some_and(|n| stamp <= n) {
                    tracing::debug!("relay: stale registration of {} from {}", id.short(), from);
                    self.reply(
                        from,
                        Message::Error {
                            code: Refusal::Stale,
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
                    // The same kind of share ports get, and for the same
                    // reason. An identity costs nothing to invent — the id
                    // is read straight off the wire — so without this one
                    // client could register thousands and leave room for
                    // nobody.
                    let share = self.cfg.registrations_per_client.max(1);
                    let client = client_key(from);
                    let mine = self
                        .registrations
                        .values()
                        .filter(|r| client_key(r.addr) == client && r.fresh(now))
                        .count();
                    let live = self.registrations.values().filter(|r| r.fresh(now)).count();
                    if live >= self.cfg.max_registrations || mine >= share {
                        if mine >= share {
                            tracing::info!(
                                "relay: {} already holds {} registrations",
                                client,
                                mine
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
                self.forgotten.remove(&id);
                self.registrations.insert(
                    id,
                    Registration {
                        addr: from,
                        expires: now + self.cfg.lease,
                        private: flags & super::REGISTER_PRIVATE != 0,
                        stamp,
                        hints,
                        via: self.via,
                    },
                );
                if !known {
                    tracing::info!("relay: {} registered at {}", id.short(), from);
                }
                self.reply(
                    from,
                    Message::Registered {
                        lease: self.cfg.lease.as_secs().min(u32::MAX as u64) as u32,
                        observed: crate::address::canonical(from),
                    },
                )
                .await;
            }
            Message::Connect {
                target,
                token,
                hints,
            } => {
                if !self.tokens.accepts(&token, from, now) {
                    let token = self.tokens.issue(from, now);
                    self.reply(from, Message::Challenge { token }).await;
                    return;
                }
                // A relay with a list of senders has to know who is asking.
                if self.cfg.allowed_senders.is_some() {
                    self.reply(
                        from,
                        Message::Error {
                            code: Refusal::Forbidden,
                        },
                    )
                    .await;
                    return;
                }
                self.put_through(target, from, hints, now).await;
            }
            Message::ConnectAs {
                target,
                token,
                hints,
                id,
                ..
            } => {
                if !self.tokens.accepts(&token, from, now) {
                    let token = self.tokens.issue(from, now);
                    self.reply(from, Message::Challenge { token }).await;
                    return;
                }
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
                if self
                    .cfg
                    .allowed_senders
                    .as_ref()
                    .is_some_and(|l| !l.contains(&id))
                {
                    tracing::info!("relay: {} is not on the list of senders", id.short());
                    self.reply(
                        from,
                        Message::Error {
                            code: Refusal::Forbidden,
                        },
                    )
                    .await;
                    return;
                }
                self.put_through(target, from, hints, now).await;
            }
            Message::Bye {
                id, token, stamp, ..
            } => {
                // A token that has gone stale gets a fresh one, as for every
                // other request. The owner holds on to its last token until
                // it leaves, and silently dropping a goodbye whose token had
                // just expired left the registration standing for the rest
                // of its lease — for a fair share of goodbyes.
                if !self.tokens.accepts(&token, from, now) {
                    let token = self.tokens.issue(from, now);
                    self.reply(from, Message::Challenge { token }).await;
                    return;
                }
                // Only from the address that holds the registration, with a
                // proof of the identity, and newer than the registration it
                // ends: otherwise anyone who knew an identity could evict
                // its owner, or an old goodbye sent again could end a
                // registration made since.
                if !self.owns(&id, raw) {
                    return;
                }
                if self
                    .registrations
                    .get(&id)
                    .is_some_and(|r| r.addr == from && stamp > r.stamp)
                {
                    self.registrations.remove(&id);
                    self.remember(id, stamp, now);
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
            | Message::Confirm { .. }
            | Message::Punch => {}
        }
    }

    /// Puts a sender at `from` through to `target`: allocates a port for
    /// the pair (or hands back the one it already has) and introduces the
    /// two.
    async fn put_through(
        &mut self,
        target: SharpId,
        from: SocketAddr,
        sender_hints: NatHints,
        now: Instant,
    ) {
        let Some(reg) = self.registrations.get(&target).filter(|r| r.fresh(now)) else {
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
        let receiver_via = reg.via;
        // An owner that asked to stay hidden is not described to
        // the caller; there is then no direct path to try and the
        // pair meets at the relay's port.
        let disclose = !reg.private;
        // What is said of where an owner is, is said of how its NAT
        // behaves only when it may be said at all.
        let (receiver_hints, sender_hints) = if disclose {
            (reg.hints, sender_hints)
        } else {
            (NatHints::unknown(), NatHints::unknown())
        };
        // The same pair asking again means our answer went missing,
        // not that they want a second port. That has to be settled
        // before the limits: a sender that already holds its whole
        // share would otherwise be refused the very port it has.
        let granted = match self.existing(from, receiver, disclose) {
            Some(granted) => Some(granted),
            None => {
                let share = self.cfg.allocations_per_client.max(1);
                let client = client_key(from);
                let mine = self
                    .allocations
                    .iter()
                    .filter(|a| a.requested_by == client && !a.task.is_finished())
                    .count();
                let live = self
                    .allocations
                    .iter()
                    .filter(|a| !a.task.is_finished())
                    .count();
                if live >= self.cfg.max_allocations || mine >= share {
                    if mine >= share {
                        tracing::info!("relay: {} already holds {} ports", client, mine);
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
                self.allocate(from, receiver, receiver_via, disclose, sender_hints)
                    .await
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
                        hints: receiver_hints,
                    },
                )
                .await;
                self.reply_via(
                    receiver,
                    receiver_via,
                    Message::Incoming {
                        port,
                        peer: shown(from, disclose),
                        ticket: receiver_ticket,
                        hints: sender_hints,
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
        receiver_via: Option<std::net::IpAddr>,
        disclose: bool,
        sender_hints: NatHints,
    ) -> Option<(u16, [u8; TOKEN_LEN], [u8; TOKEN_LEN])> {
        // On the address the control port actually has: `[::]` may have
        // fallen back to IPv4 there, and a pair must be reachable the way
        // its peers reached the relay.
        let ip = self
            .socket
            .local_addr()
            .map(|a| a.ip())
            .unwrap_or(self.cfg.bind.ip());
        let bind = SocketAddr::new(ip, 0);
        let sock = Arc::new(
            PktSocket::new(Arc::new(
                crate::transport::socket::bind_udp(bind, PAIR_BUFFER).ok()?,
            ))
            .ok()?,
        );
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
            sender_hints,
            receiver_control: receiver,
            receiver_via,
            idle: self.cfg.idle,
            meter: self.meter.clone(),
            pair_bytes: self.cfg.quotas.pair_bytes,
            cancel: self.cancel.clone(),
        }));
        self.allocations.push(Allocation {
            port,
            task,
            requested_by: client_key(sender),
            sender,
            receiver,
            disclose,
            sender_ticket,
            receiver_ticket,
        });
        Some((port, sender_ticket, receiver_ticket))
    }

    /// Keeps the newest stamp of an identity that is no longer registered,
    /// for as long as a message captured before could still be accepted.
    ///
    /// Bounded like everything else here: past twice the registrations
    /// allowed, the entry nearest to being forgotten anyway goes first.
    /// What that costs is narrow — a replay needs a message captured from
    /// that identity, sent from its own address while its token is still
    /// good — and the alternative, a table anyone can grow, is not.
    fn remember(&mut self, id: SharpId, stamp: u64, now: Instant) {
        let cap = self.cfg.max_registrations.saturating_mul(2).max(16);
        if self.forgotten.len() >= cap && !self.forgotten.contains_key(&id) {
            self.forgotten.retain(|_, (_, until)| *until > now);
            if self.forgotten.len() >= cap {
                if let Some(oldest) = self
                    .forgotten
                    .iter()
                    .min_by_key(|(_, (_, until))| *until)
                    .map(|(k, _)| *k)
                {
                    self.forgotten.remove(&oldest);
                }
            }
        }
        let entry = self.forgotten.entry(id).or_insert((stamp, now));
        entry.0 = entry.0.max(stamp);
        entry.1 = now + STAMP_MEMORY;
    }

    fn prune(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_prune) < Duration::from_secs(5) {
            return;
        }
        self.last_prune = now;
        let expired: Vec<(SharpId, u64)> = self
            .registrations
            .iter()
            .filter(|(_, r)| r.expires <= now)
            .map(|(id, r)| (*id, r.stamp))
            .collect();
        for (id, stamp) in expired {
            self.registrations.remove(&id);
            self.remember(id, stamp, now);
        }
        self.forgotten.retain(|_, (_, until)| *until > now);
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
    sock: Arc<PktSocket>,
    /// The control socket, for repeating an introduction that went missing.
    control: Arc<PktSocket>,
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
    sender_hints: NatHints,
    /// Where the control exchange reached the receiver. Used to repeat the
    /// introduction, and never as a peer address: what counts here is
    /// whichever address presents the ticket.
    receiver_control: SocketAddr,
    /// The relay address the receiver knows the control port by.
    receiver_via: Option<std::net::IpAddr>,
    idle: Duration,
    /// The relay's account of what it carries, and what this pair may carry
    /// in all (0: no limit).
    meter: Arc<parking_lot::Mutex<Meter>>,
    pair_bytes: u64,
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

/// What one pair carried, and what it was refused, told when it ends.
struct Tally {
    port: u16,
    carried: u64,
    refused: u64,
}

impl Drop for Tally {
    fn drop(&mut self) {
        if self.refused > 0 {
            tracing::info!(
                "relay: port {} carried {} bytes and refused {} datagram(s) over its limits",
                self.port,
                self.carried,
                self.refused
            );
        } else {
            tracing::debug!("relay: port {} carried {} bytes", self.port, self.carried);
        }
    }
}

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
        sender_hints,
        receiver_control,
        receiver_via,
        idle,
        meter,
        pair_bytes,
        cancel,
    } = c;
    // Said once, when the pair ends, however it ends.
    let mut tally = Tally {
        port,
        carried: 0,
        refused: 0,
    };
    let mut a: Option<SocketAddr> = None;
    let mut b: Option<SocketAddr> = None;
    let mut via_a: Option<std::net::IpAddr> = None;
    let mut via_b: Option<std::net::IpAddr> = None;
    let mut buf = vec![0u8; BUF_LEN];
    let mut last = Instant::now();
    let mut errors = 0u32;
    let mut introduced = 1u32;
    let mut next_introduce = Instant::now() + INTRODUCE_EVERY;
    let local = sock.local_addr().ok();
    // Keys this pair's confirmations; see `Message::Open`.
    let confirm_key = random_key();

    // An address is only worth carrying to if it is one we would send to at
    // all, and never one of our own ports: two allocations pointed at each
    // other would bounce a single datagram between them for ever, each hop
    // refreshing the idle timer that should have reclaimed them. The
    // confirmation below is what actually rules that out — none of our
    // ports ever answers one — and this catches the obvious case early.
    //
    // Every address judged here is one a datagram really came from, not a
    // stranger's suggestion, so it is screened as such: a peer on this very
    // host, reaching a relay bound to the wildcard over loopback, is a peer
    // like any other; a group, a broadcast or nothing at all is not.
    let acceptable = |addr: SocketAddr| -> bool {
        let Some(local) = local else { return false };
        let ours = crate::address::canonical(local).ip();
        let theirs = crate::address::canonical(addr).ip();
        if (ours == theirs || ours.is_unspecified()) && ports.lock().contains(&addr.port()) {
            return false;
        }
        crate::address::class::is_sendable_named(addr, local)
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
            r = sock.recv(&mut buf) => {
                let got = match r {
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
                let from = got.from;
                // One datagram, or a run the system handed over together;
                // each is carried on its own.
                for pkt in buf[..got.len].chunks(got.stride.max(1)) {
                    let n = pkt.len();
                    // Which of the relay's addresses each side knows this
                    // port by: what its datagrams are sent from, going back.
                    if Some(from) == a {
                        via_a = got.dst;
                    } else if Some(from) == b {
                        via_b = got.dst;
                    }
                    if is_control(pkt) {
                        // A side saying which one it is. The address it comes
                        // from is the one to use, whatever the control port saw.
                        if let Some(Message::Open { ticket, proof }) = Message::decode(pkt) {
                            let is_a = constant_time_eq(&ticket, &sender_ticket);
                            let is_b = constant_time_eq(&ticket, &receiver_ticket);
                            if !is_a && !is_b {
                                continue;
                            }
                            if !acceptable(from) {
                                tracing::debug!("relay: port {} will not carry to {}", port, from);
                                continue;
                            }
                            // Bound only once it has shown it receives here:
                            // the first Open is answered with a confirmation,
                            // to this address and nowhere else, and only an
                            // Open carrying it binds the side. A forged source
                            // never sees it.
                            let expected = confirmation(&confirm_key, &ticket, from);
                            if !constant_time_eq(&proof, &expected) {
                                let reply = Message::Confirm { proof: expected }.encode();
                                let _ = sock.send(from, got.dst, &reply).await;
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
                                via_a = got.dst;
                            } else {
                                b = Some(from);
                                via_b = got.dst;
                            }
                            last = Instant::now();
                        }
                        continue;
                    }
                    // Traffic, carried only between the two bound addresses.
                    let (to, to_via) = if Some(from) == a {
                        (b, via_b)
                    } else if Some(from) == b {
                        (a, via_a)
                    } else {
                        continue;
                    };
                    if let Some(to) = to {
                        let now = Instant::now();
                        // Within the client's and the relay's limits, or not
                        // carried at all: a policed datagram is lost like any
                        // other, and the transfer's own congestion control
                        // slows it to what the relay will carry.
                        if !meter.lock().allow(from, n, now) {
                            tally.refused += 1;
                            continue;
                        }
                        tally.carried += n as u64;
                        if pair_bytes > 0 && tally.carried > pair_bytes {
                            tracing::info!(
                                "relay: port {} has carried the {} bytes a pair may; closing it",
                                port,
                                pair_bytes
                            );
                            return;
                        }
                        last = now;
                        let _ = sock.send(to, to_via, pkt).await;
                    }
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
                        hints: sender_hints,
                    };
                    let _ = control
                        .send(receiver_control, receiver_via, &msg.encode())
                        .await;
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

    /// A token is good for at most two lifetimes on the clock, however long
    /// the relay went without being asked for one. Rotating only when used,
    /// one step per use, let a token issued before a quiet spell stay good
    /// for as long as the spell lasted.
    #[test]
    fn tokens_expire_on_the_clock_not_when_the_relay_is_next_asked() {
        let a: SocketAddr = "198.51.100.5:4000".parse().unwrap();
        let mut jar = TokenJar::new();
        let t0 = jar.born;
        let t = jar.issue(a, t0);
        assert!(!jar.accepts(&t, a, t0 + 2 * TOKEN_LIFETIME));

        let mut jar = TokenJar::new();
        let t0 = jar.born;
        let ms = Duration::from_millis(1);
        let t = jar.issue(a, t0 + TOKEN_LIFETIME - ms);
        assert!(jar.accepts(&t, a, t0 + TOKEN_LIFETIME + ms));
        assert!(jar.accepts(&t, a, t0 + 2 * TOKEN_LIFETIME - ms));
        assert!(!jar.accepts(&t, a, t0 + 2 * TOKEN_LIFETIME + ms));
        // Hours of silence, then a request: nothing from before stands.
        let mut jar = TokenJar::new();
        let t0 = jar.born;
        let t = jar.issue(a, t0);
        assert!(!jar.accepts(&t, a, t0 + 50 * TOKEN_LIFETIME));
        // And the jar still works afterwards.
        let fresh = jar.issue(a, t0 + 50 * TOKEN_LIFETIME);
        assert!(jar.accepts(&fresh, a, t0 + 50 * TOKEN_LIFETIME));
    }

    /// One subscriber is one client, however many addresses it sends from.
    #[test]
    fn a_client_is_an_ipv4_address_or_an_ipv6_slash_64() {
        let a: SocketAddr = "[2001:db8:1:2:aaaa::1]:1000".parse().unwrap();
        let b: SocketAddr = "[2001:db8:1:2:bbbb::9]:2000".parse().unwrap();
        let c: SocketAddr = "[2001:db8:1:3::1]:1000".parse().unwrap();
        assert_eq!(client_key(a), client_key(b));
        assert_ne!(client_key(a), client_key(c));
        let v4: SocketAddr = "198.51.100.7:1".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:198.51.100.7]:2".parse().unwrap();
        assert_eq!(client_key(v4), client_key(mapped));
        assert_ne!(
            client_key(v4),
            client_key("198.51.100.8:1".parse().unwrap())
        );
        // So a whole /64 shares one budget.
        let mut l = RateLimiter::new(1.0, 2.0);
        let now = Instant::now();
        assert!(l.allow(a, now) && l.allow(b, now));
        assert!(!l.allow("[2001:db8:1:2:cccc::5]:3".parse().unwrap(), now));
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
    use tokio::net::UdpSocket;

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

    /// A stamp newer than every one before it in this test run.
    fn stamp() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static LAST: AtomicU64 = AtomicU64::new(1);
        LAST.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Binds one side of an allocated port the way a peer does: an Open,
    /// the confirmation it draws, and the Open that carries it. Returns
    /// whether the port confirmed at all.
    async fn bind_side(sock: &UdpSocket, allocated: SocketAddr, ticket: [u8; TOKEN_LEN]) -> bool {
        let ask = Message::Open {
            ticket,
            proof: [0; TOKEN_LEN],
        };
        sock.send_to(&ask.encode(), allocated).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let Ok(Ok((n, from))) =
            tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await
        else {
            return false;
        };
        let Some(Message::Confirm { proof }) = Message::decode(&buf[..n]) else {
            return false;
        };
        assert_eq!(from, allocated, "confirmed from somewhere else");
        sock.send_to(&Message::Open { ticket, proof }.encode(), allocated)
            .await
            .unwrap();
        // Let it land before anything is sent behind it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        true
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
            hints: NatHints::unknown(),
            id,
            token: [0; TOKEN_LEN],
            flags: 0,
            stamp: 0,
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
        register_raw(sock, relay, relay_id, identity, flags)
            .await
            .map(|(m, _)| m)
    }

    /// [`register`], also returning the exact bytes of the registration the
    /// relay accepted — what someone watching the wire would have.
    async fn register_raw(
        sock: &UdpSocket,
        relay: SocketAddr,
        relay_id: &SharpId,
        identity: &Identity,
        flags: u8,
    ) -> Option<(Message, Vec<u8>)> {
        register_hinted(sock, relay, relay_id, identity, flags, NatHints::unknown()).await
    }

    /// [`register_raw`], saying what the receiver's NAT does.
    async fn register_hinted(
        sock: &UdpSocket,
        relay: SocketAddr,
        relay_id: &SharpId,
        identity: &Identity,
        flags: u8,
        hints: NatHints,
    ) -> Option<(Message, Vec<u8>)> {
        let id = identity.id();
        let key = crate::relay::auth_key(identity, relay_id, &id, relay_id).unwrap();
        let mut token = [0u8; TOKEN_LEN];
        for _ in 0..2 {
            let msg = signed(
                &key,
                Message::Register {
                    hints,
                    id,
                    token,
                    flags,
                    stamp: stamp(),
                    proof: [0; crate::relay::PROOF_LEN],
                },
            );
            sock.send_to(&msg, relay).await.ok()?;
            match recv_message(sock, Duration::from_secs(2)).await? {
                Message::Challenge { token: t } => token = t,
                other => return Some((other, msg)),
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
                hints: NatHints::unknown(),
                id,
                token: [0; TOKEN_LEN],
                flags: 0,
                stamp: stamp(),
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
        let allocated = with_token(&sc, relay, |token| Message::Connect {
            target: id,
            token,
            hints: NatHints::unknown(),
        })
        .await;
        let Some(Message::Allocated {
            hints: _,
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
            hints: _,
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
        assert!(bind_side(&rd, allocated_addr, receiver_ticket).await);
        assert!(bind_side(&sd, allocated_addr, sender_ticket).await);

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
        // A wrong ticket does not bind a side either, nor draw so much as
        // a confirmation.
        assert!(!bind_side(&intruder, allocated_addr, [0xAB; TOKEN_LEN]).await);
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
        let answer = with_token(&sc, relay, |token| Message::Connect {
            target,
            token,
            hints: NatHints::unknown(),
        })
        .await;
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
                stamp: stamp(),
                proof: [0; crate::relay::PROOF_LEN],
            },
        );
        impostor.send_to(&forged, relay).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let still_there = with_token(&sc, relay, |token| Message::Connect {
            target: id,
            token,
            hints: NatHints::unknown(),
        })
        .await;
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
                stamp: stamp(),
                proof: [0; crate::relay::PROOF_LEN],
            },
        );
        rc.send_to(&bye, relay).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gone = with_token(&sc, relay, |token| Message::Connect {
            target: id,
            token,
            hints: NatHints::unknown(),
        })
        .await;
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
                    hints: NatHints::unknown(),
                    id,
                    token,
                    flags: 0,
                    stamp: stamp(),
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
        let answer = with_token(&sc, relay, |token| Message::Connect {
            target: id,
            token,
            hints: NatHints::unknown(),
        })
        .await;
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
                    hints: NatHints::unknown(),
                    id,
                    token,
                    flags: 0,
                    stamp: stamp(),
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
    /// A relay on a host with several addresses answers from the one it
    /// was asked at. Without that, the kernel picks whichever it likes for
    /// a socket bound to the wildcard, and a peer — or a firewall — that
    /// sent to another address discards the answer as nobody's reply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_answer_comes_from_the_address_the_question_went_to() {
        // A second address of this host: any of 127/8 on Linux and Windows;
        // macOS has only 127.0.0.1, and the test has nothing to show there.
        if UdpSocket::bind("127.0.0.2:0").await.is_err() {
            return;
        }
        let (relay, _relay_id, cancel) = start_relay_with(Config {
            bind: "0.0.0.0:0".parse().unwrap(),
            idle: Duration::from_secs(5),
            ..Config::default()
        })
        .await;
        let owner = Identity::generate();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for asked in ["127.0.0.2", "127.0.0.1"] {
            let to = SocketAddr::new(asked.parse().unwrap(), relay.port());
            let ask = Message::Register {
                hints: NatHints::unknown(),
                id: owner.id(),
                token: [0; TOKEN_LEN],
                flags: 0,
                stamp: 0,
                proof: [0; crate::relay::PROOF_LEN],
            };
            sock.send_to(&ask.encode(), to).await.unwrap();
            let mut buf = [0u8; 256];
            let (n, from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
                .await
                .expect("no answer")
                .unwrap();
            assert!(matches!(
                Message::decode(&buf[..n]),
                Some(Message::Challenge { .. })
            ));
            assert_eq!(from.ip(), to.ip(), "answered from the wrong address");
        }
        cancel.cancel();
    }

    /// What each side says of its NAT is what the other is told — the
    /// receiver's when it registered, the sender's when it asked — so that
    /// each can aim its punches. Unless the receiver asked not to be
    /// described: then nothing about it, or about who asks, is passed on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_side_is_told_what_the_others_nat_does() {
        use crate::nat::behaviour::Allocation;
        let receiver_hints = NatHints {
            mapping: 3,
            filtering: 3,
            allocation: Allocation::Sequential,
            delta: 2,
            ..NatHints::unknown()
        };
        let sender_hints = NatHints {
            mapping: 3,
            allocation: Allocation::Random,
            ..NatHints::unknown()
        };
        for private in [false, true] {
            let (relay, relay_id, cancel) = start_relay().await;
            let owner = Identity::generate();
            let id = owner.id();
            let rc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let flags = if private {
                crate::relay::REGISTER_PRIVATE
            } else {
                0
            };
            assert!(matches!(
                register_hinted(&rc, relay, &relay_id, &owner, flags, receiver_hints)
                    .await
                    .map(|(m, _)| m),
                Some(Message::Registered { .. })
            ));
            let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let answer = with_token(&sc, relay, |token| Message::Connect {
                target: id,
                token,
                hints: sender_hints,
            })
            .await;
            let Some(Message::Allocated { hints, .. }) = answer else {
                panic!("expected an allocation, got {:?}", answer);
            };
            let Some(Message::Incoming { hints: told, .. }) =
                recv_message(&rc, Duration::from_secs(2)).await
            else {
                panic!("the receiver was not introduced");
            };
            if private {
                assert_eq!(hints, NatHints::unknown());
                assert_eq!(told, NatHints::unknown());
            } else {
                assert_eq!(hints, receiver_hints);
                assert_eq!(told, sender_hints);
            }
            cancel.cancel();
        }
    }

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
        let answer = with_token(&sc, relay, |token| Message::Connect {
            target: id,
            token,
            hints: NatHints::unknown(),
        })
        .await;
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
            // A share of two ports per client.
            max_allocations: 8,
            allocations_per_client: 2,
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
        let Some(Message::Allocated { port, ticket, .. }) =
            with_token(&first, relay, |token| Message::Connect {
                target: id,
                token,
                hints: NatHints::unknown(),
            })
            .await
        else {
            panic!("the first sender got no port");
        };
        assert!(matches!(
            with_token(&second, relay, |token| Message::Connect {
                hints: NatHints::unknown(),
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
                hints: NatHints::unknown(),
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
            hints: NatHints::unknown(),
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

    /// Everything in a registration is bound to its owner, but until it
    /// carried a stamp nothing in it was bound to a moment: one captured
    /// on the wire could be sent again from the same address while its
    /// token lived — to turn a private registration public, or, sent after
    /// the owner had left and come back, to end the new registration with
    /// the old goodbye.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_old_message_sent_again_changes_nothing() {
        let (relay, relay_id, cancel) = start_relay().await;
        let owner = Identity::generate();
        let id = owner.id();
        let key = crate::relay::auth_key(&owner, &relay_id, &id, &relay_id).unwrap();
        let rc = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Public first, then private: the public one is what gets captured.
        let (first, public) = register_raw(&rc, relay, &relay_id, &owner, 0)
            .await
            .unwrap();
        assert!(matches!(first, Message::Registered { .. }));
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
        rc.send_to(&public, relay).await.unwrap();
        let answer = recv_message(&rc, Duration::from_secs(2)).await;
        assert!(
            matches!(
                answer,
                Some(Message::Error {
                    code: Refusal::Stale
                })
            ),
            "an old registration was taken again: {:?}",
            answer
        );
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let Some(Message::Allocated { peer, .. }) =
            with_token(&sc, relay, |token| Message::Connect {
                target: id,
                token,
                hints: NatHints::unknown(),
            })
            .await
        else {
            panic!("expected an allocation");
        };
        assert!(
            peer.ip().is_unspecified(),
            "a replayed registration made a private receiver public: {}",
            peer
        );
        // Drain the introduction that Connect caused.
        while recv_message(&rc, Duration::from_millis(200))
            .await
            .is_some()
        {}

        // The owner leaves...
        let token = token_for(&rc, relay, id).await;
        let bye = signed(
            &key,
            Message::Bye {
                id,
                token,
                stamp: stamp(),
                proof: [0; crate::relay::PROOF_LEN],
            },
        );
        rc.send_to(&bye, relay).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // ...and comes back from the same address.
        assert!(matches!(
            register(&rc, relay, &relay_id, &owner, 0).await,
            Some(Message::Registered { .. })
        ));
        // The goodbye, sent again, must not end what came after it.
        rc.send_to(&bye, relay).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let still = with_token(&sc, relay, |token| Message::Connect {
            target: id,
            token,
            hints: NatHints::unknown(),
        })
        .await;
        assert!(
            matches!(still, Some(Message::Allocated { .. })),
            "an old goodbye ended a newer registration: {:?}",
            still
        );
        // Nor may the old registration come back after the goodbye it
        // preceded: the relay remembers the identity's newest stamp even
        // once it is not registered.
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_, captured) = register_raw(&other, relay, &relay_id, &owner, 0)
            .await
            .unwrap();
        let token = token_for(&other, relay, id).await;
        let leave = signed(
            &key,
            Message::Bye {
                id,
                token,
                stamp: stamp(),
                proof: [0; crate::relay::PROOF_LEN],
            },
        );
        other.send_to(&leave, relay).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        other.send_to(&captured, relay).await.unwrap();
        let answer = loop {
            match recv_message(&other, Duration::from_secs(2)).await {
                Some(Message::Incoming { .. }) => continue,
                m => break m,
            }
        };
        assert!(
            matches!(
                answer,
                Some(Message::Error {
                    code: Refusal::Stale
                })
            ),
            "a registration from before a goodbye was taken after it: {:?}",
            answer
        );
        cancel.cancel();
    }

    /// The owner keeps its last token until it leaves, and by then the
    /// token may have expired. The relay says so with a fresh one instead
    /// of dropping the goodbye, which left the registration standing for
    /// the rest of its lease.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_goodbye_with_a_stale_token_is_asked_again() {
        let (relay, relay_id, cancel) = start_relay().await;
        let owner = Identity::generate();
        let id = owner.id();
        let rc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            register(&rc, relay, &relay_id, &owner, 0).await,
            Some(Message::Registered { .. })
        ));
        let key = crate::relay::auth_key(&owner, &relay_id, &id, &relay_id).unwrap();
        let bye = |token| {
            signed(
                &key,
                Message::Bye {
                    id,
                    token,
                    stamp: stamp(),
                    proof: [0; crate::relay::PROOF_LEN],
                },
            )
        };
        rc.send_to(&bye([0x55; TOKEN_LEN]), relay).await.unwrap();
        let Some(Message::Challenge { token }) = recv_message(&rc, Duration::from_secs(2)).await
        else {
            panic!("a goodbye with a stale token was dropped without a word");
        };
        rc.send_to(&bye(token), relay).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gone = with_token(&sc, relay, |token| Message::Connect {
            target: id,
            token,
            hints: NatHints::unknown(),
        })
        .await;
        assert!(matches!(
            gone,
            Some(Message::Error {
                code: Refusal::Unknown
            })
        ));
        cancel.cancel();
    }

    /// An Open binds a side only once the address it came from has shown it
    /// receives there. An address that never answers the confirmation —
    /// which is what a forged source is, and what one of the relay's own
    /// ports would be — is carried nothing; and the confirmation for one
    /// side does not bind the other.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_an_address_that_answers_its_confirmation_is_bound() {
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
        }) = with_token(&sc, relay, |token| Message::Connect {
            target: id,
            token,
            hints: NatHints::unknown(),
        })
        .await
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
        let allocated = SocketAddr::new(relay.ip(), port);
        let rd = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sd = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(bind_side(&rd, allocated, receiver_ticket).await);

        // The sender's side says which it is, but never answers.
        let mut buf = vec![0u8; 2048];
        sd.send_to(
            &Message::Open {
                ticket: sender_ticket,
                proof: [0; TOKEN_LEN],
            }
            .encode(),
            allocated,
        )
        .await
        .unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), sd.recv_from(&mut buf))
            .await
            .expect("a confirmation")
            .unwrap();
        let Some(Message::Confirm { proof }) = Message::decode(&buf[..n]) else {
            panic!("expected a confirmation");
        };
        rd.send_to(b"to nobody yet", allocated).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), sd.recv_from(&mut buf))
                .await
                .is_err(),
            "a side was bound on its say-so alone"
        );
        // The sender's confirmation is no good for the receiver's ticket.
        sd.send_to(
            &Message::Open {
                ticket: receiver_ticket,
                proof,
            }
            .encode(),
            allocated,
        )
        .await
        .unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), sd.recv_from(&mut buf))
            .await
            .expect("asked to confirm instead")
            .unwrap();
        assert!(matches!(
            Message::decode(&buf[..n]),
            Some(Message::Confirm { .. })
        ));
        // Answered properly, it is bound, and traffic flows.
        sd.send_to(
            &Message::Open {
                ticket: sender_ticket,
                proof,
            }
            .encode(),
            allocated,
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        rd.send_to(b"now", allocated).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), sd.recv_from(&mut buf))
            .await
            .expect("carried once confirmed")
            .unwrap();
        assert_eq!(&buf[..n], b"now");
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
        }) = with_token(&sc, relay, |token| Message::Connect {
            target: id,
            token,
            hints: NatHints::unknown(),
        })
        .await
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

        // One socket presents both tickets, answering both confirmations.
        let both = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let allocated = SocketAddr::new(relay.ip(), port);
        for ticket in [sender_ticket, receiver_ticket] {
            assert!(bind_side(&both, allocated, ticket).await);
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

    /// A relay run for one's own receivers registers those and nobody else
    /// — and says so only to an identity that has proven itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_with_a_list_registers_only_those_on_it() {
        let ours = Identity::generate();
        let stranger = Identity::generate();
        let (relay, relay_id, cancel) = start_relay_with(Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_receivers: Some([ours.id()].into_iter().collect()),
            ..Config::default()
        })
        .await;
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            register(&a, relay, &relay_id, &ours, 0).await,
            Some(Message::Registered { .. })
        ));
        assert_eq!(
            register(&b, relay, &relay_id, &stranger, 0).await,
            Some(Message::Error {
                code: Refusal::Forbidden
            })
        );
        // Without the proof, not even that much is said.
        let unproven = with_token(&b, relay, |token| Message::Register {
            hints: NatHints::unknown(),
            id: ours.id(),
            token,
            flags: 0,
            stamp: stamp(),
            proof: [0; crate::relay::PROOF_LEN],
        })
        .await;
        assert_eq!(
            unproven,
            Some(Message::Error {
                code: Refusal::BadToken
            })
        );
        cancel.cancel();
    }

    /// A relay with a list of senders turns a stranger's plain request
    /// away, puts through a listed sender that proves who it is, and not
    /// one that only says so.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_with_a_list_of_senders_wants_to_know_who_asks() {
        let receiver = Identity::generate();
        let listed = Identity::generate();
        let other = Identity::generate();
        let (relay, relay_id, cancel) = start_relay_with(Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_senders: Some([listed.id()].into_iter().collect()),
            ..Config::default()
        })
        .await;
        let rc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            register(&rc, relay, &relay_id, &receiver, 0).await,
            Some(Message::Registered { .. })
        ));
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let plain = with_token(&sc, relay, |token| Message::Connect {
            hints: NatHints::unknown(),
            target: receiver.id(),
            token,
        })
        .await;
        assert_eq!(
            plain,
            Some(Message::Error {
                code: Refusal::Forbidden
            })
        );
        let token = token_for(&sc, relay, receiver.id()).await;
        let as_who = |who: &Identity, prover: &Identity| {
            let key = crate::relay::auth_key(prover, &relay_id, &prover.id(), &relay_id).unwrap();
            signed(
                &key,
                Message::ConnectAs {
                    hints: NatHints::unknown(),
                    target: receiver.id(),
                    token,
                    id: who.id(),
                    proof: [0; crate::relay::PROOF_LEN],
                },
            )
        };
        // Someone else claiming the listed identity cannot make its proof.
        sc.send_to(&as_who(&listed, &other), relay).await.unwrap();
        assert_eq!(
            recv_message(&sc, Duration::from_secs(2)).await,
            Some(Message::Error {
                code: Refusal::BadToken
            })
        );
        // Proven, but not listed.
        sc.send_to(&as_who(&other, &other), relay).await.unwrap();
        assert_eq!(
            recv_message(&sc, Duration::from_secs(2)).await,
            Some(Message::Error {
                code: Refusal::Forbidden
            })
        );
        // Proven and listed.
        sc.send_to(&as_who(&listed, &listed), relay).await.unwrap();
        assert!(matches!(
            recv_message(&sc, Duration::from_secs(2)).await,
            Some(Message::Allocated { .. })
        ));
        cancel.cancel();
    }

    fn at(t0: Instant, ms: u64) -> Instant {
        t0 + Duration::from_millis(ms)
    }

    /// A client gets its rate and no more; what it did not spend comes
    /// back with time; another client is counted on its own.
    #[test]
    fn a_client_is_carried_at_its_rate() {
        let mut m = Meter::new(Quotas {
            client_rate: 1_000_000,
            ..Quotas::default()
        });
        let a: SocketAddr = "198.51.100.1:1000".parse().unwrap();
        let b: SocketAddr = "198.51.100.2:1000".parse().unwrap();
        let t0 = Instant::now();
        // The burst is a quarter of a second's worth.
        let mut carried = 0;
        while m.allow(a, 1000, t0) {
            carried += 1000;
        }
        assert_eq!(carried, 250_000);
        assert!(m.allow(b, 1000, t0), "another client pays for the first");
        // A tenth of a second later, a tenth of a second's worth.
        let mut later = 0;
        while m.allow(a, 1000, at(t0, 100)) {
            later += 1000;
        }
        assert_eq!(later, 100_000);
        // The same client from another port, or elsewhere in its IPv6 /64,
        // is the same client.
        assert!(!m.allow("198.51.100.1:2000".parse().unwrap(), 1000, at(t0, 100)));
        assert!(m.refused >= 2);
    }

    /// The hourly quota is a bucket of the whole hour's allowance.
    #[test]
    fn an_hourly_quota_runs_out_and_comes_back() {
        let mut m = Meter::new(Quotas {
            client_rate: 0,
            client_hourly: 3_600_000,
            ..Quotas::default()
        });
        let a: SocketAddr = "[2001:db8::1]:1000".parse().unwrap();
        let same_64: SocketAddr = "[2001:db8::ffff]:1".parse().unwrap();
        let t0 = Instant::now();
        assert!(m.allow(a, 3_000_000, t0));
        assert!(!m.allow(same_64, 1_000_000, t0), "one /64 is one client");
        assert!(m.allow(same_64, 600_000, t0));
        assert!(!m.allow(a, 1, t0));
        // A thousand bytes a second come back.
        assert!(m.allow(a, 10_000, at(t0, 10_000)));
    }

    /// The relay's own limit counts everybody together, and a datagram one
    /// limit refuses costs nothing against the others.
    #[test]
    fn the_total_limit_counts_everybody_and_refusals_cost_nothing() {
        let mut m = Meter::new(Quotas {
            client_rate: 400_000,
            total_rate: 400_000,
            ..Quotas::default()
        });
        let t0 = Instant::now();
        let a: SocketAddr = "198.51.100.1:1".parse().unwrap();
        let b: SocketAddr = "198.51.100.2:1".parse().unwrap();
        // The total burst (100 KB) is shared.
        assert!(m.allow(a, 60_000, t0));
        assert!(!m.allow(b, 60_000, t0), "over the total");
        // b's refusal took nothing from b's own budget.
        assert!(m.allow(b, 40_000, t0));
        assert!(!m.allow(a, 1, t0));
    }

    /// No limits configured: nothing is tracked, and everything passes.
    #[test]
    fn without_limits_nothing_is_tracked() {
        let mut m = Meter::new(Quotas {
            client_rate: 0,
            client_hourly: 0,
            total_rate: 0,
            pair_bytes: 0,
        });
        let t0 = Instant::now();
        for i in 0..1000u32 {
            let from = SocketAddr::new(std::net::Ipv4Addr::from(0xc633_6400 + i).into(), 1);
            assert!(m.allow(from, 1 << 20, t0));
        }
        assert!(m.clients.is_empty());
    }
}
