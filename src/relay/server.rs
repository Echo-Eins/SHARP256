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
use crate::crypto::SharpId;
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

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:5560".parse().expect("valid address"),
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
}

/// A port carrying one pair, and what it knows about the two sides.
struct Allocation {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

/// Which side of an allocation a ticket names, and where that side is.
#[derive(Default)]
struct Sides {
    a: Option<SocketAddr>,
    b: Option<SocketAddr>,
}

/// A running relay.
pub struct Relay {
    socket: Arc<UdpSocket>,
    cfg: Config,
    cancel: CancellationToken,
    tokens: TokenJar,
    registrations: HashMap<SharpId, Registration>,
    allocations: Vec<Allocation>,
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
            cfg,
            cancel,
            tokens: TokenJar::new(),
            registrations: HashMap::new(),
            allocations: Vec::new(),
            limiter: RateLimiter::new(cfg_rate, cfg_burst),
            last_prune: now,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Serves until cancelled.
    pub async fn run(mut self) -> io::Result<()> {
        tracing::info!("relay listening on {}", self.socket.local_addr()?);
        let socket = self.socket.clone();
        let cancel = self.cancel.clone();
        let mut buf = vec![0u8; BUF_LEN];
        loop {
            tokio::select! {
                r = socket.recv_from(&mut buf) => {
                    let Ok((n, from)) = r else { continue };
                    let now = Instant::now();
                    self.prune(now);
                    // Anything that is not a control message on the control
                    // port is not ours; the relay never answers it, so it
                    // cannot be used to probe for one.
                    let Some(msg) = Message::decode(&buf[..n]) else { continue };
                    if !self.limiter.allow(from, now) {
                        continue;
                    }
                    self.on_message(msg, from, now).await;
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

    async fn on_message(&mut self, msg: Message, from: SocketAddr, now: Instant) {
        match msg {
            Message::Register { id, token } => {
                // An unproven address gets a token and nothing else: a
                // registration from a forged source would otherwise point
                // this relay's traffic at somebody who never asked for it.
                if !self.tokens.accepts(&token, from, now) {
                    let token = self.tokens.issue(from, now);
                    self.reply(from, Message::Challenge { token }).await;
                    return;
                }
                let known = self.registrations.contains_key(&id);
                if !known && self.registrations.len() >= self.cfg.max_registrations {
                    self.reply(
                        from,
                        Message::Error {
                            code: Refusal::Busy,
                        },
                    )
                    .await;
                    return;
                }
                self.registrations.insert(
                    id,
                    Registration {
                        addr: from,
                        expires: now + self.cfg.lease,
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
                if self.allocations.len() >= self.cfg.max_allocations {
                    self.reply(
                        from,
                        Message::Error {
                            code: Refusal::Busy,
                        },
                    )
                    .await;
                    return;
                }
                match self.allocate(from, receiver, now).await {
                    Some((port, sender_ticket, receiver_ticket)) => {
                        // Each side is told where the other appears to be,
                        // so they can try a direct path first and leave the
                        // relay carrying nothing.
                        self.reply(
                            from,
                            Message::Allocated {
                                port,
                                peer: receiver,
                                ticket: sender_ticket,
                            },
                        )
                        .await;
                        self.reply(
                            receiver,
                            Message::Incoming {
                                port,
                                peer: from,
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

    /// Sets a port aside for one pair and starts carrying it.
    async fn allocate(
        &mut self,
        sender: SocketAddr,
        receiver: SocketAddr,
        now: Instant,
    ) -> Option<(u16, [u8; TOKEN_LEN], [u8; TOKEN_LEN])> {
        let bind = SocketAddr::new(self.cfg.bind.ip(), 0);
        let sock = Arc::new(UdpSocket::bind(bind).await.ok()?);
        let port = sock.local_addr().ok()?.port();
        let sender_ticket = random_token();
        let receiver_ticket = random_token();
        let idle = self.cfg.idle;
        // The addresses the two sides will use here are very likely *not*
        // the ones they used on the control port: the NAT this relay exists
        // to get around is the kind that hands out a different port for
        // every destination. So each side says who it is with its ticket,
        // and the relay learns the address from that.
        let hint = Sides {
            a: Some(sender),
            b: Some(receiver),
        };
        let task = tokio::spawn(carry(
            sock,
            sender_ticket,
            receiver_ticket,
            hint,
            idle,
            self.cancel.clone(),
        ));
        let _ = now;
        self.allocations.push(Allocation { port, task });
        Some((port, sender_ticket, receiver_ticket))
    }

    fn prune(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_prune) < Duration::from_secs(5) {
            return;
        }
        self.last_prune = now;
        self.registrations.retain(|_, r| r.expires > now);
        self.allocations.retain(|a| {
            if a.task.is_finished() {
                tracing::debug!("relay: port {} released", a.port);
                return false;
            }
            true
        });
        self.limiter.prune(now);
    }
}

/// Copies datagrams between the two sides of one allocation.
///
/// Each side binds itself by presenting its ticket, which is also what opens
/// the way back through its NAT. Until a side has done that, nothing is sent
/// to it; afterwards, only datagrams from the two bound addresses are
/// carried, so knowing the port is not enough to join in.
async fn carry(
    sock: Arc<UdpSocket>,
    ticket_a: [u8; TOKEN_LEN],
    ticket_b: [u8; TOKEN_LEN],
    hint: Sides,
    idle: Duration,
    cancel: CancellationToken,
) {
    let mut a: Option<SocketAddr> = None;
    let mut b: Option<SocketAddr> = None;
    let mut buf = vec![0u8; BUF_LEN];
    let mut last = Instant::now();
    loop {
        let quiet = idle.saturating_sub(Instant::now().saturating_duration_since(last));
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let Ok((n, from)) = r else { return };
                let pkt = &buf[..n];
                if is_control(pkt) {
                    // A side saying which one it is. The address it comes
                    // from is the one to use, whatever the control port saw.
                    if let Some(Message::Open { ticket }) = Message::decode(pkt) {
                        if constant_time_eq(&ticket, &ticket_a) {
                            a = Some(from);
                        } else if constant_time_eq(&ticket, &ticket_b) {
                            b = Some(from);
                        } else {
                            continue;
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
            _ = tokio::time::sleep(quiet) => {
                if Instant::now().saturating_duration_since(last) >= idle {
                    tracing::debug!(
                        "relay: allocation idle for {:?}; releasing (sides {:?} {:?}, hinted {:?} {:?})",
                        idle, a, b, hint.a, hint.b
                    );
                    return;
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

    async fn start_relay() -> (SocketAddr, CancellationToken) {
        let cancel = CancellationToken::new();
        let cfg = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            idle: Duration::from_secs(5),
            ..Config::default()
        };
        let relay = Relay::bind(cfg, cancel.clone()).await.expect("binds");
        let addr = relay.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = relay.run().await;
        });
        (addr, cancel)
    }

    /// The addresses a pair uses on an allocated port are not the ones the
    /// control port saw — a NAT that gives out a port per destination is
    /// exactly what a relay is for. So each side says which one it is with
    /// the ticket it was given, and that is what binds it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_side_binds_itself_with_its_ticket_from_wherever_it_is() {
        let (relay, cancel) = start_relay().await;
        let id = Identity::generate().id();

        // The two control sockets: as far as the relay can see, this is
        // where the peers are.
        let rc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sc = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // A registration is only accepted once it echoes a token bound to
        // the address the relay saw, so a forged source gets nowhere.
        let first = ask(
            &rc,
            relay,
            Message::Register {
                id,
                token: [0; TOKEN_LEN],
            },
        )
        .await;
        assert!(matches!(first, Some(Message::Challenge { .. })));
        let registered = with_token(&rc, relay, |token| Message::Register { id, token }).await;
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
        let (relay, cancel) = start_relay().await;
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
        let (relay, cancel) = start_relay().await;
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
}
