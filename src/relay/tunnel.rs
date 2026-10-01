//! A relay over a stream (see `transport::carrier`), for a client — sender
//! or receiver — whose network lets no UDP through to it.
//!
//! The stream carries what would have gone to the relay's ports over UDP,
//! each frame tagged with its port: 0 for the control port, a pair's own
//! port for the pair. The relay takes what arrives as if it had come over
//! UDP from the address the stream comes from — its tokens, its limits per
//! client and its pairs work unchanged — and what it sends to that address
//! goes back on the stream, tagged with the port it is from.
//!
//! On the client's side the relay is known by its address with port 0 for
//! the control port, and by its port for a pair (see
//! [`crate::relay::client::Via::Stream`]): what the relay says goes to the
//! conversation with it, and what its pairs carry goes to the engine (a
//! sender's, through a shim per port) or to the dispatcher (a receiver's, as
//! if the relay's port had sent it).

use crate::address::canonical;
use crate::relay::client::{Incoming, Via};
use crate::transport::carrier::frame::{self, Frame, Kind, PREAMBLE_LEN};
use crate::transport::carrier::link::{self, Link};
use crate::transport::carrier::listen::client_of;
use crate::transport::carrier::shim::{Shim, Shims};
use crate::transport::carrier::Streams;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// How long a stream, and then the relay's preamble, may take.
const CONNECT_WAIT: Duration = Duration::from_secs(5);
/// Streams a relay holds at once, and from one client (an IPv4 address, an
/// IPv6 /64).
const MAX_TUNNELS: usize = 256;
const PER_CLIENT: usize = 8;
/// A stream that carries nothing this long is closed. A receiver's
/// registration is refreshed well within it.
const IDLE: Duration = Duration::from_secs(120);
/// What the relay's loop and each pair hold of what comes on streams.
const INBOUND: usize = 1024;

// ---------------------------------------------------------------------------
// The client's side
// ---------------------------------------------------------------------------

/// A stream to the relay at `relay`, its preamble answered, from `local`'s
/// address when the transfer socket is bound to one.
pub async fn dial(relay: SocketAddr, local: SocketAddr) -> io::Result<TcpStream> {
    let relay = canonical(relay);
    let socket = if relay.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    let ip = canonical(local).ip();
    if !ip.is_unspecified() && ip.is_ipv4() == relay.is_ipv4() {
        socket.bind(SocketAddr::new(ip, 0))?;
    }
    let mut stream = tokio::time::timeout(CONNECT_WAIT, socket.connect(relay))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer"))??;
    stream.set_nodelay(true)?;
    opened(&mut stream).await?;
    Ok(stream)
}

/// A stream to a relay: plain TCP, or TLS over it.
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

/// The TLS session to a relay is not the relay's own: something on the way
/// ended the client's and opened another (see `relay::tls`).
#[derive(Debug)]
pub struct Intercepted;

impl std::fmt::Display for Intercepted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the TLS session is not the relay's own: something on the way opened it \
             (a TLS-inspecting proxy?), so it is not used",
        )
    }
}

impl std::error::Error for Intercepted {}

/// Whether `e` says a TLS session was opened on the way.
pub fn is_intercepted(e: &io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.downcast_ref::<Intercepted>().is_some())
}

/// Where a relay takes TLS, and what it is: its port (on each of its
/// addresses), the name to give it, and its identity, which the TLS
/// session is bound to (see `relay::tls`).
#[cfg(feature = "tls")]
#[derive(Clone)]
pub struct TlsTo {
    pub port: u16,
    pub name: rustls::pki_types::ServerName<'static>,
    pub relay: crate::crypto::SharpId,
}

/// Built without TLS (the `tls` feature): no relay is reached over it.
#[cfg(not(feature = "tls"))]
#[derive(Clone)]
pub enum TlsTo {}

#[cfg(not(feature = "tls"))]
impl TlsTo {
    pub fn new(_host: &str, _relay: Option<crate::crypto::SharpId>, _port: u16) -> Option<Self> {
        None
    }

    pub fn port(&self) -> u16 {
        match *self {}
    }
}

#[cfg(not(feature = "tls"))]
async fn dial_tls(_at: SocketAddr, to: &TlsTo, _local: SocketAddr) -> io::Result<Box<dyn Stream>> {
    match *to {}
}

#[cfg(feature = "tls")]
impl TlsTo {
    /// For a relay written `host:port` with its identity known (the session
    /// is bound to it; a relay known only by address is not reached over
    /// TLS), taking TLS on `port`.
    pub fn new(host: &str, relay: Option<crate::crypto::SharpId>, port: u16) -> Option<Self> {
        let relay = relay?;
        let (h, _) = crate::address::dns::split_host_port(host).ok()?;
        let name = rustls::pki_types::ServerName::try_from(h.to_string()).ok()?;
        Some(Self { port, name, relay })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A TLS stream to the relay at `at`, the session proven its own.
#[cfg(feature = "tls")]
pub async fn dial_tls(
    at: SocketAddr,
    to: &TlsTo,
    local: SocketAddr,
) -> io::Result<Box<dyn Stream>> {
    let at = canonical(at);
    let socket = if at.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    let ip = canonical(local).ip();
    if !ip.is_unspecified() && ip.is_ipv4() == at.is_ipv4() {
        socket.bind(SocketAddr::new(ip, 0))?;
    }
    let tcp = tokio::time::timeout(CONNECT_WAIT, socket.connect(at))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer"))??;
    tcp.set_nodelay(true)?;
    let connector = tokio_rustls::TlsConnector::from(super::tls::client_config()?);
    let mut tls = tokio::time::timeout(CONNECT_WAIT, connector.connect(to.name.clone(), tcp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no TLS answer"))??;
    opened(&mut tls).await?;
    super::tls::bind(&mut tls, &to.relay).await?;
    Ok(Box::new(tls))
}

/// Why a relay was not reached over a stream.
#[derive(Debug)]
pub enum Unreached {
    /// A TLS session to it was opened on the way: refused, and to be said.
    Intercepted(String),
    /// Nothing answered, or not as a relay.
    Failed(String),
}

impl std::fmt::Display for Unreached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unreached::Intercepted(why) | Unreached::Failed(why) => f.write_str(why),
        }
    }
}

/// A stream to the relay at the first of `addrs` that takes one: plain TCP
/// at each address's own port, and — a quarter of a second later, as RFC
/// 8305 staggers attempts — TLS at `tls`'s, where the relay is known well
/// enough to bind the session to. The first up wins.
pub async fn reach(
    addrs: &[SocketAddr],
    tls: Option<&TlsTo>,
    local: SocketAddr,
) -> Result<(SocketAddr, Box<dyn Stream>), Unreached> {
    let mut attempts = tokio::task::JoinSet::new();
    let mut plan: Vec<(SocketAddr, bool)> = Vec::new();
    for &a in addrs {
        plan.push((a, false));
        if let Some(t) = tls {
            plan.push((SocketAddr::new(a.ip(), t.port()), true));
        }
    }
    let mut next = 0;
    let mut why: Vec<String> = Vec::new();
    let mut intercepted = false;
    loop {
        if next < plan.len() {
            let (at, over_tls) = plan[next];
            next += 1;
            let tls = tls.cloned();
            attempts.spawn(async move {
                let r = match (over_tls, &tls) {
                    (true, Some(t)) => dial_tls(at, t, local).await,
                    _ => dial(at, local)
                        .await
                        .map(|s| Box::new(s) as Box<dyn Stream>),
                };
                (at, over_tls, r)
            });
        }
        let wait = async {
            if next < plan.len() {
                tokio::time::sleep(Duration::from_millis(250)).await
            } else {
                std::future::pending::<()>().await
            }
        };
        tokio::select! {
            done = attempts.join_next() => match done {
                Some(Ok((at, _, Ok(stream)))) => return Ok((at, stream)),
                Some(Ok((at, over_tls, Err(e)))) => {
                    if is_intercepted(&e) {
                        intercepted = true;
                    }
                    why.push(format!("{} {}: {}", if over_tls { "TLS at" } else { "TCP at" }, at, e));
                }
                Some(Err(_)) => {}
                None if next >= plan.len() => {
                    let why = why.join("; ");
                    return Err(if intercepted {
                        Unreached::Intercepted(why)
                    } else {
                        Unreached::Failed(why)
                    });
                }
                None => {}
            },
            _ = wait => {}
        }
    }
}

/// Says a stream leads to a relay, and waits for the relay to say so too.
pub async fn opened<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> io::Result<()> {
    stream.write_all(&frame::preamble(Kind::Relay)).await?;
    let mut p = [0u8; PREAMBLE_LEN];
    tokio::time::timeout(CONNECT_WAIT, stream.read_exact(&mut p))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no SHARP-256 relay there"))??;
    if frame::parse_preamble(&p) != Some(Kind::Relay) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SHARP-256 relay",
        ));
    }
    Ok(())
}

/// Where a client's stream puts what the relay's pairs carry.
#[derive(Clone)]
pub enum Pairs {
    /// A sender's: to the engine, through a shim per port, made when the
    /// port is attached ([`ClientTunnel::attach`]).
    Engine,
    /// A receiver's: to its dispatcher, as if the relay's port had sent it
    /// over UDP, and what goes back to that port, onto the stream.
    Dispatcher(Arc<Streams>),
}

/// A client's stream to its relay.
pub struct ClientTunnel {
    link: Link,
    /// The relay as the conversation over the stream knows it: its address,
    /// with port 0 for the control port.
    relay: SocketAddr,
    socket: Arc<UdpSocket>,
    shims: Arc<parking_lot::Mutex<HashMap<u16, Arc<Shim>>>>,
}

impl ClientTunnel {
    /// Runs `stream`, to the relay at `remote`, for a client whose transfer
    /// socket is `socket`. What the relay says comes out of the channel
    /// returned, from its port; what its pairs carry goes to `pairs`.
    pub fn open<S>(
        stream: S,
        remote: SocketAddr,
        socket: Arc<UdpSocket>,
        pairs: Pairs,
        cancel: CancellationToken,
    ) -> (Self, mpsc::Receiver<Incoming>)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let ip = canonical(remote).ip();
        let (control_tx, control_rx) = mpsc::channel(64);
        let shims: Arc<parking_lot::Mutex<HashMap<u16, Arc<Shim>>>> = Default::default();
        let cell: Arc<OnceLock<Link>> = Arc::new(OnceLock::new());
        let (to_shims, to_link) = (shims.clone(), cell.clone());
        let link = link::run(
            stream,
            move |f| {
                let (control, shims, cell, pairs) = (
                    control_tx.clone(),
                    to_shims.clone(),
                    to_link.clone(),
                    pairs.clone(),
                );
                async move {
                    let Frame::Datagram { port, data } = f else {
                        return;
                    };
                    let from = SocketAddr::new(ip, port);
                    // The relay's own word, from its control port or a
                    // pair's (a confirmation): to the conversation.
                    if crate::relay::is_control(&data) {
                        let _ = control.send((data, from)).await;
                        return;
                    }
                    // Nothing but the relay's word comes from its control port.
                    if port == 0 {
                        return;
                    }
                    match pairs {
                        Pairs::Engine => {
                            let shim = shims.lock().get(&port).cloned();
                            if let Some(shim) = shim {
                                shim.deliver(&data);
                            }
                        }
                        Pairs::Dispatcher(streams) => {
                            if !streams.contains(from) {
                                if let Some(link) = cell.get() {
                                    streams.route(from, link.clone(), port);
                                }
                            }
                            streams.deliver(data, from).await;
                        }
                    }
                }
            },
            cancel,
        );
        let _ = cell.set(link.clone());
        (
            Self {
                link,
                relay: SocketAddr::new(ip, 0),
                socket,
                shims,
            },
            control_rx,
        )
    }

    /// How the conversation with the relay reaches it.
    pub fn via(&self) -> Via {
        Via::Stream {
            link: self.link.clone(),
            socket: self.socket.clone(),
        }
    }

    /// The relay, as that conversation knows it.
    pub fn relay(&self) -> SocketAddr {
        self.relay
    }

    pub fn link(&self) -> &Link {
        &self.link
    }

    /// A sender's way to the pair on `port`: a shim, joined to the engine at
    /// `engine` and counted among `shims`, whose address the engine sends to.
    pub fn attach(&self, port: u16, engine: SocketAddr, shims: &Shims) -> io::Result<SocketAddr> {
        let shim = Shim::open(engine)?;
        self.shims.lock().insert(port, shim.clone());
        let addr = shim.addr();
        shim.pump(shims, self.link.clone(), port);
        Ok(addr)
    }
}

// ---------------------------------------------------------------------------
// The relay's side
// ---------------------------------------------------------------------------

/// Where what comes on streams for one of the relay's ports goes, with the
/// address of the stream it came on.
type Inbox = mpsc::Sender<(Vec<u8>, SocketAddr)>;

/// The streams a relay holds, and where what comes on them goes.
pub struct Tunnels {
    /// Whether there is anything to look up: sending is the hot path.
    active: AtomicBool,
    links: parking_lot::RwLock<HashMap<SocketAddr, Link>>,
    /// What comes on port 0, for the relay's loop.
    control: Inbox,
    /// What comes on each pair's port, for the pair.
    pairs: parking_lot::Mutex<HashMap<u16, Inbox>>,
}

impl Tunnels {
    /// The table, and where what comes on its streams for the control port
    /// comes out.
    pub fn new() -> (Arc<Self>, mpsc::Receiver<(Vec<u8>, SocketAddr)>) {
        let (control, rx) = mpsc::channel(INBOUND);
        (
            Arc::new(Self {
                active: AtomicBool::new(false),
                links: parking_lot::RwLock::new(HashMap::new()),
                control,
                pairs: parking_lot::Mutex::new(HashMap::new()),
            }),
            rx,
        )
    }

    /// Sends `datagram` to `to` on its stream, as from the relay's `port`,
    /// if `to` holds one: `None` when it does not, and whether the stream
    /// took it when it does.
    pub fn send(&self, to: SocketAddr, port: u16, datagram: &[u8]) -> Option<bool> {
        if !self.active.load(Ordering::Relaxed) {
            return None;
        }
        let links = self.links.read();
        let link = links.get(&canonical(to))?;
        Some(link.send(port, datagram))
    }

    /// Whether `addr` reaches the relay over a stream.
    pub fn contains(&self, addr: SocketAddr) -> bool {
        self.active.load(Ordering::Relaxed) && self.links.read().contains_key(&canonical(addr))
    }

    /// A pair's port: what comes for it on a stream comes out of the
    /// channel returned, from the address the stream comes from.
    pub fn open_pair(&self, port: u16) -> mpsc::Receiver<(Vec<u8>, SocketAddr)> {
        let (tx, rx) = mpsc::channel(INBOUND);
        self.pairs.lock().insert(port, tx);
        rx
    }

    pub fn close_pair(&self, port: u16) {
        self.pairs.lock().remove(&port);
    }

    fn add(&self, addr: SocketAddr, link: Link) {
        self.links.write().insert(canonical(addr), link);
        self.active.store(true, Ordering::Relaxed);
    }

    fn remove(&self, addr: SocketAddr, link: &Link) {
        let mut links = self.links.write();
        let addr = canonical(addr);
        if links
            .get(&addr)
            .is_some_and(|l| Arc::ptr_eq(l.stats(), link.stats()))
        {
            links.remove(&addr);
        }
        self.active.store(!links.is_empty(), Ordering::Relaxed);
    }

    /// Hands what came on a stream from `from` for `port` on: the control
    /// port's to the relay's loop, a pair's to the pair, waiting while
    /// either is behind (the stream holds still meanwhile). What is for no
    /// port of ours is dropped.
    async fn deliver(&self, port: u16, data: Vec<u8>, from: SocketAddr) {
        let to = if port == 0 {
            Some(self.control.clone())
        } else {
            self.pairs.lock().get(&port).cloned()
        };
        if let Some(to) = to {
            let _ = to.send((data, from)).await;
        }
    }
}

/// A TCP listener at the relay's own address and port: for a wildcard IPv6
/// address, one that takes IPv4 too exactly when `dual_stack`.
pub fn bind(addr: SocketAddr, dual_stack: bool) -> io::Result<TcpListener> {
    crate::transport::carrier::listen::bind(addr, dual_stack)
}

#[derive(Default)]
struct Held {
    total: usize,
    per_client: HashMap<IpAddr, usize>,
}

/// What a relay speaks TLS with, and the identity it proves sessions by.
#[cfg(feature = "tls")]
pub type Tls = (tokio_rustls::TlsAcceptor, crate::crypto::Identity);
/// Built without TLS: nothing to speak it with.
#[cfg(not(feature = "tls"))]
pub enum Tls {}

/// Accepts streams to the relay on `listener` until `cancel` fires: TLS
/// streams when `tls` is given, each session proven the relay's own.
pub async fn serve(
    listener: TcpListener,
    tunnels: Arc<Tunnels>,
    tls: Option<Tls>,
    cancel: CancellationToken,
) {
    let tls = tls.map(Arc::new);
    let held = Arc::new(parking_lot::Mutex::new(Held::default()));
    let mut failures = 0u32;
    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(v) => {
                    failures = 0;
                    v
                }
                Err(e) => {
                    failures = failures.saturating_add(1);
                    if failures.is_power_of_two() {
                        tracing::debug!("relay: accept failed: {}", e);
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(50 * failures.min(20) as u64)) => {}
                        _ = cancel.cancelled() => return,
                    }
                    continue;
                }
            },
            _ = cancel.cancelled() => return,
        };
        let client = client_of(peer.ip());
        {
            let mut h = held.lock();
            let mine = h.per_client.get(&client).copied().unwrap_or(0);
            if h.total >= MAX_TUNNELS || mine >= PER_CLIENT {
                tracing::debug!("relay: refusing a stream from {}: too many", peer);
                continue;
            }
            h.total += 1;
            *h.per_client.entry(client).or_insert(0) += 1;
        }
        let (tunnels, cancel, held, tls) = (
            tunnels.clone(),
            cancel.child_token(),
            held.clone(),
            tls.clone(),
        );
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            match &tls {
                None => take(stream, peer, &tunnels, cancel).await,
                #[cfg(not(feature = "tls"))]
                Some(tls) => match **tls {},
                #[cfg(feature = "tls")]
                Some(tls) => {
                    let (acceptor, identity) = &**tls;
                    let opened = tokio::time::timeout(CONNECT_WAIT, acceptor.accept(stream)).await;
                    if let Ok(Ok(mut s)) = opened {
                        if accept(&mut s).await && super::tls::prove(&mut s, identity).await.is_ok()
                        {
                            run(s, peer, &tunnels, cancel).await;
                        }
                    }
                }
            }
            let mut h = held.lock();
            h.total -= 1;
            if let Some(n) = h.per_client.get_mut(&client) {
                *n -= 1;
                if *n == 0 {
                    h.per_client.remove(&client);
                }
            }
        });
    }
}

/// Answers a stream's preamble, if it is one to a relay: false when it is
/// not (and nothing was said back).
pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> bool {
    let mut p = [0u8; PREAMBLE_LEN];
    match tokio::time::timeout(CONNECT_WAIT, stream.read_exact(&mut p)).await {
        Ok(Ok(_)) if frame::parse_preamble(&p) == Some(Kind::Relay) => {}
        _ => return false,
    }
    stream
        .write_all(&frame::preamble(Kind::Relay))
        .await
        .is_ok()
}

/// One client's stream to the relay, for as long as it lasts.
pub async fn take<S>(
    mut stream: S,
    peer: SocketAddr,
    tunnels: &Arc<Tunnels>,
    cancel: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    if !accept(&mut stream).await {
        tracing::debug!("relay: {} did not open a stream to a relay", peer);
        return;
    }
    run(stream, peer, tunnels, cancel).await
}

/// Carries a client's stream, opened, for as long as it lasts.
async fn run<S>(stream: S, peer: SocketAddr, tunnels: &Arc<Tunnels>, cancel: CancellationToken)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let last = Arc::new(parking_lot::Mutex::new(Instant::now()));
    let (heard, t) = (last.clone(), tunnels.clone());
    // Known to the relay before the first frame is read: the answer to it
    // goes back this way.
    let link = link::run_with(
        stream,
        move |f| {
            let (heard, t) = (heard.clone(), t.clone());
            async move {
                if let Frame::Datagram { port, data } = f {
                    *heard.lock() = Instant::now();
                    t.deliver(port, data, peer).await;
                }
            }
        },
        cancel,
        |link| tunnels.add(peer, link.clone()),
    );
    tracing::debug!("relay: stream from {}", peer);
    loop {
        let quiet = last.lock().elapsed();
        if quiet >= IDLE {
            link.close();
            break;
        }
        tokio::select! {
            _ = link.closed() => break,
            _ = tokio::time::sleep(IDLE - quiet) => {}
        }
    }
    tunnels.remove(peer, &link);
    tracing::debug!(
        "relay: stream from {} ended ({} bytes in, {} out)",
        peer,
        link.stats().received(),
        link.stats().sent()
    );
}
