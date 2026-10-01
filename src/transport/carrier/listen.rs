//! A receiver's streams: accepted on TCP at the port its UDP socket has,
//! each joined to the dispatcher as if its datagrams had come in on the
//! socket — from the address the stream comes from, which the stream itself
//! proves (a TCP connection is not made from a forged source).
//!
//! What a receiver sends to such an address goes back on its stream
//! ([`Streams::send`]). The same table carries a receiver's routes through
//! a relay it reaches over a stream (see `tunnel`): an address there is the
//! relay's port, and its datagrams go on the relay's stream, tagged with it.

use super::frame::{self, Frame, Kind, PREAMBLE_LEN};
use super::link::{self, Link};
use crate::address::canonical;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Streams a receiver holds at once, and from any one client (an IPv4
/// address, an IPv6 /64). A stream is a socket and two small tasks; the
/// bounds keep what a stranger can make a receiver hold to that.
const MAX_STREAMS: usize = 64;
const PER_CLIENT: usize = 4;
/// How long a new stream has to say what it is.
const PREAMBLE_WAIT: Duration = Duration::from_secs(5);
/// A stream that carries nothing this long is closed: a sender whose
/// session runs elsewhere does not need it, and one that does dials again.
const IDLE: Duration = Duration::from_secs(60);
/// Datagrams that came in on streams and wait for the dispatcher.
const INBOUND: usize = 1024;

/// Addresses reached through a stream, and the datagrams that come in on
/// them.
pub struct Streams {
    /// Whether there is anything to look up: sending is the hot path.
    active: AtomicBool,
    routes: parking_lot::RwLock<HashMap<SocketAddr, (Link, u16)>>,
    inbound: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

impl Streams {
    /// The table, and where what comes in on its streams comes out.
    pub fn new() -> (Arc<Self>, mpsc::Receiver<(Vec<u8>, SocketAddr)>) {
        let (inbound, rx) = mpsc::channel(INBOUND);
        (
            Arc::new(Self {
                active: AtomicBool::new(false),
                routes: parking_lot::RwLock::new(HashMap::new()),
                inbound,
            }),
            rx,
        )
    }

    /// Sends `datagram` to `to` on its stream, if `to` is reached through
    /// one. `None` when it is not; a full stream refuses, as a full socket
    /// would.
    pub fn send(&self, to: SocketAddr, datagram: &[u8]) -> Option<io::Result<()>> {
        if !self.active.load(Ordering::Relaxed) {
            return None;
        }
        let routes = self.routes.read();
        let (link, port) = routes.get(&canonical(to))?;
        Some(if link.send(*port, datagram) {
            Ok(())
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        })
    }

    /// Whether `addr` is reached through a stream.
    pub fn contains(&self, addr: SocketAddr) -> bool {
        self.active.load(Ordering::Relaxed) && self.routes.read().contains_key(&canonical(addr))
    }

    /// Hands what arrives from `from` to the dispatcher, waiting while it
    /// is behind: the stream holds still meanwhile, and its sender with it.
    pub async fn deliver(&self, datagram: Vec<u8>, from: SocketAddr) {
        let _ = self.inbound.send((datagram, from)).await;
    }

    /// Sends what goes to `addr` on `link`, tagged with `port`.
    pub fn route(&self, addr: SocketAddr, link: Link, port: u16) {
        self.routes.write().insert(canonical(addr), (link, port));
        self.active.store(true, Ordering::Relaxed);
    }

    /// Forgets every route on `link` (a stream that ended).
    pub fn unroute_link(&self, link: &Link) {
        let mut routes = self.routes.write();
        routes.retain(|_, (l, _)| !Arc::ptr_eq(l.stats(), link.stats()));
        self.active.store(!routes.is_empty(), Ordering::Relaxed);
    }

    /// Forgets the route to `addr`, if it is still the one on `link`.
    pub fn unroute(&self, addr: SocketAddr, link: &Link) {
        let mut routes = self.routes.write();
        let addr = canonical(addr);
        if routes
            .get(&addr)
            .is_some_and(|(l, _)| Arc::ptr_eq(l.stats(), link.stats()))
        {
            routes.remove(&addr);
        }
        self.active.store(!routes.is_empty(), Ordering::Relaxed);
    }
}

/// A TCP listener at `addr`: for a wildcard IPv6 address, one that takes
/// IPv4 too exactly when `dual_stack` (as the receiver's UDP socket does).
pub fn bind(addr: SocketAddr, dual_stack: bool) -> io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(!dual_stack)?;
    }
    // A receiver restarted while its streams were closing gets its port
    // back at once.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// Who a stream is counted against: an IPv4 address, or an IPv6 /64 (one
/// host has a whole /64 to make addresses in).
pub(crate) fn client_of(ip: IpAddr) -> IpAddr {
    match canonical(SocketAddr::new(ip, 0)).ip() {
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(o.into())
        }
        v4 => v4,
    }
}

/// Streams held, in all and per client.
#[derive(Default)]
struct Held {
    total: usize,
    per_client: HashMap<IpAddr, usize>,
}

/// Accepts streams on `listener` until `cancel` fires, and joins each to
/// `streams`.
pub async fn serve(listener: TcpListener, streams: Arc<Streams>, cancel: CancellationToken) {
    let held = Arc::new(parking_lot::Mutex::new(Held::default()));
    let mut failures = 0u32;
    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(v) => {
                    failures = 0;
                    v
                }
                // Out of descriptors, mostly: wait a little rather than spin.
                Err(e) => {
                    failures = failures.saturating_add(1);
                    if failures.is_power_of_two() {
                        tracing::debug!("carrier: accept failed: {}", e);
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
            if h.total >= MAX_STREAMS || mine >= PER_CLIENT {
                tracing::debug!("carrier: refusing a stream from {}: too many", peer);
                continue;
            }
            h.total += 1;
            *h.per_client.entry(client).or_insert(0) += 1;
        }
        let (streams, cancel, held) = (streams.clone(), cancel.child_token(), held.clone());
        tokio::spawn(async move {
            take(stream, peer, &streams, cancel).await;
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

/// One stream to the receiver, for as long as it lasts.
async fn take(
    mut stream: TcpStream,
    peer: SocketAddr,
    streams: &Arc<Streams>,
    cancel: CancellationToken,
) {
    let _ = stream.set_nodelay(true);
    let mut p = [0u8; PREAMBLE_LEN];
    match tokio::time::timeout(PREAMBLE_WAIT, stream.read_exact(&mut p)).await {
        Ok(Ok(_)) if frame::parse_preamble(&p) == Some(Kind::Receiver) => {}
        _ => {
            tracing::debug!("carrier: {} did not open a stream to a receiver", peer);
            return;
        }
    }
    if stream
        .write_all(&frame::preamble(Kind::Receiver))
        .await
        .is_err()
    {
        return;
    }
    let last = Arc::new(parking_lot::Mutex::new(Instant::now()));
    let (heard, s) = (last.clone(), streams.clone());
    let link = link::run(
        stream,
        move |f| {
            let (heard, s) = (heard.clone(), s.clone());
            async move {
                // A receiver's stream carries datagrams on port 0, and
                // nothing of the carrier's own.
                if let Frame::Datagram { port: 0, data } = f {
                    *heard.lock() = Instant::now();
                    s.deliver(data, peer).await;
                }
            }
        },
        cancel,
    );
    streams.route(peer, link.clone(), 0);
    tracing::debug!("carrier: stream from {}", peer);
    loop {
        let quiet = last.lock().elapsed();
        if quiet >= IDLE {
            tracing::debug!(
                "carrier: the stream from {} carried nothing for {:?}; closing it",
                peer,
                quiet
            );
            link.close();
            break;
        }
        tokio::select! {
            _ = link.closed() => break,
            _ = tokio::time::sleep(IDLE - quiet) => {}
        }
    }
    streams.unroute(peer, &link);
    tracing::debug!(
        "carrier: stream from {} ended ({} bytes in, {} out)",
        peer,
        link.stats().received(),
        link.stats().sent()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_is_an_ipv4_address_or_an_ipv6_slash_64() {
        let a: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::1".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(client_of(a), client_of(b));
        assert_ne!(client_of(a), client_of(c));
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(client_of(v4), v4);
        assert_eq!(
            client_of(mapped),
            v4,
            "an IPv4 client however it is written"
        );
    }

    async fn opened(addr: SocketAddr) -> TcpStream {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&frame::preamble(Kind::Receiver)).await.unwrap();
        let mut p = [0u8; PREAMBLE_LEN];
        s.read_exact(&mut p).await.unwrap();
        assert_eq!(frame::parse_preamble(&p), Some(Kind::Receiver));
        s
    }

    #[tokio::test]
    async fn a_stream_is_joined_to_the_receiver_and_answered_on() {
        let listener = bind("127.0.0.1:0".parse().unwrap(), false).unwrap();
        let addr = listener.local_addr().unwrap();
        let (streams, mut inbound) = Streams::new();
        let cancel = CancellationToken::new();
        tokio::spawn(serve(listener, streams.clone(), cancel.clone()));
        let mut s = opened(addr).await;
        let me = s.local_addr().unwrap();
        s.write_all(&frame::header(5, 0)).await.unwrap();
        s.write_all(b"hello").await.unwrap();
        let (data, from) = inbound.recv().await.unwrap();
        assert_eq!((data.as_slice(), from), (&b"hello"[..], me));
        assert!(streams.contains(me));
        streams.send(me, b"answer").unwrap().unwrap();
        let f = frame::read_frame(&mut s).await.unwrap().unwrap();
        assert_eq!(
            f,
            Frame::Datagram {
                port: 0,
                data: b"answer".to_vec()
            }
        );
        // Gone with the stream.
        drop(s);
        for _ in 0..100 {
            if !streams.contains(me) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!streams.contains(me));
        assert!(streams.send(me, b"late").is_none());
        cancel.cancel();
    }

    #[tokio::test]
    async fn what_is_not_a_stream_to_a_receiver_is_not_joined() {
        let listener = bind("127.0.0.1:0".parse().unwrap(), false).unwrap();
        let addr = listener.local_addr().unwrap();
        let (streams, _inbound) = Streams::new();
        let cancel = CancellationToken::new();
        tokio::spawn(serve(listener, streams.clone(), cancel.clone()));
        // A web client, and a stream meant for a relay.
        for opening in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            &frame::preamble(Kind::Relay)[..],
        ] {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(opening).await.unwrap();
            let mut buf = [0u8; 8];
            let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
                .await
                .expect("closed, not left open")
                .unwrap_or(0);
            assert_eq!(n, 0, "nothing said back");
        }
        cancel.cancel();
    }

    #[tokio::test]
    async fn one_client_holds_only_so_many_streams() {
        let listener = bind("127.0.0.1:0".parse().unwrap(), false).unwrap();
        let addr = listener.local_addr().unwrap();
        let (streams, _inbound) = Streams::new();
        let cancel = CancellationToken::new();
        tokio::spawn(serve(listener, streams.clone(), cancel.clone()));
        let mut held = Vec::new();
        for _ in 0..PER_CLIENT {
            held.push(opened(addr).await);
        }
        // One more from the same address is closed unanswered.
        let mut extra = TcpStream::connect(addr).await.unwrap();
        extra
            .write_all(&frame::preamble(Kind::Receiver))
            .await
            .unwrap();
        let mut p = [0u8; PREAMBLE_LEN];
        let r = tokio::time::timeout(Duration::from_secs(5), extra.read_exact(&mut p))
            .await
            .expect("closed, not left open");
        assert!(r.is_err(), "refused");
        cancel.cancel();
    }
}
