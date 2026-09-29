//! The hard side of a birthday meeting (see [`super::punch`]).
//!
//! A NAT that draws each new external port at random cannot be told where
//! to expect a packet from, so the end behind it opens many sockets, each of
//! which makes its own mapping when it sends to the peer's one known
//! address. The peer, behind a NAT that keeps one mapping, sends to many
//! ports of ours. Somewhere one of its packets arrives at a port one of our
//! sockets holds: that socket, and no other, is the way in, and the
//! transfer has to use it from then on — the mapping belongs to the socket.
//!
//! [`meet`] does the meeting and hands back the socket that was hit;
//! [`Routes`] is what a receiver, which serves many peers from its own
//! socket, keeps to answer the one peer from that socket instead.

use crate::relay::Message;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// A socket a peer's packet arrived at, and that packet.
pub struct Hit {
    pub socket: Arc<UdpSocket>,
    pub from: SocketAddr,
    pub datagram: Vec<u8>,
}

impl std::fmt::Debug for Hit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hit")
            .field("from", &self.from)
            .field("bytes", &self.datagram.len())
            .finish()
    }
}

/// Sockets for one meeting, and the share of the process's allowance they
/// hold until the meeting is over (see [`open_sockets`]).
pub struct Sockets {
    list: Vec<Arc<UdpSocket>>,
    _allowance: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl std::ops::Deref for Sockets {
    type Target = [Arc<UdpSocket>];

    fn deref(&self) -> &Self::Target {
        &self.list
    }
}

/// Sockets open for birthday meetings at once, in the whole process. Each is
/// a descriptor, and a program that has run out of those cannot open the
/// file it is receiving into, nor a socket for anything else: half of what
/// the system lets a process have (where it says — Linux gives 1024 by
/// default, macOS 256), and never more than two meetings' worth. A meeting
/// that finds less opens less, and one that finds none waits for nothing:
/// it is only the less likely to meet.
fn allowance() -> &'static Arc<tokio::sync::Semaphore> {
    static ALLOWANCE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    ALLOWANCE.get_or_init(|| {
        let most = 2 * crate::nat::punch::BIRTHDAY_SOCKETS;
        let n = descriptor_limit().map_or(most, |limit| (limit / 2).min(most));
        Arc::new(tokio::sync::Semaphore::new(n))
    })
}

/// How many descriptors the system lets this process have open, if it says.
#[cfg(unix)]
fn descriptor_limit() -> Option<usize> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes the struct it is given.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return None;
    }
    if limit.rlim_cur == libc::RLIM_INFINITY {
        return None;
    }
    usize::try_from(limit.rlim_cur).ok()
}

/// Windows counts sockets otherwise, and has room for many thousands.
#[cfg(not(unix))]
fn descriptor_limit() -> Option<usize> {
    None
}

/// Opens up to `count` sockets of the same kind as `like` — the same local
/// address, dual-stack where it is — each on a port of its own: as many as
/// the process's allowance for meetings has left (half the descriptors the
/// system lets the process have, and never more than two meetings' worth),
/// and fewer if the system runs out of descriptors. Fewer is not an error:
/// the meeting is only less likely.
pub fn open_sockets(like: &UdpSocket, count: usize) -> Sockets {
    open_within(allowance(), like, count)
}

/// [`open_sockets`], out of `allowance`.
fn open_within(allowance: &Arc<tokio::sync::Semaphore>, like: &UdpSocket, count: usize) -> Sockets {
    let none = || Sockets {
        list: Vec::new(),
        _allowance: None,
    };
    let Ok(local) = like.local_addr() else {
        return none();
    };
    let share = count.min(allowance.available_permits());
    let Some(permit) = u32::try_from(share)
        .ok()
        .filter(|n| *n > 0)
        .and_then(|n| allowance.clone().try_acquire_many_owned(n).ok())
    else {
        tracing::debug!("birthday: no sockets left in the allowance for meetings");
        return none();
    };
    let bind = SocketAddr::new(local.ip(), 0);
    let mut out = Vec::with_capacity(share);
    for _ in 0..share {
        match crate::transport::socket::bind_udp(bind, 64 * 1024) {
            Ok(s) => out.push(Arc::new(s)),
            Err(e) => {
                tracing::debug!("birthday: {} sockets opened, then: {}", out.len(), e);
                break;
            }
        }
    }
    Sockets {
        list: out,
        _allowance: Some(permit),
    }
}

/// Sends a punch to `base` from each of `sockets`, again and again for
/// `duration`, until a datagram arrives on one of them from `base`'s IP.
/// That socket is answered with a few punches from itself — the peer's
/// packet got in, and the peer needs ours to know which port it was — and
/// returned; the others are closed.
pub async fn meet(
    sockets: Sockets,
    base: SocketAddr,
    duration: Duration,
    cancel: &CancellationToken,
) -> Option<Hit> {
    if sockets.is_empty() {
        return None;
    }
    let (tx, mut rx) = mpsc::channel::<Hit>(8);
    let peer_ip = crate::address::canonical(base).ip();
    let mut readers = Vec::with_capacity(sockets.len());
    for socket in sockets.iter() {
        let (socket, tx) = (socket.clone(), tx.clone());
        readers.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                // Only the peer: the port is open to anyone who guesses it.
                if crate::address::canonical(from).ip() != peer_ip {
                    continue;
                }
                let _ = tx
                    .send(Hit {
                        socket: socket.clone(),
                        from,
                        datagram: buf[..n].to_vec(),
                    })
                    .await;
                return;
            }
        }));
    }
    drop(tx);
    let msg = Message::Punch.encode();
    let start = Instant::now();
    let mut round = 0u32;
    let hit = loop {
        for s in sockets.iter() {
            let _ = s.send_to(&msg, base).await;
        }
        round += 1;
        let gap = match round {
            0..=3 => Duration::from_millis(150),
            _ if start.elapsed() < Duration::from_secs(20) => Duration::from_millis(500),
            _ => Duration::from_secs(2),
        };
        if start.elapsed() + gap >= duration {
            break None;
        }
        tokio::select! {
            hit = rx.recv() => break hit,
            _ = tokio::time::sleep(gap) => {}
            _ = cancel.cancelled() => break None,
        }
    };
    for r in &readers {
        r.abort();
    }
    let hit = hit?;
    tracing::info!(
        "birthday: {} reached one of our {} sockets, which is at {}",
        hit.from,
        sockets.len(),
        hit.socket
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );
    // The peer's packet found the way in; ours has to show it which way
    // that was, and a few are sent because the first may be the one that
    // opens the peer's side.
    let (socket, from) = (hit.socket.clone(), hit.from);
    tokio::spawn(async move {
        for _ in 0..4 {
            let _ = socket.send_to(&Message::Punch.encode(), from).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    Some(hit)
}

/// The sockets a receiver answers particular peers from.
///
/// A receiver has one socket for everybody, and a peer that got in through
/// one of the birthday sockets is only reachable from that one. [`adopt`]
/// takes it over: datagrams that arrive there go to the receiver's own
/// dispatcher, as if they had come to the main socket, and [`send`] says
/// where an answer to that peer has to leave from.
///
/// Bounded, because a peer that asks for one costs a socket and a task: the
/// oldest goes when there are too many, and all of them when the receiver
/// does.
///
/// [`adopt`]: Routes::adopt
/// [`send`]: Routes::send
pub struct Routes {
    /// Whether there is anything to look up: sending is the hot path, and
    /// almost always there is nothing.
    active: AtomicBool,
    map: RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>,
    order: Mutex<Vec<(SocketAddr, tokio::task::JoinHandle<()>)>>,
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

/// Peers answered from a socket of their own at once.
const MAX_ROUTES: usize = 16;

impl Routes {
    /// The datagrams that arrive on adopted sockets come out of the receiver
    /// returned with it.
    pub fn new() -> (Arc<Self>, mpsc::Receiver<(Vec<u8>, SocketAddr)>) {
        let (tx, rx) = mpsc::channel(256);
        (
            Arc::new(Self {
                active: AtomicBool::new(false),
                map: RwLock::new(HashMap::new()),
                order: Mutex::new(Vec::new()),
                tx,
            }),
            rx,
        )
    }

    /// Answers `hit.from` from `hit.socket` from now on, and passes on what
    /// arrives there.
    pub fn adopt(self: &Arc<Self>, hit: Hit) {
        let Hit {
            socket,
            from,
            datagram,
        } = hit;
        let tx = self.tx.clone();
        let reader = {
            let socket = socket.clone();
            tokio::spawn(async move {
                let _ = tx.send((datagram, from)).await;
                let mut buf = vec![0u8; 2048];
                loop {
                    let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                        return;
                    };
                    if tx.send((buf[..n].to_vec(), peer)).await.is_err() {
                        return;
                    }
                }
            })
        };
        let mut order = self.order.lock();
        let mut map = self.map.write();
        if let Some(i) = order.iter().position(|(a, _)| *a == from) {
            order.remove(i).1.abort();
        }
        while order.len() >= MAX_ROUTES {
            let (old, task) = order.remove(0);
            task.abort();
            map.remove(&old);
        }
        map.insert(from, socket);
        order.push((from, reader));
        self.active.store(true, Ordering::Release);
    }

    /// Sends `datagram` to `to` from the socket adopted for it, if there is
    /// one: `None` when there is not and the caller's own socket is the way.
    pub fn send(&self, to: SocketAddr, datagram: &[u8]) -> Option<io::Result<()>> {
        if !self.active.load(Ordering::Acquire) {
            return None;
        }
        let socket = self.map.read().get(&to)?.clone();
        Some(socket.try_send_to(datagram, to).map(|_| ()))
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        for (_, task) in self.order.get_mut().drain(..) {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One of many sockets is hit by a peer that knows only a range of
    /// ports, and both sides end up with the same socket: the one that
    /// was hit, and nothing else.
    #[tokio::test]
    async fn the_socket_that_is_hit_is_the_one_returned() {
        let peer = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let like = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sockets = open_sockets(&like, 8);
        assert_eq!(sockets.len(), 8);
        let ports: Vec<u16> = sockets
            .iter()
            .map(|s| s.local_addr().unwrap().port())
            .collect();
        let target = ports[5];
        let base = peer.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let meeting = tokio::spawn({
            let cancel = cancel.clone();
            async move { meet(sockets, base, Duration::from_secs(5), &cancel).await }
        });
        // The peer learns which sockets are out there only by their punches,
        // as it would through its NAT; it sends to just one port.
        let mut buf = [0u8; 64];
        let (_, _) = peer.recv_from(&mut buf).await.unwrap();
        peer.send_to(&Message::Punch.encode(), ("127.0.0.1", target))
            .await
            .unwrap();
        let hit = meeting.await.unwrap().expect("no hit");
        assert_eq!(hit.socket.local_addr().unwrap().port(), target);
        assert_eq!(hit.from, base);
        // And the answer comes from that very socket.
        loop {
            let (n, from) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
                .await
                .expect("no answer")
                .unwrap();
            if from.port() == target && matches!(Message::decode(&buf[..n]), Some(Message::Punch)) {
                break;
            }
        }
    }

    /// What meetings may open is shared by the whole process, and given
    /// back when a meeting's sockets go.
    #[tokio::test]
    async fn meetings_share_one_allowance_of_sockets() {
        let like = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // The process's own allowance is shared with the tests that run
        // alongside; the rule is the same for one of this test's own.
        let budget = Arc::new(tokio::sync::Semaphore::new(10));
        let first = open_within(&budget, &like, 7);
        assert_eq!(first.len(), 7);
        let second = open_within(&budget, &like, 256);
        assert_eq!(second.len(), 3, "only what is left");
        let third = open_within(&budget, &like, 256);
        assert!(third.is_empty(), "nothing is left");
        drop(first);
        assert_eq!(budget.available_permits(), 7);
        drop((second, third));
        assert_eq!(budget.available_permits(), 10);
        // And the process's own is there, and never more than two meetings.
        let total = allowance().available_permits();
        assert!(
            total <= 2 * crate::nat::punch::BIRTHDAY_SOCKETS,
            "{}",
            total
        );
    }

    #[tokio::test]
    async fn a_stranger_does_not_take_the_place_of_the_peer() {
        // Datagrams from another address are ignored, whatever port they hit.
        let like = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sockets = open_sockets(&like, 2);
        let port = sockets[0].local_addr().unwrap().port();
        let base: SocketAddr = "127.0.0.2:9".parse().unwrap();
        let cancel = CancellationToken::new();
        let meeting = tokio::spawn({
            let cancel = cancel.clone();
            async move { meet(sockets, base, Duration::from_millis(900), &cancel).await }
        });
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stranger
            .send_to(b"hello", ("127.0.0.1", port))
            .await
            .unwrap();
        assert!(meeting.await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_adopted_socket_carries_the_peer_both_ways() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (routes, mut rx) = Routes::new();
        let from = peer.local_addr().unwrap();
        assert!(routes.send(from, b"x").is_none(), "nothing adopted yet");
        routes.adopt(Hit {
            socket: socket.clone(),
            from,
            datagram: b"first".to_vec(),
        });
        let (first, who) = rx.recv().await.unwrap();
        assert_eq!((first.as_slice(), who), (b"first".as_slice(), from));
        // What the peer sends to the adopted socket comes out of the queue…
        peer.send_to(b"second", socket.local_addr().unwrap())
            .await
            .unwrap();
        let (second, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second, b"second");
        // …and what is sent to it leaves from that socket, and only that.
        routes.send(from, b"reply").unwrap().unwrap();
        let mut buf = [0u8; 16];
        let (n, src) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"reply");
        assert_eq!(src, socket.local_addr().unwrap());
        assert!(routes.send("127.0.0.1:1".parse().unwrap(), b"x").is_none());
    }
}
