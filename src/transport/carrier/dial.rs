//! A sender's streams to the receiver, dialled when the engine asks — UDP
//! has not answered, or has stopped — at the receiver's addresses, each
//! joined to the engine through a shim whose address the engine then tries
//! like any other.
//!
//! The addresses are tried as RFC 8305 tries them: one at a time, a quarter
//! of a second apart, the families already taking turns in the order the
//! engine keeps them in, and the first stream that comes up is the one kept.
//! One stream to the receiver is enough; another is dialled when it ends.

use super::frame::{self, Frame, Kind, PREAMBLE_LEN};
use super::link;
use super::shim::{Shim, Shims};
use crate::address::canonical;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Between one attempt and the next (RFC 8305's connection attempt delay).
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
/// How long a connection, and then the receiver's preamble, may take.
const CONNECT_WAIT: Duration = Duration::from_secs(5);
/// How soon an address that failed is tried again.
const RETRY_AFTER: Duration = Duration::from_secs(30);
/// Addresses tried in one go.
const MAX_TARGETS: usize = 8;

/// What else to do whenever streams are asked for: a sender's relays are
/// reached over streams too (see `relay::tunnel`).
pub type Also = Box<dyn Fn() + Send + Sync>;

/// Dials streams to the receiver at the addresses sent on the channel
/// returned, from `local`'s address when it has one, and sends the address
/// of each one's shim — joined to the engine at `engine` — on `found`.
/// `also` is called with every request.
pub fn spawn(
    engine: SocketAddr,
    local: SocketAddr,
    shims: Arc<Shims>,
    found: mpsc::UnboundedSender<SocketAddr>,
    also: Option<Also>,
    cancel: CancellationToken,
) -> mpsc::UnboundedSender<Vec<SocketAddr>> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<SocketAddr>>();
    tokio::spawn(async move {
        let mut tried: HashMap<SocketAddr, Instant> = HashMap::new();
        let mut current: Option<Arc<link::StreamStats>> = None;
        loop {
            let targets = tokio::select! {
                t = rx.recv() => match t {
                    Some(t) => t,
                    None => return,
                },
                _ = cancel.cancelled() => return,
            };
            if let Some(also) = &also {
                also();
            }
            if current.as_ref().is_some_and(|s| s.alive()) {
                continue;
            }
            let now = Instant::now();
            let mut fresh: Vec<SocketAddr> = Vec::new();
            for t in targets.into_iter().map(canonical) {
                if fresh.len() >= MAX_TARGETS || fresh.contains(&t) {
                    continue;
                }
                if tried
                    .get(&t)
                    .is_some_and(|at| now.saturating_duration_since(*at) < RETRY_AFTER)
                {
                    continue;
                }
                tried.insert(t, now);
                fresh.push(t);
            }
            if fresh.is_empty() {
                continue;
            }
            tracing::info!("trying the receiver over TCP at {:?}", fresh);
            let won = tokio::select! {
                w = race(&fresh, local) => w,
                _ = cancel.cancelled() => return,
            };
            let Some((target, stream)) = won else {
                tracing::info!("the receiver does not answer over TCP either");
                continue;
            };
            match join(stream, engine, &shims, &cancel) {
                Ok((addr, stats)) => {
                    tracing::info!(
                        "the receiver answers over TCP at {}; carried from {}",
                        target,
                        addr
                    );
                    current = Some(stats);
                    if found.send(addr).is_err() {
                        return;
                    }
                }
                Err(e) => tracing::info!("cannot carry the stream to {}: {}", target, e),
            }
        }
    });
    tx
}

/// Attempts at `targets`, a quarter of a second apart; the first stream up
/// wins, and the others are dropped.
async fn race(targets: &[SocketAddr], local: SocketAddr) -> Option<(SocketAddr, TcpStream)> {
    let mut attempts = tokio::task::JoinSet::new();
    let mut next = 0;
    loop {
        if next < targets.len() {
            let t = targets[next];
            next += 1;
            attempts.spawn(async move { (t, attempt(t, local).await) });
        }
        let wait = async {
            if next < targets.len() {
                tokio::time::sleep(ATTEMPT_DELAY).await
            } else {
                std::future::pending::<()>().await
            }
        };
        tokio::select! {
            done = attempts.join_next() => match done {
                Some(Ok((t, Ok(stream)))) => return Some((t, stream)),
                Some(Ok((t, Err(e)))) => {
                    tracing::debug!("TCP to {}: {}", t, e);
                    // A failure starts the next attempt at once.
                }
                Some(Err(_)) => {}
                None if next >= targets.len() => return None,
                None => {}
            },
            _ = wait => {}
        }
    }
}

/// A stream to a receiver at `target`, its preamble answered.
async fn attempt(target: SocketAddr, local: SocketAddr) -> io::Result<TcpStream> {
    let socket = if target.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // From the address the transfer's socket is bound to, when it is bound
    // to one: the way out the user chose.
    let ip = canonical(local).ip();
    if !ip.is_unspecified() && ip.is_ipv4() == target.is_ipv4() {
        socket.bind(SocketAddr::new(ip, 0))?;
    }
    let mut stream = tokio::time::timeout(CONNECT_WAIT, socket.connect(target))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer"))??;
    stream.set_nodelay(true)?;
    stream.write_all(&frame::preamble(Kind::Receiver)).await?;
    let mut p = [0u8; PREAMBLE_LEN];
    tokio::time::timeout(CONNECT_WAIT, stream.read_exact(&mut p))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no SHARP-256 receiver there"))??;
    if frame::parse_preamble(&p) != Some(Kind::Receiver) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SHARP-256 receiver",
        ));
    }
    Ok(stream)
}

/// Joins `stream` to the engine at `engine` through a new shim: its
/// address, and the stream's state.
fn join(
    stream: TcpStream,
    engine: SocketAddr,
    shims: &Shims,
    cancel: &CancellationToken,
) -> io::Result<(SocketAddr, Arc<link::StreamStats>)> {
    let shim = Shim::open(engine)?;
    let to_engine = shim.clone();
    let link = link::run(
        stream,
        move |f| {
            if let Frame::Datagram { port: 0, data } = f {
                to_engine.deliver(&data);
            }
            std::future::ready(())
        },
        cancel.child_token(),
    );
    let stats = link.stats().clone();
    let addr = shim.addr();
    shim.pump(shims, link, 0);
    Ok((addr, stats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::carrier::listen;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn the_first_stream_up_is_joined_to_the_engine() {
        let listener = listen::bind("127.0.0.1:0".parse().unwrap(), false).unwrap();
        let at = listener.local_addr().unwrap();
        let (streams, mut inbound) = listen::Streams::new();
        let cancel = CancellationToken::new();
        tokio::spawn(listen::serve(listener, streams.clone(), cancel.clone()));
        let engine = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let shims = Arc::new(Shims::default());
        let (found_tx, mut found_rx) = mpsc::unbounded_channel();
        let dial = spawn(
            engine.local_addr().unwrap(),
            engine.local_addr().unwrap(),
            shims.clone(),
            found_tx,
            None,
            cancel.clone(),
        );
        // A dead address first: the live one is tried a quarter second
        // later without waiting for the dead one to time out.
        let dead: SocketAddr = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        dial.send(vec![dead, at]).unwrap();
        let shim = tokio::time::timeout(Duration::from_secs(10), found_rx.recv())
            .await
            .expect("a stream came up")
            .unwrap();
        assert!(shims.contains(shim));
        engine.send_to(b"over tcp", shim).await.unwrap();
        let (data, from) = inbound.recv().await.unwrap();
        assert_eq!(data, b"over tcp");
        assert!(streams.contains(from));
        streams.send(from, b"and back").unwrap().unwrap();
        let mut buf = [0u8; 32];
        let (n, src) = engine.recv_from(&mut buf).await.unwrap();
        assert_eq!((&buf[..n], canonical(src)), (&b"and back"[..], shim));
        // Asked again while the stream runs: nothing more is dialled.
        dial.send(vec![at]).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(500), found_rx.recv())
                .await
                .is_err()
        );
        cancel.cancel();
    }
}
