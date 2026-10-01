//! The engine's end of a stream: a *shim*, a loopback socket the engine
//! sends to as if it were the peer, and which hands the engine what arrives
//! on the stream from its own address. It is the arrangement the TURN
//! client uses (`nat::turn`), for the same reason: the engine talks plain
//! UDP and is left alone, and a stream is one more address to it.

use super::link::{Link, StreamStats};
use super::MAX_DATAGRAM;
use crate::address::canonical;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// What a shim's socket buffers: a burst the engine sends while the
/// stream's writer catches up.
const SHIM_BUFFER: usize = 4 << 20;

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

/// A loopback socket connected to the engine's: it hears from the engine
/// and from nothing else.
pub fn make_shim(engine: SocketAddr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let bind = SocketAddr::new(engine.ip(), 0);
    let socket = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))?;
    // Larger than the default, which a single segmented send can fill; at
    // worst the system gives less, and a burst loses its tail.
    let _ = socket.set_recv_buffer_size(SHIM_BUFFER);
    socket.bind(&bind.into())?;
    socket.connect(&engine.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// The shims of one transfer, and the streams they lead to.
#[derive(Default)]
pub struct Shims {
    map: parking_lot::RwLock<HashMap<SocketAddr, (Link, u16)>>,
}

impl Shims {
    /// What is known of the stream behind `addr`, if it is one of these
    /// shims (one whose stream ended included).
    pub fn stats(&self, addr: SocketAddr) -> Option<Arc<StreamStats>> {
        self.map
            .read()
            .get(&canonical(addr))
            .map(|(link, _)| link.stats().clone())
    }

    /// The stream behind `addr`, and the port on it: what the engine sends
    /// there can go straight onto the stream's queue, which says when it is
    /// full, rather than through the shim's socket, which drops what it has
    /// no room for.
    pub fn route(&self, addr: SocketAddr) -> Option<(Link, u16)> {
        self.map.read().get(&canonical(addr)).cloned()
    }

    pub fn contains(&self, addr: SocketAddr) -> bool {
        self.map.read().contains_key(&canonical(addr))
    }

    fn insert(&self, addr: SocketAddr, link: Link, port: u16) {
        self.map.write().insert(canonical(addr), (link, port));
    }
}

/// A shim, bound and connected to the engine.
pub struct Shim {
    socket: UdpSocket,
    addr: SocketAddr,
}

impl Shim {
    pub fn open(engine: SocketAddr) -> io::Result<Arc<Self>> {
        let socket = make_shim(engine)?;
        let addr = canonical(socket.local_addr()?);
        Ok(Arc::new(Self { socket, addr }))
    }

    /// The address the engine sends to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Hands a datagram from the stream to the engine. Lost if the engine's
    /// socket will not take it now, as it would be over UDP.
    pub fn deliver(&self, datagram: &[u8]) {
        let _ = self.socket.try_send(datagram);
    }

    /// Carries what the engine sends to this shim onto `link`, on `port`,
    /// for as long as the stream runs. The shim is counted among `shims`
    /// from now on, with the stream's state.
    pub fn pump(self: Arc<Self>, shims: &Shims, link: Link, port: u16) {
        shims.insert(self.addr, link.clone(), port);
        tokio::spawn(async move {
            // One byte more than a frame takes, to tell "as long as allowed"
            // from "longer".
            let mut buf = vec![0u8; MAX_DATAGRAM + 1];
            loop {
                tokio::select! {
                    r = self.socket.recv(&mut buf) => match r {
                        Ok(n) if n <= MAX_DATAGRAM => {
                            // Refused when the stream's queue is full: lost,
                            // as a datagram a full buffer drops, and the
                            // engine learns from that.
                            let _ = link.send(port, &buf[..n]);
                        }
                        Ok(_) => {}
                        // An ICMP error from the engine's port (it has not
                        // bound it yet, or has gone), reported on this call.
                        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
                        Err(_) => break,
                    },
                    _ = link.closed() => break,
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::carrier::frame::Frame;
    use crate::transport::carrier::link;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn the_engine_reaches_the_stream_through_its_shim_and_back() {
        let engine = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let at = engine_address(&engine).unwrap();
        let shim = Shim::open(at).unwrap();
        let (near, far) = tokio::io::duplex(1 << 16);
        // The far end of the stream answers every datagram with its reverse.
        let (back_tx, mut back_rx) = tokio::sync::mpsc::unbounded_channel();
        let far_link = link::run(
            far,
            move |f| {
                if let Frame::Datagram { port, data } = f {
                    let _ = back_tx.send((port, data));
                }
                std::future::ready(())
            },
            CancellationToken::new(),
        );
        let near_shim = shim.clone();
        let near_link = link::run(
            near,
            move |f| {
                if let Frame::Datagram { data, .. } = f {
                    near_shim.deliver(&data);
                }
                std::future::ready(())
            },
            CancellationToken::new(),
        );
        let shims = Shims::default();
        shim.clone().pump(&shims, near_link.clone(), 7);
        assert!(shims.contains(shim.addr()));
        engine.send_to(b"to the peer", shim.addr()).await.unwrap();
        let (port, data) = back_rx.recv().await.unwrap();
        assert_eq!((port, data.as_slice()), (7, &b"to the peer"[..]));
        far_link.send(0, b"from the peer");
        let mut buf = [0u8; 64];
        let (n, from) = engine.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from the peer");
        assert_eq!(canonical(from), shim.addr(), "from the shim's address");
        // When the stream ends, the shim stays known, as dead.
        far_link.close();
        near_link.closed().await;
        assert!(!shims.stats(shim.addr()).unwrap().alive());
    }
}
