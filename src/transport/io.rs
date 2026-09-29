//! Batched datagram I/O.
//!
//! At 10 Gbit/s a 1500-byte MTU means almost a million datagrams per second
//! in each direction; one system call per datagram would cost more than the
//! rest of the protocol together. [`BatchSocket`] sends many equally sized
//! datagrams with one call (UDP generic segmentation offload on Linux, USO
//! on Windows) and receives many with one call (`recvmmsg`, and UDP generic
//! receive offload, which hands over whole runs of datagrams from one
//! sender in a single buffer). Platforms without these features fall back
//! to one datagram per call transparently.

use crate::transport::socket::{bind_udp, set_dont_fragment};
use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Most datagrams one send carries.
pub const MAX_SEGMENTS: usize = 64;
/// Most bytes one send carries (the limit of a single segmented send).
pub const MAX_SEND_BYTES: usize = 65_000;
/// Size of one receive buffer: room for a whole coalesced run.
pub const RECV_BUF_LEN: usize = 65_536;
/// Receive buffers filled per call.
pub const RECV_BATCH: usize = quinn_udp::BATCH_SIZE;

/// Datagrams received into one buffer: `len` bytes holding datagrams of
/// `stride` bytes each (the last one may be shorter).
#[derive(Debug, Clone, Copy)]
pub struct Received {
    pub from: SocketAddr,
    pub len: usize,
    pub stride: usize,
    /// The local address the datagrams were sent to, where the system says:
    /// what a host with several addresses answers *from*.
    pub dst: Option<IpAddr>,
}

impl Received {
    /// Byte ranges of the datagrams in the buffer.
    pub fn segments(&self) -> impl Iterator<Item = std::ops::Range<usize>> {
        let (len, stride) = (self.len, self.stride.max(1));
        (0..len)
            .step_by(stride)
            .map(move |s| s..(s + stride).min(len))
    }
}

/// A UDP socket that sends and receives datagrams in batches where the
/// platform allows.
pub struct BatchSocket {
    io: Arc<UdpSocket>,
    state: UdpSocketState,
    /// A segmented send failed although the network stack offered the
    /// feature (some drivers do); datagrams go out one by one from then on.
    segments_failed: AtomicBool,
}

impl BatchSocket {
    /// Binds the socket and waits until it can send: until the runtime has
    /// seen it writable, every send would report `WouldBlock`.
    pub async fn bind(addr: SocketAddr, buffer_bytes: usize) -> io::Result<Self> {
        Self::wrap(Arc::new(bind_udp(addr, buffer_bytes)?)).await
    }

    /// Batches the datagrams of a socket bound elsewhere (see [`bind_udp`]).
    pub async fn wrap(io: Arc<UdpSocket>) -> io::Result<Self> {
        let state = UdpSocketState::new((&*io).into())?;
        // The batch layer lets the kernel ignore the path MTUs it learns;
        // the transfer engines want to hear about them (EMSGSIZE) so that
        // they can shrink their packets.
        let df = set_dont_fragment(&io);
        let reach = crate::address::Reach::of(&io);
        if reach.v4() && !df.v4 {
            tracing::info!(
                "this system does not mark IPv4 datagrams from {} \"don't fragment\"; routers \
                 may fragment them, which path MTU probing cannot see",
                io.local_addr()?
            );
        }
        if reach.v6() && !df.v6 {
            tracing::info!(
                "this system does not mark IPv6 datagrams from {} \"don't fragment\"",
                io.local_addr()?
            );
        }
        io.writable().await?;
        Ok(Self {
            io,
            state,
            segments_failed: AtomicBool::new(false),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    /// The plain socket, for occasional single datagrams sent from other
    /// tasks (address discovery). Everything received must go through
    /// [`BatchSocket::try_recv`].
    pub fn udp(&self) -> Arc<UdpSocket> {
        self.io.clone()
    }

    /// Most datagrams one [`BatchSocket::try_send_segments`] may carry (1
    /// without segmentation offload, or after the kernel refused it).
    pub fn max_segments(&self) -> usize {
        if self.segments_failed.load(Ordering::Relaxed) {
            return 1;
        }
        self.state.max_gso_segments().clamp(1, MAX_SEGMENTS)
    }

    /// Sends one datagram. `WouldBlock` means the socket buffer is full.
    pub fn try_send(&self, to: SocketAddr, datagram: &[u8]) -> io::Result<()> {
        self.transmit(to, datagram, None)
    }

    /// Sends `contents` as datagrams of `segment` bytes each (the last one
    /// may be shorter), with one system call where the platform allows. On
    /// an error nothing may be assumed sent. A segmented send that fails the
    /// way a driver without segmentation offload fails turns it off for this
    /// socket ([`BatchSocket::max_segments`] becomes 1), so the caller can
    /// send the datagrams one by one instead. Any other failure — the
    /// network being unreachable for a moment, say — leaves it on: turning
    /// it off for good on a transient error cost the rest of the transfer
    /// its fastest way to send.
    pub fn try_send_segments(
        &self,
        to: SocketAddr,
        contents: &[u8],
        segment: usize,
    ) -> io::Result<()> {
        if contents.len() <= segment {
            return self.transmit(to, contents, None);
        }
        debug_assert!(contents.len().div_ceil(segment) <= self.max_segments());
        let sent = self.transmit(to, contents, Some(segment));
        if let Err(e) = &sent {
            if is_segmentation_error(e) && !self.segments_failed.swap(true, Ordering::Relaxed) {
                tracing::info!(
                    "segmented send failed ({}); sending datagrams one by one",
                    e
                );
            }
        }
        sent
    }

    fn transmit(&self, to: SocketAddr, contents: &[u8], segment: Option<usize>) -> io::Result<()> {
        let transmit = Transmit {
            destination: to,
            ecn: None,
            contents,
            segment_size: segment,
            src_ip: None,
        };
        self.io.try_io(Interest::WRITABLE, || {
            self.state.try_send((&*self.io).into(), &transmit)
        })
    }

    /// Receives into `bufs` (each [`RECV_BUF_LEN`] bytes long) and describes
    /// what arrived in `out`. Returns the number of filled buffers;
    /// `WouldBlock` when nothing is queued.
    pub fn try_recv(&self, bufs: &mut [Vec<u8>], out: &mut [Received]) -> io::Result<usize> {
        let n = bufs.len().min(out.len()).min(RECV_BATCH);
        let mut meta = [RecvMeta::default(); RECV_BATCH];
        let mut slices: Vec<IoSliceMut<'_>> = bufs[..n]
            .iter_mut()
            .map(|b| IoSliceMut::new(&mut b[..]))
            .collect();
        let got = self.io.try_io(Interest::READABLE, || {
            self.state
                .recv((&*self.io).into(), &mut slices, &mut meta[..n])
        })?;
        for (o, m) in out.iter_mut().zip(&meta[..got]) {
            *o = Received {
                // Without the flow label and stray zone some systems report:
                // the same peer must compare equal from one datagram to the
                // next.
                from: crate::address::normalize(m.addr),
                len: m.len,
                stride: if m.stride == 0 { m.len } else { m.stride },
                dst: m.dst_ip.map(|ip| ip.to_canonical()),
            };
        }
        Ok(got)
    }

    pub async fn readable(&self) -> io::Result<()> {
        self.io.readable().await
    }

    pub async fn writable(&self) -> io::Result<()> {
        self.io.writable().await
    }
}

/// A UDP socket for a service that answers *from the address it was asked
/// at*.
///
/// A socket bound to the wildcard answers from whichever of the host's
/// addresses the system likes best, and a peer that sent to another one
/// discards the answer — or a firewall between them does, since it is no
/// reply to anything. That is how a host with two addresses on one
/// interface behaves, and a relay that also runs the STUN server's second
/// address is exactly such a host. So every datagram is received with the
/// address it was sent to, and answered with it as the source
/// (`IP_PKTINFO`, `IPV6_PKTINFO`).
pub struct PktSocket {
    io: Arc<UdpSocket>,
    state: UdpSocketState,
}

/// One receive: `len` bytes holding datagrams of `stride` bytes each (the
/// system may hand several from one peer over together).
#[derive(Debug, Clone, Copy)]
pub struct PktReceived {
    pub len: usize,
    pub stride: usize,
    pub from: SocketAddr,
    pub dst: Option<IpAddr>,
}

impl PktSocket {
    pub fn new(io: Arc<UdpSocket>) -> io::Result<Self> {
        let state = UdpSocketState::new((&*io).into())?;
        Ok(Self { io, state })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    /// Waits for a datagram (or a run of them) into `buf`.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<PktReceived> {
        loop {
            self.io.readable().await?;
            let mut meta = [RecvMeta::default()];
            let mut slices = [IoSliceMut::new(&mut buf[..])];
            let got = self.io.try_io(Interest::READABLE, || {
                self.state.recv((&*self.io).into(), &mut slices, &mut meta)
            });
            match got {
                Ok(0) => continue,
                Ok(_) => {
                    let m = meta[0];
                    return Ok(PktReceived {
                        len: m.len,
                        stride: if m.stride == 0 { m.len } else { m.stride },
                        from: crate::address::normalize(m.addr),
                        dst: m.dst_ip.map(|ip| ip.to_canonical()),
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Sends `datagram` to `to`, from `via` where that is known.
    pub async fn send(
        &self,
        to: SocketAddr,
        via: Option<IpAddr>,
        datagram: &[u8],
    ) -> io::Result<()> {
        loop {
            self.io.writable().await?;
            let transmit = Transmit {
                destination: to,
                ecn: None,
                contents: datagram,
                segment_size: None,
                src_ip: via,
            };
            match self.io.try_io(Interest::WRITABLE, || {
                self.state.try_send((&*self.io).into(), &transmit)
            }) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// How a segmented send fails when the driver or the stack cannot segment:
/// Linux answers EIO from a driver without the offload, and EINVAL or
/// EOPNOTSUPP where the option is not understood; Windows answers
/// WSAEINVAL or WSAEOPNOTSUPP.
fn is_segmentation_error(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            e.raw_os_error(),
            Some(libc::EIO) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP) | Some(libc::ENOPROTOOPT)
        )
    }
    #[cfg(windows)]
    {
        // WSAEINVAL, WSAEOPNOTSUPP
        matches!(e.raw_os_error(), Some(10022) | Some(10045))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = e;
        true
    }
}

/// The network stack is momentarily out of buffers (a full device queue):
/// worth a retry shortly, unlike other send errors.
pub fn is_no_buffer_error(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::ENOBUFS)
    }
    #[cfg(windows)]
    {
        // WSAENOBUFS
        e.raw_os_error() == Some(10055)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = e;
        false
    }
}

/// A set of receive buffers for [`BatchSocket::try_recv`].
pub fn recv_buffers(count: usize) -> Vec<Vec<u8>> {
    (0..count).map(|_| vec![0u8; RECV_BUF_LEN]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn segments_cover_the_buffer() {
        let r = Received {
            from: "127.0.0.1:1".parse().unwrap(),
            len: 10,
            stride: 4,
            dst: None,
        };
        assert_eq!(r.segments().collect::<Vec<_>>(), vec![0..4, 4..8, 8..10]);
        let single = Received { stride: 10, ..r };
        assert_eq!(single.segments().collect::<Vec<_>>(), vec![0..10]);
    }

    /// Segmentation is turned off only by a failure that says the stack or
    /// driver cannot segment. Anything else — here an address the socket
    /// cannot reach, standing in for a network that is gone for a moment —
    /// leaves it on: turning it off for good on a transient error cost the
    /// rest of the transfer its fastest way to send.
    #[tokio::test]
    async fn only_a_segmentation_failure_turns_segmentation_off() {
        let a = BatchSocket::bind("127.0.0.1:0".parse().unwrap(), 1 << 20)
            .await
            .unwrap();
        if a.max_segments() == 1 {
            return; // no segmentation offload here
        }
        let before = a.max_segments();
        let to: SocketAddr = "[2001:db8::1]:9".parse().unwrap();
        assert!(a.try_send_segments(to, &[0u8; 3000], 1000).is_err());
        assert_eq!(a.max_segments(), before);
    }

    #[cfg(unix)]
    #[test]
    fn segmentation_failures_are_told_apart_from_the_rest() {
        let err = |code| io::Error::from_raw_os_error(code);
        for code in [libc::EIO, libc::EINVAL, libc::EOPNOTSUPP] {
            assert!(is_segmentation_error(&err(code)), "{}", code);
        }
        for code in [
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::ENETDOWN,
            libc::EADDRNOTAVAIL,
            libc::EAFNOSUPPORT,
            libc::EMSGSIZE,
            libc::ENOBUFS,
            libc::EPERM,
        ] {
            assert!(!is_segmentation_error(&err(code)), "{}", code);
        }
    }

    /// Segmented sends arrive as separate datagrams of the right sizes,
    /// whether or not the receiving side coalesces them.
    #[tokio::test]
    async fn segmented_send_arrives_as_datagrams() {
        let a = BatchSocket::bind("127.0.0.1:0".parse().unwrap(), 1 << 20)
            .await
            .unwrap();
        let b = BatchSocket::bind("127.0.0.1:0".parse().unwrap(), 1 << 20)
            .await
            .unwrap();
        let to = b.local_addr().unwrap();
        let seg = 1200;
        let count = a.max_segments().min(10);
        let mut contents = Vec::new();
        for i in 0..count {
            let len = if i + 1 == count { 700 } else { seg };
            contents.extend(std::iter::repeat_n(i as u8, len));
        }
        a.try_send_segments(to, &contents, seg).unwrap();
        a.try_send(to, b"tail").unwrap();

        let mut bufs = recv_buffers(RECV_BATCH);
        let mut out = vec![
            Received {
                from: to,
                len: 0,
                stride: 0,
                dst: None
            };
            RECV_BATCH
        ];
        let mut datagrams: Vec<Vec<u8>> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while datagrams.len() < count + 1 {
            tokio::time::timeout_at(deadline, b.readable())
                .await
                .expect("datagrams arrive")
                .unwrap();
            let n = match b.try_recv(&mut bufs, &mut out) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("{}", e),
            };
            for (buf, r) in bufs.iter().zip(&out[..n]) {
                assert_eq!(r.from, a.local_addr().unwrap());
                for s in r.segments() {
                    datagrams.push(buf[s].to_vec());
                }
            }
        }
        for (i, d) in datagrams[..count].iter().enumerate() {
            let len = if i + 1 == count { 700 } else { seg };
            assert_eq!(d.len(), len);
            assert!(d.iter().all(|&x| x == i as u8));
        }
        assert_eq!(datagrams[count], b"tail");
    }
}
