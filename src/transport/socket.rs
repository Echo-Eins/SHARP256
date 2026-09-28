//! UDP socket setup shared by sender and receiver.

use std::io;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::UdpSocket;

/// Binds a non-blocking UDP socket with enlarged kernel buffers. Bulk UDP at
/// hundreds of Mbit/s overflows the default ~200 KiB receive buffer within
/// milliseconds whenever the application pauses, so we ask for more (the
/// kernel may clamp the request; see `net.core.rmem_max` on Linux).
///
/// `[::]` means every address of both families: one dual-stack socket
/// (RFC 3493 section 5.3, `IPV6_V6ONLY` off) that reaches IPv4 peers under
/// their mapped addresses. Where the system has no IPv6 at all, or will not
/// let one socket speak both (OpenBSD, or IPv6 switched off in the kernel),
/// it falls back to `0.0.0.0` on the same port — IPv4 reaches the most, and
/// a socket that silently spoke IPv6 alone would reach nobody on IPv4.
/// Any other address is bound exactly as given.
pub fn bind_udp(addr: SocketAddr, buffer_bytes: usize) -> io::Result<UdpSocket> {
    if let SocketAddr::V6(v6) = addr {
        if v6.ip().is_unspecified() {
            match bind_socket(addr, buffer_bytes, true) {
                Ok(s) => return Ok(s),
                Err(e) if ipv6_unavailable(&e) => {
                    let v4 = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), addr.port());
                    static TOLD: std::sync::Once = std::sync::Once::new();
                    TOLD.call_once(|| {
                        tracing::info!("IPv6 is not available here ({}); using IPv4 only", e)
                    });
                    return bind_socket(v4, buffer_bytes, false);
                }
                Err(e) => return Err(e),
            }
        }
    }
    bind_socket(addr, buffer_bytes, false)
}

fn bind_socket(addr: SocketAddr, buffer_bytes: usize, dual_stack: bool) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if dual_stack {
        // Has to hold, or the socket would not reach IPv4 at all.
        socket.set_only_v6(false).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "this system will not let one socket speak both IPv4 and IPv6 ({})",
                    e
                ),
            )
        })?;
    } else if addr.is_ipv6() {
        // An address bound explicitly speaks its own family; a mapped one
        // speaks IPv4 through this IPv6 socket, where the system allows.
        let _ = socket.set_only_v6(false);
    }
    set_buffer_sizes(&socket, buffer_bytes);
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let udp = UdpSocket::from_std(std_socket)?;
    set_dont_fragment(&udp);
    disable_udp_connreset(&udp);
    Ok(udp)
}

/// Whether an error from making or binding an IPv6 socket means this host
/// cannot do IPv6 (or dual-stack) at all, rather than that something is
/// wrong with the address asked for.
fn ipv6_unavailable(e: &io::Error) -> bool {
    if e.kind() == io::ErrorKind::Unsupported {
        return true;
    }
    #[cfg(unix)]
    {
        matches!(
            e.raw_os_error(),
            Some(libc::EAFNOSUPPORT) | Some(libc::EPROTONOSUPPORT) | Some(libc::EADDRNOTAVAIL)
        )
    }
    #[cfg(windows)]
    {
        // WSAEAFNOSUPPORT, WSAEPROTONOSUPPORT, WSAEADDRNOTAVAIL
        matches!(e.raw_os_error(), Some(10047) | Some(10043) | Some(10049))
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Asks for kernel socket buffers of `bytes` each. Linux caps ordinary
/// requests at `net.core.rmem_max` / `wmem_max`; a privileged process may
/// exceed them, which is tried first. Too small a receive buffer is worth a
/// warning: at multi-gigabit rates it overflows whenever the process is
/// briefly descheduled.
fn set_buffer_sizes(socket: &socket2::Socket, bytes: usize) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let val = bytes.min(i32::MAX as usize) as libc::c_int;
        for opt in [libc::SO_RCVBUFFORCE, libc::SO_SNDBUFFORCE] {
            // SAFETY: plain setsockopt with an integer value on a socket we
            // own; failure (no privilege) is handled below.
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    opt,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
    }
    // Best effort: the kernel clamps to its configured maximum. (Linux
    // reports twice the size asked for, to account for its bookkeeping.)
    if socket.recv_buffer_size().is_ok_and(|n| n < bytes) {
        let _ = socket.set_recv_buffer_size(bytes);
    }
    if socket.send_buffer_size().is_ok_and(|n| n < bytes) {
        let _ = socket.set_send_buffer_size(bytes);
    }
    let got = socket.recv_buffer_size().unwrap_or(0);
    if got < bytes / 2 {
        let hint = if cfg!(target_os = "linux") {
            format!(
                " (raise the limit with: sysctl -w net.core.rmem_max={} net.core.wmem_max={})",
                bytes, bytes
            )
        } else {
            String::new()
        };
        // A few MiB serve a gigabit link well; below that, bursts overflow.
        if got < 4 << 20 {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::warn!(
                    "UDP receive buffer is only {} KiB (asked for {} KiB); fast transfers will \
                     lose packets to it{}",
                    got / 1024,
                    bytes / 1024,
                    hint
                );
            });
        } else {
            tracing::debug!(
                "UDP receive buffer is {} KiB (asked for {} KiB){}",
                got / 1024,
                bytes / 1024,
                hint
            );
        }
    }
}

/// Which address families a socket sends with "don't fragment".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DontFragment {
    pub v4: bool,
    pub v6: bool,
}

/// Marks outgoing datagrams "don't fragment" so that an oversized probe is
/// dropped on the path instead of being silently fragmented — and makes the
/// socket ignore what ICMP says about the path MTU.
///
/// That second half matters. In the ordinary mode (`IP_PMTUDISC_DO`) the
/// kernel believes every "fragmentation needed" message that matches the
/// socket, and from then on refuses to send anything larger — including to
/// us, with EMSGSIZE. ICMP is not authenticated, so one forged message could
/// shrink every datagram of a transfer, or refuse the control messages
/// outright. In probe mode the kernel sets DF and otherwise leaves the path
/// MTU to us: it is found with PROBE, which the receiver acknowledges
/// under the session's keys (RFC 8899, datagram PLPMTUD), and a real drop
/// shows up as full-size packets being lost while small ones are not.
/// EMSGSIZE is then only ever about the local interface.
///
/// IPv6 routers never fragment, but the sending host does unless told not
/// to — Linux in probe mode still splits an IPv6 datagram larger than the
/// interface — so `IPV6_DONTFRAG` (RFC 3542 section 11.2) goes on as well.
/// A dual-stack socket gets the IPv4 options too, for the IPv4 peers it
/// reaches through mapped addresses, where the system accepts them on an
/// IPv6 socket. macOS and FreeBSD may not; those datagrams can then be
/// fragmented by routers on the way, which costs efficiency, not
/// correctness. The result says what took.
pub fn set_dont_fragment(socket: &UdpSocket) -> DontFragment {
    let local = socket.local_addr().ok();
    let is_v6 = local.is_some_and(|a| a.is_ipv6());
    let dual = is_v6
        && socket2::SockRef::from(socket)
            .only_v6()
            .is_ok_and(|only| !only);
    let speaks_v4 = !is_v6 || dual;
    #[allow(unused_mut)]
    let mut out = DontFragment::default();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if speaks_v4 {
            out.v4 = set_int_option(
                socket,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_PROBE,
            );
        }
        if is_v6 {
            let probe = set_int_option(
                socket,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IPV6_PMTUDISC_PROBE,
            );
            let dontfrag = set_int_option(socket, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1);
            out.v6 = probe && dontfrag;
        }
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd"
    ))]
    {
        if speaks_v4 {
            out.v4 = set_int_option(socket, libc::IPPROTO_IP, libc::IP_DONTFRAG, 1);
        }
        if is_v6 {
            out.v6 = set_int_option(socket, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1);
        }
    }
    #[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
    {
        // IPV6_DONTFRAG, which the libc crate does not export there. IPv4
        // has no per-socket switch on these systems.
        const IPV6_DONTFRAG: libc::c_int = 62;
        if is_v6 {
            out.v6 = set_int_option(socket, libc::IPPROTO_IPV6, IPV6_DONTFRAG, 1);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use winapi::shared::ws2def::{IPPROTO_IP, IPPROTO_IPV6};
        use winapi::shared::ws2ipdef::{IPV6_DONTFRAG, IP_DONTFRAGMENT};
        use winapi::um::winsock2::setsockopt;
        let s = socket.as_raw_socket() as winapi::um::winsock2::SOCKET;
        let set = |level: i32, name: i32, value: u32| -> bool {
            // SAFETY: setsockopt on a socket we own with a DWORD value.
            unsafe {
                setsockopt(
                    s,
                    level,
                    name,
                    &value as *const u32 as *const i8,
                    std::mem::size_of::<u32>() as i32,
                ) == 0
            }
        };
        // Probe mode where the system has it (IP_MTU_DISCOVER with
        // IP_PMTUDISC_PROBE, ws2ipdef.h; Windows 10 1703 and later).
        // Older systems refuse the option and keep DF alone.
        const IP_MTU_DISCOVER: i32 = 71;
        const IPV6_MTU_DISCOVER: i32 = 71;
        const IP_PMTUDISC_PROBE: u32 = 3;
        if speaks_v4 {
            out.v4 = set(IPPROTO_IP, IP_DONTFRAGMENT, 1);
            set(IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE);
        }
        if is_v6 {
            out.v6 = set(IPPROTO_IPV6 as i32, IPV6_DONTFRAG, 1);
            set(IPPROTO_IPV6 as i32, IPV6_MTU_DISCOVER, IP_PMTUDISC_PROBE);
        }
    }
    let _ = (speaks_v4, is_v6);
    out
}

#[cfg(unix)]
#[allow(dead_code)]
fn set_int_option(
    socket: &UdpSocket,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> bool {
    use std::os::unix::io::AsRawFd;
    // SAFETY: plain setsockopt on a socket we own, with a correctly sized
    // integer option value.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) == 0
    }
}

/// On Windows, an ICMP "port unreachable" caused by an earlier send makes the
/// next `recv_from` on a UDP socket fail with WSAECONNRESET. A receiver that
/// serves many peers must not be disturbed by one peer going away, so the
/// behaviour is switched off (SIO_UDP_CONNRESET = FALSE). No-op elsewhere.
pub fn disable_udp_connreset(socket: &UdpSocket) {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use winapi::um::winsock2::WSAIoctl;
        // _WSAIOW(IOC_VENDOR, 12)
        const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
        let mut enable: u32 = 0;
        let mut returned: u32 = 0;
        // SAFETY: documented ioctl on a socket we own; input is a 4-byte BOOL,
        // no output buffer, synchronous call.
        unsafe {
            WSAIoctl(
                socket.as_raw_socket() as winapi::um::winsock2::SOCKET,
                SIO_UDP_CONNRESET,
                &mut enable as *mut u32 as *mut winapi::ctypes::c_void,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
                None,
            );
        }
    }
    #[cfg(not(windows))]
    {
        let _ = socket;
    }
}

/// True for send errors caused by a datagram exceeding the path MTU.
pub fn is_msgsize_error(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::EMSGSIZE)
    }
    #[cfg(windows)]
    {
        // WSAEMSGSIZE
        e.raw_os_error() == Some(10040)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = e;
        false
    }
}

/// Monotonic microsecond clock truncated to 32 bits (wraps every ~71 min;
/// consumers use wrapping subtraction).
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    origin: Instant,
}

impl Clock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }

    pub fn now_us(&self) -> u32 {
        self.origin.elapsed().as_micros() as u32
    }

    pub fn now_us_at(&self, at: Instant) -> u32 {
        at.saturating_duration_since(self.origin).as_micros() as u32
    }

    /// Microseconds elapsed since a timestamp taken from this clock.
    pub fn since_us(&self, ts: u32) -> u32 {
        self.now_us().wrapping_sub(ts)
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}
