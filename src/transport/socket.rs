//! UDP socket setup shared by sender and receiver.

use std::io;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::UdpSocket;

/// Binds a non-blocking UDP socket with enlarged kernel buffers. Bulk UDP at
/// hundreds of Mbit/s overflows the default ~200 KiB receive buffer within
/// milliseconds whenever the application pauses, so we ask for more (the
/// kernel may clamp the request; see `net.core.rmem_max` on Linux).
pub fn bind_udp(addr: SocketAddr, buffer_bytes: usize) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        // Accept IPv4-mapped peers on a v6 wildcard socket where the OS allows.
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

/// Marks outgoing datagrams "don't fragment" so that an oversized probe fails
/// (locally with EMSGSIZE, or by being dropped on the path) instead of being
/// silently fragmented. Best effort; other platforms keep default behaviour.
pub fn set_dont_fragment(socket: &UdpSocket) {
    let is_v6 = socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        // SAFETY: plain setsockopt on a socket we own, with a correctly sized
        // integer option value.
        unsafe {
            let val: libc::c_int = libc::IP_PMTUDISC_DO;
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if is_v6 {
                let val6: libc::c_int = libc::IPV6_PMTUDISC_DO;
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    &val6 as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use winapi::shared::ws2def::{IPPROTO_IP, IPPROTO_IPV6};
        use winapi::shared::ws2ipdef::{IPV6_DONTFRAG, IP_DONTFRAGMENT};
        use winapi::um::winsock2::setsockopt;
        let s = socket.as_raw_socket() as winapi::um::winsock2::SOCKET;
        let val: u32 = 1;
        // SAFETY: setsockopt on a socket we own with a DWORD option value.
        unsafe {
            setsockopt(
                s,
                IPPROTO_IP,
                IP_DONTFRAGMENT,
                &val as *const u32 as *const i8,
                std::mem::size_of::<u32>() as i32,
            );
            if is_v6 {
                setsockopt(
                    s,
                    IPPROTO_IPV6 as i32,
                    IPV6_DONTFRAG,
                    &val as *const u32 as *const i8,
                    std::mem::size_of::<u32>() as i32,
                );
            }
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (socket, is_v6);
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
