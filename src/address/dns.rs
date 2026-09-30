//! Name resolution the way RFC 8305 (Happy Eyeballs version 2) wants it:
//! one address family at a time, acted on as each answers.
//!
//! The system resolver asked for "any family" returns only once both the
//! IPv6 (AAAA) and the IPv4 (A) query are done, so a name server that sits
//! on one of them — AAAA, usually — holds the other hostage for its whole
//! timeout. Section 3 of the RFC asks for the two queries to go out
//! separately and for connection attempts to start as soon as there is
//! something to attempt, IPv6 first unless it is late. `getaddrinfo` asked
//! for one family at a time, on two blocking threads, is the portable way
//! to get that and still honour everything the system resolver knows: the
//! hosts file, the configured name servers, DNS64 on an IPv6-only network,
//! mDNS where it is set up.
//!
//! Like every answer from the network, what comes back is a list of
//! guesses (see [`super::resolve_all`]): the handshake decides who is who.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, Instant};

/// Which address family to ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// How long an A answer that arrives first waits for the AAAA one before
/// it is used anyway (RFC 8305 section 3 recommends 50 ms).
pub const RESOLUTION_DELAY: Duration = Duration::from_millis(50);
/// The most one family's lookup may take. Past this it counts as having
/// no answer, and the other family's addresses stop waiting for it.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Looks up the addresses of one family `host` has, with `port` attached.
/// The name is looked up as given — a literal address is answered by the
/// resolver like any other name, which is not what [`super::resolve_all`]
/// does with one.
pub async fn lookup(host: &str, port: u16, family: Family) -> io::Result<Vec<SocketAddr>> {
    let host = host.to_string();
    let ips = tokio::task::spawn_blocking(move || getaddrinfo(&host, family))
        .await
        .map_err(io::Error::other)??;
    Ok(ips
        .into_iter()
        .map(|(ip, scope)| match ip {
            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope)),
            IpAddr::V4(v4) => SocketAddr::new(v4.into(), port),
        })
        .collect())
}

#[cfg(unix)]
#[allow(unsafe_code)] // getaddrinfo(3) and its list (docs/UNSAFE.md)
fn getaddrinfo(host: &str, family: Family) -> io::Result<Vec<(IpAddr, u32)>> {
    use std::ffi::{CStr, CString};
    let name = CString::new(host)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a name cannot contain NUL"))?;
    // SAFETY: addrinfo is plain data, integers and pointers; all zeroes,
    // null pointers included, is the documented way to start hints.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = match family {
        Family::V4 => libc::AF_INET,
        Family::V6 => libc::AF_INET6,
    };
    hints.ai_socktype = libc::SOCK_DGRAM;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: a NUL-terminated name, no service, initialised hints and a
    // place for the result, all alive for the call.
    let rc = unsafe { libc::getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if rc != 0 {
        if rc == libc::EAI_SYSTEM {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: gai_strerror takes any code.
        let text = unsafe { libc::gai_strerror(rc) };
        let what = if text.is_null() {
            format!("resolver error {}", rc)
        } else {
            // SAFETY: what gai_strerror returns is a NUL-terminated string
            // that lives as long as the program.
            unsafe { CStr::from_ptr(text) }
                .to_string_lossy()
                .into_owned()
        };
        let kind = if rc == libc::EAI_AGAIN {
            io::ErrorKind::TimedOut
        } else {
            io::ErrorKind::NotFound
        };
        return Err(io::Error::new(kind, what));
    }
    // SAFETY: the list a successful getaddrinfo returned, not yet freed.
    let out = unsafe { addresses_in(res) };
    // SAFETY: `res` came from a successful getaddrinfo, nothing refers to
    // it any more, and it is freed once.
    unsafe { libc::freeaddrinfo(res) };
    Ok(out)
}

/// The addresses in a list of `addrinfo`, in its order and without
/// repeats, each read as what its family and length say it is; entries of
/// another family, or too short, are passed over.
///
/// # Safety
///
/// `list` is null or the first of a list linked by `ai_next`, each entry's
/// `ai_addr` null or pointing to `ai_addrlen` readable bytes, all of it
/// valid for the call. Nothing more is promised of the addresses: they are
/// read wherever they lie, aligned or not.
#[cfg(unix)]
#[allow(unsafe_code)] // reading getaddrinfo's list (docs/UNSAFE.md)
unsafe fn addresses_in(list: *const libc::addrinfo) -> Vec<(IpAddr, u32)> {
    let mut out = Vec::new();
    let mut p = list;
    while !p.is_null() {
        // SAFETY: the caller's promise: `p` is an entry of the list. `ai` is
        // not kept past this turn of the loop.
        let ai = unsafe { &*p };
        let len = ai.ai_addrlen as usize;
        if !ai.ai_addr.is_null() {
            if ai.ai_family == libc::AF_INET && len >= std::mem::size_of::<libc::sockaddr_in>() {
                // SAFETY: the entry says its address is a sockaddr_in and has
                // that many bytes. Read without a reference: nothing promises
                // a `*mut sockaddr`, aligned for two bytes, the four a
                // sockaddr_in wants.
                let sin =
                    unsafe { std::ptr::read_unaligned(ai.ai_addr as *const libc::sockaddr_in) };
                out.push((
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))),
                    0,
                ));
            } else if ai.ai_family == libc::AF_INET6
                && len >= std::mem::size_of::<libc::sockaddr_in6>()
            {
                // SAFETY: as for sockaddr_in, a sockaddr_in6 of that many bytes.
                let sin6 =
                    unsafe { std::ptr::read_unaligned(ai.ai_addr as *const libc::sockaddr_in6) };
                out.push((
                    IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)),
                    sin6.sin6_scope_id,
                ));
            }
        }
        p = ai.ai_next;
    }
    out.dedup();
    out
}

#[cfg(windows)]
#[allow(unsafe_code)] // getaddrinfo and its list (docs/UNSAFE.md)
fn getaddrinfo(host: &str, family: Family) -> io::Result<Vec<(IpAddr, u32)>> {
    use std::ffi::CString;
    use winapi::shared::ws2def::{ADDRINFOA, AF_INET, AF_INET6, SOCKADDR_IN, SOCK_DGRAM};
    use winapi::shared::ws2ipdef::SOCKADDR_IN6_LH;
    use winapi::um::ws2tcpip::{freeaddrinfo, getaddrinfo};
    winsock_ready();
    let name = CString::new(host)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a name cannot contain NUL"))?;
    // SAFETY: ADDRINFOA is plain data, integers and pointers; all zeroes,
    // null pointers included, is the documented way to start hints.
    let mut hints: ADDRINFOA = unsafe { std::mem::zeroed() };
    hints.ai_family = match family {
        Family::V4 => AF_INET,
        Family::V6 => AF_INET6,
    };
    hints.ai_socktype = SOCK_DGRAM;
    let mut res: *mut ADDRINFOA = std::ptr::null_mut();
    // SAFETY: a NUL-terminated name, no service, initialised hints and a
    // place for the result, all alive for the call.
    let rc = unsafe { getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    let mut out = Vec::new();
    let mut p = res;
    while !p.is_null() {
        // SAFETY: as for the Unix version: `p` is an entry of the list,
        // valid until freeaddrinfo, and `ai` is not kept past this turn.
        let ai = unsafe { &*p };
        if !ai.ai_addr.is_null() {
            if ai.ai_family == AF_INET && ai.ai_addrlen >= std::mem::size_of::<SOCKADDR_IN>() {
                // SAFETY: a SOCKADDR_IN of that many bytes, read without a
                // reference (see the Unix version).
                let sin = unsafe { std::ptr::read_unaligned(ai.ai_addr as *const SOCKADDR_IN) };
                // SAFETY: IN_ADDR's union is the same four bytes whichever way
                // it is read.
                let raw = unsafe { *sin.sin_addr.S_un.S_addr() };
                out.push((IpAddr::V4(Ipv4Addr::from(u32::from_be(raw))), 0));
            } else if ai.ai_family == AF_INET6
                && ai.ai_addrlen >= std::mem::size_of::<SOCKADDR_IN6_LH>()
            {
                // SAFETY: as for SOCKADDR_IN, a SOCKADDR_IN6_LH of that many
                // bytes.
                let sin6 =
                    unsafe { std::ptr::read_unaligned(ai.ai_addr as *const SOCKADDR_IN6_LH) };
                // SAFETY: IN6_ADDR's union is the same sixteen bytes whichever
                // way it is read.
                let bytes = unsafe { *sin6.sin6_addr.u.Byte() };
                // SAFETY: the scope id and the scope structure are the same
                // four bytes.
                let scope = unsafe { *sin6.u.sin6_scope_id() };
                out.push((IpAddr::V6(Ipv6Addr::from(bytes)), scope));
            }
        }
        p = ai.ai_next;
    }
    // SAFETY: `res` came from a successful getaddrinfo, nothing refers to
    // it any more, and it is freed once.
    unsafe { freeaddrinfo(res) };
    out.dedup();
    Ok(out)
}

/// Winsock has to be started before `getaddrinfo` works; the standard
/// library does it on first use of its own networking, which may not have
/// happened yet. Starting it again is harmless: it counts.
#[cfg(windows)]
#[allow(unsafe_code)] // WSAStartup (docs/UNSAFE.md)
fn winsock_ready() {
    static START: std::sync::Once = std::sync::Once::new();
    START.call_once(|| {
        // SAFETY: WSADATA is plain data for WSAStartup to fill in.
        let mut data: winapi::um::winsock2::WSADATA = unsafe { std::mem::zeroed() };
        // SAFETY: version 2.2 and a WSADATA to fill; a failure shows as
        // getaddrinfo's error.
        unsafe { winapi::um::winsock2::WSAStartup(0x0202, &mut data) };
    });
}

#[cfg(not(any(unix, windows)))]
fn getaddrinfo(host: &str, family: Family) -> io::Result<Vec<(IpAddr, u32)>> {
    use std::net::ToSocketAddrs;
    Ok((host, 0)
        .to_socket_addrs()?
        .filter(|a| a.is_ipv6() == (family == Family::V6))
        .map(|a| match a {
            SocketAddr::V6(v6) => (IpAddr::V6(*v6.ip()), v6.scope_id()),
            SocketAddr::V4(v4) => (IpAddr::V4(*v4.ip()), 0),
        })
        .collect())
}

/// Decides, as the two families' answers come in, which address goes out
/// next and when (RFC 8305 sections 3 and 4).
///
/// * IPv6 goes first: an AAAA answer is used the moment it arrives, while
///   an A answer that beats it waits [`RESOLUTION_DELAY`] for it.
/// * After the first address the families take turns, so neither can fill
///   the list of attempts on its own.
/// * A family whose answer is still outstanding is waited for, but only
///   for `pace` — the gap the caller leaves between attempts anyway — per
///   address the other family has ready; past that, the other family's
///   next address goes out, and the late family joins in when it answers.
///
/// Pure logic, so that the timing rules can be tested without a network.
#[derive(Debug)]
pub(crate) struct Interleaver {
    q6: VecDeque<SocketAddr>,
    q4: VecDeque<SocketAddr>,
    done6: bool,
    done4: bool,
    next_v6: bool,
    started: bool,
    hold_until: Option<Instant>,
    pace: Duration,
    seen: Vec<SocketAddr>,
    limit: usize,
}

impl Interleaver {
    pub(crate) fn new(want_v6: bool, want_v4: bool, pace: Duration, limit: usize) -> Self {
        Self {
            q6: VecDeque::new(),
            q4: VecDeque::new(),
            done6: !want_v6,
            done4: !want_v4,
            next_v6: want_v6,
            started: false,
            hold_until: None,
            pace,
            seen: Vec::new(),
            limit,
        }
    }

    /// One family has answered (an error counts as an answer with nothing
    /// in it).
    pub(crate) fn answer(&mut self, family: Family, addrs: Vec<SocketAddr>) {
        let (q, done) = match family {
            Family::V6 => (&mut self.q6, &mut self.done6),
            Family::V4 => (&mut self.q4, &mut self.done4),
        };
        *done = true;
        for a in addrs {
            if !self.seen.contains(&a) && self.seen.len() < self.limit {
                self.seen.push(a);
                q.push_back(a);
            }
        }
    }

    pub(crate) fn waiting_for(&self, family: Family) -> bool {
        match family {
            Family::V6 => !self.done6,
            Family::V4 => !self.done4,
        }
    }

    /// Everything answered and handed out.
    pub(crate) fn finished(&self) -> bool {
        self.done6 && self.done4 && self.q6.is_empty() && self.q4.is_empty()
    }

    /// What goes out now, and when to ask again if something is being
    /// held back.
    pub(crate) fn poll(&mut self, now: Instant) -> (Vec<SocketAddr>, Option<Instant>) {
        let mut out = Vec::new();
        loop {
            let want_v6 = self.next_v6;
            let (want_q, want_done, other_q) = if want_v6 {
                (&mut self.q6, self.done6, &mut self.q4)
            } else {
                (&mut self.q4, self.done4, &mut self.q6)
            };
            if let Some(a) = want_q.pop_front() {
                out.push(a);
                self.started = true;
                self.hold_until = None;
                self.next_v6 = !want_v6;
                continue;
            }
            if other_q.is_empty() {
                return (out, None);
            }
            if want_done {
                // Its turn, but it has nothing and never will.
                out.extend(other_q.pop_front());
                self.started = true;
                continue;
            }
            // Its turn, its answer is still out, and the other family has
            // something ready: hold that back, but not for long.
            let delay = if !self.started && want_v6 {
                RESOLUTION_DELAY
            } else {
                self.pace
            };
            let until = *self.hold_until.get_or_insert(now + delay);
            if now < until {
                return (out, Some(until));
            }
            out.extend(other_q.pop_front());
            self.started = true;
            self.hold_until = None;
        }
    }
}

/// Resolves `host` for both families at once and hands each address to
/// `deliver` when `Interleaver` says so. `want_v6`/`want_v4` leave out a
/// family the caller cannot use (an IPv4-only socket has no use for AAAA
/// answers, and asking costs a round trip to the name server).
///
/// Returns how many addresses were delivered, or the error of the last
/// family to fail when there were none.
pub async fn resolve_happily(
    host: &str,
    port: u16,
    want_v6: bool,
    want_v4: bool,
    pace: Duration,
    limit: usize,
    mut deliver: impl FnMut(SocketAddr),
) -> io::Result<usize> {
    let mut il = Interleaver::new(want_v6, want_v4, pace, limit);
    let bounded = |family| async move {
        match tokio::time::timeout(LOOKUP_TIMEOUT, lookup(host, port, family)).await {
            Ok(r) => r,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{} did not resolve in time", host),
            )),
        }
    };
    let v6 = bounded(Family::V6);
    let v4 = bounded(Family::V4);
    tokio::pin!(v6, v4);
    let mut delivered = 0usize;
    let mut last_error: Option<io::Error> = None;
    loop {
        let (now_out, wake) = il.poll(Instant::now());
        for a in now_out {
            delivered += 1;
            deliver(a);
        }
        if il.finished() {
            break;
        }
        let wake = wake.map(tokio::time::Instant::from_std);
        tokio::select! {
            r = &mut v6, if il.waiting_for(Family::V6) => {
                let got = r.unwrap_or_else(|e| { last_error = Some(e); Vec::new() });
                il.answer(Family::V6, sorted(got));
            }
            r = &mut v4, if il.waiting_for(Family::V4) => {
                let got = r.unwrap_or_else(|e| { last_error = Some(e); Vec::new() });
                il.answer(Family::V4, sorted(got));
            }
            _ = sleep_until_opt(wake) => {}
        }
    }
    if delivered == 0 {
        return Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} has no address this host can use", host),
            )
        }));
    }
    Ok(delivered)
}

async fn sleep_until_opt(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// One family's answer in the order RFC 6724 would try it.
fn sorted(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    super::class::sort_destinations(&mut addrs);
    addrs
}

/// Splits `host:port` into its parts. An IPv6 literal has to be written in
/// brackets (`[2001:db8::1]:5555`), as in a URL: without them there is no
/// telling where the address ends and the port begins.
pub fn split_host_port(s: &str) -> io::Result<(&str, u16)> {
    let bad =
        |why: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("\"{}\": {}", s, why));
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| bad("an opening bracket without a closing one"))?;
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| bad("no port after the address"))?;
        (host, port)
    } else {
        let (host, port) = s.rsplit_once(':').ok_or_else(|| bad("no port"))?;
        if host.contains(':') {
            return Err(bad(
                "an IPv6 address has to be written in brackets, [address]:port",
            ));
        }
        (host, port)
    };
    if host.is_empty() {
        return Err(bad("no host"));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| bad("the port is not a number from 0 to 65535"))?;
    Ok((host, port))
}

/// Parses an address literal, including an IPv6 one whose zone is written
/// as an interface name (`[fe80::1%eth0]:5555`), which the standard library
/// only accepts as a number.
pub fn parse_literal(s: &str) -> Option<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    let (host, port) = split_host_port(s).ok()?;
    let (ip, zone) = host.split_once('%')?;
    let ip: Ipv6Addr = ip.parse().ok()?;
    let scope = interface_index(zone)?;
    Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)))
}

/// The system's index for the interface called `name`.
pub fn interface_index_of(name: &str) -> Option<u32> {
    interface_index(name)
}

#[cfg(unix)]
#[allow(unsafe_code)] // if_nametoindex(3) (docs/UNSAFE.md)
fn interface_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: a NUL-terminated interface name; 0 means "no such interface".
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(windows)]
#[allow(unsafe_code)] // if_nametoindex (docs/UNSAFE.md)
fn interface_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: a NUL-terminated interface name; 0 means "no such interface".
    let index = unsafe { winapi::shared::netioapi::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(not(any(unix, windows)))]
fn interface_index(_name: &str) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A list as getaddrinfo gives it, read whatever the alignment of the
    /// addresses in it (here: at odd places): an IPv4 and an IPv6 address
    /// with its scope, in order; an entry with no address, one too short
    /// for its family and one of another family passed over; a repeat
    /// dropped. Taking the addresses by reference, as this once did, fails
    /// here in a debug build (and under Miri: `scripts/miri.sh`).
    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)] // building the list
    fn addresses_are_read_from_the_list_wherever_they_lie() {
        use std::mem::size_of;
        use std::ptr::{null_mut, write_unaligned};
        let (n4, n6) = (
            size_of::<libc::sockaddr_in>(),
            size_of::<libc::sockaddr_in6>(),
        );
        // SAFETY: plain data; all zeroes is a value of it.
        let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_addr.s_addr = u32::from(Ipv4Addr::new(192, 0, 2, 7)).to_be();
        sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sin6.sin6_addr.s6_addr = "fe80::1".parse::<Ipv6Addr>().unwrap().octets();
        sin6.sin6_scope_id = 3;
        let mut buf = vec![0u8; 4 + 1 + n4 + n6];
        let start = buf.as_mut_ptr();
        // One past a multiple of four: misaligned for both, wherever the
        // buffer lies.
        let at4 = start.wrapping_add(start.align_offset(4) + 1);
        let at6 = at4.wrapping_add(n4);
        // SAFETY: both fit in `buf`, at the odd places chosen.
        unsafe { write_unaligned(at4.cast::<libc::sockaddr_in>(), sin) };
        // SAFETY: as above.
        unsafe { write_unaligned(at6.cast::<libc::sockaddr_in6>(), sin6) };
        let entry = |family: libc::c_int, addr: *mut u8, len: usize| {
            // SAFETY: plain data; all zeroes is a value of it.
            let mut ai: libc::addrinfo = unsafe { std::mem::zeroed() };
            ai.ai_family = family;
            ai.ai_addr = addr.cast();
            ai.ai_addrlen = len as libc::socklen_t;
            ai
        };
        let mut list = [
            entry(libc::AF_INET, at4, n4),
            entry(libc::AF_INET, null_mut(), n4),
            entry(libc::AF_INET6, at6, n6 - 1),
            entry(libc::AF_UNIX, at4, n4),
            entry(libc::AF_INET6, at6, n6),
            entry(libc::AF_INET6, at6, n6),
        ];
        // Every link from one pointer to the array, which nothing else
        // touches until the list has been read (a reference taken to link
        // one entry would be undone by the next: Miri says so).
        let base = list.as_mut_ptr();
        for k in 1..list.len() {
            let (prev, next) = (base.wrapping_add(k - 1), base.wrapping_add(k));
            // SAFETY: `prev` is an entry of the array.
            unsafe { (*prev).ai_next = next };
        }
        // SAFETY: a list linked by `ai_next`, each address null or of the
        // bytes it states, all alive for the call.
        let got = unsafe { addresses_in(base) };
        assert_eq!(
            got,
            vec![
                (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 0),
                (IpAddr::V6("fe80::1".parse().unwrap()), 3),
            ]
        );
        // SAFETY: an empty list.
        assert!(unsafe { addresses_in(std::ptr::null()) }.is_empty());
    }

    const PACE: Duration = Duration::from_millis(250);

    /// Both answers at once: IPv6 first, then turns.
    #[test]
    fn interleaves_when_both_answer_together() {
        let t = Instant::now();
        let mut il = Interleaver::new(true, true, PACE, 8);
        il.answer(Family::V4, vec![sa("192.0.2.1:1"), sa("192.0.2.2:1")]);
        il.answer(
            Family::V6,
            vec![
                sa("[2001:db8::1]:1"),
                sa("[2001:db8::2]:1"),
                sa("[2001:db8::3]:1"),
            ],
        );
        let (out, wake) = il.poll(t);
        assert_eq!(
            out,
            [
                sa("[2001:db8::1]:1"),
                sa("192.0.2.1:1"),
                sa("[2001:db8::2]:1"),
                sa("192.0.2.2:1"),
                sa("[2001:db8::3]:1"),
            ]
        );
        assert_eq!(wake, None);
        assert!(il.finished());
    }

    /// An A answer that arrives first waits the resolution delay for AAAA
    /// and no longer; the AAAA addresses join in when they come.
    #[test]
    fn a_first_waits_the_resolution_delay() {
        let t = Instant::now();
        let mut il = Interleaver::new(true, true, PACE, 8);
        il.answer(
            Family::V4,
            vec![sa("192.0.2.1:1"), sa("192.0.2.2:1"), sa("192.0.2.3:1")],
        );
        let (out, wake) = il.poll(t);
        assert!(out.is_empty());
        assert_eq!(wake, Some(t + RESOLUTION_DELAY));
        // Still nothing just before the delay is up.
        let (out, _) = il.poll(t + RESOLUTION_DELAY - Duration::from_millis(1));
        assert!(out.is_empty());
        // Then one IPv4 address, and the next one waits a whole pace.
        let (out, wake) = il.poll(t + RESOLUTION_DELAY);
        assert_eq!(out, [sa("192.0.2.1:1")]);
        let at = t + RESOLUTION_DELAY;
        assert_eq!(wake, Some(at + PACE));
        let (out, _) = il.poll(at + PACE);
        assert_eq!(out, [sa("192.0.2.2:1")]);
        // AAAA arrives: from now on the families alternate.
        il.answer(
            Family::V6,
            vec![sa("[2001:db8::1]:1"), sa("[2001:db8::2]:1")],
        );
        let (out, wake) = il.poll(at + PACE + Duration::from_millis(10));
        assert_eq!(
            out,
            [
                sa("[2001:db8::1]:1"),
                sa("192.0.2.3:1"),
                sa("[2001:db8::2]:1")
            ]
        );
        assert_eq!(wake, None);
        assert!(il.finished());
    }

    /// AAAA within the delay: IPv6 still goes first.
    #[test]
    fn aaaa_within_the_delay_still_leads() {
        let t = Instant::now();
        let mut il = Interleaver::new(true, true, PACE, 8);
        il.answer(Family::V4, vec![sa("192.0.2.1:1")]);
        assert!(il.poll(t).0.is_empty());
        il.answer(Family::V6, vec![sa("[2001:db8::1]:1")]);
        let (out, _) = il.poll(t + Duration::from_millis(20));
        assert_eq!(out, [sa("[2001:db8::1]:1"), sa("192.0.2.1:1")]);
    }

    /// AAAA first: used at once; the IPv4 answer, when late, does not
    /// hold up the remaining IPv6 addresses for more than a pace each.
    #[test]
    fn aaaa_first_is_used_at_once() {
        let t = Instant::now();
        let mut il = Interleaver::new(true, true, PACE, 8);
        il.answer(
            Family::V6,
            vec![sa("[2001:db8::1]:1"), sa("[2001:db8::2]:1")],
        );
        let (out, wake) = il.poll(t);
        assert_eq!(out, [sa("[2001:db8::1]:1")]);
        assert_eq!(wake, Some(t + PACE));
        let (out, wake) = il.poll(t + PACE);
        assert_eq!(out, [sa("[2001:db8::2]:1")]);
        assert_eq!(wake, None);
        // A failed A lookup ends the wait.
        il.answer(Family::V4, Vec::new());
        assert!(il.finished());
    }

    /// A family nobody asked for is never waited for, repeats are dropped,
    /// and the cap holds.
    #[test]
    fn skips_unwanted_families_and_repeats() {
        let t = Instant::now();
        let mut il = Interleaver::new(false, true, PACE, 2);
        il.answer(
            Family::V4,
            vec![
                sa("192.0.2.1:1"),
                sa("192.0.2.1:1"),
                sa("192.0.2.2:1"),
                sa("192.0.2.3:1"),
            ],
        );
        let (out, wake) = il.poll(t);
        assert_eq!(out, [sa("192.0.2.1:1"), sa("192.0.2.2:1")]);
        assert_eq!(wake, None);
        assert!(il.finished());
    }

    #[test]
    fn splits_hosts_and_ports() {
        assert_eq!(
            split_host_port("example.org:5555").unwrap(),
            ("example.org", 5555)
        );
        assert_eq!(split_host_port("192.0.2.1:1").unwrap(), ("192.0.2.1", 1));
        assert_eq!(
            split_host_port("[2001:db8::1]:7").unwrap(),
            ("2001:db8::1", 7)
        );
        assert_eq!(
            split_host_port("[fe80::1%eth0]:7").unwrap(),
            ("fe80::1%eth0", 7)
        );
        for bad in [
            "example.org",
            "2001:db8::1:7",
            "[2001:db8::1]",
            "[2001:db8::1:7",
            ":7",
            "h:99999",
            "h:x",
        ] {
            assert!(split_host_port(bad).is_err(), "{}", bad);
        }
    }

    #[test]
    fn parses_literals_with_zones() {
        assert_eq!(parse_literal("192.0.2.1:5"), Some(sa("192.0.2.1:5")));
        assert_eq!(parse_literal("[fe80::1%3]:5"), Some(sa("[fe80::1%3]:5")));
        assert_eq!(parse_literal("[fe80::1%no-such-interface-here]:5"), None);
        assert_eq!(parse_literal("example.org:5"), None);
        #[cfg(target_os = "linux")]
        {
            let lo = parse_literal("[fe80::1%lo]:5").expect("the loopback interface has an index");
            assert!(matches!(lo, SocketAddr::V6(v6) if v6.scope_id() != 0));
        }
    }

    /// The system resolver, one family at a time.
    #[tokio::test]
    async fn looks_up_one_family_at_a_time() {
        let v4 = lookup("localhost", 9, Family::V4).await.unwrap();
        assert!(!v4.is_empty());
        assert!(v4.iter().all(|a| a.is_ipv4() && a.port() == 9), "{:?}", v4);
        // IPv6 for localhost exists wherever IPv6 does; either way, no
        // IPv4 address may come back from an IPv6 query.
        if let Ok(v6) = lookup("localhost", 9, Family::V6).await {
            assert!(v6.iter().all(|a| a.is_ipv6()), "{:?}", v6);
        }
        assert!(lookup("no-such-name.invalid", 9, Family::V4).await.is_err());
    }

    #[tokio::test]
    async fn resolves_happily() {
        let mut got = Vec::new();
        let n = resolve_happily("localhost", 9, true, true, PACE, 8, |a| got.push(a))
            .await
            .unwrap();
        assert_eq!(n, got.len());
        assert!(got.iter().any(|a| a.is_ipv4()), "{:?}", got);
        let err = resolve_happily("no-such-name.invalid", 9, true, true, PACE, 8, |_| {}).await;
        assert!(err.is_err());
    }
}
