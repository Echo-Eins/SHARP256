//! UPnP IGD port mapping for the receiver: asks the home router to forward a
//! UDP port to the receiver's socket so that senders outside the local
//! network can reach it — or, over IPv6, where nothing is translated, to open
//! its firewall to it.
//!
//! A small client of its own rather than a general-purpose one, because of
//! who it talks to. UPnP has no authentication at all: the router is found
//! by a multicast search that anything on the local network may answer, and
//! the answer names a URL the client then fetches and posts to. A client
//! that believes that answer, waits on it for as long as it takes and reads
//! whatever it sends back can be made to connect wherever a stranger likes —
//! this host's loopback services included — to hang there for ever, or to
//! read until memory runs out. So here:
//!
//! * a device is believed only if it is on a local network of ours, and only
//!   about itself: it is asked at the very address that answered the search
//!   (the description and control URLs must be on it, and over IPv6 only the
//!   port and path of the answer's URL are used — a router that answers from
//!   its link-local address and names its global one is asked at the first);
//! * every step has its own deadline, and the whole attempt one more;
//! * every response has a size limit, and anything past it is an error.
//!
//! The protocol is the UPnP Device Architecture 1.1 (SSDP discovery, the
//! device description, SOAP control) with the WANIPConnection:1/2 and
//! WANPPPConnection:1 services, over HTTP/1.0 so that nothing arrives
//! chunked. A firewall pinhole is asked for over IPv6 — the search goes to
//! the IPv6 groups on every network, and the request leaves from the address
//! the pinhole is for, because that is the only one a router lets a host open
//! a pinhole to (miniupnpd's default, and what the IGD v2 specification
//! recommends) — and, where a router turns out to answer only over IPv4,
//! there too.

use anyhow::{anyhow, bail, Result};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::address::class::is_link_local_v6;

/// Where routers listen for searches (UPnP Device Architecture 1.1, 1.3.2).
pub const SSDP_TARGET: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900));
/// ... and over IPv6: the link-local and the site-local group (same place).
const SSDP_GROUPS_V6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xc),
    Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0xc),
];
/// What is searched for, newest first.
const SEARCH_TARGETS: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
];
/// How long to wait for search answers.
const SEARCH_WAIT: Duration = Duration::from_secs(2);
/// How much longer, once a router has answered on one network, the others
/// are given to answer (a host is often on several, and a router on each).
const SEARCH_GRACE: Duration = Duration::from_millis(150);
/// Networks searched over IPv6, at most.
const MAX_LINKS: usize = 8;
/// How long one HTTP exchange may take, connecting included.
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a whole attempt at a mapping may take.
const CREATE_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest device description read, and largest SOAP answer.
const MAX_DESCRIPTION: usize = 64 << 10;
const MAX_SOAP_RESPONSE: usize = 16 << 10;
/// Search answers looked at, at most.
const MAX_ANSWERS: usize = 16;

/// The services that can forward a port, best first.
const SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

/// The service that opens an IPv6 firewall to a port (UPnP IGD v2,
/// WANIPv6FirewallControl:1): there is nothing to translate over IPv6, but
/// the router's firewall drops what nobody inside asked for, and this is how
/// a host asks for a hole (a "pinhole").
const FIREWALL_SERVICE: &str = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";

/// UPnP error codes worth telling apart (UPnP IGD WANIPConnection:2, 2.5).
const CONFLICT_IN_MAPPING: u32 = 718;
const ONLY_PERMANENT_LEASES: u32 = 725;

/// An `http://address:port/path` URL on one device, the address a literal
/// IPv4 or IPv6 one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Url {
    host: SocketAddr,
    path: String,
    /// The address requests to the device leave from, where it matters: a
    /// router lets a host open its IPv6 firewall to that host's own address
    /// only, as seen on the request.
    source: Option<IpAddr>,
}

/// `a.b.c.d[:port]` or `[v6][:port]`. A zone on an IPv6 address
/// (`%25eth0`, RFC 6874) names an interface of the device's own host, which
/// means nothing here: it is dropped, and the network is the one the device
/// answered on.
fn parse_authority(authority: &str) -> Option<SocketAddr> {
    if let Some(inner) = authority.strip_prefix('[') {
        let (addr, rest) = inner.split_once(']')?;
        let addr = addr.split_once('%').map_or(addr, |(a, _)| a);
        let ip: Ipv6Addr = addr.parse().ok()?;
        // A router names itself by its own address, not as an IPv4 one in
        // disguise.
        if ip.to_ipv4_mapped().is_some() {
            return None;
        }
        let port = match rest {
            "" => 80,
            r => r.strip_prefix(':')?.parse().ok()?,
        };
        return Some(SocketAddr::new(IpAddr::V6(ip), port));
    }
    Some(match authority.rsplit_once(':') {
        Some((ip, port)) => SocketAddr::V4(SocketAddrV4::new(ip.parse().ok()?, port.parse().ok()?)),
        None => SocketAddr::V4(SocketAddrV4::new(authority.parse().ok()?, 80)),
    })
}

/// `a.b.c.d:port` or `[v6]:port`, as HTTP's Host header has it: without the
/// zone a link-local address is given here, which a router has no use for.
fn authority(host: SocketAddr) -> String {
    match host {
        SocketAddr::V4(a) => a.to_string(),
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    }
}

impl Url {
    /// Only plain HTTP to a literal address: a router names itself by
    /// address, and a name would need a DNS lookup somebody else answers.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let rest = s.trim().strip_prefix("http://")?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let host = parse_authority(authority)?;
        if path.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return None;
        }
        Some(Self {
            host,
            path: path.to_string(),
            source: None,
        })
    }

    /// `reference` resolved against this URL: an absolute URL as it is, a
    /// path relative to this one's host.
    pub(crate) fn join(&self, reference: &str) -> Option<Self> {
        let r = reference.trim();
        if r.starts_with("http://") {
            return Self::parse(r);
        }
        if r.is_empty() || r.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return None;
        }
        let path = if r.starts_with('/') {
            r.to_string()
        } else {
            let dir = &self.path[..self.path.rfind('/').map_or(0, |i| i + 1)];
            format!("{}{}", if dir.is_empty() { "/" } else { dir }, r)
        };
        Some(Self {
            host: self.host,
            path,
            source: self.source,
        })
    }
}

/// A router's port-forwarding service.
#[derive(Debug, Clone)]
pub(crate) struct Service {
    control: Url,
    kind: &'static str,
}

/// Whether a device at `ip` is one we may believe about itself: on a local
/// subnet of ours, and an address a router has. Loopback only when the
/// search itself went to loopback (the tests' simulated router).
fn believable(ip: IpAddr, search: SocketAddr) -> bool {
    let ip = match ip {
        IpAddr::V4(ip) => ip,
        // Over IPv6 the networks are searched one by one (`answer_v6`); an
        // IPv6 answer to a search of one address is the tests' loopback.
        IpAddr::V6(ip) => return ip.is_loopback() && search.ip().is_loopback(),
    };
    if ip.is_loopback() {
        return search.ip().is_loopback();
    }
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        return false;
    }
    let private = ip.is_private()
        || ip.is_link_local()
        || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]));
    private && on_link(ip)
}

/// Whether `ip` is on one of this host's IPv4 subnets.
fn on_link(ip: Ipv4Addr) -> bool {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return false;
    };
    ifaces.iter().any(|i| match &i.addr {
        if_addrs::IfAddr::V4(v4) => {
            let mask = u32::from(v4.netmask);
            mask != 0 && u32::from(v4.ip) & mask == u32::from(ip) & mask
        }
        _ => false,
    })
}

/// A router found by a search: where to ask it, and — for one found over
/// IPv6 — which of this host's addresses are on the network it answered on
/// (a pinhole can be opened for those only).
#[derive(Debug, Clone)]
struct Found {
    url: Url,
    link: Option<Vec<Ipv6Addr>>,
}

/// Where a search goes.
#[derive(Debug, Clone, Copy)]
enum Reach {
    /// The networks this host is on.
    Lan,
    /// One unicast address: the tests' simulated router on loopback.
    At(SocketAddr),
}

/// The search request for `st`, sent to the group or address `host`.
fn m_search(host: &str, st: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {}\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {}\r\n\r\n",
        host, st
    )
}

/// The routers to ask: over IPv4 always, and with `v6` over every network
/// this host has IPv6 on, those first.
async fn find_routers(reach: Reach, v6: bool) -> Result<Vec<Found>> {
    match reach {
        Reach::At(target) => search_at(target).await,
        Reach::Lan if !v6 => search_at(SSDP_TARGET).await,
        Reach::Lan => {
            let links = links_v6();
            let (over_v6, over_v4) = tokio::join!(search_links(&links), search_at(SSDP_TARGET));
            let mut found = over_v6;
            found.extend(over_v4.unwrap_or_default());
            Ok(found)
        }
    }
}

/// Sends an SSDP search to `target` and returns the routers that answered
/// believably, in the order they answered.
async fn search_at(target: SocketAddr) -> Result<Vec<Found>> {
    let sock = UdpSocket::bind(match target {
        SocketAddr::V4(t) if t.ip().is_loopback() => "127.0.0.1:0",
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::1]:0",
    })
    .await?;
    let _ = sock.set_multicast_ttl_v4(2);
    let mut found: Vec<Found> = Vec::new();
    for st in SEARCH_TARGETS {
        let msg = m_search("239.255.255.250:1900", st);
        sock.send_to(msg.as_bytes(), target).await?;
    }
    let deadline = tokio::time::Instant::now() + SEARCH_WAIT;
    let mut buf = [0u8; 2048];
    let mut answers = 0;
    while answers < MAX_ANSWERS {
        let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await
        else {
            break;
        };
        answers += 1;
        let Ok(text) = std::str::from_utf8(&buf[..n]) else {
            continue;
        };
        let Some(location) = header(text, "location").and_then(Url::parse) else {
            continue;
        };
        // About itself, and from nearby: a device that points us anywhere
        // but its own address — this host's loopback, say, or another
        // machine — is not a router telling us where it lives.
        if location.host.ip() != from.ip() || !believable(from.ip(), target) {
            tracing::debug!(
                "UPnP: ignoring {} (answered from {}, not believable)",
                location.host,
                from
            );
            continue;
        }
        if !found.iter().any(|f| f.url == location) {
            found.push(Found {
                url: location,
                link: None,
            });
        }
        // The first believable router will do.
        break;
    }
    Ok(found)
}

/// A network this host has IPv6 on: where an IPv6 search is sent, and what
/// makes an answer to it believable.
#[derive(Debug, Clone)]
struct Link {
    index: u32,
    /// This host's addresses there, with their prefix lengths.
    addrs: Vec<(Ipv6Addr, u32)>,
}

/// The networks to search over IPv6: those this host has an IPv6 address on.
/// (The system's list of addresses leaves the link-local ones out, and a
/// network with only those has nothing a pinhole could be opened for.)
fn links_v6() -> Vec<Link> {
    let Ok(all) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut links: Vec<Link> = Vec::new();
    for i in all {
        let if_addrs::IfAddr::V6(a) = &i.addr else {
            continue;
        };
        if i.is_loopback() {
            continue;
        }
        let Some(index) = crate::address::dns::interface_index_of(&i.name) else {
            continue;
        };
        let entry = (a.ip, u128::from(a.netmask).leading_ones());
        match links.iter_mut().find(|l| l.index == index) {
            Some(l) => l.addrs.push(entry),
            None => links.push(Link {
                index,
                addrs: vec![entry],
            }),
        }
    }
    links.truncate(MAX_LINKS);
    links
}

/// Whether `a` and `b` share their first `len` bits.
fn same_prefix(a: Ipv6Addr, b: Ipv6Addr, len: u32) -> bool {
    len > 0 && len <= 128 && (u128::from(a) ^ u128::from(b)) >> (128 - len) == 0
}

/// Whether `ip` is an address a router on `link` has: not a group or a
/// nowhere, and either link-local or inside a prefix this host has there.
fn believable_on(ip: Ipv6Addr, link: &Link) -> bool {
    if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
        return false;
    }
    is_link_local_v6(&ip)
        || link
            .addrs
            .iter()
            .any(|&(own, len)| same_prefix(own, ip, len))
}

/// An IPv6 socket that sends its multicast out of the network `index`.
fn search_socket_v6(index: u32) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_only_v6(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
    s.set_multicast_if_v6(index)?;
    // UPnP Device Architecture 1.1 asks for a hop limit of 4.
    s.set_multicast_hops_v6(4)?;
    s.set_multicast_loop_v6(false)?;
    UdpSocket::from_std(s.into())
}

/// What one IPv6 answer says, if it is believable: the router that sent it
/// on `link` is asked at the address it sent it from, at the port and path
/// its `LOCATION` gives.
fn answer_v6(data: &[u8], from: SocketAddrV6, link: &Link) -> Option<Found> {
    let text = std::str::from_utf8(data).ok()?;
    let location = header(text, "location").and_then(Url::parse)?;
    let SocketAddr::V6(named) = location.host else {
        return None;
    };
    // Heard on this network (a link-local sender says which it is on), from
    // an address a router on it has.
    let here = from.scope_id() == 0 || from.scope_id() == link.index;
    if !here || !believable_on(*from.ip(), link) {
        tracing::debug!(
            "UPnP: ignoring {} (not believable on network {})",
            from,
            link.index
        );
        return None;
    }
    let scope = if is_link_local_v6(from.ip()) {
        link.index
    } else {
        0
    };
    if named.ip() != from.ip() {
        tracing::debug!(
            "UPnP: {} names {} for its description; asking it at its own address",
            from.ip(),
            named.ip()
        );
    }
    Some(Found {
        url: Url {
            host: SocketAddr::V6(SocketAddrV6::new(*from.ip(), named.port(), 0, scope)),
            path: location.path,
            source: None,
        },
        link: Some(link.addrs.iter().map(|(ip, _)| *ip).collect()),
    })
}

/// An IPv6 search answer through everything that reads it, as if it came
/// from a link-local address on a network of this host's: for the fuzz
/// harness.
#[cfg(any(test, fuzzing))]
pub(crate) fn fuzz_answer_v6(data: &[u8]) {
    let link = Link {
        index: 3,
        addrs: vec![
            (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2), 64),
            (Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 2), 64),
        ],
    };
    let from = SocketAddrV6::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 1900, 0, 3);
    let _ = answer_v6(data, from, &link);
}

/// Searches every network in `links` over IPv6 and returns the routers that
/// answered believably, the first at once and the rest within a moment.
async fn search_links(links: &[Link]) -> Vec<Found> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddrV6, usize)>(64);
    // Dropped with this function, whatever way it ends.
    let mut readers = tokio::task::JoinSet::new();
    for (position, link) in links.iter().enumerate() {
        let Ok(sock) = search_socket_v6(link.index) else {
            continue;
        };
        let sock = Arc::new(sock);
        for group in SSDP_GROUPS_V6 {
            let to = SocketAddr::V6(SocketAddrV6::new(group, 1900, 0, link.index));
            for st in SEARCH_TARGETS {
                let msg = m_search(&format!("[{}]:1900", group), st);
                let _ = sock.send_to(msg.as_bytes(), to).await;
            }
        }
        let tx = tx.clone();
        readers.spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                if let SocketAddr::V6(from) = from {
                    if tx.send((buf[..n].to_vec(), from, position)).await.is_err() {
                        return;
                    }
                }
            }
        });
    }
    drop(tx);
    let mut deadline = tokio::time::Instant::now() + SEARCH_WAIT;
    let mut found: Vec<Found> = Vec::new();
    let mut answers = 0;
    while answers < MAX_ANSWERS {
        let Ok(Some((data, from, position))) = tokio::time::timeout_at(deadline, rx.recv()).await
        else {
            break;
        };
        answers += 1;
        let Some(router) = answer_v6(&data, from, &links[position]) else {
            continue;
        };
        if !found.iter().any(|f| f.url == router.url) {
            if found.is_empty() {
                deadline = deadline.min(tokio::time::Instant::now() + SEARCH_GRACE);
            }
            found.push(router);
        }
    }
    found
}

/// The value of an HTTP-style header in `text`, case-insensitively.
pub(crate) fn header<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// A connection to a device, from the address the device is to see the
/// requests come from if one was named.
async fn connect(url: &Url) -> std::io::Result<TcpStream> {
    match (url.host, url.source) {
        (SocketAddr::V6(_), Some(source)) => {
            let socket = TcpSocket::new_v6()?;
            socket.bind(SocketAddr::new(source, 0))?;
            socket.connect(url.host).await
        }
        _ => TcpStream::connect(url.host).await,
    }
}

/// One HTTP/1.0 exchange with a device: sends `request`, reads the answer
/// up to `max` bytes, returns its status and body.
async fn http(url: &Url, request: &[u8], max: usize) -> Result<(u16, String)> {
    let exchange = async {
        let mut stream = connect(url).await?;
        stream.write_all(request).await?;
        let mut data = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            if data.len() + n > max {
                bail!("{} sent more than {} bytes", url.host, max);
            }
            data.extend_from_slice(&chunk[..n]);
        }
        anyhow::Ok(data)
    };
    let data = tokio::time::timeout(HTTP_TIMEOUT, exchange)
        .await
        .map_err(|_| anyhow!("{} did not answer in time", url.host))??;
    parse_http_answer(&data).map_err(|e| anyhow!("{} {}", url.host, e))
}

/// The status and body of an HTTP answer, from whatever bytes a device
/// sent. It is a stranger on the local network, so nothing is assumed:
/// no header block, or no status in it, is an error, never a guess.
pub(crate) fn parse_http_answer(data: &[u8]) -> Result<(u16, String)> {
    let text = String::from_utf8_lossy(data).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("sent no HTTP answer"))?;
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("sent no HTTP status"))?;
    Ok((status, body.to_string()))
}

async fn get(url: &Url) -> Result<String> {
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        url.path,
        authority(url.host)
    );
    let (status, body) = http(url, request.as_bytes(), MAX_DESCRIPTION).await?;
    if status != 200 {
        bail!("{} answered {} for its description", url.host, status);
    }
    Ok(body)
}

/// The text inside the first `<tag>…</tag>` in `xml` (namespace prefixes
/// on the tag are allowed).
pub(crate) fn element<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let mut rest = xml;
    loop {
        let open = rest.find('<')?;
        rest = &rest[open + 1..];
        let end = rest.find('>')?;
        let name = rest[..end].split_whitespace().next().unwrap_or("");
        let local = name.rsplit(':').next().unwrap_or(name);
        if local == tag && !name.starts_with('/') {
            let body = &rest[end + 1..];
            // The matching close tag, with the same prefix or none.
            let close = body
                .find(&format!("</{}>", name))
                .or_else(|| body.find(&format!("</{}>", tag)))?;
            return Some(body[..close].trim());
        }
        rest = &rest[end + 1..];
    }
}

/// Finds a port-forwarding service in a device description, preferring the
/// newest. Its control URL must be on the device that described it.
pub(crate) fn find_service(description: &str, location: &Url) -> Option<Service> {
    find_service_of(description, location, &SERVICES)
}

/// [`find_service`] for any of `kinds`, best first.
pub(crate) fn find_service_of(
    description: &str,
    location: &Url,
    kinds: &[&'static str],
) -> Option<Service> {
    let base = element(description, "URLBase")
        .and_then(Url::parse)
        .filter(|b| b.host.ip() == location.host.ip())
        .unwrap_or_else(|| location.clone());
    for &kind in kinds {
        for block in description.split("<service>").skip(1) {
            let block = block.split("</service>").next().unwrap_or("");
            if element(block, "serviceType") != Some(kind) {
                continue;
            }
            let Some(control) = element(block, "controlURL").and_then(|c| base.join(c)) else {
                continue;
            };
            if control.host.ip() != location.host.ip() {
                continue;
            }
            // Reached the way the description was: the same network, from
            // the same address.
            let control = Url {
                host: match (control.host, location.host) {
                    (SocketAddr::V6(c), SocketAddr::V6(l)) => {
                        SocketAddr::V6(SocketAddrV6::new(*c.ip(), c.port(), 0, l.scope_id()))
                    }
                    (c, _) => c,
                },
                path: control.path,
                source: location.source,
            };
            return Some(Service { control, kind });
        }
    }
    None
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Calls one SOAP action. `Ok(body)` on success; `Err` carries the UPnP
/// error code when the device gave one.
async fn soap(
    service: &Service,
    action: &str,
    args: &[(&str, String)],
) -> Result<String, SoapError> {
    let mut inner = String::new();
    for (k, v) in args {
        inner.push_str(&format!("<{k}>{}</{k}>", escape(v)));
    }
    let body = format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{kind}\">{inner}</u:{action}></s:Body></s:Envelope>\r\n",
        kind = service.kind
    );
    let request = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: \"{}#{}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        service.control.path,
        authority(service.control.host),
        service.kind,
        action,
        body.len(),
        body
    );
    let (status, answer) = http(&service.control, request.as_bytes(), MAX_SOAP_RESPONSE)
        .await
        .map_err(SoapError::Other)?;
    if status == 200 {
        return Ok(answer);
    }
    match element(&answer, "errorCode").and_then(|c| c.parse().ok()) {
        Some(code) => Err(SoapError::Upnp(code)),
        None => Err(SoapError::Other(anyhow!(
            "{} answered {} to {}",
            service.control.host,
            status,
            action
        ))),
    }
}

#[derive(Debug)]
enum SoapError {
    Upnp(u32),
    Other(anyhow::Error),
}

impl std::fmt::Display for SoapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SoapError::Upnp(code) => write!(f, "UPnP error {}", code),
            SoapError::Other(e) => write!(f, "{}", e),
        }
    }
}

pub struct UpnpMapping {
    service: Service,
    local: SocketAddrV4,
    external_port: u16,
    external_ip: Option<Ipv4Addr>,
    lease: u32,
    description: String,
}

impl UpnpMapping {
    /// Finds the router and forwards a UDP port to `local_port` on the
    /// interface that talks to it (or on `bind_ip` if the socket is bound to
    /// a specific address). The same external port number is preferred; if
    /// it is taken the router picks one (AddAnyPortMapping, IGDv2) or, on an
    /// older router, one of a few random ports is tried.
    pub async fn create(
        local_port: u16,
        bind_ip: Option<Ipv4Addr>,
        lease: u32,
        description: &str,
    ) -> Result<Self> {
        Self::create_in(Reach::Lan, local_port, bind_ip, lease, description).await
    }

    /// [`UpnpMapping::create`], searching at `target` (the tests' simulated
    /// router listens on loopback).
    pub async fn create_with(
        target: SocketAddr,
        local_port: u16,
        bind_ip: Option<Ipv4Addr>,
        lease: u32,
        description: &str,
    ) -> Result<Self> {
        Self::create_in(Reach::At(target), local_port, bind_ip, lease, description).await
    }

    async fn create_in(
        reach: Reach,
        local_port: u16,
        bind_ip: Option<Ipv4Addr>,
        lease: u32,
        description: &str,
    ) -> Result<Self> {
        tokio::time::timeout(
            CREATE_TIMEOUT,
            Self::attempt(reach, local_port, bind_ip, lease, description),
        )
        .await
        .map_err(|_| anyhow!("UPnP: the router took too long"))?
    }

    async fn attempt(
        reach: Reach,
        local_port: u16,
        bind_ip: Option<Ipv4Addr>,
        lease: u32,
        description: &str,
    ) -> Result<Self> {
        let mut last = anyhow!("no UPnP router answered");
        for Found { url: location, .. } in find_routers(reach, false).await? {
            // A port is forwarded to an IPv4 host: the router is asked over
            // IPv4.
            let IpAddr::V4(router) = location.host.ip() else {
                last = anyhow!("{} is not an IPv4 router", location.host);
                continue;
            };
            let service = match get(&location).await {
                Ok(desc) => match find_service(&desc, &location) {
                    Some(s) => s,
                    None => {
                        last = anyhow!("{} offers no port forwarding", location.host);
                        continue;
                    }
                },
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let local_ip = match bind_ip {
                Some(ip) if !ip.is_unspecified() => ip,
                _ => local_ip_towards(router)?,
            };
            let mut m = Self {
                service,
                local: SocketAddrV4::new(local_ip, local_port),
                external_port: local_port,
                external_ip: None,
                lease,
                description: description.to_string(),
            };
            match m.map().await {
                Ok(()) => {
                    m.external_ip = m.query_external_ip().await;
                    return Ok(m);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Asks for the forward, trying what the router's answers allow.
    async fn map(&mut self) -> Result<()> {
        match self.add(self.external_port, self.lease).await {
            Ok(()) => return Ok(()),
            Err(SoapError::Upnp(ONLY_PERMANENT_LEASES)) => {
                self.lease = 0;
                return self
                    .add(self.external_port, 0)
                    .await
                    .map_err(|e| anyhow!("UPnP mapping failed: {}", e));
            }
            Err(e) => tracing::debug!(
                "UPnP: port {} not available ({}); trying others",
                self.external_port,
                e
            ),
        }
        if self.service.kind.ends_with(":2") {
            if let Ok(port) = self.add_any().await {
                self.external_port = port;
                return Ok(());
            }
        }
        for _ in 0..3 {
            let port = rand::rngs::OsRng.gen_range(20_000..60_000);
            match self.add(port, self.lease).await {
                Ok(()) => {
                    self.external_port = port;
                    return Ok(());
                }
                Err(SoapError::Upnp(CONFLICT_IN_MAPPING)) => continue,
                Err(e) => return Err(anyhow!("UPnP mapping failed: {}", e)),
            }
        }
        bail!("UPnP: no external port available")
    }

    fn mapping_args(&self, external: u16, lease: u32) -> Vec<(&'static str, String)> {
        vec![
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external.to_string()),
            ("NewProtocol", "UDP".into()),
            ("NewInternalPort", self.local.port().to_string()),
            ("NewInternalClient", self.local.ip().to_string()),
            ("NewEnabled", "1".into()),
            ("NewPortMappingDescription", self.description.clone()),
            ("NewLeaseDuration", lease.to_string()),
        ]
    }

    async fn add(&self, external: u16, lease: u32) -> Result<(), SoapError> {
        soap(
            &self.service,
            "AddPortMapping",
            &self.mapping_args(external, lease),
        )
        .await
        .map(|_| ())
    }

    async fn add_any(&mut self) -> Result<u16, SoapError> {
        let args = self.mapping_args(self.external_port, self.lease);
        let answer = match soap(&self.service, "AddAnyPortMapping", &args).await {
            Err(SoapError::Upnp(ONLY_PERMANENT_LEASES)) => {
                self.lease = 0;
                let args = self.mapping_args(self.external_port, 0);
                soap(&self.service, "AddAnyPortMapping", &args).await?
            }
            other => other?,
        };
        element(&answer, "NewReservedPort")
            .and_then(|p| p.parse().ok())
            .filter(|p| *p != 0)
            .ok_or_else(|| SoapError::Other(anyhow!("no port in the router's answer")))
    }

    async fn query_external_ip(&self) -> Option<Ipv4Addr> {
        let answer = soap(&self.service, "GetExternalIPAddress", &[])
            .await
            .ok()?;
        element(&answer, "NewExternalIPAddress")?.parse().ok()
    }

    /// Public address senders should use, if the gateway reported its IP.
    pub fn external_addr(&self) -> Option<SocketAddr> {
        self.external_ip
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), self.external_port))
    }

    pub fn external_port(&self) -> u16 {
        self.external_port
    }

    pub fn local(&self) -> SocketAddrV4 {
        self.local
    }

    /// Lease in seconds; 0 means permanent (no refresh needed).
    pub fn lease(&self) -> u32 {
        self.lease
    }

    /// Renews the lease by adding the same mapping again.
    pub async fn refresh(&self) -> Result<()> {
        self.add(self.external_port, self.lease)
            .await
            .map_err(|e| anyhow!("UPnP refresh failed: {}", e))
    }

    /// Removes the mapping from the gateway.
    pub async fn remove(self) -> Result<()> {
        soap(
            &self.service,
            "DeletePortMapping",
            &[
                ("NewRemoteHost", String::new()),
                ("NewExternalPort", self.external_port.to_string()),
                ("NewProtocol", "UDP".into()),
            ],
        )
        .await
        .map(|_| ())
        .map_err(|e| anyhow!("UPnP removal failed: {}", e))
    }
}

/// A hole in a router's IPv6 firewall for one UDP port of this host: what a
/// port forward is where there is no address translation.
pub struct UpnpPinhole {
    service: Service,
    client: std::net::Ipv6Addr,
    port: u16,
    /// The router's handle on the pinhole; `None` when its firewall is off
    /// and there is nothing to open (or to close).
    unique_id: Option<String>,
    lease: u32,
}

impl UpnpPinhole {
    /// Finds the router and asks it to let packets from anywhere in to the
    /// UDP `port` of one of `clients`, this host's addresses.
    pub async fn create(clients: &[Ipv6Addr], port: u16, lease: u32) -> Result<Self> {
        Self::create_in(Reach::Lan, clients, port, lease).await
    }

    /// [`UpnpPinhole::create`], searching at `target` (the tests' simulated
    /// router listens on loopback).
    pub async fn create_with(
        target: SocketAddr,
        clients: &[Ipv6Addr],
        port: u16,
        lease: u32,
    ) -> Result<Self> {
        Self::create_in(Reach::At(target), clients, port, lease).await
    }

    async fn create_in(reach: Reach, clients: &[Ipv6Addr], port: u16, lease: u32) -> Result<Self> {
        tokio::time::timeout(CREATE_TIMEOUT, Self::attempt(reach, clients, port, lease))
            .await
            .map_err(|_| anyhow!("UPnP: the router took too long"))?
    }

    async fn attempt(reach: Reach, clients: &[Ipv6Addr], port: u16, lease: u32) -> Result<Self> {
        let mut last = anyhow!("no UPnP router answered");
        for found in find_routers(reach, true).await? {
            // For which of this host's addresses: one on the network the
            // router answered on, and where that is not known (it answered
            // over IPv4) the first.
            let client = match (&found.link, clients.first()) {
                (Some(there), _) => match clients.iter().find(|c| there.contains(c)) {
                    Some(c) => *c,
                    None => {
                        last = anyhow!(
                            "{} is on a network that has none of this host's addresses",
                            found.url.host
                        );
                        continue;
                    }
                },
                (None, Some(c)) => *c,
                (None, None) => bail!("no address of this host to open the firewall for"),
            };
            let mut location = found.url;
            // The request leaves from the address the pinhole is for: a
            // router lets a host open a pinhole to itself only.
            if location.host.is_ipv6() {
                location.source = Some(IpAddr::V6(client));
            }
            match Self::open(&location, client, port, lease).await {
                Ok(pinhole) => return Ok(pinhole),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// One router's answer to a request for a pinhole for `client`.
    async fn open(location: &Url, client: Ipv6Addr, port: u16, lease: u32) -> Result<Self> {
        let desc = get(location).await?;
        let Some(service) = find_service_of(&desc, location, &[FIREWALL_SERVICE]) else {
            bail!("{} has no IPv6 firewall control", location.host);
        };
        // A router says whether it has a firewall to open and whether it
        // lets hosts open it; either "no" is the answer, and the first is a
        // good one.
        if let Ok(status) = soap(&service, "GetFirewallStatus", &[]).await {
            if element(&status, "FirewallEnabled") == Some("0") {
                return Ok(Self {
                    service,
                    client,
                    port,
                    unique_id: None,
                    lease,
                });
            }
            if element(&status, "InboundPinholeAllowed") == Some("0") {
                bail!(
                    "{} does not let hosts open its IPv6 firewall",
                    location.host
                );
            }
        }
        // The spec's longest lease; anything more is refused.
        let lease = lease.clamp(1, 86_400);
        let args = [
            ("RemoteHost", String::new()),
            ("RemotePort", "0".to_string()),
            ("InternalClient", client.to_string()),
            ("InternalPort", port.to_string()),
            ("Protocol", "17".to_string()),
            ("LeaseTime", lease.to_string()),
        ];
        let answer = soap(&service, "AddPinhole", &args)
            .await
            .map_err(|e| anyhow!("UPnP pinhole failed: {}", e))?;
        let Some(id) = element(&answer, "UniqueID").map(str::to_string) else {
            bail!("the router granted no pinhole handle");
        };
        Ok(Self {
            service,
            client,
            port,
            unique_id: Some(id),
            lease,
        })
    }

    /// Where the host is reachable now: its own address, the port opened.
    pub fn external_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(self.client), self.port)
    }

    pub fn lease(&self) -> u32 {
        self.lease
    }

    /// Renews the lease (UpdatePinhole).
    pub async fn refresh(&self) -> Result<()> {
        let Some(id) = &self.unique_id else {
            return Ok(());
        };
        soap(
            &self.service,
            "UpdatePinhole",
            &[
                ("UniqueID", id.clone()),
                ("NewLeaseTime", self.lease.to_string()),
            ],
        )
        .await
        .map(|_| ())
        .map_err(|e| anyhow!("UPnP pinhole renewal failed: {}", e))
    }

    /// Closes the pinhole.
    pub async fn remove(self) -> Result<()> {
        let Some(id) = self.unique_id else {
            return Ok(());
        };
        soap(&self.service, "DeletePinhole", &[("UniqueID", id)])
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("UPnP pinhole removal failed: {}", e))
    }
}

/// Local IPv4 address of the interface used to reach `router`.
fn local_ip_towards(router: Ipv4Addr) -> Result<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0")?;
    probe.connect(SocketAddrV4::new(router, 1900))?;
    match probe.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(anyhow!("the router is not reachable over IPv4")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    #[test]
    fn urls_are_plain_http_to_an_address() {
        let u = Url::parse("http://192.168.1.1:5000/rootDesc.xml").unwrap();
        assert_eq!(u.host, "192.168.1.1:5000".parse().unwrap());
        assert_eq!(u.path, "/rootDesc.xml");
        assert_eq!(
            Url::parse("http://10.0.0.1").unwrap().host,
            "10.0.0.1:80".parse().unwrap()
        );
        for bad in [
            "https://192.168.1.1/x",
            "http://router.local:5000/x",
            "http://192.168.1.1:5000/a b",
            "ftp://192.168.1.1/",
            // IPv6 literals go in brackets, and are closed and complete.
            "http://fe80::1:5000/x",
            "http://[fe80::1/x",
            "http://[fe80::1]x/",
            "http://[fe80::1]:/x",
            "http://[fe80::1]:99999/x",
            "http://[]:80/x",
            "http://[router]:80/x",
            // A router is not an IPv4 address in disguise.
            "http://[::ffff:192.168.1.1]:5000/x",
        ] {
            assert!(Url::parse(bad).is_none(), "{}", bad);
        }
        let base = Url::parse("http://192.168.1.1:5000/dev/desc.xml").unwrap();
        assert_eq!(base.join("ctl/IPConn").unwrap().path, "/dev/ctl/IPConn");
        assert_eq!(base.join("/ctl").unwrap().path, "/ctl");
        assert_eq!(
            base.join("http://192.168.1.9:80/x").unwrap().host,
            "192.168.1.9:80".parse().unwrap()
        );
    }

    /// An IPv6 router's URL: the address in brackets, a port or the default,
    /// and a zone (`%25eth0`, RFC 6874) that is dropped — it names an
    /// interface of the router's host, not ours.
    #[test]
    fn urls_take_ipv6_addresses_in_brackets() {
        let u = Url::parse("http://[2001:db8::1]:5000/rootDesc.xml").unwrap();
        assert_eq!(u.host, "[2001:db8::1]:5000".parse().unwrap());
        assert_eq!(u.path, "/rootDesc.xml");
        assert_eq!(
            Url::parse("http://[2001:db8::1]/x").unwrap().host,
            "[2001:db8::1]:80".parse().unwrap()
        );
        for zoned in [
            "http://[fe80::1%25eth0]:5000/x",
            "http://[fe80::1%eth0]:5000/x",
            "http://[fe80::1%3]:5000/x",
        ] {
            let u = Url::parse(zoned).unwrap();
            assert_eq!(u.host, "[fe80::1]:5000".parse().unwrap(), "{}", zoned);
            let SocketAddr::V6(v6) = u.host else {
                panic!("not IPv6")
            };
            assert_eq!(v6.scope_id(), 0, "{}", zoned);
        }
        let base = Url::parse("http://[2001:db8::1]:5000/dev/desc.xml").unwrap();
        let ctl = base.join("ctl/IP6FCtl").unwrap();
        assert_eq!(ctl.host, base.host);
        assert_eq!(ctl.path, "/dev/ctl/IP6FCtl");
        assert_eq!(
            base.join("http://[2001:db8::9]:80/x").unwrap().host,
            "[2001:db8::9]:80".parse().unwrap()
        );
        // The Host header is the address without a zone.
        assert_eq!(
            authority("[fe80::1%3]:5000".parse().unwrap()),
            "[fe80::1]:5000"
        );
        assert_eq!(authority("10.0.0.1:80".parse().unwrap()), "10.0.0.1:80");
    }

    #[test]
    fn a_service_is_only_taken_from_the_device_that_describes_it() {
        let location = Url::parse("http://192.168.1.1:5000/desc.xml").unwrap();
        let desc = |control: &str| {
            format!(
                "<root><device><serviceList>\
                 <service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>\
                 <controlURL>/l3f</controlURL></service>\
                 <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
                 <controlURL>{}</controlURL></service>\
                 </serviceList></device></root>",
                control
            )
        };
        let s = find_service(&desc("/ctl/IPConn"), &location).unwrap();
        assert_eq!(s.kind, "urn:schemas-upnp-org:service:WANIPConnection:1");
        assert_eq!(s.control.path, "/ctl/IPConn");
        // A control URL on another host is somebody else's.
        assert!(find_service(&desc("http://127.0.0.1:22/"), &location).is_none());
        assert!(find_service(&desc("http://192.168.1.77/x"), &location).is_none());
    }

    /// The control URL of an IPv6 router is reached on the network the
    /// description was, from the address it was: a link-local address means
    /// nothing without the network, and the source is what the router checks
    /// a pinhole against.
    #[test]
    fn an_ipv6_control_url_is_reached_the_way_the_description_was() {
        let mut location = Url::parse("http://[fe80::1]:5000/desc.xml").unwrap();
        location.host = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 5000, 0, 7));
        location.source = Some("2001:db8::5".parse().unwrap());
        let desc = |control: &str| {
            format!(
                "<root><device><serviceList><service>\
                 <serviceType>{}</serviceType><controlURL>{}</controlURL>\
                 </service></serviceList></device></root>",
                FIREWALL_SERVICE, control
            )
        };
        for control in ["/ctl/IP6FCtl", "http://[fe80::1%25eth0]:5000/ctl/IP6FCtl"] {
            let s = find_service_of(&desc(control), &location, &[FIREWALL_SERVICE]).unwrap();
            let SocketAddr::V6(host) = s.control.host else {
                panic!("not IPv6")
            };
            assert_eq!(host.scope_id(), 7, "{}", control);
            assert_eq!(s.control.path, "/ctl/IP6FCtl");
            assert_eq!(s.control.source, location.source);
        }
        // Another address, even one on the same network, is another device.
        assert!(find_service_of(
            &desc("http://[fe80::2]:5000/ctl"),
            &location,
            &[FIREWALL_SERVICE]
        )
        .is_none());
    }

    #[test]
    fn soap_answers_are_read_with_or_without_prefixes() {
        let ok = "<s:Envelope><s:Body><u:GetExternalIPAddressResponse xmlns:u=\"x\">\
                  <NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>\
                  </u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
        assert_eq!(element(ok, "NewExternalIPAddress"), Some("203.0.113.7"));
        let fault = "<s:Envelope><s:Body><s:Fault><detail><UPnPError xmlns=\"x\">\
                     <errorCode>718</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>";
        assert_eq!(element(fault, "errorCode"), Some("718"));
        assert_eq!(element("<a>1</a>", "b"), None);
    }

    /// A simulated router on loopback: answers the search from `ssdp` with a
    /// description at `location`, and runs an HTTP server that behaves as
    /// `behave` says.
    struct FakeRouter {
        ssdp: SocketAddr,
        adds: Arc<AtomicU32>,
        _tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    #[derive(Clone, Copy)]
    enum Behave {
        Normal,
        /// The first AddPortMapping conflicts; the router is IGDv2.
        ConflictThenAny,
        /// Accepts connections and never answers.
        Hang,
        /// Sends a description far larger than any router's.
        Huge,
        /// An IGD v2 with an IPv6 firewall to open.
        Pinhole,
        /// Its firewall refuses hosts that ask.
        NoPinholes,
        /// Its firewall is switched off.
        FirewallOff,
    }

    async fn fake_router(behave: Behave, location_host: Option<&str>) -> FakeRouter {
        fake_router_on("127.0.0.1", CLIENT6_TEXT, behave, location_host).await
    }

    /// [`fake_router`] on the loopback address `ip`, opening pinholes for
    /// `client` only.
    async fn fake_router_on(
        ip: &'static str,
        client: &'static str,
        behave: Behave,
        location_host: Option<&str>,
    ) -> FakeRouter {
        let http = TcpListener::bind((ip, 0)).await.unwrap();
        let http_addr = http.local_addr().unwrap();
        let ssdp = UdpSocket::bind((ip, 0)).await.unwrap();
        let ssdp_addr = ssdp.local_addr().unwrap();
        let location = match location_host {
            Some(h) => format!("http://{}/desc.xml", h),
            None => format!("http://{}/desc.xml", http_addr),
        };
        let adds = Arc::new(AtomicU32::new(0));
        let ssdp_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((_, from)) = ssdp.recv_from(&mut buf).await {
                let answer = format!(
                    "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLOCATION: {}\r\n\
                     ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n",
                    location
                );
                let _ = ssdp.send_to(answer.as_bytes(), from).await;
            }
        });
        let counter = adds.clone();
        let http_task = tokio::spawn(async move {
            let kind = match behave {
                Behave::ConflictThenAny => "urn:schemas-upnp-org:service:WANIPConnection:2",
                Behave::Pinhole | Behave::NoPinholes | Behave::FirewallOff => {
                    "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1"
                }
                _ => "urn:schemas-upnp-org:service:WANIPConnection:1",
            };
            loop {
                let Ok((mut conn, _)) = http.accept().await else {
                    return;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut req = vec![0u8; 16 << 10];
                    let n = conn.read(&mut req).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&req[..n]).into_owned();
                    let reply = |status: &str, body: String| {
                        format!(
                            "HTTP/1.0 {}\r\nContent-Type: text/xml\r\n\r\n{}",
                            status, body
                        )
                    };
                    let answer = if matches!(behave, Behave::Hang) {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        return;
                    } else if req.starts_with("GET") {
                        if matches!(behave, Behave::Huge) {
                            let mut big = reply("200 OK", String::new());
                            big.push_str(&"<x>".repeat(200_000));
                            big
                        } else {
                            reply(
                                "200 OK",
                                format!(
                                    "<root><device><serviceList><service>\
                                     <serviceType>{}</serviceType>\
                                     <controlURL>/ctl</controlURL></service>\
                                     </serviceList></device></root>",
                                    kind
                                ),
                            )
                        }
                    } else if req.contains("#AddPortMapping") {
                        let n = counter.fetch_add(1, Ordering::Relaxed);
                        if matches!(behave, Behave::ConflictThenAny) && n == 0 {
                            reply(
                                "500 Internal Server Error",
                                "<s:Envelope><s:Body><s:Fault><detail><UPnPError>\
                                 <errorCode>718</errorCode></UPnPError></detail>\
                                 </s:Fault></s:Body></s:Envelope>"
                                    .into(),
                            )
                        } else {
                            reply("200 OK", "<s:Envelope/>".into())
                        }
                    } else if req.contains("#AddAnyPortMapping") {
                        reply(
                            "200 OK",
                            "<u:AddAnyPortMappingResponse>\
                             <NewReservedPort>40123</NewReservedPort>\
                             </u:AddAnyPortMappingResponse>"
                                .into(),
                        )
                    } else if req.contains("#GetExternalIPAddress") {
                        reply(
                            "200 OK",
                            "<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>".into(),
                        )
                    } else if req.contains("#DeletePortMapping") {
                        reply("200 OK", String::new())
                    } else if req.contains("#GetFirewallStatus") {
                        let (enabled, allowed) = match behave {
                            Behave::NoPinholes => (1, 0),
                            Behave::FirewallOff => (0, 1),
                            _ => (1, 1),
                        };
                        reply(
                            "200 OK",
                            format!(
                                "<u:GetFirewallStatusResponse><FirewallEnabled>{}\
                                 </FirewallEnabled><InboundPinholeAllowed>{}\
                                 </InboundPinholeAllowed></u:GetFirewallStatusResponse>",
                                enabled, allowed
                            ),
                        )
                    } else if req.contains("#AddPinhole") {
                        // The arguments a router needs, without the prefix
                        // the IGD v1 actions use.
                        let wanted = [
                            "<RemoteHost>".to_string(),
                            format!("<InternalClient>{}<", client),
                            "<InternalPort>5555<".to_string(),
                            "<Protocol>17<".to_string(),
                            "<LeaseTime>".to_string(),
                        ];
                        if wanted.iter().all(|w| req.contains(w.as_str())) {
                            counter.fetch_add(1, Ordering::Relaxed);
                            reply(
                                "200 OK",
                                "<u:AddPinholeResponse><UniqueID>77</UniqueID></u:AddPinholeResponse>"
                                    .into(),
                            )
                        } else {
                            reply("500 Internal Server Error", String::new())
                        }
                    } else if (req.contains("#UpdatePinhole") || req.contains("#DeletePinhole"))
                        && req.contains("<UniqueID>77<")
                    {
                        reply("200 OK", String::new())
                    } else {
                        reply("404 Not Found", String::new())
                    };
                    let _ = conn.write_all(answer.as_bytes()).await;
                });
            }
        });
        FakeRouter {
            ssdp: ssdp_addr,
            adds,
            _tasks: vec![ssdp_task, http_task],
        }
    }

    const HERE: Option<Ipv4Addr> = Some(Ipv4Addr::LOCALHOST);

    const CLIENT6: std::net::Ipv6Addr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
    const CLIENT6_TEXT: &str = "2001:db8::5";

    /// An IPv6 firewall is opened to the port, renewed and closed, and the
    /// host is then reachable at its own address.
    #[tokio::test]
    async fn a_router_opens_its_ipv6_firewall_to_a_port() {
        let r = fake_router(Behave::Pinhole, None).await;
        let p = UpnpPinhole::create_with(r.ssdp, &[CLIENT6], 5555, 3600)
            .await
            .expect("opened");
        assert_eq!(p.external_addr(), "[2001:db8::5]:5555".parse().unwrap());
        assert_eq!(r.adds.load(Ordering::Relaxed), 1);
        p.refresh().await.expect("renewed");
        p.remove().await.expect("closed");
    }

    #[tokio::test]
    async fn a_firewall_that_is_off_needs_no_pinhole() {
        let r = fake_router(Behave::FirewallOff, None).await;
        let p = UpnpPinhole::create_with(r.ssdp, &[CLIENT6], 5555, 3600)
            .await
            .expect("nothing to open");
        assert_eq!(r.adds.load(Ordering::Relaxed), 0);
        p.remove().await.expect("nothing to close");
    }

    #[tokio::test]
    async fn a_router_that_lets_hosts_open_nothing_is_reported() {
        let r = fake_router(Behave::NoPinholes, None).await;
        let e = UpnpPinhole::create_with(r.ssdp, &[CLIENT6], 5555, 3600)
            .await
            .err()
            .expect("refused");
        assert!(e.to_string().contains("does not let hosts open"), "{}", e);
        // And an IGD with no IPv6 firewall at all is not mistaken for one.
        let v1 = fake_router(Behave::Normal, None).await;
        assert!(UpnpPinhole::create_with(v1.ssdp, &[CLIENT6], 5555, 3600)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_router_forwards_a_port_and_says_where() {
        let r = fake_router(Behave::Normal, None).await;
        let m = UpnpMapping::create_with(r.ssdp, 5555, HERE, 3600, "test")
            .await
            .expect("mapped");
        assert_eq!(m.external_port(), 5555);
        assert_eq!(m.external_addr(), Some("203.0.113.7:5555".parse().unwrap()));
        m.refresh().await.expect("refreshed");
        m.remove().await.expect("removed");
    }

    #[tokio::test]
    async fn a_taken_port_is_exchanged_for_one_the_router_picks() {
        let r = fake_router(Behave::ConflictThenAny, None).await;
        let m = UpnpMapping::create_with(r.ssdp, 5555, HERE, 3600, "test")
            .await
            .expect("mapped");
        assert_eq!(m.external_port(), 40123);
        assert_eq!(r.adds.load(Ordering::Relaxed), 1);
    }

    /// Somewhere other than the fake router's own address that this host can
    /// listen on: a second loopback address where the system has one (Linux
    /// and Windows answer on all of 127/8), else one of the host's own
    /// addresses (macOS configures 127.0.0.1 alone).
    async fn somewhere_else() -> TcpListener {
        if let Ok(l) = TcpListener::bind("127.0.0.2:0").await {
            return l;
        }
        let ip = if_addrs::get_if_addrs()
            .expect("the host's addresses")
            .into_iter()
            .map(|i| i.ip())
            .find(|ip| ip.is_ipv4() && !ip.is_loopback())
            .expect("an IPv4 address other than loopback");
        TcpListener::bind((ip, 0)).await.unwrap()
    }

    /// Whoever answers the search is believed only about itself. Pointed at
    /// another address — here a port nothing on this host would expect a
    /// router's request on — nothing is fetched there at all.
    #[tokio::test]
    async fn a_router_that_points_elsewhere_is_not_followed() {
        let bait = somewhere_else().await;
        let bait_addr = bait.local_addr().unwrap().to_string();
        let r = fake_router(Behave::Normal, Some(&bait_addr)).await;
        let visited = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(4), bait.accept())
                .await
                .is_ok()
        });
        assert!(UpnpMapping::create_with(r.ssdp, 5555, HERE, 3600, "test")
            .await
            .is_err());
        assert!(
            !visited.await.unwrap(),
            "the client went where it was pointed"
        );
    }

    /// A device that accepts the connection and then says nothing costs a
    /// few seconds, not the receiver's address report for ever.
    #[tokio::test]
    async fn a_router_that_never_answers_costs_seconds() {
        let r = fake_router(Behave::Hang, None).await;
        let started = std::time::Instant::now();
        assert!(UpnpMapping::create_with(r.ssdp, 5555, HERE, 3600, "test")
            .await
            .is_err());
        assert!(started.elapsed() <= CREATE_TIMEOUT + Duration::from_secs(1));
    }

    /// And one that sends more than any router would is cut off, not read
    /// until memory runs out.
    #[tokio::test]
    async fn a_router_that_sends_too_much_is_cut_off() {
        let r = fake_router(Behave::Huge, None).await;
        let e = UpnpMapping::create_with(r.ssdp, 5555, HERE, 3600, "test")
            .await
            .err()
            .expect("refused");
        assert!(e.to_string().contains("more than"), "{}", e);
    }

    /// What is known of one network for the answers below: a global /64 of
    /// this host's, on interface 3.
    fn network() -> Link {
        Link {
            index: 3,
            addrs: vec![("2001:db8:1::2".parse().unwrap(), 64)],
        }
    }

    fn from6(ip: &str, scope: u32) -> SocketAddrV6 {
        SocketAddrV6::new(ip.parse().unwrap(), 1900, 0, scope)
    }

    fn answered(location: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLOCATION: {}\r\n\
             ST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n\r\n",
            location
        )
        .into_bytes()
    }

    #[test]
    fn prefixes_are_compared_bit_by_bit() {
        let a: Ipv6Addr = "2001:db8:1:2::1".parse().unwrap();
        assert!(same_prefix(a, "2001:db8:1:2:ffff::9".parse().unwrap(), 64));
        assert!(!same_prefix(a, "2001:db8:1:3::1".parse().unwrap(), 64));
        assert!(same_prefix(a, "2001:db8:1:3::1".parse().unwrap(), 48));
        assert!(same_prefix(a, a, 128));
        assert!(!same_prefix(a, "2001:db8:1:2::2".parse().unwrap(), 128));
        // No prefix, or more than an address has, matches nothing.
        assert!(!same_prefix(a, a, 0));
        assert!(!same_prefix(a, a, 129));
    }

    /// A router is believed on the network it answered on, at an address
    /// there — its link-local one, or one in a prefix this host has — and
    /// asked at the address that answered, whatever its answer says.
    #[test]
    fn an_answer_over_ipv6_is_believed_on_its_own_network_only() {
        let link = network();
        let loc = "http://[2001:db8:1::1]:5000/rootDesc.xml";
        // Answers from its link-local address and names the global one.
        let f = answer_v6(&answered(loc), from6("fe80::1", 3), &link).expect("believed");
        assert_eq!(f.url.host, "[fe80::1%3]:5000".parse().unwrap());
        assert_eq!(f.url.path, "/rootDesc.xml");
        assert_eq!(
            f.link.as_deref(),
            Some(&link.addrs.iter().map(|a| a.0).collect::<Vec<_>>()[..])
        );
        // A system that does not say which network a link-local sender is on.
        let f = answer_v6(&answered(loc), from6("fe80::1", 0), &link).expect("believed");
        assert_eq!(f.url.host, "[fe80::1%3]:5000".parse().unwrap());
        // From a global address in this host's prefix, and names itself.
        let f = answer_v6(&answered(loc), from6("2001:db8:1::1", 0), &link).expect("believed");
        assert_eq!(f.url.host, "[2001:db8:1::1]:5000".parse().unwrap());
        // Another network's link-local address, or a prefix this host is not
        // in, or an address no router has: nobody's word.
        for (from, scope) in [
            ("fe80::1", 4),
            ("2001:db8:2::1", 0),
            ("::", 0),
            ("::1", 0),
            ("ff02::c", 3),
        ] {
            assert!(
                answer_v6(&answered(loc), from6(from, scope), &link).is_none(),
                "{} on {}",
                from,
                scope
            );
        }
        // A description that is not on IPv6, or not HTTP, or not there.
        for location in [
            "http://192.168.1.1:5000/rootDesc.xml",
            "https://[2001:db8:1::1]:5000/rootDesc.xml",
            "http://router.local:5000/rootDesc.xml",
        ] {
            assert!(
                answer_v6(&answered(location), from6("fe80::1", 3), &link).is_none(),
                "{}",
                location
            );
        }
        assert!(answer_v6(b"HTTP/1.1 200 OK\r\n\r\n", from6("fe80::1", 3), &link).is_none());
        assert!(answer_v6(&[0xff, 0xfe, 0x00], from6("fe80::1", 3), &link).is_none());
    }

    /// The networks that get an IPv6 search are ones this host has IPv6 on.
    #[test]
    fn only_networks_with_ipv6_are_searched() {
        let links = links_v6();
        assert!(links.len() <= MAX_LINKS);
        for l in &links {
            assert_ne!(l.index, 0);
            assert!(!l.addrs.is_empty(), "{:?}", l);
        }
    }

    fn ipv6_here() -> bool {
        if std::net::UdpSocket::bind("[::1]:0").is_ok() {
            return true;
        }
        assert!(
            std::env::var_os("SHARP_REQUIRE_IPV6").is_none(),
            "this host has no IPv6, and SHARP_REQUIRE_IPV6 is set"
        );
        false
    }

    /// The same exchange over IPv6: search, description, firewall status,
    /// AddPinhole, renewal and removal, on a router with an IPv6 address.
    #[tokio::test]
    async fn a_router_reached_over_ipv6_opens_its_firewall() {
        if !ipv6_here() {
            return;
        }
        let r = fake_router_on("::1", "::1", Behave::Pinhole, None).await;
        assert!(r.ssdp.is_ipv6());
        let p = UpnpPinhole::create_with(r.ssdp, &[Ipv6Addr::LOCALHOST], 5555, 3600)
            .await
            .expect("opened");
        assert_eq!(p.external_addr(), "[::1]:5555".parse().unwrap());
        assert_eq!(r.adds.load(Ordering::Relaxed), 1);
        p.refresh().await.expect("renewed");
        p.remove().await.expect("closed");
    }

    /// Of this host's addresses the one the router's network has is the one
    /// a pinhole is for; none of them there is no pinhole.
    #[tokio::test]
    async fn a_pinhole_is_for_an_address_on_the_routers_network() {
        // What `attempt` chooses from, without a network: the tests' router
        // has no network, so the first address is the one.
        let r = fake_router(Behave::Pinhole, None).await;
        let other: Ipv6Addr = "2001:db8::77".parse().unwrap();
        let p = UpnpPinhole::create_with(r.ssdp, &[CLIENT6, other], 5555, 3600)
            .await
            .expect("opened");
        assert_eq!(p.external_addr().ip(), IpAddr::V6(CLIENT6));
        // Nothing to open a pinhole for.
        let e = UpnpPinhole::create_with(r.ssdp, &[], 5555, 3600)
            .await
            .err()
            .expect("refused");
        assert!(e.to_string().contains("no address"), "{}", e);
    }

    /// A request to an IPv6 router leaves from the address named, and from
    /// no other: a wrong one is an error here, not a request from somewhere
    /// else that the router then turns away.
    #[tokio::test]
    async fn requests_leave_from_the_address_asked() {
        if !ipv6_here() {
            return;
        }
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let mut url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        url.source = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
        let accepted = tokio::spawn(async move { listener.accept().await.map(|(_, from)| from) });
        connect(&url).await.expect("from ::1");
        assert_eq!(
            accepted.await.unwrap().unwrap().ip(),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
        // An address of the other family cannot be the source: the request
        // does not go out from somewhere else.
        url.source = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(connect(&url).await.is_err());
    }
}
