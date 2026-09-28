//! Receiver addresses as users write them: `<SHARP ID>@<host>:<port>`.

use crate::crypto::SharpId;
use std::net::{IpAddr, SocketAddr};

/// `addr` in the one form code that compares or screens addresses should
/// see. An IPv4 peer that reaches a dual-stack IPv6 socket appears as
/// `::ffff:a.b.c.d`; it is the same peer as `a.b.c.d`, and a check that
/// only knew about one spelling would let the other straight through.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Who a request counts against, for rate limits and shares: an IPv4
/// address, or an IPv6 /64 — the block one subscriber is usually handed,
/// and so what one of them can send from at no cost. Keying on whole IPv6
/// addresses would let one subscriber count as eighteen quintillion
/// clients. The canonical form comes first, so an IPv4 client reaching a
/// dual-stack socket is the same client either way.
pub fn client_key(addr: SocketAddr) -> IpAddr {
    match canonical(addr).ip() {
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(o.into())
        }
        v4 => v4,
    }
}

/// Which addresses a socket can send to, and how it writes them.
///
/// An IPv4 socket reaches only IPv4. An IPv6 socket bound to the wildcard
/// with dual-stack allowed (which [`crate::transport::socket::bind_udp`]
/// asks for) reaches both, but addresses IPv4 peers in their mapped form —
/// and receives from them in that form, so everything compared against
/// what arrives must be written the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reach {
    v4: bool,
    v6: bool,
    /// IPv4 addresses are written mapped into IPv6.
    mapped: bool,
}

impl Reach {
    /// What a socket bound at `local` reaches, assuming a wildcard IPv6
    /// socket was allowed to be dual-stack. If it was not, sending to a
    /// mapped address simply fails, which every caller already survives.
    pub fn assume(local: SocketAddr) -> Self {
        Self::with(local, true)
    }

    /// What `socket` reaches, asking the system whether it is dual-stack.
    pub fn of(socket: &tokio::net::UdpSocket) -> Self {
        let Ok(local) = socket.local_addr() else {
            return Self {
                v4: false,
                v6: false,
                mapped: false,
            };
        };
        let dual = local.is_ipv6()
            && socket2::SockRef::from(socket)
                .only_v6()
                .is_ok_and(|only| !only);
        Self::with(local, dual)
    }

    fn with(local: SocketAddr, dual: bool) -> Self {
        match local.ip() {
            IpAddr::V4(_) => Self {
                v4: true,
                v6: false,
                mapped: false,
            },
            IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() => Self {
                v4: true,
                v6: false,
                mapped: true,
            },
            IpAddr::V6(ip) => Self {
                v4: dual && ip.is_unspecified(),
                v6: true,
                mapped: true,
            },
        }
    }

    /// `addr` as this socket sends to it and sees replies from it, or
    /// `None` if it cannot reach it at all.
    pub fn native(&self, addr: SocketAddr) -> Option<SocketAddr> {
        let addr = canonical(addr);
        match addr.ip() {
            IpAddr::V4(v4) if self.v4 => Some(if self.mapped {
                SocketAddr::new(v4.to_ipv6_mapped().into(), addr.port())
            } else {
                addr
            }),
            IpAddr::V6(_) if self.v6 => Some(addr),
            _ => None,
        }
    }

    /// Whether this socket can reach `addr` at all.
    pub fn reaches(&self, addr: SocketAddr) -> bool {
        self.native(addr).is_some()
    }

    /// Whether it can reach IPv4 addresses.
    pub fn v4(&self) -> bool {
        self.v4
    }

    /// Whether it can reach IPv6 addresses.
    pub fn v6(&self) -> bool {
        self.v6
    }
}

/// Splits `sh-…@host:port` into the receiver's identity and its address.
///
/// A receiver behind a NAT may be reachable at more than one address and
/// publishes them all, separated by commas — its port forward, the address
/// the world sees it at, and its addresses on the local network. They are
/// candidates in the sense ICE uses the word: the sender tries each until
/// one answers, and the handshake, not the list, decides which one is really
/// the receiver.
///
/// A receiver that is reached only through a relay publishes no address at
/// all, and is written as its ID alone; the list of hosts is then empty, and
/// the sender has to be given the relay.
pub fn parse_peer(s: &str) -> Result<(SharpId, Vec<String>), String> {
    let s = s.trim();
    let Some((id, hosts)) = s.rsplit_once('@') else {
        return match s.parse::<SharpId>() {
            Ok(id) => Ok((id, Vec::new())),
            Err(_) => Err(
                "a receiver is written as <ID>@<host>:<port>, e.g. sh-…@203.0.113.5:5555 \
                 (or as its ID alone, with --relay)"
                    .to_string(),
            ),
        };
    };
    let id: SharpId = id.parse().map_err(|e| format!("receiver ID: {}", e))?;
    let mut out = Vec::new();
    for host in hosts.split(',') {
        let host = host.trim();
        if host.is_empty() || !host.contains(':') {
            return Err(format!("\"{}\" is not <host>:<port>", host));
        }
        if !out.iter().any(|h| h == host) {
            out.push(host.to_string());
        }
    }
    if out.is_empty() {
        return Err("no address given after \"@\"".to_string());
    }
    Ok((id, out))
}

/// Most addresses one name contributes. A name that resolves to more than
/// this is either load balanced (any of the first few will do) or trying to
/// make us spend the handshake budget on a long list.
pub const MAX_ADDRESSES: usize = 8;

/// Resolves `host:port` (a literal address or a DNS name) to the first
/// address it names. Prefer [`resolve_all`]: a name usually has more than
/// one address, and only one of them may be reachable.
pub async fn resolve(host_port: &str) -> std::io::Result<SocketAddr> {
    Ok(resolve_all(host_port).await?[0])
}

/// Resolves every candidate a receiver published (see [`parse_peer`]) into
/// the addresses to try, in the order given and without repeats.
///
/// A candidate that does not resolve is reported only when *none* of them
/// do: a receiver behind a NAT publishes addresses it cannot know are
/// reachable from where the sender sits, and one of them failing to resolve
/// is expected rather than an error.
pub async fn resolve_candidates(hosts: &[String]) -> Result<Vec<SocketAddr>, String> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut last_error = None;
    for host in hosts {
        match resolve_all(host).await {
            Ok(addrs) => {
                for a in addrs {
                    if !out.contains(&a) && out.len() < MAX_ADDRESSES {
                        out.push(a);
                    }
                }
            }
            Err(e) => last_error = Some(format!("cannot resolve {}: {}", host, e)),
        }
    }
    if out.is_empty() {
        return Err(last_error.unwrap_or_else(|| "no address to connect to".to_string()));
    }
    Ok(out)
}

/// Resolves `host:port` to every address it names, at most
/// [`MAX_ADDRESSES`].
///
/// Name resolution is a *hint*, never an authority. DNS and mDNS answers
/// travel unauthenticated and are the easiest thing on the network to forge
/// or poison, so the sender treats the whole answer as a list of guesses: it
/// tries them in turn, and the handshake decides. Completing one takes the
/// receiver's private key, so an address that is not the receiver simply
/// never answers — a forged record costs time, never safety. It also means
/// a host whose first address happens to be unreachable (a broken IPv6 path
/// is the usual case) no longer strands the transfer.
///
/// The families are interleaved for the same reason: if one of them is
/// broken end to end, it cannot fill the whole list of attempts.
pub async fn resolve_all(host_port: &str) -> std::io::Result<Vec<SocketAddr>> {
    if let Ok(addr) = host_port.parse() {
        return Ok(vec![addr]);
    }
    let mut v6: Vec<SocketAddr> = Vec::new();
    let mut v4: Vec<SocketAddr> = Vec::new();
    for addr in tokio::net::lookup_host(host_port).await? {
        let bucket = if addr.is_ipv6() { &mut v6 } else { &mut v4 };
        if !bucket.contains(&addr) {
            bucket.push(addr);
        }
    }
    let mut out = Vec::with_capacity(MAX_ADDRESSES);
    let mut v6 = v6.into_iter();
    let mut v4 = v4.into_iter();
    while out.len() < MAX_ADDRESSES {
        let (a, b) = (v6.next(), v4.next());
        if a.is_none() && b.is_none() {
            break;
        }
        out.extend(a.into_iter().chain(b).take(MAX_ADDRESSES - out.len()));
    }
    if out.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} does not resolve to an address", host_port),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    /// A dual-stack socket sees IPv4 peers as mapped IPv6 addresses. Code
    /// comparing those with addresses written the ordinary way — a relay
    /// from the command line, a candidate from DNS — must see them as one.
    #[test]
    fn every_socket_family_writes_addresses_its_own_way() {
        let v4: SocketAddr = "198.51.100.7:5555".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:198.51.100.7]:5555".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::7]:5555".parse().unwrap();
        assert_eq!(canonical(mapped), v4);
        assert_eq!(canonical(v4), v4);
        assert_eq!(canonical(v6), v6);

        let ipv4 = Reach::assume("0.0.0.0:0".parse().unwrap());
        assert_eq!(ipv4.native(v4), Some(v4));
        assert_eq!(ipv4.native(mapped), Some(v4));
        assert_eq!(ipv4.native(v6), None);

        let dual = Reach::assume("[::]:0".parse().unwrap());
        assert_eq!(dual.native(v4), Some(mapped));
        assert_eq!(dual.native(mapped), Some(mapped));
        assert_eq!(dual.native(v6), Some(v6));

        // Bound to one IPv6 address, a socket cannot speak IPv4 at all.
        let only6 = Reach::assume("[2001:db8::1]:0".parse().unwrap());
        assert_eq!(only6.native(v4), None);
        assert_eq!(only6.native(v6), Some(v6));
        // Bound to a mapped address, it speaks nothing but IPv4.
        let only4 = Reach::assume("[::ffff:198.51.100.1]:0".parse().unwrap());
        assert_eq!(only4.native(v4), Some(mapped));
        assert_eq!(only4.native(v6), None);
    }

    #[tokio::test]
    async fn a_socket_reports_what_it_can_reach() {
        let v4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let reach = Reach::of(&v4);
        assert!(reach.reaches("127.0.0.1:9".parse().unwrap()));
        assert!(!reach.reaches("[::1]:9".parse().unwrap()));
        // An IPv6 socket, where this host has IPv6 at all.
        if let Ok(v6) = crate::transport::socket::bind_udp("[::]:0".parse().unwrap(), 1 << 16) {
            let reach = Reach::of(&v6);
            assert!(reach.reaches("[::1]:9".parse().unwrap()));
        }
    }

    #[test]
    fn parses_id_and_address() {
        let id = Identity::generate().id();
        let (p, hosts) = parse_peer(&format!("{}@10.0.0.2:5555", id)).unwrap();
        assert_eq!(p, id);
        assert_eq!(hosts, ["10.0.0.2:5555"]);
        let (_, hosts) = parse_peer(&format!("{}@[::1]:7", id)).unwrap();
        assert_eq!(hosts, ["[::1]:7"]);
        assert!(parse_peer("10.0.0.2:5555").is_err());
        // Reached only through a relay: the ID alone, and no address.
        let (p, hosts) = parse_peer(&id.to_string()).unwrap();
        assert_eq!(p, id);
        assert!(hosts.is_empty());
        assert!(parse_peer(&format!("{}@host", id)).is_err());
        assert!(parse_peer("sh-bad@10.0.0.2:1").is_err());
    }

    /// A receiver behind a NAT publishes every address it might be reached
    /// at; the sender takes them all.
    #[test]
    fn parses_a_list_of_candidate_addresses() {
        let id = Identity::generate().id();
        let (p, hosts) = parse_peer(&format!(
            "{}@203.0.113.5:5555,[2001:db8::1]:5555,192.168.1.7:5555",
            id
        ))
        .unwrap();
        assert_eq!(p, id);
        assert_eq!(
            hosts,
            ["203.0.113.5:5555", "[2001:db8::1]:5555", "192.168.1.7:5555"]
        );
        // Spacing is forgiven and repeats are collapsed.
        let (_, hosts) = parse_peer(&format!("{}@10.0.0.2:1, 10.0.0.3:1 ,10.0.0.2:1", id)).unwrap();
        assert_eq!(hosts, ["10.0.0.2:1", "10.0.0.3:1"]);
        // One bad entry spoils the list rather than being silently dropped:
        // a typo should be reported, not turned into a mystery timeout.
        assert!(parse_peer(&format!("{}@10.0.0.2:1,nonsense", id)).is_err());
        assert!(parse_peer(&format!("{}@10.0.0.2:1,", id)).is_err());
    }

    #[tokio::test]
    async fn resolves_literals_and_names() {
        assert_eq!(
            resolve("127.0.0.1:9").await.unwrap(),
            "127.0.0.1:9".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(resolve("localhost:9").await.unwrap().port(), 9);
        // A literal is itself, and nothing else is guessed for it.
        assert_eq!(
            resolve_all("[::1]:7").await.unwrap(),
            vec!["[::1]:7".parse::<SocketAddr>().unwrap()]
        );
    }

    /// Every address a name has is offered, without duplicates, with the
    /// families interleaved so a broken one cannot fill the list, and never
    /// more than the cap.
    #[tokio::test]
    async fn resolves_names_to_every_address() {
        let all = resolve_all("localhost:9").await.unwrap();
        assert!(!all.is_empty());
        assert!(all.len() <= MAX_ADDRESSES);
        assert!(all.iter().all(|a| a.port() == 9));
        let mut unique = all.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), all.len(), "duplicates in {:?}", all);
        // localhost usually has both families; when it does, the first two
        // entries must not be the same one.
        if all.iter().any(|a| a.is_ipv6()) && all.iter().any(|a| a.is_ipv4()) {
            assert_ne!(all[0].is_ipv6(), all[1].is_ipv6(), "{:?}", all);
        }
    }
}
