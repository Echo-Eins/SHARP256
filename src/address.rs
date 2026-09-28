//! Receiver addresses as users write them: `<SHARP ID>@<host>:<port>`.

use crate::crypto::SharpId;
use std::net::SocketAddr;

/// Splits `sh-…@host:port` into the receiver's identity and its address.
///
/// A receiver behind a NAT may be reachable at more than one address and
/// publishes them all, separated by commas — its port forward, the address
/// the world sees it at, and its addresses on the local network. They are
/// candidates in the sense ICE uses the word: the sender tries each until
/// one answers, and the handshake, not the list, decides which one is really
/// the receiver.
pub fn parse_peer(s: &str) -> Result<(SharpId, Vec<String>), String> {
    let s = s.trim();
    let (id, hosts) = s.rsplit_once('@').ok_or_else(|| {
        "a receiver is written as <ID>@<host>:<port>, e.g. sh-…@203.0.113.5:5555".to_string()
    })?;
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

    #[test]
    fn parses_id_and_address() {
        let id = Identity::generate().id();
        let (p, hosts) = parse_peer(&format!("{}@10.0.0.2:5555", id)).unwrap();
        assert_eq!(p, id);
        assert_eq!(hosts, ["10.0.0.2:5555"]);
        let (_, hosts) = parse_peer(&format!("{}@[::1]:7", id)).unwrap();
        assert_eq!(hosts, ["[::1]:7"]);
        assert!(parse_peer("10.0.0.2:5555").is_err());
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
