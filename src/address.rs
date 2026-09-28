//! Receiver addresses as users write them: `<SHARP ID>@<host>:<port>`.

use crate::crypto::SharpId;
use std::net::SocketAddr;

/// Splits `sh-…@host:port` into the receiver's identity and its address.
pub fn parse_peer(s: &str) -> Result<(SharpId, String), String> {
    let s = s.trim();
    let (id, host) = s.rsplit_once('@').ok_or_else(|| {
        "a receiver is written as <ID>@<host>:<port>, e.g. sh-…@203.0.113.5:5555".to_string()
    })?;
    let id: SharpId = id.parse().map_err(|e| format!("receiver ID: {}", e))?;
    if host.is_empty() || !host.contains(':') {
        return Err(format!("\"{}\" is not <host>:<port>", host));
    }
    Ok((id, host.to_string()))
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
        let (p, host) = parse_peer(&format!("{}@10.0.0.2:5555", id)).unwrap();
        assert_eq!(p, id);
        assert_eq!(host, "10.0.0.2:5555");
        let (_, host) = parse_peer(&format!("{}@[::1]:7", id)).unwrap();
        assert_eq!(host, "[::1]:7");
        assert!(parse_peer("10.0.0.2:5555").is_err());
        assert!(parse_peer(&format!("{}@host", id)).is_err());
        assert!(parse_peer("sh-bad@10.0.0.2:1").is_err());
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
