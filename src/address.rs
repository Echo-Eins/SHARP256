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

/// Resolves `host:port` (a literal address or a DNS name).
pub async fn resolve(host_port: &str) -> std::io::Result<SocketAddr> {
    if let Ok(addr) = host_port.parse() {
        return Ok(addr);
    }
    tokio::net::lookup_host(host_port)
        .await?
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{} does not resolve to an address", host_port),
            )
        })
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
    }
}
