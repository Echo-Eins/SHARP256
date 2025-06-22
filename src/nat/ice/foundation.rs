// src/nat/ice/foundation.rs
//! ICE foundation calculation (RFC 8445 Section 5.1.1.3)

use std::net::{IpAddr, SocketAddr};
use md5::{Md5, Digest};
use super::{CandidateType, TransportProtocol};

/// Calculate foundation for a candidate
/// Foundation is used to group similar candidates
///
/// RFC 8445 allows any method to calculate foundation.
/// We use MD5 for efficiency as foundation is just an identifier.
pub fn calculate_foundation(
    typ: CandidateType,
    base_ip: &IpAddr,
    transport: TransportProtocol,
    server_reflexive_ip: Option<&IpAddr>,
    relay_server: Option<&SocketAddr>,
) -> String {
    let mut hasher = Md5::new();

    // Type
    hasher.update(typ.to_str().as_bytes());
    hasher.update(b":");

    // Base IP
    hasher.update(base_ip.to_string().as_bytes());
    hasher.update(b":");

    // Transport
    hasher.update(match transport {
        TransportProtocol::Udp => b"UDP",
        TransportProtocol::Tcp => b"TCP",
    });
    hasher.update(b":");

    // Server reflexive IP (if applicable)
    if let Some(srflx_ip) = server_reflexive_ip {
        hasher.update(srflx_ip.to_string().as_bytes());
        hasher.update(b":");
    }

    // Relay server (if applicable)
    if let Some(relay) = relay_server {
        hasher.update(relay.to_string().as_bytes());
        hasher.update(b":");
    }

    let result = hasher.finalize();

    // Take first 4 bytes and convert to hex (8 characters)
    // This provides sufficient uniqueness while being compact
    hex::encode(&result[..4])
}

/// Check if two foundations are equivalent
#[inline]
pub fn foundations_match(f1: &str, f2: &str) -> bool {
    f1 == f2
}

/// Calculate foundation for a candidate pair
pub fn calculate_pair_foundation(local_foundation: &str, remote_foundation: &str) -> String {
    format!("{}:{}", local_foundation, remote_foundation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_foundation_calculation() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        let f1 = calculate_foundation(
            CandidateType::Host,
            &ip,
            TransportProtocol::Udp,
            None,
            None,
        );

        let f2 = calculate_foundation(
            CandidateType::Host,
            &ip,
            TransportProtocol::Udp,
            None,
            None,
        );

        // Same parameters should produce same foundation
        assert_eq!(f1, f2);
        assert_eq!(f1.len(), 8); // 4 bytes as hex

        // Different type should produce different foundation
        let f3 = calculate_foundation(
            CandidateType::ServerReflexive,
            &ip,
            TransportProtocol::Udp,
            Some(&ip),
            None,
        );

        assert_ne!(f1, f3);
    }

    #[test]
    fn test_foundation_uniqueness() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101));

        let f1 = calculate_foundation(
            CandidateType::Host,
            &ip1,
            TransportProtocol::Udp,
            None,
            None,
        );

        let f2 = calculate_foundation(
            CandidateType::Host,
            &ip2,
            TransportProtocol::Udp,
            None,
            None,
        );

        // Different IPs should produce different foundations
        assert_ne!(f1, f2);
    }

    #[test]
    fn test_pair_foundation() {
        let local = "abcd1234";
        let remote = "efgh5678";

        let pair_foundation = calculate_pair_foundation(local, remote);
        assert_eq!(pair_foundation, "abcd1234:efgh5678");
    }

    #[test]
    fn test_foundation_performance() {
        use std::time::Instant;

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        // Measure time for 10000 calculations
        let start = Instant::now();
        for i in 0..10000 {
            let ip_varied = IpAddr::V4(Ipv4Addr::new(192, 168, 1, (i % 256) as u8));
            let _ = calculate_foundation(
                CandidateType::Host,
                &ip_varied,
                TransportProtocol::Udp,
                None,
                None,
            );
        }
        let elapsed = start.elapsed();

        println!("10000 MD5 foundation calculations took: {:?}", elapsed);
        // Should be under 50ms on modern hardware
        assert!(elapsed.as_millis() < 50);
    }
}