// src/nat/ice/foundation.rs
//! ICE foundation calculation (RFC 8445 Section 5.1.1.3)

use std::net::IpAddr;
use sha2::{Sha256, Digest};
use super::{CandidateType, TransportProtocol};

/// Calculate foundation for a candidate
/// Foundation is used to group similar candidates
pub fn calculate_foundation(
    typ: CandidateType,
    base_ip: &IpAddr,
    transport: TransportProtocol,
    server_reflexive_ip: Option<&IpAddr>,
    relay_server: Option<&std::net::SocketAddr>,
) -> String {
    let mut hasher = Sha256::new();
    
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
    hex::encode(&result[..4])
}

/// Check if two foundations are equivalent
pub fn foundations_match(f1: &str, f2: &str) -> bool {
    f1 == f2
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
}