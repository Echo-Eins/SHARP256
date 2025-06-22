// src/nat/ice/utils.rs
//! ICE utility functions

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

/// Check if IP address is link-local
pub fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80, // fe80::/10
    }
}

/// Check if IP address is loopback
pub fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Check if IP address is private
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => {
            // IPv6 Unique Local Address (ULA) fc00::/7
            (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Check if an IPv6 address is globally routable
fn is_global_ipv6(addr: &Ipv6Addr) -> bool {
    // More comprehensive check for global IPv6
    !(addr.is_unspecified()
        || addr.is_loopback()
        || is_unique_local(addr)
        || addr.is_unicast_link_local()
        || addr.is_multicast()
        || is_documentation(addr)
        || is_benchmarking(addr)
        || is_reserved(addr))
}

/// Check if IPv6 is Unique Local Address (ULA)
fn is_unique_local(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// Check if IPv6 is documentation address (2001:db8::/32)
fn is_documentation(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] == 0x2001 && addr.segments()[1] == 0x0db8
}

/// Check if IPv6 is benchmarking address (2001:2::/48)
fn is_benchmarking(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] == 0x2001 && addr.segments()[1] == 0x0002
}

/// Check if IPv6 is reserved
fn is_reserved(addr: &Ipv6Addr) -> bool {
    // Reserved ranges
    addr.segments()[0] == 0x0000 || // ::/8
        (addr.segments()[0] & 0xff00) == 0x0100 || // 0100::/8
        (addr.segments()[0] & 0xfe00) == 0xfe00    // fe00::/9
}

/// Get IP address preference score (higher is better)
/// Implements RFC 8421 preferences for dual-stack
pub fn ip_preference_score(ip: &IpAddr) -> u32 {
    if is_loopback(ip) {
        return 0;
    }

    if is_link_local(ip) {
        return 10;
    }

    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private() {
                50 // Private IPv4
            } else {
                90 // Public IPv4 (RFC 8421: slightly lower than global IPv6)
            }
        }
        IpAddr::V6(v6) => {
            if is_unique_local(v6) {
                40 // ULA IPv6
            } else if is_global_ipv6(v6) {
                100 // Global IPv6 (RFC 8421: prefer IPv6 for global addresses)
            } else {
                30 // Other IPv6 (site-local, etc.)
            }
        }
    }
}

/// Generate timestamp for ICE
pub fn ice_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Calculate pair priority using the corrected formula from priority.rs
pub fn calculate_pair_priority(
    controlling: bool,
    local_priority: u32,
    remote_priority: u32,
) -> u64 {
    super::priority::calculate_pair_priority(controlling, local_priority, remote_priority)
}

/// Format ICE candidate pair for logging
pub fn format_candidate_pair(local: &SocketAddr, remote: &SocketAddr) -> String {
    format!("{} -> {}", local, remote)
}

/// Check if two addresses are in the same network
pub fn same_network(addr1: &IpAddr, addr2: &IpAddr, prefix_len: u8) -> bool {
    match (addr1, addr2) {
        (IpAddr::V4(a1), IpAddr::V4(a2)) => {
            let mask = !((1u32 << (32 - prefix_len)) - 1);
            let a1_bits = u32::from_be_bytes(a1.octets());
            let a2_bits = u32::from_be_bytes(a2.octets());
            (a1_bits & mask) == (a2_bits & mask)
        }
        (IpAddr::V6(a1), IpAddr::V6(a2)) => {
            let bytes1 = a1.octets();
            let bytes2 = a2.octets();
            let full_bytes = (prefix_len / 8) as usize;
            let remaining_bits = prefix_len % 8;

            // Check full bytes
            if bytes1[..full_bytes] != bytes2[..full_bytes] {
                return false;
            }

            // Check remaining bits
            if remaining_bits > 0 && full_bytes < 16 {
                let mask = !((1u8 << (8 - remaining_bits)) - 1);
                (bytes1[full_bytes] & mask) == (bytes2[full_bytes] & mask)
            } else {
                true
            }
        }
        _ => false,
    }
}

/// Get address family preference for Happy Eyeballs (RFC 8421)
pub fn address_family_preference(ip: &IpAddr) -> u32 {
    match ip {
        IpAddr::V4(_) => 50,
        IpAddr::V6(_) => 100, // Prefer IPv6 per RFC 8421
    }
}

/// Check if address is suitable for ICE candidate
pub fn is_ice_candidate_address(ip: &IpAddr) -> bool {
    !is_loopback(ip) &&
        !is_link_local(ip) &&
        !ip.is_unspecified() &&
        !ip.is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_classification() {
        let loopback_v4 = "127.0.0.1".parse::<IpAddr>().unwrap();
        let private_v4 = "192.168.1.1".parse::<IpAddr>().unwrap();
        let public_v4 = "8.8.8.8".parse::<IpAddr>().unwrap();
        let link_local_v6 = "fe80::1".parse::<IpAddr>().unwrap();
        let global_v6 = "2001:4860:4860::8888".parse::<IpAddr>().unwrap();

        assert!(is_loopback(&loopback_v4));
        assert!(is_private(&private_v4));
        assert!(!is_private(&public_v4));
        assert!(is_link_local(&link_local_v6));
        assert!(!is_link_local(&global_v6));
    }

    #[test]
    fn test_ip_preference_rfc8421() {
        let loopback = "127.0.0.1".parse::<IpAddr>().unwrap();
        let private_v4 = "192.168.1.1".parse::<IpAddr>().unwrap();
        let public_v4 = "8.8.8.8".parse::<IpAddr>().unwrap();
        let global_v6 = "2001:4860:4860::8888".parse::<IpAddr>().unwrap();

        // RFC 8421: Global IPv6 > Public IPv4 > Private IPv4 > Loopback
        assert_eq!(ip_preference_score(&global_v6), 100);
        assert_eq!(ip_preference_score(&public_v4), 90);
        assert_eq!(ip_preference_score(&private_v4), 50);
        assert_eq!(ip_preference_score(&loopback), 0);

        // Verify ordering
        assert!(ip_preference_score(&global_v6) > ip_preference_score(&public_v4));
        assert!(ip_preference_score(&public_v4) > ip_preference_score(&private_v4));
        assert!(ip_preference_score(&private_v4) > ip_preference_score(&loopback));
    }

    #[test]
    fn test_same_network() {
        let addr1 = "192.168.1.10".parse::<IpAddr>().unwrap();
        let addr2 = "192.168.1.20".parse::<IpAddr>().unwrap();
        let addr3 = "192.168.2.10".parse::<IpAddr>().unwrap();

        assert!(same_network(&addr1, &addr2, 24));
        assert!(!same_network(&addr1, &addr3, 24));
        assert!(same_network(&addr1, &addr3, 16));
    }

    #[test]
    fn test_link_local_detection() {
        // Test IPv6 link-local with correct mask
        let link_local = "fe80::1234:5678".parse::<IpAddr>().unwrap();
        let not_link_local = "2001:db8::1".parse::<IpAddr>().unwrap();

        assert!(is_link_local(&link_local));
        assert!(!is_link_local(&not_link_local));

        // Test edge cases for fe80::/10
        let edge1 = "fe80::".parse::<IpAddr>().unwrap();
        let edge2 = "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse::<IpAddr>().unwrap();
        let outside = "fec0::".parse::<IpAddr>().unwrap();

        assert!(is_link_local(&edge1));
        assert!(is_link_local(&edge2));
        assert!(!is_link_local(&outside));
    }
}