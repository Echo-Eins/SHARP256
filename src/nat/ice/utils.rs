// src/nat/ice/utils.rs
//! ICE utility functions

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

/// Check if IP address is link-local
pub fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
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
            // IPv6 Unique Local Address (ULA)
            (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Check if an IPv6 address is globally routable
fn is_global_ipv6(addr: &Ipv6Addr) -> bool {
    !(addr.is_unspecified()
        || addr.is_loopback()
        || addr.is_unique_local()
        || addr.is_unicast_link_local()
        || addr.is_multicast())
}
/// Get IP address preference score (higher is better)
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
                100 // Public IPv4
            }
        }
        IpAddr::V6(v6) => {
            if is_private(ip) {
                40 // ULA IPv6
            } else if is_global_ipv6(v6) {
                90 // Global IPv6
            } else {
                30 // Other IPv6
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

/// Calculate pair priority as per RFC 8445
pub fn calculate_pair_priority(
    controlling: bool,
    local_priority: u32,
    remote_priority: u32,
) -> u64 {
    let g = local_priority.max(remote_priority) as u64;
    let d = local_priority.min(remote_priority) as u64;

    if controlling {
        (1u64 << 32) * g + 2 * d + if local_priority > remote_priority { 1 } else { 0 }
    } else {
        (1u64 << 32) * g + 2 * d + if remote_priority > local_priority { 1 } else { 0 }
    }
}

/// Format ICE candidate for logging
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_classification() {
        let loopback_v4 = "127.0.0.1".parse::<IpAddr>().unwrap();
        let private_v4 = "192.168.1.1".parse::<IpAddr>().unwrap();
        let public_v4 = "8.8.8.8".parse::<IpAddr>().unwrap();
        let link_local_v6 = "fe80::1".parse::<IpAddr>().unwrap();

        assert!(is_loopback(&loopback_v4));
        assert!(is_private(&private_v4));
        assert!(!is_private(&public_v4));
        assert!(is_link_local(&link_local_v6));
    }

    #[test]
    fn test_ip_preference() {
        let loopback = "127.0.0.1".parse::<IpAddr>().unwrap();
        let private = "192.168.1.1".parse::<IpAddr>().unwrap();
        let public = "8.8.8.8".parse::<IpAddr>().unwrap();

        assert!(ip_preference_score(&public) > ip_preference_score(&private));
        assert!(ip_preference_score(&private) > ip_preference_score(&loopback));
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
}