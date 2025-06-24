// src/nat/ice/foundation.rs
//! Foundation calculation for ICE candidates (RFC 8445 Section 5.1.1.3)
//!
//! The foundation is an identifier, scoped within a session, that groups
//! similar candidates together for the purposes of computing candidate pairs
//! and applying rules during the connectivity check procedure.

use std::net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use crate::nat::ice::candidate::{CandidateType, TransportProtocol};
use sha2::{Sha256, Digest};

/// Maximum foundation string length (arbitrary but reasonable limit)
const MAX_FOUNDATION_LENGTH: usize = 32;

/// Calculate foundation for a candidate according to RFC 8445 Section 5.1.1.3
///
/// Two candidates have the same foundation when they are "similar" - meaning
/// when they have the same type, base IP address, protocol, and STUN/TURN server.
///
/// # Arguments
///
/// * `candidate_type` - The type of candidate (host, srflx, prflx, relay)
/// * `base_ip` - The base IP address for this candidate
/// * `transport` - The transport protocol (UDP or TCP)
/// * `server_ip` - Optional STUN/TURN server IP (for reflexive/relay candidates)
/// * `relay_server` - Optional relay server address (for relay candidates)
///
/// # Returns
///
/// A foundation string that uniquely identifies similar candidates
pub fn calculate_foundation(
    candidate_type: CandidateType,
    base_ip: &IpAddr,
    transport: TransportProtocol,
    server_ip: Option<&IpAddr>,
    relay_server: Option<&SocketAddr>,
) -> String {
    // Create a deterministic hash based on the candidate characteristics
    let mut hasher = Sha256::new();

    // Include candidate type
    hasher.update(&[candidate_type as u8]);

    // Include transport protocol
    hasher.update(&[transport as u8]);

    // Include base IP address (normalized)
    let normalized_base = normalize_ip_for_foundation(base_ip);
    hasher.update(normalized_base.as_bytes());

    // Include server information for reflexive and relay candidates
    match candidate_type {
        CandidateType::ServerReflexive => {
            if let Some(server) = server_ip {
                let normalized_server = normalize_ip_for_foundation(server);
                hasher.update(b"stun_server:");
                hasher.update(normalized_server.as_bytes());
            }
        }
        CandidateType::Relay => {
            if let Some(relay) = relay_server {
                let normalized_relay = normalize_ip_for_foundation(&relay.ip());
                hasher.update(b"turn_server:");
                hasher.update(normalized_relay.as_bytes());
                // Include port for relay servers as they might differ
                hasher.update(&relay.port().to_be_bytes());
            }
        }
        CandidateType::Host | CandidateType::PeerReflexive => {
            // No additional server information needed
        }
    }

    // Generate foundation string from hash
    let hash_result = hasher.finalize();
    let foundation = format!("{:x}", u64::from_be_bytes([
        hash_result[0], hash_result[1], hash_result[2], hash_result[3],
        hash_result[4], hash_result[5], hash_result[6], hash_result[7],
    ]));

    // Ensure foundation is within reasonable length limits
    if foundation.len() > MAX_FOUNDATION_LENGTH {
        foundation[..MAX_FOUNDATION_LENGTH].to_string()
    } else {
        foundation
    }
}

/// Normalize IP address for foundation calculation
///
/// This ensures that IPv4-mapped IPv6 addresses and regular IPv4 addresses
/// get the same foundation when appropriate.
fn normalize_ip_for_foundation(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(ipv4) => {
            format!("ipv4:{}", ipv4)
        }
        IpAddr::V6(ipv6) => {
            // Check if this is an IPv4-mapped IPv6 address
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                format!("ipv4:{}", ipv4)
            } else {
                // Normalize IPv6 address representation
                format!("ipv6:{}", normalize_ipv6_address(ipv6))
            }
        }
    }
}

/// Normalize IPv6 address to canonical form
///
/// This ensures consistent foundation calculation for equivalent IPv6 addresses
/// that might be represented differently (e.g., with or without leading zeros)
fn normalize_ipv6_address(ipv6: &Ipv6Addr) -> String {
    // Convert to canonical form (lowercase, compressed)
    let segments = ipv6.segments();

    // Find the longest sequence of zeros for compression
    let (compress_start, compress_len) = find_longest_zero_sequence(&segments);

    let mut result = String::new();
    let mut i = 0;
    let mut compressed = false;

    while i < 8 {
        if i == compress_start && compress_len > 1 && !compressed {
            // Apply compression
            if i == 0 {
                result.push_str("::");
            } else {
                result.push(':');
            }
            compressed = true;
            i += compress_len;
        } else {
            if i > 0 && !result.ends_with("::") {
                result.push(':');
            }
            result.push_str(&format!("{:x}", segments[i]));
            i += 1;
        }
    }

    result
}

/// Find the longest sequence of consecutive zero segments in IPv6 address
fn find_longest_zero_sequence(segments: &[u16; 8]) -> (usize, usize) {
    let mut max_start = 0;
    let mut max_len = 0;
    let mut current_start = 0;
    let mut current_len = 0;

    for (i, &segment) in segments.iter().enumerate() {
        if segment == 0 {
            if current_len == 0 {
                current_start = i;
            }
            current_len += 1;
        } else {
            if current_len > max_len {
                max_start = current_start;
                max_len = current_len;
            }
            current_len = 0;
        }
    }

    // Check final sequence
    if current_len > max_len {
        max_start = current_start;
        max_len = current_len;
    }

    (max_start, max_len)
}

/// Calculate foundation for host candidates
///
/// Host candidates are grouped by their base IP address and transport protocol
pub fn calculate_host_foundation(base_ip: &IpAddr, transport: TransportProtocol) -> String {
    calculate_foundation(CandidateType::Host, base_ip, transport, None, None)
}

/// Calculate foundation for server reflexive candidates
///
/// Server reflexive candidates are grouped by their base IP, transport, and STUN server
pub fn calculate_server_reflexive_foundation(
    base_ip: &IpAddr,
    transport: TransportProtocol,
    stun_server: &IpAddr,
) -> String {
    calculate_foundation(
        CandidateType::ServerReflexive,
        base_ip,
        transport,
        Some(stun_server),
        None,
    )
}

/// Calculate foundation for peer reflexive candidates
///
/// Peer reflexive candidates are grouped by their base IP and transport protocol
pub fn calculate_peer_reflexive_foundation(
    base_ip: &IpAddr,
    transport: TransportProtocol,
) -> String {
    calculate_foundation(CandidateType::PeerReflexive, base_ip, transport, None, None)
}

/// Calculate foundation for relay candidates
///
/// Relay candidates are grouped by their base IP, transport, and TURN server
pub fn calculate_relay_foundation(
    base_ip: &IpAddr,
    transport: TransportProtocol,
    turn_server: &SocketAddr,
) -> String {
    calculate_foundation(
        CandidateType::Relay,
        base_ip,
        transport,
        Some(&turn_server.ip()),
        Some(turn_server),
    )
}

/// Validate foundation string according to RFC requirements
///
/// Foundation must be composed of 1-32 alphanumeric characters
pub fn validate_foundation(foundation: &str) -> bool {
    if foundation.is_empty() || foundation.len() > MAX_FOUNDATION_LENGTH {
        return false;
    }

    // Foundation should contain only alphanumeric characters
    foundation.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Foundation comparison for candidate pairing
///
/// Two candidates with the same foundation should not be paired together
/// during connectivity checks (with some exceptions)
pub fn foundations_match(foundation1: &str, foundation2: &str) -> bool {
    foundation1 == foundation2
}

/// Special foundation values for specific scenarios
pub mod special_foundations {
    /// Foundation for loopback addresses (for testing)
    pub const LOOPBACK: &str = "loopback";

    /// Foundation for link-local addresses
    pub const LINK_LOCAL: &str = "linklocal";

    /// Foundation for multicast addresses (should not be used)
    pub const MULTICAST: &str = "multicast";

    /// Foundation for unspecified addresses
    pub const UNSPECIFIED: &str = "unspec";
}

/// Get special foundation for special IP address types
pub fn get_special_foundation(ip: &IpAddr, transport: TransportProtocol) -> Option<String> {
    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_loopback() {
                Some(format!("{}_ipv4_{:?}", special_foundations::LOOPBACK, transport).to_lowercase())
            } else if ipv4.is_link_local() {
                Some(format!("{}_ipv4_{:?}", special_foundations::LINK_LOCAL, transport).to_lowercase())
            } else if ipv4.is_multicast() {
                Some(format!("{}_ipv4_{:?}", special_foundations::MULTICAST, transport).to_lowercase())
            } else if ipv4.is_unspecified() {
                Some(format!("{}_ipv4_{:?}", special_foundations::UNSPECIFIED, transport).to_lowercase())
            } else {
                None
            }
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() {
                Some(format!("{}_ipv6_{:?}", special_foundations::LOOPBACK, transport).to_lowercase())
            } else if ipv6.is_unicast_link_local() {
                Some(format!("{}_ipv6_{:?}", special_foundations::LINK_LOCAL, transport).to_lowercase())
            } else if ipv6.is_multicast() {
                Some(format!("{}_ipv6_{:?}", special_foundations::MULTICAST, transport).to_lowercase())
            } else if ipv6.is_unspecified() {
                Some(format!("{}_ipv6_{:?}", special_foundations::UNSPECIFIED, transport).to_lowercase())
            } else {
                None
            }
        }
    }
}

/// Enhanced foundation calculation that handles special cases
pub fn calculate_foundation_enhanced(
    candidate_type: CandidateType,
    base_ip: &IpAddr,
    transport: TransportProtocol,
    server_ip: Option<&IpAddr>,
    relay_server: Option<&SocketAddr>,
) -> String {
    // Check for special IP address types first
    if let Some(special) = get_special_foundation(base_ip, transport) {
        return special;
    }

    // Use standard foundation calculation
    calculate_foundation(candidate_type, base_ip, transport, server_ip, relay_server)
}

/// Foundation cache for performance optimization
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Cached foundation entry
#[derive(Debug, Clone)]
struct CachedFoundation {
    foundation: String,
    created_at: Instant,
}

/// Foundation cache with TTL
pub struct FoundationCache {
    cache: Arc<RwLock<HashMap<String, CachedFoundation>>>,
    ttl: Duration,
}

impl FoundationCache {
    /// Create a new foundation cache
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// Get foundation from cache or calculate if not present
    pub fn get_or_calculate(
        &self,
        candidate_type: CandidateType,
        base_ip: &IpAddr,
        transport: TransportProtocol,
        server_ip: Option<&IpAddr>,
        relay_server: Option<&SocketAddr>,
    ) -> String {
        // Create cache key
        let cache_key = self.create_cache_key(
            candidate_type,
            base_ip,
            transport,
            server_ip,
            relay_server,
        );

        // Try to get from cache
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(&cache_key) {
                if cached.created_at.elapsed() < self.ttl {
                    return cached.foundation.clone();
                }
            }
        }

        // Calculate foundation
        let foundation = calculate_foundation_enhanced(
            candidate_type,
            base_ip,
            transport,
            server_ip,
            relay_server,
        );

        // Store in cache
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(cache_key, CachedFoundation {
                foundation: foundation.clone(),
                created_at: Instant::now(),
            });
        }

        foundation
    }

    /// Create cache key for foundation parameters
    fn create_cache_key(
        &self,
        candidate_type: CandidateType,
        base_ip: &IpAddr,
        transport: TransportProtocol,
        server_ip: Option<&IpAddr>,
        relay_server: Option<&SocketAddr>,
    ) -> String {
        let mut key = format!("{}:{}:{}",
                              candidate_type as u8,
                              transport as u8,
                              base_ip
        );

        if let Some(server) = server_ip {
            key.push_str(&format!(":server:{}", server));
        }

        if let Some(relay) = relay_server {
            key.push_str(&format!(":relay:{}", relay));
        }

        key
    }

    /// Clean expired entries from cache
    pub fn cleanup_expired(&self) {
        let mut cache = self.cache.write().unwrap();
        let now = Instant::now();

        cache.retain(|_, cached| now.duration_since(cached.created_at) < self.ttl);
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().unwrap();
        let now = Instant::now();

        let total = cache.len();
        let expired = cache.values()
            .filter(|cached| now.duration_since(cached.created_at) >= self.ttl)
            .count();

        (total, expired)
    }

    /// Clear the entire cache
    pub fn clear(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }
}

impl Default for FoundationCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(300)) // 5 minute TTL
    }
}

/// Global foundation cache instance
static FOUNDATION_CACHE: std::sync::OnceLock<FoundationCache> = std::sync::OnceLock::new();

/// Get the global foundation cache
pub fn get_foundation_cache() -> &'static FoundationCache {
    FOUNDATION_CACHE.get_or_init(|| FoundationCache::default())
}

/// Utility function to get foundation with caching
pub fn get_foundation_cached(
    candidate_type: CandidateType,
    base_ip: &IpAddr,
    transport: TransportProtocol,
    server_ip: Option<&IpAddr>,
    relay_server: Option<&SocketAddr>,
) -> String {
    get_foundation_cache().get_or_calculate(
        candidate_type,
        base_ip,
        transport,
        server_ip,
        relay_server,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_host_foundation_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let foundation1 = calculate_host_foundation(&ip, TransportProtocol::Udp);
        let foundation2 = calculate_host_foundation(&ip, TransportProtocol::Udp);

        // Same parameters should give same foundation
        assert_eq!(foundation1, foundation2);

        // Different transport should give different foundation
        let foundation3 = calculate_host_foundation(&ip, TransportProtocol::Tcp);
        assert_ne!(foundation1, foundation3);
    }

    #[test]
    fn test_host_foundation_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let foundation1 = calculate_host_foundation(&ip, TransportProtocol::Udp);
        let foundation2 = calculate_host_foundation(&ip, TransportProtocol::Udp);

        assert_eq!(foundation1, foundation2);
        assert!(validate_foundation(&foundation1));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_normalization() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv6_mapped = IpAddr::V6(ipv4.to_ipv6_mapped());

        let foundation_ipv4 = calculate_host_foundation(&ipv4, TransportProtocol::Udp);
        let foundation_ipv6 = calculate_host_foundation(&ipv6_mapped, TransportProtocol::Udp);

        // IPv4 and IPv4-mapped IPv6 should have same foundation
        assert_eq!(foundation_ipv4, foundation_ipv6);
    }

    #[test]
    fn test_server_reflexive_foundation() {
        let base_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let stun_server1 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let stun_server2 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        let foundation1 = calculate_server_reflexive_foundation(
            &base_ip,
            TransportProtocol::Udp,
            &stun_server1
        );
        let foundation2 = calculate_server_reflexive_foundation(
            &base_ip,
            TransportProtocol::Udp,
            &stun_server2
        );

        // Different STUN servers should give different foundations
        assert_ne!(foundation1, foundation2);
    }

    #[test]
    fn test_relay_foundation() {
        let base_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let turn_server1 = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            3478
        );
        let turn_server2 = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            3479
        );

        let foundation1 = calculate_relay_foundation(
            &base_ip,
            TransportProtocol::Udp,
            &turn_server1
        );
        let foundation2 = calculate_relay_foundation(
            &base_ip,
            TransportProtocol::Udp,
            &turn_server2
        );

        // Different TURN server ports should give different foundations
        assert_ne!(foundation1, foundation2);
    }

    #[test]
    fn test_foundation_validation() {
        assert!(validate_foundation("abc123"));
        assert!(validate_foundation("1"));
        assert!(validate_foundation("a".repeat(32).as_str()));

        assert!(!validate_foundation(""));
        assert!(!validate_foundation(&"a".repeat(33)));
        assert!(!validate_foundation("abc-123"));
        assert!(!validate_foundation("abc_123"));
        assert!(!validate_foundation("abc 123"));
    }

    #[test]
    fn test_ipv6_normalization() {
        let ipv6_1 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let ipv6_2 = "2001:db8::1".parse::<Ipv6Addr>().unwrap();

        assert_eq!(normalize_ipv6_address(&ipv6_1), normalize_ipv6_address(&ipv6_2));

        let normalized = normalize_ipv6_address(&ipv6_1);
        assert_eq!(normalized, "2001:db8::1");
    }

    #[test]
    fn test_special_foundations() {
        let loopback_v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let loopback_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        let foundation_v4 = get_special_foundation(&loopback_v4, TransportProtocol::Udp);
        let foundation_v6 = get_special_foundation(&loopback_v6, TransportProtocol::Udp);

        assert!(foundation_v4.is_some());
        assert!(foundation_v6.is_some());
        assert_ne!(foundation_v4, foundation_v6);
    }

    #[test]
    fn test_foundation_cache() {
        let cache = FoundationCache::new(Duration::from_millis(100));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First call should calculate
        let foundation1 = cache.get_or_calculate(
            CandidateType::Host,
            &ip,
            TransportProtocol::Udp,
            None,
            None,
        );

        // Second call should use cache
        let foundation2 = cache.get_or_calculate(
            CandidateType::Host,
            &ip,
            TransportProtocol::Udp,
            None,
            None,
        );

        assert_eq!(foundation1, foundation2);

        // Wait for cache expiry
        std::thread::sleep(Duration::from_millis(150));

        // Should recalculate after expiry
        let foundation3 = cache.get_or_calculate(
            CandidateType::Host,
            &ip,
            TransportProtocol::Udp,
            None,
            None,
        );

        assert_eq!(foundation1, foundation3); // Same calculation
    }

    #[test]
    fn test_longest_zero_sequence() {
        let segments = [0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001];
        let (start, len) = find_longest_zero_sequence(&segments);
        assert_eq!(start, 2);
        assert_eq!(len, 6);

        let segments = [0x0000, 0x0000, 0x0000, 0x0001, 0x0000, 0x0000, 0x0000, 0x0001];
        let (start, len) = find_longest_zero_sequence(&segments);
        assert_eq!(start, 0);
        assert_eq!(len, 3);
    }
}