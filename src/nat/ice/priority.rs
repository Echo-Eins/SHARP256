// src/nat/ice/priority.rs
//! ICE priority calculation (RFC 8445 Section 5.1.2)
//! Full implementation with all RFC requirements and edge cases

use super::CandidateType;
use std::net::IpAddr;

/// Priority constants as per RFC 8445
const TYPE_PREFERENCE_HOST: u32 = 126;
const TYPE_PREFERENCE_PRFLX: u32 = 110;
const TYPE_PREFERENCE_SRFLX: u32 = 100;
const TYPE_PREFERENCE_RELAY: u32 = 0;

/// Maximum values for validation
const MAX_TYPE_PREFERENCE: u32 = 126;
const MAX_LOCAL_PREFERENCE: u32 = 65535;
const MAX_COMPONENT_ID: u32 = 256;

/// Calculate candidate priority per RFC 8445 Section 5.1.2.1
///
/// priority = (2^24)*(type preference) +
///            (2^8)*(local preference) +
///            (2^0)*(256 - component ID)
///
/// Returns a 32-bit priority value
pub fn calculate_priority(
    typ: CandidateType,
    local_preference: u32,
    component_id: u32,
) -> u32 {
    // Type preference from RFC 8445 recommendations
    let type_preference = match typ {
        CandidateType::Host => TYPE_PREFERENCE_HOST,
        CandidateType::PeerReflexive => TYPE_PREFERENCE_PRFLX,
        CandidateType::ServerReflexive => TYPE_PREFERENCE_SRFLX,
        CandidateType::Relay => TYPE_PREFERENCE_RELAY,
    };

    // Validate and clamp values to prevent overflow
    let type_pref = type_preference.min(MAX_TYPE_PREFERENCE);
    let local_pref = local_preference.min(MAX_LOCAL_PREFERENCE);
    let component = component_id.clamp(1, MAX_COMPONENT_ID);

    // Calculate priority ensuring no overflow
    let priority = ((type_pref as u64) << 24) +
        ((local_pref as u64) << 8) +
        ((256 - component) as u64);

    // Ensure result fits in u32
    priority.min(u32::MAX as u64) as u32
}

/// Calculate local preference based on RFC 8445 guidelines
///
/// This implementation considers:
/// - Network interface type and quality
/// - IP version preferences (RFC 8421)
/// - Network topology (VPN, direct, etc.)
/// - Interface metrics
pub fn calculate_local_preference(
    ip: &IpAddr,
    interface_type: InterfaceType,
    is_vpn: bool,
    is_temporary: bool,
    interface_metric: Option<u32>,
) -> u32 {
    let mut preference = 0u32;

    // Base preference by interface type (0-255 range for 8-bit field)
    preference += match interface_type {
        InterfaceType::Ethernet => 200,
        InterfaceType::Wifi => 150,
        InterfaceType::Cellular => 100,
        InterfaceType::Vpn => 50,
        InterfaceType::Virtual => 25,
        InterfaceType::Unknown => 10,
    };

    // IP version preference (RFC 8421 dual-stack considerations)
    preference += match ip {
        IpAddr::V4(_) => 10, // Small bonus for IPv4 compatibility
        IpAddr::V6(v6) => {
            if v6.segments()[0] == 0x2002 {
                5  // 6to4 addresses get lower preference
            } else if v6.segments()[0] & 0xfe00 == 0xfc00 {
                15 // ULA addresses
            } else {
                20 // Global IPv6 preferred per RFC 8421
            }
        }
    };

    // Penalties
    if is_vpn {
        preference = preference.saturating_sub(50);
    }

    if is_temporary {
        preference = preference.saturating_sub(25);
    }

    // Consider interface metric if available (lower is better)
    if let Some(metric) = interface_metric {
        let metric_penalty = (metric / 10).min(50);
        preference = preference.saturating_sub(metric_penalty);
    }

    // Scale to 16-bit range as per RFC recommendation
    let scaled = (preference as u64 * 65535) / 255;
    scaled.min(65535) as u32
}

/// Calculate pair priority per RFC 8445 Section 6.1.2.3
///
/// The formula MUST be:
/// - Let G be the priority of the candidate provided by the controlling agent
/// - Let D be the priority of the candidate provided by the controlled agent
/// - Pair Priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
pub fn calculate_pair_priority(
    controlling: bool,
    local_priority: u32,
    remote_priority: u32,
) -> u64 {
    let (g, d) = if controlling {
        (local_priority as u64, remote_priority as u64)
    } else {
        (remote_priority as u64, local_priority as u64)
    };

    let min_priority = g.min(d);
    let max_priority = g.max(d);

    // Use bit shifting for 2^32 to avoid potential overflow
    (min_priority << 32) + (max_priority << 1) + if g > d { 1 } else { 0 }
}

/// Calculate prflx priority for discovered peer reflexive candidates
/// RFC 8445 Section 7.2.5.2.1
pub fn calculate_prflx_priority(
    base_component_id: u32,
    is_controlling: bool,
) -> u32 {
    // For peer reflexive candidates discovered during connectivity checks
    let type_preference = TYPE_PREFERENCE_PRFLX;

    // Local preference for prflx is typically high
    let local_preference = if is_controlling {
        65535 // Maximum for controlling
    } else {
        65534 // Slightly less for controlled
    };

    calculate_priority(
        CandidateType::PeerReflexive,
        local_preference,
        base_component_id,
    )
}

/// Interface type enumeration with all possibilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceType {
    Ethernet,
    Wifi,
    Cellular,
    Vpn,
    Virtual,
    Unknown,
}

impl InterfaceType {
    /// Detect interface type from name patterns
    pub fn from_name(name: &str) -> Self {
        let lower = name.to_lowercase();

        if lower.contains("eth") || lower.contains("en") {
            InterfaceType::Ethernet
        } else if lower.contains("wlan") || lower.contains("wifi") || lower.contains("wl") {
            InterfaceType::Wifi
        } else if lower.contains("cell") || lower.contains("wwan") || lower.contains("rmnet") {
            InterfaceType::Cellular
        } else if lower.contains("tun") || lower.contains("tap") || lower.contains("vpn") ||
            lower.contains("wg") || lower.contains("utun") {
            InterfaceType::Vpn
        } else if lower.contains("veth") || lower.contains("docker") || lower.contains("br") ||
            lower.contains("virbr") {
            InterfaceType::Virtual
        } else {
            InterfaceType::Unknown
        }
    }
}

/// IP version for preference calculation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

impl From<&IpAddr> for IpVersion {
    fn from(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        }
    }
}

/// Validate that a priority value is valid according to RFC
pub fn validate_priority(priority: u32) -> bool {
    // Extract components
    let type_pref = priority >> 24;
    let local_pref = (priority >> 8) & 0xFFFF;
    let component_part = priority & 0xFF;

    // Validate ranges
    type_pref <= MAX_TYPE_PREFERENCE &&
        local_pref <= MAX_LOCAL_PREFERENCE &&
        component_part < 256
}

/// Extract components from a priority value
pub fn decompose_priority(priority: u32) -> (u32, u32, u32) {
    let type_preference = priority >> 24;
    let local_preference = (priority >> 8) & 0xFFFF;
    let component_part = priority & 0xFF;
    let component_id = 256 - component_part;

    (type_preference, local_preference, component_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_priority_calculation() {
        // Test with known values
        let priority = calculate_priority(CandidateType::Host, 65535, 1);

        // Decompose and verify
        let (type_pref, local_pref, component) = decompose_priority(priority);
        assert_eq!(type_pref, TYPE_PREFERENCE_HOST);
        assert_eq!(local_pref, 65535);
        assert_eq!(component, 1);

        // Verify the exact value
        let expected = (126u32 << 24) + (65535u32 << 8) + 255;
        assert_eq!(priority, expected);
    }

    #[test]
    fn test_pair_priority_formula() {
        // Test the corrected formula with specific values
        let controlling_priority = 2130706431u32;
        let controlled_priority = 1694498815u32;

        // Test when controlling
        let pair_priority = calculate_pair_priority(true, controlling_priority, controlled_priority);

        // Manual calculation
        let g = controlling_priority as u64;
        let d = controlled_priority as u64;
        let expected = (d << 32) + (g << 1) + 1; // MIN=d, MAX=g, g>d

        assert_eq!(pair_priority, expected);

        // Test when controlled (priorities swap)
        let pair_priority_controlled = calculate_pair_priority(false, controlling_priority, controlled_priority);
        let expected_controlled = (d << 32) + (g << 1) + 1; // MIN=d, MAX=g, g>d (same)

        assert_eq!(pair_priority_controlled, expected_controlled);
    }

    #[test]
    fn test_local_preference_calculation() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv6_global = IpAddr::V6("2001:db8::1".parse().unwrap());

        // Ethernet with global IPv6 should have highest preference
        let pref_eth_v6 = calculate_local_preference(
            &ipv6_global,
            InterfaceType::Ethernet,
            false,
            false,
            None,
        );

        // VPN should have lower preference
        let pref_vpn = calculate_local_preference(
            &ipv4,
            InterfaceType::Ethernet,
            true,
            false,
            None,
        );

        assert!(pref_eth_v6 > pref_vpn);

        // Test with interface metric
        let pref_high_metric = calculate_local_preference(
            &ipv4,
            InterfaceType::Ethernet,
            false,
            false,
            Some(100), // High metric = lower preference
        );

        let pref_low_metric = calculate_local_preference(
            &ipv4,
            InterfaceType::Ethernet,
            false,
            false,
            Some(10),
        );

        assert!(pref_low_metric > pref_high_metric);
    }

    #[test]
    fn test_priority_overflow_protection() {
        // Test with maximum values
        let priority = calculate_priority(
            CandidateType::Host,
            u32::MAX, // Should be clamped to 65535
            u32::MAX, // Should be clamped to 256
        );

        assert!(validate_priority(priority));

        // Verify no overflow occurred
        let (type_pref, local_pref, component) = decompose_priority(priority);
        assert_eq!(type_pref, TYPE_PREFERENCE_HOST);
        assert_eq!(local_pref, MAX_LOCAL_PREFERENCE);
        assert_eq!(component, MAX_COMPONENT_ID);
    }

    #[test]
    fn test_prflx_priority() {
        let prflx_controlling = calculate_prflx_priority(1, true);
        let prflx_controlled = calculate_prflx_priority(1, false);

        // Controlling should have slightly higher priority
        assert!(prflx_controlling > prflx_controlled);

        // Both should use peer reflexive type preference
        let (type_pref_ctrl, _, _) = decompose_priority(prflx_controlling);
        let (type_pref_ctld, _, _) = decompose_priority(prflx_controlled);

        assert_eq!(type_pref_ctrl, TYPE_PREFERENCE_PRFLX);
        assert_eq!(type_pref_ctld, TYPE_PREFERENCE_PRFLX);
    }

    #[test]
    fn test_interface_type_detection() {
        assert_eq!(InterfaceType::from_name("eth0"), InterfaceType::Ethernet);
        assert_eq!(InterfaceType::from_name("en0"), InterfaceType::Ethernet);
        assert_eq!(InterfaceType::from_name("wlan0"), InterfaceType::Wifi);
        assert_eq!(InterfaceType::from_name("tun0"), InterfaceType::Vpn);
        assert_eq!(InterfaceType::from_name("docker0"), InterfaceType::Virtual);
        assert_eq!(InterfaceType::from_name("rmnet_data0"), InterfaceType::Cellular);
        assert_eq!(InterfaceType::from_name("unknown"), InterfaceType::Unknown);
    }

    #[test]
    fn test_pair_priority_properties() {
        // Test that pair priority maintains consistent ordering
        let priorities = vec![1000u32, 2000, 3000, 4000];

        for &p1 in &priorities {
            for &p2 in &priorities {
                let pair_ctrl = calculate_pair_priority(true, p1, p2);
                let pair_ctld = calculate_pair_priority(false, p1, p2);

                // Pair priority should be deterministic
                assert_eq!(pair_ctrl, pair_ctld);

                // Higher individual priorities should generally yield higher pair priorities
                if p1 > 1000 && p2 > 1000 {
                    let lower_pair = calculate_pair_priority(true, 1000, 1000);
                    assert!(pair_ctrl > lower_pair);
                }
            }
        }
    }
}