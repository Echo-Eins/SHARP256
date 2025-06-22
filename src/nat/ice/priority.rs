// src/nat/ice/priority.rs
//! ICE priority calculation (RFC 8445 Section 5.1.2)

use super::CandidateType;

/// Calculate candidate priority
pub fn calculate_priority(
    typ: CandidateType,
    local_preference: u32,
    component_id: u32,
) -> u32 {
    // RFC 8445 Section 5.1.2.1:
    // priority = (2^24)*(type preference) +
    //            (2^8)*(local preference) +
    //            (2^0)*(256 - component ID)

    let type_preference = typ.preference();

    // Local preference (0-65535, but we use 0-255)
    let local_pref = local_preference.min(255);

    // Component ID must be 1-256
    let component = component_id.clamp(1, 256);

    (type_preference << 24) + (local_pref << 8) + (256 - component)
}

/// Calculate pair priority as per RFC 8445 Section 6.1.2.3
///
/// FIXED: Corrected formula according to RFC 8445
/// G = controlling candidate priority
/// D = controlled candidate priority
pub fn calculate_pair_priority(
    controlling: bool,
    controlling_candidate_priority: u32,
    controlled_candidate_priority: u32,
) -> u64 {
    let (g, d) = if controlling {
        // When we are controlling, our priority is G
        (controlling_candidate_priority as u64, controlled_candidate_priority as u64)
    } else {
        // When we are controlled, remote priority is G
        (controlled_candidate_priority as u64, controlling_candidate_priority as u64)
    };

    // RFC 8445 formula: 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
    let min_priority = g.min(d);
    let max_priority = g.max(d);

    (1u64 << 32) * min_priority + 2 * max_priority + if g > d { 1 } else { 0 }
}

/// Calculate local preference based on interface properties
pub fn calculate_local_preference(
    is_vpn: bool,
    interface_type: InterfaceType,
    ip_version: IpVersion,
) -> u32 {
    let mut preference = 128u32; // Base preference

    // Prefer non-VPN interfaces
    if is_vpn {
        preference = preference.saturating_sub(50);
    }

    // Interface type preference
    match interface_type {
        InterfaceType::Ethernet => preference += 20,
        InterfaceType::Wifi => preference += 10,
        InterfaceType::Cellular => preference = preference.saturating_sub(20),
        InterfaceType::Unknown => {}
    }

    // IP version preference (slight preference for IPv4)
    match ip_version {
        IpVersion::V4 => preference += 5,
        IpVersion::V6 => {}
    }

    preference.min(255)
}

/// Interface type for local preference calculation
#[derive(Debug, Clone, Copy)]
pub enum InterfaceType {
    Ethernet,
    Wifi,
    Cellular,
    Unknown,
}

/// IP version
#[derive(Debug, Clone, Copy)]
pub enum IpVersion {
    V4,
    V6,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_calculation() {
        // Host candidate, component 1
        let priority = calculate_priority(CandidateType::Host, 128, 1);

        // Should be: (126 << 24) + (128 << 8) + 255
        let expected = (126u32 << 24) + (128u32 << 8) + 255u32;
        assert_eq!(priority, expected);
    }

    #[test]
    fn test_pair_priority_calculation() {
        // Test case from RFC 8445 example
        let controlling_priority = 2130706431u32; // Example priority
        let controlled_priority = 2113932031u32;  // Example priority

        // When controlling
        let pair_priority_controlling = calculate_pair_priority(
            true,
            controlling_priority,
            controlled_priority
        );

        // When controlled (should be different)
        let pair_priority_controlled = calculate_pair_priority(
            false,
            controlling_priority,
            controlled_priority
        );

        // The priorities should be different
        assert_ne!(pair_priority_controlling, pair_priority_controlled);

        // Verify formula: 2^32*MIN + 2*MAX + (G>D?1:0)
        let min = controlling_priority.min(controlled_priority) as u64;
        let max = controlling_priority.max(controlled_priority) as u64;
        let expected = (1u64 << 32) * min + 2 * max + 1; // +1 because controlling > controlled

        assert_eq!(pair_priority_controlling, expected);
    }

    #[test]
    fn test_local_preference() {
        let pref1 = calculate_local_preference(false, InterfaceType::Ethernet, IpVersion::V4);
        let pref2 = calculate_local_preference(true, InterfaceType::Cellular, IpVersion::V6);

        // Non-VPN ethernet should have higher preference than VPN cellular
        assert!(pref1 > pref2);
    }
}