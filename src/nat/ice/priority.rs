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
    fn test_local_preference() {
        let pref1 = calculate_local_preference(false, InterfaceType::Ethernet, IpVersion::V4);
        let pref2 = calculate_local_preference(true, InterfaceType::Cellular, IpVersion::V6);
        
        // Non-VPN ethernet should have higher preference than VPN cellular
        assert!(pref1 > pref2);
    }
}