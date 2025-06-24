// src/nat/ice/priority.rs
//! Enhanced ICE priority calculation (RFC 8445 Section 5.1.2)
//!
//! This module provides comprehensive priority calculation with full RFC compliance,
//! including support for multiple interfaces, IPv6, and advanced scenarios.

use super::CandidateType;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;
use std::time::Duration;

/// Priority constants as per RFC 8445
pub const TYPE_PREFERENCE_HOST: u32 = 126;
pub const TYPE_PREFERENCE_PRFLX: u32 = 110;
pub const TYPE_PREFERENCE_SRFLX: u32 = 100;
pub const TYPE_PREFERENCE_RELAY: u32 = 0;

/// Maximum values for validation
pub const MAX_TYPE_PREFERENCE: u32 = 126;
pub const MAX_LOCAL_PREFERENCE: u32 = 65535;
pub const MAX_COMPONENT_ID: u32 = 256;

/// Priority calculation result with breakdown
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityBreakdown {
    /// Final calculated priority
    pub priority: u32,
    /// Type preference component
    pub type_preference: u32,
    /// Local preference component
    pub local_preference: u32,
    /// Component preference component
    pub component_preference: u32,
}

/// Calculate candidate priority per RFC 8445 Section 5.1.2.1
///
/// priority = (2^24)*(type preference) +
///            (2^8)*(local preference) +
///            (2^0)*(256 - component ID)
///
/// # Arguments
/// * `candidate_type` - The type of candidate
/// * `local_preference` - Local preference (0-65535)
/// * `component_id` - Component identifier (1-256)
///
/// # Returns
/// A 32-bit priority value
pub fn calculate_priority(
    candidate_type: CandidateType,
    local_preference: u32,
    component_id: u32,
) -> u32 {
    let breakdown = calculate_priority_with_breakdown(candidate_type, local_preference, component_id);
    breakdown.priority
}

/// Calculate priority with detailed breakdown
pub fn calculate_priority_with_breakdown(
    candidate_type: CandidateType,
    local_preference: u32,
    component_id: u32,
) -> PriorityBreakdown {
    // Type preference from RFC 8445 recommendations
    let type_preference = get_type_preference(candidate_type);

    // Validate and clamp values to prevent overflow
    let type_pref = type_preference.min(MAX_TYPE_PREFERENCE);
    let local_pref = local_preference.min(MAX_LOCAL_PREFERENCE);
    let component = component_id.clamp(1, MAX_COMPONENT_ID);
    let component_preference = 256 - component;

    // Calculate priority ensuring no overflow
    let priority = ((type_pref as u64) << 24) +
        ((local_pref as u64) << 8) +
        (component_preference as u64);

    // Ensure result fits in u32
    let final_priority = priority.min(u32::MAX as u64) as u32;

    PriorityBreakdown {
        priority: final_priority,
        type_preference: type_pref,
        local_preference: local_pref,
        component_preference,
    }
}

/// Get type preference for candidate type
pub fn get_type_preference(candidate_type: CandidateType) -> u32 {
    match candidate_type {
        CandidateType::Host => TYPE_PREFERENCE_HOST,
        CandidateType::PeerReflexive => TYPE_PREFERENCE_PRFLX,
        CandidateType::ServerReflexive => TYPE_PREFERENCE_SRFLX,
        CandidateType::Relay => TYPE_PREFERENCE_RELAY,
    }
}

/// Enhanced local preference calculation with comprehensive factors
#[derive(Debug, Clone)]
pub struct LocalPreferenceConfig {
    /// Base preference by interface type
    pub interface_type_weight: f64,
    /// IP version preference weight
    pub ip_version_weight: f64,
    /// VPN penalty weight
    pub vpn_penalty_weight: f64,
    /// Temporary address penalty weight
    pub temporary_penalty_weight: f64,
    /// Interface metric weight
    pub metric_weight: f64,
    /// Network security bonus weight
    pub security_bonus_weight: f64,
    /// Bandwidth bonus weight
    pub bandwidth_bonus_weight: f64,
}

impl Default for LocalPreferenceConfig {
    fn default() -> Self {
        Self {
            interface_type_weight: 1.0,
            ip_version_weight: 0.1,
            vpn_penalty_weight: 0.3,
            temporary_penalty_weight: 0.2,
            metric_weight: 0.1,
            security_bonus_weight: 0.05,
            bandwidth_bonus_weight: 0.05,
        }
    }
}

/// Comprehensive interface information for priority calculation
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Interface type
    pub interface_type: InterfaceType,
    /// Whether this is a VPN interface
    pub is_vpn: bool,
    /// Whether this is a temporary address (IPv6)
    pub is_temporary: bool,
    /// Interface metric (lower is better)
    pub metric: Option<u32>,
    /// Interface name
    pub name: String,
    /// Whether interface supports encryption
    pub supports_encryption: bool,
    /// Estimated bandwidth in bps
    pub estimated_bandwidth: Option<u64>,
    /// Interface status
    pub status: InterfaceStatus,
    /// Network security level
    pub security_level: NetworkSecurityLevel,
}

/// Interface status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceStatus {
    Up,
    Down,
    Dormant,
    Unknown,
}

/// Network security level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkSecurityLevel {
    Unknown = 0,
    Public = 1,
    Private = 2,
    Corporate = 3,
    Secure = 4,
}

/// Enhanced interface type with more granular classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InterfaceType {
    /// Wired Ethernet (highest preference)
    Ethernet,
    /// Thunderbolt/USB-C Ethernet
    ThunderboltEthernet,
    /// WiFi 6/6E
    Wifi6,
    /// WiFi 5 (802.11ac)
    Wifi5,
    /// WiFi 4 and older
    WifiLegacy,
    /// 5G Cellular
    Cellular5G,
    /// 4G/LTE Cellular
    Cellular4G,
    /// 3G and older cellular
    CellularLegacy,
    /// Bluetooth tethering
    Bluetooth,
    /// VPN interface
    Vpn,
    /// Virtual/bridge interface
    Virtual,
    /// Loopback interface
    Loopback,
    /// Unknown interface type
    Unknown,
}

impl InterfaceType {
    /// Get base preference score for interface type
    pub fn base_preference(&self) -> u32 {
        match self {
            Self::Ethernet => 250,
            Self::ThunderboltEthernet => 245,
            Self::Wifi6 => 200,
            Self::Wifi5 => 180,
            Self::WifiLegacy => 150,
            Self::Cellular5G => 120,
            Self::Cellular4G => 100,
            Self::CellularLegacy => 80,
            Self::Bluetooth => 60,
            Self::Vpn => 50,
            Self::Virtual => 30,
            Self::Loopback => 10,
            Self::Unknown => 5,
        }
    }

    /// Detect interface type from name patterns
    pub fn from_name(name: &str) -> Self {
        let lower = name.to_lowercase();

        // Check for specific patterns
        if lower.contains("eth") || lower.contains("en") && !lower.contains("wlan") {
            if lower.contains("thunderbolt") || lower.contains("usbc") {
                Self::ThunderboltEthernet
            } else {
                Self::Ethernet
            }
        } else if lower.contains("wlan") || lower.contains("wifi") || lower.contains("wl") {
            // Would need additional info to determine WiFi version
            Self::WifiLegacy
        } else if lower.contains("cell") || lower.contains("wwan") || lower.contains("rmnet") {
            // Would need additional info to determine cellular generation
            Self::CellularLegacy
        } else if lower.contains("bluetooth") || lower.contains("bt") {
            Self::Bluetooth
        } else if lower.contains("tun") || lower.contains("tap") || lower.contains("vpn") ||
            lower.contains("wg") || lower.contains("utun") {
            Self::Vpn
        } else if lower.contains("veth") || lower.contains("docker") || lower.contains("br") ||
            lower.contains("virbr") {
            Self::Virtual
        } else if lower.contains("lo") {
            Self::Loopback
        } else {
            Self::Unknown
        }
    }

    /// Check if this interface type is wireless
    pub fn is_wireless(&self) -> bool {
        matches!(self,
            Self::Wifi6 | Self::Wifi5 | Self::WifiLegacy |
            Self::Cellular5G | Self::Cellular4G | Self::CellularLegacy |
            Self::Bluetooth
        )
    }

    /// Check if this interface type is cellular
    pub fn is_cellular(&self) -> bool {
        matches!(self, Self::Cellular5G | Self::Cellular4G | Self::CellularLegacy)
    }

    /// Get expected latency characteristics
    pub fn expected_latency(&self) -> Duration {
        match self {
            Self::Ethernet | Self::ThunderboltEthernet => Duration::from_millis(1),
            Self::Wifi6 => Duration::from_millis(2),
            Self::Wifi5 => Duration::from_millis(5),
            Self::WifiLegacy => Duration::from_millis(10),
            Self::Cellular5G => Duration::from_millis(20),
            Self::Cellular4G => Duration::from_millis(50),
            Self::CellularLegacy => Duration::from_millis(100),
            Self::Bluetooth => Duration::from_millis(50),
            Self::Vpn => Duration::from_millis(100),
            Self::Virtual | Self::Loopback => Duration::from_millis(1),
            Self::Unknown => Duration::from_millis(100),
        }
    }
}

/// Calculate enhanced local preference with comprehensive factors
pub fn calculate_local_preference_enhanced(
    ip: &IpAddr,
    interface_info: &InterfaceInfo,
    config: &LocalPreferenceConfig,
) -> u32 {
    let mut preference = 0.0;

    // Base preference by interface type
    preference += interface_info.interface_type.base_preference() as f64 * config.interface_type_weight;

    // IP version preference (RFC 8421 dual-stack considerations)
    let ip_version_bonus = match ip {
        IpAddr::V4(_) => 10.0, // Small bonus for IPv4 compatibility
        IpAddr::V6(v6) => {
            if is_ipv6_temporary(v6) {
                5.0 // Temporary addresses get lower preference
            } else if is_ipv6_unique_local(v6) {
                15.0 // ULA addresses
            } else if is_ipv6_global_unicast(v6) {
                20.0 // Global IPv6 preferred
            } else {
                8.0 // Other IPv6 addresses
            }
        }
    };
    preference += ip_version_bonus * config.ip_version_weight;

    // Interface status bonus
    match interface_info.status {
        InterfaceStatus::Up => preference += 20.0,
        InterfaceStatus::Dormant => preference += 10.0,
        InterfaceStatus::Down => preference -= 50.0,
        InterfaceStatus::Unknown => preference += 5.0,
    }

    // Security level bonus
    preference += (interface_info.security_level as u32 as f64) * 5.0 * config.security_bonus_weight;

    // Encryption support bonus
    if interface_info.supports_encryption {
        preference += 10.0 * config.security_bonus_weight;
    }

    // Bandwidth bonus
    if let Some(bandwidth) = interface_info.estimated_bandwidth {
        let bandwidth_mbps = bandwidth / 1_000_000;
        let bandwidth_bonus = (bandwidth_mbps as f64).log10() * 10.0;
        preference += bandwidth_bonus * config.bandwidth_bonus_weight;
    }

    // Penalties
    if interface_info.is_vpn {
        preference -= 50.0 * config.vpn_penalty_weight;
    }

    if interface_info.is_temporary {
        preference -= 25.0 * config.temporary_penalty_weight;
    }

    // Interface metric penalty (lower metric is better)
    if let Some(metric) = interface_info.metric {
        let metric_penalty = (metric / 10).min(50) as f64;
        preference -= metric_penalty * config.metric_weight;
    }

    // Ensure positive preference and scale to 16-bit range
    let clamped_preference = preference.max(0.0).min(255.0);
    let scaled = (clamped_preference * 65535.0 / 255.0) as u32;
    scaled.min(65535)
}

/// Legacy local preference calculation for compatibility
pub fn calculate_local_preference(
    ip: &IpAddr,
    interface_type: InterfaceType,
    is_vpn: bool,
    is_temporary: bool,
    interface_metric: Option<u32>,
) -> u32 {
    let interface_info = InterfaceInfo {
        interface_type,
        is_vpn,
        is_temporary,
        metric: interface_metric,
        name: "unknown".to_string(),
        supports_encryption: false,
        estimated_bandwidth: None,
        status: InterfaceStatus::Up,
        security_level: NetworkSecurityLevel::Unknown,
    };

    calculate_local_preference_enhanced(ip, &interface_info, &LocalPreferenceConfig::default())
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

/// Priority calculator with caching for performance
#[derive(Debug)]
pub struct PriorityCalculator {
    cache: HashMap<String, u32>,
    config: LocalPreferenceConfig,
}

impl PriorityCalculator {
    /// Create new priority calculator
    pub fn new(config: LocalPreferenceConfig) -> Self {
        Self {
            cache: HashMap::new(),
            config,
        }
    }

    /// Calculate priority with caching
    pub fn calculate_cached(
        &mut self,
        candidate_type: CandidateType,
        ip: &IpAddr,
        interface_info: &InterfaceInfo,
        component_id: u32,
    ) -> u32 {
        let cache_key = format!(
            "{}:{}:{}:{}:{}",
            candidate_type as u8,
            ip,
            interface_info.interface_type as u8,
            interface_info.is_vpn,
            component_id
        );

        if let Some(&cached_priority) = self.cache.get(&cache_key) {
            return cached_priority;
        }

        let local_preference = calculate_local_preference_enhanced(ip, interface_info, &self.config);
        let priority = calculate_priority(candidate_type, local_preference, component_id);

        self.cache.insert(cache_key, priority);
        priority
    }

    /// Clear cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get cache size
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

impl Default for PriorityCalculator {
    fn default() -> Self {
        Self::new(LocalPreferenceConfig::default())
    }
}

/// IPv6 address classification functions
pub fn is_ipv6_temporary(ipv6: &Ipv6Addr) -> bool {
    // Simplified check - in practice would use interface flags
    // RFC 4941 temporary addresses have specific patterns
    false // Placeholder - would need OS-specific implementation
}

pub fn is_ipv6_unique_local(ipv6: &Ipv6Addr) -> bool {
    // ULA addresses: fc00::/7
    let segments = ipv6.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

pub fn is_ipv6_global_unicast(ipv6: &Ipv6Addr) -> bool {
    // Global unicast: 2000::/3
    let segments = ipv6.segments();
    (segments[0] & 0xe000) == 0x2000
}

pub fn is_ipv6_link_local(ipv6: &Ipv6Addr) -> bool {
    // Link-local: fe80::/10
    let segments = ipv6.segments();
    (segments[0] & 0xffc0) == 0xfe80
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

/// Compare two priorities
pub fn compare_priorities(priority1: u32, priority2: u32) -> std::cmp::Ordering {
    priority1.cmp(&priority2)
}

/// Get priority range for candidate type
pub fn priority_range_for_type(candidate_type: CandidateType) -> (u32, u32) {
    let type_pref = get_type_preference(candidate_type);
    let min_priority = (type_pref << 24) | 1; // Min local pref, max component
    let max_priority = (type_pref << 24) | (65535 << 8) | 255; // Max local pref, min component
    (min_priority, max_priority)
}

/// Calculate priority difference between two candidates
pub fn priority_difference(priority1: u32, priority2: u32) -> i64 {
    priority1 as i64 - priority2 as i64
}

/// Check if priority1 is significantly higher than priority2
pub fn is_significantly_higher(priority1: u32, priority2: u32, threshold: u32) -> bool {
    priority1 > priority2 && (priority1 - priority2) >= threshold
}

/// Priority statistics for analysis
#[derive(Debug, Default)]
pub struct PriorityStats {
    pub min_priority: Option<u32>,
    pub max_priority: Option<u32>,
    pub avg_priority: f64,
    pub count: u32,
    pub type_distribution: HashMap<CandidateType, u32>,
}

impl PriorityStats {
    /// Add priority to statistics
    pub fn add_priority(&mut self, priority: u32, candidate_type: CandidateType) {
        self.min_priority = Some(self.min_priority.map_or(priority, |min| min.min(priority)));
        self.max_priority = Some(self.max_priority.map_or(priority, |max| max.max(priority)));

        let new_count = self.count + 1;
        self.avg_priority = (self.avg_priority * self.count as f64 + priority as f64) / new_count as f64;
        self.count = new_count;

        *self.type_distribution.entry(candidate_type).or_insert(0) += 1;
    }

    /// Get priority spread (max - min)
    pub fn priority_spread(&self) -> Option<u32> {
        match (self.min_priority, self.max_priority) {
            (Some(min), Some(max)) => Some(max - min),
            _ => None,
        }
    }

    /// Get most common candidate type
    pub fn most_common_type(&self) -> Option<CandidateType> {
        self.type_distribution
            .iter()
            .max_by_key(|(_, &count)| count)
            .map(|(&candidate_type, _)| candidate_type)
    }
}

/// Advanced priority configuration
#[derive(Debug, Clone)]
pub struct AdvancedPriorityConfig {
    /// Custom type preferences
    pub type_preferences: HashMap<CandidateType, u32>,
    /// Interface-specific bonuses
    pub interface_bonuses: HashMap<InterfaceType, i32>,
    /// Security level multipliers
    pub security_multipliers: HashMap<NetworkSecurityLevel, f64>,
    /// Enable adaptive priority adjustment
    pub adaptive_priority: bool,
    /// Minimum priority difference for selection
    pub min_priority_difference: u32,
}

impl Default for AdvancedPriorityConfig {
    fn default() -> Self {
        let mut type_preferences = HashMap::new();
        type_preferences.insert(CandidateType::Host, TYPE_PREFERENCE_HOST);
        type_preferences.insert(CandidateType::PeerReflexive, TYPE_PREFERENCE_PRFLX);
        type_preferences.insert(CandidateType::ServerReflexive, TYPE_PREFERENCE_SRFLX);
        type_preferences.insert(CandidateType::Relay, TYPE_PREFERENCE_RELAY);

        let mut security_multipliers = HashMap::new();
        security_multipliers.insert(NetworkSecurityLevel::Secure, 1.1);
        security_multipliers.insert(NetworkSecurityLevel::Corporate, 1.05);
        security_multipliers.insert(NetworkSecurityLevel::Private, 1.02);
        security_multipliers.insert(NetworkSecurityLevel::Public, 1.0);
        security_multipliers.insert(NetworkSecurityLevel::Unknown, 0.95);

        Self {
            type_preferences,
            interface_bonuses: HashMap::new(),
            security_multipliers,
            adaptive_priority: false,
            min_priority_difference: 1000,
        }
    }
}

/// Advanced priority calculator with custom configuration
#[derive(Debug)]
pub struct AdvancedPriorityCalculator {
    config: AdvancedPriorityConfig,
    local_config: LocalPreferenceConfig,
    stats: PriorityStats,
}

impl AdvancedPriorityCalculator {
    /// Create new advanced calculator
    pub fn new(config: AdvancedPriorityConfig, local_config: LocalPreferenceConfig) -> Self {
        Self {
            config,
            local_config,
            stats: PriorityStats::default(),
        }
    }

    /// Calculate priority with advanced configuration
    pub fn calculate_advanced(
        &mut self,
        candidate_type: CandidateType,
        ip: &IpAddr,
        interface_info: &InterfaceInfo,
        component_id: u32,
    ) -> u32 {
        // Get custom type preference if configured
        let type_preference = self.config.type_preferences
            .get(&candidate_type)
            .copied()
            .unwrap_or_else(|| get_type_preference(candidate_type));

        // Calculate base local preference
        let mut local_preference = calculate_local_preference_enhanced(
            ip,
            interface_info,
            &self.local_config
        ) as f64;

        // Apply interface bonus
        if let Some(&bonus) = self.config.interface_bonuses.get(&interface_info.interface_type) {
            local_preference += bonus as f64;
        }

        // Apply security multiplier
        if let Some(&multiplier) = self.config.security_multipliers.get(&interface_info.security_level) {
            local_preference *= multiplier;
        }

        // Clamp to valid range
        let final_local_preference = (local_preference as u32).min(MAX_LOCAL_PREFERENCE);

        // Calculate final priority
        let priority = ((type_preference as u64) << 24) +
            ((final_local_preference as u64) << 8) +
            ((256 - component_id.clamp(1, MAX_COMPONENT_ID)) as u64);

        let final_priority = (priority as u32).min(u32::MAX);

        // Update statistics
        self.stats.add_priority(final_priority, candidate_type);

        final_priority
    }

    /// Get current statistics
    pub fn get_stats(&self) -> &PriorityStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = PriorityStats::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_priority_calculation() {
        // Test with known values from RFC examples
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
    fn test_priority_breakdown() {
        let breakdown = calculate_priority_with_breakdown(
            CandidateType::ServerReflexive,
            32767,
            2
        );

        assert_eq!(breakdown.type_preference, TYPE_PREFERENCE_SRFLX);
        assert_eq!(breakdown.local_preference, 32767);
        assert_eq!(breakdown.component_preference, 254);

        let expected = (100u32 << 24) + (32767u32 << 8) + 254;
        assert_eq!(breakdown.priority, expected);
    }

    #[test]
    fn test_pair_priority_formula() {
        // Test the RFC 8445 formula with specific values
        let controlling_priority = 2130706431u32;
        let controlled_priority = 1694498815u32;

        // Test when controlling
        let pair_priority = calculate_pair_priority(true, controlling_priority, controlled_priority);

        // Manual calculation according to RFC
        let g = controlling_priority as u64;
        let d = controlled_priority as u64;
        let expected = (d << 32) + (g << 1) + 1; // MIN=d, MAX=g, g>d

        assert_eq!(pair_priority, expected);

        // Test when controlled (priorities swap roles)
        let pair_priority_controlled = calculate_pair_priority(false, controlling_priority, controlled_priority);
        assert_eq!(pair_priority_controlled, expected); // Should be same result
    }

    #[test]
    fn test_interface_type_detection() {
        assert_eq!(InterfaceType::from_name("eth0"), InterfaceType::Ethernet);
        assert_eq!(InterfaceType::from_name("en0"), InterfaceType::Ethernet);
        assert_eq!(InterfaceType::from_name("wlan0"), InterfaceType::WifiLegacy);
        assert_eq!(InterfaceType::from_name("tun0"), InterfaceType::Vpn);
        assert_eq!(InterfaceType::from_name("docker0"), InterfaceType::Virtual);
        assert_eq!(InterfaceType::from_name("rmnet_data0"), InterfaceType::CellularLegacy);
        assert_eq!(InterfaceType::from_name("lo"), InterfaceType::Loopback);
        assert_eq!(InterfaceType::from_name("unknown"), InterfaceType::Unknown);
    }

    #[test]
    fn test_enhanced_local_preference() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv6_global = IpAddr::V6("2001:db8::1".parse().unwrap());

        let ethernet_info = InterfaceInfo {
            interface_type: InterfaceType::Ethernet,
            is_vpn: false,
            is_temporary: false,
            metric: Some(10),
            name: "eth0".to_string(),
            supports_encryption: false,
            estimated_bandwidth: Some(1_000_000_000), // 1 Gbps
            status: InterfaceStatus::Up,
            security_level: NetworkSecurityLevel::Private,
        };

        let vpn_info = InterfaceInfo {
            interface_type: InterfaceType::Vpn,
            is_vpn: true,
            is_temporary: false,
            metric: Some(100),
            name: "tun0".to_string(),
            supports_encryption: true,
            estimated_bandwidth: Some(100_000_000), // 100 Mbps
            status: InterfaceStatus::Up,
            security_level: NetworkSecurityLevel::Secure,
        };

        let config = LocalPreferenceConfig::default();

        // Ethernet with global IPv6 should have higher preference than VPN
        let pref_eth_v6 = calculate_local_preference_enhanced(&ipv6_global, &ethernet_info, &config);
        let pref_vpn_v4 = calculate_local_preference_enhanced(&ipv4, &vpn_info, &config);

        assert!(pref_eth_v6 > pref_vpn_v4);
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
    fn test_priority_validation() {
        // Valid priorities
        assert!(validate_priority(calculate_priority(CandidateType::Host, 1000, 1)));
        assert!(validate_priority(calculate_priority(CandidateType::Relay, 0, 256)));

        // Invalid priorities (manually constructed)
        assert!(!validate_priority(0xFFFFFFFF)); // All bits set
        assert!(!validate_priority(0xFF000000)); // Invalid type preference
    }

    #[test]
    fn test_priority_calculator_caching() {
        let mut calculator = PriorityCalculator::default();

        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let interface_info = InterfaceInfo {
            interface_type: InterfaceType::Ethernet,
            is_vpn: false,
            is_temporary: false,
            metric: None,
            name: "eth0".to_string(),
            supports_encryption: false,
            estimated_bandwidth: None,
            status: InterfaceStatus::Up,
            security_level: NetworkSecurityLevel::Unknown,
        };

        // First calculation should cache the result
        let priority1 = calculator.calculate_cached(
            CandidateType::Host,
            &ipv4,
            &interface_info,
            1,
        );

        // Second calculation should return cached result
        let priority2 = calculator.calculate_cached(
            CandidateType::Host,
            &ipv4,
            &interface_info,
            1,
        );

        assert_eq!(priority1, priority2);
        assert_eq!(calculator.cache_size(), 1);
    }

    #[test]
    fn test_ipv6_classification() {
        // Global unicast
        let global = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        assert!(is_ipv6_global_unicast(&global));
        assert!(!is_ipv6_unique_local(&global));
        assert!(!is_ipv6_link_local(&global));

        // Unique local
        let ula = "fc00::1".parse::<Ipv6Addr>().unwrap();
        assert!(is_ipv6_unique_local(&ula));
        assert!(!is_ipv6_global_unicast(&ula));

        // Link local
        let link_local = "fe80::1".parse::<Ipv6Addr>().unwrap();
        assert!(is_ipv6_link_local(&link_local));
        assert!(!is_ipv6_global_unicast(&link_local));
        assert!(!is_ipv6_unique_local(&link_local));
    }

    #[test]
    fn test_priority_stats() {
        let mut stats = PriorityStats::default();

        stats.add_priority(1000, CandidateType::Host);
        stats.add_priority(2000, CandidateType::ServerReflexive);
        stats.add_priority(1500, CandidateType::Host);

        assert_eq!(stats.count, 3);
        assert_eq!(stats.min_priority, Some(1000));
        assert_eq!(stats.max_priority, Some(2000));
        assert_eq!(stats.avg_priority, 1500.0);
        assert_eq!(stats.priority_spread(), Some(1000));
        assert_eq!(stats.most_common_type(), Some(CandidateType::Host));
    }

    #[test]
    fn test_priority_comparison_utilities() {
        let priority1 = 2000;
        let priority2 = 1000;

        assert_eq!(compare_priorities(priority1, priority2), std::cmp::Ordering::Greater);
        assert_eq!(priority_difference(priority1, priority2), 1000);
        assert!(is_significantly_higher(priority1, priority2, 500));
        assert!(!is_significantly_higher(priority1, priority2, 1500));
    }

    #[test]
    fn test_priority_range_for_type() {
        let (min, max) = priority_range_for_type(CandidateType::Host);

        let expected_min = (TYPE_PREFERENCE_HOST << 24) | 1;
        let expected_max = (TYPE_PREFERENCE_HOST << 24) | (65535 << 8) | 255;

        assert_eq!(min, expected_min);
        assert_eq!(max, expected_max);
    }
}