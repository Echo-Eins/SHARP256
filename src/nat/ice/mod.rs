// src/nat/ice/mod.rs
//! Complete ICE (Interactive Connectivity Establishment) implementation
//!
//! This module provides a full implementation of ICE as specified in RFC 8445,
//! along with related specifications including:
//! - RFC 8838: Trickle ICE
//! - RFC 7675: STUN Usage for Consent Freshness
//! - RFC 8421: Guidelines for Multihomed and IPv4/IPv6 Dual-Stack ICE
//!
//! The implementation includes:
//! - Candidate gathering from multiple sources (host, STUN, TURN)
//! - Connectivity checks with proper prioritization
//! - Nomination procedures (regular and aggressive)
//! - State management and transitions
//! - Trickle ICE for incremental candidate exchange
//! - Consent freshness and keepalive mechanisms
//! - Integration with SHARP3 P2P system

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use futures::future::BoxFuture;
use crate::nat::error::NatResult;

pub mod candidate;
pub mod foundation;
pub mod priority;
pub mod gathering;
pub mod connectivity;
pub mod nomination;
pub mod agent;
pub mod states;
pub mod trickle;
pub mod keepalive;

// Re-export main types for convenience
pub use agent::{
    IceAgent, IceConfig, IceRole, IceState, IceEvent,
    IceTransportPolicy, BundlePolicy, RtcpMuxPolicy
};

pub use candidate::{
    Candidate, CandidateType, CandidateAddress, CandidateExtensions,
    TransportProtocol, TcpType, CandidateList, CandidatePair, CandidatePairState
};

pub use connectivity::{
    ConnectivityChecker, CheckResult, ConnectivityError,
    IceCredentials, CheckListEntry, CheckEntryState
};

pub use nomination::{
    NominationProcessor, NominationConfig, NominationMode,
    NominationState, NominationEvent
};

pub use gathering::{
    CandidateGatherer, GatheringConfig, GatheringEvent,
    GatheringPhase, GatheringStats, NetworkInterface,
    InterfaceFilter, TurnServerConfig
};

pub use states::{
    IceStateManager, IceSessionState, ComponentState,
    CheckListState, StateChangeEvent, StateMachineConfig
};

pub use trickle::{
    TrickleProcessor, TrickleConfig, TrickleCandidate,
    TrickleCandidateInfo, EndOfCandidates, TrickleEvent
};

pub use keepalive::{
    ConsentManager, ConsentConfig, ConsentState,
    ConnectionConsent, ConsentEvent, ActivityDirection
};

pub use priority::{
    calculate_priority, calculate_pair_priority, calculate_prflx_priority,
    InterfaceInfo, InterfaceType, InterfaceStatus, NetworkSecurityLevel,
    LocalPreferenceConfig, PriorityCalculator
};

pub use foundation::{
    calculate_foundation, calculate_host_foundation,
    calculate_server_reflexive_foundation, calculate_peer_reflexive_foundation,
    calculate_relay_foundation, validate_foundation
};

/// ICE library version
pub const ICE_VERSION: &str = "1.0.0";

/// Supported ICE specifications
pub const SUPPORTED_SPECS: &[&str] = &[
    "RFC 8445 - Interactive Connectivity Establishment (ICE)",
    "RFC 8838 - Trickle ICE",
    "RFC 7675 - STUN Usage for Consent Freshness",
    "RFC 8421 - Guidelines for Multihomed and IPv4/IPv6 Dual-Stack ICE",
    "RFC 5768 - Indicating Support for Interactive Connectivity Establishment (ICE) in the Session Description Protocol (SDP)",
];

/// ICE implementation features
#[derive(Debug, Clone)]
pub struct IceFeatures {
    /// Full ICE support (RFC 8445)
    pub full_ice: bool,

    /// Trickle ICE support (RFC 8838)
    pub trickle_ice: bool,

    /// Consent freshness (RFC 7675)
    pub consent_freshness: bool,

    /// IPv4/IPv6 dual stack
    pub dual_stack: bool,

    /// TCP candidates
    pub tcp_candidates: bool,

    /// mDNS candidates
    pub mdns_candidates: bool,

    /// Aggressive nomination
    pub aggressive_nomination: bool,

    /// Bundle support
    pub bundle_support: bool,
}

impl Default for IceFeatures {
    fn default() -> Self {
        Self {
            full_ice: true,
            trickle_ice: true,
            consent_freshness: true,
            dual_stack: true,
            tcp_candidates: true,
            mdns_candidates: true,
            aggressive_nomination: true,
            bundle_support: true,
        }
    }
}

/// NAT manager trait for ICE integration
pub trait IceNatManager: Send + Sync {
    /// Get server reflexive candidate for component
    fn get_server_reflexive(
        &self,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> BoxFuture<'static, NatResult<Option<Candidate>>>;

    /// Get relay candidate for component
    fn get_relay_candidate(
        &self,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> BoxFuture<'static, NatResult<Option<Candidate>>>;
}

/// Get ICE implementation features
pub fn get_ice_features() -> IceFeatures {
    IceFeatures::default()
}

/// Validate ICE configuration
pub fn validate_ice_config(config: &IceConfig) -> crate::nat::error::NatResult<()> {
    use crate::nat::error::NatError;

    // Validate components
    if config.components.is_empty() {
        return Err(NatError::Configuration("No components specified".to_string()));
    }

    for &component_id in &config.components {
        if component_id == 0 || component_id > 256 {
            return Err(NatError::Configuration(
                "Component ID must be between 1 and 256".to_string()
            ));
        }
    }

    // Validate timeouts
    if config.connectivity_timeout < std::time::Duration::from_secs(1) {
        return Err(NatError::Configuration(
            "Connectivity timeout too short".to_string()
        ));
    }

    if config.keepalive_interval < std::time::Duration::from_secs(5) {
        return Err(NatError::Configuration(
            "Keepalive interval too short".to_string()
        ));
    }

    // Validate gathering config
    if !config.gathering_config.gather_host_candidates &&
        !config.gathering_config.gather_server_reflexive &&
        !config.gathering_config.gather_relay_candidates {
        return Err(NatError::Configuration(
            "At least one candidate gathering method must be enabled".to_string()
        ));
    }

    // Validate STUN servers if server reflexive is enabled
    if config.gathering_config.gather_server_reflexive &&
        config.gathering_config.stun_servers.is_empty() {
        return Err(NatError::Configuration(
            "STUN servers required for server reflexive candidates".to_string()
        ));
    }

    // Validate TURN servers if relay is enabled
    if config.gathering_config.gather_relay_candidates &&
        config.gathering_config.turn_servers.is_empty() {
        return Err(NatError::Configuration(
            "TURN servers required for relay candidates".to_string()
        ));
    }

    Ok(())
}

/// Create optimized ICE configuration for P2P applications
pub fn create_p2p_ice_config() -> IceConfig {
    use std::time::Duration;

    let gathering_config = GatheringConfig {
        gather_host_candidates: true,
        gather_server_reflexive: true,
        gather_relay_candidates: false, // Disable for faster setup
        enable_mdns: false, // Disable for security
        enable_ipv4: true,
        enable_ipv6: true,
        enable_tcp: false, // UDP only for speed
        enable_udp: true,
        stun_servers: vec![
            "stun.l.google.com:19302".parse().unwrap(),
            "stun1.l.google.com:19302".parse().unwrap(),
        ],
        turn_servers: vec![],
        gathering_timeout: Duration::from_secs(5), // Fast gathering
        max_candidates_per_type: 3, // Limit candidates
        ..Default::default()
    };

    let nomination_config = NominationConfig {
        mode: NominationMode::Aggressive, // Faster connection
        nomination_timeout: Duration::from_secs(10),
        ..Default::default()
    };

    IceConfig {
        transport_policy: IceTransportPolicy::All,
        gathering_config,
        nomination_config,
        components: vec![1], // Single component for data
        max_pairs_per_component: 20,
        connectivity_timeout: Duration::from_secs(15),
        keepalive_interval: Duration::from_secs(25),
        enable_trickle: true,
        enable_consent_freshness: true,
        bundle_policy: BundlePolicy::MaxBundle,
        rtcp_mux_policy: RtcpMuxPolicy::Require,
    }
}

/// Create ICE configuration optimized for reliability
pub fn create_reliable_ice_config() -> IceConfig {
    use std::time::Duration;

    let gathering_config = GatheringConfig {
        gather_host_candidates: true,
        gather_server_reflexive: true,
        gather_relay_candidates: true, // Include relay for reliability
        enable_mdns: false,
        enable_ipv4: true,
        enable_ipv6: true,
        enable_tcp: true, // Include TCP for fallback
        enable_udp: true,
        stun_servers: vec![
            "stun.l.google.com:19302".parse().unwrap(),
            "stun1.l.google.com:19302".parse().unwrap(),
            "stun2.l.google.com:19302".parse().unwrap(),
            "stun3.l.google.com:19302".parse().unwrap(),
        ],
        turn_servers: vec![], // Would be configured with actual TURN servers
        gathering_timeout: Duration::from_secs(15), // Longer for more candidates
        max_candidates_per_type: 10,
        ..Default::default()
    };

    let nomination_config = NominationConfig {
        mode: NominationMode::Regular, // More thorough
        nomination_timeout: Duration::from_secs(20),
        prefer_relay: false, // Prefer direct when possible
        ..Default::default()
    };

    IceConfig {
        transport_policy: IceTransportPolicy::All,
        gathering_config,
        nomination_config,
        components: vec![1, 2], // RTP and RTCP
        max_pairs_per_component: 50,
        connectivity_timeout: Duration::from_secs(45),
        keepalive_interval: Duration::from_secs(25),
        enable_trickle: true,
        enable_consent_freshness: true,
        bundle_policy: BundlePolicy::Balanced,
        rtcp_mux_policy: RtcpMuxPolicy::None,
    }
}

/// ICE utility functions
pub mod utils {
    use super::*;
    use std::net::{IpAddr, SocketAddr};

    /// Check if two candidates can form a valid pair
    pub fn can_form_pair(local: &Candidate, remote: &Candidate) -> bool {
        // Must have same transport
        if local.transport != remote.transport {
            return false;
        }

        // Must have compatible address families
        match (local.ip(), remote.ip()) {
            (Some(local_ip), Some(remote_ip)) => {
                local_ip.is_ipv4() == remote_ip.is_ipv4()
            }
            _ => true, // mDNS candidates are compatible with anything
        }
    }

    /// Calculate estimated connection quality score
    pub fn calculate_connection_quality(pair: &CandidatePair) -> u32 {
        let mut score = 0;

        // Base score from priorities
        score += pair.local.priority / 1000;
        score += pair.remote.priority / 1000;

        // Bonus for direct connections
        if pair.local.candidate_type == CandidateType::Host &&
            pair.remote.candidate_type == CandidateType::Host {
            score += 10000;
        }

        // Penalty for relay
        if pair.local.candidate_type == CandidateType::Relay ||
            pair.remote.candidate_type == CandidateType::Relay {
            score = score.saturating_sub(5000);
        }

        // Bonus for UDP
        if pair.local.transport == TransportProtocol::Udp {
            score += 1000;
        }

        score
    }

    /// Get network path type description
    pub fn describe_network_path(pair: &CandidatePair) -> String {
        match (pair.local.candidate_type, pair.remote.candidate_type) {
            (CandidateType::Host, CandidateType::Host) => "Direct".to_string(),
            (CandidateType::ServerReflexive, CandidateType::ServerReflexive) => "NAT-to-NAT".to_string(),
            (CandidateType::Relay, _) | (_, CandidateType::Relay) => "Relayed".to_string(),
            _ => "Mixed".to_string(),
        }
    }

    /// Check if address is in private range
    pub fn is_private_address(addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(ipv4) => ipv4.is_private(),
            IpAddr::V6(ipv6) => {
                // Check for ULA (fc00::/7) and link-local (fe80::/10)
                let segments = ipv6.segments();
                (segments[0] & 0xfe00) == 0xfc00 || // ULA
                    (segments[0] & 0xffc0) == 0xfe80    // Link-local
            }
        }
    }

    /// Generate ICE ufrag
    pub fn generate_ufrag() -> String {
        use rand::Rng;
        const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

        let mut rng = rand::thread_rng();
        (0..4)
            .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
            .collect()
    }

    /// Generate ICE password
    pub fn generate_password() -> String {
        use rand::Rng;
        const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

        let mut rng = rand::thread_rng();
        (0..22)
            .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
            .collect()
    }
}

/// ICE debugging and diagnostics
pub mod diagnostics {
    use super::*;
    use std::collections::HashMap;

    /// ICE session diagnostic information
    #[derive(Debug, Clone)]
    pub struct IceDiagnostics {
        pub session_id: String,
        pub local_candidates: Vec<Candidate>,
        pub remote_candidates: Vec<Candidate>,
        pub candidate_pairs: Vec<CandidatePair>,
        pub selected_pairs: HashMap<u32, CandidatePair>,
        pub gathering_stats: GatheringStats,
        pub connectivity_stats: connectivity::ConnectivityStats,
        pub state_transitions: Vec<states::StateTransition>,
        pub error_log: Vec<String>,
    }

    /// Generate diagnostic report
    pub fn generate_diagnostic_report(agent: &IceAgent) -> String {
        // This would collect comprehensive diagnostic information
        // For now, return a placeholder
        format!("ICE Diagnostic Report\n\
                 Agent State: {:?}\n\
                 Role: {:?}\n\
                 Components: {:?}\n",
                "Unknown", // agent.get_state().await,
                "Unknown", // agent.get_role().await,
                "Unknown"  // agent.config.components
        )
    }

    /// Analyze connection failures
    pub fn analyze_connection_failure(diagnostics: &IceDiagnostics) -> Vec<String> {
        let mut issues = Vec::new();

        if diagnostics.local_candidates.is_empty() {
            issues.push("No local candidates gathered".to_string());
        }

        if diagnostics.remote_candidates.is_empty() {
            issues.push("No remote candidates received".to_string());
        }

        if diagnostics.candidate_pairs.is_empty() {
            issues.push("No candidate pairs formed".to_string());
        }

        if diagnostics.selected_pairs.is_empty() {
            issues.push("No pairs selected".to_string());
        }

        issues
    }
}

/// Re-export error types
pub use crate::nat::error::{NatError, NatResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ice_features() {
        let features = get_ice_features();
        assert!(features.full_ice);
        assert!(features.trickle_ice);
        assert!(features.consent_freshness);
    }

    #[test]
    fn test_p2p_config() {
        let config = create_p2p_ice_config();
        assert_eq!(config.components, vec![1]);
        assert!(config.enable_trickle);
        assert_eq!(config.nomination_config.mode, NominationMode::Aggressive);
    }

    #[test]
    fn test_reliable_config() {
        let config = create_reliable_ice_config();
        assert_eq!(config.components, vec![1, 2]);
        assert_eq!(config.nomination_config.mode, NominationMode::Regular);
    }

    #[test]
    fn test_config_validation() {
        let mut config = create_p2p_ice_config();
        assert!(validate_ice_config(&config).is_ok());

        // Test invalid config
        config.components.clear();
        assert!(validate_ice_config(&config).is_err());
    }

    #[test]
    fn test_utils() {
        use utils::*;

        let ufrag = generate_ufrag();
        assert_eq!(ufrag.len(), 4);

        let password = generate_password();
        assert_eq!(password.len(), 22);

        let local_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        assert!(is_private_address(&local_addr));

        let public_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        assert!(!is_private_address(&public_addr));
    }

    #[tokio::test]
    async fn test_ice_agent_creation() {
        let config = create_p2p_ice_config();
        let agent = IceAgent::new(config).await.unwrap();

        assert_eq!(agent.get_state().await, IceState::Gathering);
        assert!(agent.get_role().await.is_none());
    }
}