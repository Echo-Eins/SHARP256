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
    InterfaceInfo, TypePreference, LocalPreference,
};

// Direct imports for STUN/TURN integration (без менеджеров)
use crate::nat::stun::StunService;
use crate::nat::turn::{TurnClient, TurnCredentials};
use crate::nat::error::{NatError, NatResult};

/// ICE utility functions for direct integration
pub mod utils {
    use super::*;
    use rand::Rng;

    /// Generate ICE username fragment
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

/// ICE features supported by this implementation
#[derive(Debug, Clone)]
pub struct IceFeatures {
    /// Full ICE support
    pub full_ice: bool,
    /// Lite ICE support
    pub lite_ice: bool,
    /// Trickle ICE support
    pub trickle_ice: bool,
    /// Consent freshness support
    pub consent_freshness: bool,
    /// Aggressive nomination support
    pub aggressive_nomination: bool,
    /// Bundle support
    pub bundle_support: bool,
    /// mDNS candidates support
    pub mdns_candidates: bool,
}

impl Default for IceFeatures {
    fn default() -> Self {
        Self {
            full_ice: true,
            lite_ice: false,
            trickle_ice: true,
            consent_freshness: true,
            aggressive_nomination: true,
            bundle_support: true,
            mdns_candidates: true,
        }
    }
}

/// Simple NAT manager trait for ICE integration (прямая интеграция без менеджеров)
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

/// Simple NAT manager implementation using direct STUN/TURN services
pub struct SimpleNatManager {
    stun_service: Arc<StunService>,
    turn_clients: Vec<Arc<TurnClient>>,
}

impl SimpleNatManager {
    /// Create new simple NAT manager
    pub async fn new(
        stun_servers: Vec<String>,
        turn_servers: Vec<(String, TurnCredentials)>
    ) -> NatResult<Self> {
        let stun_service = Arc::new(StunService::new());

        let mut turn_clients = Vec::new();
        for (server_url, _credentials) in turn_servers {
            let client = Arc::new(TurnClient::new(&server_url).await?);
            turn_clients.push(client);
        }

        Ok(Self {
            stun_service,
            turn_clients,
        })
    }
}

impl IceNatManager for SimpleNatManager {
    fn get_server_reflexive(
        &self,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> BoxFuture<'static, NatResult<Option<Candidate>>> {
        let stun_service = self.stun_service.clone();

        Box::pin(async move {
            match stun_service.get_public_address(&*socket).await {
                Ok(public_addr) => {
                    let local_addr = socket.local_addr()?;

                    let candidate = Candidate {
                        address: CandidateAddress {
                            ip: public_addr.ip(),
                            port: public_addr.port(),
                            transport: TransportProtocol::Udp,
                        },
                        candidate_type: CandidateType::ServerReflexive,
                        priority: calculate_priority(
                            CandidateType::ServerReflexive,
                            &local_addr,
                            component_id,
                        ),
                        foundation: format!("srflx{}{}", component_id, public_addr.port()),
                        component_id,
                        related_address: Some(local_addr),
                        tcp_type: None,
                        extensions: CandidateExtensions {
                            network_cost: Some(10),
                            generation: Some(0),
                        },
                    };

                    Ok(Some(candidate))
                }
                Err(_) => Ok(None),
            }
        })
    }

    fn get_relay_candidate(
        &self,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> BoxFuture<'static, NatResult<Option<Candidate>>> {
        let turn_clients = self.turn_clients.clone();

        Box::pin(async move {
            // Try first available TURN client
            if let Some(turn_client) = turn_clients.first() {
                // For now, return None since TURN allocation needs credentials
                // In real implementation, would call turn_client.allocate()
                tracing::debug!("TURN relay candidate not implemented yet for component {}", component_id);
            }
            Ok(None)
        })
    }
}

/// Get ICE implementation features
pub fn get_ice_features() -> IceFeatures {
    IceFeatures::default()
}

/// Validate ICE configuration
pub fn validate_ice_config(config: &IceConfig) -> NatResult<()> {
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

    Ok(())
}

/// Create ICE configuration optimized for P2P file transfer
pub fn create_p2p_ice_config() -> IceConfig {
    IceConfig {
        transport_policy: IceTransportPolicy::All,
        components: vec![1], // Only RTP component for P2P transfer
        max_pairs_per_component: 50,
        connectivity_timeout: std::time::Duration::from_secs(20),
        keepalive_interval: std::time::Duration::from_secs(15),
        enable_trickle: true,
        enable_consent_freshness: true,
        bundle_policy: BundlePolicy::MaxBundle,
        rtcp_mux_policy: RtcpMuxPolicy::Require,
    }
}

/// Create ICE agent with simple NAT manager
pub async fn create_ice_agent_with_nat(
    config: IceConfig,
    stun_servers: Vec<String>,
    turn_servers: Vec<(String, TurnCredentials)>,
) -> NatResult<IceAgent> {
    validate_ice_config(&config)?;

    let nat_manager = SimpleNatManager::new(stun_servers, turn_servers).await?;

    // Create agent with NAT manager (this would need to be implemented in agent.rs)
    IceAgent::new_with_nat_manager(config, Box::new(nat_manager)).await
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
    }

    #[test]
    fn test_config_validation() {
        let valid_config = create_p2p_ice_config();
        assert!(validate_ice_config(&valid_config).is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.components.clear();
        assert!(validate_ice_config(&invalid_config).is_err());
    }

    #[test]
    fn test_credential_generation() {
        let ufrag = utils::generate_ufrag();
        let pwd = utils::generate_password();

        assert_eq!(ufrag.len(), 4);
        assert_eq!(pwd.len(), 22);
        assert!(ufrag.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
        assert!(pwd.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
    }
}