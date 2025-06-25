// src/nat/mod.rs
//! NAT (Network Address Translation) traversal module for SHARP3
//!
//! Provides comprehensive NAT traversal capabilities including:
//! - UPnP/IGD port mapping
//! - NAT-PMP port forwarding
//! - STUN-based NAT detection
//! - Hole punching techniques
//! - ICE connectivity establishment
//! - TURN relay fallback

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use serde::{Serialize, Deserialize};

// Core error handling
pub mod error;
pub use error::{NatError, NatResult};

// STUN implementation
pub mod stun;
pub use stun::{
    StunService, StunConfig, StunClient, StunServer,
    NatBehavior, MappingBehavior, FilteringBehavior,
};

// TURN implementation
pub mod turn;
pub use turn::server::{
    TurnClient, TurnServer, TurnServerConfig, TurnCredentials,
    AllocationState, RelayAddress,
};

// ICE implementation
pub mod ice;
pub use ice::{
    IceAgent, IceConfig, IceRole, IceState, IceEvent,
    Candidate, CandidateType, CandidateAddress, CandidateExtensions,
    TcpType, IceTransportPolicy,
    BundlePolicy, RtcpMuxPolicy,
};

// Port forwarding implementations
pub mod port_forwarding;

// NAT hole punching
pub mod hole_punch;

// Network interface discovery
pub mod interface;

// **NEW: Integration managers - добавляем без конфликтов**
pub mod stun_turn_manager;
pub mod ice_integration;

// Re-export integration types with alias to avoid conflicts
pub use stun_turn_manager::{
    StunTurnManager as StunTurnIntegration,
    StunTurnConfig as StunTurnIntegrationConfig,
    StunTurnEvent,
    TurnServerInfo, TurnTransport, CandidateGatheringRequest,
    CandidateGatheringResult, TurnAllocationInfo, ConnectionQualityMetrics,
    create_stun_turn_manager,
};

pub use ice_integration::{
    Sharp3IceIntegration, IceSession as Sharp3IceSession,
    IceParameters, IceGatheringConfig,
    QualityThresholds, IceIntegrationEvent, IceIntegrationStats,
    create_ice_session_with_sharp,
};

/// NAT type classification based on RFC 3489 and 5780
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// No NAT (public IP)
    Open,
    /// Full cone NAT
    FullCone,
    /// Address-restricted NAT
    AddressRestricted,
    /// Port-restricted NAT
    PortRestricted,
    /// Symmetric NAT
    Symmetric,
    /// Unknown/undetectable
    Unknown,
}

/// Network connectivity status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityStatus {
    /// Direct connectivity possible
    Direct,
    /// NAT traversal required
    NatTraversal,
    /// Relay required
    RelayRequired,
    /// No connectivity possible
    Blocked,
    /// Status unknown
    Unknown,
}

/// Supported NAT protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatProtocol {
    /// Universal Plug and Play
    UPnP,
    /// NAT Port Mapping Protocol
    NatPMP,
    /// Port Control Protocol
    PCP,
    /// Manual configuration
    Manual,
}

/// Network information discovered by NAT manager
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    /// Local address
    pub local_addr: SocketAddr,
    /// Public address (if discoverable)
    pub public_addr: Option<SocketAddr>,
    /// NAT type
    pub nat_type: NatType,
    /// Available protocols
    pub supported_protocols: Vec<NatProtocol>,
    /// Port mappings created
    pub port_mappings: Vec<PortMapping>,
    /// Connectivity status
    pub connectivity: ConnectivityStatus,
    /// Network interfaces
    pub interfaces: Vec<NetworkInterface>,
}

/// Port mapping information
#[derive(Debug, Clone)]
pub struct PortMapping {
    /// Internal address
    pub internal_addr: SocketAddr,
    /// External address
    pub external_addr: SocketAddr,
    /// Transport protocol
    pub transport: TransportProtocol,
    /// Mapping protocol used
    pub protocol: NatProtocol,
    /// Mapping lifetime
    pub lifetime: Duration,
    /// Gateway address
    pub gateway: IpAddr,
    /// Mapping epoch (for NAT-PMP)
    pub epoch: Option<u32>,
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Interface name
    pub name: String,
    /// Interface addresses
    pub addrs: Vec<IpAddr>,
    /// Interface flags
    pub flags: u32,
    /// Interface index
    pub index: u32,
    /// Interface MTU
    pub mtu: Option<u32>,
}

/// Transport protocol for mappings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// UDP protocol
    Udp,
    /// TCP protocol
    Tcp,
    /// Both UDP and TCP
    Both,
}

impl From<TransportProtocol> for port_forwarding::Protocol {
    fn from(tp: TransportProtocol) -> Self {
        match tp {
            TransportProtocol::Udp => port_forwarding::Protocol::UDP,
            TransportProtocol::Tcp => port_forwarding::Protocol::TCP,
            TransportProtocol::Both => port_forwarding::Protocol::Both,
        }
    }
}

/// Configuration for NAT manager
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// Enable UPnP/IGD
    pub enable_upnp: bool,
    /// Enable NAT-PMP
    pub enable_natpmp: bool,
    /// Enable PCP
    pub enable_pcp: bool,
    /// Enable STUN
    pub enable_stun: bool,
    /// STUN servers
    pub stun_servers: Vec<String>,
    /// Discovery timeout
    pub discovery_timeout: Duration,
    /// Port mapping lifetime
    pub mapping_lifetime: Duration,
    /// Retry attempts
    pub retry_attempts: u32,
    /// Enable IPv6
    pub enable_ipv6: bool,
    /// Preferred external port range
    pub port_range: Option<(u16, u16)>,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enable_upnp: true,
            enable_natpmp: true,
            enable_pcp: false,
            enable_stun: true,
            stun_servers: vec![
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
                "stun2.l.google.com:19302".to_string(),
                "stun3.l.google.com:19302".to_string(),
            ],
            discovery_timeout: Duration::from_secs(10),
            mapping_lifetime: Duration::from_secs(3600),
            retry_attempts: 3,
            enable_ipv6: true,
            port_range: None,
        }
    }
}

/// Main NAT manager for the existing SHARP protocol
pub struct NatManager {
    config: NatConfig,
    network_info: Option<NetworkInfo>,
    port_forwarder: Option<Arc<port_forwarding::PortForwarder>>,
    stun_client: Option<Arc<stun::StunClient>>,
    active_mappings: HashMap<u16, PortMapping>,
}

impl NatManager {
    /// Create new NAT manager
    pub fn new(config: NatConfig) -> Self {
        Self {
            config,
            network_info: None,
            port_forwarder: None,
            stun_client: None,
            active_mappings: HashMap::new(),
        }
    }

    /// Initialize NAT manager and discover network topology
    pub async fn initialize(&mut self, socket: &tokio::net::UdpSocket) -> NatResult<NetworkInfo> {
        tracing::info!("Initializing NAT manager");

        let local_addr = socket.local_addr().map_err(|e| {
            NatError::Network(format!("Failed to get local address: {}", e))
        })?;

        let mut network_info = NetworkInfo {
            local_addr,
            public_addr: None,
            nat_type: NatType::Unknown,
            supported_protocols: Vec::new(),
            port_mappings: Vec::new(),
            connectivity: ConnectivityStatus::Unknown,
            interfaces: Vec::new(),
        };

        // Discover network interfaces
        if let Ok(interfaces) = interface::discover_interfaces().await {
            network_info.interfaces = interfaces;
        }

        // Initialize port forwarder if enabled
        if self.config.enable_upnp || self.config.enable_natpmp {
            match port_forwarding::PortForwarder::new().await {
                Ok(forwarder) => {
                    self.port_forwarder = Some(Arc::new(forwarder));

                    if self.config.enable_upnp {
                        network_info.supported_protocols.push(NatProtocol::UPnP);
                    }
                    if self.config.enable_natpmp {
                        network_info.supported_protocols.push(NatProtocol::NatPMP);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to initialize port forwarder: {}", e);
                }
            }
        }

        // Initialize STUN client if enabled
        if self.config.enable_stun && !self.config.stun_servers.is_empty() {
            let stun_config = stun::StunConfig {
                servers: self.config.stun_servers.iter()
                    .map(|s| stun::StunServerInfo {
                        address: s.clone(),
                        credentials: None,
                    })
                    .collect(),
                timeout: self.config.discovery_timeout,
                retry_count: self.config.retry_attempts,
            };

            self.stun_client = Some(Arc::new(stun::StunClient::new(stun_config)));
        }

        // Perform NAT discovery via STUN
        if let Some(stun_client) = &self.stun_client {
            match stun_client.get_mapped_address(socket).await {
                Ok(public_addr) => {
                    network_info.public_addr = Some(public_addr);

                    // Detect NAT type
                    match stun_client.detect_nat_behavior(socket).await {
                        Ok(behavior) => {
                            network_info.nat_type = behavior.to_simple_nat_type();
                        }
                        Err(e) => {
                            tracing::warn!("NAT type detection failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("STUN discovery failed: {}", e);
                }
            }
        }

        // Determine connectivity status
        network_info.connectivity = self.determine_connectivity(&network_info);

        self.network_info = Some(network_info.clone());
        tracing::info!("NAT manager initialized successfully");

        Ok(network_info)
    }

    /// Create port mapping
    pub async fn create_mapping(&mut self, internal_port: u16, external_port: Option<u16>) -> NatResult<PortMapping> {
        let forwarder = self.port_forwarder.as_ref()
            .ok_or_else(|| NatError::NotSupported("Port forwarding not available".to_string()))?;

        let network_info = self.network_info.as_ref()
            .ok_or_else(|| NatError::Configuration("NAT manager not initialized".to_string()))?;

        let config = port_forwarding::MappingConfig {
            internal_addr: SocketAddr::new(network_info.local_addr.ip(), internal_port),
            external_port,
            transport: port_forwarding::Protocol::UDP,
            lifetime: self.config.mapping_lifetime,
            description: "SHARP3 Transfer".to_string(),
            protocols: vec![port_forwarding::MappingProtocol::UPnPIGD, port_forwarding::MappingProtocol::NatPMP],
        };

        let mapping = forwarder.create_mapping(&config).await?;

        let port_mapping = PortMapping {
            internal_addr: mapping.internal_addr,
            external_addr: mapping.external_addr,
            transport: TransportProtocol::Udp,
            protocol: NatProtocol::UPnP, // Could be NatPMP depending on which succeeded
            lifetime: mapping.lifetime,
            gateway: mapping.gateway,
            epoch: mapping.epoch,
        };

        self.active_mappings.insert(internal_port, port_mapping.clone());

        Ok(port_mapping)
    }

    /// Remove port mapping
    pub async fn remove_mapping(&mut self, internal_port: u16) -> NatResult<()> {
        if let Some(mapping) = self.active_mappings.remove(&internal_port) {
            if let Some(forwarder) = &self.port_forwarder {
                let config = port_forwarding::MappingConfig {
                    internal_addr: mapping.internal_addr,
                    external_port: Some(mapping.external_addr.port()),
                    transport: mapping.transport.into(),
                    lifetime: Duration::ZERO, // Delete mapping
                    description: "SHARP3 Transfer".to_string(),
                    protocols: vec![port_forwarding::MappingProtocol::UPnPIGD, port_forwarding::MappingProtocol::NatPMP],
                };

                forwarder.remove_mapping(&config).await?;
            }
        }
        Ok(())
    }

    /// Get network information
    pub fn get_network_info(&self) -> Option<&NetworkInfo> {
        self.network_info.as_ref()
    }

    /// Get active mappings
    pub fn get_active_mappings(&self) -> &HashMap<u16, PortMapping> {
        &self.active_mappings
    }

    /// Determine connectivity status based on discovered information
    fn determine_connectivity(&self, network_info: &NetworkInfo) -> ConnectivityStatus {
        if network_info.public_addr.is_some() {
            match network_info.nat_type {
                NatType::Open => ConnectivityStatus::Direct,
                NatType::FullCone | NatType::AddressRestricted | NatType::PortRestricted => {
                    if !network_info.supported_protocols.is_empty() {
                        ConnectivityStatus::NatTraversal
                    } else {
                        ConnectivityStatus::RelayRequired
                    }
                }
                NatType::Symmetric => ConnectivityStatus::RelayRequired,
                NatType::Unknown => ConnectivityStatus::Unknown,
            }
        } else {
            ConnectivityStatus::Blocked
        }
    }

    /// Perform hole punching attempt
    pub async fn attempt_hole_punch(&self, peer_addr: SocketAddr, socket: &tokio::net::UdpSocket) -> NatResult<bool> {
        hole_punching::attempt_hole_punch(socket, peer_addr, self.config.discovery_timeout).await
    }

    /// Get recommended strategy for connection to peer
    pub fn get_connection_strategy(&self, peer_network_info: Option<&NetworkInfo>) -> ConnectionStrategy {
        let local_info = match &self.network_info {
            Some(info) => info,
            None => return ConnectionStrategy::Unknown,
        };

        match (local_info.connectivity, peer_network_info.map(|p| p.connectivity)) {
            (ConnectivityStatus::Direct, Some(ConnectivityStatus::Direct)) => ConnectionStrategy::Direct,
            (ConnectivityStatus::Direct, _) | (_, Some(ConnectivityStatus::Direct)) => ConnectionStrategy::HolePunch,
            (ConnectivityStatus::NatTraversal, Some(ConnectivityStatus::NatTraversal)) => {
                if local_info.nat_type == NatType::Symmetric ||
                    peer_network_info.map(|p| p.nat_type) == Some(NatType::Symmetric) {
                    ConnectionStrategy::Relay
                } else {
                    ConnectionStrategy::HolePunch
                }
            }
            _ => ConnectionStrategy::Relay,
        }
    }
}

/// Connection strategy recommendation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStrategy {
    /// Direct connection possible
    Direct,
    /// Try hole punching
    HolePunch,
    /// Use relay server
    Relay,
    /// Strategy unknown
    Unknown,
}

impl NatBehavior {
    /// Convert to simple NAT type classification
    pub fn to_simple_nat_type(&self) -> NatType {
        use MappingBehavior::*;
        use FilteringBehavior::*;

        match (self.mapping_behavior, self.filtering_behavior) {
            (EndpointIndependent, EndpointIndependent) => NatType::FullCone,
            (EndpointIndependent, AddressDependent) => NatType::AddressRestricted,
            (EndpointIndependent, AddressPortDependent) => NatType::PortRestricted,
            (AddressDependent, _) | (AddressPortDependent, _) => NatType::Symmetric,
            (Unknown, _) | (_, Unknown) => NatType::Unknown,
        }
    }

    /// Calculate P2P connectivity score (0.0 = impossible, 1.0 = perfect)
    pub fn p2p_score(&self) -> f64 {
        let mapping_score = match self.mapping_behavior {
            MappingBehavior::EndpointIndependent => 1.0,
            MappingBehavior::AddressDependent => 0.7,
            MappingBehavior::AddressPortDependent => 0.3,
            MappingBehavior::Unknown => 0.1,
        };

        let filtering_score = match self.filtering_behavior {
            FilteringBehavior::EndpointIndependent => 1.0,
            FilteringBehavior::AddressDependent => 0.8,
            FilteringBehavior::AddressPortDependent => 0.5,
            FilteringBehavior::Unknown => 0.1,
        };

        (mapping_score + filtering_score) / 2.0
    }
}

// Factory functions for easy setup

/// Create a basic NAT manager with default settings
pub fn create_basic_nat_manager() -> NatManager {
    NatManager::new(NatConfig::default())
}

/// Create a NAT manager optimized for P2P gaming
pub fn create_gaming_nat_manager() -> NatManager {
    let config = NatConfig {
        discovery_timeout: Duration::from_secs(5),
        retry_attempts: 5,
        mapping_lifetime: Duration::from_secs(1800), // 30 minutes
        port_range: Some((49152, 65535)), // Dynamic ports
        ..Default::default()
    };
    NatManager::new(config)
}

/// Create a NAT manager for file transfer applications
pub fn create_file_transfer_nat_manager() -> NatManager {
    let config = NatConfig {
        discovery_timeout: Duration::from_secs(15),
        mapping_lifetime: Duration::from_secs(7200), // 2 hours
        ..Default::default()
    };
    NatManager::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_config_default() {
        let config = NatConfig::default();
        assert!(config.enable_upnp);
        assert!(config.enable_stun);
        assert!(!config.stun_servers.is_empty());
    }

    #[test]
    fn test_connectivity_determination() {
        let manager = NatManager::new(NatConfig::default());

        let network_info = NetworkInfo {
            local_addr: "192.168.1.100:12345".parse().unwrap(),
            public_addr: Some("203.0.113.1:12345".parse().unwrap()),
            nat_type: NatType::FullCone,
            supported_protocols: vec![NatProtocol::UPnP],
            port_mappings: Vec::new(),
            connectivity: ConnectivityStatus::Unknown,
            interfaces: Vec::new(),
        };

        let connectivity = manager.determine_connectivity(&network_info);
        assert_eq!(connectivity, ConnectivityStatus::NatTraversal);
    }

    #[test]
    fn test_nat_behavior_conversion() {
        let behavior = NatBehavior {
            mapping_behavior: MappingBehavior::EndpointIndependent,
            filtering_behavior: FilteringBehavior::EndpointIndependent,
            public_addresses: vec!["203.0.113.1:12345".parse().unwrap()],
            hairpinning_supported: true,
            delta: None,
        };

        assert_eq!(behavior.to_simple_nat_type(), NatType::FullCone);
        assert!(behavior.p2p_score() > 0.9);
    }
}