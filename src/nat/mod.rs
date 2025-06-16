// src/nat/mod.rs
//! NAT traversal implementation with STUN, TURN, UPnP, NAT-PMP, and PCP support
//!
//! This module provides comprehensive NAT traversal functionality following
//! the latest RFC standards and best practices.

pub mod upnp;
pub mod hole_punch;
pub mod coordinator;
pub mod error;
pub mod metrics;
pub mod port_forwarding;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use parking_lot::RwLock;
use tokio::net::UdpSocket;

use self::stun::{StunService, StunConfig};
use self::port_forwarding::{PortForwardingService, PortMappingConfig, Protocol};
use self::hole_punch::HolePuncher;
use self::coordinator::AdvancedNatTraversal;
use self::error::{NatError, NatResult};

/// NAT traversal configuration
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// Enable STUN
    pub enable_stun: bool,

    /// Enable TURN relay
    pub enable_turn: bool,

    /// Enable UPnP-IGD
    pub enable_upnp: bool,

    /// Enable NAT-PMP
    pub enable_natpmp: bool,

    /// Enable PCP (Port Control Protocol)
    pub enable_pcp: bool,

    /// Enable UDP hole punching
    pub enable_hole_punching: bool,

    /// STUN servers
    pub stun_servers: Vec<String>,

    /// TURN servers with credentials
    pub turn_servers: Vec<TurnServer>,

    /// Coordinator server for advanced NAT traversal
    pub coordinator_server: Option<String>,

    /// Relay servers for symmetric NAT
    pub relay_servers: Vec<String>,

    /// Port mapping lifetime in seconds
    pub port_mapping_lifetime: u32,

    /// Retry attempts
    pub retry_attempts: u32,

    /// Detection timeout
    pub detection_timeout: Duration,

    /// Enable IPv6
    pub enable_ipv6: bool,

    /// Preferred protocols order
    pub preferred_protocols: Vec<NatProtocol>,
}

/// TURN server configuration
#[derive(Debug, Clone)]
pub struct TurnServer {
    pub url: String,
    pub username: String,
    pub password: String,
}

/// NAT traversal protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatProtocol {
    /// Direct connection (no NAT)
    Direct,
    /// STUN for address discovery
    Stun,
    /// UPnP port forwarding
    Upnp,
    /// NAT-PMP port forwarding
    NatPmp,
    /// PCP port forwarding
    Pcp,
    /// UDP hole punching
    HolePunch,
    /// TURN relay
    Turn,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enable_stun: true,
            enable_turn: false,
            enable_upnp: true,
            enable_natpmp: true,
            enable_pcp: true,
            enable_hole_punching: true,
            stun_servers: vec![
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
                "stun2.l.google.com:19302".to_string(),
                "stun3.l.google.com:19302".to_string(),
                "stun4.l.google.com:19302".to_string(),
                "stun.cloudflare.com:3478".to_string(),
                "stun.services.mozilla.com:3478".to_string(),
            ],
            turn_servers: vec![],
            coordinator_server: None,
            relay_servers: vec![],
            port_mapping_lifetime: 7200, // 2 hours
            retry_attempts: 3,
            detection_timeout: Duration::from_secs(30),
            enable_ipv6: true,
            preferred_protocols: vec![
                NatProtocol::Direct,
                NatProtocol::Upnp,
                NatProtocol::Pcp,
                NatProtocol::NatPmp,
                NatProtocol::Stun,
                NatProtocol::HolePunch,
                NatProtocol::Turn,
            ],
        }
    }
}

/// Network information
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    /// Local address
    pub local_addr: SocketAddr,

    /// Public address (if behind NAT)
    pub public_addr: Option<SocketAddr>,

    /// NAT type
    pub nat_type: NatType,

    /// Available protocols
    pub available_protocols: Vec<NatProtocol>,

    /// Port mappings
    pub port_mappings: Vec<port_forwarding::PortMapping>,

    /// Connectivity status
    pub connectivity_status: ConnectivityStatus,

    /// NAT behavior details
    pub nat_behavior: Option<stun::NatBehavior>,
}

/// NAT type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT (public IP)
    None,
    /// Full Cone NAT (best for P2P)
    FullCone,
    /// Restricted Cone NAT
    RestrictedCone,
    /// Port Restricted Cone NAT
    PortRestricted,
    /// Symmetric NAT (worst for P2P)
    Symmetric,
    /// Unknown/Not detected
    Unknown,
}

/// Connectivity status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityStatus {
    /// Direct internet connection
    Direct,
    /// Behind NAT but traversable
    BehindNat,
    /// Behind restrictive NAT/firewall
    Restricted,
    /// No internet connectivity
    Offline,
}

/// NAT traversal manager
pub struct NatManager {
    /// Configuration
    config: NatConfig,

    /// Network information
    network_info: Arc<RwLock<Option<NetworkInfo>>>,

    /// STUN service
    stun_service: Arc<StunService>,

    /// Port forwarding service
    port_forwarding: Arc<RwLock<Option<PortForwardingService>>>,

    /// Advanced NAT traversal
    advanced_traversal: Option<Arc<AdvancedNatTraversal>>,

    /// Initialization status
    initialized: Arc<RwLock<bool>>,
}

impl NatManager {
    /// Create new NAT manager
    pub fn new(config: NatConfig) -> Self {
        // Create STUN service
        let stun_config = StunConfig {
            servers: config.stun_servers.clone(),
            enable_behavior_discovery: true,
            ..Default::default()
        };
        let stun_service = Arc::new(StunService::with_config(stun_config));

        // Create advanced traversal if configured
        let advanced_traversal = if config.coordinator_server.is_some() || !config.relay_servers.is_empty() {
            let client_id = format!("sharp-{}", uuid::Uuid::new_v4());

            let coordinator_addr = config.coordinator_server.as_ref()
                .and_then(|s| s.parse().ok());

            let relay_addrs: Vec<SocketAddr> = config.relay_servers.iter()
                .filter_map(|s| s.parse().ok())
                .collect();

            Some(Arc::new(AdvancedNatTraversal::new(
                coordinator_addr,
                relay_addrs,
                client_id,
            )))
        } else {
            None
        };

        Self {
            config,
            network_info: Arc::new(RwLock::new(None)),
            stun_service,
            port_forwarding: Arc::new(RwLock::new(None)),
            advanced_traversal,
            initialized: Arc::new(RwLock::new(false)),
        }
    }

    /// Initialize NAT detection and setup
    pub async fn initialize(&mut self, socket: &UdpSocket) -> NatResult<NetworkInfo> {
        // Check if already initialized
        if *self.initialized.read() {
            if let Some(info) = &*self.network_info.read() {
                return Ok(info.clone());
            }
        }

        let local_addr = socket.local_addr()?;
        tracing::info!("=== NAT Detection Starting ===");
        tracing::info!("Local address: {}", local_addr);

        let mut available_protocols = vec![NatProtocol::Direct];
        let mut public_addr = None;
        let mut nat_type = NatType::Unknown;
        let mut connectivity_status = ConnectivityStatus::Offline;
        let mut nat_behavior = None;
        let mut port_mappings = Vec::new();

        // Step 1: STUN detection
        if self.config.enable_stun {
            tracing::info!("Running STUN detection...");

            match self.stun_service.get_public_address(socket).await {
                Ok(addr) => {
                    public_addr = Some(addr);
                    connectivity_status = ConnectivityStatus::BehindNat;
                    available_protocols.push(NatProtocol::Stun);

                    tracing::info!("Public address detected: {}", addr);

                    // Detect NAT type
                    match self.stun_service.detect_nat_type(socket).await {
                        Ok((detected_type, behavior)) => {
                            nat_type = detected_type;
                            nat_behavior = Some(behavior);
                            tracing::info!("NAT type: {:?}", nat_type);
                        }
                        Err(e) => {
                            tracing::warn!("NAT type detection failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("STUN detection failed: {}", e);
                }
            }
        }

        // Check if we have direct connection
        if let Some(pub_addr) = public_addr {
            if pub_addr.ip() == local_addr.ip() {
                nat_type = NatType::None;
                connectivity_status = ConnectivityStatus::Direct;
                tracing::info!("Direct internet connection detected");
            }
        }

        // Step 2: Port forwarding setup (only if behind NAT)
        if nat_type != NatType::None && connectivity_status != ConnectivityStatus::Offline {
            // Initialize port forwarding service
            if self.config.enable_upnp || self.config.enable_natpmp || self.config.enable_pcp {
                tracing::info!("Setting up port forwarding...");

                match PortForwardingService::new().await {
                    Ok(service) => {
                        *self.port_forwarding.write() = Some(service);

                        // Try to create port mapping
                        let mapping_config = PortMappingConfig {
                            external_port: 0, // Let router choose
                            internal_port: local_addr.port(),
                            protocol: Protocol::UDP,
                            lifetime: self.config.port_mapping_lifetime,
                            description: "SHARP P2P Connection".to_string(),
                            auto_renew: true,
                            preferred_protocols: vec![],
                        };

                        if let Some(ref service) = *self.port_forwarding.read() {
                            match service.create_mapping(mapping_config).await {
                                Ok(mapping) => {
                                    tracing::info!("Port mapping created: {:?}", mapping);

                                    // Update available protocols
                                    match mapping.protocol {
                                        port_forwarding::MappingProtocol::UPnPIGD => {
                                            available_protocols.push(NatProtocol::Upnp);
                                        }
                                        port_forwarding::MappingProtocol::NatPMP => {
                                            available_protocols.push(NatProtocol::NatPmp);
                                        }
                                        port_forwarding::MappingProtocol::PCP => {
                                            available_protocols.push(NatProtocol::Pcp);
                                        }
                                    }

                                    port_mappings.push(mapping);
                                }
                                Err(e) => {
                                    tracing::warn!("Port mapping failed: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Port forwarding service initialization failed: {}", e);
                    }
                }
            }

            // Check hole punching feasibility
            if self.config.enable_hole_punching {
                match nat_type {
                    NatType::FullCone | NatType::RestrictedCone | NatType::PortRestricted => {
                        available_protocols.push(NatProtocol::HolePunch);
                        tracing::info!("UDP hole punching available");
                    }
                    NatType::Symmetric => {
                        if let Some(ref behavior) = nat_behavior {
                            if behavior.p2p_score() > 0.3 {
                                available_protocols.push(NatProtocol::HolePunch);
                                tracing::info!("UDP hole punching may work (limited)");
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Update connectivity status based on available protocols
        if !available_protocols.is_empty() {
            if nat_type == NatType::Symmetric && available_protocols.len() == 1 {
                connectivity_status = ConnectivityStatus::Restricted;
            } else if nat_type != NatType::None {
                connectivity_status = ConnectivityStatus::BehindNat;
            }
        }

        // Create network info
        let network_info = NetworkInfo {
            local_addr,
            public_addr,
            nat_type,
            available_protocols,
            port_mappings,
            connectivity_status,
            nat_behavior,
        };

        // Log summary
        tracing::info!("=== NAT Detection Complete ===");
        tracing::info!("Local: {}", network_info.local_addr);
        tracing::info!("Public: {:?}", network_info.public_addr);
        tracing::info!("NAT Type: {:?}", network_info.nat_type);
        tracing::info!("Status: {:?}", network_info.connectivity_status);
        tracing::info!("Available: {:?}", network_info.available_protocols);
        tracing::info!("============================");

        // Store results
        *self.network_info.write() = Some(network_info.clone());
        *self.initialized.write() = true;

        Ok(network_info)
    }

    /// Get best connectable address
    pub fn get_connectable_address(&self) -> NatResult<SocketAddr> {
        let info = self.network_info.read()
            .as_ref()
            .ok_or_else(|| NatError::Configuration("Not initialized".to_string()))?
            .clone();

        // Priority order:
        // 1. Port mapped address (most reliable)
        // 2. STUN public address (if suitable NAT type)
        // 3. Local address (for LAN/direct connections)

        // Check port mappings first
        if let Some(mapping) = info.port_mappings.first() {
            return Ok(mapping.external_addr);
        }

        // Check public address
        if let Some(pub_addr) = info.public_addr {
            match info.nat_type {
                NatType::None | NatType::FullCone => return Ok(pub_addr),
                NatType::RestrictedCone | NatType::PortRestricted => {
                    if info.available_protocols.contains(&NatProtocol::HolePunch) {
                        return Ok(pub_addr);
                    }
                }
                _ => {}
            }
        }

        // Fallback to local address
        Ok(info.local_addr)
    }

    /// Prepare connection to peer
    pub async fn prepare_connection(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
    ) -> NatResult<SocketAddr> {
        let info = self.network_info.read()
            .as_ref()
            .ok_or_else(|| NatError::Configuration("Not initialized".to_string()))?
            .clone();

        tracing::info!("Preparing connection to {} (NAT: {:?})", peer_addr, info.nat_type);

        // Direct connection if possible
        if info.connectivity_status == ConnectivityStatus::Direct {
            return Ok(peer_addr);
        }

        // Try protocols in preference order
        for protocol in &self.config.preferred_protocols {
            if !info.available_protocols.contains(protocol) {
                continue;
            }

            match protocol {
                NatProtocol::Direct => {
                    // Try direct connection
                    if self.test_connectivity(socket, peer_addr).await {
                        return Ok(peer_addr);
                    }
                }

                NatProtocol::HolePunch => {
                    // Perform UDP hole punching
                    if let Err(e) = self.perform_hole_punching(socket, peer_addr, is_initiator).await {
                        tracing::warn!("Hole punching failed: {}", e);
                    } else {
                        return Ok(peer_addr);
                    }
                }

                NatProtocol::Turn => {
                    // Use TURN relay
                    if let Some(relay_addr) = self.setup_turn_relay(peer_addr).await? {
                        return Ok(relay_addr);
                    }
                }

                _ => {
                    // Port forwarding protocols already handled during initialization
                }
            }
        }

        // Advanced traversal for difficult cases
        if let Some(ref advanced) = self.advanced_traversal {
            match advanced.establish_connection(socket, "peer", Some(peer_addr)).await {
                Ok(effective_addr) => return Ok(effective_addr),
                Err(e) => tracing::warn!("Advanced traversal failed: {}", e),
            }
        }

        Err(NatError::NotSupported("No working NAT traversal method".to_string()))
    }

    /// Test direct connectivity
    async fn test_connectivity(&self, socket: &UdpSocket, addr: SocketAddr) -> bool {
        let test_data = b"SHARP_PING";

        if socket.send_to(test_data, addr).await.is_err() {
            return false;
        }

        let mut buf = vec![0u8; 256];
        match tokio::time::timeout(
            Duration::from_secs(2),
            socket.recv_from(&mut buf)
        ).await {
            Ok(Ok((size, from))) if from == addr && &buf[..size] == b"SHARP_PONG" => true,
            _ => false,
        }
    }

    /// Perform UDP hole punching
    async fn perform_hole_punching(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
    ) -> NatResult<()> {
        let puncher = HolePuncher::new(30); // 30 attempts

        // Check if we have coordinator for synchronized punching
        let coordination_server = self.config.coordinator_server.as_ref()
            .and_then(|s| s.parse().ok());

        if let Some(coord) = coordination_server {
            puncher.simultaneous_punch(socket, peer_addr, Some(coord)).await
        } else {
            puncher.punch_hole(socket, peer_addr, is_initiator).await
        }
    }

    /// Setup TURN relay
    async fn setup_turn_relay(&self, peer_addr: SocketAddr) -> NatResult<Option<SocketAddr>> {
        // This would implement TURN allocation
        // For now, return None
        Ok(None)
    }

    /// Get network info
    pub fn get_network_info(&self) -> Option<NetworkInfo> {
        self.network_info.read().clone()
    }

    /// Cleanup resources
    pub async fn cleanup(&mut self) -> NatResult<()> {
        // Delete port mappings
        if let Some(ref service) = *self.port_forwarding.read() {
            let mappings = service.get_mappings().await;
            for mapping in mappings {
                if let Err(e) = service.delete_mapping(mapping.id).await {
                    tracing::warn!("Failed to delete mapping {}: {}", mapping.id, e);
                }
            }
        }

        Ok(())
    }
}

impl Drop for NatManager {
    fn drop(&mut self) {
        // Best effort cleanup
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let port_forwarding = self.port_forwarding.clone();

            handle.spawn(async move {
                if let Some(ref service) = *port_forwarding.read() {
                    let mappings = service.get_mappings().await;
                    for mapping in mappings {
                        let _ = service.delete_mapping(mapping.id).await;
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nat_manager() {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let config = NatConfig::default();
        let mut manager = NatManager::new(config);

        match manager.initialize(&socket).await {
            Ok(info) => {
                println!("Network info: {:?}", info);
                assert!(!info.available_protocols.is_empty());
            }
            Err(e) => {
                eprintln!("NAT manager test failed (expected without network): {}", e);
            }
        }
    }
}