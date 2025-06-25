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
    StunService, StunConfig, StunClient,
    NatBehavior, MappingBehavior, FilteringBehavior,
};

// TURN implementation - ПРЯМОЙ ИМПОРТ из server.rs
pub mod turn;
// Убираем конфликтующий re-export из turn::server, импортируем прямо
pub use turn::{
    TurnServerConfig, AuthConfig, TurnCredentials,
    AllocationState, RelayAddress, TransportProtocol,
};

// ICE implementation
pub mod ice;
pub use ice::{
    IceAgent, IceConfig, IceRole, IceState, IceEvent,
    Candidate, CandidateType, CandidateAddress, CandidateExtensions,
    TcpType, IceTransportPolicy, BundlePolicy, RtcpMuxPolicy,
};

// Port forwarding implementations
pub mod port_forwarding;

// NAT hole punching
pub mod hole_punch;

// Network interface discovery
pub mod interface;

// УДАЛЕНЫ МЕНЕДЖЕРЫ:
// - stun_turn_manager
// - ice_integration

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
    pub gateway: Option<SocketAddr>,
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Interface name
    pub name: String,
    /// Interface addresses
    pub addresses: Vec<IpAddr>,
    /// Interface is up
    pub is_up: bool,
    /// Interface is loopback
    pub is_loopback: bool,
    /// Interface supports multicast
    pub is_multicast: bool,
}

// Простые утилитарные функции для прямого использования
/// Create basic STUN service for NAT detection
pub fn create_stun_service() -> StunService {
    StunService::new()
}

/// Create basic ICE configuration for P2P connections
pub fn create_ice_config() -> IceConfig {
    IceConfig::default()
}

/// Detect NAT type using STUN
pub async fn detect_nat_type(socket: &tokio::net::UdpSocket) -> NatResult<(NatType, NatBehavior)> {
    let stun_service = create_stun_service();
    stun_service.detect_nat_type(socket).await
}

/// Get public address via STUN
pub async fn get_public_address(socket: &tokio::net::UdpSocket) -> NatResult<SocketAddr> {
    let stun_service = create_stun_service();
    stun_service.get_public_address(socket).await
}