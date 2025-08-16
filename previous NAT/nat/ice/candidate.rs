// src/nat/ice/candidate.rs
//! Enhanced ICE candidate representation and parsing (RFC 8445)
//!
//! This module provides comprehensive support for ICE candidates including:
//! - Full SDP parsing and generation
//! - IPv4 and IPv6 support
//! - TCP and UDP transport protocols
//! - mDNS candidate support
//! - Complete validation according to RFC 8445

use std::net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr};
use std::fmt;
use std::str::FromStr;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::foundation;
use crate::nat::ice::priority;

/// ICE candidate type (RFC 8445 Section 5.1.1.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum CandidateType {
    /// Host candidate (local address)
    Host = 0,
    /// Server reflexive (from STUN)
    ServerReflexive = 1,
    /// Peer reflexive (discovered during connectivity checks)
    PeerReflexive = 2,
    /// Relayed candidate (from TURN)
    Relay = 3,
}

impl CandidateType {
    /// Convert to string representation used in SDP
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::ServerReflexive => "srflx",
            Self::PeerReflexive => "prflx",
            Self::Relay => "relay",
        }
    }

    /// Get the type preference value (RFC 8445 Section 5.1.2.2)
    pub fn preference(&self) -> u32 {
        match self {
            Self::Host => 126,
            Self::PeerReflexive => 110,
            Self::ServerReflexive => 100,
            Self::Relay => 0,
        }
    }

    /// Parse from string representation
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "host" => Some(Self::Host),
            "srflx" => Some(Self::ServerReflexive),
            "prflx" => Some(Self::PeerReflexive),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }

    /// Check if this candidate type requires a related address
    pub fn requires_related_address(&self) -> bool {
        matches!(self, Self::ServerReflexive | Self::PeerReflexive | Self::Relay)
    }
}

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum TransportProtocol {
    Udp = 0,
    Tcp = 1,
}

impl TransportProtocol {
    /// Convert to string representation used in SDP
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }

    /// Convert to uppercase string representation
    pub fn to_upper_str(&self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
        }
    }

    /// Parse from string representation
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "UDP" => Some(Self::Udp),
            "TCP" => Some(Self::Tcp),
            _ => None,
        }
    }
}

/// TCP candidate type (RFC 6544)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpType {
    /// Active TCP candidate (will initiate TCP connections)
    Active,
    /// Passive TCP candidate (will accept TCP connections)
    Passive,
    /// Simultaneous-Open TCP candidate
    So,
}

impl TcpType {
    /// Convert to string representation used in SDP
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Passive => "passive",
            Self::So => "so",
        }
    }

    /// Parse from string representation
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "passive" => Some(Self::Passive),
            "so" => Some(Self::So),
            _ => None,
        }
    }
}

/// ICE candidate address type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateAddress {
    /// Regular IP address
    Ip(SocketAddr),
    /// mDNS address (RFC 8445 Section 5.1.1.4)
    MDns { hostname: String, port: u16 },
}

impl CandidateAddress {
    /// Get the port number
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::MDns { port, .. } => *port,
        }
    }

    /// Check if this is an IP address
    pub fn is_ip(&self) -> bool {
        matches!(self, Self::Ip(_))
    }

    /// Check if this is an mDNS address
    pub fn is_mdns(&self) -> bool {
        matches!(self, Self::MDns { .. })
    }

    /// Get IP address if available
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(addr) => Some(addr.ip()),
            Self::MDns { .. } => None,
        }
    }

    /// Get socket address if available
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Ip(addr) => Some(*addr),
            Self::MDns { .. } => None,
        }
    }

    /// Get mDNS hostname if available
    pub fn mdns_hostname(&self) -> Option<&str> {
        match self {
            Self::Ip(_) => None,
            Self::MDns { hostname, .. } => Some(hostname),
        }
    }
}

impl fmt::Display for CandidateAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{}", addr),
            Self::MDns { hostname, port } => write!(f, "{}:{}", hostname, port),
        }
    }
}

impl FromStr for CandidateAddress {
    type Err = NatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try to parse as socket address first
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(Self::Ip(addr));
        }

        // Try to parse as IP:port
        if let Some((ip_str, port_str)) = s.rsplit_once(':') {
            if let (Ok(ip), Ok(port)) = (ip_str.parse::<IpAddr>(), port_str.parse::<u16>()) {
                return Ok(Self::Ip(SocketAddr::new(ip, port)));
            }

            // Check if it's an mDNS hostname
            if is_valid_mdns_hostname(ip_str) {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Ok(Self::MDns {
                        hostname: ip_str.to_string(),
                        port,
                    });
                }
            }
        }

        Err(NatError::Platform("Invalid candidate address format".to_string()))
    }
}

/// Validate mDNS hostname according to RFC 6763
fn is_valid_mdns_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    // mDNS hostname should end with .local
    if !hostname.ends_with(".local") {
        return false;
    }

    // Check each label
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // Labels should start and end with alphanumeric characters
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }

        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }

    true
}

/// ICE candidate extension attributes
#[derive(Debug, Clone, Default)]
pub struct CandidateExtensions {
    /// Network ID (RFC 8445 Section 5.1.1.6)
    pub network_id: Option<u32>,

    /// Network cost (RFC 8421)
    pub network_cost: Option<u32>,

    /// Generation (for ICE restart)
    pub generation: Option<u32>,

    /// Extension attributes (name -> value)
    pub extensions: HashMap<String, String>,
}

impl CandidateExtensions {
    /// Create new empty extensions
    pub fn new() -> Self {
        Self::default()
    }

    /// Set network ID
    pub fn with_network_id(mut self, network_id: u32) -> Self {
        self.network_id = Some(network_id);
        self
    }

    /// Set network cost
    pub fn with_network_cost(mut self, network_cost: u32) -> Self {
        self.network_cost = Some(network_cost);
        self
    }

    /// Set generation
    pub fn with_generation(mut self, generation: u32) -> Self {
        self.generation = Some(generation);
        self
    }

    /// Add custom extension
    pub fn with_extension(mut self, name: String, value: String) -> Self {
        self.extensions.insert(name, value);
        self
    }
}

/// Enhanced ICE candidate
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Unique foundation (RFC 8445 Section 5.1.1.3)
    pub foundation: String,

    /// Component ID (1 for RTP, 2 for RTCP, etc.)
    pub component_id: u32,

    /// Transport protocol
    pub transport: TransportProtocol,

    /// Priority (RFC 8445 Section 5.1.2)
    pub priority: u32,

    /// Candidate address
    pub address: CandidateAddress,

    /// Candidate type
    pub candidate_type: CandidateType,

    /// Related address (for reflexive/relay candidates)
    pub related_address: Option<CandidateAddress>,

    /// TCP type (if TCP transport)
    pub tcp_type: Option<TcpType>,

    /// Extension attributes
    pub extensions: CandidateExtensions,

    /// Timestamp when candidate was discovered
    pub discovered_at: Instant,

    /// Base address for foundation calculation
    pub base_address: Option<IpAddr>,

    /// STUN/TURN server used (for reflexive/relay candidates)
    pub server_address: Option<SocketAddr>,
}

impl Candidate {
    /// Create a new host candidate
    pub fn new_host(
        address: SocketAddr,
        component_id: u32,
        transport: TransportProtocol,
        extensions: CandidateExtensions,
    ) -> Self {
        let base_ip = address.ip();
        let foundation = foundation::calculate_host_foundation(&base_ip, transport);
        let priority = priority::calculate_priority(
            CandidateType::Host,
            0, // Local preference will be calculated based on interface
            component_id,
        );

        Self {
            foundation,
            component_id,
            transport,
            priority,
            address: CandidateAddress::Ip(address),
            candidate_type: CandidateType::Host,
            related_address: None,
            tcp_type: if transport == TransportProtocol::Tcp {
                Some(TcpType::Passive) // Default for host candidates
            } else {
                None
            },
            extensions,
            discovered_at: Instant::now(),
            base_address: Some(base_ip),
            server_address: None,
        }
    }

    /// Create a new server reflexive candidate
    pub fn new_server_reflexive(
        address: SocketAddr,
        base_address: SocketAddr,
        component_id: u32,
        transport: TransportProtocol,
        stun_server: SocketAddr,
        extensions: CandidateExtensions,
    ) -> Self {
        let base_ip = base_address.ip();
        let foundation = foundation::calculate_server_reflexive_foundation(
            &base_ip,
            transport,
            &stun_server.ip(),
        );
        let priority = priority::calculate_priority(
            CandidateType::ServerReflexive,
            0, // Local preference
            component_id,
        );

        Self {
            foundation,
            component_id,
            transport,
            priority,
            address: CandidateAddress::Ip(address),
            candidate_type: CandidateType::ServerReflexive,
            related_address: Some(CandidateAddress::Ip(base_address)),
            tcp_type: if transport == TransportProtocol::Tcp {
                Some(TcpType::Active) // Default for srflx candidates
            } else {
                None
            },
            extensions,
            discovered_at: Instant::now(),
            base_address: Some(base_ip),
            server_address: Some(stun_server),
        }
    }

    /// Create a new peer reflexive candidate
    pub fn new_peer_reflexive(
        address: SocketAddr,
        base_address: SocketAddr,
        component_id: u32,
        transport: TransportProtocol,
        extensions: CandidateExtensions,
    ) -> Self {
        let base_ip = base_address.ip();
        let foundation = foundation::calculate_peer_reflexive_foundation(&base_ip, transport);
        let priority = priority::calculate_prflx_priority(component_id, true);

        Self {
            foundation,
            component_id,
            transport,
            priority,
            address: CandidateAddress::Ip(address),
            candidate_type: CandidateType::PeerReflexive,
            related_address: Some(CandidateAddress::Ip(base_address)),
            tcp_type: if transport == TransportProtocol::Tcp {
                Some(TcpType::So) // Default for prflx candidates
            } else {
                None
            },
            extensions,
            discovered_at: Instant::now(),
            base_address: Some(base_ip),
            server_address: None,
        }
    }

    /// Create a new relay candidate
    pub fn new_relay(
        address: SocketAddr,
        base_address: SocketAddr,
        component_id: u32,
        transport: TransportProtocol,
        turn_server: SocketAddr,
        extensions: CandidateExtensions,
    ) -> Self {
        let base_ip = base_address.ip();
        let foundation = foundation::calculate_relay_foundation(&base_ip, transport, &turn_server);
        let priority = priority::calculate_priority(
            CandidateType::Relay,
            0, // Local preference
            component_id,
        );

        Self {
            foundation,
            component_id,
            transport,
            priority,
            address: CandidateAddress::Ip(address),
            candidate_type: CandidateType::Relay,
            related_address: Some(CandidateAddress::Ip(base_address)),
            tcp_type: if transport == TransportProtocol::Tcp {
                Some(TcpType::Active) // Default for relay candidates
            } else {
                None
            },
            extensions,
            discovered_at: Instant::now(),
            base_address: Some(base_ip),
            server_address: Some(turn_server),
        }
    }

    /// Create mDNS candidate
    pub fn new_mdns(
        hostname: String,
        port: u16,
        component_id: u32,
        transport: TransportProtocol,
        candidate_type: CandidateType,
        extensions: CandidateExtensions,
    ) -> NatResult<Self> {
        if !is_valid_mdns_hostname(&hostname) {
            return Err(NatError::Platform("Invalid mDNS hostname".to_string()));
        }

        // For mDNS candidates, foundation is based on hostname
        let foundation = format!("mdns_{}", hostname.replace('.', "_"));
        let priority = priority::calculate_priority(candidate_type, 0, component_id);

        Ok(Self {
            foundation,
            component_id,
            transport,
            priority,
            address: CandidateAddress::MDns { hostname, port },
            candidate_type,
            related_address: None,
            tcp_type: if transport == TransportProtocol::Tcp {
                Some(TcpType::Passive)
            } else {
                None
            },
            extensions,
            discovered_at: Instant::now(),
            base_address: None,
            server_address: None,
        })
    }

    /// Convert to SDP attribute format (RFC 8445 Section 5.1)
    pub fn to_sdp_attribute(&self) -> String {
        let mut parts = vec![
            "candidate".to_string(),
            self.foundation.clone(),
            self.component_id.to_string(),
            self.transport.to_upper_str().to_string(),
            self.priority.to_string(),
        ];

        // Add address and port
        match &self.address {
            CandidateAddress::Ip(addr) => {
                parts.push(addr.ip().to_string());
                parts.push(addr.port().to_string());
            }
            CandidateAddress::MDns { hostname, port } => {
                parts.push(hostname.clone());
                parts.push(port.to_string());
            }
        }

        // Add type
        parts.push("typ".to_string());
        parts.push(self.candidate_type.to_str().to_string());

        // Add related address if present
        if let Some(related) = &self.related_address {
            match related {
                CandidateAddress::Ip(addr) => {
                    parts.push("raddr".to_string());
                    parts.push(addr.ip().to_string());
                    parts.push("rport".to_string());
                    parts.push(addr.port().to_string());
                }
                CandidateAddress::MDns { hostname, port } => {
                    parts.push("raddr".to_string());
                    parts.push(hostname.clone());
                    parts.push("rport".to_string());
                    parts.push(port.to_string());
                }
            }
        }

        // Add TCP type if present
        if let Some(tcp_type) = &self.tcp_type {
            parts.push("tcptype".to_string());
            parts.push(tcp_type.to_str().to_string());
        }

        // Add extensions
        if let Some(generation) = self.extensions.generation {
            parts.push("generation".to_string());
            parts.push(generation.to_string());
        }

        if let Some(network_id) = self.extensions.network_id {
            parts.push("network-id".to_string());
            parts.push(network_id.to_string());
        }

        if let Some(network_cost) = self.extensions.network_cost {
            parts.push("network-cost".to_string());
            parts.push(network_cost.to_string());
        }

        // Add custom extensions
        for (name, value) in &self.extensions.extensions {
            parts.push(name.clone());
            parts.push(value.clone());
        }

        format!("a={}", parts.join(" "))
    }

    /// Parse from SDP attribute format
    pub fn from_sdp_attribute(line: &str) -> NatResult<Self> {
        // Remove 'a=' prefix if present
        let line = line.strip_prefix("a=").unwrap_or(line);

        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 8 || parts[0] != "candidate" {
            return Err(NatError::Platform("Invalid candidate line format".to_string()));
        }

        // Parse basic fields
        let foundation = parts[1].to_string();
        let component_id = parts[2].parse::<u32>()
            .map_err(|_| NatError::Platform("Invalid component ID".to_string()))?;

        let transport = TransportProtocol::from_str(parts[3])
            .ok_or_else(|| NatError::Platform("Invalid transport protocol".to_string()))?;

        let priority = parts[4].parse::<u32>()
            .map_err(|_| NatError::Platform("Invalid priority".to_string()))?;

        // Parse address
        let address = parse_candidate_address(parts[5], parts[6])?;

        // Find and parse type
        let typ_pos = parts.iter().position(|&p| p == "typ")
            .ok_or_else(|| NatError::Platform("Missing typ field".to_string()))?;

        if typ_pos + 1 >= parts.len() {
            return Err(NatError::Platform("Missing candidate type".to_string()));
        }

        let candidate_type = CandidateType::from_str(parts[typ_pos + 1])
            .ok_or_else(|| NatError::Platform("Invalid candidate type".to_string()))?;

        // Initialize candidate
        let mut candidate = Self {
            foundation,
            component_id,
            transport,
            priority,
            address,
            candidate_type,
            related_address: None,
            tcp_type: None,
            extensions: CandidateExtensions::new(),
            discovered_at: Instant::now(),
            base_address: None,
            server_address: None,
        };

        // Parse optional fields
        let mut i = typ_pos + 2;
        while i < parts.len() {
            match parts[i] {
                "raddr" if i + 3 < parts.len() && parts[i + 2] == "rport" => {
                    candidate.related_address = Some(parse_candidate_address(parts[i + 1], parts[i + 3])?);
                    i += 4;
                }
                "tcptype" if i + 1 < parts.len() => {
                    candidate.tcp_type = TcpType::from_str(parts[i + 1]);
                    i += 2;
                }
                "generation" if i + 1 < parts.len() => {
                    if let Ok(gen) = parts[i + 1].parse() {
                        candidate.extensions.generation = Some(gen);
                    }
                    i += 2;
                }
                "network-id" if i + 1 < parts.len() => {
                    if let Ok(id) = parts[i + 1].parse() {
                        candidate.extensions.network_id = Some(id);
                    }
                    i += 2;
                }
                "network-cost" if i + 1 < parts.len() => {
                    if let Ok(cost) = parts[i + 1].parse() {
                        candidate.extensions.network_cost = Some(cost);
                    }
                    i += 2;
                }
                _ => {
                    // Handle custom extensions
                    if i + 1 < parts.len() {
                        candidate.extensions.extensions.insert(
                            parts[i].to_string(),
                            parts[i + 1].to_string(),
                        );
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
        }

        // Validate candidate
        candidate.validate()?;

        Ok(candidate)
    }

    /// Validate candidate according to RFC 8445
    pub fn validate(&self) -> NatResult<()> {
        // Validate foundation
        if !foundation::validate_foundation(&self.foundation) {
            return Err(NatError::Platform("Invalid foundation format".to_string()));
        }

        // Validate component ID (must be between 1 and 256)
        if self.component_id == 0 || self.component_id > 256 {
            return Err(NatError::Platform("Component ID must be between 1 and 256".to_string()));
        }

        // Validate priority
        if !priority::validate_priority(self.priority) {
            return Err(NatError::Platform("Invalid priority value".to_string()));
        }

        // Validate that related address is present for appropriate candidate types
        if self.candidate_type.requires_related_address() && self.related_address.is_none() {
            return Err(NatError::Platform(
                format!("{:?} candidates require a related address", self.candidate_type)
            ));
        }

        // Validate TCP type for TCP candidates
        if self.transport == TransportProtocol::Tcp && self.tcp_type.is_none() {
            return Err(NatError::Platform("TCP candidates require tcptype".to_string()));
        }

        // Validate UDP candidates don't have TCP type
        if self.transport == TransportProtocol::Udp && self.tcp_type.is_some() {
            return Err(NatError::Platform("UDP candidates cannot have tcptype".to_string()));
        }

        // Validate address
        self.validate_address()?;

        Ok(())
    }

    /// Validate candidate address
    fn validate_address(&self) -> NatResult<()> {
        match &self.address {
            CandidateAddress::Ip(addr) => {
                // Check for invalid addresses
                let ip = addr.ip();

                if ip.is_unspecified() {
                    return Err(NatError::Platform("Unspecified IP address not allowed".to_string()));
                }

                // Host candidates should not use multicast addresses
                if self.candidate_type == CandidateType::Host && ip.is_multicast() {
                    return Err(NatError::Platform("Host candidates cannot use multicast addresses".to_string()));
                }

                // Port 0 is generally not allowed
                if addr.port() == 0 {
                    return Err(NatError::Platform("Port 0 is not allowed".to_string()));
                }
            }
            CandidateAddress::MDns { hostname, port } => {
                if !is_valid_mdns_hostname(hostname) {
                    return Err(NatError::Platform("Invalid mDNS hostname".to_string()));
                }

                if *port == 0 {
                    return Err(NatError::Platform("Port 0 is not allowed".to_string()));
                }
            }
        }

        Ok(())
    }

    /// Check if this is an IPv6 candidate
    pub fn is_ipv6(&self) -> bool {
        match &self.address {
            CandidateAddress::Ip(addr) => addr.is_ipv6(),
            CandidateAddress::MDns { .. } => false, // mDNS doesn't specify IP version
        }
    }

    /// Check if this is an IPv4 candidate
    pub fn is_ipv4(&self) -> bool {
        match &self.address {
            CandidateAddress::Ip(addr) => addr.is_ipv4(),
            CandidateAddress::MDns { .. } => false, // mDNS doesn't specify IP version
        }
    }

    /// Check if this is a host candidate
    pub fn is_host(&self) -> bool {
        self.candidate_type == CandidateType::Host
    }

    /// Check if this is a relay candidate
    pub fn is_relay(&self) -> bool {
        self.candidate_type == CandidateType::Relay
    }

    /// Check if this is a reflexive candidate (server or peer)
    pub fn is_reflexive(&self) -> bool {
        matches!(self.candidate_type, CandidateType::ServerReflexive | CandidateType::PeerReflexive)
    }

    /// Check if this is an mDNS candidate
    pub fn is_mdns(&self) -> bool {
        self.address.is_mdns()
    }

    /// Check if this is a TCP candidate
    pub fn is_tcp(&self) -> bool {
        self.transport == TransportProtocol::Tcp
    }

    /// Check if this is a UDP candidate
    pub fn is_udp(&self) -> bool {
        self.transport == TransportProtocol::Udp
    }

    /// Get the socket address if this is an IP candidate
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.address.socket_addr()
    }

    /// Get the IP address if this is an IP candidate
    pub fn ip(&self) -> Option<IpAddr> {
        self.address.ip()
    }

    /// Get the port number
    pub fn port(&self) -> u16 {
        self.address.port()
    }

    /// Update priority with new local preference
    pub fn update_priority(&mut self, local_preference: u32) {
        self.priority = priority::calculate_priority(
            self.candidate_type,
            local_preference,
            self.component_id,
        );
    }

    /// Clone candidate with new component ID
    pub fn with_component_id(&self, component_id: u32) -> Self {
        let mut candidate = self.clone();
        candidate.component_id = component_id;

        // Recalculate priority
        let (_, local_preference, _) = priority::decompose_priority(self.priority);
        candidate.priority = priority::calculate_priority(
            self.candidate_type,
            local_preference,
            component_id,
        );

        candidate
    }

    /// Check if this candidate matches another candidate (same foundation and component)
    pub fn matches(&self, other: &Self) -> bool {
        self.foundation == other.foundation && self.component_id == other.component_id
    }

    /// Calculate the age of this candidate
    pub fn age(&self) -> Duration {
        self.discovered_at.elapsed()
    }
}

/// Parse candidate address from SDP parts
fn parse_candidate_address(addr_str: &str, port_str: &str) -> NatResult<CandidateAddress> {
    let port = port_str.parse::<u16>()
        .map_err(|_| NatError::Platform("Invalid port number".to_string()))?;

    // Try to parse as IP address first
    if let Ok(ip) = addr_str.parse::<IpAddr>() {
        return Ok(CandidateAddress::Ip(SocketAddr::new(ip, port)));
    }

    // Check if it's an mDNS hostname
    if is_valid_mdns_hostname(addr_str) {
        return Ok(CandidateAddress::MDns {
            hostname: addr_str.to_string(),
            port,
        });
    }

    Err(NatError::Platform("Invalid candidate address".to_string()))
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {} {}",
               self.candidate_type.to_str(),
               self.foundation,
               self.address,
               self.transport.to_str(),
               self.priority
        )
    }
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.foundation == other.foundation &&
            self.component_id == other.component_id &&
            self.transport == other.transport &&
            self.address == other.address &&
            self.candidate_type == other.candidate_type
    }
}

impl Eq for Candidate {}

impl std::hash::Hash for Candidate {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.foundation.hash(state);
        self.component_id.hash(state);
        self.transport.hash(state);
        self.candidate_type.hash(state);

        // Hash address based on type
        match &self.address {
            CandidateAddress::Ip(addr) => {
                0u8.hash(state);
                addr.hash(state);
            }
            CandidateAddress::MDns { hostname, port } => {
                1u8.hash(state);
                hostname.hash(state);
                port.hash(state);
            }
        }
    }
}

/// Candidate pair for connectivity checks (RFC 8445 Section 6.1.2)
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// Local candidate
    pub local: Candidate,

    /// Remote candidate
    pub remote: Candidate,

    /// Pair priority (RFC 8445 Section 6.1.2.3)
    pub priority: u64,

    /// Pair foundation (for frozen state)
    pub foundation: String,

    /// Current state
    pub state: CandidatePairState,

    /// Nominated flag
    pub nominated: bool,

    /// Use candidate flag (for aggressive nomination)
    pub use_candidate: bool,

    /// Valid flag (connectivity check succeeded)
    pub valid: bool,

    /// Default flag (selected for use)
    pub default: bool,

    /// Number of checks sent
    pub checks_sent: u32,

    /// Number of check responses received
    pub responses_received: u32,

    /// Last check sent time
    pub last_check_sent: Option<Instant>,

    /// Last response received time
    pub last_response_received: Option<Instant>,

    /// Round trip time measurements
    pub rtt_measurements: Vec<Duration>,

    /// Transaction IDs of pending checks
    pub pending_transactions: Vec<[u8; 12]>,

    /// Failure count (for exponential backoff)
    pub failure_count: u32,

    /// Next check time (for retransmissions)
    pub next_check_time: Option<Instant>,
}

/// Candidate pair state (RFC 8445 Section 6.1.2.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatePairState {
    /// Waiting to be checked
    Waiting,

    /// Currently being checked
    InProgress,

    /// Check succeeded
    Succeeded,

    /// Check failed
    Failed,

    /// Will not be checked (frozen)
    Frozen,
}

impl CandidatePairState {
    /// Check if this state allows new connectivity checks
    pub fn can_send_check(&self) -> bool {
        matches!(self, Self::Waiting | Self::InProgress | Self::Failed)
    }

    /// Check if this state indicates a completed check
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }

    /// Check if this state can be nominated
    pub fn can_nominate(&self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

impl CandidatePair {
    /// Create new candidate pair
    pub fn new(local: Candidate, remote: Candidate, controlling: bool) -> Self {
        // Calculate pair priority (RFC 8445 Section 6.1.2.3)
        let priority = priority::calculate_pair_priority(
            controlling,
            local.priority,
            remote.priority,
        );

        let foundation = format!("{}:{}", local.foundation, remote.foundation);

        Self {
            local,
            remote,
            priority,
            foundation,
            state: CandidatePairState::Frozen,
            nominated: false,
            use_candidate: false,
            valid: false,
            default: false,
            checks_sent: 0,
            responses_received: 0,
            last_check_sent: None,
            last_response_received: None,
            rtt_measurements: Vec::new(),
            pending_transactions: Vec::new(),
            failure_count: 0,
            next_check_time: None,
        }
    }

    /// Get unique pair ID
    pub fn id(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.local.address,
            self.remote.address,
            self.local.component_id,
            self.remote.component_id
        )
    }

    /// Check if pair should be pruned (RFC 8445 Section 6.1.2.4)
    pub fn should_prune(&self, other: &Self) -> bool {
        // Same remote candidate, local candidate is server reflexive,
        // other local candidate is host, and base matches
        if self.remote.address == other.remote.address &&
            self.local.candidate_type == CandidateType::ServerReflexive &&
            other.local.candidate_type == CandidateType::Host {

            if let (Some(base_addr), Some(other_addr)) = (
                self.local.related_address.as_ref().and_then(|a| a.socket_addr()),
                other.local.socket_addr()
            ) {
                return base_addr == other_addr;
            }
        }

        false
    }

    /// Update state to waiting if currently frozen
    pub fn unfreeze(&mut self) {
        if self.state == CandidatePairState::Frozen {
            self.state = CandidatePairState::Waiting;
        }
    }

    /// Mark as in progress
    pub fn mark_in_progress(&mut self) {
        self.state = CandidatePairState::InProgress;
        self.checks_sent += 1;
        self.last_check_sent = Some(Instant::now());
    }

    /// Mark as succeeded
    pub fn mark_succeeded(&mut self, rtt: Duration) {
        self.state = CandidatePairState::Succeeded;
        self.valid = true;
        self.responses_received += 1;
        self.last_response_received = Some(Instant::now());
        self.rtt_measurements.push(rtt);
        self.failure_count = 0;
        self.next_check_time = None;

        // Keep only recent RTT measurements
        if self.rtt_measurements.len() > 10 {
            self.rtt_measurements.remove(0);
        }
    }

    /// Mark as failed
    pub fn mark_failed(&mut self) {
        self.state = CandidatePairState::Failed;
        self.failure_count += 1;

        // Calculate next retry time with exponential backoff
        let backoff_ms = std::cmp::min(500 * (1 << self.failure_count), 30000);
        self.next_check_time = Some(Instant::now() + Duration::from_millis(backoff_ms));
    }

    /// Nominate this pair
    pub fn nominate(&mut self) {
        if self.state == CandidatePairState::Succeeded {
            self.nominated = true;
        }
    }

    /// Set as default pair
    pub fn set_default(&mut self) {
        if self.nominated {
            self.default = true;
        }
    }

    /// Get average RTT
    pub fn average_rtt(&self) -> Option<Duration> {
        if self.rtt_measurements.is_empty() {
            None
        } else {
            let total: Duration = self.rtt_measurements.iter().sum();
            Some(total / self.rtt_measurements.len() as u32)
        }
    }

    /// Check if this pair can send a connectivity check now
    pub fn can_send_check_now(&self) -> bool {
        if !self.state.can_send_check() {
            return false;
        }

        if let Some(next_time) = self.next_check_time {
            Instant::now() >= next_time
        } else {
            true
        }
    }

    /// Add pending transaction ID
    pub fn add_pending_transaction(&mut self, transaction_id: [u8; 12]) {
        self.pending_transactions.push(transaction_id);

        // Limit number of pending transactions
        if self.pending_transactions.len() > 5 {
            self.pending_transactions.remove(0);
        }
    }

    /// Remove pending transaction ID
    pub fn remove_pending_transaction(&mut self, transaction_id: &[u8; 12]) -> bool {
        if let Some(pos) = self.pending_transactions.iter().position(|t| t == transaction_id) {
            self.pending_transactions.remove(pos);
            true
        } else {
            false
        }
    }

    /// Check if this pair has the same foundation as another
    pub fn same_foundation(&self, other: &Self) -> bool {
        self.foundation == other.foundation
    }

    /// Get the controlling/controlled priority for this pair
    pub fn get_priority(&self, controlling: bool) -> u64 {
        priority::calculate_pair_priority(controlling, self.local.priority, self.remote.priority)
    }

    /// Check if this pair is for the same component as another
    pub fn same_component(&self, other: &Self) -> bool {
        self.local.component_id == other.local.component_id &&
            self.remote.component_id == other.remote.component_id
    }

    /// Check if both candidates are the same type
    pub fn same_candidate_types(&self) -> bool {
        self.local.candidate_type == self.remote.candidate_type
    }

    /// Get pair type description for debugging
    pub fn type_description(&self) -> String {
        format!("{}->{}",
                self.local.candidate_type.to_str(),
                self.remote.candidate_type.to_str()
        )
    }
}

impl fmt::Display for CandidatePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {} ({})",
               self.local.address,
               self.remote.address,
               self.type_description()
        )
    }
}

impl PartialEq for CandidatePair {
    fn eq(&self, other: &Self) -> bool {
        self.local == other.local && self.remote == other.remote
    }
}

impl Eq for CandidatePair {}

impl std::hash::Hash for CandidatePair {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.local.hash(state);
        self.remote.hash(state);
    }
}

/// Candidate list with validation and utilities
#[derive(Debug, Clone, Default)]
pub struct CandidateList {
    candidates: Vec<Candidate>,
}

impl CandidateList {
    /// Create new empty candidate list
    pub fn new() -> Self {
        Self::default()
    }

    /// Add candidate to list
    pub fn add(&mut self, candidate: Candidate) -> NatResult<()> {
        candidate.validate()?;

        // Check for duplicates
        if !self.candidates.iter().any(|c| c == &candidate) {
            self.candidates.push(candidate);
        }

        Ok(())
    }

    /// Remove candidate from list
    pub fn remove(&mut self, candidate: &Candidate) -> bool {
        if let Some(pos) = self.candidates.iter().position(|c| c == candidate) {
            self.candidates.remove(pos);
            true
        } else {
            false
        }
    }

    /// Get all candidates
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// Get candidates for specific component
    pub fn candidates_for_component(&self, component_id: u32) -> Vec<&Candidate> {
        self.candidates.iter()
            .filter(|c| c.component_id == component_id)
            .collect()
    }

    /// Get candidates by type
    pub fn candidates_by_type(&self, candidate_type: CandidateType) -> Vec<&Candidate> {
        self.candidates.iter()
            .filter(|c| c.candidate_type == candidate_type)
            .collect()
    }

    /// Get candidates by transport
    pub fn candidates_by_transport(&self, transport: TransportProtocol) -> Vec<&Candidate> {
        self.candidates.iter()
            .filter(|c| c.transport == transport)
            .collect()
    }

    /// Sort candidates by priority (highest first)
    pub fn sort_by_priority(&mut self) {
        self.candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Get highest priority candidate for component
    pub fn highest_priority_for_component(&self, component_id: u32) -> Option<&Candidate> {
        self.candidates.iter()
            .filter(|c| c.component_id == component_id)
            .max_by_key(|c| c.priority)
    }

    /// Convert to SDP format
    pub fn to_sdp(&self) -> Vec<String> {
        self.candidates.iter()
            .map(|c| c.to_sdp_attribute())
            .collect()
    }

    /// Parse from SDP lines
    pub fn from_sdp(lines: &[String]) -> NatResult<Self> {
        let mut list = Self::new();

        for line in lines {
            if line.starts_with("a=candidate") {
                let candidate = Candidate::from_sdp_attribute(line)?;
                list.add(candidate)?;
            }
        }

        Ok(list)
    }

    /// Clear all candidates
    pub fn clear(&mut self) {
        self.candidates.clear();
    }

    /// Get number of candidates
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Check if list is empty
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Get unique foundations
    pub fn foundations(&self) -> Vec<String> {
        let mut foundations: Vec<String> = self.candidates.iter()
            .map(|c| c.foundation.clone())
            .collect();
        foundations.sort();
        foundations.dedup();
        foundations
    }

    /// Get unique component IDs
    pub fn component_ids(&self) -> Vec<u32> {
        let mut components: Vec<u32> = self.candidates.iter()
            .map(|c| c.component_id)
            .collect();
        components.sort();
        components.dedup();
        components
    }

    /// Filter candidates by predicate
    pub fn filter<F>(&self, predicate: F) -> Self
    where
        F: Fn(&Candidate) -> bool
    {
        Self {
            candidates: self.candidates.iter()
                .filter(|c| predicate(*c))
                .cloned()
                .collect(),
        }
    }

    /// Remove expired candidates (older than specified duration)
    pub fn remove_expired(&mut self, max_age: Duration) {
        self.candidates.retain(|c| c.age() <= max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_candidate_creation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 54321);
        let candidate = Candidate::new_host(
            addr,
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );

        assert_eq!(candidate.candidate_type, CandidateType::Host);
        assert_eq!(candidate.component_id, 1);
        assert_eq!(candidate.transport, TransportProtocol::Udp);
        assert!(candidate.validate().is_ok());
    }

    #[test]
    fn test_sdp_parsing() {
        let sdp = "a=candidate:1 1 UDP 2130706431 192.168.1.1 54321 typ host";
        let candidate = Candidate::from_sdp_attribute(sdp).unwrap();

        assert_eq!(candidate.foundation, "1");
        assert_eq!(candidate.component_id, 1);
        assert_eq!(candidate.transport, TransportProtocol::Udp);
        assert_eq!(candidate.priority, 2130706431);
        assert_eq!(candidate.candidate_type, CandidateType::Host);

        // Test round-trip
        let regenerated_sdp = candidate.to_sdp_attribute();
        let reparsed = Candidate::from_sdp_attribute(&regenerated_sdp).unwrap();
        assert_eq!(candidate.foundation, reparsed.foundation);
        assert_eq!(candidate.component_id, reparsed.component_id);
    }

    #[test]
    fn test_mdns_candidate() {
        let candidate = Candidate::new_mdns(
            "test.local".to_string(),
            12345,
            1,
            TransportProtocol::Udp,
            CandidateType::Host,
            CandidateExtensions::new(),
        ).unwrap();

        assert!(candidate.is_mdns());
        assert_eq!(candidate.port(), 12345);
        assert!(candidate.validate().is_ok());
    }

    #[test]
    fn test_candidate_pair() {
        let local = Candidate::new_host(
            "192.168.1.1:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );

        let remote = Candidate::new_host(
            "192.168.1.2:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );

        let pair = CandidatePair::new(local, remote, true);
        assert_eq!(pair.state, CandidatePairState::Frozen);
        assert!(!pair.valid);
        assert!(!pair.nominated);
    }

    #[test]
    fn test_candidate_list() {
        let mut list = CandidateList::new();

        let candidate1 = Candidate::new_host(
            "192.168.1.1:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );

        let candidate2 = Candidate::new_host(
            "192.168.1.2:12345".parse().unwrap(),
            2,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );

        list.add(candidate1).unwrap();
        list.add(candidate2).unwrap();

        assert_eq!(list.len(), 2);
        assert_eq!(list.component_ids(), vec![1, 2]);
    }

    #[test]
    fn test_invalid_candidates() {
        // Test invalid component ID
        let mut candidate = Candidate::new_host(
            "192.168.1.1:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );
        candidate.component_id = 0;
        assert!(candidate.validate().is_err());

        // Test TCP candidate without tcptype
        candidate.component_id = 1;
        candidate.transport = TransportProtocol::Tcp;
        candidate.tcp_type = None;
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn test_mdns_hostname_validation() {
        assert!(is_valid_mdns_hostname("test.local"));
        assert!(is_valid_mdns_hostname("my-device.local"));
        assert!(!is_valid_mdns_hostname("test.com"));
        assert!(!is_valid_mdns_hostname(""));
        assert!(!is_valid_mdns_hostname("-test.local"));
        assert!(!is_valid_mdns_hostname("test-.local"));
    }
}