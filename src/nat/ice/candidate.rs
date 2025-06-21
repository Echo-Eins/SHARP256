// src/nat/ice/candidate.rs
//! ICE candidate representation and parsing

use std::net::{IpAddr, SocketAddr};
use std::fmt;
use std::str::FromStr;
use crate::nat::error::{NatError, NatResult};

/// ICE candidate type (RFC 8445 Section 5.1.1.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// Host candidate (local address)
    Host,
    /// Server reflexive (from STUN)
    ServerReflexive,
    /// Peer reflexive (discovered during connectivity checks)
    PeerReflexive,
    /// Relayed candidate (from TURN)
    Relay,
}

impl CandidateType {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::ServerReflexive => "srflx",
            Self::PeerReflexive => "prflx",
            Self::Relay => "relay",
        }
    }
    
    pub fn preference(&self) -> u32 {
        // RFC 8445 Section 5.1.2.2: Recommended type preferences
        match self {
            Self::Host => 126,
            Self::ServerReflexive => 100,
            Self::PeerReflexive => 110,
            Self::Relay => 0,
        }
    }
}

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Udp,
    Tcp,
}

/// TCP candidate type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpType {
    Active,
    Passive,
    So,
}

/// ICE candidate
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Candidate {
    /// Unique foundation (RFC 8445 Section 5.1.1.3)
    pub foundation: String,
    
    /// Component ID (1 for RTP, 2 for RTCP)
    pub component_id: u32,
    
    /// Transport protocol
    pub transport: TransportProtocol,
    
    /// Priority (RFC 8445 Section 5.1.2)
    pub priority: u32,
    
    /// IP address
    pub addr: SocketAddr,
    
    /// Candidate type
    pub typ: CandidateType,
    
    /// Related address (for reflexive/relay candidates)
    pub related_addr: Option<SocketAddr>,
    
    /// TCP type (if TCP transport)
    pub tcp_type: Option<TcpType>,
    
    /// Generation (for ICE restart)
    pub generation: u32,
    
    /// Network ID (for multi-homed)
    pub network_id: u32,
    
    /// Network cost (RFC 8421)
    pub network_cost: u32,
}

impl Candidate {
    /// Create a new host candidate
    pub fn new_host(
        addr: SocketAddr,
        component_id: u32,
        transport: TransportProtocol,
        network_id: u32,
    ) -> Self {
        let foundation = super::foundation::calculate_foundation(
            CandidateType::Host,
            &addr.ip(),
            transport,
            None,
            None,
        );
        
        let priority = super::priority::calculate_priority(
            CandidateType::Host,
            0, // local preference
            component_id,
        );
        
        Self {
            foundation,
            component_id,
            transport,
            priority,
            addr,
            typ: CandidateType::Host,
            related_addr: None,
            tcp_type: None,
            generation: 0,
            network_id,
            network_cost: 0,
        }
    }
    
    /// Create server reflexive candidate
    pub fn new_server_reflexive(
        addr: SocketAddr,
        base: SocketAddr,
        component_id: u32,
        transport: TransportProtocol,
        network_id: u32,
    ) -> Self {
        let foundation = super::foundation::calculate_foundation(
            CandidateType::ServerReflexive,
            &base.ip(),
            transport,
            Some(&addr.ip()),
            None,
        );
        
        let priority = super::priority::calculate_priority(
            CandidateType::ServerReflexive,
            0,
            component_id,
        );
        
        Self {
            foundation,
            component_id,
            transport,
            priority,
            addr,
            typ: CandidateType::ServerReflexive,
            related_addr: Some(base),
            tcp_type: None,
            generation: 0,
            network_id,
            network_cost: 10, // Higher cost for reflexive
        }
    }
    
    /// Create relay candidate
    pub fn new_relay(
        addr: SocketAddr,
        base: SocketAddr,
        component_id: u32,
        transport: TransportProtocol,
        relay_server: &SocketAddr,
    ) -> Self {
        let foundation = super::foundation::calculate_foundation(
            CandidateType::Relay,
            &base.ip(),
            transport,
            Some(&addr.ip()),
            Some(relay_server),
        );
        
        let priority = super::priority::calculate_priority(
            CandidateType::Relay,
            0,
            component_id,
        );
        
        Self {
            foundation,
            component_id,
            transport,
            priority,
            addr,
            typ: CandidateType::Relay,
            related_addr: Some(base),
            tcp_type: None,
            generation: 0,
            network_id: u32::MAX, // Special network ID for relay
            network_cost: 50, // Highest cost for relay
        }
    }
    
    /// Convert to SDP attribute format
    pub fn to_sdp_attribute(&self) -> String {
        let mut parts = vec![
            "candidate".to_string(),
            self.foundation.clone(),
            self.component_id.to_string(),
            match self.transport {
                TransportProtocol::Udp => "UDP",
                TransportProtocol::Tcp => "TCP",
            }.to_string(),
            self.priority.to_string(),
            self.addr.ip().to_string(),
            self.addr.port().to_string(),
            "typ".to_string(),
            self.typ.to_str().to_string(),
        ];
        
        if let Some(related) = &self.related_addr {
            parts.extend_from_slice(&[
                "raddr".to_string(),
                related.ip().to_string(),
                "rport".to_string(),
                related.port().to_string(),
            ]);
        }
        
        if let Some(tcp_type) = &self.tcp_type {
            parts.extend_from_slice(&[
                "tcptype".to_string(),
                match tcp_type {
                    TcpType::Active => "active",
                    TcpType::Passive => "passive",
                    TcpType::So => "so",
                }.to_string(),
            ]);
        }
        
        if self.generation > 0 {
            parts.extend_from_slice(&[
                "generation".to_string(),
                self.generation.to_string(),
            ]);
        }
        
        if self.network_id != 0 && self.network_id != u32::MAX {
            parts.extend_from_slice(&[
                "network-id".to_string(),
                self.network_id.to_string(),
            ]);
        }
        
        if self.network_cost > 0 {
            parts.extend_from_slice(&[
                "network-cost".to_string(),
                self.network_cost.to_string(),
            ]);
        }
        
        parts.join(" ")
    }
    
    /// Parse from SDP attribute format
    pub fn from_sdp_attribute(s: &str) -> NatResult<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        
        if parts.len() < 8 || parts[0] != "candidate" {
            return Err(NatError::Platform("Invalid candidate format".to_string()));
        }
        
        let foundation = parts[1].to_string();
        let component_id = parts[2].parse()
            .map_err(|_| NatError::Platform("Invalid component ID".to_string()))?;
        
        let transport = match parts[3] {
            "UDP" => TransportProtocol::Udp,
            "TCP" => TransportProtocol::Tcp,
            _ => return Err(NatError::Platform("Invalid transport".to_string())),
        };
        
        let priority = parts[4].parse()
            .map_err(|_| NatError::Platform("Invalid priority".to_string()))?;
            
        let ip = parts[5].parse::<IpAddr>()
            .map_err(|_| NatError::Platform("Invalid IP address".to_string()))?;
            
        let port = parts[6].parse::<u16>()
            .map_err(|_| NatError::Platform("Invalid port".to_string()))?;
            
        let addr = SocketAddr::new(ip, port);
        
        // Find "typ" in remaining parts
        let typ_pos = parts.iter().position(|&p| p == "typ")
            .ok_or_else(|| NatError::Platform("Missing typ field".to_string()))?;
            
        if typ_pos + 1 >= parts.len() {
            return Err(NatError::Platform("Missing candidate type".to_string()));
        }
        
        let typ = match parts[typ_pos + 1] {
            "host" => CandidateType::Host,
            "srflx" => CandidateType::ServerReflexive,
            "prflx" => CandidateType::PeerReflexive,
            "relay" => CandidateType::Relay,
            _ => return Err(NatError::Platform("Invalid candidate type".to_string())),
        };
        
        let mut candidate = Self {
            foundation,
            component_id,
            transport,
            priority,
            addr,
            typ,
            related_addr: None,
            tcp_type: None,
            generation: 0,
            network_id: 0,
            network_cost: 0,
        };
        
        // Parse optional fields
        let mut i = typ_pos + 2;
        while i < parts.len() {
            match parts[i] {
                "raddr" if i + 1 < parts.len() => {
                    if let Ok(raddr_ip) = parts[i + 1].parse::<IpAddr>() {
                        if i + 3 < parts.len() && parts[i + 2] == "rport" {
                            if let Ok(rport) = parts[i + 3].parse::<u16>() {
                                candidate.related_addr = Some(SocketAddr::new(raddr_ip, rport));
                                i += 4;
                                continue;
                            }
                        }
                    }
                }
                "tcptype" if i + 1 < parts.len() => {
                    candidate.tcp_type = match parts[i + 1] {
                        "active" => Some(TcpType::Active),
                        "passive" => Some(TcpType::Passive),
                        "so" => Some(TcpType::So),
                        _ => None,
                    };
                    i += 2;
                    continue;
                }
                "generation" if i + 1 < parts.len() => {
                    if let Ok(gen) = parts[i + 1].parse() {
                        candidate.generation = gen;
                    }
                    i += 2;
                    continue;
                }
                "network-id" if i + 1 < parts.len() => {
                    if let Ok(id) = parts[i + 1].parse() {
                        candidate.network_id = id;
                    }
                    i += 2;
                    continue;
                }
                "network-cost" if i + 1 < parts.len() => {
                    if let Ok(cost) = parts[i + 1].parse() {
                        candidate.network_cost = cost;
                    }
                    i += 2;
                    continue;
                }
                _ => {
                    i += 1;
                }
            }
        }
        
        Ok(candidate)
    }
    
    /// Check if this is an IPv6 candidate
    pub fn is_ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }
    
    /// Check if this is a host candidate
    pub fn is_host(&self) -> bool {
        self.typ == CandidateType::Host
    }
    
    /// Check if this is a relay candidate
    pub fn is_relay(&self) -> bool {
        self.typ == CandidateType::Relay
    }
}

/// Candidate pair for connectivity checks
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
    
    /// Number of checks sent
    pub checks_sent: u32,
    
    /// Last check sent time
    pub last_check_sent: Option<std::time::Instant>,
    
    /// Round trip time
    pub rtt: Option<std::time::Duration>,
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

impl CandidatePair {
    /// Create new candidate pair
    pub fn new(local: Candidate, remote: Candidate, controlling: bool) -> Self {
        let priority = if controlling {
            // G = greater priority, D = lesser priority
            let g = local.priority.max(remote.priority) as u64;
            let d = local.priority.min(remote.priority) as u64;
            (1u64 << 32) * g + 2 * d + if local.priority > remote.priority { 1 } else { 0 }
        } else {
            let g = remote.priority.max(local.priority) as u64;
            let d = remote.priority.min(local.priority) as u64;
            (1u64 << 32) * g + 2 * d + if remote.priority > local.priority { 1 } else { 0 }
        };
        
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
            checks_sent: 0,
            last_check_sent: None,
            rtt: None,
        }
    }
    
    /// Get unique pair ID
    pub fn id(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.local.addr,
            self.remote.addr,
            self.local.component_id,
            self.remote.component_id
        )
    }
    
    /// Check if pair should be pruned (RFC 8445 Section 6.1.2.4)
    pub fn should_prune(&self, other: &Self) -> bool {
        // Same remote candidate and local candidate is server reflexive
        self.remote.addr == other.remote.addr &&
        self.local.typ == CandidateType::ServerReflexive &&
        other.local.typ == CandidateType::Host &&
        self.local.related_addr == Some(other.local.addr)
    }
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.typ.to_str(), self.addr, self.priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_candidate_sdp_format() {
        let candidate = Candidate::new_host(
            "192.168.1.100:54321".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );
        
        let sdp = candidate.to_sdp_attribute();
        assert!(sdp.starts_with("candidate"));
        assert!(sdp.contains("typ host"));
        
        // Parse back
        let parsed = Candidate::from_sdp_attribute(&sdp).unwrap();
        assert_eq!(parsed.addr, candidate.addr);
        assert_eq!(parsed.typ, candidate.typ);
    }
    
    #[test]
    fn test_candidate_pair_priority() {
        let local = Candidate::new_host(
            "192.168.1.100:54321".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );
        
        let remote = Candidate::new_host(
            "192.168.1.200:54321".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );
        
        let pair1 = CandidatePair::new(local.clone(), remote.clone(), true);
        let pair2 = CandidatePair::new(local.clone(), remote.clone(), false);
        
        // Priorities should be different for controlling vs controlled
        assert_ne!(pair1.priority, pair2.priority);
    }
}