// src/nat/ice/gathering.rs
//! ICE candidate gathering implementation

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{timeout, Duration};

use crate::nat::stun::{StunClient, StunConfig};
use crate::nat::error::{NatError, NatResult};
use super::{Candidate, CandidateType, TransportProtocol};

/// Candidate gatherer
pub struct CandidateGatherer {
    /// Component ID -> Socket mapping
    sockets: Arc<RwLock<HashMap<u32, Arc<UdpSocket>>>>,
    
    /// STUN servers
    stun_servers: Vec<String>,
    
    /// TURN servers
    turn_servers: Vec<TurnServerConfig>,
    
    /// Network interfaces to use
    interfaces: Vec<NetworkInterface>,
    
    /// Event channel
    event_tx: mpsc::UnboundedSender<GatheringEvent>,
    
    /// Transport policy
    policy: super::IceTransportPolicy,
}

/// TURN server configuration
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    pub url: String,
    pub username: String,
    pub password: String,
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub addresses: Vec<IpAddr>,
    pub index: u32,
    pub is_vpn: bool,
}

/// Gathering event
#[derive(Debug)]
pub enum GatheringEvent {
    /// New candidate discovered
    CandidateFound(Candidate),
    
    /// Gathering completed for component
    ComponentComplete(u32),
    
    /// Gathering failed for component
    ComponentFailed(u32, String),
}

impl CandidateGatherer {
    /// Create new gatherer
    pub fn new(
        stun_servers: Vec<String>,
        turn_servers: Vec<TurnServerConfig>,
        policy: super::IceTransportPolicy,
        event_tx: mpsc::UnboundedSender<GatheringEvent>,
    ) -> NatResult<Self> {
        let interfaces = Self::discover_interfaces()?;
        
        Ok(Self {
            sockets: Arc::new(RwLock::new(HashMap::new())),
            stun_servers,
            turn_servers,
            interfaces,
            event_tx,
            policy,
        })
    }
    
    /// Discover network interfaces
    fn discover_interfaces() -> NatResult<Vec<NetworkInterface>> {
        #[cfg(feature = "nat-traversal")]
        {
            use if_addrs::get_if_addrs;
            
            let mut interfaces = HashMap::new();
            
            if let Ok(if_addrs) = get_if_addrs() {
                for iface in if_addrs {
                    if iface.is_loopback() {
                        continue;
                    }
                    
                    let entry = interfaces.entry(iface.name.clone())
                        .or_insert_with(|| NetworkInterface {
                            name: iface.name.clone(),
                            addresses: Vec::new(),
                            index: 0,
                            is_vpn: iface.name.starts_with("tun") || 
                                   iface.name.starts_with("tap") ||
                                   iface.name.starts_with("wg"),
                        });
                    
                    entry.addresses.push(iface.ip());
                }
            }
            
            Ok(interfaces.into_values().collect())
        }
        
        #[cfg(not(feature = "nat-traversal"))]
        {
            // Fallback: just use default interface
            Ok(vec![NetworkInterface {
                name: "default".to_string(),
                addresses: vec![],
                index: 0,
                is_vpn: false,
            }])
        }
    }
    
    /// Gather candidates for component
    pub async fn gather_candidates(
        &self,
        component_id: u32,
        port_hint: u16,
    ) -> NatResult<Vec<Candidate>> {
        let mut candidates = Vec::new();
        
        // Skip host candidates if relay-only policy
        if self.policy != super::IceTransportPolicy::Relay {
            // Gather host candidates
            let host_candidates = self.gather_host_candidates(component_id, port_hint).await?;
            
            for candidate in &host_candidates {
                self.event_tx.send(GatheringEvent::CandidateFound(candidate.clone()))
                    .map_err(|_| NatError::Platform("Event channel closed".to_string()))?;
            }
            
            candidates.extend(host_candidates);
            
            // Gather server reflexive candidates
            let srflx_candidates = self.gather_srflx_candidates(component_id).await;
            
            for candidate in &srflx_candidates {
                self.event_tx.send(GatheringEvent::CandidateFound(candidate.clone()))
                    .map_err(|_| NatError::Platform("Event channel closed".to_string()))?;
            }
            
            candidates.extend(srflx_candidates);
        }
        
        // Gather relay candidates if configured
        if !self.turn_servers.is_empty() {
            let relay_candidates = self.gather_relay_candidates(component_id).await;
            
            for candidate in &relay_candidates {
                self.event_tx.send(GatheringEvent::CandidateFound(candidate.clone()))
                    .map_err(|_| NatError::Platform("Event channel closed".to_string()))?;
            }
            
            candidates.extend(relay_candidates);
        }
        
        // Signal completion
        self.event_tx.send(GatheringEvent::ComponentComplete(component_id))
            .map_err(|_| NatError::Platform("Event channel closed".to_string()))?;
        
        Ok(candidates)
    }
    
    /// Gather host candidates
    async fn gather_host_candidates(
        &self,
        component_id: u32,
        port_hint: u16,
    ) -> NatResult<Vec<Candidate>> {
        let mut candidates = Vec::new();
        let mut network_id = 1u32;
        
        for interface in &self.interfaces {
            for addr in &interface.addresses {
                // RFC 8421: Handle both IPv4 and IPv6
                let bind_addr = match addr {
                    IpAddr::V4(_) => SocketAddr::new(*addr, port_hint),
                    IpAddr::V6(_) => SocketAddr::new(*addr, port_hint),
                };
                
                // Try to bind socket
                match UdpSocket::bind(bind_addr).await {
                    Ok(socket) => {
                        let actual_addr = socket.local_addr()?;
                        
                        // Store socket
                        let socket = Arc::new(socket);
                        self.sockets.write().await.insert(component_id, socket.clone());
                        
                        // Create host candidate
                        let mut candidate = Candidate::new_host(
                            actual_addr,
                            component_id,
                            TransportProtocol::Udp,
                            network_id,
                        );
                        
                        // Set network cost based on interface type
                        candidate.network_cost = if interface.is_vpn { 20 } else { 0 };
                        
                        candidates.push(candidate);
                        
                        network_id += 1;
                    }
                    Err(e) => {
                        tracing::debug!("Failed to bind to {}: {}", bind_addr, e);
                    }
                }
            }
        }
        
        Ok(candidates)
    }
    
    /// Gather server reflexive candidates
    async fn gather_srflx_candidates(
        &self,
        component_id: u32,
    ) -> Vec<Candidate> {
        let mut candidates = Vec::new();
        
        let sockets = self.sockets.read().await;
        let socket = match sockets.get(&component_id) {
            Some(s) => s.clone(),
            None => return candidates,
        };
        drop(sockets);
        
        let local_addr = match socket.local_addr() {
            Ok(addr) => addr,
            Err(_) => return candidates,
        };
        
        // Try each STUN server
        for server in &self.stun_servers {
            let config = StunConfig {
                servers: vec![server.clone()],
                ..Default::default()
            };
            
            let client = StunClient::new(config);
            
            // Use timeout for STUN query
            match timeout(
                Duration::from_secs(5),
                client.get_mapped_address(&socket)
            ).await {
                Ok(Ok(mapped_addr)) => {
                    // Only add if different from local address
                    if mapped_addr != local_addr {
                        let candidate = Candidate::new_server_reflexive(
                            mapped_addr,
                            local_addr,
                            component_id,
                            TransportProtocol::Udp,
                            0, // Use same network ID as host
                        );
                        
                        candidates.push(candidate);
                        
                        // Usually one STUN server is enough
                        break;
                    }
                }
                Ok(Err(e)) => {
                    tracing::debug!("STUN query to {} failed: {}", server, e);
                }
                Err(_) => {
                    tracing::debug!("STUN query to {} timed out", server);
                }
            }
        }
        
        candidates
    }
    
    /// Gather relay candidates
    async fn gather_relay_candidates(
        &self,
        component_id: u32,
    ) -> Vec<Candidate> {
        let mut candidates = Vec::new();
        
        // TODO: Implement TURN client for relay candidates
        // For now, return empty vector
        tracing::debug!("TURN not yet implemented");
        
        candidates
    }
    
    /// Get socket for component
    pub async fn get_socket(&self, component_id: u32) -> Option<Arc<UdpSocket>> {
        self.sockets.read().await.get(&component_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_interface_discovery() {
        let interfaces = CandidateGatherer::discover_interfaces().unwrap();
        
        // Should have at least one interface
        assert!(!interfaces.is_empty());
        
        for iface in interfaces {
            println!("Interface: {} (VPN: {})", iface.name, iface.is_vpn);
            for addr in iface.addresses {
                println!("  Address: {}", addr);
            }
        }
    }
    
    #[tokio::test]
    async fn test_host_candidate_gathering() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        
        let gatherer = CandidateGatherer::new(
            vec![],
            vec![],
            super::super::IceTransportPolicy::All,
            tx,
        ).unwrap();
        
        let candidates = gatherer.gather_host_candidates(1, 0).await.unwrap();
        
        // Should have at least one host candidate
        assert!(!candidates.is_empty());
        
        // Check all are host type
        for candidate in &candidates {
            assert_eq!(candidate.typ, CandidateType::Host);
            assert_eq!(candidate.component_id, 1);
        }
        
        // Should receive events
        while let Ok(event) = rx.try_recv() {
            match event {
                GatheringEvent::CandidateFound(candidate) => {
                    println!("Found candidate: {}", candidate);
                }
                _ => {}
            }
        }
    }
}