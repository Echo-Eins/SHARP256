use anyhow::Result;
use tokio::net::UdpSocket;
use parking_lot::RwLock;
use std::sync::Arc;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub mod stun;
pub mod upnp;
pub mod hole_punch;
pub mod coordinator;
pub mod error;

use self::stun::StunClient;
use self::upnp::UpnpClient;
use self::hole_punch::HolePuncher;
use self::coordinator::AdvancedNatTraversal;

/// NAT traversal configuration
#[derive(Debug, Clone)]
pub struct NatConfig {
    pub enable_stun: bool,
    pub enable_upnp: bool,
    pub enable_hole_punching: bool,
    pub stun_servers: Vec<String>,
    pub upnp_lease_duration: u32,
    pub hole_punch_attempts: u32,
    pub coordinator_server: Option<String>,
    pub relay_servers: Vec<String>,
    pub retry_attempts: u32,
    pub detection_timeout: Duration,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enable_stun: true,
            enable_upnp: true,
            enable_hole_punching: true,
            stun_servers: vec![
                // Primary servers
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
                "stun2.l.google.com:19302".to_string(),
                "stun3.l.google.com:19302".to_string(),
                "stun4.l.google.com:19302".to_string(),

                // Fallback servers
                "stun.cloudflare.com:3478".to_string(),
                "stun.services.mozilla.com:3478".to_string(),
                "stun.stunprotocol.org:3478".to_string(),
                "stun.voip.blackberry.com:3478".to_string(),
                "stun.altar.com.pl:3478".to_string(),
                "stun.antisip.com:3478".to_string(),
                "stun.bluesip.net:3478".to_string(),
                "stun.dus.net:3478".to_string(),
                "stun.epygi.com:3478".to_string(),
                "stun.sonetel.com:3478".to_string(),
                "stun.sonetel.net:3478".to_string(),
                "stun.stunprotocol.org:3478".to_string(),
                "stun.uls.co.za:3478".to_string(),
                "stun.voipgate.com:3478".to_string(),
                "stun.voys.nl:3478".to_string(),
            ],
            upnp_lease_duration: 7200, // 2 hours
            hole_punch_attempts: 30,
            coordinator_server: None,
            relay_servers: vec![],
            retry_attempts: 3,
            detection_timeout: Duration::from_secs(30),
        }
    }
}

/// Network configuration information
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub local_addr: SocketAddr,
    pub public_addr: Option<SocketAddr>,
    pub nat_type: NatType,
    pub upnp_available: bool,
    pub mapped_port: Option<u16>,
    pub external_ip_sources: Vec<(String, IpAddr)>, // Source name and IP
    pub connectivity_status: ConnectivityStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    None,               // Public IP, no NAT
    FullCone,          // Full Cone NAT (best case)
    RestrictedCone,    // Address-Restricted Cone NAT
    PortRestricted,    // Port-Restricted Cone NAT
    Symmetric,         // Symmetric NAT (worst case)
    Unknown,           // Could not determine
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityStatus {
    Direct,            // Direct internet connection
    BehindNat,        // Behind NAT but traversable
    Restricted,       // Behind restrictive NAT/firewall
    Offline,          // No internet connectivity
}

/// Enhanced NAT traversal manager
pub struct NatManager {
    config: NatConfig,
    network_info: Arc<RwLock<Option<NetworkInfo>>>,
    upnp_client: Arc<RwLock<Option<UpnpClient>>>,
    stun_client: StunClient,
    advanced_traversal: Option<AdvancedNatTraversal>,
    initialized: Arc<RwLock<bool>>,
}

impl NatManager {
    pub fn new(config: NatConfig) -> Self {
        let advanced_traversal = if config.coordinator_server.is_some() || !config.relay_servers.is_empty() {
            let client_id = format!("sharp-{}", uuid::Uuid::new_v4());

            let coordinator_addr = config.coordinator_server.as_ref()
                .and_then(|s| s.parse().ok());

            let relay_addrs: Vec<SocketAddr> = config.relay_servers.iter()
                .filter_map(|s| s.parse().ok())
                .collect();

            Some(AdvancedNatTraversal::new(coordinator_addr, relay_addrs, client_id))
        } else {
            None
        };

        Self {
            stun_client: StunClient::new(config.stun_servers.clone()),
            config,
            network_info: Arc::new(RwLock::new(None)),
            upnp_client: Arc::new(RwLock::new(None)),
            advanced_traversal,
            initialized: Arc::new(RwLock::new(false)),
        }
    }

    /// Initialize NAT detection with comprehensive fallback
    pub async fn initialize(&mut self, local_socket: &UdpSocket) -> Result<NetworkInfo> {
        if *self.initialized.read() {
            if let Some(info) = &*self.network_info.read() {
                return Ok(info.clone());
            }
        }

        let local_addr = local_socket.local_addr()?;
        tracing::info!("=== Starting NAT Detection ===");
        tracing::info!("Local address: {}", local_addr);

        let mut external_ip_sources = Vec::new();
        let mut public_addr = None;
        let mut nat_type = NatType::Unknown;
        let mut connectivity_status = ConnectivityStatus::Offline;

        // Step 1: STUN discovery (parallel with multiple servers)
        if self.config.enable_stun {
            tracing::info!("Performing STUN discovery...");

            match tokio::time::timeout(
                self.config.detection_timeout,
                self.discover_public_address_comprehensive(local_socket, &mut external_ip_sources)
            ).await {
                Ok(Ok(addr)) => {
                    public_addr = Some(addr);
                    connectivity_status = ConnectivityStatus::BehindNat;
                    tracing::info!("STUN discovery successful: {}", addr);
                }
                Ok(Err(e)) => {
                    tracing::warn!("STUN discovery failed: {}", e);
                }
                Err(_) => {
                    tracing::warn!("STUN discovery timed out");
                }
            }
        }

        // Step 2: Determine NAT type if behind NAT
        if let Some(pub_addr) = public_addr {
            if pub_addr.ip() == local_addr.ip() {
                nat_type = NatType::None;
                connectivity_status = ConnectivityStatus::Direct;
                tracing::info!("Direct internet connection detected (public IP)");
            } else {
                // Detailed NAT type detection
                match self.detect_nat_type_comprehensive(local_socket).await {
                    Ok(detected_type) => {
                        nat_type = detected_type;
                        tracing::info!("NAT type detected: {:?}", nat_type);
                    }
                    Err(e) => {
                        tracing::warn!("NAT type detection failed: {}", e);
                        // Assume restricted cone as safe default
                        nat_type = NatType::RestrictedCone;
                    }
                }
            }
        }

        // Step 3: UPnP setup (only if behind NAT)
        let (upnp_available, mapped_port) = if self.config.enable_upnp &&
            nat_type != NatType::None &&
            connectivity_status != ConnectivityStatus::Offline {
            tracing::info!("Attempting UPnP configuration...");

            match self.setup_upnp_comprehensive(local_addr.port()).await {
                Ok(port) => {
                    tracing::info!("✓ UPnP successful! External port: {}", port);

                    // Update connectivity status
                    if nat_type == NatType::Symmetric {
                        connectivity_status = ConnectivityStatus::Restricted;
                    } else {
                        connectivity_status = ConnectivityStatus::BehindNat;
                    }

                    (true, Some(port))
                }
                Err(e) => {
                    tracing::warn!("✗ UPnP failed: {}", e);

                    // Determine if we're restricted
                    if nat_type == NatType::Symmetric || nat_type == NatType::Unknown {
                        connectivity_status = ConnectivityStatus::Restricted;
                    }

                    (false, None)
                }
            }
        } else {
            (false, None)
        };

        // Create network info
        let network_info = NetworkInfo {
            local_addr,
            public_addr,
            nat_type,
            upnp_available,
            mapped_port,
            external_ip_sources,
            connectivity_status,
        };

        // Log summary
        tracing::info!("=== NAT Detection Complete ===");
        tracing::info!("Local: {}", network_info.local_addr);
        tracing::info!("Public: {:?}", network_info.public_addr);
        tracing::info!("NAT Type: {:?}", network_info.nat_type);
        tracing::info!("UPnP: {} (port: {:?})",
            if network_info.upnp_available { "Available" } else { "Not Available" },
            network_info.mapped_port
        );
        tracing::info!("Connectivity: {:?}", network_info.connectivity_status);
        tracing::info!("=============================");

        *self.network_info.write() = Some(network_info.clone());
        *self.initialized.write() = true;

        Ok(network_info)
    }

    /// Comprehensive public address discovery using multiple STUN servers
    async fn discover_public_address_comprehensive(
        &self,
        socket: &UdpSocket,
        sources: &mut Vec<(String, IpAddr)>,
    ) -> Result<SocketAddr> {
        use futures::future::join_all;

        let servers = self.config.stun_servers.clone();
        let socket = Arc::new(socket);

        // Query multiple STUN servers in parallel
        let mut futures = Vec::new();

        for (idx, server) in servers.iter().enumerate().take(5) {
            let client = self.stun_client.clone();
            let socket_clone = socket.clone();
            let server_clone = server.clone();

            let future = async move {
                match tokio::time::timeout(
                    Duration::from_secs(3),
                    client.query_stun_server(&socket_clone, &server_clone)
                ).await {
                    Ok(Ok(addr)) => Some((server_clone, addr)),
                    _ => None,
                }
            };

            futures.push(future);
        }

        let results = join_all(futures).await;

        // Collect successful results
        let mut addresses = Vec::new();
        for result in results {
            if let Some((server, addr)) = result {
                sources.push((server.clone(), addr.ip()));
                addresses.push(addr);
                tracing::debug!("STUN {} returned: {}", server, addr);
            }
        }

        if addresses.is_empty() {
            return Err(anyhow::anyhow!("All STUN servers failed"));
        }

        // Find consensus (most common address)
        let mut addr_counts = std::collections::HashMap::new();
        for addr in &addresses {
            *addr_counts.entry(addr.ip()).or_insert(0) += 1;
        }

        let (consensus_ip, count) = addr_counts.iter()
            .max_by_key(|(_, count)| *count)
            .ok_or_else(|| anyhow::anyhow!("No consensus on public IP"))?;

        tracing::info!("Public IP consensus: {} ({}/{} servers agree)",
            consensus_ip, count, addresses.len());

        // Use first matching address with consensus IP
        addresses.into_iter()
            .find(|addr| addr.ip() == **consensus_ip)
            .ok_or_else(|| anyhow::anyhow!("Failed to determine public address"))
    }

    /// Comprehensive NAT type detection following RFC 5780
    async fn detect_nat_type_comprehensive(&self, socket: &UdpSocket) -> Result<NatType> {
        // This would implement the full RFC 5780 flow chart
        // For now, using simplified detection

        let results = self.stun_client.detect_nat_type(socket).await?;

        if results.len() < 2 {
            return Ok(NatType::Unknown);
        }

        // Check if external port changes
        let ports_differ = results.windows(2)
            .any(|w| w[0].0.port() != w[1].0.port());

        // Check if external IP changes
        let ips_differ = results.windows(2)
            .any(|w| w[0].0.ip() != w[1].0.ip());

        if ips_differ || ports_differ {
            Ok(NatType::Symmetric)
        } else if results.iter().any(|(_, changed)| *changed) {
            Ok(NatType::FullCone)
        } else {
            // Would need more tests to distinguish between restricted types
            Ok(NatType::RestrictedCone)
        }
    }

    /// Comprehensive UPnP setup with fallback
    async fn setup_upnp_comprehensive(&mut self, local_port: u16) -> Result<u16> {
        // Create UPnP client with retry logic
        let mut upnp_client = match UpnpClient::new().await {
            Ok(client) => client,
            Err(e) => return Err(anyhow::anyhow!("UPnP client creation failed: {}", e)),
        };

        if !upnp_client.is_available() {
            return Err(anyhow::anyhow!("No UPnP gateway found"));
        }

        // Log gateway info
        if let Some(info) = upnp_client.gateway_info() {
            tracing::info!("UPnP {}", info);
        }

        // Try to get external IP for verification
        match upnp_client.get_external_ip().await {
            Ok(upnp_ip) => {
                tracing::info!("UPnP reports external IP: {}", upnp_ip);

                // Verify against STUN results
                if let Some(network_info) = &*self.network_info.read() {
                    if let Some(stun_addr) = network_info.public_addr {
                        if stun_addr.ip() != upnp_ip {
                            tracing::warn!(
                                "UPnP IP {} differs from STUN IP {}",
                                upnp_ip, stun_addr.ip()
                            );
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Cannot get external IP from UPnP: {}", e);
            }
        }

        // Add port mapping with retry
        for attempt in 1..=self.config.retry_attempts {
            match upnp_client.add_port_mapping(
                local_port,
                self.config.upnp_lease_duration,
                "SHARP-256 File Transfer"
            ).await {
                Ok(external_port) => {
                    *self.upnp_client.write() = Some(upnp_client);
                    return Ok(external_port);
                }
                Err(e) if attempt < self.config.retry_attempts => {
                    tracing::warn!("UPnP mapping attempt {} failed: {}", attempt, e);
                    tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                }
                Err(e) => return Err(e),
            }
        }

        Err(anyhow::anyhow!("UPnP mapping failed after {} attempts", self.config.retry_attempts))
    }

    /// Get best connectable address based on network topology
    pub fn get_connectable_address(&self) -> Result<SocketAddr> {
        let info = self.network_info.read()
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Network info not initialized"))?
            .clone();

        // Priority order:
        // 1. UPnP mapped address (most reliable)
        // 2. STUN public address (if Full Cone NAT)
        // 3. Local address (for LAN/same network)

        if let (Some(pub_addr), Some(mapped_port)) = (info.public_addr, info.mapped_port) {
            return Ok(SocketAddr::new(pub_addr.ip(), mapped_port));
        }

        if let Some(pub_addr) = info.public_addr {
            match info.nat_type {
                NatType::None | NatType::FullCone => return Ok(pub_addr),
                NatType::RestrictedCone | NatType::PortRestricted => {
                    // These might work with hole punching
                    tracing::warn!("Using public address {} but may require hole punching", pub_addr);
                    return Ok(pub_addr);
                }
                _ => {}
            }
        }

        // Fallback to local address
        tracing::warn!("No public address available, using local address");
        Ok(info.local_addr)
    }

    /// Prepare connection with comprehensive NAT traversal
    pub async fn prepare_connection(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
    ) -> Result<()> {
        let info = self.network_info.read()
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Network info not initialized"))?
            .clone();

        tracing::info!("Preparing connection to {} (NAT type: {:?})", peer_addr, info.nat_type);

        // Check if we need NAT traversal
        match info.connectivity_status {
            ConnectivityStatus::Direct => {
                tracing::info!("Direct connection available, no NAT traversal needed");
                return Ok(());
            }
            ConnectivityStatus::Offline => {
                return Err(anyhow::anyhow!("No internet connectivity"));
            }
            _ => {}
        }

        // Try advanced traversal first for difficult NATs
        if info.nat_type == NatType::Symmetric || info.nat_type == NatType::Unknown {
            if let Some(advanced) = &self.advanced_traversal {
                tracing::info!("Using advanced NAT traversal");

                match advanced.establish_connection(socket, "peer", Some(peer_addr)).await {
                    Ok(effective_addr) => {
                        tracing::info!("Advanced traversal successful via {}", effective_addr);
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::warn!("Advanced traversal failed: {}", e);
                    }
                }
            }
        }

        // Standard hole punching for cone NATs
        if self.config.enable_hole_punching {
            let puncher = HolePuncher::new(self.config.hole_punch_attempts);

            // Use coordinated punching if available
            let coordination_server = if let Some(advanced) = &self.advanced_traversal {
                advanced.coordinator.as_ref().map(|_| self.config.coordinator_server.clone())
                    .flatten()
                    .and_then(|s| s.parse().ok())
            } else {
                None
            };

            if let Some(coord_addr) = coordination_server {
                tracing::info!("Using coordinated hole punching via {}", coord_addr);
                puncher.simultaneous_punch(socket, peer_addr, Some(coord_addr)).await?;
            } else {
                tracing::info!("Performing direct hole punching");
                puncher.punch_hole(socket, peer_addr, is_initiator).await?;
            }
        }

        Ok(())
    }

    /// Clean up resources
    pub async fn cleanup(&mut self) -> Result<()> {
        if let Some(mut client) = self.upnp_client.write().take() {
            client.cleanup_all().await?;
        }
        Ok(())
    }

    /// Extract UPnP client for external management
    pub fn take_upnp_client(&mut self) -> Option<UpnpClient> {
        self.upnp_client.write().take()
    }
}