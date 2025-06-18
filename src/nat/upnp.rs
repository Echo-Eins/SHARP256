use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use igd::aio::{search_gateway, Gateway};
use igd::{PortMappingProtocol, SearchOptions};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Instant;
use rand::Rng;

/// UPnP client for managing port forwarding on routers with robust error handling
pub struct UpnpClient {
    gateway: Option<Gateway>,
    local_ip: IpAddr,
    active_mappings: Arc<RwLock<Vec<PortMapping>>>,
    discovery_attempts: u32,
}

#[derive(Debug, Clone)]
struct PortMapping {
    external_port: u16,
    internal_port: u16,
    protocol: PortMappingProtocol,
    description: String,
    created_at: Instant,
    lease_duration: u32,
}

impl UpnpClient {
    /// Create new UPnP client with multiple discovery attempts
    pub async fn new() -> Result<Self> {
        // First, reliably determine local IP
        let local_ip = Self::get_local_ip().await
            .context("Failed to determine local IP address")?;

        tracing::info!("Local IP detected: {}", local_ip);

        // Try multiple discovery methods
        let mut discovery_attempts = 0;
        let mut last_error = None;

        // Try different timeout values
        let timeouts = [
            Duration::from_secs(2),
            Duration::from_secs(5),
            Duration::from_secs(10),
        ];

        for timeout_duration in &timeouts {
            discovery_attempts += 1;
            tracing::info!("UPnP discovery attempt {} with timeout {:?}", discovery_attempts, timeout_duration);

            let search_options = SearchOptions {
                timeout: Some(*timeout_duration),
                // Bind to specific interface if local IP is IPv4
                bind_addr: match local_ip {
                    IpAddr::V4(ipv4) => Some(std::net::SocketAddr::new(IpAddr::V4(ipv4), 0)),
                    _ => None,
                },
                ..Default::default()
            };

            match search_gateway(search_options).await {
                Ok(gateway) => {
                    tracing::info!("UPnP gateway found: {}", gateway.addr);

                    // Verify gateway is functional
                    match gateway.get_external_ip().await {
                        Ok(external_ip) => {
                            tracing::info!("External IP via UPnP: {}", external_ip);

                            // Test port mapping capability
                            if Self::test_port_mapping(&gateway, &local_ip).await {
                                return Ok(Self {
                                    gateway: Some(gateway),
                                    local_ip,
                                    active_mappings: Arc::new(RwLock::new(Vec::new())),
                                    discovery_attempts,
                                });
                            } else {
                                tracing::warn!("Gateway found but port mapping test failed");
                                last_error = Some("Port mapping not supported");
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Gateway found but cannot get external IP: {}", e);
                            last_error = Some("Cannot retrieve external IP");
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Discovery attempt {} failed: {}", discovery_attempts, e);
                    last_error = Some("No gateway found");
                }
            }
        }

        // If we're here, all attempts failed
        let error_msg = format!(
            "UPnP discovery failed after {} attempts. Last error: {}. \
             Possible causes: router doesn't support UPnP, UPnP is disabled, \
             firewall blocking UDP port 1900, or no IGD-compatible device found.",
            discovery_attempts,
            last_error.unwrap_or("Unknown error")
        );

        tracing::error!("{}", error_msg);

        // Return client without gateway (for graceful degradation)
        Ok(Self {
            gateway: None,
            local_ip,
            active_mappings: Arc::new(RwLock::new(Vec::new())),
            discovery_attempts,
        })
    }

    /// Test if port mapping actually works
    async fn test_port_mapping(gateway: &Gateway, local_ip: &IpAddr) -> bool {
        let test_port = 50000 + rand::thread_rng().gen_range(0..10000);

        let local_addr = match local_ip {
            IpAddr::V4(ip) => std::net::SocketAddrV4::new(*ip, test_port),
            IpAddr::V6(_) => return false, // UPnP typically requires IPv4
        };

        // Try to add a test mapping
        match gateway.add_port(
            PortMappingProtocol::UDP,
            test_port,
            local_addr,
            60, // 60 second lease for test
            "SHARP-256 UPnP Test"
        ).await {
            Ok(()) => {
                // Successfully added, now remove it
                let _ = gateway.remove_port(PortMappingProtocol::UDP, test_port).await;
                true
            }
            Err(e) => {
                tracing::debug!("Port mapping test failed: {}", e);
                false
            }
        }
    }

    /// Add port mapping with intelligent port selection
    pub async fn add_port_mapping(
        &mut self,
        local_port: u16,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16> {
        let gateway = self.gateway.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No UPnP gateway available"))?;

        let local_addr = match self.local_ip {
            IpAddr::V4(ip) => std::net::SocketAddrV4::new(ip, local_port),
            IpAddr::V6(_) => {
                return Err(anyhow::anyhow!("UPnP requires IPv4 local address"));
            }
        };

        // Port selection strategy
        let mut external_port = local_port;
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 20;

        loop {
            match gateway
                .add_port(
                    PortMappingProtocol::UDP,
                    external_port,
                    local_addr,
                    lease_duration,
                    description,
                )
                .await
            {
                Ok(()) => {
                    tracing::info!(
                        "UPnP port mapping created: external:{} -> {}:{} (lease: {}s)",
                        external_port, self.local_ip, local_port, lease_duration
                    );

                    // Save mapping info
                    let mapping = PortMapping {
                        external_port,
                        internal_port: local_port,
                        protocol: PortMappingProtocol::UDP,
                        description: description.to_string(),
                        created_at: Instant::now(),
                        lease_duration,
                    };
                    self.active_mappings.write().push(mapping.clone());

                    // Schedule lease renewal
                    self.schedule_lease_renewal(mapping, gateway.clone());

                    return Ok(external_port);
                }
                Err(e) => {
                    attempts += 1;

                    if attempts >= MAX_ATTEMPTS {
                        return Err(anyhow::anyhow!(
                            "Failed to create port mapping after {} attempts: {}",
                            MAX_ATTEMPTS, e
                        ));
                    }

                    // Smart port selection based on error
                    let error_str = e.to_string();

                    if error_str.contains("ConflictInMappingEntry") ||
                        error_str.contains("718") { // Common error code for conflict
                        // Port is in use, try different strategies
                        if attempts < 5 {
                            // Try sequential ports
                            external_port = local_port + attempts;
                        } else if attempts < 10 {
                            // Try common port ranges
                            external_port = 40000 + (attempts - 5) * 1000;
                        } else {
                            // Random high port
                            external_port = 49152 + rand::thread_rng().gen_range(0..16383);
                        }

                        tracing::debug!("Port {} unavailable, trying {}", external_port - 1, external_port);
                    } else if error_str.contains("NotAuthorized") ||
                        error_str.contains("606") {
                        return Err(anyhow::anyhow!("Not authorized to create port mappings"));
                    } else if error_str.contains("ExternalPortOnlySupportsWildcard") {
                        // Some routers only support wildcard external ports
                        external_port = 0; // Let router choose
                    } else {
                        // Unknown error, try random port
                        external_port = 30000 + rand::thread_rng().gen_range(0..30000);
                    }

                    // Small delay to avoid hammering the router
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Schedule automatic lease renewal
    fn schedule_lease_renewal(&self, mapping: PortMapping, gateway: Gateway) {
        let mappings = self.active_mappings.clone();

        tokio::spawn(async move {
            // Renew at 80% of lease duration
            let renewal_time = Duration::from_secs((mapping.lease_duration * 4 / 5) as u64);

            loop {
                tokio::time::sleep(renewal_time).await;

                // Check if mapping still exists
                let still_active = mappings.read()
                    .iter()
                    .any(|m| m.external_port == mapping.external_port);

                if !still_active {
                    break;
                }

                // Get local IP for renewal
                let local_ip = match Self::get_local_ip().await {
                    Ok(IpAddr::V4(ip)) => ip,
                    _ => {
                        tracing::warn!("Failed to get local IP for renewal");
                        break;
                    }
                };

                // Find local port from stored mapping
                let local_port = {
                    let mappings_guard = mappings.read();
                    mappings_guard.iter()
                        .find(|m| m.external_port == mapping.external_port)
                        .map(|m| m.internal_port)
                };

                if let Some(port) = local_port {
                    let local_addr = std::net::SocketAddrV4::new(local_ip, port);

                    match gateway.add_port(
                        mapping.protocol,
                        mapping.external_port,
                        local_addr,
                        mapping.lease_duration,
                        &mapping.description,
                    ).await {
                        Ok(()) => {
                            tracing::debug!("Renewed UPnP mapping for port {}", mapping.external_port);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to renew UPnP mapping: {}", e);
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
        });
    }

    /// Remove port mapping
    pub async fn remove_port_mapping(&mut self, external_port: u16) -> Result<()> {
        let gateway = self.gateway.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No UPnP gateway available"))?;

        let mut mappings = self.active_mappings.write();
        if let Some(pos) = mappings.iter().position(|m| m.external_port == external_port) {
            let mapping = mappings.remove(pos);

            match gateway.remove_port(mapping.protocol, external_port).await {
                Ok(()) => {
                    tracing::info!("UPnP port mapping removed: {}", external_port);
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!("Failed to remove port mapping: {}", e);
                    // Not critical - mapping will expire
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }

    /// Get external IP address via UPnP
    pub async fn get_external_ip(&self) -> Result<IpAddr> {
        let gateway = self.gateway.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No UPnP gateway available"))?;

        let external_ip = gateway.get_external_ip().await
            .context("Failed to get external IP from UPnP gateway")?;

        Ok(IpAddr::V4(external_ip))
    }

    /// Clean up all active mappings
    pub async fn cleanup_all(&mut self) -> Result<()> {
        if let Some(gateway) = &self.gateway {
            let mappings = self.active_mappings.write().drain(..).collect::<Vec<_>>();

            for mapping in mappings {
                if let Err(e) = gateway.remove_port(mapping.protocol, mapping.external_port).await {
                    tracing::warn!("Failed to remove mapping {}: {}", mapping.external_port, e);
                }
            }

            tracing::info!("All UPnP port mappings cleaned up");
        }

        Ok(())
    }

    /// Check if UPnP is available and functional
    pub fn is_available(&self) -> bool {
        self.gateway.is_some()
    }

    /// Get gateway information
    pub fn gateway_info(&self) -> Option<String> {
        self.gateway.as_ref().map(|g| format!("Gateway: {}", g.addr))
    }

    /// Get local IP address with multiple detection methods
    async fn get_local_ip() -> Result<IpAddr> {
        // Method 1: Try to get from network interfaces
        #[cfg(feature = "nat-traversal")]
        {
            use if_addrs::get_if_addrs;

            if let Ok(addrs) = get_if_addrs() {
                // Prefer non-loopback IPv4 addresses
                for iface in &addrs {
                    if !iface.is_loopback() {
                        match iface.ip() {
                            IpAddr::V4(ipv4) if !ipv4.is_link_local() => {
                                return Ok(IpAddr::V4(ipv4));
                            }
                            _ => continue,
                        }
                    }
                }

                // Fallback to any non-loopback address
                for iface in addrs {
                    if !iface.is_loopback() {
                        return Ok(iface.ip());
                    }
                }
            }
        }

        // Method 2: Connect to public DNS and check local address
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

        // Try multiple public addresses
        let test_addrs = [
            "8.8.8.8:53",      // Google DNS
            "1.1.1.1:53",      // Cloudflare DNS
            "208.67.222.222:53", // OpenDNS
        ];

        for addr in &test_addrs {
            if socket.connect(addr).await.is_ok() {
                if let Ok(local) = socket.local_addr() {
                    return Ok(local.ip());
                }
            }
        }

        // Method 3: Last resort - try to determine from hostname
        if let Ok(hostname) = hostname::get() {
            if let Ok(addrs) = tokio::net::lookup_host(format!("{}:0", hostname.to_string_lossy())).await {
                for addr in addrs {
                    if !addr.ip().is_loopback() {
                        return Ok(addr.ip());
                    }
                }
            }
        }

        Err(anyhow::anyhow!("Failed to determine local IP address"))
    }
}

impl Drop for UpnpClient {
    fn drop(&mut self) {
        if self.active_mappings.read().is_empty() {
            return;
        }

        let mappings = self.active_mappings.read().clone();
        if let Some(gateway) = self.gateway.clone() {
            // Best effort cleanup
            let _ = tokio::task::spawn(async move {
                for mapping in mappings {
                    let _ = gateway.remove_port(mapping.protocol, mapping.external_port).await;
                }
            });
        }
    }
}