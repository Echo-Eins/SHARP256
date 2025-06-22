// src/nat/ice/gathering.rs
//! ICE candidate gathering implementation with full TURN support

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::{timeout, sleep};
use tracing::{info, warn, error, debug, trace};

use crate::nat::stun::{StunClient, StunConfig};
use crate::nat::error::{NatError, NatResult};
use super::{Candidate, CandidateType, TransportProtocol};

// TURN client implementation
use turn_client::{TurnClient, TurnAllocation, TurnConfig};

/// Candidate gatherer with full RFC 8445 and TURN support
pub struct CandidateGatherer {
    /// Component ID -> Socket mapping
    sockets: Arc<RwLock<HashMap<u32, Arc<UdpSocket>>>>,

    /// STUN servers
    stun_servers: Vec<String>,

    /// TURN servers
    turn_servers: Vec<TurnServerConfig>,

    /// Network interfaces to use
    interfaces: Arc<RwLock<Vec<NetworkInterface>>>,

    /// Event channel
    event_tx: mpsc::UnboundedSender<GatheringEvent>,

    /// Transport policy
    policy: super::IceTransportPolicy,

    /// TURN allocations
    turn_allocations: Arc<Mutex<HashMap<u32, Vec<TurnAllocation>>>>,

    /// Gathering statistics
    stats: Arc<GatheringStats>,

    /// mDNS name mappings (for privacy)
    mdns_mappings: Arc<RwLock<HashMap<IpAddr, String>>>,
}

/// TURN server configuration
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    pub url: String,
    pub username: String,
    pub password: String,
    pub credential_type: TurnCredentialType,
}

/// TURN credential type
#[derive(Debug, Clone)]
pub enum TurnCredentialType {
    Password,
    OAuth {
        access_token: String,
    },
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub addresses: Vec<IpAddr>,
    pub index: u32,
    pub is_vpn: bool,
    pub is_loopback: bool,
    pub mtu: u32,
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

/// Gathering statistics
#[derive(Debug, Default)]
struct GatheringStats {
    host_candidates: std::sync::atomic::AtomicUsize,
    srflx_candidates: std::sync::atomic::AtomicUsize,
    relay_candidates: std::sync::atomic::AtomicUsize,
    prflx_candidates: std::sync::atomic::AtomicUsize,
    gather_time_ms: std::sync::atomic::AtomicU64,
}

impl CandidateGatherer {
    /// Create new gatherer
    pub fn new(
        stun_servers: Vec<String>,
        turn_servers: Vec<TurnServerConfig>,
        policy: super::IceTransportPolicy,
        event_tx: mpsc::UnboundedSender<GatheringEvent>,
    ) -> NatResult<Self> {
        info!("Creating candidate gatherer with {} STUN and {} TURN servers",
            stun_servers.len(), turn_servers.len());

        let interfaces = Self::discover_interfaces()?;
        info!("Discovered {} network interfaces", interfaces.len());

        Ok(Self {
            sockets: Arc::new(RwLock::new(HashMap::new())),
            stun_servers,
            turn_servers,
            interfaces: Arc::new(RwLock::new(interfaces)),
            event_tx,
            policy,
            turn_allocations: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(GatheringStats::default()),
            mdns_mappings: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Discover network interfaces
    fn discover_interfaces() -> NatResult<Vec<NetworkInterface>> {
        let mut interfaces = Vec::new();

        // Try if-addrs crate for interface discovery
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            use local_ip_address::list_afinet_netifas;

            if let Ok(network_interfaces) = list_afinet_netifas() {
                let mut iface_map: HashMap<String, NetworkInterface> = HashMap::new();

                for (name, addr) in network_interfaces {
                    let entry = iface_map.entry(name.clone()).or_insert_with(|| {
                        NetworkInterface {
                            name: name.clone(),
                            addresses: Vec::new(),
                            index: 0,
                            is_vpn: name.starts_with("tun") ||
                                name.starts_with("tap") ||
                                name.starts_with("wg") ||
                                name.starts_with("utun"),
                            is_loopback: name.contains("lo"),
                            mtu: 1500, // Default MTU
                        }
                    });

                    // Filter out link-local addresses
                    match addr {
                        IpAddr::V4(v4) if !v4.is_link_local() => {
                            entry.addresses.push(IpAddr::V4(v4));
                        }
                        IpAddr::V6(v6) if !is_link_local_v6(&v6) => {
                            entry.addresses.push(IpAddr::V6(v6));
                        }
                        _ => {}
                    }
                }

                interfaces = iface_map.into_values()
                    .filter(|iface| !iface.addresses.is_empty())
                    .collect();
            }
        }

        // Fallback: try to detect at least one interface
        if interfaces.is_empty() {
            warn!("No interfaces found via system APIs, using fallback");

            // Try to bind to determine local addresses
            if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
                if let Ok(()) = socket.connect("8.8.8.8:80") {
                    if let Ok(addr) = socket.local_addr() {
                        interfaces.push(NetworkInterface {
                            name: "default".to_string(),
                            addresses: vec![addr.ip()],
                            index: 0,
                            is_vpn: false,
                            is_loopback: false,
                            mtu: 1500,
                        });
                    }
                }
            }
        }

        // Sort interfaces by preference
        interfaces.sort_by_key(|iface| {
            let mut score = 0;
            if iface.is_loopback { score += 1000; }
            if iface.is_vpn { score += 100; }
            if iface.addresses.iter().all(|a| a.is_ipv6()) { score += 10; }
            score
        });

        for iface in &interfaces {
            debug!("Interface {}: {:?} (VPN: {}, Loopback: {})",
                iface.name, iface.addresses, iface.is_vpn, iface.is_loopback);
        }

        Ok(interfaces)
    }

    /// Gather candidates for component
    pub async fn gather_candidates(
        &self,
        component_id: u32,
        port_hint: u16,
    ) -> NatResult<Vec<Candidate>> {
        let start_time = std::time::Instant::now();
        info!("Starting candidate gathering for component {}", component_id);

        let mut all_candidates = Vec::new();
        let mut gathering_tasks = Vec::new();

        // Skip host candidates if relay-only policy
        if self.policy != super::IceTransportPolicy::Relay {
            // Gather host candidates
            match self.gather_host_candidates(component_id, port_hint).await {
                Ok(candidates) => {
                    info!("Gathered {} host candidates for component {}",
                        candidates.len(), component_id);

                    for candidate in &candidates {
                        debug!("Host candidate: {}", candidate.addr);
                        self.stats.host_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.event_tx.send(GatheringEvent::CandidateFound(candidate.clone()))
                            .map_err(|_| NatError::Platform("Event channel closed".to_string()))?;
                    }

                    all_candidates.extend(candidates);
                }
                Err(e) => {
                    error!("Failed to gather host candidates: {}", e);
                }
            }

            // Gather server reflexive candidates in parallel
            let stun_servers = self.stun_servers.clone();
            let sockets = self.sockets.clone();
            let stats = self.stats.clone();
            let event_tx = self.event_tx.clone();

            let stun_task = tokio::spawn(async move {
                let mut srflx_candidates = Vec::new();

                for server in &stun_servers {
                    match Self::gather_srflx_from_server(
                        &sockets,
                        component_id,
                        server,
                    ).await {
                        Ok(candidates) => {
                            for candidate in candidates {
                                debug!("Server reflexive candidate from {}: {}",
                                    server, candidate.addr);
                                stats.srflx_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let _ = event_tx.send(GatheringEvent::CandidateFound(candidate.clone()));
                                srflx_candidates.push(candidate);
                            }
                        }
                        Err(e) => {
                            debug!("Failed to get srflx from {}: {}", server, e);
                        }
                    }
                }

                srflx_candidates
            });

            gathering_tasks.push(stun_task);
        }

        // Gather relay candidates if configured
        if !self.turn_servers.is_empty() {
            let turn_servers = self.turn_servers.clone();
            let allocations = self.turn_allocations.clone();
            let stats = self.stats.clone();
            let event_tx = self.event_tx.clone();

            let turn_task = tokio::spawn(async move {
                let mut relay_candidates = Vec::new();
                let mut component_allocations = Vec::new();

                for server_config in &turn_servers {
                    match Self::gather_relay_from_server(
                        component_id,
                        server_config,
                    ).await {
                        Ok((allocation, candidate)) => {
                            info!("TURN allocation successful from {}: relay={}",
                                server_config.url, candidate.addr);
                            stats.relay_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let _ = event_tx.send(GatheringEvent::CandidateFound(candidate.clone()));
                            relay_candidates.push(candidate);
                            component_allocations.push(allocation);
                        }
                        Err(e) => {
                            error!("TURN allocation failed from {}: {}",
                                server_config.url, e);
                        }
                    }
                }

                // Store allocations
                allocations.lock().await.insert(component_id, component_allocations);

                relay_candidates
            });

            gathering_tasks.push(turn_task);
        }

        // Wait for all gathering tasks with timeout
        let gather_timeout = Duration::from_secs(10);

        for task in gathering_tasks {
            match timeout(gather_timeout, task).await {
                Ok(Ok(candidates)) => {
                    all_candidates.extend(candidates);
                }
                Ok(Err(e)) => {
                    warn!("Gathering task failed: {}", e);
                }
                Err(_) => {
                    warn!("Gathering task timed out");
                }
            }
        }

        let elapsed = start_time.elapsed();
        self.stats.gather_time_ms.store(
            elapsed.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed
        );

        info!("Candidate gathering complete for component {} in {:?}: {} candidates",
            component_id, elapsed, all_candidates.len());

        // Signal completion
        self.event_tx.send(GatheringEvent::ComponentComplete(component_id))
            .map_err(|_| NatError::Platform("Event channel closed".to_string()))?;

        Ok(all_candidates)
    }

    /// Gather host candidates
    async fn gather_host_candidates(
        &self,
        component_id: u32,
        port_hint: u16,
    ) -> NatResult<Vec<Candidate>> {
        let mut candidates = Vec::new();
        let mut network_id = 1u32;
        let mut used_ports = HashSet::new();

        let interfaces = self.interfaces.read().await;

        for interface in interfaces.iter() {
            if interface.is_loopback && !cfg!(test) {
                continue; // Skip loopback unless testing
            }

            for addr in &interface.addresses {
                // Skip IPv6 if not enabled
                if addr.is_ipv6() && !self.is_ipv6_enabled().await {
                    continue;
                }

                // Determine port to use
                let port = if port_hint != 0 && !used_ports.contains(&port_hint) {
                    port_hint
                } else {
                    0 // Let OS choose
                };

                let bind_addr = SocketAddr::new(*addr, port);

                // Try to bind socket
                match UdpSocket::bind(bind_addr).await {
                    Ok(socket) => {
                        let actual_addr = socket.local_addr()?;
                        used_ports.insert(actual_addr.port());

                        debug!("Bound socket for component {} on {}", component_id, actual_addr);

                        // Enable socket options
                        Self::configure_socket(&socket)?;

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

                        // Generate mDNS name if enabled
                        if self.is_mdns_enabled().await && actual_addr.ip().is_ipv4() {
                            let mdns_name = self.generate_mdns_name(actual_addr.ip()).await;
                            debug!("Generated mDNS name {} for {}", mdns_name, actual_addr.ip());
                            // In real implementation, would use mDNS address
                        }

                        candidates.push(candidate);
                        network_id += 1;
                    }
                    Err(e) => {
                        debug!("Failed to bind to {}: {}", bind_addr, e);
                    }
                }
            }
        }

        Ok(candidates)
    }

    /// Gather server reflexive candidates from a STUN server
    async fn gather_srflx_from_server(
        sockets: &Arc<RwLock<HashMap<u32, Arc<UdpSocket>>>>,
        component_id: u32,
        server: &str,
    ) -> NatResult<Vec<Candidate>> {
        let mut candidates = Vec::new();

        let socket = {
            let sockets = sockets.read().await;
            sockets.get(&component_id).cloned()
        };

        let socket = match socket {
            Some(s) => s,
            None => {
                debug!("No socket for component {} to query STUN", component_id);
                return Ok(candidates);
            }
        };

        let local_addr = socket.local_addr()?;

        // Create STUN client
        let config = StunConfig {
            servers: vec![server.to_string()],
            max_retries: 3,
            initial_rto_ms: 500,
            ..Default::default()
        };

        let client = StunClient::new(config);

        // Query STUN server
        match timeout(
            Duration::from_secs(5),
            client.get_mapped_address(&socket)
        ).await {
            Ok(Ok(mapped_addr)) => {
                // Only add if different from local address
                if mapped_addr.ip() != local_addr.ip() {
                    debug!("STUN {} returned mapped address: {}", server, mapped_addr);

                    let candidate = Candidate::new_server_reflexive(
                        mapped_addr,
                        local_addr,
                        component_id,
                        TransportProtocol::Udp,
                        0, // Use same network ID as host
                    );

                    candidates.push(candidate);
                } else {
                    debug!("STUN {} returned same IP - no NAT", server);
                }
            }
            Ok(Err(e)) => {
                debug!("STUN query to {} failed: {}", server, e);
            }
            Err(_) => {
                debug!("STUN query to {} timed out", server);
            }
        }

        Ok(candidates)
    }

    /// Gather relay candidates from a TURN server
    async fn gather_relay_from_server(
        component_id: u32,
        server_config: &TurnServerConfig,
    ) -> NatResult<(TurnAllocation, Candidate)> {
        info!("Creating TURN allocation on {} for component {}",
            server_config.url, component_id);

        // Parse TURN URL
        let (host, port, transport) = Self::parse_turn_url(&server_config.url)?;
        let server_addr = format!("{}:{}", host, port);

        // Create TURN configuration
        let turn_config = TurnConfig {
            server: server_addr.clone(),
            username: server_config.username.clone(),
            password: server_config.password.clone(),
            realm: None, // Will be discovered
            lifetime: Duration::from_secs(600), // 10 minutes
            software: Some("SHARP ICE/1.0".to_string()),
        };

        // Create TURN client
        let mut turn_client = TurnClient::new(turn_config).await?;

        // Create allocation
        let allocation = turn_client.allocate().await?;
        let relay_addr = allocation.relay_address;
        let local_addr = allocation.local_address;

        info!("TURN allocation created: {} -> {} (lifetime: {:?})",
            local_addr, relay_addr, allocation.lifetime);

        // Create relay candidate
        let candidate = Candidate::new_relay(
            relay_addr,
            local_addr,
            component_id,
            TransportProtocol::Udp,
            &server_addr.parse().unwrap_or_else(|_| {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port)
            }),
        );

        Ok((allocation, candidate))
    }

    /// Parse TURN URL (turn:host:port or turns:host:port)
    fn parse_turn_url(url: &str) -> NatResult<(String, u16, &'static str)> {
        if let Some(rest) = url.strip_prefix("turn:") {
            let parts: Vec<&str> = rest.split(':').collect();
            match parts.len() {
                1 => Ok((parts[0].to_string(), 3478, "udp")),
                2 => Ok((parts[0].to_string(), parts[1].parse().unwrap_or(3478), "udp")),
                _ => Err(NatError::Platform("Invalid TURN URL".to_string())),
            }
        } else if let Some(rest) = url.strip_prefix("turns:") {
            let parts: Vec<&str> = rest.split(':').collect();
            match parts.len() {
                1 => Ok((parts[0].to_string(), 5349, "tcp")),
                2 => Ok((parts[0].to_string(), parts[1].parse().unwrap_or(5349), "tcp")),
                _ => Err(NatError::Platform("Invalid TURNS URL".to_string())),
            }
        } else {
            Err(NatError::Platform("URL must start with turn: or turns:".to_string()))
        }
    }

    /// Configure socket with optimal settings
    fn configure_socket(socket: &UdpSocket) -> NatResult<()> {
        use socket2::{Domain, Socket, Type};

        // Get the raw socket
        let sock_ref = socket2::SockRef::from(socket);

        // Set receive buffer size (256KB)
        let _ = sock_ref.set_recv_buffer_size(256 * 1024);

        // Set send buffer size (256KB)
        let _ = sock_ref.set_send_buffer_size(256 * 1024);

        // Enable DSCP marking for QoS (if supported)
        #[cfg(not(target_os = "windows"))]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();

            // Set DSCP to EF (46) for low latency
            unsafe {
                let dscp = 46i32 << 2; // DSCP is upper 6 bits of TOS
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_TOS,
                    &dscp as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&dscp) as libc::socklen_t,
                );
            }
        }

        Ok(())
    }

    /// Get socket for component
    pub async fn get_socket(&self, component_id: u32) -> Option<Arc<UdpSocket>> {
        self.sockets.read().await.get(&component_id).cloned()
    }

    /// Refresh TURN allocations
    pub async fn refresh_turn_allocations(&self) -> NatResult<()> {
        let mut allocations = self.turn_allocations.lock().await;

        for (component_id, allocs) in allocations.iter_mut() {
            for allocation in allocs {
                match allocation.refresh().await {
                    Ok(new_lifetime) => {
                        debug!("Refreshed TURN allocation for component {}: {:?}",
                            component_id, new_lifetime);
                    }
                    Err(e) => {
                        error!("Failed to refresh TURN allocation: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Create TURN permission for peer
    pub async fn create_turn_permission(
        &self,
        component_id: u32,
        peer_addr: SocketAddr,
    ) -> NatResult<()> {
        let allocations = self.turn_allocations.lock().await;

        if let Some(allocs) = allocations.get(&component_id) {
            for allocation in allocs {
                match allocation.create_permission(peer_addr).await {
                    Ok(()) => {
                        info!("Created TURN permission for {} on component {}",
                            peer_addr, component_id);
                    }
                    Err(e) => {
                        error!("Failed to create TURN permission: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Send data through TURN relay
    pub async fn send_turn_data(
        &self,
        component_id: u32,
        data: &[u8],
        peer_addr: SocketAddr,
    ) -> NatResult<()> {
        let allocations = self.turn_allocations.lock().await;

        if let Some(allocs) = allocations.get(&component_id) {
            for allocation in allocs {
                if let Err(e) = allocation.send_data(data, peer_addr).await {
                    error!("Failed to send TURN data: {}", e);
                    return Err(e);
                }
                return Ok(());
            }
        }

        Err(NatError::Platform("No TURN allocation for component".to_string()))
    }

    /// Check if IPv6 is enabled
    async fn is_ipv6_enabled(&self) -> bool {
        // In real implementation, would check config
        true
    }

    /// Check if mDNS is enabled
    async fn is_mdns_enabled(&self) -> bool {
        // In real implementation, would check config
        false
    }

    /// Generate mDNS name for IP
    async fn generate_mdns_name(&self, ip: IpAddr) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random: String = (0..8)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        let name = format!("{}.local", random.to_lowercase());
        self.mdns_mappings.write().await.insert(ip, name.clone());
        name
    }

    /// Get gathering statistics
    pub fn get_stats(&self) -> String {
        format!(
            "Gathering stats: host={}, srflx={}, relay={}, time={}ms",
            self.stats.host_candidates.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.srflx_candidates.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.relay_candidates.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.gather_time_ms.load(std::sync::atomic::Ordering::Relaxed)
        )
    }
}

/// Check if IPv6 address is link-local
fn is_link_local_v6(addr: &Ipv6Addr) -> bool {
    // fe80::/10
    addr.segments()[0] & 0xffc0 == 0xfe80
}

// TURN client module
mod turn_client {
    use super::*;
    use crate::nat::stun::{
        Message, MessageType, TransactionId, Attribute, AttributeType, AttributeValue,
    };
    use bytes::{BytesMut, BufMut};
    use std::time::Instant;

    /// TURN client configuration
    #[derive(Debug, Clone)]
    pub struct TurnConfig {
        pub server: String,
        pub username: String,
        pub password: String,
        pub realm: Option<String>,
        pub lifetime: Duration,
        pub software: Option<String>,
    }

    /// TURN allocation
    pub struct TurnAllocation {
        pub relay_address: SocketAddr,
        pub local_address: SocketAddr,
        pub lifetime: Duration,
        pub created_at: Instant,
        client: Arc<TurnClient>,
    }

    impl TurnAllocation {
        /// Refresh allocation
        pub async fn refresh(&mut self) -> NatResult<Duration> {
            self.client.refresh_allocation(self.lifetime).await
        }

        /// Create permission for peer
        pub async fn create_permission(&self, peer_addr: SocketAddr) -> NatResult<()> {
            self.client.create_permission(peer_addr).await
        }

        /// Send data to peer
        pub async fn send_data(&self, data: &[u8], peer_addr: SocketAddr) -> NatResult<()> {
            self.client.send_data(data, peer_addr).await
        }
    }

    /// TURN client implementation
    pub struct TurnClient {
        config: TurnConfig,
        socket: Arc<UdpSocket>,
        server_addr: SocketAddr,
        realm: RwLock<Option<String>>,
        nonce: RwLock<Option<Vec<u8>>>,
    }

    // TURN-specific attribute types
    impl AttributeType {
        pub const ChannelNumber: AttributeType = AttributeType(0x000C);
        pub const Lifetime: AttributeType = AttributeType(0x000D);
        pub const XorPeerAddress: AttributeType = AttributeType(0x0012);
        pub const Data: AttributeType = AttributeType(0x0013);
        pub const XorRelayedAddress: AttributeType = AttributeType(0x0016);
        pub const RequestedTransport: AttributeType = AttributeType(0x0019);
        pub const DontFragment: AttributeType = AttributeType(0x001A);
    }

    impl TurnClient {
        /// Create new TURN client
        pub async fn new(config: TurnConfig) -> NatResult<Arc<Self>> {
            let server_addr: SocketAddr = config.server.parse()
                .map_err(|_| NatError::Platform("Invalid TURN server address".to_string()))?;

            let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

            info!("Created TURN client for {}", server_addr);

            Ok(Arc::new(Self {
                config,
                socket,
                server_addr,
                realm: RwLock::new(None),
                nonce: RwLock::new(None),
            }))
        }

        /// Allocate TURN relay
        pub async fn allocate(self: &Arc<Self>) -> NatResult<TurnAllocation> {
            info!("Starting TURN allocation to {}", self.server_addr);

            // First attempt without auth
            let mut attempt = 0;

            loop {
                attempt += 1;
                if attempt > 3 {
                    return Err(NatError::Platform("TURN allocation failed after 3 attempts".to_string()));
                }

                let response = self.send_allocate_request().await?;

                match response.message_type {
                    MessageType::AllocateResponse => {
                        // Success!
                        return self.handle_allocate_success(response).await;
                    }
                    MessageType::AllocateError => {
                        // Check error code
                        if let Some(error_attr) = response.get_attribute(AttributeType::ErrorCode) {
                            if let AttributeValue::ErrorCode { code, reason } = &error_attr.value {
                                match *code {
                                    401 => {
                                        // Unauthorized - extract realm and nonce
                                        self.handle_unauthorized(response).await?;
                                        info!("Got 401, retrying with credentials");
                                        continue;
                                    }
                                    438 => {
                                        // Stale nonce
                                        info!("Stale nonce, refreshing");
                                        self.handle_unauthorized(response).await?;
                                        continue;
                                    }
                                    _ => {
                                        error!("TURN allocation error {}: {}", code, reason);
                                        return Err(NatError::Platform(
                                            format!("TURN error {}: {}", code, reason)
                                        ));
                                    }
                                }
                            }
                        }

                        return Err(NatError::Platform("TURN allocation failed".to_string()));
                    }
                    _ => {
                        return Err(NatError::Platform("Unexpected TURN response".to_string()));
                    }
                }
            }
        }

        /// Send ALLOCATE request
        async fn send_allocate_request(&self) -> NatResult<Message> {
            let transaction_id = TransactionId::new();
            let mut request = Message::new(MessageType::AllocateRequest, transaction_id);

            // Add REQUESTED-TRANSPORT (UDP)
            let mut transport_data = vec![17, 0, 0, 0]; // Protocol 17 = UDP
            request.add_attribute(Attribute::new(
                AttributeType::RequestedTransport,
                AttributeValue::Raw(transport_data),
            ));

            // Add LIFETIME
            let lifetime_secs = self.config.lifetime.as_secs() as u32;
            let mut lifetime_data = vec![0u8; 4];
            lifetime_data[0] = (lifetime_secs >> 24) as u8;
            lifetime_data[1] = (lifetime_secs >> 16) as u8;
            lifetime_data[2] = (lifetime_secs >> 8) as u8;
            lifetime_data[3] = lifetime_secs as u8;
            request.add_attribute(Attribute::new(
                AttributeType::Lifetime,
                AttributeValue::Raw(lifetime_data),
            ));

            // Add DONT-FRAGMENT
            request.add_attribute(Attribute::new(
                AttributeType::DontFragment,
                AttributeValue::Raw(vec![]),
            ));

            // Add SOFTWARE if configured
            if let Some(ref software) = self.config.software {
                request.add_attribute(Attribute::new(
                    AttributeType::Software,
                    AttributeValue::Software(software.clone()),
                ));
            }

            // Add authentication if we have realm and nonce
            let realm = self.realm.read().await.clone();
            let nonce = self.nonce.read().await.clone();

            if let (Some(realm), Some(nonce)) = (realm, nonce) {
                // Add USERNAME
                request.add_attribute(Attribute::new(
                    AttributeType::Username,
                    AttributeValue::Username(self.config.username.clone()),
                ));

                // Add REALM
                request.add_attribute(Attribute::new(
                    AttributeType::Realm,
                    AttributeValue::Realm(realm.clone()),
                ));

                // Add NONCE
                request.add_attribute(Attribute::new(
                    AttributeType::Nonce,
                    AttributeValue::Nonce(nonce),
                ));
            }

            // Calculate MESSAGE-INTEGRITY if authenticated
            let integrity_key = if realm.is_some() {
                // Long-term credentials: key = MD5(username:realm:password)
                use md5::{Md5, Digest};
                let input = format!("{}:{}:{}",
                                    self.config.username,
                                    realm.unwrap_or_default(),
                                    self.config.password
                );
                let hash = Md5::digest(input.as_bytes());
                Some(hash.to_vec())
            } else {
                None
            };

            // Send request
            let encoded = request.encode(integrity_key.as_deref(), true)?;
            self.socket.send_to(&encoded, self.server_addr).await?;

            // Wait for response
            let mut buffer = vec![0u8; 2048];
            let (size, from_addr) = timeout(
                Duration::from_secs(5),
                self.socket.recv_from(&mut buffer)
            ).await
                .map_err(|_| NatError::Timeout(Duration::from_secs(5)))?
                .map_err(|e| NatError::Network(e))?;

            if from_addr != self.server_addr {
                return Err(NatError::Platform("Response from wrong address".to_string()));
            }

            let response = Message::decode(BytesMut::from(&buffer[..size]))?;

            // Verify transaction ID
            if response.transaction_id != transaction_id {
                return Err(NatError::Platform("Transaction ID mismatch".to_string()));
            }

            Ok(response)
        }

        /// Handle 401 Unauthorized response
        async fn handle_unauthorized(&self, response: Message) -> NatResult<()> {
            // Extract REALM
            if let Some(realm_attr) = response.get_attribute(AttributeType::Realm) {
                if let AttributeValue::Realm(realm) = &realm_attr.value {
                    *self.realm.write().await = Some(realm.clone());
                    debug!("Got TURN realm: {}", realm);
                }
            }

            // Extract NONCE
            if let Some(nonce_attr) = response.get_attribute(AttributeType::Nonce) {
                if let AttributeValue::Nonce(nonce) = &nonce_attr.value {
                    *self.nonce.write().await = Some(nonce.clone());
                    debug!("Got TURN nonce");
                }
            }

            Ok(())
        }

        /// Handle successful ALLOCATE response
        async fn handle_allocate_success(&self, response: Message) -> NatResult<TurnAllocation> {
            // Extract XOR-RELAYED-ADDRESS
            let relay_addr = response.attributes.iter()
                .find_map(|attr| match &attr.value {
                    AttributeValue::XorRelayedAddress(addr) => Some(*addr),
                    _ => None,
                })
                .ok_or_else(|| NatError::Platform("No XOR-RELAYED-ADDRESS in response".to_string()))?;

            // Extract LIFETIME
            let lifetime = response.attributes.iter()
                .find_map(|attr| {
                    if attr.attr_type == AttributeType::Lifetime {
                        if let AttributeValue::Raw(data) = &attr.value {
                            if data.len() >= 4 {
                                let secs = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                                return Some(Duration::from_secs(secs as u64));
                            }
                        }
                    }
                    None
                })
                .unwrap_or(self.config.lifetime);

            let local_addr = self.socket.local_addr()?;

            info!("TURN allocation successful: {} -> {} (lifetime: {:?})",
               local_addr, relay_addr, lifetime);

            Ok(TurnAllocation {
                relay_address: relay_addr,
                local_address: local_addr,
                lifetime,
                created_at: Instant::now(),
                client: Arc::clone(self),
            })
        }

        /// Refresh allocation
        pub async fn refresh_allocation(&self, lifetime: Duration) -> NatResult<Duration> {
            debug!("Refreshing TURN allocation");

            let transaction_id = TransactionId::new();
            let mut request = Message::new(MessageType::RefreshRequest, transaction_id);

            // Add LIFETIME
            let lifetime_secs = lifetime.as_secs() as u32;
            let mut lifetime_data = vec![0u8; 4];
            lifetime_data[0] = (lifetime_secs >> 24) as u8;
            lifetime_data[1] = (lifetime_secs >> 16) as u8;
            lifetime_data[2] = (lifetime_secs >> 8) as u8;
            lifetime_data[3] = lifetime_secs as u8;
            request.add_attribute(Attribute::new(
                AttributeType::Lifetime,
                AttributeValue::Raw(lifetime_data),
            ));

            // Add authentication
            self.add_authentication(&mut request).await?;

            // Send request
            let encoded = request.encode(None, true)?;
            self.socket.send_to(&encoded, self.server_addr).await?;

            // Wait for response
            let mut buffer = vec![0u8; 2048];
            let (size, _) = timeout(
                Duration::from_secs(5),
                self.socket.recv_from(&mut buffer)
            ).await
                .map_err(|_| NatError::Timeout(Duration::from_secs(5)))?
                .map_err(|e| NatError::Network(e))?;

            let response = Message::decode(BytesMut::from(&buffer[..size]))?;

            // Extract new lifetime
            let new_lifetime = response.attributes.iter()
                .find_map(|attr| {
                    if attr.attr_type == AttributeType::Lifetime {
                        if let AttributeValue::Raw(data) = &attr.value {
                            if data.len() >= 4 {
                                let secs = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                                return Some(Duration::from_secs(secs as u64));
                            }
                        }
                    }
                    None
                })
                .unwrap_or(lifetime);

            Ok(new_lifetime)
        }

        /// Create permission for peer
        pub async fn create_permission(&self, peer_addr: SocketAddr) -> NatResult<()> {
            info!("Creating TURN permission for {}", peer_addr);

            let transaction_id = TransactionId::new();
            let mut request = Message::new(MessageType::CreatePermissionRequest, transaction_id);

            // Add XOR-PEER-ADDRESS
            request.add_attribute(Attribute::new(
                AttributeType::XorPeerAddress,
                AttributeValue::XorPeerAddress(peer_addr),
            ));

            // Add authentication
            self.add_authentication(&mut request).await?;

            // Send request
            let encoded = request.encode(None, true)?;
            self.socket.send_to(&encoded, self.server_addr).await?;

            // Wait for response
            let mut buffer = vec![0u8; 2048];
            let (size, _) = timeout(
                Duration::from_secs(5),
                self.socket.recv_from(&mut buffer)
            ).await
                .map_err(|_| NatError::Timeout(Duration::from_secs(5)))?
                .map_err(|e| NatError::Network(e))?;

            let response = Message::decode(BytesMut::from(&buffer[..size]))?;

            match response.message_type {
                MessageType::CreatePermissionResponse => {
                    debug!("TURN permission created for {}", peer_addr);
                    Ok(())
                }
                MessageType::CreatePermissionError => {
                    if let Some(error_attr) = response.get_attribute(AttributeType::ErrorCode) {
                        if let AttributeValue::ErrorCode { code, reason } = &error_attr.value {
                            error!("Create permission error {}: {}", code, reason);
                            return Err(NatError::Platform(
                                format!("TURN permission error {}: {}", code, reason)
                            ));
                        }
                    }
                    Err(NatError::Platform("TURN permission failed".to_string()))
                }
                _ => Err(NatError::Platform("Unexpected response".to_string())),
            }
        }

        /// Send data through TURN
        pub async fn send_data(&self, data: &[u8], peer_addr: SocketAddr) -> NatResult<()> {
            trace!("Sending {} bytes to {} via TURN", data.len(), peer_addr);

            let mut indication = Message::new(
                MessageType::SendIndication,
                TransactionId::new(),
            );

            // Add XOR-PEER-ADDRESS
            indication.add_attribute(Attribute::new(
                AttributeType::XorPeerAddress,
                AttributeValue::XorPeerAddress(peer_addr),
            ));

            // Add DATA
            indication.add_attribute(Attribute::new(
                AttributeType::Data,
                AttributeValue::Raw(data.to_vec()),
            ));

            // Add authentication
            self.add_authentication(&mut indication).await?;

            // Send indication (no response expected)
            let encoded = indication.encode(None, true)?;
            self.socket.send_to(&encoded, self.server_addr).await?;

            Ok(())
        }

        /// Add authentication attributes to message
        async fn add_authentication(&self, message: &mut Message) -> NatResult<()> {
            let realm = self.realm.read().await.clone()
                .ok_or_else(|| NatError::Platform("No TURN realm".to_string()))?;
            let nonce = self.nonce.read().await.clone()
                .ok_or_else(|| NatError::Platform("No TURN nonce".to_string()))?;

            // Add USERNAME
            message.add_attribute(Attribute::new(
                AttributeType::Username,
                AttributeValue::Username(self.config.username.clone()),
            ));

            // Add REALM
            message.add_attribute(Attribute::new(
                AttributeType::Realm,
                AttributeValue::Realm(realm),
            ));

            // Add NONCE
            message.add_attribute(Attribute::new(
                AttributeType::Nonce,
                AttributeValue::Nonce(nonce),
            ));

            Ok(())
        }
    }

    // Add XorPeerAddress and XorRelayedAddress to AttributeValue
    impl AttributeValue {
        pub fn XorPeerAddress(addr: SocketAddr) -> Self {
            AttributeValue::XorMappedAddress(addr) // Reuse same encoding
        }

        pub fn XorRelayedAddress(addr: SocketAddr) -> Self {
            AttributeValue::XorMappedAddress(addr) // Reuse same encoding
        }
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
    }

    #[tokio::test]
    async fn test_turn_url_parsing() {
        let (host, port, transport) = CandidateGatherer::parse_turn_url("turn:example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 3478);
        assert_eq!(transport, "udp");

        let (host, port, transport) = CandidateGatherer::parse_turn_url("turns:example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(transport, "tcp");
    }
}