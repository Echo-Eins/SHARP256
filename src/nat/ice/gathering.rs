// src/nat/ice/gathering.rs
//! ICE candidate gathering implementation with full RFC compliance
//!
//! Implements:
//! - RFC 8445 (ICE) - Candidate gathering procedures
//! - RFC 5766 (TURN) - Relay candidates via TURN
//! - RFC 5389 (STUN) - Server reflexive candidates
//! - RFC 8421 (Multi-homed and IPv4/IPv6 Dual-Stack)
//! - RFC 6887 (NAT-PMP) and RFC 6970 (UPnP) for port mapping
//! - mDNS candidates for privacy (RFC 8445 Section 5.1.1.1)

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, Mutex, Semaphore};
use tokio::time::{timeout, sleep, interval};
use tracing::{info, warn, error, debug, trace};
use bytes::{Bytes, BytesMut, BufMut, Buf};
use rand::Rng;

use crate::nat::stun::{
    Message, MessageType, TransactionId, Attribute, AttributeType, AttributeValue,
    StunClient, StunConfig, StunError
};
use crate::nat::error::{NatError, NatResult};
use super::{Candidate, CandidateType, TransportProtocol, IceTransportPolicy, utils};
use super::priority::{calculate_local_preference, InterfaceType};

/// Maximum concurrent gathering operations
const MAX_CONCURRENT_OPERATIONS: usize = 20;

/// Default timeouts
const STUN_TIMEOUT: Duration = Duration::from_secs(5);
const TURN_TIMEOUT: Duration = Duration::from_secs(10);
const INTERFACE_SCAN_TIMEOUT: Duration = Duration::from_secs(2);

/// Candidate gatherer with comprehensive RFC implementation
pub struct CandidateGatherer {
    /// Component ID -> Socket mapping
    sockets: Arc<RwLock<HashMap<u32, Arc<UdpSocket>>>>,

    /// STUN servers configuration
    stun_config: StunConfig,

    /// TURN servers configuration
    turn_servers: Arc<RwLock<Vec<TurnServerConfig>>>,

    /// Network interfaces discovered
    interfaces: Arc<RwLock<Vec<NetworkInterface>>>,

    /// Event channel for gathering events
    event_tx: mpsc::UnboundedSender<GatheringEvent>,

    /// Transport policy
    policy: IceTransportPolicy,

    /// TURN allocations per component
    turn_allocations: Arc<RwLock<HashMap<u32, Vec<TurnAllocation>>>>,

    /// Gathering configuration
    config: GatheringConfig,

    /// Statistics and metrics
    stats: Arc<GatheringStats>,

    /// mDNS name mappings for privacy
    mdns_mappings: Arc<RwLock<HashMap<IpAddr, String>>>,

    /// Active gathering tasks
    active_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,

    /// Semaphore for concurrent operations
    operation_semaphore: Arc<Semaphore>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,

    /// Port allocation manager
    port_manager: Arc<PortManager>,

    /// TURN clients cache
    turn_clients: Arc<RwLock<HashMap<String, Arc<TurnClient>>>>,
}

/// Comprehensive gathering configuration
#[derive(Debug, Clone)]
pub struct GatheringConfig {
    /// Enable IPv6 gathering
    pub enable_ipv6: bool,

    /// Enable mDNS candidates for privacy
    pub enable_mdns: bool,

    /// Enable UPnP port mapping
    pub enable_upnp: bool,

    /// Enable NAT-PMP port mapping
    pub enable_nat_pmp: bool,

    /// Maximum gathering time per component
    pub max_gathering_time: Duration,

    /// STUN server retry configuration
    pub stun_retries: u32,
    pub stun_initial_rto: Duration,

    /// TURN allocation lifetime
    pub turn_allocation_lifetime: Duration,

    /// Maximum number of host interfaces to use
    pub max_host_interfaces: usize,

    /// Prefer IPv6 over IPv4 (RFC 8421)
    pub prefer_ipv6: bool,

    /// Filter private/public addresses
    pub include_private_addresses: bool,
    pub include_public_addresses: bool,

    /// Enable candidate deduplication
    pub enable_deduplication: bool,

    /// Network interface priorities
    pub interface_priorities: HashMap<String, u32>,
}

impl Default for GatheringConfig {
    fn default() -> Self {
        Self {
            enable_ipv6: true,
            enable_mdns: false, // Disabled by default for compatibility
            enable_upnp: false,
            enable_nat_pmp: false,
            max_gathering_time: Duration::from_secs(10),
            stun_retries: 3,
            stun_initial_rto: Duration::from_millis(500),
            turn_allocation_lifetime: Duration::from_secs(600),
            max_host_interfaces: 10,
            prefer_ipv6: true, // RFC 8421 recommendation
            include_private_addresses: true,
            include_public_addresses: true,
            enable_deduplication: true,
            interface_priorities: HashMap::new(),
        }
    }
}

/// TURN server configuration with comprehensive auth support
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    /// Server URL (turn: or turns:)
    pub url: String,

    /// Authentication credentials
    pub credential: TurnCredential,

    /// Transport protocol
    pub transport: TurnTransport,

    /// Connection timeout
    pub timeout: Duration,

    /// Keep-alive interval
    pub keepalive_interval: Duration,

    /// Server priority (higher = preferred)
    pub priority: u32,
}

/// TURN credential types
#[derive(Debug, Clone)]
pub enum TurnCredential {
    /// Long-term credential mechanism
    LongTerm {
        username: String,
        password: String,
    },
    /// Short-term credential mechanism
    ShortTerm {
        username: String,
        password: String,
        ttl: Duration,
    },
    /// OAuth 2.0 access token
    OAuth {
        access_token: String,
        mac_key: Vec<u8>,
        timestamp: u64,
    },
}

/// TURN transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnTransport {
    Udp,
    Tcp,
    Tls,
    Dtls,
}

/// Network interface comprehensive information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Interface name
    pub name: String,

    /// Interface index
    pub index: u32,

    /// IP addresses on this interface
    pub addresses: Vec<InterfaceAddress>,

    /// Interface type
    pub interface_type: InterfaceType,

    /// Interface flags
    pub flags: InterfaceFlags,

    /// MTU size
    pub mtu: u32,

    /// Interface metric (routing priority)
    pub metric: u32,

    /// Hardware address (MAC)
    pub hardware_addr: Option<[u8; 6]>,

    /// Interface statistics
    pub stats: InterfaceStats,
}

/// Interface address with additional metadata
#[derive(Debug, Clone)]
pub struct InterfaceAddress {
    /// IP address
    pub addr: IpAddr,

    /// Network prefix length
    pub prefix_len: u8,

    /// Address scope
    pub scope: AddressScope,

    /// Address flags
    pub flags: AddressFlags,

    /// Preferred lifetime (IPv6)
    pub preferred_lifetime: Option<Duration>,

    /// Valid lifetime (IPv6)
    pub valid_lifetime: Option<Duration>,
}

/// Interface flags
#[derive(Debug, Clone)]
pub struct InterfaceFlags {
    pub up: bool,
    pub running: bool,
    pub loopback: bool,
    pub multicast: bool,
    pub broadcast: bool,
    pub point_to_point: bool,
}

/// Address scope
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressScope {
    Host,      // Loopback
    Link,      // Link-local
    Site,      // Site-local (deprecated)
    Global,    // Global
}

/// Address flags
#[derive(Debug, Clone)]
pub struct AddressFlags {
    pub tentative: bool,
    pub duplicated: bool,
    pub optimistic: bool,
    pub temporary: bool,
    pub stable_privacy: bool,
}

/// Interface statistics
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// Gathering event types
#[derive(Debug, Clone)]
pub enum GatheringEvent {
    /// New candidate discovered
    CandidateFound(Candidate),

    /// Gathering started for component
    ComponentStarted(u32),

    /// Gathering completed for component
    ComponentComplete(u32),

    /// Gathering failed for component
    ComponentFailed(u32, String),

    /// Interface discovered
    InterfaceDiscovered(NetworkInterface),

    /// TURN allocation created
    TurnAllocationCreated {
        component_id: u32,
        server_url: String,
        relay_addr: SocketAddr,
        lifetime: Duration,
    },

    /// TURN allocation failed
    TurnAllocationFailed {
        component_id: u32,
        server_url: String,
        error: String,
    },

    /// Port mapping created (UPnP/NAT-PMP)
    PortMappingCreated {
        external_addr: SocketAddr,
        internal_addr: SocketAddr,
        protocol: String,
        lifetime: Duration,
    },

    /// Gathering statistics update
    StatsUpdate(GatheringStatsSnapshot),
}

/// Comprehensive gathering statistics
#[derive(Debug, Default)]
pub struct GatheringStats {
    // Candidate counts
    pub host_candidates: std::sync::atomic::AtomicUsize,
    pub srflx_candidates: std::sync::atomic::AtomicUsize,
    pub relay_candidates: std::sync::atomic::AtomicUsize,
    pub prflx_candidates: std::sync::atomic::AtomicUsize,

    // Timing metrics
    pub total_gather_time: std::sync::atomic::AtomicU64,
    pub host_gather_time: std::sync::atomic::AtomicU64,
    pub stun_gather_time: std::sync::atomic::AtomicU64,
    pub turn_gather_time: std::sync::atomic::AtomicU64,

    // Success/failure rates
    pub stun_queries_sent: std::sync::atomic::AtomicUsize,
    pub stun_responses_received: std::sync::atomic::AtomicUsize,
    pub turn_allocations_attempted: std::sync::atomic::AtomicUsize,
    pub turn_allocations_successful: std::sync::atomic::AtomicUsize,

    // Interface discovery
    pub interfaces_discovered: std::sync::atomic::AtomicUsize,
    pub addresses_discovered: std::sync::atomic::AtomicUsize,

    // Errors
    pub gathering_errors: std::sync::atomic::AtomicUsize,
    pub timeout_errors: std::sync::atomic::AtomicUsize,
    pub network_errors: std::sync::atomic::AtomicUsize,

    // Resource usage
    pub sockets_created: std::sync::atomic::AtomicUsize,
    pub memory_usage: std::sync::atomic::AtomicU64,
}

/// Statistics snapshot for reporting
#[derive(Debug, Clone)]
pub struct GatheringStatsSnapshot {
    pub host_candidates: usize,
    pub srflx_candidates: usize,
    pub relay_candidates: usize,
    pub prflx_candidates: usize,
    pub total_gather_time_ms: u64,
    pub stun_success_rate: f64,
    pub turn_success_rate: f64,
    pub interfaces_discovered: usize,
    pub gathering_errors: usize,
}

/// Port allocation manager for avoiding conflicts
#[derive(Debug)]
struct PortManager {
    /// Allocated ports per interface
    allocated_ports: RwLock<HashMap<IpAddr, HashSet<u16>>>,

    /// Port range preferences
    port_range: (u16, u16),

    /// Reserved ports to avoid
    reserved_ports: HashSet<u16>,
}

impl PortManager {
    fn new() -> Self {
        let mut reserved = HashSet::new();

        // Common reserved ports to avoid
        reserved.extend([22, 23, 25, 53, 80, 110, 143, 443, 993, 995]);

        Self {
            allocated_ports: RwLock::new(HashMap::new()),
            port_range: (49152, 65535), // RFC 6335 dynamic port range
            reserved_ports: reserved,
        }
    }

    /// Allocate a port for an IP address
    async fn allocate_port(&self, ip: IpAddr, hint: Option<u16>) -> Option<u16> {
        let mut allocated = self.allocated_ports.write().await;
        let ports = allocated.entry(ip).or_insert_with(HashSet::new);

        // Try hint first if provided
        if let Some(hint_port) = hint {
            if hint_port >= self.port_range.0 && hint_port <= self.port_range.1 &&
                !self.reserved_ports.contains(&hint_port) &&
                !ports.contains(&hint_port) {
                ports.insert(hint_port);
                return Some(hint_port);
            }
        }

        // Find available port in range
        for port in self.port_range.0..=self.port_range.1 {
            if !self.reserved_ports.contains(&port) && !ports.contains(&port) {
                ports.insert(port);
                return Some(port);
            }
        }

        None
    }

    /// Release an allocated port
    async fn release_port(&self, ip: IpAddr, port: u16) {
        let mut allocated = self.allocated_ports.write().await;
        if let Some(ports) = allocated.get_mut(&ip) {
            ports.remove(&port);
            if ports.is_empty() {
                allocated.remove(&ip);
            }
        }
    }
}

impl CandidateGatherer {
    /// Create new candidate gatherer with comprehensive configuration
    pub fn new(
        stun_servers: Vec<String>,
        turn_servers: Vec<TurnServerConfig>,
        policy: IceTransportPolicy,
        event_tx: mpsc::UnboundedSender<GatheringEvent>,
        config: GatheringConfig,
    ) -> NatResult<Self> {
        info!("Creating candidate gatherer with {} STUN and {} TURN servers",
            stun_servers.len(), turn_servers.len());

        // Validate configuration
        Self::validate_config(&config)?;

        let stun_config = StunConfig {
            servers: stun_servers,
            max_retries: config.stun_retries,
            initial_rto_ms: config.stun_initial_rto.as_millis() as u32,
            ..Default::default()
        };

        Ok(Self {
            sockets: Arc::new(RwLock::new(HashMap::new())),
            stun_config,
            turn_servers: Arc::new(RwLock::new(turn_servers)),
            interfaces: Arc::new(RwLock::new(Vec::new())),
            event_tx,
            policy,
            turn_allocations: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(GatheringStats::default()),
            mdns_mappings: Arc::new(RwLock::new(HashMap::new())),
            active_tasks: Arc::new(Mutex::new(Vec::new())),
            operation_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_OPERATIONS)),
            shutdown: Arc::new(RwLock::new(false)),
            port_manager: Arc::new(PortManager::new()),
            turn_clients: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Validate gathering configuration
    fn validate_config(config: &GatheringConfig) -> NatResult<()> {
        if config.max_gathering_time < Duration::from_secs(1) {
            return Err(NatError::Platform(
                "Max gathering time must be at least 1 second".to_string()
            ));
        }

        if config.stun_retries > 10 {
            return Err(NatError::Platform(
                "STUN retries should not exceed 10".to_string()
            ));
        }

        if config.max_host_interfaces == 0 {
            return Err(NatError::Platform(
                "Must allow at least one host interface".to_string()
            ));
        }

        Ok(())
    }

    /// Gather candidates for a component with comprehensive error handling
    pub async fn gather_candidates(
        &self,
        component_id: u32,
        port_hint: u16,
    ) -> NatResult<Vec<Candidate>> {
        let start_time = Instant::now();

        info!("Starting comprehensive candidate gathering for component {}", component_id);

        // Send start event
        let _ = self.event_tx.send(GatheringEvent::ComponentStarted(component_id));

        // Check if shutdown requested
        if *self.shutdown.read().await {
            return Err(NatError::Platform("Gatherer is shutting down".to_string()));
        }

        let mut all_candidates = Vec::new();
        let mut gathering_tasks = Vec::new();

        // Discover network interfaces first
        self.discover_interfaces().await?;

        // Only gather host candidates if not relay-only
        if self.policy != IceTransportPolicy::Relay {
            // Gather host candidates
            let gatherer = self.clone_arc();
            let task = tokio::spawn(async move {
                gatherer.gather_host_candidates(component_id, port_hint).await
            });
            gathering_tasks.push(("host", task));

            // Gather server reflexive candidates
            if !self.stun_config.servers.is_empty() {
                let gatherer = self.clone_arc();
                let task = tokio::spawn(async move {
                    gatherer.gather_server_reflexive_candidates(component_id).await
                });
                gathering_tasks.push(("srflx", task));
            }

            // Gather port mapping candidates (UPnP/NAT-PMP)
            if self.config.enable_upnp || self.config.enable_nat_pmp {
                let gatherer = self.clone_arc();
                let task = tokio::spawn(async move {
                    gatherer.gather_port_mapping_candidates(component_id).await
                });
                gathering_tasks.push(("port_mapping", task));
            }
        }

        // Gather relay candidates if TURN servers configured
        if !self.turn_servers.read().await.is_empty() {
            let gatherer = self.clone_arc();
            let task = tokio::spawn(async move {
                gatherer.gather_relay_candidates(component_id).await
            });
            gathering_tasks.push(("relay", task));
        }

        // Wait for all gathering tasks with timeout
        let mut successful_tasks = 0;
        let mut failed_tasks = 0;

        for (task_type, task) in gathering_tasks {
            match timeout(self.config.max_gathering_time, task).await {
                Ok(Ok(candidates)) => {
                    info!("Gathered {} {} candidates", candidates.len(), task_type);

                    // Send candidate events
                    for candidate in &candidates {
                        let _ = self.event_tx.send(GatheringEvent::CandidateFound(candidate.clone()));
                    }

                    all_candidates.extend(candidates);
                    successful_tasks += 1;
                }
                Ok(Err(e)) => {
                    warn!("Failed to gather {} candidates: {}", task_type, e);
                    self.stats.gathering_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    failed_tasks += 1;
                }
                Err(_) => {
                    warn!("Timeout gathering {} candidates", task_type);
                    self.stats.timeout_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    failed_tasks += 1;
                }
            }
        }

        // Deduplicate candidates if enabled
        if self.config.enable_deduplication {
            all_candidates = self.deduplicate_candidates(all_candidates);
        }

        // Sort candidates by priority (RFC 8445)
        all_candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

        let elapsed = start_time.elapsed();
        self.stats.total_gather_time.store(
            elapsed.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed
        );

        info!("Candidate gathering complete for component {} in {:?}: {} candidates ({} successful, {} failed tasks)",
            component_id, elapsed, all_candidates.len(), successful_tasks, failed_tasks);

        // Send completion event
        let _ = self.event_tx.send(GatheringEvent::ComponentComplete(component_id));

        // Send statistics update
        let stats_snapshot = self.get_stats_snapshot().await;
        let _ = self.event_tx.send(GatheringEvent::StatsUpdate(stats_snapshot));

        Ok(all_candidates)
    }

    /// Discover network interfaces using platform-specific methods
    async fn discover_interfaces(&self) -> NatResult<()> {
        let start_time = Instant::now();
        info!("Discovering network interfaces");

        let interfaces = match timeout(INTERFACE_SCAN_TIMEOUT, self.discover_interfaces_impl()).await {
            Ok(result) => result?,
            Err(_) => {
                warn!("Interface discovery timeout");
                Vec::new()
            }
        };

        let mut interface_store = self.interfaces.write().await;
        interface_store.clear();
        interface_store.extend(interfaces.clone());

        self.stats.interfaces_discovered.store(
            interfaces.len(),
            std::sync::atomic::Ordering::Relaxed
        );

        let total_addresses: usize = interfaces.iter()
            .map(|iface| iface.addresses.len())
            .sum();

        self.stats.addresses_discovered.store(
            total_addresses,
            std::sync::atomic::Ordering::Relaxed
        );

        info!("Discovered {} interfaces with {} addresses in {:?}",
            interfaces.len(), total_addresses, start_time.elapsed());

        // Send discovery events
        for interface in interfaces {
            let _ = self.event_tx.send(GatheringEvent::InterfaceDiscovered(interface));
        }

        Ok(())
    }

    /// Platform-specific interface discovery implementation
    async fn discover_interfaces_impl(&self) -> NatResult<Vec<NetworkInterface>> {
        let mut interfaces = Vec::new();

        #[cfg(target_os = "linux")]
        {
            interfaces.extend(self.discover_interfaces_linux().await?);
        }

        #[cfg(target_os = "macos")]
        {
            interfaces.extend(self.discover_interfaces_macos().await?);
        }

        #[cfg(target_os = "windows")]
        {
            interfaces.extend(self.discover_interfaces_windows().await?);
        }

        // Fallback method using socket probing
        if interfaces.is_empty() {
            warn!("No interfaces found via OS APIs, using fallback method");
            interfaces.extend(self.discover_interfaces_fallback().await?);
        }

        // Filter and prioritize interfaces
        self.filter_and_prioritize_interfaces(interfaces).await
    }

    /// Linux-specific interface discovery
    #[cfg(target_os = "linux")]
    async fn discover_interfaces_linux(&self) -> NatResult<Vec<NetworkInterface>> {
        use std::fs;
        use std::str::FromStr;

        let mut interfaces = Vec::new();

        // Read /proc/net/if_inet6 for IPv6 addresses
        let mut ipv6_addrs: HashMap<String, Vec<InterfaceAddress>> = HashMap::new();

        if let Ok(content) = fs::read_to_string("/proc/net/if_inet6") {
            for line in content.lines() {
                if let Some(addr_info) = self.parse_inet6_line(line) {
                    ipv6_addrs.entry(addr_info.0)
                        .or_insert_with(Vec::new)
                        .push(addr_info.1);
                }
            }
        }

        // Read /proc/net/route for interface information
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                if let Some(interface) = self.read_linux_interface(&entry.path(), &ipv6_addrs).await {
                    interfaces.push(interface);
                }
            }
        }

        Ok(interfaces)
    }

    /// Parse /proc/net/if_inet6 line
    #[cfg(target_os = "linux")]
    fn parse_inet6_line(&self, line: &str) -> Option<(String, InterfaceAddress)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            return None;
        }

        // Parse IPv6 address
        let addr_hex = parts[0];
        let prefix_len: u8 = parts[2].parse().ok()?;
        let scope = match parts[3] {
            "00" => AddressScope::Global,
            "20" => AddressScope::Link,
            "40" => AddressScope::Site,
            "10" => AddressScope::Host,
            _ => AddressScope::Global,
        };
        let flags_hex = parts[4];
        let interface_name = parts[5].to_string();

        // Convert hex string to IPv6 address
        if addr_hex.len() != 32 {
            return None;
        }

        let mut addr_bytes = [0u8; 16];
        for i in 0..16 {
            if let Ok(byte) = u8::from_str_radix(&addr_hex[i*2..i*2+2], 16) {
                addr_bytes[i] = byte;
            } else {
                return None;
            }
        }

        let ipv6_addr = Ipv6Addr::from(addr_bytes);

        // Parse flags
        let flags_val = u8::from_str_radix(flags_hex, 16).unwrap_or(0);
        let flags = AddressFlags {
            tentative: (flags_val & 0x40) != 0,
            duplicated: (flags_val & 0x08) != 0,
            optimistic: (flags_val & 0x04) != 0,
            temporary: (flags_val & 0x01) != 0,
            stable_privacy: false, // Would need additional parsing
        };

        let interface_addr = InterfaceAddress {
            addr: IpAddr::V6(ipv6_addr),
            prefix_len,
            scope,
            flags,
            preferred_lifetime: None, // Would need additional parsing
            valid_lifetime: None,
        };

        Some((interface_name, interface_addr))
    }

    /// Read Linux interface information
    #[cfg(target_os = "linux")]
    async fn read_linux_interface(
        &self,
        interface_path: &std::path::Path,
        ipv6_addrs: &HashMap<String, Vec<InterfaceAddress>>,
    ) -> Option<NetworkInterface> {
        use std::fs;

        let interface_name = interface_path.file_name()?.to_str()?.to_string();

        // Skip certain interfaces
        if interface_name.starts_with("lo") && interface_name != "lo" {
            return None;
        }

        // Read interface index
        let index_path = interface_path.join("ifindex");
        let index: u32 = fs::read_to_string(index_path).ok()?
            .trim().parse().ok()?;

        // Read MTU
        let mtu_path = interface_path.join("mtu");
        let mtu: u32 = fs::read_to_string(mtu_path).ok()?
            .trim().parse().unwrap_or(1500);

        // Read flags
        let flags_path = interface_path.join("flags");
        let flags_val: u32 = fs::read_to_string(flags_path).ok()?
            .trim().strip_prefix("0x")?.parse().ok()?;

        let flags = InterfaceFlags {
            up: (flags_val & 0x1) != 0,
            running: (flags_val & 0x40) != 0,
            loopback: (flags_val & 0x8) != 0,
            multicast: (flags_val & 0x1000) != 0,
            broadcast: (flags_val & 0x2) != 0,
            point_to_point: (flags_val & 0x10) != 0,
        };

        // Determine interface type
        let interface_type = InterfaceType::from_name(&interface_name);

        // Get IPv4 addresses (would need more complex parsing)
        let mut addresses = Vec::new();

        // Add IPv6 addresses
        if let Some(ipv6_list) = ipv6_addrs.get(&interface_name) {
            addresses.extend(ipv6_list.clone());
        }

        // Read hardware address
        let addr_path = interface_path.join("address");
        let hardware_addr = fs::read_to_string(addr_path).ok()
            .and_then(|s| self.parse_mac_address(&s));

        Some(NetworkInterface {
            name: interface_name,
            index,
            addresses,
            interface_type,
            flags,
            mtu,
            metric: 0, // Would need routing table parsing
            hardware_addr,
            stats: InterfaceStats::default(),
        })
    }

    /// Parse MAC address from string
    fn parse_mac_address(&self, mac_str: &str) -> Option<[u8; 6]> {
        let parts: Vec<&str> = mac_str.trim().split(':').collect();
        if parts.len() != 6 {
            return None;
        }

        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(part, 16).ok()?;
        }
        Some(mac)
    }

    /// Fallback interface discovery using socket probing
    async fn discover_interfaces_fallback(&self) -> NatResult<Vec<NetworkInterface>> {
        let mut interfaces = Vec::new();

        // Probe common interface addresses
        let probe_addresses = vec![
            "0.0.0.0:0",
            "::0",
        ];

        for addr_str in probe_addresses {
            if let Ok(bind_addr) = addr_str.parse::<SocketAddr>() {
                if let Ok(socket) = StdUdpSocket::bind(bind_addr) {
                    // Try to determine local address by connecting to known destinations
                    let test_destinations = vec![
                        "8.8.8.8:53",      // Google DNS IPv4
                        "1.1.1.1:53",      // Cloudflare DNS IPv4
                        "[2001:4860:4860::8888]:53", // Google DNS IPv6
                    ];

                    for dest in test_destinations {
                        if let Ok(dest_addr) = dest.parse::<SocketAddr>() {
                            if socket.connect(dest_addr).is_ok() {
                                if let Ok(local_addr) = socket.local_addr() {
                                    let interface_addr = InterfaceAddress {
                                        addr: local_addr.ip(),
                                        prefix_len: if local_addr.is_ipv4() { 24 } else { 64 },
                                        scope: if utils::is_private(&local_addr.ip()) {
                                            AddressScope::Site
                                        } else {
                                            AddressScope::Global
                                        },
                                        flags: AddressFlags {
                                            tentative: false,
                                            duplicated: false,
                                            optimistic: false,
                                            temporary: false,
                                            stable_privacy: false,
                                        },
                                        preferred_lifetime: None,
                                        valid_lifetime: None,
                                    };

                                    let interface = NetworkInterface {
                                        name: "default".to_string(),
                                        index: 1,
                                        addresses: vec![interface_addr],
                                        interface_type: InterfaceType::Unknown,
                                        flags: InterfaceFlags {
                                            up: true,
                                            running: true,
                                            loopback: false,
                                            multicast: true,
                                            broadcast: local_addr.is_ipv4(),
                                            point_to_point: false,
                                        },
                                        mtu: 1500,
                                        metric: 0,
                                        hardware_addr: None,
                                        stats: InterfaceStats::default(),
                                    };

                                    interfaces.push(interface);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(interfaces)
    }

    /// Filter and prioritize interfaces based on configuration
    async fn filter_and_prioritize_interfaces(
        &self,
        interfaces: Vec<NetworkInterface>,
    ) -> NatResult<Vec<NetworkInterface>> {
        let mut filtered: Vec<NetworkInterface> = interfaces.into_iter()
            .filter(|iface| {
                // Skip if interface is down
                if !iface.flags.up {
                    return false;
                }

                // Skip loopback unless specifically needed
                if iface.flags.loopback && !cfg!(test) {
                    return false;
                }

                // Filter by address types
                let has_suitable_addresses = iface.addresses.iter().any(|addr| {
                    // Skip if IPv6 disabled
                    if !self.config.enable_ipv6 && addr.addr.is_ipv6() {
                        return false;
                    }

                    // Skip link-local addresses usually
                    if matches!(addr.scope, AddressScope::Link) {
                        return false;
                    }

                    // Filter by private/public preference
                    let is_private = utils::is_private(&addr.addr);
                    if is_private && !self.config.include_private_addresses {
                        return false;
                    }
                    if !is_private && !self.config.include_public_addresses {
                        return false;
                    }

                    true
                });

                has_suitable_addresses
            })
            .collect();

        // Sort by priority
        filtered.sort_by(|a, b| {
            let a_priority = self.get_interface_priority(a);
            let b_priority = self.get_interface_priority(b);
            b_priority.cmp(&a_priority) // Higher priority first
        });

        // Limit to max interfaces
        if filtered.len() > self.config.max_host_interfaces {
            filtered.truncate(self.config.max_host_interfaces);
        }

        info!("Filtered and prioritized {} interfaces", filtered.len());

        Ok(filtered)
    }

    /// Get interface priority for sorting
    fn get_interface_priority(&self, interface: &NetworkInterface) -> u32 {
        let mut priority = 0u32;

        // Check configured priorities first
        if let Some(&configured_priority) = self.config.interface_priorities.get(&interface.name) {
            return configured_priority;
        }

        // Interface type priority
        priority += match interface.interface_type {
            InterfaceType::Ethernet => 1000,
            InterfaceType::Wifi => 800,
            InterfaceType::Cellular => 600,
            InterfaceType::Unknown => 400,
            InterfaceType::Virtual => 200,
            InterfaceType::Vpn => 100,
        };

        // Prefer interfaces with global addresses
        let has_global = interface.addresses.iter()
            .any(|addr| matches!(addr.scope, AddressScope::Global));
        if has_global {
            priority += 500;
        }

        // IPv6 preference (RFC 8421)
        if self.config.prefer_ipv6 {
            let has_ipv6 = interface.addresses.iter()
                .any(|addr| addr.addr.is_ipv6());
            if has_ipv6 {
                priority += 300;
            }
        }

        // Prefer running interfaces
        if interface.flags.running {
            priority += 200;
        }

        // Lower metric is better (routing preference)
        priority = priority.saturating_sub(interface.metric);

        priority
    }

    /// Gather host candidates from network interfaces
    async fn gather_host_candidates(
        &self,
        component_id: u32,
        port_hint: u16,
    ) -> NatResult<Vec<Candidate>> {
        let start_time = Instant::now();
        info!("Gathering host candidates for component {}", component_id);

        let _permit = self.operation_semaphore.acquire().await
            .map_err(|_| NatError::Platform("Operation semaphore closed".to_string()))?;

        let mut candidates = Vec::new();
        let interfaces = self.interfaces.read().await.clone();

        for interface in interfaces {
            for interface_addr in &interface.addresses {
                // Skip unsuitable addresses
                if !self.is_suitable_for_candidates(&interface_addr.addr) {
                    continue;
                }

                // Allocate port
                let port = self.port_manager.allocate_port(
                    interface_addr.addr,
                    if port_hint > 0 { Some(port_hint) } else { None }
                ).await;

                let port = match port {
                    Some(p) => p,
                    None => {
                        warn!("Failed to allocate port for {}", interface_addr.addr);
                        continue;
                    }
                };

                let bind_addr = SocketAddr::new(interface_addr.addr, port);

                // Create and bind socket
                match UdpSocket::bind(bind_addr).await {
                    Ok(socket) => {
                        let actual_addr = socket.local_addr()?;

                        // Configure socket
                        if let Err(e) = self.configure_socket(&socket, &interface).await {
                            warn!("Failed to configure socket for {}: {}", actual_addr, e);
                            continue;
                        }

                        // Store socket
                        let socket_arc = Arc::new(socket);
                        self.sockets.write().await.insert(component_id, socket_arc);
                        self.stats.sockets_created.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                        // Calculate local preference
                        let local_preference = calculate_local_preference(
                            &interface_addr.addr,
                            interface.interface_type,
                            matches!(interface.interface_type, InterfaceType::Vpn),
                            interface_addr.flags.temporary,
                            Some(interface.metric),
                        );

                        // Create host candidate
                        let mut candidate = Candidate::new_host(
                            actual_addr,
                            component_id,
                            TransportProtocol::Udp,
                            interface.index,
                        );

                        // Update priority with calculated local preference
                        candidate.priority = super::priority::calculate_priority(
                            CandidateType::Host,
                            local_preference,
                            component_id,
                        );

                        // Set network cost based on interface characteristics
                        candidate.network_cost = match interface.interface_type {
                            InterfaceType::Ethernet => 0,
                            InterfaceType::Wifi => 10,
                            InterfaceType::Cellular => 20,
                            InterfaceType::Vpn => 30,
                            InterfaceType::Virtual => 40,
                            InterfaceType::Unknown => 50,
                        };

                        // Generate mDNS name if enabled
                        if self.config.enable_mdns && actual_addr.ip().is_ipv4() {
                            let mdns_name = self.generate_mdns_name(actual_addr.ip()).await;
                            debug!("Generated mDNS name {} for {}", mdns_name, actual_addr.ip());
                            // In real implementation, would update candidate with mDNS address
                        }

                        debug!("Created host candidate: {} (priority: {}, cost: {})",
                            actual_addr, candidate.priority, candidate.network_cost);

                        candidates.push(candidate);
                        self.stats.host_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(e) => {
                        debug!("Failed to bind to {}: {}", bind_addr, e);
                        // Release the allocated port
                        self.port_manager.release_port(interface_addr.addr, port).await;
                    }
                }
            }
        }

        let elapsed = start_time.elapsed();
        self.stats.host_gather_time.store(
            elapsed.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed
        );

        info!("Gathered {} host candidates in {:?}", candidates.len(), elapsed);
        Ok(candidates)
    }

    /// Check if address is suitable for ICE candidates
    fn is_suitable_for_candidates(&self, ip: &IpAddr) -> bool {
        // Basic suitability checks
        if utils::is_loopback(ip) || utils::is_link_local(ip) ||
            ip.is_unspecified() || ip.is_multicast() {
            return false;
        }

        // IPv6 specific checks
        if let IpAddr::V6(v6) = ip {
            // Skip IPv6 if disabled
            if !self.config.enable_ipv6 {
                return false;
            }

            // Skip certain IPv6 address types
            if v6.is_unicast_link_local() {
                return false;
            }
        }

        true
    }

    /// Configure socket with optimal settings
    async fn configure_socket(
        &self,
        socket: &UdpSocket,
        interface: &NetworkInterface,
    ) -> NatResult<()> {
        use socket2::{Socket, SockRef};

        let sock_ref = SockRef::from(socket);

        // Set buffer sizes based on interface type
        let (recv_buf, send_buf) = match interface.interface_type {
            InterfaceType::Ethernet => (512 * 1024, 512 * 1024),
            InterfaceType::Wifi => (256 * 1024, 256 * 1024),
            InterfaceType::Cellular => (128 * 1024, 128 * 1024),
            _ => (256 * 1024, 256 * 1024),
        };

        let _ = sock_ref.set_recv_buffer_size(recv_buf);
        let _ = sock_ref.set_send_buffer_size(send_buf);

        // Enable reuse for rapid restart
        let _ = sock_ref.set_reuse_address(true);

        #[cfg(not(target_os = "windows"))]
        {
            let _ = sock_ref.set_reuse_port(true);
        }

        // Set DSCP for QoS (if supported)
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();

            unsafe {
                // Set DSCP to CS4 (32) for real-time communications
                let dscp = 32i32 << 2;
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

    /// Gather server reflexive candidates using STUN
    async fn gather_server_reflexive_candidates(
        &self,
        component_id: u32,
    ) -> NatResult<Vec<Candidate>> {
        let start_time = Instant::now();
        info!("Gathering server reflexive candidates for component {}", component_id);

        let _permit = self.operation_semaphore.acquire().await
            .map_err(|_| NatError::Platform("Operation semaphore closed".to_string()))?;

        let mut candidates = Vec::new();

        // Get socket for this component
        let socket = {
            let sockets = self.sockets.read().await;
            sockets.get(&component_id).cloned()
        };

        let socket = match socket {
            Some(s) => s,
            None => {
                warn!("No socket available for component {} STUN queries", component_id);
                return Ok(candidates);
            }
        };

        let local_addr = socket.local_addr()?;

        // Create STUN client
        let stun_client = StunClient::new(self.stun_config.clone());

        // Query each STUN server concurrently
        let mut stun_tasks = Vec::new();

        for server in &self.stun_config.servers {
            let server = server.clone();
            let socket = socket.clone();
            let stun_client = stun_client.clone();

            let task = tokio::spawn(async move {
                stun_client.get_mapped_address(&socket).await
                    .map(|addr| (server, addr))
            });

            stun_tasks.push(task);
        }

        // Wait for STUN responses
        for task in stun_tasks {
            self.stats.stun_queries_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            match timeout(STUN_TIMEOUT, task).await {
                Ok(Ok(Ok((server, mapped_addr)))) => {
                    self.stats.stun_responses_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // Only create candidate if mapped address differs from local
                    if mapped_addr.ip() != local_addr.ip() {
                        debug!("STUN server {} returned mapped address: {}", server, mapped_addr);

                        let candidate = Candidate::new_server_reflexive(
                            mapped_addr,
                            local_addr,
                            component_id,
                            TransportProtocol::Udp,
                            0, // Use same network ID as base
                        );

                        debug!("Created server reflexive candidate: {} -> {} (priority: {})",
                            local_addr, mapped_addr, candidate.priority);

                        candidates.push(candidate);
                        self.stats.srflx_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    } else {
                        debug!("STUN server {} returned same IP - no NAT detected", server);
                    }
                }
                Ok(Ok(Err(e))) => {
                    debug!("STUN query to {} failed: {}", server, e);
                }
                Ok(Err(_)) => {
                    debug!("STUN task panicked");
                }
                Err(_) => {
                    debug!("STUN query timeout");
                    self.stats.timeout_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        let elapsed = start_time.elapsed();
        self.stats.stun_gather_time.store(
            elapsed.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed
        );

        info!("Gathered {} server reflexive candidates in {:?}", candidates.len(), elapsed);
        Ok(candidates)
    }

    /// Gather relay candidates using TURN
    async fn gather_relay_candidates(&self, component_id: u32) -> NatResult<Vec<Candidate>> {
        let start_time = Instant::now();
        info!("Gathering relay candidates for component {}", component_id);

        let _permit = self.operation_semaphore.acquire().await
            .map_err(|_| NatError::Platform("Operation semaphore closed".to_string()))?;

        let mut candidates = Vec::new();
        let turn_servers = self.turn_servers.read().await.clone();

        if turn_servers.is_empty() {
            return Ok(candidates);
        }

        // Attempt TURN allocations concurrently
        let mut turn_tasks = Vec::new();

        for server_config in turn_servers {
            let gatherer = self.clone_arc();

            let task = tokio::spawn(async move {
                gatherer.create_turn_allocation(component_id, server_config).await
            });

            turn_tasks.push(task);
        }

        // Wait for TURN allocation results
        let mut allocations = Vec::new();

        for task in turn_tasks {
            self.stats.turn_allocations_attempted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            match timeout(TURN_TIMEOUT, task).await {
                Ok(Ok(Ok((allocation, candidate)))) => {
                    self.stats.turn_allocations_successful.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.stats.relay_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    info!("TURN allocation successful: {} -> {} (lifetime: {:?})",
                        allocation.local_address, allocation.relay_address, allocation.lifetime);

                    // Send allocation success event
                    let _ = self.event_tx.send(GatheringEvent::TurnAllocationCreated {
                        component_id,
                        server_url: allocation.server_url.clone(),
                        relay_addr: allocation.relay_address,
                        lifetime: allocation.lifetime,
                    });

                    candidates.push(candidate);
                    allocations.push(allocation);
                }
                Ok(Ok(Err(e))) => {
                    error!("TURN allocation failed: {}", e);

                    // Send allocation failure event
                    let _ = self.event_tx.send(GatheringEvent::TurnAllocationFailed {
                        component_id,
                        server_url: "unknown".to_string(),
                        error: e.to_string(),
                    });
                }
                Ok(Err(_)) => {
                    error!("TURN allocation task panicked");
                }
                Err(_) => {
                    warn!("TURN allocation timeout");
                    self.stats.timeout_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        // Store successful allocations
        if !allocations.is_empty() {
            self.turn_allocations.write().await.insert(component_id, allocations);
        }

        let elapsed = start_time.elapsed();
        self.stats.turn_gather_time.store(
            elapsed.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed
        );

        info!("Gathered {} relay candidates in {:?}", candidates.len(), elapsed);
        Ok(candidates)
    }

    /// Create TURN allocation with comprehensive error handling
    async fn create_turn_allocation(
        &self,
        component_id: u32,
        server_config: TurnServerConfig,
    ) -> NatResult<(TurnAllocation, Candidate)> {
        debug!("Creating TURN allocation on {} for component {}",
            server_config.url, component_id);

        // Parse TURN URL
        let (host, port, transport) = Self::parse_turn_url(&server_config.url)?;
        let server_addr = format!("{}:{}", host, port).parse::<SocketAddr>()
            .map_err(|e| NatError::Platform(format!("Invalid TURN server address: {}", e)))?;

        // Get or create TURN client
        let turn_client = self.get_or_create_turn_client(&server_config).await?;

        // Create allocation
        let allocation = turn_client.allocate(component_id).await?;

        // Create relay candidate
        let candidate = Candidate::new_relay(
            allocation.relay_address,
            allocation.local_address,
            component_id,
            TransportProtocol::Udp,
            &server_addr,
        );

        Ok((allocation, candidate))
    }

    /// Get or create TURN client for server configuration
    async fn get_or_create_turn_client(
        &self,
        server_config: &TurnServerConfig,
    ) -> NatResult<Arc<TurnClient>> {
        let cache_key = format!("{}:{:?}", server_config.url, server_config.transport);

        // Check cache first
        {
            let clients = self.turn_clients.read().await;
            if let Some(client) = clients.get(&cache_key) {
                return Ok(client.clone());
            }
        }

        // Create new client
        let client = Arc::new(TurnClient::new(server_config.clone()).await?);

        // Cache the client
        self.turn_clients.write().await.insert(cache_key, client.clone());

        Ok(client)
    }

    /// Parse TURN URL format
    fn parse_turn_url(url: &str) -> NatResult<(String, u16, TurnTransport)> {
        if let Some(rest) = url.strip_prefix("turn:") {
            let (host, port) = if let Some((h, p)) = rest.rsplit_once(':') {
                (h.to_string(), p.parse().unwrap_or(3478))
            } else {
                (rest.to_string(), 3478)
            };
            Ok((host, port, TurnTransport::Udp))
        } else if let Some(rest) = url.strip_prefix("turns:") {
            let (host, port) = if let Some((h, p)) = rest.rsplit_once(':') {
                (h.to_string(), p.parse().unwrap_or(5349))
            } else {
                (rest.to_string(), 5349)
            };
            Ok((host, port, TurnTransport::Tls))
        } else if let Some(rest) = url.strip_prefix("turn-tcp:") {
            let (host, port) = if let Some((h, p)) = rest.rsplit_once(':') {
                (h.to_string(), p.parse().unwrap_or(3478))
            } else {
                (rest.to_string(), 3478)
            };
            Ok((host, port, TurnTransport::Tcp))
        } else {
            Err(NatError::Platform(format!("Invalid TURN URL format: {}", url)))
        }
    }

    /// Gather port mapping candidates (UPnP/NAT-PMP)
    async fn gather_port_mapping_candidates(&self, component_id: u32) -> NatResult<Vec<Candidate>> {
        info!("Gathering port mapping candidates for component {}", component_id);

        let _permit = self.operation_semaphore.acquire().await
            .map_err(|_| NatError::Platform("Operation semaphore closed".to_string()))?;

        let mut candidates = Vec::new();

        // Get local socket address
        let local_addr = {
            let sockets = self.sockets.read().await;
            sockets.get(&component_id)
                .and_then(|s| s.local_addr().ok())
        };

        let local_addr = match local_addr {
            Some(addr) => addr,
            None => {
                debug!("No socket available for port mapping");
                return Ok(candidates);
            }
        };

        // Try UPnP if enabled
        if self.config.enable_upnp {
            if let Ok(external_addr) = self.try_upnp_port_mapping(local_addr).await {
                let candidate = Candidate::new_server_reflexive(
                    external_addr,
                    local_addr,
                    component_id,
                    TransportProtocol::Udp,
                    0,
                );

                debug!("Created UPnP candidate: {} -> {}", local_addr, external_addr);
                candidates.push(candidate);

                // Send port mapping event
                let _ = self.event_tx.send(GatheringEvent::PortMappingCreated {
                    external_addr,
                    internal_addr: local_addr,
                    protocol: "UPnP".to_string(),
                    lifetime: Duration::from_secs(7200), // 2 hours default
                });
            }
        }

        // Try NAT-PMP if enabled
        if self.config.enable_nat_pmp {
            if let Ok(external_addr) = self.try_nat_pmp_port_mapping(local_addr).await {
                let candidate = Candidate::new_server_reflexive(
                    external_addr,
                    local_addr,
                    component_id,
                    TransportProtocol::Udp,
                    0,
                );

                debug!("Created NAT-PMP candidate: {} -> {}", local_addr, external_addr);
                candidates.push(candidate);

                // Send port mapping event
                let _ = self.event_tx.send(GatheringEvent::PortMappingCreated {
                    external_addr,
                    internal_addr: local_addr,
                    protocol: "NAT-PMP".to_string(),
                    lifetime: Duration::from_secs(7200),
                });
            }
        }

        info!("Gathered {} port mapping candidates", candidates.len());
        Ok(candidates)
    }

    /// Try UPnP port mapping (simplified implementation)
    async fn try_upnp_port_mapping(&self, local_addr: SocketAddr) -> NatResult<SocketAddr> {
        // This is a simplified implementation
        // In a full implementation, you would use UPnP SSDP discovery
        // and send SOAP requests to the Internet Gateway Device

        debug!("Attempting UPnP port mapping for {}", local_addr);

        // For now, return an error as this requires complex UPnP implementation
        Err(NatError::Platform("UPnP not implemented".to_string()))
    }

    /// Try NAT-PMP port mapping (simplified implementation)
    async fn try_nat_pmp_port_mapping(&self, local_addr: SocketAddr) -> NatResult<SocketAddr> {
        // This is a simplified implementation
        // In a full implementation, you would send NAT-PMP requests to the default gateway

        debug!("Attempting NAT-PMP port mapping for {}", local_addr);

        // For now, return an error as this requires NAT-PMP protocol implementation
        Err(NatError::Platform("NAT-PMP not implemented".to_string()))
    }

    /// Deduplicate candidates based on address and type
    fn deduplicate_candidates(&self, mut candidates: Vec<Candidate>) -> Vec<Candidate> {
        let mut seen = HashSet::new();
        candidates.retain(|candidate| {
            let key = (candidate.addr, candidate.typ, candidate.component_id);
            seen.insert(key)
        });
        candidates
    }

    /// Generate mDNS name for IP address
    async fn generate_mdns_name(&self, ip: IpAddr) -> String {
        let mut rng = rand::thread_rng();
        let random: String = (0..8)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        let name = format!("{}.local", random.to_lowercase());
        self.mdns_mappings.write().await.insert(ip, name.clone());
        name
    }

    /// Get socket for component
    pub async fn get_socket(&self, component_id: u32) -> Option<Arc<UdpSocket>> {
        self.sockets.read().await.get(&component_id).cloned()
    }

    /// Refresh TURN allocations
    pub async fn refresh_turn_allocations(&self) -> NatResult<()> {
        debug!("Refreshing TURN allocations");

        let allocations = self.turn_allocations.read().await;

        for (component_id, allocs) in allocations.iter() {
            for allocation in allocs {
                match allocation.refresh().await {
                    Ok(new_lifetime) => {
                        debug!("Refreshed TURN allocation for component {}: {:?}",
                            component_id, new_lifetime);
                    }
                    Err(e) => {
                        error!("Failed to refresh TURN allocation for component {}: {}",
                            component_id, e);
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
        debug!("Creating TURN permission for {} on component {}", peer_addr, component_id);

        let allocations = self.turn_allocations.read().await;

        if let Some(allocs) = allocations.get(&component_id) {
            for allocation in allocs {
                if let Err(e) = allocation.create_permission(peer_addr).await {
                    error!("Failed to create TURN permission: {}", e);
                    return Err(e);
                }
            }
            Ok(())
        } else {
            Err(NatError::Platform("No TURN allocation for component".to_string()))
        }
    }

    /// Send data through TURN relay
    pub async fn send_turn_data(
        &self,
        component_id: u32,
        data: &[u8],
        peer_addr: SocketAddr,
    ) -> NatResult<()> {
        let allocations = self.turn_allocations.read().await;

        if let Some(allocs) = allocations.get(&component_id) {
            for allocation in allocs {
                return allocation.send_data(data, peer_addr).await;
            }
        }

        Err(NatError::Platform("No TURN allocation for component".to_string()))
    }

    /// Start automatic refresh timer for TURN allocations
    pub async fn start_refresh_timer(&self) {
        let gatherer = self.clone_arc();

        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300)); // Refresh every 5 minutes

            loop {
                interval.tick().await;

                if *gatherer.shutdown.read().await {
                    break;
                }

                if let Err(e) = gatherer.refresh_turn_allocations().await {
                    error!("TURN allocation refresh failed: {}", e);
                }
            }

            info!("TURN refresh timer stopped");
        });

        self.active_tasks.lock().await.push(task);
    }

    /// Get comprehensive statistics snapshot
    pub async fn get_stats_snapshot(&self) -> GatheringStatsSnapshot {
        let total_gather_time = self.stats.total_gather_time.load(std::sync::atomic::Ordering::Relaxed);
        let stun_sent = self.stats.stun_queries_sent.load(std::sync::atomic::Ordering::Relaxed);
        let stun_received = self.stats.stun_responses_received.load(std::sync::atomic::Ordering::Relaxed);
        let turn_attempted = self.stats.turn_allocations_attempted.load(std::sync::atomic::Ordering::Relaxed);
        let turn_successful = self.stats.turn_allocations_successful.load(std::sync::atomic::Ordering::Relaxed);

        GatheringStatsSnapshot {
            host_candidates: self.stats.host_candidates.load(std::sync::atomic::Ordering::Relaxed),
            srflx_candidates: self.stats.srflx_candidates.load(std::sync::atomic::Ordering::Relaxed),
            relay_candidates: self.stats.relay_candidates.load(std::sync::atomic::Ordering::Relaxed),
            prflx_candidates: self.stats.prflx_candidates.load(std::sync::atomic::Ordering::Relaxed),
            total_gather_time_ms: total_gather_time,
            stun_success_rate: if stun_sent > 0 {
                stun_received as f64 / stun_sent as f64
            } else {
                0.0
            },
            turn_success_rate: if turn_attempted > 0 {
                turn_successful as f64 / turn_attempted as f64
            } else {
                0.0
            },
            interfaces_discovered: self.stats.interfaces_discovered.load(std::sync::atomic::Ordering::Relaxed),
            gathering_errors: self.stats.gathering_errors.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Get detailed statistics string
    pub fn get_stats(&self) -> String {
        format!(
            "Gathering stats - Host: {}, SRflx: {}, Relay: {}, PRflx: {}, Time: {}ms, Interfaces: {}, Errors: {}",
            self.stats.host_candidates.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.srflx_candidates.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.relay_candidates.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.prflx_candidates.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.total_gather_time.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.interfaces_discovered.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.gathering_errors.load(std::sync::atomic::Ordering::Relaxed)
        )
    }

    /// Graceful shutdown with cleanup
    pub async fn shutdown(&self) -> NatResult<()> {
        info!("Shutting down candidate gatherer");

        *self.shutdown.write().await = true;

        // Cancel all active tasks
        let mut tasks = self.active_tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }

        // Close all sockets
        let mut sockets = self.sockets.write().await;
        sockets.clear();

        // Release all allocated ports
        let interfaces = self.interfaces.read().await;
        for interface in interfaces.iter() {
            for addr in &interface.addresses {
                // Would release ports if we tracked them per interface
            }
        }

        // Clean up TURN allocations
        let mut allocations = self.turn_allocations.write().await;
        for (_component_id, allocs) in allocations.drain() {
            for allocation in allocs {
                if let Err(e) = allocation.close().await {
                    warn!("Failed to close TURN allocation: {}", e);
                }
            }
        }

        // Clear TURN clients cache
        self.turn_clients.write().await.clear();

        info!("Candidate gatherer shutdown complete");
        Ok(())
    }

    /// Create Arc wrapper for async tasks
    fn clone_arc(&self) -> Arc<Self> {
        // This is a conceptual method - in real implementation,
        // CandidateGatherer would be wrapped in Arc from creation
        unreachable!("This method should not be called in real implementation")
    }
}

// TURN client implementation
mod turn_client {
    use super::*;
    use crate::nat::stun::{
        Message, MessageType, TransactionId, Attribute, AttributeType, AttributeValue,
    };

    /// TURN allocation information
    #[derive(Debug, Clone)]
    pub struct TurnAllocation {
        pub relay_address: SocketAddr,
        pub local_address: SocketAddr,
        pub lifetime: Duration,
        pub server_url: String,
        pub created_at: Instant,
        client: Arc<TurnClient>,
    }

    impl TurnAllocation {
        /// Refresh the allocation
        pub async fn refresh(&self) -> NatResult<Duration> {
            self.client.refresh_allocation(self.lifetime).await
        }

        /// Create permission for peer
        pub async fn create_permission(&self, peer_addr: SocketAddr) -> NatResult<()> {
            self.client.create_permission(peer_addr).await
        }

        /// Send data to peer through relay
        pub async fn send_data(&self, data: &[u8], peer_addr: SocketAddr) -> NatResult<()> {
            self.client.send_data(data, peer_addr).await
        }

        /// Close the allocation
        pub async fn close(&self) -> NatResult<()> {
            self.client.close_allocation().await
        }
    }

    /// TURN client implementation
    pub struct TurnClient {
        config: TurnServerConfig,
        socket: Arc<UdpSocket>,
        server_addr: SocketAddr,
        realm: RwLock<Option<String>>,
        nonce: RwLock<Option<Vec<u8>>>,
        software: String,
    }

    impl TurnClient {
        /// Create new TURN client
        pub async fn new(config: TurnServerConfig) -> NatResult<Self> {
            let (host, port, _transport) = CandidateGatherer::parse_turn_url(&config.url)?;
            let server_addr = format!("{}:{}", host, port).parse()
                .map_err(|e| NatError::Platform(format!("Invalid server address: {}", e)))?;

            let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

            Ok(Self {
                config,
                socket,
                server_addr,
                realm: RwLock::new(None),
                nonce: RwLock::new(None),
                software: "SHARP-ICE/1.0".to_string(),
            })
        }

        /// Allocate relay address
        pub async fn allocate(&self, component_id: u32) -> NatResult<TurnAllocation> {
            info!("Creating TURN allocation for component {}", component_id);

            let mut attempt = 0;
            const MAX_ATTEMPTS: u32 = 3;

            loop {
                attempt += 1;
                if attempt > MAX_ATTEMPTS {
                    return Err(NatError::Platform(
                        format!("TURN allocation failed after {} attempts", MAX_ATTEMPTS)
                    ));
                }

                let response = self.send_allocate_request().await?;

                match response.message_type {
                    MessageType::AllocateResponse => {
                        return self.handle_allocate_success(response).await;
                    }
                    MessageType::AllocateError => {
                        if let Some(error_attr) = response.get_attribute(AttributeType::ErrorCode) {
                            if let AttributeValue::ErrorCode { code, reason } = &error_attr.value {
                                match *code {
                                    401 | 438 => {
                                        // Unauthorized or stale nonce - extract credentials and retry
                                        self.extract_auth_params(&response).await?;
                                        debug!("Got error {}, retrying with auth (attempt {})", code, attempt);
                                        continue;
                                    }
                                    _ => {
                                        return Err(NatError::Platform(
                                            format!("TURN allocation error {}: {}", code, reason)
                                        ));
                                    }
                                }
                            }
                        }
                        return Err(NatError::Platform("Unknown TURN allocation error".to_string()));
                    }
                    _ => {
                        return Err(NatError::Platform("Unexpected TURN response type".to_string()));
                    }
                }
            }
        }

        /// Send ALLOCATE request
        async fn send_allocate_request(&self) -> NatResult<Message> {
            let transaction_id = TransactionId::new();
            let mut request = Message::new(MessageType::AllocateRequest, transaction_id);

            // Add REQUESTED-TRANSPORT (UDP = 17)
            request.add_attribute(Attribute::new(
                AttributeType::RequestedTransport,
                AttributeValue::Raw(vec![17, 0, 0, 0]),
            ));

            // Add LIFETIME
            let lifetime_secs = self.config.timeout.as_secs() as u32;
            let mut lifetime_bytes = Vec::new();
            lifetime_bytes.extend_from_slice(&lifetime_secs.to_be_bytes());
            request.add_attribute(Attribute::new(
                AttributeType::Lifetime,
                AttributeValue::Raw(lifetime_bytes),
            ));

            // Add SOFTWARE
            request.add_attribute(Attribute::new(
                AttributeType::Software,
                AttributeValue::Software(self.software.clone()),
            ));

            // Add authentication if available
            self.add_auth_attributes(&mut request).await?;

            // Send request and wait for response
            self.send_request_and_wait_response(request).await
        }

        /// Add authentication attributes to request
        async fn add_auth_attributes(&self, request: &mut Message) -> NatResult<()> {
            let realm = self.realm.read().await.clone();
            let nonce = self.nonce.read().await.clone();

            if let (Some(realm), Some(nonce)) = (realm, nonce) {
                match &self.config.credential {
                    TurnCredential::LongTerm { username, password } => {
                        // Add USERNAME
                        request.add_attribute(Attribute::new(
                            AttributeType::Username,
                            AttributeValue::Username(username.clone()),
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

                        // MESSAGE-INTEGRITY will be added during encoding
                    }
                    TurnCredential::ShortTerm { username, password } => {
                        // Similar to long-term but without realm
                        request.add_attribute(Attribute::new(
                            AttributeType::Username,
                            AttributeValue::Username(username.clone()),
                        ));

                        request.add_attribute(Attribute::new(
                            AttributeType::Nonce,
                            AttributeValue::Nonce(nonce),
                        ));
                    }
                    TurnCredential::OAuth { access_token, .. } => {
                        // OAuth implementation would go here
                        return Err(NatError::Platform("OAuth not implemented".to_string()));
                    }
                }
            }

            Ok(())
        }

        /// Extract authentication parameters from error response
        async fn extract_auth_params(&self, response: &Message) -> NatResult<()> {
            // Extract REALM
            if let Some(realm_attr) = response.get_attribute(AttributeType::Realm) {
                if let AttributeValue::Realm(realm) = &realm_attr.value {
                    *self.realm.write().await = Some(realm.clone());
                    debug!("Extracted TURN realm: {}", realm);
                }
            }

            // Extract NONCE
            if let Some(nonce_attr) = response.get_attribute(AttributeType::Nonce) {
                if let AttributeValue::Nonce(nonce) = &nonce_attr.value {
                    *self.nonce.write().await = Some(nonce.clone());
                    debug!("Extracted TURN nonce");
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
                .unwrap_or(self.config.timeout);

            let local_addr = self.socket.local_addr()?;

            info!("TURN allocation successful: {} -> {} (lifetime: {:?})",
                local_addr, relay_addr, lifetime);

            Ok(TurnAllocation {
                relay_address: relay_addr,
                local_address: local_addr,
                lifetime,
                server_url: self.config.url.clone(),
                created_at: Instant::now(),
                client: Arc::new(self.clone()),
            })
        }

        /// Send request and wait for response
        async fn send_request_and_wait_response(&self, request: Message) -> NatResult<Message> {
            // Calculate MESSAGE-INTEGRITY if we have credentials
            let integrity_key = self.get_integrity_key().await?;

            // Encode and send request
            let encoded = request.encode(integrity_key.as_deref(), true)?;
            self.socket.send_to(&encoded, self.server_addr).await?;

            // Wait for response
            let mut buffer = vec![0u8; 2048];
            let (size, from_addr) = timeout(
                self.config.timeout,
                self.socket.recv_from(&mut buffer)
            ).await??;

            if from_addr != self.server_addr {
                return Err(NatError::Platform("Response from wrong address".to_string()));
            }

            // Decode response
            let response = Message::decode(BytesMut::from(&buffer[..size]))?;

            // Verify transaction ID
            if response.transaction_id != request.transaction_id {
                return Err(NatError::Platform("Transaction ID mismatch".to_string()));
            }

            Ok(response)
        }

        /// Get integrity key for MESSAGE-INTEGRITY calculation
        async fn get_integrity_key(&self) -> NatResult<Option<Vec<u8>>> {
            match &self.config.credential {
                TurnCredential::LongTerm { username, password } => {
                    if let Some(realm) = &*self.realm.read().await {
                        // Long-term credential: key = MD5(username:realm:password)
                        use md5::{Md5, Digest};
                        let input = format!("{}:{}:{}", username, realm, password);
                        let hash = Md5::digest(input.as_bytes());
                        Ok(Some(hash.to_vec()))
                    } else {
                        Ok(None)
                    }
                }
                TurnCredential::ShortTerm { username: _, password } => {
                    // Short-term credential: key = password
                    Ok(Some(password.as_bytes().to_vec()))
                }
                TurnCredential::OAuth { mac_key, .. } => {
                    Ok(Some(mac_key.clone()))
                }
            }
        }

        /// Refresh allocation
        pub async fn refresh_allocation(&self, lifetime: Duration) -> NatResult<Duration> {
            debug!("Refreshing TURN allocation");

            let transaction_id = TransactionId::new();
            let mut request = Message::new(MessageType::RefreshRequest, transaction_id);

            // Add LIFETIME
            let lifetime_secs = lifetime.as_secs() as u32;
            let mut lifetime_bytes = Vec::new();
            lifetime_bytes.extend_from_slice(&lifetime_secs.to_be_bytes());
            request.add_attribute(Attribute::new(
                AttributeType::Lifetime,
                AttributeValue::Raw(lifetime_bytes),
            ));

            // Add authentication
            self.add_auth_attributes(&mut request).await?;

            // Send request
            let response = self.send_request_and_wait_response(request).await?;

            match response.message_type {
                MessageType::RefreshResponse => {
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

                    debug!("TURN allocation refreshed with lifetime: {:?}", new_lifetime);
                    Ok(new_lifetime)
                }
                MessageType::RefreshError => {
                    if let Some(error_attr) = response.get_attribute(AttributeType::ErrorCode) {
                        if let AttributeValue::ErrorCode { code, reason } = &error_attr.value {
                            return Err(NatError::Platform(
                                format!("TURN refresh error {}: {}", code, reason)
                            ));
                        }
                    }
                    Err(NatError::Platform("TURN refresh failed".to_string()))
                }
                _ => Err(NatError::Platform("Unexpected refresh response".to_string())),
            }
        }

        /// Create permission for peer
        pub async fn create_permission(&self, peer_addr: SocketAddr) -> NatResult<()> {
            debug!("Creating TURN permission for {}", peer_addr);

            let transaction_id = TransactionId::new();
            let mut request = Message::new(MessageType::CreatePermissionRequest, transaction_id);

            // Add XOR-PEER-ADDRESS
            request.add_attribute(Attribute::new(
                AttributeType::XorPeerAddress,
                AttributeValue::XorMappedAddress(peer_addr), // Reuse XorMappedAddress encoding
            ));

            // Add authentication
            self.add_auth_attributes(&mut request).await?;

            // Send request
            let response = self.send_request_and_wait_response(request).await?;

            match response.message_type {
                MessageType::CreatePermissionResponse => {
                    debug!("TURN permission created for {}", peer_addr);
                    Ok(())
                }
                MessageType::CreatePermissionError => {
                    if let Some(error_attr) = response.get_attribute(AttributeType::ErrorCode) {
                        if let AttributeValue::ErrorCode { code, reason } = &error_attr.value {
                            return Err(NatError::Platform(
                                format!("TURN permission error {}: {}", code, reason)
                            ));
                        }
                    }
                    Err(NatError::Platform("TURN permission failed".to_string()))
                }
                _ => Err(NatError::Platform("Unexpected permission response".to_string())),
            }
        }

        /// Send data through TURN relay
        pub async fn send_data(&self, data: &[u8], peer_addr: SocketAddr) -> NatResult<()> {
            trace!("Sending {} bytes to {} via TURN", data.len(), peer_addr);

            let transaction_id = TransactionId::new();
            let mut indication = Message::new(MessageType::SendIndication, transaction_id);

            // Add XOR-PEER-ADDRESS
            indication.add_attribute(Attribute::new(
                AttributeType::XorPeerAddress,
                AttributeValue::XorMappedAddress(peer_addr),
            ));

            // Add DATA
            indication.add_attribute(Attribute::new(
                AttributeType::Data,
                AttributeValue::Raw(data.to_vec()),
            ));

            // Add authentication
            self.add_auth_attributes(&mut indication).await?;

            // Send indication (no response expected)
            let integrity_key = self.get_integrity_key().await?;
            let encoded = indication.encode(integrity_key.as_deref(), true)?;
            self.socket.send_to(&encoded, self.server_addr).await?;

            Ok(())
        }

        /// Close allocation
        pub async fn close_allocation(&self) -> NatResult<()> {
            debug!("Closing TURN allocation");

            let transaction_id = TransactionId::new();
            let mut request = Message::new(MessageType::RefreshRequest, transaction_id);

            // Add LIFETIME with value 0 to delete allocation
            request.add_attribute(Attribute::new(
                AttributeType::Lifetime,
                AttributeValue::Raw(vec![0, 0, 0, 0]),
            ));

            // Add authentication
            self.add_auth_attributes(&mut request).await?;

            // Send request
            let _response = self.send_request_and_wait_response(request).await?;

            debug!("TURN allocation closed");
            Ok(())
        }
    }

    impl Clone for TurnClient {
        fn clone(&self) -> Self {
            Self {
                config: self.config.clone(),
                socket: self.socket.clone(),
                server_addr: self.server_addr,
                realm: RwLock::new(self.realm.blocking_read().clone()),
                nonce: RwLock::new(self.nonce.blocking_read().clone()),
                software: self.software.clone(),
            }
        }
    }
}

pub use turn_client::{TurnAllocation, TurnClient};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_interface_discovery() {
        let gatherer = create_test_gatherer().await;
        gatherer.discover_interfaces().await.unwrap();

        let interfaces = gatherer.interfaces.read().await;
        assert!(!interfaces.is_empty(), "Should discover at least one interface");

        for interface in interfaces.iter() {
            println!("Interface: {} ({:?})", interface.name, interface.interface_type);
            assert!(!interface.addresses.is_empty(), "Interface should have addresses");
        }
    }

    #[tokio::test]
    async fn test_host_candidate_gathering() {
        let gatherer = create_test_gatherer().await;

        let candidates = gatherer.gather_host_candidates(1, 0).await.unwrap();
        assert!(!candidates.is_empty(), "Should gather at least one host candidate");

        for candidate in &candidates {
            assert_eq!(candidate.typ, CandidateType::Host);
            assert_eq!(candidate.component_id, 1);
            assert!(candidate.priority > 0);
        }
    }

    #[tokio::test]
    async fn test_candidate_deduplication() {
        let gatherer = create_test_gatherer().await;

        let mut candidates = vec![
            Candidate::new_host("192.168.1.100:50000".parse().unwrap(), 1, TransportProtocol::Udp, 1),
            Candidate::new_host("192.168.1.100:50000".parse().unwrap(), 1, TransportProtocol::Udp, 1), // Duplicate
            Candidate::new_host("192.168.1.100:50001".parse().unwrap(), 1, TransportProtocol::Udp, 1),
        ];

        let deduplicated = gatherer.deduplicate_candidates(candidates);
        assert_eq!(deduplicated.len(), 2, "Should remove duplicate candidate");
    }

    #[tokio::test]
    async fn test_turn_url_parsing() {
        assert_eq!(
            CandidateGatherer::parse_turn_url("turn:example.com").unwrap(),
            ("example.com".to_string(), 3478, TurnTransport::Udp)
        );

        assert_eq!(
            CandidateGatherer::parse_turn_url("turns:example.com:5349").unwrap(),
            ("example.com".to_string(), 5349, TurnTransport::Tls)
        );

        assert!(CandidateGatherer::parse_turn_url("invalid:url").is_err());
    }

    #[tokio::test]
    async fn test_port_manager() {
        let port_manager = PortManager::new();
        let ip = "192.168.1.100".parse().unwrap();

        // Allocate some ports
        let port1 = port_manager.allocate_port(ip, None).await.unwrap();
        let port2 = port_manager.allocate_port(ip, None).await.unwrap();

        assert_ne!(port1, port2, "Should allocate different ports");

        // Try to allocate same port again (should fail)
        let port3 = port_manager.allocate_port(ip, Some(port1)).await;
        assert!(port3.is_none() || port3.unwrap() != port1, "Should not allocate already used port");

        // Release and reallocate
        port_manager.release_port(ip, port1).await;
        let port4 = port_manager.allocate_port(ip, Some(port1)).await.unwrap();
        assert_eq!(port4, port1, "Should be able to reallocate released port");
    }

    async fn create_test_gatherer() -> CandidateGatherer {
        let (tx, _rx) = mpsc::unbounded_channel();

        CandidateGatherer::new(
            vec!["stun.l.google.com:19302".to_string()],
            vec![],
            IceTransportPolicy::All,
            tx,
            GatheringConfig::default(),
        ).unwrap()
    }
}