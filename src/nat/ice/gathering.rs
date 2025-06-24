// src/nat/ice/gathering.rs
//! Complete RFC-compliant ICE candidate gathering implementation (RFC 8445 Section 5.1.1)
//!
//! This module implements comprehensive candidate gathering with full RFC compliance,
//! including all candidate types, error handling, and advanced features.

use std::collections::{HashMap, HashSet, VecDeque, BTreeMap};
use std::net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, mpsc, oneshot, broadcast, Semaphore};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::time::{sleep, timeout, interval};
use tokio::process::Command;
use tracing::{debug, info, warn, error, trace, instrument};
use rand::{thread_rng, Rng};
use serde::{Serialize, Deserialize};

use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::candidate::{
    Candidate, CandidateType, CandidateAddress, CandidateExtensions,
    TransportProtocol, TcpType, CandidateList
};
use crate::nat::ice::priority::{
    InterfaceInfo, InterfaceType, InterfaceStatus, NetworkSecurityLevel,
    calculate_local_preference_enhanced, LocalPreferenceConfig, PriorityCalculator
};
use crate::nat::stun::{Message, MessageType, TransactionId, Attribute, AttributeType, AttributeValue};

/// Maximum gathering timeout per RFC 8445
const MAX_GATHERING_TIMEOUT: Duration = Duration::from_secs(300);

/// Minimum gathering timeout
const MIN_GATHERING_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum concurrent operations to prevent resource exhaustion
const MAX_CONCURRENT_OPERATIONS: usize = 50;

/// Maximum network interfaces to process
const MAX_NETWORK_INTERFACES: usize = 64;

/// Maximum candidates per type per component
const MAX_CANDIDATES_PER_TYPE: usize = 100;

/// Retry delays with exponential backoff
const RETRY_DELAYS: &[Duration] = &[
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
    Duration::from_millis(800),
    Duration::from_millis(1600),
];

/// Gathering phase state with detailed tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatheringPhase {
    /// Not started
    New,
    /// Initializing gathering infrastructure
    Initializing,
    /// Discovering network interfaces
    DiscoveringInterfaces,
    /// Gathering host candidates
    GatheringHost,
    /// Gathering server reflexive candidates via STUN
    GatheringServerReflexive,
    /// Gathering relay candidates via TURN
    GatheringRelay,
    /// Gathering mDNS candidates
    GatheringMdns,
    /// Finalizing and sorting candidates
    Finalizing,
    /// Gathering completed successfully
    Complete,
    /// Gathering failed
    Failed,
    /// Gathering timed out
    TimedOut,
}

/// Comprehensive gathering configuration with full validation
#[derive(Debug, Clone)]
pub struct GatheringConfig {
    /// Enable host candidate gathering
    pub gather_host_candidates: bool,

    /// Enable server reflexive candidate gathering
    pub gather_server_reflexive: bool,

    /// Enable relay candidate gathering
    pub gather_relay_candidates: bool,

    /// Enable mDNS candidates (RFC 8445 Section 5.1.1.4)
    pub enable_mdns: bool,

    /// Enable IPv4 candidates
    pub enable_ipv4: bool,

    /// Enable IPv6 candidates
    pub enable_ipv6: bool,

    /// Enable TCP candidates (RFC 6544)
    pub enable_tcp: bool,

    /// Enable UDP candidates
    pub enable_udp: bool,

    /// STUN servers for server reflexive candidates
    pub stun_servers: Vec<SocketAddr>,

    /// TURN servers for relay candidates
    pub turn_servers: Vec<TurnServerConfig>,

    /// Network interface filter configuration
    pub interface_filter: InterfaceFilter,

    /// Total gathering timeout
    pub gathering_timeout: Duration,

    /// STUN request timeout
    pub stun_timeout: Duration,

    /// TURN allocation timeout
    pub turn_timeout: Duration,

    /// Maximum candidates per type per component
    pub max_candidates_per_type: u32,

    /// Candidate TTL for refresh operations
    pub candidate_ttl: Duration,

    /// Enable happy eyeballs for dual stack
    pub enable_happy_eyeballs: bool,

    /// Priority calculator configuration
    pub priority_config: LocalPreferenceConfig,

    /// Maximum concurrent STUN requests
    pub max_concurrent_stun: usize,

    /// Maximum concurrent TURN allocations
    pub max_concurrent_turn: usize,

    /// Enable interface monitoring for dynamic updates
    pub enable_interface_monitoring: bool,

    /// Gathering retry attempts for failed operations
    pub retry_attempts: u32,

    /// Enable bandwidth estimation for interface ranking
    pub enable_bandwidth_estimation: bool,

    /// Enable network quality assessment
    pub enable_network_quality_assessment: bool,

    /// Security policy for candidate gathering
    pub security_policy: SecurityPolicy,
}

/// Security policy for candidate gathering
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityPolicy {
    /// Allow all candidates
    Permissive,
    /// Standard security (block dangerous interfaces)
    Standard,
    /// Strict security (only safe candidates)
    Strict,
    /// Custom policy with specific rules
    Custom(SecurityRules),
}

/// Custom security rules
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityRules {
    pub allow_loopback: bool,
    pub allow_link_local: bool,
    pub allow_private_networks: bool,
    pub allow_vpn_interfaces: bool,
    pub require_encryption: bool,
    pub blocked_ip_ranges: Vec<(IpAddr, u8)>, // IP/prefix
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::Standard
    }
}

impl Default for GatheringConfig {
    fn default() -> Self {
        Self {
            gather_host_candidates: true,
            gather_server_reflexive: true,
            gather_relay_candidates: false,
            enable_mdns: false,
            enable_ipv4: true,
            enable_ipv6: true,
            enable_tcp: true,
            enable_udp: true,
            stun_servers: vec![
                "stun.l.google.com:19302".parse().unwrap(),
                "stun1.l.google.com:19302".parse().unwrap(),
            ],
            turn_servers: vec![],
            interface_filter: InterfaceFilter::default(),
            gathering_timeout: Duration::from_secs(30),
            stun_timeout: Duration::from_secs(5),
            turn_timeout: Duration::from_secs(10),
            max_candidates_per_type: 10,
            candidate_ttl: Duration::from_secs(300),
            enable_happy_eyeballs: true,
            priority_config: LocalPreferenceConfig::default(),
            max_concurrent_stun: 10,
            max_concurrent_turn: 5,
            enable_interface_monitoring: true,
            retry_attempts: 3,
            enable_bandwidth_estimation: true,
            enable_network_quality_assessment: true,
            security_policy: SecurityPolicy::default(),
        }
    }
}

/// TURN server configuration with full authentication support
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    pub address: SocketAddr,
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
    pub transport: TransportProtocol,
    pub auth_method: TurnAuthMethod,
    pub allocation_lifetime: Duration,
    pub max_bandwidth: Option<u64>,
    pub priority: u32,
}

/// TURN authentication methods
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnAuthMethod {
    /// Long-term credentials
    LongTerm,
    /// Short-term credentials with nonce
    ShortTerm { nonce: String },
    /// OAuth token-based authentication
    OAuth { token: String },
}

impl Default for TurnAuthMethod {
    fn default() -> Self {
        Self::LongTerm
    }
}

/// Interface filter configuration with comprehensive rules
#[derive(Debug, Clone)]
pub struct InterfaceFilter {
    /// Allowed interface names (empty = allow all)
    pub allowed_interfaces: Vec<String>,

    /// Blocked interface names
    pub blocked_interfaces: Vec<String>,

    /// Allowed interface types
    pub allowed_types: Vec<InterfaceType>,

    /// Blocked interface types
    pub blocked_types: Vec<InterfaceType>,

    /// Block VPN interfaces
    pub block_vpn: bool,

    /// Block loopback interfaces
    pub block_loopback: bool,

    /// Block virtual interfaces
    pub block_virtual: bool,

    /// Require interface to be up
    pub require_up: bool,

    /// Require interface to support multicast
    pub require_multicast: bool,

    /// Minimum interface metric (lower is better)
    pub min_metric: Option<u32>,

    /// Maximum interface metric
    pub max_metric: Option<u32>,

    /// Minimum estimated bandwidth
    pub min_bandwidth: Option<u64>,

    /// Interface priority overrides
    pub interface_priorities: HashMap<String, u32>,
}

impl Default for InterfaceFilter {
    fn default() -> Self {
        Self {
            allowed_interfaces: vec![],
            blocked_interfaces: vec![],
            allowed_types: vec![],
            blocked_types: vec![],
            block_vpn: false,
            block_loopback: true,
            block_virtual: false,
            require_up: true,
            require_multicast: false,
            min_metric: None,
            max_metric: None,
            min_bandwidth: None,
            interface_priorities: HashMap::new(),
        }
    }
}

/// Network interface information with comprehensive details
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Interface name
    pub name: String,

    /// Interface index
    pub index: u32,

    /// Interface type classification
    pub interface_type: InterfaceType,

    /// Current interface status
    pub status: InterfaceStatus,

    /// IPv4 addresses assigned to interface
    pub ipv4_addresses: Vec<Ipv4Addr>,

    /// IPv6 addresses assigned to interface
    pub ipv6_addresses: Vec<Ipv6Addr>,

    /// Interface capability flags
    pub flags: InterfaceFlags,

    /// Interface metric (routing priority)
    pub metric: Option<u32>,

    /// Estimated bandwidth in bits per second
    pub bandwidth: Option<u64>,

    /// Network security level assessment
    pub security_level: NetworkSecurityLevel,

    /// Physical MAC address
    pub mac_address: Option<String>,

    /// MTU (Maximum Transmission Unit)
    pub mtu: Option<u32>,

    /// Interface description
    pub description: Option<String>,

    /// Parent interface (for virtual interfaces)
    pub parent_interface: Option<String>,

    /// VLAN ID (if applicable)
    pub vlan_id: Option<u16>,

    /// Interface statistics
    pub stats: InterfaceStats,

    /// Last update timestamp
    pub last_updated: Instant,
}

/// Interface capability flags
#[derive(Debug, Clone, Default)]
pub struct InterfaceFlags {
    pub is_up: bool,
    pub is_running: bool,
    pub is_loopback: bool,
    pub is_point_to_point: bool,
    pub is_multicast: bool,
    pub is_broadcast: bool,
    pub supports_multicast: bool,
    pub supports_promiscuous: bool,
    pub is_dormant: bool,
    pub is_lower_up: bool,
}

/// Interface network statistics
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub collisions: u64,
}

/// Gathering event with comprehensive information
#[derive(Debug, Clone)]
pub enum GatheringEvent {
    /// Gathering phase changed
    PhaseChanged {
        old_phase: GatheringPhase,
        new_phase: GatheringPhase,
        timestamp: Instant,
    },

    /// New candidate discovered
    CandidateDiscovered {
        candidate: Candidate,
        component_id: u32,
        interface_name: String,
        gathering_method: GatheringMethod,
        timestamp: Instant,
    },

    /// Candidate gathering failed for specific method
    CandidateGatheringFailed {
        candidate_type: CandidateType,
        interface_name: Option<String>,
        error: GatheringError,
        retry_possible: bool,
        timestamp: Instant,
    },

    /// Network interface discovered
    InterfaceDiscovered {
        interface: NetworkInterface,
        timestamp: Instant,
    },

    /// Network interface status changed
    InterfaceChanged {
        interface_name: String,
        old_status: InterfaceStatus,
        new_status: InterfaceStatus,
        timestamp: Instant,
    },

    /// Network interface removed
    InterfaceRemoved {
        interface_name: String,
        timestamp: Instant,
    },

    /// STUN server response received
    StunResponse {
        server: SocketAddr,
        success: bool,
        response_time: Duration,
        mapped_address: Option<SocketAddr>,
        timestamp: Instant,
    },

    /// TURN allocation result
    TurnAllocation {
        server: SocketAddr,
        success: bool,
        allocated_address: Option<SocketAddr>,
        lifetime: Option<Duration>,
        timestamp: Instant,
    },

    /// Gathering completed for component
    ComponentGatheringCompleted {
        component_id: u32,
        candidate_count: usize,
        duration: Duration,
        timestamp: Instant,
    },

    /// Overall gathering completed
    GatheringCompleted {
        total_candidates: usize,
        candidates_by_type: HashMap<CandidateType, u32>,
        duration: Duration,
        timestamp: Instant,
    },

    /// Gathering timeout occurred
    GatheringTimeout {
        phase: GatheringPhase,
        partial_results: usize,
        timestamp: Instant,
    },

    /// Network quality assessment completed
    NetworkQualityAssessment {
        interface_name: String,
        quality_score: f64,
        latency: Option<Duration>,
        bandwidth: Option<u64>,
        packet_loss: Option<f64>,
        timestamp: Instant,
    },
}

/// Gathering method used to discover candidate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatheringMethod {
    HostDiscovery,
    StunBinding,
    TurnAllocation,
    MdnsResolution,
    InterfaceMonitoring,
}

/// Detailed gathering error information
#[derive(Debug, Clone)]
pub enum GatheringError {
    /// Network interface error
    InterfaceError {
        interface: String,
        error: String,
        error_code: Option<i32>,
    },

    /// STUN server error
    StunError {
        server: SocketAddr,
        error: String,
        error_code: Option<u16>,
    },

    /// TURN server error
    TurnError {
        server: SocketAddr,
        error: String,
        error_code: Option<u16>,
    },

    /// mDNS resolution error
    MdnsError {
        hostname: String,
        error: String,
    },

    /// Security policy violation
    SecurityViolation {
        rule: String,
        description: String,
    },

    /// Resource exhaustion
    ResourceExhaustion {
        resource: String,
        limit: usize,
        attempted: usize,
    },

    /// Configuration error
    ConfigurationError {
        parameter: String,
        reason: String,
    },

    /// System error
    SystemError {
        operation: String,
        error: String,
    },
}

/// Comprehensive gathering statistics
#[derive(Debug, Default, Clone)]
pub struct GatheringStats {
    pub start_time: Option<Instant>,
    pub end_time: Option<Instant>,
    pub total_duration: Duration,
    pub phase_durations: HashMap<GatheringPhase, Duration>,

    // Candidate statistics
    pub host_candidates: u32,
    pub server_reflexive_candidates: u32,
    pub relay_candidates: u32,
    pub mdns_candidates: u32,
    pub ipv4_candidates: u32,
    pub ipv6_candidates: u32,
    pub tcp_candidates: u32,
    pub udp_candidates: u32,

    // Operation statistics
    pub interfaces_discovered: u32,
    pub interfaces_used: u32,
    pub stun_requests_sent: u32,
    pub stun_responses_received: u32,
    pub stun_success_rate: f64,
    pub turn_allocations_attempted: u32,
    pub turn_allocations_successful: u32,
    pub turn_success_rate: f64,

    // Error statistics
    pub total_errors: u32,
    pub errors_by_type: HashMap<String, u32>,
    pub retry_attempts: u32,
    pub successful_retries: u32,

    // Performance statistics
    pub average_stun_response_time: Duration,
    pub average_turn_allocation_time: Duration,
    pub candidates_per_second: f64,
    pub memory_peak_usage: usize,

    // Quality metrics
    pub network_quality_scores: HashMap<String, f64>,
    pub interface_utilization: HashMap<String, f64>,
}

/// Main candidate gatherer with full RFC compliance
pub struct CandidateGatherer {
    /// Gathering configuration
    config: Arc<GatheringConfig>,

    /// Current gathering phase
    phase: Arc<RwLock<GatheringPhase>>,

    /// Discovered candidates by component
    candidates: Arc<RwLock<HashMap<u32, CandidateList>>>,

    /// Discovered network interfaces
    interfaces: Arc<RwLock<HashMap<String, NetworkInterface>>>,

    /// Priority calculator
    priority_calculator: Arc<Mutex<PriorityCalculator>>,

    /// Event broadcaster
    event_sender: broadcast::Sender<GatheringEvent>,

    /// Gathering statistics
    stats: Arc<RwLock<GatheringStats>>,

    /// Active gathering operations
    active_operations: Arc<RwLock<HashMap<String, GatheringOperation>>>,

    /// Concurrency control
    operation_semaphore: Arc<Semaphore>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,

    /// STUN client pool
    stun_clients: Arc<RwLock<Vec<Arc<StunClient>>>>,

    /// TURN client pool
    turn_clients: Arc<RwLock<Vec<Arc<TurnClient>>>>,

    /// mDNS resolver
    mdns_resolver: Option<Arc<MdnsResolver>>,

    /// Interface monitor
    interface_monitor: Arc<InterfaceMonitor>,

    /// Network quality assessor
    quality_assessor: Option<Arc<NetworkQualityAssessor>>,

    /// Security validator
    security_validator: Arc<SecurityValidator>,

    /// Retry manager
    retry_manager: Arc<RetryManager>,
}

/// Individual gathering operation tracking
#[derive(Debug, Clone)]
pub struct GatheringOperation {
    pub id: String,
    pub operation_type: GatheringMethod,
    pub component_id: u32,
    pub interface_name: Option<String>,
    pub server_address: Option<SocketAddr>,
    pub started_at: Instant,
    pub timeout: Duration,
    pub retry_count: u32,
    pub status: OperationStatus,
}

/// Operation status tracking
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

impl CandidateGatherer {
    /// Create new candidate gatherer with comprehensive validation
    #[instrument(skip_all)]
    pub async fn new(config: GatheringConfig) -> NatResult<Self> {
        // Validate configuration thoroughly
        Self::validate_config(&config)?;

        let config = Arc::new(config);
        let (event_sender, _) = broadcast::channel(10000);

        // Initialize components
        let interface_monitor = Arc::new(InterfaceMonitor::new().await?);

        let stun_clients = Arc::new(RwLock::new(
            Self::create_stun_client_pool(&config).await?
        ));

        let turn_clients = Arc::new(RwLock::new(
            Self::create_turn_client_pool(&config).await?
        ));

        let mdns_resolver = if config.enable_mdns {
            Some(Arc::new(MdnsResolver::new().await?))
        } else {
            None
        };

        let quality_assessor = if config.enable_network_quality_assessment {
            Some(Arc::new(NetworkQualityAssessor::new().await?))
        } else {
            None
        };

        let security_validator = Arc::new(SecurityValidator::new(config.security_policy.clone()));
        let retry_manager = Arc::new(RetryManager::new(config.retry_attempts));

        let priority_calculator = Arc::new(Mutex::new(
            PriorityCalculator::new(config.priority_config.clone())
        ));

        Ok(Self {
            config,
            phase: Arc::new(RwLock::new(GatheringPhase::New)),
            candidates: Arc::new(RwLock::new(HashMap::new())),
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            priority_calculator,
            event_sender,
            stats: Arc::new(RwLock::new(GatheringStats::default())),
            active_operations: Arc::new(RwLock::new(HashMap::new())),
            operation_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_OPERATIONS)),
            shutdown: Arc::new(RwLock::new(false)),
            stun_clients,
            turn_clients,
            mdns_resolver,
            interface_monitor,
            quality_assessor,
            security_validator,
            retry_manager,
        })
    }

    /// Validate gathering configuration comprehensively
    fn validate_config(config: &GatheringConfig) -> NatResult<()> {
        // Validate timeouts
        if config.gathering_timeout < MIN_GATHERING_TIMEOUT || config.gathering_timeout > MAX_GATHERING_TIMEOUT {
            return Err(NatError::Configuration(
                format!("Gathering timeout must be between {:?} and {:?}",
                        MIN_GATHERING_TIMEOUT, MAX_GATHERING_TIMEOUT)
            ));
        }

        if config.stun_timeout == Duration::ZERO || config.stun_timeout > Duration::from_secs(30) {
            return Err(NatError::Configuration(
                "STUN timeout must be between 1ms and 30s".to_string()
            ));
        }

        if config.turn_timeout == Duration::ZERO || config.turn_timeout > Duration::from_secs(60) {
            return Err(NatError::Configuration(
                "TURN timeout must be between 1ms and 60s".to_string()
            ));
        }

        // Validate candidate limits
        if config.max_candidates_per_type == 0 || config.max_candidates_per_type > MAX_CANDIDATES_PER_TYPE as u32 {
            return Err(NatError::Configuration(
                format!("Max candidates per type must be between 1 and {}", MAX_CANDIDATES_PER_TYPE)
            ));
        }

        // Validate protocol configuration
        if !config.enable_ipv4 && !config.enable_ipv6 {
            return Err(NatError::Configuration(
                "At least one IP version (IPv4 or IPv6) must be enabled".to_string()
            ));
        }

        if !config.enable_tcp && !config.enable_udp {
            return Err(NatError::Configuration(
                "At least one transport protocol (TCP or UDP) must be enabled".to_string()
            ));
        }

        // Validate gathering methods
        if !config.gather_host_candidates && !config.gather_server_reflexive && !config.gather_relay_candidates {
            return Err(NatError::Configuration(
                "At least one candidate gathering method must be enabled".to_string()
            ));
        }

        // Validate STUN servers if server reflexive is enabled
        if config.gather_server_reflexive {
            if config.stun_servers.is_empty() {
                return Err(NatError::Configuration(
                    "STUN servers required when server reflexive gathering is enabled".to_string()
                ));
            }

            for server in &config.stun_servers {
                if server.port() == 0 {
                    return Err(NatError::Configuration(
                        "STUN server addresses must include valid port numbers".to_string()
                    ));
                }
            }
        }

        // Validate TURN servers if relay is enabled
        if config.gather_relay_candidates {
            if config.turn_servers.is_empty() {
                return Err(NatError::Configuration(
                    "TURN servers required when relay gathering is enabled".to_string()
                ));
            }

            for server in &config.turn_servers {
                if server.address.port() == 0 {
                    return Err(NatError::Configuration(
                        "TURN server addresses must include valid port numbers".to_string()
                    ));
                }

                if server.username.is_empty() || server.password.is_empty() {
                    return Err(NatError::Configuration(
                        "TURN servers must have valid credentials".to_string()
                    ));
                }

                if server.allocation_lifetime < Duration::from_secs(60) ||
                    server.allocation_lifetime > Duration::from_secs(3600) {
                    return Err(NatError::Configuration(
                        "TURN allocation lifetime must be between 60s and 3600s".to_string()
                    ));
                }
            }
        }

        // Validate concurrency limits
        if config.max_concurrent_stun == 0 || config.max_concurrent_stun > 100 {
            return Err(NatError::Configuration(
                "Max concurrent STUN requests must be between 1 and 100".to_string()
            ));
        }

        if config.max_concurrent_turn == 0 || config.max_concurrent_turn > 50 {
            return Err(NatError::Configuration(
                "Max concurrent TURN allocations must be between 1 and 50".to_string()
            ));
        }

        Ok(())
    }

    /// Create STUN client pool
    async fn create_stun_client_pool(config: &GatheringConfig) -> NatResult<Vec<Arc<StunClient>>> {
        let mut clients = Vec::new();

        for &server in &config.stun_servers {
            let client = Arc::new(StunClient::new(server, config.stun_timeout).await?);
            clients.push(client);
        }

        if clients.is_empty() && config.gather_server_reflexive {
            return Err(NatError::Configuration("No valid STUN servers available".to_string()));
        }

        Ok(clients)
    }

    /// Create TURN client pool
    async fn create_turn_client_pool(config: &GatheringConfig) -> NatResult<Vec<Arc<TurnClient>>> {
        let mut clients = Vec::new();

        for server_config in &config.turn_servers {
            let client = Arc::new(TurnClient::new(server_config.clone()).await?);
            clients.push(client);
        }

        if clients.is_empty() && config.gather_relay_candidates {
            return Err(NatError::Configuration("No valid TURN servers available".to_string()));
        }

        Ok(clients)
    }

    /// Start comprehensive candidate gathering
    #[instrument(skip_all, fields(component_id = component_id))]
    pub async fn start_gathering(&self, component_id: u32) -> NatResult<()> {
        if component_id == 0 || component_id > 256 {
            return Err(NatError::Configuration("Component ID must be between 1 and 256".to_string()));
        }

        info!("Starting ICE candidate gathering for component {}", component_id);

        // Initialize statistics
        {
            let mut stats = self.stats.write().await;
            stats.start_time = Some(Instant::now());
        }

        // Set initial phase
        self.set_phase(GatheringPhase::Initializing).await;

        // Start gathering process
        let gathering_result = timeout(
            self.config.gathering_timeout,
            self.execute_gathering_process(component_id)
        ).await;

        match gathering_result {
            Ok(Ok(_)) => {
                self.set_phase(GatheringPhase::Complete).await;
                self.finalize_gathering_statistics(component_id).await;
                info!("Candidate gathering completed successfully for component {}", component_id);
                Ok(())
            }
            Ok(Err(e)) => {
                self.set_phase(GatheringPhase::Failed).await;
                error!("Candidate gathering failed for component {}: {}", component_id, e);
                Err(e)
            }
            Err(_) => {
                self.set_phase(GatheringPhase::TimedOut).await;
                let timeout_event = GatheringEvent::GatheringTimeout {
                    phase: *self.phase.read().await,
                    partial_results: self.get_candidate_count(component_id).await,
                    timestamp: Instant::now(),
                };
                let _ = self.event_sender.send(timeout_event);
                error!("Candidate gathering timed out for component {}", component_id);
                Err(NatError::Timeout(self.config.gathering_timeout))
            }
        }
    }

    /// Execute the main gathering process
    async fn execute_gathering_process(&self, component_id: u32) -> NatResult<()> {
        // Phase 1: Discover network interfaces
        self.set_phase(GatheringPhase::DiscoveringInterfaces).await;
        self.discover_network_interfaces().await?;

        // Phase 2: Gather host candidates
        if self.config.gather_host_candidates {
            self.set_phase(GatheringPhase::GatheringHost).await;
            self.gather_host_candidates(component_id).await?;
        }

        // Phase 3: Gather server reflexive candidates
        if self.config.gather_server_reflexive && !self.config.stun_servers.is_empty() {
            self.set_phase(GatheringPhase::GatheringServerReflexive).await;
            self.gather_server_reflexive_candidates(component_id).await?;
        }

        // Phase 4: Gather relay candidates
        if self.config.gather_relay_candidates && !self.config.turn_servers.is_empty() {
            self.set_phase(GatheringPhase::GatheringRelay).await;
            self.gather_relay_candidates(component_id).await?;
        }

        // Phase 5: Gather mDNS candidates
        if self.config.enable_mdns && self.mdns_resolver.is_some() {
            self.set_phase(GatheringPhase::GatheringMdns).await;
            self.gather_mdns_candidates(component_id).await?;
        }

        // Phase 6: Finalize candidates
        self.set_phase(GatheringPhase::Finalizing).await;
        self.finalize_candidates(component_id).await?;

        Ok(())
    }

    /// Comprehensive network interface discovery with platform-specific implementation
    #[instrument(skip_all)]
    async fn discover_network_interfaces(&self) -> NatResult<()> {
        info!("Discovering network interfaces");
        let start_time = Instant::now();

        // Get raw interface data from system
        let raw_interfaces = self.get_system_interfaces().await?;

        // Process and validate interfaces
        let mut valid_interfaces = HashMap::new();
        let mut interfaces_processed = 0;

        for (name, mut interface) in raw_interfaces {
            interfaces_processed += 1;

            if interfaces_processed > MAX_NETWORK_INTERFACES {
                warn!("Maximum interface limit reached ({}), skipping remaining", MAX_NETWORK_INTERFACES);
                break;
            }

            // Apply interface filtering
            if !self.should_use_interface(&interface).await {
                debug!("Filtering out interface: {} ({})", name, interface.interface_type);
                continue;
            }

            // Validate interface security
            if !self.security_validator.validate_interface(&interface).await {
                warn!("Interface {} failed security validation", name);
                continue;
            }

            // Enhance interface information
            self.enhance_interface_info(&mut interface).await;

            // Perform network quality assessment if enabled
            if let Some(ref assessor) = self.quality_assessor {
                match assessor.assess_interface(&interface).await {
                    Ok(quality) => {
                        let quality_event = GatheringEvent::NetworkQualityAssessment {
                            interface_name: name.clone(),
                            quality_score: quality.overall_score,
                            latency: quality.latency,
                            bandwidth: quality.bandwidth,
                            packet_loss: quality.packet_loss,
                            timestamp: Instant::now(),
                        };
                        let _ = self.event_sender.send(quality_event);
                    }
                    Err(e) => {
                        debug!("Quality assessment failed for interface {}: {}", name, e);
                    }
                }
            }

            // Emit interface discovered event
            let discovered_event = GatheringEvent::InterfaceDiscovered {
                interface: interface.clone(),
                timestamp: Instant::now(),
            };
            let _ = self.event_sender.send(discovered_event);

            valid_interfaces.insert(name, interface);
        }

        // Store discovered interfaces
        *self.interfaces.write().await = valid_interfaces;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.interfaces_discovered = interfaces_processed as u32;
            stats.interfaces_used = self.interfaces.read().await.len() as u32;
            stats.phase_durations.insert(GatheringPhase::DiscoveringInterfaces, start_time.elapsed());
        }

        let discovered_count = self.interfaces.read().await.len();
        info!("Discovered {} usable network interfaces in {:?}", discovered_count, start_time.elapsed());

        if discovered_count == 0 {
            return Err(NatError::Configuration("No usable network interfaces found".to_string()));
        }

        Ok(())
    }

    /// Get system network interfaces using platform-specific methods
    async fn get_system_interfaces(&self) -> NatResult<HashMap<String, NetworkInterface>> {
        #[cfg(target_os = "windows")]
        {
            self.get_windows_interfaces().await
        }

        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
        {
            self.get_unix_interfaces().await
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos", target_os = "freebsd")))]
        {
            self.get_generic_interfaces().await
        }
    }

    /// Windows-specific interface discovery
    #[cfg(target_os = "windows")]
    async fn get_windows_interfaces(&self) -> NatResult<HashMap<String, NetworkInterface>> {
        let mut interfaces = HashMap::new();

        // Use Windows IP Helper API via system commands
        let output = Command::new("netsh")
            .args(&["interface", "show", "interface"])
            .output()
            .await
            .map_err(|e| NatError::Platform(format!("Failed to execute netsh: {}", e)))?;

        if !output.status.success() {
            return Err(NatError::Platform("netsh command failed".to_string()));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse netsh output
        for line in output_str.lines().skip(3) { // Skip header lines
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 4 {
                let status = fields[0];
                let interface_type = fields[1];
                let connect_state = fields[2];
                let name = fields[3..].join(" ");

                if name.is_empty() {
                    continue;
                }

                let interface = NetworkInterface {
                    name: name.clone(),
                    index: 0, // Will be populated later
                    interface_type: self.parse_windows_interface_type(interface_type),
                    status: if status == "Enabled" && connect_state == "Connected" {
                        InterfaceStatus::Up
                    } else {
                        InterfaceStatus::Down
                    },
                    ipv4_addresses: Vec::new(),
                    ipv6_addresses: Vec::new(),
                    flags: InterfaceFlags::default(),
                    metric: None,
                    bandwidth: None,
                    security_level: NetworkSecurityLevel::Unknown,
                    mac_address: None,
                    mtu: None,
                    description: Some(interface_type.to_string()),
                    parent_interface: None,
                    vlan_id: None,
                    stats: InterfaceStats::default(),
                    last_updated: Instant::now(),
                };

                interfaces.insert(name, interface);
            }
        }

        // Get detailed IP configuration
        self.enhance_windows_interfaces(&mut interfaces).await?;

        Ok(interfaces)
    }

    /// Unix-like systems interface discovery
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    async fn get_unix_interfaces(&self) -> NatResult<HashMap<String, NetworkInterface>> {
        let mut interfaces = HashMap::new();

        // Try ip command first (Linux), then ifconfig (macOS/FreeBSD)
        let output = if cfg!(target_os = "linux") {
            Command::new("ip")
                .args(&["addr", "show"])
                .output()
                .await
                .or_else(|_| async {
                    Command::new("ifconfig")
                        .output()
                        .await
                })
                .await
        } else {
            Command::new("ifconfig")
                .output()
                .await
        };

        let output = output.map_err(|e| NatError::Platform(format!("Failed to get interface info: {}", e)))?;

        if !output.status.success() {
            return Err(NatError::Platform("Interface enumeration command failed".to_string()));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse interface information
        if cfg!(target_os = "linux") && output_str.contains("inet ") {
            self.parse_ip_addr_output(&output_str, &mut interfaces).await?;
        } else {
            self.parse_ifconfig_output(&output_str, &mut interfaces).await?;
        }

        Ok(interfaces)
    }

    /// Generic interface discovery fallback
    async fn get_generic_interfaces(&self) -> NatResult<HashMap<String, NetworkInterface>> {
        // Fallback using Rust standard library
        let mut interfaces = HashMap::new();

        // Create a basic loopback interface as minimum requirement
        let loopback = NetworkInterface {
            name: "lo".to_string(),
            index: 1,
            interface_type: InterfaceType::Loopback,
            status: InterfaceStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::LOCALHOST],
            ipv6_addresses: vec![Ipv6Addr::LOCALHOST],
            flags: InterfaceFlags {
                is_up: true,
                is_running: true,
                is_loopback: true,
                is_multicast: false,
                is_broadcast: false,
                supports_multicast: false,
                supports_promiscuous: false,
                is_dormant: false,
                is_lower_up: true,
                is_point_to_point: false,
            },
            metric: Some(1),
            bandwidth: None,
            security_level: NetworkSecurityLevel::Private,
            mac_address: None,
            mtu: Some(65536),
            description: Some("Loopback".to_string()),
            parent_interface: None,
            vlan_id: None,
            stats: InterfaceStats::default(),
            last_updated: Instant::now(),
        };

        interfaces.insert("lo".to_string(), loopback);

        warn!("Using generic interface discovery - limited functionality available");
        Ok(interfaces)
    }

    /// Parse Linux ip addr output
    async fn parse_ip_addr_output(&self, output: &str, interfaces: &mut HashMap<String, NetworkInterface>) -> NatResult<()> {
        let mut current_interface: Option<NetworkInterface> = None;

        for line in output.lines() {
            let line = line.trim();

            if let Some(captures) = regex::Regex::new(r"^(\d+): ([^:@]+)[@:].*<([^>]*)>.*mtu (\d+)")
                .unwrap()
                .captures(line) {

                // Save previous interface
                if let Some(interface) = current_interface.take() {
                    interfaces.insert(interface.name.clone(), interface);
                }

                // Parse new interface
                let index: u32 = captures[1].parse().unwrap_or(0);
                let name = captures[2].to_string();
                let flags_str = &captures[3];
                let mtu: u32 = captures[4].parse().unwrap_or(1500);

                let flags = self.parse_linux_flags(flags_str);
                let interface_type = InterfaceType::from_name(&name);

                current_interface = Some(NetworkInterface {
                    name,
                    index,
                    interface_type,
                    status: if flags.is_up { InterfaceStatus::Up } else { InterfaceStatus::Down },
                    ipv4_addresses: Vec::new(),
                    ipv6_addresses: Vec::new(),
                    flags,
                    metric: None,
                    bandwidth: None,
                    security_level: NetworkSecurityLevel::Unknown,
                    mac_address: None,
                    mtu: Some(mtu),
                    description: None,
                    parent_interface: None,
                    vlan_id: None,
                    stats: InterfaceStats::default(),
                    last_updated: Instant::now(),
                });
            } else if line.starts_with("inet ") {
                // Parse IPv4 address
                if let Some(ref mut interface) = current_interface {
                    if let Some(addr_str) = line.split_whitespace().nth(1) {
                        if let Some(ip_str) = addr_str.split('/').next() {
                            if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
                                interface.ipv4_addresses.push(ipv4);
                            }
                        }
                    }
                }
            } else if line.starts_with("inet6 ") {
                // Parse IPv6 address
                if let Some(ref mut interface) = current_interface {
                    if let Some(addr_str) = line.split_whitespace().nth(1) {
                        if let Some(ip_str) = addr_str.split('/').next() {
                            if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
                                interface.ipv6_addresses.push(ipv6);
                            }
                        }
                    }
                }
            }
        }

        // Save last interface
        if let Some(interface) = current_interface {
            interfaces.insert(interface.name.clone(), interface);
        }

        Ok(())
    }

    /// Parse ifconfig output (macOS/FreeBSD/fallback)
    async fn parse_ifconfig_output(&self, output: &str, interfaces: &mut HashMap<String, NetworkInterface>) -> NatResult<()> {
        let mut current_interface: Option<NetworkInterface> = None;
        let mut interface_index = 1u32;

        for line in output.lines() {
            if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
                // Save previous interface
                if let Some(interface) = current_interface.take() {
                    interfaces.insert(interface.name.clone(), interface);
                }

                // Parse new interface header
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let name = parts[0].trim().to_string();
                    let flags_part = parts[1].trim();

                    let flags = self.parse_bsd_flags(flags_part);
                    let interface_type = InterfaceType::from_name(&name);

                    current_interface = Some(NetworkInterface {
                        name,
                        index: interface_index,
                        interface_type,
                        status: if flags.is_up { InterfaceStatus::Up } else { InterfaceStatus::Down },
                        ipv4_addresses: Vec::new(),
                        ipv6_addresses: Vec::new(),
                        flags,
                        metric: None,
                        bandwidth: None,
                        security_level: NetworkSecurityLevel::Unknown,
                        mac_address: None,
                        mtu: None,
                        description: None,
                        parent_interface: None,
                        vlan_id: None,
                        stats: InterfaceStats::default(),
                        last_updated: Instant::now(),
                    });

                    interface_index += 1;
                }
            } else if let Some(ref mut interface) = current_interface {
                let line = line.trim();

                if line.starts_with("inet ") {
                    // Parse IPv4 address
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(ipv4) = parts[1].parse::<Ipv4Addr>() {
                            interface.ipv4_addresses.push(ipv4);
                        }
                    }
                } else if line.starts_with("inet6 ") {
                    // Parse IPv6 address
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let addr_str = parts[1].split('%').next().unwrap_or(parts[1]);
                        if let Ok(ipv6) = addr_str.parse::<Ipv6Addr>() {
                            interface.ipv6_addresses.push(ipv6);
                        }
                    }
                } else if line.starts_with("mtu ") {
                    // Parse MTU
                    if let Some(mtu_str) = line.split_whitespace().nth(1) {
                        if let Ok(mtu) = mtu_str.parse::<u32>() {
                            interface.mtu = Some(mtu);
                        }
                    }
                } else if line.starts_with("ether ") {
                    // Parse MAC address
                    if let Some(mac_str) = line.split_whitespace().nth(1) {
                        interface.mac_address = Some(mac_str.to_string());
                    }
                }
            }
        }

        // Save last interface
        if let Some(interface) = current_interface {
            interfaces.insert(interface.name.clone(), interface);
        }

        Ok(())
    }

    /// Parse Linux interface flags
    fn parse_linux_flags(&self, flags_str: &str) -> InterfaceFlags {
        let mut flags = InterfaceFlags::default();

        for flag in flags_str.split(',') {
            match flag.trim().to_uppercase().as_str() {
                "UP" => flags.is_up = true,
                "RUNNING" => flags.is_running = true,
                "LOOPBACK" => flags.is_loopback = true,
                "POINTOPOINT" => flags.is_point_to_point = true,
                "MULTICAST" => {
                    flags.is_multicast = true;
                    flags.supports_multicast = true;
                }
                "BROADCAST" => flags.is_broadcast = true,
                "PROMISC" => flags.supports_promiscuous = true,
                "DORMANT" => flags.is_dormant = true,
                "LOWER_UP" => flags.is_lower_up = true,
                _ => {}
            }
        }

        flags
    }

    /// Parse BSD-style interface flags
    fn parse_bsd_flags(&self, flags_str: &str) -> InterfaceFlags {
        let mut flags = InterfaceFlags::default();

        // BSD flags are typically in format: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>
        if let Some(start) = flags_str.find('<') {
            if let Some(end) = flags_str.find('>') {
                let flag_part = &flags_str[start+1..end];
                for flag in flag_part.split(',') {
                    match flag.trim().to_uppercase().as_str() {
                        "UP" => flags.is_up = true,
                        "RUNNING" => flags.is_running = true,
                        "LOOPBACK" => flags.is_loopback = true,
                        "POINTOPOINT" => flags.is_point_to_point = true,
                        "MULTICAST" => {
                            flags.is_multicast = true;
                            flags.supports_multicast = true;
                        }
                        "BROADCAST" => flags.is_broadcast = true,
                        "PROMISC" => flags.supports_promiscuous = true,
                        _ => {}
                    }
                }
            }
        }

        flags
    }

    /// Windows interface type parsing
    #[cfg(target_os = "windows")]
    fn parse_windows_interface_type(&self, type_str: &str) -> InterfaceType {
        match type_str.to_lowercase().as_str() {
            "ethernet" => InterfaceType::Ethernet,
            "wireless" | "wi-fi" => InterfaceType::WifiLegacy,
            "loopback" => InterfaceType::Loopback,
            "tunnel" | "teredo" => InterfaceType::Vpn,
            _ => InterfaceType::Unknown,
        }
    }

    /// Enhance Windows interface information
    #[cfg(target_os = "windows")]
    async fn enhance_windows_interfaces(&self, interfaces: &mut HashMap<String, NetworkInterface>) -> NatResult<()> {
        // Get IP configuration for each interface
        for (name, interface) in interfaces.iter_mut() {
            // Use netsh to get IP addresses
            if let Ok(output) = Command::new("netsh")
                .args(&["interface", "ip", "show", "addresses", name])
                .output()
                .await {

                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);

                    for line in output_str.lines() {
                        if line.contains("IP Address:") {
                            if let Some(ip_str) = line.split(':').nth(1) {
                                let ip_str = ip_str.trim();
                                if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
                                    interface.ipv4_addresses.push(ipv4);
                                } else if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
                                    interface.ipv6_addresses.push(ipv6);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if interface should be used based on filtering rules
    async fn should_use_interface(&self, interface: &NetworkInterface) -> bool {
        let filter = &self.config.interface_filter;

        // Check allowed interfaces list
        if !filter.allowed_interfaces.is_empty() {
            if !filter.allowed_interfaces.contains(&interface.name) {
                return false;
            }
        }

        // Check blocked interfaces list
        if filter.blocked_interfaces.contains(&interface.name) {
            return false;
        }

        // Check allowed types
        if !filter.allowed_types.is_empty() {
            if !filter.allowed_types.contains(&interface.interface_type) {
                return false;
            }
        }

        // Check blocked types
        if filter.blocked_types.contains(&interface.interface_type) {
            return false;
        }

        // Check interface status
        if filter.require_up && interface.status != InterfaceStatus::Up {
            return false;
        }

        // Check multicast requirement
        if filter.require_multicast && !interface.flags.supports_multicast {
            return false;
        }

        // Check VPN filtering
        if filter.block_vpn && interface.interface_type == InterfaceType::Vpn {
            return false;
        }

        // Check loopback filtering
        if filter.block_loopback && interface.interface_type == InterfaceType::Loopback {
            return false;
        }

        // Check virtual interface filtering
        if filter.block_virtual && interface.interface_type == InterfaceType::Virtual {
            return false;
        }

        // Check metric bounds
        if let Some(metric) = interface.metric {
            if let Some(min_metric) = filter.min_metric {
                if metric < min_metric {
                    return false;
                }
            }
            if let Some(max_metric) = filter.max_metric {
                if metric > max_metric {
                    return false;
                }
            }
        }

        // Check bandwidth bounds
        if let Some(bandwidth) = interface.bandwidth {
            if let Some(min_bandwidth) = filter.min_bandwidth {
                if bandwidth < min_bandwidth {
                    return false;
                }
            }
        }

        // Check if interface has any usable addresses
        let has_ipv4 = self.config.enable_ipv4 && !interface.ipv4_addresses.is_empty();
        let has_ipv6 = self.config.enable_ipv6 && !interface.ipv6_addresses.is_empty();

        if !has_ipv4 && !has_ipv6 {
            return false;
        }

        true
    }

    /// Enhance interface information with additional details
    async fn enhance_interface_info(&self, interface: &mut NetworkInterface) {
        // Estimate bandwidth if not available
        if interface.bandwidth.is_none() && self.config.enable_bandwidth_estimation {
            interface.bandwidth = self.estimate_interface_bandwidth(interface).await;
        }

        // Determine security level
        interface.security_level = self.assess_interface_security(interface).await;

        // Apply priority overrides
        if let Some(&priority) = self.config.interface_filter.interface_priorities.get(&interface.name) {
            interface.metric = Some(priority);
        }

        // Update timestamp
        interface.last_updated = Instant::now();
    }

    /// Estimate interface bandwidth
    async fn estimate_interface_bandwidth(&self, interface: &NetworkInterface) -> Option<u64> {
        match interface.interface_type {
            InterfaceType::Loopback => Some(1_000_000_000_000), // 1 Tbps theoretical
            InterfaceType::Ethernet => Some(1_000_000_000), // 1 Gbps default
            InterfaceType::ThunderboltEthernet => Some(10_000_000_000), // 10 Gbps
            InterfaceType::Wifi6 => Some(1_200_000_000), // 1.2 Gbps
            InterfaceType::Wifi5 => Some(600_000_000), // 600 Mbps
            InterfaceType::WifiLegacy => Some(100_000_000), // 100 Mbps
            InterfaceType::Cellular5G => Some(1_000_000_000), // 1 Gbps peak
            InterfaceType::Cellular4G => Some(100_000_000), // 100 Mbps
            InterfaceType::CellularLegacy => Some(10_000_000), // 10 Mbps
            InterfaceType::Bluetooth => Some(3_000_000), // 3 Mbps
            InterfaceType::Vpn => Some(100_000_000), // 100 Mbps estimated
            InterfaceType::Virtual => Some(1_000_000_000), // 1 Gbps virtual
            InterfaceType::Unknown => Some(10_000_000), // 10 Mbps conservative
        }
    }

    /// Assess interface security level
    async fn assess_interface_security(&self, interface: &NetworkInterface) -> NetworkSecurityLevel {
        match interface.interface_type {
            InterfaceType::Loopback => NetworkSecurityLevel::Secure,
            InterfaceType::Ethernet | InterfaceType::ThunderboltEthernet => {
                NetworkSecurityLevel::Corporate
            }
            InterfaceType::Wifi6 | InterfaceType::Wifi5 | InterfaceType::WifiLegacy => {
                NetworkSecurityLevel::Private
            }
            InterfaceType::Cellular5G | InterfaceType::Cellular4G | InterfaceType::CellularLegacy => {
                NetworkSecurityLevel::Public
            }
            InterfaceType::Vpn => NetworkSecurityLevel::Secure,
            InterfaceType::Virtual => NetworkSecurityLevel::Private,
            InterfaceType::Bluetooth => NetworkSecurityLevel::Private,
            InterfaceType::Unknown => NetworkSecurityLevel::Unknown,
        }
    }

    /// Gather host candidates from all suitable interfaces
    #[instrument(skip_all, fields(component_id = component_id))]
    async fn gather_host_candidates(&self, component_id: u32) -> NatResult<()> {
        info!("Gathering host candidates for component {}", component_id);
        let start_time = Instant::now();

        let interfaces = self.interfaces.read().await.clone();
        let mut gathering_tasks = Vec::new();

        // Create gathering tasks for each interface
        for (interface_name, interface) in interfaces.iter() {
            if self.config.enable_ipv4 {
                for &ipv4 in &interface.ipv4_addresses {
                    if self.should_use_ipv4_address(&ipv4) {
                        let task = self.gather_host_candidates_for_address(
                            IpAddr::V4(ipv4),
                            component_id,
                            interface_name.clone(),
                            interface.clone(),
                        );
                        gathering_tasks.push(task);
                    }
                }
            }

            if self.config.enable_ipv6 {
                for &ipv6 in &interface.ipv6_addresses {
                    if self.should_use_ipv6_address(&ipv6) {
                        let task = self.gather_host_candidates_for_address(
                            IpAddr::V6(ipv6),
                            component_id,
                            interface_name.clone(),
                            interface.clone(),
                        );
                        gathering_tasks.push(task);
                    }
                }
            }
        }

        // Execute gathering tasks with concurrency control
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_stun));
        let mut task_handles = Vec::new();

        for task in gathering_tasks {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let handle = tokio::spawn(async move {
                let result = task.await;
                drop(permit);
                result
            });
            task_handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut successful_candidates = 0;
        let mut failed_attempts = 0;

        for handle in task_handles {
            match handle.await {
                Ok(Ok(candidates)) => {
                    successful_candidates += candidates.len();
                    for candidate in candidates {
                        self.add_candidate(candidate, component_id).await?;
                    }
                }
                Ok(Err(e)) => {
                    failed_attempts += 1;
                    debug!("Host candidate gathering failed: {}", e);
                }
                Err(e) => {
                    failed_attempts += 1;
                    debug!("Host candidate gathering task panicked: {}", e);
                }
            }
        }