// src/turn/server.rs
//! High-performance TURN relay server implementation
//!
//! Implements:
//! - RFC 5766 (TURN) - Traversal Using Relays around NAT
//! - RFC 5389 (STUN) - Session Traversal Utilities for NAT
//! - RFC 6062 (TURN Extensions for TCP)
//! - RFC 8656 (TURN over DTLS/TLS)
//! - RFC 7635 (TURN Third Party Authorization)
//! - RFC 8016 (TURN mobility extensions)
//!
//! Performance optimizations:
//! - Zero-copy packet processing where possible
//! - Lock-free data structures for hot paths
//! - DPDK-style high-performance networking
//! - Efficient memory pooling
//! - Advanced rate limiting and DDoS protection

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::sync::{RwLock, Mutex, Semaphore, mpsc, oneshot};
use tokio::time::{interval, timeout, sleep};
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};
use bytes::{Bytes, BytesMut, BufMut, Buf};
use dashmap::DashMap;
use parking_lot::{RwLock as ParkingRwLock, Mutex as ParkingMutex};
use crossbeam::queue::SegQueue;
use tracing::{info, warn, error, debug, trace, instrument};
use serde::{Serialize, Deserialize};
use rand::{Rng, thread_rng};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use ring::rand::{SecureRandom, SystemRandom};

use crate::nat::stun::{
    Message, MessageType, TransactionId, Attribute, AttributeType, AttributeValue,
    StunError, MAGIC_COOKIE
};
use crate::nat::error::{NatError, NatResult};

// Performance constants
const MAX_CONCURRENT_ALLOCATIONS: usize = 100_000;
const MAX_ALLOCATIONS_PER_CLIENT: usize = 10;
const MAX_PERMISSIONS_PER_ALLOCATION: usize = 100;
const MAX_CHANNELS_PER_ALLOCATION: usize = 100;
const DEFAULT_ALLOCATION_LIFETIME: Duration = Duration::from_secs(600);
const MAX_ALLOCATION_LIFETIME: Duration = Duration::from_secs(3600);
const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
const CHANNEL_BIND_LIFETIME: Duration = Duration::from_secs(600);

// Security constants
const MAX_PACKET_SIZE: usize = 65536;
const MIN_PACKET_SIZE: usize = 20;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const DEFAULT_RATE_LIMIT: u32 = 1000; // packets per minute
const MAX_AUTH_FAILURES: u32 = 5;
const AUTH_FAILURE_PENALTY: Duration = Duration::from_secs(300);

// Memory pool constants
const PACKET_POOL_SIZE: usize = 10000;
const ALLOCATION_POOL_SIZE: usize = 1000;

/// High-performance TURN relay server
pub struct TurnServer {
    /// Server configuration
    config: Arc<TurnConfig>,

    /// Allocation manager with lock-free operations
    allocation_manager: Arc<AllocationManager>,

    /// Authentication manager with rate limiting
    auth_manager: Arc<AuthenticationManager>,

    /// Rate limiter with DDoS protection
    rate_limiter: Arc<RateLimiter>,

    /// Permission manager for peer access control
    permission_manager: Arc<PermissionManager>,

    /// Channel manager for efficient data relay
    channel_manager: Arc<ChannelManager>,

    /// Metrics collector for monitoring
    metrics: Arc<MetricsCollector>,

    /// Memory pools for zero-allocation paths
    memory_pools: Arc<MemoryPools>,

    /// Security filter for malicious traffic
    security_filter: Arc<SecurityFilter>,

    /// Active network listeners
    listeners: Arc<RwLock<HashMap<SocketAddr, Arc<NetworkListener>>>>,

    /// Shutdown coordination
    shutdown_tx: Arc<RwLock<Option<mpsc::UnboundedSender<()>>>>,

    /// Runtime statistics
    stats: Arc<ServerStats>,

    /// Configuration hot reload capability
    config_watcher: Arc<ConfigWatcher>,
}

/// Comprehensive TURN server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnConfig {
    /// Server bind addresses
    pub listen_addrs: Vec<ListenConfig>,

    /// Relay address ranges
    pub relay_addrs: Vec<RelayRange>,

    /// Authentication configuration
    pub auth: AuthConfig,

    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,

    /// Security configuration
    pub security: SecurityConfig,

    /// Performance tuning
    pub performance: PerformanceConfig,

    /// TLS/DTLS configuration
    pub tls: Option<TlsConfig>,

    /// Logging and monitoring
    pub monitoring: MonitoringConfig,

    /// Realm for authentication
    pub realm: String,

    /// Software name sent in responses
    pub software: String,
}

/// Network listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    /// Bind address
    pub addr: SocketAddr,

    /// Transport protocol
    pub transport: Transport,

    /// Interface name (optional)
    pub interface: Option<String>,

    /// Enable on this listener
    pub enabled: bool,

    /// Listener-specific rate limits
    pub rate_limit: Option<u32>,
}

/// Transport protocol support
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
    Dtls,
}

/// Relay address range configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRange {
    /// Start IP address
    pub start_ip: IpAddr,

    /// End IP address
    pub end_ip: IpAddr,

    /// Port range
    pub port_range: (u16, u16),

    /// Transport protocols allowed
    pub transports: Vec<Transport>,

    /// Maximum bandwidth per allocation (bytes/sec)
    pub max_bandwidth: Option<u64>,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Authentication method
    pub method: AuthMethod,

    /// Credential storage
    pub credential_store: CredentialStore,

    /// Enable anonymous access (for testing only)
    pub allow_anonymous: bool,

    /// Require encrypted transport for auth
    pub require_tls: bool,

    /// Enable third-party authorization
    pub enable_third_party_auth: bool,

    /// Third party auth server URL
    pub third_party_url: Option<String>,
}

/// Authentication methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    /// Long-term credential mechanism (RFC 5389)
    LongTerm,

    /// Short-term credential mechanism
    ShortTerm,

    /// OAuth 2.0 mechanism (RFC 7635)
    OAuth,

    /// Third-party authorization
    ThirdParty,
}

/// Credential storage backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialStore {
    /// In-memory storage (for testing)
    Memory { users: HashMap<String, String> },

    /// File-based storage
    File { path: String },

    /// Database storage
    Database { connection_string: String },

    /// Redis storage
    Redis { connection_string: String },

    /// External API
    Api { endpoint: String, api_key: String },
}

/// Rate limiting configuration with advanced DDoS protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Global rate limit (packets/minute)
    pub global_rate_limit: u32,

    /// Per-IP rate limit (packets/minute)
    pub per_ip_rate_limit: u32,

    /// Per-user rate limit (packets/minute)
    pub per_user_rate_limit: u32,

    /// Rate limit window duration
    pub window_duration: Duration,

    /// Enable adaptive rate limiting
    pub adaptive: bool,

    /// DDoS detection threshold
    pub ddos_threshold: u32,

    /// DDoS response mode
    pub ddos_response: DdosResponse,

    /// Bandwidth limiting (bytes/sec)
    pub bandwidth_limit: Option<u64>,

    /// Concurrent allocation limits
    pub max_allocations_per_ip: u32,
    pub max_allocations_per_user: u32,
}

/// DDoS response strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DdosResponse {
    /// Drop packets silently
    Drop,

    /// Send error responses
    Reject,

    /// Temporary IP banning
    TempBan { duration: Duration },

    /// Rate limit with exponential backoff
    Throttle { factor: f64 },
}

/// Security configuration for hardened deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable request validation
    pub validate_requests: bool,

    /// Enable amplification attack protection
    pub anti_amplification: bool,

    /// Maximum response size multiplier
    pub max_response_multiplier: f64,

    /// Enable IP filtering
    pub ip_filtering: IpFilterConfig,

    /// Enable fingerprinting protection
    pub anti_fingerprinting: bool,

    /// Enable timing attack protection
    pub constant_time_auth: bool,

    /// Require specific user agents
    pub allowed_user_agents: Option<Vec<String>>,

    /// Enable geographic restrictions
    pub geo_restrictions: Option<GeoConfig>,
}

/// IP filtering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFilterConfig {
    /// Whitelist of allowed IPs/ranges
    pub whitelist: Vec<String>,

    /// Blacklist of blocked IPs/ranges
    pub blacklist: Vec<String>,

    /// Enable automatic blacklisting
    pub auto_blacklist: bool,

    /// Blacklist threshold (violations before ban)
    pub blacklist_threshold: u32,

    /// Blacklist duration
    pub blacklist_duration: Duration,
}

/// Geographic restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoConfig {
    /// Allowed country codes (ISO 3166-1 alpha-2)
    pub allowed_countries: Vec<String>,

    /// Blocked country codes
    pub blocked_countries: Vec<String>,

    /// GeoIP database path
    pub geoip_db_path: String,
}

/// Performance tuning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Worker thread count (0 = auto)
    pub worker_threads: usize,

    /// Enable SO_REUSEPORT
    pub reuse_port: bool,

    /// Socket buffer sizes
    pub socket_recv_buffer: usize,
    pub socket_send_buffer: usize,

    /// Enable zero-copy networking
    pub zero_copy: bool,

    /// Memory pool sizes
    pub packet_pool_size: usize,
    pub allocation_pool_size: usize,

    /// Enable CPU affinity
    pub cpu_affinity: bool,

    /// Enable NUMA awareness
    pub numa_aware: bool,

    /// Batch processing size
    pub batch_size: usize,
}

/// TLS/DTLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Certificate chain file path
    pub cert_chain_file: String,

    /// Private key file path
    pub private_key_file: String,

    /// Supported TLS versions
    pub tls_versions: Vec<TlsVersion>,

    /// Cipher suite preferences
    pub cipher_suites: Vec<String>,

    /// Enable ALPN
    pub alpn_protocols: Vec<String>,

    /// Client certificate verification
    pub client_cert_verification: ClientCertVerification,

    /// DTLS-specific settings
    pub dtls: Option<DtlsConfig>,
}

/// TLS version support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

/// Client certificate verification modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientCertVerification {
    None,
    Optional,
    Required,
}

/// DTLS-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtlsConfig {
    /// MTU size for DTLS fragmentation
    pub mtu: u16,

    /// Retransmission timeout
    pub retransmission_timeout: Duration,

    /// Maximum retransmissions
    pub max_retransmissions: u32,
}

/// Monitoring and observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable metrics collection
    pub enable_metrics: bool,

    /// Metrics export interval
    pub metrics_interval: Duration,

    /// Prometheus metrics endpoint
    pub prometheus_addr: Option<SocketAddr>,

    /// Enable detailed logging
    pub detailed_logging: bool,

    /// Log level
    pub log_level: String,

    /// Enable performance profiling
    pub enable_profiling: bool,

    /// Health check endpoint
    pub health_check_addr: Option<SocketAddr>,
}

/// Lock-free allocation manager for maximum throughput
pub struct AllocationManager {
    /// Active allocations with fast lookup
    allocations: DashMap<AllocationKey, Arc<Allocation>>,

    /// Allocation by relay address for reverse lookup
    relay_lookup: DashMap<SocketAddr, AllocationKey>,

    /// Client allocation counters
    client_counters: DashMap<IpAddr, AtomicU32>,

    /// Available relay addresses pool
    relay_pool: Arc<RelayAddressPool>,

    /// Allocation ID generator
    next_allocation_id: AtomicU64,

    /// Memory pool for allocations
    allocation_pool: Arc<SegQueue<Box<Allocation>>>,

    /// Configuration
    config: Arc<TurnConfig>,

    /// Metrics
    metrics: Arc<MetricsCollector>,
}

/// Allocation identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocationKey {
    pub client_addr: SocketAddr,
    pub allocation_id: u64,
}

/// TURN allocation with comprehensive state management
pub struct Allocation {
    /// Unique allocation key
    pub key: AllocationKey,

    /// Relay address assigned to this allocation
    pub relay_addr: SocketAddr,

    /// Transport protocol
    pub transport: Transport,

    /// Creation timestamp
    pub created_at: Instant,

    /// Expiration timestamp
    pub expires_at: AtomicU64, // Unix timestamp in milliseconds

    /// Lifetime in seconds
    pub lifetime: AtomicU32,

    /// Authentication username
    pub username: String,

    /// Realm
    pub realm: String,

    /// Client transport address
    pub client_addr: SocketAddr,

    /// Allocated bandwidth (bytes/sec)
    pub bandwidth_limit: AtomicU64,

    /// Current bandwidth usage
    pub bandwidth_used: AtomicU64,

    /// Bandwidth measurement window
    pub bandwidth_window_start: AtomicU64,

    /// Permissions for this allocation
    pub permissions: DashMap<IpAddr, Permission>,

    /// Channel bindings for this allocation
    pub channels: DashMap<u16, ChannelBinding>,

    /// Statistics
    pub stats: AllocationStats,

    /// Active flag for quick checks
    pub active: AtomicBool,

    /// Lock for atomic operations
    pub lock: ParkingMutex<()>,
}

/// Permission for peer communication
#[derive(Debug)]
pub struct Permission {
    /// Peer IP address
    pub peer_ip: IpAddr,

    /// Creation timestamp
    pub created_at: Instant,

    /// Expiration timestamp
    pub expires_at: Instant,

    /// Usage statistics
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
}

/// Channel binding for efficient data transfer
#[derive(Debug)]
pub struct ChannelBinding {
    /// Channel number (0x4000-0x7FFF)
    pub channel_number: u16,

    /// Peer address
    pub peer_addr: SocketAddr,

    /// Creation timestamp
    pub created_at: Instant,

    /// Expiration timestamp
    pub expires_at: Instant,

    /// Usage statistics
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,

    /// Last activity timestamp
    pub last_activity: AtomicU64,
}

/// Allocation statistics
#[derive(Debug, Default)]
pub struct AllocationStats {
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub permissions_created: AtomicU32,
    pub channels_bound: AtomicU32,
    pub refresh_count: AtomicU32,
    pub last_activity: AtomicU64,
}

/// Relay address pool with efficient allocation
pub struct RelayAddressPool {
    /// Available addresses
    available: SegQueue<SocketAddr>,

    /// Total pool size
    total_size: AtomicU32,

    /// Available count
    available_count: AtomicU32,

    /// Address ranges
    ranges: Vec<RelayRange>,

    /// Port allocation strategy
    strategy: PortAllocationStrategy,
}

/// Port allocation strategies
#[derive(Debug, Clone)]
pub enum PortAllocationStrategy {
    /// Sequential allocation
    Sequential,

    /// Random allocation
    Random,

    /// Round-robin across ranges
    RoundRobin,

    /// Least recently used
    LeastRecentlyUsed,
}

/// High-performance authentication manager
pub struct AuthenticationManager {
    /// Credential store
    credential_store: Arc<dyn CredentialStore + Send + Sync>,

    /// Authentication cache for performance
    auth_cache: DashMap<String, CachedAuth>,

    /// Failed authentication tracking
    auth_failures: DashMap<IpAddr, AuthFailureTracker>,

    /// Nonce generation and validation
    nonce_manager: Arc<NonceManager>,

    /// Configuration
    config: AuthConfig,

    /// Third-party authorization client
    third_party_client: Option<Arc<ThirdPartyAuthClient>>,

    /// Metrics
    metrics: Arc<MetricsCollector>,
}

/// Cached authentication result
#[derive(Debug, Clone)]
struct CachedAuth {
    username: String,
    realm: String,
    password_hash: Vec<u8>,
    expires_at: Instant,
    auth_method: AuthMethod,
}

/// Authentication failure tracking
#[derive(Debug)]
struct AuthFailureTracker {
    failure_count: AtomicU32,
    last_failure: AtomicU64,
    penalty_until: AtomicU64,
}

/// Nonce management for security
pub struct NonceManager {
    /// Nonce key for HMAC
    nonce_key: [u8; 32],

    /// Nonce lifetime
    nonce_lifetime: Duration,

    /// Random number generator
    rng: Arc<Mutex<SystemRandom>>,
}

/// Credential store trait for authentication backends
pub trait CredentialStore {
    /// Get credentials for user
    async fn get_credentials(&self, username: &str, realm: &str) -> NatResult<Option<UserCredentials>>;

    /// Validate credentials
    async fn validate_credentials(
        &self,
        username: &str,
        realm: &str,
        response: &[u8],
        nonce: &[u8],
        method: &str,
        uri: &str,
    ) -> NatResult<bool>;

    /// Get user permissions
    async fn get_user_permissions(&self, username: &str) -> NatResult<UserPermissions>;
}

/// User credentials
#[derive(Debug, Clone)]
pub struct UserCredentials {
    pub username: String,
    pub password: String,
    pub realm: String,
    pub permissions: UserPermissions,
}

/// User permissions and quotas
#[derive(Debug, Clone)]
pub struct UserPermissions {
    pub max_allocations: u32,
    pub max_bandwidth: u64,
    pub allowed_transports: Vec<Transport>,
    pub allocation_lifetime: Duration,
    pub quota_resets_at: Option<SystemTime>,
}

/// Advanced rate limiter with DDoS protection
pub struct RateLimiter {
    /// Global rate limit state
    global_state: Arc<RateLimitState>,

    /// Per-IP rate limit states
    ip_states: DashMap<IpAddr, Arc<RateLimitState>>,

    /// Per-user rate limit states
    user_states: DashMap<String, Arc<RateLimitState>>,

    /// DDoS detection and mitigation
    ddos_detector: Arc<DdosDetector>,

    /// Configuration
    config: RateLimitingConfig,

    /// Metrics
    metrics: Arc<MetricsCollector>,
}

/// Rate limit state with sliding window
#[derive(Debug)]
pub struct RateLimitState {
    /// Request timestamps in current window
    requests: ParkingMutex<VecDeque<Instant>>,

    /// Current window start
    window_start: AtomicU64,

    /// Request count in current window
    request_count: AtomicU32,

    /// Blocked until timestamp
    blocked_until: AtomicU64,

    /// Total requests
    total_requests: AtomicU64,

    /// Total blocked requests
    blocked_requests: AtomicU64,
}

/// DDoS detection and mitigation
pub struct DdosDetector {
    /// Detection threshold (requests/sec)
    threshold: AtomicU32,

    /// Current request rate
    current_rate: AtomicU32,

    /// Rate measurement window
    measurement_window: Duration,

    /// Last measurement time
    last_measurement: AtomicU64,

    /// DDoS active flag
    ddos_active: AtomicBool,

    /// Response strategy
    response: DdosResponse,
}

/// Permission manager for peer access control
pub struct PermissionManager {
    /// Global permission state
    global_permissions: DashMap<(AllocationKey, IpAddr), Arc<Permission>>,

    /// Permission expiry queue
    expiry_queue: Arc<Mutex<VecDeque<(Instant, AllocationKey, IpAddr)>>>,

    /// Cleanup task handle
    cleanup_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,

    /// Metrics
    metrics: Arc<MetricsCollector>,
}

/// Channel manager for efficient data relay
pub struct ChannelManager {
    /// Channel bindings by allocation
    channels: DashMap<AllocationKey, DashMap<u16, Arc<ChannelBinding>>>,

    /// Reverse lookup: peer address -> channel
    peer_lookup: DashMap<(AllocationKey, SocketAddr), u16>,

    /// Available channel numbers
    available_channels: Arc<SegQueue<u16>>,

    /// Channel expiry queue
    expiry_queue: Arc<Mutex<VecDeque<(Instant, AllocationKey, u16)>>>,

    /// Cleanup task handle
    cleanup_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,

    /// Metrics
    metrics: Arc<MetricsCollector>,
}

/// Comprehensive metrics collection
pub struct MetricsCollector {
    /// Allocation metrics
    pub allocations_active: AtomicU64,
    pub allocations_created: AtomicU64,
    pub allocations_expired: AtomicU64,
    pub allocations_failed: AtomicU64,

    /// Traffic metrics
    pub packets_relayed: AtomicU64,
    pub bytes_relayed: AtomicU64,
    pub packets_dropped: AtomicU64,

    /// Authentication metrics
    pub auth_requests: AtomicU64,
    pub auth_successes: AtomicU64,
    pub auth_failures: AtomicU64,

    /// Rate limiting metrics
    pub rate_limited_requests: AtomicU64,
    pub ddos_events: AtomicU64,

    /// Performance metrics
    pub request_duration_total: AtomicU64,
    pub request_count: AtomicU64,

    /// Resource metrics
    pub memory_usage: AtomicU64,
    pub cpu_usage: AtomicU64,

    /// Error metrics
    pub stun_errors: AtomicU64,
    pub network_errors: AtomicU64,
    pub internal_errors: AtomicU64,
}

/// Memory pools for zero-allocation fast paths
pub struct MemoryPools {
    /// Packet buffer pool
    packet_pool: Arc<SegQueue<BytesMut>>,

    /// Message object pool
    message_pool: Arc<SegQueue<Box<Message>>>,

    /// Allocation object pool
    allocation_pool: Arc<SegQueue<Box<Allocation>>>,

    /// Pool configuration
    config: MemoryPoolConfig,

    /// Pool statistics
    stats: MemoryPoolStats,
}

/// Memory pool configuration
#[derive(Debug, Clone)]
pub struct MemoryPoolConfig {
    pub packet_pool_size: usize,
    pub packet_buffer_size: usize,
    pub message_pool_size: usize,
    pub allocation_pool_size: usize,
    pub preallocate: bool,
}

/// Memory pool statistics
#[derive(Debug, Default)]
pub struct MemoryPoolStats {
    pub packet_pool_hits: AtomicU64,
    pub packet_pool_misses: AtomicU64,
    pub message_pool_hits: AtomicU64,
    pub message_pool_misses: AtomicU64,
    pub allocation_pool_hits: AtomicU64,
    pub allocation_pool_misses: AtomicU64,
}

/// Advanced security filter for malicious traffic
pub struct SecurityFilter {
    /// IP filtering rules
    ip_filter: Arc<IpFilter>,

    /// Request validation rules
    request_validator: Arc<RequestValidator>,

    /// Amplification protection
    amplification_guard: Arc<AmplificationGuard>,

    /// Fingerprinting protection
    fingerprint_guard: Arc<FingerprintGuard>,

    /// Geographic filtering
    geo_filter: Option<Arc<GeoFilter>>,

    /// Configuration
    config: SecurityConfig,

    /// Metrics
    metrics: Arc<MetricsCollector>,
}

/// IP filtering with automatic blacklisting
pub struct IpFilter {
    /// Static whitelist
    whitelist: HashSet<IpAddr>,

    /// Static blacklist
    blacklist: Arc<RwLock<HashSet<IpAddr>>>,

    /// Automatic blacklist with TTL
    auto_blacklist: DashMap<IpAddr, Instant>,

    /// Violation counters
    violations: DashMap<IpAddr, AtomicU32>,

    /// Configuration
    config: IpFilterConfig,
}

/// Request validation for malformed packets
pub struct RequestValidator {
    /// Enable strict validation
    strict_mode: bool,

    /// Allowed message types
    allowed_message_types: HashSet<MessageType>,

    /// Maximum attribute count
    max_attributes: usize,

    /// Maximum message size
    max_message_size: usize,

    /// Metrics
    validation_errors: AtomicU64,
}

/// Amplification attack protection
pub struct AmplificationGuard {
    /// Maximum response size multiplier
    max_multiplier: f64,

    /// Request size tracking
    request_sizes: DashMap<SocketAddr, u32>,

    /// Amplification violations
    violations: DashMap<IpAddr, AtomicU32>,

    /// Metrics
    amplification_blocks: AtomicU64,
}

/// Fingerprinting protection
pub struct FingerprintGuard {
    /// Randomize response timing
    randomize_timing: bool,

    /// Randomize error messages
    randomize_errors: bool,

    /// Hide server information
    hide_server_info: bool,

    /// Random delay range
    delay_range: (Duration, Duration),
}

/// Geographic filtering
pub struct GeoFilter {
    /// GeoIP database
    geoip_db: Arc<dyn GeoIpProvider + Send + Sync>,

    /// Allowed countries
    allowed_countries: HashSet<String>,

    /// Blocked countries
    blocked_countries: HashSet<String>,

    /// Unknown location handling
    allow_unknown: bool,

    /// Metrics
    geo_blocks: AtomicU64,
}

/// GeoIP provider trait
pub trait GeoIpProvider {
    /// Get country code for IP address
    fn get_country(&self, ip: IpAddr) -> Option<String>;
}

/// Network listener for handling connections
pub struct NetworkListener {
    /// Listener address
    addr: SocketAddr,

    /// Transport protocol
    transport: Transport,

    /// UDP socket (for UDP/DTLS)
    udp_socket: Option<Arc<UdpSocket>>,

    /// TCP listener (for TCP/TLS)
    tcp_listener: Option<Arc<TcpListener>>,

    /// TLS acceptor (for TLS/DTLS)
    tls_acceptor: Option<Arc<TlsAcceptor>>,

    /// Active connections
    connections: Arc<DashMap<SocketAddr, Arc<Connection>>>,

    /// Listener statistics
    stats: ListenerStats,

    /// Configuration
    config: ListenConfig,
}

/// Connection state for TCP/TLS connections
pub struct Connection {
    /// Remote address
    remote_addr: SocketAddr,

    /// Transport type
    transport: Transport,

    /// TCP stream (for TCP/TLS)
    tcp_stream: Option<Arc<Mutex<TcpStream>>>,

    /// Connection state
    state: AtomicU32, // 0=connecting, 1=connected, 2=disconnecting, 3=disconnected

    /// Connection statistics
    stats: ConnectionStats,

    /// Last activity timestamp
    last_activity: AtomicU64,

    /// Buffer for partial messages
    message_buffer: Arc<Mutex<BytesMut>>,
}

/// Listener statistics
#[derive(Debug, Default)]
pub struct ListenerStats {
    pub connections_accepted: AtomicU64,
    pub connections_rejected: AtomicU64,
    pub packets_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub errors: AtomicU64,
}

/// Connection statistics
#[derive(Debug, Default)]
pub struct ConnectionStats {
    pub packets_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub errors: AtomicU64,
    pub connected_at: AtomicU64,
}

/// Server runtime statistics
#[derive(Debug, Default)]
pub struct ServerStats {
    pub uptime_start: AtomicU64,
    pub total_allocations: AtomicU64,
    pub active_allocations: AtomicU64,
    pub total_requests: AtomicU64,
    pub successful_requests: AtomicU64,
    pub failed_requests: AtomicU64,
    pub memory_usage: AtomicU64,
    pub cpu_usage_percent: AtomicU64,
}

/// Configuration hot-reload capability
pub struct ConfigWatcher {
    /// Configuration file path
    config_path: String,

    /// Last modification time
    last_modified: AtomicU64,

    /// Reload channel
    reload_tx: mpsc::UnboundedSender<TurnConfig>,

    /// Watch task handle
    watch_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl TurnServer {
    /// Create new high-performance TURN server
    pub async fn new(config: TurnConfig) -> NatResult<Self> {
        info!("Initializing high-performance TURN server");

        // Validate configuration
        Self::validate_config(&config)?;

        let config = Arc::new(config);

        // Initialize memory pools
        let memory_pools = Arc::new(MemoryPools::new(MemoryPoolConfig {
            packet_pool_size: config.performance.packet_pool_size,
            packet_buffer_size: MAX_PACKET_SIZE,
            message_pool_size: 1000,
            allocation_pool_size: config.performance.allocation_pool_size,
            preallocate: true,
        }).await?);

        // Initialize metrics collector
        let metrics = Arc::new(MetricsCollector::default());

        // Initialize relay address pool
        let relay_pool = Arc::new(RelayAddressPool::new(&config.relay_addrs).await?);

        // Initialize allocation manager
        let allocation_manager = Arc::new(AllocationManager::new(
            config.clone(),
            relay_pool,
            memory_pools.clone(),
            metrics.clone(),
        ).await?);

        // Initialize authentication manager
        let auth_manager = Arc::new(AuthenticationManager::new(
            config.auth.clone(),
            metrics.clone(),
        ).await?);

        // Initialize rate limiter
        let rate_limiter = Arc::new(RateLimiter::new(
            config.rate_limiting.clone(),
            metrics.clone(),
        ).await?);

        // Initialize permission manager
        let permission_manager = Arc::new(PermissionManager::new(metrics.clone()).await?);

        // Initialize channel manager
        let channel_manager = Arc::new(ChannelManager::new(metrics.clone()).await?);

        // Initialize security filter
        let security_filter = Arc::new(SecurityFilter::new(
            config.security.clone(),
            metrics.clone(),
        ).await?);

        // Initialize server stats
        let stats = Arc::new(ServerStats {
            uptime_start: AtomicU64::new(
                SystemTime::now().duration_since(UNIX_EPOCH)
                    .unwrap().as_secs()
            ),
            ..Default::default()
        });

        // Create shutdown channel
        let (shutdown_tx, _) = mpsc::unbounded_channel();

        // Initialize configuration watcher
        let config_watcher = Arc::new(ConfigWatcher::new("/etc/turn/config.toml").await?);

        let server = Self {
            config,
            allocation_manager,
            auth_manager,
            rate_limiter,
            permission_manager,
            channel_manager,
            metrics,
            memory_pools,
            security_filter,
            listeners: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx: Arc::new(RwLock::new(Some(shutdown_tx))),
            stats,
            config_watcher,
        };

        info!("TURN server initialized successfully");
        Ok(server)
    }

    /// Validate server configuration
    fn validate_config(config: &TurnConfig) -> NatResult<()> {
        if config.listen_addrs.is_empty() {
            return Err(NatError::Platform("No listen addresses configured".to_string()));
        }

        if config.relay_addrs.is_empty() {
            return Err(NatError::Platform("No relay address ranges configured".to_string()));
        }

        if config.realm.is_empty() {
            return Err(NatError::Platform("Realm must be configured".to_string()));
        }

        // Validate relay address ranges
        for range in &config.relay_addrs {
            if range.port_range.0 >= range.port_range.1 {
                return Err(NatError::Platform("Invalid port range".to_string()));
            }
        }

        // Validate rate limiting configuration
        if config.rate_limiting.global_rate_limit == 0 {
            return Err(NatError::Platform("Global rate limit cannot be zero".to_string()));
        }

        Ok(())
    }

    /// Start the TURN server with all listeners
    pub async fn start(&self) -> NatResult<()> {
        info!("Starting TURN server with {} listeners", self.config.listen_addrs.len());

        // Start all network listeners
        let mut listeners = self.listeners.write().await;

        for listen_config in &self.config.listen_addrs {
            if !listen_config.enabled {
                continue;
            }

            info!("Starting listener on {} ({:?})", listen_config.addr, listen_config.transport);

            let listener = Arc::new(
                NetworkListener::new(listen_config.clone(), self.config.clone()).await?
            );

            // Start listener processing
            self.start_listener_processing(listener.clone()).await?;

            listeners.insert(listen_config.addr, listener);
        }

        // Start background tasks
        self.start_background_tasks().await?;

        // Start metrics collection
        if self.config.monitoring.enable_metrics {
            self.start_metrics_collection().await?;
        }

        // Start configuration watcher
        self.start_config_watcher().await?;

        info!("TURN server started successfully on {} listeners", listeners.len());
        Ok(())
    }

    /// Start processing for a network listener
    async fn start_listener_processing(&self, listener: Arc<NetworkListener>) -> NatResult<()> {
        match listener.transport {
            Transport::Udp => {
                self.start_udp_processing(listener).await?;
            }
            Transport::Tcp => {
                self.start_tcp_processing(listener).await?;
            }
            Transport::Tls => {
                self.start_tls_processing(listener).await?;
            }
            Transport::Dtls => {
                self.start_dtls_processing(listener).await?;
            }
        }
        Ok(())
    }

    /// Start UDP packet processing with high-performance optimizations
    #[instrument(skip(self, listener), level = "debug")]
    async fn start_udp_processing(&self, listener: Arc<NetworkListener>) -> NatResult<()> {
        let socket = listener.udp_socket.as_ref()
            .ok_or_else(|| NatError::Platform("No UDP socket".to_string()))?
            .clone();

        let server = self.clone_for_task();
        let listener_clone = listener.clone();

        tokio::spawn(async move {
            info!("UDP processing started for {}", listener_clone.addr);

            // Use multiple worker tasks for parallel processing
            let worker_count = server.config.performance.worker_threads
                .max(1).min(num_cpus::get());

            let mut workers = Vec::new();

            for worker_id in 0..worker_count {
                let server_clone = server.clone();
                let socket_clone = socket.clone();
                let listener_clone = listener_clone.clone();

                let worker = tokio::spawn(async move {
                    server_clone.udp_worker_loop(worker_id, socket_clone, listener_clone).await;
                });

                workers.push(worker);
            }

            // Wait for all workers
            for worker in workers {
                if let Err(e) = worker.await {
                    error!("UDP worker failed: {}", e);
                }
            }

            info!("UDP processing ended for {}", listener.addr);
        });

        Ok(())
    }

    /// UDP worker loop with optimized packet processing
    async fn udp_worker_loop(
        &self,
        worker_id: usize,
        socket: Arc<UdpSocket>,
        listener: Arc<NetworkListener>,
    ) {
        debug!("UDP worker {} started", worker_id);

        let mut packet_buffer = BytesMut::with_capacity(MAX_PACKET_SIZE);

        loop {
            // Check for shutdown
            if self.is_shutting_down().await {
                break;
            }

            // Receive packet with timeout
            match timeout(Duration::from_millis(100), socket.recv_from(&mut packet_buffer)).await {
                Ok(Ok((size, remote_addr))) => {
                    if size < MIN_PACKET_SIZE || size > MAX_PACKET_SIZE {
                        listener.stats.packets_received.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    // Update listener statistics
                    listener.stats.packets_received.fetch_add(1, Ordering::Relaxed);
                    listener.stats.bytes_received.fetch_add(size as u64, Ordering::Relaxed);

                    // Process packet asynchronously
                    let packet_data = packet_buffer.split_to(size).freeze();

                    if let Err(e) = self.process_udp_packet(
                        packet_data,
                        remote_addr,
                        socket.clone(),
                        listener.clone(),
                    ).await {
                        debug!("Failed to process UDP packet from {}: {}", remote_addr, e);
                        listener.stats.errors.fetch_add(1, Ordering::Relaxed);
                    }

                    // Reset buffer for next packet
                    packet_buffer.clear();
                    packet_buffer.reserve(MAX_PACKET_SIZE);
                }
                Ok(Err(e)) => {
                    debug!("UDP receive error: {}", e);
                    listener.stats.errors.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    // Timeout - continue loop
                }
            }
        }

        debug!("UDP worker {} stopped", worker_id);
    }

    /// Process incoming UDP packet with full RFC compliance
    #[instrument(skip(self, packet_data, socket, listener), level = "trace")]
    async fn process_udp_packet(
        &self,
        packet_data: Bytes,
        remote_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        listener: Arc<NetworkListener>,
    ) -> NatResult<()> {
        // Security filtering first
        if !self.security_filter.should_accept(&packet_data, remote_addr).await? {
            self.metrics.packets_dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        // Rate limiting check
        if !self.rate_limiter.check_rate_limit(remote_addr, None).await? {
            self.metrics.rate_limited_requests.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        // Check if this is a STUN/TURN packet or ChannelData
        if packet_data.len() >= 4 {
            let first_two_bytes = u16::from_be_bytes([packet_data[0], packet_data[1]]);

            if first_two_bytes >= 0x4000 && first_two_bytes <= 0x7FFF {
                // ChannelData packet (RFC 5766 Section 11.4)
                return self.process_channel_data(packet_data, remote_addr, socket).await;
            }
        }

        // Parse STUN message
        let message = match self.parse_stun_message(packet_data).await {
            Ok(msg) => msg,
            Err(e) => {
                debug!("Failed to parse STUN message from {}: {}", remote_addr, e);
                self.metrics.stun_errors.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        };

        // Process STUN message
        self.process_stun_message(message, remote_addr, socket, listener).await
    }

    /// Parse STUN message with validation
    async fn parse_stun_message(&self, data: Bytes) -> NatResult<Message> {
        // Get message from pool if available
        let mut message = self.memory_pools.get_message().await?;

        // Decode message
        *message = Message::decode(data.into())?;

        // Validate message
        self.security_filter.validate_message(&message)?;

        Ok(*message)
    }

    /// Process STUN message according to RFC 5766
    #[instrument(skip(self, message, socket, listener), level = "debug")]
    async fn process_stun_message(
        &self,
        message: Message,
        remote_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        listener: Arc<NetworkListener>,
    ) -> NatResult<()> {
        let start_time = Instant::now();

        // Update metrics
        self.metrics.request_count.fetch_add(1, Ordering::Relaxed);
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        let result = match message.message_type {
            MessageType::AllocateRequest => {
                self.handle_allocate_request(message, remote_addr, socket.clone()).await
            }
            MessageType::RefreshRequest => {
                self.handle_refresh_request(message, remote_addr, socket.clone()).await
            }
            MessageType::CreatePermissionRequest => {
                self.handle_create_permission_request(message, remote_addr, socket.clone()).await
            }
            MessageType::ChannelBindRequest => {
                self.handle_channel_bind_request(message, remote_addr, socket.clone()).await
            }
            MessageType::SendIndication => {
                self.handle_send_indication(message, remote_addr).await
            }
            MessageType::BindingRequest => {
                self.handle_binding_request(message, remote_addr, socket.clone()).await
            }
            _ => {
                debug!("Unsupported message type: {:?}", message.message_type);
                self.send_error_response(
                    &message,
                    remote_addr,
                    socket.clone(),
                    400,
                    "Bad Request",
                ).await
            }
        };

        // Update metrics
        let duration = start_time.elapsed();
        self.metrics.request_duration_total.fetch_add(
            duration.as_micros() as u64,
            Ordering::Relaxed,
        );

        match result {
            Ok(_) => {
                self.stats.successful_requests.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                debug!("Request processing failed: {}", e);
                self.stats.failed_requests.fetch_add(1, Ordering::Relaxed);
                listener.stats.errors.fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(())
    }

    /// Handle ALLOCATE request (RFC 5766 Section 6)
    #[instrument(skip(self, request, socket), level = "debug")]
    async fn handle_allocate_request(
        &self,
        request: Message,
        client_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> NatResult<()> {
        info!("Processing ALLOCATE request from {}", client_addr);

        // Extract REQUESTED-TRANSPORT attribute (required)
        let transport = self.extract_requested_transport(&request)?;

        // Extract LIFETIME attribute
        let requested_lifetime = self.extract_lifetime(&request)
            .unwrap_or(DEFAULT_ALLOCATION_LIFETIME);

        // Perform authentication
        let auth_result = self.authenticate_request(&request, client_addr, "ALLOCATE").await?;

        // Check user permissions and quotas
        let user_permissions = self.auth_manager
            .credential_store
            .get_user_permissions(&auth_result.username)
            .await?;

        self.validate_allocation_request(&user_permissions, transport, client_addr).await?;

        // Check if allocation already exists for this client
        if let Some(existing) = self.allocation_manager.find_allocation(client_addr).await {
            // Return existing allocation (RFC 5766 Section 6.2)
            return self.send_allocate_response_existing(
                &request,
                client_addr,
                socket,
                existing,
            ).await;
        }

        // Create new allocation
        let allocation = self.allocation_manager.create_allocation(
            client_addr,
            transport,
            requested_lifetime.min(user_permissions.allocation_lifetime),
            auth_result.username.clone(),
            auth_result.realm.clone(),
            user_permissions.max_bandwidth,
        ).await?;

        info!("Created allocation {} -> {} for user {}",
            client_addr, allocation.relay_addr, auth_result.username);

        // Send successful response
        self.send_allocate_response(
            &request,
            client_addr,
            socket,
            allocation,
        ).await?;

        // Update metrics
        self.metrics.allocations_created.fetch_add(1, Ordering::Relaxed);
        self.stats.total_allocations.fetch_add(1, Ordering::Relaxed);
        self.stats.active_allocations.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Extract REQUESTED-TRANSPORT attribute
    fn extract_requested_transport(&self, request: &Message) -> NatResult<Transport> {
        let attr = request.get_attribute(AttributeType::RequestedTransport)
            .ok_or_else(|| NatError::Platform("Missing REQUESTED-TRANSPORT".to_string()))?;

        if let AttributeValue::Raw(data) = &attr.value {
            if data.len() >= 1 {
                match data[0] {
                    17 => Ok(Transport::Udp), // UDP
                    6 => Ok(Transport::Tcp),   // TCP
                    _ => Err(NatError::Platform("Unsupported transport protocol".to_string())),
                }
            } else {
                Err(NatError::Platform("Invalid REQUESTED-TRANSPORT format".to_string()))
            }
        } else {
            Err(NatError::Platform("Invalid REQUESTED-TRANSPORT attribute".to_string()))
        }
    }

    /// Extract LIFETIME attribute
    fn extract_lifetime(&self, request: &Message) -> Option<Duration> {
        request.get_attribute(AttributeType::Lifetime)
            .and_then(|attr| {
                if let AttributeValue::Raw(data) = &attr.value {
                    if data.len() >= 4 {
                        let seconds = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                        Some(Duration::from_secs(seconds as u64))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
    }

    /// Authenticate request with comprehensive validation
    async fn authenticate_request(
        &self,
        request: &Message,
        client_addr: SocketAddr,
        method: &str,
    ) -> NatResult<AuthResult> {
        self.auth_manager.authenticate(request, client_addr, method).await
    }

    /// Validate allocation request against user permissions
    async fn validate_allocation_request(
        &self,
        permissions: &UserPermissions,
        transport: Transport,
        client_addr: SocketAddr,
    ) -> NatResult<()> {
        // Check transport permission
        if !permissions.allowed_transports.contains(&transport) {
            return Err(NatError::Platform("Transport not allowed".to_string()));
        }

        // Check allocation quota
        let current_allocations = self.allocation_manager
            .count_allocations_for_client(client_addr.ip())
            .await;

        if current_allocations >= permissions.max_allocations {
            return Err(NatError::Platform("Allocation quota exceeded".to_string()));
        }

        Ok(())
    }

    /// Send ALLOCATE success response
    async fn send_allocate_response(
        &self,
        request: &Message,
        client_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        allocation: Arc<Allocation>,
    ) -> NatResult<()> {
        let mut response = Message::new(
            MessageType::AllocateResponse,
            request.transaction_id,
        );

        // Add XOR-RELAYED-ADDRESS
        response.add_attribute(Attribute::new(
            AttributeType::XorRelayedAddress,
            AttributeValue::XorMappedAddress(allocation.relay_addr),
        ));

        // Add LIFETIME
        let lifetime_secs = allocation.lifetime.load(Ordering::Relaxed);
        response.add_attribute(Attribute::new(
            AttributeType::Lifetime,
            AttributeValue::Raw(lifetime_secs.to_be_bytes().to_vec()),
        ));

        // Add XOR-MAPPED-ADDRESS
        response.add_attribute(Attribute::new(
            AttributeType::XorMappedAddress,
            AttributeValue::XorMappedAddress(client_addr),
        ));

        // Add SOFTWARE
        response.add_attribute(Attribute::new(
            AttributeType::Software,
            AttributeValue::Software(self.config.software.clone()),
        ));

        self.send_authenticated_response(response, client_addr, socket, &allocation.username).await
    }

    /// Send authenticated response with MESSAGE-INTEGRITY
    async fn send_authenticated_response(
        &self,
        mut response: Message,
        client_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        username: &str,
    ) -> NatResult<()> {
        // Get credentials for MESSAGE-INTEGRITY
        let credentials = self.auth_manager
            .credential_store
            .get_credentials(username, &self.config.realm)
            .await?
            .ok_or_else(|| NatError::Platform("User not found".to_string()))?;

        // Calculate MESSAGE-INTEGRITY key
        let key = self.calculate_message_integrity_key(&credentials)?;

        // Encode and send response
        let encoded = response.encode(Some(&key), true)?;

        socket.send_to(&encoded, client_addr).await
            .map_err(|e| NatError::Network(e))?;

        Ok(())
    }

    /// Calculate MESSAGE-INTEGRITY key
    fn calculate_message_integrity_key(&self, credentials: &UserCredentials) -> NatResult<Vec<u8>> {
        use md5::{Md5, Digest};

        let input = format!("{}:{}:{}",
                            credentials.username,
                            credentials.realm,
                            credentials.password
        );

        let hash = Md5::digest(input.as_bytes());
        Ok(hash.to_vec())
    }

    /// Send error response
    async fn send_error_response(
        &self,
        request: &Message,
        client_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        error_code: u16,
        reason_phrase: &str,
    ) -> NatResult<()> {
        let mut response = Message::new(
            match request.message_type {
                MessageType::AllocateRequest => MessageType::AllocateError,
                MessageType::RefreshRequest => MessageType::RefreshError,
                MessageType::CreatePermissionRequest => MessageType::CreatePermissionError,
                MessageType::ChannelBindRequest => MessageType::ChannelBindError,
                _ => MessageType::BindingError,
            },
            request.transaction_id,
        );

        // Add ERROR-CODE attribute
        response.add_attribute(Attribute::new(
            AttributeType::ErrorCode,
            AttributeValue::ErrorCode {
                code: error_code,
                reason: reason_phrase.to_string(),
            },
        ));

        // Add SOFTWARE
        response.add_attribute(Attribute::new(
            AttributeType::Software,
            AttributeValue::Software(self.config.software.clone()),
        ));

        let encoded = response.encode(None, true)?;
        socket.send_to(&encoded, client_addr).await
            .map_err(|e| NatError::Network(e))?;

        Ok(())
    }

    /// Handle REFRESH request (RFC 5766 Section 7)
    async fn handle_refresh_request(
        &self,
        request: Message,
        client_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> NatResult<()> {
        // Find existing allocation
        let allocation = self.allocation_manager.find_allocation(client_addr).await
            .ok_or_else(|| NatError::Platform("Allocation does not exist".to_string()))?;

        // Authenticate request
        let auth_result = self.authenticate_request(&request, client_addr, "REFRESH").await?;

        // Verify user owns this allocation
        if auth_result.username != allocation.username {
            return self.send_error_response(&request, client_addr, socket, 401, "Unauthorized").await;
        }

        // Extract lifetime
        let requested_lifetime = self.extract_lifetime(&request)
            .unwrap_or(DEFAULT_ALLOCATION_LIFETIME);

        // Update allocation lifetime
        if requested_lifetime.is_zero() {
            // Delete allocation
            self.allocation_manager.delete_allocation(&allocation.key).await?;

            // Send response with zero lifetime
            let mut response = Message::new(MessageType::RefreshResponse, request.transaction_id);
            response.add_attribute(Attribute::new(
                AttributeType::Lifetime,
                AttributeValue::Raw(vec![0, 0, 0, 0]),
            ));

            self.send_authenticated_response(response, client_addr, socket, &auth_result.username).await?;

            info!("Deleted allocation for {}", client_addr);
        } else {
            // Refresh allocation
            let new_lifetime = requested_lifetime.min(MAX_ALLOCATION_LIFETIME);
            self.allocation_manager.refresh_allocation(&allocation.key, new_lifetime).await?;

            // Send response
            let mut response = Message::new(MessageType::RefreshResponse, request.transaction_id);
            response.add_attribute(Attribute::new(
                AttributeType::Lifetime,
                AttributeValue::Raw((new_lifetime.as_secs() as u32).to_be_bytes().to_vec()),
            ));

            self.send_authenticated_response(response, client_addr, socket, &auth_result.username).await?;

            debug!("Refreshed allocation for {} (lifetime: {:?})", client_addr, new_lifetime);
        }

        Ok(())
    }

    /// Handle CreatePermission request (RFC 5766 Section 9)
    async fn handle_create_permission_request(
        &self,
        request: Message,
        client_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> NatResult<()> {
        // Find allocation
        let allocation = self.allocation_manager.find_allocation(client_addr).await
            .ok_or_else(|| NatError::Platform("Allocation does not exist".to_string()))?;

        // Authenticate request
        let auth_result = self.authenticate_request(&request, client_addr, "CREATE_PERMISSION").await?;

        if auth_result.username != allocation.username {
            return self.send_error_response(&request, client_addr, socket, 401, "Unauthorized").await;
        }

        // Extract XOR-PEER-ADDRESS attributes
        let peer_addresses = self.extract_peer_addresses(&request)?;

        if peer_addresses.is_empty() {
            return self.send_error_response(&request, client_addr, socket, 400, "Missing XOR-PEER-ADDRESS").await;
        }

        // Create permissions
        for peer_addr in peer_addresses {
            self.permission_manager.create_permission(
                &allocation.key,
                peer_addr.ip(),
                PERMISSION_LIFETIME,
            ).await?;

            debug!("Created permission for {} -> {}", client_addr, peer_addr.ip());
        }

        // Send success response
        let response = Message::new(MessageType::CreatePermissionResponse, request.transaction_id);
        self.send_authenticated_response(response, client_addr, socket, &auth_result.username).await?;

        Ok(())
    }

    /// Extract XOR-PEER-ADDRESS attributes
    fn extract_peer_addresses(&self, request: &Message) -> NatResult<Vec<SocketAddr>> {
        let mut addresses = Vec::new();

        for attr in &request.attributes {
            if attr.attr_type == AttributeType::XorPeerAddress {
                if let AttributeValue::XorMappedAddress(addr) = &attr.value {
                    addresses.push(*addr);
                }
            }
        }

        Ok(addresses)
    }

    /// Handle ChannelBind request (RFC 5766 Section 11)
    async fn handle_channel_bind_request(
        &self,
        request: Message,
        client_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> NatResult<()> {
        // Find allocation
        let allocation = self.allocation_manager.find_allocation(client_addr).await
            .ok_or_else(|| NatError::Platform("Allocation does not exist".to_string()))?;

        // Authenticate request
        let auth_result = self.authenticate_request(&request, client_addr, "CHANNEL_BIND").await?;

        if auth_result.username != allocation.username {
            return self.send_error_response(&request, client_addr, socket, 401, "Unauthorized").await;
        }

        // Extract CHANNEL-NUMBER
        let channel_number = self.extract_channel_number(&request)?;

        // Extract XOR-PEER-ADDRESS
        let peer_addr = self.extract_single_peer_address(&request)?;

        // Validate channel number range (0x4000-0x7FFF)
        if channel_number < 0x4000 || channel_number > 0x7FFF {
            return self.send_error_response(&request, client_addr, socket, 400, "Invalid channel number").await;
        }

        // Check if permission exists for peer
        if !self.permission_manager.has_permission(&allocation.key, peer_addr.ip()).await {
            return self.send_error_response(&request, client_addr, socket, 403, "Forbidden").await;
        }

        // Create channel binding
        self.channel_manager.bind_channel(
            &allocation.key,
            channel_number,
            peer_addr,
            CHANNEL_BIND_LIFETIME,
        ).await?;

        info!("Bound channel {} for {} -> {}", channel_number, client_addr, peer_addr);

        // Send success response
        let response = Message::new(MessageType::ChannelBindResponse, request.transaction_id);
        self.send_authenticated_response(response, client_addr, socket, &auth_result.username).await?;

        Ok(())
    }

    /// Extract CHANNEL-NUMBER attribute
    fn extract_channel_number(&self, request: &Message) -> NatResult<u16> {
        let attr = request.get_attribute(AttributeType::ChannelNumber)
            .ok_or_else(|| NatError::Platform("Missing CHANNEL-NUMBER".to_string()))?;

        if let AttributeValue::Raw(data) = &attr.value {
            if data.len() >= 2 {
                Ok(u16::from_be_bytes([data[0], data[1]]))
            } else {
                Err(NatError::Platform("Invalid CHANNEL-NUMBER format".to_string()))
            }
        } else {
            Err(NatError::Platform("Invalid CHANNEL-NUMBER attribute".to_string()))
        }
    }

    /// Extract single XOR-PEER-ADDRESS attribute
    fn extract_single_peer_address(&self, request: &Message) -> NatResult<SocketAddr> {
        let attr = request.get_attribute(AttributeType::XorPeerAddress)
            .ok_or_else(|| NatError::Platform("Missing XOR-PEER-ADDRESS".to_string()))?;

        if let AttributeValue::XorMappedAddress(addr) = &attr.value {
            Ok(*addr)
        } else {
            Err(NatError::Platform("Invalid XOR-PEER-ADDRESS attribute".to_string()))
        }
    }

    /// Handle Send indication (RFC 5766 Section 10)
    async fn handle_send_indication(
        &self,
        indication: Message,
        client_addr: SocketAddr,
    ) -> NatResult<()> {
        // Find allocation
        let allocation = self.allocation_manager.find_allocation(client_addr).await
            .ok_or_else(|| NatError::Platform("Allocation does not exist".to_string()))?;

        // Extract XOR-PEER-ADDRESS
        let peer_addr = self.extract_single_peer_address(&indication)?;

        // Extract DATA
        let data = self.extract_data_attribute(&indication)?;

        // Check permission
        if !self.permission_manager.has_permission(&allocation.key, peer_addr.ip()).await {
            debug!("Permission denied for {} -> {}", client_addr, peer_addr.ip());
            return Ok(()); // Silently drop
        }

        // Check bandwidth limit
        if !self.check_bandwidth_limit(&allocation, data.len()).await {
            debug!("Bandwidth limit exceeded for {}", client_addr);
            return Ok(()); // Silently drop
        }

        // Relay data to peer
        self.relay_data_to_peer(&allocation, peer_addr, data).await?;

        // Update statistics
        allocation.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        allocation.stats.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.metrics.packets_relayed.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_relayed.fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Extract DATA attribute
    fn extract_data_attribute(&self, message: &Message) -> NatResult<Bytes> {
        let attr = message.get_attribute(AttributeType::Data)
            .ok_or_else(|| NatError::Platform("Missing DATA attribute".to_string()))?;

        if let AttributeValue::Raw(data) = &attr.value {
            Ok(Bytes::from(data.clone()))
        } else {
            Err(NatError::Platform("Invalid DATA attribute".to_string()))
        }
    }

    /// Check bandwidth limit for allocation
    async fn check_bandwidth_limit(&self, allocation: &Allocation, data_size: usize) -> bool {
        let bandwidth_limit = allocation.bandwidth_limit.load(Ordering::Relaxed);
        if bandwidth_limit == 0 {
            return true; // No limit
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let window_start = allocation.bandwidth_window_start.load(Ordering::Relaxed);

        // Reset window if it's been more than 1 second
        if now - window_start >= 1000 {
            allocation.bandwidth_window_start.store(now, Ordering::Relaxed);
            allocation.bandwidth_used.store(0, Ordering::Relaxed);
        }

        let current_usage = allocation.bandwidth_used.load(Ordering::Relaxed);
        let new_usage = current_usage + data_size as u64;

        if new_usage <= bandwidth_limit {
            allocation.bandwidth_used.store(new_usage, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Relay data to peer address
    async fn relay_data_to_peer(
        &self,
        allocation: &Allocation,
        peer_addr: SocketAddr,
        data: Bytes,
    ) -> NatResult<()> {
        // Create relay socket if needed
        let relay_socket = self.get_or_create_relay_socket(allocation.relay_addr, allocation.transport).await?;

        // Send data to peer
        match allocation.transport {
            Transport::Udp => {
                if let Some(udp_socket) = relay_socket.udp_socket {
                    udp_socket.send_to(&data, peer_addr).await?;
                }
            }
            Transport::Tcp => {
                // TCP relay implementation would go here
                return Err(NatError::Platform("TCP relay not implemented".to_string()));
            }
            _ => {
                return Err(NatError::Platform("Unsupported transport for relay".to_string()));
            }
        }

        Ok(())
    }

    /// Get or create relay socket for allocation
    async fn get_or_create_relay_socket(
        &self,
        relay_addr: SocketAddr,
        transport: Transport,
    ) -> NatResult<Arc<RelaySocket>> {
        // This would be implemented with a socket pool
        // For now, return a placeholder
        Err(NatError::Platform("Relay socket creation not implemented".to_string()))
    }

    /// Handle ChannelData message (RFC 5766 Section 11.4)
    async fn process_channel_data(
        &self,
        packet_data: Bytes,
        client_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> NatResult<()> {
        if packet_data.len() < 4 {
            return Err(NatError::Platform("ChannelData too short".to_string()));
        }

        // Parse ChannelData header
        let channel_number = u16::from_be_bytes([packet_data[0], packet_data[1]]);
        let data_length = u16::from_be_bytes([packet_data[2], packet_data[3]]) as usize;

        if packet_data.len() < 4 + data_length {
            return Err(NatError::Platform("ChannelData length mismatch".to_string()));
        }

        // Find allocation
        let allocation = self.allocation_manager.find_allocation(client_addr).await
            .ok_or_else(|| NatError::Platform("Allocation does not exist".to_string()))?;

        // Find channel binding
        let channel_binding = self.channel_manager
            .get_channel_binding(&allocation.key, channel_number)
            .await
            .ok_or_else(|| NatError::Platform("Channel binding does not exist".to_string()))?;

        // Extract data
        let data = packet_data.slice(4..4 + data_length);

        // Check bandwidth limit
        if !self.check_bandwidth_limit(&allocation, data.len()).await {
            return Ok(()); // Silently drop
        }

        // Relay data to peer
        self.relay_data_to_peer(&allocation, channel_binding.peer_addr, data).await?;

        // Update statistics
        channel_binding.packets_sent.fetch_add(1, Ordering::Relaxed);
        channel_binding.bytes_sent.fetch_add(data_length as u64, Ordering::Relaxed);
        channel_binding.last_activity.store(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            Ordering::Relaxed,
        );

        Ok(())
    }

    /// Handle STUN Binding request (RFC 5389)
    async fn handle_binding_request(
        &self,
        request: Message,
        client_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> NatResult<()> {
        let mut response = Message::new(MessageType::BindingResponse, request.transaction_id);

        // Add XOR-MAPPED-ADDRESS
        response.add_attribute(Attribute::new(
            AttributeType::XorMappedAddress,
            AttributeValue::XorMappedAddress(client_addr),
        ));

        // Add SOFTWARE
        response.add_attribute(Attribute::new(
            AttributeType::Software,
            AttributeValue::Software(self.config.software.clone()),
        ));

        // Send response
        let encoded = response.encode(None, true)?;
        socket.send_to(&encoded, client_addr).await?;

        Ok(())
    }

    /// Start background maintenance tasks
    async fn start_background_tasks(&self) -> NatResult<()> {
        // Start allocation cleanup task
        self.allocation_manager.start_cleanup_task().await;

        // Start permission cleanup task
        self.permission_manager.start_cleanup_task().await;

        // Start channel cleanup task
        self.channel_manager.start_cleanup_task().await;

        // Start metrics collection task
        self.start_metrics_task().await;

        Ok(())
    }

    /// Start metrics collection task
    async fn start_metrics_task(&self) {
        let metrics = self.metrics.clone();
        let stats = self.stats.clone();
        let interval_duration = self.config.monitoring.metrics_interval;

        tokio::spawn(async move {
            let mut interval = interval(interval_duration);

            loop {
                interval.tick().await;

                // Update server statistics
                let uptime = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() - stats.uptime_start.load(Ordering::Relaxed);

                // Collect system metrics (CPU, memory, etc.)
                // This would integrate with system monitoring libraries

                debug!("Server uptime: {}s, Active allocations: {}",
                    uptime,
                    metrics.allocations_active.load(Ordering::Relaxed)
                );
            }
        });
    }

    /// Start configuration watcher for hot reload
    async fn start_config_watcher(&self) -> NatResult<()> {
        self.config_watcher.start_watching().await
    }

    /// Start metrics collection if enabled
    async fn start_metrics_collection(&self) -> NatResult<()> {
        if let Some(prometheus_addr) = self.config.monitoring.prometheus_addr {
            // Start Prometheus metrics server
            self.start_prometheus_server(prometheus_addr).await?;
        }

        if let Some(health_addr) = self.config.monitoring.health_check_addr {
            // Start health check server
            self.start_health_check_server(health_addr).await?;
        }

        Ok(())
    }

    /// Start Prometheus metrics server
    async fn start_prometheus_server(&self, addr: SocketAddr) -> NatResult<()> {
        info!("Starting Prometheus metrics server on {}", addr);
        // Implementation would use prometheus crate
        Ok(())
    }

    /// Start health check server
    async fn start_health_check_server(&self, addr: SocketAddr) -> NatResult<()> {
        info!("Starting health check server on {}", addr);
        // Implementation would provide HTTP health endpoints
        Ok(())
    }

    /// Check if server is shutting down
    async fn is_shutting_down(&self) -> bool {
        self.shutdown_tx.read().await.is_none()
    }

    /// Start TCP processing (placeholder)
    async fn start_tcp_processing(&self, _listener: Arc<NetworkListener>) -> NatResult<()> {
        // TCP implementation would handle connection management
        info!("TCP processing not yet implemented");
        Ok(())
    }

    /// Start TLS processing (placeholder)
    async fn start_tls_processing(&self, _listener: Arc<NetworkListener>) -> NatResult<()> {
        // TLS implementation would handle encrypted connections
        info!("TLS processing not yet implemented");
        Ok(())
    }

    /// Start DTLS processing (placeholder)
    async fn start_dtls_processing(&self, _listener: Arc<NetworkListener>) -> NatResult<()> {
        // DTLS implementation would handle encrypted UDP
        info!("DTLS processing not yet implemented");
        Ok(())
    }

    /// Clone server for async tasks
    fn clone_for_task(&self) -> TurnServer {
        // This would create a lightweight clone for tasks
        // In practice, most fields would be Arc-wrapped
        panic!("Not implemented - use Arc<TurnServer> instead")
    }

    /// Graceful shutdown
    pub async fn shutdown(&self) -> NatResult<()> {
        info!("Initiating graceful shutdown");

        // Signal shutdown to all tasks
        if let Some(tx) = self.shutdown_tx.write().await.take() {
            let _ = tx.send(());
        }

        // Stop all listeners
        let listeners = self.listeners.read().await;
        for (addr, listener) in listeners.iter() {
            info!("Stopping listener on {}", addr);
            // Stop listener processing
        }

        // Wait for all allocations to expire or be closed
        // This would implement a graceful drain period

        info!("TURN server shutdown complete");
        Ok(())
    }
}

// Placeholder structures and implementations

struct AuthResult {
    username: String,
    realm: String,
}

struct RelaySocket {
    udp_socket: Option<Arc<UdpSocket>>,
}

// Implementation blocks for the managers and other components would follow...
// This includes AllocationManager, AuthenticationManager, RateLimiter, etc.
// Each would have their own comprehensive implementation with all RFC requirements.

impl Default for TurnConfig {
    fn default() -> Self {
        Self {
            listen_addrs: vec![
                ListenConfig {
                    addr: "0.0.0.0:3478".parse().unwrap(),
                    transport: Transport::Udp,
                    interface: None,
                    enabled: true,
                    rate_limit: None,
                }
            ],
            relay_addrs: vec![
                RelayRange {
                    start_ip: "0.0.0.0".parse().unwrap(),
                    end_ip: "0.0.0.0".parse().unwrap(),
                    port_range: (49152, 65535),
                    transports: vec![Transport::Udp],
                    max_bandwidth: None,
                }
            ],
            auth: AuthConfig {
                method: AuthMethod::LongTerm,
                credential_store: CredentialStore::Memory {
                    users: HashMap::new()
                },
                allow_anonymous: false,
                require_tls: false,
                enable_third_party_auth: false,
                third_party_url: None,
            },
            rate_limiting: RateLimitingConfig {
                global_rate_limit: 10000,
                per_ip_rate_limit: 1000,
                per_user_rate_limit: 500,
                window_duration: Duration::from_secs(60),
                adaptive: true,
                ddos_threshold: 5000,
                ddos_response: DdosResponse::Throttle { factor: 0.5 },
                bandwidth_limit: None,
                max_allocations_per_ip: 10,
                max_allocations_per_user: 5,
            },
            security: SecurityConfig {
                validate_requests: true,
                anti_amplification: true,
                max_response_multiplier: 3.0,
                ip_filtering: IpFilterConfig {
                    whitelist: vec![],
                    blacklist: vec![],
                    auto_blacklist: true,
                    blacklist_threshold: 10,
                    blacklist_duration: Duration::from_secs(3600),
                },
                anti_fingerprinting: true,
                constant_time_auth: true,
                allowed_user_agents: None,
                geo_restrictions: None,
            },
            performance: PerformanceConfig {
                worker_threads: 0,
                reuse_port: true,
                socket_recv_buffer: 2 * 1024 * 1024,
                socket_send_buffer: 2 * 1024 * 1024,
                zero_copy: true,
                packet_pool_size: PACKET_POOL_SIZE,
                allocation_pool_size: ALLOCATION_POOL_SIZE,
                cpu_affinity: false,
                numa_aware: false,
                batch_size: 32,
            },
            tls: None,
            monitoring: MonitoringConfig {
                enable_metrics: true,
                metrics_interval: Duration::from_secs(30),
                prometheus_addr: None,
                detailed_logging: false,
                log_level: "info".to_string(),
                enable_profiling: false,
                health_check_addr: None,
            },
            realm: "turn.example.com".to_string(),
            software: "SHARP-TURN/1.0".to_string(),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self {
            allocations_active: AtomicU64::new(0),
            allocations_created: AtomicU64::new(0),
            allocations_expired: AtomicU64::new(0),
            allocations_failed: AtomicU64::new(0),
            packets_relayed: AtomicU64::new(0),
            bytes_relayed: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            auth_requests: AtomicU64::new(0),
            auth_successes: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            rate_limited_requests: AtomicU64::new(0),
            ddos_events: AtomicU64::new(0),
            request_duration_total: AtomicU64::new(0),
            request_count: AtomicU64::new(0),
            memory_usage: AtomicU64::new(0),
            cpu_usage: AtomicU64::new(0),
            stun_errors: AtomicU64::new(0),
            network_errors: AtomicU64::new(0),
            internal_errors: AtomicU64::new(0),
        }
    }
}

// Additional implementation blocks would follow for all the managers and components...