// src/turn/permission_channel_manager.rs
//! Permission and Channel Management for TURN relay
//!
//! Implements:
//! - RFC 5766 (TURN) Permission management (Section 9)
//! - RFC 5766 (TURN) Channel management (Section 11)
//! - High-performance concurrent access
//! - Automatic expiration and cleanup
//! - Comprehensive security validation

use std::collections::{HashMap, HashSet, VecDeque, BTreeMap};
use std::net::{SocketAddr, IpAddr};
use std::sync::{Arc, atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, Mutex};
use tokio::time::interval;
use dashmap::DashMap;
use parking_lot::{RwLock as ParkingRwLock, Mutex as ParkingMutex};
use crossbeam::queue::SegQueue;
use tracing::{info, warn, error, debug, trace, instrument};
use bytes::{Bytes, BytesMut};

use super::{
    AllocationKey, MetricsCollector, PERMISSION_LIFETIME, CHANNEL_BIND_LIFETIME,
    MAX_PERMISSIONS_PER_ALLOCATION, MAX_CHANNELS_PER_ALLOCATION
};
use crate::nat::error::{NatError, NatResult};

/// High-performance permission manager with concurrent access optimization
pub struct PermissionManager {
    /// Global permission registry: (allocation, peer_ip) -> permission
    permissions: DashMap<(AllocationKey, IpAddr), Arc<Permission>>,

    /// Allocation to permissions mapping for efficient cleanup
    allocation_permissions: DashMap<AllocationKey, Vec<IpAddr>>,

    /// IP to allocations mapping for reverse lookup
    ip_allocations: DashMap<IpAddr, HashSet<AllocationKey>>,

    /// Permission expiration queue for efficient cleanup
    expiry_queue: Arc<ParkingMutex<ExpirationQueue<(AllocationKey, IpAddr)>>>,

    /// Permission object pool for zero-allocation hot paths
    permission_pool: Arc<SegQueue<Box<Permission>>>,

    /// Security validator for permission requests
    security_validator: Arc<PermissionSecurityValidator>,

    /// Metrics collector
    metrics: Arc<MetricsCollector>,

    /// Statistics
    stats: PermissionStats,

    /// Cleanup task handle
    cleanup_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,

    /// Active flag
    active: AtomicBool,
}

/// Channel manager with optimized data relay
pub struct ChannelManager {
    /// Channel bindings: (allocation, channel_number) -> binding
    channels: DashMap<(AllocationKey, u16), Arc<ChannelBinding>>,

    /// Allocation to channels mapping
    allocation_channels: DashMap<AllocationKey, Vec<u16>>,

    /// Peer address to channel reverse lookup
    peer_channels: DashMap<(AllocationKey, SocketAddr), u16>,

    /// Available channel numbers pool (0x4000-0x7FFF)
    available_channels: Arc<ChannelPool>,

    /// Channel expiration queue
    expiry_queue: Arc<ParkingMutex<ExpirationQueue<(AllocationKey, u16)>>>,

    /// Channel binding pool for object reuse
    binding_pool: Arc<SegQueue<Box<ChannelBinding>>>,

    /// Channel data cache for performance
    data_cache: Arc<ChannelDataCache>,

    /// Security validator
    security_validator: Arc<ChannelSecurityValidator>,

    /// Metrics collector
    metrics: Arc<MetricsCollector>,

    /// Statistics
    stats: ChannelStats,

    /// Cleanup task handle
    cleanup_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,

    /// Active flag
    active: AtomicBool,
}

/// Permission with comprehensive tracking
#[derive(Debug)]
pub struct Permission {
    /// Peer IP address
    pub peer_ip: IpAddr,

    /// Creation timestamp
    pub created_at: Instant,

    /// Expiration timestamp
    pub expires_at: Instant,

    /// Last activity timestamp
    pub last_activity: AtomicU64,

    /// Usage statistics
    pub stats: PermissionUsageStats,

    /// Permission flags
    pub flags: PermissionFlags,

    /// Security context
    pub security_context: PermissionSecurityContext,
}

/// Channel binding with optimized data handling
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

    /// Last activity timestamp
    pub last_activity: AtomicU64,

    /// Usage statistics
    pub stats: ChannelUsageStats,

    /// Channel configuration
    pub config: ChannelConfig,

    /// Data flow metrics
    pub flow_metrics: ChannelFlowMetrics,

    /// Security context
    pub security_context: ChannelSecurityContext,
}

/// Permission usage statistics
#[derive(Debug, Default)]
pub struct PermissionUsageStats {
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub send_errors: AtomicU32,
    pub receive_errors: AtomicU32,
    pub last_send: AtomicU64,
    pub last_receive: AtomicU64,
}

/// Channel usage statistics
#[derive(Debug, Default)]
pub struct ChannelUsageStats {
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub channel_data_packets: AtomicU64,
    pub send_indications: AtomicU64,
    pub data_relay_errors: AtomicU32,
    pub encoding_errors: AtomicU32,
}

/// Permission flags for access control
#[derive(Debug)]
pub struct PermissionFlags {
    /// Allow bidirectional traffic
    pub bidirectional: bool,

    /// Enable traffic monitoring
    pub monitor_traffic: bool,

    /// Apply bandwidth limits
    pub bandwidth_limited: bool,

    /// Allow protocol upgrades
    pub allow_upgrades: bool,

    /// Temporary permission (shorter lifetime)
    pub temporary: bool,
}

/// Channel configuration
#[derive(Debug)]
pub struct ChannelConfig {
    /// Maximum packet size for channel
    pub max_packet_size: u32,

    /// Enable compression
    pub compression: bool,

    /// Enable encryption (for future use)
    pub encryption: bool,

    /// Quality of Service settings
    pub qos: QosSettings,

    /// Flow control settings
    pub flow_control: FlowControlSettings,
}

/// Quality of Service settings
#[derive(Debug, Clone)]
pub struct QosSettings {
    /// Priority level (0-7, higher is better)
    pub priority: u8,

    /// Bandwidth allocation (bytes/sec)
    pub bandwidth_allocation: u64,

    /// Maximum latency tolerance
    pub max_latency: Duration,

    /// Jitter tolerance
    pub jitter_tolerance: Duration,

    /// Packet loss tolerance (percentage)
    pub loss_tolerance: f32,
}

/// Flow control settings
#[derive(Debug, Clone)]
pub struct FlowControlSettings {
    /// Enable flow control
    pub enabled: bool,

    /// Window size for flow control
    pub window_size: u32,

    /// Congestion control algorithm
    pub congestion_algorithm: CongestionAlgorithm,

    /// Rate limiting settings
    pub rate_limit: Option<RateLimit>,
}

/// Congestion control algorithms
#[derive(Debug, Clone)]
pub enum CongestionAlgorithm {
    None,
    AIMD, // Additive Increase Multiplicative Decrease
    Cubic,
    BBR,
    Custom(String),
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Maximum rate (bytes/sec)
    pub max_rate: u64,

    /// Burst size
    pub burst_size: u32,

    /// Token bucket refill rate
    pub refill_rate: u64,
}

/// Channel flow metrics for performance analysis
#[derive(Debug, Default)]
pub struct ChannelFlowMetrics {
    /// Current throughput (bytes/sec)
    pub current_throughput: AtomicU64,

    /// Peak throughput
    pub peak_throughput: AtomicU64,

    /// Average latency (microseconds)
    pub avg_latency: AtomicU32,

    /// Jitter (microseconds)
    pub jitter: AtomicU32,

    /// Packet loss count
    pub packet_loss: AtomicU32,

    /// Out-of-order packets
    pub out_of_order: AtomicU32,

    /// Congestion events
    pub congestion_events: AtomicU32,
}

/// Security context for permissions
#[derive(Debug)]
pub struct PermissionSecurityContext {
    /// Source validation level
    pub validation_level: ValidationLevel,

    /// Allowed protocols
    pub allowed_protocols: HashSet<u8>,

    /// Traffic pattern analysis
    pub pattern_analysis: TrafficPattern,

    /// Threat score (0-100)
    pub threat_score: AtomicU32,

    /// Anomaly detection flags
    pub anomaly_flags: AtomicU32,
}

/// Security context for channels
#[derive(Debug)]
pub struct ChannelSecurityContext {
    /// Encryption status
    pub encrypted: bool,

    /// Authentication status
    pub authenticated: bool,

    /// Integrity protection
    pub integrity_protected: bool,

    /// Anti-replay sequence
    pub sequence_number: AtomicU64,

    /// Security violations count
    pub violations: AtomicU32,
}

/// Validation levels for security
#[derive(Debug, Clone, Copy)]
pub enum ValidationLevel {
    None,
    Basic,
    Enhanced,
    Strict,
    Paranoid,
}

/// Traffic pattern for anomaly detection
#[derive(Debug, Default)]
pub struct TrafficPattern {
    /// Request pattern entropy
    pub entropy: f64,

    /// Timing regularity score
    pub timing_regularity: f64,

    /// Size pattern variance
    pub size_variance: f64,

    /// Protocol conformance score
    pub protocol_conformance: f64,
}

/// Available channel number pool
pub struct ChannelPool {
    /// Available channel numbers
    available: SegQueue<u16>,

    /// Total pool size
    total_size: AtomicU32,

    /// Available count
    available_count: AtomicU32,

    /// Allocation strategy
    strategy: ChannelAllocationStrategy,
}

/// Channel allocation strategies
#[derive(Debug, Clone)]
pub enum ChannelAllocationStrategy {
    Sequential,
    Random,
    LeastRecentlyUsed,
    LoadBalanced,
}

/// Channel data cache for performance
pub struct ChannelDataCache {
    /// Cached channel data packets
    cache: DashMap<u16, CachedChannelData>,

    /// Cache configuration
    config: CacheConfig,

    /// Cache statistics
    stats: CacheStats,
}

/// Cached channel data
#[derive(Debug, Clone)]
struct CachedChannelData {
    /// Channel number
    channel_number: u16,

    /// Cached data
    data: Bytes,

    /// Cache timestamp
    cached_at: Instant,

    /// Access count
    access_count: AtomicU32,

    /// Last access time
    last_access: AtomicU64,
}

/// Cache configuration
#[derive(Debug, Clone)]
struct CacheConfig {
    /// Maximum cache size
    max_size: usize,

    /// Cache entry TTL
    ttl: Duration,

    /// Enable compression
    compression: bool,

    /// Eviction policy
    eviction_policy: EvictionPolicy,
}

/// Cache eviction policies
#[derive(Debug, Clone)]
enum EvictionPolicy {
    LRU,
    LFU,
    FIFO,
    TTL,
    Adaptive,
}

/// Cache statistics
#[derive(Debug, Default)]
struct CacheStats {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    memory_usage: AtomicU64,
}

/// Generic expiration queue
#[derive(Debug)]
struct ExpirationQueue<T> {
    /// Entries sorted by expiration time
    entries: BTreeMap<u64, Vec<T>>,

    /// Total entries count
    count: usize,
}

/// Permission security validator
pub struct PermissionSecurityValidator {
    /// Security policies
    policies: Vec<PermissionSecurityPolicy>,

    /// Threat intelligence
    threat_intel: Arc<ThreatIntelligence>,

    /// Validation cache
    validation_cache: DashMap<IpAddr, ValidationCacheEntry>,

    /// Statistics
    stats: SecurityValidationStats,
}

/// Channel security validator
pub struct ChannelSecurityValidator {
    /// Security policies
    policies: Vec<ChannelSecurityPolicy>,

    /// Protocol validators
    protocol_validators: HashMap<u8, Box<dyn ProtocolValidator + Send + Sync>>,

    /// Validation cache
    validation_cache: DashMap<SocketAddr, ValidationCacheEntry>,

    /// Statistics
    stats: SecurityValidationStats,
}

/// Security policy for permissions
#[derive(Debug, Clone)]
pub struct PermissionSecurityPolicy {
    /// Policy name
    pub name: String,

    /// IP address filters
    pub ip_filters: Vec<IpFilter>,

    /// Protocol restrictions
    pub protocol_restrictions: HashMap<u8, ProtocolRestriction>,

    /// Rate limits
    pub rate_limits: HashMap<String, u32>,

    /// Anomaly detection thresholds
    pub anomaly_thresholds: AnomalyThresholds,
}

/// Security policy for channels
#[derive(Debug, Clone)]
pub struct ChannelSecurityPolicy {
    /// Policy name
    pub name: String,

    /// Channel number restrictions
    pub channel_restrictions: ChannelRestrictions,

    /// Data validation rules
    pub data_validation: DataValidationRules,

    /// Encryption requirements
    pub encryption_requirements: EncryptionRequirements,
}

/// IP filter for security
#[derive(Debug, Clone)]
pub enum IpFilter {
    Allow(IpAddr),
    Block(IpAddr),
    AllowSubnet { network: IpAddr, prefix: u8 },
    BlockSubnet { network: IpAddr, prefix: u8 },
    AllowCountry(String),
    BlockCountry(String),
}

/// Protocol restriction
#[derive(Debug, Clone)]
pub struct ProtocolRestriction {
    /// Allowed protocols
    pub allowed: HashSet<u8>,

    /// Maximum packet size
    pub max_packet_size: u32,

    /// Rate limit (packets/sec)
    pub rate_limit: u32,
}

/// Anomaly detection thresholds
#[derive(Debug, Clone)]
pub struct AnomalyThresholds {
    /// Maximum entropy change
    pub max_entropy_change: f64,

    /// Maximum timing deviation
    pub max_timing_deviation: Duration,

    /// Maximum size variance
    pub max_size_variance: f64,

    /// Protocol conformance threshold
    pub min_protocol_conformance: f64,
}

/// Channel restrictions
#[derive(Debug, Clone)]
pub struct ChannelRestrictions {
    /// Allowed channel range
    pub allowed_range: (u16, u16),

    /// Maximum channels per allocation
    pub max_channels: u32,

    /// Minimum lifetime
    pub min_lifetime: Duration,

    /// Maximum lifetime
    pub max_lifetime: Duration,
}

/// Data validation rules
#[derive(Debug, Clone)]
pub struct DataValidationRules {
    /// Maximum data size
    pub max_data_size: u32,

    /// Minimum data size
    pub min_data_size: u32,

    /// Content filters
    pub content_filters: Vec<ContentFilter>,

    /// Protocol validators
    pub protocol_validators: HashMap<u8, String>,
}

/// Content filter for data validation
#[derive(Debug, Clone)]
pub enum ContentFilter {
    ProhibitedBytes(Vec<u8>),
    RequiredPattern(String),
    MaxEntropy(f64),
    ProtocolSignature { protocol: u8, signature: Vec<u8> },
}

/// Encryption requirements
#[derive(Debug, Clone)]
pub struct EncryptionRequirements {
    /// Require encryption
    pub required: bool,

    /// Minimum key size
    pub min_key_size: u32,

    /// Allowed algorithms
    pub allowed_algorithms: HashSet<String>,

    /// Perfect forward secrecy required
    pub pfs_required: bool,
}

/// Validation cache entry
#[derive(Debug, Clone)]
struct ValidationCacheEntry {
    /// Validation result
    pub result: ValidationResult,

    /// Cache timestamp
    pub cached_at: Instant,

    /// Cache TTL
    pub ttl: Duration,

    /// Hit count
    pub hit_count: AtomicU32,
}

/// Validation result
#[derive(Debug, Clone)]
enum ValidationResult {
    Allow,
    Block(String),
    Monitor,
    Challenge,
}

/// Threat intelligence provider
pub struct ThreatIntelligence {
    /// Known malicious IPs
    malicious_ips: DashMap<IpAddr, ThreatInfo>,

    /// Threat feeds
    threat_feeds: Vec<ThreatFeed>,

    /// Reputation scores
    reputation_cache: DashMap<IpAddr, ReputationScore>,

    /// Update frequency
    update_frequency: Duration,

    /// Statistics
    stats: ThreatIntelStats,
}

/// Threat information
#[derive(Debug, Clone)]
struct ThreatInfo {
    /// Threat type
    pub threat_type: ThreatType,

    /// Confidence score (0-100)
    pub confidence: u8,

    /// First seen timestamp
    pub first_seen: SystemTime,

    /// Last seen timestamp
    pub last_seen: SystemTime,

    /// Source of intelligence
    pub source: String,
}

/// Threat types
#[derive(Debug, Clone)]
enum ThreatType {
    Botnet,
    Scanner,
    Attacker,
    Spam,
    Malware,
    Tor,
    Proxy,
    Unknown,
}

/// Threat feed configuration
#[derive(Debug, Clone)]
struct ThreatFeed {
    /// Feed name
    pub name: String,

    /// Feed URL
    pub url: String,

    /// Update frequency
    pub update_frequency: Duration,

    /// Feed format
    pub format: FeedFormat,

    /// Credibility weight
    pub weight: f64,
}

/// Feed format types
#[derive(Debug, Clone)]
enum FeedFormat {
    Json,
    Csv,
    Text,
    Xml,
    Custom(String),
}

/// Reputation score
#[derive(Debug, Clone)]
struct ReputationScore {
    /// Score (0-100, higher is better)
    pub score: u8,

    /// Confidence (0-100)
    pub confidence: u8,

    /// Last updated
    pub updated_at: SystemTime,

    /// Source count
    pub source_count: u32,
}

/// Protocol validator trait
pub trait ProtocolValidator {
    /// Validate protocol data
    fn validate(&self, data: &[u8]) -> ValidationResult;

    /// Get protocol name
    fn protocol_name(&self) -> &str;
}

// Statistics structures
#[derive(Debug, Default)]
struct PermissionStats {
    permissions_created: AtomicU64,
    permissions_expired: AtomicU64,
    permissions_revoked: AtomicU64,
    permission_checks: AtomicU64,
    permission_violations: AtomicU32,
    average_lifetime: AtomicU32,
}

#[derive(Debug, Default)]
struct ChannelStats {
    channels_created: AtomicU64,
    channels_expired: AtomicU64,
    channels_closed: AtomicU64,
    channel_data_packets: AtomicU64,
    channel_data_bytes: AtomicU64,
    encoding_errors: AtomicU32,
    decoding_errors: AtomicU32,
}

#[derive(Debug, Default)]
struct SecurityValidationStats {
    validations_performed: AtomicU64,
    validations_passed: AtomicU64,
    validations_failed: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    threats_detected: AtomicU32,
}

#[derive(Debug, Default)]
struct ThreatIntelStats {
    feeds_updated: AtomicU32,
    threats_added: AtomicU64,
    threats_removed: AtomicU64,
    reputation_queries: AtomicU64,
    cache_hits: AtomicU64,
}

impl PermissionManager {
    /// Create new permission manager
    pub async fn new(metrics: Arc<MetricsCollector>) -> NatResult<Self> {
        info!("Initializing permission manager");

        // Initialize permission pool
        let permission_pool = Arc::new(SegQueue::new());
        for _ in 0..1000 {
            permission_pool.push(Box::new(Permission::new_empty()));
        }

        // Initialize security validator
        let security_validator = Arc::new(PermissionSecurityValidator::new().await?);

        let manager = Self {
            permissions: DashMap::with_capacity(10000),
            allocation_permissions: DashMap::with_capacity(1000),
            ip_allocations: DashMap::with_capacity(10000),
            expiry_queue: Arc::new(ParkingMutex::new(ExpirationQueue::new())),
            permission_pool,
            security_validator,
            metrics,
            stats: PermissionStats::default(),
            cleanup_task: Arc::new(Mutex::new(None)),
            active: AtomicBool::new(true),
        };

        // Start cleanup task
        manager.start_cleanup_task().await;

        info!("Permission manager initialized successfully");
        Ok(manager)
    }

    /// Create permission for peer IP
    #[instrument(skip(self), level = "debug")]
    pub async fn create_permission(
        &self,
        allocation_key: &AllocationKey,
        peer_ip: IpAddr,
        lifetime: Duration,
    ) -> NatResult<()> {
        debug!("Creating permission for {} -> {}", allocation_key.allocation_id, peer_ip);

        // Security validation
        if !self.security_validator.validate_peer_ip(peer_ip).await? {
            return Err(NatError::Platform("Peer IP blocked by security policy".to_string()));
        }

        // Check allocation limits
        if let Some(perms) = self.allocation_permissions.get(allocation_key) {
            if perms.len() >= MAX_PERMISSIONS_PER_ALLOCATION {
                return Err(NatError::Platform("Maximum permissions per allocation exceeded".to_string()));
            }
        }

        let permission_key = (*allocation_key, peer_ip);

        // Check if permission already exists
        if self.permissions.contains_key(&permission_key) {
            debug!("Permission already exists for {} -> {}", allocation_key.allocation_id, peer_ip);
            return Ok(());
        }

        // Get permission object from pool or create new
        let mut permission = self.permission_pool.pop()
            .unwrap_or_else(|| Box::new(Permission::new_empty()));

        // Initialize permission
        let expires_at = Instant::now() + lifetime.min(PERMISSION_LIFETIME);
        permission.initialize(peer_ip, expires_at);

        let permission = Arc::new(*permission);

        // Store permission
        self.permissions.insert(permission_key, permission.clone());

        // Update allocation permissions
        self.allocation_permissions.entry(*allocation_key)
            .or_insert_with(Vec::new)
            .push(peer_ip);

        // Update IP allocations
        self.ip_allocations.entry(peer_ip)
            .or_insert_with(HashSet::new)
            .insert(*allocation_key);

        // Add to expiration queue
        let expires_ms = expires_at.elapsed().as_millis() as u64 +
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        self.expiry_queue.lock().add_entry(expires_ms, permission_key);

        // Update statistics
        self.stats.permissions_created.fetch_add(1, Ordering::Relaxed);

        info!("Permission created: {} -> {} (expires in {:?})",
            allocation_key.allocation_id, peer_ip, lifetime);

        Ok(())
    }

    /// Check if permission exists and is valid
    #[instrument(skip(self), level = "trace")]
    pub async fn has_permission(
        &self,
        allocation_key: &AllocationKey,
        peer_ip: IpAddr,
    ) -> bool {
        let permission_key = (*allocation_key, peer_ip);

        if let Some(permission) = self.permissions.get(&permission_key) {
            let now = Instant::now();
            if permission.expires_at > now {
                // Update activity
                let now_millis = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                permission.last_activity.store(now_millis, Ordering::Relaxed);

                self.stats.permission_checks.fetch_add(1, Ordering::Relaxed);
                true
            } else {
                // Permission expired
                false
            }
        } else {
            self.stats.permission_violations.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Get all permissions for allocation
    pub async fn get_allocation_permissions(
        &self,
        allocation_key: &AllocationKey,
    ) -> Vec<Arc<Permission>> {
        if let Some(peer_ips) = self.allocation_permissions.get(allocation_key) {
            peer_ips.iter()
                .filter_map(|ip| {
                    let key = (*allocation_key, *ip);
                    self.permissions.get(&key).map(|p| p.clone())
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Remove all permissions for allocation
    pub async fn remove_allocation_permissions(
        &self,
        allocation_key: &AllocationKey,
    ) -> NatResult<()> {
        debug!("Removing all permissions for allocation {}", allocation_key.allocation_id);

        if let Some((_, peer_ips)) = self.allocation_permissions.remove(allocation_key) {
            for peer_ip in peer_ips {
                let permission_key = (*allocation_key, peer_ip);

                // Remove permission
                if let Some((_, permission)) = self.permissions.remove(&permission_key) {
                    // Return to pool
                    if let Ok(mut perm_box) = Arc::try_unwrap(permission) {
                        perm_box.reset();
                        self.permission_pool.push(Box::new(perm_box));
                    }
                }

                // Update IP allocations
                if let Some(mut allocations) = self.ip_allocations.get_mut(&peer_ip) {
                    allocations.remove(allocation_key);
                    if allocations.is_empty() {
                        drop(allocations);
                        self.ip_allocations.remove(&peer_ip);
                    }
                }
            }
        }

        Ok(())
    }

    /// Start cleanup task for expired permissions
    pub async fn start_cleanup_task(&self) {
        let manager = self.clone_for_task();

        let task = tokio::spawn(async move {
            manager.cleanup_loop().await;
        });

        *self.cleanup_task.lock().await = Some(task);
        info!("Permission cleanup task started");
    }

    /// Main cleanup loop
    async fn cleanup_loop(self: Arc<Self>) {
        let mut cleanup_interval = interval(Duration::from_secs(30));

        while self.active.load(Ordering::Relaxed) {
            cleanup_interval.tick().await;

            let cleanup_start = Instant::now();
            let expired_count = self.cleanup_expired_permissions().await;
            let cleanup_duration = cleanup_start.elapsed();

            if expired_count > 0 {
                debug!("Cleaned up {} expired permissions in {:?}",
                    expired_count, cleanup_duration);
            }
        }

        info!("Permission cleanup task stopped");
    }

    /// Clean up expired permissions
    async fn cleanup_expired_permissions(&self) -> usize {
        let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let mut expired_keys = Vec::new();

        // Get expired entries from queue
        {
            let mut queue = self.expiry_queue.lock();
            queue.get_expired_entries(now, &mut expired_keys);
        }

        let mut cleaned_count = 0;

        // Remove expired permissions
        for permission_key in expired_keys {
            if let Some((_, permission)) = self.permissions.remove(&permission_key) {
                let (allocation_key, peer_ip) = permission_key;

                // Update allocation permissions
                if let Some(mut perms) = self.allocation_permissions.get_mut(&allocation_key) {
                    perms.retain(|&ip| ip != peer_ip);
                }

                // Update IP allocations
                if let Some(mut allocations) = self.ip_allocations.get_mut(&peer_ip) {
                    allocations.remove(&allocation_key);
                    if allocations.is_empty() {
                        drop(allocations);
                        self.ip_allocations.remove(&peer_ip);
                    }
                }

                // Return to pool
                if let Ok(mut perm_box) = Arc::try_unwrap(permission) {
                    perm_box.reset();
                    self.permission_pool.push(Box::new(perm_box));
                }

                cleaned_count += 1;
                self.stats.permissions_expired.fetch_add(1, Ordering::Relaxed);
            }
        }

        cleaned_count
    }

    /// Clone for async tasks
    fn clone_for_task(&self) -> Arc<Self> {
        unreachable!("Use Arc<PermissionManager>")
    }

    /// Shutdown permission manager
    pub async fn shutdown(&self) -> NatResult<()> {
        info!("Shutting down permission manager");

        self.active.store(false, Ordering::Relaxed);

        // Stop cleanup task
        if let Some(task) = self.cleanup_task.lock().await.take() {
            task.abort();
        }

        // Clean up all permissions
        self.permissions.clear();
        self.allocation_permissions.clear();
        self.ip_allocations.clear();

        info!("Permission manager shutdown complete");
        Ok(())
    }
}

impl ChannelManager {
    /// Create new channel manager
    pub async fn new(metrics: Arc<MetricsCollector>) -> NatResult<Self> {
        info!("Initializing channel manager");

        // Initialize channel pool with available channel numbers (0x4000-0x7FFF)
        let available_channels = Arc::new(ChannelPool::new().await?);

        // Initialize binding pool
        let binding_pool = Arc::new(SegQueue::new());
        for _ in 0..1000 {
            binding_pool.push(Box::new(ChannelBinding::new_empty()));
        }

        // Initialize data cache
        let cache_config = CacheConfig {
            max_size: 10000,
            ttl: Duration::from_secs(300),
            compression: false,
            eviction_policy: EvictionPolicy::LRU,
        };
        let data_cache = Arc::new(ChannelDataCache::new(cache_config));

        // Initialize security validator
        let security_validator = Arc::new(ChannelSecurityValidator::new().await?);

        let manager = Self {
            channels: DashMap::with_capacity(10000),
            allocation_channels: DashMap::with_capacity(1000),
            peer_channels: DashMap::with_capacity(10000),
            available_channels,
            expiry_queue: Arc::new(ParkingMutex::new(ExpirationQueue::new())),
            binding_pool,
            data_cache,
            security_validator,
            metrics,
            stats: ChannelStats::default(),
            cleanup_task: Arc::new(Mutex::new(None)),
            active: AtomicBool::new(true),
        };

        // Start cleanup task
        manager.start_cleanup_task().await;

        info!("Channel manager initialized successfully");
        Ok(manager)
    }

    /// Bind channel to peer address
    #[instrument(skip(self), level = "debug")]
    pub async fn bind_channel(
        &self,
        allocation_key: &AllocationKey,
        channel_number: u16,
        peer_addr: SocketAddr,
        lifetime: Duration,
    ) -> NatResult<()> {
        debug!("Binding channel {} for {} -> {}", channel_number, allocation_key.allocation_id, peer_addr);

        // Validate channel number range
        if channel_number < 0x4000 || channel_number > 0x7FFF {
            return Err(NatError::Platform("Invalid channel number range".to_string()));
        }

        // Security validation
        if !self.security_validator.validate_channel_binding(channel_number, peer_addr).await? {
            return Err(NatError::Platform("Channel binding blocked by security policy".to_string()));
        }

        // Check allocation limits
        if let Some(channels) = self.allocation_channels.get(allocation_key) {
            if channels.len() >= MAX_CHANNELS_PER_ALLOCATION {
                return Err(NatError::Platform("Maximum channels per allocation exceeded".to_string()));
            }
        }

        let channel_key = (*allocation_key, channel_number);

        // Check if channel already exists
        if self.channels.contains_key(&channel_key) {
            return Err(NatError::Platform("Channel already bound".to_string()));
        }

        // Mark channel as allocated
        if !self.available_channels.allocate_channel(channel_number).await {
            return Err(NatError::Platform("Channel number not available".to_string()));
        }

        // Get binding object from pool or create new
        let mut binding = self.binding_pool.pop()
            .unwrap_or_else(|| Box::new(ChannelBinding::new_empty()));

        // Initialize binding
        let expires_at = Instant::now() + lifetime.min(CHANNEL_BIND_LIFETIME);
        binding.initialize(channel_number, peer_addr, expires_at);

        let binding = Arc::new(*binding);

        // Store binding
        self.channels.insert(channel_key, binding.clone());

        // Update allocation channels
        self.allocation_channels.entry(*allocation_key)
            .or_insert_with(Vec::new)
            .push(channel_number);

        // Update peer channels for reverse lookup
        let peer_key = (*allocation_key, peer_addr);
        self.peer_channels.insert(peer_key, channel_number);

        // Add to expiration queue
        let expires_ms = expires_at.elapsed().as_millis() as u64 +
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        self.expiry_queue.lock().add_entry(expires_ms, channel_key);

        // Update statistics
        self.stats.channels_created.fetch_add(1, Ordering::Relaxed);

        info!("Channel bound: {} -> {} (channel: {}, expires in {:?})",
            allocation_key.allocation_id, peer_addr, channel_number, lifetime);

        Ok(())
    }

    /// Get channel binding by channel number
    pub async fn get_channel_binding(
        &self,
        allocation_key: &AllocationKey,
        channel_number: u16,
    ) -> Option<Arc<ChannelBinding>> {
        let channel_key = (*allocation_key, channel_number);

        if let Some(binding) = self.channels.get(&channel_key) {
            let now = Instant::now();
            if binding.expires_at > now {
                // Update activity
                let now_millis = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                binding.last_activity.store(now_millis, Ordering::Relaxed);

                Some(binding.clone())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get channel number for peer address
    pub async fn get_channel_for_peer(
        &self,
        allocation_key: &AllocationKey,
        peer_addr: SocketAddr,
    ) -> Option<u16> {
        let peer_key = (*allocation_key, peer_addr);
        self.peer_channels.get(&peer_key).map(|entry| *entry.value())
    }

    /// Process channel data packet
    #[instrument(skip(self, data), level = "trace")]
    pub async fn process_channel_data(
        &self,
        allocation_key: &AllocationKey,
        channel_number: u16,
        data: Bytes,
    ) -> NatResult<Option<SocketAddr>> {
        let channel_key = (*allocation_key, channel_number);

        if let Some(binding) = self.channels.get(&channel_key) {
            if binding.expires_at <= Instant::now() {
                return Err(NatError::Platform("Channel binding expired".to_string()));
            }

            // Validate data size
            if data.len() > binding.config.max_packet_size as usize {
                binding.stats.data_relay_errors.fetch_add(1, Ordering::Relaxed);
                return Err(NatError::Platform("Channel data exceeds maximum size".to_string()));
            }

            // Security validation
            if !self.security_validator.validate_channel_data(&data, &binding).await? {
                binding.security_context.violations.fetch_add(1, Ordering::Relaxed);
                return Err(NatError::Platform("Channel data blocked by security policy".to_string()));
            }

            // Update statistics
            binding.stats.channel_data_packets.fetch_add(1, Ordering::Relaxed);
            binding.stats.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);

            // Update flow metrics
            self.update_flow_metrics(&binding, data.len()).await;

            // Cache data if beneficial
            if self.should_cache_data(channel_number, &data) {
                self.data_cache.cache_data(channel_number, data.clone()).await;
            }

            // Update activity
            let now_millis = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            binding.last_activity.store(now_millis, Ordering::Relaxed);

            Ok(Some(binding.peer_addr))
        } else {
            Err(NatError::Platform("Channel binding not found".to_string()))
        }
    }

    /// Encode channel data packet
    pub async fn encode_channel_data(
        &self,
        channel_number: u16,
        data: &[u8],
    ) -> NatResult<Bytes> {
        if data.len() > 65535 - 4 {
            return Err(NatError::Platform("Data too large for channel packet".to_string()));
        }

        let mut packet = Vec::with_capacity(4 + data.len());

        // Channel Data header (RFC 5766 Section 11.4)
        packet.extend_from_slice(&channel_number.to_be_bytes());  // Channel Number
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes()); // Length
        packet.extend_from_slice(data); // Data

        // Padding to 4-byte boundary
        let padding = (4 - (data.len() % 4)) % 4;
        packet.extend(vec![0u8; padding]);

        Ok(Bytes::from(packet))
    }

    /// Decode channel data packet
    pub async fn decode_channel_data(
        &self,
        packet: &[u8],
    ) -> NatResult<(u16, Bytes)> {
        if packet.len() < 4 {
            return Err(NatError::Platform("Channel data packet too short".to_string()));
        }

        let channel_number = u16::from_be_bytes([packet[0], packet[1]]);
        let data_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;

        if packet.len() < 4 + data_length {
            return Err(NatError::Platform("Channel data packet length mismatch".to_string()));
        }

        let data = Bytes::copy_from_slice(&packet[4..4 + data_length]);

        Ok((channel_number, data))
    }

    /// Update flow metrics for channel
    async fn update_flow_metrics(&self, binding: &ChannelBinding, data_size: usize) {
        let now = SystemTime::now();
        let current_throughput = binding.flow_metrics.current_throughput.load(Ordering::Relaxed);

        // Simple throughput calculation (would be more sophisticated in production)
        let new_throughput = current_throughput + data_size as u64;
        binding.flow_metrics.current_throughput.store(new_throughput, Ordering::Relaxed);

        // Update peak throughput
        let peak = binding.flow_metrics.peak_throughput.load(Ordering::Relaxed);
        if new_throughput > peak {
            binding.flow_metrics.peak_throughput.store(new_throughput, Ordering::Relaxed);
        }

        // Update packet counts
        binding.stats.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Check if data should be cached
    fn should_cache_data(&self, channel_number: u16, data: &Bytes) -> bool {
        // Cache small, frequently accessed data
        data.len() < 1024 && self.data_cache.should_cache(channel_number)
    }

    /// Remove all channels for allocation
    pub async fn remove_allocation_channels(
        &self,
        allocation_key: &AllocationKey,
    ) -> NatResult<()> {
        debug!("Removing all channels for allocation {}", allocation_key.allocation_id);

        if let Some((_, channel_numbers)) = self.allocation_channels.remove(allocation_key) {
            for channel_number in channel_numbers {
                let channel_key = (*allocation_key, channel_number);

                // Remove channel binding
                if let Some((_, binding)) = self.channels.remove(&channel_key) {
                    // Remove peer channel mapping
                    let peer_key = (*allocation_key, binding.peer_addr);
                    self.peer_channels.remove(&peer_key);

                    // Return channel number to pool
                    self.available_channels.deallocate_channel(channel_number).await;

                    // Return to pool
                    if let Ok(mut binding_box) = Arc::try_unwrap(binding) {
                        binding_box.reset();
                        self.binding_pool.push(Box::new(binding_box));
                    }

                    self.stats.channels_closed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        Ok(())
    }

    /// Start cleanup task for expired channels
    pub async fn start_cleanup_task(&self) {
        let manager = self.clone_for_task();

        let task = tokio::spawn(async move {
            manager.cleanup_loop().await;
        });

        *self.cleanup_task.lock().await = Some(task);
        info!("Channel cleanup task started");
    }

    /// Main cleanup loop
    async fn cleanup_loop(self: Arc<Self>) {
        let mut cleanup_interval = interval(Duration::from_secs(30));

        while self.active.load(Ordering::Relaxed) {
            cleanup_interval.tick().await;

            let cleanup_start = Instant::now();
            let expired_count = self.cleanup_expired_channels().await;
            let cleanup_duration = cleanup_start.elapsed();

            if expired_count > 0 {
                debug!("Cleaned up {} expired channels in {:?}",
                    expired_count, cleanup_duration);
            }

            // Clean cache
            self.data_cache.cleanup_expired().await;
        }

        info!("Channel cleanup task stopped");
    }

    /// Clean up expired channels
    async fn cleanup_expired_channels(&self) -> usize {
        let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let mut expired_keys = Vec::new();

        // Get expired entries from queue
        {
            let mut queue = self.expiry_queue.lock();
            queue.get_expired_entries(now, &mut expired_keys);
        }

        let mut cleaned_count = 0;

        // Remove expired channels
        for channel_key in expired_keys {
            if let Some((_, binding)) = self.channels.remove(&channel_key) {
                let (allocation_key, channel_number) = channel_key;

                // Update allocation channels
                if let Some(mut channels) = self.allocation_channels.get_mut(&allocation_key) {
                    channels.retain(|&ch| ch != channel_number);
                }

                // Remove peer channel mapping
                let peer_key = (allocation_key, binding.peer_addr);
                self.peer_channels.remove(&peer_key);

                // Return channel number to pool
                self.available_channels.deallocate_channel(channel_number).await;

                // Return to pool
                if let Ok(mut binding_box) = Arc::try_unwrap(binding) {
                    binding_box.reset();
                    self.binding_pool.push(Box::new(binding_box));
                }

                cleaned_count += 1;
                self.stats.channels_expired.fetch_add(1, Ordering::Relaxed);
            }
        }

        cleaned_count
    }

    /// Clone for async tasks
    fn clone_for_task(&self) -> Arc<Self> {
        unreachable!("Use Arc<ChannelManager>")
    }

    /// Shutdown channel manager
    pub async fn shutdown(&self) -> NatResult<()> {
        info!("Shutting down channel manager");

        self.active.store(false, Ordering::Relaxed);

        // Stop cleanup task
        if let Some(task) = self.cleanup_task.lock().await.take() {
            task.abort();
        }

        // Clean up all channels
        self.channels.clear();
        self.allocation_channels.clear();
        self.peer_channels.clear();

        info!("Channel manager shutdown complete");
        Ok(())
    }
}

// Implementation of helper structures

impl<T> ExpirationQueue<T> {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            count: 0,
        }
    }

    fn add_entry(&mut self, expires_at: u64, item: T) {
        self.entries.entry(expires_at)
            .or_insert_with(Vec::new)
            .push(item);
        self.count += 1;
    }

    fn get_expired_entries(&mut self, now: u64, expired: &mut Vec<T>) {
        let expired_times: Vec<u64> = self.entries.range(..=now)
            .map(|(time, _)| *time)
            .collect();

        for time in expired_times {
            if let Some(items) = self.entries.remove(&time) {
                self.count = self.count.saturating_sub(items.len());
                expired.extend(items);
            }
        }
    }
}

impl Permission {
    fn new_empty() -> Self {
        Self {
            peer_ip: "0.0.0.0".parse().unwrap(),
            created_at: Instant::now(),
            expires_at: Instant::now(),
            last_activity: AtomicU64::new(0),
            stats: PermissionUsageStats::default(),
            flags: PermissionFlags {
                bidirectional: true,
                monitor_traffic: false,
                bandwidth_limited: false,
                allow_upgrades: false,
                temporary: false,
            },
            security_context: PermissionSecurityContext {
                validation_level: ValidationLevel::Basic,
                allowed_protocols: HashSet::new(),
                pattern_analysis: TrafficPattern::default(),
                threat_score: AtomicU32::new(0),
                anomaly_flags: AtomicU32::new(0),
            },
        }
    }

    fn initialize(&mut self, peer_ip: IpAddr, expires_at: Instant) {
        self.peer_ip = peer_ip;
        self.created_at = Instant::now();
        self.expires_at = expires_at;
        self.last_activity.store(
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
            Ordering::Relaxed
        );
        self.stats = PermissionUsageStats::default();
        self.security_context.threat_score.store(0, Ordering::Relaxed);
        self.security_context.anomaly_flags.store(0, Ordering::Relaxed);
    }

    fn reset(&mut self) {
        self.peer_ip = "0.0.0.0".parse().unwrap();
        self.stats = PermissionUsageStats::default();
        self.security_context.threat_score.store(0, Ordering::Relaxed);
        self.security_context.anomaly_flags.store(0, Ordering::Relaxed);
    }
}

impl ChannelBinding {
    fn new_empty() -> Self {
        Self {
            channel_number: 0,
            peer_addr: "0.0.0.0:0".parse().unwrap(),
            created_at: Instant::now(),
            expires_at: Instant::now(),
            last_activity: AtomicU64::new(0),
            stats: ChannelUsageStats::default(),
            config: ChannelConfig {
                max_packet_size: 65535,
                compression: false,
                encryption: false,
                qos: QosSettings {
                    priority: 0,
                    bandwidth_allocation: 0,
                    max_latency: Duration::from_millis(100),
                    jitter_tolerance: Duration::from_millis(50),
                    loss_tolerance: 1.0,
                },
                flow_control: FlowControlSettings {
                    enabled: false,
                    window_size: 8192,
                    congestion_algorithm: CongestionAlgorithm::None,
                    rate_limit: None,
                },
            },
            flow_metrics: ChannelFlowMetrics::default(),
            security_context: ChannelSecurityContext {
                encrypted: false,
                authenticated: false,
                integrity_protected: false,
                sequence_number: AtomicU64::new(0),
                violations: AtomicU32::new(0),
            },
        }
    }

    fn initialize(&mut self, channel_number: u16, peer_addr: SocketAddr, expires_at: Instant) {
        self.channel_number = channel_number;
        self.peer_addr = peer_addr;
        self.created_at = Instant::now();
        self.expires_at = expires_at;
        self.last_activity.store(
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
            Ordering::Relaxed
        );
        self.stats = ChannelUsageStats::default();
        self.flow_metrics = ChannelFlowMetrics::default();
        self.security_context.violations.store(0, Ordering::Relaxed);
        self.security_context.sequence_number.store(0, Ordering::Relaxed);
    }

    fn reset(&mut self) {
        self.channel_number = 0;
        self.peer_addr = "0.0.0.0:0".parse().unwrap();
        self.stats = ChannelUsageStats::default();
        self.flow_metrics = ChannelFlowMetrics::default();
        self.security_context.violations.store(0, Ordering::Relaxed);
        self.security_context.sequence_number.store(0, Ordering::Relaxed);
    }
}

impl ChannelPool {
    async fn new() -> NatResult<Self> {
        let available = SegQueue::new();

        // Add all valid channel numbers (0x4000-0x7FFF)
        for channel in 0x4000..=0x7FFF {
            available.push(channel);
        }

        let total_size = 0x7FFF - 0x4000 + 1;

        Ok(Self {
            available,
            total_size: AtomicU32::new(total_size as u32),
            available_count: AtomicU32::new(total_size as u32),
            strategy: ChannelAllocationStrategy::Random,
        })
    }

    async fn allocate_channel(&self, channel_number: u16) -> bool {
        // For now, simply check if channel is in range
        if channel_number >= 0x4000 && channel_number <= 0x7FFF {
            self.available_count.fetch_sub(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    async fn deallocate_channel(&self, channel_number: u16) {
        if channel_number >= 0x4000 && channel_number <= 0x7FFF {
            self.available.push(channel_number);
            self.available_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl ChannelDataCache {
    fn new(config: CacheConfig) -> Self {
        Self {
            cache: DashMap::with_capacity(config.max_size),
            config,
            stats: CacheStats::default(),
        }
    }

    async fn cache_data(&self, channel_number: u16, data: Bytes) {
        if self.cache.len() >= self.config.max_size {
            self.evict_entries().await;
        }

        let cached_data = CachedChannelData {
            channel_number,
            data: data.clone(),
            cached_at: Instant::now(),
            access_count: AtomicU32::new(0),
            last_access: AtomicU64::new(
                SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
            ),
        };

        self.cache.insert(channel_number, cached_data);
        self.stats.memory_usage.fetch_add(data.len() as u64, Ordering::Relaxed);
    }

    fn should_cache(&self, channel_number: u16) -> bool {
        // Simple heuristic: cache if channel is frequently used
        if let Some(entry) = self.cache.get(&channel_number) {
            entry.access_count.load(Ordering::Relaxed) > 5
        } else {
            false
        }
    }

    async fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut expired_channels = Vec::new();

        for entry in self.cache.iter() {
            let cached_data = entry.value();
            if now.duration_since(cached_data.cached_at) > self.config.ttl {
                expired_channels.push(*entry.key());
            }
        }

        for channel in expired_channels {
            if let Some((_, cached_data)) = self.cache.remove(&channel) {
                self.stats.memory_usage.fetch_sub(cached_data.data.len() as u64, Ordering::Relaxed);
                self.stats.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    async fn evict_entries(&self) {
        // Simple LRU eviction
        let mut oldest_access = u64::MAX;
        let mut oldest_channel = None;

        for entry in self.cache.iter() {
            let last_access = entry.value().last_access.load(Ordering::Relaxed);
            if last_access < oldest_access {
                oldest_access = last_access;
                oldest_channel = Some(*entry.key());
            }
        }

        if let Some(channel) = oldest_channel {
            if let Some((_, cached_data)) = self.cache.remove(&channel) {
                self.stats.memory_usage.fetch_sub(cached_data.data.len() as u64, Ordering::Relaxed);
                self.stats.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// Security validator implementations
impl PermissionSecurityValidator {
    async fn new() -> NatResult<Self> {
        Ok(Self {
            policies: vec![],
            threat_intel: Arc::new(ThreatIntelligence::new().await?),
            validation_cache: DashMap::new(),
            stats: SecurityValidationStats::default(),
        })
    }

    async fn validate_peer_ip(&self, peer_ip: IpAddr) -> NatResult<bool> {
        // Check cache first
        if let Some(cached) = self.validation_cache.get(&peer_ip) {
            if cached.cached_at.elapsed() < cached.ttl {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                cached.hit_count.fetch_add(1, Ordering::Relaxed);
                return Ok(matches!(cached.result, ValidationResult::Allow));
            }
        }

        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

        // Check threat intelligence
        if self.threat_intel.is_malicious(peer_ip).await {
            self.stats.threats_detected.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        // Apply security policies
        for policy in &self.policies {
            if !self.check_ip_policy(peer_ip, policy).await? {
                return Ok(false);
            }
        }

        // Cache result
        let cache_entry = ValidationCacheEntry {
            result: ValidationResult::Allow,
            cached_at: Instant::now(),
            ttl: Duration::from_secs(300),
            hit_count: AtomicU32::new(0),
        };
        self.validation_cache.insert(peer_ip, cache_entry);

        self.stats.validations_passed.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    async fn check_ip_policy(&self, ip: IpAddr, policy: &PermissionSecurityPolicy) -> NatResult<bool> {
        for filter in &policy.ip_filters {
            match filter {
                IpFilter::Block(blocked_ip) if ip == *blocked_ip => return Ok(false),
                IpFilter::BlockSubnet { network, prefix } => {
                    if self.ip_in_subnet(ip, *network, *prefix) {
                        return Ok(false);
                    }
                }
                IpFilter::BlockCountry(country) => {
                    // Would check GeoIP database
                    if self.ip_in_country(ip, country).await? {
                        return Ok(false);
                    }
                }
                _ => {} // Allow rules don't block
            }
        }
        Ok(true)
    }

    fn ip_in_subnet(&self, ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
        // Simplified subnet check
        match (ip, network) {
            (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
                let mask = !((1u32 << (32 - prefix)) - 1);
                (u32::from(ip4) & mask) == (u32::from(net4) & mask)
            }
            _ => false, // IPv6 not implemented for brevity
        }
    }

    async fn ip_in_country(&self, ip: IpAddr, country: &str) -> NatResult<bool> {
        // Would use GeoIP service
        Ok(false) // Simplified
    }
}

impl ChannelSecurityValidator {
    async fn new() -> NatResult<Self> {
        Ok(Self {
            policies: vec![],
            protocol_validators: HashMap::new(),
            validation_cache: DashMap::new(),
            stats: SecurityValidationStats::default(),
        })
    }

    async fn validate_channel_binding(&self, channel_number: u16, peer_addr: SocketAddr) -> NatResult<bool> {
        // Basic validation
        if channel_number < 0x4000 || channel_number > 0x7FFF {
            return Ok(false);
        }

        // Apply security policies
        for policy in &self.policies {
            if !self.check_channel_policy(channel_number, peer_addr, policy).await? {
                return Ok(false);
            }
        }

        Ok(true)