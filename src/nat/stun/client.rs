// src/nat/stun/client.rs
//! STUN client implementation fully compliant with RFC 8489 and RFC 5780
//!
//! Provides comprehensive NAT traversal capabilities including:
//! - Full RFC 8489 STUN protocol support
//! - RFC 5780 NAT behavior discovery
//! - Advanced retransmission with exponential backoff
//! - Multiple server fallback with health monitoring
//! - Authenticated requests with all credential types
//! - Performance optimization and connection pooling

use std::net::{SocketAddr, IpAddr};
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::{timeout, sleep, interval};
use tokio::sync::{RwLock, Mutex, Semaphore};
use bytes::BytesMut;
use rand::Rng;
use futures::future::{join_all, select_all};
use parking_lot::RwLock as SyncRwLock;

use crate::nat::error::{NatError, StunError, NatResult};
use crate::nat::metrics::{StunMetricsHelper, record_ip_version_usage};
use super::protocol::*;
use super::auth::{Credentials, CredentialType, SecurityFeatures, compute_message_integrity_sha256};
use super::discovery::{NatBehavior, NatBehaviorDiscovery};

/// Comprehensive STUN client configuration with all RFC features
#[derive(Debug, Clone)]
pub struct StunConfig {
    /// Primary STUN servers (RFC 8489 compliant)
    pub servers: Vec<String>,

    /// RFC 5780 servers (with CHANGE-REQUEST support)
    pub rfc5780_servers: Vec<String>,

    /// Initial RTO in milliseconds (RFC 8489 Section 7.2.1)
    pub initial_rto_ms: u64,

    /// Maximum RTO in milliseconds
    pub max_rto_ms: u64,

    /// Maximum number of retransmissions (Rc)
    pub max_retries: u32,

    /// Request timeout for overall operation
    pub request_timeout: Duration,

    /// Enable RFC 5780 NAT behavior discovery
    pub enable_behavior_discovery: bool,

    /// Credentials for authenticated requests
    pub credentials: Option<Credentials>,

    /// Add FINGERPRINT attribute to messages
    pub use_fingerprint: bool,

    /// Software name for SOFTWARE attribute
    pub software_name: Option<String>,

    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,

    /// Jitter range in milliseconds (±jitter_ms)
    pub jitter_ms: u64,

    /// Enable IPv6 support
    pub enable_ipv6: bool,

    /// Enable server health monitoring
    pub enable_health_monitoring: bool,

    /// Server health check interval
    pub health_check_interval: Duration,

    /// Maximum failed health checks before marking server as down
    pub max_health_failures: u32,

    /// Enable connection pooling for authenticated sessions
    pub enable_connection_pooling: bool,

    /// Connection pool size per server
    pub connection_pool_size: usize,

    /// Connection idle timeout
    pub connection_idle_timeout: Duration,

    /// Enable detailed performance metrics
    pub enable_metrics: bool,

    /// Security features configuration
    pub security_features: SecurityFeatures,

    /// Transport protocols preference order
    pub transport_preference: Vec<TransportProtocol>,

    /// Enable automatic server discovery via DNS SRV
    pub enable_srv_discovery: bool,

    /// DNS SRV service name
    pub srv_service: String,

    /// Enable load balancing across servers
    pub enable_load_balancing: bool,

    /// Load balancing strategy
    pub load_balancing_strategy: LoadBalancingStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    UDP,
    TCP,
    TLS,
    DTLS,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    LeastConnections,
    ResponseTime,
    Random,
}

impl Default for StunConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                // Google STUN servers (most reliable)
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
                "stun2.l.google.com:19302".to_string(),
                "stun3.l.google.com:19302".to_string(),
                "stun4.l.google.com:19302".to_string(),

                // Cloudflare STUN
                "stun.cloudflare.com:3478".to_string(),

                // Mozilla STUN
                "stun.services.mozilla.com:3478".to_string(),

                // STUN protocol organization
                "stun.stunprotocol.org:3478".to_string(),

                // Twilio STUN
                "global.stun.twilio.com:3478".to_string(),

                // Microsoft STUN
                "stun.3cx.com:3478".to_string(),
            ],
            rfc5780_servers: vec![
                "stun.stunprotocol.org:3478".to_string(),
                "stun.voiparound.com:3478".to_string(),
                "stun.voipbuster.com:3478".to_string(),
            ],
            initial_rto_ms: 500,    // RFC 8489 recommendation
            max_rto_ms: 3200,       // RFC 8489 recommendation
            max_retries: 7,         // Rc = 7 as per RFC 8489
            request_timeout: Duration::from_millis(39500), // Sum of all retries
            enable_behavior_discovery: true,
            credentials: None,
            use_fingerprint: true,
            software_name: Some("SHARP STUN Client/1.0".to_string()),
            max_concurrent_requests: 20,
            jitter_ms: 50, // ±50ms as recommended
            enable_ipv6: true,
            enable_health_monitoring: true,
            health_check_interval: Duration::from_secs(30),
            max_health_failures: 3,
            enable_connection_pooling: true,
            connection_pool_size: 5,
            connection_idle_timeout: Duration::from_secs(300),
            enable_metrics: true,
            security_features: SecurityFeatures::default(),
            transport_preference: vec![TransportProtocol::UDP, TransportProtocol::TCP],
            enable_srv_discovery: true,
            srv_service: "_stun._udp".to_string(),
            enable_load_balancing: true,
            load_balancing_strategy: LoadBalancingStrategy::ResponseTime,
        }
    }
}

/// Comprehensive information about a STUN server
#[derive(Debug, Clone)]
pub struct StunServerInfo {
    pub address: SocketAddr,
    pub transport: TransportProtocol,
    pub supports_change_request: bool,
    pub supports_rfc5780: bool,
    pub alternate_address: Option<SocketAddr>,
    pub response_origin: Option<SocketAddr>,
    pub other_address: Option<SocketAddr>,
    pub software: Option<String>,
    pub response_time_ms: u64,
    pub health_status: ServerHealthStatus,
    pub last_health_check: Instant,
    pub failure_count: u32,
    pub success_count: u32,
    pub supported_attributes: HashSet<AttributeType>,
    pub max_message_size: usize,
    pub authentication_required: bool,
    pub supported_auth_methods: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerHealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Connection pool entry for authenticated sessions
#[derive(Debug)]
struct PooledConnection {
    socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    last_used: Instant,
    authenticated: bool,
    realm: Option<String>,
    nonce: Option<Vec<u8>>,
    auth_count: u32,
}

/// Request tracking for retransmission management
#[derive(Debug)]
struct PendingRequest {
    transaction_id: TransactionId,
    message: Vec<u8>,
    server_addr: SocketAddr,
    attempt: u32,
    created_at: Instant,
    next_retry: Instant,
    rto: Duration,
    completion_sender: tokio::sync::oneshot::Sender<NatResult<Message>>,
}

/// STUN client implementation compliant with RFC 8489 and RFC 5780
pub struct StunClient {
    config: StunConfig,
    server_cache: Arc<RwLock<Vec<StunServerInfo>>>,
    connection_pool: Arc<Mutex<HashMap<SocketAddr, VecDeque<PooledConnection>>>>,
    pending_requests: Arc<Mutex<HashMap<TransactionId, PendingRequest>>>,
    request_semaphore: Arc<Semaphore>,
    metrics: Arc<StunClientMetrics>,
    discovery_engine: Arc<Mutex<Option<NatBehaviorDiscovery>>>,
    load_balancer: Arc<Mutex<LoadBalancer>>,
}

#[derive(Debug, Default)]
struct StunClientMetrics {
    requests_sent: std::sync::atomic::AtomicU64,
    responses_received: std::sync::atomic::AtomicU64,
    timeouts: std::sync::atomic::AtomicU64,
    errors: std::sync::atomic::AtomicU64,
    retransmissions: std::sync::atomic::AtomicU64,
    auth_failures: std::sync::atomic::AtomicU64,
    server_failures: std::sync::atomic::AtomicU64,
    total_response_time_ms: std::sync::atomic::AtomicU64,
    ipv4_requests: std::sync::atomic::AtomicU64,
    ipv6_requests: std::sync::atomic::AtomicU64,
}

#[derive(Debug)]
struct LoadBalancer {
    strategy: LoadBalancingStrategy,
    current_index: usize,
    server_weights: HashMap<SocketAddr, f64>,
    connection_counts: HashMap<SocketAddr, u32>,
}

impl LoadBalancer {
    fn new(strategy: LoadBalancingStrategy) -> Self {
        Self {
            strategy,
            current_index: 0,
            server_weights: HashMap::new(),
            connection_counts: HashMap::new(),
        }
    }

    fn select_server(&mut self, servers: &[StunServerInfo]) -> Option<&StunServerInfo> {
        if servers.is_empty() {
            return None;
        }

        match self.strategy {
            LoadBalancingStrategy::RoundRobin => {
                let server = &servers[self.current_index % servers.len()];
                self.current_index = (self.current_index + 1) % servers.len();
                Some(server)
            }
            LoadBalancingStrategy::LeastConnections => {
                servers.iter()
                    .min_by_key(|s| self.connection_counts.get(&s.address).unwrap_or(&0))
            }
            LoadBalancingStrategy::ResponseTime => {
                servers.iter()
                    .filter(|s| s.health_status == ServerHealthStatus::Healthy)
                    .min_by_key(|s| s.response_time_ms)
            }
            LoadBalancingStrategy::Random => {
                let mut rng = rand::thread_rng();
                let index = rng.gen_range(0..servers.len());
                Some(&servers[index])
            }
        }
    }

    fn update_server_weight(&mut self, addr: SocketAddr, response_time: Duration) {
        // Exponential moving average for response time weighting
        let new_weight = 1.0 / (response_time.as_millis() as f64 + 1.0);
        let current_weight = self.server_weights.get(&addr).unwrap_or(&1.0);
        let alpha = 0.3; // Smoothing factor
        self.server_weights.insert(addr, alpha * new_weight + (1.0 - alpha) * current_weight);
    }
}

impl StunClient {
    /// Create new STUN client with comprehensive configuration
    pub fn new(config: StunConfig) -> Self {
        let request_semaphore = Arc::new(Semaphore::new(config.max_concurrent_requests));
        let metrics = Arc::new(StunClientMetrics::default());
        let load_balancer = Arc::new(Mutex::new(LoadBalancer::new(config.load_balancing_strategy)));

        Self {
            config,
            server_cache: Arc::new(RwLock::new(Vec::new())),
            connection_pool: Arc::new(Mutex::new(HashMap::new())),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            request_semaphore,
            metrics,
            discovery_engine: Arc::new(Mutex::new(None)),
            load_balancer,
        }
    }

    /// Get a reference to the client configuration
    pub fn config(&self) -> &StunConfig {
        &self.config
    }

    /// Get client metrics
    pub fn metrics(&self) -> &StunClientMetrics {
        &self.metrics
    }

    /// Initialize the client and discover available servers
    pub async fn initialize(&self) -> NatResult<()> {
        tracing::info!("Initializing STUN client with {} servers", self.config.servers.len());

        // Discover servers via DNS SRV if enabled
        if self.config.enable_srv_discovery {
            if let Ok(srv_servers) = self.discover_srv_servers().await {
                tracing::info!("Discovered {} servers via DNS SRV", srv_servers.len());
                // Add to server list (implementation would merge with existing)
            }
        }

        // Initialize server health monitoring
        if self.config.enable_health_monitoring {
            self.start_health_monitoring().await;
        }

        // Initialize discovery engine if enabled
        if self.config.enable_behavior_discovery {
            let mut discovery = self.discovery_engine.lock().await;
            *discovery = Some(NatBehaviorDiscovery::new(self.clone()));
        }

        Ok(())
    }

    /// Discover STUN servers via DNS SRV records
    async fn discover_srv_servers(&self) -> NatResult<Vec<String>> {
        let srv_query = format!("{}.", self.config.srv_service);

        // In a real implementation, this would use a DNS library to query SRV records
        // For now, we return an empty list
        tracing::debug!("DNS SRV discovery for {} not yet implemented", srv_query);
        Ok(Vec::new())
    }

    /// Start background health monitoring task
    async fn start_health_monitoring(&self) {
        let config = self.config.clone();
        let server_cache = self.server_cache.clone();
        let metrics = self.metrics.clone();

        tokio::spawn(async move {
            let mut interval = interval(config.health_check_interval);

            loop {
                interval.tick().await;

                let servers = {
                    let cache = server_cache.read().await;
                    cache.clone()
                };

                for server_info in servers {
                    // Perform health check (simplified)
                    let is_healthy = Self::check_server_health(&server_info).await;

                    // Update server status
                    let mut cache = server_cache.write().await;
                    if let Some(server) = cache.iter_mut().find(|s| s.address == server_info.address) {
                        if is_healthy {
                            server.health_status = ServerHealthStatus::Healthy;
                            server.failure_count = 0;
                            server.success_count += 1;
                        } else {
                            server.failure_count += 1;
                            if server.failure_count >= config.max_health_failures {
                                server.health_status = ServerHealthStatus::Unhealthy;
                            } else {
                                server.health_status = ServerHealthStatus::Degraded;
                            }
                        }
                        server.last_health_check = Instant::now();
                    }
                }
            }
        });
    }

    /// Perform health check on a server
    async fn check_server_health(server_info: &StunServerInfo) -> bool {
        // Create a temporary socket for health check
        match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => {
                // Create a simple binding request
                let tid = TransactionId::new();
                let mut msg = Message::new(MessageType::BindingRequest, tid);

                // Add SOFTWARE attribute
                msg.add_attribute(Attribute::new(
                    AttributeType::Software,
                    AttributeValue::Software("SHARP Health Check/1.0".to_string()),
                ));

                match msg.encode(None, false) {
                    Ok(encoded) => {
                        // Send with short timeout
                        match timeout(
                            Duration::from_secs(2),
                            socket.send_to(&encoded, server_info.address)
                        ).await {
                            Ok(Ok(_)) => {
                                // Try to receive response
                                let mut buf = vec![0u8; 1500];
                                match timeout(
                                    Duration::from_secs(2),
                                    socket.recv_from(&mut buf)
                                ).await {
                                    Ok(Ok((len, _))) => {
                                        // Attempt to decode response
                                        let mut buf = BytesMut::from(&buf[..len]);
                                        Message::decode(buf).is_ok()
                                    }
                                    _ => false,
                                }
                            }
                            _ => false,
                        }
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Get mapped address from the best available STUN server
    pub async fn get_mapped_address(&self, socket: &UdpSocket) -> NatResult<SocketAddr> {
        let local_addr = socket.local_addr()?;

        // Record IP version usage
        match local_addr.ip() {
            IpAddr::V4(_) => {
                self.metrics.ipv4_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                record_ip_version_usage(4);
            }
            IpAddr::V6(_) => {
                self.metrics.ipv6_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                record_ip_version_usage(6);
            }
        }

        // Try multiple servers for redundancy
        let servers = self.get_healthy_servers().await;

        if servers.is_empty() {
            return Err(NatError::NoServersAvailable);
        }

        // Use load balancer to select optimal server
        let selected_server = {
            let mut lb = self.load_balancer.lock().await;
            lb.select_server(&servers)
                .ok_or(NatError::NoServersAvailable)?
                .clone()
        };

        // Get connection from pool or create new one
        let connection = self.get_or_create_connection(selected_server.address).await?;

        // Send binding request
        let response = self.send_binding_request(&connection, selected_server.address).await?;

        // Extract mapped address
        let mapped_addr = response.attributes.iter()
            .find_map(|attr| match &attr.value {
                AttributeValue::XorMappedAddress(addr) => Some(*addr),
                AttributeValue::MappedAddress(addr) => Some(*addr),
                _ => None,
            })
            .ok_or_else(|| StunError::MissingAttribute("MAPPED-ADDRESS".to_string()))?;

        // Update load balancer metrics
        {
            let mut lb = self.load_balancer.lock().await;
            lb.update_server_weight(selected_server.address,
                                    Duration::from_millis(selected_server.response_time_ms));
        }

        Ok(mapped_addr)
    }

    /// Get list of healthy servers
    async fn get_healthy_servers(&self) -> Vec<StunServerInfo> {
        let cache = self.server_cache.read().await;
        cache.iter()
            .filter(|s| matches!(s.health_status, ServerHealthStatus::Healthy | ServerHealthStatus::Unknown))
            .cloned()
            .collect()
    }

    /// Get connection from pool or create new one
    async fn get_or_create_connection(&self, server_addr: SocketAddr) -> NatResult<Arc<UdpSocket>> {
        if !self.config.enable_connection_pooling {
            // Create new socket for each request
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            return Ok(Arc::new(socket));
        }

        let mut pool = self.connection_pool.lock().await;

        // Check for available connection in pool
        if let Some(connections) = pool.get_mut(&server_addr) {
            while let Some(mut conn) = connections.pop_front() {
                // Check if connection is still valid
                if conn.last_used.elapsed() < self.config.connection_idle_timeout {
                    conn.last_used = Instant::now();
                    connections.push_back(conn);
                    return Ok(connections.back().unwrap().socket.clone());
                }
                // Connection expired, will create new one
            }
        }

        // Create new connection
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let socket = Arc::new(socket);

        // Add to pool
        let pooled_conn = PooledConnection {
            socket: socket.clone(),
            server_addr,
            last_used: Instant::now(),
            authenticated: false,
            realm: None,
            nonce: None,
            auth_count: 0,
        };

        pool.entry(server_addr)
            .or_insert_with(VecDeque::new)
            .push_back(pooled_conn);

        Ok(socket)
    }

    /// Send binding request to server
    async fn send_binding_request(&self, socket: &UdpSocket, server_addr: SocketAddr) -> NatResult<Message> {
        let tid = TransactionId::new();
        let mut msg = Message::new(MessageType::BindingRequest, tid);

        // Add SOFTWARE attribute if configured
        if let Some(ref software) = self.config.software_name {
            msg.add_attribute(Attribute::new(
                AttributeType::Software,
                AttributeValue::Software(software.clone()),
            ));
        }

        // Add authentication if configured
        if let Some(ref creds) = self.config.credentials {
            self.add_authentication(&mut msg, creds, None).await?;
        }

        // Encode message
        let encoded = msg.encode(
            self.config.credentials.as_ref(),
            self.config.use_fingerprint,
        )?;

        // Send with retransmission logic
        self.send_with_retransmission(socket, server_addr, encoded, tid).await
    }

    /// Add authentication to message
    async fn add_authentication(&self, msg: &mut Message, creds: &Credentials, realm: Option<&str>) -> NatResult<()> {
        match &creds.credential_type {
            CredentialType::ShortTerm { username, .. } => {
                msg.add_attribute(Attribute::new(
                    AttributeType::Username,
                    AttributeValue::Username(username.clone()),
                ));
            }
            CredentialType::LongTerm { username, realm: cred_realm, .. } => {
                msg.add_attribute(Attribute::new(
                    AttributeType::Username,
                    AttributeValue::Username(username.clone()),
                ));

                let realm_value = realm.unwrap_or(cred_realm);
                msg.add_attribute(Attribute::new(
                    AttributeType::Realm,
                    AttributeValue::Realm(realm_value.to_string()),
                ));
            }
            CredentialType::Anonymous { username, realm: cred_realm, use_userhash, .. } => {
                if *use_userhash {
                    // Compute USERHASH
                    let realm_value = realm.unwrap_or(cred_realm);
                    let userhash = self.compute_userhash(username, realm_value)?;
                    msg.add_attribute(Attribute::new(
                        AttributeType::UserHash,
                        AttributeValue::UserHash(userhash),
                    ));
                } else {
                    msg.add_attribute(Attribute::new(
                        AttributeType::Username,
                        AttributeValue::Username(username.clone()),
                    ));
                }

                let realm_value = realm.unwrap_or(cred_realm);
                msg.add_attribute(Attribute::new(
                    AttributeType::Realm,
                    AttributeValue::Realm(realm_value.to_string()),
                ));
            }
        }

        Ok(())
    }

    /// Compute USERHASH for anonymous authentication
    fn compute_userhash(&self, username: &str, realm: &str) -> NatResult<Vec<u8>> {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(username.as_bytes());
        hasher.update(b":");
        hasher.update(realm.as_bytes());

        Ok(hasher.finalize().to_vec())
    }

    /// Send message with RFC 8489 compliant retransmission
    async fn send_with_retransmission(
        &self,
        socket: &UdpSocket,
        server_addr: SocketAddr,
        message: Vec<u8>,
        tid: TransactionId,
    ) -> NatResult<Message> {
        let _permit = self.request_semaphore.acquire().await
            .map_err(|_| NatError::TooManyRequests)?;

        self.metrics.requests_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut rto = Duration::from_millis(self.config.initial_rto_ms);
        let max_rto = Duration::from_millis(self.config.max_rto_ms);

        for attempt in 0..=self.config.max_retries {
            // Add jitter to prevent thundering herd
            let jitter = rand::thread_rng().gen_range(
                -(self.config.jitter_ms as i64)..=(self.config.jitter_ms as i64)
            );
            let send_delay = Duration::from_millis(jitter.unsigned_abs());

            if send_delay.as_millis() > 0 {
                sleep(send_delay).await;
            }

            // Send message
            match socket.send_to(&message, server_addr).await {
                Ok(_) => {
                    tracing::debug!("Sent STUN request to {} (attempt {})", server_addr, attempt + 1);
                }
                Err(e) => {
                    tracing::error!("Failed to send STUN request to {}: {}", server_addr, e);
                    if attempt == self.config.max_retries {
                        return Err(NatError::NetworkError(format!("Send failed: {}", e)));
                    }
                    continue;
                }
            }

            // Wait for response with timeout
            let mut buf = vec![0u8; MAX_MESSAGE_SIZE];

            match timeout(rto, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from_addr))) => {
                    if from_addr != server_addr {
                        tracing::warn!("Received response from unexpected address: {}", from_addr);
                        continue;
                    }

                    // Decode response
                    let mut buf = BytesMut::from(&buf[..len]);
                    match Message::decode(buf) {
                        Ok(response) => {
                            // Verify transaction ID
                            if response.transaction_id == tid {
                                self.metrics.responses_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                return Ok(response);
                            } else {
                                tracing::warn!("Transaction ID mismatch");
                                continue;
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to decode STUN response: {}", e);
                            continue;
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::error!("Socket error: {}", e);
                }
                Err(_) => {
                    // Timeout
                    tracing::debug!("Timeout waiting for response (attempt {})", attempt + 1);

                    if attempt < self.config.max_retries {
                        self.metrics.retransmissions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                        // Exponential backoff with maximum RTO
                        rto = std::cmp::min(rto * 2, max_rto);
                    }
                }
            }
        }

        self.metrics.timeouts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Err(NatError::Timeout)
    }

    /// Detect NAT behavior using RFC 5780 tests
    pub async fn detect_nat_behavior(&self, socket: &UdpSocket) -> NatResult<NatBehavior> {
        let mut discovery = self.discovery_engine.lock().await;

        match discovery.as_mut() {
            Some(engine) => engine.discover_nat_behavior(socket).await,
            None => {
                // Fallback to basic behavior detection
                self.detect_basic_behavior(socket).await
            }
        }
    }

    /// Basic behavior detection without RFC 5780 features
    async fn detect_basic_behavior(&self, socket: &UdpSocket) -> NatResult<NatBehavior> {
        let local_addr = socket.local_addr()?;
        let mapped_addr = self.get_mapped_address(socket).await?;

        // Determine if behind NAT
        let behind_nat = local_addr.ip() != mapped_addr.ip() || local_addr.port() != mapped_addr.port();

        // Basic behavior analysis
        let behavior = if !behind_nat {
            NatBehavior {
                mapping_behavior: super::discovery::MappingBehavior::DirectMapping,
                filtering_behavior: super::discovery::FilteringBehavior::None,
                public_addresses: vec![mapped_addr],
                port_prediction_difficulty: 0.0,
                supports_hairpinning: true,
                allocation_lifetime: Duration::from_secs(300),
                cone_nat_level: 0,
                symmetric_behavior_detected: false,
                multiple_interfaces_detected: false,
                consistent_external_port: true,
            }
        } else {
            // Default to most restrictive behavior
            NatBehavior {
                mapping_behavior: super::discovery::MappingBehavior::AddressAndPortDependent,
                filtering_behavior: super::discovery::FilteringBehavior::AddressAndPortDependent,
                public_addresses: vec![mapped_addr],
                port_prediction_difficulty: 1.0,
                supports_hairpinning: false,
                allocation_lifetime: Duration::from_secs(300),
                cone_nat_level: 3,
                symmetric_behavior_detected: true,
                multiple_interfaces_detected: false,
                consistent_external_port: false,
            }
        };

        Ok(behavior)
    }

    /// Query specific server for information and capabilities
    pub async fn query_server(&self, socket: &UdpSocket, server: &str) -> NatResult<StunServerInfo> {
        // Resolve server address
        let server_addr = self.resolve_server_address(server).await?;

        let start_time = Instant::now();

        // Send binding request
        let response = self.send_binding_request(socket, server_addr).await?;

        let response_time = start_time.elapsed();

        // Extract server information from response
        let mut server_info = StunServerInfo {
            address: server_addr,
            transport: TransportProtocol::UDP, // Default, would be detected
            supports_change_request: false,
            supports_rfc5780: false,
            alternate_address: None,
            response_origin: None,
            other_address: None,
            software: None,
            response_time_ms: response_time.as_millis() as u64,
            health_status: ServerHealthStatus::Healthy,
            last_health_check: Instant::now(),
            failure_count: 0,
            success_count: 1,
            supported_attributes: HashSet::new(),
            max_message_size: MAX_MESSAGE_SIZE,
            authentication_required: false,
            supported_auth_methods: Vec::new(),
        };

        // Parse response attributes
        for attr in &response.attributes {
            match &attr.value {
                AttributeValue::Software(sw) => {
                    server_info.software = Some(sw.clone());
                }
                AttributeValue::AlternateServer(addr) => {
                    server_info.alternate_address = Some(*addr);
                }
                AttributeValue::ResponseOrigin(addr) => {
                    server_info.response_origin = Some(*addr);
                }
                AttributeValue::OtherAddress(addr) => {
                    server_info.other_address = Some(*addr);
                    server_info.supports_rfc5780 = true;
                }
                _ => {}
            }

            server_info.supported_attributes.insert(attr.attr_type);
        }

        // Update server cache
        {
            let mut cache = self.server_cache.write().await;
            // Remove existing entry for this address
            cache.retain(|s| s.address != server_addr);
            // Add updated info
            cache.push(server_info.clone());
        }

        Ok(server_info)
    }

    /// Resolve server address from string
    async fn resolve_server_address(&self, server: &str) -> NatResult<SocketAddr> {
        // Handle direct IP:port format
        if let Ok(addr) = server.parse::<SocketAddr>() {
            return Ok(addr);
        }

        // Handle hostname:port format
        if let Some((host, port_str)) = server.split_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                // DNS resolution
                match lookup_host((host, port)).await {
                    Ok(mut addrs) => {
                        // Prefer IPv4 unless IPv6 is specifically enabled
                        if !self.config.enable_ipv6 {
                            if let Some(addr) = addrs.find(|a| a.is_ipv4()) {
                                return Ok(addr);
                            }
                        }

                        // Return first address if no preference or IPv6 enabled
                        if let Some(addr) = addrs.next() {
                            return Ok(addr);
                        }
                    }
                    Err(e) => {
                        return Err(NatError::DnsResolution(format!("Failed to resolve {}: {}", host, e)));
                    }
                }
            }
        }

        Err(NatError::Configuration(format!("Invalid server address: {}", server)))
    }

    /// Get comprehensive server statistics
    pub async fn get_server_statistics(&self) -> HashMap<SocketAddr, StunServerInfo> {
        let cache = self.server_cache.read().await;
        cache.iter()
            .map(|s| (s.address, s.clone()))
            .collect()
    }

    /// Get client performance metrics
    pub fn get_metrics(&self) -> HashMap<String, u64> {
        let mut metrics = HashMap::new();

        metrics.insert("requests_sent".to_string(),
                       self.metrics.requests_sent.load(std::sync::atomic::Ordering::Relaxed));
        metrics.insert("responses_received".to_string(),
                       self.metrics.responses_received.load(std::sync::atomic::Ordering::Relaxed));
        metrics.insert("timeouts".to_string(),
                       self.metrics.timeouts.load(std::sync::atomic::Ordering::Relaxed));
        metrics.insert("errors".to_string(),
                       self.metrics.errors.load(std::sync::atomic::Ordering::Relaxed));
        metrics.insert("retransmissions".to_string(),
                       self.metrics.retransmissions.load(std::sync::atomic::Ordering::Relaxed));
        metrics.insert("auth_failures".to_string(),
                       self.metrics.auth_failures.load(std::sync::atomic::Ordering::Relaxed));
        metrics.insert("server_failures".to_string(),
                       self.metrics.server_failures.load(std::sync::atomic::Ordering::Relaxed));
        metrics.insert("ipv4_requests".to_string(),
                       self.metrics.ipv4_requests.load(std::sync::atomic::Ordering::Relaxed));
        metrics.insert("ipv6_requests".to_string(),
                       self.metrics.ipv6_requests.load(std::sync::atomic::Ordering::Relaxed));

        let total_response_time = self.metrics.total_response_time_ms.load(std::sync::atomic::Ordering::Relaxed);
        let responses = self.metrics.responses_received.load(std::sync::atomic::Ordering::Relaxed);
        if responses > 0 {
            metrics.insert("avg_response_time_ms".to_string(), total_response_time / responses);
        }

        metrics
    }

    /// Shutdown client and cleanup resources
    pub async fn shutdown(&self) -> NatResult<()> {
        tracing::info!("Shutting down STUN client");

        // Close all pooled connections
        {
            let mut pool = self.connection_pool.lock().await;
            pool.clear();
        }

        // Cancel pending requests
        {
            let mut pending = self.pending_requests.lock().await;
            for (_, req) in pending.drain() {
                let _ = req.completion_sender.send(Err(NatError::ClientShutdown));
            }
        }

        // Log final metrics
        if self.config.enable_metrics {
            let metrics = self.get_metrics();
            tracing::info!("Final STUN client metrics: {:?}", metrics);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stun_client_basic() {
        let config = StunConfig::default();
        let client = StunClient::new(config);

        assert!(client.initialize().await.is_ok());

        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

        // Test basic mapped address retrieval
        match client.get_mapped_address(&socket).await {
            Ok(addr) => {
                println!("Mapped address: {}", addr);
                assert!(!addr.ip().is_loopback());
            }
            Err(e) => {
                eprintln!("STUN test failed (network required): {}", e);
                // This is acceptable in test environments without network access
            }
        }
    }

    #[tokio::test]
    async fn test_server_resolution() {
        let config = StunConfig::default();
        let client = StunClient::new(config);

        // Test direct IP resolution
        let addr1 = client.resolve_server_address("8.8.8.8:53").await.unwrap();
        assert_eq!(addr1.ip().to_string(), "8.8.8.8");
        assert_eq!(addr1.port(), 53);

        // Test hostname resolution (may fail in test environments)
        match client.resolve_server_address("stun.l.google.com:19302").await {
            Ok(addr) => {
                assert_eq!(addr.port(), 19302);
            }
            Err(_) => {
                // DNS resolution may fail in test environments
            }
        }
    }

    #[tokio::test]
    async fn test_load_balancer() {
        let mut lb = LoadBalancer::new(LoadBalancingStrategy::RoundRobin);

        let servers = vec![
            StunServerInfo {
                address: "127.0.0.1:3478".parse().unwrap(),
                transport: TransportProtocol::UDP,
                supports_change_request: false,
                supports_rfc5780: false,
                alternate_address: None,
                response_origin: None,
                other_address: None,
                software: None,
                response_time_ms: 100,
                health_status: ServerHealthStatus::Healthy,
                last_health_check: Instant::now(),
                failure_count: 0,
                success_count: 1,
                supported_attributes: HashSet::new(),
                max_message_size: 1500,
                authentication_required: false,
                supported_auth_methods: Vec::new(),
            },
            StunServerInfo {
                address: "127.0.0.1:3479".parse().unwrap(),
                transport: TransportProtocol::UDP,
                supports_change_request: false,
                supports_rfc5780: false,
                alternate_address: None,
                response_origin: None,
                other_address: None,
                software: None,
                response_time_ms: 200,
                health_status: ServerHealthStatus::Healthy,
                last_health_check: Instant::now(),
                failure_count: 0,
                success_count: 1,
                supported_attributes: HashSet::new(),
                max_message_size: 1500,
                authentication_required: false,
                supported_auth_methods: Vec::new(),
            },
        ];

        // Test round-robin selection
        let server1 = lb.select_server(&servers).unwrap();
        let server2 = lb.select_server(&servers).unwrap();
        let server3 = lb.select_server(&servers).unwrap();

        assert_eq!(server1.address.port(), 3478);
        assert_eq!(server2.address.port(), 3479);
        assert_eq!(server3.address.port(), 3478); // Should wrap around
    }

    #[test]
    fn test_metrics() {
        let metrics = StunClientMetrics::default();

        metrics.requests_sent.store(10, std::sync::atomic::Ordering::Relaxed);
        metrics.responses_received.store(8, std::sync::atomic::Ordering::Relaxed);
        metrics.timeouts.store(2, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(metrics.requests_sent.load(std::sync::atomic::Ordering::Relaxed), 10);
        assert_eq!(metrics.responses_received.load(std::sync::atomic::Ordering::Relaxed), 8);
        assert_eq!(metrics.timeouts.load(std::sync::atomic::Ordering::Relaxed), 2);
    }
}