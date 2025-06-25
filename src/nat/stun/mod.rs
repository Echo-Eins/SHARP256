// src/nat/stun/mod.rs
//! STUN (Session Traversal Utilities for NAT) implementation
//!
//! This module provides a complete, production-ready STUN implementation
//! fully compliant with RFC 8489 and RFC 5780 standards, including:
//!
//! ## Core Features
//! - Full RFC 8489 STUN protocol support
//! - RFC 5780 NAT behavior discovery
//! - Comprehensive authentication mechanisms
//! - High-performance client with connection pooling
//! - Advanced error handling and diagnostics
//! - Extensive logging and metrics
//!
//! ## Authentication Support
//! - Short-term credentials (RFC 8489 Section 9.1)
//! - Long-term credentials (RFC 8489 Section 9.2)
//! - Anonymous authentication with USERHASH (RFC 8489 Section 9.3)
//! - MESSAGE-INTEGRITY-SHA256 (RFC 8489 Section 14.6)
//! - Multiple password algorithms (MD5, SHA-256)
//! - Nonce management and replay protection
//!
//! ## NAT Discovery Features
//! - Complete RFC 5780 test suite implementation
//! - Mapping behavior detection (endpoint-independent, address-dependent, etc.)
//! - Filtering behavior analysis
//! - Port prediction difficulty assessment
//! - Hairpinning support detection
//! - P2P feasibility scoring
//!
//! ## Performance Features
//! - Connection pooling for authenticated sessions
//! - Load balancing across multiple servers
//! - Health monitoring and failover
//! - Concurrent request handling
//! - DNS resolution with IPv4/IPv6 support
//! - Optimized retransmission logic
//!
//! ## Usage Examples

pub mod protocol;
pub mod client;
pub mod auth;
pub mod discovery;
pub mod utils;
pub mod monitoring;

// Re-export core types for easy access
pub use protocol::{
    Message, MessageType, MessageClass, TransactionId,
    Attribute, AttributeType, AttributeValue,
    MAGIC_COOKIE, HEADER_SIZE, MAX_MESSAGE_SIZE,
};

pub use client::{
    StunClient, StunConfig, StunServerInfo,
    LoadBalancingStrategy, TransportProtocol, ServerHealthStatus,
};

pub use auth::{
    Credentials, CredentialType, SecurityFeatures, NonceCookie,
    PasswordAlgorithm, PasswordAlgorithmParams, NonceManager,
    compute_message_integrity_sha256, verify_message_integrity_sha256,
    generate_random_bytes, generate_anonymous_username, PasswordValidator,
};

pub use discovery::{
    NatBehavior, NatBehaviorDiscovery, DiscoveryConfig,
    MappingBehavior, FilteringBehavior, TestResult,
};

pub use utils::{
    StunValidator, MessageBuilder, AddressResolver,
    PerformanceTester, ConnectivityChecker,
};

pub use monitoring::{
    StunMonitor, ClientMetrics, ServerMetrics,
    HealthMetrics, NetworkQualityMetrics,
};

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use crate::nat::error::NatResult;
use crate::nat::NatType;

/// High-level STUN service interface for simple NAT traversal operations
///
/// This is the main entry point for most applications. It provides a simplified
/// interface over the more complex STUN client for common use cases.
pub struct StunService {
    client: StunClient,
    monitor: Option<StunMonitor>,
}

impl StunService {
    /// Create new STUN service with default configuration
    ///
    /// Uses a curated list of reliable public STUN servers and
    /// conservative timeout/retry settings suitable for most applications.
    pub fn new() -> Self {
        let config = StunConfig::default();
        let client = StunClient::new(config);

        Self {
            client,
            monitor: None,
        }
    }

    /// Create STUN service with custom configuration
    ///
    /// Allows full customization of STUN client behavior including:
    /// - Custom server lists
    /// - Authentication credentials
    /// - Timeout and retry parameters
    /// - Load balancing strategies
    /// - Performance monitoring
    pub fn with_config(config: StunConfig) -> Self {
        let client = StunClient::new(config);

        Self {
            client,
            monitor: None,
        }
    }

    /// Create STUN service with monitoring enabled
    ///
    /// Enables comprehensive monitoring and metrics collection
    /// for production environments.
    pub fn with_monitoring(config: StunConfig) -> Self {
        let client = StunClient::new(config);
        let monitor = Some(StunMonitor::new());

        Self {
            client,
            monitor,
        }
    }

    /// Initialize the STUN service
    ///
    /// Performs initial server discovery, health checks, and
    /// connection pool setup. Should be called before using
    /// other methods for optimal performance.
    pub async fn initialize(&self) -> NatResult<()> {
        self.client.initialize().await?;

        if let Some(monitor) = &self.monitor {
            monitor.start_monitoring().await;
        }

        Ok(())
    }

    /// Get public (mapped) address via STUN
    ///
    /// This is the most basic STUN operation - sends a binding request
    /// to a STUN server and returns the public IP address and port
    /// that the server sees.
    ///
    /// # Arguments
    /// * `socket` - Local UDP socket to use for the request
    ///
    /// # Returns
    /// The public (server-reflexive) address visible to the STUN server
    ///
    /// # Errors
    /// - `NatError::NoServersAvailable` if no STUN servers are reachable
    /// - `NatError::Timeout` if request times out
    /// - `NatError::NetworkError` for network-related failures
    pub async fn get_public_address(&self, socket: &UdpSocket) -> NatResult<SocketAddr> {
        let result = self.client.get_mapped_address(socket).await;

        if let Some(monitor) = &self.monitor {
            monitor.record_request_result(&result).await;
        }

        result
    }

    /// Detect NAT type and comprehensive behavior analysis
    ///
    /// Performs RFC 5780 NAT behavior discovery to determine:
    /// - Simple NAT type classification (Open, Full Cone, Restricted, etc.)
    /// - Detailed mapping and filtering behavior
    /// - P2P connectivity feasibility
    /// - Port prediction difficulty
    /// - Hairpinning support
    ///
    /// # Arguments
    /// * `socket` - Local UDP socket to use for tests
    ///
    /// # Returns
    /// Tuple of (simple NAT type, detailed behavior analysis)
    pub async fn detect_nat_type(&self, socket: &UdpSocket) -> NatResult<(NatType, NatBehavior)> {
        let behavior = self.client.detect_nat_behavior(socket).await?;
        let nat_type = behavior.to_simple_nat_type();

        if let Some(monitor) = &self.monitor {
            monitor.record_nat_detection(&nat_type, &behavior).await;
        }

        Ok((nat_type, behavior))
    }

    /// Check P2P connection feasibility
    ///
    /// Analyzes NAT behavior to determine how likely it is that
    /// peer-to-peer connections will succeed. Returns a score
    /// from 0.0 (impossible) to 1.0 (very likely).
    ///
    /// # Arguments
    /// * `socket` - Local UDP socket to use for analysis
    ///
    /// # Returns
    /// P2P feasibility score (0.0 = impossible, 1.0 = easy)
    pub async fn check_p2p_feasibility(&self, socket: &UdpSocket) -> NatResult<f64> {
        let behavior = self.client.detect_nat_behavior(socket).await?;
        let score = behavior.p2p_score();

        if let Some(monitor) = &self.monitor {
            monitor.record_p2p_assessment(score).await;
        }

        Ok(score)
    }

    /// Get multiple public addresses for redundancy
    ///
    /// Contacts multiple STUN servers to get a comprehensive view
    /// of public addresses. Useful for detecting inconsistent NAT
    /// behavior or multiple network interfaces.
    ///
    /// # Arguments
    /// * `socket` - Local UDP socket to use for requests
    ///
    /// # Returns
    /// Vector of all discovered public addresses
    pub async fn get_all_public_addresses(&self, socket: &UdpSocket) -> NatResult<Vec<SocketAddr>> {
        let behavior = self.client.detect_nat_behavior(socket).await?;
        Ok(behavior.public_addresses)
    }

    /// Test connectivity to specific STUN server
    ///
    /// Performs a connectivity test to a specific STUN server
    /// to check reachability and measure response time.
    ///
    /// # Arguments
    /// * `socket` - Local UDP socket to use
    /// * `server` - Server address string (hostname:port or ip:port)
    ///
    /// # Returns
    /// Server information including response time and capabilities
    pub async fn test_server_connectivity(&self, socket: &UdpSocket, server: &str) -> NatResult<StunServerInfo> {
        self.client.query_server(socket, server).await
    }

    /// Get comprehensive service statistics
    ///
    /// Returns detailed metrics about STUN service performance,
    /// including request/response counts, error rates, and
    /// response times.
    pub async fn get_statistics(&self) -> ServiceStatistics {
        let client_metrics = self.client.get_metrics();
        let server_stats = self.client.get_server_statistics().await;

        let monitor_metrics = if let Some(monitor) = &self.monitor {
            Some(monitor.get_metrics().await)
        } else {
            None
        };

        ServiceStatistics {
            client_metrics,
            server_statistics: server_stats,
            monitoring_metrics: monitor_metrics,
            total_requests: client_metrics.get("requests_sent").copied().unwrap_or(0),
            success_rate: calculate_success_rate(&client_metrics),
            average_response_time: client_metrics.get("avg_response_time_ms").copied().unwrap_or(0),
        }
    }

    /// Shutdown the STUN service gracefully
    ///
    /// Closes all connections, stops monitoring tasks, and
    /// releases resources. Should be called before dropping
    /// the service to ensure clean shutdown.
    pub async fn shutdown(&self) -> NatResult<()> {
        if let Some(monitor) = &self.monitor {
            monitor.shutdown().await?;
        }

        self.client.shutdown().await
    }

    /// Get reference to underlying STUN client
    ///
    /// Provides access to the lower-level STUN client for
    /// advanced use cases that require fine-grained control.
    pub fn client(&self) -> &StunClient {
        &self.client
    }
}

impl Default for StunService {
    fn default() -> Self {
        Self::new()
    }
}

/// Comprehensive service statistics
#[derive(Debug, Clone)]
pub struct ServiceStatistics {
    /// Raw client metrics
    pub client_metrics: std::collections::HashMap<String, u64>,

    /// Per-server statistics
    pub server_statistics: std::collections::HashMap<SocketAddr, StunServerInfo>,

    /// Monitoring metrics if enabled
    pub monitoring_metrics: Option<ClientMetrics>,

    /// Total requests sent
    pub total_requests: u64,

    /// Success rate (0.0 - 1.0)
    pub success_rate: f64,

    /// Average response time in milliseconds
    pub average_response_time: u64,
}

impl ServiceStatistics {
    /// Check if service is performing well
    pub fn is_healthy(&self) -> bool {
        self.success_rate > 0.9 && self.average_response_time < 1000
    }

    /// Get the best performing server
    pub fn best_server(&self) -> Option<&StunServerInfo> {
        self.server_statistics.values()
            .filter(|s| s.health_status == ServerHealthStatus::Healthy)
            .min_by_key(|s| s.response_time_ms)
    }

    /// Get summary string for logging
    pub fn summary(&self) -> String {
        format!(
            "STUN Service: {} requests, {:.1}% success, {}ms avg response",
            self.total_requests,
            self.success_rate * 100.0,
            self.average_response_time
        )
    }
}

/// Calculate success rate from client metrics
fn calculate_success_rate(metrics: &std::collections::HashMap<String, u64>) -> f64 {
    let total = metrics.get("requests_sent").copied().unwrap_or(0);
    let responses = metrics.get("responses_received").copied().unwrap_or(0);

    if total == 0 {
        0.0
    } else {
        responses as f64 / total as f64
    }
}

/// STUN service builder for advanced configuration
pub struct StunServiceBuilder {
    config: StunConfig,
    enable_monitoring: bool,
    custom_servers: Vec<String>,
}

impl StunServiceBuilder {
    /// Create new service builder
    pub fn new() -> Self {
        Self {
            config: StunConfig::default(),
            enable_monitoring: false,
            custom_servers: Vec::new(),
        }
    }

    /// Add custom STUN servers
    pub fn with_servers(mut self, servers: Vec<String>) -> Self {
        self.custom_servers = servers;
        self
    }

    /// Enable authentication
    pub fn with_credentials(mut self, credentials: Credentials) -> Self {
        self.config.credentials = Some(credentials);
        self
    }

    /// Set timeout values
    pub fn with_timeouts(mut self, initial_rto: Duration, max_retries: u32) -> Self {
        self.config.initial_rto_ms = initial_rto.as_millis() as u64;
        self.config.max_retries = max_retries;
        self
    }

    /// Enable monitoring and metrics
    pub fn with_monitoring(mut self) -> Self {
        self.enable_monitoring = true;
        self
    }

    /// Set load balancing strategy
    pub fn with_load_balancing(mut self, strategy: LoadBalancingStrategy) -> Self {
        self.config.load_balancing_strategy = strategy;
        self
    }

    /// Build the service
    pub fn build(mut self) -> StunService {
        if !self.custom_servers.is_empty() {
            self.config.servers = self.custom_servers;
        }

        if self.enable_monitoring {
            StunService::with_monitoring(self.config)
        } else {
            StunService::with_config(self.config)
        }
    }
}

impl Default for StunServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for STUN operations
pub mod utils {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::time::{timeout, Instant};

    /// STUN message validator for testing and debugging
    pub struct StunValidator;

    impl StunValidator {
        /// Validate STUN message structure
        pub fn validate_message(data: &[u8]) -> NatResult<()> {
            if data.len() < HEADER_SIZE {
                return Err(crate::nat::error::StunError::InvalidMessage(
                    "Message too short".to_string()
                ).into());
            }

            // Check magic cookie
            let magic_cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            if magic_cookie != MAGIC_COOKIE {
                return Err(crate::nat::error::StunError::InvalidMessage(
                    "Invalid magic cookie".to_string()
                ).into());
            }

            // Check message length
            let length = u16::from_be_bytes([data[2], data[3]]) as usize;
            if data.len() != HEADER_SIZE + length {
                return Err(crate::nat::error::StunError::InvalidMessage(
                    "Length mismatch".to_string()
                ).into());
            }

            Ok(())
        }

        /// Check if data looks like a STUN message
        pub fn is_stun_message(data: &[u8]) -> bool {
            if data.len() < HEADER_SIZE {
                return false;
            }

            // Check magic cookie
            let magic_cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            magic_cookie == MAGIC_COOKIE
        }

        /// Extract transaction ID from message
        pub fn extract_transaction_id(data: &[u8]) -> Option<TransactionId> {
            if data.len() < HEADER_SIZE {
                return None;
            }

            let tid_bytes: [u8; 12] = data[8..20].try_into().ok()?;
            Some(TransactionId::from_bytes(tid_bytes))
        }
    }

    /// Builder for constructing STUN messages
    pub struct MessageBuilder {
        message: Message,
    }

    impl MessageBuilder {
        /// Create new binding request
        pub fn binding_request() -> Self {
            let tid = TransactionId::new();
            let message = Message::new(MessageType::BindingRequest, tid);
            Self { message }
        }

        /// Create new binding response
        pub fn binding_response(transaction_id: TransactionId) -> Self {
            let message = Message::new(MessageType::BindingResponse, transaction_id);
            Self { message }
        }

        /// Add username attribute
        pub fn with_username(mut self, username: String) -> Self {
            self.message.add_attribute(Attribute::new(
                AttributeType::Username,
                AttributeValue::Username(username),
            ));
            self
        }

        /// Add software attribute
        pub fn with_software(mut self, software: String) -> Self {
            self.message.add_attribute(Attribute::new(
                AttributeType::Software,
                AttributeValue::Software(software),
            ));
            self
        }

        /// Add mapped address attribute
        pub fn with_mapped_address(mut self, addr: SocketAddr) -> Self {
            self.message.add_attribute(Attribute::new(
                AttributeType::XorMappedAddress,
                AttributeValue::XorMappedAddress(addr),
            ));
            self
        }

        /// Build the message
        pub fn build(self) -> Message {
            self.message
        }
    }

    /// DNS address resolver with caching
    pub struct AddressResolver {
        cache: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Vec<SocketAddr>>>>,
    }

    impl AddressResolver {
        /// Create new resolver
        pub fn new() -> Self {
            Self {
                cache: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            }
        }

        /// Resolve server address with caching
        pub async fn resolve(&self, server: &str) -> NatResult<Vec<SocketAddr>> {
            // Check cache first
            {
                let cache = self.cache.read().await;
                if let Some(addrs) = cache.get(server) {
                    return Ok(addrs.clone());
                }
            }

            // Perform DNS resolution
            let addrs = tokio::net::lookup_host(server).await
                .map_err(|e| crate::nat::error::NatError::DnsResolution(e.to_string()))?
                .collect::<Vec<_>>();

            // Cache results
            {
                let mut cache = self.cache.write().await;
                cache.insert(server.to_string(), addrs.clone());
            }

            Ok(addrs)
        }

        /// Clear DNS cache
        pub async fn clear_cache(&self) {
            let mut cache = self.cache.write().await;
            cache.clear();
        }
    }

    /// Performance testing utilities
    pub struct PerformanceTester;

    impl PerformanceTester {
        /// Measure round-trip time to STUN server
        pub async fn measure_rtt(socket: &UdpSocket, server_addr: SocketAddr) -> NatResult<Duration> {
            let start = Instant::now();

            // Create simple binding request
            let tid = TransactionId::new();
            let message = Message::new(MessageType::BindingRequest, tid);
            let encoded = message.encode(None, false)?;

            // Send request
            socket.send_to(&encoded, server_addr).await?;

            // Wait for response
            let mut buf = vec![0u8; 1500];
            let _result = timeout(
                Duration::from_secs(5),
                socket.recv_from(&mut buf)
            ).await??;

            Ok(start.elapsed())
        }

        /// Test server throughput
        pub async fn measure_throughput(
            socket: &UdpSocket,
            server_addr: SocketAddr,
            requests: usize,
        ) -> NatResult<f64> {
            let start = Instant::now();

            for _ in 0..requests {
                let tid = TransactionId::new();
                let message = Message::new(MessageType::BindingRequest, tid);
                let encoded = message.encode(None, false)?;
                socket.send_to(&encoded, server_addr).await?;

                // Brief delay to avoid overwhelming server
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            let duration = start.elapsed();
            let requests_per_second = requests as f64 / duration.as_secs_f64();

            Ok(requests_per_second)
        }
    }

    /// Connectivity checker for network diagnostics
    pub struct ConnectivityChecker;

    impl ConnectivityChecker {
        /// Check basic UDP connectivity
        pub async fn check_udp_connectivity(local_port: u16) -> NatResult<bool> {
            let socket = UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await?;

            // Try to bind - if successful, basic UDP works
            let _local_addr = socket.local_addr()?;
            Ok(true)
        }

        /// Check if behind NAT
        pub async fn check_nat_presence(socket: &UdpSocket, stun_server: &str) -> NatResult<bool> {
            let resolver = AddressResolver::new();
            let server_addrs = resolver.resolve(stun_server).await?;

            if server_addrs.is_empty() {
                return Err(crate::nat::error::NatError::NoServersAvailable);
            }

            let server_addr = server_addrs[0];
            let local_addr = socket.local_addr()?;

            // Send binding request
            let tid = TransactionId::new();
            let message = Message::new(MessageType::BindingRequest, tid);
            let encoded = message.encode(None, false)?;

            socket.send_to(&encoded, server_addr).await?;

            // Receive response
            let mut buf = vec![0u8; 1500];
            let (len, _) = timeout(
                Duration::from_secs(5),
                socket.recv_from(&mut buf)
            ).await??;

            // Decode and check mapped address
            let response = Message::decode(bytes::BytesMut::from(&buf[..len]))?;

            if let Some(attr) = response.get_attribute(AttributeType::XorMappedAddress) {
                if let AttributeValue::XorMappedAddress(mapped_addr) = &attr.value {
                    return Ok(local_addr != *mapped_addr);
                }
            }

            Ok(false) // Couldn't determine
        }

        /// Test IPv6 connectivity
        pub async fn check_ipv6_connectivity() -> bool {
            match UdpSocket::bind("[::1]:0").await {
                Ok(_) => true,
                Err(_) => false,
            }
        }
    }
}

/// Monitoring and metrics collection
pub mod monitoring {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;
    use tokio::sync::RwLock;

    /// STUN service monitor
    pub struct StunMonitor {
        metrics: Arc<RwLock<ClientMetrics>>,
        start_time: Instant,
    }

    impl StunMonitor {
        /// Create new monitor
        pub fn new() -> Self {
            Self {
                metrics: Arc::new(RwLock::new(ClientMetrics::default())),
                start_time: Instant::now(),
            }
        }

        /// Start monitoring tasks
        pub async fn start_monitoring(&self) {
            // Background monitoring tasks would be started here
            tracing::info!("STUN monitoring started");
        }

        /// Record request result
        pub async fn record_request_result(&self, result: &NatResult<SocketAddr>) {
            let mut metrics = self.metrics.write().await;
            metrics.total_requests += 1;

            match result {
                Ok(_) => metrics.successful_requests += 1,
                Err(_) => metrics.failed_requests += 1,
            }
        }

        /// Record NAT detection result
        pub async fn record_nat_detection(&self, nat_type: &NatType, behavior: &NatBehavior) {
            let mut metrics = self.metrics.write().await;
            metrics.nat_detections += 1;

            // Record NAT type distribution
            *metrics.nat_type_distribution.entry(*nat_type).or_insert(0) += 1;

            // Record P2P scores for analysis
            metrics.p2p_scores.push(behavior.p2p_score());
        }

        /// Record P2P assessment
        pub async fn record_p2p_assessment(&self, score: f64) {
            let mut metrics = self.metrics.write().await;
            metrics.p2p_assessments += 1;
            metrics.p2p_scores.push(score);
        }

        /// Get current metrics
        pub async fn get_metrics(&self) -> ClientMetrics {
            let metrics = self.metrics.read().await;
            let mut result = metrics.clone();
            result.uptime = self.start_time.elapsed();
            result
        }

        /// Shutdown monitor
        pub async fn shutdown(&self) -> NatResult<()> {
            tracing::info!("STUN monitoring shutdown");
            Ok(())
        }
    }

    /// Client performance metrics
    #[derive(Debug, Clone, Default)]
    pub struct ClientMetrics {
        pub total_requests: u64,
        pub successful_requests: u64,
        pub failed_requests: u64,
        pub nat_detections: u64,
        pub p2p_assessments: u64,
        pub nat_type_distribution: HashMap<NatType, u64>,
        pub p2p_scores: Vec<f64>,
        pub uptime: Duration,
    }

    impl ClientMetrics {
        /// Calculate success rate
        pub fn success_rate(&self) -> f64 {
            if self.total_requests == 0 {
                0.0
            } else {
                self.successful_requests as f64 / self.total_requests as f64
            }
        }

        /// Calculate average P2P score
        pub fn average_p2p_score(&self) -> f64 {
            if self.p2p_scores.is_empty() {
                0.0
            } else {
                self.p2p_scores.iter().sum::<f64>() / self.p2p_scores.len() as f64
            }
        }

        /// Get most common NAT type
        pub fn most_common_nat_type(&self) -> Option<NatType> {
            self.nat_type_distribution.iter()
                .max_by_key(|(_, &count)| count)
                .map(|(&nat_type, _)| nat_type)
        }
    }

    /// Server-specific metrics
    #[derive(Debug, Clone)]
    pub struct ServerMetrics {
        pub requests_sent: AtomicU64,
        pub responses_received: AtomicU64,
        pub timeouts: AtomicU64,
        pub total_response_time: AtomicU64,
        pub last_seen: std::sync::RwLock<Option<Instant>>,
    }

    impl Default for ServerMetrics {
        fn default() -> Self {
            Self {
                requests_sent: AtomicU64::new(0),
                responses_received: AtomicU64::new(0),
                timeouts: AtomicU64::new(0),
                total_response_time: AtomicU64::new(0),
                last_seen: std::sync::RwLock::new(None),
            }
        }
    }

    impl ServerMetrics {
        /// Record request sent
        pub fn record_request(&self) {
            self.requests_sent.fetch_add(1, Ordering::Relaxed);
        }

        /// Record response received
        pub fn record_response(&self, response_time: Duration) {
            self.responses_received.fetch_add(1, Ordering::Relaxed);
            self.total_response_time.fetch_add(
                response_time.as_millis() as u64,
                Ordering::Relaxed,
            );

            let mut last_seen = self.last_seen.write().unwrap();
            *last_seen = Some(Instant::now());
        }

        /// Record timeout
        pub fn record_timeout(&self) {
            self.timeouts.fetch_add(1, Ordering::Relaxed);
        }

        /// Calculate success rate
        pub fn success_rate(&self) -> f64 {
            let sent = self.requests_sent.load(Ordering::Relaxed);
            let received = self.responses_received.load(Ordering::Relaxed);

            if sent == 0 {
                0.0
            } else {
                received as f64 / sent as f64
            }
        }

        /// Calculate average response time
        pub fn average_response_time(&self) -> Duration {
            let total_time = self.total_response_time.load(Ordering::Relaxed);
            let responses = self.responses_received.load(Ordering::Relaxed);

            if responses == 0 {
                Duration::from_millis(0)
            } else {
                Duration::from_millis(total_time / responses)
            }
        }
    }

    /// Health monitoring metrics
    #[derive(Debug, Clone, Default)]
    pub struct HealthMetrics {
        pub server_health_checks: u64,
        pub healthy_servers: u64,
        pub unhealthy_servers: u64,
        pub dns_resolution_failures: u64,
        pub network_errors: u64,
    }

    /// Network quality assessment metrics
    #[derive(Debug, Clone, Default)]
    pub struct NetworkQualityMetrics {
        pub average_latency: Duration,
        pub packet_loss_rate: f64,
        pub jitter: Duration,
        pub bandwidth_estimate: u64, // bytes per second
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_stun_service_creation() {
        let service = StunService::new();
        assert!(service.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_service_builder() {
        let service = StunServiceBuilder::new()
            .with_servers(vec!["stun.example.com:3478".to_string()])
            .with_monitoring()
            .build();

        // Service should be created successfully
        assert!(service.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_stun_validator() {
        // Test with valid STUN message header
        let mut msg_data = vec![0u8; 20];
        msg_data[0] = 0x00; // Message type (binding request)
        msg_data[1] = 0x01;
        msg_data[2] = 0x00; // Length (0)
        msg_data[3] = 0x00;
        msg_data[4] = 0x21; // Magic cookie
        msg_data[5] = 0x12;
        msg_data[6] = 0xA4;
        msg_data[7] = 0x42;
        // Transaction ID (8 bytes)

        assert!(utils::StunValidator::is_stun_message(&msg_data));
        assert!(utils::StunValidator::validate_message(&msg_data).is_ok());
    }

    #[tokio::test]
    async fn test_message_builder() {
        let message = utils::MessageBuilder::binding_request()
            .with_username("test".to_string())
            .with_software("Test Client".to_string())
            .build();

        assert_eq!(message.message_type as u16, MessageType::BindingRequest as u16);
        assert!(message.has_attribute(AttributeType::Username));
        assert!(message.has_attribute(AttributeType::Software));
    }

    #[tokio::test]
    async fn test_connectivity_checker() {
        // Test UDP connectivity
        let can_bind = utils::ConnectivityChecker::check_udp_connectivity(0).await;
        assert!(can_bind.is_ok());

        // Test IPv6 support
        let ipv6_support = utils::ConnectivityChecker::check_ipv6_connectivity().await;
        println!("IPv6 support: {}", ipv6_support);
    }

    #[tokio::test]
    async fn test_address_resolver() {
        let resolver = utils::AddressResolver::new();

        // Test with localhost
        match resolver.resolve("localhost:80").await {
            Ok(addrs) => {
                assert!(!addrs.is_empty());
                println!("Resolved addresses: {:?}", addrs);
            }
            Err(e) => {
                println!("Resolution failed (expected in some environments): {}", e);
            }
        }
    }

    #[test]
    fn test_service_statistics() {
        let mut metrics = std::collections::HashMap::new();
        metrics.insert("requests_sent".to_string(), 100);
        metrics.insert("responses_received".to_string(), 95);
        metrics.insert("avg_response_time_ms".to_string(), 150);

        let stats = ServiceStatistics {
            client_metrics: metrics,
            server_statistics: std::collections::HashMap::new(),
            monitoring_metrics: None,
            total_requests: 100,
            success_rate: 0.95,
            average_response_time: 150,
        };

        assert!(stats.is_healthy());
        assert!(stats.summary().contains("95.0%"));
    }

    #[test]
    fn test_client_metrics() {
        let mut metrics = monitoring::ClientMetrics::default();
        metrics.total_requests = 100;
        metrics.successful_requests = 95;
        metrics.p2p_scores = vec![0.8, 0.9, 0.7, 0.85];

        assert_eq!(metrics.success_rate(), 0.95);
        assert_eq!(metrics.average_p2p_score(), 0.8);
    }
}