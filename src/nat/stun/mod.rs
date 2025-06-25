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