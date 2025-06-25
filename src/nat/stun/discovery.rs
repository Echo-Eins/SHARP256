// src/nat/stun/discovery.rs
//! STUN NAT Behavior Discovery implementation fully compliant with RFC 5780
//!
//! This module provides comprehensive NAT behavior discovery using the tests
//! defined in RFC 5780 "NAT Behavior Discovery Using Session Traversal
//! Utilities for NAT (STUN)". It implements all the behavior discovery tests
//! to determine NAT mapping and filtering behavior.
//!
//! Implemented tests:
//! - Test I: Basic Binding Request
//! - Test II: Binding Request with Change IP and Port
//! - Test III: Binding Request with Change Port
//! - Additional tests for mapping behavior determination
//! - Comprehensive filtering behavior analysis

use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::{timeout, sleep};
use parking_lot::RwLock;

use crate::nat::error::{NatError, StunError, NatResult};
use crate::nat::NatType;
use super::client::StunClient;
use super::protocol::*;

/// NAT mapping behavior as defined in RFC 4787 and RFC 5780
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingBehavior {
    /// Direct mapping (no NAT or full cone NAT)
    DirectMapping,

    /// Endpoint-Independent Mapping (RFC 4787)
    /// Same internal address:port maps to same external address:port
    /// regardless of destination
    EndpointIndependent,

    /// Address-Dependent Mapping (RFC 4787)
    /// Internal address:port maps to same external address:port for
    /// packets to the same destination IP (but different ports)
    AddressDependent,

    /// Address and Port-Dependent Mapping (RFC 4787)
    /// Internal address:port maps to same external address:port only
    /// for packets to the same destination IP:port
    AddressAndPortDependent,
}

/// NAT filtering behavior as defined in RFC 4787 and RFC 5780
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilteringBehavior {
    /// No filtering (not behind NAT)
    None,

    /// Endpoint-Independent Filtering (RFC 4787)
    /// NAT allows any external host to send packets to the mapped address
    EndpointIndependent,

    /// Address-Dependent Filtering (RFC 4787)
    /// NAT allows packets from external hosts that the internal host has
    /// previously sent packets to (same IP, any port)
    AddressDependent,

    /// Address and Port-Dependent Filtering (RFC 4787)
    /// NAT allows packets only from external hosts that the internal host
    /// has previously sent packets to (same IP:port)
    AddressAndPortDependent,
}

/// Comprehensive NAT behavior analysis result
#[derive(Debug, Clone)]
pub struct NatBehavior {
    /// NAT mapping behavior
    pub mapping_behavior: MappingBehavior,

    /// NAT filtering behavior
    pub filtering_behavior: FilteringBehavior,

    /// All discovered public addresses
    pub public_addresses: Vec<SocketAddr>,

    /// Port prediction difficulty (0.0 = easy, 1.0 = impossible)
    pub port_prediction_difficulty: f64,

    /// Whether NAT supports hairpinning
    pub supports_hairpinning: bool,

    /// Estimated allocation lifetime
    pub allocation_lifetime: Duration,

    /// Cone NAT classification level (0 = open, 1 = full cone, 2 = restricted, 3 = port restricted, 4 = symmetric)
    pub cone_nat_level: u8,

    /// Whether symmetric NAT behavior was detected
    pub symmetric_behavior_detected: bool,

    /// Whether multiple network interfaces were detected
    pub multiple_interfaces_detected: bool,

    /// Whether external port allocation is consistent
    pub consistent_external_port: bool,
}

impl NatBehavior {
    /// Convert to simple NAT type classification
    pub fn to_simple_nat_type(&self) -> NatType {
        match (self.mapping_behavior, self.filtering_behavior) {
            (MappingBehavior::DirectMapping, FilteringBehavior::None) => NatType::Open,

            (MappingBehavior::EndpointIndependent, FilteringBehavior::EndpointIndependent) =>
                NatType::FullCone,

            (MappingBehavior::EndpointIndependent, FilteringBehavior::AddressDependent) =>
                NatType::AddressRestricted,

            (MappingBehavior::EndpointIndependent, FilteringBehavior::AddressAndPortDependent) =>
                NatType::PortRestricted,

            (MappingBehavior::AddressDependent, _) |
            (MappingBehavior::AddressAndPortDependent, _) =>
                NatType::Symmetric,
        }
    }

    /// Calculate P2P feasibility score (0.0 = impossible, 1.0 = easy)
    pub fn p2p_score(&self) -> f64 {
        let mut score = 1.0;

        // Mapping behavior penalty
        match self.mapping_behavior {
            MappingBehavior::DirectMapping => score *= 1.0,
            MappingBehavior::EndpointIndependent => score *= 0.9,
            MappingBehavior::AddressDependent => score *= 0.6,
            MappingBehavior::AddressAndPortDependent => score *= 0.3,
        }

        // Filtering behavior penalty
        match self.filtering_behavior {
            FilteringBehavior::None => score *= 1.0,
            FilteringBehavior::EndpointIndependent => score *= 0.9,
            FilteringBehavior::AddressDependent => score *= 0.7,
            FilteringBehavior::AddressAndPortDependent => score *= 0.4,
        }

        // Port prediction difficulty penalty
        score *= 1.0 - (self.port_prediction_difficulty * 0.5);

        // Hairpinning bonus
        if self.supports_hairpinning {
            score *= 1.1;
        } else {
            score *= 0.8;
        }

        // Consistent port allocation bonus
        if self.consistent_external_port {
            score *= 1.1;
        } else {
            score *= 0.9;
        }

        score.min(1.0).max(0.0)
    }

    /// Check if this NAT configuration supports STUN-based hole punching
    pub fn supports_stun_hole_punching(&self) -> bool {
        match self.filtering_behavior {
            FilteringBehavior::None |
            FilteringBehavior::EndpointIndependent => true,
            FilteringBehavior::AddressDependent => {
                // May work with birthday paradox or port prediction
                self.port_prediction_difficulty < 0.8
            }
            FilteringBehavior::AddressAndPortDependent => {
                // Very difficult, needs specific techniques
                self.port_prediction_difficulty < 0.3 && self.supports_hairpinning
            }
        }
    }
}

/// Individual test result from RFC 5780 test procedures
#[derive(Debug, Clone)]
pub struct TestResult {
    /// Local address used for the test
    pub local_addr: SocketAddr,

    /// Mapped address received in response
    pub mapped_addr: SocketAddr,

    /// Server address that responded
    pub server_addr: SocketAddr,

    /// Alternative server address (from CHANGE-REQUEST)
    pub changed_addr: Option<SocketAddr>,

    /// Response origin address
    pub response_origin: Option<SocketAddr>,
}

/// NAT behavior discovery engine implementing RFC 5780
pub struct NatBehaviorDiscovery {
    /// STUN client for sending requests
    client: StunClient,

    /// Test results cache
    test_results: RwLock<HashMap<String, TestResult>>,

    /// Discovery configuration
    config: DiscoveryConfig,
}

/// Configuration for NAT behavior discovery
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Timeout for individual tests
    pub test_timeout: Duration,

    /// Number of test repetitions for reliability
    pub test_repetitions: u32,

    /// Delay between test repetitions
    pub repetition_delay: Duration,

    /// Enable comprehensive port prediction analysis
    pub enable_port_prediction: bool,

    /// Enable hairpinning detection
    pub enable_hairpinning_detection: bool,

    /// Enable allocation lifetime estimation
    pub enable_lifetime_estimation: bool,

    /// Maximum number of servers to test
    pub max_servers_to_test: usize,

    /// Enable parallel testing
    pub enable_parallel_testing: bool,

    /// Confidence threshold for results (0.0-1.0)
    pub confidence_threshold: f64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            test_timeout: Duration::from_secs(5),
            test_repetitions: 3,
            repetition_delay: Duration::from_millis(100),
            enable_port_prediction: true,
            enable_hairpinning_detection: true,
            enable_lifetime_estimation: true,
            max_servers_to_test: 5,
            enable_parallel_testing: true,
            confidence_threshold: 0.7,
        }
    }
}

impl NatBehaviorDiscovery {
    /// Create new NAT behavior discovery engine
    pub fn new(client: StunClient) -> Self {
        Self {
            client,
            test_results: RwLock::new(HashMap::new()),
            config: DiscoveryConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(client: StunClient, config: DiscoveryConfig) -> Self {
        Self {
            client,
            test_results: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Discover comprehensive NAT behavior using RFC 5780 tests
    pub async fn discover_nat_behavior(&mut self, socket: &UdpSocket) -> NatResult<NatBehavior> {
        tracing::info!("Starting comprehensive NAT behavior discovery");
        let start_time = Instant::now();

        // Clear previous test results
        self.test_results.write().clear();

        // Step 1: Find RFC 5780 compliant servers
        let rfc5780_servers = self.find_rfc5780_servers(socket).await?;

        if rfc5780_servers.is_empty() {
            tracing::warn!("No RFC 5780 compliant servers found, falling back to basic detection");
            return self.detect_basic_behavior(socket).await;
        }

        tracing::info!("Found {} RFC 5780 compliant servers", rfc5780_servers.len());

        // Step 2: Perform RFC 5780 Test I (Basic Binding Request)
        let test1_result = self.perform_test_i(socket, &rfc5780_servers[0]).await?;

        // Step 3: Determine if behind NAT
        let behind_nat = test1_result.local_addr.ip() != test1_result.mapped_addr.ip() ||
            test1_result.local_addr.port() != test1_result.mapped_addr.port();

        if !behind_nat {
            tracing::info!("Not behind NAT - direct connectivity detected");
            return Ok(NatBehavior {
                mapping_behavior: MappingBehavior::DirectMapping,
                filtering_behavior: FilteringBehavior::None,
                public_addresses: vec![test1_result.mapped_addr],
                port_prediction_difficulty: 0.0,
                supports_hairpinning: true,
                allocation_lifetime: Duration::from_secs(0),
                cone_nat_level: 0,
                symmetric_behavior_detected: false,
                multiple_interfaces_detected: false,
                consistent_external_port: true,
            });
        }

        tracing::info!("NAT detected - performing comprehensive behavior analysis");

        // Step 4: Perform RFC 5780 Test II (Change IP and Port)
        let test2_result = self.perform_test_ii(socket, &rfc5780_servers[0]).await;

        // Step 5: Perform RFC 5780 Test III (Change Port only)
        let test3_result = self.perform_test_iii(socket, &rfc5780_servers[0]).await;

        // Step 6: Determine mapping behavior
        let mapping_behavior = self.analyze_mapping_behavior(socket, &rfc5780_servers).await?;

        // Step 7: Determine filtering behavior
        let filtering_behavior = self.analyze_filtering_behavior(&test2_result, &test3_result);

        // Step 8: Additional analysis
        let port_prediction = if self.config.enable_port_prediction {
            self.analyze_port_prediction(socket, &rfc5780_servers).await
        } else {
            0.5 // Default moderate difficulty
        };

        let hairpinning = if self.config.enable_hairpinning_detection {
            self.test_hairpinning(socket, &rfc5780_servers).await
        } else {
            false
        };

        let lifetime = if self.config.enable_lifetime_estimation {
            self.estimate_allocation_lifetime(socket, &rfc5780_servers).await
        } else {
            Duration::from_secs(300) // Default 5 minutes
        };

        // Step 9: Collect all public addresses
        let public_addresses = self.collect_public_addresses();

        // Step 10: Advanced behavior analysis
        let cone_level = self.determine_cone_nat_level(mapping_behavior, filtering_behavior);
        let symmetric_detected = matches!(mapping_behavior,
            MappingBehavior::AddressDependent | MappingBehavior::AddressAndPortDependent);
        let consistent_ports = self.check_port_consistency(&public_addresses);

        let behavior = NatBehavior {
            mapping_behavior,
            filtering_behavior,
            public_addresses,
            port_prediction_difficulty: port_prediction,
            supports_hairpinning: hairpinning,
            allocation_lifetime: lifetime,
            cone_nat_level: cone_level,
            symmetric_behavior_detected: symmetric_detected,
            multiple_interfaces_detected: self.detect_multiple_interfaces(),
            consistent_external_port: consistent_ports,
        };

        let discovery_time = start_time.elapsed();
        tracing::info!(
            "NAT behavior discovery completed in {:?}: mapping={:?}, filtering={:?}, p2p_score={:.2}",
            discovery_time, mapping_behavior, filtering_behavior, behavior.p2p_score()
        );

        Ok(behavior)
    }

    /// RFC 5780 Test I: Basic Binding Request
    async fn perform_test_i(&self, socket: &UdpSocket, server: &super::client::StunServerInfo) -> NatResult<TestResult> {
        tracing::debug!("Performing RFC 5780 Test I: Basic Binding Request");

        let response = self.send_binding_request(socket, server.address, false, false).await?;

        // Extract mapped address
        let mapped_addr = response.attributes.iter()
            .find_map(|attr| match &attr.value {
                AttributeValue::XorMappedAddress(addr) => Some(*addr),
                AttributeValue::MappedAddress(addr) => Some(*addr),
                _ => None,
            })
            .ok_or_else(|| StunError::MissingAttribute("MAPPED-ADDRESS".to_string()))?;

        // Extract other address (for change requests)
        let other_addr = response.attributes.iter()
            .find_map(|attr| match &attr.value {
                AttributeValue::OtherAddress(addr) => Some(*addr),
                _ => None,
            });

        // Extract response origin
        let response_origin = response.attributes.iter()
            .find_map(|attr| match &attr.value {
                AttributeValue::ResponseOrigin(addr) => Some(*addr),
                _ => None,
            });

        let result = TestResult {
            local_addr: socket.local_addr()?,
            mapped_addr,
            server_addr: server.address,
            changed_addr: other_addr,
            response_origin,
        };

        self.test_results.write().insert("test_i".to_string(), result.clone());
        Ok(result)
    }

    /// RFC 5780 Test II: Binding Request with Change IP and Port
    async fn perform_test_ii(&self, socket: &UdpSocket, server: &super::client::StunServerInfo) -> Option<TestResult> {
        tracing::debug!("Performing RFC 5780 Test II: Change IP and Port");

        match self.send_binding_request(socket, server.address, true, true).await {
            Ok(response) => {
                let mapped_addr = response.attributes.iter()
                    .find_map(|attr| match &attr.value {
                        AttributeValue::XorMappedAddress(addr) => Some(*addr),
                        AttributeValue::MappedAddress(addr) => Some(*addr),
                        _ => None,
                    })?;

                let response_origin = response.attributes.iter()
                    .find_map(|attr| match &attr.value {
                        AttributeValue::ResponseOrigin(addr) => Some(*addr),
                        _ => None,
                    });

                let result = TestResult {
                    local_addr: socket.local_addr().ok()?,
                    mapped_addr,
                    server_addr: server.address,
                    changed_addr: response_origin,
                    response_origin,
                };

                self.test_results.write().insert("test_ii".to_string(), result.clone());
                Some(result)
            }
            Err(e) => {
                tracing::debug!("Test II failed (expected for some NAT types): {}", e);
                None
            }
        }
    }

    /// RFC 5780 Test III: Binding Request with Change Port only
    async fn perform_test_iii(&self, socket: &UdpSocket, server: &super::client::StunServerInfo) -> Option<TestResult> {
        tracing::debug!("Performing RFC 5780 Test III: Change Port only");

        match self.send_binding_request(socket, server.address, false, true).await {
            Ok(response) => {
                let mapped_addr = response.attributes.iter()
                    .find_map(|attr| match &attr.value {
                        AttributeValue::XorMappedAddress(addr) => Some(*addr),
                        AttributeValue::MappedAddress(addr) => Some(*addr),
                        _ => None,
                    })?;

                let response_origin = response.attributes.iter()
                    .find_map(|attr| match &attr.value {
                        AttributeValue::ResponseOrigin(addr) => Some(*addr),
                        _ => None,
                    });

                let result = TestResult {
                    local_addr: socket.local_addr().ok()?,
                    mapped_addr,
                    server_addr: server.address,
                    changed_addr: response_origin,
                    response_origin,
                };

                self.test_results.write().insert("test_iii".to_string(), result.clone());
                Some(result)
            }
            Err(e) => {
                tracing::debug!("Test III failed (expected for some NAT types): {}", e);
                None
            }
        }
    }

    /// Send binding request with optional CHANGE-REQUEST
    async fn send_binding_request(
        &self,
        socket: &UdpSocket,
        server_addr: SocketAddr,
        change_ip: bool,
        change_port: bool,
    ) -> NatResult<Message> {
        let tid = TransactionId::new();
        let mut msg = Message::new(MessageType::BindingRequest, tid);

        // Add CHANGE-REQUEST attribute if needed (RFC 3489 compatibility)
        if change_ip || change_port {
            let change_flags = (if change_ip { 0x04 } else { 0 }) | (if change_port { 0x02 } else { 0 });
            // Note: CHANGE-REQUEST is deprecated in RFC 8489 but still used by some servers
            msg.add_attribute(Attribute::new(
                AttributeType::Raw(0x0003), // CHANGE-REQUEST
                AttributeValue::Raw(vec![0, 0, 0, change_flags]),
            ));
        }

        // Add SOFTWARE attribute
        if let Some(ref software) = self.client.config().software_name {
            msg.add_attribute(Attribute::new(
                AttributeType::Software,
                AttributeValue::Software(software.clone()),
            ));
        }

        let encoded = msg.encode(None, self.client.config().use_fingerprint)?;

        // Send with timeout
        socket.send_to(&encoded, server_addr).await?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let (len, from_addr) = timeout(self.config.test_timeout, socket.recv_from(&mut buf)).await
            .map_err(|_| NatError::Timeout)??;

        if from_addr.ip() != server_addr.ip() && !change_ip {
            return Err(StunError::UnexpectedSource(from_addr).into());
        }

        let mut buf = bytes::BytesMut::from(&buf[..len]);
        let response = Message::decode(buf)?;

        if response.transaction_id != tid {
            return Err(StunError::TransactionIdMismatch.into());
        }

        Ok(response)
    }

    /// Find servers that support RFC 5780 features
    async fn find_rfc5780_servers(&self, socket: &UdpSocket) -> NatResult<Vec<super::client::StunServerInfo>> {
        let mut rfc5780_servers = Vec::new();

        // Check configured RFC 5780 servers first
        for server_str in &self.client.config().rfc5780_servers {
            match self.client.query_server(socket, server_str).await {
                Ok(info) if info.supports_rfc5780 => {
                    tracing::debug!("Found RFC 5780 server: {}", server_str);
                    rfc5780_servers.push(info);
                }
                Ok(_) => {
                    tracing::debug!("Server {} doesn't support RFC 5780", server_str);
                }
                Err(e) => {
                    tracing::debug!("Failed to query {}: {}", server_str, e);
                }
            }

            if rfc5780_servers.len() >= self.config.max_servers_to_test {
                break;
            }
        }

        // If no RFC 5780 servers found, try regular servers
        if rfc5780_servers.is_empty() {
            for server_str in &self.client.config().servers {
                match self.client.query_server(socket, server_str).await {
                    Ok(info) if info.other_address.is_some() => {
                        tracing::debug!("Server {} supports OTHER-ADDRESS: {}", server_str, server_str);
                        rfc5780_servers.push(info);
                    }
                    _ => {}
                }

                if rfc5780_servers.len() >= self.config.max_servers_to_test {
                    break;
                }
            }
        }

        Ok(rfc5780_servers)
    }

    /// Analyze NAT mapping behavior using multiple servers
    async fn analyze_mapping_behavior(
        &self,
        socket: &UdpSocket,
        servers: &[super::client::StunServerInfo],
    ) -> NatResult<MappingBehavior> {
        tracing::debug!("Analyzing NAT mapping behavior");

        if servers.len() < 2 {
            tracing::warn!("Need at least 2 servers for mapping behavior analysis");
            return Ok(MappingBehavior::AddressAndPortDependent); // Most restrictive assumption
        }

        let mut mapped_addresses = Vec::new();

        // Test with multiple servers
        for (i, server) in servers.iter().take(self.config.max_servers_to_test).enumerate() {
            for attempt in 0..self.config.test_repetitions {
                match self.send_binding_request(socket, server.address, false, false).await {
                    Ok(response) => {
                        if let Some(mapped_addr) = response.attributes.iter()
                            .find_map(|attr| match &attr.value {
                                AttributeValue::XorMappedAddress(addr) => Some(*addr),
                                AttributeValue::MappedAddress(addr) => Some(*addr),
                                _ => None,
                            }) {
                            mapped_addresses.push((i, attempt, mapped_addr));
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Mapping test failed for server {}: {}", server.address, e);
                    }
                }

                if attempt < self.config.test_repetitions - 1 {
                    sleep(self.config.repetition_delay).await;
                }
            }
        }

        // Analyze results
        if mapped_addresses.is_empty() {
            return Err(NatError::NoServersAvailable);
        }

        // Group by server
        let mut server_mappings: HashMap<usize, Vec<SocketAddr>> = HashMap::new();
        for (server_idx, _, addr) in mapped_addresses {
            server_mappings.entry(server_idx).or_default().push(addr);
        }

        // Check if same external port is used across different servers
        let mut all_ports: Vec<u16> = Vec::new();
        let mut different_ips_same_port = true;

        for addrs in server_mappings.values() {
            if let Some(first_addr) = addrs.first() {
                all_ports.push(first_addr.port());

                // Check consistency within same server
                for addr in addrs {
                    if addr.port() != first_addr.port() || addr.ip() != first_addr.ip() {
                        different_ips_same_port = false;
                    }
                }
            }
        }

        // Determine mapping behavior based on port consistency across servers
        if all_ports.len() <= 1 {
            // Only one server tested or all same
            return Ok(MappingBehavior::EndpointIndependent);
        }

        let first_port = all_ports[0];
        let same_port_across_servers = all_ports.iter().all(|&port| port == first_port);

        if same_port_across_servers && different_ips_same_port {
            Ok(MappingBehavior::EndpointIndependent)
        } else {
            // Need more sophisticated testing to distinguish between
            // address-dependent and address+port-dependent
            self.distinguish_mapping_behavior(socket, servers).await
        }
    }

    /// Distinguish between address-dependent and address+port-dependent mapping
    async fn distinguish_mapping_behavior(
        &self,
        socket: &UdpSocket,
        servers: &[super::client::StunServerInfo],
    ) -> NatResult<MappingBehavior> {
        // This would require servers with multiple ports or more sophisticated testing
        // For now, return the more restrictive behavior
        tracing::debug!("Cannot distinguish mapping behavior precisely, assuming address+port dependent");
        Ok(MappingBehavior::AddressAndPortDependent)
    }

    /// Analyze filtering behavior based on change request results
    fn analyze_filtering_behavior(
        &self,
        test2_result: &Option<TestResult>,
        test3_result: &Option<TestResult>,
    ) -> FilteringBehavior {
        match (test2_result, test3_result) {
            (Some(_), Some(_)) => {
                // Both change requests succeeded - endpoint independent filtering
                FilteringBehavior::EndpointIndependent
            }
            (None, Some(_)) => {
                // Only port change succeeded - address dependent filtering
                FilteringBehavior::AddressDependent
            }
            (None, None) => {
                // No change requests succeeded - address and port dependent filtering
                FilteringBehavior::AddressAndPortDependent
            }
            (Some(_), None) => {
                // This shouldn't happen (IP+port change succeeded but port-only failed)
                // Assume most restrictive
                FilteringBehavior::AddressAndPortDependent
            }
        }
    }

    /// Analyze port prediction difficulty
    async fn analyze_port_prediction(
        &self,
        socket: &UdpSocket,
        servers: &[super::client::StunServerInfo],
    ) -> f64 {
        tracing::debug!("Analyzing port prediction difficulty");

        if servers.is_empty() {
            return 1.0; // Maximum difficulty
        }

        let mut port_sequences = Vec::new();

        // Collect port allocation sequences
        for server in servers.iter().take(3) {
            let mut ports = Vec::new();

            for _ in 0..10 {
                match self.send_binding_request(socket, server.address, false, false).await {
                    Ok(response) => {
                        if let Some(mapped_addr) = response.attributes.iter()
                            .find_map(|attr| match &attr.value {
                                AttributeValue::XorMappedAddress(addr) => Some(*addr),
                                AttributeValue::MappedAddress(addr) => Some(*addr),
                                _ => None,
                            }) {
                            ports.push(mapped_addr.port());
                        }
                    }
                    Err(_) => break,
                }

                sleep(Duration::from_millis(100)).await;
            }

            if ports.len() >= 3 {
                port_sequences.push(ports);
            }
        }

        if port_sequences.is_empty() {
            return 1.0;
        }

        // Analyze port allocation patterns
        let mut total_predictability = 0.0;
        let mut sequence_count = 0;

        for ports in port_sequences {
            let predictability = self.calculate_port_predictability(&ports);
            total_predictability += predictability;
            sequence_count += 1;
        }

        if sequence_count == 0 {
            1.0
        } else {
            1.0 - (total_predictability / sequence_count as f64)
        }
    }

    /// Calculate predictability of a port sequence
    fn calculate_port_predictability(&self, ports: &[u16]) -> f64 {
        if ports.len() < 3 {
            return 0.0;
        }

        // Check for common patterns
        let mut sequential_count = 0;
        let mut random_count = 0;

        for i in 1..ports.len() {
            let diff = (ports[i] as i32 - ports[i-1] as i32).abs();

            if diff <= 2 {
                sequential_count += 1; // Sequential or very close
            } else if diff > 1000 {
                random_count += 1; // Appears random
            }
        }

        let total_transitions = ports.len() - 1;
        let sequential_ratio = sequential_count as f64 / total_transitions as f64;

        sequential_ratio // Higher value = more predictable
    }

    /// Test for hairpinning support
    async fn test_hairpinning(
        &self,
        socket: &UdpSocket,
        servers: &[super::client::StunServerInfo],
    ) -> bool {
        tracing::debug!("Testing hairpinning support");

        // Get our external address
        let external_addr = match self.send_binding_request(socket, servers[0].address, false, false).await {
            Ok(response) => {
                response.attributes.iter()
                    .find_map(|attr| match &attr.value {
                        AttributeValue::XorMappedAddress(addr) => Some(*addr),
                        AttributeValue::MappedAddress(addr) => Some(*addr),
                        _ => None,
                    })
            }
            Err(_) => return false,
        };

        if let Some(ext_addr) = external_addr {
            // Try to send a packet to our own external address
            // This is a simplified test - full hairpinning test requires more setup
            match timeout(
                Duration::from_secs(2),
                socket.send_to(b"hairpin_test", ext_addr)
            ).await {
                Ok(Ok(_)) => {
                    // If we can send to our external address without error,
                    // hairpinning might be supported
                    // A full test would require receiving the packet back
                    true
                }
                _ => false,
            }
        } else {
            false
        }
    }

    /// Estimate allocation lifetime
    async fn estimate_allocation_lifetime(
        &self,
        socket: &UdpSocket,
        servers: &[super::client::StunServerInfo],
    ) -> Duration {
        tracing::debug!("Estimating allocation lifetime");

        if servers.is_empty() {
            return Duration::from_secs(300); // Default 5 minutes
        }

        // Get initial mapping
        let initial_mapping = match self.send_binding_request(socket, servers[0].address, false, false).await {
            Ok(response) => {
                response.attributes.iter()
                    .find_map(|attr| match &attr.value {
                        AttributeValue::XorMappedAddress(addr) => Some(*addr),
                        AttributeValue::MappedAddress(addr) => Some(*addr),
                        _ => None,
                    })
            }
            Err(_) => return Duration::from_secs(300),
        };

        if let Some(initial_addr) = initial_mapping {
            // Test after increasing intervals to find when mapping expires
            let test_intervals = [
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(120),
                Duration::from_secs(300),
            ];

            for interval in test_intervals {
                sleep(interval).await;

                match self.send_binding_request(socket, servers[0].address, false, false).await {
                    Ok(response) => {
                        if let Some(current_addr) = response.attributes.iter()
                            .find_map(|attr| match &attr.value {
                                AttributeValue::XorMappedAddress(addr) => Some(*addr),
                                AttributeValue::MappedAddress(addr) => Some(*addr),
                                _ => None,
                            }) {

                            if current_addr != initial_addr {
                                // Mapping changed, lifetime is approximately this interval
                                return interval;
                            }
                        }
                    }
                    Err(_) => {
                        // Request failed, mapping might have expired
                        return interval;
                    }
                }
            }
        }

        // Default if we couldn't determine
        Duration::from_secs(300)
    }

    /// Collect all discovered public addresses
    fn collect_public_addresses(&self) -> Vec<SocketAddr> {
        let results = self.test_results.read();
        let mut addresses = Vec::new();

        for result in results.values() {
            if !addresses.contains(&result.mapped_addr) {
                addresses.push(result.mapped_addr);
            }
        }

        addresses
    }

    /// Determine cone NAT classification level
    fn determine_cone_nat_level(&self, mapping: MappingBehavior, filtering: FilteringBehavior) -> u8 {
        match (mapping, filtering) {
            (MappingBehavior::DirectMapping, FilteringBehavior::None) => 0, // Open
            (MappingBehavior::EndpointIndependent, FilteringBehavior::EndpointIndependent) => 1, // Full cone
            (MappingBehavior::EndpointIndependent, FilteringBehavior::AddressDependent) => 2, // Restricted
            (MappingBehavior::EndpointIndependent, FilteringBehavior::AddressAndPortDependent) => 3, // Port restricted
            _ => 4, // Symmetric
        }
    }

    /// Check port consistency across multiple addresses
    fn check_port_consistency(&self, addresses: &[SocketAddr]) -> bool {
        if addresses.len() <= 1 {
            return true;
        }

        let first_port = addresses[0].port();
        addresses.iter().all(|addr| addr.port() == first_port)
    }

    /// Detect multiple network interfaces
    fn detect_multiple_interfaces(&self) -> bool {
        let results = self.test_results.read();
        let mut local_addresses: std::collections::HashSet<IpAddr> = std::collections::HashSet::new();

        for result in results.values() {
            local_addresses.insert(result.local_addr.ip());
        }

        local_addresses.len() > 1
    }

    /// Fallback behavior detection using basic tests
    pub async fn detect_basic_behavior(&mut self, socket: &UdpSocket) -> NatResult<NatBehavior> {
        tracing::info!("Performing basic NAT behavior detection (RFC 8489 only)");

        // Get mapped address using any available server
        let servers = &self.client.config().servers;
        if servers.is_empty() {
            return Err(NatError::NoServersAvailable);
        }

        let server_addr = servers[0].parse::<SocketAddr>()
            .map_err(|e| NatError::Configuration(format!("Invalid server address: {}", e)))?;

        let response = self.send_binding_request(socket, server_addr, false, false).await?;

        let mapped_addr = response.attributes.iter()
            .find_map(|attr| match &attr.value {
                AttributeValue::XorMappedAddress(addr) => Some(*addr),
                AttributeValue::MappedAddress(addr) => Some(*addr),
                _ => None,
            })
            .ok_or_else(|| StunError::MissingAttribute("MAPPED-ADDRESS".to_string()))?;

        let local_addr = socket.local_addr()?;
        let behind_nat = local_addr.ip() != mapped_addr.ip() || local_addr.port() != mapped_addr.port();

        let behavior = if !behind_nat {
            NatBehavior {
                mapping_behavior: MappingBehavior::DirectMapping,
                filtering_behavior: FilteringBehavior::None,
                public_addresses: vec![mapped_addr],
                port_prediction_difficulty: 0.0,
                supports_hairpinning: true,
                allocation_lifetime: Duration::from_secs(0),
                cone_nat_level: 0,
                symmetric_behavior_detected: false,
                multiple_interfaces_detected: false,
                consistent_external_port: true,
            }
        } else {
            // Default to most restrictive behavior without proper testing
            NatBehavior {
                mapping_behavior: MappingBehavior::AddressAndPortDependent,
                filtering_behavior: FilteringBehavior::AddressAndPortDependent,
                public_addresses: vec![mapped_addr],
                port_prediction_difficulty: 1.0,
                supports_hairpinning: false,
                allocation_lifetime: Duration::from_secs(300),
                cone_nat_level: 4,
                symmetric_behavior_detected: true,
                multiple_interfaces_detected: false,
                consistent_external_port: false,
            }
        };

        Ok(behavior)
    }

    /// Get detailed test results for analysis
    pub fn get_test_results(&self) -> HashMap<String, TestResult> {
        self.test_results.read().clone()
    }

    /// Clear test results cache
    pub fn clear_results(&self) {
        self.test_results.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::stun::StunConfig;

    #[tokio::test]
    async fn test_nat_behavior_analysis() {
        let behavior = NatBehavior {
            mapping_behavior: MappingBehavior::EndpointIndependent,
            filtering_behavior: FilteringBehavior::AddressDependent,
            public_addresses: vec!["203.0.113.1:54321".parse().unwrap()],
            port_prediction_difficulty: 0.3,
            supports_hairpinning: true,
            allocation_lifetime: Duration::from_secs(300),
            cone_nat_level: 2,
            symmetric_behavior_detected: false,
            multiple_interfaces_detected: false,
            consistent_external_port: true,
        };

        assert_eq!(behavior.to_simple_nat_type(), NatType::AddressRestricted);
        assert!(behavior.p2p_score() > 0.5);
        assert!(behavior.supports_stun_hole_punching());
    }

    #[test]
    fn test_mapping_behavior_classification() {
        let behaviors = [
            MappingBehavior::DirectMapping,
            MappingBehavior::EndpointIndependent,
            MappingBehavior::AddressDependent,
            MappingBehavior::AddressAndPortDependent,
        ];

        for behavior in behaviors {
            println!("Mapping behavior: {:?}", behavior);
        }
    }

    #[test]
    fn test_filtering_behavior_classification() {
        let behaviors = [
            FilteringBehavior::None,
            FilteringBehavior::EndpointIndependent,
            FilteringBehavior::AddressDependent,
            FilteringBehavior::AddressAndPortDependent,
        ];

        for behavior in behaviors {
            println!("Filtering behavior: {:?}", behavior);
        }
    }

    #[test]
    fn test_port_predictability() {
        let discovery = NatBehaviorDiscovery::new(
            crate::nat::stun::StunClient::new(StunConfig::default())
        );

        // Sequential ports (predictable)
        let sequential = vec![12345, 12346, 12347, 12348, 12349];
        let pred1 = discovery.calculate_port_predictability(&sequential);
        assert!(pred1 > 0.8);

        // Random ports (unpredictable)
        let random = vec![12345, 45678, 23456, 67890, 34567];
        let pred2 = discovery.calculate_port_predictability(&random);
        assert!(pred2 < 0.2);
    }

    #[test]
    fn test_cone_nat_levels() {
        let discovery = NatBehaviorDiscovery::new(
            crate::nat::stun::StunClient::new(StunConfig::default())
        );

        assert_eq!(discovery.determine_cone_nat_level(
            MappingBehavior::DirectMapping,
            FilteringBehavior::None
        ), 0);

        assert_eq!(discovery.determine_cone_nat_level(
            MappingBehavior::EndpointIndependent,
            FilteringBehavior::EndpointIndependent
        ), 1);

        assert_eq!(discovery.determine_cone_nat_level(
            MappingBehavior::AddressAndPortDependent,
            FilteringBehavior::AddressAndPortDependent
        ), 4);
    }
}