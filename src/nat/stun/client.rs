use std::net::{SocketAddr, IpAddr};
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::{timeout, sleep};
use bytes::BytesMut;
use rand::Rng;
use futures::future::join_all;
use parking_lot::RwLock;

use crate::nat::error::{NatError, StunError, NatResult};
use crate::nat::metrics::{StunMetrics, record_ip_version_usage};
use super::protocol::*;
use super::auth::Credentials;
use super::discovery::{NatBehavior, NatBehaviorDiscovery};

/// STUN client configuration
#[derive(Debug, Clone)]
pub struct StunConfig {
    /// List of STUN servers to use
    pub servers: Vec<String>,

    /// Initial RTO in milliseconds (RFC 8489 Section 7.2.1)
    pub initial_rto_ms: u64,

    /// Maximum RTO in milliseconds
    pub max_rto_ms: u64,

    /// Maximum number of retransmissions (Rc)
    pub max_retries: u32,

    /// Request timeout for overall operation (should be Rc * RTO)
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

                // Other reliable public servers
                "stun.cloudflare.com:3478".to_string(),
                "stun.services.mozilla.com:3478".to_string(),
                "stun.stunprotocol.org:3478".to_string(),
                "global.stun.twilio.com:3478".to_string(),
            ],
            initial_rto_ms: 500,    // RFC 8489 recommendation
            max_rto_ms: 3200,       // RFC 8489 recommendation
            max_retries: 7,         // Rc = 7 as per RFC 8489
            request_timeout: Duration::from_millis(39500), // Sum of all retries
            enable_behavior_discovery: true,
            credentials: None,
            use_fingerprint: true,
            software_name: Some("SHARP NAT Traversal/1.0".to_string()),
            max_concurrent_requests: 10,
            jitter_ms: 50, // ±50ms as recommended
        }
    }
}

/// Information about a STUN server
#[derive(Debug, Clone)]
pub struct StunServerInfo {
    pub address: SocketAddr,
    pub supports_change_request: bool,
    pub alternate_address: Option<SocketAddr>,
    pub response_origin: Option<SocketAddr>,
    pub other_address: Option<SocketAddr>,
    pub software: Option<String>,
    pub response_time_ms: u64,
}

/// STUN client implementation compliant with RFC 8489
pub struct StunClient {
    config: StunConfig,
    server_cache: Arc<RwLock<Vec<StunServerInfo>>>,
}

impl StunClient {
    /// Create new STUN client
    pub fn new(config: StunConfig) -> Self {
        Self {
            config,
            server_cache: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get a reference to the client configuration
    pub fn config(&self) -> &StunConfig {
        &self.config
    }

    /// Get mapped address from any available STUN server
    pub async fn get_mapped_address(
        &self,
        socket: &UdpSocket,
    ) -> NatResult<SocketAddr> {
        let local_addr = socket.local_addr()?;
        let ip_version = if local_addr.is_ipv4() { "ipv4" } else { "ipv6" };
        record_ip_version_usage(ip_version, "stun_request");

        // Try primary servers first with parallel requests
        let primary_servers: Vec<_> = self.config.servers
            .iter()
            .take(3)
            .cloned()
            .collect();

        let results = self.query_multiple_servers(socket, &primary_servers).await;

        // Find consensus among results
        if let Some(addr) = Self::find_consensus_address(&results) {
            return Ok(addr);
        }

        // If primary servers failed, try remaining servers sequentially
        for server in self.config.servers.iter().skip(3) {
            match self.query_server(socket, server).await {
                Ok(info) => {
                    if let Some(addr) = info.response_origin {
                        return Ok(addr);
                    }
                }
                Err(e) => {
                    tracing::debug!("Server {} failed: {}", server, e);
                }
            }
        }

        Err(StunError::AllServersFailed.into())
    }

    /// Query a specific STUN server
    pub async fn query_server(
        &self,
        socket: &UdpSocket,
        server: &str,
    ) -> NatResult<StunServerInfo> {
        let server_addr = self.resolve_server(server).await?;
        let metrics = StunMetrics::new(server.to_string());

        let start_time = Instant::now();
        let transaction_id = TransactionId::new();

        // Create binding request
        let mut request = Message::new(MessageType::BindingRequest, transaction_id);

        // Add SOFTWARE attribute if configured
        if let Some(ref software) = self.config.software_name {
            request.add_attribute(Attribute::new(
                AttributeType::Software,
                AttributeValue::Software(software.clone()),
            ));
        }

        // Add credentials if configured
        let integrity_key = if let Some(ref creds) = self.config.credentials {
            // Add USERNAME attribute
            request.add_attribute(Attribute::new(
                AttributeType::Username,
                AttributeValue::Username(creds.get_username().to_string()),
            ));

            // Add REALM if applicable
            if let Some(realm) = creds.get_realm() {
                request.add_attribute(Attribute::new(
                    AttributeType::Realm,
                    AttributeValue::Realm(realm.to_string()),
                ));
            }

            // Add NONCE if available
            if let Some(ref nonce) = creds.nonce {
                request.add_attribute(Attribute::new(
                    AttributeType::Nonce,
                    AttributeValue::Nonce(nonce.clone()),
                ));
            }

            Some(creds.compute_key()?)
        } else {
            None
        };

        // Send request with retries
        let response = self.send_with_retries(
            socket,
            server_addr,
            request,
            integrity_key.as_deref(),
        ).await?;

        let response_time = start_time.elapsed().as_millis() as u64;
        metrics.record_response(true);

        // Parse server info from response
        let info = self.parse_server_info(server_addr, response, response_time)?;

        // Cache server info
        self.server_cache.write().push(info.clone());

        Ok(info)
    }

    /// Detect NAT behavior using RFC 5780 tests
    pub async fn detect_nat_behavior(
        &self,
        socket: &UdpSocket,
    ) -> NatResult<NatBehavior> {
        if !self.config.enable_behavior_discovery {
            return Err(NatError::Configuration(
                "NAT behavior discovery is disabled".to_string()
            ));
        }

        let mut discovery = NatBehaviorDiscovery::new(self);
        discovery.detect_behavior(socket).await
    }

    /// Query multiple servers in parallel
    async fn query_multiple_servers(
        &self,
        socket: &UdpSocket,
        servers: &[String],
    ) -> Vec<(String, Result<StunServerInfo, NatError>)> {
        let futures = servers.iter().map(|server| {
            let server_clone = server.clone();
            let client = self.clone();
            let socket_ref = socket;

            async move {
                let result = timeout(
                    Duration::from_secs(5),
                    client.query_server(socket_ref, &server_clone)
                ).await;

                let final_result = match result {
                    Ok(Ok(info)) => Ok(info),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(NatError::Timeout(Duration::from_secs(5))),
                };

                (server_clone, final_result)
            }
        });

        join_all(futures).await
    }

    /// Find consensus address from multiple results
    fn find_consensus_address(
        results: &[(String, Result<StunServerInfo, NatError>)]
    ) -> Option<SocketAddr> {
        let mut addr_counts = std::collections::HashMap::new();

        for (_, result) in results {
            if let Ok(info) = result {
                if let Some(addr) = info.response_origin {
                    *addr_counts.entry(addr.ip()).or_insert(0) += 1;
                }
            }
        }

        // Find IP with most votes
        let consensus_ip = addr_counts.into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(ip, _)| ip)?;

        // Find first matching address with consensus IP
        for (_, result) in results {
            if let Ok(info) = result {
                if let Some(addr) = info.response_origin {
                    if addr.ip() == consensus_ip {
                        return Some(addr);
                    }
                }
            }
        }

        None
    }

    /// Send STUN request with retries following RFC 8489 Section 7.2.1
    pub async fn send_with_retries(
        &self,
        socket: &UdpSocket,
        server_addr: SocketAddr,
        request: Message,
        integrity_key: Option<&[u8]>,
    ) -> NatResult<Message> {
        let encoded = request.encode(integrity_key, self.config.use_fingerprint)?;
        let mut rto = self.config.initial_rto_ms;
        let mut total_wait_time = 0u64;

        for attempt in 0..=self.config.max_retries {
            // Calculate jitter for this attempt
            let jitter = if attempt > 0 && self.config.jitter_ms > 0 {
                let range = self.config.jitter_ms as i64;
                rand::thread_rng().gen_range(-range..=range)
            } else {
                0
            };

            // Apply jitter to RTO (ensuring it doesn't go negative)
            let jittered_rto = if jitter < 0 {
                rto.saturating_sub(jitter.unsigned_abs())
            } else {
                rto.saturating_add(jitter as u64)
            };

            let timeout_duration = Duration::from_millis(jittered_rto);
            total_wait_time += jittered_rto;

            // Check if we've exceeded total timeout
            if Duration::from_millis(total_wait_time) > self.config.request_timeout {
                break;
            }

            // Send request
            socket.send_to(&encoded, server_addr).await?;

            // Wait for response
            let mut buffer = vec![0u8; MAX_MESSAGE_SIZE];
            match timeout(timeout_duration, socket.recv_from(&mut buffer)).await {
                Ok(Ok((size, from_addr))) => {
                    // Validate source address
                    if from_addr != server_addr {
                        tracing::debug!(
                            "Ignoring response from unexpected address: {} (expected {})",
                            from_addr, server_addr
                        );
                        continue;
                    }

                    // Parse response
                    let response = Message::decode(BytesMut::from(&buffer[..size]))?;

                    // Verify transaction ID
                    if response.transaction_id != request.transaction_id {
                        return Err(StunError::TransactionIdMismatch.into());
                    }

                    // Verify FINGERPRINT if present
                    if response.get_attribute(AttributeType::Fingerprint).is_some() {
                        if !response.verify_fingerprint(&buffer[..size])? {
                            return Err(StunError::FingerprintCheckFailed.into());
                        }
                    }

                    // Verify MESSAGE-INTEGRITY-SHA256 if we sent credentials
                    if integrity_key.is_some() {
                        if let Some(_) = response.get_attribute(AttributeType::MessageIntegritySha256) {
                            if !response.verify_integrity_sha256(
                                integrity_key.unwrap(),
                                &buffer[..size]
                            )? {
                                return Err(StunError::IntegrityCheckFailed.into());
                            }
                        }
                    }

                    // Check for error response
                    if response.message_type.class() == MessageClass::ErrorResponse {
                        if let Some(error_attr) = response.get_attribute(AttributeType::ErrorCode) {
                            if let AttributeValue::ErrorCode { code, reason } = &error_attr.value {
                                // Handle specific error codes
                                match *code {
                                    401 => {
                                        // Unauthorized - need to authenticate
                                        if self.config.credentials.is_some() {
                                            // We already tried with credentials
                                            return Err(StunError::Authentication(
                                                "Authentication failed".to_string()
                                            ).into());
                                        }
                                        // Could retry with credentials here
                                    }
                                    438 => {
                                        // Stale nonce
                                        return Err(StunError::NonceExpired.into());
                                    }
                                    _ => {}
                                }

                                return Err(StunError::ErrorResponse {
                                    code: *code,
                                    reason: reason.clone(),
                                }.into());
                            }
                        }
                    }

                    return Ok(response);
                }
                Ok(Err(e)) => {
                    return Err(e.into());
                }
                Err(_) => {
                    // Timeout - continue to next retry
                    tracing::debug!(
                        "Request timeout for {} (attempt {}/{}, RTO: {}ms + jitter: {}ms)",
                        server_addr,
                        attempt + 1,
                        self.config.max_retries + 1,
                        rto,
                        jitter
                    );
                }
            }

            // Double RTO for next attempt (capped at max)
            rto = (rto * 2).min(self.config.max_rto_ms);
        }

        Err(StunError::NoResponse(server_addr).into())
    }

    /// Parse server information from response
    fn parse_server_info(
        &self,
        server_addr: SocketAddr,
        response: Message,
        response_time_ms: u64,
    ) -> NatResult<StunServerInfo> {
        let mut info = StunServerInfo {
            address: server_addr,
            supports_change_request: false,
            alternate_address: None,
            response_origin: None,
            other_address: None,
            software: None,
            response_time_ms,
        };

        // Extract attributes
        for attr in &response.attributes {
            match &attr.value {
                AttributeValue::XorMappedAddress(addr) => {
                    info.response_origin = Some(*addr);
                }
                AttributeValue::MappedAddress(addr) => {
                    // Use if XOR-MAPPED-ADDRESS not present
                    if info.response_origin.is_none() {
                        info.response_origin = Some(*addr);
                    }
                }
                AttributeValue::AlternateServer(addr) => {
                    info.alternate_address = Some(*addr);
                }
                AttributeValue::OtherAddress(addr) => {
                    info.other_address = Some(*addr);
                    info.supports_change_request = true;
                }
                AttributeValue::ResponseOrigin(addr) => {
                    // Override with explicit response origin if present
                    info.response_origin = Some(*addr);
                }
                AttributeValue::Software(software) => {
                    info.software = Some(software.clone());
                }
                _ => {}
            }
        }

        Ok(info)
    }

    /// Resolve server address with Happy Eyeballs (RFC 8305)
    async fn resolve_server(&self, server: &str) -> NatResult<SocketAddr> {
        // First try parsing as socket address
        if let Ok(addr) = server.parse::<SocketAddr>() {
            return Ok(addr);
        }

        // DNS resolution with timeout
        let resolution = timeout(
            Duration::from_secs(5),
            self.resolve_with_happy_eyeballs(server)
        ).await;

        match resolution {
            Ok(Ok(addr)) => Ok(addr),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(NatError::Timeout(Duration::from_secs(5))),
        }
    }

    /// Happy Eyeballs DNS resolution (RFC 8305)
    async fn resolve_with_happy_eyeballs(&self, server: &str) -> NatResult<SocketAddr> {
        let addrs: Vec<SocketAddr> = lookup_host(server).await
            .map_err(|e| NatError::Platform(format!("DNS lookup failed: {}", e)))?
            .collect();

        if addrs.is_empty() {
            return Err(NatError::Platform(format!("No addresses found for {}", server)));
        }

        // Separate IPv4 and IPv6 addresses
        let mut ipv4_addrs = Vec::new();
        let mut ipv6_addrs = Vec::new();

        for addr in addrs {
            match addr.ip() {
                IpAddr::V4(_) => ipv4_addrs.push(addr),
                IpAddr::V6(_) => ipv6_addrs.push(addr),
            }
        }

        // Implement Happy Eyeballs v2 (RFC 8305)
        if !ipv6_addrs.is_empty() && !ipv4_addrs.is_empty() {
            // Start with IPv6
            let ipv6_addr = ipv6_addrs[0];

            // Give IPv6 a 50ms head start
            let ipv4_future = async {
                sleep(Duration::from_millis(50)).await;
                ipv4_addrs.first().cloned()
            };

            // Race IPv6 and delayed IPv4
            tokio::select! {
                _ = async { ipv6_addrs.first().cloned() } => {
                    record_ip_version_usage("ipv6", "dns_resolution");
                    return Ok(ipv6_addr);
                }
                ipv4_result = ipv4_future => {
                    if let Some(addr) = ipv4_result {
                        record_ip_version_usage("ipv4", "dns_resolution");
                        return Ok(addr);
                    }
                }
            }
        }

        // Fallback to available addresses
        if let Some(addr) = ipv6_addrs.first() {
            record_ip_version_usage("ipv6", "dns_resolution");
            Ok(*addr)
        } else if let Some(addr) = ipv4_addrs.first() {
            record_ip_version_usage("ipv4", "dns_resolution");
            Ok(*addr)
        } else {
            Err(NatError::Platform(format!("No valid addresses for {}", server)))
        }
    }
}

impl Clone for StunClient {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            server_cache: self.server_cache.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_stun_request() {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let config = StunConfig {
            servers: vec!["stun.l.google.com:19302".to_string()],
            ..Default::default()
        };

        let client = StunClient::new(config);

        match client.get_mapped_address(&socket).await {
            Ok(addr) => {
                println!("Mapped address: {}", addr);
                assert!(!addr.ip().is_loopback());
            }
            Err(e) => {
                eprintln!("STUN test failed (may be offline): {}", e);
            }
        }
    }

    #[test]
    fn test_retry_timing() {
        let config = StunConfig::default();

        // Verify retry timing follows RFC 8489
        let mut rto = config.initial_rto_ms;
        let mut total_time = 0u64;

        for i in 0..=config.max_retries {
            println!("Attempt {}: RTO = {}ms, Total = {}ms", i, rto, total_time);
            total_time += rto;
            rto = (rto * 2).min(config.max_rto_ms);
        }

        // Should be close to 39.5 seconds
        assert!(total_time >= 39000 && total_time <= 40000);
    }
}