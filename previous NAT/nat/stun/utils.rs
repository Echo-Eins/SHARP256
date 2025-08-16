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
                "Message too short".to_string(),
            ).into());
        }

        // Check magic cookie
        let magic_cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if magic_cookie != MAGIC_COOKIE {
            return Err(crate::nat::error::StunError::InvalidMessage(
                "Invalid magic cookie".to_string(),
            ).into());
        }

        // Check message length
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() != HEADER_SIZE + length {
            return Err(crate::nat::error::StunError::InvalidMessage(
                "Length mismatch".to_string(),
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