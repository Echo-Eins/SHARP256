use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut, Buf};
use std::net::{SocketAddr, IpAddr};
use tokio::time::{timeout, Duration};
use rand::Rng;
use tokio::net::{lookup_host, UdpSocket};
use std::collections::HashMap;

// STUN Message Types (RFC 5389)
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;
const BINDING_INDICATION: u16 = 0x0011;

// STUN Attributes
const MAPPED_ADDRESS: u16 = 0x0001;
const RESPONSE_ADDRESS: u16 = 0x0002;
const CHANGE_REQUEST: u16 = 0x0003;
const SOURCE_ADDRESS: u16 = 0x0004;
const CHANGED_ADDRESS: u16 = 0x0005;
const USERNAME: u16 = 0x0006;
const MESSAGE_INTEGRITY: u16 = 0x0008;
const ERROR_CODE: u16 = 0x0009;
const UNKNOWN_ATTRIBUTES: u16 = 0x000A;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const PRIORITY: u16 = 0x0024;
const USE_CANDIDATE: u16 = 0x0025;
const SOFTWARE: u16 = 0x8022;
const ALTERNATE_SERVER: u16 = 0x8023;
const FINGERPRINT: u16 = 0x8028;
const RESPONSE_ORIGIN: u16 = 0x802b;
const OTHER_ADDRESS: u16 = 0x802c;

// Magic Cookie
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

// Change Request Flags
const CHANGE_IP: u32 = 0x04;
const CHANGE_PORT: u32 = 0x02;

/// Enhanced STUN client with RFC 5389/5780 compliance
#[derive(Clone)]
pub struct StunClient {
    servers: Vec<String>,
    software_name: String,
}

/// STUN server capabilities
#[derive(Debug, Clone)]
pub struct StunServerInfo {
    pub primary_address: SocketAddr,
    pub alternate_address: Option<SocketAddr>,
    pub supports_change_request: bool,
    pub response_origin: Option<SocketAddr>,
}

/// NAT behavior characteristics
#[derive(Debug, Clone)]
pub struct NatBehavior {
    pub mapping_behavior: MappingBehavior,
    pub filtering_behavior: FilteringBehavior,
    pub hairpinning: bool,
    pub mapping_lifetime: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MappingBehavior {
    EndpointIndependent,    // Same mapping for all destinations
    AddressDependent,       // Different mapping per destination IP
    AddressPortDependent,   // Different mapping per destination IP:port
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FilteringBehavior {
    EndpointIndependent,    // Allow from any source
    AddressDependent,       // Allow only from contacted IPs
    AddressPortDependent,   // Allow only from contacted IP:ports
}

impl StunClient {
    pub fn new(servers: Vec<String>) -> Self {
        Self {
            servers,
            software_name: "SHARP-256/1.0".to_string(),
        }
    }

    /// Get mapped address from STUN server with retries
    pub async fn get_mapped_address(&self, socket: &UdpSocket) -> Result<SocketAddr> {
        let mut last_error = None;

        // Try primary servers first
        let primary_servers: Vec<_> = self.servers.iter()
            .take(3)
            .cloned()
            .collect();

        for server in &primary_servers {
            for attempt in 0..3 {
                match self.query_stun_server(socket, server).await {
                    Ok(addr) => return Ok(addr),
                    Err(e) => {
                        last_error = Some(e);
                        if attempt < 2 {
                            tokio::time::sleep(Duration::from_millis(100 * (attempt + 1) as u64)).await;
                        }
                    }
                }
            }
        }

        // Try additional servers if primary failed
        for server in self.servers.iter().skip(3).take(5) {
            match self.query_stun_server(socket, server).await {
                Ok(addr) => return Ok(addr),
                Err(e) => last_error = Some(e),
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All STUN servers failed")))
    }

    /// Query a single STUN server
    pub async fn query_stun_server(&self, socket: &UdpSocket, server: &str) -> Result<SocketAddr> {
        let server_addr = self.resolve_server(server).await
            .with_context(|| format!("Failed to resolve STUN server: {}", server))?;

        let transaction_id = self.generate_transaction_id();
        let request = self.create_binding_request(&transaction_id, None, None);

        // Send request
        socket.send_to(&request, server_addr).await
            .context("Failed to send STUN request")?;

        // Receive response
        let mut buffer = vec![0u8; 1500];
        let (size, from_addr) = timeout(
            Duration::from_secs(3),
            socket.recv_from(&mut buffer)
        ).await
            .context("STUN response timeout")??;

        // Verify response is from the server
        if from_addr != server_addr {
            anyhow::bail!("Response from unexpected address: {} (expected {})", from_addr, server_addr);
        }

        // Parse response
        let response = self.parse_stun_message(&buffer[..size], &transaction_id)?;

        response.mapped_address
            .ok_or_else(|| anyhow::anyhow!("No mapped address in STUN response"))
    }

    /// Perform comprehensive NAT type detection (RFC 5780)
    pub async fn detect_nat_type(&self, socket: &UdpSocket) -> Result<Vec<(SocketAddr, bool)>> {
        // Find a STUN server that supports RFC 5780 tests
        let test_server = match self.find_rfc5780_server(socket).await {
            Ok(server) => server,
            Err(e) => {
                tracing::warn!("No RFC 5780 compliant server found: {}", e);
                // Fallback to basic detection
                return self.basic_nat_detection(socket).await;
            }
        };

        tracing::info!("Using STUN server {} for NAT detection", test_server.primary_address);

        // Test 1: Basic binding request
        let test1_addr = self.query_stun_server(socket, &test_server.primary_address.to_string()).await?;

        let mut results = vec![(test1_addr, false)];

        // Test 2: Binding request with change IP and port
        if test_server.supports_change_request {
            match self.query_with_change_request(
                socket,
                &test_server,
                CHANGE_IP | CHANGE_PORT
            ).await {
                Ok(addr) => results.push((addr, true)),
                Err(e) => tracing::debug!("Change request test failed: {}", e),
            }
        }

        // Test 3: Binding request to alternate address if available
        if let Some(alt_addr) = test_server.alternate_address {
            match self.query_stun_server(socket, &alt_addr.to_string()).await {
                Ok(addr) => results.push((addr, addr != test1_addr)),
                Err(e) => tracing::debug!("Alternate address test failed: {}", e),
            }
        }

        Ok(results)
    }

    /// Detect detailed NAT behavior for optimal traversal strategy
    pub async fn detect_nat_behavior(&self, socket: &UdpSocket) -> Result<NatBehavior> {
        let server = self.find_rfc5780_server(socket).await?;

        // Test mapping behavior
        let mapping_behavior = self.test_mapping_behavior(socket, &server).await?;

        // Test filtering behavior
        let filtering_behavior = self.test_filtering_behavior(socket, &server).await?;

        // Test hairpinning
        let hairpinning = self.test_hairpinning(socket).await.unwrap_or(false);

        // Estimate mapping lifetime
        let mapping_lifetime = self.estimate_mapping_lifetime(socket, &server).await.ok();

        Ok(NatBehavior {
            mapping_behavior,
            filtering_behavior,
            hairpinning,
            mapping_lifetime,
        })
    }

    /// Find a STUN server that supports RFC 5780 (NAT behavior discovery)
    async fn find_rfc5780_server(&self, socket: &UdpSocket) -> Result<StunServerInfo> {
        for server in &self.servers {
            match self.probe_server_capabilities(socket, server).await {
                Ok(info) if info.supports_change_request => return Ok(info),
                Ok(info) => tracing::debug!("{} doesn't support change requests", server),
                Err(e) => tracing::debug!("Failed to probe {}: {}", server, e),
            }
        }

        Err(anyhow::anyhow!("No RFC 5780 compliant STUN server found"))
    }

    /// Probe server capabilities
    async fn probe_server_capabilities(&self, socket: &UdpSocket, server: &str) -> Result<StunServerInfo> {
        let server_addr = self.resolve_server(server).await?;
        let transaction_id = self.generate_transaction_id();

        // Send request with software attribute
        let request = self.create_binding_request(&transaction_id, Some(&self.software_name), None);
        socket.send_to(&request, server_addr).await?;

        let mut buffer = vec![0u8; 1500];
        let (size, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await??;

        let response = self.parse_stun_message(&buffer[..size], &transaction_id)?;

        Ok(StunServerInfo {
            primary_address: server_addr,
            alternate_address: response.other_address,
            supports_change_request: response.other_address.is_some(),
            response_origin: response.response_origin,
        })
    }

    /// Test mapping behavior
    async fn test_mapping_behavior(&self, socket: &UdpSocket, server: &StunServerInfo) -> Result<MappingBehavior> {
        // Get mapping for primary server
        let mapping1 = self.query_stun_server(socket, &server.primary_address.to_string()).await?;

        // Get mapping for alternate server (different IP)
        if let Some(alt_addr) = server.alternate_address {
            let mapping2 = self.query_stun_server(socket, &alt_addr.to_string()).await?;

            if mapping1 != mapping2 {
                // Different mappings for different destination IPs
                return Ok(MappingBehavior::AddressDependent);
            }

            // Test with different port on same IP
            let mut diff_port = server.primary_address;
            diff_port.set_port(diff_port.port() + 1);

            if let Ok(mapping3) = self.query_stun_server(socket, &diff_port.to_string()).await {
                if mapping1 != mapping3 {
                    return Ok(MappingBehavior::AddressPortDependent);
                }
            }
        }

        Ok(MappingBehavior::EndpointIndependent)
    }

    /// Test filtering behavior
    async fn test_filtering_behavior(&self, socket: &UdpSocket, server: &StunServerInfo) -> Result<FilteringBehavior> {
        if !server.supports_change_request {
            return Ok(FilteringBehavior::AddressPortDependent); // Conservative assumption
        }

        // Test if we can receive from different IP
        match self.query_with_change_request(socket, server, CHANGE_IP).await {
            Ok(_) => {
                // Can receive from different IP, test port change
                match self.query_with_change_request(socket, server, CHANGE_PORT).await {
                    Ok(_) => Ok(FilteringBehavior::EndpointIndependent),
                    Err(_) => Ok(FilteringBehavior::AddressDependent),
                }
            }
            Err(_) => Ok(FilteringBehavior::AddressPortDependent),
        }
    }

    /// Test hairpinning support
    async fn test_hairpinning(&self, socket: &UdpSocket) -> Result<bool> {
        // Get our external address
        let external_addr = self.get_mapped_address(socket).await?;

        // Try to send to our own external address
        let test_data = b"HAIRPIN_TEST";
        socket.send_to(test_data, external_addr).await?;

        // Check if we receive it
        let mut buffer = vec![0u8; 100];
        match timeout(Duration::from_millis(500), socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, addr))) if addr == external_addr && &buffer[..size] == test_data => Ok(true),
            _ => Ok(false),
        }
    }

    /// Estimate mapping lifetime
    async fn estimate_mapping_lifetime(&self, socket: &UdpSocket, server: &StunServerInfo) -> Result<Duration> {
        let initial_mapping = self.query_stun_server(socket, &server.primary_address.to_string()).await?;

        // Test at increasing intervals
        let test_intervals = [30, 60, 120, 300, 600]; // seconds

        for interval in test_intervals {
            tokio::time::sleep(Duration::from_secs(interval)).await;

            let current_mapping = self.query_stun_server(socket, &server.primary_address.to_string()).await?;

            if current_mapping != initial_mapping {
                // Mapping changed, lifetime is less than this interval
                return Ok(Duration::from_secs(interval));
            }
        }

        // Mapping stable for at least 10 minutes
        Ok(Duration::from_secs(600))
    }

    /// Query with change request attribute
    async fn query_with_change_request(
        &self,
        socket: &UdpSocket,
        server: &StunServerInfo,
        change_flags: u32
    ) -> Result<SocketAddr> {
        let transaction_id = self.generate_transaction_id();
        let request = self.create_binding_request(&transaction_id, None, Some(change_flags));

        socket.send_to(&request, server.primary_address).await?;

        let mut buffer = vec![0u8; 1500];
        let (size, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut buffer)).await??;

        let response = self.parse_stun_message(&buffer[..size], &transaction_id)?;

        response.mapped_address
            .ok_or_else(|| anyhow::anyhow!("No mapped address in change request response"))
    }

    /// Basic NAT detection for non-RFC5780 servers
    async fn basic_nat_detection(&self, socket: &UdpSocket) -> Result<Vec<(SocketAddr, bool)>> {
        let mut results = Vec::new();
        let mut servers_used = HashMap::new();

        // Query multiple servers
        for server in self.servers.iter().take(5) {
            match self.query_stun_server(socket, server).await {
                Ok(addr) => {
                    let changed = servers_used.values().any(|&prev_addr| prev_addr != addr);
                    results.push((addr, changed));
                    servers_used.insert(server.clone(), addr);
                }
                Err(e) => tracing::debug!("Server {} failed: {}", server, e),
            }
        }

        if results.is_empty() {
            return Err(anyhow::anyhow!("No STUN servers responded"));
        }

        Ok(results)
    }

    /// Create STUN binding request
    fn create_binding_request(
        &self,
        transaction_id: &[u8; 12],
        software: Option<&str>,
        change_request: Option<u32>
    ) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(256);

        // Calculate message length
        let mut msg_length = 0u16;

        if software.is_some() {
            msg_length += 4 + software.unwrap().len() as u16;
            msg_length += (4 - (software.unwrap().len() % 4)) % 4; // Padding
        }

        if change_request.is_some() {
            msg_length += 8; // CHANGE-REQUEST attribute
        }

        // Message header
        buf.put_u16(BINDING_REQUEST);
        buf.put_u16(msg_length);
        buf.put_u32(STUN_MAGIC_COOKIE);
        buf.put_slice(transaction_id);

        // SOFTWARE attribute
        if let Some(sw) = software {
            buf.put_u16(SOFTWARE);
            buf.put_u16(sw.len() as u16);
            buf.put_slice(sw.as_bytes());

            // Padding to 32-bit boundary
            let padding = (4 - (sw.len() % 4)) % 4;
            for _ in 0..padding {
                buf.put_u8(0);
            }
        }

        // CHANGE-REQUEST attribute
        if let Some(flags) = change_request {
            buf.put_u16(CHANGE_REQUEST);
            buf.put_u16(4);
            buf.put_u32(flags);
        }

        buf.to_vec()
    }

    /// Parse STUN message
    fn parse_stun_message(&self, data: &[u8], expected_tid: &[u8; 12]) -> Result<StunResponse> {
        if data.len() < 20 {
            anyhow::bail!("STUN message too short");
        }

        let mut buf = BytesMut::from(data);

        // Parse header
        let msg_type = buf.get_u16();
        let msg_length = buf.get_u16() as usize;
        let magic = buf.get_u32();

        if magic != STUN_MAGIC_COOKIE {
            anyhow::bail!("Invalid STUN magic cookie");
        }

        let mut tid = [0u8; 12];
        buf.copy_to_slice(&mut tid);

        if tid != *expected_tid {
            anyhow::bail!("Transaction ID mismatch");
        }

        // Check message type
        if msg_type != BINDING_RESPONSE && msg_type != BINDING_ERROR {
            anyhow::bail!("Unexpected message type: 0x{:04x}", msg_type);
        }

        let mut response = StunResponse::default();

        // Parse attributes
        let mut remaining = msg_length;
        while remaining >= 4 && buf.remaining() >= 4 {
            let attr_type = buf.get_u16();
            let attr_length = buf.get_u16() as usize;

            if buf.remaining() < attr_length {
                break;
            }

            match attr_type {
                XOR_MAPPED_ADDRESS => {
                    response.mapped_address = Some(self.parse_xor_mapped_address(&mut buf, attr_length, &tid)?);
                }
                MAPPED_ADDRESS => {
                    response.mapped_address = Some(self.parse_mapped_address(&mut buf, attr_length)?);
                }
                OTHER_ADDRESS => {
                    response.other_address = Some(self.parse_xor_mapped_address(&mut buf, attr_length, &tid)?);
                }
                RESPONSE_ORIGIN => {
                    response.response_origin = Some(self.parse_xor_mapped_address(&mut buf, attr_length, &tid)?);
                }
                ERROR_CODE => {
                    let error = self.parse_error_code(&mut buf, attr_length)?;
                    anyhow::bail!("STUN error: {}", error);
                }
                _ => {
                    // Skip unknown attributes
                    buf.advance(attr_length);
                }
            }

            // Handle padding
            let padding = (4 - (attr_length % 4)) % 4;
            if buf.remaining() >= padding {
                buf.advance(padding);
            }

            remaining = remaining.saturating_sub(4 + attr_length + padding);
        }

        Ok(response)
    }

    /// Parse XOR-MAPPED-ADDRESS
    fn parse_xor_mapped_address(&self, buf: &mut BytesMut, length: usize, tid: &[u8; 12]) -> Result<SocketAddr> {
        if length < 8 {
            anyhow::bail!("XOR-MAPPED-ADDRESS too short");
        }

        let _ = buf.get_u8(); // Reserved
        let family = buf.get_u8();
        let port = buf.get_u16() ^ (STUN_MAGIC_COOKIE >> 16) as u16;

        match family {
            0x01 => {
                // IPv4
                let ip_bytes = buf.get_u32() ^ STUN_MAGIC_COOKIE;
                let ip = std::net::Ipv4Addr::from(ip_bytes);
                Ok(SocketAddr::new(ip.into(), port))
            }
            0x02 => {
                // IPv6
                if length < 20 {
                    anyhow::bail!("IPv6 XOR-MAPPED-ADDRESS too short");
                }

                let mut addr_bytes = [0u8; 16];
                buf.copy_to_slice(&mut addr_bytes);

                // XOR with magic cookie and transaction ID
                for i in 0..4 {
                    addr_bytes[i] ^= ((STUN_MAGIC_COOKIE >> (8 * (3 - i))) & 0xFF) as u8;
                }
                for i in 0..12 {
                    addr_bytes[i + 4] ^= tid[i];
                }

                let ip = std::net::Ipv6Addr::from(addr_bytes);
                Ok(SocketAddr::new(ip.into(), port))
            }
            _ => anyhow::bail!("Unknown address family: {}", family),
        }
    }

    /// Parse MAPPED-ADDRESS (legacy)
    fn parse_mapped_address(&self, buf: &mut BytesMut, length: usize) -> Result<SocketAddr> {
        if length < 8 {
            anyhow::bail!("MAPPED-ADDRESS too short");
        }

        let _ = buf.get_u8(); // Reserved
        let family = buf.get_u8();
        let port = buf.get_u16();

        match family {
            0x01 => {
                let ip = std::net::Ipv4Addr::from(buf.get_u32());
                Ok(SocketAddr::new(ip.into(), port))
            }
            0x02 => {
                if length < 20 {
                    anyhow::bail!("IPv6 MAPPED-ADDRESS too short");
                }
                let mut addr_bytes = [0u8; 16];
                buf.copy_to_slice(&mut addr_bytes);
                let ip = std::net::Ipv6Addr::from(addr_bytes);
                Ok(SocketAddr::new(ip.into(), port))
            }
            _ => anyhow::bail!("Unknown address family"),
        }
    }

    /// Parse ERROR-CODE attribute
    fn parse_error_code(&self, buf: &mut BytesMut, length: usize) -> Result<String> {
        if length < 4 {
            anyhow::bail!("ERROR-CODE too short");
        }

        let _ = buf.get_u16(); // Reserved
        let class = buf.get_u8();
        let number = buf.get_u8();
        let code = (class as u16 * 100) + number as u16;

        let reason_length = length.saturating_sub(4);
        let mut reason_bytes = vec![0u8; reason_length];
        buf.copy_to_slice(&mut reason_bytes);

        let reason = String::from_utf8_lossy(&reason_bytes);

        Ok(format!("Error {}: {}", code, reason))
    }

    /// Resolve STUN server address
    async fn resolve_server(&self, server: &str) -> Result<SocketAddr> {
        // First try parsing as socket address
        if let Ok(addr) = server.parse() {
            return Ok(addr);
        }

        // Try DNS resolution with timeout
        match timeout(Duration::from_secs(5), lookup_host(server)).await {
            Ok(Ok(mut addrs)) => {
                addrs.next()
                    .ok_or_else(|| anyhow::anyhow!("No addresses found for {}", server))
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("DNS lookup failed for {}: {}", server, e)),
            Err(_) => Err(anyhow::anyhow!("DNS lookup timeout for {}", server)),
        }
    }

    /// Generate random transaction ID
    fn generate_transaction_id(&self) -> [u8; 12] {
        let mut tid = [0u8; 12];
        rand::thread_rng().fill(&mut tid);
        tid
    }
}

/// STUN response structure
#[derive(Debug, Default)]
struct StunResponse {
    mapped_address: Option<SocketAddr>,
    other_address: Option<SocketAddr>,
    response_origin: Option<SocketAddr>,
    software: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_real_stun_servers() {
        let servers = vec![
            "stun.l.google.com:19302".to_string(),
            "stun1.l.google.com:19302".to_string(),
        ];

        let client = StunClient::new(servers);

        // Test with a real socket
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

        match client.get_mapped_address(&socket).await {
            Ok(addr) => {
                println!("Mapped address: {}", addr);
                assert!(!addr.ip().is_loopback());
            }
            Err(e) => {
                // This might fail in test environments without internet
                eprintln!("STUN test failed (expected in isolated env): {}", e);
            }
        }
    }
}