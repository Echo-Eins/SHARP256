use std::net::SocketAddr;
use std::collections::HashMap;
use tokio::net::UdpSocket;
use crate::nat::{NatType, error::NatResult};
use crate::nat::metrics::record_nat_type_detection;
use super::client::StunClient;
use super::protocol::*;

/// NAT mapping behavior (RFC 5780)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingBehavior {
    /// Same mapping for all destinations (best for P2P)
    EndpointIndependent,
    
    /// Different mapping per destination IP
    AddressDependent,
    
    /// Different mapping per destination IP:port
    AddressPortDependent,
}

/// NAT filtering behavior (RFC 5780)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilteringBehavior {
    /// Allow packets from any source (best for P2P)
    EndpointIndependent,
    
    /// Allow only from IPs we've sent to
    AddressDependent,
    
    /// Allow only from IP:port pairs we've sent to
    AddressPortDependent,
}

/// Complete NAT behavior characteristics
#[derive(Debug, Clone)]
pub struct NatBehavior {
    /// Mapping behavior
    pub mapping: MappingBehavior,
    
    /// Filtering behavior
    pub filtering: FilteringBehavior,
    
    /// Supports hairpinning (local connections)
    pub hairpinning: bool,
    
    /// Mapping lifetime in seconds
    pub mapping_lifetime: Option<u64>,
    
    /// Detected public addresses
    pub public_addresses: Vec<SocketAddr>,
    
    /// Confidence level (0.0 to 1.0)
    pub confidence: f64,
}

impl NatBehavior {
    /// Convert to simple NAT type classification
    pub fn to_simple_nat_type(&self) -> NatType {
        match (self.mapping, self.filtering) {
            (MappingBehavior::EndpointIndependent, FilteringBehavior::EndpointIndependent) => {
                NatType::FullCone
            }
            (MappingBehavior::EndpointIndependent, FilteringBehavior::AddressDependent) => {
                NatType::RestrictedCone
            }
            (MappingBehavior::EndpointIndependent, FilteringBehavior::AddressPortDependent) => {
                NatType::PortRestricted
            }
            (MappingBehavior::AddressDependent, _) |
            (MappingBehavior::AddressPortDependent, _) => {
                NatType::Symmetric
            }
        }
    }
    
    /// Get P2P connectivity score (0.0 to 1.0)
    pub fn p2p_score(&self) -> f64 {
        let mapping_score = match self.mapping {
            MappingBehavior::EndpointIndependent => 1.0,
            MappingBehavior::AddressDependent => 0.5,
            MappingBehavior::AddressPortDependent => 0.2,
        };
        
        let filtering_score = match self.filtering {
            FilteringBehavior::EndpointIndependent => 1.0,
            FilteringBehavior::AddressDependent => 0.6,
            FilteringBehavior::AddressPortDependent => 0.3,
        };
        
        let hairpin_score = if self.hairpinning { 0.1 } else { 0.0 };
        
        (mapping_score * 0.5 + filtering_score * 0.4 + hairpin_score) * self.confidence
    }
}

/// NAT behavior discovery implementation (RFC 5780)
pub struct NatBehaviorDiscovery<'a> {
    client: &'a StunClient,
    test_results: HashMap<String, TestResult>,
}

#[derive(Debug, Clone)]
struct TestResult {
    local_addr: SocketAddr,
    mapped_addr: SocketAddr,
    server_addr: SocketAddr,
    changed_addr: Option<SocketAddr>,
    response_origin: Option<SocketAddr>,
}

impl<'a> NatBehaviorDiscovery<'a> {
    pub fn new(client: &'a StunClient) -> Self {
        Self {
            client,
            test_results: HashMap::new(),
        }
    }
    
    /// Detect complete NAT behavior
    pub async fn detect_behavior(&mut self, socket: &UdpSocket) -> NatResult<NatBehavior> {
        let local_addr = socket.local_addr()?;
        
        // Test 1: Basic binding request
        let test1 = self.perform_test(socket, "test1", None).await?;
        
        // Check if we're behind NAT
        if test1.mapped_addr.ip() == local_addr.ip() {
            // No NAT detected
            tracing::info!("No NAT detected - public IP address");
            record_nat_type_detection("none", "high");
            
            return Ok(NatBehavior {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::EndpointIndependent,
                hairpinning: true,
                mapping_lifetime: None,
                public_addresses: vec![test1.mapped_addr],
                confidence: 1.0,
            });
        }
        
        // We're behind NAT, continue testing
        tracing::info!("NAT detected - mapped address: {}", test1.mapped_addr);
        
        // Test 2: Request from different IP (if server supports it)
        let test2 = if test1.changed_addr.is_some() {
            match self.perform_test(socket, "test2", Some(ChangeRequest::ChangeIP)).await {
                Ok(result) => Some(result),
                Err(_) => None,
            }
        } else {
            None
        };
        
        // Test 3: Request from different port
        let test3 = if test1.changed_addr.is_some() {
            match self.perform_test(socket, "test3", Some(ChangeRequest::ChangePort)).await {
                Ok(result) => Some(result),
                Err(_) => None,
            }
        } else {
            None
        };
        
        // Test 4: Request from different IP and port
        let test4 = if test1.changed_addr.is_some() {
            match self.perform_test(socket, "test4", Some(ChangeRequest::ChangeBoth)).await {
                Ok(result) => Some(result),
                Err(_) => None,
            }
        } else {
            None
        };
        
        // Analyze results
        let behavior = self.analyze_results(test1, test2, test3, test4)?;
        
        // Test hairpinning
        let hairpinning = self.test_hairpinning(socket, behavior.public_addresses[0]).await;
        
        // Test mapping lifetime
        let mapping_lifetime = self.test_mapping_lifetime(socket).await.ok();
        
        let final_behavior = NatBehavior {
            hairpinning,
            mapping_lifetime,
            ..behavior
        };
        
        // Record metrics
        let nat_type = final_behavior.to_simple_nat_type();
        let confidence_level = if final_behavior.confidence > 0.8 {
            "high"
        } else if final_behavior.confidence > 0.5 {
            "medium"
        } else {
            "low"
        };
        
        record_nat_type_detection(&format!("{:?}", nat_type), confidence_level);
        
        tracing::info!("NAT behavior detected: {:?}", final_behavior);
        
        Ok(final_behavior)
    }
    
    /// Perform a single test
    async fn perform_test(
        &mut self,
        socket: &UdpSocket,
        test_name: &str,
        change_request: Option<ChangeRequest>,
    ) -> NatResult<TestResult> {
        // Find a server that supports RFC 5780 tests
        let server_info = self.find_rfc5780_server(socket).await?;
        
        let transaction_id = TransactionId::new();
        let mut request = Message::new(MessageType::BindingRequest, transaction_id);
        
        // Add CHANGE-REQUEST if needed
        if let Some(change_req) = change_request {
            let flags = match change_req {
                ChangeRequest::ChangeIP => 0x04,
                ChangeRequest::ChangePort => 0x02,
                ChangeRequest::ChangeBoth => 0x06,
            };
            
            request.add_attribute(Attribute::new(
                AttributeType::ChangeRequest,
                AttributeValue::Raw(vec![0, 0, 0, flags]),
            ));
        }
        
        // Send request
        let response = self.client.send_with_retries(
            socket,
            server_info.address,
            request,
            None,
        ).await?;
        
        // Extract mapped address
        let mapped_addr = response.attributes.iter()
            .find_map(|attr| match &attr.value {
                AttributeValue::XorMappedAddress(addr) |
                AttributeValue::MappedAddress(addr) => Some(*addr),
                _ => None,
            })
            .ok_or_else(|| crate::nat::error::StunError::MissingAttribute(
                "MAPPED-ADDRESS".to_string()
            ))?;
        
        // Extract changed address
        let changed_addr = response.attributes.iter()
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
            server_addr: server_info.address,
            changed_addr,
            response_origin,
        };
        
        self.test_results.insert(test_name.to_string(), result.clone());
        
        Ok(result)
    }
    
    /// Find a server that supports RFC 5780
    async fn find_rfc5780_server(&self, socket: &UdpSocket) -> NatResult<super::StunServerInfo> {
        // Try servers from configuration
        for server in &self.client.config.servers {
            match self.client.query_server(socket, server).await {
                Ok(info) if info.supports_change_request => {
                    tracing::info!("Found RFC 5780 compliant server: {}", server);
                    return Ok(info);
                }
                Ok(_) => {
                    tracing::debug!("Server {} doesn't support CHANGE-REQUEST", server);
                }
                Err(e) => {
                    tracing::debug!("Failed to query {}: {}", server, e);
                }
            }
        }
        
        Err(crate::nat::error::NatError::Configuration(
            "No RFC 5780 compliant STUN servers found".to_string()
        ))
    }
    
    /// Analyze test results to determine NAT behavior
    fn analyze_results(
        &self,
        test1: TestResult,
        test2: Option<TestResult>,
        test3: Option<TestResult>,
        test4: Option<TestResult>,
    ) -> NatResult<NatBehavior> {
        let mut public_addresses = vec![test1.mapped_addr];
        let mut confidence = 1.0;
        
        // Determine mapping behavior
        let mapping = if let Some(ref t2) = test2 {
            if t2.mapped_addr == test1.mapped_addr {
                MappingBehavior::EndpointIndependent
            } else {
                public_addresses.push(t2.mapped_addr);
                MappingBehavior::AddressDependent
            }
        } else {
            // Can't determine precisely without test2
            confidence *= 0.7;
            MappingBehavior::EndpointIndependent // Optimistic assumption
        };
        
        // Determine filtering behavior
        let filtering = match (test2.is_some(), test3.is_some(), test4.is_some()) {
            (true, true, true) => {
                // Full test suite available
                FilteringBehavior::EndpointIndependent
            }
            (true, false, false) => {
                // Only IP change test worked
                FilteringBehavior::AddressDependent
            }
            (false, true, false) => {
                // Only port change test worked
                FilteringBehavior::AddressPortDependent
            }
            _ => {
                // Limited test results
                confidence *= 0.5;
                FilteringBehavior::AddressPortDependent // Conservative assumption
            }
        };
        
        Ok(NatBehavior {
            mapping,
            filtering,
            hairpinning: false, // Will be tested separately
            mapping_lifetime: None, // Will be tested separately
            public_addresses,
            confidence,
        })
    }
    
    /// Test hairpinning support
    async fn test_hairpinning(&self, socket: &UdpSocket, public_addr: SocketAddr) -> bool {
        // Try to send packet to our own public address
        let test_data = b"SHARP_HAIRPIN_TEST";
        
        if socket.send_to(test_data, public_addr).await.is_err() {
            return false;
        }
        
        // Try to receive it
        let mut buffer = vec![0u8; 100];
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            socket.recv_from(&mut buffer)
        ).await {
            Ok(Ok((size, addr))) if addr == public_addr && &buffer[..size] == test_data => {
                tracing::info!("Hairpinning supported");
                true
            }
            _ => {
                tracing::info!("Hairpinning not supported");
                false
            }
        }
    }
    
    /// Test mapping lifetime
    async fn test_mapping_lifetime(&self, socket: &UdpSocket) -> NatResult<u64> {
        let initial_result = self.perform_test(socket, "lifetime_initial", None).await?;
        let initial_mapping = initial_result.mapped_addr;
        
        // Test at increasing intervals
        let test_intervals = [30, 60, 120, 300, 600, 1800, 3600]; // seconds
        
        for interval in test_intervals {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            
            let result = self.perform_test(socket, &format!("lifetime_{}", interval), None).await?;
            
            if result.mapped_addr != initial_mapping {
                // Mapping changed, lifetime is less than this interval
                tracing::info!("NAT mapping lifetime: < {} seconds", interval);
                return Ok(interval);
            }
        }
        
        // Mapping stable for at least 1 hour
        tracing::info!("NAT mapping lifetime: > 3600 seconds");
        Ok(3600)
    }
}

#[derive(Debug, Clone, Copy)]
enum ChangeRequest {
    ChangeIP,
    ChangePort,
    ChangeBoth,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nat_type_mapping() {
        let behavior = NatBehavior {
            mapping: MappingBehavior::EndpointIndependent,
            filtering: FilteringBehavior::EndpointIndependent,
            hairpinning: true,
            mapping_lifetime: Some(3600),
            public_addresses: vec!["1.2.3.4:5678".parse().unwrap()],
            confidence: 1.0,
        };
        
        assert_eq!(behavior.to_simple_nat_type(), NatType::FullCone);
        assert_eq!(behavior.p2p_score(), 1.0);
    }
    
    #[test]
    fn test_symmetric_nat_detection() {
        let behavior = NatBehavior {
            mapping: MappingBehavior::AddressPortDependent,
            filtering: FilteringBehavior::AddressPortDependent,
            hairpinning: false,
            mapping_lifetime: Some(60),
            public_addresses: vec![
                "1.2.3.4:5678".parse().unwrap(),
                "1.2.3.4:5679".parse().unwrap(),
            ],
            confidence: 0.8,
        };
        
        assert_eq!(behavior.to_simple_nat_type(), NatType::Symmetric);
        assert!(behavior.p2p_score() < 0.5);
    }
}