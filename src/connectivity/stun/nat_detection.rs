// src/connectivity/stun/nat_detection.rs
//! RFC 5780 NAT Behavior Discovery
//!
//! This module implements NAT type detection through three STUN binding tests:
//!
//! ## Mapping Behavior (how NAT maps internal addresses)
//! - Endpoint-Independent: Same external mapping for all destinations
//! - Address-Dependent: Same mapping only for same destination IP
//! - Address and Port-Dependent: New mapping for each destination IP:port
//!
//! ## Filtering Behavior (what packets NAT allows in)
//! - Endpoint-Independent: Accepts from any source
//! - Address-Dependent: Only accepts from contacted IPs
//! - Address and Port-Dependent: Only accepts from contacted IP:port
//!
//! ## Test Procedure
//!
//! 1. Test I: Binding Request to primary server → get MAPPED-ADDRESS, OTHER-ADDRESS
//! 2. Test II: Binding Request to same IP, different port → compare with Test I
//! 3. Test III: Binding Request to different IP → compare with Test I

use anyhow::{Result, Context};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, warn, debug, instrument};

use super::{
    StunClient, StunClientConfig, StunConfig, BindingResult, StunError,
};

/// NAT Mapping Behavior per RFC 5780
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatMappingBehavior {
    /// Same external endpoint for all destinations
    /// (Best for P2P connectivity)
    EndpointIndependent,

    /// Same external endpoint for same destination IP
    AddressDependent,

    /// New external endpoint for each destination IP:port
    /// (Hardest for P2P, requires TURN)
    AddressAndPortDependent,

    /// Could not determine
    Unknown,
}

impl std::fmt::Display for NatMappingBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatMappingBehavior::EndpointIndependent => write!(f, "Endpoint-Independent Mapping"),
            NatMappingBehavior::AddressDependent => write!(f, "Address-Dependent Mapping"),
            NatMappingBehavior::AddressAndPortDependent => write!(f, "Address and Port-Dependent Mapping"),
            NatMappingBehavior::Unknown => write!(f, "Unknown Mapping"),
        }
    }
}

/// NAT Filtering Behavior per RFC 5780
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatFilteringBehavior {
    /// Accepts packets from any source
    /// (Best for P2P connectivity)
    EndpointIndependent,

    /// Only accepts from IPs that were contacted
    AddressDependent,

    /// Only accepts from IP:port that were contacted
    /// (Most restrictive)
    AddressAndPortDependent,

    /// Could not determine
    Unknown,
}

impl std::fmt::Display for NatFilteringBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatFilteringBehavior::EndpointIndependent => write!(f, "Endpoint-Independent Filtering"),
            NatFilteringBehavior::AddressDependent => write!(f, "Address-Dependent Filtering"),
            NatFilteringBehavior::AddressAndPortDependent => write!(f, "Address and Port-Dependent Filtering"),
            NatFilteringBehavior::Unknown => write!(f, "Unknown Filtering"),
        }
    }
}

/// Simplified NAT type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT (public IP)
    OpenInternet,

    /// Full Cone NAT (Endpoint-Independent Mapping + Filtering)
    FullCone,

    /// Restricted Cone NAT (Endpoint-Independent Mapping, Address-Dependent Filtering)
    RestrictedCone,

    /// Port Restricted Cone NAT (Endpoint-Independent Mapping, Address+Port-Dependent Filtering)
    PortRestrictedCone,

    /// Symmetric NAT (Address+Port-Dependent Mapping)
    Symmetric,

    /// UDP blocked
    UdpBlocked,

    /// Could not determine
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::OpenInternet => write!(f, "Open Internet"),
            NatType::FullCone => write!(f, "Full Cone NAT"),
            NatType::RestrictedCone => write!(f, "Restricted Cone NAT"),
            NatType::PortRestrictedCone => write!(f, "Port Restricted Cone NAT"),
            NatType::Symmetric => write!(f, "Symmetric NAT"),
            NatType::UdpBlocked => write!(f, "UDP Blocked"),
            NatType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Result of NAT detection
#[derive(Debug, Clone)]
pub struct NatDetectionResult {
    /// NAT Mapping Behavior
    pub mapping_behavior: NatMappingBehavior,

    /// NAT Filtering Behavior
    pub filtering_behavior: NatFilteringBehavior,

    /// Simplified NAT type
    pub nat_type: NatType,

    /// Our external (mapped) address from primary server
    pub external_address: SocketAddr,

    /// Primary STUN server address
    pub primary_server: SocketAddr,

    /// Alternate server address (if available)
    pub alternate_server: Option<SocketAddr>,

    /// Average RTT to primary server
    pub average_rtt: Duration,

    /// Test results for debugging
    pub test_results: NatTestResults,

    /// Recommendations for ICE strategy
    pub recommendations: Vec<String>,
}

/// Individual test results
#[derive(Debug, Clone, Default)]
pub struct NatTestResults {
    /// Test I: Primary server binding
    pub test_1: Option<BindingResult>,

    /// Test II: Same IP, different port
    pub test_2: Option<BindingResult>,

    /// Test III: Different IP
    pub test_3: Option<BindingResult>,

    /// Test I with CHANGE-REQUEST (IP only)
    pub test_1_change_ip: Option<BindingResult>,

    /// Test I with CHANGE-REQUEST (port only)
    pub test_1_change_port: Option<BindingResult>,

    /// Test I with CHANGE-REQUEST (IP and port)
    pub test_1_change_both: Option<BindingResult>,
}

/// NAT Detector for RFC 5780 behavior discovery
pub struct NatDetector {
    /// STUN client
    client: StunClient,

    /// Primary STUN server
    primary_server: SocketAddr,

    /// Test timeout
    timeout: Duration,
}

impl NatDetector {
    /// Create a new NAT detector
    pub async fn new(config: StunConfig) -> Result<Self> {
        if config.servers.is_empty() {
            return Err(anyhow::anyhow!("No STUN servers configured"));
        }

        let (primary_server, _) = super::parse_stun_url(&config.servers[0])
            .map_err(|e| anyhow::anyhow!("Invalid STUN server: {}", e))?;

        let client_config = StunClientConfig {
            config: config.clone(),
            local_addr: None,
            verbose: true,
        };

        let client = StunClient::new(client_config)
            .await
            .context("Failed to create STUN client")?;

        Ok(Self {
            client,
            primary_server,
            timeout: config.timeout,
        })
    }

    /// Create with existing STUN client
    pub fn with_client(client: StunClient, primary_server: SocketAddr) -> Self {
        Self {
            client,
            primary_server,
            timeout: Duration::from_secs(10),
        }
    }

    /// Perform NAT detection
    ///
    /// This runs the RFC 5780 test suite and returns comprehensive results.
    #[instrument(skip(self))]
    pub async fn detect_nat_behavior(&self) -> Result<NatDetectionResult> {
        info!("Starting NAT behavior detection with server {}", self.primary_server);

        let mut test_results = NatTestResults::default();

        // Test I: Basic binding request to primary server
        let test_1 = self.client.binding_request_udp(self.primary_server, None).await
            .context("Test I (primary binding) failed")?;

        info!("Test I: Mapped address = {}", test_1.mapped_address);
        test_results.test_1 = Some(test_1.clone());

        let external_address = test_1.xor_mapped_address.unwrap_or(test_1.mapped_address);

        // Check if we have OTHER-ADDRESS for alternate server
        let alternate_server = test_1.other_address;
        if let Some(alt) = alternate_server {
            info!("Alternate server available: {}", alt);
        } else {
            warn!("Server does not provide OTHER-ADDRESS, limited NAT detection");
        }

        // Determine mapping behavior
        let mapping_behavior = self.detect_mapping_behavior(
            &test_1,
            &mut test_results,
        ).await;

        // Determine filtering behavior
        let filtering_behavior = self.detect_filtering_behavior(
            &test_1,
            &mut test_results,
        ).await;

        // Classify NAT type
        let nat_type = classify_nat_type(mapping_behavior, filtering_behavior, &test_1);

        // Calculate average RTT
        let stats = self.client.get_stats().await;
        let average_rtt = stats.average_rtt().unwrap_or(test_1.rtt);

        // Generate recommendations
        let recommendations = generate_recommendations(nat_type, mapping_behavior, filtering_behavior);

        let result = NatDetectionResult {
            mapping_behavior,
            filtering_behavior,
            nat_type,
            external_address,
            primary_server: self.primary_server,
            alternate_server,
            average_rtt,
            test_results,
            recommendations,
        };

        info!("NAT Detection complete: {}", nat_type);
        info!("  Mapping: {}", mapping_behavior);
        info!("  Filtering: {}", filtering_behavior);

        Ok(result)
    }

    /// Detect NAT Mapping Behavior
    async fn detect_mapping_behavior(
        &self,
        test_1: &BindingResult,
        results: &mut NatTestResults,
    ) -> NatMappingBehavior {
        let mapped_1 = test_1.xor_mapped_address.unwrap_or(test_1.mapped_address);

        // Need alternate server for proper mapping detection
        let Some(other_addr) = test_1.other_address else {
            // Try to use second server from config if available
            debug!("No OTHER-ADDRESS, cannot fully determine mapping behavior");
            return NatMappingBehavior::Unknown;
        };

        // Test II: Same IP, different port
        let alt_port_addr = SocketAddr::new(
            self.primary_server.ip(),
            other_addr.port(),
        );

        match self.client.binding_request_udp(alt_port_addr, None).await {
            Ok(test_2) => {
                let mapped_2 = test_2.xor_mapped_address.unwrap_or(test_2.mapped_address);
                results.test_2 = Some(test_2);

                if mapped_1 == mapped_2 {
                    // Same mapping for different port, test with different IP
                    // Test III: Different IP
                    match self.client.binding_request_udp(other_addr, None).await {
                        Ok(test_3) => {
                            let mapped_3 = test_3.xor_mapped_address.unwrap_or(test_3.mapped_address);
                            results.test_3 = Some(test_3);

                            if mapped_1 == mapped_3 {
                                info!("Mapping: Endpoint-Independent (same mapping for all destinations)");
                                NatMappingBehavior::EndpointIndependent
                            } else {
                                info!("Mapping: Address-Dependent (different mapping for different IP)");
                                NatMappingBehavior::AddressDependent
                            }
                        }
                        Err(e) => {
                            warn!("Test III failed: {}", e);
                            // If test II passed but III failed, likely Address-Dependent
                            NatMappingBehavior::AddressDependent
                        }
                    }
                } else {
                    info!("Mapping: Address and Port-Dependent (different mapping for different port)");
                    NatMappingBehavior::AddressAndPortDependent
                }
            }
            Err(e) => {
                warn!("Test II failed: {}", e);
                NatMappingBehavior::Unknown
            }
        }
    }

    /// Detect NAT Filtering Behavior
    async fn detect_filtering_behavior(
        &self,
        test_1: &BindingResult,
        results: &mut NatTestResults,
    ) -> NatFilteringBehavior {
        // Filtering behavior is detected by using CHANGE-REQUEST
        // to have the server respond from a different address/port

        // Test with CHANGE-REQUEST: change both IP and port
        match self.client.binding_request_with_change(
            self.primary_server,
            true,  // change IP
            true,  // change port
        ).await {
            Ok(result) => {
                results.test_1_change_both = Some(result);
                info!("Filtering: Endpoint-Independent (received response from different IP:port)");
                return NatFilteringBehavior::EndpointIndependent;
            }
            Err(StunError::Timeout { .. }) => {
                debug!("No response with change IP+port");
            }
            Err(e) => {
                debug!("Change IP+port test error: {}", e);
            }
        }

        // Test with CHANGE-REQUEST: change port only
        match self.client.binding_request_with_change(
            self.primary_server,
            false, // same IP
            true,  // change port
        ).await {
            Ok(result) => {
                results.test_1_change_port = Some(result);
                info!("Filtering: Address-Dependent (received from same IP, different port)");
                return NatFilteringBehavior::AddressDependent;
            }
            Err(StunError::Timeout { .. }) => {
                debug!("No response with change port");
            }
            Err(e) => {
                debug!("Change port test error: {}", e);
            }
        }

        // If we got here, filtering is Address and Port-Dependent
        info!("Filtering: Address and Port-Dependent (only receives from contacted IP:port)");
        NatFilteringBehavior::AddressAndPortDependent
    }

    /// Quick NAT check (just Test I)
    pub async fn quick_check(&self) -> Result<BindingResult> {
        self.client.binding_request_udp(self.primary_server, None).await
            .map_err(|e| anyhow::anyhow!("Quick NAT check failed: {}", e))
    }

    /// Get the STUN client
    pub fn client(&self) -> &StunClient {
        &self.client
    }
}

/// Classify NAT type from mapping and filtering behaviors
fn classify_nat_type(
    mapping: NatMappingBehavior,
    filtering: NatFilteringBehavior,
    test_1: &BindingResult,
) -> NatType {
    // Check if external address equals local (no NAT)
    // This would require knowing local address

    match mapping {
        NatMappingBehavior::EndpointIndependent => {
            match filtering {
                NatFilteringBehavior::EndpointIndependent => NatType::FullCone,
                NatFilteringBehavior::AddressDependent => NatType::RestrictedCone,
                NatFilteringBehavior::AddressAndPortDependent => NatType::PortRestrictedCone,
                NatFilteringBehavior::Unknown => NatType::Unknown,
            }
        }
        NatMappingBehavior::AddressDependent |
        NatMappingBehavior::AddressAndPortDependent => NatType::Symmetric,
        NatMappingBehavior::Unknown => NatType::Unknown,
    }
}

/// Generate ICE strategy recommendations based on NAT type
fn generate_recommendations(
    nat_type: NatType,
    mapping: NatMappingBehavior,
    filtering: NatFilteringBehavior,
) -> Vec<String> {
    let mut recommendations = Vec::new();

    match nat_type {
        NatType::OpenInternet | NatType::FullCone => {
            recommendations.push("Direct P2P connection likely to succeed".to_string());
            recommendations.push("Host candidates should work well".to_string());
        }
        NatType::RestrictedCone | NatType::PortRestrictedCone => {
            recommendations.push("P2P possible with proper hole punching".to_string());
            recommendations.push("Server-reflexive candidates recommended".to_string());
            recommendations.push("Ensure both peers send to each other simultaneously".to_string());
        }
        NatType::Symmetric => {
            recommendations.push("Symmetric NAT detected - P2P challenging".to_string());
            recommendations.push("TURN relay likely required".to_string());
            recommendations.push("Consider using relay candidates".to_string());
        }
        NatType::UdpBlocked => {
            recommendations.push("UDP appears blocked".to_string());
            recommendations.push("TURN over TCP may be required".to_string());
        }
        NatType::Unknown => {
            recommendations.push("NAT type unclear - use all candidate types".to_string());
            recommendations.push("Include relay candidates as fallback".to_string());
        }
    }

    // Add specific recommendations based on behaviors
    if mapping == NatMappingBehavior::AddressAndPortDependent {
        recommendations.push("New mapping for each destination - requires TURN for peer behind symmetric NAT".to_string());
    }

    if filtering == NatFilteringBehavior::AddressAndPortDependent {
        recommendations.push("Strict filtering - ensure binding holes are punched correctly".to_string());
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_type_classification() {
        // Full Cone
        let nat_type = classify_nat_type(
            NatMappingBehavior::EndpointIndependent,
            NatFilteringBehavior::EndpointIndependent,
            &create_dummy_result(),
        );
        assert_eq!(nat_type, NatType::FullCone);

        // Restricted Cone
        let nat_type = classify_nat_type(
            NatMappingBehavior::EndpointIndependent,
            NatFilteringBehavior::AddressDependent,
            &create_dummy_result(),
        );
        assert_eq!(nat_type, NatType::RestrictedCone);

        // Port Restricted Cone
        let nat_type = classify_nat_type(
            NatMappingBehavior::EndpointIndependent,
            NatFilteringBehavior::AddressAndPortDependent,
            &create_dummy_result(),
        );
        assert_eq!(nat_type, NatType::PortRestrictedCone);

        // Symmetric
        let nat_type = classify_nat_type(
            NatMappingBehavior::AddressAndPortDependent,
            NatFilteringBehavior::AddressAndPortDependent,
            &create_dummy_result(),
        );
        assert_eq!(nat_type, NatType::Symmetric);
    }

    #[test]
    fn test_recommendations() {
        let recs = generate_recommendations(
            NatType::Symmetric,
            NatMappingBehavior::AddressAndPortDependent,
            NatFilteringBehavior::AddressAndPortDependent,
        );

        assert!(!recs.is_empty());
        assert!(recs.iter().any(|r| r.contains("TURN")));
    }

    fn create_dummy_result() -> BindingResult {
        use super::super::transaction::TransactionId;

        BindingResult {
            server_addr: "1.2.3.4:3478".parse().unwrap(),
            mapped_address: "5.6.7.8:12345".parse().unwrap(),
            xor_mapped_address: Some("5.6.7.8:12345".parse().unwrap()),
            rtt: Duration::from_millis(50),
            transaction_id: TransactionId::generate(),
            integrity_verified: false,
            response_origin: None,
            other_address: None,
        }
    }
}
