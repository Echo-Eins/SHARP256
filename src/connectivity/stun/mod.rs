// src/connectivity/stun/mod.rs
//! STUN Protocol Implementation
//!
//! RFC 8489 compliant STUN client with NAT detection capabilities.
//!
//! This module provides:
//! - StunClient for sending Binding Requests
//! - MESSAGE-INTEGRITY verification (HMAC-SHA1)
//! - XOR-MAPPED-ADDRESS parsing
//! - Transaction ID tracking with RTT measurement
//! - Retransmission with exponential backoff
//! - RFC 5780 NAT Behavior Discovery
//!
//! # Architecture
//!
//! This STUN implementation works alongside webrtc-rs:
//! - webrtc-rs handles ICE connectivity checks
//! - Our StunClient handles NAT detection and precise RTT measurement
//!
//! # Example
//!
//! ```rust,ignore
//! use sharp256::connectivity::stun::{StunClient, NatDetector};
//!
//! // Create STUN client
//! let client = StunClient::new(config).await?;
//!
//! // Perform NAT detection
//! let detector = NatDetector::new(client);
//! let nat_result = detector.detect_nat_behavior().await?;
//!
//! println!("NAT Mapping: {:?}", nat_result.mapping_behavior);
//! println!("NAT Filtering: {:?}", nat_result.filtering_behavior);
//! ```

pub mod attributes;
pub mod client;
pub mod integrity;
pub mod message;
pub mod nat_detection;
pub mod retransmission;
pub mod transaction;
pub mod ipv6;

// Re-exports
pub use attributes::{
    StunAttribute, XorMappedAddress, MappedAddress,
    ChangeRequest, ResponseOrigin, OtherAddress,
};
pub use client::{StunClient, StunClientConfig};
pub use integrity::{MessageIntegrity, IntegrityError};
pub use message::{StunMessage, StunMessageType, StunClass, StunMethod};
pub use nat_detection::{
    NatDetector, NatDetectionResult, NatMappingBehavior,
    NatFilteringBehavior, NatType,
};
pub use retransmission::{RetransmissionConfig, RetransmissionState};
pub use transaction::{TransactionId, TransactionTracker, TransactionResult};

use std::net::SocketAddr;
use std::time::Duration;

/// STUN protocol constants per RFC 8489
pub mod constants {
    /// STUN magic cookie (RFC 8489 Section 6)
    pub const MAGIC_COOKIE: u32 = 0x2112A442;

    /// STUN header size in bytes
    pub const HEADER_SIZE: usize = 20;

    /// Transaction ID size in bytes
    pub const TRANSACTION_ID_SIZE: usize = 12;

    /// Default STUN port
    pub const DEFAULT_STUN_PORT: u16 = 3478;

    /// Default STUNS (STUN over DTLS) port
    pub const DEFAULT_STUNS_PORT: u16 = 5349;

    /// Initial RTO (Retransmission Timeout) per RFC 8489
    pub const INITIAL_RTO_MS: u64 = 500;

    /// Maximum retransmissions per RFC 8489
    pub const MAX_RETRANSMISSIONS: u32 = 7;

    /// Rm value for RTO calculation (RFC 8489 Section 14.3)
    pub const RM: u32 = 16;

    /// Maximum STUN message size
    pub const MAX_MESSAGE_SIZE: usize = 548;

    // STUN Attribute Types (RFC 8489 Section 18.2)
    pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
    pub const ATTR_CHANGE_REQUEST: u16 = 0x0003;
    pub const ATTR_USERNAME: u16 = 0x0006;
    pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const ATTR_ERROR_CODE: u16 = 0x0009;
    pub const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
    pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const ATTR_PRIORITY: u16 = 0x0024;
    pub const ATTR_USE_CANDIDATE: u16 = 0x0025;
    pub const ATTR_FINGERPRINT: u16 = 0x8028;
    pub const ATTR_ICE_CONTROLLED: u16 = 0x8029;
    pub const ATTR_ICE_CONTROLLING: u16 = 0x802A;

    // RFC 5780 NAT Behavior Discovery attributes
    pub const ATTR_RESPONSE_ORIGIN: u16 = 0x802B;
    pub const ATTR_OTHER_ADDRESS: u16 = 0x802C;

    // STUN error codes
    pub const ERROR_TRY_ALTERNATE: u16 = 300;
    pub const ERROR_BAD_REQUEST: u16 = 400;
    pub const ERROR_UNAUTHORIZED: u16 = 401;
    pub const ERROR_UNKNOWN_ATTRIBUTE: u16 = 420;
    pub const ERROR_STALE_NONCE: u16 = 438;
    pub const ERROR_SERVER_ERROR: u16 = 500;
}

/// Configuration for STUN operations
#[derive(Debug, Clone)]
pub struct StunConfig {
    /// List of STUN server addresses (from IceConfig)
    pub servers: Vec<String>,

    /// Use DTLS for STUN (stuns:// URLs)
    pub use_dtls: bool,

    /// Connection timeout
    pub timeout: Duration,

    /// Maximum retransmissions
    pub max_retransmissions: u32,

    /// Initial RTO in milliseconds
    pub initial_rto_ms: u64,

    /// ICE username fragment for MESSAGE-INTEGRITY
    pub ice_ufrag: Option<String>,

    /// ICE password for MESSAGE-INTEGRITY
    pub ice_pwd: Option<String>,

    /// Fallback to plain requests if MESSAGE-INTEGRITY fails
    pub fallback_on_integrity_failure: bool,

    /// Number of integrity failures before fallback
    pub integrity_failure_threshold: u32,
}

impl Default for StunConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
            ],
            use_dtls: false,
            timeout: Duration::from_secs(10),
            max_retransmissions: constants::MAX_RETRANSMISSIONS,
            initial_rto_ms: constants::INITIAL_RTO_MS,
            ice_ufrag: None,
            ice_pwd: None,
            fallback_on_integrity_failure: true,
            integrity_failure_threshold: 3,
        }
    }
}

/// Result of a single STUN binding request
#[derive(Debug, Clone)]
pub struct BindingResult {
    /// Server that responded
    pub server_addr: SocketAddr,

    /// Our mapped address as seen by the server
    pub mapped_address: SocketAddr,

    /// XOR-MAPPED-ADDRESS (preferred)
    pub xor_mapped_address: Option<SocketAddr>,

    /// Round-trip time for this request
    pub rtt: Duration,

    /// Transaction ID used
    pub transaction_id: TransactionId,

    /// Whether MESSAGE-INTEGRITY was verified
    pub integrity_verified: bool,

    /// Response origin (for RFC 5780)
    pub response_origin: Option<SocketAddr>,

    /// Other address (for RFC 5780)
    pub other_address: Option<SocketAddr>,
}

/// Errors that can occur during STUN operations
#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("Timeout after {retries} retransmissions")]
    Timeout { retries: u32 },

    #[error("Invalid STUN message: {0}")]
    InvalidMessage(String),

    #[error("MESSAGE-INTEGRITY verification failed")]
    IntegrityFailed,

    #[error("STUN error response: {code} {reason}")]
    ErrorResponse { code: u16, reason: String },

    #[error("No STUN servers configured")]
    NoServers,

    #[error("Server does not support required attributes")]
    UnsupportedServer,

    #[error("DTLS connection failed: {0}")]
    DtlsFailed(String),

    #[error("Transaction mismatch")]
    TransactionMismatch,

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Parse STUN server URL into address
pub fn parse_stun_url(url: &str) -> Result<(SocketAddr, bool), StunError> {
    let (scheme, rest) = if url.starts_with("stuns:") {
        (true, url.trim_start_matches("stuns:").trim_start_matches("//"))
    } else if url.starts_with("stun:") {
        (false, url.trim_start_matches("stun:").trim_start_matches("//"))
    } else {
        // Assume plain address
        (false, url)
    };

    let addr: SocketAddr = rest.parse().map_err(|_| {
        // Try adding default port
        let with_port = if scheme {
            format!("{}:{}", rest, constants::DEFAULT_STUNS_PORT)
        } else {
            format!("{}:{}", rest, constants::DEFAULT_STUN_PORT)
        };
        with_port.parse().map_err(|e| StunError::ParseError(format!("Invalid STUN URL '{}': {}", url, e)))
    }).unwrap_or_else(|r: Result<SocketAddr, StunError>| r.unwrap());

    Ok((addr, scheme))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stun_url() {
        // Standard STUN URL
        let (addr, dtls) = parse_stun_url("stun:stun.l.google.com:19302").unwrap();
        assert_eq!(addr.port(), 19302);
        assert!(!dtls);

        // STUNS URL
        let (addr, dtls) = parse_stun_url("stuns:stun.example.com:5349").unwrap();
        assert_eq!(addr.port(), 5349);
        assert!(dtls);
    }

    #[test]
    fn test_default_config() {
        let config = StunConfig::default();
        assert_eq!(config.max_retransmissions, 7);
        assert_eq!(config.initial_rto_ms, 500);
        assert!(config.fallback_on_integrity_failure);
    }
}
