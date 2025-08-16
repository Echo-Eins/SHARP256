// src/nat/error.rs
//! Error types for NAT traversal operations

use std::net::SocketAddr;
use std::time::Duration;
use std::io;
use thiserror::Error;
use serde_json;

/// Result type for NAT operations
pub type NatResult<T> = Result<T, NatError>;

/// Main NAT error type
#[derive(Error, Debug)]
pub enum NatError {
    /// STUN-specific errors
    #[error("STUN error: {0}")]
    Stun(#[from] StunError),

    /// TURN-specific errors
    #[error("TURN error: {0}")]
    Turn(#[from] TurnError),

    /// UPnP errors
    #[error("UPnP error: {0}")]
    Upnp(String),

    /// NAT-PMP errors
    #[error("NAT-PMP error: {0}")]
    NatPmp(#[from] NatPmpError),

    /// PCP errors
    #[error("PCP error: {0}")]
    Pcp(#[from] PcpError),

    /// Network I/O errors
    #[error("Network error: {0}")]
    Network(#[from] io::Error),

    /// Timeout errors
    #[error("Operation timed out after {0:?}")]
    Timeout(Duration),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Platform-specific errors
    #[error("Platform error: {0}")]
    Platform(String),

    /// Feature not supported
    #[error("Feature not supported: {0}")]
    NotSupported(String),


    /// Transient errors that may succeed on retry
    #[error("Transient error: {0}")]
    Transient(String),

    /// Permanent errors that should not be retried
    #[error("Permanent error: {0}")]
    Permanent(String),

    /// Circuit breaker opened for specific resource
    #[error("Circuit breaker open for {0}")]
    CircuitBreakerOpen(String),

    /// All available methods failed
    #[error("All NAT traversal methods failed")]
    AllMethodsFailed,
}

impl From<tokio::time::error::Elapsed> for NatError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        NatError::Timeout(Duration::from_secs(0))
    }
}

impl From<serde_json::Error> for NatError {
    fn from(err: serde_json::Error) -> Self {
        NatError::Platform(err.to_string())
    }
}

/// STUN-specific error types
#[derive(Error, Debug)]
pub enum StunError {
    /// Invalid magic cookie in STUN message
    #[error("Invalid magic cookie: 0x{0:08X}")]
    InvalidMagicCookie(u32),

    /// Transaction ID mismatch
    #[error("Transaction ID mismatch")]
    TransactionIdMismatch,

    /// Invalid address family
    #[error("Invalid address family: {0}")]
    InvalidAddressFamily(u8),

    /// Parse error
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Missing required attribute
    #[error("Missing required attribute: {0}")]
    MissingAttribute(String),

    /// Attribute parsing error
    #[error("Failed to parse attribute {attr_type:#06X}: {reason}")]
    AttributeParseError {
        attr_type: u16,
        reason: String,
    },

    /// Authentication error
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Nonce expired
    #[error("Nonce has expired")]
    NonceExpired,

    /// Integrity check failed
    #[error("MESSAGE-INTEGRITY verification failed")]
    IntegrityCheckFailed,

    /// Fingerprint check failed
    #[error("FINGERPRINT verification failed")]
    FingerprintCheckFailed,

    /// Unknown comprehension-required attributes
    #[error("Unknown comprehension-required attributes: {0:?}")]
    UnknownComprehensionRequired(Vec<u16>),

    /// Server returned error response
    #[error("Server error {code}: {reason}")]
    ErrorResponse {
        code: u16,
        reason: String,
    },

    /// No response from server
    #[error("No response from server {0}")]
    NoResponse(SocketAddr),

    /// All servers failed
    #[error("All STUN servers failed")]
    AllServersFailed,

    /// Invalid message type
    #[error("Invalid message type")]
    InvalidMessageType,
}

/// TURN-specific error types
#[derive(Error, Debug)]
pub enum TurnError {
    /// Allocation failed
    #[error("Failed to allocate relay: {0}")]
    AllocationFailed(String),

    /// Permission denied
    #[error("Permission denied for peer {0}")]
    PermissionDenied(SocketAddr),

    /// Channel bind failed
    #[error("Failed to bind channel {0}")]
    ChannelBindFailed(u16),

    /// Quota exceeded
    #[error("Allocation quota exceeded")]
    QuotaExceeded,

    /// Relay not found
    #[error("Relay allocation not found")]
    RelayNotFound,

    /// Invalid channel number
    #[error("Invalid channel number: {0}")]
    InvalidChannel(u16),

    /// Lifetime expired
    #[error("Allocation lifetime expired")]
    LifetimeExpired,
}

/// NAT-PMP specific errors (RFC 6886)
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NatPmpError {
    #[error("Unsupported Version (1)")]
    UnsupportedVersion = 1,
    #[error("Not Authorized/Refused (2)")]
    NotAuthorized = 2,
    #[error("Network Failure (3)")]
    NetworkFailure = 3,
    #[error("Out of Resources (4)")]
    OutOfResources = 4,
    #[error("Unsupported Opcode (5)")]
    UnsupportedOpcode = 5,
    #[error("Unknown Error ({0})")]
    Unknown(u16) = 0xFFFF,
    #[error("Invalid response: {0}")]
    InvalidResponse(&'static str) = 0,
}

impl NatPmpError {
    /// Convert NAT-PMP result code to error
    pub fn from_code(code: u16) -> Self {
        match code {
            1 => NatPmpError::UnsupportedVersion,
            2 => NatPmpError::NotAuthorized,
            3 => NatPmpError::NetworkFailure,
            4 => NatPmpError::OutOfResources,
            5 => NatPmpError::UnsupportedOpcode,
            c => NatPmpError::Unknown(c),
        }
    }
}

/// PCP specific errors (RFC 6887)
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PcpError {
    #[error("UNSUPP_VERSION (1)")]
    UnsupportedVersion = 1,
    #[error("NOT_AUTHORIZED (2)")]
    NotAuthorized = 2,
    #[error("MALFORMED_REQUEST (3)")]
    MalformedRequest = 3,
    #[error("UNSUPP_OPCODE (4)")]
    UnsupportedOpcode = 4,
    #[error("UNSUPP_OPTION (5)")]
    UnsupportedOption = 5,
    #[error("MALFORMED_OPTION (6)")]
    MalformedOption = 6,
    #[error("NETWORK_FAILURE (7)")]
    NetworkFailure = 7,
    #[error("NO_RESOURCES (8)")]
    NoResources = 8,
    #[error("UNSUPP_PROTOCOL (9)")]
    UnsupportedProtocol = 9,
    #[error("USER_EX_QUOTA (10)")]
    UserExQuota = 10,
    #[error("CANNOT_PROVIDE_EXTERNAL (11)")]
    CannotProvideExternal = 11,
    #[error("ADDRESS_MISMATCH (12)")]
    AddressMismatch = 12,
    #[error("EXCESSIVE_REMOTE_PEERS (13)")]
    ExcessiveRemotePeers = 13,
    #[error("Unknown Error ({0})")]
    Unknown(u8) = 0xFF,
    #[error("Invalid response: {0}")]
    InvalidResponse(&'static str) = 0,
}

impl PcpError {
    /// Convert PCP result code to error
    pub fn from_code(code: u8) -> Self {
        match code {
            1 => PcpError::UnsupportedVersion,
            2 => PcpError::NotAuthorized,
            3 => PcpError::MalformedRequest,
            4 => PcpError::UnsupportedOpcode,
            5 => PcpError::UnsupportedOption,
            6 => PcpError::MalformedOption,
            7 => PcpError::NetworkFailure,
            8 => PcpError::NoResources,
            9 => PcpError::UnsupportedProtocol,
            10 => PcpError::UserExQuota,
            11 => PcpError::CannotProvideExternal,
            12 => PcpError::AddressMismatch,
            13 => PcpError::ExcessiveRemotePeers,
            c => PcpError::Unknown(c),
        }
    }
}


impl NatError {
    /// Check if the error is transient and a retry may succeed
    pub fn is_transient(&self) -> bool {
        matches!(self,
            NatError::Transient(_) | NatError::Timeout(_) | NatError::Network(_)
        )
    }

    /// Helper to create a transient error
    pub fn transient(msg: impl Into<String>) -> Self {
        NatError::Transient(msg.into())
    }

    /// Helper to create a permanent error
    pub fn permanent(msg: impl Into<String>) -> Self {
        NatError::Permanent(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_conversion() {
        let stun_err = StunError::InvalidMagicCookie(0x12345678);
        let nat_err: NatError = stun_err.into();

        match nat_err {
            NatError::Stun(StunError::InvalidMagicCookie(cookie)) => {
                assert_eq!(cookie, 0x12345678);
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_error_display() {
        let err = StunError::ErrorResponse {
            code: 401,
            reason: "Unauthorized".to_string(),
        };

        assert_eq!(err.to_string(), "Server error 401: Unauthorized");
    }
}