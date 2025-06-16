// src/nat/error.rs
//! Error types for NAT traversal operations

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;
use std::io;
use thiserror::Error;

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
    NatPmp(String),

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

impl From<StunError> for NatError {
    fn from(err: StunError) -> Self {
        NatError::Stun(err)
    }
}

impl From<TurnError> for NatError {
    fn from(err: TurnError) -> Self {
        NatError::Turn(err)
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