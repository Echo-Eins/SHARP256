/// RFC 8489 compliant STUN implementation
/// 
/// This module provides a complete STUN (Session Traversal Utilities for NAT)
/// implementation following RFC 8489 with support for:
/// - MESSAGE-INTEGRITY-SHA256 authentication
/// - IPv6/IPv4 dual-stack
/// - NAT behavior discovery (RFC 5780)
/// - Comprehensive error handling and retry logic

pub mod protocol;
pub mod client;
pub mod auth;
pub mod discovery;

// Re-export commonly used types
pub use protocol::{
    Message, MessageType, MessageClass, 
    Attribute, AttributeType, AttributeValue,
    TransactionId, MAGIC_COOKIE
};

pub use client::{StunClient, StunConfig, StunServerInfo};
pub use discovery::{NatBehavior, MappingBehavior, FilteringBehavior};
pub use auth::{Credentials, CredentialType};

use crate::nat::error::NatResult;
use std::net::SocketAddr;

/// Quick helper to get mapped address from a STUN server
pub async fn get_mapped_address(
    socket: &tokio::net::UdpSocket,
    stun_server: &str,
) -> NatResult<SocketAddr> {
    let config = StunConfig::default();
    let client = StunClient::new(config);
    
    client.get_mapped_address(socket, stun_server).await
}

/// Quick helper to detect NAT type
pub async fn detect_nat_type(
    socket: &tokio::net::UdpSocket,
) -> NatResult<crate::nat::NatType> {
    let config = StunConfig::default();
    let client = StunClient::new(config);
    
    let behavior = client.detect_nat_behavior(socket).await?;
    
    // Map detailed behavior to simple NAT type
    Ok(behavior.to_simple_nat_type())
}