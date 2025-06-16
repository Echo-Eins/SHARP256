// src/nat/stun/mod.rs
//! STUN (Session Traversal Utilities for NAT) implementation
//!
//! Fully compliant with RFC 8489 and RFC 5780 for NAT traversal
//! and behavior discovery.

mod protocol;
mod client;
mod auth;
mod discovery;

pub use protocol::{
    Message, MessageType, MessageClass, TransactionId,
    Attribute, AttributeType, AttributeValue,
    MAGIC_COOKIE, HEADER_SIZE, MAX_MESSAGE_SIZE,
    PasswordAlgorithm, PasswordAlgorithmParams,
};

pub use client::{
    StunClient, StunConfig, StunServerInfo,
};

pub use auth::{
    Credentials, CredentialType, SecurityFeatures, NonceCookie,
    compute_message_integrity_sha256, verify_message_integrity_sha256,
};

pub use discovery::{
    NatBehavior, NatBehaviorDiscovery,
    MappingBehavior, FilteringBehavior,
};

use std::net::SocketAddr;
use tokio::net::UdpSocket;
use crate::nat::{NatType, error::NatResult};

/// High-level STUN interface for NAT traversal
pub struct StunService {
    client: StunClient,
}

impl StunService {
    /// Create new STUN service with default configuration
    pub fn new() -> Self {
        Self {
            client: StunClient::new(StunConfig::default()),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: StunConfig) -> Self {
        Self {
            client: StunClient::new(config),
        }
    }

    /// Get public address via STUN
    pub async fn get_public_address(&self, socket: &UdpSocket) -> NatResult<SocketAddr> {
        self.client.get_mapped_address(socket).await
    }

    /// Detect NAT type and behavior
    pub async fn detect_nat_type(&self, socket: &UdpSocket) -> NatResult<(NatType, NatBehavior)> {
        let behavior = self.client.detect_nat_behavior(socket).await?;
        let nat_type = behavior.to_simple_nat_type();
        Ok((nat_type, behavior))
    }

    /// Check if P2P connection is feasible
    pub async fn check_p2p_feasibility(&self, socket: &UdpSocket) -> NatResult<f64> {
        let behavior = self.client.detect_nat_behavior(socket).await?;
        Ok(behavior.p2p_score())
    }

    /// Get multiple public addresses for redundancy
    pub async fn get_all_public_addresses(&self, socket: &UdpSocket) -> NatResult<Vec<SocketAddr>> {
        let behavior = self.client.detect_nat_behavior(socket).await?;
        Ok(behavior.public_addresses)
    }
}

impl Default for StunService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stun_service() {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let service = StunService::new();

        // This test requires network access
        match service.get_public_address(&socket).await {
            Ok(addr) => {
                println!("Public address: {}", addr);
                assert!(!addr.ip().is_loopback());
            }
            Err(e) => {
                eprintln!("STUN test failed (may be offline): {}", e);
            }
        }
    }
}