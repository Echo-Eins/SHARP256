// src/nat/turn/mod.rs
//! TURN (Traversal Using Relays around NAT) implementation
//!
//! This module provides a complete TURN relay implementation with:
//! - RFC 8656 compliant TURN protocol
//! - SHARP protocol extensions for P2P connectivity
//! - High-performance server with memory pools
//! - Quantum-resistant cryptography support
//! - Comprehensive monitoring and statistics

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

use crate::nat::error::{NatError, NatResult};

// MAIN MODULE: настоящий TURN сервер
pub mod server;

// Use STUN components from the NAT module
use crate::nat::stun::{protocol, client, auth};


// Re-export main types from server module
pub use server::{
    TurnServer,
    TurnServerConfig,
    AuthConfig,
    TransportProtocol,
    // Статистика и мониторинг
    ServerStatistics,
    AllocationStats,
    // Конфигурации
    SharpConfig,
    PerformanceConfig,
    MonitoringConfig,
    // Пулы памяти
    PacketPool,
    AllocationPool,
};

// Re-export client types
pub use client::{
    TurnClient,
    TurnClientConfig,
    ClientConnectionState,
};

// Re-export protocol types
pub use protocol::{
    TurnMessage,
    TurnMessageType,
    TurnAttribute,
    AttributeType,
    StunMagicCookie,
    // SHARP protocol extensions
    SharpHeader,
    HandshakeInitMessage,
    HandshakeResponseMessage,
};

// Re-export auth types
pub use auth::{
    AuthManager,
    UserCredentials,
    NonceManager,
    LongTermCredentialMechanism,
};


/// TURN credentials for client authentication
#[derive(Debug, Clone)]
pub struct TurnCredentials {
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
}

/// Basic client allocation info (simplified)
#[derive(Debug, Clone)]
pub struct TurnAllocation {
    pub relay_address: SocketAddr,
    pub allocated_at: Instant,
    pub expires_at: Instant,
}

/// Create a default TURN server configuration
pub fn create_default_config(bind_addr: &str, external_addr: &str) -> NatResult<TurnServerConfig> {
    let bind_address = bind_addr.parse()
        .map_err(|e| NatError::Configuration(format!("Invalid bind address: {}", e)))?;

    let external_address = if external_addr.is_empty() {
        None
    } else {
        Some(external_addr.parse()
            .map_err(|e| NatError::Configuration(format!("Invalid external address: {}", e)))?)
    };

    Ok(TurnServerConfig {
        // Basic settings
        bind_address,
        external_address,
        realm: "sharp3.local".to_string(),

        // Authentication
        auth_config: AuthConfig::Static {
            users: HashMap::new(),
        },

        // Allocation management
        allocation_lifetime: Duration::from_secs(600),
        max_allocations: 1000,
        allocation_cleanup_interval: Duration::from_secs(60),

        // Transport settings
        enable_tcp: false,
        enable_tls: false,
        enable_dtls: false,
        cert_path: None,
        key_path: None,

        // SHARP protocol settings
        sharp_config: SharpConfig::default(),

        // Performance settings
        performance_config: PerformanceConfig::default(),

        // Monitoring settings
        monitoring_config: MonitoringConfig::default(),

        // Security settings
        enable_fingerprinting: true,
        software_name: Some("SHARP TURN Server/1.0".to_string()),

        // Rate limiting
        max_requests_per_minute: 60,
        max_allocations_per_client: 10,

        // Bandwidth management
        bandwidth_limits: Default::default(),

        // Additional settings
        nonce_expiry: Duration::from_secs(600),
        thread_pool_size: num_cpus::get(),
        packet_pool_size: 1000,
        allocation_pool_size: 100,
    })
}

/// Create basic TURN credentials for testing
pub fn create_test_credentials() -> TurnCredentials {
    TurnCredentials {
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        realm: Some("sharp3.local".to_string()),
    }
}

/// Validate TURN server configuration
pub fn validate_turn_config(config: &TurnServerConfig) -> NatResult<()> {
    // Validate addresses
    if config.bind_address.port() == 0 {
        return Err(NatError::Configuration("Bind address must have a valid port".to_string()));
    }

    // Validate allocation settings
    if config.allocation_lifetime < Duration::from_secs(30) {
        return Err(NatError::Configuration("Allocation lifetime too short (minimum 30 seconds)".to_string()));
    }

    if config.max_allocations == 0 {
        return Err(NatError::Configuration("Max allocations must be greater than 0".to_string()));
    }

    // Validate auth config
    match &config.auth_config {
        AuthConfig::Static { users } => {
            if users.is_empty() {
                tracing::warn!("No users configured for static authentication");
            }
        }
        AuthConfig::External { endpoint, .. } => {
            if endpoint.is_empty() {
                return Err(NatError::Configuration("External auth endpoint cannot be empty".to_string()));
            }
        }
        AuthConfig::Disabled => {
            tracing::warn!("Authentication disabled - use only for testing");
        }
    }

    // Validate TLS configuration
    if config.enable_tls {
        if config.cert_path.is_none() || config.key_path.is_none() {
            return Err(NatError::Configuration("TLS enabled but certificate or key path not specified".to_string()));
        }
    }

    Ok(())
}

// Utility functions for direct usage (без менеджеров)
/// Create and start a basic TURN server
pub async fn create_turn_server(config: TurnServerConfig) -> NatResult<TurnServer> {
    validate_turn_config(&config)?;
    TurnServer::new(config).await
}

/// Create a TURN client for specific server
pub async fn create_turn_client(server_url: &str) -> NatResult<TurnClient> {
    TurnClient::new(server_url).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_turn_server_creation() {
        let config = create_default_config("0.0.0.0:3478", "203.0.113.1").unwrap();
        let server = create_turn_server(config).await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_turn_client_creation() {
        let client = create_turn_client("turn:example.com:3478").await;
        assert!(client.is_ok());
    }

    #[test]
    fn test_config_validation() {
        let valid_config = create_default_config("0.0.0.0:3478", "203.0.113.1").unwrap();
        assert!(validate_turn_config(&valid_config).is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.allocation_lifetime = Duration::from_secs(10); // Too short
        assert!(validate_turn_config(&invalid_config).is_err());
    }

    #[test]
    fn test_credentials_creation() {
        let creds = create_test_credentials();
        assert_eq!(creds.username, "testuser");
        assert_eq!(creds.password, "testpass");
        assert!(creds.realm.is_some());
    }
}