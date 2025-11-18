//! Transport abstraction for various connection methods

use anyhow::Result;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use parking_lot::RwLock;

// Submodules (only existing ones)
pub mod direct;
pub mod relay;
// TODO: Implement hairpin detection
// pub mod hairpin;

// Re-exports
pub use direct::DirectTransport;
pub use relay::RelayTransport;

/// Universal transport trait for all connection types
#[async_trait]
pub trait Transport: Send + Sync + Debug {
    /// Establish connection
    async fn connect(&self, remote_addr: SocketAddr) -> Result<EstablishedConnection>;

    /// Get transport type
    fn transport_type(&self) -> TransportType;

    /// Check if transport is available
    async fn is_available(&self) -> bool;

    /// Get priority (higher is better)
    fn priority(&self) -> u8;
}

/// Transport types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportType {
    /// Direct UDP connection
    Direct,
    /// ICE-established connection
    Ice,
    /// TURN relay connection
    Relay,
    /// UPnP port forwarding
    Upnp,
    /// Hairpin NAT loopback
    Hairpin,
}

/// Established connection
#[derive(Debug, Clone)]
pub struct EstablishedConnection {
    /// Local address
    pub local_addr: SocketAddr,
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Transport type used
    pub transport_type: TransportType,
    /// Connection quality metrics
    pub metrics: ConnectionMetrics,
    /// Established timestamp
    pub established_at: Instant,
}

impl EstablishedConnection {
    /// Create new connection
    pub fn new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        transport_type: TransportType,
    ) -> Self {
        Self {
            local_addr,
            remote_addr,
            transport_type,
            metrics: ConnectionMetrics::default(),
            established_at: Instant::now(),
        }
    }

    /// Get connection age
    pub fn age(&self) -> Duration {
        self.established_at.elapsed()
    }

    /// Check if connection is healthy
    pub fn is_healthy(&self) -> bool {
        self.metrics.packet_loss < 0.05 && // < 5% loss
        self.metrics.rtt < Duration::from_millis(500)
    }
}

/// Connection quality metrics
#[derive(Debug, Clone, Default)]
pub struct ConnectionMetrics {
    /// Round-trip time
    pub rtt: Duration,
    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss: f64,
    /// Bandwidth estimate (bytes/sec)
    pub bandwidth: u64,
    /// Jitter
    pub jitter: Duration,
}

impl ConnectionMetrics {
    /// Calculate connection score (0.0 - 1.0)
    pub fn score(&self) -> f64 {
        let rtt_score = 1.0 - (self.rtt.as_millis() as f64 / 1000.0).min(1.0);
        let loss_score = 1.0 - self.packet_loss;
        let jitter_score = 1.0 - (self.jitter.as_millis() as f64 / 100.0).min(1.0);

        (rtt_score + loss_score + jitter_score) / 3.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_metrics_score() {
        let mut metrics = ConnectionMetrics::default();
        metrics.rtt = Duration::from_millis(50);
        metrics.packet_loss = 0.01;
        metrics.jitter = Duration::from_millis(10);

        let score = metrics.score();
        assert!(score > 0.9, "Good connection should have high score");
    }

    #[test]
    fn test_established_connection() {
        let conn = EstablishedConnection::new(
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:6000".parse().unwrap(),
            TransportType::Direct,
        );

        assert_eq!(conn.transport_type, TransportType::Direct);
        assert!(conn.age() < Duration::from_secs(1));
    }
}
