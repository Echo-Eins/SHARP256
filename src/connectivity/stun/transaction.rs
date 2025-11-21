// src/connectivity/stun/transaction.rs
//! STUN Transaction ID Tracking and RTT Measurement
//!
//! RFC 8489 Section 6: Transaction ID is a 96-bit identifier
//! used to uniquely identify STUN transactions.

use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Transaction ID (96 bits / 12 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId([u8; 12]);

impl TransactionId {
    /// Generate a random transaction ID
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 12];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Get as byte slice
    pub fn as_bytes(&self) -> [u8; 12] {
        self.0
    }

    /// Get as hex string for logging
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::fmt::Display for TransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Result of a completed transaction
#[derive(Debug, Clone)]
pub struct TransactionResult {
    /// Transaction ID
    pub transaction_id: TransactionId,

    /// Request sent timestamp
    pub sent_at: Instant,

    /// Response received timestamp
    pub received_at: Instant,

    /// Round-trip time
    pub rtt: Duration,

    /// Number of retransmissions before success
    pub retransmissions: u32,

    /// Response data
    pub response: Vec<u8>,
}

/// Pending transaction state
#[derive(Debug)]
struct PendingTransaction {
    /// When the request was first sent
    sent_at: Instant,

    /// When the last retransmission was sent
    last_sent: Instant,

    /// Number of retransmissions
    retransmissions: u32,

    /// Original request data
    request: Vec<u8>,

    /// Destination address
    destination: std::net::SocketAddr,
}

/// Transaction tracker for managing pending STUN transactions
#[derive(Debug)]
pub struct TransactionTracker {
    /// Pending transactions keyed by transaction ID
    pending: Arc<RwLock<HashMap<TransactionId, PendingTransaction>>>,

    /// Completed transactions (for statistics)
    completed: Arc<RwLock<Vec<TransactionResult>>>,

    /// RTT statistics
    stats: Arc<RwLock<RttStats>>,
}

/// RTT statistics
#[derive(Debug, Default, Clone)]
pub struct RttStats {
    /// Minimum RTT observed
    pub min_rtt: Option<Duration>,

    /// Maximum RTT observed
    pub max_rtt: Option<Duration>,

    /// Sum of all RTTs (for average calculation)
    pub total_rtt: Duration,

    /// Number of successful transactions
    pub count: u64,

    /// Number of failed transactions (timeouts)
    pub failures: u64,

    /// Total retransmissions
    pub total_retransmissions: u64,
}

impl RttStats {
    /// Get average RTT
    pub fn average_rtt(&self) -> Option<Duration> {
        if self.count > 0 {
            Some(self.total_rtt / self.count as u32)
        } else {
            None
        }
    }

    /// Update stats with new RTT measurement
    pub fn update(&mut self, rtt: Duration, retransmissions: u32) {
        self.min_rtt = Some(self.min_rtt.map_or(rtt, |min| min.min(rtt)));
        self.max_rtt = Some(self.max_rtt.map_or(rtt, |max| max.max(rtt)));
        self.total_rtt += rtt;
        self.count += 1;
        self.total_retransmissions += retransmissions as u64;
    }

    /// Record a failure
    pub fn record_failure(&mut self) {
        self.failures += 1;
    }
}

impl TransactionTracker {
    /// Create a new transaction tracker
    pub fn new() -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            completed: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(RttStats::default())),
        }
    }

    /// Register a new transaction
    pub async fn register(
        &self,
        transaction_id: TransactionId,
        request: Vec<u8>,
        destination: std::net::SocketAddr,
    ) {
        let now = Instant::now();
        let pending = PendingTransaction {
            sent_at: now,
            last_sent: now,
            retransmissions: 0,
            request,
            destination,
        };

        self.pending.write().await.insert(transaction_id, pending);
    }

    /// Record a retransmission for a transaction
    pub async fn record_retransmission(&self, transaction_id: &TransactionId) -> Option<u32> {
        let mut pending = self.pending.write().await;
        if let Some(tx) = pending.get_mut(transaction_id) {
            tx.retransmissions += 1;
            tx.last_sent = Instant::now();
            Some(tx.retransmissions)
        } else {
            None
        }
    }

    /// Complete a transaction with response
    pub async fn complete(
        &self,
        transaction_id: TransactionId,
        response: Vec<u8>,
    ) -> Option<TransactionResult> {
        let received_at = Instant::now();

        let mut pending = self.pending.write().await;
        let tx = pending.remove(&transaction_id)?;

        let rtt = received_at - tx.sent_at;
        let result = TransactionResult {
            transaction_id,
            sent_at: tx.sent_at,
            received_at,
            rtt,
            retransmissions: tx.retransmissions,
            response,
        };

        // Update statistics
        self.stats.write().await.update(rtt, tx.retransmissions);

        // Store completed transaction
        self.completed.write().await.push(result.clone());

        Some(result)
    }

    /// Mark a transaction as failed (timeout)
    pub async fn fail(&self, transaction_id: &TransactionId) -> bool {
        let removed = self.pending.write().await.remove(transaction_id).is_some();
        if removed {
            self.stats.write().await.record_failure();
        }
        removed
    }

    /// Check if a transaction is pending
    pub async fn is_pending(&self, transaction_id: &TransactionId) -> bool {
        self.pending.read().await.contains_key(transaction_id)
    }

    /// Get pending transaction info
    pub async fn get_pending(
        &self,
        transaction_id: &TransactionId,
    ) -> Option<(Vec<u8>, std::net::SocketAddr, u32)> {
        let pending = self.pending.read().await;
        pending
            .get(transaction_id)
            .map(|tx| (tx.request.clone(), tx.destination, tx.retransmissions))
    }

    /// Get all pending transaction IDs
    pub async fn get_pending_ids(&self) -> Vec<TransactionId> {
        self.pending.read().await.keys().copied().collect()
    }

    /// Get RTT statistics
    pub async fn get_stats(&self) -> RttStats {
        self.stats.read().await.clone()
    }

    /// Get the latest RTT measurement
    pub async fn get_latest_rtt(&self) -> Option<Duration> {
        self.completed.read().await.last().map(|r| r.rtt)
    }

    /// Clear all pending transactions
    pub async fn clear_pending(&self) {
        self.pending.write().await.clear();
    }

    /// Get number of pending transactions
    pub async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }
}

impl Default for TransactionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_transaction_id_generation() {
        let id1 = TransactionId::generate();
        let id2 = TransactionId::generate();

        // Should be different
        assert_ne!(id1, id2);

        // Should be 12 bytes
        assert_eq!(id1.as_bytes().len(), 12);
    }

    #[test]
    fn test_transaction_id_hex() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        ];
        let id = TransactionId::from_bytes(bytes);
        assert_eq!(id.to_hex(), "0123456789abcdef01234567");
    }

    #[tokio::test]
    async fn test_transaction_tracker() {
        let tracker = TransactionTracker::new();
        let id = TransactionId::generate();
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 3478);

        // Register transaction
        tracker.register(id, vec![1, 2, 3], dest).await;
        assert!(tracker.is_pending(&id).await);

        // Complete transaction
        let result = tracker.complete(id, vec![4, 5, 6]).await;
        assert!(result.is_some());
        assert!(!tracker.is_pending(&id).await);

        // Check stats
        let stats = tracker.get_stats().await;
        assert_eq!(stats.count, 1);
        assert!(stats.average_rtt().is_some());
    }

    #[tokio::test]
    async fn test_retransmission_tracking() {
        let tracker = TransactionTracker::new();
        let id = TransactionId::generate();
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 3478);

        tracker.register(id, vec![1, 2, 3], dest).await;

        // Record retransmissions
        let count = tracker.record_retransmission(&id).await;
        assert_eq!(count, Some(1));

        let count = tracker.record_retransmission(&id).await;
        assert_eq!(count, Some(2));

        // Complete and check retransmission count
        let result = tracker.complete(id, vec![4, 5, 6]).await.unwrap();
        assert_eq!(result.retransmissions, 2);
    }

    #[test]
    fn test_rtt_stats() {
        let mut stats = RttStats::default();

        stats.update(Duration::from_millis(100), 0);
        stats.update(Duration::from_millis(200), 1);
        stats.update(Duration::from_millis(150), 0);

        assert_eq!(stats.min_rtt, Some(Duration::from_millis(100)));
        assert_eq!(stats.max_rtt, Some(Duration::from_millis(200)));
        assert_eq!(stats.count, 3);
        assert_eq!(stats.total_retransmissions, 1);
        assert_eq!(stats.average_rtt(), Some(Duration::from_millis(150)));
    }
}
