// src/nat/metrics.rs
//! Metrics collection for NAT traversal operations

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use std::collections::HashMap;

/// Global metrics instance
static METRICS:once_cell::sync::Lazy<Arc<NatMetricsCollector>> =
    once_cell::sync::Lazy::new(|| Arc::new(NatMetricsCollector::new()));

/// NAT traversal metrics collector
pub struct NatMetricsCollector {
    /// STUN metrics by server
    stun_metrics: RwLock<HashMap<String, StunServerMetrics>>,

    /// TURN metrics by server
    turn_metrics: RwLock<HashMap<String, TurnServerMetrics>>,

    /// NAT type detection results
    nat_type_detections: RwLock<HashMap<String, AtomicUsize>>,

    /// IP version usage
    ip_version_usage: RwLock<HashMap<String, AtomicUsize>>,

    /// Overall success rates
    overall_success: AtomicU64,
    overall_attempts: AtomicU64,
}

/// Metrics for individual STUN server
#[derive(Debug)]
pub struct StunServerMetrics {
    /// Total requests sent
    pub requests: AtomicUsize,

    /// Successful responses
    pub successes: AtomicUsize,

    /// Failed requests
    pub failures: AtomicUsize,

    /// Average response time in milliseconds
    pub avg_response_time_ms: AtomicU64,

    /// Total response time for averaging
    total_response_time_ms: AtomicU64,

    /// Number of responses for averaging
    response_count: AtomicUsize,
}

/// Metrics for individual TURN server
#[derive(Debug)]
pub struct TurnServerMetrics {
    /// Active allocations
    pub active_allocations: AtomicUsize,

    /// Total allocations created
    pub total_allocations: AtomicUsize,

    /// Failed allocations
    pub failed_allocations: AtomicUsize,

    /// Total data relayed (bytes)
    pub bytes_relayed: AtomicU64,

    /// Average allocation lifetime (seconds)
    pub avg_lifetime_seconds: AtomicU64,
}

impl NatMetricsCollector {
    fn new() -> Self {
        Self {
            stun_metrics: RwLock::new(HashMap::new()),
            turn_metrics: RwLock::new(HashMap::new()),
            nat_type_detections: RwLock::new(HashMap::new()),
            ip_version_usage: RwLock::new(HashMap::new()),
            overall_success: AtomicU64::new(0),
            overall_attempts: AtomicU64::new(0),
        }
    }

    /// Get global metrics instance
    pub fn global() -> Arc<Self> {
        METRICS.clone()
    }

    /// Record STUN request
    pub fn record_stun_request(&self, server: &str) {
        let mut metrics = self.stun_metrics.write();
        let server_metrics = metrics.entry(server.to_string())
            .or_insert_with(|| StunServerMetrics::new());

        server_metrics.requests.fetch_add(1, Ordering::Relaxed);
        self.overall_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record STUN response
    pub fn record_stun_response(&self, server: &str, success: bool, response_time: Duration) {
        let mut metrics = self.stun_metrics.write();
        let server_metrics = metrics.entry(server.to_string())
            .or_insert_with(|| StunServerMetrics::new());

        if success {
            server_metrics.successes.fetch_add(1, Ordering::Relaxed);
            self.overall_success.fetch_add(1, Ordering::Relaxed);

            // Update response time
            let ms = response_time.as_millis() as u64;
            server_metrics.total_response_time_ms.fetch_add(ms, Ordering::Relaxed);
            let count = server_metrics.response_count.fetch_add(1, Ordering::Relaxed) + 1;
            let total = server_metrics.total_response_time_ms.load(Ordering::Relaxed);
            server_metrics.avg_response_time_ms.store(total / count as u64, Ordering::Relaxed);
        } else {
            server_metrics.failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record NAT type detection
    pub fn record_nat_type(&self, nat_type: &str, confidence: &str) {
        let key = format!("{}_{}", nat_type, confidence);
        let mut detections = self.nat_type_detections.write();
        detections.entry(key)
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record IP version usage
    pub fn record_ip_version(&self, version: &str, context: &str) {
        let key = format!("{}_{}", version, context);
        let mut usage = self.ip_version_usage.write();
        usage.entry(key)
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get overall success rate
    pub fn success_rate(&self) -> f64 {
        let attempts = self.overall_attempts.load(Ordering::Relaxed);
        if attempts == 0 {
            return 0.0;
        }

        let successes = self.overall_success.load(Ordering::Relaxed);
        successes as f64 / attempts as f64
    }

    /// Get metrics summary
    pub fn summary(&self) -> MetricsSummary {
        let stun_metrics = self.stun_metrics.read();
        let turn_metrics = self.turn_metrics.read();
        let nat_types = self.nat_type_detections.read();
        let ip_usage = self.ip_version_usage.read();

        // Calculate best STUN server
        let best_stun_server = stun_metrics.iter()
            .max_by_key(|(_, m)| m.successes.load(Ordering::Relaxed))
            .map(|(s, _)| s.clone());

        // Calculate most common NAT type
        let most_common_nat_type = nat_types.iter()
            .max_by_key(|(_, count)| count.load(Ordering::Relaxed))
            .map(|(t, _)| t.clone());

        MetricsSummary {
            overall_success_rate: self.success_rate(),
            total_stun_servers: stun_metrics.len(),
            total_turn_servers: turn_metrics.len(),
            best_stun_server,
            most_common_nat_type,
            ipv4_usage: ip_usage.iter()
                .filter(|(k, _)| k.starts_with("ipv4"))
                .map(|(_, v)| v.load(Ordering::Relaxed))
                .sum(),
            ipv6_usage: ip_usage.iter()
                .filter(|(k, _)| k.starts_with("ipv6"))
                .map(|(_, v)| v.load(Ordering::Relaxed))
                .sum(),
        }
    }
}

impl StunServerMetrics {
    fn new() -> Self {
        Self {
            requests: AtomicUsize::new(0),
            successes: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
            avg_response_time_ms: AtomicU64::new(0),
            total_response_time_ms: AtomicU64::new(0),
            response_count: AtomicUsize::new(0),
        }
    }

    /// Get success rate for this server
    pub fn success_rate(&self) -> f64 {
        let requests = self.requests.load(Ordering::Relaxed);
        if requests == 0 {
            return 0.0;
        }

        let successes = self.successes.load(Ordering::Relaxed);
        successes as f64 / requests as f64
    }
}

impl TurnServerMetrics {
    fn new() -> Self {
        Self {
            active_allocations: AtomicUsize::new(0),
            total_allocations: AtomicUsize::new(0),
            failed_allocations: AtomicUsize::new(0),
            bytes_relayed: AtomicU64::new(0),
            avg_lifetime_seconds: AtomicU64::new(0),
        }
    }
}

/// Summary of all metrics
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub overall_success_rate: f64,
    pub total_stun_servers: usize,
    pub total_turn_servers: usize,
    pub best_stun_server: Option<String>,
    pub most_common_nat_type: Option<String>,
    pub ipv4_usage: usize,
    pub ipv6_usage: usize,
}

/// Per-request STUN metrics
pub struct StunMetrics {
    server: String,
    start_time: Instant,
}

impl StunMetrics {
    pub fn new(server: String) -> Self {
        NatMetricsCollector::global().record_stun_request(&server);
        Self {
            server,
            start_time: Instant::now(),
        }
    }

    pub fn record_response(&self, success: bool) {
        let elapsed = self.start_time.elapsed();
        NatMetricsCollector::global().record_stun_response(&self.server, success, elapsed);
    }
}

// Convenience functions

/// Record NAT type detection result
pub fn record_nat_type_detection(nat_type: &str, confidence: &str) {
    NatMetricsCollector::global().record_nat_type(nat_type, confidence);
}

/// Record IP version usage
pub fn record_ip_version_usage(version: &str, context: &str) {
    NatMetricsCollector::global().record_ip_version(version, context);
}

/// Get metrics summary
pub fn get_metrics_summary() -> MetricsSummary {
    NatMetricsCollector::global().summary()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collection() {
        let collector = NatMetricsCollector::new();

        // Record some STUN metrics
        collector.record_stun_request("stun.example.com");
        collector.record_stun_response("stun.example.com", true, Duration::from_millis(50));
        collector.record_stun_response("stun.example.com", true, Duration::from_millis(100));
        collector.record_stun_response("stun.example.com", false, Duration::from_millis(0));

        // Check metrics
        let metrics = collector.stun_metrics.read();
        let server_metrics = metrics.get("stun.example.com").unwrap();

        assert_eq!(server_metrics.requests.load(Ordering::Relaxed), 1);
        assert_eq!(server_metrics.successes.load(Ordering::Relaxed), 2);
        assert_eq!(server_metrics.failures.load(Ordering::Relaxed), 1);
        assert_eq!(server_metrics.avg_response_time_ms.load(Ordering::Relaxed), 75);
        assert_eq!(server_metrics.success_rate(), 2.0 / 3.0);
    }

    #[test]
    fn test_nat_type_recording() {
        let collector = NatMetricsCollector::new();

        collector.record_nat_type("FullCone", "high");
        collector.record_nat_type("FullCone", "high");
        collector.record_nat_type("Symmetric", "low");

        let detections = collector.nat_type_detections.read();
        assert_eq!(
            detections.get("FullCone_high").unwrap().load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            detections.get("Symmetric_low").unwrap().load(Ordering::Relaxed),
            1
        );
    }
}