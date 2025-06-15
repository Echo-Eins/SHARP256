use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use prometheus::{
    register_counter_vec, register_histogram_vec, register_gauge_vec,
    CounterVec, HistogramVec, GaugeVec, Encoder, TextEncoder
};
use once_cell::sync::Lazy;

/// Global metrics registry
static METRICS: Lazy<NatMetrics> = Lazy::new(|| {
    NatMetrics::new().expect("Failed to initialize metrics")
});

/// NAT traversal metrics collection
pub struct NatMetrics {
    /// Connection attempts by method
    pub connection_attempts: CounterVec,

    /// Successful connections by method
    pub connection_successes: CounterVec,

    /// Failed connections by method and reason
    pub connection_failures: CounterVec,

    /// Connection establishment latency
    pub connection_latency: HistogramVec,

    /// Active connections by method
    pub active_connections: GaugeVec,

    /// STUN server response times
    pub stun_response_time: HistogramVec,

    /// UPnP operation latency
    pub upnp_operation_latency: HistogramVec,

    /// Circuit breaker state (0=closed, 1=open, 2=half-open)
    pub circuit_breaker_state: GaugeVec,

    /// Packet loss rate by connection
    pub packet_loss_rate: GaugeVec,

    /// Bandwidth utilization
    pub bandwidth_bytes: CounterVec,

    /// NAT type distribution
    pub nat_type_detected: CounterVec,

    /// Port mapping lifetime
    pub port_mapping_lifetime: HistogramVec,

    /// Method fallback events
    pub fallback_events: CounterVec,

    /// IPv4 vs IPv6 usage
    pub ip_version_usage: CounterVec,
}

impl NatMetrics {
    /// Initialize metrics with Prometheus registrations
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            connection_attempts: register_counter_vec!(
                "nat_connection_attempts_total",
                "Total number of connection attempts",
                &["method", "ip_version"]
            )?,

            connection_successes: register_counter_vec!(
                "nat_connection_successes_total",
                "Total number of successful connections",
                &["method", "ip_version", "nat_type"]
            )?,

            connection_failures: register_counter_vec!(
                "nat_connection_failures_total",
                "Total number of failed connections",
                &["method", "reason", "ip_version"]
            )?,

            connection_latency: register_histogram_vec!(
                "nat_connection_latency_seconds",
                "Connection establishment latency in seconds",
                &["method", "success"],
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
            )?,

            active_connections: register_gauge_vec!(
                "nat_active_connections",
                "Number of currently active connections",
                &["method", "state"]
            )?,

            stun_response_time: register_histogram_vec!(
                "nat_stun_response_time_seconds",
                "STUN server response time in seconds",
                &["server", "success"],
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
            )?,

            upnp_operation_latency: register_histogram_vec!(
                "nat_upnp_operation_latency_seconds",
                "UPnP operation latency in seconds",
                &["operation", "success"],
                vec![0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
            )?,

            circuit_breaker_state: register_gauge_vec!(
                "nat_circuit_breaker_state",
                "Circuit breaker state (0=closed, 1=open, 2=half-open)",
                &["method"]
            )?,

            packet_loss_rate: register_gauge_vec!(
                "nat_packet_loss_rate",
                "Packet loss rate as a percentage",
                &["connection_id", "direction"]
            )?,

            bandwidth_bytes: register_counter_vec!(
                "nat_bandwidth_bytes_total",
                "Total bandwidth usage in bytes",
                &["connection_id", "direction"]
            )?,

            nat_type_detected: register_counter_vec!(
                "nat_type_detected_total",
                "NAT types detected",
                &["type", "confidence"]
            )?,

            port_mapping_lifetime: register_histogram_vec!(
                "nat_port_mapping_lifetime_seconds",
                "Port mapping lifetime in seconds",
                &["protocol", "success"],
                vec![60.0, 300.0, 600.0, 1800.0, 3600.0, 7200.0, 86400.0]
            )?,

            fallback_events: register_counter_vec!(
                "nat_fallback_events_total",
                "Method fallback events",
                &["from_method", "to_method", "reason"]
            )?,

            ip_version_usage: register_counter_vec!(
                "nat_ip_version_usage_total",
                "IP version usage statistics",
                &["version", "operation"]
            )?,
        })
    }

    /// Get global metrics instance
    pub fn global() -> &'static Self {
        &METRICS
    }

    /// Export metrics in Prometheus format
    pub fn export(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

/// Connection metrics tracker
pub struct ConnectionMetrics {
    pub connection_id: String,
    pub method: String,
    pub start_time: Instant,
    pub ip_version: String,
    metrics: Arc<NatMetrics>,
}

impl ConnectionMetrics {
    /// Create new connection metrics tracker
    pub fn new(connection_id: String, method: String, ip_version: &str) -> Self {
        let metrics = Arc::new(METRICS.clone());

        metrics.connection_attempts
            .with_label_values(&[&method, ip_version])
            .inc();

        metrics.active_connections
            .with_label_values(&[&method, "establishing"])
            .inc();

        Self {
            connection_id,
            method: method.clone(),
            start_time: Instant::now(),
            ip_version: ip_version.to_string(),
            metrics,
        }
    }

    /// Record successful connection
    pub fn record_success(&self, nat_type: &str) {
        let latency = self.start_time.elapsed().as_secs_f64();

        self.metrics.connection_successes
            .with_label_values(&[&self.method, &self.ip_version, nat_type])
            .inc();

        self.metrics.connection_latency
            .with_label_values(&[&self.method, "true"])
            .observe(latency);

        self.metrics.active_connections
            .with_label_values(&[&self.method, "establishing"])
            .dec();

        self.metrics.active_connections
            .with_label_values(&[&self.method, "established"])
            .inc();
    }

    /// Record failed connection
    pub fn record_failure(&self, reason: &str) {
        let latency = self.start_time.elapsed().as_secs_f64();

        self.metrics.connection_failures
            .with_label_values(&[&self.method, reason, &self.ip_version])
            .inc();

        self.metrics.connection_latency
            .with_label_values(&[&self.method, "false"])
            .observe(latency);

        self.metrics.active_connections
            .with_label_values(&[&self.method, "establishing"])
            .dec();
    }

    /// Record bandwidth usage
    pub fn record_bandwidth(&self, bytes: u64, direction: &str) {
        self.metrics.bandwidth_bytes
            .with_label_values(&[&self.connection_id, direction])
            .inc_by(bytes as f64);
    }

    /// Update packet loss rate
    pub fn update_packet_loss(&self, loss_rate: f64, direction: &str) {
        self.metrics.packet_loss_rate
            .with_label_values(&[&self.connection_id, direction])
            .set(loss_rate * 100.0);
    }
}

impl Drop for ConnectionMetrics {
    fn drop(&mut self) {
        self.metrics.active_connections
            .with_label_values(&[&self.method, "established"])
            .dec();
    }
}

/// STUN operation metrics
pub struct StunMetrics {
    server: String,
    start_time: Instant,
    metrics: Arc<NatMetrics>,
}

impl StunMetrics {
    pub fn new(server: String) -> Self {
        Self {
            server,
            start_time: Instant::now(),
            metrics: Arc::new(METRICS.clone()),
        }
    }

    pub fn record_response(&self, success: bool) {
        let latency = self.start_time.elapsed().as_secs_f64();

        self.metrics.stun_response_time
            .with_label_values(&[&self.server, if success { "true" } else { "false" }])
            .observe(latency);
    }
}

/// UPnP operation metrics
pub struct UpnpMetrics {
    operation: String,
    start_time: Instant,
    metrics: Arc<NatMetrics>,
}

impl UpnpMetrics {
    pub fn new(operation: String) -> Self {
        Self {
            operation,
            start_time: Instant::now(),
            metrics: Arc::new(METRICS.clone()),
        }
    }

    pub fn record_completion(&self, success: bool) {
        let latency = self.start_time.elapsed().as_secs_f64();

        self.metrics.upnp_operation_latency
            .with_label_values(&[&self.operation, if success { "true" } else { "false" }])
            .observe(latency);
    }
}

/// Circuit breaker metrics
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed = 0,
    Open = 1,
    HalfOpen = 2,
}

pub struct CircuitBreakerMetrics {
    method: String,
    metrics: Arc<NatMetrics>,
}

impl CircuitBreakerMetrics {
    pub fn new(method: String) -> Self {
        let metrics = Arc::new(METRICS.clone());

        // Initialize to closed state
        metrics.circuit_breaker_state
            .with_label_values(&[&method])
            .set(CircuitState::Closed as f64);

        Self { method, metrics }
    }

    pub fn update_state(&self, state: CircuitState) {
        self.metrics.circuit_breaker_state
            .with_label_values(&[&self.method])
            .set(state as i32 as f64);
    }
}

/// NAT type detection metrics
pub fn record_nat_type_detection(nat_type: &str, confidence: &str) {
    METRICS.nat_type_detected
        .with_label_values(&[nat_type, confidence])
        .inc();
}

/// Fallback event metrics
pub fn record_fallback_event(from_method: &str, to_method: &str, reason: &str) {
    METRICS.fallback_events
        .with_label_values(&[from_method, to_method, reason])
        .inc();
}

/// IP version usage metrics
pub fn record_ip_version_usage(version: &str, operation: &str) {
    METRICS.ip_version_usage
        .with_label_values(&[version, operation])
        .inc();
}

/// Port mapping lifetime metrics
pub fn record_port_mapping_lifetime(protocol: &str, lifetime: Duration, success: bool) {
    METRICS.port_mapping_lifetime
        .with_label_values(&[protocol, if success { "true" } else { "false" }])
        .observe(lifetime.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_metrics() {
        let metrics = ConnectionMetrics::new(
            "test-123".to_string(),
            "stun".to_string(),
            "ipv4"
        );

        // Simulate some operations
        std::thread::sleep(Duration::from_millis(50));
        metrics.record_success("full_cone");

        metrics.record_bandwidth(1024 * 1024, "inbound");
        metrics.record_bandwidth(512 * 1024, "outbound");

        metrics.update_packet_loss(0.02, "inbound");
    }

    #[test]
    fn test_circuit_breaker_metrics() {
        let cb_metrics = CircuitBreakerMetrics::new("upnp".to_string());

        cb_metrics.update_state(CircuitState::Open);
        std::thread::sleep(Duration::from_millis(100));
        cb_metrics.update_state(CircuitState::HalfOpen);
        std::thread::sleep(Duration::from_millis(50));
        cb_metrics.update_state(CircuitState::Closed);
    }
}