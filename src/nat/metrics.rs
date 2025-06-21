// src/nat/metrics.rs
//! Comprehensive metrics collection for NAT traversal operations
//!
//! Provides detailed metrics for:
//! - STUN operations and NAT detection
//! - ICE candidate gathering and connectivity checks
//! - Hole punching strategies and success rates
//! - Port forwarding (UPnP/NAT-PMP/PCP)
//! - Overall NAT traversal performance

use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

/// Time window for rate calculations (5 minutes)
const RATE_WINDOW: Duration = Duration::from_secs(300);

/// Maximum samples to keep for percentile calculations
const MAX_SAMPLES: usize = 1000;

/// Get current timestamp in seconds
fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Global metrics instance
static METRICS: once_cell::sync::Lazy<Arc<NatMetricsCollector>> =
    once_cell::sync::Lazy::new(|| Arc::new(NatMetricsCollector::new()));

/// Main NAT traversal metrics collector
pub struct NatMetricsCollector {
    /// STUN metrics
    pub stun: Arc<StunMetrics>,

    /// ICE metrics
    pub ice: Arc<IceMetrics>,

    /// Hole punching metrics
    pub hole_punch: Arc<HolePunchMetrics>,

    /// Port forwarding metrics
    pub port_forwarding: Arc<PortForwardingMetrics>,

    /// Overall metrics
    pub overall: Arc<OverallMetrics>,

    /// Metrics export format
    export_format: RwLock<MetricsExportFormat>,
}

/// Metrics export format
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MetricsExportFormat {
    /// Human-readable text
    Text,
    /// JSON format
    Json,
    /// Prometheus format
    Prometheus,
}

impl NatMetricsCollector {
    fn new() -> Self {
        Self {
            stun: Arc::new(StunMetrics::new()),
            ice: Arc::new(IceMetrics::new()),
            hole_punch: Arc::new(HolePunchMetrics::new()),
            port_forwarding: Arc::new(PortForwardingMetrics::new()),
            overall: Arc::new(OverallMetrics::new()),
            export_format: RwLock::new(MetricsExportFormat::Text),
        }
    }

    /// Get global metrics instance
    pub fn global() -> Arc<Self> {
        METRICS.clone()
    }

    /// Set export format
    pub fn set_export_format(&self, format: MetricsExportFormat) {
        *self.export_format.write() = format;
    }

    /// Export all metrics
    pub fn export(&self) -> String {
        match *self.export_format.read() {
            MetricsExportFormat::Text => self.export_text(),
            MetricsExportFormat::Json => self.export_json(),
            MetricsExportFormat::Prometheus => self.export_prometheus(),
        }
    }

    /// Export as human-readable text
    fn export_text(&self) -> String {
        let mut output = String::from("=== NAT Traversal Metrics ===\n\n");

        // STUN metrics
        output.push_str("STUN Operations:\n");
        output.push_str(&self.stun.format_text());
        output.push_str("\n");

        // ICE metrics
        output.push_str("ICE Operations:\n");
        output.push_str(&self.ice.format_text());
        output.push_str("\n");

        // Hole punching metrics
        output.push_str("Hole Punching:\n");
        output.push_str(&self.hole_punch.format_text());
        output.push_str("\n");

        // Port forwarding metrics
        output.push_str("Port Forwarding:\n");
        output.push_str(&self.port_forwarding.format_text());
        output.push_str("\n");

        // Overall metrics
        output.push_str("Overall Performance:\n");
        output.push_str(&self.overall.format_text());

        output
    }

    /// Export as JSON
    fn export_json(&self) -> String {
        serde_json::json!({
            "timestamp": timestamp(),
            "stun": self.stun.to_json(),
            "ice": self.ice.to_json(),
            "hole_punch": self.hole_punch.to_json(),
            "port_forwarding": self.port_forwarding.to_json(),
            "overall": self.overall.to_json(),
        }).to_string()
    }

    /// Export as Prometheus metrics
    fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Add header
        output.push_str("# HELP nat_operations_total Total NAT traversal operations\n");
        output.push_str("# TYPE nat_operations_total counter\n");

        // STUN metrics
        output.push_str(&self.stun.to_prometheus("stun"));

        // ICE metrics
        output.push_str(&self.ice.to_prometheus("ice"));

        // Hole punching metrics
        output.push_str(&self.hole_punch.to_prometheus("hole_punch"));

        // Port forwarding metrics
        output.push_str(&self.port_forwarding.to_prometheus("port_forwarding"));

        // Overall metrics
        output.push_str(&self.overall.to_prometheus("nat"));

        output
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.stun.reset();
        self.ice.reset();
        self.hole_punch.reset();
        self.port_forwarding.reset();
        self.overall.reset();
    }
}

/// STUN metrics
pub struct StunMetrics {
    /// Requests by server
    requests: RwLock<HashMap<String, ServerMetrics>>,

    /// NAT type detections
    nat_types: RwLock<HashMap<String, AtomicUsize>>,

    /// Behavior discovery results
    behaviors: RwLock<HashMap<String, AtomicUsize>>,

    /// Response time percentiles
    response_times: RwLock<VecDeque<Duration>>,

    /// Total requests
    total_requests: AtomicU64,

    /// Successful responses
    total_successes: AtomicU64,

    /// Failed requests
    total_failures: AtomicU64,
}

/// Per-server STUN metrics
#[derive(Debug)]
struct ServerMetrics {
    requests: AtomicUsize,
    successes: AtomicUsize,
    failures: AtomicUsize,
    total_response_time: AtomicU64,
    last_success: RwLock<Option<Instant>>,
    last_failure: RwLock<Option<Instant>>,
}

impl StunMetrics {
    fn new() -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
            nat_types: RwLock::new(HashMap::new()),
            behaviors: RwLock::new(HashMap::new()),
            response_times: RwLock::new(VecDeque::with_capacity(MAX_SAMPLES)),
            total_requests: AtomicU64::new(0),
            total_successes: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
        }
    }

    /// Record STUN request
    pub fn record_request(&self, server: &str) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut servers = self.requests.write();
        let metrics = servers.entry(server.to_string())
            .or_insert_with(|| ServerMetrics::new());
        metrics.requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record STUN response
    pub fn record_response(&self, server: &str, success: bool, response_time: Duration) {
        let mut servers = self.requests.write();
        let metrics = servers.entry(server.to_string())
            .or_insert_with(|| ServerMetrics::new());

        if success {
            self.total_successes.fetch_add(1, Ordering::Relaxed);
            metrics.successes.fetch_add(1, Ordering::Relaxed);
            metrics.total_response_time.fetch_add(
                response_time.as_millis() as u64,
                Ordering::Relaxed
            );
            *metrics.last_success.write() = Some(Instant::now());

            // Record response time
            let mut times = self.response_times.write();
            if times.len() >= MAX_SAMPLES {
                times.pop_front();
            }
            times.push_back(response_time);
        } else {
            self.total_failures.fetch_add(1, Ordering::Relaxed);
            metrics.failures.fetch_add(1, Ordering::Relaxed);
            *metrics.last_failure.write() = Some(Instant::now());
        }
    }

    /// Record NAT type detection
    pub fn record_nat_type(&self, nat_type: &str, confidence: &str) {
        let key = format!("{}_{}", nat_type, confidence);
        let mut types = self.nat_types.write();
        types.entry(key)
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record NAT behavior
    pub fn record_behavior(&self, mapping: &str, filtering: &str) {
        let key = format!("{}_mapping_{}_filtering", mapping, filtering);
        let mut behaviors = self.behaviors.write();
        behaviors.entry(key)
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let successes = self.total_successes.load(Ordering::Relaxed);
        successes as f64 / total as f64
    }

    /// Get response time percentiles
    pub fn response_percentiles(&self) -> ResponsePercentiles {
        let times = self.response_times.read();
        if times.is_empty() {
            return ResponsePercentiles::default();
        }

        let mut sorted: Vec<Duration> = times.iter().cloned().collect();
        sorted.sort();

        ResponsePercentiles {
            p50: sorted[sorted.len() / 2],
            p90: sorted[sorted.len() * 9 / 10],
            p99: sorted[sorted.len() * 99 / 100],
            p999: sorted[sorted.len() * 999 / 1000],
        }
    }

    fn format_text(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "  Total: {} requests, {} successes ({:.1}%), {} failures\n",
            self.total_requests.load(Ordering::Relaxed),
            self.total_successes.load(Ordering::Relaxed),
            self.success_rate() * 100.0,
            self.total_failures.load(Ordering::Relaxed)
        ));

        let percentiles = self.response_percentiles();
        output.push_str(&format!(
            "  Response times: p50={:?}, p90={:?}, p99={:?}\n",
            percentiles.p50, percentiles.p90, percentiles.p99
        ));

        // Top servers
        let servers = self.requests.read();
        let mut server_list: Vec<_> = servers.iter().collect();
        server_list.sort_by_key(|(_, m)| m.successes.load(Ordering::Relaxed));

        output.push_str("  Top servers:\n");
        for (server, metrics) in server_list.iter().take(5).rev() {
            output.push_str(&format!(
                "    {}: {} successes, {:.1}% success rate\n",
                server,
                metrics.successes.load(Ordering::Relaxed),
                metrics.success_rate() * 100.0
            ));
        }

        output
    }

    fn to_json(&self) -> serde_json::Value {
        let servers = self.requests.read();
        let nat_types = self.nat_types.read();
        let behaviors = self.behaviors.read();

        serde_json::json!({
            "total_requests": self.total_requests.load(Ordering::Relaxed),
            "total_successes": self.total_successes.load(Ordering::Relaxed),
            "total_failures": self.total_failures.load(Ordering::Relaxed),
            "success_rate": self.success_rate(),
            "response_percentiles": self.response_percentiles(),
            "servers": servers.iter().map(|(name, metrics)| {
                (name.clone(), serde_json::json!({
                    "requests": metrics.requests.load(Ordering::Relaxed),
                    "successes": metrics.successes.load(Ordering::Relaxed),
                    "failures": metrics.failures.load(Ordering::Relaxed),
                    "avg_response_ms": metrics.avg_response_time().as_millis(),
                }))
            }).collect::<HashMap<_, _>>(),
            "nat_types": nat_types.iter().map(|(k, v)| {
                (k.clone(), v.load(Ordering::Relaxed))
            }).collect::<HashMap<_, _>>(),
            "behaviors": behaviors.iter().map(|(k, v)| {
                (k.clone(), v.load(Ordering::Relaxed))
            }).collect::<HashMap<_, _>>(),
        })
    }

    fn to_prometheus(&self, prefix: &str) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "{}_requests_total {{}} {}\n",
            prefix,
            self.total_requests.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "{}_successes_total {{}} {}\n",
            prefix,
            self.total_successes.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "{}_failures_total {{}} {}\n",
            prefix,
            self.total_failures.load(Ordering::Relaxed)
        ));

        // Per-server metrics
        let servers = self.requests.read();
        for (server, metrics) in servers.iter() {
            output.push_str(&format!(
                "{}_server_requests_total {{server=\"{}\"}} {}\n",
                prefix,
                server,
                metrics.requests.load(Ordering::Relaxed)
            ));
        }

        output
    }

    fn reset(&self) {
        self.requests.write().clear();
        self.nat_types.write().clear();
        self.behaviors.write().clear();
        self.response_times.write().clear();
        self.total_requests.store(0, Ordering::Relaxed);
        self.total_successes.store(0, Ordering::Relaxed);
        self.total_failures.store(0, Ordering::Relaxed);
    }
}

impl ServerMetrics {
    fn new() -> Self {
        Self {
            requests: AtomicUsize::new(0),
            successes: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
            total_response_time: AtomicU64::new(0),
            last_success: RwLock::new(None),
            last_failure: RwLock::new(None),
        }
    }

    fn success_rate(&self) -> f64 {
        let total = self.requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let successes = self.successes.load(Ordering::Relaxed);
        successes as f64 / total as f64
    }

    fn avg_response_time(&self) -> Duration {
        let successes = self.successes.load(Ordering::Relaxed);
        if successes == 0 {
            return Duration::ZERO;
        }
        let total = self.total_response_time.load(Ordering::Relaxed);
        Duration::from_millis(total / successes as u64)
    }
}

/// ICE metrics
pub struct IceMetrics {
    /// Gathering statistics
    gathering: Arc<IceGatheringMetrics>,

    /// Connectivity check statistics
    connectivity: Arc<IceConnectivityMetrics>,

    /// Overall ICE statistics
    sessions: Arc<IceSessionMetrics>,
}

/// ICE gathering metrics
pub struct IceGatheringMetrics {
    /// Candidates gathered by type
    candidates_by_type: RwLock<HashMap<String, AtomicUsize>>,

    /// Gathering time samples
    gathering_times: RwLock<VecDeque<Duration>>,

    /// Total gathering attempts
    total_attempts: AtomicU64,

    /// Successful gatherings
    successful_gatherings: AtomicU64,
}

/// ICE connectivity metrics
pub struct IceConnectivityMetrics {
    /// Checks by state
    checks_by_state: RwLock<HashMap<String, AtomicUsize>>,

    /// Valid pairs found
    valid_pairs: AtomicU64,

    /// Nominated pairs
    nominated_pairs: AtomicU64,

    /// Check durations
    check_durations: RwLock<VecDeque<Duration>>,
}

/// ICE session metrics
pub struct IceSessionMetrics {
    /// Total sessions
    total_sessions: AtomicU64,

    /// Successful sessions
    successful_sessions: AtomicU64,

    /// Failed sessions
    failed_sessions: AtomicU64,

    /// Connection establishment times
    establishment_times: RwLock<VecDeque<Duration>>,
}

impl IceMetrics {
    fn new() -> Self {
        Self {
            gathering: Arc::new(IceGatheringMetrics::new()),
            connectivity: Arc::new(IceConnectivityMetrics::new()),
            sessions: Arc::new(IceSessionMetrics::new()),
        }
    }

    fn format_text(&self) -> String {
        let mut output = String::new();

        // Gathering metrics
        output.push_str(&format!(
            "  Gathering: {} attempts, {} successful ({:.1}%)\n",
            self.gathering.total_attempts.load(Ordering::Relaxed),
            self.gathering.successful_gatherings.load(Ordering::Relaxed),
            self.gathering.success_rate() * 100.0
        ));

        // Connectivity metrics
        output.push_str(&format!(
            "  Connectivity: {} valid pairs, {} nominated\n",
            self.connectivity.valid_pairs.load(Ordering::Relaxed),
            self.connectivity.nominated_pairs.load(Ordering::Relaxed)
        ));

        // Session metrics
        output.push_str(&format!(
            "  Sessions: {} total, {} successful ({:.1}%)\n",
            self.sessions.total_sessions.load(Ordering::Relaxed),
            self.sessions.successful_sessions.load(Ordering::Relaxed),
            self.sessions.success_rate() * 100.0
        ));

        output
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "gathering": self.gathering.to_json(),
            "connectivity": self.connectivity.to_json(),
            "sessions": self.sessions.to_json(),
        })
    }

    fn to_prometheus(&self, prefix: &str) -> String {
        let mut output = String::new();
        output.push_str(&self.gathering.to_prometheus(&format!("{}_gathering", prefix)));
        output.push_str(&self.connectivity.to_prometheus(&format!("{}_connectivity", prefix)));
        output.push_str(&self.sessions.to_prometheus(&format!("{}_sessions", prefix)));
        output
    }

    fn reset(&self) {
        self.gathering.reset();
        self.connectivity.reset();
        self.sessions.reset();
    }
}

impl IceGatheringMetrics {
    fn new() -> Self {
        Self {
            candidates_by_type: RwLock::new(HashMap::new()),
            gathering_times: RwLock::new(VecDeque::with_capacity(MAX_SAMPLES)),
            total_attempts: AtomicU64::new(0),
            successful_gatherings: AtomicU64::new(0),
        }
    }

    pub fn record_candidate(&self, candidate_type: &str) {
        let mut types = self.candidates_by_type.write();
        types.entry(candidate_type.to_string())
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_gathering(&self, duration: Duration, success: bool) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);

        if success {
            self.successful_gatherings.fetch_add(1, Ordering::Relaxed);

            let mut times = self.gathering_times.write();
            if times.len() >= MAX_SAMPLES {
                times.pop_front();
            }
            times.push_back(duration);
        }
    }

    fn success_rate(&self) -> f64 {
        let total = self.total_attempts.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let successes = self.successful_gatherings.load(Ordering::Relaxed);
        successes as f64 / total as f64
    }

    fn to_json(&self) -> serde_json::Value {
        let types = self.candidates_by_type.read();

        serde_json::json!({
            "total_attempts": self.total_attempts.load(Ordering::Relaxed),
            "successful_gatherings": self.successful_gatherings.load(Ordering::Relaxed),
            "success_rate": self.success_rate(),
            "candidates_by_type": types.iter().map(|(k, v)| {
                (k.clone(), v.load(Ordering::Relaxed))
            }).collect::<HashMap<_, _>>(),
        })
    }

    fn to_prometheus(&self, prefix: &str) -> String {
        format!(
            "{}_attempts_total {{}} {}\n\
             {}_successes_total {{}} {}\n",
            prefix, self.total_attempts.load(Ordering::Relaxed),
            prefix, self.successful_gatherings.load(Ordering::Relaxed)
        )
    }

    fn reset(&self) {
        self.candidates_by_type.write().clear();
        self.gathering_times.write().clear();
        self.total_attempts.store(0, Ordering::Relaxed);
        self.successful_gatherings.store(0, Ordering::Relaxed);
    }
}

impl IceConnectivityMetrics {
    fn new() -> Self {
        Self {
            checks_by_state: RwLock::new(HashMap::new()),
            valid_pairs: AtomicU64::new(0),
            nominated_pairs: AtomicU64::new(0),
            check_durations: RwLock::new(VecDeque::with_capacity(MAX_SAMPLES)),
        }
    }

    pub fn record_check_state(&self, state: &str) {
        let mut states = self.checks_by_state.write();
        states.entry(state.to_string())
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_valid_pair(&self) {
        self.valid_pairs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_nominated_pair(&self) {
        self.nominated_pairs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_check_duration(&self, duration: Duration) {
        let mut durations = self.check_durations.write();
        if durations.len() >= MAX_SAMPLES {
            durations.pop_front();
        }
        durations.push_back(duration);
    }

    fn to_json(&self) -> serde_json::Value {
        let states = self.checks_by_state.read();

        serde_json::json!({
            "valid_pairs": self.valid_pairs.load(Ordering::Relaxed),
            "nominated_pairs": self.nominated_pairs.load(Ordering::Relaxed),
            "checks_by_state": states.iter().map(|(k, v)| {
                (k.clone(), v.load(Ordering::Relaxed))
            }).collect::<HashMap<_, _>>(),
        })
    }

    fn to_prometheus(&self, prefix: &str) -> String {
        format!(
            "{}_valid_pairs_total {{}} {}\n\
             {}_nominated_pairs_total {{}} {}\n",
            prefix, self.valid_pairs.load(Ordering::Relaxed),
            prefix, self.nominated_pairs.load(Ordering::Relaxed)
        )
    }

    fn reset(&self) {
        self.checks_by_state.write().clear();
        self.valid_pairs.store(0, Ordering::Relaxed);
        self.nominated_pairs.store(0, Ordering::Relaxed);
        self.check_durations.write().clear();
    }
}

impl IceSessionMetrics {
    fn new() -> Self {
        Self {
            total_sessions: AtomicU64::new(0),
            successful_sessions: AtomicU64::new(0),
            failed_sessions: AtomicU64::new(0),
            establishment_times: RwLock::new(VecDeque::with_capacity(MAX_SAMPLES)),
        }
    }

    pub fn record_session(&self, duration: Duration, success: bool) {
        self.total_sessions.fetch_add(1, Ordering::Relaxed);

        if success {
            self.successful_sessions.fetch_add(1, Ordering::Relaxed);

            let mut times = self.establishment_times.write();
            if times.len() >= MAX_SAMPLES {
                times.pop_front();
            }
            times.push_back(duration);
        } else {
            self.failed_sessions.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn success_rate(&self) -> f64 {
        let total = self.total_sessions.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let successes = self.successful_sessions.load(Ordering::Relaxed);
        successes as f64 / total as f64
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "total_sessions": self.total_sessions.load(Ordering::Relaxed),
            "successful_sessions": self.successful_sessions.load(Ordering::Relaxed),
            "failed_sessions": self.failed_sessions.load(Ordering::Relaxed),
            "success_rate": self.success_rate(),
        })
    }

    fn to_prometheus(&self, prefix: &str) -> String {
        format!(
            "{}_total {{}} {}\n\
             {}_successful {{}} {}\n\
             {}_failed {{}} {}\n",
            prefix, self.total_sessions.load(Ordering::Relaxed),
            prefix, self.successful_sessions.load(Ordering::Relaxed),
            prefix, self.failed_sessions.load(Ordering::Relaxed)
        )
    }

    fn reset(&self) {
        self.total_sessions.store(0, Ordering::Relaxed);
        self.successful_sessions.store(0, Ordering::Relaxed);
        self.failed_sessions.store(0, Ordering::Relaxed);
        self.establishment_times.write().clear();
    }
}

/// Hole punching metrics
pub struct HolePunchMetrics {
    /// Attempts by strategy
    attempts_by_strategy: RwLock<HashMap<String, AtomicUsize>>,

    /// Successes by strategy
    successes_by_strategy: RwLock<HashMap<String, AtomicUsize>>,

    /// Connection times
    connection_times: RwLock<VecDeque<Duration>>,

    /// Packets sent/received
    packets_sent: AtomicU64,
    packets_received: AtomicU64,

    /// Total attempts
    total_attempts: AtomicU64,

    /// Successful connections
    successful_connections: AtomicU64,
}

impl HolePunchMetrics {
    pub fn new() -> Self {
        Self {
            attempts_by_strategy: RwLock::new(HashMap::new()),
            successes_by_strategy: RwLock::new(HashMap::new()),
            connection_times: RwLock::new(VecDeque::with_capacity(MAX_SAMPLES)),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            total_attempts: AtomicU64::new(0),
            successful_connections: AtomicU64::new(0),
        }
    }

    pub fn record_attempt(&self, peer: SocketAddr) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        tracing::trace!("Hole punch attempt to {}", peer);
    }

    pub fn record_success(&self, peer: SocketAddr, duration: Duration, strategy: String) {
        self.successful_connections.fetch_add(1, Ordering::Relaxed);

        // Record strategy success
        let mut successes = self.successes_by_strategy.write();
        successes.entry(strategy.clone())
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);

        // Record connection time
        let mut times = self.connection_times.write();
        if times.len() >= MAX_SAMPLES {
            times.pop_front();
        }
        times.push_back(duration);

        tracing::info!("Hole punch success to {} using {} in {:?}", peer, strategy, duration);
    }

    pub fn record_failure(&self, peer: SocketAddr, strategy: String) {
        // Record strategy attempt
        let mut attempts = self.attempts_by_strategy.write();
        attempts.entry(strategy.clone())
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);

        tracing::debug!("Hole punch failure to {} using {}", peer, strategy);
    }

    pub fn add_packets_sent(&self, count: u32) {
        self.packets_sent.fetch_add(count as u64, Ordering::Relaxed);
    }

    pub fn add_packets_received(&self, count: u32) {
        self.packets_received.fetch_add(count as u64, Ordering::Relaxed);
    }

    fn success_rate(&self) -> f64 {
        let total = self.total_attempts.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let successes = self.successful_connections.load(Ordering::Relaxed);
        successes as f64 / total as f64
    }

    fn format_text(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "  Total: {} attempts, {} successful ({:.1}%)\n",
            self.total_attempts.load(Ordering::Relaxed),
            self.successful_connections.load(Ordering::Relaxed),
            self.success_rate() * 100.0
        ));

        output.push_str(&format!(
            "  Packets: {} sent, {} received\n",
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed)
        ));

        // Strategy success rates
        let attempts = self.attempts_by_strategy.read();
        let successes = self.successes_by_strategy.read();

        output.push_str("  Strategy success rates:\n");
        for (strategy, success_count) in successes.iter() {
            let attempt_count = attempts.get(strategy)
                .map(|a| a.load(Ordering::Relaxed))
                .unwrap_or(0);

            if attempt_count > 0 {
                let rate = success_count.load(Ordering::Relaxed) as f64 / attempt_count as f64;
                output.push_str(&format!(
                    "    {}: {:.1}% ({}/{})\n",
                    strategy,
                    rate * 100.0,
                    success_count.load(Ordering::Relaxed),
                    attempt_count
                ));
            }
        }

        output
    }

    fn to_json(&self) -> serde_json::Value {
        let attempts = self.attempts_by_strategy.read();
        let successes = self.successes_by_strategy.read();

        serde_json::json!({
            "total_attempts": self.total_attempts.load(Ordering::Relaxed),
            "successful_connections": self.successful_connections.load(Ordering::Relaxed),
            "success_rate": self.success_rate(),
            "packets_sent": self.packets_sent.load(Ordering::Relaxed),
            "packets_received": self.packets_received.load(Ordering::Relaxed),
            "strategies": attempts.iter().map(|(strategy, attempt_count)| {
                let success_count = successes.get(strategy)
                    .map(|s| s.load(Ordering::Relaxed))
                    .unwrap_or(0);

                (strategy.clone(), serde_json::json!({
                    "attempts": attempt_count.load(Ordering::Relaxed),
                    "successes": success_count,
                    "success_rate": if attempt_count.load(Ordering::Relaxed) > 0 {
                        success_count as f64 / attempt_count.load(Ordering::Relaxed) as f64
                    } else {
                        0.0
                    }
                }))
            }).collect::<HashMap<_, _>>(),
        })
    }

    fn to_prometheus(&self, prefix: &str) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "{}_attempts_total {{}} {}\n",
            prefix,
            self.total_attempts.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "{}_successes_total {{}} {}\n",
            prefix,
            self.successful_connections.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "{}_packets_sent_total {{}} {}\n",
            prefix,
            self.packets_sent.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "{}_packets_received_total {{}} {}\n",
            prefix,
            self.packets_received.load(Ordering::Relaxed)
        ));

        output
    }

    fn reset(&self) {
        self.attempts_by_strategy.write().clear();
        self.successes_by_strategy.write().clear();
        self.connection_times.write().clear();
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_received.store(0, Ordering::Relaxed);
        self.total_attempts.store(0, Ordering::Relaxed);
        self.successful_connections.store(0, Ordering::Relaxed);
    }
}

/// Port forwarding metrics
pub struct PortForwardingMetrics {
    /// Mappings by protocol
    mappings_by_protocol: RwLock<HashMap<String, AtomicUsize>>,

    /// Success counts by protocol
    successes_by_protocol: RwLock<HashMap<String, AtomicUsize>>,

    /// Failure counts by protocol
    failures_by_protocol: RwLock<HashMap<String, AtomicUsize>>,

    /// Mapping creation times
    creation_times: RwLock<HashMap<String, VecDeque<Duration>>>,

    /// Active mappings
    active_mappings: AtomicUsize,

    /// Total mapping attempts
    total_attempts: AtomicU64,
}

impl PortForwardingMetrics {
    fn new() -> Self {
        Self {
            mappings_by_protocol: RwLock::new(HashMap::new()),
            successes_by_protocol: RwLock::new(HashMap::new()),
            failures_by_protocol: RwLock::new(HashMap::new()),
            creation_times: RwLock::new(HashMap::new()),
            active_mappings: AtomicUsize::new(0),
            total_attempts: AtomicU64::new(0),
        }
    }

    pub fn record_attempt(&self, protocol: &str) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);

        let mut attempts = self.mappings_by_protocol.write();
        attempts.entry(protocol.to_string())
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_success(&self, protocol: &str, duration: Duration) {
        let mut successes = self.successes_by_protocol.write();
        successes.entry(protocol.to_string())
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);

        let mut times = self.creation_times.write();
        let protocol_times = times.entry(protocol.to_string())
            .or_insert_with(|| VecDeque::with_capacity(MAX_SAMPLES));

        if protocol_times.len() >= MAX_SAMPLES {
            protocol_times.pop_front();
        }
        protocol_times.push_back(duration);

        self.active_mappings.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self, protocol: &str, error: &str) {
        let mut failures = self.failures_by_protocol.write();
        failures.entry(protocol.to_string())
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);

        tracing::debug!("Port forwarding {} failed: {}", protocol, error);
    }

    pub fn record_deletion(&self) {
        self.active_mappings.fetch_sub(1, Ordering::Relaxed);
    }

    fn format_text(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "  Active mappings: {}\n",
            self.active_mappings.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "  Total attempts: {}\n",
            self.total_attempts.load(Ordering::Relaxed)
        ));

        // Protocol success rates
        let attempts = self.mappings_by_protocol.read();
        let successes = self.successes_by_protocol.read();
        let failures = self.failures_by_protocol.read();

        output.push_str("  Protocol statistics:\n");
        for (protocol, attempt_count) in attempts.iter() {
            let success_count = successes.get(protocol)
                .map(|s| s.load(Ordering::Relaxed))
                .unwrap_or(0);
            let failure_count = failures.get(protocol)
                .map(|f| f.load(Ordering::Relaxed))
                .unwrap_or(0);

            let total = attempt_count.load(Ordering::Relaxed);
            if total > 0 {
                output.push_str(&format!(
                    "    {}: {} attempts, {} successes ({:.1}%), {} failures\n",
                    protocol,
                    total,
                    success_count,
                    (success_count as f64 / total as f64) * 100.0,
                    failure_count
                ));
            }
        }

        output
    }

    fn to_json(&self) -> serde_json::Value {
        let attempts = self.mappings_by_protocol.read();
        let successes = self.successes_by_protocol.read();
        let failures = self.failures_by_protocol.read();

        serde_json::json!({
            "active_mappings": self.active_mappings.load(Ordering::Relaxed),
            "total_attempts": self.total_attempts.load(Ordering::Relaxed),
            "protocols": attempts.iter().map(|(protocol, attempt_count)| {
                let success_count = successes.get(protocol)
                    .map(|s| s.load(Ordering::Relaxed))
                    .unwrap_or(0);
                let failure_count = failures.get(protocol)
                    .map(|f| f.load(Ordering::Relaxed))
                    .unwrap_or(0);

                (protocol.clone(), serde_json::json!({
                    "attempts": attempt_count.load(Ordering::Relaxed),
                    "successes": success_count,
                    "failures": failure_count,
                }))
            }).collect::<HashMap<_, _>>(),
        })
    }

    fn to_prometheus(&self, prefix: &str) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "{}_active {{}} {}\n",
            prefix,
            self.active_mappings.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "{}_attempts_total {{}} {}\n",
            prefix,
            self.total_attempts.load(Ordering::Relaxed)
        ));

        let attempts = self.mappings_by_protocol.read();
        for (protocol, count) in attempts.iter() {
            output.push_str(&format!(
                "{}_protocol_attempts_total {{protocol=\"{}\"}} {}\n",
                prefix,
                protocol,
                count.load(Ordering::Relaxed)
            ));
        }

        output
    }

    fn reset(&self) {
        self.mappings_by_protocol.write().clear();
        self.successes_by_protocol.write().clear();
        self.failures_by_protocol.write().clear();
        self.creation_times.write().clear();
        self.active_mappings.store(0, Ordering::Relaxed);
        self.total_attempts.store(0, Ordering::Relaxed);
    }
}

/// Overall NAT traversal metrics
pub struct OverallMetrics {
    /// Start time
    start_time: Instant,

    /// Successful NAT traversals
    successful_traversals: AtomicU64,

    /// Failed NAT traversals
    failed_traversals: AtomicU64,

    /// Traversal method used
    methods_used: RwLock<HashMap<String, AtomicUsize>>,

    /// Total bytes transferred through NAT
    bytes_transferred: AtomicU64,

    /// Connection lifetimes
    connection_lifetimes: RwLock<VecDeque<Duration>>,
}

impl OverallMetrics {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            successful_traversals: AtomicU64::new(0),
            failed_traversals: AtomicU64::new(0),
            methods_used: RwLock::new(HashMap::new()),
            bytes_transferred: AtomicU64::new(0),
            connection_lifetimes: RwLock::new(VecDeque::with_capacity(MAX_SAMPLES)),
        }
    }

    pub fn record_traversal(&self, method: &str, success: bool) {
        if success {
            self.successful_traversals.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_traversals.fetch_add(1, Ordering::Relaxed);
        }

        let mut methods = self.methods_used.write();
        methods.entry(method.to_string())
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_transferred(&self, bytes: u64) {
        self.bytes_transferred.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_connection_lifetime(&self, lifetime: Duration) {
        let mut lifetimes = self.connection_lifetimes.write();
        if lifetimes.len() >= MAX_SAMPLES {
            lifetimes.pop_front();
        }
        lifetimes.push_back(lifetime);
    }

    fn success_rate(&self) -> f64 {
        let total = self.successful_traversals.load(Ordering::Relaxed) +
            self.failed_traversals.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let successes = self.successful_traversals.load(Ordering::Relaxed);
        successes as f64 / total as f64
    }

    fn format_text(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "  Uptime: {:?}\n",
            self.start_time.elapsed()
        ));

        output.push_str(&format!(
            "  Traversals: {} successful, {} failed ({:.1}% success rate)\n",
            self.successful_traversals.load(Ordering::Relaxed),
            self.failed_traversals.load(Ordering::Relaxed),
            self.success_rate() * 100.0
        ));

        output.push_str(&format!(
            "  Data transferred: {:.2} MB\n",
            self.bytes_transferred.load(Ordering::Relaxed) as f64 / 1_048_576.0
        ));

        // Methods used
        let methods = self.methods_used.read();
        output.push_str("  Methods used:\n");
        for (method, count) in methods.iter() {
            output.push_str(&format!(
                "    {}: {} times\n",
                method,
                count.load(Ordering::Relaxed)
            ));
        }

        output
    }

    fn to_json(&self) -> serde_json::Value {
        let methods = self.methods_used.read();

        serde_json::json!({
            "uptime_seconds": self.start_time.elapsed().as_secs(),
            "successful_traversals": self.successful_traversals.load(Ordering::Relaxed),
            "failed_traversals": self.failed_traversals.load(Ordering::Relaxed),
            "success_rate": self.success_rate(),
            "bytes_transferred": self.bytes_transferred.load(Ordering::Relaxed),
            "methods_used": methods.iter().map(|(k, v)| {
                (k.clone(), v.load(Ordering::Relaxed))
            }).collect::<HashMap<_, _>>(),
        })
    }

    fn to_prometheus(&self, prefix: &str) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "{}_uptime_seconds {{}} {}\n",
            prefix,
            self.start_time.elapsed().as_secs()
        ));

        output.push_str(&format!(
            "{}_successful_total {{}} {}\n",
            prefix,
            self.successful_traversals.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "{}_failed_total {{}} {}\n",
            prefix,
            self.failed_traversals.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "{}_bytes_transferred_total {{}} {}\n",
            prefix,
            self.bytes_transferred.load(Ordering::Relaxed)
        ));

        output
    }

    fn reset(&self) {
        self.successful_traversals.store(0, Ordering::Relaxed);
        self.failed_traversals.store(0, Ordering::Relaxed);
        self.methods_used.write().clear();
        self.bytes_transferred.store(0, Ordering::Relaxed);
        self.connection_lifetimes.write().clear();
    }
}

/// Response time percentiles
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ResponsePercentiles {
    pub p50: Duration,
    pub p90: Duration,
    pub p99: Duration,
    pub p999: Duration,
}

/// Helper struct for STUN metrics
pub struct StunMetricsHelper {
    server: String,
    start_time: Instant,
}

impl StunMetricsHelper {
    pub fn new(server: String) -> Self {
        NatMetricsCollector::global().stun.record_request(&server);
        Self {
            server,
            start_time: Instant::now(),
        }
    }

    pub fn record_response(&self, success: bool) {
        let elapsed = self.start_time.elapsed();
        NatMetricsCollector::global().stun.record_response(&self.server, success, elapsed);
    }
}

// Convenience functions

/// Record NAT type detection result
pub fn record_nat_type_detection(nat_type: &str, confidence: &str) {
    NatMetricsCollector::global().stun.record_nat_type(nat_type, confidence);
}

/// Record NAT behavior
pub fn record_nat_behavior(mapping: &str, filtering: &str) {
    NatMetricsCollector::global().stun.record_behavior(mapping, filtering);
}

/// Record IP version usage
pub fn record_ip_version_usage(version: &str, context: &str) {
    let key = format!("{}_{}", version, context);
    NatMetricsCollector::global().overall.record_traversal(&key, true);
}

/// Record ICE candidate
pub fn record_ice_candidate(candidate_type: &str) {
    NatMetricsCollector::global().ice.gathering.record_candidate(candidate_type);
}

/// Record ICE gathering
pub fn record_ice_gathering(duration: Duration, success: bool) {
    NatMetricsCollector::global().ice.gathering.record_gathering(duration, success);
}

/// Record ICE session
pub fn record_ice_session(duration: Duration, success: bool) {
    NatMetricsCollector::global().ice.sessions.record_session(duration, success);
}

/// Record hole punch attempt
pub fn record_hole_punch_attempt(peer: SocketAddr) {
    NatMetricsCollector::global().hole_punch.record_attempt(peer);
}

/// Record hole punch success
pub fn record_hole_punch_success(peer: SocketAddr, duration: Duration, strategy: String) {
    NatMetricsCollector::global().hole_punch.record_success(peer, duration, strategy);
}

/// Record port forwarding attempt
pub fn record_port_forwarding_attempt(protocol: &str) {
    NatMetricsCollector::global().port_forwarding.record_attempt(protocol);
}

/// Record port forwarding success
pub fn record_port_forwarding_success(protocol: &str, duration: Duration) {
    NatMetricsCollector::global().port_forwarding.record_success(protocol, duration);
}

/// Get metrics summary
pub fn get_metrics_summary() -> String {
    NatMetricsCollector::global().export()
}

/// Export metrics in specific format
pub fn export_metrics(format: MetricsExportFormat) -> String {
    let collector = NatMetricsCollector::global();
    collector.set_export_format(format);
    collector.export()
}

/// Reset all metrics
pub fn reset_metrics() {
    NatMetricsCollector::global().reset();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_metrics() {
        let metrics = StunMetrics::new();

        metrics.record_request("stun.example.com");
        metrics.record_response("stun.example.com", true, Duration::from_millis(50));
        metrics.record_response("stun.example.com", true, Duration::from_millis(100));
        metrics.record_response("stun.example.com", false, Duration::from_millis(0));

        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.total_successes.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.total_failures.load(Ordering::Relaxed), 1);

        let percentiles = metrics.response_percentiles();
        assert!(percentiles.p50.as_millis() > 0);
    }

    #[test]
    fn test_metrics_export() {
        let collector = NatMetricsCollector::new();

        // Add some test data
        collector.stun.record_request("test.server");
        collector.stun.record_response("test.server", true, Duration::from_millis(50));

        // Test text export
        collector.set_export_format(MetricsExportFormat::Text);
        let text = collector.export();
        assert!(text.contains("NAT Traversal Metrics"));
        assert!(text.contains("STUN Operations"));

        // Test JSON export
        collector.set_export_format(MetricsExportFormat::Json);
        let json = collector.export();
        assert!(json.contains("\"stun\""));
        assert!(json.contains("\"total_requests\""));

        // Test Prometheus export
        collector.set_export_format(MetricsExportFormat::Prometheus);
        let prometheus = collector.export();
        assert!(prometheus.contains("# HELP"));
        assert!(prometheus.contains("stun_requests_total"));
    }

    #[test]
    fn test_percentile_calculation() {
        let metrics = StunMetrics::new();

        // Add samples
        for i in 1..=100 {
            metrics.record_response("test", true, Duration::from_millis(i));
        }

        let percentiles = metrics.response_percentiles();
        assert_eq!(percentiles.p50.as_millis(), 50);
        assert_eq!(percentiles.p90.as_millis(), 90);
        assert_eq!(percentiles.p99.as_millis(), 99);
    }
}