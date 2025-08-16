use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;

/// STUN service monitor
pub struct StunMonitor {
    metrics: Arc<RwLock<ClientMetrics>>,
    start_time: Instant,
}

impl StunMonitor {
    /// Create new monitor
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(ClientMetrics::default())),
            start_time: Instant::now(),
        }
    }

    /// Start monitoring tasks
    pub async fn start_monitoring(&self) {
        // Background monitoring tasks would be started here
        tracing::info!("STUN monitoring started");
    }

    /// Record request result
    pub async fn record_request_result(&self, result: &NatResult<SocketAddr>) {
        let mut metrics = self.metrics.write().await;
        metrics.total_requests += 1;

        match result {
            Ok(_) => metrics.successful_requests += 1,
            Err(_) => metrics.failed_requests += 1,
        }
    }

    /// Record NAT detection result
    pub async fn record_nat_detection(&self, nat_type: &NatType, behavior: &NatBehavior) {
        let mut metrics = self.metrics.write().await;
        metrics.nat_detections += 1;

        // Record NAT type distribution
        *metrics.nat_type_distribution.entry(*nat_type).or_insert(0) += 1;

        // Record P2P scores for analysis
        metrics.p2p_scores.push(behavior.p2p_score());
    }

    /// Record P2P assessment
    pub async fn record_p2p_assessment(&self, score: f64) {
        let mut metrics = self.metrics.write().await;
        metrics.p2p_assessments += 1;
        metrics.p2p_scores.push(score);
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> ClientMetrics {
        let metrics = self.metrics.read().await;
        let mut result = metrics.clone();
        result.uptime = self.start_time.elapsed();
        result
    }

    /// Shutdown monitor
    pub async fn shutdown(&self) -> NatResult<()> {
        tracing::info!("STUN monitoring shutdown");
        Ok(())
    }
}

/// Client performance metrics
#[derive(Debug, Clone, Default)]
pub struct ClientMetrics {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub nat_detections: u64,
    pub p2p_assessments: u64,
    pub nat_type_distribution: HashMap<NatType, u64>,
    pub p2p_scores: Vec<f64>,
    pub uptime: Duration,
}

impl ClientMetrics {
    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.successful_requests as f64 / self.total_requests as f64
        }
    }

    /// Calculate average P2P score
    pub fn average_p2p_score(&self) -> f64 {
        if self.p2p_scores.is_empty() {
            0.0
        } else {
            self.p2p_scores.iter().sum::<f64>() / self.p2p_scores.len() as f64
        }
    }

    /// Get most common NAT type
    pub fn most_common_nat_type(&self) -> Option<NatType> {
        self.nat_type_distribution.iter()
            .max_by_key(|(_, &count)| count)
            .map(|(&nat_type, _)| nat_type)
    }
}

/// Server-specific metrics
#[derive(Debug, Clone)]
pub struct ServerMetrics {
    pub requests_sent: AtomicU64,
    pub responses_received: AtomicU64,
    pub timeouts: AtomicU64,
    pub total_response_time: AtomicU64,
    pub last_seen: std::sync::RwLock<Option<Instant>>,
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self {
            requests_sent: AtomicU64::new(0),
            responses_received: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            total_response_time: AtomicU64::new(0),
            last_seen: std::sync::RwLock::new(None),
        }
    }
}

impl ServerMetrics {
    /// Record request sent
    pub fn record_request(&self) {
        self.requests_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record response received
    pub fn record_response(&self, response_time: Duration) {
        self.responses_received.fetch_add(1, Ordering::Relaxed);
        self.total_response_time.fetch_add(
            response_time.as_millis() as u64,
            Ordering::Relaxed,
        );

        let mut last_seen = self.last_seen.write().unwrap();
        *last_seen = Some(Instant::now());
    }

    /// Record timeout
    pub fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        let sent = self.requests_sent.load(Ordering::Relaxed);
        let received = self.responses_received.load(Ordering::Relaxed);

        if sent == 0 {
            0.0
        } else {
            received as f64 / sent as f64
        }
    }

    /// Calculate average response time
    pub fn average_response_time(&self) -> Duration {
        let total_time = self.total_response_time.load(Ordering::Relaxed);
        let responses = self.responses_received.load(Ordering::Relaxed);

        if responses == 0 {
            Duration::from_millis(0)
        } else {
            Duration::from_millis(total_time / responses)
        }
    }
}

/// Health monitoring metrics
#[derive(Debug, Clone, Default)]
pub struct HealthMetrics {
    pub server_health_checks: u64,
    pub healthy_servers: u64,
    pub unhealthy_servers: u64,
    pub dns_resolution_failures: u64,
    pub network_errors: u64,
}

/// Network quality assessment metrics
#[derive(Debug, Clone, Default)]
pub struct NetworkQualityMetrics {
    pub average_latency: Duration,
    pub packet_loss_rate: f64,
    pub jitter: Duration,
    pub bandwidth_estimate: u64, // bytes per second
}