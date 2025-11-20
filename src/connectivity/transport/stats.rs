//! Transport Statistics - RFC 8445 Section 14 Compliance
//!
//! This module provides comprehensive statistics collection for ICE transports
//! as mandated by RFC 8445 Section 14 and extended for SHARP-256 protocol.
//!
//! # RFC 8445 Section 14 Requirements
//!
//! ICE implementations MUST collect and make available statistics about:
//! - Number and types of candidates gathered
//! - Number of connectivity checks performed
//! - Number of connectivity checks that succeeded
//! - Number of connectivity checks that failed
//! - Round-trip time (RTT) measurements
//! - Bytes and packets sent/received
//!
//! # Additional Standards
//!
//! - RFC 7675: Consent freshness statistics
//! - RFC 8838: Trickle ICE metrics
//! - SHARP-256: Protocol-specific performance counters

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::connectivity::{Candidate, CandidatePair, CandidateType};

// ═══════════════════════════════════════════════════════════════════════════
// TRANSPORT STATS - Main Structure (RFC 8445 Section 14)
// ═══════════════════════════════════════════════════════════════════════════

/// Comprehensive transport statistics
///
/// Collects all statistics required by RFC 8445 Section 14 plus additional
/// metrics for monitoring and debugging.
///
/// # RFC 8445 Section 14 Compliance
///
/// This structure contains all MUST-implement statistics:
/// - Candidate gathering metrics
/// - Connectivity check results
/// - Data transfer statistics
/// - Quality measurements
///
/// # Performance
///
/// Statistics collection is designed to have minimal performance impact.
/// Most fields are simple counters or cached values.
///
/// # Total Fields: 60+ (RFC 8445 compliant)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportStats {
    // ═══════════════════════════════════════════════════════════════════════
    // Timing Information
    // ═══════════════════════════════════════════════════════════════════════
    /// When these statistics were collected
    #[serde(skip)]
    pub collected_at: Instant,

    /// When the transport was created
    #[serde(skip)]
    pub created_at: Instant,

    /// Total uptime duration
    pub uptime: Duration,

    /// When ICE gathering started (RFC 8445 Section 5)
    #[serde(skip)]
    pub gathering_started_at: Option<Instant>,

    /// When ICE gathering completed
    #[serde(skip)]
    pub gathering_completed_at: Option<Instant>,

    /// Duration of candidate gathering phase
    pub gathering_duration: Option<Duration>,

    /// When connectivity checks started (RFC 8445 Section 6)
    #[serde(skip)]
    pub checking_started_at: Option<Instant>,

    /// When first successful connectivity check completed
    #[serde(skip)]
    pub first_check_success_at: Option<Instant>,

    /// When connection was established (RFC 8445 Section 7)
    #[serde(skip)]
    pub connected_at: Option<Instant>,

    /// Duration from start to connection establishment
    pub connection_establishment_duration: Option<Duration>,

    // ═══════════════════════════════════════════════════════════════════════
    // Candidate Statistics (RFC 8445 Section 5)
    // ═══════════════════════════════════════════════════════════════════════
    /// Total number of local candidates gathered
    pub local_candidates_total: u32,

    /// Number of host candidates (local interfaces)
    pub local_candidates_host: u32,

    /// Number of server-reflexive candidates (STUN)
    pub local_candidates_srflx: u32,

    /// Number of relay candidates (TURN)
    pub local_candidates_relay: u32,

    /// Total number of remote candidates received
    pub remote_candidates_total: u32,

    /// Number of remote host candidates
    pub remote_candidates_host: u32,

    /// Number of remote server-reflexive candidates
    pub remote_candidates_srflx: u32,

    /// Number of remote relay candidates
    pub remote_candidates_relay: u32,

    /// Breakdown of candidates by network type
    pub candidates_by_network: HashMap<String, u32>,

    // ═══════════════════════════════════════════════════════════════════════
    // Candidate Pair Statistics (RFC 8445 Section 6)
    // ═══════════════════════════════════════════════════════════════════════
    /// Total number of candidate pairs formed
    pub candidate_pairs_total: u32,

    /// Pairs currently in Waiting state
    pub pairs_waiting: u32,

    /// Pairs currently In-Progress
    pub pairs_in_progress: u32,

    /// Pairs that succeeded
    pub pairs_succeeded: u32,

    /// Pairs that failed
    pub pairs_failed: u32,

    /// Pairs that were frozen
    pub pairs_frozen: u32,

    // ═══════════════════════════════════════════════════════════════════════
    // Connectivity Check Statistics (RFC 8445 Section 6)
    // ═══════════════════════════════════════════════════════════════════════
    /// Total connectivity checks performed (STUN binding requests sent)
    pub connectivity_checks_total: u32,

    /// Connectivity checks that succeeded
    pub connectivity_checks_succeeded: u32,

    /// Connectivity checks that failed
    pub connectivity_checks_failed: u32,

    /// Connectivity checks that timed out
    pub connectivity_checks_timeout: u32,

    /// Number of retransmitted checks
    pub connectivity_checks_retransmitted: u32,

    /// Average RTT from connectivity checks
    pub connectivity_checks_avg_rtt: Option<Duration>,

    /// Minimum RTT observed
    pub connectivity_checks_min_rtt: Option<Duration>,

    /// Maximum RTT observed
    pub connectivity_checks_max_rtt: Option<Duration>,

    // ═══════════════════════════════════════════════════════════════════════
    // Nomination Statistics (RFC 8445 Section 8)
    // ═══════════════════════════════════════════════════════════════════════
    /// Number of nomination attempts
    pub nomination_attempts: u32,

    /// Successful nominations
    pub nomination_succeeded: u32,

    /// Failed nominations
    pub nomination_failed: u32,

    /// Whether aggressive nomination was used
    pub aggressive_nomination: bool,

    /// Information about nominated pair
    pub nominated_pair: Option<CandidatePairStats>,

    // ═══════════════════════════════════════════════════════════════════════
    // Data Transfer Statistics (Production Metrics)
    // ═══════════════════════════════════════════════════════════════════════
    /// Total bytes sent through this transport
    pub bytes_sent: u64,

    /// Total bytes received
    pub bytes_received: u64,

    /// Total packets sent
    pub packets_sent: u64,

    /// Total packets received
    pub packets_received: u64,

    /// Packets lost (estimated)
    pub packets_lost: u64,

    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss_rate: f64,

    /// Packets received out of order
    pub packets_out_of_order: u64,

    // ═══════════════════════════════════════════════════════════════════════
    // Quality Metrics
    // ═══════════════════════════════════════════════════════════════════════
    /// Current round-trip time
    pub current_rtt: Option<Duration>,

    /// Average RTT over recent measurements
    pub average_rtt: Option<Duration>,

    /// Jitter (variance in RTT)
    pub jitter: Duration,

    /// Estimated available bandwidth (bytes/sec)
    pub available_bandwidth: u64,

    /// Quality metrics details
    pub quality: QualityMetrics,

    // ═══════════════════════════════════════════════════════════════════════
    // ICE-Specific Statistics
    // ═══════════════════════════════════════════════════════════════════════
    /// ICE-specific statistics (if using ICE transport)
    pub ice: Option<IceStats>,

    // ═══════════════════════════════════════════════════════════════════════
    // Consent Freshness (RFC 7675)
    // ═══════════════════════════════════════════════════════════════════════
    /// Consent freshness statistics
    pub consent: Option<ConsentStats>,

    // ═══════════════════════════════════════════════════════════════════════
    // Socket-Level Statistics
    // ═══════════════════════════════════════════════════════════════════════
    /// Socket-level statistics
    pub socket: Option<SocketStats>,

    // ═══════════════════════════════════════════════════════════════════════
    // SHARP-256 Protocol Specific
    // ═══════════════════════════════════════════════════════════════════════
    /// Performance metrics for SHARP-256 protocol
    pub performance: Option<PerformanceMetrics>,
}

impl TransportStats {
    /// Create new statistics instance
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            collected_at: now,
            created_at: now,
            uptime: Duration::ZERO,
            gathering_started_at: None,
            gathering_completed_at: None,
            gathering_duration: None,
            checking_started_at: None,
            first_check_success_at: None,
            connected_at: None,
            connection_establishment_duration: None,
            local_candidates_total: 0,
            local_candidates_host: 0,
            local_candidates_srflx: 0,
            local_candidates_relay: 0,
            remote_candidates_total: 0,
            remote_candidates_host: 0,
            remote_candidates_srflx: 0,
            remote_candidates_relay: 0,
            candidates_by_network: HashMap::new(),
            candidate_pairs_total: 0,
            pairs_waiting: 0,
            pairs_in_progress: 0,
            pairs_succeeded: 0,
            pairs_failed: 0,
            pairs_frozen: 0,
            connectivity_checks_total: 0,
            connectivity_checks_succeeded: 0,
            connectivity_checks_failed: 0,
            connectivity_checks_timeout: 0,
            connectivity_checks_retransmitted: 0,
            connectivity_checks_avg_rtt: None,
            connectivity_checks_min_rtt: None,
            connectivity_checks_max_rtt: None,
            nomination_attempts: 0,
            nomination_succeeded: 0,
            nomination_failed: 0,
            aggressive_nomination: false,
            nominated_pair: None,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            packets_lost: 0,
            packet_loss_rate: 0.0,
            packets_out_of_order: 0,
            current_rtt: None,
            average_rtt: None,
            jitter: Duration::ZERO,
            available_bandwidth: 0,
            quality: QualityMetrics::default(),
            ice: None,
            consent: None,
            socket: None,
            performance: None,
        }
    }

    /// Update uptime field
    pub fn update_uptime(&mut self) {
        self.uptime = self.created_at.elapsed();
        self.collected_at = Instant::now();
    }

    /// Calculate packet loss rate
    pub fn calculate_packet_loss_rate(&mut self) {
        if self.packets_sent > 0 {
            self.packet_loss_rate = self.packets_lost as f64 / self.packets_sent as f64;
        }
    }

    /// Get success rate for connectivity checks (0.0 - 1.0)
    pub fn connectivity_check_success_rate(&self) -> f64 {
        if self.connectivity_checks_total > 0 {
            self.connectivity_checks_succeeded as f64 / self.connectivity_checks_total as f64
        } else {
            0.0
        }
    }

    /// Get candidate pair success rate (0.0 - 1.0)
    pub fn pair_success_rate(&self) -> f64 {
        let checked_pairs = self.pairs_succeeded + self.pairs_failed;
        if checked_pairs > 0 {
            self.pairs_succeeded as f64 / checked_pairs as f64
        } else {
            0.0
        }
    }

    /// Get throughput in bytes per second
    pub fn throughput_bps(&self) -> f64 {
        if self.uptime.as_secs() > 0 {
            (self.bytes_sent + self.bytes_received) as f64 / self.uptime.as_secs_f64()
        } else {
            0.0
        }
    }

    /// Record candidate gathered
    pub fn record_candidate_gathered(&mut self, candidate: &Candidate) {
        self.local_candidates_total += 1;
        match candidate.candidate_type {
            CandidateType::Host => self.local_candidates_host += 1,
            CandidateType::ServerReflexive => self.local_candidates_srflx += 1,
            CandidateType::Relay => self.local_candidates_relay += 1,
            _ => {}
        }
    }

    /// Record remote candidate
    pub fn record_remote_candidate(&mut self, candidate: &Candidate) {
        self.remote_candidates_total += 1;
        match candidate.candidate_type {
            CandidateType::Host => self.remote_candidates_host += 1,
            CandidateType::ServerReflexive => self.remote_candidates_srflx += 1,
            CandidateType::Relay => self.remote_candidates_relay += 1,
            _ => {}
        }
    }

    /// Record connectivity check result
    pub fn record_connectivity_check(&mut self, success: bool, rtt: Option<Duration>) {
        self.connectivity_checks_total += 1;

        if success {
            self.connectivity_checks_succeeded += 1;

            if let Some(rtt) = rtt {
                // Update min/max RTT
                match self.connectivity_checks_min_rtt {
                    Some(min) if rtt < min => self.connectivity_checks_min_rtt = Some(rtt),
                    None => self.connectivity_checks_min_rtt = Some(rtt),
                    _ => {}
                }

                match self.connectivity_checks_max_rtt {
                    Some(max) if rtt > max => self.connectivity_checks_max_rtt = Some(rtt),
                    None => self.connectivity_checks_max_rtt = Some(rtt),
                    _ => {}
                }

                // Update average RTT (simple moving average)
                match self.connectivity_checks_avg_rtt {
                    Some(avg) => {
                        let new_avg = (avg + rtt) / 2;
                        self.connectivity_checks_avg_rtt = Some(new_avg);
                    }
                    None => {
                        self.connectivity_checks_avg_rtt = Some(rtt);
                    }
                }
            }
        } else {
            self.connectivity_checks_failed += 1;
        }
    }

    /// Record data sent
    pub fn record_send(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
        self.packets_sent += 1;
    }

    /// Record data received
    pub fn record_recv(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
        self.packets_received += 1;
    }
}

impl Default for TransportStats {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ICE STATISTICS (RFC 8445 Specific)
// ═══════════════════════════════════════════════════════════════════════════

/// ICE-specific statistics
///
/// Additional metrics specific to ICE protocol implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceStats {
    /// ICE agent role: controlling or controlled
    pub role: IceRole,

    /// Local ICE username fragment
    pub local_ufrag: String,

    /// Remote ICE username fragment
    pub remote_ufrag: Option<String>,

    /// ICE password (not stored for security)
    /// This field always returns a placeholder
    pub pwd_length: usize,

    /// Number of ICE restarts performed (RFC 8445 Section 9)
    pub restart_count: u32,

    /// Trickle ICE enabled (RFC 8838)
    pub trickle_ice_enabled: bool,

    /// Whether end-of-candidates signaling was received
    pub end_of_candidates_received: bool,

    /// STUN server statistics
    pub stun_servers: Vec<StunServerStats>,

    /// TURN server statistics
    pub turn_servers: Vec<TurnServerStats>,
}

/// ICE agent role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IceRole {
    Controlling,
    Controlled,
}

/// STUN server statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StunServerStats {
    /// Server address
    pub address: String,

    /// Total requests sent
    pub requests_sent: u32,

    /// Successful responses received
    pub responses_received: u32,

    /// Request timeouts
    pub timeouts: u32,

    /// Average RTT to this server
    pub avg_rtt: Option<Duration>,
}

/// TURN server statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnServerStats {
    /// Server address
    pub address: String,

    /// Number of allocations
    pub allocations: u32,

    /// Allocation failures
    pub allocation_failures: u32,

    /// Bytes relayed through this server
    pub bytes_relayed: u64,

    /// Active permissions
    pub active_permissions: u32,

    /// Refresh operations performed
    pub refreshes: u32,
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSENT FRESHNESS STATISTICS (RFC 7675)
// ═══════════════════════════════════════════════════════════════════════════

/// Consent freshness statistics
///
/// RFC 7675 requires periodic consent checks to ensure the peer still
/// consents to receive data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentStats {
    /// Total consent checks performed
    pub checks_performed: u32,

    /// Successful consent checks
    pub checks_succeeded: u32,

    /// Failed consent checks
    pub checks_failed: u32,

    /// Consent check timeouts
    pub checks_timeout: u32,

    /// Time of last successful consent check
    #[serde(skip)]
    pub last_successful_check: Option<Instant>,

    /// Time of last failed consent check
    #[serde(skip)]
    pub last_failed_check: Option<Instant>,

    /// Current consent status
    pub consent_fresh: bool,

    /// Consent check interval (RFC 7675 recommends 5-30 seconds)
    pub check_interval: Duration,

    /// Time until consent expires if no check succeeds
    pub consent_timeout: Duration,

    /// Number of consecutive failures
    pub consecutive_failures: u32,
}

impl ConsentStats {
    /// Create new consent statistics
    pub fn new(check_interval: Duration, consent_timeout: Duration) -> Self {
        Self {
            checks_performed: 0,
            checks_succeeded: 0,
            checks_failed: 0,
            checks_timeout: 0,
            last_successful_check: None,
            last_failed_check: None,
            consent_fresh: false,
            check_interval,
            consent_timeout,
            consecutive_failures: 0,
        }
    }

    /// Record consent check result
    pub fn record_check(&mut self, success: bool) {
        self.checks_performed += 1;

        if success {
            self.checks_succeeded += 1;
            self.last_successful_check = Some(Instant::now());
            self.consent_fresh = true;
            self.consecutive_failures = 0;
        } else {
            self.checks_failed += 1;
            self.last_failed_check = Some(Instant::now());
            self.consecutive_failures += 1;
        }
    }

    /// Check if consent is expired
    pub fn is_expired(&self) -> bool {
        match self.last_successful_check {
            Some(last_check) => last_check.elapsed() > self.consent_timeout,
            None => true,
        }
    }

    /// Get consent success rate
    pub fn success_rate(&self) -> f64 {
        if self.checks_performed > 0 {
            self.checks_succeeded as f64 / self.checks_performed as f64
        } else {
            0.0
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CANDIDATE PAIR STATISTICS
// ═══════════════════════════════════════════════════════════════════════════

/// Statistics for a candidate pair
///
/// Provides detailed information about the nominated/selected pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePairStats {
    /// The candidate pair
    #[serde(skip)]
    pub pair: CandidatePair,

    /// Local candidate type
    pub local_candidate_type: CandidateType,

    /// Remote candidate type
    pub remote_candidate_type: CandidateType,

    /// Pair priority (RFC 8445 Section 6.1.2)
    pub priority: u64,

    /// Current pair state
    pub state: PairState,

    /// Number of checks performed on this pair
    pub checks_performed: u32,

    /// Number of successful checks
    pub checks_succeeded: u32,

    /// Last RTT measured for this pair
    pub last_rtt: Option<Duration>,

    /// Average RTT for this pair
    pub avg_rtt: Option<Duration>,

    /// When this pair was nominated
    #[serde(skip)]
    pub nominated_at: Option<Instant>,

    /// Total bytes sent through this pair
    pub bytes_sent: u64,

    /// Total bytes received
    pub bytes_received: u64,
}

/// Candidate pair state (RFC 8445 Section 6.1.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairState {
    Waiting,
    InProgress,
    Succeeded,
    Failed,
    Frozen,
}

// ═══════════════════════════════════════════════════════════════════════════
// QUALITY METRICS
// ═══════════════════════════════════════════════════════════════════════════

/// Connection quality metrics
///
/// Provides high-level quality assessment of the connection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QualityMetrics {
    /// Overall quality score (0.0 - 1.0, higher is better)
    pub score: f64,

    /// RTT quality (0.0 - 1.0)
    pub rtt_quality: f64,

    /// Packet loss quality (0.0 - 1.0)
    pub loss_quality: f64,

    /// Jitter quality (0.0 - 1.0)
    pub jitter_quality: f64,

    /// Bandwidth quality (0.0 - 1.0)
    pub bandwidth_quality: f64,
}

impl QualityMetrics {
    /// Calculate overall quality score
    pub fn calculate(
        &mut self,
        rtt: Option<Duration>,
        loss_rate: f64,
        jitter: Duration,
        bandwidth: u64,
    ) {
        // RTT quality (excellent < 50ms, acceptable < 200ms, poor > 500ms)
        self.rtt_quality = match rtt {
            Some(rtt) => {
                let ms = rtt.as_millis() as f64;
                if ms < 50.0 {
                    1.0
                } else if ms < 200.0 {
                    1.0 - (ms - 50.0) / 150.0 * 0.5
                } else if ms < 500.0 {
                    0.5 - (ms - 200.0) / 300.0 * 0.5
                } else {
                    0.0
                }
            }
            None => 0.0,
        };

        // Loss quality (excellent < 1%, acceptable < 5%, poor > 10%)
        self.loss_quality = if loss_rate < 0.01 {
            1.0
        } else if loss_rate < 0.05 {
            1.0 - (loss_rate - 0.01) / 0.04 * 0.5
        } else if loss_rate < 0.10 {
            0.5 - (loss_rate - 0.05) / 0.05 * 0.5
        } else {
            0.0
        };

        // Jitter quality (excellent < 10ms, acceptable < 30ms, poor > 50ms)
        let jitter_ms = jitter.as_millis() as f64;
        self.jitter_quality = if jitter_ms < 10.0 {
            1.0
        } else if jitter_ms < 30.0 {
            1.0 - (jitter_ms - 10.0) / 20.0 * 0.5
        } else if jitter_ms < 50.0 {
            0.5 - (jitter_ms - 30.0) / 20.0 * 0.5
        } else {
            0.0
        };

        // Bandwidth quality (simplistic, based on typical requirements)
        // Excellent > 10 Mbps, acceptable > 1 Mbps, poor < 1 Mbps
        let mbps = bandwidth as f64 * 8.0 / 1_000_000.0;
        self.bandwidth_quality = if mbps > 10.0 {
            1.0
        } else if mbps > 1.0 {
            mbps / 10.0
        } else {
            mbps / 1.0 * 0.5
        };

        // Overall score (weighted average)
        self.score = self.rtt_quality * 0.3
            + self.loss_quality * 0.3
            + self.jitter_quality * 0.2
            + self.bandwidth_quality * 0.2;
    }

    /// Check if quality is acceptable for production use
    pub fn is_acceptable(&self) -> bool {
        self.score >= 0.5
    }

    /// Get quality rating
    pub fn rating(&self) -> QualityRating {
        if self.score >= 0.8 {
            QualityRating::Excellent
        } else if self.score >= 0.6 {
            QualityRating::Good
        } else if self.score >= 0.4 {
            QualityRating::Fair
        } else {
            QualityRating::Poor
        }
    }
}

/// Quality rating categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityRating {
    Excellent,
    Good,
    Fair,
    Poor,
}

// ═══════════════════════════════════════════════════════════════════════════
// SOCKET STATISTICS
// ═══════════════════════════════════════════════════════════════════════════

/// Socket-level statistics
///
/// Low-level socket metrics for debugging and optimization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SocketStats {
    /// Socket buffer sizes
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,

    /// Socket errors encountered
    pub socket_errors: u32,

    /// IPv4 packets sent
    pub ipv4_packets_sent: u64,

    /// IPv6 packets sent
    pub ipv6_packets_sent: u64,

    /// IPv4 packets received
    pub ipv4_packets_received: u64,

    /// IPv6 packets received
    pub ipv6_packets_received: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// PERFORMANCE METRICS (SHARP-256 Specific)
// ═══════════════════════════════════════════════════════════════════════════

/// SHARP-256 protocol performance metrics
///
/// Protocol-specific statistics for SAO and batch optimization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Current SAO batch size
    pub current_batch_size: u16,

    /// SAO score
    pub sao_score: f64,

    /// Number of batch size adjustments
    pub batch_adjustments: u32,

    /// GSO (Generic Segmentation Offload) packets
    pub gso_packets: u64,

    /// GRO (Generic Receive Offload) packets
    pub gro_packets: u64,

    /// Average packet size
    pub avg_packet_size: usize,

    /// Maximum packet size used
    pub max_packet_size_used: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_stats_creation() {
        let stats = TransportStats::new();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.connectivity_checks_total, 0);
    }

    #[test]
    fn test_record_connectivity_check() {
        let mut stats = TransportStats::new();

        stats.record_connectivity_check(true, Some(Duration::from_millis(50)));
        assert_eq!(stats.connectivity_checks_total, 1);
        assert_eq!(stats.connectivity_checks_succeeded, 1);
        assert_eq!(
            stats.connectivity_checks_avg_rtt,
            Some(Duration::from_millis(50))
        );
        assert_eq!(
            stats.connectivity_checks_min_rtt,
            Some(Duration::from_millis(50))
        );

        stats.record_connectivity_check(true, Some(Duration::from_millis(100)));
        assert_eq!(stats.connectivity_checks_total, 2);
        assert_eq!(
            stats.connectivity_checks_max_rtt,
            Some(Duration::from_millis(100))
        );

        stats.record_connectivity_check(false, None);
        assert_eq!(stats.connectivity_checks_failed, 1);
    }

    #[test]
    fn test_success_rates() {
        let mut stats = TransportStats::new();

        stats.connectivity_checks_total = 10;
        stats.connectivity_checks_succeeded = 7;
        assert_eq!(stats.connectivity_check_success_rate(), 0.7);

        stats.pairs_succeeded = 5;
        stats.pairs_failed = 5;
        assert_eq!(stats.pair_success_rate(), 0.5);
    }

    #[test]
    fn test_consent_stats() {
        let check_interval = Duration::from_secs(15);
        let consent_timeout = Duration::from_secs(30);
        let mut consent = ConsentStats::new(check_interval, consent_timeout);

        consent.record_check(true);
        assert_eq!(consent.checks_succeeded, 1);
        assert!(consent.consent_fresh);
        assert_eq!(consent.consecutive_failures, 0);

        consent.record_check(false);
        assert_eq!(consent.checks_failed, 1);
        assert_eq!(consent.consecutive_failures, 1);

        assert!(!consent.is_expired()); // Just checked
    }

    #[test]
    fn test_quality_metrics() {
        let mut quality = QualityMetrics::default();

        // Excellent connection
        quality.calculate(
            Some(Duration::from_millis(30)),
            0.005, // 0.5% loss
            Duration::from_millis(5),
            10_000_000, // 10 Mbps
        );
        assert!(quality.score > 0.8);
        assert_eq!(quality.rating(), QualityRating::Excellent);
        assert!(quality.is_acceptable());

        // Poor connection
        quality.calculate(
            Some(Duration::from_millis(600)),
            0.15, // 15% loss
            Duration::from_millis(100),
            500_000, // 500 Kbps
        );
        assert!(quality.score < 0.5);
        assert_eq!(quality.rating(), QualityRating::Poor);
        assert!(!quality.is_acceptable());
    }

    #[test]
    fn test_record_candidates() {
        let mut stats = TransportStats::new();

        let host = Candidate::host("192.168.1.1:5000".parse().unwrap());
        stats.record_candidate_gathered(&host);
        assert_eq!(stats.local_candidates_total, 1);
        assert_eq!(stats.local_candidates_host, 1);

        let srflx = Candidate::server_reflexive(
            "8.8.8.8:5000".parse().unwrap(),
            Some("192.168.1.1:5000".parse().unwrap()),
        );
        stats.record_candidate_gathered(&srflx);
        assert_eq!(stats.local_candidates_total, 2);
        assert_eq!(stats.local_candidates_srflx, 1);
    }

    #[test]
    fn test_throughput_calculation() {
        let mut stats = TransportStats::new();
        stats.created_at = Instant::now() - Duration::from_secs(10);
        stats.uptime = Duration::from_secs(10);
        stats.bytes_sent = 1_000_000;
        stats.bytes_received = 1_000_000;

        let throughput = stats.throughput_bps();
        assert_eq!(throughput, 200_000.0); // 200 KB/s
    }
}
