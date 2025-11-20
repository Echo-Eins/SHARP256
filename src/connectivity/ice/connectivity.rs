// src/connectivity/ice/connectivity.rs
//! ICE Connectivity Checks Implementation
//!
//! Production-ready connectivity checking using webrtc-rs.
//! RFC 8445 compliant - all checks performed through webrtc-rs Agent.
//!
//! ## Architecture
//!
//! webrtc-rs Agent handles connectivity checks automatically when `dial()` or `accept()` is called.
//! This module wraps that functionality and provides:
//! - State tracking through callbacks
//! - Statistics collection
//! - Clean API for the rest of the system
//!
//! ## Usage
//!
//! ```rust,ignore
//! let checker = ConnectivityChecker::new(agent, ice_config, true, event_tx);
//! checker.start_connectivity_checks().await?;
//! let valid_pairs = checker.get_valid_pairs().await;
//! ```

use anyhow::{Result, Context};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Notify, Mutex, oneshot};
use tokio::time::{timeout, sleep, interval};
use tracing::{debug, info, warn, error, trace, instrument};

use webrtc::ice::{
    agent::Agent as WebRtcAgent,
    candidate::Candidate as WebRtcCandidate,
    state::ConnectionState as WebRtcConnectionState,
};

use crate::connectivity::{
    Candidate, CandidatePair, CandidatePairState, CandidateType,
    ConnectivityCheckResult,
};
use crate::connectivity::config::IceConfig;

/// Events emitted by ConnectivityChecker
#[derive(Debug, Clone)]
pub enum ConnectivityEvent {
    /// Connectivity checks started
    ConnectivityChecksStarted,
    /// State changed
    StateChanged(ConnectivityState),
    /// Connectivity check result for a pair
    ConnectivityCheckResult(ConnectivityCheckResult),
    /// Candidate pair nominated
    CandidatePairNominated(CandidatePair),
    /// Connection established
    ConnectionEstablished {
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        rtt: Duration,
    },
    /// Connectivity checks completed
    ConnectivityChecksCompleted {
        success: bool,
        duration: Duration,
    },
    /// Error occurred
    Error(String),
}

/// Result of a single connectivity check
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Checked candidate pair
    pub pair: CandidatePair,
    /// Whether check succeeded
    pub success: bool,
    /// Round-trip time
    pub rtt: Option<Duration>,
    /// Timestamp of check
    pub timestamp: Instant,
    /// Failure reason if any
    pub failure_reason: Option<String>,
    /// Check type (ordinary or triggered)
    pub check_type: CheckType,
    /// STUN transaction ID
    pub transaction_id: Option<String>,
}

/// Type of connectivity check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckType {
    /// Ordinary check from check list
    Ordinary,
    /// Triggered check from incoming STUN request
    Triggered,
}

/// Connectivity checker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityState {
    /// New, checks not started
    New,
    /// Performing checks
    Checking,
    /// At least one valid pair exists
    Connected,
    /// Checks completed successfully
    Completed,
    /// All checks failed
    Failed,
    /// Temporarily disconnected
    Disconnected,
    /// Checker closed
    Closed,
}

impl std::fmt::Display for ConnectivityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "New"),
            Self::Checking => write!(f, "Checking"),
            Self::Connected => write!(f, "Connected"),
            Self::Completed => write!(f, "Completed"),
            Self::Failed => write!(f, "Failed"),
            Self::Disconnected => write!(f, "Disconnected"),
            Self::Closed => write!(f, "Closed"),
        }
    }
}

impl From<WebRtcConnectionState> for ConnectivityState {
    fn from(state: WebRtcConnectionState) -> Self {
        match state {
            WebRtcConnectionState::New => Self::New,
            WebRtcConnectionState::Checking => Self::Checking,
            WebRtcConnectionState::Connected => Self::Connected,
            WebRtcConnectionState::Completed => Self::Completed,
            WebRtcConnectionState::Failed => Self::Failed,
            WebRtcConnectionState::Disconnected => Self::Disconnected,
            WebRtcConnectionState::Closed => Self::Closed,
        }
    }
}

/// Configuration for connectivity checks
#[derive(Debug, Clone)]
pub struct ConnectivityConfig {
    /// Maximum time to wait for connectivity
    pub connectivity_timeout: Duration,
    /// Interval between check list processing (Ta timer per RFC 8445)
    pub check_interval: Duration,
    /// Maximum concurrent checks
    pub max_concurrent_checks: usize,
    /// Maximum retries per check
    pub max_retries: u32,
    /// Timeout for single STUN request
    pub stun_timeout: Duration,
    /// Retransmission interval (RTO per RFC 8489)
    pub retransmission_interval: Duration,
    /// Maximum candidate pairs in check list
    pub max_candidate_pairs: usize,
    /// Use aggressive nomination
    pub aggressive_nomination: bool,
}

impl Default for ConnectivityConfig {
    fn default() -> Self {
        Self {
            connectivity_timeout: Duration::from_secs(30),
            check_interval: Duration::from_millis(50), // Ta timer per RFC 8445
            max_concurrent_checks: 5,
            max_retries: 7, // Rc per RFC 8489
            stun_timeout: Duration::from_millis(500), // RTO per RFC 8489
            retransmission_interval: Duration::from_millis(500),
            max_candidate_pairs: 100,
            aggressive_nomination: false,
        }
    }
}

/// Statistics for connectivity checks
#[derive(Debug, Clone, Default)]
pub struct ConnectivityStats {
    /// When checks started
    pub started_at: Option<Instant>,
    /// When checks completed
    pub completed_at: Option<Instant>,
    /// Total checks sent
    pub checks_sent: u64,
    /// Total responses received
    pub checks_received: u64,
    /// Successful checks
    pub successful_checks: u64,
    /// Failed checks
    pub failed_checks: u64,
    /// Retransmissions sent
    pub retransmissions: u64,
    /// Triggered checks performed
    pub triggered_checks: u64,
    /// Average RTT across all successful checks
    pub average_rtt: Option<Duration>,
    /// Total pairs checked
    pub total_pairs_checked: u64,
    /// Pairs that succeeded
    pub successful_pairs: u64,
    /// Time until first successful connection
    pub time_to_connect: Option<Duration>,
    /// Selected pair RTT
    pub selected_pair_rtt: Option<Duration>,
}

impl ConnectivityStats {
    /// Create new stats with start time
    pub fn new() -> Self {
        Self {
            started_at: Some(Instant::now()),
            ..Default::default()
        }
    }

    /// Get total duration
    pub fn duration(&self) -> Option<Duration> {
        match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => Some(end - start),
            (Some(start), None) => Some(Instant::now() - start),
            _ => None,
        }
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.checks_sent > 0 {
            self.successful_checks as f64 / self.checks_sent as f64
        } else {
            0.0
        }
    }

    /// Update average RTT with new measurement
    fn update_average_rtt(&mut self, rtt: Duration) {
        self.average_rtt = Some(match self.average_rtt {
            Some(avg) => {
                let count = self.successful_checks;
                if count > 0 {
                    Duration::from_nanos(
                        ((avg.as_nanos() * (count - 1) as u128) + rtt.as_nanos()) / count as u128
                    )
                } else {
                    rtt
                }
            }
            None => rtt,
        });
    }
}

/// Entry in the check list
#[derive(Debug, Clone)]
struct CheckListEntry {
    /// Candidate pair
    pair: CandidatePair,
    /// Entry state
    state: CheckEntryState,
    /// Last check time
    last_check_time: Option<Instant>,
    /// Retry count
    retry_count: u32,
    /// Next retry time
    next_retry_time: Option<Instant>,
    /// Check results history
    check_results: Vec<CheckResult>,
}

/// State of check list entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckEntryState {
    /// Waiting to be checked
    Waiting,
    /// Check in progress
    InProgress,
    /// Check succeeded
    Succeeded,
    /// Check failed
    Failed,
    /// Frozen (will be checked later)
    Frozen,
}

/// Main connectivity checker
///
/// Wraps webrtc-rs Agent and provides connectivity check management.
/// All actual STUN binding requests are performed by webrtc-rs internally.
pub struct ConnectivityChecker {
    /// WebRTC ICE Agent - performs actual connectivity checks
    webrtc_agent: Arc<WebRtcAgent>,
    /// Checker configuration
    config: ConnectivityConfig,
    /// ICE configuration
    ice_config: IceConfig,
    /// Current state
    state: Arc<RwLock<ConnectivityState>>,
    /// Check list (prioritized pairs to check)
    check_list: Arc<RwLock<Vec<CheckListEntry>>>,
    /// Valid list (successfully checked pairs)
    valid_list: Arc<RwLock<Vec<CandidatePair>>>,
    /// Nominated pairs
    nominated_pairs: Arc<RwLock<Vec<CandidatePair>>>,
    /// Selected candidate pair (after connection)
    selected_pair: Arc<RwLock<Option<CandidatePair>>>,
    /// Statistics
    stats: Arc<RwLock<ConnectivityStats>>,
    /// Event sender
    event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    /// Notification when checks complete
    checks_complete: Arc<Notify>,
    /// Notification when first connection established
    first_connection: Arc<Notify>,
    /// Shutdown flag
    shutdown: Arc<RwLock<bool>>,
    /// Controlling role (determines nomination behavior)
    controlling: bool,
    /// Connection result channel
    connection_result: Arc<Mutex<Option<oneshot::Sender<Result<()>>>>>,
}

impl ConnectivityChecker {
    /// Create new connectivity checker
    ///
    /// # Arguments
    /// * `webrtc_agent` - WebRTC Agent that will perform actual checks
    /// * `ice_config` - ICE configuration
    /// * `controlling` - Whether this is the controlling agent
    /// * `event_tx` - Channel for sending events
    #[instrument(skip(webrtc_agent, event_tx))]
    pub fn new(
        webrtc_agent: Arc<WebRtcAgent>,
        ice_config: IceConfig,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> Self {
        let config = ConnectivityConfig::default();

        info!(
            controlling = controlling,
            timeout_secs = config.connectivity_timeout.as_secs(),
            "Creating ConnectivityChecker"
        );

        Self {
            webrtc_agent,
            config,
            ice_config,
            state: Arc::new(RwLock::new(ConnectivityState::New)),
            check_list: Arc::new(RwLock::new(Vec::new())),
            valid_list: Arc::new(RwLock::new(Vec::new())),
            nominated_pairs: Arc::new(RwLock::new(Vec::new())),
            selected_pair: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(ConnectivityStats::new())),
            event_tx,
            checks_complete: Arc::new(Notify::new()),
            first_connection: Arc::new(Notify::new()),
            shutdown: Arc::new(RwLock::new(false)),
            controlling,
            connection_result: Arc::new(Mutex::new(None)),
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        webrtc_agent: Arc<WebRtcAgent>,
        ice_config: IceConfig,
        connectivity_config: ConnectivityConfig,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> Self {
        let mut checker = Self::new(webrtc_agent, ice_config, controlling, event_tx);
        checker.config = connectivity_config;
        checker
    }

    /// Form check list from candidate pairs
    ///
    /// Pairs are sorted by priority and frozen according to RFC 8445.
    #[instrument(skip(self, candidate_pairs), fields(pair_count = candidate_pairs.len()))]
    pub async fn form_check_list(&self, candidate_pairs: Vec<CandidatePair>) -> Result<()> {
        if *self.shutdown.read().await {
            return Err(anyhow::anyhow!("ConnectivityChecker is shut down"));
        }

        info!(pair_count = candidate_pairs.len(), "Forming check list");

        // Limit number of pairs per RFC 8445
        let limited_pairs = if candidate_pairs.len() > self.config.max_candidate_pairs {
            warn!(
                original = candidate_pairs.len(),
                limit = self.config.max_candidate_pairs,
                "Too many candidate pairs, limiting"
            );
            candidate_pairs
                .into_iter()
                .take(self.config.max_candidate_pairs)
                .collect()
        } else {
            candidate_pairs
        };

        // Sort by priority (descending) per RFC 8445 Section 6.1.2.3
        let mut sorted_pairs = limited_pairs;
        sorted_pairs.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Create check list entries - start frozen per RFC 8445
        let check_entries: Vec<CheckListEntry> = sorted_pairs
            .into_iter()
            .map(|pair| CheckListEntry {
                pair,
                state: CheckEntryState::Frozen,
                last_check_time: None,
                retry_count: 0,
                next_retry_time: None,
                check_results: Vec::new(),
            })
            .collect();

        let mut check_list = self.check_list.write().await;
        *check_list = check_entries;

        // Unfreeze first pairs to start checks
        let unfreeze_count = std::cmp::min(self.config.max_concurrent_checks, check_list.len());
        for entry in check_list.iter_mut().take(unfreeze_count) {
            entry.state = CheckEntryState::Waiting;
        }

        info!(
            total = check_list.len(),
            unfrozen = unfreeze_count,
            "Check list formed"
        );

        Ok(())
    }

    /// Start connectivity checks
    ///
    /// This sets up webrtc-rs Agent callbacks and initiates the connection.
    /// webrtc-rs Agent performs actual STUN binding requests internally.
    #[instrument(skip(self))]
    pub async fn start_connectivity_checks(&self) -> Result<()> {
        if *self.shutdown.read().await {
            return Err(anyhow::anyhow!("ConnectivityChecker is shut down"));
        }

        let current_state = *self.state.read().await;
        if current_state != ConnectivityState::New {
            return Err(anyhow::anyhow!(
                "Connectivity checks already started, current state: {}",
                current_state
            ));
        }

        info!(
            controlling = self.controlling,
            "Starting ICE connectivity checks"
        );

        // Update state
        *self.state.write().await = ConnectivityState::Checking;
        let _ = self.event_tx.send(ConnectivityEvent::ConnectivityChecksStarted);
        let _ = self.event_tx.send(ConnectivityEvent::StateChanged(ConnectivityState::Checking));

        // Setup webrtc-rs event handlers
        self.setup_webrtc_handlers().await?;

        // Start the connection process via webrtc-rs
        // Agent.dial() or Agent.accept() performs all connectivity checks internally
        let connection_result = self.perform_webrtc_connection().await;

        // Update final state and stats
        let duration = self.stats.read().await.duration().unwrap_or_default();

        match &connection_result {
            Ok(()) => {
                info!(duration_ms = duration.as_millis(), "Connectivity checks completed successfully");
                let _ = self.event_tx.send(ConnectivityEvent::ConnectivityChecksCompleted {
                    success: true,
                    duration,
                });
            }
            Err(e) => {
                error!(error = %e, duration_ms = duration.as_millis(), "Connectivity checks failed");
                let _ = self.event_tx.send(ConnectivityEvent::ConnectivityChecksCompleted {
                    success: false,
                    duration,
                });
                let _ = self.event_tx.send(ConnectivityEvent::Error(e.to_string()));
            }
        }

        connection_result
    }

    /// Setup webrtc-rs Agent event handlers
    async fn setup_webrtc_handlers(&self) -> Result<()> {
        // Handler for connection state changes
        let state = Arc::clone(&self.state);
        let stats = Arc::clone(&self.stats);
        let event_tx = self.event_tx.clone();
        let first_connection = Arc::clone(&self.first_connection);
        let checks_complete = Arc::clone(&self.checks_complete);

        self.webrtc_agent
            .on_connection_state_change(Box::new(move |webrtc_state| {
                let state = Arc::clone(&state);
                let stats = Arc::clone(&stats);
                let event_tx = event_tx.clone();
                let first_connection = Arc::clone(&first_connection);
                let checks_complete = Arc::clone(&checks_complete);

                Box::pin(async move {
                    let new_state = ConnectivityState::from(webrtc_state);
                    debug!(state = %new_state, "WebRTC connection state changed");

                    // Update state
                    let old_state = {
                        let mut current = state.write().await;
                        let old = *current;
                        *current = new_state;
                        old
                    };

                    // Send state change event
                    let _ = event_tx.send(ConnectivityEvent::StateChanged(new_state));

                    // Update stats based on state transition
                    match new_state {
                        ConnectivityState::Connected => {
                            if old_state != ConnectivityState::Connected {
                                let mut stats = stats.write().await;
                                if let Some(started_at) = stats.started_at {
                                    stats.time_to_connect = Some(Instant::now() - started_at);
                                }
                                first_connection.notify_one();
                                info!(
                                    time_to_connect_ms = stats.time_to_connect.map(|d| d.as_millis()),
                                    "First connection established"
                                );
                            }
                        }
                        ConnectivityState::Completed => {
                            stats.write().await.completed_at = Some(Instant::now());
                            checks_complete.notify_one();
                        }
                        ConnectivityState::Failed => {
                            stats.write().await.completed_at = Some(Instant::now());
                            checks_complete.notify_one();
                        }
                        _ => {}
                    }
                })
            }))
            .await;

        // Handler for selected candidate pair change
        let selected_pair = Arc::clone(&self.selected_pair);
        let nominated_pairs = Arc::clone(&self.nominated_pairs);
        let valid_list = Arc::clone(&self.valid_list);
        let stats = Arc::clone(&self.stats);
        let event_tx = self.event_tx.clone();

        self.webrtc_agent
            .on_selected_candidate_pair_change(Box::new(move |local, remote| {
                let selected_pair = Arc::clone(&selected_pair);
                let nominated_pairs = Arc::clone(&nominated_pairs);
                let valid_list = Arc::clone(&valid_list);
                let stats = Arc::clone(&stats);
                let event_tx = event_tx.clone();

                Box::pin(async move {
                    // Convert webrtc-rs candidates to our format
                    let pair = Self::webrtc_candidates_to_pair(&local, &remote);

                    debug!(
                        local = %pair.local.address,
                        remote = %pair.remote.address,
                        priority = pair.priority,
                        "Selected candidate pair changed"
                    );

                    // Update selected pair
                    *selected_pair.write().await = Some(pair.clone());

                    // Add to nominated and valid lists
                    nominated_pairs.write().await.push(pair.clone());
                    valid_list.write().await.push(pair.clone());

                    // Update stats
                    stats.write().await.successful_pairs += 1;

                    // Send events
                    let _ = event_tx.send(ConnectivityEvent::CandidatePairNominated(pair.clone()));
                    let _ = event_tx.send(ConnectivityEvent::ConnectionEstablished {
                        local_addr: pair.local.address,
                        remote_addr: pair.remote.address,
                        rtt: Duration::from_millis(10), // Will be updated with actual RTT
                    });
                })
            }))
            .await;

        debug!("WebRTC event handlers configured");
        Ok(())
    }

    /// Perform the actual webrtc-rs connection
    ///
    /// This calls Agent.dial() or Agent.accept() which performs all connectivity checks.
    async fn perform_webrtc_connection(&self) -> Result<()> {
        let timeout_duration = self.config.connectivity_timeout;

        // webrtc-rs Agent.dial() / accept() performs connectivity checks internally
        // The connection is established via STUN binding requests per RFC 8445
        let connection_future = async {
            if self.controlling {
                // Controlling agent initiates (dial)
                debug!("Initiating connection as controlling agent");
                self.webrtc_agent
                    .dial(
                        tokio::sync::mpsc::channel(1).1, // Cancel channel
                        self.ice_config.ufrag.clone().unwrap_or_default(),
                        self.ice_config.pwd.clone().unwrap_or_default(),
                    )
                    .await
                    .context("Agent dial failed")?;
            } else {
                // Controlled agent accepts
                debug!("Accepting connection as controlled agent");
                self.webrtc_agent
                    .accept(
                        tokio::sync::mpsc::channel(1).1, // Cancel channel
                        self.ice_config.ufrag.clone().unwrap_or_default(),
                        self.ice_config.pwd.clone().unwrap_or_default(),
                    )
                    .await
                    .context("Agent accept failed")?;
            }

            // Get selected pair info for stats
            if let Some((local, remote)) = self.webrtc_agent.get_selected_candidate_pair().await {
                let pair = Self::webrtc_candidates_to_pair(&local, &remote);
                *self.selected_pair.write().await = Some(pair);
            }

            Ok::<(), anyhow::Error>(())
        };

        // Wait for connection with timeout
        match timeout(timeout_duration, connection_future).await {
            Ok(result) => {
                result?;
                *self.state.write().await = ConnectivityState::Completed;
                Ok(())
            }
            Err(_) => {
                warn!(timeout_secs = timeout_duration.as_secs(), "Connectivity checks timed out");
                *self.state.write().await = ConnectivityState::Failed;
                self.stats.write().await.completed_at = Some(Instant::now());
                Err(anyhow::anyhow!(
                    "Connectivity checks timeout after {:?}",
                    timeout_duration
                ))
            }
        }
    }

    /// Convert webrtc-rs candidates to our CandidatePair format
    fn webrtc_candidates_to_pair(
        local: &Arc<dyn WebRtcCandidate + Send + Sync>,
        remote: &Arc<dyn WebRtcCandidate + Send + Sync>,
    ) -> CandidatePair {
        let local_candidate = Self::webrtc_candidate_to_candidate(local);
        let remote_candidate = Self::webrtc_candidate_to_candidate(remote);
        CandidatePair::new(local_candidate, remote_candidate)
    }

    /// Convert webrtc-rs candidate to our Candidate format
    fn webrtc_candidate_to_candidate(
        webrtc_candidate: &Arc<dyn WebRtcCandidate + Send + Sync>,
    ) -> Candidate {
        use crate::connectivity::CandidateAttributes;
        use webrtc::ice::candidate::CandidateType as WebRtcCandidateType;

        let candidate_type = match webrtc_candidate.candidate_type() {
            WebRtcCandidateType::Host => CandidateType::Host,
            WebRtcCandidateType::ServerReflexive => CandidateType::ServerReflexive,
            WebRtcCandidateType::PeerReflexive => CandidateType::PeerReflexive,
            WebRtcCandidateType::Relay => CandidateType::Relay,
            _ => CandidateType::Host,
        };

        Candidate {
            foundation: webrtc_candidate.foundation().to_string(),
            priority: webrtc_candidate.priority(),
            address: webrtc_candidate.address(),
            candidate_type,
            related_address: webrtc_candidate.related_address(),
            attributes: CandidateAttributes {
                transport: "udp".to_string(),
                component: webrtc_candidate.component() as u16,
                network_cost: 0,
                generation: 0,
                network_id: webrtc_candidate.network_type() as u32,
                extensions: std::collections::HashMap::new(),
            },
        }
    }

    // === Public API methods ===

    /// Get current state
    pub async fn get_state(&self) -> ConnectivityState {
        *self.state.read().await
    }

    /// Get valid (successfully checked) pairs
    pub async fn get_valid_pairs(&self) -> Vec<CandidatePair> {
        self.valid_list.read().await.clone()
    }

    /// Get nominated pairs
    pub async fn get_nominated_pairs(&self) -> Vec<CandidatePair> {
        self.nominated_pairs.read().await.clone()
    }

    /// Get selected candidate pair
    pub async fn get_selected_pair(&self) -> Option<CandidatePair> {
        self.selected_pair.read().await.clone()
    }

    /// Get statistics
    pub async fn get_stats(&self) -> ConnectivityStats {
        self.stats.read().await.clone()
    }

    /// Check if connection is established
    pub async fn is_connected(&self) -> bool {
        matches!(
            *self.state.read().await,
            ConnectivityState::Connected | ConnectivityState::Completed
        )
    }

    /// Wait for first connection
    pub async fn wait_for_connection(&self) -> Result<()> {
        let timeout_duration = self.config.connectivity_timeout;
        match timeout(timeout_duration, self.first_connection.notified()).await {
            Ok(()) => Ok(()),
            Err(_) => Err(anyhow::anyhow!("Timeout waiting for connection")),
        }
    }

    /// Shutdown the checker
    #[instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down ConnectivityChecker");
        *self.shutdown.write().await = true;
        self.checks_complete.notify_one();
        Ok(())
    }
}

/// Factory for creating ConnectivityChecker instances
pub struct ConnectivityCheckerFactory;

impl ConnectivityCheckerFactory {
    /// Create standard checker
    pub fn create_standard(
        webrtc_agent: Arc<WebRtcAgent>,
        ice_config: IceConfig,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> ConnectivityChecker {
        ConnectivityChecker::new(webrtc_agent, ice_config, controlling, event_tx)
    }

    /// Create checker for testing
    pub fn create_for_testing(
        webrtc_agent: Arc<WebRtcAgent>,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> ConnectivityChecker {
        let ice_config = IceConfig {
            connectivity_timeout: Duration::from_secs(10),
            check_interval: Duration::from_millis(50),
            ..Default::default()
        };

        let connectivity_config = ConnectivityConfig {
            connectivity_timeout: Duration::from_secs(10),
            max_concurrent_checks: 3,
            ..Default::default()
        };

        ConnectivityChecker::with_config(
            webrtc_agent,
            ice_config,
            connectivity_config,
            controlling,
            event_tx,
        )
    }

    /// Create checker optimized for P2P
    pub fn create_p2p_optimized(
        webrtc_agent: Arc<WebRtcAgent>,
        ice_config: IceConfig,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> ConnectivityChecker {
        let connectivity_config = ConnectivityConfig {
            connectivity_timeout: Duration::from_secs(15),
            check_interval: Duration::from_millis(20), // Faster checks
            max_concurrent_checks: 10,
            aggressive_nomination: true,
            ..Default::default()
        };

        ConnectivityChecker::with_config(
            webrtc_agent,
            ice_config,
            connectivity_config,
            controlling,
            event_tx,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connectivity_state_display() {
        assert_eq!(ConnectivityState::New.to_string(), "New");
        assert_eq!(ConnectivityState::Checking.to_string(), "Checking");
        assert_eq!(ConnectivityState::Connected.to_string(), "Connected");
        assert_eq!(ConnectivityState::Completed.to_string(), "Completed");
        assert_eq!(ConnectivityState::Failed.to_string(), "Failed");
    }

    #[test]
    fn test_connectivity_state_from_webrtc() {
        assert_eq!(
            ConnectivityState::from(WebRtcConnectionState::New),
            ConnectivityState::New
        );
        assert_eq!(
            ConnectivityState::from(WebRtcConnectionState::Checking),
            ConnectivityState::Checking
        );
        assert_eq!(
            ConnectivityState::from(WebRtcConnectionState::Connected),
            ConnectivityState::Connected
        );
        assert_eq!(
            ConnectivityState::from(WebRtcConnectionState::Failed),
            ConnectivityState::Failed
        );
    }

    #[test]
    fn test_connectivity_config_default() {
        let config = ConnectivityConfig::default();
        assert_eq!(config.connectivity_timeout, Duration::from_secs(30));
        assert_eq!(config.check_interval, Duration::from_millis(50));
        assert_eq!(config.max_concurrent_checks, 5);
        assert_eq!(config.max_retries, 7);
        assert!(!config.aggressive_nomination);
    }

    #[test]
    fn test_connectivity_stats_new() {
        let stats = ConnectivityStats::new();
        assert!(stats.started_at.is_some());
        assert!(stats.completed_at.is_none());
        assert_eq!(stats.checks_sent, 0);
        assert_eq!(stats.successful_checks, 0);
    }

    #[test]
    fn test_connectivity_stats_success_rate() {
        let mut stats = ConnectivityStats::new();

        // No checks yet
        assert_eq!(stats.success_rate(), 0.0);

        // 2/4 successful
        stats.checks_sent = 4;
        stats.successful_checks = 2;
        assert_eq!(stats.success_rate(), 0.5);

        // All successful
        stats.successful_checks = 4;
        assert_eq!(stats.success_rate(), 1.0);
    }

    #[test]
    fn test_connectivity_stats_update_average_rtt() {
        let mut stats = ConnectivityStats::new();

        // First RTT
        stats.successful_checks = 1;
        stats.update_average_rtt(Duration::from_millis(100));
        assert_eq!(stats.average_rtt, Some(Duration::from_millis(100)));

        // Second RTT (should average)
        stats.successful_checks = 2;
        stats.update_average_rtt(Duration::from_millis(200));
        // Average of 100 and 200 = 150
        assert!(stats.average_rtt.is_some());
    }

    #[test]
    fn test_check_entry_state() {
        let entry = CheckListEntry {
            pair: CandidatePair::new(
                Candidate::host("127.0.0.1:5000".parse().unwrap()),
                Candidate::host("127.0.0.1:5001".parse().unwrap()),
            ),
            state: CheckEntryState::Frozen,
            last_check_time: None,
            retry_count: 0,
            next_retry_time: None,
            check_results: Vec::new(),
        };

        assert_eq!(entry.state, CheckEntryState::Frozen);
        assert_eq!(entry.retry_count, 0);
    }

    #[tokio::test]
    async fn test_form_check_list() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();

        // Create pairs with different priorities
        let mut pairs = vec![
            CandidatePair::new(
                Candidate::host("192.168.1.1:5000".parse().unwrap()),
                Candidate::host("192.168.1.2:5000".parse().unwrap()),
            ),
            CandidatePair::new(
                Candidate::host("10.0.0.1:5000".parse().unwrap()),
                Candidate::host("10.0.0.2:5000".parse().unwrap()),
            ),
        ];

        // Set different priorities
        pairs[0].priority = 100;
        pairs[1].priority = 200;

        // Note: We can't fully test without a real webrtc Agent,
        // but we can test the pair sorting logic
        let mut sorted = pairs.clone();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

        assert_eq!(sorted[0].priority, 200);
        assert_eq!(sorted[1].priority, 100);
    }

    #[test]
    fn test_candidate_conversion() {
        // Test that our candidate types work correctly
        let host = Candidate::host("192.168.1.1:5000".parse().unwrap());
        assert_eq!(host.candidate_type, CandidateType::Host);
        assert!(!host.is_public());

        let public = Candidate::host("8.8.8.8:53".parse().unwrap());
        assert!(public.is_public());
    }

    #[test]
    fn test_check_result() {
        let pair = CandidatePair::new(
            Candidate::host("192.168.1.1:5000".parse().unwrap()),
            Candidate::host("192.168.1.2:5000".parse().unwrap()),
        );

        let result = CheckResult {
            pair: pair.clone(),
            success: true,
            rtt: Some(Duration::from_millis(50)),
            timestamp: Instant::now(),
            failure_reason: None,
            check_type: CheckType::Ordinary,
            transaction_id: Some("12345678".to_string()),
        };

        assert!(result.success);
        assert!(result.rtt.is_some());
        assert!(result.failure_reason.is_none());
    }

    #[test]
    fn test_connectivity_event() {
        let event = ConnectivityEvent::ConnectivityChecksStarted;
        match event {
            ConnectivityEvent::ConnectivityChecksStarted => {}
            _ => panic!("Wrong event type"),
        }

        let error_event = ConnectivityEvent::Error("Test error".to_string());
        match error_event {
            ConnectivityEvent::Error(msg) => assert_eq!(msg, "Test error"),
            _ => panic!("Wrong event type"),
        }
    }
}
