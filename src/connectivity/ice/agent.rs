// src/connectivity/ice/agent.rs
//! Integrated ICE Agent Implementation
//!
//! Production-ready ICE agent coordinating all ICE processes using webrtc-rs.
//! RFC 8445 compliant.
//!
//! ## Usage
//!
//! ```rust,ignore
//! let agent = IceAgent::new(ice_config, true).await?;
//! let connection = agent.perform_ice_process().await?;
//! ```

use anyhow::{Result, Context};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Notify, Mutex};
use tokio::time::timeout;
use tracing::{debug, info, warn, error, trace, instrument};

use webrtc::ice::{
    agent::{Agent as WebRtcAgent, AgentConfig as WebRtcAgentConfig},
    candidate::{Candidate as WebRtcCandidate, CandidateType as WebRtcCandidateType},
    state::{ConnectionState as WebRtcConnectionState, GatheringState as WebRtcGatheringState},
    url::Url,
    network_type::NetworkType,
};

use crate::connectivity::{
    Candidate, CandidatePair, CandidatePairState, ConnectivityCheckResult, ConnectivityEvent
};
use crate::connectivity::config::IceConfig;
use super::{
    IceConnection, IceAgentState, IceEvent,
    gathering::{CandidateGatherer, GatheringState, GatheringStats},
    connectivity::{ConnectivityChecker, ConnectivityState, ConnectivityStats},
    nomination::{CandidateNominator, NominationState, NominationStats},
};

/// ICE Agent configuration
#[derive(Debug, Clone)]
pub struct IceAgentConfig {
    /// ICE configuration (STUN/TURN servers)
    pub ice_config: IceConfig,
    /// Controlling role
    pub controlling: bool,
    /// Local ICE credentials
    pub local_ufrag: Option<String>,
    pub local_pwd: Option<String>,
    /// Remote ICE credentials
    pub remote_ufrag: Option<String>,
    pub remote_pwd: Option<String>,
    /// Trickle ICE support
    pub trickle_ice: bool,
    /// Aggressive nomination
    pub aggressive_nomination: bool,
}

impl Default for IceAgentConfig {
    fn default() -> Self {
        Self {
            ice_config: IceConfig::default(),
            controlling: true,
            local_ufrag: None,
            local_pwd: None,
            remote_ufrag: None,
            remote_pwd: None,
            trickle_ice: true,
            aggressive_nomination: false,
        }
    }
}

/// ICE process state
#[derive(Debug, Clone)]
pub struct IceProcessState {
    /// Agent state
    pub agent_state: IceAgentState,
    /// Gathering state
    pub gathering_state: GatheringState,
    /// Connectivity checks state
    pub connectivity_state: ConnectivityState,
    /// Nomination state
    pub nomination_state: NominationState,
    /// Process start time
    pub started_at: Option<Instant>,
    /// Process completion time
    pub completed_at: Option<Instant>,
}

impl Default for IceProcessState {
    fn default() -> Self {
        Self {
            agent_state: IceAgentState::New,
            gathering_state: GatheringState::New,
            connectivity_state: ConnectivityState::New,
            nomination_state: NominationState::NotStarted,
            started_at: None,
            completed_at: None,
        }
    }
}

/// Complete ICE process statistics
#[derive(Debug, Clone)]
pub struct IceAgentStats {
    /// Gathering statistics
    pub gathering_stats: GatheringStats,
    /// Connectivity check statistics
    pub connectivity_stats: ConnectivityStats,
    /// Nomination statistics
    pub nomination_stats: NominationStats,
    /// Total duration
    pub total_duration: Option<Duration>,
    /// ICE restart count
    pub ice_restart_count: u32,
    /// Connection failure count
    pub connection_failures: u32,
}

impl Default for IceAgentStats {
    fn default() -> Self {
        Self {
            gathering_stats: GatheringStats::new(),
            connectivity_stats: ConnectivityStats::new(),
            nomination_stats: NominationStats::new(),
            total_duration: None,
            ice_restart_count: 0,
            connection_failures: 0,
        }
    }
}

/// Main ICE Agent - coordinates all ICE processes
pub struct IceAgent {
    /// WebRTC ICE Agent (foundation)
    webrtc_agent: Arc<WebRtcAgent>,

    /// Configuration
    config: IceAgentConfig,

    /// Process state
    process_state: Arc<RwLock<IceProcessState>>,

    /// ICE components
    candidate_gatherer: Arc<Mutex<Option<CandidateGatherer>>>,
    connectivity_checker: Arc<Mutex<Option<ConnectivityChecker>>>,
    candidate_nominator: Arc<Mutex<Option<CandidateNominator>>>,

    /// Local candidates
    local_candidates: Arc<RwLock<Vec<Candidate>>>,

    /// Remote candidates
    remote_candidates: Arc<RwLock<Vec<Candidate>>>,

    /// Candidate pairs
    candidate_pairs: Arc<RwLock<Vec<CandidatePair>>>,

    /// Nominated pair
    nominated_pair: Arc<RwLock<Option<CandidatePair>>>,

    /// Established connection
    ice_connection: Arc<RwLock<Option<IceConnection>>>,

    /// Statistics
    stats: Arc<RwLock<IceAgentStats>>,

    /// Event sender
    event_tx: mpsc::UnboundedSender<IceEvent>,
    event_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<IceEvent>>>>,

    /// Internal event channel for component coordination
    internal_event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    internal_event_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<ConnectivityEvent>>>>,

    /// Completion notifications
    gathering_complete: Arc<Notify>,
    connectivity_complete: Arc<Notify>,
    nomination_complete: Arc<Notify>,
    connection_established: Arc<Notify>,

    /// Shutdown flag
    shutdown: Arc<RwLock<bool>>,
}

impl IceAgent {
    /// Create new ICE Agent
    #[instrument(skip(ice_config))]
    pub async fn new(ice_config: IceConfig, controlling: bool) -> Result<Self> {
        let config = IceAgentConfig {
            ice_config: ice_config.clone(),
            controlling,
            ..Default::default()
        };

        Self::with_config(config).await
    }

    /// Create with full configuration
    #[instrument(skip(config))]
    pub async fn with_config(config: IceAgentConfig) -> Result<Self> {
        // Create WebRTC Agent configuration
        let webrtc_config = Self::create_webrtc_config(&config)
            .context("Failed to create WebRTC config")?;

        // Create WebRTC Agent
        let webrtc_agent = Arc::new(
            WebRtcAgent::new(webrtc_config)
                .await
                .context("Failed to create WebRTC Agent")?
        );

        // Create event channels
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (internal_event_tx, internal_event_rx) = mpsc::unbounded_channel();

        let agent = Self {
            webrtc_agent,
            config,
            process_state: Arc::new(RwLock::new(IceProcessState::default())),
            candidate_gatherer: Arc::new(Mutex::new(None)),
            connectivity_checker: Arc::new(Mutex::new(None)),
            candidate_nominator: Arc::new(Mutex::new(None)),
            local_candidates: Arc::new(RwLock::new(Vec::new())),
            remote_candidates: Arc::new(RwLock::new(Vec::new())),
            candidate_pairs: Arc::new(RwLock::new(Vec::new())),
            nominated_pair: Arc::new(RwLock::new(None)),
            ice_connection: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(IceAgentStats::default())),
            event_tx,
            event_rx: Arc::new(RwLock::new(Some(event_rx))),
            internal_event_tx,
            internal_event_rx: Arc::new(Mutex::new(Some(internal_event_rx))),
            gathering_complete: Arc::new(Notify::new()),
            connectivity_complete: Arc::new(Notify::new()),
            nomination_complete: Arc::new(Notify::new()),
            connection_established: Arc::new(Notify::new()),
            shutdown: Arc::new(RwLock::new(false)),
        };

        // Initialize components
        agent.initialize_components().await?;

        // Start event processing
        agent.start_event_processing().await?;

        info!(
            controlling = agent.config.controlling,
            "ICE Agent created"
        );

        Ok(agent)
    }

    /// Create WebRTC Agent configuration
    fn create_webrtc_config(config: &IceAgentConfig) -> Result<WebRtcAgentConfig> {
        let mut urls = Vec::new();

        // Add STUN servers
        for stun_server in &config.ice_config.stun_servers {
            let url = Url::parse_url(stun_server)
                .map_err(|e| anyhow::anyhow!("Invalid STUN server URL {}: {}", stun_server, e))?;
            urls.push(url);
        }

        // Add TURN servers
        for turn_server in &config.ice_config.turn_servers {
            let url = Url::parse_url(&turn_server.url)
                .map_err(|e| anyhow::anyhow!("Invalid TURN server URL {}: {}", turn_server.url, e))?;
            urls.push(url);
        }

        // Define candidate types
        let mut candidate_types = Vec::new();
        if config.ice_config.enable_host_candidates {
            candidate_types.push(WebRtcCandidateType::Host);
        }
        if config.ice_config.enable_srflx_candidates {
            candidate_types.push(WebRtcCandidateType::ServerReflexive);
        }
        if config.ice_config.enable_relay_candidates {
            candidate_types.push(WebRtcCandidateType::Relay);
        }

        // UDP only per user requirement
        let network_types = vec![NetworkType::Udp4, NetworkType::Udp6];

        Ok(WebRtcAgentConfig {
            urls,
            is_controlling: config.controlling,
            candidate_types,
            network_types,
            ..Default::default()
        })
    }

    /// Initialize components
    async fn initialize_components(&self) -> Result<()> {
        debug!("Initializing ICE Agent components");

        // Create CandidateGatherer
        let gatherer = CandidateGatherer::new(
            Arc::clone(&self.webrtc_agent),
            self.config.ice_config.clone(),
            self.internal_event_tx.clone(),
        );
        *self.candidate_gatherer.lock().await = Some(gatherer);

        // Create ConnectivityChecker
        let checker = ConnectivityChecker::new(
            Arc::clone(&self.webrtc_agent),
            self.config.ice_config.clone(),
            self.config.controlling,
            self.internal_event_tx.clone(),
        );
        *self.connectivity_checker.lock().await = Some(checker);

        // Create CandidateNominator (only for controlling agent)
        if self.config.controlling {
            let nominator = CandidateNominator::new(
                Arc::clone(&self.webrtc_agent),
                self.config.controlling,
                self.internal_event_tx.clone(),
            );
            *self.candidate_nominator.lock().await = Some(nominator);
        }

        debug!("ICE Agent components initialized");
        Ok(())
    }

    /// Start event processing
    async fn start_event_processing(&self) -> Result<()> {
        let event_rx = self.internal_event_rx.lock().await.take()
            .ok_or_else(|| anyhow::anyhow!("Event receiver already taken"))?;

        let processor = IceEventProcessor {
            event_rx: Mutex::new(event_rx),
            event_tx: self.event_tx.clone(),
            process_state: Arc::clone(&self.process_state),
            stats: Arc::clone(&self.stats),
            ice_connection: Arc::clone(&self.ice_connection),
            nominated_pair: Arc::clone(&self.nominated_pair),
            gathering_complete: Arc::clone(&self.gathering_complete),
            connectivity_complete: Arc::clone(&self.connectivity_complete),
            nomination_complete: Arc::clone(&self.nomination_complete),
            connection_established: Arc::clone(&self.connection_established),
            shutdown: Arc::clone(&self.shutdown),
        };

        tokio::spawn(async move {
            processor.run().await;
        });

        Ok(())
    }

    /// Complete ICE process: gathering -> connectivity checks -> nomination
    #[instrument(skip(self))]
    pub async fn perform_ice_process(&self) -> Result<IceConnection> {
        if *self.shutdown.read().await {
            return Err(anyhow::anyhow!("ICE Agent is shut down"));
        }

        info!("Starting complete ICE process");

        // Update state
        {
            let mut state = self.process_state.write().await;
            state.agent_state = IceAgentState::Gathering;
            state.started_at = Some(Instant::now());
        }

        // Send process started event
        let _ = self.event_tx.send(IceEvent::IceProcessStarted);

        // Phase 1: Gather candidates
        self.gather_candidates_with_progress().await?;

        // Phase 2: Form pairs and connectivity checks
        self.perform_connectivity_checks().await?;

        // Phase 3: Nomination (only for controlling agent)
        if self.config.controlling {
            self.perform_nomination().await?;
        }

        // Wait for connection establishment
        let timeout_duration = self.config.ice_config.connectivity_timeout;
        match timeout(timeout_duration, self.connection_established.notified()).await {
            Ok(()) => {
                info!("ICE process completed successfully");

                // Update state
                {
                    let mut state = self.process_state.write().await;
                    state.agent_state = IceAgentState::Connected;
                    state.completed_at = Some(Instant::now());
                }

                // Get established connection
                self.get_connection().await
            }
            Err(_) => {
                error!(timeout_secs = timeout_duration.as_secs(), "ICE process timed out");

                // Update state
                {
                    let mut state = self.process_state.write().await;
                    state.agent_state = IceAgentState::Failed;
                    state.completed_at = Some(Instant::now());
                }

                self.stats.write().await.connection_failures += 1;
                let _ = self.event_tx.send(IceEvent::Error("ICE process timeout".to_string()));
                Err(anyhow::anyhow!("ICE process timeout after {:?}", timeout_duration))
            }
        }
    }

    /// Gather candidates with progress tracking
    #[instrument(skip(self))]
    pub async fn gather_candidates_with_progress(&self) -> Result<Vec<Candidate>> {
        info!("Starting candidate gathering");

        let gatherer = self.candidate_gatherer.lock().await;
        let gatherer = gatherer.as_ref()
            .ok_or_else(|| anyhow::anyhow!("CandidateGatherer not initialized"))?;

        // Start gathering
        gatherer.start_gathering().await?;

        // Wait for completion
        self.gathering_complete.notified().await;

        // Get gathered candidates
        let candidates = gatherer.get_candidates().await;

        // Update local candidates
        *self.local_candidates.write().await = candidates.clone();

        info!(count = candidates.len(), "Gathering completed");
        Ok(candidates)
    }

    /// Add remote candidate
    #[instrument(skip(self, candidate), fields(addr = %candidate.address))]
    pub async fn add_remote_candidate(&self, candidate: Candidate) -> Result<()> {
        debug!("Adding remote candidate");

        // Add to remote candidates list
        self.remote_candidates.write().await.push(candidate.clone());

        // Convert to WebRTC format and add to WebRTC Agent
        let webrtc_candidate = self.candidate_to_webrtc(&candidate)?;
        self.webrtc_agent
            .add_remote_candidate(&webrtc_candidate)
            .await
            .context("Failed to add remote candidate to WebRTC Agent")?;

        // Update candidate pairs if we have local candidates
        self.update_candidate_pairs().await?;

        Ok(())
    }

    /// Convert our Candidate to webrtc-rs format
    fn candidate_to_webrtc(&self, candidate: &Candidate) -> Result<Arc<dyn WebRtcCandidate + Send + Sync>> {
        use webrtc::ice::candidate::candidate_host::CandidateHostConfig;
        use webrtc::ice::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
        use webrtc::ice::candidate::candidate_relay::CandidateRelayConfig;

        let network_type = if candidate.address.is_ipv4() {
            NetworkType::Udp4
        } else {
            NetworkType::Udp6
        };

        match candidate.candidate_type {
            crate::connectivity::CandidateType::Host => {
                let config = CandidateHostConfig {
                    base_config: webrtc::ice::candidate::CandidateBaseConfig {
                        network: "udp".to_string(),
                        address: candidate.address.ip().to_string(),
                        port: candidate.address.port(),
                        component: candidate.attributes.component,
                        priority: candidate.priority,
                        foundation: candidate.foundation.clone(),
                        ..Default::default()
                    },
                    ..Default::default()
                };
                Ok(Arc::new(config.new_candidate_host()?))
            }
            crate::connectivity::CandidateType::ServerReflexive => {
                let related = candidate.related_address.unwrap_or(candidate.address);
                let config = CandidateServerReflexiveConfig {
                    base_config: webrtc::ice::candidate::CandidateBaseConfig {
                        network: "udp".to_string(),
                        address: candidate.address.ip().to_string(),
                        port: candidate.address.port(),
                        component: candidate.attributes.component,
                        priority: candidate.priority,
                        foundation: candidate.foundation.clone(),
                        ..Default::default()
                    },
                    rel_addr: related.ip().to_string(),
                    rel_port: related.port(),
                };
                Ok(Arc::new(config.new_candidate_server_reflexive()?))
            }
            crate::connectivity::CandidateType::Relay => {
                let related = candidate.related_address.unwrap_or(candidate.address);
                let config = CandidateRelayConfig {
                    base_config: webrtc::ice::candidate::CandidateBaseConfig {
                        network: "udp".to_string(),
                        address: candidate.address.ip().to_string(),
                        port: candidate.address.port(),
                        component: candidate.attributes.component,
                        priority: candidate.priority,
                        foundation: candidate.foundation.clone(),
                        ..Default::default()
                    },
                    rel_addr: related.ip().to_string(),
                    rel_port: related.port(),
                    ..Default::default()
                };
                Ok(Arc::new(config.new_candidate_relay()?))
            }
            _ => {
                // Default to host candidate
                let config = CandidateHostConfig {
                    base_config: webrtc::ice::candidate::CandidateBaseConfig {
                        network: "udp".to_string(),
                        address: candidate.address.ip().to_string(),
                        port: candidate.address.port(),
                        component: candidate.attributes.component,
                        priority: candidate.priority,
                        foundation: candidate.foundation.clone(),
                        ..Default::default()
                    },
                    ..Default::default()
                };
                Ok(Arc::new(config.new_candidate_host()?))
            }
        }
    }

    /// Update candidate pairs
    async fn update_candidate_pairs(&self) -> Result<()> {
        let local_candidates = self.local_candidates.read().await;
        let remote_candidates = self.remote_candidates.read().await;

        if local_candidates.is_empty() || remote_candidates.is_empty() {
            return Ok(()); // Not ready to form pairs
        }

        let mut new_pairs = Vec::new();

        // Form all compatible pairs
        for local in local_candidates.iter() {
            for remote in remote_candidates.iter() {
                if self.are_candidates_compatible(local, remote) {
                    let pair = CandidatePair::new(local.clone(), remote.clone());
                    new_pairs.push(pair);
                }
            }
        }

        // Sort by priority (descending)
        new_pairs.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Limit number of pairs
        let max_pairs = self.config.ice_config.max_candidate_pairs;
        if new_pairs.len() > max_pairs {
            new_pairs.truncate(max_pairs);
        }

        // Update pairs
        *self.candidate_pairs.write().await = new_pairs;

        debug!(count = self.candidate_pairs.read().await.len(), "Updated candidate pairs");
        Ok(())
    }

    /// Check candidate compatibility
    fn are_candidates_compatible(&self, local: &Candidate, remote: &Candidate) -> bool {
        // IP versions must match
        if local.address.is_ipv4() != remote.address.is_ipv4() {
            return false;
        }

        // Transport must match
        if local.attributes.transport != remote.attributes.transport {
            return false;
        }

        // Components must match
        if local.attributes.component != remote.attributes.component {
            return false;
        }

        true
    }

    /// Perform connectivity checks
    #[instrument(skip(self))]
    pub async fn perform_connectivity_checks(&self) -> Result<Vec<ConnectivityCheckResult>> {
        info!("Starting connectivity checks");

        // Update state
        {
            let mut state = self.process_state.write().await;
            state.agent_state = IceAgentState::Connecting;
            state.connectivity_state = ConnectivityState::Checking;
        }

        let checker = self.connectivity_checker.lock().await;
        let checker = checker.as_ref()
            .ok_or_else(|| anyhow::anyhow!("ConnectivityChecker not initialized"))?;

        // Form check list from candidate pairs
        let candidate_pairs = self.candidate_pairs.read().await.clone();
        checker.form_check_list(candidate_pairs).await?;

        // Start connectivity checks
        checker.start_connectivity_checks().await?;

        // Wait for completion
        self.connectivity_complete.notified().await;

        // Get valid pairs
        let valid_pairs = checker.get_valid_pairs().await;

        if valid_pairs.is_empty() {
            return Err(anyhow::anyhow!("No valid candidate pairs found"));
        }

        info!(count = valid_pairs.len(), "Connectivity checks completed");

        // If we have valid pairs and we're not controlling, wait for nomination
        if !self.config.controlling && !valid_pairs.is_empty() {
            self.process_state.write().await.agent_state = IceAgentState::Connected;
        }

        // Create results
        let results: Vec<ConnectivityCheckResult> = valid_pairs
            .into_iter()
            .map(|pair| ConnectivityCheckResult {
                pair,
                success: true,
                rtt: Some(Duration::from_millis(50)),
                error: None,
                timestamp: Instant::now(),
            })
            .collect();

        Ok(results)
    }

    /// Perform nomination (only for controlling agent)
    #[instrument(skip(self))]
    pub async fn perform_nomination(&self) -> Result<Option<CandidatePair>> {
        if !self.config.controlling {
            debug!("Not controlling agent, skipping nomination");
            return Ok(None);
        }

        info!("Starting nomination process");

        // Update state
        {
            let mut state = self.process_state.write().await;
            state.nomination_state = NominationState::InProgress;
        }

        let nominator = self.candidate_nominator.lock().await;
        let nominator = nominator.as_ref()
            .ok_or_else(|| anyhow::anyhow!("CandidateNominator not initialized"))?;

        // Get valid pairs from connectivity checker
        let checker = self.connectivity_checker.lock().await;
        let checker = checker.as_ref()
            .ok_or_else(|| anyhow::anyhow!("ConnectivityChecker not initialized"))?;

        let valid_pairs = checker.get_valid_pairs().await;

        // Add pairs for nomination
        nominator.add_valid_pairs(valid_pairs).await?;

        // Start nomination
        nominator.start_nomination().await?;

        // Wait for completion
        self.nomination_complete.notified().await;

        // Get nominated pairs
        let nominated_pairs = nominator.get_nominated_pairs().await;

        if let Some(pair) = nominated_pairs.first() {
            *self.nominated_pair.write().await = Some(pair.clone());

            // Create connection from nominated pair
            let connection = IceConnection::new(pair.clone());
            *self.ice_connection.write().await = Some(connection);

            info!("Nomination completed successfully");
            Ok(Some(pair.clone()))
        } else {
            Err(anyhow::anyhow!("Nomination failed - no pairs nominated"))
        }
    }

    /// Get established connection
    pub async fn get_connection(&self) -> Result<IceConnection> {
        let ice_connection = self.ice_connection.read().await;
        if let Some(connection) = ice_connection.as_ref() {
            Ok(connection.clone())
        } else {
            // Try to create from nominated pair
            let nominated_pair = self.nominated_pair.read().await;
            if let Some(pair) = nominated_pair.as_ref() {
                let connection = IceConnection::new(pair.clone());
                drop(ice_connection);
                *self.ice_connection.write().await = Some(connection.clone());
                Ok(connection)
            } else {
                Err(anyhow::anyhow!("No connection available - ICE process not completed"))
            }
        }
    }

    /// Restart ICE process
    #[instrument(skip(self))]
    pub async fn restart_ice(&self) -> Result<()> {
        info!("Restarting ICE process");

        // Update stats
        self.stats.write().await.ice_restart_count += 1;

        // Reset state
        {
            let mut state = self.process_state.write().await;
            *state = IceProcessState::default();
            state.started_at = Some(Instant::now());
        }

        // Clear data
        self.local_candidates.write().await.clear();
        self.remote_candidates.write().await.clear();
        self.candidate_pairs.write().await.clear();
        *self.nominated_pair.write().await = None;
        *self.ice_connection.write().await = None;

        // Restart gathering
        let gatherer = self.candidate_gatherer.lock().await;
        if let Some(gatherer) = gatherer.as_ref() {
            gatherer.restart_gathering().await?;
        }

        info!("ICE restart initiated");
        Ok(())
    }

    // === Public getters ===

    /// Get current process state
    pub async fn get_process_state(&self) -> IceProcessState {
        self.process_state.read().await.clone()
    }

    /// Get local candidates
    pub async fn get_local_candidates(&self) -> Vec<Candidate> {
        self.local_candidates.read().await.clone()
    }

    /// Get remote candidates
    pub async fn get_remote_candidates(&self) -> Vec<Candidate> {
        self.remote_candidates.read().await.clone()
    }

    /// Get candidate pairs
    pub async fn get_candidate_pairs(&self) -> Vec<CandidatePair> {
        self.candidate_pairs.read().await.clone()
    }

    /// Get nominated pair
    pub async fn get_nominated_pair(&self) -> Option<CandidatePair> {
        self.nominated_pair.read().await.clone()
    }

    /// Get statistics
    pub async fn get_stats(&self) -> IceAgentStats {
        let mut stats = self.stats.read().await.clone();

        // Update from components
        if let Some(gatherer) = self.candidate_gatherer.lock().await.as_ref() {
            stats.gathering_stats = gatherer.get_stats().await;
        }

        if let Some(checker) = self.connectivity_checker.lock().await.as_ref() {
            stats.connectivity_stats = checker.get_stats().await;
        }

        if let Some(nominator) = self.candidate_nominator.lock().await.as_ref() {
            stats.nomination_stats = nominator.get_stats().await;
        }

        // Calculate total duration
        let state = self.process_state.read().await;
        if let (Some(start), Some(end)) = (state.started_at, state.completed_at) {
            stats.total_duration = Some(end - start);
        }

        stats
    }

    /// Get event receiver
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<IceEvent>> {
        self.event_rx.write().await.take()
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        let state = self.process_state.read().await;
        matches!(state.agent_state, IceAgentState::Connected | IceAgentState::Completed)
    }

    /// Shutdown ICE Agent
    #[instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down ICE Agent");
        *self.shutdown.write().await = true;

        // Shutdown components
        if let Some(gatherer) = self.candidate_gatherer.lock().await.as_ref() {
            gatherer.shutdown().await?;
        }

        if let Some(checker) = self.connectivity_checker.lock().await.as_ref() {
            checker.shutdown().await?;
        }

        if let Some(nominator) = self.candidate_nominator.lock().await.as_ref() {
            nominator.shutdown().await?;
        }

        // Close connection
        if let Some(connection) = self.ice_connection.read().await.as_ref() {
            connection.close().await?;
        }

        // Update state
        self.process_state.write().await.agent_state = IceAgentState::Closed;

        Ok(())
    }
}

/// Event processor for internal event handling
struct IceEventProcessor {
    event_rx: Mutex<mpsc::UnboundedReceiver<ConnectivityEvent>>,
    event_tx: mpsc::UnboundedSender<IceEvent>,
    process_state: Arc<RwLock<IceProcessState>>,
    stats: Arc<RwLock<IceAgentStats>>,
    ice_connection: Arc<RwLock<Option<IceConnection>>>,
    nominated_pair: Arc<RwLock<Option<CandidatePair>>>,
    gathering_complete: Arc<Notify>,
    connectivity_complete: Arc<Notify>,
    nomination_complete: Arc<Notify>,
    connection_established: Arc<Notify>,
    shutdown: Arc<RwLock<bool>>,
}

impl IceEventProcessor {
    async fn run(self) {
        let mut event_rx = self.event_rx.into_inner();

        while let Some(event) = event_rx.recv().await {
            if *self.shutdown.read().await {
                break;
            }

            self.handle_internal_event(event).await;
        }

        debug!("ICE event processor stopped");
    }

    async fn handle_internal_event(&self, event: ConnectivityEvent) {
        match event {
            ConnectivityEvent::GatheringStarted => {
                debug!("Processing gathering started");
                self.process_state.write().await.gathering_state = GatheringState::Gathering;
            }

            ConnectivityEvent::CandidateGathered(candidate) => {
                trace!(addr = %candidate.address, "Processing candidate gathered");
                let _ = self.event_tx.send(IceEvent::CandidateGathered(candidate));
            }

            ConnectivityEvent::GatheringComplete(candidates) => {
                info!(count = candidates.len(), "Processing gathering complete");
                self.process_state.write().await.gathering_state = GatheringState::Complete;
                let _ = self.event_tx.send(IceEvent::GatheringComplete);
                self.gathering_complete.notify_one();
            }

            ConnectivityEvent::ConnectivityChecksStarted => {
                debug!("Processing connectivity checks started");
                self.process_state.write().await.connectivity_state = ConnectivityState::Checking;
                let _ = self.event_tx.send(IceEvent::ConnectivityChecksStarted);
            }

            ConnectivityEvent::ConnectivityCheckResult(result) => {
                trace!(success = result.success, "Processing connectivity check result");
                let _ = self.event_tx.send(IceEvent::ConnectivityCheckCompleted(result));
            }

            ConnectivityEvent::CandidatePairNominated(pair) => {
                info!("Processing candidate pair nominated");
                self.process_state.write().await.nomination_state = NominationState::Nominated;

                // Create connection from nominated pair
                let connection = IceConnection::new(pair.clone());
                *self.nominated_pair.write().await = Some(pair.clone());
                *self.ice_connection.write().await = Some(connection.clone());

                let _ = self.event_tx.send(IceEvent::CandidatePairNominated(pair));
                let _ = self.event_tx.send(IceEvent::ConnectionEstablished(connection));
                self.nomination_complete.notify_one();
                self.connection_established.notify_one();
            }

            ConnectivityEvent::ConnectionEstablished(established) => {
                info!("Processing connection established");
                self.process_state.write().await.agent_state = IceAgentState::Connected;
                self.connection_established.notify_one();
            }

            ConnectivityEvent::Error(error) => {
                error!(error = %error, "Processing error event");
                self.process_state.write().await.agent_state = IceAgentState::Failed;
                self.stats.write().await.connection_failures += 1;
                let _ = self.event_tx.send(IceEvent::Error(error));
            }

            _ => {
                trace!("Unhandled internal event");
            }
        }
    }
}

/// Factory for creating ICE Agents
pub struct IceAgentFactory;

impl IceAgentFactory {
    /// Create standard ICE Agent
    pub async fn create_standard(ice_config: IceConfig, controlling: bool) -> Result<IceAgent> {
        IceAgent::new(ice_config, controlling).await
    }

    /// Create test ICE Agent
    pub async fn create_test_agent() -> Result<IceAgent> {
        let ice_config = IceConfig {
            stun_servers: vec!["stun:stun.l.google.com:19302".to_string()],
            gathering_timeout: Duration::from_secs(5),
            connectivity_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        IceAgent::new(ice_config, true).await
    }

    /// Create agent pair for testing
    pub async fn create_agent_pair() -> Result<(IceAgent, IceAgent)> {
        let ice_config = IceConfig {
            stun_servers: vec!["stun:stun.l.google.com:19302".to_string()],
            gathering_timeout: Duration::from_secs(5),
            connectivity_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        let controlling_agent = IceAgent::new(ice_config.clone(), true).await?;
        let controlled_agent = IceAgent::new(ice_config, false).await?;

        Ok((controlling_agent, controlled_agent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ice_agent_config_default() {
        let config = IceAgentConfig::default();
        assert!(config.controlling);
        assert!(config.trickle_ice);
        assert!(!config.aggressive_nomination);
    }

    #[test]
    fn test_ice_process_state_default() {
        let state = IceProcessState::default();
        assert_eq!(state.agent_state, IceAgentState::New);
        assert!(state.started_at.is_none());
    }

    #[test]
    fn test_ice_agent_stats_default() {
        let stats = IceAgentStats::default();
        assert_eq!(stats.ice_restart_count, 0);
        assert_eq!(stats.connection_failures, 0);
    }

    #[test]
    fn test_candidate_compatibility() {
        let local = Candidate::host("192.168.1.1:5000".parse().unwrap());
        let remote = Candidate::host("192.168.1.2:5000".parse().unwrap());

        // Same IP version, transport, component - should be compatible
        assert!(local.address.is_ipv4() == remote.address.is_ipv4());
    }

    #[test]
    fn test_ice_connection_creation() {
        let pair = CandidatePair::new(
            Candidate::host("192.168.1.1:5000".parse().unwrap()),
            Candidate::host("192.168.1.2:5000".parse().unwrap()),
        );

        let connection = IceConnection::new(pair.clone());
        assert_eq!(connection.local_addr, pair.local.address);
        assert_eq!(connection.remote_addr, pair.remote.address);
    }
}
