// src/nat/ice/nomination.rs
//! ICE nomination process implementation (RFC 8445 Section 8)
//!
//! This module implements both aggressive and regular nomination procedures
//! for selecting candidate pairs to be used for media transmission.

use std::collections::{HashMap, HashSet, BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, broadcast};
use tokio::time::{interval, sleep};
use tracing::{debug, info, warn, error, trace};

use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::candidate::{CandidatePair, CandidateType, TransportProtocol};
use crate::nat::ice::connectivity::{ConnectivityChecker, CheckResult};

/// Nomination mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NominationMode {
    /// Regular nomination (RFC 8445 Section 8.1.1)
    Regular,
    /// Aggressive nomination (RFC 8445 Section 8.1.2)
    Aggressive,
}

/// Nomination state for a component
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NominationState {
    /// No nomination started
    NotStarted,
    /// Nomination in progress
    InProgress,
    /// At least one pair nominated
    Nominated,
    /// All components nominated (completed)
    Completed,
    /// Nomination failed
    Failed,
}

/// Nomination event
#[derive(Debug, Clone)]
pub enum NominationEvent {
    /// Pair was nominated
    PairNominated {
        component_id: u32,
        pair_id: String,
        priority: u64,
    },
    /// Component nomination completed
    ComponentCompleted {
        component_id: u32,
        selected_pair: String,
    },
    /// All components completed
    NominationCompleted {
        selected_pairs: HashMap<u32, String>,
    },
    /// Nomination failed for component
    NominationFailed {
        component_id: u32,
        reason: String,
    },
}

/// Nomination strategy configuration
#[derive(Debug, Clone)]
pub struct NominationConfig {
    /// Nomination mode
    pub mode: NominationMode,
    /// Minimum delay before starting nomination (for regular mode)
    pub nomination_delay: Duration,
    /// Maximum time to wait for nomination completion
    pub nomination_timeout: Duration,
    /// Prefer relay candidates over reflexive
    pub prefer_relay: bool,
    /// Prefer IPv6 over IPv4
    pub prefer_ipv6: bool,
    /// Require nominated pair for each component
    pub require_all_components: bool,
    /// Maximum number of nomination attempts per pair
    pub max_nomination_attempts: u32,
}

impl Default for NominationConfig {
    fn default() -> Self {
        Self {
            mode: NominationMode::Regular,
            nomination_delay: Duration::from_millis(100),
            nomination_timeout: Duration::from_secs(30),
            prefer_relay: false,
            prefer_ipv6: false,
            require_all_components: true,
            max_nomination_attempts: 3,
        }
    }
}

/// Nomination processor manages candidate pair nomination
pub struct NominationProcessor {
    /// Configuration
    config: NominationConfig,

    /// Role (controlling agent performs nomination)
    controlling: Arc<RwLock<bool>>,

    /// Component nomination states
    component_states: Arc<RwLock<HashMap<u32, ComponentNominationState>>>,

    /// Valid pairs by component
    valid_pairs: Arc<RwLock<HashMap<u32, Vec<CandidatePair>>>>,

    /// Nominated pairs by component
    nominated_pairs: Arc<RwLock<HashMap<u32, Vec<CandidatePair>>>>,

    /// Selected pairs (final result)
    selected_pairs: Arc<RwLock<HashMap<u32, CandidatePair>>>,

    /// Connectivity checker reference
    connectivity_checker: Arc<ConnectivityChecker>,

    /// Event broadcaster
    event_sender: broadcast::Sender<NominationEvent>,

    /// Nomination start time by component
    nomination_start_times: Arc<RwLock<HashMap<u32, Instant>>>,

    /// Pending nominations (for regular mode)
    pending_nominations: Arc<RwLock<VecDeque<PendingNomination>>>,

    /// Nomination attempts tracking
    nomination_attempts: Arc<RwLock<HashMap<String, u32>>>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,

    /// Statistics
    stats: Arc<RwLock<NominationStats>>,
}

/// Component nomination state
#[derive(Debug, Clone)]
struct ComponentNominationState {
    state: NominationState,
    best_pair: Option<CandidatePair>,
    nomination_queue: VecDeque<CandidatePair>,
    last_nomination_time: Option<Instant>,
}

/// Pending nomination (for regular mode)
#[derive(Debug, Clone)]
struct PendingNomination {
    component_id: u32,
    pair: CandidatePair,
    scheduled_time: Instant,
    attempts: u32,
}

/// Nomination statistics
#[derive(Debug, Default, Clone)]
pub struct NominationStats {
    pub total_nominations: u64,
    pub successful_nominations: u64,
    pub failed_nominations: u64,
    pub components_completed: u32,
    pub average_nomination_time: Duration,
    pub aggressive_nominations: u64,
    pub regular_nominations: u64,
}

impl NominationProcessor {
    /// Create new nomination processor
    pub fn new(
        config: NominationConfig,
        controlling: bool,
        connectivity_checker: Arc<ConnectivityChecker>,
    ) -> Self {
        let (event_sender, _) = broadcast::channel(100);

        Self {
            config,
            controlling: Arc::new(RwLock::new(controlling)),
            component_states: Arc::new(RwLock::new(HashMap::new())),
            valid_pairs: Arc::new(RwLock::new(HashMap::new())),
            nominated_pairs: Arc::new(RwLock::new(HashMap::new())),
            selected_pairs: Arc::new(RwLock::new(HashMap::new())),
            connectivity_checker,
            event_sender,
            nomination_start_times: Arc::new(RwLock::new(HashMap::new())),
            pending_nominations: Arc::new(RwLock::new(VecDeque::new())),
            nomination_attempts: Arc::new(RwLock::new(HashMap::new())),
            shutdown: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(NominationStats::default())),
        }
    }

    /// Start nomination process
    pub async fn start_nomination(&self, components: Vec<u32>) -> NatResult<()> {
        if !*self.controlling.read().await {
            debug!("Not controlling agent - nomination handled by peer");
            return Ok(());
        }

        info!("Starting {} nomination for {} components",
              match self.config.mode {
                  NominationMode::Aggressive => "aggressive",
                  NominationMode::Regular => "regular",
              },
              components.len());

        // Initialize component states
        {
            let mut states = self.component_states.write().await;
            let mut start_times = self.nomination_start_times.write().await;

            for component_id in components {
                states.insert(component_id, ComponentNominationState {
                    state: NominationState::NotStarted,
                    best_pair: None,
                    nomination_queue: VecDeque::new(),
                    last_nomination_time: None,
                });
                start_times.insert(component_id, Instant::now());
            }
        }

        // Subscribe to connectivity check results
        let mut result_receiver = self.connectivity_checker.subscribe_results();

        // Start nomination processor task
        let processor_task = self.clone_for_task().start_nomination_processor();

        // Start result processor task
        let result_task = async {
            while let Ok(result) = result_receiver.recv().await {
                if *self.shutdown.read().await {
                    break;
                }

                if let Err(e) = self.process_connectivity_result(result).await {
                    warn!("Error processing connectivity result: {}", e);
                }
            }
        };

        // Wait for completion or shutdown
        tokio::select! {
            _ = processor_task => {},
            _ = result_task => {},
            _ = async {
                loop {
                    if *self.shutdown.read().await {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            } => {},
        }

        Ok(())
    }

    /// Clone for background task (avoiding Send issues with Arc<RwLock>)
    fn clone_for_task(&self) -> NominationProcessorTask {
        NominationProcessorTask {
            config: self.config.clone(),
            controlling: self.controlling.clone(),
            component_states: self.component_states.clone(),
            valid_pairs: self.valid_pairs.clone(),
            nominated_pairs: self.nominated_pairs.clone(),
            selected_pairs: self.selected_pairs.clone(),
            connectivity_checker: self.connectivity_checker.clone(),
            event_sender: self.event_sender.clone(),
            nomination_start_times: self.nomination_start_times.clone(),
            pending_nominations: self.pending_nominations.clone(),
            nomination_attempts: self.nomination_attempts.clone(),
            shutdown: self.shutdown.clone(),
            stats: self.stats.clone(),
        }
    }

    /// Process connectivity check result
    async fn process_connectivity_result(&self, result: CheckResult) -> NatResult<()> {
        match result {
            CheckResult::Success { pair_id, nominated, .. } => {
                if nominated {
                    self.handle_pair_nomination(&pair_id).await?;
                } else {
                    self.update_valid_pairs(&pair_id).await?;
                }
            }
            CheckResult::Failure { pair_id, .. } => {
                self.handle_pair_failure(&pair_id).await?;
            }
            CheckResult::Timeout { pair_id } => {
                self.handle_pair_timeout(&pair_id).await?;
            }
        }

        Ok(())
    }

    /// Handle successful pair nomination
    async fn handle_pair_nomination(&self, pair_id: &str) -> NatResult<()> {
        info!("Pair {} nominated successfully", pair_id);

        // Find the component for this pair
        let component_id = self.find_component_for_pair(pair_id).await
            .ok_or_else(|| NatError::Configuration("Pair not found in any component".to_string()))?;

        // Get the pair details
        let pair = {
            let valid_pairs = self.valid_pairs.read().await;
            valid_pairs.get(&component_id)
                .and_then(|pairs| pairs.iter().find(|p| p.id() == pair_id))
                .cloned()
                .ok_or_else(|| NatError::Configuration("Nominated pair not in valid list".to_string()))?
        };

        // Update nominated pairs
        {
            let mut nominated_pairs = self.nominated_pairs.write().await;
            nominated_pairs.entry(component_id)
                .or_insert_with(Vec::new)
                .push(pair.clone());
        }

        // Update component state
        {
            let mut states = self.component_states.write().await;
            if let Some(state) = states.get_mut(&component_id) {
                state.state = NominationState::Nominated;

                // Update best pair if this is better
                if let Some(ref current_best) = state.best_pair {
                    if pair.priority > current_best.priority {
                        state.best_pair = Some(pair.clone());
                    }
                } else {
                    state.best_pair = Some(pair.clone());
                }
            }
        }

        // Update selected pair for component
        {
            let mut selected_pairs = self.selected_pairs.write().await;
            selected_pairs.insert(component_id, pair.clone());
        }

        // Send event
        let _ = self.event_sender.send(NominationEvent::PairNominated {
            component_id,
            pair_id: pair_id.to_string(),
            priority: pair.priority,
        });

        // Check if component is complete
        self.check_component_completion(component_id).await?;

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.successful_nominations += 1;

        match self.config.mode {
            NominationMode::Aggressive => stats.aggressive_nominations += 1,
            NominationMode::Regular => stats.regular_nominations += 1,
        }

        Ok(())
    }

    /// Handle pair failure
    async fn handle_pair_failure(&self, pair_id: &str) -> NatResult<()> {
        debug!("Pair {} failed", pair_id);

        if let Some(component_id) = self.find_component_for_pair(pair_id).await {
            // Remove from nomination queue if present
            let mut states = self.component_states.write().await;
            if let Some(state) = states.get_mut(&component_id) {
                state.nomination_queue.retain(|p| p.id() != pair_id);
            }
        }

        self.stats.write().await.failed_nominations += 1;
        Ok(())
    }

    /// Handle pair timeout
    async fn handle_pair_timeout(&self, pair_id: &str) -> NatResult<()> {
        debug!("Pair {} timed out", pair_id);
        self.handle_pair_failure(pair_id).await
    }

    /// Update valid pairs list
    async fn update_valid_pairs(&self, pair_id: &str) -> NatResult<()> {
        // This would be called when a pair becomes valid but isn't nominated yet
        // Implementation depends on how valid pairs are tracked
        Ok(())
    }

    /// Find component ID for a pair
    async fn find_component_for_pair(&self, pair_id: &str) -> Option<u32> {
        let valid_pairs = self.valid_pairs.read().await;
        for (component_id, pairs) in valid_pairs.iter() {
            if pairs.iter().any(|p| p.id() == pair_id) {
                return Some(*component_id);
            }
        }
        None
    }

    /// Check if component nomination is complete
    async fn check_component_completion(&self, component_id: u32) -> NatResult<()> {
        let is_complete = {
            let states = self.component_states.read().await;
            let nominated_pairs = self.nominated_pairs.read().await;

            // Component is complete if it has at least one nominated pair
            nominated_pairs.get(&component_id)
                .map(|pairs| !pairs.is_empty())
                .unwrap_or(false)
        };

        if is_complete {
            // Update component state
            {
                let mut states = self.component_states.write().await;
                if let Some(state) = states.get_mut(&component_id) {
                    state.state = NominationState::Completed;
                }
            }

            // Get selected pair
            let selected_pair = {
                let selected_pairs = self.selected_pairs.read().await;
                selected_pairs.get(&component_id)
                    .map(|pair| pair.id())
                    .unwrap_or_else(|| "unknown".to_string())
            };

            // Send event
            let _ = self.event_sender.send(NominationEvent::ComponentCompleted {
                component_id,
                selected_pair,
            });

            // Update statistics
            let mut stats = self.stats.write().await;
            stats.components_completed += 1;

            // Calculate average nomination time
            if let Some(start_time) = self.nomination_start_times.read().await.get(&component_id) {
                let nomination_time = start_time.elapsed();
                let total_time = stats.average_nomination_time.as_millis() as u64 * (stats.components_completed - 1) as u64
                    + nomination_time.as_millis() as u64;
                stats.average_nomination_time = Duration::from_millis(total_time / stats.components_completed as u64);
            }

            info!("Component {} nomination completed", component_id);

            // Check if all components are complete
            self.check_overall_completion().await?;
        }

        Ok(())
    }

    /// Check if overall nomination is complete
    async fn check_overall_completion(&self) -> NatResult<()> {
        let all_complete = {
            let states = self.component_states.read().await;
            states.values().all(|state| state.state == NominationState::Completed)
        };

        if all_complete {
            let selected_pairs = self.selected_pairs.read().await.clone();

            let _ = self.event_sender.send(NominationEvent::NominationCompleted {
                selected_pairs: selected_pairs.iter()
                    .map(|(id, pair)| (*id, pair.id()))
                    .collect(),
            });

            info!("ICE nomination completed for all components");
        }

        Ok(())
    }

    /// Add valid pairs for component
    pub async fn add_valid_pairs(&self, component_id: u32, pairs: Vec<CandidatePair>) {
        let mut valid_pairs = self.valid_pairs.write().await;
        let component_pairs = valid_pairs.entry(component_id).or_insert_with(Vec::new);

        for pair in pairs {
            if !component_pairs.iter().any(|p| p.id() == pair.id()) {
                component_pairs.push(pair);
            }
        }

        // Sort by priority (highest first)
        component_pairs.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Update nomination queue
        if self.config.mode == NominationMode::Regular {
            self.update_nomination_queue(component_id).await;
        }
    }

    /// Update nomination queue for regular nomination
    async fn update_nomination_queue(&self, component_id: u32) {
        let mut states = self.component_states.write().await;
        let valid_pairs = self.valid_pairs.read().await;

        if let (Some(state), Some(pairs)) = (states.get_mut(&component_id), valid_pairs.get(&component_id)) {
            // Add new pairs to nomination queue based on priority and preferences
            for pair in pairs {
                if !state.nomination_queue.iter().any(|p| p.id() == pair.id()) {
                    let should_add = self.should_nominate_pair(pair).await;
                    if should_add {
                        // Insert in priority order
                        let insert_pos = state.nomination_queue
                            .binary_search_by(|p| p.priority.cmp(&pair.priority))
                            .unwrap_or_else(|pos| pos);
                        state.nomination_queue.insert(insert_pos, pair.clone());
                    }
                }
            }
        }
    }

    /// Check if pair should be nominated based on preferences
    async fn should_nominate_pair(&self, pair: &CandidatePair) -> bool {
        // Apply nomination preferences

        // Prefer relay if configured
        if self.config.prefer_relay {
            if pair.local.candidate_type == CandidateType::Relay ||
                pair.remote.candidate_type == CandidateType::Relay {
                return true;
            }
        }

        // Prefer IPv6 if configured
        if self.config.prefer_ipv6 {
            if pair.local.is_ipv6() && pair.remote.is_ipv6() {
                return true;
            }
        }

        // Default: nominate all valid pairs
        true
    }

    /// Get nomination state for component
    pub async fn get_component_state(&self, component_id: u32) -> Option<NominationState> {
        let states = self.component_states.read().await;
        states.get(&component_id).map(|s| s.state)
    }

    /// Get selected pairs
    pub async fn get_selected_pairs(&self) -> HashMap<u32, CandidatePair> {
        self.selected_pairs.read().await.clone()
    }

    /// Get nominated pairs for component
    pub async fn get_nominated_pairs(&self, component_id: u32) -> Vec<CandidatePair> {
        let nominated_pairs = self.nominated_pairs.read().await;
        nominated_pairs.get(&component_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get nomination statistics
    pub async fn get_statistics(&self) -> NominationStats {
        self.stats.read().await.clone()
    }

    /// Subscribe to nomination events
    pub fn subscribe_events(&self) -> broadcast::Receiver<NominationEvent> {
        self.event_sender.subscribe()
    }

    /// Stop nomination process
    pub async fn stop(&self) {
        *self.shutdown.write().await = true;
        info!("Nomination processor stopped");
    }

    /// Check if nomination is complete
    pub async fn is_complete(&self) -> bool {
        let states = self.component_states.read().await;
        !states.is_empty() && states.values().all(|state| {
            matches!(state.state, NominationState::Completed | NominationState::Failed)
        })
    }

    /// Force nomination of specific pair
    pub async fn force_nominate_pair(&self, component_id: u32, pair_id: &str) -> NatResult<()> {
        if !*self.controlling.read().await {
            return Err(NatError::Configuration("Only controlling agent can nominate".to_string()));
        }

        // Find the pair
        let pair = {
            let valid_pairs = self.valid_pairs.read().await;
            valid_pairs.get(&component_id)
                .and_then(|pairs| pairs.iter().find(|p| p.id() == pair_id))
                .cloned()
                .ok_or_else(|| NatError::Configuration("Pair not found".to_string()))?
        };

        // Trigger nomination check
        // This would typically send a USE-CANDIDATE check
        // Implementation depends on connectivity checker interface

        info!("Forced nomination of pair {} for component {}", pair_id, component_id);
        Ok(())
    }
}

/// Task wrapper for background processing
struct NominationProcessorTask {
    config: NominationConfig,
    controlling: Arc<RwLock<bool>>,
    component_states: Arc<RwLock<HashMap<u32, ComponentNominationState>>>,
    valid_pairs: Arc<RwLock<HashMap<u32, Vec<CandidatePair>>>>,
    nominated_pairs: Arc<RwLock<HashMap<u32, Vec<CandidatePair>>>>,
    selected_pairs: Arc<RwLock<HashMap<u32, CandidatePair>>>,
    connectivity_checker: Arc<ConnectivityChecker>,
    event_sender: broadcast::Sender<NominationEvent>,
    nomination_start_times: Arc<RwLock<HashMap<u32, Instant>>>,
    pending_nominations: Arc<RwLock<VecDeque<PendingNomination>>>,
    nomination_attempts: Arc<RwLock<HashMap<String, u32>>>,
    shutdown: Arc<RwLock<bool>>,
    stats: Arc<RwLock<NominationStats>>,
}

impl NominationProcessorTask {
    /// Start nomination processor background task
    async fn start_nomination_processor(&self) -> NatResult<()> {
        match self.config.mode {
            NominationMode::Aggressive => self.process_aggressive_nomination().await,
            NominationMode::Regular => self.process_regular_nomination().await,
        }
    }

    /// Process aggressive nomination
    async fn process_aggressive_nomination(&self) -> NatResult<()> {
        info!("Starting aggressive nomination");

        // In aggressive mode, we nominate pairs as soon as they become valid
        // The actual nomination is handled by the connectivity checker
        // This task just monitors for completion

        let mut timer = interval(Duration::from_millis(100));

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            // Check for timeout
            let now = Instant::now();
            let start_times = self.nomination_start_times.read().await;

            for (component_id, start_time) in start_times.iter() {
                if now.duration_since(*start_time) > self.config.nomination_timeout {
                    warn!("Nomination timeout for component {}", component_id);

                    let _ = self.event_sender.send(NominationEvent::NominationFailed {
                        component_id: *component_id,
                        reason: "Timeout".to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Process regular nomination
    async fn process_regular_nomination(&self) -> NatResult<()> {
        info!("Starting regular nomination");

        let mut timer = interval(Duration::from_millis(50));

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            // Process pending nominations
            self.process_pending_nominations().await?;

            // Schedule new nominations
            self.schedule_nominations().await?;
        }

        Ok(())
    }

    /// Process pending nominations
    async fn process_pending_nominations(&self) -> NatResult<()> {
        let now = Instant::now();
        let mut nominations_to_send = Vec::new();

        // Collect due nominations
        {
            let mut pending = self.pending_nominations.write().await;
            while let Some(nomination) = pending.front() {
                if now >= nomination.scheduled_time {
                    nominations_to_send.push(pending.pop_front().unwrap());
                } else {
                    break;
                }
            }
        }

        // Send nominations
        for nomination in nominations_to_send {
            if nomination.attempts < self.config.max_nomination_attempts {
                // Send nomination check (with USE-CANDIDATE)
                // This would interface with connectivity checker
                self.send_nomination_check(&nomination).await?;

                // Reschedule if needed
                if nomination.attempts + 1 < self.config.max_nomination_attempts {
                    let mut updated = nomination.clone();
                    updated.attempts += 1;
                    updated.scheduled_time = now + Duration::from_millis(500 * (1 << updated.attempts));

                    self.pending_nominations.write().await.push_back(updated);
                }
            }
        }

        Ok(())
    }

    /// Schedule new nominations
    async fn schedule_nominations(&self) -> NatResult<()> {
        let now = Instant::now();

        let states = self.component_states.read().await;
        for (component_id, state) in states.iter() {
            if state.state == NominationState::NotStarted || state.state == NominationState::InProgress {
                // Check if it's time to nominate the next pair
                let should_nominate = if let Some(last_time) = state.last_nomination_time {
                    now.duration_since(last_time) > self.config.nomination_delay
                } else {
                    true // First nomination
                };

                if should_nominate && !state.nomination_queue.is_empty() {
                    let pair = state.nomination_queue.front().unwrap().clone();

                    let pending = PendingNomination {
                        component_id: *component_id,
                        pair,
                        scheduled_time: now,
                        attempts: 0,
                    };

                    self.pending_nominations.write().await.push_back(pending);
                }
            }
        }

        Ok(())
    }

    /// Send nomination check
    async fn send_nomination_check(&self, nomination: &PendingNomination) -> NatResult<()> {
        // This would interface with the connectivity checker to send a USE-CANDIDATE check
        // For now, we'll just log it
        debug!("Sending nomination check for pair {} (attempt {})",
               nomination.pair.id(), nomination.attempts + 1);

        // Update statistics
        self.stats.write().await.total_nominations += 1;

        Ok(())
    }
}

/// Nomination helper functions

/// Calculate pair nomination score based on preferences
pub fn calculate_nomination_score(pair: &CandidatePair, config: &NominationConfig) -> u32 {
    let mut score = 0;

    // Base score from priority
    score += (pair.priority / 1000000) as u32;

    // Preference bonuses
    if config.prefer_relay {
        if pair.local.candidate_type == CandidateType::Relay {
            score += 1000;
        }
        if pair.remote.candidate_type == CandidateType::Relay {
            score += 500;
        }
    }

    if config.prefer_ipv6 {
        if pair.local.is_ipv6() && pair.remote.is_ipv6() {
            score += 200;
        }
    }

    // Prefer host candidates for direct connections
    if pair.local.candidate_type == CandidateType::Host &&
        pair.remote.candidate_type == CandidateType::Host {
        score += 300;
    }

    score
}

/// Check if component has sufficient nominated pairs
pub fn has_sufficient_nomination(pairs: &[CandidatePair]) -> bool {
    // For basic functionality, we need at least one nominated pair
    pairs.iter().any(|p| p.nominated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::ice::candidate::{Candidate, CandidateExtensions};
    use crate::nat::ice::connectivity::ConnectivityChecker;

    #[tokio::test]
    async fn test_nomination_processor_creation() {
        let config = NominationConfig::default();
        let checker = Arc::new(ConnectivityChecker::new(1, true, false));
        let processor = NominationProcessor::new(config, true, checker);

        assert_eq!(processor.config.mode, NominationMode::Regular);
    }

    #[tokio::test]
    async fn test_nomination_config() {
        let config = NominationConfig {
            mode: NominationMode::Aggressive,
            prefer_relay: true,
            prefer_ipv6: true,
            ..Default::default()
        };

        assert_eq!(config.mode, NominationMode::Aggressive);
        assert!(config.prefer_relay);
        assert!(config.prefer_ipv6);
    }

    #[test]
    fn test_nomination_score_calculation() {
        let local = Candidate::new_host(
            "192.168.1.1:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );

        let remote = Candidate::new_host(
            "192.168.1.2:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );

        let pair = CandidatePair::new(local, remote, true);
        let config = NominationConfig::default();

        let score = calculate_nomination_score(&pair, &config);
        assert!(score > 0);
    }

    #[test]
    fn test_sufficient_nomination() {
        let local = Candidate::new_host(
            "192.168.1.1:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );

        let remote = Candidate::new_host(
            "192.168.1.2:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );

        let mut pair = CandidatePair::new(local, remote, true);

        // Initially not nominated
        assert!(!has_sufficient_nomination(&[pair.clone()]));

        // After nomination
        pair.nominate();
        assert!(has_sufficient_nomination(&[pair]));
    }
}