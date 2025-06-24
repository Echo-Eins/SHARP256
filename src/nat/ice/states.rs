// src/nat/ice/states.rs
//! ICE state management and transitions (RFC 8445)
//!
//! This module manages the complex state transitions during ICE processing,
//! ensuring proper coordination between gathering, connectivity checks, and nomination.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, broadcast};
use tokio::time::{interval, sleep};
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};

use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::agent::{IceState, IceRole};
use crate::nat::ice::candidate::{CandidatePair, CandidatePairState};
use crate::nat::ice::gathering::GatheringPhase;
use crate::nat::ice::nomination::NominationState;

/// ICE component state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentState {
    /// Component is gathering candidates
    Gathering,
    /// Component has candidates but no connectivity
    Ready,
    /// Component is performing connectivity checks
    Checking,
    /// Component has valid pairs but not nominated
    Connected,
    /// Component has nominated pairs
    Nominated,
    /// Component has selected pair (final state)
    Completed,
    /// Component failed to establish connectivity
    Failed,
}

/// ICE check list state per RFC 8445
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckListState {
    /// Check list is running
    Running,
    /// Check list has completed successfully
    Completed,
    /// Check list has failed
    Failed,
}

/// Detailed ICE session state
#[derive(Debug, Clone)]
pub struct IceSessionState {
    /// Overall ICE state
    pub ice_state: IceState,

    /// ICE role
    pub role: Option<IceRole>,

    /// Component states
    pub component_states: HashMap<u32, ComponentState>,

    /// Gathering phase
    pub gathering_phase: GatheringPhase,

    /// Check list state
    pub check_list_state: CheckListState,

    /// Nomination states by component
    pub nomination_states: HashMap<u32, NominationState>,

    /// Valid pairs count by component
    pub valid_pairs: HashMap<u32, u32>,

    /// Nominated pairs count by component
    pub nominated_pairs: HashMap<u32, u32>,

    /// Selected pairs by component
    pub selected_pairs: HashMap<u32, String>,

    /// State transition timestamps
    pub state_transitions: Vec<StateTransition>,

    /// Current phase timings
    pub phase_timings: PhaseTimings,

    /// Error information if failed
    pub failure_reason: Option<String>,
}

/// State transition record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub timestamp: Instant,
    pub from_state: String,
    pub to_state: String,
    pub component_id: Option<u32>,
    pub trigger: TransitionTrigger,
}

/// What triggered a state transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionTrigger {
    /// Candidate discovered
    CandidateAdded,
    /// Gathering completed
    GatheringCompleted,
    /// Check succeeded
    CheckSucceeded,
    /// Check failed
    CheckFailed,
    /// Pair nominated
    PairNominated,
    /// Timeout occurred
    Timeout,
    /// Manual intervention
    Manual,
    /// Error condition
    Error(String),
}

/// Phase timing information
#[derive(Debug, Clone, Default)]
pub struct PhaseTimings {
    /// When gathering started
    pub gathering_start: Option<Instant>,
    /// When gathering completed
    pub gathering_end: Option<Instant>,
    /// When connectivity checks started
    pub connectivity_start: Option<Instant>,
    /// When first valid pair found
    pub first_valid: Option<Instant>,
    /// When nomination started
    pub nomination_start: Option<Instant>,
    /// When nomination completed
    pub nomination_end: Option<Instant>,
    /// When session completed
    pub session_complete: Option<Instant>,
}

impl PhaseTimings {
    /// Get gathering duration
    pub fn gathering_duration(&self) -> Option<Duration> {
        match (self.gathering_start, self.gathering_end) {
            (Some(start), Some(end)) => Some(end.duration_since(start)),
            _ => None,
        }
    }

    /// Get connectivity duration
    pub fn connectivity_duration(&self) -> Option<Duration> {
        match (self.connectivity_start, self.first_valid) {
            (Some(start), Some(end)) => Some(end.duration_since(start)),
            _ => None,
        }
    }

    /// Get nomination duration
    pub fn nomination_duration(&self) -> Option<Duration> {
        match (self.nomination_start, self.nomination_end) {
            (Some(start), Some(end)) => Some(end.duration_since(start)),
            _ => None,
        }
    }

    /// Get total session duration
    pub fn total_duration(&self) -> Option<Duration> {
        match (self.gathering_start, self.session_complete) {
            (Some(start), Some(end)) => Some(end.duration_since(start)),
            _ => None,
        }
    }
}

/// ICE state manager
pub struct IceStateManager {
    /// Current session state
    state: Arc<RwLock<IceSessionState>>,

    /// State change event broadcaster
    event_sender: broadcast::Sender<StateChangeEvent>,

    /// Component configurations
    components: Vec<u32>,

    /// State machine configuration
    config: StateMachineConfig,

    /// Metrics and monitoring
    metrics: Arc<RwLock<StateMetrics>>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,
}

/// State change event
#[derive(Debug, Clone)]
pub enum StateChangeEvent {
    /// ICE state changed
    IceStateChanged {
        old_state: IceState,
        new_state: IceState,
        timestamp: Instant,
    },

    /// Component state changed
    ComponentStateChanged {
        component_id: u32,
        old_state: ComponentState,
        new_state: ComponentState,
        timestamp: Instant,
    },

    /// Gathering phase changed
    GatheringPhaseChanged {
        old_phase: GatheringPhase,
        new_phase: GatheringPhase,
        timestamp: Instant,
    },

    /// Check list state changed
    CheckListStateChanged {
        old_state: CheckListState,
        new_state: CheckListState,
        timestamp: Instant,
    },

    /// Nomination state changed
    NominationStateChanged {
        component_id: u32,
        old_state: NominationState,
        new_state: NominationState,
        timestamp: Instant,
    },
}

/// State machine configuration
#[derive(Debug, Clone)]
pub struct StateMachineConfig {
    /// Timeout for gathering phase
    pub gathering_timeout: Duration,

    /// Timeout for connectivity checks
    pub connectivity_timeout: Duration,

    /// Timeout for nomination
    pub nomination_timeout: Duration,

    /// Enable aggressive state transitions
    pub aggressive_transitions: bool,

    /// Require all components to complete
    pub require_all_components: bool,

    /// Allow fallback to partial connectivity
    pub allow_partial_connectivity: bool,
}

impl Default for StateMachineConfig {
    fn default() -> Self {
        Self {
            gathering_timeout: Duration::from_secs(10),
            connectivity_timeout: Duration::from_secs(20),
            nomination_timeout: Duration::from_secs(10),
            aggressive_transitions: false,
            require_all_components: true,
            allow_partial_connectivity: false,
        }
    }
}

/// State metrics for monitoring
#[derive(Debug, Default, Clone)]
pub struct StateMetrics {
    pub total_transitions: u64,
    pub component_transitions: HashMap<u32, u64>,
    pub phase_transitions: u64,
    pub average_gathering_time: Duration,
    pub average_connectivity_time: Duration,
    pub average_nomination_time: Duration,
    pub success_rate: f64,
    pub failure_reasons: HashMap<String, u32>,
}

impl IceStateManager {
    /// Create new state manager
    pub fn new(components: Vec<u32>, config: StateMachineConfig) -> Self {
        let (event_sender, _) = broadcast::channel(1000);

        let initial_state = IceSessionState {
            ice_state: IceState::Gathering,
            role: None,
            component_states: components.iter().map(|&id| (id, ComponentState::Gathering)).collect(),
            gathering_phase: GatheringPhase::New,
            check_list_state: CheckListState::Running,
            nomination_states: components.iter().map(|&id| (id, NominationState::NotStarted)).collect(),
            valid_pairs: HashMap::new(),
            nominated_pairs: HashMap::new(),
            selected_pairs: HashMap::new(),
            state_transitions: Vec::new(),
            phase_timings: PhaseTimings::default(),
            failure_reason: None,
        };

        Self {
            state: Arc::new(RwLock::new(initial_state)),
            event_sender,
            components,
            config,
            metrics: Arc::new(RwLock::new(StateMetrics::default())),
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Start state management
    pub async fn start(&self) -> NatResult<()> {
        info!("Starting ICE state manager for {} components", self.components.len());

        // Mark gathering start
        {
            let mut state = self.state.write().await;
            state.phase_timings.gathering_start = Some(Instant::now());
        }

        // Start timeout monitoring
        let timeout_monitor = self.start_timeout_monitor();

        // Wait for shutdown
        tokio::select! {
            _ = timeout_monitor => {},
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

    /// Update ICE state
    pub async fn update_ice_state(&self, new_state: IceState) -> NatResult<()> {
        let old_state = {
            let mut state = self.state.write().await;
            let old = state.ice_state;

            if old != new_state {
                state.ice_state = new_state;

                // Record transition
                let transition = StateTransition {
                    timestamp: Instant::now(),
                    from_state: format!("{:?}", old),
                    to_state: format!("{:?}", new_state),
                    component_id: None,
                    trigger: TransitionTrigger::Manual,
                };
                state.state_transitions.push(transition);

                // Update timings
                match new_state {
                    IceState::Connecting => {
                        state.phase_timings.connectivity_start = Some(Instant::now());
                    }
                    IceState::Connected => {
                        state.phase_timings.first_valid = Some(Instant::now());
                    }
                    IceState::Completed => {
                        state.phase_timings.session_complete = Some(Instant::now());
                    }
                    _ => {}
                }

                old
            } else {
                return Ok(());
            }
        };

        // Send event
        let _ = self.event_sender.send(StateChangeEvent::IceStateChanged {
            old_state,
            new_state,
            timestamp: Instant::now(),
        });

        // Update metrics
        self.metrics.write().await.total_transitions += 1;

        info!("ICE state changed: {:?} -> {:?}", old_state, new_state);
        Ok(())
    }

    /// Update component state
    pub async fn update_component_state(
        &self,
        component_id: u32,
        new_state: ComponentState,
        trigger: TransitionTrigger,
    ) -> NatResult<()> {
        let old_state = {
            let mut state = self.state.write().await;
            let old = state.component_states.get(&component_id).copied()
                .unwrap_or(ComponentState::Gathering);

            if old != new_state {
                state.component_states.insert(component_id, new_state);

                // Record transition
                let transition = StateTransition {
                    timestamp: Instant::now(),
                    from_state: format!("{:?}", old),
                    to_state: format!("{:?}", new_state),
                    component_id: Some(component_id),
                    trigger,
                };
                state.state_transitions.push(transition);

                old
            } else {
                return Ok(());
            }
        };

        // Send event
        let _ = self.event_sender.send(StateChangeEvent::ComponentStateChanged {
            component_id,
            old_state,
            new_state,
            timestamp: Instant::now(),
        });

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_transitions += 1;
            *metrics.component_transitions.entry(component_id).or_insert(0) += 1;
        }

        // Check for overall state changes
        self.evaluate_overall_state().await?;

        debug!("Component {} state changed: {:?} -> {:?}", component_id, old_state, new_state);
        Ok(())
    }

    /// Update gathering phase
    pub async fn update_gathering_phase(&self, new_phase: GatheringPhase) -> NatResult<()> {
        let old_phase = {
            let mut state = self.state.write().await;
            let old = state.gathering_phase;

            if old != new_phase {
                state.gathering_phase = new_phase;

                // Update timings
                if new_phase == GatheringPhase::Complete {
                    state.phase_timings.gathering_end = Some(Instant::now());
                }

                old
            } else {
                return Ok(());
            }
        };

        // Send event
        let _ = self.event_sender.send(StateChangeEvent::GatheringPhaseChanged {
            old_phase,
            new_phase,
            timestamp: Instant::now(),
        });

        self.metrics.write().await.phase_transitions += 1;

        debug!("Gathering phase changed: {:?} -> {:?}", old_phase, new_phase);
        Ok(())
    }

    /// Update nomination state
    pub async fn update_nomination_state(
        &self,
        component_id: u32,
        new_state: NominationState,
    ) -> NatResult<()> {
        let old_state = {
            let mut state = self.state.write().await;
            let old = state.nomination_states.get(&component_id).copied()
                .unwrap_or(NominationState::NotStarted);

            if old != new_state {
                state.nomination_states.insert(component_id, new_state);

                // Update timings
                match new_state {
                    NominationState::InProgress => {
                        if state.phase_timings.nomination_start.is_none() {
                            state.phase_timings.nomination_start = Some(Instant::now());
                        }
                    }
                    NominationState::Completed => {
                        state.phase_timings.nomination_end = Some(Instant::now());
                    }
                    _ => {}
                }

                old
            } else {
                return Ok(());
            }
        };

        // Send event
        let _ = self.event_sender.send(StateChangeEvent::NominationStateChanged {
            component_id,
            old_state,
            new_state,
            timestamp: Instant::now(),
        });

        debug!("Component {} nomination state changed: {:?} -> {:?}",
               component_id, old_state, new_state);
        Ok(())
    }

    /// Add candidate for component
    pub async fn add_candidate(&self, component_id: u32) -> NatResult<()> {
        self.update_component_state(
            component_id,
            ComponentState::Ready,
            TransitionTrigger::CandidateAdded,
        ).await
    }

    /// Mark valid pair for component
    pub async fn add_valid_pair(&self, component_id: u32) -> NatResult<()> {
        {
            let mut state = self.state.write().await;
            let count = state.valid_pairs.entry(component_id).or_insert(0);
            *count += 1;
        }

        self.update_component_state(
            component_id,
            ComponentState::Connected,
            TransitionTrigger::CheckSucceeded,
        ).await
    }

    /// Mark nominated pair for component
    pub async fn add_nominated_pair(&self, component_id: u32, pair_id: String) -> NatResult<()> {
        {
            let mut state = self.state.write().await;
            let count = state.nominated_pairs.entry(component_id).or_insert(0);
            *count += 1;
            state.selected_pairs.insert(component_id, pair_id);
        }

        self.update_component_state(
            component_id,
            ComponentState::Nominated,
            TransitionTrigger::PairNominated,
        ).await?;

        self.update_nomination_state(component_id, NominationState::Completed).await
    }

    /// Mark component as completed
    pub async fn complete_component(&self, component_id: u32) -> NatResult<()> {
        self.update_component_state(
            component_id,
            ComponentState::Completed,
            TransitionTrigger::Manual,
        ).await
    }

    /// Mark component as failed
    pub async fn fail_component(&self, component_id: u32, reason: String) -> NatResult<()> {
        {
            let mut state = self.state.write().await;
            if state.failure_reason.is_none() {
                state.failure_reason = Some(reason.clone());
            }
        }

        // Update failure metrics
        {
            let mut metrics = self.metrics.write().await;
            *metrics.failure_reasons.entry(reason.clone()).or_insert(0) += 1;
        }

        self.update_component_state(
            component_id,
            ComponentState::Failed,
            TransitionTrigger::Error(reason),
        ).await
    }

    /// Evaluate overall ICE state based on components
    async fn evaluate_overall_state(&self) -> NatResult<()> {
        let (component_states, current_ice_state) = {
            let state = self.state.read().await;
            (state.component_states.clone(), state.ice_state)
        };

        let new_ice_state = if component_states.values().all(|&s| s == ComponentState::Failed) {
            IceState::Failed
        } else if self.config.require_all_components {
            if component_states.values().all(|&s| s == ComponentState::Completed) {
                IceState::Completed
            } else if component_states.values().any(|&s| s == ComponentState::Connected || s == ComponentState::Nominated) {
                IceState::Connected
            } else if component_states.values().any(|&s| s == ComponentState::Checking) {
                IceState::Connecting
            } else {
                current_ice_state
            }
        } else {
            // Allow partial connectivity
            if component_states.values().any(|&s| s == ComponentState::Completed) {
                IceState::Completed
            } else if component_states.values().any(|&s| s == ComponentState::Connected || s == ComponentState::Nominated) {
                IceState::Connected
            } else if component_states.values().any(|&s| s == ComponentState::Checking) {
                IceState::Connecting
            } else {
                current_ice_state
            }
        };

        if new_ice_state != current_ice_state {
            self.update_ice_state(new_ice_state).await?;
        }

        Ok(())
    }

    /// Start timeout monitoring
    async fn start_timeout_monitor(&self) -> NatResult<()> {
        let mut timer = interval(Duration::from_secs(1));

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            self.check_timeouts().await?;
        }

        Ok(())
    }

    /// Check for timeouts
    async fn check_timeouts(&self) -> NatResult<()> {
        let now = Instant::now();
        let state = self.state.read().await;

        // Check gathering timeout
        if let Some(start) = state.phase_timings.gathering_start {
            if state.gathering_phase != GatheringPhase::Complete &&
                now.duration_since(start) > self.config.gathering_timeout {

                drop(state);
                warn!("Gathering timeout exceeded");
                self.update_gathering_phase(GatheringPhase::Failed).await?;
                return Ok(());
            }
        }

        // Check connectivity timeout
        if let Some(start) = state.phase_timings.connectivity_start {
            if state.ice_state == IceState::Connecting &&
                now.duration_since(start) > self.config.connectivity_timeout {

                drop(state);
                warn!("Connectivity timeout exceeded");
                self.update_ice_state(IceState::Failed).await?;
                return Ok(());
            }
        }

        // Check nomination timeout
        if let Some(start) = state.phase_timings.nomination_start {
            if state.ice_state == IceState::Connected &&
                now.duration_since(start) > self.config.nomination_timeout {

                drop(state);
                warn!("Nomination timeout exceeded");

                // Mark all non-completed components as failed
                let components: Vec<u32> = state.component_states.keys().cloned().collect();
                drop(state);

                for component_id in components {
                    let comp_state = {
                        let state = self.state.read().await;
                        state.component_states.get(&component_id).copied()
                    };

                    if let Some(ComponentState::Connected) = comp_state {
                        self.fail_component(component_id, "Nomination timeout".to_string()).await?;
                    }
                }

                return Ok(());
            }
        }

        Ok(())
    }

    /// Get current state
    pub async fn get_state(&self) -> IceSessionState {
        self.state.read().await.clone()
    }

    /// Get component state
    pub async fn get_component_state(&self, component_id: u32) -> Option<ComponentState> {
        let state = self.state.read().await;
        state.component_states.get(&component_id).copied()
    }

    /// Get metrics
    pub async fn get_metrics(&self) -> StateMetrics {
        let mut metrics = self.metrics.read().await.clone();

        // Calculate success rate
        let state = self.state.read().await;
        let completed_components = state.component_states.values()
            .filter(|&&s| s == ComponentState::Completed)
            .count();
        let total_components = state.component_states.len();

        metrics.success_rate = if total_components > 0 {
            completed_components as f64 / total_components as f64
        } else {
            0.0
        };

        // Update average timings
        if let Some(duration) = state.phase_timings.gathering_duration() {
            metrics.average_gathering_time = duration;
        }
        if let Some(duration) = state.phase_timings.connectivity_duration() {
            metrics.average_connectivity_time = duration;
        }
        if let Some(duration) = state.phase_timings.nomination_duration() {
            metrics.average_nomination_time = duration;
        }

        metrics
    }

    /// Subscribe to state change events
    pub fn subscribe_events(&self) -> broadcast::Receiver<StateChangeEvent> {
        self.event_sender.subscribe()
    }

    /// Check if session is complete
    pub async fn is_complete(&self) -> bool {
        let state = self.state.read().await;
        matches!(state.ice_state, IceState::Completed | IceState::Failed)
    }

    /// Check if session failed
    pub async fn is_failed(&self) -> bool {
        let state = self.state.read().await;
        state.ice_state == IceState::Failed
    }

    /// Get failure reason
    pub async fn get_failure_reason(&self) -> Option<String> {
        let state = self.state.read().await;
        state.failure_reason.clone()
    }

    /// Stop state manager
    pub async fn stop(&self) {
        *self.shutdown.write().await = true;
        info!("ICE state manager stopped");
    }

    /// Reset state for restart
    pub async fn reset(&self) -> NatResult<()> {
        let mut state = self.state.write().await;

        state.ice_state = IceState::Gathering;
        state.gathering_phase = GatheringPhase::New;
        state.check_list_state = CheckListState::Running;

        for component_id in &self.components {
            state.component_states.insert(*component_id, ComponentState::Gathering);
            state.nomination_states.insert(*component_id, NominationState::NotStarted);
        }

        state.valid_pairs.clear();
        state.nominated_pairs.clear();
        state.selected_pairs.clear();
        state.state_transitions.clear();
        state.phase_timings = PhaseTimings::default();
        state.failure_reason = None;

        // Mark new gathering start
        state.phase_timings.gathering_start = Some(Instant::now());

        info!("ICE state manager reset");
        Ok(())
    }
}

/// Helper functions for state analysis

/// Determine if components are ready for connectivity checks
pub fn components_ready_for_checks(component_states: &HashMap<u32, ComponentState>) -> bool {
    component_states.values().any(|&state| {
        matches!(state, ComponentState::Ready | ComponentState::Checking | ComponentState::Connected)
    })
}

/// Determine if nomination should start
pub fn should_start_nomination(component_states: &HashMap<u32, ComponentState>) -> bool {
    component_states.values().any(|&state| state == ComponentState::Connected)
}

/// Check if session can be considered successful with partial connectivity
pub fn is_partial_success_acceptable(
    component_states: &HashMap<u32, ComponentState>,
    required_components: &[u32],
) -> bool {
    required_components.iter().any(|&id| {
        component_states.get(&id)
            .map(|&state| matches!(state, ComponentState::Connected | ComponentState::Nominated | ComponentState::Completed))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_state_manager_creation() {
        let components = vec![1, 2];
        let config = StateMachineConfig::default();
        let manager = IceStateManager::new(components, config);

        let state = manager.get_state().await;
        assert_eq!(state.ice_state, IceState::Gathering);
        assert_eq!(state.component_states.len(), 2);
    }

    #[tokio::test]
    async fn test_component_state_transitions() {
        let components = vec![1];
        let config = StateMachineConfig::default();
        let manager = IceStateManager::new(components, config);

        // Test normal progression
        manager.add_candidate(1).await.unwrap();
        assert_eq!(manager.get_component_state(1).await, Some(ComponentState::Ready));

        manager.add_valid_pair(1).await.unwrap();
        assert_eq!(manager.get_component_state(1).await, Some(ComponentState::Connected));

        manager.add_nominated_pair(1, "pair1".to_string()).await.unwrap();
        assert_eq!(manager.get_component_state(1).await, Some(ComponentState::Nominated));
    }

    #[tokio::test]
    async fn test_phase_timings() {
        let components = vec![1];
        let config = StateMachineConfig::default();
        let manager = IceStateManager::new(components, config);

        // Start the manager to initialize timing
        let _handle = tokio::spawn(manager.start());

        tokio::time::sleep(Duration::from_millis(10)).await;

        let state = manager.get_state().await;
        assert!(state.phase_timings.gathering_start.is_some());

        manager.stop().await;
    }

    #[test]
    fn test_helper_functions() {
        let mut states = HashMap::new();
        states.insert(1, ComponentState::Ready);
        states.insert(2, ComponentState::Gathering);

        assert!(components_ready_for_checks(&states));
        assert!(!should_start_nomination(&states));

        states.insert(1, ComponentState::Connected);
        assert!(should_start_nomination(&states));

        let required = vec![1];
        assert!(is_partial_success_acceptable(&states, &required));
    }
}