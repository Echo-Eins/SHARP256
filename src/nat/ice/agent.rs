// src/nat/ice/agent.rs
//! Main ICE agent implementation with full RFC 8445 compliance

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::{interval, timeout, sleep};
use tracing::{info, warn, error, debug};

use crate::nat::error::{NatError, NatResult};
use super::{
    Candidate, CandidateType, IceCredentials, IceEvent, IceTransportPolicy,
    connectivity::{ConnectivityChecker, ConnectivityEvent},
    gathering::{CandidateGatherer, GatheringEvent, TurnServerConfig},
    stream::IceStream,
    trickle::{TrickleIce, TrickleEvent},
};

/// ICE agent configuration
#[derive(Debug, Clone)]
pub struct IceConfig {
    /// ICE transport policy
    pub ice_transport_policy: IceTransportPolicy,

    /// STUN servers
    pub stun_servers: Vec<String>,

    /// TURN servers
    pub turn_servers: Vec<TurnServerConfig>,

    /// Enable Trickle ICE
    pub trickle: bool,

    /// Enable aggressive nomination
    pub aggressive_nomination: bool,

    /// Gathering timeout
    pub gathering_timeout: Duration,

    /// Keepalive interval (RFC 8445 Section 11)
    pub keepalive_interval: Duration,

    /// Consent freshness interval (RFC 7675)
    pub consent_interval: Duration,

    /// Component count per stream
    pub component_count: u32,

    /// Enable IPv6
    pub enable_ipv6: bool,

    /// Enable mDNS candidates
    pub enable_mdns: bool,

    /// ICE restart timeout
    pub restart_timeout: Duration,

    /// Max consent failures before disconnect
    pub max_consent_failures: u32,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            ice_transport_policy: IceTransportPolicy::All,
            stun_servers: vec![
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
            ],
            turn_servers: vec![],
            trickle: true,
            aggressive_nomination: false,
            gathering_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(15),
            consent_interval: Duration::from_secs(30),
            component_count: 1,
            enable_ipv6: true,
            enable_mdns: false,
            restart_timeout: Duration::from_secs(30),
            max_consent_failures: 5,
        }
    }
}

/// ICE role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    Controlling,
    Controlled,
}

/// ICE agent state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    /// Initial state
    New,

    /// Gathering candidates
    Gathering,

    /// Ready to start checks
    Ready,

    /// Performing connectivity checks
    Checking,

    /// At least one working pair
    Connected,

    /// All components have selected pairs
    Completed,

    /// ICE failed
    Failed,

    /// ICE closed
    Closed,

    /// ICE disconnected (consent timeout)
    Disconnected,
}

/// Keep-alive and consent state
#[derive(Debug)]
struct KeepaliveState {
    /// Last keepalive sent time
    last_sent: Instant,

    /// Last response received time
    last_received: Instant,

    /// Consecutive failures
    failures: u32,

    /// Is active
    active: bool,
}

/// Main ICE agent with full RFC compliance
pub struct IceAgent {
    /// Configuration
    config: IceConfig,

    /// Current state
    state: Arc<RwLock<IceState>>,

    /// Role
    role: Arc<RwLock<IceRole>>,

    /// Local credentials
    local_credentials: IceCredentials,

    /// Remote credentials
    remote_credentials: Arc<RwLock<Option<IceCredentials>>>,

    /// Streams
    streams: Arc<RwLock<HashMap<u32, IceStream>>>,

    /// Candidate gatherer
    gatherer: Arc<CandidateGatherer>,

    /// Connectivity checker
    checker: Arc<RwLock<ConnectivityChecker>>,

    /// Trickle ICE handler
    trickle: Option<Arc<TrickleIce>>,

    /// Event channel
    event_tx: mpsc::UnboundedSender<IceEvent>,
    event_rx: Arc<Mutex<mpsc::UnboundedReceiver<IceEvent>>>,

    /// Internal event handlers
    gathering_rx: Arc<Mutex<mpsc::UnboundedReceiver<GatheringEvent>>>,
    connectivity_rx: Arc<Mutex<mpsc::UnboundedReceiver<ConnectivityEvent>>>,
    trickle_rx: Option<Arc<Mutex<mpsc::UnboundedReceiver<TrickleEvent>>>>,

    /// Selected pairs per stream/component
    selected_pairs: Arc<RwLock<HashMap<(u32, u32), (Candidate, Candidate)>>>,

    /// Nomination state
    nomination_complete: Arc<RwLock<bool>>,

    /// Keep-alive states per component
    keepalive_states: Arc<RwLock<HashMap<(u32, u32), KeepaliveState>>>,

    /// Active tasks
    active_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,

    /// ICE restart counter
    restart_counter: Arc<RwLock<u32>>,
}

impl IceAgent {
    /// Create new ICE agent
    pub fn new(config: IceConfig, role: IceRole) -> NatResult<Self> {
        info!("Creating new ICE agent with role {:?}", role);

        let local_credentials = IceCredentials::generate();
        info!("Generated local credentials: ufrag={}, pwd_len={}",
            local_credentials.ufrag, local_credentials.pwd.len());

        // Create event channels
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (gathering_tx, gathering_rx) = mpsc::unbounded_channel();
        let (connectivity_tx, connectivity_rx) = mpsc::unbounded_channel();

        // Create gatherer
        let gatherer = Arc::new(CandidateGatherer::new(
            config.stun_servers.clone(),
            config.turn_servers.clone(),
            config.ice_transport_policy,
            gathering_tx,
        )?);

        // Create connectivity checker
        let checker = Arc::new(RwLock::new(ConnectivityChecker::new(
            role == IceRole::Controlling,
            local_credentials.clone(),
            connectivity_tx,
            config.aggressive_nomination,
        )));

        // Create trickle ICE if enabled
        let (trickle, trickle_rx) = if config.trickle {
            let (trickle_tx, trickle_rx) = mpsc::unbounded_channel();
            let trickle = Arc::new(TrickleIce::new(trickle_tx));
            info!("Trickle ICE enabled");
            (Some(trickle), Some(Arc::new(Mutex::new(trickle_rx))))
        } else {
            info!("Trickle ICE disabled");
            (None, None)
        };

        let agent = Self {
            config,
            state: Arc::new(RwLock::new(IceState::New)),
            role: Arc::new(RwLock::new(role)),
            local_credentials,
            remote_credentials: Arc::new(RwLock::new(None)),
            streams: Arc::new(RwLock::new(HashMap::new())),
            gatherer,
            checker,
            trickle,
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
            gathering_rx: Arc::new(Mutex::new(gathering_rx)),
            connectivity_rx: Arc::new(Mutex::new(connectivity_rx)),
            trickle_rx,
            selected_pairs: Arc::new(RwLock::new(HashMap::new())),
            nomination_complete: Arc::new(RwLock::new(false)),
            keepalive_states: Arc::new(RwLock::new(HashMap::new())),
            active_tasks: Arc::new(Mutex::new(Vec::new())),
            restart_counter: Arc::new(RwLock::new(0)),
        };

        // Start event processing
        agent.start_event_processing();

        Ok(agent)
    }

    /// Get local credentials
    pub fn get_local_credentials(&self) -> &IceCredentials {
        &self.local_credentials
    }

    /// Set remote credentials
    pub async fn set_remote_credentials(&self, credentials: IceCredentials) -> NatResult<()> {
        info!("Setting remote credentials: ufrag={}", credentials.ufrag);
        *self.remote_credentials.write().await = Some(credentials.clone());
        self.checker.write().await.set_remote_credentials(credentials);
        Ok(())
    }

    /// Add stream
    pub async fn add_stream(&self, stream_id: u32) -> NatResult<()> {
        info!("Adding stream {} with {} components", stream_id, self.config.component_count);

        let stream = IceStream::new(stream_id, self.config.component_count);
        self.streams.write().await.insert(stream_id, stream);

        // Initialize keepalive states for each component
        let mut keepalive_states = self.keepalive_states.write().await;
        for component_id in 1..=self.config.component_count {
            keepalive_states.insert(
                (stream_id, component_id),
                KeepaliveState {
                    last_sent: Instant::now(),
                    last_received: Instant::now(),
                    failures: 0,
                    active: false,
                }
            );
        }

        Ok(())
    }

    /// Start gathering candidates
    pub async fn start_gathering(&self) -> NatResult<()> {
        let mut state = self.state.write().await;
        match *state {
            IceState::New => {
                info!("Starting candidate gathering");
                *state = IceState::Gathering;
            }
            IceState::Ready | IceState::Failed => {
                // ICE restart
                info!("ICE restart - gathering new candidates");
                *state = IceState::Gathering;
                *self.restart_counter.write().await += 1;

                // Clear old candidates
                let mut streams = self.streams.write().await;
                for stream in streams.values_mut() {
                    stream.clear_candidates();
                }
            }
            current_state => {
                warn!("Cannot start gathering in state {:?}", current_state);
                return Err(NatError::Platform(
                    format!("Invalid state for gathering: {:?}", current_state)
                ));
            }
        }
        drop(state);

        // Send state change event
        let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Gathering));

        // Gather for each stream/component
        let streams = self.streams.read().await;
        let mut gather_tasks = Vec::new();

        for (stream_id, stream) in streams.iter() {
            for component_id in 1..=stream.component_count {
                let gatherer = self.gatherer.clone();
                let stream_id = *stream_id;

                info!("Starting gathering for stream {} component {}", stream_id, component_id);

                let task = tokio::spawn(async move {
                    if let Err(e) = gatherer.gather_candidates(component_id, 0).await {
                        error!("Failed to gather candidates for component {}: {}", component_id, e);
                    }
                });

                gather_tasks.push(task);
            }
        }

        // Start gathering timeout
        let agent = self.clone();
        let timeout_duration = self.config.gathering_timeout;
        tokio::spawn(async move {
            sleep(timeout_duration).await;
            agent.handle_gathering_timeout().await;
        });

        Ok(())
    }

    /// Handle gathering timeout
    async fn handle_gathering_timeout(&self) {
        let state = *self.state.read().await;
        if state == IceState::Gathering {
            warn!("Gathering timeout - completing with available candidates");

            // Force gathering complete
            *self.state.write().await = IceState::Ready;
            let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Ready));
            let _ = self.event_tx.send(IceEvent::GatheringComplete);
        }
    }

    /// Add remote candidate
    pub async fn add_remote_candidate(&self, candidate: Candidate) -> NatResult<()> {
        info!("Adding remote candidate: {} for component {}",
            candidate.addr, candidate.component_id);

        // Find the stream
        let mut streams = self.streams.write().await;

        // Find stream by iterating (component_id might not match stream_id)
        let stream = streams.values_mut()
            .find(|s| s.id == 1) // Default to stream 1 for now
            .ok_or_else(|| NatError::Platform("No streams available".to_string()))?;

        stream.add_remote_candidate(candidate.clone());

        // If we're already checking, add to checker
        if *self.state.read().await == IceState::Checking {
            debug!("Adding candidate to active checker");
            self.checker.write().await.add_remote_candidate(candidate).await?;
        }

        Ok(())
    }

    /// Start connectivity checks
    pub async fn start_checks(&self) -> NatResult<()> {
        let mut state = self.state.write().await;
        match *state {
            IceState::Ready => {
                info!("Starting connectivity checks");
                *state = IceState::Checking;
            }
            IceState::Failed => {
                info!("Restarting connectivity checks after failure");
                *state = IceState::Checking;
            }
            current_state => {
                return Err(NatError::Platform(
                    format!("Cannot start checks in state {:?}", current_state)
                ));
            }
        }
        drop(state);

        // Send state change event
        let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Checking));

        // Create check lists
        let streams = self.streams.read().await;
        for (stream_id, stream) in streams.iter() {
            let local_candidates = stream.get_local_candidates().await;
            let remote_candidates = stream.get_remote_candidates().await;

            info!("Stream {}: {} local x {} remote candidates",
                stream_id, local_candidates.len(), remote_candidates.len());

            if !local_candidates.is_empty() && !remote_candidates.is_empty() {
                // Add sockets to checker
                for candidate in &local_candidates {
                    if let Some(socket) = self.gatherer.get_socket(candidate.component_id).await {
                        self.checker.write().await.add_socket(candidate.addr, socket).await;
                    }
                }

                // Create check list
                self.checker.write().await.create_check_list(
                    *stream_id,
                    local_candidates,
                    remote_candidates,
                ).await?;
            }
        }

        // Start checks
        info!("Starting connectivity checker");
        self.checker.write().await.start_checks().await;

        // Start keepalive timer
        self.start_keepalive_timer().await;

        // Start consent freshness timer
        self.start_consent_timer().await;

        Ok(())
    }

    /// Get selected candidate pair for stream/component
    pub async fn get_selected_pair(
        &self,
        stream_id: u32,
        component_id: u32,
    ) -> Option<(Candidate, Candidate)> {
        self.selected_pairs.read().await.get(&(stream_id, component_id)).cloned()
    }

    /// Perform ICE restart
    pub async fn restart(&self) -> NatResult<()> {
        info!("Performing ICE restart");

        // Generate new credentials
        self.local_credentials = IceCredentials::generate();

        // Clear selected pairs
        self.selected_pairs.write().await.clear();
        *self.nomination_complete.write().await = false;

        // Reset keepalive states
        for state in self.keepalive_states.write().await.values_mut() {
            state.failures = 0;
            state.active = false;
        }

        // Restart gathering
        self.start_gathering().await?;

        let _ = self.event_tx.send(IceEvent::RestartRequired);

        Ok(())
    }

    /// Close ICE agent
    pub async fn close(&self) -> NatResult<()> {
        info!("Closing ICE agent");

        *self.state.write().await = IceState::Closed;
        let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Closed));

        // Cancel all active tasks
        let mut tasks = self.active_tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }

        // Close checker
        self.checker.write().await.close().await;

        Ok(())
    }

    /// Get event receiver
    pub fn get_event_rx(&self) -> Arc<Mutex<mpsc::UnboundedReceiver<IceEvent>>> {
        self.event_rx.clone()
    }

    /// Start event processing loops
    fn start_event_processing(&self) {
        info!("Starting ICE event processing");

        // Gathering events
        let agent = self.clone();
        let task = tokio::spawn(async move {
            agent.process_gathering_events().await;
        });
        self.active_tasks.blocking_lock().push(task);

        // Connectivity events
        let agent = self.clone();
        let task = tokio::spawn(async move {
            agent.process_connectivity_events().await;
        });
        self.active_tasks.blocking_lock().push(task);

        // Trickle events
        if let Some(trickle_rx) = &self.trickle_rx {
            let agent = self.clone();
            let trickle_rx = trickle_rx.clone();
            let task = tokio::spawn(async move {
                agent.process_trickle_events(trickle_rx).await;
            });
            self.active_tasks.blocking_lock().push(task);
        }
    }

    /// Process gathering events
    async fn process_gathering_events(&self) {
        let mut rx = self.gathering_rx.lock().await;

        while let Some(event) = rx.recv().await {
            match event {
                GatheringEvent::CandidateFound(candidate) => {
                    info!("Found local candidate: {} type={:?}",
                        candidate.addr, candidate.typ);

                    // Add to appropriate stream
                    let mut added = false;
                    let mut streams = self.streams.write().await;

                    // Try to find stream with matching component
                    for stream in streams.values_mut() {
                        if candidate.component_id <= stream.component_count {
                            stream.add_local_candidate(candidate.clone());
                            added = true;
                            break;
                        }
                    }

                    if !added {
                        warn!("No stream found for candidate component {}", candidate.component_id);
                        continue;
                    }

                    // Send event
                    let _ = self.event_tx.send(IceEvent::CandidateGathered(candidate));
                }

                GatheringEvent::ComponentComplete(component) => {
                    info!("Gathering complete for component {}", component);

                    // Check if all components complete
                    let all_complete = self.streams.read().await.values()
                        .all(|s| s.gathering_complete);

                    if all_complete {
                        info!("All components gathered - transitioning to Ready");
                        *self.state.write().await = IceState::Ready;
                        let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Ready));
                        let _ = self.event_tx.send(IceEvent::GatheringComplete);
                    }
                }

                GatheringEvent::ComponentFailed(component, reason) => {
                    error!("Gathering failed for component {}: {}", component, reason);

                    // Don't fail entire ICE, continue with other components
                    let _ = self.event_tx.send(IceEvent::GatheringError(
                        format!("Component {} gathering failed: {}", component, reason)
                    ));
                }
            }
        }

        info!("Gathering event processing ended");
    }

    /// Process connectivity events
    async fn process_connectivity_events(&self) {
        let mut rx = self.connectivity_rx.lock().await;
        let mut first_connected = true;

        while let Some(event) = rx.recv().await {
            match event {
                ConnectivityEvent::PairStateChanged { stream_id, pair } => {
                    debug!("Pair state changed: {} -> {:?} for stream {}",
                        pair.id(), pair.state, stream_id);
                }

                ConnectivityEvent::ValidPair { stream_id, pair } => {
                    info!("Valid pair found: {} <-> {} for stream {}",
                        pair.local.addr, pair.remote.addr, stream_id);

                    // First valid pair means connected
                    if first_connected {
                        first_connected = false;
                        info!("First valid pair - transitioning to Connected");
                        *self.state.write().await = IceState::Connected;
                        let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Connected));
                    }

                    // Activate keepalive for this component
                    if let Some(state) = self.keepalive_states.write().await
                        .get_mut(&(stream_id, pair.local.component_id)) {
                        state.active = true;
                        state.last_received = Instant::now();
                        state.failures = 0;
                    }

                    let _ = self.event_tx.send(IceEvent::ValidatedPair(pair));
                }

                ConnectivityEvent::CheckListCompleted { stream_id } => {
                    info!("Check list completed for stream {}", stream_id);
                    self.check_all_completed().await;
                }

                ConnectivityEvent::CheckListFailed { stream_id } => {
                    error!("Check list failed for stream {}", stream_id);

                    // Check if all lists failed
                    let all_failed = self.checker.read().await.all_failed().await;
                    if all_failed {
                        error!("All check lists failed - ICE failed");
                        *self.state.write().await = IceState::Failed;
                        let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Failed));
                        let _ = self.event_tx.send(IceEvent::Failed("All connectivity checks failed".to_string()));
                    }
                }

                ConnectivityEvent::NominatedPair { stream_id, component_id, pair } => {
                    info!("Nominated pair for stream {} component {}: {} <-> {}",
                        stream_id, component_id, pair.local.addr, pair.remote.addr);

                    // Store selected pair
                    self.selected_pairs.write().await.insert(
                        (stream_id, component_id),
                        (pair.local.clone(), pair.remote.clone()),
                    );

                    let _ = self.event_tx.send(IceEvent::SelectedPair {
                        stream_id,
                        component_id,
                        local: pair.local,
                        remote: pair.remote,
                    });

                    // Check if all components have selected pairs
                    self.check_nomination_complete().await;
                }

                ConnectivityEvent::RoleConflict { their_tie_breaker } => {
                    warn!("ICE role conflict detected, tie-breaker: {}", their_tie_breaker);
                    self.handle_role_conflict(their_tie_breaker).await;
                }
            }
        }

        info!("Connectivity event processing ended");
    }

    /// Process trickle events
    async fn process_trickle_events(
        &self,
        trickle_rx: Arc<Mutex<mpsc::UnboundedReceiver<TrickleEvent>>>,
    ) {
        let mut rx = trickle_rx.lock().await;

        while let Some(event) = rx.recv().await {
            match event {
                TrickleEvent::LocalCandidateReady(candidate) => {
                    debug!("Trickle: local candidate ready {}", candidate.addr);
                    let _ = self.event_tx.send(IceEvent::CandidateGathered(candidate));
                }

                TrickleEvent::RemoteCandidateReceived(candidate) => {
                    debug!("Trickle: remote candidate received {}", candidate.addr);
                    if let Err(e) = self.add_remote_candidate(candidate).await {
                        warn!("Failed to add trickled remote candidate: {}", e);
                    }
                }

                TrickleEvent::EndOfCandidates => {
                    info!("Trickle: end of remote candidates");
                }
            }
        }

        info!("Trickle event processing ended");
    }

    /// Handle role conflict
    async fn handle_role_conflict(&self, their_tie_breaker: u64) {
        let our_tie_breaker = self.checker.read().await.get_tie_breaker();

        let should_switch = match *self.role.read().await {
            IceRole::Controlling => our_tie_breaker < their_tie_breaker,
            IceRole::Controlled => our_tie_breaker > their_tie_breaker,
        };

        if should_switch {
            let new_role = match *self.role.read().await {
                IceRole::Controlling => IceRole::Controlled,
                IceRole::Controlled => IceRole::Controlling,
            };

            info!("Switching ICE role to {:?} due to conflict", new_role);
            *self.role.write().await = new_role;

            // Update checker role
            self.checker.write().await.set_controlling(new_role == IceRole::Controlling);
        }
    }

    /// Check if all streams/components are completed
    async fn check_all_completed(&self) {
        let expected_pairs = self.streams.read().await.len() * self.config.component_count as usize;
        let selected_count = self.selected_pairs.read().await.len();

        debug!("Checking completion: {} selected pairs, {} expected",
            selected_count, expected_pairs);

        if selected_count >= expected_pairs {
            // All components have pairs, but wait for nomination to complete
            if !*self.nomination_complete.read().await {
                info!("All components have pairs, waiting for nomination");
                // Nomination completion will be triggered by NominatedPair events
            }
        }
    }

    /// Check if nomination is complete
    async fn check_nomination_complete(&self) {
        let streams = self.streams.read().await;
        let selected_pairs = self.selected_pairs.read().await;

        // Check each stream/component has a nominated pair
        let mut all_nominated = true;
        for (stream_id, stream) in streams.iter() {
            for component_id in 1..=stream.component_count {
                if !selected_pairs.contains_key(&(*stream_id, component_id)) {
                    all_nominated = false;
                    break;
                }
            }
            if !all_nominated {
                break;
            }
        }

        if all_nominated && !*self.nomination_complete.read().await {
            info!("ICE nomination complete - all components have selected pairs");
            *self.nomination_complete.write().await = true;
            *self.state.write().await = IceState::Completed;
            let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Completed));
        }
    }

    /// Start keepalive timer (RFC 8445 Section 11)
    async fn start_keepalive_timer(&self) {
        info!("Starting ICE keepalive timer with interval {:?}", self.config.keepalive_interval);

        let agent = self.clone();
        let task = tokio::spawn(async move {
            let mut timer = interval(agent.config.keepalive_interval);

            loop {
                timer.tick().await;

                if matches!(*agent.state.read().await,
                    IceState::Closed | IceState::Failed | IceState::Disconnected) {
                    break;
                }

                agent.send_keepalives().await;
            }

            info!("Keepalive timer stopped");
        });

        self.active_tasks.lock().await.push(task);
    }

    /// Start consent freshness timer (RFC 7675)
    async fn start_consent_timer(&self) {
        info!("Starting consent freshness timer with interval {:?}", self.config.consent_interval);

        let agent = self.clone();
        let task = tokio::spawn(async move {
            let mut timer = interval(agent.config.consent_interval);

            loop {
                timer.tick().await;

                if matches!(*agent.state.read().await,
                    IceState::Closed | IceState::Failed) {
                    break;
                }

                agent.check_consent_freshness().await;
            }

            info!("Consent timer stopped");
        });

        self.active_tasks.lock().await.push(task);
    }

    /// Send keepalives on selected pairs
    async fn send_keepalives(&self) {
        let selected_pairs = self.selected_pairs.read().await;

        for ((stream_id, component_id), (local, remote)) in selected_pairs.iter() {
            debug!("Sending keepalive for stream {} component {}", stream_id, component_id);

            if let Err(e) = self.checker.read().await
                .send_keepalive(local.addr, remote.addr).await {
                warn!("Failed to send keepalive: {}", e);

                // Update failure count
                if let Some(state) = self.keepalive_states.write().await
                    .get_mut(&(*stream_id, *component_id)) {
                    state.failures += 1;
                }
            } else {
                // Update sent time
                if let Some(state) = self.keepalive_states.write().await
                    .get_mut(&(*stream_id, *component_id)) {
                    state.last_sent = Instant::now();
                }
            }
        }
    }

    /// Check consent freshness
    async fn check_consent_freshness(&self) {
        let mut disconnected_components = Vec::new();

        {
            let states = self.keepalive_states.read().await;
            let now = Instant::now();

            for ((stream_id, component_id), state) in states.iter() {
                if !state.active {
                    continue;
                }

                let time_since_response = now.duration_since(state.last_received);

                if time_since_response > self.config.consent_interval * 2 {
                    warn!("Consent timeout for stream {} component {} ({:?} since last response)",
                        stream_id, component_id, time_since_response);
                    disconnected_components.push((*stream_id, *component_id));
                } else if state.failures >= self.config.max_consent_failures {
                    warn!("Too many keepalive failures for stream {} component {} ({} failures)",
                        stream_id, component_id, state.failures);
                    disconnected_components.push((*stream_id, *component_id));
                }
            }
        }

        // Handle disconnected components
        if !disconnected_components.is_empty() {
            error!("Consent lost for {} components", disconnected_components.len());

            // Remove from selected pairs
            let mut selected_pairs = self.selected_pairs.write().await;
            for key in &disconnected_components {
                selected_pairs.remove(key);
            }

            // Check if any pairs remain
            if selected_pairs.is_empty() {
                error!("All components disconnected");
                *self.state.write().await = IceState::Disconnected;
                let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Disconnected));
                let _ = self.event_tx.send(IceEvent::Disconnected);
            }
        }
    }

    /// Update consent received for a component
    pub async fn update_consent_received(&self, stream_id: u32, component_id: u32) {
        if let Some(state) = self.keepalive_states.write().await
            .get_mut(&(stream_id, component_id)) {
            state.last_received = Instant::now();
            state.failures = 0;
        }
    }
}

impl Clone for IceAgent {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: self.state.clone(),
            role: self.role.clone(),
            local_credentials: self.local_credentials.clone(),
            remote_credentials: self.remote_credentials.clone(),
            streams: self.streams.clone(),
            gatherer: self.gatherer.clone(),
            checker: self.checker.clone(),
            trickle: self.trickle.clone(),
            event_tx: self.event_tx.clone(),
            event_rx: self.event_rx.clone(),
            gathering_rx: self.gathering_rx.clone(),
            connectivity_rx: self.connectivity_rx.clone(),
            trickle_rx: self.trickle_rx.clone(),
            selected_pairs: self.selected_pairs.clone(),
            nomination_complete: self.nomination_complete.clone(),
            keepalive_states: self.keepalive_states.clone(),
            active_tasks: self.active_tasks.clone(),
            restart_counter: self.restart_counter.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ice_agent_creation() {
        let config = IceConfig::default();
        let agent = IceAgent::new(config, IceRole::Controlling).unwrap();

        assert_eq!(*agent.state.read().await, IceState::New);
        assert_eq!(*agent.role.read().await, IceRole::Controlling);

        // Credentials should be generated
        assert!(agent.local_credentials.ufrag.len() >= 4);
        assert!(agent.local_credentials.pwd.len() >= 22);
    }

    #[tokio::test]
    async fn test_ice_agent_lifecycle() {
        let config = IceConfig {
            stun_servers: vec![], // No STUN for test
            gathering_timeout: Duration::from_millis(100),
            ..Default::default()
        };

        let agent = IceAgent::new(config, IceRole::Controlling).unwrap();
        let mut event_rx = agent.get_event_rx();

        // Add stream
        agent.add_stream(1).await.unwrap();

        // Start gathering
        agent.start_gathering().await.unwrap();

        // Should receive state change event
        let rx = event_rx.lock().await.recv().await;
        match rx {
            Some(IceEvent::StateChanged(IceState::Gathering)) => {},
            other => panic!("Expected gathering state change, got {:?}", other),
        }

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should transition to Ready after timeout
        assert_eq!(*agent.state.read().await, IceState::Ready);
    }

    #[tokio::test]
    async fn test_ice_restart() {
        let config = IceConfig::default();
        let agent = IceAgent::new(config, IceRole::Controlling).unwrap();

        let original_ufrag = agent.local_credentials.ufrag.clone();

        // Add stream and gather
        agent.add_stream(1).await.unwrap();
        *agent.state.write().await = IceState::Ready;

        // Perform restart
        agent.restart().await.unwrap();

        // Credentials should change
        assert_ne!(agent.local_credentials.ufrag, original_ufrag);
        assert_eq!(*agent.state.read().await, IceState::Gathering);
    }

    #[tokio::test]
    async fn test_keepalive_state_management() {
        let config = IceConfig::default();
        let agent = IceAgent::new(config, IceRole::Controlling).unwrap();

        // Add stream
        agent.add_stream(1).await.unwrap();

        // Should have keepalive state for each component
        let states = agent.keepalive_states.read().await;
        assert!(states.contains_key(&(1, 1)));

        let state = &states[&(1, 1)];
        assert_eq!(state.failures, 0);
        assert!(!state.active);
    }
}