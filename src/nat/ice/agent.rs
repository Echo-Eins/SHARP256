// src/nat/ice/agent.rs
//! ICE Agent implementation (RFC 8445)
//!
//! The ICE Agent is the main orchestrator that coordinates candidate gathering,
//! connectivity checks, and nomination processes for establishing peer-to-peer connections.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, broadcast, mpsc, oneshot};
use tokio::time::{interval, timeout, sleep};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};

use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::candidate::{Candidate, CandidateList, CandidatePair, TransportProtocol};
use crate::nat::ice::gathering::{CandidateGatherer, GatheringConfig, GatheringEvent};
use crate::nat::ice::connectivity::{ConnectivityChecker, CheckResult, IceCredentials};
use crate::nat::ice::nomination::{NominationProcessor, NominationConfig, NominationEvent, NominationMode};
use crate::nat::stun::Message;

/// ICE Agent role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IceRole {
    /// Controlling agent (initiates nomination)
    Controlling,
    /// Controlled agent (responds to nomination)
    Controlled,
}

/// ICE Agent state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IceState {
    /// Gathering candidates
    Gathering,
    /// Connecting (performing connectivity checks)
    Connecting,
    /// Connected (at least one component connected)
    Connected,
    /// Completed (all components connected)
    Completed,
    /// Failed (unable to establish connection)
    Failed,
    /// Closed (agent has been shut down)
    Closed,
}

impl Default for IceState {
    fn default() -> Self {
        IceState::Gathering
    }
}

/// ICE transport policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IceTransportPolicy {
    /// Use all available transports
    All,
    /// Only use relay transports (TURN)
    Relay,
    /// No ICE transport (disable ICE)
    None,
}

/// ICE configuration
#[derive(Debug, Clone)]
pub struct IceConfig {
    /// Transport policy
    pub transport_policy: IceTransportPolicy,

    /// Gathering configuration
    pub gathering_config: GatheringConfig,

    /// Nomination configuration
    pub nomination_config: NominationConfig,

    /// Components to establish (typically 1 for RTP, 2 for RTCP)
    pub components: Vec<u32>,

    /// Maximum number of candidate pairs per component
    pub max_pairs_per_component: usize,

    /// ICE connectivity check timeout
    pub connectivity_timeout: Duration,

    /// Keep-alive interval for established connections
    pub keepalive_interval: Duration,

    /// Enable trickle ICE
    pub enable_trickle: bool,

    /// Enable consent freshness (RFC 7675)
    pub enable_consent_freshness: bool,

    /// Bundle policy for multiple components
    pub bundle_policy: BundlePolicy,

    /// RTCP mux policy
    pub rtcp_mux_policy: RtcpMuxPolicy,
}

/// Bundle policy for multiple components
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundlePolicy {
    /// No bundling
    None,
    /// Bundle if possible
    Balanced,
    /// Force bundling
    MaxBundle,
}

/// RTCP mux policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcpMuxPolicy {
    /// No RTCP mux
    None,
    /// RTCP mux required
    Require,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            transport_policy: IceTransportPolicy::All,
            gathering_config: GatheringConfig::default(),
            nomination_config: NominationConfig::default(),
            components: vec![1], // RTP only by default
            max_pairs_per_component: 100,
            connectivity_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(25),
            enable_trickle: true,
            enable_consent_freshness: true,
            bundle_policy: BundlePolicy::Balanced,
            rtcp_mux_policy: RtcpMuxPolicy::Require,
        }
    }
}

/// ICE Agent event
#[derive(Debug, Clone)]
pub enum IceEvent {
    /// State changed
    StateChanged {
        old_state: IceState,
        new_state: IceState,
    },

    /// New candidate discovered
    CandidateAdded {
        candidate: Candidate,
        component_id: u32,
    },

    /// Candidate gathering completed
    GatheringCompleted {
        component_id: u32,
        candidate_count: usize,
    },

    /// Connectivity check result
    ConnectivityResult {
        pair_id: String,
        success: bool,
        rtt: Option<Duration>,
    },

    /// Component connected
    ComponentConnected {
        component_id: u32,
        local_candidate: Candidate,
        remote_candidate: Candidate,
        selected_pair: CandidatePair,
    },

    /// Connection established (all components connected)
    ConnectionEstablished {
        selected_pairs: HashMap<u32, CandidatePair>,
        establishment_time: Duration,
    },

    /// Connection failed
    ConnectionFailed {
        reason: String,
    },

    /// Consent freshness lost
    ConsentLost {
        component_id: u32,
        pair_id: String,
    },

    /// ICE restart initiated
    IceRestart,
}

/// ICE Agent statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IceStats {
    pub state: IceState,
    pub role: Option<IceRole>,
    pub gathering_time: Duration,
    pub connectivity_time: Duration,
    pub total_establishment_time: Duration,
    pub candidates_gathered: u32,
    pub pairs_checked: u32,
    pub successful_pairs: u32,
    pub nominated_pairs: u32,
    pub selected_pairs: HashMap<u32, String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

/// Component connection info
#[derive(Debug, Clone)]
pub struct ComponentConnection {
    pub component_id: u32,
    pub local_candidate: Candidate,
    pub remote_candidate: Candidate,
    pub selected_pair: CandidatePair,
    pub socket: Arc<UdpSocket>,
    pub established_at: Instant,
    pub last_activity: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// ICE Agent - main orchestrator for ICE protocol
pub struct IceAgent {
    /// Configuration
    config: IceConfig,

    /// Current state
    state: Arc<RwLock<IceState>>,

    /// Current role
    role: Arc<RwLock<Option<IceRole>>>,

    /// Local ICE credentials
    local_credentials: IceCredentials,

    /// Remote ICE credentials
    remote_credentials: Arc<RwLock<Option<IceCredentials>>>,

    /// Candidate gatherer
    gatherer: Arc<CandidateGatherer>,

    /// Connectivity checker
    connectivity_checker: Arc<ConnectivityChecker>,

    /// Nomination processor
    nomination_processor: Arc<NominationProcessor>,

    /// Local candidates by component
    local_candidates: Arc<RwLock<HashMap<u32, CandidateList>>>,

    /// Remote candidates by component
    remote_candidates: Arc<RwLock<HashMap<u32, CandidateList>>>,

    /// Candidate pairs by component
    candidate_pairs: Arc<RwLock<HashMap<u32, Vec<CandidatePair>>>>,

    /// Component connections (established pairs)
    connections: Arc<RwLock<HashMap<u32, ComponentConnection>>>,

    /// Event broadcaster
    event_sender: broadcast::Sender<IceEvent>,

    /// Command channel for external control
    command_sender: mpsc::UnboundedSender<AgentCommand>,
    command_receiver: Arc<Mutex<mpsc::UnboundedReceiver<AgentCommand>>>,

    /// STUN message channel for processing incoming messages
    stun_sender: mpsc::UnboundedSender<(Message, SocketAddr, SocketAddr)>,
    stun_receiver: Arc<Mutex<mpsc::UnboundedReceiver<(Message, SocketAddr, SocketAddr)>>>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,

    /// Statistics
    stats: Arc<RwLock<IceStats>>,

    /// Start time for timing measurements
    start_time: Instant,

    /// Gathering start time
    gathering_start_time: Arc<RwLock<Option<Instant>>>,

    /// Connectivity start time
    connectivity_start_time: Arc<RwLock<Option<Instant>>>,
}

/// Agent commands for external control
#[derive(Debug)]
enum AgentCommand {
    /// Start ICE gathering and connectivity checks
    Start,

    /// Add remote candidate
    AddRemoteCandidate {
        candidate: Candidate,
        component_id: u32,
        response: oneshot::Sender<NatResult<()>>,
    },

    /// Set remote credentials
    SetRemoteCredentials {
        credentials: IceCredentials,
        response: oneshot::Sender<NatResult<()>>,
    },

    /// Restart ICE
    Restart {
        response: oneshot::Sender<NatResult<()>>,
    },

    /// Close agent
    Close,

    /// Send data on component
    SendData {
        component_id: u32,
        data: Vec<u8>,
        response: oneshot::Sender<NatResult<usize>>,
    },
}

impl IceAgent {
    /// Create new ICE agent
    pub async fn new(config: IceConfig) -> NatResult<Self> {
        let (event_sender, _) = broadcast::channel(1000);
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (stun_sender, stun_receiver) = mpsc::unbounded_channel();

        // Create gatherer
        let gatherer = Arc::new(CandidateGatherer::new(config.gathering_config.clone()).await?);

        // Create connectivity checker - role will be set later
        let connectivity_checker = Arc::new(ConnectivityChecker::new(
            1, // Default component, will be updated
            false, // Default role, will be updated
            config.nomination_config.mode == NominationMode::Aggressive,
        ));

        // Create nomination processor
        let nomination_processor = Arc::new(NominationProcessor::new(
            config.nomination_config.clone(),
            false, // Default role, will be updated
            connectivity_checker.clone(),
        ));

        let agent = Self {
            config,
            state: Arc::new(RwLock::new(IceState::Gathering)),
            role: Arc::new(RwLock::new(None)),
            local_credentials: IceCredentials::new(),
            remote_credentials: Arc::new(RwLock::new(None)),
            gatherer,
            connectivity_checker,
            nomination_processor,
            local_candidates: Arc::new(RwLock::new(HashMap::new())),
            remote_candidates: Arc::new(RwLock::new(HashMap::new())),
            candidate_pairs: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            command_sender,
            command_receiver: Arc::new(Mutex::new(command_receiver)),
            stun_sender,
            stun_receiver: Arc::new(Mutex::new(stun_receiver)),
            shutdown: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(IceStats::default())),
            start_time: Instant::now(),
            gathering_start_time: Arc::new(RwLock::new(None)),
            connectivity_start_time: Arc::new(RwLock::new(None)),
        };

        Ok(agent)
    }

    /// Start ICE agent
    pub async fn start(&self, role: IceRole) -> NatResult<()> {
        info!("Starting ICE agent with role: {:?}", role);

        // Set role
        *self.role.write().await = Some(role);

        // Start background tasks
        let agent_task = self.clone_for_task().start_background_tasks();

        // Send start command
        self.command_sender.send(AgentCommand::Start)
            .map_err(|_| NatError::Configuration("Failed to send start command".to_string()))?;

        // Wait for background tasks or shutdown
        tokio::select! {
            result = agent_task => {
                if let Err(e) = result {
                    error!("Agent background task failed: {}", e);
                    self.set_state(IceState::Failed).await;
                }
            }
            _ = async {
                loop {
                    if *self.shutdown.read().await {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            } => {}
        }

        Ok(())
    }

    /// Clone for background task
    fn clone_for_task(&self) -> IceAgentTask {
        IceAgentTask {
            config: self.config.clone(),
            state: self.state.clone(),
            role: self.role.clone(),
            local_credentials: self.local_credentials.clone(),
            remote_credentials: self.remote_credentials.clone(),
            gatherer: self.gatherer.clone(),
            connectivity_checker: self.connectivity_checker.clone(),
            nomination_processor: self.nomination_processor.clone(),
            local_candidates: self.local_candidates.clone(),
            remote_candidates: self.remote_candidates.clone(),
            candidate_pairs: self.candidate_pairs.clone(),
            connections: self.connections.clone(),
            event_sender: self.event_sender.clone(),
            command_receiver: self.command_receiver.clone(),
            stun_receiver: self.stun_receiver.clone(),
            shutdown: self.shutdown.clone(),
            stats: self.stats.clone(),
            start_time: self.start_time,
            gathering_start_time: self.gathering_start_time.clone(),
            connectivity_start_time: self.connectivity_start_time.clone(),
        }
    }

    /// Add remote candidate
    pub async fn add_remote_candidate(&self, candidate: Candidate, component_id: u32) -> NatResult<()> {
        let (tx, rx) = oneshot::channel();

        self.command_sender.send(AgentCommand::AddRemoteCandidate {
            candidate,
            component_id,
            response: tx,
        }).map_err(|_| NatError::Configuration("Failed to send command".to_string()))?;

        rx.await.map_err(|_| NatError::Configuration("Command response failed".to_string()))?
    }

    /// Set remote credentials
    pub async fn set_remote_credentials(&self, credentials: IceCredentials) -> NatResult<()> {
        let (tx, rx) = oneshot::channel();

        self.command_sender.send(AgentCommand::SetRemoteCredentials {
            credentials,
            response: tx,
        }).map_err(|_| NatError::Configuration("Failed to send command".to_string()))?;

        rx.await.map_err(|_| NatError::Configuration("Command response failed".to_string()))?
    }

    /// Restart ICE
    pub async fn restart(&self) -> NatResult<()> {
        let (tx, rx) = oneshot::channel();

        self.command_sender.send(AgentCommand::Restart {
            response: tx,
        }).map_err(|_| NatError::Configuration("Failed to send command".to_string()))?;

        rx.await.map_err(|_| NatError::Configuration("Command response failed".to_string()))?
    }

    /// Send data on component
    pub async fn send_data(&self, component_id: u32, data: Vec<u8>) -> NatResult<usize> {
        let (tx, rx) = oneshot::channel();

        self.command_sender.send(AgentCommand::SendData {
            component_id,
            data,
            response: tx,
        }).map_err(|_| NatError::Configuration("Failed to send command".to_string()))?;

        rx.await.map_err(|_| NatError::Configuration("Command response failed".to_string()))?
    }

    /// Process incoming STUN message
    pub async fn process_stun_message(&self, message: Message, from: SocketAddr, to: SocketAddr) -> NatResult<()> {
        self.stun_sender.send((message, from, to))
            .map_err(|_| NatError::Configuration("Failed to send STUN message".to_string()))?;
        Ok(())
    }

    /// Get local candidates
    pub async fn get_local_candidates(&self, component_id: u32) -> Vec<Candidate> {
        let candidates = self.local_candidates.read().await;
        candidates.get(&component_id)
            .map(|list| list.candidates().to_vec())
            .unwrap_or_default()
    }

    /// Get local credentials
    pub fn get_local_credentials(&self) -> &IceCredentials {
        &self.local_credentials
    }

    /// Get current state
    pub async fn get_state(&self) -> IceState {
        *self.state.read().await
    }

    /// Get current role
    pub async fn get_role(&self) -> Option<IceRole> {
        *self.role.read().await
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> IceStats {
        let mut stats = self.stats.read().await.clone();
        stats.state = *self.state.read().await;
        stats.role = *self.role.read().await;
        stats
    }

    /// Get component connections
    pub async fn get_connections(&self) -> HashMap<u32, ComponentConnection> {
        self.connections.read().await.clone()
    }

    /// Subscribe to events
    pub fn subscribe_events(&self) -> broadcast::Receiver<IceEvent> {
        self.event_sender.subscribe()
    }

    /// Close agent
    pub async fn close(&self) {
        info!("Closing ICE agent");

        let _ = self.command_sender.send(AgentCommand::Close);
        *self.shutdown.write().await = true;

        self.set_state(IceState::Closed).await;
    }

    /// Set state and emit event
    async fn set_state(&self, new_state: IceState) {
        let old_state = {
            let mut state = self.state.write().await;
            let old = *state;
            *state = new_state;
            old
        };

        if old_state != new_state {
            info!("ICE state changed: {:?} -> {:?}", old_state, new_state);

            let _ = self.event_sender.send(IceEvent::StateChanged {
                old_state,
                new_state,
            });
        }
    }
}

/// Task wrapper for background processing
#[derive(Clone)]
struct IceAgentTask {
    config: IceConfig,
    state: Arc<RwLock<IceState>>,
    role: Arc<RwLock<Option<IceRole>>>,
    local_credentials: IceCredentials,
    remote_credentials: Arc<RwLock<Option<IceCredentials>>>,
    gatherer: Arc<CandidateGatherer>,
    connectivity_checker: Arc<ConnectivityChecker>,
    nomination_processor: Arc<NominationProcessor>,
    local_candidates: Arc<RwLock<HashMap<u32, CandidateList>>>,
    remote_candidates: Arc<RwLock<HashMap<u32, CandidateList>>>,
    candidate_pairs: Arc<RwLock<HashMap<u32, Vec<CandidatePair>>>>,
    connections: Arc<RwLock<HashMap<u32, ComponentConnection>>>,
    event_sender: broadcast::Sender<IceEvent>,
    command_receiver: Arc<Mutex<mpsc::UnboundedReceiver<AgentCommand>>>,
    stun_receiver: Arc<Mutex<mpsc::UnboundedReceiver<(Message, SocketAddr, SocketAddr)>>>,
    shutdown: Arc<RwLock<bool>>,
    stats: Arc<RwLock<IceStats>>,
    start_time: Instant,
    gathering_start_time: Arc<RwLock<Option<Instant>>>,
    connectivity_start_time: Arc<RwLock<Option<Instant>>>,
}

impl IceAgentTask {
    /// Start background tasks
    async fn start_background_tasks(self) -> NatResult<()> {
        let command_task = self.clone().process_commands();
        let stun_task = self.clone().process_stun_messages();
        let event_task = self.clone().process_events();
        let keepalive_task = self.process_keepalive();

        tokio::select! {
            result = command_task => {
                if let Err(e) = result {
                    error!("Command processing failed: {}", e);
                }
            }
            result = stun_task => {
                if let Err(e) = result {
                    error!("STUN processing failed: {}", e);
                }
            }
            result = event_task => {
                if let Err(e) = result {
                    error!("Event processing failed: {}", e);
                }
            }
            result = keepalive_task => {
                if let Err(e) = result {
                    error!("Keepalive processing failed: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Process agent commands
    async fn process_commands(self) -> NatResult<()> {
        let mut receiver = self.command_receiver.lock().await;

        while let Some(command) = receiver.recv().await {
            if *self.shutdown.read().await {
                break;
            }

            match command {
                AgentCommand::Start => {
                    if let Err(e) = self.handle_start().await {
                        error!("Failed to start: {}", e);
                    }
                }

                AgentCommand::AddRemoteCandidate { candidate, component_id, response } => {
                    let result = self.handle_add_remote_candidate(candidate, component_id).await;
                    let _ = response.send(result);
                }

                AgentCommand::SetRemoteCredentials { credentials, response } => {
                    let result = self.handle_set_remote_credentials(credentials).await;
                    let _ = response.send(result);
                }

                AgentCommand::Restart { response } => {
                    let result = self.handle_restart().await;
                    let _ = response.send(result);
                }

                AgentCommand::Close => {
                    self.handle_close().await;
                    break;
                }

                AgentCommand::SendData { component_id, data, response } => {
                    let result = self.handle_send_data(component_id, data).await;
                    let _ = response.send(result);
                }
            }
        }

        Ok(())
    }

    /// Handle start command
    async fn handle_start(&self) -> NatResult<()> {
        info!("Starting ICE gathering for {} components", self.config.components.len());

        *self.gathering_start_time.write().await = Some(Instant::now());

        // Start gathering for each component
        for &component_id in &self.config.components {
            if let Err(e) = self.gatherer.start_gathering(component_id).await {
                warn!("Failed to start gathering for component {}: {}", component_id, e);
            }
        }

        Ok(())
    }

    /// Handle add remote candidate
    async fn handle_add_remote_candidate(&self, candidate: Candidate, component_id: u32) -> NatResult<()> {
        debug!("Adding remote candidate for component {}: {}", component_id, candidate);

        // Add to remote candidates
        {
            let mut remote_candidates = self.remote_candidates.write().await;
            let component_candidates = remote_candidates.entry(component_id).or_insert_with(CandidateList::new);
            component_candidates.add(candidate.clone())?;
        }

        // If we have local candidates, form pairs
        let local_candidates = {
            let local_candidates = self.local_candidates.read().await;
            local_candidates.get(&component_id).cloned()
        };

        if let Some(local_list) = local_candidates {
            self.form_candidate_pairs(component_id, local_list.candidates(), &[candidate]).await?;
        }

        Ok(())
    }

    /// Handle set remote credentials
    async fn handle_set_remote_credentials(&self, credentials: IceCredentials) -> NatResult<()> {
        info!("Setting remote ICE credentials: ufrag={}", credentials.ufrag);

        *self.remote_credentials.write().await = Some(credentials.clone());
        self.connectivity_checker.set_remote_credentials(credentials).await;

        Ok(())
    }

    /// Handle restart
    async fn handle_restart(&self) -> NatResult<()> {
        info!("Restarting ICE");

        // Generate new credentials
        let new_credentials = IceCredentials::new();
        *self.remote_credentials.write().await = None;

        // Clear candidates and pairs
        self.local_candidates.write().await.clear();
        self.remote_candidates.write().await.clear();
        self.candidate_pairs.write().await.clear();
        self.connections.write().await.clear();

        // Reset state
        *self.state.write().await = IceState::Gathering;

        // Emit restart event
        let _ = self.event_sender.send(IceEvent::IceRestart);

        // Restart gathering
        self.handle_start().await?;

        Ok(())
    }

    /// Handle close
    async fn handle_close(&self) {
        info!("Closing ICE agent");

        // Stop all processors
        self.gatherer.stop_gathering().await;
        self.connectivity_checker.stop().await;
        self.nomination_processor.stop().await;

        // Close connections
        self.connections.write().await.clear();

        *self.shutdown.write().await = true;
    }

    /// Handle send data
    async fn handle_send_data(&self, component_id: u32, data: Vec<u8>) -> NatResult<usize> {
        let connection = {
            let connections = self.connections.read().await;
            connections.get(&component_id).cloned()
        };

        match connection {
            Some(conn) => {
                let remote_addr = conn.selected_pair.remote.socket_addr()
                    .ok_or_else(|| NatError::Configuration("No remote address for connection".to_string()))?;

                let bytes_sent = conn.socket.send_to(&data, remote_addr).await
                    .map_err(|e| NatError::Network(e))?;

                // Update connection statistics
                {
                    let mut connections = self.connections.write().await;
                    if let Some(conn) = connections.get_mut(&component_id) {
                        conn.bytes_sent += bytes_sent as u64;
                        conn.last_activity = Instant::now();
                    }
                }

                // Update global statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.bytes_sent += bytes_sent as u64;
                    stats.packets_sent += 1;
                }

                Ok(bytes_sent)
            }
            None => Err(NatError::Configuration("No connection for component".to_string())),
        }
    }

    /// Form candidate pairs
    async fn form_candidate_pairs(
        &self,
        component_id: u32,
        local_candidates: &[Candidate],
        remote_candidates: &[Candidate],
    ) -> NatResult<()> {
        let mut new_pairs = Vec::new();
        let controlling = *self.role.read().await == Some(IceRole::Controlling);

        for local in local_candidates {
            for remote in remote_candidates {
                // Check if pair is valid
                if self.is_valid_pair(local, remote) {
                    let pair = CandidatePair::new(local.clone(), remote.clone(), controlling);
                    new_pairs.push(pair);
                }
            }
        }

        if !new_pairs.is_empty() {
            // Sort pairs by priority
            new_pairs.sort_by(|a, b| b.priority.cmp(&a.priority));

            // Limit number of pairs
            new_pairs.truncate(self.config.max_pairs_per_component);

            // Add to candidate pairs
            {
                let mut candidate_pairs = self.candidate_pairs.write().await;
                let component_pairs = candidate_pairs.entry(component_id).or_insert_with(Vec::new);
                component_pairs.extend(new_pairs.clone());

                // Sort and limit again
                component_pairs.sort_by(|a, b| b.priority.cmp(&a.priority));
                component_pairs.truncate(self.config.max_pairs_per_component);
            }

            // If we have remote credentials, start connectivity checks
            if self.remote_credentials.read().await.is_some() {
                if *self.state.read().await == IceState::Gathering {
                    *self.state.write().await = IceState::Connecting;
                    *self.connectivity_start_time.write().await = Some(Instant::now());
                }

                // Form check list and start checks
                self.connectivity_checker.form_check_list(new_pairs.clone()).await?;

                // Add valid pairs to nomination processor
                self.nomination_processor.add_valid_pairs(component_id, new_pairs).await;
            }

            debug!("Formed {} candidate pairs for component {}", new_pairs.len(), component_id);
        }

        Ok(())
    }

    /// Check if candidate pair is valid
    fn is_valid_pair(&self, local: &Candidate, remote: &Candidate) -> bool {
        // Check transport compatibility
        if local.transport != remote.transport {
            return false;
        }

        // Check address family compatibility
        match (local.ip(), remote.ip()) {
            (Some(local_ip), Some(remote_ip)) => {
                local_ip.is_ipv4() == remote_ip.is_ipv4()
            }
            _ => true, // mDNS candidates
        }
    }

    /// Process STUN messages
    async fn process_stun_messages(self) -> NatResult<()> {
        let mut receiver = self.stun_receiver.lock().await;

        while let Some((message, from, to)) = receiver.recv().await {
            if *self.shutdown.read().await {
                break;
            }

            if let Err(e) = self.handle_stun_message(message, from, to).await {
                debug!("Error handling STUN message: {}", e);
            }
        }

        Ok(())
    }

    /// Handle STUN message
    async fn handle_stun_message(&self, message: Message, from: SocketAddr, to: SocketAddr) -> NatResult<()> {
        // Delegate to connectivity checker
        if let Some(response) = self.connectivity_checker.process_stun_message(&message, from, to).await? {
            // Send response back
            // This would require socket management
            debug!("Generated STUN response for {}", from);
        }

        Ok(())
    }

    /// Process events from sub-components
    async fn process_events(self) -> NatResult<()> {
        let mut gathering_events = self.gatherer.subscribe_events();
        let mut connectivity_results = self.connectivity_checker.subscribe_results();
        let mut nomination_events = self.nomination_processor.subscribe_events();

        loop {
            if *self.shutdown.read().await {
                break;
            }

            tokio::select! {
                Ok(event) = gathering_events.recv() => {
                    self.handle_gathering_event(event).await;
                }
                Ok(result) = connectivity_results.recv() => {
                    self.handle_connectivity_result(result).await;
                }
                Ok(event) = nomination_events.recv() => {
                    self.handle_nomination_event(event).await;
                }
                _ = sleep(Duration::from_millis(100)) => {
                    // Periodic cleanup
                }
            }
        }

        Ok(())
    }

    /// Handle gathering event
    async fn handle_gathering_event(&self, event: GatheringEvent) {
        match event {
            GatheringEvent::CandidateDiscovered { candidate, component_id } => {
                debug!("New local candidate: {} for component {}", candidate, component_id);

                // Add to local candidates
                {
                    let mut local_candidates = self.local_candidates.write().await;
                    let component_candidates = local_candidates.entry(component_id).or_insert_with(CandidateList::new);
                    if let Err(e) = component_candidates.add(candidate.clone()) {
                        warn!("Failed to add local candidate: {}", e);
                        return;
                    }
                }

                // Update statistics
                self.stats.write().await.candidates_gathered += 1;

                // Emit event
                let _ = self.event_sender.send(IceEvent::CandidateAdded {
                    candidate: candidate.clone(),
                    component_id,
                });

                // Form pairs with remote candidates if available
                let remote_candidates = {
                    let remote_candidates = self.remote_candidates.read().await;
                    remote_candidates.get(&component_id).cloned()
                };

                if let Some(remote_list) = remote_candidates {
                    if let Err(e) = self.form_candidate_pairs(component_id, &[candidate], remote_list.candidates()).await {
                        warn!("Failed to form candidate pairs: {}", e);
                    }
                }
            }

            GatheringEvent::GatheringCompleted { total_candidates, duration } => {
                info!("Gathering completed: {} candidates in {:?}", total_candidates, duration);

                // Update timing statistics
                self.stats.write().await.gathering_time = duration;

                // Emit event for each component
                for &component_id in &self.config.components {
                    let candidate_count = {
                        let local_candidates = self.local_candidates.read().await;
                        local_candidates.get(&component_id)
                            .map(|list| list.len())
                            .unwrap_or(0)
                    };

                    let _ = self.event_sender.send(IceEvent::GatheringCompleted {
                        component_id,
                        candidate_count,
                    });
                }
            }

            _ => {}
        }
    }

    /// Handle connectivity result
    async fn handle_connectivity_result(&self, result: CheckResult) {
        match result {
            CheckResult::Success { pair_id, rtt, nominated, .. } => {
                debug!("Connectivity check succeeded for {}", pair_id);

                self.stats.write().await.successful_pairs += 1;

                let _ = self.event_sender.send(IceEvent::ConnectivityResult {
                    pair_id,
                    success: true,
                    rtt,
                });

                if nominated {
                    // Find component and establish connection
                    if let Some(component_id) = self.find_component_for_pair(&pair_id).await {
                        self.establish_component_connection(component_id, &pair_id).await;
                    }
                }
            }

            CheckResult::Failure { pair_id, .. } | CheckResult::Timeout { pair_id } => {
                debug!("Connectivity check failed for {}", pair_id);

                let _ = self.event_sender.send(IceEvent::ConnectivityResult {
                    pair_id,
                    success: false,
                    rtt: None,
                });
            }
        }

        self.stats.write().await.pairs_checked += 1;
    }

    /// Handle nomination event
    async fn handle_nomination_event(&self, event: NominationEvent) {
        match event {
            NominationEvent::ComponentCompleted { component_id, selected_pair } => {
                info!("Component {} nomination completed with pair {}", component_id, selected_pair);

                self.establish_component_connection(component_id, &selected_pair).await;
            }

            NominationEvent::NominationCompleted { selected_pairs } => {
                info!("ICE nomination completed for all components");

                let connections = self.connections.read().await;
                let component_pairs: HashMap<u32, CandidatePair> = connections.iter()
                    .map(|(id, conn)| (*id, conn.selected_pair.clone()))
                    .collect();

                let establishment_time = self.start_time.elapsed();
                self.stats.write().await.total_establishment_time = establishment_time;

                *self.state.write().await = IceState::Completed;

                let _ = self.event_sender.send(IceEvent::ConnectionEstablished {
                    selected_pairs: component_pairs,
                    establishment_time,
                });
            }

            _ => {}
        }
    }

    /// Find component for pair
    async fn find_component_for_pair(&self, pair_id: &str) -> Option<u32> {
        let candidate_pairs = self.candidate_pairs.read().await;
        for (component_id, pairs) in candidate_pairs.iter() {
            if pairs.iter().any(|p| p.id() == pair_id) {
                return Some(*component_id);
            }
        }
        None
    }

    /// Establish component connection
    async fn establish_component_connection(&self, component_id: u32, pair_id: &str) {
        let pair = {
            let candidate_pairs = self.candidate_pairs.read().await;
            candidate_pairs.get(&component_id)
                .and_then(|pairs| pairs.iter().find(|p| p.id() == pair_id))
                .cloned()
        };

        if let Some(selected_pair) = pair {
            // Create socket for this connection
            if let Some(local_addr) = selected_pair.local.socket_addr() {
                match UdpSocket::bind(SocketAddr::new(local_addr.ip(), 0)).await {
                    Ok(socket) => {
                        let connection = ComponentConnection {
                            component_id,
                            local_candidate: selected_pair.local.clone(),
                            remote_candidate: selected_pair.remote.clone(),
                            selected_pair: selected_pair.clone(),
                            socket: Arc::new(socket),
                            established_at: Instant::now(),
                            last_activity: Instant::now(),
                            bytes_sent: 0,
                            bytes_received: 0,
                        };

                        self.connections.write().await.insert(component_id, connection.clone());
                        self.stats.write().await.nominated_pairs += 1;

                        // Update state if this is the first connection
                        let current_state = *self.state.read().await;
                        if current_state == IceState::Connecting {
                            *self.state.write().await = IceState::Connected;
                        }

                        let _ = self.event_sender.send(IceEvent::ComponentConnected {
                            component_id,
                            local_candidate: connection.local_candidate,
                            remote_candidate: connection.remote_candidate,
                            selected_pair: connection.selected_pair,
                        });

                        info!("Component {} connected via {}", component_id, pair_id);
                    }
                    Err(e) => {
                        error!("Failed to create socket for component {}: {}", component_id, e);
                    }
                }
            }
        }
    }

    /// Process keepalive and consent freshness
    async fn process_keepalive(self) -> NatResult<()> {
        let mut timer = interval(self.config.keepalive_interval);

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            // Send keepalive for established connections
            let connections = self.connections.read().await.clone();
            for (component_id, connection) in connections {
                if connection.last_activity.elapsed() > self.config.keepalive_interval {
                    // Send keepalive (STUN binding indication)
                    self.send_keepalive(&connection).await;
                }
            }
        }

        Ok(())
    }

    /// Send keepalive for connection
    async fn send_keepalive(&self, connection: &ComponentConnection) {
        // This would send a STUN binding indication
        debug!("Sending keepalive for component {}", connection.component_id);
    }
}

impl Drop for IceAgent {
    fn drop(&mut self) {
        // Best effort cleanup
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let shutdown = self.shutdown.clone();
            handle.spawn(async move {
                *shutdown.write().await = true;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ice_agent_creation() {
        let config = IceConfig::default();
        let agent = IceAgent::new(config).await.unwrap();

        assert_eq!(agent.get_state().await, IceState::Gathering);
        assert!(agent.get_role().await.is_none());
    }

    #[tokio::test]
    async fn test_ice_credentials() {
        let creds1 = IceCredentials::new();
        let creds2 = IceCredentials::new();

        assert_ne!(creds1.ufrag, creds2.ufrag);
        assert_ne!(creds1.password, creds2.password);
    }

    #[tokio::test]
    async fn test_ice_config() {
        let config = IceConfig {
            transport_policy: IceTransportPolicy::Relay,
            enable_trickle: false,
            ..Default::default()
        };

        assert_eq!(config.transport_policy, IceTransportPolicy::Relay);
        assert!(!config.enable_trickle);
    }
}