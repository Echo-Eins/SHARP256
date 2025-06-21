// src/nat/ice/agent.rs
//! Main ICE agent implementation

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::{interval, Duration};

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
    
    /// Keepalive interval
    pub keepalive_interval: Duration,
    
    /// Component count per stream
    pub component_count: u32,
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
            component_count: 1,
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
}

/// Main ICE agent
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
    selected_pairs: Arc<RwLock<HashMap<(u32, u32), Candidate>>>,
    
    /// Nomination state
    nomination_complete: Arc<RwLock<bool>>,
}

impl IceAgent {
    /// Create new ICE agent
    pub fn new(config: IceConfig, role: IceRole) -> NatResult<Self> {
        let local_credentials = IceCredentials::generate();
        
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
        )));
        
        // Create trickle ICE if enabled
        let (trickle, trickle_rx) = if config.trickle {
            let (trickle_tx, trickle_rx) = mpsc::unbounded_channel();
            let trickle = Arc::new(TrickleIce::new(trickle_tx));
            (Some(trickle), Some(Arc::new(Mutex::new(trickle_rx))))
        } else {
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
        *self.remote_credentials.write().await = Some(credentials.clone());
        self.checker.write().await.set_remote_credentials(credentials);
        Ok(())
    }
    
    /// Add stream
    pub async fn add_stream(&self, stream_id: u32) -> NatResult<()> {
        let stream = IceStream::new(stream_id, self.config.component_count);
        self.streams.write().await.insert(stream_id, stream);
        Ok(())
    }
    
    /// Start gathering candidates
    pub async fn start_gathering(&self) -> NatResult<()> {
        let mut state = self.state.write().await;
        if *state != IceState::New {
            return Err(NatError::Platform("Invalid state for gathering".to_string()));
        }
        *state = IceState::Gathering;
        drop(state);
        
        // Send state change event
        let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Gathering));
        
        // Gather for each stream/component
        let streams = self.streams.read().await;
        for (stream_id, stream) in streams.iter() {
            for component_id in 1..=stream.component_count {
                let gatherer = self.gatherer.clone();
                let stream_id = *stream_id;
                
                tokio::spawn(async move {
                    let _ = gatherer.gather_candidates(component_id, 0).await;
                });
            }
        }
        
        Ok(())
    }
    
    /// Add remote candidate (for non-trickle or manual trickle)
    pub async fn add_remote_candidate(&self, candidate: Candidate) -> NatResult<()> {
        // Find the stream
        let mut streams = self.streams.write().await;
        let stream = streams.get_mut(&candidate.component_id)
            .ok_or_else(|| NatError::Platform("Unknown stream".to_string()))?;
        
        stream.add_remote_candidate(candidate);
        
        Ok(())
    }
    
    /// Start connectivity checks
    pub async fn start_checks(&self) -> NatResult<()> {
        let mut state = self.state.write().await;
        if *state != IceState::Ready {
            return Err(NatError::Platform("Not ready for checks".to_string()));
        }
        *state = IceState::Checking;
        drop(state);
        
        // Send state change event
        let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Checking));
        
        // Create check lists
        let streams = self.streams.read().await;
        for (stream_id, stream) in streams.iter() {
            let local_candidates = stream.get_local_candidates().await;
            let remote_candidates = stream.get_remote_candidates().await;
            
            if !local_candidates.is_empty() && !remote_candidates.is_empty() {
                // Add sockets to checker
                for candidate in &local_candidates {
                    if let Some(socket) = self.gatherer.get_socket(candidate.component_id).await {
                        self.checker.read().await.add_socket(candidate.addr, socket).await;
                    }
                }
                
                // Create check list
                self.checker.read().await.create_check_list(
                    *stream_id,
                    local_candidates,
                    remote_candidates,
                ).await?;
            }
        }
        
        // Start checks
        self.checker.read().await.start_checks().await;
        
        // Start keepalive timer
        self.start_keepalive_timer();
        
        Ok(())
    }
    
    /// Get selected candidate pair for stream/component
    pub async fn get_selected_pair(
        &self,
        stream_id: u32,
        component_id: u32,
    ) -> Option<(Candidate, Candidate)> {
        // TODO: Return actual selected pair
        None
    }
    
    /// Close ICE agent
    pub async fn close(&self) -> NatResult<()> {
        *self.state.write().await = IceState::Closed;
        let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Closed));
        Ok(())
    }
    
    /// Get event receiver
    pub fn get_event_rx(&self) -> Arc<Mutex<mpsc::UnboundedReceiver<IceEvent>>> {
        self.event_rx.clone()
    }
    
    /// Start event processing loops
    fn start_event_processing(&self) {
        // Gathering events
        let agent = self.clone();
        tokio::spawn(async move {
            agent.process_gathering_events().await;
        });
        
        // Connectivity events
        let agent = self.clone();
        tokio::spawn(async move {
            agent.process_connectivity_events().await;
        });
        
        // Trickle events
        if let Some(trickle_rx) = &self.trickle_rx {
            let agent = self.clone();
            let trickle_rx = trickle_rx.clone();
            tokio::spawn(async move {
                agent.process_trickle_events(trickle_rx).await;
            });
        }
    }
    
    /// Process gathering events
    async fn process_gathering_events(&self) {
        let mut rx = self.gathering_rx.lock().await;
        
        while let Some(event) = rx.recv().await {
            match event {
                GatheringEvent::CandidateFound(candidate) => {
                    // Add to stream
                    if let Some(stream) = self.streams.write().await.get_mut(&candidate.component_id) {
                        stream.add_local_candidate(candidate.clone());
                    }
                    
                    // Send event
                    let _ = self.event_tx.send(IceEvent::CandidateGathered(candidate));
                }
                
                GatheringEvent::ComponentComplete(_component) => {
                    // Check if all components complete
                    let all_complete = self.streams.read().await.values()
                        .all(|s| s.gathering_complete);
                    
                    if all_complete {
                        *self.state.write().await = IceState::Ready;
                        let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Ready));
                        let _ = self.event_tx.send(IceEvent::GatheringComplete);
                    }
                }
                
                GatheringEvent::ComponentFailed(component, reason) => {
                    tracing::error!("Gathering failed for component {}: {}", component, reason);
                }
            }
        }
    }
    
    /// Process connectivity events
    async fn process_connectivity_events(&self) {
        let mut rx = self.connectivity_rx.lock().await;
        let mut first_connected = true;
        
        while let Some(event) = rx.recv().await {
            match event {
                ConnectivityEvent::PairStateChanged { stream_id, pair } => {
                    tracing::debug!("Pair state changed: {} -> {:?}", pair.id(), pair.state);
                }
                
                ConnectivityEvent::ValidPair { stream_id, pair } => {
                    // First valid pair means connected
                    if first_connected {
                        first_connected = false;
                        *self.state.write().await = IceState::Connected;
                        let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Connected));
                    }
                    
                    let _ = self.event_tx.send(IceEvent::ValidatedPair(pair));
                }
                
                ConnectivityEvent::CheckListCompleted { stream_id } => {
                    // Check if all streams completed
                    // TODO: Implement completion check
                }
                
                ConnectivityEvent::CheckListFailed { stream_id } => {
                    *self.state.write().await = IceState::Failed;
                    let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Failed));
                    let _ = self.event_tx.send(IceEvent::Failed("Check list failed".to_string()));
                }
                
                ConnectivityEvent::NominatedPair { stream_id, component_id, pair } => {
                    // Store selected pair
                    self.selected_pairs.write().await.insert(
                        (stream_id, component_id),
                        pair.local.clone(),
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
            }
        }
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
                    // Trickle candidate is ready to be sent
                    let _ = self.event_tx.send(IceEvent::CandidateGathered(candidate));
                }
                
                TrickleEvent::RemoteCandidateReceived(candidate) => {
                    // Add remote candidate dynamically
                    let _ = self.add_remote_candidate(candidate).await;
                }
                
                TrickleEvent::EndOfCandidates => {
                    // Remote signaled end of candidates
                    tracing::info!("Remote end of candidates");
                }
            }
        }
    }
    
    /// Check if nomination is complete
    async fn check_nomination_complete(&self) {
        let expected_pairs = self.streams.read().await.len() * self.config.component_count as usize;
        let selected_count = self.selected_pairs.read().await.len();
        
        if selected_count >= expected_pairs && !*self.nomination_complete.read().await {
            *self.nomination_complete.write().await = true;
            *self.state.write().await = IceState::Completed;
            let _ = self.event_tx.send(IceEvent::StateChanged(IceState::Completed));
        }
    }
    
    /// Start keepalive timer
    fn start_keepalive_timer(&self) {
        let agent = self.clone();
        let interval_duration = self.config.keepalive_interval;
        
        tokio::spawn(async move {
            let mut timer = interval(interval_duration);
            
            loop {
                timer.tick().await;
                
                if *agent.state.read().await == IceState::Closed {
                    break;
                }
                
                // Send keepalives on selected pairs
                // TODO: Implement keepalive sending
            }
        });
    }
}

impl Clone for IceAgent {
    fn clone(&self) -> Self {
        // Note: This creates a shallow clone sharing the same internal state
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
            Some(IceEvent::StateChanged(IceState::Gathering)) => {}
            _ => panic!("Expected gathering state change"),
        }
    }
}