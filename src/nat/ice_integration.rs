// src/nat/ice_integration.rs
//! SHARP3 ICE Integration
//!
//! This module provides seamless integration between the ICE implementation
//! and the SHARP3 P2P system, enabling automatic peer-to-peer connectivity
//! with full ICE support.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, broadcast, mpsc, oneshot};
use tokio::time::{interval, timeout, sleep};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};

use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::{
    IceAgent, IceConfig, IceRole, IceState, IceEvent,
    IceCredentials, IceTransportPolicy
};
use crate::nat::ice::candidate::{Candidate, CandidateType, TransportProtocol};
use crate::nat::ice::gathering::GatheringConfig;
use crate::nat::ice::nomination::{NominationConfig, NominationMode};

/// ICE parameters for peer exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceParameters {
    /// ICE credentials
    pub credentials: IceCredentials,

    /// ICE candidates
    pub candidates: Vec<CandidateInfo>,

    /// ICE options
    pub options: IceOptions,
}

/// Serializable candidate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateInfo {
    /// Foundation
    pub foundation: String,

    /// Component ID
    pub component_id: u32,

    /// Transport protocol
    pub transport: String,

    /// Priority
    pub priority: u32,

    /// Connection address
    pub address: String,

    /// Port
    pub port: u16,

    /// Candidate type
    pub candidate_type: String,

    /// Related address (for reflexive/relay candidates)
    pub related_address: Option<String>,

    /// Related port
    pub related_port: Option<u16>,

    /// TCP type (for TCP candidates)
    pub tcp_type: Option<String>,

    /// Extension attributes
    pub extensions: HashMap<String, String>,
}

/// ICE options for configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceOptions {
    /// Enable trickle ICE
    pub trickle: bool,

    /// Nomination mode
    pub nomination_mode: String,

    /// Transport policy
    pub transport_policy: String,

    /// Component count
    pub component_count: u32,

    /// Enable consent freshness
    pub consent_freshness: bool,
}

impl Default for IceOptions {
    fn default() -> Self {
        Self {
            trickle: true,
            nomination_mode: "regular".to_string(),
            transport_policy: "all".to_string(),
            component_count: 1,
            consent_freshness: true,
        }
    }
}

/// SHARP3 ICE integration interface
#[derive(Debug, Clone)]
pub enum IceIntegrationEvent {
    /// ICE parameters ready for exchange
    ParametersReady {
        parameters: IceParameters,
    },

    /// New trickle candidate available
    TrickleCandidate {
        candidate: CandidateInfo,
        component_id: u32,
    },

    /// ICE connection established
    ConnectionEstablished {
        local_address: SocketAddr,
        remote_address: SocketAddr,
        component_id: u32,
    },

    /// ICE connection failed
    ConnectionFailed {
        reason: String,
    },

    /// ICE gathering completed
    GatheringCompleted {
        candidate_count: usize,
    },

    /// Data channel ready
    DataChannelReady {
        component_id: u32,
    },
}

/// SHARP3 ICE Integration manager
pub struct Sharp3IceIntegration {
    /// ICE agent
    ice_agent: Arc<IceAgent>,

    /// Integration configuration
    config: IceIntegrationConfig,

    /// Current role
    role: Arc<RwLock<Option<IceRole>>>,

    /// Connection state
    state: Arc<RwLock<IceIntegrationState>>,

    /// Local ICE parameters
    local_parameters: Arc<RwLock<Option<IceParameters>>>,

    /// Remote ICE parameters
    remote_parameters: Arc<RwLock<Option<IceParameters>>>,

    /// Event broadcaster
    event_sender: broadcast::Sender<IceIntegrationEvent>,

    /// Data channels by component
    data_channels: Arc<RwLock<HashMap<u32, DataChannel>>>,

    /// Trickle candidate queue
    trickle_queue: Arc<RwLock<Vec<CandidateInfo>>>,

    /// Statistics
    stats: Arc<RwLock<IceIntegrationStats>>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,

    /// Start time for timing
    start_time: Instant,
}

/// ICE integration configuration
#[derive(Debug, Clone)]
pub struct IceIntegrationConfig {
    /// Enable aggressive nomination for faster connection
    pub aggressive_nomination: bool,

    /// Maximum time to wait for ICE completion
    pub ice_timeout: Duration,

    /// Enable automatic role determination
    pub auto_role: bool,

    /// Preferred candidate types (in order)
    pub preferred_candidates: Vec<CandidateType>,

    /// Enable IPv6
    pub enable_ipv6: bool,

    /// Enable TCP candidates
    pub enable_tcp: bool,

    /// Maximum candidates to gather per component
    pub max_candidates: u32,

    /// STUN servers for reflexive candidates
    pub stun_servers: Vec<String>,

    /// TURN servers for relay candidates
    pub turn_servers: Vec<TurnServerInfo>,

    /// Enable bundle (single transport for all components)
    pub enable_bundle: bool,

    /// Component mapping for bundle
    pub component_mapping: HashMap<u32, String>,
}

/// TURN server information for configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnServerInfo {
    pub url: String,
    pub username: String,
    pub password: String,
    pub transport: String,
}

impl Default for IceIntegrationConfig {
    fn default() -> Self {
        Self {
            aggressive_nomination: false,
            ice_timeout: Duration::from_secs(30),
            auto_role: true,
            preferred_candidates: vec![
                CandidateType::Host,
                CandidateType::ServerReflexive,
                CandidateType::Relay,
            ],
            enable_ipv6: true,
            enable_tcp: true,
            max_candidates: 10,
            stun_servers: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
            ],
            turn_servers: vec![],
            enable_bundle: true,
            component_mapping: [(1, "data".to_string())].into_iter().collect(),
        }
    }
}

/// ICE integration state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceIntegrationState {
    /// Not started
    Idle,
    /// Gathering local parameters
    Gathering,
    /// Waiting for remote parameters
    WaitingForRemote,
    /// Performing connectivity checks
    Connecting,
    /// Connection established
    Connected,
    /// Connection failed
    Failed,
    /// Closed
    Closed,
}

/// Data channel for component communication
#[derive(Debug, Clone)]
pub struct DataChannel {
    pub component_id: u32,
    pub local_address: SocketAddr,
    pub remote_address: SocketAddr,
    pub socket: Arc<UdpSocket>,
    pub established_at: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// ICE integration statistics
#[derive(Debug, Default, Clone)]
pub struct IceIntegrationStats {
    pub state: IceIntegrationState,
    pub role: Option<IceRole>,
    pub gathering_time: Duration,
    pub connection_time: Duration,
    pub total_time: Duration,
    pub candidates_gathered: u32,
    pub trickle_candidates_sent: u32,
    pub trickle_candidates_received: u32,
    pub successful_pairs: u32,
    pub selected_pairs: u32,
    pub data_channels: u32,
    pub bytes_transferred: u64,
}

impl Sharp3IceIntegration {
    /// Create new SHARP3 ICE integration
    pub async fn new(config: IceIntegrationConfig) -> NatResult<Self> {
        // Convert to ICE configuration
        let ice_config = Self::build_ice_config(&config)?;

        // Create ICE agent
        let ice_agent = Arc::new(IceAgent::new(ice_config).await?);

        let (event_sender, _) = broadcast::channel(1000);

        Ok(Self {
            ice_agent,
            config,
            role: Arc::new(RwLock::new(None)),
            state: Arc::new(RwLock::new(IceIntegrationState::Idle)),
            local_parameters: Arc::new(RwLock::new(None)),
            remote_parameters: Arc::new(RwLock::new(None)),
            event_sender,
            data_channels: Arc::new(RwLock::new(HashMap::new())),
            trickle_queue: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(IceIntegrationStats::default())),
            shutdown: Arc::new(RwLock::new(false)),
            start_time: Instant::now(),
        })
    }

    /// Build ICE configuration from integration config
    fn build_ice_config(config: &IceIntegrationConfig) -> NatResult<IceConfig> {
        let gathering_config = GatheringConfig {
            gather_host_candidates: true,
            gather_server_reflexive: !config.stun_servers.is_empty(),
            gather_relay_candidates: !config.turn_servers.is_empty(),
            enable_mdns: false, // Disable for P2P
            enable_ipv4: true,
            enable_ipv6: config.enable_ipv6,
            enable_tcp: config.enable_tcp,
            enable_udp: true,
            stun_servers: config.stun_servers.iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
            turn_servers: config.turn_servers.iter()
                .map(|t| crate::nat::ice::gathering::TurnServerConfig {
                    address: t.url.parse().unwrap_or("0.0.0.0:3478".parse().unwrap()),
                    username: t.username.clone(),
                    password: t.password.clone(),
                    realm: None,
                    transport: if t.transport == "tcp" {
                        TransportProtocol::Tcp
                    } else {
                        TransportProtocol::Udp
                    },
                })
                .collect(),
            max_candidates_per_type: config.max_candidates,
            ..Default::default()
        };

        let nomination_config = NominationConfig {
            mode: if config.aggressive_nomination {
                NominationMode::Aggressive
            } else {
                NominationMode::Regular
            },
            ..Default::default()
        };

        Ok(IceConfig {
            transport_policy: if config.turn_servers.is_empty() {
                IceTransportPolicy::All
            } else {
                IceTransportPolicy::All // Could be Relay for TURN-only
            },
            gathering_config,
            nomination_config,
            components: config.component_mapping.keys().cloned().collect(),
            connectivity_timeout: config.ice_timeout,
            enable_trickle: true,
            ..Default::default()
        })
    }

    /// Start ICE as initiator (controlling)
    pub async fn start_as_initiator(&self) -> NatResult<()> {
        info!("Starting ICE as initiator");

        *self.role.write().await = Some(IceRole::Controlling);
        *self.state.write().await = IceIntegrationState::Gathering;

        // Start ICE agent
        let ice_agent = self.ice_agent.clone();
        let event_sender = self.event_sender.clone();
        let local_parameters = self.local_parameters.clone();
        let state = self.state.clone();

        // Start background event processing
        let event_processor = self.start_event_processor();

        // Start ICE agent
        let start_task = async move {
            if let Err(e) = ice_agent.start(IceRole::Controlling).await {
                error!("Failed to start ICE agent: {}", e);
                return;
            }

            // Wait for local parameters
            let mut retry_count = 0;
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;

                let candidates = ice_agent.get_local_candidates(1).await;
                if !candidates.is_empty() {
                    let parameters = IceParameters {
                        credentials: ice_agent.get_local_credentials().clone(),
                        candidates: candidates.iter().map(|c| Self::candidate_to_info(c)).collect(),
                        options: IceOptions::default(),
                    };

                    *local_parameters.write().await = Some(parameters.clone());
                    *state.write().await = IceIntegrationState::WaitingForRemote;

                    let _ = event_sender.send(IceIntegrationEvent::ParametersReady { parameters });
                    break;
                }

                retry_count += 1;
                if retry_count > 100 { // 10 second timeout
                    error!("Timeout waiting for local candidates");
                    break;
                }
            }
        };

        tokio::select! {
            _ = start_task => {},
            _ = event_processor => {},
        }

        Ok(())
    }

    /// Start ICE as responder (controlled)
    pub async fn start_as_responder(&self, remote_params: IceParameters) -> NatResult<()> {
        info!("Starting ICE as responder");

        *self.role.write().await = Some(IceRole::Controlled);
        *self.state.write().await = IceIntegrationState::Gathering;

        // Store remote parameters
        *self.remote_parameters.write().await = Some(remote_params.clone());

        // Set remote credentials
        self.ice_agent.set_remote_credentials(remote_params.credentials).await?;

        // Add remote candidates
        for candidate_info in &remote_params.candidates {
            if let Ok(candidate) = Self::info_to_candidate(candidate_info) {
                self.ice_agent.add_remote_candidate(candidate, candidate_info.component_id).await?;
            }
        }

        // Start ICE agent
        let ice_agent = self.ice_agent.clone();
        let event_sender = self.event_sender.clone();
        let local_parameters = self.local_parameters.clone();
        let state = self.state.clone();

        // Start background event processing
        let event_processor = self.start_event_processor();

        // Start ICE agent
        let start_task = async move {
            if let Err(e) = ice_agent.start(IceRole::Controlled).await {
                error!("Failed to start ICE agent: {}", e);
                return;
            }

            // Wait for local parameters
            let mut retry_count = 0;
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;

                let candidates = ice_agent.get_local_candidates(1).await;
                if !candidates.is_empty() {
                    let parameters = IceParameters {
                        credentials: ice_agent.get_local_credentials().clone(),
                        candidates: candidates.iter().map(|c| Self::candidate_to_info(c)).collect(),
                        options: IceOptions::default(),
                    };

                    *local_parameters.write().await = Some(parameters.clone());
                    *state.write().await = IceIntegrationState::Connecting;

                    let _ = event_sender.send(IceIntegrationEvent::ParametersReady { parameters });
                    break;
                }

                retry_count += 1;
                if retry_count > 100 { // 10 second timeout
                    error!("Timeout waiting for local candidates");
                    break;
                }
            }
        };

        tokio::select! {
            _ = start_task => {},
            _ = event_processor => {},
        }

        Ok(())
    }

    /// Set remote ICE parameters
    pub async fn set_remote_parameters(&self, params: IceParameters) -> NatResult<()> {
        info!("Setting remote ICE parameters");

        *self.remote_parameters.write().await = Some(params.clone());

        // Set remote credentials
        self.ice_agent.set_remote_credentials(params.credentials).await?;

        // Add remote candidates
        for candidate_info in &params.candidates {
            if let Ok(candidate) = Self::info_to_candidate(candidate_info) {
                self.ice_agent.add_remote_candidate(candidate, candidate_info.component_id).await?;
            }
        }

        *self.state.write().await = IceIntegrationState::Connecting;

        Ok(())
    }

    /// Add trickle candidate
    pub async fn add_trickle_candidate(&self, candidate_info: CandidateInfo) -> NatResult<()> {
        debug!("Adding trickle candidate: {:?}", candidate_info);

        if let Ok(candidate) = Self::info_to_candidate(&candidate_info) {
            self.ice_agent.add_remote_candidate(candidate, candidate_info.component_id).await?;
        }

        self.stats.write().await.trickle_candidates_received += 1;

        Ok(())
    }

    /// Get local ICE parameters
    pub async fn get_local_parameters(&self) -> Option<IceParameters> {
        self.local_parameters.read().await.clone()
    }

    /// Send data on component
    pub async fn send_data(&self, component_id: u32, data: Vec<u8>) -> NatResult<usize> {
        // First try data channel
        let data_channel = {
            let channels = self.data_channels.read().await;
            channels.get(&component_id).cloned()
        };

        if let Some(channel) = data_channel {
            let bytes_sent = channel.socket.send_to(&data, channel.remote_address).await
                .map_err(|e| NatError::Network(e))?;

            // Update statistics
            {
                let mut channels = self.data_channels.write().await;
                if let Some(channel) = channels.get_mut(&component_id) {
                    channel.bytes_sent += bytes_sent as u64;
                }
            }

            self.stats.write().await.bytes_transferred += bytes_sent as u64;

            Ok(bytes_sent)
        } else {
            // Fallback to ICE agent
            self.ice_agent.send_data(component_id, data).await
        }
    }

    /// Receive data from component
    pub async fn receive_data(&self, component_id: u32, buffer: &mut [u8]) -> NatResult<(usize, SocketAddr)> {
        let data_channel = {
            let channels = self.data_channels.read().await;
            channels.get(&component_id).cloned()
        };

        if let Some(channel) = data_channel {
            let (size, from) = channel.socket.recv_from(buffer).await
                .map_err(|e| NatError::Network(e))?;

            // Update statistics
            {
                let mut channels = self.data_channels.write().await;
                if let Some(channel) = channels.get_mut(&component_id) {
                    channel.bytes_received += size as u64;
                }
            }

            self.stats.write().await.bytes_transferred += size as u64;

            Ok((size, from))
        } else {
            Err(NatError::Configuration("No data channel for component".to_string()))
        }
    }

    /// Start event processor
    async fn start_event_processor(&self) -> NatResult<()> {
        let mut ice_events = self.ice_agent.subscribe_events();
        let event_sender = self.event_sender.clone();
        let state = self.state.clone();
        let data_channels = self.data_channels.clone();
        let stats = self.stats.clone();
        let shutdown = self.shutdown.clone();
        let trickle_queue = self.trickle_queue.clone();

        loop {
            if *shutdown.read().await {
                break;
            }

            tokio::select! {
                Ok(event) = ice_events.recv() => {
                    match event {
                        IceEvent::CandidateAdded { candidate, component_id } => {
                            // Send as trickle candidate
                            let candidate_info = Self::candidate_to_info(&candidate);
                            let _ = event_sender.send(IceIntegrationEvent::TrickleCandidate {
                                candidate: candidate_info,
                                component_id,
                            });

                            stats.write().await.trickle_candidates_sent += 1;
                        }

                        IceEvent::ComponentConnected {
                            component_id,
                            local_candidate,
                            remote_candidate,
                            selected_pair,
                            ..
                        } => {
                            if let (Some(local_addr), Some(remote_addr)) = (
                                local_candidate.socket_addr(),
                                remote_candidate.socket_addr()
                            ) {
                                // Create data channel
                                if let Ok(socket) = UdpSocket::bind(SocketAddr::new(local_addr.ip(), 0)).await {
                                    let data_channel = DataChannel {
                                        component_id,
                                        local_address: local_addr,
                                        remote_address: remote_addr,
                                        socket: Arc::new(socket),
                                        established_at: Instant::now(),
                                        bytes_sent: 0,
                                        bytes_received: 0,
                                    };

                                    data_channels.write().await.insert(component_id, data_channel);
                                    stats.write().await.data_channels += 1;

                                    let _ = event_sender.send(IceIntegrationEvent::ConnectionEstablished {
                                        local_address: local_addr,
                                        remote_address: remote_addr,
                                        component_id,
                                    });

                                    let _ = event_sender.send(IceIntegrationEvent::DataChannelReady {
                                        component_id,
                                    });
                                }
                            }
                        }

                        IceEvent::ConnectionEstablished { .. } => {
                            *state.write().await = IceIntegrationState::Connected;
                            stats.write().await.connection_time = self.start_time.elapsed();
                        }

                        IceEvent::ConnectionFailed { reason } => {
                            *state.write().await = IceIntegrationState::Failed;
                            let _ = event_sender.send(IceIntegrationEvent::ConnectionFailed { reason });
                        }

                        IceEvent::GatheringCompleted { candidate_count, .. } => {
                            stats.write().await.candidates_gathered = candidate_count as u32;
                            stats.write().await.gathering_time = self.start_time.elapsed();

                            let _ = event_sender.send(IceIntegrationEvent::GatheringCompleted {
                                candidate_count,
                            });
                        }

                        _ => {}
                    }
                }
                _ = sleep(Duration::from_millis(100)) => {
                    // Periodic cleanup
                }
            }
        }

        Ok(())
    }

    /// Convert candidate to info
    fn candidate_to_info(candidate: &Candidate) -> CandidateInfo {
        let (address, port) = match &candidate.address {
            crate::nat::ice::candidate::CandidateAddress::Ip(addr) => {
                (addr.ip().to_string(), addr.port())
            }
            crate::nat::ice::candidate::CandidateAddress::MDns { hostname, port } => {
                (hostname.clone(), *port)
            }
        };

        let (related_address, related_port) = match &candidate.related_address {
            Some(crate::nat::ice::candidate::CandidateAddress::Ip(addr)) => {
                (Some(addr.ip().to_string()), Some(addr.port()))
            }
            Some(crate::nat::ice::candidate::CandidateAddress::MDns { hostname, port }) => {
                (Some(hostname.clone()), Some(*port))
            }
            None => (None, None),
        };

        CandidateInfo {
            foundation: candidate.foundation.clone(),
            component_id: candidate.component_id,
            transport: candidate.transport.to_str().to_string(),
            priority: candidate.priority,
            address,
            port,
            candidate_type: candidate.candidate_type.to_str().to_string(),
            related_address,
            related_port,
            tcp_type: candidate.tcp_type.map(|t| t.to_str().to_string()),
            extensions: HashMap::new(), // Could populate from candidate.extensions
        }
    }

    /// Convert info to candidate
    fn info_to_candidate(info: &CandidateInfo) -> NatResult<Candidate> {
        use crate::nat::ice::candidate::{CandidateExtensions, CandidateAddress};

        let transport = match info.transport.as_str() {
            "udp" => TransportProtocol::Udp,
            "tcp" => TransportProtocol::Tcp,
            _ => return Err(NatError::Platform("Invalid transport protocol".to_string())),
        };

        let candidate_type = match info.candidate_type.as_str() {
            "host" => CandidateType::Host,
            "srflx" => CandidateType::ServerReflexive,
            "prflx" => CandidateType::PeerReflexive,
            "relay" => CandidateType::Relay,
            _ => return Err(NatError::Platform("Invalid candidate type".to_string())),
        };

        // Parse address
        let address = if info.address.ends_with(".local") {
            CandidateAddress::MDns {
                hostname: info.address.clone(),
                port: info.port,
            }
        } else {
            let ip = info.address.parse()
                .map_err(|_| NatError::Platform("Invalid IP address".to_string()))?;
            CandidateAddress::Ip(SocketAddr::new(ip, info.port))
        };

        // Parse related address
        let related_address = if let (Some(related_addr), Some(related_port)) =
            (&info.related_address, &info.related_port) {

            if related_addr.ends_with(".local") {
                Some(CandidateAddress::MDns {
                    hostname: related_addr.clone(),
                    port: *related_port,
                })
            } else {
                let ip = related_addr.parse()
                    .map_err(|_| NatError::Platform("Invalid related IP address".to_string()))?;
                Some(CandidateAddress::Ip(SocketAddr::new(ip, *related_port)))
            }
        } else {
            None
        };

        let extensions = CandidateExtensions::new();

        let mut candidate = Candidate {
            foundation: info.foundation.clone(),
            component_id: info.component_id,
            transport,
            priority: info.priority,
            address,
            candidate_type,
            related_address,
            tcp_type: info.tcp_type.as_ref().and_then(|t| {
                match t.as_str() {
                    "active" => Some(crate::nat::ice::candidate::TcpType::Active),
                    "passive" => Some(crate::nat::ice::candidate::TcpType::Passive),
                    "so" => Some(crate::nat::ice::candidate::TcpType::So),
                    _ => None,
                }
            }),
            extensions,
            discovered_at: Instant::now(),
            base_address: None,
            server_address: None,
        };

        candidate.validate()?;

        Ok(candidate)
    }

    /// Get current state
    pub async fn get_state(&self) -> IceIntegrationState {
        *self.state.read().await
    }

    /// Get current role
    pub async fn get_role(&self) -> Option<IceRole> {
        *self.role.read().await
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> IceIntegrationStats {
        let mut stats = self.stats.read().await.clone();
        stats.state = *self.state.read().await;
        stats.role = *self.role.read().await;
        stats.total_time = self.start_time.elapsed();
        stats
    }

    /// Subscribe to integration events
    pub fn subscribe_events(&self) -> broadcast::Receiver<IceIntegrationEvent> {
        self.event_sender.subscribe()
    }

    /// Check if connection is established
    pub async fn is_connected(&self) -> bool {
        *self.state.read().await == IceIntegrationState::Connected
    }

    /// Get established data channels
    pub async fn get_data_channels(&self) -> HashMap<u32, DataChannel> {
        self.data_channels.read().await.clone()
    }

    /// Close integration
    pub async fn close(&self) {
        info!("Closing ICE integration");

        *self.shutdown.write().await = true;
        *self.state.write().await = IceIntegrationState::Closed;

        self.ice_agent.close().await;
        self.data_channels.write().await.clear();
    }

    /// Restart ICE
    pub async fn restart(&self) -> NatResult<()> {
        info!("Restarting ICE");

        self.ice_agent.restart().await?;

        // Clear state
        *self.local_parameters.write().await = None;
        *self.remote_parameters.write().await = None;
        self.data_channels.write().await.clear();
        self.trickle_queue.write().await.clear();

        *self.state.write().await = IceIntegrationState::Gathering;

        Ok(())
    }
}

impl Drop for Sharp3IceIntegration {
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

/// Helper functions for SHARP3 integration

/// Create ICE integration with SHARP3 optimized settings
pub async fn create_sharp3_ice_integration() -> NatResult<Sharp3IceIntegration> {
    let config = IceIntegrationConfig {
        aggressive_nomination: true, // Faster for P2P
        ice_timeout: Duration::from_secs(20),
        enable_ipv6: true,
        enable_tcp: false, // UDP only for P2P speed
        max_candidates: 5, // Limit for faster gathering
        enable_bundle: true,
        ..Default::default()
    };

    Sharp3IceIntegration::new(config).await
}

/// Extract connection info for SHARP3 use
pub fn extract_connection_info(data_channel: &DataChannel) -> (SocketAddr, SocketAddr) {
    (data_channel.local_address, data_channel.remote_address)
}

/// Check if ICE parameters are compatible
pub fn are_parameters_compatible(local: &IceParameters, remote: &IceParameters) -> bool {
    // Basic compatibility checks
    !local.candidates.is_empty() &&
        !remote.candidates.is_empty() &&
        local.options.component_count == remote.options.component_count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ice_integration_creation() {
        let config = IceIntegrationConfig::default();
        let integration = Sharp3IceIntegration::new(config).await.unwrap();

        assert_eq!(integration.get_state().await, IceIntegrationState::Idle);
        assert!(integration.get_role().await.is_none());
    }

    #[test]
    fn test_candidate_conversion() {
        use crate::nat::ice::candidate::{Candidate, CandidateExtensions};

        let candidate = Candidate::new_host(
            "192.168.1.1:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );

        let info = Sharp3IceIntegration::candidate_to_info(&candidate);
        let converted = Sharp3IceIntegration::info_to_candidate(&info).unwrap();

        assert_eq!(candidate.foundation, converted.foundation);
        assert_eq!(candidate.component_id, converted.component_id);
        assert_eq!(candidate.transport, converted.transport);
        assert_eq!(candidate.candidate_type, converted.candidate_type);
    }

    #[test]
    fn test_ice_parameters_compatibility() {
        let params1 = IceParameters {
            credentials: IceCredentials::new(),
            candidates: vec![],
            options: IceOptions {
                component_count: 1,
                ..Default::default()
            },
        };

        let params2 = IceParameters {
            credentials: IceCredentials::new(),
            candidates: vec![],
            options: IceOptions {
                component_count: 2,
                ..Default::default()
            },
        };

        assert!(!are_parameters_compatible(&params1, &params2));
    }

    #[tokio::test]
    async fn test_sharp3_optimized_creation() {
        let integration = create_sharp3_ice_integration().await.unwrap();
        assert!(integration.config.aggressive_nomination);
        assert!(!integration.config.enable_tcp);
        assert!(integration.config.enable_bundle);
    }
}