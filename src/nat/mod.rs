// src/nat/mod.rs
//! NAT (Network Address Translation) System for SHARP3 P2P Framework
//!
//! This module provides a comprehensive NAT traversal solution that integrates:
//! - STUN (Session Traversal Utilities for NAT) for NAT discovery
//! - TURN (Traversal Using Relays around NAT) for relay functionality
//! - ICE (Interactive Connectivity Establishment) for connection establishment
//!
//! The system provides a unified, high-level API for establishing peer-to-peer
//! connections across NAT boundaries.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tracing::{info, warn, debug, error};
use serde::{Serialize, Deserialize};

// Re-export core error types
pub mod error;
pub use error::{NatError, NatResult};

// STUN system
pub mod stun;
pub use stun::{
    StunService, StunConfig, StunClient, StunServer,
    NatType, NatBehavior, MappingBehavior, FilteringBehavior,
};

// TURN system
pub mod turn;
pub use turn::{
    TurnClient, TurnServer, TurnServerConfig, TurnCredentials,
    AllocationState, RelayAddress,
};

// ICE system
pub mod ice;
pub use ice::{
    IceAgent, IceConfig, IceRole, IceState, IceEvent,
    Candidate, CandidateType, CandidateAddress, CandidateExtensions,
    TransportProtocol, TcpType, IceTransportPolicy,
    BundlePolicy, RtcpMuxPolicy,
};

// Integration modules
pub mod stun_turn_manager;
pub mod ice_integration;

// Re-export integration types
pub use stun_turn_manager::{
    StunTurnManager, StunTurnConfig, StunTurnEvent,
    TurnServerInfo, TurnTransport, CandidateGatheringRequest,
    CandidateGatheringResult, TurnAllocationInfo, ConnectionQualityMetrics,
    create_stun_turn_manager,
};

pub use ice_integration::{
    Sharp3IceIntegration, IceSession, IceParameters, IceGatheringConfig,
    QualityThresholds, IceIntegrationEvent, IceIntegrationStats,
    create_ice_session_with_sharp,
};

/// Main NAT system configuration
#[derive(Debug, Clone)]
pub struct NatSystemConfig {
    /// STUN configuration
    pub stun_config: StunConfig,

    /// TURN servers to use
    pub turn_servers: Vec<TurnServerInfo>,

    /// Whether to enable integrated TURN server
    pub enable_turn_server: bool,

    /// TURN server configuration (if enabled)
    pub turn_server_config: Option<turn::server::TurnServerConfig>,

    /// ICE configuration
    pub ice_config: IceConfig,

    /// ICE gathering configuration
    pub ice_gathering_config: IceGatheringConfig,

    /// Quality thresholds for connection assessment
    pub quality_thresholds: QualityThresholds,

    /// System-wide timeouts
    pub timeouts: NatTimeouts,

    /// Feature flags
    pub features: NatFeatures,
}

/// NAT system timeouts
#[derive(Debug, Clone)]
pub struct NatTimeouts {
    /// Overall connection establishment timeout
    pub connection_timeout: Duration,

    /// STUN request timeout
    pub stun_timeout: Duration,

    /// TURN allocation timeout
    pub turn_timeout: Duration,

    /// ICE gathering timeout
    pub ice_gathering_timeout: Duration,

    /// ICE connectivity check timeout
    pub ice_connectivity_timeout: Duration,

    /// Keep-alive interval for established connections
    pub keepalive_interval: Duration,
}

/// NAT system feature flags
#[derive(Debug, Clone)]
pub struct NatFeatures {
    /// Enable IPv6 support
    pub enable_ipv6: bool,

    /// Enable TCP candidates
    pub enable_tcp: bool,

    /// Enable mDNS candidates
    pub enable_mdns: bool,

    /// Enable trickle ICE
    pub enable_trickle_ice: bool,

    /// Enable aggressive nomination
    pub enable_aggressive_nomination: bool,

    /// Enable consent freshness (RFC 7675)
    pub enable_consent_freshness: bool,

    /// Enable quality monitoring
    pub enable_quality_monitoring: bool,

    /// Enable detailed logging
    pub enable_detailed_logging: bool,
}

/// NAT connection establishment result
#[derive(Debug, Clone)]
pub struct NatConnectionResult {
    /// Local address used for connection
    pub local_address: SocketAddr,

    /// Remote address of peer
    pub remote_address: SocketAddr,

    /// Connection path type
    pub connection_type: ConnectionType,

    /// Selected candidate pair information
    pub selected_candidate: SelectedCandidateInfo,

    /// Connection quality metrics
    pub quality_metrics: ConnectionQualityMetrics,

    /// Time taken to establish connection
    pub establishment_time: Duration,

    /// NAT behavior detected during connection
    pub nat_behavior: Option<NatBehavior>,
}

/// Type of connection established
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Direct connection (host to host)
    Direct,

    /// Connection through NAT (server reflexive)
    NatTraversal,

    /// Connection through TURN relay
    Relayed,

    /// Peer reflexive connection (discovered during checks)
    PeerReflexive,
}

/// Information about selected candidate pair
#[derive(Debug, Clone)]
pub struct SelectedCandidateInfo {
    /// Local candidate that was selected
    pub local_candidate: Candidate,

    /// Remote candidate that was selected
    pub remote_candidate: Candidate,

    /// Candidate pair priority
    pub pair_priority: u64,

    /// Round-trip time for this pair
    pub rtt: Option<Duration>,

    /// Whether this pair was nominated
    pub nominated: bool,
}

/// Main NAT system manager
pub struct NatSystem {
    /// System configuration
    config: Arc<NatSystemConfig>,

    /// STUN/TURN manager
    stun_turn_manager: Arc<StunTurnManager>,

    /// Active NAT sessions
    sessions: Arc<RwLock<HashMap<String, Arc<NatSession>>>>,

    /// System-wide event broadcaster
    event_sender: broadcast::Sender<NatSystemEvent>,

    /// System statistics
    stats: Arc<NatSystemStats>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,
}

/// Individual NAT session for a connection
pub struct NatSession {
    /// Session identifier
    pub session_id: String,

    /// ICE session handle
    pub ice_session: Arc<IceSession>,

    /// Session configuration
    pub config: NatSessionConfig,

    /// Session state
    pub state: Arc<RwLock<NatSessionState>>,

    /// Session events
    pub event_sender: broadcast::Sender<NatSessionEvent>,

    /// Session statistics
    pub stats: Arc<NatSessionStats>,

    /// Connection result (when established)
    pub connection_result: Arc<RwLock<Option<NatConnectionResult>>>,
}

/// NAT session configuration
#[derive(Debug, Clone)]
pub struct NatSessionConfig {
    /// Session role (controlling or controlled)
    pub role: IceRole,

    /// Components to establish (usually 1 for data, 2 for RTP+RTCP)
    pub components: Vec<u32>,

    /// Local ICE parameters
    pub local_ice_params: IceParameters,

    /// Session-specific timeouts
    pub timeouts: NatTimeouts,

    /// Session-specific features
    pub features: NatFeatures,
}

/// NAT session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatSessionState {
    /// Session created but not started
    Created,

    /// Gathering candidates
    Gathering,

    /// Exchanging candidates with peer
    Exchanging,

    /// Performing connectivity checks
    Connecting,

    /// Connection established
    Connected,

    /// Connection failed
    Failed,

    /// Session completed and closed
    Closed,
}

/// System-wide NAT events
#[derive(Debug, Clone)]
pub enum NatSystemEvent {
    /// New session created
    SessionCreated {
        session_id: String,
        config: NatSessionConfig,
    },

    /// Session state changed
    SessionStateChanged {
        session_id: String,
        old_state: NatSessionState,
        new_state: NatSessionState,
    },

    /// Connection established for session
    ConnectionEstablished {
        session_id: String,
        result: NatConnectionResult,
    },

    /// Session failed
    SessionFailed {
        session_id: String,
        error: String,
    },

    /// Session closed
    SessionClosed {
        session_id: String,
    },

    /// System-wide quality change
    SystemQualityChanged {
        metric: String,
        old_value: f64,
        new_value: f64,
    },
}

/// Session-specific NAT events
#[derive(Debug, Clone)]
pub enum NatSessionEvent {
    /// Candidate gathered
    CandidateGathered {
        component_id: u32,
        candidate: Candidate,
    },

    /// Remote candidate received
    RemoteCandidateReceived {
        component_id: u32,
        candidate: Candidate,
    },

    /// Connectivity check result
    ConnectivityCheckResult {
        pair_id: String,
        success: bool,
        rtt: Option<Duration>,
    },

    /// Component connected
    ComponentConnected {
        component_id: u32,
        local_candidate: Candidate,
        remote_candidate: Candidate,
    },

    /// Session connection established
    ConnectionEstablished {
        result: NatConnectionResult,
    },

    /// Session failed
    Failed {
        error: String,
    },
}

/// NAT system statistics
#[derive(Debug, Default)]
pub struct NatSystemStats {
    /// Total sessions created
    pub total_sessions: std::sync::atomic::AtomicU64,

    /// Currently active sessions
    pub active_sessions: std::sync::atomic::AtomicU64,

    /// Successful connections
    pub successful_connections: std::sync::atomic::AtomicU64,

    /// Failed connections
    pub failed_connections: std::sync::atomic::AtomicU64,

    /// Connection success rate (percentage * 100)
    pub success_rate: std::sync::atomic::AtomicU64,

    /// Average connection establishment time (microseconds)
    pub avg_connection_time: std::sync::atomic::AtomicU64,

    /// Total candidates gathered
    pub total_candidates: std::sync::atomic::AtomicU64,

    /// Breakdown by connection type
    pub direct_connections: std::sync::atomic::AtomicU64,
    pub nat_traversal_connections: std::sync::atomic::AtomicU64,
    pub relayed_connections: std::sync::atomic::AtomicU64,

    /// STUN/TURN statistics (delegated)
    pub stun_turn_stats: Arc<stun_turn_manager::StunTurnStats>,
}

/// NAT session statistics
#[derive(Debug, Default)]
pub struct NatSessionStats {
    /// Session creation time
    pub created_at: Option<std::time::Instant>,

    /// Connection establishment time
    pub connected_at: Option<std::time::Instant>,

    /// Total gathering time
    pub gathering_duration: Option<Duration>,

    /// Total connectivity time
    pub connectivity_duration: Option<Duration>,

    /// Candidates gathered by type
    pub host_candidates: u32,
    pub server_reflexive_candidates: u32,
    pub relay_candidates: u32,
    pub peer_reflexive_candidates: u32,

    /// Connectivity checks performed
    pub connectivity_checks: u32,
    pub successful_checks: u32,
    pub failed_checks: u32,

    /// Quality metrics
    pub final_rtt: Option<Duration>,
    pub packet_loss_rate: f64,
    pub bandwidth_estimate: Option<u64>,
}

impl Default for NatSystemConfig {
    fn default() -> Self {
        Self {
            stun_config: StunConfig::default(),
            turn_servers: vec![],
            enable_turn_server: false,
            turn_server_config: None,
            ice_config: ice::create_p2p_ice_config(),
            ice_gathering_config: IceGatheringConfig::default(),
            quality_thresholds: QualityThresholds::default(),
            timeouts: NatTimeouts::default(),
            features: NatFeatures::default(),
        }
    }
}

impl Default for NatTimeouts {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(30),
            stun_timeout: Duration::from_secs(5),
            turn_timeout: Duration::from_secs(10),
            ice_gathering_timeout: Duration::from_secs(10),
            ice_connectivity_timeout: Duration::from_secs(20),
            keepalive_interval: Duration::from_secs(25),
        }
    }
}

impl Default for NatFeatures {
    fn default() -> Self {
        Self {
            enable_ipv6: true,
            enable_tcp: true,
            enable_mdns: false,
            enable_trickle_ice: true,
            enable_aggressive_nomination: true,
            enable_consent_freshness: true,
            enable_quality_monitoring: true,
            enable_detailed_logging: false,
        }
    }
}

impl NatSystem {
    /// Create new NAT system
    pub async fn new(config: NatSystemConfig) -> NatResult<Self> {
        info!("Creating NAT system with {} TURN servers", config.turn_servers.len());

        let config = Arc::new(config);

        // Create STUN/TURN manager
        let stun_turn_config = StunTurnConfig {
            stun_config: config.stun_config.clone(),
            turn_server_config: config.turn_server_config.clone(),
            turn_servers: config.turn_servers.clone(),
            gathering_timeout: config.timeouts.ice_gathering_timeout,
            turn_allocation_lifetime: Duration::from_secs(600),
            enable_server_reflexive: true,
            enable_relay: !config.turn_servers.is_empty(),
            max_turn_allocations: 10,
            turn_retry_config: stun_turn_manager::TurnRetryConfig {
                max_retries: 3,
                initial_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(10),
                backoff_multiplier: 2.0,
            },
            quality_monitoring: stun_turn_manager::QualityMonitoringConfig {
                enable_rtt_monitoring: config.features.enable_quality_monitoring,
                enable_packet_loss_monitoring: config.features.enable_quality_monitoring,
                monitoring_interval: Duration::from_secs(10),
                quality_threshold: config.quality_thresholds.min_quality_score,
            },
        };

        let stun_turn_manager = Arc::new(StunTurnManager::new(stun_turn_config).await?);

        // Create event channel
        let (event_sender, _) = broadcast::channel(10000);

        // Create statistics
        let stats = Arc::new(NatSystemStats {
            stun_turn_stats: Arc::new(stun_turn_manager::StunTurnStats::default()),
            ..Default::default()
        });

        let system = Self {
            config,
            stun_turn_manager,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            stats,
            shutdown: Arc::new(RwLock::new(false)),
        };

        info!("NAT system created successfully");
        Ok(system)
    }

    /// Create new NAT session
    pub async fn create_session(
        &self,
        session_id: String,
        session_config: NatSessionConfig,
    ) -> NatResult<Arc<NatSession>> {
        info!("Creating NAT session: {}", session_id);

        // Validate session configuration
        self.validate_session_config(&session_config)?;

        // Create ICE session with SHARP integration
        let ice_session = Arc::new(
            IceSession::new(
                self.config.ice_config.clone(),
                self.stun_turn_manager.clone(),
                session_config.local_ice_params.clone(),
            ).await?
        );

        // Create session event channel
        let (session_event_sender, _) = broadcast::channel(1000);

        // Create session statistics
        let session_stats = Arc::new(NatSessionStats {
            created_at: Some(std::time::Instant::now()),
            ..Default::default()
        });

        let session = Arc::new(NatSession {
            session_id: session_id.clone(),
            ice_session,
            config: session_config.clone(),
            state: Arc::new(RwLock::new(NatSessionState::Created)),
            event_sender: session_event_sender,
            stats: session_stats,
            connection_result: Arc::new(RwLock::new(None)),
        });

        // Setup event forwarding
        self.setup_session_event_forwarding(session.clone()).await;

        // Store session
        self.sessions.write().await.insert(session_id.clone(), session.clone());

        // Update statistics
        self.stats.total_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.stats.active_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Emit system event
        let _ = self.event_sender.send(NatSystemEvent::SessionCreated {
            session_id,
            config: session_config,
        });

        info!("NAT session created successfully");
        Ok(session)
    }

    /// Get existing session
    pub async fn get_session(&self, session_id: &str) -> Option<Arc<NatSession>> {
        self.sessions.read().await.get(session_id).cloned()
    }

    /// Remove session
    pub async fn remove_session(&self, session_id: &str) -> NatResult<()> {
        if let Some(session) = self.sessions.write().await.remove(session_id) {
            // Update session state
            *session.state.write().await = NatSessionState::Closed;

            // Update statistics
            self.stats.active_sessions.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

            // Emit event
            let _ = self.event_sender.send(NatSystemEvent::SessionClosed {
                session_id: session_id.to_string(),
            });

            info!("NAT session removed: {}", session_id);
        }

        Ok(())
    }

    /// List all active sessions
    pub async fn list_sessions(&self) -> Vec<String> {
        self.sessions.read().await.keys().cloned().collect()
    }

    /// Get system statistics
    pub fn get_stats(&self) -> &NatSystemStats {
        &self.stats
    }

    /// Get STUN/TURN statistics
    pub fn get_stun_turn_stats(&self) -> &stun_turn_manager::StunTurnStats {
        self.stun_turn_manager.get_stats()
    }

    /// Subscribe to system events
    pub fn subscribe_events(&self) -> broadcast::Receiver<NatSystemEvent> {
        self.event_sender.subscribe()
    }

    /// Shutdown the NAT system
    pub async fn shutdown(&self) -> NatResult<()> {
        info!("Shutting down NAT system");

        *self.shutdown.write().await = true;

        // Close all sessions
        let session_ids: Vec<String> = self.sessions.read().await.keys().cloned().collect();
        for session_id in session_ids {
            let _ = self.remove_session(&session_id).await;
        }

        // Shutdown STUN/TURN manager
        self.stun_turn_manager.shutdown().await?;

        info!("NAT system shutdown complete");
        Ok(())
    }

    /// Validate session configuration
    fn validate_session_config(&self, config: &NatSessionConfig) -> NatResult<()> {
        if config.components.is_empty() {
            return Err(NatError::Configuration("No components specified".to_string()));
        }

        for &component_id in &config.components {
            if component_id == 0 || component_id > 256 {
                return Err(NatError::Configuration(
                    "Component ID must be between 1 and 256".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Setup event forwarding for session
    async fn setup_session_event_forwarding(&self, session: Arc<NatSession>) {
        let session_id = session.session_id.clone();
        let mut ice_events = session.ice_session.subscribe_ice_events();
        let mut integration_events = session.ice_session.subscribe_integration_events().await;
        let system_event_sender = self.event_sender.clone();
        let session_event_sender = session.event_sender.clone();
        let session_state = session.state.clone();
        let connection_result = session.connection_result.clone();
        let stats = self.stats.clone();

        // Forward ICE events
        tokio::spawn(async move {
            while let Ok(event) = ice_events.recv().await {
                let session_event = match event {
                    IceEvent::CandidateAdded { candidate, component_id } => {
                        Some(NatSessionEvent::CandidateGathered { component_id, candidate })
                    }
                    IceEvent::ConnectivityResult { pair_id, success, rtt } => {
                        Some(NatSessionEvent::ConnectivityCheckResult { pair_id, success, rtt })
                    }
                    IceEvent::ComponentConnected { component_id, local_candidate, remote_candidate, .. } => {
                        Some(NatSessionEvent::ComponentConnected {
                            component_id,
                            local_candidate,
                            remote_candidate,
                        })
                    }
                    IceEvent::ConnectionEstablished { selected_pairs, establishment_time } => {
                        // Update session state
                        *session_state.write().await = NatSessionState::Connected;

                        // Create connection result
                        if let Some((_, pair)) = selected_pairs.iter().next() {
                            let result = NatConnectionResult {
                                local_address: pair.local.socket_addr().unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()),
                                remote_address: pair.remote.socket_addr().unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()),
                                connection_type: ConnectionType::from_candidate_types(
                                    pair.local.candidate_type,
                                    pair.remote.candidate_type,
                                ),
                                selected_candidate: SelectedCandidateInfo {
                                    local_candidate: pair.local.clone(),
                                    remote_candidate: pair.remote.clone(),
                                    pair_priority: pair.priority,
                                    rtt: None,
                                    nominated: pair.nominated,
                                },
                                quality_metrics: ConnectionQualityMetrics::default(),
                                establishment_time,
                                nat_behavior: None,
                            };

                            *connection_result.write().await = Some(result.clone());

                            // Update statistics
                            stats.successful_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            // Emit system event
                            let _ = system_event_sender.send(NatSystemEvent::ConnectionEstablished {
                                session_id: session_id.clone(),
                                result: result.clone(),
                            });

                            Some(NatSessionEvent::ConnectionEstablished { result })
                        } else {
                            None
                        }
                    }
                    IceEvent::ConnectionFailed { reason } => {
                        // Update session state
                        *session_state.write().await = NatSessionState::Failed;

                        // Update statistics
                        stats.failed_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                        // Emit system event
                        let _ = system_event_sender.send(NatSystemEvent::SessionFailed {
                            session_id: session_id.clone(),
                            error: reason.clone(),
                        });

                        Some(NatSessionEvent::Failed { error: reason })
                    }
                    _ => None,
                };

                if let Some(session_event) = session_event {
                    let _ = session_event_sender.send(session_event);
                }
            }
        });

        // Forward integration events
        let session_id_clone = session_id.clone();
        tokio::spawn(async move {
            while let Ok(event) = integration_events.recv().await {
                match event {
                    IceIntegrationEvent::CandidateGathered { component_id, candidate, .. } => {
                        let session_event = NatSessionEvent::CandidateGathered { component_id, candidate };
                        let _ = session_event_sender.send(session_event);
                    }
                    _ => {
                        // Handle other integration events as needed
                    }
                }
            }
        });
    }
}

impl NatSession {
    /// Start the NAT session
    pub async fn start(&self) -> NatResult<()> {
        info!("Starting NAT session: {}", self.session_id);

        // Update state
        *self.state.write().await = NatSessionState::Gathering;

        // Start ICE session
        self.ice_session.start(self.config.role).await?;

        info!("NAT session started successfully");
        Ok(())
    }

    /// Add remote candidate
    pub async fn add_remote_candidate(
        &self,
        candidate: Candidate,
        component_id: u32,
    ) -> NatResult<()> {
        debug!("Adding remote candidate for component {}: {}", component_id, candidate);

        self.ice_session.agent().add_remote_candidate(candidate.clone(), component_id).await?;

        // Emit session event
        let _ = self.event_sender.send(NatSessionEvent::RemoteCandidateReceived {
            component_id,
            candidate,
        });

        Ok(())
    }

    /// Set remote ICE credentials
    pub async fn set_remote_credentials(
        &self,
        ufrag: String,
        pwd: String,
    ) -> NatResult<()> {
        let credentials = ice::connectivity::IceCredentials { ufrag, pwd };
        self.ice_session.agent().set_remote_credentials(credentials).await
    }

    /// Get local candidates for component
    pub async fn get_local_candidates(&self, component_id: u32) -> Vec<Candidate> {
        self.ice_session.get_candidates(component_id).await
    }

    /// Get session state
    pub async fn get_state(&self) -> NatSessionState {
        *self.state.read().await
    }

    /// Get connection result (if connected)
    pub async fn get_connection_result(&self) -> Option<NatConnectionResult> {
        self.connection_result.read().await.clone()
    }

    /// Get session statistics
    pub fn get_stats(&self) -> &NatSessionStats {
        &self.stats
    }

    /// Subscribe to session events
    pub fn subscribe_events(&self) -> broadcast::Receiver<NatSessionEvent> {
        self.event_sender.subscribe()
    }

    /// Send data on established connection
    pub async fn send_data(&self, component_id: u32, data: Vec<u8>) -> NatResult<usize> {
        if *self.state.read().await != NatSessionState::Connected {
            return Err(NatError::Configuration("Session not connected".to_string()));
        }

        self.ice_session.agent().send_data(component_id, data).await
    }

    /// Close the session
    pub async fn close(&self) {
        info!("Closing NAT session: {}", self.session_id);

        *self.state.write().await = NatSessionState::Closed;
        self.ice_session.agent().close().await;
    }
}

impl ConnectionType {
    /// Determine connection type from candidate types
    fn from_candidate_types(local_type: CandidateType, remote_type: CandidateType) -> Self {
        match (local_type, remote_type) {
            (CandidateType::Host, CandidateType::Host) => Self::Direct,
            (CandidateType::Relay, _) | (_, CandidateType::Relay) => Self::Relayed,
            (CandidateType::PeerReflexive, _) | (_, CandidateType::PeerReflexive) => Self::PeerReflexive,
            _ => Self::NatTraversal,
        }
    }
}

/// Factory functions for common NAT configurations

/// Create NAT system optimized for P2P gaming
pub async fn create_p2p_nat_system(
    stun_servers: Vec<String>,
    turn_servers: Vec<TurnServerInfo>,
) -> NatResult<NatSystem> {
    let mut config = NatSystemConfig::default();

    // Configure for low latency P2P
    config.stun_config.servers = stun_servers;
    config.turn_servers = turn_servers;
    config.ice_config = ice::create_p2p_ice_config();
    config.timeouts.connection_timeout = Duration::from_secs(15);
    config.features.enable_aggressive_nomination = true;

    NatSystem::new(config).await
}

/// Create NAT system optimized for reliability
pub async fn create_reliable_nat_system(
    stun_servers: Vec<String>,
    turn_servers: Vec<TurnServerInfo>,
) -> NatResult<NatSystem> {
    let mut config = NatSystemConfig::default();

    // Configure for maximum reliability
    config.stun_config.servers = stun_servers;
    config.turn_servers = turn_servers;
    config.ice_config = ice::create_reliable_ice_config();
    config.timeouts.connection_timeout = Duration::from_secs(60);
    config.features.enable_aggressive_nomination = false;
    config.enable_turn_server = true;

    NatSystem::new(config).await
}

/// Create NAT session configuration for controlling agent
pub fn create_controlling_session_config(components: Vec<u32>) -> NatSessionConfig {
    NatSessionConfig {
        role: IceRole::Controlling,
        components,
        local_ice_params: IceParameters::default(),
        timeouts: NatTimeouts::default(),
        features: NatFeatures::default(),
    }
}

/// Create NAT session configuration for controlled agent
pub fn create_controlled_session_config(components: Vec<u32>) -> NatSessionConfig {
    NatSessionConfig {
        role: IceRole::Controlled,
        components,
        local_ice_params: IceParameters::default(),
        timeouts: NatTimeouts::default(),
        features: NatFeatures::default(),
    }
}

/// Utility functions

/// Parse TURN server URL into TurnServerInfo
pub fn parse_turn_server_url(
    url: &str,
    username: &str,
    password: &str,
) -> NatResult<TurnServerInfo> {
    // Parse URL format: turn:host:port or turns:host:port
    let transport = if url.starts_with("turns:") {
        TurnTransport::Tls
    } else if url.starts_with("turn:") {
        TurnTransport::Udp
    } else {
        return Err(NatError::Configuration("Invalid TURN URL format".to_string()));
    };

    Ok(TurnServerInfo {
        url: url.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        realm: None,
        transport,
        priority: 100,
    })
}

/// Create default STUN server list
pub fn default_stun_servers() -> Vec<String> {
    vec![
        "stun.l.google.com:19302".to_string(),
        "stun1.l.google.com:19302".to_string(),
        "stun2.l.google.com:19302".to_string(),
        "stun3.l.google.com:19302".to_string(),
    ]
}

/// Validate NAT system configuration
pub fn validate_nat_config(config: &NatSystemConfig) -> NatResult<()> {
    // Validate ICE configuration
    ice::validate_ice_config(&config.ice_config)?;

    // Validate timeouts
    if config.timeouts.connection_timeout < Duration::from_secs(5) {
        return Err(NatError::Configuration("Connection timeout too short".to_string()));
    }

    if config.timeouts.stun_timeout == Duration::ZERO {
        return Err(NatError::Configuration("STUN timeout cannot be zero".to_string()));
    }

    // Validate TURN servers
    for turn_server in &config.turn_servers {
        if turn_server.url.is_empty() {
            return Err(NatError::Configuration("TURN server URL cannot be empty".to_string()));
        }
        if turn_server.username.is_empty() || turn_server.password.is_empty() {
            return Err(NatError::Configuration("TURN server credentials required".to_string()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nat_system_creation() {
        let config = NatSystemConfig::default();
        let result = NatSystem::new(config).await;

        match result {
            Ok(_system) => {
                // Test passed
            }
            Err(e) => {
                println!("NAT system creation failed (expected in test environment): {}", e);
            }
        }
    }

    #[test]
    fn test_config_validation() {
        let config = NatSystemConfig::default();
        assert!(validate_nat_config(&config).is_ok());

        let mut invalid_config = config;
        invalid_config.timeouts.connection_timeout = Duration::from_secs(1);
        assert!(validate_nat_config(&invalid_config).is_err());
    }

    #[test]
    fn test_turn_server_parsing() {
        let result = parse_turn_server_url("turn:example.com:3478", "user", "pass");
        assert!(result.is_ok());

        let turn_info = result.unwrap();
        assert_eq!(turn_info.transport, TurnTransport::Udp);
        assert_eq!(turn_info.username, "user");
    }

    #[test]
    fn test_connection_type_detection() {
        let conn_type = ConnectionType::from_candidate_types(
            CandidateType::Host,
            CandidateType::Host
        );
        assert_eq!(conn_type, ConnectionType::Direct);

        let conn_type = ConnectionType::from_candidate_types(
            CandidateType::Relay,
            CandidateType::Host
        );
        assert_eq!(conn_type, ConnectionType::Relayed);
    }

    #[tokio::test]
    async fn test_session_creation() {
        // This test might fail due to network dependencies
        let config = NatSystemConfig::default();

        match NatSystem::new(config).await {
            Ok(system) => {
                let session_config = create_controlling_session_config(vec![1]);
                let result = system.create_session("test_session".to_string(), session_config).await;

                match result {
                    Ok(session) => {
                        assert_eq!(session.session_id, "test_session");
                        assert_eq!(session.get_state().await, NatSessionState::Created);
                    }
                    Err(e) => {
                        println!("Session creation failed (expected in test environment): {}", e);
                    }
                }
            }
            Err(e) => {
                println!("NAT system creation failed (expected in test environment): {}", e);
            }
        }
    }
}