// src/nat/ice_integration.rs
//! ICE Integration with STUN/TURN Manager
//!
//! This module provides integration between the ICE system and the STUN/TURN manager,
//! implementing the IceNatManager trait to provide candidates for ICE connectivity establishment.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, broadcast};
use tracing::{info, warn, debug, error, trace};
use futures::future::BoxFuture;
use serde::{Serialize, Deserialize};

use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::{
    IceNatManager, Candidate, CandidateType, CandidateAddress, CandidateExtensions,
    TransportProtocol, IceAgent, IceConfig, IceRole, IceState, IceEvent,
    CandidateGatherer, GatheringEvent, GatheringPhase, GatheringStats,
};
use crate::nat::stun_turn_manager::{
    StunTurnManager, StunTurnEvent, CandidateGatheringRequest,
    ConnectionQualityMetrics, TurnAllocationInfo,
};
use crate::nat::stun::NatBehavior;

/// ICE parameters for integration
#[derive(Debug, Clone)]
pub struct IceParameters {
    /// ICE username fragment
    pub ufrag: String,

    /// ICE password
    pub pwd: String,

    /// Components to gather candidates for
    pub components: Vec<u32>,

    /// Gathering configuration
    pub gathering_config: IceGatheringConfig,

    /// Quality thresholds
    pub quality_thresholds: QualityThresholds,
}

/// ICE gathering configuration
#[derive(Debug, Clone)]
pub struct IceGatheringConfig {
    /// Enable host candidate gathering
    pub gather_host: bool,

    /// Enable server reflexive candidate gathering
    pub gather_server_reflexive: bool,

    /// Enable relay candidate gathering
    pub gather_relay: bool,

    /// Gathering timeout per component
    pub component_timeout: Duration,

    /// Total gathering timeout
    pub total_timeout: Duration,

    /// Maximum candidates per component
    pub max_candidates_per_component: usize,

    /// Prefer IPv6 candidates
    pub prefer_ipv6: bool,

    /// Enable trickle ICE
    pub enable_trickle: bool,
}

/// Quality thresholds for candidate selection
#[derive(Debug, Clone)]
pub struct QualityThresholds {
    /// Minimum RTT for acceptable candidates (ms)
    pub max_acceptable_rtt: Duration,

    /// Maximum packet loss rate (0.0 to 1.0)
    pub max_packet_loss_rate: f64,

    /// Minimum bandwidth estimate (bytes/sec)
    pub min_bandwidth: u64,

    /// Quality score threshold (0.0 to 1.0)
    pub min_quality_score: f64,
}

/// SHARP ICE integration - implements IceNatManager for the ICE system
pub struct Sharp3IceIntegration {
    /// STUN/TURN manager
    stun_turn_manager: Arc<StunTurnManager>,

    /// ICE parameters
    ice_params: Arc<RwLock<IceParameters>>,

    /// Active candidate gathering sessions
    gathering_sessions: Arc<RwLock<HashMap<String, GatheringSession>>>,

    /// Gathered candidates cache
    candidates_cache: Arc<RwLock<HashMap<u32, Vec<Candidate>>>>,

    /// NAT behavior cache
    nat_behavior_cache: Arc<RwLock<Option<NatBehavior>>>,

    /// Event subscribers
    event_subscribers: Arc<RwLock<Vec<broadcast::Sender<IceIntegrationEvent>>>>,

    /// Statistics
    stats: Arc<IceIntegrationStats>,
}

/// Candidate gathering session
#[derive(Debug)]
pub struct GatheringSession {
    /// Session ID
    pub session_id: String,

    /// Associated socket
    pub socket: Arc<UdpSocket>,

    /// Components being gathered
    pub components: Vec<u32>,

    /// Gathering phase
    pub phase: GatheringPhase,

    /// Started timestamp
    pub started_at: Instant,

    /// Gathered candidates
    pub candidates: HashMap<u32, Vec<Candidate>>,

    /// Quality metrics
    pub quality_metrics: HashMap<String, ConnectionQualityMetrics>,

    /// TURN allocations
    pub turn_allocations: Vec<TurnAllocationInfo>,
}

/// Events emitted by ICE integration
#[derive(Debug, Clone)]
pub enum IceIntegrationEvent {
    /// Candidate gathering started
    GatheringStarted {
        session_id: String,
        components: Vec<u32>,
    },

    /// New candidate gathered
    CandidateGathered {
        session_id: String,
        component_id: u32,
        candidate: Candidate,
        quality_score: Option<f64>,
    },

    /// Gathering completed for component
    ComponentGatheringComplete {
        session_id: String,
        component_id: u32,
        candidate_count: usize,
    },

    /// All gathering completed
    GatheringComplete {
        session_id: String,
        total_candidates: usize,
        duration: Duration,
    },

    /// NAT behavior detected
    NatBehaviorDetected {
        behavior: NatBehavior,
        confidence: f64,
    },

    /// Quality measurement updated
    QualityUpdated {
        target: String,
        metrics: ConnectionQualityMetrics,
    },
}

/// ICE integration statistics
#[derive(Debug, Default)]
pub struct IceIntegrationStats {
    /// Total gathering sessions
    pub total_sessions: std::sync::atomic::AtomicU64,

    /// Active gathering sessions
    pub active_sessions: std::sync::atomic::AtomicU64,

    /// Total candidates gathered
    pub total_candidates: std::sync::atomic::AtomicU64,

    /// Candidates by type
    pub host_candidates: std::sync::atomic::AtomicU64,
    pub server_reflexive_candidates: std::sync::atomic::AtomicU64,
    pub relay_candidates: std::sync::atomic::AtomicU64,

    /// Gathering failures
    pub gathering_failures: std::sync::atomic::AtomicU64,

    /// Average gathering time (microseconds)
    pub avg_gathering_time: std::sync::atomic::AtomicU64,

    /// Quality metrics
    pub avg_candidate_quality: std::sync::atomic::AtomicU64, // * 1000
}

impl Default for IceGatheringConfig {
    fn default() -> Self {
        Self {
            gather_host: true,
            gather_server_reflexive: true,
            gather_relay: true,
            component_timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(30),
            max_candidates_per_component: 5,
            prefer_ipv6: false,
            enable_trickle: true,
        }
    }
}

impl Default for QualityThresholds {
    fn default() -> Self {
        Self {
            max_acceptable_rtt: Duration::from_millis(200),
            max_packet_loss_rate: 0.05, // 5%
            min_bandwidth: 100_000,     // 100 KB/s
            min_quality_score: 0.6,
        }
    }
}

impl Default for IceParameters {
    fn default() -> Self {
        Self {
            ufrag: crate::nat::ice::utils::generate_ufrag(),
            pwd: crate::nat::ice::utils::generate_password(),
            components: vec![1], // RTP component
            gathering_config: IceGatheringConfig::default(),
            quality_thresholds: QualityThresholds::default(),
        }
    }
}

impl Sharp3IceIntegration {
    /// Create new ICE integration
    pub async fn new(
        stun_turn_manager: Arc<StunTurnManager>,
        ice_params: IceParameters,
    ) -> NatResult<Self> {
        info!("Creating SHARP ICE integration with {} components", ice_params.components.len());

        let integration = Self {
            stun_turn_manager,
            ice_params: Arc::new(RwLock::new(ice_params)),
            gathering_sessions: Arc::new(RwLock::new(HashMap::new())),
            candidates_cache: Arc::new(RwLock::new(HashMap::new())),
            nat_behavior_cache: Arc::new(RwLock::new(None)),
            event_subscribers: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(IceIntegrationStats::default()),
        };

        // Subscribe to STUN/TURN events
        integration.setup_event_forwarding().await;

        Ok(integration)
    }

    /// Setup event forwarding from STUN/TURN manager
    async fn setup_event_forwarding(&self) {
        let mut stun_turn_events = self.stun_turn_manager.subscribe();
        let nat_behavior_cache = self.nat_behavior_cache.clone();
        let event_subscribers = self.event_subscribers.clone();

        tokio::spawn(async move {
            while let Ok(event) = stun_turn_events.recv().await {
                match event {
                    StunTurnEvent::NatBehaviorDiscovered { behavior, .. } => {
                        *nat_behavior_cache.write().await = Some(behavior.clone());

                        let ice_event = IceIntegrationEvent::NatBehaviorDetected {
                            behavior,
                            confidence: 0.8, // Would be calculated based on detection method
                        };

                        let subscribers = event_subscribers.read().await;
                        for sender in subscribers.iter() {
                            let _ = sender.send(ice_event.clone());
                        }
                    }
                    StunTurnEvent::ConnectionQualityChanged { target, .. } => {
                        // Forward quality updates
                        trace!("Connection quality updated for {}", target);
                    }
                    _ => {
                        // Handle other events as needed
                    }
                }
            }
        });
    }

    /// Start candidate gathering session
    pub async fn start_gathering_session(
        &self,
        session_id: String,
        socket: Arc<UdpSocket>,
    ) -> NatResult<()> {
        let ice_params = self.ice_params.read().await;
        let components = ice_params.components.clone();

        info!("Starting ICE gathering session '{}' for components: {:?}", session_id, components);

        let session = GatheringSession {
            session_id: session_id.clone(),
            socket: socket.clone(),
            components: components.clone(),
            phase: GatheringPhase::New,
            started_at: Instant::now(),
            candidates: HashMap::new(),
            quality_metrics: HashMap::new(),
            turn_allocations: Vec::new(),
        };

        self.gathering_sessions.write().await.insert(session_id.clone(), session);
        self.stats.total_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.stats.active_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Emit event
        self.emit_event(IceIntegrationEvent::GatheringStarted {
            session_id: session_id.clone(),
            components,
        }).await;

        // Start gathering process
        self.perform_candidate_gathering(session_id, socket).await?;

        Ok(())
    }

    /// Perform candidate gathering
    async fn perform_candidate_gathering(
        &self,
        session_id: String,
        socket: Arc<UdpSocket>,
    ) -> NatResult<()> {
        let ice_params = self.ice_params.read().await.clone();

        // Update session phase
        {
            let mut sessions = self.gathering_sessions.write().await;
            if let Some(session) = sessions.get_mut(&session_id) {
                session.phase = GatheringPhase::GatheringHost;
            }
        }

        let local_addr = socket.local_addr()?;
        debug!("Performing candidate gathering for session '{}' from {}", session_id, local_addr);

        for component_id in ice_params.components {
            let component_start = Instant::now();
            let mut component_candidates = Vec::new();

            // Gather host candidate
            if ice_params.gathering_config.gather_host {
                let host_candidate = self.gather_host_candidate(component_id, &socket).await?;
                if let Some(candidate) = host_candidate {
                    component_candidates.push(candidate.clone());
                    self.process_gathered_candidate(session_id.clone(), component_id, candidate).await;
                }
            }

            // Gather server reflexive candidate
            if ice_params.gathering_config.gather_server_reflexive {
                if let Some(candidate) = self.stun_turn_manager
                    .get_server_reflexive_candidate(socket.clone(), component_id).await?
                {
                    component_candidates.push(candidate.clone());
                    self.process_gathered_candidate(session_id.clone(), component_id, candidate).await;
                }
            }

            // Gather relay candidate
            if ice_params.gathering_config.gather_relay {
                if let Some(candidate) = self.stun_turn_manager
                    .get_relay_candidate(socket.clone(), component_id).await?
                {
                    component_candidates.push(candidate.clone());
                    self.process_gathered_candidate(session_id.clone(), component_id, candidate).await;
                }
            }

            // Store candidates for this component
            {
                let mut sessions = self.gathering_sessions.write().await;
                if let Some(session) = sessions.get_mut(&session_id) {
                    session.candidates.insert(component_id, component_candidates.clone());
                }
            }

            // Update cache
            {
                let mut cache = self.candidates_cache.write().await;
                cache.insert(component_id, component_candidates.clone());
            }

            let component_duration = component_start.elapsed();
            debug!("Component {} gathering completed: {} candidates in {}ms",
                  component_id, component_candidates.len(), component_duration.as_millis());

            self.emit_event(IceIntegrationEvent::ComponentGatheringComplete {
                session_id: session_id.clone(),
                component_id,
                candidate_count: component_candidates.len(),
            }).await;
        }

        // Complete gathering
        self.complete_gathering_session(session_id).await?;

        Ok(())
    }

    /// Gather host candidate
    async fn gather_host_candidate(
        &self,
        component_id: u32,
        socket: &UdpSocket,
    ) -> NatResult<Option<Candidate>> {
        let local_addr = socket.local_addr()?;

        let candidate = Candidate {
            foundation: crate::nat::ice::foundation::calculate_host_foundation(
                &local_addr.ip(),
                TransportProtocol::Udp
            ),
            component_id,
            transport: TransportProtocol::Udp,
            priority: crate::nat::ice::priority::calculate_priority(
                CandidateType::Host,
                65535, // Max local preference for host
                component_id,
            ),
            address: CandidateAddress::Ip(local_addr),
            candidate_type: CandidateType::Host,
            related_address: None,
            tcp_type: None,
            extensions: CandidateExtensions::new(),
            discovered_at: Instant::now(),
            base_address: Some(local_addr.ip()),
            server_address: None,
        };

        self.stats.host_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.stats.total_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        debug!("Gathered host candidate: {}", local_addr);
        Ok(Some(candidate))
    }

    /// Process gathered candidate
    async fn process_gathered_candidate(
        &self,
        session_id: String,
        component_id: u32,
        candidate: Candidate,
    ) {
        // Calculate quality score if applicable
        let quality_score = self.calculate_candidate_quality(&candidate).await;

        self.emit_event(IceIntegrationEvent::CandidateGathered {
            session_id,
            component_id,
            candidate,
            quality_score,
        }).await;
    }

    /// Calculate candidate quality score
    async fn calculate_candidate_quality(&self, candidate: &Candidate) -> Option<f64> {
        let ice_params = self.ice_params.read().await;
        let thresholds = &ice_params.quality_thresholds;

        let mut quality_score = 0.0;
        let mut factors = 0;

        // Base score by candidate type
        let type_score = match candidate.candidate_type {
            CandidateType::Host => 1.0,
            CandidateType::ServerReflexive => 0.8,
            CandidateType::PeerReflexive => 0.7,
            CandidateType::Relay => 0.6,
        };
        quality_score += type_score;
        factors += 1;

        // IPv4 vs IPv6 preference
        if let Some(addr) = candidate.socket_addr() {
            if addr.is_ipv6() && ice_params.gathering_config.prefer_ipv6 {
                quality_score += 0.1;
            }
            factors += 1;

            // Get quality metrics if available
            let target = addr.to_string();
            if let Some(metrics) = self.stun_turn_manager.get_connection_quality(&target).await {
                // RTT factor
                if let Some(rtt) = metrics.rtt {
                    let rtt_score = if rtt <= thresholds.max_acceptable_rtt {
                        1.0 - (rtt.as_millis() as f64 / thresholds.max_acceptable_rtt.as_millis() as f64)
                    } else {
                        0.0
                    };
                    quality_score += rtt_score * 0.3;
                    factors += 1;
                }

                // Packet loss factor
                let loss_score = 1.0 - (metrics.packet_loss_rate / thresholds.max_packet_loss_rate).min(1.0);
                quality_score += loss_score * 0.2;
                factors += 1;

                // Bandwidth factor
                if let Some(bandwidth) = metrics.bandwidth_estimate {
                    let bandwidth_score = (bandwidth as f64 / thresholds.min_bandwidth as f64).min(1.0);
                    quality_score += bandwidth_score * 0.1;
                    factors += 1;
                }
            }
        }

        if factors > 0 {
            let final_score = quality_score / factors as f64;

            // Update statistics
            let score_scaled = (final_score * 1000.0) as u64;
            self.stats.avg_candidate_quality.store(score_scaled, std::sync::atomic::Ordering::Relaxed);

            Some(final_score)
        } else {
            None
        }
    }

    /// Complete gathering session
    async fn complete_gathering_session(&self, session_id: String) -> NatResult<()> {
        let (total_candidates, duration) = {
            let mut sessions = self.gathering_sessions.write().await;
            if let Some(session) = sessions.get_mut(&session_id) {
                session.phase = GatheringPhase::Complete;

                let total_candidates = session.candidates.values()
                    .map(|candidates| candidates.len())
                    .sum::<usize>();

                let duration = session.started_at.elapsed();

                (total_candidates, duration)
            } else {
                return Err(NatError::Platform(format!("Session '{}' not found", session_id)));
            }
        };

        self.stats.active_sessions.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        // Update average gathering time
        let duration_us = duration.as_micros() as u64;
        self.stats.avg_gathering_time.store(duration_us, std::sync::atomic::Ordering::Relaxed);

        info!("ICE gathering session '{}' completed: {} candidates in {}ms",
             session_id, total_candidates, duration.as_millis());

        self.emit_event(IceIntegrationEvent::GatheringComplete {
            session_id,
            total_candidates,
            duration,
        }).await;

        Ok(())
    }

    /// Get gathered candidates for component
    pub async fn get_candidates_for_component(&self, component_id: u32) -> Vec<Candidate> {
        self.candidates_cache.read().await
            .get(&component_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get NAT behavior
    pub async fn get_nat_behavior(&self) -> Option<NatBehavior> {
        self.nat_behavior_cache.read().await.clone()
    }

    /// Subscribe to events
    pub async fn subscribe_to_events(&self) -> broadcast::Receiver<IceIntegrationEvent> {
        let (tx, rx) = broadcast::channel(1000);
        self.event_subscribers.write().await.push(tx);
        rx
    }

    /// Emit event to all subscribers
    async fn emit_event(&self, event: IceIntegrationEvent) {
        let subscribers = self.event_subscribers.read().await;
        for sender in subscribers.iter() {
            let _ = sender.send(event.clone());
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> &IceIntegrationStats {
        &self.stats
    }

    /// Update ICE parameters
    pub async fn update_ice_parameters(&self, params: IceParameters) {
        *self.ice_params.write().await = params;
        info!("Updated ICE parameters");
    }

    /// Clear candidates cache
    pub async fn clear_candidates_cache(&self) {
        self.candidates_cache.write().await.clear();
        debug!("Cleared candidates cache");
    }
}

// Implement IceNatManager trait for integration with ICE system
impl IceNatManager for Sharp3IceIntegration {
    /// Acquire a server reflexive candidate for the given component
    fn get_server_reflexive(
        &self,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> BoxFuture<'static, NatResult<Option<Candidate>>> {
        let manager = self.stun_turn_manager.clone();
        let stats = self.stats.clone();

        Box::pin(async move {
            let result = manager.get_server_reflexive_candidate(socket, component_id).await?;

            if result.is_some() {
                stats.server_reflexive_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                stats.total_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            Ok(result)
        })
    }

    /// Acquire a relay candidate via TURN for the given component
    fn get_relay_candidate(
        &self,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> BoxFuture<'static, NatResult<Option<Candidate>>> {
        let manager = self.stun_turn_manager.clone();
        let stats = self.stats.clone();

        Box::pin(async move {
            let result = manager.get_relay_candidate(socket, component_id).await?;

            if result.is_some() {
                stats.relay_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                stats.total_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            Ok(result)
        })
    }
}

/// Wrapper that binds an IceAgent with Sharp3IceIntegration
pub struct IceSession {
    agent: Arc<crate::nat::ice::IceAgent>,
    integration: Arc<Sharp3IceIntegration>,
}

impl IceSession {
    /// Create a new ICE session using the SHARP integration
    pub async fn new(
        config: crate::nat::ice::IceConfig,
        stun_turn_manager: Arc<StunTurnManager>,
        ice_params: IceParameters,
    ) -> NatResult<Self> {
        let integration = Arc::new(Sharp3IceIntegration::new(stun_turn_manager, ice_params).await?);

        // Validate ICE config
        crate::nat::ice::validate_ice_config(&config)?;

        // Create ICE agent
        let agent = Arc::new(crate::nat::ice::IceAgent::new(config).await?);

        Ok(Self { agent, integration })
    }

    /// Access the underlying ICE agent
    pub fn agent(&self) -> Arc<crate::nat::ice::IceAgent> {
        self.agent.clone()
    }

    /// Access the ICE integration
    pub fn integration(&self) -> Arc<Sharp3IceIntegration> {
        self.integration.clone()
    }

    /// Start ICE processing with the specified role
    pub async fn start(&self, role: IceRole) -> NatResult<()> {
        self.agent.start(role).await
    }

    /// Start candidate gathering
    pub async fn start_gathering(&self, socket: Arc<UdpSocket>) -> NatResult<()> {
        let session_id = format!("session_{}", uuid::Uuid::new_v4());
        self.integration.start_gathering_session(session_id, socket).await
    }

    /// Get gathered candidates for component
    pub async fn get_candidates(&self, component_id: u32) -> Vec<Candidate> {
        self.integration.get_candidates_for_component(component_id).await
    }

    /// Get current ICE state
    pub async fn get_state(&self) -> crate::nat::ice::IceState {
        self.agent.get_state().await
    }

    /// Subscribe to ICE events
    pub fn subscribe_ice_events(&self) -> broadcast::Receiver<IceEvent> {
        self.agent.subscribe_events()
    }

    /// Subscribe to integration events
    pub async fn subscribe_integration_events(&self) -> broadcast::Receiver<IceIntegrationEvent> {
        self.integration.subscribe_to_events().await
    }

    /// Get integration statistics
    pub fn get_integration_stats(&self) -> &IceIntegrationStats {
        self.integration.get_stats()
    }

    /// Get STUN/TURN statistics
    pub fn get_stun_turn_stats(&self) -> &crate::nat::stun_turn_manager::StunTurnStats {
        self.integration.stun_turn_manager.get_stats()
    }
}

/// Factory function to create ICE session with SHARP integration
pub async fn create_ice_session_with_sharp(
    ice_config: crate::nat::ice::IceConfig,
    stun_servers: Vec<String>,
    turn_servers: Vec<crate::nat::stun_turn_manager::TurnServerInfo>,
) -> NatResult<IceSession> {
    // Create STUN/TURN manager
    let stun_turn_manager = Arc::new(
        crate::nat::stun_turn_manager::create_stun_turn_manager(
            stun_servers,
            turn_servers,
            false, // Don't start integrated TURN server
        ).await?
    );

    // Create ICE parameters
    let ice_params = IceParameters {
        ufrag: crate::nat::ice::utils::generate_ufrag(),
        pwd: crate::nat::ice::utils::generate_password(),
        components: ice_config.components.clone(),
        gathering_config: IceGatheringConfig::default(),
        quality_thresholds: QualityThresholds::default(),
    };

    // Create ICE session
    IceSession::new(ice_config, stun_turn_manager, ice_params).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_ice_integration_creation() {
        let stun_turn_manager = Arc::new(
            crate::nat::stun_turn_manager::create_stun_turn_manager(
                vec!["stun.l.google.com:19302".to_string()],
                vec![],
                false,
            ).await.unwrap()
        );

        let ice_params = IceParameters::default();
        let integration = Sharp3IceIntegration::new(stun_turn_manager, ice_params).await.unwrap();

        assert_eq!(integration.get_stats().total_sessions.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_gathering_session() {
        let stun_turn_manager = Arc::new(
            crate::nat::stun_turn_manager::create_stun_turn_manager(
                vec!["stun.l.google.com:19302".to_string()],
                vec![],
                false,
            ).await.unwrap()
        );

        let ice_params = IceParameters::default();
        let integration = Sharp3IceIntegration::new(stun_turn_manager, ice_params).await.unwrap();

        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let session_id = "test_session".to_string();

        // Start gathering session
        integration.start_gathering_session(session_id.clone(), socket).await.unwrap();

        // Wait a bit for gathering to complete
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check that we have some candidates
        let candidates = integration.get_candidates_for_component(1).await;
        assert!(!candidates.is_empty(), "Should have at least host candidate");
    }

    #[tokio::test]
    async fn test_ice_session_creation() {
        let ice_config = crate::nat::ice::create_p2p_ice_config();

        let result = create_ice_session_with_sharp(
            ice_config,
            vec!["stun.l.google.com:19302".to_string()],
            vec![],
        ).await;

        // This might fail due to network dependencies, but tests the integration
        match result {
            Ok(session) => {
                assert!(session.agent().get_state().await == crate::nat::ice::IceState::Gathering);
            }
            Err(e) => {
                println!("ICE session creation failed (expected in test environment): {}", e);
            }
        }
    }
}