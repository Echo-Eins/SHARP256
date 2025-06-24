// src/nat/mod.rs
//! Unified NAT Traversal System for SHARP3
//!
//! This module provides a comprehensive NAT traversal system that integrates:
//! - STUN for NAT discovery and server reflexive candidates
//! - TURN for relay functionality when direct connections fail
//! - ICE for coordinated connectivity establishment
//! - UPnP/NAT-PMP/PCP for port forwarding
//! - Advanced hole punching techniques
//!
//! The system is designed hierarchically:
//! 1. STUN/TURN Manager: Handles low-level STUN and TURN operations
//! 2. ICE Integration: Provides ICE connectivity using STUN/TURN manager
//! 3. NAT Manager: Coordinates all NAT traversal methods
//! 4. Public API: Simple interface for applications

pub mod error;
pub mod stun;
pub mod turn;
pub mod upnp;
pub mod hole_punch;
pub mod coordinator;
pub mod metrics;
pub mod port_forwarding;
pub mod stun_turn_manager;
pub mod ice;
pub mod ice_integration;

// Re-export key types for external use
pub use error::{NatError, NatResult};
pub use stun::{StunService, StunConfig, NatBehavior, MappingBehavior, FilteringBehavior};
pub use stun_turn_manager::{
    StunTurnManager, StunTurnConfig, TurnServerInfo, TurnTransport,
    CandidateGatheringRequest, CandidateGatheringResult, StunTurnEvent
};
pub use ice::{
    IceAgent, IceConfig, IceRole, IceState, IceEvent,
    Candidate, CandidateType, TransportProtocol,
    create_p2p_ice_config, create_reliable_ice_config
};
pub use ice_integration::{
    Sharp3IceIntegration, IceSession, IceParameters, IceGatheringConfig,
    QualityThresholds, IceIntegrationEvent, create_ice_session_with_sharp
};
pub use port_forwarding::{
    PortForwardingService, PortMappingConfig, Protocol as PortProtocol,
    MappingProtocol, PortMapping
};
pub use hole_punch::{HolePuncher, HolePunchConfig, CoordinatedHolePunch};

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, broadcast, Mutex};
use tokio::time::{interval, timeout};
use tracing::{info, warn, debug, error, trace};
use parking_lot::RwLock as SyncRwLock;

/// Comprehensive NAT traversal configuration
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// STUN/TURN configuration
    pub stun_turn_config: StunTurnConfig,

    /// ICE configuration
    pub ice_config: IceConfig,

    /// Port forwarding configuration
    pub port_forwarding_config: PortForwardingConfig,

    /// Hole punching configuration
    pub hole_punch_config: HolePunchConfig,

    /// Advanced NAT traversal settings
    pub advanced_config: AdvancedNatConfig,

    /// Quality and performance settings
    pub quality_config: QualityConfig,
}

/// Port forwarding configuration
#[derive(Debug, Clone)]
pub struct PortForwardingConfig {
    /// Enable UPnP-IGD
    pub enable_upnp: bool,

    /// Enable NAT-PMP
    pub enable_natpmp: bool,

    /// Enable PCP (Port Control Protocol)
    pub enable_pcp: bool,

    /// Port mapping lifetime
    pub mapping_lifetime: Duration,

    /// Auto-renewal of mappings
    pub auto_renew: bool,

    /// Preferred external port range
    pub external_port_range: Option<(u16, u16)>,
}

/// Advanced NAT traversal configuration
#[derive(Debug, Clone)]
pub struct AdvancedNatConfig {
    /// Enable coordinated hole punching
    pub enable_coordinated_hole_punch: bool,

    /// Coordinator server URL
    pub coordinator_server: Option<String>,

    /// Relay servers for symmetric NAT
    pub relay_servers: Vec<String>,

    /// Maximum concurrent traversal attempts
    pub max_concurrent_attempts: usize,

    /// Traversal timeout
    pub traversal_timeout: Duration,

    /// Retry configuration
    pub retry_config: RetryConfig,

    /// Fallback configuration
    pub fallback_config: FallbackConfig,
}

/// Quality and performance configuration
#[derive(Debug, Clone)]
pub struct QualityConfig {
    /// Enable connection quality monitoring
    pub enable_quality_monitoring: bool,

    /// Quality measurement interval
    pub measurement_interval: Duration,

    /// Quality thresholds for path selection
    pub quality_thresholds: QualityThresholds,

    /// Performance optimization settings
    pub performance_optimization: PerformanceOptimization,
}

/// Retry configuration for various operations
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    pub jitter: bool,
}

/// Fallback configuration
#[derive(Debug, Clone)]
pub struct FallbackConfig {
    /// Fallback to relay if P2P fails
    pub fallback_to_relay: bool,

    /// Relay selection strategy
    pub relay_selection: RelaySelectionStrategy,

    /// Maximum relay usage time
    pub max_relay_time: Duration,

    /// Retry P2P while using relay
    pub retry_p2p_on_relay: bool,
}

/// Relay selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySelectionStrategy {
    /// Closest geographic location
    Closest,
    /// Lowest latency
    LowestLatency,
    /// Highest bandwidth
    HighestBandwidth,
    /// Load balanced
    LoadBalanced,
    /// Random selection
    Random,
}

/// Performance optimization settings
#[derive(Debug, Clone)]
pub struct PerformanceOptimization {
    /// Parallel candidate gathering
    pub parallel_gathering: bool,

    /// Aggressive optimization for speed
    pub aggressive_optimization: bool,

    /// Bandwidth-aware selection
    pub bandwidth_aware: bool,

    /// Latency-sensitive optimization
    pub latency_sensitive: bool,
}

/// Network information and status
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    /// Local address
    pub local_addr: SocketAddr,

    /// Public address (if detected)
    pub public_addr: Option<SocketAddr>,

    /// NAT type
    pub nat_type: NatType,

    /// NAT behavior details
    pub nat_behavior: Option<NatBehavior>,

    /// Available protocols
    pub available_protocols: Vec<NatProtocol>,

    /// Port mappings
    pub port_mappings: Vec<PortMapping>,

    /// Connectivity status
    pub connectivity_status: ConnectivityStatus,

    /// Quality metrics
    pub quality_metrics: ConnectionQualityMetrics,
}

/// NAT type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT (public IP)
    None,
    /// Full Cone NAT
    FullCone,
    /// Restricted Cone NAT
    RestrictedCone,
    /// Port Restricted Cone NAT
    PortRestricted,
    /// Symmetric NAT
    Symmetric,
    /// Unknown/Not detected
    Unknown,
}

/// NAT traversal protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatProtocol {
    /// Direct connection
    Direct,
    /// STUN
    Stun,
    /// UPnP-IGD
    Upnp,
    /// NAT-PMP
    NatPmp,
    /// PCP
    Pcp,
    /// UDP hole punching
    HolePunch,
    /// TURN relay
    Turn,
    /// ICE
    Ice,
}

/// Connectivity status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityStatus {
    /// Direct internet connection
    Direct,
    /// Behind NAT but traversable
    BehindNat,
    /// Behind restrictive NAT/firewall
    Restricted,
    /// No internet connectivity
    Offline,
    /// Connection established via relay
    Relayed,
}

/// Connection quality metrics (re-exported for convenience)
pub use ice_integration::ConnectionQualityMetrics;
pub use ice_integration::QualityThresholds;

/// Main NAT traversal manager
pub struct NatManager {
    /// Configuration
    config: Arc<NatConfig>,

    /// STUN/TURN manager
    stun_turn_manager: Arc<StunTurnManager>,

    /// ICE session
    ice_session: Option<Arc<IceSession>>,

    /// Port forwarding service
    port_forwarding: Arc<RwLock<Option<PortForwardingService>>>,

    /// Hole puncher
    hole_puncher: Arc<HolePuncher>,

    /// Coordinated hole punch service
    coordinated_punch: Option<Arc<CoordinatedHolePunch>>,

    /// Network information cache
    network_info: Arc<RwLock<Option<NetworkInfo>>>,

    /// Active connections
    active_connections: Arc<RwLock<HashMap<String, ConnectionInfo>>>,

    /// Event broadcasting
    event_tx: broadcast::Sender<NatEvent>,

    /// Statistics
    stats: Arc<NatStatistics>,

    /// Quality monitor
    quality_monitor: Arc<QualityMonitor>,

    /// Background tasks
    background_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,
}

/// Information about an active connection
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub connection_id: String,
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub nat_protocol: NatProtocol,
    pub established_at: Instant,
    pub quality_metrics: ConnectionQualityMetrics,
    pub ice_state: Option<IceState>,
}

/// Quality monitor for connections
pub struct QualityMonitor {
    config: QualityConfig,
    measurements: Arc<RwLock<HashMap<String, QualityMeasurement>>>,
    monitoring_active: Arc<RwLock<bool>>,
}

/// Quality measurement data
#[derive(Debug, Clone)]
pub struct QualityMeasurement {
    pub target: String,
    pub metrics: ConnectionQualityMetrics,
    pub last_updated: Instant,
    pub trend: QualityTrend,
}

/// Quality trend indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityTrend {
    Improving,
    Stable,
    Degrading,
    Unknown,
}

/// Events emitted by the NAT manager
#[derive(Debug, Clone)]
pub enum NatEvent {
    /// Network detection completed
    NetworkDetected {
        network_info: NetworkInfo,
    },

    /// NAT traversal method succeeded
    TraversalSucceeded {
        method: NatProtocol,
        peer_addr: SocketAddr,
        duration: Duration,
    },

    /// NAT traversal method failed
    TraversalFailed {
        method: NatProtocol,
        error: String,
    },

    /// Connection established
    ConnectionEstablished {
        connection_id: String,
        peer_addr: SocketAddr,
        method: NatProtocol,
    },

    /// Connection quality changed
    QualityChanged {
        connection_id: String,
        old_quality: f64,
        new_quality: f64,
    },

    /// ICE state changed
    IceStateChanged {
        old_state: IceState,
        new_state: IceState,
    },

    /// Port mapping created
    PortMappingCreated {
        mapping: PortMapping,
    },

    /// Port mapping failed
    PortMappingFailed {
        protocol: MappingProtocol,
        error: String,
    },
}

/// NAT traversal statistics
#[derive(Debug, Default)]
pub struct NatStatistics {
    /// Detection attempts
    pub detection_attempts: std::sync::atomic::AtomicU64,
    pub detection_successes: std::sync::atomic::AtomicU64,

    /// Traversal attempts by method
    pub direct_attempts: std::sync::atomic::AtomicU64,
    pub stun_attempts: std::sync::atomic::AtomicU64,
    pub upnp_attempts: std::sync::atomic::AtomicU64,
    pub natpmp_attempts: std::sync::atomic::AtomicU64,
    pub pcp_attempts: std::sync::atomic::AtomicU64,
    pub hole_punch_attempts: std::sync::atomic::AtomicU64,
    pub turn_attempts: std::sync::atomic::AtomicU64,
    pub ice_attempts: std::sync::atomic::AtomicU64,

    /// Success rates
    pub direct_successes: std::sync::atomic::AtomicU64,
    pub stun_successes: std::sync::atomic::AtomicU64,
    pub upnp_successes: std::sync::atomic::AtomicU64,
    pub natpmp_successes: std::sync::atomic::AtomicU64,
    pub pcp_successes: std::sync::atomic::AtomicU64,
    pub hole_punch_successes: std::sync::atomic::AtomicU64,
    pub turn_successes: std::sync::atomic::AtomicU64,
    pub ice_successes: std::sync::atomic::AtomicU64,

    /// Connection statistics
    pub active_connections: std::sync::atomic::AtomicU64,
    pub total_connections: std::sync::atomic::AtomicU64,
    pub failed_connections: std::sync::atomic::AtomicU64,

    /// Performance metrics
    pub avg_connection_time: std::sync::atomic::AtomicU64, // microseconds
    pub avg_quality_score: std::sync::atomic::AtomicU64,   // * 1000
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            stun_turn_config: StunTurnConfig::default(),
            ice_config: create_p2p_ice_config(),
            port_forwarding_config: PortForwardingConfig::default(),
            hole_punch_config: HolePunchConfig::default(),
            advanced_config: AdvancedNatConfig::default(),
            quality_config: QualityConfig::default(),
        }
    }
}

impl Default for PortForwardingConfig {
    fn default() -> Self {
        Self {
            enable_upnp: true,
            enable_natpmp: true,
            enable_pcp: true,
            mapping_lifetime: Duration::from_secs(3600),
            auto_renew: true,
            external_port_range: None,
        }
    }
}

impl Default for AdvancedNatConfig {
    fn default() -> Self {
        Self {
            enable_coordinated_hole_punch: true,
            coordinator_server: None,
            relay_servers: Vec::new(),
            max_concurrent_attempts: 5,
            traversal_timeout: Duration::from_secs(30),
            retry_config: RetryConfig::default(),
            fallback_config: FallbackConfig::default(),
        }
    }
}

impl Default for QualityConfig {
    fn default() -> Self {
        Self {
            enable_quality_monitoring: true,
            measurement_interval: Duration::from_secs(10),
            quality_thresholds: QualityThresholds::default(),
            performance_optimization: PerformanceOptimization::default(),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

impl Default for FallbackConfig {
    fn default() -> Self {
        Self {
            fallback_to_relay: true,
            relay_selection: RelaySelectionStrategy::LowestLatency,
            max_relay_time: Duration::from_secs(300),
            retry_p2p_on_relay: true,
        }
    }
}

impl Default for PerformanceOptimization {
    fn default() -> Self {
        Self {
            parallel_gathering: true,
            aggressive_optimization: false,
            bandwidth_aware: true,
            latency_sensitive: true,
        }
    }
}

impl NatManager {
    /// Create new NAT manager with comprehensive configuration
    pub async fn new(config: NatConfig) -> NatResult<Self> {
        info!("Creating comprehensive NAT manager");

        let config = Arc::new(config);

        // Create STUN/TURN manager
        let stun_turn_manager = Arc::new(
            StunTurnManager::new(config.stun_turn_config.clone()).await?
        );

        // Create port forwarding service
        let port_forwarding = if config.port_forwarding_config.enable_upnp ||
            config.port_forwarding_config.enable_natpmp ||
            config.port_forwarding_config.enable_pcp {

            match PortForwardingService::new().await {
                Ok(service) => Some(service),
                Err(e) => {
                    warn!("Failed to initialize port forwarding: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Create hole puncher
        let hole_puncher = Arc::new(HolePuncher::new(config.hole_punch_config.clone()));

        // Create coordinated hole punch service if configured
        let coordinated_punch = if config.advanced_config.enable_coordinated_hole_punch {
            let coordinator_addr = config.advanced_config.coordinator_server.as_ref()
                .and_then(|s| s.parse().ok());

            if let Some(addr) = coordinator_addr {
                Some(Arc::new(CoordinatedHolePunch::new(
                    config.hole_punch_config.clone(),
                    Some(addr)
                )))
            } else {
                None
            }
        } else {
            None
        };

        // Create quality monitor
        let quality_monitor = Arc::new(QualityMonitor::new(config.quality_config.clone()));

        // Create event channel
        let (event_tx, _) = broadcast::channel(1000);

        let manager = Self {
            config: config.clone(),
            stun_turn_manager,
            ice_session: None,
            port_forwarding: Arc::new(RwLock::new(port_forwarding)),
            hole_puncher,
            coordinated_punch,
            network_info: Arc::new(RwLock::new(None)),
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            stats: Arc::new(NatStatistics::default()),
            quality_monitor,
            background_tasks: Arc::new(Mutex::new(Vec::new())),
            shutdown: Arc::new(RwLock::new(false)),
        };

        // Start background tasks
        manager.start_background_tasks().await?;

        info!("NAT manager created successfully");
        Ok(manager)
    }

    /// Initialize NAT detection and setup
    pub async fn initialize(&self, socket: &UdpSocket) -> NatResult<NetworkInfo> {
        info!("Initializing NAT detection and setup");

        self.stats.detection_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let local_addr = socket.local_addr()?;
        let start_time = Instant::now();

        // Detect network information
        let mut available_protocols = vec![NatProtocol::Direct];
        let mut public_addr = None;
        let mut nat_type = NatType::Unknown;
        let mut nat_behavior = None;
        let mut connectivity_status = ConnectivityStatus::Offline;
        let mut port_mappings = Vec::new();
        let mut quality_metrics = ConnectionQualityMetrics::default();

        // STUN detection
        if let Some(addr) = self.stun_turn_manager
            .get_server_reflexive_candidate(Arc::new(socket.try_clone()?), 1).await?
        {
            if let Some(resolved_addr) = addr.get_address() {
                public_addr = Some(resolved_addr);
                available_protocols.push(NatProtocol::Stun);
                connectivity_status = ConnectivityStatus::BehindNat;

                // Get NAT behavior
                if let Some(behavior) = self.stun_turn_manager.get_nat_behavior(local_addr).await {
                    nat_behavior = Some(behavior.clone());
                    nat_type = behavior.to_simple_nat_type();
                }
            }
        }

        // Check if we have direct connection
        if let Some(pub_addr) = public_addr {
            if pub_addr.ip() == local_addr.ip() {
                nat_type = NatType::None;
                connectivity_status = ConnectivityStatus::Direct;
            }
        }

        // Port forwarding setup (only if behind NAT)
        if nat_type != NatType::None {
            port_mappings = self.setup_port_forwarding(socket).await.unwrap_or_default();

            if !port_mappings.is_empty() {
                // Add protocols based on successful mappings
                for mapping in &port_mappings {
                    let protocol = match mapping.protocol {
                        MappingProtocol::UPnPIGD => NatProtocol::Upnp,
                        MappingProtocol::NatPMP => NatProtocol::NatPmp,
                        MappingProtocol::PCP => NatProtocol::Pcp,
                    };
                    if !available_protocols.contains(&protocol) {
                        available_protocols.push(protocol);
                    }
                }
            }

            // Enable hole punching for suitable NAT types
            if let Some(ref behavior) = nat_behavior {
                if behavior.p2p_score() > 0.3 {
                    available_protocols.push(NatProtocol::HolePunch);
                }
            }
        }

        // Check TURN availability
        if !self.config.stun_turn_config.turn_servers.is_empty() {
            available_protocols.push(NatProtocol::Turn);
        }

        // ICE is always available if configured
        available_protocols.push(NatProtocol::Ice);

        // Get initial quality metrics
        if let Some(ref addr) = public_addr {
            quality_metrics = self.stun_turn_manager
                .get_connection_quality(&addr.to_string()).await
                .unwrap_or_default();
        }

        let network_info = NetworkInfo {
            local_addr,
            public_addr,
            nat_type,
            nat_behavior,
            available_protocols,
            port_mappings,
            connectivity_status,
            quality_metrics,
        };

        // Cache network info
        *self.network_info.write().await = Some(network_info.clone());

        let detection_duration = start_time.elapsed();
        info!("NAT detection completed in {}ms: {:?} via {:?}",
             detection_duration.as_millis(),
             connectivity_status,
             available_protocols);

        self.stats.detection_successes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Emit event
        let _ = self.event_tx.send(NatEvent::NetworkDetected {
            network_info: network_info.clone(),
        });

        Ok(network_info)
    }

    /// Establish connection to peer using best available method
    pub async fn establish_connection(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        options: ConnectionOptions,
    ) -> NatResult<ConnectionInfo> {
        info!("Establishing connection to {} with options: {:?}", peer_addr, options);

        let connection_id = format!("conn_{}", uuid::Uuid::new_v4());
        let start_time = Instant::now();

        // Get network info
        let network_info = self.get_network_info().await
            .ok_or_else(|| NatError::Platform("Network not initialized".to_string()))?;

        // Try connection methods in order of preference
        let methods = self.select_traversal_methods(&network_info, &options).await;

        for method in methods {
            match self.try_connection_method(socket, peer_addr, method, &options).await {
                Ok(connection_info) => {
                    let duration = start_time.elapsed();

                    // Store connection info
                    self.active_connections.write().await.insert(
                        connection_id.clone(),
                        connection_info.clone()
                    );

                    self.stats.total_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.stats.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // Update statistics for successful method
                    self.update_method_stats(method, true).await;

                    info!("Connection established via {:?} in {}ms", method, duration.as_millis());

                    let _ = self.event_tx.send(NatEvent::ConnectionEstablished {
                        connection_id: connection_id.clone(),
                        peer_addr,
                        method,
                    });

                    let _ = self.event_tx.send(NatEvent::TraversalSucceeded {
                        method,
                        peer_addr,
                        duration,
                    });

                    return Ok(connection_info);
                }
                Err(e) => {
                    warn!("Connection via {:?} failed: {}", method, e);

                    self.update_method_stats(method, false).await;

                    let _ = self.event_tx.send(NatEvent::TraversalFailed {
                        method,
                        error: e.to_string(),
                    });
                }
            }
        }

        self.stats.failed_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Err(NatError::Platform("All connection methods failed".to_string()))
    }

    /// Create ICE session for P2P connectivity
    pub async fn create_ice_session(&mut self, socket: Arc<UdpSocket>) -> NatResult<Arc<IceSession>> {
        info!("Creating ICE session");

        // Extract STUN/TURN servers from config
        let stun_servers = self.config.stun_turn_config.stun_config.servers.clone();
        let turn_servers = self.config.stun_turn_config.turn_servers.clone();

        // Create ICE session with SHARP integration
        let ice_session = Arc::new(
            create_ice_session_with_sharp(
                self.config.ice_config.clone(),
                stun_servers,
                turn_servers,
            ).await?
        );

        // Start gathering
        ice_session.start_gathering(socket).await?;

        // Store session
        self.ice_session = Some(ice_session.clone());

        info!("ICE session created and gathering started");
        Ok(ice_session)
    }

    /// Get current network information
    pub async fn get_network_info(&self) -> Option<NetworkInfo> {
        self.network_info.read().await.clone()
    }

    /// Get connection quality for target
    pub async fn get_connection_quality(&self, target: &str) -> Option<ConnectionQualityMetrics> {
        self.quality_monitor.get_quality(target).await
    }

    /// Subscribe to NAT events
    pub fn subscribe(&self) -> broadcast::Receiver<NatEvent> {
        self.event_tx.subscribe()
    }

    /// Get statistics
    pub fn get_stats(&self) -> &NatStatistics {
        &self.stats
    }