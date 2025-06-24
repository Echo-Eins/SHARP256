// src/nat/stun_turn_manager.rs
//! STUN/TURN Integration Manager
//!
//! This module provides a unified interface for STUN and TURN operations,
//! coordinating between STUN client for NAT discovery and TURN server/client
//! for relay functionality when direct connections are not possible.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, Mutex, broadcast};
use tokio::time::{interval, timeout};
use tracing::{info, warn, debug, error, trace};
use parking_lot::RwLock as SyncRwLock;

use crate::nat::stun::{StunService, StunConfig, NatBehavior};
use crate::nat::turn::server::{TurnServer, TurnServerConfig};
use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::{Candidate, CandidateType, TransportProtocol};

/// STUN/TURN management configuration
#[derive(Debug, Clone)]
pub struct StunTurnConfig {
    /// STUN configuration
    pub stun_config: StunConfig,

    /// TURN server configuration (when running our own TURN server)
    pub turn_server_config: Option<TurnServerConfig>,

    /// External TURN servers to use
    pub turn_servers: Vec<TurnServerInfo>,

    /// Candidate gathering timeout
    pub gathering_timeout: Duration,

    /// TURN allocation lifetime
    pub turn_allocation_lifetime: Duration,

    /// Enable server reflexive candidate gathering via STUN
    pub enable_server_reflexive: bool,

    /// Enable relay candidate gathering via TURN
    pub enable_relay: bool,

    /// Maximum concurrent TURN allocations
    pub max_turn_allocations: usize,

    /// TURN retry configuration
    pub turn_retry_config: TurnRetryConfig,

    /// Quality monitoring configuration
    pub quality_monitoring: QualityMonitoringConfig,
}

/// TURN server information
#[derive(Debug, Clone)]
pub struct TurnServerInfo {
    pub url: String,
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
    pub transport: TurnTransport,
    pub priority: u32,
}

/// TURN transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnTransport {
    Udp,
    Tcp,
    Tls,
    Dtls,
}

/// TURN retry configuration
#[derive(Debug, Clone)]
pub struct TurnRetryConfig {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

/// Quality monitoring configuration
#[derive(Debug, Clone)]
pub struct QualityMonitoringConfig {
    pub enable_rtt_monitoring: bool,
    pub enable_packet_loss_monitoring: bool,
    pub monitoring_interval: Duration,
    pub quality_threshold: f64,
}

/// Candidate gathering request
#[derive(Debug, Clone)]
pub struct CandidateGatheringRequest {
    pub component_id: u32,
    pub local_socket: Arc<UdpSocket>,
    pub gather_server_reflexive: bool,
    pub gather_relay: bool,
    pub preferred_turn_servers: Vec<String>,
}

/// Candidate gathering result
#[derive(Debug)]
pub struct CandidateGatheringResult {
    pub server_reflexive_candidates: Vec<Candidate>,
    pub relay_candidates: Vec<Candidate>,
    pub gathering_duration: Duration,
    pub nat_behavior: Option<NatBehavior>,
    pub turn_allocations: Vec<TurnAllocationInfo>,
}

/// TURN allocation information
#[derive(Debug, Clone)]
pub struct TurnAllocationInfo {
    pub allocation_id: String,
    pub server_url: String,
    pub relay_address: SocketAddr,
    pub allocated_at: Instant,
    pub expires_at: Instant,
    pub username: String,
    pub quality_metrics: ConnectionQualityMetrics,
}

/// Connection quality metrics
#[derive(Debug, Clone, Default)]
pub struct ConnectionQualityMetrics {
    pub rtt: Option<Duration>,
    pub packet_loss_rate: f64,
    pub bandwidth_estimate: Option<u64>,
    pub jitter: Option<Duration>,
    pub last_updated: Option<Instant>,
}

/// STUN/TURN unified manager
pub struct StunTurnManager {
    /// Configuration
    config: Arc<StunTurnConfig>,

    /// STUN service for NAT discovery and server reflexive candidates
    stun_service: Arc<StunService>,

    /// Optional TURN server (if we're running our own)
    turn_server: Option<Arc<TurnServer>>,

    /// Active TURN allocations
    turn_allocations: Arc<RwLock<HashMap<String, TurnAllocationInfo>>>,

    /// TURN client connections
    turn_clients: Arc<RwLock<HashMap<String, Arc<TurnClient>>>>,

    /// NAT behavior cache
    nat_behavior_cache: Arc<RwLock<HashMap<SocketAddr, (NatBehavior, Instant)>>>,

    /// Quality monitoring
    quality_monitor: Arc<QualityMonitor>,

    /// Statistics
    stats: Arc<StunTurnStats>,

    /// Event broadcasting
    event_tx: broadcast::Sender<StunTurnEvent>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,

    /// Background tasks
    background_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

/// TURN client for external TURN servers
#[derive(Debug)]
pub struct TurnClient {
    pub server_info: TurnServerInfo,
    pub socket: Arc<UdpSocket>,
    pub allocations: Arc<SyncRwLock<HashMap<u32, TurnAllocation>>>, // component_id -> allocation
    pub quality_metrics: Arc<SyncRwLock<ConnectionQualityMetrics>>,
    pub last_used: Arc<SyncRwLock<Instant>>,
}

/// Individual TURN allocation
#[derive(Debug)]
pub struct TurnAllocation {
    pub component_id: u32,
    pub relay_address: SocketAddr,
    pub allocated_at: Instant,
    pub expires_at: Instant,
    pub refresh_timer: Option<tokio::task::JoinHandle<()>>,
}

/// Quality monitor for connection assessment
pub struct QualityMonitor {
    config: QualityMonitoringConfig,
    measurements: Arc<RwLock<HashMap<String, QualityMeasurement>>>,
    monitor_interval: Mutex<Option<tokio::time::Interval>>,
}

/// Quality measurement data
#[derive(Debug, Clone)]
pub struct QualityMeasurement {
    pub target: String,
    pub metrics: ConnectionQualityMetrics,
    pub measurement_history: Vec<(Instant, ConnectionQualityMetrics)>,
}

/// STUN/TURN statistics
#[derive(Debug, Default)]
pub struct StunTurnStats {
    /// STUN operations
    pub stun_requests: std::sync::atomic::AtomicU64,
    pub stun_successes: std::sync::atomic::AtomicU64,
    pub stun_failures: std::sync::atomic::AtomicU64,

    /// TURN operations
    pub turn_allocations: std::sync::atomic::AtomicU64,
    pub turn_allocation_failures: std::sync::atomic::AtomicU64,
    pub active_turn_allocations: std::sync::atomic::AtomicU64,

    /// Candidate gathering
    pub server_reflexive_candidates: std::sync::atomic::AtomicU64,
    pub relay_candidates: std::sync::atomic::AtomicU64,
    pub gathering_failures: std::sync::atomic::AtomicU64,

    /// Quality metrics
    pub average_rtt: std::sync::atomic::AtomicU64, // microseconds
    pub packet_loss_rate: std::sync::atomic::AtomicU64, // percentage * 1000
}

/// Events emitted by the STUN/TURN manager
#[derive(Debug, Clone)]
pub enum StunTurnEvent {
    /// NAT behavior discovered
    NatBehaviorDiscovered {
        local_addr: SocketAddr,
        behavior: NatBehavior,
    },

    /// Server reflexive candidate gathered
    ServerReflexiveCandidateGathered {
        component_id: u32,
        candidate: Candidate,
    },

    /// Relay candidate gathered
    RelayCandidateGathered {
        component_id: u32,
        candidate: Candidate,
        turn_server: String,
    },

    /// TURN allocation created
    TurnAllocationCreated {
        allocation_id: String,
        server_url: String,
        relay_address: SocketAddr,
    },

    /// TURN allocation failed
    TurnAllocationFailed {
        server_url: String,
        error: String,
    },

    /// Connection quality changed
    ConnectionQualityChanged {
        target: String,
        old_quality: f64,
        new_quality: f64,
    },
}

impl Default for StunTurnConfig {
    fn default() -> Self {
        Self {
            stun_config: StunConfig::default(),
            turn_server_config: None,
            turn_servers: Vec::new(),
            gathering_timeout: Duration::from_secs(30),
            turn_allocation_lifetime: Duration::from_secs(600),
            enable_server_reflexive: true,
            enable_relay: true,
            max_turn_allocations: 10,
            turn_retry_config: TurnRetryConfig {
                max_retries: 3,
                initial_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(10),
                backoff_multiplier: 2.0,
            },
            quality_monitoring: QualityMonitoringConfig {
                enable_rtt_monitoring: true,
                enable_packet_loss_monitoring: true,
                monitoring_interval: Duration::from_secs(10),
                quality_threshold: 0.8,
            },
        }
    }
}

impl StunTurnManager {
    /// Create new STUN/TURN manager
    pub async fn new(config: StunTurnConfig) -> NatResult<Self> {
        info!("Creating STUN/TURN manager with {} TURN servers", config.turn_servers.len());

        let config = Arc::new(config);

        // Create STUN service
        let stun_service = Arc::new(StunService::with_config(config.stun_config.clone()));

        // Optionally create TURN server
        let turn_server = if let Some(ref turn_config) = config.turn_server_config {
            info!("Starting integrated TURN server");
            let server = TurnServer::new(turn_config.clone()).await?;
            server.start().await?;
            Some(Arc::new(server))
        } else {
            None
        };

        // Create quality monitor
        let quality_monitor = Arc::new(QualityMonitor::new(config.quality_monitoring.clone()));

        // Create event channel
        let (event_tx, _) = broadcast::channel(1000);

        let manager = Self {
            config: config.clone(),
            stun_service,
            turn_server,
            turn_allocations: Arc::new(RwLock::new(HashMap::new())),
            turn_clients: Arc::new(RwLock::new(HashMap::new())),
            nat_behavior_cache: Arc::new(RwLock::new(HashMap::new())),
            quality_monitor,
            stats: Arc::new(StunTurnStats::default()),
            event_tx,
            shutdown: Arc::new(RwLock::new(false)),
            background_tasks: Arc::new(Mutex::new(Vec::new())),
        };

        // Start background tasks
        manager.start_background_tasks().await?;

        Ok(manager)
    }

    /// Get server reflexive candidate via STUN
    pub async fn get_server_reflexive_candidate(
        &self,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> NatResult<Option<Candidate>> {
        if !self.config.enable_server_reflexive {
            return Ok(None);
        }

        debug!("Gathering server reflexive candidate for component {}", component_id);

        let start_time = Instant::now();
        self.stats.stun_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        match timeout(
            self.config.gathering_timeout / 2, // Use half timeout for STUN
            self.stun_service.get_public_address(&socket)
        ).await {
            Ok(Ok(public_addr)) => {
                let gathering_duration = start_time.elapsed();
                self.stats.stun_successes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let local_addr = socket.local_addr()?;

                let candidate = Candidate {
                    foundation: crate::nat::ice::foundation::calculate_server_reflexive_foundation(
                        &local_addr, &public_addr
                    ),
                    component_id,
                    transport: TransportProtocol::Udp,
                    priority: crate::nat::ice::priority::calculate_priority(
                        CandidateType::ServerReflexive,
                        local_addr.is_ipv4(),
                        component_id,
                    ),
                    candidate_type: CandidateType::ServerReflexive,
                    address: crate::nat::ice::CandidateAddress::Resolved {
                        addr: public_addr,
                        base_addr: Some(local_addr),
                    },
                    related_address: Some(local_addr),
                    tcp_type: None,
                    extensions: crate::nat::ice::CandidateExtensions::default(),
                };

                info!("Gathered server reflexive candidate: {} -> {} ({}ms)",
                     local_addr, public_addr, gathering_duration.as_millis());

                // Cache NAT behavior
                if let Ok((_, behavior)) = self.stun_service.detect_nat_type(&socket).await {
                    let mut cache = self.nat_behavior_cache.write().await;
                    cache.insert(local_addr, (behavior.clone(), Instant::now()));

                    let _ = self.event_tx.send(StunTurnEvent::NatBehaviorDiscovered {
                        local_addr,
                        behavior,
                    });
                }

                self.stats.server_reflexive_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let _ = self.event_tx.send(StunTurnEvent::ServerReflexiveCandidateGathered {
                    component_id,
                    candidate: candidate.clone(),
                });

                Ok(Some(candidate))
            }
            Ok(Err(e)) => {
                warn!("STUN request failed: {}", e);
                self.stats.stun_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(None)
            }
            Err(_) => {
                warn!("STUN request timed out");
                self.stats.stun_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(None)
            }
        }
    }

    /// Get relay candidate via TURN
    pub async fn get_relay_candidate(
        &self,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> NatResult<Option<Candidate>> {
        if !self.config.enable_relay || self.config.turn_servers.is_empty() {
            return Ok(None);
        }

        debug!("Gathering relay candidate for component {}", component_id);

        // Try TURN servers in priority order
        let mut turn_servers = self.config.turn_servers.clone();
        turn_servers.sort_by_key(|s| std::cmp::Reverse(s.priority));

        for turn_server in turn_servers {
            if let Some(candidate) = self.try_turn_server(&turn_server, socket.clone(), component_id).await? {
                return Ok(Some(candidate));
            }
        }

        self.stats.gathering_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(None)
    }

    /// Gather all candidates for a component
    pub async fn gather_candidates(&self, request: CandidateGatheringRequest) -> NatResult<CandidateGatheringResult> {
        let start_time = Instant::now();
        let mut server_reflexive_candidates = Vec::new();
        let mut relay_candidates = Vec::new();
        let mut turn_allocations = Vec::new();
        let mut nat_behavior = None;

        info!("Gathering candidates for component {} (server_reflexive: {}, relay: {})",
             request.component_id, request.gather_server_reflexive, request.gather_relay);

        // Gather server reflexive candidate
        if request.gather_server_reflexive {
            if let Some(candidate) = self.get_server_reflexive_candidate(
                request.local_socket.clone(),
                request.component_id
            ).await? {
                server_reflexive_candidates.push(candidate);
            }

            // Get NAT behavior from cache
            let local_addr = request.local_socket.local_addr()?;
            if let Some((behavior, _)) = self.nat_behavior_cache.read().await.get(&local_addr) {
                nat_behavior = Some(behavior.clone());
            }
        }

        // Gather relay candidates
        if request.gather_relay {
            if let Some(candidate) = self.get_relay_candidate(
                request.local_socket.clone(),
                request.component_id
            ).await? {
                relay_candidates.push(candidate);

                // Get TURN allocation info
                if let Some(allocation) = self.turn_allocations.read().await.values().next() {
                    turn_allocations.push(allocation.clone());
                }
            }
        }

        let gathering_duration = start_time.elapsed();

        info!("Candidate gathering completed in {}ms: {} server reflexive, {} relay",
             gathering_duration.as_millis(),
             server_reflexive_candidates.len(),
             relay_candidates.len());

        Ok(CandidateGatheringResult {
            server_reflexive_candidates,
            relay_candidates,
            gathering_duration,
            nat_behavior,
            turn_allocations,
        })
    }

    /// Try to allocate from a specific TURN server
    async fn try_turn_server(
        &self,
        turn_server: &TurnServerInfo,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> NatResult<Option<Candidate>> {
        debug!("Trying TURN server: {}", turn_server.url);

        let start_time = Instant::now();
        self.stats.turn_allocations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Get or create TURN client for this server
        let turn_client = self.get_or_create_turn_client(turn_server, socket).await?;

        // Attempt allocation
        match timeout(
            self.config.gathering_timeout / 2,
            turn_client.allocate(component_id, self.config.turn_allocation_lifetime)
        ).await {
            Ok(Ok(allocation)) => {
                let allocation_duration = start_time.elapsed();

                let candidate = Candidate {
                    foundation: crate::nat::ice::foundation::calculate_relay_foundation(
                        &allocation.relay_address, &turn_server.url
                    ),
                    component_id,
                    transport: match turn_server.transport {
                        TurnTransport::Udp => TransportProtocol::Udp,
                        TurnTransport::Tcp => TransportProtocol::Tcp,
                        TurnTransport::Tls => TransportProtocol::Tcp,
                        TurnTransport::Dtls => TransportProtocol::Udp,
                    },
                    priority: crate::nat::ice::priority::calculate_priority(
                        CandidateType::Relay,
                        allocation.relay_address.is_ipv4(),
                        component_id,
                    ),
                    candidate_type: CandidateType::Relay,
                    address: crate::nat::ice::CandidateAddress::Resolved {
                        addr: allocation.relay_address,
                        base_addr: Some(socket.local_addr()?),
                    },
                    related_address: Some(socket.local_addr()?),
                    tcp_type: None,
                    extensions: crate::nat::ice::CandidateExtensions::default(),
                };

                // Store allocation info
                let allocation_info = TurnAllocationInfo {
                    allocation_id: format!("{}:{}", turn_server.url, component_id),
                    server_url: turn_server.url.clone(),
                    relay_address: allocation.relay_address,
                    allocated_at: allocation.allocated_at,
                    expires_at: allocation.expires_at,
                    username: turn_server.username.clone(),
                    quality_metrics: ConnectionQualityMetrics::default(),
                };

                self.turn_allocations.write().await.insert(
                    allocation_info.allocation_id.clone(),
                    allocation_info.clone()
                );

                self.stats.active_turn_allocations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.stats.relay_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                info!("TURN allocation successful: {} -> {} ({}ms)",
                     socket.local_addr()?, allocation.relay_address, allocation_duration.as_millis());

                let _ = self.event_tx.send(StunTurnEvent::TurnAllocationCreated {
                    allocation_id: allocation_info.allocation_id,
                    server_url: turn_server.url.clone(),
                    relay_address: allocation.relay_address,
                });

                let _ = self.event_tx.send(StunTurnEvent::RelayCandidateGathered {
                    component_id,
                    candidate: candidate.clone(),
                    turn_server: turn_server.url.clone(),
                });

                Ok(Some(candidate))
            }
            Ok(Err(e)) => {
                warn!("TURN allocation failed for {}: {}", turn_server.url, e);
                self.stats.turn_allocation_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let _ = self.event_tx.send(StunTurnEvent::TurnAllocationFailed {
                    server_url: turn_server.url.clone(),
                    error: e.to_string(),
                });

                Ok(None)
            }
            Err(_) => {
                warn!("TURN allocation timed out for {}", turn_server.url);
                self.stats.turn_allocation_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let _ = self.event_tx.send(StunTurnEvent::TurnAllocationFailed {
                    server_url: turn_server.url.clone(),
                    error: "Timeout".to_string(),
                });

                Ok(None)
            }
        }
    }

    /// Get or create TURN client for server
    async fn get_or_create_turn_client(
        &self,
        turn_server: &TurnServerInfo,
        socket: Arc<UdpSocket>,
    ) -> NatResult<Arc<TurnClient>> {
        let mut clients = self.turn_clients.write().await;

        if let Some(client) = clients.get(&turn_server.url) {
            // Update last used timestamp
            *client.last_used.write() = Instant::now();
            return Ok(client.clone());
        }

        // Create new client
        let client = Arc::new(TurnClient {
            server_info: turn_server.clone(),
            socket,
            allocations: Arc::new(SyncRwLock::new(HashMap::new())),
            quality_metrics: Arc::new(SyncRwLock::new(ConnectionQualityMetrics::default())),
            last_used: Arc::new(SyncRwLock::new(Instant::now())),
        });

        clients.insert(turn_server.url.clone(), client.clone());

        info!("Created TURN client for {}", turn_server.url);
        Ok(client)
    }

    /// Get NAT behavior for a local address
    pub async fn get_nat_behavior(&self, local_addr: SocketAddr) -> Option<NatBehavior> {
        self.nat_behavior_cache.read().await
            .get(&local_addr)
            .map(|(behavior, _)| behavior.clone())
    }

    /// Get connection quality for a target
    pub async fn get_connection_quality(&self, target: &str) -> Option<ConnectionQualityMetrics> {
        self.quality_monitor.get_quality(target).await
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> broadcast::Receiver<StunTurnEvent> {
        self.event_tx.subscribe()
    }

    /// Get statistics
    pub fn get_stats(&self) -> &StunTurnStats {
        &self.stats
    }

    /// Start background tasks
    async fn start_background_tasks(&self) -> NatResult<()> {
        let mut tasks = self.background_tasks.lock().await;

        // Quality monitoring task
        if self.config.quality_monitoring.enable_rtt_monitoring {
            let quality_monitor = self.quality_monitor.clone();
            let shutdown = self.shutdown.clone();

            let task = tokio::spawn(async move {
                let mut interval = interval(quality_monitor.config.monitoring_interval);

                loop {
                    if *shutdown.read().await {
                        break;
                    }

                    interval.tick().await;
                    quality_monitor.perform_measurements().await;
                }
            });

            tasks.push(task);
        }

        // Allocation refresh task
        {
            let turn_allocations = self.turn_allocations.clone();
            let turn_clients = self.turn_clients.clone();
            let shutdown = self.shutdown.clone();

            let task = tokio::spawn(async move {
                let mut interval = interval(Duration::from_secs(60));

                loop {
                    if *shutdown.read().await {
                        break;
                    }

                    interval.tick().await;

                    // Refresh expiring allocations
                    let allocations = turn_allocations.read().await;
                    let now = Instant::now();

                    for allocation in allocations.values() {
                        let time_until_expiry = allocation.expires_at.saturating_duration_since(now);

                        // Refresh if expiring within 2 minutes
                        if time_until_expiry < Duration::from_secs(120) {
                            // Find corresponding client and refresh
                            if let Some(client) = turn_clients.read().await.get(&allocation.server_url) {
                                let _ = client.refresh_allocations().await;
                            }
                        }
                    }
                }
            });

            tasks.push(task);
        }

        // Cleanup task
        {
            let nat_behavior_cache = self.nat_behavior_cache.clone();
            let turn_clients = self.turn_clients.clone();
            let shutdown = self.shutdown.clone();

            let task = tokio::spawn(async move {
                let mut interval = interval(Duration::from_secs(300)); // 5 minutes

                loop {
                    if *shutdown.read().await {
                        break;
                    }

                    interval.tick().await;

                    let now = Instant::now();

                    // Clean old NAT behavior cache entries
                    {
                        let mut cache = nat_behavior_cache.write().await;
                        cache.retain(|_, (_, timestamp)| {
                            now.duration_since(*timestamp) < Duration::from_secs(3600)
                        });
                    }

                    // Clean unused TURN clients
                    {
                        let mut clients = turn_clients.write().await;
                        clients.retain(|_, client| {
                            let last_used = *client.last_used.read();
                            now.duration_since(last_used) < Duration::from_secs(1800) // 30 minutes
                        });
                    }
                }
            });

            tasks.push(task);
        }

        info!("Started {} background tasks", tasks.len());
        Ok(())
    }

    /// Shutdown the manager
    pub async fn shutdown(&self) -> NatResult<()> {
        info!("Shutting down STUN/TURN manager");

        *self.shutdown.write().await = true;

        // Wait for background tasks
        let mut tasks = self.background_tasks.lock().await;
        for task in tasks.drain(..) {
            let _ = timeout(Duration::from_secs(5), task).await;
        }

        // Shutdown TURN server if running
        if let Some(ref server) = self.turn_server {
            server.shutdown().await?;
        }

        // Clean up TURN allocations
        {
            let clients = self.turn_clients.read().await;
            for client in clients.values() {
                let _ = client.deallocate_all().await;
            }
        }

        info!("STUN/TURN manager shutdown complete");
        Ok(())
    }
}

impl TurnClient {
    /// Allocate relay address for component
    pub async fn allocate(&self, component_id: u32, lifetime: Duration) -> NatResult<TurnAllocation> {
        // This is a simplified implementation
        // In reality, this would send TURN ALLOCATE request

        let relay_address = SocketAddr::new(
            "192.0.2.1".parse().unwrap(), // Example relay address
            49152 + component_id as u16
        );

        let allocation = TurnAllocation {
            component_id,
            relay_address,
            allocated_at: Instant::now(),
            expires_at: Instant::now() + lifetime,
            refresh_timer: None,
        };

        self.allocations.write().insert(component_id, allocation.clone());

        Ok(allocation)
    }

    /// Refresh all allocations
    pub async fn refresh_allocations(&self) -> NatResult<()> {
        let allocations = self.allocations.read();
        debug!("Refreshing {} TURN allocations for {}", allocations.len(), self.server_info.url);

        // In reality, would send REFRESH requests for each allocation
        for allocation in allocations.values() {
            trace!("Refreshing allocation for component {}", allocation.component_id);
        }

        Ok(())
    }

    /// Deallocate all allocations
    pub async fn deallocate_all(&self) -> NatResult<()> {
        let mut allocations = self.allocations.write();
        debug!("Deallocating {} TURN allocations for {}", allocations.len(), self.server_info.url);

        // Cancel refresh timers
        for allocation in allocations.values() {
            if let Some(ref timer) = allocation.refresh_timer {
                timer.abort();
            }
        }

        allocations.clear();
        Ok(())
    }
}

impl QualityMonitor {
    fn new(config: QualityMonitoringConfig) -> Self {
        Self {
            config,
            measurements: Arc::new(RwLock::new(HashMap::new())),
            monitor_interval: Mutex::new(None),
        }
    }

    async fn get_quality(&self, target: &str) -> Option<ConnectionQualityMetrics> {
        self.measurements.read().await
            .get(target)
            .map(|m| m.metrics.clone())
    }

    async fn perform_measurements(&self) {
        if self.config.enable_rtt_monitoring || self.config.enable_packet_loss_monitoring {
            // Perform quality measurements for active connections
            trace!("Performing connection quality measurements");

            // In reality, would measure RTT, packet loss, etc.
            // This is a placeholder
        }
    }
}

/// Factory function to create configured STUN/TURN manager
pub async fn create_stun_turn_manager(
    stun_servers: Vec<String>,
    turn_servers: Vec<TurnServerInfo>,
    enable_integrated_turn_server: bool,
) -> NatResult<StunTurnManager> {
    let mut config = StunTurnConfig::default();

    // Configure STUN
    config.stun_config.servers = stun_servers;

    // Configure TURN servers
    config.turn_servers = turn_servers;

    // Optionally enable integrated TURN server
    if enable_integrated_turn_server {
        config.turn_server_config = Some(
            crate::nat::turn::server::create_default_config("0.0.0.0:3478", "0.0.0.0")?
        );
    }

    StunTurnManager::new(config).await
}