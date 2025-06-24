// src/nat/ice/gathering.rs
//! ICE candidate gathering implementation (RFC 8445 Section 5.1.1)
//!
//! This module handles the complete candidate gathering process including:
//! - Host candidate discovery
//! - Server reflexive candidate gathering via STUN
//! - Relay candidate allocation via TURN
//! - mDNS candidate resolution
//! - Interface monitoring and updates

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, mpsc, oneshot, broadcast};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout, interval};
use tracing::{debug, info, warn, error, trace};
use rand::{thread_rng, Rng};

use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::candidate::{
    Candidate, CandidateType, CandidateAddress, CandidateExtensions,
    TransportProtocol, TcpType, CandidateList
};
use crate::nat::ice::priority::{
    InterfaceInfo, InterfaceType, InterfaceStatus, NetworkSecurityLevel,
    calculate_local_preference_enhanced, LocalPreferenceConfig, PriorityCalculator
};
use crate::nat::stun::{Message, MessageType, TransactionId, Attribute, AttributeType, AttributeValue};

/// Gathering phase state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatheringPhase {
    /// Not started
    New,
    /// Currently gathering candidates
    Gathering,
    /// Gathering completed
    Complete,
    /// Gathering failed
    Failed,
}

/// Candidate gathering configuration
#[derive(Debug, Clone)]
pub struct GatheringConfig {
    /// Enable host candidate gathering
    pub gather_host_candidates: bool,

    /// Enable server reflexive candidate gathering
    pub gather_server_reflexive: bool,

    /// Enable relay candidate gathering
    pub gather_relay_candidates: bool,

    /// Enable mDNS candidates
    pub enable_mdns: bool,

    /// Enable IPv4 candidates
    pub enable_ipv4: bool,

    /// Enable IPv6 candidates
    pub enable_ipv6: bool,

    /// Enable TCP candidates
    pub enable_tcp: bool,

    /// Enable UDP candidates
    pub enable_udp: bool,

    /// STUN servers for server reflexive candidates
    pub stun_servers: Vec<SocketAddr>,

    /// TURN servers for relay candidates
    pub turn_servers: Vec<TurnServerConfig>,

    /// Network interface filter
    pub interface_filter: InterfaceFilter,

    /// Gathering timeout
    pub gathering_timeout: Duration,

    /// STUN request timeout
    pub stun_timeout: Duration,

    /// TURN allocation timeout
    pub turn_timeout: Duration,

    /// Maximum candidates per type
    pub max_candidates_per_type: u32,

    /// Candidate TTL for refresh
    pub candidate_ttl: Duration,

    /// Enable happy eyeballs for dual stack
    pub enable_happy_eyeballs: bool,

    /// Priority calculator configuration
    pub priority_config: LocalPreferenceConfig,
}

impl Default for GatheringConfig {
    fn default() -> Self {
        Self {
            gather_host_candidates: true,
            gather_server_reflexive: true,
            gather_relay_candidates: true,
            enable_mdns: false, // Disabled by default for security
            enable_ipv4: true,
            enable_ipv6: true,
            enable_tcp: true,
            enable_udp: true,
            stun_servers: vec![
                "stun.l.google.com:19302".parse().unwrap(),
                "stun1.l.google.com:19302".parse().unwrap(),
            ],
            turn_servers: vec![],
            interface_filter: InterfaceFilter::default(),
            gathering_timeout: Duration::from_secs(30),
            stun_timeout: Duration::from_secs(5),
            turn_timeout: Duration::from_secs(10),
            max_candidates_per_type: 10,
            candidate_ttl: Duration::from_secs(300),
            enable_happy_eyeballs: true,
            priority_config: LocalPreferenceConfig::default(),
        }
    }
}

/// TURN server configuration
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    pub address: SocketAddr,
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
    pub transport: TransportProtocol,
}

/// Interface filter configuration
#[derive(Debug, Clone)]
pub struct InterfaceFilter {
    /// Allowed interface names (empty = allow all)
    pub allowed_interfaces: Vec<String>,

    /// Blocked interface names
    pub blocked_interfaces: Vec<String>,

    /// Allowed interface types
    pub allowed_types: Vec<InterfaceType>,

    /// Block VPN interfaces
    pub block_vpn: bool,

    /// Block loopback interfaces
    pub block_loopback: bool,

    /// Require interface to be up
    pub require_up: bool,
}

impl Default for InterfaceFilter {
    fn default() -> Self {
        Self {
            allowed_interfaces: vec![],
            blocked_interfaces: vec![],
            allowed_types: vec![],
            block_vpn: false,
            block_loopback: true,
            require_up: true,
        }
    }
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Interface name
    pub name: String,

    /// Interface index
    pub index: u32,

    /// Interface type
    pub interface_type: InterfaceType,

    /// Interface status
    pub status: InterfaceStatus,

    /// IPv4 addresses
    pub ipv4_addresses: Vec<Ipv4Addr>,

    /// IPv6 addresses
    pub ipv6_addresses: Vec<Ipv6Addr>,

    /// Interface flags
    pub flags: InterfaceFlags,

    /// Interface metric
    pub metric: Option<u32>,

    /// Estimated bandwidth
    pub bandwidth: Option<u64>,

    /// Security level
    pub security_level: NetworkSecurityLevel,
}

/// Interface flags
#[derive(Debug, Clone, Default)]
pub struct InterfaceFlags {
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_point_to_point: bool,
    pub is_multicast: bool,
    pub is_broadcast: bool,
    pub supports_multicast: bool,
}

/// Candidate gathering event
#[derive(Debug, Clone)]
pub enum GatheringEvent {
    /// New candidate discovered
    CandidateDiscovered {
        candidate: Candidate,
        component_id: u32,
    },

    /// Candidate gathering failed
    CandidateGatheringFailed {
        candidate_type: CandidateType,
        error: String,
    },

    /// Gathering phase changed
    PhaseChanged {
        old_phase: GatheringPhase,
        new_phase: GatheringPhase,
    },

    /// Interface added
    InterfaceAdded {
        interface: NetworkInterface,
    },

    /// Interface removed
    InterfaceRemoved {
        interface_name: String,
    },

    /// Interface changed
    InterfaceChanged {
        interface: NetworkInterface,
    },

    /// Gathering completed
    GatheringCompleted {
        total_candidates: usize,
        duration: Duration,
    },

    /// Gathering timeout
    GatheringTimeout,
}

/// Gathering statistics
#[derive(Debug, Default, Clone)]
pub struct GatheringStats {
    pub host_candidates: u32,
    pub server_reflexive_candidates: u32,
    pub relay_candidates: u32,
    pub mdns_candidates: u32,
    pub ipv4_candidates: u32,
    pub ipv6_candidates: u32,
    pub tcp_candidates: u32,
    pub udp_candidates: u32,
    pub failed_gatherings: u32,
    pub total_gathering_time: Duration,
    pub average_gathering_time: Duration,
    pub stun_requests_sent: u32,
    pub stun_responses_received: u32,
    pub turn_allocations_attempted: u32,
    pub turn_allocations_successful: u32,
}

/// Main candidate gatherer
#[derive(Debug)]
pub struct CandidateGatherer {
    /// Configuration
    config: Arc<GatheringConfig>,

    /// Current gathering phase
    phase: Arc<RwLock<GatheringPhase>>,

    /// Discovered candidates
    candidates: Arc<RwLock<CandidateList>>,

    /// Network interfaces
    interfaces: Arc<RwLock<HashMap<String, NetworkInterface>>>,

    /// Priority calculator
    priority_calculator: Arc<Mutex<PriorityCalculator>>,

    /// Event sender
    event_sender: broadcast::Sender<GatheringEvent>,

    /// Gathering statistics
    stats: Arc<RwLock<GatheringStats>>,

    /// Active gathering tasks
    active_tasks: Arc<RwLock<HashSet<String>>>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,

    /// Interface monitor
    interface_monitor: Arc<InterfaceMonitor>,

    /// STUN client
    stun_client: Arc<StunClient>,

    /// TURN client
    turn_client: Arc<TurnClient>,

    /// mDNS resolver
    mdns_resolver: Option<Arc<MdnsResolver>>,
}

impl CandidateGatherer {
    /// Create new candidate gatherer
    pub async fn new(config: GatheringConfig) -> NatResult<Self> {
        let config = Arc::new(config);
        let (event_sender, _) = broadcast::channel(1000);

        let interface_monitor = Arc::new(InterfaceMonitor::new().await?);
        let stun_client = Arc::new(StunClient::new(config.stun_timeout).await?);
        let turn_client = Arc::new(TurnClient::new(config.turn_timeout).await?);

        let mdns_resolver = if config.enable_mdns {
            Some(Arc::new(MdnsResolver::new().await?))
        } else {
            None
        };

        let priority_calculator = Arc::new(Mutex::new(
            PriorityCalculator::new(config.priority_config.clone())
        ));

        Ok(Self {
            config,
            phase: Arc::new(RwLock::new(GatheringPhase::New)),
            candidates: Arc::new(RwLock::new(CandidateList::new())),
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            priority_calculator,
            event_sender,
            stats: Arc::new(RwLock::new(GatheringStats::default())),
            active_tasks: Arc::new(RwLock::new(HashSet::new())),
            shutdown: Arc::new(RwLock::new(false)),
            interface_monitor,
            stun_client,
            turn_client,
            mdns_resolver,
        })
    }

    /// Start candidate gathering
    pub async fn start_gathering(&self, component_id: u32) -> NatResult<()> {
        let mut phase = self.phase.write().await;
        if *phase != GatheringPhase::New {
            return Err(NatError::Platform("Gathering already started or completed".to_string()));
        }

        *phase = GatheringPhase::Gathering;
        let old_phase = GatheringPhase::New;
        let new_phase = GatheringPhase::Gathering;
        drop(phase);

        let _ = self.event_sender.send(GatheringEvent::PhaseChanged { old_phase, new_phase });

        let start_time = Instant::now();
        info!("Starting ICE candidate gathering for component {}", component_id);

        // Update interface list
        self.update_interfaces().await?;

        // Start gathering tasks
        let mut tasks = Vec::new();

        if self.config.gather_host_candidates {
            tasks.push(self.start_host_gathering(component_id));
        }

        if self.config.gather_server_reflexive && !self.config.stun_servers.is_empty() {
            tasks.push(self.start_server_reflexive_gathering(component_id));
        }

        if self.config.gather_relay_candidates && !self.config.turn_servers.is_empty() {
            tasks.push(self.start_relay_gathering(component_id));
        }

        if self.config.enable_mdns && self.mdns_resolver.is_some() {
            tasks.push(self.start_mdns_gathering(component_id));
        }

        // Start interface monitoring
        tasks.push(self.start_interface_monitoring());

        // Wait for gathering to complete or timeout
        let gathering_result = timeout(
            self.config.gathering_timeout,
            self.wait_for_gathering_completion(tasks)
        ).await;

        let final_phase = match gathering_result {
            Ok(Ok(())) => {
                let duration = start_time.elapsed();
                let candidate_count = self.candidates.read().await.len();

                let _ = self.event_sender.send(GatheringEvent::GatheringCompleted {
                    total_candidates: candidate_count,
                    duration,
                });

                // Update statistics
                let mut stats = self.stats.write().await;
                stats.total_gathering_time += duration;
                stats.average_gathering_time = stats.total_gathering_time /
                    (stats.average_gathering_time.as_millis().max(1) as u32);

                info!("ICE candidate gathering completed: {} candidates in {:?}",
                      candidate_count, duration);

                GatheringPhase::Complete
            }
            Ok(Err(e)) => {
                error!("ICE candidate gathering failed: {}", e);
                self.stats.write().await.failed_gatherings += 1;
                GatheringPhase::Failed
            }
            Err(_) => {
                warn!("ICE candidate gathering timed out after {:?}", self.config.gathering_timeout);
                let _ = self.event_sender.send(GatheringEvent::GatheringTimeout);
                GatheringPhase::Complete // Partial results are still useful
            }
        };

        *self.phase.write().await = final_phase;
        let _ = self.event_sender.send(GatheringEvent::PhaseChanged {
            old_phase: GatheringPhase::Gathering,
            new_phase: final_phase,
        });

        Ok(())
    }

    /// Start host candidate gathering
    async fn start_host_gathering(&self, component_id: u32) -> NatResult<()> {
        debug!("Starting host candidate gathering");
        let task_id = format!("host_{}", component_id);
        self.active_tasks.write().await.insert(task_id.clone());

        let interfaces = self.interfaces.read().await.clone();
        let mut host_candidates = Vec::new();

        for interface in interfaces.values() {
            if !self.should_use_interface(interface).await {
                continue;
            }

            // Generate IPv4 host candidates
            if self.config.enable_ipv4 {
                for &ipv4 in &interface.ipv4_addresses {
                    if self.should_use_ipv4_address(&ipv4) {
                        let candidates = self.create_host_candidates_for_ip(
                            IpAddr::V4(ipv4),
                            component_id,
                            interface,
                        ).await?;
                        host_candidates.extend(candidates);
                    }
                }
            }

            // Generate IPv6 host candidates
            if self.config.enable_ipv6 {
                for &ipv6 in &interface.ipv6_addresses {
                    if self.should_use_ipv6_address(&ipv6) {
                        let candidates = self.create_host_candidates_for_ip(
                            IpAddr::V6(ipv6),
                            component_id,
                            interface,
                        ).await?;
                        host_candidates.extend(candidates);
                    }
                }
            }
        }

        // Add candidates to list
        for candidate in host_candidates {
            self.add_candidate(candidate, component_id).await?;
        }

        self.active_tasks.write().await.remove(&task_id);
        debug!("Host candidate gathering completed");
        Ok(())
    }

    /// Create host candidates for IP address
    async fn create_host_candidates_for_ip(
        &self,
        ip: IpAddr,
        component_id: u32,
        interface: &NetworkInterface,
    ) -> NatResult<Vec<Candidate>> {
        let mut candidates = Vec::new();

        // Create interface info for priority calculation
        let interface_info = InterfaceInfo {
            interface_type: interface.interface_type,
            is_vpn: interface.interface_type == InterfaceType::Vpn,
            is_temporary: self.is_temporary_address(&ip),
            metric: interface.metric,
            name: interface.name.clone(),
            supports_encryption: interface.interface_type == InterfaceType::Vpn,
            estimated_bandwidth: interface.bandwidth,
            status: interface.status,
            security_level: interface.security_level,
        };

        // Create UDP candidate
        if self.config.enable_udp {
            let socket = self.bind_socket(&ip, 0, TransportProtocol::Udp).await?;
            let local_addr = socket.local_addr()?;

            let extensions = CandidateExtensions::new()
                .with_network_id(interface.index);

            let candidate = Candidate::new_host(
                local_addr,
                component_id,
                TransportProtocol::Udp,
                extensions,
            );

            candidates.push(candidate);
        }

        // Create TCP candidates
        if self.config.enable_tcp {
            // Create passive TCP candidate
            let tcp_socket = self.bind_tcp_socket(&ip, 0).await?;
            let local_addr = tcp_socket.local_addr()?;

            let extensions = CandidateExtensions::new()
                .with_network_id(interface.index);

            let mut tcp_candidate = Candidate::new_host(
                local_addr,
                component_id,
                TransportProtocol::Tcp,
                extensions,
            );
            tcp_candidate.tcp_type = Some(TcpType::Passive);

            candidates.push(tcp_candidate);

            // For multi-homed hosts, also create active candidates
            if interface.ipv4_addresses.len() + interface.ipv6_addresses.len() > 1 {
                let mut active_candidate = tcp_candidate.clone();
                active_candidate.tcp_type = Some(TcpType::Active);
                candidates.push(active_candidate);
            }
        }

        Ok(candidates)
    }

    /// Start server reflexive candidate gathering
    async fn start_server_reflexive_gathering(&self, component_id: u32) -> NatResult<()> {
        debug!("Starting server reflexive candidate gathering");
        let task_id = format!("srflx_{}", component_id);
        self.active_tasks.write().await.insert(task_id.clone());

        let interfaces = self.interfaces.read().await.clone();
        let mut tasks = Vec::new();

        // For each interface and STUN server combination
        for interface in interfaces.values() {
            if !self.should_use_interface(interface).await {
                continue;
            }

            for &stun_server in &self.config.stun_servers {
                // IPv4 STUN requests
                if self.config.enable_ipv4 {
                    for &ipv4 in &interface.ipv4_addresses {
                        if self.should_use_ipv4_address(&ipv4) {
                            let ip = IpAddr::V4(ipv4);
                            tasks.push(self.perform_stun_request(
                                ip, stun_server, component_id, interface.clone()
                            ));
                        }
                    }
                }

                // IPv6 STUN requests
                if self.config.enable_ipv6 {
                    for &ipv6 in &interface.ipv6_addresses {
                        if self.should_use_ipv6_address(&ipv6) {
                            let ip = IpAddr::V6(ipv6);
                            tasks.push(self.perform_stun_request(
                                ip, stun_server, component_id, interface.clone()
                            ));
                        }
                    }
                }
            }
        }

        // Execute STUN requests with limited concurrency
        let chunk_size = 10; // Limit concurrent STUN requests
        for chunk in tasks.chunks(chunk_size) {
            let results = futures::future::join_all(chunk).await;
            for result in results {
                if let Err(e) = result {
                    debug!("STUN request failed: {}", e);
                    self.stats.write().await.failed_gatherings += 1;
                }
            }
        }

        self.active_tasks.write().await.remove(&task_id);
        debug!("Server reflexive candidate gathering completed");
        Ok(())
    }

    /// Perform STUN request to discover server reflexive candidate
    async fn perform_stun_request(
        &self,
        local_ip: IpAddr,
        stun_server: SocketAddr,
        component_id: u32,
        interface: NetworkInterface,
    ) -> NatResult<()> {
        self.stats.write().await.stun_requests_sent += 1;

        let transport = if self.config.enable_udp {
            TransportProtocol::Udp
        } else {
            TransportProtocol::Tcp
        };

        let socket = self.bind_socket(&local_ip, 0, transport).await?;
        let local_addr = socket.local_addr()?;

        // Send STUN Binding Request
        let result = self.stun_client.send_binding_request(
            &socket,
            stun_server,
            self.config.stun_timeout,
        ).await;

        match result {
            Ok(reflexive_addr) => {
                self.stats.write().await.stun_responses_received += 1;

                let extensions = CandidateExtensions::new()
                    .with_network_id(interface.index);

                let candidate = Candidate::new_server_reflexive(
                    reflexive_addr,
                    local_addr,
                    component_id,
                    transport,
                    stun_server,
                    extensions,
                );

                self.add_candidate(candidate, component_id).await?;
            }
            Err(e) => {
                debug!("STUN request to {} failed: {}", stun_server, e);
                let _ = self.event_sender.send(GatheringEvent::CandidateGatheringFailed {
                    candidate_type: CandidateType::ServerReflexive,
                    error: e.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Start relay candidate gathering
    async fn start_relay_gathering(&self, component_id: u32) -> NatResult<()> {
        debug!("Starting relay candidate gathering");
        let task_id = format!("relay_{}", component_id);
        self.active_tasks.write().await.insert(task_id.clone());

        self.stats.write().await.turn_allocations_attempted += self.config.turn_servers.len() as u32;

        let mut tasks = Vec::new();

        for turn_config in &self.config.turn_servers {
            tasks.push(self.allocate_turn_relay(turn_config.clone(), component_id));
        }

        // Execute TURN allocations
        let results = futures::future::join_all(tasks).await;
        for result in results {
            if let Err(e) = result {
                debug!("TURN allocation failed: {}", e);
                let _ = self.event_sender.send(GatheringEvent::CandidateGatheringFailed {
                    candidate_type: CandidateType::Relay,
                    error: e.to_string(),
                });
            }
        }

        self.active_tasks.write().await.remove(&task_id);
        debug!("Relay candidate gathering completed");
        Ok(())
    }

    /// Allocate TURN relay
    async fn allocate_turn_relay(
        &self,
        turn_config: TurnServerConfig,
        component_id: u32,
    ) -> NatResult<()> {
        let result = self.turn_client.allocate_relay(
            &turn_config,
            self.config.turn_timeout,
        ).await;

        match result {
            Ok((relay_addr, local_addr)) => {
                self.stats.write().await.turn_allocations_successful += 1;

                let extensions = CandidateExtensions::new();

                let candidate = Candidate::new_relay(
                    relay_addr,
                    local_addr,
                    component_id,
                    turn_config.transport,
                    turn_config.address,
                    extensions,
                );

                self.add_candidate(candidate, component_id).await?;
            }
            Err(e) => {
                debug!("TURN allocation to {} failed: {}", turn_config.address, e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Start mDNS candidate gathering
    async fn start_mdns_gathering(&self, component_id: u32) -> NatResult<()> {
        debug!("Starting mDNS candidate gathering");
        let task_id = format!("mdns_{}", component_id);
        self.active_tasks.write().await.insert(task_id.clone());

        if let Some(ref mdns_resolver) = self.mdns_resolver {
            // Generate mDNS hostname
            let hostname = self.generate_mdns_hostname().await;

            // Create mDNS candidates for each transport
            if self.config.enable_udp {
                let port = self.allocate_port_for_mdns(TransportProtocol::Udp).await?;
                let candidate = Candidate::new_mdns(
                    hostname.clone(),
                    port,
                    component_id,
                    TransportProtocol::Udp,
                    CandidateType::Host,
                    CandidateExtensions::new(),
                )?;

                self.add_candidate(candidate, component_id).await?;
            }

            if self.config.enable_tcp {
                let port = self.allocate_port_for_mdns(TransportProtocol::Tcp).await?;
                let mut candidate = Candidate::new_mdns(
                    hostname,
                    port,
                    component_id,
                    TransportProtocol::Tcp,
                    CandidateType::Host,
                    CandidateExtensions::new(),
                )?;
                candidate.tcp_type = Some(TcpType::Passive);

                self.add_candidate(candidate, component_id).await?;
            }

            // Register with mDNS
            mdns_resolver.register_service(component_id).await?;
        }

        self.active_tasks.write().await.remove(&task_id);
        debug!("mDNS candidate gathering completed");
        Ok(())
    }

    /// Start interface monitoring
    async fn start_interface_monitoring(&self) -> NatResult<()> {
        let monitor = self.interface_monitor.clone();
        let event_sender = self.event_sender.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut interface_events = monitor.subscribe_events().await;

            loop {
                tokio::select! {
                    event = interface_events.recv() => {
                        match event {
                            Ok(InterfaceEvent::Added(interface)) => {
                                let _ = event_sender.send(GatheringEvent::InterfaceAdded { interface });
                            }
                            Ok(InterfaceEvent::Removed(name)) => {
                                let _ = event_sender.send(GatheringEvent::InterfaceRemoved {
                                    interface_name: name
                                });
                            }
                            Ok(InterfaceEvent::Changed(interface)) => {
                                let _ = event_sender.send(GatheringEvent::InterfaceChanged { interface });
                            }
                            Err(_) => break,
                        }
                    }
                    _ = async {
                        loop {
                            if *shutdown.read().await {
                                break;
                            }
                            sleep(Duration::from_millis(100)).await;
                        }
                    } => {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Wait for gathering completion
    async fn wait_for_gathering_completion(
        &self,
        tasks: Vec<impl std::future::Future<Output = NatResult<()>> + Send>,
    ) -> NatResult<()> {
        let results = futures::future::join_all(tasks).await;

        // Check if any critical tasks failed
        let mut errors = Vec::new();
        for result in results {
            if let Err(e) = result {
                errors.push(e);
            }
        }

        // Wait for all active tasks to complete
        loop {
            let active_count = self.active_tasks.read().await.len();
            if active_count == 0 {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }

        if errors.is_empty() {
            Ok(())
        } else {
            // Return first error, but log all
            for (i, error) in errors.iter().enumerate() {
                if i == 0 {
                    error!("Critical gathering error: {}", error);
                } else {
                    warn!("Additional gathering error: {}", error);
                }
            }