// src/nat/ice/trickle.rs
//! Trickle ICE implementation (RFC 8838)
//!
//! Trickle ICE allows ICE agents to send and receive candidates incrementally
//! rather than exchanging complete lists, enabling faster connection establishment.

use std::collections::{HashMap, VecDeque, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, broadcast, mpsc, oneshot};
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};

use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::candidate::{Candidate, CandidateType, TransportProtocol};
use crate::nat::ice::connectivity::{ConnectivityChecker, IceCredentials};
use crate::nat::ice::agent::IceRole;

/// Trickle ICE configuration
#[derive(Debug, Clone)]
pub struct TrickleConfig {
    /// Enable trickle ICE
    pub enabled: bool,

    /// Maximum time to wait before sending end-of-candidates
    pub gathering_timeout: Duration,

    /// Interval for batching trickle candidates
    pub batch_interval: Duration,

    /// Maximum candidates per batch
    pub max_batch_size: usize,

    /// Enable immediate trickling for priority candidates
    pub immediate_trickle: bool,

    /// Priority threshold for immediate trickling
    pub immediate_priority_threshold: u32,

    /// Buffer size for outgoing candidates
    pub outgoing_buffer_size: usize,

    /// Buffer size for incoming candidates
    pub incoming_buffer_size: usize,

    /// Enable half-trickle mode (only send, don't expect to receive)
    pub half_trickle: bool,
}

impl Default for TrickleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            gathering_timeout: Duration::from_secs(10),
            batch_interval: Duration::from_millis(50),
            max_batch_size: 5,
            immediate_trickle: true,
            immediate_priority_threshold: 2000000000, // High priority threshold
            outgoing_buffer_size: 100,
            incoming_buffer_size: 100,
            half_trickle: false,
        }
    }
}

/// Trickle candidate message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrickleCandidate {
    /// The actual candidate
    pub candidate: TrickleCandidateInfo,

    /// Component ID for this candidate
    pub component_id: u32,

    /// Sequence number for ordering
    pub sequence: u64,

    /// Timestamp when created
    pub timestamp: u64,

    /// Media line index (for SDP)
    pub sdp_mline_index: Option<u32>,

    /// SDP MID attribute
    pub sdp_mid: Option<String>,
}

/// Simplified candidate info for trickle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrickleCandidateInfo {
    pub foundation: String,
    pub component: u32,
    pub protocol: String,
    pub priority: u32,
    pub ip: String,
    pub port: u16,
    pub candidate_type: String,
    pub rel_addr: Option<String>,
    pub rel_port: Option<u16>,
    pub tcp_type: Option<String>,
}

/// End-of-candidates message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndOfCandidates {
    /// Component ID (None for all components)
    pub component_id: Option<u32>,

    /// Timestamp when sent
    pub timestamp: u64,

    /// Media line index
    pub sdp_mline_index: Option<u32>,

    /// SDP MID attribute
    pub sdp_mid: Option<String>,
}

/// Trickle ICE events
#[derive(Debug, Clone)]
pub enum TrickleEvent {
    /// New trickle candidate to send
    CandidateReady {
        candidate: TrickleCandidate,
    },

    /// Candidate batch ready to send
    BatchReady {
        candidates: Vec<TrickleCandidate>,
    },

    /// End of candidates for component
    EndOfCandidates {
        message: EndOfCandidates,
    },

    /// Received trickle candidate
    CandidateReceived {
        candidate: TrickleCandidate,
    },

    /// Received end-of-candidates
    EndOfCandidatesReceived {
        message: EndOfCandidates,
    },

    /// Trickle processing error
    Error {
        error: String,
        candidate: Option<TrickleCandidate>,
    },
}

/// Trickle ICE processor
pub struct TrickleProcessor {
    /// Configuration
    config: TrickleConfig,

    /// Current role
    role: Arc<RwLock<Option<IceRole>>>,

    /// Local ICE credentials
    local_credentials: IceCredentials,

    /// Remote ICE credentials
    remote_credentials: Arc<RwLock<Option<IceCredentials>>>,

    /// Connectivity checker reference
    connectivity_checker: Arc<ConnectivityChecker>,

    /// Outgoing candidate queue
    outgoing_queue: Arc<RwLock<VecDeque<TrickleCandidate>>>,

    /// Incoming candidate buffer
    incoming_buffer: Arc<RwLock<VecDeque<TrickleCandidate>>>,

    /// Batch buffer for outgoing candidates
    batch_buffer: Arc<RwLock<Vec<TrickleCandidate>>>,

    /// Sequence number for outgoing candidates
    sequence_counter: Arc<RwLock<u64>>,

    /// Components that have ended candidate gathering
    ended_components: Arc<RwLock<HashSet<u32>>>,

    /// Components for which we received end-of-candidates
    remote_ended_components: Arc<RwLock<HashSet<u32>>>,

    /// Event broadcaster
    event_sender: broadcast::Sender<TrickleEvent>,

    /// Command channel
    command_sender: mpsc::UnboundedSender<TrickleCommand>,
    command_receiver: Arc<Mutex<mpsc::UnboundedReceiver<TrickleCommand>>>,

    /// Statistics
    stats: Arc<RwLock<TrickleStats>>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,

    /// Start time for metrics
    start_time: Instant,
}

/// Trickle command for external control
#[derive(Debug)]
enum TrickleCommand {
    /// Add local candidate to trickle
    AddCandidate {
        candidate: Candidate,
        component_id: u32,
        immediate: bool,
    },

    /// Process received trickle candidate
    ProcessCandidate {
        trickle_candidate: TrickleCandidate,
    },

    /// Process received end-of-candidates
    ProcessEndOfCandidates {
        message: EndOfCandidates,
    },

    /// Mark component gathering as complete
    EndCandidates {
        component_id: u32,
    },

    /// Send buffered candidates immediately
    FlushBuffer,
}

/// Trickle statistics
#[derive(Debug, Default, Clone)]
pub struct TrickleStats {
    pub candidates_sent: u64,
    pub candidates_received: u64,
    pub batches_sent: u64,
    pub immediate_sends: u64,
    pub end_of_candidates_sent: u64,
    pub end_of_candidates_received: u64,
    pub processing_errors: u64,
    pub average_batch_size: f64,
    pub total_processing_time: Duration,
}

impl TrickleProcessor {
    /// Create new trickle processor
    pub fn new(
        config: TrickleConfig,
        local_credentials: IceCredentials,
        connectivity_checker: Arc<ConnectivityChecker>,
    ) -> Self {
        let (event_sender, _) = broadcast::channel(1000);
        let (command_sender, command_receiver) = mpsc::unbounded_channel();

        Self {
            config,
            role: Arc::new(RwLock::new(None)),
            local_credentials,
            remote_credentials: Arc::new(RwLock::new(None)),
            connectivity_checker,
            outgoing_queue: Arc::new(RwLock::new(VecDeque::new())),
            incoming_buffer: Arc::new(RwLock::new(VecDeque::new())),
            batch_buffer: Arc::new(RwLock::new(Vec::new())),
            sequence_counter: Arc::new(RwLock::new(0)),
            ended_components: Arc::new(RwLock::new(HashSet::new())),
            remote_ended_components: Arc::new(RwLock::new(HashSet::new())),
            event_sender,
            command_sender,
            command_receiver: Arc::new(Mutex::new(command_receiver)),
            stats: Arc::new(RwLock::new(TrickleStats::default())),
            shutdown: Arc::new(RwLock::new(false)),
            start_time: Instant::now(),
        }
    }

    /// Start trickle processing
    pub async fn start(&self) -> NatResult<()> {
        if !self.config.enabled {
            info!("Trickle ICE disabled");
            return Ok(());
        }

        info!("Starting Trickle ICE processor");

        // Start background tasks
        let command_task = self.process_commands();
        let batch_task = self.process_batching();
        let timeout_task = self.process_timeouts();

        tokio::select! {
            result = command_task => {
                if let Err(e) = result {
                    error!("Trickle command processing failed: {}", e);
                }
            }
            result = batch_task => {
                if let Err(e) = result {
                    error!("Trickle batching failed: {}", e);
                }
            }
            result = timeout_task => {
                if let Err(e) = result {
                    error!("Trickle timeout processing failed: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Set role
    pub async fn set_role(&self, role: IceRole) {
        *self.role.write().await = Some(role);
    }

    /// Set remote credentials
    pub async fn set_remote_credentials(&self, credentials: IceCredentials) {
        *self.remote_credentials.write().await = Some(credentials);
    }

    /// Add local candidate for trickling
    pub async fn add_candidate(&self, candidate: Candidate, component_id: u32) -> NatResult<()> {
        let immediate = self.should_send_immediately(&candidate);

        self.command_sender.send(TrickleCommand::AddCandidate {
            candidate,
            component_id,
            immediate,
        }).map_err(|_| NatError::Configuration("Failed to send trickle command".to_string()))?;

        Ok(())
    }

    /// Process received trickle candidate
    pub async fn process_candidate(&self, trickle_candidate: TrickleCandidate) -> NatResult<()> {
        self.command_sender.send(TrickleCommand::ProcessCandidate {
            trickle_candidate,
        }).map_err(|_| NatError::Configuration("Failed to send trickle command".to_string()))?;

        Ok(())
    }

    /// Process received end-of-candidates
    pub async fn process_end_of_candidates(&self, message: EndOfCandidates) -> NatResult<()> {
        self.command_sender.send(TrickleCommand::ProcessEndOfCandidates {
            message,
        }).map_err(|_| NatError::Configuration("Failed to send trickle command".to_string()))?;

        Ok(())
    }

    /// End candidates for component
    pub async fn end_candidates(&self, component_id: u32) -> NatResult<()> {
        self.command_sender.send(TrickleCommand::EndCandidates {
            component_id,
        }).map_err(|_| NatError::Configuration("Failed to send trickle command".to_string()))?;

        Ok(())
    }

    /// Flush pending candidates immediately
    pub async fn flush(&self) -> NatResult<()> {
        self.command_sender.send(TrickleCommand::FlushBuffer)
            .map_err(|_| NatError::Configuration("Failed to send flush command".to_string()))?;

        Ok(())
    }

    /// Process commands
    async fn process_commands(&self) -> NatResult<()> {
        let mut receiver = self.command_receiver.lock().await;

        while let Some(command) = receiver.recv().await {
            if *self.shutdown.read().await {
                break;
            }

            let start_time = Instant::now();

            match command {
                TrickleCommand::AddCandidate { candidate, component_id, immediate } => {
                    if let Err(e) = self.handle_add_candidate(candidate, component_id, immediate).await {
                        warn!("Failed to handle add candidate: {}", e);
                    }
                }

                TrickleCommand::ProcessCandidate { trickle_candidate } => {
                    if let Err(e) = self.handle_process_candidate(trickle_candidate).await {
                        warn!("Failed to process trickle candidate: {}", e);
                    }
                }

                TrickleCommand::ProcessEndOfCandidates { message } => {
                    if let Err(e) = self.handle_process_end_of_candidates(message).await {
                        warn!("Failed to process end-of-candidates: {}", e);
                    }
                }

                TrickleCommand::EndCandidates { component_id } => {
                    if let Err(e) = self.handle_end_candidates(component_id).await {
                        warn!("Failed to handle end candidates: {}", e);
                    }
                }

                TrickleCommand::FlushBuffer => {
                    if let Err(e) = self.handle_flush_buffer().await {
                        warn!("Failed to flush buffer: {}", e);
                    }
                }
            }

            // Update processing time stats
            let processing_time = start_time.elapsed();
            let mut stats = self.stats.write().await;
            stats.total_processing_time += processing_time;
        }

        Ok(())
    }

    /// Handle add candidate command
    async fn handle_add_candidate(
        &self,
        candidate: Candidate,
        component_id: u32,
        immediate: bool,
    ) -> NatResult<()> {
        // Convert to trickle candidate
        let trickle_candidate = self.candidate_to_trickle(candidate, component_id).await?;

        if immediate {
            // Send immediately
            self.send_candidate_immediately(trickle_candidate).await?;
        } else {
            // Add to batch buffer
            self.add_to_batch_buffer(trickle_candidate).await?;
        }

        Ok(())
    }

    /// Handle process candidate command
    async fn handle_process_candidate(&self, trickle_candidate: TrickleCandidate) -> NatResult<()> {
        debug!("Processing received trickle candidate: component {}", trickle_candidate.component_id);

        // Convert to ICE candidate
        let candidate = self.trickle_to_candidate(&trickle_candidate).await?;

        // Add to connectivity checker
        self.connectivity_checker.add_remote_candidate(candidate, trickle_candidate.component_id).await?;

        // Update statistics
        self.stats.write().await.candidates_received += 1;

        // Emit event
        let _ = self.event_sender.send(TrickleEvent::CandidateReceived {
            candidate: trickle_candidate,
        });

        Ok(())
    }

    /// Handle process end-of-candidates command
    async fn handle_process_end_of_candidates(&self, message: EndOfCandidates) -> NatResult<()> {
        info!("Received end-of-candidates for component {:?}", message.component_id);

        // Mark components as ended
        {
            let mut ended = self.remote_ended_components.write().await;
            if let Some(component_id) = message.component_id {
                ended.insert(component_id);
            } else {
                // End for all components - add some default components
                ended.insert(1);
            }
        }

        // Update statistics
        self.stats.write().await.end_of_candidates_received += 1;

        // Emit event
        let _ = self.event_sender.send(TrickleEvent::EndOfCandidatesReceived {
            message,
        });

        Ok(())
    }

    /// Handle end candidates command
    async fn handle_end_candidates(&self, component_id: u32) -> NatResult<()> {
        info!("Ending candidates for component {}", component_id);

        // Flush any pending candidates for this component
        self.flush_component_candidates(component_id).await?;

        // Mark component as ended
        self.ended_components.write().await.insert(component_id);

        // Send end-of-candidates message
        let message = EndOfCandidates {
            component_id: Some(component_id),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            sdp_mline_index: Some(0),
            sdp_mid: None,
        };

        // Update statistics
        self.stats.write().await.end_of_candidates_sent += 1;

        // Emit event
        let _ = self.event_sender.send(TrickleEvent::EndOfCandidates {
            message,
        });

        Ok(())
    }

    /// Handle flush buffer command
    async fn handle_flush_buffer(&self) -> NatResult<()> {
        let candidates = {
            let mut buffer = self.batch_buffer.write().await;
            let candidates = buffer.clone();
            buffer.clear();
            candidates
        };

        if !candidates.is_empty() {
            self.send_candidate_batch(candidates).await?;
        }

        Ok(())
    }

    /// Process batching
    async fn process_batching(&self) -> NatResult<()> {
        let mut timer = interval(self.config.batch_interval);

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            // Check if we have candidates to batch
            let should_send = {
                let buffer = self.batch_buffer.read().await;
                buffer.len() >= self.config.max_batch_size ||
                    (!buffer.is_empty() && self.has_batch_timeout().await)
            };

            if should_send {
                if let Err(e) = self.handle_flush_buffer().await {
                    warn!("Failed to flush batch: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Process timeouts
    async fn process_timeouts(&self) -> NatResult<()> {
        let mut timer = interval(Duration::from_secs(1));

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            // Check for gathering timeout
            if self.start_time.elapsed() > self.config.gathering_timeout {
                // End all components that haven't ended yet
                let components_to_end: Vec<u32> = {
                    let ended = self.ended_components.read().await;
                    (1..=4).filter(|id| !ended.contains(id)).collect()
                };

                for component_id in components_to_end {
                    if let Err(e) = self.end_candidates(component_id).await {
                        warn!("Failed to end candidates for component {}: {}", component_id, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Convert ICE candidate to trickle candidate
    async fn candidate_to_trickle(
        &self,
        candidate: Candidate,
        component_id: u32,
    ) -> NatResult<TrickleCandidate> {
        let sequence = {
            let mut counter = self.sequence_counter.write().await;
            *counter += 1;
            *counter
        };

        let (ip, port) = match &candidate.address {
            crate::nat::ice::candidate::CandidateAddress::Ip(addr) => {
                (addr.ip().to_string(), addr.port())
            }
            crate::nat::ice::candidate::CandidateAddress::MDns { hostname, port } => {
                (hostname.clone(), *port)
            }
        };

        let (rel_addr, rel_port) = match &candidate.related_address {
            Some(crate::nat::ice::candidate::CandidateAddress::Ip(addr)) => {
                (Some(addr.ip().to_string()), Some(addr.port()))
            }
            Some(crate::nat::ice::candidate::CandidateAddress::MDns { hostname, port }) => {
                (Some(hostname.clone()), Some(*port))
            }
            None => (None, None),
        };

        let candidate_info = TrickleCandidateInfo {
            foundation: candidate.foundation,
            component: candidate.component_id,
            protocol: candidate.transport.to_str().to_string(),
            priority: candidate.priority,
            ip,
            port,
            candidate_type: candidate.candidate_type.to_str().to_string(),
            rel_addr,
            rel_port,
            tcp_type: candidate.tcp_type.map(|t| t.to_str().to_string()),
        };

        Ok(TrickleCandidate {
            candidate: candidate_info,
            component_id,
            sequence,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            sdp_mline_index: Some(0),
            sdp_mid: None,
        })
    }

    /// Convert trickle candidate to ICE candidate
    async fn trickle_to_candidate(&self, trickle: &TrickleCandidate) -> NatResult<Candidate> {
        use crate::nat::ice::candidate::{CandidateExtensions, CandidateAddress};

        let transport = match trickle.candidate.protocol.as_str() {
            "UDP" | "udp" => TransportProtocol::Udp,
            "TCP" | "tcp" => TransportProtocol::Tcp,
            _ => return Err(NatError::Platform("Invalid transport protocol".to_string())),
        };

        let candidate_type = match trickle.candidate.candidate_type.as_str() {
            "host" => CandidateType::Host,
            "srflx" => CandidateType::ServerReflexive,
            "prflx" => CandidateType::PeerReflexive,
            "relay" => CandidateType::Relay,
            _ => return Err(NatError::Platform("Invalid candidate type".to_string())),
        };

        // Parse address
        let address = if trickle.candidate.ip.ends_with(".local") {
            CandidateAddress::MDns {
                hostname: trickle.candidate.ip.clone(),
                port: trickle.candidate.port,
            }
        } else {
            let ip = trickle.candidate.ip.parse()
                .map_err(|_| NatError::Platform("Invalid IP address".to_string()))?;
            CandidateAddress::Ip(std::net::SocketAddr::new(ip, trickle.candidate.port))
        };

        // Parse related address
        let related_address = if let (Some(rel_addr), Some(rel_port)) =
            (&trickle.candidate.rel_addr, &trickle.candidate.rel_port) {

            if rel_addr.ends_with(".local") {
                Some(CandidateAddress::MDns {
                    hostname: rel_addr.clone(),
                    port: *rel_port,
                })
            } else {
                let ip = rel_addr.parse()
                    .map_err(|_| NatError::Platform("Invalid related IP address".to_string()))?;
                Some(CandidateAddress::Ip(std::net::SocketAddr::new(ip, *rel_port)))
            }
        } else {
            None
        };

        let extensions = CandidateExtensions::new();

        let candidate = Candidate {
            foundation: trickle.candidate.foundation.clone(),
            component_id: trickle.candidate.component,
            transport,
            priority: trickle.candidate.priority,
            address,
            candidate_type,
            related_address,
            tcp_type: trickle.candidate.tcp_type.as_ref().and_then(|t| {
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

        Ok(candidate)
    }

    /// Check if candidate should be sent immediately
    fn should_send_immediately(&self, candidate: &Candidate) -> bool {
        if !self.config.immediate_trickle {
            return false;
        }

        // Send high priority candidates immediately
        candidate.priority >= self.config.immediate_priority_threshold ||
            candidate.candidate_type == CandidateType::Host
    }

    /// Send candidate immediately
    async fn send_candidate_immediately(&self, candidate: TrickleCandidate) -> NatResult<()> {
        debug!("Sending trickle candidate immediately: component {}", candidate.component_id);

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.candidates_sent += 1;
            stats.immediate_sends += 1;
        }

        // Emit event
        let _ = self.event_sender.send(TrickleEvent::CandidateReady {
            candidate,
        });

        Ok(())
    }

    /// Add candidate to batch buffer
    async fn add_to_batch_buffer(&self, candidate: TrickleCandidate) -> NatResult<()> {
        let mut buffer = self.batch_buffer.write().await;

        // Check buffer size limit
        if buffer.len() >= self.config.outgoing_buffer_size {
            // Remove oldest candidate
            buffer.remove(0);
        }

        buffer.push(candidate);
        Ok(())
    }

    /// Send candidate batch
    async fn send_candidate_batch(&self, candidates: Vec<TrickleCandidate>) -> NatResult<()> {
        if candidates.is_empty() {
            return Ok(());
        }

        debug!("Sending trickle candidate batch: {} candidates", candidates.len());

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.candidates_sent += candidates.len() as u64;
            stats.batches_sent += 1;

            // Update average batch size
            let total_candidates = stats.candidates_sent;
            let total_batches = stats.batches_sent;
            stats.average_batch_size = total_candidates as f64 / total_batches as f64;
        }

        // Emit event
        let _ = self.event_sender.send(TrickleEvent::BatchReady {
            candidates,
        });

        Ok(())
    }

    /// Flush candidates for specific component
    async fn flush_component_candidates(&self, component_id: u32) -> NatResult<()> {
        let component_candidates = {
            let mut buffer = self.batch_buffer.write().await;
            let (component_candidates, remaining): (Vec<_>, Vec<_>) = buffer
                .drain(..)
                .partition(|c| c.component_id == component_id);

            *buffer = remaining;
            component_candidates
        };

        if !component_candidates.is_empty() {
            self.send_candidate_batch(component_candidates).await?;
        }

        Ok(())
    }

    /// Check if batch has timeout
    async fn has_batch_timeout(&self) -> bool {
        // For simplicity, always return true after interval
        // In real implementation, would track timestamp of first candidate in batch
        true
    }

    /// Subscribe to trickle events
    pub fn subscribe_events(&self) -> broadcast::Receiver<TrickleEvent> {
        self.event_sender.subscribe()
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> TrickleStats {
        self.stats.read().await.clone()
    }

    /// Check if component has ended
    pub async fn is_component_ended(&self, component_id: u32) -> bool {
        self.ended_components.read().await.contains(&component_id)
    }

    /// Check if remote component has ended
    pub async fn is_remote_component_ended(&self, component_id: u32) -> bool {
        self.remote_ended_components.read().await.contains(&component_id)
    }

    /// Stop trickle processor
    pub async fn stop(&self) {
        *self.shutdown.write().await = true;
        info!("Trickle ICE processor stopped");
    }
}

/// Helper functions for trickle ICE

/// Create SDP representation of trickle candidate
pub fn trickle_candidate_to_sdp(candidate: &TrickleCandidate) -> String {
    let info = &candidate.candidate;
    let mut sdp = format!(
        "candidate:{} {} {} {} {} {} typ {}",
        info.foundation,
        info.component,
        info.protocol.to_uppercase(),
        info.priority,
        info.ip,
        info.port,
        info.candidate_type
    );

    if let (Some(rel_addr), Some(rel_port)) = (&info.rel_addr, &info.rel_port) {
        sdp.push_str(&format!(" raddr {} rport {}", rel_addr, rel_port));
    }

    if let Some(tcp_type) = &info.tcp_type {
        sdp.push_str(&format!(" tcptype {}", tcp_type));
    }

    sdp
}

/// Parse trickle candidate from SDP
pub fn sdp_to_trickle_candidate(
    sdp: &str,
    component_id: u32,
    sequence: u64,
) -> NatResult<TrickleCandidate> {
    // Remove "a=" prefix if present
    let sdp = sdp.strip_prefix("a=").unwrap_or(sdp);

    let parts: Vec<&str> = sdp.split_whitespace().collect();

    if parts.len() < 8 || !parts[0].starts_with("candidate:") {
        return Err(NatError::Platform("Invalid candidate SDP format".to_string()));
    }

    let foundation = parts[0].strip_prefix("candidate:").unwrap().to_string();
    let component = parts[1].parse::<u32>()
        .map_err(|_| NatError::Platform("Invalid component ID".to_string()))?;
    let protocol = parts[2].to_string();
    let priority = parts[3].parse::<u32>()
        .map_err(|_| NatError::Platform("Invalid priority".to_string()))?;
    let ip = parts[4].to_string();
    let port = parts[5].parse::<u16>()
        .map_err(|_| NatError::Platform("Invalid port".to_string()))?;

    // Find "typ" keyword
    let typ_pos = parts.iter().position(|&p| p == "typ")
        .ok_or_else(|| NatError::Platform("Missing typ field".to_string()))?;

    if typ_pos + 1 >= parts.len() {
        return Err(NatError::Platform("Missing candidate type".to_string()));
    }

    let candidate_type = parts[typ_pos + 1].to_string();

    // Parse optional fields
    let mut rel_addr = None;
    let mut rel_port = None;
    let mut tcp_type = None;

    let mut i = typ_pos + 2;
    while i < parts.len() {
        match parts[i] {
            "raddr" if i + 3 < parts.len() && parts[i + 2] == "rport" => {
                rel_addr = Some(parts[i + 1].to_string());
                rel_port = Some(parts[i + 3].parse().unwrap_or(0));
                i += 4;
            }
            "tcptype" if i + 1 < parts.len() => {
                tcp_type = Some(parts[i + 1].to_string());
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let candidate_info = TrickleCandidateInfo {
        foundation,
        component,
        protocol,
        priority,
        ip,
        port,
        candidate_type,
        rel_addr,
        rel_port,
        tcp_type,
    };

    Ok(TrickleCandidate {
        candidate: candidate_info,
        component_id,
        sequence,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        sdp_mline_index: Some(0),
        sdp_mid: None,
    })
}

/// Validate trickle candidate
pub fn validate_trickle_candidate(candidate: &TrickleCandidate) -> NatResult<()> {
    let info = &candidate.candidate;

    // Validate foundation
    if info.foundation.is_empty() || info.foundation.len() > 32 {
        return Err(NatError::Platform("Invalid foundation".to_string()));
    }

    // Validate component
    if info.component == 0 || info.component > 256 {
        return Err(NatError::Platform("Invalid component ID".to_string()));
    }

    // Validate protocol
    if !matches!(info.protocol.to_uppercase().as_str(), "UDP" | "TCP") {
        return Err(NatError::Platform("Invalid protocol".to_string()));
    }

    // Validate candidate type
    if !matches!(info.candidate_type.as_str(), "host" | "srflx" | "prflx" | "relay") {
        return Err(NatError::Platform("Invalid candidate type".to_string()));
    }

    // Validate IP address
    if info.ip.parse::<std::net::IpAddr>().is_err() && !info.ip.ends_with(".local") {
        return Err(NatError::Platform("Invalid IP address".to_string()));
    }

    // Validate port
    if info.port == 0 {
        return Err(NatError::Platform("Invalid port".to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::ice::connectivity::ConnectivityChecker;

    #[tokio::test]
    async fn test_trickle_processor_creation() {
        let config = TrickleConfig::default();
        let credentials = IceCredentials::new();
        let checker = Arc::new(ConnectivityChecker::new(1, true, false));

        let processor = TrickleProcessor::new(config, credentials, checker);
        assert!(processor.config.enabled);
    }

    #[test]
    fn test_sdp_conversion() {
        let sdp = "candidate:1 1 UDP 2130706431 192.168.1.1 54321 typ host";
        let trickle = sdp_to_trickle_candidate(sdp, 1, 1).unwrap();

        assert_eq!(trickle.candidate.foundation, "1");
        assert_eq!(trickle.candidate.component, 1);
        assert_eq!(trickle.candidate.protocol, "UDP");
        assert_eq!(trickle.candidate.ip, "192.168.1.1");
        assert_eq!(trickle.candidate.port, 54321);
        assert_eq!(trickle.candidate.candidate_type, "host");

        let regenerated_sdp = trickle_candidate_to_sdp(&trickle);
        assert!(regenerated_sdp.contains("192.168.1.1"));
        assert!(regenerated_sdp.contains("54321"));
    }

    #[test]
    fn test_trickle_validation() {
        let candidate = TrickleCandidate {
            candidate: TrickleCandidateInfo {
                foundation: "test".to_string(),
                component: 1,
                protocol: "UDP".to_string(),
                priority: 1000,
                ip: "192.168.1.1".to_string(),
                port: 12345,
                candidate_type: "host".to_string(),
                rel_addr: None,
                rel_port: None,
                tcp_type: None,
            },
            component_id: 1,
            sequence: 1,
            timestamp: 0,
            sdp_mline_index: None,
            sdp_mid: None,
        };

        assert!(validate_trickle_candidate(&candidate).is_ok());

        // Test invalid candidate
        let mut invalid_candidate = candidate.clone();
        invalid_candidate.candidate.port = 0;
        assert!(validate_trickle_candidate(&invalid_candidate).is_err());
    }

    #[tokio::test]
    async fn test_end_of_candidates() {
        let config = TrickleConfig::default();
        let credentials = IceCredentials::new();
        let checker = Arc::new(ConnectivityChecker::new(1, true, false));

        let processor = TrickleProcessor::new(config, credentials, checker);

        // Test ending candidates
        processor.end_candidates(1).await.unwrap();
        assert!(processor.is_component_ended(1).await);
    }
}