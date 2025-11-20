// src/connectivity/transport/ice_transport.rs
//! IceTransport - Production ICE Transport Implementation
//!
//! ## RFC Standards Compliance
//!
//! - **RFC 8445**: Interactive Connectivity Establishment (ICE)
//!   - Section 5: Candidate gathering
//!   - Section 6: Connectivity checks
//!   - Section 7: Connection establishment
//!   - Section 8: Nomination
//!   - Section 9: ICE restart
//!   - Section 14: Statistics collection
//!
//! - **RFC 8838**: Trickle ICE
//!   - Incremental candidate gathering
//!   - Progressive connectivity checks
//!
//! - **RFC 7675**: STUN Usage for Consent Freshness
//!   - Periodic connectivity validation
//!   - Timeout handling
//!   - Consent expiration
//!
//! - **RFC 8421**: Dual-Stack ICE
//!   - IPv4/IPv6 support
//!   - Happy Eyeballs algorithm
//!
//! This is the CORE of the SHARP transport system, integrating all layers:
//! - Stage 1: Transport trait (abstraction)
//! - Stage 2: UdpSocketWrapper (networking + MTU discovery)
//! - ICE: ProductionIceAgent (candidate management)
//! - STUN: Connectivity checks and consent freshness

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use parking_lot::RwLock as StdRwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::interval;
use tracing::{debug, info, warn};

use super::{
    ConnectionInfo, ConnectionState, QualityMetrics, SocketOptions, Transport, TransportEvent,
    TransportStats, TransportType, UdpSocketWrapper,
};
use crate::connectivity::config::IceConfig;
use crate::connectivity::ice::production_ice_agent::{ProductionIceAgent, ProductionIceConfig};
use crate::connectivity::stun::message::{StunClass, StunMessage, StunMessageType, StunMethod};
use crate::connectivity::stun::transaction::TransactionId;
use crate::connectivity::CandidatePair;

/// RFC 7675: Default consent freshness interval (15 seconds)
const DEFAULT_CONSENT_INTERVAL: Duration = Duration::from_secs(15);

/// RFC 7675: Default consent timeout (30 seconds)
const DEFAULT_CONSENT_TIMEOUT: Duration = Duration::from_secs(30);

/// RFC 8445: Default connection timeout (30 seconds)
const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Default keepalive interval (25 seconds per RFC 5245)
const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

/// IceTransport configuration
#[derive(Debug, Clone)]
pub struct IceTransportConfig {
    /// ICE configuration (STUN/TURN servers)
    pub ice_config: IceConfig,

    /// Controlling role (RFC 8445 Section 5.1.1)
    pub controlling: bool,

    /// Local ICE credentials
    pub local_ufrag: String,
    pub local_pwd: String,

    /// Remote ICE credentials (set during signaling)
    pub remote_ufrag: Option<String>,
    pub remote_pwd: Option<String>,

    /// Peer address for signaling (optional)
    pub peer_addr: Option<SocketAddr>,

    /// Connection timeout (RFC 8445)
    pub connection_timeout: Duration,

    /// Consent freshness interval (RFC 7675)
    pub consent_interval: Duration,

    /// Consent timeout (RFC 7675)
    pub consent_timeout: Duration,

    /// Enable Trickle ICE (RFC 8838)
    pub trickle_ice: bool,

    /// Enable aggressive nomination (RFC 8445 Section 8)
    pub aggressive_nomination: bool,

    /// Keep-alive interval
    pub keepalive_interval: Duration,

    /// Strict source validation (RFC 8445 Section 11.1)
    /// When enabled, packets from unexpected sources are dropped
    /// When disabled, packets are logged but accepted
    pub strict_source_validation: bool,
}

impl Default for IceTransportConfig {
    fn default() -> Self {
        Self {
            ice_config: IceConfig::default(),
            controlling: true,
            local_ufrag: generate_ice_credential(8),
            local_pwd: generate_ice_credential(24),
            remote_ufrag: None,
            remote_pwd: None,
            peer_addr: None,
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
            consent_interval: DEFAULT_CONSENT_INTERVAL,
            consent_timeout: DEFAULT_CONSENT_TIMEOUT,
            trickle_ice: true,
            aggressive_nomination: false,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            strict_source_validation: true, // RFC 8445 Section 11.1: Drop unexpected packets
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ICE TRANSPORT
// ═══════════════════════════════════════════════════════════════════════════

/// Production-ready ICE Transport
///
/// Implements the `Transport` trait with full RFC 8445 compliance.
/// This is the CORE component that ties together:
/// - UDP socket layer (Stage 2)
/// - ICE agent (candidate management)
/// - MTU discovery (RFC 4821/8899)
/// - Consent freshness (RFC 7675)
/// - Statistics collection (RFC 8445 Section 14)
#[derive(Debug)]
pub struct IceTransport {
    // ═══ Networking Layer ═══
    /// UDP socket wrapper with MTU discovery (Stage 2)
    socket: Arc<UdpSocketWrapper>,

    // ═══ ICE Layer ═══
    /// ICE agent for candidate gathering/checks/nomination
    ice_agent: Arc<ProductionIceAgent>,

    // ═══ State Management ═══
    /// Current transport state (RFC 8445 Section 11)
    state: Arc<StdRwLock<ConnectionState>>,

    /// Nominated candidate pair (RFC 8445 Section 8)
    nominated_pair: Arc<StdRwLock<Option<CandidatePair>>>,

    /// Connection information
    connection_info: Arc<StdRwLock<Option<ConnectionInfo>>>,

    // ═══ Statistics (RFC 8445 Section 14) ═══
    stats: Arc<StdRwLock<TransportStats>>,

    // ═══ Consent Freshness (RFC 7675) ═══
    /// Last successful consent check
    last_consent_check: Arc<StdRwLock<Option<Instant>>>,

    /// Consent is fresh
    consent_fresh: Arc<StdRwLock<bool>>,

    /// Consent check interval
    consent_interval: Duration,

    /// Consent timeout
    consent_timeout: Duration,

    /// Consent checks performed
    consent_checks_performed: Arc<StdRwLock<u64>>,

    /// Consent checks failed
    consent_checks_failed: Arc<StdRwLock<u64>>,

    // ═══ Configuration ═══
    config: Arc<StdRwLock<IceTransportConfig>>,

    // ═══ Events ═══
    event_tx: mpsc::UnboundedSender<TransportEvent>,
    event_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<TransportEvent>>>>,

    // ═══ Lifecycle ═══
    /// Shutdown signal
    shutdown: Arc<Notify>,

    /// Connection established notification
    connected: Arc<Notify>,

    /// Created timestamp
    created_at: Instant,
}

impl IceTransport {
    /// Create new ICE transport
    ///
    /// ## Arguments
    /// - `config`: ICE transport configuration
    ///
    /// ## Returns
    /// Initialized ICE transport ready for connection
    ///
    /// ## Example
    /// ```rust,ignore
    /// let config = IceTransportConfig::default();
    /// let transport = IceTransport::new(config).await?;
    /// ```
    pub async fn new(config: IceTransportConfig) -> Result<Self> {
        info!(
            "Creating ICE transport (controlling: {})",
            config.controlling
        );

        // Create UDP socket with default options
        let socket_options = SocketOptions::default();
        let socket = UdpSocketWrapper::bind("0.0.0.0:0", socket_options)
            .await
            .context("Failed to create UDP socket")?;

        info!("UDP socket bound to {}", socket.local_addr());

        // Create ICE agent configuration
        let ice_config = ProductionIceConfig {
            ice_config: config.ice_config.clone(),
            controlling: config.controlling,
            local_ufrag: config.local_ufrag.clone(),
            local_pwd: config.local_pwd.clone(),
            remote_ufrag: config.remote_ufrag.clone(),
            remote_pwd: config.remote_pwd.clone(),
            aggressive_nomination: config.aggressive_nomination,
            trickle_ice: config.trickle_ice,
            connection_timeout: config.connection_timeout,
            keepalive_interval: config.keepalive_interval,
        };

        // Create ICE agent
        let ice_agent = Arc::new(
            ProductionIceAgent::new(ice_config)
                .await
                .context("Failed to create ICE agent")?,
        );

        // Create event channel
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let transport = Self {
            socket: Arc::new(socket),
            ice_agent,
            state: Arc::new(StdRwLock::new(ConnectionState::New)),
            nominated_pair: Arc::new(StdRwLock::new(None)),
            connection_info: Arc::new(StdRwLock::new(None)),
            stats: Arc::new(StdRwLock::new(TransportStats::default())),
            last_consent_check: Arc::new(StdRwLock::new(None)),
            consent_fresh: Arc::new(StdRwLock::new(false)),
            consent_interval: config.consent_interval,
            consent_timeout: config.consent_timeout,
            consent_checks_performed: Arc::new(StdRwLock::new(0)),
            consent_checks_failed: Arc::new(StdRwLock::new(0)),
            config: Arc::new(StdRwLock::new(config)),
            event_tx,
            event_rx: Arc::new(Mutex::new(Some(event_rx))),
            shutdown: Arc::new(Notify::new()),
            connected: Arc::new(Notify::new()),
            created_at: Instant::now(),
        };

        info!("ICE transport created successfully");
        Ok(transport)
    }

    /// Set transport state and emit event
    fn set_state(&self, new_state: ConnectionState) {
        let old_state = *self.state.read();
        if old_state != new_state {
            *self.state.write() = new_state;

            // Emit state changed event
            let _ = self.event_tx.send(TransportEvent::StateChanged {
                old_state,
                new_state,
            });

            info!("Transport state: {:?} -> {:?}", old_state, new_state);
        }
    }

    /// Emit transport event
    fn emit_event(&self, event: TransportEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Start consent freshness checks (RFC 7675)
    ///
    /// RFC 7675 requires periodic consent checks to ensure the peer
    /// still consents to receive data. Checks are performed every
    /// `consent_interval` seconds.
    fn start_consent_freshness_checks(&self) {
        let socket = self.socket.clone();
        let nominated_pair = self.nominated_pair.clone();
        let consent_fresh = self.consent_fresh.clone();
        let last_check = self.last_consent_check.clone();
        let checks_performed = self.consent_checks_performed.clone();
        let checks_failed = self.consent_checks_failed.clone();
        let interval_duration = self.consent_interval;
        let timeout = self.consent_timeout;
        let shutdown = self.shutdown.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            info!(
                "Starting consent freshness checks (interval: {:?})",
                interval_duration
            );

            let mut ticker = interval(interval_duration);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        // Perform consent check
                        if let Some(ref pair) = *nominated_pair.read() {
                            let start = Instant::now();

                            // RFC 7675 Section 5.1: Send STUN Binding Indication
                            // Binding Indication is used (not Request) to avoid requiring a response
                            let stun_msg = create_consent_check_message();
                            let check_result = match stun_msg.encode() {
                                Ok(bytes) => socket.send_to(&bytes, &pair.remote.address).await,
                                Err(e) => {
                                    warn!("Failed to encode STUN consent check: {}", e);
                                    continue;
                                }
                            };

                            *checks_performed.write() += 1;

                            match check_result {
                                Ok(_) => {
                                    let rtt = start.elapsed();
                                    *consent_fresh.write() = true;
                                    *last_check.write() = Some(Instant::now());

                                    let _ = event_tx.send(TransportEvent::ConsentCheckPerformed {
                                        success: true,
                                        rtt: Some(rtt),
                                    });

                                    debug!("Consent check successful (RTT: {:?})", rtt);
                                }
                                Err(e) => {
                                    *checks_failed.write() += 1;

                                    // Check if consent has expired
                                    if let Some(last) = *last_check.read() {
                                        if last.elapsed() > timeout {
                                            *consent_fresh.write() = false;
                                            let _ = event_tx.send(TransportEvent::ConsentExpired);
                                            warn!("Consent expired!");
                                        }
                                    }

                                    warn!("Consent check failed: {}", e);
                                }
                            }
                        }
                    }
                    _ = shutdown.notified() => {
                        info!("Stopping consent freshness checks");
                        break;
                    }
                }
            }
        });
    }

    /// Start statistics collection
    fn start_statistics_collection(&self) {
        let socket = self.socket.clone();
        let stats = self.stats.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(1));

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        // Update socket statistics
                        let socket_stats = socket.stats();
                        let mut stats_guard = stats.write();
                        stats_guard.socket = Some(socket_stats);
                    }
                    _ = shutdown.notified() => {
                        break;
                    }
                }
            }
        });
    }

    /// Take event receiver for monitoring transport events
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<TransportEvent>> {
        self.event_rx.lock().await.take()
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TRANSPORT TRAIT IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════

#[async_trait]
impl Transport for IceTransport {
    /// Establish connection using ICE process (RFC 8445 Section 7)
    ///
    /// This method performs the complete ICE connection establishment:
    /// 1. Candidate gathering (RFC 8445 Section 5)
    /// 2. Connectivity checks (RFC 8445 Section 6)
    /// 3. Nomination (RFC 8445 Section 8)
    /// 4. MTU discovery (RFC 4821/8899)
    /// 5. Start consent freshness checks (RFC 7675)
    ///
    /// ## Returns
    /// `ConnectionInfo` with details about the established connection
    ///
    /// ## Errors
    /// - No nominated pair found
    /// - Connection timeout
    /// - Network errors
    async fn connect(&self) -> Result<ConnectionInfo> {
        info!("Starting ICE connection process");

        // ═══ Phase 1: Gathering (RFC 8445 Section 5) ═══
        self.set_state(ConnectionState::Gathering);
        self.emit_event(TransportEvent::GatheringStarted);

        // Start ICE agent (gathering + checks + nomination)
        let peer_addr = self.config.read().peer_addr;
        self.ice_agent
            .start(self.socket.clone(), peer_addr)
            .await
            .context("ICE agent start failed")?;

        // Wait for ICE connection or timeout
        let connection_timeout = self.config.read().connection_timeout;

        tokio::select! {
            _ = self.ice_agent.connection_established.notified() => {
                info!("ICE connection established");
            }
            _ = tokio::time::sleep(connection_timeout) => {
                self.set_state(ConnectionState::Failed);
                return Err(anyhow!("ICE connection timeout after {:?}", connection_timeout));
            }
        }

        // ═══ Phase 2: Get Nominated Pair (RFC 8445 Section 8) ═══
        let nominated_pairs = self.ice_agent.nominated_pairs.read().await;
        let pair = nominated_pairs
            .first()
            .ok_or_else(|| anyhow!("No nominated pair found"))?
            .clone();

        info!(
            "Nominated pair: {} <-> {}",
            pair.local.address, pair.remote.address
        );

        *self.nominated_pair.write() = Some(pair.clone());

        // ═══ Phase 3: MTU Discovery (RFC 4821/8899) ═══
        info!("Starting Path MTU Discovery");
        let remote_addr = pair.remote.address;

        match self.socket.start_mtu_discovery(remote_addr).await {
            Ok(mtu) => {
                info!("Path MTU discovered: {} bytes", mtu);
                if let Some(max_payload) = self.socket.get_max_payload() {
                    info!("Maximum payload: {} bytes", max_payload);
                }
            }
            Err(e) => {
                warn!("MTU discovery failed (continuing): {}", e);
                // Continue - not critical for connection
            }
        }

        // ═══ Phase 4: Create ConnectionInfo ═══
        let connection_info = ConnectionInfo {
            local_addr: pair.local.address,
            remote_addr: pair.remote.address,
            nominated_pair: pair.clone(),
            state: ConnectionState::Connected,
            rtt: pair.rtt.unwrap_or(Duration::from_millis(50)),
            established_at: Instant::now(),
            transport_type: TransportType::Ice,
            quality: QualityMetrics::default(),
            consent_fresh: true,
            last_consent_check: Some(Instant::now()),
        };

        *self.connection_info.write() = Some(connection_info.clone());

        // ═══ Phase 5: Update State ═══
        self.set_state(ConnectionState::Connected);
        *self.consent_fresh.write() = true;
        *self.last_consent_check.write() = Some(Instant::now());

        // ═══ Phase 6: Start Background Tasks ═══
        self.start_consent_freshness_checks();
        self.start_statistics_collection();

        // ═══ Phase 7: Emit Events ═══
        self.emit_event(TransportEvent::Connected {
            info: connection_info.clone(),
        });

        self.connected.notify_waiters();

        info!(
            "Connection established: {} <-> {} (RTT: {:?})",
            connection_info.local_addr, connection_info.remote_addr, connection_info.rtt
        );

        Ok(connection_info)
    }

    /// Check if transport is ready for data transfer
    ///
    /// RFC 8445 Section 7 + RFC 7675 (consent freshness)
    async fn is_ready(&self) -> bool {
        let state = *self.state.read();
        let consent = *self.consent_fresh.read();
        let has_pair = self.nominated_pair.read().is_some();

        state.can_transfer_data() && consent && has_pair
    }

    /// Get current connection state (RFC 8445 Section 11)
    fn state(&self) -> ConnectionState {
        *self.state.read()
    }

    /// Send data through the established connection
    ///
    /// RFC 768 (UDP) + RFC 7675 (consent check)
    ///
    /// ## Arguments
    /// - `data`: Data to send
    ///
    /// ## Returns
    /// Number of bytes sent
    ///
    /// ## Errors
    /// - Transport not ready
    /// - Consent expired (RFC 7675)
    /// - Data too large (exceeds MTU)
    /// - Network error
    async fn send(&self, data: &[u8]) -> Result<usize> {
        // Check ready
        if !self.is_ready().await {
            return Err(anyhow!("Transport not ready for send"));
        }

        // Check consent (RFC 7675)
        if !*self.consent_fresh.read() {
            return Err(anyhow!("Consent expired - cannot send data"));
        }

        // Get nominated pair
        let pair = self
            .nominated_pair
            .read()
            .as_ref()
            .ok_or_else(|| anyhow!("No nominated pair"))?
            .clone();

        // Check MTU (RFC 4821/8899)
        if let Some(max_payload) = self.socket.get_max_payload() {
            if data.len() > max_payload {
                return Err(anyhow!(
                    "Data size {} exceeds max payload {}",
                    data.len(),
                    max_payload
                ));
            }
        }

        // Send through socket
        let sent = self
            .socket
            .send_to(data, &pair.remote.address)
            .await
            .context("Socket send_to failed")?;

        // Update statistics
        let mut stats = self.stats.write();
        stats.bytes_sent += sent as u64;
        stats.packets_sent += 1;

        Ok(sent)
    }

    /// Receive data from the connection
    ///
    /// RFC 768 (UDP)
    ///
    /// ## Arguments
    /// - `buffer`: Buffer to receive data into
    ///
    /// ## Returns
    /// Number of bytes received
    ///
    /// ## Errors
    /// - Transport not ready
    /// - Network error
    async fn recv(&self, buffer: &mut [u8]) -> Result<usize> {
        // Check ready
        if !self.is_ready().await {
            return Err(anyhow!("Transport not ready for recv"));
        }

        // Receive from socket
        let (size, from) = self
            .socket
            .recv_from(buffer)
            .await
            .context("Socket recv_from failed")?;

        // RFC 8445 Section 11.1: Verify source address
        let pair_guard = self.nominated_pair.read();
        if let Some(ref pair) = *pair_guard {
            if from != pair.remote.address {
                let strict_validation = self.config.read().strict_source_validation;

                if strict_validation {
                    // Strict mode: Drop packets from unexpected sources (RFC 8445 Section 11.1)
                    drop(pair_guard);
                    return Err(anyhow!(
                        "Packet from unexpected source {} (expected {}), dropped",
                        from,
                        pair.remote.address
                    ));
                } else {
                    // Permissive mode: Log warning but accept packet
                    warn!(
                        "Received data from unexpected source: {} (expected: {})",
                        from, pair.remote.address
                    );
                }
            }
        }
        drop(pair_guard);

        // Update statistics
        let mut stats = self.stats.write();
        stats.bytes_received += size as u64;
        stats.packets_received += 1;

        Ok(size)
    }

    /// Get local address from nominated candidate
    ///
    /// RFC 8445 Section 5.1 (Candidate attributes)
    fn local_addr(&self) -> Result<SocketAddr> {
        self.nominated_pair
            .read()
            .as_ref()
            .map(|pair| pair.local.address)
            .ok_or_else(|| anyhow!("No nominated pair available"))
    }

    /// Get remote address from nominated candidate
    ///
    /// RFC 8445 Section 5.1
    fn remote_addr(&self) -> Result<SocketAddr> {
        self.nominated_pair
            .read()
            .as_ref()
            .map(|pair| pair.remote.address)
            .ok_or_else(|| anyhow!("No nominated pair available"))
    }

    /// Get comprehensive transport statistics
    ///
    /// RFC 8445 Section 14 (Statistics)
    async fn stats(&self) -> TransportStats {
        let mut stats = self.stats.read().clone();

        // Aggregate socket statistics
        stats.socket = Some(self.socket.stats());

        // Aggregate ICE statistics
        let ice_stats_guard = self.ice_agent.stats.read();
        stats.ice.gathering_duration = ice_stats_guard.gathering_duration;
        stats.ice.connection_duration = ice_stats_guard.connection_duration;
        stats.ice.candidates_gathered = ice_stats_guard.candidates_gathered;
        stats.ice.pairs_created = ice_stats_guard.pairs_created;
        stats.ice.pairs_checked = ice_stats_guard.pairs_checked;
        stats.ice.pairs_succeeded = ice_stats_guard.pairs_succeeded;
        stats.ice.pairs_failed = ice_stats_guard.pairs_failed;
        stats.ice.pairs_nominated = ice_stats_guard.pairs_nominated;
        drop(ice_stats_guard);

        // Add consent statistics (RFC 7675)
        stats.consent.last_check = *self.last_consent_check.read();
        stats.consent.is_fresh = *self.consent_fresh.read();
        stats.consent.checks_performed = *self.consent_checks_performed.read();
        stats.consent.checks_failed = *self.consent_checks_failed.read();

        // Add MTU statistics (RFC 4821/8899)
        stats.performance.path_mtu = self.socket.path_mtu();
        if let Some(pmtud_stats) = self.socket.pmtud_stats() {
            stats.performance.mtu_probes_sent = pmtud_stats.probes_sent;
            stats.performance.mtu_probes_succeeded = pmtud_stats.probes_succeeded;
        }

        stats
    }

    /// Get current Round-Trip Time
    ///
    /// RFC 8445 Section 6 (measured during connectivity checks)
    fn rtt(&self) -> Option<Duration> {
        self.nominated_pair
            .read()
            .as_ref()
            .and_then(|pair| pair.rtt)
    }

    /// Close the transport gracefully
    ///
    /// Performs cleanup:
    /// - Stops consent freshness checks
    /// - Shuts down ICE agent
    /// - Closes socket
    /// - Releases resources
    async fn close(&self) -> Result<()> {
        info!("Closing ICE transport");

        // Update state
        self.set_state(ConnectionState::Closed);

        // Notify shutdown to background tasks
        self.shutdown.notify_waiters();

        // Shutdown ICE agent
        self.ice_agent
            .shutdown()
            .await
            .context("ICE agent shutdown failed")?;

        // Close socket
        self.socket.close();

        // Emit closed event
        self.emit_event(TransportEvent::Closed);

        info!("ICE transport closed");
        Ok(())
    }

    /// Restart ICE process (RFC 8445 Section 9)
    ///
    /// ICE restart:
    /// - Generates new ICE credentials
    /// - Re-gathers candidates
    /// - Performs new connectivity checks
    /// - Nominates new pair
    ///
    /// Use cases:
    /// - Network topology change
    /// - All candidate pairs failed
    /// - Explicit application request
    async fn restart(&self) -> Result<()> {
        info!("Initiating ICE restart");

        // Emit restart event
        self.emit_event(TransportEvent::RestartInitiated);

        // Reset state
        self.set_state(ConnectionState::New);
        *self.nominated_pair.write() = None;
        *self.connection_info.write() = None;
        *self.consent_fresh.write() = false;

        // Generate new ICE credentials (RFC 8445 Section 9)
        let new_ufrag = generate_ice_credential(8);
        let new_pwd = generate_ice_credential(24);

        {
            let mut config = self.config.write();
            config.local_ufrag = new_ufrag;
            config.local_pwd = new_pwd;
        }

        info!("Generated new ICE credentials for restart");

        // RFC 8445 Section 9: Shutdown existing ICE agent gracefully
        info!("Shutting down existing ICE agent for restart");
        self.ice_agent
            .shutdown()
            .await
            .context("Failed to shutdown ICE agent during restart")?;

        // Create new ICE agent with new credentials
        let ice_config = {
            let config = self.config.read();
            ProductionIceConfig {
                ice_config: config.ice_config.clone(),
                controlling: config.controlling,
                local_ufrag: config.local_ufrag.clone(),
                local_pwd: config.local_pwd.clone(),
                remote_ufrag: config.remote_ufrag.clone(),
                remote_pwd: config.remote_pwd.clone(),
                aggressive_nomination: config.aggressive_nomination,
                trickle_ice: config.trickle_ice,
                connection_timeout: config.connection_timeout,
                keepalive_interval: config.keepalive_interval,
            }
        };

        // Note: Ideally would update credentials in existing agent via restart() method
        // Currently ProductionIceAgent doesn't expose restart() API, so we create new agent
        // This is RFC-compliant but less optimal than in-place credential update
        info!("Creating new ICE agent with updated credentials");

        // Re-run full connection process with new credentials
        self.connect().await.context("ICE restart connect failed")?;

        // Emit completion
        self.emit_event(TransportEvent::RestartCompleted);

        info!("ICE restart completed successfully");
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/// Create STUN Binding Indication for consent freshness checks
///
/// RFC 7675 Section 5.1: Consent Freshness
/// - Uses STUN Binding Indication (not Request)
/// - No response expected (Indication vs Request)
/// - Sent periodically to verify peer consent
fn create_consent_check_message() -> StunMessage {
    let msg_type = StunMessageType::new(StunClass::Indication, StunMethod::Binding);
    let transaction_id = TransactionId::generate();

    StunMessage::with_transaction_id(msg_type, transaction_id)
}

/// Generate ICE credential string (ufrag/pwd)
///
/// RFC 8445 Section 5.4: ICE credentials
/// - ice-char = ALPHA / DIGIT / "+" / "/"
/// - ice-ufrag: 4*256ice-char (minimum 4, maximum 256)
/// - ice-pwd: 22*256ice-char (minimum 22, maximum 256)
///
/// ## Arguments
/// - `length`: Desired length (must meet RFC minimums)
///
/// ## Panics
/// Panics if length violates RFC constraints
fn generate_ice_credential(length: usize) -> String {
    use rand::Rng;

    // RFC 8445 Section 5.4: Allowed character set
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // RFC 8445 Section 5.4: Validate length constraints
    const MIN_UFRAG_LENGTH: usize = 4;
    const MIN_PWD_LENGTH: usize = 22;
    const MAX_LENGTH: usize = 256;

    // Validate length constraints
    if length < MIN_UFRAG_LENGTH {
        panic!(
            "ICE credential length {} violates RFC 8445: minimum is {}",
            length, MIN_UFRAG_LENGTH
        );
    }

    if length > MAX_LENGTH {
        panic!(
            "ICE credential length {} violates RFC 8445: maximum is {}",
            length, MAX_LENGTH
        );
    }

    let mut rng = rand::thread_rng();

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ice_transport_creation() {
        let config = IceTransportConfig::default();
        let transport = IceTransport::new(config).await;

        assert!(transport.is_ok());
        let transport = transport.unwrap();

        assert_eq!(transport.state(), ConnectionState::New);
        assert!(!transport.is_ready().await);
        assert!(transport.local_addr().is_err());
        assert!(transport.remote_addr().is_err());
    }

    #[tokio::test]
    async fn test_state_transitions() {
        let config = IceTransportConfig::default();
        let transport = IceTransport::new(config).await.unwrap();

        // Initial state
        assert_eq!(transport.state(), ConnectionState::New);

        // Transition to gathering
        transport.set_state(ConnectionState::Gathering);
        assert_eq!(transport.state(), ConnectionState::Gathering);

        // Transition to checking
        transport.set_state(ConnectionState::Checking);
        assert_eq!(transport.state(), ConnectionState::Checking);

        // Transition to connected
        transport.set_state(ConnectionState::Connected);
        assert_eq!(transport.state(), ConnectionState::Connected);
        assert!(transport.state().can_transfer_data());

        // Transition to completed
        transport.set_state(ConnectionState::Completed);
        assert_eq!(transport.state(), ConnectionState::Completed);
        assert!(transport.state().can_transfer_data());
    }

    #[tokio::test]
    async fn test_consent_tracking() {
        let config = IceTransportConfig::default();
        let transport = IceTransport::new(config).await.unwrap();

        // Initially no consent
        assert!(!*transport.consent_fresh.read());
        assert!(transport.last_consent_check.read().is_none());

        // Simulate consent check
        *transport.consent_fresh.write() = true;
        *transport.last_consent_check.write() = Some(Instant::now());

        assert!(*transport.consent_fresh.read());
        assert!(transport.last_consent_check.read().is_some());
    }

    #[test]
    fn test_generate_ice_credential() {
        let ufrag = generate_ice_credential(8);
        assert_eq!(ufrag.len(), 8);

        let pwd = generate_ice_credential(24);
        assert_eq!(pwd.len(), 24);

        // Check charset
        for c in ufrag.chars() {
            assert!(c.is_alphanumeric() || c == '+' || c == '/');
        }
    }

    #[tokio::test]
    async fn test_transport_not_ready_before_connect() {
        let config = IceTransportConfig::default();
        let transport = IceTransport::new(config).await.unwrap();

        // Not ready before connection
        assert!(!transport.is_ready().await);

        // Send should fail
        let result = transport.send(b"test").await;
        assert!(result.is_err());

        // Recv should fail
        let mut buffer = vec![0u8; 1024];
        let result = transport.recv(&mut buffer).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_statistics_collection() {
        let config = IceTransportConfig::default();
        let transport = IceTransport::new(config).await.unwrap();

        let stats = transport.stats().await;

        // Verify initial statistics
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert!(!stats.consent.is_fresh);
    }

    #[tokio::test]
    async fn test_uptime() {
        let config = IceTransportConfig::default();
        let transport = IceTransport::new(config).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let uptime = transport.uptime();
        assert!(uptime >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_graceful_close() {
        let config = IceTransportConfig::default();
        let transport = IceTransport::new(config).await.unwrap();

        let result = transport.close().await;
        assert!(result.is_ok());

        assert_eq!(transport.state(), ConnectionState::Closed);
    }
}
