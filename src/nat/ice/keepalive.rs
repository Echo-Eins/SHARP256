// src/nat/ice/keepalive.rs
//! ICE keepalive and consent freshness implementation (RFC 7675)
//!
//! This module implements consent freshness and keepalive mechanisms to ensure
//! that established ICE connections remain active and that peers continue to
//! consent to receiving traffic.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, broadcast, mpsc};
use tokio::time::{interval, sleep, timeout};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};

use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::candidate::CandidatePair;
use crate::nat::ice::connectivity::IceCredentials;
use crate::nat::stun::{Message, MessageType, TransactionId, Attribute, AttributeType, AttributeValue};

/// Consent freshness configuration per RFC 7675
#[derive(Debug, Clone)]
pub struct ConsentConfig {
    /// Consent freshness timeout (default: 30 seconds)
    pub consent_timeout: Duration,

    /// Keepalive interval (default: 25 seconds)
    pub keepalive_interval: Duration,

    /// Maximum keepalive interval with jitter (default: 50 seconds)
    pub max_keepalive_interval: Duration,

    /// Binding request timeout
    pub binding_timeout: Duration,

    /// Maximum retransmissions for binding requests
    pub max_retransmissions: u32,

    /// RTO initial value
    pub rto_initial: Duration,

    /// RTO maximum value
    pub rto_max: Duration,

    /// Enable adaptive keepalive intervals
    pub adaptive_keepalive: bool,

    /// Network activity detection window
    pub activity_window: Duration,

    /// Minimum time between consent checks
    pub min_consent_interval: Duration,
}

impl Default for ConsentConfig {
    fn default() -> Self {
        Self {
            consent_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(25),
            max_keepalive_interval: Duration::from_secs(50),
            binding_timeout: Duration::from_secs(5),
            max_retransmissions: 3,
            rto_initial: Duration::from_millis(500),
            rto_max: Duration::from_secs(3),
            adaptive_keepalive: true,
            activity_window: Duration::from_secs(60),
            min_consent_interval: Duration::from_secs(5),
        }
    }
}

/// Consent state for a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentState {
    /// Consent is fresh (recently confirmed)
    Fresh,
    /// Consent is stale (approaching timeout)
    Stale,
    /// Consent has expired
    Expired,
    /// Consent check is in progress
    Checking,
    /// Consent checking failed
    Failed,
}

/// Connection consent information
#[derive(Debug, Clone)]
pub struct ConnectionConsent {
    /// Connection identifier
    pub connection_id: String,

    /// Selected candidate pair
    pub pair: CandidatePair,

    /// Current consent state
    pub state: ConsentState,

    /// Last successful consent check
    pub last_consent: Instant,

    /// Last activity timestamp
    pub last_activity: Instant,

    /// Last keepalive sent
    pub last_keepalive: Instant,

    /// Pending consent check transaction
    pub pending_transaction: Option<TransactionId>,

    /// Consecutive failed consent checks
    pub failed_checks: u32,

    /// Total successful consent checks
    pub successful_checks: u64,

    /// Current RTO for this connection
    pub current_rto: Duration,

    /// Next scheduled consent check
    pub next_consent_check: Instant,

    /// Network activity statistics
    pub activity_stats: ActivityStats,

    /// Socket for this connection
    pub socket: Arc<UdpSocket>,
}

/// Network activity statistics
#[derive(Debug, Clone, Default)]
pub struct ActivityStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub last_send_time: Option<Instant>,
    pub last_receive_time: Option<Instant>,
}

/// Consent freshness events
#[derive(Debug, Clone)]
pub enum ConsentEvent {
    /// Consent is fresh for connection
    ConsentFresh {
        connection_id: String,
        timestamp: Instant,
    },

    /// Consent became stale
    ConsentStale {
        connection_id: String,
        timestamp: Instant,
    },

    /// Consent expired
    ConsentExpired {
        connection_id: String,
        timestamp: Instant,
    },

    /// Consent check failed
    ConsentCheckFailed {
        connection_id: String,
        error: String,
        timestamp: Instant,
    },

    /// Connection activity detected
    ActivityDetected {
        connection_id: String,
        bytes: u64,
        direction: ActivityDirection,
        timestamp: Instant,
    },

    /// Keepalive sent
    KeepaliveSent {
        connection_id: String,
        timestamp: Instant,
    },

    /// Connection should be terminated
    ConnectionTerminated {
        connection_id: String,
        reason: String,
        timestamp: Instant,
    },
}

/// Activity direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityDirection {
    Inbound,
    Outbound,
}

/// Consent freshness manager
pub struct ConsentManager {
    /// Configuration
    config: ConsentConfig,

    /// Local ICE credentials
    local_credentials: IceCredentials,

    /// Remote ICE credentials
    remote_credentials: Arc<RwLock<Option<IceCredentials>>>,

    /// Active connections being monitored
    connections: Arc<RwLock<HashMap<String, ConnectionConsent>>>,

    /// Pending consent checks
    pending_checks: Arc<RwLock<HashMap<TransactionId, String>>>,

    /// Event broadcaster
    event_sender: broadcast::Sender<ConsentEvent>,

    /// Command channel
    command_sender: mpsc::UnboundedSender<ConsentCommand>,
    command_receiver: Arc<Mutex<mpsc::UnboundedReceiver<ConsentCommand>>>,

    /// Statistics
    stats: Arc<RwLock<ConsentStats>>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,
}

/// Consent command for external control
#[derive(Debug)]
enum ConsentCommand {
    /// Add connection to monitor
    AddConnection {
        connection_id: String,
        pair: CandidatePair,
        socket: Arc<UdpSocket>,
    },

    /// Remove connection from monitoring
    RemoveConnection {
        connection_id: String,
    },

    /// Record network activity
    RecordActivity {
        connection_id: String,
        bytes: u64,
        direction: ActivityDirection,
    },

    /// Process STUN response
    ProcessStunResponse {
        transaction_id: TransactionId,
        success: bool,
        from: SocketAddr,
    },

    /// Force consent check
    ForceConsentCheck {
        connection_id: String,
    },
}

/// Consent statistics
#[derive(Debug, Default, Clone)]
pub struct ConsentStats {
    pub active_connections: u32,
    pub total_consent_checks: u64,
    pub successful_consent_checks: u64,
    pub failed_consent_checks: u64,
    pub expired_connections: u64,
    pub total_keepalives_sent: u64,
    pub average_consent_rtt: Duration,
    pub consent_success_rate: f64,
    pub connections_by_state: HashMap<ConsentState, u32>,
}

impl ConsentManager {
    /// Create new consent manager
    pub fn new(config: ConsentConfig, local_credentials: IceCredentials) -> Self {
        let (event_sender, _) = broadcast::channel(1000);
        let (command_sender, command_receiver) = mpsc::unbounded_channel();

        Self {
            config,
            local_credentials,
            remote_credentials: Arc::new(RwLock::new(None)),
            connections: Arc::new(RwLock::new(HashMap::new())),
            pending_checks: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            command_sender,
            command_receiver: Arc::new(Mutex::new(command_receiver)),
            stats: Arc::new(RwLock::new(ConsentStats::default())),
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Start consent management
    pub async fn start(&self) -> NatResult<()> {
        info!("Starting ICE consent freshness manager");

        // Start background tasks
        let command_task = self.process_commands();
        let consent_task = self.process_consent_checks();
        let keepalive_task = self.process_keepalives();
        let cleanup_task = self.process_cleanup();

        tokio::select! {
            result = command_task => {
                if let Err(e) = result {
                    error!("Consent command processing failed: {}", e);
                }
            }
            result = consent_task => {
                if let Err(e) = result {
                    error!("Consent check processing failed: {}", e);
                }
            }
            result = keepalive_task => {
                if let Err(e) = result {
                    error!("Keepalive processing failed: {}", e);
                }
            }
            result = cleanup_task => {
                if let Err(e) = result {
                    error!("Cleanup processing failed: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Set remote credentials
    pub async fn set_remote_credentials(&self, credentials: IceCredentials) {
        *self.remote_credentials.write().await = Some(credentials);
    }

    /// Add connection to monitor
    pub async fn add_connection(
        &self,
        connection_id: String,
        pair: CandidatePair,
        socket: Arc<UdpSocket>,
    ) -> NatResult<()> {
        self.command_sender.send(ConsentCommand::AddConnection {
            connection_id,
            pair,
            socket,
        }).map_err(|_| NatError::Configuration("Failed to send consent command".to_string()))?;

        Ok(())
    }

    /// Remove connection from monitoring
    pub async fn remove_connection(&self, connection_id: String) -> NatResult<()> {
        self.command_sender.send(ConsentCommand::RemoveConnection {
            connection_id,
        }).map_err(|_| NatError::Configuration("Failed to send consent command".to_string()))?;

        Ok(())
    }

    /// Record network activity
    pub async fn record_activity(
        &self,
        connection_id: String,
        bytes: u64,
        direction: ActivityDirection,
    ) -> NatResult<()> {
        self.command_sender.send(ConsentCommand::RecordActivity {
            connection_id,
            bytes,
            direction,
        }).map_err(|_| NatError::Configuration("Failed to send consent command".to_string()))?;

        Ok(())
    }

    /// Process STUN response for consent
    pub async fn process_stun_response(
        &self,
        transaction_id: TransactionId,
        success: bool,
        from: SocketAddr,
    ) -> NatResult<()> {
        self.command_sender.send(ConsentCommand::ProcessStunResponse {
            transaction_id,
            success,
            from,
        }).map_err(|_| NatError::Configuration("Failed to send consent command".to_string()))?;

        Ok(())
    }

    /// Force consent check
    pub async fn force_consent_check(&self, connection_id: String) -> NatResult<()> {
        self.command_sender.send(ConsentCommand::ForceConsentCheck {
            connection_id,
        }).map_err(|_| NatError::Configuration("Failed to send consent command".to_string()))?;

        Ok(())
    }

    /// Process commands
    async fn process_commands(&self) -> NatResult<()> {
        let mut receiver = self.command_receiver.lock().await;

        while let Some(command) = receiver.recv().await {
            if *self.shutdown.read().await {
                break;
            }

            match command {
                ConsentCommand::AddConnection { connection_id, pair, socket } => {
                    self.handle_add_connection(connection_id, pair, socket).await;
                }

                ConsentCommand::RemoveConnection { connection_id } => {
                    self.handle_remove_connection(connection_id).await;
                }

                ConsentCommand::RecordActivity { connection_id, bytes, direction } => {
                    self.handle_record_activity(connection_id, bytes, direction).await;
                }

                ConsentCommand::ProcessStunResponse { transaction_id, success, from } => {
                    self.handle_stun_response(transaction_id, success, from).await;
                }

                ConsentCommand::ForceConsentCheck { connection_id } => {
                    if let Err(e) = self.perform_consent_check(&connection_id).await {
                        warn!("Failed to perform forced consent check: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle add connection
    async fn handle_add_connection(
        &self,
        connection_id: String,
        pair: CandidatePair,
        socket: Arc<UdpSocket>,
    ) {
        let now = Instant::now();

        let consent = ConnectionConsent {
            connection_id: connection_id.clone(),
            pair,
            state: ConsentState::Fresh,
            last_consent: now,
            last_activity: now,
            last_keepalive: now,
            pending_transaction: None,
            failed_checks: 0,
            successful_checks: 0,
            current_rto: self.config.rto_initial,
            next_consent_check: now + self.config.consent_timeout / 2, // Check at half timeout
            activity_stats: ActivityStats::default(),
            socket,
        };

        self.connections.write().await.insert(connection_id.clone(), consent);

        info!("Added connection {} to consent monitoring", connection_id);

        // Update statistics
        self.update_connection_stats().await;
    }

    /// Handle remove connection
    async fn handle_remove_connection(&self, connection_id: String) {
        if self.connections.write().await.remove(&connection_id).is_some() {
            info!("Removed connection {} from consent monitoring", connection_id);
            self.update_connection_stats().await;
        }
    }

    /// Handle record activity
    async fn handle_record_activity(
        &self,
        connection_id: String,
        bytes: u64,
        direction: ActivityDirection,
    ) {
        let mut connections = self.connections.write().await;
        if let Some(consent) = connections.get_mut(&connection_id) {
            let now = Instant::now();

            // Update activity statistics
            match direction {
                ActivityDirection::Inbound => {
                    consent.activity_stats.bytes_received += bytes;
                    consent.activity_stats.packets_received += 1;
                    consent.activity_stats.last_receive_time = Some(now);
                }
                ActivityDirection::Outbound => {
                    consent.activity_stats.bytes_sent += bytes;
                    consent.activity_stats.packets_sent += 1;
                    consent.activity_stats.last_send_time = Some(now);
                }
            }

            consent.last_activity = now;

            // Activity is implicit consent for inbound traffic
            if direction == ActivityDirection::Inbound {
                consent.last_consent = now;
                if consent.state != ConsentState::Fresh {
                    consent.state = ConsentState::Fresh;

                    let _ = self.event_sender.send(ConsentEvent::ConsentFresh {
                        connection_id: connection_id.clone(),
                        timestamp: now,
                    });
                }
            }

            // Emit activity event
            let _ = self.event_sender.send(ConsentEvent::ActivityDetected {
                connection_id,
                bytes,
                direction,
                timestamp: now,
            });
        }
    }

    /// Handle STUN response
    async fn handle_stun_response(
        &self,
        transaction_id: TransactionId,
        success: bool,
        from: SocketAddr,
    ) {
        // Find connection for this transaction
        let connection_id = {
            let pending = self.pending_checks.read().await;
            pending.get(&transaction_id).cloned()
        };

        if let Some(conn_id) = connection_id {
            // Remove from pending
            self.pending_checks.write().await.remove(&transaction_id);

            // Update connection consent
            let mut connections = self.connections.write().await;
            if let Some(consent) = connections.get_mut(&conn_id) {
                let now = Instant::now();

                if success {
                    // Successful consent check
                    consent.last_consent = now;
                    consent.state = ConsentState::Fresh;
                    consent.failed_checks = 0;
                    consent.successful_checks += 1;
                    consent.pending_transaction = None;

                    // Update RTO (successful response)
                    consent.current_rto = (consent.current_rto * 3 / 4).max(self.config.rto_initial);

                    // Schedule next check
                    let next_interval = if self.config.adaptive_keepalive {
                        self.calculate_adaptive_interval(consent)
                    } else {
                        self.config.keepalive_interval
                    };
                    consent.next_consent_check = now + next_interval;

                    // Update statistics
                    self.stats.write().await.successful_consent_checks += 1;

                    let _ = self.event_sender.send(ConsentEvent::ConsentFresh {
                        connection_id: conn_id,
                        timestamp: now,
                    });

                    debug!("Consent check succeeded for connection {}", conn_id);
                } else {
                    // Failed consent check
                    consent.failed_checks += 1;
                    consent.pending_transaction = None;

                    // Update RTO (exponential backoff)
                    consent.current_rto = (consent.current_rto * 2).min(self.config.rto_max);

                    if consent.failed_checks >= self.config.max_retransmissions {
                        // Too many failures, mark as failed
                        consent.state = ConsentState::Failed;

                        let _ = self.event_sender.send(ConsentEvent::ConsentCheckFailed {
                            connection_id: conn_id.clone(),
                            error: "Maximum retransmissions exceeded".to_string(),
                            timestamp: now,
                        });

                        let _ = self.event_sender.send(ConsentEvent::ConnectionTerminated {
                            connection_id: conn_id,
                            reason: "Consent check failures".to_string(),
                            timestamp: now,
                        });
                    } else {
                        // Retry after RTO
                        consent.next_consent_check = now + consent.current_rto;
                    }

                    // Update statistics
                    self.stats.write().await.failed_consent_checks += 1;

                    warn!("Consent check failed for connection {} (attempt {})",
                          conn_id, consent.failed_checks);
                }
            }
        }
    }

    /// Process consent checks
    async fn process_consent_checks(&self) -> NatResult<()> {
        let mut timer = interval(Duration::from_millis(100));

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            let now = Instant::now();
            let connections_to_check: Vec<String> = {
                let connections = self.connections.read().await;
                connections.iter()
                    .filter(|(_, consent)| {
                        consent.state != ConsentState::Failed &&
                            consent.pending_transaction.is_none() &&
                            now >= consent.next_consent_check
                    })
                    .map(|(id, _)| id.clone())
                    .collect()
            };

            for connection_id in connections_to_check {
                if let Err(e) = self.perform_consent_check(&connection_id).await {
                    warn!("Failed to perform consent check for {}: {}", connection_id, e);
                }
            }

            // Check for expired consent
            self.check_expired_consent(now).await;
        }

        Ok(())
    }

    /// Perform consent check for connection
    async fn perform_consent_check(&self, connection_id: &str) -> NatResult<()> {
        let (socket, remote_addr, credentials) = {
            let connections = self.connections.read().await;
            let consent = connections.get(connection_id)
                .ok_or_else(|| NatError::Configuration("Connection not found".to_string()))?;

            let remote_addr = consent.pair.remote.socket_addr()
                .ok_or_else(|| NatError::Configuration("No remote address".to_string()))?;

            let credentials = self.remote_credentials.read().await
                .as_ref()
                .ok_or_else(|| NatError::Configuration("No remote credentials".to_string()))?
                .clone();

            (consent.socket.clone(), remote_addr, credentials)
        };

        // Create binding request for consent check
        let transaction_id = TransactionId::generate();
        let mut request = Message::new(MessageType::BindingRequest, transaction_id);

        // Add USERNAME attribute
        let username = format!("{}:{}", credentials.ufrag, self.local_credentials.ufrag);
        request.add_attribute(Attribute {
            attribute_type: AttributeType::Username,
            value: AttributeValue::Username(username),
        })?;

        // Add MESSAGE-INTEGRITY
        request.add_message_integrity(&credentials.password)?;

        // Add FINGERPRINT
        request.add_fingerprint()?;

        // Send the request
        let data = request.to_bytes()?;
        socket.send_to(&data, remote_addr).await
            .map_err(|e| NatError::Network(e))?;

        // Update connection state
        {
            let mut connections = self.connections.write().await;
            if let Some(consent) = connections.get_mut(connection_id) {
                consent.pending_transaction = Some(transaction_id);
                consent.state = ConsentState::Checking;
            }
        }

        // Track pending check
        self.pending_checks.write().await.insert(transaction_id, connection_id.to_string());

        // Update statistics
        self.stats.write().await.total_consent_checks += 1;

        debug!("Sent consent check for connection {}", connection_id);
        Ok(())
    }

    /// Check for expired consent
    async fn check_expired_consent(&self, now: Instant) {
        let expired_connections: Vec<String> = {
            let mut connections = self.connections.write().await;
            let mut expired = Vec::new();

            for (connection_id, consent) in connections.iter_mut() {
                let time_since_consent = now.duration_since(consent.last_consent);

                if time_since_consent > self.config.consent_timeout {
                    if consent.state != ConsentState::Expired {
                        consent.state = ConsentState::Expired;
                        expired.push(connection_id.clone());
                    }
                } else if time_since_consent > self.config.consent_timeout / 2 {
                    if consent.state == ConsentState::Fresh {
                        consent.state = ConsentState::Stale;

                        let _ = self.event_sender.send(ConsentEvent::ConsentStale {
                            connection_id: connection_id.clone(),
                            timestamp: now,
                        });
                    }
                }
            }

            expired
        };

        // Emit expired events
        for connection_id in expired_connections {
            self.stats.write().await.expired_connections += 1;

            let _ = self.event_sender.send(ConsentEvent::ConsentExpired {
                connection_id: connection_id.clone(),
                timestamp: now,
            });

            let _ = self.event_sender.send(ConsentEvent::ConnectionTerminated {
                connection_id,
                reason: "Consent expired".to_string(),
                timestamp: now,
            });

            warn!("Consent expired for connection {}", connection_id);
        }
    }

    /// Process keepalives
    async fn process_keepalives(&self) -> NatResult<()> {
        let mut timer = interval(self.config.keepalive_interval);

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            let now = Instant::now();
            let connections_for_keepalive: Vec<String> = {
                let connections = self.connections.read().await;
                connections.iter()
                    .filter(|(_, consent)| {
                        consent.state == ConsentState::Fresh &&
                            now.duration_since(consent.last_keepalive) >= self.config.keepalive_interval &&
                            now.duration_since(consent.last_activity) >= self.config.activity_window
                    })
                    .map(|(id, _)| id.clone())
                    .collect()
            };

            for connection_id in connections_for_keepalive {
                if let Err(e) = self.send_keepalive(&connection_id).await {
                    warn!("Failed to send keepalive for {}: {}", connection_id, e);
                }
            }
        }

        Ok(())
    }

    /// Send keepalive for connection
    async fn send_keepalive(&self, connection_id: &str) -> NatResult<()> {
        // Use consent check as keepalive
        self.perform_consent_check(connection_id).await?;

        // Update last keepalive time
        {
            let mut connections = self.connections.write().await;
            if let Some(consent) = connections.get_mut(connection_id) {
                consent.last_keepalive = Instant::now();
            }
        }

        // Update statistics
        self.stats.write().await.total_keepalives_sent += 1;

        // Emit event
        let _ = self.event_sender.send(ConsentEvent::KeepaliveSent {
            connection_id: connection_id.to_string(),
            timestamp: Instant::now(),
        });

        debug!("Sent keepalive for connection {}", connection_id);
        Ok(())
    }

    /// Calculate adaptive keepalive interval
    fn calculate_adaptive_interval(&self, consent: &ConnectionConsent) -> Duration {
        // Base interval on network activity and success rate
        let base_interval = self.config.keepalive_interval;

        // If we have recent activity, extend interval
        let activity_factor = if consent.last_activity.elapsed() < self.config.activity_window {
            1.5 // Extend interval if recent activity
        } else {
            1.0
        };

        // Success rate factor
        let success_factor = if consent.successful_checks > 0 && consent.failed_checks == 0 {
            1.2 // Extend if no recent failures
        } else {
            0.8 // Shorten if recent failures
        };

        let adaptive_interval = Duration::from_millis(
            (base_interval.as_millis() as f64 * activity_factor * success_factor) as u64
        );

        adaptive_interval
            .max(self.config.min_consent_interval)
            .min(self.config.max_keepalive_interval)
    }

    /// Process cleanup
    async fn process_cleanup(&self) -> NatResult<()> {
        let mut timer = interval(Duration::from_secs(30));

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            // Remove failed and expired connections
            let connections_to_remove: Vec<String> = {
                let connections = self.connections.read().await;
                connections.iter()
                    .filter(|(_, consent)| {
                        matches!(consent.state, ConsentState::Failed | ConsentState::Expired)
                    })
                    .map(|(id, _)| id.clone())
                    .collect()
            };

            for connection_id in connections_to_remove {
                self.handle_remove_connection(connection_id).await;
            }

            // Update statistics
            self.update_connection_stats().await;
        }

        Ok(())
    }

    /// Update connection statistics
    async fn update_connection_stats(&self) {
        let connections = self.connections.read().await;
        let mut stats = self.stats.write().await;

        stats.active_connections = connections.len() as u32;

        // Count by state
        stats.connections_by_state.clear();
        for consent in connections.values() {
            *stats.connections_by_state.entry(consent.state).or_insert(0) += 1;
        }

        // Calculate success rate
        let total_checks = stats.total_consent_checks;
        if total_checks > 0 {
            stats.consent_success_rate = stats.successful_consent_checks as f64 / total_checks as f64;
        }
    }

    /// Get connection consent state
    pub async fn get_consent_state(&self, connection_id: &str) -> Option<ConsentState> {
        let connections = self.connections.read().await;
        connections.get(connection_id).map(|c| c.state)
    }

    /// Get all connections
    pub async fn get_connections(&self) -> HashMap<String, ConnectionConsent> {
        self.connections.read().await.clone()
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> ConsentStats {
        self.stats.read().await.clone()
    }

    /// Subscribe to consent events
    pub fn subscribe_events(&self) -> broadcast::Receiver<ConsentEvent> {
        self.event_sender.subscribe()
    }

    /// Stop consent manager
    pub async fn stop(&self) {
        *self.shutdown.write().await = true;
        info!("ICE consent freshness manager stopped");
    }
}

/// Helper functions for consent freshness

/// Create consent check binding request
pub fn create_consent_binding_request(
    local_credentials: &IceCredentials,
    remote_credentials: &IceCredentials,
) -> NatResult<Message> {
    let transaction_id = TransactionId::generate();
    let mut request = Message::new(MessageType::BindingRequest, transaction_id);

    // Add USERNAME
    let username = format!("{}:{}", remote_credentials.ufrag, local_credentials.ufrag);
    request.add_attribute(Attribute {
        attribute_type: AttributeType::Username,
        value: AttributeValue::Username(username),
    })?;

    // Add MESSAGE-INTEGRITY
    request.add_message_integrity(&remote_credentials.password)?;

    // Add FINGERPRINT
    request.add_fingerprint()?;

    Ok(request)
}

/// Check if STUN message is a valid consent response
pub fn is_valid_consent_response(
    message: &Message,
    expected_transaction: &TransactionId,
    credentials: &IceCredentials,
) -> bool {
    // Check transaction ID
    if message.transaction_id != *expected_transaction {
        return false;
    }

    // Check message type
    if message.message_type != MessageType::BindingSuccessResponse {
        return false;
    }

    // Validate MESSAGE-INTEGRITY
    message.validate_message_integrity(&credentials.password).unwrap_or(false)
}

/// Calculate jittered keepalive interval
pub fn calculate_jittered_interval(base_interval: Duration, max_jitter: Duration) -> Duration {
    use rand::Rng;

    let jitter_ms = rand::thread_rng().gen_range(0..max_jitter.as_millis() as u64);
    base_interval + Duration::from_millis(jitter_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::ice::candidate::{Candidate, CandidateExtensions, TransportProtocol};

    #[tokio::test]
    async fn test_consent_manager_creation() {
        let config = ConsentConfig::default();
        let credentials = IceCredentials::new();
        let manager = ConsentManager::new(config, credentials);

        assert_eq!(manager.config.consent_timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_add_remove_connection() {
        let config = ConsentConfig::default();
        let credentials = IceCredentials::new();
        let manager = ConsentManager::new(config, credentials);

        // Create test pair
        let local = Candidate::new_host(
            "192.168.1.1:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );
        let remote = Candidate::new_host(
            "192.168.1.2:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );
        let pair = crate::nat::ice::candidate::CandidatePair::new(local, remote, true);

        let socket = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap());

        manager.add_connection("test_conn".to_string(), pair, socket).await.unwrap();

        // Allow some time for processing
        tokio::time::sleep(Duration::from_millis(10)).await;

        let connections = manager.get_connections().await;
        assert!(connections.contains_key("test_conn"));

        manager.remove_connection("test_conn".to_string()).await.unwrap();

        // Allow some time for processing
        tokio::time::sleep(Duration::from_millis(10)).await;

        let connections = manager.get_connections().await;
        assert!(!connections.contains_key("test_conn"));
    }

    #[test]
    fn test_adaptive_interval_calculation() {
        let config = ConsentConfig::default();
        let credentials = IceCredentials::new();
        let manager = ConsentManager::new(config, credentials);

        let mut consent = ConnectionConsent {
            connection_id: "test".to_string(),
            pair: crate::nat::ice::candidate::CandidatePair::new(
                Candidate::new_host(
                    "192.168.1.1:12345".parse().unwrap(),
                    1,
                    TransportProtocol::Udp,
                    CandidateExtensions::new(),
                ),
                Candidate::new_host(
                    "192.168.1.2:12345".parse().unwrap(),
                    1,
                    TransportProtocol::Udp,
                    CandidateExtensions::new(),
                ),
                true
            ),
            state: ConsentState::Fresh,
            last_consent: Instant::now(),
            last_activity: Instant::now() - Duration::from_secs(70), // Old activity
            last_keepalive: Instant::now(),
            pending_transaction: None,
            failed_checks: 0,
            successful_checks: 10,
            current_rto: Duration::from_millis(500),
            next_consent_check: Instant::now(),
            activity_stats: ActivityStats::default(),
            socket: Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").unwrap()),
        };

        let interval = manager.calculate_adaptive_interval(&consent);
        assert!(interval >= manager.config.min_consent_interval);
        assert!(interval <= manager.config.max_keepalive_interval);
    }

    #[test]
    fn test_jittered_interval() {
        let base = Duration::from_secs(25);
        let max_jitter = Duration::from_secs(5);

        let jittered = calculate_jittered_interval(base, max_jitter);
        assert!(jittered >= base);
        assert!(jittered <= base + max_jitter);
    }

    #[tokio::test]
    async fn test_activity_recording() {
        let config = ConsentConfig::default();
        let credentials = IceCredentials::new();
        let manager = ConsentManager::new(config, credentials);

        // Setup a connection first
        let local = Candidate::new_host(
            "192.168.1.1:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );
        let remote = Candidate::new_host(
            "192.168.1.2:12345".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            CandidateExtensions::new(),
        );
        let pair = crate::nat::ice::candidate::CandidatePair::new(local, remote, true);
        let socket = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap());

        manager.add_connection("test_conn".to_string(), pair, socket).await.unwrap();

        // Record activity
        manager.record_activity(
            "test_conn".to_string(),
            1024,
            ActivityDirection::Inbound,
        ).await.unwrap();

        // Allow processing
        tokio::time::sleep(Duration::from_millis(10)).await;

        let connections = manager.get_connections().await;
        let consent = connections.get("test_conn").unwrap();
        assert_eq!(consent.activity_stats.bytes_received, 1024);
        assert_eq!(consent.activity_stats.packets_received, 1);
    }
}