// src/nat/ice/connectivity.rs
//! ICE connectivity checks implementation (RFC 8445 Section 7)
//!
//! This module implements the complete connectivity check procedure including:
//! - Check list construction and prioritization
//! - Triggered and ordinary checks
//! - Response processing and validation
//! - Pair state management
//! - Frozen/waiting state transitions

use std::collections::{HashMap, HashSet, VecDeque, BTreeMap};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, mpsc, broadcast};
use tokio::time::{interval, timeout, sleep};
use tracing::{debug, info, warn, error, trace};
use rand::{thread_rng, Rng};
use serde::{Serialize, Deserialize};

use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::candidate::{
    Candidate, CandidateType, TransportProtocol, CandidatePair, CandidatePairState
};
use crate::nat::ice::priority;
use crate::nat::stun::{
    Message, MessageType, TransactionId, Attribute, AttributeType, AttributeValue,
    StunError
};

/// Connectivity check intervals per RFC 8445
const RTO_INITIAL: Duration = Duration::from_millis(500);
const RTO_MAX: Duration = Duration::from_secs(3);
const RTO_CACHE_DURATION: Duration = Duration::from_secs(30);
const MAX_RETRANSMISSIONS: u32 = 7;
const CONSENT_FRESHNESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Timing constants
const TA_TIMER_INTERVAL: Duration = Duration::from_millis(50); // Ta timer (check scheduling)
const KEEPALIVE_TIMER_INTERVAL: Duration = Duration::from_secs(15);

/// ICE credentials for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCredentials {
    pub ufrag: String,
    pub password: String,
}

impl IceCredentials {
    pub fn new() -> Self {
        Self {
            ufrag: generate_ice_string(4),
            password: generate_ice_string(22),
        }
    }

    pub fn generate_new() -> Self {
        Self::new()
    }
}

/// Generate ICE-chars string per RFC 8445
fn generate_ice_string(length: usize) -> String {
    use rand::Rng;
    const ICE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

    let mut rng = thread_rng();
    (0..length)
        .map(|_| ICE_CHARS[rng.gen_range(0..ICE_CHARS.len())] as char)
        .collect()
}

/// Connectivity check result
#[derive(Debug, Clone)]
pub enum CheckResult {
    Success {
        pair_id: String,
        mapped_address: Option<SocketAddr>,
        rtt: Duration,
        nominated: bool,
    },
    Failure {
        pair_id: String,
        error: ConnectivityError,
        retransmit: bool,
    },
    Timeout {
        pair_id: String,
    },
}

/// Connectivity check errors
#[derive(Debug, Clone)]
pub enum ConnectivityError {
    NetworkError(String),
    StunError(String),
    AuthenticationFailure,
    RoleConflict,
    UnknownAttribute(Vec<u16>),
    IceConflict,
    Forbidden,
    UnauthorizedRole,
}

/// Check list entry with scheduling information
#[derive(Debug, Clone)]
pub struct CheckListEntry {
    pub pair: CandidatePair,
    pub state: CheckEntryState,
    pub check_count: u32,
    pub next_check_time: Option<Instant>,
    pub last_check_time: Option<Instant>,
    pub rto: Duration,
    pub waiting_transaction_id: Option<TransactionId>,
    pub triggered: bool,
}

/// Check entry state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckEntryState {
    Waiting,
    InProgress,
    Succeeded,
    Failed,
    Frozen,
}

impl From<CandidatePairState> for CheckEntryState {
    fn from(state: CandidatePairState) -> Self {
        match state {
            CandidatePairState::Waiting => Self::Waiting,
            CandidatePairState::InProgress => Self::InProgress,
            CandidatePairState::Succeeded => Self::Succeeded,
            CandidatePairState::Failed => Self::Failed,
            CandidatePairState::Frozen => Self::Frozen,
        }
    }
}

/// Connectivity check processor
pub struct ConnectivityChecker {
    /// Local ICE credentials
    local_credentials: IceCredentials,

    /// Remote ICE credentials
    remote_credentials: Arc<RwLock<Option<IceCredentials>>>,

    /// Check list organized by priority
    check_list: Arc<RwLock<BTreeMap<u64, CheckListEntry>>>,

    /// Valid list of successful pairs
    valid_list: Arc<RwLock<Vec<CandidatePair>>>,

    /// Triggered check queue
    triggered_queue: Arc<RwLock<VecDeque<String>>>,

    /// Transaction ID to pair mapping
    transaction_map: Arc<RwLock<HashMap<TransactionId, String>>>,

    /// RTO cache for addresses
    rto_cache: Arc<RwLock<HashMap<SocketAddr, Duration>>>,

    /// Consent freshness tracking
    consent_freshness: Arc<RwLock<HashMap<String, Instant>>>,

    /// Check results channel
    result_sender: broadcast::Sender<CheckResult>,

    /// Role (controlling or controlled)
    controlling: Arc<RwLock<bool>>,

    /// Nomination mode (aggressive or regular)
    aggressive_nomination: bool,

    /// State lock to prevent concurrent state changes
    state_lock: Arc<Mutex<()>>,

    /// Active check limit
    max_concurrent_checks: usize,

    /// Currently active checks
    active_checks: Arc<RwLock<HashSet<String>>>,

    /// Component ID
    component_id: u32,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,

    /// Statistics
    stats: Arc<RwLock<ConnectivityStats>>,
}

/// Connectivity check statistics
#[derive(Debug, Default, Clone)]
pub struct ConnectivityStats {
    pub checks_sent: u64,
    pub checks_received: u64,
    pub successful_checks: u64,
    pub failed_checks: u64,
    pub retransmissions: u64,
    pub consent_failures: u64,
    pub role_conflicts: u64,
    pub average_rtt: Duration,
    pub total_pairs: usize,
    pub valid_pairs: usize,
    pub nominated_pairs: usize,
}

impl ConnectivityChecker {
    /// Create new connectivity checker
    pub fn new(
        component_id: u32,
        controlling: bool,
        aggressive_nomination: bool,
    ) -> Self {
        let (result_sender, _) = broadcast::channel(1000);

        Self {
            local_credentials: IceCredentials::new(),
            remote_credentials: Arc::new(RwLock::new(None)),
            check_list: Arc::new(RwLock::new(BTreeMap::new())),
            valid_list: Arc::new(RwLock::new(Vec::new())),
            triggered_queue: Arc::new(RwLock::new(VecDeque::new())),
            transaction_map: Arc::new(RwLock::new(HashMap::new())),
            rto_cache: Arc::new(RwLock::new(HashMap::new())),
            consent_freshness: Arc::new(RwLock::new(HashMap::new())),
            result_sender,
            controlling: Arc::new(RwLock::new(controlling)),
            aggressive_nomination,
            state_lock: Arc::new(Mutex::new(())),
            max_concurrent_checks: 5,
            active_checks: Arc::new(RwLock::new(HashSet::new())),
            component_id,
            shutdown: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(ConnectivityStats::default())),
        }
    }

    /// Set remote credentials
    pub async fn set_remote_credentials(&self, credentials: IceCredentials) {
        *self.remote_credentials.write().await = Some(credentials);
        debug!("Remote ICE credentials set: ufrag={}", credentials.ufrag);
    }

    /// Get local credentials
    pub fn get_local_credentials(&self) -> &IceCredentials {
        &self.local_credentials
    }

    /// Form check list from candidate pairs (RFC 8445 Section 6.1.2)
    pub async fn form_check_list(&self, pairs: Vec<CandidatePair>) -> NatResult<()> {
        let _lock = self.state_lock.lock().await;
        let mut check_list = self.check_list.write().await;
        let mut stats = self.stats.write().await;

        check_list.clear();
        stats.total_pairs = pairs.len();

        info!("Forming check list with {} candidate pairs", pairs.len());

        // Group pairs by foundation for frozen/waiting logic
        let mut foundation_groups: HashMap<String, Vec<CandidatePair>> = HashMap::new();
        for pair in pairs {
            foundation_groups
                .entry(pair.foundation.clone())
                .or_default()
                .push(pair);
        }

        // Sort each foundation group by priority
        for group in foundation_groups.values_mut() {
            group.sort_by(|a, b| b.priority.cmp(&a.priority));
        }

        // Create check list entries
        for (foundation, mut pairs) in foundation_groups {
            // First pair in each foundation starts in Waiting state
            // Others start in Frozen state
            let mut is_first = true;

            for pair in pairs {
                let state = if is_first {
                    CheckEntryState::Waiting
                } else {
                    CheckEntryState::Frozen
                };

                let entry = CheckListEntry {
                    pair: pair.clone(),
                    state,
                    check_count: 0,
                    next_check_time: if is_first { Some(Instant::now()) } else { None },
                    last_check_time: None,
                    rto: RTO_INITIAL,
                    waiting_transaction_id: None,
                    triggered: false,
                };

                check_list.insert(pair.priority, entry);
                is_first = false;
            }
        }

        info!("Check list formed with {} entries", check_list.len());
        Ok(())
    }

    /// Start connectivity checks
    pub async fn start_checks(&self) -> NatResult<()> {
        if *self.shutdown.read().await {
            return Err(NatError::Configuration("Checker is shut down".to_string()));
        }

        info!("Starting ICE connectivity checks for component {}", self.component_id);

        // Start Ta timer for regular checks
        let ta_timer = self.start_ta_timer();

        // Start triggered check processor
        let triggered_processor = self.start_triggered_check_processor();

        // Start consent freshness timer
        let consent_timer = self.start_consent_freshness_timer();

        // Wait for completion or shutdown
        tokio::select! {
            _ = ta_timer => {},
            _ = triggered_processor => {},
            _ = consent_timer => {},
            _ = async {
                loop {
                    if *self.shutdown.read().await {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            } => {},
        }

        Ok(())
    }

    /// Start Ta timer for ordinary checks (RFC 8445 Section 6.1.4.1)
    async fn start_ta_timer(&self) -> NatResult<()> {
        let mut timer = interval(TA_TIMER_INTERVAL);

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            if let Err(e) = self.process_ordinary_checks().await {
                warn!("Error processing ordinary checks: {}", e);
            }
        }

        Ok(())
    }

    /// Process ordinary checks
    async fn process_ordinary_checks(&self) -> NatResult<()> {
        let now = Instant::now();
        let mut checks_to_send = Vec::new();

        // Collect checks that need to be sent
        {
            let check_list = self.check_list.read().await;
            let active_checks = self.active_checks.read().await;

            // Limit concurrent checks
            if active_checks.len() >= self.max_concurrent_checks {
                return Ok(());
            }

            for (priority, entry) in check_list.iter().rev() { // Highest priority first
                if active_checks.len() + checks_to_send.len() >= self.max_concurrent_checks {
                    break;
                }

                if entry.state == CheckEntryState::Waiting {
                    if let Some(next_time) = entry.next_check_time {
                        if now >= next_time {
                            checks_to_send.push((entry.pair.id(), *priority));
                        }
                    } else {
                        // Schedule immediate check
                        checks_to_send.push((entry.pair.id(), *priority));
                    }
                }
            }
        }

        // Send checks
        for (pair_id, priority) in checks_to_send {
            if let Err(e) = self.send_connectivity_check(&pair_id, false).await {
                warn!("Failed to send connectivity check for {}: {}", pair_id, e);
            }
        }

        // Process retransmissions
        self.process_retransmissions().await?;

        Ok(())
    }

    /// Start triggered check processor
    async fn start_triggered_check_processor(&self) -> NatResult<()> {
        let mut timer = interval(Duration::from_millis(10)); // High frequency for triggered checks

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            self.process_triggered_checks().await?;
        }

        Ok(())
    }

    /// Process triggered checks
    async fn process_triggered_checks(&self) -> NatResult<()> {
        loop {
            let pair_id = {
                let mut queue = self.triggered_queue.write().await;
                queue.pop_front()
            };

            match pair_id {
                Some(id) => {
                    if let Err(e) = self.send_connectivity_check(&id, true).await {
                        warn!("Failed to send triggered check for {}: {}", id, e);
                    }
                }
                None => break,
            }
        }

        Ok(())
    }

    /// Send connectivity check (RFC 8445 Section 7.2.4)
    async fn send_connectivity_check(&self, pair_id: &str, triggered: bool) -> NatResult<()> {
        let (pair, entry_state) = {
            let check_list = self.check_list.read().await;
            let entry = check_list.values()
                .find(|e| e.pair.id() == pair_id)
                .ok_or_else(|| NatError::Configuration("Pair not found".to_string()))?;

            (entry.pair.clone(), entry.state)
        };

        // Check if we can send this check
        if entry_state != CheckEntryState::Waiting && !triggered {
            return Ok(());
        }

        // Get remote credentials
        let remote_creds = self.remote_credentials.read().await
            .as_ref()
            .ok_or_else(|| NatError::Configuration("Remote credentials not set".to_string()))?
            .clone();

        // Create binding request
        let transaction_id = TransactionId::new();
        let mut request = Message::new(MessageType::BindingRequest, transaction_id);

        // Add USERNAME attribute
        let username = format!("{}:{}", remote_creds.ufrag, self.local_credentials.ufrag);
        request.add_attribute(Attribute {
            attr_type: AttributeType::Username,
            value: AttributeValue::Username(username),
        });

        // Add PRIORITY attribute
        request.add_attribute(Attribute {
            attr_type: AttributeType::Priority,
            value: AttributeValue::Priority(pair.local.priority),
        });

        // Add USE-CANDIDATE for controlling agent (RFC 8445 Section 7.3.1.1)
        let controlling = *self.controlling.read().await;
        if controlling {
            // Add ICE-CONTROLLING attribute
            request.add_attribute(Attribute {
                attr_type: AttributeType::IceControlling,
                value: AttributeValue::IceControlling(generate_tie_breaker()),
            });

            // Add USE-CANDIDATE for nomination
            if self.aggressive_nomination || pair.nominated {
                request.add_attribute(Attribute {
                    attr_type: AttributeType::UseCandidate,
                    value: AttributeValue::Flag,
                });
            }
        } else {
            // Add ICE-CONTROLLED attribute
            request.add_attribute(Attribute {
                attr_type: AttributeType::IceControlled,
                value: AttributeValue::IceControlled(generate_tie_breaker()),
            });
        }

        // Add MESSAGE-INTEGRITY
        request.add_message_integrity(&remote_creds.password)?;

        // Add FINGERPRINT
        request.add_fingerprint()?;

        // Send the check
        let local_socket = create_socket_for_candidate(&pair.local).await?;
        let send_result = local_socket.send_to(&request.to_bytes()?, pair.remote.socket_addr().unwrap()).await;

        if let Err(e) = send_result {
            return Err(NatError::Network(e));
        }

        // Update state
        {
            let mut check_list = self.check_list.write().await;
            let mut transaction_map = self.transaction_map.write().await;
            let mut active_checks = self.active_checks.write().await;

            for entry in check_list.values_mut() {
                if entry.pair.id() == pair_id {
                    entry.state = CheckEntryState::InProgress;
                    entry.check_count += 1;
                    entry.last_check_time = Some(Instant::now());
                    entry.waiting_transaction_id = Some(transaction_id);
                    entry.triggered = triggered;

                    // Schedule retransmission
                    entry.next_check_time = Some(Instant::now() + entry.rto);

                    break;
                }
            }

            transaction_map.insert(transaction_id, pair_id.to_string());
            active_checks.insert(pair_id.to_string());
        }

        // Update statistics
        self.stats.write().await.checks_sent += 1;

        trace!("Sent connectivity check for {} (triggered: {})", pair_id, triggered);
        Ok(())
    }

    /// Process incoming STUN message (RFC 8445 Section 7.3)
    pub async fn process_stun_message(
        &self,
        message: &Message,
        from: SocketAddr,
        to: SocketAddr,
    ) -> NatResult<Option<Message>> {
        match message.message_type {
            MessageType::BindingRequest => {
                self.process_binding_request(message, from, to).await
            }
            MessageType::BindingResponse => {
                self.process_binding_response(message, from).await?;
                Ok(None)
            }
            MessageType::BindingErrorResponse => {
                self.process_binding_error(message, from).await?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Process binding request (RFC 8445 Section 7.3.1)
    async fn process_binding_request(
        &self,
        request: &Message,
        from: SocketAddr,
        to: SocketAddr,
    ) -> NatResult<Option<Message>> {
        // Validate credentials
        let username = request.get_username()
            .ok_or_else(|| NatError::Configuration("Missing USERNAME attribute".to_string()))?;

        let parts: Vec<&str> = username.split(':').collect();
        if parts.len() != 2 {
            return Err(NatError::Configuration("Invalid USERNAME format".to_string()));
        }

        let (remote_ufrag, local_ufrag) = (parts[0], parts[1]);
        if local_ufrag != self.local_credentials.ufrag {
            return Err(NatError::Configuration("Invalid local ufrag".to_string()));
        }

        // Validate MESSAGE-INTEGRITY
        if !request.validate_message_integrity(&self.local_credentials.password)? {
            return Err(NatError::Configuration("MESSAGE-INTEGRITY validation failed".to_string()));
        }

        // Create success response
        let mut response = Message::new(
            MessageType::BindingResponse,
            request.transaction_id,
        );

        // Add XOR-MAPPED-ADDRESS
        response.add_attribute(Attribute {
            attr_type: AttributeType::XorMappedAddress,
            value: AttributeValue::XorMappedAddress(from),
        });

        // Add MESSAGE-INTEGRITY
        response.add_message_integrity(&self.local_credentials.password)?;

        // Add FINGERPRINT
        response.add_fingerprint()?;

        // Check for role conflict
        let controlling = *self.controlling.read().await;
        let request_has_controlling = request.has_attribute(AttributeType::IceControlling);
        let request_has_controlled = request.has_attribute(AttributeType::IceControlled);

        if (controlling && request_has_controlling) || (!controlling && request_has_controlled) {
            // Role conflict detected
            warn!("ICE role conflict detected from {}", from);
            self.stats.write().await.role_conflicts += 1;

            // Handle role conflict according to tie-breaker rules
            self.handle_role_conflict(request).await?;
        }

        // Process USE-CANDIDATE attribute
        if request.has_attribute(AttributeType::UseCandidate) {
            self.process_use_candidate(from, to).await?;
        }

        // Trigger connectivity check for this pair
        self.trigger_connectivity_check(from, to).await?;

        self.stats.write().await.checks_received += 1;

        Ok(Some(response))
    }

    /// Process binding success response (RFC 8445 Section 7.3.1.4)
    async fn process_binding_response(&self, response: &Message, from: SocketAddr) -> NatResult<()> {
        let pair_id = {
            let transaction_map = self.transaction_map.read().await;
            transaction_map.get(&response.transaction_id)
                .cloned()
                .ok_or_else(|| NatError::Configuration("Unknown transaction ID".to_string()))?
        };

        // Get mapped address from response
        let mapped_address = response.get_xor_mapped_address();

        // Calculate RTT
        let rtt = {
            let check_list = self.check_list.read().await;
            let entry = check_list.values()
                .find(|e| e.pair.id() == pair_id)
                .ok_or_else(|| NatError::Configuration("Pair not found".to_string()))?;

            entry.last_check_time
                .map(|start| start.elapsed())
                .unwrap_or(Duration::ZERO)
        };

        // Update pair state and statistics
        {
            let mut check_list = self.check_list.write().await;
            let mut valid_list = self.valid_list.write().await;
            let mut active_checks = self.active_checks.write().await;
            let mut consent_freshness = self.consent_freshness.write().await;
            let mut stats = self.stats.write().await;

            for entry in check_list.values_mut() {
                if entry.pair.id() == pair_id {
                    entry.state = CheckEntryState::Succeeded;
                    entry.pair.mark_succeeded(rtt);
                    entry.waiting_transaction_id = None;

                    // Add to valid list if not already present
                    if !valid_list.iter().any(|p| p.id() == pair_id) {
                        valid_list.push(entry.pair.clone());
                        stats.valid_pairs += 1;
                    }

                    // Update consent freshness
                    consent_freshness.insert(pair_id.clone(), Instant::now());

                    // Check for nomination
                    let nominated = response.has_attribute(AttributeType::UseCandidate);
                    if nominated {
                        entry.pair.nominate();
                        stats.nominated_pairs += 1;
                    }

                    break;
                }
            }

            active_checks.remove(&pair_id);
            stats.successful_checks += 1;

            // Update average RTT
            let total_rtt = stats.average_rtt.as_millis() as u64 * (stats.successful_checks - 1) + rtt.as_millis() as u64;
            stats.average_rtt = Duration::from_millis(total_rtt / stats.successful_checks);
        }

        // Unfreeze related pairs
        self.unfreeze_pairs(&pair_id).await?;

        // Send result
        let _ = self.result_sender.send(CheckResult::Success {
            pair_id,
            mapped_address,
            rtt,
            nominated: response.has_attribute(AttributeType::UseCandidate),
        });

        // Update RTO cache
        self.update_rto_cache(from, rtt).await;

        debug!("Connectivity check succeeded for {} (RTT: {:?})", pair_id, rtt);
        Ok(())
    }

    /// Process binding error response
    async fn process_binding_error(&self, response: &Message, from: SocketAddr) -> NatResult<()> {
        let pair_id = {
            let transaction_map = self.transaction_map.read().await;
            transaction_map.get(&response.transaction_id)
                .cloned()
                .ok_or_else(|| NatError::Configuration("Unknown transaction ID".to_string()))?
        };

        // Get error code
        let error = if let Some(error_code) = response.get_error_code() {
            match error_code.code {
                401 => ConnectivityError::AuthenticationFailure,
                403 => ConnectivityError::Forbidden,
                487 => ConnectivityError::RoleConflict,
                _ => ConnectivityError::StunError(format!("Error {}: {}", error_code.code, error_code.reason)),
            }
        } else {
            ConnectivityError::StunError("Unknown error".to_string())
        };

        // Update pair state
        let should_retry = {
            let mut check_list = self.check_list.write().await;
            let mut active_checks = self.active_checks.write().await;

            for entry in check_list.values_mut() {
                if entry.pair.id() == pair_id {
                    entry.state = CheckEntryState::Failed;
                    entry.pair.mark_failed();
                    entry.waiting_transaction_id = None;

                    active_checks.remove(&pair_id);

                    // Determine if we should retry
                    return Ok(entry.check_count < MAX_RETRANSMISSIONS);
                }
            }

            false
        };

        self.stats.write().await.failed_checks += 1;

        // Send result
        let _ = self.result_sender.send(CheckResult::Failure {
            pair_id,
            error,
            retransmit: should_retry,
        });

        debug!("Connectivity check failed for {}", pair_id);
        Ok(())
    }

    /// Handle role conflict (RFC 8445 Section 7.3.1.1)
    async fn handle_role_conflict(&self, request: &Message) -> NatResult<()> {
        let our_tie_breaker = generate_tie_breaker();
        let their_tie_breaker = if let Some(controlling_value) = request.get_ice_controlling() {
            controlling_value
        } else if let Some(controlled_value) = request.get_ice_controlled() {
            controlled_value
        } else {
            return Err(NatError::Configuration("No tie-breaker value found".to_string()));
        };

        // Compare tie-breakers to determine who should switch roles
        if our_tie_breaker > their_tie_breaker {
            // We have higher tie-breaker, they should switch roles
            warn!("Role conflict: peer should switch roles");
        } else {
            // We have lower tie-breaker, we should switch roles
            warn!("Role conflict: switching our role");
            let mut controlling = self.controlling.write().await;
            *controlling = !*controlling;
        }

        Ok(())
    }

    /// Process USE-CANDIDATE attribute
    async fn process_use_candidate(&self, from: SocketAddr, to: SocketAddr) -> NatResult<()> {
        // Find the pair for this address combination
        let pair_id = {
            let check_list = self.check_list.read().await;
            check_list.values()
                .find(|entry| {
                    entry.pair.remote.socket_addr() == Some(from) &&
                        entry.pair.local.socket_addr() == Some(to)
                })
                .map(|entry| entry.pair.id())
        };

        if let Some(id) = pair_id {
            let mut check_list = self.check_list.write().await;
            for entry in check_list.values_mut() {
                if entry.pair.id() == id {
                    entry.pair.nominated = true;
                    debug!("Pair {} nominated via USE-CANDIDATE", id);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Trigger connectivity check for address pair
    async fn trigger_connectivity_check(&self, from: SocketAddr, to: SocketAddr) -> NatResult<()> {
        let pair_id = {
            let check_list = self.check_list.read().await;
            check_list.values()
                .find(|entry| {
                    entry.pair.remote.socket_addr() == Some(from) &&
                        entry.pair.local.socket_addr() == Some(to)
                })
                .map(|entry| entry.pair.id())
        };

        if let Some(id) = pair_id {
            let mut triggered_queue = self.triggered_queue.write().await;
            triggered_queue.push_back(id);
        }

        Ok(())
    }

    /// Unfreeze pairs after successful check (RFC 8445 Section 6.1.3.4)
    async fn unfreeze_pairs(&self, successful_pair_id: &str) -> NatResult<()> {
        let foundation = {
            let check_list = self.check_list.read().await;
            check_list.values()
                .find(|entry| entry.pair.id() == successful_pair_id)
                .map(|entry| entry.pair.foundation.clone())
        };

        if let Some(found) = foundation {
            let mut check_list = self.check_list.write().await;
            for entry in check_list.values_mut() {
                if entry.state == CheckEntryState::Frozen && entry.pair.foundation == found {
                    entry.state = CheckEntryState::Waiting;
                    entry.next_check_time = Some(Instant::now());
                    trace!("Unfroze pair {} due to success of {}", entry.pair.id(), successful_pair_id);
                }
            }
        }

        Ok(())
    }

    /// Process retransmissions
    async fn process_retransmissions(&self) -> NatResult<()> {
        let now = Instant::now();
        let mut pairs_to_retransmit = Vec::new();

        {
            let mut check_list = self.check_list.write().await;
            let mut stats = self.stats.write().await;

            for entry in check_list.values_mut() {
                if entry.state == CheckEntryState::InProgress {
                    if let Some(next_time) = entry.next_check_time {
                        if now >= next_time {
                            if entry.check_count < MAX_RETRANSMISSIONS {
                                // Exponential backoff with jitter
                                entry.rto = (entry.rto * 2).min(RTO_MAX);
                                let jitter = Duration::from_millis(thread_rng().gen_range(0..100));
                                entry.next_check_time = Some(now + entry.rto + jitter);

                                pairs_to_retransmit.push(entry.pair.id());
                                stats.retransmissions += 1;
                            } else {
                                // Max retransmissions reached
                                entry.state = CheckEntryState::Failed;
                                entry.pair.mark_failed();
                                entry.waiting_transaction_id = None;

                                let _ = self.result_sender.send(CheckResult::Timeout {
                                    pair_id: entry.pair.id(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Send retransmissions
        for pair_id in pairs_to_retransmit {
            if let Err(e) = self.send_connectivity_check(&pair_id, false).await {
                warn!("Failed to retransmit check for {}: {}", pair_id, e);
            }
        }

        Ok(())
    }

    /// Update RTO cache for address
    async fn update_rto_cache(&self, addr: SocketAddr, rtt: Duration) {
        let mut cache = self.rto_cache.write().await;

        // Calculate smoothed RTT (RFC 6298)
        let new_rto = if let Some(cached_rto) = cache.get(&addr) {
            // SRTT = (1-α) * SRTT + α * RTT, where α = 1/8
            let alpha = 0.125;
            let srtt = Duration::from_millis(
                ((1.0 - alpha) * cached_rto.as_millis() as f64 + alpha * rtt.as_millis() as f64) as u64
            );
            srtt.max(RTO_INITIAL).min(RTO_MAX)
        } else {
            rtt.max(RTO_INITIAL).min(RTO_MAX)
        };

        cache.insert(addr, new_rto);

        // Clean old entries
        let cutoff = Instant::now() - RTO_CACHE_DURATION;
        cache.retain(|_, _| true); // Would need timestamp tracking for proper cleanup
    }

    /// Start consent freshness timer
    async fn start_consent_freshness_timer(&self) -> NatResult<()> {
        let mut timer = interval(KEEPALIVE_TIMER_INTERVAL);

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            self.check_consent_freshness().await?;
        }

        Ok(())
    }

    /// Check consent freshness for valid pairs
    async fn check_consent_freshness(&self) -> NatResult<()> {
        let now = Instant::now();
        let mut expired_pairs = Vec::new();

        {
            let consent_freshness = self.consent_freshness.read().await;

            for (pair_id, last_consent) in consent_freshness.iter() {
                if now.duration_since(*last_consent) > CONSENT_FRESHNESS_TIMEOUT {
                    expired_pairs.push(pair_id.clone());
                }
            }
        }

        if !expired_pairs.is_empty() {
            warn!("Consent expired for {} pairs", expired_pairs.len());

            let mut stats = self.stats.write().await;
            stats.consent_failures += expired_pairs.len() as u64;

            // Remove expired pairs from valid list
            let mut valid_list = self.valid_list.write().await;
            valid_list.retain(|pair| !expired_pairs.contains(&pair.id()));
        }

        Ok(())
    }

    /// Get valid pairs
    pub async fn get_valid_pairs(&self) -> Vec<CandidatePair> {
        self.valid_list.read().await.clone()
    }

    /// Get nominated pairs
    pub async fn get_nominated_pairs(&self) -> Vec<CandidatePair> {
        let valid_pairs = self.valid_list.read().await;
        valid_pairs.iter()
            .filter(|pair| pair.nominated)
            .cloned()
            .collect()
    }

    /// Get connectivity statistics
    pub async fn get_statistics(&self) -> ConnectivityStats {
        self.stats.read().await.clone()
    }

    /// Subscribe to check results
    pub fn subscribe_results(&self) -> broadcast::Receiver<CheckResult> {
        self.result_sender.subscribe()
    }

    /// Stop connectivity checks
    pub async fn stop(&self) {
        *self.shutdown.write().await = true;
        info!("Connectivity checker stopped for component {}", self.component_id);
    }

    /// Check if all pairs are completed
    pub async fn is_completed(&self) -> bool {
        let check_list = self.check_list.read().await;
        check_list.values().all(|entry| {
            matches!(entry.state, CheckEntryState::Succeeded | CheckEntryState::Failed)
        })
    }
}

/// Helper functions

/// Generate ICE tie-breaker value
fn generate_tie_breaker() -> u64 {
    thread_rng().gen()
}

/// Create socket for candidate
async fn create_socket_for_candidate(candidate: &Candidate) -> NatResult<tokio::net::UdpSocket> {
    if let Some(addr) = candidate.socket_addr() {
        tokio::net::UdpSocket::bind(SocketAddr::new(addr.ip(), 0)).await
            .map_err(|e| NatError::Network(e))
    } else {
        Err(NatError::Configuration("Cannot create socket for mDNS candidate".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::ice::candidate::CandidateExtensions;

    #[tokio::test]
    async fn test_connectivity_checker_creation() {
        let checker = ConnectivityChecker::new(1, true, false);
        assert_eq!(checker.component_id, 1);
        assert_eq!(*checker.controlling.read().await, true);
        assert!(!checker.aggressive_nomination);
    }

    #[tokio::test]
    async fn test_credentials_generation() {
        let creds1 = IceCredentials::new();
        let creds2 = IceCredentials::new();

        assert_ne!(creds1.ufrag, creds2.ufrag);
        assert_ne!(creds1.password, creds2.password);
        assert_eq!(creds1.ufrag.len(), 4);
        assert_eq!(creds1.password.len(), 22);
    }

    #[tokio::test]
    async fn test_check_list_formation() {
        let checker = ConnectivityChecker::new(1, true, false);

        // Create test candidates
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

        let pair = CandidatePair::new(local, remote, true);
        let pairs = vec![pair];

        checker.form_check_list(pairs).await.unwrap();

        let check_list = checker.check_list.read().await;
        assert_eq!(check_list.len(), 1);
    }
}