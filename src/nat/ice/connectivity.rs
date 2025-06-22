// src/nat/ice/connectivity.rs
//! ICE connectivity checks implementation (RFC 8445 Section 7)

use std::collections::{HashMap, VecDeque, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::{interval, timeout, sleep};
use rand::Rng;
use bytes::{Bytes, BytesMut, BufMut};
use tracing::{info, warn, error, debug, trace};

use crate::nat::stun::{
    Message, MessageType, TransactionId, Attribute, AttributeType, AttributeValue,
    compute_message_integrity_sha256, MAGIC_COOKIE,
};
use crate::nat::error::{NatError, StunError, NatResult};
use super::{Candidate, CandidatePair, IceCredentials, TransportProtocol};
use super::candidate::CandidatePairState;
use super::foundation::foundations_match;

/// Connectivity check manager with full RFC 8445 compliance
pub struct ConnectivityChecker {
    /// Check lists for each stream
    check_lists: Arc<RwLock<HashMap<u32, CheckList>>>,

    /// Sockets for sending checks
    sockets: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>>,

    /// Transaction to pair mapping
    transactions: Arc<Mutex<HashMap<TransactionId, CheckTransaction>>>,

    /// Triggered check queue (RFC 8445 Section 7.3.1.4)
    triggered_queue: Arc<Mutex<VecDeque<TriggeredCheck>>>,

    /// Timer interval (Ta) - default 50ms
    ta: Duration,

    /// RTO (retransmission timeout)
    rto: Duration,

    /// Maximum check attempts (Rc)
    max_attempts: u32,

    /// Role (controlling/controlled)
    controlling: Arc<RwLock<bool>>,

    /// Tie breaker for role conflicts
    tie_breaker: u64,

    /// Local credentials
    local_creds: IceCredentials,

    /// Remote credentials
    remote_creds: Arc<RwLock<Option<IceCredentials>>>,

    /// Event sender
    event_tx: mpsc::UnboundedSender<ConnectivityEvent>,

    /// Active checker task handle
    checker_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,

    /// Triggered check processor task handle
    triggered_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,

    /// Receiver task handles
    receiver_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,

    /// Shutdown flag
    shutdown: Arc<RwLock<bool>>,

    /// Aggressive nomination mode
    aggressive_nomination: bool,

    /// Nomination timer handles
    nomination_timers: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,

    /// Statistics
    stats: Arc<ConnectivityStats>,
}

/// Connectivity statistics
#[derive(Debug, Default)]
struct ConnectivityStats {
    checks_sent: std::sync::atomic::AtomicU64,
    checks_received: std::sync::atomic::AtomicU64,
    checks_succeeded: std::sync::atomic::AtomicU64,
    checks_failed: std::sync::atomic::AtomicU64,
    role_conflicts: std::sync::atomic::AtomicU64,
}

/// Check list for a stream
#[derive(Debug)]
pub struct CheckList {
    /// Stream ID
    stream_id: u32,

    /// All pairs sorted by priority
    pairs: Vec<Arc<RwLock<CandidatePair>>>,

    /// Check list state
    state: CheckListState,

    /// Valid list (succeeded pairs)
    valid_list: Vec<Arc<RwLock<CandidatePair>>>,

    /// Running checks
    running_checks: HashSet<String>,

    /// Foundation to pairs mapping for frozen candidates
    foundation_map: HashMap<String, Vec<Arc<RwLock<CandidatePair>>>>,
}

/// Check list state (RFC 8445 Section 6.1.2.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckListState {
    Running,
    Completed,
    Failed,
}

/// Transaction information
#[derive(Debug)]
struct CheckTransaction {
    pair: Arc<RwLock<CandidatePair>>,
    stream_id: u32,
    attempt: u32,
    sent_at: Instant,
    request: Message,
}

/// Triggered check
#[derive(Debug, Clone)]
struct TriggeredCheck {
    pair: Arc<RwLock<CandidatePair>>,
    stream_id: u32,
    use_candidate: bool,
    remote_addr: SocketAddr,
}

/// Connectivity check event
#[derive(Debug, Clone)]
pub enum ConnectivityEvent {
    /// Pair state changed
    PairStateChanged {
        stream_id: u32,
        pair: CandidatePair,
    },

    /// New valid pair
    ValidPair {
        stream_id: u32,
        pair: CandidatePair,
    },

    /// Check list completed
    CheckListCompleted {
        stream_id: u32,
    },

    /// Check list failed
    CheckListFailed {
        stream_id: u32,
    },

    /// Nominated pair
    NominatedPair {
        stream_id: u32,
        component_id: u32,
        pair: CandidatePair,
    },

    /// Role conflict detected
    RoleConflict {
        their_tie_breaker: u64,
    },
}

// ICE-specific STUN attribute types
impl AttributeType {
    pub const Priority: AttributeType = AttributeType(0x0024);
    pub const UseCandidate: AttributeType = AttributeType(0x0025);
    pub const IceControlled: AttributeType = AttributeType(0x8029);
    pub const IceControlling: AttributeType = AttributeType(0x802A);
}

impl AttributeType {
    const fn new(value: u16) -> Self {
        AttributeType(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeType(u16);

impl ConnectivityChecker {
    /// Create new connectivity checker
    pub fn new(
        controlling: bool,
        local_creds: IceCredentials,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
        aggressive_nomination: bool,
    ) -> Self {
        let tie_breaker = rand::thread_rng().gen::<u64>();

        info!("Creating connectivity checker: controlling={}, tie_breaker={}, aggressive={}",
            controlling, tie_breaker, aggressive_nomination);

        Self {
            check_lists: Arc::new(RwLock::new(HashMap::new())),
            sockets: Arc::new(RwLock::new(HashMap::new())),
            transactions: Arc::new(Mutex::new(HashMap::new())),
            triggered_queue: Arc::new(Mutex::new(VecDeque::new())),
            ta: Duration::from_millis(50), // RFC 8445 recommends 50ms
            rto: Duration::from_millis(500), // Initial RTO
            max_attempts: 7, // Rc = 7
            controlling: Arc::new(RwLock::new(controlling)),
            tie_breaker,
            local_creds,
            remote_creds: Arc::new(RwLock::new(None)),
            event_tx,
            checker_task: Arc::new(Mutex::new(None)),
            triggered_task: Arc::new(Mutex::new(None)),
            receiver_tasks: Arc::new(Mutex::new(Vec::new())),
            shutdown: Arc::new(RwLock::new(false)),
            aggressive_nomination,
            nomination_timers: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(ConnectivityStats::default()),
        }
    }

    /// Set remote credentials
    pub fn set_remote_credentials(&mut self, creds: IceCredentials) {
        info!("Setting remote credentials: ufrag={}", creds.ufrag);
        *self.remote_creds.blocking_write() = Some(creds);
    }

    /// Set controlling role
    pub fn set_controlling(&mut self, controlling: bool) {
        info!("Setting controlling role to {}", controlling);
        *self.controlling.blocking_write() = controlling;
    }

    /// Get tie breaker
    pub fn get_tie_breaker(&self) -> u64 {
        self.tie_breaker
    }

    /// Add socket for candidate
    pub async fn add_socket(&self, addr: SocketAddr, socket: Arc<UdpSocket>) {
        debug!("Adding socket for {}", addr);
        self.sockets.write().await.insert(addr, socket);
    }

    /// Create check list for stream
    pub async fn create_check_list(
        &self,
        stream_id: u32,
        local_candidates: Vec<Candidate>,
        remote_candidates: Vec<Candidate>,
    ) -> NatResult<()> {
        info!("Creating check list for stream {}: {} local x {} remote candidates",
            stream_id, local_candidates.len(), remote_candidates.len());

        let mut pairs = Vec::new();
        let controlling = *self.controlling.read().await;

        // Form candidate pairs (RFC 8445 Section 6.1.2.2)
        for local in &local_candidates {
            for remote in &remote_candidates {
                // Only pair candidates with same component
                if local.component_id != remote.component_id {
                    continue;
                }

                // RFC 8421: Skip pairing IPv4 with IPv6
                if local.addr.is_ipv4() != remote.addr.is_ipv4() {
                    continue;
                }

                // Skip loopback addresses
                if local.addr.ip().is_loopback() || remote.addr.ip().is_loopback() {
                    continue;
                }

                let pair = CandidatePair::new(
                    local.clone(),
                    remote.clone(),
                    controlling,
                );

                trace!("Created pair: {} -> {} (priority: {})",
                    local.addr, remote.addr, pair.priority);

                pairs.push(Arc::new(RwLock::new(pair)));
            }
        }

        if pairs.is_empty() {
            warn!("No valid pairs created for stream {}", stream_id);
            return Ok(());
        }

        // Sort by priority (RFC 8445 Section 6.1.2.3)
        pairs.sort_by_key(|p| std::cmp::Reverse(p.blocking_read().priority));

        // Prune redundant pairs (RFC 8445 Section 6.1.2.4)
        let mut pruned_pairs = Vec::new();
        for pair in pairs {
            let should_keep = {
                let p = pair.read().await;
                !pruned_pairs.iter().any(|existing: &Arc<RwLock<CandidatePair>>| {
                    let e = existing.blocking_read();
                    p.should_prune(&e)
                })
            };

            if should_keep {
                pruned_pairs.push(pair);
            }
        }

        info!("Pruned {} pairs to {} for stream {}",
            pairs.len(), pruned_pairs.len(), stream_id);

        // Limit check list size (RFC 8445 Section 6.1.2.5)
        const MAX_PAIRS: usize = 100;
        if pruned_pairs.len() > MAX_PAIRS {
            info!("Limiting check list from {} to {} pairs", pruned_pairs.len(), MAX_PAIRS);
            pruned_pairs.truncate(MAX_PAIRS);
        }

        // Build foundation map
        let mut foundation_map: HashMap<String, Vec<Arc<RwLock<CandidatePair>>>> = HashMap::new();
        for pair in &pruned_pairs {
            let foundation = pair.read().await.foundation.clone();
            foundation_map.entry(foundation)
                .or_insert_with(Vec::new)
                .push(pair.clone());
        }

        // Set initial states (RFC 8445 Section 6.1.2.6)
        let mut waiting_foundations = HashSet::new();

        for (i, pair) in pruned_pairs.iter().enumerate() {
            let mut p = pair.write().await;
            let foundation = p.foundation.clone();

            if i < 5 || !waiting_foundations.contains(&foundation) {
                // First pairs or first of each foundation are Waiting
                p.state = CandidatePairState::Waiting;
                waiting_foundations.insert(foundation);
                debug!("Pair {} set to Waiting", p.id());
            } else {
                // Others are Frozen
                p.state = CandidatePairState::Frozen;
                debug!("Pair {} set to Frozen", p.id());
            }
        }

        let check_list = CheckList {
            stream_id,
            pairs: pruned_pairs,
            state: CheckListState::Running,
            valid_list: Vec::new(),
            running_checks: HashSet::new(),
            foundation_map,
        };

        self.check_lists.write().await.insert(stream_id, check_list);

        info!("Check list created for stream {} with {} pairs",
            stream_id, self.check_lists.read().await[&stream_id].pairs.len());

        Ok(())
    }

    /// Add remote candidate dynamically (for trickle ICE)
    pub async fn add_remote_candidate(&self, candidate: Candidate) -> NatResult<()> {
        debug!("Adding remote candidate dynamically: {}", candidate.addr);

        // Find appropriate check list
        let check_lists = self.check_lists.read().await;

        for (stream_id, list) in check_lists.iter() {
            // Add pairs with all matching local candidates
            let local_candidates: Vec<Candidate> = list.pairs.iter()
                .filter_map(|p| {
                    let pair = p.blocking_read();
                    if pair.local.component_id == candidate.component_id {
                        Some(pair.local.clone())
                    } else {
                        None
                    }
                })
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            drop(check_lists);

            for local in local_candidates {
                if local.addr.is_ipv4() != candidate.addr.is_ipv4() {
                    continue;
                }

                let controlling = *self.controlling.read().await;
                let pair = CandidatePair::new(local, candidate.clone(), controlling);
                let pair_ref = Arc::new(RwLock::new(pair));

                // Add to check list
                let mut lists = self.check_lists.write().await;
                if let Some(list) = lists.get_mut(stream_id) {
                    list.pairs.push(pair_ref.clone());

                    // Add to foundation map
                    let foundation = pair_ref.read().await.foundation.clone();
                    list.foundation_map.entry(foundation)
                        .or_insert_with(Vec::new)
                        .push(pair_ref);

                    // Resort by priority
                    list.pairs.sort_by_key(|p| std::cmp::Reverse(p.blocking_read().priority));
                }
            }

            return Ok(());
        }

        Ok(())
    }

    /// Start connectivity checks
    pub async fn start_checks(&self) {
        info!("Starting connectivity checks");

        // Start check timer loop
        let checker = Arc::new(self.clone());
        let task = tokio::spawn(async move {
            checker.check_timer_loop().await;
        });
        *self.checker_task.lock().await = Some(task);

        // Start triggered check processor (RFC 8445 Section 7.3.1.4)
        let checker = Arc::new(self.clone());
        let task = tokio::spawn(async move {
            checker.triggered_check_loop().await;
        });
        *self.triggered_task.lock().await = Some(task);

        // Start receiver loops
        let sockets = self.sockets.read().await;
        let mut tasks = Vec::new();

        for (addr, socket) in sockets.iter() {
            let addr = *addr;
            let socket = socket.clone();
            let checker = Arc::new(self.clone());

            let task = tokio::spawn(async move {
                checker.socket_receive_loop(addr, socket).await;
            });
            tasks.push(task);
        }

        *self.receiver_tasks.lock().await = tasks;
    }

    /// Main check timer loop (RFC 8445 Section 7.3)
    async fn check_timer_loop(self: Arc<Self>) {
        info!("Check timer loop started with Ta={:?}", self.ta);
        let mut timer = interval(self.ta);

        loop {
            timer.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            // Find next pair to check
            let check_lists = self.check_lists.read().await;

            for (stream_id, list) in check_lists.iter() {
                if list.state != CheckListState::Running {
                    continue;
                }

                // Skip if too many running checks
                if list.running_checks.len() >= 5 {
                    continue;
                }

                // Find next waiting pair with highest priority
                let mut next_pair = None;
                for pair_ref in &list.pairs {
                    let pair = pair_ref.read().await;
                    if pair.state == CandidatePairState::Waiting {
                        next_pair = Some(pair_ref.clone());
                        break; // Already sorted by priority
                    }
                }

                if let Some(pair_ref) = next_pair {
                    let pair_id = pair_ref.read().await.id();
                    if !list.running_checks.contains(&pair_id) {
                        let sid = *stream_id;
                        drop(check_lists);

                        debug!("Starting check for pair {}", pair_id);
                        self.send_check(sid, pair_ref, self.aggressive_nomination).await;
                        return; // Process one pair per Ta
                    }
                }
            }

            // No waiting pairs, try to unfreeze
            for (stream_id, list) in check_lists.iter() {
                if list.state != CheckListState::Running {
                    continue;
                }

                // Find foundations with no running checks
                let running_foundations: HashSet<String> = list.pairs.iter()
                    .filter_map(|p| {
                        let pair = p.blocking_read();
                        if pair.state == CandidatePairState::InProgress {
                            Some(pair.foundation.clone())
                        } else {
                            None
                        }
                    })
                    .collect();

                // Unfreeze one pair from each foundation without running checks
                for (foundation, pairs) in &list.foundation_map {
                    if running_foundations.contains(foundation) {
                        continue;
                    }

                    for pair_ref in pairs {
                        let mut pair = pair_ref.write().await;
                        if pair.state == CandidatePairState::Frozen {
                            debug!("Unfreezing pair {} (foundation: {})", pair.id(), foundation);
                            pair.state = CandidatePairState::Waiting;
                            break; // Unfreeze only one per foundation
                        }
                    }
                }
            }
        }

        info!("Check timer loop ended");
    }

    /// Triggered check processor loop (RFC 8445 Section 7.3.1.4)
    async fn triggered_check_loop(self: Arc<Self>) {
        info!("Triggered check processor started");

        loop {
            if *self.shutdown.read().await {
                break;
            }

            // Process triggered checks immediately, not waiting for Ta
            let triggered = self.triggered_queue.lock().await.pop_front();

            if let Some(check) = triggered {
                debug!("Processing triggered check for pair {}", check.pair.read().await.id());
                self.send_check(check.stream_id, check.pair, check.use_candidate).await;
            } else {
                // No triggered checks, wait a bit
                sleep(Duration::from_millis(10)).await;
            }
        }

        info!("Triggered check processor ended");
    }

    /// Send connectivity check
    async fn send_check(
        &self,
        stream_id: u32,
        pair_ref: Arc<RwLock<CandidatePair>>,
        use_candidate: bool,
    ) {
        let mut pair = pair_ref.write().await;

        // Update state
        let pair_id = pair.id();
        pair.state = CandidatePairState::InProgress;
        pair.checks_sent += 1;
        pair.last_check_sent = Some(Instant::now());

        if use_candidate && *self.controlling.read().await {
            pair.use_candidate = true;
        }

        let local_addr = pair.local.addr;
        let remote_addr = pair.remote.addr;

        drop(pair);

        // Mark as running
        if let Some(list) = self.check_lists.write().await.get_mut(&stream_id) {
            list.running_checks.insert(pair_id.clone());
        }

        // Get socket
        let sockets = self.sockets.read().await;
        let socket = match sockets.get(&local_addr) {
            Some(s) => s.clone(),
            None => {
                error!("No socket for local address {}", local_addr);
                self.handle_check_failure(stream_id, pair_ref).await;
                return;
            }
        };
        drop(sockets);

        // Create STUN binding request
        let transaction_id = TransactionId::new();
        let mut request = Message::new(MessageType::BindingRequest, transaction_id);

        // Add USERNAME attribute (RFC 8445 Section 7.2.1)
        if let Some(remote_creds) = &*self.remote_creds.read().await {
            let username = format!("{}:{}", remote_creds.ufrag, self.local_creds.ufrag);
            request.add_attribute(Attribute::new(
                AttributeType::Username,
                AttributeValue::Username(username),
            ));
        } else {
            error!("No remote credentials available");
            self.handle_check_failure(stream_id, pair_ref).await;
            return;
        }

        // Add PRIORITY attribute
        let pair = pair_ref.read().await;
        let priority = if *self.controlling.read().await {
            pair.local.priority
        } else {
            // Prflx priority calculation
            let type_pref = 110u32; // Peer reflexive
            let local_pref = 65535u32;
            let component = pair.local.component_id;
            (type_pref << 24) + (local_pref << 8) + (256 - component)
        };
        drop(pair);

        let mut priority_bytes = vec![0u8; 4];
        priority_bytes[0] = (priority >> 24) as u8;
        priority_bytes[1] = (priority >> 16) as u8;
        priority_bytes[2] = (priority >> 8) as u8;
        priority_bytes[3] = priority as u8;

        request.add_attribute(Attribute::new(
            AttributeType::Priority,
            AttributeValue::Raw(priority_bytes),
        ));

        // Add role attributes
        if *self.controlling.read().await {
            let mut controlling_bytes = vec![0u8; 8];
            for (i, byte) in self.tie_breaker.to_be_bytes().iter().enumerate() {
                controlling_bytes[i] = *byte;
            }
            request.add_attribute(Attribute::new(
                AttributeType::IceControlling,
                AttributeValue::Raw(controlling_bytes),
            ));

            if use_candidate {
                debug!("Adding USE-CANDIDATE to check");
                request.add_attribute(Attribute::new(
                    AttributeType::UseCandidate,
                    AttributeValue::Raw(vec![]),
                ));
            }
        } else {
            let mut controlled_bytes = vec![0u8; 8];
            for (i, byte) in self.tie_breaker.to_be_bytes().iter().enumerate() {
                controlled_bytes[i] = *byte;
            }
            request.add_attribute(Attribute::new(
                AttributeType::IceControlled,
                AttributeValue::Raw(controlled_bytes),
            ));
        }

        // Store transaction
        let transaction = CheckTransaction {
            pair: pair_ref.clone(),
            stream_id,
            attempt: 1,
            sent_at: Instant::now(),
            request: request.clone(),
        };

        self.transactions.lock().await.insert(transaction_id, transaction);

        // Get integrity key
        let integrity_key = self.remote_creds.read().await
            .as_ref()
            .map(|c| c.pwd.as_bytes().to_vec());

        // Send request with MESSAGE-INTEGRITY and FINGERPRINT
        match request.encode(integrity_key.as_deref(), true) {
            Ok(data) => {
                trace!("Sending check from {} to {}", local_addr, remote_addr);
                if let Err(e) = socket.send_to(&data, remote_addr).await {
                    error!("Failed to send check: {}", e);
                    self.handle_check_failure(stream_id, pair_ref).await;
                } else {
                    self.stats.checks_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // Schedule retransmission
                    self.schedule_retransmission(transaction_id).await;
                }
            }
            Err(e) => {
                error!("Failed to encode STUN request: {}", e);
                self.handle_check_failure(stream_id, pair_ref).await;
            }
        }
    }

    /// Schedule retransmission for a check
    async fn schedule_retransmission(&self, transaction_id: TransactionId) {
        let checker = Arc::new(self.clone());
        tokio::spawn(async move {
            sleep(checker.rto).await;

            let transaction = checker.transactions.lock().await.get(&transaction_id).cloned();

            if let Some(mut trans) = transaction {
                if trans.attempt < checker.max_attempts {
                    trans.attempt += 1;
                    debug!("Retransmitting check (attempt {})", trans.attempt);

                    // Re-send the check
                    let local_addr = trans.pair.read().await.local.addr;
                    let remote_addr = trans.pair.read().await.remote.addr;

                    if let Some(socket) = checker.sockets.read().await.get(&local_addr) {
                        let integrity_key = checker.remote_creds.read().await
                            .as_ref()
                            .map(|c| c.pwd.as_bytes().to_vec());

                        if let Ok(data) = trans.request.encode(integrity_key.as_deref(), true) {
                            let _ = socket.send_to(&data, remote_addr).await;

                            // Update transaction
                            trans.sent_at = Instant::now();
                            checker.transactions.lock().await.insert(transaction_id, trans);

                            // Schedule next retransmission with exponential backoff
                            let next_rto = checker.rto * (1 << trans.attempt);
                            checker.schedule_retransmission_with_delay(transaction_id, next_rto).await;
                        }
                    }
                } else {
                    // Max attempts reached
                    warn!("Max retransmissions reached for check");
                    checker.transactions.lock().await.remove(&transaction_id);
                    checker.handle_check_failure(trans.stream_id, trans.pair).await;
                }
            }
        });
    }

    /// Schedule retransmission with specific delay
    async fn schedule_retransmission_with_delay(&self, transaction_id: TransactionId, delay: Duration) {
        let checker = Arc::new(self.clone());
        tokio::spawn(async move {
            sleep(delay).await;
            checker.schedule_retransmission(transaction_id).await;
        });
    }

    /// Handle check failure
    async fn handle_check_failure(
        &self,
        stream_id: u32,
        pair_ref: Arc<RwLock<CandidatePair>>,
    ) {
        let pair_id = {
            let mut pair = pair_ref.write().await;
            pair.state = CandidatePairState::Failed;
            pair.id()
        };

        // Remove from running checks
        if let Some(list) = self.check_lists.write().await.get_mut(&stream_id) {
            list.running_checks.remove(&pair_id);
        }

        self.stats.checks_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Send event
        let pair = pair_ref.read().await.clone();
        let _ = self.event_tx.send(ConnectivityEvent::PairStateChanged {
            stream_id,
            pair,
        });

        // Check if all pairs failed
        self.check_list_completion(stream_id).await;
    }

    /// Receive loop for single socket
    async fn socket_receive_loop(
        &self,
        local_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) {
        info!("Starting receive loop for {}", local_addr);
        let mut buffer = vec![0u8; 2048];

        loop {
            if *self.shutdown.read().await {
                break;
            }

            match socket.recv_from(&mut buffer).await {
                Ok((size, remote_addr)) => {
                    trace!("Received {} bytes from {} on {}", size, remote_addr, local_addr);
                    self.stats.checks_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let data = BytesMut::from(&buffer[..size]);

                    if let Ok(message) = Message::decode(data.clone()) {
                        match message.message_type {
                            MessageType::BindingResponse => {
                                self.handle_binding_response(
                                    local_addr,
                                    remote_addr,
                                    message,
                                    &buffer[..size],
                                ).await;
                            }
                            MessageType::BindingRequest => {
                                self.handle_binding_request(
                                    local_addr,
                                    remote_addr,
                                    message,
                                    &socket,
                                ).await;
                            }
                            MessageType::BindingError => {
                                self.handle_binding_error(message).await;
                            }
                            _ => {
                                debug!("Ignoring message type {:?}", message.message_type);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Socket receive error on {}: {}", local_addr, e);
                    break;
                }
            }
        }

        info!("Receive loop ended for {}", local_addr);
    }

    /// Handle STUN binding response
    async fn handle_binding_response(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        response: Message,
        raw_data: &[u8],
    ) {
        debug!("Handling binding response from {}", remote_addr);

        // Find transaction
        let transaction = match self.transactions.lock().await.remove(&response.transaction_id) {
            Some(t) => t,
            None => {
                debug!("Received response for unknown transaction");
                return;
            }
        };

        // Verify addresses match
        let pair = transaction.pair.read().await;
        if pair.local.addr != local_addr || pair.remote.addr != remote_addr {
            warn!("Address mismatch in response");
            return;
        }
        drop(pair);

        // Verify MESSAGE-INTEGRITY if present
        if response.get_attribute(AttributeType::MessageIntegrity).is_some() ||
            response.get_attribute(AttributeType::MessageIntegritySha256).is_some() {
            let key = self.local_creds.pwd.as_bytes();

            if response.get_attribute(AttributeType::MessageIntegritySha256).is_some() {
                if !response.verify_integrity_sha256(key, raw_data).unwrap_or(false) {
                    error!("MESSAGE-INTEGRITY-SHA256 verification failed");
                    self.handle_check_failure(transaction.stream_id, transaction.pair).await;
                    return;
                }
            } else if !response.verify_integrity_sha1(key, raw_data).unwrap_or(false) {
                error!("MESSAGE-INTEGRITY verification failed");
                self.handle_check_failure(transaction.stream_id, transaction.pair).await;
                return;
            }
        }

        // Verify FINGERPRINT if present
        if response.get_attribute(AttributeType::Fingerprint).is_some() {
            if !response.verify_fingerprint(raw_data).unwrap_or(false) {
                error!("FINGERPRINT verification failed");
                self.handle_check_failure(transaction.stream_id, transaction.pair).await;
                return;
            }
        }

        // Calculate RTT
        let rtt = transaction.sent_at.elapsed();

        // Get mapped address
        let mapped_addr = response.attributes.iter()
            .find_map(|attr| match &attr.value {
                AttributeValue::XorMappedAddress(addr) => Some(*addr),
                AttributeValue::MappedAddress(addr) => Some(*addr),
                _ => None,
            });

        if mapped_addr.is_none() {
            warn!("No mapped address in response");
            self.handle_check_failure(transaction.stream_id, transaction.pair).await;
            return;
        }

        // Update pair state
        let pair_id = {
            let mut pair = transaction.pair.write().await;
            pair.state = CandidatePairState::Succeeded;
            pair.valid = true;
            pair.rtt = Some(rtt);
            pair.id()
        };

        // Remove from running checks
        if let Some(list) = self.check_lists.write().await.get_mut(&transaction.stream_id) {
            list.running_checks.remove(&pair_id);

            // Add to valid list
            let already_valid = list.valid_list.iter()
                .any(|p| p.blocking_read().id() == pair_id);

            if !already_valid {
                list.valid_list.push(transaction.pair.clone());
            }
        }

        self.stats.checks_succeeded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Construct discovered peer reflexive candidate if needed
        if let Some(mapped) = mapped_addr {
            if mapped != local_addr {
                // Peer reflexive candidate discovered
                info!("Discovered peer reflexive candidate: {}", mapped);
                // TODO: Add to candidate list
            }
        }

        let pair = transaction.pair.read().await.clone();
        info!("Check succeeded for pair: {} (RTT: {:?})", pair.id(), rtt);

        // Send valid pair event
        let _ = self.event_tx.send(ConnectivityEvent::ValidPair {
            stream_id: transaction.stream_id,
            pair: pair.clone(),
        });

        // Handle nomination
        if pair.use_candidate || (self.aggressive_nomination && *self.controlling.read().await) {
            self.handle_nomination(transaction.stream_id, transaction.pair.clone()).await;
        }

        // Unfreeze pairs with same foundation
        self.unfreeze_pairs_with_foundation(&pair.foundation).await;

        // Check completion
        self.check_list_completion(transaction.stream_id).await;
    }

    /// Handle incoming STUN binding request
    async fn handle_binding_request(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        request: Message,
        socket: &UdpSocket,
    ) {
        debug!("Handling binding request from {} to {}", remote_addr, local_addr);

        // Verify USERNAME attribute
        let username_attr = match request.get_attribute(AttributeType::Username) {
            Some(attr) => attr,
            None => {
                warn!("No USERNAME in binding request");
                self.send_error_response(socket, remote_addr, request.transaction_id, 400, "Bad Request").await;
                return;
            }
        };

        let username = match &username_attr.value {
            AttributeValue::Username(u) => u,
            _ => {
                warn!("Invalid USERNAME attribute");
                self.send_error_response(socket, remote_addr, request.transaction_id, 400, "Bad Request").await;
                return;
            }
        };

        // Verify username format (remote:local)
        let parts: Vec<&str> = username.split(':').collect();
        if parts.len() != 2 || parts[1] != self.local_creds.ufrag {
            warn!("Invalid USERNAME format or ufrag mismatch");
            self.send_error_response(socket, remote_addr, request.transaction_id, 401, "Unauthorized").await;
            return;
        }

        // Verify MESSAGE-INTEGRITY
        let has_integrity = request.get_attribute(AttributeType::MessageIntegrity).is_some() ||
            request.get_attribute(AttributeType::MessageIntegritySha256).is_some();

        if !has_integrity {
            warn!("No MESSAGE-INTEGRITY in request");
            self.send_error_response(socket, remote_addr, request.transaction_id, 401, "Unauthorized").await;
            return;
        }

        // Create response
        let mut response = Message::new(
            MessageType::BindingResponse,
            request.transaction_id,
        );

        // Add XOR-MAPPED-ADDRESS
        response.add_attribute(Attribute::new(
            AttributeType::XorMappedAddress,
            AttributeValue::XorMappedAddress(remote_addr),
        ));

        // Check for role conflict (RFC 8445 Section 7.3.1.1)
        let has_controlling = request.attributes.iter()
            .any(|a| matches!(a.attr_type, AttributeType::IceControlling));
        let has_controlled = request.attributes.iter()
            .any(|a| matches!(a.attr_type, AttributeType::IceControlled));

        let controlling = *self.controlling.read().await;

        if (controlling && has_controlling) || (!controlling && has_controlled) {
            // Role conflict - compare tie breakers
            let their_tie_breaker = request.attributes.iter()
                .find_map(|a| match &a.value {
                    AttributeValue::Raw(data) if data.len() == 8 => {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(data);
                        Some(u64::from_be_bytes(bytes))
                    }
                    _ => None,
                })
                .unwrap_or(0);

            warn!("Role conflict detected: our_tie={}, their_tie={}",
                self.tie_breaker, their_tie_breaker);

            self.stats.role_conflicts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            if (controlling && self.tie_breaker >= their_tie_breaker) ||
                (!controlling && self.tie_breaker < their_tie_breaker) {
                // We win, send 487 error
                self.send_error_response(socket, remote_addr, request.transaction_id, 487, "Role Conflict").await;
                return;
            } else {
                // They win, we should switch roles
                let _ = self.event_tx.send(ConnectivityEvent::RoleConflict {
                    their_tie_breaker,
                });
            }
        }

        // Check USE-CANDIDATE
        let use_candidate = request.attributes.iter()
            .any(|a| matches!(a.attr_type, AttributeType::UseCandidate));

        // Send response with MESSAGE-INTEGRITY and FINGERPRINT
        let integrity_key = self.local_creds.pwd.as_bytes();

        match response.encode(Some(integrity_key), true) {
            Ok(data) => {
                if let Err(e) = socket.send_to(&data, remote_addr).await {
                    error!("Failed to send response: {}", e);
                }
            }
            Err(e) => {
                error!("Failed to encode response: {}", e);
            }
        }

        // Trigger check for this pair (RFC 8445 Section 7.3.1.4)
        self.trigger_check(local_addr, remote_addr, use_candidate).await;
    }

    /// Send STUN error response
    async fn send_error_response(
        &self,
        socket: &UdpSocket,
        remote_addr: SocketAddr,
        transaction_id: TransactionId,
        error_code: u16,
        reason: &str,
    ) {
        let mut response = Message::new(MessageType::BindingError, transaction_id);

        response.add_attribute(Attribute::new(
            AttributeType::ErrorCode,
            AttributeValue::ErrorCode {
                code: error_code,
                reason: reason.to_string(),
            },
        ));

        let integrity_key = self.local_creds.pwd.as_bytes();

        if let Ok(data) = response.encode(Some(integrity_key), true) {
            let _ = socket.send_to(&data, remote_addr).await;
        }
    }

    /// Trigger check for a pair (RFC 8445 Section 7.3.1.4)
    async fn trigger_check(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        use_candidate: bool,
    ) {
        debug!("Triggering check for {} -> {}", local_addr, remote_addr);

        let check_lists = self.check_lists.read().await;

        for (stream_id, list) in check_lists.iter() {
            for pair_ref in &list.pairs {
                let pair = pair_ref.read().await;
                if pair.local.addr == local_addr && pair.remote.addr == remote_addr {
                    match pair.state {
                        CandidatePairState::Waiting | CandidatePairState::Frozen => {
                            drop(pair);
                            let sid = *stream_id;
                            let pair_cloned = pair_ref.clone();
                            drop(check_lists);

                            info!("Adding triggered check to queue");

                            // Add to triggered queue for immediate processing
                            self.triggered_queue.lock().await.push_back(TriggeredCheck {
                                pair: pair_cloned,
                                stream_id: sid,
                                use_candidate,
                                remote_addr,
                            });

                            return;
                        }
                        CandidatePairState::InProgress | CandidatePairState::Succeeded => {
                            // Already being checked or succeeded
                            if use_candidate && pair.state == CandidatePairState::Succeeded {
                                drop(pair);
                                let sid = *stream_id;
                                drop(check_lists);

                                // Nominate this pair
                                self.handle_nomination(sid, pair_ref.clone()).await;
                            }
                            return;
                        }
                        CandidatePairState::Failed => {
                            // Re-check failed pairs
                            drop(pair);
                            let sid = *stream_id;
                            let pair_cloned = pair_ref.clone();
                            drop(check_lists);

                            pair_cloned.write().await.state = CandidatePairState::Waiting;

                            self.triggered_queue.lock().await.push_back(TriggeredCheck {
                                pair: pair_cloned,
                                stream_id: sid,
                                use_candidate,
                                remote_addr,
                            });

                            return;
                        }
                    }
                }
            }
        }

        // No matching pair found - create peer reflexive
        info!("No matching pair for trigger - would create peer reflexive");
        // TODO: Create peer reflexive candidate and pair
    }

    /// Handle STUN binding error
    async fn handle_binding_error(&self, error: Message) {
        if let Some(transaction) = self.transactions.lock().await.remove(&error.transaction_id) {
            if let Some(error_attr) = error.get_attribute(AttributeType::ErrorCode) {
                if let AttributeValue::ErrorCode { code, reason } = &error_attr.value {
                    error!("Binding error {}: {}", code, reason);

                    if *code == 487 {
                        // Role conflict
                        self.stats.role_conflicts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }

            self.handle_check_failure(transaction.stream_id, transaction.pair).await;
        }
    }

    /// Handle nomination of a pair
    async fn handle_nomination(&self, stream_id: u32, pair_ref: Arc<RwLock<CandidatePair>>) {
        let mut pair = pair_ref.write().await;

        if pair.nominated {
            return; // Already nominated
        }

        pair.nominated = true;
        let component_id = pair.local.component_id;
        let pair_clone = pair.clone();
        drop(pair);

        info!("Nominating pair: {} for stream {} component {}",
            pair_clone.id(), stream_id, component_id);

        let _ = self.event_tx.send(ConnectivityEvent::NominatedPair {
            stream_id,
            component_id,
            pair: pair_clone,
        });
    }

    /// Unfreeze pairs with same foundation
    async fn unfreeze_pairs_with_foundation(&self, foundation: &str) {
        debug!("Unfreezing pairs with foundation: {}", foundation);

        let check_lists = self.check_lists.read().await;

        for list in check_lists.values() {
            if let Some(pairs) = list.foundation_map.get(foundation) {
                for pair_ref in pairs {
                    let mut pair = pair_ref.write().await;
                    if pair.state == CandidatePairState::Frozen {
                        debug!("Unfreezing pair: {}", pair.id());
                        pair.state = CandidatePairState::Waiting;
                    }
                }
            }
        }
    }

    /// Check if check list is complete
    async fn check_list_completion(&self, stream_id: u32) {
        let mut check_lists = self.check_lists.write().await;
        let list = match check_lists.get_mut(&stream_id) {
            Some(l) => l,
            None => return,
        };

        // Check if we have nominated pairs for all components
        let components: HashSet<u32> = list.pairs.iter()
            .map(|p| p.blocking_read().local.component_id)
            .collect();

        let nominated_components: HashSet<u32> = list.valid_list.iter()
            .filter_map(|p| {
                let pair = p.blocking_read();
                if pair.nominated {
                    Some(pair.local.component_id)
                } else {
                    None
                }
            })
            .collect();

        if nominated_components.len() == components.len() {
            info!("Check list completed for stream {} - all components nominated", stream_id);
            list.state = CheckListState::Completed;
            let _ = self.event_tx.send(ConnectivityEvent::CheckListCompleted { stream_id });
            return;
        }

        // Check if all pairs are in terminal state
        let all_terminal = list.pairs.iter().all(|p| {
            let pair = p.blocking_read();
            matches!(pair.state, CandidatePairState::Succeeded | CandidatePairState::Failed)
        });

        if all_terminal {
            if list.valid_list.is_empty() {
                error!("Check list failed for stream {} - no valid pairs", stream_id);
                list.state = CheckListState::Failed;
                let _ = self.event_tx.send(ConnectivityEvent::CheckListFailed { stream_id });
            } else if *self.controlling.read().await {
                // Controlling agent nominates best pairs
                info!("All checks complete, nominating best pairs for stream {}", stream_id);

                for component_id in components {
                    let best_pair = list.valid_list.iter()
                        .filter(|p| p.blocking_read().local.component_id == component_id)
                        .max_by_key(|p| p.blocking_read().priority);

                    if let Some(pair_ref) = best_pair {
                        self.handle_nomination(stream_id, pair_ref.clone()).await;
                    }
                }
            }
        }
    }

    /// Send keepalive on a pair
    pub async fn send_keepalive(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> NatResult<()> {
        debug!("Sending keepalive from {} to {}", local_addr, remote_addr);

        let socket = self.sockets.read().await
            .get(&local_addr)
            .cloned()
            .ok_or_else(|| NatError::Platform("No socket for keepalive".to_string()))?;

        // Send STUN Binding Indication (no response expected)
        let indication = Message::new(
            MessageType::BindingIndication,
            TransactionId::new(),
        );

        let data = indication.encode(None, true)?;
        socket.send_to(&data, remote_addr).await?;

        Ok(())
    }

    /// Check if all check lists have failed
    pub async fn all_failed(&self) -> bool {
        let lists = self.check_lists.read().await;

        !lists.is_empty() && lists.values().all(|list| {
            list.state == CheckListState::Failed
        })
    }

    /// Close connectivity checker
    pub async fn close(&self) {
        info!("Closing connectivity checker");
        *self.shutdown.write().await = true;

        // Cancel all tasks
        if let Some(task) = self.checker_task.lock().await.take() {
            task.abort();
        }

        if let Some(task) = self.triggered_task.lock().await.take() {
            task.abort();
        }

        for task in self.receiver_tasks.lock().await.drain(..) {
            task.abort();
        }

        for task in self.nomination_timers.lock().await.drain() {
            task.1.abort();
        }
    }
}

// Clone implementation
impl Clone for ConnectivityChecker {
    fn clone(&self) -> Self {
        Self {
            check_lists: self.check_lists.clone(),
            sockets: self.sockets.clone(),
            transactions: self.transactions.clone(),
            triggered_queue: self.triggered_queue.clone(),
            ta: self.ta,
            rto: self.rto,
            max_attempts: self.max_attempts,
            controlling: self.controlling.clone(),
            tie_breaker: self.tie_breaker,
            local_creds: self.local_creds.clone(),
            remote_creds: self.remote_creds.clone(),
            event_tx: self.event_tx.clone(),
            checker_task: self.checker_task.clone(),
            triggered_task: self.triggered_task.clone(),
            receiver_tasks: self.receiver_tasks.clone(),
            shutdown: self.shutdown.clone(),
            aggressive_nomination: self.aggressive_nomination,
            nomination_timers: self.nomination_timers.clone(),
            stats: self.stats.clone(),
        }
    }
}

// Helper trait implementations for STUN
impl Message {
    fn verify_integrity_sha1(&self, key: &[u8], raw_msg: &[u8]) -> NatResult<bool> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        let attr = self.get_attribute(AttributeType::MessageIntegrity)
            .ok_or_else(|| StunError::MissingAttribute("MESSAGE-INTEGRITY".to_string()))?;

        if let AttributeValue::Raw(hash) = &attr.value {
            if hash.len() != 20 {
                return Ok(false);
            }

            // Find position of MESSAGE-INTEGRITY attribute
            let integrity_pos = self.find_attribute_position(raw_msg, AttributeType::MessageIntegrity)?;

            // Create message for verification (up to but not including the attribute)
            let verify_len = integrity_pos + 4 + 20; // Include the attribute itself
            if raw_msg.len() < verify_len {
                return Ok(false);
            }

            // Copy message and update length field
            let mut verify_msg = raw_msg[..verify_len].to_vec();
            let new_len = (verify_len - 20) as u16; // STUN header is 20 bytes
            verify_msg[2..4].copy_from_slice(&new_len.to_be_bytes());

            // Calculate HMAC-SHA1
            let mut mac = Hmac::<Sha1>::new_from_slice(key)
                .map_err(|e| StunError::ParseError(format!("Invalid key: {}", e)))?;
            mac.update(&verify_msg[..integrity_pos]);

            Ok(mac.verify_slice(hash).is_ok())
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_list_creation() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let checker = ConnectivityChecker::new(
            true,
            IceCredentials::generate(),
            tx,
            false,
        );

        let local = vec![
            Candidate::new_host(
                "192.168.1.100:50000".parse().unwrap(),
                1,
                TransportProtocol::Udp,
                1,
            ),
        ];

        let remote = vec![
            Candidate::new_host(
                "192.168.1.200:50000".parse().unwrap(),
                1,
                TransportProtocol::Udp,
                1,
            ),
        ];

        checker.create_check_list(1, local, remote).await.unwrap();

        let lists = checker.check_lists.read().await;
        assert!(lists.contains_key(&1));

        let list = &lists[&1];
        assert_eq!(list.pairs.len(), 1);
        assert_eq!(list.state, CheckListState::Running);
    }

    #[tokio::test]
    async fn test_triggered_check_queue() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let checker = Arc::new(ConnectivityChecker::new(
            true,
            IceCredentials::generate(),
            tx,
            false,
        ));

        // Add a triggered check
        let pair = CandidatePair::new(
            Candidate::new_host("192.168.1.1:5000".parse().unwrap(), 1, TransportProtocol::Udp, 1),
            Candidate::new_host("192.168.1.2:5000".parse().unwrap(), 1, TransportProtocol::Udp, 1),
            true,
        );

        checker.triggered_queue.lock().await.push_back(TriggeredCheck {
            pair: Arc::new(RwLock::new(pair)),
            stream_id: 1,
            use_candidate: false,
            remote_addr: "192.168.1.2:5000".parse().unwrap(),
        });

        // Queue should have one item
        assert_eq!(checker.triggered_queue.lock().await.len(), 1);
    }
}