// src/nat/ice/connectivity.rs
//! ICE connectivity checks implementation (RFC 8445 Section 7)

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::{interval, timeout};
use rand::Rng;
use bytes::{Bytes, BytesMut, BufMut};
use crate::nat::stun::{
    Message, MessageType, TransactionId, Attribute, AttributeType, AttributeValue,
};
use crate::nat::error::{NatError, NatResult};
use super::{Candidate, CandidatePair, IceCredentials, TransportProtocol};
use super::candidate::CandidatePairState;

/// Connectivity check manager
pub struct ConnectivityChecker {
    /// Check list for each stream
    check_lists: Arc<RwLock<HashMap<u32, CheckList>>>,
    
    /// Sockets for sending checks
    sockets: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>>,
    
    /// Transaction to pair mapping
    transactions: Arc<Mutex<HashMap<TransactionId, CheckTransaction>>>,
    
    /// Triggered check queue (RFC 8445 Section 7.3.1.4)
    triggered_queue: Arc<Mutex<VecDeque<TriggeredCheck>>>,
    
    /// Timer interval (Ta)
    ta: Duration,
    
    /// RTO (retransmission timeout)
    rto: Duration,
    
    /// Maximum check attempts
    max_attempts: u32,
    
    /// Role (controlling/controlled)
    controlling: bool,
    
    /// Tie breaker for role conflicts
    tie_breaker: u64,
    
    /// Local credentials
    local_creds: IceCredentials,
    
    /// Remote credentials
    remote_creds: Option<IceCredentials>,
    
    /// Event sender
    event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
}

/// Check list for a stream
#[derive(Debug)]
pub struct CheckList {
    /// Stream ID
    stream_id: u32,
    
    /// All pairs
    pairs: Vec<Arc<RwLock<CandidatePair>>>,
    
    /// Check list state
    state: CheckListState,
    
    /// Valid list (succeeded pairs)
    valid_list: Vec<Arc<RwLock<CandidatePair>>>,
    
    /// Running check (currently in progress)
    running_check: Option<Arc<RwLock<CandidatePair>>>,
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
}

/// Triggered check
#[derive(Debug)]
struct TriggeredCheck {
    pair: Arc<RwLock<CandidatePair>>,
    stream_id: u32,
    use_candidate: bool,
}

/// Connectivity check event
#[derive(Debug)]
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
}

impl ConnectivityChecker {
    /// Create new connectivity checker
    pub fn new(
        controlling: bool,
        local_creds: IceCredentials,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> Self {
        let tie_breaker = rand::thread_rng().gen::<u64>();
        
        Self {
            check_lists: Arc::new(RwLock::new(HashMap::new())),
            sockets: Arc::new(RwLock::new(HashMap::new())),
            transactions: Arc::new(Mutex::new(HashMap::new())),
            triggered_queue: Arc::new(Mutex::new(VecDeque::new())),
            ta: Duration::from_millis(50), // RFC 8445 recommends 50ms
            rto: Duration::from_millis(500), // Initial RTO
            max_attempts: 7, // Rc = 7
            controlling,
            tie_breaker,
            local_creds,
            remote_creds: None,
            event_tx,
        }
    }
    
    /// Set remote credentials
    pub fn set_remote_credentials(&mut self, creds: IceCredentials) {
        self.remote_creds = Some(creds);
    }
    
    /// Add socket for candidate
    pub async fn add_socket(&self, addr: SocketAddr, socket: Arc<UdpSocket>) {
        self.sockets.write().await.insert(addr, socket);
    }
    
    /// Create check list for stream
    pub async fn create_check_list(
        &self,
        stream_id: u32,
        local_candidates: Vec<Candidate>,
        remote_candidates: Vec<Candidate>,
    ) -> NatResult<()> {
        let mut pairs = Vec::new();
        
        // Form candidate pairs (RFC 8445 Section 6.1.2.2)
        for local in &local_candidates {
            for remote in &remote_candidates {
                // Only pair candidates with same component
                if local.component_id != remote.component_id {
                    continue;
                }
                
                // RFC 8421: Skip pairing IPv4 with IPv6
                if local.is_ipv6() != remote.is_ipv6() {
                    continue;
                }
                
                let pair = CandidatePair::new(
                    local.clone(),
                    remote.clone(),
                    self.controlling,
                );
                
                pairs.push(Arc::new(RwLock::new(pair)));
            }
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
        
        // Limit check list size (RFC 8445 Section 6.1.2.5)
        const MAX_PAIRS: usize = 100;
        if pruned_pairs.len() > MAX_PAIRS {
            pruned_pairs.truncate(MAX_PAIRS);
        }
        
        // Set initial states (RFC 8445 Section 6.1.2.6)
        for (i, pair) in pruned_pairs.iter().enumerate() {
            let mut p = pair.write().await;
            if i == 0 {
                // First pair is Waiting
                p.state = CandidatePairState::Waiting;
            } else {
                // Check if foundation matches any previous pair
                let foundation = p.foundation.clone();
                let matches_previous = pruned_pairs[..i].iter().any(|prev| {
                    prev.blocking_read().foundation == foundation
                });
                
                if matches_previous {
                    p.state = CandidatePairState::Frozen;
                } else {
                    p.state = CandidatePairState::Waiting;
                }
            }
        }
        
        let check_list = CheckList {
            stream_id,
            pairs: pruned_pairs,
            state: CheckListState::Running,
            valid_list: Vec::new(),
            running_check: None,
        };
        
        self.check_lists.write().await.insert(stream_id, check_list);
        
        Ok(())
    }
    
    /// Start connectivity checks
    pub async fn start_checks(&self) {
        let checker = Arc::new(self.clone());
        
        tokio::spawn(async move {
            checker.check_timer_loop().await;
        });
        
        let checker = Arc::new(self.clone());
        tokio::spawn(async move {
            checker.receive_loop().await;
        });
    }
    
    /// Main check timer loop
    async fn check_timer_loop(self: Arc<Self>) {
        let mut timer = interval(self.ta);
        
        loop {
            timer.tick().await;
            
            // Process triggered checks first (RFC 8445 Section 7.3.1.4)
            if let Some(triggered) = self.triggered_queue.lock().await.pop_front() {
                self.send_check(
                    triggered.stream_id,
                    triggered.pair,
                    triggered.use_candidate,
                ).await;
                continue;
            }
            
            // Find next pair to check
            let check_lists = self.check_lists.read().await;
            
            for (stream_id, list) in check_lists.iter() {
                if list.state != CheckListState::Running {
                    continue;
                }
                
                // Skip if already have running check
                if list.running_check.is_some() {
                    continue;
                }
                
                // Find next waiting pair
                for pair_ref in &list.pairs {
                    let pair = pair_ref.read().await;
                    if pair.state == CandidatePairState::Waiting {
                        drop(pair);
                        drop(check_lists);
                        
                        self.send_check(*stream_id, pair_ref.clone(), false).await;
                        return;
                    }
                }
            }
            
            // No waiting pairs, unfreeze if needed (RFC 8445 Section 6.1.4.2)
            for (_stream_id, list) in check_lists.iter() {
                if list.state != CheckListState::Running {
                    continue;
                }
                
                // Find frozen pairs with unique foundation
                let mut foundations_in_progress = std::collections::HashSet::new();
                
                for pair_ref in &list.pairs {
                    let pair = pair_ref.read().await;
                    if pair.state == CandidatePairState::InProgress {
                        foundations_in_progress.insert(pair.foundation.clone());
                    }
                }
                
                for pair_ref in &list.pairs {
                    let mut pair = pair_ref.write().await;
                    if pair.state == CandidatePairState::Frozen &&
                       !foundations_in_progress.contains(&pair.foundation) {
                        pair.state = CandidatePairState::Waiting;
                        break;
                    }
                }
            }
        }
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
        pair.state = CandidatePairState::InProgress;
        pair.checks_sent += 1;
        pair.last_check_sent = Some(Instant::now());
        
        if use_candidate {
            pair.use_candidate = true;
        }
        
        let local_addr = pair.local.addr;
        let remote_addr = pair.remote.addr;
        
        drop(pair);
        
        // Get socket
        let sockets = self.sockets.read().await;
        let socket = match sockets.get(&local_addr) {
            Some(s) => s.clone(),
            None => {
                tracing::error!("No socket for local address {}", local_addr);
                return;
            }
        };
        drop(sockets);
        
        // Create STUN binding request
        let transaction_id = TransactionId::new();
        let mut request = Message::new(MessageType::BindingRequest, transaction_id);
        
        // Add USERNAME attribute (RFC 8445 Section 7.2.1)
        if let Some(remote_creds) = &self.remote_creds {
            let username = format!("{}:{}", remote_creds.ufrag, self.local_creds.ufrag);
            request.add_attribute(Attribute::new(
                AttributeType::Username,
                AttributeValue::Username(username),
            ));
        }
        
        // Add PRIORITY attribute
        let pair = pair_ref.read().await;
        let priority = if self.controlling {
            pair.local.priority
        } else {
            pair.remote.priority
        };
        drop(pair);
        
        let mut priority_bytes = BytesMut::with_capacity(4);
        priority_bytes.put_u32(priority);
        request.add_attribute(Attribute::new(
            AttributeType::Priority,
            AttributeValue::Raw(priority_bytes.to_vec()),
        ));
        
        // Add role attributes
        if self.controlling {
            let mut controlling_bytes = BytesMut::with_capacity(8);
            controlling_bytes.put_u64(self.tie_breaker);
            request.add_attribute(Attribute::new(
                AttributeType::IceControlling,
                AttributeValue::Raw(controlling_bytes.to_vec()),
            ));
            
            if use_candidate {
                request.add_attribute(Attribute::new(
                    AttributeType::UseCandidate,
                    AttributeValue::Raw(vec![]),
                ));
            }
        } else {
            let mut controlled_bytes = BytesMut::with_capacity(8);
            controlled_bytes.put_u64(self.tie_breaker);
            request.add_attribute(Attribute::new(
                AttributeType::IceControlled,
                AttributeValue::Raw(controlled_bytes.to_vec()),
            ));
        }
        
        // Store transaction
        let transaction = CheckTransaction {
            pair: pair_ref.clone(),
            stream_id,
            attempt: 1,
            sent_at: Instant::now(),
        };
        
        self.transactions.lock().await.insert(transaction_id, transaction);
        
        // Update check list
        self.check_lists.write().await
            .get_mut(&stream_id)
            .unwrap()
            .running_check = Some(pair_ref.clone());
        
        // Send request
        let integrity_key = self.remote_creds.as_ref()
            .map(|c| c.pwd.as_bytes().to_vec());
            
        match request.encode(integrity_key.as_deref(), true) {
            Ok(data) => {
                if let Err(e) = socket.send_to(&data, remote_addr).await {
                    tracing::error!("Failed to send check: {}", e);
                    self.handle_check_failure(stream_id, pair_ref).await;
                }
            }
            Err(e) => {
                tracing::error!("Failed to encode STUN request: {}", e);
                self.handle_check_failure(stream_id, pair_ref).await;
            }
        }
    }
    
    /// Handle check failure
    async fn handle_check_failure(
        &self,
        stream_id: u32,
        pair_ref: Arc<RwLock<CandidatePair>>,
    ) {
        let mut pair = pair_ref.write().await;
        pair.state = CandidatePairState::Failed;
        drop(pair);
        
        // Clear running check
        if let Some(list) = self.check_lists.write().await.get_mut(&stream_id) {
            list.running_check = None;
        }
        
        // Send event
        let pair = pair_ref.read().await.clone();
        let _ = self.event_tx.send(ConnectivityEvent::PairStateChanged {
            stream_id,
            pair,
        });
        
        // Check if all pairs failed
        self.check_list_completion(stream_id).await;
    }
    
    /// Receive loop for STUN responses
    async fn receive_loop(self: Arc<Self>) {
        let sockets = self.sockets.read().await;
        let mut receivers = Vec::new();
        
        for (addr, socket) in sockets.iter() {
            let addr = *addr;
            let socket = socket.clone();
            let checker = self.clone();
            
            receivers.push(tokio::spawn(async move {
                checker.socket_receive_loop(addr, socket).await;
            }));
        }
        
        drop(sockets);
        
        // Wait for all receivers
        for receiver in receivers {
            let _ = receiver.await;
        }
    }
    
    /// Receive loop for single socket
    async fn socket_receive_loop(
        &self,
        local_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) {
        let mut buffer = vec![0u8; 2048];
        
        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((size, remote_addr)) => {
                    let data = BytesMut::from(&buffer[..size]);
                    
                    if let Ok(message) = Message::decode(data) {
                        match message.message_type {
                            MessageType::BindingResponse => {
                                self.handle_binding_response(
                                    local_addr,
                                    remote_addr,
                                    message,
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
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Socket receive error on {}: {}", local_addr, e);
                    break;
                }
            }
        }
    }
    
    /// Handle STUN binding response
    async fn handle_binding_response(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        response: Message,
    ) {
        // Find transaction
        let transaction = match self.transactions.lock().await.remove(&response.transaction_id) {
            Some(t) => t,
            None => {
                tracing::debug!("Received response for unknown transaction");
                return;
            }
        };
        
        // Calculate RTT
        let rtt = transaction.sent_at.elapsed();
        
        // Get mapped address
        let mapped_addr = response.attributes.iter()
            .find_map(|attr| match &attr.value {
                AttributeValue::XorMappedAddress(addr) => Some(*addr),
                AttributeValue::MappedAddress(addr) => Some(*addr),
                _ => None,
            });
        
        let mut pair = transaction.pair.write().await;
        
        // Verify addresses match
        if pair.local.addr != local_addr || pair.remote.addr != remote_addr {
            tracing::warn!("Address mismatch in response");
            return;
        }
        
        // Update pair state
        pair.state = CandidatePairState::Succeeded;
        pair.valid = true;
        pair.rtt = Some(rtt);
        
        let pair_clone = pair.clone();
        drop(pair);
        
        // Clear running check
        if let Some(list) = self.check_lists.write().await.get_mut(&transaction.stream_id) {
            list.running_check = None;
            
            // Add to valid list
            let already_valid = list.valid_list.iter()
                .any(|p| p.blocking_read().id() == pair_clone.id());
                
            if !already_valid {
                list.valid_list.push(transaction.pair.clone());
            }
        }
        
        // Construct discovered peer reflexive candidate if needed
        if let Some(mapped) = mapped_addr {
            if mapped != local_addr {
                // Peer reflexive candidate discovered
                // TODO: Add to candidate list
                tracing::debug!("Discovered peer reflexive candidate: {}", mapped);
            }
        }
        
        // Send event
        let _ = self.event_tx.send(ConnectivityEvent::ValidPair {
            stream_id: transaction.stream_id,
            pair: pair_clone.clone(),
        });
        
        // Handle nomination if USE-CANDIDATE was set
        if pair_clone.use_candidate {
            let _ = self.event_tx.send(ConnectivityEvent::NominatedPair {
                stream_id: transaction.stream_id,
                component_id: pair_clone.local.component_id,
                pair: pair_clone,
            });
        }
        
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
            .any(|a| a.attr_type == AttributeType::IceControlling);
        let has_controlled = request.attributes.iter()
            .any(|a| a.attr_type == AttributeType::IceControlled);
            
        if (self.controlling && has_controlling) || (!self.controlling && has_controlled) {
            // Role conflict - compare tie breakers
            // For now, just log it
            tracing::warn!("Role conflict detected");
        }
        
        // Check USE-CANDIDATE
        let use_candidate = request.attributes.iter()
            .any(|a| a.attr_type == AttributeType::UseCandidate);
            
        // Send response
        let integrity_key = self.local_creds.pwd.as_bytes();
        
        match response.encode(Some(integrity_key), true) {
            Ok(data) => {
                if let Err(e) = socket.send_to(&data, remote_addr).await {
                    tracing::error!("Failed to send response: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to encode response: {}", e);
            }
        }
        
        // Trigger check for this pair (RFC 8445 Section 7.3.1.4)
        let check_lists = self.check_lists.read().await;
        for (stream_id, list) in check_lists.iter() {
            for pair_ref in &list.pairs {
                let pair = pair_ref.read().await;
                if pair.local.addr == local_addr && pair.remote.addr == remote_addr {
                    if pair.state == CandidatePairState::Waiting ||
                       pair.state == CandidatePairState::Frozen {
                        drop(pair);
                        drop(check_lists);
                        
                        // Add to triggered queue
                        self.triggered_queue.lock().await.push_back(TriggeredCheck {
                            pair: pair_ref.clone(),
                            stream_id: *stream_id,
                            use_candidate,
                        });
                        
                        return;
                    }
                }
            }
        }
    }
    
    /// Handle STUN binding error
    async fn handle_binding_error(&self, error: Message) {
        if let Some(transaction) = self.transactions.lock().await.remove(&error.transaction_id) {
            self.handle_check_failure(transaction.stream_id, transaction.pair).await;
        }
    }
    
    /// Check if check list is complete
    async fn check_list_completion(&self, stream_id: u32) {
        let mut check_lists = self.check_lists.write().await;
        let list = match check_lists.get_mut(&stream_id) {
            Some(l) => l,
            None => return,
        };
        
        // Check if all pairs are in terminal state
        let all_terminal = list.pairs.iter().all(|p| {
            let pair = p.blocking_read();
            matches!(pair.state, CandidatePairState::Succeeded | CandidatePairState::Failed)
        });
        
        if all_terminal {
            if list.valid_list.is_empty() {
                list.state = CheckListState::Failed;
                let _ = self.event_tx.send(ConnectivityEvent::CheckListFailed { stream_id });
            } else {
                list.state = CheckListState::Completed;
                let _ = self.event_tx.send(ConnectivityEvent::CheckListCompleted { stream_id });
            }
        }
    }
}

// Additional attribute types for ICE
impl AttributeType {
    pub const Priority: AttributeType = AttributeType::Padding; // 0x0024
    pub const UseCandidate: AttributeType = AttributeType::Padding; // 0x0025
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
            controlling: self.controlling,
            tie_breaker: self.tie_breaker,
            local_creds: self.local_creds.clone(),
            remote_creds: self.remote_creds.clone(),
            event_tx: self.event_tx.clone(),
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
}