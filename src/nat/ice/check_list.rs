// src/nat/ice/check_list.rs
//! ICE check list management - Full RFC 8445 implementation
//! Implements all requirements from RFC 8445 Section 6

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tracing::{debug, info, warn, error, trace};

use super::{CandidatePair, Candidate, CandidateType};
use super::candidate::CandidatePairState;
use super::foundation::calculate_pair_foundation;
use crate::nat::error::{NatError, NatResult};

/// Maximum number of pairs in a check list (RFC 8445 Section 6.1.2.5)
const MAX_PAIRS_PER_STREAM: usize = 100;

/// Maximum number of waiting+in-progress pairs per foundation
const MAX_PAIRS_PER_FOUNDATION: usize = 5;

/// Check list for managing candidate pairs per RFC 8445 Section 6
pub struct CheckList {
    /// Stream ID
    pub stream_id: u32,

    /// All candidate pairs sorted by priority (highest first)
    /// Invariant: Always sorted in descending priority order
    pairs: Vec<Arc<RwLock<CandidatePair>>>,

    /// State of the check list
    pub state: CheckListState,

    /// Valid pairs (connectivity check succeeded)
    /// Sorted by priority for efficient nomination
    valid_pairs: Vec<Arc<RwLock<CandidatePair>>>,

    /// Running pairs indexed by pair ID
    running_pairs: HashMap<String, Arc<RwLock<CandidatePair>>>,

    /// Foundation groups for managing frozen candidates
    foundation_groups: HashMap<String, FoundationGroup>,

    /// Triggered check queue (RFC 8445 Section 7.3.1.4)
    triggered_queue: VecDeque<TriggeredCheck>,

    /// Statistics
    stats: CheckListStats,

    /// Creation timestamp
    created_at: Instant,
}

/// Foundation group for managing related pairs
#[derive(Debug)]
struct FoundationGroup {
    /// Pairs in this foundation
    pairs: Vec<Arc<RwLock<CandidatePair>>>,

    /// Number of waiting or in-progress pairs
    active_count: usize,

    /// Has at least one succeeded pair
    has_succeeded: bool,
}

/// Triggered check information
#[derive(Debug, Clone)]
pub struct TriggeredCheck {
    /// The pair to check
    pub pair: Arc<RwLock<CandidatePair>>,

    /// Use candidate flag
    pub use_candidate: bool,

    /// When this was triggered
    pub triggered_at: Instant,
}

/// Check list statistics
#[derive(Debug, Default)]
struct CheckListStats {
    /// Total pairs created
    total_pairs: usize,

    /// Pairs pruned
    pruned_pairs: usize,

    /// Checks performed
    checks_performed: usize,

    /// Successful checks
    successful_checks: usize,

    /// Failed checks
    failed_checks: usize,

    /// Nominated pairs
    nominated_pairs: usize,
}

/// Check list state per RFC 8445 Section 6.1.2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckListState {
    /// Initial state
    Running,

    /// All pairs have been tested, some succeeded
    Completed,

    /// All pairs have been tested, none succeeded
    Failed,
}

impl CheckList {
    /// Create new check list for a stream
    pub fn new(stream_id: u32) -> Self {
        info!("Creating check list for stream {}", stream_id);

        Self {
            stream_id,
            pairs: Vec::with_capacity(MAX_PAIRS_PER_STREAM),
            state: CheckListState::Running,
            valid_pairs: Vec::new(),
            running_pairs: HashMap::new(),
            foundation_groups: HashMap::new(),
            triggered_queue: VecDeque::new(),
            stats: CheckListStats::default(),
            created_at: Instant::now(),
        }
    }

    /// Form check list from candidates per RFC 8445 Section 6.1.2
    pub async fn form_check_list(
        &mut self,
        local_candidates: Vec<Candidate>,
        remote_candidates: Vec<Candidate>,
        controlling: bool,
    ) -> NatResult<()> {
        info!(
            "Forming check list for stream {}: {} local x {} remote candidates",
            self.stream_id,
            local_candidates.len(),
            remote_candidates.len()
        );

        // Step 1: Form candidate pairs (RFC 8445 Section 6.1.2.2)
        let mut all_pairs = Vec::new();

        for local in &local_candidates {
            for remote in &remote_candidates {
                // Only pair candidates with same component
                if local.component_id != remote.component_id {
                    continue;
                }

                // Skip pairing IPv4 with IPv6 (RFC 8421)
                if local.addr.is_ipv4() != remote.addr.is_ipv4() {
                    continue;
                }

                // Skip loopback addresses
                if local.addr.ip().is_loopback() || remote.addr.ip().is_loopback() {
                    continue;
                }

                // Create pair
                let pair = CandidatePair::new(
                    local.clone(),
                    remote.clone(),
                    controlling,
                );

                trace!(
                    "Created pair: {} -> {} (priority: {}, foundation: {})",
                    local.addr,
                    remote.addr,
                    pair.priority,
                    pair.foundation
                );

                all_pairs.push(Arc::new(RwLock::new(pair)));
            }
        }

        self.stats.total_pairs = all_pairs.len();
        info!("Created {} candidate pairs", all_pairs.len());

        if all_pairs.is_empty() {
            warn!("No valid pairs created for stream {}", self.stream_id);
            self.state = CheckListState::Failed;
            return Ok(());
        }

        // Step 2: Sort by priority (RFC 8445 Section 6.1.2.3)
        // Collect priorities to avoid holding locks during sort
        let mut pairs_with_priority: Vec<(Arc<RwLock<CandidatePair>>, u64)> =
            Vec::with_capacity(all_pairs.len());

        for pair in all_pairs {
            let priority = pair.read().await.priority;
            pairs_with_priority.push((pair, priority));
        }

        // Sort by priority descending (highest first)
        pairs_with_priority.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        debug!("Sorted {} pairs by priority", pairs_with_priority.len());

        // Step 3: Prune redundant pairs (RFC 8445 Section 6.1.2.4)
        let pruned_pairs = self.prune_pairs_internal(pairs_with_priority).await?;
        info!(
            "Pruned {} redundant pairs, {} remaining",
            self.stats.pruned_pairs,
            pruned_pairs.len()
        );

        // Step 4: Limit check list size (RFC 8445 Section 6.1.2.5)
        let limited_pairs = if pruned_pairs.len() > MAX_PAIRS_PER_STREAM {
            info!(
                "Limiting check list from {} to {} pairs",
                pruned_pairs.len(),
                MAX_PAIRS_PER_STREAM
            );
            pruned_pairs.into_iter()
                .take(MAX_PAIRS_PER_STREAM)
                .collect()
        } else {
            pruned_pairs
        };

        // Step 5: Initialize pair states and foundation groups (RFC 8445 Section 6.1.2.6)
        await self.initialize_pair_states(limited_pairs).await?;

        info!(
            "Check list formed for stream {}: {} pairs, {} foundations",
            self.stream_id,
            self.pairs.len(),
            self.foundation_groups.len()
        );

        Ok(())
    }

    /// Prune redundant pairs per RFC 8445 Section 6.1.2.4
    async fn prune_pairs_internal(
        &mut self,
        mut pairs: Vec<(Arc<RwLock<CandidatePair>>, u64)>,
    ) -> NatResult<Vec<Arc<RwLock<CandidatePair>>>> {
        let mut pruned = Vec::with_capacity(pairs.len());
        let mut seen_bases = HashSet::new();

        for (pair_ref, _) in pairs {
            let pair = pair_ref.read().await;
            let should_prune = {
                // Check if this is a redundant server reflexive pair
                if pair.local.typ == CandidateType::ServerReflexive {
                    if let Some(base_addr) = pair.local.related_addr {
                        // Check if we've seen a host candidate with this base
                        let base_key = format!("{}:{}", base_addr, pair.remote.addr);
                        if seen_bases.contains(&base_key) {
                            debug!(
                                "Pruning redundant srflx pair: {} (base: {})",
                                pair.id(),
                                base_addr
                            );
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if !should_prune {
                // Record base addresses for host candidates
                if pair.local.typ == CandidateType::Host {
                    let base_key = format!("{}:{}", pair.local.addr, pair.remote.addr);
                    seen_bases.insert(base_key);
                }

                drop(pair);
                pruned.push(pair_ref);
            } else {
                self.stats.pruned_pairs += 1;
            }
        }

        Ok(pruned)
    }

    /// Initialize pair states and foundation groups
    async fn initialize_pair_states(
        &mut self,
        pairs: Vec<Arc<RwLock<CandidatePair>>>,
    ) -> NatResult<()> {
        // Group by foundation
        let mut temp_foundation_groups: HashMap<String, Vec<Arc<RwLock<CandidatePair>>>> =
            HashMap::new();

        for pair_ref in &pairs {
            let foundation = pair_ref.read().await.foundation.clone();
            temp_foundation_groups
                .entry(foundation)
                .or_insert_with(Vec::new)
                .push(pair_ref.clone());
        }

        // Initialize states per RFC 8445 Section 6.1.2.6
        let mut waiting_foundations = HashSet::new();

        for pair_ref in &pairs {
            let mut pair = pair_ref.write().await;

            // First pairs and first of each foundation start as Waiting
            if self.pairs.len() < 5 || !waiting_foundations.contains(&pair.foundation) {
                pair.state = CandidatePairState::Waiting;
                waiting_foundations.insert(pair.foundation.clone());
                debug!("Pair {} set to Waiting (foundation: {})", pair.id(), pair.foundation);
            } else {
                pair.state = CandidatePairState::Frozen;
                trace!("Pair {} set to Frozen (foundation: {})", pair.id(), pair.foundation);
            }
        }

        // Build foundation groups
        for (foundation, pairs) in temp_foundation_groups {
            let active_count = pairs.iter()
                .filter(|p| {
                    let state = p.blocking_read().state;
                    matches!(state, CandidatePairState::Waiting | CandidatePairState::InProgress)
                })
                .count();

            self.foundation_groups.insert(
                foundation.clone(),
                FoundationGroup {
                    pairs,
                    active_count,
                    has_succeeded: false,
                }
            );
        }

        // Store sorted pairs
        self.pairs = pairs;

        Ok(())
    }

    /// Add candidate pair maintaining sorted order
    pub async fn add_pair(&mut self, pair: Arc<RwLock<CandidatePair>>) {
        let pair_data = pair.read().await;
        let priority = pair_data.priority;
        let foundation = pair_data.foundation.clone();
        let pair_id = pair_data.id();
        drop(pair_data);

        debug!("Adding pair {} with priority {}", pair_id, priority);

        // Find insertion position (binary search)
        let pos = match self.pairs.binary_search_by(|p| {
            priority.cmp(&p.blocking_read().priority)
        }) {
            Ok(pos) => pos,
            Err(pos) => pos,
        };

        // Insert at correct position
        self.pairs.insert(pos, pair.clone());

        // Update foundation group
        match self.foundation_groups.get_mut(&foundation) {
            Some(group) => {
                group.pairs.push(pair);
            }
            None => {
                self.foundation_groups.insert(
                    foundation,
                    FoundationGroup {
                        pairs: vec![pair],
                        active_count: 0,
                        has_succeeded: false,
                    }
                );
            }
        }

        self.stats.total_pairs += 1;
    }

    /// Get next pair to check (highest priority waiting pair)
    pub async fn get_next_pair(&self) -> Option<Arc<RwLock<CandidatePair>>> {
        // Check triggered queue first (RFC 8445 Section 7.3.1.4)
        if let Some(triggered) = self.triggered_queue.front() {
            return Some(triggered.pair.clone());
        }

        // Find highest priority waiting pair
        for pair_ref in &self.pairs {
            let pair = pair_ref.read().await;
            if pair.state == CandidatePairState::Waiting {
                trace!("Next pair to check: {} (priority: {})", pair.id(), pair.priority);
                return Some(pair_ref.clone());
            }
        }

        None
    }

    /// Update pair state with all side effects
    pub async fn update_pair_state(
        &mut self,
        pair_id: String,
        new_state: CandidatePairState,
    ) -> NatResult<()> {
        debug!("Updating pair {} state to {:?}", pair_id, new_state);

        // Find the pair
        let pair_ref = self.pairs.iter()
            .find(|p| p.blocking_read().id() == pair_id)
            .ok_or_else(|| NatError::Platform(format!("Pair {} not found", pair_id)))?
            .clone();

        let mut pair = pair_ref.write().await;
        let old_state = pair.state;
        let foundation = pair.foundation.clone();

        // Update state
        pair.state = new_state;
        drop(pair);

        // Handle state transition side effects
        match (old_state, new_state) {
            (_, CandidatePairState::InProgress) => {
                self.running_pairs.insert(pair_id.clone(), pair_ref.clone());
                self.stats.checks_performed += 1;

                // Update foundation active count
                if let Some(group) = self.foundation_groups.get_mut(&foundation) {
                    if old_state != CandidatePairState::InProgress {
                        group.active_count += 1;
                    }
                }
            }

            (CandidatePairState::InProgress, CandidatePairState::Succeeded) => {
                self.running_pairs.remove(&pair_id);
                self.stats.successful_checks += 1;

                // Add to valid list maintaining sort order
                self.insert_valid_pair(pair_ref.clone()).await;

                // Update foundation group
                if let Some(group) = self.foundation_groups.get_mut(&foundation) {
                    group.active_count = group.active_count.saturating_sub(1);
                    group.has_succeeded = true;
                }

                // Unfreeze pairs with same foundation (RFC 8445 Section 7.2.5.3.3)
                self.unfreeze_foundation(&foundation).await;
            }

            (CandidatePairState::InProgress, CandidatePairState::Failed) => {
                self.running_pairs.remove(&pair_id);
                self.stats.failed_checks += 1;

                // Update foundation active count
                if let Some(group) = self.foundation_groups.get_mut(&foundation) {
                    group.active_count = group.active_count.saturating_sub(1);
                }
            }

            _ => {}
        }

        // Update check list state
        self.update_list_state().await;

        Ok(())
    }

    /// Insert pair into valid list maintaining sort order
    async fn insert_valid_pair(&mut self, pair: Arc<RwLock<CandidatePair>>) {
        let priority = pair.read().await.priority;

        // Find insertion position
        let pos = match self.valid_pairs.binary_search_by(|p| {
            priority.cmp(&p.blocking_read().priority)
        }) {
            Ok(pos) => pos,
            Err(pos) => pos,
        };

        self.valid_pairs.insert(pos, pair);
    }

    /// Unfreeze pairs with same foundation
    async fn unfreeze_foundation(&mut self, foundation: &str) {
        if let Some(group) = self.foundation_groups.get(foundation) {
            for pair_ref in &group.pairs {
                let mut pair = pair_ref.write().await;
                if pair.state == CandidatePairState::Frozen {
                    pair.state = CandidatePairState::Waiting;
                    debug!("Unfroze pair {} (foundation: {})", pair.id(), foundation);
                }
            }
        }
    }

    /// Update overall check list state
    async fn update_list_state(&mut self) {
        // Count pair states
        let mut waiting = 0;
        let mut in_progress = 0;
        let mut succeeded = 0;
        let mut failed = 0;

        for pair_ref in &self.pairs {
            match pair_ref.read().await.state {
                CandidatePairState::Waiting | CandidatePairState::Frozen => waiting += 1,
                CandidatePairState::InProgress => in_progress += 1,
                CandidatePairState::Succeeded => succeeded += 1,
                CandidatePairState::Failed => failed += 1,
            }
        }

        trace!(
            "Check list state: {} waiting, {} in progress, {} succeeded, {} failed",
            waiting, in_progress, succeeded, failed
        );

        // Determine new state
        let new_state = if in_progress > 0 || waiting > 0 {
            // Still have work to do
            CheckListState::Running
        } else if succeeded > 0 {
            // All done, some succeeded
            CheckListState::Completed
        } else {
            // All done, none succeeded
            CheckListState::Failed
        };

        if new_state != self.state {
            info!(
                "Check list {} state changed from {:?} to {:?}",
                self.stream_id, self.state, new_state
            );
            self.state = new_state;
        }
    }

    /// Add triggered check (RFC 8445 Section 7.3.1.4)
    pub async fn add_triggered_check(
        &mut self,
        pair: Arc<RwLock<CandidatePair>>,
        use_candidate: bool,
    ) {
        let pair_id = pair.read().await.id();
        debug!("Adding triggered check for pair {} (use_candidate: {})", pair_id, use_candidate);

        // Check if already in queue
        let already_queued = self.triggered_queue.iter()
            .any(|tc| Arc::ptr_eq(&tc.pair, &pair));

        if !already_queued {
            self.triggered_queue.push_back(TriggeredCheck {
                pair,
                use_candidate,
                triggered_at: Instant::now(),
            });
        }
    }

    /// Get and remove next triggered check
    pub fn pop_triggered_check(&mut self) -> Option<TriggeredCheck> {
        self.triggered_queue.pop_front()
    }

    /// Get valid pairs for a component
    pub async fn get_valid_pairs(&self, component_id: u32) -> Vec<Arc<RwLock<CandidatePair>>> {
        let mut component_pairs = Vec::new();

        for pair_ref in &self.valid_pairs {
            if pair_ref.read().await.local.component_id == component_id {
                component_pairs.push(pair_ref.clone());
            }
        }

        component_pairs
    }

    /// Get best valid pair for a component
    pub async fn get_best_valid_pair(
        &self,
        component_id: u32,
    ) -> Option<Arc<RwLock<CandidatePair>>> {
        // Valid pairs are sorted, so first matching component is best
        for pair_ref in &self.valid_pairs {
            if pair_ref.read().await.local.component_id == component_id {
                return Some(pair_ref.clone());
            }
        }
        None
    }

    /// Handle nomination of a pair
    pub async fn nominate_pair(&mut self, pair_id: &str) -> NatResult<()> {
        let pair_ref = self.valid_pairs.iter()
            .find(|p| p.blocking_read().id() == pair_id)
            .ok_or_else(|| NatError::Platform(format!("Pair {} not in valid list", pair_id)))?
            .clone();

        let mut pair = pair_ref.write().await;
        if !pair.nominated {
            pair.nominated = true;
            self.stats.nominated_pairs += 1;
            info!("Nominated pair: {}", pair.id());
        }

        Ok(())
    }

    /// Check if specific component has nominated pair
    pub async fn has_nominated_pair(&self, component_id: u32) -> bool {
        for pair_ref in &self.valid_pairs {
            let pair = pair_ref.read().await;
            if pair.local.component_id == component_id && pair.nominated {
                return true;
            }
        }
        false
    }

    /// Get all nominated pairs
    pub async fn get_nominated_pairs(&self) -> Vec<Arc<RwLock<CandidatePair>>> {
        let mut nominated = Vec::new();

        for pair_ref in &self.valid_pairs {
            if pair_ref.read().await.nominated {
                nominated.push(pair_ref.clone());
            }
        }

        nominated
    }

    /// Get statistics
    pub fn get_stats(&self) -> String {
        format!(
            "CheckList[{}] - Total: {}, Pruned: {}, Checks: {} (Success: {}, Failed: {}), Nominated: {}, State: {:?}",
            self.stream_id,
            self.stats.total_pairs,
            self.stats.pruned_pairs,
            self.stats.checks_performed,
            self.stats.successful_checks,
            self.stats.failed_checks,
            self.stats.nominated_pairs,
            self.state
        )
    }

    /// Get number of running checks
    pub fn running_count(&self) -> usize {
        self.running_pairs.len()
    }

    /// Check if can start more checks (respects pacing)
    pub fn can_start_check(&self) -> bool {
        // RFC 8445: Limit concurrent checks
        const MAX_CONCURRENT_CHECKS: usize = 5;
        self.running_pairs.len() < MAX_CONCURRENT_CHECKS
    }

    /// Get all pairs for debugging
    pub fn get_all_pairs(&self) -> &Vec<Arc<RwLock<CandidatePair>>> {
        &self.pairs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::ice::{Candidate, TransportProtocol};

    async fn create_test_candidates() -> (Vec<Candidate>, Vec<Candidate>) {
        let local = vec![
            Candidate::new_host(
                "192.168.1.100:50000".parse().unwrap(),
                1,
                TransportProtocol::Udp,
                1,
            ),
            Candidate::new_host(
                "192.168.1.100:50001".parse().unwrap(),
                2,
                TransportProtocol::Udp,
                1,
            ),
        ];

        let remote = vec![
            Candidate::new_host(
                "192.168.1.200:60000".parse().unwrap(),
                1,
                TransportProtocol::Udp,
                1,
            ),
            Candidate::new_host(
                "192.168.1.200:60001".parse().unwrap(),
                2,
                TransportProtocol::Udp,
                1,
            ),
        ];

        (local, remote)
    }

    #[tokio::test]
    async fn test_check_list_formation() {
        let mut check_list = CheckList::new(1);
        let (local, remote) = create_test_candidates().await;

        check_list.form_check_list(local, remote, true).await.unwrap();

        // Should create 2 pairs (one per component)
        assert_eq!(check_list.pairs.len(), 2);

        // Verify pairs are sorted by priority
        let priorities: Vec<u64> = stream::iter(&check_list.pairs)
            .then(|p| async { p.read().await.priority })
            .collect().await;

        for i in 1..priorities.len() {
            assert!(priorities[i-1] >= priorities[i], "Pairs not sorted");
        }
    }

    #[tokio::test]
    async fn test_triggered_checks() {
        let mut check_list = CheckList::new(1);
        let (local, remote) = create_test_candidates().await;

        check_list.form_check_list(local, remote, true).await.unwrap();

        // Add triggered check
        let pair = check_list.pairs[0].clone();
        check_list.add_triggered_check(pair.clone(), true).await;

        // Should be in queue
        assert_eq!(check_list.triggered_queue.len(), 1);

        // Get next pair should return triggered check
        let next = check_list.get_next_pair().await.unwrap();
        assert!(Arc::ptr_eq(&next, &pair));

        // Pop triggered check
        let triggered = check_list.pop_triggered_check().unwrap();
        assert!(triggered.use_candidate);
    }

    #[tokio::test]
    async fn test_state_transitions() {
        let mut check_list = CheckList::new(1);
        let (local, remote) = create_test_candidates().await;

        check_list.form_check_list(local, remote, true).await.unwrap();

        // Initially Running
        assert_eq!(check_list.state, CheckListState::Running);

        // Update all pairs to failed
        for pair in check_list.pairs.clone() {
            let pair_id = pair.read().await.id();
            check_list.update_pair_state(pair_id, CandidatePairState::Failed).await.unwrap();
        }

        // Should be Failed
        assert_eq!(check_list.state, CheckListState::Failed);
    }

    #[tokio::test]
    async fn test_nomination() {
        let mut check_list = CheckList::new(1);
        let (local, remote) = create_test_candidates().await;

        check_list.form_check_list(local, remote, true).await.unwrap();

        // Make first pair valid
        let pair_id = check_list.pairs[0].read().await.id();
        check_list.update_pair_state(
            pair_id.clone(),
            CandidatePairState::InProgress
        ).await.unwrap();

        check_list.update_pair_state(
            pair_id.clone(),
            CandidatePairState::Succeeded
        ).await.unwrap();

        // Nominate the pair
        check_list.nominate_pair(&pair_id).await.unwrap();

        // Check nomination
        assert!(check_list.has_nominated_pair(1).await);
        assert_eq!(check_list.get_nominated_pairs().await.len(), 1);
    }
}