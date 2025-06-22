// src/nat/ice/check_list.rs
//! ICE check list management

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use super::{CandidatePair};
use super::candidate::CandidatePairState;

/// Check list for managing candidate pairs
pub struct CheckList {
    /// Stream ID
    pub stream_id: u32,

    /// All candidate pairs sorted by priority (highest first)
    pairs: Vec<Arc<RwLock<CandidatePair>>>,

    /// State of the check list
    pub state: CheckListState,

    /// Valid pairs (connectivity check succeeded)
    valid_pairs: Vec<Arc<RwLock<CandidatePair>>>,

    /// Running pairs (currently being checked)
    running_pairs: HashMap<String, Arc<RwLock<CandidatePair>>>,

    /// Foundation groups for managing frozen candidates
    foundation_groups: HashMap<String, Vec<Arc<RwLock<CandidatePair>>>>,
}

/// Check list state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckListState {
    /// Actively running checks
    Running,

    /// Completed (has nominated pairs)
    Completed,

    /// Failed (no valid pairs)
    Failed,
}

impl CheckList {
    /// Create new check list
    pub fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            pairs: Vec::new(),
            state: CheckListState::Running,
            valid_pairs: Vec::new(),
            running_pairs: HashMap::new(),
            foundation_groups: HashMap::new(),
        }
    }

    /// Add candidate pair and maintain sorted order
    pub fn add_pair(&mut self, pair: Arc<RwLock<CandidatePair>>) {
        // Add to foundation groups
        let foundation = pair.blocking_read().foundation.clone();
        self.foundation_groups
            .entry(foundation)
            .or_insert_with(Vec::new)
            .push(pair.clone());

        // Insert in sorted position (highest priority first)
        let pair_priority = pair.blocking_read().priority;

        match self.pairs.binary_search_by(|p| {
            // Reverse comparison for descending order
            pair_priority.cmp(&p.blocking_read().priority)
        }) {
            Ok(pos) | Err(pos) => self.pairs.insert(pos, pair),
        }
    }

    /// Sort pairs by priority (should maintain sorted order but can be called to re-sort)
    pub async fn sort_pairs(&mut self) {
        // Collect priorities to avoid holding locks during sort
        let mut pairs_with_priority: Vec<(Arc<RwLock<CandidatePair>>, u64)> =
            Vec::with_capacity(self.pairs.len());

        for pair in &self.pairs {
            let priority = pair.read().await.priority;
            pairs_with_priority.push((pair.clone(), priority));
        }

        // Sort by priority (highest first)
        pairs_with_priority.sort_by(|a, b| b.1.cmp(&a.1));

        // Update pairs vector
        self.pairs = pairs_with_priority.into_iter()
            .map(|(pair, _)| pair)
            .collect();
    }

    /// Get next pair to check (highest priority waiting pair)
    pub async fn get_next_pair(&self) -> Option<Arc<RwLock<CandidatePair>>> {
        // Pairs are sorted by priority, so iterate in order
        for pair_ref in &self.pairs {
            let pair = pair_ref.read().await;
            if pair.state == CandidatePairState::Waiting {
                return Some(pair_ref.clone());
            }
        }
        None
    }

    /// Get pairs by foundation
    pub fn get_foundation_pairs(&self, foundation: &str) -> Vec<Arc<RwLock<CandidatePair>>> {
        self.foundation_groups
            .get(foundation)
            .cloned()
            .unwrap_or_default()
    }

    /// Update pair state
    pub async fn update_pair_state(
        &mut self,
        pair_id: String,
        new_state: CandidatePairState,
    ) {
        for pair_ref in &self.pairs {
            let mut pair = pair_ref.write().await;
            if pair.id() == pair_id {
                let old_state = pair.state;
                pair.state = new_state;

                // Update tracking lists based on state change
                match (old_state, new_state) {
                    (_, CandidatePairState::Succeeded) => {
                        // Add to valid pairs if not already there
                        if !self.valid_pairs.iter().any(|p| {
                            p.blocking_read().id() == pair_id
                        }) {
                            self.valid_pairs.push(pair_ref.clone());
                        }
                        // Remove from running
                        self.running_pairs.remove(&pair_id);
                    }
                    (_, CandidatePairState::InProgress) => {
                        // Add to running pairs
                        self.running_pairs.insert(pair_id.clone(), pair_ref.clone());
                    }
                    (CandidatePairState::InProgress, CandidatePairState::Failed) |
                    (CandidatePairState::InProgress, CandidatePairState::Waiting) => {
                        // Remove from running
                        self.running_pairs.remove(&pair_id);
                    }
                    _ => {}
                }

                break;
            }
        }

        // Update check list state
        self.update_state().await;
    }

    /// Update check list state based on pairs
    async fn update_state(&mut self) {
        // Check if we have nominated pairs
        let has_nominated = self.valid_pairs.iter().any(|p| {
            p.blocking_read().nominated
        });

        if has_nominated {
            self.state = CheckListState::Completed;
            return;
        }

        // Check if all pairs are in terminal state
        let all_terminal = self.pairs.iter().all(|p| {
            let pair = p.blocking_read();
            matches!(
                pair.state,
                CandidatePairState::Succeeded | CandidatePairState::Failed
            )
        });

        if all_terminal {
            if self.valid_pairs.is_empty() {
                self.state = CheckListState::Failed;
            } else {
                self.state = CheckListState::Completed;
            }
        }
    }

    /// Get valid pairs for component
    pub async fn get_valid_pairs(&self, component_id: u32) -> Vec<Arc<RwLock<CandidatePair>>> {
        let mut component_pairs = Vec::new();

        for pair in &self.valid_pairs {
            if pair.read().await.local.component_id == component_id {
                component_pairs.push(pair.clone());
            }
        }

        // Sort by priority (highest first)
        component_pairs.sort_by(|a, b| {
            let a_priority = a.blocking_read().priority;
            let b_priority = b.blocking_read().priority;
            b_priority.cmp(&a_priority)
        });

        component_pairs
    }

    /// Prune pairs based on RFC 8445 Section 6.1.2.4
    pub async fn prune_pairs(&mut self) {
        let mut pairs_to_remove = HashSet::new();

        // Find redundant pairs
        for i in 0..self.pairs.len() {
            if pairs_to_remove.contains(&i) {
                continue;
            }

            for j in (i + 1)..self.pairs.len() {
                if pairs_to_remove.contains(&j) {
                    continue;
                }

                let pair_i = self.pairs[i].read().await;
                let pair_j = self.pairs[j].read().await;

                if pair_i.should_prune(&pair_j) {
                    pairs_to_remove.insert(i);
                    tracing::debug!("Pruning redundant pair: {}", pair_i.id());
                } else if pair_j.should_prune(&pair_i) {
                    pairs_to_remove.insert(j);
                    tracing::debug!("Pruning redundant pair: {}", pair_j.id());
                }
            }
        }

        // Remove pruned pairs (in reverse order to maintain indices)
        let mut indices: Vec<_> = pairs_to_remove.into_iter().collect();
        indices.sort_by(|a, b| b.cmp(a));

        for idx in indices {
            let removed = self.pairs.remove(idx);
            // Also remove from foundation groups
            let foundation = removed.blocking_read().foundation.clone();
            if let Some(group) = self.foundation_groups.get_mut(&foundation) {
                group.retain(|p| !Arc::ptr_eq(p, &removed));
            }
        }
    }

    /// Get number of running checks
    pub fn running_count(&self) -> usize {
        self.running_pairs.len()
    }

    /// Get all pairs (for debugging/testing)
    pub fn get_all_pairs(&self) -> &Vec<Arc<RwLock<CandidatePair>>> {
        &self.pairs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::ice::{Candidate, TransportProtocol};

    #[tokio::test]
    async fn test_check_list_sorting() {
        let mut check_list = CheckList::new(1);

        // Create test pairs with different priorities
        let local = Candidate::new_host(
            "192.168.1.100:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        let remote1 = Candidate::new_host(
            "192.168.1.200:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        let remote2 = Candidate::new_host(
            "192.168.1.201:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        let mut pair1 = CandidatePair::new(local.clone(), remote1, true);
        pair1.priority = 1000;
        pair1.state = CandidatePairState::Waiting;

        let mut pair2 = CandidatePair::new(local.clone(), remote2, true);
        pair2.priority = 2000;
        pair2.state = CandidatePairState::Waiting;

        // Add in wrong order
        check_list.add_pair(Arc::new(RwLock::new(pair1)));
        check_list.add_pair(Arc::new(RwLock::new(pair2)));

        // Verify pairs are sorted by priority (highest first)
        let pairs = check_list.get_all_pairs();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].read().await.priority, 2000);
        assert_eq!(pairs[1].read().await.priority, 1000);

        // Get next pair should return highest priority
        let next = check_list.get_next_pair().await.unwrap();
        assert_eq!(next.read().await.priority, 2000);
    }

    #[tokio::test]
    async fn test_check_list_management() {
        let mut check_list = CheckList::new(1);

        // Create test pair
        let local = Candidate::new_host(
            "192.168.1.100:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        let remote = Candidate::new_host(
            "192.168.1.200:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        let mut pair = CandidatePair::new(local, remote, true);
        pair.state = CandidatePairState::Waiting;

        let pair_ref = Arc::new(RwLock::new(pair));
        check_list.add_pair(pair_ref.clone());

        // Should find waiting pair
        let next = check_list.get_next_pair().await;
        assert!(next.is_some());

        // Update state
        let pair_id = pair_ref.read().await.id();
        check_list.update_pair_state(pair_id.clone(), CandidatePairState::InProgress).await;

        // Should be in running pairs
        assert_eq!(check_list.running_count(), 1);

        // Update to succeeded
        check_list.update_pair_state(pair_id, CandidatePairState::Succeeded).await;

        // Should be in valid pairs
        assert_eq!(check_list.valid_pairs.len(), 1);
        assert_eq!(check_list.running_count(), 0);
    }

    #[tokio::test]
    async fn test_foundation_groups() {
        let mut check_list = CheckList::new(1);

        let local = Candidate::new_host(
            "192.168.1.100:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        let remote1 = Candidate::new_host(
            "192.168.1.200:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        let remote2 = Candidate::new_host(
            "192.168.1.201:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        // Create pairs with same foundation
        let pair1 = CandidatePair::new(local.clone(), remote1.clone(), true);
        let pair2 = CandidatePair::new(local.clone(), remote2.clone(), true);

        let foundation = pair1.foundation.clone();

        check_list.add_pair(Arc::new(RwLock::new(pair1)));
        check_list.add_pair(Arc::new(RwLock::new(pair2)));

        // Check foundation grouping
        let foundation_pairs = check_list.get_foundation_pairs(&foundation);
        assert_eq!(foundation_pairs.len(), 2);
    }
}