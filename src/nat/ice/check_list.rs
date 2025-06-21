// src/nat/ice/check_list.rs
//! ICE check list management

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use super::{CandidatePair, CandidatePairState};

/// Check list for managing candidate pairs
pub struct CheckList {
    /// Stream ID
    pub stream_id: u32,

    /// All candidate pairs
    pairs: Vec<Arc<RwLock<CandidatePair>>>,

    /// State of the check list
    pub state: CheckListState,

    /// Valid pairs (connectivity check succeeded)
    valid_pairs: Vec<Arc<RwLock<CandidatePair>>>,

    /// Running pairs (currently being checked)
    running_pairs: Vec<Arc<RwLock<CandidatePair>>>,
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
            running_pairs: Vec::new(),
        }
    }

    /// Add candidate pair
    pub fn add_pair(&mut self, pair: Arc<RwLock<CandidatePair>>) {
        self.pairs.push(pair);
    }

    /// Get next pair to check
    pub async fn get_next_pair(&self) -> Option<Arc<RwLock<CandidatePair>>> {
        // Find highest priority waiting pair
        let mut best_pair = None;
        let mut best_priority = 0u64;

        for pair_ref in &self.pairs {
            let pair = pair_ref.read().await;
            if pair.state == CandidatePairState::Waiting && pair.priority > best_priority {
                best_priority = pair.priority;
                best_pair = Some(pair_ref.clone());
            }
        }

        best_pair
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
                pair.state = new_state;

                // Update valid/running lists
                match new_state {
                    CandidatePairState::Succeeded => {
                        if !self.valid_pairs.iter().any(|p| p.blocking_read().id() == pair_id) {
                            self.valid_pairs.push(pair_ref.clone());
                        }
                        self.running_pairs.retain(|p| p.blocking_read().id() != pair_id);
                    }
                    CandidatePairState::InProgress => {
                        if !self.running_pairs.iter().any(|p| p.blocking_read().id() == pair_id) {
                            self.running_pairs.push(pair_ref.clone());
                        }
                    }
                    CandidatePairState::Failed => {
                        self.running_pairs.retain(|p| p.blocking_read().id() != pair_id);
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
        let has_nominated = self.valid_pairs.iter().any(|p| p.blocking_read().nominated);

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
        self.valid_pairs.iter()
            .filter(|p| p.blocking_read().local.component_id == component_id)
            .cloned()
            .collect()
    }

    /// Prune pairs based on RFC 8445 Section 6.1.2.4
    pub async fn prune_pairs(&mut self) {
        let mut pairs_to_remove = Vec::new();

        for i in 0..self.pairs.len() {
            for j in (i + 1)..self.pairs.len() {
                let pair_i = self.pairs[i].read().await;
                let pair_j = self.pairs[j].read().await;

                if pair_i.should_prune(&pair_j) {
                    pairs_to_remove.push(i);
                } else if pair_j.should_prune(&pair_i) {
                    pairs_to_remove.push(j);
                }
            }
        }

        // Remove duplicates and sort in reverse order
        pairs_to_remove.sort_unstable();
        pairs_to_remove.dedup();
        pairs_to_remove.reverse();

        // Remove pruned pairs
        for idx in pairs_to_remove {
            self.pairs.remove(idx);
        }
    }

    /// Compute foundation groups for frozen pairs
    pub async fn compute_foundations(&self) -> HashMap<String, Vec<Arc<RwLock<CandidatePair>>>> {
        let mut foundations = HashMap::new();

        for pair in &self.pairs {
            let foundation = pair.read().await.foundation.clone();
            foundations.entry(foundation)
                .or_insert_with(Vec::new)
                .push(pair.clone());
        }

        foundations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::ice::{Candidate, TransportProtocol};

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
        assert_eq!(check_list.running_pairs.len(), 1);

        // Update to succeeded
        check_list.update_pair_state(pair_id, CandidatePairState::Succeeded).await;

        // Should be in valid pairs
        assert_eq!(check_list.valid_pairs.len(), 1);
        assert_eq!(check_list.running_pairs.len(), 0);
    }
}