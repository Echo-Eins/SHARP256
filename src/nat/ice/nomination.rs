// src/nat/ice/nomination.rs
//! ICE nomination procedures (RFC 8445 Section 8)

use std::sync::Arc;
use tokio::sync::RwLock;
use super::{CandidatePair, CandidatePairState};

/// Nomination strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NominationMode {
    /// Regular nomination (RFC 8445 Section 8.1.1)
    Regular,

    /// Aggressive nomination (RFC 8445 Section 8.1.2)
    Aggressive,
}

/// Nomination controller
pub struct Nominator {
    /// Nomination mode
    mode: NominationMode,

    /// Nomination timer in ms
    nomination_timer: u64,

    /// Nominations per stream/component
    nominations: Arc<RwLock<std::collections::HashMap<(u32, u32), Arc<RwLock<CandidatePair>>>>>,
}

impl Nominator {
    /// Create new nominator
    pub fn new(mode: NominationMode) -> Self {
        Self {
            mode,
            nomination_timer: match mode {
                NominationMode::Regular => 1000, // 1 second
                NominationMode::Aggressive => 0,  // Immediate
            },
            nominations: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Select pair for nomination
    pub async fn select_pair(
        &self,
        stream_id: u32,
        component_id: u32,
        valid_pairs: &[Arc<RwLock<CandidatePair>>],
    ) -> Option<Arc<RwLock<CandidatePair>>> {
        if valid_pairs.is_empty() {
            return None;
        }

        // Sort by priority and RTT
        let mut sorted_pairs: Vec<_> = valid_pairs.iter()
            .filter(|p| {
                let pair = p.blocking_read();
                pair.valid && pair.state == CandidatePairState::Succeeded
            })
            .collect();

        sorted_pairs.sort_by(|a, b| {
            let a_pair = a.blocking_read();
            let b_pair = b.blocking_read();

            // First by priority (higher is better)
            match b_pair.priority.cmp(&a_pair.priority) {
                std::cmp::Ordering::Equal => {
                    // Then by RTT (lower is better)
                    match (a_pair.rtt, b_pair.rtt) {
                        (Some(a_rtt), Some(b_rtt)) => a_rtt.cmp(&b_rtt),
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (None, None) => std::cmp::Ordering::Equal,
                    }
                }
                other => other,
            }
        });

        // Select best pair
        sorted_pairs.first().map(|&&p| p.clone())
    }

    /// Nominate pair
    pub async fn nominate(
        &self,
        stream_id: u32,
        component_id: u32,
        pair: Arc<RwLock<CandidatePair>>,
    ) {
        // Store nomination
        self.nominations.write().await.insert((stream_id, component_id), pair.clone());

        // Mark pair as nominated
        pair.write().await.nominated = true;

        match self.mode {
            NominationMode::Aggressive => {
                // Set use-candidate immediately
                pair.write().await.use_candidate = true;
            }
            NominationMode::Regular => {
                // Wait before setting use-candidate
                let pair = pair.clone();
                let timer = self.nomination_timer;
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(timer)).await;
                    pair.write().await.use_candidate = true;
                });
            }
        }
    }

    /// Get nominated pair
    pub async fn get_nominated_pair(
        &self,
        stream_id: u32,
        component_id: u32,
    ) -> Option<Arc<RwLock<CandidatePair>>> {
        self.nominations.read().await.get(&(stream_id, component_id)).cloned()
    }

    /// Check if all components have nominations
    pub async fn all_nominated(&self, stream_id: u32, component_count: u32) -> bool {
        let nominations = self.nominations.read().await;

        for component_id in 1..=component_count {
            if !nominations.contains_key(&(stream_id, component_id)) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::ice::{Candidate, CandidateType, TransportProtocol};

    #[tokio::test]
    async fn test_nomination_selection() {
        let nominator = Nominator::new(NominationMode::Regular);

        // Create test pairs
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

        let mut pair1 = CandidatePair::new(local.clone(), remote.clone(), true);
        pair1.state = CandidatePairState::Succeeded;
        pair1.valid = true;
        pair1.rtt = Some(std::time::Duration::from_millis(50));

        let mut pair2 = CandidatePair::new(local.clone(), remote.clone(), true);
        pair2.state = CandidatePairState::Succeeded;
        pair2.valid = true;
        pair2.rtt = Some(std::time::Duration::from_millis(100));
        pair2.priority = pair1.priority + 100; // Higher priority but worse RTT

        let pairs = vec![
            Arc::new(RwLock::new(pair1)),
            Arc::new(RwLock::new(pair2)),
        ];

        // Should select pair2 due to higher priority
        let selected = nominator.select_pair(1, 1, &pairs).await.unwrap();
        assert_eq!(selected.read().await.priority, pair2.priority);
    }
}