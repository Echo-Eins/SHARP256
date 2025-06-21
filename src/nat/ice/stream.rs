// src/nat/ice/stream.rs
//! ICE stream representation

use std::sync::Arc;
use tokio::sync::RwLock;
use super::Candidate;

/// ICE stream component
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Component {
    pub id: u32,
}

/// ICE stream
pub struct IceStream {
    /// Stream ID
    pub id: u32,

    /// Number of components
    pub component_count: u32,

    /// Local candidates
    local_candidates: Arc<RwLock<Vec<Candidate>>>,

    /// Remote candidates
    remote_candidates: Arc<RwLock<Vec<Candidate>>>,

    /// Gathering complete flag
    pub gathering_complete: bool,
}

impl IceStream {
    /// Create new stream
    pub fn new(id: u32, component_count: u32) -> Self {
        Self {
            id,
            component_count,
            local_candidates: Arc::new(RwLock::new(Vec::new())),
            remote_candidates: Arc::new(RwLock::new(Vec::new())),
            gathering_complete: false,
        }
    }

    /// Add local candidate
    pub fn add_local_candidate(&mut self, candidate: Candidate) {
        self.local_candidates.blocking_write().push(candidate);
    }

    /// Add remote candidate
    pub fn add_remote_candidate(&mut self, candidate: Candidate) {
        self.remote_candidates.blocking_write().push(candidate);
    }

    /// Get local candidates
    pub async fn get_local_candidates(&self) -> Vec<Candidate> {
        self.local_candidates.read().await.clone()
    }

    /// Get remote candidates
    pub async fn get_remote_candidates(&self) -> Vec<Candidate> {
        self.remote_candidates.read().await.clone()
    }

    /// Get candidates for specific component
    pub async fn get_component_candidates(&self, component_id: u32) -> (Vec<Candidate>, Vec<Candidate>) {
        let local = self.local_candidates.read().await
            .iter()
            .filter(|c| c.component_id == component_id)
            .cloned()
            .collect();

        let remote = self.remote_candidates.read().await
            .iter()
            .filter(|c| c.component_id == component_id)
            .cloned()
            .collect();
        // src/nat/ice/stream.rs (continued)
        (local, remote)
    }

    /// Mark gathering as complete
    pub fn set_gathering_complete(&mut self) {
        self.gathering_complete = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::ice::{CandidateType, TransportProtocol};

    #[tokio::test]
    async fn test_stream_candidate_management() {
        let mut stream = IceStream::new(1, 2);

        // Add local candidate
        let local = Candidate::new_host(
            "192.168.1.100:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );
        stream.add_local_candidate(local.clone());

        // Add remote candidate
        let remote = Candidate::new_host(
            "192.168.1.200:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );
        stream.add_remote_candidate(remote.clone());

        // Check retrieval
        let locals = stream.get_local_candidates().await;
        assert_eq!(locals.len(), 1);
        assert_eq!(locals[0].addr, local.addr);

        let remotes = stream.get_remote_candidates().await;
        assert_eq!(remotes.len(), 1);
        assert_eq!(remotes[0].addr, remote.addr);
    }
}