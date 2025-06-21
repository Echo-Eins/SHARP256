// src/nat/ice/trickle.rs
//! Trickle ICE implementation (RFC 8838)

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{timeout, Duration};
use super::Candidate;

/// Trickle ICE handler
pub struct TrickleIce {
    /// Event sender
    event_tx: mpsc::UnboundedSender<TrickleEvent>,

    /// End-of-candidates sent flag
    eoc_sent: Arc<RwLock<bool>>,

    /// End-of-candidates received flag
    eoc_received: Arc<RwLock<bool>>,
}

/// Trickle ICE events
#[derive(Debug)]
pub enum TrickleEvent {
    /// Local candidate ready to be sent
    LocalCandidateReady(Candidate),

    /// Remote candidate received
    RemoteCandidateReceived(Candidate),

    /// End of candidates marker
    EndOfCandidates,
}

impl TrickleIce {
    /// Create new trickle ICE handler
    pub fn new(event_tx: mpsc::UnboundedSender<TrickleEvent>) -> Self {
        Self {
            event_tx,
            eoc_sent: Arc::new(RwLock::new(false)),
            eoc_received: Arc::new(RwLock::new(false)),
        }
    }

    /// Send local candidate
    pub async fn send_candidate(&self, candidate: Candidate) -> Result<(), mpsc::error::SendError<TrickleEvent>> {
        // Don't send if we already sent end-of-candidates
        if *self.eoc_sent.read().await {
            return Ok(());
        }

        self.event_tx.send(TrickleEvent::LocalCandidateReady(candidate))
    }

    /// Signal end of local candidates
    pub async fn send_end_of_candidates(&self) -> Result<(), mpsc::error::SendError<TrickleEvent>> {
        let mut eoc_sent = self.eoc_sent.write().await;
        if !*eoc_sent {
            *eoc_sent = true;
            self.event_tx.send(TrickleEvent::EndOfCandidates)
        } else {
            Ok(())
        }
    }

    /// Receive remote candidate
    pub async fn receive_candidate(&self, candidate: Candidate) -> Result<(), mpsc::error::SendError<TrickleEvent>> {
        // Don't process if we already received end-of-candidates
        if *self.eoc_received.read().await {
            return Ok(());
        }

        self.event_tx.send(TrickleEvent::RemoteCandidateReceived(candidate))
    }

    /// Receive end of remote candidates
    pub async fn receive_end_of_candidates(&self) -> Result<(), mpsc::error::SendError<TrickleEvent>> {
        let mut eoc_received = self.eoc_received.write().await;
        if !*eoc_received {
            *eoc_received = true;
            self.event_tx.send(TrickleEvent::EndOfCandidates)
        } else {
            Ok(())
        }
    }

    /// Check if both sides have signaled end of candidates
    pub async fn is_complete(&self) -> bool {
        *self.eoc_sent.read().await && *self.eoc_received.read().await
    }

    /// Wait for completion with timeout
    pub async fn wait_for_completion(&self, timeout_duration: Duration) -> bool {
        let start = tokio::time::Instant::now();

        while !self.is_complete().await {
            if start.elapsed() > timeout_duration {
                return false;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        true
    }
}

/// Trickle ICE candidate format for signaling
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrickleCandidate {
    /// SDP mid value
    pub sdp_mid: String,

    /// SDP m-line index
    pub sdp_mline_index: u32,

    /// Candidate SDP attribute
    pub candidate: String,
}

impl TrickleCandidate {
    /// Create from ICE candidate
    pub fn from_candidate(candidate: &Candidate, sdp_mid: String, sdp_mline_index: u32) -> Self {
        Self {
            sdp_mid,
            sdp_mline_index,
            candidate: candidate.to_sdp_attribute(),
        }
    }

    /// Parse to ICE candidate
    pub fn to_candidate(&self) -> Result<Candidate, crate::nat::error::NatError> {
        Candidate::from_sdp_attribute(&self.candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::ice::{CandidateType, TransportProtocol};

    #[tokio::test]
    async fn test_trickle_ice_flow() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let trickle = TrickleIce::new(tx);

        // Send candidate
        let candidate = Candidate::new_host(
            "192.168.1.100:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        trickle.send_candidate(candidate.clone()).await.unwrap();

        // Should receive event
        match rx.recv().await {
            Some(TrickleEvent::LocalCandidateReady(c)) => {
                assert_eq!(c.addr, candidate.addr);
            }
            _ => panic!("Expected local candidate event"),
        }

        // Send end of candidates
        trickle.send_end_of_candidates().await.unwrap();

        match rx.recv().await {
            Some(TrickleEvent::EndOfCandidates) => {}
            _ => panic!("Expected end of candidates event"),
        }

        // Should not send more after EOC
        assert!(*trickle.eoc_sent.read().await);

        // Try sending another candidate - should be ignored
        trickle.send_candidate(candidate).await.unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_trickle_candidate_serialization() {
        let candidate = Candidate::new_host(
            "192.168.1.100:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        let trickle_candidate = TrickleCandidate::from_candidate(
            &candidate,
            "0".to_string(),
            0,
        );

        // Serialize to JSON
        let json = serde_json::to_string(&trickle_candidate).unwrap();

        // Deserialize back
        let deserialized: TrickleCandidate = serde_json::from_str(&json).unwrap();

        // Parse back to candidate
        let parsed = deserialized.to_candidate().unwrap();
        assert_eq!(parsed.addr, candidate.addr);
        assert_eq!(parsed.typ, candidate.typ);
    }
}