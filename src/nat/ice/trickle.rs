// src/nat/ice/trickle.rs
//! Trickle ICE implementation (RFC 8838) with robust error handling

use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::{timeout, sleep};
use tracing::{info, warn, error, debug};
use super::Candidate;

/// Trickle ICE handler with graceful error handling
pub struct TrickleIce {
    /// Event sender
    event_tx: mpsc::UnboundedSender<TrickleEvent>,

    /// End-of-candidates sent flag per stream
    eoc_sent: Arc<RwLock<HashMap<u32, bool>>>,

    /// End-of-candidates received flag per stream
    eoc_received: Arc<RwLock<HashMap<u32, bool>>>,

    /// Pending candidates (buffered until remote is ready)
    pending_local: Arc<Mutex<Vec<TrickleCandidate>>>,
    pending_remote: Arc<Mutex<Vec<TrickleCandidate>>>,

    /// Active streams
    active_streams: Arc<RwLock<HashSet<u32>>>,

    /// Remote ready flag (can accept trickled candidates)
    remote_ready: Arc<RwLock<bool>>,

    /// Statistics
    stats: Arc<TrickleStats>,

    /// Configuration
    config: TrickleConfig,
}

/// Trickle ICE configuration
#[derive(Debug, Clone)]
pub struct TrickleConfig {
    /// Maximum time to wait for end-of-candidates
    pub eoc_timeout: Duration,

    /// Buffer candidates until remote signals ready
    pub buffer_candidates: bool,

    /// Maximum buffered candidates
    pub max_buffered: usize,

    /// Enable candidate deduplication
    pub deduplicate: bool,
}

impl Default for TrickleConfig {
    fn default() -> Self {
        Self {
            eoc_timeout: Duration::from_secs(30),
            buffer_candidates: true,
            max_buffered: 100,
            deduplicate: true,
        }
    }
}

/// Trickle ICE statistics
#[derive(Debug, Default)]
struct TrickleStats {
    candidates_sent: std::sync::atomic::AtomicUsize,
    candidates_received: std::sync::atomic::AtomicUsize,
    candidates_buffered: std::sync::atomic::AtomicUsize,
    candidates_dropped: std::sync::atomic::AtomicUsize,
    eoc_sent_count: std::sync::atomic::AtomicUsize,
    eoc_received_count: std::sync::atomic::AtomicUsize,
}

/// Trickle ICE events
#[derive(Debug, Clone)]
pub enum TrickleEvent {
    /// Local candidate ready to be sent
    LocalCandidateReady(Candidate),

    /// Remote candidate received
    RemoteCandidateReceived(Candidate),

    /// End of candidates marker for a stream
    EndOfCandidates { stream_id: u32 },

    /// Remote is ready to receive candidates
    RemoteReady,

    /// Error occurred
    Error(String),
}

/// Trickle ICE state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrickleState {
    /// Initial state
    New,

    /// Actively trickling candidates
    Trickling,

    /// All candidates sent/received
    Complete,

    /// Trickle ICE failed
    Failed,
}

impl TrickleIce {
    /// Create new trickle ICE handler
    pub fn new(event_tx: mpsc::UnboundedSender<TrickleEvent>) -> Self {
        Self::with_config(event_tx, TrickleConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(
        event_tx: mpsc::UnboundedSender<TrickleEvent>,
        config: TrickleConfig,
    ) -> Self {
        info!("Creating TrickleIce handler with config: {:?}", config);

        Self {
            event_tx,
            eoc_sent: Arc::new(RwLock::new(HashMap::new())),
            eoc_received: Arc::new(RwLock::new(HashMap::new())),
            pending_local: Arc::new(Mutex::new(Vec::new())),
            pending_remote: Arc::new(Mutex::new(Vec::new())),
            active_streams: Arc::new(RwLock::new(HashSet::new())),
            remote_ready: Arc::new(RwLock::new(false)),
            stats: Arc::new(TrickleStats::default()),
            config,
        }
    }

    /// Register a stream for trickle ICE
    pub async fn add_stream(&self, stream_id: u32) -> Result<(), TrickleError> {
        debug!("Adding stream {} to trickle ICE", stream_id);

        self.active_streams.write().await.insert(stream_id);
        self.eoc_sent.write().await.insert(stream_id, false);
        self.eoc_received.write().await.insert(stream_id, false);

        Ok(())
    }

    /// Signal that remote is ready to receive trickled candidates
    pub async fn set_remote_ready(&self) -> Result<(), TrickleError> {
        info!("Remote signaled ready for trickle ICE");
        *self.remote_ready.write().await = true;

        // Flush buffered candidates
        if self.config.buffer_candidates {
            self.flush_buffered_candidates().await?;
        }

        let _ = self.event_tx.send(TrickleEvent::RemoteReady);

        Ok(())
    }

    /// Send local candidate
    pub async fn send_candidate(&self, candidate: Candidate) -> Result<(), TrickleError> {
        let stream_id = self.find_stream_for_candidate(&candidate).await?;

        // Check if we already sent end-of-candidates for this stream
        let eoc_sent = self.eoc_sent.read().await.get(&stream_id).copied().unwrap_or(false);
        if eoc_sent {
            warn!("Attempted to send candidate after end-of-candidates for stream {}", stream_id);
            self.stats.candidates_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(TrickleError::InvalidState(
                "Cannot send candidates after end-of-candidates".to_string()
            ));
        }

        let remote_ready = *self.remote_ready.read().await;

        if self.config.buffer_candidates && !remote_ready {
            // Buffer the candidate
            let mut pending = self.pending_local.lock().await;

            if pending.len() >= self.config.max_buffered {
                warn!("Local candidate buffer full, dropping oldest");
                self.stats.candidates_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                pending.remove(0);
            }

            let trickle_candidate = TrickleCandidate::from_candidate(
                &candidate,
                stream_id.to_string(),
                stream_id,
            );

            pending.push(trickle_candidate);
            self.stats.candidates_buffered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            debug!("Buffered local candidate for stream {} (total: {})",
                stream_id, pending.len());
        } else {
            // Send immediately
            self.stats.candidates_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            if let Err(e) = self.event_tx.send(TrickleEvent::LocalCandidateReady(candidate)) {
                error!("Failed to send local candidate event: {}", e);
                return Err(TrickleError::ChannelClosed);
            }
        }

        Ok(())
    }

    /// Signal end of local candidates for a stream
    pub async fn send_end_of_candidates(&self, stream_id: u32) -> Result<(), TrickleError> {
        // Validate stream exists
        if !self.active_streams.read().await.contains(&stream_id) {
            warn!("Attempted to send EOC for unknown stream {}", stream_id);
            return Err(TrickleError::UnknownStream(stream_id));
        }

        let mut eoc_sent = self.eoc_sent.write().await;

        if let Some(sent) = eoc_sent.get(&stream_id) {
            if *sent {
                debug!("End-of-candidates already sent for stream {}", stream_id);
                return Ok(());
            }
        }

        info!("Sending end-of-candidates for stream {}", stream_id);
        eoc_sent.insert(stream_id, true);
        drop(eoc_sent);

        self.stats.eoc_sent_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if let Err(e) = self.event_tx.send(TrickleEvent::EndOfCandidates { stream_id }) {
            error!("Failed to send EOC event: {}", e);
            return Err(TrickleError::ChannelClosed);
        }

        // Check if all streams are complete
        self.check_completion().await;

        Ok(())
    }

    /// Receive remote candidate
    pub async fn receive_candidate(
        &self,
        candidate: Candidate,
        stream_id: u32,
    ) -> Result<(), TrickleError> {
        // Validate stream exists
        if !self.active_streams.read().await.contains(&stream_id) {
            warn!("Received candidate for unknown stream {}", stream_id);
            return Err(TrickleError::UnknownStream(stream_id));
        }

        // Check if we already received end-of-candidates for this stream
        let eoc_received = self.eoc_received.read().await
            .get(&stream_id).copied().unwrap_or(false);

        if eoc_received {
            warn!("Received candidate after end-of-candidates for stream {}", stream_id);
            self.stats.candidates_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(TrickleError::InvalidState(
                "Received candidate after end-of-candidates".to_string()
            ));
        }

        // Deduplicate if enabled
        if self.config.deduplicate {
            let pending = self.pending_remote.lock().await;
            let duplicate = pending.iter().any(|tc| {
                if let Ok(c) = tc.to_candidate() {
                    c.addr == candidate.addr && c.typ == candidate.typ
                } else {
                    false
                }
            });
            drop(pending);

            if duplicate {
                debug!("Dropping duplicate remote candidate: {}", candidate.addr);
                self.stats.candidates_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(());
            }
        }

        self.stats.candidates_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if let Err(e) = self.event_tx.send(TrickleEvent::RemoteCandidateReceived(candidate)) {
            error!("Failed to send remote candidate event: {}", e);
            return Err(TrickleError::ChannelClosed);
        }

        Ok(())
    }

    /// Receive end of remote candidates for a stream
    pub async fn receive_end_of_candidates(&self, stream_id: u32) -> Result<(), TrickleError> {
        // Validate stream exists
        if !self.active_streams.read().await.contains(&stream_id) {
            warn!("Received EOC for unknown stream {}", stream_id);
            return Err(TrickleError::UnknownStream(stream_id));
        }

        let mut eoc_received = self.eoc_received.write().await;

        if let Some(received) = eoc_received.get(&stream_id) {
            if *received {
                debug!("End-of-candidates already received for stream {}", stream_id);
                return Ok(());
            }
        }

        info!("Received end-of-candidates for stream {}", stream_id);
        eoc_received.insert(stream_id, true);
        drop(eoc_received);

        self.stats.eoc_received_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if let Err(e) = self.event_tx.send(TrickleEvent::EndOfCandidates { stream_id }) {
            error!("Failed to send remote EOC event: {}", e);
            return Err(TrickleError::ChannelClosed);
        }

        // Check if all streams are complete
        self.check_completion().await;

        Ok(())
    }

    /// Check if trickle ICE is complete for all streams
    pub async fn is_complete(&self) -> bool {
        let streams = self.active_streams.read().await;
        if streams.is_empty() {
            return false;
        }

        let eoc_sent = self.eoc_sent.read().await;
        let eoc_received = self.eoc_received.read().await;

        for stream_id in streams.iter() {
            let sent = eoc_sent.get(stream_id).copied().unwrap_or(false);
            let received = eoc_received.get(stream_id).copied().unwrap_or(false);

            if !sent || !received {
                return false;
            }
        }

        true
    }

    /// Wait for completion with timeout
    pub async fn wait_for_completion(&self) -> Result<(), TrickleError> {
        let start = Instant::now();
        let timeout_duration = self.config.eoc_timeout;

        while !self.is_complete().await {
            if start.elapsed() > timeout_duration {
                error!("Trickle ICE completion timeout after {:?}", timeout_duration);
                return Err(TrickleError::Timeout);
            }

            sleep(Duration::from_millis(100)).await;
        }

        info!("Trickle ICE complete for all streams");
        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> TrickleStatsSnapshot {
        TrickleStatsSnapshot {
            candidates_sent: self.stats.candidates_sent.load(std::sync::atomic::Ordering::Relaxed),
            candidates_received: self.stats.candidates_received.load(std::sync::atomic::Ordering::Relaxed),
            candidates_buffered: self.stats.candidates_buffered.load(std::sync::atomic::Ordering::Relaxed),
            candidates_dropped: self.stats.candidates_dropped.load(std::sync::atomic::Ordering::Relaxed),
            eoc_sent_count: self.stats.eoc_sent_count.load(std::sync::atomic::Ordering::Relaxed),
            eoc_received_count: self.stats.eoc_received_count.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Find which stream a candidate belongs to
    async fn find_stream_for_candidate(&self, candidate: &Candidate) -> Result<u32, TrickleError> {
        let streams = self.active_streams.read().await;

        // For now, use component_id as a hint, but in practice would need better mapping
        // In real implementation, would track which stream each component belongs to
        if streams.contains(&1) {
            Ok(1) // Default to stream 1
        } else if let Some(&stream_id) = streams.iter().next() {
            Ok(stream_id)
        } else {
            Err(TrickleError::NoActiveStreams)
        }
    }

    /// Flush buffered candidates
    async fn flush_buffered_candidates(&self) -> Result<(), TrickleError> {
        let mut pending = self.pending_local.lock().await;

        if pending.is_empty() {
            return Ok(());
        }

        info!("Flushing {} buffered local candidates", pending.len());

        for trickle_candidate in pending.drain(..) {
            if let Ok(candidate) = trickle_candidate.to_candidate() {
                self.stats.candidates_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                if let Err(e) = self.event_tx.send(TrickleEvent::LocalCandidateReady(candidate)) {
                    error!("Failed to flush candidate: {}", e);
                    return Err(TrickleError::ChannelClosed);
                }
            }
        }

        self.stats.candidates_buffered.store(0, std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }

    /// Check if all streams are complete
    async fn check_completion(&self) {
        if self.is_complete().await {
            info!("All streams have completed trickle ICE");
            // Could send a completion event here if needed
        }
    }

    /// Reset state for ICE restart
    pub async fn reset(&self) -> Result<(), TrickleError> {
        info!("Resetting trickle ICE state");

        // Clear all state
        self.eoc_sent.write().await.clear();
        self.eoc_received.write().await.clear();
        self.pending_local.lock().await.clear();
        self.pending_remote.lock().await.clear();
        self.active_streams.write().await.clear();
        *self.remote_ready.write().await = false;

        // Reset stats
        self.stats.candidates_sent.store(0, std::sync::atomic::Ordering::Relaxed);
        self.stats.candidates_received.store(0, std::sync::atomic::Ordering::Relaxed);
        self.stats.candidates_buffered.store(0, std::sync::atomic::Ordering::Relaxed);
        self.stats.candidates_dropped.store(0, std::sync::atomic::Ordering::Relaxed);
        self.stats.eoc_sent_count.store(0, std::sync::atomic::Ordering::Relaxed);
        self.stats.eoc_received_count.store(0, std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }
}

/// Trickle ICE error types
#[derive(Debug, thiserror::Error)]
pub enum TrickleError {
    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Unknown stream: {0}")]
    UnknownStream(u32),

    #[error("No active streams")]
    NoActiveStreams,

    #[error("Event channel closed")]
    ChannelClosed,

    #[error("Trickle ICE timeout")]
    Timeout,

    #[error("Candidate parsing error: {0}")]
    CandidateError(String),
}

/// Trickle ICE candidate format for signaling
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrickleCandidate {
    /// SDP mid value (media stream identification)
    pub sdp_mid: String,

    /// SDP m-line index
    pub sdp_mline_index: u32,

    /// Candidate SDP attribute line
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
    pub fn to_candidate(&self) -> Result<Candidate, TrickleError> {
        Candidate::from_sdp_attribute(&self.candidate)
            .map_err(|e| TrickleError::CandidateError(e.to_string()))
    }
}

/// Statistics snapshot
#[derive(Debug, Clone)]
pub struct TrickleStatsSnapshot {
    pub candidates_sent: usize,
    pub candidates_received: usize,
    pub candidates_buffered: usize,
    pub candidates_dropped: usize,
    pub eoc_sent_count: usize,
    pub eoc_received_count: usize,
}

/// JSON format for trickle ICE signaling
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum TrickleMessage {
    /// New candidate available
    #[serde(rename = "candidate")]
    Candidate {
        candidate: TrickleCandidate,
        #[serde(skip_serializing_if = "Option::is_none")]
        stream_id: Option<u32>,
    },

    /// End of candidates for a stream
    #[serde(rename = "end-of-candidates")]
    EndOfCandidates {
        stream_id: u32,
    },

    /// Remote is ready to receive candidates
    #[serde(rename = "ready")]
    Ready,

    /// ICE restart
    #[serde(rename = "restart")]
    Restart {
        #[serde(skip_serializing_if = "Option::is_none")]
        ufrag: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pwd: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::ice::{CandidateType, TransportProtocol};

    #[tokio::test]
    async fn test_trickle_ice_flow() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let trickle = TrickleIce::new(tx);

        // Add stream
        trickle.add_stream(1).await.unwrap();

        // Send candidate before remote ready (should buffer)
        let candidate = Candidate::new_host(
            "192.168.1.100:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        trickle.send_candidate(candidate.clone()).await.unwrap();

        // Should be buffered, not sent
        assert!(rx.try_recv().is_err());
        assert_eq!(trickle.get_stats().candidates_buffered, 1);

        // Signal remote ready
        trickle.set_remote_ready().await.unwrap();

        // Should receive ready event and flushed candidate
        match rx.recv().await {
            Some(TrickleEvent::RemoteReady) => {}
            other => panic!("Expected RemoteReady, got {:?}", other),
        }

        match rx.recv().await {
            Some(TrickleEvent::LocalCandidateReady(c)) => {
                assert_eq!(c.addr, candidate.addr);
            }
            other => panic!("Expected LocalCandidateReady, got {:?}", other),
        }

        // Send end of candidates
        trickle.send_end_of_candidates(1).await.unwrap();

        match rx.recv().await {
            Some(TrickleEvent::EndOfCandidates { stream_id }) => {
                assert_eq!(stream_id, 1);
            }
            other => panic!("Expected EndOfCandidates, got {:?}", other),
        }

        // Should not be able to send more candidates
        let result = trickle.send_candidate(candidate).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_completion_tracking() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let trickle = TrickleIce::new(tx);

        // Add multiple streams
        trickle.add_stream(1).await.unwrap();
        trickle.add_stream(2).await.unwrap();

        assert!(!trickle.is_complete().await);

        // Send EOC for stream 1
        trickle.send_end_of_candidates(1).await.unwrap();
        assert!(!trickle.is_complete().await);

        // Receive EOC for stream 1
        trickle.receive_end_of_candidates(1).await.unwrap();
        assert!(!trickle.is_complete().await);

        // Complete stream 2
        trickle.send_end_of_candidates(2).await.unwrap();
        trickle.receive_end_of_candidates(2).await.unwrap();

        assert!(trickle.is_complete().await);
    }

    #[tokio::test]
    async fn test_unknown_stream_handling() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let trickle = TrickleIce::new(tx);

        // Try to send EOC for unknown stream
        let result = trickle.send_end_of_candidates(99).await;
        assert!(matches!(result, Err(TrickleError::UnknownStream(99))));

        // Try to receive candidate for unknown stream
        let candidate = Candidate::new_host(
            "192.168.1.100:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        let result = trickle.receive_candidate(candidate, 99).await;
        assert!(matches!(result, Err(TrickleError::UnknownStream(99))));
    }

    #[tokio::test]
    async fn test_duplicate_eoc_handling() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let trickle = TrickleIce::new(tx);

        trickle.add_stream(1).await.unwrap();

        // Send EOC twice
        trickle.send_end_of_candidates(1).await.unwrap();
        trickle.send_end_of_candidates(1).await.unwrap(); // Should be idempotent

        // Should only receive one event
        let mut eoc_count = 0;
        while let Ok(event) = rx.try_recv() {
            if matches!(event, TrickleEvent::EndOfCandidates { .. }) {
                eoc_count += 1;
            }
        }
        assert_eq!(eoc_count, 1);
    }

    #[tokio::test]
    async fn test_trickle_message_serialization() {
        let candidate = Candidate::new_host(
            "192.168.1.100:50000".parse().unwrap(),
            1,
            TransportProtocol::Udp,
            1,
        );

        let trickle_candidate = TrickleCandidate::from_candidate(&candidate, "0".to_string(), 0);

        let message = TrickleMessage::Candidate {
            candidate: trickle_candidate,
            stream_id: Some(1),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("\"type\":\"candidate\""));

        // Deserialize back
        let deserialized: TrickleMessage = serde_json::from_str(&json).unwrap();

        match deserialized {
            TrickleMessage::Candidate { candidate: tc, stream_id } => {
                assert_eq!(stream_id, Some(1));
                let parsed = tc.to_candidate().unwrap();
                assert_eq!(parsed.addr, candidate.addr);
            }
            _ => panic!("Wrong message type"),
        }
    }
}