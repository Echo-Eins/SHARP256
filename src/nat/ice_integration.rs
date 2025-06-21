// src/nat/ice_integration.rs
//! Integration of ICE with SHARP3 protocol

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};

use crate::nat::ice::{
    IceAgent, IceConfig, IceRole, IceState, IceEvent,
    IceCredentials, Candidate,
};
use crate::nat::error::{NatError, NatResult};

/// ICE integration for SHARP3
pub struct Sharp3IceIntegration {
    /// ICE agent
    ice_agent: Arc<IceAgent>,

    /// Selected transport address
    selected_addr: Arc<RwLock<Option<SocketAddr>>>,

    /// Connection established flag
    connected: Arc<RwLock<bool>>,
}

impl Sharp3IceIntegration {
    /// Create new ICE integration
    pub async fn new(
        role: IceRole,
        stun_servers: Vec<String>,
    ) -> NatResult<Self> {
        let config = IceConfig {
            stun_servers,
            component_count: 1, // SHARP3 only needs one component
            trickle: true,
            ..Default::default()
        };

        let ice_agent = Arc::new(IceAgent::new(config, role)?);

        Ok(Self {
            ice_agent,
            selected_addr: Arc::new(RwLock::new(None)),
            connected: Arc::new(RwLock::new(false)),
        })
    }

    /// Get local ICE credentials for signaling
    pub fn get_local_credentials(&self) -> &IceCredentials {
        self.ice_agent.get_local_credentials()
    }

    /// Set remote ICE credentials from signaling
    pub async fn set_remote_credentials(&self, credentials: IceCredentials) -> NatResult<()> {
        self.ice_agent.set_remote_credentials(credentials).await
    }

    /// Start ICE gathering and return local candidates
    pub async fn gather_candidates(&self) -> NatResult<Vec<Candidate>> {
        // Add stream for SHARP3 data
        self.ice_agent.add_stream(1).await?;

        // Start gathering
        self.ice_agent.start_gathering().await?;

        // Collect candidates with timeout
        let mut candidates = Vec::new();
        let mut event_rx = self.ice_agent.get_event_rx();

        let gathering_timeout = Duration::from_secs(10);
        let deadline = tokio::time::Instant::now() + gathering_timeout;

        loop {
            match timeout(deadline - tokio::time::Instant::now(), event_rx.lock().await.recv()).await {
                Ok(Some(event)) => match event {
                    IceEvent::CandidateGathered(candidate) => {
                        candidates.push(candidate);
                    }
                    IceEvent::GatheringComplete => {
                        break;
                    }
                    IceEvent::StateChanged(IceState::Failed) => {
                        return Err(NatError::Platform("ICE gathering failed".to_string()));
                    }
                    _ => {}
                },
                Ok(None) => {
                    return Err(NatError::Platform("ICE event channel closed".to_string()));
                }
                Err(_) => {
                    // Timeout - return what we have
                    tracing::warn!("ICE gathering timeout, returning {} candidates", candidates.len());
                    break;
                }
            }
        }

        Ok(candidates)
    }

    /// Add remote candidates
    pub async fn add_remote_candidates(&self, candidates: Vec<Candidate>) -> NatResult<()> {
        for candidate in candidates {
            self.ice_agent.add_remote_candidate(candidate).await?;
        }
        Ok(())
    }

    /// Start ICE connectivity checks and wait for connection
    pub async fn establish_connection(&self) -> NatResult<SocketAddr> {
        // Start connectivity checks
        self.ice_agent.start_checks().await?;

        // Wait for connection with timeout
        let mut event_rx = self.ice_agent.get_event_rx();
        let connection_timeout = Duration::from_secs(30);
        let deadline = tokio::time::Instant::now() + connection_timeout;

        loop {
            match timeout(deadline - tokio::time::Instant::now(), event_rx.lock().await.recv()).await {
                Ok(Some(event)) => match event {
                    IceEvent::StateChanged(IceState::Connected) => {
                        *self.connected.write().await = true;
                        tracing::info!("ICE connected");
                    }
                    IceEvent::SelectedPair { stream_id, component_id, local, remote } => {
                        if stream_id == 1 && component_id == 1 {
                            *self.selected_addr.write().await = Some(remote.addr);
                            tracing::info!("ICE selected pair: {} -> {}", local.addr, remote.addr);
                            return Ok(remote.addr);
                        }
                    }
                    IceEvent::StateChanged(IceState::Failed) => {
                        return Err(NatError::Platform("ICE connection failed".to_string()));
                    }
                    _ => {}
                },
                Ok(None) => {
                    return Err(NatError::Platform("ICE event channel closed".to_string()));
                }
                Err(_) => {
                    return Err(NatError::Timeout(connection_timeout));
                }
            }
        }
    }

    /// Get the selected address for data transfer
    pub async fn get_selected_address(&self) -> Option<SocketAddr> {
        *self.selected_addr.read().await
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    /// Close ICE agent
    pub async fn close(&self) -> NatResult<()> {
        self.ice_agent.close().await
    }
}

/// ICE parameters for signaling
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IceParameters {
    /// ICE username fragment
    pub ufrag: String,

    /// ICE password
    pub pwd: String,

    /// ICE candidates
    pub candidates: Vec<String>, // SDP format
}

impl IceParameters {
    /// Create from ICE credentials and candidates
    pub fn new(credentials: &IceCredentials, candidates: Vec<Candidate>) -> Self {
        Self {
            ufrag: credentials.ufrag.clone(),
            pwd: credentials.pwd.clone(),
            candidates: candidates.iter()
                .map(|c| c.to_sdp_attribute())
                .collect(),
        }
    }

    /// Convert to ICE credentials
    pub fn to_credentials(&self) -> IceCredentials {
        IceCredentials {
            ufrag: self.ufrag.clone(),
            pwd: self.pwd.clone(),
        }
    }

    /// Parse candidates
    pub fn parse_candidates(&self) -> Vec<Candidate> {
        self.candidates.iter()
            .filter_map(|s| Candidate::from_sdp_attribute(s).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ice_integration() {
        // Create ICE integration for controlling side
        let ice = Sharp3IceIntegration::new(
            IceRole::Controlling,
            vec!["stun.l.google.com:19302".to_string()],
        ).await.unwrap();

        // Get local credentials
        let local_creds = ice.get_local_credentials();
        assert!(!local_creds.ufrag.is_empty());
        assert!(!local_creds.pwd.is_empty());

        // This would normally gather candidates, but requires network
        // so we skip in test
    }

    #[test]
    fn test_ice_parameters_serialization() {
        let creds = IceCredentials::generate();
        let candidates = vec![
            Candidate::new_host(
                "192.168.1.100:50000".parse().unwrap(),
                1,
                crate::nat::ice::TransportProtocol::Udp,
                1,
            ),
        ];

        let params = IceParameters::new(&creds, candidates);

        // Serialize to JSON
        let json = serde_json::to_string(&params).unwrap();

        // Deserialize back
        let deserialized: IceParameters = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.ufrag, creds.ufrag);
        assert_eq!(deserialized.pwd, creds.pwd);

        // Parse candidates
        let parsed_candidates = deserialized.parse_candidates();
        assert_eq!(parsed_candidates.len(), 1);
    }
}