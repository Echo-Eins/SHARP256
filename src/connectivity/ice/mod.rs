//! ICE (Interactive Connectivity Establishment) module
//!
//! Production implementation based on webrtc-rs library
//! RFC 8445 compliant

use crate::connectivity::{Candidate, CandidatePair, ConnectivityCheckResult};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// Core ICE modules
pub mod agent;
pub mod connectivity;
pub mod gathering;
pub mod nomination;
pub mod production_ice_agent;
pub mod utils;
pub mod webrtc_integration;

// Re-export main types for convenience
pub use agent::IceAgent;
pub use connectivity::{ConnectivityChecker, ConnectivityState};
pub use gathering::{CandidateGatherer, GatheringState};
pub use nomination::{CandidateNominator, NominationState};
pub use production_ice_agent::ProductionIceAgent;
pub use utils::*;
pub use webrtc_integration::*;

// Type alias for production use
pub type ProductionAgent = ProductionIceAgent;

/// ICE Agent state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceAgentState {
    /// Agent created, not started
    New,
    /// Gathering candidates
    Gathering,
    /// Performing connectivity checks
    Connecting,
    /// At least one valid pair found
    Connected,
    /// ICE process completed successfully
    Completed,
    /// ICE process failed
    Failed,
    /// Agent closed
    Closed,
}

impl std::fmt::Display for IceAgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "New"),
            Self::Gathering => write!(f, "Gathering"),
            Self::Connecting => write!(f, "Connecting"),
            Self::Connected => write!(f, "Connected"),
            Self::Completed => write!(f, "Completed"),
            Self::Failed => write!(f, "Failed"),
            Self::Closed => write!(f, "Closed"),
        }
    }
}

/// ICE events
#[derive(Debug, Clone)]
pub enum IceEvent {
    /// ICE process started
    IceProcessStarted,
    /// Candidate gathered
    CandidateGathered(Candidate),
    /// Gathering completed
    GatheringComplete,
    /// Connectivity checks started
    ConnectivityChecksStarted,
    /// Connectivity check completed
    ConnectivityCheckCompleted(ConnectivityCheckResult),
    /// Candidate pair nominated
    CandidatePairNominated(CandidatePair),
    /// Connection established
    ConnectionEstablished(IceConnection),
    /// State changed
    StateChanged(IceAgentState),
    /// Error occurred
    Error(String),
}

/// Established ICE connection
#[derive(Clone)]
pub struct IceConnection {
    /// Local address
    pub local_addr: SocketAddr,
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Selected candidate pair
    pub selected_pair: CandidatePair,
    /// Connection RTT
    pub rtt: Duration,
    /// Creation time
    pub created_at: Instant,
    /// Connection state
    state: Arc<RwLock<IceConnectionState>>,
}

/// ICE connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceConnectionState {
    Active,
    Closing,
    Closed,
}

impl IceConnection {
    /// Create new ICE connection from selected pair
    pub fn new(pair: CandidatePair) -> Self {
        Self {
            local_addr: pair.local.address,
            remote_addr: pair.remote.address,
            selected_pair: pair,
            rtt: Duration::from_millis(0),
            created_at: Instant::now(),
            state: Arc::new(RwLock::new(IceConnectionState::Active)),
        }
    }

    /// Create connection with RTT
    pub fn with_rtt(pair: CandidatePair, rtt: Duration) -> Self {
        let mut conn = Self::new(pair);
        conn.rtt = rtt;
        conn
    }

    /// Get connection uptime
    pub fn uptime(&self) -> Duration {
        Instant::now() - self.created_at
    }

    /// Check if connection is active
    pub async fn is_active(&self) -> bool {
        *self.state.read().await == IceConnectionState::Active
    }

    /// Close the connection
    pub async fn close(&self) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        *state = IceConnectionState::Closed;
        Ok(())
    }
}

impl std::fmt::Debug for IceConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceConnection")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .field("rtt", &self.rtt)
            .field("uptime", &self.uptime())
            .finish()
    }
}
