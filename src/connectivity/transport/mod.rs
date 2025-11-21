//! Transport Layer for SHARP-256
//!
//! This module provides a production-ready transport abstraction layer compliant with:
//! - RFC 8445: Interactive Connectivity Establishment (ICE)
//! - RFC 8838: Trickle ICE
//! - RFC 7675: STUN Usage for Consent Freshness
//! - RFC 8421: Guidelines for Multihomed and IPv4/IPv6 Dual-Stack ICE
//!
//! # Architecture
//!
//! The transport layer is built on top of ICE (Interactive Connectivity Establishment)
//! which provides NAT traversal capabilities through:
//! - Candidate gathering (host, server-reflexive, relayed)
//! - Connectivity checks using STUN
//! - Nomination of candidate pairs
//! - Consent freshness validation
//!
//! # Usage
//!
//! ```no_run
//! # use anyhow::Result;
//! # use sharp256::connectivity::transport::{Transport, IceTransport};
//! # async fn example() -> Result<()> {
//! // Create ICE transport
//! let transport = IceTransport::new(ice_config, true).await?;
//!
//! // Start ICE process (gathering, checks, nomination)
//! transport.connect().await?;
//!
//! // Send data
//! transport.send(b"Hello, World!").await?;
//!
//! // Receive data
//! let mut buffer = vec![0u8; 1024];
//! let size = transport.recv(&mut buffer).await?;
//!
//! // Get statistics
//! let stats = transport.stats().await;
//! # Ok(())
//! # }
//! ```

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::connectivity::{Candidate, CandidatePair};

pub mod ice_transport;
pub mod mtu_discovery;
pub mod socket;
pub mod stats;

pub use stats::{
    CandidatePairStats, ConsentStats, IceRole, IceStats, PerformanceMetrics, QualityMetrics,
    SocketStats, StunServerStats, TransportStats, TurnServerStats,
};

pub use socket::{
    HappyEyeballsConnector, IpVersion, NetworkInterface, NetworkInterfaceDetector, SocketOptions,
    SocketState, UdpSocketWrapper,
};

pub use mtu_discovery::{
    InterfaceMtuDetector, PathMtuDiscovery, PmtudState, PmtudStats, ProbeResult,
};

pub use ice_transport::{IceTransport, IceTransportConfig};

// ═══════════════════════════════════════════════════════════════════════════
// TRANSPORT TRAIT - RFC 8445 Section 7
// ═══════════════════════════════════════════════════════════════════════════

/// Transport trait providing a unified interface for network connectivity
///
/// This trait is designed to be RFC 8445 compliant and provides methods for:
/// - Connection establishment (Section 7)
/// - Data transfer (UDP-based)
/// - State management (Section 11)
/// - Statistics collection (Section 14)
/// - ICE restart capability (Section 9)
/// - Consent freshness (RFC 7675)
///
/// # RFC 8445 Compliance
///
/// The trait enforces RFC 8445 requirements:
/// - MUST support gathering of all candidate types (Section 5)
/// - MUST perform connectivity checks (Section 6)
/// - MUST support nomination (Section 8)
/// - SHOULD support ICE restart (Section 9)
/// - MUST collect statistics (Section 14)
/// - MUST implement consent freshness checks (RFC 7675)
///
/// # Thread Safety
///
/// All implementations MUST be Send + Sync to support concurrent access.
#[async_trait]
pub trait Transport: Send + Sync + Debug {
    // ═══════════════════════════════════════════════════════════════════════
    // Connection Management (RFC 8445 Section 7)
    // ═══════════════════════════════════════════════════════════════════════

    /// Establish connection using ICE process
    ///
    /// This method initiates the full ICE connection establishment process:
    /// 1. Candidate gathering (RFC 8445 Section 5)
    /// 2. Connectivity checks (RFC 8445 Section 6)
    /// 3. Nomination (RFC 8445 Section 8)
    /// 4. Connection conclusion (RFC 8445 Section 7)
    ///
    /// # Returns
    ///
    /// - `Ok(ConnectionInfo)` - Connection successfully established
    /// - `Err` - ICE process failed or timed out
    ///
    /// # RFC 8445 Section 7 (Conclusion of ICE)
    ///
    /// ICE concludes when:
    /// - At least one valid candidate pair exists
    /// - A nominated pair is selected
    /// - Connectivity checks complete
    ///
    /// # Errors
    ///
    /// - No valid candidate pairs found
    /// - Connectivity checks failed
    /// - Nomination timeout
    /// - Network unreachable
    async fn connect(&self) -> Result<ConnectionInfo>;

    /// Check if transport is ready for data transfer
    ///
    /// A transport is considered ready when:
    /// - ICE process is completed (RFC 8445 Section 7)
    /// - Nominated pair is selected (RFC 8445 Section 8)
    /// - Consent is fresh (RFC 7675)
    ///
    /// # RFC 7675 Consent Freshness
    ///
    /// Even after ICE completion, consent MUST be maintained through
    /// periodic STUN checks to ensure the peer still consents to receive data.
    async fn is_ready(&self) -> bool;

    /// Get current connection state
    ///
    /// Returns the ICE agent state as defined in RFC 8445 Section 11.
    /// State transitions follow the ICE state machine.
    ///
    /// # RFC 8445 Section 11 States
    ///
    /// - New: Initial state
    /// - Gathering: Collecting candidates
    /// - Checking: Performing connectivity checks
    /// - Connected: At least one working pair
    /// - Completed: ICE concluded, nominated pair selected
    /// - Failed: All checks failed
    /// - Closed: ICE process terminated
    fn state(&self) -> ConnectionState;

    // ═══════════════════════════════════════════════════════════════════════
    // Data Transfer (UDP Protocol - RFC 768)
    // ═══════════════════════════════════════════════════════════════════════

    /// Send data through the established connection
    ///
    /// Transmits data using the nominated candidate pair over UDP.
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice to transmit
    ///
    /// # Returns
    ///
    /// Number of bytes sent
    ///
    /// # Errors
    ///
    /// - Connection not established
    /// - Consent expired (RFC 7675)
    /// - Network error
    /// - Buffer too large
    ///
    /// # RFC 7675 Consent
    ///
    /// Before sending, the implementation MUST verify that consent is fresh.
    /// If consent has expired, an error MUST be returned.
    async fn send(&self, data: &[u8]) -> Result<usize>;

    /// Receive data from the connection
    ///
    /// Receives data on the nominated candidate pair.
    ///
    /// # Arguments
    ///
    /// * `buffer` - Buffer to receive data into
    ///
    /// # Returns
    ///
    /// Number of bytes received
    ///
    /// # Errors
    ///
    /// - Connection not established
    /// - Consent expired
    /// - Network error
    /// - Timeout
    async fn recv(&self, buffer: &mut [u8]) -> Result<usize>;

    // ═══════════════════════════════════════════════════════════════════════
    // Addressing (RFC 8445 Section 5.1)
    // ═══════════════════════════════════════════════════════════════════════

    /// Get local address from the nominated candidate
    ///
    /// Returns the local address of the selected candidate pair.
    /// This is the address that will be used for data transmission.
    ///
    /// # RFC 8445 Section 5.1 Candidate Attributes
    ///
    /// The local address corresponds to the connection address of the
    /// nominated local candidate.
    ///
    /// # Errors
    ///
    /// - No nominated pair selected yet
    fn local_addr(&self) -> Result<SocketAddr>;

    /// Get remote address from the nominated candidate
    ///
    /// Returns the remote address of the selected candidate pair.
    ///
    /// # Errors
    ///
    /// - No nominated pair selected yet
    fn remote_addr(&self) -> Result<SocketAddr>;

    // ═══════════════════════════════════════════════════════════════════════
    // Statistics (RFC 8445 Section 14)
    // ═══════════════════════════════════════════════════════════════════════

    /// Get comprehensive transport statistics
    ///
    /// Collects statistics as mandated by RFC 8445 Section 14.
    /// Statistics include:
    /// - Candidate gathering metrics
    /// - Connectivity check results
    /// - Nomination information
    /// - Data transfer statistics
    /// - Consent freshness status
    /// - Quality metrics (RTT, jitter, packet loss)
    ///
    /// # RFC 8445 Section 14 Requirements
    ///
    /// Implementations MUST collect and report:
    /// - Number and types of candidates gathered
    /// - Connectivity check statistics
    /// - Selected candidate pair information
    /// - Bytes and packets sent/received
    ///
    /// # Performance
    ///
    /// This method should be lightweight and not block data transfer.
    async fn stats(&self) -> TransportStats;

    /// Get current Round-Trip Time (RTT)
    ///
    /// Returns the latest RTT measurement from connectivity checks.
    ///
    /// # RFC 8445 Section 6
    ///
    /// RTT is measured during connectivity checks using STUN request/response
    /// timing.
    fn rtt(&self) -> Option<Duration>;

    // ═══════════════════════════════════════════════════════════════════════
    // Lifecycle Management
    // ═══════════════════════════════════════════════════════════════════════

    /// Close the transport gracefully
    ///
    /// Performs cleanup:
    /// - Stops consent freshness checks
    /// - Closes sockets
    /// - Releases resources
    /// - Notifies peer (if possible)
    ///
    /// # Graceful Shutdown
    ///
    /// The implementation SHOULD attempt to:
    /// - Send final STUN indication to peer
    /// - Wait for in-flight packets (with timeout)
    /// - Close sockets cleanly
    async fn close(&self) -> Result<()>;

    /// Restart ICE process
    ///
    /// Initiates ICE restart as defined in RFC 8445 Section 9.
    ///
    /// # RFC 8445 Section 9 (ICE Restart)
    ///
    /// ICE restart:
    /// - Generates new ice-ufrag and ice-pwd
    /// - Re-gathers candidates
    /// - Performs new connectivity checks
    /// - Maintains data transfer during transition (if possible)
    ///
    /// # Use Cases
    ///
    /// - Network topology change detected
    /// - All candidate pairs failed
    /// - Explicit request from application
    ///
    /// # Errors
    ///
    /// - Already in restart process
    /// - Resources unavailable
    async fn restart(&self) -> Result<()>;
}

// ═══════════════════════════════════════════════════════════════════════════
// CONNECTION STATE - RFC 8445 Section 11
// ═══════════════════════════════════════════════════════════════════════════

/// ICE agent connection state as defined in RFC 8445 Section 11
///
/// The state machine transitions according to ICE process progress.
///
/// # State Transitions (RFC 8445 Section 11)
///
/// ```text
/// New -> Gathering -> Checking -> (Connected | Failed)
///                                      |
///                                  Completed -> Closed
/// ```
///
/// # States
///
/// - **New**: Initial state, no activity yet
/// - **Gathering**: Collecting local candidates
/// - **Checking**: Performing connectivity checks
/// - **Connected**: At least one working candidate pair exists
/// - **Completed**: ICE concluded, nominated pair selected
/// - **Failed**: All connectivity checks failed
/// - **Disconnected**: Previously connected, now lost connectivity
/// - **Closed**: ICE process terminated, resources released
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Initial state before any ICE processing
    New,

    /// Gathering candidates (RFC 8445 Section 5)
    /// In this state, the agent is:
    /// - Discovering local interfaces
    /// - Performing STUN binding requests to discover reflexive candidates
    /// - Allocating TURN relays for relayed candidates
    Gathering,

    /// Performing connectivity checks (RFC 8445 Section 6)
    /// The agent is:
    /// - Sending STUN binding requests to candidate pairs
    /// - Processing STUN responses
    /// - Updating pair states
    Checking,

    /// At least one candidate pair is working (RFC 8445 Section 6)
    /// - Can send/receive data
    /// - Still performing checks on other pairs
    /// - Not yet nominated (unless aggressive nomination)
    Connected,

    /// ICE process completed (RFC 8445 Section 7)
    /// - Nominated pair selected
    /// - All checks complete
    /// - Ready for data transfer
    /// - Consent freshness checks active (RFC 7675)
    Completed,

    /// All connectivity checks failed (RFC 8445 Section 8.1.2)
    /// No working candidate pairs found
    /// May trigger ICE restart
    Failed,

    /// Previously connected, connectivity lost
    /// - Consent freshness check failed (RFC 7675)
    /// - Network change detected
    /// - May automatically trigger ICE restart
    Disconnected,

    /// Transport closed, resources released
    /// Terminal state
    Closed,
}

impl ConnectionState {
    /// Check if state represents an active connection
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Connected | Self::Completed)
    }

    /// Check if state allows data transfer
    pub fn can_transfer_data(&self) -> bool {
        matches!(self, Self::Connected | Self::Completed)
    }

    /// Check if state is terminal (no further transitions)
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed | Self::Failed)
    }

    /// Check if ICE gathering is in progress
    pub fn is_gathering(&self) -> bool {
        matches!(self, Self::Gathering)
    }

    /// Check if connectivity checks are running
    pub fn is_checking(&self) -> bool {
        matches!(self, Self::Checking | Self::Connected)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONNECTION INFO
// ═══════════════════════════════════════════════════════════════════════════

/// Information about an established connection
///
/// Provides complete details about the ICE connection including
/// selected candidate pair, quality metrics, and timing information.
///
/// # RFC 8445 Compliance
///
/// This structure captures information required by:
/// - Section 7: Connection conclusion details
/// - Section 8: Nomination information
/// - Section 14: Statistics collection
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Local address from nominated pair
    pub local_addr: SocketAddr,

    /// Remote address from nominated pair
    pub remote_addr: SocketAddr,

    /// The nominated candidate pair (RFC 8445 Section 8)
    pub nominated_pair: CandidatePair,

    /// Connection state
    pub state: ConnectionState,

    /// Round-Trip Time measured during connectivity checks
    pub rtt: Duration,

    /// When the connection was established
    pub established_at: Instant,

    /// Transport type (ICE, Direct, etc.)
    pub transport_type: TransportType,

    /// Connection quality metrics
    pub quality: QualityMetrics,

    /// Whether consent is currently fresh (RFC 7675)
    pub consent_fresh: bool,

    /// Time of last consent freshness check
    pub last_consent_check: Option<Instant>,
}

impl ConnectionInfo {
    /// Get connection age
    pub fn age(&self) -> Duration {
        self.established_at.elapsed()
    }

    /// Check if connection is healthy
    pub fn is_healthy(&self) -> bool {
        self.state.is_active() && self.consent_fresh && self.quality.is_acceptable()
    }

    /// Check if consent needs refresh (RFC 7675)
    ///
    /// RFC 7675 requires periodic consent checks.
    /// Typically every 5-30 seconds.
    pub fn needs_consent_refresh(&self, interval: Duration) -> bool {
        match self.last_consent_check {
            Some(last_check) => last_check.elapsed() >= interval,
            None => true,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TRANSPORT TYPE
// ═══════════════════════════════════════════════════════════════════════════

/// Type of transport used for connection
///
/// Indicates which connectivity method successfully established the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportType {
    /// ICE-based connection (RFC 8445)
    /// Most common for NAT traversal
    Ice,

    /// Direct UDP connection (no NAT traversal)
    /// Used when both endpoints are publicly reachable
    Direct,

    /// WebRTC Data Channel
    /// Built on top of ICE
    WebRtc,
}

impl TransportType {
    /// Check if transport requires ICE
    pub fn uses_ice(&self) -> bool {
        matches!(self, Self::Ice | Self::WebRtc)
    }

    /// Get human-readable name
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ice => "ICE (RFC 8445)",
            Self::Direct => "Direct UDP",
            Self::WebRtc => "WebRTC DataChannel",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TRANSPORT CAPABILITIES
// ═══════════════════════════════════════════════════════════════════════════

/// Transport capabilities and features
///
/// Describes what features a transport implementation supports.
#[derive(Debug, Clone, Default)]
pub struct TransportCapabilities {
    /// Supports ICE (RFC 8445)
    pub ice: bool,

    /// Supports Trickle ICE (RFC 8838)
    pub trickle_ice: bool,

    /// Supports ICE restart (RFC 8445 Section 9)
    pub ice_restart: bool,

    /// Supports consent freshness (RFC 7675)
    pub consent_freshness: bool,

    /// Supports IPv4
    pub ipv4: bool,

    /// Supports IPv6
    pub ipv6: bool,

    /// Supports dual-stack (RFC 8421)
    pub dual_stack: bool,

    /// Supports TURN relay (RFC 5766)
    pub turn_relay: bool,

    /// Maximum packet size supported
    pub max_packet_size: usize,

    /// Supports gathering host candidates
    pub host_candidates: bool,

    /// Supports gathering server-reflexive candidates
    pub srflx_candidates: bool,

    /// Supports gathering relay candidates
    pub relay_candidates: bool,
}

impl TransportCapabilities {
    /// Create capabilities for full RFC 8445 implementation
    pub fn full_ice() -> Self {
        Self {
            ice: true,
            trickle_ice: true,
            ice_restart: true,
            consent_freshness: true,
            ipv4: true,
            ipv6: true,
            dual_stack: true,
            turn_relay: true,
            max_packet_size: 65535,
            host_candidates: true,
            srflx_candidates: true,
            relay_candidates: true,
        }
    }

    /// Create capabilities for minimal RFC 8445 implementation
    pub fn minimal_ice() -> Self {
        Self {
            ice: true,
            trickle_ice: false,
            ice_restart: false,
            consent_freshness: true,
            ipv4: true,
            ipv6: false,
            dual_stack: false,
            turn_relay: false,
            max_packet_size: 1500,
            host_candidates: true,
            srflx_candidates: true,
            relay_candidates: false,
        }
    }

    /// Check if RFC 8445 MUST requirements are met
    pub fn is_rfc8445_compliant(&self) -> bool {
        self.ice
            && self.consent_freshness
            && (self.ipv4 || self.ipv6)
            && self.host_candidates
            && self.srflx_candidates
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TRANSPORT EVENT
// ═══════════════════════════════════════════════════════════════════════════

/// Events emitted by transport during its lifecycle
///
/// Provides real-time visibility into the ICE process and connection health.
///
/// # Use Cases
///
/// - Monitoring ICE progress
/// - Debugging connectivity issues
/// - Collecting metrics
/// - UI updates
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// ICE gathering started (RFC 8445 Section 5)
    GatheringStarted,

    /// New local candidate gathered
    ///
    /// Emitted for each candidate:
    /// - Host candidate (local interface)
    /// - Server-reflexive (STUN response)
    /// - Relayed (TURN allocation)
    CandidateGathered { candidate: Candidate },

    /// Candidate gathering completed (RFC 8445 Section 5)
    ///
    /// All candidates have been collected.
    /// Ready to exchange with peer.
    GatheringCompleted { total_candidates: usize },

    /// Remote candidate added (Trickle ICE - RFC 8838)
    RemoteCandidateAdded { candidate: Candidate },

    /// Connectivity checks started (RFC 8445 Section 6)
    CheckingStarted,

    /// Connectivity check completed for a candidate pair
    ///
    /// Provides result of STUN binding request/response.
    CheckCompleted {
        pair: CandidatePair,
        success: bool,
        rtt: Option<Duration>,
    },

    /// Candidate pair nominated (RFC 8445 Section 8)
    ///
    /// This pair will be used for data transfer.
    PairNominated { pair: CandidatePair },

    /// Connection established (RFC 8445 Section 7)
    ///
    /// ICE has concluded successfully.
    Connected { info: ConnectionInfo },

    /// Connection state changed
    StateChanged {
        old_state: ConnectionState,
        new_state: ConnectionState,
    },

    /// Consent freshness check performed (RFC 7675)
    ConsentCheckPerformed {
        success: bool,
        rtt: Option<Duration>,
    },

    /// Consent expired (RFC 7675)
    ///
    /// No successful consent check within timeout period.
    /// Data transfer should stop.
    ConsentExpired,

    /// ICE restart initiated (RFC 8445 Section 9)
    RestartInitiated,

    /// ICE restart completed
    RestartCompleted,

    /// End-of-candidates received (RFC 8838 Section 13)
    ///
    /// Remote peer has finished gathering candidates.
    /// No more candidates will be received.
    EndOfCandidatesReceived,

    /// Connection failed
    ///
    /// All connectivity checks failed or timed out.
    Failed { reason: String },

    /// Connection closed gracefully
    Closed,

    /// Error occurred
    Error { error: String },

    /// Statistics updated
    ///
    /// Emitted periodically (e.g., every second)
    StatsUpdated { stats: TransportStats },
}

impl TransportEvent {
    /// Check if event indicates a critical failure
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. } | Self::ConsentExpired)
    }

    /// Check if event indicates successful connection
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }

    /// Get event type name for logging
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::GatheringStarted => "GatheringStarted",
            Self::CandidateGathered { .. } => "CandidateGathered",
            Self::GatheringCompleted { .. } => "GatheringCompleted",
            Self::RemoteCandidateAdded { .. } => "RemoteCandidateAdded",
            Self::CheckingStarted => "CheckingStarted",
            Self::CheckCompleted { .. } => "CheckCompleted",
            Self::PairNominated { .. } => "PairNominated",
            Self::Connected { .. } => "Connected",
            Self::StateChanged { .. } => "StateChanged",
            Self::ConsentCheckPerformed { .. } => "ConsentCheckPerformed",
            Self::ConsentExpired => "ConsentExpired",
            Self::RestartInitiated => "RestartInitiated",
            Self::RestartCompleted => "RestartCompleted",
            Self::EndOfCandidatesReceived => "EndOfCandidatesReceived",
            Self::Failed { .. } => "Failed",
            Self::Closed => "Closed",
            Self::Error { .. } => "Error",
            Self::StatsUpdated { .. } => "StatsUpdated",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_transitions() {
        let state = ConnectionState::New;
        assert!(!state.is_active());
        assert!(!state.can_transfer_data());
        assert!(!state.is_terminal());

        let state = ConnectionState::Completed;
        assert!(state.is_active());
        assert!(state.can_transfer_data());
        assert!(!state.is_terminal());

        let state = ConnectionState::Closed;
        assert!(!state.is_active());
        assert!(!state.can_transfer_data());
        assert!(state.is_terminal());
    }

    #[test]
    fn test_transport_type() {
        assert!(TransportType::Ice.uses_ice());
        assert!(TransportType::WebRtc.uses_ice());
        assert!(!TransportType::Direct.uses_ice());

        assert_eq!(TransportType::Ice.as_str(), "ICE (RFC 8445)");
    }

    #[test]
    fn test_transport_capabilities_full() {
        let caps = TransportCapabilities::full_ice();
        assert!(caps.is_rfc8445_compliant());
        assert!(caps.ice);
        assert!(caps.trickle_ice);
        assert!(caps.ice_restart);
        assert!(caps.consent_freshness);
        assert!(caps.dual_stack);
    }

    #[test]
    fn test_transport_capabilities_minimal() {
        let caps = TransportCapabilities::minimal_ice();
        assert!(caps.is_rfc8445_compliant());
        assert!(caps.ice);
        assert!(!caps.trickle_ice);
        assert!(!caps.dual_stack);
    }

    #[test]
    fn test_transport_event_classification() {
        let event = TransportEvent::Connected {
            info: create_mock_connection_info(),
        };
        assert!(event.is_success());
        assert!(!event.is_failure());

        let event = TransportEvent::Failed {
            reason: "timeout".to_string(),
        };
        assert!(!event.is_success());
        assert!(event.is_failure());

        let event = TransportEvent::ConsentExpired;
        assert!(event.is_failure());
    }

    #[test]
    fn test_connection_info_health() {
        let mut info = create_mock_connection_info();
        info.consent_fresh = true;
        info.state = ConnectionState::Completed;
        assert!(info.is_healthy());

        info.consent_fresh = false;
        assert!(!info.is_healthy());
    }

    #[test]
    fn test_consent_refresh_timing() {
        let mut info = create_mock_connection_info();
        info.last_consent_check = Some(Instant::now());

        // Should not need refresh immediately
        assert!(!info.needs_consent_refresh(Duration::from_secs(30)));

        // Simulate old check
        info.last_consent_check = Some(Instant::now() - Duration::from_secs(31));
        assert!(info.needs_consent_refresh(Duration::from_secs(30)));

        // No check ever performed
        info.last_consent_check = None;
        assert!(info.needs_consent_refresh(Duration::from_secs(30)));
    }

    // Helper function for tests
    fn create_mock_connection_info() -> ConnectionInfo {
        use crate::connectivity::CandidateType;

        let local_addr = "192.168.1.100:5000".parse().unwrap();
        let remote_addr = "192.168.1.200:5000".parse().unwrap();

        let local_candidate = Candidate::host(local_addr);
        let remote_candidate = Candidate::host(remote_addr);
        let pair = CandidatePair::new(local_candidate, remote_candidate);

        ConnectionInfo {
            local_addr,
            remote_addr,
            nominated_pair: pair,
            state: ConnectionState::Completed,
            rtt: Duration::from_millis(50),
            established_at: Instant::now(),
            transport_type: TransportType::Ice,
            quality: QualityMetrics::default(),
            consent_fresh: true,
            last_consent_check: Some(Instant::now()),
        }
    }
}
