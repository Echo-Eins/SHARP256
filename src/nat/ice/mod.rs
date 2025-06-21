// src/nat/ice/mod.rs
//! ICE (Interactive Connectivity Establishment) implementation
//!
//! Implements RFC 8445 (ICE), RFC 5768 (TURN for ICE),
//! RFC 8421 (Multi-homed and IPv4/IPv6 Dual-Stack),
//! and RFC 8838 (Trickle ICE)

pub mod agent;
pub mod candidate;
pub mod check_list;
pub mod connectivity;
pub mod foundation;
pub mod gathering;
pub mod nomination;
pub mod priority;
pub mod stream;
pub mod trickle;
pub mod utils;

pub use agent::{IceAgent, IceConfig, IceRole, IceState};
pub use candidate::{Candidate, CandidateType, CandidatePair, TransportProtocol};
pub use stream::{IceStream, Component};
pub use trickle::{TrickleIce, TrickleEvent};

use crate::nat::error::{NatError, NatResult};
use std::net::SocketAddr;
use tokio::sync::mpsc;

/// ICE session credentials
#[derive(Debug, Clone)]
pub struct IceCredentials {
    /// Username fragment (ufrag)
    pub ufrag: String,
    /// Password
    pub pwd: String,
}

impl IceCredentials {
    /// Generate new random credentials
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // RFC 8445 Section 5.4: ufrag at least 4 characters
        let ufrag: String = (0..8)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        // RFC 8445 Section 5.4: password at least 22 characters
        let pwd: String = (0..24)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        Self { ufrag, pwd }
    }
}

/// ICE event for application callbacks
#[derive(Debug, Clone)]
pub enum IceEvent {
    /// New local candidate discovered
    CandidateGathered(Candidate),

    /// All candidates have been gathered
    GatheringComplete,

    /// ICE state changed
    StateChanged(IceState),

    /// New validated pair (can send data)
    ValidatedPair(CandidatePair),

    /// Selected candidate pair for component
    SelectedPair {
        stream_id: u32,
        component_id: u32,
        local: Candidate,
        remote: Candidate,
    },

    /// ICE restart required
    RestartRequired,

    /// Connection failed
    Failed(String),
}

/// ICE transport policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceTransportPolicy {
    /// Use all candidate types
    All,
    /// Only use relay candidates
    Relay,
}