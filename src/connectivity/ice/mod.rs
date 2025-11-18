//! ICE (Interactive Connectivity Establishment) module
//!
//! Production implementation based on webrtc-rs library
//! RFC 8445 compliant

// Core ICE modules
pub mod agent;
pub mod connectivity;
pub mod gathering;
pub mod nomination;
pub mod utils;
pub mod webrtc_integration;
pub mod production_ice_agent;

// Re-export main types for convenience
pub use agent::IceAgent;
pub use connectivity::ConnectivityChecker;
pub use gathering::CandidateGatherer;
pub use nomination::NominationHandler;
pub use utils::*;
pub use webrtc_integration::*;
pub use production_ice_agent::ProductionIceAgent;

// Type alias for production use
pub type ProductionAgent = ProductionIceAgent;
