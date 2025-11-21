//! SHARP-256 Protocol Library (lib.rs)
//!
//! High-performance file transfer protocol with BLAKE3 integrity verification
//! and comprehensive connectivity/NAT traversal support via ICE.

#![warn(missing_docs)]
#![warn(clippy::all)]

// Core protocol modules
pub mod buffer;
pub mod file;
pub mod fragmentation;
pub mod progress;
pub mod protocol;
pub mod sao;
pub mod state;

// Security module
pub mod security;

// Connectivity system (ICE/STUN/TURN - RFC 8445 compliant)
#[cfg(feature = "connectivity")]
pub mod connectivity;

// GUI module (feature-gated) - DEPRECATED: Will be replaced with TUI
#[cfg(feature = "gui")]
pub mod gui;

// Re-export main types
pub use fragmentation::*;
pub use progress::{EventCallback, ProgressCallback, ProgressInfo, TransferEvent};
pub use protocol::constants::*;

// Re-export connectivity types
// PHASE 2: Connectivity, ConnectivityManager, EstablishedConnection will be added back
#[cfg(feature = "connectivity")]
pub use connectivity::{
    Candidate, CandidatePair, ConnectionState, ConnectivityEvent, Transport, TransportStats,
    TransportType,
};

/// Protocol version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize logging system with custom configuration
///
/// # Arguments
/// * `level` - Log level (trace/debug/info/warn/error)
///
/// # Example
/// ```
/// SHARP3::init_logging("info");
/// ```
pub fn init_logging(level: &str) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"))
        // Reduce verbosity of some dependencies
        .add_directive("igd=warn".parse().unwrap())
        .add_directive("tokio=warn".parse().unwrap())
        .add_directive("runtime=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("reqwest=warn".parse().unwrap());

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .with_ansi(true),
        )
        .with(filter)
        .init();
}

/// Get detailed system information including network interfaces
///
/// # Returns
/// A formatted string containing system and network information
pub fn system_info() -> String {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu_brand = sys
        .cpus()
        .first()
        .map(|cpu| cpu.brand())
        .unwrap_or("Unknown");

    let mut info = format!(
        "SHARP-256 Protocol v{}\n\
         ════════════════════════════════════════\n\
         OS: {} {}\n\
         CPU: {} ({} cores)\n\
         Memory: {:.2} GB available / {:.2} GB total",
        VERSION,
        System::name().unwrap_or_else(|| "Unknown".to_string()),
        System::os_version().unwrap_or_else(|| "Unknown".to_string()),
        cpu_brand,
        sys.cpus().len(),
        sys.available_memory() as f64 / 1024.0 / 1024.0 / 1024.0,
        sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0
    );

    // Add connectivity features information
    #[cfg(feature = "connectivity")]
    {
        info.push_str("\n\nConnectivity Features:");

        #[cfg(feature = "webrtc-ice-stack")]
        info.push_str("\n  ✓ WebRTC ICE support");

        #[cfg(feature = "libp2p-fallback")]
        info.push_str("\n  ✓ libp2p fallback");

        #[cfg(feature = "relay-encryption")]
        info.push_str("\n  ✓ Relay header encryption");

        #[cfg(feature = "nat-router-pools")]
        info.push_str("\n  ✓ NAT router pools");

        #[cfg(feature = "upnp-support")]
        info.push_str("\n  ✓ UPnP support");
    }

    #[cfg(not(feature = "connectivity"))]
    {
        info.push_str("\n\nConnectivity: Direct connections only");
    }

    info.push_str("\n════════════════════════════════════════");
    info
}

// OLD SENDER/RECEIVER BUILDERS REMOVED
// These will be replaced with new transport layer API after Phase 1 cleanup

/// Check if the current build has connectivity support
pub const fn has_connectivity() -> bool {
    cfg!(feature = "connectivity")
}

/// Check if the current build has GUI support
pub const fn has_gui() -> bool {
    cfg!(feature = "gui")
}

/// Check if the current build has TLS support
pub const fn has_tls() -> bool {
    cfg!(feature = "tls")
}

/// Get connectivity configuration for production use
#[cfg(feature = "connectivity")]
pub fn default_connectivity_config() -> connectivity::config::ConnectivityConfig {
    connectivity::config::ConnectivityConfig::default()
}

/// Get connectivity configuration optimized for production
#[cfg(feature = "connectivity")]
pub fn production_connectivity_config() -> connectivity::config::ConnectivityConfig {
    connectivity::config::ConnectivityConfig::for_production()
}

/// Get connectivity configuration optimized for symmetric NAT
#[cfg(feature = "connectivity")]
pub fn symmetric_nat_connectivity_config() -> connectivity::config::ConnectivityConfig {
    let mut config = connectivity::config::ConnectivityConfig::for_production();
    config.optimize_for_symmetric_nat();
    config
}

/// Connectivity utilities
/* PHASE 2: connectivity_utils will be rebuilt when Connectivity is available
#[cfg(feature = "connectivity")]
pub mod connectivity_utils {
    use super::connectivity::*;
    use std::net::SocketAddr;

    /// Create connectivity with automatic configuration
    pub async fn create_auto_connectivity() -> anyhow::Result<Connectivity> {
        let config = super::default_connectivity_config();
        Connectivity::with_config(config).await
    }

    /// Create connectivity for symmetric NAT scenarios
    pub async fn create_symmetric_nat_connectivity() -> anyhow::Result<Connectivity> {
        let config = super::symmetric_nat_connectivity_config();
        Connectivity::with_config(config).await
    }

    /// Quick connectivity test between two addresses
    pub async fn quick_connectivity_test(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<bool> {
        use tokio::net::UdpSocket;
        use std::sync::Arc;
        use std::time::Duration;

        let socket = Arc::new(UdpSocket::bind(local_addr).await?);
        let connectivity = create_auto_connectivity().await?;

        match tokio::time::timeout(
            Duration::from_secs(10),
            connectivity.establish_connection(socket, Some(remote_addr), true)
        ).await {
            Ok(Ok(_)) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Get best connectable address for this host
    pub async fn get_best_connectable_address() -> anyhow::Result<SocketAddr> {
        let connectivity = create_auto_connectivity().await?;
        connectivity.get_connectable_address().await
    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
        assert!(VERSION.chars().next().unwrap().is_ascii_digit());
    }

    #[test]
    fn test_system_info() {
        let info = system_info();
        assert!(info.contains("SHARP-256 Protocol"));
        assert!(info.contains("CPU:"));
        assert!(info.contains("Memory:"));
    }

    #[test]
    fn test_feature_detection() {
        // These should compile regardless of features
        let _ = has_connectivity();
        let _ = has_gui();
        let _ = has_tls();
    }

    #[cfg(feature = "connectivity")]
    #[test]
    fn test_default_connectivity_config() {
        let config = default_connectivity_config();
        assert!(!config.ice.stun_servers.is_empty());
        assert!(config.general.connection_timeout.as_secs() > 0);
    }

    #[cfg(feature = "connectivity")]
    #[test]
    fn test_symmetric_nat_config() {
        let config = symmetric_nat_connectivity_config();
        // Verify config is optimized for symmetric NAT
        assert!(config.ice.aggressive_nomination);
    }

    #[cfg(feature = "connectivity")]
    #[tokio::test]
    async fn test_connectivity_creation() {
        let connectivity = connectivity_utils::create_auto_connectivity().await;
        assert!(connectivity.is_ok());
    }
}
