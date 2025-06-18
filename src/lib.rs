//! SHARP-256 Protocol Library (lib.rs)
//!
//! High-performance file transfer protocol with BLAKE3 integrity verification
//! and comprehensive NAT traversal support.

#![warn(missing_docs)]
#![warn(clippy::all)]

// Core protocol modules
pub mod protocol;
pub mod buffer;
pub mod file;
pub mod sao;
pub mod state;
pub mod progress;
pub mod sender;
pub mod receiver;

// Fragmentation module with stub implementation
pub mod fragmentation;

// NAT traversal module (always compiled, feature controls functionality)
pub mod nat;

// GUI module (feature-gated)
#[cfg(feature = "gui")]
pub mod gui;

// Re-export main types
pub use sender::Sender;
pub use receiver::Receiver;
pub use protocol::constants::*;
pub use progress::{ProgressInfo, TransferEvent, ProgressCallback, EventCallback};

// Re-export fragmentation types
pub use fragmentation::{
    FragmentationInfo,
    check_fragmentation,
    detect_max_payload,
    handle_fragmentation_packet,
};

// Re-export NAT types
pub use nat::{
    NatManager,
    NatConfig,
    NetworkInfo,
    NatType,
    ConnectivityStatus,
    NatProtocol,
};

// Re-export error types
#[cfg(feature = "nat-traversal")]
pub use nat::error::{NatError, NatResult};

/// Protocol version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize logging system with custom configuration
///
/// # Arguments
/// * `level` - Log level (trace/debug/info/warn/error)
///
/// # Example
/// ```
///SHARP3::init_logging("info");
/// ```
///
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
                .with_ansi(true)
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

    let cpu_brand = sys.cpus()
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

    // Add network interface information
    #[cfg(feature = "nat-traversal")]
    {
        info.push_str("\n\nNetwork Interfaces:");
        if let Ok(interfaces) = if_addrs::get_if_addrs() {
            let mut displayed = false;

            for iface in interfaces {
                if !iface.is_loopback() {
                    let ip_version = match iface.ip() {
                        std::net::IpAddr::V4(_) => "IPv4",
                        std::net::IpAddr::V6(_) => "IPv6",
                    };

                    info.push_str(&format!(
                        "\n  {} ({}): {}",
                        iface.name,
                        ip_version,
                        iface.ip()
                    ));
                    displayed = true;
                }
            }
            if !displayed {
                info.push_str("\n  No active network interfaces found");
            }
        } else {
            info.push_str("\n  Failed to enumerate network interfaces");
        }
    }

    info.push_str("\n════════════════════════════════════════");
    info
}

/// Builder for creating a Sender with custom configuration
pub struct SenderBuilder {
    local_addr: std::net::SocketAddr,
    peer_addr: std::net::SocketAddr,
    file_path: std::path::PathBuf,
    use_encryption: bool,
    nat_config: Option<NatConfig>,
}

impl SenderBuilder {
    /// Create a new sender builder
    pub fn new(
        local_addr: impl Into<std::net::SocketAddr>,
        peer_addr: impl Into<std::net::SocketAddr>,
        file_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            local_addr: local_addr.into(),
            peer_addr: peer_addr.into(),
            file_path: file_path.into(),
            use_encryption: false,
            nat_config: None,
        }
    }

    /// Enable encryption
    pub fn with_encryption(mut self, enabled: bool) -> Self {
        self.use_encryption = enabled;
        self
    }

    /// Set custom NAT configuration
    #[cfg(feature = "nat-traversal")]
    pub fn with_nat_config(mut self, config: NatConfig) -> Self {
        self.nat_config = Some(config);
        self
    }

    /// Build the sender
    pub async fn build(self) -> anyhow::Result<Sender> {
        Sender::new(
            self.local_addr,
            self.peer_addr,
            &self.file_path,
            self.use_encryption,
        ).await
    }
}

/// Builder for creating a Receiver with custom configuration
pub struct ReceiverBuilder {
    local_addr: std::net::SocketAddr,
    output_dir: std::path::PathBuf,
    nat_config: Option<NatConfig>,
}

impl ReceiverBuilder {
    /// Create a new receiver builder
    pub fn new(
        local_addr: impl Into<std::net::SocketAddr>,
        output_dir: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            local_addr: local_addr.into(),
            output_dir: output_dir.into(),
            nat_config: None,
        }
    }

    /// Set custom NAT configuration
    #[cfg(feature = "nat-traversal")]
    pub fn with_nat_config(mut self, config: NatConfig) -> Self {
        self.nat_config = Some(config);
        self
    }

    /// Build the receiver
    pub async fn build(self) -> anyhow::Result<Receiver> {
        Receiver::new(self.local_addr, self.output_dir).await
    }
}

/// Check if the current build has NAT traversal support
pub const fn has_nat_traversal() -> bool {
    cfg!(feature = "nat-traversal")
}

/// Check if the current build has GUI support
pub const fn has_gui() -> bool {
    cfg!(feature = "gui")
}

/// Check if the current build has TLS support
pub const fn has_tls() -> bool {
    cfg!(feature = "tls")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_system_info() {
        let info = system_info();
        assert!(info.contains("SHARP-256"));
        assert!(info.contains("OS:"));
        assert!(info.contains("CPU:"));
    }

    #[test]
    fn test_feature_detection() {
        // These should compile regardless of features
        let _ = has_nat_traversal();
        let _ = has_gui();
        let _ = has_tls();
    }
}