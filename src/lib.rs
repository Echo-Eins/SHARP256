pub mod protocol {
    pub mod constants;
    pub mod packet;
    pub mod ack;
}

pub mod buffer;
pub mod file;
pub mod sao;
pub mod state;
pub mod progress;
pub mod sender;
pub mod receiver;

// Fragmentation module with stub implementation
pub mod fragmentation;

// NAT traversal module with proper feature gating
#[cfg(feature = "nat-traversal")]
pub mod nat;

// GUI module
#[cfg(feature = "gui")]
pub mod gui;

// Re-export main types
pub use sender::Sender;
pub use receiver::Receiver;
pub use protocol::constants::*;

// Re-export fragmentation types
pub use fragmentation::{FragmentationInfo, check_fragmentation, detect_max_payload, handle_fragmentation_packet};

// Re-export NAT types when feature is enabled
#[cfg(feature = "nat-traversal")]
pub use nat::{NatManager, NatConfig, NetworkInfo, NatType, ConnectivityStatus};

/// Initialize logging system
pub fn init_logging(level: &str) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level))
        .add_directive("igd=warn".parse().unwrap()) // Reduce IGD verbosity
        .add_directive("tokio=warn".parse().unwrap())
        .add_directive("runtime=warn".parse().unwrap());

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
        )
        .with(filter)
        .init();
}

/// Protocol version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get detailed system information
pub fn system_info() -> String {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_all();

    let mut info = format!(
        "SHARP-256 Protocol v{}\n\
         OS: {} {}\n\
         CPU: {} cores\n\
         Memory: {} MB available",
        VERSION,
        System::name().unwrap_or_else(|| "Unknown".to_string()),
        System::os_version().unwrap_or_else(|| "Unknown".to_string()),
        sys.cpus().len(),
        sys.available_memory() / 1024 / 1024
    );

    // Add network interface information
    #[cfg(feature = "nat-traversal")]
    {
        use if_addrs::get_if_addrs;

        info.push_str("\n\nNetwork Interfaces:");
        if let Ok(interfaces) = get_if_addrs() {
            for iface in interfaces {
                if !iface.is_loopback() {
                    info.push_str(&format!("\n  {}: {}", iface.name, iface.ip()));
                }
            }
        }
    }

    info
}