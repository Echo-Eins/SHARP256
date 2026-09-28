//! SHARP-256 (Swift Hash Assurance Rust Protocol): reliable, BLAKE3-verified
//! file transfer over UDP with adaptive rate control and resumable sessions.

pub mod address;
pub mod config;
pub mod crypto;
pub mod file;
pub mod progress;
pub mod protocol;
pub mod state;
pub mod transport;

#[cfg(feature = "nat-traversal")]
pub mod nat;

#[cfg(feature = "gui")]
pub mod gui;

pub use config::{AcceptPolicy, IncomingRequest, ReceiverConfig, SenderConfig, TransportConfig};
pub use crypto::{Identity, SharpId};
pub use progress::{EventCallback, TransferEvent, TransferStats};
pub use transport::{Receiver, RecvError, SendError, Sender, TransferSummary};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialises `tracing` with the given default level (overridable by
/// `RUST_LOG`).
pub fn init_logging(level: &str) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .try_init();
}

/// Short description of the host, printed by the CLI tools.
pub fn system_info() -> String {
    format!(
        "SHARP-256 v{} (protocol v{}) on {} {} with {} CPU threads",
        VERSION,
        protocol::constants::PROTOCOL_VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    )
}
