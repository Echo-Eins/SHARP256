//! SHARP-256 (Swift Hash Assurance Rust Protocol): encrypted, mutually
//! authenticated, BLAKE3-verified transfer of files and directories over UDP,
//! with adaptive rate control, batched I/O for multi-gigabit links and
//! resumable sessions. The wire protocol is specified in `docs/PROTOCOL.md`.

pub mod address;
pub mod config;
pub mod crypto;
pub mod file;
pub mod progress;
pub mod protocol;
pub mod state;
mod sync;
pub mod transport;
#[cfg(test)]
mod vectors;

#[cfg(feature = "nat-traversal")]
pub mod nat;

#[cfg(feature = "nat-traversal")]
pub mod relay;

#[cfg(feature = "gui")]
pub mod gui;

/// Entry points for fuzzing; see `fuzz/`. Only in test and fuzzing builds.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod fuzz;

pub use config::{AcceptPolicy, IncomingRequest, ReceiverConfig, SenderConfig, TransportConfig};
pub use crypto::{Identity, SharpId};
pub use progress::{EventCallback, TransferEvent, TransferStats};
pub use transport::{Receiver, RecvError, SendError, Sender, TransferSummary};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialises `tracing` with the given default level (overridable by
/// `RUST_LOG`). Either is a level (`debug`) or a list of `target=level`
/// with an optional default (`sharp256::nat=trace,info`); one that does not
/// parse is passed over.
pub fn init_logging(level: &str) {
    use std::io::IsTerminal;
    use tracing_subscriber::{fmt, prelude::*};
    let filter = log_filter(std::env::var("RUST_LOG").ok().as_deref(), level);
    // Colours for a terminal only: a log kept in a file or sent through a
    // pipe — the way one is sent back from a field test — is read as text,
    // and escapes in it are noise. NO_COLOR (no-color.org) turns them off
    // anywhere.
    let ansi = std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let _ = tracing_subscriber::registry()
        .with(fmt::layer().with_ansi(ansi))
        .with(filter)
        .try_init();
}

/// What `init_logging` lets through: `RUST_LOG` if it parses, else `level`
/// if that does, else `info`.
fn log_filter(env: Option<&str>, level: &str) -> tracing_subscriber::filter::Targets {
    use tracing_subscriber::filter::Targets;
    env.and_then(|v| v.parse::<Targets>().ok())
        .or_else(|| level.parse().ok())
        .unwrap_or_else(|| Targets::new().with_default(tracing::Level::INFO))
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

#[cfg(test)]
mod tests {
    use tracing::Level;

    /// A level, or a list of `target=level` with a default; what does not
    /// parse is passed over, down to `info`.
    #[test]
    fn a_log_level_is_a_level_or_a_list_of_targets() {
        let f = super::log_filter(None, "debug");
        assert!(f.would_enable("sharp256::nat", &Level::DEBUG));
        assert!(!f.would_enable("sharp256::nat", &Level::TRACE));

        let f = super::log_filter(Some("sharp256::nat=trace,warn"), "debug");
        assert!(f.would_enable("sharp256::nat::punch", &Level::TRACE));
        assert!(f.would_enable("sharp256::transport", &Level::WARN));
        assert!(!f.would_enable("sharp256::transport", &Level::INFO));

        let f = super::log_filter(Some("sharp256=loudly"), "error");
        assert!(f.would_enable("sharp256", &Level::ERROR));
        assert!(!f.would_enable("sharp256", &Level::WARN));

        let f = super::log_filter(Some("sharp256=loudly"), "sharp256=loudly");
        assert!(f.would_enable("sharp256", &Level::INFO));
        assert!(!f.would_enable("sharp256", &Level::DEBUG));

        // A word that is no level names a target (as EnvFilter had it).
        let f = super::log_filter(None, "loud");
        assert!(f.would_enable("loud", &Level::TRACE));
        assert!(!f.would_enable("sharp256", &Level::ERROR));

        let f = super::log_filter(Some("off"), "debug");
        assert!(!f.would_enable("sharp256", &Level::ERROR));
    }
}
