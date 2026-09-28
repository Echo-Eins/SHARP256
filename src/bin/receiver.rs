use anyhow::{Context, Result};
use clap::Parser;
use sharp256::progress::{format_bytes, format_rate};
use sharp256::{init_logging, system_info, Receiver, ReceiverConfig, TransferEvent};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(author, version, about = "SHARP-256 file receiver", long_about = None)]
struct Args {
    /// Directory to store received files
    #[arg(short, long, default_value = "./received")]
    output: PathBuf,

    /// Listen address (IP:port)
    #[arg(short, long, default_value = "0.0.0.0:5555")]
    bind: SocketAddr,

    /// Disable NAT traversal (STUN / UPnP)
    #[arg(long)]
    no_nat: bool,

    /// Replace existing files with the same name instead of writing "name (1)"
    #[arg(long)]
    overwrite: bool,

    /// Maximum number of concurrent transfers
    #[arg(long, default_value_t = 16)]
    max_sessions: usize,

    /// Largest chunk of file bytes per packet this receiver accepts
    #[arg(long)]
    chunk_size: Option<u16>,

    /// Directory for resume state (default: per-user data directory)
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Run without GUI
    #[arg(long)]
    headless: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log_level);

    let mut cfg = ReceiverConfig::new(args.bind, args.output.clone());
    cfg.overwrite = args.overwrite;
    cfg.max_sessions = args.max_sessions.max(1);
    cfg.nat_traversal = !args.no_nat && cfg!(feature = "nat-traversal");
    cfg.state_dir = args.state_dir.clone();
    if let Some(c) = args.chunk_size {
        cfg.transport.max_chunk = c;
    }

    if !args.headless {
        #[cfg(feature = "gui")]
        {
            return sharp256::gui::run_receiver_gui(cfg);
        }
    }
    run_headless(cfg).await
}

async fn run_headless(mut cfg: ReceiverConfig) -> Result<()> {
    println!("{}", system_info());
    std::fs::create_dir_all(&cfg.output_dir)?;
    println!("Output:    {}", cfg.output_dir.canonicalize()?.display());
    println!("Listening: {}", cfg.bind);
    println!("Press Ctrl-C to stop.\n");

    cfg.events = Some(Arc::new(|ev: TransferEvent| match ev {
        TransferEvent::IncomingRequest {
            peer,
            file_name,
            file_size,
            resumed_bytes,
            ..
        } => {
            println!(
                "Incoming from {}: {} ({}){}",
                peer,
                file_name,
                format_bytes(file_size),
                if resumed_bytes > 0 {
                    format!(", resuming from {}", format_bytes(resumed_bytes))
                } else {
                    String::new()
                }
            );
        }
        TransferEvent::Completed {
            path,
            file_hash_hex,
            peer_confirmed,
            stats,
            ..
        } => {
            println!(
                "Received {} in {:.2?} ({} avg), BLAKE3 {}{}",
                path.unwrap_or_default(),
                stats.elapsed,
                format_rate(stats.avg_rate_bps),
                file_hash_hex,
                if peer_confirmed {
                    ""
                } else {
                    " (sender did not confirm)"
                }
            );
        }
        TransferEvent::Failed { error, .. } => println!("Transfer failed: {}", error),
        TransferEvent::Reachability { summary, .. } => println!("Network: {}", summary),
        TransferEvent::Stalled { since, .. } => {
            println!(
                "No packets from sender for {:?}; keeping state for resume",
                since
            )
        }
        _ => {}
    }));

    let receiver = Receiver::new(cfg).await.context("cannot start receiver")?;
    let cancel = receiver.cancel_token();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("\nShutting down...");
            cancel.cancel();
        }
    });
    receiver.run().await?;
    Ok(())
}
