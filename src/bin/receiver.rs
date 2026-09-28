use anyhow::{Context, Result};
use clap::Parser;
use sharp256::crypto::identity::load_id_list;
use sharp256::crypto::{psk_from_passphrase, Identity, SharpId};
use sharp256::progress::{format_bytes, format_rate};
use sharp256::{init_logging, system_info, Receiver, ReceiverConfig, TransferEvent};
use std::collections::HashSet;
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

    /// Accept transfers only from this sender ID (repeatable)
    #[arg(long = "allow", value_name = "ID")]
    allow: Vec<SharpId>,

    /// Accept transfers only from the sender IDs listed in this file
    #[arg(long, value_name = "FILE")]
    authorized_senders: Option<PathBuf>,

    /// Shared secret every sender must also use (or set SHARP256_SECRET)
    #[arg(long, env = "SHARP256_SECRET", hide_env_values = true)]
    secret: Option<String>,

    /// Identity key file (default: per-user data directory)
    #[arg(long)]
    identity: Option<PathBuf>,

    /// Print this receiver's SHARP ID and exit
    #[arg(long)]
    id: bool,

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

    let identity_path = match &args.identity {
        Some(p) => p.clone(),
        None => Identity::default_path().context("no per-user data directory")?,
    };
    let identity = Identity::load_or_create(&identity_path)
        .with_context(|| format!("identity {}", identity_path.display()))?;
    if args.id {
        println!("{}", identity.id());
        return Ok(());
    }

    let mut cfg = ReceiverConfig::new(args.bind, args.output.clone());
    cfg.overwrite = args.overwrite;
    cfg.max_sessions = args.max_sessions.max(1);
    cfg.nat_traversal = !args.no_nat && cfg!(feature = "nat-traversal");
    cfg.state_dir = args.state_dir.clone();
    if let Some(c) = args.chunk_size {
        cfg.transport.max_chunk = c;
    }
    if let Some(secret) = &args.secret {
        cfg.psk = Some(psk_from_passphrase(secret, &identity.id()));
    }
    let mut allowed: HashSet<SharpId> = args.allow.iter().copied().collect();
    if let Some(path) = &args.authorized_senders {
        allowed.extend(load_id_list(path).with_context(|| format!("{}", path.display()))?);
    }
    if !allowed.is_empty() || args.authorized_senders.is_some() {
        cfg.allowed_senders = Some(allowed);
    }
    cfg.identity = Some(identity);

    if !args.headless {
        #[cfg(feature = "gui")]
        {
            return sharp256::gui::run_receiver_gui(cfg);
        }
    }
    run_headless(cfg).await
}

async fn run_headless(mut cfg: ReceiverConfig) -> Result<()> {
    let id = cfg.identity.as_ref().map(|i| i.id()).expect("identity set");
    println!("{}", system_info());
    std::fs::create_dir_all(&cfg.output_dir)?;
    println!("Output:      {}", cfg.output_dir.canonicalize()?.display());
    println!("Listening:   {}", cfg.bind);
    println!("Receiver ID: {}", id);
    println!("Senders use: {}@<this host>:{}", id, cfg.bind.port());
    match &cfg.allowed_senders {
        Some(list) => println!("Accepting:   {} allowed sender(s) only", list.len()),
        None => {
            println!("Accepting:   any sender that knows the receiver ID (restrict with --allow)")
        }
    }
    if cfg.psk.is_some() {
        println!("Secret:      required");
    }
    println!("Press Ctrl-C to stop.\n");

    cfg.events = Some(Arc::new(move |ev: TransferEvent| match ev {
        TransferEvent::IncomingRequest {
            peer,
            sender_id,
            file_name,
            file_size,
            directory,
            resumed_bytes,
            ..
        } => {
            let what = match directory {
                Some(d) => format!(
                    "folder {} ({}, {})",
                    file_name,
                    d.describe(),
                    format_bytes(file_size)
                ),
                None => format!("{} ({})", file_name, format_bytes(file_size)),
            };
            println!(
                "Incoming from {} ({}): {}{}",
                peer,
                sender_id,
                what,
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
        TransferEvent::Reachability {
            summary,
            advertised,
        } => {
            println!("Network: {}", summary);
            if let Some(addr) = advertised {
                println!("From outside, senders use: {}@{}", id, addr);
            }
        }
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
