use anyhow::{Context, Result};
use clap::Parser;
use sharp256::crypto::{psk_from_passphrase, Identity};
use sharp256::progress::{format_bytes, format_rate, parse_rate, DirectoryInfo};
use sharp256::{init_logging, system_info, Sender, SenderConfig, TransferEvent};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about = "SHARP-256 file sender", long_about = None)]
struct Args {
    /// File or folder to send (omit to open the GUI, if built with it)
    file: Option<PathBuf>,

    /// Receiver as <ID>@<host>:<port> (the receiver prints it at startup)
    receiver: Option<String>,

    /// Local bind address
    #[arg(short, long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,

    /// Accepted for compatibility; the sender needs no NAT handling
    #[arg(long, hide = true)]
    no_nat: bool,

    /// Largest chunk of file bytes per packet (probed downwards if the path
    /// cannot carry it). Default fits a 1500-byte MTU.
    #[arg(long)]
    chunk_size: Option<u16>,

    /// Skip path-MTU probing and use the chunk size as configured
    #[arg(long)]
    no_probe: bool,

    /// Cap the send rate, e.g. 50M, 800K, 1G (bits per second)
    #[arg(long)]
    max_rate: Option<String>,

    /// Shared secret the receiver also uses (or set SHARP256_SECRET)
    #[arg(long, env = "SHARP256_SECRET", hide_env_values = true)]
    secret: Option<String>,

    /// Identity key file (default: per-user data directory)
    #[arg(long)]
    identity: Option<PathBuf>,

    /// Print this machine's SHARP ID and exit
    #[arg(long)]
    id: bool,

    /// Directory for resume state (default: per-user data directory)
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "warn")]
    log_level: String,

    /// Run without GUI
    #[arg(long)]
    headless: bool,
}

fn load_identity(path: &Option<PathBuf>) -> Result<Identity> {
    let path = match path {
        Some(p) => p.clone(),
        None => Identity::default_path().context("no per-user data directory")?,
    };
    Identity::load_or_create(&path).with_context(|| format!("identity {}", path.display()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log_level);

    if args.id {
        println!("{}", load_identity(&args.identity)?.id());
        return Ok(());
    }
    match (&args.file, &args.receiver) {
        (Some(file), Some(receiver)) => run_headless(&args, file.clone(), receiver.clone()).await,
        _ if args.headless => {
            anyhow::bail!("headless mode needs both <FILE|FOLDER> and <RECEIVER>")
        }
        _ => {
            #[cfg(feature = "gui")]
            {
                sharp256::gui::run_sender_gui(args.file.clone(), args.receiver.clone())
            }
            #[cfg(not(feature = "gui"))]
            {
                anyhow::bail!("usage: sharp-sender <FILE|FOLDER> <ID>@<HOST>:<PORT>")
            }
        }
    }
}

async fn run_headless(args: &Args, file: PathBuf, receiver: String) -> Result<()> {
    if !file.exists() {
        anyhow::bail!("no such file or folder: {}", file.display());
    }
    let (receiver_id, hosts) =
        sharp256::address::parse_peer(&receiver).map_err(|e| anyhow::anyhow!(e))?;
    // A receiver may publish several addresses, and each name may have
    // several of its own. Try them all and let the handshake decide which
    // one is the receiver.
    let addrs = sharp256::address::resolve_candidates(&hosts)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let addr = addrs[0];
    let identity = load_identity(&args.identity)?;
    let sender_id = identity.id();
    println!("{}", system_info());

    let mut cfg = SenderConfig::new(addr, receiver_id, file.clone());
    cfg.alternate_peers = addrs[1..].to_vec();
    cfg.bind = args.bind;
    let _ = args.no_nat;
    cfg.state_dir = args.state_dir.clone();
    cfg.identity = Some(identity);
    if let Some(secret) = &args.secret {
        cfg.psk = Some(psk_from_passphrase(secret, &receiver_id));
    }
    if let Some(c) = args.chunk_size {
        cfg.transport.max_chunk = c;
    }
    cfg.transport.probe_mtu = !args.no_probe;
    if let Some(r) = &args.max_rate {
        let bps = parse_rate(r).map_err(|e| anyhow::anyhow!(e))?;
        cfg.transport.max_rate_bytes = Some(bps / 8);
        println!("Rate cap:  {}", format_rate(bps as f64));
    }

    let last_print = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    cfg.events = Some(Arc::new(move |ev: TransferEvent| match ev {
        TransferEvent::Started {
            peer,
            cipher,
            chunk_size,
            resumed_from,
            ..
        } => {
            println!(
                "Connected to {} (encrypted, {}; chunk {} B)",
                peer, cipher, chunk_size
            );
            if resumed_from > 0 {
                println!(
                    "Resuming: {} already at receiver",
                    format_bytes(resumed_from)
                );
            }
        }
        TransferEvent::Progress(s) => {
            let now_ms = started.elapsed().as_millis() as u64;
            if now_ms.saturating_sub(last_print.load(Ordering::Relaxed)) >= 1000 {
                last_print.store(now_ms, Ordering::Relaxed);
                let eta = s
                    .eta
                    .map(|d| format!("{}s", d.as_secs()))
                    .unwrap_or_else(|| "-".into());
                println!(
                    "{:5.1}%  {:>10}  {:>14}  rtt {:6.2} ms  cwnd {:>9}  retx {:>9}  eta {}{}",
                    s.fraction() * 100.0,
                    format_bytes(s.bytes_done),
                    format_rate(s.rate_bps),
                    s.rtt_ms,
                    format_bytes(s.cwnd_bytes),
                    format_bytes(s.retransmitted_bytes),
                    eta,
                    if s.stalled { "  [stalled]" } else { "" }
                );
            }
        }
        TransferEvent::Stalled { since, .. } => {
            println!("No answer from receiver for {:?}; waiting...", since);
        }
        TransferEvent::Recovered { .. } => println!("Receiver is back; continuing"),
        _ => {}
    }));

    let sender = Sender::new(cfg).await.context("cannot start sender")?;
    match sender.source().tree() {
        Some(tree) => {
            let m = tree.manifest();
            let contents = DirectoryInfo {
                files: m.files(),
                dirs: m.dirs(),
            };
            println!(
                "Folder:    {} ({}, {})",
                file.display(),
                contents.describe(),
                format_bytes(m.data_len())
            );
            if !tree.skipped().is_empty() {
                println!(
                    "Skipped:   {} symbolic link(s) or special file(s), which are not sent",
                    tree.skipped().len()
                );
            }
        }
        None => println!(
            "File:      {} ({})",
            file.display(),
            format_bytes(sender.source().size())
        ),
    }
    println!("Receiver:  {} ({})", addr, receiver_id);
    println!("Sender ID: {}", sender_id);
    let cancel = sender.cancel_token();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("\nCancelling...");
            cancel.cancel();
        }
    });

    match sender.run().await {
        Ok(summary) => {
            println!(
                "\nDone: {} in {:.2?} ({} avg), {} retransmitted, {} loss events, BLAKE3 {}",
                format_bytes(summary.file_size),
                summary.elapsed,
                format_rate(summary.avg_rate_bps),
                format_bytes(summary.retransmitted_bytes),
                summary.loss_events,
                summary.file_hash_hex
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("\nTransfer failed: {}", e);
            std::process::exit(1);
        }
    }
}
