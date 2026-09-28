use anyhow::{Context, Result};
use clap::Parser;
use sharp256::progress::{format_bytes, format_rate, parse_rate};
use sharp256::{init_logging, system_info, Sender, SenderConfig, TransferEvent};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about = "SHARP-256 file sender", long_about = None)]
struct Args {
    /// File to send (omit to open the GUI, if built with it)
    file: Option<PathBuf>,

    /// Receiver address (IP:port)
    receiver: Option<SocketAddr>,

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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log_level);

    match (&args.file, args.receiver) {
        (Some(file), Some(receiver)) => run_headless(&args, file.clone(), receiver).await,
        _ if args.headless => {
            anyhow::bail!("headless mode needs both <FILE> and <RECEIVER>")
        }
        _ => {
            #[cfg(feature = "gui")]
            {
                sharp256::gui::run_sender_gui(args.file.clone(), args.receiver)
            }
            #[cfg(not(feature = "gui"))]
            {
                anyhow::bail!("usage: sharp-sender <FILE> <RECEIVER_IP:PORT>")
            }
        }
    }
}

async fn run_headless(args: &Args, file: PathBuf, receiver: SocketAddr) -> Result<()> {
    if !file.is_file() {
        anyhow::bail!("not a file: {}", file.display());
    }
    let size = std::fs::metadata(&file)?.len();
    println!("{}", system_info());
    println!("File:      {} ({})", file.display(), format_bytes(size));
    println!("Receiver:  {}", receiver);

    let mut cfg = SenderConfig::new(receiver, file);
    cfg.bind = args.bind;
    let _ = args.no_nat;
    cfg.state_dir = args.state_dir.clone();
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
            chunk_size,
            resumed_from,
            ..
        } => {
            println!("Connected to {} (chunk {} B)", peer, chunk_size);
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
