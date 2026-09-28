//! `sharp-relay` — the meeting point for peers that cannot reach each other.
//!
//! Run it on a host both ends can reach. It introduces a sender and a
//! receiver to each other and, when that is not enough, copies datagrams
//! between them.
//!
//! It is not trusted with anything and does not need to be. Transfers are
//! sealed end to end, so it cannot read them, cannot alter one without the
//! receiving end rejecting it, and cannot impersonate a peer, because
//! completing a SHARP-256 handshake takes that peer's private key. It holds
//! no keys, keeps nothing on disk, and decides nothing about who may send to
//! whom — a receiver admits or refuses a sender on the strength of its
//! identity, over a relay exactly as it would directly.

use anyhow::{Context, Result};
use clap::Parser;
use sharp256::relay::server::{Config, Relay};
use std::net::SocketAddr;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(
    name = "sharp-relay",
    about = "Introduces SHARP-256 peers to each other, and carries them when they cannot meet",
    version
)]
struct Args {
    /// Address to listen on.
    #[arg(short, long, default_value = "0.0.0.0:5560")]
    bind: SocketAddr,

    /// Identities that may be registered at once.
    #[arg(long, default_value_t = 4096)]
    max_registrations: usize,

    /// Pairs that may be carried at once. Each one costs a UDP port and
    /// whatever bandwidth the transfer uses.
    #[arg(long, default_value_t = 256)]
    max_pairs: usize,

    /// Requests per second accepted from one address.
    #[arg(long, default_value_t = 10.0)]
    rate: f64,

    /// Seconds a registration lives without a keepalive.
    #[arg(long, default_value_t = 120)]
    lease: u64,

    /// Seconds a carried pair survives with nothing flowing through it.
    #[arg(long, default_value_t = 60)]
    idle: u64,

    /// Log level (error, warn, info, debug, trace).
    #[arg(long, default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    sharp256::init_logging(&args.log);

    let cfg = Config {
        bind: args.bind,
        max_registrations: args.max_registrations,
        max_allocations: args.max_pairs,
        rate: args.rate,
        burst: (args.rate * 2.0).max(2.0),
        lease: Duration::from_secs(args.lease.clamp(10, 3600)),
        idle: Duration::from_secs(args.idle.clamp(5, 3600)),
    };

    let cancel = CancellationToken::new();
    let relay = Relay::bind(cfg, cancel.clone())
        .await
        .with_context(|| format!("cannot listen on {}", args.bind))?;
    let addr = relay.local_addr()?;
    println!("{}", sharp256::system_info());
    println!("Relay listening on {}", addr);
    println!("Receivers: --relay {}", addr);
    println!("Senders:   --relay {}", addr);

    let stopper = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("\nShutting down...");
            stopper.cancel();
        }
    });
    relay.run().await?;
    Ok(())
}
