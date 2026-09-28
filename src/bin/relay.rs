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
use sharp256::crypto::identity::load_id_list;
use sharp256::crypto::{Identity, SharpId};
use sharp256::progress::{format_bytes, format_rate, parse_bytes, parse_rate};
use sharp256::relay::server::Quotas;
use sharp256::relay::server::{Config, Relay};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(
    name = "sharp-relay",
    about = "Introduces SHARP-256 peers to each other, and carries them when they cannot meet",
    version
)]
struct Args {
    /// Address to listen on. The default, [::]:5560, serves IPv6 and IPv4
    /// alike on one dual-stack socket — and carries pairs across the two —
    /// falling back to IPv4 where the system has no IPv6.
    #[arg(short, long, default_value = "[::]:5560")]
    bind: SocketAddr,

    /// Identities that may be registered at once.
    #[arg(long, default_value_t = 4096)]
    max_registrations: usize,

    /// Pairs that may be carried at once. Each one costs a UDP port and
    /// whatever bandwidth the transfer uses.
    #[arg(long, default_value_t = 256)]
    max_pairs: usize,

    /// Registrations one client may hold. A client is an IPv4 address or
    /// an IPv6 /64; raise this where many receivers share one address
    /// behind a carrier-grade NAT.
    #[arg(long, default_value_t = 128)]
    registrations_per_client: usize,

    /// Pairs one client may have carried at once.
    #[arg(long, default_value_t = 16)]
    pairs_per_client: usize,

    /// Requests per second accepted from one client.
    #[arg(long, default_value_t = 10.0)]
    rate: f64,

    /// Seconds a registration lives without a keepalive.
    #[arg(long, default_value_t = 120)]
    lease: u64,

    /// Seconds a carried pair survives with nothing flowing through it.
    #[arg(long, default_value_t = 60)]
    idle: u64,

    /// Let only this receiver register (repeatable). Without any, every
    /// receiver that proves its identity may make this relay its
    /// rendezvous and have its transfers carried on this host's bandwidth.
    #[arg(long = "allow-receiver", value_name = "ID")]
    allow_receivers: Vec<SharpId>,

    /// Let only the receivers listed in this file register (one ID per
    /// line; # starts a comment).
    #[arg(long, value_name = "FILE")]
    allowed_receivers: Option<PathBuf>,

    /// Put through only this sender (repeatable). A sender then has to
    /// prove who it is, which it does when given the relay as
    /// <relay ID>@<host>:<port>.
    #[arg(long = "allow-sender", value_name = "ID")]
    allow_senders: Vec<SharpId>,

    /// Put through only the senders listed in this file.
    #[arg(long, value_name = "FILE")]
    allowed_senders: Option<PathBuf>,

    /// Most one client (an IPv4 address or an IPv6 /64) may have carried,
    /// in bits per second, e.g. 100M; 0 for no limit.
    #[arg(long, value_name = "RATE", default_value = "100M")]
    client_rate: String,

    /// Most one client may have carried per hour, e.g. 20G; 0 for no limit.
    #[arg(long, value_name = "BYTES", default_value = "0")]
    client_quota: String,

    /// Most everybody together may have carried, in bits per second, e.g.
    /// 900M for a gigabit uplink; 0 for no limit.
    #[arg(long, value_name = "RATE", default_value = "0")]
    total_rate: String,

    /// Most one pair may carry in all before its port is closed, e.g. 50G;
    /// 0 for no limit.
    #[arg(long, value_name = "BYTES", default_value = "0")]
    pair_bytes: String,

    /// Identity file. A relay has a long-term key of its own, which is how
    /// a receiver registering here proves it owns the identity it claims:
    /// the two work out a shared secret from their keys alone. Created on
    /// first use if it does not exist.
    #[arg(long)]
    identity: Option<PathBuf>,

    /// Log level (error, warn, info, debug, trace).
    #[arg(long, default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    sharp256::init_logging(&args.log);

    let path = args
        .identity
        .clone()
        .or_else(|| Identity::default_path().map(|p| p.with_file_name("relay.key")))
        .context("no per-user data directory for the identity file")?;
    let identity = Identity::load_or_create(&path)
        .with_context(|| format!("cannot use identity file {}", path.display()))?;

    let rate = |s: &str| -> Result<u64> {
        if s.trim() == "0" {
            return Ok(0);
        }
        parse_rate(s)
            .map(|bps| bps / 8)
            .map_err(|e| anyhow::anyhow!(e))
    };
    let bytes = |s: &str| parse_bytes(s).map_err(|e| anyhow::anyhow!(e));
    let quotas = Quotas {
        client_rate: rate(&args.client_rate)?,
        client_hourly: bytes(&args.client_quota)?,
        total_rate: rate(&args.total_rate)?,
        pair_bytes: bytes(&args.pair_bytes)?,
    };
    let list = |ids: &[SharpId],
                file: &Option<PathBuf>|
     -> Result<Option<std::collections::HashSet<SharpId>>> {
        let mut set: std::collections::HashSet<SharpId> = ids.iter().copied().collect();
        if let Some(path) = file {
            set.extend(load_id_list(path).with_context(|| format!("{}", path.display()))?);
        }
        Ok((!set.is_empty() || file.is_some()).then_some(set))
    };
    let allowed_receivers = list(&args.allow_receivers, &args.allowed_receivers)?;
    let allowed_senders = list(&args.allow_senders, &args.allowed_senders)?;

    let cfg = Config {
        bind: args.bind,
        identity: identity.clone(),
        max_registrations: args.max_registrations,
        max_allocations: args.max_pairs,
        registrations_per_client: args.registrations_per_client.max(1),
        allocations_per_client: args.pairs_per_client.max(1),
        rate: args.rate,
        burst: (args.rate * 2.0).max(2.0),
        lease: Duration::from_secs(args.lease.clamp(10, 3600)),
        idle: Duration::from_secs(args.idle.clamp(5, 3600)),
        allowed_receivers: allowed_receivers.clone(),
        allowed_senders: allowed_senders.clone(),
        quotas,
    };

    let cancel = CancellationToken::new();
    let relay = Relay::bind(cfg, cancel.clone())
        .await
        .with_context(|| format!("cannot listen on {}", args.bind))?;
    let addr = relay.local_addr()?;
    println!("{}", sharp256::system_info());
    println!("Relay listening on {}", addr);
    // A receiver has to know which relay it is registering with; a sender
    // claims no identity of its own and so needs only the address. A
    // wildcard is no address anyone else can use.
    let public = if addr.ip().is_unspecified() {
        format!("<this host>:{}", addr.port())
    } else {
        addr.to_string()
    };
    println!("Receivers: --relay {}@{}", identity.id(), public);
    match &allowed_senders {
        None => println!("Senders:   --relay {}", public),
        Some(_) => println!("Senders:   --relay {}@{}", identity.id(), public),
    }
    match &allowed_receivers {
        Some(l) => println!("Serving:   {} listed receiver(s)", l.len()),
        None => println!(
            "Serving:   ANY receiver that proves its identity. Anyone may use this relay as \
             their rendezvous and have transfers carried on this host's bandwidth; limit it \
             with --allow-receiver or --allowed-receivers"
        ),
    }
    if let Some(l) = &allowed_senders {
        println!("Senders:   {} listed sender(s) only", l.len());
    }
    let show_rate = |b: u64| {
        if b == 0 {
            "no limit".to_string()
        } else {
            format_rate(b as f64 * 8.0)
        }
    };
    let show_bytes = |b: u64| {
        if b == 0 {
            "no limit".to_string()
        } else {
            format_bytes(b)
        }
    };
    println!(
        "Limits:    {} per client, {} per client per hour, {} in all, {} per pair",
        show_rate(quotas.client_rate),
        show_bytes(quotas.client_hourly),
        show_rate(quotas.total_rate),
        show_bytes(quotas.pair_bytes)
    );

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
