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

    /// Listen address (IP:port). The default, [::]:5555, takes IPv6 and
    /// IPv4 alike on one dual-stack socket, and falls back to IPv4 where
    /// the system has no IPv6
    #[arg(short, long, default_value = "[::]:5555")]
    bind: SocketAddr,

    /// Disable NAT traversal (address discovery, NAT behaviour tests, port
    /// forwarding)
    #[arg(long)]
    no_nat: bool,

    /// Register with a relay, written as <relay ID>@<host>:<port>, so that
    /// senders which cannot reach this receiver directly can still be put
    /// through. May be repeated. The relay's identity is needed because
    /// registering means proving ownership of this receiver's identity
    /// against it — without that, anyone who knew the published ID could
    /// register it there instead. The relay is trusted with nothing else:
    /// transfers stay sealed end to end and senders are still admitted by
    /// their identity.
    #[arg(long = "relay", value_name = "ID@HOST:PORT")]
    relays: Vec<String>,

    /// Ask the relays not to tell senders this receiver's address, so that
    /// everything goes through the relay. It costs the relay's bandwidth
    /// and gives up the direct path, and it is the only arrangement in
    /// which a relay actually hides where you are.
    #[arg(long)]
    relay_private: bool,

    /// Do not publish this host's addresses on the local network (private
    /// IPv4, unique-local IPv6), only those the internet routes. Senders on
    /// the same network then come in through the router, or not at all;
    /// in exchange, whoever is given the receiver's address learns nothing
    /// about how that network is laid out.
    #[arg(long)]
    no_lan_addresses: bool,

    /// Seconds between the packets that keep this receiver's NAT mapping
    /// alive while it waits (RFC 8445 suggests 15). It sends less often
    /// once it has measured that the NAT keeps mappings longer, and more
    /// often when it sees one lapse.
    #[arg(long, value_name = "SECONDS", default_value_t = 15)]
    keepalive: u64,

    /// A STUN server (host:port) that tells this receiver how it is seen
    /// from outside; repeat it for several. A `sharp-relay --stun` is one,
    /// and only a server with two addresses can measure everything a NAT
    /// does. Default: well-known public ones.
    #[arg(long = "stun", value_name = "HOST:PORT")]
    stun: Vec<String>,

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
    cfg.relays = args.relays.clone();
    cfg.relay_private = args.relay_private;
    cfg.publish_lan_addresses = !args.no_lan_addresses;
    cfg.nat_keepalive = std::time::Duration::from_secs(args.keepalive.clamp(1, 3600));
    cfg.stun_servers = args.stun.clone();
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
    println!("Receiver ID: {}", id);
    if cfg.relay_private && cfg.relays.is_empty() {
        println!("Warning:     --relay-private does nothing without --relay");
    }
    println!("Senders use: {}", cfg.contact_hint(&id));
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
            address,
        } => {
            println!("Network: {}", summary);
            // Every address a sender might reach us at, best first: the
            // sender tries each in turn and the handshake decides.
            if let Some(full) = address {
                println!("Senders use: {}", full);
            } else if let Some(addr) = advertised {
                println!("From outside, senders use: {}@{}", id, addr);
            }
        }
        TransferEvent::RelayRegistered { relay, private, .. } => {
            // The relay, not where it sees us: that is our mapping towards
            // it, and nobody else would arrive at it.
            println!(
                "Relay:       registered with {}{}; senders can add --relay {}",
                relay,
                if private {
                    " (it will not tell senders where we are)"
                } else {
                    ""
                },
                relay
            );
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
    // What was actually bound: `[::]` falls back to IPv4 where the system
    // has no IPv6.
    println!("Listening:   {}", receiver.local_addr()?);
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
