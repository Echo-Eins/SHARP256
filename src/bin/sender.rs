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

    /// Local bind address. The default, [::]:0, speaks IPv6 and IPv4
    /// alike through one dual-stack socket, and falls back to IPv4 where
    /// the system has no IPv6
    #[arg(short, long, default_value = "[::]:0")]
    bind: SocketAddr,

    /// Do not find out what this host's NAT does. With a relay the sender
    /// asks STUN servers (see --stun) how its NAT numbers ports, so that
    /// the receiver can aim its punches; this switches that off
    #[arg(long)]
    no_nat: bool,

    /// A STUN server (host:port) for that; repeat it for several. A
    /// `sharp-relay --stun` is one, and only a server with two addresses
    /// can measure everything a NAT does. Default: well-known public ones.
    #[arg(long = "stun", value_name = "HOST:PORT")]
    stun: Vec<String>,

    /// A TURN server, USER:PASSWORD@HOST[:PORT] (RFC 8656): this sender
    /// gets an address on it, which goes on the card the sender prints for
    /// the receiver's user, and reaches the receiver through it as well as
    /// directly. Only TURN over UDP is spoken. Everything through it is
    /// sealed end to end, and costs the server's owner the bandwidth. A
    /// colon in a user name is written %3A. Repeat it for several, or set
    /// SHARP256_TURN (servers separated by spaces), which keeps the password
    /// off the command line
    #[arg(
        long = "turn",
        value_name = "USER:PASSWORD@HOST[:PORT]",
        env = "SHARP256_TURN",
        hide_env_values = true,
        value_delimiter = ' ',
        value_parser = sharp256::crypto::secret::secret_text
    )]
    turn: Vec<sharp256::crypto::secret::SecretText>,

    /// Look for the receiver in the Mainline DHT (the one BitTorrent uses),
    /// which it has to be announced in too (sharp-receiver --dht), so that
    /// <RECEIVER> may be its ID alone. Every DHT node asked learns this
    /// host's address, and without --secret anybody who knows the receiver's
    /// ID can see that a sender is looking for it. Needs the NAT tests (no
    /// --no-nat)
    #[arg(long)]
    dht: bool,

    /// A DHT node (host:port) to start from instead of the well-known ones;
    /// repeat it for several
    #[arg(long = "dht-bootstrap", value_name = "HOST:PORT")]
    dht_bootstrap: Vec<String>,

    /// Find out how the internet sees this sender (STUN, and a port forward
    /// from the router) and print its contact card and addresses, for the
    /// receiver's user to paste into the running sharp-receiver: a receiver
    /// given by address is told nothing of this side otherwise. The sender
    /// then also punches at the receiver's addresses, and waits for it as
    /// long as with a card. With the receiver's own card, --turn or --dht the
    /// card is printed anyway
    #[arg(long, conflicts_with = "no_nat")]
    card: bool,

    /// Look for the receiver on the local network with multicast DNS: it
    /// has to be started with --announce-lan, and <RECEIVER> may then be its
    /// ID alone. The question tells everybody on the network whom you are
    /// looking for, which is why it is only asked when you ask it
    #[arg(long)]
    lan: bool,

    /// Ask a relay at [<relay ID>@]<host>:<port> to put this transfer
    /// through when the receiver's own addresses do not answer. May be
    /// repeated. Only a relay that puts through just the senders it lists
    /// needs its ID written in front: the sender then proves who it is when
    /// the relay asks — in the clear, as all of a relay's messages are.
    /// Without the ID the sender never names itself.
    #[arg(long = "relay", value_name = "[ID@]HOST:PORT")]
    relays: Vec<String>,

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
    #[arg(long, env = "SHARP256_SECRET", hide_env_values = true, value_parser = sharp256::crypto::secret::secret_text)]
    secret: Option<sharp256::crypto::secret::SecretText>,

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
    // A contact card (shc1-…) instead of an address: everything the
    // receiver's program knows about how to reach it.
    let looks_like_card = receiver
        .trim_start()
        .get(..4)
        .is_some_and(|head| head.eq_ignore_ascii_case("shc1"));
    #[cfg(feature = "nat-traversal")]
    let card = if looks_like_card {
        let card = sharp256::nat::card::Card::from_arg(&receiver)
            .map_err(|e| anyhow::anyhow!("the receiver's card: {}", e))?;
        if card.role != sharp256::nat::card::Role::Receiver {
            anyhow::bail!("that is a sender's card; give the sender the receiver's card instead");
        }
        if let Some(why) = card.staleness() {
            eprintln!("Warning: {}", why);
        }
        Some(card)
    } else {
        None
    };
    #[cfg(feature = "nat-traversal")]
    let card_id = card.as_ref().map(|c| c.id);
    #[cfg(not(feature = "nat-traversal"))]
    let card_id: Option<sharp256::SharpId> = if looks_like_card {
        anyhow::bail!("this build has no NAT traversal, so it cannot read contact cards")
    } else {
        None
    };
    let (receiver_id, hosts) = match card_id {
        Some(id) => (id, Vec::new()),
        None => sharp256::address::parse_peer(&receiver).map_err(|e| anyhow::anyhow!(e))?,
    };
    // A receiver reached only through a relay publishes no address.
    if card_id.is_none() && hosts.is_empty() && args.relays.is_empty() && !args.lan && !args.dht {
        anyhow::bail!(
            "{} has no address: write it as <ID>@<host>:<port>, or name the relay it \
             registered with using --relay, or ask the local network (--lan) or the \
             DHT (--dht)",
            receiver
        );
    }
    let identity = load_identity(&args.identity)?;
    let sender_id = identity.id();
    println!("{}", system_info());

    // A receiver may publish several addresses, and each name may have
    // several of its own. The sender tries them all — names resolved while
    // the literal addresses are already being tried — and the handshake
    // decides which one is the receiver.
    #[cfg(feature = "nat-traversal")]
    let mut cfg = match card {
        Some(card) => SenderConfig::for_card(card, file.clone()),
        None => SenderConfig::for_hosts(&hosts, receiver_id, file.clone()),
    };
    #[cfg(not(feature = "nat-traversal"))]
    let mut cfg = SenderConfig::for_hosts(&hosts, receiver_id, file.clone());
    cfg.bind = args.bind;
    cfg.nat_traversal = !args.no_nat && cfg!(feature = "nat-traversal");
    cfg.find_lan = args.lan && cfg!(feature = "nat-traversal");
    #[cfg(not(feature = "nat-traversal"))]
    if args.card {
        anyhow::bail!("--card needs a build with the nat-traversal feature");
    }
    cfg.give_card = args.card;
    #[cfg(feature = "nat-traversal")]
    for t in &args.turn {
        t.as_str()
            .parse::<sharp256::nat::turn::Server>()
            .map_err(|e| anyhow::anyhow!("--turn: {}", e))?;
    }
    #[cfg(not(feature = "nat-traversal"))]
    if !args.turn.is_empty() {
        anyhow::bail!("--turn needs a build with the nat-traversal feature");
    }
    cfg.turn_servers = args.turn.iter().map(|t| t.to_string()).collect();
    cfg.dht = args.dht && cfg!(feature = "nat-traversal");
    cfg.dht_bootstrap = args.dht_bootstrap.clone();
    #[cfg(feature = "nat-traversal")]
    if cfg.dht || cfg.give_card {
        // The receiver may take a while to turn up in the DHT, or its user to
        // be handed this sender's addresses and paste them in.
        cfg.transport.handshake_timeout = sharp256::nat::punch::MEET_DURATION;
    }
    cfg.stun_servers = args.stun.clone();
    cfg.relays.extend(args.relays.iter().cloned());
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

    let last_card: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
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
        TransferEvent::ContactCard { card, summary } => {
            // Said again only when it changes: the tests report more than
            // once as they find things out.
            let mut last = last_card.lock().unwrap_or_else(|e| e.into_inner());
            if last.as_deref() != Some(card.as_str()) {
                println!("Network:   {}", summary);
                println!("Your card: {}", card);
                println!(
                    "           (paste it into the running receiver, or start the receiver \
                     with --peer-card <card>)"
                );
                // Where the outside sees this host, for a receiver whose user
                // would rather type an address than a card.
                #[cfg(feature = "nat-traversal")]
                {
                    let addresses = sharp256::nat::card::Card::from_text(&card)
                        .map(|c| c.outside_addrs())
                        .unwrap_or_default();
                    if !addresses.is_empty() {
                        let list: Vec<String> = addresses.iter().map(|a| a.to_string()).collect();
                        println!("Addresses: {}", list.join("  "));
                        println!(
                            "           (or just these: paste them into the running receiver, \
                             or start it with --peer-addr <address>)"
                        );
                    }
                }
                *last = Some(card);
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
    if hosts.is_empty() {
        println!("Receiver:  {} (through the relays)", receiver_id);
    } else {
        println!("Receiver:  {} ({})", hosts.join(", "), receiver_id);
    }
    println!("Local:     {}", sender.local_addr()?);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The arguments derive Debug; the passphrase and a TURN server's
    /// password are in them, and are not what it prints.
    #[test]
    fn secrets_given_as_arguments_are_not_printed() {
        let args = Args::parse_from([
            "sharp-sender",
            "--secret",
            "correct horse battery staple",
            "--turn",
            "alice:hunter2hunter2@turn.example.org",
        ]);
        let shown = format!("{:?}", args);
        assert!(!shown.contains("horse"), "{}", shown);
        assert!(!shown.contains("hunter2"), "{}", shown);
        assert_eq!(args.secret.as_deref(), Some("correct horse battery staple"));
    }
}
