//! `sharp-probe` — how does the internet see this host, and can a friend
//! reach it?
//!
//! Run it on the sending host and on the receiving host, on their own
//! networks. Each prints the address and port the NAT in front of it gives
//! out, what kind of NAT that is, whether the router would forward a port,
//! and a contact card. Swap the cards (or just the addresses) and give the
//! other side's to it, both at the same time: it sends at the other side's
//! addresses the way a transfer would and says whether a packet got through
//! — without a file being sent.

use anyhow::{Context, Result};
use clap::Parser;
use sharp256::crypto::{identity_file, Identity};
use sharp256::nat::card::{parse_peer_addr, parse_peer_addrs, Card, NatHints, Role};
use sharp256::nat::probe::{Options, Probe};
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "sharp-probe",
    about = "Finds out how the internet sees this host, and whether a peer can reach it",
    version
)]
struct Args {
    /// Local bind address. The default, [::]:0, measures both IPv4 and IPv6
    /// through one dual-stack socket
    #[arg(short, long, default_value = "[::]:0")]
    bind: SocketAddr,

    /// A STUN server (host:port); repeat it for several. A `sharp-relay
    /// --stun` is one, and only a server with a second address and port can
    /// measure everything a NAT does. Default: well-known public ones.
    #[arg(long = "stun", value_name = "HOST:PORT")]
    stun: Vec<String>,

    /// Do not ask the router for a port forward (PCP, NAT-PMP, UPnP)
    #[arg(long)]
    no_port_mapping: bool,

    /// A TURN server, USER:PASSWORD@HOST[:PORT] (RFC 8656), to ask for an
    /// address: it goes on the card, and is used in the test with a peer's
    /// card. The way to find out whether a server's credentials work and
    /// what it gives. Repeat it for several, or set SHARP256_TURN (servers
    /// separated by spaces)
    #[arg(
        long = "turn",
        value_name = "USER:PASSWORD@HOST[:PORT]",
        env = "SHARP256_TURN",
        hide_env_values = true,
        value_delimiter = ' ',
        value_parser = sharp256::crypto::secret::secret_text
    )]
    turn: Vec<sharp256::crypto::secret::SecretText>,

    /// The other side's contact card (shc1-…), or @FILE with one in it.
    /// Sends at its addresses for --wait seconds, listens for the other
    /// side doing the same, and reports whether a packet got through. Both
    /// sides run this at about the same time
    #[arg(long = "peer-card", value_name = "CARD|@FILE")]
    peer_card: Option<String>,

    /// The other side's address, IP:PORT (an IPv6 address in brackets), as
    /// its own test printed it — for when there is no card to hand over.
    /// The same test as with a card, but nothing is known of the NAT in
    /// front of the address, so every way of getting through is tried in
    /// turn. Several: repeat it, or separate them with commas
    #[arg(
        long = "peer-addr",
        value_name = "IP:PORT",
        value_parser = parse_peer_addr,
        value_delimiter = ','
    )]
    peer_addr: Vec<SocketAddr>,

    /// Seconds the test with the other side's card or addresses goes on for
    #[arg(long, default_value_t = 120)]
    wait: u64,

    /// Read the other side's card or addresses from standard input even when
    /// it is not a terminal (a terminal is always asked)
    #[arg(long)]
    stdin: bool,

    /// Make the card as a receiver's (default: a sender's)
    #[arg(long)]
    receiver: bool,

    /// Identity key file the card is made for (default: per-user data
    /// directory)
    #[arg(long)]
    identity: Option<PathBuf>,

    /// Seal the identity file (the private key in it) with a passphrase, or
    /// with a key the operating system keeps for this user (the Secret
    /// Service, the Keychain, DPAPI), or not at all; then exit
    #[arg(long, value_name = "HOW")]
    protect_identity: Option<sharp256::crypto::identity_file::ProtectAs>,

    /// Read the identity file's passphrase from this file (its first line);
    /// or set SHARP256_IDENTITY_PASSPHRASE, or type it when asked
    #[arg(long, value_name = "FILE")]
    identity_passphrase_file: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "warn")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    sharp256::init_logging(&args.log_level);
    let path = match &args.identity {
        Some(p) => p.clone(),
        None => Identity::default_path().context("no per-user data directory")?,
    };
    let passphrase = identity_file::PassphraseFrom {
        file: args.identity_passphrase_file.as_deref(),
        ask: true,
    };
    if let Some(how) = args.protect_identity {
        println!("{}", identity_file::protect(&path, how, &passphrase)?);
        return Ok(());
    }
    let identity = identity_file::open_or_create(&path, &passphrase)
        .with_context(|| format!("identity {}", path.display()))?;
    let peer = args
        .peer_card
        .as_deref()
        .map(Card::from_arg)
        .transpose()
        .map_err(|e| anyhow::anyhow!("--peer-card: {}", e))?;

    if let Some(why) = peer.as_ref().and_then(Card::staleness) {
        eprintln!("Warning: {}", why);
    }
    println!("{}", sharp256::system_info());
    println!("Measuring (a few seconds)...\n");
    let mut probe = Probe::start(Options {
        bind: args.bind,
        stun_servers: args.stun.clone(),
        port_mapping: !args.no_port_mapping,
        id: identity.id(),
        role: if args.receiver {
            Role::Receiver
        } else {
            Role::Sender
        },
        relays: Vec::new(),
        turn: args.turn.iter().map(|t| t.to_string()).collect(),
    })
    .await
    .context("the tests could not be run")?;
    print!("{}", probe.render());

    // Nobody to test with yet: ask for a card or an address, here, so that
    // the test runs on the socket that was measured — the address on the
    // card given away is that socket's, and a second run would be a
    // different one.
    let mut targets: Vec<(SocketAddr, NatHints)> = args
        .peer_addr
        .iter()
        .map(|a| (*a, NatHints::unknown()))
        .collect();
    let mut whose = args
        .peer_addr
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if let Some(card) = &peer {
        targets.extend(card.punch_targets());
        whose = if whose.is_empty() {
            card.id.to_string()
        } else {
            format!("{}, {}", card.id, whose)
        };
    }
    if targets.is_empty() && (args.stdin || std::io::stdin().is_terminal()) {
        println!(
            "\nPaste the other side's card, or its address (IP:PORT), and press Enter (or Ctrl-C \
             to stop here). Both sides should do this within a minute or two of each other:"
        );
        match read_peer().await {
            Some(Peer::Card(card)) => {
                targets = card.punch_targets();
                whose = card.id.to_string();
            }
            Some(Peer::Addrs(addrs)) => {
                whose = addrs
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                targets = addrs
                    .into_iter()
                    .map(|a| (a, NatHints::unknown()))
                    .collect();
            }
            None => {}
        }
    }
    if targets.is_empty() {
        probe.finish().await;
        return Ok(());
    }
    println!(
        "\nSending at {} address(es) of {} for up to {} s; the other side has to be running \
         this too...",
        targets.len(),
        whose,
        args.wait
    );
    let outcome = probe
        .punch_test_at(targets, Duration::from_secs(args.wait))
        .await;
    probe.finish().await;
    match outcome.heard_from {
        Some(from) => {
            println!(
                "\nA packet from the other side arrived from {}: a direct path exists.",
                from
            );
            Ok(())
        }
        None => {
            println!(
                "\nNothing arrived from the other side. Either it was not running this at the \
                 same time, or the two NATs cannot be punched through (two that number ports \
                 per destination at random need a relay)."
            );
            std::process::exit(1);
        }
    }
}

/// Who the test is with.
enum Peer {
    Card(Card),
    Addrs(Vec<SocketAddr>),
}

/// Reads lines from standard input until one is a card of the other side,
/// or its addresses.
async fn read_peer() -> Option<Peer> {
    tokio::task::spawn_blocking(|| {
        use std::io::BufRead;
        for line in std::io::stdin().lock().lines() {
            let line = line.ok()?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line
                .get(..4)
                .is_some_and(|h| h.eq_ignore_ascii_case("shc1"))
            {
                match Card::from_text(line) {
                    Ok(card) => return Some(Peer::Card(card)),
                    Err(e) => println!("That card cannot be read ({}); paste it again:", e),
                }
            } else {
                match parse_peer_addrs(line) {
                    Ok(addrs) => return Some(Peer::Addrs(addrs)),
                    Err(e) => println!("{}; paste a card or an address again:", e),
                }
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}
