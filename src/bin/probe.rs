//! `sharp-probe` — how does the internet see this host, and can a friend
//! reach it?
//!
//! Run it on the sending host and on the receiving host, on their own
//! networks. Each prints the address and port the NAT in front of it gives
//! out, what kind of NAT that is, whether the router would forward a port,
//! and a contact card. Swap the cards and run it again with `--peer-card`,
//! both at the same time: it sends at the other side's addresses the way a
//! transfer would and says whether a packet got through — without a file
//! being sent.

use anyhow::{Context, Result};
use clap::Parser;
use sharp256::crypto::Identity;
use sharp256::nat::card::{Card, Role};
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
        value_delimiter = ' '
    )]
    turn: Vec<String>,

    /// The other side's contact card (shc1-…), or @FILE with one in it.
    /// Sends at its addresses for --wait seconds, listens for the other
    /// side doing the same, and reports whether a packet got through. Both
    /// sides run this at about the same time
    #[arg(long = "peer-card", value_name = "CARD|@FILE")]
    peer_card: Option<String>,

    /// Seconds the test with a peer's card goes on for
    #[arg(long, default_value_t = 120)]
    wait: u64,

    /// Read the other side's card from standard input even when it is not a
    /// terminal (a terminal is always asked)
    #[arg(long)]
    stdin: bool,

    /// Make the card as a receiver's (default: a sender's)
    #[arg(long)]
    receiver: bool,

    /// Identity key file the card is made for (default: per-user data
    /// directory)
    #[arg(long)]
    identity: Option<PathBuf>,

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
    let identity =
        Identity::load_or_create(&path).with_context(|| format!("identity {}", path.display()))?;
    let mut peer = args
        .peer_card
        .as_deref()
        .map(Card::from_arg)
        .transpose()
        .map_err(|e| anyhow::anyhow!("--peer-card: {}", e))?;

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
        turn: args.turn.clone(),
    })
    .await
    .context("the tests could not be run")?;
    print!("{}", probe.render());

    // No card yet: ask for one, here, so that the test runs on the socket
    // that was measured — the address on the card given away is that
    // socket's, and a second run would be a different one.
    if peer.is_none() && (args.stdin || std::io::stdin().is_terminal()) {
        println!(
            "\nPaste the other side's card and press Enter (or Ctrl-C to stop here). Both sides \
             should do this within a minute or two of each other:"
        );
        peer = read_card().await;
    }
    let Some(peer) = peer else {
        probe.finish().await;
        return Ok(());
    };
    println!(
        "\nSending at {} address(es) of {} for up to {} s; the other side has to be running \
         this too...",
        peer.punch_targets().len(),
        peer.id,
        args.wait
    );
    let outcome = probe
        .punch_test(&peer, Duration::from_secs(args.wait))
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

/// Reads lines from standard input until one is a card of the other side.
async fn read_card() -> Option<Card> {
    tokio::task::spawn_blocking(|| {
        use std::io::BufRead;
        for line in std::io::stdin().lock().lines() {
            let line = line.ok()?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match Card::from_text(line) {
                Ok(card) => return Some(card),
                Err(e) => println!("That card cannot be read ({}); paste it again:", e),
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}
