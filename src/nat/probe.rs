//! Finding out how the internet sees this host — the same for a sender and
//! a receiver, before either has anything to send.
//!
//! [`Probe::start`] binds a socket, asks STUN servers what address and port
//! the NAT in front of it gives out and how that NAT behaves (RFC 5780), asks
//! the router for a port forward (PCP, NAT-PMP, UPnP) to see whether it
//! would, and makes a contact card of the answer. [`Probe::render`] says all
//! of it in words, and [`Probe::punch_test`] takes a peer's card and finds
//! out whether the two of you, each running this at the same time, can reach
//! each other — without a file being sent.
//!
//! What the probe measures is the mapping of *its* socket. A NAT that keeps
//! one mapping per source (and so per socket) gives the transfer socket the
//! same treatment; one that does not is described as such, and the numbers
//! it shows are only what one socket was given.

use super::behaviour::{Allocation, Behaviour, Filtering, Mapping};
use super::card::{Card, FamilyHints, RelayRef, Role};
use super::punch::Puncher;
use super::{spawn_discovery, NatConfig, Reachability};
use crate::crypto::SharpId;
use crate::relay::Message;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// What to probe with.
#[derive(Debug, Clone)]
pub struct Options {
    /// Where to bind: `[::]:0` reaches both families on one socket.
    pub bind: SocketAddr,
    /// STUN servers; empty means the built-in list.
    pub stun_servers: Vec<String>,
    /// Ask the router for a port forward, to see whether it would (it is
    /// given back when the probe ends).
    pub port_mapping: bool,
    /// The identity a card is made for.
    pub id: SharpId,
    pub role: Role,
    pub relays: Vec<RelayRef>,
    /// TURN servers, `USER:PASSWORD@HOST[:PORT]`: each is asked for an
    /// address, which goes on the card, and is used in [`Probe::punch_test`].
    pub turn: Vec<String>,
}

/// A running probe: the socket it measured with, and what was found.
pub struct Probe {
    pub socket: Arc<UdpSocket>,
    pub reach: Reachability,
    pub card: Card,
    options: Options,
    hints: tokio::sync::watch::Receiver<FamilyHints>,
    datagrams: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    cancel: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    turns: Vec<super::turn::Turn>,
    /// What came of each TURN server asked, in words.
    turn_notes: Vec<String>,
}

/// How long a TURN server is waited for, at most.
const TURN_WAIT: Duration = Duration::from_secs(8);
/// How long the tests are waited for, at most.
const TESTS_WAIT: Duration = Duration::from_secs(25);
/// How long, after the tests, a router is given to answer a port-forward
/// request.
const MAPPING_WAIT: Duration = Duration::from_secs(5);

impl Probe {
    /// Runs the tests and waits for what they found.
    pub async fn start(options: Options) -> io::Result<Self> {
        let socket = Arc::new(crate::transport::socket::bind_udp(
            options.bind,
            256 * 1024,
        )?);
        let cancel = CancellationToken::new();
        let (stun_tx, mut stun_rx) = mpsc::channel::<super::stun::Incoming>(64);
        let (data_tx, data_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(256);
        // This socket is read by nobody else: STUN answers go to the tests,
        // everything else to whoever wants it.
        let reader = {
            let (socket, cancel) = (socket.clone(), cancel.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let (n, from) = tokio::select! {
                        r = socket.recv_from(&mut buf) => match r {
                            Ok(r) => r,
                            Err(_) => continue,
                        },
                        _ = cancel.cancelled() => return,
                    };
                    let d = buf[..n].to_vec();
                    if super::stun::is_stun_message(&d) {
                        let _ = stun_tx.try_send((d, from));
                    } else {
                        let _ = data_tx.try_send((d, from));
                    }
                }
            })
        };
        let (hints_tx, hints_rx) = tokio::sync::watch::channel(FamilyHints::unknown());
        let (result_tx, mut result_rx) = mpsc::unbounded_channel::<Reachability>();
        let mut config = NatConfig {
            enable_port_mapping: options.port_mapping,
            ..NatConfig::default()
        };
        if !options.stun_servers.is_empty() {
            config.stun_servers = options.stun_servers.clone();
        }
        let task = spawn_discovery(
            socket.clone(),
            config,
            Default::default(),
            hints_tx,
            cancel.clone(),
            move |r| {
                let _ = result_tx.send(r.clone());
            },
        )
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a loopback address has no NAT to probe",
            )
        })?;
        // The discovery task reads STUN answers from this channel.
        let forward = {
            let tx = task.stun_responses.clone();
            tokio::spawn(async move {
                while let Some(m) = stun_rx.recv().await {
                    if tx.send(m).await.is_err() {
                        return;
                    }
                }
            })
        };
        let mut reach = tokio::time::timeout(TESTS_WAIT, result_rx.recv())
            .await
            .ok()
            .flatten()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "the NAT tests gave no result")
            })?;
        // The router answers in its own time: more news, if any, comes as a
        // second result.
        if options.port_mapping {
            let deadline = tokio::time::Instant::now() + MAPPING_WAIT;
            while reach.upnp_addr.is_none() {
                match tokio::time::timeout_at(deadline, result_rx.recv()).await {
                    Ok(Some(r)) => reach = r,
                    _ => break,
                }
            }
        }
        // The TURN servers, if any were given: each asked for an address.
        let turns = super::turn::start_all(&options.turn, &socket, &cancel);
        let mut turn_notes = Vec::new();
        for (t, name) in turns.iter().zip(&options.turn) {
            let mut changes = t.subscribe();
            let _ = tokio::time::timeout(TURN_WAIT, async {
                while t.relayed().is_empty() {
                    if changes.changed().await.is_err() {
                        return;
                    }
                }
            })
            .await;
            let who = name
                .parse::<super::turn::Server>()
                .map(|s| s.to_string())
                .unwrap_or_else(|_| name.clone());
            let got = t.relayed();
            turn_notes.push(if got.is_empty() {
                format!(
                    "{}: no address in {:?} (the credentials, or UDP to the server, are what to check)",
                    who, TURN_WAIT
                )
            } else {
                format!(
                    "{}: relaying at {}",
                    who,
                    got.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
                )
            });
            reach.relayed.extend(got);
        }
        let card = reach.card(&options.id, options.role, &options.relays);
        Ok(Self {
            socket,
            reach,
            card,
            options,
            hints: hints_rx,
            datagrams: data_rx,
            cancel,
            tasks: vec![reader, forward, task.task],
            turns,
            turn_notes,
        })
    }

    /// Ends the probe and gives back whatever the router granted and the
    /// servers allocated.
    pub async fn finish(self) {
        self.cancel.cancel();
        for t in self.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
        }
        for t in &self.turns {
            t.finished(Duration::from_secs(2)).await;
        }
    }

    /// Everything found, in words.
    pub fn render(&self) -> String {
        let r = &self.reach;
        let mut out = String::new();
        let mut line = |label: &str, text: String| {
            out.push_str(&format!("{:<20} {}\n", label, text));
        };
        let host: Vec<String> = r.host.iter().map(|ip| ip.to_string()).collect();
        line(
            "This host:",
            if host.is_empty() {
                "no address worth publishing".to_string()
            } else {
                host.join(", ")
            },
        );
        let primary_v6 = r
            .behaviour
            .tested_with
            .is_some_and(|a| crate::address::canonical(a).is_ipv6());
        line(
            if primary_v6 { "IPv6:" } else { "IPv4:" },
            describe_family(&r.behaviour, r.double_nat, primary_v6),
        );
        match &r.behaviour6 {
            Some(b6) => line("IPv6:", describe_family(b6, false, true)),
            None if !primary_v6 => line(
                "IPv6:",
                "not measured (no global IPv6 address, or no STUN server over IPv6)".to_string(),
            ),
            None => {}
        }
        if !self.options.port_mapping {
            line("Port forwarding:", "not asked".to_string());
        } else {
            let mut said = false;
            for f in &r.forwards {
                line(
                    if said { "" } else { "Port forwarding:" },
                    format!("{} (given back when this ends)", f),
                );
                said = true;
            }
            // What each protocol said, granted or not: "the router refused"
            // and "no router answered" are different things to know.
            for note in &r.mapping_notes {
                line(if said { "" } else { "Port forwarding:" }, note.clone());
                said = true;
            }
            if !said {
                line(
                    "Port forwarding:",
                    "none: no router answered PCP, NAT-PMP or UPnP".to_string(),
                );
            }
        }
        if !self.turn_notes.is_empty() {
            let mut said = false;
            for note in &self.turn_notes {
                line(if said { "" } else { "TURN:" }, note.clone());
                said = true;
            }
        }
        line("Relays on the card:", self.card.relays.len().to_string());
        out.push_str(&format!(
            "\nYour card (give it to the other side):\n{}\n",
            self.card.to_text()
        ));
        out
    }

    /// Sends at every address on `peer`'s card, as a transfer would, and
    /// listens for the peer doing the same: the two of you both running
    /// this within `duration` of each other is the test.
    pub async fn punch_test(&mut self, peer: &Card, duration: Duration) -> Outcome {
        let puncher = Arc::new(
            Puncher::new(self.socket.clone(), self.hints.clone()).with_turns(self.turns.clone()),
        );
        let cancel = self.cancel.child_token();
        let targets = peer.punch_targets();
        let mut runs = Vec::new();
        for (addr, hints) in &targets {
            let (puncher, cancel, addr, hints) = (puncher.clone(), cancel.clone(), *addr, *hints);
            runs.push(tokio::spawn(async move {
                puncher.run_for(addr, hints, duration, &cancel).await;
            }));
        }
        let peer_ips: Vec<_> = targets
            .iter()
            .map(|(a, _)| crate::address::canonical(*a).ip())
            .collect();
        let deadline = tokio::time::Instant::now() + duration;
        let mut heard = None;
        while heard.is_none() {
            let Ok(Some((d, from))) =
                tokio::time::timeout_at(deadline, self.datagrams.recv()).await
            else {
                break;
            };
            if !peer_ips.contains(&crate::address::canonical(from).ip()) {
                continue;
            }
            if matches!(Message::decode(&d), Some(Message::Punch)) {
                heard = Some(from);
            }
        }
        // Answer from where it was heard, a few times, so that the peer
        // hears us too if it has not.
        if let Some(from) = heard {
            for _ in 0..4 {
                let _ = self.socket.send_to(&Message::Punch.encode(), from).await;
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
        }
        cancel.cancel();
        for r in runs {
            let _ = r.await;
        }
        Outcome {
            heard_from: heard,
            tried: targets.into_iter().map(|(a, _)| a).collect(),
        }
    }
}

/// How a punch test ended.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The address the peer's packet arrived from: a direct path exists at
    /// least this way.
    pub heard_from: Option<SocketAddr>,
    pub tried: Vec<SocketAddr>,
}

fn describe_family(b: &Behaviour, double_nat: bool, v6: bool) -> String {
    let Some(mapped) = b.mapped else {
        return "no STUN server answered: address and NAT behaviour not measured".to_string();
    };
    let mut out = format!("your address as the internet sees it: {}", mapped);
    if b.open_internet {
        out.push_str(if v6 {
            "; no address translation"
        } else {
            "; no NAT"
        });
    } else {
        out.push_str("; ");
        out.push_str(match b.mapping {
            Mapping::EndpointIndependent => "one port for every destination",
            Mapping::AddressDependent => "the port depends on the destination host",
            Mapping::AddressAndPortDependent => {
                "the port depends on destination host and port (symmetric)"
            }
            Mapping::Unknown => "mapping not measured",
        });
    }
    out.push_str(&format!(
        "; {}",
        match b.filtering {
            Filtering::EndpointIndependent => "lets in packets from anyone".to_string(),
            Filtering::AddressDependent => "lets in packets from hosts it was sent to".to_string(),
            Filtering::AddressAndPortDependent => {
                "lets in only packets from the exact address and port it was sent to".to_string()
            }
            Filtering::Unknown =>
                "filtering not measured (needs a STUN server with a second address)".to_string(),
        }
    ));
    if b.mapping == Mapping::AddressAndPortDependent || b.mapping == Mapping::AddressDependent {
        out.push_str(match b.allocation {
            Allocation::Sequential => {
                "; new ports count up, so a peer with a simple NAT can aim at them"
            }
            Allocation::Random => {
                "; new ports are random: a peer with a simple NAT finds them by trying very many"
            }
            Allocation::Preserved => "; the NAT keeps your port when it can",
            Allocation::Unknown => "",
        });
    }
    match b.hairpinning {
        Some(true) => out.push_str("; hairpinning works"),
        Some(false) => out.push_str(
            "; no hairpinning (two hosts behind this NAT cannot use each other's outside address)",
        ),
        None => {}
    }
    if double_nat {
        out.push_str("; another NAT in front (carrier-grade)");
    }
    out.push_str(&format!("; {}", b.reachable_text()));
    out
}
