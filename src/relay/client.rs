//! The peer side of the relay protocol.
//!
//! A receiver [`serve`]s: it registers with the relay and keeps the
//! registration alive, and when the relay introduces someone it pushes back
//! through its own NAT so the two can meet. A sender [`connect`]s: it asks
//! the relay to put it through and comes away with two more addresses to
//! try — where the receiver appears to be, worth attempting directly, and
//! the relay's own port, which works whenever anything does.
//!
//! Both talk to the relay over the transfer socket. That is not incidental:
//! the mapping a NAT opens belongs to a socket and a destination, so a
//! registration made from any other socket would describe a way in that
//! does not exist.

use super::{Message, Refusal, PROOF_LEN, TOKEN_LEN};
use crate::crypto::{Identity, SharpId};
use crate::nat::stun::is_usable_server_address;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Relay datagrams handed over by the socket's owner, with their source.
pub type Incoming = (Vec<u8>, SocketAddr);

/// How long to wait for each answer from the relay.
const REPLY_WAIT: Duration = Duration::from_millis(600);
/// Tries per relay exchange.
const TRIES: u32 = 3;
/// How many times a side announces itself on an allocated port, and how
/// many punches a receiver sends. More than one because the first may be
/// the one that opens the NAT rather than the one that gets through.
const REPEATS: u32 = 4;
/// Gap between those.
const REPEAT_GAP: Duration = Duration::from_millis(150);
/// Introductions acted on per second, and the burst. A relay is not
/// trusted, and acting on an introduction means sending a handful of
/// datagrams at an address it chose; without a bound of our own, a hostile
/// one could have us do that as fast as it liked.
const INTRODUCTION_RATE: f64 = 2.0;
const INTRODUCTION_BURST: f64 = 8.0;
/// Introductions remembered, so that a relay repeating one it already sent
/// is recognised rather than acted on twice.
const HANDLED_REMEMBERED: usize = 64;

/// What a relay introduction is worth: two more addresses to try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Introduction {
    /// Where the receiver appears to be, when the relay will say. Both ends
    /// push outwards at once, so this often works and costs the relay
    /// nothing. `None` when the receiver asked to stay hidden.
    pub peer: Option<SocketAddr>,
    /// The relay's port for this pair. Slower and not free for whoever runs
    /// the relay, but it works when nothing else does.
    pub relayed: SocketAddr,
    /// Which side of that port we are; see [`hold`].
    pub ticket: [u8; TOKEN_LEN],
}

/// Asks a relay to put us through to `target`.
///
/// Runs alongside the connectivity checks rather than before them, as ICE
/// gathers candidates while it is already checking others (RFC 8445 section
/// 6.1.4.2): a relay that is slow, or simply not needed because the direct
/// path works, must not hold a transfer up. `incoming` carries this relay's
/// datagrams, handed over by whoever owns the socket's receive loop — the
/// engine is reading it at the same time, so reading it here too would have
/// the two stealing each other's packets.
pub async fn connect(
    socket: Arc<UdpSocket>,
    relay: SocketAddr,
    target: SharpId,
    incoming: &mut mpsc::Receiver<Incoming>,
    cancel: &CancellationToken,
) -> Result<Introduction, String> {
    let mut token = [0u8; TOKEN_LEN];
    for _ in 0..TRIES {
        if cancel.is_cancelled() {
            return Err("cancelled".into());
        }
        let ask = Message::Connect { target, token };
        if let Err(e) = socket.send_to(&ask.encode(), relay).await {
            return Err(format!("cannot reach the relay {}: {}", relay, e));
        }
        match wait_for(incoming, relay, REPLY_WAIT).await {
            // The relay wants us to prove we receive where we say we do.
            Some(Message::Challenge { token: t }) => token = t,
            Some(Message::Allocated { port, peer, ticket }) => {
                // The relay may decline to say where the receiver is,
                // because the receiver asked it not to. There is then no
                // direct path to offer, only the relayed one.
                let peer = if peer.ip().is_unspecified() {
                    None
                } else {
                    Some(peer)
                };
                let relayed = SocketAddr::new(relay.ip(), port);
                // Binding our side of that port is the caller's to run,
                // with [`hold`]: it takes a round trip to the port and
                // back, and the caller has candidates to be getting on
                // with meanwhile.
                return Ok(Introduction {
                    peer,
                    relayed,
                    ticket,
                });
            }
            Some(Message::Error { code }) => return Err(code.describe().to_string()),
            _ => {}
        }
    }
    Err(format!("the relay {} did not answer", relay))
}

/// Binds our side of an allocated port and keeps it bound, until cancelled.
///
/// Says which side we are a few times — the first may be the datagram that
/// opens our NAT rather than the one that arrives — and answers each
/// confirmation the port sends back with an Open that carries it, which is
/// what actually binds us: the port only believes an address once it has
/// seen that address receive. `incoming` carries the relay's datagrams, as
/// for [`connect`]; only those from the allocated port matter here.
pub async fn hold(
    socket: Arc<UdpSocket>,
    relayed: SocketAddr,
    ticket: [u8; TOKEN_LEN],
    incoming: &mut mpsc::Receiver<Incoming>,
    cancel: &CancellationToken,
) {
    let ask = Message::Open {
        ticket,
        proof: [0; TOKEN_LEN],
    }
    .encode();
    let mut asked = 0u32;
    let mut next = Instant::now();
    loop {
        let wait = next.saturating_duration_since(Instant::now());
        tokio::select! {
            _ = tokio::time::sleep(wait), if asked < REPEATS => {
                let _ = socket.send_to(&ask, relayed).await;
                asked += 1;
                next = Instant::now() + REPEAT_GAP;
            }
            m = incoming.recv() => {
                let Some((pkt, from)) = m else { return };
                if from != relayed {
                    continue;
                }
                if let Some(Message::Confirm { proof }) = Message::decode(&pkt) {
                    let open = Message::Open { ticket, proof }.encode();
                    let _ = socket.send_to(&open, relayed).await;
                }
            }
            _ = cancel.cancelled() => return,
        }
    }
}

/// Registers with a relay and stays registered, introducing senders as they
/// arrive. Runs until cancelled.
///
/// `incoming` carries the relay's datagrams — from its control port and
/// from the ports it allocates — handed over by whoever owns the socket's
/// receive loop.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    socket: Arc<UdpSocket>,
    relay: SocketAddr,
    relay_id: SharpId,
    identity: Identity,
    private: bool,
    mut incoming: mpsc::Receiver<Incoming>,
    cancel: CancellationToken,
    on_registered: impl Fn(SocketAddr) + Send + 'static,
) {
    let id = identity.id();
    // A secret only this receiver and this relay can work out, from their
    // long-term keys and nothing else. It is what turns "I am sh-…" into
    // something the relay can check.
    let Some(key) = super::auth_key(&identity, &relay_id, &id, &relay_id) else {
        // Parsing an ID refuses these, so only a caller that built one by
        // hand gets here; there is no relay to prove anything to.
        tracing::warn!("relay {}: its identity is not a usable key", relay);
        return;
    };
    let reach = crate::address::Reach::of(&socket);
    let flags = if private { super::REGISTER_PRIVATE } else { 0 };
    let mut stamps = Stamps::default();
    let mut token = [0u8; TOKEN_LEN];
    let mut registered = false;
    let mut next_send = Instant::now();
    // What we are willing to do on this relay's say-so.
    let mut allowance = INTRODUCTION_BURST;
    let mut allowance_at = Instant::now();
    // Introductions already acted on — their tickets and ports — so the
    // relay's repeats cost no allowance, and its confirmations can be
    // matched to the port they came from.
    let mut handled: std::collections::VecDeque<([u8; TOKEN_LEN], u16)> =
        std::collections::VecDeque::new();
    // Until the relay answers, ask briskly; once registered, just keep the
    // lease and the NAT mapping alive.
    let mut retry = Duration::from_millis(500);
    let mut lease = Duration::from_secs(60);
    let mut send_failures = 0u32;
    loop {
        let now = Instant::now();
        if now >= next_send {
            let msg = signed(
                &key,
                Message::Register {
                    id,
                    token,
                    flags,
                    stamp: stamps.next(),
                    proof: [0; PROOF_LEN],
                },
            );
            match socket.send_to(&msg, relay).await {
                Ok(_) => {
                    send_failures = 0;
                    next_send = now + if registered { lease / 2 } else { retry };
                    if !registered {
                        retry = (retry * 2).min(Duration::from_secs(15));
                    }
                }
                // Not a reason to give up: the network may not be up yet,
                // or be changing under us. The relay may be the only way
                // anyone can reach this receiver, so keep trying — less
                // often, and saying so once.
                Err(e) => {
                    send_failures = send_failures.saturating_add(1);
                    if send_failures == 1 {
                        tracing::warn!("relay {}: cannot send ({}); will keep trying", relay, e);
                    }
                    next_send = now + Duration::from_secs(2u64 << send_failures.min(4));
                }
            }
        }
        let wait = next_send.saturating_duration_since(Instant::now());
        let msg = tokio::select! {
            m = incoming.recv() => m,
            _ = tokio::time::sleep(wait) => continue,
            _ = cancel.cancelled() => {
                if registered {
                    goodbye(&socket, relay, &key, id, token, &mut stamps, &mut incoming).await;
                }
                return;
            }
        };
        let Some((pkt, from)) = msg else { return };
        // From the relay's host: its control port, or one of the ports it
        // set aside for us.
        if from.ip() != relay.ip() {
            continue;
        }
        let Some(msg) = Message::decode(&pkt) else {
            continue;
        };
        if from != relay {
            // An allocated port asking us to prove we receive here. Only
            // for a port we were introduced on, and only with the ticket we
            // were given for it.
            if let Message::Confirm { proof } = msg {
                if let Some((ticket, _)) = handled.iter().find(|(_, p)| *p == from.port()) {
                    let open = Message::Open {
                        ticket: *ticket,
                        proof,
                    };
                    let _ = socket.send_to(&open.encode(), from).await;
                }
            }
            continue;
        }
        match msg {
            Message::Challenge { token: t } => {
                token = t;
                next_send = Instant::now();
            }
            Message::Registered {
                lease: secs,
                observed,
            } => {
                if !registered {
                    tracing::info!("relay {} reached; it sees us at {}", relay, observed);
                    on_registered(observed);
                }
                registered = true;
                lease = Duration::from_secs(secs.clamp(10, 3600) as u64);
                next_send = Instant::now() + lease / 2;
            }
            Message::Incoming { port, peer, ticket } => {
                let relayed = SocketAddr::new(relay.ip(), port);
                // The relay repeats an introduction until our side of the
                // port is bound, because a lost one would otherwise fail the
                // transfer silently. A repeat means the binding has not
                // happened yet, so it is worth saying which side we are
                // again — that goes to the relay's own address and costs
                // nothing — but it is not a new introduction, and must not
                // spend the allowance below or punch again.
                if handled.iter().any(|(t, _)| *t == ticket) {
                    let socket = socket.clone();
                    tokio::spawn(async move { announce(&socket, relayed, ticket).await });
                    continue;
                }
                if handled.len() >= HANDLED_REMEMBERED {
                    handled.pop_front();
                }
                handled.push_back((ticket, port));
                // Pushing outwards towards the sender means sending a
                // handful of datagrams at an address the relay chose, so
                // how often we are willing to do that is our decision, not
                // the relay's. Binding our side of its port is not: that
                // goes to the relay itself, and holding it back would let
                // anyone who can ask the relay for introductions starve the
                // real ones.
                let now = Instant::now();
                allowance = (allowance
                    + now.saturating_duration_since(allowance_at).as_secs_f64()
                        * INTRODUCTION_RATE)
                    .min(INTRODUCTION_BURST);
                allowance_at = now;
                // An unspecified peer means the relay was asked not to say
                // where the other side is — either it asked to stay hidden,
                // or we did — so there is nothing to punch towards and the
                // pair meets at the relay's port.
                let target = if peer.ip().is_unspecified() {
                    None
                } else if allowance >= 1.0 {
                    allowance -= 1.0;
                    Some(peer)
                } else {
                    tracing::debug!("relay {} is introducing too fast; not punching", relay);
                    None
                };
                tracing::info!("relay {} is introducing {}", relay, peer);
                let socket = socket.clone();
                // Both jobs at once, and that is not a figure of speech.
                // Binding our side of the relay's port and pushing outwards
                // towards the sender are each spread over most of a second,
                // and hole punching only works while both ends are pushing
                // at the same time — running them one after the other would
                // have our first datagram leave after the sender's had
                // already been dropped by our NAT.
                tokio::spawn(async move {
                    match target.and_then(|p| reach.native(p)) {
                        Some(peer) => {
                            tokio::join!(announce(&socket, relayed, ticket), punch(&socket, peer));
                        }
                        None => announce(&socket, relayed, ticket).await,
                    }
                });
            }
            Message::Error { code } => {
                match code {
                    // Worth retrying, later.
                    Refusal::Busy => next_send = Instant::now() + Duration::from_secs(30),
                    // Our clock is behind what the relay last took from us.
                    // Nothing to do but wait for it to forget.
                    Refusal::Stale => {
                        tracing::warn!("relay {}: {}", relay, code.describe());
                        next_send = Instant::now() + Duration::from_secs(60);
                    }
                    _ => {}
                }
                tracing::debug!("relay {}: {}", relay, code.describe());
            }
            _ => {}
        }
    }
}

/// Stamps for our registrations: strictly increasing, and close to the
/// wall clock so that a restarted receiver carries on above where it was
/// (see `Message::Register::stamp`).
#[derive(Default)]
struct Stamps {
    last: u64,
}

impl Stamps {
    fn next(&mut self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
            .unwrap_or(0);
        self.last = now.max(self.last.saturating_add(1));
        self.last
    }
}

/// How long leaving waits for the relay to ask for a fresh token.
const GOODBYE_WAIT: Duration = Duration::from_millis(700);

/// Tells the relay we are going. Otherwise it keeps sending people to an
/// address that no longer answers until the lease runs out, which is the
/// difference between a sender failing over in a moment and in two minutes.
///
/// The token we hold may have expired since the last keepalive; the relay
/// then answers with a fresh one, and the goodbye is sent again with it.
async fn goodbye(
    socket: &UdpSocket,
    relay: SocketAddr,
    key: &[u8; 32],
    id: SharpId,
    mut token: [u8; TOKEN_LEN],
    stamps: &mut Stamps,
    incoming: &mut mpsc::Receiver<Incoming>,
) {
    for _ in 0..2 {
        let bye = signed(
            key,
            Message::Bye {
                id,
                token,
                stamp: stamps.next(),
                proof: [0; PROOF_LEN],
            },
        );
        if socket.send_to(&bye, relay).await.is_err() {
            return;
        }
        match wait_for(incoming, relay, GOODBYE_WAIT).await {
            Some(Message::Challenge { token: t }) => token = t,
            _ => return,
        }
    }
}

/// Encodes a message and fills in its proof, which covers everything in
/// front of it.
fn signed(key: &[u8; 32], msg: Message) -> Vec<u8> {
    let mut bytes = msg.encode();
    let split = bytes.len() - PROOF_LEN;
    let proof = super::proof_for(key, &bytes[..split]);
    bytes[split..].copy_from_slice(&proof);
    bytes
}

/// Says which side of an allocation we are, repeatedly: the first may be
/// the one that opens the NAT rather than the one that arrives. Each draws
/// a confirmation from the port, which [`serve`] answers.
async fn announce(socket: &UdpSocket, allocated: SocketAddr, ticket: [u8; TOKEN_LEN]) {
    let msg = Message::Open {
        ticket,
        proof: [0; TOKEN_LEN],
    }
    .encode();
    for i in 0..REPEATS {
        if socket.send_to(&msg, allocated).await.is_err() {
            return;
        }
        if i + 1 < REPEATS {
            tokio::time::sleep(REPEAT_GAP).await;
        }
    }
}

/// Pushes a few datagrams at the address the relay named, so that our NAT
/// has a way back open when the other side's first packet arrives.
///
/// The address comes from the relay, which is not trusted, so it is screened
/// the same way a STUN server's suggestions are. There is nothing to amplify
/// here — these draw no reply at all — but a handful of unasked-for
/// datagrams should still not be aimed at a stranger.
async fn punch(socket: &UdpSocket, peer: SocketAddr) {
    let Ok(local) = socket.local_addr() else {
        return;
    };
    if !is_usable_server_address(peer, local) {
        tracing::debug!("relay named {}, which is not worth sending to", peer);
        return;
    }
    let msg = Message::Punch.encode();
    for i in 0..REPEATS {
        if socket.send_to(&msg, peer).await.is_err() {
            return;
        }
        if i + 1 < REPEATS {
            tokio::time::sleep(REPEAT_GAP).await;
        }
    }
}

/// Reads until a relay message from `relay` arrives, or the time is up.
async fn wait_for(
    incoming: &mut mpsc::Receiver<Incoming>,
    relay: SocketAddr,
    within: Duration,
) -> Option<Message> {
    let deadline = Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        let (pkt, from) = tokio::time::timeout(left, incoming.recv()).await.ok()??;
        if from != relay {
            continue;
        }
        if let Some(m) = Message::decode(&pkt) {
            return Some(m);
        }
    }
}
