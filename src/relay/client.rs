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
                // Tell the allocated port which side we are. This is also
                // what opens our NAT towards it, and the address it sees
                // here is very likely not the one the control port saw.
                // It is spaced out over most of a second, so it runs on its
                // own: the caller has candidates to be getting on with.
                let announcer = socket.clone();
                tokio::spawn(async move {
                    announce(&announcer, relayed, ticket).await;
                });
                return Ok(Introduction { peer, relayed });
            }
            Some(Message::Error { code }) => return Err(code.describe().to_string()),
            _ => {}
        }
    }
    Err(format!("the relay {} did not answer", relay))
}

/// Registers with a relay and stays registered, introducing senders as they
/// arrive. Runs until cancelled.
///
/// `incoming` carries the relay's datagrams, handed over by whoever owns the
/// socket's receive loop.
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
    let flags = if private { super::REGISTER_PRIVATE } else { 0 };
    let mut token = [0u8; TOKEN_LEN];
    let mut registered = false;
    let mut next_send = Instant::now();
    // What we are willing to do on this relay's say-so.
    let mut allowance = INTRODUCTION_BURST;
    let mut allowance_at = Instant::now();
    // Introductions already acted on, so the relay's repeats are free.
    let mut handled: std::collections::VecDeque<[u8; TOKEN_LEN]> =
        std::collections::VecDeque::new();
    // Until the relay answers, ask briskly; once registered, just keep the
    // lease and the NAT mapping alive.
    let mut retry = Duration::from_millis(500);
    let mut lease = Duration::from_secs(60);
    loop {
        let now = Instant::now();
        if now >= next_send {
            let msg = signed(
                &key,
                Message::Register {
                    id,
                    token,
                    flags,
                    proof: [0; PROOF_LEN],
                },
            );
            if socket.send_to(&msg, relay).await.is_err() {
                return;
            }
            next_send = now + if registered { lease / 2 } else { retry };
            if !registered {
                retry = (retry * 2).min(Duration::from_secs(15));
            }
        }
        let wait = next_send.saturating_duration_since(Instant::now());
        let msg = tokio::select! {
            m = incoming.recv() => m,
            _ = tokio::time::sleep(wait) => continue,
            _ = cancel.cancelled() => {
                // Say so on the way out. Otherwise the relay keeps sending
                // people to an address that no longer answers until the
                // lease runs out, which is the difference between a sender
                // failing over in a moment and failing over in two minutes.
                if registered {
                    let bye = signed(
                        &key,
                        Message::Bye {
                            id,
                            token,
                            proof: [0; PROOF_LEN],
                        },
                    );
                    let _ = socket.send_to(&bye, relay).await;
                }
                return;
            }
        };
        let Some((pkt, from)) = msg else { return };
        if from != relay {
            continue;
        }
        match Message::decode(&pkt) {
            Some(Message::Challenge { token: t }) => {
                token = t;
                next_send = Instant::now();
            }
            Some(Message::Registered {
                lease: secs,
                observed,
            }) => {
                if !registered {
                    tracing::info!("relay {} reached; it sees us at {}", relay, observed);
                    on_registered(observed);
                }
                registered = true;
                lease = Duration::from_secs(secs.clamp(10, 3600) as u64);
                next_send = Instant::now() + lease / 2;
            }
            Some(Message::Incoming { port, peer, ticket }) => {
                // The relay repeats an introduction until we bind our side,
                // because a lost one would otherwise fail the transfer
                // silently. A repeat is not a new introduction, and must not
                // spend the allowance below or start the work again.
                if handled.contains(&ticket) {
                    continue;
                }
                // Acting on an introduction means sending a handful of
                // datagrams at an address the relay chose, so how often we
                // are willing to do that is our decision, not the relay's.
                let now = Instant::now();
                allowance = (allowance
                    + now.saturating_duration_since(allowance_at).as_secs_f64()
                        * INTRODUCTION_RATE)
                    .min(INTRODUCTION_BURST);
                allowance_at = now;
                if allowance < 1.0 {
                    tracing::debug!("relay {} is introducing too fast; ignoring", relay);
                    continue;
                }
                allowance -= 1.0;
                if handled.len() >= HANDLED_REMEMBERED {
                    handled.pop_front();
                }
                handled.push_back(ticket);
                let relayed = SocketAddr::new(relay.ip(), port);
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
                    // An unspecified peer means the relay was asked not to
                    // say where the other side is — either it asked to stay
                    // hidden, or we did — so there is nothing to punch
                    // towards and the pair meets at the relay's port.
                    if peer.ip().is_unspecified() {
                        announce(&socket, relayed, ticket).await;
                    } else {
                        tokio::join!(announce(&socket, relayed, ticket), punch(&socket, peer));
                    }
                });
            }
            Some(Message::Error { code }) => {
                // Busy is worth retrying; the rest are not about us.
                if code == Refusal::Busy {
                    next_send = Instant::now() + Duration::from_secs(30);
                }
                tracing::debug!("relay {}: {}", relay, code.describe());
            }
            _ => {}
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
/// the one that opens the NAT rather than the one that arrives.
async fn announce(socket: &UdpSocket, allocated: SocketAddr, ticket: [u8; TOKEN_LEN]) {
    let msg = Message::Open { ticket }.encode();
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
