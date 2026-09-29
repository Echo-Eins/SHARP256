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

use super::{Alt, Hints, Message, Refusal, PROOF_LEN, TOKEN_LEN};
use crate::crypto::{Identity, SharpId};
use crate::nat::card::NatHints;
use crate::nat::punch::Puncher;
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
/// How long a sender goes on asking a relay for a receiver the relay says it
/// does not know, and the pauses between asks (doubling, up to the last).
/// The receiver may be registering this very moment — two people starting at
/// about the same time — or its registration may have lapsed and be renewed
/// within seconds; giving up on the relay at the first "unknown" loses the
/// introduction for good, and with it every direct path that needs one.
const UNKNOWN_PATIENCE: Duration = Duration::from_secs(120);
const UNKNOWN_PAUSE: Duration = Duration::from_millis(600);
const UNKNOWN_PAUSE_MAX: Duration = Duration::from_secs(4);
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
    /// What the receiver says its NAT does; all "not measured" when it has
    /// not said. Advice from a party that need not be honest, used only to
    /// decide how much to send (see `nat::punch`).
    pub peer_hints: NatHints,
    /// Where the receiver says it can also be reached, in the other address
    /// family — already screened: another family from `peer`'s, one the
    /// internet routes. Worth pushing at too, and often the only direct
    /// path there is: two IPv4 NATs that cannot meet leave IPv6 with none
    /// to get through.
    pub peer_alt: Option<Alt>,
}

/// Why a relay did not put us through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// It answered, and said no. Asking it at another of its addresses
    /// would get the same answer.
    Refused(String),
    /// Nothing came back from this address, or we could not send there.
    /// Another address of the same relay may do better.
    NoAnswer(String),
    Cancelled,
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Refused(why) | ConnectError::NoAnswer(why) => f.write_str(why),
            ConnectError::Cancelled => f.write_str("cancelled"),
        }
    }
}

/// Who we are, for a relay that puts through only senders on its list: our
/// identity, and the relay's, against which ownership of ours is proven.
pub type SenderAuth<'a> = Option<(&'a Identity, SharpId)>;

/// Asks a relay to put us through to `target`, telling it (and through it,
/// the receiver) what `hints` says of our NAT and of where else we can be
/// reached.
///
/// Runs alongside the connectivity checks rather than before them, as ICE
/// gathers candidates while it is already checking others (RFC 8445 section
/// 6.1.4.2): a relay that is slow, or simply not needed because the direct
/// path works, must not hold a transfer up. `incoming` carries this relay's
/// datagrams, handed over by whoever owns the socket's receive loop — the
/// engine is reading it at the same time, so reading it here too would have
/// the two stealing each other's packets.
///
/// We say who we are only to a relay that asks, by refusing us as a
/// stranger, and only when we know the relay's identity (`auth`): a relay
/// that serves anyone learns nothing about the sender, and one that wants
/// to know gets a proof it can check, made as a receiver's registration
/// is.
pub async fn connect(
    socket: Arc<UdpSocket>,
    relay: SocketAddr,
    target: SharpId,
    incoming: &mut mpsc::Receiver<Incoming>,
    cancel: &CancellationToken,
    auth: SenderAuth<'_>,
    hints: Hints,
) -> Result<Introduction, ConnectError> {
    let mut token = [0u8; TOKEN_LEN];
    // Set once the relay has refused us as a stranger.
    let mut identify: Option<(SharpId, [u8; 32])> = None;
    // Since when the relay has been saying it does not know the receiver,
    // and how long to pause before asking again.
    let mut unknown: Option<(Instant, Duration)> = None;
    // Two more than the plain exchange needs, for the round that tells us
    // to identify ourselves and the one that fetches a token for it.
    let mut tries = 0;
    while tries < TRIES + 2 {
        tries += 1;
        if cancel.is_cancelled() {
            return Err(ConnectError::Cancelled);
        }
        let ask = match identify {
            Some((id, key)) => signed(
                &key,
                Message::ConnectAs {
                    target,
                    token,
                    hints,
                    id,
                    proof: [0; PROOF_LEN],
                },
            ),
            None => Message::Connect {
                target,
                token,
                hints,
            }
            .encode(),
        };
        if let Err(e) = socket.send_to(&ask, relay).await {
            return Err(ConnectError::NoAnswer(format!(
                "cannot reach the relay {}: {}",
                relay, e
            )));
        }
        match wait_for(incoming, relay, REPLY_WAIT).await {
            // The relay wants us to prove we receive where we say we do.
            Some(Message::Challenge { token: t }) => token = t,
            Some(Message::Allocated {
                port,
                peer,
                ticket,
                hints: peer_hints,
            }) => {
                // The relay may decline to say where the receiver is,
                // because the receiver asked it not to. There is then no
                // direct path to offer, only the relayed one.
                let peer = if peer.ip().is_unspecified() {
                    None
                } else {
                    Some(peer)
                };
                // What the relay passes on of the receiver is no more
                // trusted than the rest of what it says, and the other
                // family's address is only meaningful next to one in this
                // family.
                let peer_hints = match peer {
                    Some(seen) => peer_hints.screened(seen),
                    None => Hints::none(),
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
                    peer_hints: peer_hints.nat,
                    peer_alt: peer_hints.alt,
                });
            }
            // A relay that serves only senders on its list: say who we
            // are, if we can prove it to this relay.
            Some(Message::Error {
                code: Refusal::Forbidden,
            }) if identify.is_none() => {
                let proven = auth.and_then(|(identity, relay_id)| {
                    let id = identity.id();
                    super::auth_key(identity, &relay_id, &id, &relay_id).map(|k| (id, k))
                });
                match proven {
                    Some(p) => identify = Some(p),
                    None => {
                        return Err(ConnectError::Refused(format!(
                            "{} (it has to be given as <relay ID>@<host>:<port> for the \
                             sender to prove who it is)",
                            Refusal::Forbidden.describe()
                        )))
                    }
                }
            }
            Some(Message::Error {
                code: Refusal::Unknown,
            }) => {
                let (since, pause) = unknown.get_or_insert((Instant::now(), UNKNOWN_PAUSE));
                if since.elapsed() >= UNKNOWN_PATIENCE {
                    return Err(ConnectError::Refused(
                        Refusal::Unknown.describe().to_string(),
                    ));
                }
                if *pause == UNKNOWN_PAUSE {
                    tracing::info!(
                        "relay {}: the receiver is not registered there (yet); asking again",
                        relay
                    );
                }
                let wait = *pause;
                *pause = (*pause * 2).min(UNKNOWN_PAUSE_MAX);
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = cancel.cancelled() => return Err(ConnectError::Cancelled),
                }
                // Waiting for the receiver is not a try that failed.
                tries -= 1;
            }
            Some(Message::Error { code }) => {
                return Err(ConnectError::Refused(code.describe().to_string()))
            }
            _ => {}
        }
    }
    Err(ConnectError::NoAnswer(format!(
        "the relay {} did not answer",
        relay
    )))
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
/// `relays` are the addresses the relay's name gave, in the order to try
/// them: until one of them answers, the registration moves on to the next
/// after two unanswered attempts, so that a relay whose IPv6 path is broken
/// is still reached over IPv4.
///
/// Once registered, the registration is refreshed often enough to keep our
/// NAT's mapping towards the relay alive (see [`crate::nat::keepalive`]),
/// not merely the relay's lease: a mapping forgotten between refreshes
/// leaves the relay introducing senders to an address that leads nowhere
/// until the next one. If the relay sees us at a new address after a
/// refresh anyway, the mapping did lapse, and the refreshes get closer
/// together. A relay that stops answering for a whole lease has forgotten
/// us: registering starts over, on the next address if there is one.
///
/// `incoming` carries the relay's datagrams — from its control port and
/// from the ports it allocates — handed over by whoever owns the socket's
/// receive loop. `on_registered` hears the address registered with and
/// where the relay sees us, the first time and whenever that changes.
///
/// What `puncher` knows of our NAT goes into every registration, and a
/// registration is sent again the moment that changes, so that a sender
/// asking after the NAT tests finished is told what they found. When the
/// relay introduces a sender, `puncher` pushes back at it.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    socket: Arc<UdpSocket>,
    relays: Vec<SocketAddr>,
    relay_id: SharpId,
    identity: Identity,
    private: bool,
    mut incoming: mpsc::Receiver<Incoming>,
    cancel: CancellationToken,
    keepalive: crate::nat::keepalive::SharedKeepalive,
    puncher: Arc<Puncher>,
    on_registered: impl Fn(SocketAddr, SocketAddr) + Send + 'static,
) {
    let Some(&first) = relays.first() else {
        return;
    };
    let mut relay = first;
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
    let mut hints_changed = puncher.subscribe();
    let mut watching_hints = true;
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
    // Until the relay answers, ask briskly; once registered, keep the lease
    // and the NAT mapping alive.
    let mut retry = Duration::from_millis(500);
    let mut lease = Duration::from_secs(60);
    let mut send_failures = 0u32;
    // Registrations sent to the current address with nothing back yet.
    let mut unanswered = 0u32;
    let mut index = 0usize;
    // When the relay last confirmed the registration, and where it saw us.
    let mut confirmed_at = Instant::now();
    let mut observed: Option<SocketAddr> = None;
    loop {
        let now = Instant::now();
        // A whole lease without a confirmation: the relay has let the
        // registration go, or cannot hear us. Start over.
        if registered && now.saturating_duration_since(confirmed_at) > lease {
            tracing::warn!(
                "relay {} has not answered for {:?}; registering again",
                relay,
                lease
            );
            registered = false;
            retry = Duration::from_millis(500);
            unanswered = 0;
        }
        if now >= next_send {
            // Nothing back from this address after two tries: the next one
            // may do better (a broken IPv6 path is the usual case).
            if !registered && unanswered >= 2 && relays.len() > 1 {
                index = (index + 1) % relays.len();
                relay = relays[index];
                token = [0; TOKEN_LEN];
                unanswered = 0;
                tracing::debug!("relay: trying its address {}", relay);
            }
            let msg = signed(
                &key,
                Message::Register {
                    id,
                    token,
                    flags,
                    stamp: stamps.next(),
                    hints: Hints::told_to(&puncher.mine(), relay),
                    proof: [0; PROOF_LEN],
                },
            );
            match socket.send_to(&msg, relay).await {
                Ok(_) => {
                    send_failures = 0;
                    if registered {
                        next_send = now + keepalive.lock().next().min(lease / 2);
                    } else {
                        unanswered += 1;
                        next_send = now + retry;
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
                    if !registered {
                        unanswered += 1;
                    }
                    next_send = now + Duration::from_secs(2u64 << send_failures.min(4));
                }
            }
        }
        let wait = next_send.saturating_duration_since(Instant::now());
        let msg = tokio::select! {
            m = incoming.recv() => m,
            _ = tokio::time::sleep(wait) => continue,
            // What we know of our NAT has changed (its tests finished): say
            // so now, not at the next refresh.
            changed = hints_changed.changed(), if watching_hints => {
                match changed {
                    Ok(()) if registered => next_send = Instant::now(),
                    Ok(()) => {}
                    // Nothing will ever change it now.
                    Err(_) => watching_hints = false,
                }
                continue;
            }
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
        unanswered = 0;
        match msg {
            Message::Challenge { token: t } => {
                token = t;
                next_send = Instant::now();
            }
            Message::Registered {
                lease: secs,
                observed: seen,
            } => {
                lease = Duration::from_secs(secs.clamp(10, 3600) as u64);
                confirmed_at = Instant::now();
                match observed {
                    None => {
                        tracing::info!("relay {} reached; it sees us at {}", relay, seen);
                        on_registered(relay, seen);
                    }
                    // The mapping lapsed although it was being refreshed:
                    // the refreshes are too far apart for this NAT.
                    Some(before) if before != seen => {
                        let shorter = keepalive.lock().mapping_changed();
                        if shorter {
                            tracing::info!(
                                "our NAT gave us a new address towards relay {} ({} -> {}); \
                                 refreshing every {:?} from now on",
                                relay,
                                before,
                                seen,
                                keepalive.lock().interval()
                            );
                        } else {
                            tracing::info!(
                                "our NAT gave us a new address towards relay {} ({} -> {})",
                                relay,
                                before,
                                seen
                            );
                        }
                        on_registered(relay, seen);
                    }
                    Some(_) => {}
                }
                observed = Some(seen);
                registered = true;
                retry = Duration::from_millis(500);
                next_send = Instant::now() + keepalive.lock().next().min(lease / 2);
            }
            Message::Incoming {
                port,
                peer,
                ticket,
                hints: peer_hints,
            } => {
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
                let hidden = peer.ip().is_unspecified();
                let target = if hidden {
                    None
                } else if allowance >= 1.0 {
                    allowance -= 1.0;
                    Some(peer)
                } else {
                    tracing::debug!("relay {} is introducing too fast; not punching", relay);
                    None
                };
                // The sender's address in the other family, when it named
                // one. It belongs to the same introduction, so it costs no
                // allowance of its own; what bounds the datagrams sent
                // there is the puncher's own budget per address.
                let peer_hints = if hidden {
                    Hints::none()
                } else {
                    peer_hints.screened(peer)
                };
                let alt = target
                    .and(peer_hints.alt)
                    .and_then(|a| reach.native(a.addr).map(|addr| (addr, a.nat)));
                match &peer_hints.alt {
                    Some(a) if alt.is_some() => tracing::info!(
                        "relay {} is introducing {} (and {} in the other family)",
                        relay,
                        peer,
                        a.addr
                    ),
                    _ => tracing::info!("relay {} is introducing {}", relay, peer),
                }
                let socket = socket.clone();
                let puncher = puncher.clone();
                let cancel = cancel.clone();
                // Both jobs at once, and that is not a figure of speech.
                // Binding our side of the relay's port and pushing outwards
                // towards the sender are each spread over most of a second,
                // and hole punching only works while both ends are pushing
                // at the same time — running them one after the other would
                // have our first datagram leave after the sender's had
                // already been dropped by our NAT.
                tokio::spawn(async move {
                    let towards = async {
                        if let Some(peer) = target.and_then(|p| reach.native(p)) {
                            puncher.run(peer, peer_hints.nat, &cancel).await;
                        }
                    };
                    let towards_other_family = async {
                        if let Some((addr, nat)) = alt {
                            puncher.run(addr, nat, &cancel).await;
                        }
                    };
                    tokio::join!(
                        announce(&socket, relayed, ticket),
                        towards,
                        towards_other_family
                    );
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
                    // Not on the relay's list. Its operator may add us, so
                    // ask again now and then, not in a tight loop.
                    Refusal::Forbidden => {
                        if registered || unanswered == 0 {
                            tracing::warn!(
                                "relay {} serves only receivers on its list, and not this one",
                                relay
                            );
                        }
                        registered = false;
                        next_send = Instant::now() + Duration::from_secs(600);
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
