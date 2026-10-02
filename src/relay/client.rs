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
//! does not exist. Where no UDP gets through to the relay at all, they talk
//! to it over a stream instead ([`Via::Stream`], `relay::tunnel`): the same
//! messages, framed with the relay's port each is to or from.

use super::{Alt, Hints, Message, Refusal, NONCE_LEN, PROOF_LEN, TOKEN_LEN};
use crate::crypto::{Identity, SharpId};
use crate::nat::card::NatHints;
use crate::nat::punch::Puncher;
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Relay datagrams handed over by the socket's owner, with their source.
pub type Incoming = (Vec<u8>, SocketAddr);

/// How a client reaches its relay.
#[derive(Clone)]
pub enum Via {
    /// From the transfer socket, over UDP.
    Socket(Arc<UdpSocket>),
    /// Over a stream (see `relay::tunnel`). The relay is then known by its
    /// address with port 0 for its control port, and by its port for each of
    /// its pairs: a datagram goes on the stream tagged with the port of the
    /// address it is sent to. The transfer socket is still what punches go
    /// out from, and what says which addresses this host can reach.
    Stream {
        link: crate::transport::carrier::Link,
        socket: Arc<UdpSocket>,
    },
}

impl From<Arc<UdpSocket>> for Via {
    fn from(socket: Arc<UdpSocket>) -> Self {
        Via::Socket(socket)
    }
}

impl Via {
    async fn send_to(&self, datagram: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        match self {
            Via::Socket(s) => s.send_to(datagram, to).await,
            Via::Stream { link, .. } => {
                if link.send(to.port(), datagram) {
                    Ok(datagram.len())
                } else if link.is_closed() {
                    Err(std::io::ErrorKind::BrokenPipe.into())
                } else {
                    Err(std::io::ErrorKind::WouldBlock.into())
                }
            }
        }
    }

    /// The transfer socket.
    pub fn socket(&self) -> &Arc<UdpSocket> {
        match self {
            Via::Socket(s) | Via::Stream { socket: s, .. } => s,
        }
    }

    pub fn is_stream(&self) -> bool {
        matches!(self, Via::Stream { .. })
    }
}

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
    via: impl Into<Via>,
    relay: SocketAddr,
    target: SharpId,
    incoming: &mut mpsc::Receiver<Incoming>,
    cancel: &CancellationToken,
    auth: SenderAuth<'_>,
    hints: Hints,
) -> Result<Introduction, ConnectError> {
    connect_with(via, relay, target, incoming, cancel, auth, hints)
        .await
        .map(|(i, _)| i)
}

/// What it takes to ask a relay again for the same pair — a token it gave
/// us, and our proof if it wanted one: the same port back, and the
/// receiver introduced again, with what we know of our NAT by then (see
/// [`Refresh`]).
#[derive(Clone)]
pub struct Again {
    relay: SocketAddr,
    target: SharpId,
    token: [u8; TOKEN_LEN],
    identify: Option<(SharpId, crate::crypto::SecretKey)>,
}

impl Again {
    /// The request, and the nonce its answers have to carry back.
    fn message(&self, hints: Hints) -> ([u8; NONCE_LEN], Vec<u8>) {
        let nonce: [u8; NONCE_LEN] = rand::rngs::OsRng.gen();
        let bytes = match &self.identify {
            Some((id, key)) => signed(
                key,
                Message::ConnectAs {
                    target: self.target,
                    token: self.token,
                    hints,
                    nonce,
                    id: *id,
                    proof: [0; PROOF_LEN],
                },
            ),
            None => Message::Connect {
                target: self.target,
                token: self.token,
                hints,
                nonce,
            }
            .encode(),
        };
        (nonce, bytes)
    }
}

/// [`connect`], and what it takes to ask again ([`Again`]).
#[allow(clippy::too_many_arguments)]
pub async fn connect_with(
    via: impl Into<Via>,
    relay: SocketAddr,
    target: SharpId,
    incoming: &mut mpsc::Receiver<Incoming>,
    cancel: &CancellationToken,
    auth: SenderAuth<'_>,
    hints: Hints,
) -> Result<(Introduction, Again), ConnectError> {
    let via: Via = via.into();
    let mut token = [0u8; TOKEN_LEN];
    // What every answer to us has to carry back: without it, anybody who
    // can write the relay's address on a datagram could answer for it —
    // refuse us, or point our punches at whoever they liked.
    let nonce: [u8; NONCE_LEN] = rand::rngs::OsRng.gen();
    // Set once the relay has refused us as a stranger.
    let mut identify: Option<(SharpId, crate::crypto::SecretKey)> = None;
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
        let ask = match &identify {
            Some((id, key)) => signed(
                key,
                Message::ConnectAs {
                    target,
                    token,
                    hints,
                    nonce,
                    id: *id,
                    proof: [0; PROOF_LEN],
                },
            ),
            None => Message::Connect {
                target,
                token,
                hints,
                nonce,
            }
            .encode(),
        };
        if let Err(e) = via.send_to(&ask, relay).await {
            return Err(ConnectError::NoAnswer(format!(
                "cannot reach the relay {}: {}",
                relay, e
            )));
        }
        match wait_for(incoming, relay, REPLY_WAIT, |pkt| {
            super::echoes(&nonce, pkt)
        })
        .await
        {
            // The relay wants us to prove we receive where we say we do.
            Some(Message::Challenge { token: t, .. }) => token = t,
            Some(Message::Allocated {
                port,
                peer,
                ticket,
                hints: peer_hints,
                ..
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
                return Ok((
                    Introduction {
                        peer,
                        relayed,
                        ticket,
                        peer_hints: peer_hints.nat,
                        peer_alt: peer_hints.alt,
                    },
                    Again {
                        relay,
                        target,
                        token,
                        identify,
                    },
                ));
            }
            // A relay that serves only senders on its list: say who we
            // are, if we can prove it to this relay.
            Some(Message::Error {
                code: Refusal::Forbidden,
                ..
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
                ..
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
            Some(Message::Error { code, .. }) => {
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
    via: impl Into<Via>,
    relayed: SocketAddr,
    ticket: [u8; TOKEN_LEN],
    incoming: &mut mpsc::Receiver<Incoming>,
    cancel: &CancellationToken,
    refresh: Option<Refresh>,
) {
    let via: Via = via.into();
    // What asking again takes, apart from the two things it waits on, so
    // that each can be waited on while the other is.
    let (mut again, mut hints, mut nudge) = match refresh {
        Some(Refresh {
            again,
            hints,
            told,
            nudge,
            answers,
        }) => (Some((again, told, answers)), Some(hints), Some(nudge)),
        None => (None, None, None),
    };
    let mut watch_hints = hints.as_ref().is_some_and(|h| !h.borrow().is_known());
    // The request out, the nonce its answers carry, until when they are
    // taken, and the rounds left.
    let mut pending: Option<([u8; NONCE_LEN], Instant, u32)> = None;
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
                let _ = via.send_to(&ask, relayed).await;
                asked += 1;
                next = Instant::now() + REPEAT_GAP;
            }
            m = incoming.recv() => {
                let Some((pkt, from)) = m else { return };
                if let (Some((a, told, answers)), Some((nonce, until, rounds))) = (again.as_mut(), pending) {
                    if from == a.relay && super::echoes(&nonce, &pkt) && Instant::now() < until {
                        match Message::decode(&pkt) {
                            // Asked from another address than the token
                            // was for: a new one, and the request again.
                            Some(Message::Challenge { token, .. }) if rounds > 1 => {
                                a.token = token;
                                let (nonce, msg) = a.message(*told);
                                let _ = via.send_to(&msg, a.relay).await;
                                pending = Some((nonce, until, rounds - 1));
                            }
                            // Where the receiver is now, by the relay —
                            // on another port of its, if the receiver's
                            // address changed: the pair is another then,
                            // and this one goes on carrying as it did.
                            Some(Message::Allocated { peer, hints: said, .. }) => {
                                pending = None;
                                let peer = (!peer.ip().is_unspecified()).then_some(peer);
                                let said = match peer {
                                    Some(seen) => said.screened(seen),
                                    None => Hints::none(),
                                };
                                let _ = answers.send(Introduction {
                                    peer,
                                    relayed,
                                    ticket,
                                    peer_hints: said.nat,
                                    peer_alt: said.alt,
                                });
                            }
                            _ => {}
                        }
                        continue;
                    }
                }
                if from != relayed {
                    continue;
                }
                if let Some(Message::Confirm { proof }) = Message::decode(&pkt) {
                    let open = Message::Open { ticket, proof }.encode();
                    let _ = via.send_to(&open, relayed).await;
                }
            }
            changed = async { hints.as_mut().expect("guarded").changed().await }, if watch_hints => {
                let (Some((a, told, _)), Some(h)) = (again.as_mut(), hints.as_ref()) else {
                    watch_hints = false;
                    continue;
                };
                if changed.is_err() {
                    watch_hints = false;
                    continue;
                }
                let mine = *h.borrow();
                let now_told = Hints::told_to(&mine, a.relay);
                if now_told != *told {
                    tracing::info!(
                        "relay {}: this host's NAT tests are done; the receiver is told again",
                        a.relay
                    );
                    let (nonce, msg) = a.message(now_told);
                    let _ = via.send_to(&msg, a.relay).await;
                    pending = Some((nonce, Instant::now() + AGAIN_WAIT, AGAIN_ROUNDS));
                    *told = now_told;
                }
                if mine.is_known() {
                    watch_hints = false;
                }
            }
            changed = async { nudge.as_mut().expect("guarded").changed().await }, if nudge.is_some() => {
                let Some((a, told, _)) = again.as_mut().filter(|_| changed.is_ok()) else {
                    nudge = None;
                    continue;
                };
                tracing::info!(
                    "relay {}: asked again for the receiver, from where this host is now",
                    a.relay
                );
                if let Some(h) = &hints {
                    *told = Hints::told_to(&h.borrow(), a.relay);
                }
                let (nonce, msg) = a.message(*told);
                let _ = via.send_to(&msg, a.relay).await;
                pending = Some((nonce, Instant::now() + AGAIN_WAIT, AGAIN_ROUNDS));
            }
            _ = cancel.cancelled() => return,
        }
    }
}

/// What has [`hold`] ask the relay again for the same pair, and where the
/// answers go.
///
/// * When this end's NAT tests finish after the introduction went out: the
///   receiver aims its punches by them, and the introduction is not held up
///   for them (they take a second and more over IPv6).
/// * When the caller says so (`nudge`): the session fell back from a direct
///   path to the relay's port, which is what a change of network does to
///   it — ours, and the receiver punches at where we were; or the
///   receiver's, and we punch at where it was. Asked again from where we
///   are now, the relay introduces us to the receiver anew, and says where
///   the receiver is now (`answers`).
pub struct Refresh {
    pub again: Again,
    pub hints: tokio::sync::watch::Receiver<crate::nat::card::FamilyHints>,
    /// What the introduction said.
    pub told: Hints,
    pub nudge: tokio::sync::watch::Receiver<u64>,
    pub answers: mpsc::UnboundedSender<Introduction>,
}

/// How long the answers to asking again are taken after it, and how many
/// rounds (a challenge from the relay — another address of ours, another
/// token — and the request again) one nudge may cost.
const AGAIN_WAIT: Duration = Duration::from_secs(5);
const AGAIN_ROUNDS: u32 = 3;

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
///
/// `standing` says whether the relay holds the registration now: true from
/// its confirmation, false again once a whole lease has gone unconfirmed.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    via: impl Into<Via>,
    relays: Vec<SocketAddr>,
    relay_id: SharpId,
    identity: Identity,
    private: bool,
    mut incoming: mpsc::Receiver<Incoming>,
    cancel: CancellationToken,
    keepalive: crate::nat::keepalive::SharedKeepalive,
    puncher: Arc<Puncher>,
    standing: tokio::sync::watch::Sender<bool>,
    on_registered: impl Fn(SocketAddr, SocketAddr) + Send + 'static,
) {
    let via: Via = via.into();
    let socket = via.socket().clone();
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
    // Chosen now and put in every registration: what the relay sends us is
    // tagged with it and with the key above, and nothing it does not carry
    // is acted on — a datagram's source address is anybody's to write, and
    // a forged introduction would have us push datagrams at whoever it
    // named, a forged refusal take us off the relay (see `relay_tag`).
    let nonce: [u8; NONCE_LEN] = rand::rngs::OsRng.gen();
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
    let mut handled: std::collections::VecDeque<([u8; TOKEN_LEN], u16, Hints, SocketAddr)> =
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
    // When the last refresh left, while registered — what the NAT counts
    // its memory of the mapping from — and the interval the next one was
    // planned by.
    let mut refreshed_at = Instant::now();
    let mut planned = keepalive.lock().interval();
    loop {
        let now = Instant::now();
        // A shorter interval learnt meanwhile — the mapping's lifetime was
        // measured, or another refresh saw the mapping change — applies to
        // the refresh already planned, not only to those after it: the NAT
        // forgets on its own schedule, and a refresh planned by the old
        // interval would come after it had.
        if registered {
            let interval = keepalive.lock().interval();
            if interval < planned {
                planned = interval;
                let due = refreshed_at + keepalive.lock().next().min(lease / 2);
                if due < next_send {
                    next_send = due;
                }
            }
        }
        // A whole lease without a confirmation: the relay has let the
        // registration go, or cannot hear us. Start over.
        if registered && now.saturating_duration_since(confirmed_at) > lease {
            tracing::warn!(
                "relay {} has not answered for {:?}; registering again",
                relay,
                lease
            );
            registered = false;
            standing.send_replace(false);
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
                    nonce,
                    proof: [0; PROOF_LEN],
                },
            );
            match via.send_to(&msg, relay).await {
                Ok(_) => {
                    send_failures = 0;
                    if registered {
                        refreshed_at = now;
                        planned = keepalive.lock().interval();
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
        // Woken at least this often, to see whether the interval has
        // become shorter (above).
        let wait = next_send
            .saturating_duration_since(Instant::now())
            .min(crate::nat::keepalive::FLOOR);
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
                    goodbye(&via, relay, &key, id, token, nonce, &mut stamps, &mut incoming).await;
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
                if let Some((ticket, _, _, _)) =
                    handled.iter().find(|(_, p, _, _)| *p == from.port())
                {
                    let open = Message::Open {
                        ticket: *ticket,
                        proof,
                    };
                    let _ = via.send_to(&open.encode(), from).await;
                }
            }
            continue;
        }
        // Made by the relay for this run of ours, or at least an answer to
        // a request of ours; nothing else from its address is believed.
        let authentic = super::relay_tag_is_good(&key, &nonce, &pkt);
        if !authentic && !super::echoes(&nonce, &pkt) {
            tracing::debug!("relay {}: a message not made for us; ignored", relay);
            continue;
        }
        unanswered = 0;
        match msg {
            Message::Challenge { token: t, .. } => {
                token = t;
                next_send = Instant::now();
            }
            Message::Registered {
                lease: secs,
                observed: seen,
                ..
            } if authentic => {
                lease = Duration::from_secs(secs.clamp(10, 3600) as u64);
                confirmed_at = Instant::now();
                standing.send_replace(true);
                match observed {
                    None => {
                        tracing::info!("relay {} reached; it sees us at {}", relay, seen);
                        on_registered(relay, seen);
                    }
                    // The mapping lapsed although it was being refreshed:
                    // the refreshes are too far apart for this NAT. (Over a
                    // stream there is no mapping of ours to keep, and a new
                    // stream is seen from a new port.)
                    Some(before) if before != seen && !via.is_stream() => {
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
                if !registered {
                    refreshed_at = Instant::now();
                }
                registered = true;
                retry = Duration::from_millis(500);
                planned = keepalive.lock().interval();
                next_send = Instant::now() + keepalive.lock().next().min(lease / 2);
            }
            Message::Incoming {
                port,
                peer,
                ticket,
                hints: peer_hints,
                ..
            } if authentic => {
                let relayed = SocketAddr::new(relay.ip(), port);
                // The relay repeats an introduction until our side of the
                // port is bound, because a lost one would otherwise fail the
                // transfer silently. A repeat means the binding has not
                // happened yet, so it is worth saying which side we are
                // again — that goes to the relay's own address and costs
                // nothing — but it is not a new introduction, and must not
                // spend the allowance below or punch again.
                // A repeat that says more of the sender's NAT than the first
                // did is the sender's tests having finished after it asked:
                // worth punching again, by them, within the same allowance.
                // So is one from another address: the sender changed
                // networks, and asked again from where it is now.
                if let Some(h) = handled.iter_mut().find(|(t, _, _, _)| *t == ticket) {
                    let (new_hints, moved) = (h.2 != peer_hints, h.3 != peer);
                    h.2 = peer_hints;
                    h.3 = peer;
                    if !new_hints && !moved {
                        let via = via.clone();
                        tokio::spawn(async move { announce(&via, relayed, ticket).await });
                        continue;
                    }
                    if moved {
                        tracing::info!("relay {}: the sender is at {} now", relay, peer);
                    } else {
                        tracing::info!("relay {}: the sender says more of its NAT", relay);
                    }
                } else {
                    if handled.len() >= HANDLED_REMEMBERED {
                        handled.pop_front();
                    }
                    handled.push_back((ticket, port, peer_hints, peer));
                }
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
                let via = via.clone();
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
                        announce(&via, relayed, ticket),
                        towards,
                        towards_other_family
                    );
                });
            }
            Message::Error { code, .. } => {
                match code {
                    // Worth retrying, later. (Before it has checked who we
                    // are, a relay under load can only give our nonce back.)
                    Refusal::Busy => next_send = Instant::now() + Duration::from_secs(30),
                    // Our clock is behind what the relay last took from us.
                    // Nothing to do but wait for it to forget.
                    Refusal::Stale if authentic => {
                        tracing::warn!("relay {}: {}", relay, code.describe());
                        next_send = Instant::now() + Duration::from_secs(60);
                    }
                    // Not on the relay's list. Its operator may add us, so
                    // ask again now and then, not in a tight loop.
                    Refusal::Forbidden if authentic => {
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
#[allow(clippy::too_many_arguments)]
async fn goodbye(
    via: &Via,
    relay: SocketAddr,
    key: &crate::crypto::SecretKey,
    id: SharpId,
    mut token: [u8; TOKEN_LEN],
    nonce: [u8; NONCE_LEN],
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
                nonce,
                proof: [0; PROOF_LEN],
            },
        );
        if via.send_to(&bye, relay).await.is_err() {
            return;
        }
        match wait_for(incoming, relay, GOODBYE_WAIT, |pkt| {
            super::echoes(&nonce, pkt)
        })
        .await
        {
            Some(Message::Challenge { token: t, .. }) => token = t,
            _ => return,
        }
    }
}

/// Encodes a message and fills in its proof, which covers everything in
/// front of it.
fn signed(key: &crate::crypto::SecretKey, msg: Message) -> Vec<u8> {
    let mut bytes = msg.encode();
    let split = bytes.len() - PROOF_LEN;
    let proof = super::proof_for(key, &bytes[..split]);
    bytes[split..].copy_from_slice(&proof);
    bytes
}

/// Says which side of an allocation we are, repeatedly: the first may be
/// the one that opens the NAT rather than the one that arrives. Each draws
/// a confirmation from the port, which [`serve`] answers.
async fn announce(via: &Via, allocated: SocketAddr, ticket: [u8; TOKEN_LEN]) {
    let msg = Message::Open {
        ticket,
        proof: [0; TOKEN_LEN],
    }
    .encode();
    for i in 0..REPEATS {
        if via.send_to(&msg, allocated).await.is_err() {
            return;
        }
        if i + 1 < REPEATS {
            tokio::time::sleep(REPEAT_GAP).await;
        }
    }
}

/// Reads until a relay message from `relay` that `answers_us` takes
/// arrives, or the time is up. One it refuses — that does not carry what an
/// answer to us must — is passed over, as anything from elsewhere is: the
/// relay's address on a datagram proves nothing.
async fn wait_for(
    incoming: &mut mpsc::Receiver<Incoming>,
    relay: SocketAddr,
    within: Duration,
    answers_us: impl Fn(&[u8]) -> bool,
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
        if !answers_us(&pkt) {
            tracing::debug!(
                "relay {}: a message that answers nothing of ours; ignored",
                relay
            );
            continue;
        }
        if let Some(m) = Message::decode(&pkt) {
            return Some(m);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{auth_key, tagged, TAG_LEN};

    /// A relay of our own making on loopback: it answers the receiver's
    /// registrations as a real one does, and can send it anything else.
    struct FakeRelay {
        sock: UdpSocket,
        identity: Identity,
    }

    impl FakeRelay {
        /// The next registration from the receiver, its nonce, and where it
        /// came from.
        async fn registration(&self) -> ([u8; NONCE_LEN], SocketAddr) {
            let mut buf = [0u8; 512];
            loop {
                let (n, from) = self.sock.recv_from(&mut buf).await.unwrap();
                if let Some(Message::Register { nonce, .. }) = Message::decode(&buf[..n]) {
                    return (nonce, from);
                }
            }
        }
    }

    /// Nothing that arrives at `sock` within `within`: its datagrams.
    async fn heard(sock: &UdpSocket, within: Duration) -> usize {
        let mut buf = [0u8; 512];
        let mut n = 0;
        let deadline = tokio::time::Instant::now() + within;
        while tokio::time::timeout_at(deadline, sock.recv_from(&mut buf))
            .await
            .is_ok()
        {
            n += 1;
        }
        n
    }

    /// The introduction does not wait for this end's NAT tests: a sender
    /// holding its side of the pair tells the relay again once they are
    /// done — a Connect with the same token and what it now knows — and
    /// says nothing more while that does not change. Nudged (its session
    /// fell back to the relay's port: a change of network), it asks again,
    /// and passes on where the relay says the receiver is now; an answer
    /// that does not carry its nonce back is nobody's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_relay_is_told_again_once_the_nat_tests_are_done() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_at = relay.local_addr().unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (tx, mut rx) = mpsc::channel(8);
        let (nudge_tx, nudge_rx) = tokio::sync::watch::channel(0u64);
        let (answers_tx, mut answers) = mpsc::unbounded_channel();
        let (hints_tx, hints_rx) =
            tokio::sync::watch::channel(crate::nat::card::FamilyHints::unknown());
        let told = Hints::told_to(&crate::nat::card::FamilyHints::unknown(), relay_at);
        let target = Identity::generate().id();
        let token = [7u8; TOKEN_LEN];
        let again = Again {
            relay: relay_at,
            target,
            token,
            identify: None,
        };
        let cancel = CancellationToken::new();
        // Nothing of the pair's own: the port is nowhere, the relay's
        // control address only hears the refresh.
        let pair: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let holding = {
            let (socket, cancel) = (socket.clone(), cancel.clone());
            tokio::spawn(async move {
                hold(
                    socket,
                    pair,
                    [1; TOKEN_LEN],
                    &mut rx,
                    &cancel,
                    Some(Refresh {
                        again,
                        hints: hints_rx,
                        told,
                        nudge: nudge_rx,
                        answers: answers_tx,
                    }),
                )
                .await
            })
        };
        assert_eq!(heard(&relay, Duration::from_millis(300)).await, 0);
        // The tests finish: one Connect, with them and the same token.
        let mut mine = crate::nat::card::FamilyHints::unknown();
        mine.v4.mapping = 1;
        mine.v4.filtering = 3;
        hints_tx.send(mine).unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
            .await
            .expect("the relay is told again")
            .unwrap();
        match Message::decode(&buf[..n]) {
            Some(Message::Connect {
                target: t,
                token: k,
                hints,
                ..
            }) => {
                assert_eq!((t, k), (target, token));
                assert_eq!(hints, Hints::told_to(&mine, relay_at));
            }
            other => panic!("{:?}", other),
        }
        // Known now: nothing more, even if the hints change again.
        mine.v4.delta = 1;
        let _ = hints_tx.send(mine);
        assert_eq!(heard(&relay, Duration::from_millis(300)).await, 0);

        // Nudged: asked again, and the answer passed on.
        nudge_tx.send_modify(|n| *n += 1);
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
            .await
            .expect("asked again")
            .unwrap();
        let Some(Message::Connect { nonce, .. }) = Message::decode(&buf[..n]) else {
            panic!("{:?}", Message::decode(&buf[..n]))
        };
        let now_at: SocketAddr = "192.0.2.7:4444".parse().unwrap();
        let answer = |tag| {
            Message::Allocated {
                port: pair.port(),
                peer: now_at,
                ticket: [1; TOKEN_LEN],
                hints: Hints::none(),
                tag,
            }
            .encode()
        };
        tx.send((answer([9; TAG_LEN]), relay_at)).await.unwrap();
        tx.send((answer(nonce), relay_at)).await.unwrap();
        let i = tokio::time::timeout(Duration::from_secs(5), answers.recv())
            .await
            .expect("passed on")
            .unwrap();
        assert_eq!(i.peer, Some(now_at));
        assert!(answers.try_recv().is_err(), "the forged one is not");
        cancel.cancel();
        holding.await.unwrap();
    }

    /// Only what the relay made for this receiver is acted on. An
    /// introduction "from the relay" with anything else for a tag — which
    /// anybody who can write the relay's address on a datagram could send —
    /// has the receiver push not a single datagram at the address it names,
    /// and a confirmation with a made-up address changes nothing; the real
    /// ones, tagged with the key the registration was proven with and the
    /// receiver's nonce, work as they always did.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_what_the_relay_made_for_us_is_acted_on() {
        let relay = FakeRelay {
            sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            identity: Identity::generate(),
        };
        let relay_addr = relay.sock.local_addr().unwrap();
        let relay_id = relay.identity.id();
        let receiver = Identity::generate();
        let rid = receiver.id();
        let key = auth_key(&relay.identity, &rid, &rid, &relay_id).unwrap();

        // The receiver's socket, and the engine's part: handing it what the
        // relay sends.
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (tx, rx) = mpsc::channel(64);
        let reader = {
            let socket = socket.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                    if tx.send((buf[..n].to_vec(), from)).await.is_err() {
                        return;
                    }
                }
            })
        };
        let told = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let cancel = CancellationToken::new();
        let serving = {
            let told = told.clone();
            tokio::spawn(serve(
                socket.clone(),
                vec![relay_addr],
                relay_id,
                receiver,
                false,
                rx,
                cancel.clone(),
                Arc::new(parking_lot::Mutex::new(
                    crate::nat::keepalive::Keepalive::new(Duration::from_secs(15)),
                )),
                Arc::new(Puncher::without_hints(socket.clone())),
                tokio::sync::watch::channel(false).0,
                move |_relay, seen| told.lock().push(seen),
            ))
        };

        // Registered, as a relay does it: a challenge, then the confirmation.
        let (nonce, from) = relay.registration().await;
        let challenge = Message::Challenge {
            token: [7; TOKEN_LEN],
            tag: nonce,
        };
        relay.sock.send_to(&challenge.encode(), from).await.unwrap();
        let (again, _) = relay.registration().await;
        assert_eq!(again, nonce, "one nonce for all of a run's registrations");
        let registered = Message::Registered {
            lease: 60,
            observed: from,
            tag: [0; TAG_LEN],
        };
        let bytes = tagged(&key, &nonce, &registered);
        relay.sock.send_to(&bytes, from).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            told.lock().as_slice(),
            &[from],
            "the real confirmation counts"
        );

        // A confirmation with a made-up address and no tag of the relay's:
        // not believed.
        let elsewhere: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let forged = Message::Registered {
            lease: 60,
            observed: elsewhere,
            tag: nonce,
        };
        relay.sock.send_to(&forged.encode(), from).await.unwrap();

        // An introduction naming a stranger, with a tag that is not the
        // relay's for us (the nonce alone, and nothing at all).
        let victim = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let spare = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for tag in [nonce, [0; TAG_LEN]] {
            let forged = Message::Incoming {
                port: spare.local_addr().unwrap().port(),
                peer: victim.local_addr().unwrap(),
                ticket: [1; TOKEN_LEN],
                hints: Hints::none(),
                tag,
            };
            relay.sock.send_to(&forged.encode(), from).await.unwrap();
        }
        assert_eq!(
            heard(&victim, Duration::from_millis(1500)).await,
            0,
            "a forged introduction had the receiver push datagrams at a stranger"
        );
        assert_eq!(heard(&spare, Duration::from_millis(100)).await, 0);
        assert_eq!(
            told.lock().as_slice(),
            &[from],
            "a forged confirmation was believed"
        );

        // The relay's own introduction is acted on.
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let real = Message::Incoming {
            port: spare.local_addr().unwrap().port(),
            peer: sender.local_addr().unwrap(),
            ticket: [2; TOKEN_LEN],
            hints: Hints::none(),
            tag: [0; TAG_LEN],
        };
        relay
            .sock
            .send_to(&tagged(&key, &nonce, &real), from)
            .await
            .unwrap();
        assert!(
            heard(&sender, Duration::from_millis(1500)).await > 0,
            "the real introduction was not acted on"
        );
        assert!(
            heard(&spare, Duration::from_millis(500)).await > 0,
            "the receiver did not take its side of the relay's port"
        );

        cancel.cancel();
        let _ = serving.await;
        reader.abort();
    }
}
