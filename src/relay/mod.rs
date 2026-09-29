//! Meeting through a relay, when the two ends cannot meet directly.
//!
//! A port forward or a stable NAT mapping gets a receiver reached in most
//! cases. What is left is the case nothing on either side can fix: both
//! peers behind NATs that give out a different external port for every
//! destination. Then no address either one can publish is the address the
//! other would need, and the only way through is a third party both can
//! reach — which is what TURN (RFC 8656) is for, and what this is.
//!
//! The relay does two jobs, in this order:
//!
//! 1. **Rendezvous.** It knows where both peers are, so it tells each the
//!    other's address and they try to reach each other directly, both
//!    sending at once. Where the NATs allow it, that opens a direct path and
//!    the relay carries nothing.
//! 2. **Forwarding.** When that fails, the relay allocates a UDP port for
//!    the pair and copies datagrams between them. The transfer then runs
//!    over it unchanged: to each peer the relay is simply the address the
//!    other one appears to be at.
//!
//! ## What the relay is not trusted with
//!
//! Nothing. It carries SHARP-256 transport packets, which are sealed
//! end to end: it cannot read them, cannot alter one without the AEAD
//! rejecting it, and cannot inject one without the peers' keys. It cannot
//! impersonate a peer either, because completing a SHARP handshake takes
//! that peer's private key — so the worst a hostile relay achieves is
//! refusing to carry the traffic, which any relay can do by existing.
//!
//! Registering an identity is therefore not a privilege worth guarding
//! heavily: somebody who registers an identity that is not theirs gets
//! senders connected to them and then fails the handshake, which is denial
//! of service on one path and nothing more. What is guarded is the cheap
//! abuse — a registration from a forged source address would point a relay's
//! traffic at a stranger, so the relay hands out a token bound to the
//! address it saw and only accepts a registration that echoes it back.
//!
//! This is also the honest answer to hiding one's own address from a peer:
//! run traffic through a relay you control. Forging a source address is not
//! an alternative — a transfer needs a return path, and it is an attack
//! technique rather than a defence.

pub mod client;
pub mod server;

use crate::crypto::{Identity, SharpId};
use crate::nat::card::{FamilyHints, NatHints};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use subtle::ConstantTimeEq;

/// Every relay control message starts with this. Data the relay forwards
/// never does: a SHARP packet begins with a random connection id, and the
/// endpoints refuse to pick the one value that would collide.
pub const MAGIC: [u8; 8] = crate::protocol::constants::RESERVED_CID.to_be_bytes();
/// Smallest control message: magic and a type byte.
pub const HEADER_LEN: usize = MAGIC.len() + 1;
/// A token proving the holder receives at the address it claims.
pub const TOKEN_LEN: usize = 16;
/// Proof that a registration is made by whoever owns the identity it
/// claims.
pub const PROOF_LEN: usize = 16;

/// A registration asks the relay to send people to us. Whoever owns the
/// identity is the only one who should be able to ask.
///
/// The two sides already know each other's long-term public keys — the peer
/// is given the relay's in its address, and the relay reads the peer's out
/// of the registration — so a static Diffie-Hellman between them is a
/// secret only those two can compute, with nothing to exchange first. That
/// is useless for a session, having no forward secrecy and nothing fresh in
/// it, which is why transfers use a proper handshake; it is exactly right
/// for proving to someone who knows your public key that you hold the
/// private one.
///
/// Both sides derive the same key: the public keys go into it in a fixed
/// order, peer first, so it does not matter which of the two is computing.
///
/// `None` when the other side's key is a small-order point. The exchange
/// would then come out the same whatever our secret is, so the "key" would
/// be one anybody could compute — and an identity nobody holds could be
/// registered by anyone.
pub fn auth_key(
    ours: &Identity,
    theirs: &SharpId,
    peer: &SharpId,
    relay: &SharpId,
) -> Option<[u8; 32]> {
    let dh = ours.shared_secret(theirs)?;
    let mut material = zeroize::Zeroizing::new([0u8; 96]);
    material[..32].copy_from_slice(&dh[..]);
    material[32..64].copy_from_slice(peer.as_bytes());
    material[64..].copy_from_slice(relay.as_bytes());
    Some(blake3::derive_key(
        "sharp256 relay v1 registration",
        &material[..],
    ))
}

/// The proof carried by a message, over everything in it that precedes it.
pub fn proof_for(key: &[u8; 32], signed: &[u8]) -> [u8; PROOF_LEN] {
    let mut out = [0u8; PROOF_LEN];
    out.copy_from_slice(&blake3::keyed_hash(key, signed).as_bytes()[..PROOF_LEN]);
    out
}

/// Whether `pkt` carries a proof that matches `key`. The proof covers the
/// whole message before it, so nothing in it can be altered in flight.
pub fn proof_is_good(key: &[u8; 32], pkt: &[u8]) -> bool {
    let Some(split) = pkt.len().checked_sub(PROOF_LEN) else {
        return false;
    };
    let (signed, given) = pkt.split_at(split);
    bool::from(proof_for(key, signed).ct_eq(given))
}

/// Registration flags.
/// The receiver's address is not to be disclosed to anyone asking for it;
/// everything goes through the relay instead. It costs the relay's
/// bandwidth and gives up the direct path, and it is the only way the relay
/// actually hides where you are.
pub const REGISTER_PRIVATE: u8 = 0x01;
/// Longest control message. Everything here is far smaller.
pub const MAX_MESSAGE: usize = 192;

/// Where a peer can be reached in the address family the relay did not see
/// it in, and how the NAT (or firewall) in front of that path behaves.
///
/// A relay sees a peer over one family — whichever its registration or its
/// request came in on — and can say nothing of the other. On a host with
/// both, that is exactly the path worth trying: IPv6 has no NAT to punch
/// through, and two IPv4 NATs that give out a new port for every
/// destination cannot be punched at all. Without this, the two peers would
/// learn of each other's IPv6 addresses only once they were already
/// talking — too late for a firewall that lets in nothing but what its own
/// side sent out first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alt {
    pub addr: SocketAddr,
    pub nat: NatHints,
}

/// What a peer tells a relay about itself, for the relay to hand on to
/// whoever it is put through to. Advice, not authority: the proof on a
/// registration covers it only so that nobody on the way can change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hints {
    /// How the NAT in front of the address the relay sees behaves.
    pub nat: NatHints,
    /// The other family's address, when there is one worth naming.
    pub alt: Option<Alt>,
}

impl Hints {
    /// Nothing to say.
    pub const fn none() -> Self {
        Self {
            nat: NatHints::unknown(),
            alt: None,
        }
    }

    /// What to tell a relay reached at `via`: how the NAT in front of that
    /// family behaves, and where the other family can be aimed at.
    pub fn told_to(mine: &FamilyHints, via: SocketAddr) -> Self {
        let (nat, alt) = if crate::address::canonical(via).is_ipv6() {
            (mine.v6, mine.aim4.map(|addr| Alt { addr, nat: mine.v4 }))
        } else {
            (mine.v4, mine.aim6.map(|addr| Alt { addr, nat: mine.v6 }))
        };
        Self { nat, alt }
    }

    /// What is worth passing on from a peer seen at `seen`: the other
    /// family's address only if it really is the other family and one the
    /// internet routes. A peer may name anything, and what is named ends up
    /// as a place somebody else sends datagrams to.
    pub fn screened(self, seen: SocketAddr) -> Self {
        let seen = crate::address::canonical(seen);
        Self {
            nat: self.nat,
            // Passed on in its plain spelling, so that "IPv4 written the
            // IPv6 way" is neither taken for the other family nor handed
            // to somebody whose socket would not know what to do with it.
            alt: self
                .alt
                .map(|a| Alt {
                    addr: crate::address::canonical(a.addr),
                    nat: a.nat,
                })
                .filter(|a| {
                    a.addr.port() != 0
                        && a.addr.is_ipv6() != seen.is_ipv6()
                        && crate::address::class::is_global(a.addr.ip())
                }),
        }
    }
}

/// The connection id a SHARP packet must never use, because a relay would
/// read it as one of these messages instead.
pub fn reserved_cid() -> u64 {
    crate::protocol::constants::RESERVED_CID
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Kind {
    Register = 1,
    Challenge = 2,
    Registered = 3,
    Connect = 4,
    Allocated = 5,
    Incoming = 6,
    Error = 7,
    Open = 8,
    Punch = 9,
    Bye = 10,
    Confirm = 11,
    ConnectAs = 12,
}

impl Kind {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Kind::Register,
            2 => Kind::Challenge,
            3 => Kind::Registered,
            4 => Kind::Connect,
            5 => Kind::Allocated,
            6 => Kind::Incoming,
            7 => Kind::Error,
            8 => Kind::Open,
            9 => Kind::Punch,
            10 => Kind::Bye,
            11 => Kind::Confirm,
            12 => Kind::ConnectAs,
            _ => return None,
        })
    }
}

/// Why the relay would not do what was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Refusal {
    /// Nobody has registered that identity here.
    Unknown = 1,
    /// The token was missing, stale, or for another address.
    BadToken = 2,
    /// The relay is at its limit.
    Busy = 3,
    /// The message is older than one the relay already took for the same
    /// identity: a replay, or a clock that went backwards.
    Stale = 4,
    /// The relay serves only identities on its list, and this one is not,
    /// or did not say who it is.
    Forbidden = 5,
}

impl Refusal {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Refusal::Unknown,
            2 => Refusal::BadToken,
            3 => Refusal::Busy,
            4 => Refusal::Stale,
            5 => Refusal::Forbidden,
            _ => return None,
        })
    }

    pub fn describe(self) -> &'static str {
        match self {
            Refusal::Unknown => "the relay has no registration for that receiver",
            Refusal::BadToken => "the relay did not accept the token",
            Refusal::Busy => "the relay is at its limit",
            Refusal::Stale => {
                "the relay has already seen a newer message from this identity \
                 (a replay, or this host's clock went backwards)"
            }
            Refusal::Forbidden => "the relay serves only identities on its list, and not this one",
        }
    }
}

/// A relay control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Peer → relay: "reachable here as this identity". Also the keepalive;
    /// the token is zero the first time and the one the relay issued after.
    Register {
        id: SharpId,
        token: [u8; TOKEN_LEN],
        /// See [`REGISTER_PRIVATE`].
        flags: u8,
        /// Strictly increasing per identity. The proof binds everything in
        /// the message to the owner, but nothing in it is fresh apart from
        /// this: without it, a registration captured from the owner's
        /// address could be sent again later — to move the registration
        /// back to an old address, or to turn a private one public.
        stamp: u64,
        /// What the sender of this knows of its own NAT, for the relay to
        /// hand to whoever asks for it (see [`NatHints`]). Advice, not
        /// authority: the proof covers it, but only so that nobody on the
        /// way can change it.
        hints: Hints,
        /// Proof that this is the identity's owner asking.
        proof: [u8; PROOF_LEN],
    },
    /// Relay → peer: "prove you receive where you say you do" — repeat the
    /// registration with this token.
    Challenge {
        token: [u8; TOKEN_LEN],
    },
    /// Relay → peer: registered, for this many seconds, and this is the
    /// address the relay sees you at.
    Registered {
        lease: u32,
        observed: SocketAddr,
    },
    /// Sender → relay: "put me through to this identity".
    Connect {
        target: SharpId,
        token: [u8; TOKEN_LEN],
        /// The sender's own, for the receiver to be told.
        hints: Hints,
    },
    /// Sender → relay: the same, saying who is asking and proving it, for a
    /// relay that serves only identities on its list. The proof is made as
    /// a registration's is, over this message, so it cannot be moved onto
    /// another.
    ConnectAs {
        target: SharpId,
        token: [u8; TOKEN_LEN],
        hints: Hints,
        id: SharpId,
        proof: [u8; PROOF_LEN],
    },
    /// Relay → sender: a port has been set aside for the pair, and the
    /// receiver appears to be at this address — worth trying directly
    /// first, both ends sending at once. The ticket says which side of the
    /// allocation we are.
    Allocated {
        port: u16,
        peer: SocketAddr,
        ticket: [u8; TOKEN_LEN],
        /// What the receiver said of its NAT when it registered: how to aim
        /// at it when its address alone is not enough.
        hints: Hints,
    },
    /// Relay → receiver: somebody is coming through on this port, and they
    /// appear to be at this address. Send an [`Message::Open`] to the port
    /// so the NAT lets the relay's traffic back in.
    Incoming {
        port: u16,
        peer: SocketAddr,
        ticket: [u8; TOKEN_LEN],
        /// What the sender said of its NAT.
        hints: Hints,
    },
    Error {
        code: Refusal,
    },
    /// Peer → relay, at an allocated port: nothing to carry. It says which
    /// side is speaking and, just as importantly, opens the way back
    /// through the NAT — which is why the relay cannot simply assume a
    /// peer's address here. The NAT it is behind is very likely the kind
    /// that hands out a different port for every destination, which is what
    /// the relay exists for in the first place.
    ///
    /// A side is only bound once it has shown it receives at the address
    /// it speaks from: the first Open carries a zero `proof` and draws a
    /// [`Message::Confirm`] back to that address, and the side repeats the
    /// Open with what the confirmation said. A forged source address never
    /// sees the confirmation, so it can bind nothing — and in particular
    /// cannot bind one of the relay's own ports, which would set two
    /// allocations forwarding a datagram to each other for ever.
    Open {
        ticket: [u8; TOKEN_LEN],
        proof: [u8; TOKEN_LEN],
    },
    /// Relay → peer, from an allocated port: repeat your Open with this.
    Confirm {
        proof: [u8; TOKEN_LEN],
    },
    /// Peer → peer, not to the relay at all: a datagram whose only purpose
    /// is to make the sender's own NAT open a way back for the other side.
    /// The receiver sends a few of these the moment the relay introduces
    /// the two, so that both ends are pushing outwards at the same time —
    /// which is the whole of hole punching. Whoever gets one ignores it.
    Punch,
    /// Peer → relay: I am going away, forget me. Without it the relay would
    /// keep sending people to an address nothing answers at until the lease
    /// ran out, which is the difference between a sender failing over in a
    /// moment and failing over in two minutes.
    Bye {
        id: SharpId,
        token: [u8; TOKEN_LEN],
        /// Newer than the registration it ends; see `Register::stamp`. An
        /// old goodbye sent again must not end a registration made since.
        stamp: u64,
        proof: [u8; PROOF_LEN],
    },
}

/// Splits how a relay is written down.
///
/// A receiver must be given the relay's identity — `ID@host:port` — because
/// registering means proving ownership of *our* identity against *its*
/// public key, and there is nothing to prove against without it. A sender
/// may write the address alone, and then never names itself; given the
/// relay's identity too, it proves its own when the relay refuses strangers
/// — which a relay that puts through only the senders it lists does, and
/// which anyone on the path could fake.
pub fn parse_relay(s: &str) -> Result<(Option<SharpId>, String), String> {
    let s = s.trim();
    let (id, host) = match s.rsplit_once('@') {
        Some((id, host)) => {
            let id: SharpId = id.parse().map_err(|e| format!("relay ID: {}", e))?;
            (Some(id), host)
        }
        None => (None, s),
    };
    if host.is_empty() || !host.contains(':') {
        return Err(format!("\"{}\" is not <host>:<port>", host));
    }
    Ok((id, host.to_string()))
}

/// True when a datagram is a relay control message rather than traffic.
pub fn is_control(pkt: &[u8]) -> bool {
    pkt.len() >= HEADER_LEN && pkt[..MAGIC.len()] == MAGIC
}

fn put_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&addr.port().to_be_bytes());
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&addr.port().to_be_bytes());
            out.extend_from_slice(&v6.octets());
        }
    }
}

fn take_addr(buf: &[u8], pos: &mut usize) -> Option<SocketAddr> {
    let fam = *buf.get(*pos)?;
    let port = u16::from_be_bytes(buf.get(*pos + 1..*pos + 3)?.try_into().ok()?);
    match fam {
        4 => {
            let ip: [u8; 4] = buf.get(*pos + 3..*pos + 7)?.try_into().ok()?;
            *pos += 7;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        6 => {
            let ip: [u8; 16] = buf.get(*pos + 3..*pos + 19)?.try_into().ok()?;
            *pos += 19;
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => None,
    }
}

/// Hints are advice, but they are read like everything else here: a value
/// this version would not have written is not guessed at, and the message
/// carrying it is refused (there is one encoding of each message, which the
/// fuzzing target insists on).
fn take_hints(buf: &[u8], pos: &mut usize) -> Option<Hints> {
    let nat = take_nat(buf, pos)?;
    // No other family's address is a single zero byte; one is written as an
    // address, which starts with its family (4 or 6).
    let alt = match *buf.get(*pos)? {
        0 => {
            *pos += 1;
            None
        }
        _ => {
            let addr = take_addr(buf, pos)?;
            Some(Alt {
                addr,
                nat: take_nat(buf, pos)?,
            })
        }
    };
    Some(Hints { nat, alt })
}

fn take_nat(buf: &[u8], pos: &mut usize) -> Option<NatHints> {
    let raw: [u8; NatHints::WIRE_LEN] =
        buf.get(*pos..*pos + NatHints::WIRE_LEN)?.try_into().ok()?;
    *pos += NatHints::WIRE_LEN;
    NatHints::from_bytes(&raw)
}

fn put_hints(out: &mut Vec<u8>, hints: &Hints) {
    out.extend_from_slice(&hints.nat.to_bytes());
    match &hints.alt {
        None => out.push(0),
        Some(alt) => {
            put_addr(out, alt.addr);
            out.extend_from_slice(&alt.nat.to_bytes());
        }
    }
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 96);
        out.extend_from_slice(&MAGIC);
        match self {
            Message::Register {
                id,
                token,
                flags,
                stamp,
                hints,
                proof,
            } => {
                out.push(Kind::Register as u8);
                out.extend_from_slice(id.as_bytes());
                out.extend_from_slice(token);
                out.push(*flags);
                out.extend_from_slice(&stamp.to_be_bytes());
                put_hints(&mut out, hints);
                out.extend_from_slice(proof);
            }
            Message::Challenge { token } => {
                out.push(Kind::Challenge as u8);
                out.extend_from_slice(token);
            }
            Message::Registered { lease, observed } => {
                out.push(Kind::Registered as u8);
                out.extend_from_slice(&lease.to_be_bytes());
                put_addr(&mut out, *observed);
            }
            Message::Connect {
                target,
                token,
                hints,
            } => {
                out.push(Kind::Connect as u8);
                out.extend_from_slice(target.as_bytes());
                out.extend_from_slice(token);
                put_hints(&mut out, hints);
            }
            Message::ConnectAs {
                target,
                token,
                hints,
                id,
                proof,
            } => {
                out.push(Kind::ConnectAs as u8);
                out.extend_from_slice(target.as_bytes());
                out.extend_from_slice(token);
                put_hints(&mut out, hints);
                out.extend_from_slice(id.as_bytes());
                out.extend_from_slice(proof);
            }
            Message::Allocated {
                port,
                peer,
                ticket,
                hints,
            } => {
                out.push(Kind::Allocated as u8);
                out.extend_from_slice(&port.to_be_bytes());
                put_addr(&mut out, *peer);
                out.extend_from_slice(ticket);
                put_hints(&mut out, hints);
            }
            Message::Incoming {
                port,
                peer,
                ticket,
                hints,
            } => {
                out.push(Kind::Incoming as u8);
                out.extend_from_slice(&port.to_be_bytes());
                put_addr(&mut out, *peer);
                out.extend_from_slice(ticket);
                put_hints(&mut out, hints);
            }
            Message::Error { code } => {
                out.push(Kind::Error as u8);
                out.push(*code as u8);
            }
            Message::Open { ticket, proof } => {
                out.push(Kind::Open as u8);
                out.extend_from_slice(ticket);
                out.extend_from_slice(proof);
            }
            Message::Confirm { proof } => {
                out.push(Kind::Confirm as u8);
                out.extend_from_slice(proof);
            }
            Message::Punch => out.push(Kind::Punch as u8),
            Message::Bye {
                id,
                token,
                stamp,
                proof,
            } => {
                out.push(Kind::Bye as u8);
                out.extend_from_slice(id.as_bytes());
                out.extend_from_slice(token);
                out.extend_from_slice(&stamp.to_be_bytes());
                out.extend_from_slice(proof);
            }
        }
        debug_assert!(out.len() <= MAX_MESSAGE);
        out
    }

    /// Reads a control message. Anything that is not exactly one is refused;
    /// these arrive from strangers, so nothing is guessed at.
    pub fn decode(pkt: &[u8]) -> Option<Self> {
        if !is_control(pkt) || pkt.len() > MAX_MESSAGE {
            return None;
        }
        let kind = Kind::from_u8(pkt[MAGIC.len()])?;
        let body = &pkt[HEADER_LEN..];
        // How much of the body the message accounts for; anything left over
        // means this is not the message it claims to be.
        let mut pos;
        let msg = match kind {
            Kind::Register | Kind::Connect | Kind::Bye => {
                let key: [u8; 32] = body.get(0..32)?.try_into().ok()?;
                let token: [u8; TOKEN_LEN] = body.get(32..32 + TOKEN_LEN)?.try_into().ok()?;
                let id = SharpId::from_public(key);
                pos = 32 + TOKEN_LEN;
                match kind {
                    Kind::Register => {
                        let flags = *body.get(pos)?;
                        pos += 1;
                        let stamp = u64::from_be_bytes(body.get(pos..pos + 8)?.try_into().ok()?);
                        pos += 8;
                        let hints = take_hints(body, &mut pos)?;
                        let proof: [u8; PROOF_LEN] =
                            body.get(pos..pos + PROOF_LEN)?.try_into().ok()?;
                        pos += PROOF_LEN;
                        Message::Register {
                            id,
                            token,
                            flags,
                            stamp,
                            hints,
                            proof,
                        }
                    }
                    Kind::Connect => {
                        let hints = take_hints(body, &mut pos)?;
                        Message::Connect {
                            target: id,
                            token,
                            hints,
                        }
                    }
                    _ => {
                        let stamp = u64::from_be_bytes(body.get(pos..pos + 8)?.try_into().ok()?);
                        pos += 8;
                        let proof: [u8; PROOF_LEN] =
                            body.get(pos..pos + PROOF_LEN)?.try_into().ok()?;
                        pos += PROOF_LEN;
                        Message::Bye {
                            id,
                            token,
                            stamp,
                            proof,
                        }
                    }
                }
            }
            Kind::ConnectAs => {
                let target: [u8; 32] = body.get(0..32)?.try_into().ok()?;
                let token: [u8; TOKEN_LEN] = body.get(32..32 + TOKEN_LEN)?.try_into().ok()?;
                pos = 32 + TOKEN_LEN;
                let hints = take_hints(body, &mut pos)?;
                let id: [u8; 32] = body.get(pos..pos + 32)?.try_into().ok()?;
                pos += 32;
                let proof: [u8; PROOF_LEN] = body.get(pos..pos + PROOF_LEN)?.try_into().ok()?;
                pos += PROOF_LEN;
                Message::ConnectAs {
                    target: SharpId::from_public(target),
                    token,
                    hints,
                    id: SharpId::from_public(id),
                    proof,
                }
            }
            Kind::Challenge => {
                pos = TOKEN_LEN;
                Message::Challenge {
                    token: body.get(0..TOKEN_LEN)?.try_into().ok()?,
                }
            }
            Kind::Registered => {
                let lease = u32::from_be_bytes(body.get(0..4)?.try_into().ok()?);
                pos = 4;
                Message::Registered {
                    lease,
                    observed: take_addr(body, &mut pos)?,
                }
            }
            Kind::Allocated | Kind::Incoming => {
                let port = u16::from_be_bytes(body.get(0..2)?.try_into().ok()?);
                pos = 2;
                let peer = take_addr(body, &mut pos)?;
                let ticket: [u8; TOKEN_LEN] = body.get(pos..pos + TOKEN_LEN)?.try_into().ok()?;
                pos += TOKEN_LEN;
                let hints = take_hints(body, &mut pos)?;
                if kind == Kind::Allocated {
                    Message::Allocated {
                        port,
                        peer,
                        ticket,
                        hints,
                    }
                } else {
                    Message::Incoming {
                        port,
                        peer,
                        ticket,
                        hints,
                    }
                }
            }
            Kind::Error => {
                pos = 1;
                Message::Error {
                    code: Refusal::from_u8(*body.first()?)?,
                }
            }
            Kind::Open => {
                pos = 2 * TOKEN_LEN;
                Message::Open {
                    ticket: body.get(0..TOKEN_LEN)?.try_into().ok()?,
                    proof: body.get(TOKEN_LEN..2 * TOKEN_LEN)?.try_into().ok()?,
                }
            }
            Kind::Confirm => {
                pos = TOKEN_LEN;
                Message::Confirm {
                    proof: body.get(0..TOKEN_LEN)?.try_into().ok()?,
                }
            }
            Kind::Punch => {
                pos = 0;
                Message::Punch
            }
        };
        // Nothing real has anything after its fields, so trailing bytes
        // mean this is not the message it claims to be.
        if pos != body.len() {
            return None;
        }
        Some(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    fn roundtrip(m: Message) {
        let bytes = m.encode();
        assert!(is_control(&bytes), "{:?} is not recognisable", m);
        assert!(bytes.len() <= MAX_MESSAGE);
        assert_eq!(Message::decode(&bytes).as_ref(), Some(&m));
    }

    /// The hints a message carries survive the wire, and a value this
    /// version would not write is refused.
    #[test]
    fn hints_ride_along_and_invalid_ones_are_refused() {
        use crate::nat::behaviour::Allocation;
        let nat = NatHints {
            mapping: 3,
            filtering: 2,
            allocation: Allocation::Sequential,
            delta: -4,
            hairpin: Some(true),
            cgn: true,
        };
        let plain = Hints { nat, alt: None };
        let with_v6 = Hints {
            nat,
            alt: Some(Alt {
                addr: "[2a0e:aa00:1:1::1]:40000".parse().unwrap(),
                nat: NatHints {
                    mapping: 4,
                    filtering: 3,
                    ..NatHints::unknown()
                },
            }),
        };
        let with_v4 = Hints {
            nat,
            alt: Some(Alt {
                addr: "198.18.0.1:7".parse().unwrap(),
                nat: NatHints::unknown(),
            }),
        };
        let id = Identity::generate().id();
        for hints in [plain, with_v6, with_v4] {
            roundtrip(Message::Connect {
                target: id,
                token: [1; TOKEN_LEN],
                hints,
            });
            roundtrip(Message::ConnectAs {
                target: id,
                token: [1; TOKEN_LEN],
                hints,
                id,
                proof: [9; PROOF_LEN],
            });
            roundtrip(Message::Register {
                id,
                token: [1; TOKEN_LEN],
                flags: 0,
                stamp: 5,
                hints,
                proof: [9; PROOF_LEN],
            });
            roundtrip(Message::Allocated {
                port: 40000,
                peer: "203.0.113.1:5".parse().unwrap(),
                ticket: [2; TOKEN_LEN],
                hints,
            });
            roundtrip(Message::Incoming {
                port: 40001,
                peer: "[2001:db8::1]:5".parse().unwrap(),
                ticket: [3; TOKEN_LEN],
                hints,
            });
        }
        // A value this version would not write is refused, not guessed at.
        let mut bytes = Message::Incoming {
            port: 1,
            peer: "203.0.113.1:5".parse().unwrap(),
            ticket: [3; TOKEN_LEN],
            hints: plain,
        }
        .encode();
        let at = bytes.len() - 1 - NatHints::WIRE_LEN;
        bytes[at] = 99;
        assert_eq!(Message::decode(&bytes), None);
        // So is a family byte that is neither "none" nor an address, and an
        // alternative address cut short.
        let good = Message::Incoming {
            port: 1,
            peer: "203.0.113.1:5".parse().unwrap(),
            ticket: [3; TOKEN_LEN],
            hints: with_v6,
        }
        .encode();
        let mut bytes = good.clone();
        let family = good.len() - (19 + NatHints::WIRE_LEN);
        assert_eq!(bytes[family], 6);
        bytes[family] = 5;
        assert_eq!(Message::decode(&bytes), None);
        assert_eq!(Message::decode(&good[..good.len() - 1]), None);
        // And the longest thing that can be said fits.
        let longest = Message::ConnectAs {
            target: id,
            token: [1; TOKEN_LEN],
            hints: with_v6,
            id,
            proof: [9; PROOF_LEN],
        }
        .encode();
        assert!(longest.len() <= MAX_MESSAGE, "{} bytes", longest.len());
    }

    /// What is passed on of a peer's other address is what could be true of
    /// it, and the choice of which family is "other" follows the way the
    /// relay is reached.
    #[test]
    fn the_other_family_is_named_from_the_way_the_relay_is_reached() {
        let mut mine = FamilyHints::unknown();
        mine.v4.mapping = 3;
        mine.v6.mapping = 4;
        mine.aim4 = Some("11.1.0.1:4000".parse().unwrap());
        mine.aim6 = Some("[2a0e:aa00:1:1::1]:5000".parse().unwrap());

        let over_v4 = Hints::told_to(&mine, "11.9.0.10:5560".parse().unwrap());
        assert_eq!(over_v4.nat.mapping, 3);
        assert_eq!(over_v4.alt.unwrap().addr, mine.aim6.unwrap());
        assert_eq!(over_v4.alt.unwrap().nat.mapping, 4);

        let over_v6 = Hints::told_to(&mine, "[2a0e:aa00:f::10]:5560".parse().unwrap());
        assert_eq!(over_v6.nat.mapping, 4);
        assert_eq!(over_v6.alt.unwrap().addr, mine.aim4.unwrap());
        assert_eq!(over_v6.alt.unwrap().nat.mapping, 3);

        // A relay reached through the mapped spelling is an IPv4 one.
        let mapped = Hints::told_to(&mine, "[::ffff:11.9.0.10]:5560".parse().unwrap());
        assert_eq!(mapped, over_v4);

        // Nothing to say of the other family: nothing said.
        mine.aim6 = None;
        assert_eq!(
            Hints::told_to(&mine, "11.9.0.10:5560".parse().unwrap()).alt,
            None
        );
    }

    #[test]
    fn only_a_believable_other_address_is_passed_on() {
        let alt = |addr: &str| Alt {
            addr: addr.parse().unwrap(),
            nat: NatHints::unknown(),
        };
        let seen_v4: SocketAddr = "11.1.0.1:4000".parse().unwrap();
        let seen_v6: SocketAddr = "[2a0e:aa00:1:1::1]:5000".parse().unwrap();
        let said = |a: Alt| Hints {
            nat: NatHints::unknown(),
            alt: Some(a),
        };
        // The other family, routable, with a port: kept.
        assert!(said(alt("[2a0e:aa00:2:1::2]:6"))
            .screened(seen_v4)
            .alt
            .is_some());
        assert!(said(alt("11.2.0.1:6")).screened(seen_v6).alt.is_some());
        // The same family as the one seen, or a mapped spelling of it.
        assert!(said(alt("11.2.0.1:6")).screened(seen_v4).alt.is_none());
        assert!(said(alt("[2a0e:aa00:2:1::2]:6"))
            .screened(seen_v6)
            .alt
            .is_none());
        assert!(said(alt("[::ffff:11.2.0.1]:6"))
            .screened(seen_v4)
            .alt
            .is_none());
        // IPv4 written the IPv6 way is IPv4: the other family to an IPv6
        // peer, and passed on plainly.
        let plain = said(alt("[::ffff:11.2.0.1]:6"))
            .screened(seen_v6)
            .alt
            .unwrap();
        assert_eq!(plain.addr, "11.2.0.1:6".parse::<SocketAddr>().unwrap());
        // Not something the internet routes, and no port at all.
        for bad in [
            "10.0.0.1:6",
            "100.64.0.1:6",
            "127.0.0.1:6",
            "[::1]:6",
            "[fd00::1]:6",
            "[fe80::1]:6",
            "[ff02::1]:6",
            "[2001:db8::1]:6",
        ] {
            let seen = if bad.starts_with('[') {
                seen_v4
            } else {
                seen_v6
            };
            assert!(said(alt(bad)).screened(seen).alt.is_none(), "{}", bad);
        }
        assert!(said(alt("[2a0e:aa00:2:1::2]:0"))
            .screened(seen_v4)
            .alt
            .is_none());
    }

    #[test]
    fn a_relay_is_written_with_or_without_its_identity() {
        let id = Identity::generate().id();
        let (got, host) = parse_relay(&format!("{}@203.0.113.9:5560", id)).unwrap();
        assert_eq!(got, Some(id));
        assert_eq!(host, "203.0.113.9:5560");
        // A sender claims no identity, so it needs none of the relay's.
        let (got, host) = parse_relay("relay.example:5560").unwrap();
        assert_eq!(got, None);
        assert_eq!(host, "relay.example:5560");
        let (_, host) = parse_relay(&format!(" {}@[2001:db8::1]:5560 ", id)).unwrap();
        assert_eq!(host, "[2001:db8::1]:5560");
        assert!(parse_relay("sh-nonsense@1.2.3.4:1").is_err());
        assert!(parse_relay("no-port").is_err());
        assert!(parse_relay(&format!("{}@", id)).is_err());
    }

    /// Only the identity's owner can make a proof the relay will take, and
    /// the proof covers the whole message, so nothing in it can be changed
    /// on the way.
    #[test]
    fn a_registration_proof_is_the_owners_alone() {
        let relay = Identity::generate();
        let owner = Identity::generate();
        let (rid, oid) = (relay.id(), owner.id());

        // Both sides reach the same key from their long-term keys alone.
        let by_owner = auth_key(&owner, &rid, &oid, &rid).unwrap();
        let by_relay = auth_key(&relay, &oid, &oid, &rid).unwrap();
        assert_eq!(by_owner, by_relay);

        let mut bytes = Message::Register {
            hints: Hints::none(),
            id: oid,
            token: [4; TOKEN_LEN],
            flags: REGISTER_PRIVATE,
            stamp: 77,
            proof: [0; PROOF_LEN],
        }
        .encode();
        let split = bytes.len() - PROOF_LEN;
        let proof = proof_for(&by_owner, &bytes[..split]);
        bytes[split..].copy_from_slice(&proof);
        assert!(proof_is_good(&by_relay, &bytes));
        assert_eq!(
            Message::decode(&bytes),
            Some(Message::Register {
                hints: Hints::none(),
                id: oid,
                token: [4; TOKEN_LEN],
                flags: REGISTER_PRIVATE,
                stamp: 77,
                proof,
            })
        );

        // Somebody who merely knows the published identity cannot make one.
        let impostor = Identity::generate();
        let theirs = auth_key(&impostor, &rid, &oid, &rid).unwrap();
        assert!(!proof_is_good(&theirs, &bytes));

        // Nor can any byte of the message be altered afterwards.
        for i in 0..split {
            let mut tampered = bytes.clone();
            tampered[i] ^= 1;
            assert!(
                !proof_is_good(&by_relay, &tampered),
                "byte {} slipped through",
                i
            );
        }
        // Nor the proof itself.
        let mut tampered = bytes.clone();
        tampered[split] ^= 1;
        assert!(!proof_is_good(&by_relay, &tampered));
        assert!(!proof_is_good(&by_relay, &bytes[..split]));
    }

    #[test]
    fn every_message_survives_the_wire() {
        let id = Identity::generate().id();
        roundtrip(Message::Register {
            hints: Hints::none(),
            id,
            token: [0; TOKEN_LEN],
            flags: 0,
            stamp: 0,
            proof: [0; PROOF_LEN],
        });
        roundtrip(Message::Register {
            hints: Hints::none(),
            id,
            token: [7; TOKEN_LEN],
            flags: REGISTER_PRIVATE,
            stamp: u64::MAX,
            proof: [1; PROOF_LEN],
        });
        roundtrip(Message::Challenge {
            token: [9; TOKEN_LEN],
        });
        roundtrip(Message::Registered {
            lease: 300,
            observed: "203.0.113.4:41000".parse().unwrap(),
        });
        roundtrip(Message::Registered {
            lease: 0,
            observed: "[2001:db8::1]:5555".parse().unwrap(),
        });
        roundtrip(Message::Connect {
            hints: Hints::none(),
            target: id,
            token: [3; TOKEN_LEN],
        });
        roundtrip(Message::ConnectAs {
            hints: Hints::none(),
            target: id,
            token: [3; TOKEN_LEN],
            id: Identity::generate().id(),
            proof: [9; PROOF_LEN],
        });
        roundtrip(Message::Allocated {
            hints: Hints::none(),
            port: 50001,
            peer: "198.51.100.9:6000".parse().unwrap(),
            ticket: [5; TOKEN_LEN],
        });
        roundtrip(Message::Incoming {
            hints: Hints::none(),
            port: 50001,
            peer: "[2001:db8::2]:6000".parse().unwrap(),
            ticket: [6; TOKEN_LEN],
        });
        for code in [
            Refusal::Unknown,
            Refusal::BadToken,
            Refusal::Busy,
            Refusal::Stale,
            Refusal::Forbidden,
        ] {
            roundtrip(Message::Error { code });
        }
        roundtrip(Message::Open {
            ticket: [8; TOKEN_LEN],
            proof: [0; TOKEN_LEN],
        });
        roundtrip(Message::Open {
            ticket: [8; TOKEN_LEN],
            proof: [4; TOKEN_LEN],
        });
        roundtrip(Message::Confirm {
            proof: [4; TOKEN_LEN],
        });
        roundtrip(Message::Punch);
        roundtrip(Message::Bye {
            id,
            token: [2; TOKEN_LEN],
            stamp: 1 << 40,
            proof: [3; PROOF_LEN],
        });
    }

    /// The relay reads these from strangers, so anything that is not exactly
    /// a message must be refused rather than guessed at — and must not
    /// panic, whatever it contains.
    #[test]
    fn malformed_messages_are_refused_not_guessed() {
        let id = Identity::generate().id();
        let good = Message::Register {
            hints: Hints::none(),
            id,
            token: [1; TOKEN_LEN],
            flags: 0,
            stamp: 9,
            proof: [1; PROOF_LEN],
        }
        .encode();

        // Truncated at every length.
        for n in 0..good.len() {
            assert!(
                Message::decode(&good[..n]).is_none(),
                "accepted {} bytes",
                n
            );
        }
        // Trailing rubbish is not a message either.
        let mut extra = good.clone();
        extra.push(0);
        assert!(Message::decode(&extra).is_none());
        // Wrong magic: the relay would be reading traffic as control.
        let mut wrong = good.clone();
        wrong[0] ^= 1;
        assert!(!is_control(&wrong));
        assert!(Message::decode(&wrong).is_none());
        // Unknown type, unknown error code, unknown address family.
        let mut bad_kind = good.clone();
        bad_kind[MAGIC.len()] = 99;
        assert!(Message::decode(&bad_kind).is_none());
        let mut bad_code = Message::Error {
            code: Refusal::Busy,
        }
        .encode();
        bad_code[HEADER_LEN] = 42;
        assert!(Message::decode(&bad_code).is_none());
        let mut bad_family = Message::Registered {
            lease: 1,
            observed: "10.0.0.1:1".parse().unwrap(),
        }
        .encode();
        bad_family[HEADER_LEN + 4] = 9;
        assert!(Message::decode(&bad_family).is_none());
        // A message longer than anything real.
        let mut huge = good.clone();
        huge.resize(MAX_MESSAGE + 1, 0);
        assert!(Message::decode(&huge).is_none());
        // Arbitrary rubbish of every length, magic or not.
        for len in 0..80usize {
            let junk: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let _ = Message::decode(&junk);
            let mut magicked = MAGIC.to_vec();
            magicked.extend(&junk);
            let _ = Message::decode(&magicked);
        }
    }

    /// Traffic the relay forwards must never be mistaken for control, so
    /// endpoints refuse the one connection id that would collide.
    #[test]
    fn the_reserved_connection_id_is_the_magic() {
        assert_eq!(reserved_cid().to_be_bytes(), MAGIC);
        let mut pkt = MAGIC.to_vec();
        pkt.extend_from_slice(&[0u8; 40]);
        assert!(is_control(&pkt));
        // A packet with any other connection id is traffic.
        let mut other = pkt.clone();
        other[7] ^= 1;
        assert!(!is_control(&other));
    }
}
