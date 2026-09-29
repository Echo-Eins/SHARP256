//! The contact card: what one side tells the other, by any channel that
//! carries text, so that they can find each other across networks.
//!
//! The picture behind it is a friend on another network at another provider.
//! Each of you runs SHARP-256; each finds out how the internet sees you —
//! the address and port your NAT gives you, and what kind of NAT it is —
//! and prints it as one short line, a card. You paste yours into whatever
//! you chat in, they paste theirs back, and each program is then given the
//! other's card. From it a program has what a hand-typed `ID@host:port`
//! never had: the peer's every address, and the *behaviour* of the peer's
//! NAT — whether its port follows the destination, which packets it lets in,
//! how it numbers new ports — which is what decides how both sides should
//! start sending at each other at once.
//!
//! A card is a hint, like every address this crate is told: it selects what
//! to try and never who is trusted. The identity in it is the one the
//! handshake will demand a private key for. The checksum is there to catch a
//! chat client mangling the line, not to authenticate it; a forged card
//! costs the attempts it aims at, and a program never sends anything to an
//! address on a card that it would not send to an address typed in.
//!
//! Text form: `shc1-` and the base32 of the card followed by a four-byte
//! checksum. Whitespace and dashes inside are ignored, so a line that got
//! wrapped on the way still reads.

use crate::crypto::identity::{base32_decode, base32_encode};
use crate::crypto::SharpId;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The format version, the first byte of every card.
const VERSION: u8 = 1;
const PREFIX: &str = "shc1-";
/// Most addresses a card lists. Every one is an attempt someone makes.
pub const MAX_CANDIDATES: usize = 16;
/// Most relays a card names.
pub const MAX_RELAYS: usize = 4;
const CHECK_LEN: usize = 4;

/// Which end wrote the card. Only information: neither role can do
/// anything the other cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Sender,
    Receiver,
}

/// How an address was found. Tells the other side how far to trust it as a
/// place to send *first*: a mapped address is where the NAT put a port, a
/// host address is only good on the same network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An address of an interface of the host.
    Host,
    /// What a STUN server saw (server-reflexive).
    Mapped,
    /// Granted by the router — UPnP, NAT-PMP, PCP.
    PortMapped,
    /// An address on a TURN server that carries what arrives at it to its
    /// owner (see `nat::turn`): the owner's NAT is out of the way, and the
    /// server's price is bandwidth. It passes only what the owner has
    /// permitted, so the owner has to know the sender's address first —
    /// which the sender's own card tells it.
    Relayed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub kind: Kind,
    pub addr: SocketAddr,
}

pub use super::behaviour::Allocation;

/// What one address family's NAT or firewall does, in the terms of RFC 4787
/// (mapping, filtering) and the port numbering of a symmetric one. `0` is
/// always "not measured".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatHints {
    /// 1 endpoint-independent, 2 address-dependent, 3 address-and-port-
    /// dependent; 4 no translation at all (an address that is the host's own).
    pub mapping: u8,
    /// 1 endpoint-independent, 2 address-dependent, 3 address-and-port-
    /// dependent.
    pub filtering: u8,
    pub allocation: Allocation,
    /// The step between the external ports of two new mappings, for a
    /// sequential allocator.
    pub delta: i16,
    /// `Some(true)`: a packet sent to our own mapped address comes back.
    pub hairpin: Option<bool>,
    /// A carrier-grade NAT lies between this host and the internet.
    pub cgn: bool,
}

impl NatHints {
    pub const fn unknown() -> Self {
        Self {
            mapping: 0,
            filtering: 0,
            allocation: Allocation::Unknown,
            delta: 0,
            hairpin: None,
            cgn: false,
        }
    }

    /// Whether the external port depends on where the packet goes — so that
    /// the mapped address a STUN server saw is not the one anybody else
    /// will be sent from.
    pub fn is_symmetric(&self) -> bool {
        matches!(self.mapping, 2 | 3)
    }

    /// Bytes on the wire, in a card and in a relay message.
    pub const WIRE_LEN: usize = 6;

    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let d = self.delta.to_be_bytes();
        [
            self.mapping,
            self.filtering,
            match self.allocation {
                Allocation::Unknown => 0,
                Allocation::Preserved => 1,
                Allocation::Sequential => 2,
                Allocation::Random => 3,
            },
            d[0],
            d[1],
            match self.hairpin {
                None => 0,
                Some(false) => 1,
                Some(true) => 2,
            } | (self.cgn as u8) << 2,
        ]
    }

    /// `None` for anything a version of ours would not have written: hints
    /// come from strangers, and a value we do not know is refused rather
    /// than guessed at.
    pub fn from_bytes(raw: &[u8; Self::WIRE_LEN]) -> Option<Self> {
        let [mapping, filtering, allocation, d0, d1, f] = *raw;
        if mapping > 4 || filtering > 3 || f & !0b111 != 0 || f & 0b11 == 3 {
            return None;
        }
        Some(Self {
            mapping,
            filtering,
            allocation: match allocation {
                0 => Allocation::Unknown,
                1 => Allocation::Preserved,
                2 => Allocation::Sequential,
                3 => Allocation::Random,
                _ => return None,
            },
            delta: i16::from_be_bytes([d0, d1]),
            hairpin: match f & 0b11 {
                0 => None,
                1 => Some(false),
                _ => Some(true),
            },
            cgn: f & 0b100 != 0,
        })
    }
}

/// What is known of the NAT (or firewall) in front of each address family.
/// A host on both has two paths to the same peer, and what punches through
/// one says nothing about the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyHints {
    pub v4: NatHints,
    pub v6: NatHints,
    /// Where a peer should aim in each family, as far as this end knows:
    /// the address the internet sees this socket at, when it is one worth
    /// naming. A relay sees a registration over one family only, and these
    /// are how it can be told where the *other* one is (see
    /// `relay::Hints`).
    pub aim4: Option<SocketAddr>,
    pub aim6: Option<SocketAddr>,
}

impl FamilyHints {
    pub const fn unknown() -> Self {
        Self {
            v4: NatHints::unknown(),
            v6: NatHints::unknown(),
            aim4: None,
            aim6: None,
        }
    }

    /// The hints for the path to `addr`.
    pub fn for_addr(&self, addr: &SocketAddr) -> NatHints {
        if crate::address::canonical(*addr).is_ipv6() {
            self.v6
        } else {
            self.v4
        }
    }

    /// The one a relay is told: IPv4's when it was measured, where the NATs
    /// are, and IPv6's otherwise.
    pub fn primary(&self) -> NatHints {
        if self.v4.mapping != 0 {
            self.v4
        } else {
            self.v6
        }
    }

    /// Whether anything has been measured.
    pub fn is_known(&self) -> bool {
        self.v4.mapping != 0 || self.v6.mapping != 0
    }
}

impl From<&super::behaviour::Behaviour> for NatHints {
    fn from(b: &super::behaviour::Behaviour) -> Self {
        use super::behaviour::{Filtering, Mapping};
        Self {
            mapping: if b.open_internet {
                4
            } else {
                match b.mapping {
                    Mapping::Unknown => 0,
                    Mapping::EndpointIndependent => 1,
                    Mapping::AddressDependent => 2,
                    Mapping::AddressAndPortDependent => 3,
                }
            },
            filtering: match b.filtering {
                Filtering::Unknown => 0,
                Filtering::EndpointIndependent => 1,
                Filtering::AddressDependent => 2,
                Filtering::AddressAndPortDependent => 3,
            },
            allocation: b.allocation,
            delta: b.alloc_step,
            hairpin: b.hairpinning,
            cgn: false,
        }
    }
}

/// A relay the card's owner is registered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayRef {
    pub id: SharpId,
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    pub role: Role,
    /// Seconds since the Unix epoch when it was made: NAT mappings do not
    /// last, and an old card is worth saying so about.
    pub created: u64,
    pub id: SharpId,
    pub candidates: Vec<Candidate>,
    pub v4: Option<NatHints>,
    pub v6: Option<NatHints>,
    pub relays: Vec<RelayRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CardError {
    #[error("this is not a contact card (it should begin with \"{}\")", PREFIX)]
    NotACard,
    #[error("the card is damaged: {0}")]
    Damaged(&'static str),
    #[error("the card was made by a newer version of SHARP-256 (format {0})")]
    Version(u8),
}

impl Card {
    /// A card made now.
    pub fn new(role: Role, id: SharpId) -> Self {
        Self {
            role,
            created: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            id,
            candidates: Vec::new(),
            v4: None,
            v6: None,
            relays: Vec::new(),
        }
    }

    /// How long ago the card was made, by this clock.
    pub fn age(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Duration::from_secs(now.saturating_sub(self.created))
    }

    /// The addresses worth punching towards, each with what the NAT in
    /// front of it does. An address on a TURN server is one: what is sent
    /// there is passed to its owner, and the server needs to hear from us
    /// first only in the sense that our sending makes it worth passing.
    /// Nothing is translated in front of it, so it is aimed at as it is.
    pub fn punch_targets(&self) -> Vec<(SocketAddr, NatHints)> {
        let mut out: Vec<(SocketAddr, NatHints)> = Vec::new();
        for c in &self.candidates {
            if out.iter().any(|(a, _)| *a == c.addr) {
                continue;
            }
            let hints = if c.kind == Kind::Relayed {
                // Nothing is translated in front of it, and what it lets in
                // is by address only (a permission is for an IP, whatever
                // port it sends from): one socket of ours, from any port, is
                // all it takes — no spray of sockets to guess a port with.
                NatHints {
                    mapping: 4,
                    filtering: 2,
                    ..NatHints::unknown()
                }
            } else {
                self.hints_for(&c.addr)
                    .copied()
                    .unwrap_or(NatHints::unknown())
            };
            out.push((c.addr, hints));
        }
        out
    }

    /// The NAT hints for the family of `addr`.
    pub fn hints_for(&self, addr: &SocketAddr) -> Option<&NatHints> {
        if crate::address::canonical(*addr).is_ipv6() {
            self.v6.as_ref()
        } else {
            self.v4.as_ref()
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        out.push(match self.role {
            Role::Sender => 1,
            Role::Receiver => 2,
        });
        out.extend_from_slice(&(self.created.min(u32::MAX as u64) as u32).to_be_bytes());
        out.extend_from_slice(self.id.as_bytes());
        let candidates = &self.candidates[..self.candidates.len().min(MAX_CANDIDATES)];
        out.push(candidates.len() as u8);
        for c in candidates {
            out.push(match c.kind {
                Kind::Host => 0,
                Kind::Mapped => 1,
                Kind::PortMapped => 2,
                Kind::Relayed => 3,
            });
            put_addr(&mut out, c.addr);
        }
        let flags = self.v4.is_some() as u8 | (self.v6.is_some() as u8) << 1;
        out.push(flags);
        for h in [&self.v4, &self.v6].into_iter().flatten() {
            out.extend_from_slice(&h.to_bytes());
        }
        let relays = &self.relays[..self.relays.len().min(MAX_RELAYS)];
        out.push(relays.len() as u8);
        for r in relays {
            out.extend_from_slice(r.id.as_bytes());
            put_addr(&mut out, r.addr);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CardError> {
        let mut r = Reader { buf: bytes, pos: 0 };
        let version = r.u8()?;
        if version != VERSION {
            return Err(CardError::Version(version));
        }
        let role = match r.u8()? {
            1 => Role::Sender,
            2 => Role::Receiver,
            _ => return Err(CardError::Damaged("unknown role")),
        };
        let created = u32::from_be_bytes(r.take(4)?.try_into().unwrap()) as u64;
        let id = SharpId::from_public(r.take(32)?.try_into().unwrap());
        if id.is_low_order() {
            return Err(CardError::Damaged(
                "the identity is not a key anybody holds",
            ));
        }
        let n = r.u8()? as usize;
        if n > MAX_CANDIDATES {
            return Err(CardError::Damaged("too many addresses"));
        }
        let mut candidates = Vec::with_capacity(n);
        for _ in 0..n {
            let kind = match r.u8()? {
                0 => Kind::Host,
                1 => Kind::Mapped,
                2 => Kind::PortMapped,
                3 => Kind::Relayed,
                _ => return Err(CardError::Damaged("unknown kind of address")),
            };
            candidates.push(Candidate {
                kind,
                addr: r.addr()?,
            });
        }
        let flags = r.u8()?;
        if flags & !0b11 != 0 {
            return Err(CardError::Damaged("unknown flags"));
        }
        let mut hints = |present: bool| -> Result<Option<NatHints>, CardError> {
            if !present {
                return Ok(None);
            }
            let raw: [u8; NatHints::WIRE_LEN] = r.take(NatHints::WIRE_LEN)?.try_into().unwrap();
            NatHints::from_bytes(&raw)
                .map(Some)
                .ok_or(CardError::Damaged("unknown NAT behaviour"))
        };
        let v4 = hints(flags & 1 != 0)?;
        let v6 = hints(flags & 2 != 0)?;
        let n = r.u8()? as usize;
        if n > MAX_RELAYS {
            return Err(CardError::Damaged("too many relays"));
        }
        let mut relays = Vec::with_capacity(n);
        for _ in 0..n {
            let rid = SharpId::from_public(r.take(32)?.try_into().unwrap());
            if rid.is_low_order() {
                return Err(CardError::Damaged("a relay's identity is not a key"));
            }
            relays.push(RelayRef {
                id: rid,
                addr: r.addr()?,
            });
        }
        if r.pos != bytes.len() {
            return Err(CardError::Damaged("something follows the card"));
        }
        Ok(Self {
            role,
            created,
            id,
            candidates,
            v4,
            v6,
            relays,
        })
    }

    /// The card as one line of text.
    pub fn to_text(&self) -> String {
        let mut body = self.encode();
        let check = blake3::hash(&body);
        body.extend_from_slice(&check.as_bytes()[..CHECK_LEN]);
        format!("{}{}", PREFIX, base32_encode(&body))
    }

    /// A card as a command line gives it: the text itself, or `@path` to a
    /// file that holds it.
    pub fn from_arg(arg: &str) -> Result<Self, String> {
        let arg = arg.trim();
        match arg.strip_prefix('@') {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read {}: {}", path, e))?;
                Self::from_text(&text).map_err(|e| format!("{}: {}", path, e))
            }
            None => Self::from_text(arg).map_err(|e| e.to_string()),
        }
    }

    /// Reads a card as text, however a chat wrapped it.
    pub fn from_text(text: &str) -> Result<Self, CardError> {
        let squeezed: String = text
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let head = PREFIX.replace('-', "");
        let squeezed_lower = squeezed.to_ascii_lowercase();
        let Some(rest) = squeezed_lower.strip_prefix(&head) else {
            return Err(CardError::NotACard);
        };
        let bytes = base32_decode(rest).ok_or(CardError::Damaged("not base32"))?;
        if bytes.len() <= CHECK_LEN {
            return Err(CardError::Damaged("too short"));
        }
        let (body, check) = bytes.split_at(bytes.len() - CHECK_LEN);
        if blake3::hash(body).as_bytes()[..CHECK_LEN] != *check {
            return Err(CardError::Damaged(
                "the checksum does not match: a character was lost or changed",
            ));
        }
        Self::decode(body)
    }
}

impl std::fmt::Display for Card {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl std::str::FromStr for Card {
    type Err = CardError;
    fn from_str(s: &str) -> Result<Self, CardError> {
        Self::from_text(s)
    }
}

fn put_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match crate::address::canonical(addr).ip() {
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

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CardError> {
        let s = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(CardError::Damaged("it ends too soon"))?;
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, CardError> {
        Ok(self.take(1)?[0])
    }

    fn addr(&mut self) -> Result<SocketAddr, CardError> {
        let fam = self.u8()?;
        let port = u16::from_be_bytes(self.take(2)?.try_into().unwrap());
        let ip = match fam {
            4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(self.take(4)?).unwrap())),
            6 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(self.take(16)?).unwrap(),
            )),
            _ => return Err(CardError::Damaged("unknown address family")),
        };
        if port == 0 {
            return Err(CardError::Damaged("an address without a port"));
        }
        Ok(SocketAddr::new(ip, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    fn sample() -> Card {
        let mut c = Card::new(Role::Receiver, Identity::generate().id());
        c.candidates = vec![
            Candidate {
                kind: Kind::Mapped,
                addr: "203.0.113.7:41235".parse().unwrap(),
            },
            Candidate {
                kind: Kind::Host,
                addr: "192.168.1.20:5555".parse().unwrap(),
            },
            Candidate {
                kind: Kind::Host,
                addr: "[2001:db8:1:2::9]:5555".parse().unwrap(),
            },
        ];
        c.v4 = Some(NatHints {
            mapping: 3,
            filtering: 3,
            allocation: Allocation::Sequential,
            delta: 1,
            hairpin: Some(false),
            cgn: true,
        });
        c.v6 = Some(NatHints {
            mapping: 4,
            filtering: 3,
            ..NatHints::unknown()
        });
        c.relays = vec![RelayRef {
            id: Identity::generate().id(),
            addr: "198.51.100.1:5560".parse().unwrap(),
        }];
        c
    }

    #[test]
    fn a_card_survives_its_text() {
        let c = sample();
        let text = c.to_text();
        assert!(text.starts_with("shc1-"));
        assert_eq!(Card::from_text(&text).unwrap(), c);
        // Short enough to paste into a chat: one screen line or two.
        assert!(text.len() < 520, "{} characters", text.len());
    }

    #[test]
    fn a_card_wrapped_by_a_chat_still_reads() {
        let c = sample();
        let text = c.to_text();
        let mangled: String = text
            .as_bytes()
            .chunks(37)
            .map(|p| std::str::from_utf8(p).unwrap())
            .collect::<Vec<_>>()
            .join("\n  ");
        assert_eq!(Card::from_text(&format!("  {}\n", mangled)).unwrap(), c);
        assert_eq!(Card::from_text(&text.to_uppercase()).unwrap(), c);
        assert_eq!(Card::from_text(&text.replace("shc1-", "SHC1-")).unwrap(), c);
    }

    #[test]
    fn a_changed_or_lost_character_is_noticed() {
        let text = sample().to_text();
        for i in (PREFIX.len()..text.len()).step_by(7) {
            // Another letter in its place.
            let mut b = text.clone().into_bytes();
            b[i] = if b[i] == b'q' { b'r' } else { b'q' };
            assert!(
                Card::from_text(std::str::from_utf8(&b).unwrap()).is_err(),
                "a changed character at {} went unnoticed",
                i
            );
            // The character gone.
            let mut gone = text.clone();
            gone.remove(i);
            assert!(Card::from_text(&gone).is_err(), "a lost character at {}", i);
        }
        assert_eq!(Card::from_text("hello"), Err(CardError::NotACard));
        assert_eq!(
            Card::from_text(&Identity::generate().id().to_string()),
            Err(CardError::NotACard)
        );
    }

    #[test]
    fn a_card_that_lies_about_its_size_is_refused() {
        let good = sample().encode();
        // Too many addresses.
        let mut c = sample();
        c.candidates = vec![c.candidates[0]; MAX_CANDIDATES];
        assert!(Card::decode(&c.encode()).is_ok());
        let mut b = c.encode();
        b[38] = MAX_CANDIDATES as u8 + 1;
        assert!(Card::decode(&b).is_err());
        // Cut short at every length, and with something added.
        for n in 0..good.len() {
            assert!(Card::decode(&good[..n]).is_err(), "{} bytes", n);
        }
        let mut more = good.clone();
        more.push(0);
        assert!(Card::decode(&more).is_err());
        // A version this program does not know.
        let mut newer = good;
        newer[0] = 2;
        assert_eq!(Card::decode(&newer), Err(CardError::Version(2)));
    }

    #[test]
    fn an_identity_nobody_holds_is_refused() {
        let mut c = sample();
        c.id = SharpId::from_public([0; 32]);
        assert!(Card::decode(&c.encode()).is_err());
        let mut c = sample();
        c.relays[0].id = SharpId::from_public([0; 32]);
        assert!(Card::decode(&c.encode()).is_err());
    }

    #[test]
    fn mapped_ipv4_addresses_are_written_as_ipv4() {
        let mut c = sample();
        c.candidates = vec![Candidate {
            kind: Kind::Mapped,
            addr: "[::ffff:203.0.113.7]:4000".parse().unwrap(),
        }];
        let back = Card::decode(&c.encode()).unwrap();
        assert_eq!(back.candidates[0].addr, "203.0.113.7:4000".parse().unwrap());
    }

    #[test]
    fn a_new_card_is_young_and_hints_follow_the_family() {
        let c = sample();
        assert!(c.age() < Duration::from_secs(5));
        assert_eq!(
            c.hints_for(&"203.0.113.7:1".parse().unwrap())
                .unwrap()
                .mapping,
            3
        );
        assert_eq!(
            c.hints_for(&"[2001:db8::1]:1".parse().unwrap())
                .unwrap()
                .mapping,
            4
        );
        assert!(NatHints {
            mapping: 3,
            ..NatHints::unknown()
        }
        .is_symmetric());
        assert!(!NatHints::unknown().is_symmetric());
    }
}
