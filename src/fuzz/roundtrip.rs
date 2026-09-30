//! The encoders, checked from the other side: a value is built as the
//! program would build one (within what the format can say), encoded, and
//! must decode as itself. The byte-first targets check the reverse, what a
//! decoder takes and an encoder writes back; this one finds the values an
//! encoder writes that its decoder refuses or reads otherwise.
//!
//! Where an encoder is meant to change a value, the check says so and
//! expects exactly that change: text shortened at a character boundary to
//! its field, an IPv6 zone or flow label that the format does not carry,
//! an address written in its canonical family.

use super::gen::Gen;
use crate::crypto::transport::OVERHEAD as TRANSPORT_OVERHEAD;
use crate::protocol::constants::*;
use crate::protocol::wire::{self, Message, MsgType, MAX_CONTROL_BODY};
#[cfg(feature = "nat-traversal")]
use std::net::SocketAddr;

type Codec = fn(&mut Gen);

const CODECS: &[Codec] = &[
    frame,
    handshake_payloads,
    ids,
    manifest,
    #[cfg(feature = "nat-traversal")]
    relay,
    #[cfg(feature = "nat-traversal")]
    card,
    #[cfg(feature = "nat-traversal")]
    bencode,
    #[cfg(feature = "nat-traversal")]
    mdns,
    #[cfg(feature = "nat-traversal")]
    turn,
    #[cfg(feature = "nat-traversal")]
    stun,
];

/// One value of one format, chosen by the first byte.
pub fn roundtrip(data: &[u8]) {
    let mut g = Gen::new(data);
    let codec = CODECS[g.below(CODECS.len())];
    codec(&mut g);
}

/// `s` as an encoder that keeps `max` bytes writes it: cut at the last
/// character boundary at or before `max`.
fn shortened(s: &str, max: usize) -> String {
    let mut n = s.len().min(max);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    s[..n].to_string()
}

/// What a format without zones and flow labels keeps of an address.
#[cfg(feature = "nat-traversal")]
fn plain(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(a.ip(), a.port())
}

// ---------------------------------------------------------------------------
// Transport frames and handshake payloads
// ---------------------------------------------------------------------------

pub(super) fn hello(g: &mut Gen) -> wire::Hello {
    let file_size = g.u64() >> (g.u8() % 64);
    let tree = (g.bool() && file_size > 0).then(|| {
        let files = g.within(0, MAX_MANIFEST_ENTRIES);
        wire::TreeInfo {
            manifest_len: g.within(1, file_size),
            manifest_hash: g.array(),
            files,
            dirs: g.within(0, MAX_MANIFEST_ENTRIES - files),
        }
    });
    let mut file_name = g.text(MAX_FILE_NAME_LEN + 40);
    if file_name.is_empty() {
        file_name.push('x');
    }
    wire::Hello {
        transfer_id: g.array(),
        timestamp: g.u32(),
        file_size,
        file_mtime: g.i64(),
        max_chunk: g.u16(),
        capabilities: g.u32(),
        tree,
        file_name,
    }
}

/// What the encoder makes of a HELLO: the name kept to its field.
fn hello_as_sent(h: &wire::Hello) -> wire::Hello {
    wire::Hello {
        file_name: shortened(&h.file_name, MAX_FILE_NAME_LEN),
        ..h.clone()
    }
}

/// Holes above `base` as a receiver describes them: in order, apart,
/// no more of them than a frame carries. Returns where the last one ends.
fn holes(g: &mut Gen, base: u64) -> (Vec<wire::Range>, u64) {
    let n = g.below(MAX_HOLES_DECODE + 1);
    let mut out = Vec::with_capacity(n);
    let mut prev = base;
    for i in 0..n {
        let gap = u64::from(g.u16()) + u64::from(i > 0);
        let len = u64::from(g.u16()) + 1;
        let Some((s, e)) = prev
            .checked_add(gap)
            .and_then(|s| Some((s, s.checked_add(len)?)))
        else {
            break;
        };
        out.push((s, e));
        prev = e;
    }
    (out, prev)
}

fn hello_ack(g: &mut Gen) -> wire::HelloAck {
    let resume_upto = g.u64() >> (g.u8() % 65).min(63);
    let (holes, end) = holes(g, resume_upto);
    wire::HelloAck {
        status: g.pick(&[HELLO_ACCEPTED, HELLO_REJECTED, HELLO_PENDING]),
        reason: g.u8(),
        max_chunk: g.u16(),
        capabilities: g.u32(),
        echo_ts: g.u32(),
        max_ack_delay_us: g.u32(),
        rwnd: g.u64(),
        resume_upto,
        known_end: end.saturating_add(u64::from(g.u16())),
        holes,
        message: g.text(MAX_TEXT_LEN + 40),
    }
}

/// A frame of any type, as a session builds one: its fields in the range
/// they are read in. `payload` is a DATA frame's.
pub(super) fn message<'a>(g: &mut Gen, payload: &'a [u8]) -> Message<'a> {
    let ty = MsgType::from_u8(1 + g.below(14) as u8).expect("1..=14");
    match ty {
        MsgType::Hello => Message::Hello(hello(g)),
        MsgType::HelloAck => Message::HelloAck(hello_ack(g)),
        MsgType::Data => Message::Data(wire::Data {
            offset: g.u64(),
            timestamp: g.u32(),
            payload,
        }),
        MsgType::Ack => {
            let contiguous_upto = g.u64() >> (g.u8() % 65).min(63);
            let (holes, end) = holes(g, contiguous_upto);
            Message::Ack(wire::Ack {
                contiguous_upto,
                highest: end.saturating_add(u64::from(g.u16())),
                received_bytes: g.u64(),
                echo_ts: g.u32(),
                ack_delay_us: g.u32(),
                rwnd: g.u64(),
                holes,
            })
        }
        MsgType::Fin => Message::Fin(wire::Fin {
            file_hash: g.array(),
        }),
        MsgType::FinAck => Message::FinAck(wire::FinAck {
            verdict: g.u8(),
            file_hash: g.array(),
        }),
        MsgType::Ping => Message::Ping(wire::Ping { timestamp: g.u32() }),
        MsgType::Pong => Message::Pong(wire::Pong { echo: g.u32() }),
        MsgType::Probe => Message::Probe(wire::Probe { size: g.u16() }),
        MsgType::ProbeAck => Message::ProbeAck(wire::ProbeAck { size: g.u16() }),
        MsgType::Abort => Message::Abort(wire::Abort {
            code: g.u16(),
            reason: g.text(MAX_TEXT_LEN + 40),
        }),
        MsgType::FinDone => Message::FinDone(wire::FinDone { verdict: g.u8() }),
        MsgType::PathChallenge => Message::PathChallenge(wire::PathChallenge { data: g.array() }),
        MsgType::PathResponse => Message::PathResponse(wire::PathResponse { data: g.array() }),
    }
}

/// Every frame type, with its type byte: encoded without a limit it must
/// come back exactly (text kept to its field); encoded within a control
/// datagram's body, as the sessions send them, it must fit when what
/// cannot be shortened does.
fn frame(g: &mut Gen) {
    let payload = g.bytes(1500);
    let msg = message(g, &payload);
    let ty = msg.msg_type();
    let flags = g.u8() & 0x0f;
    assert_eq!(
        wire::parse_type_byte(wire::type_byte(ty, flags)).expect("a type byte we wrote"),
        (ty, flags)
    );
    let expected = match &msg {
        Message::Hello(h) => Message::Hello(hello_as_sent(h)),
        Message::HelloAck(a) => Message::HelloAck(wire::HelloAck {
            message: shortened(&a.message, MAX_TEXT_LEN),
            ..a.clone()
        }),
        Message::Abort(a) => Message::Abort(wire::Abort {
            code: a.code,
            reason: shortened(&a.reason, MAX_TEXT_LEN),
        }),
        m => m.clone(),
    };
    let mut body = Vec::new();
    wire::encode_body(&msg, &mut body, usize::MAX);
    let back = wire::decode_body(ty, &body)
        .unwrap_or_else(|e| panic!("{:?} as encoded does not decode: {}", ty, e));
    assert_eq!(back, expected, "a frame comes back changed");
    if let Message::Probe(p) = &msg {
        let want = (p.size as usize).saturating_sub(TRANSPORT_OVERHEAD).max(2);
        assert_eq!(body.len(), want, "a probe of {} bytes", p.size);
    }

    // Within a control datagram. Only text is shortened to a limit, so
    // the rest must fit on its own for the frame to; then it does, and it
    // reads back as it was apart from the text.
    let mut control = Vec::new();
    wire::encode_body(&msg, &mut control, MAX_CONTROL_BODY);
    let text = match &expected {
        Message::Hello(h) => Some(h.file_name.len()),
        Message::HelloAck(a) => Some(a.message.len()),
        Message::Abort(a) => Some(a.reason.len()),
        _ => None,
    };
    // What precedes the text (it is always last), less its length byte.
    let fixed = text.map(|t| body.len() - 1 - t);
    if let Some(fixed) = fixed.filter(|f| *f < MAX_CONTROL_BODY) {
        assert!(
            control.len() <= MAX_CONTROL_BODY,
            "a {:?} of {} bytes past the text, {} in all, within a limit of {}",
            ty,
            fixed,
            control.len(),
            MAX_CONTROL_BODY
        );
        let back = wire::decode_body(ty, &control).expect("a shortened frame decodes");
        let (got, full) = match (&back, &expected) {
            (Message::Hello(b), Message::Hello(e)) => (&b.file_name, &e.file_name),
            (Message::HelloAck(b), Message::HelloAck(e)) => (&b.message, &e.message),
            (Message::Abort(b), Message::Abort(e)) => (&b.reason, &e.reason),
            _ => unreachable!("the texts are in these three"),
        };
        assert!(
            full.starts_with(got.as_str()),
            "text changed, not shortened"
        );
        if matches!(msg, Message::Hello(_)) {
            assert!(
                !got.is_empty(),
                "a HELLO whose name was shortened to nothing"
            );
        }
    }
}

/// The payloads inside the handshake, both versions: the initiation (and
/// its padded form, which a resuming sender uses) and the response, which
/// is held to one control datagram.
fn handshake_payloads(g: &mut Gen) {
    let init = wire::Initiation {
        timestamp: g.u64(),
        suites: g.u8(),
        hardware_aes: g.bool(),
        hello_flags: g.u8() & 0x0f,
        hello: hello(g),
    };
    let expected = wire::Initiation {
        hello: hello_as_sent(&init.hello),
        ..init.clone()
    };
    let bytes = wire::encode_initiation(&init);
    assert_eq!(wire::decode_initiation(&bytes).ok(), Some(expected.clone()));
    let padded = wire::encode_padded_initiation(&init);
    assert_eq!(
        padded.len(),
        bytes.len().max(wire::PADDED_INITIATION_PAYLOAD)
    );
    assert_eq!(wire::decode_initiation(&padded).ok(), Some(expected));

    let resp = wire::Response {
        suite: g.u8(),
        ack_flags: g.u8() & 0x0f,
        ack: hello_ack(g),
    };
    let bytes = wire::encode_response(&resp);
    let back = wire::decode_response(&bytes).expect("a response we wrote decodes");
    // Its text is shortened to fit one control datagram, and only that.
    assert!(resp.ack.message.starts_with(back.ack.message.as_str()));
    let mut expected = resp.clone();
    expected.ack.message.clone_from(&back.ack.message);
    assert_eq!(back, expected, "a response comes back changed");
    // Shortened only for room: with bytes to spare, the text is all there
    // (to its field).
    if bytes.len() + 4 <= wire::MAX_RESPONSE_PAYLOAD {
        assert_eq!(back.ack.message, shortened(&resp.ack.message, MAX_TEXT_LEN));
    }

    let v4 = wire::InitiationV4 {
        timestamp: g.u64(),
        suites: g.u8(),
        hardware_aes: g.bool(),
    };
    assert_eq!(
        wire::decode_initiation_v4(&wire::encode_initiation_v4(&v4)).ok(),
        Some(v4)
    );
    let r4 = wire::ResponseV4 {
        suite: g.u8(),
        reason: g.u8(),
    };
    assert_eq!(
        wire::decode_response_v4(&wire::encode_response_v4(&r4)).ok(),
        Some(r4)
    );
}

/// Identities as text, in both versions' forms.
fn ids(g: &mut Gen) {
    use crate::crypto::handshake::Version;
    use crate::crypto::SharpId;
    let id = SharpId::from_public(g.array());
    // A key of small order is written like any other and read by nobody:
    // it is not a key anybody holds.
    let expected = |v| (!id.is_low_order()).then_some((id, v));
    for version in [Version::V3, Version::V4] {
        let text = id.text(version);
        assert_eq!(
            SharpId::parse_versioned(&text).ok(),
            expected(version),
            "{}",
            text
        );
    }
    assert_eq!(
        id.text(Version::V3).parse::<SharpId>().ok(),
        expected(Version::V3).map(|(id, _)| id)
    );
}

// ---------------------------------------------------------------------------
// Directory listings
// ---------------------------------------------------------------------------

/// A listing of whatever shape the builder takes (it checks names, nesting,
/// order and metadata as a scan does), encoded and read back.
fn manifest(g: &mut Gen) {
    use crate::file::tree::{EntryKind, ListingBuilder, Manifest, Meta};
    let meta = |g: &mut Gen| Meta {
        mode: g.bool().then(|| g.u32() >> (g.u8() % 32)),
        mtime: g.bool().then(|| (g.i64(), g.u32() >> (g.u8() % 32))),
    };
    let mut b = ListingBuilder::new(meta(g));
    let mut slots = 0u32;
    for _ in 0..g.below(48) {
        let parent = g.below(slots as usize + 1) as u32;
        let name = g.text(40);
        let kind = if g.bool() {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        let size = if kind == EntryKind::Dir && g.u8() != 0 {
            0
        } else {
            g.u64() >> (g.u8() % 64)
        };
        let m = meta(g);
        if b.push(parent, &name, kind, size, m).is_ok() {
            slots += 1;
        }
    }
    let Ok(listing) = b.finish() else {
        return;
    };
    let bytes = listing.encode();
    let back = Manifest::decode(&bytes).expect("a listing the builder took decodes");
    assert_eq!(back.encode(), bytes, "a listing comes back changed");
    assert_eq!(back.encoded_len(), bytes.len() as u64);
    assert_eq!(listing.encoded_len(), bytes.len() as u64);
    assert_eq!(
        (back.files(), back.dirs(), back.data_len()),
        (listing.files(), listing.dirs(), listing.data_len())
    );
    assert_eq!(back.entries().len(), listing.entries().len());
    for (i, (a, b)) in back.entries().iter().zip(listing.entries()).enumerate() {
        assert_eq!(
            (a.parent, a.kind, a.size, a.start, a.meta),
            (b.parent, b.kind, b.size, b.start, b.meta),
            "entry {}",
            i
        );
        assert_eq!(back.name(i), listing.name(i));
    }
    assert_eq!(back.root_meta(), listing.root_meta());
}

// ---------------------------------------------------------------------------
// What the NAT traversal says to relays, peers, servers and the network
// ---------------------------------------------------------------------------

#[cfg(feature = "nat-traversal")]
fn nat_hints(g: &mut Gen) -> crate::nat::card::NatHints {
    use crate::nat::behaviour::Allocation;
    crate::nat::card::NatHints {
        mapping: g.below(5) as u8,
        filtering: g.below(4) as u8,
        allocation: g.pick(&[
            Allocation::Unknown,
            Allocation::Preserved,
            Allocation::Sequential,
            Allocation::Random,
        ]),
        delta: g.u16() as i16,
        hairpin: g.pick(&[None, Some(false), Some(true)]),
        cgn: g.bool(),
    }
}

#[cfg(feature = "nat-traversal")]
fn relay_hints(g: &mut Gen) -> crate::relay::Hints {
    crate::relay::Hints {
        nat: nat_hints(g),
        alt: g.bool().then(|| crate::relay::Alt {
            addr: g.socket_addr(),
            nat: nat_hints(g),
        }),
    }
}

/// Every relay message, as a peer or a relay writes it. Addresses are
/// written without zone or flow label, and every message must be one
/// control datagram of the relay's.
/// A relay message of any kind, with fields in their ranges.
#[cfg(feature = "nat-traversal")]
pub(super) fn relay_message(g: &mut Gen) -> crate::relay::Message {
    use crate::crypto::SharpId;
    use crate::relay::{Message, Refusal};
    let id = |g: &mut Gen| SharpId::from_public(g.array());
    match g.below(13) {
        0 => Message::Register {
            id: id(g),
            token: g.array(),
            flags: g.u8(),
            stamp: g.u64(),
            hints: relay_hints(g),
            nonce: g.array(),
            proof: g.array(),
        },
        1 => Message::Challenge {
            token: g.array(),
            tag: g.array(),
        },
        2 => Message::Registered {
            lease: g.u32(),
            observed: g.socket_addr(),
            tag: g.array(),
        },
        3 => Message::Connect {
            target: id(g),
            token: g.array(),
            hints: relay_hints(g),
            nonce: g.array(),
        },
        4 => Message::ConnectAs {
            target: id(g),
            token: g.array(),
            hints: relay_hints(g),
            nonce: g.array(),
            id: id(g),
            proof: g.array(),
        },
        5 | 6 => {
            let (port, peer, ticket, hints, tag) = (
                g.u16(),
                g.socket_addr(),
                g.array(),
                relay_hints(g),
                g.array(),
            );
            if g.bool() {
                Message::Allocated {
                    port,
                    peer,
                    ticket,
                    hints,
                    tag,
                }
            } else {
                Message::Incoming {
                    port,
                    peer,
                    ticket,
                    hints,
                    tag,
                }
            }
        }
        7 => Message::Error {
            code: g.pick(&[
                Refusal::Unknown,
                Refusal::BadToken,
                Refusal::Busy,
                Refusal::Stale,
                Refusal::Forbidden,
            ]),
            tag: g.array(),
        },
        8 => Message::Open {
            ticket: g.array(),
            proof: g.array(),
        },
        9 => Message::Confirm { proof: g.array() },
        10 => Message::Punch,
        _ => Message::Bye {
            id: id(g),
            token: g.array(),
            stamp: g.u64(),
            nonce: g.array(),
            proof: g.array(),
        },
    }
}

#[cfg(feature = "nat-traversal")]
fn relay(g: &mut Gen) {
    use crate::relay::Message;
    let m = relay_message(g);
    let plain_hints = |h: &crate::relay::Hints| crate::relay::Hints {
        nat: h.nat,
        alt: h.alt.map(|a| crate::relay::Alt {
            addr: plain(a.addr),
            nat: a.nat,
        }),
    };
    let expected = match m.clone() {
        Message::Register {
            id,
            token,
            flags,
            stamp,
            hints,
            nonce,
            proof,
        } => Message::Register {
            id,
            token,
            flags,
            stamp,
            hints: plain_hints(&hints),
            nonce,
            proof,
        },
        Message::Registered {
            lease,
            observed,
            tag,
        } => Message::Registered {
            lease,
            observed: plain(observed),
            tag,
        },
        Message::Connect {
            target,
            token,
            hints,
            nonce,
        } => Message::Connect {
            target,
            token,
            hints: plain_hints(&hints),
            nonce,
        },
        Message::ConnectAs {
            target,
            token,
            hints,
            nonce,
            id,
            proof,
        } => Message::ConnectAs {
            target,
            token,
            hints: plain_hints(&hints),
            nonce,
            id,
            proof,
        },
        Message::Allocated {
            port,
            peer,
            ticket,
            hints,
            tag,
        } => Message::Allocated {
            port,
            peer: plain(peer),
            ticket,
            hints: plain_hints(&hints),
            tag,
        },
        Message::Incoming {
            port,
            peer,
            ticket,
            hints,
            tag,
        } => Message::Incoming {
            port,
            peer: plain(peer),
            ticket,
            hints: plain_hints(&hints),
            tag,
        },
        other => other,
    };
    let bytes = m.encode();
    assert!(
        bytes.len() <= crate::relay::MAX_MESSAGE,
        "{} bytes",
        bytes.len()
    );
    assert!(crate::relay::is_control(&bytes));
    assert_eq!(
        Message::decode(&bytes),
        Some(expected),
        "a relay message comes back changed"
    );
}

/// A contact card: in bytes and as the text a person passes on. The card
/// keeps no more addresses and relays than it has room for, a creation
/// time in 32 bits, and addresses in their canonical family.
#[cfg(feature = "nat-traversal")]
fn card(g: &mut Gen) {
    use crate::crypto::handshake::Version;
    use crate::crypto::SharpId;
    use crate::nat::card::{Candidate, Card, Kind, RelayRef, Role, MAX_CANDIDATES, MAX_RELAYS};
    let key = |g: &mut Gen| {
        let id = SharpId::from_public(g.array());
        (!id.is_low_order()).then_some(id)
    };
    let addr = |g: &mut Gen| {
        let a = g.socket_addr();
        SocketAddr::new(a.ip(), a.port().max(1))
    };
    let Some(id) = key(g) else {
        return;
    };
    let mut c = Card::new(g.pick(&[Role::Sender, Role::Receiver]), id);
    c.created = g.u64() >> (g.u8() % 64);
    c.version = g.pick(&[Version::V3, Version::V4]);
    c.candidates = (0..g.below(MAX_CANDIDATES + 4))
        .map(|_| Candidate {
            kind: g.pick(&[Kind::Host, Kind::Mapped, Kind::PortMapped, Kind::Relayed]),
            addr: addr(g),
        })
        .collect();
    c.v4 = g.bool().then(|| nat_hints(g));
    c.v6 = g.bool().then(|| nat_hints(g));
    for _ in 0..g.below(MAX_RELAYS + 3) {
        let Some(id) = key(g) else {
            return;
        };
        c.relays.push(RelayRef { id, addr: addr(g) });
    }
    let canonical = |a: SocketAddr| plain(crate::address::canonical(a));
    let mut expected = c.clone();
    expected.created = c.created.min(u64::from(u32::MAX));
    expected.candidates.truncate(MAX_CANDIDATES);
    for x in &mut expected.candidates {
        x.addr = canonical(x.addr);
    }
    expected.relays.truncate(MAX_RELAYS);
    for r in &mut expected.relays {
        r.addr = canonical(r.addr);
    }
    let bytes = c.encode();
    assert_eq!(
        Card::decode(&bytes).as_ref(),
        Ok(&expected),
        "a card comes back changed"
    );
    assert_eq!(Card::from_text(&c.to_text()).as_ref(), Ok(&expected));
}

#[cfg(feature = "nat-traversal")]
fn bencode_value(g: &mut Gen, depth: usize, items: &mut usize) -> crate::nat::dht::bencode::Value {
    use crate::nat::dht::bencode::{Value, MAX_DEPTH, MAX_ITEMS};
    let mut room = |n: usize| {
        let n = n.min(MAX_ITEMS - (*items).min(MAX_ITEMS));
        *items += n;
        n
    };
    match g.u8() % 4 {
        2 if depth < MAX_DEPTH => {
            let n = room(g.below(6));
            Value::List((0..n).map(|_| bencode_value(g, depth + 1, items)).collect())
        }
        3 if depth < MAX_DEPTH => {
            let n = room(g.below(6));
            Value::Dict(
                (0..n)
                    .map(|_| (g.bytes(12), bencode_value(g, depth + 1, items)))
                    .collect(),
            )
        }
        1 => Value::Bytes(g.bytes(48)),
        _ => Value::Int(g.i64() >> (g.u8() % 64)),
    }
}

/// Bencoding as the DHT writes its queries and answers.
#[cfg(feature = "nat-traversal")]
fn bencode(g: &mut Gen) {
    use crate::nat::dht::bencode::{decode, encode};
    let mut items = 0;
    let v = bencode_value(g, 0, &mut items);
    let bytes = encode(&v);
    assert_eq!(
        decode(&bytes).as_ref(),
        Some(&v),
        "bencoding comes back changed"
    );
}

/// A DNS name as the responder writes one: lower-case labels, dot at the
/// end, within the length the reader takes.
#[cfg(feature = "nat-traversal")]
fn dns_name(g: &mut Gen) -> String {
    const LABEL: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut name = String::new();
    for _ in 0..g.below(5) {
        let len = 1 + g.below(63);
        if name.len() + len + 1 > crate::nat::mdns::MAX_NAME {
            break;
        }
        name.extend((0..len).map(|_| char::from(LABEL[g.below(LABEL.len())])));
        name.push('.');
    }
    if name.is_empty() {
        name.push('.');
    }
    name
}

/// Multicast DNS as a receiver answers and a sender asks: every record
/// comes back with the cache-flush bit taken off its class, as it was
/// before it was put on.
#[cfg(feature = "nat-traversal")]
fn mdns(g: &mut Gen) {
    use crate::nat::mdns::{Data, Message, Question, Record, MAX_RECORDS};
    let record = |g: &mut Gen| Record {
        name: dns_name(g),
        class: g.u16() & 0x7fff,
        ttl: g.u32(),
        data: match g.below(5) {
            0 => Data::A(g.ipv4()),
            1 => Data::Aaaa(g.ipv6()),
            2 => Data::Ptr(dns_name(g)),
            3 => Data::Srv {
                port: g.u16(),
                target: dns_name(g),
            },
            _ => Data::Txt((0..g.below(4)).map(|_| g.text(80)).collect()),
        },
    };
    let n = |g: &mut Gen| g.below(6).min(MAX_RECORDS);
    let m = Message {
        id: g.u16(),
        response: g.bool(),
        questions: (0..n(g))
            .map(|_| Question {
                name: dns_name(g),
                qtype: g.u16(),
                class: g.u16(),
            })
            .collect(),
        answers: (0..n(g)).map(|_| record(g)).collect(),
        additionals: (0..n(g)).map(|_| record(g)).collect(),
    };
    let bytes = m
        .encode()
        .expect("names the responder writes can be written");
    let mut expected = m.clone();
    for r in expected.answers.iter_mut().chain(&mut expected.additionals) {
        // No strings is written as one empty one.
        if let Data::Txt(s) = &mut r.data {
            if s.is_empty() {
                s.push(String::new());
            }
        }
    }
    assert_eq!(
        Message::decode(&bytes),
        Some(expected),
        "a DNS message comes back changed"
    );
}

/// TURN messages as a client writes them to a server: attributes in order,
/// addresses XOR-ed (without zones), integrity that the same key checks
/// and another does not.
#[cfg(feature = "nat-traversal")]
fn turn(g: &mut Gen) {
    use crate::nat::turn::wire::*;
    const TYPES: &[u16] = &[
        ATTR_USERNAME,
        ATTR_ERROR_CODE,
        ATTR_CHANNEL_NUMBER,
        ATTR_LIFETIME,
        ATTR_DATA,
        ATTR_REALM,
        ATTR_NONCE,
        ATTR_REQUESTED_ADDRESS_FAMILY,
        ATTR_REQUESTED_TRANSPORT,
        ATTR_DONT_FRAGMENT,
        ATTR_SOFTWARE,
        0x7fff,
        0xc001,
    ];
    let method = g.u16() & 0x0fff;
    let class = g.pick(&[
        Class::Request,
        Class::Indication,
        Class::Success,
        Class::Error,
    ]);
    let tid: [u8; 12] = g.array();
    let mut b = Builder::new(method, class, &tid);
    let mut attrs: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut addrs: Vec<(u16, SocketAddr)> = Vec::new();
    for _ in 0..g.below(12) {
        if g.u8() % 4 == 0 {
            let ty = g.pick(&[
                ATTR_XOR_PEER_ADDRESS,
                ATTR_XOR_RELAYED_ADDRESS,
                ATTR_XOR_MAPPED_ADDRESS,
            ]);
            let a = g.socket_addr();
            b = b.xor_address(ty, a);
            addrs.push((ty, a));
        } else {
            let ty = g.pick(TYPES);
            let v = g.bytes(64);
            b = b.attr(ty, &v);
            attrs.push((ty, v));
        }
    }
    let cred = Credentials::new(&g.text(20), &g.text(20), &g.text(20), &g.bytes(16));
    let how = g.below(3);
    let bytes = match how {
        0 => b.finish(),
        1 => b.finish_with_integrity(cred.key()),
        _ => b.finish_authenticated(&cred),
    };
    let m = parse(&bytes).expect("a message we wrote reads");
    assert_eq!((m.method, m.class, m.tid), (method, class, tid));
    for (ty, v) in &attrs {
        assert!(
            m.attrs_of(*ty).any(|x| x == v.as_slice()),
            "attribute {:#x}",
            ty
        );
    }
    // `xor_address` reads the first address of its kind.
    let mut seen = Vec::new();
    for (ty, a) in &addrs {
        if !seen.contains(ty) {
            seen.push(*ty);
            assert_eq!(m.xor_address(*ty), Some(plain(*a)));
        }
    }
    let other = Credentials::new("someone", "else", "entirely", b"n");
    assert_eq!(m.integrity_is_good(cred.key()), how > 0);
    assert!(!m.integrity_is_good(other.key()) || other.key() == cred.key());
}

/// STUN Binding as this crate asks and answers it.
#[cfg(feature = "nat-traversal")]
fn stun(g: &mut Gen) {
    use crate::nat::stun::*;
    let tid: [u8; 12] = g.array();
    let (ip, port) = (g.bool(), g.bool());
    let asked = binding_request_with_change(&tid, ip, port);
    assert!(is_stun_request(&asked));
    assert_eq!(requested_change(&asked), (ip, port));
    let response_port = g.u16();
    assert_eq!(
        requested_response_port(&binding_request_with_response_port(&tid, response_port)),
        Some(response_port)
    );
    let mapped = g.socket_addr();
    let origin = g.bool().then(|| g.socket_addr());
    let other = g.bool().then(|| g.socket_addr());
    let answer = binding_success(&tid, mapped, origin, other);
    assert!(is_stun_response(&answer));
    let back = parse_binding_response(&answer, &tid).expect("an answer we wrote reads");
    assert_eq!(back.mapped, plain(mapped));
    assert_eq!(back.response_origin, origin.map(plain));
    assert_eq!(back.other_address, other.map(plain));
}
