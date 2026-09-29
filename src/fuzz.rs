//! Entry points for fuzzing: everything that reads bytes somebody else
//! chose, one function per kind of input.
//!
//! They are what the targets in `fuzz/` call under libFuzzer (`cargo fuzz`,
//! which builds with `--cfg fuzzing`), and what the smoke test at the end of
//! this file runs on thousands of mutated inputs in every `cargo test`, so
//! that a stable toolchain exercises the same code. A panic anywhere below
//! is a finding. So is a broken invariant: a message that decodes but does
//! not come back the same after being encoded and decoded again means the
//! two directions disagree about the format, which is how parsers end up
//! accepting what nobody could have sent.
//!
//! Not part of the crate's interface: compiled only for tests and fuzzing.

use crate::address::{self, class, dns, nat64};
use crate::protocol::wire;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

/// A transport frame: a type byte and a body, as a session delivers them
/// after decryption — from a peer that holds the keys, but is not trusted.
pub fn wire_frame(data: &[u8]) {
    let Some((&first, body)) = data.split_first() else {
        return;
    };
    let Ok((ty, _flags)) = wire::parse_type_byte(first) else {
        return;
    };
    let Ok(msg) = wire::decode_body(ty, body) else {
        return;
    };
    assert_eq!(msg.msg_type(), ty);
    let mut out = Vec::new();
    wire::encode_body(&msg, &mut out, usize::MAX);
    let back = wire::decode_body(ty, &out).expect("an encoded frame decodes");
    assert_eq!(back, msg, "a frame does not survive a round trip");
}

/// The payloads inside the handshake messages.
pub fn handshake_payload(data: &[u8]) {
    if let Ok(i) = wire::decode_initiation(data) {
        let again = wire::encode_initiation(&i);
        assert_eq!(
            wire::decode_initiation(&again).expect("re-decodes"),
            i,
            "an initiation does not survive a round trip"
        );
    }
    if let Ok(r) = wire::decode_response(data) {
        let again = wire::encode_response(&r);
        let mut back = wire::decode_response(&again).expect("re-decodes");
        // Our encoder shortens the free text to keep a response within one
        // control datagram; a peer's encoder need not have. Everything else
        // must come back exactly, and the text as a prefix of what it was.
        assert!(
            r.ack.message.starts_with(&back.ack.message),
            "the text of a response came back changed, not shortened"
        );
        back.ack.message.clone_from(&r.ack.message);
        assert_eq!(back, r, "a response does not survive a round trip");
    }
}

/// Keys and identities fixed for the whole run, so that every input meets
/// the same receiver.
struct Fixture {
    responder: crate::crypto::handshake::Responder,
    receiver: crate::crypto::SharpId,
    sender: crate::crypto::Identity,
    keys: crate::crypto::transport::DirectionKeys,
}

fn fixture() -> &'static Fixture {
    static F: std::sync::OnceLock<Fixture> = std::sync::OnceLock::new();
    F.get_or_init(|| {
        let receiver = crate::crypto::Identity::generate();
        let id = receiver.id();
        Fixture {
            responder: crate::crypto::handshake::Responder::new(receiver, crate::crypto::no_psk()),
            receiver: id,
            sender: crate::crypto::Identity::generate(),
            keys: crate::crypto::transport::DirectionKeys::new(
                crate::crypto::transport::Suite::ChaCha20Poly1305,
                &[7; 32],
            ),
        }
    })
}

/// Whole datagrams as a receiver or sender gets them from the network:
/// handshake initiations (MACs first, then Noise), responses and cookie
/// replies to an attempt, transport packets.
pub fn datagram(data: &[u8]) {
    let f = fixture();
    let _ = crate::crypto::transport::peek_cid(data);
    let _ = f.responder.read_initiation(data);
    if let Ok(mut attempt) =
        crate::crypto::handshake::Initiator::new(&f.sender, &f.receiver, &crate::crypto::no_psk())
    {
        let _ = attempt.read_cookie_reply(data);
        let _ = attempt.read_response(data);
    }
    let mut copy = data.to_vec();
    let _ = f.keys.open(&mut copy);
}

/// A directory listing, as a sender sends it.
pub fn manifest(data: &[u8]) {
    let Ok(m) = crate::file::tree::Manifest::decode(data) else {
        return;
    };
    let once = m.encode();
    let back = crate::file::tree::Manifest::decode(&once).expect("an encoded listing decodes");
    assert_eq!(
        back.encode(),
        once,
        "a listing does not survive a round trip"
    );
    assert_eq!(m.encoded_len() as usize, once.len());
}

/// Text that comes from users, files and name servers: receiver addresses,
/// relays, identities, rates, sizes.
pub fn text(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    let _ = address::parse_peer(&s);
    if let Ok((host, port)) = dns::split_host_port(&s) {
        assert!(!host.is_empty());
        let _ = port;
    }
    let _ = dns::parse_literal(&s);
    let _ = address::targets(&[s.to_string()]);
    let _ = s.parse::<crate::crypto::SharpId>();
    let _ = crate::progress::parse_rate(&s);
    let _ = crate::progress::parse_bytes(&s);
    let _ = crate::state::parse_hex16(&s);
    #[cfg(feature = "nat-traversal")]
    {
        let _ = crate::relay::parse_relay(&s);
        let _ = crate::nat::parse_if_inet6(&s);
    }
}

/// Addresses, as bytes: what every screen and ordering makes of them, and
/// the NAT64 arithmetic, whose round trip must hold for every valid prefix.
pub fn addresses(data: &[u8]) {
    let mut addrs = Vec::new();
    for chunk in data.chunks(18) {
        let port = u16::from_be_bytes([
            chunk.first().copied().unwrap_or(0),
            *chunk.get(1).unwrap_or(&0),
        ]);
        let rest = chunk.get(2..).unwrap_or(&[]);
        let ip: IpAddr = if rest.len() >= 16 {
            Ipv6Addr::from(<[u8; 16]>::try_from(&rest[..16]).expect("16 bytes")).into()
        } else if rest.len() >= 4 {
            Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]).into()
        } else {
            continue;
        };
        let scope = if rest.len() >= 16 {
            u32::from(rest[15] & 3)
        } else {
            0
        };
        let addr = match ip {
            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, u32::from(port), scope)),
            v4 => SocketAddr::new(v4, port),
        };
        let c = address::canonical(addr);
        assert_eq!(address::canonical(c), c, "canonical form is not stable");
        assert_eq!(class::classify(addr.ip()), class::classify(c.ip()));
        let _ = (class::precedence(ip), class::label(ip), class::scope(ip));
        let _ = class::is_publishable_host(ip);
        for local in ["0.0.0.0:0", "[::]:0", "127.0.0.1:0", "[::1]:0"] {
            let local: SocketAddr = local.parse().expect("literal");
            let _ = class::is_sendable_hint(addr, local);
            let _ = class::is_sendable_named(addr, local);
        }
        let _ = address::client_key(addr);
        addrs.push(addr);
    }
    let sorted = class::interleave_families(&addrs);
    assert_eq!(sorted.len(), addrs.len());
    let mut by_source = addrs.clone();
    class::sort_by_source(&mut by_source, |d| Some(d.ip()));
    assert_eq!(by_source.len(), addrs.len());

    let v6: Vec<Ipv6Addr> = data
        .chunks_exact(16)
        .map(|c| Ipv6Addr::from(<[u8; 16]>::try_from(c).expect("16 bytes")))
        .collect();
    if let Some(p) = nat64::from_answers(&v6) {
        for a in &v6 {
            let v4 = p
                .extract(*a)
                .expect("every answer lies in the prefix it gave");
            assert!(nat64::WELL_KNOWN_V4.contains(&v4));
        }
    }
    if let (Some(&len), Some(first)) = (data.first(), v6.first()) {
        if let Some(p) = nat64::Prefix::new(*first, len) {
            let v4 = Ipv4Addr::new(data[1 % data.len()], data[2 % data.len()], 0, 1);
            assert_eq!(p.extract(p.synthesize(v4)), Some(v4), "NAT64 round trip");
        }
    }
}

/// The relay protocol: what a relay reads from anyone, and what a peer
/// reads from a relay.
#[cfg(feature = "nat-traversal")]
pub fn relay_message(data: &[u8]) {
    let control = crate::relay::is_control(data);
    if let Some(m) = crate::relay::Message::decode(data) {
        assert!(control, "decoded something that is not a control message");
        let again = m.encode();
        assert_eq!(
            crate::relay::Message::decode(&again).as_ref(),
            Some(&m),
            "a relay message does not survive a round trip"
        );
        assert_eq!(again.as_slice(), data, "two encodings of one relay message");
    }
}

/// A contact card, as a person pastes it: from bytes, and as text.
#[cfg(feature = "nat-traversal")]
pub fn card(data: &[u8]) {
    use crate::nat::card::Card;
    if let Ok(c) = Card::decode(data) {
        assert_eq!(c.encode().as_slice(), data, "two encodings of one card");
        assert_eq!(
            Card::from_text(&c.to_text()).as_ref(),
            Ok(&c),
            "a card does not survive being written as text"
        );
        // Whatever it says, asking it for addresses must not panic.
        let _ = c.punch_targets();
        let _ = c.hints_for(&"203.0.113.1:1".parse().expect("literal"));
    }
    // Text: anything at all, of which a card is a tiny part.
    let _ = Card::from_text(&String::from_utf8_lossy(data));
}

/// STUN, as a receiver reads it from servers it did not choose — and as
/// the tests' servers read requests.
#[cfg(feature = "nat-traversal")]
pub fn stun(data: &[u8]) {
    use crate::nat::stun;
    let _ = stun::is_stun_message(data);
    let _ = stun::requested_change(data);
    let _ = stun::requested_response_port(data);
    // With the transaction id the message itself carries, the parser gets
    // past the check that would stop most random input.
    if let Some(tid) = stun::message_transaction_id(data) {
        if let Ok(r) = stun::parse_binding_response(data, &tid) {
            let _ = r.mapped.port();
        }
    }
}

/// PCP and NAT-PMP answers from whatever claims to be the router.
#[cfg(feature = "nat-traversal")]
pub fn portmap(data: &[u8]) {
    use crate::nat::portmap;
    let _ = portmap::pmp_parse_external_response(data);
    let port = data
        .get(8..10)
        .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
    let _ = portmap::pmp_parse_map_response(data, port);
    // The nonce and port the answer carries, so that it is read in full.
    let nonce: [u8; 12] = data
        .get(24..36)
        .and_then(|b| b.try_into().ok())
        .unwrap_or([0; 12]);
    let internal = data
        .get(40..42)
        .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
    let _ = portmap::pcp_parse_map_response(data, &nonce, internal);
}

/// UPnP: SSDP answers, device descriptions and SOAP answers, from devices
/// on the local network.
#[cfg(feature = "nat-traversal")]
pub fn upnp(data: &[u8]) {
    use crate::nat::upnp;
    let _ = upnp::parse_http_answer(data);
    let s = String::from_utf8_lossy(data);
    let _ = upnp::header(&s, "LOCATION");
    let _ = upnp::element(&s, "controlURL");
    let _ = upnp::element(&s, "NewExternalIPAddress");
    let location = upnp::Url::parse("http://192.168.1.1:5000/rootDesc.xml").expect("literal");
    let _ = upnp::find_service(&s, &location);
    if let Some(u) = upnp::Url::parse(&s) {
        let _ = u.join("/ctl/IPConn");
    }
    let _ = location.join(&s);
    // The same over IPv6: addresses in brackets, a zone after them, and the
    // answers to a search of the IPv6 groups.
    let location = upnp::Url::parse("http://[fe80::1%25eth0]:5000/rootDesc.xml").expect("literal");
    let _ = upnp::find_service(&s, &location);
    let _ = location.join(&s);
    let _ = upnp::Url::parse(&format!("http://[{}]:80/x", s.trim()));
    upnp::fuzz_answer_v6(data);
}

/// Multicast DNS, as a receiver reads questions from anyone on its network
/// and a sender reads answers from anyone there.
#[cfg(feature = "nat-traversal")]
pub fn mdns(data: &[u8]) {
    use crate::nat::mdns;
    let id = fixture().receiver;
    if let Some(m) = mdns::Message::decode(data) {
        // Whatever it says, answering it and reading it as an answer must
        // not panic, and what is answered decodes again.
        let host = mdns::Announcement {
            id,
            port: 5555,
            addresses: vec![
                "192.0.2.7".parse().expect("literal"),
                "2001:db8::7".parse().expect("literal"),
            ],
        };
        if let Some(answer) = host.answer(&m) {
            if let Some(bytes) = answer.encode() {
                assert!(
                    mdns::Message::decode(&bytes).is_some(),
                    "an answer that cannot be read back"
                );
            }
        }
        let _ = mdns::addresses_in(&m, &id);
        let _ = m.encode();
    }
}

/// TURN and STUN messages as a client reads them from a server it was told
/// to use, and ChannelData framing.
#[cfg(feature = "nat-traversal")]
pub fn turn(data: &[u8]) {
    use crate::nat::turn::wire;
    if let Some(m) = wire::parse(data) {
        let _ = m.xor_address(wire::ATTR_XOR_PEER_ADDRESS);
        let _ = m.xor_address(wire::ATTR_XOR_RELAYED_ADDRESS);
        let _ = m.lifetime();
        let _ = m.error();
        let _ = m.text(wire::ATTR_REALM);
        let _ = m.attrs_of(wire::ATTR_XOR_PEER_ADDRESS).count();
        let key = wire::Credentials::new("user", "realm", "password", b"nonce");
        let _ = m.integrity_is_good(key.key());
    }
    if let Some((channel, payload)) = wire::parse_channel_data(data) {
        assert!((wire::CHANNEL_MIN..=0x7fff).contains(&channel));
        assert!(payload.len() <= data.len());
        // What is framed is read back the same.
        let framed = wire::channel_data(channel, payload);
        assert_eq!(wire::parse_channel_data(&framed), Some((channel, payload)));
    }
    let _ = wire::looks_like_channel_data(data);
    let _ = wire::parse_xor_address(data, &[1; 12]);
}

/// The DHT: bencoding, and a node's answer to a query.
#[cfg(feature = "nat-traversal")]
pub fn dht(data: &[u8]) {
    use crate::nat::dht::bencode;
    if let Some(v) = bencode::decode(data) {
        // What is read is written the one way, and that reads the same.
        let again = bencode::encode(&v);
        assert_eq!(
            bencode::decode(&again).as_ref(),
            Some(&v),
            "bencoding does not survive a round trip"
        );
        crate::nat::dht::fuzz_reply(&v);
    }
}

/// One entry point: what reads the bytes.
pub type Target = fn(&[u8]);

/// Every entry point, by the name of its target in `fuzz/`.
pub const TARGETS: &[(&str, Target)] = &[
    ("wire_frame", wire_frame),
    ("handshake_payload", handshake_payload),
    ("datagram", datagram),
    ("manifest", manifest),
    ("text", text),
    ("addresses", addresses),
    #[cfg(feature = "nat-traversal")]
    ("relay_message", relay_message),
    #[cfg(feature = "nat-traversal")]
    ("card", card),
    #[cfg(feature = "nat-traversal")]
    ("stun", stun),
    #[cfg(feature = "nat-traversal")]
    ("portmap", portmap),
    #[cfg(feature = "nat-traversal")]
    ("upnp", upnp),
    #[cfg(feature = "nat-traversal")]
    ("mdns", mdns),
    #[cfg(feature = "nat-traversal")]
    ("turn", turn),
    #[cfg(feature = "nat-traversal")]
    ("dht", dht),
];

/// Well-formed inputs for each target, made by the encoders: the starting
/// points mutation works from (and the seed corpus in `fuzz/corpus`).
pub fn seeds(target: &str) -> Vec<Vec<u8>> {
    match target {
        "wire_frame" => seed_frames(),
        "handshake_payload" => {
            let init = wire::Initiation {
                timestamp: 1 << 40,
                suites: 3,
                hardware_aes: true,
                hello_flags: 1,
                hello: seed_hello(),
            };
            vec![wire::encode_initiation(&init)]
        }
        "datagram" => {
            let f = fixture();
            let mut attempt = crate::crypto::handshake::Initiator::new(
                &f.sender,
                &f.receiver,
                &crate::crypto::no_psk(),
            )
            .expect("initiator");
            let payload = wire::encode_initiation(&wire::Initiation {
                timestamp: crate::crypto::handshake::initiation_timestamp(),
                suites: 3,
                hardware_aes: false,
                hello_flags: 0,
                hello: seed_hello(),
            });
            let init = attempt.initiation(&payload, None).expect("initiation");
            let mut pkt = Vec::new();
            crate::crypto::transport::begin_packet(&mut pkt, 7, 1, 3);
            pkt.extend_from_slice(b"body");
            let _ = f.keys.seal(&mut pkt);
            vec![init, pkt]
        }
        "manifest" => Vec::new(),
        "text" => vec![
            b"sh-aaaa@203.0.113.5:5555,[2001:db8::1]:5555,example.org:1".to_vec(),
            b"[fe80::1%eth0]:5555".to_vec(),
            b"100M".to_vec(),
            b"4GiB".to_vec(),
            b"20010db8000000000000000000000001 02 40 00 01     eth0".to_vec(),
        ],
        "addresses" => {
            let mut v = vec![96u8, 1, 2];
            v.extend_from_slice(
                &nat64::Prefix::WELL_KNOWN
                    .synthesize(nat64::WELL_KNOWN_V4[0])
                    .octets(),
            );
            v.extend_from_slice(&[0x13, 0x88, 192, 0, 2, 1]);
            vec![v]
        }
        #[cfg(feature = "nat-traversal")]
        "relay_message" => seed_relay(),
        #[cfg(feature = "nat-traversal")]
        "card" => seed_cards(),
        #[cfg(feature = "nat-traversal")]
        "stun" => {
            let tid = [9u8; 12];
            vec![
                crate::nat::stun::binding_request(&tid),
                crate::nat::stun::binding_request_with_change(&tid, true, true),
                crate::nat::stun::binding_request_with_response_port(&tid, 5000),
                crate::nat::stun::binding_success(
                    &tid,
                    "203.0.113.9:50000".parse().expect("literal"),
                    Some("198.51.100.1:3478".parse().expect("literal")),
                    Some("[2001:db8::2]:3479".parse().expect("literal")),
                ),
            ]
        }
        #[cfg(feature = "nat-traversal")]
        "portmap" => vec![
            crate::nat::portmap::pmp_map_request(5555, 5555, 3600),
            crate::nat::portmap::pcp_map_request(
                &[1; 12],
                "192.168.1.7".parse().expect("literal"),
                5555,
                5555,
                3600,
            ),
        ],
        #[cfg(feature = "nat-traversal")]
        "upnp" => vec![
            b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nLOCATION: http://[2001:db8:1::1]:5000/rootDesc.xml\r\n\r\n"
                .to_vec(),
            b"HTTP/1.1 200 OK\r\nLOCATION: http://[fe80::1%25eth0]:5000/rootDesc.xml\r\n\r\n"
                .to_vec(),
            b"HTTP/1.0 200 OK\r\n\r\n<root><URLBase>http://192.168.1.1:5000/</URLBase><device>\
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>\
<controlURL>/ctl/IPConn</controlURL></service></device></root>"
                .to_vec(),
            b"<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>\
203.0.113.9</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
                .to_vec(),
        ],
        #[cfg(feature = "nat-traversal")]
        "mdns" => {
            use crate::nat::mdns;
            let id = fixture().receiver;
            let host = mdns::Announcement {
                id,
                port: 5555,
                addresses: vec![
                    "192.0.2.7".parse().expect("literal"),
                    "2001:db8::7".parse().expect("literal"),
                ],
            };
            let query = mdns::query_for(&id);
            let mut out = Vec::new();
            out.extend(query.encode());
            out.extend(host.answer(&query).and_then(|a| a.encode()));
            out
        }
        #[cfg(feature = "nat-traversal")]
        "turn" => {
            use crate::nat::turn::wire::*;
            let tid = [5u8; 12];
            let cred = Credentials::new("alice", "example.org", "s3cret", b"nonce");
            let peer: std::net::SocketAddr = "198.51.100.7:4000".parse().expect("literal");
            vec![
                Builder::new(ALLOCATE, Class::Request, &tid)
                    .attr(ATTR_REQUESTED_TRANSPORT, &[TRANSPORT_UDP, 0, 0, 0])
                    .finish_authenticated(&cred),
                Builder::new(ALLOCATE, Class::Success, &tid)
                    .xor_address(
                        ATTR_XOR_RELAYED_ADDRESS,
                        "203.0.113.9:49152".parse().expect("literal"),
                    )
                    .xor_address(
                        ATTR_XOR_MAPPED_ADDRESS,
                        "[2001:db8::5]:40000".parse().expect("literal"),
                    )
                    .attr(ATTR_LIFETIME, &600u32.to_be_bytes())
                    .finish_with_integrity(cred.key()),
                Builder::new(DATA, Class::Indication, &tid)
                    .xor_address(ATTR_XOR_PEER_ADDRESS, peer)
                    .attr(ATTR_DATA, b"payload")
                    .finish(),
                Builder::new(ALLOCATE, Class::Error, &tid)
                    .attr(ATTR_ERROR_CODE, &[0, 0, 4, 1, b'n', b'o'])
                    .attr(ATTR_REALM, b"example.org")
                    .attr(ATTR_NONCE, b"nonce")
                    .finish(),
                channel_data(0x4001, b"a datagram"),
            ]
        }
        #[cfg(feature = "nat-traversal")]
        "dht" => {
            use crate::nat::dht::bencode::{encode, Value};
            let mut nodes = Vec::new();
            for i in 0..3u8 {
                nodes.extend_from_slice(&[i; 20]);
                nodes.extend_from_slice(&[10, 0, 0, i, 0x1a, 0xe1]);
            }
            vec![
                encode(&Value::dict(vec![
                    ("t", Value::bytes(b"abcd")),
                    ("y", Value::bytes(b"r")),
                    (
                        "r",
                        Value::dict(vec![
                            ("id", Value::bytes(&[5; 20])),
                            ("token", Value::bytes(b"tok")),
                            ("nodes", Value::Bytes(nodes)),
                            (
                                "values",
                                Value::List(vec![Value::bytes(&[1, 2, 3, 4, 0x1f, 0x90])]),
                            ),
                        ]),
                    ),
                ])),
                encode(&Value::dict(vec![
                    ("t", Value::bytes(b"abcd")),
                    ("y", Value::bytes(b"e")),
                    (
                        "e",
                        Value::List(vec![Value::Int(203), Value::bytes(b"bad token")]),
                    ),
                ])),
            ]
        }
        _ => Vec::new(),
    }
}

fn seed_hello() -> wire::Hello {
    wire::Hello {
        transfer_id: [3; 16],
        timestamp: 77,
        file_size: 1 << 30,
        file_mtime: 1_700_000_000,
        max_chunk: 1400,
        capabilities: 0,
        tree: None,
        file_name: "seed.bin".to_string(),
    }
}

fn seed_frames() -> Vec<Vec<u8>> {
    let frames = [
        wire::Message::Hello(seed_hello()),
        wire::Message::Ping(wire::Ping { timestamp: 5 }),
        wire::Message::PathChallenge(wire::PathChallenge { data: [4; 8] }),
        wire::Message::Abort(wire::Abort {
            code: 3,
            reason: "seed".to_string(),
        }),
    ];
    frames
        .iter()
        .map(|m| {
            let mut out = vec![wire::type_byte(m.msg_type(), 0)];
            wire::encode_body(m, &mut out, usize::MAX);
            out
        })
        .collect()
}

#[cfg(feature = "nat-traversal")]
fn seed_cards() -> Vec<Vec<u8>> {
    use crate::nat::card::{Candidate, Card, Kind, NatHints, RelayRef, Role};
    let id = fixture().receiver;
    let mut full = Card::new(Role::Receiver, id);
    full.created = 1_700_000_000;
    full.candidates = vec![
        Candidate {
            kind: Kind::Mapped,
            addr: "203.0.113.9:40000".parse().expect("literal"),
        },
        Candidate {
            kind: Kind::Host,
            addr: "[2001:db8::5]:5555".parse().expect("literal"),
        },
        Candidate {
            kind: Kind::Relayed,
            addr: "198.51.100.1:41000".parse().expect("literal"),
        },
    ];
    full.v4 = Some(NatHints {
        mapping: 3,
        filtering: 3,
        allocation: crate::nat::behaviour::Allocation::Sequential,
        delta: 2,
        hairpin: Some(false),
        cgn: true,
    });
    full.v6 = Some(NatHints::unknown());
    full.relays = vec![RelayRef {
        id,
        addr: "198.51.100.1:5560".parse().expect("literal"),
    }];
    let mut bare = Card::new(Role::Sender, id);
    bare.created = 1_700_000_000;
    vec![full.encode(), bare.encode()]
}

#[cfg(feature = "nat-traversal")]
fn seed_relay() -> Vec<Vec<u8>> {
    use crate::nat::card::NatHints;
    use crate::relay::{Alt, Hints, Message, Refusal, PROOF_LEN, TOKEN_LEN};
    let id = fixture().receiver;
    let sequential = Hints {
        nat: NatHints {
            mapping: 3,
            allocation: crate::nat::behaviour::Allocation::Sequential,
            delta: 2,
            ..NatHints::unknown()
        },
        alt: None,
    };
    // The other family's address, in each spelling.
    let with_v6 = Hints {
        nat: sequential.nat,
        alt: Some(Alt {
            addr: "[2a0e:aa00:1:1::1]:40000".parse().expect("literal"),
            nat: NatHints {
                mapping: 4,
                filtering: 3,
                ..NatHints::unknown()
            },
        }),
    };
    let with_v4 = Hints {
        nat: NatHints::unknown(),
        alt: Some(Alt {
            addr: "198.18.0.1:7".parse().expect("literal"),
            nat: sequential.nat,
        }),
    };
    [
        Message::Register {
            hints: with_v6,
            id,
            token: [1; TOKEN_LEN],
            flags: 1,
            stamp: 42,
            proof: [2; PROOF_LEN],
            nonce: [0x5a; 16],
        },
        Message::Register {
            hints: Hints::none(),
            id,
            token: [1; TOKEN_LEN],
            flags: 0,
            stamp: 43,
            proof: [2; PROOF_LEN],
            nonce: [0x5a; 16],
        },
        Message::Connect {
            hints: with_v4,
            target: id,
            token: [3; TOKEN_LEN],
            nonce: [0x5a; 16],
        },
        Message::Connect {
            hints: Hints::none(),
            target: id,
            token: [3; TOKEN_LEN],
            nonce: [0x5a; 16],
        },
        Message::ConnectAs {
            hints: with_v6,
            target: id,
            token: [3; TOKEN_LEN],
            id,
            proof: [4; PROOF_LEN],
            nonce: [0x5a; 16],
        },
        Message::Allocated {
            hints: sequential,
            port: 40000,
            peer: "203.0.113.5:4000".parse().expect("literal"),
            ticket: [5; TOKEN_LEN],
            tag: [0; 16],
        },
        Message::Allocated {
            hints: with_v6,
            port: 40000,
            peer: "203.0.113.5:4000".parse().expect("literal"),
            ticket: [5; TOKEN_LEN],
            tag: [0; 16],
        },
        Message::Incoming {
            hints: with_v4,
            port: 40001,
            peer: "[2001:db8::7]:4000".parse().expect("literal"),
            ticket: [6; TOKEN_LEN],
            tag: [0; 16],
        },
        Message::Registered {
            lease: 120,
            observed: "[2001:db8::1]:5555".parse().expect("literal"),
            tag: [0; 16],
        },
        Message::Error {
            code: Refusal::Forbidden,
            tag: [0; 16],
        },
        Message::Punch,
    ]
    .iter()
    .map(|m| m.encode())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic mutator: flips, overwrites, truncates, extends and
    /// splices, the way a fuzzer's first rounds do.
    fn mutate(rng: &mut u64, seed: &[u8], other: &[u8]) -> Vec<u8> {
        let mut next = || {
            // xorshift64*
            *rng ^= *rng >> 12;
            *rng ^= *rng << 25;
            *rng ^= *rng >> 27;
            rng.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        let mut v = seed.to_vec();
        for _ in 0..(1 + next() % 4) {
            match next() % 6 {
                0 if !v.is_empty() => {
                    let i = (next() as usize) % v.len();
                    v[i] ^= 1 << (next() % 8);
                }
                1 if !v.is_empty() => {
                    let i = (next() as usize) % v.len();
                    v[i] = next() as u8;
                }
                2 => {
                    let n = (next() as usize) % (v.len() + 1);
                    v.truncate(n);
                }
                3 => {
                    for _ in 0..(next() % 16) {
                        v.push(next() as u8);
                    }
                }
                4 if !other.is_empty() => {
                    let from = (next() as usize) % other.len();
                    let at = (next() as usize) % (v.len() + 1);
                    let take = (next() as usize) % (other.len() - from + 1);
                    v.splice(at..at, other[from..from + take].iter().copied());
                }
                _ => {
                    if !v.is_empty() {
                        let i = (next() as usize) % v.len();
                        v[i] = [0, 0xff, 0x7f, 0x80][(next() % 4) as usize];
                    }
                }
            }
        }
        v
    }

    /// Every target, on its seeds, on nothing and on noise, and on a few
    /// thousand mutations of the seeds: no panic, no broken round trip.
    /// `cargo fuzz` goes much further (see `fuzz/`); this keeps every
    /// `cargo test`, on any toolchain, going this far.
    #[test]
    fn every_target_survives_mutated_input() {
        let rounds: usize = std::env::var("SHARP_FUZZ_ROUNDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3000);
        for (name, target) in TARGETS {
            let mut seeds = seeds(name);
            // Inputs that once crashed a target are kept in its corpus, and
            // run here on every toolchain.
            let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fuzz/corpus")
                .join(name);
            if let Ok(dir) = std::fs::read_dir(&corpus) {
                for e in dir.flatten() {
                    if e.file_name().to_string_lossy().starts_with("regression-") {
                        seeds.push(std::fs::read(e.path()).unwrap());
                    }
                }
            }
            seeds.push(Vec::new());
            seeds.push(vec![0; 64]);
            seeds.push((0..=255).collect());
            for s in &seeds {
                target(s);
            }
            let mut rng = 0x9e37_79b9_7f4a_7c15u64 ^ name.len() as u64;
            for i in 0..rounds {
                let seed = &seeds[i % seeds.len()];
                let other = &seeds[(i / seeds.len()) % seeds.len()];
                let input = mutate(&mut rng, seed, other);
                target(&input);
            }
        }
    }

    /// The seeds are what the encoders make, so every one of them must be
    /// read back: a seed the parser refuses would mean the corpus starts
    /// the fuzzer nowhere.
    #[test]
    fn the_seeds_are_well_formed() {
        for frame in seeds("wire_frame") {
            let (ty, _) = wire::parse_type_byte(frame[0]).unwrap();
            wire::decode_body(ty, &frame[1..]).unwrap();
        }
        #[cfg(feature = "nat-traversal")]
        for m in seeds("relay_message") {
            assert!(crate::relay::Message::decode(&m).is_some());
        }
        #[cfg(feature = "nat-traversal")]
        for c in seeds("card") {
            assert!(crate::nat::card::Card::decode(&c).is_ok());
        }
        #[cfg(feature = "nat-traversal")]
        for m in seeds("mdns") {
            assert!(crate::nat::mdns::Message::decode(&m).is_some());
        }
        #[cfg(feature = "nat-traversal")]
        for m in seeds("turn").iter().take(4) {
            assert!(crate::nat::turn::wire::parse(m).is_some());
        }
        #[cfg(feature = "nat-traversal")]
        for m in seeds("dht") {
            assert!(crate::nat::dht::bencode::decode(&m).is_some());
        }
    }

    /// Runs one target on one file — a crash `cargo fuzz` left in
    /// `fuzz/artifacts` — with the stable toolchain and a full backtrace:
    /// `SHARP_FUZZ_TARGET=datagram SHARP_FUZZ_INPUT=path cargo test --lib
    /// reproduce -- --nocapture`.
    #[test]
    fn reproduce_an_artifact_when_asked() {
        let (Some(target), Some(input)) = (
            std::env::var_os("SHARP_FUZZ_TARGET"),
            std::env::var_os("SHARP_FUZZ_INPUT"),
        ) else {
            return;
        };
        let target = target.to_string_lossy().into_owned();
        let run = TARGETS
            .iter()
            .find(|(n, _)| *n == target)
            .unwrap_or_else(|| panic!("no target {}", target))
            .1;
        run(&std::fs::read(input).unwrap());
    }

    /// Writes the seed corpus for `cargo fuzz` into `fuzz/corpus/<target>`
    /// (run with `SHARP_WRITE_CORPUS=1`).
    #[test]
    fn write_seed_corpus_when_asked() {
        if std::env::var_os("SHARP_WRITE_CORPUS").is_none() {
            return;
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
        for (name, _) in TARGETS {
            let dir = root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            for (i, s) in seeds(name).iter().enumerate() {
                std::fs::write(dir.join(format!("seed-{}", i)), s).unwrap();
            }
        }
    }
}
