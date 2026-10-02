//! The test vectors of `docs/vectors`, checked against this crate's code.
//!
//! The vectors are computed by a second implementation of PROTOCOL.md that
//! shares no code with this one (`scripts/vectors`, in Go: its own BLAKE3
//! and Noise, Go's X25519, AES-GCM and ML-KEM, x/crypto's ChaCha20-Poly1305,
//! BLAKE2s and Argon2id), and CI checks that it still computes them. Every
//! value here is then computed twice. What the crate's other tests cannot
//! see is a change both of its own ends make alike — a nonce, a MAC key or
//! a label that is wrong the same way on both sides interoperates with
//! itself perfectly; against these files it does not.
//!
//! Every random value of a handshake is given (see the `fix` methods of
//! `handshake` and `noise`): the bytes on the wire are then fixed too.

use crate::crypto::handshake::{self, Fragments, Initiator, Responder, Version};
use crate::crypto::identity::{Identity, SharpId};
use crate::crypto::identity_file::IdentityFile;
use crate::crypto::transport::{self, begin_packet, DirectionKeys, SessionKeys, Suite};
use crate::crypto::SecretKey;
use serde_json::Value;
use std::time::Instant;

fn load(json: &str) -> Value {
    serde_json::from_str(json).expect("a vector file is JSON")
}

fn cases(v: &Value) -> &Vec<Value> {
    v["cases"].as_array().expect("cases")
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("a hex string");
    assert!(s.len() % 2 == 0, "odd hex: {}", s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    hex(v).try_into().expect("a value of its length")
}

fn cid(v: &Value) -> u64 {
    u64::from_be_bytes(arr(v))
}

fn num(v: &Value) -> u64 {
    v.as_u64().expect("a number")
}

/// A suite by the name the vectors give it, which is the crate's own.
fn suite(v: &Value) -> Suite {
    let name = v.as_str().expect("a suite's name");
    [Suite::Aes256Gcm, Suite::ChaCha20Poly1305]
        .into_iter()
        .find(|s| s.name() == name)
        .unwrap_or_else(|| panic!("no suite is called {}", name))
}

#[test]
fn ids_are_as_specified() {
    let v = load(include_str!("../docs/vectors/ids.json"));
    for c in cases(&v) {
        let id = SharpId::from_public(arr(&c["public_key"]));
        let (v3, v4) = (c["id_v3"].as_str().unwrap(), c["id_v4"].as_str().unwrap());
        assert_eq!(id.text(Version::V3), v3);
        assert_eq!(id.to_string(), v3);
        assert_eq!(id.text(Version::V4), v4);
        assert_eq!(SharpId::parse_versioned(v3).unwrap(), (id, Version::V3));
        assert_eq!(SharpId::parse_versioned(v4).unwrap(), (id, Version::V4));
    }
}

#[test]
fn pre_shared_keys_are_as_specified() {
    let v = load(include_str!("../docs/vectors/psk.json"));
    let cases = cases(&v);
    // The first case is the protocol's own cost.
    assert_eq!(
        num(&cases[0]["memory_kib"]),
        crate::crypto::PSK_MEMORY_KIB as u64
    );
    assert_eq!(num(&cases[0]["passes"]), crate::crypto::PSK_PASSES as u64);
    for c in cases {
        assert_eq!(num(&c["lanes"]), 1);
        let psk = crate::crypto::psk_from_passphrase_with_cost(
            c["passphrase"].as_str().unwrap(),
            &SharpId::from_public(arr(&c["receiver_public_key"])),
            num(&c["memory_kib"]) as u32,
            num(&c["passes"]) as u32,
        );
        assert_eq!(psk.expose()[..], hex(&c["psk"])[..]);
    }
}

#[test]
fn a_sealed_identity_file_is_as_specified() {
    let v = load(include_str!("../docs/vectors/identity_file.json"));
    // The cost a new file is sealed with.
    use crate::crypto::identity_file::{
        PASSPHRASE_LANES, PASSPHRASE_MEMORY_KIB, PASSPHRASE_PASSES,
    };
    let d = &v["defaults"];
    assert_eq!(num(&d["memory_kib"]), PASSPHRASE_MEMORY_KIB as u64);
    assert_eq!(num(&d["passes"]), PASSPHRASE_PASSES as u64);
    assert_eq!(num(&d["lanes"]), PASSPHRASE_LANES as u64);
    for c in cases(&v) {
        let public: [u8; 32] = arr(&c["public_key"]);
        assert_eq!(
            *Identity::from_secret(arr(&c["secret_key"])).public(),
            public
        );
        let text = format!("# a comment\n{}\n", c["line"].as_str().unwrap());
        let file = IdentityFile::parse(text.as_bytes()).unwrap();
        let opened = file.open(Some(c["passphrase"].as_str().unwrap())).unwrap();
        assert_eq!(*opened.public(), public);
        assert!(file.open(Some("another passphrase")).is_err());
    }
}

#[test]
fn mac_keys_are_as_specified() {
    let v = load(include_str!("../docs/vectors/mac_keys.json"));
    for c in v["cases"]["public_keys"].as_array().unwrap() {
        let p = arr(&c["public_key"]);
        assert_eq!(handshake::mac1_key(&p)[..], hex(&c["mac1_key_v3"])[..]);
        assert_eq!(handshake::mac1_key_v4(&p)[..], hex(&c["mac1_key_v4"])[..]);
        assert_eq!(handshake::cookie_key(&p)[..], hex(&c["cookie_key"])[..]);
    }
    for c in v["cases"]["cookies"].as_array().unwrap() {
        assert_eq!(
            handshake::mac2_key(&arr(&c["cookie"]))[..],
            hex(&c["mac2_key"])[..]
        );
    }
}

#[test]
fn a_cookie_reply_is_as_specified() {
    let v = load(include_str!("../docs/vectors/cookie_reply.json"));
    for c in cases(&v) {
        let key = handshake::cookie_key(&arr(&c["receiver_public_key"]));
        let reply = hex(&c["reply"]);
        let mac1 = arr(&c["mac1"]);
        let got = handshake::open_cookie(&key, &[mac1], cid(&c["sender_cid"]), &reply);
        assert_eq!(got, Some(arr(&c["cookie"])));
        // Sealed to that mac1, and to that connection id.
        let mut other = mac1;
        other[0] ^= 1;
        assert_eq!(
            handshake::open_cookie(&key, &[other], cid(&c["sender_cid"]), &reply),
            None
        );
        assert_eq!(
            handshake::open_cookie(&key, &[mac1], cid(&c["sender_cid"]) ^ 1, &reply),
            None
        );
    }
}

#[test]
fn traffic_keys_are_as_specified() {
    let v = load(include_str!("../docs/vectors/traffic.json"));
    for c in cases(&v) {
        let secret = transport::traffic_secret(&arr(&c["split_key"]), &arr(&c["handshake_hash"]));
        assert_eq!(secret[..], hex(&c["traffic_secret"])[..]);
        assert_eq!(transport::iv_of(&secret)[..], hex(&c["iv"])[..]);
        assert_eq!(
            transport::header_key_of(&secret)[..],
            hex(&c["header_protection_key"])[..]
        );
        for k in c["aead_keys"].as_array().unwrap() {
            assert_eq!(
                transport::aead_key_of(&secret, num(&k["epoch"]))[..],
                hex(&k["key"])[..],
                "epoch {}",
                k["epoch"]
            );
        }
    }
}

/// Seals `body` as a packet the way the session does, and opens the
/// vector's packet with the same keys.
fn check_packet(keys: &DirectionKeys, c: &Value) {
    let (dcid, t, pn) = (
        cid(&c["dcid"]),
        num(&c["type"]) as u8,
        num(&c["packet_number"]),
    );
    let mut buf = Vec::new();
    begin_packet(&mut buf, dcid, t, pn);
    buf.extend_from_slice(&hex(&c["body"]));
    keys.seal(&mut buf).unwrap();
    assert_eq!(buf, hex(&c["packet"]), "packet number {}", pn);
    let mut theirs = hex(&c["packet"]);
    let (got_t, got_pn, body) = keys.open(&mut theirs).unwrap();
    assert_eq!((got_t, got_pn), (t, pn));
    assert_eq!(body, &hex(&c["body"])[..]);
}

#[test]
fn transport_packets_are_as_specified() {
    let v = load(include_str!("../docs/vectors/packets.json"));
    for c in cases(&v) {
        check_packet(
            &DirectionKeys::new(suite(&c["suite"]), &arr(&c["traffic_secret"])),
            c,
        );
    }
}

/// A whole handshake: the sender's datagrams, the receiver's reading of
/// them and its answer, the sender's reading of that, the keys both end
/// with, and the first packet each way under them.
fn check_handshake(c: &Value, version: Version) {
    let initiator_identity = Identity::from_secret(arr(&c["initiator_static_secret"]));
    let responder_identity = Identity::from_secret(arr(&c["responder_static_secret"]));
    assert_eq!(
        initiator_identity.public()[..],
        hex(&c["initiator_static_public"])[..]
    );
    assert_eq!(
        responder_identity.public()[..],
        hex(&c["responder_static_public"])[..]
    );
    let psk = SecretKey::from_bytes(&arr(&c["psk"]));
    let (scid, rcid) = (cid(&c["sender_cid"]), cid(&c["receiver_cid"]));
    let cookie: Option<[u8; 16]> = c.get("cookie").map(arr);
    let kem_seed: Option<[u8; 64]> = c.get("kem_seed").map(arr);
    let kem_random: Option<[u8; 32]> = c.get("kem_encapsulation_random").map(arr);
    let suite = suite(&c["suite"]);

    let mut initiator = match version {
        Version::V3 => Initiator::new(&initiator_identity, &responder_identity.id(), &psk),
        Version::V4 => Initiator::new_v4(&initiator_identity, &responder_identity.id(), &psk),
    }
    .unwrap();
    initiator.fix(
        scid,
        SecretKey::from_bytes(&arr(&c["initiator_ephemeral_secret"])),
        kem_seed.as_ref(),
    );
    let datagrams = initiator
        .initiation_datagrams(&hex(&c["initiation_payload"]), cookie.as_ref())
        .unwrap();
    let want: Vec<Vec<u8>> = c["initiation_datagrams"]
        .as_array()
        .unwrap()
        .iter()
        .map(hex)
        .collect();
    assert_eq!(datagrams, want, "the initiation");

    let responder = Responder::new(responder_identity.clone(), psk.clone());
    let mut incoming = match version {
        Version::V3 => {
            assert!(responder.is_initiation(&want[0]));
            responder.read_initiation(&want[0]).unwrap()
        }
        Version::V4 => {
            let mut fragments = Fragments::default();
            let from = "192.0.2.1:4000".parse().unwrap();
            let mut whole = None;
            for d in &want {
                let f = responder.fragment(d).expect("a fragment for this receiver");
                whole = fragments.add(d, f, from, Instant::now());
            }
            let whole = whole.expect("every fragment in");
            assert_eq!(whole.sender_cid, scid);
            responder
                .read_initiation_v4(whole.sender_cid, &whole.msg)
                .unwrap()
        }
    };
    assert_eq!(incoming.version, version);
    assert_eq!(incoming.sender_cid, scid);
    assert_eq!(incoming.sender, initiator_identity.id());
    assert_eq!(incoming.payload, hex(&c["initiation_payload"]));
    incoming.fix(
        SecretKey::from_bytes(&arr(&c["responder_ephemeral_secret"])),
        kem_random,
    );
    let (response, responder_split) = incoming
        .respond(rcid, &hex(&c["response_payload"]))
        .unwrap();
    assert_eq!(response, hex(&c["response_datagram"]), "the response");

    let (got_rcid, payload, initiator_split) = initiator.read_response(&response).unwrap();
    assert_eq!(got_rcid, rcid);
    assert_eq!(payload, hex(&c["response_payload"]));
    for split in [&initiator_split, &responder_split] {
        assert_eq!(split.hash[..], hex(&c["handshake_hash"])[..]);
        assert_eq!(
            split.initiator_to_responder[..],
            hex(&c["split_initiator_to_responder"])[..]
        );
        assert_eq!(
            split.responder_to_initiator[..],
            hex(&c["split_responder_to_initiator"])[..]
        );
    }
    let sender = SessionKeys::derive(&initiator_split, true, suite);
    let receiver = SessionKeys::derive(&responder_split, false, suite);
    check_packet(&sender.send, &c["first_packet_initiator_to_responder"]);
    check_packet(&receiver.send, &c["first_packet_responder_to_initiator"]);
    // And each opens what the other sealed.
    let mut i2r = hex(&c["first_packet_initiator_to_responder"]["packet"]);
    assert!(receiver.recv.open(&mut i2r).is_ok());
    let mut r2i = hex(&c["first_packet_responder_to_initiator"]["packet"]);
    assert!(sender.recv.open(&mut r2i).is_ok());
}

#[test]
fn version_3_handshakes_are_as_specified() {
    let v = load(include_str!("../docs/vectors/handshake_v3.json"));
    for c in cases(&v) {
        check_handshake(c, Version::V3);
    }
}

#[test]
fn version_4_handshakes_are_as_specified() {
    let v = load(include_str!("../docs/vectors/handshake_v4.json"));
    for c in cases(&v) {
        check_handshake(c, Version::V4);
    }
}

// ---------------------------------------------------------------------------
// Section 8: the relay, contact cards, the DHT, carriers other than UDP
// ---------------------------------------------------------------------------

#[cfg(feature = "nat-traversal")]
mod reachability {
    use super::*;
    use crate::nat::card::{Candidate, Card, Kind, NatHints, RelayRef, Role};
    use crate::relay::{self, Alt, Hints, Message, Refusal};
    use std::net::SocketAddr;

    fn addr(v: &Value) -> SocketAddr {
        v.as_str().expect("an address").parse().expect("an address")
    }

    fn nat(v: &Value) -> NatHints {
        NatHints::from_bytes(&arr(v)).expect("hints this version writes")
    }

    fn hints(v: &Value) -> Hints {
        Hints {
            nat: nat(&v["nat"]),
            alt: v["alt"].as_object().map(|_| Alt {
                addr: addr(&v["alt"]["addr"]),
                nat: nat(&v["alt"]["nat"]),
            }),
        }
    }

    fn id(v: &Value) -> SharpId {
        SharpId::from_public(arr(v))
    }

    /// The message a vector describes, field by field, with the codes of
    /// PROTOCOL.md's table.
    fn message(c: &Value) -> Message {
        let token = || arr(&c["token"]);
        match num(&c["kind"]) {
            1 => Message::Register {
                id: id(&c["id"]),
                token: token(),
                flags: num(&c["flags"]) as u8,
                stamp: num(&c["stamp"]),
                hints: hints(&c["hints"]),
                nonce: arr(&c["nonce"]),
                proof: arr(&c["proof"]),
            },
            2 => Message::Challenge {
                token: token(),
                tag: arr(&c["tag"]),
            },
            3 => Message::Registered {
                lease: num(&c["lease"]) as u32,
                observed: addr(&c["observed"]),
                tag: arr(&c["tag"]),
            },
            4 => Message::Connect {
                target: id(&c["target"]),
                token: token(),
                hints: hints(&c["hints"]),
                nonce: arr(&c["nonce"]),
            },
            5 => Message::Allocated {
                port: num(&c["port"]) as u16,
                peer: addr(&c["peer"]),
                ticket: arr(&c["ticket"]),
                hints: hints(&c["hints"]),
                tag: arr(&c["tag"]),
            },
            6 => Message::Incoming {
                port: num(&c["port"]) as u16,
                peer: addr(&c["peer"]),
                ticket: arr(&c["ticket"]),
                hints: hints(&c["hints"]),
                tag: arr(&c["tag"]),
            },
            7 => Message::Error {
                code: match num(&c["code"]) {
                    1 => Refusal::Unknown,
                    2 => Refusal::BadToken,
                    3 => Refusal::Busy,
                    4 => Refusal::Stale,
                    5 => Refusal::Forbidden,
                    n => panic!("no refusal {}", n),
                },
                tag: arr(&c["tag"]),
            },
            8 => Message::Open {
                ticket: arr(&c["ticket"]),
                proof: arr(&c["proof"]),
            },
            9 => Message::Punch,
            10 => Message::Bye {
                id: id(&c["id"]),
                token: token(),
                stamp: num(&c["stamp"]),
                nonce: arr(&c["nonce"]),
                proof: arr(&c["proof"]),
            },
            11 => Message::Confirm {
                proof: arr(&c["proof"]),
            },
            12 => Message::ConnectAs {
                target: id(&c["target"]),
                token: token(),
                hints: hints(&c["hints"]),
                nonce: arr(&c["nonce"]),
                id: id(&c["id"]),
                proof: arr(&c["proof"]),
            },
            k => panic!("no message of kind {}", k),
        }
    }

    #[test]
    fn relay_messages_are_as_specified() {
        let v = load(include_str!("../docs/vectors/relay.json"));
        let receiver = Identity::from_secret(arr(&v["receiver_static_secret"]));
        let sender = Identity::from_secret(arr(&v["sender_static_secret"]));
        let relay_identity = Identity::from_secret(arr(&v["relay_static_secret"]));
        let relay_id = relay_identity.id();
        // The registration keys, as the peer and as the relay make them.
        let kr = relay::auth_key(&receiver, &relay_id, &receiver.id(), &relay_id).unwrap();
        assert_eq!(kr.expose()[..], hex(&v["registration_key_receiver"])[..]);
        let kr_relay =
            relay::auth_key(&relay_identity, &receiver.id(), &receiver.id(), &relay_id).unwrap();
        assert_eq!(kr_relay.expose(), kr.expose());
        let ks = relay::auth_key(&sender, &relay_id, &sender.id(), &relay_id).unwrap();
        assert_eq!(ks.expose()[..], hex(&v["registration_key_sender"])[..]);
        let rnonce = arr(&v["receiver_nonce"]);
        for c in cases(&v) {
            let name = &c["name"];
            let bytes = hex(&c["message"]);
            let msg = message(c);
            assert_eq!(Message::decode(&bytes).as_ref(), Some(&msg), "{}", name);
            assert_eq!(msg.encode(), bytes, "{}", name);
            match num(&c["kind"]) {
                1 | 10 => assert!(relay::proof_is_good(&kr, &bytes), "{}", name),
                12 => assert!(relay::proof_is_good(&ks, &bytes), "{}", name),
                _ => {}
            }
            match c["tagged_by"].as_str() {
                Some("relay key") => {
                    assert!(relay::relay_tag_is_good(&kr, &rnonce, &bytes), "{}", name);
                    assert_eq!(relay::tagged(&kr, &rnonce, &msg), bytes, "{}", name);
                }
                Some("nonce") => assert!(relay::echoes(&arr(&c["tag"]), &bytes), "{}", name),
                _ => {}
            }
        }
    }

    #[test]
    fn contact_cards_are_as_specified() {
        let v = load(include_str!("../docs/vectors/cards.json"));
        for c in cases(&v) {
            let list = |key: &str| c[key].as_array().cloned().unwrap_or_default();
            let card = Card {
                role: match num(&c["role"]) {
                    1 => Role::Sender,
                    2 => Role::Receiver,
                    r => panic!("no role {}", r),
                },
                created: num(&c["created"]),
                id: id(&c["id"]),
                version: match num(&c["version"]) {
                    3 => Version::V3,
                    4 => Version::V4,
                    n => panic!("no version {}", n),
                },
                candidates: list("candidates")
                    .iter()
                    .map(|x| Candidate {
                        kind: match num(&x["kind"]) {
                            0 => Kind::Host,
                            1 => Kind::Mapped,
                            2 => Kind::PortMapped,
                            3 => Kind::Relayed,
                            k => panic!("no kind {}", k),
                        },
                        addr: addr(&x["addr"]),
                    })
                    .collect(),
                v4: c.get("v4_hints").map(nat),
                v6: c.get("v6_hints").map(nat),
                relays: list("relays")
                    .iter()
                    .map(|r| RelayRef {
                        id: id(&r["id"]),
                        addr: addr(&r["addr"]),
                    })
                    .collect(),
            };
            assert_eq!(card.encode(), hex(&c["body"]));
            assert_eq!(Card::decode(&hex(&c["body"])).unwrap(), card);
            let text = c["text"].as_str().unwrap();
            assert_eq!(card.to_text(), text);
            assert_eq!(Card::from_text(text).unwrap(), card);
            // As a chat client wraps it, and in capitals.
            let chars: Vec<char> = text.to_uppercase().chars().collect();
            let wrapped: Vec<String> = chars.chunks(23).map(|l| l.iter().collect()).collect();
            assert_eq!(Card::from_text(&wrapped.join("-\n  ")).unwrap(), card);
        }
    }

    #[test]
    fn dht_keys_are_as_specified() {
        use crate::nat::dht::{info_hash, rendezvous_key, Role};
        let v = load(include_str!("../docs/vectors/dht.json"));
        for c in cases(&v) {
            let secret = hex(&c["secret"]);
            let secret = (!secret.is_empty())
                .then(|| SecretKey::from_bytes(&secret.try_into().expect("32 bytes")));
            let key = rendezvous_key(&id(&c["receiver_id"]), secret.as_ref());
            assert_eq!(key.expose()[..], hex(&c["key"])[..]);
            assert_eq!(
                info_hash(key.expose(), Role::Receiver)[..],
                hex(&c["infohash_receiver"])[..]
            );
            assert_eq!(
                info_hash(key.expose(), Role::Sender)[..],
                hex(&c["infohash_sender"])[..]
            );
        }
    }
}

#[tokio::test]
async fn carrier_framing_is_as_specified() {
    use crate::transport::carrier::frame::{self, Frame, Kind};
    let v = load(include_str!("../docs/vectors/carriers.json"));
    assert_eq!(
        frame::preamble(Kind::Receiver)[..],
        hex(&v["preambles"]["receiver"])[..]
    );
    assert_eq!(
        frame::preamble(Kind::Relay)[..],
        hex(&v["preambles"]["relay"])[..]
    );
    for f in v["frames"].as_array().unwrap() {
        let data = hex(&f["data"]);
        let own = f["own"].as_bool().unwrap();
        let port = num(&f["port"]) as u16;
        let head = if own {
            frame::own_header(data.len())
        } else {
            frame::header(data.len(), port)
        };
        let bytes = hex(&f["frame"]);
        assert_eq!([&head[..], &data].concat(), bytes);
        // Read back: an empty frame is skipped, and the stream then ends.
        let read = frame::read_frame(&mut &bytes[..]).await.unwrap();
        let want = match (own, data.is_empty()) {
            (_, true) => None,
            (true, false) => Some(Frame::Own(data)),
            (false, false) => Some(Frame::Datagram { port, data }),
        };
        assert_eq!(read, want);
    }
}

#[cfg(feature = "tls")]
#[test]
fn the_tls_binding_is_as_specified() {
    use crate::relay::tls;
    use crate::transport::carrier::frame;
    let v = load(include_str!("../docs/vectors/carriers.json"));
    for b in v["tls_binding"].as_array().unwrap() {
        let relay = Identity::from_secret(arr(&b["relay_static_secret"]));
        let ephemeral = Identity::from_secret(arr(&b["ephemeral_secret"]));
        let nonce: [u8; 16] = arr(&b["nonce"]);
        let shared = ephemeral.shared_secret(&relay.id()).unwrap();
        assert_eq!(shared[..], hex(&b["shared_secret"])[..]);
        assert_eq!(
            relay.shared_secret(&ephemeral.id()).unwrap()[..],
            shared[..]
        );
        let mac = tls::binding_mac(
            &shared[..],
            ephemeral.id().as_bytes(),
            &relay.id(),
            &nonce,
            &arr(&b["exported_key"]),
        );
        assert_eq!(mac[..], hex(&b["mac"])[..]);
        let framed = |body: Vec<u8>| [&frame::own_header(body.len())[..], &body].concat();
        assert_eq!(
            framed(tls::ask(ephemeral.id().as_bytes(), &nonce)),
            hex(&b["ask_frame"])
        );
        assert_eq!(framed(tls::answer(&mac)), hex(&b["answer_frame"]));
    }
}

// ---------------------------------------------------------------------------
// Sections 2 (handshake payloads), 4 (frames) and 6 (a directory's manifest)
// ---------------------------------------------------------------------------

mod frames {
    use super::*;
    use crate::protocol::wire::{
        self, Abort, Ack, Data, Fin, FinAck, FinDone, Hello, HelloAck, Initiation, InitiationV4,
        Message, PathChallenge, PathResponse, Ping, Pong, Probe, ProbeAck, Response, ResponseV4,
        TreeInfo,
    };

    fn holes(v: &Value) -> Vec<(u64, u64)> {
        v.as_array().map_or(Vec::new(), |a| {
            a.iter().map(|h| (num(&h[0]), num(&h[1]))).collect()
        })
    }

    fn text(v: &Value) -> String {
        v.as_str().expect("text").to_string()
    }

    fn hello(v: &Value) -> Hello {
        let t = &v["tree"];
        Hello {
            transfer_id: arr(&v["transfer_id"]),
            timestamp: num(&v["timestamp"]) as u32,
            file_size: num(&v["file_size"]),
            file_mtime: v["file_mtime"].as_i64().expect("a number"),
            max_chunk: num(&v["max_chunk"]) as u16,
            capabilities: num(&v["capabilities"]) as u32,
            tree: t.as_object().map(|_| TreeInfo {
                manifest_len: num(&t["manifest_len"]),
                manifest_hash: arr(&t["manifest_hash"]),
                files: num(&t["files"]),
                dirs: num(&t["dirs"]),
            }),
            file_name: text(&v["name"]),
        }
    }

    fn hello_ack(v: &Value) -> HelloAck {
        HelloAck {
            status: num(&v["status"]) as u8,
            reason: num(&v["reason"]) as u8,
            max_chunk: num(&v["max_chunk"]) as u16,
            capabilities: num(&v["capabilities"]) as u32,
            echo_ts: num(&v["echo_ts"]) as u32,
            max_ack_delay_us: num(&v["max_ack_delay_us"]) as u32,
            rwnd: num(&v["rwnd"]),
            resume_upto: num(&v["resume_upto"]),
            known_end: num(&v["known_end"]),
            holes: holes(&v["holes"]),
            message: text(&v["message"]),
        }
    }

    fn ack(v: &Value) -> Ack {
        Ack {
            contiguous_upto: num(&v["contiguous_upto"]),
            highest: num(&v["highest"]),
            received_bytes: num(&v["received_bytes"]),
            echo_ts: num(&v["echo_ts"]) as u32,
            ack_delay_us: num(&v["ack_delay_us"]) as u32,
            rwnd: num(&v["rwnd"]),
            holes: holes(&v["holes"]),
        }
    }

    #[test]
    fn frames_are_as_specified() {
        let v = load(include_str!("../docs/vectors/frames.json"));
        for c in cases(&v) {
            let name = &c["name"];
            let bytes = c.get("bytes").map(hex).unwrap_or_default();
            let msg = match num(&c["type"]) {
                1 => Message::Hello(hello(&c["hello"])),
                2 => Message::HelloAck(hello_ack(&c["hello_ack"])),
                3 => Message::Data(Data {
                    offset: num(&c["offset"]),
                    timestamp: num(&c["value"]) as u32,
                    payload: &bytes,
                }),
                4 => Message::Ack(ack(&c["ack"])),
                5 => Message::Fin(Fin {
                    file_hash: arr(&c["bytes"]),
                }),
                6 => Message::FinAck(FinAck {
                    verdict: num(&c["verdict"]) as u8,
                    file_hash: arr(&c["bytes"]),
                }),
                7 => Message::Ping(Ping {
                    timestamp: num(&c["value"]) as u32,
                }),
                8 => Message::Pong(Pong {
                    echo: num(&c["value"]) as u32,
                }),
                9 => Message::Probe(Probe {
                    size: num(&c["size"]) as u16,
                }),
                10 => Message::ProbeAck(ProbeAck {
                    size: num(&c["size"]) as u16,
                }),
                11 => Message::Abort(Abort {
                    code: num(&c["code"]) as u16,
                    reason: text(&c["reason"]),
                }),
                12 => Message::FinDone(FinDone {
                    verdict: num(&c["verdict"]) as u8,
                }),
                13 => Message::PathChallenge(PathChallenge {
                    data: arr(&c["bytes"]),
                }),
                14 => Message::PathResponse(PathResponse {
                    data: arr(&c["bytes"]),
                }),
                t => panic!("no frame of type {}", t),
            };
            let (flags, type_byte) = (num(&c["flags"]) as u8, num(&c["type_byte"]) as u8);
            assert_eq!(
                wire::type_byte(msg.msg_type(), flags),
                type_byte,
                "{}",
                name
            );
            assert_eq!(
                wire::parse_type_byte(type_byte).unwrap(),
                (msg.msg_type(), flags),
                "{}",
                name
            );
            let body = hex(&c["body"]);
            let mut out = Vec::new();
            wire::encode_body(&msg, &mut out, usize::MAX);
            assert_eq!(out, body, "{}", name);
            assert_eq!(
                wire::decode_body(msg.msg_type(), &body).unwrap(),
                msg,
                "{}",
                name
            );
        }
    }

    #[test]
    fn handshake_payloads_are_as_specified() {
        let v = load(include_str!("../docs/vectors/frames.json"));
        let byte = |p: &Value, k: &str| p.get(k).map_or(0, num) as u8;
        for p in v["handshake_payloads"].as_array().unwrap() {
            let (name, payload) = (&p["name"], hex(&p["payload"]));
            match (num(&p["version"]), p.get("hello"), p.get("hello_ack")) {
                (3, Some(h), _) => {
                    let init = Initiation {
                        timestamp: num(&p["timestamp"]),
                        suites: byte(p, "suites"),
                        hardware_aes: p["hardware_aes"].as_bool().unwrap_or(false),
                        hello_flags: byte(p, "hello_flags"),
                        hello: hello(h),
                    };
                    let encoded = if p["padded"].as_bool().unwrap_or(false) {
                        wire::encode_padded_initiation(&init)
                    } else {
                        wire::encode_initiation(&init)
                    };
                    assert_eq!(encoded, payload, "{}", name);
                    assert_eq!(wire::decode_initiation(&payload).unwrap(), init, "{}", name);
                }
                (3, None, Some(a)) => {
                    let resp = Response {
                        suite: byte(p, "suite"),
                        ack_flags: byte(p, "ack_flags"),
                        ack: hello_ack(a),
                    };
                    assert_eq!(wire::encode_response(&resp), payload, "{}", name);
                    assert_eq!(wire::decode_response(&payload).unwrap(), resp, "{}", name);
                }
                (4, ..) if p.get("reason").is_some() => {
                    let resp = ResponseV4 {
                        suite: byte(p, "suite"),
                        reason: byte(p, "reason"),
                    };
                    assert_eq!(wire::encode_response_v4(&resp), payload, "{}", name);
                    assert_eq!(
                        wire::decode_response_v4(&payload).unwrap(),
                        resp,
                        "{}",
                        name
                    );
                }
                (4, ..) => {
                    let init = InitiationV4 {
                        timestamp: num(&p["timestamp"]),
                        suites: byte(p, "suites"),
                        hardware_aes: p["hardware_aes"].as_bool().unwrap_or(false),
                    };
                    assert_eq!(wire::encode_initiation_v4(&init), payload, "{}", name);
                    assert_eq!(
                        wire::decode_initiation_v4(&payload).unwrap(),
                        init,
                        "{}",
                        name
                    );
                }
                _ => panic!("no such payload: {}", name),
            }
        }
    }

    #[test]
    fn a_manifest_is_as_specified() {
        use crate::file::tree::{EntryKind, Manifest, Meta};
        let v = load(include_str!("../docs/vectors/manifest.json"));
        let bytes = hex(&v["manifest"]);
        let m = Manifest::decode(&bytes).unwrap();
        let meta = |e: &Value| Meta {
            mode: e["mode"].as_u64().map(|m| m as u32),
            mtime: e["mtime_seconds"]
                .as_i64()
                .map(|s| (s, num(&e["mtime_nanoseconds"]) as u32)),
        };
        assert_eq!(m.root_meta(), meta(&v["root"]));
        let entries = v["entries"].as_array().unwrap();
        assert_eq!(m.entries().len(), entries.len());
        for (i, (e, want)) in m.entries().iter().zip(entries).enumerate() {
            assert_eq!(u64::from(e.parent), num(&want["parent"]), "entry {}", i);
            assert_eq!(
                e.kind == EntryKind::Dir,
                want["dir"].as_bool().unwrap(),
                "entry {}",
                i
            );
            assert_eq!(m.name(i), want["name"].as_str().unwrap(), "entry {}", i);
            assert_eq!(e.size, num(&want["size"]), "entry {}", i);
            assert_eq!(e.meta, meta(want), "entry {}", i);
        }
        assert_eq!(m.files(), num(&v["files"]));
        assert_eq!(m.dirs(), num(&v["dirs"]));
        assert_eq!(m.data_len(), num(&v["data_len"]));
        assert_eq!(m.encode(), bytes);
        let info = m.info(&bytes);
        assert_eq!(info.manifest_hash[..], hex(&v["manifest_hash"])[..]);
        assert_eq!(info.manifest_len, bytes.len() as u64);
        // The directory HELLO of frames.json describes this manifest.
        let f = load(include_str!("../docs/vectors/frames.json"));
        let dir = cases(&f)
            .iter()
            .find_map(|c| c["hello"]["tree"].as_object().map(|_| hello(&c["hello"])))
            .expect("a directory's HELLO");
        assert_eq!(dir.tree, Some(info));
        assert_eq!(dir.file_size, m.stream_len());
    }
}
