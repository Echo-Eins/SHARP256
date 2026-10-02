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
    let v = load(include_str!("../../docs/vectors/ids.json"));
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
    let v = load(include_str!("../../docs/vectors/psk.json"));
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
    let v = load(include_str!("../../docs/vectors/identity_file.json"));
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
    let v = load(include_str!("../../docs/vectors/mac_keys.json"));
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
    let v = load(include_str!("../../docs/vectors/cookie_reply.json"));
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
    let v = load(include_str!("../../docs/vectors/traffic.json"));
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
    let v = load(include_str!("../../docs/vectors/packets.json"));
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
    let v = load(include_str!("../../docs/vectors/handshake_v3.json"));
    for c in cases(&v) {
        check_handshake(c, Version::V3);
    }
}

#[test]
fn version_4_handshakes_are_as_specified() {
    let v = load(include_str!("../../docs/vectors/handshake_v4.json"));
    for c in cases(&v) {
        check_handshake(c, Version::V4);
    }
}
