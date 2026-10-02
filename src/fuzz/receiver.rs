//! The receiver as everybody on the network finds it, driven through its
//! dispatcher (`transport::receiver::DispatcherHarness`) with datagrams from
//! four addresses of the target's own:
//!
//! * [`handshake`]: handshakes of both versions from two senders, whole or
//!   in fragments in any order and number, with a cookie when the receiver
//!   asks for one; and whatever a stranger who knows the receiver's ID can
//!   send — initiations and fragments it stamps with a valid `mac1`,
//!   copies of what others sent, floods, noise — while time passes. Every
//!   transfer is declined.
//! * [`session`]: a transfer accepted, and a sender with its keys that sends
//!   what it likes under them — data at any offset, any frame, old and
//!   repeated packet numbers, from other addresses — while a stranger
//!   copies its packets and the handshake's strangers go on.
//!
//! What must hold after every step: nothing panics, in the dispatcher or in
//! a session; no address that has proven nothing (by sending a packet under
//! a session's keys) has been sent more bytes than came from it; the
//! dispatcher holds no more than its bounds allow; nothing is written
//! outside the directory the receiver receives into.

use super::gen::Gen;
use super::roundtrip::{hello, message};
use crate::crypto::handshake::{self as hs, forge, Initiator, Version};
use crate::crypto::transport::{begin_packet, SessionKeys, Suite};
use crate::crypto::{no_psk, Identity, SharpId};
use crate::protocol::wire::{self, MsgType};
use crate::transport::receiver::DispatcherHarness;
use crate::{AcceptPolicy, Receiver, ReceiverConfig};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PEERS: usize = 4;
/// Steps of one input at most.
const STEPS: usize = 24;
/// Datagrams kept for copies, and in each address's inbox.
const KEPT: usize = 32;

/// What lasts for the whole run: a receiver and the target's addresses.
struct World {
    rt: tokio::runtime::Runtime,
    receiver: Receiver,
    id: SharpId,
    senders: [Identity; 2],
    peers: Vec<UdpSocket>,
    addrs: Vec<SocketAddr>,
    accept: Arc<AtomicBool>,
    root: PathBuf,
    out: PathBuf,
    state: PathBuf,
}

impl World {
    fn new() -> Self {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let root =
            std::env::temp_dir().join(format!("sharp256-fuzz-receiver-{}", std::process::id()));
        let out = root.join("out");
        let state = root.join("state");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&out).expect("a directory to receive into");
        std::fs::create_dir_all(&state).expect("a directory for resume state");
        let accept = Arc::new(AtomicBool::new(false));
        let identity = Identity::generate();
        let id = identity.id();
        let mut cfg = ReceiverConfig::new("127.0.0.1:0".parse().expect("literal"), out.clone());
        // Its own identity and its own place for resume state: without them a
        // receiver takes the user's, from the per-user data directory.
        cfg.identity = Some(identity);
        cfg.state_dir = Some(state.clone());
        // Under load after three initiations in a second, not two hundred:
        // an input's two dozen steps could never reach the cookie exchange
        // otherwise (and did not, by the coverage of the first corpus).
        cfg.handshake_load_threshold = 3;
        cfg.nat_traversal = false;
        cfg.speak_v4 = true;
        // Version 3 is fuzzed too, as long as a receiver may be asked to
        // answer it.
        cfg.speak_v3 = true;
        let answer = accept.clone();
        cfg.accept = AcceptPolicy::Ask(Arc::new(
            move |_: crate::IncomingRequest, tx: tokio::sync::oneshot::Sender<bool>| {
                let _ = tx.send(answer.load(Ordering::Relaxed));
            },
        ));
        let receiver = rt.block_on(Receiver::new(cfg)).expect("a receiver");
        let peers: Vec<UdpSocket> = (0..PEERS)
            .map(|_| {
                let s = UdpSocket::bind("127.0.0.1:0").expect("a socket");
                s.set_nonblocking(true).expect("non-blocking");
                s
            })
            .collect();
        let addrs = peers
            .iter()
            .map(|s| s.local_addr().expect("bound"))
            .collect();
        Self {
            rt,
            receiver,
            id,
            senders: [Identity::generate(), Identity::generate()],
            peers,
            addrs,
            accept,
            root,
            out,
            state,
        }
    }
}

impl Drop for World {
    /// The run's directory goes with it, when the process ends normally.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

thread_local! {
    static WORLD: std::cell::OnceCell<World> = const { std::cell::OnceCell::new() };
}

/// A session the target holds the keys of, as its sender.
struct Held {
    keys: SessionKeys,
    /// The receiver's connection id, which packets to it carry.
    rcid: u64,
    next_pn: u64,
    /// Where it was made from.
    peer: usize,
    hello: wire::Hello,
    /// Its packets as sent, for a stranger to copy.
    sent: Vec<Vec<u8>>,
}

/// One input's worth of steps.
struct Run<'w> {
    w: &'w World,
    h: DispatcherHarness,
    now: Instant,
    /// Bytes from each address to the receiver, and from it to each.
    got: [u64; PEERS],
    sent: [u64; PEERS],
    /// Addresses a packet under a session's keys came from.
    proven: [bool; PEERS],
    inbox: [Vec<Vec<u8>>; PEERS],
    /// Every datagram sent to the receiver, for copies (the last few).
    log: Vec<(Vec<u8>, Option<Version>)>,
    cookies: [Option<[u8; hs::MAC_LEN]>; PEERS],
    /// Stamped datagrams' connection ids and mac1s, to open cookie replies
    /// to them: what a stranger at its own address can do.
    stamped: Vec<(usize, u64, [u8; hs::MAC_LEN])>,
    held: Vec<Held>,
}

impl<'w> Run<'w> {
    fn new(w: &'w World) -> Self {
        let _in_runtime = w.rt.enter();
        let h = DispatcherHarness::new(&w.receiver);
        let mut run = Self {
            w,
            h,
            now: Instant::now(),
            got: [0; PEERS],
            sent: [0; PEERS],
            proven: [false; PEERS],
            inbox: Default::default(),
            log: Vec::new(),
            cookies: [None; PEERS],
            stamped: Vec::new(),
            held: Vec::new(),
        };
        // What the last input's sessions sent after it ended is not ours.
        run.collect();
        run.sent = [0; PEERS];
        run.inbox = Default::default();
        run
    }

    /// Lets the sessions run until they wait for something.
    fn settle(&self) {
        self.w.rt.block_on(async {
            for _ in 0..32 {
                tokio::task::yield_now().await;
            }
        });
    }

    /// Whatever the receiver sent to the target's addresses.
    fn collect(&mut self) {
        let w = self.w;
        let mut buf = [0u8; 2048];
        for (p, s) in w.peers.iter().enumerate() {
            while let Ok((n, _)) = s.recv_from(&mut buf) {
                self.take(p, &buf[..n]);
            }
        }
    }

    /// One datagram the receiver sent to address `p`.
    fn take(&mut self, p: usize, d: &[u8]) {
        let w = self.w;
        self.sent[p] += d.len() as u64;
        if self.inbox[p].len() < KEPT {
            self.inbox[p].push(d.to_vec());
        }
        if d.len() == hs::COOKIE_REPLY_LEN {
            if let Some(c) = self
                .stamped
                .iter()
                .filter(|(q, _, _)| *q == p)
                .find_map(|(_, cid, m1)| forge::open_cookie_reply(&w.id, *cid, m1, d))
            {
                self.cookies[p] = Some(c);
            }
        }
    }

    /// Everything the receiver sent during the input, counted to it: a
    /// mark sent last to each address, and that address read until the mark
    /// is there. Without it, what arrived late on macOS was counted to the
    /// next input, at an address that had sent nothing in that one.
    fn fence(&mut self) {
        const MARK: &[u8] = b"sharp256 fuzz: all that came before has arrived";
        let w = self.w;
        let mut buf = [0u8; 2048];
        for p in 0..PEERS {
            if self.h.fence(w.addrs[p], MARK).is_err() {
                continue;
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                match w.peers[p].recv_from(&mut buf) {
                    Ok((n, _)) if &buf[..n] == MARK => break,
                    Ok((n, _)) => {
                        let d = buf[..n].to_vec();
                        self.take(p, &d);
                    }
                    Err(_) if std::time::Instant::now() < deadline => std::thread::yield_now(),
                    Err(_) => panic!("the fence to address {} never arrived", p),
                }
            }
        }
    }

    /// One datagram from `peer`, and what comes of it.
    fn deliver(&mut self, pkt: &[u8], peer: usize, kind: Option<Version>) {
        self.got[peer] += pkt.len() as u64;
        if self.log.len() >= KEPT {
            self.log.remove(0);
        }
        self.log.push((pkt.to_vec(), kind));
        let w = self.w;
        {
            let _in_runtime = w.rt.enter();
            self.h.datagram(pkt, w.addrs[peer], self.now);
        }
        self.settle();
        self.collect();
        self.check();
    }

    fn check(&self) {
        for p in 0..PEERS {
            if !self.proven[p] {
                assert!(
                    self.sent[p] <= self.got[p],
                    "{} bytes went to an address that proved nothing and sent {}",
                    self.sent[p],
                    self.got[p]
                );
            }
        }
        let (sessions, _pending, fragments) = self.h.counts();
        assert!(sessions <= 16, "{} sessions", sessions);
        assert!(fragments <= hs::Fragments::CAPACITY);
    }

    fn stamp(&mut self, peer: usize, version: Version, body: &[u8]) -> Vec<u8> {
        let (pkt, m1) = forge::stamp(&self.w.id, version, body, self.cookies[peer].as_ref());
        if body.len() >= 8 {
            let cid = u64::from_be_bytes(body[..8].try_into().expect("eight bytes"));
            if self.stamped.len() >= KEPT {
                self.stamped.remove(0);
            }
            self.stamped.push((peer, cid, m1));
        }
        pkt
    }

    // ----- what senders do -----------------------------------------------

    /// A handshake of version 3 by sender `s` from `peer`; the session, if
    /// the receiver answered with one.
    fn handshake_v3(
        &mut self,
        g: &mut Gen,
        s: usize,
        peer: usize,
        hello: wire::Hello,
    ) -> Option<Held> {
        let init = |g: &mut Gen, hello: &wire::Hello| {
            let init = wire::Initiation {
                timestamp: hs::initiation_timestamp(),
                suites: g.pick(&[1, 2, 3]),
                hardware_aes: g.bool(),
                hello_flags: g.u8() & 0x0f,
                hello: hello.clone(),
            };
            if g.bool() {
                wire::encode_padded_initiation(&init)
            } else {
                wire::encode_initiation(&init)
            }
        };
        let mut att = Initiator::new(&self.w.senders[s], &self.w.id, &no_psk()).ok()?;
        let payload = init(g, &hello);
        let pkt = att.initiation(&payload, self.cookies[peer].as_ref()).ok()?;
        self.deliver(&pkt, peer, Some(Version::V3));
        // Asked for a cookie: once more, with it, as a sender does.
        if let Some(c) = self.inbox[peer]
            .iter()
            .find_map(|d| att.read_cookie_reply(d))
        {
            self.cookies[peer] = Some(c);
            att = Initiator::new(&self.w.senders[s], &self.w.id, &no_psk()).ok()?;
            let payload = init(g, &hello);
            let pkt = att.initiation(&payload, Some(&c)).ok()?;
            self.deliver(&pkt, peer, Some(Version::V3));
        }
        let mut answer = None;
        for d in &self.inbox[peer] {
            if let Ok(a) = att.read_response(d) {
                answer = Some(a);
                break;
            }
        }
        let (rcid, payload, split) = answer?;
        let suite = Suite::from_u8(wire::decode_response(&payload).ok()?.suite)?;
        Some(Held {
            keys: SessionKeys::derive(&split, true, suite),
            rcid,
            next_pn: 0,
            peer,
            hello,
            sent: Vec::new(),
        })
    }

    /// A handshake of version 4, its fragments in the order (and number)
    /// the input says, then its HELLO; the session, if one was made.
    fn handshake_v4(
        &mut self,
        g: &mut Gen,
        s: usize,
        peer: usize,
        hello: wire::Hello,
    ) -> Option<Held> {
        let mut att = Initiator::new_v4(&self.w.senders[s], &self.w.id, &no_psk()).ok()?;
        let payload = wire::encode_initiation_v4(&wire::InitiationV4 {
            timestamp: hs::initiation_timestamp(),
            suites: g.pick(&[1, 2, 3]),
            hardware_aes: g.bool(),
        });
        let frags = att
            .initiation_datagrams(&payload, self.cookies[peer].as_ref())
            .ok()?;
        let mut order: Vec<usize> = (0..frags.len()).collect();
        for i in (1..order.len()).rev() {
            order.swap(i, g.below(i + 1));
        }
        if g.u8() % 4 == 0 {
            order.push(order[0]);
        }
        if g.u8() % 8 == 0 {
            order.pop();
        }
        for i in order {
            // Now and then from another address, as a mobile sender might.
            let from = if g.u8() % 16 == 0 {
                g.below(PEERS)
            } else {
                peer
            };
            self.deliver(&frags[i], from, Some(Version::V4));
        }
        let mut answer = None;
        for d in &self.inbox[peer] {
            if let Ok(a) = att.read_response(d) {
                answer = Some(a);
                break;
            }
        }
        let (rcid, payload, split) = answer?;
        let suite = Suite::from_u8(wire::decode_response_v4(&payload).ok()?.suite)?;
        let mut held = Held {
            keys: SessionKeys::derive(&split, true, suite),
            rcid,
            next_pn: 0,
            peer,
            hello: hello.clone(),
            sent: Vec::new(),
        };
        let mut body = Vec::new();
        wire::encode_body(&wire::Message::Hello(hello), &mut body, usize::MAX);
        self.packet(
            &mut held,
            wire::type_byte(MsgType::Hello, 0),
            &body,
            peer,
            None,
        );
        Some(held)
    }

    /// A packet of `held`'s under its keys, from `peer`: the next packet
    /// number, or `pn`.
    fn packet(&mut self, held: &mut Held, tb: u8, body: &[u8], peer: usize, pn: Option<u64>) {
        let pn = pn.unwrap_or_else(|| {
            held.next_pn += 1;
            held.next_pn - 1
        });
        let mut pkt = Vec::with_capacity(body.len() + 64);
        begin_packet(&mut pkt, held.rcid, tb, pn);
        pkt.extend_from_slice(body);
        if held.keys.send.seal(&mut pkt).is_err() {
            return;
        }
        self.proven[peer] = true;
        if held.sent.len() >= KEPT {
            held.sent.remove(0);
        }
        held.sent.push(pkt.clone());
        self.deliver(&pkt, peer, None);
    }

    // ----- what strangers do ----------------------------------------------

    /// One thing a stranger who knows the receiver's ID does, from `peer`.
    fn stranger(&mut self, g: &mut Gen, peer: usize) {
        match g.below(8) {
            // A copy of something sent before, from here.
            0 if !self.log.is_empty() => {
                let (pkt, _) = self.log[g.below(self.log.len())].clone();
                self.deliver(&pkt, peer, None);
            }
            // A copy with bytes changed, stamped again when it was a
            // handshake's (anybody can make its mac1).
            1 if !self.log.is_empty() => {
                let (mut pkt, kind) = self.log[g.below(self.log.len())].clone();
                for _ in 0..1 + g.below(4) {
                    if !pkt.is_empty() {
                        let i = g.below(pkt.len());
                        pkt[i] ^= 1 << g.below(8);
                    }
                }
                match kind {
                    Some(v) if pkt.len() > 2 * hs::MAC_LEN && g.bool() => {
                        let body = pkt[..pkt.len() - 2 * hs::MAC_LEN].to_vec();
                        let pkt = self.stamp(peer, v, &body);
                        self.deliver(&pkt, peer, Some(v));
                    }
                    _ => self.deliver(&pkt, peer, kind),
                }
            }
            // An initiation of its own making, stamped.
            2 => {
                let mut body = g.u64().to_be_bytes().to_vec();
                body.extend(g.bytes(hs::INITIATION_OVERHEAD + 300));
                let pkt = self.stamp(peer, Version::V3, &body);
                self.deliver(&pkt, peer, Some(Version::V3));
            }
            // A fragment of its own making, stamped.
            3 => {
                let mut body = g.u64().to_be_bytes().to_vec();
                body.push(g.u8());
                body.extend(g.bytes(hs::FRAGMENT_CHUNK + 8));
                let pkt = self.stamp(peer, Version::V4, &body);
                self.deliver(&pkt, peer, Some(Version::V4));
            }
            // Many initiations at once: the receiver comes under load.
            4 => {
                for _ in 0..g.below(48) {
                    let mut body = g.u64().to_be_bytes().to_vec();
                    body.extend(std::iter::repeat_n(0x5a, hs::INITIATION_OVERHEAD));
                    let pkt = self.stamp(peer, Version::V3, &body);
                    self.deliver(&pkt, peer, Some(Version::V3));
                }
            }
            // A packet to a connection the receiver has, of noise.
            5 => {
                let cids: Vec<u64> = self.held.iter().map(|h| h.rcid).collect();
                let cid = if cids.is_empty() {
                    g.u64()
                } else {
                    cids[g.below(cids.len())]
                };
                let mut pkt = cid.to_be_bytes().to_vec();
                pkt.extend(g.bytes(1400));
                self.deliver(&pkt, peer, None);
            }
            // Time passes: enough, now and then, for cookies and patience
            // to run out.
            6 => {
                let ms = u64::from(g.u16()) * if g.u8() % 8 == 0 { 8 } else { 1 };
                self.now += Duration::from_millis(ms);
            }
            // Noise.
            _ => {
                let pkt = g.bytes(1500);
                self.deliver(&pkt, peer, None);
            }
        }
    }

    /// Ends the input: everything sent counted to it and the bound checked
    /// once more, every session ended (its panic, if it had one, passed
    /// on), and nothing written where it should not be.
    fn finish(mut self) {
        self.fence();
        self.check();
        let Run { w, h, .. } = self;
        w.rt.block_on(h.finish());
        let stray: Vec<_> = std::fs::read_dir(&w.root)
            .expect("the run's directory")
            .flatten()
            .map(|e| e.file_name())
            .filter(|n| n != "out" && n != "state")
            .collect();
        assert!(
            stray.is_empty(),
            "written beside the output directory: {:?}",
            stray
        );
        // Each input starts from nothing: no file, no resume state of the
        // last one's.
        for dir in [&w.out, &w.state] {
            for e in std::fs::read_dir(dir)
                .expect("the run's directory")
                .flatten()
            {
                let p = e.path();
                let _ = std::fs::remove_dir_all(&p).or_else(|_| std::fs::remove_file(&p));
            }
        }
    }
}

/// A HELLO the receiver can take: a file of up to 256 KiB, or now and then
/// whatever the generator makes.
fn small_hello(g: &mut Gen) -> wire::Hello {
    let mut h = hello(g);
    if g.u8() % 8 != 0 {
        h.file_size %= 256 << 10;
        h.tree = None;
    }
    h
}

/// Handshakes, and strangers at them. Every transfer is declined.
pub fn handshake(data: &[u8]) {
    WORLD.with(|w| {
        let w = w.get_or_init(World::new);
        w.accept.store(false, Ordering::Relaxed);
        let mut g = Gen::new(data);
        let mut run = Run::new(w);
        for _ in 0..STEPS {
            if g.is_empty() {
                break;
            }
            let peer = g.below(PEERS);
            match g.below(4) {
                0 => {
                    let h = small_hello(&mut g);
                    let s = g.below(2);
                    let _ = run.handshake_v3(&mut g, s, peer, h);
                }
                1 => {
                    let h = small_hello(&mut g);
                    let s = g.below(2);
                    let _ = run.handshake_v4(&mut g, s, peer, h);
                }
                _ => run.stranger(&mut g, peer),
            }
        }
        run.finish();
    });
}

/// A transfer accepted, and its sender doing what it likes under its keys,
/// with strangers about. The last address is only ever a stranger's.
pub fn session(data: &[u8]) {
    WORLD.with(|w| {
        let w = w.get_or_init(World::new);
        w.accept.store(true, Ordering::Relaxed);
        let mut g = Gen::new(data);
        let mut run = Run::new(w);
        let h = small_hello(&mut g);
        let held = if g.bool() {
            run.handshake_v4(&mut g, 0, 0, h)
        } else {
            run.handshake_v3(&mut g, 0, 0, h)
        };
        if let Some(held) = held {
            run.held.push(held);
        }
        for _ in 0..STEPS {
            if g.is_empty() || run.held.is_empty() {
                break;
            }
            let mut held = run.held.remove(0);
            let peer = if g.u8() % 8 == 0 {
                g.below(PEERS - 1)
            } else {
                held.peer
            };
            match g.below(6) {
                // File data, somewhere in the file or past it.
                0 | 1 => {
                    let offset = g.u64() % (held.hello.file_size.saturating_add(4096).max(1));
                    let payload = g.bytes(1400);
                    let mut body = Vec::new();
                    wire::encode_body(
                        &wire::Message::Data(wire::Data {
                            offset,
                            timestamp: g.u32(),
                            payload: &payload,
                        }),
                        &mut body,
                        usize::MAX,
                    );
                    let tb = wire::type_byte(MsgType::Data, g.u8() & 0x0f);
                    run.packet(&mut held, tb, &body, peer, None);
                }
                // Any frame, well formed.
                2 => {
                    let payload = g.bytes(256);
                    let m = message(&mut g, &payload);
                    let mut body = Vec::new();
                    wire::encode_body(&m, &mut body, usize::MAX);
                    let tb = wire::type_byte(m.msg_type(), g.u8() & 0x0f);
                    run.packet(&mut held, tb, &body, peer, None);
                }
                // Any type byte and any body, at any packet number.
                3 => {
                    let tb = g.u8();
                    let body = g.bytes(1400);
                    let pn = g.bool().then(|| g.u64() >> (g.u8() % 64));
                    run.packet(&mut held, tb, &body, peer, pn);
                }
                // A stranger copies one of its packets.
                4 if !held.sent.is_empty() => {
                    let pkt = held.sent[g.below(held.sent.len())].clone();
                    run.deliver(&pkt, PEERS - 1, None);
                }
                _ => run.stranger(&mut g, PEERS - 1),
            }
            run.held.push(held);
        }
        run.finish();
    });
}
