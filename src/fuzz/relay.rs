//! A relay (`relay::server::RelayHarness`) as its clients and everybody
//! else find it, from four addresses of the target's own: two receivers
//! registering (a token first, then proof of their key), a sender
//! connecting to them, both sides binding the port pair they are given
//! (an Open, the confirmation it draws, the Open repeated) and sending
//! through it, goodbyes; and a stranger at the last address, copying and
//! changing what the others sent, sending messages of every kind and
//! noise, to the control port and to the pairs' ports, while time passes.
//!
//! What must hold after every step: nothing panics, in the relay or in a
//! pair; no address that has proven nothing (by using a token or a
//! confirmation it received there) has been sent more bytes, by the
//! control port and the pairs together, than came from it; the relay
//! holds no more registrations and allocations than its limits.

use super::gen::Gen;
use crate::crypto::{Identity, SharpId};
use crate::relay::server::{Config, RelayHarness};
use crate::relay::{auth_key, proof_for, Hints, Message, NONCE_LEN, PROOF_LEN, TOKEN_LEN};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const PEERS: usize = 4;
const STEPS: usize = 32;
const KEPT: usize = 32;

struct World {
    rt: tokio::runtime::Runtime,
    receivers: [Identity; 2],
    sender: Identity,
    peers: Vec<UdpSocket>,
    addrs: Vec<SocketAddr>,
    relay_identity: Identity,
}

impl World {
    fn new() -> Self {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
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
            receivers: [Identity::generate(), Identity::generate()],
            sender: Identity::generate(),
            peers,
            addrs,
            relay_identity: Identity::generate(),
        }
    }
}

thread_local! {
    static WORLD: std::cell::OnceCell<World> = const { std::cell::OnceCell::new() };
}

/// A port pair's side as a peer was told of it.
#[derive(Clone, Copy)]
struct Side {
    peer: usize,
    port: u16,
    ticket: [u8; TOKEN_LEN],
    /// What the port's confirmation said, once it came.
    proof: Option<[u8; TOKEN_LEN]>,
}

struct Run<'w> {
    w: &'w World,
    h: RelayHarness,
    limits: (usize, usize),
    relay: SocketAddr,
    relay_id: SharpId,
    now: Instant,
    got: [u64; PEERS],
    sent: [u64; PEERS],
    proven: [bool; PEERS],
    /// The token each address was given.
    tokens: [Option<[u8; TOKEN_LEN]>; PEERS],
    stamps: [u64; 3],
    nonce: [u8; NONCE_LEN],
    sides: Vec<Side>,
    log: Vec<Vec<u8>>,
}

impl<'w> Run<'w> {
    fn new(w: &'w World, g: &mut Gen) -> Option<Self> {
        let mut cfg = Config {
            bind: "127.0.0.1:0".parse().expect("literal"),
            ..Config::default()
        };
        cfg.identity = w.relay_identity.clone();
        // Small limits, so that an input can reach them.
        cfg.max_registrations = 1 + g.below(4);
        cfg.max_allocations = 1 + g.below(4);
        let limits = (cfg.max_registrations, cfg.max_allocations);
        let h = w.rt.block_on(RelayHarness::bind(cfg)).ok()?;
        let relay = h.local_addr().ok()?;
        let relay_id = h.id();
        let mut run = Self {
            w,
            h,
            limits,
            relay,
            relay_id,
            now: Instant::now(),
            got: [0; PEERS],
            sent: [0; PEERS],
            proven: [false; PEERS],
            tokens: [None; PEERS],
            stamps: [1; 3],
            nonce: g.array(),
            sides: Vec::new(),
            log: Vec::new(),
        };
        // What the last input's pairs sent after it ended is not ours.
        run.collect();
        run.sent = [0; PEERS];
        run.sides.clear();
        run.tokens = [None; PEERS];
        Some(run)
    }

    fn settle(&self) {
        self.w.rt.block_on(async {
            for _ in 0..32 {
                tokio::task::yield_now().await;
            }
        });
    }

    /// What came to the target's addresses, and what the clients make of it.
    fn collect(&mut self) {
        let w = self.w;
        let mut buf = [0u8; 2048];
        for (p, s) in w.peers.iter().enumerate() {
            while let Ok((n, from)) = s.recv_from(&mut buf) {
                self.sent[p] += n as u64;
                match Message::decode(&buf[..n]) {
                    Some(Message::Challenge { token, .. }) if from == self.relay => {
                        self.tokens[p] = Some(token);
                    }
                    Some(
                        Message::Allocated { port, ticket, .. }
                        | Message::Incoming { port, ticket, .. },
                    ) if from == self.relay && self.sides.len() < KEPT => {
                        self.sides.push(Side {
                            peer: p,
                            port,
                            ticket,
                            proof: None,
                        });
                    }
                    Some(Message::Confirm { proof }) => {
                        if let Some(side) = self
                            .sides
                            .iter_mut()
                            .find(|s| s.peer == p && s.port == from.port())
                        {
                            side.proof = Some(proof);
                        }
                    }
                    _ => {}
                }
            }
        }
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
        let (registrations, allocations) = self.h.counts();
        assert!(
            registrations <= self.limits.0 && allocations <= self.limits.1,
            "{} registrations, {} allocations, beyond {:?}",
            registrations,
            allocations,
            self.limits
        );
    }

    /// A datagram to the control port.
    fn control(&mut self, pkt: &[u8], peer: usize) {
        self.got[peer] += pkt.len() as u64;
        if self.log.len() >= KEPT {
            self.log.remove(0);
        }
        self.log.push(pkt.to_vec());
        let from = self.w.addrs[peer];
        let now = self.now;
        self.w.rt.block_on(self.h.datagram(pkt, from, now));
        self.settle();
        self.collect();
        self.check();
    }

    /// A datagram to a pair's port, through the network (the pair is a task
    /// of its own with a socket of its own).
    fn at_port(&mut self, pkt: &[u8], peer: usize, port: u16) {
        self.got[peer] += pkt.len() as u64;
        let _ = self.w.peers[peer].send_to(pkt, SocketAddr::new(self.relay.ip(), port));
        self.settle();
        self.collect();
        self.check();
    }

    /// A message closed with the proof of `who`'s key.
    fn signed(&self, who: &Identity, msg: Message) -> Option<Vec<u8>> {
        let key = auth_key(who, &self.relay_id, &who.id(), &self.relay_id)?;
        let mut bytes = msg.encode();
        let split = bytes.len() - PROOF_LEN;
        let proof = proof_for(&key, &bytes[..split]);
        bytes[split..].copy_from_slice(&proof);
        Some(bytes)
    }

    fn stamp(&mut self, who: usize, g: &mut Gen) -> u64 {
        // Mostly the next one; now and then an old one, or any.
        match g.u8() % 8 {
            0 => g.u64(),
            1 => self.stamps[who].saturating_sub(1 + g.below(3) as u64),
            _ => {
                self.stamps[who] += 1;
                self.stamps[who]
            }
        }
    }

    /// The token this address has, if it has one; zero otherwise. Using one
    /// it was given proves the address receives.
    fn token(&mut self, peer: usize) -> [u8; TOKEN_LEN] {
        match self.tokens[peer] {
            Some(t) => {
                self.proven[peer] = true;
                t
            }
            None => [0; TOKEN_LEN],
        }
    }

    fn step(&mut self, g: &mut Gen) {
        let peer = g.below(PEERS - 1);
        match g.below(9) {
            // A receiver registers, or keeps its registration up.
            0 | 1 => {
                let r = g.below(2);
                let who = self.w.receivers[r].clone();
                let msg = Message::Register {
                    id: who.id(),
                    token: self.token(peer),
                    flags: g.u8() & 1,
                    stamp: self.stamp(r, g),
                    hints: Hints::none(),
                    nonce: self.nonce,
                    proof: [0; PROOF_LEN],
                };
                if let Some(bytes) = self.signed(&who, msg) {
                    self.control(&bytes, peer);
                }
            }
            // The sender asks to be put through to a receiver, as a
            // stranger or as itself.
            2 | 3 => {
                let target = if g.u8() % 8 == 0 {
                    SharpId::from_public(g.array())
                } else {
                    self.w.receivers[g.below(2)].id()
                };
                let token = self.token(peer);
                let nonce = g.array();
                let bytes = if g.bool() {
                    Some(
                        Message::Connect {
                            target,
                            token,
                            hints: Hints::none(),
                            nonce,
                        }
                        .encode(),
                    )
                } else {
                    let who = self.w.sender.clone();
                    self.signed(
                        &who,
                        Message::ConnectAs {
                            target,
                            token,
                            hints: Hints::none(),
                            nonce,
                            id: who.id(),
                            proof: [0; PROOF_LEN],
                        },
                    )
                };
                if let Some(bytes) = bytes {
                    self.control(&bytes, peer);
                }
            }
            // A side binds its port: an Open, repeated with the
            // confirmation once that came.
            4 | 5 if !self.sides.is_empty() => {
                let side = self.sides[g.below(self.sides.len())];
                if side.proof.is_some() {
                    self.proven[side.peer] = true;
                }
                let msg = Message::Open {
                    ticket: side.ticket,
                    proof: side.proof.unwrap_or([0; TOKEN_LEN]),
                };
                self.at_port(&msg.encode(), side.peer, side.port);
            }
            // Something through a pair.
            6 if !self.sides.is_empty() => {
                let side = self.sides[g.below(self.sides.len())];
                let data = g.bytes(1400);
                self.at_port(&data, side.peer, side.port);
            }
            // A receiver says goodbye.
            7 => {
                let r = g.below(2);
                let who = self.w.receivers[r].clone();
                let msg = Message::Bye {
                    id: who.id(),
                    token: self.token(peer),
                    stamp: self.stamp(r, g),
                    nonce: self.nonce,
                    proof: [0; PROOF_LEN],
                };
                if let Some(bytes) = self.signed(&who, msg) {
                    self.control(&bytes, peer);
                }
            }
            _ => self.stranger(g),
        }
    }

    /// The stranger, at the last address.
    fn stranger(&mut self, g: &mut Gen) {
        let me = PEERS - 1;
        match g.below(7) {
            0 if !self.log.is_empty() => {
                let pkt = self.log[g.below(self.log.len())].clone();
                self.control(&pkt, me);
            }
            1 if !self.log.is_empty() => {
                let mut pkt = self.log[g.below(self.log.len())].clone();
                for _ in 0..1 + g.below(4) {
                    let i = g.below(pkt.len().max(1));
                    if let Some(b) = pkt.get_mut(i) {
                        *b ^= 1 << g.below(8);
                    }
                }
                self.control(&pkt, me);
            }
            2 => {
                let msg = super::roundtrip::relay_message(g);
                self.control(&msg.encode(), me);
            }
            3 if !self.sides.is_empty() => {
                let side = self.sides[g.below(self.sides.len())];
                let pkt = if g.bool() {
                    Message::Open {
                        ticket: if g.bool() { side.ticket } else { g.array() },
                        proof: g.array(),
                    }
                    .encode()
                } else {
                    g.bytes(1400)
                };
                self.at_port(&pkt, me, side.port);
            }
            4 => {
                let ms = u64::from(g.u16()) * if g.u8() % 8 == 0 { 64 } else { 1 };
                self.now += Duration::from_millis(ms);
            }
            _ => {
                let pkt = g.bytes(256);
                self.control(&pkt, me);
            }
        }
    }

    fn finish(self) {
        self.w.rt.block_on(self.h.finish());
    }
}

/// A relay, its clients and a stranger.
pub fn relay(data: &[u8]) {
    WORLD.with(|w| {
        let w = w.get_or_init(World::new);
        let mut g = Gen::new(data);
        let Some(mut run) = Run::new(w, &mut g) else {
            return;
        };
        for _ in 0..STEPS {
            if g.is_empty() {
                break;
            }
            run.step(&mut g);
        }
        run.finish();
    });
}
