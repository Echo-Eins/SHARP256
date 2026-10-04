//! Meeting through the Mainline DHT (BEP 5): two peers who share a secret
//! find each other's addresses by announcing to, and asking for, an
//! infohash both derive from it — with no server of ours, and none to run.
//!
//! **What it is.** The DHT BitTorrent clients use is a public key-value
//! store that maps a 160-bit infohash to the (IP, port) pairs that
//! announced it. Here the receiver announces one infohash and the sender
//! another, each derived from the receiver's ID (and the shared secret, if
//! there is one); each asks for the other's. What comes back is an address
//! to punch at, the same as one from a contact card, and it is used the
//! same way: aimed at with nine-byte punches, and tried in the handshake,
//! which only the real peer can answer.
//!
//! **What it is not.** It says nothing of the NAT in front of an address,
//! so punches at it are aimed as at an easy one; and an address that a NAT
//! numbers per destination is the wrong one for anyone but the node that
//! saw it. It is a way of finding a peer, not of reaching it.
//!
//! **What it costs in privacy.** Every node asked learns this host's
//! address and that it is looking for, or announcing, an infohash; anyone
//! who knows the infohash can read the addresses announced under it. The
//! infohash is derived from the receiver's ID, which is not secret — so
//! without a shared secret (`--secret`) anybody who knows the ID can find
//! where the receiver is, exactly as if its address had been published. It
//! is off unless asked for, and this says so where it is asked.
//!
//! The client is read-only (BEP 43): it asks and announces but is not part
//! of anybody's routing table and answers nothing. It uses a socket of its
//! own; what is announced is the port the *transfer* socket has outside,
//! which the NAT tests found.

pub mod bencode;

#[cfg(test)]
mod tests;

use crate::address::canonical;
use bencode::Value;
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub type NodeId = [u8; 20];

/// Nodes announced to: the ones closest to the infohash (BEP 5).
pub const K: usize = 8;
/// Queries in flight at once in a lookup.
const ALPHA: usize = 3;
/// The nodes that let a client in. Well known, and run by the projects
/// whose clients use them.
pub const DEFAULT_BOOTSTRAP: [&str; 4] = [
    "router.bittorrent.com:6881",
    "router.utorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "dht.libtorrent.org:25401",
];
/// How long a query is waited for. A lookup has plenty of other nodes to
/// ask, so a node that does not answer its question once is passed by; an
/// announcement goes to few, and is sent twice.
const ASK_WAIT: Duration = Duration::from_secs(2);
const ANNOUNCE_WAIT: Duration = Duration::from_millis(1500);
/// Bounds on one lookup, whatever the nodes say.
const MAX_QUERIES: usize = 60;
const MAX_CANDIDATES: usize = 256;
const MAX_PEERS: usize = 64;
/// Nodes and peers read from one reply.
const MAX_PER_REPLY: usize = 32;
/// Longest token read.
const MAX_TOKEN: usize = 64;
/// Nodes, each at an address of its own, that must report an address before
/// it is taken for one somebody announced. A node answers a lookup with
/// whatever it likes, and one on the lookup's path — it sees the infohash
/// in the question — can name any address to have punched at; an
/// announcement is stored on up to [`K`] nodes, so the real one is named by
/// several (see `nat::punch::Puncher::run_for_found`).
pub const VOUCHERS: usize = 2;
/// Peers whose reporting nodes are remembered across lookups.
const REMEMBERED_PEERS: usize = 256;

/// What a rendezvous has learnt of an address of the other end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerNews {
    /// Turned up for the first time; `vouched` if [`VOUCHERS`] nodes named
    /// it already.
    Found { vouched: bool },
    /// Turned up before, named by one node; now enough of them name it.
    Vouched,
}

/// A node worth asking, and what became of asking it.
struct Candidate {
    addr: SocketAddr,
    id: Option<NodeId>,
    state: State,
}

enum State {
    New,
    Asked,
    /// Answered, with the token an announcement to it needs.
    Answered(Option<Vec<u8>>),
    Failed,
}

/// What a lookup found.
#[derive(Debug, Default, Clone)]
pub struct Lookup {
    /// Addresses announced under the infohash, as the nodes report them.
    pub peers: Vec<SocketAddr>,
    /// Which node said so, by its IP address: (peer, node). A peer that
    /// several nodes report was announced; one that a single node reports
    /// may be that node's invention (see [`VOUCHERS`]).
    pub sources: Vec<(SocketAddr, IpAddr)>,
    /// The nodes closest to it that answered, with their tokens: where an
    /// announcement goes.
    closest: Vec<(SocketAddr, Vec<u8>)>,
}

impl Lookup {
    /// How many nodes an announcement can be made to.
    pub fn announceable(&self) -> usize {
        self.closest.len()
    }
}

struct Pending {
    from: SocketAddr,
    reply: oneshot::Sender<Value>,
}

struct Inner {
    sock: Arc<UdpSocket>,
    id: NodeId,
    bootstrap: Vec<String>,
    pending: parking_lot::Mutex<HashMap<[u8; 4], Pending>>,
}

/// A client of the DHT.
#[derive(Clone)]
pub struct Dht {
    inner: Arc<Inner>,
}

impl Dht {
    /// Binds a socket for the client and starts reading it. `bootstrap`
    /// are `host:port`s, resolved when a lookup begins; empty means
    /// [`DEFAULT_BOOTSTRAP`].
    pub fn start(bootstrap: Vec<String>, cancel: CancellationToken) -> io::Result<Self> {
        let sock = Arc::new(crate::transport::socket::bind_udp(
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            256 * 1024,
        )?);
        let mut id = [0u8; 20];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let bootstrap = if bootstrap.is_empty() {
            DEFAULT_BOOTSTRAP.iter().map(|s| s.to_string()).collect()
        } else {
            bootstrap
        };
        let inner = Arc::new(Inner {
            sock,
            id,
            bootstrap,
            pending: parking_lot::Mutex::new(HashMap::new()),
        });
        tokio::spawn(read_replies(inner.clone(), cancel));
        Ok(Self { inner })
    }

    /// Asks for the addresses announced under `info_hash`, walking towards
    /// the nodes closest to it, for at most `within`.
    pub async fn lookup(&self, info_hash: &NodeId, within: Duration) -> Lookup {
        let deadline = Instant::now() + within;
        let mut cands: Vec<Candidate> = Vec::new();
        for name in &self.inner.bootstrap {
            let resolved =
                tokio::time::timeout_at(deadline, crate::address::resolve_all(name)).await;
            if let Ok(Ok(addrs)) = resolved {
                for a in addrs {
                    add_candidate(&mut cands, None, a);
                }
            }
        }
        let mut peers: Vec<SocketAddr> = Vec::new();
        let mut sources: Vec<(SocketAddr, IpAddr)> = Vec::new();
        let mut queries = 0usize;
        loop {
            if Instant::now() >= deadline || queries >= MAX_QUERIES {
                break;
            }
            // The closest that have not been asked. A node whose ID is not
            // known yet (a bootstrap node) is asked after those that are, but
            // asked: it is how the first ones are learned.
            let mut order: Vec<usize> = (0..cands.len())
                .filter(|&i| matches!(cands[i].state, State::New))
                .collect();
            order.sort_by_key(|&i| distance(cands[i].id.as_ref(), info_hash));
            // Done when the K closest known nodes have all been dealt with.
            let mut known: Vec<usize> = (0..cands.len())
                .filter(|&i| cands[i].id.is_some())
                .collect();
            known.sort_by_key(|&i| distance(cands[i].id.as_ref(), info_hash));
            let unsettled = known
                .iter()
                .take(K)
                .any(|&i| matches!(cands[i].state, State::New | State::Asked));
            if order.is_empty() || (!unsettled && known.len() >= K) {
                break;
            }
            let batch: Vec<usize> = order.into_iter().take(ALPHA).collect();
            let mut set = tokio::task::JoinSet::new();
            for &i in &batch {
                cands[i].state = State::Asked;
                queries += 1;
                let (this, addr, ih) = (self.clone(), cands[i].addr, *info_hash);
                set.spawn(async move { (i, this.get_peers(addr, &ih).await) });
            }
            while let Some(done) = set.join_next().await {
                let Ok((i, reply)) = done else { continue };
                match reply {
                    Some(r) => {
                        cands[i].id = Some(r.id);
                        cands[i].state = State::Answered(r.token);
                        let node = canonical(cands[i].addr).ip();
                        for p in r.values {
                            if peers.len() < MAX_PEERS && !peers.contains(&p) {
                                peers.push(p);
                            }
                            if peers.contains(&p) && !sources.contains(&(p, node)) {
                                sources.push((p, node));
                            }
                        }
                        for (id, addr) in r.nodes {
                            add_candidate(&mut cands, Some(id), addr);
                        }
                    }
                    None => cands[i].state = State::Failed,
                }
            }
        }
        let mut answered: Vec<(&Candidate, Vec<u8>)> = cands
            .iter()
            .filter_map(|c| match (&c.state, c.id) {
                (State::Answered(Some(t)), Some(_)) => Some((c, t.clone())),
                _ => None,
            })
            .collect();
        answered.sort_by_key(|(c, _)| distance(c.id.as_ref(), info_hash));
        Lookup {
            peers,
            sources,
            closest: answered
                .into_iter()
                .take(K)
                .map(|(c, t)| (c.addr, t))
                .collect(),
        }
    }

    /// Announces that `port` (of this host's address, as the nodes see it)
    /// is a peer for `info_hash`, to the nodes a lookup found closest to it.
    /// `port` says which port goes with each node: the transfer socket's
    /// outside port differs per family. Returns how many nodes agreed.
    pub async fn announce(
        &self,
        lookup: &Lookup,
        info_hash: &NodeId,
        port: impl Fn(&SocketAddr) -> Option<u16>,
    ) -> usize {
        let mut set = tokio::task::JoinSet::new();
        for (addr, token) in &lookup.closest {
            let Some(port) = port(addr) else { continue };
            let (this, addr, token, ih) = (self.clone(), *addr, token.clone(), *info_hash);
            set.spawn(async move { this.announce_peer(addr, &ih, port, &token).await });
        }
        let mut agreed = 0;
        while let Some(done) = set.join_next().await {
            if done.unwrap_or(false) {
                agreed += 1;
            }
        }
        agreed
    }

    async fn get_peers(&self, to: SocketAddr, info_hash: &NodeId) -> Option<Reply> {
        let value = self
            .query(to, "get_peers", 1, ASK_WAIT, |a| {
                a.push(("info_hash", Value::bytes(info_hash)));
                // Both families' nodes, where the node keeps both (BEP 32).
                a.push((
                    "want",
                    Value::List(vec![Value::bytes(b"n4"), Value::bytes(b"n6")]),
                ));
            })
            .await?;
        parse_reply(&value)
    }

    async fn announce_peer(
        &self,
        to: SocketAddr,
        info_hash: &NodeId,
        port: u16,
        token: &[u8],
    ) -> bool {
        self.query(to, "announce_peer", 2, ANNOUNCE_WAIT, |a| {
            a.push(("info_hash", Value::bytes(info_hash)));
            a.push(("port", Value::Int(port as i64)));
            a.push(("token", Value::bytes(token)));
            a.push(("implied_port", Value::Int(0)));
        })
        .await
        .is_some_and(|v| parse_reply(&v).is_some())
    }

    /// One query and its answer, resent once if none came, accepted only
    /// from the address it went to and under the transaction it carried.
    async fn query(
        &self,
        to: SocketAddr,
        method: &str,
        tries: usize,
        wait: Duration,
        args: impl Fn(&mut Vec<(&'static str, Value)>),
    ) -> Option<Value> {
        let target = to;
        for _ in 0..tries {
            let mut tid = [0u8; 4];
            rand::rngs::OsRng.fill_bytes(&mut tid);
            let (tx, rx) = oneshot::channel();
            {
                let mut pending = self.inner.pending.lock();
                if pending.len() >= 256 || pending.contains_key(&tid) {
                    return None;
                }
                pending.insert(
                    tid,
                    Pending {
                        from: canonical(target),
                        reply: tx,
                    },
                );
            }
            let mut a: Vec<(&'static str, Value)> = vec![("id", Value::bytes(&self.inner.id))];
            args(&mut a);
            let msg = bencode::encode(&Value::dict(vec![
                ("t", Value::bytes(&tid)),
                ("y", Value::bytes(b"q")),
                ("q", Value::bytes(method.as_bytes())),
                // Read-only (BEP 43): not to be put in anybody's table.
                ("ro", Value::Int(1)),
                ("a", Value::dict(a)),
            ]));
            let send_to = match (
                self.inner.sock.local_addr().ok()?.is_ipv6(),
                canonical(target),
            ) {
                (true, SocketAddr::V4(v4)) => {
                    SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
                }
                (_, other) => other,
            };
            if self.inner.sock.send_to(&msg, send_to).await.is_err() {
                self.inner.pending.lock().remove(&tid);
                return None;
            }
            match tokio::time::timeout(wait, rx).await {
                Ok(Ok(v)) => return Some(v),
                _ => {
                    self.inner.pending.lock().remove(&tid);
                }
            }
        }
        None
    }
}

fn add_candidate(cands: &mut Vec<Candidate>, id: Option<NodeId>, addr: SocketAddr) {
    let addr = canonical(addr);
    // Never ourselves, nowhere that cannot be a node, and no more than
    // there is room for.
    if addr.port() == 0
        || addr.ip().is_unspecified()
        || addr.ip().is_multicast()
        || cands.len() >= MAX_CANDIDATES
    {
        return;
    }
    if let Some(c) = cands.iter_mut().find(|c| c.addr == addr) {
        if c.id.is_none() {
            c.id = id;
        }
        return;
    }
    cands.push(Candidate {
        addr,
        id,
        state: State::New,
    });
}

/// How far a node is from an infohash: the XOR of the two, as Kademlia
/// measures. A node whose ID is not known is as far as anything is.
fn distance(id: Option<&NodeId>, target: &NodeId) -> [u8; 20] {
    let mut d = [0xffu8; 20];
    if let Some(id) = id {
        for (i, b) in d.iter_mut().enumerate() {
            *b = id[i] ^ target[i];
        }
    }
    d
}

async fn read_replies(inner: Arc<Inner>, cancel: CancellationToken) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = tokio::select! {
            _ = cancel.cancelled() => return,
            r = inner.sock.recv_from(&mut buf) => match r {
                Ok(r) => r,
                Err(_) => continue,
            },
        };
        let Some(v) = bencode::decode(&buf[..n]) else {
            continue;
        };
        let Some(Value::Bytes(t)) = v.get("t") else {
            continue;
        };
        let Ok(tid): Result<[u8; 4], _> = t.as_slice().try_into() else {
            continue;
        };
        let mut pending = inner.pending.lock();
        // Only from where the query went: anybody else who guessed a
        // transaction id (32 bits) would have to be at that address too.
        if pending.get(&tid).is_some_and(|p| p.from == canonical(from)) {
            if let Some(p) = pending.remove(&tid) {
                let _ = p.reply.send(v);
            }
        }
    }
}

/// What a node's answer holds, as far as it is one.
struct Reply {
    id: NodeId,
    token: Option<Vec<u8>>,
    values: Vec<SocketAddr>,
    nodes: Vec<(NodeId, SocketAddr)>,
}

fn parse_reply(v: &Value) -> Option<Reply> {
    // An error answer, or anything that is not an answer.
    if v.get("y")?.as_bytes()? != b"r" {
        return None;
    }
    let r = v.get("r")?;
    let id: NodeId = r.get("id")?.as_bytes()?.try_into().ok()?;
    let token = r
        .get("token")
        .and_then(Value::as_bytes)
        .filter(|t| !t.is_empty() && t.len() <= MAX_TOKEN)
        .map(<[u8]>::to_vec);
    let mut values = Vec::new();
    if let Some(list) = r.get("values").and_then(Value::as_list) {
        for item in list.iter().take(MAX_PER_REPLY) {
            if let Some(a) = item.as_bytes().and_then(compact_peer) {
                values.push(a);
            }
        }
    }
    let mut nodes = Vec::new();
    for (key, width) in [("nodes", 26usize), ("nodes6", 38)] {
        if let Some(raw) = r.get(key).and_then(Value::as_bytes) {
            for chunk in raw.chunks_exact(width).take(MAX_PER_REPLY) {
                let nid: NodeId = chunk[..20].try_into().ok()?;
                if let Some(a) = compact_peer(&chunk[20..]) {
                    nodes.push((nid, a));
                }
            }
        }
    }
    Some(Reply {
        id,
        token,
        values,
        nodes,
    })
}

/// For the fuzzing entry point: a node's answer read as far as it is one.
#[doc(hidden)]
pub fn fuzz_reply(v: &Value) {
    if let Some(r) = parse_reply(v) {
        assert!(r.values.len() <= MAX_PER_REPLY * 2 && r.nodes.len() <= MAX_PER_REPLY * 2);
        assert!(r.token.as_ref().is_none_or(|t| t.len() <= MAX_TOKEN));
    }
}

/// An address in its compact form: four or sixteen bytes of IP and two of
/// port (BEP 5, BEP 32).
fn compact_peer(b: &[u8]) -> Option<SocketAddr> {
    let (ip, port): (IpAddr, &[u8]) = match b.len() {
        6 => (Ipv4Addr::new(b[0], b[1], b[2], b[3]).into(), &b[4..]),
        18 => {
            let ip: [u8; 16] = b[..16].try_into().ok()?;
            (Ipv6Addr::from(ip).into(), &b[16..])
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([port[0], port[1]]);
    (port != 0 && !ip.is_unspecified()).then(|| canonical(SocketAddr::new(ip, port)))
}

// ---------------------------------------------------------------------------
// Rendezvous
// ---------------------------------------------------------------------------

/// Which end of a transfer announces the infohash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Receiver,
    Sender,
}

impl Role {
    fn other(self) -> Self {
        match self {
            Role::Receiver => Role::Sender,
            Role::Sender => Role::Receiver,
        }
    }
}

/// What both ends know, and nobody else need: derived from the receiver's
/// ID and the shared secret, if there is one. With no secret the key is a
/// function of the ID alone, and anybody who knows the ID can compute it.
pub fn rendezvous_key(
    receiver: &crate::crypto::SharpId,
    secret: Option<&crate::crypto::SecretKey>,
) -> crate::crypto::SecretKey {
    let secret: &[u8] = secret.map_or(&[], |s| &s.expose()[..]);
    crate::crypto::SecretKey::derive("sharp256 dht rendezvous v1", &[receiver.as_bytes(), secret])
}

/// The infohash a role announces under.
pub fn info_hash(key: &[u8; 32], role: Role) -> NodeId {
    let tag: &[u8] = match role {
        Role::Receiver => b"receiver",
        Role::Sender => b"sender",
    };
    crate::crypto::keyed_mac(key, &[tag])
}

/// How long between one round of asking and the next, once the first
/// rounds are behind.
#[cfg(not(test))]
const SEARCH_EVERY: Duration = Duration::from_secs(20);
#[cfg(test)]
const SEARCH_EVERY: Duration = Duration::from_millis(500);
/// Tokens and stored peers age out after some minutes; announce again
/// within them.
const ANNOUNCE_EVERY: Duration = Duration::from_secs(300);
/// One lookup's budget.
const LOOKUP_WITHIN: Duration = Duration::from_secs(12);

/// Announces this end and looks for the other, until `cancel` fires: every
/// address that turns up for the other end is handed to `on_peer`, once.
/// `aims` says where this host is outside, per family: the port announced
/// is the transfer socket's, which the NAT tests found, and it is announced
/// again when it changes.
pub fn spawn_rendezvous(
    dht: Dht,
    key: crate::crypto::SecretKey,
    role: Role,
    aims: tokio::sync::watch::Receiver<crate::nat::card::FamilyHints>,
    cancel: CancellationToken,
    on_peer: impl Fn(SocketAddr, PeerNews) + Send + Sync + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (mine, theirs) = (
            info_hash(key.expose(), role),
            info_hash(key.expose(), role.other()),
        );
        let mut seen: HashSet<SocketAddr> = HashSet::new();
        // Which nodes have reported each peer, over every lookup so far, and
        // the peers already said to be vouched for.
        let mut vouchers: HashMap<SocketAddr, HashSet<IpAddr>> = HashMap::new();
        let mut vouched: HashSet<SocketAddr> = HashSet::new();
        let mut announced: Option<(Option<u16>, Option<u16>, Instant)> = None;
        let mut aims = aims;
        let mut round = 0u32;
        loop {
            round += 1;
            // The other end first: the sooner it is found the sooner the
            // punching starts.
            let found = tokio::select! {
                l = dht.lookup(&theirs, LOOKUP_WITHIN) => l,
                _ = cancel.cancelled() => return,
            };
            for (p, node) in found.sources {
                if vouchers.len() < REMEMBERED_PEERS || vouchers.contains_key(&p) {
                    vouchers.entry(p).or_default().insert(node);
                }
            }
            for p in found.peers {
                let sure = vouchers.get(&p).is_some_and(|n| n.len() >= VOUCHERS);
                if seen.insert(p) {
                    tracing::info!(
                        "the DHT says the other end is at {}{}",
                        p,
                        if sure {
                            ""
                        } else {
                            " (one node says so, so far)"
                        }
                    );
                    if sure {
                        vouched.insert(p);
                    }
                    on_peer(p, PeerNews::Found { vouched: sure });
                } else if sure && vouched.insert(p) {
                    tracing::info!("the DHT's nodes agree that the other end is at {}", p);
                    on_peer(p, PeerNews::Vouched);
                }
            }
            let (v4, v6) = {
                let a = aims.borrow();
                (a.aim4.map(|a| a.port()), a.aim6.map(|a| a.port()))
            };
            let due = match &announced {
                Some((p4, p6, at)) => (*p4, *p6) != (v4, v6) || at.elapsed() >= ANNOUNCE_EVERY,
                None => true,
            };
            if due && (v4.is_some() || v6.is_some()) {
                let l = tokio::select! {
                    l = dht.lookup(&mine, LOOKUP_WITHIN) => l,
                    _ = cancel.cancelled() => return,
                };
                let agreed = dht
                    .announce(
                        &l,
                        &mine,
                        |node| {
                            if canonical(*node).is_ipv6() {
                                v6
                            } else {
                                v4
                            }
                        },
                    )
                    .await;
                // One that no node took is made again next round, not
                // [`ANNOUNCE_EVERY`] later: the first, before this host has
                // found its way into the DHT, reached nobody (in the field,
                // and the next went out seven minutes on).
                if agreed > 0 {
                    tracing::info!(
                        "announced on the DHT to {} node(s) (port {:?}/{:?})",
                        agreed,
                        v4,
                        v6
                    );
                    announced = Some((v4, v6, Instant::now()));
                } else {
                    tracing::debug!("no DHT node took the announcement; again next round");
                }
            }
            // Soon at first, while the other end may be about to announce,
            // then every [`SEARCH_EVERY`], for as long as this end runs.
            // Not less often once an address the nodes agree on has turned
            // up: a receiver has its next sender to find (which waited up
            // to two minutes so), and an address two nodes agree on is not
            // even sure to be anybody's — in the field, two named one for
            // an infohash nobody had announced under.
            let pause = (Duration::from_secs(2) * 2u32.pow((round - 1).min(4))).min(SEARCH_EVERY);
            tokio::select! {
                _ = tokio::time::sleep(pause) => {}
                // Where this host is outside has become known or changed.
                _ = aims.changed() => {}
                _ = cancel.cancelled() => return,
            }
        }
    })
}
