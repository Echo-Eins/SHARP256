//! The client against a DHT made for the purpose: a few dozen nodes on
//! loopback, each knowing only some of the others, answering the way BEP 5
//! says. The live network is not reachable from where these run; what they
//! show is that the client walks a partial network to the nodes closest to
//! an infohash, that what one client announces another finds, and that what
//! a hostile node sends cannot make it do more than a bounded amount of
//! work.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const SECRET: &[u8; 32] = b"a token secret, thirty-two bytes";

fn token_for(ip: IpAddr) -> Vec<u8> {
    let ip = canonical(SocketAddr::new(ip, 0)).ip();
    let bytes = match ip {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    };
    blake3::keyed_hash(SECRET, &bytes).as_bytes()[..8].to_vec()
}

fn compact(a: SocketAddr) -> Vec<u8> {
    match canonical(a) {
        SocketAddr::V4(v) => [&v.ip().octets()[..], &v.port().to_be_bytes()].concat(),
        SocketAddr::V6(v) => [&v.ip().octets()[..], &v.port().to_be_bytes()].concat(),
    }
}

fn xor(a: &NodeId, b: &NodeId) -> [u8; 20] {
    let mut d = [0u8; 20];
    for i in 0..20 {
        d[i] = a[i] ^ b[i];
    }
    d
}

struct Net {
    nodes: Vec<(NodeId, SocketAddr)>,
    cancel: CancellationToken,
    queries: Arc<AtomicUsize>,
}

impl Net {
    /// `n` nodes, each knowing `knows` others at random and its two
    /// neighbours by ID, so that everybody can be reached and nobody knows
    /// everybody.
    async fn start(n: usize, knows: usize) -> Net {
        Self::start_at(n, knows, |_| Ipv4Addr::LOCALHOST.into(), None)
            .await
            .expect("loopback")
    }

    /// [`Net::start`] with node `i` at the address `at(i)`, and the first
    /// node adding `plant` to every answer, as a hostile node would. `None`
    /// where the addresses cannot be had (macOS has 127.0.0.1 alone).
    async fn start_at(
        n: usize,
        knows: usize,
        at: impl Fn(usize) -> IpAddr,
        plant: Option<SocketAddr>,
    ) -> Option<Net> {
        let mut socks = Vec::new();
        for i in 0..n {
            let s = Arc::new(UdpSocket::bind(SocketAddr::new(at(i), 0)).await.ok()?);
            let mut id = [0u8; 20];
            rand::thread_rng().fill_bytes(&mut id);
            socks.push((id, s));
        }
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&i| socks[i].0);
        let addrs: Vec<(NodeId, SocketAddr)> = socks
            .iter()
            .map(|(id, s)| (*id, s.local_addr().unwrap()))
            .collect();
        let cancel = CancellationToken::new();
        let queries = Arc::new(AtomicUsize::new(0));
        for (rank, &i) in order.iter().enumerate() {
            let mut table: Vec<(NodeId, SocketAddr)> = vec![
                addrs[order[(rank + 1) % n]],
                addrs[order[(rank + n - 1) % n]],
            ];
            for _ in 0..knows {
                let j = (rand::thread_rng().next_u32() as usize) % n;
                if j != i && !table.contains(&addrs[j]) {
                    table.push(addrs[j]);
                }
            }
            tokio::spawn(node_loop(
                addrs[i].0,
                socks[i].1.clone(),
                table,
                cancel.clone(),
                queries.clone(),
                plant.filter(|_| i == 0),
            ));
        }
        Some(Net {
            nodes: addrs,
            cancel,
            queries,
        })
    }

    fn bootstrap(&self) -> Vec<String> {
        vec![self.nodes[0].1.to_string()]
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn node_loop(
    id: NodeId,
    sock: Arc<UdpSocket>,
    table: Vec<(NodeId, SocketAddr)>,
    cancel: CancellationToken,
    queries: Arc<AtomicUsize>,
    plant: Option<SocketAddr>,
) {
    let mut stored: HashMap<NodeId, Vec<SocketAddr>> = HashMap::new();
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, from) = tokio::select! {
            _ = cancel.cancelled() => return,
            r = sock.recv_from(&mut buf) => match r { Ok(r) => r, Err(_) => continue },
        };
        let Some(v) = bencode::decode(&buf[..n]) else {
            continue;
        };
        let (Some(Value::Bytes(t)), Some(Value::Bytes(q)), Some(a)) =
            (v.get("t"), v.get("q"), v.get("a"))
        else {
            continue;
        };
        queries.fetch_add(1, Ordering::SeqCst);
        let reply = |r: Value| {
            bencode::encode(&Value::dict(vec![
                ("t", Value::Bytes(t.clone())),
                ("y", Value::bytes(b"r")),
                ("r", r),
            ]))
        };
        let error = |code: i64, msg: &str| {
            bencode::encode(&Value::dict(vec![
                ("t", Value::Bytes(t.clone())),
                ("y", Value::bytes(b"e")),
                (
                    "e",
                    Value::List(vec![Value::Int(code), Value::bytes(msg.as_bytes())]),
                ),
            ]))
        };
        let Some(ih) = a
            .get("info_hash")
            .and_then(Value::as_bytes)
            .and_then(|b| <NodeId>::try_from(b).ok())
        else {
            let _ = sock.send_to(&error(203, "no info_hash"), from).await;
            continue;
        };
        let out = match q.as_slice() {
            b"get_peers" => {
                let mut closest = table.clone();
                closest.sort_by_key(|(nid, _)| xor(nid, &ih));
                let nodes: Vec<u8> = closest
                    .iter()
                    .take(8)
                    .flat_map(|(nid, addr)| [nid.to_vec(), compact(*addr)].concat())
                    .collect();
                let mut r = vec![
                    ("id", Value::bytes(&id)),
                    ("token", Value::Bytes(token_for(from.ip()))),
                    ("nodes", Value::Bytes(nodes)),
                ];
                let peers: Vec<SocketAddr> = stored
                    .get(&ih)
                    .into_iter()
                    .flatten()
                    .copied()
                    .chain(plant)
                    .collect();
                if !peers.is_empty() {
                    r.push((
                        "values",
                        Value::List(peers.iter().map(|p| Value::Bytes(compact(*p))).collect()),
                    ));
                }
                reply(Value::dict(r))
            }
            b"announce_peer" => {
                let token = a.get("token").and_then(Value::as_bytes).unwrap_or(b"");
                if token != token_for(from.ip()).as_slice() {
                    error(203, "bad token")
                } else {
                    let port = if a.get("implied_port").and_then(Value::as_int) == Some(1) {
                        from.port()
                    } else {
                        a.get("port").and_then(Value::as_int).unwrap_or(0) as u16
                    };
                    stored
                        .entry(ih)
                        .or_default()
                        .push(SocketAddr::new(from.ip(), port));
                    reply(Value::dict(vec![("id", Value::bytes(&id))]))
                }
            }
            _ => error(204, "method unknown"),
        };
        let _ = sock.send_to(&out, from).await;
    }
}

fn hash(n: u8) -> NodeId {
    [n; 20]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_one_client_announces_another_finds() {
    let net = Net::start(30, 6).await;
    let cancel = CancellationToken::new();
    let (a, b) = (
        Dht::start(net.bootstrap(), cancel.clone()).unwrap(),
        Dht::start(net.bootstrap(), cancel.clone()).unwrap(),
    );
    let ih = hash(0x42);
    let first = a.lookup(&ih, Duration::from_secs(10)).await;
    assert!(first.peers.is_empty(), "nothing was announced yet");
    assert!(first.announceable() >= 1);
    let agreed = a.announce(&first, &ih, |_| Some(5555)).await;
    assert!(agreed >= 1, "no node took the announcement");
    let found = b.lookup(&ih, Duration::from_secs(10)).await;
    assert!(
        found.peers.contains(&"127.0.0.1:5555".parse().unwrap()),
        "{:?} after {} queries",
        found.peers,
        net.queries.load(Ordering::SeqCst)
    );
    // Another infohash has nobody.
    assert!(b
        .lookup(&hash(0x43), Duration::from_secs(10))
        .await
        .peers
        .is_empty());
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_walk_ends_at_the_nodes_nearest_the_infohash() {
    let net = Net::start(40, 8).await;
    let cancel = CancellationToken::new();
    let dht = Dht::start(net.bootstrap(), cancel.clone()).unwrap();
    let ih = hash(0x99);
    let l = dht.lookup(&ih, Duration::from_secs(10)).await;
    let mut truth: Vec<SocketAddr> = {
        let mut all = net.nodes.clone();
        all.sort_by_key(|(id, _)| xor(id, &ih));
        all.into_iter().take(K).map(|(_, a)| a).collect()
    };
    truth.sort();
    let mut got: Vec<SocketAddr> = l.closest.iter().map(|(a, _)| *a).collect();
    got.sort();
    // A walk over tables that each know a fifth of the network finds most of
    // the true nearest, and always some.
    let hits = got.iter().filter(|a| truth.contains(a)).count();
    assert!(
        hits >= 5,
        "only {} of the {} nearest found: {:?} against {:?}",
        hits,
        K,
        got,
        truth
    );
    // And it did not ask everybody.
    assert!(net.queries.load(Ordering::SeqCst) < 60);
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_announcement_needs_the_token_the_node_gave() {
    let net = Net::start(3, 2).await;
    let cancel = CancellationToken::new();
    let dht = Dht::start(net.bootstrap(), cancel.clone()).unwrap();
    let ih = hash(7);
    let node = net.nodes[0].1;
    assert!(!dht.announce_peer(node, &ih, 1234, b"not the token").await);
    assert!(!dht.announce_peer(node, &ih, 1234, b"").await);
    let l = dht.lookup(&ih, Duration::from_secs(5)).await;
    assert!(l.peers.is_empty(), "a refused announcement was kept");
    // With the token a node gave it, an announcement to that node is taken.
    // Which nodes the walk reached depends on who knows whom (the tables
    // are drawn at random), so it is one that it did reach.
    let (node, token) = l.closest.first().cloned().expect("a token from some node");
    assert!(dht.announce_peer(node, &ih, 1234, &token).await);
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_that_is_not_there_does_not_hold_a_lookup_up() {
    let net = Net::start(10, 4).await;
    let cancel = CancellationToken::new();
    // The first of the bootstrap nodes is nobody's.
    let mut bootstrap = vec!["127.0.0.1:9".to_string()];
    bootstrap.extend(net.bootstrap());
    let dht = Dht::start(bootstrap, cancel.clone()).unwrap();
    let ih = hash(1);
    let started = std::time::Instant::now();
    let l = dht.lookup(&ih, Duration::from_secs(20)).await;
    assert!(l.announceable() >= 1);
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "took {:?}",
        started.elapsed()
    );
    cancel.cancel();
}

/// A node that claims the world: thousands of nodes and peers, a token as
/// long as it likes, and nodes that lead nowhere.
async fn hostile_node() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Some(v) = bencode::decode(&buf[..n]) else {
                continue;
            };
            let Some(Value::Bytes(t)) = v.get("t") else {
                continue;
            };
            let nodes: Vec<u8> = (0..1000u32)
                .flat_map(|i| {
                    let mut e = [i as u8; 20].to_vec();
                    e.extend_from_slice(&[127, 1, (i >> 8) as u8, i as u8]);
                    e.extend_from_slice(&(1000 + i as u16).to_be_bytes());
                    e
                })
                .collect();
            let values: Vec<Value> = (0..1000u32)
                .map(|i| Value::Bytes(vec![8, 8, (i >> 8) as u8, i as u8, 0x1f, 0x90]))
                .collect();
            let r = Value::dict(vec![
                ("id", Value::bytes(&[9; 20])),
                ("token", Value::Bytes(vec![1; 5000])),
                ("nodes", Value::Bytes(nodes)),
                ("values", Value::List(values)),
            ]);
            let out = bencode::encode(&Value::dict(vec![
                ("t", Value::Bytes(t.clone())),
                ("y", Value::bytes(b"r")),
                ("r", r),
            ]));
            // Larger than a datagram carries: it cannot even be sent; what
            // is sent is the largest that can.
            let _ = sock.send_to(&out[..out.len().min(1400)], from).await;
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_a_hostile_node_says_is_bounded() {
    let evil = hostile_node().await;
    let cancel = CancellationToken::new();
    let dht = Dht::start(vec![evil.to_string()], cancel.clone()).unwrap();
    // Its whole reply does not fit a datagram, so as sent it is not even a
    // valid value; the lookup treats it as no answer and ends.
    let started = std::time::Instant::now();
    let l = dht.lookup(&hash(3), Duration::from_secs(6)).await;
    assert!(l.peers.len() <= MAX_PEERS);
    assert!(
        started.elapsed() < Duration::from_secs(12),
        "took {:?}",
        started.elapsed()
    );
    cancel.cancel();
}

#[test]
fn a_reply_is_read_only_as_far_as_it_is_one() {
    let mut nodes = Vec::new();
    for i in 0..3u8 {
        nodes.extend_from_slice(&[i; 20]);
        nodes.extend_from_slice(&[10, 0, 0, i, 0x1a, 0xe1]);
    }
    // A trailing partial node is left out; a zero port is not an address.
    nodes.extend_from_slice(&[9; 25]);
    let v = Value::dict(vec![
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
                    Value::List(vec![
                        Value::bytes(&[1, 2, 3, 4, 0x1f, 0x90]),
                        Value::bytes(&[1, 2, 3, 4, 0, 0]),
                        Value::bytes(&[1, 2, 3]),
                    ]),
                ),
            ]),
        ),
    ]);
    let r = parse_reply(&v).expect("a reply");
    assert_eq!(r.id, [5; 20]);
    assert_eq!(r.token.as_deref(), Some(&b"tok"[..]));
    assert_eq!(
        r.values,
        vec!["1.2.3.4:8080".parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(r.nodes.len(), 3);
    assert_eq!(r.nodes[1].1, "10.0.0.1:6881".parse::<SocketAddr>().unwrap());
    // IPv6 peers are eighteen bytes.
    let mut six = [0u8; 18];
    six[15] = 1;
    six[16..].copy_from_slice(&443u16.to_be_bytes());
    assert_eq!(compact_peer(&six), Some("[::1]:443".parse().unwrap()));
    // An error, a query, or an ID of the wrong size are not replies.
    let mut e = v.clone();
    if let Value::Dict(d) = &mut e {
        d.insert(b"y".to_vec(), Value::bytes(b"e"));
    }
    assert!(parse_reply(&e).is_none());
    let bad_id = Value::dict(vec![
        ("y", Value::bytes(b"r")),
        ("r", Value::dict(vec![("id", Value::bytes(&[1; 19]))])),
    ]);
    assert!(parse_reply(&bad_id).is_none());
    // A token too long to be one is not kept.
    let long = Value::dict(vec![
        ("y", Value::bytes(b"r")),
        (
            "r",
            Value::dict(vec![
                ("id", Value::bytes(&[1; 20])),
                ("token", Value::Bytes(vec![0; MAX_TOKEN + 1])),
            ]),
        ),
    ]);
    assert!(parse_reply(&long).unwrap().token.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_from_anywhere_but_where_the_query_went_is_ignored() {
    // A node that receives on one socket and answers from another.
    let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let back = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = front.recv_from(&mut buf).await {
            if let Some(v) = bencode::decode(&buf[..n]) {
                if let Some(Value::Bytes(t)) = v.get("t") {
                    let r = Value::dict(vec![
                        ("id", Value::bytes(&[4; 20])),
                        ("token", Value::bytes(b"t")),
                        (
                            "values",
                            Value::List(vec![Value::bytes(&[6, 6, 6, 6, 0x1f, 0x90])]),
                        ),
                    ]);
                    let out = bencode::encode(&Value::dict(vec![
                        ("t", Value::Bytes(t.clone())),
                        ("y", Value::bytes(b"r")),
                        ("r", r),
                    ]));
                    let _ = back.send_to(&out, from).await;
                }
            }
        }
    });
    let cancel = CancellationToken::new();
    let dht = Dht::start(vec![front_addr.to_string()], cancel.clone()).unwrap();
    assert!(
        dht.get_peers(front_addr, &hash(5)).await.is_none(),
        "an answer from another address was believed"
    );
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_ends_meet_through_the_dht() {
    use crate::nat::card::FamilyHints;
    let net = Net::start(30, 6).await;
    let cancel = CancellationToken::new();
    let key = rendezvous_key(&crate::crypto::Identity::generate().id(), None);
    let aims = |port: u16| {
        let mut h = FamilyHints::unknown();
        h.aim4 = Some(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port));
        tokio::sync::watch::channel(h)
    };
    let (recv_aims, send_aims) = (aims(5555), aims(6666));
    let (recv_tx, mut recv_seen) = tokio::sync::mpsc::unbounded_channel();
    let (send_tx, mut send_seen) = tokio::sync::mpsc::unbounded_channel();
    let receiver = spawn_rendezvous(
        Dht::start(net.bootstrap(), cancel.clone()).unwrap(),
        key.clone(),
        Role::Receiver,
        recv_aims.1.clone(),
        cancel.clone(),
        move |p, _| {
            let _ = recv_tx.send(p);
        },
    );
    let sender = spawn_rendezvous(
        Dht::start(net.bootstrap(), cancel.clone()).unwrap(),
        key,
        Role::Sender,
        send_aims.1.clone(),
        cancel.clone(),
        move |p, _| {
            let _ = send_tx.send(p);
        },
    );
    async fn heard(rx: &mut tokio::sync::mpsc::UnboundedReceiver<SocketAddr>) -> SocketAddr {
        tokio::time::timeout(Duration::from_secs(40), rx.recv())
            .await
            .expect("nobody found")
            .expect("open")
    }
    // Each finds the other's announced port, not its own.
    assert_eq!(
        heard(&mut recv_seen).await,
        "127.0.0.1:6666".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        heard(&mut send_seen).await,
        "127.0.0.1:5555".parse::<SocketAddr>().unwrap()
    );
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = receiver.await;
        let _ = sender.await;
    })
    .await;
}

/// An address one node names is not taken on its word: the other end,
/// announced to the nodes nearest the infohash, is named by several and
/// vouched for; an address a single node adds to its answers never is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_address_one_node_names_is_not_vouched_for() {
    use crate::nat::card::FamilyHints;
    let planted: SocketAddr = "192.0.2.77:7000".parse().unwrap();
    // Every node at an address of its own: 127.0.0.10 and on.
    let Some(net) = Net::start_at(
        20,
        6,
        |i| Ipv4Addr::new(127, 0, 0, 10 + i as u8).into(),
        Some(planted),
    )
    .await
    else {
        return;
    };
    let cancel = CancellationToken::new();
    let key = rendezvous_key(&crate::crypto::Identity::generate().id(), None);
    let aims = |port: u16| {
        let mut h = FamilyHints::unknown();
        h.aim4 = Some(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port));
        tokio::sync::watch::channel(h)
    };
    let (recv_aims, send_aims) = (aims(5555), aims(6666));
    let (tx, mut news) = tokio::sync::mpsc::unbounded_channel();
    let receiver = spawn_rendezvous(
        Dht::start(net.bootstrap(), cancel.clone()).unwrap(),
        key.clone(),
        Role::Receiver,
        recv_aims.1.clone(),
        cancel.clone(),
        |_, _| {},
    );
    let sender = spawn_rendezvous(
        Dht::start(net.bootstrap(), cancel.clone()).unwrap(),
        key,
        Role::Sender,
        send_aims.1.clone(),
        cancel.clone(),
        move |p, n| {
            let _ = tx.send((p, n));
        },
    );
    let receiver_at: SocketAddr = "127.0.0.1:5555".parse().unwrap();
    let mut said: Vec<(SocketAddr, PeerNews)> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    let vouched = |said: &[(SocketAddr, PeerNews)], a: SocketAddr| {
        said.iter().any(|(p, n)| {
            *p == a && matches!(n, PeerNews::Vouched | PeerNews::Found { vouched: true })
        })
    };
    while !vouched(&said, receiver_at) {
        match tokio::time::timeout_at(deadline, news.recv()).await {
            Ok(Some(n)) => said.push(n),
            _ => panic!("the receiver was never vouched for: {:?}", said),
        }
    }
    while let Ok(n) = news.try_recv() {
        said.push(n);
    }
    assert!(
        said.contains(&(planted, PeerNews::Found { vouched: false })),
        "the planted address was not even turned up, so this proved nothing: {:?}",
        said
    );
    assert!(!vouched(&said, planted), "{:?}", said);
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = receiver.await;
        let _ = sender.await;
    })
    .await;
}

#[test]
fn the_key_is_what_both_ends_know_and_the_roles_differ() {
    let id = crate::crypto::Identity::generate().id();
    let other = crate::crypto::Identity::generate().id();
    let secret = crate::crypto::SecretKey::from_bytes(&[7u8; 32]);
    // The same for both ends, whichever computes it.
    assert_eq!(
        rendezvous_key(&id, Some(&secret)),
        rendezvous_key(&id, Some(&secret))
    );
    // Another receiver, or another secret, or none: another key.
    assert_ne!(rendezvous_key(&id, None), rendezvous_key(&other, None));
    assert_ne!(
        rendezvous_key(&id, None),
        rendezvous_key(&id, Some(&secret))
    );
    assert_ne!(
        rendezvous_key(&id, Some(&secret)),
        rendezvous_key(&id, Some(&crate::crypto::SecretKey::from_bytes(&[8u8; 32])))
    );
    // The two roles announce under different infohashes, which are not the
    // key itself.
    let key = rendezvous_key(&id, Some(&secret));
    let (r, s) = (
        info_hash(key.expose(), Role::Receiver),
        info_hash(key.expose(), Role::Sender),
    );
    assert_ne!(r, s);
    assert_ne!(&r[..], &key.expose()[..20]);
}
