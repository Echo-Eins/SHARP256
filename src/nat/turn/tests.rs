//! The client against a TURN server made for the purpose: one that checks
//! credentials the way RFC 8489 says, relays between its control socket and
//! a relayed one, and records what it was asked. (The real thing — coturn,
//! an independent implementation — is what the laboratory runs it against.)

use super::wire::*;
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const USER: &str = "alice";
const PASSWORD: &str = "s3cret";
const REALM: &str = "sharp.test";

#[derive(Default)]
struct Seen {
    allocates: AtomicUsize,
    /// Lifetimes asked for by Refresh, in order.
    refreshes: parking_lot::Mutex<Vec<u32>>,
    permitted: parking_lot::Mutex<HashSet<IpAddr>>,
    binds: AtomicUsize,
    /// Datagrams from the client as ChannelData, and as Send indications.
    channel_data: AtomicUsize,
    send_indications: AtomicUsize,
    /// Datagrams sent to the client from a peer.
    to_client: AtomicUsize,
    bindings: AtomicUsize,
}

#[derive(Clone, Default)]
struct Options {
    /// The password the server expects (the client is given another).
    password: Option<&'static str>,
    /// Lifetime granted.
    lifetime: Option<u32>,
    /// Answer the first CreatePermission with a stale-nonce error.
    stale_once: bool,
    /// Answer every Refresh with "allocation mismatch", once.
    forget_on_refresh: bool,
    /// Turn every Allocate down with this code.
    refuse: Option<u16>,
}

struct Fake {
    control: SocketAddr,
    relayed: SocketAddr,
    seen: Arc<Seen>,
    cancel: CancellationToken,
}

impl Fake {
    async fn start(options: Options) -> Fake {
        let control = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (control_addr, relayed) = (control.local_addr().unwrap(), relay.local_addr().unwrap());
        let seen = Arc::new(Seen::default());
        let cancel = CancellationToken::new();
        tokio::spawn(fake_loop(
            control,
            relay,
            options,
            seen.clone(),
            cancel.clone(),
        ));
        Fake {
            control: control_addr,
            relayed,
            seen,
            cancel,
        }
    }

    fn server(&self, password: &str) -> Server {
        Server {
            address: self.control.to_string(),
            username: USER.to_string(),
            password: password.to_string().into(),
        }
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn fake_loop(
    control: UdpSocket,
    relay: UdpSocket,
    options: Options,
    seen: Arc<Seen>,
    cancel: CancellationToken,
) {
    let password = options.password.unwrap_or(PASSWORD);
    let mut nonce = b"nonce-0001".to_vec();
    let mut nonces = 1u32;
    let mut client: Option<SocketAddr> = None;
    let mut channels: HashMap<u16, SocketAddr> = HashMap::new();
    let mut forgot = false;
    let mut stale_done = false;
    let (mut cbuf, mut rbuf) = (vec![0u8; 2048], vec![0u8; 2048]);
    let key = |realm: &str| *Credentials::new(USER, realm, password, b"").key();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            r = control.recv_from(&mut cbuf) => {
                let Ok((n, from)) = r else { continue };
                let pkt = &cbuf[..n];
                if looks_like_channel_data(pkt) {
                    if let Some((ch, data)) = parse_channel_data(pkt) {
                        seen.channel_data.fetch_add(1, Ordering::SeqCst);
                        if let Some(peer) = channels.get(&ch) {
                            if seen.permitted.lock().contains(&peer.ip()) {
                                let _ = relay.send_to(data, peer).await;
                            }
                        }
                    }
                    continue;
                }
                let Some(m) = parse(pkt) else { continue };
                let reply = |class: Class, b: Builder| -> Vec<u8> {
                    let _ = class;
                    b.finish()
                };
                let authenticated = |m: &Message<'_>| -> bool {
                    m.text(ATTR_USERNAME).as_deref() == Some(USER)
                        && m.attr(ATTR_NONCE) == Some(&nonce[..])
                        && m.integrity_is_good(&key(REALM))
                };
                let error = |m: &Message<'_>, code: u16, reason: &str, extra: &[(u16, Vec<u8>)]| -> Vec<u8> {
                    let mut v = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
                    v.extend_from_slice(reason.as_bytes());
                    let mut b = Builder::new(m.method, Class::Error, &m.tid).attr(ATTR_ERROR_CODE, &v);
                    for (t, val) in extra {
                        b = b.attr(*t, val);
                    }
                    b.finish()
                };
                let success = |m: &Message<'_>, b: Builder| -> Vec<u8> {
                    let _ = m;
                    b.finish_with_integrity(&key(REALM))
                };
                match (m.method, m.class) {
                    (BINDING, Class::Request) => {
                        seen.bindings.fetch_add(1, Ordering::SeqCst);
                        let b = Builder::new(BINDING, Class::Success, &m.tid).xor_address(ATTR_XOR_MAPPED_ADDRESS, from);
                        let _ = control.send_to(&reply(Class::Success, b), from).await;
                    }
                    (ALLOCATE, Class::Request) => {
                        seen.allocates.fetch_add(1, Ordering::SeqCst);
                        let challenge = [(ATTR_REALM, REALM.as_bytes().to_vec()), (ATTR_NONCE, nonce.clone())];
                        let bytes = if let Some(code) = options.refuse {
                            error(&m, code, "refused", &[])
                        } else if m.attr(ATTR_MESSAGE_INTEGRITY).is_none() || !authenticated(&m) {
                            error(&m, 401, "Unauthorized", &challenge)
                        } else if client.is_some() && client != Some(from) {
                            error(&m, 437, "Allocation Mismatch", &[])
                        } else {
                            client = Some(from);
                            let b = Builder::new(ALLOCATE, Class::Success, &m.tid)
                                .xor_address(ATTR_XOR_RELAYED_ADDRESS, relay.local_addr().unwrap())
                                .xor_address(ATTR_XOR_MAPPED_ADDRESS, from)
                                .attr(ATTR_LIFETIME, &options.lifetime.unwrap_or(600).to_be_bytes());
                            success(&m, b)
                        };
                        let _ = control.send_to(&bytes, from).await;
                    }
                    (REFRESH, Class::Request) => {
                        if !authenticated(&m) {
                            let challenge = [(ATTR_REALM, REALM.as_bytes().to_vec()), (ATTR_NONCE, nonce.clone())];
                            let _ = control.send_to(&error(&m, 438, "Stale Nonce", &challenge), from).await;
                            continue;
                        }
                        let asked = m.lifetime().unwrap_or(0);
                        seen.refreshes.lock().push(asked);
                        if options.forget_on_refresh && !forgot {
                            forgot = true;
                            client = None;
                            let _ = control.send_to(&error(&m, 437, "Allocation Mismatch", &[]), from).await;
                            continue;
                        }
                        if asked == 0 {
                            client = None;
                        }
                        let b = Builder::new(REFRESH, Class::Success, &m.tid).attr(ATTR_LIFETIME, &asked.to_be_bytes());
                        let _ = control.send_to(&success(&m, b), from).await;
                    }
                    (CREATE_PERMISSION, Class::Request) => {
                        if options.stale_once && !stale_done {
                            stale_done = true;
                            nonces += 1;
                            nonce = format!("nonce-{:04}", nonces).into_bytes();
                            let challenge = [(ATTR_REALM, REALM.as_bytes().to_vec()), (ATTR_NONCE, nonce.clone())];
                            let _ = control.send_to(&error(&m, 438, "Stale Nonce", &challenge), from).await;
                            continue;
                        }
                        if !authenticated(&m) || client != Some(from) {
                            let challenge = [(ATTR_REALM, REALM.as_bytes().to_vec()), (ATTR_NONCE, nonce.clone())];
                            let _ = control.send_to(&error(&m, 401, "Unauthorized", &challenge), from).await;
                            continue;
                        }
                        for value in m.attrs_of(ATTR_XOR_PEER_ADDRESS) {
                            if let Some(a) = parse_xor_address(value, &m.tid) {
                                seen.permitted.lock().insert(a.ip());
                            }
                        }
                        let b = Builder::new(CREATE_PERMISSION, Class::Success, &m.tid);
                        let _ = control.send_to(&success(&m, b), from).await;
                    }
                    (CHANNEL_BIND, Class::Request) => {
                        if !authenticated(&m) || client != Some(from) {
                            let challenge = [(ATTR_REALM, REALM.as_bytes().to_vec()), (ATTR_NONCE, nonce.clone())];
                            let _ = control.send_to(&error(&m, 401, "Unauthorized", &challenge), from).await;
                            continue;
                        }
                        let (Some(ch), Some(peer)) = (m.attr(ATTR_CHANNEL_NUMBER), m.xor_address(ATTR_XOR_PEER_ADDRESS)) else {
                            continue;
                        };
                        let ch = u16::from_be_bytes([ch[0], ch[1]]);
                        seen.binds.fetch_add(1, Ordering::SeqCst);
                        channels.insert(ch, peer);
                        seen.permitted.lock().insert(peer.ip());
                        let b = Builder::new(CHANNEL_BIND, Class::Success, &m.tid);
                        let _ = control.send_to(&success(&m, b), from).await;
                    }
                    (SEND, Class::Indication) => {
                        seen.send_indications.fetch_add(1, Ordering::SeqCst);
                        if let (Some(peer), Some(data)) = (m.xor_address(ATTR_XOR_PEER_ADDRESS), m.attr(ATTR_DATA)) {
                            if seen.permitted.lock().contains(&peer.ip()) {
                                let _ = relay.send_to(data, peer).await;
                            }
                        }
                    }
                    _ => {}
                }
            }
            r = relay.recv_from(&mut rbuf) => {
                let Ok((n, peer)) = r else { continue };
                let Some(to) = client else { continue };
                if !seen.permitted.lock().contains(&peer.ip()) {
                    continue;
                }
                seen.to_client.fetch_add(1, Ordering::SeqCst);
                let channel = channels.iter().find(|(_, p)| **p == peer).map(|(c, _)| *c);
                let bytes = match channel {
                    Some(ch) => channel_data(ch, &rbuf[..n]),
                    None => Builder::new(DATA, Class::Indication, &transaction_id())
                        .xor_address(ATTR_XOR_PEER_ADDRESS, peer)
                        .attr(ATTR_DATA, &rbuf[..n])
                        .finish(),
                };
                let _ = control.send_to(&bytes, to).await;
            }
        }
    }
}

/// The engine, as far as these tests are concerned: a socket on loopback.
async fn engine() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

async fn within<F: std::future::Future>(what: &str, f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), f)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {}", what))
}

async fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    within(what, async {
        while !ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
}

async fn recv(sock: &UdpSocket, what: &str) -> (Vec<u8>, SocketAddr) {
    let mut buf = vec![0u8; 2048];
    let (n, from) = within(what, sock.recv_from(&mut buf)).await.expect("recv");
    (buf[..n].to_vec(), canonical(from))
}

async fn start(fake: &Fake, engine: &UdpSocket) -> (Turn, CancellationToken) {
    let cancel = CancellationToken::new();
    let turn = Turn::start(
        fake.server(PASSWORD),
        engine.local_addr().unwrap(),
        &[Family::V4],
        cancel.clone(),
    );
    let t = turn.clone();
    wait_until("an allocation", move || !t.relayed().is_empty()).await;
    (turn, cancel)
}

#[test]
fn servers_are_written_user_password_at_host() {
    let s: Server = "alice:s3cret@turn.example.org:3479".parse().unwrap();
    assert_eq!(
        (s.username.as_str(), s.password.as_str(), s.address.as_str()),
        ("alice", "s3cret", "turn.example.org:3479")
    );
    // The well-known port when none is given, and the scheme is optional.
    let s: Server = "turn:alice:s3cret@turn.example.org".parse().unwrap();
    assert_eq!(s.address, "turn.example.org:3478");
    let s: Server = "turn://alice:s3cret@203.0.113.7".parse().unwrap();
    assert_eq!(s.address, "203.0.113.7:3478");
    // A password with the characters a URL would object to; the host is
    // what follows the last `@`.
    let s: Server = "alice:p:a@ss@turn.example.org:1".parse().unwrap();
    assert_eq!(
        (s.password.as_str(), s.address.as_str()),
        ("p:a@ss", "turn.example.org:1")
    );
    // A time-limited credential's user name has a colon in it, written as
    // a URL writes it; so is a literal percent sign.
    let s: Server = "1690000000%3Aalice:pa%25ss@turn.example.org"
        .parse()
        .unwrap();
    assert_eq!(
        (s.username.as_str(), s.password.as_str()),
        ("1690000000:alice", "pa%ss")
    );
    assert!("alice:bad%zz@turn.example.org".parse::<Server>().is_err());
    assert!("alice:cut%4@turn.example.org".parse::<Server>().is_err());
    assert!(
        "alice:%ff@turn.example.org".parse::<Server>().is_err(),
        "not text"
    );
    // IPv6 in brackets, with and without a port.
    let s: Server = "alice:s3cret@[2001:db8::7]:3478".parse().unwrap();
    assert_eq!(s.address, "[2001:db8::7]:3478");
    let s: Server = "alice:s3cret@[2001:db8::7]".parse().unwrap();
    assert_eq!(s.address, "[2001:db8::7]:3478");
    assert!("alice:s3cret@2001:db8::7".parse::<Server>().is_err());
    // What is not a server, and TLS, which is not spoken.
    assert!("turn.example.org".parse::<Server>().is_err());
    assert!("alice@turn.example.org".parse::<Server>().is_err());
    assert!(":s3cret@turn.example.org".parse::<Server>().is_err());
    let e = "turns:alice:s3cret@turn.example.org:5349"
        .parse::<Server>()
        .unwrap_err();
    assert!(e.contains("UDP"), "{}", e);
    // The password is not in what is printed.
    let s: Server = "alice:s3cret@turn.example.org".parse().unwrap();
    assert!(!format!("{} {:?}", s, s).contains("s3cret"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_allocation_carries_datagrams_both_ways() {
    let fake = Fake::start(Options::default()).await;
    let engine = engine().await;
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (turn, cancel) = start(&fake, &engine).await;
    assert_eq!(turn.relayed(), vec![fake.relayed]);
    // Nothing gets in until the peer is permitted.
    peer.send_to(b"too early", fake.relayed).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), engine.recv_from(&mut [0u8; 64]))
            .await
            .is_err(),
        "a datagram from an address with no permission got through"
    );
    turn.permit(peer.local_addr().unwrap().ip());
    wait_until("the permission", || {
        fake.seen
            .permitted
            .lock()
            .contains(&"127.0.0.1".parse::<IpAddr>().unwrap())
    })
    .await;

    peer.send_to(b"hello", fake.relayed).await.unwrap();
    let (data, shim) = recv(&engine, "the peer's datagram").await;
    assert_eq!(data, b"hello");
    assert!(turn.is_shim(shim), "{} is not one of ours", shim);
    // A reply to the shim reaches the peer from the relayed address.
    engine.send_to(b"hello back", shim).await.unwrap();
    let (data, from) = recv(&peer, "the reply").await;
    assert_eq!((data.as_slice(), from), (&b"hello back"[..], fake.relayed));

    // Traffic in both directions settles on the cheap framing.
    for i in 0..20u8 {
        engine.send_to(&[i; 40], shim).await.unwrap();
        recv(&peer, "a datagram").await;
        peer.send_to(&[i; 40], fake.relayed).await.unwrap();
        let (data, _) = recv(&engine, "a datagram back").await;
        assert_eq!(data, vec![i; 40]);
    }
    assert_eq!(
        fake.seen.binds.load(Ordering::SeqCst),
        1,
        "one channel for one peer"
    );
    assert!(
        fake.seen.channel_data.load(Ordering::SeqCst) > 0,
        "no ChannelData was used"
    );
    // And a stranger is not a shim.
    assert!(!turn.is_shim(peer.local_addr().unwrap()));
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dialled_peer_is_reached_through_the_server() {
    let fake = Fake::start(Options::default()).await;
    let engine = engine().await;
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (turn, cancel) = start(&fake, &engine).await;
    let peer_addr = peer.local_addr().unwrap();
    let shim = turn.dial(peer_addr).await.expect("a shim");
    assert!(turn.is_shim(shim));
    // Dialling twice is the same peer.
    assert_eq!(turn.dial(peer_addr).await, Some(shim));
    engine.send_to(b"through", shim).await.unwrap();
    // The first datagrams may be dropped until the permission is in: the
    // engine's own retransmissions are what carry on, here repeated by hand.
    let got = within("the datagram at the peer", async {
        let mut buf = vec![0u8; 64];
        loop {
            engine.send_to(b"through", shim).await.unwrap();
            if let Ok(Ok((n, from))) =
                tokio::time::timeout(Duration::from_millis(100), peer.recv_from(&mut buf)).await
            {
                break (buf[..n].to_vec(), from);
            }
        }
    })
    .await;
    assert_eq!(
        got,
        (b"through".to_vec(), fake.relayed),
        "from the relayed address"
    );
    // The peer answers to the relayed address, and the engine hears the shim.
    peer.send_to(b"answer", fake.relayed).await.unwrap();
    let (data, from) = recv(&engine, "the answer").await;
    assert_eq!((data.as_slice(), from), (&b"answer"[..], shim));
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_password_is_refused_once_and_not_hammered() {
    let fake = Fake::start(Options::default()).await;
    let engine = engine().await;
    let cancel = CancellationToken::new();
    let turn = Turn::start(
        fake.server("guess"),
        engine.local_addr().unwrap(),
        &[Family::V4],
        cancel.clone(),
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(turn.relayed().is_empty());
    // One try without credentials to be told the realm, one with them; then
    // nothing, since asking again could not change the answer.
    assert_eq!(fake.seen.allocates.load(Ordering::SeqCst), 2);
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_says_no_is_believed() {
    for code in [403u16, 442] {
        let fake = Fake::start(Options {
            refuse: Some(code),
            ..Default::default()
        })
        .await;
        let engine = engine().await;
        let cancel = CancellationToken::new();
        let turn = Turn::start(
            fake.server(PASSWORD),
            engine.local_addr().unwrap(),
            &[Family::V4],
            cancel.clone(),
        );
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(turn.relayed().is_empty());
        assert_eq!(
            fake.seen.allocates.load(Ordering::SeqCst),
            1,
            "{} asked again",
            code
        );
        cancel.cancel();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_nonce_is_taken_and_the_request_repeated() {
    let fake = Fake::start(Options {
        stale_once: true,
        ..Default::default()
    })
    .await;
    let engine = engine().await;
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (turn, cancel) = start(&fake, &engine).await;
    turn.permit(peer.local_addr().unwrap().ip());
    wait_until("the permission, after the nonce went stale", || {
        fake.seen
            .permitted
            .lock()
            .contains(&"127.0.0.1".parse::<IpAddr>().unwrap())
    })
    .await;
    peer.send_to(b"hello", fake.relayed).await.unwrap();
    assert_eq!(recv(&engine, "the datagram").await.0, b"hello");
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_allocation_is_kept_alive_and_given_back() {
    // Two seconds is as short as a lifetime is believed under test.
    let fake = Fake::start(Options {
        lifetime: Some(2),
        ..Default::default()
    })
    .await;
    let engine = engine().await;
    let (turn, cancel) = start(&fake, &engine).await;
    let seen = fake.seen.clone();
    wait_until("a refresh", move || seen.refreshes.lock().contains(&2)).await;
    assert!(!turn.relayed().is_empty());
    cancel.cancel();
    let seen = fake.seen.clone();
    wait_until("the allocation being given back", move || {
        seen.refreshes.lock().last() == Some(&0)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forgotten_allocation_is_made_again() {
    let fake = Fake::start(Options {
        lifetime: Some(2),
        forget_on_refresh: true,
        ..Default::default()
    })
    .await;
    let engine = engine().await;
    let (turn, cancel) = start(&fake, &engine).await;
    let mut changes = turn.subscribe();
    // It goes (the refresh is answered with "no such allocation") and comes
    // back, at the same address, after the pause before asking again.
    within("the allocation to be lost", async {
        while !turn.relayed().is_empty() {
            let _ = changes.changed().await;
        }
    })
    .await;
    within("the allocation to come back", async {
        while turn.relayed().is_empty() {
            let _ = changes.changed().await;
        }
    })
    .await;
    assert!(
        fake.seen.allocates.load(Ordering::SeqCst) >= 4,
        "two rounds of two"
    );
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_datagram_too_large_for_the_way_through_is_dropped() {
    let fake = Fake::start(Options::default()).await;
    let engine = engine().await;
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (turn, cancel) = start(&fake, &engine).await;
    let shim = turn.dial(peer.local_addr().unwrap()).await.unwrap();
    let seen = fake.seen.clone();
    wait_until("the permission", move || !seen.permitted.lock().is_empty()).await;
    engine
        .send_to(&vec![7u8; MAX_DATAGRAM + 1], shim)
        .await
        .unwrap();
    engine
        .send_to(&vec![8u8; MAX_DATAGRAM], shim)
        .await
        .unwrap();
    let (data, _) = recv(&peer, "the datagram that fits").await;
    assert_eq!(data.len(), MAX_DATAGRAM);
    assert_eq!(data[0], 8, "the oversized one arrived");
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_so_many_peers_are_carried() {
    let fake = Fake::start(Options::default()).await;
    let engine = engine().await;
    let (turn, cancel) = start(&fake, &engine).await;
    let mut shims = HashSet::new();
    for i in 0..MAX_ROUTES {
        let peer: SocketAddr = format!("127.0.0.1:{}", 40000 + i).parse().unwrap();
        assert!(
            shims.insert(turn.dial(peer).await.expect("room for it")),
            "one address per peer"
        );
    }
    assert_eq!(turn.dial("127.0.0.1:41000".parse().unwrap()).await, None);
    // A peer of the other family has no allocation to go through.
    assert_eq!(turn.dial("[2001:db8::1]:5".parse().unwrap()).await, None);
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_is_not_there_costs_nothing_but_patience() {
    // Nothing listens here: the allocation is tried in the background and
    // the caller is never held up.
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = dead.local_addr().unwrap().to_string();
    let engine = engine().await;
    let cancel = CancellationToken::new();
    let started = std::time::Instant::now();
    let turn = Turn::start(
        Server {
            address,
            username: USER.into(),
            password: PASSWORD.to_string().into(),
        },
        engine.local_addr().unwrap(),
        &[Family::V4],
        cancel.clone(),
    );
    assert!(started.elapsed() < Duration::from_millis(200));
    assert!(turn.relayed().is_empty());
    assert_eq!(turn.dial("127.0.0.1:9".parse().unwrap()).await, None);
    cancel.cancel();
}
