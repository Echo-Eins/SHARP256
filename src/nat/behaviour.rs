//! What kind of NAT are we behind? (RFC 5780)
//!
//! "NAT type" in the old RFC 3489 sense — full cone, restricted, symmetric —
//! was never a property of a box but of two separate choices it makes, and
//! RFC 3489's classification was retired because real NATs mix them freely.
//! RFC 5780 measures the two separately:
//!
//! * **Mapping behaviour** — when we send to a new destination, do we keep
//!   the same external port? This decides whether a peer can be *told* where
//!   to reach us. If the port changes per destination, whatever we learned
//!   from a STUN server is worthless for talking to anyone else.
//! * **Filtering behaviour** — which inbound packets does the NAT let
//!   through to a mapping we have already created? This decides whether the
//!   peer has to send first, and whether a hole punched by one side is
//!   enough.
//!
//! Together they say whether a direct path can be established at all, or
//! whether the transfer needs a relay. Guessing wrong is expensive in both
//! directions: assuming success wastes a long timeout, assuming failure
//! wastes a relay. So every test here reports `Unknown` rather than a guess
//! when the evidence is not there.
//!
//! **The measurements are hints, never authority.** A STUN server is an
//! unauthenticated stranger and may lie about all of it. Nothing here grants
//! anyone access or decides who we talk to: it only picks which addresses to
//! *try*. Authentication settles the rest, and a lie costs a wasted attempt.

use super::stun::{
    binding_request, is_usable_server_address, message_transaction_id, resolve_server,
    transaction_id, BindingResponse, Incoming, StunClient,
};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// How the NAT picks the external port for a new destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mapping {
    /// One external address and port for everything: a peer can be told
    /// where we are.
    EndpointIndependent,
    /// A fresh mapping per destination host.
    AddressDependent,
    /// A fresh mapping per destination host *and* port — the "symmetric"
    /// case. What one server sees says nothing about what a peer would see.
    AddressAndPortDependent,
    Unknown,
}

/// Which inbound packets reach a mapping we have already opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filtering {
    /// Anything may come in once the mapping exists.
    EndpointIndependent,
    /// Only from hosts we have sent something to.
    AddressDependent,
    /// Only from the exact address and port we have sent to.
    AddressAndPortDependent,
    Unknown,
}

/// What it takes for a peer to reach us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachable {
    /// No NAT in the way.
    Directly,
    /// The mapping is stable and open: telling a peer the address is enough.
    OncePublished,
    /// The mapping is stable but filtered: both sides must send at the same
    /// time (hole punching), which needs a rendezvous to coordinate.
    ByPunching,
    /// The external port differs per destination, so no address we can
    /// publish is the one a peer would need. Only a relay is left.
    OnlyByRelay,
    Unknown,
}

/// The measured behaviour of the NAT in front of one socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Behaviour {
    pub mapping: Mapping,
    pub filtering: Filtering,
    /// Our address as the first server saw it.
    pub mapped: Option<SocketAddr>,
    /// The NAT kept our own port number in the mapping. Where it does, a
    /// peer's port can sometimes be guessed even under a symmetric NAT.
    pub port_preserved: Option<bool>,
    /// A packet sent to our own public address comes back to us, so two
    /// peers behind this same NAT can reach each other through it.
    pub hairpinning: Option<bool>,
    /// The mapped address is one of this host's own: no NAT.
    pub open_internet: bool,
    /// The server the behaviour tests ran against, if any could.
    pub tested_with: Option<SocketAddr>,
    /// The full RFC 5780 tests ran; otherwise the weaker cross-check
    /// between two independent servers was used.
    pub rfc5780: bool,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            mapping: Mapping::Unknown,
            filtering: Filtering::Unknown,
            mapped: None,
            port_preserved: None,
            hairpinning: None,
            open_internet: false,
            tested_with: None,
            rfc5780: false,
        }
    }
}

impl Behaviour {
    /// What a peer has to do to reach us.
    pub fn reachable(&self) -> Reachable {
        if self.open_internet {
            return Reachable::Directly;
        }
        match (self.mapping, self.filtering) {
            (Mapping::AddressDependent | Mapping::AddressAndPortDependent, _) => {
                Reachable::OnlyByRelay
            }
            (Mapping::EndpointIndependent, Filtering::EndpointIndependent) => {
                Reachable::OncePublished
            }
            (
                Mapping::EndpointIndependent,
                Filtering::AddressDependent | Filtering::AddressAndPortDependent,
            ) => Reachable::ByPunching,
            // A stable mapping with unmeasured filtering is still worth
            // punching for; unmeasured mapping says nothing at all.
            (Mapping::EndpointIndependent, Filtering::Unknown) => Reachable::ByPunching,
            (Mapping::Unknown, _) => Reachable::Unknown,
        }
    }

    /// One line for a human.
    pub fn describe(&self) -> String {
        if self.open_internet {
            return "no NAT: this host is on the open internet".to_string();
        }
        if self.mapping == Mapping::Unknown && self.filtering == Filtering::Unknown {
            return "NAT behaviour unknown (no STUN server could measure it)".to_string();
        }
        let mapping = match self.mapping {
            Mapping::EndpointIndependent => "one port for every destination",
            Mapping::AddressDependent => "a port per destination host",
            Mapping::AddressAndPortDependent => "a port per destination host and port (symmetric)",
            Mapping::Unknown => "unknown mapping",
        };
        let filtering = match self.filtering {
            Filtering::EndpointIndependent => "lets anyone in",
            Filtering::AddressDependent => "lets in hosts we sent to",
            Filtering::AddressAndPortDependent => "lets in only what we sent to exactly",
            Filtering::Unknown => "unknown filtering",
        };
        let outlook = match self.reachable() {
            Reachable::Directly => "reachable directly",
            Reachable::OncePublished => "reachable once the address is published",
            Reachable::ByPunching => "reachable by punching (both sides send at once)",
            Reachable::OnlyByRelay => "needs a relay",
            Reachable::Unknown => "reachability unknown",
        };
        format!(
            "NAT: {}, {}{}; {}",
            mapping,
            filtering,
            match self.hairpinning {
                Some(true) => ", hairpinning works",
                Some(false) => ", no hairpinning",
                None => "",
            },
            outlook
        )
    }
}

/// How long one test waits and how often it repeats. Discovery runs in the
/// background, but it should still finish in a few seconds. A filtering test
/// answers by *silence*, so this is also how long "nothing came back" takes
/// to establish.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub per_try: Duration,
    pub tries: u32,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            per_try: Duration::from_millis(500),
            tries: 2,
        }
    }
}

/// Whether a mapped address means there is no NAT at all.
///
/// It has to be one of this host's own addresses *and* a globally routable
/// one. The first half alone trusts a stranger too far: a hostile or
/// on-path STUN server that guessed a common private address — and
/// 192.168.1.x is not much of a guess — would be believed, and believing it
/// skips asking the router for a port forward and publishes a local address
/// as the public one.
fn means_no_nat(ip: IpAddr) -> bool {
    let routable = match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 127
                // 100.64.0.0/10, where carrier-grade NAT lives.
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fe80::/10 link-local and fc00::/7 unique-local.
                || v6.segments()[0] & 0xffc0 == 0xfe80
                || v6.segments()[0] & 0xfe00 == 0xfc00)
        }
    };
    routable
        && if_addrs::get_if_addrs()
            .map(|ifs| ifs.iter().any(|i| i.ip() == ip))
            .unwrap_or(false)
}

/// Runs the RFC 5780 tests on `socket`, falling back to a cross-check
/// between two independent servers when no server offers the second address
/// the full tests need.
pub async fn discover(
    socket: &UdpSocket,
    servers: &[String],
    responses: &mut mpsc::Receiver<Incoming>,
) -> Behaviour {
    discover_with(socket, servers, responses, Timing::default()).await
}

/// [`discover`] with explicit timing (the tests use a brisk one).
pub async fn discover_with(
    socket: &UdpSocket,
    servers: &[String],
    responses: &mut mpsc::Receiver<Incoming>,
    timing: Timing,
) -> Behaviour {
    let mut out = Behaviour::default();
    let Ok(local) = socket.local_addr() else {
        return out;
    };
    let client = StunClient::new(servers.to_vec()).with_timing(timing.per_try, timing.tries);
    let reach = crate::address::Reach::of(socket);
    // A dual-stack socket is tested over IPv4, which is where the NATs are;
    // its IPv6 addresses are published as they are, being the host's own.
    let family = (reach.v4() && reach.v6()).then_some(false);

    // Test I against each server in turn. One server that offers a usable
    // second address is all the real tests need; otherwise a second server's
    // independent view of our mapping serves the weaker fallback.
    let mut primary: Option<(SocketAddr, BindingResponse)> = None;
    let mut second_opinion: Option<SocketAddr> = None;
    for name in servers {
        let Some(addr) = resolve_server(name, reach, family).await else {
            continue;
        };
        let Ok(Some(reply)) = client
            .transaction(socket, addr, responses, false, false)
            .await
        else {
            continue;
        };
        tracing::debug!("STUN: {} sees us at {}", addr, reply.response.mapped);
        if primary.is_none() {
            let has_other = reply
                .response
                .other_address
                .is_some_and(|o| is_usable_server_address(o, addr));
            primary = Some((addr, reply.response));
            if has_other {
                break;
            }
        } else {
            second_opinion = Some(reply.response.mapped);
            break;
        }
    }

    let Some((server, first)) = primary else {
        return out;
    };
    out.mapped = Some(first.mapped);
    out.tested_with = Some(server);
    out.port_preserved = Some(first.mapped.port() == local.port());
    if means_no_nat(first.mapped.ip().to_canonical()) {
        out.open_internet = true;
        out.mapping = Mapping::EndpointIndependent;
    }

    // The server's other address is what the mapping and filtering tests
    // need. It arrives from an unauthenticated stranger and we act on it by
    // sending there, so it is screened first.
    let other = first
        .other_address
        .filter(|o| is_usable_server_address(*o, server))
        .and_then(|o| reach.native(o));
    if other.is_none() {
        tracing::debug!(
            "STUN: {} offers no usable second address; \
             falling back to comparing two servers",
            server
        );
    }

    if let Some(other) = other {
        out.rfc5780 = true;
        if !out.open_internet {
            out.mapping =
                mapping_behaviour(socket, &client, responses, server, other, first.mapped).await;
        }
        out.filtering = filtering_behaviour(socket, &client, responses, server).await;
    } else if !out.open_internet {
        // Weaker, but the same question: does a different destination get a
        // different external port? Two independent servers stand in for one
        // server's two addresses. It cannot tell address-dependent from
        // address-and-port-dependent, so it never claims to.
        out.mapping = match second_opinion {
            Some(m) if m == first.mapped => Mapping::EndpointIndependent,
            Some(_) => Mapping::AddressAndPortDependent,
            None => Mapping::Unknown,
        };
    }

    if !out.open_internet && out.mapping == Mapping::EndpointIndependent {
        out.hairpinning = hairpinning(socket, responses, first.mapped, timing).await;
    }
    out
}

/// RFC 5780 section 4.3: does the external port follow the destination?
async fn mapping_behaviour(
    socket: &UdpSocket,
    client: &StunClient,
    responses: &mut mpsc::Receiver<Incoming>,
    server: SocketAddr,
    other: SocketAddr,
    first_mapped: SocketAddr,
) -> Mapping {
    // Test II: the server's other IP address, its primary port.
    let second = SocketAddr::new(other.ip(), server.port());
    let Ok(Some(r2)) = client
        .transaction(socket, second, responses, false, false)
        .await
    else {
        return Mapping::Unknown;
    };
    if r2.response.mapped == first_mapped {
        return Mapping::EndpointIndependent;
    }
    // Test III: the server's other IP address and other port.
    let Ok(Some(r3)) = client
        .transaction(socket, other, responses, false, false)
        .await
    else {
        // The mapping is not endpoint-independent, but we cannot tell how
        // far it varies. Report the weaker of the two claims.
        return Mapping::AddressDependent;
    };
    if r3.response.mapped == r2.response.mapped {
        Mapping::AddressDependent
    } else {
        Mapping::AddressAndPortDependent
    }
}

/// RFC 5780 section 4.4: which inbound packets get through?
///
/// The subtlety that makes naive implementations wrong: a server that does
/// not implement CHANGE-REQUEST answers anyway, from its primary address. A
/// reply alone therefore proves nothing — the reply has to have come from
/// the address we asked it to come from. Where it did not, the result is
/// `Unknown`, never "wide open".
async fn filtering_behaviour(
    socket: &UdpSocket,
    client: &StunClient,
    responses: &mut mpsc::Receiver<Incoming>,
    server: SocketAddr,
) -> Filtering {
    // Test II: ask for a reply from the other address *and* other port.
    match client
        .transaction(socket, server, responses, true, true)
        .await
    {
        Ok(Some(r)) if r.from.ip() != server.ip() && r.from.port() != server.port() => {
            return Filtering::EndpointIndependent;
        }
        Ok(Some(r)) => {
            tracing::debug!(
                "STUN: {} ignored CHANGE-REQUEST (answered from {}); \
                 filtering behaviour not measured",
                server,
                r.from
            );
            return Filtering::Unknown;
        }
        Ok(None) => {}
        Err(_) => return Filtering::Unknown,
    }
    // Test III: same IP address, other port.
    match client
        .transaction(socket, server, responses, false, true)
        .await
    {
        Ok(Some(r)) if r.from.ip() == server.ip() && r.from.port() != server.port() => {
            Filtering::AddressDependent
        }
        Ok(Some(r)) => {
            tracing::debug!(
                "STUN: {} ignored CHANGE-REQUEST (answered from {})",
                server,
                r.from
            );
            Filtering::Unknown
        }
        // Nothing came back from either, and the server does answer plain
        // requests: only what we sent to exactly gets in.
        Ok(None) => Filtering::AddressAndPortDependent,
        Err(_) => Filtering::Unknown,
    }
}

/// RFC 5780 section 4.5: does a packet sent to our own public address come
/// back to us? Two peers behind the same NAT depend on it.
///
/// Nothing answers this one: what we wait for is *our own request*, looped
/// back by the NAT. So it cannot reuse the ordinary transaction, which
/// expects a response and would discard the request as unparseable.
async fn hairpinning(
    socket: &UdpSocket,
    responses: &mut mpsc::Receiver<Incoming>,
    mapped: SocketAddr,
    timing: Timing,
) -> Option<bool> {
    let local = socket.local_addr().ok()?;
    if !is_usable_server_address(mapped, local) {
        return None;
    }
    let mapped = crate::address::Reach::of(socket).native(mapped)?;
    let tid = transaction_id();
    let request = binding_request(&tid);
    for _ in 0..timing.tries.max(1) {
        if socket.send_to(&request, mapped).await.is_err() {
            return None;
        }
        let deadline = Instant::now() + timing.per_try;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, responses.recv()).await {
                Ok(Some((pkt, _))) if message_transaction_id(&pkt) == Some(tid) => {
                    return Some(true);
                }
                Ok(Some(_)) => continue,
                Ok(None) => return None,
                Err(_) => break,
            }
        }
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::stun::{binding_success, is_stun_message, requested_change};
    use std::sync::Arc;

    // ----- a NAT to measure ------------------------------------------------
    //
    // The tests below run the real discovery against a STUN server with two
    // addresses and two ports, as RFC 5780 needs, sitting behind a simulated
    // NAT whose behaviour we choose. Nothing here is a mock of the code
    // under test: `discover` sends real datagrams and draws its conclusions
    // from what comes back, so the whole decision tree is exercised.

    /// Loopback answers at once, so the tests need not wait like the real
    /// thing does. The silences a filtering test relies on still happen.
    fn brisk() -> Timing {
        Timing {
            per_try: Duration::from_millis(120),
            tries: 2,
        }
    }

    /// The NAT we are pretending to sit behind.
    #[derive(Clone, Copy)]
    struct Sim {
        mapping: Mapping,
        filtering: Filtering,
    }

    /// Index of a server address (0 for the primary IP, 1 for the other).
    fn ip_index(a: SocketAddr, primary_ip: IpAddr) -> u16 {
        u16::from(a.ip() != primary_ip)
    }

    impl Sim {
        /// The public address the simulated NAT would use towards `dst`.
        /// The port varies exactly as much as the mapping behaviour says.
        fn mapped(&self, dst: SocketAddr, primary: SocketAddr) -> SocketAddr {
            let ip = ip_index(dst, primary.ip());
            let port = u16::from(dst.port() != primary.port());
            let offset = match self.mapping {
                Mapping::EndpointIndependent => 0,
                Mapping::AddressDependent => ip,
                Mapping::AddressAndPortDependent => ip * 2 + port,
                Mapping::Unknown => 0,
            };
            // A public address that is not one of ours, so the discovery
            // does not decide there is no NAT.
            SocketAddr::new("203.0.113.9".parse().unwrap(), 50_000 + offset)
        }

        /// Would the NAT let a packet from `src` in, given that we had sent
        /// to `dst`?
        fn lets_in(&self, dst: SocketAddr, src: SocketAddr) -> bool {
            match self.filtering {
                Filtering::EndpointIndependent | Filtering::Unknown => true,
                Filtering::AddressDependent => src.ip() == dst.ip(),
                Filtering::AddressAndPortDependent => src == dst,
            }
        }
    }

    /// A STUN server on four sockets: two addresses times two ports.
    struct FakeStun {
        primary: SocketAddr,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    impl Drop for FakeStun {
        fn drop(&mut self) {
            for t in &self.tasks {
                t.abort();
            }
        }
    }

    async fn start_fake_stun(sim: Sim) -> Option<FakeStun> {
        // 127.0.0.2 is loopback too on Linux; without it there is no second
        // address and the RFC 5780 tests cannot run at all.
        let a1 = UdpSocket::bind("127.0.0.1:0").await.ok()?;
        let b1 = UdpSocket::bind("127.0.0.2:0").await.ok()?;
        let a2 = UdpSocket::bind("127.0.0.1:0").await.ok()?;
        let b2 = UdpSocket::bind("127.0.0.2:0").await.ok()?;
        // The four sockets must be (A:P, B:P, A:Q, B:Q), so the two ports
        // have to line up. Rebind until they do.
        let (pa, pb) = (a1.local_addr().ok()?.port(), a2.local_addr().ok()?.port());
        drop((b1, b2));
        let b1 = UdpSocket::bind(format!("127.0.0.2:{}", pa)).await.ok()?;
        let b2 = UdpSocket::bind(format!("127.0.0.2:{}", pb)).await.ok()?;

        let primary: SocketAddr = format!("127.0.0.1:{}", pa).parse().ok()?;
        let other: SocketAddr = format!("127.0.0.2:{}", pb).parse().ok()?;
        let socks: Vec<Arc<UdpSocket>> = vec![a1, b1, a2, b2].into_iter().map(Arc::new).collect();

        let mut tasks = Vec::new();
        for listener in &socks {
            let listener = listener.clone();
            let all = socks.clone();
            tasks.push(tokio::spawn(async move {
                let dst = listener.local_addr().expect("bound");
                let mut buf = vec![0u8; 2048];
                loop {
                    let Ok((n, from)) = listener.recv_from(&mut buf).await else {
                        return;
                    };
                    let pkt = &buf[..n];
                    let Some(tid) = crate::nat::stun::message_transaction_id(pkt) else {
                        continue;
                    };
                    if !is_stun_message(pkt) {
                        continue;
                    }
                    let (change_ip, change_port) = requested_change(pkt);
                    // Answer from the address we were asked to answer from.
                    let src_ip = if change_ip { other.ip() } else { dst.ip() };
                    let src_port = if change_port {
                        if dst.port() == primary.port() {
                            other.port()
                        } else {
                            primary.port()
                        }
                    } else {
                        dst.port()
                    };
                    let src = SocketAddr::new(src_ip, src_port);
                    // ... but only if the simulated NAT would let that
                    // packet back in to the client.
                    if !sim.lets_in(dst, src) {
                        continue;
                    }
                    let Some(out) = all
                        .iter()
                        .find(|s| s.local_addr().map(|a| a == src).unwrap_or(false))
                    else {
                        continue;
                    };
                    let reply =
                        binding_success(&tid, sim.mapped(dst, primary), Some(src), Some(other));
                    let _ = out.send_to(&reply, from).await;
                }
            }));
        }
        Some(FakeStun { primary, tasks })
    }

    /// Runs the real discovery against the fake server, wiring the client
    /// socket to the response channel the way the receiver's dispatcher
    /// does.
    async fn measure(sim: Sim) -> Option<Behaviour> {
        let server = start_fake_stun(sim).await?;
        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.ok()?);
        let (tx, mut rx) = mpsc::channel::<Incoming>(64);
        let pump = {
            let client = client.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                while let Ok((n, from)) = client.recv_from(&mut buf).await {
                    if is_stun_message(&buf[..n]) {
                        let _ = tx.send((buf[..n].to_vec(), from)).await;
                    }
                }
            })
        };
        let servers = vec![server.primary.to_string()];
        let out = discover_with(&client, &servers, &mut rx, brisk()).await;
        pump.abort();
        assert_eq!(out.tested_with, Some(server.primary));
        assert!(out.rfc5780, "the full tests should have been possible");
        Some(out)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn measures_every_combination_of_nat_behaviour() {
        for mapping in [
            Mapping::EndpointIndependent,
            Mapping::AddressDependent,
            Mapping::AddressAndPortDependent,
        ] {
            for filtering in [
                Filtering::EndpointIndependent,
                Filtering::AddressDependent,
                Filtering::AddressAndPortDependent,
            ] {
                let sim = Sim { mapping, filtering };
                let Some(got) = measure(sim).await else {
                    // No second loopback address here; nothing to test.
                    eprintln!("skipped: cannot bind 127.0.0.2");
                    return;
                };
                assert_eq!(
                    got.mapping, mapping,
                    "mapping misread with {:?}/{:?}",
                    mapping, filtering
                );
                assert_eq!(
                    got.filtering, filtering,
                    "filtering misread with {:?}/{:?}",
                    mapping, filtering
                );
                assert!(!got.open_internet);
                assert_eq!(
                    got.mapped.map(|m| m.ip().to_string()).as_deref(),
                    Some("203.0.113.9")
                );
            }
        }
    }

    /// A server that ignores CHANGE-REQUEST answers from its primary address
    /// anyway. Reading that as "anything gets in" is the classic mistake: it
    /// would send a peer punching at a NAT that will never let it through.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_server_that_ignores_change_request_yields_no_verdict() {
        let listener = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(s) => Arc::new(s),
            Err(_) => return,
        };
        let primary = listener.local_addr().unwrap();
        let server = {
            let listener = listener.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                while let Ok((n, from)) = listener.recv_from(&mut buf).await {
                    let Some(tid) = crate::nat::stun::message_transaction_id(&buf[..n]) else {
                        continue;
                    };
                    // Always the same address, whatever was asked for, and
                    // no second address on offer.
                    let mapped: SocketAddr = "203.0.113.9:50000".parse().unwrap();
                    let reply = binding_success(&tid, mapped, Some(primary), None);
                    let _ = listener.send_to(&reply, from).await;
                }
            })
        };

        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (tx, mut rx) = mpsc::channel::<Incoming>(64);
        let pump = {
            let client = client.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                while let Ok((n, from)) = client.recv_from(&mut buf).await {
                    if is_stun_message(&buf[..n]) {
                        let _ = tx.send((buf[..n].to_vec(), from)).await;
                    }
                }
            })
        };
        let servers = vec![primary.to_string()];
        let got = discover_with(&client, &servers, &mut rx, brisk()).await;
        pump.abort();
        server.abort();

        assert!(!got.rfc5780, "no second address, so no RFC 5780 tests");
        assert_eq!(got.filtering, Filtering::Unknown);
        // With one server and no second address there is nothing to compare
        // against, so the mapping is unknown too — and an unknown mapping
        // must not be reported as reachable.
        assert_eq!(got.mapping, Mapping::Unknown);
        assert_eq!(got.reachable(), Reachable::Unknown);
        assert_eq!(got.mapped, "203.0.113.9:50000".parse().ok());
    }

    fn b(mapping: Mapping, filtering: Filtering) -> Behaviour {
        Behaviour {
            mapping,
            filtering,
            ..Behaviour::default()
        }
    }

    #[test]
    fn what_it_takes_to_reach_us() {
        // No NAT.
        let open = Behaviour {
            open_internet: true,
            ..Behaviour::default()
        };
        assert_eq!(open.reachable(), Reachable::Directly);

        // A stable mapping that lets anyone in: publishing the address is
        // enough.
        assert_eq!(
            b(Mapping::EndpointIndependent, Filtering::EndpointIndependent).reachable(),
            Reachable::OncePublished
        );
        // A stable mapping behind a filter: both sides must send at once.
        for f in [
            Filtering::AddressDependent,
            Filtering::AddressAndPortDependent,
            Filtering::Unknown,
        ] {
            assert_eq!(
                b(Mapping::EndpointIndependent, f).reachable(),
                Reachable::ByPunching,
                "{:?}",
                f
            );
        }
        // A mapping that changes per destination: nothing we can publish is
        // the address a peer would need, however open the filter is.
        for m in [Mapping::AddressDependent, Mapping::AddressAndPortDependent] {
            for f in [
                Filtering::EndpointIndependent,
                Filtering::AddressDependent,
                Filtering::AddressAndPortDependent,
                Filtering::Unknown,
            ] {
                assert_eq!(
                    b(m, f).reachable(),
                    Reachable::OnlyByRelay,
                    "{:?} {:?}",
                    m,
                    f
                );
            }
        }
        // Nothing measured: say so instead of guessing.
        assert_eq!(
            b(Mapping::Unknown, Filtering::EndpointIndependent).reachable(),
            Reachable::Unknown
        );
    }

    #[test]
    fn descriptions_say_what_was_measured() {
        assert!(Behaviour::default().describe().contains("unknown"));
        let open = Behaviour {
            open_internet: true,
            ..Behaviour::default()
        };
        assert!(open.describe().contains("no NAT"));
        let sym = b(
            Mapping::AddressAndPortDependent,
            Filtering::AddressDependent,
        );
        let text = sym.describe();
        assert!(text.contains("symmetric"), "{}", text);
        assert!(text.contains("relay"), "{}", text);
        let mut cone = b(Mapping::EndpointIndependent, Filtering::AddressDependent);
        cone.hairpinning = Some(true);
        assert!(cone.describe().contains("hairpinning works"));
    }
}
