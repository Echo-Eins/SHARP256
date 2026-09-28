//! A STUN server with the behaviour-discovery features of RFC 5780.
//!
//! Anyone running `sharp-relay` can offer it. It does two jobs: it tells
//! whoever asks which address and port the request came from (RFC 8489),
//! and — given two addresses and two ports — it lets the asker measure what
//! its NAT does: whether the external port follows the destination, which
//! inbound packets get in, how long an idle mapping lasts (RFC 5780
//! sections 4.3 to 4.6). Public STUN servers rarely have the second address
//! those tests need, so a relay with one is what makes the whole report
//! possible without leaving your own infrastructure.
//!
//! Four sockets serve one family: (primary address, primary port), (primary
//! address, alternate port), (alternate address, primary port) and
//! (alternate address, alternate port). A request is answered from the
//! socket its CHANGE-REQUEST asks for, and the answer names the other
//! address as OTHER-ADDRESS. With a single address the alternate port still
//! supports the port-only tests; without a second address the tests that
//! need one are reported as "unknown" by the client, never guessed.
//!
//! What it will not do: answer anything but a Binding request; answer from
//! an address it does not own; send the answer anywhere but to the source
//! IP of the request (RESPONSE-PORT only changes the port, so a forged
//! source cannot aim it at a third party any more than the request could);
//! answer one client faster than a token bucket allows.

use super::stun;
use crate::relay::server::RateLimiter;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// Where one family's sockets go.
#[derive(Debug, Clone)]
pub struct FamilyConfig {
    pub primary: IpAddr,
    /// A second address of the same family, on the same host, for the tests
    /// that need one. `None` serves the port-only tests.
    pub alternate: Option<IpAddr>,
}

/// What to serve.
#[derive(Debug, Clone)]
pub struct Config {
    pub families: Vec<FamilyConfig>,
    /// The port clients ask (3478 is the STUN default).
    pub port: u16,
    /// The port the "change port" tests answer from; 0 picks one above
    /// `port`.
    pub alternate_port: u16,
    /// Answers per second one client may have.
    pub rate: f64,
    pub burst: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            families: Vec::new(),
            port: 3478,
            alternate_port: 0,
            rate: 20.0,
            burst: 40.0,
        }
    }
}

/// A running server: what it listens on, and the task serving it.
pub struct StunServer {
    /// Every address it answers from, primary first.
    pub addresses: Vec<SocketAddr>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl StunServer {
    /// Binds the sockets and starts answering until `cancel` fires.
    pub async fn bind(config: Config, cancel: CancellationToken) -> std::io::Result<Self> {
        let limiter = Arc::new(parking_lot::Mutex::new(RateLimiter::new(
            config.rate,
            config.burst,
        )));
        let mut addresses = Vec::new();
        let mut tasks = Vec::new();
        for fam in &config.families {
            let group = Arc::new(Group::bind(fam, config.port, config.alternate_port).await?);
            addresses.extend(group.addresses());
            for (i, sock) in group.socks.iter().enumerate() {
                let (group, sock) = (group.clone(), sock.clone());
                let (limiter, cancel) = (limiter.clone(), cancel.clone());
                tasks.push(tokio::spawn(async move {
                    let mut buf = [0u8; 1500];
                    loop {
                        let (n, from) = tokio::select! {
                            r = sock.recv_from(&mut buf) => match r {
                                Ok(x) => x,
                                // ICMP errors and the like: keep serving.
                                Err(_) => continue,
                            },
                            _ = cancel.cancelled() => return,
                        };
                        if let Some((reply, to, via)) = group.answer(i, &buf[..n], from) {
                            if limiter.lock().allow(from, Instant::now()) {
                                let _ = group.socks[via].send_to(&reply, to).await;
                            }
                        }
                    }
                }));
            }
        }
        Ok(Self { addresses, tasks })
    }

    /// Stops answering.
    pub fn abort(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// The four sockets of one family, and what they stand for. Index bit 0 is
/// "alternate port", bit 1 is "alternate address".
struct Group {
    socks: Vec<Arc<UdpSocket>>,
    /// The address each socket answers from.
    origins: Vec<SocketAddr>,
    /// Whether a second address exists at all.
    has_alt_ip: bool,
}

impl Group {
    async fn bind(fam: &FamilyConfig, port: u16, alt_port: u16) -> std::io::Result<Self> {
        // Port 0 asks the system for every port (the tests do); otherwise the
        // alternate is the next one up unless said.
        let alt_port = match (port, alt_port) {
            (0, _) => 0,
            (_, 0) => port.checked_add(1).unwrap_or(port - 1),
            (_, p) => p,
        };
        let ips: Vec<IpAddr> = std::iter::once(fam.primary).chain(fam.alternate).collect();
        let mut socks = Vec::new();
        let mut origins = Vec::new();
        // Index = ip_index * 2 + port_index, so bit 1 changes the address
        // and bit 0 the port.
        for ip in &ips {
            for p in [port, alt_port] {
                let s = UdpSocket::bind(SocketAddr::new(*ip, p)).await?;
                origins.push(s.local_addr()?);
                socks.push(Arc::new(s));
            }
        }
        Ok(Self {
            has_alt_ip: ips.len() > 1,
            socks,
            origins,
        })
    }

    fn addresses(&self) -> Vec<SocketAddr> {
        self.origins.clone()
    }

    /// The reply to a request that arrived on socket `on`: the message, where
    /// to send it and which socket to send it from. `None` for anything that
    /// is not a Binding request.
    fn answer(
        &self,
        on: usize,
        pkt: &[u8],
        from: SocketAddr,
    ) -> Option<(Vec<u8>, SocketAddr, usize)> {
        if !stun::is_stun_request(pkt) {
            return None;
        }
        let tid = stun::message_transaction_id(pkt)?;
        let (change_ip, change_port) = stun::requested_change(pkt);
        // "Change IP" needs an address to change to; a server without one
        // does not pretend, and the client sees no answer.
        if change_ip && !self.has_alt_ip {
            return None;
        }
        let mut via = on;
        if change_ip {
            via ^= 0b10;
        }
        if change_port {
            via ^= 0b01;
        }
        // The answer goes to the source address, with the port the client
        // asked for if it asked (RFC 5780 section 7.3: only the port).
        let mut to = from;
        if let Some(p) = stun::requested_response_port(pkt) {
            to.set_port(p);
        }
        // OTHER-ADDRESS is the socket that differs in both address and port
        // from the one the request arrived on.
        let other = self.origins[on ^ if self.has_alt_ip { 0b11 } else { 0b01 }];
        let reply = stun::binding_success(&tid, from, Some(self.origins[via]), Some(other));
        Some((reply, to, via))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn ask(
        sock: &UdpSocket,
        to: SocketAddr,
        msg: Vec<u8>,
        tid: &[u8; 12],
    ) -> Option<stun::BindingResponse> {
        sock.send_to(&msg, to).await.unwrap();
        let mut buf = [0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_millis(400), sock.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        stun::parse_binding_response(&buf[..n], tid).ok()
    }

    async fn server(alternate: Option<IpAddr>) -> Option<(StunServer, CancellationToken)> {
        let cancel = CancellationToken::new();
        let s = StunServer::bind(
            Config {
                families: vec![FamilyConfig {
                    primary: "127.0.0.1".parse().unwrap(),
                    alternate,
                }],
                port: 0,
                alternate_port: 0,
                ..Config::default()
            },
            cancel.clone(),
        )
        .await
        .ok()?;
        Some((s, cancel))
    }

    /// With port 0 the system picks each port, so the "alternate port" is
    /// only an ordinary port here; what the tests check is which socket
    /// answers, told apart by the origin the reply names.
    #[tokio::test]
    async fn answers_from_the_socket_the_request_asks_for() {
        // Some systems (macOS) have only 127.0.0.1 on loopback: the address
        // change is then not offered, which is the other test below.
        let alt: IpAddr = "127.0.0.2".parse().unwrap();
        let Some((s, cancel)) = server(Some(alt)).await else {
            return;
        };
        let [p00, p01, p10, p11] = s.addresses[..] else {
            panic!("{:?}", s.addresses)
        };
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let me = client.local_addr().unwrap();

        let tid = stun::transaction_id();
        let r = ask(&client, p00, stun::binding_request(&tid), &tid)
            .await
            .expect("a plain request is answered");
        assert_eq!(r.mapped, me);
        assert_eq!(r.response_origin, Some(p00));
        // The other address is the one that differs in both.
        assert_eq!(r.other_address, Some(p11));

        for (change_ip, change_port, origin) in
            [(false, true, p01), (true, false, p10), (true, true, p11)]
        {
            let tid = stun::transaction_id();
            let r = ask(
                &client,
                p00,
                stun::binding_request_with_change(&tid, change_ip, change_port),
                &tid,
            )
            .await
            .unwrap_or_else(|| {
                panic!("no answer for change ip {} port {}", change_ip, change_port)
            });
            assert_eq!(
                r.response_origin,
                Some(origin),
                "{} {}",
                change_ip,
                change_port
            );
        }
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_server_with_one_address_does_not_pretend_to_have_two() {
        let Some((s, cancel)) = server(None).await else {
            return;
        };
        let [p0, p1] = s.addresses[..] else {
            panic!("{:?}", s.addresses)
        };
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tid = stun::transaction_id();
        let r = ask(&client, p0, stun::binding_request(&tid), &tid)
            .await
            .expect("answered");
        // The other address is the same one, on the other port.
        assert_eq!(r.other_address, Some(p1));
        // Changing the port works; changing the address gets no answer.
        let tid = stun::transaction_id();
        let r = ask(
            &client,
            p0,
            stun::binding_request_with_change(&tid, false, true),
            &tid,
        )
        .await
        .expect("port change answered");
        assert_eq!(r.response_origin, Some(p1));
        let tid = stun::transaction_id();
        assert!(ask(
            &client,
            p0,
            stun::binding_request_with_change(&tid, true, false),
            &tid
        )
        .await
        .is_none());
        cancel.cancel();
    }

    /// RESPONSE-PORT moves the answer to another port of the requester's own
    /// address — how the lifetime of an idle mapping is measured — and never
    /// to another address.
    #[tokio::test]
    async fn a_response_port_moves_the_answer_to_another_port_of_the_asker() {
        let Some((s, cancel)) = server(None).await else {
            return;
        };
        let asker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tid = stun::transaction_id();
        asker
            .send_to(
                &stun::binding_request_with_response_port(
                    &tid,
                    listener.local_addr().unwrap().port(),
                ),
                s.addresses[0],
            )
            .await
            .unwrap();
        let mut buf = [0u8; 1500];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(500), listener.recv_from(&mut buf))
                .await
                .expect("the answer arrives at the port asked for")
                .unwrap();
        assert_eq!(from, s.addresses[0]);
        let r = stun::parse_binding_response(&buf[..n], &tid).unwrap();
        // It names the address the request came from, not where it went.
        assert_eq!(r.mapped, asker.local_addr().unwrap());
        // And the asking socket heard nothing.
        assert!(
            tokio::time::timeout(Duration::from_millis(150), asker.recv_from(&mut buf))
                .await
                .is_err()
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn only_binding_requests_are_answered_and_a_client_is_rate_limited() {
        let cancel = CancellationToken::new();
        let Ok(s) = StunServer::bind(
            Config {
                families: vec![FamilyConfig {
                    primary: "127.0.0.1".parse().unwrap(),
                    alternate: None,
                }],
                port: 0,
                rate: 0.001,
                burst: 3.0,
                ..Config::default()
            },
            cancel.clone(),
        )
        .await
        else {
            return;
        };
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Rubbish and a Binding *response* get no answer.
        for junk in [vec![0u8; 3], vec![0x5au8; 40], {
            let tid = stun::transaction_id();
            stun::binding_success(&tid, "127.0.0.1:9".parse().unwrap(), None, None)
        }] {
            client.send_to(&junk, s.addresses[0]).await.unwrap();
        }
        let mut buf = [0u8; 1500];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .is_err()
        );
        // The burst is three answers; the rest are held back.
        let mut answered = 0;
        for _ in 0..8 {
            let tid = stun::transaction_id();
            if ask(&client, s.addresses[0], stun::binding_request(&tid), &tid)
                .await
                .is_some()
            {
                answered += 1;
            }
        }
        assert_eq!(
            answered, 3,
            "the limiter never engaged, or engaged too soon"
        );
        cancel.cancel();
    }
}
