//! Optional NAT helpers for the receiver.
//!
//! * [`stun`] tells which public address and port the receiver's transfer
//!   socket is seen under, so the user knows what to give to senders;
//! * [`behaviour`] measures what the NAT actually does with that mapping
//!   (RFC 5780), which is what says whether publishing the address is enough,
//!   whether the sender has to be let in first, or whether nothing but a
//!   relay will do;
//! * [`portmap`] and [`upnp`] ask the router to forward a port, which is the
//!   one way through that depends on neither. All three protocols routers
//!   speak for this are tried — PCP, NAT-PMP and UPnP-IGD.
//!
//! It all runs in a background task: the receiver serves transfers
//! immediately, and STUN messages are routed to the task by the receiver's
//! dispatcher.
//!
//! The sender needs no NAT handling: its outgoing HELLO creates the mapping
//! on its own NAT, and the receiver answers the address the handshake came
//! from (following it later only through address validation). Two peers that
//! are both behind NATs without a forward need a rendezvous to punch or a
//! relay to meet at.
//!
//! **Nothing learned here is trusted.** STUN servers and routers are
//! unauthenticated, and on a network we do not own anything may answer. All
//! any of them can produce is an address that does or does not work: it
//! decides which addresses are worth *trying*, never who we talk to.
//! Authentication settles that, so a lie costs a wasted attempt.

pub mod behaviour;
pub mod portmap;
pub mod stun;
pub mod upnp;

use self::behaviour::{Behaviour, Reachable};
use self::upnp::UpnpMapping;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct NatConfig {
    pub enable_stun: bool,
    /// Ask the router for a port forward (PCP, NAT-PMP and UPnP-IGD).
    pub enable_port_mapping: bool,
    /// Servers for the address and behaviour tests. The RFC 5780 tests need
    /// a server with a second address and port; one that has none still
    /// reports the mapped address, and two such servers still cross-check
    /// the mapping between them.
    pub stun_servers: Vec<String>,
    /// Requested lease in seconds; the mapping is renewed at half of it.
    pub mapping_lease: u32,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enable_stun: true,
            enable_port_mapping: true,
            stun_servers: vec![
                "stun.l.google.com:19302".to_string(),
                "stun.cloudflare.com:3478".to_string(),
                "stun1.l.google.com:19302".to_string(),
            ],
            mapping_lease: 3600,
        }
    }
}

/// A port forward, however it was obtained.
pub enum PortForward {
    Modern(portmap::Mapping),
    Upnp(UpnpMapping),
}

impl PortForward {
    pub fn protocol(&self) -> &'static str {
        match self {
            PortForward::Modern(m) => m.protocol().name(),
            PortForward::Upnp(_) => "UPnP-IGD",
        }
    }

    pub fn external_port(&self) -> u16 {
        match self {
            PortForward::Modern(m) => m.external_port(),
            PortForward::Upnp(m) => m.external_port(),
        }
    }

    /// The external address, when the router reported its own IP.
    pub fn external_addr(&self) -> Option<SocketAddr> {
        match self {
            PortForward::Modern(m) => m.external_addr(),
            PortForward::Upnp(m) => m.external_addr(),
        }
    }

    /// Seconds the forward lives; 0 means it never expires.
    pub fn lifetime(&self) -> u32 {
        match self {
            PortForward::Modern(m) => m.lifetime(),
            PortForward::Upnp(m) => m.lease(),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            PortForward::Modern(m) => format!(
                "{} forwards port {} to {} for {} s (router {})",
                m.protocol().name(),
                m.external_port(),
                m.internal(),
                m.lifetime(),
                m.router()
            ),
            PortForward::Upnp(m) => format!(
                "UPnP-IGD forwards port {} to {} for {} s",
                m.external_port(),
                m.local(),
                m.lease()
            ),
        }
    }

    async fn refresh(&self, lease: u32) -> anyhow::Result<()> {
        match self {
            PortForward::Modern(m) => m.refresh(lease).await,
            PortForward::Upnp(m) => m.refresh().await,
        }
    }

    async fn remove(self) -> anyhow::Result<()> {
        match self {
            PortForward::Modern(m) => m.remove().await,
            PortForward::Upnp(m) => m.remove().await,
        }
    }
}

/// Asks the router for a UDP forward to `local_port`, trying every protocol
/// routers speak for it. PCP and NAT-PMP come first: they are two small
/// datagrams against UPnP's multicast discovery followed by HTTP and SOAP,
/// and they are what most routers made in the last decade implement.
async fn forward_port(local_addr: SocketAddr, lease: u32) -> Option<PortForward> {
    let bind_ip = match local_addr.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    };
    if let Some(ip) = bind_ip {
        // A socket bound to one address knows which one to claim; a wildcard
        // one has to try each interface it could be reached on.
        let clients = if ip.is_unspecified() {
            local_ipv4_addresses()
        } else {
            vec![ip]
        };
        for client in clients {
            match portmap::request(client, local_addr.port(), lease).await {
                Ok(m) => return Some(PortForward::Modern(m)),
                Err(e) => tracing::debug!("NAT: {}", e),
            }
        }
    }
    match UpnpMapping::create(local_addr.port(), bind_ip, lease, "SHARP-256 receiver").await {
        Ok(m) => Some(PortForward::Upnp(m)),
        Err(e) => {
            tracing::debug!("NAT: {}", e);
            None
        }
    }
}

/// This host's own addresses that a peer on the same network could use.
///
/// A socket bound to one address has only that one; a wildcard socket is
/// reachable on every interface. Loopback is left out: a candidate nobody
/// but this host can use is only a quarter of a second wasted for whoever
/// tries it.
fn host_addresses(local: SocketAddr) -> Vec<IpAddr> {
    if !local.ip().is_unspecified() {
        return if local.ip().is_loopback() {
            Vec::new()
        } else {
            vec![local.ip()]
        };
    }
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut out: Vec<IpAddr> = Vec::new();
    for i in ifaces {
        let ip = i.ip();
        if ip.is_loopback() || out.contains(&ip) {
            continue;
        }
        // A wildcard IPv6 socket usually also serves IPv4; a wildcard IPv4
        // one never serves IPv6.
        if ip.is_ipv6() && !local.is_ipv6() {
            continue;
        }
        // An IPv6 link-local address (fe80::/10) only works with the scope
        // it belongs to, which a written address does not carry.
        // `Ipv6Addr::is_unicast_link_local` would say this, but it is newer
        // than the Rust version this crate supports.
        match ip {
            IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80 => continue,
            _ => {}
        }
        out.push(ip);
        if out.len() >= MAX_CANDIDATES {
            break;
        }
    }
    out
}

/// This host's own IPv4 addresses, for a socket bound to the wildcard.
fn local_ipv4_addresses() -> Vec<std::net::Ipv4Addr> {
    if_addrs::get_if_addrs()
        .map(|ifs| {
            ifs.into_iter()
                .filter_map(|i| match i.addr {
                    if_addrs::IfAddr::V4(v4) if !v4.ip.is_loopback() => Some(v4.ip),
                    _ => None,
                })
                .take(4)
                .collect()
        })
        .unwrap_or_default()
}

/// Where a candidate address came from. The names are ICE's (RFC 8445
/// section 5.1.1), because the idea is the same: gather every address a peer
/// might reach us at, publish them all, and let the checks decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// An address of this host, as it sees itself. Reaches peers on the same
    /// network and nobody else.
    Host,
    /// The address a STUN server sees us at, which is the NAT's mapping.
    ServerReflexive,
    /// A port the router agreed to forward to us.
    PortForward,
}

impl CandidateKind {
    pub fn name(self) -> &'static str {
        match self {
            CandidateKind::Host => "host",
            CandidateKind::ServerReflexive => "seen from outside",
            CandidateKind::PortForward => "port forward",
        }
    }
}

/// One address a sender may be able to reach this receiver at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub addr: SocketAddr,
    pub kind: CandidateKind,
}

/// Candidates a receiver publishes at most. The sender tries them in turn,
/// so a long list costs setup time.
pub const MAX_CANDIDATES: usize = 6;

/// Outcome of a discovery run.
#[derive(Debug, Clone)]
pub struct Reachability {
    pub local_addr: SocketAddr,
    pub public_addr: Option<SocketAddr>,
    /// What the NAT in front of this socket actually does (RFC 5780).
    pub behaviour: Behaviour,
    pub upnp_addr: Option<SocketAddr>,
}

impl Reachability {
    /// Address senders outside the local network should use, if known.
    pub fn advertised(&self) -> Option<SocketAddr> {
        if let Some(a) = self.upnp_addr {
            return Some(a);
        }
        if self.behaviour.open_internet {
            return self
                .public_addr
                .map(|p| SocketAddr::new(p.ip(), self.local_addr.port()));
        }
        // A mapping that does not change with the destination is the same
        // one a sender would arrive at, so it is worth publishing even when
        // a filter means the sender has to be let in first.
        match self.behaviour.reachable() {
            Reachable::OncePublished | Reachable::ByPunching => self.public_addr,
            _ => None,
        }
    }

    /// Every address a sender might reach this receiver at, best first.
    ///
    /// The ones that work from outside come first, because that is who the
    /// address gets given to; the host addresses follow for a sender on the
    /// same network. The sender tries them in turn a quarter of a second
    /// apart and lets the handshake decide, so a candidate that does not
    /// work costs that much and nothing else — which is exactly why it is
    /// safe to publish addresses we are not sure about.
    pub fn candidates(&self) -> Vec<Candidate> {
        let mut out: Vec<Candidate> = Vec::new();
        let mut add = |addr: SocketAddr, kind: CandidateKind| {
            if addr.port() != 0
                && !addr.ip().is_unspecified()
                && out.len() < MAX_CANDIDATES
                && !out.iter().any(|c| c.addr == addr)
            {
                out.push(Candidate { addr, kind });
            }
        };
        if let Some(a) = self.upnp_addr {
            add(a, CandidateKind::PortForward);
        }
        // Worth publishing only when the mapping does not change with the
        // destination; otherwise this address is the one *a STUN server*
        // reaches us at and tells a sender nothing.
        if let Some(p) = self.public_addr {
            if self.behaviour.open_internet
                || matches!(
                    self.behaviour.reachable(),
                    Reachable::OncePublished | Reachable::ByPunching
                )
            {
                add(p, CandidateKind::ServerReflexive);
            }
        }
        for ip in host_addresses(self.local_addr) {
            add(
                SocketAddr::new(ip, self.local_addr.port()),
                CandidateKind::Host,
            );
        }
        out
    }

    /// The candidates as a sender writes them: `ID@host:port,host:port,…`.
    pub fn address_string(&self, id: &crate::crypto::SharpId) -> Option<String> {
        let list: Vec<String> = self
            .candidates()
            .iter()
            .map(|c| c.addr.to_string())
            .collect();
        if list.is_empty() {
            return None;
        }
        Some(format!("{}@{}", id, list.join(",")))
    }

    /// One-line human-readable summary.
    pub fn describe(&self) -> String {
        if let Some(a) = self.upnp_addr {
            return format!("reachable from outside at {} (port forward)", a);
        }
        if self.behaviour.open_internet {
            let a = self.advertised();
            return match a {
                Some(a) => format!("reachable from outside at {} (public address)", a),
                None => "on the open internet".to_string(),
            };
        }
        match (self.public_addr, self.behaviour.reachable()) {
            (Some(p), Reachable::OncePublished) => {
                format!(
                    "reachable from outside at {} ({})",
                    p,
                    self.behaviour.describe()
                )
            }
            (Some(p), Reachable::ByPunching) => format!(
                "seen from outside at {}, but inbound packets are filtered: a sender has to be \
                 let in first ({})",
                p,
                self.behaviour.describe()
            ),
            (Some(p), Reachable::OnlyByRelay) => format!(
                "behind a symmetric NAT (seen at {} right now, but the port changes per \
                 destination): senders outside this network need a port forward to local port {}, \
                 or a relay",
                p,
                self.local_addr.port()
            ),
            (Some(p), _) => format!(
                "public IP {}, NAT behaviour not determined; senders outside this network may \
                 need a port forward to local port {}",
                p.ip(),
                self.local_addr.port()
            ),
            (None, _) => "public address unknown (no STUN answer, no port forward); \
                          senders on the local network can connect directly"
                .to_string(),
        }
    }
}

async fn discover(
    socket: &UdpSocket,
    config: &NatConfig,
    responses: &mut mpsc::Receiver<stun::Incoming>,
) -> (Reachability, Option<PortForward>) {
    let local_addr = socket
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let behaviour = if config.enable_stun {
        behaviour::discover(socket, &config.stun_servers, responses).await
    } else {
        Behaviour::default()
    };
    let public_addr = behaviour.mapped;
    if config.enable_stun {
        tracing::debug!("NAT: {}", behaviour.describe());
    }

    // A host on the open internet has nothing to forward.
    let forward = if config.enable_port_mapping && !behaviour.open_internet {
        let f = forward_port(local_addr, config.mapping_lease).await;
        if let Some(f) = &f {
            tracing::info!("NAT: {}", f.describe());
        }
        f
    } else {
        None
    };
    let upnp_addr = forward.as_ref().and_then(|m| {
        m.external_addr().or_else(|| {
            // The router did not name its own address: STUN's view of our IP
            // plus the port the router granted is the same thing.
            public_addr.map(|p| SocketAddr::new(p.ip(), m.external_port()))
        })
    });
    (
        Reachability {
            local_addr,
            public_addr,
            behaviour,
            upnp_addr,
        },
        forward,
    )
}

/// Handle of a background discovery task.
pub struct NatTask {
    /// The receiver's dispatcher passes STUN messages here, with the address
    /// each came from: what a server claims about where it answered from is
    /// worth checking against where the packet really came from.
    pub stun_responses: mpsc::Sender<stun::Incoming>,
    pub task: JoinHandle<()>,
}

/// Starts NAT discovery for the receiver's socket in the background. The
/// result is reported through `on_result`; a port forward is kept alive
/// until `cancel` fires and then given back, so the router does not keep
/// forwarding a port nothing listens on. Returns `None` for loopback
/// sockets, where there is nothing to discover.
pub fn spawn_receiver_discovery(
    socket: Arc<UdpSocket>,
    config: NatConfig,
    cancel: CancellationToken,
    on_result: impl FnOnce(&Reachability) + Send + 'static,
) -> Option<NatTask> {
    let local = socket.local_addr().ok()?;
    if local.ip().is_loopback() {
        return None;
    }
    let (tx, mut rx) = mpsc::channel::<stun::Incoming>(64);
    let task = tokio::spawn(async move {
        let (reach, mapping) = tokio::select! {
            r = discover(&socket, &config, &mut rx) => r,
            _ = cancel.cancelled() => return,
        };
        drop(rx);
        tracing::info!("NAT: {}", reach.describe());
        on_result(&reach);
        let Some(mapping) = mapping else { return };
        let lease = mapping.lifetime();
        if lease > 0 {
            // Renew at half the lease, so one lost renewal is not fatal.
            let every = Duration::from_secs((lease / 2).max(30) as u64);
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(every) => {
                        if let Err(e) = mapping.refresh(config.mapping_lease).await {
                            tracing::warn!("NAT: {}", e);
                        }
                    }
                    _ = cancel.cancelled() => break,
                }
            }
        } else {
            cancel.cancelled().await;
        }
        let how = mapping.protocol();
        match tokio::time::timeout(Duration::from_secs(3), mapping.remove()).await {
            Ok(Ok(())) => tracing::info!("NAT: {} port forward given back", how),
            Ok(Err(e)) => tracing::warn!("NAT: {}", e),
            Err(_) => tracing::warn!("NAT: the router did not answer the removal request"),
        }
    });
    Some(NatTask {
        stun_responses: tx,
        task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::behaviour::{Filtering, Mapping};

    fn reach(behaviour: Behaviour, upnp: Option<&str>, public: Option<&str>) -> Reachability {
        Reachability {
            local_addr: "0.0.0.0:5555".parse().unwrap(),
            public_addr: public.map(|p| p.parse().unwrap()),
            behaviour,
            upnp_addr: upnp.map(|u| u.parse().unwrap()),
        }
    }

    fn nat(mapping: Mapping, filtering: Filtering) -> Behaviour {
        Behaviour {
            mapping,
            filtering,
            ..Behaviour::default()
        }
    }

    /// A mapping that changes with the destination means the address a STUN
    /// server sees is the one *it* reaches us at and nothing more. Publishing
    /// it would send every sender at an address that cannot work.
    #[test]
    fn a_symmetric_nats_mapping_is_not_published() {
        let r = reach(
            nat(
                Mapping::AddressAndPortDependent,
                Filtering::AddressDependent,
            ),
            None,
            Some("203.0.113.9:50000"),
        );
        let kinds: Vec<CandidateKind> = r.candidates().iter().map(|c| c.kind).collect();
        assert!(
            !kinds.contains(&CandidateKind::ServerReflexive),
            "{:?}",
            r.candidates()
        );
        assert_eq!(r.advertised(), None);
    }

    /// A stable mapping is worth publishing even behind a filter: the sender
    /// still has to be let in, but it is the address that will work when it
    /// is.
    #[test]
    fn a_stable_mapping_is_published_even_when_filtered() {
        for filtering in [
            Filtering::EndpointIndependent,
            Filtering::AddressDependent,
            Filtering::AddressAndPortDependent,
        ] {
            let r = reach(
                nat(Mapping::EndpointIndependent, filtering),
                None,
                Some("203.0.113.9:50000"),
            );
            let first = r.candidates();
            assert_eq!(
                first[0].kind,
                CandidateKind::ServerReflexive,
                "{:?}",
                filtering
            );
            assert_eq!(first[0].addr, "203.0.113.9:50000".parse().unwrap());
        }
    }

    /// The port forward comes first: it is the one that depends on neither
    /// the other side's behaviour nor on timing.
    #[test]
    fn a_port_forward_outranks_everything_else() {
        let r = reach(
            nat(Mapping::EndpointIndependent, Filtering::AddressDependent),
            Some("198.51.100.4:41000"),
            Some("203.0.113.9:50000"),
        );
        let c = r.candidates();
        assert_eq!(c[0].kind, CandidateKind::PortForward);
        assert_eq!(c[0].addr, "198.51.100.4:41000".parse().unwrap());
        assert_eq!(c[1].kind, CandidateKind::ServerReflexive);
        assert_eq!(r.advertised(), Some("198.51.100.4:41000".parse().unwrap()));
    }

    /// The published address is what a sender types, so it has to survive
    /// the round trip through the parser.
    #[test]
    fn the_published_address_parses_back() {
        let id = crate::crypto::Identity::generate().id();
        let r = reach(
            nat(Mapping::EndpointIndependent, Filtering::EndpointIndependent),
            Some("198.51.100.4:41000"),
            Some("203.0.113.9:50000"),
        );
        let text = r.address_string(&id).expect("candidates to publish");
        let (parsed_id, hosts) = crate::address::parse_peer(&text).expect("parses back");
        assert_eq!(parsed_id, id);
        assert_eq!(hosts.len(), r.candidates().len());
        assert_eq!(hosts[0], "198.51.100.4:41000");

        // Nothing discovered at all: no address to publish, and saying so
        // beats printing something that cannot work.
        let empty = reach(Behaviour::default(), None, None);
        let host_only = empty.candidates().len();
        assert_eq!(empty.address_string(&id).is_some(), host_only > 0);
    }

    /// Duplicates cost the sender a quarter of a second each for nothing.
    #[test]
    fn the_same_address_is_never_published_twice() {
        let r = reach(
            nat(Mapping::EndpointIndependent, Filtering::EndpointIndependent),
            Some("203.0.113.9:50000"),
            Some("203.0.113.9:50000"),
        );
        let c = r.candidates();
        assert_eq!(c.len(), 1 + host_addresses(r.local_addr).len());
        assert_eq!(c[0].kind, CandidateKind::PortForward);
        assert!(c.len() <= MAX_CANDIDATES);
    }

    /// A loopback socket has nothing to offer anyone else.
    #[test]
    fn loopback_is_never_a_candidate() {
        let r = Reachability {
            local_addr: "127.0.0.1:5555".parse().unwrap(),
            public_addr: None,
            behaviour: Behaviour::default(),
            upnp_addr: None,
        };
        assert!(r.candidates().is_empty());
        for ip in host_addresses("0.0.0.0:1".parse().unwrap()) {
            assert!(!ip.is_loopback());
        }
    }
}
