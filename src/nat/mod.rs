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
pub mod keepalive;
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
    /// Publish this host's addresses on the local network (private IPv4,
    /// unique-local IPv6) along with the public ones. They let a sender on
    /// the same network in without going out and back through the router,
    /// and they tell whoever is given the address how that network is laid
    /// out; this is the switch for the second concern.
    pub publish_lan_addresses: bool,
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
            publish_lan_addresses: true,
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
///
/// Every router we might be behind is asked at once, from every interface
/// that might be the one it serves: asking them in turn, each allowed its
/// full series of retries, could take a minute and a half before UPnP was
/// even tried — and the receiver's address was not reported until then.
async fn forward_port(local_addr: SocketAddr, lease: u32) -> Option<PortForward> {
    // Only IPv4 is forwarded; an IPv6 socket reaches IPv4 only when it is a
    // dual-stack wildcard.
    let bind_ip = match crate::address::canonical(local_addr).ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) if v6.is_unspecified() => Some(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => return None,
    };
    let ip = bind_ip?;
    // A socket bound to one address knows which one to claim; a wildcard
    // one has to try each interface it could be reached on.
    let clients = if ip.is_unspecified() {
        local_ipv4_addresses()
    } else {
        vec![ip]
    };
    let mut attempts = tokio::task::JoinSet::new();
    for gw in portmap::gateway_candidates() {
        let router = SocketAddr::new(IpAddr::V4(gw), portmap::PORT);
        for &client in &clients {
            let port = local_addr.port();
            attempts.spawn(async move { portmap::request_at(router, client, port, lease).await });
        }
    }
    let mut found = None;
    while let Some(r) = attempts.join_next().await {
        match r {
            Ok(Ok(m)) => {
                found = Some(m);
                break;
            }
            Ok(Err(e)) => tracing::debug!("NAT: {}", e),
            Err(_) => {}
        }
    }
    if let Some(m) = found {
        // Any other router that also agreed would forward a port nothing
        // uses until its lease ran out: let the rest finish, in their own
        // time, and give back whatever they were granted.
        if !attempts.is_empty() {
            tokio::spawn(async move {
                while let Some(r) = attempts.join_next().await {
                    if let Ok(Ok(extra)) = r {
                        let _ = extra.remove().await;
                    }
                }
            });
        }
        return Some(PortForward::Modern(m));
    }
    let bind = (!ip.is_unspecified()).then_some(ip);
    match UpnpMapping::create(local_addr.port(), bind, lease, "SHARP-256 receiver").await {
        Ok(m) => Some(PortForward::Upnp(m)),
        Err(e) => {
            tracing::debug!("NAT: {}", e);
            None
        }
    }
}

/// Whether a router's "external" address is really another network's
/// inside: a private or carrier-grade NAT address means the router is
/// itself behind a NAT, and what it forwards only reaches it from there.
fn is_inner_address(ip: IpAddr) -> bool {
    crate::address::class::is_inside(ip)
}

/// Where a port forward can be reached from outside, and whether it
/// cannot, because the router doing it is behind another NAT.
fn forward_address(
    forward: &PortForward,
    public: Option<SocketAddr>,
) -> (Option<SocketAddr>, bool) {
    match forward.external_addr() {
        Some(ext) if is_inner_address(ext.ip()) => (None, true),
        Some(ext) => (Some(ext), false),
        // The router did not name its own address: STUN's view of our IP
        // plus the port the router granted is the same thing — as long as
        // the router is the NAT the STUN server sees, which a router that
        // says nothing leaves us to assume.
        None => (
            public.map(|p| SocketAddr::new(p.ip(), forward.external_port())),
            false,
        ),
    }
}

/// This host's own addresses that a peer could use, best first.
///
/// A socket bound to one address has only that one; a wildcard socket is
/// reachable on every interface, and a wildcard IPv6 one (dual-stack) on
/// every address of both families. ICE's rules for host candidates apply
/// (RFC 8445 section 5.1.1.1, see `address::class::is_publishable_host`),
/// and two more:
///
/// * An IPv6 address the system itself no longer prefers or has not
///   finished checking — deprecated, tentative, failed duplicate address
///   detection — is left out: it may be gone, or someone else's, by the
///   time a sender uses it.
/// * Where the system uses temporary IPv6 addresses (RFC 8981), whose whole
///   point is that the stable half of an address cannot be used to follow
///   a host from network to network, the stable address of the same
///   interface and prefix is left out too (RFC 8445 section 5.1.1.1 says
///   MUST NOT): publishing it would give away exactly what the temporary
///   one hides. Where the system cannot say which addresses are temporary,
///   the one it picks itself as the source for a global destination (RFC
///   6724 prefers a temporary one) stands for its prefix.
///
/// With `lan` off, only addresses the internet routes are published: the
/// rest say how the local network is laid out, to whoever is given them.
fn host_addresses(local: SocketAddr, lan: bool) -> Vec<IpAddr> {
    use crate::address::class;
    let wanted = |ip: IpAddr| class::is_publishable_host(ip) && (lan || class::is_global(ip));
    let local_ip = crate::address::canonical(local).ip();
    if !local_ip.is_unspecified() {
        return if wanted(local_ip) {
            vec![local_ip]
        } else {
            Vec::new()
        };
    }
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    // A wildcard IPv6 socket usually also serves IPv4; a wildcard IPv4 one
    // never serves IPv6.
    let serves_v6 = local.is_ipv6();
    let states = ipv6_states();
    let found: Vec<(IpAddr, String)> = ifaces
        .into_iter()
        .map(|i| (i.ip(), i.name))
        .filter(|(ip, _)| wanted(*ip) && (serves_v6 || ip.is_ipv4()))
        .filter(|(ip, _)| match ip {
            IpAddr::V6(v6) => states.get(v6).is_none_or(|s| s.usable()),
            IpAddr::V4(_) => true,
        })
        .collect();
    let preferred = if serves_v6 {
        class::source_for(SocketAddr::new(PREFERENCE_PROBE.into(), 9))
    } else {
        None
    };
    choose_host_addresses(&found, &states, preferred)
}

/// The choice [`host_addresses`] makes, from what it gathered: every
/// usable address with its interface, the system's flags, and the source
/// address the system prefers for a global destination.
fn choose_host_addresses(
    found: &[(IpAddr, String)],
    states: &std::collections::HashMap<std::net::Ipv6Addr, V6State>,
    preferred: Option<IpAddr>,
) -> Vec<IpAddr> {
    use crate::address::class;
    // One IPv6 address per interface and /64 stands for it: the one the
    // system itself prefers, else a temporary one, else the first listed.
    let score = |ip: &IpAddr| match ip {
        IpAddr::V6(v6) => (
            Some(*ip) == preferred,
            states.get(v6).is_some_and(|s| s.temporary),
        ),
        IpAddr::V4(_) => (false, false),
    };
    let group = |(ip, iface): &(IpAddr, String)| match ip {
        IpAddr::V6(v6) => Some((iface.clone(), v6.segments()[..4].to_vec())),
        IpAddr::V4(_) => None,
    };
    let mut out: Vec<IpAddr> = Vec::new();
    for (i, entry) in found.iter().enumerate() {
        if let Some(g) = group(entry) {
            let best = found
                .iter()
                .enumerate()
                .filter(|(_, other)| group(other).as_ref() == Some(&g))
                .max_by_key(|(j, other)| (score(&other.0), std::cmp::Reverse(*j)))
                .map(|(j, _)| j);
            if best != Some(i) {
                continue;
            }
        }
        if !out.contains(&entry.0) {
            out.push(entry.0);
        }
    }
    // Global first — they are what a peer anywhere can use — the system's
    // own preference first among those, then the local network's.
    out.sort_by_key(|ip| {
        let rank = match class::classify(*ip) {
            class::Class::Global if ip.is_ipv6() => 0,
            class::Class::Global => 1,
            class::Class::Private | class::Class::Shared if ip.is_ipv4() => 2,
            class::Class::Private | class::Class::Shared => 3,
            _ => 4,
        };
        (rank, Some(*ip) != preferred)
    });
    out.truncate(MAX_CANDIDATES);
    out
}

/// A global IPv6 destination, to ask the system which of its addresses it
/// would send from (nothing is sent: see `address::class::source_for`).
/// From the documentation prefix, so that it can never be anybody's.
const PREFERENCE_PROBE: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);

/// What the system says about one of its IPv6 addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct V6State {
    temporary: bool,
    deprecated: bool,
    tentative: bool,
    dad_failed: bool,
}

impl V6State {
    /// Still one to give out.
    fn usable(&self) -> bool {
        !(self.deprecated || self.tentative || self.dad_failed)
    }
}

/// The system's own view of its IPv6 addresses, where it offers one:
/// Linux lists them with their flags in `/proc/net/if_inet6`. Elsewhere
/// the map is empty, and the choice falls back to the system's preferred
/// source address (see [`host_addresses`]).
fn ipv6_states() -> std::collections::HashMap<std::net::Ipv6Addr, V6State> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        std::fs::read_to_string("/proc/net/if_inet6")
            .map(|t| parse_if_inet6(&t))
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        std::collections::HashMap::new()
    }
}

/// Parses `/proc/net/if_inet6`: per line the address as 32 hex digits, the
/// interface index, prefix length, scope and flags in hex, and the
/// interface name. The flags are the kernel's `IFA_F_*`.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", test)),
    allow(dead_code)
)]
fn parse_if_inet6(text: &str) -> std::collections::HashMap<std::net::Ipv6Addr, V6State> {
    const IFA_F_TEMPORARY: u32 = 0x01;
    const IFA_F_DADFAILED: u32 = 0x08;
    const IFA_F_DEPRECATED: u32 = 0x20;
    const IFA_F_TENTATIVE: u32 = 0x40;
    let mut out = std::collections::HashMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 || fields[0].len() != 32 {
            continue;
        }
        let Ok(raw) = u128::from_str_radix(fields[0], 16) else {
            continue;
        };
        let Ok(flags) = u32::from_str_radix(fields[4], 16) else {
            continue;
        };
        out.insert(
            std::net::Ipv6Addr::from(raw),
            V6State {
                temporary: flags & IFA_F_TEMPORARY != 0,
                deprecated: flags & IFA_F_DEPRECATED != 0,
                tentative: flags & IFA_F_TENTATIVE != 0,
                dad_failed: flags & IFA_F_DADFAILED != 0,
            },
        );
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
    /// The router forwarded a port, but reports an inside address as its
    /// own: it is behind another NAT, and the forward does not reach it
    /// from the internet.
    pub double_nat: bool,
    /// This host's own addresses worth publishing, best first (see
    /// [`host_addresses`]).
    pub host: Vec<IpAddr>,
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
        for ip in &self.host {
            add(
                SocketAddr::new(*ip, self.local_addr.port()),
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
        let summary = self.describe_path();
        if self.double_nat {
            return format!(
                "{}; the router forwarded a port, but it is itself behind another NAT, so \
                 the forward only helps inside that network",
                summary
            );
        }
        summary
    }

    fn describe_path(&self) -> String {
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

/// What discovery has found so far.
fn reachability(
    local_addr: SocketAddr,
    behaviour: &Behaviour,
    forward: Option<&PortForward>,
    publish_lan: bool,
) -> Reachability {
    let public_addr = behaviour.mapped;
    let (upnp_addr, double_nat) = match forward {
        Some(f) => forward_address(f, public_addr),
        None => (None, false),
    };
    Reachability {
        local_addr,
        public_addr,
        behaviour: *behaviour,
        upnp_addr,
        double_nat,
        host: host_addresses(local_addr, publish_lan),
    }
}

/// Handle of a background discovery task.
pub struct NatTask {
    /// The receiver's dispatcher passes STUN messages here, with the address
    /// each came from: what a server claims about where it answered from is
    /// worth checking against where the packet really came from.
    pub stun_responses: mpsc::Sender<stun::Incoming>,
    pub task: JoinHandle<()>,
}

/// Starts NAT discovery for the receiver's socket in the background.
///
/// The address tests and the port-forward request run side by side, and
/// what they find is reported through `on_result` as it comes: first when
/// the tests are done, again if a port forward is granted after that. A
/// router that is slow to answer, or never does, no longer holds up telling
/// the user where the receiver can be reached. A port forward is kept alive
/// until `cancel` fires and then given back, so the router does not keep
/// forwarding a port nothing listens on. Returns `None` for loopback
/// sockets, where there is nothing to discover.
pub fn spawn_receiver_discovery(
    socket: Arc<UdpSocket>,
    config: NatConfig,
    cancel: CancellationToken,
    on_result: impl Fn(&Reachability) + Send + 'static,
) -> Option<NatTask> {
    let local = socket.local_addr().ok()?;
    if crate::address::canonical(local).ip().is_loopback() {
        return None;
    }
    let (tx, mut rx) = mpsc::channel::<stun::Incoming>(64);
    let task = tokio::spawn(async move {
        // Owns the channel the STUN messages come in on, and lets go of it
        // when done: the dispatcher then stops handing us any.
        let (tests_socket, servers, enable_stun) = (
            socket.clone(),
            config.stun_servers.clone(),
            config.enable_stun,
        );
        let tests = async move {
            if enable_stun {
                let b = behaviour::discover(&tests_socket, &servers, &mut rx).await;
                tracing::debug!("NAT: {}", b.describe());
                b
            } else {
                Behaviour::default()
            }
        };
        let mapping = async {
            if config.enable_port_mapping {
                forward_port(local, config.mapping_lease).await
            } else {
                None
            }
        };
        tokio::pin!(tests, mapping);
        let mut behaviour: Option<Behaviour> = None;
        let mut forward: Option<Option<PortForward>> = None;
        while behaviour.is_none() || forward.is_none() {
            tokio::select! {
                b = &mut tests, if behaviour.is_none() => {
                    let r = reachability(
                        local,
                        &b,
                        forward.as_ref().and_then(|f| f.as_ref()),
                        config.publish_lan_addresses,
                    );
                    tracing::info!("NAT: {}", r.describe());
                    on_result(&r);
                    behaviour = Some(b);
                }
                f = &mut mapping, if forward.is_none() => {
                    if let Some(f) = &f {
                        tracing::info!("NAT: {}", f.describe());
                        // Worth saying again only once there is something
                        // to say it with.
                        if let Some(b) = &behaviour {
                            let r = reachability(local, b, Some(f), config.publish_lan_addresses);
                            tracing::info!("NAT: {}", r.describe());
                            on_result(&r);
                        }
                    }
                    forward = Some(f);
                }
                _ = cancel.cancelled() => {
                    if let Some(Some(m)) = forward {
                        let _ = tokio::time::timeout(Duration::from_secs(3), m.remove()).await;
                    }
                    return;
                }
            }
        }
        let Some(Some(mapping)) = forward else { return };
        let lease = mapping.lifetime();
        if lease > 0 {
            // Renew at half the lease, so one lost renewal is not fatal.
            // The floor is small on purpose: a router may grant far less
            // than was asked for — PCP explicitly allows it, and they do it
            // under pressure — and a floor of half a minute would have left
            // a thirty-second grant dead for half of every cycle.
            let every = Duration::from_secs((lease as u64 / 2).max(5));
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(every) => {
                        // Bounded, and interruptible: a router that stops
                        // answering must not keep the receiver from
                        // shutting down.
                        tokio::select! {
                            r = tokio::time::timeout(
                                Duration::from_secs(10),
                                mapping.refresh(config.mapping_lease),
                            ) => match r {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => tracing::warn!("NAT: {}", e),
                                Err(_) => tracing::warn!("NAT: the router did not answer the renewal"),
                            },
                            _ = cancel.cancelled() => break,
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
            double_nat: false,
            host: Vec::new(),
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
        assert_eq!(c.len(), 1 + r.host.len());
        assert_eq!(c[0].kind, CandidateKind::PortForward);
        assert!(c.len() <= MAX_CANDIDATES);
    }

    /// A router that reports an inside address as its own is behind another
    /// NAT: the port it forwards reaches it only from that network, and
    /// publishing it — first, as the best candidate of all — sent every
    /// sender outside to an address that cannot work.
    #[test]
    fn a_forward_on_a_router_behind_another_nat_is_not_published() {
        let inner = |ip: &str| {
            let m = portmap::Mapping::for_tests(
                "192.168.1.1:5351".parse().unwrap(),
                Some(ip.parse().unwrap()),
                41000,
            );
            PortForward::Modern(m)
        };
        let public: Option<SocketAddr> = Some("203.0.113.9:50000".parse().unwrap());
        for ip in ["100.64.3.4", "10.1.2.3", "192.168.0.2", "172.16.9.9"] {
            let (addr, double) = forward_address(&inner(ip), public);
            assert_eq!(addr, None, "{}", ip);
            assert!(double, "{}", ip);
        }
        let (addr, double) = forward_address(&inner("198.51.100.4"), public);
        assert_eq!(addr, Some("198.51.100.4:41000".parse().unwrap()));
        assert!(!double);

        let behaviour = nat(Mapping::EndpointIndependent, Filtering::AddressDependent);
        let r = reachability(
            "0.0.0.0:5555".parse().unwrap(),
            &Behaviour {
                mapped: public,
                ..behaviour
            },
            Some(&inner("100.64.3.4")),
            true,
        );
        assert!(r.double_nat);
        assert!(r
            .candidates()
            .iter()
            .all(|c| c.kind != CandidateKind::PortForward));
        assert!(
            r.describe().contains("behind another NAT"),
            "{}",
            r.describe()
        );
    }

    /// The kernel's own list, flags and all.
    #[test]
    fn reads_the_kernels_ipv6_flags() {
        let text = "\
20010db8000000000000000000000001 02 40 00 80     eth0
20010db800000000a1b2c3d4e5f60718 02 40 00 01     eth0
20010db8000000000000000000000002 02 40 00 a0     eth0
fe800000000000000000000000000001 02 40 20 80     eth0
20010db8000000000000000000000003 02 40 00 c0     eth0
garbage line
";
        let states = parse_if_inet6(text);
        let v6 = |s: &str| s.parse::<std::net::Ipv6Addr>().unwrap();
        assert_eq!(states.len(), 5);
        assert!(states[&v6("2001:db8::1")].usable());
        assert!(!states[&v6("2001:db8::1")].temporary);
        assert!(states[&v6("2001:db8::a1b2:c3d4:e5f6:718")].temporary);
        assert!(!states[&v6("2001:db8::2")].usable(), "deprecated");
        assert!(!states[&v6("2001:db8::3")].usable(), "tentative");
    }

    /// RFC 8445 section 5.1.1.1: where a temporary address exists, the
    /// stable one of the same interface and prefix is not published; one
    /// address stands for each prefix; global addresses come first.
    #[test]
    fn temporary_addresses_hide_the_stable_ones() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let v6 = |s: &str| s.parse::<std::net::Ipv6Addr>().unwrap();
        let found: Vec<(IpAddr, String)> = [
            ("192.168.1.7", "eth0"),
            ("2a00:1:1::1", "eth0"),
            ("2a00:1:1::a1b2:c3d4", "eth0"),
            ("2a00:1:2::1", "eth0"),
            ("fd00::1", "eth0"),
            ("2a00:1:1::5", "wlan0"),
        ]
        .iter()
        .map(|(a, i)| (ip(a), i.to_string()))
        .collect();
        let mut states = std::collections::HashMap::new();
        states.insert(
            v6("2a00:1:1::a1b2:c3d4"),
            V6State {
                temporary: true,
                ..V6State::default()
            },
        );
        let out = choose_host_addresses(&found, &states, None);
        assert_eq!(
            out,
            [
                ip("2a00:1:1::a1b2:c3d4"),
                ip("2a00:1:2::1"),
                ip("2a00:1:1::5"),
                ip("192.168.1.7"),
                ip("fd00::1"),
            ]
        );
        // Where the system does not say which are temporary, its own
        // choice of source stands for its prefix, and comes first.
        let out = choose_host_addresses(
            &found,
            &std::collections::HashMap::new(),
            Some(ip("2a00:1:2::1")),
        );
        assert_eq!(out[0], ip("2a00:1:2::1"));
        assert!(out.contains(&ip("2a00:1:1::1")));
        assert!(!out.contains(&ip("2a00:1:1::a1b2:c3d4")), "{:?}", out);
    }

    /// With the local network's addresses withheld, only what the internet
    /// routes is published — whatever this host's interfaces are.
    #[test]
    fn without_lan_addresses_only_global_ones_are_published() {
        use crate::address::class::is_global;
        for local in ["[::]:1", "0.0.0.0:1"] {
            for ip in host_addresses(local.parse().unwrap(), false) {
                assert!(is_global(ip), "{} published from {}", ip, local);
            }
        }
        let lan: SocketAddr = "192.168.1.7:5555".parse().unwrap();
        assert!(host_addresses(lan, false).is_empty());
        assert_eq!(host_addresses(lan, true), vec![lan.ip()]);
        let public: SocketAddr = "[2a00:1:2::7]:5555".parse().unwrap();
        assert_eq!(host_addresses(public, false), vec![public.ip()]);
    }

    /// A loopback socket has nothing to offer anyone else.
    #[test]
    fn loopback_is_never_a_candidate() {
        let r = Reachability {
            local_addr: "127.0.0.1:5555".parse().unwrap(),
            public_addr: None,
            behaviour: Behaviour::default(),
            upnp_addr: None,
            double_nat: false,
            host: host_addresses("127.0.0.1:5555".parse().unwrap(), true),
        };
        assert!(r.candidates().is_empty());
        for ip in host_addresses("0.0.0.0:1".parse().unwrap(), true) {
            assert!(!ip.is_loopback());
        }
    }
}
