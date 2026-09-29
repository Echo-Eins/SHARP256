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
pub mod birthday;
pub mod card;
pub mod dht;
pub mod keepalive;
pub mod mdns;
pub mod portmap;
pub mod probe;
pub mod punch;
pub mod stun;
pub mod stunserver;
pub mod turn;
pub mod upnp;

use self::behaviour::{Allocation, Behaviour, Reachable};
use self::upnp::UpnpMapping;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
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
    /// How often the mapping behind a published address is checked with a
    /// request, between the keepalives (see `maintain`).
    pub mapping_check: Duration,
    /// How often this host's own addresses are looked at again.
    pub host_refresh: Duration,
    /// Keep the mapping and the addresses up to date after the first
    /// results. A receiver does, for as long as it runs; a sender wants
    /// its NAT's behaviour once, for the length of one transfer.
    pub maintain: bool,
    /// When the first tests found nothing at all (no STUN server answered),
    /// how long until they are run again; the wait doubles each time they
    /// find nothing, up to [`REDISCOVER_CEILING`]. Only while `maintain`.
    pub rediscover: Duration,
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
            mapping_check: MAPPING_CHECK,
            host_refresh: HOST_REFRESH,
            maintain: true,
            rediscover: REDISCOVER,
        }
    }
}

/// A port forward, however it was obtained.
pub enum PortForward {
    Modern(portmap::Mapping),
    Upnp(UpnpMapping),
    /// A hole in the router's IPv6 firewall, by UPnP: nothing is translated
    /// over IPv6, so the address to use is the host's own.
    Pinhole(upnp::UpnpPinhole),
}

impl PortForward {
    pub fn protocol(&self) -> &'static str {
        match self {
            PortForward::Modern(m) => m.protocol().name(),
            PortForward::Upnp(_) => "UPnP-IGD",
            PortForward::Pinhole(_) => "UPnP-IGD (IPv6 firewall)",
        }
    }

    /// Whether this is a forward on the IPv4 side of the router.
    pub fn is_v4(&self) -> bool {
        match self {
            PortForward::Modern(m) => m.internal().is_ipv4(),
            PortForward::Upnp(_) => true,
            PortForward::Pinhole(_) => false,
        }
    }

    pub fn external_port(&self) -> u16 {
        match self {
            PortForward::Modern(m) => m.external_port(),
            PortForward::Upnp(m) => m.external_port(),
            PortForward::Pinhole(m) => m.external_addr().port(),
        }
    }

    /// The external address, when the router reported its own IP.
    pub fn external_addr(&self) -> Option<SocketAddr> {
        match self {
            PortForward::Modern(m) => m.external_addr(),
            PortForward::Upnp(m) => m.external_addr(),
            PortForward::Pinhole(m) => Some(m.external_addr()),
        }
    }

    /// Seconds the forward lives; 0 means it never expires.
    pub fn lifetime(&self) -> u32 {
        match self {
            PortForward::Modern(m) => m.lifetime(),
            PortForward::Upnp(m) => m.lease(),
            PortForward::Pinhole(m) => m.lease(),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            PortForward::Modern(m) if m.internal().is_ipv6() => format!(
                "{} opens the IPv6 firewall to {} for {} s (router {})",
                m.protocol().name(),
                m.internal(),
                m.lifetime(),
                m.router()
            ),
            PortForward::Modern(m) => format!(
                "{} forwards port {} to {} for {} s (router {})",
                m.protocol().name(),
                m.external_port(),
                m.internal(),
                m.lifetime(),
                m.router()
            ),
            PortForward::Pinhole(m) => format!(
                "UPnP-IGD opens the IPv6 firewall to {} for {} s",
                m.external_addr(),
                m.lease()
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
            PortForward::Pinhole(m) => m.refresh().await,
        }
    }

    async fn remove(self) -> anyhow::Result<()> {
        match self {
            PortForward::Modern(m) => m.remove().await,
            PortForward::Upnp(m) => m.remove().await,
            PortForward::Pinhole(m) => m.remove().await,
        }
    }
}

/// Every forward or firewall opening obtained, and what came of each thing
/// tried — so that a person told "no port forward" can also be told why.
#[derive(Default)]
pub struct Forwards {
    pub granted: Vec<PortForward>,
    /// One line for each protocol asked, in words.
    pub notes: Vec<String>,
}

/// Asks the routers for what lets a peer in: a UDP forward to `local_addr`'s
/// port over IPv4, and, where this host has a global IPv6 address, a hole in
/// the IPv6 firewall — both at once, since each takes a router a few
/// seconds and neither depends on the other.
async fn forward_ports(local_addr: SocketAddr, lease: u32) -> Forwards {
    let ((v4, mut notes), (v6, notes6)) = tokio::join!(
        forward_port_v4(local_addr, lease),
        forward_port_v6(local_addr, lease)
    );
    notes.extend(notes6);
    Forwards {
        granted: v4.into_iter().chain(v6).collect(),
        notes,
    }
}

/// The IPv4 half of [`forward_ports`]: every protocol routers speak for a
/// forward. PCP and NAT-PMP come first: they are two small datagrams against
/// UPnP's multicast discovery followed by HTTP and SOAP, and they are what
/// most routers made in the last decade implement.
///
/// Every router we might be behind is asked at once, from every interface
/// that might be the one it serves: asking them in turn, each allowed its
/// full series of retries, could take a minute and a half before UPnP was
/// even tried — and the receiver's address was not reported until then.
async fn forward_port_v4(local_addr: SocketAddr, lease: u32) -> (Option<PortForward>, Vec<String>) {
    let mut notes: Vec<String> = Vec::new();
    // An IPv6 socket reaches IPv4 only when it is a dual-stack wildcard.
    let bind_ip = match crate::address::canonical(local_addr).ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) if v6.is_unspecified() => std::net::Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(_) => {
            notes.push("IPv4: this socket has no IPv4 address to forward".to_string());
            return (None, notes);
        }
    };
    let ip = bind_ip;
    // A socket bound to one address knows which one to claim; a wildcard
    // one has to try each interface it could be reached on.
    let clients = if ip.is_unspecified() {
        local_ipv4_addresses()
    } else {
        vec![ip]
    };
    let mut attempts = tokio::task::JoinSet::new();
    // The routers, and where a carrier's PCP server answers (RFC 7723).
    let routers = portmap::gateway_candidates()
        .into_iter()
        .chain(std::iter::once(portmap::PCP_ANYCAST));
    for gw in routers {
        let router = SocketAddr::new(IpAddr::V4(gw), portmap::PORT);
        for &client in &clients {
            let port = local_addr.port();
            attempts.spawn(async move {
                (
                    router,
                    portmap::request_at(router, client, port, lease).await,
                )
            });
        }
    }
    let mut found = None;
    while let Some(r) = attempts.join_next().await {
        match r {
            Ok((router, Ok(m))) => {
                notes.push(format!(
                    "IPv4: {} at {} granted external port {}",
                    m.protocol().name(),
                    router,
                    m.external_port()
                ));
                found = Some(m);
                break;
            }
            Ok((router, Err(e))) => {
                tracing::debug!("NAT: {}", e);
                let note = if portmap::is_pcp_anycast(router.ip()) {
                    format!("IPv4: PCP at the anycast address {}: {}", router.ip(), e)
                } else {
                    format!("IPv4: PCP and NAT-PMP at {}: {}", router.ip(), e)
                };
                if !notes.contains(&note) && notes.len() < 6 {
                    notes.push(note);
                }
            }
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
                    if let Ok((_, Ok(extra))) = r {
                        let _ = extra.remove().await;
                    }
                }
            });
        }
        return (Some(PortForward::Modern(m)), notes);
    }
    let bind = (!ip.is_unspecified()).then_some(ip);
    match UpnpMapping::create(local_addr.port(), bind, lease, "SHARP-256 receiver").await {
        Ok(m) => {
            notes.push(format!(
                "IPv4: UPnP-IGD granted external port {}",
                m.external_port()
            ));
            (Some(PortForward::Upnp(m)), notes)
        }
        Err(e) => {
            tracing::debug!("NAT: {}", e);
            notes.push(format!("IPv4: UPnP-IGD: {}", e));
            (None, notes)
        }
    }
}

/// The IPv6 half: no address is translated over IPv6, but a router's
/// firewall drops what nobody inside asked for, and PCP (RFC 6887) and UPnP
/// IGD v2 both let a host ask it to let a port in.
async fn forward_port_v6(local_addr: SocketAddr, lease: u32) -> (Option<PortForward>, Vec<String>) {
    let mut notes: Vec<String> = Vec::new();
    if !local_addr.is_ipv6() {
        return (None, notes);
    }
    let clients: Vec<std::net::Ipv6Addr> = host_addresses(local_addr, false)
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V6(v6) => Some(v6),
            IpAddr::V4(_) => None,
        })
        .take(2)
        .collect();
    if clients.is_empty() {
        notes.push("IPv6: no global address to ask a firewall to open for".to_string());
        return (None, notes);
    }
    let port = local_addr.port();
    let mut attempts = tokio::task::JoinSet::new();
    let anycast = SocketAddr::new(IpAddr::V6(portmap::PCP_ANYCAST_V6), portmap::PORT);
    let routers = portmap::gateway_candidates_v6().await;
    for router in routers.into_iter().chain(std::iter::once(anycast)) {
        for &client in &clients {
            attempts.spawn(async move {
                (
                    router,
                    portmap::request_v6_at(router, client, port, lease).await,
                )
            });
        }
    }
    let mut found = None;
    while let Some(r) = attempts.join_next().await {
        match r {
            Ok((router, Ok(m))) => {
                notes.push(format!(
                    "IPv6: PCP at {} opened its firewall to {}",
                    router.ip(),
                    m.internal()
                ));
                found = Some(m);
                break;
            }
            Ok((router, Err(e))) => {
                tracing::debug!("NAT: {}", e);
                let anycast = if portmap::is_pcp_anycast(router.ip()) {
                    "the anycast address "
                } else {
                    ""
                };
                let note = format!("IPv6: PCP at {}{}: {}", anycast, router.ip(), e);
                if !notes.contains(&note) && notes.len() < 4 {
                    notes.push(note);
                }
            }
            Err(_) => {}
        }
    }
    if let Some(m) = found {
        if !attempts.is_empty() {
            tokio::spawn(async move {
                while let Some(r) = attempts.join_next().await {
                    if let Ok((_, Ok(extra))) = r {
                        let _ = extra.remove().await;
                    }
                }
            });
        }
        return (Some(PortForward::Modern(m)), notes);
    }
    match upnp::UpnpPinhole::create(&clients, port, lease).await {
        Ok(p) => {
            notes.push(format!(
                "IPv6: UPnP-IGD opened its firewall to {}",
                p.external_addr()
            ));
            (Some(PortForward::Pinhole(p)), notes)
        }
        Err(e) => {
            tracing::debug!("NAT: {}", e);
            notes.push(format!("IPv6: UPnP-IGD: {}", e));
            (None, notes)
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
pub(crate) fn host_addresses(local: SocketAddr, lan: bool) -> Vec<IpAddr> {
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

/// Where to aim over IPv6 when nothing has been measured: the host's own
/// global address — the one the system prefers for a global destination
/// comes first — at the socket's port. With no NAT in the way there is
/// nothing to measure, and a peer can be told at once.
fn aim6_from_host(host: &[IpAddr], port: u16) -> Option<SocketAddr> {
    host.iter()
        .find(|ip| ip.is_ipv6() && crate::address::class::is_global(**ip))
        .map(|ip| SocketAddr::new(*ip, port))
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
pub(crate) struct V6State {
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
    not(any(target_os = "linux", target_os = "android", test, fuzzing)),
    allow(dead_code)
)]
pub(crate) fn parse_if_inet6(text: &str) -> std::collections::HashMap<std::net::Ipv6Addr, V6State> {
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
    /// An address on a TURN server that reaches us (see [`turn`]): slower
    /// and somebody else's bandwidth, but it needs nothing of our NAT.
    Relayed,
}

impl CandidateKind {
    pub fn name(self) -> &'static str {
        match self {
            CandidateKind::Host => "host",
            CandidateKind::ServerReflexive => "seen from outside",
            CandidateKind::PortForward => "port forward",
            CandidateKind::Relayed => "relayed",
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
    /// What the NAT in front of this socket actually does (RFC 5780): over
    /// IPv4 where the socket speaks it, since that is where the NATs are.
    pub behaviour: Behaviour,
    /// The same measured over IPv6, on a dual-stack socket whose host has a
    /// global IPv6 address: usually no NAT, and what shows is the firewall.
    pub behaviour6: Option<Behaviour>,
    pub upnp_addr: Option<SocketAddr>,
    /// The address the router's IPv6 firewall was opened to (PCP or UPnP):
    /// this host's own, on the port.
    pub pinhole6: Option<SocketAddr>,
    /// What each forward or firewall opening obtained is, in words.
    pub forwards: Vec<String>,
    /// What came of each protocol asked for one, in words.
    pub mapping_notes: Vec<String>,
    /// The router forwarded a port, but reports an inside address as its
    /// own: it is behind another NAT, and the forward does not reach it
    /// from the internet.
    pub double_nat: bool,
    /// This host's own addresses worth publishing, best first (see
    /// `host_addresses`).
    pub host: Vec<IpAddr>,
    /// Addresses on TURN servers that reach this host. Not found by
    /// discovery: whoever runs the allocations puts them here.
    pub relayed: Vec<SocketAddr>,
}

impl Reachability {
    /// The reachability of a host that has looked at nothing: for the one
    /// that is to be reached through a TURN server alone.
    pub fn bare(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            public_addr: None,
            behaviour: Behaviour::default(),
            behaviour6: None,
            upnp_addr: None,
            pinhole6: None,
            forwards: Vec::new(),
            mapping_notes: Vec::new(),
            double_nat: false,
            host: Vec::new(),
            relayed: Vec::new(),
        }
    }

    /// What is known of the NAT or firewall in front of each family, in the
    /// form a peer is told: over a relay, or in a contact card.
    pub fn hints(&self) -> card::FamilyHints {
        let primary_v6 = self
            .behaviour
            .tested_with
            .is_some_and(|a| crate::address::canonical(a).is_ipv6());
        let mut first = card::NatHints::from(&self.behaviour);
        if !primary_v6 {
            // Behind a carrier's NAT as well as the router's: the shared
            // address space, or a router that itself has an inside address.
            first.cgn = self.double_nat
                || matches!(
                    self.behaviour.mapped.map(|m| crate::address::canonical(m).ip()),
                    Some(IpAddr::V4(v4)) if is_shared_address_space(v4)
                );
        }
        let mut second = self.behaviour6.as_ref().map(card::NatHints::from);
        // A pinhole lets anyone in at the port, which is what an
        // endpoint-independent filter does.
        if self.pinhole6.is_some() {
            let mut h = second.unwrap_or_else(card::NatHints::unknown);
            h.mapping = 4;
            h.filtering = 1;
            second = Some(h);
        }
        let (v4, v6) = if primary_v6 {
            (card::NatHints::unknown(), first)
        } else {
            (first, second.unwrap_or_else(card::NatHints::unknown))
        };
        card::FamilyHints {
            v4,
            v6,
            aim4: self.aim4(),
            aim6: self.aim6(),
        }
    }

    /// Where a peer should aim over IPv4: the address a router forwards to
    /// us, or else the one the internet sees the socket at. Only an address
    /// the internet routes counts — a private one is what a peer on our own
    /// network already knows, and a stranger has no use for it.
    fn aim4(&self) -> Option<SocketAddr> {
        self.upnp_addr
            .or(self.public_addr)
            .filter(|a| a.port() != 0 && crate::address::class::is_global(a.ip()))
            .filter(|a| crate::address::canonical(*a).is_ipv4())
    }

    /// Where a peer should aim over IPv6: an opening the router made for us
    /// if there is one, else the address the internet sees the socket at (the
    /// STUN answer, which is right even where a prefix is translated), else
    /// one of the host's own global addresses at the socket's port.
    fn aim6(&self) -> Option<SocketAddr> {
        self.pinhole6
            .or_else(|| self.behaviour6.as_ref().and_then(|b| b.mapped))
            .or_else(|| aim6_from_host(&self.host, self.local_addr.port()))
            .filter(|a| a.port() != 0 && crate::address::class::is_global(a.ip()))
            .filter(|a| crate::address::canonical(*a).is_ipv6())
    }

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
        if let Some(a) = self.pinhole6 {
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
        // Somebody else's bandwidth, so last — but never left out for lack
        // of room: with the others failing, it is what a sender has.
        for a in &self.relayed {
            if !out.iter().any(|c| c.addr == *a) {
                out.push(Candidate {
                    addr: *a,
                    kind: CandidateKind::Relayed,
                });
            }
        }
        out
    }

    /// The contact card of a host with this reachability: everything a
    /// peer on another network needs to start sending at us at the same
    /// moment we start sending at it (see [`card`]).
    ///
    /// Unlike [`Reachability::candidates`], which keeps back an address that
    /// would tell a stranger nothing, the card lists the address a STUN
    /// server saw even behind a NAT that numbers ports per destination: it
    /// is the base from which the peer works out the port to aim at, and the
    /// hints say how.
    pub fn card(
        &self,
        id: &crate::crypto::SharpId,
        role: card::Role,
        relays: &[card::RelayRef],
    ) -> card::Card {
        use card::{Candidate as Cand, Kind};
        let mut c = card::Card::new(role, *id);
        let port = self.local_addr.port();
        let mut add = |addr: SocketAddr, kind: Kind| {
            if addr.port() != 0
                && !addr.ip().is_unspecified()
                && c.candidates.len() < card::MAX_CANDIDATES
                && !c.candidates.iter().any(|x| x.addr == addr)
            {
                c.candidates.push(Cand { kind, addr });
            }
        };
        if let Some(a) = self.upnp_addr {
            add(a, Kind::PortMapped);
        }
        if let Some(a) = self.pinhole6 {
            add(a, Kind::PortMapped);
        }
        // Global IPv6 first: no NAT to get through, so where the peer has
        // it too it is the shortest way.
        if let Some(m) = self.behaviour6.and_then(|b| b.mapped) {
            add(m, Kind::Mapped);
        }
        for ip in self.host.iter().filter(|ip| ip.is_ipv6()) {
            add(SocketAddr::new(*ip, port), Kind::Host);
        }
        if let Some(p) = self.public_addr {
            add(p, Kind::Mapped);
        }
        for ip in self.host.iter().filter(|ip| ip.is_ipv4()) {
            add(SocketAddr::new(*ip, port), Kind::Host);
        }
        for a in &self.relayed {
            add(*a, Kind::Relayed);
        }
        let hints = self.hints();
        c.v4 = (hints.v4.mapping != 0).then_some(hints.v4);
        c.v6 = (hints.v6.mapping != 0).then_some(hints.v6);
        c.relays = relays.iter().take(card::MAX_RELAYS).copied().collect();
        c
    }

    /// The candidates as a sender writes them: `ID@host:port,host:port,…`.
    ///
    /// Behind a NAT whose mapping changes with the destination the address a
    /// STUN server saw is no candidate — it is where *that server* reaches us
    /// — but it is what a sender who was told nothing else needs: its IP is
    /// where our punches will come from, which is how the sender knows them
    /// for ours, and its port is the base the sender predicts ours from. So
    /// it ends the line, after every address that could work (with a card
    /// the same is said, and better: see [`Reachability::card`]).
    ///
    /// An address on a TURN server is left out: written as a bare `IP:PORT`
    /// nothing says it is one, and a sender that punches at the addresses it
    /// was given, as one asked for its own does, would spray somebody else's
    /// server with guessed ports. A card says what each address is.
    pub fn address_string(&self, id: &crate::crypto::SharpId) -> Option<String> {
        let candidates = self.candidates();
        let mut list: Vec<String> = candidates
            .iter()
            .filter(|c| c.kind != CandidateKind::Relayed)
            .map(|c| c.addr.to_string())
            .collect();
        if let Some(p) = self.public_addr {
            if !candidates.iter().any(|c| c.addr == p) && list.len() < MAX_CANDIDATES {
                list.push(p.to_string());
            }
        }
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
        if let (Some(a), None) = (self.pinhole6, self.upnp_addr) {
            return format!(
                "reachable over IPv6 at {} (the router's firewall was opened to it)",
                a
            );
        }
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
            (Some(p), Reachable::OnlyByRelay) => {
                let how = match self.behaviour.allocation {
                    Allocation::Sequential => {
                        "a sender behind a simple NAT can still aim at the ports it hands out \
                         next"
                    }
                    Allocation::Random => {
                        "a sender behind a simple NAT can still find it by trying very many ports"
                    }
                    _ => "a sender behind a simple NAT may still get through by trying ports",
                };
                format!(
                    "behind a symmetric NAT (seen at {} right now, but the port changes per \
                     destination): {}; against another symmetric NAT it needs a relay, or a \
                     port forward to local port {}",
                    p,
                    how,
                    self.local_addr.port()
                )
            }
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

/// Whether `ip` is in 100.64.0.0/10, the address space carriers give their
/// customers behind a carrier-grade NAT (RFC 6598).
fn is_shared_address_space(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..128).contains(&o[1])
}

/// What discovery has found so far.
fn reachability(
    local_addr: SocketAddr,
    behaviour: &Behaviour,
    behaviour6: Option<&Behaviour>,
    forwards: &Forwards,
    publish_lan: bool,
) -> Reachability {
    let public_addr = behaviour.mapped;
    let (upnp_addr, double_nat) = match forwards.granted.iter().find(|f| f.is_v4()) {
        Some(f) => forward_address(f, public_addr),
        None => (None, false),
    };
    let pinhole6 = forwards
        .granted
        .iter()
        .find(|f| !f.is_v4())
        .and_then(|f| f.external_addr());
    Reachability {
        local_addr,
        public_addr,
        behaviour: *behaviour,
        behaviour6: behaviour6.copied(),
        upnp_addr,
        pinhole6,
        forwards: forwards.granted.iter().map(PortForward::describe).collect(),
        mapping_notes: forwards.notes.clone(),
        double_nat,
        host: host_addresses(local_addr, publish_lan),
        relayed: Vec::new(),
    }
}

/// Reports what discovery found together with what the TURN allocations
/// have given, and again whenever either changes: an allocation is made
/// while the NAT tests run, and finishes before or after them.
pub struct RelayedReports {
    local: SocketAddr,
    turns: Vec<turn::Turn>,
    /// Whether a discovery is running, whose result is still to come.
    discovering: bool,
    latest: parking_lot::Mutex<Option<Reachability>>,
    report: Box<dyn Fn(&Reachability) + Send + Sync>,
}

impl RelayedReports {
    /// `report` is called with each new state. Nothing is reported until
    /// there is something to say: a discovery result, or — where none is
    /// coming (`discovering` is false) — an address on a TURN server. A
    /// card handed out before the tests are done would be one with the
    /// server's address alone, and the person who copies the first card
    /// they see would be handing over the poorer one.
    pub fn new(
        local: SocketAddr,
        turns: Vec<turn::Turn>,
        cancel: CancellationToken,
        discovering: bool,
        report: impl Fn(&Reachability) + Send + Sync + 'static,
    ) -> Arc<Self> {
        let this = Arc::new(Self {
            local,
            turns,
            discovering,
            latest: parking_lot::Mutex::new(None),
            report: Box::new(report),
        });
        for t in &this.turns {
            let (mut changes, this, cancel) = (t.subscribe(), this.clone(), cancel.clone());
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        c = changes.changed() => if c.is_err() { return },
                        _ = cancel.cancelled() => return,
                    }
                    this.emit(None);
                }
            });
        }
        this
    }

    /// A discovery result.
    pub fn update(&self, r: &Reachability) {
        self.emit(Some(r.clone()));
    }

    fn emit(&self, found: Option<Reachability>) {
        let relayed: Vec<SocketAddr> = self.turns.iter().flat_map(|t| t.relayed()).collect();
        let mut latest = self.latest.lock();
        if let Some(r) = found {
            *latest = Some(r);
        }
        // Without a discovery result an address on a server is worth telling
        // only if there is no discovery to wait for.
        let mut r = match latest.clone() {
            Some(r) => r,
            None if !relayed.is_empty() && !self.discovering => Reachability::bare(self.local),
            None => return,
        };
        drop(latest);
        r.relayed = relayed;
        (self.report)(&r);
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

/// Starts NAT discovery for the receiver's socket in the background, and
/// keeps what it found true for as long as the receiver runs.
///
/// The address tests and the port-forward request run side by side, and
/// what they find is reported through `on_result` as it comes: first when
/// the tests are done, again if a port forward is granted after that. A
/// router that is slow to answer, or never does, no longer holds up telling
/// the user where the receiver can be reached.
///
/// After that the task maintains it all (see `maintain`): the NAT mapping
/// a published address rests on is kept alive and checked, its lifetime
/// measured where the server allows, this host's own addresses looked at
/// again now and then, and a port forward renewed — each change reported
/// through `on_result` again. A port forward is given back when `cancel`
/// fires, so the router does not keep forwarding a port nothing listens on.
/// Returns `None` for loopback sockets, where there is nothing to discover.
pub fn spawn_discovery(
    socket: Arc<UdpSocket>,
    config: NatConfig,
    keepalive: keepalive::SharedKeepalive,
    hints: tokio::sync::watch::Sender<card::FamilyHints>,
    cancel: CancellationToken,
    on_result: impl Fn(&Reachability) + Send + 'static,
) -> Option<NatTask> {
    let local = socket.local_addr().ok()?;
    if crate::address::canonical(local).ip().is_loopback() {
        return None;
    }
    let (tx, rx) = mpsc::channel::<stun::Incoming>(64);
    // What is found is passed to whoever follows `hints` as it is found,
    // and every result that is reported says it again.
    let hints = Arc::new(hints);
    let on_result = {
        let hints = hints.clone();
        move |r: &Reachability| {
            publish_hints(&hints, r.hints());
            on_result(r)
        }
    };
    let task = tokio::spawn(async move {
        // Owns the channel the STUN messages come in on, and lets go of it
        // when done: the dispatcher then stops handing us any.
        let (tests_socket, servers, enable_stun) = (
            socket.clone(),
            config.stun_servers.clone(),
            config.enable_stun,
        );
        let early = hints.clone();
        // Over IPv6 there is usually no NAT to measure, and a peer can be
        // told where to aim before any test is done — which is when a
        // sender asking a relay for an introduction wants it.
        if let Some(aim) = aim6_from_host(&host_addresses(local, false), local.port()) {
            hints.send_if_modified(|h| {
                let changed = h.aim6.is_none();
                h.aim6.get_or_insert(aim);
                changed
            });
        }
        let tests = async move {
            let mut rx = rx;
            let (b, b6) = if enable_stun {
                discover_families(&tests_socket, &servers, &mut rx, local, &mut |b| {
                    let found = card::NatHints::from(b);
                    let six = b
                        .tested_with
                        .is_some_and(|a| crate::address::canonical(a).is_ipv6());
                    // The address the server saw is where a peer is to
                    // aim, as far as anything is yet known of it.
                    let seen = b
                        .mapped
                        .filter(|a| crate::address::class::is_global(a.ip()));
                    early.send_if_modified(|h| {
                        let (slot, aim) = if six {
                            (&mut h.v6, &mut h.aim6)
                        } else {
                            (&mut h.v4, &mut h.aim4)
                        };
                        let changed = *slot != found || (seen.is_some() && *aim != seen);
                        *slot = found;
                        if seen.is_some() {
                            *aim = seen;
                        }
                        changed
                    });
                })
                .await
            } else {
                (Behaviour::default(), None)
            };
            (b, b6, rx)
        };
        let (enable_mapping, lease) = (config.enable_port_mapping, config.mapping_lease);
        let mapping = async move {
            if enable_mapping {
                forward_ports(local, lease).await
            } else {
                Forwards::default()
            }
        };
        tokio::pin!(tests, mapping);
        let mut behaviour: Option<Behaviour> = None;
        let mut behaviour6: Option<Behaviour> = None;
        let mut responses: Option<mpsc::Receiver<stun::Incoming>> = None;
        let mut forward: Option<Forwards> = None;
        let none = Forwards::default();
        while behaviour.is_none() || forward.is_none() {
            tokio::select! {
                (b, b6, rx) = &mut tests, if behaviour.is_none() => {
                    let r = reachability(
                        local,
                        &b,
                        b6.as_ref(),
                        forward.as_ref().unwrap_or(&none),
                        config.publish_lan_addresses,
                    );
                    tracing::info!("NAT: {}", r.describe());
                    if let Some(b6) = &b6 {
                        tracing::info!("NAT over IPv6: {}", b6.describe());
                    }
                    on_result(&r);
                    behaviour = Some(b);
                    behaviour6 = b6;
                    responses = Some(rx);
                }
                f = &mut mapping, if forward.is_none() => {
                    for granted in &f.granted {
                        tracing::info!("NAT: {}", granted.describe());
                    }
                    // Worth saying again only once there is something to
                    // say it with.
                    if let Some(b) = &behaviour {
                        if !f.granted.is_empty() {
                            let r = reachability(
                                local,
                                b,
                                behaviour6.as_ref(),
                                &f,
                                config.publish_lan_addresses,
                            );
                            tracing::info!("NAT: {}", r.describe());
                            on_result(&r);
                        }
                    }
                    forward = Some(f);
                }
                _ = cancel.cancelled() => {
                    if let Some(f) = forward {
                        for m in f.granted {
                            let _ = tokio::time::timeout(Duration::from_secs(3), m.remove()).await;
                        }
                    }
                    return;
                }
            }
        }
        let (Some(behaviour), Some(responses), Some(forward)) = (behaviour, responses, forward)
        else {
            return;
        };
        if !config.maintain {
            // Once is what was asked for. Letting go of the channel tells
            // whoever routes STUN messages here to stop.
            drop(responses);
            return;
        }
        maintain(Maintained {
            socket,
            config,
            local,
            behaviour,
            behaviour6,
            forward,
            responses,
            keepalive,
            cancel,
            on_result,
        })
        .await;
    });
    Some(NatTask {
        stun_responses: tx,
        task,
    })
}

/// The tests of both families on `socket`: the one it speaks first (IPv4,
/// where it speaks both — that is where the NATs are), with `progress`
/// told as it goes; then IPv6, where the host has a global address in it,
/// and what is measured there is the firewall.
async fn discover_families(
    socket: &UdpSocket,
    servers: &[String],
    rx: &mut mpsc::Receiver<stun::Incoming>,
    local: SocketAddr,
    progress: &mut (dyn FnMut(&Behaviour) + Send),
) -> (Behaviour, Option<Behaviour>) {
    let b =
        behaviour::discover_reporting(socket, servers, rx, behaviour::Timing::default(), progress)
            .await;
    tracing::debug!("NAT: {}", b.describe());
    let reach = crate::address::Reach::of(socket);
    let has_global_v6 = host_addresses(local, false).iter().any(IpAddr::is_ipv6);
    let mut b6 = None;
    if reach.v4() && reach.v6() && has_global_v6 {
        let six = behaviour::discover_family(
            socket,
            servers,
            rx,
            behaviour::Timing::default(),
            Some(true),
            &mut |_| {},
        )
        .await;
        if six.mapped.is_some() {
            tracing::debug!("NAT (IPv6): {}", six.describe());
            b6 = Some(six);
        }
    }
    (b, b6)
}

/// Tells whoever follows `hints` what the NAT tests have found, when that
/// is news.
fn publish_hints(hints: &tokio::sync::watch::Sender<card::FamilyHints>, found: card::FamilyHints) {
    hints.send_if_modified(|current| {
        let changed = *current != found;
        *current = found;
        changed
    });
}

/// How often the mapping behind a published address is checked with a
/// request (the keepalives in between are indications, which a server
/// takes in without answering, and which tell us nothing back).
const MAPPING_CHECK: Duration = Duration::from_secs(60);
/// How often this host's own addresses are looked at again: interfaces
/// come and go, and a temporary IPv6 address is replaced every day or so.
const HOST_REFRESH: Duration = Duration::from_secs(300);

/// A first round of tests that found nothing is run again this long after,
/// and then twice as long each time, up to [`REDISCOVER_CEILING`]: no STUN
/// server answering at start-up may only mean that the network was not
/// there yet (a laptop just woken, a link still coming up), and a receiver
/// that runs for hours should not stay without an outside address for it.
const REDISCOVER: Duration = Duration::from_secs(5);
pub const REDISCOVER_CEILING: Duration = Duration::from_secs(300);

/// What [`maintain`] looks after.
struct Maintained<F> {
    socket: Arc<UdpSocket>,
    config: NatConfig,
    local: SocketAddr,
    behaviour: Behaviour,
    behaviour6: Option<Behaviour>,
    forward: Forwards,
    responses: mpsc::Receiver<stun::Incoming>,
    keepalive: keepalive::SharedKeepalive,
    cancel: CancellationToken,
    on_result: F,
}

/// Keeps what discovery found true until `cancel` fires, then gives the
/// port forward back.
///
/// * The NAT mapping a published address rests on — the address a STUN
///   server sees us at, when the mapping is stable enough to publish — is
///   kept alive with a STUN indication at the keepalive interval (RFC 8445
///   section 11), and checked with a request every [`MAPPING_CHECK`]. A
///   mapping that changed anyway is reported, and the interval shortened.
/// * Where the server has shown itself an RFC 5780 one, how long the NAT
///   keeps an idle mapping is measured in the background (RFC 5780 section
///   4.6) and sets the interval.
/// * This host's own addresses are looked at again every [`HOST_REFRESH`].
/// * A port forward is renewed at half its lease.
/// * Tests that found nothing at all are run again, after
///   [`NatConfig::rediscover`] and then less and less often.
async fn maintain<F: Fn(&Reachability)>(m: Maintained<F>) {
    let Maintained {
        socket,
        config,
        local,
        mut behaviour,
        mut behaviour6,
        forward,
        mut responses,
        keepalive,
        cancel,
        on_result,
    } = m;
    let lan = config.publish_lan_addresses;
    let mut current = reachability(local, &behaviour, behaviour6.as_ref(), &forward, lan);
    let mut server = behaviour.tested_with;
    // Worth keeping only when an address resting on the mapping is
    // published: a NAT that changes the port per destination gets nothing
    // published, and no NAT at all needs nothing kept.
    let rests_on_mapping = |b: &Behaviour| {
        b.mapped.is_some()
            && !b.open_internet
            && matches!(
                b.reachable(),
                Reachable::OncePublished | Reachable::ByPunching
            )
    };
    let now = Instant::now();
    let mut next_keepalive = now + keepalive.lock().next();
    let mut next_check = now + config.mapping_check;
    let mut next_host = now + config.host_refresh;
    // Renew at half the lease, so one lost renewal is not fatal. The floor
    // is small on purpose: a router may grant far less than was asked for —
    // PCP explicitly allows it, and they do it under pressure — and a floor
    // of half a minute would have left a thirty-second grant dead for half
    // of every cycle.
    let renew_every = forward
        .granted
        .iter()
        .map(|f| f.lifetime())
        .filter(|&l| l > 0)
        .min()
        .map(|l| Duration::from_secs((l as u64 / 2).max(5)));
    let mut next_renewal = renew_every.map(|e| now + e);
    // How long an idle mapping lasts, measured in the background where the
    // server can tell (RFC 5780).
    let measure_lifetime = |server: Option<SocketAddr>, b: &Behaviour| match server {
        Some(server) if b.rfc5780 && rests_on_mapping(b) => {
            let bind_ip: IpAddr = if crate::address::canonical(server).is_ipv6() {
                std::net::Ipv6Addr::UNSPECIFIED.into()
            } else {
                std::net::Ipv4Addr::UNSPECIFIED.into()
            };
            Some(tokio::spawn(behaviour::binding_lifetime(
                bind_ip,
                server,
                &behaviour::LIFETIME_PROBES,
                Duration::from_millis(500),
            )))
        }
        _ => None,
    };
    let mut lifetime = measure_lifetime(server, &behaviour);
    // Nothing measured in either family: tried again, less and less often,
    // until something is.
    let unmeasured = |b: &Behaviour, b6: &Option<Behaviour>| {
        b.mapped.is_none() && b6.as_ref().is_none_or(|b| b.mapped.is_none())
    };
    let mut rediscover_every = config.rediscover;
    let mut next_rediscovery = (config.enable_stun
        && !config.stun_servers.is_empty()
        && unmeasured(&behaviour, &behaviour6))
    .then(|| now + rediscover_every);
    let client = stun::StunClient::new(Vec::new()).with_timing(Duration::from_millis(500), 2);
    let at = |i: Instant| tokio::time::sleep_until(tokio::time::Instant::from_std(i));
    loop {
        let keeping = server.filter(|_| rests_on_mapping(&behaviour));
        tokio::select! {
            _ = at(next_keepalive), if keeping.is_some() => {
                let server = keeping.expect("guarded");
                let _ = socket
                    .send_to(&stun::binding_indication(&stun::transaction_id()), server)
                    .await;
                next_keepalive = Instant::now() + keepalive.lock().next();
            }
            _ = at(next_check), if keeping.is_some() => {
                let server = keeping.expect("guarded");
                // Bounded, and interruptible like everything else here.
                let reply = tokio::select! {
                    r = client.transaction(&socket, server, &mut responses, false, false) => r,
                    _ = cancel.cancelled() => break,
                };
                if let Ok(Some(reply)) = reply {
                    let seen = reply.response.mapped;
                    if behaviour.mapped != Some(seen) {
                        let shorter = keepalive.lock().mapping_changed();
                        // The mapping is new: keep it from the start, by
                        // the new interval.
                        if shorter {
                            next_keepalive = Instant::now();
                        }
                        tracing::info!(
                            "NAT: the address we are seen at changed ({} -> {}){}",
                            behaviour
                                .mapped
                                .map(|a| a.to_string())
                                .unwrap_or_else(|| "none".into()),
                            seen,
                            if shorter {
                                format!(
                                    "; keeping the mapping alive every {:?} from now on",
                                    keepalive.lock().interval()
                                )
                            } else {
                                String::new()
                            }
                        );
                        behaviour.mapped = Some(seen);
                        current = reachability(local, &behaviour, behaviour6.as_ref(), &forward, lan);
                        on_result(&current);
                    }
                }
                next_check = Instant::now() + config.mapping_check;
            }
            _ = at(next_rediscovery.unwrap_or(next_host)), if next_rediscovery.is_some() => {
                let mut quietly = |_: &Behaviour| {};
                let (b, b6) = tokio::select! {
                    found = discover_families(
                        &socket,
                        &config.stun_servers,
                        &mut responses,
                        local,
                        &mut quietly,
                    ) => found,
                    _ = cancel.cancelled() => break,
                };
                if unmeasured(&b, &b6) {
                    rediscover_every = (rediscover_every * 2).min(REDISCOVER_CEILING);
                    next_rediscovery = Some(Instant::now() + rediscover_every);
                    tracing::debug!(
                        "NAT: still no STUN server answers; asking again in {:?}",
                        rediscover_every
                    );
                } else {
                    behaviour = b;
                    behaviour6 = b6;
                    server = behaviour.tested_with;
                    next_rediscovery = None;
                    lifetime = measure_lifetime(server, &behaviour);
                    next_keepalive = Instant::now() + keepalive.lock().next();
                    next_check = Instant::now() + config.mapping_check;
                    current = reachability(local, &behaviour, behaviour6.as_ref(), &forward, lan);
                    tracing::info!("NAT: a STUN server answers now: {}", current.describe());
                    if let Some(b6) = &behaviour6 {
                        tracing::info!("NAT over IPv6: {}", b6.describe());
                    }
                    on_result(&current);
                }
            }
            _ = at(next_host) => {
                let fresh = reachability(local, &behaviour, behaviour6.as_ref(), &forward, lan);
                if fresh.candidates() != current.candidates() {
                    tracing::info!("NAT: this host's addresses changed");
                    current = fresh;
                    on_result(&current);
                }
                next_host = Instant::now() + config.host_refresh;
            }
            _ = at(next_renewal.unwrap_or(next_host)), if next_renewal.is_some() => {
                for f in &forward.granted {
                    // Bounded, and interruptible: a router that stops
                    // answering must not keep the receiver from shutting
                    // down.
                    tokio::select! {
                        r = tokio::time::timeout(
                            Duration::from_secs(10),
                            f.refresh(config.mapping_lease),
                        ) => match r {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => tracing::warn!("NAT: {}", e),
                            Err(_) => tracing::warn!("NAT: the router did not answer the renewal"),
                        },
                        _ = cancel.cancelled() => break,
                    }
                }
                next_renewal = renew_every.map(|e| Instant::now() + e);
            }
            r = async { lifetime.as_mut().expect("guarded").await }, if lifetime.is_some() => {
                lifetime = None;
                match r {
                    Ok(Some(l)) => {
                        let mut k = keepalive.lock();
                        let before = k.interval();
                        k.lifetime_measured(l);
                        // A keepalive planned by the old interval may come
                        // after the NAT has forgotten: one now, and the new
                        // interval from there.
                        if k.interval() < before {
                            next_keepalive = next_keepalive.min(Instant::now());
                        }
                        tracing::info!(
                            "NAT: an idle mapping lasts at least {:?} here; keeping ours alive \
                             every {:?}",
                            l,
                            k.interval()
                        );
                    }
                    _ => tracing::debug!("NAT: the mapping lifetime could not be measured"),
                }
            }
            _ = cancel.cancelled() => break,
        }
    }
    if let Some(task) = lifetime {
        task.abort();
    }
    for f in forward.granted {
        let how = f.protocol();
        match tokio::time::timeout(Duration::from_secs(3), f.remove()).await {
            Ok(Ok(())) => tracing::info!("NAT: {} port forward given back", how),
            Ok(Err(e)) => tracing::warn!("NAT: {}", e),
            Err(_) => tracing::warn!("NAT: the router did not answer the removal request"),
        }
    }
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
            behaviour6: None,
            upnp_addr: upnp.map(|u| u.parse().unwrap()),
            pinhole6: None,
            forwards: Vec::new(),
            mapping_notes: Vec::new(),
            double_nat: false,
            host: Vec::new(),
            relayed: Vec::new(),
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

    /// An address on a TURN server is no host's, and a bare `IP:PORT` cannot
    /// say so: it stays off the line a person copies (a card carries it).
    #[test]
    fn a_turn_address_is_not_on_the_line_a_person_copies() {
        let id = crate::crypto::Identity::generate().id();
        let mut r = reach(
            nat(Mapping::EndpointIndependent, Filtering::AddressDependent),
            None,
            Some("203.0.113.9:50000"),
        );
        r.relayed = vec!["198.51.100.20:49200".parse().unwrap()];
        assert!(r
            .candidates()
            .iter()
            .any(|c| c.kind == CandidateKind::Relayed));
        let text = r.address_string(&id).expect("an address to give");
        assert!(!text.contains("198.51.100.20"), "{}", text);
        let card = r.card(&id, card::Role::Receiver, &[]);
        assert!(card
            .candidates
            .iter()
            .any(|c| c.kind == card::Kind::Relayed));
        assert!(!card
            .outside_addrs()
            .contains(&"198.51.100.20:49200".parse().unwrap()));
    }

    /// What a person copies into the sender's command line still has to say
    /// where the punches will come from: the address the STUN server saw ends
    /// it, after everything that could work, and only where it is not a
    /// candidate already.
    #[test]
    fn a_symmetric_nats_address_ends_the_line_a_person_copies() {
        let id = crate::crypto::Identity::generate().id();
        let r = reach(
            nat(
                Mapping::AddressAndPortDependent,
                Filtering::AddressAndPortDependent,
            ),
            None,
            Some("203.0.113.9:50000"),
        );
        let text = r.address_string(&id).expect("an address to give");
        let (_, hosts) = crate::address::parse_peer(&text).expect("parses back");
        assert_eq!(hosts.last().unwrap(), "203.0.113.9:50000", "{}", text);
        assert_eq!(hosts.len(), r.candidates().len() + 1, "{}", text);
        // A stable mapping is a candidate already, and is said once.
        let r = reach(
            nat(Mapping::EndpointIndependent, Filtering::AddressDependent),
            None,
            Some("203.0.113.9:50000"),
        );
        let text = r.address_string(&id).expect("an address to give");
        let (_, hosts) = crate::address::parse_peer(&text).expect("parses back");
        assert_eq!(
            hosts.iter().filter(|h| *h == "203.0.113.9:50000").count(),
            1,
            "{}",
            text
        );
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
            None,
            &Forwards {
                granted: vec![inner("100.64.3.4")],
                notes: Vec::new(),
            },
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

    /// The mapping behind a published address is kept alive with STUN
    /// indications at the keepalive interval, checked with requests in
    /// between, and when it changes anyway the new address is reported at
    /// once and the keepalives come closer together.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_published_mapping_is_kept_alive_and_its_changes_reported() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let indications = Arc::new(AtomicU32::new(0));
        let requests = Arc::new(AtomicU32::new(0));
        let fake = {
            let (server, indications, requests) =
                (server.clone(), indications.clone(), requests.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                while let Ok((n, from)) = server.recv_from(&mut buf).await {
                    let pkt = &buf[..n];
                    if pkt.len() >= 20 && pkt[0..2] == [0x00, 0x11] {
                        indications.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if !stun::is_stun_request(pkt) {
                        continue;
                    }
                    let Some(tid) = stun::message_transaction_id(pkt) else {
                        continue;
                    };
                    // The NAT moves us to a new port from the second check on.
                    let port = if requests.fetch_add(1, Ordering::Relaxed) == 0 {
                        50000
                    } else {
                        50001
                    };
                    let mapped: SocketAddr = format!("203.0.113.9:{}", port).parse().unwrap();
                    let reply = stun::binding_success(&tid, mapped, Some(server_addr), None);
                    let _ = server.send_to(&reply, from).await;
                }
            })
        };
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (tx, rx) = mpsc::channel(64);
        let pump = {
            let socket = socket.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                    if stun::is_stun_message(&buf[..n]) {
                        let _ = tx.send((buf[..n].to_vec(), from)).await;
                    }
                }
            })
        };
        let behaviour = Behaviour {
            mapping: behaviour::Mapping::EndpointIndependent,
            filtering: behaviour::Filtering::EndpointIndependent,
            mapped: Some("203.0.113.9:50000".parse().unwrap()),
            tested_with: Some(server_addr),
            ..Behaviour::default()
        };
        let keepalive: keepalive::SharedKeepalive = Arc::new(parking_lot::Mutex::new(
            keepalive::Keepalive::new(Duration::from_millis(100)),
        ));
        let cancel = CancellationToken::new();
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
        let config = NatConfig {
            enable_port_mapping: false,
            mapping_check: Duration::from_millis(300),
            host_refresh: Duration::from_secs(3600),
            ..NatConfig::default()
        };
        let task = tokio::spawn(maintain(Maintained {
            socket: socket.clone(),
            config,
            local: socket.local_addr().unwrap(),
            behaviour,
            behaviour6: None,
            forward: Forwards::default(),
            responses: rx,
            keepalive: keepalive.clone(),
            cancel: cancel.clone(),
            on_result: move |r: &Reachability| {
                let _ = seen_tx.send(r.public_addr);
            },
        }));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("stops when cancelled")
            .unwrap();
        pump.abort();
        fake.abort();
        assert!(
            indications.load(Ordering::Relaxed) >= 5,
            "only {} keepalives in a second at 100 ms",
            indications.load(Ordering::Relaxed)
        );
        assert!(requests.load(Ordering::Relaxed) >= 2);
        assert_eq!(
            seen_rx.try_recv().ok(),
            Some(Some("203.0.113.9:50001".parse().unwrap())),
            "the new address was not reported"
        );
        assert_eq!(keepalive.lock().interval(), Duration::from_millis(50));
    }

    /// Tests that found nothing — no STUN server answered, as when the
    /// network was not there yet — are run again until something is found,
    /// which is then reported; and not again after that.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tests_that_found_nothing_are_run_again_until_they_find() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let requests = Arc::new(AtomicU32::new(0));
        let fake = {
            let (server, requests) = (server.clone(), requests.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                while let Ok((n, from)) = server.recv_from(&mut buf).await {
                    let pkt = &buf[..n];
                    if !stun::is_stun_request(pkt) {
                        continue;
                    }
                    let Some(tid) = stun::message_transaction_id(pkt) else {
                        continue;
                    };
                    // Silent for the first three: the whole first round of
                    // tests, and the first try of the next.
                    if requests.fetch_add(1, Ordering::Relaxed) < 3 {
                        continue;
                    }
                    let mapped: SocketAddr = "203.0.113.9:50000".parse().unwrap();
                    let reply = stun::binding_success(&tid, mapped, Some(server_addr), None);
                    let _ = server.send_to(&reply, from).await;
                }
            })
        };
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (tx, rx) = mpsc::channel(64);
        let pump = {
            let socket = socket.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                    if stun::is_stun_message(&buf[..n]) {
                        let _ = tx.send((buf[..n].to_vec(), from)).await;
                    }
                }
            })
        };
        let cancel = CancellationToken::new();
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
        let config = NatConfig {
            enable_port_mapping: false,
            stun_servers: vec![server_addr.to_string()],
            rediscover: Duration::from_millis(100),
            mapping_check: Duration::from_secs(3600),
            host_refresh: Duration::from_secs(3600),
            ..NatConfig::default()
        };
        let task = tokio::spawn(maintain(Maintained {
            socket: socket.clone(),
            config,
            local: socket.local_addr().unwrap(),
            // What the first tests found: nothing.
            behaviour: Behaviour::default(),
            behaviour6: None,
            forward: Forwards::default(),
            responses: rx,
            keepalive: Arc::new(parking_lot::Mutex::new(keepalive::Keepalive::new(
                Duration::from_secs(3600),
            ))),
            cancel: cancel.clone(),
            on_result: move |r: &Reachability| {
                let _ = seen_tx.send(r.public_addr);
            },
        }));
        let seen = tokio::time::timeout(Duration::from_secs(10), seen_rx.recv())
            .await
            .expect("the tests were not run again, or found nothing");
        assert_eq!(seen, Some(Some("203.0.113.9:50000".parse().unwrap())));
        let asked = requests.load(Ordering::Relaxed);
        assert_eq!(asked, 4, "three unanswered, then the one that was");
        // Found: no more asking (a mapping that changes nothing with the
        // destination is not known to be stable, so there is nothing to keep
        // alive either).
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(requests.load(Ordering::Relaxed), asked);
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("stops when cancelled")
            .unwrap();
        pump.abort();
        fake.abort();
    }

    /// A loopback socket has nothing to offer anyone else.
    fn id() -> crate::crypto::SharpId {
        crate::crypto::Identity::generate().id()
    }

    /// The card lists what a peer can send to, best first, and says what
    /// each family's NAT does: a symmetric NAT's address is on it too, as
    /// the base to aim from.
    #[test]
    fn the_card_lists_addresses_best_first_and_carries_what_the_nat_does() {
        let mut r = reach(
            Behaviour {
                mapped: Some("203.0.113.9:40000".parse().unwrap()),
                allocation: Allocation::Sequential,
                alloc_step: 2,
                ..nat(
                    Mapping::AddressAndPortDependent,
                    Filtering::AddressAndPortDependent,
                )
            },
            Some("203.0.113.9:5555"),
            Some("203.0.113.9:40000"),
        );
        r.host = vec![
            "2001:db8::5".parse().unwrap(),
            "192.168.1.5".parse().unwrap(),
        ];
        r.behaviour6 = Some(Behaviour {
            mapped: Some("[2001:db8::5]:5555".parse().unwrap()),
            open_internet: true,
            ..nat(
                Mapping::EndpointIndependent,
                Filtering::AddressAndPortDependent,
            )
        });
        let c = r.card(&id(), card::Role::Receiver, &[]);
        let addrs: Vec<String> = c.candidates.iter().map(|c| c.addr.to_string()).collect();
        assert_eq!(
            addrs,
            [
                "203.0.113.9:5555",
                "[2001:db8::5]:5555",
                "203.0.113.9:40000",
                "192.168.1.5:5555",
            ],
            "the router's forward, IPv6, the mapped address, the LAN"
        );
        let v4 = c.v4.expect("IPv4 hints");
        assert_eq!(v4.mapping, 3);
        assert_eq!(v4.allocation, Allocation::Sequential);
        assert_eq!(v4.delta, 2);
        assert_eq!(c.v6.expect("IPv6 hints").mapping, 4, "no translation");
        // And it survives being written down and read back.
        assert_eq!(card::Card::from_text(&c.to_text()).unwrap(), c);
    }

    /// A peer is told where to aim in each family: what a router forwards
    /// or opens for us first, then what the internet sees the socket at,
    /// then — over IPv6, where nothing has to be measured — the host's own
    /// address. Never an address the internet does not route.
    #[test]
    fn a_peer_is_told_where_to_aim_in_each_family() {
        let mut r = reach(
            Behaviour {
                mapped: Some("11.1.0.1:40000".parse().unwrap()),
                ..nat(Mapping::EndpointIndependent, Filtering::AddressDependent)
            },
            None,
            Some("11.1.0.1:40000"),
        );
        r.host = vec![
            "192.168.1.5".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "2a0e:aa00:1:1::5".parse().unwrap(),
        ];
        let aim = |r: &Reachability| (r.hints().aim4, r.hints().aim6);
        let a = |s: &str| Some(s.parse::<SocketAddr>().unwrap());
        // The socket is at port 5555; the host has no NAT over IPv6.
        assert_eq!(aim(&r), (a("11.1.0.1:40000"), a("[2a0e:aa00:1:1::5]:5555")));
        // A forward the router made outranks the mapped address.
        r.upnp_addr = a("11.1.0.1:5555");
        assert_eq!(aim(&r).0, a("11.1.0.1:5555"));
        // What the internet saw over IPv6 outranks the host's own address —
        // it is right where a prefix is translated — and a pinhole the
        // router opened outranks both.
        r.behaviour6 = Some(Behaviour {
            mapped: a("[2a0e:aa00:1:1::99]:5555"),
            ..nat(Mapping::EndpointIndependent, Filtering::AddressDependent)
        });
        assert_eq!(aim(&r).1, a("[2a0e:aa00:1:1::99]:5555"));
        r.pinhole6 = a("[2a0e:aa00:1:1::5]:6000");
        assert_eq!(aim(&r).1, a("[2a0e:aa00:1:1::5]:6000"));
        // Nothing the internet routes, nothing to say.
        let mut r = reach(
            Behaviour {
                mapped: Some("10.9.9.9:40000".parse().unwrap()),
                ..nat(Mapping::EndpointIndependent, Filtering::AddressDependent)
            },
            None,
            Some("10.9.9.9:40000"),
        );
        r.host = vec!["fd00::5".parse().unwrap(), "2001:db8::5".parse().unwrap()];
        assert_eq!(aim(&r), (None, None));
    }

    #[test]
    fn the_hosts_own_global_ipv6_address_is_where_to_aim_before_any_test() {
        let host: Vec<IpAddr> = vec![
            "192.168.1.2".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "fd00::2".parse().unwrap(),
            "2a0e:aa00:1:1::2".parse().unwrap(),
        ];
        assert_eq!(
            aim6_from_host(&host, 40000),
            Some("[2a0e:aa00:1:1::2]:40000".parse().unwrap())
        );
        assert_eq!(aim6_from_host(&host[..3], 40000), None);
    }

    #[test]
    fn a_carriers_address_space_is_a_carrier_grade_nat() {
        let behind = |ip: &str| {
            reach(
                Behaviour {
                    mapped: Some(format!("{}:40000", ip).parse().unwrap()),
                    ..nat(Mapping::EndpointIndependent, Filtering::AddressDependent)
                },
                None,
                Some(&format!("{}:40000", ip)),
            )
            .hints()
            .v4
            .cgn
        };
        assert!(behind("100.64.7.7"));
        assert!(behind("100.127.255.254"));
        assert!(!behind("100.128.0.1"));
        assert!(!behind("203.0.113.7"));
    }

    #[test]
    fn loopback_is_never_a_candidate() {
        let r = Reachability {
            local_addr: "127.0.0.1:5555".parse().unwrap(),
            public_addr: None,
            behaviour: Behaviour::default(),
            behaviour6: None,
            upnp_addr: None,
            pinhole6: None,
            forwards: Vec::new(),
            mapping_notes: Vec::new(),
            double_nat: false,
            host: host_addresses("127.0.0.1:5555".parse().unwrap(), true),
            relayed: Vec::new(),
        };
        assert!(r.candidates().is_empty());
        for ip in host_addresses("0.0.0.0:1".parse().unwrap(), true) {
            assert!(!ip.is_loopback());
        }
    }
}
