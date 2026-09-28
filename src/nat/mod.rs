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
