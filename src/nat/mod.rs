//! Optional NAT helpers for the receiver.
//!
//! * STUN tells which public address and port the receiver's transfer socket
//!   is seen under, so the user knows what to give to senders;
//! * UPnP asks the home router to forward a port to the receiver, which makes
//!   it reachable from outside without manual router configuration.
//!
//! Both run in a background task: the receiver serves transfers immediately,
//! and STUN responses are routed to the task by the receiver's dispatcher.
//!
//! The sender needs no NAT handling: its outgoing HELLO creates the mapping on
//! its own NAT and the receiver always answers to the address the datagrams
//! actually come from. Hole punching between two NATed peers would need a
//! rendezvous service and is not implemented.

pub mod behaviour;
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
    pub enable_upnp: bool,
    pub stun_servers: Vec<String>,
    /// UPnP lease in seconds; the mapping is renewed at half the lease.
    pub upnp_lease: u32,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enable_stun: true,
            enable_upnp: true,
            stun_servers: vec![
                "stun.l.google.com:19302".to_string(),
                "stun.cloudflare.com:3478".to_string(),
                "stun1.l.google.com:19302".to_string(),
            ],
            upnp_lease: 3600,
        }
    }
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
) -> (Reachability, Option<UpnpMapping>) {
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

    let mut mapping = None;
    if config.enable_upnp && !behaviour.open_internet {
        let bind_ip = match local_addr.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        };
        match UpnpMapping::create(
            local_addr.port(),
            bind_ip,
            config.upnp_lease,
            "SHARP-256 receiver",
        )
        .await
        {
            Ok(m) => {
                tracing::info!(
                    "NAT: UPnP forwards port {} to {} (lease {} s)",
                    m.external_port(),
                    m.local(),
                    m.lease()
                );
                mapping = Some(m);
            }
            Err(e) => tracing::debug!("NAT: {}", e),
        }
    }
    let upnp_addr = mapping
        .as_ref()
        .and_then(|m| m.external_addr())
        .or_else(|| {
            // Gateway did not report its IP: combine STUN's with the mapping.
            let m = mapping.as_ref()?;
            public_addr.map(|p| SocketAddr::new(p.ip(), m.external_port()))
        });
    (
        Reachability {
            local_addr,
            public_addr,
            behaviour,
            upnp_addr,
        },
        mapping,
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
/// result is reported through `on_result`; a UPnP mapping is kept alive
/// until `cancel` fires and then removed. Returns `None` for loopback
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
        if mapping.lease() > 0 {
            let every = Duration::from_secs((mapping.lease() / 2).max(30) as u64);
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(every) => {
                        if let Err(e) = mapping.refresh().await {
                            tracing::warn!("NAT: {}", e);
                        }
                    }
                    _ = cancel.cancelled() => break,
                }
            }
        } else {
            cancel.cancelled().await;
        }
        match tokio::time::timeout(Duration::from_secs(3), mapping.remove()).await {
            Ok(Ok(())) => tracing::info!("NAT: UPnP port forward removed"),
            Ok(Err(e)) => tracing::warn!("NAT: {}", e),
            Err(_) => tracing::warn!("NAT: gateway did not answer the removal request"),
        }
    });
    Some(NatTask {
        stun_responses: tx,
        task,
    })
}
