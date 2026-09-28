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

pub mod stun;
pub mod upnp;

use self::stun::StunClient;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// The public address is one of this host's own addresses.
    None,
    /// The same public mapping is used towards different servers.
    Cone,
    /// The mapping changes per destination; inbound transfers need a port
    /// forward.
    Symmetric,
    Unknown,
}

/// Outcome of a discovery run.
#[derive(Debug, Clone)]
pub struct Reachability {
    pub local_addr: SocketAddr,
    pub public_addr: Option<SocketAddr>,
    pub nat_type: NatType,
    pub upnp_addr: Option<SocketAddr>,
}

impl Reachability {
    /// Address senders outside the local network should use, if known.
    pub fn advertised(&self) -> Option<SocketAddr> {
        if let Some(a) = self.upnp_addr {
            return Some(a);
        }
        match (self.nat_type, self.public_addr) {
            (NatType::None, Some(p)) => Some(SocketAddr::new(p.ip(), self.local_addr.port())),
            _ => None,
        }
    }

    /// One-line human-readable summary.
    pub fn describe(&self) -> String {
        match (self.advertised(), self.public_addr) {
            (Some(a), _) if self.upnp_addr.is_some() => {
                format!("reachable from outside at {} (UPnP port forward)", a)
            }
            (Some(a), _) => format!("reachable from outside at {} (public address)", a),
            (None, Some(p)) => format!(
                "behind {} NAT (public IP {}); senders outside this network need a port forward to local port {}",
                match self.nat_type {
                    NatType::Symmetric => "a symmetric",
                    _ => "a",
                },
                p.ip(),
                self.local_addr.port()
            ),
            (None, None) => "public address unknown (no STUN answer, no UPnP gateway); \
                             senders on the local network can connect directly"
                .to_string(),
        }
    }
}

fn is_own_address(ip: IpAddr) -> bool {
    if_addrs::get_if_addrs()
        .map(|ifs| ifs.iter().any(|i| i.ip() == ip))
        .unwrap_or(false)
}

async fn discover(
    socket: &UdpSocket,
    config: &NatConfig,
    responses: &mut mpsc::Receiver<Vec<u8>>,
) -> (Reachability, Option<UpnpMapping>) {
    let local_addr = socket
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mapped = if config.enable_stun {
        StunClient::new(config.stun_servers.clone())
            .mapped_addresses(socket, responses, 2)
            .await
    } else {
        Vec::new()
    };
    let public_addr = mapped.first().copied();
    let nat_type = match public_addr {
        None => NatType::Unknown,
        Some(p) if is_own_address(p.ip()) => NatType::None,
        Some(_) if mapped.len() >= 2 => {
            if mapped.iter().all(|m| *m == mapped[0]) {
                NatType::Cone
            } else {
                NatType::Symmetric
            }
        }
        Some(_) => NatType::Unknown,
    };

    let mut mapping = None;
    if config.enable_upnp && nat_type != NatType::None {
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
            nat_type,
            upnp_addr,
        },
        mapping,
    )
}

/// Handle of a background discovery task.
pub struct NatTask {
    /// The receiver's dispatcher passes STUN responses here.
    pub stun_responses: mpsc::Sender<Vec<u8>>,
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
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
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
