//! UPnP IGD port mapping for the receiver: asks the home router to forward a
//! UDP port to the receiver's socket so that senders outside the local
//! network can reach it.

use anyhow::{anyhow, Result};
use igd::aio::{search_gateway, Gateway};
use igd::{AddAnyPortError, AddPortError, PortMappingProtocol, SearchOptions};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

pub struct UpnpMapping {
    gateway: Gateway,
    local: SocketAddrV4,
    external_port: u16,
    external_ip: Option<Ipv4Addr>,
    lease: u32,
    description: String,
}

impl UpnpMapping {
    /// Finds the gateway and forwards a UDP port to `local_port` on the
    /// interface that talks to it (or on `bind_ip` if the socket is bound to
    /// a specific address). The same external port number is preferred; if
    /// it is taken the gateway picks one (AddAnyPortMapping, IGDv2).
    pub async fn create(
        local_port: u16,
        bind_ip: Option<Ipv4Addr>,
        lease: u32,
        description: &str,
    ) -> Result<Self> {
        let options = SearchOptions {
            timeout: Some(Duration::from_secs(3)),
            ..Default::default()
        };
        let gateway = search_gateway(options)
            .await
            .map_err(|e| anyhow!("no UPnP gateway: {}", e))?;
        let local_ip = match bind_ip {
            Some(ip) if !ip.is_unspecified() => ip,
            _ => local_ip_towards(gateway.addr)?,
        };
        let local = SocketAddrV4::new(local_ip, local_port);
        let udp = PortMappingProtocol::UDP;

        let (external_port, lease) = match gateway
            .add_port(udp, local_port, local, lease, description)
            .await
        {
            Ok(()) => (local_port, lease),
            Err(AddPortError::OnlyPermanentLeasesSupported) => {
                gateway
                    .add_port(udp, local_port, local, 0, description)
                    .await
                    .map_err(|e| anyhow!("UPnP mapping failed: {}", e))?;
                (local_port, 0)
            }
            Err(first) => {
                tracing::debug!(
                    "UPnP: port {} not available ({}); asking for any port",
                    local_port,
                    first
                );
                match gateway.add_any_port(udp, local, lease, description).await {
                    Ok(p) => (p, lease),
                    Err(AddAnyPortError::OnlyPermanentLeasesSupported) => {
                        let p = gateway
                            .add_any_port(udp, local, 0, description)
                            .await
                            .map_err(|e| anyhow!("UPnP mapping failed: {}", e))?;
                        (p, 0)
                    }
                    Err(e) => return Err(anyhow!("UPnP mapping failed: {}", e)),
                }
            }
        };
        let external_ip = gateway.get_external_ip().await.ok();
        Ok(Self {
            gateway,
            local,
            external_port,
            external_ip,
            lease,
            description: description.to_string(),
        })
    }

    /// Public address senders should use, if the gateway reported its IP.
    pub fn external_addr(&self) -> Option<SocketAddr> {
        self.external_ip
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), self.external_port))
    }

    pub fn external_port(&self) -> u16 {
        self.external_port
    }

    pub fn local(&self) -> SocketAddrV4 {
        self.local
    }

    /// Lease in seconds; 0 means permanent (no refresh needed).
    pub fn lease(&self) -> u32 {
        self.lease
    }

    /// Renews the lease by adding the same mapping again.
    pub async fn refresh(&self) -> Result<()> {
        self.gateway
            .add_port(
                PortMappingProtocol::UDP,
                self.external_port,
                self.local,
                self.lease,
                &self.description,
            )
            .await
            .map_err(|e| anyhow!("UPnP refresh failed: {}", e))
    }

    /// Removes the mapping from the gateway.
    pub async fn remove(self) -> Result<()> {
        self.gateway
            .remove_port(PortMappingProtocol::UDP, self.external_port)
            .await
            .map_err(|e| anyhow!("UPnP removal failed: {}", e))
    }
}

/// Local IPv4 address of the interface used to reach `peer`.
fn local_ip_towards(peer: SocketAddrV4) -> Result<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0")?;
    probe.connect(peer)?;
    match probe.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(anyhow!("gateway is not reachable over IPv4")),
    }
}
