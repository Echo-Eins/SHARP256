//! UPnP IGD port mapping for the receiver: asks the home router to forward a
//! UDP port to the receiver's socket so that senders outside the local
//! network can reach it.
//!
//! A small client of its own rather than a general-purpose one, because of
//! who it talks to. UPnP has no authentication at all: the router is found
//! by a multicast search that anything on the local network may answer, and
//! the answer names a URL the client then fetches and posts to. A client
//! that believes that answer, waits on it for as long as it takes and reads
//! whatever it sends back can be made to connect wherever a stranger likes —
//! this host's loopback services included — to hang there for ever, or to
//! read until memory runs out. So here:
//!
//! * a device is believed only if it is on a local subnet of ours, and only
//!   about itself: the description and control URLs must be on the very
//!   address that answered the search;
//! * every step has its own deadline, and the whole attempt one more;
//! * every response has a size limit, and anything past it is an error.
//!
//! The protocol is the UPnP Device Architecture 1.1 (SSDP discovery, the
//! device description, SOAP control) with the WANIPConnection:1/2 and
//! WANPPPConnection:1 services, over HTTP/1.0 so that nothing arrives
//! chunked.

use anyhow::{anyhow, bail, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Where routers listen for searches (UPnP Device Architecture 1.1, 1.3.2).
pub const SSDP_TARGET: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900));
/// How long to wait for search answers.
const SEARCH_WAIT: Duration = Duration::from_secs(2);
/// How long one HTTP exchange may take, connecting included.
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a whole attempt at a mapping may take.
const CREATE_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest device description read, and largest SOAP answer.
const MAX_DESCRIPTION: usize = 64 << 10;
const MAX_SOAP_RESPONSE: usize = 16 << 10;
/// Search answers looked at, at most.
const MAX_ANSWERS: usize = 16;

/// The services that can forward a port, best first.
const SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

/// The service that opens an IPv6 firewall to a port (UPnP IGD v2,
/// WANIPv6FirewallControl:1): there is nothing to translate over IPv6, but
/// the router's firewall drops what nobody inside asked for, and this is how
/// a host asks for a hole (a "pinhole").
const FIREWALL_SERVICE: &str = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";

/// UPnP error codes worth telling apart (UPnP IGD WANIPConnection:2, 2.5).
const CONFLICT_IN_MAPPING: u32 = 718;
const ONLY_PERMANENT_LEASES: u32 = 725;

/// An `http://a.b.c.d:port/path` URL on one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Url {
    host: SocketAddrV4,
    path: String,
}

impl Url {
    /// Only plain HTTP to a literal IPv4 address: a router names itself by
    /// address, and a name would need a DNS lookup somebody else answers.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let rest = s.trim().strip_prefix("http://")?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let host = match authority.rsplit_once(':') {
            Some((ip, port)) => SocketAddrV4::new(ip.parse().ok()?, port.parse().ok()?),
            None => SocketAddrV4::new(authority.parse().ok()?, 80),
        };
        if path.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return None;
        }
        Some(Self {
            host,
            path: path.to_string(),
        })
    }

    /// `reference` resolved against this URL: an absolute URL as it is, a
    /// path relative to this one's host.
    pub(crate) fn join(&self, reference: &str) -> Option<Self> {
        let r = reference.trim();
        if r.starts_with("http://") {
            return Self::parse(r);
        }
        if r.is_empty() || r.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return None;
        }
        let path = if r.starts_with('/') {
            r.to_string()
        } else {
            let dir = &self.path[..self.path.rfind('/').map_or(0, |i| i + 1)];
            format!("{}{}", if dir.is_empty() { "/" } else { dir }, r)
        };
        Some(Self {
            host: self.host,
            path,
        })
    }
}

/// A router's port-forwarding service.
#[derive(Debug, Clone)]
pub(crate) struct Service {
    control: Url,
    kind: &'static str,
}

/// Whether a device at `ip` is one we may believe about itself: on a local
/// subnet of ours, and an address a router has. Loopback only when the
/// search itself went to loopback (the tests' simulated router).
fn believable(ip: Ipv4Addr, search: SocketAddr) -> bool {
    if ip.is_loopback() {
        return search.ip().is_loopback();
    }
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        return false;
    }
    let private = ip.is_private()
        || ip.is_link_local()
        || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]));
    private && on_link(ip)
}

/// Whether `ip` is on one of this host's IPv4 subnets.
fn on_link(ip: Ipv4Addr) -> bool {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return false;
    };
    ifaces.iter().any(|i| match &i.addr {
        if_addrs::IfAddr::V4(v4) => {
            let mask = u32::from(v4.netmask);
            mask != 0 && u32::from(v4.ip) & mask == u32::from(ip) & mask
        }
        _ => false,
    })
}

/// Sends an SSDP search and returns the description URLs of the routers
/// that answered believably, in the order they answered.
async fn search(target: SocketAddr) -> Result<Vec<Url>> {
    let sock = UdpSocket::bind(if target.ip().is_loopback() {
        "127.0.0.1:0"
    } else {
        "0.0.0.0:0"
    })
    .await?;
    let _ = sock.set_multicast_ttl_v4(2);
    let mut found: Vec<Url> = Vec::new();
    for st in [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    ] {
        let msg = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
             MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {}\r\n\r\n",
            st
        );
        sock.send_to(msg.as_bytes(), target).await?;
    }
    let deadline = tokio::time::Instant::now() + SEARCH_WAIT;
    let mut buf = [0u8; 2048];
    let mut answers = 0;
    while answers < MAX_ANSWERS {
        let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await
        else {
            break;
        };
        answers += 1;
        let IpAddr::V4(from_ip) = from.ip() else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&buf[..n]) else {
            continue;
        };
        let Some(location) = header(text, "location").and_then(Url::parse) else {
            continue;
        };
        // About itself, and from nearby: a device that points us anywhere
        // but its own address — this host's loopback, say, or another
        // machine — is not a router telling us where it lives.
        if *location.host.ip() != from_ip || !believable(from_ip, target) {
            tracing::debug!(
                "UPnP: ignoring {} (answered from {}, not believable)",
                location.host,
                from
            );
            continue;
        }
        if !found.contains(&location) {
            found.push(location);
        }
        // The first believable router will do.
        break;
    }
    Ok(found)
}

/// The value of an HTTP-style header in `text`, case-insensitively.
pub(crate) fn header<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// One HTTP/1.0 exchange with a device: sends `request`, reads the answer
/// up to `max` bytes, returns its status and body.
async fn http(url: &Url, request: &[u8], max: usize) -> Result<(u16, String)> {
    let exchange = async {
        let mut stream = TcpStream::connect(SocketAddr::V4(url.host)).await?;
        stream.write_all(request).await?;
        let mut data = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            if data.len() + n > max {
                bail!("{} sent more than {} bytes", url.host, max);
            }
            data.extend_from_slice(&chunk[..n]);
        }
        anyhow::Ok(data)
    };
    let data = tokio::time::timeout(HTTP_TIMEOUT, exchange)
        .await
        .map_err(|_| anyhow!("{} did not answer in time", url.host))??;
    parse_http_answer(&data).map_err(|e| anyhow!("{} {}", url.host, e))
}

/// The status and body of an HTTP answer, from whatever bytes a device
/// sent. It is a stranger on the local network, so nothing is assumed:
/// no header block, or no status in it, is an error, never a guess.
pub(crate) fn parse_http_answer(data: &[u8]) -> Result<(u16, String)> {
    let text = String::from_utf8_lossy(data).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("sent no HTTP answer"))?;
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("sent no HTTP status"))?;
    Ok((status, body.to_string()))
}

async fn get(url: &Url) -> Result<String> {
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        url.path, url.host
    );
    let (status, body) = http(url, request.as_bytes(), MAX_DESCRIPTION).await?;
    if status != 200 {
        bail!("{} answered {} for its description", url.host, status);
    }
    Ok(body)
}

/// The text inside the first `<tag>…</tag>` in `xml` (namespace prefixes
/// on the tag are allowed).
pub(crate) fn element<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let mut rest = xml;
    loop {
        let open = rest.find('<')?;
        rest = &rest[open + 1..];
        let end = rest.find('>')?;
        let name = rest[..end].split_whitespace().next().unwrap_or("");
        let local = name.rsplit(':').next().unwrap_or(name);
        if local == tag && !name.starts_with('/') {
            let body = &rest[end + 1..];
            // The matching close tag, with the same prefix or none.
            let close = body
                .find(&format!("</{}>", name))
                .or_else(|| body.find(&format!("</{}>", tag)))?;
            return Some(body[..close].trim());
        }
        rest = &rest[end + 1..];
    }
}

/// Finds a port-forwarding service in a device description, preferring the
/// newest. Its control URL must be on the device that described it.
pub(crate) fn find_service(description: &str, location: &Url) -> Option<Service> {
    find_service_of(description, location, &SERVICES)
}

/// [`find_service`] for any of `kinds`, best first.
pub(crate) fn find_service_of(
    description: &str,
    location: &Url,
    kinds: &[&'static str],
) -> Option<Service> {
    let base = element(description, "URLBase")
        .and_then(Url::parse)
        .filter(|b| b.host.ip() == location.host.ip())
        .unwrap_or_else(|| location.clone());
    for &kind in kinds {
        for block in description.split("<service>").skip(1) {
            let block = block.split("</service>").next().unwrap_or("");
            if element(block, "serviceType") != Some(kind) {
                continue;
            }
            let Some(control) = element(block, "controlURL").and_then(|c| base.join(c)) else {
                continue;
            };
            if control.host.ip() != location.host.ip() {
                continue;
            }
            return Some(Service { control, kind });
        }
    }
    None
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Calls one SOAP action. `Ok(body)` on success; `Err` carries the UPnP
/// error code when the device gave one.
async fn soap(
    service: &Service,
    action: &str,
    args: &[(&str, String)],
) -> Result<String, SoapError> {
    let mut inner = String::new();
    for (k, v) in args {
        inner.push_str(&format!("<{k}>{}</{k}>", escape(v)));
    }
    let body = format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{kind}\">{inner}</u:{action}></s:Body></s:Envelope>\r\n",
        kind = service.kind
    );
    let request = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: \"{}#{}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        service.control.path,
        service.control.host,
        service.kind,
        action,
        body.len(),
        body
    );
    let (status, answer) = http(&service.control, request.as_bytes(), MAX_SOAP_RESPONSE)
        .await
        .map_err(SoapError::Other)?;
    if status == 200 {
        return Ok(answer);
    }
    match element(&answer, "errorCode").and_then(|c| c.parse().ok()) {
        Some(code) => Err(SoapError::Upnp(code)),
        None => Err(SoapError::Other(anyhow!(
            "{} answered {} to {}",
            service.control.host,
            status,
            action
        ))),
    }
}

#[derive(Debug)]
enum SoapError {
    Upnp(u32),
    Other(anyhow::Error),
}

impl std::fmt::Display for SoapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SoapError::Upnp(code) => write!(f, "UPnP error {}", code),
            SoapError::Other(e) => write!(f, "{}", e),
        }
    }
}

pub struct UpnpMapping {
    service: Service,
    local: SocketAddrV4,
    external_port: u16,
    external_ip: Option<Ipv4Addr>,
    lease: u32,
    description: String,
}

impl UpnpMapping {
    /// Finds the router and forwards a UDP port to `local_port` on the
    /// interface that talks to it (or on `bind_ip` if the socket is bound to
    /// a specific address). The same external port number is preferred; if
    /// it is taken the router picks one (AddAnyPortMapping, IGDv2) or, on an
    /// older router, one of a few random ports is tried.
    pub async fn create(
        local_port: u16,
        bind_ip: Option<Ipv4Addr>,
        lease: u32,
        description: &str,
    ) -> Result<Self> {
        Self::create_with(SSDP_TARGET, local_port, bind_ip, lease, description).await
    }

    /// [`UpnpMapping::create`], searching at `target` (the tests' simulated
    /// router listens on loopback).
    pub async fn create_with(
        target: SocketAddr,
        local_port: u16,
        bind_ip: Option<Ipv4Addr>,
        lease: u32,
        description: &str,
    ) -> Result<Self> {
        tokio::time::timeout(
            CREATE_TIMEOUT,
            Self::attempt(target, local_port, bind_ip, lease, description),
        )
        .await
        .map_err(|_| anyhow!("UPnP: the router took too long"))?
    }

    async fn attempt(
        target: SocketAddr,
        local_port: u16,
        bind_ip: Option<Ipv4Addr>,
        lease: u32,
        description: &str,
    ) -> Result<Self> {
        let mut last = anyhow!("no UPnP router answered");
        for location in search(target).await? {
            let service = match get(&location).await {
                Ok(desc) => match find_service(&desc, &location) {
                    Some(s) => s,
                    None => {
                        last = anyhow!("{} offers no port forwarding", location.host);
                        continue;
                    }
                },
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let local_ip = match bind_ip {
                Some(ip) if !ip.is_unspecified() => ip,
                _ => local_ip_towards(*location.host.ip())?,
            };
            let mut m = Self {
                service,
                local: SocketAddrV4::new(local_ip, local_port),
                external_port: local_port,
                external_ip: None,
                lease,
                description: description.to_string(),
            };
            match m.map().await {
                Ok(()) => {
                    m.external_ip = m.query_external_ip().await;
                    return Ok(m);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Asks for the forward, trying what the router's answers allow.
    async fn map(&mut self) -> Result<()> {
        match self.add(self.external_port, self.lease).await {
            Ok(()) => return Ok(()),
            Err(SoapError::Upnp(ONLY_PERMANENT_LEASES)) => {
                self.lease = 0;
                return self
                    .add(self.external_port, 0)
                    .await
                    .map_err(|e| anyhow!("UPnP mapping failed: {}", e));
            }
            Err(e) => tracing::debug!(
                "UPnP: port {} not available ({}); trying others",
                self.external_port,
                e
            ),
        }
        if self.service.kind.ends_with(":2") {
            if let Ok(port) = self.add_any().await {
                self.external_port = port;
                return Ok(());
            }
        }
        for _ in 0..3 {
            let port = 20_000 + (rand::random::<u16>() % 40_000);
            match self.add(port, self.lease).await {
                Ok(()) => {
                    self.external_port = port;
                    return Ok(());
                }
                Err(SoapError::Upnp(CONFLICT_IN_MAPPING)) => continue,
                Err(e) => return Err(anyhow!("UPnP mapping failed: {}", e)),
            }
        }
        bail!("UPnP: no external port available")
    }

    fn mapping_args(&self, external: u16, lease: u32) -> Vec<(&'static str, String)> {
        vec![
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external.to_string()),
            ("NewProtocol", "UDP".into()),
            ("NewInternalPort", self.local.port().to_string()),
            ("NewInternalClient", self.local.ip().to_string()),
            ("NewEnabled", "1".into()),
            ("NewPortMappingDescription", self.description.clone()),
            ("NewLeaseDuration", lease.to_string()),
        ]
    }

    async fn add(&self, external: u16, lease: u32) -> Result<(), SoapError> {
        soap(
            &self.service,
            "AddPortMapping",
            &self.mapping_args(external, lease),
        )
        .await
        .map(|_| ())
    }

    async fn add_any(&mut self) -> Result<u16, SoapError> {
        let args = self.mapping_args(self.external_port, self.lease);
        let answer = match soap(&self.service, "AddAnyPortMapping", &args).await {
            Err(SoapError::Upnp(ONLY_PERMANENT_LEASES)) => {
                self.lease = 0;
                let args = self.mapping_args(self.external_port, 0);
                soap(&self.service, "AddAnyPortMapping", &args).await?
            }
            other => other?,
        };
        element(&answer, "NewReservedPort")
            .and_then(|p| p.parse().ok())
            .filter(|p| *p != 0)
            .ok_or_else(|| SoapError::Other(anyhow!("no port in the router's answer")))
    }

    async fn query_external_ip(&self) -> Option<Ipv4Addr> {
        let answer = soap(&self.service, "GetExternalIPAddress", &[])
            .await
            .ok()?;
        element(&answer, "NewExternalIPAddress")?.parse().ok()
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
        self.add(self.external_port, self.lease)
            .await
            .map_err(|e| anyhow!("UPnP refresh failed: {}", e))
    }

    /// Removes the mapping from the gateway.
    pub async fn remove(self) -> Result<()> {
        soap(
            &self.service,
            "DeletePortMapping",
            &[
                ("NewRemoteHost", String::new()),
                ("NewExternalPort", self.external_port.to_string()),
                ("NewProtocol", "UDP".into()),
            ],
        )
        .await
        .map(|_| ())
        .map_err(|e| anyhow!("UPnP removal failed: {}", e))
    }
}

/// A hole in a router's IPv6 firewall for one UDP port of this host: what a
/// port forward is where there is no address translation.
pub struct UpnpPinhole {
    service: Service,
    client: std::net::Ipv6Addr,
    port: u16,
    /// The router's handle on the pinhole; `None` when its firewall is off
    /// and there is nothing to open (or to close).
    unique_id: Option<String>,
    lease: u32,
}

impl UpnpPinhole {
    /// Finds the router and asks it to let packets from anywhere in to
    /// `client`'s UDP `port`.
    pub async fn create(client: std::net::Ipv6Addr, port: u16, lease: u32) -> Result<Self> {
        Self::create_with(SSDP_TARGET, client, port, lease).await
    }

    /// [`UpnpPinhole::create`], searching at `target` (the tests' simulated
    /// router listens on loopback).
    pub async fn create_with(
        target: SocketAddr,
        client: std::net::Ipv6Addr,
        port: u16,
        lease: u32,
    ) -> Result<Self> {
        tokio::time::timeout(CREATE_TIMEOUT, Self::attempt(target, client, port, lease))
            .await
            .map_err(|_| anyhow!("UPnP: the router took too long"))?
    }

    async fn attempt(
        target: SocketAddr,
        client: std::net::Ipv6Addr,
        port: u16,
        lease: u32,
    ) -> Result<Self> {
        let mut last = anyhow!("no UPnP router answered");
        for location in search(target).await? {
            let service = match get(&location).await {
                Ok(desc) => match find_service_of(&desc, &location, &[FIREWALL_SERVICE]) {
                    Some(s) => s,
                    None => {
                        last = anyhow!("{} has no IPv6 firewall control", location.host);
                        continue;
                    }
                },
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            // A router says whether it has a firewall to open and whether
            // it lets hosts open it; either "no" is the answer, and the
            // first is a good one.
            let mut open = false;
            if let Ok(status) = soap(&service, "GetFirewallStatus", &[]).await {
                if element(&status, "FirewallEnabled") == Some("0") {
                    open = true;
                } else if element(&status, "InboundPinholeAllowed") == Some("0") {
                    last = anyhow!(
                        "{} does not let hosts open its IPv6 firewall",
                        location.host
                    );
                    continue;
                }
            }
            if open {
                return Ok(Self {
                    service,
                    client,
                    port,
                    unique_id: None,
                    lease,
                });
            }
            // The spec's longest lease; anything more is refused.
            let lease = lease.clamp(1, 86_400);
            let args = [
                ("RemoteHost", String::new()),
                ("RemotePort", "0".to_string()),
                ("InternalClient", client.to_string()),
                ("InternalPort", port.to_string()),
                ("Protocol", "17".to_string()),
                ("LeaseTime", lease.to_string()),
            ];
            match soap(&service, "AddPinhole", &args).await {
                Ok(answer) => {
                    let Some(id) = element(&answer, "UniqueID").map(str::to_string) else {
                        last = anyhow!("the router granted no pinhole handle");
                        continue;
                    };
                    return Ok(Self {
                        service,
                        client,
                        port,
                        unique_id: Some(id),
                        lease,
                    });
                }
                Err(e) => last = anyhow!("UPnP pinhole failed: {}", e),
            }
        }
        Err(last)
    }

    /// Where the host is reachable now: its own address, the port opened.
    pub fn external_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(self.client), self.port)
    }

    pub fn lease(&self) -> u32 {
        self.lease
    }

    /// Renews the lease (UpdatePinhole).
    pub async fn refresh(&self) -> Result<()> {
        let Some(id) = &self.unique_id else {
            return Ok(());
        };
        soap(
            &self.service,
            "UpdatePinhole",
            &[
                ("UniqueID", id.clone()),
                ("NewLeaseTime", self.lease.to_string()),
            ],
        )
        .await
        .map(|_| ())
        .map_err(|e| anyhow!("UPnP pinhole renewal failed: {}", e))
    }

    /// Closes the pinhole.
    pub async fn remove(self) -> Result<()> {
        let Some(id) = self.unique_id else {
            return Ok(());
        };
        soap(&self.service, "DeletePinhole", &[("UniqueID", id)])
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("UPnP pinhole removal failed: {}", e))
    }
}

/// Local IPv4 address of the interface used to reach `router`.
fn local_ip_towards(router: Ipv4Addr) -> Result<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0")?;
    probe.connect(SocketAddrV4::new(router, 1900))?;
    match probe.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(anyhow!("the router is not reachable over IPv4")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    #[test]
    fn urls_are_plain_http_to_an_address() {
        let u = Url::parse("http://192.168.1.1:5000/rootDesc.xml").unwrap();
        assert_eq!(u.host, "192.168.1.1:5000".parse().unwrap());
        assert_eq!(u.path, "/rootDesc.xml");
        assert_eq!(
            Url::parse("http://10.0.0.1").unwrap().host,
            "10.0.0.1:80".parse().unwrap()
        );
        for bad in [
            "https://192.168.1.1/x",
            "http://router.local:5000/x",
            "http://192.168.1.1:5000/a b",
            "ftp://192.168.1.1/",
        ] {
            assert!(Url::parse(bad).is_none(), "{}", bad);
        }
        let base = Url::parse("http://192.168.1.1:5000/dev/desc.xml").unwrap();
        assert_eq!(base.join("ctl/IPConn").unwrap().path, "/dev/ctl/IPConn");
        assert_eq!(base.join("/ctl").unwrap().path, "/ctl");
        assert_eq!(
            base.join("http://192.168.1.9:80/x").unwrap().host,
            "192.168.1.9:80".parse().unwrap()
        );
    }

    #[test]
    fn a_service_is_only_taken_from_the_device_that_describes_it() {
        let location = Url::parse("http://192.168.1.1:5000/desc.xml").unwrap();
        let desc = |control: &str| {
            format!(
                "<root><device><serviceList>\
                 <service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>\
                 <controlURL>/l3f</controlURL></service>\
                 <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
                 <controlURL>{}</controlURL></service>\
                 </serviceList></device></root>",
                control
            )
        };
        let s = find_service(&desc("/ctl/IPConn"), &location).unwrap();
        assert_eq!(s.kind, "urn:schemas-upnp-org:service:WANIPConnection:1");
        assert_eq!(s.control.path, "/ctl/IPConn");
        // A control URL on another host is somebody else's.
        assert!(find_service(&desc("http://127.0.0.1:22/"), &location).is_none());
        assert!(find_service(&desc("http://192.168.1.77/x"), &location).is_none());
    }

    #[test]
    fn soap_answers_are_read_with_or_without_prefixes() {
        let ok = "<s:Envelope><s:Body><u:GetExternalIPAddressResponse xmlns:u=\"x\">\
                  <NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>\
                  </u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
        assert_eq!(element(ok, "NewExternalIPAddress"), Some("203.0.113.7"));
        let fault = "<s:Envelope><s:Body><s:Fault><detail><UPnPError xmlns=\"x\">\
                     <errorCode>718</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>";
        assert_eq!(element(fault, "errorCode"), Some("718"));
        assert_eq!(element("<a>1</a>", "b"), None);
    }

    /// A simulated router on loopback: answers the search from `ssdp` with a
    /// description at `location`, and runs an HTTP server that behaves as
    /// `behave` says.
    struct FakeRouter {
        ssdp: SocketAddr,
        adds: Arc<AtomicU32>,
        _tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    #[derive(Clone, Copy)]
    enum Behave {
        Normal,
        /// The first AddPortMapping conflicts; the router is IGDv2.
        ConflictThenAny,
        /// Accepts connections and never answers.
        Hang,
        /// Sends a description far larger than any router's.
        Huge,
        /// An IGD v2 with an IPv6 firewall to open.
        Pinhole,
        /// Its firewall refuses hosts that ask.
        NoPinholes,
        /// Its firewall is switched off.
        FirewallOff,
    }

    async fn fake_router(behave: Behave, location_host: Option<&str>) -> FakeRouter {
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http.local_addr().unwrap();
        let ssdp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ssdp_addr = ssdp.local_addr().unwrap();
        let location = match location_host {
            Some(h) => format!("http://{}/desc.xml", h),
            None => format!("http://{}/desc.xml", http_addr),
        };
        let adds = Arc::new(AtomicU32::new(0));
        let ssdp_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((_, from)) = ssdp.recv_from(&mut buf).await {
                let answer = format!(
                    "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLOCATION: {}\r\n\
                     ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n",
                    location
                );
                let _ = ssdp.send_to(answer.as_bytes(), from).await;
            }
        });
        let counter = adds.clone();
        let http_task = tokio::spawn(async move {
            let kind = match behave {
                Behave::ConflictThenAny => "urn:schemas-upnp-org:service:WANIPConnection:2",
                Behave::Pinhole | Behave::NoPinholes | Behave::FirewallOff => {
                    "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1"
                }
                _ => "urn:schemas-upnp-org:service:WANIPConnection:1",
            };
            loop {
                let Ok((mut conn, _)) = http.accept().await else {
                    return;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut req = vec![0u8; 16 << 10];
                    let n = conn.read(&mut req).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&req[..n]).into_owned();
                    let reply = |status: &str, body: String| {
                        format!(
                            "HTTP/1.0 {}\r\nContent-Type: text/xml\r\n\r\n{}",
                            status, body
                        )
                    };
                    let answer = if matches!(behave, Behave::Hang) {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        return;
                    } else if req.starts_with("GET") {
                        if matches!(behave, Behave::Huge) {
                            let mut big = reply("200 OK", String::new());
                            big.push_str(&"<x>".repeat(200_000));
                            big
                        } else {
                            reply(
                                "200 OK",
                                format!(
                                    "<root><device><serviceList><service>\
                                     <serviceType>{}</serviceType>\
                                     <controlURL>/ctl</controlURL></service>\
                                     </serviceList></device></root>",
                                    kind
                                ),
                            )
                        }
                    } else if req.contains("#AddPortMapping") {
                        let n = counter.fetch_add(1, Ordering::Relaxed);
                        if matches!(behave, Behave::ConflictThenAny) && n == 0 {
                            reply(
                                "500 Internal Server Error",
                                "<s:Envelope><s:Body><s:Fault><detail><UPnPError>\
                                 <errorCode>718</errorCode></UPnPError></detail>\
                                 </s:Fault></s:Body></s:Envelope>"
                                    .into(),
                            )
                        } else {
                            reply("200 OK", "<s:Envelope/>".into())
                        }
                    } else if req.contains("#AddAnyPortMapping") {
                        reply(
                            "200 OK",
                            "<u:AddAnyPortMappingResponse>\
                             <NewReservedPort>40123</NewReservedPort>\
                             </u:AddAnyPortMappingResponse>"
                                .into(),
                        )
                    } else if req.contains("#GetExternalIPAddress") {
                        reply(
                            "200 OK",
                            "<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>".into(),
                        )
                    } else if req.contains("#DeletePortMapping") {
                        reply("200 OK", String::new())
                    } else if req.contains("#GetFirewallStatus") {
                        let (enabled, allowed) = match behave {
                            Behave::NoPinholes => (1, 0),
                            Behave::FirewallOff => (0, 1),
                            _ => (1, 1),
                        };
                        reply(
                            "200 OK",
                            format!(
                                "<u:GetFirewallStatusResponse><FirewallEnabled>{}\
                                 </FirewallEnabled><InboundPinholeAllowed>{}\
                                 </InboundPinholeAllowed></u:GetFirewallStatusResponse>",
                                enabled, allowed
                            ),
                        )
                    } else if req.contains("#AddPinhole") {
                        // The arguments a router needs, without the prefix
                        // the IGD v1 actions use.
                        let wanted = [
                            "<RemoteHost>",
                            "<InternalClient>2001:db8::5<",
                            "<InternalPort>5555<",
                            "<Protocol>17<",
                            "<LeaseTime>",
                        ];
                        if wanted.iter().all(|w| req.contains(w)) {
                            counter.fetch_add(1, Ordering::Relaxed);
                            reply(
                                "200 OK",
                                "<u:AddPinholeResponse><UniqueID>77</UniqueID></u:AddPinholeResponse>"
                                    .into(),
                            )
                        } else {
                            reply("500 Internal Server Error", String::new())
                        }
                    } else if (req.contains("#UpdatePinhole") || req.contains("#DeletePinhole"))
                        && req.contains("<UniqueID>77<")
                    {
                        reply("200 OK", String::new())
                    } else {
                        reply("404 Not Found", String::new())
                    };
                    let _ = conn.write_all(answer.as_bytes()).await;
                });
            }
        });
        FakeRouter {
            ssdp: ssdp_addr,
            adds,
            _tasks: vec![ssdp_task, http_task],
        }
    }

    const HERE: Option<Ipv4Addr> = Some(Ipv4Addr::LOCALHOST);

    const CLIENT6: std::net::Ipv6Addr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);

    /// An IPv6 firewall is opened to the port, renewed and closed, and the
    /// host is then reachable at its own address.
    #[tokio::test]
    async fn a_router_opens_its_ipv6_firewall_to_a_port() {
        let r = fake_router(Behave::Pinhole, None).await;
        let p = UpnpPinhole::create_with(r.ssdp, CLIENT6, 5555, 3600)
            .await
            .expect("opened");
        assert_eq!(p.external_addr(), "[2001:db8::5]:5555".parse().unwrap());
        assert_eq!(r.adds.load(Ordering::Relaxed), 1);
        p.refresh().await.expect("renewed");
        p.remove().await.expect("closed");
    }

    #[tokio::test]
    async fn a_firewall_that_is_off_needs_no_pinhole() {
        let r = fake_router(Behave::FirewallOff, None).await;
        let p = UpnpPinhole::create_with(r.ssdp, CLIENT6, 5555, 3600)
            .await
            .expect("nothing to open");
        assert_eq!(r.adds.load(Ordering::Relaxed), 0);
        p.remove().await.expect("nothing to close");
    }

    #[tokio::test]
    async fn a_router_that_lets_hosts_open_nothing_is_reported() {
        let r = fake_router(Behave::NoPinholes, None).await;
        let e = UpnpPinhole::create_with(r.ssdp, CLIENT6, 5555, 3600)
            .await
            .err()
            .expect("refused");
        assert!(e.to_string().contains("does not let hosts open"), "{}", e);
        // And an IGD with no IPv6 firewall at all is not mistaken for one.
        let v1 = fake_router(Behave::Normal, None).await;
        assert!(UpnpPinhole::create_with(v1.ssdp, CLIENT6, 5555, 3600)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_router_forwards_a_port_and_says_where() {
        let r = fake_router(Behave::Normal, None).await;
        let m = UpnpMapping::create_with(r.ssdp, 5555, HERE, 3600, "test")
            .await
            .expect("mapped");
        assert_eq!(m.external_port(), 5555);
        assert_eq!(m.external_addr(), Some("203.0.113.7:5555".parse().unwrap()));
        m.refresh().await.expect("refreshed");
        m.remove().await.expect("removed");
    }

    #[tokio::test]
    async fn a_taken_port_is_exchanged_for_one_the_router_picks() {
        let r = fake_router(Behave::ConflictThenAny, None).await;
        let m = UpnpMapping::create_with(r.ssdp, 5555, HERE, 3600, "test")
            .await
            .expect("mapped");
        assert_eq!(m.external_port(), 40123);
        assert_eq!(r.adds.load(Ordering::Relaxed), 1);
    }

    /// Somewhere other than the fake router's own address that this host can
    /// listen on: a second loopback address where the system has one (Linux
    /// and Windows answer on all of 127/8), else one of the host's own
    /// addresses (macOS configures 127.0.0.1 alone).
    async fn somewhere_else() -> TcpListener {
        if let Ok(l) = TcpListener::bind("127.0.0.2:0").await {
            return l;
        }
        let ip = if_addrs::get_if_addrs()
            .expect("the host's addresses")
            .into_iter()
            .map(|i| i.ip())
            .find(|ip| ip.is_ipv4() && !ip.is_loopback())
            .expect("an IPv4 address other than loopback");
        TcpListener::bind((ip, 0)).await.unwrap()
    }

    /// Whoever answers the search is believed only about itself. Pointed at
    /// another address — here a port nothing on this host would expect a
    /// router's request on — nothing is fetched there at all.
    #[tokio::test]
    async fn a_router_that_points_elsewhere_is_not_followed() {
        let bait = somewhere_else().await;
        let bait_addr = bait.local_addr().unwrap().to_string();
        let r = fake_router(Behave::Normal, Some(&bait_addr)).await;
        let visited = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(4), bait.accept())
                .await
                .is_ok()
        });
        assert!(UpnpMapping::create_with(r.ssdp, 5555, HERE, 3600, "test")
            .await
            .is_err());
        assert!(
            !visited.await.unwrap(),
            "the client went where it was pointed"
        );
    }

    /// A device that accepts the connection and then says nothing costs a
    /// few seconds, not the receiver's address report for ever.
    #[tokio::test]
    async fn a_router_that_never_answers_costs_seconds() {
        let r = fake_router(Behave::Hang, None).await;
        let started = std::time::Instant::now();
        assert!(UpnpMapping::create_with(r.ssdp, 5555, HERE, 3600, "test")
            .await
            .is_err());
        assert!(started.elapsed() <= CREATE_TIMEOUT + Duration::from_secs(1));
    }

    /// And one that sends more than any router would is cut off, not read
    /// until memory runs out.
    #[tokio::test]
    async fn a_router_that_sends_too_much_is_cut_off() {
        let r = fake_router(Behave::Huge, None).await;
        let e = UpnpMapping::create_with(r.ssdp, 5555, HERE, 3600, "test")
            .await
            .err()
            .expect("refused");
        assert!(e.to_string().contains("more than"), "{}", e);
    }
}
