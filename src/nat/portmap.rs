//! Asking the router for a port forward: PCP (RFC 6887) and its predecessor
//! NAT-PMP (RFC 6886).
//!
//! A port forward is the one way through a NAT that does not depend on the
//! other side's behaviour or on timing: the router simply sends the port to
//! us. UPnP-IGD (see [`super::upnp`]) does the same job over HTTP and SOAP
//! and is the oldest of the three; these two are small binary protocols on
//! UDP port 5351, are what most routers made since about 2013 speak, and are
//! what Apple and most mobile networks implement. Trying all three costs a
//! few datagrams and roughly doubles the number of routers we get through.
//!
//! Both are asked in the same breath: PCP first, since it is the successor
//! and a PCP router usually also answers NAT-PMP, then NAT-PMP if PCP says
//! nothing or rejects the version.
//!
//! **What the router says is not trusted.** A PCP or NAT-PMP server is an
//! unauthenticated box on the local network, and on a network we do not own
//! anything could answer. A wrong or hostile answer can only produce an
//! address that does not work: senders fail to reach it, try the next
//! candidate, and authentication decides. Nothing here grants access. The
//! reply is still checked as far as the protocols allow — PCP echoes a
//! 96-bit nonce we chose, which binds a response to our request, and
//! NAT-PMP's response must at least name the port we asked about.

use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;

/// The port both protocols listen on.
pub const PORT: u16 = 5351;
/// IANA protocol number for UDP, as PCP names it.
const PROTO_UDP: u8 = 17;

const PCP_VERSION: u8 = 2;
const PCP_OPCODE_MAP: u8 = 1;
const PCP_REQUEST_LEN: usize = 60;
const PCP_RESPONSE_LEN: usize = 60;
/// Longest PCP message we will read (RFC 6887 section 7).
const PCP_MAX_LEN: usize = 1100;

const PMP_VERSION: u8 = 0;
const PMP_OP_EXTERNAL: u8 = 0;
const PMP_OP_MAP_UDP: u8 = 1;
/// Responses carry the opcode with the high bit set.
const PMP_RESPONSE_BIT: u8 = 128;

/// Which protocol produced a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Pcp,
    NatPmp,
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Protocol::Pcp => "PCP",
            Protocol::NatPmp => "NAT-PMP",
        }
    }
}

/// What the router granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    pub external_port: u16,
    /// PCP reports the external address; NAT-PMP only does so in a separate
    /// exchange, and either may be missing.
    pub external_ip: Option<IpAddr>,
    /// Seconds the mapping lives. Routers may grant less than asked.
    pub lifetime: u32,
}

// ---------------------------------------------------------------------------
// PCP (RFC 6887)
// ---------------------------------------------------------------------------

/// A PCP MAP request: 24 bytes of header and 36 of MAP payload.
pub fn pcp_map_request(
    nonce: &[u8; 12],
    client: Ipv4Addr,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime: u32,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(PCP_REQUEST_LEN);
    m.push(PCP_VERSION);
    m.push(PCP_OPCODE_MAP); // R bit clear: a request
    m.extend_from_slice(&[0, 0]); // reserved
    m.extend_from_slice(&lifetime.to_be_bytes());
    m.extend_from_slice(&client.to_ipv6_mapped().octets());
    m.extend_from_slice(nonce);
    m.push(PROTO_UDP);
    m.extend_from_slice(&[0, 0, 0]); // reserved
    m.extend_from_slice(&internal_port.to_be_bytes());
    m.extend_from_slice(&suggested_external_port.to_be_bytes());
    m.extend_from_slice(&std::net::Ipv6Addr::UNSPECIFIED.octets());
    debug_assert_eq!(m.len(), PCP_REQUEST_LEN);
    m
}

/// Reads a PCP MAP response. The nonce must be the one we sent: that is what
/// binds an answer to our request.
pub fn pcp_parse_map_response(pkt: &[u8], nonce: &[u8; 12], internal_port: u16) -> Result<Grant> {
    if pkt.len() < PCP_RESPONSE_LEN {
        bail!("PCP response too short ({} bytes)", pkt.len());
    }
    if pkt[0] != PCP_VERSION {
        bail!("PCP version {} not supported", pkt[0]);
    }
    if pkt[1] & 0x80 == 0 {
        bail!("not a PCP response");
    }
    if pkt[1] & 0x7f != PCP_OPCODE_MAP {
        bail!("PCP response to another opcode");
    }
    let result = pkt[3];
    if result != 0 {
        bail!("{}", pcp_result_name(result));
    }
    if pkt[24..36] != nonce[..] {
        bail!("PCP response carries another request's nonce");
    }
    if pkt[36] != PROTO_UDP {
        bail!("PCP response is not about UDP");
    }
    let got_internal = u16::from_be_bytes([pkt[40], pkt[41]]);
    if got_internal != internal_port {
        bail!(
            "PCP response is about internal port {}, not {}",
            got_internal,
            internal_port
        );
    }
    let lifetime = u32::from_be_bytes(pkt[4..8].try_into().unwrap());
    let external_port = u16::from_be_bytes([pkt[42], pkt[43]]);
    if external_port == 0 {
        bail!("PCP granted external port 0");
    }
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&pkt[44..60]);
    let external_ip = unmap(std::net::Ipv6Addr::from(ip));
    Ok(Grant {
        external_port,
        external_ip,
        lifetime,
    })
}

fn pcp_result_name(code: u8) -> &'static str {
    match code {
        1 => "PCP: unsupported version",
        2 => "PCP: not authorised (port mapping is disabled on the router)",
        3 => "PCP: router is out of network resources",
        4 => "PCP: no resources for this mapping",
        5 => "PCP: unsupported protocol",
        6 => "PCP: too many mappings for this host",
        7 => "PCP: router is out of memory",
        8 => "PCP: unsupported option",
        9 => "PCP: malformed option",
        10 => "PCP: the router's network failed",
        11 => "PCP: cannot provide the external address asked for",
        12 => "PCP: the address in the request is not ours",
        13 => "PCP: cannot create a mapping for this port",
        14 => "PCP: excessive number of remote peers",
        _ => "PCP: the router refused the mapping",
    }
}

/// An IPv6 address that is really an IPv4 one, unwrapped; `None` for the
/// unspecified address, which means "not reported".
fn unmap(ip: std::net::Ipv6Addr) -> Option<IpAddr> {
    if ip.is_unspecified() {
        return None;
    }
    match ip.to_ipv4_mapped() {
        Some(v4) if v4.is_unspecified() => None,
        Some(v4) => Some(IpAddr::V4(v4)),
        None => Some(IpAddr::V6(ip)),
    }
}

// ---------------------------------------------------------------------------
// NAT-PMP (RFC 6886)
// ---------------------------------------------------------------------------

/// NAT-PMP request for the router's external address.
pub fn pmp_external_request() -> [u8; 2] {
    [PMP_VERSION, PMP_OP_EXTERNAL]
}

pub fn pmp_parse_external_response(pkt: &[u8]) -> Result<Ipv4Addr> {
    if pkt.len() < 12 {
        bail!("NAT-PMP response too short");
    }
    if pkt[0] != PMP_VERSION || pkt[1] != PMP_RESPONSE_BIT + PMP_OP_EXTERNAL {
        bail!("not a NAT-PMP external address response");
    }
    let result = u16::from_be_bytes([pkt[2], pkt[3]]);
    if result != 0 {
        bail!("{}", pmp_result_name(result));
    }
    Ok(Ipv4Addr::new(pkt[8], pkt[9], pkt[10], pkt[11]))
}

/// NAT-PMP UDP mapping request. A lifetime of 0 removes the mapping.
pub fn pmp_map_request(internal_port: u16, suggested_external_port: u16, lifetime: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(12);
    m.push(PMP_VERSION);
    m.push(PMP_OP_MAP_UDP);
    m.extend_from_slice(&[0, 0]); // reserved
    m.extend_from_slice(&internal_port.to_be_bytes());
    m.extend_from_slice(&suggested_external_port.to_be_bytes());
    m.extend_from_slice(&lifetime.to_be_bytes());
    m
}

/// Reads a NAT-PMP mapping response. There is no nonce in this protocol, so
/// the only thing binding a response to our request is the internal port it
/// names; it is checked.
pub fn pmp_parse_map_response(pkt: &[u8], internal_port: u16) -> Result<Grant> {
    if pkt.len() < 16 {
        bail!("NAT-PMP response too short ({} bytes)", pkt.len());
    }
    if pkt[0] != PMP_VERSION {
        bail!("NAT-PMP version {} not supported", pkt[0]);
    }
    if pkt[1] != PMP_RESPONSE_BIT + PMP_OP_MAP_UDP {
        bail!("not a NAT-PMP UDP mapping response");
    }
    let result = u16::from_be_bytes([pkt[2], pkt[3]]);
    if result != 0 {
        bail!("{}", pmp_result_name(result));
    }
    let got_internal = u16::from_be_bytes([pkt[8], pkt[9]]);
    if got_internal != internal_port {
        bail!(
            "NAT-PMP response is about internal port {}, not {}",
            got_internal,
            internal_port
        );
    }
    let external_port = u16::from_be_bytes([pkt[10], pkt[11]]);
    if external_port == 0 {
        bail!("NAT-PMP granted external port 0");
    }
    Ok(Grant {
        external_port,
        external_ip: None,
        lifetime: u32::from_be_bytes(pkt[12..16].try_into().unwrap()),
    })
}

fn pmp_result_name(code: u16) -> &'static str {
    match code {
        1 => "NAT-PMP: unsupported version",
        2 => "NAT-PMP: not authorised (port mapping is disabled on the router)",
        3 => "NAT-PMP: the router's network failed",
        4 => "NAT-PMP: router is out of resources",
        5 => "NAT-PMP: unsupported opcode",
        _ => "NAT-PMP: the router refused the mapping",
    }
}

// ---------------------------------------------------------------------------
// Finding the router
// ---------------------------------------------------------------------------

/// Addresses worth asking for a port forward, best first.
///
/// The routing table is read where the platform makes that easy; otherwise —
/// and in addition, because a host can have several networks — the first
/// address of each local IPv4 subnet is tried, which is where home routers
/// almost always sit. A wrong guess costs one datagram that nothing answers.
pub fn gateway_candidates() -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    let mut add = |ip: Ipv4Addr| {
        if !ip.is_unspecified() && !ip.is_loopback() && !out.contains(&ip) && out.len() < 4 {
            out.push(ip);
        }
    };
    for ip in routing_table_gateways() {
        add(ip);
    }
    for ip in subnet_first_addresses() {
        add(ip);
    }
    out
}

#[cfg(target_os = "linux")]
fn routing_table_gateways() -> Vec<Ipv4Addr> {
    // /proc/net/route: columns Iface Destination Gateway ... in little-endian
    // hex. The default route is the one whose destination is 0.
    let Ok(text) = std::fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let mut f = line.split_whitespace();
        let (_iface, dest, gw) = (f.next(), f.next(), f.next());
        let (Some(dest), Some(gw)) = (dest, gw) else {
            continue;
        };
        if u32::from_str_radix(dest, 16) != Ok(0) {
            continue;
        }
        if let Ok(raw) = u32::from_str_radix(gw, 16) {
            out.push(Ipv4Addr::from(raw.to_le_bytes()));
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
fn routing_table_gateways() -> Vec<Ipv4Addr> {
    Vec::new()
}

/// The first usable address of every local IPv4 subnet (`x.y.z.1` for the
/// usual /24), which is where a home router almost always is.
fn subnet_first_addresses() -> Vec<Ipv4Addr> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for i in ifaces {
        let if_addrs::IfAddr::V4(v4) = i.addr else {
            continue;
        };
        if v4.ip.is_loopback() {
            continue;
        }
        let ip = u32::from(v4.ip);
        let mask = u32::from(v4.netmask);
        // A mask that covers everything, or nothing, names no subnet.
        if mask == 0 || mask == u32::MAX {
            continue;
        }
        let first = (ip & mask) | 1;
        if first != ip {
            out.push(Ipv4Addr::from(first));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Asking
// ---------------------------------------------------------------------------

/// A port forward granted by PCP or NAT-PMP, with what it takes to renew and
/// to give it back.
pub struct Mapping {
    router: SocketAddr,
    protocol: Protocol,
    /// PCP binds renewals and the removal to this nonce.
    nonce: [u8; 12],
    client: Ipv4Addr,
    internal_port: u16,
    grant: Grant,
}

impl Mapping {
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn external_port(&self) -> u16 {
        self.grant.external_port
    }

    pub fn external_addr(&self) -> Option<SocketAddr> {
        self.grant
            .external_ip
            .map(|ip| SocketAddr::new(ip, self.grant.external_port))
    }

    pub fn lifetime(&self) -> u32 {
        self.grant.lifetime
    }

    pub fn internal(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.client, self.internal_port)
    }

    pub fn router(&self) -> SocketAddr {
        self.router
    }

    /// Asks for the same mapping again, which renews the lease.
    pub async fn refresh(&self, lifetime: u32) -> Result<()> {
        let sock = bound_socket(self.client).await?;
        match self.protocol {
            Protocol::Pcp => {
                let req = pcp_map_request(
                    &self.nonce,
                    self.client,
                    self.internal_port,
                    self.grant.external_port,
                    lifetime,
                );
                let pkt = exchange(&sock, self.router, &req, PCP_MAX_LEN).await?;
                pcp_parse_map_response(&pkt, &self.nonce, self.internal_port)?;
            }
            Protocol::NatPmp => {
                let req = pmp_map_request(self.internal_port, self.grant.external_port, lifetime);
                let pkt = exchange(&sock, self.router, &req, 64).await?;
                pmp_parse_map_response(&pkt, self.internal_port)?;
            }
        }
        Ok(())
    }

    /// Gives the mapping back (lifetime 0), so the router does not keep a
    /// forward to a port nothing listens on.
    pub async fn remove(&self) -> Result<()> {
        let sock = bound_socket(self.client).await?;
        match self.protocol {
            Protocol::Pcp => {
                // RFC 6887 section 15: lifetime 0 with the same nonce.
                let req = pcp_map_request(&self.nonce, self.client, self.internal_port, 0, 0);
                sock.send_to(&req, self.router).await?;
            }
            Protocol::NatPmp => {
                // RFC 6886 section 3.4: external port and lifetime both 0.
                let req = pmp_map_request(self.internal_port, 0, 0);
                sock.send_to(&req, self.router).await?;
            }
        }
        // The removal is best effort: the mapping expires on its own.
        Ok(())
    }
}

async fn bound_socket(client: Ipv4Addr) -> Result<UdpSocket> {
    // Bound to the interface that faces the router, so the client address in
    // a PCP request is the one the router will see.
    let sock = UdpSocket::bind(SocketAddrV4::new(client, 0))
        .await
        .or(UdpSocket::bind("0.0.0.0:0").await)?;
    Ok(sock)
}

/// Sends `request` and waits for one answer, retrying as both RFCs ask
/// (250 ms, doubling).
async fn exchange(
    sock: &UdpSocket,
    router: SocketAddr,
    request: &[u8],
    max_len: usize,
) -> Result<Vec<u8>> {
    let mut wait = Duration::from_millis(250);
    let mut buf = vec![0u8; max_len];
    for _ in 0..3 {
        sock.send_to(request, router).await?;
        match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) if from.ip() == router.ip() => return Ok(buf[..n].to_vec()),
            // A datagram from somewhere else is not an answer to this.
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => wait *= 2,
        }
    }
    Err(anyhow!("{} did not answer", router))
}

/// Asks one router for a UDP port forward, PCP first and NAT-PMP after.
pub async fn request_at(
    router: SocketAddr,
    client: Ipv4Addr,
    internal_port: u16,
    lifetime: u32,
) -> Result<Mapping> {
    let sock = bound_socket(client).await?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    // PCP: the successor, and its nonce binds the answer to this request.
    let req = pcp_map_request(&nonce, client, internal_port, internal_port, lifetime);
    match exchange(&sock, router, &req, PCP_MAX_LEN).await {
        Ok(pkt) => match pcp_parse_map_response(&pkt, &nonce, internal_port) {
            Ok(grant) => {
                return Ok(Mapping {
                    router,
                    protocol: Protocol::Pcp,
                    nonce,
                    client,
                    internal_port,
                    grant,
                })
            }
            Err(e) => tracing::debug!("port mapping: {} at {}", e, router),
        },
        Err(e) => tracing::debug!("port mapping: {}", e),
    }

    // NAT-PMP: older, and what a router that ignored PCP may still answer.
    let req = pmp_map_request(internal_port, internal_port, lifetime);
    let pkt = exchange(&sock, router, &req, 64).await?;
    let mut grant = pmp_parse_map_response(&pkt, internal_port)?;
    // NAT-PMP needs a second exchange to learn the external address.
    if let Ok(pkt) = exchange(&sock, router, &pmp_external_request(), 64).await {
        if let Ok(ip) = pmp_parse_external_response(&pkt) {
            grant.external_ip = Some(IpAddr::V4(ip));
        }
    }
    Ok(Mapping {
        router,
        protocol: Protocol::NatPmp,
        nonce,
        client,
        internal_port,
        grant,
    })
}

/// Tries every plausible router until one grants a forward.
pub async fn request(client: Ipv4Addr, internal_port: u16, lifetime: u32) -> Result<Mapping> {
    let candidates = gateway_candidates();
    if candidates.is_empty() {
        bail!("no router address to ask");
    }
    let mut last = anyhow!("no router answered");
    for gw in candidates {
        let router = SocketAddr::new(IpAddr::V4(gw), PORT);
        match request_at(router, client, internal_port, lifetime).await {
            Ok(m) => return Ok(m),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

    // ----- PCP -------------------------------------------------------------

    /// Builds the response a router would send for a request.
    fn pcp_response(
        nonce: &[u8; 12],
        result: u8,
        lifetime: u32,
        internal: u16,
        external: u16,
        ip: Option<Ipv4Addr>,
    ) -> Vec<u8> {
        let mut m = Vec::with_capacity(PCP_RESPONSE_LEN);
        m.push(PCP_VERSION);
        m.push(0x80 | PCP_OPCODE_MAP);
        m.push(0);
        m.push(result);
        m.extend_from_slice(&lifetime.to_be_bytes());
        m.extend_from_slice(&7u32.to_be_bytes()); // epoch
        m.extend_from_slice(&[0u8; 12]); // reserved
        m.extend_from_slice(nonce);
        m.push(PROTO_UDP);
        m.extend_from_slice(&[0, 0, 0]);
        m.extend_from_slice(&internal.to_be_bytes());
        m.extend_from_slice(&external.to_be_bytes());
        let v6 = ip
            .map(|v| v.to_ipv6_mapped())
            .unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);
        m.extend_from_slice(&v6.octets());
        assert_eq!(m.len(), PCP_RESPONSE_LEN);
        m
    }

    #[test]
    fn pcp_request_has_the_shape_the_rfc_describes() {
        let nonce = [9u8; 12];
        let req = pcp_map_request(&nonce, CLIENT, 5555, 5555, 3600);
        assert_eq!(req.len(), PCP_REQUEST_LEN);
        assert_eq!(req[0], PCP_VERSION);
        assert_eq!(req[1], PCP_OPCODE_MAP, "the R bit must be clear");
        assert_eq!(u32::from_be_bytes(req[4..8].try_into().unwrap()), 3600);
        assert_eq!(&req[8..24], &CLIENT.to_ipv6_mapped().octets());
        assert_eq!(&req[24..36], &nonce);
        assert_eq!(req[36], PROTO_UDP);
        assert_eq!(u16::from_be_bytes([req[40], req[41]]), 5555);
        assert_eq!(u16::from_be_bytes([req[42], req[43]]), 5555);
    }

    #[test]
    fn pcp_response_is_accepted_only_when_it_answers_our_request() {
        let nonce = [3u8; 12];
        let ok = pcp_response(
            &nonce,
            0,
            1800,
            5555,
            41234,
            Some(Ipv4Addr::new(203, 0, 113, 4)),
        );
        let grant = pcp_parse_map_response(&ok, &nonce, 5555).unwrap();
        assert_eq!(grant.external_port, 41234);
        assert_eq!(grant.lifetime, 1800);
        assert_eq!(grant.external_ip, Some("203.0.113.4".parse().unwrap()));

        // Another request's nonce: a different client's mapping, or someone
        // guessing. Not ours.
        assert!(pcp_parse_map_response(&ok, &[4u8; 12], 5555).is_err());
        // A response about a port we did not ask about.
        assert!(pcp_parse_map_response(&ok, &nonce, 6666).is_err());
        // A refusal is reported, not mistaken for success.
        let refused = pcp_response(&nonce, 2, 0, 5555, 0, None);
        let e = pcp_parse_map_response(&refused, &nonce, 5555)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not authorised"), "{}", e);
        // Truncated, wrong version, and a request echoed back.
        assert!(pcp_parse_map_response(&ok[..40], &nonce, 5555).is_err());
        let mut bad_version = ok.clone();
        bad_version[0] = 1;
        assert!(pcp_parse_map_response(&bad_version, &nonce, 5555).is_err());
        let echoed = pcp_map_request(&nonce, CLIENT, 5555, 5555, 10);
        assert!(pcp_parse_map_response(&echoed, &nonce, 5555).is_err());
        // Port 0 is not a usable grant.
        let zero = pcp_response(&nonce, 0, 100, 5555, 0, None);
        assert!(pcp_parse_map_response(&zero, &nonce, 5555).is_err());
    }

    /// No external address reported is `None`, not the unspecified address.
    #[test]
    fn pcp_unreported_external_address_is_none() {
        let nonce = [1u8; 12];
        let r = pcp_response(&nonce, 0, 60, 7000, 7000, None);
        let g = pcp_parse_map_response(&r, &nonce, 7000).unwrap();
        assert_eq!(g.external_ip, None);
    }

    // ----- NAT-PMP ---------------------------------------------------------

    fn pmp_response(result: u16, internal: u16, external: u16, lifetime: u32) -> Vec<u8> {
        let mut m = Vec::with_capacity(16);
        m.push(PMP_VERSION);
        m.push(PMP_RESPONSE_BIT + PMP_OP_MAP_UDP);
        m.extend_from_slice(&result.to_be_bytes());
        m.extend_from_slice(&11u32.to_be_bytes()); // epoch
        m.extend_from_slice(&internal.to_be_bytes());
        m.extend_from_slice(&external.to_be_bytes());
        m.extend_from_slice(&lifetime.to_be_bytes());
        m
    }

    #[test]
    fn natpmp_roundtrip_and_refusals() {
        let req = pmp_map_request(5555, 5555, 3600);
        assert_eq!(req.len(), 12);
        assert_eq!(req[0], PMP_VERSION);
        assert_eq!(req[1], PMP_OP_MAP_UDP);
        assert_eq!(u32::from_be_bytes(req[8..12].try_into().unwrap()), 3600);

        let ok = pmp_response(0, 5555, 40001, 1800);
        let g = pmp_parse_map_response(&ok, 5555).unwrap();
        assert_eq!((g.external_port, g.lifetime), (40001, 1800));
        assert_eq!(
            g.external_ip, None,
            "NAT-PMP needs a second exchange for it"
        );

        // The only thing binding a response to our request is the port.
        assert!(pmp_parse_map_response(&ok, 5556).is_err());
        let refused = pmp_response(2, 5555, 0, 0);
        let e = pmp_parse_map_response(&refused, 5555)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not authorised"), "{}", e);
        assert!(pmp_parse_map_response(&ok[..10], 5555).is_err());
        // A TCP mapping response is not a UDP one.
        let mut tcp = ok.clone();
        tcp[1] = PMP_RESPONSE_BIT + 2;
        assert!(pmp_parse_map_response(&tcp, 5555).is_err());
    }

    #[test]
    fn natpmp_external_address() {
        let mut m = vec![PMP_VERSION, PMP_RESPONSE_BIT + PMP_OP_EXTERNAL, 0, 0];
        m.extend_from_slice(&5u32.to_be_bytes());
        m.extend_from_slice(&[198, 51, 100, 3]);
        assert_eq!(
            pmp_parse_external_response(&m).unwrap(),
            Ipv4Addr::new(198, 51, 100, 3)
        );
        assert_eq!(pmp_external_request(), [0, 0]);
        // A mapping response is not an address response.
        assert!(pmp_parse_external_response(&pmp_response(0, 1, 2, 3)).is_err());
        assert!(pmp_parse_external_response(&m[..6]).is_err());
    }

    // ----- finding the router ---------------------------------------------

    // ----- a router to ask -------------------------------------------------

    /// What the fake router does with a PCP request.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum PcpAnswer {
        /// Grants the mapping.
        Grant,
        /// Answers the way a NAT-PMP-only box does when it sees a version 2
        /// packet: a NAT-PMP-shaped "unsupported version" (RFC 6886 3.5).
        WrongVersion,
        /// Answers a *different* request's nonce. A confused router, or one
        /// that is not ours.
        ForeignNonce,
    }

    /// A router on loopback, so the whole exchange runs over real sockets.
    async fn fake_router(
        pcp: PcpAnswer,
        natpmp: bool,
        external: u16,
    ) -> Option<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let sock = UdpSocket::bind("127.0.0.1:0").await.ok()?;
        let addr = sock.local_addr().ok()?;
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let req = &buf[..n];
                let reply = if req.first() == Some(&PCP_VERSION) && n >= PCP_REQUEST_LEN {
                    let nonce: [u8; 12] = req[24..36].try_into().expect("12 bytes");
                    let internal = u16::from_be_bytes([req[40], req[41]]);
                    let lifetime = u32::from_be_bytes(req[4..8].try_into().unwrap());
                    match pcp {
                        PcpAnswer::Grant => {
                            pcp_response(&nonce, 0, lifetime, internal, external, None)
                        }
                        PcpAnswer::ForeignNonce => {
                            pcp_response(&[0xEE; 12], 0, lifetime, internal, external, None)
                        }
                        PcpAnswer::WrongVersion => {
                            vec![PMP_VERSION, PMP_RESPONSE_BIT, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
                        }
                    }
                } else if natpmp && req.first() == Some(&PMP_VERSION) && n >= 2 {
                    match req.get(1) {
                        Some(&PMP_OP_MAP_UDP) if n >= 12 => {
                            let internal = u16::from_be_bytes([req[4], req[5]]);
                            let lifetime = u32::from_be_bytes(req[8..12].try_into().unwrap());
                            // A lifetime of 0 is a removal; acknowledge it
                            // with the port it asked about.
                            pmp_response(0, internal, external, lifetime)
                        }
                        Some(&PMP_OP_EXTERNAL) => {
                            let mut m = vec![PMP_VERSION, PMP_RESPONSE_BIT, 0, 0];
                            m.extend_from_slice(&1u32.to_be_bytes());
                            m.extend_from_slice(&[198, 51, 100, 7]);
                            m
                        }
                        _ => continue,
                    }
                } else {
                    continue;
                };
                let _ = sock.send_to(&reply, from).await;
            }
        });
        Some((addr, task))
    }

    const LOCAL: Ipv4Addr = Ipv4Addr::LOCALHOST;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pcp_grants_a_forward_and_gives_it_back() {
        let Some((router, task)) = fake_router(PcpAnswer::Grant, false, 41000).await else {
            return;
        };
        let m = request_at(router, LOCAL, 5555, 3600)
            .await
            .expect("the router grants the mapping");
        assert_eq!(m.protocol(), Protocol::Pcp);
        assert_eq!(m.external_port(), 41000);
        assert_eq!(m.lifetime(), 3600);
        assert_eq!(m.internal(), SocketAddrV4::new(LOCAL, 5555));
        m.refresh(3600).await.expect("the lease renews");
        m.remove().await.expect("the mapping is given back");
        task.abort();
    }

    /// A router that only speaks the older protocol still gets us a forward.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn natpmp_takes_over_when_pcp_is_not_understood() {
        let Some((router, task)) = fake_router(PcpAnswer::WrongVersion, true, 40002).await else {
            return;
        };
        let m = request_at(router, LOCAL, 5555, 1200)
            .await
            .expect("NAT-PMP grants the mapping");
        assert_eq!(m.protocol(), Protocol::NatPmp);
        assert_eq!(m.external_port(), 40002);
        // NAT-PMP learns the external address in a second exchange.
        assert_eq!(
            m.external_addr(),
            Some("198.51.100.7:40002".parse().unwrap())
        );
        m.refresh(1200).await.expect("the lease renews");
        task.abort();
    }

    /// The nonce is what binds a PCP answer to our request. An answer
    /// carrying somebody else's must not be taken for ours — even though it
    /// is otherwise perfectly well formed and says "success".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pcp_answer_to_another_request_is_not_ours() {
        let Some((router, task)) = fake_router(PcpAnswer::ForeignNonce, true, 40003).await else {
            return;
        };
        let m = request_at(router, LOCAL, 5555, 600)
            .await
            .expect("the older protocol still works");
        assert_eq!(
            m.protocol(),
            Protocol::NatPmp,
            "the PCP answer should have been refused"
        );
        task.abort();

        // With nothing else on offer, there is no mapping at all.
        let Some((router, task)) = fake_router(PcpAnswer::ForeignNonce, false, 40004).await else {
            return;
        };
        assert!(request_at(router, LOCAL, 5555, 600).await.is_err());
        task.abort();
    }

    #[test]
    fn gateway_candidates_are_plausible_and_bounded() {
        let gws = gateway_candidates();
        assert!(gws.len() <= 4);
        for gw in &gws {
            assert!(!gw.is_loopback(), "{} is loopback", gw);
            assert!(!gw.is_unspecified());
        }
        let mut sorted = gws.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), gws.len(), "duplicates in {:?}", gws);
    }
}
