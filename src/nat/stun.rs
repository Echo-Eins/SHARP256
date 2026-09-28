//! Minimal STUN client (RFC 8489 Binding requests) used by the receiver to
//! learn the public address its transfer socket is mapped to.
//!
//! Requests go out on the transfer socket itself (the mapping of *that*
//! socket is what matters); responses are handed over by the receiver's
//! dispatcher through a channel, so discovery never competes with the
//! transport for incoming datagrams.

use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::mpsc;

pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_HEADER_LEN: usize = 20;

/// True for datagrams that look like STUN Binding responses. SHARP datagrams
/// start with "SH", so the two can never be confused.
pub fn is_stun_response(pkt: &[u8]) -> bool {
    if pkt.len() < STUN_HEADER_LEN {
        return false;
    }
    let msg_type = u16::from_be_bytes([pkt[0], pkt[1]]);
    (msg_type == BINDING_SUCCESS || msg_type == BINDING_ERROR)
        && pkt[4..8] == STUN_MAGIC_COOKIE.to_be_bytes()
}

/// A random 96-bit transaction id from a cryptographically secure generator
/// (RFC 8489 section 6).
pub fn transaction_id() -> [u8; 12] {
    let mut tid = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut tid);
    tid
}

/// Binding request without attributes.
pub fn binding_request(tid: &[u8; 12]) -> [u8; STUN_HEADER_LEN] {
    let mut msg = [0u8; STUN_HEADER_LEN];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // message length 0
    msg[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg[8..20].copy_from_slice(tid);
    msg
}

/// Extracts the mapped address from a Binding success response for `tid`.
/// XOR-MAPPED-ADDRESS is preferred; MAPPED-ADDRESS is accepted from legacy
/// servers.
pub fn parse_binding_response(data: &[u8], tid: &[u8; 12]) -> Result<SocketAddr> {
    if data.len() < STUN_HEADER_LEN {
        bail!("STUN response too short");
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if data[4..8] != STUN_MAGIC_COOKIE.to_be_bytes() {
        bail!("bad STUN magic cookie");
    }
    if data[8..20] != tid[..] {
        bail!("STUN transaction id mismatch");
    }
    if msg_type == BINDING_ERROR {
        bail!("STUN server returned an error response");
    }
    if msg_type != BINDING_SUCCESS {
        bail!("not a STUN binding response");
    }
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if len % 4 != 0 || STUN_HEADER_LEN + len > data.len() {
        bail!("bad STUN message length");
    }
    let body = &data[STUN_HEADER_LEN..STUN_HEADER_LEN + len];
    let mut pos = 0;
    let mut legacy = None;
    while pos + 4 <= body.len() {
        let attr = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let alen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        let start = pos + 4;
        let end = start + alen;
        if end > body.len() {
            bail!("STUN attribute overruns the message");
        }
        let value = &body[start..end];
        match attr {
            ATTR_XOR_MAPPED_ADDRESS => return parse_address(value, Some(tid)),
            ATTR_MAPPED_ADDRESS => legacy = Some(parse_address(value, None)?),
            _ => {}
        }
        pos = end + (4 - alen % 4) % 4;
    }
    legacy.ok_or_else(|| anyhow!("no mapped address in STUN response"))
}

fn parse_address(value: &[u8], xor_tid: Option<&[u8; 12]>) -> Result<SocketAddr> {
    if value.len() < 4 {
        bail!("STUN address attribute too short");
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    if xor_tid.is_some() {
        port ^= (STUN_MAGIC_COOKIE >> 16) as u16;
    }
    match family {
        0x01 => {
            if value.len() < 8 {
                bail!("IPv4 STUN address too short");
            }
            let mut ip = [value[4], value[5], value[6], value[7]];
            if xor_tid.is_some() {
                for (b, c) in ip.iter_mut().zip(cookie) {
                    *b ^= c;
                }
            }
            Ok(SocketAddr::new(Ipv4Addr::from(ip).into(), port))
        }
        0x02 => {
            if value.len() < 20 {
                bail!("IPv6 STUN address too short");
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&value[4..20]);
            if let Some(tid) = xor_tid {
                let mask = cookie.iter().chain(tid.iter());
                for (b, m) in ip.iter_mut().zip(mask) {
                    *b ^= m;
                }
            }
            Ok(SocketAddr::new(Ipv6Addr::from(ip).into(), port))
        }
        _ => bail!("unknown STUN address family {}", family),
    }
}

/// STUN client working on a shared socket plus a response channel.
pub struct StunClient {
    servers: Vec<String>,
    per_try: Duration,
    tries: u32,
}

impl StunClient {
    pub fn new(servers: Vec<String>) -> Self {
        Self {
            servers,
            per_try: Duration::from_secs(1),
            tries: 2,
        }
    }

    /// Asks one server for the mapped address of `socket`.
    pub async fn query(
        &self,
        socket: &UdpSocket,
        server: SocketAddr,
        responses: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<SocketAddr> {
        let tid = transaction_id();
        let request = binding_request(&tid);
        for _ in 0..self.tries {
            socket.send_to(&request, server).await?;
            let deadline = Instant::now() + self.per_try;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                match tokio::time::timeout(left, responses.recv()).await {
                    Ok(Some(pkt)) => {
                        if let Ok(addr) = parse_binding_response(&pkt, &tid) {
                            return Ok(addr);
                        }
                    }
                    Ok(None) => bail!("STUN response channel closed"),
                    Err(_) => break,
                }
            }
        }
        bail!("no answer from STUN server {}", server)
    }

    /// Mapped addresses reported by up to `want` different servers.
    pub async fn mapped_addresses(
        &self,
        socket: &UdpSocket,
        responses: &mut mpsc::Receiver<Vec<u8>>,
        want: usize,
    ) -> Vec<SocketAddr> {
        let v6 = socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
        let mut out = Vec::new();
        for server in &self.servers {
            if out.len() >= want {
                break;
            }
            let Some(addr) = resolve(server, v6).await else {
                tracing::debug!("STUN: cannot resolve {}", server);
                continue;
            };
            match self.query(socket, addr, responses).await {
                Ok(mapped) => {
                    tracing::debug!("STUN: {} reports {}", server, mapped);
                    out.push(mapped);
                }
                Err(e) => tracing::debug!("STUN: {}", e),
            }
        }
        out
    }
}

async fn resolve(server: &str, v6: bool) -> Option<SocketAddr> {
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return (addr.is_ipv6() == v6).then_some(addr);
    }
    let mut addrs = tokio::time::timeout(Duration::from_secs(2), lookup_host(server))
        .await
        .ok()?
        .ok()?;
    addrs.find(|a| a.is_ipv6() == v6)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(tid: &[u8; 12], attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            body.resize(body.len() + (4 - v.len() % 4) % 4, 0);
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(tid);
        msg.extend_from_slice(&body);
        msg
    }

    fn xor_v4(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut v = vec![0, 0x01];
        v.extend_from_slice(&(port ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        let c = STUN_MAGIC_COOKIE.to_be_bytes();
        v.extend(ip.octets().iter().zip(c).map(|(a, b)| a ^ b));
        v
    }

    #[test]
    fn parses_ipv6_xor_mapped_address() {
        let tid: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let port: u16 = 54321;
        let mut v = vec![0, 0x02];
        v.extend_from_slice(&(port ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        let mask: Vec<u8> = STUN_MAGIC_COOKIE
            .to_be_bytes()
            .into_iter()
            .chain(tid)
            .collect();
        v.extend(ip.octets().iter().zip(mask).map(|(a, b)| a ^ b));
        let msg = response(&tid, &[(ATTR_XOR_MAPPED_ADDRESS, v)]);
        assert!(is_stun_response(&msg));
        assert_eq!(
            parse_binding_response(&msg, &tid).unwrap(),
            SocketAddr::new(ip.into(), port)
        );
    }

    #[test]
    fn prefers_xor_mapped_and_skips_unknown_attributes() {
        let tid = transaction_id();
        let legacy = {
            let mut v = vec![0, 0x01];
            v.extend_from_slice(&1111u16.to_be_bytes());
            v.extend_from_slice(&[10, 0, 0, 1]);
            v
        };
        let msg = response(
            &tid,
            &[
                (0x8022, b"software/1.0".to_vec()), // SOFTWARE, 12 bytes
                (ATTR_MAPPED_ADDRESS, legacy),
                (0x802b, vec![1, 2, 3]), // odd length, padded
                (
                    ATTR_XOR_MAPPED_ADDRESS,
                    xor_v4(Ipv4Addr::new(203, 0, 113, 7), 40000),
                ),
            ],
        );
        assert_eq!(
            parse_binding_response(&msg, &tid).unwrap(),
            "203.0.113.7:40000".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn accepts_legacy_mapped_address_and_rejects_garbage() {
        let tid = transaction_id();
        let mut v = vec![0, 0x01];
        v.extend_from_slice(&5555u16.to_be_bytes());
        v.extend_from_slice(&[198, 51, 100, 9]);
        let msg = response(&tid, &[(ATTR_MAPPED_ADDRESS, v)]);
        assert_eq!(
            parse_binding_response(&msg, &tid).unwrap(),
            "198.51.100.9:5555".parse::<SocketAddr>().unwrap()
        );
        // Wrong transaction id, truncated message, SHARP datagram.
        assert!(parse_binding_response(&msg, &transaction_id()).is_err());
        assert!(parse_binding_response(&msg[..msg.len() - 3], &tid).is_err());
        assert!(!is_stun_response(b"SH\x02\x03................"));
        assert!(is_stun_response(&msg));
        let req = binding_request(&tid);
        assert!(!is_stun_response(&req));
    }
}
