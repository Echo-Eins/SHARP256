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
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
/// A Binding indication: sent, never answered (RFC 8489 section 6.3.2).
const BINDING_INDICATION: u16 = 0x0011;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// RFC 3489 SOURCE-ADDRESS, superseded by RESPONSE-ORIGIN.
const ATTR_SOURCE_ADDRESS: u16 = 0x0004;
/// RFC 3489 CHANGED-ADDRESS, superseded by OTHER-ADDRESS.
const ATTR_CHANGED_ADDRESS: u16 = 0x0005;
const ATTR_CHANGE_REQUEST: u16 = 0x0003;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// RFC 5780: the port the response is to go to, instead of the one the
/// request came from (section 7.5).
const ATTR_RESPONSE_PORT: u16 = 0x0027;
/// RFC 5780: address the response was sent from.
const ATTR_RESPONSE_ORIGIN: u16 = 0x802b;
/// RFC 5780: the server's second address and port.
const ATTR_OTHER_ADDRESS: u16 = 0x802c;
const STUN_HEADER_LEN: usize = 20;
/// RFC 8489: a textual description of the software; comprehension-optional,
/// so every server ignores what it does not need of it.
const ATTR_SOFTWARE: u16 = 0x8022;
/// The length every Binding request of ours is padded to.
///
/// A STUN server answers the address a request came from, which nobody has
/// proven, and the answer is longer than a bare request: a server that
/// answered every 20-byte request with 56 bytes (IPv4) or 92 (IPv6) would
/// hand anyone who forged a source address almost five times what they
/// sent. `sharp-relay`'s server answers only a request at least as long as
/// its answer; this is longer than its longest (three IPv6 addresses, 92
/// bytes), with room for more. The padding is a SOFTWARE attribute:
/// RFC 5780's PADDING would be the attribute made for it, but it is one a
/// server has to understand, and one that does not must refuse the request
/// (RFC 8489 section 7.3.1, error 420), where SOFTWARE is one every server
/// may ignore. (Google's and Cloudflare's public servers answer both.)
pub const REQUEST_LEN: usize = 128;

/// CHANGE-REQUEST flag: answer from the other IP address.
const CHANGE_IP: u32 = 0x04;
/// CHANGE-REQUEST flag: answer from the other port.
const CHANGE_PORT: u32 = 0x02;

/// True for datagrams that look like STUN Binding responses.
///
/// A transport packet begins with a random 64-bit connection id, and no
/// endpoint ever picks one whose second four bytes are the STUN cookie
/// ([`crate::protocol::constants::is_usable_cid`]), so the two cannot be
/// confused: every packet this says yes to really is STUN-shaped.
pub fn is_stun_response(pkt: &[u8]) -> bool {
    if pkt.len() < STUN_HEADER_LEN {
        return false;
    }
    let msg_type = u16::from_be_bytes([pkt[0], pkt[1]]);
    (msg_type == BINDING_SUCCESS || msg_type == BINDING_ERROR)
        && pkt[4..8] == STUN_MAGIC_COOKIE.to_be_bytes()
}

/// True for a STUN Binding *request*. The hairpinning test (RFC 5780
/// section 4.5) works by sending one to our own mapped address and seeing
/// whether the NAT loops it back to us, so the receiver has to recognise
/// these too.
pub fn is_stun_request(pkt: &[u8]) -> bool {
    pkt.len() >= STUN_HEADER_LEN
        && u16::from_be_bytes([pkt[0], pkt[1]]) == BINDING_REQUEST
        && pkt[4..8] == STUN_MAGIC_COOKIE.to_be_bytes()
}

/// True for any STUN message the discovery task may need to see.
pub fn is_stun_message(pkt: &[u8]) -> bool {
    is_stun_response(pkt) || is_stun_request(pkt)
}

/// The transaction id of a STUN message, if it is long enough to have one.
pub fn message_transaction_id(pkt: &[u8]) -> Option<[u8; 12]> {
    pkt.get(8..20)?.try_into().ok()
}

/// A random 96-bit transaction id from a cryptographically secure generator
/// (RFC 8489 section 6).
pub fn transaction_id() -> [u8; 12] {
    let mut tid = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut tid);
    tid
}

/// Binding request without attributes.
pub fn binding_request(tid: &[u8; 12]) -> Vec<u8> {
    binding_request_with_change(tid, false, false)
}

/// Binding request carrying CHANGE-REQUEST (RFC 5780 section 7.2), which
/// asks the server to answer from its other IP address and/or its other
/// port. Whether such an answer gets back to us is what reveals the NAT's
/// filtering behaviour.
pub fn binding_request_with_change(tid: &[u8; 12], change_ip: bool, change_port: bool) -> Vec<u8> {
    let mut msg = request_head(tid);
    if change_ip || change_port {
        let mut flags = 0u32;
        if change_ip {
            flags |= CHANGE_IP;
        }
        if change_port {
            flags |= CHANGE_PORT;
        }
        msg.extend_from_slice(&ATTR_CHANGE_REQUEST.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&flags.to_be_bytes());
    }
    padded(msg)
}

/// A Binding request's header; the length is [`padded`]'s to set.
fn request_head(tid: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(REQUEST_LEN);
    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(tid);
    msg
}

/// Pads a request to [`REQUEST_LEN`] with a SOFTWARE attribute and writes
/// its length.
fn padded(mut msg: Vec<u8>) -> Vec<u8> {
    const NAME: &[u8] = b"SHARP-256";
    let value = REQUEST_LEN.saturating_sub(msg.len() + 4).max(NAME.len());
    msg.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    msg.extend_from_slice(&(value as u16).to_be_bytes());
    msg.extend_from_slice(NAME);
    msg.resize(msg.len() + value - NAME.len(), b' ');
    msg.resize(msg.len() + (4 - value % 4) % 4, 0);
    let body = (msg.len() - STUN_HEADER_LEN) as u16;
    msg[2..4].copy_from_slice(&body.to_be_bytes());
    msg
}

/// Binding request carrying RESPONSE-PORT (RFC 5780 section 7.5): the
/// server is to answer to the source IP address of the request but this
/// port. Measuring how long a NAT keeps an idle mapping rests on it (RFC
/// 5780 section 4.6): a request from one socket asks for the answer to be
/// sent to another socket's mapping, and whether it arrives says whether
/// that mapping still exists.
pub fn binding_request_with_response_port(tid: &[u8; 12], port: u16) -> Vec<u8> {
    let mut msg = request_head(tid);
    msg.extend_from_slice(&ATTR_RESPONSE_PORT.to_be_bytes());
    msg.extend_from_slice(&4u16.to_be_bytes());
    msg.extend_from_slice(&port.to_be_bytes());
    msg.extend_from_slice(&[0, 0]);
    padded(msg)
}

/// A Binding indication (RFC 8489 section 6.3.2): a message a server
/// takes in and never answers. It is what keeps a NAT mapping towards the
/// server alive (RFC 8445 section 11) without costing the server a reply.
pub fn binding_indication(tid: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(STUN_HEADER_LEN);
    msg.extend_from_slice(&BINDING_INDICATION.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(tid);
    msg
}

/// Encodes an address the plain way (MAPPED-ADDRESS, RESPONSE-ORIGIN,
/// OTHER-ADDRESS), or XOR-ed against the cookie and transaction id when
/// `xor_tid` is given (XOR-MAPPED-ADDRESS).
pub fn encode_address(addr: SocketAddr, xor_tid: Option<&[u8; 12]>) -> Vec<u8> {
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    let mut port = addr.port();
    if xor_tid.is_some() {
        port ^= (STUN_MAGIC_COOKIE >> 16) as u16;
    }
    let mut out = Vec::with_capacity(20);
    out.push(0);
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&port.to_be_bytes());
            let mut ip = v4.octets();
            if xor_tid.is_some() {
                for (b, c) in ip.iter_mut().zip(cookie) {
                    *b ^= c;
                }
            }
            out.extend_from_slice(&ip);
        }
        std::net::IpAddr::V6(v6) => {
            out.push(0x02);
            out.extend_from_slice(&port.to_be_bytes());
            let mut ip = v6.octets();
            if let Some(tid) = xor_tid {
                let mask = cookie.iter().chain(tid.iter());
                for (b, m) in ip.iter_mut().zip(mask) {
                    *b ^= m;
                }
            }
            out.extend_from_slice(&ip);
        }
    }
    out
}

/// Builds a Binding success response.
///
/// SHARP-256 needs to *answer* Binding requests, not only send them: a
/// connectivity check between two candidate addresses is a Binding request
/// that the far end has to reply to. The behaviour tests are exercised
/// against a server built from this too.
pub fn binding_success(
    tid: &[u8; 12],
    mapped: SocketAddr,
    response_origin: Option<SocketAddr>,
    other_address: Option<SocketAddr>,
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut attr = |t: u16, v: Vec<u8>| {
        body.extend_from_slice(&t.to_be_bytes());
        body.extend_from_slice(&(v.len() as u16).to_be_bytes());
        body.extend_from_slice(&v);
        // Attributes are padded to a multiple of four bytes.
        body.resize(body.len() + (4 - v.len() % 4) % 4, 0);
    };
    attr(ATTR_XOR_MAPPED_ADDRESS, encode_address(mapped, Some(tid)));
    if let Some(o) = response_origin {
        attr(ATTR_RESPONSE_ORIGIN, encode_address(o, None));
    }
    if let Some(o) = other_address {
        attr(ATTR_OTHER_ADDRESS, encode_address(o, None));
    }
    let mut msg = Vec::with_capacity(STUN_HEADER_LEN + body.len());
    msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(tid);
    msg.extend_from_slice(&body);
    msg
}

/// The CHANGE-REQUEST flags a Binding request carries, as
/// `(change_ip, change_port)`. Both false when the attribute is absent.
pub fn requested_change(pkt: &[u8]) -> (bool, bool) {
    let Some(len) = pkt
        .get(2..4)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
    else {
        return (false, false);
    };
    let Some(body) = pkt.get(STUN_HEADER_LEN..STUN_HEADER_LEN + len) else {
        return (false, false);
    };
    let mut pos = 0;
    while pos + 4 <= body.len() {
        let attr = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let alen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        let end = pos + 4 + alen;
        if end > body.len() {
            break;
        }
        if attr == ATTR_CHANGE_REQUEST && alen >= 4 {
            let flags = u32::from_be_bytes(body[pos + 4..pos + 8].try_into().unwrap());
            return (flags & CHANGE_IP != 0, flags & CHANGE_PORT != 0);
        }
        pos = end + (4 - alen % 4) % 4;
    }
    (false, false)
}

/// The RESPONSE-PORT a Binding request carries, if any (what a server
/// supporting RFC 5780 reads; the tests' servers read it with this).
pub fn requested_response_port(pkt: &[u8]) -> Option<u16> {
    let len = u16::from_be_bytes([*pkt.get(2)?, *pkt.get(3)?]) as usize;
    let body = pkt.get(STUN_HEADER_LEN..STUN_HEADER_LEN + len)?;
    let mut pos = 0;
    while pos + 4 <= body.len() {
        let attr = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let alen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        let end = pos + 4 + alen;
        if end > body.len() {
            return None;
        }
        if attr == ATTR_RESPONSE_PORT && alen >= 2 {
            return Some(u16::from_be_bytes([body[pos + 4], body[pos + 5]]));
        }
        pos = end + (4 - alen % 4) % 4;
    }
    None
}

/// What one Binding success response tells us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingResponse {
    /// Our address as the server saw it (XOR-MAPPED-ADDRESS, or the legacy
    /// MAPPED-ADDRESS).
    pub mapped: SocketAddr,
    /// The address the server answered from (RESPONSE-ORIGIN, or the legacy
    /// SOURCE-ADDRESS). With CHANGE-REQUEST this is how we tell which of the
    /// server's addresses actually answered.
    pub response_origin: Option<SocketAddr>,
    /// The server's *other* address and port (OTHER-ADDRESS, or the legacy
    /// CHANGED-ADDRESS). Only a server that has two of each can be used for
    /// the behaviour tests of RFC 5780.
    pub other_address: Option<SocketAddr>,
}

/// Extracts the mapped address from a Binding success response for `tid`.
/// XOR-MAPPED-ADDRESS is preferred; MAPPED-ADDRESS is accepted from legacy
/// servers.
pub fn parse_mapped_address(data: &[u8], tid: &[u8; 12]) -> Result<SocketAddr> {
    Ok(parse_binding_response(data, tid)?.mapped)
}

/// Parses a Binding success response for `tid` into everything it carries.
pub fn parse_binding_response(data: &[u8], tid: &[u8; 12]) -> Result<BindingResponse> {
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
    let mut xor_mapped = None;
    let mut legacy_mapped = None;
    let mut response_origin = None;
    let mut other_address = None;
    while pos + 4 <= body.len() {
        let attr = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let alen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        let start = pos + 4;
        let end = start + alen;
        if end > body.len() {
            bail!("STUN attribute overruns the message");
        }
        let value = &body[start..end];
        // A malformed address in an attribute we do not need must not throw
        // the whole response away.
        match attr {
            ATTR_XOR_MAPPED_ADDRESS => xor_mapped = Some(parse_address(value, Some(tid))?),
            ATTR_MAPPED_ADDRESS => legacy_mapped = parse_address(value, None).ok(),
            ATTR_RESPONSE_ORIGIN | ATTR_SOURCE_ADDRESS => {
                response_origin = response_origin.or(parse_address(value, None).ok());
            }
            ATTR_OTHER_ADDRESS | ATTR_CHANGED_ADDRESS => {
                other_address = other_address.or(parse_address(value, None).ok());
            }
            _ => {}
        }
        pos = end + (4 - alen % 4) % 4;
    }
    let mapped = xor_mapped
        .or(legacy_mapped)
        .ok_or_else(|| anyhow!("no mapped address in STUN response"))?;
    Ok(BindingResponse {
        mapped,
        response_origin,
        other_address,
    })
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

/// A STUN datagram that arrived on the transfer socket, with the address the
/// socket saw it come from. The source address is kept because a STUN server
/// is an unauthenticated stranger: what it *claims* in RESPONSE-ORIGIN is
/// worth checking against where the packet actually came from.
pub type Incoming = (Vec<u8>, SocketAddr);

/// A parsed reply and where it really came from.
#[derive(Debug, Clone, Copy)]
pub struct StunReply {
    pub response: BindingResponse,
    pub from: SocketAddr,
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

    pub fn with_timing(mut self, per_try: Duration, tries: u32) -> Self {
        self.per_try = per_try;
        self.tries = tries.max(1);
        self
    }

    pub fn servers(&self) -> &[String] {
        &self.servers
    }

    /// One Binding transaction. `change_ip` / `change_port` ask the server to
    /// answer from its other address and/or port (RFC 5780).
    ///
    /// Returns `Ok(None)` when nothing came back: for a filtering test that
    /// silence *is* the result, not an error. `Err` means the response
    /// channel is gone or the socket refused the send.
    pub async fn transaction(
        &self,
        socket: &UdpSocket,
        server: SocketAddr,
        responses: &mut mpsc::Receiver<Incoming>,
        change_ip: bool,
        change_port: bool,
    ) -> Result<Option<StunReply>> {
        let tid = transaction_id();
        let request = binding_request_with_change(&tid, change_ip, change_port);
        for _ in 0..self.tries {
            socket.send_to(&request, server).await?;
            let deadline = Instant::now() + self.per_try;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                match tokio::time::timeout(left, responses.recv()).await {
                    // Anything for another transaction (a late answer, or a
                    // stranger's packet that merely looks like STUN) is
                    // dropped: the transaction id is what binds a reply to
                    // its request.
                    Ok(Some((pkt, from))) => {
                        if message_transaction_id(&pkt) != Some(tid) {
                            continue;
                        }
                        // A plain request is answered by the server it went
                        // to, and by nobody else: the transaction id travels
                        // in the clear, so anyone who sees the request can
                        // answer it too. A CHANGE-REQUEST is answered from
                        // elsewhere by design; where it came from is the
                        // result, and the tests judge it themselves.
                        if !(change_ip || change_port) && from != server {
                            continue;
                        }
                        if u16::from_be_bytes([pkt[0], pkt[1]]) == BINDING_ERROR {
                            // Refused outright (a server without RFC 5780
                            // answers a CHANGE-REQUEST with 420): that is not
                            // silence, and waiting out the other tries for
                            // an answer that is not coming would make it
                            // look like some.
                            bail!("{} refused the request", server);
                        }
                        if let Ok(response) = parse_binding_response(&pkt, &tid) {
                            return Ok(Some(StunReply { response, from }));
                        }
                    }
                    Ok(None) => bail!("STUN response channel closed"),
                    Err(_) => break,
                }
            }
        }
        Ok(None)
    }

    /// Asks one server for the mapped address of `socket`.
    pub async fn query(
        &self,
        socket: &UdpSocket,
        server: SocketAddr,
        responses: &mut mpsc::Receiver<Incoming>,
    ) -> Result<SocketAddr> {
        match self
            .transaction(socket, server, responses, false, false)
            .await?
        {
            Some(r) => Ok(r.response.mapped),
            None => bail!("no answer from STUN server {}", server),
        }
    }

    /// Mapped addresses reported by up to `want` different servers.
    pub async fn mapped_addresses(
        &self,
        socket: &UdpSocket,
        responses: &mut mpsc::Receiver<Incoming>,
        want: usize,
    ) -> Vec<SocketAddr> {
        let reach = crate::address::Reach::of(socket);
        let family = (reach.v4() && reach.v6()).then_some(false);
        let mut out = Vec::new();
        for server in &self.servers {
            if out.len() >= want {
                break;
            }
            let Some(addr) = resolve_server(server, reach, family).await else {
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

/// Whether an address a server told us about is worth sending a packet to.
///
/// OTHER-ADDRESS comes from an unauthenticated stranger, and we act on it by
/// sending there. Without this check a hostile STUN server could use every
/// client as a small reflector aimed at an address of its choosing. There is
/// no amplification to be had (we send a request and it draws no reply from
/// the victim), but the packets should not be sent at all.
pub fn is_usable_server_address(addr: SocketAddr, local: SocketAddr) -> bool {
    // One screen for everything a stranger names; see there for why each
    // kind of address is or is not worth a datagram.
    crate::address::class::is_sendable_hint(addr, local)
}

/// Resolves a server name to an address `socket` can reach, written the way
/// that socket sends to it and sees replies from it.
///
/// `family` picks which one a dual-stack socket should use: `Some(true)`
/// for IPv6, `Some(false)` for IPv4, `None` for whichever comes first.
pub async fn resolve_server(
    server: &str,
    reach: crate::address::Reach,
    family: Option<bool>,
) -> Option<SocketAddr> {
    let fits = |a: &SocketAddr| {
        let a = crate::address::canonical(*a);
        family.is_none_or(|v6| a.is_ipv6() == v6) && reach.reaches(a)
    };
    if let Some(addr) = crate::address::dns::parse_literal(server) {
        return fits(&addr).then(|| reach.native(addr)).flatten();
    }
    let (host, port) = crate::address::dns::split_host_port(server).ok()?;
    // Asked for the family wanted, not for "any": the other family's
    // answer is not waited for, and not asked for at all.
    let addrs = match family {
        Some(v6) => {
            let f = if v6 {
                crate::address::dns::Family::V6
            } else {
                crate::address::dns::Family::V4
            };
            tokio::time::timeout(
                Duration::from_secs(2),
                crate::address::dns::lookup(host, port, f),
            )
            .await
            .ok()?
            .ok()?
        }
        None => tokio::time::timeout(Duration::from_secs(2), crate::address::resolve_all(server))
            .await
            .ok()?
            .ok()?,
    };
    addrs
        .into_iter()
        .find(|a| fits(a))
        .and_then(|a| reach.native(a))
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
            parse_mapped_address(&msg, &tid).unwrap(),
            SocketAddr::new(ip.into(), port)
        );
    }

    /// The plain address encoding used by RESPONSE-ORIGIN / OTHER-ADDRESS.
    fn plain_v4(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut v = vec![0, 0x01];
        v.extend_from_slice(&port.to_be_bytes());
        v.extend_from_slice(&ip.octets());
        v
    }

    /// The attributes the behaviour tests of RFC 5780 depend on: where the
    /// answer came from, and the server's second address.
    #[test]
    fn parses_response_origin_and_other_address() {
        let tid = transaction_id();
        let msg = response(
            &tid,
            &[
                (
                    ATTR_XOR_MAPPED_ADDRESS,
                    xor_v4(Ipv4Addr::new(203, 0, 113, 7), 40000),
                ),
                (
                    ATTR_RESPONSE_ORIGIN,
                    plain_v4(Ipv4Addr::new(198, 51, 100, 1), 3478),
                ),
                (
                    ATTR_OTHER_ADDRESS,
                    plain_v4(Ipv4Addr::new(198, 51, 100, 2), 3479),
                ),
            ],
        );
        let r = parse_binding_response(&msg, &tid).unwrap();
        assert_eq!(r.mapped, "203.0.113.7:40000".parse().unwrap());
        assert_eq!(r.response_origin, "198.51.100.1:3478".parse().ok());
        assert_eq!(r.other_address, "198.51.100.2:3479".parse().ok());

        // The legacy RFC 3489 spellings carry the same meaning.
        let legacy = response(
            &tid,
            &[
                (
                    ATTR_XOR_MAPPED_ADDRESS,
                    xor_v4(Ipv4Addr::new(203, 0, 113, 7), 40000),
                ),
                (
                    ATTR_SOURCE_ADDRESS,
                    plain_v4(Ipv4Addr::new(198, 51, 100, 1), 3478),
                ),
                (
                    ATTR_CHANGED_ADDRESS,
                    plain_v4(Ipv4Addr::new(198, 51, 100, 2), 3479),
                ),
            ],
        );
        let r = parse_binding_response(&legacy, &tid).unwrap();
        assert_eq!(r.response_origin, "198.51.100.1:3478".parse().ok());
        assert_eq!(r.other_address, "198.51.100.2:3479".parse().ok());
    }

    #[test]
    fn change_request_carries_the_asked_for_flags() {
        let tid = transaction_id();
        for (ip, port, want) in [
            (false, true, CHANGE_PORT),
            (true, false, CHANGE_IP),
            (true, true, CHANGE_IP | CHANGE_PORT),
        ] {
            let req = binding_request_with_change(&tid, ip, port);
            assert!(is_stun_request(&req) && !is_stun_response(&req));
            assert_eq!(message_transaction_id(&req), Some(tid));
            let attr = u16::from_be_bytes([req[20], req[21]]);
            assert_eq!(attr, ATTR_CHANGE_REQUEST);
            let flags = u32::from_be_bytes(req[24..28].try_into().unwrap());
            assert_eq!(flags, want);
            assert_eq!(requested_change(&req), (ip, port));
        }
    }

    /// Every request is padded to the same length, which is what a server
    /// that answers no more than it was sent needs; the padding is a
    /// well-formed SOFTWARE attribute that closes the message.
    #[test]
    fn every_request_is_padded_with_software() {
        let tid = transaction_id();
        for req in [
            binding_request(&tid),
            binding_request_with_change(&tid, true, true),
            binding_request_with_response_port(&tid, 40000),
        ] {
            assert_eq!(req.len(), REQUEST_LEN);
            assert!(is_stun_request(&req));
            assert_eq!(
                u16::from_be_bytes([req[2], req[3]]) as usize,
                REQUEST_LEN - STUN_HEADER_LEN
            );
            // Walk the attributes: they end exactly at the end, the last
            // is SOFTWARE, and it names us.
            let (mut pos, mut last) = (STUN_HEADER_LEN, None);
            while pos < req.len() {
                let t = u16::from_be_bytes([req[pos], req[pos + 1]]);
                let l = u16::from_be_bytes([req[pos + 2], req[pos + 3]]) as usize;
                last = Some((t, pos + 4, l));
                pos += 4 + l + (4 - l % 4) % 4;
            }
            assert_eq!(pos, req.len());
            let (t, at, l) = last.unwrap();
            assert_eq!(t, ATTR_SOFTWARE);
            assert!(l < 128);
            assert!(req[at..at + l].starts_with(b"SHARP-256"));
            assert!(std::str::from_utf8(&req[at..at + l]).is_ok());
        }
        assert_eq!(
            requested_response_port(&binding_request_with_response_port(&tid, 40000)),
            Some(40000)
        );
    }

    /// A plain request is answered by the server it went to. The
    /// transaction id travels in the clear, so anyone who sees the request
    /// can answer it — and used to be believed, whatever it said our
    /// address was. And a server that refuses a request says so, which is
    /// not the same as silence.
    #[tokio::test]
    async fn only_the_server_asked_can_answer_and_a_refusal_is_not_silence() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = server_sock.local_addr().unwrap();
        let stranger: SocketAddr = "127.0.0.9:3478".parse().unwrap();
        let (tx, mut rx) = mpsc::channel::<Incoming>(8);
        let client = StunClient::new(vec![]).with_timing(Duration::from_millis(300), 1);

        let genuine: SocketAddr = "198.51.100.1:40000".parse().unwrap();
        let forged: SocketAddr = "203.0.113.66:1".parse().unwrap();
        let answer = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = server_sock.recv_from(&mut buf).await.unwrap();
            let tid = message_transaction_id(&buf[..n]).unwrap();
            tx.send((binding_success(&tid, forged, None, None), stranger))
                .await
                .unwrap();
            tx.send((binding_success(&tid, genuine, None, None), server))
                .await
                .unwrap();
            let _ = from;
            (server_sock, tx)
        });
        let reply = client
            .transaction(&sock, server, &mut rx, false, false)
            .await
            .unwrap()
            .expect("the server answered");
        assert_eq!(reply.from, server);
        assert_eq!(
            reply.response.mapped, genuine,
            "a stranger's answer was believed"
        );

        // A refusal ends the transaction at once, as an error.
        let (server_sock, tx) = answer.await.unwrap();
        let refuse = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, _) = server_sock.recv_from(&mut buf).await.unwrap();
            let mut err = buf[..n].to_vec();
            err[0..2].copy_from_slice(&BINDING_ERROR.to_be_bytes());
            err[2..4].copy_from_slice(&0u16.to_be_bytes());
            err.truncate(20);
            tx.send((err, server)).await.unwrap();
        });
        let client = StunClient::new(vec![]).with_timing(Duration::from_secs(5), 3);
        let started = std::time::Instant::now();
        assert!(client
            .transaction(&sock, server, &mut rx, true, true)
            .await
            .is_err());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "waited out a refusal"
        );
        refuse.await.unwrap();
    }

    /// An address a stranger told us to send to is filtered: loopback,
    /// multicast, link-local, port 0 and anything the socket cannot reach
    /// are all refused, in whichever spelling they come.
    #[test]
    fn server_addresses_are_screened_before_we_send_there() {
        let v4: SocketAddr = "198.51.100.1:3478".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:3478".parse().unwrap();
        assert!(is_usable_server_address(
            "198.51.100.2:3479".parse().unwrap(),
            v4
        ));
        for bad in [
            "127.0.0.1:3478",
            "0.0.0.0:3478",
            "224.0.0.1:3478",
            "255.255.255.255:3478",
            "169.254.1.1:3478",
            "198.51.100.2:0",
        ] {
            assert!(
                !is_usable_server_address(bad.parse().unwrap(), v4),
                "{} accepted",
                bad
            );
        }
        // The socket we would send from has to be able to reach it.
        assert!(!is_usable_server_address(v6, v4));
        assert!(!is_usable_server_address(v4, v6));
        assert!(is_usable_server_address(
            "[2001:db8::2]:3479".parse().unwrap(),
            v6
        ));
        assert!(!is_usable_server_address("[::1]:3479".parse().unwrap(), v6));
        // Link-local means nothing without the interface it belongs to.
        assert!(!is_usable_server_address(
            "[fe80::1]:3479".parse().unwrap(),
            v6
        ));

        // "This network" is nobody's address.
        assert!(!is_usable_server_address(
            "0.1.2.3:3478".parse().unwrap(),
            v4
        ));

        // A dual-stack socket sees IPv4 in its mapped spelling, and the
        // screen must see through it: loopback, multicast and broadcast in
        // disguise are what they are.
        let dual: SocketAddr = "[::]:5555".parse().unwrap();
        for bad in [
            "[::ffff:127.0.0.1]:3478",
            "[::ffff:224.0.0.1]:3478",
            "[::ffff:255.255.255.255]:3478",
            "[::ffff:169.254.1.1]:3478",
            "[::ffff:0.0.0.0]:3478",
        ] {
            assert!(
                !is_usable_server_address(bad.parse().unwrap(), dual),
                "{} accepted",
                bad
            );
        }
        assert!(is_usable_server_address(
            "[::ffff:198.51.100.2]:3479".parse().unwrap(),
            dual
        ));
        assert!(is_usable_server_address(
            "198.51.100.2:3479".parse().unwrap(),
            dual
        ));
        // And an IPv4 socket told about a mapped address can reach it.
        assert!(is_usable_server_address(
            "[::ffff:198.51.100.2]:3479".parse().unwrap(),
            v4
        ));

        // From loopback, loopback is fine: a server on this host, and the
        // simulated NAT the behaviour tests run against.
        let local: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        assert!(is_usable_server_address(
            "127.0.0.2:3478".parse().unwrap(),
            local
        ));
        assert!(!is_usable_server_address(
            "224.0.0.1:3478".parse().unwrap(),
            local
        ));
    }

    /// A response we build is a response we can read back.
    #[test]
    fn binding_success_roundtrips() {
        let tid = transaction_id();
        let mapped: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let origin: SocketAddr = "198.51.100.1:3478".parse().unwrap();
        let other: SocketAddr = "198.51.100.2:3479".parse().unwrap();
        let msg = binding_success(&tid, mapped, Some(origin), Some(other));
        assert!(is_stun_response(&msg));
        let r = parse_binding_response(&msg, &tid).unwrap();
        assert_eq!(r.mapped, mapped);
        assert_eq!(r.response_origin, Some(origin));
        assert_eq!(r.other_address, Some(other));

        // IPv6 and the minimal form with no optional attributes.
        let v6m: SocketAddr = "[2001:db8::5]:1234".parse().unwrap();
        let bare = binding_success(&tid, v6m, None, None);
        let r = parse_binding_response(&bare, &tid).unwrap();
        assert_eq!(r.mapped, v6m);
        assert_eq!(r.response_origin, None);
        assert_eq!(r.other_address, None);
    }

    #[test]
    fn change_request_flags_are_read_back() {
        let tid = transaction_id();
        assert_eq!(requested_change(&binding_request(&tid)), (false, false));
        for (ip, port) in [(false, true), (true, false), (true, true)] {
            let req = binding_request_with_change(&tid, ip, port);
            assert_eq!(requested_change(&req), (ip, port));
        }
        // Nonsense must not panic.
        assert_eq!(requested_change(b""), (false, false));
        assert_eq!(requested_change(&[0u8; 24]), (false, false));
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
            parse_mapped_address(&msg, &tid).unwrap(),
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
            parse_mapped_address(&msg, &tid).unwrap(),
            "198.51.100.9:5555".parse::<SocketAddr>().unwrap()
        );
        // Wrong transaction id, truncated message, SHARP datagram.
        assert!(parse_mapped_address(&msg, &transaction_id()).is_err());
        assert!(parse_mapped_address(&msg[..msg.len() - 3], &tid).is_err());
        assert!(!is_stun_response(b"SH\x02\x03................"));
        assert!(is_stun_response(&msg));
        let req = binding_request(&tid);
        assert!(!is_stun_response(&req));
    }
}
