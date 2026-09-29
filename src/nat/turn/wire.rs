//! The messages of TURN (RFC 8656, with RFC 6156 for IPv6), which are STUN
//! messages (RFC 8489) with a few more methods and attributes, and the
//! ChannelData framing that carries a datagram with four bytes of overhead
//! instead of thirty-six.
//!
//! Everything here is a pure function of bytes: what a server sends is
//! read strictly and bounded (one attribute may not run past the message,
//! nothing is allocated in proportion to what the datagram claims), and what
//! is built is built the one way.

use crate::nat::stun::STUN_MAGIC_COOKIE;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use subtle::ConstantTimeEq;

pub const HEADER_LEN: usize = 20;

// Methods (RFC 8656 section 20 and RFC 8489 section 5).
pub const BINDING: u16 = 0x001;
pub const ALLOCATE: u16 = 0x003;
pub const REFRESH: u16 = 0x004;
pub const SEND: u16 = 0x006;
pub const DATA: u16 = 0x007;
pub const CREATE_PERMISSION: u16 = 0x008;
pub const CHANNEL_BIND: u16 = 0x009;

// Attributes.
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_LIFETIME: u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTR_DONT_FRAGMENT: u16 = 0x001A;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_SOFTWARE: u16 = 0x8022;

/// UDP, the only transport a TURN server relays (RFC 8656 section 12).
pub const TRANSPORT_UDP: u8 = 17;
/// RFC 6156: the family of the relayed address asked for.
pub const FAMILY_IPV4: u8 = 0x01;
pub const FAMILY_IPV6: u8 = 0x02;

/// Channel numbers a client may bind (RFC 8656 section 12).
pub const CHANNEL_MIN: u16 = 0x4000;
pub const CHANNEL_MAX: u16 = 0x4FFF;

/// Longest message read: a TURN server's answers are all small, and one
/// larger than a datagram this size carries is not one.
pub const MAX_MESSAGE: usize = 1500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    Success,
    Error,
}

impl Class {
    fn bits(self) -> u16 {
        match self {
            Class::Request => 0b00,
            Class::Indication => 0b01,
            Class::Success => 0b10,
            Class::Error => 0b11,
        }
    }
}

/// The 14-bit message type: the method's bits with the class's two bits
/// woven in (RFC 8489 section 5).
pub fn message_type(method: u16, class: Class) -> u16 {
    let c = class.bits();
    (method & 0x000F)
        | ((c & 0x1) << 4)
        | ((method & 0x0070) << 1)
        | ((c & 0x2) << 7)
        | ((method & 0x0F80) << 2)
}

fn split_type(t: u16) -> Option<(u16, Class)> {
    if t & 0xC000 != 0 {
        return None;
    }
    let method = (t & 0x000F) | ((t >> 1) & 0x0070) | ((t >> 2) & 0x0F80);
    let class = match ((t >> 4) & 1) | ((t >> 7) & 2) {
        0 => Class::Request,
        1 => Class::Indication,
        2 => Class::Success,
        _ => Class::Error,
    };
    Some((method, class))
}

/// What a long-term credential (RFC 8489 section 9.2) is made of once the
/// server has said which realm and nonce to use.
#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub realm: String,
    pub nonce: Vec<u8>,
    /// `MD5(username ":" realm ":" password)`.
    key: [u8; 16],
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key is a password in all but name.
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("realm", &self.realm)
            .finish_non_exhaustive()
    }
}

impl Credentials {
    pub fn new(username: &str, realm: &str, password: &str, nonce: &[u8]) -> Self {
        let mut md5 = Md5::new();
        md5.update(username.as_bytes());
        md5.update(b":");
        md5.update(realm.as_bytes());
        md5.update(b":");
        md5.update(password.as_bytes());
        Self {
            username: username.to_string(),
            realm: realm.to_string(),
            nonce: nonce.to_vec(),
            key: md5.finalize().into(),
        }
    }

    pub fn key(&self) -> &[u8; 16] {
        &self.key
    }
}

fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    // A key of any length is accepted; this cannot fail.
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// A message being built.
pub struct Builder {
    buf: Vec<u8>,
}

impl Builder {
    pub fn new(method: u16, class: Class, tid: &[u8; 12]) -> Self {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&message_type(method, class).to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(tid);
        Self { buf }
    }

    fn tid(&self) -> [u8; 12] {
        self.buf[8..20]
            .try_into()
            .expect("a header has a transaction id")
    }

    pub fn attr(mut self, ty: u16, value: &[u8]) -> Self {
        debug_assert!(value.len() <= u16::MAX as usize);
        self.buf.extend_from_slice(&ty.to_be_bytes());
        self.buf
            .extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(value);
        let pad = (4 - value.len() % 4) % 4;
        self.buf.extend_from_slice(&[0u8; 3][..pad]);
        self
    }

    /// An address attribute in its XOR form (XOR-PEER-ADDRESS and the like).
    pub fn xor_address(self, ty: u16, addr: SocketAddr) -> Self {
        let tid = self.tid();
        let value = crate::nat::stun::encode_address(addr, Some(&tid));
        self.attr(ty, &value)
    }

    fn set_length(&mut self) {
        let len = (self.buf.len() - HEADER_LEN) as u16;
        self.buf[2..4].copy_from_slice(&len.to_be_bytes());
    }

    /// Ends a message that is not authenticated.
    pub fn finish(mut self) -> Vec<u8> {
        self.set_length();
        self.buf
    }

    /// Ends a message with MESSAGE-INTEGRITY over everything before it, the
    /// length field already counting the attribute itself (RFC 8489
    /// section 14.5). A server answers a request this way.
    pub fn finish_with_integrity(mut self, key: &[u8; 16]) -> Vec<u8> {
        let len = (self.buf.len() - HEADER_LEN + 4 + 20) as u16;
        self.buf[2..4].copy_from_slice(&len.to_be_bytes());
        let mac = hmac_sha1(key, &[&self.buf]);
        self.buf
            .extend_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
        self.buf.extend_from_slice(&20u16.to_be_bytes());
        self.buf.extend_from_slice(&mac);
        self.set_length();
        self.buf
    }

    /// Ends an authenticated request: USERNAME, REALM and NONCE go in, and
    /// MESSAGE-INTEGRITY after them.
    pub fn finish_authenticated(self, cred: &Credentials) -> Vec<u8> {
        self.attr(ATTR_USERNAME, cred.username.as_bytes())
            .attr(ATTR_REALM, cred.realm.as_bytes())
            .attr(ATTR_NONCE, &cred.nonce)
            .finish_with_integrity(&cred.key)
    }
}

/// A message read.
#[derive(Debug)]
pub struct Message<'a> {
    pub method: u16,
    pub class: Class,
    pub tid: [u8; 12],
    attrs: Vec<(u16, &'a [u8])>,
    raw: &'a [u8],
    /// Where MESSAGE-INTEGRITY's attribute starts, if there is one.
    integrity_at: Option<usize>,
}

/// Attributes read from one message at most: a real one has a dozen, and
/// what a stranger sends must not decide how much is kept.
const MAX_ATTRS: usize = 32;

/// Reads a STUN message. Anything not exactly one — a wrong cookie, a
/// length that is not the datagram's, an attribute that runs past the end —
/// is refused, not repaired.
pub fn parse(data: &[u8]) -> Option<Message<'_>> {
    if data.len() < HEADER_LEN || data.len() > MAX_MESSAGE {
        return None;
    }
    let (method, class) = split_type(u16::from_be_bytes([data[0], data[1]]))?;
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if len % 4 != 0 || HEADER_LEN + len != data.len() {
        return None;
    }
    if data[4..8] != STUN_MAGIC_COOKIE.to_be_bytes() {
        return None;
    }
    let tid: [u8; 12] = data[8..20].try_into().ok()?;
    let mut attrs = Vec::new();
    let mut integrity_at = None;
    let mut pos = HEADER_LEN;
    while pos < data.len() {
        if pos + 4 > data.len() || attrs.len() >= MAX_ATTRS {
            return None;
        }
        let ty = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let alen = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let start = pos + 4;
        let end = start.checked_add(alen)?;
        let next = end.checked_add((4 - alen % 4) % 4)?;
        if next > data.len() {
            return None;
        }
        if ty == ATTR_MESSAGE_INTEGRITY && integrity_at.is_none() {
            integrity_at = Some(pos);
        }
        attrs.push((ty, &data[start..end]));
        pos = next;
    }
    Some(Message {
        method,
        class,
        tid,
        attrs,
        raw: data,
        integrity_at,
    })
}

impl<'a> Message<'a> {
    pub fn attr(&self, ty: u16) -> Option<&'a [u8]> {
        self.attrs.iter().find(|(t, _)| *t == ty).map(|(_, v)| *v)
    }

    /// Every attribute of a kind, in the order they came (a request for
    /// several permissions carries several XOR-PEER-ADDRESS).
    pub fn attrs_of(&self, ty: u16) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.attrs
            .iter()
            .filter(move |(t, _)| *t == ty)
            .map(|(_, v)| *v)
    }

    pub fn xor_address(&self, ty: u16) -> Option<SocketAddr> {
        parse_xor_address(self.attr(ty)?, &self.tid)
    }

    pub fn lifetime(&self) -> Option<u32> {
        Some(u32::from_be_bytes(
            self.attr(ATTR_LIFETIME)?.try_into().ok()?,
        ))
    }

    /// The class and number of an error response, and its reason.
    pub fn error(&self) -> Option<(u16, String)> {
        let v = self.attr(ATTR_ERROR_CODE)?;
        if v.len() < 4 {
            return None;
        }
        let code = (v[2] as u16 & 0x7) * 100 + v[3] as u16;
        // The reason is text from a stranger: bounded, and printable only.
        let reason: String = String::from_utf8_lossy(&v[4..v.len().min(4 + 128)])
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        Some((code, reason))
    }

    pub fn text(&self, ty: u16) -> Option<String> {
        let v = self.attr(ty)?;
        if v.len() > 763 {
            return None;
        }
        Some(String::from_utf8_lossy(v).into_owned())
    }

    /// Whether the message carries a MESSAGE-INTEGRITY that `key` makes:
    /// HMAC-SHA1 over the message up to that attribute, with the length
    /// field counting through it.
    pub fn integrity_is_good(&self, key: &[u8; 16]) -> bool {
        let Some(at) = self.integrity_at else {
            return false;
        };
        let Some(given) = self.attr(ATTR_MESSAGE_INTEGRITY) else {
            return false;
        };
        if given.len() != 20 {
            return false;
        }
        let mut head = self.raw[..at].to_vec();
        let len = (at - HEADER_LEN + 4 + 20) as u16;
        head[2..4].copy_from_slice(&len.to_be_bytes());
        bool::from(hmac_sha1(key, &[&head]).ct_eq(given))
    }
}

/// An XOR-ed address (RFC 8489 section 14.2), which is how every address in
/// TURN is written.
pub fn parse_xor_address(value: &[u8], tid: &[u8; 12]) -> Option<SocketAddr> {
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    let port =
        u16::from_be_bytes([*value.get(2)?, *value.get(3)?]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;
    match *value.get(1)? {
        FAMILY_IPV4 if value.len() == 8 => {
            let mut ip = [0u8; 4];
            for (i, b) in ip.iter_mut().enumerate() {
                *b = value[4 + i] ^ cookie[i];
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        FAMILY_IPV6 if value.len() == 20 => {
            let mut ip = [0u8; 16];
            for (i, b) in ip.iter_mut().enumerate() {
                let mask = if i < 4 { cookie[i] } else { tid[i - 4] };
                *b = value[4 + i] ^ mask;
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => None,
    }
}

/// A ChannelData message: two bytes of channel number, two of length, and
/// the datagram (RFC 8656 section 12.4).
pub fn channel_data(channel: u16, data: &[u8]) -> Vec<u8> {
    debug_assert!((CHANNEL_MIN..=0x7FFF).contains(&channel) && data.len() <= u16::MAX as usize);
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Reads a ChannelData message. Over UDP the padding to four bytes is
/// optional, so what follows the datagram is not looked at.
pub fn parse_channel_data(pkt: &[u8]) -> Option<(u16, &[u8])> {
    if pkt.len() < 4 {
        return None;
    }
    let channel = u16::from_be_bytes([pkt[0], pkt[1]]);
    if !(CHANNEL_MIN..=0x7FFF).contains(&channel) {
        return None;
    }
    let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    pkt.get(4..4 + len).map(|d| (channel, d))
}

/// True for the first byte of a datagram that is ChannelData rather than a
/// STUN message (the top two bits are 01, RFC 8656 section 12.4).
pub fn looks_like_channel_data(pkt: &[u8]) -> bool {
    pkt.first().is_some_and(|b| b & 0xC0 == 0x40)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid() -> [u8; 12] {
        [7; 12]
    }

    #[test]
    fn method_and_class_are_woven_into_the_message_type() {
        // The values RFC 8656 section 22 and RFC 8489 section 5 list.
        let cases = [
            (BINDING, Class::Request, 0x0001),
            (BINDING, Class::Success, 0x0101),
            (BINDING, Class::Error, 0x0111),
            (ALLOCATE, Class::Request, 0x0003),
            (ALLOCATE, Class::Success, 0x0103),
            (ALLOCATE, Class::Error, 0x0113),
            (REFRESH, Class::Request, 0x0004),
            (REFRESH, Class::Success, 0x0104),
            (SEND, Class::Indication, 0x0016),
            (DATA, Class::Indication, 0x0017),
            (CREATE_PERMISSION, Class::Request, 0x0008),
            (CREATE_PERMISSION, Class::Success, 0x0108),
            (CREATE_PERMISSION, Class::Error, 0x0118),
            (CHANNEL_BIND, Class::Request, 0x0009),
            (CHANNEL_BIND, Class::Success, 0x0109),
        ];
        for (method, class, wire) in cases {
            assert_eq!(
                message_type(method, class),
                wire,
                "{:#x} {:?}",
                method,
                class
            );
            assert_eq!(split_type(wire), Some((method, class)));
        }
        // The two top bits are zero in STUN; anything else is not.
        assert_eq!(split_type(0x4003), None);
        assert_eq!(split_type(0x8003), None);
    }

    /// A long-term credential's integrity against a value an independent
    /// implementation (Python's `hmac` and `hashlib`) computes for the same
    /// bytes, and the sample request of RFC 5769 section 2.4.
    #[test]
    fn integrity_matches_the_rfcs_sample_request() {
        // RFC 5769 section 2.4: a request with long-term credentials.
        let nonce = b"f//499k954d6OL34oL9FSTvy64sA";
        assert_eq!(nonce.len(), 28);
        let username = "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}";
        assert_eq!(username.len(), 18);
        let cred = Credentials::new(username, "example.org", "TheMatrIX", nonce);
        let tid: [u8; 12] = [
            0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e,
        ];
        // The RFC's request is USERNAME, NONCE, REALM, MESSAGE-INTEGRITY, in
        // that order, which is not the order this builder writes them in, so
        // put it together by hand from the same attributes.
        let mut msg = Builder::new(BINDING, Class::Request, &tid)
            .attr(ATTR_USERNAME, username.as_bytes())
            .attr(ATTR_NONCE, nonce)
            .attr(ATTR_REALM, b"example.org");
        let len = (msg.buf.len() - HEADER_LEN + 24) as u16;
        msg.buf[2..4].copy_from_slice(&len.to_be_bytes());
        let mac = hmac_sha1(cred.key(), &[&msg.buf]);
        let expected: [u8; 20] = [
            0xf6, 0x70, 0x24, 0x65, 0x6d, 0xd6, 0x4a, 0x3e, 0x02, 0xb8, 0xe0, 0x71, 0x2e, 0x85,
            0xc9, 0xa2, 0x8c, 0xa8, 0x96, 0x66,
        ];
        assert_eq!(mac, expected, "the RFC 5769 section 2.4 integrity value");
    }

    #[test]
    fn an_authenticated_request_verifies_and_a_changed_one_does_not() {
        let cred = Credentials::new("alice", "example.org", "s3cret", b"nonce-1");
        let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
        let bytes = Builder::new(CREATE_PERMISSION, Class::Request, &tid())
            .xor_address(ATTR_XOR_PEER_ADDRESS, peer)
            .finish_authenticated(&cred);
        let m = parse(&bytes).expect("parses");
        assert_eq!((m.method, m.class), (CREATE_PERMISSION, Class::Request));
        assert_eq!(m.xor_address(ATTR_XOR_PEER_ADDRESS), Some(peer));
        assert_eq!(m.text(ATTR_USERNAME).as_deref(), Some("alice"));
        assert!(m.integrity_is_good(cred.key()));
        // Another password is another key.
        let other = Credentials::new("alice", "example.org", "guess", b"nonce-1");
        assert!(!m.integrity_is_good(other.key()));
        // Any changed bit anywhere before the integrity is caught.
        for i in HEADER_LEN..bytes.len() - 24 {
            let mut bad = bytes.clone();
            bad[i] ^= 0x01;
            if let Some(m) = parse(&bad) {
                assert!(
                    !m.integrity_is_good(cred.key()),
                    "byte {} changed unnoticed",
                    i
                );
            }
        }
    }

    #[test]
    fn addresses_are_xored_both_ways_round() {
        for addr in ["203.0.113.9:49152", "[2a0e:aa00:1:1::5]:40000", "0.0.0.0:0"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let bytes = Builder::new(DATA, Class::Indication, &tid())
                .xor_address(ATTR_XOR_PEER_ADDRESS, addr)
                .attr(ATTR_DATA, b"hello")
                .finish();
            let m = parse(&bytes).unwrap();
            assert_eq!(m.xor_address(ATTR_XOR_PEER_ADDRESS), Some(addr));
            assert_eq!(m.attr(ATTR_DATA), Some(&b"hello"[..]));
        }
        // A family that is neither, and a length that fits neither.
        assert_eq!(parse_xor_address(&[0, 3, 0, 0, 1, 2, 3, 4], &tid()), None);
        assert_eq!(parse_xor_address(&[0, 1, 0, 0, 1, 2, 3], &tid()), None);
        assert_eq!(parse_xor_address(&[0, 2, 0, 0, 1, 2, 3, 4], &tid()), None);
    }

    #[test]
    fn what_a_stranger_sends_is_refused_or_bounded() {
        let good = Builder::new(ALLOCATE, Class::Success, &tid())
            .attr(ATTR_LIFETIME, &600u32.to_be_bytes())
            .finish();
        assert!(parse(&good).is_some());
        // Every prefix and every single-byte change parses to something
        // or to nothing, and never panics.
        for n in 0..good.len() {
            let _ = parse(&good[..n]);
        }
        for i in 0..good.len() {
            for v in [0u8, 0xff, 0x40, 0x80] {
                let mut bad = good.clone();
                bad[i] = v;
                let _ = parse(&bad);
            }
        }
        // A length that is not the datagram's.
        let mut bad = good.clone();
        bad[3] = 12;
        assert!(parse(&bad).is_none());
        // An attribute claiming more than there is.
        let mut bad = good.clone();
        bad[HEADER_LEN + 3] = 200;
        assert!(parse(&bad).is_none());
        // Not a STUN cookie.
        let mut bad = good.clone();
        bad[4] ^= 1;
        assert!(parse(&bad).is_none());
        // More attributes than any message has.
        let mut b = Builder::new(ALLOCATE, Class::Success, &tid());
        for _ in 0..(MAX_ATTRS + 1) {
            b = b.attr(ATTR_SOFTWARE, b"x");
        }
        assert!(parse(&b.finish()).is_none());
    }

    #[test]
    fn an_error_response_says_what_went_wrong() {
        let mut v = vec![0, 0, 4, 1];
        v.extend_from_slice(b"Unauthorized");
        let bytes = Builder::new(ALLOCATE, Class::Error, &tid())
            .attr(ATTR_ERROR_CODE, &v)
            .attr(ATTR_REALM, b"example.org")
            .attr(ATTR_NONCE, b"abc")
            .finish();
        let m = parse(&bytes).unwrap();
        assert_eq!(m.error(), Some((401, "Unauthorized".to_string())));
        assert_eq!(m.text(ATTR_REALM).as_deref(), Some("example.org"));
        // Control characters in a reason are not passed on.
        let mut v = vec![0, 0, 4, 38];
        v.extend_from_slice(b"Stale\x1b[31m Nonce");
        let bytes = Builder::new(ALLOCATE, Class::Error, &tid())
            .attr(ATTR_ERROR_CODE, &v)
            .finish();
        let (code, reason) = parse(&bytes).unwrap().error().unwrap();
        assert_eq!(code, 438);
        assert!(!reason.contains('\u{1b}'), "{:?}", reason);
    }

    #[test]
    fn channel_data_is_told_from_stun_by_its_first_bits() {
        let framed = channel_data(0x4001, b"payload");
        assert_eq!(framed.len(), 4 + 7);
        assert!(looks_like_channel_data(&framed));
        assert_eq!(parse_channel_data(&framed), Some((0x4001, &b"payload"[..])));
        // Padding after the data is allowed and not part of it.
        let mut padded = framed.clone();
        padded.push(0);
        assert_eq!(parse_channel_data(&padded), Some((0x4001, &b"payload"[..])));
        // Short, a channel out of range, a length past the end.
        assert_eq!(parse_channel_data(&framed[..10]), None);
        assert_eq!(parse_channel_data(&[0x80, 0, 0, 0]), None);
        assert_eq!(parse_channel_data(&[0x3f, 0xff, 0, 0]), None);
        assert_eq!(parse_channel_data(&[0x40, 0, 0, 9, 1]), None);
        let stun = Builder::new(BINDING, Class::Request, &tid()).finish();
        assert!(!looks_like_channel_data(&stun));
    }
}
