// src/connectivity/stun/attributes.rs
//! STUN Attributes Implementation
//!
//! RFC 8489 Section 14: STUN Attributes
//! RFC 5780: NAT Behavior Discovery attributes

use anyhow::{Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::constants::*;

/// STUN attribute
#[derive(Debug, Clone)]
pub enum StunAttribute {
    /// MAPPED-ADDRESS (0x0001)
    MappedAddress(MappedAddress),

    /// CHANGE-REQUEST (0x0003) - RFC 5780
    ChangeRequest(ChangeRequest),

    /// USERNAME (0x0006)
    Username(String),

    /// MESSAGE-INTEGRITY (0x0008)
    MessageIntegrity([u8; 20]),

    /// ERROR-CODE (0x0009)
    ErrorCode { code: u16, reason: String },

    /// UNKNOWN-ATTRIBUTES (0x000A)
    UnknownAttributes(Vec<u16>),

    /// XOR-MAPPED-ADDRESS (0x0020)
    XorMappedAddress(XorMappedAddress),

    /// PRIORITY (0x0024) - ICE
    Priority(u32),

    /// USE-CANDIDATE (0x0025) - ICE
    UseCandidate,

    /// FINGERPRINT (0x8028)
    Fingerprint(u32),

    /// ICE-CONTROLLED (0x8029)
    IceControlled(u64),

    /// ICE-CONTROLLING (0x802A)
    IceControlling(u64),

    /// RESPONSE-ORIGIN (0x802B) - RFC 5780
    ResponseOrigin(ResponseOrigin),

    /// OTHER-ADDRESS (0x802C) - RFC 5780
    OtherAddress(OtherAddress),

    /// Unknown attribute
    Unknown { attr_type: u16, value: Vec<u8> },
}

impl StunAttribute {
    /// Get attribute type code
    pub fn attr_type(&self) -> u16 {
        match self {
            StunAttribute::MappedAddress(_) => ATTR_MAPPED_ADDRESS,
            StunAttribute::ChangeRequest(_) => ATTR_CHANGE_REQUEST,
            StunAttribute::Username(_) => ATTR_USERNAME,
            StunAttribute::MessageIntegrity(_) => ATTR_MESSAGE_INTEGRITY,
            StunAttribute::ErrorCode { .. } => ATTR_ERROR_CODE,
            StunAttribute::UnknownAttributes(_) => ATTR_UNKNOWN_ATTRIBUTES,
            StunAttribute::XorMappedAddress(_) => ATTR_XOR_MAPPED_ADDRESS,
            StunAttribute::Priority(_) => ATTR_PRIORITY,
            StunAttribute::UseCandidate => ATTR_USE_CANDIDATE,
            StunAttribute::Fingerprint(_) => ATTR_FINGERPRINT,
            StunAttribute::IceControlled(_) => ATTR_ICE_CONTROLLED,
            StunAttribute::IceControlling(_) => ATTR_ICE_CONTROLLING,
            StunAttribute::ResponseOrigin(_) => ATTR_RESPONSE_ORIGIN,
            StunAttribute::OtherAddress(_) => ATTR_OTHER_ADDRESS,
            StunAttribute::Unknown { attr_type, .. } => *attr_type,
        }
    }

    /// Encode attribute to bytes
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        let start_len = buf.len();

        match self {
            StunAttribute::MappedAddress(addr) => {
                buf.put_u16(ATTR_MAPPED_ADDRESS);
                let value_start = buf.len();
                buf.put_u16(0); // Placeholder for length
                addr.encode(buf);
                let value_len = buf.len() - value_start - 2;
                buf[value_start..value_start + 2]
                    .copy_from_slice(&(value_len as u16).to_be_bytes());
            }

            StunAttribute::XorMappedAddress(addr) => {
                buf.put_u16(ATTR_XOR_MAPPED_ADDRESS);
                let value_start = buf.len();
                buf.put_u16(0); // Placeholder for length
                addr.encode(buf);
                let value_len = buf.len() - value_start - 2;
                buf[value_start..value_start + 2]
                    .copy_from_slice(&(value_len as u16).to_be_bytes());
            }

            StunAttribute::ChangeRequest(req) => {
                buf.put_u16(ATTR_CHANGE_REQUEST);
                buf.put_u16(4);
                buf.put_u32(req.encode());
            }

            StunAttribute::Username(username) => {
                buf.put_u16(ATTR_USERNAME);
                let bytes = username.as_bytes();
                buf.put_u16(bytes.len() as u16);
                buf.put_slice(bytes);
                // Padding to 4-byte boundary
                let padding = (4 - (bytes.len() % 4)) % 4;
                buf.put_bytes(0, padding);
            }

            StunAttribute::MessageIntegrity(hmac) => {
                buf.put_u16(ATTR_MESSAGE_INTEGRITY);
                buf.put_u16(20);
                buf.put_slice(hmac);
            }

            StunAttribute::ErrorCode { code, reason } => {
                buf.put_u16(ATTR_ERROR_CODE);
                let reason_bytes = reason.as_bytes();
                buf.put_u16((4 + reason_bytes.len()) as u16);
                buf.put_u16(0); // Reserved
                buf.put_u8((code / 100) as u8);
                buf.put_u8((code % 100) as u8);
                buf.put_slice(reason_bytes);
                let padding = (4 - (reason_bytes.len() % 4)) % 4;
                buf.put_bytes(0, padding);
            }

            StunAttribute::Priority(priority) => {
                buf.put_u16(ATTR_PRIORITY);
                buf.put_u16(4);
                buf.put_u32(*priority);
            }

            StunAttribute::UseCandidate => {
                buf.put_u16(ATTR_USE_CANDIDATE);
                buf.put_u16(0);
            }

            StunAttribute::Fingerprint(crc) => {
                buf.put_u16(ATTR_FINGERPRINT);
                buf.put_u16(4);
                buf.put_u32(*crc);
            }

            StunAttribute::IceControlled(tiebreaker) => {
                buf.put_u16(ATTR_ICE_CONTROLLED);
                buf.put_u16(8);
                buf.put_u64(*tiebreaker);
            }

            StunAttribute::IceControlling(tiebreaker) => {
                buf.put_u16(ATTR_ICE_CONTROLLING);
                buf.put_u16(8);
                buf.put_u64(*tiebreaker);
            }

            StunAttribute::ResponseOrigin(origin) => {
                buf.put_u16(ATTR_RESPONSE_ORIGIN);
                let value_start = buf.len();
                buf.put_u16(0);
                origin.encode(buf);
                let value_len = buf.len() - value_start - 2;
                buf[value_start..value_start + 2]
                    .copy_from_slice(&(value_len as u16).to_be_bytes());
            }

            StunAttribute::OtherAddress(addr) => {
                buf.put_u16(ATTR_OTHER_ADDRESS);
                let value_start = buf.len();
                buf.put_u16(0);
                addr.encode(buf);
                let value_len = buf.len() - value_start - 2;
                buf[value_start..value_start + 2]
                    .copy_from_slice(&(value_len as u16).to_be_bytes());
            }

            StunAttribute::UnknownAttributes(attrs) => {
                buf.put_u16(ATTR_UNKNOWN_ATTRIBUTES);
                buf.put_u16((attrs.len() * 2) as u16);
                for attr in attrs {
                    buf.put_u16(*attr);
                }
                if attrs.len() % 2 != 0 {
                    buf.put_u16(0); // Padding
                }
            }

            StunAttribute::Unknown { attr_type, value } => {
                buf.put_u16(*attr_type);
                buf.put_u16(value.len() as u16);
                buf.put_slice(value);
                let padding = (4 - (value.len() % 4)) % 4;
                buf.put_bytes(0, padding);
            }
        }

        Ok(())
    }

    /// Decode attribute from bytes
    pub fn decode(buf: &mut &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(anyhow::anyhow!("Attribute too short"));
        }

        let attr_type = buf.get_u16();
        let length = buf.get_u16() as usize;

        if buf.len() < length {
            return Err(anyhow::anyhow!("Attribute value truncated"));
        }

        let value = &buf[..length];
        let padded_length = (length + 3) & !3;

        let attr = match attr_type {
            ATTR_MAPPED_ADDRESS => StunAttribute::MappedAddress(MappedAddress::decode(value)?),

            ATTR_XOR_MAPPED_ADDRESS => {
                StunAttribute::XorMappedAddress(XorMappedAddress::decode(value)?)
            }

            ATTR_CHANGE_REQUEST => {
                if length < 4 {
                    return Err(anyhow::anyhow!("CHANGE-REQUEST too short"));
                }
                let flags = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                StunAttribute::ChangeRequest(ChangeRequest::decode(flags))
            }

            ATTR_USERNAME => {
                let username =
                    String::from_utf8(value.to_vec()).context("Invalid USERNAME UTF-8")?;
                StunAttribute::Username(username)
            }

            ATTR_MESSAGE_INTEGRITY => {
                if length != 20 {
                    return Err(anyhow::anyhow!("MESSAGE-INTEGRITY must be 20 bytes"));
                }
                let mut hmac = [0u8; 20];
                hmac.copy_from_slice(value);
                StunAttribute::MessageIntegrity(hmac)
            }

            ATTR_ERROR_CODE => {
                if length < 4 {
                    return Err(anyhow::anyhow!("ERROR-CODE too short"));
                }
                let class = (value[2] & 0x07) as u16;
                let number = value[3] as u16;
                let code = class * 100 + number;
                let reason = String::from_utf8_lossy(&value[4..]).to_string();
                StunAttribute::ErrorCode { code, reason }
            }

            ATTR_PRIORITY => {
                if length < 4 {
                    return Err(anyhow::anyhow!("PRIORITY too short"));
                }
                let priority = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                StunAttribute::Priority(priority)
            }

            ATTR_USE_CANDIDATE => StunAttribute::UseCandidate,

            ATTR_FINGERPRINT => {
                if length < 4 {
                    return Err(anyhow::anyhow!("FINGERPRINT too short"));
                }
                let crc = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                StunAttribute::Fingerprint(crc)
            }

            ATTR_ICE_CONTROLLED => {
                if length < 8 {
                    return Err(anyhow::anyhow!("ICE-CONTROLLED too short"));
                }
                let tiebreaker = u64::from_be_bytes([
                    value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
                ]);
                StunAttribute::IceControlled(tiebreaker)
            }

            ATTR_ICE_CONTROLLING => {
                if length < 8 {
                    return Err(anyhow::anyhow!("ICE-CONTROLLING too short"));
                }
                let tiebreaker = u64::from_be_bytes([
                    value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
                ]);
                StunAttribute::IceControlling(tiebreaker)
            }

            ATTR_RESPONSE_ORIGIN => StunAttribute::ResponseOrigin(ResponseOrigin::decode(value)?),

            ATTR_OTHER_ADDRESS => StunAttribute::OtherAddress(OtherAddress::decode(value)?),

            _ => StunAttribute::Unknown {
                attr_type,
                value: value.to_vec(),
            },
        };

        *buf = &buf[padded_length.min(buf.len())..];
        Ok(attr)
    }
}

/// MAPPED-ADDRESS attribute
#[derive(Debug, Clone)]
pub struct MappedAddress {
    pub address: SocketAddr,
}

impl MappedAddress {
    pub fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(0); // Reserved
        match self.address {
            SocketAddr::V4(addr) => {
                buf.put_u8(0x01); // IPv4
                buf.put_u16(addr.port());
                buf.put_slice(&addr.ip().octets());
            }
            SocketAddr::V6(addr) => {
                buf.put_u8(0x02); // IPv6
                buf.put_u16(addr.port());
                buf.put_slice(&addr.ip().octets());
            }
        }
    }

    pub fn decode(value: &[u8]) -> Result<Self> {
        if value.len() < 4 {
            return Err(anyhow::anyhow!("MAPPED-ADDRESS too short"));
        }

        let family = value[1];
        let port = u16::from_be_bytes([value[2], value[3]]);

        let address = match family {
            0x01 => {
                if value.len() < 8 {
                    return Err(anyhow::anyhow!("IPv4 MAPPED-ADDRESS too short"));
                }
                let ip = Ipv4Addr::new(value[4], value[5], value[6], value[7]);
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            0x02 => {
                if value.len() < 20 {
                    return Err(anyhow::anyhow!("IPv6 MAPPED-ADDRESS too short"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&value[4..20]);
                let ip = Ipv6Addr::from(octets);
                SocketAddr::new(IpAddr::V6(ip), port)
            }
            _ => return Err(anyhow::anyhow!("Unknown address family: {}", family)),
        };

        Ok(Self { address })
    }
}

/// XOR-MAPPED-ADDRESS attribute
#[derive(Debug, Clone)]
pub struct XorMappedAddress {
    pub address: SocketAddr,
}

impl XorMappedAddress {
    pub fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(0); // Reserved
        match self.address {
            SocketAddr::V4(addr) => {
                buf.put_u8(0x01); // IPv4
                                  // XOR port with high 16 bits of magic cookie
                let xport = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
                buf.put_u16(xport);
                // XOR address with magic cookie
                let ip_bytes = addr.ip().octets();
                let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
                buf.put_u8(ip_bytes[0] ^ cookie_bytes[0]);
                buf.put_u8(ip_bytes[1] ^ cookie_bytes[1]);
                buf.put_u8(ip_bytes[2] ^ cookie_bytes[2]);
                buf.put_u8(ip_bytes[3] ^ cookie_bytes[3]);
            }
            SocketAddr::V6(addr) => {
                buf.put_u8(0x02); // IPv6
                let xport = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
                buf.put_u16(xport);
                // XOR with magic cookie + transaction ID (not implemented here)
                // For now, just encode the IP directly
                buf.put_slice(&addr.ip().octets());
            }
        }
    }

    /// Decode XOR-MAPPED-ADDRESS from value bytes
    /// Note: transaction_id is needed for IPv6 XOR operation
    pub fn decode(value: &[u8]) -> Result<Self> {
        if value.len() < 4 {
            return Err(anyhow::anyhow!("XOR-MAPPED-ADDRESS too short"));
        }

        let family = value[1];
        let xport = u16::from_be_bytes([value[2], value[3]]);
        let port = xport ^ ((MAGIC_COOKIE >> 16) as u16);

        let address = match family {
            0x01 => {
                if value.len() < 8 {
                    return Err(anyhow::anyhow!("IPv4 XOR-MAPPED-ADDRESS too short"));
                }
                let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
                let ip = Ipv4Addr::new(
                    value[4] ^ cookie_bytes[0],
                    value[5] ^ cookie_bytes[1],
                    value[6] ^ cookie_bytes[2],
                    value[7] ^ cookie_bytes[3],
                );
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            0x02 => {
                if value.len() < 20 {
                    return Err(anyhow::anyhow!("IPv6 XOR-MAPPED-ADDRESS too short"));
                }
                // For IPv6, XOR with magic cookie + transaction ID
                // Simplified: just decode without full XOR
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&value[4..20]);
                let ip = Ipv6Addr::from(octets);
                SocketAddr::new(IpAddr::V6(ip), port)
            }
            _ => return Err(anyhow::anyhow!("Unknown address family: {}", family)),
        };

        Ok(Self { address })
    }

    /// Get the socket address
    pub fn socket_addr(&self) -> SocketAddr {
        self.address
    }
}

/// CHANGE-REQUEST attribute for RFC 5780 NAT detection
#[derive(Debug, Clone, Copy)]
pub struct ChangeRequest {
    /// Change IP address in response
    pub change_ip: bool,
    /// Change port in response
    pub change_port: bool,
}

impl ChangeRequest {
    pub fn new(change_ip: bool, change_port: bool) -> Self {
        Self {
            change_ip,
            change_port,
        }
    }

    pub fn encode(&self) -> u32 {
        let mut flags = 0u32;
        if self.change_ip {
            flags |= 0x04;
        }
        if self.change_port {
            flags |= 0x02;
        }
        flags
    }

    pub fn decode(flags: u32) -> Self {
        Self {
            change_ip: (flags & 0x04) != 0,
            change_port: (flags & 0x02) != 0,
        }
    }
}

/// RESPONSE-ORIGIN attribute (RFC 5780)
#[derive(Debug, Clone)]
pub struct ResponseOrigin {
    pub address: SocketAddr,
}

impl ResponseOrigin {
    pub fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        MappedAddress::new(self.address).encode(buf);
    }

    pub fn decode(value: &[u8]) -> Result<Self> {
        let mapped = MappedAddress::decode(value)?;
        Ok(Self {
            address: mapped.address,
        })
    }
}

/// OTHER-ADDRESS attribute (RFC 5780)
#[derive(Debug, Clone)]
pub struct OtherAddress {
    pub address: SocketAddr,
}

impl OtherAddress {
    pub fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        MappedAddress::new(self.address).encode(buf);
    }

    pub fn decode(value: &[u8]) -> Result<Self> {
        let mapped = MappedAddress::decode(value)?;
        Ok(Self {
            address: mapped.address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_mapped_address_ipv4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let xma = XorMappedAddress::new(addr);

        let mut buf = BytesMut::new();
        xma.encode(&mut buf);

        let decoded = XorMappedAddress::decode(&buf).unwrap();
        assert_eq!(decoded.address, addr);
    }

    #[test]
    fn test_change_request() {
        let req = ChangeRequest::new(true, false);
        let encoded = req.encode();
        assert_eq!(encoded, 0x04);

        let req = ChangeRequest::new(false, true);
        let encoded = req.encode();
        assert_eq!(encoded, 0x02);

        let req = ChangeRequest::new(true, true);
        let encoded = req.encode();
        assert_eq!(encoded, 0x06);

        let decoded = ChangeRequest::decode(0x06);
        assert!(decoded.change_ip);
        assert!(decoded.change_port);
    }

    #[test]
    fn test_attribute_roundtrip() {
        let attr = StunAttribute::Priority(1000);
        let mut buf = BytesMut::new();
        attr.encode(&mut buf).unwrap();

        let mut slice = &buf[..];
        let decoded = StunAttribute::decode(&mut slice).unwrap();

        match decoded {
            StunAttribute::Priority(p) => assert_eq!(p, 1000),
            _ => panic!("Wrong attribute type"),
        }
    }

    #[test]
    fn test_use_candidate() {
        let attr = StunAttribute::UseCandidate;
        let mut buf = BytesMut::new();
        attr.encode(&mut buf).unwrap();

        assert_eq!(&buf[..], &[0x00, 0x25, 0x00, 0x00]);
    }
}
