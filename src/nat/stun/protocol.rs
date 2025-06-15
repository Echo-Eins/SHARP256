use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha1};
use crc::{Crc, CRC_32_ISO_HDLC};
use rand::{Rng, RngCore};
use crate::nat::error::{StunError, NatResult};

/// STUN magic cookie as defined in RFC 8489
pub const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN header size (20 bytes)
pub const HEADER_SIZE: usize = 20;

/// Maximum STUN message size
pub const MAX_MESSAGE_SIZE: usize = 65536;

/// STUN message types (RFC 8489 Section 3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    // Binding
    BindingRequest = 0x0001,
    BindingIndication = 0x0011,
    BindingResponse = 0x0101,
    BindingError = 0x0111,
    
    // Allocate (TURN)
    AllocateRequest = 0x0003,
    AllocateResponse = 0x0103,
    AllocateError = 0x0113,
    
    // Refresh (TURN)
    RefreshRequest = 0x0004,
    RefreshResponse = 0x0104,
    RefreshError = 0x0114,
    
    // Send (TURN)
    SendIndication = 0x0016,
    
    // Data (TURN)
    DataIndication = 0x0017,
    
    // CreatePermission (TURN)
    CreatePermissionRequest = 0x0008,
    CreatePermissionResponse = 0x0108,
    CreatePermissionError = 0x0118,
    
    // ChannelBind (TURN)
    ChannelBindRequest = 0x0009,
    ChannelBindResponse = 0x0109,
    ChannelBindError = 0x0119,
}

impl MessageType {
    /// Get message class (request, indication, response, error)
    pub fn class(&self) -> MessageClass {
        let value = *self as u16;
        match value & 0x0110 {
            0x0000 => MessageClass::Request,
            0x0010 => MessageClass::Indication,
            0x0100 => MessageClass::SuccessResponse,
            0x0110 => MessageClass::ErrorResponse,
            _ => unreachable!(),
        }
    }
    
    /// Get message method
    pub fn method(&self) -> u16 {
        let value = *self as u16;
        ((value & 0x000F) | ((value & 0x00E0) >> 1) | ((value & 0x3E00) >> 2))
    }
}

/// STUN message class
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

/// STUN attribute types (RFC 8489 Section 14)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AttributeType {
    // Comprehension-required (0x0000-0x7FFF)
    MappedAddress = 0x0001,
    ResponseAddress = 0x0002,  // Deprecated
    ChangeRequest = 0x0003,    // Deprecated  
    SourceAddress = 0x0004,    // Deprecated
    ChangedAddress = 0x0005,   // Deprecated
    Username = 0x0006,
    Password = 0x0007,         // Deprecated
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000A,
    ReflectedFrom = 0x000B,    // Deprecated
    Realm = 0x0014,
    Nonce = 0x0015,
    XorMappedAddress = 0x0020,
    
    // STUN Security Features
    MessageIntegritySha256 = 0x001C,
    PasswordAlgorithm = 0x001D,
    UserHash = 0x001E,
    
    // Comprehension-optional (0x8000-0xFFFF)
    Software = 0x8022,
    AlternateServer = 0x8023,
    Cache = 0x8027,
    Fingerprint = 0x8028,
    IceControlled = 0x8029,
    IceControlling = 0x802A,
    ResponseOrigin = 0x802B,
    OtherAddress = 0x802C,
    
    // TURN attributes
    ChannelNumber = 0x000C,
    Lifetime = 0x000D,
    Bandwidth = 0x0010,         // Deprecated
    XorPeerAddress = 0x0012,
    Data = 0x0013,
    XorRelayedAddress = 0x0016,
    EvenPort = 0x0018,
    RequestedTransport = 0x0019,
    DontFragment = 0x001A,
    AccessToken = 0x001B,
    ReservationToken = 0x0022,
    
    // NAT Behavior Discovery
    ResponsePort = 0x0027,
    Padding = 0x0028,
}

impl AttributeType {
    /// Check if attribute is comprehension-required
    pub fn is_comprehension_required(&self) -> bool {
        (*self as u16) < 0x8000
    }
}

/// STUN transaction ID (96 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionId([u8; 12]);

impl TransactionId {
    /// Generate new random transaction ID
    pub fn new() -> Self {
        let mut id = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut id);
        Self(id)
    }
    
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }
    
    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// STUN message
#[derive(Debug, Clone)]
pub struct Message {
    pub message_type: MessageType,
    pub transaction_id: TransactionId,
    pub attributes: Vec<Attribute>,
}

impl Message {
    /// Create new STUN message
    pub fn new(message_type: MessageType, transaction_id: TransactionId) -> Self {
        Self {
            message_type,
            transaction_id,
            attributes: Vec::new(),
        }
    }
    
    /// Add attribute to message
    pub fn add_attribute(&mut self, attribute: Attribute) {
        self.attributes.push(attribute);
    }
    
    /// Get attribute by type
    pub fn get_attribute(&self, attr_type: AttributeType) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.attr_type == attr_type)
    }
    
    /// Encode message to bytes
    pub fn encode(&self, integrity_key: Option<&[u8]>, fingerprint: bool) -> NatResult<Bytes> {
        let mut buf = BytesMut::with_capacity(MAX_MESSAGE_SIZE);
        
        // Reserve space for header
        buf.put_u16(0); // Message type (will be set later)
        buf.put_u16(0); // Message length (will be set later)
        buf.put_u32(MAGIC_COOKIE);
        buf.put_slice(self.transaction_id.as_bytes());
        
        // Encode attributes
        for attr in &self.attributes {
            // Skip integrity and fingerprint attributes (will be added later)
            if matches!(attr.attr_type, 
                AttributeType::MessageIntegrity | 
                AttributeType::MessageIntegritySha256 |
                AttributeType::Fingerprint) {
                continue;
            }
            
            attr.encode(&mut buf, &self.transaction_id)?;
        }
        
        // Add MESSAGE-INTEGRITY-SHA256 if key provided
        if let Some(key) = integrity_key {
            // Calculate length including MESSAGE-INTEGRITY-SHA256
            let msg_len = buf.len() - HEADER_SIZE + 4 + 32; // attr header + sha256
            
            // Update message length for integrity calculation
            buf[2..4].copy_from_slice(&(msg_len as u16).to_be_bytes());
            
            // Calculate HMAC-SHA256
            let mut mac = Hmac::<Sha256>::new_from_slice(key)
                .map_err(|e| StunError::ParseError(format!("Invalid key: {}", e)))?;
            mac.update(&buf);
            let result = mac.finalize();
            
            // Add MESSAGE-INTEGRITY-SHA256 attribute
            buf.put_u16(AttributeType::MessageIntegritySha256 as u16);
            buf.put_u16(32);
            buf.put_slice(&result.into_bytes());
        }
        
        // Add FINGERPRINT if requested
        if fingerprint {
            // Calculate CRC32
            let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
            let mut digest = crc.digest();
            digest.update(&buf);
            let crc_value = digest.finalize() ^ 0x5354554E; // XOR with STUN constant
            
            // Add FINGERPRINT attribute
            buf.put_u16(AttributeType::Fingerprint as u16);
            buf.put_u16(4);
            buf.put_u32(crc_value);
        }
        
        // Update header
        let msg_len = buf.len() - HEADER_SIZE;
        buf[0..2].copy_from_slice(&(self.message_type as u16).to_be_bytes());
        buf[2..4].copy_from_slice(&(msg_len as u16).to_be_bytes());
        
        Ok(buf.freeze())
    }
    
    /// Decode message from bytes
    pub fn decode(mut buf: BytesMut) -> NatResult<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(StunError::ParseError("Message too short".to_string()).into());
        }
        
        // Parse header
        let msg_type_raw = buf.get_u16();
        let msg_len = buf.get_u16() as usize;
        let magic = buf.get_u32();
        
        if magic != MAGIC_COOKIE {
            return Err(StunError::InvalidMagicCookie(magic).into());
        }
        
        let mut tid_bytes = [0u8; 12];
        buf.copy_to_slice(&mut tid_bytes);
        let transaction_id = TransactionId::from_bytes(tid_bytes);
        
        // Validate message type
        let message_type = match msg_type_raw {
            0x0001 => MessageType::BindingRequest,
            0x0011 => MessageType::BindingIndication,
            0x0101 => MessageType::BindingResponse,
            0x0111 => MessageType::BindingError,
            _ => return Err(StunError::ParseError(
                format!("Unknown message type: 0x{:04X}", msg_type_raw)
            ).into()),
        };
        
        // Validate length
        if buf.remaining() != msg_len {
            return Err(StunError::ParseError(
                format!("Invalid message length: expected {}, got {}", msg_len, buf.remaining())
            ).into());
        }
        
        // Parse attributes
        let mut attributes = Vec::new();
        let mut unknown_required = Vec::new();
        
        while buf.has_remaining() {
            if buf.remaining() < 4 {
                return Err(StunError::ParseError("Incomplete attribute header".to_string()).into());
            }
            
            let attr_type_raw = buf.get_u16();
            let attr_len = buf.get_u16() as usize;
            
            if buf.remaining() < attr_len {
                return Err(StunError::ParseError("Incomplete attribute value".to_string()).into());
            }
            
            // Try to parse known attribute types
            match Attribute::decode(attr_type_raw, attr_len, &mut buf, &transaction_id) {
                Ok(attr) => attributes.push(attr),
                Err(_) if attr_type_raw < 0x8000 => {
                    // Unknown comprehension-required attribute
                    unknown_required.push(attr_type_raw);
                    buf.advance(attr_len);
                }
                Err(_) => {
                    // Unknown comprehension-optional attribute, skip
                    buf.advance(attr_len);
                }
            }
            
            // Skip padding to 4-byte boundary
            let padding = (4 - (attr_len % 4)) % 4;
            if buf.remaining() >= padding {
                buf.advance(padding);
            }
        }
        
        // Check for unknown comprehension-required attributes
        if !unknown_required.is_empty() {
            return Err(StunError::UnknownComprehensionRequired(unknown_required).into());
        }
        
        Ok(Self {
            message_type,
            transaction_id,
            attributes,
        })
    }
    
    /// Verify MESSAGE-INTEGRITY-SHA256
    pub fn verify_integrity_sha256(&self, key: &[u8], raw_msg: &[u8]) -> NatResult<bool> {
        let attr = self.get_attribute(AttributeType::MessageIntegritySha256)
            .ok_or_else(|| StunError::MissingAttribute("MESSAGE-INTEGRITY-SHA256".to_string()))?;
        
        if let AttributeValue::Raw(hash) = &attr.value {
            if hash.len() != 32 {
                return Ok(false);
            }
            
            // Find position of MESSAGE-INTEGRITY-SHA256 attribute
            let integrity_pos = self.find_attribute_position(raw_msg, AttributeType::MessageIntegritySha256)?;
            
            // Create modified message for verification
            let mut verify_msg = raw_msg[..integrity_pos].to_vec();
            
            // Update length to exclude everything after MESSAGE-INTEGRITY-SHA256
            let new_len = (integrity_pos - HEADER_SIZE + 4 + 32) as u16;
            verify_msg[2..4].copy_from_slice(&new_len.to_be_bytes());
            
            // Calculate HMAC-SHA256
            let mut mac = Hmac::<Sha256>::new_from_slice(key)
                .map_err(|e| StunError::ParseError(format!("Invalid key: {}", e)))?;
            mac.update(&verify_msg);
            
            Ok(mac.verify_slice(hash).is_ok())
        } else {
            Ok(false)
        }
    }
    
    /// Find attribute position in raw message
    fn find_attribute_position(&self, raw_msg: &[u8], attr_type: AttributeType) -> NatResult<usize> {
        let mut pos = HEADER_SIZE;
        
        while pos + 4 <= raw_msg.len() {
            let attr = u16::from_be_bytes([raw_msg[pos], raw_msg[pos + 1]]);
            let len = u16::from_be_bytes([raw_msg[pos + 2], raw_msg[pos + 3]]) as usize;
            
            if attr == attr_type as u16 {
                return Ok(pos);
            }
            
            pos += 4 + len;
            pos += (4 - (len % 4)) % 4; // Padding
        }
        
        Err(StunError::MissingAttribute(format!("{:?}", attr_type)).into())
    }
}

/// STUN attribute
#[derive(Debug, Clone)]
pub struct Attribute {
    pub attr_type: AttributeType,
    pub value: AttributeValue,
}

/// STUN attribute values
#[derive(Debug, Clone)]
pub enum AttributeValue {
    MappedAddress(SocketAddr),
    XorMappedAddress(SocketAddr),
    Username(String),
    Realm(String),
    Nonce(Vec<u8>),
    Software(String),
    ErrorCode { code: u16, reason: String },
    UnknownAttributes(Vec<u16>),
    AlternateServer(SocketAddr),
    ResponseOrigin(SocketAddr),
    OtherAddress(SocketAddr),
    UserHash(Vec<u8>),
    PasswordAlgorithm { algorithm: u16, parameters: Vec<u8> },
    Raw(Vec<u8>),
}

impl Attribute {
    /// Create new attribute
    pub fn new(attr_type: AttributeType, value: AttributeValue) -> Self {
        Self { attr_type, value }
    }
    
    /// Encode attribute
    pub fn encode(&self, buf: &mut BytesMut, tid: &TransactionId) -> NatResult<()> {
        let start_pos = buf.len();
        
        // Write type and placeholder for length
        buf.put_u16(self.attr_type as u16);
        buf.put_u16(0); // Length placeholder
        
        // Encode value
        match &self.value {
            AttributeValue::MappedAddress(addr) => {
                encode_address(buf, addr, false, tid)?;
            }
            AttributeValue::XorMappedAddress(addr) => {
                encode_address(buf, addr, true, tid)?;
            }
            AttributeValue::Username(username) => {
                buf.put_slice(username.as_bytes());
            }
            AttributeValue::Realm(realm) => {
                buf.put_slice(realm.as_bytes());
            }
            AttributeValue::Nonce(nonce) => {
                buf.put_slice(nonce);
            }
            AttributeValue::Software(software) => {
                buf.put_slice(software.as_bytes());
            }
            AttributeValue::ErrorCode { code, reason } => {
                buf.put_u16(0); // Reserved
                buf.put_u8((code / 100) as u8);
                buf.put_u8((code % 100) as u8);
                buf.put_slice(reason.as_bytes());
            }
            AttributeValue::UnknownAttributes(attrs) => {
                for attr in attrs {
                    buf.put_u16(*attr);
                }
            }
            AttributeValue::AlternateServer(addr) |
            AttributeValue::ResponseOrigin(addr) |
            AttributeValue::OtherAddress(addr) => {
                encode_address(buf, addr, true, tid)?;
            }
            AttributeValue::UserHash(hash) => {
                buf.put_slice(hash);
            }
            AttributeValue::PasswordAlgorithm { algorithm, parameters } => {
                buf.put_u16(*algorithm);
                buf.put_u16(parameters.len() as u16);
                buf.put_slice(parameters);
            }
            AttributeValue::Raw(data) => {
                buf.put_slice(data);
            }
        }
        
        // Update length
        let value_len = buf.len() - start_pos - 4;
        buf[start_pos + 2..start_pos + 4].copy_from_slice(&(value_len as u16).to_be_bytes());
        
        // Add padding to 4-byte boundary
        let padding = (4 - (value_len % 4)) % 4;
        for _ in 0..padding {
            buf.put_u8(0);
        }
        
        Ok(())
    }
    
    /// Decode attribute
    pub fn decode(
        attr_type_raw: u16, 
        attr_len: usize, 
        buf: &mut BytesMut,
        tid: &TransactionId
    ) -> NatResult<Self> {
        let attr_data = buf.copy_to_bytes(attr_len);
        let mut attr_buf = BytesMut::from(attr_data.as_ref());
        
        let value = match attr_type_raw {
            0x0001 => AttributeValue::MappedAddress(decode_address(&mut attr_buf, false, tid)?),
            0x0020 => AttributeValue::XorMappedAddress(decode_address(&mut attr_buf, true, tid)?),
            0x0006 => AttributeValue::Username(
                String::from_utf8(attr_buf.to_vec())
                    .map_err(|e| StunError::ParseError(format!("Invalid username: {}", e)))?
            ),
            0x0014 => AttributeValue::Realm(
                String::from_utf8(attr_buf.to_vec())
                    .map_err(|e| StunError::ParseError(format!("Invalid realm: {}", e)))?
            ),
            0x0015 => AttributeValue::Nonce(attr_buf.to_vec()),
            0x8022 => AttributeValue::Software(
                String::from_utf8(attr_buf.to_vec())
                    .map_err(|e| StunError::ParseError(format!("Invalid software: {}", e)))?
            ),
            0x0009 => {
                if attr_buf.remaining() < 4 {
                    return Err(StunError::AttributeParseError {
                        attr_type: attr_type_raw,
                        reason: "ERROR-CODE too short".to_string(),
                    }.into());
                }
                attr_buf.advance(2); // Skip reserved
                let class = attr_buf.get_u8() as u16;
                let number = attr_buf.get_u8() as u16;
                let code = class * 100 + number;
                let reason = String::from_utf8(attr_buf.to_vec())
                    .unwrap_or_else(|_| String::from("Unknown error"));
                AttributeValue::ErrorCode { code, reason }
            }
            0x000A => {
                let mut attrs = Vec::new();
                while attr_buf.remaining() >= 2 {
                    attrs.push(attr_buf.get_u16());
                }
                AttributeValue::UnknownAttributes(attrs)
            }
            0x8023 => AttributeValue::AlternateServer(decode_address(&mut attr_buf, true, tid)?),
            0x802B => AttributeValue::ResponseOrigin(decode_address(&mut attr_buf, true, tid)?),
            0x802C => AttributeValue::OtherAddress(decode_address(&mut attr_buf, true, tid)?),
            0x001E => AttributeValue::UserHash(attr_buf.to_vec()),
            0x001D => {
                if attr_buf.remaining() < 4 {
                    return Err(StunError::AttributeParseError {
                        attr_type: attr_type_raw,
                        reason: "PASSWORD-ALGORITHM too short".to_string(),
                    }.into());
                }
                let algorithm = attr_buf.get_u16();
                let param_len = attr_buf.get_u16() as usize;
                let parameters = if attr_buf.remaining() >= param_len {
                    attr_buf.copy_to_bytes(param_len).to_vec()
                } else {
                    Vec::new()
                };
                AttributeValue::PasswordAlgorithm { algorithm, parameters }
            }
            _ => AttributeValue::Raw(attr_buf.to_vec()),
        };
        
        // Map raw type to enum if possible
        let attr_type = match attr_type_raw {
            0x0001 => AttributeType::MappedAddress,
            0x0020 => AttributeType::XorMappedAddress,
            0x0006 => AttributeType::Username,
            0x0014 => AttributeType::Realm,
            0x0015 => AttributeType::Nonce,
            0x8022 => AttributeType::Software,
            0x0009 => AttributeType::ErrorCode,
            0x000A => AttributeType::UnknownAttributes,
            0x8023 => AttributeType::AlternateServer,
            0x802B => AttributeType::ResponseOrigin,
            0x802C => AttributeType::OtherAddress,
            0x001E => AttributeType::UserHash,
            0x001D => AttributeType::PasswordAlgorithm,
            0x001C => AttributeType::MessageIntegritySha256,
            0x0008 => AttributeType::MessageIntegrity,
            0x8028 => AttributeType::Fingerprint,
            _ => return Err(StunError::AttributeParseError {
                attr_type: attr_type_raw,
                reason: "Unknown attribute type".to_string(),
            }.into()),
        };
        
        Ok(Self { attr_type, value })
    }
}

/// Encode IP address
fn encode_address(buf: &mut BytesMut, addr: &SocketAddr, xor: bool, tid: &TransactionId) -> NatResult<()> {
    buf.put_u8(0); // Reserved
    
    match addr {
        SocketAddr::V4(addr_v4) => {
            buf.put_u8(0x01); // IPv4
            let port = if xor {
                addr_v4.port() ^ (MAGIC_COOKIE >> 16) as u16
            } else {
                addr_v4.port()
            };
            buf.put_u16(port);
            
            let ip_bytes = addr_v4.ip().octets();
            if xor {
                let magic_bytes = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    buf.put_u8(ip_bytes[i] ^ magic_bytes[i]);
                }
            } else {
                buf.put_slice(&ip_bytes);
            }
        }
        SocketAddr::V6(addr_v6) => {
            buf.put_u8(0x02); // IPv6
            let port = if xor {
                addr_v6.port() ^ (MAGIC_COOKIE >> 16) as u16
            } else {
                addr_v6.port()
            };
            buf.put_u16(port);
            
            let ip_bytes = addr_v6.ip().octets();
            if xor {
                let magic_bytes = MAGIC_COOKIE.to_be_bytes();
                let tid_bytes = tid.as_bytes();
                
                // XOR first 4 bytes with magic cookie
                for i in 0..4 {
                    buf.put_u8(ip_bytes[i] ^ magic_bytes[i]);
                }
                
                // XOR remaining 12 bytes with transaction ID
                for i in 0..12 {
                    buf.put_u8(ip_bytes[i + 4] ^ tid_bytes[i]);
                }
            } else {
                buf.put_slice(&ip_bytes);
            }
        }
    }
    
    Ok(())
}

/// Decode IP address
fn decode_address(buf: &mut BytesMut, xor: bool, tid: &TransactionId) -> NatResult<SocketAddr> {
    if buf.remaining() < 8 {
        return Err(StunError::ParseError("Address too short".to_string()).into());
    }
    
    buf.advance(1); // Skip reserved
    let family = buf.get_u8();
    let port_raw = buf.get_u16();
    let port = if xor {
        port_raw ^ (MAGIC_COOKIE >> 16) as u16
    } else {
        port_raw
    };
    
    match family {
        0x01 => {
            // IPv4
            if buf.remaining() < 4 {
                return Err(StunError::InvalidAddressFamily(family).into());
            }
            
            let mut ip_bytes = [0u8; 4];
            buf.copy_to_slice(&mut ip_bytes);
            
            if xor {
                let magic_bytes = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    ip_bytes[i] ^= magic_bytes[i];
                }
            }
            
            let ip = Ipv4Addr::from(ip_bytes);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6
            if buf.remaining() < 16 {
                return Err(StunError::InvalidAddressFamily(family).into());
            }
            
            let mut ip_bytes = [0u8; 16];
            buf.copy_to_slice(&mut ip_bytes);
            
            if xor {
                let magic_bytes = MAGIC_COOKIE.to_be_bytes();
                let tid_bytes = tid.as_bytes();
                
                // XOR first 4 bytes with magic cookie
                for i in 0..4 {
                    ip_bytes[i] ^= magic_bytes[i];
                }
                
                // XOR remaining 12 bytes with transaction ID
                for i in 0..12 {
                    ip_bytes[i + 4] ^= tid_bytes[i];
                }
            }
            
            let ip = Ipv6Addr::from(ip_bytes);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => Err(StunError::InvalidAddressFamily(family).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_encode_decode() {
        let tid = TransactionId::new();
        let mut msg = Message::new(MessageType::BindingRequest, tid);
        
        // Add SOFTWARE attribute
        msg.add_attribute(Attribute::new(
            AttributeType::Software,
            AttributeValue::Software("SHARP STUN 1.0".to_string()),
        ));
        
        // Encode
        let encoded = msg.encode(None, false).unwrap();
        
        // Decode
        let decoded = Message::decode(BytesMut::from(encoded.as_ref())).unwrap();
        
        assert_eq!(decoded.message_type, MessageType::BindingRequest);
        assert_eq!(decoded.transaction_id, tid);
        assert_eq!(decoded.attributes.len(), 1);
    }
    
    #[test]
    fn test_xor_address_encoding() {
        let tid = TransactionId::new();
        let addr = "192.168.1.1:12345".parse::<SocketAddr>().unwrap();
        
        let mut buf = BytesMut::new();
        encode_address(&mut buf, &addr, true, &tid).unwrap();
        
        let mut decode_buf = buf.clone();
        let decoded = decode_address(&mut decode_buf, true, &tid).unwrap();
        
        assert_eq!(addr, decoded);
    }
}