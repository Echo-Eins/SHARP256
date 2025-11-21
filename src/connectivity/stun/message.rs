// src/connectivity/stun/message.rs
//! STUN Message Building and Parsing
//!
//! RFC 8489 Section 5 compliant STUN message format.
//!
//! STUN Message Header (20 bytes):
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     STUN Message Type     |         Message Length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                     Transaction ID (96 bits)                  |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};

use super::attributes::StunAttribute;
use super::constants::*;
use super::transaction::TransactionId;

/// STUN message class (2 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunClass {
    /// Request message
    Request,
    /// Indication message (no response expected)
    Indication,
    /// Success response
    SuccessResponse,
    /// Error response
    ErrorResponse,
}

impl StunClass {
    /// Get the 2-bit class value
    pub fn to_bits(self) -> u16 {
        match self {
            StunClass::Request => 0b00,
            StunClass::Indication => 0b01,
            StunClass::SuccessResponse => 0b10,
            StunClass::ErrorResponse => 0b11,
        }
    }

    /// Parse from 2-bit value
    pub fn from_bits(bits: u16) -> Option<Self> {
        match bits & 0b11 {
            0b00 => Some(StunClass::Request),
            0b01 => Some(StunClass::Indication),
            0b10 => Some(StunClass::SuccessResponse),
            0b11 => Some(StunClass::ErrorResponse),
            _ => None,
        }
    }
}

/// STUN method (12 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunMethod {
    /// Binding method (0x001)
    Binding,
    /// Unknown method
    Unknown(u16),
}

impl StunMethod {
    /// Get the 12-bit method value
    pub fn to_bits(self) -> u16 {
        match self {
            StunMethod::Binding => 0x001,
            StunMethod::Unknown(v) => v,
        }
    }

    /// Parse from 12-bit value
    pub fn from_bits(bits: u16) -> Self {
        match bits {
            0x001 => StunMethod::Binding,
            v => StunMethod::Unknown(v),
        }
    }
}

/// STUN message type combining class and method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunMessageType {
    pub class: StunClass,
    pub method: StunMethod,
}

impl StunMessageType {
    /// Create a new message type
    pub fn new(class: StunClass, method: StunMethod) -> Self {
        Self { class, method }
    }

    /// Binding Request
    pub fn binding_request() -> Self {
        Self::new(StunClass::Request, StunMethod::Binding)
    }

    /// Binding Success Response
    pub fn binding_success() -> Self {
        Self::new(StunClass::SuccessResponse, StunMethod::Binding)
    }

    /// Binding Error Response
    pub fn binding_error() -> Self {
        Self::new(StunClass::ErrorResponse, StunMethod::Binding)
    }

    /// Encode to 16-bit message type
    ///
    /// RFC 8489 Section 5:
    /// The message type field uses a 14-bit encoding where C0 and C1
    /// represent the class and M0-M11 represent the method.
    pub fn encode(&self) -> u16 {
        let method = self.method.to_bits();
        let class = self.class.to_bits();

        // Method bits: M11-M7, M6-M4, M3-M0
        // Class bits: C1, C0
        // Format: 0 0 M11 M10 M9 M8 M7 C1 M6 M5 M4 C0 M3 M2 M1 M0
        let m0_3 = method & 0x000F;
        let m4_6 = (method & 0x0070) >> 4;
        let m7_11 = (method & 0x0F80) >> 7;

        let c0 = class & 0x01;
        let c1 = (class & 0x02) >> 1;

        (m7_11 << 9) | (c1 << 8) | (m4_6 << 5) | (c0 << 4) | m0_3
    }

    /// Decode from 16-bit message type
    pub fn decode(value: u16) -> Option<Self> {
        // Check that the first two bits are 0
        if value & 0xC000 != 0 {
            return None;
        }

        // Extract method and class bits
        let m0_3 = value & 0x000F;
        let c0 = (value >> 4) & 0x01;
        let m4_6 = (value >> 5) & 0x07;
        let c1 = (value >> 8) & 0x01;
        let m7_11 = (value >> 9) & 0x1F;

        let method = m0_3 | (m4_6 << 4) | (m7_11 << 7);
        let class = c0 | (c1 << 1);

        Some(Self {
            class: StunClass::from_bits(class)?,
            method: StunMethod::from_bits(method),
        })
    }
}

/// Complete STUN message
#[derive(Debug, Clone)]
pub struct StunMessage {
    /// Message type (class + method)
    pub msg_type: StunMessageType,

    /// Transaction ID (96 bits)
    pub transaction_id: TransactionId,

    /// Message attributes
    pub attributes: Vec<StunAttribute>,

    /// Raw bytes for MESSAGE-INTEGRITY calculation
    raw_without_integrity: Option<Vec<u8>>,
}

impl StunMessage {
    /// Create a new STUN Binding Request
    pub fn new_binding_request() -> Self {
        Self {
            msg_type: StunMessageType::binding_request(),
            transaction_id: TransactionId::generate(),
            attributes: Vec::new(),
            raw_without_integrity: None,
        }
    }

    /// Create a new STUN message with specific transaction ID
    pub fn with_transaction_id(msg_type: StunMessageType, transaction_id: TransactionId) -> Self {
        Self {
            msg_type,
            transaction_id,
            attributes: Vec::new(),
            raw_without_integrity: None,
        }
    }

    /// Add an attribute to the message
    pub fn add_attribute(&mut self, attr: StunAttribute) {
        self.attributes.push(attr);
    }

    /// Get attribute by type
    pub fn get_attribute(&self, attr_type: u16) -> Option<&StunAttribute> {
        self.attributes.iter().find(|a| a.attr_type() == attr_type)
    }

    /// Check if this is a success response
    pub fn is_success(&self) -> bool {
        self.msg_type.class == StunClass::SuccessResponse
    }

    /// Check if this is an error response
    pub fn is_error(&self) -> bool {
        self.msg_type.class == StunClass::ErrorResponse
    }

    /// Encode message to bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(MAX_MESSAGE_SIZE);

        // Encode attributes first to get length
        let mut attr_buf = BytesMut::new();
        let transaction_id_bytes = self.transaction_id.as_bytes();
        for attr in &self.attributes {
            attr.encode(&mut attr_buf, transaction_id_bytes)?;
        }

        // Write header
        buf.put_u16(self.msg_type.encode());
        buf.put_u16(attr_buf.len() as u16);
        buf.put_u32(MAGIC_COOKIE);
        buf.put_slice(transaction_id_bytes);

        // Write attributes
        buf.put_slice(&attr_buf);

        Ok(buf.to_vec())
    }

    /// Encode message for MESSAGE-INTEGRITY calculation
    /// (includes dummy MESSAGE-INTEGRITY attribute in length)
    pub fn encode_for_integrity(&self, key: &[u8]) -> Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(MAX_MESSAGE_SIZE);

        // Encode attributes (excluding MESSAGE-INTEGRITY)
        let mut attr_buf = BytesMut::new();
        let transaction_id_bytes = self.transaction_id.as_bytes();
        for attr in &self.attributes {
            if attr.attr_type() != ATTR_MESSAGE_INTEGRITY {
                attr.encode(&mut attr_buf, transaction_id_bytes)?;
            }
        }

        // Calculate length including MESSAGE-INTEGRITY (24 bytes: 4 header + 20 HMAC)
        let length_with_integrity = attr_buf.len() + 24;

        // Write header with adjusted length
        buf.put_u16(self.msg_type.encode());
        buf.put_u16(length_with_integrity as u16);
        buf.put_u32(MAGIC_COOKIE);
        buf.put_slice(transaction_id_bytes);

        // Write attributes
        buf.put_slice(&attr_buf);

        Ok(buf.to_vec())
    }

    /// Decode message from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(anyhow::anyhow!("Message too short: {} bytes", data.len()));
        }

        let mut buf = &data[..];

        // Read header
        let msg_type_raw = buf.get_u16();
        let msg_length = buf.get_u16() as usize;
        let magic = buf.get_u32();

        let mut transaction_bytes = [0u8; 12];
        buf.copy_to_slice(&mut transaction_bytes);
        let transaction_id = TransactionId::from_bytes(transaction_bytes);

        // Verify magic cookie
        if magic != MAGIC_COOKIE {
            return Err(anyhow::anyhow!("Invalid magic cookie: 0x{:08X}", magic));
        }

        // Verify message type
        let msg_type = StunMessageType::decode(msg_type_raw)
            .ok_or_else(|| anyhow::anyhow!("Invalid message type: 0x{:04X}", msg_type_raw))?;

        // Verify length
        if msg_length % 4 != 0 {
            return Err(anyhow::anyhow!(
                "Message length not multiple of 4: {}",
                msg_length
            ));
        }

        if data.len() < HEADER_SIZE + msg_length {
            return Err(anyhow::anyhow!(
                "Message truncated: expected {} bytes, got {}",
                HEADER_SIZE + msg_length,
                data.len()
            ));
        }

        // Parse attributes
        let mut attributes = Vec::new();
        let mut attr_data = &data[HEADER_SIZE..HEADER_SIZE + msg_length];

        while attr_data.len() >= 4 {
            let attr = StunAttribute::decode(&mut attr_data, &transaction_bytes)?;
            attributes.push(attr);
        }

        Ok(Self {
            msg_type,
            transaction_id,
            attributes,
            raw_without_integrity: Some(data[..HEADER_SIZE + msg_length].to_vec()),
        })
    }

    /// Get raw message bytes for integrity verification
    pub fn raw_for_integrity(&self) -> Option<&[u8]> {
        self.raw_without_integrity.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_encoding() {
        // Binding Request: method=0x001, class=0b00
        let binding_req = StunMessageType::binding_request();
        assert_eq!(binding_req.encode(), 0x0001);

        // Binding Success Response: method=0x001, class=0b10
        let binding_success = StunMessageType::binding_success();
        assert_eq!(binding_success.encode(), 0x0101);

        // Binding Error Response: method=0x001, class=0b11
        let binding_error = StunMessageType::binding_error();
        assert_eq!(binding_error.encode(), 0x0111);
    }

    #[test]
    fn test_message_type_decoding() {
        let binding_req = StunMessageType::decode(0x0001).unwrap();
        assert_eq!(binding_req.class, StunClass::Request);
        assert_eq!(binding_req.method, StunMethod::Binding);

        let binding_success = StunMessageType::decode(0x0101).unwrap();
        assert_eq!(binding_success.class, StunClass::SuccessResponse);
        assert_eq!(binding_success.method, StunMethod::Binding);
    }

    #[test]
    fn test_binding_request_encoding() {
        let msg = StunMessage::new_binding_request();
        let encoded = msg.encode().unwrap();

        // Should be at least 20 bytes (header)
        assert!(encoded.len() >= 20);

        // Check magic cookie
        assert_eq!(&encoded[4..8], &MAGIC_COOKIE.to_be_bytes());

        // Should be decodable
        let decoded = StunMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.msg_type.class, StunClass::Request);
        assert_eq!(decoded.msg_type.method, StunMethod::Binding);
        assert_eq!(decoded.transaction_id, msg.transaction_id);
    }

    #[test]
    fn test_invalid_magic_cookie() {
        let mut data = vec![0u8; 20];
        data[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Invalid magic

        let result = StunMessage::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_xor_mapped_address_integration_ipv4() {
        use super::super::attributes::{StunAttribute, XorMappedAddress};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // Create a STUN message with XOR-MAPPED-ADDRESS attribute
        let mut msg = StunMessage::new_binding_request();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32853);
        msg.add_attribute(StunAttribute::XorMappedAddress(XorMappedAddress::new(addr)));

        // Encode the message
        let encoded = msg.encode().unwrap();

        // Decode the message
        let decoded = StunMessage::decode(&encoded).unwrap();

        // Verify transaction ID matches
        assert_eq!(decoded.transaction_id, msg.transaction_id);

        // Verify XOR-MAPPED-ADDRESS attribute is correctly decoded
        let xor_attr = decoded
            .get_attribute(ATTR_XOR_MAPPED_ADDRESS)
            .expect("XOR-MAPPED-ADDRESS not found");

        match xor_attr {
            StunAttribute::XorMappedAddress(xma) => {
                assert_eq!(xma.address, addr);
            }
            _ => panic!("Wrong attribute type"),
        }
    }

    #[test]
    fn test_xor_mapped_address_integration_ipv6() {
        use super::super::attributes::{StunAttribute, XorMappedAddress};
        use std::net::{IpAddr, Ipv6Addr, SocketAddr};

        // Create a STUN message with IPv6 XOR-MAPPED-ADDRESS attribute
        let mut msg = StunMessage::new_binding_request();
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334)),
            8080,
        );
        msg.add_attribute(StunAttribute::XorMappedAddress(XorMappedAddress::new(addr)));

        // Encode the message
        let encoded = msg.encode().unwrap();

        // Decode the message
        let decoded = StunMessage::decode(&encoded).unwrap();

        // Verify transaction ID matches
        assert_eq!(decoded.transaction_id, msg.transaction_id);

        // Verify XOR-MAPPED-ADDRESS attribute is correctly decoded with IPv6
        let xor_attr = decoded
            .get_attribute(ATTR_XOR_MAPPED_ADDRESS)
            .expect("XOR-MAPPED-ADDRESS not found");

        match xor_attr {
            StunAttribute::XorMappedAddress(xma) => {
                assert_eq!(xma.address, addr);
            }
            _ => panic!("Wrong attribute type"),
        }
    }

    #[test]
    fn test_xor_mapped_address_different_transaction_ids() {
        use super::super::attributes::{StunAttribute, XorMappedAddress};
        use super::super::transaction::TransactionId;
        use std::net::{IpAddr, Ipv6Addr, SocketAddr};

        // Create two messages with different transaction IDs but same address
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9090);

        let mut msg1 = StunMessage::new_binding_request();
        msg1.add_attribute(StunAttribute::XorMappedAddress(XorMappedAddress::new(addr)));
        let encoded1 = msg1.encode().unwrap();

        let mut msg2 = StunMessage::new_binding_request();
        msg2.add_attribute(StunAttribute::XorMappedAddress(XorMappedAddress::new(addr)));
        let encoded2 = msg2.encode().unwrap();

        // Different transaction IDs should produce different encoded XOR-MAPPED-ADDRESS
        // (for IPv6, since XOR mask includes transaction ID)
        assert_ne!(msg1.transaction_id, msg2.transaction_id);
        assert_ne!(encoded1, encoded2);

        // But both should decode to the same address
        let decoded1 = StunMessage::decode(&encoded1).unwrap();
        let decoded2 = StunMessage::decode(&encoded2).unwrap();

        let get_xor_addr = |msg: &StunMessage| -> SocketAddr {
            match msg.get_attribute(ATTR_XOR_MAPPED_ADDRESS).unwrap() {
                StunAttribute::XorMappedAddress(xma) => xma.address,
                _ => panic!("Wrong attribute type"),
            }
        };

        assert_eq!(get_xor_addr(&decoded1), addr);
        assert_eq!(get_xor_addr(&decoded2), addr);
    }
}
