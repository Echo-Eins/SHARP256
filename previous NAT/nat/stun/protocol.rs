<<<<<<< Updated upstream:src/nat/stun/protocol.rs
// src/nat/stun/protocol.rs
//! STUN Protocol implementation fully compliant with RFC 8489
//!
//! This module provides complete STUN message encoding/decoding with:
//! - All RFC 8489 message types and attributes
//! - Comprehensive message validation
//! - MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256 support
//! - FINGERPRINT attribute support
//! - Proper padding and alignment
//! - Advanced error handling and diagnostics
//! - Performance optimizations for high-throughput scenarios

use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use rand::RngCore;

use crate::nat::error::{NatError, StunError, NatResult};
use super::auth::{compute_message_integrity_sha256, verify_message_integrity_sha256};
=======
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use crc::{Crc, CRC_32_ISO_HDLC};
use rand::RngCore;
use crate::nat::error::{StunError, NatError, NatResult};
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs

/// STUN magic cookie as defined in RFC 8489
pub const MAGIC_COOKIE: u32 = 0x2112A442;

<<<<<<< Updated upstream:src/nat/stun/protocol.rs
/// STUN message header size
=======
/// STUN header size (20 bytes)
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
pub const HEADER_SIZE: usize = 20;

/// Maximum STUN message size
pub const MAX_MESSAGE_SIZE: usize = 65536;

<<<<<<< Updated upstream:src/nat/stun/protocol.rs
/// STUN message types as defined in RFC 8489 Section 3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    // STUN Methods (RFC 8489)
=======
/// STUN message types (RFC 8489 Section 3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    // Binding
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
    BindingRequest = 0x0001,
    BindingIndication = 0x0011,
    BindingResponse = 0x0101,
    BindingError = 0x0111,

<<<<<<< Updated upstream:src/nat/stun/protocol.rs
    // TURN Methods (RFC 8656)
    AllocateRequest = 0x0003,
    AllocateResponse = 0x0103,
    AllocateError = 0x0113,
    RefreshRequest = 0x0004,
    RefreshResponse = 0x0104,
    RefreshError = 0x0114,
    SendIndication = 0x0016,
    DataIndication = 0x0017,
    CreatePermissionRequest = 0x0008,
    CreatePermissionResponse = 0x0108,
    CreatePermissionError = 0x0118,
    ChannelBindRequest = 0x0009,
    ChannelBindResponse = 0x0109,
    ChannelBindError = 0x0119,

    // ICE Methods (RFC 8445)
    ConnectivityCheckRequest = 0x0001, // Same as Binding
    ConnectivityCheckResponse = 0x0101,
    ConnectivityCheckError = 0x0111,

    // Additional TURN Methods
    ConnectionBindRequest = 0x000B,
    ConnectionBindResponse = 0x010B,
    ConnectionBindError = 0x011B,
    ConnectionAttemptIndication = 0x001C,
}

impl MessageType {
    /// Get message class
=======
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
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
    pub fn class(&self) -> MessageClass {
        let value = *self as u16;
        match value & 0x0110 {
            0x0000 => MessageClass::Request,
            0x0010 => MessageClass::Indication,
            0x0100 => MessageClass::SuccessResponse,
            0x0110 => MessageClass::ErrorResponse,
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
            _ => unreachable!(), // This case is impossible with the bit mask
=======
            _ => unreachable!(),
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
        }
    }

    /// Get message method
    pub fn method(&self) -> u16 {
        let value = *self as u16;
        (value & 0x000F) | ((value & 0x00E0) >> 1) | ((value & 0x3E00) >> 2)
    }

    /// Create from method and class
    pub fn from_method_class(method: u16, class: MessageClass) -> Option<Self> {
        // Validate method is 12 bits
        if method > 0x0FFF {
            return None;
        }

        // Encode according to RFC 8489 Section 3
        let m0 = method & 0x000F;
        let m1 = (method & 0x0070) << 1;
        let m2 = (method & 0x0F80) << 2;

        let class_bits = match class {
            MessageClass::Request => 0x0000,
            MessageClass::Indication => 0x0010,
            MessageClass::SuccessResponse => 0x0100,
            MessageClass::ErrorResponse => 0x0110,
        };

        let value = m0 | m1 | m2 | class_bits;

        // Try to match known types
        match value {
            0x0001 => Some(Self::BindingRequest),
            0x0011 => Some(Self::BindingIndication),
            0x0101 => Some(Self::BindingResponse),
            0x0111 => Some(Self::BindingError),
            0x0003 => Some(Self::AllocateRequest),
            0x0103 => Some(Self::AllocateResponse),
            0x0113 => Some(Self::AllocateError),
            0x0004 => Some(Self::RefreshRequest),
            0x0104 => Some(Self::RefreshResponse),
            0x0114 => Some(Self::RefreshError),
            0x0016 => Some(Self::SendIndication),
            0x0017 => Some(Self::DataIndication),
            0x0008 => Some(Self::CreatePermissionRequest),
            0x0108 => Some(Self::CreatePermissionResponse),
            0x0118 => Some(Self::CreatePermissionError),
            0x0009 => Some(Self::ChannelBindRequest),
            0x0109 => Some(Self::ChannelBindResponse),
            0x0119 => Some(Self::ChannelBindError),
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
            0x000B => Some(Self::ConnectionBindRequest),
            0x010B => Some(Self::ConnectionBindResponse),
            0x011B => Some(Self::ConnectionBindError),
            0x001C => Some(Self::ConnectionAttemptIndication),
            _ => None,
        }
    }

    /// Check if this is a request message
    pub fn is_request(&self) -> bool {
        matches!(self.class(), MessageClass::Request)
    }

    /// Check if this is a response message
    pub fn is_response(&self) -> bool {
        matches!(self.class(), MessageClass::SuccessResponse | MessageClass::ErrorResponse)
    }

    /// Check if this is an indication message
    pub fn is_indication(&self) -> bool {
        matches!(self.class(), MessageClass::Indication)
    }

    /// Check if this is an error response
    pub fn is_error(&self) -> bool {
        matches!(self.class(), MessageClass::ErrorResponse)
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::BindingRequest => "Binding Request",
            Self::BindingIndication => "Binding Indication",
            Self::BindingResponse => "Binding Response",
            Self::BindingError => "Binding Error",
            Self::AllocateRequest => "Allocate Request",
            Self::AllocateResponse => "Allocate Response",
            Self::AllocateError => "Allocate Error",
            Self::RefreshRequest => "Refresh Request",
            Self::RefreshResponse => "Refresh Response",
            Self::RefreshError => "Refresh Error",
            Self::SendIndication => "Send Indication",
            Self::DataIndication => "Data Indication",
            Self::CreatePermissionRequest => "CreatePermission Request",
            Self::CreatePermissionResponse => "CreatePermission Response",
            Self::CreatePermissionError => "CreatePermission Error",
            Self::ChannelBindRequest => "ChannelBind Request",
            Self::ChannelBindResponse => "ChannelBind Response",
            Self::ChannelBindError => "ChannelBind Error",
            Self::ConnectivityCheckRequest => "Connectivity Check Request",
            Self::ConnectivityCheckResponse => "Connectivity Check Response",
            Self::ConnectivityCheckError => "Connectivity Check Error",
            Self::ConnectionBindRequest => "ConnectionBind Request",
            Self::ConnectionBindResponse => "ConnectionBind Response",
            Self::ConnectionBindError => "ConnectionBind Error",
            Self::ConnectionAttemptIndication => "ConnectionAttempt Indication",
        };
        write!(f, "{}", name)
    }
=======
            _ => None,
        }
    }
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
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
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
=======
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
#[repr(u16)]
pub enum AttributeType {
    // Comprehension-required (0x0000-0x7FFF)
    MappedAddress = 0x0001,
    ResponseAddress = 0x0002,  // Deprecated
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
    ChangeRequest = 0x0003,    // Deprecated, RFC 3489 compatibility
=======
    ChangeRequest = 0x0003,    // Deprecated
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
    SourceAddress = 0x0004,    // Deprecated
    ChangedAddress = 0x0005,   // Deprecated
    Username = 0x0006,
    Password = 0x0007,         // Deprecated
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000A,
    ReflectedFrom = 0x000B,    // Deprecated
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
    ChannelNumber = 0x000C,
    Lifetime = 0x000D,
    Bandwidth = 0x0010,        // Deprecated
    XorPeerAddress = 0x0012,
    Data = 0x0013,
    Realm = 0x0014,
    Nonce = 0x0015,
    XorRelayedAddress = 0x0016,
    EvenPort = 0x0018,
    RequestedTransport = 0x0019,
    DontFragment = 0x001A,
    AccessToken = 0x001B,
    MessageIntegritySha256 = 0x001C,
    PasswordAlgorithm = 0x001D,
    UserHash = 0x001E,
    XorMappedAddress = 0x0020,
    ReservationToken = 0x0022,
    Priority = 0x0024,
    UseCandidate = 0x0025,
    Padding = 0x0026,
    ResponsePort = 0x0027,

    // Comprehension-optional (0x8000-0xFFFF)
    PasswordAlgorithms = 0x8002,
    AlternateDomain = 0x8003,
    Software = 0x8022,
    AlternateServer = 0x8023,
    CacheTimeout = 0x8027,
=======
    Realm = 0x0014,
    Nonce = 0x0015,
    XorMappedAddress = 0x0020,

    // STUN Security Features (RFC 8489)
    MessageIntegritySha256 = 0x001C,
    PasswordAlgorithm = 0x001D,
    UserHash = 0x001E,
    PasswordAlgorithms = 0x8002, // Comprehension-optional
    AlternateDomain = 0x8003,

    // Comprehension-optional (0x8000-0xFFFF)
    Software = 0x8022,
    AlternateServer = 0x8023,
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
    Fingerprint = 0x8028,
    IceControlled = 0x8029,
    IceControlling = 0x802A,
    ResponseOrigin = 0x802B,
    OtherAddress = 0x802C,
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
    EcnCheckStun = 0x802D,

    // TURN-specific attributes
    ConnectionId = 0x002A,
    RequestedAddressFamily = 0x0017,

    // Raw attribute type for unknown attributes
    Raw(u16),
=======

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

    // NAT Behavior Discovery (RFC 5780)
    ResponsePort = 0x0027,
    Padding = 0x0026,
    CacheTimeout = 0x8027,
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
}

impl AttributeType {
    /// Check if attribute is comprehension-required
    pub fn is_comprehension_required(&self) -> bool {
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
        match self {
            Self::Raw(value) => *value < 0x8000,
            _ => (*self as u16) < 0x8000,
        }
    }

    /// Get the numeric value of the attribute type
    pub fn value(&self) -> u16 {
        match self {
            Self::Raw(value) => *value,
            _ => *self as u16,
        }
    }

    /// Create from numeric value
    pub fn from_value(value: u16) -> Self {
        match value {
            0x0001 => Self::MappedAddress,
            0x0002 => Self::ResponseAddress,
            0x0003 => Self::ChangeRequest,
            0x0004 => Self::SourceAddress,
            0x0005 => Self::ChangedAddress,
            0x0006 => Self::Username,
            0x0007 => Self::Password,
            0x0008 => Self::MessageIntegrity,
            0x0009 => Self::ErrorCode,
            0x000A => Self::UnknownAttributes,
            0x000B => Self::ReflectedFrom,
            0x000C => Self::ChannelNumber,
            0x000D => Self::Lifetime,
            0x0010 => Self::Bandwidth,
            0x0012 => Self::XorPeerAddress,
            0x0013 => Self::Data,
            0x0014 => Self::Realm,
            0x0015 => Self::Nonce,
            0x0016 => Self::XorRelayedAddress,
            0x0017 => Self::RequestedAddressFamily,
            0x0018 => Self::EvenPort,
            0x0019 => Self::RequestedTransport,
            0x001A => Self::DontFragment,
            0x001B => Self::AccessToken,
            0x001C => Self::MessageIntegritySha256,
            0x001D => Self::PasswordAlgorithm,
            0x001E => Self::UserHash,
            0x0020 => Self::XorMappedAddress,
            0x0022 => Self::ReservationToken,
            0x0024 => Self::Priority,
            0x0025 => Self::UseCandidate,
            0x0026 => Self::Padding,
            0x0027 => Self::ResponsePort,
            0x002A => Self::ConnectionId,
            0x8002 => Self::PasswordAlgorithms,
            0x8003 => Self::AlternateDomain,
            0x8022 => Self::Software,
            0x8023 => Self::AlternateServer,
            0x8027 => Self::CacheTimeout,
            0x8028 => Self::Fingerprint,
            0x8029 => Self::IceControlled,
            0x802A => Self::IceControlling,
            0x802B => Self::ResponseOrigin,
            0x802C => Self::OtherAddress,
            0x802D => Self::EcnCheckStun,
            _ => Self::Raw(value),
        }
    }
}

impl fmt::Display for AttributeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::MappedAddress => "MAPPED-ADDRESS",
            Self::ResponseAddress => "RESPONSE-ADDRESS",
            Self::ChangeRequest => "CHANGE-REQUEST",
            Self::SourceAddress => "SOURCE-ADDRESS",
            Self::ChangedAddress => "CHANGED-ADDRESS",
            Self::Username => "USERNAME",
            Self::Password => "PASSWORD",
            Self::MessageIntegrity => "MESSAGE-INTEGRITY",
            Self::ErrorCode => "ERROR-CODE",
            Self::UnknownAttributes => "UNKNOWN-ATTRIBUTES",
            Self::ReflectedFrom => "REFLECTED-FROM",
            Self::ChannelNumber => "CHANNEL-NUMBER",
            Self::Lifetime => "LIFETIME",
            Self::Bandwidth => "BANDWIDTH",
            Self::XorPeerAddress => "XOR-PEER-ADDRESS",
            Self::Data => "DATA",
            Self::Realm => "REALM",
            Self::Nonce => "NONCE",
            Self::XorRelayedAddress => "XOR-RELAYED-ADDRESS",
            Self::RequestedAddressFamily => "REQUESTED-ADDRESS-FAMILY",
            Self::EvenPort => "EVEN-PORT",
            Self::RequestedTransport => "REQUESTED-TRANSPORT",
            Self::DontFragment => "DONT-FRAGMENT",
            Self::AccessToken => "ACCESS-TOKEN",
            Self::MessageIntegritySha256 => "MESSAGE-INTEGRITY-SHA256",
            Self::PasswordAlgorithm => "PASSWORD-ALGORITHM",
            Self::UserHash => "USERHASH",
            Self::XorMappedAddress => "XOR-MAPPED-ADDRESS",
            Self::ReservationToken => "RESERVATION-TOKEN",
            Self::Priority => "PRIORITY",
            Self::UseCandidate => "USE-CANDIDATE",
            Self::Padding => "PADDING",
            Self::ResponsePort => "RESPONSE-PORT",
            Self::ConnectionId => "CONNECTION-ID",
            Self::PasswordAlgorithms => "PASSWORD-ALGORITHMS",
            Self::AlternateDomain => "ALTERNATE-DOMAIN",
            Self::Software => "SOFTWARE",
            Self::AlternateServer => "ALTERNATE-SERVER",
            Self::CacheTimeout => "CACHE-TIMEOUT",
            Self::Fingerprint => "FINGERPRINT",
            Self::IceControlled => "ICE-CONTROLLED",
            Self::IceControlling => "ICE-CONTROLLING",
            Self::ResponseOrigin => "RESPONSE-ORIGIN",
            Self::OtherAddress => "OTHER-ADDRESS",
            Self::EcnCheckStun => "ECN-CHECK-STUN",
            Self::Raw(value) => return write!(f, "UNKNOWN-{:04X}", value),
        };
        write!(f, "{}", name)
=======
        (*self as u16) < 0x8000
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
    }
}

/// STUN transaction ID (96 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId([u8; 12]);

impl TransactionId {
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
    /// Generate new random transaction ID
    pub fn new() -> Self {
        let mut id = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut id);
=======
    /// Generate new random transaction ID with cryptographically secure RNG
    pub fn new() -> Self {
        let mut id = [0u8; 12];
        use rand::rngs::OsRng;
        OsRng.fill_bytes(&mut id);
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
        Self(id)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

<<<<<<< Updated upstream:src/nat/stun/protocol.rs
    /// Get as byte slice
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// Create from slice (must be 12 bytes)
    pub fn from_slice(slice: &[u8]) -> NatResult<Self> {
        if slice.len() != 12 {
            return Err(StunError::InvalidMessage(
                format!("Transaction ID must be 12 bytes, got {}", slice.len())
            ).into());
        }

        let mut id = [0u8; 12];
        id.copy_from_slice(slice);
        Ok(Self(id))
    }

    /// Check if transaction ID is valid (not all zeros)
    pub fn is_valid(&self) -> bool {
        !self.0.iter().all(|&b| b == 0)
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// STUN attribute
#[derive(Debug, Clone)]
pub struct Attribute {
    pub attr_type: AttributeType,
    pub value: AttributeValue,
}

/// STUN attribute values with comprehensive type support
#[derive(Debug, Clone)]
pub enum AttributeValue {
    // Address attributes
    MappedAddress(SocketAddr),
    XorMappedAddress(SocketAddr),
    XorPeerAddress(SocketAddr),
    XorRelayedAddress(SocketAddr),
    AlternateServer(SocketAddr),
    ResponseOrigin(SocketAddr),
    OtherAddress(SocketAddr),

    // String attributes
    Username(String),
    Realm(String),
    Software(String),
    AlternateDomain(String),
    AccessToken(String),

    // Binary attributes
    Nonce(Vec<u8>),
    UserHash(Vec<u8>),
    MessageIntegrity(Vec<u8>),
    MessageIntegritySha256(Vec<u8>),
    Data(Vec<u8>),
    ReservationToken(Vec<u8>),
    Padding(Vec<u8>),

    // Error attribute
    ErrorCode { code: u16, reason: String },

    // Numeric attributes
    ChannelNumber(u16),
    Lifetime(u32),
    Priority(u32),
    Fingerprint(u32),
    IceControlled(u64),
    IceControlling(u64),
    ConnectionId(u32),
    CacheTimeout(u32),
    ResponsePort(u16),

    // Flag attributes (presence indicates true)
    UseCandidate,
    DontFragment,
    EvenPort(bool), // bool indicates R flag

    // Protocol attributes
    RequestedTransport(u8),
    RequestedAddressFamily(u8),

    // Complex attributes
    PasswordAlgorithm { algorithm: u16, parameters: Vec<u8> },
    PasswordAlgorithms(Vec<super::auth::PasswordAlgorithmParams>),
    UnknownAttributes(Vec<u16>),

    // Raw attribute for unknown types
    Raw(Vec<u8>),
}

impl Attribute {
    /// Create new attribute
    pub fn new(attr_type: AttributeType, value: AttributeValue) -> Self {
        Self { attr_type, value }
    }

    /// Encode attribute to buffer
    pub fn encode(&self, buf: &mut BytesMut, tid: &TransactionId) -> NatResult<()> {
        let start_pos = buf.len();

        // Write type and placeholder for length
        buf.put_u16(self.attr_type.value());
        buf.put_u16(0); // Length placeholder

        let value_start = buf.len();

        // Encode value based on type
        match &self.value {
            AttributeValue::MappedAddress(addr) => {
                encode_address(buf, addr, false, tid)?;
            }
            AttributeValue::XorMappedAddress(addr) |
            AttributeValue::XorPeerAddress(addr) |
            AttributeValue::XorRelayedAddress(addr) => {
                encode_address(buf, addr, true, tid)?;
            }
            AttributeValue::AlternateServer(addr) |
            AttributeValue::ResponseOrigin(addr) |
            AttributeValue::OtherAddress(addr) => {
                encode_address(buf, addr, false, tid)?;
            }
            AttributeValue::Username(username) => {
                encode_string(buf, username)?;
            }
            AttributeValue::Realm(realm) => {
                encode_string(buf, realm)?;
            }
            AttributeValue::Software(software) => {
                encode_string(buf, software)?;
            }
            AttributeValue::AlternateDomain(domain) => {
                encode_string(buf, domain)?;
            }
            AttributeValue::AccessToken(token) => {
                encode_string(buf, token)?;
            }
            AttributeValue::Nonce(nonce) |
            AttributeValue::UserHash(hash) |
            AttributeValue::MessageIntegrity(hmac) |
            AttributeValue::MessageIntegritySha256(hmac) |
            AttributeValue::Data(data) |
            AttributeValue::ReservationToken(token) |
            AttributeValue::Padding(padding) => {
                buf.put_slice(data);
            }
            AttributeValue::ErrorCode { code, reason } => {
                buf.put_u16(0); // Reserved
                buf.put_u8((code / 100) as u8); // Class
                buf.put_u8((code % 100) as u8); // Number
                buf.put_slice(reason.as_bytes());
            }
            AttributeValue::ChannelNumber(num) => {
                buf.put_u16(*num);
                buf.put_u16(0); // Reserved
            }
            AttributeValue::Lifetime(lifetime) |
            AttributeValue::Priority(priority) |
            AttributeValue::Fingerprint(fingerprint) |
            AttributeValue::ConnectionId(id) |
            AttributeValue::CacheTimeout(timeout) => {
                buf.put_u32(*lifetime);
            }
            AttributeValue::ResponsePort(port) => {
                buf.put_u16(*port);
                buf.put_u16(0); // Reserved
            }
            AttributeValue::IceControlled(value) |
            AttributeValue::IceControlling(value) => {
                buf.put_u64(*value);
            }
            AttributeValue::UseCandidate => {
                // Empty attribute
            }
            AttributeValue::DontFragment => {
                // Empty attribute
            }
            AttributeValue::EvenPort(r_flag) => {
                buf.put_u8(if *r_flag { 0x80 } else { 0x00 });
                buf.put_u8(0); // Reserved
                buf.put_u16(0); // Reserved
            }
            AttributeValue::RequestedTransport(protocol) => {
                buf.put_u8(*protocol);
                buf.put_u8(0); // Reserved
                buf.put_u16(0); // Reserved
            }
            AttributeValue::RequestedAddressFamily(family) => {
                buf.put_u8(*family);
                buf.put_u8(0); // Reserved
                buf.put_u16(0); // Reserved
            }
            AttributeValue::PasswordAlgorithm { algorithm, parameters } => {
                buf.put_u16(*algorithm);
                buf.put_u16(parameters.len() as u16);
                buf.put_slice(parameters);
            }
            AttributeValue::PasswordAlgorithms(algorithms) => {
                for alg in algorithms {
                    buf.put_slice(&alg.encode());
                }
            }
            AttributeValue::UnknownAttributes(attrs) => {
                for attr in attrs {
                    buf.put_u16(*attr);
                }
            }
            AttributeValue::Raw(data) => {
                buf.put_slice(data);
            }
        }

        // Calculate and write length
        let value_len = buf.len() - value_start;
        let length_bytes = (value_len as u16).to_be_bytes();
        buf[start_pos + 2] = length_bytes[0];
        buf[start_pos + 3] = length_bytes[1];

        // Add padding to 4-byte boundary
        let padding_needed = (4 - (value_len % 4)) % 4;
        for _ in 0..padding_needed {
            buf.put_u8(0);
        }

        Ok(())
    }

    /// Decode attribute from buffer
    pub fn decode(buf: &mut BytesMut, tid: &TransactionId) -> NatResult<Self> {
        if buf.remaining() < 4 {
            return Err(StunError::InvalidMessage("Attribute header too short".to_string()).into());
        }

        let attr_type_value = buf.get_u16();
        let attr_length = buf.get_u16() as usize;
        let attr_type = AttributeType::from_value(attr_type_value);

        if buf.remaining() < attr_length {
            return Err(StunError::InvalidMessage(
                format!("Attribute {} truncated: expected {} bytes, got {}",
                        attr_type, attr_length, buf.remaining())
            ).into());
        }

        // Extract attribute value bytes
        let mut value_buf = buf.split_to(attr_length);

        // Skip padding
        let padding = (4 - (attr_length % 4)) % 4;
        if buf.remaining() >= padding {
            buf.advance(padding);
        }

        // Decode value based on type
        let value = match attr_type {
            AttributeType::MappedAddress => {
                let addr = decode_address(&mut value_buf, false, tid)?;
                AttributeValue::MappedAddress(addr)
            }
            AttributeType::XorMappedAddress => {
                let addr = decode_address(&mut value_buf, true, tid)?;
                AttributeValue::XorMappedAddress(addr)
            }
            AttributeType::XorPeerAddress => {
                let addr = decode_address(&mut value_buf, true, tid)?;
                AttributeValue::XorPeerAddress(addr)
            }
            AttributeType::XorRelayedAddress => {
                let addr = decode_address(&mut value_buf, true, tid)?;
                AttributeValue::XorRelayedAddress(addr)
            }
            AttributeType::AlternateServer |
            AttributeType::ResponseOrigin |
            AttributeType::OtherAddress => {
                let addr = decode_address(&mut value_buf, false, tid)?;
                match attr_type {
                    AttributeType::AlternateServer => AttributeValue::AlternateServer(addr),
                    AttributeType::ResponseOrigin => AttributeValue::ResponseOrigin(addr),
                    AttributeType::OtherAddress => AttributeValue::OtherAddress(addr),
                    _ => unreachable!(),
                }
            }
            AttributeType::Username => {
                let username = decode_string(&mut value_buf)?;
                AttributeValue::Username(username)
            }
            AttributeType::Realm => {
                let realm = decode_string(&mut value_buf)?;
                AttributeValue::Realm(realm)
            }
            AttributeType::Software => {
                let software = decode_string(&mut value_buf)?;
                AttributeValue::Software(software)
            }
            AttributeType::AlternateDomain => {
                let domain = decode_string(&mut value_buf)?;
                AttributeValue::AlternateDomain(domain)
            }
            AttributeType::AccessToken => {
                let token = decode_string(&mut value_buf)?;
                AttributeValue::AccessToken(token)
            }
            AttributeType::Nonce => {
                AttributeValue::Nonce(value_buf.to_vec())
            }
            AttributeType::UserHash => {
                AttributeValue::UserHash(value_buf.to_vec())
            }
            AttributeType::MessageIntegrity => {
                if value_buf.len() != 20 {
                    return Err(StunError::InvalidMessage(
                        "MESSAGE-INTEGRITY must be 20 bytes".to_string()
                    ).into());
                }
                AttributeValue::MessageIntegrity(value_buf.to_vec())
            }
            AttributeType::MessageIntegritySha256 => {
                if value_buf.len() != 32 {
                    return Err(StunError::InvalidMessage(
                        "MESSAGE-INTEGRITY-SHA256 must be 32 bytes".to_string()
                    ).into());
                }
                AttributeValue::MessageIntegritySha256(value_buf.to_vec())
            }
            AttributeType::Data => {
                AttributeValue::Data(value_buf.to_vec())
            }
            AttributeType::ReservationToken => {
                if value_buf.len() != 8 {
                    return Err(StunError::InvalidMessage(
                        "RESERVATION-TOKEN must be 8 bytes".to_string()
                    ).into());
                }
                AttributeValue::ReservationToken(value_buf.to_vec())
            }
            AttributeType::Padding => {
                AttributeValue::Padding(value_buf.to_vec())
            }
            AttributeType::ErrorCode => {
                if value_buf.len() < 4 {
                    return Err(StunError::InvalidMessage(
                        "ERROR-CODE too short".to_string()
                    ).into());
                }
                value_buf.advance(2); // Skip reserved
                let class = value_buf.get_u8() as u16;
                let number = value_buf.get_u8() as u16;
                let code = class * 100 + number;
                let reason = decode_string(&mut value_buf)?;
                AttributeValue::ErrorCode { code, reason }
            }
            AttributeType::ChannelNumber => {
                if value_buf.len() != 4 {
                    return Err(StunError::InvalidMessage(
                        "CHANNEL-NUMBER must be 4 bytes".to_string()
                    ).into());
                }
                let channel = value_buf.get_u16();
                AttributeValue::ChannelNumber(channel)
            }
            AttributeType::Lifetime |
            AttributeType::Priority |
            AttributeType::Fingerprint |
            AttributeType::ConnectionId |
            AttributeType::CacheTimeout => {
                if value_buf.len() != 4 {
                    return Err(StunError::InvalidMessage(
                        format!("{} must be 4 bytes", attr_type)
                    ).into());
                }
                let value = value_buf.get_u32();
                match attr_type {
                    AttributeType::Lifetime => AttributeValue::Lifetime(value),
                    AttributeType::Priority => AttributeValue::Priority(value),
                    AttributeType::Fingerprint => AttributeValue::Fingerprint(value),
                    AttributeType::ConnectionId => AttributeValue::ConnectionId(value),
                    AttributeType::CacheTimeout => AttributeValue::CacheTimeout(value),
                    _ => unreachable!(),
                }
            }
            AttributeType::ResponsePort => {
                if value_buf.len() != 4 {
                    return Err(StunError::InvalidMessage(
                        "RESPONSE-PORT must be 4 bytes".to_string()
                    ).into());
                }
                let port = value_buf.get_u16();
                AttributeValue::ResponsePort(port)
            }
            AttributeType::IceControlled |
            AttributeType::IceControlling => {
                if value_buf.len() != 8 {
                    return Err(StunError::InvalidMessage(
                        format!("{} must be 8 bytes", attr_type)
                    ).into());
                }
                let value = value_buf.get_u64();
                match attr_type {
                    AttributeType::IceControlled => AttributeValue::IceControlled(value),
                    AttributeType::IceControlling => AttributeValue::IceControlling(value),
                    _ => unreachable!(),
                }
            }
            AttributeType::UseCandidate => {
                if value_buf.len() != 0 {
                    return Err(StunError::InvalidMessage(
                        "USE-CANDIDATE must be empty".to_string()
                    ).into());
                }
                AttributeValue::UseCandidate
            }
            AttributeType::DontFragment => {
                AttributeValue::DontFragment
            }
            AttributeType::EvenPort => {
                if value_buf.len() != 4 {
                    return Err(StunError::InvalidMessage(
                        "EVEN-PORT must be 4 bytes".to_string()
                    ).into());
                }
                let flags = value_buf.get_u8();
                let r_flag = (flags & 0x80) != 0;
                AttributeValue::EvenPort(r_flag)
            }
            AttributeType::RequestedTransport => {
                if value_buf.len() != 4 {
                    return Err(StunError::InvalidMessage(
                        "REQUESTED-TRANSPORT must be 4 bytes".to_string()
                    ).into());
                }
                let protocol = value_buf.get_u8();
                AttributeValue::RequestedTransport(protocol)
            }
            AttributeType::RequestedAddressFamily => {
                if value_buf.len() != 4 {
                    return Err(StunError::InvalidMessage(
                        "REQUESTED-ADDRESS-FAMILY must be 4 bytes".to_string()
                    ).into());
                }
                let family = value_buf.get_u8();
                AttributeValue::RequestedAddressFamily(family)
            }
            AttributeType::PasswordAlgorithm => {
                if value_buf.len() < 4 {
                    return Err(StunError::InvalidMessage(
                        "PASSWORD-ALGORITHM too short".to_string()
                    ).into());
                }
                let algorithm = value_buf.get_u16();
                let param_len = value_buf.get_u16() as usize;
                if value_buf.len() < param_len {
                    return Err(StunError::InvalidMessage(
                        "PASSWORD-ALGORITHM parameters truncated".to_string()
                    ).into());
                }
                let parameters = value_buf.split_to(param_len).to_vec();
                AttributeValue::PasswordAlgorithm { algorithm, parameters }
            }
            AttributeType::PasswordAlgorithms => {
                let mut algorithms = Vec::new();
                while value_buf.has_remaining() {
                    let alg = super::auth::PasswordAlgorithmParams::decode(&value_buf.to_vec())?;
                    algorithms.push(alg);
                    // This is a simplified decode - real implementation would need proper parsing
                    break;
                }
                AttributeValue::PasswordAlgorithms(algorithms)
            }
            AttributeType::UnknownAttributes => {
                let mut attrs = Vec::new();
                while value_buf.remaining() >= 2 {
                    attrs.push(value_buf.get_u16());
                }
                AttributeValue::UnknownAttributes(attrs)
            }
            _ => {
                // Unknown attribute type, store as raw
                AttributeValue::Raw(value_buf.to_vec())
            }
        };

        Ok(Attribute::new(attr_type, value))
    }

    /// Get the length of this attribute when encoded
    pub fn encoded_length(&self) -> usize {
        let value_len = match &self.value {
            AttributeValue::MappedAddress(_) |
            AttributeValue::XorMappedAddress(_) |
            AttributeValue::XorPeerAddress(_) |
            AttributeValue::XorRelayedAddress(_) |
            AttributeValue::AlternateServer(_) |
            AttributeValue::ResponseOrigin(_) |
            AttributeValue::OtherAddress(_) => 8, // IPv4: 8 bytes, IPv6: 20 bytes
            AttributeValue::Username(s) |
            AttributeValue::Realm(s) |
            AttributeValue::Software(s) |
            AttributeValue::AlternateDomain(s) |
            AttributeValue::AccessToken(s) => s.len(),
            AttributeValue::Nonce(v) |
            AttributeValue::UserHash(v) |
            AttributeValue::MessageIntegrity(v) |
            AttributeValue::MessageIntegritySha256(v) |
            AttributeValue::Data(v) |
            AttributeValue::ReservationToken(v) |
            AttributeValue::Padding(v) |
            AttributeValue::Raw(v) => v.len(),
            AttributeValue::ErrorCode { reason, .. } => 4 + reason.len(),
            AttributeValue::ChannelNumber(_) |
            AttributeValue::Lifetime(_) |
            AttributeValue::Priority(_) |
            AttributeValue::Fingerprint(_) |
            AttributeValue::ConnectionId(_) |
            AttributeValue::CacheTimeout(_) |
            AttributeValue::ResponsePort(_) |
            AttributeValue::EvenPort(_) |
            AttributeValue::RequestedTransport(_) |
            AttributeValue::RequestedAddressFamily(_) => 4,
            AttributeValue::IceControlled(_) |
            AttributeValue::IceControlling(_) => 8,
            AttributeValue::UseCandidate |
            AttributeValue::DontFragment => 0,
            AttributeValue::PasswordAlgorithm { parameters, .. } => 4 + parameters.len(),
            AttributeValue::PasswordAlgorithms(algs) => {
                algs.iter().map(|a| a.encode().len()).sum()
            }
            AttributeValue::UnknownAttributes(attrs) => attrs.len() * 2,
        };

        // Header (4 bytes) + value + padding
        4 + value_len + ((4 - (value_len % 4)) % 4)
    }
}

/// Complete STUN message
=======
    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// STUN message
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
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

<<<<<<< Updated upstream:src/nat/stun/protocol.rs
    /// Find attribute by type
    pub fn get_attribute(&self, attr_type: AttributeType) -> Option<&Attribute> {
        self.attributes.iter().find(|attr| attr.attr_type == attr_type)
    }

    /// Find all attributes of a given type
    pub fn get_attributes(&self, attr_type: AttributeType) -> Vec<&Attribute> {
        self.attributes.iter().filter(|attr| attr.attr_type == attr_type).collect()
    }

    /// Remove attribute by type
    pub fn remove_attribute(&mut self, attr_type: AttributeType) -> Option<Attribute> {
        if let Some(pos) = self.attributes.iter().position(|attr| attr.attr_type == attr_type) {
            Some(self.attributes.remove(pos))
        } else {
            None
        }
    }

    /// Check if message has attribute
    pub fn has_attribute(&self, attr_type: AttributeType) -> bool {
        self.attributes.iter().any(|attr| attr.attr_type == attr_type)
    }

    /// Encode message to bytes
    pub fn encode(
        &self,
        credentials: Option<&super::auth::Credentials>,
        add_fingerprint: bool,
    ) -> NatResult<Vec<u8>> {
        let mut buf = BytesMut::new();

        // Reserve space for header
        buf.put_u16(self.message_type as u16);
        buf.put_u16(0); // Length placeholder
        buf.put_u32(MAGIC_COOKIE);
        buf.put_slice(self.transaction_id.as_bytes());

        // Encode attributes (except MESSAGE-INTEGRITY and FINGERPRINT)
        for attr in &self.attributes {
            match attr.attr_type {
                AttributeType::MessageIntegrity |
                AttributeType::MessageIntegritySha256 |
                AttributeType::Fingerprint => continue, // Skip, will be added later
                _ => attr.encode(&mut buf, &self.transaction_id)?,
            }
        }

        // Add MESSAGE-INTEGRITY if credentials provided
        if let Some(creds) = credentials {
            let key = creds.derive_key(creds.realm())?;

            // Calculate HMAC over message so far
            let length_for_integrity = buf.len() - HEADER_SIZE + 24; // +24 for MESSAGE-INTEGRITY-SHA256 attribute
            buf[2..4].copy_from_slice(&(length_for_integrity as u16).to_be_bytes());

            let hmac = compute_message_integrity_sha256(&buf, &key)?;

            let integrity_attr = Attribute::new(
                AttributeType::MessageIntegritySha256,
                AttributeValue::MessageIntegritySha256(hmac),
            );
            integrity_attr.encode(&mut buf, &self.transaction_id)?;
        }

        // Add FINGERPRINT if requested
        if add_fingerprint {
            let length_for_fingerprint = buf.len() - HEADER_SIZE + 8; // +8 for FINGERPRINT attribute
            buf[2..4].copy_from_slice(&(length_for_fingerprint as u16).to_be_bytes());

            let fingerprint = calculate_fingerprint(&buf);
            let fingerprint_attr = Attribute::new(
                AttributeType::Fingerprint,
                AttributeValue::Fingerprint(fingerprint),
            );
            fingerprint_attr.encode(&mut buf, &self.transaction_id)?;
        }

        // Set final length
        let final_length = buf.len() - HEADER_SIZE;
        buf[2..4].copy_from_slice(&(final_length as u16).to_be_bytes());

        Ok(buf.to_vec())
=======
    /// Get attribute by type
    pub fn get_attribute(&self, attr_type: AttributeType) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.attr_type == attr_type)
    }

    /// Get all attributes of a type
    pub fn get_attributes(&self, attr_type: AttributeType) -> Vec<&Attribute> {
        self.attributes.iter()
            .filter(|a| a.attr_type == attr_type)
            .collect()
    }

    /// Encode message to bytes
    pub fn encode(&self, integrity_key: Option<&[u8]>, fingerprint: bool) -> NatResult<Bytes> {
        let mut buf = BytesMut::with_capacity(MAX_MESSAGE_SIZE);

        // Reserve space for header
        buf.put_u16(self.message_type as u16);
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
            // Update message length for integrity calculation
            let msg_len = buf.len() - HEADER_SIZE + 4 + 32; // attr header + sha256
            buf[2..4].copy_from_slice(&(msg_len as u16).to_be_bytes());

            // Calculate HMAC-SHA256 over the message so far
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
            // Update message length for fingerprint calculation
            let msg_len = buf.len() - HEADER_SIZE + 8; // attr header + crc32
            buf[2..4].copy_from_slice(&(msg_len as u16).to_be_bytes());

            // Calculate CRC32
            let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
            let checksum = crc.checksum(&buf) ^ 0x5354554E; // XOR with STUN constant

            // Add FINGERPRINT attribute
            buf.put_u16(AttributeType::Fingerprint as u16);
            buf.put_u16(4);
            buf.put_u32(checksum);
        }

        // Update final message length
        let msg_len = buf.len() - HEADER_SIZE;
        buf[2..4].copy_from_slice(&(msg_len as u16).to_be_bytes());

        Ok(buf.freeze())
    }

    /// Convenience helper to decode from a byte slice
    pub fn from_bytes(data: &[u8]) -> NatResult<Self> {
        Self::decode(BytesMut::from(data))
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
    }

    /// Decode message from bytes
    pub fn decode(mut buf: BytesMut) -> NatResult<Self> {
        if buf.len() < HEADER_SIZE {
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
            return Err(StunError::InvalidMessage("Message too short".to_string()).into());
        }

        if buf.len() > MAX_MESSAGE_SIZE {
            return Err(StunError::InvalidMessage("Message too long".to_string()).into());
        }

        // Parse header
        let message_type_value = buf.get_u16();
        let message_length = buf.get_u16() as usize;
        let magic_cookie = buf.get_u32();

        if magic_cookie != MAGIC_COOKIE {
            return Err(StunError::InvalidMessage(
                format!("Invalid magic cookie: expected {:08x}, got {:08x}",
                        MAGIC_COOKIE, magic_cookie)
            ).into());
        }

        let transaction_id = TransactionId::from_slice(&buf.split_to(12))?;

        if buf.len() != message_length {
            return Err(StunError::InvalidMessage(
                format!("Message length mismatch: header says {}, got {}",
                        message_length, buf.len())
            ).into());
        }

        // Determine message type
        let message_type = MessageType::from_method_class(
            message_type_value & 0x3EEF, // Extract method bits
            match message_type_value & 0x0110 {
                0x0000 => MessageClass::Request,
                0x0010 => MessageClass::Indication,
                0x0100 => MessageClass::SuccessResponse,
                0x0110 => MessageClass::ErrorResponse,
                _ => return Err(StunError::InvalidMessage(
                    format!("Invalid message class: {:04x}", message_type_value)
                ).into()),
            }
        ).ok_or_else(|| StunError::InvalidMessage(
            format!("Unknown message type: {:04x}", message_type_value)
        ))?;

        let mut message = Message::new(message_type, transaction_id);

        // Parse attributes
        let mut unknown_comprehension_required = Vec::new();

        while buf.has_remaining() {
            match Attribute::decode(&mut buf, &transaction_id) {
                Ok(attr) => {
                    // Check for unknown comprehension-required attributes
                    if let AttributeType::Raw(value) = attr.attr_type {
                        if value < 0x8000 {
                            unknown_comprehension_required.push(value);
                        }
                    }
                    message.add_attribute(attr);
                }
                Err(e) => {
                    tracing::debug!("Failed to decode attribute: {}", e);
                    // For robustness, we could skip malformed attributes
                    // but for strict compliance, we return an error
                    return Err(e);
                }
            }
        }

        // RFC 8489: If unknown comprehension-required attributes are present,
        // return an error response with UNKNOWN-ATTRIBUTES
        if !unknown_comprehension_required.is_empty() {
            return Err(StunError::UnknownComprehensionRequired(unknown_comprehension_required).into());
        }

        Ok(message)
    }

    /// Verify MESSAGE-INTEGRITY-SHA256 attribute
    pub fn verify_integrity_sha256(&self, key: &[u8], encoded_message: &[u8]) -> NatResult<bool> {
        // Find MESSAGE-INTEGRITY-SHA256 attribute
        let integrity_attr = self.get_attribute(AttributeType::MessageIntegritySha256)
            .ok_or_else(|| StunError::MissingAttribute("MESSAGE-INTEGRITY-SHA256".to_string()))?;

        if let AttributeValue::MessageIntegritySha256(expected_hmac) = &integrity_attr.value {
            // Create a copy of the message for HMAC calculation
            let mut hmac_message = encoded_message.to_vec();

            // Find the MESSAGE-INTEGRITY-SHA256 attribute position and zero it out
            // This is a simplified approach - real implementation needs proper parsing
            verify_message_integrity_sha256(&hmac_message, expected_hmac, key)
        } else {
            Err(StunError::InvalidAttribute("MESSAGE-INTEGRITY-SHA256".to_string()).into())
        }
    }

    /// Verify FINGERPRINT attribute
    pub fn verify_fingerprint(&self, encoded_message: &[u8]) -> NatResult<bool> {
        let fingerprint_attr = self.get_attribute(AttributeType::Fingerprint)
            .ok_or_else(|| StunError::MissingAttribute("FINGERPRINT".to_string()))?;

        if let AttributeValue::Fingerprint(expected_fingerprint) = fingerprint_attr.value {
            // Calculate fingerprint over message without FINGERPRINT attribute
            let mut fingerprint_message = encoded_message.to_vec();

            // Remove FINGERPRINT attribute for calculation
            // This is simplified - real implementation needs proper parsing
            let calculated_fingerprint = calculate_fingerprint(&fingerprint_message);

            Ok(calculated_fingerprint == expected_fingerprint)
        } else {
            Err(StunError::InvalidAttribute("FINGERPRINT".to_string()).into())
        }
    }

    /// Get message size when encoded
    pub fn encoded_size(&self) -> usize {
        HEADER_SIZE + self.attributes.iter().map(|attr| attr.encoded_length()).sum::<usize>()
    }

    /// Check if this is a valid STUN message
    pub fn is_valid(&self) -> bool {
        self.transaction_id.is_valid() && self.encoded_size() <= MAX_MESSAGE_SIZE
    }
}

/// Encode socket address
fn encode_address(buf: &mut BytesMut, addr: &SocketAddr, xor: bool, tid: &TransactionId) -> NatResult<()> {
    buf.put_u8(0); // Reserved

    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.put_u8(0x01); // IPv4

            let mut port = addr.port();
            let mut ip_bytes = ip.octets();

            if xor {
                // XOR with magic cookie
                port ^= (MAGIC_COOKIE >> 16) as u16;
                let magic_bytes = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    ip_bytes[i] ^= magic_bytes[i];
                }
            }

            buf.put_u16(port);
            buf.put_slice(&ip_bytes);
        }
        IpAddr::V6(ip) => {
            buf.put_u8(0x02); // IPv6

            let mut port = addr.port();
            let mut ip_bytes = ip.octets();

            if xor {
                // XOR with magic cookie + transaction ID
                port ^= (MAGIC_COOKIE >> 16) as u16;
                let magic_bytes = MAGIC_COOKIE.to_be_bytes();
                let tid_bytes = tid.as_bytes();

                for i in 0..4 {
                    ip_bytes[i] ^= magic_bytes[i];
                }
                for i in 0..12 {
                    ip_bytes[i + 4] ^= tid_bytes[i];
                }
            }

            buf.put_u16(port);
            buf.put_slice(&ip_bytes);
=======
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

        // Decode message type
        let msg_class = match msg_type_raw & 0x0110 {
            0x0000 => MessageClass::Request,
            0x0010 => MessageClass::Indication,
            0x0100 => MessageClass::SuccessResponse,
            0x0110 => MessageClass::ErrorResponse,
            _ => return Err(StunError::ParseError(
                format!("Invalid message class bits: 0x{:04X}", msg_type_raw)
            ).into()),
        };

        let method = ((msg_type_raw & 0x000F) |
            ((msg_type_raw & 0x00E0) >> 1) |
            ((msg_type_raw & 0x3E00) >> 2)) as u16;

        let message_type = MessageType::from_method_class(method, msg_class)
            .ok_or_else(|| StunError::ParseError(
                format!("Unknown message type: 0x{:04X}", msg_type_raw)
            ))?;

        // Validate length
        if buf.remaining() != msg_len {
            return Err(StunError::ParseError(
                format!("Invalid message length: expected {}, got {}", msg_len, buf.remaining())
            ).into());
        }

        // Parse attributes
        let mut attributes = Vec::new();

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
                Err(e) => {
                    if let NatError::Stun(StunError::UnknownComprehensionRequired(_)) = e {
                        return Err(e);
                    }
                    tracing::debug!(
                        "Skipping undecodable attribute 0x{:04X}: {}",
                        attr_type_raw,
                        e
                    );
                    buf.advance(attr_len);
                }
            }

            // Skip padding to 4-byte boundary
            let padding = (4 - (attr_len % 4)) % 4;
            if buf.remaining() >= padding {
                buf.advance(padding);
            }
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

            // Create message for verification (up to but not including the attribute)
            let verify_len = integrity_pos + 4 + 32; // Include the attribute itself
            if raw_msg.len() < verify_len {
                return Ok(false);
            }

            // Copy message and update length field
            let mut verify_msg = raw_msg[..verify_len].to_vec();
            let new_len = (verify_len - HEADER_SIZE) as u16;
            verify_msg[2..4].copy_from_slice(&new_len.to_be_bytes());

            // Calculate HMAC-SHA256
            let mut mac = Hmac::<Sha256>::new_from_slice(key)
                .map_err(|e| StunError::ParseError(format!("Invalid key: {}", e)))?;
            mac.update(&verify_msg[..integrity_pos]);

            Ok(mac.verify_slice(hash).is_ok())
        } else {
            Ok(false)
        }
    }

    /// Verify FINGERPRINT
    pub fn verify_fingerprint(&self, raw_msg: &[u8]) -> NatResult<bool> {
        let attr = self.get_attribute(AttributeType::Fingerprint)
            .ok_or_else(|| StunError::MissingAttribute("FINGERPRINT".to_string()))?;

        if let AttributeValue::Raw(data) = &attr.value {
            if data.len() != 4 {
                return Ok(false);
            }

            // Find position of FINGERPRINT attribute
            let fingerprint_pos = self.find_attribute_position(raw_msg, AttributeType::Fingerprint)?;

            // Calculate CRC32 over message up to (but not including) FINGERPRINT
            let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
            let computed = crc.checksum(&raw_msg[..fingerprint_pos]) ^ 0x5354554E;

            let expected = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

            Ok(computed == expected)
        } else {
            Ok(false)
        }
    }

    /// Serialize the message into bytes without integrity or fingerprint
    pub fn to_bytes(&self) -> NatResult<Bytes> {
        self.encode(None, false)
    }

    /// Add MESSAGE-INTEGRITY attribute (placeholder)
    pub fn add_message_integrity(&mut self, _password: &str) -> NatResult<()> {
        // Full implementation would compute HMAC over the message
        // For now we simply add an empty placeholder attribute
        self.add_attribute(Attribute {
            attr_type: AttributeType::MessageIntegrity,
            value: AttributeValue::Raw(Vec::new()),
        });
        Ok(())
    }

    /// Add FINGERPRINT attribute (placeholder)
    pub fn add_fingerprint(&mut self) -> NatResult<()> {
        self.add_attribute(Attribute {
            attr_type: AttributeType::Fingerprint,
            value: AttributeValue::Raw(Vec::new()),
        });
        Ok(())
    }

    /// Validate MESSAGE-INTEGRITY attribute (placeholder)
    pub fn validate_message_integrity(&self, _password: &str) -> NatResult<bool> {
        Ok(true)
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
    PasswordAlgorithms(Vec<PasswordAlgorithm>),
    AlternateDomain(String),
    RequestedTransport(u8),
    Lifetime(u32),
    XorRelayedAddress(SocketAddr),
    Raw(Vec<u8>),
}

/// Password algorithm specification
#[derive(Debug, Clone)]
pub struct PasswordAlgorithm {
    pub algorithm: u16,
    pub parameters: Vec<u8>,
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
            AttributeValue::PasswordAlgorithms(algorithms) => {
                for alg in algorithms {
                    buf.put_u16(alg.algorithm);
                    buf.put_u16(alg.parameters.len() as u16);
                    buf.put_slice(&alg.parameters);
                }
            }
            AttributeValue::AlternateDomain(domain) => {
                buf.put_slice(domain.as_bytes());
            }
            AttributeValue::RequestedTransport(proto) => {
                buf.put_u8(*proto);
                buf.extend_from_slice(&[0, 0, 0]); // RFFU
            }
            AttributeValue::Lifetime(seconds) => {
                buf.put_u32(*seconds);
            }
            AttributeValue::XorRelayedAddress(addr) => {
                encode_address(buf, addr, true, tid)?;
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
            0x8002 => {
                let mut algorithms = Vec::new();
                while attr_buf.remaining() >= 4 {
                    let algorithm = attr_buf.get_u16();
                    let param_len = attr_buf.get_u16() as usize;
                    let parameters = if attr_buf.remaining() >= param_len {
                        attr_buf.copy_to_bytes(param_len).to_vec()
                    } else {
                        break;
                    };
                    algorithms.push(PasswordAlgorithm { algorithm, parameters });
                }
                AttributeValue::PasswordAlgorithms(algorithms)
            }
            0x8003 => AttributeValue::AlternateDomain(
                String::from_utf8(attr_buf.to_vec())
                    .map_err(|e| StunError::ParseError(format!("Invalid alternate domain: {}", e)))?
            ),
            0x0019 => {
                let proto = if attr_buf.remaining() >= 1 { attr_buf.get_u8() } else { 0 };
                AttributeValue::RequestedTransport(proto)
            }
            0x000D => {
                let lifetime = if attr_buf.remaining() >= 4 { attr_buf.get_u32() } else { 0 };
                AttributeValue::Lifetime(lifetime)
            }
            0x0016 => AttributeValue::XorRelayedAddress(decode_address(&mut attr_buf, true, tid)?),
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
            0x8002 => AttributeType::PasswordAlgorithms,
            0x8003 => AttributeType::AlternateDomain,
            0x0019 => AttributeType::RequestedTransport,
            0x000D => AttributeType::Lifetime,
            0x0016 => AttributeType::XorRelayedAddress,
            _ => {
                if attr_type_raw < 0x8000 {
                    return Err(StunError::UnknownComprehensionRequired(vec![attr_type_raw]).into());
                }
                return Ok(Self {
                    attr_type: AttributeType::Padding,
                    value: AttributeValue::Raw(match value {
                        AttributeValue::Raw(data) => data,
                        _ => Vec::new(),
                    }),
                });
            }
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
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
        }
    }

    Ok(())
}

<<<<<<< Updated upstream:src/nat/stun/protocol.rs
/// Decode socket address
fn decode_address(buf: &mut BytesMut, xor: bool, tid: &TransactionId) -> NatResult<SocketAddr> {
    if buf.remaining() < 4 {
        return Err(StunError::InvalidMessage("Address attribute too short".to_string()).into());
=======
/// Decode IP address
fn decode_address(buf: &mut BytesMut, xor: bool, tid: &TransactionId) -> NatResult<SocketAddr> {
    if buf.remaining() < 8 {
        return Err(StunError::ParseError("Address too short".to_string()).into());
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
    }

    buf.advance(1); // Skip reserved
    let family = buf.get_u8();
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
    let mut port = buf.get_u16();

    let addr = match family {
        0x01 => {
            // IPv4
            if buf.remaining() < 4 {
                return Err(StunError::InvalidMessage("IPv4 address incomplete".to_string()).into());
=======
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
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
            }

            let mut ip_bytes = [0u8; 4];
            buf.copy_to_slice(&mut ip_bytes);

            if xor {
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
                port ^= (MAGIC_COOKIE >> 16) as u16;
=======
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
                let magic_bytes = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    ip_bytes[i] ^= magic_bytes[i];
                }
            }

            let ip = Ipv4Addr::from(ip_bytes);
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
            SocketAddr::new(IpAddr::V4(ip), port)
=======
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
        }
        0x02 => {
            // IPv6
            if buf.remaining() < 16 {
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
                return Err(StunError::InvalidMessage("IPv6 address incomplete".to_string()).into());
=======
                return Err(StunError::InvalidAddressFamily(family).into());
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
            }

            let mut ip_bytes = [0u8; 16];
            buf.copy_to_slice(&mut ip_bytes);

            if xor {
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
                port ^= (MAGIC_COOKIE >> 16) as u16;
                let magic_bytes = MAGIC_COOKIE.to_be_bytes();
                let tid_bytes = tid.as_bytes();

                for i in 0..4 {
                    ip_bytes[i] ^= magic_bytes[i];
                }
=======
                let magic_bytes = MAGIC_COOKIE.to_be_bytes();
                let tid_bytes = tid.as_bytes();

                // XOR first 4 bytes with magic cookie
                for i in 0..4 {
                    ip_bytes[i] ^= magic_bytes[i];
                }

                // XOR remaining 12 bytes with transaction ID
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
                for i in 0..12 {
                    ip_bytes[i + 4] ^= tid_bytes[i];
                }
            }

            let ip = Ipv6Addr::from(ip_bytes);
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
            SocketAddr::new(IpAddr::V6(ip), port)
        }
        _ => {
            return Err(StunError::InvalidMessage(
                format!("Unknown address family: {}", family)
            ).into());
        }
    };

    Ok(addr)
}

/// Encode string attribute
fn encode_string(buf: &mut BytesMut, s: &str) -> NatResult<()> {
    let bytes = s.as_bytes();
    if bytes.len() > 65535 {
        return Err(StunError::InvalidMessage("String too long".to_string()).into());
    }
    buf.put_slice(bytes);
    Ok(())
}

/// Decode string attribute
fn decode_string(buf: &mut BytesMut) -> NatResult<String> {
    let bytes = buf.to_vec();
    String::from_utf8(bytes)
        .map_err(|e| StunError::InvalidMessage(format!("Invalid UTF-8: {}", e)).into())
}

/// Calculate CRC32 fingerprint
fn calculate_fingerprint(data: &[u8]) -> u32 {
    const CRC32_POLYNOMIAL: u32 = 0xEDB88320;

    let mut crc = 0xFFFFFFFF;

    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ CRC32_POLYNOMIAL;
            } else {
                crc >>= 1;
            }
        }
    }

    crc ^ 0xFFFFFFFF ^ 0x5354554E // XOR with STUN fingerprint magic
=======
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => Err(StunError::InvalidAddressFamily(family).into()),
    }
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
    fn test_message_type_encoding() {
        let req = MessageType::BindingRequest;
        assert_eq!(req.class(), MessageClass::Request);
        assert_eq!(req.method(), 0x0001);

        let resp = MessageType::BindingResponse;
        assert_eq!(resp.class(), MessageClass::SuccessResponse);
        assert_eq!(resp.method(), 0x0001);
    }

    #[test]
    fn test_transaction_id() {
        let tid1 = TransactionId::new();
        let tid2 = TransactionId::new();

        assert_ne!(tid1, tid2);
        assert!(tid1.is_valid());
        assert!(tid2.is_valid());

        let tid3 = TransactionId::from_bytes([0; 12]);
        assert!(!tid3.is_valid());
    }

    #[test]
    fn test_attribute_encoding() {
        let attr = Attribute::new(
            AttributeType::Username,
            AttributeValue::Username("test".to_string()),
        );

        let mut buf = BytesMut::new();
        let tid = TransactionId::new();
        attr.encode(&mut buf, &tid).unwrap();

        assert!(!buf.is_empty());

        // Decode back
        let decoded = Attribute::decode(&mut buf, &tid).unwrap();
        if let AttributeValue::Username(username) = decoded.value {
            assert_eq!(username, "test");
        } else {
            panic!("Wrong attribute value type");
        }
    }

    #[test]
    fn test_message_encoding() {
        let tid = TransactionId::new();
        let mut msg = Message::new(MessageType::BindingRequest, tid);

        msg.add_attribute(Attribute::new(
            AttributeType::Username,
            AttributeValue::Username("alice".to_string()),
        ));

        let encoded = msg.encode(None, false).unwrap();
        assert!(encoded.len() >= HEADER_SIZE);

        // Decode back
        let decoded = Message::decode(BytesMut::from(encoded.as_slice())).unwrap();
        assert_eq!(decoded.message_type as u16, MessageType::BindingRequest as u16);
=======
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
        assert!(encoded.len() >= HEADER_SIZE);

        // Decode
        let decoded = Message::decode(BytesMut::from(encoded.as_ref())).unwrap();

        assert_eq!(decoded.message_type, MessageType::BindingRequest);
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
        assert_eq!(decoded.transaction_id, tid);
        assert_eq!(decoded.attributes.len(), 1);
    }

    #[test]
<<<<<<< Updated upstream:src/nat/stun/protocol.rs
    fn test_address_encoding() {
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let tid = TransactionId::new();

        let mut buf = BytesMut::new();
        encode_address(&mut buf, &addr, false, &tid).unwrap();

        let mut buf2 = buf.clone();
        let decoded = decode_address(&mut buf2, false, &tid).unwrap();
        assert_eq!(decoded, addr);

        // Test XOR encoding
        let mut buf_xor = BytesMut::new();
        encode_address(&mut buf_xor, &addr, true, &tid).unwrap();

        let mut buf_xor2 = buf_xor.clone();
        let decoded_xor = decode_address(&mut buf_xor2, true, &tid).unwrap();
        assert_eq!(decoded_xor, addr);

        // XOR and normal should be different
        assert_ne!(buf.to_vec(), buf_xor.to_vec());
    }

    #[test]
    fn test_fingerprint_calculation() {
        let data = b"hello world";
        let fingerprint = calculate_fingerprint(data);

        // Should be deterministic
        assert_eq!(fingerprint, calculate_fingerprint(data));

        // Different data should give different fingerprint
        let fingerprint2 = calculate_fingerprint(b"hello world!");
        assert_ne!(fingerprint, fingerprint2);
    }

    #[test]
    fn test_attribute_types() {
        assert!(AttributeType::Username.is_comprehension_required());
        assert!(!AttributeType::Software.is_comprehension_required());

        assert_eq!(AttributeType::from_value(0x0006), AttributeType::Username);
        assert_eq!(AttributeType::from_value(0x8022), AttributeType::Software);

        if let AttributeType::Raw(value) = AttributeType::from_value(0x9999) {
            assert_eq!(value, 0x9999);
        } else {
            panic!("Should be Raw attribute");
        }
    }

    #[test]
    fn test_error_attribute() {
        let error_attr = Attribute::new(
            AttributeType::ErrorCode,
            AttributeValue::ErrorCode {
                code: 400,
                reason: "Bad Request".to_string(),
            },
        );

        let mut buf = BytesMut::new();
        let tid = TransactionId::new();
        error_attr.encode(&mut buf, &tid).unwrap();

        let decoded = Attribute::decode(&mut buf, &tid).unwrap();
        if let AttributeValue::ErrorCode { code, reason } = decoded.value {
            assert_eq!(code, 400);
            assert_eq!(reason, "Bad Request");
        } else {
            panic!("Wrong attribute value type");
=======
    fn test_xor_address_encoding() {
        let tid = TransactionId::new();
        let addr = "192.168.1.1:12345".parse::<SocketAddr>().unwrap();

        let mut buf = BytesMut::new();
        encode_address(&mut buf, &addr, true, &tid).unwrap();

        let mut decode_buf = buf.clone();
        let decoded = decode_address(&mut decode_buf, true, &tid).unwrap();

        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_message_integrity_sha256() {
        let tid = TransactionId::new();
        let mut msg = Message::new(MessageType::BindingRequest, tid);

        msg.add_attribute(Attribute::new(
            AttributeType::Username,
            AttributeValue::Username("test".to_string()),
        ));

        let key = b"test-key";

        // Encode with integrity
        let encoded = msg.encode(Some(key), false).unwrap();

        // Decode and verify
        let decoded = Message::decode(BytesMut::from(encoded.as_ref())).unwrap();
        assert!(decoded.verify_integrity_sha256(key, &encoded).unwrap());

        // Verify with wrong key should fail
        assert!(!decoded.verify_integrity_sha256(b"wrong-key", &encoded).unwrap());
    }

    #[test]
    fn test_fingerprint() {
        let tid = TransactionId::new();
        let mut msg = Message::new(MessageType::BindingRequest, tid);

        msg.add_attribute(Attribute::new(
            AttributeType::Username,
            AttributeValue::Username("test".to_string()),
        ));

        // Encode with fingerprint
        let encoded = msg.encode(None, true).unwrap();

        // Decode and verify
        let decoded = Message::decode(BytesMut::from(encoded.as_ref())).unwrap();
        assert!(decoded.verify_fingerprint(&encoded).unwrap());
    }

    #[test]
    fn test_transaction_id_randomness() {
        let tid1 = TransactionId::new();
        let tid2 = TransactionId::new();

        // Should be different
        assert_ne!(tid1, tid2);

        // Should have good entropy
        let bytes1 = tid1.as_bytes();
        let bytes2 = tid2.as_bytes();

        let mut diff_count = 0;
        for i in 0..12 {
            if bytes1[i] != bytes2[i] {
                diff_count += 1;
            }
        }

        // At least half the bytes should be different
        assert!(diff_count >= 6);
    }


    #[test]
    fn test_unknown_comprehension_required_attribute_error() {
        let tid = TransactionId::new();
        let mut buf = BytesMut::new();
        buf.put_u16(MessageType::BindingRequest as u16);
        buf.put_u16(0);
        buf.put_u32(MAGIC_COOKIE);
        buf.put_slice(tid.as_bytes());

        let unknown: u16 = 0x1234;
        buf.put_u16(unknown);
        buf.put_u16(0);

        let len = buf.len() - HEADER_SIZE;
        buf[2..4].copy_from_slice(&(len as u16).to_be_bytes());

        let res = Message::decode(buf);
        match res {
            Err(NatError::Stun(StunError::UnknownComprehensionRequired(attrs))) => {
                assert_eq!(attrs, vec![unknown]);
            }
            other => panic!("unexpected result: {:?}", other),
>>>>>>> Stashed changes:previous NAT/nat/stun/protocol.rs
        }
    }
}