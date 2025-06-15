use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

/// Comprehensive error types for NAT traversal operations
#[derive(Debug, Error)]
pub enum NatError {
    /// STUN protocol errors
    #[error("STUN error: {0}")]
    Stun(#[from] StunError),

    /// UPnP IGD errors
    #[error("UPnP error: {0}")]
    Upnp(#[from] UpnpError),

    /// Network I/O errors
    #[error("Network I/O error: {0}")]
    Io(#[from] io::Error),

    /// Timeout errors
    #[error("Operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// NAT type incompatibility
    #[error("NAT type {nat_type:?} is incompatible with {method}")]
    IncompatibleNatType {
        nat_type: crate::nat::NatType,
        method: String,
    },

    /// No available methods
    #[error("All NAT traversal methods exhausted")]
    NoAvailableMethods,

    /// Circuit breaker opened
    #[error("Circuit breaker is open for {method}")]
    CircuitBreakerOpen { method: String },

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Platform-specific error
    #[error("Platform error: {0}")]
    Platform(String),

    /// Relay server error
    #[error("Relay server error: {0}")]
    RelayServer(String),

    /// Authentication failure
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Resource exhaustion
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),
}

/// STUN-specific errors following RFC 8489
#[derive(Debug, Error)]
pub enum StunError {
    /// Protocol version mismatch
    #[error("Unsupported STUN version: {0}")]
    UnsupportedVersion(u8),

    /// Invalid magic cookie
    #[error("Invalid magic cookie: expected 0x2112A442, got 0x{0:08X}")]
    InvalidMagicCookie(u32),

    /// Transaction ID mismatch
    #[error("Transaction ID mismatch")]
    TransactionIdMismatch,

    /// Message parsing error
    #[error("Failed to parse STUN message: {0}")]
    ParseError(String),

    /// Attribute parsing error
    #[error("Failed to parse attribute {attr_type}: {reason}")]
    AttributeParseError { attr_type: u16, reason: String },

    /// Missing required attribute
    #[error("Missing required attribute: {0}")]
    MissingAttribute(String),

    /// Authentication failure
    #[error("MESSAGE-INTEGRITY check failed")]
    IntegrityCheckFailed,

    /// Fingerprint mismatch
    #[error("FINGERPRINT check failed")]
    FingerprintCheckFailed,

    /// STUN error response
    #[error("STUN error response: {code} - {reason}")]
    ErrorResponse { code: u16, reason: String },

    /// No response from server
    #[error("No response from STUN server {0}")]
    NoResponse(SocketAddr),

    /// All servers failed
    #[error("All STUN servers failed")]
    AllServersFailed,

    /// Invalid address family
    #[error("Invalid address family: {0}")]
    InvalidAddressFamily(u8),

    /// Nonce expired
    #[error("STUN nonce expired")]
    NonceExpired,

    /// Unknown comprehension required
    #[error("Unknown comprehension-required attributes: {0:?}")]
    UnknownComprehensionRequired(Vec<u16>),
}

/// UPnP IGD v2.0 specific errors
#[derive(Debug, Error)]
pub enum UpnpError {
    /// Discovery failure
    #[error("Failed to discover UPnP gateway after {attempts} attempts")]
    DiscoveryFailed { attempts: u32 },

    /// No gateway found
    #[error("No UPnP gateway found on network")]
    NoGatewayFound,

    /// SOAP fault with error code
    #[error("SOAP fault {code}: {description}")]
    SoapFault { code: u16, description: String },

    /// Specific UPnP error codes
    #[error("UPnP error {0}")]
    ErrorCode(UpnpErrorCode),

    /// Invalid service type
    #[error("Invalid service type: {0}")]
    InvalidServiceType(String),

    /// HTTP error
    #[error("HTTP error {code}: {reason}")]
    HttpError { code: u16, reason: String },

    /// XML parsing error
    #[error("XML parsing error: {0}")]
    XmlParseError(String),

    /// Invalid response
    #[error("Invalid UPnP response: {0}")]
    InvalidResponse(String),

    /// Port mapping conflict
    #[error("Port {port} already mapped to {existing_client}")]
    PortConflict { port: u16, existing_client: IpAddr },

    /// Lease not supported
    #[error("Device does not support lease duration {0}")]
    LeaseNotSupported(u32),

    /// Action not supported
    #[error("Action {0} not supported by device")]
    ActionNotSupported(String),

    /// Invalid argument
    #[error("Invalid argument {name}: {value}")]
    InvalidArgument { name: String, value: String },
}

/// UPnP error codes from IGD v2.0 specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum UpnpErrorCode {
    /// Invalid action
    InvalidAction = 401,

    /// Invalid args
    InvalidArgs = 402,

    /// Out of sync
    OutOfSync = 403,

    /// Invalid variable
    InvalidVariable = 404,

    /// Action failed
    ActionFailed = 501,

    /// Argument value invalid
    ArgumentValueInvalid = 600,

    /// Argument value out of range
    ArgumentValueOutOfRange = 601,

    /// Optional action not implemented
    OptionalActionNotImplemented = 602,

    /// Out of memory
    OutOfMemory = 603,

    /// Human intervention required
    HumanInterventionRequired = 604,

    /// String argument too long
    StringArgumentTooLong = 605,

    /// Action not authorized
    ActionNotAuthorized = 606,

    /// Signature failure
    SignatureFailure = 607,

    /// Signature missing
    SignatureMissing = 608,

    /// Not encrypted
    NotEncrypted = 609,

    /// Invalid sequence
    InvalidSequence = 610,

    /// Invalid control URL
    InvalidControlUrl = 611,

    /// No such session
    NoSuchSession = 612,

    /// Wild card not permitted in source IP
    WildCardNotPermittedInSrcIp = 715,

    /// Wild card not permitted in external port
    WildCardNotPermittedInExtPort = 716,

    /// Port mapping conflict
    ConflictInMappingEntry = 718,

    /// Same port values required
    SamePortValuesRequired = 724,

    /// Only permanent lease supported
    OnlyPermanentLeaseSupported = 725,

    /// Remote host only supports wildcard
    RemoteHostOnlySupportsWildcard = 726,

    /// External port only supports wildcard
    ExternalPortOnlySupportsWildcard = 727,

    /// No port maps available
    NoPortMapsAvailable = 728,

    /// Conflict with other mechanism
    ConflictWithOtherMechanism = 729,

    /// Port mapping not found
    PortMappingNotFound = 714,
}

impl fmt::Display for UpnpErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAction => write!(f, "Invalid Action"),
            Self::InvalidArgs => write!(f, "Invalid Arguments"),
            Self::OutOfSync => write!(f, "Out of Sync"),
            Self::InvalidVariable => write!(f, "Invalid Variable"),
            Self::ActionFailed => write!(f, "Action Failed"),
            Self::ArgumentValueInvalid => write!(f, "Argument Value Invalid"),
            Self::ArgumentValueOutOfRange => write!(f, "Argument Value Out of Range"),
            Self::OptionalActionNotImplemented => write!(f, "Optional Action Not Implemented"),
            Self::OutOfMemory => write!(f, "Out of Memory"),
            Self::HumanInterventionRequired => write!(f, "Human Intervention Required"),
            Self::StringArgumentTooLong => write!(f, "String Argument Too Long"),
            Self::ActionNotAuthorized => write!(f, "Action Not Authorized"),
            Self::SignatureFailure => write!(f, "Signature Failure"),
            Self::SignatureMissing => write!(f, "Signature Missing"),
            Self::NotEncrypted => write!(f, "Not Encrypted"),
            Self::InvalidSequence => write!(f, "Invalid Sequence"),
            Self::InvalidControlUrl => write!(f, "Invalid Control URL"),
            Self::NoSuchSession => write!(f, "No Such Session"),
            Self::WildCardNotPermittedInSrcIp => write!(f, "Wildcard Not Permitted in Source IP"),
            Self::WildCardNotPermittedInExtPort => write!(f, "Wildcard Not Permitted in External Port"),
            Self::ConflictInMappingEntry => write!(f, "Conflict in Mapping Entry"),
            Self::SamePortValuesRequired => write!(f, "Same Port Values Required"),
            Self::OnlyPermanentLeaseSupported => write!(f, "Only Permanent Lease Supported"),
            Self::RemoteHostOnlySupportsWildcard => write!(f, "Remote Host Only Supports Wildcard"),
            Self::ExternalPortOnlySupportsWildcard => write!(f, "External Port Only Supports Wildcard"),
            Self::NoPortMapsAvailable => write!(f, "No Port Maps Available"),
            Self::ConflictWithOtherMechanism => write!(f, "Conflict with Other Mechanism"),
            Self::PortMappingNotFound => write!(f, "Port Mapping Not Found"),
        }
    }
}

impl UpnpErrorCode {
    /// Convert from u16 error code
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            401 => Some(Self::InvalidAction),
            402 => Some(Self::InvalidArgs),
            403 => Some(Self::OutOfSync),
            404 => Some(Self::InvalidVariable),
            501 => Some(Self::ActionFailed),
            600 => Some(Self::ArgumentValueInvalid),
            601 => Some(Self::ArgumentValueOutOfRange),
            602 => Some(Self::OptionalActionNotImplemented),
            603 => Some(Self::OutOfMemory),
            604 => Some(Self::HumanInterventionRequired),
            605 => Some(Self::StringArgumentTooLong),
            606 => Some(Self::ActionNotAuthorized),
            607 => Some(Self::SignatureFailure),
            608 => Some(Self::SignatureMissing),
            609 => Some(Self::NotEncrypted),
            610 => Some(Self::InvalidSequence),
            611 => Some(Self::InvalidControlUrl),
            612 => Some(Self::NoSuchSession),
            715 => Some(Self::WildCardNotPermittedInSrcIp),
            716 => Some(Self::WildCardNotPermittedInExtPort),
            718 => Some(Self::ConflictInMappingEntry),
            724 => Some(Self::SamePortValuesRequired),
            725 => Some(Self::OnlyPermanentLeaseSupported),
            726 => Some(Self::RemoteHostOnlySupportsWildcard),
            727 => Some(Self::ExternalPortOnlySupportsWildcard),
            728 => Some(Self::NoPortMapsAvailable),
            729 => Some(Self::ConflictWithOtherMechanism),
            714 => Some(Self::PortMappingNotFound),
            _ => None,
        }
    }

    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::ConflictInMappingEntry |
            Self::NoPortMapsAvailable |
            Self::OutOfMemory |
            Self::OutOfSync
        )
    }

    /// Check if error suggests using wildcard
    pub fn requires_wildcard(&self) -> bool {
        matches!(
            self,
            Self::RemoteHostOnlySupportsWildcard |
            Self::ExternalPortOnlySupportsWildcard |
            Self::WildCardNotPermittedInSrcIp |
            Self::WildCardNotPermittedInExtPort
        )
    }
}

/// Result type for NAT operations
pub type NatResult<T> = Result<T, NatError>;

/// Convert I/O errors to NAT errors with context
pub trait IoErrorContext<T> {
    fn nat_context(self, context: &str) -> NatResult<T>;
}

impl<T> IoErrorContext<T> for io::Result<T> {
    fn nat_context(self, context: &str) -> NatResult<T> {
        self.map_err(|e| {
            if e.kind() == io::ErrorKind::TimedOut {
                NatError::Timeout(std::time::Duration::from_secs(30))
            } else {
                NatError::Platform(format!("{}: {}", context, e))
            }
        })
    }
}