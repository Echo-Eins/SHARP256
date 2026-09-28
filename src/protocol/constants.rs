//! Protocol-wide constants for SHARP-256 wire protocol version 2.
//!
//! Sizes are chosen so that every control message fits into a single
//! 1200-byte datagram, which crosses any IPv4/IPv6 path without
//! fragmentation (the same floor QUIC uses).

/// First two bytes of every datagram: "SH".
pub const MAGIC: [u8; 2] = *b"SH";
/// Wire protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u8 = 2;

/// Fixed header size: magic(2) version(1) type(1) flags(2) reserved(2) conn_id(4).
pub const HEADER_LEN: usize = 12;
/// Integrity tag appended to every datagram (truncated keyed BLAKE3).
pub const TAG_LEN: usize = 16;
/// Fixed part of a DATA message after the header: offset(8) timestamp(4).
pub const DATA_FIXED_LEN: usize = 12;
/// Total per-packet overhead of a DATA datagram at the UDP payload level.
pub const DATA_OVERHEAD: usize = HEADER_LEN + DATA_FIXED_LEN + TAG_LEN;

/// UDP payload that fits a 1500-byte Ethernet MTU over IPv4 (1500 - 20 - 8).
pub const UDP_PAYLOAD_IPV4_1500: usize = 1472;
/// UDP payload that fits a 1500-byte MTU over IPv6 (1500 - 40 - 8).
pub const UDP_PAYLOAD_IPV6_1500: usize = 1452;
/// UDP payload that is safe on every path (IPv6 minimum MTU 1280 - 40 - 8).
pub const UDP_PAYLOAD_SAFE: usize = 1232;

/// Default DATA chunk (file bytes per packet): 1472 - 40 bytes of overhead.
pub const DEFAULT_CHUNK: u16 = (UDP_PAYLOAD_IPV4_1500 - DATA_OVERHEAD) as u16;
/// Chunk that is safe without path-MTU probing.
pub const SAFE_CHUNK: u16 = (UDP_PAYLOAD_SAFE - DATA_OVERHEAD) as u16;
/// Smallest chunk we ever negotiate.
pub const MIN_CHUNK: u16 = 512;
/// Largest chunk we ever negotiate (jumbo frames minus headers).
pub const MAX_CHUNK: u16 = 8960;

/// Largest datagram we accept from the network.
pub const MAX_DATAGRAM: usize = 65535;

/// Upper bound for every control datagram (everything except DATA and
/// PROBE). The encoder shortens free-form text to stay within it.
pub const MAX_CONTROL_DATAGRAM: usize = 1200;

/// Byte budget for the varint-encoded hole list of one ACK or HELLO_ACK, so
/// that the message always fits into a control datagram (ACK: 12 + 40 + 2 +
/// 1024 + 16 = 1094 bytes). A typical hole costs 3-4 bytes, so ~250-300
/// holes fit.
pub const HOLES_BYTE_BUDGET: usize = 1024;
/// Upper bound on the number of holes a decoder accepts in one message.
pub const MAX_HOLES_DECODE: usize = 1024;

/// Longest file name (in bytes) accepted from the wire.
pub const MAX_FILE_NAME_LEN: usize = 255;
/// Longest free-form text (reject reason, abort reason) carried on the wire.
pub const MAX_TEXT_LEN: usize = 255;

/// Size of the hash blocks the file is conceptually divided into (the "256"
/// in SHARP-256). Used for resume bookkeeping granularity and reporting.
pub const BLOCK_SIZE: u64 = 256 * 1024;

/// Whole-file hash length (BLAKE3-256).
pub const FILE_HASH_LEN: usize = 32;

/// HELLO status codes.
pub const HELLO_ACCEPTED: u8 = 1;
pub const HELLO_REJECTED: u8 = 2;

/// HELLO_ACK reject reasons.
pub const REASON_NONE: u8 = 0;
pub const REASON_DISK_SPACE: u8 = 1;
pub const REASON_BAD_FILE_NAME: u8 = 2;
pub const REASON_BUSY: u8 = 3;
pub const REASON_DECLINED: u8 = 4;
pub const REASON_CONN_CONFLICT: u8 = 5;
pub const REASON_INTERNAL: u8 = 6;
pub const REASON_TIMEOUT: u8 = 7;

/// FIN_ACK verdicts.
pub const VERDICT_OK: u8 = 1;
pub const VERDICT_MISMATCH: u8 = 2;

/// ABORT codes (1 is reserved: a peer that does not know a connection has
/// no key to tag an answer with).
pub const ABORT_CANCELLED: u16 = 2;
pub const ABORT_IO_ERROR: u16 = 3;
pub const ABORT_TIMEOUT: u16 = 4;
pub const ABORT_PROTOCOL: u16 = 5;

/// HELLO flags.
pub const HELLO_FLAG_RESUME: u16 = 0x0001;
/// HELLO_ACK flags.
pub const HELLO_ACK_FLAG_RESUMED: u16 = 0x0001;
/// DATA flags.
pub const DATA_FLAG_RETRANSMIT: u16 = 0x0001;

/// Capability bits offered in HELLO and confirmed in HELLO_ACK. None are
/// defined in version 2; unknown bits are ignored by the receiver (it never
/// confirms them), so new features can be introduced without a new version.
pub const CAP_NONE: u32 = 0;
/// Capabilities this implementation supports.
pub const SUPPORTED_CAPS: u32 = CAP_NONE;
