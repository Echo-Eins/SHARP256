//! Protocol-wide constants for SHARP-256 wire protocol version 3.
//!
//! Sizes are chosen so that every control message fits into a single
//! 1200-byte datagram, which crosses any IPv4/IPv6 path without
//! fragmentation (the same floor QUIC uses).

use crate::crypto::transport::OVERHEAD as TRANSPORT_OVERHEAD;

/// Wire protocol version implemented by this crate. It is bound into the
/// handshake (Noise prologue and MAC labels), not sent in the clear.
pub const PROTOCOL_VERSION: u8 = 3;

/// Fixed part of a DATA frame body: offset(8) timestamp(4).
pub const DATA_FIXED_LEN: usize = 12;
/// Total per-packet overhead of a DATA datagram at the UDP payload level:
/// connection id, masked type and packet number, frame header, AEAD tag.
pub const DATA_OVERHEAD: usize = TRANSPORT_OVERHEAD + DATA_FIXED_LEN;

/// UDP payload that fits a 1500-byte Ethernet MTU over IPv4 (1500 - 20 - 8).
pub const UDP_PAYLOAD_IPV4_1500: usize = 1472;
/// UDP payload that fits a 1500-byte MTU over IPv6 (1500 - 40 - 8).
pub const UDP_PAYLOAD_IPV6_1500: usize = 1452;
/// UDP payload that is safe on every path (IPv6 minimum MTU 1280 - 40 - 8).
pub const UDP_PAYLOAD_SAFE: usize = 1232;
/// UDP payload of a 9000-byte jumbo frame over IPv4.
pub const UDP_PAYLOAD_JUMBO: usize = 8972;

/// Default DATA chunk (file bytes per packet) for a 1500-byte MTU.
pub const DEFAULT_CHUNK: u16 = (UDP_PAYLOAD_IPV4_1500 - DATA_OVERHEAD) as u16;
/// The same over IPv6, whose header is 20 bytes longer. It is also what a
/// 1492-byte PPPoE link carries over IPv4, the most common MTU below 1500.
pub const DEFAULT_CHUNK_V6: u16 = (UDP_PAYLOAD_IPV6_1500 - DATA_OVERHEAD) as u16;
/// UDP payload of IPv4 inside an IPv4-in-IPv6 tunnel over a 1500-byte link
/// (1500 - 40 - 20 - 8): DS-Lite (RFC 6333), which many cable and fibre
/// subscribers' IPv4 goes through.
pub const UDP_PAYLOAD_DSLITE: usize = 1432;
/// The chunk that fits it.
pub const DSLITE_CHUNK: u16 = (UDP_PAYLOAD_DSLITE - DATA_OVERHEAD) as u16;
/// Chunk that is safe without path-MTU probing.
pub const SAFE_CHUNK: u16 = (UDP_PAYLOAD_SAFE - DATA_OVERHEAD) as u16;
/// Chunk whose DATA datagram is no larger than a control datagram (1200
/// bytes of UDP payload, QUIC's base PMTU): what a path the handshake got
/// through is expected to carry when not even [`SAFE_CHUNK`] fits — an
/// IPv4 path below 1260 bytes (a tunnel, a VPN).
pub const BASE_CHUNK: u16 = (MAX_CONTROL_DATAGRAM - DATA_OVERHEAD) as u16;
/// Smallest chunk we ever negotiate.
pub const MIN_CHUNK: u16 = 512;
/// Largest chunk we ever negotiate (jumbo frames).
pub const MAX_CHUNK: u16 = (UDP_PAYLOAD_JUMBO - DATA_OVERHEAD) as u16;

/// Largest datagram we accept from the network.
pub const MAX_DATAGRAM: usize = 65535;

/// Upper bound for every control datagram (everything except DATA and
/// PROBE). The encoder shortens free-form text to stay within it.
pub const MAX_CONTROL_DATAGRAM: usize = 1200;

/// Byte budget for the varint-encoded hole list of one ACK or HELLO_ACK, so
/// that the message always fits into a control datagram (ACK: 33 + 40 + 2 +
/// 1024 = 1099 bytes; a handshake response carrying HELLO_ACK: 96 + 1 + 44 +
/// 2 + 1024 + 1 = 1168 bytes). A typical hole costs 3-4 bytes, so ~250-300
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

/// A connection id no endpoint ever picks.
///
/// A datagram starting with these eight bytes is a relay control message
/// (see `crate::relay`). A relay carrying traffic has to tell the two apart,
/// and it does so by these bytes, so a packet whose connection id happened
/// to equal them would be swallowed instead of forwarded. One value out of
/// 2^64 is a cheap thing to give up.
pub const RESERVED_CID: u64 = u64::from_be_bytes(*b"SHRELAY1");

/// Whether an endpoint may pick `cid` as a connection id.
///
/// Zero means "none"; [`RESERVED_CID`] marks relay control messages; and an
/// id whose second four bytes are the STUN magic cookie (0x2112A442, RFC
/// 8489) would make a packet addressed to it look like STUN on a socket
/// that also carries STUN, and be handed to the wrong reader. Giving up one
/// id in 2^32 makes that impossible instead of merely unlikely.
pub fn is_usable_cid(cid: u64) -> bool {
    const STUN_MAGIC_COOKIE: u64 = 0x2112_A442;
    cid != 0 && cid != RESERVED_CID && cid & 0xFFFF_FFFF != STUN_MAGIC_COOKIE
}

/// Length of the unpredictable token of a PATH_CHALLENGE / PATH_RESPONSE.
/// Eight bytes make guessing one hopeless (2^-64 per try) while keeping the
/// frame small enough to be sent freely.
pub const PATH_TOKEN_LEN: usize = 8;

/// HELLO_ACK status codes.
pub const HELLO_ACCEPTED: u8 = 1;
pub const HELLO_REJECTED: u8 = 2;
/// The receiver's user has not decided yet; the sender keeps asking.
pub const HELLO_PENDING: u8 = 3;

/// HELLO_ACK reject reasons.
pub const REASON_NONE: u8 = 0;
pub const REASON_DISK_SPACE: u8 = 1;
pub const REASON_BAD_FILE_NAME: u8 = 2;
pub const REASON_BUSY: u8 = 3;
pub const REASON_DECLINED: u8 = 4;
pub const REASON_CONN_CONFLICT: u8 = 5;
pub const REASON_INTERNAL: u8 = 6;
pub const REASON_TIMEOUT: u8 = 7;
/// The sender's identity is not on the receiver's list of allowed senders.
pub const REASON_UNAUTHORIZED: u8 = 8;
/// No AEAD suite in common.
pub const REASON_NO_SUITE: u8 = 9;
/// The request exceeds what this receiver supports (e.g. a directory
/// manifest beyond its limits).
pub const REASON_UNSUPPORTED: u8 = 10;

/// FIN_ACK verdicts.
pub const VERDICT_OK: u8 = 1;
pub const VERDICT_MISMATCH: u8 = 2;

/// ABORT codes (1 is reserved).
pub const ABORT_CANCELLED: u16 = 2;
pub const ABORT_IO_ERROR: u16 = 3;
pub const ABORT_TIMEOUT: u16 = 4;
pub const ABORT_PROTOCOL: u16 = 5;

/// Frame flags (4 bits, meaning depends on the frame type).
/// HELLO: the sender is willing to resume.
pub const HELLO_FLAG_RESUME: u8 = 0x1;
/// HELLO_ACK: the receiver already stores part of the file.
pub const HELLO_ACK_FLAG_RESUMED: u8 = 0x1;
/// DATA: the range was sent before (statistics only).
pub const DATA_FLAG_RETRANSMIT: u8 = 0x1;

/// What a transfer's byte stream holds (HELLO `kind`).
pub const KIND_FILE: u8 = 0;
/// A directory tree: a manifest followed by the contents of its files (see
/// `file::tree`).
pub const KIND_DIRECTORY: u8 = 1;

/// Largest directory manifest a receiver accepts. The receiver keeps the
/// manifest in memory while it arrives.
pub const MAX_MANIFEST_LEN: u64 = 64 << 20;
/// Most entries (files plus directories) one directory transfer may hold.
pub const MAX_MANIFEST_ENTRIES: u64 = 1 << 21;
/// Deepest nesting of a directory transfer (entries below the root).
pub const MAX_TREE_DEPTH: usize = 256;
/// Longest relative path, in bytes, of an entry of a directory transfer.
pub const MAX_TREE_PATH: usize = 4096;

/// Capability bits offered in HELLO and confirmed in HELLO_ACK. Unknown bits
/// are ignored by the receiver (it never confirms them), so new features can
/// be introduced without a new version.
pub const CAP_NONE: u32 = 0;
/// Capabilities this implementation supports.
pub const SUPPORTED_CAPS: u32 = CAP_NONE;

#[cfg(test)]
mod tests {
    use super::*;

    /// A packet addressed to a connection id is only ever taken for what it
    /// is: never for a relay's control message, never for STUN.
    #[test]
    fn no_connection_id_looks_like_something_else() {
        assert!(!is_usable_cid(0));
        assert!(!is_usable_cid(RESERVED_CID));
        // A Binding response prefix, then the cookie: exactly what the
        // receiver would otherwise have handed to NAT discovery.
        assert!(!is_usable_cid(0x0101_0000_2112_A442));
        assert!(!is_usable_cid(0xFFFF_FFFF_2112_A442));
        assert!(is_usable_cid(0x0101_0000_2112_A443));
        assert!(is_usable_cid(1));
    }
}
