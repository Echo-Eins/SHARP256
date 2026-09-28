//! Frames of SHARP-256 protocol version 3 and the handshake payloads.
//!
//! Every transport packet (see [`crate::crypto::transport`]) carries exactly
//! one frame. The frame type and four flag bits travel in the packet's
//! masked type byte; the body is encrypted. All integers are big-endian.
//!
//! DATA frames are self-describing: they carry the absolute file offset of
//! the payload, so the receiver never has to reconstruct positions from any
//! mutable state. Chunk sizes may even change mid-transfer.
//!
//! The two handshake messages carry the transfer negotiation as their
//! encrypted payload: the initiation holds a HELLO, the response a
//! HELLO_ACK (see [`Initiation`] and [`Response`]).

use crate::crypto::handshake::RESPONSE_OVERHEAD;
use crate::crypto::transport::OVERHEAD as TRANSPORT_OVERHEAD;
use crate::protocol::constants::*;

pub type Range = (u64, u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MsgType {
    Hello = 1,
    HelloAck = 2,
    Data = 3,
    Ack = 4,
    Fin = 5,
    FinAck = 6,
    Ping = 7,
    Pong = 8,
    Probe = 9,
    ProbeAck = 10,
    Abort = 11,
    FinDone = 12,
    PathChallenge = 13,
    PathResponse = 14,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => MsgType::Hello,
            2 => MsgType::HelloAck,
            3 => MsgType::Data,
            4 => MsgType::Ack,
            5 => MsgType::Fin,
            6 => MsgType::FinAck,
            7 => MsgType::Ping,
            8 => MsgType::Pong,
            9 => MsgType::Probe,
            10 => MsgType::ProbeAck,
            11 => MsgType::Abort,
            12 => MsgType::FinDone,
            13 => MsgType::PathChallenge,
            14 => MsgType::PathResponse,
            _ => return None,
        })
    }
}

/// Packs a frame type and its flags into a packet's type byte.
pub fn type_byte(t: MsgType, flags: u8) -> u8 {
    ((flags & 0x0f) << 4) | (t as u8)
}

/// Splits a type byte into frame type and flags.
pub fn parse_type_byte(b: u8) -> Result<(MsgType, u8), WireError> {
    let t = MsgType::from_u8(b & 0x0f).ok_or(WireError::UnknownType(b & 0x0f))?;
    Ok((t, b >> 4))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("frame too short")]
    TooShort,
    #[error("unknown frame type {0}")]
    UnknownType(u8),
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("text field is not valid UTF-8")]
    Utf8,
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Sender -> receiver: open a transfer (in the initiation), or ask for the
/// receiver's current state (as a frame).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub transfer_id: [u8; 16],
    /// Sender clock, microseconds, echoed in HELLO_ACK for an RTT sample.
    pub timestamp: u32,
    pub file_size: u64,
    /// Unix seconds of the source file modification time (0 if unknown).
    pub file_mtime: i64,
    /// Largest chunk (file bytes per DATA packet) the sender is willing to use.
    pub max_chunk: u16,
    pub capabilities: u32,
    /// `None` for a single file; for a directory, what describes the tree.
    /// `file_size` is then the length of the whole stream (manifest plus
    /// file contents) and `file_name` the name of the directory.
    pub tree: Option<TreeInfo>,
    pub file_name: String,
}

/// HELLO fields of a directory transfer (see `crate::file::tree`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeInfo {
    /// Length of the manifest at the start of the stream.
    pub manifest_len: u64,
    /// BLAKE3 of the manifest; the receiver checks the manifest against it
    /// before acting on any of its contents.
    pub manifest_hash: [u8; 32],
    pub files: u64,
    pub dirs: u64,
}

/// Receiver -> sender: accept, reject or "still deciding", with resume
/// information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    pub status: u8,
    pub reason: u8,
    /// Largest chunk the receiver accepts.
    pub max_chunk: u16,
    /// Capabilities in effect for this transfer: the subset of those offered
    /// in HELLO that the receiver supports. Neither peer may use a capability
    /// that is not listed here.
    pub capabilities: u32,
    pub echo_ts: u32,
    /// Longest time, in microseconds, the receiver holds back an ACK while
    /// data arrives; the sender adds it to its timeouts.
    pub max_ack_delay_us: u32,
    /// Bytes the receiver is willing to have in flight.
    pub rwnd: u64,
    /// Everything below this offset is already stored durably at the receiver.
    pub resume_upto: u64,
    /// The receiver knows nothing at or beyond this offset; the sender must
    /// send `holes` plus `[known_end, file_size)`.
    pub known_end: u64,
    pub holes: Vec<Range>,
    pub message: String,
}

/// Sender -> receiver: a slice of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Data<'a> {
    pub offset: u64,
    /// Sender clock, microseconds, echoed in ACK for RTT measurement.
    pub timestamp: u32,
    pub payload: &'a [u8],
}

/// Receiver -> sender: selective acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    /// All bytes below this offset have been received.
    pub contiguous_upto: u64,
    /// End of the interval `holes` describes completely.
    pub highest: u64,
    /// Total unique bytes received so far (progress for the sender).
    pub received_bytes: u64,
    pub echo_ts: u32,
    /// Microseconds between the arrival of the echoed DATA and this ACK.
    pub ack_delay_us: u32,
    pub rwnd: u64,
    pub holes: Vec<Range>,
}

/// Receiver -> sender: all bytes stored, here is the whole-file hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fin {
    pub file_hash: [u8; FILE_HASH_LEN],
}

/// Sender -> receiver: verdict on the receiver's hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinAck {
    pub verdict: u8,
    pub file_hash: [u8; FILE_HASH_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    pub timestamp: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pong {
    pub echo: u32,
}

/// Path-MTU probe: the encoder pads the frame so that the whole datagram is
/// exactly `size` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub size: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeAck {
    pub size: u16,
}

/// Receiver -> sender: the verdict arrived and was acted upon; the sender may
/// exit without lingering for a repeated FIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinDone {
    pub verdict: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abort {
    pub code: u16,
    pub reason: String,
}

/// Address validation, as in QUIC (RFC 9000 section 8): unpredictable data
/// that the peer must echo from the address being validated. Both ends may
/// send it, and both answer one addressed to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathChallenge {
    pub data: [u8; PATH_TOKEN_LEN],
}

/// The echo of a [`PathChallenge`]. Only the holder of the session keys can
/// produce one, and only from the address it was challenged at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathResponse {
    pub data: [u8; PATH_TOKEN_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message<'a> {
    Hello(Hello),
    HelloAck(HelloAck),
    Data(Data<'a>),
    Ack(Ack),
    Fin(Fin),
    FinAck(FinAck),
    Ping(Ping),
    Pong(Pong),
    Probe(Probe),
    ProbeAck(ProbeAck),
    Abort(Abort),
    FinDone(FinDone),
    PathChallenge(PathChallenge),
    PathResponse(PathResponse),
}

impl<'a> Message<'a> {
    pub fn msg_type(&self) -> MsgType {
        match self {
            Message::Hello(_) => MsgType::Hello,
            Message::HelloAck(_) => MsgType::HelloAck,
            Message::Data(_) => MsgType::Data,
            Message::Ack(_) => MsgType::Ack,
            Message::Fin(_) => MsgType::Fin,
            Message::FinAck(_) => MsgType::FinAck,
            Message::Ping(_) => MsgType::Ping,
            Message::Pong(_) => MsgType::Pong,
            Message::Probe(_) => MsgType::Probe,
            Message::ProbeAck(_) => MsgType::ProbeAck,
            Message::Abort(_) => MsgType::Abort,
            Message::FinDone(_) => MsgType::FinDone,
            Message::PathChallenge(_) => MsgType::PathChallenge,
            Message::PathResponse(_) => MsgType::PathResponse,
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

struct Writer<'b> {
    buf: &'b mut Vec<u8>,
    start: usize,
    /// Longest body the caller can fit; text fields are shortened to it.
    limit: usize,
}

impl Writer<'_> {
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    /// Length-prefixed text, shortened at a character boundary to at most
    /// `max` bytes and to the room left in the body.
    fn text(&mut self, s: &str, max: usize) {
        let used = self.buf.len() - self.start;
        let room = self.limit.saturating_sub(used + 1);
        let mut n = s.len().min(max).min(room).min(u8::MAX as usize);
        // Never cut a UTF-8 sequence in half.
        while n > 0 && !s.is_char_boundary(n) {
            n -= 1;
        }
        self.u8(n as u8);
        self.bytes(&s.as_bytes()[..n]);
    }
    fn varint(&mut self, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.u8(b);
                return;
            }
            self.u8(b | 0x80);
        }
    }
    /// Holes as (gap from the previous end, length) varint pairs; the first
    /// gap is measured from `base`.
    fn holes(&mut self, base: u64, holes: &[Range]) {
        let n = holes.len().min(MAX_HOLES_DECODE);
        self.u16(n as u16);
        let mut prev = base;
        for &(s, e) in &holes[..n] {
            debug_assert!(
                s >= prev && e > s,
                "holes must be sorted, disjoint and above base"
            );
            self.varint(s.saturating_sub(prev));
            self.varint(e.saturating_sub(s));
            prev = e;
        }
    }
}

/// Number of bytes `v` takes as an unsigned LEB128 varint.
pub fn varint_len(v: u64) -> usize {
    if v == 0 {
        1
    } else {
        (64 - v.leading_zeros() as usize).div_ceil(7)
    }
}

/// Encoded size of one hole that follows a hole (or base) ending at `prev_end`.
pub fn hole_encoded_len(prev_end: u64, hole: Range) -> usize {
    varint_len(hole.0.saturating_sub(prev_end)) + varint_len(hole.1.saturating_sub(hole.0))
}

/// Describes the gaps of `received` inside `[from, to)` for an ACK or
/// HELLO_ACK. Returns the holes and the end of the described interval: if
/// all gaps do not fit into [`HOLES_BYTE_BUDGET`], the interval ends at the
/// start of the first gap that does not fit. The returned list is therefore
/// always *complete* for the interval it describes, which is what lets the
/// sender treat every other byte of that interval as delivered.
pub fn describe_holes(
    received: &crate::protocol::RangeSet,
    from: u64,
    to: u64,
) -> (Vec<Range>, u64) {
    describe_holes_within(received, from, to, HOLES_BYTE_BUDGET)
}

/// [`describe_holes`] within a smaller byte budget, for a message that must
/// stay small: a handshake answer goes to an address nobody has proven yet.
pub fn describe_holes_within(
    received: &crate::protocol::RangeSet,
    from: u64,
    to: u64,
    budget: usize,
) -> (Vec<Range>, u64) {
    let budget = budget.min(HOLES_BYTE_BUDGET);
    if from >= to {
        return (Vec::new(), from.max(to));
    }
    let candidates = received.holes(from, to, MAX_HOLES_DECODE + 1);
    let mut used = 0usize;
    let mut prev = from;
    for (i, &h) in candidates.iter().enumerate() {
        let len = hole_encoded_len(prev, h);
        if i >= MAX_HOLES_DECODE || used + len > budget {
            return (candidates[..i].to_vec(), h.0);
        }
        used += len;
        prev = h.1;
    }
    (candidates, to)
}

/// Longest frame body that keeps a transport packet within
/// [`MAX_CONTROL_DATAGRAM`].
pub const MAX_CONTROL_BODY: usize = MAX_CONTROL_DATAGRAM - TRANSPORT_OVERHEAD;

/// Appends the body of `msg` to `out`. `limit` bounds the body's length:
/// text fields are shortened to fit it, and a PROBE is padded to exactly the
/// body length that makes the datagram `size` bytes long.
pub fn encode_body(msg: &Message<'_>, out: &mut Vec<u8>, limit: usize) {
    let start = out.len();
    let mut w = Writer {
        buf: out,
        start,
        limit,
    };
    match msg {
        Message::Hello(h) => {
            w.bytes(&h.transfer_id);
            w.u32(h.timestamp);
            w.u64(h.file_size);
            w.i64(h.file_mtime);
            w.u16(h.max_chunk);
            w.u32(h.capabilities);
            match &h.tree {
                None => w.u8(KIND_FILE),
                Some(t) => {
                    w.u8(KIND_DIRECTORY);
                    w.u64(t.manifest_len);
                    w.bytes(&t.manifest_hash);
                    w.u64(t.files);
                    w.u64(t.dirs);
                }
            }
            w.text(&h.file_name, MAX_FILE_NAME_LEN);
        }
        Message::HelloAck(a) => {
            w.u8(a.status);
            w.u8(a.reason);
            w.u16(a.max_chunk);
            w.u32(a.capabilities);
            w.u32(a.echo_ts);
            w.u32(a.max_ack_delay_us);
            w.u64(a.rwnd);
            w.u64(a.resume_upto);
            w.u64(a.known_end);
            w.holes(a.resume_upto, &a.holes);
            w.text(&a.message, MAX_TEXT_LEN);
        }
        Message::Data(d) => {
            w.u64(d.offset);
            w.u32(d.timestamp);
            w.bytes(d.payload);
        }
        Message::Ack(a) => {
            w.u64(a.contiguous_upto);
            w.u64(a.highest);
            w.u64(a.received_bytes);
            w.u32(a.echo_ts);
            w.u32(a.ack_delay_us);
            w.u64(a.rwnd);
            w.holes(a.contiguous_upto, &a.holes);
        }
        Message::Fin(f) => w.bytes(&f.file_hash),
        Message::FinAck(f) => {
            w.u8(f.verdict);
            w.bytes(&f.file_hash);
        }
        Message::Ping(p) => w.u32(p.timestamp),
        Message::Pong(p) => w.u32(p.echo),
        Message::Probe(p) => {
            w.u16(p.size);
            let body = (p.size as usize).saturating_sub(TRANSPORT_OVERHEAD).max(2);
            w.buf.resize(w.start + body, 0);
        }
        Message::ProbeAck(p) => w.u16(p.size),
        Message::Abort(a) => {
            w.u16(a.code);
            w.text(&a.reason, MAX_TEXT_LEN);
        }
        Message::FinDone(f) => w.u8(f.verdict),
        Message::PathChallenge(p) => w.bytes(&p.data),
        Message::PathResponse(p) => w.bytes(&p.data),
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError::TooShort);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, WireError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
    fn text(&mut self, max: usize) -> Result<String, WireError> {
        let n = self.u8()? as usize;
        if n > max {
            return Err(WireError::Malformed("text"));
        }
        let bytes = self.take(n)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| WireError::Utf8)
    }
    fn varint(&mut self, what: &'static str) -> Result<u64, WireError> {
        let mut v: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            if shift == 63 && b > 1 {
                return Err(WireError::Malformed(what));
            }
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
            if shift > 63 {
                return Err(WireError::Malformed(what));
            }
        }
    }
    /// Reads holes encoded by `Writer::holes`; they must lie in `[base, limit]`,
    /// be non-empty and be separated by at least one byte.
    fn holes(
        &mut self,
        base: u64,
        limit: u64,
        what: &'static str,
    ) -> Result<Vec<Range>, WireError> {
        let n = self.u16()? as usize;
        if n > MAX_HOLES_DECODE {
            return Err(WireError::Malformed(what));
        }
        let mut out = Vec::with_capacity(n.min(self.remaining() / 2));
        let mut prev = base;
        for i in 0..n {
            let gap = self.varint(what)?;
            let len = self.varint(what)?;
            if len == 0 || (i > 0 && gap == 0) {
                return Err(WireError::Malformed(what));
            }
            let s = prev.checked_add(gap).ok_or(WireError::Malformed(what))?;
            let e = s.checked_add(len).ok_or(WireError::Malformed(what))?;
            if e > limit {
                return Err(WireError::Malformed(what));
            }
            out.push((s, e));
            prev = e;
        }
        Ok(out)
    }
}

/// Decodes a frame body. Trailing bytes after the known fields of a control
/// frame are ignored (they are where later versions append fields).
pub fn decode_body(msg_type: MsgType, body: &[u8]) -> Result<Message<'_>, WireError> {
    let mut r = Reader::new(body);
    let msg = match msg_type {
        MsgType::Hello => {
            let transfer_id = r.array::<16>()?;
            let timestamp = r.u32()?;
            let file_size = r.u64()?;
            let file_mtime = r.i64()?;
            let max_chunk = r.u16()?;
            let capabilities = r.u32()?;
            let tree = match r.u8()? {
                KIND_FILE => None,
                KIND_DIRECTORY => {
                    let t = TreeInfo {
                        manifest_len: r.u64()?,
                        manifest_hash: r.array::<32>()?,
                        files: r.u64()?,
                        dirs: r.u64()?,
                    };
                    let entries = t.files.checked_add(t.dirs);
                    if t.manifest_len == 0
                        || t.manifest_len > file_size
                        || entries.is_none_or(|n| n > MAX_MANIFEST_ENTRIES)
                    {
                        return Err(WireError::Malformed("hello"));
                    }
                    Some(t)
                }
                _ => return Err(WireError::Malformed("hello")),
            };
            let file_name = r.text(MAX_FILE_NAME_LEN)?;
            if file_name.is_empty() {
                return Err(WireError::Malformed("hello"));
            }
            Message::Hello(Hello {
                transfer_id,
                timestamp,
                file_size,
                file_mtime,
                max_chunk,
                capabilities,
                tree,
                file_name,
            })
        }
        MsgType::HelloAck => {
            let status = r.u8()?;
            let reason = r.u8()?;
            let max_chunk = r.u16()?;
            let capabilities = r.u32()?;
            let echo_ts = r.u32()?;
            let max_ack_delay_us = r.u32()?;
            let rwnd = r.u64()?;
            let resume_upto = r.u64()?;
            let known_end = r.u64()?;
            if known_end < resume_upto {
                return Err(WireError::Malformed("hello_ack"));
            }
            let holes = r.holes(resume_upto, known_end, "hello_ack")?;
            let message = r.text(MAX_TEXT_LEN)?;
            if !matches!(status, HELLO_ACCEPTED | HELLO_REJECTED | HELLO_PENDING) {
                return Err(WireError::Malformed("hello_ack"));
            }
            Message::HelloAck(HelloAck {
                status,
                reason,
                max_chunk,
                capabilities,
                echo_ts,
                max_ack_delay_us,
                rwnd,
                resume_upto,
                known_end,
                holes,
                message,
            })
        }
        MsgType::Data => {
            let offset = r.u64()?;
            let timestamp = r.u32()?;
            let payload = r.take(r.remaining())?;
            Message::Data(Data {
                offset,
                timestamp,
                payload,
            })
        }
        MsgType::Ack => {
            let contiguous_upto = r.u64()?;
            let highest = r.u64()?;
            let received_bytes = r.u64()?;
            let echo_ts = r.u32()?;
            let ack_delay_us = r.u32()?;
            let rwnd = r.u64()?;
            if highest < contiguous_upto {
                return Err(WireError::Malformed("ack"));
            }
            let holes = r.holes(contiguous_upto, highest, "ack")?;
            Message::Ack(Ack {
                contiguous_upto,
                highest,
                received_bytes,
                echo_ts,
                ack_delay_us,
                rwnd,
                holes,
            })
        }
        MsgType::Fin => Message::Fin(Fin {
            file_hash: r.array::<FILE_HASH_LEN>()?,
        }),
        MsgType::FinAck => {
            let verdict = r.u8()?;
            let file_hash = r.array::<FILE_HASH_LEN>()?;
            Message::FinAck(FinAck { verdict, file_hash })
        }
        MsgType::Ping => Message::Ping(Ping {
            timestamp: r.u32()?,
        }),
        MsgType::Pong => Message::Pong(Pong { echo: r.u32()? }),
        MsgType::Probe => Message::Probe(Probe { size: r.u16()? }),
        MsgType::ProbeAck => Message::ProbeAck(ProbeAck { size: r.u16()? }),
        MsgType::Abort => {
            let code = r.u16()?;
            let reason = r.text(MAX_TEXT_LEN)?;
            Message::Abort(Abort { code, reason })
        }
        MsgType::FinDone => Message::FinDone(FinDone { verdict: r.u8()? }),
        MsgType::PathChallenge => Message::PathChallenge(PathChallenge {
            data: r.array::<PATH_TOKEN_LEN>()?,
        }),
        MsgType::PathResponse => Message::PathResponse(PathResponse {
            data: r.array::<PATH_TOKEN_LEN>()?,
        }),
    };
    Ok(msg)
}

// ---------------------------------------------------------------------------
// Handshake payloads
// ---------------------------------------------------------------------------

/// Payload of a handshake initiation (encrypted by Noise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Initiation {
    /// Strictly increasing per sender; see `crypto::handshake`.
    pub timestamp: u64,
    /// Bit set of [`crate::crypto::Suite`] values the sender supports.
    pub suites: u8,
    /// The sender has AES instructions.
    pub hardware_aes: bool,
    /// HELLO frame flags.
    pub hello_flags: u8,
    pub hello: Hello,
}

/// Payload of a handshake response (encrypted by Noise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Chosen [`crate::crypto::Suite`] (0 when the transfer is rejected).
    pub suite: u8,
    /// HELLO_ACK frame flags.
    pub ack_flags: u8,
    pub ack: HelloAck,
}

pub fn encode_initiation(p: &Initiation) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + p.hello.file_name.len());
    out.extend_from_slice(&p.timestamp.to_be_bytes());
    out.push(p.suites);
    out.push(p.hardware_aes as u8);
    out.push(p.hello_flags);
    encode_body(&Message::Hello(p.hello.clone()), &mut out, usize::MAX);
    out
}

pub fn decode_initiation(buf: &[u8]) -> Result<Initiation, WireError> {
    let mut r = Reader::new(buf);
    let timestamp = r.u64()?;
    let suites = r.u8()?;
    let hardware_aes = r.u8()? & 1 == 1;
    let hello_flags = r.u8()? & 0x0f;
    let hello = match decode_body(MsgType::Hello, &buf[r.pos..])? {
        Message::Hello(h) => h,
        _ => unreachable!("decode_body returns the requested type"),
    };
    Ok(Initiation {
        timestamp,
        suites,
        hardware_aes,
        hello_flags,
        hello,
    })
}

/// Longest response payload that keeps the response datagram within
/// [`MAX_CONTROL_DATAGRAM`].
pub const MAX_RESPONSE_PAYLOAD: usize = MAX_CONTROL_DATAGRAM - RESPONSE_OVERHEAD;

pub fn encode_response(p: &Response) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.push(p.suite);
    out.push(p.ack_flags);
    encode_body(
        &Message::HelloAck(p.ack.clone()),
        &mut out,
        MAX_RESPONSE_PAYLOAD - 2,
    );
    out
}

pub fn decode_response(buf: &[u8]) -> Result<Response, WireError> {
    let mut r = Reader::new(buf);
    let suite = r.u8()?;
    let ack_flags = r.u8()? & 0x0f;
    let ack = match decode_body(MsgType::HelloAck, &buf[r.pos..])? {
        Message::HelloAck(a) => a,
        _ => unreachable!("decode_body returns the requested type"),
    };
    Ok(Response {
        suite,
        ack_flags,
        ack,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RangeSet;

    fn body(msg: &Message<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        encode_body(msg, &mut out, MAX_CONTROL_BODY);
        out
    }

    fn roundtrip(msg: Message<'_>) -> Vec<u8> {
        let b = body(&msg);
        let back = decode_body(msg.msg_type(), &b).expect("decode");
        assert_eq!(back, msg);
        b
    }

    fn hello() -> Hello {
        Hello {
            transfer_id: [1; 16],
            timestamp: 42,
            file_size: 1 << 40,
            file_mtime: -5,
            max_chunk: 1427,
            capabilities: 0,
            tree: None,
            file_name: "отчёт-2026.bin".to_string(),
        }
    }

    fn tree_hello() -> Hello {
        Hello {
            file_size: 5 << 30,
            tree: Some(TreeInfo {
                manifest_len: 12_345,
                manifest_hash: [7; 32],
                files: 1000,
                dirs: 20,
            }),
            file_name: "photos".into(),
            ..hello()
        }
    }

    fn hello_ack(holes: Vec<Range>, known_end: u64, message: &str) -> HelloAck {
        HelloAck {
            status: HELLO_ACCEPTED,
            reason: REASON_NONE,
            max_chunk: 1200,
            capabilities: 0x8000_0001,
            echo_ts: 42,
            max_ack_delay_us: 20_000,
            rwnd: 1 << 26,
            resume_upto: 1000,
            known_end,
            holes,
            message: message.into(),
        }
    }

    #[test]
    fn type_byte_packs_type_and_flags() {
        for t in 1..=14u8 {
            let mt = MsgType::from_u8(t).unwrap();
            for flags in 0..16u8 {
                assert_eq!(parse_type_byte(type_byte(mt, flags)).unwrap(), (mt, flags));
            }
        }
        assert_eq!(parse_type_byte(0), Err(WireError::UnknownType(0)));
        assert_eq!(parse_type_byte(0x0f), Err(WireError::UnknownType(15)));
    }

    #[test]
    fn roundtrip_all_frames() {
        roundtrip(Message::Hello(hello()));
        roundtrip(Message::Hello(tree_hello()));
        roundtrip(Message::HelloAck(hello_ack(
            vec![(1000, 1500), (2000, 2100)],
            5000,
            "",
        )));
        let payload = vec![0xAB; 1427];
        let b = roundtrip(Message::Data(Data {
            offset: 123_456_789,
            timestamp: 999,
            payload: &payload,
        }));
        assert_eq!(b.len() + TRANSPORT_OVERHEAD, DATA_OVERHEAD + 1427);
        roundtrip(Message::Ack(Ack {
            contiguous_upto: 10,
            highest: 100,
            received_bytes: 70,
            echo_ts: 5,
            ack_delay_us: 120,
            rwnd: 4096,
            holes: vec![(10, 20), (30, 50)],
        }));
        roundtrip(Message::Fin(Fin { file_hash: [9; 32] }));
        roundtrip(Message::FinAck(FinAck {
            verdict: VERDICT_OK,
            file_hash: [3; 32],
        }));
        roundtrip(Message::Ping(Ping { timestamp: 1 }));
        roundtrip(Message::Pong(Pong { echo: 2 }));
        roundtrip(Message::ProbeAck(ProbeAck { size: 1472 }));
        roundtrip(Message::Abort(Abort {
            code: ABORT_CANCELLED,
            reason: "user cancelled".into(),
        }));
        roundtrip(Message::FinDone(FinDone {
            verdict: VERDICT_OK,
        }));
        roundtrip(Message::PathChallenge(PathChallenge {
            data: [0x5A; PATH_TOKEN_LEN],
        }));
        roundtrip(Message::PathResponse(PathResponse {
            data: [0xA5; PATH_TOKEN_LEN],
        }));
    }

    #[test]
    fn probe_fills_the_datagram_to_its_size() {
        for size in [64u16, 1232, 1472, 8972] {
            let msg = Message::Probe(Probe { size });
            let mut b = Vec::new();
            encode_body(&msg, &mut b, usize::MAX);
            assert_eq!(b.len() + TRANSPORT_OVERHEAD, size as usize);
            assert_eq!(decode_body(MsgType::Probe, &b).unwrap(), msg);
        }
    }

    #[test]
    fn malformed_bodies_are_rejected_not_panicking() {
        for t in 1u8..=14 {
            let msg_type = MsgType::from_u8(t).unwrap();
            for len in 0..80usize {
                let body: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
                let _ = decode_body(msg_type, &body);
            }
        }
        // Hole list with a bogus count.
        let mut b = vec![0u8; 8 + 8 + 8 + 4 + 4 + 8];
        b.extend_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            decode_body(MsgType::Ack, &b),
            Err(WireError::Malformed("ack"))
        ));
        // Holes beyond the described interval, and adjacent holes.
        for holes in [vec![(10, 20), (150, 160)], vec![(10, 20), (20, 30)]] {
            let ack = Ack {
                contiguous_upto: 0,
                highest: 100,
                received_bytes: 0,
                echo_ts: 0,
                ack_delay_us: 0,
                rwnd: 0,
                holes,
            };
            let b = body(&Message::Ack(ack));
            assert!(matches!(
                decode_body(MsgType::Ack, &b),
                Err(WireError::Malformed("ack"))
            ));
        }
        // Over-long varint.
        let mut b = vec![0u8; 8 + 8 + 8 + 4 + 4 + 8];
        b[8..16].copy_from_slice(&100u64.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0xff; 11]);
        assert!(matches!(
            decode_body(MsgType::Ack, &b),
            Err(WireError::Malformed("ack"))
        ));
        // Directory HELLOs whose manifest cannot fit the stream, is empty or
        // lists too many entries, and unknown kinds.
        let kind_at = 16 + 4 + 8 + 8 + 2 + 4;
        for t in [
            TreeInfo {
                manifest_len: 0,
                ..tree_hello().tree.unwrap()
            },
            TreeInfo {
                manifest_len: (5 << 30) + 1,
                ..tree_hello().tree.unwrap()
            },
            TreeInfo {
                files: MAX_MANIFEST_ENTRIES,
                dirs: 1,
                ..tree_hello().tree.unwrap()
            },
            TreeInfo {
                files: u64::MAX,
                dirs: u64::MAX,
                ..tree_hello().tree.unwrap()
            },
        ] {
            let h = Hello {
                tree: Some(t),
                ..tree_hello()
            };
            assert!(decode_body(MsgType::Hello, &body(&Message::Hello(h))).is_err());
        }
        let mut b = body(&Message::Hello(hello()));
        b[kind_at] = 2;
        assert!(decode_body(MsgType::Hello, &b).is_err());
        // Unknown HELLO_ACK status.
        let mut b = body(&Message::HelloAck(hello_ack(vec![], 1000, "")));
        b[0] = 9;
        assert!(decode_body(MsgType::HelloAck, &b).is_err());
    }

    #[test]
    fn varints_and_far_holes_roundtrip() {
        for v in [
            0u64,
            1,
            127,
            128,
            16_383,
            16_384,
            u32::MAX as u64,
            u64::MAX / 2,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            Writer {
                buf: &mut buf,
                start: 0,
                limit: usize::MAX,
            }
            .varint(v);
            assert_eq!(buf.len(), varint_len(v), "len of {}", v);
            let mut r = Reader::new(&buf);
            assert_eq!(r.varint("t").unwrap(), v);
        }
        let base = 5u64 << 40;
        roundtrip(Message::Ack(Ack {
            contiguous_upto: base,
            highest: base + (3u64 << 33),
            received_bytes: base,
            echo_ts: 1,
            ack_delay_us: 2,
            rwnd: 3,
            holes: vec![
                (base, base + 1432),
                (base + 10_000, base + 20_000),
                (base + (1u64 << 33), base + (2u64 << 33)),
            ],
        }));
    }

    fn fragmented(n: u64) -> RangeSet {
        let mut rs = RangeSet::new();
        for i in 0..n {
            rs.insert(i * 2864, i * 2864 + 1432); // every other chunk missing
        }
        rs
    }

    #[test]
    fn describe_holes_is_complete_and_bounded() {
        let rs = RangeSet::from_ranges([(0, 100), (200, 300), (400, 500)]);
        let (holes, end) = describe_holes(&rs, 100, 500);
        assert_eq!(holes, vec![(100, 200), (300, 400)]);
        assert_eq!(end, 500);
        let rs = fragmented(3000);
        let top = rs.last_end().unwrap();
        let (holes, end) = describe_holes(&rs, 1432, top);
        assert!(holes.len() > 200, "only {} holes fit", holes.len());
        assert!(end < top);
        assert_eq!(end, holes.last().unwrap().1 + 1432, "cut at the next hole");
        let mut size = 0;
        let mut prev = 1432;
        for &h in &holes {
            size += hole_encoded_len(prev, h);
            prev = h.1;
        }
        assert!(size <= HOLES_BYTE_BUDGET);
        let mut described = RangeSet::from_ranges([(1432, end)]);
        for &(s, e) in &holes {
            described.remove(s, e);
        }
        for (s, e) in described.iter() {
            assert!(rs.contains(s, e), "undescribed gap {}..{}", s, e);
        }
        let ack = Ack {
            contiguous_upto: 1432,
            highest: end,
            received_bytes: rs.total(),
            echo_ts: 0,
            ack_delay_us: 0,
            rwnd: 0,
            holes,
        };
        let b = roundtrip(Message::Ack(ack));
        assert!(
            b.len() + TRANSPORT_OVERHEAD <= MAX_CONTROL_DATAGRAM,
            "{} bytes",
            b.len()
        );
    }

    #[test]
    fn handshake_payloads_roundtrip_and_fit() {
        let init = Initiation {
            timestamp: 1_700_000_000_123_456_789,
            suites: 3,
            hardware_aes: true,
            hello_flags: HELLO_FLAG_RESUME,
            hello: hello(),
        };
        assert_eq!(decode_initiation(&encode_initiation(&init)).unwrap(), init);
        // The largest initiation (a directory with the longest name) stays
        // well within a control datagram.
        let big = Initiation {
            hello: Hello {
                file_name: "x".repeat(MAX_FILE_NAME_LEN),
                ..tree_hello()
            },
            ..init
        };
        let enc = encode_initiation(&big);
        assert_eq!(decode_initiation(&enc).unwrap(), big);
        assert!(
            enc.len() + crate::crypto::handshake::INITIATION_OVERHEAD <= MAX_CONTROL_DATAGRAM,
            "{} bytes",
            enc.len()
        );

        // A response with the fullest possible hole list and a long message
        // still fits the control datagram bound; holes are never cut.
        let rs = fragmented(5000);
        let (holes, end) = describe_holes(&rs, 1000, rs.last_end().unwrap());
        let resp = Response {
            suite: 1,
            ack_flags: HELLO_ACK_FLAG_RESUMED,
            ack: hello_ack(holes.clone(), end, &"ж".repeat(200)),
        };
        let enc = encode_response(&resp);
        assert!(enc.len() <= MAX_RESPONSE_PAYLOAD, "{} bytes", enc.len());
        let back = decode_response(&enc).unwrap();
        assert_eq!(back.ack.holes, holes);
        assert!(back.ack.message.chars().all(|c| c == 'ж'));
        assert!(back.ack.message.len() < 400);
        // Without holes, a reject message survives in full.
        let reject = Response {
            suite: 0,
            ack_flags: 0,
            ack: HelloAck {
                status: HELLO_REJECTED,
                reason: REASON_UNAUTHORIZED,
                ..hello_ack(vec![], 1000, "not on the list of allowed senders")
            },
        };
        assert_eq!(decode_response(&encode_response(&reject)).unwrap(), reject);
    }

    #[test]
    fn trailing_bytes_in_control_bodies_are_ignored() {
        let msgs = [
            Message::Hello(hello()),
            Message::Hello(tree_hello()),
            Message::HelloAck(hello_ack(vec![(1000, 1200)], 2000, "ok")),
            Message::Ack(Ack {
                contiguous_upto: 1,
                highest: 9,
                received_bytes: 5,
                echo_ts: 2,
                ack_delay_us: 3,
                rwnd: 4,
                holes: vec![(2, 4)],
            }),
            Message::Fin(Fin { file_hash: [7; 32] }),
            Message::FinAck(FinAck {
                verdict: VERDICT_OK,
                file_hash: [8; 32],
            }),
            Message::Ping(Ping { timestamp: 9 }),
            Message::Pong(Pong { echo: 10 }),
            Message::ProbeAck(ProbeAck { size: 1200 }),
            Message::Abort(Abort {
                code: ABORT_TIMEOUT,
                reason: "gone".into(),
            }),
            Message::FinDone(FinDone {
                verdict: VERDICT_MISMATCH,
            }),
        ];
        for msg in msgs {
            let mut b = body(&msg);
            b.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
            assert_eq!(decode_body(msg.msg_type(), &b).unwrap(), msg);
        }
    }

    #[test]
    fn file_name_is_cut_at_char_boundary() {
        let h = Hello {
            file_name: "ж".repeat(200), // 400 bytes
            ..hello()
        };
        let b = body(&Message::Hello(h));
        let Message::Hello(back) = decode_body(MsgType::Hello, &b).unwrap() else {
            panic!("expected hello");
        };
        assert!(back.file_name.len() <= MAX_FILE_NAME_LEN);
        assert!(back.file_name.chars().all(|c| c == 'ж'));
    }
}
