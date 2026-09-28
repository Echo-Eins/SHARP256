//! Wire encoding of SHARP-256 protocol version 2.
//!
//! Every datagram is `header (12) | body | tag (16)`:
//!
//! ```text
//!  0      2      3      4        6        8          12
//!  +------+------+------+--------+--------+----------+
//!  | 'SH' | ver  | type | flags  | rsvd   | conn_id  |  body ...  | tag[16] |
//!  +------+------+------+--------+--------+----------+
//! ```
//!
//! All integers are big-endian. The tag is a keyed BLAKE3 hash (truncated to
//! 128 bits) over header and body, keyed by a key derived from the 128-bit
//! transfer id negotiated in HELLO. It lets both peers reject corrupted
//! datagrams and datagrams that do not belong to the session before acting
//! on them. It is not a confidentiality mechanism.
//!
//! DATA packets are self-describing: they carry the absolute file offset of
//! the payload, so the receiver never has to reconstruct positions from any
//! mutable state (batch sizes, packet counts, chunk sizes). Chunk sizes may
//! even change mid-transfer without affecting correctness.

use crate::protocol::constants::*;
use std::fmt;

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
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub msg_type: MsgType,
    pub flags: u16,
    pub conn_id: u32,
}

impl Header {
    pub fn new(msg_type: MsgType, conn_id: u32) -> Self {
        Self {
            msg_type,
            flags: 0,
            conn_id,
        }
    }
    pub fn with_flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("datagram too short")]
    TooShort,
    #[error("bad magic number")]
    BadMagic,
    #[error("unsupported protocol version {0}")]
    Version(u8),
    #[error("unknown message type {0}")]
    UnknownType(u8),
    #[error("malformed {0} message")]
    Malformed(&'static str),
    #[error("integrity tag mismatch")]
    BadTag,
    #[error("text field is not valid UTF-8")]
    Utf8,
}

/// Key used for per-datagram integrity tags, derived from the transfer id.
#[derive(Clone, Copy)]
pub struct TagKey([u8; 32]);

const TAG_CONTEXT: &str = "sharp256 v2 2026-09 datagram integrity tag";

impl TagKey {
    pub fn derive(transfer_id: &[u8; 16]) -> Self {
        Self(blake3::derive_key(TAG_CONTEXT, transfer_id))
    }

    fn tag(&self, data: &[u8]) -> [u8; TAG_LEN] {
        let hash = blake3::keyed_hash(&self.0, data);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&hash.as_bytes()[..TAG_LEN]);
        tag
    }
}

impl fmt::Debug for TagKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TagKey(..)")
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Sender -> receiver: open a transfer.
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
    pub file_name: String,
}

/// Receiver -> sender: accept or reject, with resume information.
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
    /// End of the highest received range; `holes` are gaps below it.
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

/// Path-MTU probe: the encoder pads the datagram to exactly `size` bytes.
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
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

struct Writer<'b> {
    buf: &'b mut Vec<u8>,
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
    /// Length-prefixed text, shortened (at a character boundary) so that the
    /// datagram including its tag stays within [`MAX_CONTROL_DATAGRAM`].
    fn text(&mut self, s: &str) {
        let b = s.as_bytes();
        let room = (MAX_CONTROL_DATAGRAM - TAG_LEN).saturating_sub(self.buf.len() + 1);
        let mut n = b.len().min(MAX_TEXT_LEN).min(room);
        // Never cut a UTF-8 sequence in half.
        while n > 0 && !s.is_char_boundary(n) {
            n -= 1;
        }
        self.u8(n as u8);
        self.bytes(&b[..n]);
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
    if from >= to {
        return (Vec::new(), from.max(to));
    }
    let candidates = received.holes(from, to, MAX_HOLES_DECODE + 1);
    let mut used = 0usize;
    let mut prev = from;
    for (i, &h) in candidates.iter().enumerate() {
        let len = hole_encoded_len(prev, h);
        if i >= MAX_HOLES_DECODE || used + len > HOLES_BYTE_BUDGET {
            return (candidates[..i].to_vec(), h.0);
        }
        used += len;
        prev = h.1;
    }
    (candidates, to)
}

/// Encodes a complete datagram: header, body and integrity tag.
pub fn encode(header: &Header, msg: &Message<'_>, key: &TagKey) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(header, msg, key, &mut out);
    out
}

/// Like [`encode`], but writes into `out` (which is cleared first) so that
/// hot paths can reuse one buffer instead of allocating per datagram.
pub fn encode_into(header: &Header, msg: &Message<'_>, key: &TagKey, out: &mut Vec<u8>) {
    let body_hint = match msg {
        Message::Data(d) => DATA_FIXED_LEN + d.payload.len(),
        Message::Probe(p) => (p.size as usize).saturating_sub(HEADER_LEN + TAG_LEN),
        _ => 128,
    };
    out.clear();
    out.reserve(HEADER_LEN + body_hint + TAG_LEN);
    let mut w = Writer { buf: out };
    w.bytes(&MAGIC);
    w.u8(PROTOCOL_VERSION);
    w.u8(msg.msg_type() as u8);
    w.u16(header.flags);
    w.u16(0);
    w.u32(header.conn_id);

    match msg {
        Message::Hello(h) => {
            w.bytes(&h.transfer_id);
            w.u32(h.timestamp);
            w.u64(h.file_size);
            w.i64(h.file_mtime);
            w.u16(h.max_chunk);
            w.u32(h.capabilities);
            let name = h.file_name.as_bytes();
            let n = name.len().min(MAX_FILE_NAME_LEN);
            let mut n = n;
            while n > 0 && !h.file_name.is_char_boundary(n) {
                n -= 1;
            }
            w.u8(n as u8);
            w.bytes(&name[..n]);
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
            w.text(&a.message);
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
            let target = (p.size as usize).max(HEADER_LEN + 2 + TAG_LEN);
            let pad = target - HEADER_LEN - 2 - TAG_LEN;
            w.buf.resize(w.buf.len() + pad, 0);
        }
        Message::ProbeAck(p) => w.u16(p.size),
        Message::Abort(a) => {
            w.u16(a.code);
            w.text(&a.reason);
        }
        Message::FinDone(f) => w.u8(f.verdict),
    }

    let tag = key.tag(w.buf.as_slice());
    w.bytes(&tag);
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

/// Parses and validates the fixed header. Does not check the tag.
pub fn parse_header(buf: &[u8]) -> Result<Header, WireError> {
    if buf.len() < HEADER_LEN + TAG_LEN {
        return Err(WireError::TooShort);
    }
    if buf[0..2] != MAGIC {
        return Err(WireError::BadMagic);
    }
    if buf[2] != PROTOCOL_VERSION {
        return Err(WireError::Version(buf[2]));
    }
    let msg_type = MsgType::from_u8(buf[3]).ok_or(WireError::UnknownType(buf[3]))?;
    let flags = u16::from_be_bytes([buf[4], buf[5]]);
    let conn_id = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    Ok(Header {
        msg_type,
        flags,
        conn_id,
    })
}

/// Verifies the trailing integrity tag in constant time.
pub fn verify_tag(buf: &[u8], key: &TagKey) -> bool {
    if buf.len() < HEADER_LEN + TAG_LEN {
        return false;
    }
    let (data, tag) = buf.split_at(buf.len() - TAG_LEN);
    let expected = key.tag(data);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Returns the transfer id of an (unverified) HELLO datagram so the receiver
/// can derive the key needed to verify it.
pub fn peek_hello_transfer_id(buf: &[u8]) -> Option<[u8; 16]> {
    if buf.len() < HEADER_LEN + 16 + TAG_LEN || buf[3] != MsgType::Hello as u8 {
        return None;
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&buf[HEADER_LEN..HEADER_LEN + 16]);
    Some(id)
}

/// Decodes the body of a datagram whose header was already parsed and whose
/// tag was already verified. `body` excludes header and tag.
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
            if status != HELLO_ACCEPTED && status != HELLO_REJECTED {
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
    };
    Ok(msg)
}

/// Full decode: header, tag verification, body.
pub fn decode<'a>(buf: &'a [u8], key: &TagKey) -> Result<(Header, Message<'a>), WireError> {
    let header = parse_header(buf)?;
    if !verify_tag(buf, key) {
        return Err(WireError::BadTag);
    }
    let body = &buf[HEADER_LEN..buf.len() - TAG_LEN];
    let msg = decode_body(header.msg_type, body)?;
    Ok((header, msg))
}

/// Returns the body slice of a datagram (header and tag stripped).
pub fn body_of(buf: &[u8]) -> &[u8] {
    &buf[HEADER_LEN..buf.len() - TAG_LEN]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> TagKey {
        TagKey::derive(&[7u8; 16])
    }

    fn roundtrip(msg: Message<'_>) -> Vec<u8> {
        let hdr = Header::new(msg.msg_type(), 0xDEADBEEF).with_flags(0x0102);
        let bytes = encode(&hdr, &msg, &key());
        let (h2, m2) = decode(&bytes, &key()).expect("decode");
        assert_eq!(h2, hdr);
        assert_eq!(m2, msg);
        bytes
    }

    #[test]
    fn roundtrip_all_messages() {
        roundtrip(Message::Hello(Hello {
            transfer_id: [1; 16],
            timestamp: 42,
            file_size: 1 << 40,
            file_mtime: -5,
            max_chunk: 1432,
            capabilities: 0,
            file_name: "отчёт-2026.bin".to_string(),
        }));
        roundtrip(Message::HelloAck(HelloAck {
            status: HELLO_ACCEPTED,
            reason: REASON_NONE,
            max_chunk: 1200,
            capabilities: 0x8000_0001,
            echo_ts: 42,
            max_ack_delay_us: 20_000,
            rwnd: 1 << 26,
            resume_upto: 1000,
            known_end: 5000,
            holes: vec![(1000, 1500), (2000, 2100)],
            message: String::new(),
        }));
        let payload = vec![0xAB; 1432];
        let bytes = roundtrip(Message::Data(Data {
            offset: 123_456_789,
            timestamp: 999,
            payload: &payload,
        }));
        assert_eq!(bytes.len(), DATA_OVERHEAD + 1432);
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
    }

    #[test]
    fn probe_is_padded_to_requested_size() {
        for size in [64u16, 1200, 1472, 8000] {
            let bytes = roundtrip(Message::Probe(Probe { size }));
            assert_eq!(bytes.len(), size as usize);
        }
    }

    #[test]
    fn empty_data_payload_is_valid() {
        roundtrip(Message::Data(Data {
            offset: 0,
            timestamp: 0,
            payload: &[],
        }));
    }

    #[test]
    fn rejects_corruption_and_wrong_key() {
        let payload = vec![1u8; 100];
        let hdr = Header::new(MsgType::Data, 1);
        let bytes = encode(
            &hdr,
            &Message::Data(Data {
                offset: 5,
                timestamp: 6,
                payload: &payload,
            }),
            &key(),
        );
        // wrong key
        let other = TagKey::derive(&[8u8; 16]);
        assert_eq!(decode(&bytes, &other).unwrap_err(), WireError::BadTag);
        // flipped payload byte
        let mut bad = bytes.clone();
        bad[HEADER_LEN + DATA_FIXED_LEN + 10] ^= 1;
        assert_eq!(decode(&bad, &key()).unwrap_err(), WireError::BadTag);
        // flipped header byte (conn id)
        let mut bad = bytes.clone();
        bad[9] ^= 1;
        assert_eq!(decode(&bad, &key()).unwrap_err(), WireError::BadTag);
        // truncated
        assert_eq!(
            decode(&bytes[..20], &key()).unwrap_err(),
            WireError::TooShort
        );
        // bad magic / version / type are rejected before the tag is checked
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert_eq!(parse_header(&bad).unwrap_err(), WireError::BadMagic);
        let mut bad = bytes.clone();
        bad[2] = 1;
        assert_eq!(parse_header(&bad).unwrap_err(), WireError::Version(1));
        let mut bad = bytes.clone();
        bad[3] = 200;
        assert_eq!(parse_header(&bad).unwrap_err(), WireError::UnknownType(200));
    }

    #[test]
    fn malformed_bodies_are_rejected_not_panicking() {
        // Random-ish garbage of every length for every type must never panic.
        for t in 1u8..=12 {
            let msg_type = MsgType::from_u8(t).unwrap();
            for len in 0..80usize {
                let body: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
                let _ = decode_body(msg_type, &body);
            }
        }
        // Hole list with a bogus count.
        let mut body = vec![0u8; 8 + 8 + 8 + 4 + 4 + 8];
        body.extend_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            decode_body(MsgType::Ack, &body),
            Err(WireError::Malformed("ack"))
        ));
        // Holes beyond the described interval, and adjacent holes, are rejected.
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
            let bytes = encode(&Header::new(MsgType::Ack, 1), &Message::Ack(ack), &key());
            assert!(matches!(
                decode(&bytes, &key()),
                Err(WireError::Malformed("ack"))
            ));
        }
        // Over-long varint.
        let mut body = vec![0u8; 8 + 8 + 8 + 4 + 4 + 8];
        body[8..16].copy_from_slice(&100u64.to_be_bytes()); // highest
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[0xff; 11]);
        assert!(matches!(
            decode_body(MsgType::Ack, &body),
            Err(WireError::Malformed("ack"))
        ));
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
            Writer { buf: &mut buf }.varint(v);
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

    #[test]
    fn describe_holes_is_complete_and_bounded() {
        use crate::protocol::RangeSet;
        // Few holes: everything is described.
        let rs = RangeSet::from_ranges([(0, 100), (200, 300), (400, 500)]);
        let (holes, end) = describe_holes(&rs, 100, 500);
        assert_eq!(holes, vec![(100, 200), (300, 400)]);
        assert_eq!(end, 500);
        // Thousands of holes: the interval is cut so that the list is
        // complete for it and fits the byte budget.
        let mut rs = RangeSet::new();
        for i in 0..3000u64 {
            rs.insert(i * 2864, i * 2864 + 1432); // every other chunk missing
        }
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
        // Encoded ACK stays within the safe datagram size.
        let ack = Ack {
            contiguous_upto: 1432,
            highest: end,
            received_bytes: rs.total(),
            echo_ts: 0,
            ack_delay_us: 0,
            rwnd: 0,
            holes,
        };
        let bytes = encode(
            &Header::new(MsgType::Ack, 1),
            &Message::Ack(ack.clone()),
            &key(),
        );
        assert!(bytes.len() <= UDP_PAYLOAD_SAFE, "{} bytes", bytes.len());
        assert_eq!(decode(&bytes, &key()).unwrap().1, Message::Ack(ack));
    }

    #[test]
    fn control_messages_never_exceed_the_control_datagram() {
        use crate::protocol::RangeSet;
        let mut rs = RangeSet::new();
        for i in 0..5000u64 {
            rs.insert(i * 3000 + (i % 7) * 100, i * 3000 + 1432);
        }
        let top = rs.last_end().unwrap();
        let (holes, end) = describe_holes(&rs, 0, top);
        let ack = HelloAck {
            status: HELLO_ACCEPTED,
            reason: REASON_NONE,
            max_chunk: 1432,
            capabilities: 0,
            echo_ts: 1,
            max_ack_delay_us: 20_000,
            rwnd: 1,
            resume_upto: 0,
            known_end: end,
            holes,
            message: "ж".repeat(200), // 400 bytes, more than fits
        };
        let bytes = encode(
            &Header::new(MsgType::HelloAck, 1),
            &Message::HelloAck(ack.clone()),
            &key(),
        );
        assert!(bytes.len() <= MAX_CONTROL_DATAGRAM, "{} bytes", bytes.len());
        let Ok((_, Message::HelloAck(back))) = decode(&bytes, &key()) else {
            panic!("hello_ack must decode");
        };
        assert_eq!(back.holes, ack.holes, "holes are never shortened");
        assert!(back.message.chars().all(|c| c == 'ж'));
        assert!(back.message.len() < ack.message.len());
    }

    #[test]
    fn trailing_bytes_in_control_bodies_are_ignored() {
        // Extension rule: new fields are appended to control messages, and
        // an older decoder must accept and ignore them.
        let msgs = [
            Message::Hello(Hello {
                transfer_id: [1; 16],
                timestamp: 2,
                file_size: 3,
                file_mtime: 4,
                max_chunk: 1432,
                capabilities: 5,
                file_name: "x".into(),
            }),
            Message::HelloAck(HelloAck {
                status: HELLO_ACCEPTED,
                reason: REASON_NONE,
                max_chunk: 1432,
                capabilities: 0,
                echo_ts: 6,
                max_ack_delay_us: 7,
                rwnd: 7,
                resume_upto: 8,
                known_end: 20,
                holes: vec![(10, 12)],
                message: "ok".into(),
            }),
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
            let bytes = encode(&Header::new(msg.msg_type(), 1), &msg, &key());
            let mut body = body_of(&bytes).to_vec();
            body.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
            assert_eq!(decode_body(msg.msg_type(), &body).unwrap(), msg);
        }
    }

    #[test]
    fn peek_transfer_id_from_hello() {
        let hello = Hello {
            transfer_id: [0x42; 16],
            timestamp: 0,
            file_size: 1,
            file_mtime: 0,
            max_chunk: 1432,
            capabilities: 0,
            file_name: "a".into(),
        };
        let bytes = encode(
            &Header::new(MsgType::Hello, 9),
            &Message::Hello(hello),
            &key(),
        );
        assert_eq!(peek_hello_transfer_id(&bytes), Some([0x42; 16]));
        assert_eq!(peek_hello_transfer_id(&bytes[..10]), None);
    }

    #[test]
    fn file_name_is_cut_at_char_boundary() {
        let name: String = "ж".repeat(200); // 400 bytes
        let hello = Hello {
            transfer_id: [0; 16],
            timestamp: 0,
            file_size: 1,
            file_mtime: 0,
            max_chunk: 1432,
            capabilities: 0,
            file_name: name,
        };
        let bytes = encode(
            &Header::new(MsgType::Hello, 9),
            &Message::Hello(hello),
            &key(),
        );
        let (_, msg) = decode(&bytes, &key()).unwrap();
        if let Message::Hello(h) = msg {
            assert!(h.file_name.len() <= MAX_FILE_NAME_LEN);
            assert!(h.file_name.chars().all(|c| c == 'ж'));
        } else {
            panic!("expected hello");
        }
    }
}
