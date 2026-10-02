//! Authenticated key exchange: Noise `IKpsk2` (the pattern WireGuard uses)
//! with two extra MACs that make the receiver silent and cheap to defend.
//!
//! ```text
//! initiation  S -> R   sender_cid[8] | e[32] | enc(s)[48] | enc(payload)[n+16] | mac1[16] | mac2[16]
//! response    R -> S   sender_cid[8] | receiver_cid[8] | e[32] | enc(payload)[n+16] | mac1[16] | mac2[16]
//! cookie      R -> S   sender_cid[8] | nonce[24] | enc(cookie)[16+16]
//! ```
//!
//! * The sender knows the receiver's static key (its SHARP ID) in advance;
//!   it is authenticated by construction, and its own static key travels
//!   encrypted (identity hiding). Both sides contribute ephemeral keys, so
//!   every session has fresh keys (forward secrecy). An optional pre-shared
//!   key is mixed in as well (post-quantum protection of recorded traffic).
//! * `mac1` is a MAC keyed by the *recipient's* public key. A receiver drops
//!   every initiation whose mac1 is wrong before doing any public-key work
//!   and never answers it: to anyone who does not know its ID it looks like
//!   a closed port.
//! * `mac2` proves that the sender can receive at its source address. Under
//!   load, the receiver answers initiations without a valid mac2 with an
//!   encrypted *cookie* bound to the source address (and changing every two
//!   minutes); the sender repeats its initiation with a mac2 computed from
//!   it. Spoofed floods therefore cost the receiver one MAC per packet.

use crate::crypto::identity::{Identity, SharpId, KEY_LEN};
use crate::crypto::noise;
use crate::crypto::transport::CID_LEN;
use crate::crypto::{derive_secret, keyed_mac, CryptoError, SecretKey};
use crate::sync::{AtomicU64, Ordering};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use crate::crypto::noise::{Split, PROTOCOL_NAME as NOISE_PARAMS};

/// Bound into the handshake transcript: a peer speaking another version of
/// the protocol cannot complete a handshake by accident.
pub const PROLOGUE: &[u8] = b"SHARP-256 v3";
/// The same for version 4.
pub const PROLOGUE_V4: &[u8] = b"SHARP-256 v4";

/// The handshake a peer speaks.
///
/// * Version 3: `Noise_IKpsk2`, the HELLO inside message 1.
/// * Version 4: `Noise_IKpsk2+hfs` with ML-KEM-768 (the session keys depend
///   on X25519 and ML-KEM alike). Message 1 is too long for one datagram
///   and travels in fragments, each with its own `mac1` and `mac2`; message
///   2 carries no HELLO_ACK and no clear copy of the receiver's connection
///   id, and fits one. The HELLO goes after the handshake, under its keys:
///   it has forward secrecy, and a thief of the receiver's key can no
///   longer write one in anybody's name (see the receiver).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {
    V3,
    V4,
}

/// A version 4 fragment's own bytes: the sender's connection id, the
/// fragment byte (index in the high nibble, count in the low one), `mac1`
/// and `mac2`.
pub const FRAGMENT_OVERHEAD: usize = CID_LEN + 1 + 2 * MAC_LEN;
/// Most fragments one initiation is cut into.
pub const MAX_FRAGMENTS: usize = 4;
/// The most of the Noise message one fragment carries: every fragment fits
/// a control datagram.
pub const FRAGMENT_CHUNK: usize =
    crate::protocol::constants::MAX_CONTROL_DATAGRAM - FRAGMENT_OVERHEAD;
/// A version 4 initiation's bytes without payload: the Noise message (with
/// the sealed connection id), and each fragment's own.
pub const INITIATION_OVERHEAD_V4: usize = CID_LEN + noise::HFS_INITIATION_LEN;
/// A version 4 response without payload: the sender's connection id in the
/// clear, the Noise message with the receiver's sealed inside, `mac1`.
pub const RESPONSE_OVERHEAD_V4: usize = 2 * CID_LEN + noise::HFS_RESPONSE_LEN + MAC_LEN;
pub const MAC_LEN: usize = 16;
const AEAD_TAG: usize = 16;
/// Initiation size without payload. The sender's connection id is in it
/// twice: in the clear, where the receiver's dispatcher can see it, and
/// sealed at the start of the Noise payload, where nobody can change it.
pub const INITIATION_OVERHEAD: usize = 2 * CID_LEN + noise::INITIATION_LEN + 2 * MAC_LEN;
/// Response size without payload; both connection ids in the clear, and the
/// receiver's sealed again inside, for the same reason.
pub const RESPONSE_OVERHEAD: usize = 3 * CID_LEN + noise::RESPONSE_LEN + 2 * MAC_LEN;
pub const COOKIE_REPLY_LEN: usize = CID_LEN + 24 + 16 + AEAD_TAG;
/// How long a cookie secret is used before it is replaced.
pub const COOKIE_LIFETIME: Duration = Duration::from_secs(120);

pub(crate) fn mac1_key(public: &[u8; KEY_LEN]) -> [u8; 32] {
    blake3::derive_key("sharp256 v3 mac1", public)
}

/// Version 4's `mac1` key: a receiver of either version tells the two apart
/// by it, and one of version 3 hears nothing it knows in a fragment.
pub(crate) fn mac1_key_v4(public: &[u8; KEY_LEN]) -> [u8; 32] {
    blake3::derive_key("sharp256 v4 mac1", public)
}

pub(crate) fn cookie_key(public: &[u8; KEY_LEN]) -> [u8; 32] {
    blake3::derive_key("sharp256 v3 cookie", public)
}

pub(crate) fn mac2_key(cookie: &[u8; MAC_LEN]) -> Zeroizing<[u8; 32]> {
    derive_secret("sharp256 v3 mac2", &[cookie])
}

fn mac(key: &[u8; 32], data: &[u8]) -> [u8; MAC_LEN] {
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&blake3::keyed_hash(key, data).as_bytes()[..MAC_LEN]);
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

fn random_cid() -> u64 {
    loop {
        let c = rand::rngs::OsRng.next_u64();
        // Some values mean something else on the wire; see there.
        if crate::protocol::constants::is_usable_cid(c) {
            return c;
        }
    }
}

/// Initiation timestamps: each above every one handed out before by this
/// process, whichever threads ask at once and whatever floor is raised
/// meanwhile (the order of changes to one atomic is total, so no ordering
/// stronger than Relaxed is needed; the loom model checks it).
struct Clock {
    last: AtomicU64,
}

impl Clock {
    /// `now`, or just above the newest handed out if that is not below it.
    fn next(&self, now: u64) -> u64 {
        use Ordering::Relaxed;
        let mut prev = self.last.load(Relaxed);
        loop {
            let next = now.max(prev + 1);
            match self
                .last
                .compare_exchange_weak(prev, next, Relaxed, Relaxed)
            {
                Ok(_) => return next,
                Err(p) => prev = p,
            }
        }
    }

    fn last(&self) -> u64 {
        self.last.load(Ordering::Relaxed)
    }

    fn raise(&self, floor: u64) {
        self.last.fetch_max(floor, Ordering::Relaxed);
    }
}

/// The newest initiation timestamp handed out by this process.
#[cfg(not(all(test, sharp_loom)))]
static CLOCK: Clock = Clock {
    last: AtomicU64::new(0),
};

// loom's atomics cannot be made in a constant; this one is made afresh in
// each run of a model.
#[cfg(all(test, sharp_loom))]
loom::lazy_static! {
    static ref CLOCK: Clock = Clock { last: AtomicU64::new(0) };
}

/// Strictly increasing wall-clock timestamp (nanoseconds since the Unix
/// epoch) carried in initiations: a receiver accepts an initiation from a
/// given sender only if its timestamp exceeds the last one it saw, so
/// recorded initiations cannot be replayed.
pub fn initiation_timestamp() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    CLOCK.next(now)
}

/// The newest timestamp [`initiation_timestamp`] has handed out, for saving
/// across restarts.
pub fn last_initiation_timestamp() -> u64 {
    CLOCK.last()
}

/// Never hand out a timestamp at or below `floor` — the newest one a
/// previous run used. A receiver refuses an initiation that is not newer
/// than the last it took from us, silently, as it must refuse replays; so a
/// sender whose clock was set back since then would otherwise be refused
/// without a word until the clock caught up again.
pub fn raise_initiation_timestamp_floor(floor: u64) {
    CLOCK.raise(floor);
}

// ---------------------------------------------------------------------------
// Initiator (sender)
// ---------------------------------------------------------------------------

/// One handshake attempt of a sender. Every retry is a new attempt with a
/// new ephemeral key and connection id.
pub struct Initiator {
    noise: noise::Initiator,
    version: Version,
    cid: u64,
    receiver_mac1_key: [u8; 32],
    receiver_cookie_key: [u8; 32],
    own_mac1_key: [u8; 32],
    /// The mac1 of each datagram of the latest initiation: a cookie reply
    /// is sealed to one of them.
    last_mac1: Vec<[u8; MAC_LEN]>,
}

impl Initiator {
    pub fn new(
        identity: &Identity,
        receiver: &SharpId,
        psk: &SecretKey,
    ) -> Result<Self, CryptoError> {
        // Every exchange with such a key comes out the same whatever the
        // secrets, so the handshake would authenticate nobody. Parsing an ID
        // already refuses one; this is for callers that built it by hand.
        if receiver.is_low_order() {
            return Err(CryptoError::Handshake("receiver key is not usable".into()));
        }
        Ok(Self {
            noise: noise::Initiator::new(identity, receiver.as_bytes(), psk, PROLOGUE),
            version: Version::V3,
            cid: random_cid(),
            receiver_mac1_key: mac1_key(receiver.as_bytes()),
            receiver_cookie_key: cookie_key(receiver.as_bytes()),
            own_mac1_key: mac1_key(identity.public()),
            last_mac1: Vec::new(),
        })
    }

    /// An attempt at a version 4 handshake.
    pub fn new_v4(
        identity: &Identity,
        receiver: &SharpId,
        psk: &SecretKey,
    ) -> Result<Self, CryptoError> {
        let v3 = Self::new(identity, receiver, psk)?;
        Ok(Self {
            noise: noise::Initiator::new_hybrid(identity, receiver.as_bytes(), psk, PROLOGUE_V4),
            version: Version::V4,
            receiver_mac1_key: mac1_key_v4(receiver.as_bytes()),
            own_mac1_key: mac1_key_v4(identity.public()),
            ..v3
        })
    }

    pub fn version(&self) -> Version {
        self.version
    }

    /// The connection id and ephemeral keys of this attempt — in version 4
    /// the ML-KEM key pair of FIPS 203's seed `d || z` too — instead of
    /// fresh ones: the test vectors' (`crypto::vectors`).
    #[cfg(test)]
    pub(crate) fn fix(&mut self, cid: u64, e: SecretKey, kem_seed: Option<&[u8; 64]>) {
        self.cid = cid;
        self.noise
            .fix(e, kem_seed.map(crate::crypto::kem::KemSecret::from_seed));
    }

    /// The sender's connection id for this attempt: responses and transport
    /// packets from the receiver are addressed to it.
    pub fn cid(&self) -> u64 {
        self.cid
    }

    /// Whether an answer has been read into this attempt, so that it can
    /// take no other.
    pub fn is_spent(&self) -> bool {
        self.noise.is_finished()
    }

    /// The datagrams of the initiation: one in version 3, the fragments of
    /// it in version 4. `cookie` is the latest cookie received from this
    /// receiver, if any.
    pub fn initiation_datagrams(
        &mut self,
        payload: &[u8],
        cookie: Option<&[u8; MAC_LEN]>,
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        match self.version {
            Version::V3 => Ok(vec![self.initiation(payload, cookie)?]),
            Version::V4 => self.fragments(payload, cookie),
        }
    }

    /// Version 4: the Noise message, cut into fragments of about equal
    /// size, each of them `cid | index·count | chunk | mac1 | mac2`.
    fn fragments(
        &mut self,
        payload: &[u8],
        cookie: Option<&[u8; MAC_LEN]>,
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        let sealed = [&self.cid.to_be_bytes()[..], payload].concat();
        let msg = self.noise.write_initiation(&sealed)?;
        let count = msg.len().div_ceil(FRAGMENT_CHUNK);
        if count > MAX_FRAGMENTS {
            return Err(CryptoError::Handshake("initiation too long".into()));
        }
        let per = msg.len().div_ceil(count);
        self.last_mac1.clear();
        let mut out = Vec::with_capacity(count);
        for (i, chunk) in msg.chunks(per).enumerate() {
            let mut d = Vec::with_capacity(FRAGMENT_OVERHEAD + chunk.len());
            d.extend_from_slice(&self.cid.to_be_bytes());
            d.push(((i as u8) << 4) | count as u8);
            d.extend_from_slice(chunk);
            let end = d.len();
            d.resize(end + 2 * MAC_LEN, 0);
            let m1 = mac(&self.receiver_mac1_key, &d[..end]);
            d[end..end + MAC_LEN].copy_from_slice(&m1);
            self.last_mac1.push(m1);
            if let Some(cookie) = cookie {
                let m2: [u8; MAC_LEN] = keyed_mac(&mac2_key(cookie), &[&d[..end + MAC_LEN]]);
                d[end + MAC_LEN..].copy_from_slice(&m2);
            }
            out.push(d);
        }
        Ok(out)
    }

    /// Builds the initiation datagram (version 3). `cookie` is the latest
    /// cookie received from this receiver, if any.
    pub fn initiation(
        &mut self,
        payload: &[u8],
        cookie: Option<&[u8; MAC_LEN]>,
    ) -> Result<Vec<u8>, CryptoError> {
        if self.version != Version::V3 {
            return Err(CryptoError::Handshake(
                "a version 4 initiation is fragments".into(),
            ));
        }
        let sealed = [&self.cid.to_be_bytes()[..], payload].concat();
        let msg = self.noise.write_initiation(&sealed)?;
        let mut out = Vec::with_capacity(INITIATION_OVERHEAD + payload.len());
        out.extend_from_slice(&self.cid.to_be_bytes());
        out.extend_from_slice(&msg);
        let end = out.len();
        out.resize(end + 2 * MAC_LEN, 0);
        let m1 = mac(&self.receiver_mac1_key, &out[..end]);
        self.last_mac1 = vec![m1];
        out[end..end + MAC_LEN].copy_from_slice(&m1);
        if let Some(cookie) = cookie {
            let m2: [u8; MAC_LEN] = keyed_mac(&mac2_key(cookie), &[&out[..end + MAC_LEN]]);
            out[end + MAC_LEN..].copy_from_slice(&m2);
        }
        Ok(out)
    }

    /// Decrypts a cookie reply to this attempt's latest initiation.
    pub fn read_cookie_reply(&self, pkt: &[u8]) -> Option<[u8; MAC_LEN]> {
        open_cookie(&self.receiver_cookie_key, &self.last_mac1, self.cid, pkt)
    }

    /// Completes the handshake with the receiver's response. Returns the
    /// receiver's connection id, the response payload and the key split.
    ///
    /// A datagram that is not the receiver's answer leaves the attempt as
    /// it was, ready for the real one: the connection id it is addressed to
    /// travels in the clear, so anyone who sees the initiation can send
    /// something to it, and consuming the attempt on the first such thing
    /// would let one junk datagram per attempt stop a handshake for good.
    /// The Noise state restores itself when a message fails to decrypt.
    /// Once an answer has been read (see [`Initiator::is_spent`]), the
    /// attempt is finished either way.
    pub fn read_response(&mut self, pkt: &[u8]) -> Result<(u64, Vec<u8>, Split), CryptoError> {
        if self.noise.is_finished() {
            return Err(CryptoError::Malformed);
        }
        let n = pkt.len();
        // Version 3: sender cid | receiver cid | Noise | mac1 | mac2 (zero);
        // version 4: sender cid | Noise | mac1.
        let (least, noise_at, body_end) = match self.version {
            Version::V3 => (
                RESPONSE_OVERHEAD,
                2 * CID_LEN,
                n.saturating_sub(2 * MAC_LEN),
            ),
            Version::V4 => (RESPONSE_OVERHEAD_V4, CID_LEN, n.saturating_sub(MAC_LEN)),
        };
        if n < least || pkt[..CID_LEN] != self.cid.to_be_bytes() {
            return Err(CryptoError::Malformed);
        }
        if !ct_eq(
            &mac(&self.own_mac1_key, &pkt[..body_end]),
            &pkt[body_end..body_end + MAC_LEN],
        ) {
            return Err(CryptoError::Mac);
        }
        let mut payload = self.noise.read_response(&pkt[noise_at..body_end])?;
        // The receiver's connection id is taken from inside, where it is
        // sealed, never from the clear copy: that one is covered only by a
        // mac1 anyone who knows our public key can make, so a copy of the
        // answer could be raced ahead of it with the id changed, and the
        // whole session would then be addressed to a connection the
        // receiver does not have. Refusing such a copy is not an option —
        // reading it has already finished the handshake — but it no
        // longer matters what the clear copy says.
        if payload.len() < CID_LEN {
            return Err(CryptoError::Malformed);
        }
        let responder_cid = u64::from_be_bytes(payload[..CID_LEN].try_into().unwrap());
        payload.drain(..CID_LEN);
        if responder_cid == 0 {
            return Err(CryptoError::Malformed);
        }
        let split = self.noise.split().expect("the response was read");
        Ok((responder_cid, payload.to_vec(), split))
    }
}

/// The cookie in a reply to a datagram of `cid`, sealed with a receiver's
/// cookie `key` to the mac1 of the datagram it answers: any of `sent`.
pub(crate) fn open_cookie(
    key: &[u8; 32],
    sent: &[[u8; MAC_LEN]],
    cid: u64,
    pkt: &[u8],
) -> Option<[u8; MAC_LEN]> {
    if pkt.len() != COOKIE_REPLY_LEN || pkt[..CID_LEN] != cid.to_be_bytes() {
        return None;
    }
    let nonce = &pkt[CID_LEN..CID_LEN + 24];
    let tag = &pkt[CID_LEN + 40..];
    sent.iter().find_map(|m1| {
        let mut cookie = [0u8; MAC_LEN];
        cookie.copy_from_slice(&pkt[CID_LEN + 24..CID_LEN + 40]);
        XChaCha20Poly1305::new(key.into())
            .decrypt_in_place_detached(nonce.into(), m1, &mut cookie, tag.into())
            .ok()
            .map(|()| cookie)
    })
}

/// What anybody who knows a receiver's ID can make: the MACs on datagrams
/// of their own choosing, and the cookie in a reply that reaches their own
/// address. For the fuzzing targets, which have to get past `mac1` (the
/// check that stops whoever does not know the ID) to reach what is behind
/// it.
#[cfg(any(test, fuzzing))]
pub mod forge {
    use super::*;

    /// `body` — a version 3 initiation up to its MACs, or a version 4
    /// fragment — with its `mac1`, and the `mac2` of `cookie` if one has
    /// come to the forger; the datagram, and its `mac1`.
    pub fn stamp(
        receiver: &SharpId,
        version: Version,
        body: &[u8],
        cookie: Option<&[u8; MAC_LEN]>,
    ) -> (Vec<u8>, [u8; MAC_LEN]) {
        let key = match version {
            Version::V3 => mac1_key(receiver.as_bytes()),
            Version::V4 => mac1_key_v4(receiver.as_bytes()),
        };
        let m1 = mac(&key, body);
        let mut out = body.to_vec();
        out.extend_from_slice(&m1);
        let m2: [u8; MAC_LEN] = match cookie {
            Some(c) => keyed_mac(&mac2_key(c), &[&out]),
            None => [0; MAC_LEN],
        };
        out.extend_from_slice(&m2);
        (out, m1)
    }

    /// The cookie in `reply`, to a datagram of `cid` stamped with `mac1`.
    pub fn open_cookie_reply(
        receiver: &SharpId,
        cid: u64,
        mac1: &[u8; MAC_LEN],
        reply: &[u8],
    ) -> Option<[u8; MAC_LEN]> {
        open_cookie(
            &cookie_key(receiver.as_bytes()),
            std::slice::from_ref(mac1),
            cid,
            reply,
        )
    }
}

// ---------------------------------------------------------------------------
// Responder (receiver)
// ---------------------------------------------------------------------------

/// Receiver side of handshakes: checks MACs, reads initiations.
pub struct Responder {
    identity: Identity,
    psk: SecretKey,
    mac1_key: [u8; 32],
    mac1_key_v4: [u8; 32],
}

/// An authenticated initiation waiting for the receiver's answer.
pub struct Incoming {
    noise: noise::Responder,
    pub version: Version,
    pub sender_cid: u64,
    pub sender: SharpId,
    pub payload: Vec<u8>,
}

/// A version 4 fragment whose `mac1` is ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    pub sender_cid: u64,
    pub index: usize,
    pub count: usize,
}

impl Responder {
    pub fn new(identity: Identity, psk: SecretKey) -> Self {
        let mac1_key = mac1_key(identity.public());
        let mac1_key_v4 = mac1_key_v4(identity.public());
        Self {
            identity,
            psk,
            mac1_key,
            mac1_key_v4,
        }
    }

    /// The same check for a version 4 fragment: whether it is one, made by
    /// someone who knows our ID, and where it goes.
    pub fn fragment(&self, pkt: &[u8]) -> Option<Fragment> {
        let n = pkt.len();
        if n <= FRAGMENT_OVERHEAD {
            return None;
        }
        let body_end = n - 2 * MAC_LEN;
        if !ct_eq(
            &mac(&self.mac1_key_v4, &pkt[..body_end]),
            &pkt[body_end..body_end + MAC_LEN],
        ) {
            return None;
        }
        let byte = pkt[CID_LEN];
        let (index, count) = ((byte >> 4) as usize, (byte & 0x0f) as usize);
        if count == 0 || count > MAX_FRAGMENTS || index >= count {
            return None;
        }
        Some(Fragment {
            sender_cid: u64::from_be_bytes(pkt[..CID_LEN].try_into().unwrap()),
            index,
            count,
        })
    }

    /// Reads a version 4 initiation put together from its fragments: the
    /// sender's connection id and the Noise message.
    pub fn read_initiation_v4(&self, sender_cid: u64, msg: &[u8]) -> Result<Incoming, CryptoError> {
        if sender_cid == 0 {
            return Err(CryptoError::Malformed);
        }
        let read =
            noise::Responder::read_hybrid_initiation(&self.identity, &self.psk, PROLOGUE_V4, msg)?;
        self.incoming(Version::V4, sender_cid, read)
    }

    pub fn id(&self) -> SharpId {
        self.identity.id()
    }

    /// Cheap first check of a datagram that is not addressed to a known
    /// connection: is it an initiation made by someone who knows our ID?
    pub fn is_initiation(&self, pkt: &[u8]) -> bool {
        let n = pkt.len();
        if n < INITIATION_OVERHEAD {
            return false;
        }
        let body_end = n - 2 * MAC_LEN;
        ct_eq(
            &mac(&self.mac1_key, &pkt[..body_end]),
            &pkt[body_end..body_end + MAC_LEN],
        )
    }

    /// Reads an initiation whose mac1 was verified; fails unless it was made
    /// for our static key. The pre-shared key is only verified when the
    /// sender reads the response (IKpsk2 mixes it into the second message):
    /// a sender with a different PSK never completes the handshake.
    pub fn read_initiation(&self, pkt: &[u8]) -> Result<Incoming, CryptoError> {
        let n = pkt.len();
        if n < INITIATION_OVERHEAD {
            return Err(CryptoError::Malformed);
        }
        let sender_cid = u64::from_be_bytes(pkt[..CID_LEN].try_into().unwrap());
        if sender_cid == 0 {
            return Err(CryptoError::Malformed);
        }
        let read = noise::Responder::read_initiation(
            &self.identity,
            &self.psk,
            PROLOGUE,
            &pkt[CID_LEN..n - 2 * MAC_LEN],
        )?;
        self.incoming(Version::V3, sender_cid, read)
    }

    fn incoming(
        &self,
        version: Version,
        sender_cid: u64,
        read: noise::Initiation,
    ) -> Result<Incoming, CryptoError> {
        let mut payload = read.payload;
        // The connection id in the clear is covered by nothing but mac1,
        // whose key anyone can work out from our public key, so a copy of
        // an initiation could arrive with it changed — and the answer would
        // then go to a connection the sender does not have. The sealed copy
        // is the sender's; a packet where the two differ was altered on the
        // way, and is refused before it counts for anything.
        if payload.len() < CID_LEN || payload[..CID_LEN] != sender_cid.to_be_bytes() {
            return Err(CryptoError::Malformed);
        }
        payload.drain(..CID_LEN);
        let sender = SharpId::from_public(read.initiator_static);
        // A static key with no private half. Anyone could present it, so it
        // identifies nobody — and a sender limit keyed on identities would
        // count everyone presenting it as one stranger.
        if sender.is_low_order() {
            return Err(CryptoError::Malformed);
        }
        Ok(Incoming {
            noise: read.responder,
            version,
            sender_cid,
            sender,
            payload: payload.to_vec(),
        })
    }
}

impl Incoming {
    /// The ephemeral key the response is written with — and in version 4
    /// FIPS 203's `m` for the encapsulation — instead of fresh ones: the
    /// test vectors' (`crypto::vectors`).
    #[cfg(test)]
    pub(crate) fn fix(&mut self, e: SecretKey, kem_random: Option<[u8; 32]>) {
        self.noise.fix(e, kem_random);
    }

    /// Writes the response and completes the handshake.
    pub fn respond(
        self,
        receiver_cid: u64,
        payload: &[u8],
    ) -> Result<(Vec<u8>, Split), CryptoError> {
        let sealed = [&receiver_cid.to_be_bytes()[..], payload].concat();
        let (msg, split) = self.noise.write_response(&sealed)?;
        let mut out = Vec::with_capacity(RESPONSE_OVERHEAD_V4 + payload.len());
        out.extend_from_slice(&self.sender_cid.to_be_bytes());
        match self.version {
            Version::V3 => {
                out.extend_from_slice(&receiver_cid.to_be_bytes());
                out.extend_from_slice(&msg);
                let end = out.len();
                out.resize(end + 2 * MAC_LEN, 0);
                let m1 = mac(&mac1_key(self.sender.as_bytes()), &out[..end]);
                out[end..end + MAC_LEN].copy_from_slice(&m1);
            }
            // No clear copy of the receiver's id (only the sealed one ever
            // counted) and no mac2 (always zero in an answer): what keeps
            // the answer within one control datagram.
            Version::V4 => {
                out.extend_from_slice(&msg);
                let m1 = mac(&mac1_key_v4(self.sender.as_bytes()), &out);
                out.extend_from_slice(&m1);
            }
        }
        Ok((out, split))
    }
}

// ---------------------------------------------------------------------------
// Fragments (version 4)
// ---------------------------------------------------------------------------

/// Version 4 initiations being put together from their fragments.
///
/// Only a fragment whose `mac1` is ours comes here — made by someone who
/// knows our ID — and what it may make us hold is bounded: a few initiations
/// per client (an IPv4 address or an IPv6 /64, as the handshake limiter
/// counts), a table of [`Fragments::CAPACITY`], each for
/// [`Fragments::PATIENCE`], the oldest going first when the table is full.
/// Nothing is answered until every fragment is in.
#[derive(Default)]
pub struct Fragments {
    partial: HashMap<(SocketAddr, u64), Partial>,
}

struct Partial {
    chunks: [Option<Vec<u8>>; MAX_FRAGMENTS],
    count: usize,
    /// Bytes of the datagrams taken, fragments' own included: what the
    /// address has sent, and what may be sent back to it.
    bytes: usize,
    first: Instant,
}

/// An initiation put together: the sender's connection id, the Noise
/// message, and the bytes of all its datagrams.
pub struct Assembled {
    pub sender_cid: u64,
    pub msg: Vec<u8>,
    pub len: usize,
}

impl Fragments {
    /// Initiations being put together at once.
    pub const CAPACITY: usize = 1024;
    /// Of them, from one client.
    pub const PER_CLIENT: usize = 8;
    /// How long the fragments of one are waited for.
    pub const PATIENCE: Duration = Duration::from_secs(2);

    /// Takes the fragment `f` (checked by [`Responder::fragment`]) of the
    /// datagram `pkt` from `from`; the whole initiation when it was the
    /// last one missing.
    pub fn add(
        &mut self,
        pkt: &[u8],
        f: Fragment,
        from: SocketAddr,
        now: Instant,
    ) -> Option<Assembled> {
        self.partial
            .retain(|_, p| now.saturating_duration_since(p.first) < Self::PATIENCE);
        let key = (from, f.sender_cid);
        if !self.partial.contains_key(&key) {
            let client = crate::address::client_key(from);
            let mine = self
                .partial
                .keys()
                .filter(|(a, _)| crate::address::client_key(*a) == client)
                .count();
            if mine >= Self::PER_CLIENT {
                return None;
            }
            if self.partial.len() >= Self::CAPACITY {
                let oldest = self
                    .partial
                    .iter()
                    .min_by_key(|(_, p)| p.first)
                    .map(|(k, _)| *k)?;
                self.partial.remove(&oldest);
            }
            self.partial.insert(
                key,
                Partial {
                    chunks: Default::default(),
                    count: f.count,
                    bytes: 0,
                    first: now,
                },
            );
        }
        let p = self.partial.get_mut(&key).expect("just made");
        // A fragment that disagrees on how many there are is not one of
        // these; one already here is not taken twice.
        if p.count != f.count || p.chunks[f.index].is_some() {
            return None;
        }
        p.chunks[f.index] = Some(pkt[CID_LEN + 1..pkt.len() - 2 * MAC_LEN].to_vec());
        p.bytes += pkt.len();
        if p.chunks[..p.count].iter().any(Option::is_none) {
            return None;
        }
        let p = self.partial.remove(&key).expect("present");
        let msg = p.chunks[..p.count]
            .iter()
            .flatten()
            .flatten()
            .copied()
            .collect();
        Some(Assembled {
            sender_cid: f.sender_cid,
            msg,
            len: p.bytes,
        })
    }

    /// Initiations being put together.
    pub fn len(&self) -> usize {
        self.partial.len()
    }

    pub fn is_empty(&self) -> bool {
        self.partial.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Cookies (denial-of-service protection)
// ---------------------------------------------------------------------------

/// Receiver-side cookie state: verifies mac2 and issues cookie replies.
pub struct CookieJar {
    reply_key: [u8; 32],
    secrets: [SecretKey; 2],
    born: Instant,
}

impl CookieJar {
    pub fn new(own: &SharpId) -> Self {
        Self {
            reply_key: cookie_key(own.as_bytes()),
            secrets: [SecretKey::random(), SecretKey::random()],
            born: Instant::now(),
        }
    }

    fn rotate(&mut self, now: Instant) {
        if now.saturating_duration_since(self.born) >= COOKIE_LIFETIME {
            self.secrets.swap(0, 1);
            self.secrets[0] = SecretKey::random();
            self.born = now;
        }
    }

    fn cookie(secret: &[u8; 32], addr: SocketAddr) -> [u8; MAC_LEN] {
        let ip = match addr.ip() {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };
        keyed_mac(secret, &[&ip, &addr.port().to_be_bytes()])
    }

    /// Whether the initiation carries a mac2 made with a current cookie for
    /// its source address.
    pub fn mac2_ok(&mut self, pkt: &[u8], from: SocketAddr, now: Instant) -> bool {
        self.rotate(now);
        let n = pkt.len();
        if n < INITIATION_OVERHEAD {
            return false;
        }
        let (msg, mac2) = pkt.split_at(n - MAC_LEN);
        self.secrets.iter().any(|s| {
            let cookie = Self::cookie(s.expose(), from);
            ct_eq(&keyed_mac::<MAC_LEN>(&mac2_key(&cookie), &[msg]), mac2)
        })
    }

    /// Cookie reply for an initiation received from `from`.
    pub fn reply(&mut self, initiation: &[u8], from: SocketAddr, now: Instant) -> Option<Vec<u8>> {
        self.rotate(now);
        let n = initiation.len();
        if n < INITIATION_OVERHEAD {
            return None;
        }
        let mac1 = &initiation[n - 2 * MAC_LEN..n - MAC_LEN];
        let mut cookie = Self::cookie(self.secrets[0].expose(), from);
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let tag = XChaCha20Poly1305::new((&self.reply_key).into())
            .encrypt_in_place_detached((&nonce).into(), mac1, &mut cookie)
            .ok()?;
        let mut out = Vec::with_capacity(COOKIE_REPLY_LEN);
        out.extend_from_slice(&initiation[..CID_LEN]);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&cookie);
        out.extend_from_slice(&tag);
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// Admission control
// ---------------------------------------------------------------------------

/// Rejects replayed initiations: per sender, timestamps must increase.
///
/// The number of remembered senders is capped. When it is reached the
/// first-seen sender is forgotten in O(1) (a first-in-first-out order kept
/// alongside the map), so a flood of fresh identities cannot make admission
/// cost grow with the table size. Forgetting an entry can at worst allow one
/// replay of an initiation, which still cannot complete without the sender's
/// private key.
pub struct ReplayGuard {
    last: HashMap<SharpId, u64>,
    /// Senders in the order they were first seen; the eviction queue.
    order: VecDeque<SharpId>,
    capacity: usize,
}

impl ReplayGuard {
    pub fn new(capacity: usize) -> Self {
        Self {
            last: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    pub fn accept(&mut self, sender: &SharpId, timestamp: u64) -> bool {
        self.accept_keeping(sender, timestamp, |_| false)
    }

    /// [`ReplayGuard::accept`], never forgetting a sender for which `keep`
    /// is true to make room.
    ///
    /// The guard is bounded, and identities cost nothing to make, so anyone
    /// can push old entries out by presenting enough new ones. For a sender
    /// with a transfer in progress that must not work: forgetting it would
    /// let a captured initiation of the live transfer be taken again, and
    /// the session be switched to a handshake its sender never finished.
    pub fn accept_keeping(
        &mut self,
        sender: &SharpId,
        timestamp: u64,
        keep: impl Fn(&SharpId) -> bool,
    ) -> bool {
        if let Some(slot) = self.last.get_mut(sender) {
            if timestamp <= *slot {
                return false;
            }
            *slot = timestamp;
            return true;
        }
        if self.last.len() >= self.capacity {
            // `order` holds exactly the live keys (each pushed once when
            // first inserted, popped only here), so its front is present.
            // Kept senders go to the back; there are only ever as many of
            // them as sessions, so a victim turns up at once.
            for _ in 0..self.order.len() {
                let Some(old) = self.order.pop_front() else {
                    break;
                };
                if keep(&old) {
                    self.order.push_back(old);
                    continue;
                }
                self.last.remove(&old);
                break;
            }
        }
        self.last.insert(*sender, timestamp);
        self.order.push_back(*sender);
        true
    }
}

/// Rate limits for initiations: per source address, and a global rate
/// beyond which the receiver is "under load" and demands cookies.
pub struct HandshakeLimiter {
    per_ip: HashMap<IpAddr, (f64, Instant)>,
    rate: f64,
    burst: f64,
    window_start: Instant,
    window_count: u32,
    load_threshold: u32,
    last_prune: Instant,
    last_full_prune: Instant,
}

/// Clients the handshake limiter tracks at once.
const MAX_LIMITED_CLIENTS: usize = 65_536;

impl HandshakeLimiter {
    /// `rate`/`burst`: initiations per second and burst per source address;
    /// `load_threshold`: initiations per second (all sources) beyond which
    /// cookies are required.
    pub fn new(rate: f64, burst: f64, load_threshold: u32) -> Self {
        let now = Instant::now();
        Self {
            per_ip: HashMap::new(),
            rate,
            burst,
            window_start: now,
            window_count: 0,
            load_threshold,
            last_prune: now,
            last_full_prune: now,
        }
    }

    /// Counts an initiation and tells whether the receiver is under load.
    pub fn note_initiation(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.window_count = 0;
        }
        self.window_count += 1;
        self.window_count > self.load_threshold
    }

    /// Takes a token for the client `from` counts as (see
    /// [`crate::address::client_key`]); false if it exceeded its rate.
    pub fn allow(&mut self, from: SocketAddr, now: Instant) -> bool {
        let key = crate::address::client_key(from);
        let (rate, burst) = (self.rate, self.burst);
        let prune = |m: &mut HashMap<IpAddr, (f64, Instant)>| {
            m.retain(|_, (tokens, at)| {
                *tokens + now.saturating_duration_since(*at).as_secs_f64() * rate < burst
            });
        };
        if now.saturating_duration_since(self.last_prune) >= Duration::from_secs(10) {
            prune(&mut self.per_ip);
            self.last_prune = now;
        }
        // Bounded: a spray of forged source addresses would otherwise grow
        // the table by an entry per packet until the next prune. Full, it
        // makes room at most four times a second, and otherwise refuses
        // newcomers rather than grow.
        if self.per_ip.len() >= MAX_LIMITED_CLIENTS && !self.per_ip.contains_key(&key) {
            if now.saturating_duration_since(self.last_full_prune) >= Duration::from_millis(250) {
                self.last_full_prune = now;
                prune(&mut self.per_ip);
            }
            if self.per_ip.len() >= MAX_LIMITED_CLIENTS {
                return false;
            }
        }
        let (tokens, at) = self.per_ip.entry(key).or_insert((self.burst, now));
        *tokens = (*tokens + now.saturating_duration_since(*at).as_secs_f64() * self.rate)
            .min(self.burst);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk() -> SecretKey {
        SecretKey::from_bytes(&[7; 32])
    }

    fn pair() -> (Identity, Identity) {
        (Identity::generate(), Identity::generate())
    }

    #[test]
    fn handshake_agrees_on_keys_and_authenticates_both() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), psk());
        let mut init = Initiator::new(&s, &r.id(), &psk()).unwrap();
        let pkt = init.initiation(b"hello payload", None).unwrap();
        assert_eq!(pkt.len(), INITIATION_OVERHEAD + 13);
        assert!(responder.is_initiation(&pkt));
        let incoming = responder.read_initiation(&pkt).unwrap();
        assert_eq!(incoming.sender, s.id());
        assert_eq!(incoming.payload, b"hello payload");
        assert_eq!(incoming.sender_cid, init.cid());
        let (resp, rsplit) = incoming.respond(42, b"ack").unwrap();
        let (rcid, payload, isplit) = init.read_response(&resp).unwrap();
        assert_eq!(rcid, 42);
        assert_eq!(payload, b"ack");
        assert_eq!(isplit.initiator_to_responder, rsplit.initiator_to_responder);
        assert_eq!(isplit.responder_to_initiator, rsplit.responder_to_initiator);
        assert_eq!(isplit.hash, rsplit.hash);
        assert_ne!(isplit.initiator_to_responder, isplit.responder_to_initiator);
    }

    #[test]
    fn strangers_and_tampering_are_rejected() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), psk());
        // Sender that does not know the receiver's ID: mac1 fails, silence.
        let wrong = Identity::generate();
        let mut init = Initiator::new(&s, &wrong.id(), &psk()).unwrap();
        let pkt = init.initiation(b"x", None).unwrap();
        assert!(!responder.is_initiation(&pkt));
        // Right ID, but any modified byte breaks mac1 or the handshake.
        let mut init = Initiator::new(&s, &r.id(), &psk()).unwrap();
        let pkt = init.initiation(b"payload", None).unwrap();
        for i in 0..pkt.len() - MAC_LEN {
            let mut bad = pkt.clone();
            bad[i] ^= 1;
            assert!(
                !responder.is_initiation(&bad) || responder.read_initiation(&bad).is_err(),
                "flip at {} accepted",
                i
            );
        }
        // Random garbage of any length is never mistaken for an initiation.
        for len in 0..400usize {
            let junk: Vec<u8> = (0..len).map(|i| (i * 131 + 7) as u8).collect();
            assert!(!responder.is_initiation(&junk));
        }
    }

    /// A receiver "key" with no private half would make every exchange in
    /// the handshake come out the same whatever the secrets, so the
    /// handshake would authenticate nobody. It is refused before one starts.
    #[test]
    fn a_low_order_receiver_key_is_refused() {
        let s = Identity::generate();
        for point in crate::crypto::identity::tests::low_order_points() {
            let id = SharpId::from_public(point);
            assert!(Initiator::new(&s, &id, &psk()).is_err());
        }
    }

    #[test]
    fn different_psk_fails_at_the_response() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), SecretKey::from_bytes(&[9; 32]));
        let mut init = Initiator::new(&s, &r.id(), &psk()).unwrap();
        let pkt = init.initiation(b"p", None).unwrap();
        let incoming = responder.read_initiation(&pkt).unwrap();
        let (resp, _) = incoming.respond(5, b"r").unwrap();
        assert!(init.read_response(&resp).is_err());
    }

    /// The connection id an answer is addressed to travels in the clear, so
    /// anyone who saw the initiation can send something to it — even with
    /// a valid mac1, if they know the sender's public key. None of it may
    /// use the attempt up: the real answer, arriving after, still completes
    /// the handshake.
    #[test]
    fn junk_addressed_to_an_attempt_does_not_use_it_up() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), psk());
        let mut init = Initiator::new(&s, &r.id(), &psk()).unwrap();
        let pkt = init.initiation(b"p", None).unwrap();
        let (resp, _) = responder
            .read_initiation(&pkt)
            .unwrap()
            .respond(7, b"r")
            .unwrap();
        let body_end = resp.len() - 2 * MAC_LEN;
        for i in [2 * CID_LEN, 2 * CID_LEN + 40, body_end - 1] {
            let mut junk = resp.clone();
            junk[i] ^= 0x40;
            // Re-made so that it passes the mac1 check and reaches Noise.
            let m1 = mac(&mac1_key(s.public()), &junk[..body_end]);
            junk[body_end..body_end + MAC_LEN].copy_from_slice(&m1);
            assert!(init.read_response(&junk).is_err());
            assert!(!init.is_spent());
        }
        assert!(init.read_response(&resp[..resp.len() - 1]).is_err());
        let (rcid, payload, _) = init.read_response(&resp).expect("the real answer");
        assert_eq!((rcid, payload.as_slice()), (7, &b"r"[..]));
        assert!(init.is_spent());
        // And nothing more can be read into it.
        assert!(init.read_response(&resp).is_err());
    }

    /// The connection ids travel in the clear, covered only by mac1 — whose
    /// key is derived from a public key. Changed on the way, they must not
    /// be believed: the receiver refuses an initiation whose id was
    /// altered, and the sender takes the receiver's id from where it is
    /// sealed, so an altered answer raced ahead of the real one sets up the
    /// session exactly as the real one would have.
    #[test]
    fn connection_ids_changed_on_the_way_are_not_believed() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), psk());
        let mut init = Initiator::new(&s, &r.id(), &psk()).unwrap();
        let pkt = init.initiation(b"p", None).unwrap();
        let end = pkt.len() - 2 * MAC_LEN;
        let mut altered = pkt.clone();
        altered[0] ^= 1;
        let m1 = mac(&mac1_key(r.public()), &altered[..end]);
        altered[end..end + MAC_LEN].copy_from_slice(&m1);
        assert!(responder.is_initiation(&altered));
        assert!(responder.read_initiation(&altered).is_err());

        let incoming = responder.read_initiation(&pkt).unwrap();
        assert_eq!(incoming.sender_cid, init.cid());
        assert_eq!(incoming.payload, b"p");
        let (resp, _) = incoming.respond(0x1234, b"r").unwrap();
        let body_end = resp.len() - 2 * MAC_LEN;
        let mut altered = resp.clone();
        altered[CID_LEN + 3] ^= 0x55;
        let m1 = mac(&mac1_key(s.public()), &altered[..body_end]);
        altered[body_end..body_end + MAC_LEN].copy_from_slice(&m1);
        let (rcid, payload, _) = init.read_response(&altered).unwrap();
        assert_eq!(rcid, 0x1234, "the id in the clear was believed");
        assert_eq!(payload, b"r");
    }

    #[test]
    fn responses_are_bound_to_their_attempt() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), psk());
        let mut first = Initiator::new(&s, &r.id(), &psk()).unwrap();
        let pkt1 = first.initiation(b"1", None).unwrap();
        let mut second = Initiator::new(&s, &r.id(), &psk()).unwrap();
        let _pkt2 = second.initiation(b"2", None).unwrap();
        let (resp1, _) = responder
            .read_initiation(&pkt1)
            .unwrap()
            .respond(9, b"")
            .unwrap();
        assert!(second.read_response(&resp1).is_err());
        assert!(first.read_response(&resp1).is_ok());
    }

    #[test]
    fn cookie_roundtrip_proves_the_address() {
        let (s, r) = pair();
        let mut jar = CookieJar::new(&r.id());
        let now = Instant::now();
        let from: SocketAddr = "192.0.2.7:4000".parse().unwrap();
        let mut init = Initiator::new(&s, &r.id(), &psk()).unwrap();
        let pkt = init.initiation(b"p", None).unwrap();
        assert!(!jar.mac2_ok(&pkt, from, now));
        let reply = jar.reply(&pkt, from, now).unwrap();
        assert_eq!(reply.len(), COOKIE_REPLY_LEN);
        let cookie = init.read_cookie_reply(&reply).unwrap();
        // The retried attempt carries mac2 with the cookie.
        let mut retry = Initiator::new(&s, &r.id(), &psk()).unwrap();
        let pkt2 = retry.initiation(b"p", Some(&cookie)).unwrap();
        assert!(jar.mac2_ok(&pkt2, from, now));
        // From another address the same mac2 is worthless.
        let other: SocketAddr = "192.0.2.8:4000".parse().unwrap();
        assert!(!jar.mac2_ok(&pkt2, other, now));
        // Still valid right after a rotation, invalid after two.
        let later = now + COOKIE_LIFETIME;
        assert!(jar.mac2_ok(&pkt2, from, later));
        assert!(!jar.mac2_ok(&pkt2, from, later + COOKIE_LIFETIME));
        // A cookie reply for another attempt is not accepted.
        assert!(retry.read_cookie_reply(&reply).is_none());
    }

    #[test]
    fn replay_guard_and_limiter() {
        let a = Identity::generate().id();
        let b = Identity::generate().id();
        let mut g = ReplayGuard::new(2);
        assert!(g.accept(&a, 10));
        assert!(!g.accept(&a, 10));
        assert!(!g.accept(&a, 9));
        assert!(g.accept(&a, 11));
        assert!(g.accept(&b, 1));

        // At capacity, the first-seen sender (a) is evicted when a third
        // identity appears, in O(1). Re-accepting `a` afterwards is a fresh
        // entry (one replay is tolerable; it still cannot complete).
        let c = Identity::generate().id();
        assert!(g.accept(&c, 5)); // evicts `a`, keeps `b` and `c`
        assert!(!g.accept(&b, 1)); // `b` still remembered: replay rejected
        assert!(g.accept(&a, 1)); // `a` forgotten: accepted anew (evicts `b`)
        let t1 = initiation_timestamp();
        let t2 = initiation_timestamp();
        assert!(t2 > t1);

        let now = Instant::now();
        let mut l = HandshakeLimiter::new(1.0, 3.0, 5);
        let ip: SocketAddr = "198.51.100.1:1000".parse().unwrap();
        assert!(l.allow(ip, now) && l.allow(ip, now) && l.allow(ip, now));
        assert!(!l.allow(ip, now));
        assert!(l.allow(ip, now + Duration::from_millis(1100)));
        let other: SocketAddr = "198.51.100.2:1000".parse().unwrap();
        assert!(l.allow(other, now));
        let loaded = (0..6).map(|_| l.note_initiation(now)).last().unwrap();
        assert!(loaded);
        assert!(!l.note_initiation(now + Duration::from_secs(2)));
    }

    /// Identities cost nothing to make, so a stranger can fill the replay
    /// guard with new ones. Whoever has a transfer in progress is never
    /// pushed out for them: forgetting a live sender would let a captured
    /// initiation of its transfer be taken again.
    #[test]
    fn a_live_sender_is_never_pushed_out_of_the_replay_guard() {
        let mut g = ReplayGuard::new(4);
        let live = Identity::generate().id();
        assert!(g.accept(&live, 100));
        for _ in 0..1000 {
            let stranger = Identity::generate().id();
            assert!(g.accept_keeping(&stranger, 1, |id| *id == live));
        }
        assert!(!g.accept_keeping(&live, 100, |id| *id == live));
        assert!(g.accept_keeping(&live, 101, |id| *id == live));
    }

    /// One IPv6 subscriber is one client for the handshake limit, whatever
    /// address in its /64 it sends from; and a spray of new sources cannot
    /// grow the limiter's table without bound.
    #[test]
    fn the_handshake_limit_counts_a_slash_64_once_and_stays_bounded() {
        let now = Instant::now();
        let mut l = HandshakeLimiter::new(1.0, 2.0, 5);
        let a: SocketAddr = "[2001:db8:1:2::1]:1".parse().unwrap();
        let b: SocketAddr = "[2001:db8:1:2:ffff::7]:2".parse().unwrap();
        assert!(l.allow(a, now) && l.allow(b, now));
        assert!(!l.allow("[2001:db8:1:2:1234::1]:3".parse().unwrap(), now));
        let mut l = HandshakeLimiter::new(1.0, 2.0, 5);
        for i in 0..(MAX_LIMITED_CLIENTS as u32 + 1000) {
            let ip = std::net::Ipv4Addr::from(0x0A00_0000 + i);
            l.allow(SocketAddr::new(ip.into(), 9), now);
        }
        assert!(l.per_ip.len() <= MAX_LIMITED_CLIENTS);
    }

    /// The load threshold is a number of initiations a second that is not
    /// yet load; the one past it is.
    #[test]
    fn load_begins_past_the_threshold() {
        let mut l = HandshakeLimiter::new(10.0, 20.0, 5);
        // The first window starts when the limiter is made.
        let now = Instant::now();
        for i in 1..=5 {
            assert!(!l.note_initiation(now), "initiation {} of 5", i);
        }
        assert!(l.note_initiation(now));
        assert!(!l.note_initiation(now + Duration::from_secs(1)));
    }

    /// A full limiter table makes room only from clients whose buckets have
    /// filled again — no sooner, and as soon as it may (every 250 ms) — and
    /// a client it already holds is served however full it is. Two tokens a
    /// second and a burst of twenty: a client that took one is full again
    /// half a second later.
    #[test]
    fn a_full_limiter_table_makes_room_from_full_buckets_only() {
        let mut l = HandshakeLimiter::new(2.0, 20.0, 5);
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let client = |i: u32| SocketAddr::new(std::net::Ipv4Addr::from(0x0A00_0000 + i).into(), 9);
        for i in 0..MAX_LIMITED_CLIENTS as u32 {
            assert!(l.allow(client(i), t0));
        }
        let newcomer = client(MAX_LIMITED_CLIENTS as u32);
        // Nobody full yet (19 + 0.26 × 2 tokens): no room.
        assert!(!l.allow(newcomer, at(260)));
        // One the table holds is served, full table or not.
        assert!(l.allow(client(5), at(270)));
        // Everyone else full again (19 + 0.52 × 2), and 260 ms since the
        // last look: room.
        assert!(l.allow(newcomer, at(520)));
    }

    /// The smallest initiation there is — no payload — is one: recognised,
    /// answered with a cookie under load, and let in with the cookie's mac2.
    #[test]
    fn the_smallest_initiation_is_one() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), psk());
        let mut jar = CookieJar::new(&r.id());
        let (from, now) = (addr("192.0.2.9:4000"), Instant::now());
        let mut init = Initiator::new(&s, &r.id(), &psk()).unwrap();
        let pkt = init.initiation(b"", None).unwrap();
        assert_eq!(pkt.len(), INITIATION_OVERHEAD);
        assert!(responder.is_initiation(&pkt));
        assert!(responder.read_initiation(&pkt).is_ok());
        let reply = jar.reply(&pkt, from, now).expect("a cookie reply");
        let cookie = init.read_cookie_reply(&reply).unwrap();
        let mut retry = Initiator::new(&s, &r.id(), &psk()).unwrap();
        let pkt = retry.initiation(b"", Some(&cookie)).unwrap();
        assert!(jar.mac2_ok(&pkt, from, now));
        // One byte short of it is nothing.
        assert!(!responder.is_initiation(&pkt[..pkt.len() - 1]));
        assert!(jar.reply(&pkt[..pkt.len() - 1], from, now).is_none());
        assert!(!jar.mac2_ok(&pkt[..pkt.len() - 1], from, now));
    }

    /// An initiation whose sealed payload is too short to hold the sender's
    /// connection id is refused, not read past its end.
    #[test]
    fn a_sealed_payload_shorter_than_a_connection_id_is_refused() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), psk());
        for sealed in [&b""[..], b"\x00\x00\x00\x01", b"seven b"] {
            let msg = noise::Initiator::new(&s, r.public(), &psk(), PROLOGUE)
                .write_initiation(sealed)
                .unwrap();
            let body = [&7u64.to_be_bytes()[..], &msg].concat();
            let (pkt, _) = forge::stamp(&r.id(), Version::V3, &body, None);
            assert!(matches!(
                responder.read_initiation(&pkt),
                Err(CryptoError::Malformed)
            ));
        }
    }

    /// A version 4 initiation takes as many fragments as its length needs,
    /// up to four, each of them within a control datagram; the receiver
    /// puts every count together; and one too long for four is refused.
    #[test]
    fn every_fragment_fits_a_datagram_up_to_four() {
        use crate::protocol::constants::MAX_CONTROL_DATAGRAM;
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), psk());
        // What four fragments can carry of the payload, the sealed
        // connection id taken out.
        let most = MAX_FRAGMENTS * FRAGMENT_CHUNK - noise::HFS_INITIATION_LEN - CID_LEN;
        let mut counts = std::collections::BTreeSet::new();
        for len in (0..=most).step_by(97).chain([most]) {
            let payload = vec![0x5a; len];
            let mut init = Initiator::new_v4(&s, &r.id(), &psk()).unwrap();
            let frags = init.initiation_datagrams(&payload, None).unwrap();
            counts.insert(frags.len());
            assert!(frags.len() <= MAX_FRAGMENTS);
            let mut table = Fragments::default();
            let mut whole = None;
            for f in &frags {
                assert!(f.len() <= MAX_CONTROL_DATAGRAM, "{} bytes of payload", len);
                let fragment = responder.fragment(f).expect("a fragment");
                assert_eq!(fragment.count, frags.len());
                whole = table.add(f, fragment, addr("198.51.100.9:4000"), Instant::now());
                assert_eq!(table.is_empty(), whole.is_some());
            }
            let whole = whole.expect("put together");
            let incoming = responder
                .read_initiation_v4(whole.sender_cid, &whole.msg)
                .unwrap();
            assert_eq!(incoming.payload, payload);
        }
        assert_eq!(counts.into_iter().collect::<Vec<_>>(), [2, 3, 4]);
        let mut init = Initiator::new_v4(&s, &r.id(), &psk()).unwrap();
        assert!(init.initiation_datagrams(&vec![0; most + 1], None).is_err());
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A version 4 handshake: the initiation in fragments that each fit a
    /// control datagram, put together in any order; the answer in one
    /// datagram, no longer than the fragments together; the same keys on
    /// both sides.
    #[test]
    fn a_version_4_handshake_goes_in_fragments_and_agrees() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), psk());
        let mut init = Initiator::new_v4(&s, &r.id(), &psk()).unwrap();
        assert_eq!(init.version(), Version::V4);
        let frags = init.initiation_datagrams(b"hello", None).unwrap();
        assert_eq!(frags.len(), 2);
        for f in &frags {
            assert!(
                f.len() <= crate::protocol::constants::MAX_CONTROL_DATAGRAM,
                "{}",
                f.len()
            );
            assert!(
                !responder.is_initiation(f),
                "a version 3 receiver hears nothing it knows"
            );
        }
        let total: usize = frags.iter().map(Vec::len).sum();
        assert_eq!(total, INITIATION_OVERHEAD_V4 + 5 + 2 * FRAGMENT_OVERHEAD);
        let (from, now) = (addr("198.51.100.7:4000"), Instant::now());
        let mut table = Fragments::default();
        let second = responder.fragment(&frags[1]).unwrap();
        assert!(table.add(&frags[1], second, from, now).is_none());
        // The same fragment again changes nothing.
        assert!(table.add(&frags[1], second, from, now).is_none());
        let first = responder.fragment(&frags[0]).unwrap();
        let whole = table.add(&frags[0], first, from, now).expect("complete");
        assert!(table.is_empty());
        assert_eq!(whole.len, total);
        assert_eq!(whole.sender_cid, init.cid());
        let incoming = responder
            .read_initiation_v4(whole.sender_cid, &whole.msg)
            .unwrap();
        assert_eq!((incoming.version, incoming.sender), (Version::V4, s.id()));
        assert_eq!(incoming.payload, b"hello");
        let (resp, rsplit) = incoming.respond(77, b"ok").unwrap();
        assert_eq!(resp.len(), RESPONSE_OVERHEAD_V4 + 2);
        assert!(resp.len() <= crate::protocol::constants::MAX_CONTROL_DATAGRAM);
        assert!(resp.len() <= whole.len, "no more back than came in");
        let (rcid, payload, isplit) = init.read_response(&resp).unwrap();
        assert_eq!((rcid, payload.as_slice()), (77, &b"ok"[..]));
        assert_eq!(
            *isplit.initiator_to_responder,
            *rsplit.initiator_to_responder
        );
        assert_eq!(
            *isplit.responder_to_initiator,
            *rsplit.responder_to_initiator
        );

        // A version 3 initiation is not a fragment.
        let mut old = Initiator::new(&s, &r.id(), &psk()).unwrap();
        let v3 = old.initiation(b"hello", None).unwrap();
        assert!(responder.fragment(&v3).is_none());
        let mut fresh = Initiator::new(&s, &r.id(), &psk()).unwrap();
        assert_eq!(fresh.initiation_datagrams(b"x", None).unwrap().len(), 1);
    }

    /// A fragment altered anywhere is not ours (its mac1 fails); one whose
    /// mac1 the alterer made anew — anyone who knows our ID can — is put
    /// together and then fails in Noise. Fragments that disagree on their
    /// count are not put together.
    #[test]
    fn altered_fragments_come_to_nothing() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), psk());
        let mut init = Initiator::new_v4(&s, &r.id(), &psk()).unwrap();
        let frags = init.initiation_datagrams(b"hello", None).unwrap();
        for i in (0..frags[0].len()).step_by(41) {
            let mut bad = frags[0].clone();
            bad[i] ^= 0x04;
            assert!(responder.fragment(&bad).is_none(), "byte {}", i);
        }
        let (from, now) = (addr("198.51.100.7:4000"), Instant::now());
        let mut rewritten = frags[0].clone();
        rewritten[40] ^= 0x04;
        let end = rewritten.len() - 2 * MAC_LEN;
        let m1 = mac(&mac1_key_v4(r.public()), &rewritten[..end]);
        rewritten[end..end + MAC_LEN].copy_from_slice(&m1);
        let mut table = Fragments::default();
        let f = responder.fragment(&rewritten).unwrap();
        assert!(table.add(&rewritten, f, from, now).is_none());
        let f = responder.fragment(&frags[1]).unwrap();
        let whole = table.add(&frags[1], f, from, now).unwrap();
        assert!(responder
            .read_initiation_v4(whole.sender_cid, &whole.msg)
            .is_err());

        // A count that is not the other fragment's.
        let mut table = Fragments::default();
        let f = responder.fragment(&frags[0]).unwrap();
        assert!(table.add(&frags[0], f, from, now).is_none());
        let odd = Fragment {
            count: 3,
            ..responder.fragment(&frags[1]).unwrap()
        };
        assert!(table.add(&frags[1], odd, from, now).is_none());
    }

    /// What fragments may make a receiver hold is bounded: a few
    /// initiations per client, the table as a whole, and a while each.
    #[test]
    fn fragments_waiting_are_bounded() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), psk());
        let now = Instant::now();
        let mut table = Fragments::default();
        let first_of = |init: &mut Initiator| {
            let frags = init.initiation_datagrams(b"x", None).unwrap();
            let f = responder.fragment(&frags[0]).unwrap();
            (frags[0].clone(), f)
        };
        // One client, from ports of its own: no more than its share.
        for port in 0..20u16 {
            let mut init = Initiator::new_v4(&s, &r.id(), &psk()).unwrap();
            let (pkt, f) = first_of(&mut init);
            table.add(&pkt, f, addr(&format!("198.51.100.7:{}", 4000 + port)), now);
        }
        assert_eq!(table.len(), Fragments::PER_CLIENT);
        // An IPv6 /64 is one client too.
        for host in 1..20u16 {
            let mut init = Initiator::new_v4(&s, &r.id(), &psk()).unwrap();
            let (pkt, f) = first_of(&mut init);
            table.add(
                &pkt,
                f,
                addr(&format!("[2001:db8:1:2::{:x}]:4000", host)),
                now,
            );
        }
        assert_eq!(table.len(), 2 * Fragments::PER_CLIENT);
        // Many clients: the table stays at its size.
        for i in 0..(Fragments::CAPACITY + 100) {
            let mut init = Initiator::new_v4(&s, &r.id(), &psk()).unwrap();
            let (pkt, f) = first_of(&mut init);
            let a = addr(&format!("10.{}.{}.1:4000", i / 256, i % 256));
            table.add(&pkt, f, a, now);
        }
        assert_eq!(table.len(), Fragments::CAPACITY);
        // And nothing waits longer than it may.
        let mut init = Initiator::new_v4(&s, &r.id(), &psk()).unwrap();
        let (pkt, f) = first_of(&mut init);
        table.add(&pkt, f, addr("192.0.2.1:1"), now + Fragments::PATIENCE);
        assert_eq!(table.len(), 1);
    }

    /// Under load every fragment needs a mac2, and a cookie reply to any
    /// fragment gives the cookie that makes them.
    #[test]
    fn a_cookie_proves_the_address_of_every_fragment() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), psk());
        let mut jar = CookieJar::new(&r.id());
        let (from, now) = (addr("203.0.113.9:5000"), Instant::now());
        let mut init = Initiator::new_v4(&s, &r.id(), &psk()).unwrap();
        let frags = init.initiation_datagrams(b"x", None).unwrap();
        assert!(frags.iter().all(|f| !jar.mac2_ok(f, from, now)));
        let reply = jar.reply(&frags[1], from, now).unwrap();
        assert!(reply.len() <= frags[1].len());
        let cookie = init
            .read_cookie_reply(&reply)
            .expect("a reply to one of ours");
        let again = init.initiation_datagrams(b"x", Some(&cookie));
        // One message 1 per attempt: the retry is a new attempt.
        assert!(again.is_err());
        let mut retry = Initiator::new_v4(&s, &r.id(), &psk()).unwrap();
        let frags = retry.initiation_datagrams(b"x", Some(&cookie)).unwrap();
        assert!(frags.iter().all(|f| jar.mac2_ok(f, from, now)));
        assert!(frags
            .iter()
            .all(|f| !jar.mac2_ok(f, addr("203.0.113.9:5001"), now)));
        assert!(frags.iter().all(|f| responder.fragment(f).is_some()));
    }
}

/// Initiation timestamps asked for on two threads at once, with the floor
/// raised on a third: in every interleaving loom makes, each is new, each
/// thread's rise, and the newest is above all of them and the floor
/// (`scripts/loom.sh`).
#[cfg(all(test, sharp_loom))]
mod loom_models {
    use super::{AtomicU64, Clock};
    use loom::sync::Arc;

    #[test]
    fn loom_timestamps_are_unique_and_rise() {
        loom::model(|| {
            let clock = Arc::new(Clock {
                last: AtomicU64::new(0),
            });
            let other = {
                let clock = clock.clone();
                loom::thread::spawn(move || [clock.next(100), clock.next(100)])
            };
            let floor = {
                let clock = clock.clone();
                loom::thread::spawn(move || clock.raise(500))
            };
            let mine = [clock.next(50), clock.next(1000)];
            let theirs = other.join().unwrap();
            floor.join().unwrap();
            assert!(mine[0] < mine[1] && theirs[0] < theirs[1]);
            let mut all = [mine[0], mine[1], theirs[0], theirs[1]];
            all.sort_unstable();
            assert!(all.windows(2).all(|w| w[0] < w[1]), "{:?}", all);
            assert_eq!(clock.last(), all[3].max(500));
        });
    }
}
