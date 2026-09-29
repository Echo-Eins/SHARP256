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
use crate::crypto::transport::CID_LEN;
use crate::crypto::{derive_secret, keyed_mac, CryptoError};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const NOISE_PARAMS: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// Bound into the handshake transcript: a peer speaking another version of
/// the protocol cannot complete a handshake by accident.
pub const PROLOGUE: &[u8] = b"SHARP-256 v3";
pub const MAC_LEN: usize = 16;
const E_LEN: usize = 32;
const S_LEN: usize = 32 + 16;
const AEAD_TAG: usize = 16;
/// Initiation size without payload. The sender's connection id is in it
/// twice: in the clear, where the receiver's dispatcher can see it, and
/// sealed at the start of the Noise payload, where nobody can change it.
pub const INITIATION_OVERHEAD: usize = 2 * CID_LEN + E_LEN + S_LEN + AEAD_TAG + 2 * MAC_LEN;
/// Response size without payload; both connection ids in the clear, and the
/// receiver's sealed again inside, for the same reason.
pub const RESPONSE_OVERHEAD: usize = 3 * CID_LEN + E_LEN + AEAD_TAG + 2 * MAC_LEN;
pub const COOKIE_REPLY_LEN: usize = CID_LEN + 24 + 16 + AEAD_TAG;
/// How long a cookie secret is used before it is replaced.
pub const COOKIE_LIFETIME: Duration = Duration::from_secs(120);

/// Transport secrets agreed by a handshake.
pub struct Split {
    pub initiator_to_responder: [u8; 32],
    pub responder_to_initiator: [u8; 32],
    /// Handshake transcript hash; binds the derived keys to the transcript.
    pub hash: [u8; 32],
}

impl Drop for Split {
    fn drop(&mut self) {
        self.initiator_to_responder.zeroize();
        self.responder_to_initiator.zeroize();
    }
}

fn params() -> snow::params::NoiseParams {
    NOISE_PARAMS.parse().expect("valid Noise parameters")
}

fn mac1_key(public: &[u8; KEY_LEN]) -> [u8; 32] {
    blake3::derive_key("sharp256 v3 mac1", public)
}

fn cookie_key(public: &[u8; KEY_LEN]) -> [u8; 32] {
    blake3::derive_key("sharp256 v3 cookie", public)
}

fn mac2_key(cookie: &[u8; MAC_LEN]) -> Zeroizing<[u8; 32]> {
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

fn split_of(state: &mut snow::HandshakeState) -> Split {
    let (a, b) = state.dangerously_get_raw_split();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&state.get_handshake_hash()[..32]);
    Split {
        initiator_to_responder: a,
        responder_to_initiator: b,
        hash,
    }
}

/// The newest initiation timestamp handed out by this process.
static LAST_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

/// Strictly increasing wall-clock timestamp (nanoseconds since the Unix
/// epoch) carried in initiations: a receiver accepts an initiation from a
/// given sender only if its timestamp exceeds the last one it saw, so
/// recorded initiations cannot be replayed.
pub fn initiation_timestamp() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut prev = LAST_TIMESTAMP.load(Ordering::Relaxed);
    loop {
        let next = now.max(prev + 1);
        match LAST_TIMESTAMP.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return next,
            Err(p) => prev = p,
        }
    }
}

/// The newest timestamp [`initiation_timestamp`] has handed out, for saving
/// across restarts.
pub fn last_initiation_timestamp() -> u64 {
    LAST_TIMESTAMP.load(Ordering::Relaxed)
}

/// Never hand out a timestamp at or below `floor` — the newest one a
/// previous run used. A receiver refuses an initiation that is not newer
/// than the last it took from us, silently, as it must refuse replays; so a
/// sender whose clock was set back since then would otherwise be refused
/// without a word until the clock caught up again.
pub fn raise_initiation_timestamp_floor(floor: u64) {
    LAST_TIMESTAMP.fetch_max(floor, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Initiator (sender)
// ---------------------------------------------------------------------------

/// One handshake attempt of a sender. Every retry is a new attempt with a
/// new ephemeral key and connection id.
pub struct Initiator {
    state: snow::HandshakeState,
    cid: u64,
    receiver_mac1_key: [u8; 32],
    receiver_cookie_key: [u8; 32],
    own_mac1_key: [u8; 32],
    last_mac1: [u8; MAC_LEN],
}

impl Initiator {
    pub fn new(
        identity: &Identity,
        receiver: &SharpId,
        psk: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        // Every exchange with such a key comes out the same whatever the
        // secrets, so the handshake would authenticate nobody. Parsing an ID
        // already refuses one; this is for callers that built it by hand.
        if receiver.is_low_order() {
            return Err(CryptoError::Handshake("receiver key is not usable".into()));
        }
        let state = snow::Builder::new(params())
            .local_private_key(identity.secret())
            .remote_public_key(receiver.as_bytes())
            .psk(2, psk)
            .prologue(PROLOGUE)
            .build_initiator()?;
        Ok(Self {
            state,
            cid: random_cid(),
            receiver_mac1_key: mac1_key(receiver.as_bytes()),
            receiver_cookie_key: cookie_key(receiver.as_bytes()),
            own_mac1_key: mac1_key(identity.public()),
            last_mac1: [0; MAC_LEN],
        })
    }

    /// The sender's connection id for this attempt: responses and transport
    /// packets from the receiver are addressed to it.
    pub fn cid(&self) -> u64 {
        self.cid
    }

    /// Whether an answer has been read into this attempt, so that it can
    /// take no other.
    pub fn is_spent(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Builds the initiation datagram. `cookie` is the latest cookie received
    /// from this receiver, if any.
    pub fn initiation(
        &mut self,
        payload: &[u8],
        cookie: Option<&[u8; MAC_LEN]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0u8; INITIATION_OVERHEAD + payload.len()];
        out[..CID_LEN].copy_from_slice(&self.cid.to_be_bytes());
        let sealed = [&self.cid.to_be_bytes()[..], payload].concat();
        let n = self.state.write_message(&sealed, &mut out[CID_LEN..])?;
        let end = CID_LEN + n;
        out.truncate(end + 2 * MAC_LEN);
        self.last_mac1 = mac(&self.receiver_mac1_key, &out[..end]);
        out[end..end + MAC_LEN].copy_from_slice(&self.last_mac1);
        if let Some(cookie) = cookie {
            let m2: [u8; MAC_LEN] = keyed_mac(&mac2_key(cookie), &[&out[..end + MAC_LEN]]);
            out[end + MAC_LEN..].copy_from_slice(&m2);
        }
        Ok(out)
    }

    /// Decrypts a cookie reply to this attempt's latest initiation.
    pub fn read_cookie_reply(&self, pkt: &[u8]) -> Option<[u8; MAC_LEN]> {
        if pkt.len() != COOKIE_REPLY_LEN || pkt[..CID_LEN] != self.cid.to_be_bytes() {
            return None;
        }
        let nonce = &pkt[CID_LEN..CID_LEN + 24];
        let mut cookie = [0u8; MAC_LEN];
        cookie.copy_from_slice(&pkt[CID_LEN + 24..CID_LEN + 40]);
        let tag = &pkt[CID_LEN + 40..];
        XChaCha20Poly1305::new((&self.receiver_cookie_key).into())
            .decrypt_in_place_detached(nonce.into(), &self.last_mac1, &mut cookie, tag.into())
            .ok()?;
        Some(cookie)
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
        if self.state.is_handshake_finished() {
            return Err(CryptoError::Malformed);
        }
        let n = pkt.len();
        if n < RESPONSE_OVERHEAD || pkt[..CID_LEN] != self.cid.to_be_bytes() {
            return Err(CryptoError::Malformed);
        }
        let body_end = n - 2 * MAC_LEN;
        if !ct_eq(
            &mac(&self.own_mac1_key, &pkt[..body_end]),
            &pkt[body_end..body_end + MAC_LEN],
        ) {
            return Err(CryptoError::Mac);
        }
        let mut payload = vec![0u8; n];
        let len = self
            .state
            .read_message(&pkt[2 * CID_LEN..body_end], &mut payload)?;
        payload.truncate(len);
        // The receiver's connection id is taken from inside, where it is
        // sealed, never from the clear copy: that one is covered only by a
        // mac1 anyone who knows our public key can make, so a copy of the
        // answer could be raced ahead of it with the id changed, and the
        // whole session would then be addressed to a connection the
        // receiver does not have. Refusing such a copy is not an option —
        // reading it has already finished the handshake — but it no
        // longer matters what the clear copy says.
        if len < CID_LEN || !self.state.is_handshake_finished() {
            return Err(CryptoError::Malformed);
        }
        let responder_cid = u64::from_be_bytes(payload[..CID_LEN].try_into().unwrap());
        payload.drain(..CID_LEN);
        if responder_cid == 0 {
            return Err(CryptoError::Malformed);
        }
        let split = split_of(&mut self.state);
        Ok((responder_cid, payload, split))
    }
}

// ---------------------------------------------------------------------------
// Responder (receiver)
// ---------------------------------------------------------------------------

/// Receiver side of handshakes: checks MACs, reads initiations.
pub struct Responder {
    identity: Identity,
    psk: Zeroizing<[u8; 32]>,
    mac1_key: [u8; 32],
}

/// An authenticated initiation waiting for the receiver's answer.
pub struct Incoming {
    state: snow::HandshakeState,
    pub sender_cid: u64,
    pub sender: SharpId,
    pub payload: Vec<u8>,
}

impl Responder {
    pub fn new(identity: Identity, psk: [u8; 32]) -> Self {
        let mac1_key = mac1_key(identity.public());
        Self {
            identity,
            psk: Zeroizing::new(psk),
            mac1_key,
        }
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
        let mut state = snow::Builder::new(params())
            .local_private_key(self.identity.secret())
            .psk(2, &self.psk[..])
            .prologue(PROLOGUE)
            .build_responder()?;
        let sender_cid = u64::from_be_bytes(pkt[..CID_LEN].try_into().unwrap());
        if sender_cid == 0 {
            return Err(CryptoError::Malformed);
        }
        let mut payload = vec![0u8; n];
        let len = state.read_message(&pkt[CID_LEN..n - 2 * MAC_LEN], &mut payload)?;
        payload.truncate(len);
        // The connection id in the clear is covered by nothing but mac1,
        // whose key anyone can work out from our public key, so a copy of
        // an initiation could arrive with it changed — and the answer would
        // then go to a connection the sender does not have. The sealed copy
        // is the sender's; a packet where the two differ was altered on the
        // way, and is refused before it counts for anything.
        if len < CID_LEN || payload[..CID_LEN] != pkt[..CID_LEN] {
            return Err(CryptoError::Malformed);
        }
        payload.drain(..CID_LEN);
        let sender = state
            .get_remote_static()
            .and_then(|s| <[u8; KEY_LEN]>::try_from(s).ok())
            .map(SharpId::from_public)
            .ok_or(CryptoError::Malformed)?;
        // A static key with no private half. Anyone could present it, so it
        // identifies nobody — and a sender limit keyed on identities would
        // count everyone presenting it as one stranger.
        if sender.is_low_order() {
            return Err(CryptoError::Malformed);
        }
        Ok(Incoming {
            state,
            sender_cid,
            sender,
            payload,
        })
    }
}

impl Incoming {
    /// Writes the response and completes the handshake.
    pub fn respond(
        mut self,
        receiver_cid: u64,
        payload: &[u8],
    ) -> Result<(Vec<u8>, Split), CryptoError> {
        let mut out = vec![0u8; RESPONSE_OVERHEAD + payload.len()];
        out[..CID_LEN].copy_from_slice(&self.sender_cid.to_be_bytes());
        out[CID_LEN..2 * CID_LEN].copy_from_slice(&receiver_cid.to_be_bytes());
        let sealed = [&receiver_cid.to_be_bytes()[..], payload].concat();
        let n = self.state.write_message(&sealed, &mut out[2 * CID_LEN..])?;
        let end = 2 * CID_LEN + n;
        out.truncate(end + 2 * MAC_LEN);
        let m1 = mac(&mac1_key(self.sender.as_bytes()), &out[..end]);
        out[end..end + MAC_LEN].copy_from_slice(&m1);
        if !self.state.is_handshake_finished() {
            return Err(CryptoError::Malformed);
        }
        let split = split_of(&mut self.state);
        Ok((out, split))
    }
}

// ---------------------------------------------------------------------------
// Cookies (denial-of-service protection)
// ---------------------------------------------------------------------------

/// Receiver-side cookie state: verifies mac2 and issues cookie replies.
pub struct CookieJar {
    reply_key: [u8; 32],
    secrets: [Zeroizing<[u8; 32]>; 2],
    born: Instant,
}

impl CookieJar {
    pub fn new(own: &SharpId) -> Self {
        Self {
            reply_key: cookie_key(own.as_bytes()),
            secrets: [random_key(), random_key()],
            born: Instant::now(),
        }
    }

    fn rotate(&mut self, now: Instant) {
        if now.saturating_duration_since(self.born) >= COOKIE_LIFETIME {
            self.secrets.swap(0, 1);
            self.secrets[0] = random_key();
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
            let cookie = Self::cookie(s, from);
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
        let mut cookie = Self::cookie(&self.secrets[0], from);
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

fn random_key() -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *k);
    k
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

    const PSK: [u8; 32] = [7; 32];

    fn pair() -> (Identity, Identity) {
        (Identity::generate(), Identity::generate())
    }

    #[test]
    fn handshake_agrees_on_keys_and_authenticates_both() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), PSK);
        let mut init = Initiator::new(&s, &r.id(), &PSK).unwrap();
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
        let responder = Responder::new(r.clone(), PSK);
        // Sender that does not know the receiver's ID: mac1 fails, silence.
        let wrong = Identity::generate();
        let mut init = Initiator::new(&s, &wrong.id(), &PSK).unwrap();
        let pkt = init.initiation(b"x", None).unwrap();
        assert!(!responder.is_initiation(&pkt));
        // Right ID, but any modified byte breaks mac1 or the handshake.
        let mut init = Initiator::new(&s, &r.id(), &PSK).unwrap();
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
            assert!(Initiator::new(&s, &id, &PSK).is_err());
        }
    }

    #[test]
    fn different_psk_fails_at_the_response() {
        let (s, r) = pair();
        let responder = Responder::new(r.clone(), [9; 32]);
        let mut init = Initiator::new(&s, &r.id(), &PSK).unwrap();
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
        let responder = Responder::new(r.clone(), PSK);
        let mut init = Initiator::new(&s, &r.id(), &PSK).unwrap();
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
        let responder = Responder::new(r.clone(), PSK);
        let mut init = Initiator::new(&s, &r.id(), &PSK).unwrap();
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
        let responder = Responder::new(r.clone(), PSK);
        let mut first = Initiator::new(&s, &r.id(), &PSK).unwrap();
        let pkt1 = first.initiation(b"1", None).unwrap();
        let mut second = Initiator::new(&s, &r.id(), &PSK).unwrap();
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
        let mut init = Initiator::new(&s, &r.id(), &PSK).unwrap();
        let pkt = init.initiation(b"p", None).unwrap();
        assert!(!jar.mac2_ok(&pkt, from, now));
        let reply = jar.reply(&pkt, from, now).unwrap();
        assert_eq!(reply.len(), COOKIE_REPLY_LEN);
        let cookie = init.read_cookie_reply(&reply).unwrap();
        // The retried attempt carries mac2 with the cookie.
        let mut retry = Initiator::new(&s, &r.id(), &PSK).unwrap();
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
}
