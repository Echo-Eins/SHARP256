//! Protection of transport packets.
//!
//! ```text
//!  0        8      9               17                     n-16      n
//!  +--------+------+----------------+----------------------+---------+
//!  |  dcid  | type | packet number  |  encrypted frame body |   tag   |
//!  +--------+------+----------------+----------------------+---------+
//!             \_______ masked ______/
//! ```
//!
//! * `dcid` — connection id chosen by the packet's recipient; random, sent in
//!   the clear so the recipient can find the session;
//! * `type` and `packet number` are masked with a mask computed from the tag
//!   (header protection as in QUIC), so an observer sees neither the kind of
//!   message nor packet counts, retransmissions or reordering;
//! * the body is encrypted with an AEAD whose associated data is the
//!   unmasked 17-byte header and whose nonce is `iv XOR packet number`.
//!
//! Every direction has its own secret. The AEAD key is derived per *epoch*
//! of 2^22 packets from that secret, so no key is ever used for more packets
//! than AES-GCM's confidentiality bound allows, without any key-update
//! signalling: both sides compute the key from the packet number.

use crate::crypto::secret::Locked;
use crate::crypto::{derive_secret, CryptoError};
use aes::cipher::BlockEncrypt;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};
use zeroize::Zeroize;

/// Connection id length.
pub const CID_LEN: usize = 8;
/// Clear connection id + masked type byte + masked packet number.
pub const HEADER_LEN: usize = CID_LEN + 1 + 8;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
/// Bytes a transport packet adds around its frame body.
pub const OVERHEAD: usize = HEADER_LEN + TAG_LEN;
/// Packets per AEAD key (2^22, well inside AES-GCM's usage limits).
pub const EPOCH_BITS: u32 = 22;

/// AEAD algorithm of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Suite {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
}

impl Suite {
    pub const ALL_BITS: u8 = 0b11;

    pub fn bit(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Suite::Aes256Gcm),
            2 => Some(Suite::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Suite::Aes256Gcm => "AES-256-GCM",
            Suite::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }

    /// Whether this machine has AES instructions (AES-GCM is then the
    /// faster choice; without them ChaCha20-Poly1305 is).
    pub fn hardware_aes() -> bool {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            std::arch::is_x86_feature_detected!("aes")
                && std::arch::is_x86_feature_detected!("pclmulqdq")
        }
        #[cfg(target_arch = "aarch64")]
        {
            std::arch::is_aarch64_feature_detected!("aes")
                && std::arch::is_aarch64_feature_detected!("pmull")
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
        {
            false
        }
    }

    /// Picks the suite for a session: AES-256-GCM when both sides accelerate
    /// it, ChaCha20-Poly1305 otherwise; `None` if nothing is shared.
    pub fn choose(offered: u8, peer_hw_aes: bool) -> Option<Suite> {
        let aes = offered & Suite::Aes256Gcm.bit() != 0;
        let chacha = offered & Suite::ChaCha20Poly1305.bit() != 0;
        match (aes, chacha) {
            (true, true) if peer_hw_aes && Suite::hardware_aes() => Some(Suite::Aes256Gcm),
            (_, true) => Some(Suite::ChaCha20Poly1305),
            (true, false) => Some(Suite::Aes256Gcm),
            (false, false) => None,
        }
    }
}

/// The AEAD of one epoch, or none. It wipes itself when dropped (its
/// crates' `zeroize` features), so wiping it is dropping it where it lies.
/// Kept inline, not boxed: it is inside a locked page, and a box would put
/// the key schedule on an ordinary one.
#[derive(Default)]
#[allow(clippy::large_enum_variant)]
enum Aead {
    #[default]
    None,
    Aes(aes_gcm::Aes256Gcm),
    ChaCha(chacha20poly1305::ChaCha20Poly1305),
}

impl Aead {
    fn new(suite: Suite, key: &[u8; 32]) -> Self {
        match suite {
            Suite::Aes256Gcm => Aead::Aes(aes_gcm::Aes256Gcm::new(key.into())),
            Suite::ChaCha20Poly1305 => {
                Aead::ChaCha(chacha20poly1305::ChaCha20Poly1305::new(key.into()))
            }
        }
    }

    fn seal(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; TAG_LEN], CryptoError> {
        let tag = match self {
            Aead::Aes(c) => c.encrypt_in_place_detached(nonce.into(), aad, body),
            Aead::ChaCha(c) => c.encrypt_in_place_detached(nonce.into(), aad, body),
            Aead::None => return Err(CryptoError::Seal),
        }
        .map_err(|_| CryptoError::Seal)?;
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        match self {
            Aead::Aes(c) => c.decrypt_in_place_detached(nonce.into(), aad, body, tag.into()),
            Aead::ChaCha(c) => c.decrypt_in_place_detached(nonce.into(), aad, body, tag.into()),
            Aead::None => return Err(CryptoError::Open),
        }
        .map_err(|_| CryptoError::Open)
    }
}

impl Zeroize for Aead {
    fn zeroize(&mut self) {
        *self = Aead::None;
    }
}

/// The header protection key; inline for the same reason as [`Aead`].
#[derive(Default)]
#[allow(clippy::large_enum_variant)]
enum HeaderKey {
    #[default]
    None,
    Aes(aes::Aes256),
    ChaCha([u8; 32]),
}

impl HeaderKey {
    #[cfg(test)]
    fn new(suite: Suite, key: &[u8; 32]) -> Self {
        let mut hp = HeaderKey::None;
        hp.set(suite, key);
        hp
    }

    fn set(&mut self, suite: Suite, key: &[u8; 32]) {
        *self = match suite {
            Suite::Aes256Gcm => HeaderKey::Aes(aes::Aes256::new(key.into())),
            Suite::ChaCha20Poly1305 => HeaderKey::ChaCha(*key),
        };
    }

    /// Mask for the 9 protected header bytes, computed from a 16-byte sample
    /// of the packet (its tag): AES-ECB of the sample, or the ChaCha20
    /// keystream with counter and nonce taken from the sample (as in QUIC).
    fn mask(&self, sample: &[u8; 16]) -> [u8; 16] {
        match self {
            HeaderKey::Aes(c) => {
                let mut block = (*sample).into();
                c.encrypt_block(&mut block);
                block.into()
            }
            HeaderKey::ChaCha(key) => {
                use chacha20::cipher::{
                    consts::U10, KeyIvInit, StreamCipherCore, StreamCipherSeekCore,
                };
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&sample[4..16]);
                // One keystream block, at whatever counter the sample names
                // — u32::MAX included. The stream-cipher interface refuses
                // that last block (it counts the blocks left *after* the
                // position) and refusing panics, so a packet whose tag began
                // with ff ff ff ff took the endpoint down before its tag was
                // even checked; and one of our own came out that way once
                // in 2^32 packets. Found by fuzzing. (The core wipes its
                // state when dropped.)
                let mut core = chacha20::ChaChaCore::<U10>::new(key.into(), (&nonce).into());
                core.set_block_pos(counter);
                let mut block = Default::default();
                core.write_keystream_block(&mut block);
                let mut mask = [0u8; 16];
                mask.copy_from_slice(&block[..16]);
                block.zeroize();
                mask
            }
            HeaderKey::None => [0; 16],
        }
    }
}

impl Zeroize for HeaderKey {
    fn zeroize(&mut self) {
        if let HeaderKey::ChaCha(key) = self {
            key.zeroize();
        }
        *self = HeaderKey::None;
    }
}

/// The key of one epoch: which epoch, and its AEAD.
#[derive(Default)]
struct Slot {
    epoch: u64,
    aead: Aead,
}

/// Epochs whose keys are kept at a time: the newest one that has carried an
/// authentic packet, the one after it (so that the first packet of a new
/// epoch finds its key ready), and the one before it (for packets reordered
/// across the boundary).
const SLOTS: usize = 3;

/// How many epochs beyond the kept ones a packet may be from and still be
/// tried, with a key made for it alone (and kept only if it authenticates).
/// A sender never has more packets unacknowledged than its window holds —
/// at most 256 MiB, 2^19 packets of the smallest size — while an epoch is
/// 2^22 packets, so an authentic packet is always within an epoch or two;
/// this is a margin, not a limit anything reaches. A forged packet cannot
/// choose its epoch (the packet number is masked with a function of the
/// tag it does not know), so almost none land here; one made from a real
/// packet by flipping bits of its masked header can, and costs one key
/// derivation, about what checking its tag costs anyway.
const AHEAD: u64 = 16;

/// What one direction keeps, all of it in locked memory: the traffic
/// secret, the IV, the header protection key and the AEADs of the epochs
/// in use.
#[derive(Default)]
struct Secrets {
    secret: [u8; 32],
    iv: [u8; 12],
    hp: HeaderKey,
    slots: parking_lot::RwLock<[Slot; SLOTS]>,
}

impl Zeroize for Secrets {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        self.iv.zeroize();
        self.hp.zeroize();
        for slot in self.slots.get_mut().iter_mut() {
            slot.epoch = 0;
            slot.aead.zeroize();
        }
    }
}

/// Keys of one direction of a session.
///
/// Keys are derived for an epoch only once a packet of the epoch before it
/// has authenticated (or, when sealing, once our own packet numbers reach
/// it). The epoch of a packet comes from its packet number, which a packet
/// that has not yet authenticated only claims; deriving a key for whatever
/// epoch a forgery named made every forged packet cost a key derivation and
/// push the real epoch's key out of a small cache, and made its handling
/// take a time that depended on the header. A packet naming an epoch that
/// is not kept is opened with the newest epoch's key instead — it fails the
/// same way, in the same time, as any other forgery.
pub struct DirectionKeys {
    suite: Suite,
    keys: Locked<Secrets>,
    /// The newest epoch that has carried an authentic packet (opening), or
    /// that our own packets have reached (sealing).
    top: AtomicU64,
}

impl DirectionKeys {
    pub fn new(suite: Suite, secret: &[u8; 32]) -> Self {
        let keys = Locked::with(|k: &mut Secrets| {
            k.secret = *secret;
            let iv = derive_secret("sharp256 v3 aead iv", &[secret]);
            k.iv.copy_from_slice(&iv[..12]);
            k.hp.set(
                suite,
                &derive_secret("sharp256 v3 header protection", &[secret]),
            );
            let slots = k.slots.get_mut();
            for (slot, epoch) in slots.iter_mut().zip(0..) {
                Self::fill(slot, suite, secret, epoch);
            }
        });
        Self {
            suite,
            keys,
            top: AtomicU64::new(0),
        }
    }

    pub fn suite(&self) -> Suite {
        self.suite
    }

    fn fill(slot: &mut Slot, suite: Suite, secret: &[u8; 32], epoch: u64) {
        let key = derive_secret("sharp256 v3 aead key", &[secret, &epoch.to_be_bytes()]);
        slot.epoch = epoch;
        slot.aead = Aead::new(suite, &key);
    }

    /// Moves the kept epochs on to `epoch - 1 ..= epoch + 1`, deriving the
    /// keys not yet there. Called only for an epoch an authentic packet (or
    /// our own packet number) has reached.
    fn advance(&self, epoch: u64) {
        let mut slots = self.keys.slots.write();
        if epoch <= self.top.load(Ordering::Acquire) {
            return;
        }
        let wanted = [epoch.saturating_sub(1), epoch, epoch + 1];
        // Keys still wanted stay where they are; the others' places are
        // refilled with the ones missing.
        let missing: Vec<u64> = wanted
            .iter()
            .copied()
            .filter(|e| {
                !slots
                    .iter()
                    .any(|s| s.epoch == *e && !matches!(s.aead, Aead::None))
            })
            .collect();
        let mut missing = missing.into_iter();
        for slot in slots.iter_mut() {
            if wanted.contains(&slot.epoch) && !matches!(slot.aead, Aead::None) {
                continue;
            }
            match missing.next() {
                Some(e) => Self::fill(slot, self.suite, &self.keys.secret, e),
                None => slot.aead.zeroize(),
            }
        }
        self.top.store(epoch, Ordering::Release);
    }

    fn nonce(&self, pn: u64) -> [u8; 12] {
        let mut n = self.keys.iv;
        for (b, p) in n[4..].iter_mut().zip(pn.to_be_bytes()) {
            *b ^= p;
        }
        n
    }

    /// Seals a packet in place. `buf` holds the unprotected header
    /// ([`HEADER_LEN`] bytes: dcid, type byte, packet number) followed by the
    /// plaintext body; the tag is appended and the header masked.
    pub fn seal(&self, buf: &mut Vec<u8>) -> Result<(), CryptoError> {
        if buf.len() < HEADER_LEN {
            return Err(CryptoError::Malformed);
        }
        buf.extend_from_slice(&[0u8; TAG_LEN]);
        self.seal_in_place(buf)
    }

    /// Seals a packet laid out in `pkt`: the unprotected header, the
    /// plaintext body and [`TAG_LEN`] bytes of room for the tag at the end
    /// (for packets built side by side in one buffer).
    pub fn seal_in_place(&self, pkt: &mut [u8]) -> Result<(), CryptoError> {
        if pkt.len() < OVERHEAD {
            return Err(CryptoError::Malformed);
        }
        let pn = u64::from_be_bytes(pkt[CID_LEN + 1..HEADER_LEN].try_into().unwrap());
        let epoch = pn >> EPOCH_BITS;
        // Our own packet numbers only ever grow within a session.
        if epoch > self.top.load(Ordering::Acquire) {
            self.advance(epoch);
        }
        let nonce = self.nonce(pn);
        let (head, rest) = pkt.split_at_mut(HEADER_LEN);
        let (body, tag_room) = rest.split_at_mut(rest.len() - TAG_LEN);
        let tag = {
            let slots = self.keys.slots.read();
            let slot = slots
                .iter()
                .find(|s| s.epoch == epoch)
                .ok_or(CryptoError::Seal)?;
            slot.aead.seal(&nonce, head, body)?
        };
        tag_room.copy_from_slice(&tag);
        let mask = self.keys.hp.mask(&tag);
        for (b, m) in pkt[CID_LEN..HEADER_LEN].iter_mut().zip(mask) {
            *b ^= m;
        }
        Ok(())
    }

    /// Opens a packet in place and returns its type byte, packet number and
    /// decrypted body. On failure the packet must be discarded.
    pub fn open<'a>(&self, pkt: &'a mut [u8]) -> Result<(u8, u64, &'a mut [u8]), CryptoError> {
        let n = pkt.len();
        if n < OVERHEAD {
            return Err(CryptoError::Malformed);
        }
        let mut sample = [0u8; TAG_LEN];
        sample.copy_from_slice(&pkt[n - TAG_LEN..]);
        let mask = self.keys.hp.mask(&sample);
        for (b, m) in pkt[CID_LEN..HEADER_LEN].iter_mut().zip(mask) {
            *b ^= m;
        }
        let type_byte = pkt[CID_LEN];
        let pn = u64::from_be_bytes(pkt[CID_LEN + 1..HEADER_LEN].try_into().unwrap());
        let epoch = pn >> EPOCH_BITS;
        let nonce = self.nonce(pn);
        let (head, rest) = pkt.split_at_mut(HEADER_LEN);
        let (body, tag) = rest.split_at_mut(rest.len() - TAG_LEN);
        {
            let slots = self.keys.slots.read();
            let top = self.top.load(Ordering::Acquire);
            // The slot to open with: the packet's epoch's if it is kept,
            // the newest one's if not (the packet is then a forgery, or
            // older than any replay window, and fails like any forgery).
            // Chosen without a branch on the epoch, which is the unmasked
            // header of a packet nobody has authenticated yet: an epoch
            // compared with branches took a cycle or so less when it was
            // a kept one, and that showed (`crypto::dudect`).
            let mut chosen = 0u64;
            let mut newest = 0u64;
            let mut kept = Choice::from(0);
            for (k, slot) in (0u64..).zip(slots.iter()) {
                let here = slot.epoch.ct_eq(&epoch);
                chosen.conditional_assign(&k, here);
                newest.conditional_assign(&k, slot.epoch.ct_eq(&top));
                kept |= here;
            }
            let ahead = epoch.ct_gt(&top) & !epoch.ct_gt(&(top + AHEAD));
            // Taken only for an epoch in the look-ahead, which no forgery
            // chooses (see `AHEAD`).
            if bool::from(ahead & !kept) {
                #[cfg(test)]
                tests::LOOKAHEAD_KEYS.with(|n| n.set(n.get() + 1));
                let key = derive_secret(
                    "sharp256 v3 aead key",
                    &[&self.keys.secret, &epoch.to_be_bytes()],
                );
                Locked::new(Aead::new(self.suite, &key)).open(&nonce, head, body, tag)?;
            } else {
                let index = u64::conditional_select(&newest, &chosen, kept);
                slots[index as usize].aead.open(&nonce, head, body, tag)?;
            }
        }
        if epoch > self.top.load(Ordering::Acquire) {
            self.advance(epoch);
        }
        Ok((type_byte, pn, body))
    }
}

/// Both directions of a session.
pub struct SessionKeys {
    pub suite: Suite,
    pub send: DirectionKeys,
    pub recv: DirectionKeys,
}

impl SessionKeys {
    /// Derives the session keys from the handshake's split. The initiator
    /// sends with the first key and the responder with the second.
    pub fn derive(split: &crate::crypto::handshake::Split, initiator: bool, suite: Suite) -> Self {
        let secret = |k: &[u8; 32]| derive_secret("sharp256 v3 traffic secret", &[k, &split.hash]);
        let i2r = secret(&split.initiator_to_responder);
        let r2i = secret(&split.responder_to_initiator);
        let (send, recv) = if initiator { (i2r, r2i) } else { (r2i, i2r) };
        Self {
            suite,
            send: DirectionKeys::new(suite, &send),
            recv: DirectionKeys::new(suite, &recv),
        }
    }
}

/// Starts a transport packet in `buf` (cleared): connection id, type byte
/// and packet number, unprotected. The caller appends the frame body and
/// calls [`DirectionKeys::seal`].
pub fn begin_packet(buf: &mut Vec<u8>, dcid: u64, type_byte: u8, pn: u64) {
    buf.clear();
    push_header(buf, dcid, type_byte, pn);
}

/// Appends an unprotected packet header to `buf` (for packets built side by
/// side; see [`DirectionKeys::seal_in_place`]).
pub fn push_header(buf: &mut Vec<u8>, dcid: u64, type_byte: u8, pn: u64) {
    buf.extend_from_slice(&dcid.to_be_bytes());
    buf.push(type_byte);
    buf.extend_from_slice(&pn.to_be_bytes());
}

/// Connection id at the start of any packet, if the packet is long enough.
pub fn peek_cid(pkt: &[u8]) -> Option<u64> {
    pkt.get(..CID_LEN)
        .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The ChaCha20 header protection of RFC 9001 (appendix A.5): counter
    /// and nonce from the sample, the mask the first bytes of that block.
    #[test]
    fn chacha20_header_mask_matches_rfc9001() {
        let key: [u8; 32] = hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
            .try_into()
            .unwrap();
        let sample: [u8; 16] = hex("5e5cd55c41f69080575d7999c25a5bfb").try_into().unwrap();
        let hp = super::HeaderKey::new(super::Suite::ChaCha20Poly1305, &key);
        assert_eq!(hp.mask(&sample)[..5], hex("aefefe7d03")[..]);
    }

    /// A sample naming the last block of the counter space is a sample like
    /// any other. It used to make the stream cipher refuse, and the refusal
    /// panicked: anybody who could put a packet with such a tag in front of
    /// an endpoint took it down, and so did one of our own packets in 2^32.
    #[test]
    fn a_tag_naming_the_last_block_does_not_take_the_endpoint_down() {
        let key = [0x42u8; 32];
        let hp = super::HeaderKey::new(super::Suite::ChaCha20Poly1305, &key);
        let mut sample = [0x5au8; 16];
        sample[..4].copy_from_slice(&[0xff; 4]);
        let a = hp.mask(&sample);
        assert_eq!(a, hp.mask(&sample), "the mask is a function of the sample");
        sample[0] = 0xfe;
        assert_ne!(a, hp.mask(&sample));
        // And a whole packet with such a tag is simply not authentic.
        let keys = super::DirectionKeys::new(super::Suite::ChaCha20Poly1305, &key);
        let mut pkt = vec![0u8; 64];
        let n = pkt.len();
        pkt[n - 16..n - 12].copy_from_slice(&[0xff; 4]);
        assert!(keys.open(&mut pkt).is_err());
    }

    use super::*;
    use crate::crypto::handshake::Split;

    thread_local! {
        /// Keys made for a single packet ahead of the kept epochs, on this
        /// thread (each test runs on its own).
        pub(super) static LOOKAHEAD_KEYS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Throughput of sealing and opening full-size packets:
    /// `cargo test --release --lib aead_throughput -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn aead_throughput() {
        for suite in [Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
            let keys = DirectionKeys::new(suite, &[7; 32]);
            let n = 200_000u64;
            let mut buf = Vec::with_capacity(1500);
            let started = std::time::Instant::now();
            for pn in 0..n {
                begin_packet(&mut buf, 1, 3, pn);
                buf.resize(1472 - TAG_LEN, 0xAB);
                keys.seal(&mut buf).unwrap();
            }
            let secs = started.elapsed().as_secs_f64();
            let started = std::time::Instant::now();
            let mut pkt = buf.clone();
            for _ in 0..n {
                pkt.copy_from_slice(&buf);
                keys.open(&mut pkt).unwrap();
            }
            let open_secs = started.elapsed().as_secs_f64();
            println!(
                "{}: seal {:.2} Gbit/s ({:.0} ns/packet), open {:.2} Gbit/s ({:.0} ns/packet)",
                suite.name(),
                n as f64 * 1472.0 * 8.0 / secs / 1e9,
                secs * 1e9 / n as f64,
                n as f64 * 1472.0 * 8.0 / open_secs / 1e9,
                open_secs * 1e9 / n as f64
            );
        }
    }

    fn split() -> Split {
        Split {
            initiator_to_responder: zeroize::Zeroizing::new([1; 32]),
            responder_to_initiator: zeroize::Zeroizing::new([2; 32]),
            hash: [3; 32],
        }
    }

    fn roundtrip(suite: Suite) {
        let a = SessionKeys::derive(&split(), true, suite);
        let b = SessionKeys::derive(&split(), false, suite);
        for (pn, len) in [
            (0u64, 0usize),
            (1, 1),
            (77, 1400),
            (1 << 22, 100),
            (u64::MAX >> 1, 33),
        ] {
            let body: Vec<u8> = (0..len).map(|i| i as u8).collect();
            // A receiver follows the epochs authentic packets reach; one
            // that has never seen the epochs in between would refuse a
            // packet this far ahead (see the test after this one).
            let epoch = pn >> EPOCH_BITS;
            if epoch > b.recv.top.load(Ordering::Relaxed) + AHEAD {
                b.recv.advance(epoch);
            }
            let mut buf = Vec::new();
            begin_packet(&mut buf, 0xABCD_EF01_2345_6789, 0x43, pn);
            buf.extend_from_slice(&body);
            a.send.seal(&mut buf).unwrap();
            assert_eq!(buf.len(), OVERHEAD + len);
            assert_eq!(peek_cid(&buf), Some(0xABCD_EF01_2345_6789));
            // The masked header does not reveal the packet number.
            if len > 0 {
                assert_ne!(&buf[CID_LEN + 1..HEADER_LEN], &pn.to_be_bytes());
            }
            let (t, p, plain) = b.recv.open(&mut buf).unwrap();
            assert_eq!((t, p), (0x43, pn));
            assert_eq!(plain, &body[..]);
        }
    }

    #[test]
    fn seal_open_both_suites() {
        roundtrip(Suite::Aes256Gcm);
        roundtrip(Suite::ChaCha20Poly1305);
    }

    /// The epochs a direction keeps keys for, in order.
    fn kept(k: &DirectionKeys) -> Vec<u64> {
        let mut epochs: Vec<u64> = k
            .keys
            .slots
            .read()
            .iter()
            .filter(|s| !matches!(s.aead, Aead::None))
            .map(|s| s.epoch)
            .collect();
        epochs.sort();
        epochs
    }

    fn sealed(k: &DirectionKeys, pn: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        begin_packet(&mut buf, 5, 3, pn);
        buf.extend_from_slice(&pn.to_be_bytes());
        k.seal(&mut buf).unwrap();
        buf
    }

    /// Forged packets make no keys, whatever their headers say: the epochs
    /// kept stay where authentic packets put them, and those still open.
    /// (Each used to cost a key derivation for whatever epoch it named, and
    /// to push the real epoch's key out of a cache of three.)
    #[test]
    fn forged_packets_make_no_keys() {
        use rand::{Rng, RngCore};
        for suite in [Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
            let a = SessionKeys::derive(&split(), true, suite);
            let b = SessionKeys::derive(&split(), false, suite);
            let real = sealed(&a.send, 1000);
            let mut rng = rand::thread_rng();
            // Random ones cannot choose their epoch, so none gets a key of
            // its own either.
            LOOKAHEAD_KEYS.with(|n| n.set(0));
            for _ in 0..20_000 {
                let mut forged = vec![0u8; rng.gen_range(OVERHEAD..200)];
                rng.fill_bytes(&mut forged);
                assert!(b.recv.open(&mut forged).is_err());
            }
            assert_eq!(LOOKAHEAD_KEYS.with(|n| n.get()), 0);
            // A real packet with bits of its masked packet number flipped
            // is the one way to aim at an epoch.
            for byte in CID_LEN + 1..HEADER_LEN {
                for bit in 0..8 {
                    let mut forged = real.clone();
                    forged[byte] ^= 1 << bit;
                    assert!(b.recv.open(&mut forged).is_err());
                }
            }
            // Of those, the ones that turn epoch 0 into 4, 8 or 16 — ahead
            // of the kept epochs 0 to 2, within the look-ahead — got a key
            // for themselves alone; none was kept.
            assert_eq!(LOOKAHEAD_KEYS.with(|n| n.get()), 3);
            assert_eq!(kept(&b.recv), vec![0, 1, 2]);
            assert_eq!(b.recv.top.load(Ordering::Relaxed), 0);
            let mut pkt = real.clone();
            assert_eq!(b.recv.open(&mut pkt).unwrap().1, 1000);
        }
    }

    /// Packets on both sides of epoch boundaries open, reordered too; the
    /// kept epochs follow the newest epoch that has carried an authentic
    /// packet; one well ahead of the kept ones opens with a key made for it
    /// alone, and moves them on; one from before the kept ones, or too far
    /// ahead, is refused.
    #[test]
    fn epochs_move_on_with_authentic_packets_only() {
        let e = 1u64 << EPOCH_BITS;
        let a = SessionKeys::derive(&split(), true, Suite::Aes256Gcm);
        let b = SessionKeys::derive(&split(), false, Suite::Aes256Gcm);
        let pns = [
            e - 2,
            e - 1,
            e,
            e + 1,
            2 * e,
            e + 3,
            2 * e + 5,
            3 * e + 1,
            5 * e,
        ];
        let mut sorted = pns;
        sorted.sort();
        let packets: std::collections::HashMap<u64, Vec<u8>> =
            sorted.iter().map(|&pn| (pn, sealed(&a.send, pn))).collect();
        let open = |pn: u64| {
            let mut pkt = packets[&pn].clone();
            b.recv.open(&mut pkt).map(|(_, p, _)| p)
        };
        for pn in [e - 2, e, e - 1, e + 1, 2 * e] {
            assert_eq!(open(pn), Ok(pn));
        }
        assert_eq!(kept(&b.recv), vec![1, 2, 3]);
        // Reordered from the epoch before: still kept.
        assert_eq!(open(e + 3), Ok(e + 3));
        assert_eq!(open(3 * e + 1), Ok(3 * e + 1));
        assert_eq!(kept(&b.recv), vec![2, 3, 4]);
        // Two epochs ahead of the newest kept one: a key of its own.
        assert_eq!(open(5 * e), Ok(5 * e));
        assert_eq!(kept(&b.recv), vec![4, 5, 6]);
        // Epoch 2 is behind the kept ones now, and older than any replay
        // window: refused.
        assert_eq!(open(2 * e + 5), Err(CryptoError::Open));
        // Beyond the look-ahead: refused, and nothing moves.
        let far = sealed(&a.send, (5 + AHEAD + 2) * e);
        assert!(b.recv.open(&mut far.clone()).is_err());
        assert_eq!(kept(&b.recv), vec![4, 5, 6]);
    }

    #[test]
    fn any_modification_is_rejected() {
        let a = SessionKeys::derive(&split(), true, Suite::ChaCha20Poly1305);
        let b = SessionKeys::derive(&split(), false, Suite::ChaCha20Poly1305);
        let mut pkt = Vec::new();
        begin_packet(&mut pkt, 7, 3, 1234);
        pkt.extend_from_slice(&[9u8; 64]);
        a.send.seal(&mut pkt).unwrap();
        for i in 0..pkt.len() {
            let mut bad = pkt.clone();
            bad[i] ^= 0x10;
            assert!(
                b.recv.open(&mut bad).is_err(),
                "flip at byte {} accepted",
                i
            );
        }
        // Wrong direction / wrong session.
        let mut other = pkt.clone();
        assert!(a.recv.open(&mut other).is_err());
        let c = SessionKeys::derive(
            &Split {
                hash: [4; 32],
                ..split()
            },
            false,
            Suite::ChaCha20Poly1305,
        );
        let mut other = pkt.clone();
        assert!(c.recv.open(&mut other).is_err());
        let mut short = pkt[..OVERHEAD - 1].to_vec();
        assert!(b.recv.open(&mut short).is_err());
    }

    #[test]
    fn suite_choice() {
        assert_eq!(
            Suite::choose(Suite::ALL_BITS, false),
            Some(Suite::ChaCha20Poly1305)
        );
        assert_eq!(
            Suite::choose(Suite::Aes256Gcm.bit(), false),
            Some(Suite::Aes256Gcm)
        );
        assert_eq!(Suite::choose(0, true), None);
        if Suite::hardware_aes() {
            assert_eq!(Suite::choose(Suite::ALL_BITS, true), Some(Suite::Aes256Gcm));
        }
    }
}
