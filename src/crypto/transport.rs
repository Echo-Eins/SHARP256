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

use crate::crypto::{derive_secret, CryptoError};
use aes::cipher::BlockEncrypt;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

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

enum Aead {
    Aes(Box<aes_gcm::Aes256Gcm>),
    ChaCha(Box<chacha20poly1305::ChaCha20Poly1305>),
}

impl Aead {
    fn new(suite: Suite, key: &[u8; 32]) -> Self {
        match suite {
            Suite::Aes256Gcm => Aead::Aes(Box::new(aes_gcm::Aes256Gcm::new(key.into()))),
            Suite::ChaCha20Poly1305 => Aead::ChaCha(Box::new(
                chacha20poly1305::ChaCha20Poly1305::new(key.into()),
            )),
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
        }
        .map_err(|_| CryptoError::Open)
    }
}

enum HeaderKey {
    Aes(Box<aes::Aes256>),
    ChaCha(Zeroizing<[u8; 32]>),
}

impl HeaderKey {
    fn new(suite: Suite, key: &[u8; 32]) -> Self {
        match suite {
            Suite::Aes256Gcm => HeaderKey::Aes(Box::new(aes::Aes256::new(key.into()))),
            Suite::ChaCha20Poly1305 => HeaderKey::ChaCha(Zeroizing::new(*key)),
        }
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
                // in 2^32 packets. Found by fuzzing.
                let mut core = chacha20::ChaChaCore::<U10>::new((&**key).into(), (&nonce).into());
                core.set_block_pos(counter);
                let mut block = Default::default();
                core.write_keystream_block(&mut block);
                let mut mask = [0u8; 16];
                mask.copy_from_slice(&block[..16]);
                mask
            }
        }
    }
}

/// Keys of one direction of a session.
pub struct DirectionKeys {
    suite: Suite,
    secret: Zeroizing<[u8; 32]>,
    iv: [u8; 12],
    hp: HeaderKey,
    /// AEAD instances of recently used epochs.
    epochs: RwLock<Vec<(u64, Arc<Aead>)>>,
}

impl DirectionKeys {
    pub fn new(suite: Suite, secret: &[u8; 32]) -> Self {
        let iv_full = derive_secret("sharp256 v3 aead iv", &[secret]);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_full[..12]);
        let hp_key = derive_secret("sharp256 v3 header protection", &[secret]);
        Self {
            suite,
            secret: Zeroizing::new(*secret),
            iv,
            hp: HeaderKey::new(suite, &hp_key),
            epochs: RwLock::new(Vec::new()),
        }
    }

    pub fn suite(&self) -> Suite {
        self.suite
    }

    fn aead(&self, epoch: u64) -> Arc<Aead> {
        if let Ok(cache) = self.epochs.read() {
            if let Some((_, a)) = cache.iter().find(|(e, _)| *e == epoch) {
                return a.clone();
            }
        }
        let key = derive_secret(
            "sharp256 v3 aead key",
            &[&*self.secret, &epoch.to_be_bytes()],
        );
        let aead = Arc::new(Aead::new(self.suite, &key));
        if let Ok(mut cache) = self.epochs.write() {
            if cache.len() >= 3 {
                cache.remove(0);
            }
            cache.push((epoch, aead.clone()));
        }
        aead
    }

    fn nonce(&self, pn: u64) -> [u8; 12] {
        let mut n = self.iv;
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
        let nonce = self.nonce(pn);
        let aead = self.aead(pn >> EPOCH_BITS);
        let (head, rest) = pkt.split_at_mut(HEADER_LEN);
        let (body, tag_room) = rest.split_at_mut(rest.len() - TAG_LEN);
        let tag = aead.seal(&nonce, head, body)?;
        tag_room.copy_from_slice(&tag);
        let mask = self.hp.mask(&tag);
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
        let mask = self.hp.mask(&sample);
        for (b, m) in pkt[CID_LEN..HEADER_LEN].iter_mut().zip(mask) {
            *b ^= m;
        }
        let type_byte = pkt[CID_LEN];
        let pn = u64::from_be_bytes(pkt[CID_LEN + 1..HEADER_LEN].try_into().unwrap());
        let nonce = self.nonce(pn);
        let aead = self.aead(pn >> EPOCH_BITS);
        let (head, rest) = pkt.split_at_mut(HEADER_LEN);
        let (body, tag) = rest.split_at_mut(rest.len() - TAG_LEN);
        aead.open(&nonce, head, body, tag)?;
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
            initiator_to_responder: [1; 32],
            responder_to_initiator: [2; 32],
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
