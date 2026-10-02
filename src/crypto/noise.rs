//! The Noise handshake of SHARP-256, `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`
//! (The Noise Protocol Framework, revision 34), written out for exactly its
//! two messages:
//!
//! ```text
//! IKpsk2:
//!   <- s
//!   ...
//!   -> e, es, s, ss
//!   <- e, ee, se, psk
//! ```
//!
//! and, for protocol version 4, the same with the tokens of Noise's hybrid
//! forward secrecy (the Noise HFS draft; the IK layout I2P's proposal 169
//! uses), `Noise_IKpsk2+hfs_25519+MLKEM768_ChaChaPoly_BLAKE2s`:
//!
//! ```text
//! IKpsk2+hfs:
//!   <- s
//!   ...
//!   -> e, es, e1, s, ss
//!   <- e, ee, ekem1, se, psk
//! ```
//!
//! `e1` is the initiator's ephemeral ML-KEM-768 encapsulation key
//! (`EncryptAndHash`), `ekem1` the responder's ciphertext to it
//! (`EncryptAndHash`, then `MixKey` of the shared secret): the keys of the
//! session then depend on X25519 and on ML-KEM alike, and traffic recorded
//! today stays unreadable to whoever breaks only one of them later.
//!
//! This was the `snow` crate. No version of snow wipes anything, so every
//! handshake left in freed memory a copy of the long-term private key, the
//! ephemeral key, the pre-shared key and the chaining key the session's keys
//! are derived from. Here each of them, and each intermediate value of the
//! derivations (`blake2s`), is held where it is wiped when it goes. It is
//! also short enough to be read against the specification line by line —
//! the section of it each step implements is named where it is done.
//!
//! Checked by the Noise test vector for this protocol from cacophony (both
//! messages byte for byte, the handshake hash, and the split keys through
//! the four transport messages that follow), and against snow itself, kept
//! for the tests only: the same ephemeral keys must give the same bytes and
//! keys, and each must complete handshakes with the other in both roles.

use crate::crypto::blake2s::{hash, hmac, HASH_LEN};
use crate::crypto::identity::{Identity, KEY_LEN};
use crate::crypto::kem::{self, KemSecret, CT_LEN, EK_LEN};
use crate::crypto::secret::{Locked, SecretKey};
use crate::crypto::CryptoError;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const PROTOCOL_NAME: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// The hybrid handshake's name (version 4).
pub const PROTOCOL_NAME_HFS: &str = "Noise_IKpsk2+hfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";
const TAG_LEN: usize = 16;
/// Bytes message 1 adds to its payload: `e`, the encrypted `s` and the
/// payload's tag.
pub const INITIATION_LEN: usize = KEY_LEN + KEY_LEN + TAG_LEN + TAG_LEN;
/// Bytes message 2 adds to its payload: `e` and the payload's tag.
pub const RESPONSE_LEN: usize = KEY_LEN + TAG_LEN;
/// The same for the hybrid handshake: message 1 carries the encrypted `e1`,
/// message 2 the encrypted `ekem1`.
pub const HFS_INITIATION_LEN: usize = INITIATION_LEN + EK_LEN + TAG_LEN;
pub const HFS_RESPONSE_LEN: usize = RESPONSE_LEN + CT_LEN + TAG_LEN;

/// What a completed handshake leaves: the two transport keys of Noise's
/// `Split()` and the handshake hash, which binds whatever is derived from
/// them to the whole transcript.
pub struct Split {
    pub initiator_to_responder: Zeroizing<[u8; 32]>,
    pub responder_to_initiator: Zeroizing<[u8; 32]>,
    pub hash: [u8; 32],
}

fn failed(what: &str) -> CryptoError {
    CryptoError::Handshake(what.to_string())
}

/// Diffie-Hellman (section 12.1), refusing a public key whose exchange
/// comes out the same for every secret — a small-order point, which has
/// no private half and so authenticates nothing. The private key goes into
/// x25519-dalek's type only for the computation, which wipes it after.
fn dh(secret: &[u8; KEY_LEN], public: &[u8; KEY_LEN]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(failed("a key with no private half"));
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

fn public_of(secret: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// `HKDF(chaining_key, input_key_material, 2)` (section 4.3).
fn hkdf2(ck: &[u8; 32], ikm: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let temp = hmac(ck, &[ikm]);
    let one = hmac(&temp, &[&[1]]);
    let two = hmac(&temp, &[&one[..], &[2]]);
    (one, two)
}

/// `HKDF(chaining_key, input_key_material, 3)` (section 4.3).
#[allow(clippy::type_complexity)]
fn hkdf3(
    ck: &[u8; 32],
    ikm: &[u8],
) -> (
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
) {
    let temp = hmac(ck, &[ikm]);
    let one = hmac(&temp, &[&[1]]);
    let two = hmac(&temp, &[&one[..], &[2]]);
    let three = hmac(&temp, &[&two[..], &[3]]);
    (one, two, three)
}

/// A CipherState (section 5.1): a key, once there is one, and the nonce.
#[derive(Default)]
struct CipherState {
    k: [u8; 32],
    has_key: bool,
    n: u64,
}

impl CipherState {
    fn set(&mut self, k: &[u8; 32]) {
        self.k = *k;
        self.has_key = true;
        self.n = 0;
    }

    /// ChaChaPoly's nonce: 32 zero bits and the counter little-endian
    /// (section 12.3).
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.n.to_le_bytes());
        nonce
    }

    /// `EncryptWithAd`: appends the ciphertext of `plaintext` to `out`.
    fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let start = out.len();
        out.extend_from_slice(plaintext);
        if !self.has_key {
            return Ok(());
        }
        let tag = ChaCha20Poly1305::new((&self.k).into())
            .encrypt_in_place_detached((&self.nonce()).into(), ad, &mut out[start..])
            .map_err(|_| failed("encryption failed"))?;
        out.extend_from_slice(&tag);
        self.n += 1;
        Ok(())
    }

    /// `DecryptWithAd`: appends the plaintext of `ciphertext` to `out`, or
    /// fails and appends nothing.
    fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        if !self.has_key {
            out.extend_from_slice(ciphertext);
            return Ok(());
        }
        let Some(body_len) = ciphertext.len().checked_sub(TAG_LEN) else {
            return Err(failed("message too short"));
        };
        let start = out.len();
        out.extend_from_slice(&ciphertext[..body_len]);
        let opened = ChaCha20Poly1305::new((&self.k).into()).decrypt_in_place_detached(
            (&self.nonce()).into(),
            ad,
            &mut out[start..],
            ciphertext[body_len..].into(),
        );
        if opened.is_err() {
            out.truncate(start);
            return Err(failed("decryption failed"));
        }
        self.n += 1;
        Ok(())
    }
}

impl Zeroize for CipherState {
    fn zeroize(&mut self) {
        self.k.zeroize();
        self.has_key.zeroize();
        self.n.zeroize();
    }
}

/// A SymmetricState (section 5.2). It holds the chaining key, from which
/// every key of the session follows, so it lives in locked memory.
#[derive(Default)]
struct SymmetricState {
    ck: [u8; 32],
    h: [u8; 32],
    cipher: CipherState,
}

impl Zeroize for SymmetricState {
    fn zeroize(&mut self) {
        self.ck.zeroize();
        self.h.zeroize();
        self.cipher.zeroize();
    }
}

impl SymmetricState {
    /// `InitializeSymmetric(protocol_name)`, then the prologue and the
    /// responder's static key, which IK's pre-message makes known to both.
    fn new(name: &str, prologue: &[u8], responder_static: &[u8; KEY_LEN]) -> Locked<Self> {
        Locked::with(|state: &mut Self| {
            // A name longer than a hash is hashed; both are (37 and 52
            // bytes).
            const { assert!(PROTOCOL_NAME.len() > HASH_LEN) };
            const { assert!(PROTOCOL_NAME_HFS.len() > HASH_LEN) };
            debug_assert!(name.len() > HASH_LEN);
            state.h = *hash(&[name.as_bytes()]);
            state.ck = state.h;
            state.mix_hash(prologue);
            state.mix_hash(responder_static);
        })
    }

    /// A copy in locked memory of its own, to work on.
    fn copy(&self) -> Locked<Self> {
        Locked::with(|copy: &mut Self| {
            copy.ck = self.ck;
            copy.h = self.h;
            copy.cipher.k = self.cipher.k;
            copy.cipher.has_key = self.cipher.has_key;
            copy.cipher.n = self.cipher.n;
        })
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf2(&self.ck, ikm);
        self.ck = *ck;
        self.cipher.set(&k);
        #[cfg(test)]
        {
            crate::crypto::secret::keylog::note(&self.ck);
            crate::crypto::secret::keylog::note(&self.cipher.k);
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = *hash(&[&self.h, data]);
    }

    fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let (ck, temp_h, k) = hkdf3(&self.ck, ikm);
        self.ck = *ck;
        self.mix_hash(&temp_h[..]);
        self.cipher.set(&k);
        #[cfg(test)]
        {
            crate::crypto::secret::keylog::note(&self.ck);
            crate::crypto::secret::keylog::note(&self.cipher.k);
        }
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError> {
        let start = out.len();
        let h = self.h;
        self.cipher.encrypt_with_ad(&h, plaintext, out)?;
        self.mix_hash(&out[start..]);
        Ok(())
    }

    fn decrypt_and_hash(
        &mut self,
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let h = self.h;
        self.cipher.decrypt_with_ad(&h, ciphertext, out)?;
        self.mix_hash(ciphertext);
        Ok(())
    }

    /// `Split()`: the initiator sends with the first key, the responder
    /// with the second.
    fn split(&self) -> Split {
        let (first, second) = hkdf2(&self.ck, &[]);
        #[cfg(test)]
        {
            crate::crypto::secret::keylog::note(&first[..]);
            crate::crypto::secret::keylog::note(&second[..]);
        }
        Split {
            initiator_to_responder: first,
            responder_to_initiator: second,
            hash: self.h,
        }
    }
}

/// The `e` token (sections 7.3 and 9.2): the public key goes out and into
/// the hash, and — in a handshake with a PSK — into the key as well.
fn mix_ephemeral(state: &mut SymmetricState, public: &[u8; KEY_LEN]) {
    state.mix_hash(public);
    state.mix_key(public);
}

/// The initiator of a handshake: made, then writes message 1, then reads
/// message 2. Its keys are in locked memory (`secret`): the identity's is
/// shared with the identity, not copied.
pub struct Initiator {
    state: Locked<SymmetricState>,
    identity: Identity,
    rs: [u8; KEY_LEN],
    psk: SecretKey,
    e: Option<SecretKey>,
    /// The hybrid handshake: `e1`, made with message 1.
    hybrid: bool,
    e1: Option<KemSecret>,
    finished: bool,
    /// The ephemeral keys of the next message 1, when a test gives them
    /// (see [`Initiator::fix`]).
    #[cfg(test)]
    fixed: Option<(SecretKey, Option<KemSecret>)>,
}

impl Initiator {
    pub fn new(
        identity: &Identity,
        responder: &[u8; KEY_LEN],
        psk: &SecretKey,
        prologue: &[u8],
    ) -> Self {
        Self {
            state: SymmetricState::new(PROTOCOL_NAME, prologue, responder),
            identity: identity.clone(),
            rs: *responder,
            psk: psk.clone(),
            e: None,
            hybrid: false,
            e1: None,
            finished: false,
            #[cfg(test)]
            fixed: None,
        }
    }

    /// The initiator of the hybrid handshake (`IKpsk2+hfs`).
    pub fn new_hybrid(
        identity: &Identity,
        responder: &[u8; KEY_LEN],
        psk: &SecretKey,
        prologue: &[u8],
    ) -> Self {
        Self {
            state: SymmetricState::new(PROTOCOL_NAME_HFS, prologue, responder),
            hybrid: true,
            ..Self::new(identity, responder, psk, prologue)
        }
    }

    /// Message 1, `-> e, es, s, ss` (or `-> e, es, e1, s, ss`), carrying
    /// `payload`.
    pub fn write_initiation(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        #[cfg(test)]
        if let Some((e, e1)) = self.fixed.take() {
            return self.write_initiation_with(e, e1, payload);
        }
        let e1 = self.hybrid.then(KemSecret::generate);
        self.write_initiation_with(SecretKey::random(), e1, payload)
    }

    /// The ephemeral keys the next message 1 is written with — `e`, and in
    /// the hybrid handshake `e1` — instead of fresh ones: the test vectors'
    /// (`crypto::vectors`).
    #[cfg(test)]
    pub(crate) fn fix(&mut self, e: SecretKey, e1: Option<KemSecret>) {
        self.fixed = Some((e, e1));
    }

    fn write_initiation_with(
        &mut self,
        e: SecretKey,
        e1: Option<KemSecret>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if self.e.is_some() {
            return Err(failed("message 1 was already written"));
        }
        let mut out = Vec::with_capacity(HFS_INITIATION_LEN + payload.len());
        let e_pub = public_of(e.expose());
        out.extend_from_slice(&e_pub);
        mix_ephemeral(&mut self.state, &e_pub);
        self.state.mix_key(&dh(e.expose(), &self.rs)?[..]); // es
        if self.hybrid {
            let e1 = e1.ok_or_else(|| failed("a hybrid handshake without e1"))?;
            self.state.encrypt_and_hash(e1.public(), &mut out)?; // e1
            self.e1 = Some(e1);
        }
        self.state
            .encrypt_and_hash(self.identity.public(), &mut out)?; // s
        self.state
            .mix_key(&dh(self.identity.secret(), &self.rs)?[..]); // ss
        self.state.encrypt_and_hash(payload, &mut out)?;
        self.e = Some(e);
        Ok(out)
    }

    /// Reads message 2, `<- e, ee, se, psk` (or `<- e, ee, ekem1, se,
    /// psk`), and returns its payload.
    ///
    /// Nothing is used up by a message that fails: the state is worked on
    /// in a copy and taken only once the message has authenticated, so a
    /// forgery leaves the handshake ready for the real answer.
    pub fn read_response(&mut self, msg: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let Some(e) = &self.e else {
            return Err(CryptoError::Malformed);
        };
        let least = if self.hybrid {
            HFS_RESPONSE_LEN
        } else {
            RESPONSE_LEN
        };
        if self.finished || msg.len() < least {
            return Err(CryptoError::Malformed);
        }
        let re: [u8; KEY_LEN] = msg[..KEY_LEN].try_into().expect("a key's length");
        let mut state = self.state.copy();
        mix_ephemeral(&mut state, &re);
        state.mix_key(&dh(e.expose(), &re)?[..]); // ee
        let mut at = KEY_LEN;
        if let Some(e1) = &self.e1 {
            let mut ct = Vec::with_capacity(CT_LEN);
            state.decrypt_and_hash(&msg[at..at + CT_LEN + TAG_LEN], &mut ct)?; // ekem1
            at += CT_LEN + TAG_LEN;
            let ct: [u8; CT_LEN] = ct.try_into().expect("a ciphertext's length");
            state.mix_key(&e1.decapsulate(&ct)[..]);
        }
        state.mix_key(&dh(self.identity.secret(), &re)?[..]); // se
        state.mix_key_and_hash(self.psk.expose()); // psk
        let mut payload = Zeroizing::new(Vec::with_capacity(msg.len() - at));
        state.decrypt_and_hash(&msg[at..], &mut payload)?;
        self.state = state;
        self.finished = true;
        Ok(payload)
    }

    /// Whether message 2 has been read.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// The transport keys, once message 2 has been read.
    pub fn split(&self) -> Option<Split> {
        self.finished.then(|| self.state.split())
    }
}

/// The responder, after message 1 has been read: writes message 2.
pub struct Responder {
    state: Locked<SymmetricState>,
    re: [u8; KEY_LEN],
    rs: [u8; KEY_LEN],
    psk: SecretKey,
    /// The initiator's `e1`, in the hybrid handshake.
    re1: Option<Box<[u8; EK_LEN]>>,
    /// The ephemeral key and the encapsulation's randomness message 2 is
    /// written with, when a test gives them (see [`Responder::fix`]).
    #[cfg(test)]
    fixed: Option<(SecretKey, Option<[u8; 32]>)>,
}

/// What message 1 said: who sent it, and its payload.
pub struct Initiation {
    pub responder: Responder,
    pub initiator_static: [u8; KEY_LEN],
    pub payload: Zeroizing<Vec<u8>>,
}

impl Responder {
    /// Reads message 1, `-> e, es, s, ss`, made for `identity`.
    pub fn read_initiation(
        identity: &Identity,
        psk: &SecretKey,
        prologue: &[u8],
        msg: &[u8],
    ) -> Result<Initiation, CryptoError> {
        Self::read(identity, psk, prologue, msg, false)
    }

    /// Reads message 1 of the hybrid handshake, `-> e, es, e1, s, ss`.
    pub fn read_hybrid_initiation(
        identity: &Identity,
        psk: &SecretKey,
        prologue: &[u8],
        msg: &[u8],
    ) -> Result<Initiation, CryptoError> {
        Self::read(identity, psk, prologue, msg, true)
    }

    fn read(
        identity: &Identity,
        psk: &SecretKey,
        prologue: &[u8],
        msg: &[u8],
        hybrid: bool,
    ) -> Result<Initiation, CryptoError> {
        let (name, least) = if hybrid {
            (PROTOCOL_NAME_HFS, HFS_INITIATION_LEN)
        } else {
            (PROTOCOL_NAME, INITIATION_LEN)
        };
        if msg.len() < least {
            return Err(CryptoError::Malformed);
        }
        let mut state = SymmetricState::new(name, prologue, identity.public());
        let re: [u8; KEY_LEN] = msg[..KEY_LEN].try_into().expect("a key's length");
        mix_ephemeral(&mut state, &re);
        state.mix_key(&dh(identity.secret(), &re)?[..]); // es
        let mut at = KEY_LEN;
        let mut re1 = None;
        if hybrid {
            let mut ek = Vec::with_capacity(EK_LEN);
            state.decrypt_and_hash(&msg[at..at + EK_LEN + TAG_LEN], &mut ek)?; // e1
            at += EK_LEN + TAG_LEN;
            re1 = Some(Box::new(
                <[u8; EK_LEN]>::try_from(ek).expect("a key's length"),
            ));
        }
        let mut rs = Vec::with_capacity(KEY_LEN);
        state.decrypt_and_hash(&msg[at..at + KEY_LEN + TAG_LEN], &mut rs)?; // s
        at += KEY_LEN + TAG_LEN;
        let rs: [u8; KEY_LEN] = rs.try_into().expect("a key's length");
        state.mix_key(&dh(identity.secret(), &rs)?[..]); // ss
        let mut payload = Zeroizing::new(Vec::with_capacity(msg.len() - at));
        state.decrypt_and_hash(&msg[at..], &mut payload)?;
        Ok(Initiation {
            responder: Responder {
                state,
                re,
                rs,
                psk: psk.clone(),
                re1,
                #[cfg(test)]
                fixed: None,
            },
            initiator_static: rs,
            payload,
        })
    }

    /// Message 2, `<- e, ee, se, psk` (or `<- e, ee, ekem1, se, psk`),
    /// carrying `payload`, and the keys.
    pub fn write_response(self, payload: &[u8]) -> Result<(Vec<u8>, Split), CryptoError> {
        #[cfg(test)]
        if let Some((e, _)) = &self.fixed {
            let e = e.clone();
            return self.write_response_with(e, payload);
        }
        self.write_response_with(SecretKey::random(), payload)
    }

    /// The ephemeral key message 2 is written with, and in the hybrid
    /// handshake FIPS 203's `m` for the encapsulation, instead of fresh
    /// ones: the test vectors' (`crypto::vectors`).
    #[cfg(test)]
    pub(crate) fn fix(&mut self, e: SecretKey, m: Option<[u8; 32]>) {
        self.fixed = Some((e, m));
    }

    fn write_response_with(
        mut self,
        e: SecretKey,
        payload: &[u8],
    ) -> Result<(Vec<u8>, Split), CryptoError> {
        let mut out = Vec::with_capacity(HFS_RESPONSE_LEN + payload.len());
        let e_pub = public_of(e.expose());
        out.extend_from_slice(&e_pub);
        mix_ephemeral(&mut self.state, &e_pub);
        self.state.mix_key(&dh(e.expose(), &self.re)?[..]); // ee
        if let Some(re1) = &self.re1 {
            #[cfg(test)]
            let (ct, shared) = match self.fixed.as_ref().and_then(|f| f.1) {
                Some(m) => kem::encapsulate_deterministic(re1, &m)?,
                None => kem::encapsulate(re1)?,
            };
            #[cfg(not(test))]
            let (ct, shared) = kem::encapsulate(re1)?;
            self.state.encrypt_and_hash(&ct, &mut out)?; // ekem1
            self.state.mix_key(&shared[..]);
        }
        self.state.mix_key(&dh(e.expose(), &self.rs)?[..]); // se
        self.state.mix_key_and_hash(self.psk.expose()); // psk
        self.state.encrypt_and_hash(payload, &mut out)?;
        Ok((out, self.state.split()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key(s: &str) -> [u8; 32] {
        hex(s).try_into().unwrap()
    }

    /// The transport messages after a handshake, as Noise defines them
    /// (this protocol derives its own traffic keys from the split, but the
    /// vector checks the split through them).
    fn transport(k: &[u8; 32], n: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut cipher = CipherState::default();
        cipher.set(k);
        cipher.n = n;
        let mut out = Vec::new();
        cipher.encrypt_with_ad(&[], plaintext, &mut out).unwrap();
        out
    }

    /// Cacophony's test vector for `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`
    /// (`noise_ikpsk2_vector.json`, taken from `tests/vectors/cacophony.txt`
    /// of snow's repository): both handshake messages byte for byte, from
    /// both sides, the handshake hash, and the split keys through the four
    /// transport messages after it.
    #[test]
    fn the_noise_test_vector() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("noise_ikpsk2_vector.json")).unwrap();
        let s = |k: &str| v[k].as_str().unwrap();
        assert_eq!(s("protocol_name"), PROTOCOL_NAME);
        let prologue = hex(s("init_prologue"));
        assert_eq!(prologue, hex(s("resp_prologue")));
        let psk = SecretKey::from_bytes(&key(v["init_psks"][0].as_str().unwrap()));
        assert_eq!(psk.expose(), &key(v["resp_psks"][0].as_str().unwrap()));
        let init = Identity::from_secret(key(s("init_static")));
        let resp = Identity::from_secret(key(s("resp_static")));
        assert_eq!(resp.public(), &key(s("init_remote_static")));
        let messages = v["messages"].as_array().unwrap();
        let msg = |i: usize, f: &str| hex(messages[i][f].as_str().unwrap());

        let mut initiator = Initiator::new(&init, resp.public(), &psk, &prologue);
        let m1 = initiator
            .write_initiation_with(
                SecretKey::from_bytes(&key(s("init_ephemeral"))),
                None,
                &msg(0, "payload"),
            )
            .unwrap();
        assert_eq!(m1, msg(0, "ciphertext"), "message 1");
        let read = Responder::read_initiation(&resp, &psk, &prologue, &m1).unwrap();
        assert_eq!(&read.initiator_static, init.public());
        assert_eq!(*read.payload, msg(0, "payload"));
        let (m2, rsplit) = read
            .responder
            .write_response_with(
                SecretKey::from_bytes(&key(s("resp_ephemeral"))),
                &msg(1, "payload"),
            )
            .unwrap();
        assert_eq!(m2, msg(1, "ciphertext"), "message 2");
        assert_eq!(*initiator.read_response(&m2).unwrap(), msg(1, "payload"));
        let isplit = initiator.split().unwrap();
        assert_eq!(isplit.hash.to_vec(), hex(s("handshake_hash")));
        assert_eq!(rsplit.hash, isplit.hash);
        assert_eq!(
            *rsplit.initiator_to_responder,
            *isplit.initiator_to_responder
        );
        assert_eq!(
            *rsplit.responder_to_initiator,
            *isplit.responder_to_initiator
        );

        // After the handshake the initiator's messages are the odd ones of
        // the vector's list, each direction counting its own nonces.
        let (mut to_resp, mut to_init) = (0, 0);
        for (i, m) in messages.iter().enumerate().skip(2) {
            let payload = hex(m["payload"].as_str().unwrap());
            let sent = if i % 2 == 0 {
                to_resp += 1;
                transport(&isplit.initiator_to_responder, to_resp - 1, &payload)
            } else {
                to_init += 1;
                transport(&isplit.responder_to_initiator, to_init - 1, &payload)
            };
            assert_eq!(
                sent,
                hex(m["ciphertext"].as_str().unwrap()),
                "message {}",
                i + 1
            );
        }
    }

    fn snow_builder(prologue: &[u8]) -> snow::Builder<'_> {
        snow::Builder::new(PROTOCOL_NAME.parse().unwrap()).prologue(prologue)
    }

    fn random<const N: usize>() -> [u8; N] {
        let mut out = [0u8; N];
        rand::rngs::OsRng.fill_bytes(&mut out);
        out
    }

    /// With the same keys, ephemeral ones included, this and snow write the
    /// same bytes and arrive at the same keys and hash — for payloads of
    /// every size a handshake here carries, and random keys each time.
    #[test]
    fn writes_what_snow_writes() {
        for round in 0..300usize {
            let (init, resp) = (Identity::generate(), Identity::generate());
            let (ie, re) = (random::<32>(), random::<32>());
            let psk = if round % 3 == 0 { [0u8; 32] } else { random() };
            let prologue = &b"SHARP-256 v3"[..round % 13];
            let p1: Vec<u8> = (0..round * 3 % 1100).map(|i| i as u8).collect();
            let p2: Vec<u8> = (0..round * 7 % 1000).map(|i| (i * 7) as u8).collect();

            let mut ours =
                Initiator::new(&init, resp.public(), &SecretKey::from_bytes(&psk), prologue);
            let m1 = ours
                .write_initiation_with(SecretKey::from_bytes(&ie), None, &p1)
                .unwrap();
            let mut snow_i = snow_builder(prologue)
                .local_private_key(init.secret())
                .remote_public_key(resp.public())
                .psk(2, &psk)
                .fixed_ephemeral_key_for_testing_only(&ie)
                .build_initiator()
                .unwrap();
            let mut buf = vec![0u8; 65535];
            let n = snow_i.write_message(&p1, &mut buf).unwrap();
            assert_eq!(m1, &buf[..n], "message 1, round {}", round);

            let read =
                Responder::read_initiation(&resp, &SecretKey::from_bytes(&psk), prologue, &m1)
                    .unwrap();
            let (m2, rsplit) = read
                .responder
                .write_response_with(SecretKey::from_bytes(&re), &p2)
                .unwrap();
            let mut snow_r = snow_builder(prologue)
                .local_private_key(resp.secret())
                .psk(2, &psk)
                .fixed_ephemeral_key_for_testing_only(&re)
                .build_responder()
                .unwrap();
            snow_r.read_message(&m1, &mut buf).unwrap();
            let n = snow_r.write_message(&p2, &mut buf).unwrap();
            assert_eq!(m2, &buf[..n], "message 2, round {}", round);

            assert_eq!(*ours.read_response(&m2).unwrap(), p2);
            let isplit = ours.split().unwrap();
            let (a, b) = snow_r.dangerously_get_raw_split();
            assert_eq!(*rsplit.initiator_to_responder, a);
            assert_eq!(*rsplit.responder_to_initiator, b);
            assert_eq!(*isplit.initiator_to_responder, a);
            assert_eq!(*isplit.responder_to_initiator, b);
            assert_eq!(&isplit.hash[..], snow_r.get_handshake_hash());
        }
    }

    /// Each completes handshakes with the other in both roles, with random
    /// ephemeral keys, and both ends agree on the keys.
    #[test]
    fn completes_handshakes_with_snow_both_ways() {
        let prologue = b"SHARP-256 v3";
        let mut buf = vec![0u8; 65535];
        for _ in 0..50 {
            let (init, resp, psk) = (Identity::generate(), Identity::generate(), random::<32>());

            // Ours starts, snow answers.
            let mut ours =
                Initiator::new(&init, resp.public(), &SecretKey::from_bytes(&psk), prologue);
            let m1 = ours.write_initiation(b"hello").unwrap();
            let mut snow_r = snow_builder(prologue)
                .local_private_key(resp.secret())
                .psk(2, &psk)
                .build_responder()
                .unwrap();
            let n = snow_r.read_message(&m1, &mut buf).unwrap();
            assert_eq!(&buf[..n], b"hello");
            assert_eq!(snow_r.get_remote_static().unwrap(), init.public());
            let n = snow_r.write_message(b"ack", &mut buf).unwrap();
            assert_eq!(*ours.read_response(&buf[..n]).unwrap(), b"ack");
            let (a, b) = snow_r.dangerously_get_raw_split();
            let split = ours.split().unwrap();
            assert_eq!(
                (*split.initiator_to_responder, *split.responder_to_initiator),
                (a, b)
            );

            // Snow starts, ours answers.
            let mut snow_i = snow_builder(prologue)
                .local_private_key(init.secret())
                .remote_public_key(resp.public())
                .psk(2, &psk)
                .build_initiator()
                .unwrap();
            let n = snow_i.write_message(b"hello", &mut buf).unwrap();
            let read = Responder::read_initiation(
                &resp,
                &SecretKey::from_bytes(&psk),
                prologue,
                &buf[..n],
            )
            .unwrap();
            assert_eq!(&read.initiator_static, init.public());
            assert_eq!(*read.payload, b"hello");
            let (m2, split) = read.responder.write_response(b"ack").unwrap();
            let n = snow_i.read_message(&m2, &mut buf).unwrap();
            assert_eq!(&buf[..n], b"ack");
            let (a, b) = snow_i.dangerously_get_raw_split();
            assert_eq!(
                (*split.initiator_to_responder, *split.responder_to_initiator),
                (a, b)
            );
        }
    }

    /// What a handshake keeps its keys in wipes them: the chaining key, the
    /// hash, and the cipher's key and count.
    #[test]
    fn the_handshake_state_is_wiped() {
        let mut state = SymmetricState {
            ck: [1; 32],
            h: [2; 32],
            cipher: CipherState::default(),
        };
        state.cipher.set(&[3; 32]);
        state.cipher.n = 9;
        state.zeroize();
        assert_eq!((state.ck, state.h), ([0; 32], [0; 32]));
        let c = &state.cipher;
        assert_eq!((c.k, c.has_key, c.n), ([0; 32], false, 0));
    }

    /// A message that fails leaves the initiator as it was: the real
    /// answer after it still completes the handshake. And nothing is read
    /// before message 1 is written, or twice.
    #[test]
    fn a_failed_read_uses_nothing_up() {
        let (init, resp, psk) = (Identity::generate(), Identity::generate(), [5u8; 32]);
        let mut ours = Initiator::new(&init, resp.public(), &SecretKey::from_bytes(&psk), b"p");
        assert!(ours.read_response(&[0u8; 80]).is_err());
        let m1 = ours.write_initiation(b"x").unwrap();
        assert!(ours.write_initiation(b"x").is_err(), "message 1 twice");
        let read =
            Responder::read_initiation(&resp, &SecretKey::from_bytes(&psk), b"p", &m1).unwrap();
        let (m2, _) = read.responder.write_response(b"y").unwrap();
        for i in 0..m2.len() {
            let mut bad = m2.clone();
            bad[i] ^= 0x80;
            assert!(ours.read_response(&bad).is_err(), "byte {} flipped", i);
            assert!(!ours.is_finished());
        }
        assert!(ours.read_response(&m2[..RESPONSE_LEN - 1]).is_err());
        assert_eq!(*ours.read_response(&m2).unwrap(), b"y");
        assert!(ours.is_finished());
        assert!(ours.read_response(&m2).is_err(), "read twice");
    }

    /// A different PSK, prologue or responder key fails where Noise says
    /// it must: the PSK and prologue at message 2, the responder key at
    /// message 1.
    #[test]
    fn what_does_not_match_does_not_complete() {
        let (init, resp) = (Identity::generate(), Identity::generate());
        let other = Identity::generate();
        let psk = [1u8; 32];
        let mut ours = Initiator::new(&init, resp.public(), &SecretKey::from_bytes(&psk), b"v3");
        let m1 = ours.write_initiation(b"x").unwrap();
        assert!(
            Responder::read_initiation(&other, &SecretKey::from_bytes(&psk), b"v3", &m1).is_err()
        );
        assert!(
            Responder::read_initiation(&resp, &SecretKey::from_bytes(&psk), b"v4", &m1).is_err()
        );
        // The PSK comes in only with message 2.
        let read =
            Responder::read_initiation(&resp, &SecretKey::from_bytes(&[2u8; 32]), b"v3", &m1)
                .unwrap();
        let (m2, _) = read.responder.write_response(b"y").unwrap();
        assert!(ours.read_response(&m2).is_err());
    }

    /// A small-order point as an ephemeral key sends every exchange with it
    /// to zero, whatever the secret on the other side; it is refused.
    #[test]
    fn an_ephemeral_with_no_private_half_is_refused() {
        let (init, resp, psk) = (Identity::generate(), Identity::generate(), [0u8; 32]);
        let mut ours = Initiator::new(&init, resp.public(), &SecretKey::from_bytes(&psk), b"");
        let mut m1 = ours.write_initiation(b"x").unwrap();
        m1[..32].copy_from_slice(&[0u8; 32]);
        assert!(Responder::read_initiation(&resp, &SecretKey::from_bytes(&psk), b"", &m1).is_err());
        let good = ours.write_initiation(b"x");
        assert!(good.is_err(), "one message 1 per initiator");
        let mut ours = Initiator::new(&init, resp.public(), &SecretKey::from_bytes(&psk), b"");
        let m1 = ours.write_initiation(b"x").unwrap();
        let read =
            Responder::read_initiation(&resp, &SecretKey::from_bytes(&psk), b"", &m1).unwrap();
        let (mut m2, _) = read.responder.write_response(b"y").unwrap();
        m2[..32].copy_from_slice(&[0u8; 32]);
        assert!(ours.read_response(&m2).is_err());
    }

    /// The hybrid handshake completes with the same keys on both sides,
    /// with messages of the lengths the wire format counts on; neither form
    /// is read as the other (the protocol names differ, and so does every
    /// key after them).
    #[test]
    fn the_hybrid_handshake_completes_and_is_its_own() {
        let (init, resp) = (Identity::generate(), Identity::generate());
        let psk = SecretKey::from_bytes(&[3u8; 32]);
        let mut ours = Initiator::new_hybrid(&init, resp.public(), &psk, b"v4");
        let m1 = ours.write_initiation(b"hello").unwrap();
        assert_eq!(m1.len(), HFS_INITIATION_LEN + 5);
        assert!(Responder::read_initiation(&resp, &psk, b"v4", &m1).is_err());
        let read = Responder::read_hybrid_initiation(&resp, &psk, b"v4", &m1).unwrap();
        assert_eq!(&read.payload[..], b"hello");
        assert_eq!(read.initiator_static, *init.public());
        let (m2, theirs) = read.responder.write_response(b"ack").unwrap();
        assert_eq!(m2.len(), HFS_RESPONSE_LEN + 3);
        assert_eq!(&ours.read_response(&m2).unwrap()[..], b"ack");
        let mine = ours.split().unwrap();
        assert_eq!(*mine.initiator_to_responder, *theirs.initiator_to_responder);
        assert_eq!(*mine.responder_to_initiator, *theirs.responder_to_initiator);
        assert_eq!(mine.hash, theirs.hash);

        // A classical message 1 is not a hybrid one either.
        let mut classical = Initiator::new(&init, resp.public(), &psk, b"v4");
        let m1 = classical.write_initiation(b"hello").unwrap();
        assert!(Responder::read_hybrid_initiation(&resp, &psk, b"v4", &m1).is_err());
    }

    /// Every byte of both hybrid messages counts: `e1` and `ekem1` as much
    /// as the rest. A forged message 2 uses nothing up (the real one after
    /// it completes), and a responder that encapsulated to another key —
    /// here, a message 2 made for another message 1 — is refused.
    #[test]
    fn every_byte_of_the_hybrid_handshake_counts() {
        let (init, resp) = (Identity::generate(), Identity::generate());
        let psk = SecretKey::from_bytes(&[4u8; 32]);
        let mut ours = Initiator::new_hybrid(&init, resp.public(), &psk, b"v4");
        let m1 = ours.write_initiation(b"x").unwrap();
        // A sample of positions, every region among them: e, e1, s, payload.
        for i in (0..m1.len())
            .step_by(37)
            .chain([KEY_LEN, KEY_LEN + EK_LEN, m1.len() - 1])
        {
            let mut bad = m1.clone();
            bad[i] ^= 0x01;
            assert!(
                Responder::read_hybrid_initiation(&resp, &psk, b"v4", &bad).is_err(),
                "byte {} of message 1",
                i
            );
        }
        let read = Responder::read_hybrid_initiation(&resp, &psk, b"v4", &m1).unwrap();
        let (m2, _) = read.responder.write_response(b"y").unwrap();
        for i in (0..m2.len())
            .step_by(29)
            .chain([KEY_LEN, KEY_LEN + CT_LEN, m2.len() - 1])
        {
            let mut bad = m2.clone();
            bad[i] ^= 0x01;
            assert!(ours.read_response(&bad).is_err(), "byte {} of message 2", i);
            assert!(!ours.is_finished());
        }
        // The answer to another initiator's message 1 (another e1).
        let mut someone = Initiator::new_hybrid(&init, resp.public(), &psk, b"v4");
        let other = someone.write_initiation(b"x").unwrap();
        let read = Responder::read_hybrid_initiation(&resp, &psk, b"v4", &other).unwrap();
        let (wrong, _) = read.responder.write_response(b"y").unwrap();
        assert!(ours.read_response(&wrong).is_err());
        assert_eq!(&ours.read_response(&m2).unwrap()[..], b"y");
    }
}
