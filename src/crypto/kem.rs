//! ML-KEM-768 (FIPS 203), the post-quantum half of protocol version 4's
//! hybrid key exchange (see [`crate::crypto::noise`], the `e1` and `ekem1`
//! tokens).
//!
//! The KEM itself is RustCrypto's `ml-kem`; what is here is what that crate
//! leaves to its caller:
//!
//! * the check FIPS 203 (section 7.2) requires of an encapsulation key
//!   before it is used — every coefficient reduced modulo q = 3329 — which
//!   the crate does not make: a key that fails it is refused;
//! * the decapsulation key kept in locked memory ([`Locked`]), and the
//!   shared secret wiped when it goes (the crate returns it bare);
//! * the sizes, as constants the wire format can use.
//!
//! Checked against the accumulated vectors of Go's `crypto/mlkem` (ten
//! thousand deterministic key generations, encapsulations and implicit
//! rejections, hashed together), which shares no code with it.

use crate::crypto::secret::Locked;
use crate::crypto::CryptoError;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use zeroize::{Zeroize, Zeroizing};

/// An encapsulation key: 3 × 384 bytes of coefficients and the 32-byte seed.
pub const EK_LEN: usize = 1184;
/// A ciphertext.
pub const CT_LEN: usize = 1088;
/// The shared secret.
pub const SS_LEN: usize = 32;
/// FIPS 203's modulus.
const Q: u16 = 3329;

type DecapsulationKey = ml_kem::kem::DecapsulationKey<MlKem768Params>;
type EncapsulationKey = ml_kem::kem::EncapsulationKey<MlKem768Params>;

/// A decapsulation key, wiped when it goes (the crate's type wipes itself
/// when dropped; this drops it where it lies).
#[derive(Default)]
struct Held(Option<DecapsulationKey>);

impl Zeroize for Held {
    fn zeroize(&mut self) {
        // Dropped in place: its own `Drop` wipes the secret parts.
        self.0 = None;
    }
}

/// One side's ephemeral ML-KEM key pair: made for one handshake, used once.
pub struct KemSecret {
    dk: Locked<Held>,
    ek: Box<[u8; EK_LEN]>,
}

impl KemSecret {
    /// A fresh key pair from the system's random source.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let (dk, ek) = MlKem768::generate(&mut rng);
        Self::holding(dk, ek)
    }

    /// The key pair of FIPS 203's seed `d || z` (`ML-KEM.KeyGen_internal`):
    /// the test vectors' (`crypto::vectors`).
    #[cfg(test)]
    pub fn from_seed(seed: &[u8; 64]) -> Self {
        let (mut d, mut z) = (ml_kem::B32::default(), ml_kem::B32::default());
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);
        let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
        Self::holding(dk, ek)
    }

    fn holding(dk: DecapsulationKey, ek: EncapsulationKey) -> Self {
        let mut public = Box::new([0u8; EK_LEN]);
        public.copy_from_slice(ek.as_bytes().as_slice());
        let mut held = Locked::new(Held::default());
        held.0 = Some(dk);
        Self {
            dk: held,
            ek: public,
        }
    }

    /// The encapsulation key, for the other side.
    pub fn public(&self) -> &[u8; EK_LEN] {
        &self.ek
    }

    /// The shared secret a ciphertext for this key carries — or, for one
    /// that is not (it was altered, or made for another key), the implicit
    /// rejection's pseudo-random one, which the handshake then fails on.
    pub fn decapsulate(&self, ct: &[u8; CT_LEN]) -> Zeroizing<[u8; SS_LEN]> {
        let dk = self.dk.0.as_ref().expect("held until dropped");
        let ct = ml_kem::Ciphertext::<MlKem768>::try_from(&ct[..]).expect("a ciphertext's length");
        let mut shared = dk.decapsulate(&ct).expect("decapsulation cannot fail");
        let mut out = Zeroizing::new([0u8; SS_LEN]);
        out.copy_from_slice(shared.as_slice());
        shared.as_mut_slice().zeroize();
        out
    }
}

/// Encapsulates a fresh secret to `ek`: the ciphertext, and the secret.
/// Refuses a key FIPS 203 does not allow: one with a coefficient that is
/// not reduced modulo q.
pub fn encapsulate(
    ek: &[u8; EK_LEN],
) -> Result<([u8; CT_LEN], Zeroizing<[u8; SS_LEN]>), CryptoError> {
    let (ct, shared) = checked(ek)?
        .encapsulate(&mut rand::rngs::OsRng)
        .map_err(|_| CryptoError::Malformed)?;
    Ok(taken(ct, shared))
}

/// [`encapsulate`] with FIPS 203's `m` given (`ML-KEM.Encaps_internal`):
/// the test vectors'.
#[cfg(test)]
pub fn encapsulate_deterministic(
    ek: &[u8; EK_LEN],
    m: &[u8; 32],
) -> Result<([u8; CT_LEN], Zeroizing<[u8; SS_LEN]>), CryptoError> {
    use ml_kem::EncapsulateDeterministic;
    let (ct, shared) = checked(ek)?
        .encapsulate_deterministic(&ml_kem::B32::from(*m))
        .map_err(|_| CryptoError::Malformed)?;
    Ok(taken(ct, shared))
}

/// The key, if FIPS 203 allows it (see [`is_reduced`]).
fn checked(ek: &[u8; EK_LEN]) -> Result<EncapsulationKey, CryptoError> {
    if !is_reduced(ek) {
        return Err(CryptoError::Malformed);
    }
    let encoded = ml_kem::Encoded::<EncapsulationKey>::try_from(&ek[..]).expect("a key's length");
    Ok(EncapsulationKey::from_bytes(&encoded))
}

/// The ciphertext, and the secret moved where it is wiped.
fn taken(
    ct: ml_kem::Ciphertext<MlKem768>,
    mut shared: ml_kem::SharedKey<MlKem768>,
) -> ([u8; CT_LEN], Zeroizing<[u8; SS_LEN]>) {
    let mut out = [0u8; CT_LEN];
    out.copy_from_slice(ct.as_slice());
    let mut secret = Zeroizing::new([0u8; SS_LEN]);
    secret.copy_from_slice(shared.as_slice());
    shared.as_mut_slice().zeroize();
    (out, secret)
}

/// FIPS 203, section 7.2, "modulus check": the key's coefficients, twelve
/// bits each, are all below q — that is, decoding and encoding the key
/// again gives back the same bytes.
fn is_reduced(ek: &[u8; EK_LEN]) -> bool {
    ek[..EK_LEN - 32].chunks_exact(3).all(|b| {
        let c0 = u16::from(b[0]) | (u16::from(b[1] & 0x0f) << 8);
        let c1 = u16::from(b[1] >> 4) | (u16::from(b[2]) << 4);
        c0 < Q && c1 < Q
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_encapsulated_is_the_secret_decapsulated() {
        let mine = KemSecret::generate();
        let (ct, sent) = encapsulate(mine.public()).unwrap();
        assert_eq!(*mine.decapsulate(&ct), *sent);
        // Another key pair, or an altered ciphertext: the implicit
        // rejection's secret, which is some other one.
        let other = KemSecret::generate();
        assert_ne!(*other.decapsulate(&ct), *sent);
        let mut altered = ct;
        altered[100] ^= 1;
        assert_ne!(*mine.decapsulate(&altered), *sent);
    }

    /// A key with one coefficient equal to q (or above) is refused; the
    /// largest reduced one, q - 1, is not.
    #[test]
    fn a_key_with_an_unreduced_coefficient_is_refused() {
        let good = *KemSecret::generate().public();
        assert!(encapsulate(&good).is_ok());
        for (value, allowed) in [(Q - 1, true), (Q, false), (4095, false)] {
            // The first coefficient of the key, and then the second.
            let mut first = good;
            first[0] = (value & 0xff) as u8;
            first[1] = (first[1] & 0xf0) | (value >> 8) as u8;
            assert_eq!(encapsulate(&first).is_ok(), allowed, "{}", value);
            let mut second = good;
            second[1] = (second[1] & 0x0f) | ((value & 0x0f) << 4) as u8;
            second[2] = (value >> 4) as u8;
            assert_eq!(encapsulate(&second).is_ok(), allowed, "{}", value);
        }
        // The last two coefficients, just before the seed, are checked
        // like the first.
        let mut last = good;
        last[EK_LEN - 32 - 1] = 0xff;
        last[EK_LEN - 32 - 2] |= 0xf0;
        assert!(encapsulate(&last).is_err());
        // The seed at the end is any 32 bytes.
        let mut seed = good;
        seed[EK_LEN - 1] = 0xff;
        assert!(encapsulate(&seed).is_ok());
    }

    /// A key pair is wiped when it goes: what holds it lets go of it.
    #[test]
    fn a_key_pair_held_is_let_go_of() {
        let mut held = Held(Some(MlKem768::generate(&mut rand::rngs::OsRng).0));
        held.zeroize();
        assert!(held.0.is_none());
    }

    /// The accumulated vectors of Go's `crypto/mlkem` (`TestAccumulated`,
    /// Go 1.25: an implementation that shares no code with this crate's):
    /// a SHAKE-128 stream of empty input gives each round's seed d ‖ z (key
    /// generation), m (encapsulation) and a random ciphertext
    /// (decapsulation, which rejects it implicitly); ek, ct, k and the
    /// rejection's k go into a SHAKE-128 accumulator, and 32 bytes of it
    /// are compared: a hundred rounds here, as Go's `-short`, and ten
    /// thousand in the test after, on request (the generic code is built
    /// with this crate's optimisation, none in a test build).
    ///
    /// (C2SP CCTV's accumulated vectors also write the expanded
    /// decapsulation key after ek; with it this does not come out as CCTV
    /// says — f959d18d… against f7db260e… — while without it it comes out
    /// as Go says. The decapsulations above use every part of that key, so
    /// what differs is at most how the crate writes it out, which nothing
    /// here does: the key never leaves this program.)
    #[test]
    fn the_accumulated_vectors_of_go_come_out() {
        assert_eq!(
            accumulated(100),
            "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415"
        );
    }

    #[test]
    #[ignore = "ten thousand rounds; cargo test --release -- --ignored accumulated"]
    fn ten_thousand_accumulated_vectors_of_go_come_out() {
        assert_eq!(
            accumulated(10_000),
            "8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc"
        );
    }

    fn accumulated(rounds: usize) -> String {
        use ml_kem::EncapsulateDeterministic;
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut rng = sha3::Shake128::default().finalize_xof();
        let mut acc = sha3::Shake128::default();
        let mut d = ml_kem::B32::default();
        let mut z = ml_kem::B32::default();
        let mut m = ml_kem::B32::default();
        let mut bad = ml_kem::Ciphertext::<MlKem768>::default();
        for _ in 0..rounds {
            rng.read(&mut d);
            rng.read(&mut z);
            let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
            acc.update(&ek.as_bytes());
            rng.read(&mut m);
            let (ct, k) = ek.encapsulate_deterministic(&m).unwrap();
            acc.update(&ct);
            acc.update(&k);
            assert_eq!(dk.decapsulate(&ct).unwrap(), k);
            rng.read(&mut bad);
            acc.update(&dk.decapsulate(&bad).unwrap());
        }
        let mut out = [0u8; 32];
        acc.finalize_xof().read(&mut out);
        out.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
