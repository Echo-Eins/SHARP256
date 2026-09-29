//! Security layer of SHARP-256 protocol v3.
//!
//! * [`identity`] — long-term X25519 identities and SHARP IDs;
//! * [`handshake`] — Noise `IKpsk2` key exchange with stealth MACs, cookies
//!   against spoofed floods, replay and rate limits;
//! * [`transport`] — per-packet AEAD with header protection and per-epoch keys;
//! * [`replay`] — replay window for transport packet numbers.

pub mod handshake;
pub mod identity;
pub mod replay;
pub mod transport;

pub use identity::{Identity, SharpId};
pub use transport::{SessionKeys, Suite};

use zeroize::{Zeroize, Zeroizing};

/// BLAKE3's key derivation for material that is secret: the same key as
/// `blake3::derive_key(context, material.concat())`, without a buffer that
/// holds the concatenation, and with the hasher — which saw all of the
/// material — wiped before this returns. The key itself is wiped when the
/// result is dropped.
///
/// `blake3::derive_key` and `blake3::keyed_hash` leave their hasher, and
/// with it the key or the material, in a stack slot that nothing clears.
pub(crate) fn derive_secret(context: &str, material: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for part in material {
        hasher.update(part);
    }
    let mut hash = hasher.finalize();
    let key = Zeroizing::new(*hash.as_bytes());
    hash.zeroize();
    hasher.zeroize();
    key
}

/// A MAC with BLAKE3 in keyed mode over `parts`, cut to `N` bytes. The MAC
/// goes on the wire and is no secret; the key is, so the hasher that held
/// it is wiped before this returns.
pub(crate) fn keyed_mac<const N: usize>(key: &[u8; 32], parts: &[&[u8]]) -> [u8; N] {
    const { assert!(N <= 32, "a BLAKE3 hash has 32 bytes") };
    let mut hasher = blake3::Hasher::new_keyed(key);
    for part in parts {
        hasher.update(part);
    }
    let mut hash = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&hash.as_bytes()[..N]);
    hash.zeroize();
    hasher.zeroize();
    out
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("malformed packet")]
    Malformed,
    #[error("packet authentication failed")]
    Open,
    #[error("packet encryption failed")]
    Seal,
    #[error("MAC check failed")]
    Mac,
    #[error("handshake failed: {0}")]
    Handshake(String),
}

impl From<snow::Error> for CryptoError {
    fn from(e: snow::Error) -> Self {
        CryptoError::Handshake(e.to_string())
    }
}

/// Pre-shared key used when no shared secret is configured.
pub const NO_PSK: [u8; 32] = [0; 32];

/// Argon2id cost of turning a shared passphrase into a pre-shared key: a
/// guess costs about a quarter of a second and 64 MiB of memory.
pub const PSK_MEMORY_KIB: u32 = 64 * 1024;
pub const PSK_PASSES: u32 = 3;

/// Derives the pre-shared key from a passphrase shared by sender and
/// receiver. The receiver's ID salts the derivation, so the same passphrase
/// yields unrelated keys for different receivers.
pub fn psk_from_passphrase(passphrase: &str, receiver: &SharpId) -> [u8; 32] {
    psk_from_passphrase_with_cost(passphrase, receiver, PSK_MEMORY_KIB, PSK_PASSES)
}

/// [`psk_from_passphrase`] with explicit Argon2id cost (tests use a low one).
pub fn psk_from_passphrase_with_cost(
    passphrase: &str,
    receiver: &SharpId,
    memory_kib: u32,
    passes: u32,
) -> [u8; 32] {
    let params = argon2::Params::new(memory_kib.max(8), passes.max(1), 1, Some(32))
        .expect("valid Argon2 parameters");
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut salt = b"sharp256 v3 psk ".to_vec();
    salt.extend_from_slice(receiver.as_bytes());
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut out)
        .expect("Argon2 output length is valid");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The helpers compute exactly what the one-shot functions compute:
    /// no key changes by going through them.
    #[test]
    fn derive_secret_and_keyed_mac_are_blake3() {
        let (a, b) = ([0x11u8; 32], b"and more material".as_slice());
        let whole = [&a[..], b].concat();
        assert_eq!(
            *derive_secret("sharp256 test", &[&a, b]),
            blake3::derive_key("sharp256 test", &whole)
        );
        assert_eq!(
            *derive_secret("sharp256 test", &[]),
            blake3::derive_key("sharp256 test", &[])
        );
        let key = [0x42u8; 32];
        let full = blake3::keyed_hash(&key, &whole);
        assert_eq!(keyed_mac::<32>(&key, &[&a, b]), *full.as_bytes());
        assert_eq!(keyed_mac::<16>(&key, &[&whole]), full.as_bytes()[..16]);
    }

    /// Every type a key is kept in wipes it when dropped. This fails to
    /// compile if a crate's `zeroize` feature is switched off (Cargo.toml)
    /// or a type is replaced by one that does not.
    #[test]
    fn what_holds_keys_wipes_them() {
        fn wipes<T: zeroize::ZeroizeOnDrop>() {}
        wipes::<aes::Aes256>();
        wipes::<chacha20poly1305::ChaCha20Poly1305>();
        wipes::<chacha20poly1305::XChaCha20Poly1305>();
        wipes::<chacha20::ChaChaCore<chacha20::cipher::consts::U10>>();
        wipes::<Zeroizing<[u8; 32]>>();
        // x25519-dalek wipes its secrets in a Drop of its own without
        // saying so with the marker: that it can be wiped and has a Drop
        // is as much as the type system shows.
        fn wiped_in_its_drop<T: zeroize::Zeroize>() -> bool {
            std::mem::needs_drop::<T>()
        }
        assert!(wiped_in_its_drop::<x25519_dalek::StaticSecret>());
        assert!(wiped_in_its_drop::<x25519_dalek::SharedSecret>());
    }

    #[test]
    fn psk_depends_on_passphrase_and_receiver() {
        let a = Identity::generate().id();
        let b = Identity::generate().id();
        let k1 = psk_from_passphrase_with_cost("correct horse", &a, 8, 1);
        let k2 = psk_from_passphrase_with_cost("correct horse", &a, 8, 1);
        let k3 = psk_from_passphrase_with_cost("correct horsf", &a, 8, 1);
        let k4 = psk_from_passphrase_with_cost("correct horse", &b, 8, 1);
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, k4);
        assert_ne!(k1, NO_PSK);
    }
}
