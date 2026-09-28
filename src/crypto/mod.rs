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
