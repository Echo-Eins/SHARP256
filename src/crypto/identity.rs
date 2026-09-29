//! Long-term identities (X25519 key pairs) and their textual form.
//!
//! A *SHARP ID* is the public half of an identity written as
//! `sh-` followed by 56 base32 characters: the 32-byte public key and a
//! 3-byte checksum, so that a mistyped ID is rejected instead of silently
//! addressing somebody else. Knowing a receiver's ID is what allows a sender
//! to reach it at all (see `handshake`), and the ID authenticates the
//! receiver to the sender.

use crate::crypto::SecretKey;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;
const CHECKSUM_LEN: usize = 3;
const ID_PREFIX: &str = "sh-";
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Public identity of a peer.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SharpId([u8; KEY_LEN]);

impl SharpId {
    pub fn from_public(key: [u8; KEY_LEN]) -> Self {
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Whether this is one of the handful of points every Diffie-Hellman
    /// with sends to zero, whatever the other side's secret. Such a "key"
    /// has no private half: anyone can claim it, and anything derived from
    /// it with our secret is a constant everybody can compute. No real
    /// identity is one, so it is refused wherever an identity comes in.
    ///
    /// Clamping makes every X25519 scalar a multiple of eight, which
    /// annihilates exactly the small-order points (on the curve and on its
    /// twist), so one multiplication by any scalar tells them apart.
    pub fn is_low_order(&self) -> bool {
        x25519_dalek::x25519([1; KEY_LEN], self.0) == [0; KEY_LEN]
    }

    /// Short form for display ("sh-abcdefgh…").
    pub fn short(&self) -> String {
        let full = self.to_string();
        format!("{}…", &full[..ID_PREFIX.len() + 8])
    }

    fn checksum(key: &[u8; KEY_LEN]) -> [u8; CHECKSUM_LEN] {
        let h = blake3::derive_key("sharp256 id checksum", key);
        [h[0], h[1], h[2]]
    }
}

impl fmt::Display for SharpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut data = [0u8; KEY_LEN + CHECKSUM_LEN];
        data[..KEY_LEN].copy_from_slice(&self.0);
        data[KEY_LEN..].copy_from_slice(&Self::checksum(&self.0));
        write!(f, "{}{}", ID_PREFIX, base32_encode(&data))
    }
}

impl fmt::Debug for SharpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharpId({})", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("a SHARP ID starts with \"sh-\"")]
    Prefix,
    #[error("a SHARP ID has 56 characters after \"sh-\" (a-z, 2-7)")]
    Encoding,
    #[error("SHARP ID checksum mismatch (typo?)")]
    Checksum,
    #[error("SHARP ID is not a usable public key")]
    Weak,
}

impl FromStr for SharpId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, IdError> {
        let s = s.trim();
        let rest = s
            .get(..ID_PREFIX.len())
            .filter(|p| p.eq_ignore_ascii_case(ID_PREFIX))
            .map(|_| &s[ID_PREFIX.len()..])
            .ok_or(IdError::Prefix)?;
        // Tolerate grouping characters that people insert when copying.
        let cleaned: String = rest.chars().filter(|c| !matches!(c, '-' | ' ')).collect();
        let data = base32_decode(&cleaned).ok_or(IdError::Encoding)?;
        if data.len() != KEY_LEN + CHECKSUM_LEN {
            return Err(IdError::Encoding);
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&data[..KEY_LEN]);
        if data[KEY_LEN..] != Self::checksum(&key) {
            return Err(IdError::Checksum);
        }
        let id = Self(key);
        if id.is_low_order() {
            return Err(IdError::Weak);
        }
        Ok(id)
    }
}

/// A local identity: X25519 static key pair. The private key is in locked
/// memory ([`SecretKey`]); clones share it.
#[derive(Clone)]
pub struct Identity {
    secret: SecretKey,
    public: [u8; KEY_LEN],
}

impl Identity {
    pub fn generate() -> Self {
        Self::from_key(SecretKey::random())
    }

    /// The identity with this private key. The array passed in is wiped.
    pub fn from_secret(mut secret: [u8; KEY_LEN]) -> Self {
        let key = SecretKey::from_bytes(&secret);
        secret.zeroize();
        Self::from_key(key)
    }

    fn from_key(secret: SecretKey) -> Self {
        // StaticSecret wipes its copy when dropped.
        let public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret.expose()))
                .to_bytes();
        Self { secret, public }
    }

    pub fn id(&self) -> SharpId {
        SharpId(self.public)
    }

    pub fn public(&self) -> &[u8; KEY_LEN] {
        &self.public
    }

    /// Private key bytes (for the Noise handshake).
    pub(crate) fn secret(&self) -> &[u8; KEY_LEN] {
        self.secret.expose()
    }

    /// The X25519 shared secret between this identity and `other`.
    ///
    /// Both sides compute the same value from their long-term keys alone,
    /// with no exchange at all. That is exactly what makes it unsuitable for
    /// a session — there is no forward secrecy and nothing fresh in it, which
    /// is why transfers use the Noise handshake instead. It is the right tool
    /// for proving to a party that already knows your public key that you
    /// hold the private one, which is what registering with a relay needs.
    ///
    /// `None` when `other` is a small-order point: the result would then be
    /// the same for every secret, known to anyone, and prove nothing.
    pub fn shared_secret(&self, other: &SharpId) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        let sk = x25519_dalek::StaticSecret::from(*self.secret());
        let pk = x25519_dalek::PublicKey::from(*other.as_bytes());
        let shared = sk.diffie_hellman(&pk);
        if !shared.was_contributory() {
            return None;
        }
        Some(Zeroizing::new(shared.to_bytes()))
    }

    /// Default location of the identity file in the per-user data directory.
    pub fn default_path() -> Option<PathBuf> {
        dirs::data_dir().map(|d| d.join("sharp-256").join("identity.key"))
    }

    /// Loads the identity stored at `path`, or creates and stores a new one.
    /// The file is created readable by its owner only.
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        // The file holds the private key: its bytes are read into memory
        // that is wiped afterwards.
        match fs::read(path).map(Zeroizing::new) {
            Ok(text) => {
                warn_if_exposed(path);
                Self::parse_file(&text).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} is not a SHARP-256 identity file", path.display()),
                    )
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let id = Self::generate();
                if let Some(dir) = path.parent() {
                    fs::create_dir_all(dir)?;
                }
                match write_private(path, &id.file_text()) {
                    Ok(()) => Ok(id),
                    // Another process created it first: use theirs.
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        Self::load_or_create(path)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// The file's contents. Written into a buffer of exactly its size, so
    /// that no copy of the key is left behind in a buffer that grew; the
    /// hex is made without a branch on the key (see [`hex_encode`]).
    fn file_text(&self) -> Zeroizing<Vec<u8>> {
        let head = format!(
            "# SHARP-256 identity {}\n# Keep this file private: whoever has it can act as this machine.\n",
            self.id()
        );
        let mut text = Zeroizing::new(Vec::with_capacity(head.len() + 2 * KEY_LEN + 1));
        text.extend_from_slice(head.as_bytes());
        let mut hex = Zeroizing::new([0u8; 2 * KEY_LEN]);
        hex_encode(self.secret.expose(), &mut hex[..]);
        text.extend_from_slice(&*hex);
        text.push(b'\n');
        text
    }

    fn parse_file(text: &[u8]) -> Option<Self> {
        let line = text
            .split(|&b| b == b'\n')
            .map(<[u8]>::trim_ascii)
            .find(|l| !l.is_empty() && !l.starts_with(b"#"))?;
        // Decoded straight into its locked place.
        let mut valid = false;
        let key = SecretKey::with(|k| valid = hex_decode(line, k));
        valid.then(|| Self::from_key(key))
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({})", self.id())
    }
}

/// Reads a list of SHARP IDs: one per line, anything after the ID (a name)
/// and lines starting with `#` are ignored.
pub fn load_id_list(path: &Path) -> io::Result<std::collections::HashSet<SharpId>> {
    let text = fs::read_to_string(path)?;
    let mut ids = std::collections::HashSet::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let word = line.split_whitespace().next().unwrap_or("");
        let id = word.parse::<SharpId>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}:{}: {}", path.display(), n + 1, e),
            )
        })?;
        ids.insert(id);
    }
    Ok(ids)
}

fn write_private(path: &Path, text: &[u8]) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(text)?;
    f.sync_all()
}

/// Lower-case hex of `bytes` into `out` (twice as long), computed without
/// a branch or a table lookup that depends on the bytes: this is how the
/// private key is written, and the time it takes must not say what it is.
/// (`format!("{:02x}")` picks the digit with a branch.)
fn hex_encode(bytes: &[u8], out: &mut [u8]) {
    debug_assert_eq!(out.len(), 2 * bytes.len());
    fn digit(n: u8) -> u8 {
        // n < 10: '0' + n; otherwise 'a' + n - 10, which is 39 further on.
        // (9 - n) is negative exactly when n > 9, and its sign, spread
        // over the byte by the arithmetic shift, selects the 39.
        let n = n as i16;
        (n + 0x30 + (((9 - n) >> 8) & 0x27)) as u8
    }
    for (b, pair) in bytes.iter().zip(out.chunks_exact_mut(2)) {
        pair[0] = digit(b >> 4);
        pair[1] = digit(b & 0x0f);
    }
}

/// The bytes written by `text` in hex (either case) into `out`, which it
/// must fill exactly; false if it is not that. The digits are read without
/// a branch on their value, for the reason given at [`hex_encode`]; only
/// whether the whole text was valid is decided at the end.
fn hex_decode(text: &[u8], out: &mut [u8]) -> bool {
    if text.len() != 2 * out.len() {
        return false;
    }
    /// The digit's value, or -1: each range adds its offset only when the
    /// character lies in it — `(lo - c) & (c - hi)` is negative exactly
    /// then, and its sign bit becomes the mask.
    fn value(c: u8) -> i16 {
        let c = c as i16;
        let mut v: i16 = -1;
        v += (((0x2f - c) & (c - 0x3a)) >> 8) & (c - 0x2f); // '0'..='9'
        v += (((0x40 - c) & (c - 0x47)) >> 8) & (c - 0x36); // 'A'..='F'
        v += (((0x60 - c) & (c - 0x67)) >> 8) & (c - 0x56); // 'a'..='f'
        v
    }
    let mut bad: i16 = 0;
    for (pair, byte) in text.chunks_exact(2).zip(out.iter_mut()) {
        let (hi, lo) = (value(pair[0]), value(pair[1]));
        bad |= hi | lo;
        *byte = ((hi << 4) | lo) as u8;
    }
    // -1 has the sign bit; every valid value is 0..=15.
    bad >= 0
}

fn warn_if_exposed(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                tracing::warn!(
                    "{} is readable by other users; restrict it with chmod 600",
                    path.display()
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Unpadded lowercase base32 (RFC 4648 alphabet).
pub(crate) fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Inverse of [`base32_encode`]; case-insensitive, rejects non-zero padding
/// bits so that every value has exactly one spelling.
pub(crate) fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        } as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 5 || acc != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let s = base32_encode(&data);
            assert_eq!(base32_decode(&s).unwrap(), data, "len {}", len);
            assert_eq!(base32_decode(&s.to_uppercase()).unwrap(), data);
        }
        assert!(base32_decode("a1").is_none());
    }

    /// The small-order points of Curve25519 and its twist, in every
    /// encoding X25519 accepts (the top bit is ignored, so each also comes
    /// with it set). Any of them sends every exchange to zero.
    pub(crate) fn low_order_points() -> Vec<[u8; KEY_LEN]> {
        let hex = |s: &str| -> [u8; KEY_LEN] {
            let mut out = [0u8; KEY_LEN];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        };
        let canonical = [
            hex("0000000000000000000000000000000000000000000000000000000000000000"),
            hex("0100000000000000000000000000000000000000000000000000000000000000"),
            hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            // p - 1, p and p + 1: non-canonical, but decoded all the same.
            hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ];
        let mut all = canonical.to_vec();
        for mut p in canonical {
            p[KEY_LEN - 1] |= 0x80;
            all.push(p);
        }
        all
    }

    #[test]
    fn a_key_with_no_private_half_is_not_an_identity() {
        let me = Identity::generate();
        for point in low_order_points() {
            let id = SharpId::from_public(point);
            assert!(id.is_low_order(), "{:02x?} was taken for a real key", point);
            // Typed in, it is refused like any other bad ID.
            assert_eq!(id.to_string().parse::<SharpId>(), Err(IdError::Weak));
            // And nothing is derived from it: the "secret" would be the
            // same constant for everyone.
            assert!(me.shared_secret(&id).is_none());
        }
        // Real keys are none of those, and agree on a secret.
        for _ in 0..64 {
            let other = Identity::generate();
            assert!(!other.id().is_low_order());
            assert_eq!(
                me.shared_secret(&other.id()).map(|k| *k),
                other.shared_secret(&me.id()).map(|k| *k)
            );
        }
    }

    #[test]
    fn ids_roundtrip_and_detect_typos() {
        let id = Identity::generate().id();
        let text = id.to_string();
        assert!(text.starts_with("sh-"));
        assert_eq!(text.len(), 3 + 56);
        assert_eq!(text.parse::<SharpId>().unwrap(), id);
        assert_eq!(text.to_uppercase().parse::<SharpId>().unwrap(), id);
        // Grouped for readability.
        let grouped = format!("{} {}", &text[..20], &text[20..]);
        assert_eq!(grouped.parse::<SharpId>().unwrap(), id);
        // One wrong character.
        let mut typo = text.clone().into_bytes();
        let i = 10;
        typo[i] = if typo[i] == b'a' { b'b' } else { b'a' };
        let typo = String::from_utf8(typo).unwrap();
        assert!(typo.parse::<SharpId>().is_err());
        assert_eq!("xx-abc".parse::<SharpId>(), Err(IdError::Prefix));
        assert_eq!("sh-abc".parse::<SharpId>(), Err(IdError::Encoding));
    }

    /// The branch-free hex is ordinary hex: every byte value is written as
    /// `format!` would write it and read back, in either case; anything
    /// that is not a hex digit, anywhere, is refused, and so is a wrong
    /// length.
    #[test]
    fn the_key_is_written_and_read_as_plain_hex() {
        let all: Vec<u8> = (0..=255).collect();
        let mut hex = vec![0u8; 512];
        hex_encode(&all, &mut hex);
        let expected: String = all.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, expected.as_bytes());
        let mut back = vec![0u8; 256];
        assert!(hex_decode(&hex, &mut back));
        assert_eq!(back, all);
        assert!(hex_decode(expected.to_uppercase().as_bytes(), &mut back));
        assert_eq!(back, all);
        let mut one = [0u8; 1];
        for c in 0..=255u8 {
            let valid = c.is_ascii_hexdigit();
            assert_eq!(
                hex_decode(&[c, b'0'], &mut one),
                valid,
                "{:?} first",
                c as char
            );
            assert_eq!(
                hex_decode(&[b'0', c], &mut one),
                valid,
                "{:?} second",
                c as char
            );
        }
        assert!(!hex_decode(b"0", &mut one));
        assert!(!hex_decode(b"000", &mut one));
        assert!(!hex_decode(b"", &mut one));
    }

    /// A file written the way identity files always were (`{:02x}` per
    /// byte, CRLF line ends allowed) is read as the same identity.
    #[test]
    fn an_identity_file_from_before_reads_the_same() {
        let secret: [u8; KEY_LEN] = std::array::from_fn(|i| (i * 29 + 3) as u8);
        let id = Identity::from_secret(secret);
        let hex: String = secret.iter().map(|b| format!("{:02x}", b)).collect();
        for text in [
            format!(
                "# SHARP-256 identity {}\n# Keep this file private.\n{}\n",
                id.id(),
                hex
            ),
            format!("# comment\r\n\r\n  {}  \r\n", hex.to_uppercase()),
        ] {
            let read = Identity::parse_file(text.as_bytes()).expect("an identity file");
            assert_eq!(read.id(), id.id());
            assert_eq!(read.secret(), &secret);
        }
        assert_eq!(&*id.file_text(), format!(
            "# SHARP-256 identity {}\n# Keep this file private: whoever has it can act as this machine.\n{}\n",
            id.id(),
            hex
        ).as_bytes());
    }

    #[test]
    fn identity_file_roundtrip_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("identity.key");
        let a = Identity::load_or_create(&path).unwrap();
        let b = Identity::load_or_create(&path).unwrap();
        assert_eq!(a.id(), b.id());
        assert_eq!(a.secret(), b.secret());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::write(&path, "garbage").unwrap();
        assert!(Identity::load_or_create(&path).is_err());
    }

    #[test]
    fn id_lists_ignore_comments_and_names() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (Identity::generate().id(), Identity::generate().id());
        let path = dir.path().join("allowed");
        fs::write(&path, format!("# senders\n{}  laptop\n\n{}\n", a, b)).unwrap();
        let ids = load_id_list(&path).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&a) && ids.contains(&b));
        fs::write(&path, "sh-typo\n").unwrap();
        assert!(load_id_list(&path).is_err());
    }

    #[test]
    fn public_key_matches_x25519() {
        let a = Identity::generate();
        let b = Identity::generate();
        let ab = x25519_dalek::StaticSecret::from(*a.secret())
            .diffie_hellman(&x25519_dalek::PublicKey::from(*b.public()));
        let ba = x25519_dalek::StaticSecret::from(*b.secret())
            .diffie_hellman(&x25519_dalek::PublicKey::from(*a.public()));
        assert_eq!(ab.as_bytes(), ba.as_bytes());
    }
}
