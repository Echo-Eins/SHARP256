//! Long-term identities (X25519 key pairs) and their textual form.
//!
//! A *SHARP ID* is the public half of an identity written as
//! `sh-` followed by 56 base32 characters: the 32-byte public key and a
//! 3-byte checksum, so that a mistyped ID is rejected instead of silently
//! addressing somebody else. Knowing a receiver's ID is what allows a sender
//! to reach it at all (see `handshake`), and the ID authenticates the
//! receiver to the sender.

use rand::RngCore;
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
        Ok(Self(key))
    }
}

/// A local identity: X25519 static key pair.
#[derive(Clone)]
pub struct Identity {
    secret: Zeroizing<[u8; KEY_LEN]>,
    public: [u8; KEY_LEN],
}

impl Identity {
    pub fn generate() -> Self {
        let mut secret = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let id = Self::from_secret(secret);
        secret.zeroize();
        id
    }

    pub fn from_secret(secret: [u8; KEY_LEN]) -> Self {
        let sk = x25519_dalek::StaticSecret::from(secret);
        let public = x25519_dalek::PublicKey::from(&sk).to_bytes();
        Self {
            secret: Zeroizing::new(sk.to_bytes()),
            public,
        }
    }

    pub fn id(&self) -> SharpId {
        SharpId(self.public)
    }

    pub fn public(&self) -> &[u8; KEY_LEN] {
        &self.public
    }

    /// Private key bytes (for the Noise handshake).
    pub(crate) fn secret(&self) -> &[u8; KEY_LEN] {
        &self.secret
    }

    /// Default location of the identity file in the per-user data directory.
    pub fn default_path() -> Option<PathBuf> {
        dirs::data_dir().map(|d| d.join("sharp-256").join("identity.key"))
    }

    /// Loads the identity stored at `path`, or creates and stores a new one.
    /// The file is created readable by its owner only.
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        match fs::read_to_string(path) {
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

    fn file_text(&self) -> Zeroizing<String> {
        let mut hex = String::with_capacity(2 * KEY_LEN);
        for b in self.secret.iter() {
            hex.push_str(&format!("{:02x}", b));
        }
        Zeroizing::new(format!(
            "# SHARP-256 identity {}\n# Keep this file private: whoever has it can act as this machine.\n{}\n",
            self.id(),
            hex
        ))
    }

    fn parse_file(text: &str) -> Option<Self> {
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))?;
        if line.len() != 2 * KEY_LEN {
            return None;
        }
        let mut secret = Zeroizing::new([0u8; KEY_LEN]);
        for (i, byte) in secret.iter_mut().enumerate() {
            *byte = u8::from_str_radix(line.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(Self::from_secret(*secret))
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

fn write_private(path: &Path, text: &str) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()
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
mod tests {
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
