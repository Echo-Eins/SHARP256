//! Identity files, and keeping the private key in them sealed.
//!
//! An identity file is text. Its first lines say whose it is; then comes
//! the key, in one of two forms:
//!
//! ```text
//! # SHARP-256 identity sh-…
//! # Keep this file private: whoever has it can act as this machine.
//! 4e1f…(64 hex digits: the private key)
//! ```
//!
//! — the form every file had before, still read and still written when no
//! protection is asked for — or sealed:
//!
//! ```text
//! sharp256-identity-2 <public> passphrase argon2id <memory KiB> <passes> <lanes> <salt> <nonce> <sealed>
//! sharp256-identity-2 <public> keystore secret-service|keychain <nonce> <sealed>
//! sharp256-identity-2 <public> keystore dpapi <blob> <nonce> <sealed>
//! ```
//!
//! `sealed` is the private key encrypted with XChaCha20-Poly1305 under a
//! key that is either derived from a passphrase with Argon2id (with the
//! parameters and salt written before it) or kept by the operating system
//! (`crypto::keystore`); the associated data is the whole line before the
//! nonce, so that neither the public key nor any parameter can be changed
//! without the seal failing. The public key is in the clear, so a program
//! can say whose identity a file holds (`--id`) without opening it; once
//! opened, the private key must give that public key back, or the file is
//! refused as damaged.
//!
//! Every byte read from a file, every derived key and the private key live
//! in memory that is locked and wiped (`crypto::secret`). A file is always
//! replaced whole — written beside it, flushed to disk, renamed over it,
//! and the directory flushed — so that a crash in the middle leaves either
//! the old file or the new one, never half of one.

use crate::crypto::identity::{hex_decode, hex_encode, Identity, SharpId, KEY_LEN};
use crate::crypto::keystore::{self, Backend};
use crate::crypto::secret::{SecretKey, SecretText};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const TAG: &str = "sharp256-identity-2";
const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;
const SEALED_LEN: usize = KEY_LEN + 16;

/// Argon2id's cost for a passphrase: 256 MiB and three passes — half a
/// second and 262 MiB of memory on the machine this was measured on (a
/// Ryzen 9 5900HX). A file is opened once per start of a program, and
/// whoever has stolen it has as long as they like: the cost is what each
/// of their guesses takes. The cost is written into the file, so that a
/// file made with another opens all the same.
pub const PASSPHRASE_MEMORY_KIB: u32 = 256 * 1024;
pub const PASSPHRASE_PASSES: u32 = 3;
pub const PASSPHRASE_LANES: u32 = 1;

/// The environment variable a passphrase may be given in.
pub const PASSPHRASE_VAR: &str = "SHARP256_IDENTITY_PASSPHRASE";

/// How a file keeps its private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// In the clear, protected by the file's permissions alone.
    None,
    /// Sealed with a key derived from a passphrase.
    Passphrase,
    /// Sealed with a key the operating system keeps.
    Keystore(Backend),
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protection::None => f.write_str("not sealed (the file's permissions alone)"),
            Protection::Passphrase => f.write_str("sealed with a passphrase"),
            Protection::Keystore(b) => write!(f, "sealed with a key kept by {}", b),
        }
    }
}

/// How a file is to keep its private key from now on.
pub enum NewProtection<'a> {
    None,
    Passphrase(&'a str),
    Keystore(Backend),
}

/// What can go wrong with an identity file.
#[derive(Debug)]
pub enum IdentityError {
    Io(io::Error),
    /// Not an identity file, or not one this version understands.
    Unreadable(String),
    /// Sealed with a passphrase, and none was given.
    NeedsPassphrase(SharpId),
    /// The passphrase does not open it.
    WrongPassphrase(SharpId),
    /// The operating system's store would not give the key.
    Keystore(SharpId, keystore::Error),
    /// It opened, but the key in it is not the key it says it is — or the
    /// seal failed with a key the store gave: the file was changed.
    Damaged(SharpId),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::Io(e) => write!(f, "{}", e),
            IdentityError::Unreadable(why) => write!(f, "not a SHARP-256 identity file: {}", why),
            IdentityError::NeedsPassphrase(id) => write!(
                f,
                "identity {} is sealed with a passphrase; give it on the terminal, in {}, or with --identity-passphrase-file",
                id.short(),
                PASSPHRASE_VAR
            ),
            IdentityError::WrongPassphrase(id) => {
                write!(f, "the passphrase does not open identity {}", id.short())
            }
            IdentityError::Keystore(id, e) => {
                write!(f, "identity {} cannot be opened: {}", id.short(), e)
            }
            IdentityError::Damaged(id) => write!(
                f,
                "identity file of {} has been changed: the key in it does not match",
                id.short()
            ),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<io::Error> for IdentityError {
    fn from(e: io::Error) -> Self {
        IdentityError::Io(e)
    }
}

impl From<IdentityError> for io::Error {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::Io(e) => e,
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}

/// Argon2id parameters, as a file records them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cost {
    memory_kib: u32,
    passes: u32,
    lanes: u32,
}

impl Cost {
    const DEFAULT: Cost = Cost {
        memory_kib: PASSPHRASE_MEMORY_KIB,
        passes: PASSPHRASE_PASSES,
        lanes: PASSPHRASE_LANES,
    };

    fn key(&self, passphrase: &str, salt: &[u8]) -> Result<SecretKey, String> {
        let params = argon2::Params::new(self.memory_kib, self.passes, self.lanes, Some(32))
            .map_err(|e| format!("Argon2 parameters: {}", e))?;
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut failed = None;
        let key = SecretKey::with(|k| {
            if let Err(e) = argon.hash_password_into(passphrase.as_bytes(), salt, k) {
                failed = Some(e.to_string());
            }
        });
        match failed {
            None => Ok(key),
            Some(e) => Err(e),
        }
    }
}

enum How {
    Passphrase { cost: Cost, salt: [u8; SALT_LEN] },
    Keystore { backend: Backend, blob: Vec<u8> },
}

enum Body {
    Plain(SecretKey),
    Sealed {
        how: How,
        /// The line up to the nonce: what the seal authenticates.
        aad: String,
        nonce: [u8; NONCE_LEN],
        sealed: [u8; SEALED_LEN],
    },
}

/// An identity file as read: whose it is, and what opening it takes.
pub struct IdentityFile {
    public: [u8; KEY_LEN],
    body: Body,
}

fn unreadable(why: &str) -> IdentityError {
    IdentityError::Unreadable(why.to_string())
}

fn hex_field<const N: usize>(field: Option<&str>, what: &str) -> Result<[u8; N], IdentityError> {
    let mut out = [0u8; N];
    match field {
        Some(text) if hex_decode(text.as_bytes(), &mut out) => Ok(out),
        _ => Err(IdentityError::Unreadable(format!(
            "{} is missing or not hex",
            what
        ))),
    }
}

fn number(field: Option<&str>, what: &str) -> Result<u32, IdentityError> {
    field
        .and_then(|f| f.parse().ok())
        .ok_or_else(|| IdentityError::Unreadable(format!("{} is missing or not a number", what)))
}

impl IdentityFile {
    /// Reads the file at `path`. Opening it is a separate step.
    pub fn read(path: &Path) -> Result<Self, IdentityError> {
        // It holds the private key: read into memory that is wiped.
        let text = Zeroizing::new(fs::read(path)?);
        warn_if_exposed(path);
        Self::parse(&text)
    }

    pub(crate) fn parse(text: &[u8]) -> Result<Self, IdentityError> {
        let line = text
            .split(|&b| b == b'\n')
            .map(<[u8]>::trim_ascii)
            .find(|l| !l.is_empty() && !l.starts_with(b"#"))
            .ok_or_else(|| unreadable("it holds no key"))?;
        if !line.starts_with(TAG.as_bytes()) {
            // The form every file had before: the private key in hex.
            let mut valid = false;
            let key = SecretKey::with(|k| valid = hex_decode(line, k));
            if !valid {
                return Err(unreadable("the key is not 64 hexadecimal digits"));
            }
            let identity = Identity::from_key(key.clone());
            return Ok(Self {
                public: *identity.public(),
                body: Body::Plain(key),
            });
        }
        let line = std::str::from_utf8(line).map_err(|_| unreadable("not text"))?;
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.len() < 5 {
            return Err(unreadable("the sealed key's line is cut short"));
        }
        let public: [u8; KEY_LEN] = hex_field(fields.get(1).copied(), "the public key")?;
        let (how, rest) = match (fields[2], fields.get(3).copied()) {
            ("passphrase", Some("argon2id")) => {
                let cost = Cost {
                    memory_kib: number(fields.get(4).copied(), "Argon2's memory")?,
                    passes: number(fields.get(5).copied(), "Argon2's passes")?,
                    lanes: number(fields.get(6).copied(), "Argon2's lanes")?,
                };
                let salt = hex_field(fields.get(7).copied(), "the salt")?;
                (How::Passphrase { cost, salt }, 8)
            }
            ("keystore", Some("dpapi")) => {
                let blob = fields
                    .get(4)
                    .and_then(|f| {
                        let mut b = vec![0u8; f.len() / 2];
                        hex_decode(f.as_bytes(), &mut b).then_some(b)
                    })
                    .ok_or_else(|| unreadable("the sealed key is missing"))?;
                (
                    How::Keystore {
                        backend: Backend::Dpapi,
                        blob,
                    },
                    5,
                )
            }
            ("keystore", Some(name)) => {
                let backend = Backend::from_name(name).ok_or_else(|| {
                    IdentityError::Unreadable(format!(
                        "a store this version does not know: {}",
                        name
                    ))
                })?;
                (
                    How::Keystore {
                        backend,
                        blob: Vec::new(),
                    },
                    4,
                )
            }
            (method, _) => {
                return Err(IdentityError::Unreadable(format!(
                    "sealed in a way this version does not know: {}",
                    method
                )))
            }
        };
        if fields.len() != rest + 2 {
            return Err(unreadable(
                "the sealed key's line has the wrong number of fields",
            ));
        }
        let nonce = hex_field(fields.get(rest).copied(), "the nonce")?;
        let sealed = hex_field(fields.get(rest + 1).copied(), "the sealed key")?;
        Ok(Self {
            public,
            body: Body::Sealed {
                how,
                aad: fields[..rest].join(" "),
                nonce,
                sealed,
            },
        })
    }

    /// Whose identity it is — known without opening it.
    pub fn id(&self) -> SharpId {
        SharpId::from_public(self.public)
    }

    pub fn protection(&self) -> Protection {
        match &self.body {
            Body::Plain(_) => Protection::None,
            Body::Sealed {
                how: How::Passphrase { .. },
                ..
            } => Protection::Passphrase,
            Body::Sealed {
                how: How::Keystore { backend, .. },
                ..
            } => Protection::Keystore(*backend),
        }
    }

    /// The identity, opened with `passphrase` if it is sealed with one, or
    /// with the key the operating system keeps for it.
    pub fn open(&self, passphrase: Option<&str>) -> Result<Identity, IdentityError> {
        let id = self.id();
        let (key, aad, nonce, sealed, wrong) = match &self.body {
            Body::Plain(key) => return Ok(Identity::from_key(key.clone())),
            Body::Sealed {
                how: How::Passphrase { cost, salt },
                aad,
                nonce,
                sealed,
            } => {
                let passphrase = passphrase.ok_or(IdentityError::NeedsPassphrase(id))?;
                let key = cost.key(passphrase, salt).map_err(|e| {
                    IdentityError::Unreadable(format!("the passphrase could not be used: {}", e))
                })?;
                (key, aad, nonce, sealed, IdentityError::WrongPassphrase(id))
            }
            Body::Sealed {
                how: How::Keystore { backend, blob },
                aad,
                nonce,
                sealed,
            } => {
                let key = keystore::get(*backend, &self.public, blob)
                    .map_err(|e| IdentityError::Keystore(id, e))?;
                (key, aad, nonce, sealed, IdentityError::Damaged(id))
            }
        };
        let mut failed = false;
        let secret = SecretKey::with(|k| {
            let mut buf = *sealed;
            let (body, tag) = buf.split_at_mut(KEY_LEN);
            let opened = XChaCha20Poly1305::new(key.expose().into()).decrypt_in_place_detached(
                nonce.into(),
                aad.as_bytes(),
                body,
                (&*tag).into(),
            );
            match opened {
                Ok(()) => k.copy_from_slice(body),
                Err(_) => failed = true,
            }
            buf.zeroize();
        });
        if failed {
            return Err(wrong);
        }
        let identity = Identity::from_key(secret);
        if identity.public() != &self.public {
            return Err(IdentityError::Damaged(id));
        }
        Ok(identity)
    }
}

/// The contents of an unsealed file for `identity`.
pub(crate) fn render_plain(identity: &Identity) -> Zeroizing<Vec<u8>> {
    render(identity, &NewProtection::None, Cost::DEFAULT).expect("an unsealed file is always made")
}

/// The file's contents for `identity`, protected as asked.
fn render(
    identity: &Identity,
    protection: &NewProtection,
    cost: Cost,
) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let id = identity.id();
    let public = hex_of(identity.public());
    let (note, line_head, key) = match protection {
        NewProtection::None => {
            let mut text = Zeroizing::new(Vec::new());
            text.extend_from_slice(
                format!(
                    "# SHARP-256 identity {}\n# Keep this file private: whoever has it can act as this machine.\n",
                    id
                )
                .as_bytes(),
            );
            let mut hex = Zeroizing::new([0u8; 2 * KEY_LEN]);
            hex_encode(identity.secret(), &mut hex[..]);
            text.extend_from_slice(&hex[..]);
            text.push(b'\n');
            return Ok(text);
        }
        NewProtection::Passphrase(passphrase) => {
            let mut salt = [0u8; SALT_LEN];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            let key = cost.key(passphrase, &salt).map_err(|e| {
                IdentityError::Unreadable(format!("the passphrase could not be used: {}", e))
            })?;
            (
                "Its private key is sealed with a passphrase (Argon2id); without the passphrase this file is of no use to anyone.",
                format!(
                    "{} {} passphrase argon2id {} {} {} {}",
                    TAG,
                    public,
                    cost.memory_kib,
                    cost.passes,
                    cost.lanes,
                    hex_of(&salt)
                ),
                key,
            )
        }
        NewProtection::Keystore(backend) => {
            let key = SecretKey::random();
            let blob = keystore::put(*backend, identity.public(), &key)
                .map_err(|e| IdentityError::Keystore(id, e))?;
            let head = if blob.is_empty() {
                format!("{} {} keystore {}", TAG, public, backend.name())
            } else {
                format!(
                    "{} {} keystore {} {}",
                    TAG,
                    public,
                    backend.name(),
                    hex_of(&blob)
                )
            };
            (
                match backend {
                    Backend::SecretService => "Its private key is sealed with a key the Secret Service keeps for the user who sealed it.",
                    Backend::Keychain => "Its private key is sealed with a key the Keychain keeps for the user who sealed it.",
                    Backend::Dpapi => "Its private key is sealed by Windows for the account that sealed it.",
                },
                head,
                key,
            )
        }
    };
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut sealed = Zeroizing::new([0u8; SEALED_LEN]);
    sealed[..KEY_LEN].copy_from_slice(identity.secret());
    let (body, tag_room) = sealed.split_at_mut(KEY_LEN);
    let tag = XChaCha20Poly1305::new(key.expose().into())
        .encrypt_in_place_detached((&nonce).into(), line_head.as_bytes(), body)
        .map_err(|_| IdentityError::Unreadable("sealing failed".to_string()))?;
    tag_room.copy_from_slice(&tag);
    let text = format!(
        "# SHARP-256 identity {}\n# {}\n{} {} {}\n",
        id,
        note,
        line_head,
        hex_of(&nonce),
        hex_of(&sealed[..])
    );
    Ok(Zeroizing::new(text.into_bytes()))
}

fn hex_of(bytes: &[u8]) -> String {
    let mut hex = vec![0u8; 2 * bytes.len()];
    hex_encode(bytes, &mut hex);
    String::from_utf8(hex).expect("hex is text")
}

/// Writes `identity` to `path`, protected as asked, replacing whatever file
/// is there — whole, as the module's documentation describes. When the old
/// file's key was kept by the operating system and the new one's is not,
/// the store's entry is removed afterwards.
pub fn save(
    path: &Path,
    identity: &Identity,
    protection: &NewProtection,
) -> Result<(), IdentityError> {
    save_with_cost(path, identity, protection, Cost::DEFAULT)
}

fn save_with_cost(
    path: &Path,
    identity: &Identity,
    protection: &NewProtection,
    cost: Cost,
) -> Result<(), IdentityError> {
    let before = IdentityFile::read(path).ok().map(|f| f.protection());
    let text = render(identity, protection, cost)?;
    if let Err(e) = replace(path, &text) {
        // The store took a key for a file that was never written.
        if let NewProtection::Keystore(backend) = protection {
            if before != Some(Protection::Keystore(*backend)) {
                let _ = keystore::remove(*backend, identity.public());
            }
        }
        return Err(e.into());
    }
    if let Some(Protection::Keystore(old)) = before {
        let still = matches!(protection, NewProtection::Keystore(b) if *b == old);
        if !still {
            if let Err(e) = keystore::remove(old, identity.public()) {
                tracing::warn!(
                    "the old key of {} is still kept: {}",
                    identity.id().short(),
                    e
                );
            }
        }
    }
    Ok(())
}

/// Creates a new file at `path` with `text`, or replaces the one there,
/// without a moment in which half a file is there: written beside it,
/// flushed, renamed over it, and the directory flushed so that the rename
/// itself is on disk.
pub(crate) fn replace(path: &Path, text: &[u8]) -> io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&dir)?;
    let mut name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?
        .to_os_string();
    name.push(format!(".{:016x}.tmp", rand::rngs::OsRng.next_u64()));
    let tmp = dir.join(name);
    let result = (|| {
        write_private(&tmp, text)?;
        fs::rename(&tmp, path)?;
        sync_dir(&dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Creates `path` readable by its owner only, writes `text` and flushes it
/// to disk; refuses if something is there.
pub(crate) fn write_private(path: &Path, text: &[u8]) -> io::Result<()> {
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

/// Flushes a directory's entries, so that a file created or renamed in it
/// survives a crash. (Windows has no such call; its renames are journaled.)
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
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

/// Where a program looks for the passphrase of a sealed identity file, in
/// this order: a file named on its command line, the environment variable
/// [`PASSPHRASE_VAR`], and — if `ask` says so — the terminal.
#[derive(Default)]
pub struct PassphraseFrom<'a> {
    pub file: Option<&'a Path>,
    pub ask: bool,
}

impl PassphraseFrom<'_> {
    /// The passphrase for `id`, if any of the sources has one.
    pub fn get(&self, id: &SharpId) -> Result<Option<SecretText>, IdentityError> {
        if let Some(path) = self.file {
            return Ok(Some(read_passphrase_file(path)?));
        }
        if let Some(value) = std::env::var_os(PASSPHRASE_VAR) {
            let text = value
                .into_string()
                .map_err(|_| unreadable("the passphrase in the environment is not text"))?;
            return Ok(Some(SecretText::new(text)));
        }
        if self.ask {
            let prompt = format!("Passphrase of identity {}: ", id.short());
            return match rpassword::prompt_password(prompt) {
                Ok(text) => Ok(Some(SecretText::new(text))),
                // No terminal to ask on.
                Err(_) => Ok(None),
            };
        }
        Ok(None)
    }

    /// A new passphrase: from the file or the environment as it is, or asked
    /// twice on the terminal, and not accepted empty.
    pub fn new_passphrase(&self, id: &SharpId) -> Result<SecretText, IdentityError> {
        if self.file.is_some() || std::env::var_os(PASSPHRASE_VAR).is_some() {
            let given = self.get(id)?.expect("a source was there");
            if given.is_empty() {
                return Err(unreadable("the passphrase is empty"));
            }
            return Ok(given);
        }
        let ask = |prompt: &str| {
            rpassword::prompt_password(prompt)
                .map(SecretText::new)
                .map_err(|e| {
                    IdentityError::Io(io::Error::new(
                        e.kind(),
                        format!("no terminal to ask on ({})", e),
                    ))
                })
        };
        let first = ask(&format!("New passphrase of identity {}: ", id.short()))?;
        if first.is_empty() {
            return Err(unreadable("the passphrase is empty"));
        }
        let again = ask("The same again: ")?;
        if *first != *again {
            return Err(unreadable("the two passphrases differ"));
        }
        Ok(first)
    }
}

/// The first line of a file, as a passphrase (a trailing line end is not
/// part of it).
fn read_passphrase_file(path: &Path) -> Result<SecretText, IdentityError> {
    let mut bytes = Zeroizing::new(fs::read(path)?);
    let end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(bytes.len());
    bytes.truncate(end);
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| unreadable("the passphrase file is not text"))?
        .to_string();
    Ok(SecretText::new(text))
}

/// The identity at `path`, for a program: created (not sealed) if there is
/// none, opened with the passphrase from `passphrase` if it is sealed with
/// one.
pub fn open_or_create(path: &Path, passphrase: &PassphraseFrom) -> Result<Identity, IdentityError> {
    let file = match IdentityFile::read(path) {
        Ok(file) => file,
        Err(IdentityError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
            return Identity::load_or_create(path).map_err(IdentityError::Io);
        }
        Err(e) => return Err(e),
    };
    let given = match file.protection() {
        Protection::Passphrase => passphrase.get(&file.id())?,
        _ => None,
    };
    file.open(given.as_deref())
}

/// How `--protect-identity` asks a file to be kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ProtectAs {
    /// The private key in the clear, protected by the file's permissions.
    None,
    /// Sealed with a passphrase (Argon2id), asked for whenever the
    /// identity is used.
    Passphrase,
    /// Sealed with a key the operating system keeps for this user: the
    /// Secret Service, the Keychain or DPAPI.
    Keystore,
}

/// The ID of the identity at `path` — created, unsealed, if there is none —
/// without opening a sealed file.
pub fn id_of(path: &Path) -> Result<SharpId, IdentityError> {
    match IdentityFile::read(path) {
        Ok(file) => Ok(file.id()),
        Err(IdentityError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
            Ok(Identity::load_or_create(path)?.id())
        }
        Err(e) => Err(e),
    }
}

/// Seals the identity file at `path` as `how` says (creating an identity if
/// there is none), and says what was done. The current passphrase, if the
/// file has one, comes from `from`; a new one is asked twice on the
/// terminal — or, if the file had no passphrase before, may come from
/// `from` as well.
pub fn protect(
    path: &Path,
    how: ProtectAs,
    from: &PassphraseFrom,
) -> Result<String, IdentityError> {
    let before = IdentityFile::read(path).ok().map(|f| f.protection());
    let identity = open_or_create(path, from)?;
    let id = identity.id();
    let new_passphrase;
    let protection = match how {
        ProtectAs::None => NewProtection::None,
        ProtectAs::Passphrase => {
            new_passphrase = if before == Some(Protection::Passphrase) {
                // The sources gave the old one; the new one must be typed.
                PassphraseFrom::default().new_passphrase(&id)?
            } else {
                from.new_passphrase(&id)?
            };
            NewProtection::Passphrase(&new_passphrase)
        }
        ProtectAs::Keystore => {
            NewProtection::Keystore(Backend::of_this_system().ok_or_else(|| {
                IdentityError::Unreadable("this system has no store for keys".to_string())
            })?)
        }
    };
    save(path, &identity, &protection)?;
    let now = IdentityFile::read(path)?.protection();
    Ok(format!("identity {} ({}) is {}", id, path.display(), now))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cost the tests can afford.
    const CHEAP: Cost = Cost {
        memory_kib: 64,
        passes: 1,
        lanes: 1,
    };

    #[test]
    fn a_passphrase_seals_and_opens_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let identity = Identity::generate();
        save_with_cost(
            &path,
            &identity,
            &NewProtection::Passphrase("correct horse"),
            CHEAP,
        )
        .unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(&hex_of(identity.secret())),
            "the key is in the clear"
        );
        assert!(text.contains(&identity.id().to_string()));
        let file = IdentityFile::read(&path).unwrap();
        assert_eq!(file.id(), identity.id());
        assert_eq!(file.protection(), Protection::Passphrase);
        let opened = file.open(Some("correct horse")).unwrap();
        assert_eq!(opened.secret(), identity.secret());
        assert!(matches!(
            file.open(Some("correct horsf")),
            Err(IdentityError::WrongPassphrase(_))
        ));
        assert!(matches!(
            file.open(None),
            Err(IdentityError::NeedsPassphrase(_))
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    /// Any change to the sealed line — the public key, a parameter, the
    /// salt, the nonce or the sealed key itself — and it does not open.
    #[test]
    fn a_changed_file_does_not_open() {
        let identity = Identity::generate();
        let text = render(&identity, &NewProtection::Passphrase("pw"), CHEAP).unwrap();
        let text = String::from_utf8(text.to_vec()).unwrap();
        let line = text
            .lines()
            .find(|l| l.starts_with(TAG))
            .unwrap()
            .to_string();
        let fields: Vec<&str> = line.split(' ').collect();
        for i in 1..fields.len() {
            if fields[i] == "passphrase" || fields[i] == "argon2id" {
                continue;
            }
            let mut changed: Vec<String> = fields.iter().map(|f| f.to_string()).collect();
            // A different digit, or a different number of passes.
            let f = &mut changed[i];
            let c = f.pop().unwrap();
            f.push(if c == '0' { '1' } else { '0' });
            let bad = text.replace(&line, &changed.join(" "));
            let opened = IdentityFile::parse(bad.as_bytes()).and_then(|f| f.open(Some("pw")));
            assert!(opened.is_err(), "field {} changed and it still opened", i);
        }
        // Unchanged, it opens.
        let file = IdentityFile::parse(text.as_bytes()).unwrap();
        assert_eq!(file.open(Some("pw")).unwrap().id(), identity.id());
    }

    /// Unsealed files are the form they always were, and read the same.
    #[test]
    fn an_unsealed_file_is_the_old_form() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.key");
        let identity = Identity::generate();
        save(&path, &identity, &NewProtection::None).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains(&hex_of(identity.secret())));
        let file = IdentityFile::read(&path).unwrap();
        assert_eq!(file.protection(), Protection::None);
        assert_eq!(file.open(None).unwrap().secret(), identity.secret());
        assert_eq!(Identity::load_or_create(&path).unwrap().id(), identity.id());
    }

    /// A file sealed, unsealed and sealed again keeps its identity; the
    /// replacement leaves no temporary file behind.
    #[test]
    fn protection_changes_and_the_identity_stays() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let identity = Identity::load_or_create(&path).unwrap();
        save_with_cost(&path, &identity, &NewProtection::Passphrase("one"), CHEAP).unwrap();
        let opened = IdentityFile::read(&path)
            .unwrap()
            .open(Some("one"))
            .unwrap();
        save(&path, &opened, &NewProtection::None).unwrap();
        save_with_cost(&path, &opened, &NewProtection::Passphrase("two"), CHEAP).unwrap();
        let last = IdentityFile::read(&path).unwrap();
        assert!(last.open(Some("one")).is_err());
        assert_eq!(last.open(Some("two")).unwrap().id(), identity.id());
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{:?}", names);
    }

    /// A program opens a sealed file with the passphrase from a file or the
    /// environment, says what it needs when it has none, and still creates
    /// a new identity where there is none.
    #[test]
    fn a_program_finds_the_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let created = open_or_create(&path, &PassphraseFrom::default()).unwrap();
        save_with_cost(
            &path,
            &created,
            &NewProtection::Passphrase("from a file"),
            CHEAP,
        )
        .unwrap();
        let pw = dir.path().join("pw");
        fs::write(&pw, "from a file\r\n").unwrap();
        let opened = open_or_create(
            &path,
            &PassphraseFrom {
                file: Some(&pw),
                ask: false,
            },
        )
        .unwrap();
        assert_eq!(opened.id(), created.id());
        // (The environment variable is left alone: tests run side by side.)
        if std::env::var_os(PASSPHRASE_VAR).is_none() {
            match open_or_create(&path, &PassphraseFrom::default()) {
                Err(e @ IdentityError::NeedsPassphrase(_)) => {
                    assert!(e.to_string().contains(PASSPHRASE_VAR))
                }
                other => panic!(
                    "expected a request for the passphrase, got {:?}",
                    other.map(|i| i.id())
                ),
            }
        }
    }

    /// What is not an identity file is refused with a reason, and so is a
    /// seal this version does not know.
    #[test]
    fn what_is_not_one_is_refused() {
        for text in [
            "",
            "# only comments\n",
            "abc\n",
            "sharp256-identity-2 00\n",
            "sharp256-identity-2 0000000000000000000000000000000000000000000000000000000000000000 quantum a b\n",
            "sharp256-identity-2 0000000000000000000000000000000000000000000000000000000000000000 keystore floppy 00 00\n",
        ] {
            assert!(
                matches!(IdentityFile::parse(text.as_bytes()), Err(IdentityError::Unreadable(_))),
                "{:?}",
                text
            );
        }
    }

    /// The operating system's store, for real: needs a Secret Service that
    /// may be written to — `scripts/keystore-test.sh` starts a private one
    /// (gnome-keyring in its own D-Bus session) so that nobody's own
    /// keyring is touched.
    #[test]
    #[ignore]
    fn the_keystore_seals_and_opens_it() {
        let backend = Backend::of_this_system().expect("a store on this system");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let identity = Identity::generate();
        save(&path, &identity, &NewProtection::Keystore(backend)).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&hex_of(identity.secret())));
        let file = IdentityFile::read(&path).unwrap();
        assert_eq!(file.protection(), Protection::Keystore(backend));
        assert_eq!(file.open(None).unwrap().secret(), identity.secret());
        // The store forgets the key when the file is sealed otherwise, and
        // then the old file does not open any more.
        let copy = dir.path().join("copy.key");
        fs::copy(&path, &copy).unwrap();
        save_with_cost(&path, &identity, &NewProtection::Passphrase("x"), CHEAP).unwrap();
        assert!(matches!(
            IdentityFile::read(&copy).unwrap().open(None),
            Err(IdentityError::Keystore(..))
        ));
        assert_eq!(
            IdentityFile::read(&path)
                .unwrap()
                .open(Some("x"))
                .unwrap()
                .id(),
            identity.id()
        );
    }
}
