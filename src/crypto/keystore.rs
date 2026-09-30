//! The operating system's store for secrets, where an identity file
//! protected by it keeps the key that opens it (`crypto::identity_file`):
//! the Secret Service on Linux and the BSDs (GNOME Keyring, KWallet,
//! KeePassXC — whatever answers `org.freedesktop.secrets`), the Keychain
//! on macOS, DPAPI on Windows.
//!
//! What is kept is a random 32-byte key that seals the identity's private
//! key in its file, never the private key itself: the file stays the one
//! place the identity is, and losing the store's entry loses the identity
//! the way losing a passphrase would. The store unlocks with the user's
//! session (DPAPI: the Windows account; the Keychain and the Secret Service:
//! their own login), so a protected identity opens without being asked for
//! anything while the user is logged in, and not for anybody who has only
//! the file.
//!
//! The Secret Service is spoken through `secret-tool` (libsecret's command
//! line, `libsecret-tools` in most distributions) rather than a D-Bus
//! library: it is where the Secret Service is installed anyway, and it
//! adds nothing to what the program is built from. The key goes to it
//! through a pipe, never on a command line.

use crate::crypto::SecretKey;
use std::fmt;

/// Where a protected identity's key is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    SecretService,
    Keychain,
    Dpapi,
}

impl Backend {
    /// As written in an identity file.
    pub fn name(self) -> &'static str {
        match self {
            Backend::SecretService => "secret-service",
            Backend::Keychain => "keychain",
            Backend::Dpapi => "dpapi",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "secret-service" => Some(Backend::SecretService),
            "keychain" => Some(Backend::Keychain),
            "dpapi" => Some(Backend::Dpapi),
            _ => None,
        }
    }

    /// This system's store.
    pub fn of_this_system() -> Option<Self> {
        if cfg!(windows) {
            Some(Backend::Dpapi)
        } else if cfg!(target_os = "macos") {
            Some(Backend::Keychain)
        } else if cfg!(unix) {
            Some(Backend::SecretService)
        } else {
            None
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Backend::SecretService => "the Secret Service",
            Backend::Keychain => "the Keychain",
            Backend::Dpapi => "Windows (DPAPI)",
        })
    }
}

/// Why the store would not do it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name an identity's key is kept under: one entry per identity, so
/// that several identity files each have their own.
#[cfg(unix)]
fn account(public: &[u8; 32]) -> String {
    format!("identity {}", crate::crypto::SharpId::from_public(*public))
}

#[cfg(unix)]
const SERVICE: &str = "sharp-256";

/// Keeps `key` for the identity `public` in `backend`. Returns what the
/// file must carry to find it again: for DPAPI the sealed key itself
/// (Windows keeps no entry; it seals to the account), for the others
/// nothing.
pub fn put(backend: Backend, public: &[u8; 32], key: &SecretKey) -> Result<Vec<u8>, Error> {
    match backend {
        Backend::SecretService => secret_service::put(public, key).map(|()| Vec::new()),
        Backend::Keychain => keychain::put(public, key).map(|()| Vec::new()),
        Backend::Dpapi => dpapi::protect(public, key),
    }
}

/// The key kept for `public`; `blob` is what `put` returned.
pub fn get(backend: Backend, public: &[u8; 32], blob: &[u8]) -> Result<SecretKey, Error> {
    match backend {
        Backend::SecretService => secret_service::get(public),
        Backend::Keychain => keychain::get(public),
        Backend::Dpapi => dpapi::unprotect(public, blob),
    }
}

/// Forgets the key kept for `public` (when its file is protected otherwise
/// from now on). Nothing to do for DPAPI.
pub fn remove(backend: Backend, public: &[u8; 32]) -> Result<(), Error> {
    match backend {
        Backend::SecretService => secret_service::remove(public),
        Backend::Keychain => keychain::remove(public),
        Backend::Dpapi => Ok(()),
    }
}

/// A 32-byte key from its hex, into locked memory.
#[cfg(unix)]
fn key_from_hex(hex: &[u8]) -> Option<SecretKey> {
    let mut valid = false;
    let key = SecretKey::with(|k| valid = crate::crypto::identity::hex_decode(hex, k));
    valid.then_some(key)
}

#[cfg(unix)]
mod secret_service {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use zeroize::Zeroize;

    /// `secret-tool`, or `SHARP256_SECRET_TOOL` in its place (for tests).
    fn tool() -> Command {
        let program =
            std::env::var_os("SHARP256_SECRET_TOOL").unwrap_or_else(|| "secret-tool".into());
        Command::new(program)
    }

    fn attributes(public: &[u8; 32]) -> [String; 4] {
        [
            "application".to_string(),
            SERVICE.to_string(),
            "identity".to_string(),
            crate::crypto::SharpId::from_public(*public).to_string(),
        ]
    }

    fn unavailable(e: std::io::Error) -> Error {
        Error(format!(
            "secret-tool, which speaks to the Secret Service, could not be run ({}); \
             install libsecret's tools (libsecret-tools), or protect the identity with a passphrase",
            e
        ))
    }

    pub fn put(public: &[u8; 32], key: &SecretKey) -> Result<(), Error> {
        let label = format!("SHARP-256 {}", account(public));
        let mut child = tool()
            .arg("store")
            .arg(format!("--label={}", label))
            .args(attributes(public))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(unavailable)?;
        let mut hex = zeroize::Zeroizing::new([0u8; 64]);
        crate::crypto::identity::hex_encode(key.expose(), &mut hex[..]);
        let written = child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(&hex[..]);
        let out = child.wait_with_output().map_err(unavailable)?;
        written.map_err(|e| Error(format!("the Secret Service did not take the key: {}", e)))?;
        if !out.status.success() {
            return Err(Error(format!(
                "the Secret Service did not keep the key: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    pub fn get(public: &[u8; 32]) -> Result<SecretKey, Error> {
        let mut out = tool()
            .arg("lookup")
            .args(attributes(public))
            .stdin(Stdio::null())
            .output()
            .map_err(unavailable)?;
        let found = out.status.success() && !out.stdout.is_empty();
        let key = found
            .then(|| key_from_hex(out.stdout.trim_ascii()))
            .flatten();
        out.stdout.zeroize();
        match key {
            Some(key) => Ok(key),
            None if found => Err(Error(
                "what the Secret Service keeps for this identity is not a key".to_string(),
            )),
            None => Err(Error(format!(
                "the Secret Service has no key for this identity{}",
                match String::from_utf8_lossy(&out.stderr).trim() {
                    "" => String::new(),
                    why => format!(" ({})", why),
                }
            ))),
        }
    }

    pub fn remove(public: &[u8; 32]) -> Result<(), Error> {
        let out = tool()
            .arg("clear")
            .args(attributes(public))
            .stdin(Stdio::null())
            .output()
            .map_err(unavailable)?;
        if !out.status.success() {
            return Err(Error(format!(
                "the Secret Service did not forget the key: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }
}

#[cfg(not(unix))]
mod secret_service {
    use super::*;
    fn none() -> Error {
        Error("the Secret Service is a store of Linux and the BSDs".to_string())
    }
    pub fn put(_: &[u8; 32], _: &SecretKey) -> Result<(), Error> {
        Err(none())
    }
    pub fn get(_: &[u8; 32]) -> Result<SecretKey, Error> {
        Err(none())
    }
    pub fn remove(_: &[u8; 32]) -> Result<(), Error> {
        Err(none())
    }
}

#[cfg(target_os = "macos")]
mod keychain {
    use super::*;
    use security_framework::passwords;
    use zeroize::Zeroize;

    pub fn put(public: &[u8; 32], key: &SecretKey) -> Result<(), Error> {
        passwords::set_generic_password(SERVICE, &account(public), key.expose())
            .map_err(|e| Error(format!("the Keychain did not keep the key: {}", e)))
    }

    pub fn get(public: &[u8; 32]) -> Result<SecretKey, Error> {
        let mut bytes = passwords::get_generic_password(SERVICE, &account(public))
            .map_err(|e| Error(format!("the Keychain has no key for this identity ({})", e)))?;
        let key = (bytes.len() == 32).then(|| SecretKey::with(|k| k.copy_from_slice(&bytes)));
        bytes.zeroize();
        key.ok_or_else(|| {
            Error("what the Keychain keeps for this identity is not a key".to_string())
        })
    }

    pub fn remove(public: &[u8; 32]) -> Result<(), Error> {
        passwords::delete_generic_password(SERVICE, &account(public))
            .map_err(|e| Error(format!("the Keychain did not forget the key: {}", e)))
    }
}

#[cfg(not(target_os = "macos"))]
mod keychain {
    use super::*;
    fn none() -> Error {
        Error("the Keychain is a store of macOS".to_string())
    }
    pub fn put(_: &[u8; 32], _: &SecretKey) -> Result<(), Error> {
        Err(none())
    }
    pub fn get(_: &[u8; 32]) -> Result<SecretKey, Error> {
        Err(none())
    }
    pub fn remove(_: &[u8; 32]) -> Result<(), Error> {
        Err(none())
    }
}

#[cfg(windows)]
#[allow(unsafe_code)] // CryptProtectData, CryptUnprotectData (docs/UNSAFE.md)
mod dpapi {
    //! DPAPI seals data to the Windows account: only the same user on the
    //! same machine (or domain) can unseal it. The identity's public key is
    //! the "optional entropy" both calls must be given, so that a sealed key
    //! opens only the identity it was made for.
    use super::*;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN};
    use winapi::um::winbase::LocalFree;
    use winapi::um::wincrypt::DATA_BLOB;
    use zeroize::Zeroize;

    fn entropy(public: &[u8; 32]) -> Vec<u8> {
        [&b"sharp256 identity "[..], &public[..]].concat()
    }

    fn blob(bytes: &[u8]) -> DATA_BLOB {
        DATA_BLOB {
            cbData: bytes.len() as DWORD,
            pbData: bytes.as_ptr() as *mut u8,
        }
    }

    /// Copies what DPAPI allocated, wipes it and gives it back to it.
    ///
    /// # Safety
    ///
    /// `out` must be a blob a successful DPAPI call filled in: `pbData`
    /// null, or `cbData` bytes it allocated with LocalAlloc.
    unsafe fn take(out: &mut DATA_BLOB) -> Vec<u8> {
        // Nothing promises a non-null pointer for nothing, and a slice may
        // not be made from a null one, whatever its length.
        if out.pbData.is_null() {
            return Vec::new();
        }
        // SAFETY: the caller's promise: `cbData` bytes of DPAPI's, which
        // nothing else refers to.
        let bytes = unsafe { std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize) };
        let copy = bytes.to_vec();
        bytes.zeroize();
        // SAFETY: DPAPI's LocalAlloc allocation, given back once; `bytes`
        // is not used after.
        unsafe { LocalFree(out.pbData as _) };
        copy
    }

    pub fn protect(public: &[u8; 32], key: &SecretKey) -> Result<Vec<u8>, Error> {
        let entropy = entropy(public);
        let mut input = blob(key.expose());
        let mut extra = blob(&entropy);
        let mut out = DATA_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: the input and entropy blobs point to live buffers of the
        // lengths they state, which DPAPI only reads; `out` is filled by the
        // call and taken (and freed) only when it succeeded.
        let ok = unsafe {
            CryptProtectData(
                &mut input,
                std::ptr::null(),
                &mut extra,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(Error(format!(
                "Windows did not seal the key: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: the call succeeded, so `out` is DPAPI's allocation.
        Ok(unsafe { take(&mut out) })
    }

    pub fn unprotect(public: &[u8; 32], sealed: &[u8]) -> Result<SecretKey, Error> {
        let entropy = entropy(public);
        let mut input = blob(sealed);
        let mut extra = blob(&entropy);
        let mut out = DATA_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: as in `protect`.
        let ok = unsafe {
            CryptUnprotectData(
                &mut input,
                std::ptr::null_mut(),
                &mut extra,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(Error(format!(
                "Windows did not unseal the key (another account, or another machine?): {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: the call succeeded, so `out` is DPAPI's allocation.
        let mut bytes = unsafe { take(&mut out) };
        let key = (bytes.len() == 32).then(|| SecretKey::with(|k| k.copy_from_slice(&bytes)));
        bytes.zeroize();
        key.ok_or_else(|| Error("what Windows unsealed is not a key".to_string()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A blob with nothing in it and no pointer is nothing, not a
        /// slice made from a null pointer (which taking it once made: a
        /// panic in a debug build, undefined behaviour otherwise; Miri
        /// sees it too, `scripts/miri.sh`).
        #[test]
        fn an_empty_blob_is_nothing() {
            let mut out = DATA_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            // SAFETY: a blob as a successful call may leave it, empty.
            assert!(unsafe { take(&mut out) }.is_empty());
        }
    }
}

#[cfg(not(windows))]
mod dpapi {
    use super::*;
    fn none() -> Error {
        Error("DPAPI is a store of Windows".to_string())
    }
    pub fn protect(_: &[u8; 32], _: &SecretKey) -> Result<Vec<u8>, Error> {
        Err(none())
    }
    pub fn unprotect(_: &[u8; 32], _: &[u8]) -> Result<SecretKey, Error> {
        Err(none())
    }
}
