//! Persistent transfer state used to resume interrupted transfers.
//!
//! The receiver stores which byte ranges of the partial file (or of the
//! stream of a partial directory) are durable (written and fsynced), and for
//! a directory also its manifest. The sender stores the transfer id it used
//! for a given (file or directory, peer) so that a restarted sender can
//! present the same id. Files are replaced whole and flushed with their
//! directory (`file::durable`).

use crate::file::durable;
use crate::protocol::RangeSet;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const STATE_FORMAT_VERSION: u32 = 3;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn hex16(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Reads what [`hex16`] writes. Anything else — including text that is 32
/// bytes long but not 32 characters, which a damaged state file can hold —
/// is `None`, never a panic: slicing it two bytes at a time used to cut a
/// multi-byte character in half (found by the fuzzing smoke test).
pub fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = digit(b[2 * i])? << 4 | digit(b[2 * i + 1])?;
    }
    Some(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverState {
    pub format: u32,
    pub transfer_id: String,
    pub file_name: String,
    pub file_size: u64,
    /// Modification time of the source file as announced in HELLO; a source
    /// that changed since the partial file was started is not resumed.
    #[serde(default)]
    pub file_mtime: i64,
    pub part_path: PathBuf,
    pub final_path: PathBuf,
    pub peer: String,
    /// SHARP ID of the sender; only the same sender may resume the transfer.
    #[serde(default)]
    pub sender: String,
    /// Directory transfers: BLAKE3 of the manifest (hex) and its length;
    /// empty and 0 for a single file. `part_path` is then the staging
    /// directory and `durable` refers to the transfer stream.
    #[serde(default)]
    pub manifest_hash: String,
    #[serde(default)]
    pub manifest_len: u64,
    /// Byte ranges that are written and fsynced.
    pub durable: Vec<(u64, u64)>,
    pub updated_unix: u64,
    /// BLAKE3 (hex) of the result once it is under `final_path` but not yet
    /// confirmed by the sender; empty before. A transfer cut off in that
    /// moment is finished from the result in place, not received a second
    /// time beside it as `name (1)` (Р22).
    #[serde(default)]
    pub placed: String,
}

impl ReceiverState {
    /// Where the transfer's data is: the result in place once it is
    /// [`placed`](Self::placed), the partial file or staging directory
    /// before.
    pub fn data_path(&self) -> &Path {
        if self.placed.is_empty() {
            &self.part_path
        } else {
            &self.final_path
        }
    }

    /// [`placed`](Self::placed) as bytes, if it is set and well formed.
    pub fn placed_hash(&self) -> Option<[u8; 32]> {
        let (hi, lo) = self.placed.split_at_checked(32)?;
        let (hi, lo) = (parse_hex16(hi)?, parse_hex16(lo)?);
        let mut h = [0u8; 32];
        h[..16].copy_from_slice(&hi);
        h[16..].copy_from_slice(&lo);
        Some(h)
    }

    pub fn durable_set(&self) -> RangeSet {
        RangeSet::from_ranges(self.durable.iter().copied())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderState {
    pub format: u32,
    pub transfer_id: String,
    pub file_path: PathBuf,
    pub file_size: u64,
    pub file_mtime: i64,
    /// BLAKE3 (hex) of the manifest when the path is a directory.
    #[serde(default)]
    pub manifest_hash: String,
    pub peer: String,
    pub updated_unix: u64,
}

/// Directory-backed store of state files.
#[derive(Debug, Clone)]
pub struct StateStore {
    dir: PathBuf,
}

impl StateStore {
    /// Uses `dir` when given, otherwise the per-user data directory
    /// (`~/.local/share/sharp-256/states`, `%APPDATA%\sharp-256\states`, ...).
    pub fn open(dir: Option<PathBuf>) -> io::Result<Self> {
        let dir = match dir {
            Some(d) => d,
            None => dirs::data_dir()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no data directory"))?
                .join("sharp-256")
                .join("states"),
        };
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn receiver_path(&self, transfer_id: &str) -> PathBuf {
        self.dir.join(format!("recv-{}.json", transfer_id))
    }

    /// Where the manifest of a directory transfer is kept for resume.
    pub fn manifest_path(&self, transfer_id: &str) -> PathBuf {
        self.dir.join(format!("recv-{}.manifest", transfer_id))
    }

    pub fn load_manifest(&self, transfer_id: &str) -> Option<Vec<u8>> {
        fs::read(self.manifest_path(transfer_id)).ok()
    }

    fn sender_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("send-{}.json", key))
    }

    fn stamp_path(&self) -> PathBuf {
        self.dir.join("initiation.stamp")
    }

    /// The newest handshake timestamp a previous run used (see
    /// `crypto::handshake::raise_initiation_timestamp_floor`); 0 if none.
    pub fn load_stamp(&self) -> u64 {
        fs::read_to_string(self.stamp_path())
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0)
    }

    pub fn save_stamp(&self, stamp: u64) -> io::Result<()> {
        durable::replace(&self.stamp_path(), stamp.to_string().as_bytes())
    }

    /// Every state file is replaced whole and flushed with its directory
    /// (`file::durable`): after a crash it is the old one or the new one.
    /// It used to be written and renamed without a flush, which could leave
    /// an empty or cut-off file under the name after a power cut.
    fn write_atomic(path: &Path, json: &str) -> io::Result<()> {
        durable::replace(path, json.as_bytes())
    }

    pub fn save_receiver(&self, state: &ReceiverState) -> io::Result<()> {
        let mut state = state.clone();
        state.format = STATE_FORMAT_VERSION;
        state.updated_unix = now_unix();
        let json = serde_json::to_string_pretty(&state).map_err(io::Error::other)?;
        Self::write_atomic(&self.receiver_path(&state.transfer_id), &json)
    }

    pub fn load_receiver(&self, transfer_id: &str) -> Option<ReceiverState> {
        let json = fs::read_to_string(self.receiver_path(transfer_id)).ok()?;
        let st: ReceiverState = serde_json::from_str(&json).ok()?;
        (st.format == STATE_FORMAT_VERSION).then_some(st)
    }

    pub fn remove_receiver(&self, transfer_id: &str) {
        let _ = durable::remove(&self.receiver_path(transfer_id));
        let _ = durable::remove(&self.manifest_path(transfer_id));
    }

    /// Finds the most recent receiver state of `sender` for a file (or
    /// directory, identified by its manifest hash) of this name, size and
    /// source modification time whose partial file still exists.
    pub fn find_receiver_by_file(
        &self,
        sender: &str,
        file_name: &str,
        file_size: u64,
        file_mtime: i64,
        manifest_hash: &str,
    ) -> Option<ReceiverState> {
        let mut best: Option<ReceiverState> = None;
        for entry in fs::read_dir(&self.dir).ok()?.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("recv-") || !name.ends_with(".json") {
                continue;
            }
            let Ok(json) = fs::read_to_string(entry.path()) else {
                continue;
            };
            let Ok(st) = serde_json::from_str::<ReceiverState>(&json) else {
                continue;
            };
            if st.format != STATE_FORMAT_VERSION
                || st.sender != sender
                || st.file_name != file_name
                || st.file_size != file_size
                || st.file_mtime != file_mtime
                || st.manifest_hash != manifest_hash
                || !st.data_path().exists()
            {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|b| st.updated_unix > b.updated_unix)
            {
                best = Some(st);
            }
        }
        best
    }

    fn sender_key(file_path: &Path, file_size: u64, peer: &str) -> String {
        let mut h = blake3::Hasher::new();
        h.update(file_path.to_string_lossy().as_bytes());
        h.update(&file_size.to_le_bytes());
        h.update(peer.as_bytes());
        h.finalize().to_hex()[..32].to_string()
    }

    pub fn save_sender(&self, state: &SenderState) -> io::Result<()> {
        let mut state = state.clone();
        state.format = STATE_FORMAT_VERSION;
        state.updated_unix = now_unix();
        let json = serde_json::to_string_pretty(&state).map_err(io::Error::other)?;
        let key = Self::sender_key(&state.file_path, state.file_size, &state.peer);
        Self::write_atomic(&self.sender_path(&key), &json)
    }

    pub fn load_sender(&self, file_path: &Path, file_size: u64, peer: &str) -> Option<SenderState> {
        let key = Self::sender_key(file_path, file_size, peer);
        let json = fs::read_to_string(self.sender_path(&key)).ok()?;
        let st: SenderState = serde_json::from_str(&json).ok()?;
        (st.format == STATE_FORMAT_VERSION && st.file_size == file_size).then_some(st)
    }

    pub fn remove_sender(&self, file_path: &Path, file_size: u64, peer: &str) {
        let key = Self::sender_key(file_path, file_size, peer);
        let _ = durable::remove(&self.sender_path(&key));
    }

    /// Deletes state files older than `max_age`, together with the partial
    /// files they describe (without its state a partial file cannot be
    /// resumed). Returns the number of state files removed.
    pub fn cleanup_older_than(&self, max_age: Duration) -> io::Result<usize> {
        let cutoff = now_unix().saturating_sub(max_age.as_secs());
        let mut removed = 0;
        for entry in fs::read_dir(&self.dir)?.flatten() {
            let path = entry.path();
            // What a replacement left when the process died in the middle
            // of it; an hour is long past any replacement in progress.
            if path.extension().and_then(|e| e.to_str()) == Some("tmp") {
                let stale = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > Duration::from_secs(3600));
                if stale {
                    let _ = fs::remove_file(&path);
                }
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(json) = fs::read_to_string(&path) else {
                continue;
            };
            let value = serde_json::from_str::<serde_json::Value>(&json).ok();
            let updated = value
                .as_ref()
                .and_then(|v| v.get("updated_unix").and_then(|u| u.as_u64()))
                .unwrap_or(0);
            if updated >= cutoff {
                continue;
            }
            let part = value
                .as_ref()
                .and_then(|v| v.get("part_path").and_then(|p| p.as_str()))
                .map(PathBuf::from);
            if let Some(part) = part {
                // Only ever delete our own partial files (or staging
                // directories).
                let ours = part
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().ends_with(crate::file::PART_SUFFIX));
                if ours && part.exists() && crate::file::tree::remove_partial(&part).is_ok() {
                    tracing::info!("removed abandoned partial transfer {}", part.display());
                }
            }
            let _ = fs::remove_file(&path);
            let _ = fs::remove_file(path.with_extension("manifest"));
            removed += 1;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiver_state_roundtrip_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(Some(dir.path().join("states"))).unwrap();
        let part = dir.path().join("f.bin.sharp-part");
        fs::write(&part, b"partial").unwrap();
        let st = ReceiverState {
            format: 0,
            transfer_id: hex16(&[1; 16]),
            file_name: "f.bin".into(),
            file_size: 1000,
            file_mtime: 1_700_000_000,
            part_path: part.clone(),
            final_path: dir.path().join("f.bin"),
            peer: "127.0.0.1:1".into(),
            sender: "sh-a".into(),
            manifest_hash: String::new(),
            manifest_len: 0,
            durable: vec![(0, 100), (200, 300)],
            updated_unix: 0,
            placed: String::new(),
        };
        store.save_receiver(&st).unwrap();
        let loaded = store.load_receiver(&st.transfer_id).unwrap();
        assert_eq!(loaded.durable_set().total(), 200);
        assert_eq!(loaded.format, STATE_FORMAT_VERSION);
        assert_eq!(loaded.file_mtime, 1_700_000_000);
        assert!(store
            .find_receiver_by_file("sh-a", "f.bin", 1000, 1_700_000_000, "")
            .is_some());
        assert!(store
            .find_receiver_by_file("sh-a", "f.bin", 999, 1_700_000_000, "")
            .is_none());
        // The source changed since the partial file was started.
        assert!(store
            .find_receiver_by_file("sh-a", "f.bin", 1000, 1_700_000_001, "")
            .is_none());
        // Another sender never resumes this partial file.
        assert!(store
            .find_receiver_by_file("sh-b", "f.bin", 1000, 1_700_000_000, "")
            .is_none());
        // A directory of the same name is something else.
        assert!(store
            .find_receiver_by_file("sh-a", "f.bin", 1000, 1_700_000_000, "ab12")
            .is_none());
        fs::remove_file(&part).unwrap();
        assert!(store
            .find_receiver_by_file("sh-a", "f.bin", 1000, 1_700_000_000, "")
            .is_none());
        store.remove_receiver(&st.transfer_id);
        assert!(store.load_receiver(&st.transfer_id).is_none());
    }

    #[test]
    fn expired_state_takes_its_partial_file_along() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(Some(dir.path().join("states"))).unwrap();
        let part = dir.path().join("old.bin.sharp-part");
        let staging = dir.path().join("photos.sharp-part");
        let foreign = dir.path().join("keep.txt");
        fs::write(&part, b"partial").unwrap();
        fs::create_dir_all(staging.join("a/b")).unwrap();
        fs::write(staging.join("a/b/c.jpg"), b"partial").unwrap();
        fs::write(&foreign, b"user data").unwrap();
        fs::write(store.manifest_path(&hex16(&[3; 16])), b"manifest").unwrap();
        for (id, part_path) in [
            (1u8, part.clone()),
            (2u8, foreign.clone()),
            (3u8, staging.clone()),
        ] {
            let st = ReceiverState {
                format: STATE_FORMAT_VERSION,
                transfer_id: hex16(&[id; 16]),
                file_name: "old.bin".into(),
                file_size: 7,
                file_mtime: 0,
                part_path,
                final_path: dir.path().join("old.bin"),
                peer: "127.0.0.1:1".into(),
                sender: String::new(),
                manifest_hash: String::new(),
                manifest_len: 0,
                durable: vec![(0, 7)],
                updated_unix: 1, // long ago
                placed: String::new(),
            };
            let json = serde_json::to_string(&st).unwrap();
            fs::write(store.receiver_path(&st.transfer_id), json).unwrap();
        }
        assert_eq!(
            store.cleanup_older_than(Duration::from_secs(3600)).unwrap(),
            3
        );
        assert!(!part.exists(), "abandoned partial file must be removed");
        assert!(
            !staging.exists(),
            "abandoned staging directory must be removed"
        );
        assert!(store.load_manifest(&hex16(&[3; 16])).is_none());
        assert!(
            foreign.exists(),
            "files that are not ours are never touched"
        );
        assert!(store.load_receiver(&hex16(&[1; 16])).is_none());
    }

    #[test]
    fn sender_state_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(Some(dir.path().to_path_buf())).unwrap();
        let st = SenderState {
            format: 0,
            transfer_id: hex16(&[9; 16]),
            file_path: PathBuf::from("/tmp/x.bin"),
            file_size: 5,
            file_mtime: 1,
            manifest_hash: String::new(),
            peer: "10.0.0.1:5555".into(),
            updated_unix: 0,
        };
        store.save_sender(&st).unwrap();
        let l = store
            .load_sender(Path::new("/tmp/x.bin"), 5, "10.0.0.1:5555")
            .unwrap();
        assert_eq!(l.transfer_id, st.transfer_id);
        assert!(store
            .load_sender(Path::new("/tmp/x.bin"), 6, "10.0.0.1:5555")
            .is_none());
        assert_eq!(parse_hex16(&l.transfer_id), Some([9; 16]));
        // 32 bytes that are not 32 hex digits, or not even 32 characters.
        assert_eq!(parse_hex16("200\u{fffd}0db80000000000000000000000"), None);
        assert_eq!(parse_hex16(&"g".repeat(32)), None);
        assert_eq!(
            parse_hex16(&hex16(&[0xab; 16]).to_uppercase()),
            Some([0xab; 16])
        );
        assert_eq!(store.cleanup_older_than(Duration::from_secs(0)).unwrap(), 0);
        store.remove_sender(Path::new("/tmp/x.bin"), 5, "10.0.0.1:5555");
        assert!(store
            .load_sender(Path::new("/tmp/x.bin"), 5, "10.0.0.1:5555")
            .is_none());
    }
}
