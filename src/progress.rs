//! Progress reporting shared by CLI and GUI front ends.

use std::sync::Arc;
use std::time::Duration;

/// Snapshot of a transfer's state, emitted periodically.
#[derive(Debug, Clone, Default)]
pub struct TransferStats {
    pub transfer_id: String,
    pub bytes_done: u64,
    pub total_bytes: u64,
    /// Instantaneous goodput over the last progress interval, bits per second.
    pub rate_bps: f64,
    /// Average goodput since the transfer started, bits per second.
    pub avg_rate_bps: f64,
    pub rtt_ms: f64,
    pub cwnd_bytes: u64,
    pub inflight_bytes: u64,
    pub chunk_size: u16,
    pub retransmitted_bytes: u64,
    pub loss_events: u64,
    pub elapsed: Duration,
    pub eta: Option<Duration>,
    pub stalled: bool,
}

impl TransferStats {
    pub fn fraction(&self) -> f32 {
        if self.total_bytes == 0 {
            1.0
        } else {
            (self.bytes_done as f64 / self.total_bytes as f64) as f32
        }
    }
}

/// What a directory transfer holds, for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryInfo {
    pub files: u64,
    pub dirs: u64,
}

impl DirectoryInfo {
    /// "12 files in 3 folders" (the directory itself not counted).
    pub fn describe(&self) -> String {
        let plural =
            |n: u64, one: &str, many: &str| format!("{} {}", n, if n == 1 { one } else { many });
        if self.dirs == 0 {
            plural(self.files, "file", "files")
        } else {
            format!(
                "{} in {}",
                plural(self.files, "file", "files"),
                plural(self.dirs, "folder", "folders")
            )
        }
    }
}

/// Events emitted by senders and receivers.
#[derive(Debug, Clone)]
pub enum TransferEvent {
    /// Handshake finished; data will flow. `resumed_from` is the number of
    /// bytes that were already stored by the receiver.
    Started {
        transfer_id: String,
        peer: String,
        /// Authenticated SHARP ID of the other side.
        peer_id: String,
        /// AEAD protecting the session.
        cipher: String,
        /// Name of the file, or of the directory.
        file_name: String,
        /// Bytes to transfer (for a directory: its listing and all files).
        file_size: u64,
        /// Set for a directory transfer.
        directory: Option<DirectoryInfo>,
        resumed_from: u64,
        chunk_size: u16,
    },
    Progress(TransferStats),
    /// No packets from the peer for the configured stall timeout.
    Stalled {
        transfer_id: String,
        since: Duration,
    },
    /// Packets from the peer resumed after a stall.
    Recovered {
        transfer_id: String,
    },
    Completed {
        transfer_id: String,
        file_name: String,
        /// Where the receiver stored the file (receiver side only).
        path: Option<String>,
        file_hash_hex: String,
        /// True when both peers agreed on the whole-file hash.
        peer_confirmed: bool,
        stats: TransferStats,
    },
    Failed {
        transfer_id: String,
        error: String,
        /// True when the saved state allows resuming later.
        resumable: bool,
    },
    /// Receiver side: a sender asked to start a transfer.
    IncomingRequest {
        transfer_id: String,
        peer: String,
        /// Authenticated SHARP ID of the sender.
        sender_id: String,
        file_name: String,
        file_size: u64,
        /// Set for a directory transfer.
        directory: Option<DirectoryInfo>,
        resumed_bytes: u64,
    },
    /// Receiver side: what NAT discovery found (STUN, RFC 5780 behaviour
    /// tests, and a port forward via PCP, NAT-PMP or UPnP).
    Reachability {
        /// Address senders outside the local network should use, if known.
        advertised: Option<String>,
        /// The whole address to hand a sender, `ID@host:port,…`, listing
        /// every candidate address this receiver may be reached at.
        address: Option<String>,
        summary: String,
    },
    /// Receiver side: a relay has taken this receiver's registration, so
    /// senders that cannot reach it directly can name that relay.
    RelayRegistered {
        /// The relay, as configured.
        relay: String,
        /// Where the relay sees this receiver. Not an address to publish:
        /// it is the mapping towards the relay, and under the NAT a relay
        /// exists for, nobody else would arrive at it.
        observed: String,
        /// The relay was asked not to tell senders where we are.
        private: bool,
    },
}

pub type EventCallback = Arc<dyn Fn(TransferEvent) + Send + Sync>;

/// Helper for emitting events through an optional callback.
pub(crate) fn emit(cb: &Option<EventCallback>, ev: TransferEvent) {
    if let Some(cb) = cb {
        cb(ev);
    }
}

/// Human-readable bit rate.
pub fn format_rate(bps: f64) -> String {
    if bps >= 1e9 {
        format!("{:.2} Gbit/s", bps / 1e9)
    } else if bps >= 1e6 {
        format!("{:.1} Mbit/s", bps / 1e6)
    } else if bps >= 1e3 {
        format!("{:.0} kbit/s", bps / 1e3)
    } else {
        format!("{:.0} bit/s", bps)
    }
}

/// Human-readable byte count.
pub fn format_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} B", b)
    } else {
        format!("{:.2} {}", v, UNITS[i])
    }
}

/// Parses a byte count such as `10G`, `512M`, `1.5T` or a plain number.
/// `K`, `M`, `G` and `T` are powers of 1000; `Ki`, `Mi`, `Gi` and `Ti` are
/// powers of 1024. A trailing `B` is allowed (`10GB`, `4GiB`).
pub fn parse_bytes(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let t = t
        .strip_suffix('B')
        .or_else(|| t.strip_suffix('b'))
        .unwrap_or(t);
    let (num, mult) = if let Some(n) = t.strip_suffix("Ki").or_else(|| t.strip_suffix("ki")) {
        (n, 1024f64)
    } else if let Some(n) = t.strip_suffix("Mi").or_else(|| t.strip_suffix("mi")) {
        (n, 1024f64.powi(2))
    } else if let Some(n) = t.strip_suffix("Gi").or_else(|| t.strip_suffix("gi")) {
        (n, 1024f64.powi(3))
    } else if let Some(n) = t.strip_suffix("Ti").or_else(|| t.strip_suffix("ti")) {
        (n, 1024f64.powi(4))
    } else {
        match t.chars().last() {
            Some('k' | 'K') => (&t[..t.len() - 1], 1e3),
            Some('m' | 'M') => (&t[..t.len() - 1], 1e6),
            Some('g' | 'G') => (&t[..t.len() - 1], 1e9),
            Some('t' | 'T') => (&t[..t.len() - 1], 1e12),
            _ => (t, 1.0),
        }
    };
    let v: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("cannot parse size '{}'", s))?;
    if v.is_nan() || v < 0.0 || !v.is_finite() {
        return Err(format!("'{}' is not a size", s));
    }
    Ok((v * mult) as u64)
}

/// Parses a bit rate such as `10M`, `800k`, `1.5G` or a plain number (bits
/// per second).
pub fn parse_rate(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty rate".into());
    }
    let (num, mult) = match s.chars().last().unwrap() {
        'k' | 'K' => (&s[..s.len() - 1], 1e3),
        'm' | 'M' => (&s[..s.len() - 1], 1e6),
        'g' | 'G' => (&s[..s.len() - 1], 1e9),
        _ => (s, 1.0),
    };
    let v: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("cannot parse rate '{}'", s))?;
    if v <= 0.0 {
        return Err("rate must be positive".into());
    }
    Ok((v * mult) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_and_sizes_format() {
        assert_eq!(parse_rate("10M").unwrap(), 10_000_000);
        assert_eq!(parse_rate("1.5G").unwrap(), 1_500_000_000);
        assert_eq!(parse_rate("800k").unwrap(), 800_000);
        assert_eq!(parse_rate("42").unwrap(), 42);
        assert!(parse_rate("x").is_err());
        assert_eq!(parse_bytes("10G").unwrap(), 10_000_000_000);
        assert_eq!(parse_bytes("4GiB").unwrap(), 4 << 30);
        assert_eq!(parse_bytes("512Mi").unwrap(), 512 << 20);
        assert_eq!(parse_bytes("1.5k").unwrap(), 1500);
        assert_eq!(parse_bytes("0").unwrap(), 0);
        assert_eq!(parse_bytes("7").unwrap(), 7);
        assert!(parse_bytes("-1G").is_err());
        assert!(parse_bytes("lots").is_err());
        assert_eq!(format_rate(1.5e9), "1.50 Gbit/s");
        assert_eq!(format_bytes(1536), "1.50 KiB");
        assert_eq!(format_bytes(12), "12 B");
        let d = |files, dirs| DirectoryInfo { files, dirs }.describe();
        assert_eq!(d(1, 0), "1 file");
        assert_eq!(d(12, 3), "12 files in 3 folders");
        assert_eq!(d(0, 1), "0 files in 1 folder");
    }
}
