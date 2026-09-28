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
        file_name: String,
        file_size: u64,
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
        resumed_bytes: u64,
    },
    /// Receiver side: result of NAT discovery (STUN / UPnP).
    Reachability {
        /// Address senders outside the local network should use, if known.
        advertised: Option<String>,
        summary: String,
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
        assert_eq!(format_rate(1.5e9), "1.50 Gbit/s");
        assert_eq!(format_bytes(1536), "1.50 KiB");
        assert_eq!(format_bytes(12), "12 B");
    }
}
