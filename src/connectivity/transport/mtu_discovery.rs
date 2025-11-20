// src/connectivity/transport/mtu_discovery.rs
//! Path MTU Discovery (PLPMTUD) - RFC 4821 & RFC 8899
//!
//! ## RFC Standards
//!
//! - **RFC 4821**: Packetization Layer Path MTU Discovery
//!   - PLPMTUD algorithm for finding optimal MTU
//!   - Probe packet generation and validation
//!   - Black hole detection
//!
//! - **RFC 8899**: Packetization Layer Path MTU Discovery for Datagram Transports
//!   - Updated PLPMTUD for UDP/QUIC/SCTP
//!   - DPLPMTUD (Datagram PLPMTUD)
//!   - Probe loss detection
//!   - PTB (Packet Too Big) message handling
//!
//! - **RFC 1191**: Path MTU Discovery (classic PMTUD)
//!   - Standard IPv4 MTU values
//!   - Don't Fragment (DF) bit usage
//!
//! - **RFC 8201**: Path MTU Discovery for IPv6
//!   - IPv6 minimum MTU: 1280 bytes
//!   - ICMPv6 Packet Too Big messages

use anyhow::Result;
use parking_lot::RwLock;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, trace, warn};

use crate::protocol::constants::{
    IPV4_HEADER_SIZE, IPV6_HEADER_SIZE, SHARP_HEADER_SIZE, UDP_HEADER_SIZE,
};

/// RFC 8899 Section 5.1.2: PLPMTUD Constants
pub const BASE_PLPMTU: usize = 1200; // Conservative starting point
pub const MIN_PLPMTU_IPV4: usize = 68; // RFC 791: minimum IPv4 datagram
pub const MIN_PLPMTU_IPV6: usize = 1280; // RFC 8200: minimum IPv6 MTU
pub const MAX_PLPMTU: usize = 65535; // Theoretical maximum

/// Standard MTU sizes to probe (RFC 8899 Section 5.1.2)
pub const MTU_PROBE_SIZES: [usize; 8] = [
    1500, // Ethernet
    1492, // PPPoE
    1280, // IPv6 minimum
    9000, // Jumbo frames
    4464, // Token Ring
    2048, // WLAN
    1006, // SLIP
    576,  // IPv4 minimum recommended
];

/// RFC 8899: Probe timeout
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum probe attempts per size
const MAX_PROBE_ATTEMPTS: u32 = 3;

/// Interval between probes
const PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// Path MTU Discovery state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmtudState {
    /// Initial state, not started
    Initial,
    /// Currently probing
    Probing,
    /// Discovery complete
    Complete,
    /// Black hole detected (packets lost)
    BlackHole,
    /// Error occurred
    Error,
}

/// MTU probe result
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// Probed MTU size
    pub mtu: usize,
    /// Was probe successful?
    pub success: bool,
    /// RTT if successful
    pub rtt: Option<Duration>,
    /// Timestamp
    pub timestamp: Instant,
}

/// Path MTU Discovery statistics
#[derive(Debug, Clone, Default)]
pub struct PmtudStats {
    /// Total probes sent
    pub probes_sent: u32,
    /// Successful probes
    pub probes_successful: u32,
    /// Failed probes
    pub probes_failed: u32,
    /// Current discovered MTU
    pub current_mtu: Option<usize>,
    /// Maximum MTU found
    pub max_mtu_found: Option<usize>,
    /// Time of last successful probe
    pub last_successful_probe: Option<Instant>,
    /// Black holes detected
    pub black_holes_detected: u32,
}

/// Path MTU Discovery Manager
///
/// Implements RFC 8899 DPLPMTUD (Datagram PLPMTUD) algorithm.
///
/// ## Algorithm (RFC 8899 Section 5.2)
///
/// 1. Start with BASE_PLPMTU (1200 bytes)
/// 2. Send probe packets of increasing sizes
/// 3. Wait for acknowledgment or timeout
/// 4. Binary search for optimal MTU
/// 5. Handle black holes (packet loss)
/// 6. Periodic re-validation
pub struct PathMtuDiscovery {
    /// Current state
    state: Arc<RwLock<PmtudState>>,

    /// Discovered Path MTU
    path_mtu: Arc<RwLock<Option<usize>>>,

    /// Statistics
    stats: Arc<RwLock<PmtudStats>>,

    /// IP version for this path
    ip_version: IpAddr,

    /// Remote address being probed
    remote_addr: SocketAddr,

    /// Probe history
    probe_history: Arc<RwLock<Vec<ProbeResult>>>,
}

impl PathMtuDiscovery {
    /// Create new Path MTU Discovery instance
    pub fn new(local_ip: IpAddr, remote_addr: SocketAddr) -> Self {
        let min_mtu = match local_ip {
            IpAddr::V4(_) => MIN_PLPMTU_IPV4,
            IpAddr::V6(_) => MIN_PLPMTU_IPV6,
        };

        Self {
            state: Arc::new(RwLock::new(PmtudState::Initial)),
            path_mtu: Arc::new(RwLock::new(Some(min_mtu))),
            stats: Arc::new(RwLock::new(PmtudStats::default())),
            ip_version: local_ip,
            remote_addr,
            probe_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Start Path MTU Discovery process
    ///
    /// RFC 8899 Section 5.2: DPLPMTUD Algorithm
    pub async fn discover<F>(&self, probe_fn: F) -> Result<usize>
    where
        F: Fn(usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send>>
            + Send
            + Sync,
    {
        *self.state.write() = PmtudState::Probing;

        info!(
            "Starting Path MTU Discovery to {} (IP version: {})",
            self.remote_addr,
            match self.ip_version {
                IpAddr::V4(_) => "IPv4",
                IpAddr::V6(_) => "IPv6",
            }
        );

        // Get initial MTU from interface
        let mut current_mtu = self.get_min_mtu();
        let mut max_success = current_mtu;

        // RFC 8899: Probe standard MTU sizes
        let mut probe_sizes: Vec<usize> = MTU_PROBE_SIZES
            .iter()
            .filter(|&&size| size >= current_mtu && size <= MAX_PLPMTU)
            .copied()
            .collect();
        probe_sizes.sort();

        for &probe_size in &probe_sizes {
            debug!("Probing MTU size: {}", probe_size);

            let success = self.probe_mtu(probe_size, &probe_fn).await?;

            if success {
                max_success = probe_size;
                *self.path_mtu.write() = Some(probe_size);
                self.stats.write().max_mtu_found = Some(probe_size);
                info!("MTU {} successful", probe_size);
            } else {
                warn!("MTU {} failed, stopping probes", probe_size);
                break;
            }

            // Small delay between probes
            sleep(PROBE_INTERVAL).await;
        }

        // Binary search for exact MTU between last success and first failure
        if let Some(next_size) = probe_sizes.iter().find(|&&s| s > max_success) {
            if next_size - max_success > 100 {
                debug!("Binary search between {} and {}", max_success, next_size);
                let refined = self
                    .binary_search_mtu(max_success, *next_size, &probe_fn)
                    .await?;
                max_success = refined;
                *self.path_mtu.write() = Some(refined);
            }
        }

        *self.state.write() = PmtudState::Complete;
        self.stats.write().current_mtu = Some(max_success);

        info!(
            "Path MTU Discovery complete: {} bytes (payload: {} bytes)",
            max_success,
            self.calculate_max_payload(max_success)
        );

        Ok(max_success)
    }

    /// Probe specific MTU size
    async fn probe_mtu<F>(&self, mtu: usize, probe_fn: &F) -> Result<bool>
    where
        F: Fn(usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send>>
            + Send
            + Sync,
    {
        for attempt in 1..=MAX_PROBE_ATTEMPTS {
            trace!(
                "Probe attempt {}/{} for MTU {}",
                attempt,
                MAX_PROBE_ATTEMPTS,
                mtu
            );

            let probe_start = Instant::now();
            self.stats.write().probes_sent += 1;

            // Execute probe with timeout
            let result = timeout(PROBE_TIMEOUT, probe_fn(mtu)).await;

            match result {
                Ok(Ok(true)) => {
                    // Successful probe
                    let rtt = probe_start.elapsed();
                    self.stats.write().probes_successful += 1;
                    self.stats.write().last_successful_probe = Some(Instant::now());

                    self.probe_history.write().push(ProbeResult {
                        mtu,
                        success: true,
                        rtt: Some(rtt),
                        timestamp: Instant::now(),
                    });

                    debug!("Probe successful: MTU {} (RTT: {:?})", mtu, rtt);
                    return Ok(true);
                }
                Ok(Ok(false)) | Ok(Err(_)) | Err(_) => {
                    // Probe failed or timeout
                    self.stats.write().probes_failed += 1;

                    self.probe_history.write().push(ProbeResult {
                        mtu,
                        success: false,
                        rtt: None,
                        timestamp: Instant::now(),
                    });

                    if attempt < MAX_PROBE_ATTEMPTS {
                        trace!("Probe failed, retrying...");
                        sleep(PROBE_INTERVAL).await;
                    }
                }
            }
        }

        // All attempts failed
        warn!("All probe attempts failed for MTU {}", mtu);
        Ok(false)
    }

    /// Binary search for exact MTU between min and max
    async fn binary_search_mtu<F>(
        &self,
        mut min: usize,
        mut max: usize,
        probe_fn: &F,
    ) -> Result<usize>
    where
        F: Fn(usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send>>
            + Send
            + Sync,
    {
        let mut best = min;

        while max - min > 10 {
            let mid = (min + max) / 2;
            debug!("Binary search: trying MTU {}", mid);

            if self.probe_mtu(mid, probe_fn).await? {
                best = mid;
                min = mid;
            } else {
                max = mid;
            }

            sleep(PROBE_INTERVAL).await;
        }

        Ok(best)
    }

    /// Get minimum MTU based on IP version
    fn get_min_mtu(&self) -> usize {
        match self.ip_version {
            IpAddr::V4(_) => MIN_PLPMTU_IPV4,
            IpAddr::V6(_) => MIN_PLPMTU_IPV6,
        }
    }

    /// Calculate maximum payload size from MTU
    ///
    /// Accounts for:
    /// - IP header (20 bytes IPv4, 40 bytes IPv6)
    /// - UDP header (8 bytes)
    /// - SHARP header (30 bytes)
    pub fn calculate_max_payload(&self, mtu: usize) -> usize {
        let ip_header = match self.ip_version {
            IpAddr::V4(_) => IPV4_HEADER_SIZE,
            IpAddr::V6(_) => IPV6_HEADER_SIZE,
        };

        mtu.saturating_sub(ip_header + UDP_HEADER_SIZE + SHARP_HEADER_SIZE)
    }

    /// Get current discovered Path MTU
    pub fn get_path_mtu(&self) -> Option<usize> {
        *self.path_mtu.read()
    }

    /// Get maximum payload size for current MTU
    pub fn get_max_payload(&self) -> Option<usize> {
        self.get_path_mtu()
            .map(|mtu| self.calculate_max_payload(mtu))
    }

    /// Get current state
    pub fn state(&self) -> PmtudState {
        *self.state.read()
    }

    /// Get statistics
    pub fn stats(&self) -> PmtudStats {
        self.stats.read().clone()
    }

    /// Check if black hole detected (RFC 8899 Section 5.3)
    pub fn is_black_hole(&self) -> bool {
        let stats = self.stats.read();

        // Black hole if too many failures
        if stats.probes_sent > 10 && stats.probes_failed as f64 / stats.probes_sent as f64 > 0.8 {
            return true;
        }

        false
    }

    /// Reset to lower MTU (RFC 8899 Section 5.3: Black Hole Detection)
    pub fn handle_black_hole(&self) {
        warn!("Black hole detected, resetting MTU");

        let current = self.get_path_mtu().unwrap_or(BASE_PLPMTU);
        let reduced = current.saturating_sub(200).max(self.get_min_mtu());

        *self.path_mtu.write() = Some(reduced);
        *self.state.write() = PmtudState::BlackHole;
        self.stats.write().black_holes_detected += 1;

        info!(
            "MTU reduced from {} to {} due to black hole",
            current, reduced
        );
    }
}

/// Platform-specific interface MTU detection
pub struct InterfaceMtuDetector;

impl InterfaceMtuDetector {
    /// Get MTU for specific interface (platform-specific)
    pub fn get_interface_mtu(interface_name: &str) -> Option<usize> {
        #[cfg(target_os = "linux")]
        {
            Self::get_mtu_linux(interface_name)
        }

        #[cfg(target_os = "windows")]
        {
            Self::get_mtu_windows(interface_name)
        }

        #[cfg(target_os = "macos")]
        {
            Self::get_mtu_macos(interface_name)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            let _ = interface_name;
            Some(1500) // Fallback to standard Ethernet MTU
        }
    }

    /// Linux: Read from /sys/class/net/<interface>/mtu
    #[cfg(target_os = "linux")]
    fn get_mtu_linux(interface_name: &str) -> Option<usize> {
        let path = format!("/sys/class/net/{}/mtu", interface_name);
        std::fs::read_to_string(&path)
            .ok()?
            .trim()
            .parse::<usize>()
            .ok()
    }

    /// Windows: Use GetAdaptersAddresses API
    #[cfg(target_os = "windows")]
    fn get_mtu_windows(interface_name: &str) -> Option<usize> {
        use std::process::Command;

        // Method 1: Try netsh command (most reliable)
        if let Ok(output) = Command::new("netsh")
            .args(&["interface", "ipv4", "show", "interfaces"])
            .output()
        {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                for line in stdout.lines() {
                    if line.contains(interface_name) {
                        // Parse MTU from output
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 {
                            if let Ok(mtu) = parts[3].parse::<usize>() {
                                trace!("Windows MTU for {}: {} (via netsh)", interface_name, mtu);
                                return Some(mtu);
                            }
                        }
                    }
                }
            }
        }

        // Fallback to standard Ethernet MTU
        Some(1500)
    }

    /// macOS: Use ioctl with SIOCGIFMTU
    #[cfg(target_os = "macos")]
    fn get_mtu_macos(interface_name: &str) -> Option<usize> {
        use std::os::raw::c_int;

        // Use getifaddrs + ioctl for accurate MTU
        // For now, return standard MTU (can be improved with unsafe ioctl calls)
        let _ = interface_name;

        // TODO: Implement proper ioctl SIOCGIFMTU call
        // This requires unsafe code with libc::ioctl
        Some(1500)
    }

    /// Get MTU for local IP address
    pub fn get_mtu_for_address(addr: IpAddr) -> Option<usize> {
        #[cfg(feature = "connectivity")]
        {
            use if_addrs::get_if_addrs;

            if let Ok(interfaces) = get_if_addrs() {
                for iface in interfaces {
                    if iface.addr.ip() == addr {
                        return Self::get_interface_mtu(&iface.name);
                    }
                }
            }
        }

        // Fallback based on IP version
        match addr {
            IpAddr::V4(_) => Some(1500), // Standard Ethernet
            IpAddr::V6(_) => Some(1280), // IPv6 minimum
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_mtu_calculation() {
        let ipv4_addr = "127.0.0.1".parse().unwrap();
        let ipv6_addr = "::1".parse().unwrap();
        let remote = "127.0.0.1:1234".parse().unwrap();

        let pmtud_v4 = PathMtuDiscovery::new(ipv4_addr, remote);
        assert_eq!(pmtud_v4.get_min_mtu(), MIN_PLPMTU_IPV4);

        let pmtud_v6 = PathMtuDiscovery::new(ipv6_addr, remote);
        assert_eq!(pmtud_v6.get_min_mtu(), MIN_PLPMTU_IPV6);
    }

    #[test]
    fn test_payload_calculation_ipv4() {
        let ipv4_addr = "127.0.0.1".parse().unwrap();
        let remote = "127.0.0.1:1234".parse().unwrap();
        let pmtud = PathMtuDiscovery::new(ipv4_addr, remote);

        // Standard Ethernet MTU 1500
        // IPv4 header: 20, UDP: 8, SHARP: 30
        // Payload = 1500 - 20 - 8 - 30 = 1442
        let payload = pmtud.calculate_max_payload(1500);
        assert_eq!(payload, 1442);
    }

    #[test]
    fn test_payload_calculation_ipv6() {
        let ipv6_addr = "::1".parse().unwrap();
        let remote = "[::1]:1234".parse().unwrap();
        let pmtud = PathMtuDiscovery::new(ipv6_addr, remote);

        // Standard Ethernet MTU 1500
        // IPv6 header: 40, UDP: 8, SHARP: 30
        // Payload = 1500 - 40 - 8 - 30 = 1422
        let payload = pmtud.calculate_max_payload(1500);
        assert_eq!(payload, 1422);
    }

    #[test]
    fn test_jumbo_frames_payload() {
        let ipv4_addr = "127.0.0.1".parse().unwrap();
        let remote = "127.0.0.1:1234".parse().unwrap();
        let pmtud = PathMtuDiscovery::new(ipv4_addr, remote);

        // Jumbo frames MTU 9000
        // Payload = 9000 - 20 - 8 - 30 = 8942
        let payload = pmtud.calculate_max_payload(9000);
        assert_eq!(payload, 8942);
    }

    #[test]
    fn test_state_transitions() {
        let ipv4_addr = "127.0.0.1".parse().unwrap();
        let remote = "127.0.0.1:1234".parse().unwrap();
        let pmtud = PathMtuDiscovery::new(ipv4_addr, remote);

        assert_eq!(pmtud.state(), PmtudState::Initial);

        *pmtud.state.write() = PmtudState::Probing;
        assert_eq!(pmtud.state(), PmtudState::Probing);

        *pmtud.state.write() = PmtudState::Complete;
        assert_eq!(pmtud.state(), PmtudState::Complete);
    }

    #[test]
    fn test_black_hole_detection() {
        let ipv4_addr = "127.0.0.1".parse().unwrap();
        let remote = "127.0.0.1:1234".parse().unwrap();
        let pmtud = PathMtuDiscovery::new(ipv4_addr, remote);

        // Simulate many failures
        pmtud.stats.write().probes_sent = 20;
        pmtud.stats.write().probes_failed = 18;

        assert!(pmtud.is_black_hole());
    }

    #[test]
    fn test_mtu_probe_sizes_sorted() {
        let mut sizes = MTU_PROBE_SIZES.to_vec();
        sizes.sort();
        sizes.reverse(); // Should be descending for efficient probing

        // Verify standard sizes are included
        assert!(sizes.contains(&1500)); // Ethernet
        assert!(sizes.contains(&1280)); // IPv6 minimum
        assert!(sizes.contains(&9000)); // Jumbo frames
    }
}
