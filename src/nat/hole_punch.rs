// src/nat/hole_punch.rs
//! Enhanced UDP hole punching implementation with RFC 4787 compliance
//! and integration with ICE, STUN, and advanced NAT traversal techniques

use std::net::{SocketAddr, IpAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::{interval, timeout, sleep, Instant as TokioInstant};
use rand::{Rng, RngCore};
use std::sync::Arc;
use parking_lot::RwLock;
use bytes::{Bytes, BytesMut, BufMut};

use crate::nat::error::{NatError, NatResult};
use crate::nat::metrics::HolePunchMetrics;
use crate::nat::stun::{NatBehavior, MappingBehavior, FilteringBehavior};
use crate::nat::ice::{Candidate, CandidateType};

/// RFC 4787 compliant hole punching configuration
#[derive(Debug, Clone)]
pub struct HolePunchConfig {
    /// Maximum attempts for hole punching
    pub max_attempts: u32,

    /// Base interval between packets (RFC 4787 recommends 20ms)
    pub packet_interval: Duration,

    /// Overall timeout for hole punching
    pub timeout: Duration,

    /// Enable birthday paradox optimization
    pub enable_birthday_paradox: bool,

    /// Enable rapid fire for symmetric NATs
    pub enable_rapid_fire: bool,

    /// Enable TTL probing for detecting NAT hops
    pub enable_ttl_probing: bool,

    /// Enable port prediction for symmetric NATs
    pub enable_port_prediction: bool,

    /// Number of sockets for birthday paradox
    pub birthday_sockets: usize,

    /// Packet sizes to test (for PMTU discovery)
    pub probe_sizes: Vec<usize>,
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            max_attempts: 50,
            packet_interval: Duration::from_millis(20),
            timeout: Duration::from_secs(30),
            enable_birthday_paradox: true,
            enable_rapid_fire: true,
            enable_ttl_probing: true,
            enable_port_prediction: true,
            birthday_sockets: 20,
            probe_sizes: vec![
                28,    // Minimum UDP
                576,   // IPv4 minimum reassembly
                1280,  // IPv6 minimum MTU
                1472,  // Ethernet - headers
                9000,  // Jumbo frames
            ],
        }
    }
}

/// Enhanced hole punching statistics
#[derive(Debug, Clone)]
pub struct HolePunchStats {
    /// Strategy that succeeded
    pub successful_strategy: Option<String>,

    /// Total packets sent
    pub packets_sent: u32,

    /// Total packets received
    pub packets_received: u32,

    /// Time to first response
    pub first_response_time: Option<Duration>,

    /// Time to stable connection
    pub connection_time: Option<Duration>,

    /// Detected MTU
    pub detected_mtu: Option<usize>,

    /// Detected TTL distance
    pub ttl_distance: Option<u8>,

    /// Port prediction accuracy (for symmetric NAT)
    pub port_prediction_accuracy: Option<f64>,

    /// Packet loss rate
    pub packet_loss_rate: f64,

    /// Round trip times
    pub rtt_samples: Vec<Duration>,
}

impl Default for HolePunchStats {
    fn default() -> Self {
        Self {
            successful_strategy: None,
            packets_sent: 0,
            packets_received: 0,
            first_response_time: None,
            connection_time: None,
            detected_mtu: None,
            ttl_distance: None,
            port_prediction_accuracy: None,
            packet_loss_rate: 0.0,
            rtt_samples: Vec::new(),
        }
    }
}

/// Protocol identifier for hole punch packets
const HOLE_PUNCH_MAGIC: &[u8] = b"SHARP_HP_V2";

/// Hole punch packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum PacketType {
    /// Initial probe
    Probe = 0x01,
    /// Response to probe
    Response = 0x02,
    /// Keep-alive
    KeepAlive = 0x03,
    /// MTU discovery
    MtuProbe = 0x04,
    /// TTL probe
    TtlProbe = 0x05,
    /// Port prediction
    PortPredict = 0x06,
    /// Connection established
    Connected = 0x07,
}

/// Hole punch packet structure
#[derive(Debug, Clone)]
struct HolePunchPacket {
    /// Packet type
    packet_type: PacketType,

    /// Session ID
    session_id: [u8; 16],

    /// Sequence number
    sequence: u32,

    /// Timestamp (microseconds)
    timestamp: u64,

    /// Sender's observed address (for STUN-like behavior)
    observed_addr: Option<SocketAddr>,

    /// Payload data
    payload: Vec<u8>,
}

impl HolePunchPacket {
    fn new(packet_type: PacketType, session_id: [u8; 16], sequence: u32) -> Self {
        Self {
            packet_type,
            session_id,
            sequence,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64,
            observed_addr: None,
            payload: Vec::new(),
        }
    }

    fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(256);

        // Magic
        buf.put_slice(HOLE_PUNCH_MAGIC);

        // Version
        buf.put_u8(2);

        // Packet type
        buf.put_u8(self.packet_type as u8);

        // Session ID
        buf.put_slice(&self.session_id);

        // Sequence
        buf.put_u32(self.sequence);

        // Timestamp
        buf.put_u64(self.timestamp);

        // Observed address (optional)
        match self.observed_addr {
            Some(addr) => {
                buf.put_u8(1); // Has address
                match addr {
                    SocketAddr::V4(v4) => {
                        buf.put_u8(4); // IPv4
                        buf.put_slice(&v4.ip().octets());
                        buf.put_u16(v4.port());
                    }
                    SocketAddr::V6(v6) => {
                        buf.put_u8(6); // IPv6
                        buf.put_slice(&v6.ip().octets());
                        buf.put_u16(v6.port());
                    }
                }
            }
            None => {
                buf.put_u8(0); // No address
            }
        }

        // Payload length and data
        buf.put_u16(self.payload.len() as u16);
        buf.put_slice(&self.payload);

        buf.freeze()
    }

    fn decode(data: &[u8]) -> NatResult<Self> {
        if data.len() < HOLE_PUNCH_MAGIC.len() + 32 {
            return Err(NatError::Platform("Packet too short".to_string()));
        }

        let mut cursor = 0;

        // Check magic
        if &data[..HOLE_PUNCH_MAGIC.len()] != HOLE_PUNCH_MAGIC {
            return Err(NatError::Platform("Invalid magic".to_string()));
        }
        cursor += HOLE_PUNCH_MAGIC.len();

        // Version
        let version = data[cursor];
        if version != 2 {
            return Err(NatError::Platform(format!(
                "Unsupported version: {}",
                version
            )));
        }
        cursor += 1;

        // Packet type
        let packet_type = match data[cursor] {
            0x01 => PacketType::Probe,
            0x02 => PacketType::Response,
            0x03 => PacketType::KeepAlive,
            0x04 => PacketType::MtuProbe,
            0x05 => PacketType::TtlProbe,
            0x06 => PacketType::PortPredict,
            0x07 => PacketType::Connected,
            _ => return Err(NatError::Platform("Invalid packet type".to_string())),
        };
        cursor += 1;

        // Session ID
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[cursor..cursor + 16]);
        cursor += 16;

        // Sequence
        let sequence = u32::from_be_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]);
        cursor += 4;

        // Timestamp
        let timestamp = u64::from_be_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
            data[cursor + 4],
            data[cursor + 5],
            data[cursor + 6],
            data[cursor + 7],
        ]);
        cursor += 8;

        // Observed address
        let observed_addr = if data[cursor] == 1 {
            cursor += 1;
            let addr_type = data[cursor];
            cursor += 1;

            match addr_type {
                4 => {
                    let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                        data[cursor], data[cursor + 1], data[cursor + 2], data[cursor + 3]
                    ));
                    cursor += 4;
                    let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
                    cursor += 2;
                    Some(SocketAddr::new(ip, port))
                }
                6 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&data[cursor..cursor + 16]);
                    cursor += 16;
                    let ip = IpAddr::V6(std::net::Ipv6Addr::from(octets));
                    let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
                    cursor += 2;
                    Some(SocketAddr::new(ip, port))
                }
                _ => return Err(NatError::Platform("Invalid address type".to_string())),
            }
        } else {
            cursor += 1;
            None
        };

        // Payload
        let payload_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
        cursor += 2;

        let payload = if cursor + payload_len <= data.len() {
            data[cursor..cursor + payload_len].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            packet_type,
            session_id,
            sequence,
            timestamp,
            observed_addr,
            payload,
        })
    }
}

/// Enhanced UDP hole puncher with multiple strategies
pub struct HolePuncher {
    config: HolePunchConfig,
    stats: Arc<RwLock<HolePunchStats>>,
    metrics: Arc<HolePunchMetrics>,
}

impl HolePuncher {
    /// Create new hole puncher with configuration
    pub fn new(config: HolePunchConfig) -> Self {
        Self {
            config,
            stats: Arc::new(RwLock::new(HolePunchStats::default())),
            metrics: Arc::new(HolePunchMetrics::new()),
        }
    }

    /// Perform hole punching with automatic strategy selection
    pub async fn punch_hole(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
        nat_behavior: Option<&NatBehavior>,
    ) -> NatResult<HolePunchStats> {
        let start_time = Instant::now();
        let session_id = self.generate_session_id();

        tracing::info!(
            "Starting hole punch to {} (role: {}, NAT: {:?})",
            peer_addr,
            if is_initiator {
                "initiator"
            } else {
                "responder"
            },
            nat_behavior.map(|n| n.to_simple_nat_type())
        );

        self.metrics.record_attempt(peer_addr);

        // Select strategy based on NAT behavior
        let strategy = self.select_strategy(nat_behavior);

        // Execute selected strategy
        let result = match strategy.as_str() {
            "direct" => {
                self.direct_punch(socket, peer_addr, is_initiator, session_id)
                    .await
            }
            "birthday" => {
                self.birthday_paradox_punch(socket, peer_addr, is_initiator, session_id)
                    .await
            }
            "rapid_fire" => {
                self.rapid_fire_punch(socket, peer_addr, is_initiator, session_id)
                    .await
            }
            "port_prediction" => {
                self.port_prediction_punch(socket, peer_addr, is_initiator, session_id)
                    .await
            }
            "ttl_discovery" => {
                self.ttl_discovery_punch(socket, peer_addr, is_initiator, session_id)
                    .await
            }
            "sequential" => {
                self.sequential_strategy(socket, peer_addr, is_initiator, session_id, nat_behavior)
                    .await
            }
            _ => {
                self.classic_punch(socket, peer_addr, is_initiator, session_id)
                    .await
            }
        };

        // Update stats
        let mut stats = self.stats.write();
        if result.is_ok() {
            stats.successful_strategy = Some(strategy.clone());
            stats.connection_time = Some(start_time.elapsed());
            self.metrics
                .record_success(peer_addr, start_time.elapsed(), strategy);
        } else {
            self.metrics.record_failure(peer_addr, strategy);
        }

        result.map(|_| stats.clone())
    }

    /// Select optimal strategy based on NAT behavior
    fn select_strategy(&self, nat_behavior: Option<&NatBehavior>) -> String {
        match nat_behavior {
            Some(behavior) => {
                match (behavior.mapping, behavior.filtering) {
                    // Best case: Full Cone NAT
                    (
                        MappingBehavior::EndpointIndependent,
                        FilteringBehavior::EndpointIndependent,
                    ) => "direct".to_string(),
                    // Good case: Restricted Cone NAT
                    (MappingBehavior::EndpointIndependent, FilteringBehavior::AddressDependent) => {
                        "classic".to_string()
                    }
                    // Moderate case: Port Restricted Cone NAT
                    (
                        MappingBehavior::EndpointIndependent,
                        FilteringBehavior::AddressPortDependent,
                    ) => {
                        if self.config.enable_birthday_paradox {
                            "birthday".to_string()
                        } else {
                            "rapid_fire".to_string()
                        }
                    }
                    // Hard case: Symmetric NAT
                    (MappingBehavior::AddressDependent, _)
                    | (MappingBehavior::AddressPortDependent, _) => {
                        if self.config.enable_port_prediction {
                            "port_prediction".to_string()
                        } else if self.config.enable_birthday_paradox {
                            "birthday".to_string()
                        } else {
                            "rapid_fire".to_string()
                        }
                    }
                }
            }
            None => {
                // Unknown NAT behavior - try all strategies sequentially
                "sequential".to_string()
            }
        }
    }

    /// Direct connection (for Full Cone NAT or no NAT)
    async fn direct_punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
        session_id: [u8; 16],
    ) -> NatResult<()> {
        tracing::debug!("Using direct connection strategy");

        let mut packet = HolePunchPacket::new(PacketType::Probe, session_id, 0);

        // Simple handshake
        for i in 0..3 {
            packet.sequence = i;
            socket.send_to(&packet.encode(), peer_addr).await?;

            let mut buf = vec![0u8; 2048];
            match timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) if addr == peer_addr => {
                    if let Ok(response) = HolePunchPacket::decode(&buf[..size]) {
                        if response.packet_type == PacketType::Response
                            && response.session_id == session_id
                        {
                            self.stats.write().packets_received += 1;

                            // Send confirmation
                            let confirm =
                                HolePunchPacket::new(PacketType::Connected, session_id, i + 1);
                            socket.send_to(&confirm.encode(), peer_addr).await?;

                            return Ok(());
                        }
                    }
                }
                _ => {}
            }

            self.stats.write().packets_sent += 1;
        }

        Err(NatError::Transient("Direct connection failed".to_string()))
    }

    /// Classic hole punching with improved timing
    async fn classic_punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
        session_id: [u8; 16],
    ) -> NatResult<()> {
        tracing::debug!("Using classic hole punching strategy");

        let start_time = Instant::now();
        let mut interval = interval(self.config.packet_interval);
        let mut sequence = 0u32;

        // Phase 1: Initial burst (RFC 4787 recommends initial rapid packets)
        for i in 0..10 {
            let packet = HolePunchPacket::new(
                if is_initiator {
                    PacketType::Probe
                } else {
                    PacketType::Response
                },
                session_id,
                sequence,
            );
            sequence += 1;

            socket.send_to(&packet.encode(), peer_addr).await?;
            self.stats.write().packets_sent += 1;

            // Check for response immediately
            let mut buf = vec![0u8; 2048];
            match timeout(Duration::from_millis(10), socket.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) if addr == peer_addr => {
                    if self
                        .handle_packet(&buf[..size], session_id, socket, peer_addr)
                        .await?
                    {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }

        // Phase 2: Regular interval packets with backoff
        let mut backoff_factor = 1;

        while start_time.elapsed() < self.config.timeout {
            interval.tick().await;

            let packet = HolePunchPacket::new(
                if is_initiator {
                    PacketType::Probe
                } else {
                    PacketType::Response
                },
                session_id,
                sequence,
            );
            sequence += 1;

            socket.send_to(&packet.encode(), peer_addr).await?;
            self.stats.write().packets_sent += 1;

            // Listen for responses with timeout
            let mut buf = vec![0u8; 2048];
            let listen_duration = self.config.packet_interval * backoff_factor;

            match timeout(listen_duration, socket.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) if addr == peer_addr => {
                    if self
                        .handle_packet(&buf[..size], session_id, socket, peer_addr)
                        .await?
                    {
                        return Ok(());
                    }
                }
                _ => {
                    // Increase backoff on no response
                    if sequence % 20 == 0 && backoff_factor < 10 {
                        backoff_factor += 1;
                    }
                }
            }
        }

        Err(NatError::Timeout(self.config.timeout))
    }

    /// Birthday paradox optimization for symmetric NATs (RFC 4787 Section 4)
    async fn birthday_paradox_punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
        session_id: [u8; 16],
    ) -> NatResult<()> {
        tracing::debug!(
            "Using birthday paradox strategy with {} sockets",
            self.config.birthday_sockets
        );

        // Create multiple sockets
        let mut sockets = Vec::new();
        for _ in 0..self.config.birthday_sockets {
            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => sockets.push(Arc::new(s)),
                Err(_) => break,
            }
        }

        if sockets.len() < 3 {
            return Err(NatError::Platform(
                "Failed to create enough sockets".to_string(),
            ));
        }

        tracing::debug!("Created {} sockets for birthday paradox", sockets.len());

        // Send from all sockets concurrently
        let mut handles = Vec::new();

        for (idx, sock) in sockets.iter().enumerate() {
            let sock = sock.clone();
            let stats = self.stats.clone();

            let handle = tokio::spawn(async move {
                let mut sequence = (idx as u32) * 1000;
                let mut packet = HolePunchPacket::new(PacketType::Probe, session_id, sequence);

                // Rapid burst from each socket
                for i in 0..20 {
                    packet.sequence = sequence + i;
                    packet.payload = vec![idx as u8; 32]; // Identify source socket

                    if sock.send_to(&packet.encode(), peer_addr).await.is_ok() {
                        stats.write().packets_sent += 1;
                    }

                    // Very short delay
                    sleep(Duration::from_micros(100)).await;
                }

                // Listen for responses
                let mut buf = vec![0u8; 2048];
                for _ in 0..100 {
                    match timeout(Duration::from_millis(50), sock.recv_from(&mut buf)).await {
                        Ok(Ok((size, addr))) if addr == peer_addr => {
                            if let Ok(response) = HolePunchPacket::decode(&buf[..size]) {
                                if response.session_id == session_id {
                                    stats.write().packets_received += 1;
                                    return Ok((sock, response));
                                }
                            }
                        }
                        _ => {}
                    }
                }

                Err(())
            });

            handles.push(handle);
        }

        // Wait for any socket to succeed
        match timeout(self.config.timeout, async {
            for handle in handles {
                if let Ok(Ok((sock, response))) = handle.await {
                    return Ok((sock, response));
                }
            }
            Err(())
        })
            .await
        {
            Ok(Ok((winning_socket, response))) => {
                tracing::info!(
                    "Birthday paradox succeeded with socket on port {}",
                    winning_socket.local_addr()?.port()
                );

                // Confirm connection
                let confirm =
                    HolePunchPacket::new(PacketType::Connected, session_id, response.sequence + 1);
                winning_socket.send_to(&confirm.encode(), peer_addr).await?;

                Ok(())
            }
            _ => Err(NatError::Transient("Birthday paradox failed".to_string())),
        }
    }

    /// Rapid fire approach for aggressive NATs
    async fn rapid_fire_punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
        session_id: [u8; 16],
    ) -> NatResult<()> {
        tracing::debug!("Using rapid fire strategy");

        let mut rng = rand::thread_rng();
        let mut sequence = 0u32;

        // Phase 1: Burst with varying packet sizes
        for size in &self.config.probe_sizes {
            for _ in 0..20 {
                let mut packet = HolePunchPacket::new(PacketType::MtuProbe, session_id, sequence);
                packet.payload = vec![0u8; *size];
                rng.fill_bytes(&mut packet.payload);
                sequence += 1;

                if socket.send_to(&packet.encode(), peer_addr).await.is_ok() {
                    self.stats.write().packets_sent += 1;
                }

                // Minimal delay
                sleep(Duration::from_micros(50)).await;
            }
        }

        // Phase 2: Pattern variation
        let patterns = vec![
            vec![100, 200, 100, 300], // Variable delays
            vec![50; 10],             // Consistent rapid
            vec![500, 50, 50, 500],   // Burst pattern
        ];

        for pattern in patterns {
            for delay in pattern {
                let packet = HolePunchPacket::new(PacketType::Probe, session_id, sequence);
                sequence += 1;

                socket.send_to(&packet.encode(), peer_addr).await?;
                self.stats.write().packets_sent += 1;

                // Check for response
                let mut buf = vec![0u8; 2048];
                match timeout(Duration::from_millis(delay), socket.recv_from(&mut buf)).await {
                    Ok(Ok((size, addr))) if addr == peer_addr => {
                        if self
                            .handle_packet(&buf[..size], session_id, socket, peer_addr)
                            .await?
                        {
                            return Ok(());
                        }
                    }
                    _ => {}
                }

                sleep(Duration::from_millis(delay)).await;
            }
        }

        Err(NatError::Transient("Rapid fire failed".to_string()))
    }

    /// Port prediction for symmetric NATs
    async fn port_prediction_punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
        session_id: [u8; 16],
    ) -> NatResult<()> {
        tracing::debug!("Using port prediction strategy");

        // First, try to determine port allocation pattern
        let base_port = peer_addr.port();
        let mut predicted_ports = Vec::new();

        // Common port allocation patterns
        // 1. Sequential
        for offset in -10i16..=10 {
            let port = base_port.wrapping_add(offset as u16);
            predicted_ports.push(port);
        }

        // 2. Random but in ranges
        let ranges = vec![
            (1024, 5000),
            (10000, 30000),
            (30000, 60000),
        ];

        for (start, end) in ranges {
            if base_port >= start && base_port <= end {
                // Add some random ports in the same range
                let mut rng = rand::thread_rng();
                for _ in 0..10 {
                    predicted_ports.push(rng.gen_range(start..=end));
                }
            }
        }

        // 3. Port reuse from a pool
        let common_ports = vec![
            base_port.wrapping_sub(1),
            base_port.wrapping_add(1),
            base_port ^ 0xFF,   // Simple bit manipulation
            base_port ^ 0xFFFF, // Invert all bits
        ];
        predicted_ports.extend(common_ports);

        // Remove duplicates
        predicted_ports.sort_unstable();
        predicted_ports.dedup();

        let total_ports = predicted_ports.len();
        tracing::debug!("Testing {} predicted ports", total_ports);

        // Test predicted ports
        let mut sequence = 0u32;
        for port in predicted_ports {
            let mut test_addr = peer_addr;
            test_addr.set_port(port);

            let packet = HolePunchPacket::new(PacketType::PortPredict, session_id, sequence);
            sequence += 1;

            socket.send_to(&packet.encode(), test_addr).await?;
            self.stats.write().packets_sent += 1;

            // Quick check for response
            let mut buf = vec![0u8; 2048];
            match timeout(Duration::from_millis(5), socket.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) => {
                    if let Ok(response) = HolePunchPacket::decode(&buf[..size]) {
                        if response.session_id == session_id {
                            tracing::info!("Port prediction succeeded: {} -> {}", peer_addr, addr);

                            self.stats.write().port_prediction_accuracy =
                                Some(sequence as f64 / total_ports as f64);

                            // Continue with this address
                            return self
                                .classic_punch(socket, addr, is_initiator, session_id)
                                .await;
                        }
                    }
                }
                _ => {}
            }
        }

        Err(NatError::Transient("Port prediction failed".to_string()))
    }

    /// TTL-based distance discovery
    async fn ttl_discovery_punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
        session_id: [u8; 16],
    ) -> NatResult<()> {
        tracing::debug!("Using TTL discovery strategy");

        // Note: Setting TTL requires special socket options
        // This is a simplified version

        let ttl_values = vec![1, 2, 3, 4, 8, 16, 32, 64, 128, 255];

        for ttl in ttl_values {
            tracing::trace!("Testing TTL {}", ttl);

            let mut packet = HolePunchPacket::new(PacketType::TtlProbe, session_id, ttl as u32);
            packet.payload = vec![ttl; 32];

            // In real implementation, we would set socket TTL here
            // socket.set_ttl(ttl)?;

            socket.send_to(&packet.encode(), peer_addr).await?;
            self.stats.write().packets_sent += 1;

            // Listen for response or ICMP
            let mut buf = vec![0u8; 2048];
            match timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) if addr == peer_addr => {
                    if let Ok(response) = HolePunchPacket::decode(&buf[..size]) {
                        if response.session_id == session_id {
                            self.stats.write().ttl_distance = Some(ttl);
                            tracing::info!("TTL distance to peer: {}", ttl);

                            // Continue with classic approach
                            return self.classic_punch(socket, peer_addr, is_initiator, session_id).await;
                        }
                    }
                }
                _ => {}
            }
        }

        Err(NatError::Transient("TTL discovery failed".to_string()))
    }

    /// Sequential strategy - try all strategies in order
    async fn sequential_strategy(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
        session_id: [u8; 16],
        nat_behavior: Option<&NatBehavior>,
    ) -> NatResult<()> {
        tracing::debug!("Using sequential strategy (unknown NAT behavior)");

        // Try each strategy in a predefined order. We avoid casting async
        // functions to function pointers by matching on the strategy name
        // inside the loop.

        let strategies = vec![
            "direct",
            "classic",
            "rapid_fire",
            "birthday",
            "port_prediction",
        ];

        for name in strategies {
            tracing::info!("Trying {} strategy", name);

            let res = match name {
                "direct" => {
                    timeout(
                        Duration::from_secs(5),
                        self.direct_punch(socket, peer_addr, is_initiator, session_id),
                    )
                        .await
                }
                "classic" => {
                    timeout(
                        Duration::from_secs(5),
                        self.classic_punch(socket, peer_addr, is_initiator, session_id),
                    )
                        .await
                }
                "rapid_fire" => {
                    timeout(
                        Duration::from_secs(5),
                        self.rapid_fire_punch(socket, peer_addr, is_initiator, session_id),
                    )
                        .await
                }
                "birthday" => {
                    timeout(
                        Duration::from_secs(5),
                        self.birthday_paradox_punch(socket, peer_addr, is_initiator, session_id),
                    )
                        .await
                }
                "port_prediction" => {
                    timeout(
                        Duration::from_secs(5),
                        self.port_prediction_punch(socket, peer_addr, is_initiator, session_id),
                    )
                        .await
                }
                _ => unreachable!(),
            };

            match res {
                Ok(Ok(())) => {
                    self.stats.write().successful_strategy = Some(name.to_string());
                    return Ok(());
                }
                Ok(Err(e)) => {
                    tracing::debug!("{} strategy failed: {}", name, e);
                }
                Err(_) => {
                    tracing::debug!("{} strategy timed out", name);
                }
            }

            // Brief pause between strategies
            sleep(Duration::from_millis(100)).await;
        }

        Err(NatError::AllMethodsFailed)
    }

    /// Handle incoming packet
    async fn handle_packet(
        &self,
        data: &[u8],
        session_id: [u8; 16],
        socket: &UdpSocket,
        peer_addr: SocketAddr,
    ) -> NatResult<bool> {
        let packet = HolePunchPacket::decode(data)?;

        if packet.session_id != session_id {
            return Ok(false);
        }

        let mut stats = self.stats.write();
        stats.packets_received += 1;

        if stats.first_response_time.is_none() {
            let micros = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64)
                .saturating_sub(packet.timestamp)
                .max(1);
            stats.first_response_time = Some(Duration::from_micros(micros));
        }

        // Calculate RTT
        let rtt = Duration::from_micros(
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64)
                .saturating_sub(packet.timestamp),
        );
        stats.rtt_samples.push(rtt);

        drop(stats);

        match packet.packet_type {
            PacketType::Probe => {
                // Respond to probe
                let mut response = HolePunchPacket::new(PacketType::Response, session_id, packet.sequence);
                response.observed_addr = Some(peer_addr);
                socket.send_to(&response.encode(), peer_addr).await?;
                Ok(false)
            }
            PacketType::Response => {
                // Send connection confirmation
                let confirm = HolePunchPacket::new(PacketType::Connected, session_id, packet.sequence + 1);
                socket.send_to(&confirm.encode(), peer_addr).await?;
                Ok(true)
            }
            PacketType::Connected => {
                // Connection established
                Ok(true)
            }
            PacketType::MtuProbe => {
                // MTU discovery
                self.stats.write().detected_mtu = Some(packet.payload.len());
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// Generate session ID
    fn generate_session_id(&self) -> [u8; 16] {
        let mut id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    /// Test connectivity after hole punching
    pub async fn test_connectivity(
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        test_data: &[u8],
    ) -> NatResult<bool> {
        let test_packet = [b"SHARP_CONNECTIVITY_TEST", test_data].concat();

        for i in 0..3 {
            socket.send_to(&test_packet, peer_addr).await?;

            let mut buf = vec![0u8; test_packet.len() + 100];
            match timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) if addr == peer_addr && size >= test_packet.len() => {
                    if &buf[..test_packet.len()] == test_packet.as_slice() {
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }

        Ok(false)
    }

    /// Maintain hole with keep-alive packets
    pub async fn maintain_hole(
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        interval_secs: u64,
        session_id: [u8; 16],
    ) -> NatResult<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        let mut seq = 0u32;

        loop {
            interval.tick().await;

            let packet = HolePunchPacket::new(PacketType::KeepAlive, session_id, seq);
            seq = seq.wrapping_add(1);

            if let Err(e) = socket.send_to(&packet.encode(), peer_addr).await {
                tracing::warn!("Keep-alive failed: {}", e);
                return Err(NatError::Network(e));
            }

            tracing::trace!("Keep-alive {} sent to {}", seq, peer_addr);
        }
    }
}

/// Coordinated hole punching with signaling server
pub struct CoordinatedHolePunch {
    puncher: HolePuncher,
    coordinator_addr: Option<SocketAddr>,
}

impl CoordinatedHolePunch {
    pub fn new(config: HolePunchConfig, coordinator_addr: Option<SocketAddr>) -> Self {
        Self {
            puncher: HolePuncher::new(config),
            coordinator_addr,
        }
    }

    /// Perform coordinated simultaneous hole punching
    pub async fn simultaneous_punch(
        &self,
        socket: &UdpSocket,
        peer_id: &str,
        nat_behavior: Option<&NatBehavior>,
    ) -> NatResult<(SocketAddr, HolePunchStats)> {
        if let Some(coordinator) = self.coordinator_addr {
            // Register with coordinator
            let register_msg = format!("REGISTER:{}:{}", peer_id, socket.local_addr()?);
            socket.send_to(register_msg.as_bytes(), coordinator).await?;

            // Wait for peer info
            let mut buf = vec![0u8; 1024];
            let (size, _) = timeout(
                Duration::from_secs(30),
                socket.recv_from(&mut buf)
            ).await
                .map_err(|_| NatError::Timeout(Duration::from_secs(30)))?
                .map_err(|e| NatError::Network(e))?;

            let response = String::from_utf8_lossy(&buf[..size]);
            if let Some(peer_addr_str) = response.strip_prefix("PEER:") {
                let peer_addr: SocketAddr = peer_addr_str.parse()
                    .map_err(|_| NatError::Platform("Invalid peer address".to_string()))?;

                // Signal ready
                let ready_msg = format!("READY:{}", peer_id);
                socket.send_to(ready_msg.as_bytes(), coordinator).await?;

                // Wait for start signal
                let (size, _) = timeout(
                    Duration::from_secs(10),
                    socket.recv_from(&mut buf)
                ).await
                    .map_err(|_| NatError::Timeout(Duration::from_secs(10)))?
                    .map_err(|e| NatError::Network(e))?;

                if &buf[..size] == b"START" {
                    // Perform synchronized hole punching
                    let stats = self
                        .puncher
                        .punch_hole(
                            socket,
                            peer_addr,
                            true, // Both act as initiators in simultaneous mode
                            nat_behavior,
                        )
                        .await?;

                    return Ok((peer_addr, stats));
                }
            }
        }

        Err(NatError::Platform("Coordination failed".to_string()))
    }
}

/// ICE-compatible hole punching
pub struct IceCompatibleHolePunch {
    puncher: HolePuncher,
}

impl IceCompatibleHolePunch {
    pub fn new(config: HolePunchConfig) -> Self {
        Self {
            puncher: HolePuncher::new(config),
        }
    }

    /// Create hole punch from ICE candidates
    pub async fn punch_from_candidates(
        &self,
        socket: &UdpSocket,
        local_candidate: &Candidate,
        remote_candidate: &Candidate,
        is_controlling: bool,
    ) -> NatResult<HolePunchStats> {
        // Determine NAT behavior from candidate types
        let nat_behavior = self.infer_nat_behavior(local_candidate, remote_candidate);

        // Perform hole punching
        self.puncher
            .punch_hole(
                socket,
                remote_candidate.addr,
                is_controlling,
                nat_behavior.as_ref(),
            )
            .await
    }

    /// Infer NAT behavior from ICE candidates
    fn infer_nat_behavior(
        &self,
        local: &Candidate,
        remote: &Candidate,
    ) -> Option<NatBehavior> {
        // Basic inference based on candidate types
        let mapping = match local.typ {
            CandidateType::Host => MappingBehavior::EndpointIndependent,
            CandidateType::ServerReflexive => MappingBehavior::EndpointIndependent,
            CandidateType::PeerReflexive => MappingBehavior::AddressDependent,
            CandidateType::Relay => MappingBehavior::AddressPortDependent,
        };

        let filtering = match remote.typ {
            CandidateType::Host => FilteringBehavior::EndpointIndependent,
            CandidateType::ServerReflexive => FilteringBehavior::AddressDependent,
            CandidateType::PeerReflexive => FilteringBehavior::AddressPortDependent,
            CandidateType::Relay => FilteringBehavior::AddressPortDependent,
        };

        Some(NatBehavior {
            mapping,
            filtering,
            hairpinning: false,
            mapping_lifetime: None,
            public_addresses: vec![local.addr],
            confidence: 0.5, // Low confidence from inference
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_encoding_decoding() {
        let mut packet = HolePunchPacket::new(
            PacketType::Probe,
            [1u8; 16],
            42
        );
        packet.observed_addr = Some("192.168.1.1:12345".parse().unwrap());
        packet.payload = vec![1, 2, 3, 4, 5];

        let encoded = packet.encode();
        let decoded = HolePunchPacket::decode(&encoded).unwrap();

        assert_eq!(decoded.packet_type, packet.packet_type);
        assert_eq!(decoded.session_id, packet.session_id);
        assert_eq!(decoded.sequence, packet.sequence);
        assert_eq!(decoded.observed_addr, packet.observed_addr);
        assert_eq!(decoded.payload, packet.payload);
    }

    #[tokio::test]
    async fn test_strategy_selection() {
        let config = HolePunchConfig::default();
        let puncher = HolePuncher::new(config);

        // Full Cone NAT
        let behavior = NatBehavior {
            mapping: MappingBehavior::EndpointIndependent,
            filtering: FilteringBehavior::EndpointIndependent,
            hairpinning: true,
            mapping_lifetime: Some(3600),
            public_addresses: vec![],
            confidence: 1.0,
        };

        assert_eq!(puncher.select_strategy(Some(&behavior)), "direct");

        // Symmetric NAT
        let behavior = NatBehavior {
            mapping: MappingBehavior::AddressPortDependent,
            filtering: FilteringBehavior::AddressPortDependent,
            hairpinning: false,
            mapping_lifetime: Some(60),
            public_addresses: vec![],
            confidence: 1.0,
        };

        let strategy = puncher.select_strategy(Some(&behavior));
        assert!(strategy == "port_prediction" || strategy == "birthday");
    }
}