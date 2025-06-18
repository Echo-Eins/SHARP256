use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::{interval, timeout, sleep};
use rand::{Rng, RngCore};
use std::sync::Arc;
use parking_lot::RwLock;

/// Enhanced UDP hole punching with multiple strategies
pub struct HolePuncher {
    max_attempts: u32,
    packet_interval: Duration,
    timeout_duration: Duration,
    use_birthday_paradox: bool,
}

/// Hole punching statistics
#[derive(Debug, Default, Clone)]
pub struct PunchStatistics {
    pub packets_sent: u32,
    pub packets_received: u32,
    pub first_response_time: Option<Duration>,
    pub success: bool,
    pub strategy_used: String,
}

impl HolePuncher {
    pub fn new(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            packet_interval: Duration::from_millis(20), // 50 packets/sec
            timeout_duration: Duration::from_secs(10),
            use_birthday_paradox: true,
        }
    }

    /// Perform hole punching with multiple strategies
    pub async fn punch_hole(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
    ) -> Result<()> {
        tracing::info!("Starting hole punch to {} (role: {})",
            peer_addr,
            if is_initiator { "initiator" } else { "responder" }
        );

        let stats = Arc::new(RwLock::new(PunchStatistics::default()));

        // Try strategies sequentially with proper async handling
        let result = tokio::select! {
            res = self.classic_punch(socket, peer_addr, is_initiator, stats.clone()) => {
                stats.write().strategy_used = "Classic".to_string();
                res
            }
            res = self.birthday_paradox_punch(socket, peer_addr, is_initiator, stats.clone()) => {
                stats.write().strategy_used = "Birthday Paradox".to_string();
                res
            }
            res = self.rapid_fire_punch(socket, peer_addr, is_initiator, stats.clone()) => {
                stats.write().strategy_used = "Rapid Fire".to_string();
                res
            }
        };

        let final_stats = stats.read().clone();
        tracing::info!("Hole punch completed - Strategy: {}, Packets sent: {}, Received: {}",
            final_stats.strategy_used,
            final_stats.packets_sent,
            final_stats.packets_received
        );

        result
    }

    /// Classic hole punching with improved timing
    async fn classic_punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
        stats: Arc<RwLock<PunchStatistics>>,
    ) -> Result<()> {
        let punch_id = rand::thread_rng().gen::<u32>();
        let start_time = Instant::now();

        // Create punch packet with role information
        let mut punch_packet = vec![
            b'S', b'H', b'A', b'R', b'P', // Protocol identifier
            b'_', b'P', b'U', b'N', b'C', b'H', // Punch identifier
            if is_initiator { 1 } else { 2 }, // Role byte
        ];
        punch_packet.extend_from_slice(&punch_id.to_be_bytes());

        let mut punch_interval = interval(self.packet_interval);
        let mut attempt = 0;

        // Create a channel for receiving responses
        let mut buf = vec![0u8; 1024];
        let expected_response = if is_initiator { 2u8 } else { 1u8 };

        // Send packets with adaptive timing
        while attempt < self.max_attempts {
            punch_interval.tick().await;

            // Send punch packet
            if let Err(e) = socket.send_to(&punch_packet, peer_addr).await {
                tracing::debug!("Punch send error: {}", e);
            } else {
                stats.write().packets_sent += 1;
            }

            // Wait briefly for a response
            match timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) if addr == peer_addr => {
                    if size >= 12 && &buf[..11] == b"SHARP_PUNCH" {
                        let role = buf[11];
                        if role == expected_response {
                            let mut s = stats.write();
                            s.packets_received += 1;
                            if s.first_response_time.is_none() {
                                s.first_response_time = Some(start_time.elapsed());
                            }
                            s.success = true;

                    // Send confirmation packets
                            // Send confirmation packets
                            for _ in 0..5 {
                                let _ = socket.send_to(b"SHARP_PUNCH_CONFIRM", peer_addr).await;
                                sleep(Duration::from_millis(10)).await;
                            }

                            return Ok(());
                        }
                    }
                }
                Ok(Ok((_size, _addr))) => {}
                Ok(Err(e)) => {
                    tracing::debug!("Receiver error: {}", e);
                }
                Err(_) => {}

            }

            // Adaptive timing - increase interval after initial burst
            if attempt == 10 {
                punch_interval = interval(Duration::from_millis(50));
            } else if attempt == 30 {
                punch_interval = interval(Duration::from_millis(100));
            }

            attempt += 1;
        }
        Ok(())
    }

    /// Birthday paradox optimization for symmetric NATs
    async fn birthday_paradox_punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
        stats: Arc<RwLock<PunchStatistics>>,
    ) -> Result<()> {
        if !self.use_birthday_paradox {
            // Never complete if not enabled
            loop {
                sleep(Duration::from_secs(3600)).await;
            }
        }

        tracing::debug!("Using birthday paradox optimization");

        // Create multiple sockets to increase port allocation
        let mut sockets = Vec::new();
        let socket_count = 10; // sqrt(65536) ≈ 256, but 10 is practical

        for _ in 0..socket_count {
            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => sockets.push(s),
                Err(e) => tracing::debug!("Failed to create extra socket: {}", e),
            }
        }

        // Include original socket if it can be cloned

        let punch_id = rand::thread_rng().gen::<u32>();
        let mut packets_sent = 0;

        // Send from all sockets rapidly
        for round in 0u8..5u8 {
            for (idx, sock) in sockets.iter().enumerate() {
                let mut packet = vec![
                    b'S', b'H', b'A', b'R', b'P',
                    b'_', b'B', b'D', b'A', b'Y', // Birthday marker
                    idx as u8,
                    if is_initiator { 1 } else { 2 },
                ];
                packet.extend_from_slice(&punch_id.to_be_bytes());
                packet.extend_from_slice(&(round as u32).to_be_bytes());

                if sock.send_to(&packet, peer_addr).await.is_ok() {
                    packets_sent += 1;
                }

                // Very short delay to avoid congestion
                sleep(Duration::from_micros(100)).await;
            }
        }

        stats.write().packets_sent += packets_sent;

        // Listen on all sockets for response
        let start = Instant::now();
        let timeout_duration = Duration::from_secs(5);

        while start.elapsed() < timeout_duration {
            for sock in &sockets {
                let mut buf = vec![0u8; 1024];
                match timeout(Duration::from_millis(10), sock.recv_from(&mut buf)).await {
                    Ok(Ok((size, addr))) if addr == peer_addr => {
                        if size >= 10 && &buf[..10] == b"SHARP_BDAY" {
                            stats.write().success = true;
                            stats.write().packets_received += 1;

                            // Found working socket, use it for confirmation
                            for _ in 0..3 {
                                let _ = sock.send_to(b"SHARP_BDAY_CONFIRM", peer_addr).await;
                            }

                            return Ok(());
                        }
                    }
                    _ => continue,
                }
            }

            // Small delay before next check
            sleep(Duration::from_millis(10)).await;
        }

        // Timeout reached
        Ok(())
    }

    /// Rapid fire approach for aggressive NATs
    async fn rapid_fire_punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
        stats: Arc<RwLock<PunchStatistics>>,
    ) -> Result<()> {
        tracing::debug!("Using rapid fire hole punching");

        let punch_id = rand::thread_rng().gen::<u32>();
        let mut rng = rand::thread_rng();

        // Phase 1: Initial burst (100 packets in 1 second)
        for i in 0u16..100u16 {
            let mut packet = vec![
                b'S', b'H', b'A', b'R', b'P',
                b'_', b'R', b'A', b'P', b'I', b'D',
                if is_initiator { 1 } else { 2 },
            ];
            packet.extend_from_slice(&punch_id.to_be_bytes());
            packet.extend_from_slice(&(i as u32).to_be_bytes());

            // Add random padding to vary packet size
            let padding_size = rng.gen_range(0..32);
            let padding: Vec<u8> = (0..padding_size).map(|_| rng.gen()).collect();
            packet.extend(padding);

            if socket.send_to(&packet, peer_addr).await.is_ok() {
                stats.write().packets_sent += 1;
            }

            sleep(Duration::from_millis(10)).await;
        }

        // Phase 2: Sustained fire with variable timing
        for _ in 0..50 {
            let mut packet = vec![b'S', b'H', b'A', b'R', b'P', b'_', b'R', b'2'];
            packet.extend_from_slice(&punch_id.to_be_bytes());

            if socket.send_to(&packet, peer_addr).await.is_ok() {
                stats.write().packets_sent += 1;
            }

            // Variable delay to work around timing-based filters
            let delay = rng.gen_range(20..100);
            sleep(Duration::from_millis(delay)).await;
        }

        Ok(())
    }

    /// Coordinated simultaneous hole punching
    pub async fn simultaneous_punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        coordination_server: Option<SocketAddr>,
    ) -> Result<()> {
        if let Some(coord_server) = coordination_server {
            // Signal readiness to coordinator
            let ready_msg = format!("READY:{}:{}", peer_addr, rand::thread_rng().gen::<u32>()).into_bytes();
            socket.send_to(&ready_msg, coord_server).await?;

            // Wait for start signal
            let mut buf = vec![0u8; 256];
            let start_time = Instant::now();

            loop {
                match timeout(Duration::from_secs(10), socket.recv_from(&mut buf)).await {
                    Ok(Ok((size, addr))) if addr == coord_server => {
                        let response = String::from_utf8_lossy(&buf[..size]);
                        if response.starts_with("START") {
                            tracing::info!("Received START signal after {:?}", start_time.elapsed());
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        return Err(anyhow::anyhow!("Failed to receive coordination signal: {}", e));
                    }
                    Err(_) => {
                        return Err(anyhow::anyhow!("Coordination timeout"));
                    }
                    _ => continue,
                }
            }

            // Add small random jitter to avoid exact simultaneity
            let jitter = rand::thread_rng().gen_range(0..10);
            sleep(Duration::from_millis(jitter)).await;
        }

        // Perform synchronized hole punch
        self.punch_hole(socket, peer_addr, true).await
    }

    /// Test connectivity after hole punching
    pub async fn test_connectivity(
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        test_data: &[u8],
    ) -> Result<bool> {
        // Send test packet
        socket.send_to(test_data, peer_addr).await?;

        // Wait for echo
        let mut buf = vec![0u8; test_data.len() + 100];
        match timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
            Ok(Ok((size, addr))) if addr == peer_addr && &buf[..size] == test_data => Ok(true),
            _ => Ok(false),
        }
    }

    /// Maintain hole punch with keep-alive packets
    pub async fn maintain_hole(
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        interval_secs: u64,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        let mut seq = 0u32;

        loop {
            interval.tick().await;

            let mut keepalive = vec![b'S', b'H', b'A', b'R', b'P', b'_', b'K', b'A'];
            keepalive.extend_from_slice(&seq.to_be_bytes());

            if let Err(e) = socket.send_to(&keepalive, peer_addr).await {
                tracing::debug!("Keep-alive failed: {}", e);
            } else {
                tracing::trace!("Keep-alive {} sent to {}", seq, peer_addr);
            }

            seq = seq.wrapping_add(1);
        }
    }
}