use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{interval, timeout};

/// UDP hole punching для установления P2P соединения через NAT
pub struct HolePuncher {
    max_attempts: u32,
}

impl HolePuncher {
    pub fn new(max_attempts: u32) -> Self {
        Self { max_attempts }
    }

    /// Выполнение hole punching с удаленным пиром
    pub async fn punch_hole(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
    ) -> Result<()> {
        tracing::info!("Starting hole punch to {} (initiator: {})", peer_addr, is_initiator);

        // Hole punching пакет - небольшой идентификатор
        let punch_packet = if is_initiator {
            b"SHARP_PUNCH_INIT"
        } else {
            b"SHARP_PUNCH_RESP"
        };

        let mut attempt = 0;
        let mut punch_interval = interval(Duration::from_millis(200));

        // Отправляем пакеты для "пробивания" NAT
        while attempt < self.max_attempts {
            punch_interval.tick().await;
            
            // Отправляем punch пакет
            if let Err(e) = socket.send_to(punch_packet, peer_addr).await {
                tracing::warn!("Hole punch send failed: {}", e);
            } else {
                tracing::debug!("Sent hole punch packet {} to {}", attempt + 1, peer_addr);
            }

            // Проверяем, получили ли ответ
            let mut buf = vec![0u8; 1024];
            match timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) if addr == peer_addr => {
                    let received = &buf[..size];
                    if received.starts_with(b"SHARP_PUNCH_") {
                        tracing::info!("Hole punch successful! Received response from {}", addr);
                        
                        // Отправляем подтверждение несколько раз для надежности
                        for _ in 0..3 {
                            let _ = socket.send_to(b"SHARP_PUNCH_ACK", peer_addr).await;
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                        
                        return Ok(());
                    }
                }
                Ok(Ok((_, addr))) => {
                    tracing::debug!("Received packet from unexpected address: {}", addr);
                }
                Ok(Err(e)) => {
                    tracing::debug!("Recv error during hole punch: {}", e);
                }
                Err(_) => {
                    // Timeout - нормально, продолжаем попытки
                }
            }

            attempt += 1;
        }

        // Даже если не получили явного ответа, NAT должен быть "пробит"
        tracing::warn!("Hole punch completed without confirmation after {} attempts", attempt);
        Ok(())
    }

    /// Вспомогательный метод для одновременного hole punching (STUN-coordinated)
    pub async fn simultaneous_punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        coordination_server: Option<SocketAddr>,
    ) -> Result<()> {
        if let Some(coord_server) = coordination_server {
            // Сигнализируем серверу о готовности
            let ready_msg = format!("READY:{}", peer_addr).into_bytes();
            socket.send_to(&ready_msg, coord_server).await?;

            // Ждем сигнал от сервера
            let mut buf = vec![0u8; 256];
            let (size, _) = timeout(
                Duration::from_secs(10),
                socket.recv_from(&mut buf)
            ).await??;

            let response = String::from_utf8_lossy(&buf[..size]);
            if response.starts_with("START") {
                tracing::info!("Received START signal, beginning simultaneous punch");
            }
        }

        // Выполняем обычный hole punch
        self.punch_hole(socket, peer_addr, true).await
    }
}