// src/connectivity/transport/direct.rs
//! Прямой UDP транспорт

use super::{Transport, TransportType, TransportStats, BaseTransport};
use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use parking_lot::RwLock;
use tracing::{debug, trace, warn};

/// Прямой UDP транспорт без дополнительной обработки
#[derive(Debug)]
pub struct DirectTransport {
    base: BaseTransport,
    connection_verified: Arc<RwLock<bool>>,
    last_ping: Arc<RwLock<Option<Instant>>>,
}

impl DirectTransport {
    /// Создание нового прямого транспорта
    pub fn new(
        socket: Arc<UdpSocket>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Self {
        debug!("Creating DirectTransport: {} -> {}", local_addr, remote_addr);

        let base = BaseTransport::new(
            socket,
            local_addr,
            remote_addr,
            TransportType::Direct,
        );

        Self {
            base,
            connection_verified: Arc::new(RwLock::new(false)),
            last_ping: Arc::new(RwLock::new(None)),
        }
    }

    /// Проверка прямого соединения
    pub async fn verify_connection(&self) -> Result<Duration> {
        debug!("Verifying direct connection to {}", self.remote_addr());

        let start = Instant::now();
        let verify_data = b"SHARP_DIRECT_VERIFY";

        // Отправляем верификационный пакет
        self.base.send(verify_data).await?;

        // Ждем ответ
        let mut buffer = vec![0u8; 1024];
        let timeout_duration = Duration::from_secs(3);

        match tokio::time::timeout(timeout_duration, self.base.recv(&mut buffer)).await {
            Ok(Ok((size, addr))) => {
                if addr == self.remote_addr() && size >= verify_data.len() {
                    let rtt = start.elapsed();
                    *self.connection_verified.write() = true;
                    *self.last_ping.write() = Some(start);

                    debug!("Direct connection verified, RTT: {:?}", rtt);
                    Ok(rtt)
                } else {
                    warn!("Invalid verification response from {}, expected {}", addr, self.remote_addr());
                    Err(anyhow::anyhow!("Invalid verification response"))
                }
            }
            Ok(Err(e)) => {
                warn!("Verification receive error: {}", e);
                Err(e.into())
            }
            Err(_) => {
                warn!("Direct connection verification timeout");
                Err(anyhow::anyhow!("Verification timeout"))
            }
        }
    }

    /// Проверка качества соединения
    pub async fn check_connection_quality(&self) -> Result<ConnectionQuality> {
        let start = Instant::now();
        let mut successful_pings = 0;
        let mut total_rtt = Duration::ZERO;
        const PING_COUNT: usize = 5;

        for i in 0..PING_COUNT {
            match self.ping().await {
                Ok(rtt) => {
                    successful_pings += 1;
                    total_rtt += rtt;
                    trace!("Ping {}: {:?}", i + 1, rtt);
                }
                Err(e) => {
                    trace!("Ping {} failed: {}", i + 1, e);
                }
            }

            // Небольшая пауза между пингами
            if i < PING_COUNT - 1 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        let success_rate = successful_pings as f32 / PING_COUNT as f32;
        let average_rtt = if successful_pings > 0 {
            Some(total_rtt / successful_pings as u32)
        } else {
            None
        };

        let quality = ConnectionQuality {
            success_rate,
            average_rtt,
            measurement_duration: start.elapsed(),
            ping_count: PING_COUNT,
            successful_pings,
        };

        debug!("Connection quality: success_rate={:.2}, avg_rtt={:?}",
               success_rate, average_rtt);

        Ok(quality)
    }

    /// Проверка достижимости удаленного адреса
    pub async fn is_reachable(&self) -> bool {
        match self.ping().await {
            Ok(rtt) => {
                trace!("Remote address {} is reachable, RTT: {:?}", self.remote_addr(), rtt);
                true
            }
            Err(_) => {
                trace!("Remote address {} is not reachable", self.remote_addr());
                false
            }
        }
    }

    /// Получение базового транспорта (для тестирования)
    #[cfg(test)]
    pub fn base(&self) -> &BaseTransport {
        &self.base
    }
}

#[async_trait]
impl Transport for DirectTransport {
    async fn send(&self, data: &[u8]) -> Result<usize> {
        // Для прямого транспорта просто передаем в базовый
        self.base.send(data).await
    }

    async fn recv(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr)> {
        // Для прямого транспорта просто передаем в базовый
        self.base.recv(buffer).await
    }

    fn local_addr(&self) -> SocketAddr {
        self.base.local_addr()
    }

    fn remote_addr(&self) -> SocketAddr {
        self.base.remote_addr()
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Direct
    }

    fn is_reliable(&self) -> bool {
        // Прямое UDP соединение не гарантирует доставку
        false
    }

    fn supports_encryption(&self) -> bool {
        // Базовый прямой транспорт не поддерживает шифрование
        false
    }

    fn max_packet_size(&self) -> usize {
        self.base.max_packet_size()
    }

    fn get_stats(&self) -> TransportStats {
        self.base.get_stats()
    }

    async fn close(&self) -> Result<()> {
        debug!("Closing DirectTransport");
        *self.connection_verified.write() = false;
        self.base.close().await
    }

    async fn is_connected(&self) -> bool {
        // Проверяем была ли верификация и не истекло ли время
        let verified = *self.connection_verified.read();
        if !verified {
            return false;
        }

        // Проверяем последнюю активность
        if let Some(last_activity) = self.base.get_stats().last_activity {
            last_activity.elapsed() < Duration::from_secs(30)
        } else {
            false
        }
    }

    async fn ping(&self) -> Result<Duration> {
        let result = self.base.ping().await;

        // Обновляем время последнего пинга
        if result.is_ok() {
            *self.last_ping.write() = Some(Instant::now());
        }

        result
    }
}

/// Качество соединения
#[derive(Debug, Clone)]
pub struct ConnectionQuality {
    /// Процент успешных пингов (0.0 - 1.0)
    pub success_rate: f32,
    /// Средний RTT
    pub average_rtt: Option<Duration>,
    /// Время измерения
    pub measurement_duration: Duration,
    /// Общее количество пингов
    pub ping_count: usize,
    /// Количество успешных пингов
    pub successful_pings: usize,
}

impl ConnectionQuality {
    /// Оценка качества соединения (0.0 - 1.0)
    pub fn quality_score(&self) -> f32 {
        let success_score = self.success_rate;

        let rtt_score = if let Some(avg_rtt) = self.average_rtt {
            let rtt_ms = avg_rtt.as_millis() as f32;
            if rtt_ms < 50.0 {
                1.0
            } else if rtt_ms < 100.0 {
                0.8
            } else if rtt_ms < 200.0 {
                0.6
            } else if rtt_ms < 500.0 {
                0.4
            } else {
                0.2
            }
        } else {
            0.0
        };

        // Взвешенная оценка
        (success_score * 0.7) + (rtt_score * 0.3)
    }

    /// Классификация качества
    pub fn quality_class(&self) -> QualityClass {
        let score = self.quality_score();

        if score >= 0.9 {
            QualityClass::Excellent
        } else if score >= 0.7 {
            QualityClass::Good
        } else if score >= 0.5 {
            QualityClass::Fair
        } else if score >= 0.3 {
            QualityClass::Poor
        } else {
            QualityClass::Unusable
        }
    }
}

/// Классификация качества соединения
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityClass {
    Excellent,  // > 90%
    Good,       // 70-90%
    Fair,       // 50-70%
    Poor,       // 30-50%
    Unusable,   // < 30%
}

impl std::fmt::Display for QualityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QualityClass::Excellent => write!(f, "Excellent"),
            QualityClass::Good => write!(f, "Good"),
            QualityClass::Fair => write!(f, "Fair"),
            QualityClass::Poor => write!(f, "Poor"),
            QualityClass::Unusable => write!(f, "Unusable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_direct_transport_creation() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = "127.0.0.1:8080".parse().unwrap();

        let transport = DirectTransport::new(socket, local_addr, remote_addr);

        assert_eq!(transport.local_addr(), local_addr);
        assert_eq!(transport.remote_addr(), remote_addr);
        assert_eq!(transport.transport_type(), TransportType::Direct);
        assert!(!transport.is_reliable());
        assert!(!transport.supports_encryption());
    }

    #[tokio::test]
    async fn test_direct_transport_connection_state() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = "127.0.0.1:8080".parse().unwrap();

        let transport = DirectTransport::new(socket, local_addr, remote_addr);

        // Изначально не подключен
        assert!(!transport.is_connected().await);

        // После верификации не будет подключен (нет эхо-сервера)
        assert!(transport.verify_connection().await.is_err());
        assert!(!transport.is_connected().await);
    }

    #[test]
    fn test_connection_quality_scoring() {
        let excellent_quality = ConnectionQuality {
            success_rate: 1.0,
            average_rtt: Some(Duration::from_millis(30)),
            measurement_duration: Duration::from_secs(5),
            ping_count: 5,
            successful_pings: 5,
        };

        assert!(excellent_quality.quality_score() > 0.9);
        assert_eq!(excellent_quality.quality_class(), QualityClass::Excellent);

        let poor_quality = ConnectionQuality {
            success_rate: 0.4,
            average_rtt: Some(Duration::from_millis(800)),
            measurement_duration: Duration::from_secs(5),
            ping_count: 5,
            successful_pings: 2,
        };

        assert!(poor_quality.quality_score() < 0.5);
        assert_eq!(poor_quality.quality_class(), QualityClass::Poor);
    }

    #[tokio::test]
    async fn test_direct_transport_stats() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = "127.0.0.1:8080".parse().unwrap();

        let transport = DirectTransport::new(socket, local_addr, remote_addr);
        let initial_stats = transport.get_stats();

        assert_eq!(initial_stats.bytes_sent, 0);
        assert_eq!(initial_stats.bytes_received, 0);
        assert_eq!(initial_stats.packets_sent, 0);
        assert_eq!(initial_stats.packets_received, 0);
        assert!(initial_stats.created_at.is_some());
    }

    #[tokio::test]
    async fn test_direct_transport_packet_size_limit() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = "127.0.0.1:8080".parse().unwrap();

        let transport = DirectTransport::new(socket, local_addr, remote_addr);

        // Проверяем лимит размера пакета
        let max_size = transport.max_packet_size();
        assert!(max_size > 0);
        assert!(max_size <= 65535); // UDP limit

        // Попытка отправить слишком большой пакет должна завершиться ошибкой
        let oversized_data = vec![0u8; max_size + 1];
        assert!(transport.send(&oversized_data).await.is_err());
    }
}