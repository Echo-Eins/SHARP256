// src/connectivity/transport/mod.rs
//! Transport abstraction для различных методов подключения

use anyhow::Result;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use parking_lot::RwLock;

// Submodules
pub mod direct;
pub mod ice;
pub mod relay;
pub mod upnp;
pub mod router_pool;
pub mod hairpin;

// Re-exports
pub use direct::DirectTransport;
pub use ice::IceTransport;
pub use relay::RelayTransport;
pub use upnp::UpnpTransport;
pub use router_pool::RouterPoolTransport;
pub use hairpin::{HairpinDetector, HairpinResult};

/// Универсальный transport trait для всех типов соединений
#[async_trait]
pub trait Transport: Send + Sync + Debug {
    /// Отправка данных
    async fn send(&self, data: &[u8]) -> Result<usize>;

    /// Получение данных
    async fn recv(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr)>;

    /// Локальный адрес транспорта
    fn local_addr(&self) -> SocketAddr;

    /// Удаленный адрес транспорта
    fn remote_addr(&self) -> SocketAddr;

    /// Тип транспорта
    fn transport_type(&self) -> TransportType;

    /// Надежность доставки
    fn is_reliable(&self) -> bool {
        false // UDP по умолчанию не надежен
    }

    /// Поддержка шифрования
    fn supports_encryption(&self) -> bool {
        false
    }

    /// Максимальный размер пакета
    fn max_packet_size(&self) -> usize {
        1200 // Безопасный размер для UDP
    }

    /// Статистика транспорта
    fn get_stats(&self) -> TransportStats;

    /// Закрытие транспорта
    async fn close(&self) -> Result<()>;

    /// Проверка активности соединения
    async fn is_connected(&self) -> bool;

    /// Ping для измерения RTT
    async fn ping(&self) -> Result<Duration>;
}

/// Тип транспорта
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransportType {
    /// Прямое UDP соединение
    Direct,
    /// ICE nominated pair
    IceNominated,
    /// Через relay с опциональным шифрованием
    Relayed { encryption: bool },
    /// Hairpin соединение (через NAT loopback)
    Hairpin,
}

/// Статистика транспорта
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    /// Время создания соединения
    pub created_at: Option<Instant>,
    /// Время последней активности
    pub last_activity: Option<Instant>,
    /// Общее количество отправленных байт
    pub bytes_sent: u64,
    /// Общее количество полученных байт
    pub bytes_received: u64,
    /// Количество отправленных пакетов
    pub packets_sent: u64,
    /// Количество полученных пакетов
    pub packets_received: u64,
    /// Последний измеренный RTT
    pub last_rtt: Option<Duration>,
    /// Средний RTT
    pub average_rtt: Option<Duration>,
    /// Количество ошибок
    pub error_count: u64,
    /// Качество соединения (0.0 - 1.0)
    pub connection_quality: f32,
}

impl TransportStats {
    pub fn new() -> Self {
        Self {
            created_at: Some(Instant::now()),
            connection_quality: 1.0,
            ..Default::default()
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Some(Instant::now());
    }

    pub fn record_send(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.packets_sent += 1;
        self.update_activity();
    }

    pub fn record_receive(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.packets_received += 1;
        self.update_activity();
    }

    pub fn record_error(&mut self) {
        self.error_count += 1;
        // Ухудшаем качество соединения
        self.connection_quality = (self.connection_quality * 0.9).max(0.0);
    }

    pub fn record_rtt(&mut self, rtt: Duration) {
        self.last_rtt = Some(rtt);

        // Обновляем средний RTT
        if let Some(avg_rtt) = self.average_rtt {
            self.average_rtt = Some(Duration::from_nanos(
                (avg_rtt.as_nanos() as u64 * 7 + rtt.as_nanos() as u64) / 8
            ));
        } else {
            self.average_rtt = Some(rtt);
        }

        // Обновляем качество соединения на основе RTT
        let rtt_ms = rtt.as_millis() as f32;
        let rtt_quality = if rtt_ms < 50.0 {
            1.0
        } else if rtt_ms < 100.0 {
            0.8
        } else if rtt_ms < 200.0 {
            0.6
        } else if rtt_ms < 500.0 {
            0.4
        } else {
            0.2
        };

        self.connection_quality = (self.connection_quality + rtt_quality) / 2.0;
    }
}

/// Установленное соединение с выбранным транспортом
#[derive(Debug)]
pub struct EstablishedConnection {
    transport: Box<dyn Transport>,
    transport_type: TransportType,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    established_at: Instant,
    stats: Arc<RwLock<TransportStats>>,
}

impl EstablishedConnection {
    pub fn new(
        transport: Box<dyn Transport>,
        transport_type: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Self {
        Self {
            transport,
            transport_type,
            local_addr,
            remote_addr,
            established_at: Instant::now(),
            stats: Arc::new(RwLock::new(TransportStats::new())),
        }
    }

    /// Отправка данных через установленное соединение
    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        let bytes_sent = self.transport.send(data).await?;
        self.stats.write().record_send(bytes_sent as u64);
        Ok(bytes_sent)
    }

    /// Получение данных через установленное соединение
    pub async fn recv(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (bytes_received, addr) = self.transport.recv(buffer).await?;
        self.stats.write().record_receive(bytes_received as u64);
        Ok((bytes_received, addr))
    }

    /// Ping для измерения RTT
    pub async fn ping(&self) -> Result<Duration> {
        let rtt = self.transport.ping().await?;
        self.stats.write().record_rtt(rtt);
        Ok(rtt)
    }

    // Getters
    pub fn transport_type(&self) -> TransportType {
        self.transport_type
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn established_at(&self) -> Instant {
        self.established_at
    }

    pub fn get_stats(&self) -> TransportStats {
        self.stats.read().clone()
    }

    pub fn is_reliable(&self) -> bool {
        self.transport.is_reliable()
    }

    pub fn supports_encryption(&self) -> bool {
        self.transport.supports_encryption()
    }

    pub fn max_packet_size(&self) -> usize {
        self.transport.max_packet_size()
    }

    /// Проверка активности соединения
    pub async fn is_connected(&self) -> bool {
        self.transport.is_connected().await
    }

    /// Закрытие соединения
    pub async fn close(&self) -> Result<()> {
        self.transport.close().await
    }
}

/// Базовый транспорт с общими функциями
#[derive(Debug)]
pub struct BaseTransport {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    transport_type: TransportType,
    stats: Arc<RwLock<TransportStats>>,
    max_packet_size: usize,
    supports_encryption: bool,
}

impl BaseTransport {
    pub fn new(
        socket: Arc<UdpSocket>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        transport_type: TransportType,
    ) -> Self {
        Self {
            socket,
            local_addr,
            remote_addr,
            transport_type,
            stats: Arc::new(RwLock::new(TransportStats::new())),
            max_packet_size: 1200,
            supports_encryption: false,
        }
    }

    pub fn with_encryption(mut self, supports_encryption: bool) -> Self {
        self.supports_encryption = supports_encryption;
        self
    }

    pub fn with_max_packet_size(mut self, max_packet_size: usize) -> Self {
        self.max_packet_size = max_packet_size;
        self
    }
}

#[async_trait]
impl Transport for BaseTransport {
    async fn send(&self, data: &[u8]) -> Result<usize> {
        if data.len() > self.max_packet_size {
            return Err(anyhow::anyhow!(
                "Packet size {} exceeds maximum {}",
                data.len(),
                self.max_packet_size
            ));
        }

        match self.socket.send_to(data, self.remote_addr).await {
            Ok(bytes_sent) => {
                self.stats.write().record_send(bytes_sent as u64);
                Ok(bytes_sent)
            }
            Err(e) => {
                self.stats.write().record_error();
                Err(e.into())
            }
        }
    }

    async fn recv(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr)> {
        match self.socket.recv_from(buffer).await {
            Ok((bytes_received, addr)) => {
                self.stats.write().record_receive(bytes_received as u64);
                Ok((bytes_received, addr))
            }
            Err(e) => {
                self.stats.write().record_error();
                Err(e.into())
            }
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn transport_type(&self) -> TransportType {
        self.transport_type
    }

    fn supports_encryption(&self) -> bool {
        self.supports_encryption
    }

    fn max_packet_size(&self) -> usize {
        self.max_packet_size
    }

    fn get_stats(&self) -> TransportStats {
        self.stats.read().clone()
    }

    async fn close(&self) -> Result<()> {
        // Для базового транспорта нет специальных действий по закрытию
        Ok(())
    }

    async fn is_connected(&self) -> bool {
        // Простая проверка - если последняя активность была недавно
        if let Some(last_activity) = self.stats.read().last_activity {
            last_activity.elapsed() < Duration::from_secs(30)
        } else {
            false
        }
    }

    async fn ping(&self) -> Result<Duration> {
        let start = Instant::now();
        let ping_data = b"SHARP_PING";

        self.socket.send_to(ping_data, self.remote_addr).await?;

        let mut buffer = vec![0u8; 1024];
        let timeout_duration = Duration::from_secs(5);

        match tokio::time::timeout(timeout_duration, self.socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, addr))) => {
                if addr == self.remote_addr && size >= ping_data.len() {
                    let rtt = start.elapsed();
                    self.stats.write().record_rtt(rtt);
                    Ok(rtt)
                } else {
                    Err(anyhow::anyhow!("Invalid ping response"))
                }
            }
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(anyhow::anyhow!("Ping timeout")),
        }
    }
}

/// Utilities для работы с транспортами
pub mod utils {
    use super::*;
    use std::net::IpAddr;

    /// Выбор лучшего транспорта из списка возможных
    pub fn select_best_transport(connections: Vec<EstablishedConnection>) -> Option<EstablishedConnection> {
        if connections.is_empty() {
            return None;
        }

        // Сортируем по приоритету транспорта и качеству
        let mut scored_connections: Vec<_> = connections.into_iter()
            .map(|conn| {
                let priority_score = match conn.transport_type() {
                    TransportType::Direct => 100,
                    TransportType::IceNominated => 90,
                    TransportType::Hairpin => 80,
                    TransportType::Relayed { encryption: false } => 50,
                    TransportType::Relayed { encryption: true } => 60,
                };

                let quality_score = (conn.get_stats().connection_quality * 100.0) as u32;
                let total_score = priority_score + quality_score;

                (total_score, conn)
            })
            .collect();

        scored_connections.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
        scored_connections.into_iter().next().map(|(_, conn)| conn)
    }

    /// Проверка совместимости адресов
    pub fn are_addresses_compatible(local: &SocketAddr, remote: &SocketAddr) -> bool {
        match (local.ip(), remote.ip()) {
            (IpAddr::V4(_), IpAddr::V4(_)) => true,
            (IpAddr::V6(_), IpAddr::V6(_)) => true,
            _ => false,
        }
    }

    /// Расчет сетевого расстояния между адресами
    pub fn calculate_network_distance(local: &SocketAddr, remote: &SocketAddr) -> u32 {
        match (local.ip(), remote.ip()) {
            (IpAddr::V4(local_v4), IpAddr::V4(remote_v4)) => {
                if local_v4.is_private() && remote_v4.is_private() {
                    // Локальная сеть
                    let local_octets = local_v4.octets();
                    let remote_octets = remote_v4.octets();

                    if local_octets[0..3] == remote_octets[0..3] {
                        10 // Та же подсеть
                    } else if local_octets[0..2] == remote_octets[0..2] {
                        20 // Та же сеть класса B
                    } else {
                        30 // Разные приватные сети
                    }
                } else if local_v4.is_private() || remote_v4.is_private() {
                    50 // Через NAT
                } else {
                    40 // Публичные адреса
                }
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                // Упрощенная логика для IPv6
                30
            }
            _ => {
                100 // Несовместимые версии IP
            }
        }
    }

    /// Определение оптимального размера пакета для соединения
    pub fn determine_optimal_packet_size(local: &SocketAddr, remote: &SocketAddr) -> usize {
        let distance = calculate_network_distance(local, remote);

        match distance {
            0..=20 => 8192,   // Локальная сеть - большие пакеты
            21..=40 => 4096,  // Публичные адреса - средние пакеты
            41..=60 => 1472,  // Через NAT - стандартный MTU
            _ => 1200,        // Консервативный размер
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_base_transport_creation() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = "127.0.0.1:8080".parse().unwrap();

        let transport = BaseTransport::new(
            socket,
            local_addr,
            remote_addr,
            TransportType::Direct,
        );

        assert_eq!(transport.local_addr(), local_addr);
        assert_eq!(transport.remote_addr(), remote_addr);
        assert_eq!(transport.transport_type(), TransportType::Direct);
    }

    #[test]
    fn test_transport_stats() {
        let mut stats = TransportStats::new();

        stats.record_send(1024);
        assert_eq!(stats.bytes_sent, 1024);
        assert_eq!(stats.packets_sent, 1);

        stats.record_receive(512);
        assert_eq!(stats.bytes_received, 512);
        assert_eq!(stats.packets_received, 1);

        stats.record_error();
        assert_eq!(stats.error_count, 1);
        assert!(stats.connection_quality < 1.0);
    }

    #[test]
    fn test_network_distance_calculation() {
        let local_private: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let remote_private: SocketAddr = "192.168.1.200:5000".parse().unwrap();
        let remote_different_subnet: SocketAddr = "192.168.2.100:5000".parse().unwrap();
        let public_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

        assert_eq!(utils::calculate_network_distance(&local_private, &remote_private), 10);
        assert_eq!(utils::calculate_network_distance(&local_private, &remote_different_subnet), 20);
        assert_eq!(utils::calculate_network_distance(&local_private, &public_addr), 50);
    }

    #[test]
    fn test_optimal_packet_size() {
        let local: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let remote_same_subnet: SocketAddr = "192.168.1.200:5000".parse().unwrap();
        let remote_public: SocketAddr = "8.8.8.8:53".parse().unwrap();

        assert_eq!(utils::determine_optimal_packet_size(&local, &remote_same_subnet), 8192);
        assert_eq!(utils::determine_optimal_packet_size(&local, &remote_public), 1472);
    }
}