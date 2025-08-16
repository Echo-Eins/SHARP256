// src/connectivity/transport/relay.rs
//! Relay транспорт с поддержкой шифрования заголовков

use super::{Transport, TransportType, TransportStats};
use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn, trace, error};
use uuid::Uuid;

#[cfg(feature = "relay-encryption")]
use crate::connectivity::encryption::HeaderCrypto;

/// Relay транспорт для SHARP протокола
#[derive(Debug)]
pub struct RelayTransport {
    /// UDP сокет
    socket: Arc<UdpSocket>,
    /// Локальный адрес
    local_addr: SocketAddr,
    /// Адрес relay сервера
    relay_addr: SocketAddr,
    /// Целевой peer адрес (для relay)
    target_peer_addr: Option<SocketAddr>,
    /// Включено ли шифрование заголовков
    encryption_enabled: bool,
    /// Шифрование заголовков
    #[cfg(feature = "relay-encryption")]
    header_crypto: Option<Arc<HeaderCrypto>>,
    /// Идентификатор клиента на relay
    client_id: String,
    /// Статистика транспорта
    stats: Arc<RwLock<TransportStats>>,
    /// Состояние регистрации на relay
    registered: Arc<RwLock<bool>>,
    /// Последний heartbeat
    last_heartbeat: Arc<RwLock<Option<Instant>>>,
}

impl RelayTransport {
    /// Создание нового relay транспорта
    pub fn new(
        socket: Arc<UdpSocket>,
        local_addr: SocketAddr,
        relay_addr: SocketAddr,
        encryption_enabled: bool,
        #[cfg(feature = "relay-encryption")]
        header_crypto: Option<Arc<HeaderCrypto>>,
        #[cfg(not(feature = "relay-encryption"))]
        _header_crypto: Option<()>,
    ) -> Self {
        let client_id = format!("sharp-{}", Uuid::new_v4().simple());

        info!(
            "Creating RelayTransport: {} -> {} (encryption: {})",
            local_addr, relay_addr, encryption_enabled
        );

        Self {
            socket,
            local_addr,
            relay_addr,
            target_peer_addr: None,
            encryption_enabled,
            #[cfg(feature = "relay-encryption")]
            header_crypto,
            client_id,
            stats: Arc::new(RwLock::new(TransportStats::new())),
            registered: Arc::new(RwLock::new(false)),
            last_heartbeat: Arc::new(RwLock::new(None)),
        }
    }

    /// Установка целевого peer адреса
    pub fn set_target_peer(&mut self, peer_addr: SocketAddr) {
        self.target_peer_addr = Some(peer_addr);
        debug!("Set relay target peer: {}", peer_addr);
    }

    /// Регистрация на relay сервере
    pub async fn register(&self) -> Result<()> {
        info!("Registering with relay server: {}", self.relay_addr);

        let register_message = format!("REGISTER:{}", self.client_id);
        self.socket.send_to(register_message.as_bytes(), self.relay_addr).await?;

        // Ждем подтверждение регистрации
        let mut buffer = vec![0u8; 1024];

        match timeout(Duration::from_secs(5), self.socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, addr))) => {
                if addr == self.relay_addr {
                    let response = String::from_utf8_lossy(&buffer[..size]);
                    if response.starts_with("REGISTERED:") {
                        *self.registered.write() = true;
                        *self.last_heartbeat.write() = Some(Instant::now());
                        info!("Successfully registered with relay server");

                        // Запускаем heartbeat
                        self.start_heartbeat().await;

                        return Ok(());
                    }
                }
            }
            _ => {}
        }

        Err(anyhow::anyhow!("Failed to register with relay server"))
    }

    /// Запуск heartbeat механизма
    async fn start_heartbeat(&self) {
        let socket = self.socket.clone();
        let relay_addr = self.relay_addr;
        let client_id = self.client_id.clone();
        let last_heartbeat = self.last_heartbeat.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let heartbeat_message = format!("HEARTBEAT:{}", client_id);

                if let Err(e) = socket.send_to(heartbeat_message.as_bytes(), relay_addr).await {
                    warn!("Failed to send heartbeat to relay: {}", e);
                } else {
                    *last_heartbeat.write() = Some(Instant::now());
                    trace!("Sent heartbeat to relay server");
                }
            }
        });
    }

    /// Отправка данных через relay
    async fn send_via_relay(&self, data: &[u8]) -> Result<usize> {
        if !*self.registered.read() {
            return Err(anyhow::anyhow!("Not registered with relay server"));
        }

        let target_peer = self.target_peer_addr
            .ok_or_else(|| anyhow::anyhow!("No target peer address set"))?;

        // Создаем relay сообщение
        let relay_message = if self.encryption_enabled {
            self.create_encrypted_relay_message(data, &target_peer).await?
        } else {
            self.create_plain_relay_message(data, &target_peer)
        };

        // Отправляем через relay
        match self.socket.send_to(&relay_message, self.relay_addr).await {
            Ok(bytes_sent) => {
                self.stats.write().record_send(data.len() as u64);
                trace!("Sent {} bytes via relay to {}", data.len(), target_peer);
                Ok(data.len()) // Возвращаем размер оригинальных данных
            }
            Err(e) => {
                self.stats.write().record_error();
                Err(e.into())
            }
        }
    }

    /// Создание зашифрованного relay сообщения
    #[cfg(feature = "relay-encryption")]
    async fn create_encrypted_relay_message(&self, data: &[u8], target_peer: &SocketAddr) -> Result<Vec<u8>> {
        if let Some(ref crypto) = self.header_crypto {
            // Извлекаем SHARP заголовок (первые 30 байт)
            if data.len() < crate::protocol::constants::SHARP_HEADER_SIZE {
                return Err(anyhow::anyhow!("Data too small for SHARP header"));
            }

            let (header_bytes, payload) = data.split_at(crate::protocol::constants::SHARP_HEADER_SIZE);

            // Шифруем только заголовок
            let encrypted_header = crypto.encrypt_header_bytes(header_bytes)?;

            // Формат: RELAY_ENCRYPTED:<peer_id>:<encrypted_header>:<payload>
            let peer_id = format!("{}:{}", target_peer.ip(), target_peer.port());
            let mut message = Vec::new();
            message.extend_from_slice(b"RELAY_ENCRYPTED:");
            message.extend_from_slice(peer_id.as_bytes());
            message.push(b':');
            message.extend_from_slice(&encrypted_header);
            message.push(b':');
            message.extend_from_slice(payload);

            debug!(
                "Created encrypted relay message: header {} bytes, payload {} bytes",
                encrypted_header.len(),
                payload.len()
            );

            Ok(message)
        } else {
            Err(anyhow::anyhow!("Header crypto not available"))
        }
    }

    /// Создание зашифрованного relay сообщения (fallback без crypto)
    #[cfg(not(feature = "relay-encryption"))]
    async fn create_encrypted_relay_message(&self, _data: &[u8], _target_peer: &SocketAddr) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("Relay encryption not available (feature disabled)"))
    }

    /// Создание обычного relay сообщения
    fn create_plain_relay_message(&self, data: &[u8], target_peer: &SocketAddr) -> Vec<u8> {
        // Формат: RELAY:<peer_id>:<data>
        let peer_id = format!("{}:{}", target_peer.ip(), target_peer.port());
        let mut message = Vec::new();
        message.extend_from_slice(b"RELAY:");
        message.extend_from_slice(peer_id.as_bytes());
        message.push(b':');
        message.extend_from_slice(data);

        trace!("Created plain relay message: {} bytes", data.len());
        message
    }

    /// Получение данных через relay
    async fn recv_via_relay(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr)> {
        // Получаем данные от relay сервера
        let (size, addr) = self.socket.recv_from(buffer).await?;

        if addr != self.relay_addr {
            return Err(anyhow::anyhow!("Received data from unexpected address: {}", addr));
        }

        // Парсим relay сообщение
        let received_data = &buffer[..size];

        if received_data.starts_with(b"RELAY_ENCRYPTED:") {
            self.handle_encrypted_relay_message(received_data, buffer).await
        } else if received_data.starts_with(b"RELAY:") {
            self.handle_plain_relay_message(received_data, buffer)
        } else {
            // Может быть системное сообщение от relay
            self.handle_relay_system_message(received_data)?;
            Err(anyhow::anyhow!("System message, try again"))
        }
    }

    /// Обработка зашифрованного relay сообщения
    #[cfg(feature = "relay-encryption")]
    async fn handle_encrypted_relay_message(
        &self,
        relay_data: &[u8],
        buffer: &mut [u8]
    ) -> Result<(usize, SocketAddr)> {
        if let Some(ref crypto) = self.header_crypto {
            // Парсим: RELAY_ENCRYPTED:<peer_id>:<encrypted_header>:<payload>
            let content = &relay_data[16..]; // Skip "RELAY_ENCRYPTED:"

            let parts: Vec<&[u8]> = content.splitn(3, |&b| b == b':').collect();
            if parts.len() != 3 {
                return Err(anyhow::anyhow!("Invalid encrypted relay message format"));
            }

            let peer_id = String::from_utf8_lossy(parts[0]);
            let encrypted_header = parts[1];
            let payload = parts[2];

            // Парсим peer_id для получения адреса отправителя
            let peer_addr: SocketAddr = peer_id.parse()
                .map_err(|e| anyhow::anyhow!("Invalid peer address in relay message: {}", e))?;

            // Дешифруем заголовок
            let decrypted_header = crypto.decrypt_header_bytes(encrypted_header)?;

            // Собираем полное сообщение
            if decrypted_header.len() + payload.len() > buffer.len() {
                return Err(anyhow::anyhow!("Relay message too large for buffer"));
            }

            buffer[..decrypted_header.len()].copy_from_slice(&decrypted_header);
            buffer[decrypted_header.len()..decrypted_header.len() + payload.len()].copy_from_slice(payload);

            let total_size = decrypted_header.len() + payload.len();

            self.stats.write().record_receive(total_size as u64);

            debug!(
                "Received encrypted relay message from {}: header {} bytes, payload {} bytes",
                peer_addr, decrypted_header.len(), payload.len()
            );

            Ok((total_size, peer_addr))
        } else {
            Err(anyhow::anyhow!("Header crypto not available"))
        }
    }

    /// Обработка зашифрованного relay сообщения (fallback без crypto)
    #[cfg(not(feature = "relay-encryption"))]
    async fn handle_encrypted_relay_message(
        &self,
        _relay_data: &[u8],
        _buffer: &mut [u8]
    ) -> Result<(usize, SocketAddr)> {
        Err(anyhow::anyhow!("Relay encryption not available (feature disabled)"))
    }

    /// Обработка обычного relay сообщения
    fn handle_plain_relay_message(&self, relay_data: &[u8], buffer: &mut [u8]) -> Result<(usize, SocketAddr)> {
        // Парсим: RELAY:<peer_id>:<data>
        let content = &relay_data[6..]; // Skip "RELAY:"

        if let Some(colon_pos) = content.iter().position(|&b| b == b':') {
            let peer_id = String::from_utf8_lossy(&content[..colon_pos]);
            let data = &content[colon_pos + 1..];

            // Парсим peer_id для получения адреса отправителя
            let peer_addr: SocketAddr = peer_id.parse()
                .map_err(|e| anyhow::anyhow!("Invalid peer address in relay message: {}", e))?;

            // Копируем данные в буфер
            if data.len() > buffer.len() {
                return Err(anyhow::anyhow!("Relay message too large for buffer"));
            }

            buffer[..data.len()].copy_from_slice(data);

            self.stats.write().record_receive(data.len() as u64);

            trace!("Received plain relay message from {}: {} bytes", peer_addr, data.len());

            Ok((data.len(), peer_addr))
        } else {
            Err(anyhow::anyhow!("Invalid plain relay message format"))
        }
    }

    /// Обработка системных сообщений relay
    fn handle_relay_system_message(&self, message: &[u8]) -> Result<()> {
        let message_str = String::from_utf8_lossy(message);

        if message_str.starts_with("REGISTERED:") {
            debug!("Received registration confirmation from relay");
            *self.registered.write() = true;
        } else if message_str.starts_with("ERROR:") {
            warn!("Relay server error: {}", message_str);
        } else {
            trace!("Unknown relay system message: {}", message_str);
        }

        Ok(())
    }

    /// Проверка соединения с relay
    pub async fn check_relay_connection(&self) -> Result<Duration> {
        let start = Instant::now();
        let ping_message = format!("PING:{}", self.client_id);

        self.socket.send_to(ping_message.as_bytes(), self.relay_addr).await?;

        let mut buffer = vec![0u8; 1024];
        match timeout(Duration::from_secs(5), self.socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, addr))) => {
                if addr == self.relay_addr {
                    let response = String::from_utf8_lossy(&buffer[..size]);
                    if response.starts_with("PONG:") {
                        let rtt = start.elapsed();
                        debug!("Relay ping successful: {:?}", rtt);
                        return Ok(rtt);
                    }
                }
            }
            _ => {}
        }

        Err(anyhow::anyhow!("Relay ping failed"))
    }

    /// Проверка регистрации
    pub fn is_registered(&self) -> bool {
        *self.registered.read()
    }

    /// Получение client ID
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}

#[async_trait]
impl Transport for RelayTransport {
    async fn send(&self, data: &[u8]) -> Result<usize> {
        if data.len() > self.max_packet_size() {
            return Err(anyhow::anyhow!(
                "Packet size {} exceeds maximum {}",
                data.len(),
                self.max_packet_size()
            ));
        }

        self.send_via_relay(data).await
    }

    async fn recv(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.recv_via_relay(buffer).await
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn remote_addr(&self) -> SocketAddr {
        self.target_peer_addr.unwrap_or(self.relay_addr)
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Relayed {
            encryption: self.encryption_enabled
        }
    }

    fn is_reliable(&self) -> bool {
        // Relay обеспечивает некоторую надежность
        true
    }

    fn supports_encryption(&self) -> bool {
        self.encryption_enabled
    }

    fn max_packet_size(&self) -> usize {
        // Учитываем overhead relay протокола
        if self.encryption_enabled {
            // RELAY_ENCRYPTED: + peer_id + : + encrypted_header + : + payload
            60000 // Консервативный размер для зашифрованных сообщений
        } else {
            // RELAY: + peer_id + : + payload
            64000 // Больший размер для незашифрованных
        }
    }

    fn get_stats(&self) -> TransportStats {
        self.stats.read().clone()
    }

    async fn close(&self) -> Result<()> {
        info!("Closing RelayTransport");

        if *self.registered.read() {
            // Отправляем unregister сообщение
            let unregister_message = format!("UNREGISTER:{}", self.client_id);
            let _ = self.socket.send_to(unregister_message.as_bytes(), self.relay_addr).await;

            *self.registered.write() = false;
        }

        debug!("RelayTransport closed");
        Ok(())
    }

    async fn is_connected(&self) -> bool {
        if !*self.registered.read() {
            return false;
        }

        // Проверяем время последнего heartbeat
        if let Some(last_hb) = *self.last_heartbeat.read() {
            last_hb.elapsed() < Duration::from_secs(90) // 3 интервала heartbeat
        } else {
            false
        }
    }

    async fn ping(&self) -> Result<Duration> {
        self.check_relay_connection().await
    }
}

/// Утилиты для работы с relay
pub mod utils {
    use super::*;

    /// Парсинг relay сообщения для определения типа
    pub fn parse_relay_message_type(data: &[u8]) -> RelayMessageType {
        if data.starts_with(b"RELAY_ENCRYPTED:") {
            RelayMessageType::EncryptedData
        } else if data.starts_with(b"RELAY:") {
            RelayMessageType::PlainData
        } else if data.starts_with(b"REGISTER:") {
            RelayMessageType::Register
        } else if data.starts_with(b"REGISTERED:") {
            RelayMessageType::RegisterResponse
        } else if data.starts_with(b"HEARTBEAT:") {
            RelayMessageType::Heartbeat
        } else if data.starts_with(b"PING:") {
            RelayMessageType::Ping
        } else if data.starts_with(b"PONG:") {
            RelayMessageType::Pong
        } else if data.starts_with(b"ERROR:") {
            RelayMessageType::Error
        } else {
            RelayMessageType::Unknown
        }
    }

    /// Извлечение peer ID из relay сообщения
    pub fn extract_peer_id(relay_data: &[u8]) -> Result<String> {
        if relay_data.starts_with(b"RELAY:") {
            let content = &relay_data[6..];
            if let Some(colon_pos) = content.iter().position(|&b| b == b':') {
                return Ok(String::from_utf8_lossy(&content[..colon_pos]).to_string());
            }
        } else if relay_data.starts_with(b"RELAY_ENCRYPTED:") {
            let content = &relay_data[16..];
            if let Some(colon_pos) = content.iter().position(|&b| b == b':') {
                return Ok(String::from_utf8_lossy(&content[..colon_pos]).to_string());
            }
        }

        Err(anyhow::anyhow!("Cannot extract peer ID from relay message"))
    }
}

/// Типы relay сообщений
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMessageType {
    EncryptedData,
    PlainData,
    Register,
    RegisterResponse,
    Heartbeat,
    Ping,
    Pong,
    Error,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_relay_transport_creation() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = socket.local_addr().unwrap();
        let relay_addr = "127.0.0.1:8080".parse().unwrap();

        let transport = RelayTransport::new(
            socket,
            local_addr,
            relay_addr,
            false,
            #[cfg(feature = "relay-encryption")]
            None,
            #[cfg(not(feature = "relay-encryption"))]
            None,
        );

        assert_eq!(transport.local_addr(), local_addr);
        assert_eq!(transport.relay_addr, relay_addr);
        assert!(!transport.encryption_enabled);
        assert!(transport.is_reliable());
    }

    #[tokio::test]
    async fn test_plain_relay_message_creation() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = socket.local_addr().unwrap();
        let relay_addr = "127.0.0.1:8080".parse().unwrap();

        let transport = RelayTransport::new(
            socket,
            local_addr,
            relay_addr,
            false,
            #[cfg(feature = "relay-encryption")]
            None,
            #[cfg(not(feature = "relay-encryption"))]
            None,
        );

        let data = b"test data";
        let peer_addr = "192.168.1.100:5000".parse().unwrap();
        let message = transport.create_plain_relay_message(data, &peer_addr);

        let expected = b"RELAY:192.168.1.100:5000:test data";
        assert_eq!(message, expected);
    }

    #[test]
    fn test_relay_message_type_parsing() {
        assert_eq!(utils::parse_relay_message_type(b"RELAY:test"), RelayMessageType::PlainData);
        assert_eq!(utils::parse_relay_message_type(b"RELAY_ENCRYPTED:test"), RelayMessageType::EncryptedData);
        assert_eq!(utils::parse_relay_message_type(b"REGISTER:test"), RelayMessageType::Register);
        assert_eq!(utils::parse_relay_message_type(b"PING:test"), RelayMessageType::Ping);
        assert_eq!(utils::parse_relay_message_type(b"unknown"), RelayMessageType::Unknown);
    }

    #[test]
    fn test_peer_id_extraction() {
        let relay_data = b"RELAY:192.168.1.100:5000:some data";
        let peer_id = utils::extract_peer_id(relay_data).unwrap();
        assert_eq!(peer_id, "192.168.1.100:5000");

        let encrypted_data = b"RELAY_ENCRYPTED:10.0.0.1:8080:encrypted_header:payload";
        let peer_id = utils::extract_peer_id(encrypted_data).unwrap();
        assert_eq!(peer_id, "10.0.0.1:8080");
    }
}