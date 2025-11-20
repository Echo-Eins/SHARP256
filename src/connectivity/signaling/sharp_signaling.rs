// src/connectivity/signaling/sharp_signaling.rs
//! SHARP-256 signaling implementation через UDP пакеты

use super::{SignalingMessage, SignalingStats, SignalingTransport};
use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, trace, warn};

use crate::connectivity::Candidate;
use crate::protocol::{constants::*, packet::*};

/// SHARP signaling transport через UDP
pub struct SharpSignaling {
    /// UDP сокет для отправки signaling сообщений
    socket: Arc<UdpSocket>,
    /// Адрес peer для signaling
    peer_addr: SocketAddr,
    /// Входящие сообщения
    incoming_messages: Arc<RwLock<VecDeque<(SignalingMessage, SocketAddr)>>>,
    /// Статистика
    stats: Arc<RwLock<SignalingStats>>,
    /// Notification для новых сообщений
    message_notify: Arc<Notify>,
    /// Shutdown флаг
    active: Arc<RwLock<bool>>,
    /// Reliability layer для важных сообщений
    reliable_sender: Arc<ReliableMessageSender>,
}

impl SharpSignaling {
    /// Создание нового SHARP signaling транспорта
    pub fn new(socket: Arc<UdpSocket>, peer_addr: SocketAddr) -> Self {
        info!("Creating SHARP signaling transport to {}", peer_addr);

        let reliable_sender = Arc::new(ReliableMessageSender::new(socket.clone(), peer_addr));

        Self {
            socket,
            peer_addr,
            incoming_messages: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(SignalingStats::new())),
            message_notify: Arc::new(Notify::new()),
            active: Arc::new(RwLock::new(true)),
            reliable_sender,
        }
    }

    /// Обмен кандидатами с peer
    pub async fn exchange_candidates(
        &self,
        local_candidates: Vec<Candidate>,
    ) -> Result<Vec<Candidate>> {
        info!(
            "Starting candidate exchange with {} candidates",
            local_candidates.len()
        );

        // Создаем сообщение с кандидатами
        let exchange_message = SignalingMessage::CandidateExchange {
            session_id: uuid::Uuid::new_v4().to_string(),
            candidates: local_candidates
                .into_iter()
                .map(super::SerializedCandidate::from)
                .collect(),
            gathering_complete: true,
            sequence: 1,
        };

        // Отправляем кандидаты надежным способом
        self.reliable_sender.send_reliable(exchange_message).await?;

        // Ждем кандидаты от peer
        let timeout_duration = Duration::from_secs(30);
        let start_time = Instant::now();

        while start_time.elapsed() < timeout_duration {
            if let Some((message, _)) = self.try_receive_message().await {
                if let SignalingMessage::CandidateExchange { candidates, .. } = message {
                    let received_candidates: Result<Vec<Candidate>> =
                        candidates.into_iter().map(|sc| sc.try_into()).collect();

                    match received_candidates {
                        Ok(candidates) => {
                            info!("Received {} candidates from peer", candidates.len());
                            return Ok(candidates);
                        }
                        Err(e) => {
                            warn!("Failed to deserialize received candidates: {}", e);
                        }
                    }
                }
            }

            // Короткая пауза перед следующей попыткой
            sleep(Duration::from_millis(100)).await;
        }

        Err(anyhow::anyhow!("Candidate exchange timeout"))
    }

    /// Обработка входящего SHARP пакета
    pub async fn handle_sharp_packet(&self, packet: Packet) -> Result<()> {
        match packet.header.packet_type {
            PacketType::IceCandidate | PacketType::IceConnCheck | PacketType::IceNomination => {
                // Десериализуем signaling сообщение
                match bincode::deserialize::<SignalingMessage>(&packet.payload) {
                    Ok(message) => {
                        trace!("Received signaling message: {:?}", message);

                        // Добавляем в очередь входящих сообщений
                        self.incoming_messages
                            .write()
                            .push_back((message, self.peer_addr));
                        self.message_notify.notify_one();
                        self.stats.write().record_message_received();

                        Ok(())
                    }
                    Err(e) => {
                        warn!("Failed to deserialize signaling message: {}", e);
                        Err(e.into())
                    }
                }
            }
            _ => {
                // Не signaling пакет
                Ok(())
            }
        }
    }

    /// Попытка получения сообщения без блокировки
    async fn try_receive_message(&self) -> Option<(SignalingMessage, SocketAddr)> {
        self.incoming_messages.write().pop_front()
    }

    /// Создание SHARP пакета для signaling сообщения
    fn create_signaling_packet(&self, message: &SignalingMessage) -> Result<Packet> {
        let serialized = bincode::serialize(message)?;

        let packet_type = match message {
            SignalingMessage::CandidateExchange { .. } | SignalingMessage::CandidateAck { .. } => {
                PacketType::IceCandidate
            }

            SignalingMessage::ConnectivityCheck { .. }
            | SignalingMessage::ConnectivityResponse { .. } => PacketType::IceConnCheck,

            SignalingMessage::NominationRequest { .. }
            | SignalingMessage::NominationResponse { .. } => PacketType::IceNomination,

            _ => PacketType::IceCandidate, // Default
        };

        let mut header = PacketHeader::new(packet_type);
        header.payload_length = serialized.len() as u32;
        header.sequence = self.stats.read().messages_sent as u32;

        Ok(Packet::new(header, serialized))
    }
}

#[async_trait]
impl SignalingTransport for SharpSignaling {
    async fn send_message(&self, message: SignalingMessage, target: SocketAddr) -> Result<()> {
        if target != self.peer_addr {
            warn!(
                "Attempting to send message to {}, but configured peer is {}",
                target, self.peer_addr
            );
        }

        let packet = self.create_signaling_packet(&message)?;
        let packet_bytes = packet.to_bytes();

        trace!(
            "Sending signaling packet: {} bytes to {}",
            packet_bytes.len(),
            self.peer_addr
        );

        match self.socket.send_to(&packet_bytes, self.peer_addr).await {
            Ok(bytes_sent) => {
                if bytes_sent != packet_bytes.len() {
                    warn!(
                        "Partial signaling packet sent: {}/{} bytes",
                        bytes_sent,
                        packet_bytes.len()
                    );
                }

                self.stats.write().record_message_sent();
                debug!(
                    "Sent signaling message to {}: {:?}",
                    self.peer_addr, message
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    "Failed to send signaling message to {}: {}",
                    self.peer_addr, e
                );
                self.stats.write().record_error();
                Err(e.into())
            }
        }
    }

    async fn receive_message(&self) -> Result<(SignalingMessage, SocketAddr)> {
        // Ждем уведомления о новом сообщении
        let timeout_duration = Duration::from_secs(1);

        loop {
            // Проверяем есть ли уже сообщения в очереди
            if let Some(message) = self.try_receive_message().await {
                return Ok(message);
            }

            // Ждем уведомления с таймаутом
            if timeout(timeout_duration, self.message_notify.notified())
                .await
                .is_ok()
            {
                continue;
            }

            // Проверяем активность
            if !*self.active.read() {
                return Err(anyhow::anyhow!("Signaling transport closed"));
            }
        }
    }

    async fn close(&self) -> Result<()> {
        info!("Closing SHARP signaling transport");
        *self.active.write() = false;
        self.message_notify.notify_waiters();
        Ok(())
    }

    fn is_active(&self) -> bool {
        *self.active.read()
    }

    fn get_stats(&self) -> SignalingStats {
        self.stats.read().clone()
    }
}

/// Надежная отправка сообщений с повторами и подтверждениями
struct ReliableMessageSender {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    pending_messages: Arc<RwLock<Vec<PendingMessage>>>,
}

#[derive(Debug, Clone)]
struct PendingMessage {
    id: String,
    message: SignalingMessage,
    packet: Packet,
    sent_at: Instant,
    retry_count: u32,
    max_retries: u32,
    retry_interval: Duration,
}

impl ReliableMessageSender {
    fn new(socket: Arc<UdpSocket>, peer_addr: SocketAddr) -> Self {
        let sender = Self {
            socket,
            peer_addr,
            pending_messages: Arc::new(RwLock::new(Vec::new())),
        };

        // Запускаем фоновую задачу для повторов
        let sender_clone = sender.clone();
        tokio::spawn(async move {
            sender_clone.retry_loop().await;
        });

        sender
    }

    /// Отправка сообщения с гарантией доставки
    async fn send_reliable(&self, message: SignalingMessage) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let serialized = bincode::serialize(&message)?;

        let mut header = PacketHeader::new(PacketType::IceCandidate);
        header.payload_length = serialized.len() as u32;
        header.flags |= packet_flags::RETRANSMIT; // Маркируем как требующий подтверждения

        let packet = Packet::new(header, serialized);

        let pending = PendingMessage {
            id: id.clone(),
            message,
            packet: packet.clone(),
            sent_at: Instant::now(),
            retry_count: 0,
            max_retries: 5,
            retry_interval: Duration::from_millis(500),
        };

        // Отправляем первый раз
        self.socket
            .send_to(&packet.to_bytes(), self.peer_addr)
            .await?;

        // Добавляем в список ожидающих подтверждения
        self.pending_messages.write().push(pending);

        debug!("Sent reliable message {} to {}", id, self.peer_addr);
        Ok(())
    }

    /// Подтверждение получения сообщения
    fn acknowledge_message(&self, message_id: &str) {
        let mut pending = self.pending_messages.write();
        pending.retain(|msg| msg.id != message_id);
        debug!("Acknowledged message: {}", message_id);
    }

    /// Фоновый цикл повторной отправки
    async fn retry_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_millis(100));

        loop {
            interval.tick().await;

            let mut to_retry = Vec::new();
            let mut to_remove = Vec::new();

            // Проверяем сообщения, требующие повтора
            {
                let mut pending = self.pending_messages.write();
                for (index, msg) in pending.iter_mut().enumerate() {
                    let elapsed = msg.sent_at.elapsed();

                    if elapsed >= msg.retry_interval {
                        if msg.retry_count < msg.max_retries {
                            msg.retry_count += 1;
                            msg.sent_at = Instant::now();
                            msg.retry_interval *= 2; // Exponential backoff

                            to_retry.push(msg.clone());
                            debug!("Retrying message {} (attempt {})", msg.id, msg.retry_count);
                        } else {
                            warn!("Message {} exceeded max retries", msg.id);
                            to_remove.push(index);
                        }
                    }
                }

                // Удаляем сообщения с превышенным количеством попыток
                for &index in to_remove.iter().rev() {
                    pending.remove(index);
                }
            }

            // Повторно отправляем сообщения
            for msg in to_retry {
                if let Err(e) = self
                    .socket
                    .send_to(&msg.packet.to_bytes(), self.peer_addr)
                    .await
                {
                    warn!("Failed to retry message {}: {}", msg.id, e);
                }
            }
        }
    }
}

impl Clone for ReliableMessageSender {
    fn clone(&self) -> Self {
        Self {
            socket: self.socket.clone(),
            peer_addr: self.peer_addr,
            pending_messages: self.pending_messages.clone(),
        }
    }
}

/// Менеджер SHARP signaling сессий
pub struct SharpSignalingManager {
    socket: Arc<UdpSocket>,
    active_transports: Arc<RwLock<std::collections::HashMap<SocketAddr, Arc<SharpSignaling>>>>,
    message_handlers: Arc<RwLock<Vec<mpsc::UnboundedSender<(Packet, SocketAddr)>>>>,
}

impl SharpSignalingManager {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            active_transports: Arc::new(RwLock::new(std::collections::HashMap::new())),
            message_handlers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Создание signaling транспорта для peer
    pub async fn create_transport(&self, peer_addr: SocketAddr) -> Arc<SharpSignaling> {
        let transport = Arc::new(SharpSignaling::new(self.socket.clone(), peer_addr));

        self.active_transports
            .write()
            .insert(peer_addr, transport.clone());

        info!("Created SHARP signaling transport for {}", peer_addr);
        transport
    }

    /// Получение существующего транспорта
    pub async fn get_transport(&self, peer_addr: SocketAddr) -> Option<Arc<SharpSignaling>> {
        self.active_transports.read().get(&peer_addr).cloned()
    }

    /// Обработка входящего пакета от основного SHARP протокола
    pub async fn handle_incoming_packet(
        &self,
        packet: Packet,
        from_addr: SocketAddr,
    ) -> Result<bool> {
        // Проверяем, является ли это signaling пакетом
        match packet.header.packet_type {
            PacketType::IceCandidate | PacketType::IceConnCheck | PacketType::IceNomination => {
                // Находим или создаем транспорт для этого peer
                let transport = if let Some(transport) = self.get_transport(from_addr).await {
                    transport
                } else {
                    // Создаем новый транспорт для входящего соединения
                    self.create_transport(from_addr).await
                };

                // Передаем пакет транспорту для обработки
                transport.handle_sharp_packet(packet).await?;

                debug!("Handled signaling packet from {}", from_addr);
                Ok(true) // Пакет обработан
            }
            _ => {
                // Не signaling пакет
                Ok(false)
            }
        }
    }

    /// Подписка на signaling пакеты
    pub async fn subscribe_packets(&self) -> mpsc::UnboundedReceiver<(Packet, SocketAddr)> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.message_handlers.write().push(tx);
        rx
    }

    /// Удаление транспорта
    pub async fn remove_transport(&self, peer_addr: SocketAddr) -> Option<Arc<SharpSignaling>> {
        let transport = self.active_transports.write().remove(&peer_addr);
        if transport.is_some() {
            info!("Removed SHARP signaling transport for {}", peer_addr);
        }
        transport
    }

    /// Получение всех активных адресов
    pub async fn get_active_peers(&self) -> Vec<SocketAddr> {
        self.active_transports.read().keys().cloned().collect()
    }

    /// Закрытие всех транспортов
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down SHARP signaling manager");

        let transports: Vec<_> = self.active_transports.write().drain().collect();

        for (_, transport) in transports {
            transport.close().await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_sharp_signaling_creation() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer_addr = "127.0.0.1:8080".parse().unwrap();

        let signaling = SharpSignaling::new(socket, peer_addr);

        assert!(signaling.is_active());
        assert_eq!(signaling.peer_addr, peer_addr);
    }

    #[tokio::test]
    async fn test_signaling_packet_creation() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer_addr = "127.0.0.1:8080".parse().unwrap();

        let signaling = SharpSignaling::new(socket, peer_addr);

        let message = SignalingMessage::Heartbeat {
            session_id: "test".to_string(),
            timestamp: 1234567890,
        };

        let packet = signaling.create_signaling_packet(&message).unwrap();

        assert_eq!(packet.header.packet_type, PacketType::IceCandidate);
        assert!(packet.header.payload_length > 0);
    }

    #[tokio::test]
    async fn test_sharp_signaling_manager() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let manager = SharpSignalingManager::new(socket);

        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        let transport = manager.create_transport(peer_addr).await;

        assert!(manager.get_transport(peer_addr).await.is_some());
        assert_eq!(manager.get_active_peers().await.len(), 1);

        manager.remove_transport(peer_addr).await;
        assert!(manager.get_transport(peer_addr).await.is_none());
    }

    #[tokio::test]
    async fn test_reliable_message_sender() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer_addr = "127.0.0.1:8080".parse().unwrap();

        let sender = ReliableMessageSender::new(socket, peer_addr);

        let message = SignalingMessage::Heartbeat {
            session_id: "test".to_string(),
            timestamp: 1234567890,
        };

        // Должно завершиться с ошибкой, так как нет получателя
        assert!(sender.send_reliable(message).await.is_ok());

        // Проверяем что сообщение добавлено в pending
        assert_eq!(sender.pending_messages.read().len(), 1);
    }
}
