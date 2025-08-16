// src/connectivity/signaling/mod.rs
//! Signaling система для обмена ICE кандидатами через SHARP протокол

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, Notify};
use tokio::time::timeout;
use tracing::{debug, info, warn, trace, error};
use uuid::Uuid;
use bytes::BytesMut;

use crate::connectivity::{Candidate, CandidatePair};
use crate::protocol::{packet::*, constants::*};

// Submodules
pub mod sharp_signaling;
pub mod session;

// Re-exports
pub use sharp_signaling::SharpSignaling;
pub use session::{SignalingSession, SessionState};

/// Сообщения signaling протокола
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalingMessage {
    /// Инициация сессии
    SessionInit {
        session_id: String,
        protocol_version: String,
        controlling: bool,
        capabilities: SignalingCapabilities,
    },

    /// Ответ на инициацию сессии
    SessionInitResponse {
        session_id: String,
        accepted: bool,
        reason: Option<String>,
        capabilities: SignalingCapabilities,
    },

    /// Обмен кандидатами
    CandidateExchange {
        session_id: String,
        candidates: Vec<SerializedCandidate>,
        gathering_complete: bool,
        sequence: u32,
    },

    /// Подтверждение получения кандидатов
    CandidateAck {
        session_id: String,
        last_received_sequence: u32,
        received_count: usize,
    },

    /// Connectivity check запрос
    ConnectivityCheck {
        session_id: String,
        check_id: String,
        from_candidate: SerializedCandidate,
        to_candidate: SerializedCandidate,
        priority: u64,
        use_candidate: bool,
        transaction_id: String,
    },

    /// Ответ на connectivity check
    ConnectivityResponse {
        session_id: String,
        check_id: String,
        transaction_id: String,
        success: bool,
        rtt_ms: Option<u64>,
        mapped_address: Option<SocketAddr>,
    },

    /// Nomination запрос
    NominationRequest {
        session_id: String,
        nominated_pair: (SerializedCandidate, SerializedCandidate),
        controlling: bool,
    },

    /// Ответ на nomination
    NominationResponse {
        session_id: String,
        accepted: bool,
        reason: Option<String>,
    },

    /// Уведомление об установленном соединении
    ConnectionEstablished {
        session_id: String,
        selected_pair: (SerializedCandidate, SerializedCandidate),
        connection_info: ConnectionInfo,
    },

    /// Завершение сессии
    SessionTerminate {
        session_id: String,
        reason: String,
    },

    /// Heartbeat для поддержания сессии
    Heartbeat {
        session_id: String,
        timestamp: u64,
    },

    /// Ошибка signaling
    Error {
        session_id: Option<String>,
        error_code: SignalingErrorCode,
        error_message: String,
    },
}

/// Возможности signaling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingCapabilities {
    /// Поддержка trickle ICE
    pub trickle_ice: bool,
    /// Поддержка IPv6
    pub ipv6: bool,
    /// Поддержка relay encryption
    pub relay_encryption: bool,
    /// Поддержка hairpining
    pub hairpining: bool,
    /// Максимальный размер пакета
    pub max_packet_size: usize,
    /// Поддерживаемые типы кандидатов
    pub supported_candidate_types: Vec<String>,
}

/// Информация о соединении
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Тип транспорта
    pub transport_type: String,
    /// Поддержка шифрования
    pub encryption_enabled: bool,
    /// Максимальный размер пакета
    pub max_packet_size: usize,
    /// RTT
    pub rtt_ms: Option<u64>,
    /// Качество соединения
    pub quality_score: f32,
}

/// Serialized кандидат для передачи по сети
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedCandidate {
    pub foundation: String,
    pub priority: u32,
    pub address: SocketAddr,
    pub candidate_type: String,
    pub related_address: Option<SocketAddr>,
    pub transport: String,
    pub component: u16,
    pub network_cost: u16,
    pub extensions: HashMap<String, String>,
}

impl From<Candidate> for SerializedCandidate {
    fn from(candidate: Candidate) -> Self {
        Self {
            foundation: candidate.foundation,
            priority: candidate.priority,
            address: candidate.address,
            candidate_type: format!("{:?}", candidate.candidate_type),
            related_address: candidate.related_address,
            transport: candidate.attributes.transport,
            component: candidate.attributes.component,
            network_cost: candidate.attributes.network_cost,
            extensions: HashMap::new(),
        }
    }
}

impl TryFrom<SerializedCandidate> for Candidate {
    type Error = anyhow::Error;

    fn try_from(serialized: SerializedCandidate) -> Result<Self> {
        let candidate_type = match serialized.candidate_type.as_str() {
            "Host" => crate::connectivity::CandidateType::Host,
            "ServerReflexive" => crate::connectivity::CandidateType::ServerReflexive,
            "PeerReflexive" => crate::connectivity::CandidateType::PeerReflexive,
            "Relay" => crate::connectivity::CandidateType::Relay,
            "RouterPool" => crate::connectivity::CandidateType::RouterPool,
            _ => return Err(anyhow::anyhow!("Unknown candidate type: {}", serialized.candidate_type)),
        };

        Ok(Candidate {
            foundation: serialized.foundation,
            priority: serialized.priority,
            address: serialized.address,
            candidate_type,
            related_address: serialized.related_address,
            attributes: crate::connectivity::CandidateAttributes {
                transport: serialized.transport,
                component: serialized.component,
                network_cost: serialized.network_cost,
                hairpin_capable: false,
                encryption_capable: false,
            },
        })
    }
}

/// Коды ошибок signaling
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SignalingErrorCode {
    InvalidMessage = 400,
    SessionNotFound = 404,
    SessionConflict = 409,
    InvalidCandidate = 422,
    ConnectivityCheckFailed = 500,
    NominationFailed = 502,
    Timeout = 504,
    InternalError = 500,
}

impl std::fmt::Display for SignalingErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignalingErrorCode::InvalidMessage => write!(f, "Invalid Message"),
            SignalingErrorCode::SessionNotFound => write!(f, "Session Not Found"),
            SignalingErrorCode::SessionConflict => write!(f, "Session Conflict"),
            SignalingErrorCode::InvalidCandidate => write!(f, "Invalid Candidate"),
            SignalingErrorCode::ConnectivityCheckFailed => write!(f, "Connectivity Check Failed"),
            SignalingErrorCode::NominationFailed => write!(f, "Nomination Failed"),
            SignalingErrorCode::Timeout => write!(f, "Timeout"),
            SignalingErrorCode::InternalError => write!(f, "Internal Error"),
        }
    }
}

/// Статистика signaling
#[derive(Debug, Clone, Default)]
pub struct SignalingStats {
    /// Время начала сессии
    pub session_started: Option<Instant>,
    /// Общее количество отправленных сообщений
    pub messages_sent: u64,
    /// Общее количество полученных сообщений
    pub messages_received: u64,
    /// Количество обменов кандидатами
    pub candidate_exchanges: u64,
    /// Количество connectivity checks
    pub connectivity_checks: u64,
    /// Количество успешных nomination
    pub successful_nominations: u64,
    /// Ошибки signaling
    pub errors: u64,
    /// Время последней активности
    pub last_activity: Option<Instant>,
}

impl SignalingStats {
    pub fn new() -> Self {
        Self {
            session_started: Some(Instant::now()),
            ..Default::default()
        }
    }

    pub fn record_message_sent(&mut self) {
        self.messages_sent += 1;
        self.last_activity = Some(Instant::now());
    }

    pub fn record_message_received(&mut self) {
        self.messages_received += 1;
        self.last_activity = Some(Instant::now());
    }

    pub fn record_error(&mut self) {
        self.errors += 1;
    }

    pub fn record_candidate_exchange(&mut self) {
        self.candidate_exchanges += 1;
    }

    pub fn record_connectivity_check(&mut self) {
        self.connectivity_checks += 1;
    }

    pub fn record_nomination(&mut self) {
        self.successful_nominations += 1;
    }
}

/// События signaling для подписчиков
#[derive(Debug, Clone)]
pub enum SignalingEvent {
    /// Сессия инициирована
    SessionInitiated { session_id: String },
    /// Получены новые кандидаты
    CandidatesReceived {
        session_id: String,
        candidates: Vec<Candidate>
    },
    /// Результат connectivity check
    ConnectivityCheckResult {
        session_id: String,
        check_id: String,
        success: bool,
        rtt: Option<Duration>,
    },
    /// Пара номинирована
    CandidatePairNominated {
        session_id: String,
        pair: CandidatePair,
    },
    /// Соединение установлено
    ConnectionEstablished {
        session_id: String,
        connection_info: ConnectionInfo,
    },
    /// Сессия завершена
    SessionTerminated {
        session_id: String,
        reason: String,
    },
    /// Ошибка signaling
    Error {
        session_id: Option<String>,
        error: SignalingErrorCode,
        message: String,
    },
}

/// Интерфейс для signaling реализаций
#[async_trait::async_trait]
pub trait SignalingTransport: Send + Sync {
    /// Отправка signaling сообщения
    async fn send_message(&self, message: SignalingMessage, target: SocketAddr) -> Result<()>;

    /// Получение signaling сообщений
    async fn receive_message(&self) -> Result<(SignalingMessage, SocketAddr)>;

    /// Закрытие транспорта
    async fn close(&self) -> Result<()>;

    /// Проверка активности
    fn is_active(&self) -> bool;

    /// Получение статистики
    fn get_stats(&self) -> SignalingStats;
}

/// Менеджер signaling сессий
pub struct SignalingManager {
    /// Активные сессии
    sessions: Arc<RwLock<HashMap<String, Arc<SignalingSession>>>>,
    /// Транспорт для отправки сообщений
    transport: Arc<dyn SignalingTransport>,
    /// События для подписчиков
    event_tx: mpsc::UnboundedSender<SignalingEvent>,
    event_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<SignalingEvent>>>>,
    /// Статистика
    stats: Arc<RwLock<SignalingStats>>,
    /// Shutdown флаг
    shutdown: Arc<tokio::sync::Notify>,
}

impl SignalingManager {
    pub fn new(transport: Arc<dyn SignalingTransport>) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            transport,
            event_tx,
            event_rx: Arc::new(RwLock::new(Some(event_rx))),
            stats: Arc::new(RwLock::new(SignalingStats::new())),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Запуск менеджера signaling
    pub async fn start(&self) -> Result<()> {
        info!("Starting SignalingManager");

        let manager = self.clone();
        tokio::spawn(async move {
            manager.message_loop().await;
        });

        Ok(())
    }

    /// Создание новой signaling сессии
    pub async fn create_session(
        &self,
        peer_addr: SocketAddr,
        controlling: bool,
    ) -> Result<String> {
        let session_id = Uuid::new_v4().to_string();
        let session = Arc::new(SignalingSession::new(
            session_id.clone(),
            peer_addr,
            controlling,
            self.event_tx.clone(),
        ));

        self.sessions.write().await.insert(session_id.clone(), session.clone());

        // Отправляем инициацию сессии
        let init_message = SignalingMessage::SessionInit {
            session_id: session_id.clone(),
            protocol_version: "SHARP-256-ICE/1.0".to_string(),
            controlling,
            capabilities: self.get_default_capabilities(),
        };

        self.transport.send_message(init_message, peer_addr).await?;
        self.stats.write().await.record_message_sent();

        info!("Created signaling session: {}", session_id);
        self.emit_event(SignalingEvent::SessionInitiated { session_id: session_id.clone() }).await;

        Ok(session_id)
    }

    /// Получение сессии по ID
    pub async fn get_session(&self, session_id: &str) -> Option<Arc<SignalingSession>> {
        self.sessions.read().await.get(session_id).cloned()
    }

    /// Обмен кандидатами
    pub async fn exchange_candidates(
        &self,
        session_id: &str,
        candidates: Vec<Candidate>,
    ) -> Result<Vec<Candidate>> {
        let session = self.get_session(session_id).await
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

        // Отправляем наши кандидаты
        let exchange_message = SignalingMessage::CandidateExchange {
            session_id: session_id.to_string(),
            candidates: candidates.into_iter().map(SerializedCandidate::from).collect(),
            gathering_complete: true,
            sequence: session.next_sequence().await,
        };

        self.transport.send_message(exchange_message, session.peer_addr()).await?;
        self.stats.write().await.record_message_sent();
        self.stats.write().await.record_candidate_exchange();

        // Ждем ответ с кандидатами от peer
        let timeout_duration = Duration::from_secs(10);
        match timeout(timeout_duration, session.wait_for_candidates()).await {
            Ok(candidates) => Ok(candidates),
            Err(_) => Err(anyhow::anyhow!("Candidate exchange timeout")),
        }
    }

    /// Отправка connectivity check
    pub async fn send_connectivity_check(
        &self,
        session_id: &str,
        local_candidate: &Candidate,
        remote_candidate: &Candidate,
        use_candidate: bool,
    ) -> Result<()> {
        let session = self.get_session(session_id).await
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

        let check_id = Uuid::new_v4().to_string();
        let transaction_id = Uuid::new_v4().to_string();

        let check_message = SignalingMessage::ConnectivityCheck {
            session_id: session_id.to_string(),
            check_id,
            from_candidate: SerializedCandidate::from(local_candidate.clone()),
            to_candidate: SerializedCandidate::from(remote_candidate.clone()),
            priority: crate::connectivity::CandidatePair::new(
                local_candidate.clone(),
                remote_candidate.clone()
            ).priority,
            use_candidate,
            transaction_id,
        };

        self.transport.send_message(check_message, session.peer_addr()).await?;
        self.stats.write().await.record_message_sent();
        self.stats.write().await.record_connectivity_check();

        Ok(())
    }

    /// Nomination кандидатной пары
    pub async fn nominate_pair(
        &self,
        session_id: &str,
        pair: &CandidatePair,
        controlling: bool,
    ) -> Result<()> {
        let session = self.get_session(session_id).await
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

        let nomination_message = SignalingMessage::NominationRequest {
            session_id: session_id.to_string(),
            nominated_pair: (
                SerializedCandidate::from(pair.local.clone()),
                SerializedCandidate::from(pair.remote.clone()),
            ),
            controlling,
        };

        self.transport.send_message(nomination_message, session.peer_addr()).await?;
        self.stats.write().await.record_message_sent();

        Ok(())
    }

    /// Завершение сессии
    pub async fn terminate_session(&self, session_id: &str, reason: &str) -> Result<()> {
        if let Some(session) = self.get_session(session_id).await {
            let terminate_message = SignalingMessage::SessionTerminate {
                session_id: session_id.to_string(),
                reason: reason.to_string(),
            };

            self.transport.send_message(terminate_message, session.peer_addr()).await?;
            self.stats.write().await.record_message_sent();
        }

        self.sessions.write().await.remove(session_id);

        self.emit_event(SignalingEvent::SessionTerminated {
            session_id: session_id.to_string(),
            reason: reason.to_string(),
        }).await;

        info!("Terminated signaling session: {}", session_id);
        Ok(())
    }

    /// Подписка на события
    pub async fn subscribe_events(&self) -> Option<mpsc::UnboundedReceiver<SignalingEvent>> {
        self.event_rx.write().await.take()
    }

    /// Shutdown менеджера
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down SignalingManager");

        // Завершаем все сессии
        let sessions: Vec<String> = self.sessions.read().await.keys().cloned().collect();
        for session_id in sessions {
            let _ = self.terminate_session(&session_id, "Manager shutdown").await;
        }

        // Закрываем транспорт
        self.transport.close().await?;

        // Сигнализируем shutdown
        self.shutdown.notify_waiters();

        Ok(())
    }

    /// Получение статистики
    pub async fn get_stats(&self) -> SignalingStats {
        self.stats.read().await.clone()
    }

    /// Главный цикл обработки сообщений
    async fn message_loop(&self) {
        info!("SignalingManager message loop started");

        loop {
            tokio::select! {
                // Получение сообщений
                result = self.transport.receive_message() => {
                    match result {
                        Ok((message, from_addr)) => {
                            self.stats.write().await.record_message_received();
                            if let Err(e) = self.handle_received_message(message, from_addr).await {
                                warn!("Error handling signaling message: {}", e);
                                self.stats.write().await.record_error();
                            }
                        }
                        Err(e) => {
                            error!("Error receiving signaling message: {}", e);
                            self.stats.write().await.record_error();
                        }
                    }
                }

                // Shutdown signal
                _ = self.shutdown.notified() => {
                    info!("SignalingManager message loop shutting down");
                    break;
                }
            }
        }
    }

    /// Обработка полученного сообщения
    async fn handle_received_message(
        &self,
        message: SignalingMessage,
        from_addr: SocketAddr,
    ) -> Result<()> {
        trace!("Received signaling message from {}: {:?}", from_addr, message);

        match message {
            SignalingMessage::SessionInit { session_id, controlling, capabilities, .. } => {
                self.handle_session_init(session_id, from_addr, controlling, capabilities).await
            }

            SignalingMessage::CandidateExchange { session_id, candidates, .. } => {
                self.handle_candidate_exchange(session_id, candidates).await
            }

            SignalingMessage::ConnectivityCheck { session_id, check_id, transaction_id, .. } => {
                self.handle_connectivity_check(session_id, check_id, transaction_id, from_addr).await
            }

            SignalingMessage::NominationRequest { session_id, nominated_pair, .. } => {
                self.handle_nomination_request(session_id, nominated_pair).await
            }

            SignalingMessage::SessionTerminate { session_id, reason } => {
                self.handle_session_terminate(session_id, reason).await
            }

            _ => {
                debug!("Unhandled signaling message type");
                Ok(())
            }
        }
    }

    /// Обработка инициации сессии
    async fn handle_session_init(
        &self,
        session_id: String,
        from_addr: SocketAddr,
        controlling: bool,
        _capabilities: SignalingCapabilities,
    ) -> Result<()> {
        // Создаем новую сессию для входящего запроса
        let session = Arc::new(SignalingSession::new(
            session_id.clone(),
            from_addr,
            !controlling, // Мы не controlling, если peer controlling
            self.event_tx.clone(),
        ));

        self.sessions.write().await.insert(session_id.clone(), session);

        // Отправляем ответ
        let response = SignalingMessage::SessionInitResponse {
            session_id: session_id.clone(),
            accepted: true,
            reason: None,
            capabilities: self.get_default_capabilities(),
        };

        self.transport.send_message(response, from_addr).await?;
        self.stats.write().await.record_message_sent();

        self.emit_event(SignalingEvent::SessionInitiated { session_id }).await;

        Ok(())
    }

    /// Обработка обмена кандидатами
    async fn handle_candidate_exchange(
        &self,
        session_id: String,
        serialized_candidates: Vec<SerializedCandidate>,
    ) -> Result<()> {
        let candidates: Result<Vec<Candidate>> = serialized_candidates
            .into_iter()
            .map(|sc| sc.try_into())
            .collect();

        let candidates = candidates?;

        if let Some(session) = self.get_session(&session_id).await {
            session.add_remote_candidates(candidates.clone()).await;

            self.emit_event(SignalingEvent::CandidatesReceived {
                session_id,
                candidates,
            }).await;
        }

        Ok(())
    }

    /// Обработка connectivity check
    async fn handle_connectivity_check(
        &self,
        session_id: String,
        check_id: String,
        transaction_id: String,
        from_addr: SocketAddr,
    ) -> Result<()> {
        // Отправляем ответ на connectivity check
        let response = SignalingMessage::ConnectivityResponse {
            session_id,
            check_id,
            transaction_id,
            success: true,
            rtt_ms: Some(10), // Mock RTT
            mapped_address: Some(from_addr),
        };

        self.transport.send_message(response, from_addr).await?;
        self.stats.write().await.record_message_sent();

        Ok(())
    }

    /// Обработка nomination запроса
    async fn handle_nomination_request(
        &self,
        session_id: String,
        nominated_pair: (SerializedCandidate, SerializedCandidate),
    ) -> Result<()> {
        let local_candidate = nominated_pair.0.try_into()?;
        let remote_candidate = nominated_pair.1.try_into()?;
        let pair = CandidatePair::new(local_candidate, remote_candidate);

        self.emit_event(SignalingEvent::CandidatePairNominated {
            session_id,
            pair,
        }).await;

        self.stats.write().await.record_nomination();

        Ok(())
    }

    /// Обработка завершения сессии
    async fn handle_session_terminate(&self, session_id: String, reason: String) -> Result<()> {
        self.sessions.write().await.remove(&session_id);

        self.emit_event(SignalingEvent::SessionTerminated {
            session_id,
            reason,
        }).await;

        Ok(())
    }

    /// Отправка события
    async fn emit_event(&self, event: SignalingEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Получение capabilities по умолчанию
    fn get_default_capabilities(&self) -> SignalingCapabilities {
        SignalingCapabilities {
            trickle_ice: true,
            ipv6: true,
            relay_encryption: true,
            hairpining: true,
            max_packet_size: 65535,
            supported_candidate_types: vec![
                "Host".to_string(),
                "ServerReflexive".to_string(),
                "Relay".to_string(),
                "RouterPool".to_string(),
            ],
        }
    }
}

impl Clone for SignalingManager {
    fn clone(&self) -> Self {
        Self {
            sessions: self.sessions.clone(),
            transport: self.transport.clone(),
            event_tx: self.event_tx.clone(),
            event_rx: self.event_rx.clone(),
            stats: self.stats.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock transport for testing
    struct MockSignalingTransport {
        stats: SignalingStats,
    }

    impl MockSignalingTransport {
        fn new() -> Self {
            Self {
                stats: SignalingStats::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl SignalingTransport for MockSignalingTransport {
        async fn send_message(&self, _message: SignalingMessage, _target: SocketAddr) -> Result<()> {
            Ok(())
        }

        async fn receive_message(&self) -> Result<(SignalingMessage, SocketAddr)> {
            // Для тестов возвращаем mock сообщение
            let message = SignalingMessage::Heartbeat {
                session_id: "test".to_string(),
                timestamp: 0,
            };
            Ok((message, "127.0.0.1:8080".parse().unwrap()))
        }

        async fn close(&self) -> Result<()> {
            Ok(())
        }

        fn is_active(&self) -> bool {
            true
        }

        fn get_stats(&self) -> SignalingStats {
            self.stats.clone()
        }
    }

    #[tokio::test]
    async fn test_signaling_manager_creation() {
        let transport = Arc::new(MockSignalingTransport::new());
        let manager = SignalingManager::new(transport);

        assert!(manager.sessions.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_session_creation() {
        let transport = Arc::new(MockSignalingTransport::new());
        let manager = SignalingManager::new(transport);

        let peer_addr = "127.0.0.1:8080".parse().unwrap();
        let session_id = manager.create_session(peer_addr, true).await.unwrap();

        assert!(!session_id.is_empty());
        assert!(manager.get_session(&session_id).await.is_some());
    }

    #[test]
    fn test_candidate_serialization() {
        let candidate = Candidate::host("192.168.1.100:5000".parse().unwrap());
        let serialized = SerializedCandidate::from(candidate.clone());
        let deserialized: Candidate = serialized.try_into().unwrap();

        assert_eq!(candidate.address, deserialized.address);
        assert_eq!(candidate.priority, deserialized.priority);
    }
}