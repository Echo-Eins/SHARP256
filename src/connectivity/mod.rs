// src/connectivity/mod.rs
//! SHARP-256 Connectivity Module
//!
//! Обеспечивает установление соединений через различные методы:
//! - WebRTC ICE (primary)
//! - libp2p fallback
//! - NAT router pools
//! - Relay with encryption
//! - Direct connections with hairpining

// src/connectivity/mod.rs
//! SHARP-256 Connectivity Module
//!
//! Обеспечивает установление соединений через различные методы:
//! - WebRTC ICE (primary)
//! - libp2p fallback
//! - NAT router pools
//! - Relay with encryption
//! - Direct connections with hairpining

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use serde::{Deserialize, Serialize};
use parking_lot::Mutex;

// Публичные модули
pub mod manager;
pub mod config;

// ICE модули (primary)
#[cfg(feature = "webrtc-ice-stack")]
pub mod ice;

// Fallback модули
#[cfg(feature = "libp2p-fallback")]
pub mod fallback;

// Transport абстракция
pub mod transport;

// Signaling система
pub mod signaling;

// Encryption для relay
#[cfg(feature = "relay-encryption")]
pub mod encryption;

// NAT router pools
#[cfg(feature = "nat-router-pools")]
pub mod router_pools;

// UPnP legacy support
#[cfg(feature = "upnp-support")]
pub mod upnp;

// Re-exports для удобства
pub use manager::{ConnectivityManager, ConnectivityEvent};
pub use config::{ConnectivityConfig, IceConfig, LibP2pConfig, RelayConfig};
pub use transport::{Transport, TransportType, TransportStats, EstablishedConnection};

/// Главная структура для управления connectivity
pub struct Connectivity {
    manager: Arc<ConnectivityManager>,
    config: ConnectivityConfig,
}

impl Connectivity {
    /// Создание новой connectivity системы с конфигурацией по умолчанию
    pub async fn new() -> Result<Self> {
        let config = ConnectivityConfig::default();
        Self::with_config(config).await
    }

    /// Создание с пользовательской конфигурацией
    pub async fn with_config(config: ConnectivityConfig) -> Result<Self> {
        let manager = Arc::new(ConnectivityManager::new(config.clone()).await?);

        Ok(Self { manager, config })
    }

    /// Установление соединения с peer
    ///
    /// # Arguments
    /// * `socket` - UDP сокет для связи
    /// * `peer_hint` - предполагаемый адрес peer (может быть неточным из-за NAT)
    /// * `is_controlling` - роль в ICE (true для инициатора)
    ///
    /// # Returns
    /// Установленное соединение с выбранным транспортом
    pub async fn establish_connection(
        &self,
        socket: Arc<UdpSocket>,
        peer_hint: Option<SocketAddr>,
        is_controlling: bool,
    ) -> Result<EstablishedConnection> {
        self.manager
            .establish_connection(socket, peer_hint, is_controlling)
            .await
    }

    /// Получение публичного адреса для подключения
    pub async fn get_connectable_address(&self) -> Result<SocketAddr> {
        self.manager.get_connectable_address().await
    }

    /// Получение локальных кандидатов для обмена
    pub async fn get_local_candidates(&self) -> Result<Vec<Candidate>> {
        self.manager.gather_candidates().await
    }

    /// Добавление удаленных кандидатов от peer
    pub async fn add_remote_candidates(&self, candidates: Vec<Candidate>) -> Result<()> {
        self.manager.add_remote_candidates(candidates).await
    }

    /// Получение состояния подключения
    pub fn get_connection_state(&self) -> ConnectionState {
        self.manager.get_connection_state()
    }

    /// Подписка на события connectivity
    pub fn subscribe_events(&self) -> mpsc::UnboundedReceiver<ConnectivityEvent> {
        self.manager.subscribe_events()
    }

    /// Graceful shutdown
    pub async fn shutdown(&self) -> Result<()> {
        self.manager.shutdown().await
    }
}

/// Состояние подключения
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Начальное состояние
    New,
    /// Сбор кандидатов
    Gathering,
    /// Проверка связности
    Connecting,
    /// Соединение установлено
    Connected,
    /// Соединение закрыто
    Closed,
    /// Ошибка соединения
    Failed,
}

/// Кандидат для соединения (универсальный для всех методов)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    /// Уникальный идентификатор кандидата
    pub foundation: String,
    /// Приоритет кандидата (RFC 8445)
    pub priority: u32,
    /// Адрес кандидата
    pub address: SocketAddr,
    /// Тип кандидата
    pub candidate_type: CandidateType,
    /// Связанный адрес (для reflexive/relay кандидатов)
    pub related_address: Option<SocketAddr>,
    /// Дополнительные атрибуты
    pub attributes: CandidateAttributes,
}

/// Тип кандидата
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CandidateType {
    /// Локальный адрес хоста
    Host,
    /// Reflexive адрес (через STUN)
    ServerReflexive,
    /// Peer reflexive адрес
    PeerReflexive,
    /// Relay адрес (через TURN)
    Relay,
    /// NAT router из пула
    RouterPool,
}

/// Дополнительные атрибуты кандидата
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CandidateAttributes {
    /// Transport protocol (обычно UDP)
    pub transport: String,
    /// Component ID (обычно 1 для RTP)
    pub component: u16,
    /// Network cost (для приоритизации)
    pub network_cost: u16,
    /// Supports hairpining
    pub hairpin_capable: bool,
    /// Encryption capable (для relay)
    pub encryption_capable: bool,
}

impl Candidate {
    /// Создание host кандидата
    pub fn host(address: SocketAddr) -> Self {
        Self {
            foundation: format!("host-{}", address),
            priority: Self::calculate_priority(CandidateType::Host, 65535, 1),
            address,
            candidate_type: CandidateType::Host,
            related_address: None,
            attributes: CandidateAttributes {
                transport: "UDP".to_string(),
                component: 1,
                network_cost: 10,
                hairpin_capable: false,
                encryption_capable: false,
            },
        }
    }

    /// Создание server reflexive кандидата
    pub fn server_reflexive(address: SocketAddr, base: SocketAddr) -> Self {
        Self {
            foundation: format!("srflx-{}", address),
            priority: Self::calculate_priority(CandidateType::ServerReflexive, 65535, 1),
            address,
            candidate_type: CandidateType::ServerReflexive,
            related_address: Some(base),
            attributes: CandidateAttributes {
                transport: "UDP".to_string(),
                component: 1,
                network_cost: 20,
                hairpin_capable: false,
                encryption_capable: false,
            },
        }
    }

    /// Создание relay кандидата
    pub fn relay(address: SocketAddr, related: SocketAddr, encryption_capable: bool) -> Self {
        Self {
            foundation: format!("relay-{}", address),
            priority: Self::calculate_priority(CandidateType::Relay, 65535, 1),
            address,
            candidate_type: CandidateType::Relay,
            related_address: Some(related),
            attributes: CandidateAttributes {
                transport: "UDP".to_string(),
                component: 1,
                network_cost: 100,
                hairpin_capable: true,
                encryption_capable,
            },
        }
    }

    /// Расчет приоритета по RFC 8445
    fn calculate_priority(candidate_type: CandidateType, local_pref: u16, component_id: u16) -> u32 {
        let type_pref = match candidate_type {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::RouterPool => 90,
            CandidateType::Relay => 0,
        };

        (type_pref << 24) | ((local_pref as u32) << 8) | (component_id as u32)
    }

    /// Проверка совместимости с другим кандидатом
    pub fn is_compatible_with(&self, other: &Candidate) -> bool {
        // Проверяем совместимость транспорта
        if self.attributes.transport != other.attributes.transport {
            return false;
        }

        // Проверяем IP версии
        match (self.address, other.address) {
            (SocketAddr::V4(_), SocketAddr::V4(_)) => true,
            (SocketAddr::V6(_), SocketAddr::V6(_)) => true,
            _ => false,
        }
    }
}

/// Пара кандидатов для connectivity check
#[derive(Debug, Clone)]
pub struct CandidatePair {
    pub local: Candidate,
    pub remote: Candidate,
    pub priority: u64,
    pub state: CandidatePairState,
    pub nominated: bool,
    pub last_activity: Option<Instant>,
}

/// Состояние пары кандидатов
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatePairState {
    Waiting,
    InProgress,
    Succeeded,
    Failed,
    Frozen,
}

impl CandidatePair {
    pub fn new(local: Candidate, remote: Candidate) -> Self {
        let priority = Self::calculate_pair_priority(&local, &remote);
        Self {
            local,
            remote,
            priority,
            state: CandidatePairState::Waiting,
            nominated: false,
            last_activity: None,
        }
    }

    /// Расчет приоритета пары по RFC 8445
    fn calculate_pair_priority(local: &Candidate, remote: &Candidate) -> u64 {
        let g = if local.priority > remote.priority { 1 } else { 0 };
        let min_priority = std::cmp::min(local.priority, remote.priority) as u64;
        let max_priority = std::cmp::max(local.priority, remote.priority) as u64;

        (1u64 << 32) * min_priority + 2 * max_priority + g
    }

    /// Обновление состояния пары
    pub fn update_state(&mut self, new_state: CandidatePairState) {
        self.state = new_state;
        self.last_activity = Some(Instant::now());
    }
}

/// Результат connectivity check
#[derive(Debug, Clone)]
pub struct ConnectivityCheckResult {
    pub pair: CandidatePair,
    pub success: bool,
    pub rtt: Option<Duration>,
    pub error: Option<String>,
    pub timestamp: Instant,
}

/// Метрики connectivity для мониторинга
#[derive(Debug, Clone, Default)]
pub struct ConnectivityMetrics {
    /// Время начала процесса
    pub started_at: Option<Instant>,
    /// Время установления соединения
    pub connected_at: Option<Instant>,
    /// Общее время установления
    pub connection_time: Option<Duration>,
    /// Количество собранных кандидатов
    pub candidates_gathered: usize,
    /// Количество успешных checks
    pub successful_checks: usize,
    /// Количество неудачных checks
    pub failed_checks: usize,
    /// Выбранная пара кандидатов
    pub selected_pair: Option<CandidatePair>,
    /// Использованный метод подключения
    pub connection_method: Option<String>,
    /// Ошибки в процессе
    pub errors: Vec<String>,
}

impl ConnectivityMetrics {
    pub fn new() -> Self {
        Self {
            started_at: Some(Instant::now()),
            ..Default::default()
        }
    }

    pub fn mark_connected(&mut self) {
        self.connected_at = Some(Instant::now());
        if let Some(started) = self.started_at {
            self.connection_time = Some(Instant::now() - started);
        }
    }

    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
    }
}

/// Utilities для работы с адресами
pub mod utils {
    use std::net::{IpAddr, SocketAddr};

    /// Проверка является ли адрес приватным
    pub fn is_private_addr(addr: &SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(ipv4) => ipv4.is_private(),
            IpAddr::V6(ipv6) => ipv6.is_unique_local(),
        }
    }

    /// Проверка являются ли адреса из одной подсети
    pub fn is_same_subnet(addr1: &SocketAddr, addr2: &SocketAddr) -> bool {
        match (addr1.ip(), addr2.ip()) {
            (IpAddr::V4(ip1), IpAddr::V4(ip2)) => {
                let octets1 = ip1.octets();
                let octets2 = ip2.octets();
                octets1[0..3] == octets2[0..3]
            }
            (IpAddr::V6(ip1), IpAddr::V6(ip2)) => {
                let segments1 = ip1.segments();
                let segments2 = ip2.segments();
                segments1[0..4] == segments2[0..4]
            }
            _ => false,
        }
    }

    /// Определение сетевой стоимости для приоритизации
    pub fn calculate_network_cost(local: &SocketAddr, remote: &SocketAddr) -> u16 {
        if is_same_subnet(local, remote) {
            // Локальная сеть - минимальная стоимость
            10
        } else if is_private_addr(local) && is_private_addr(remote) {
            // Обе приватные, но разные сети
            30
        } else if is_private_addr(local) || is_private_addr(remote) {
            // Одна приватная, одна публичная - NAT traversal
            50
        } else {
            // Обе публичные
            20
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidate_priority_calculation() {
        let host_candidate = Candidate::host("192.168.1.100:5000".parse().unwrap());
        let relay_candidate = Candidate::relay(
            "1.2.3.4:3478".parse().unwrap(),
            "192.168.1.100:5000".parse().unwrap(),
            true,
        );

        assert!(host_candidate.priority > relay_candidate.priority);
    }

    #[test]
    fn test_candidate_compatibility() {
        let v4_candidate = Candidate::host("192.168.1.100:5000".parse().unwrap());
        let v6_candidate = Candidate::host("[::1]:5000".parse().unwrap());

        assert!(!v4_candidate.is_compatible_with(&v6_candidate));
    }

    #[test]
    fn test_pair_priority_calculation() {
        let local = Candidate::host("192.168.1.100:5000".parse().unwrap());
        let remote = Candidate::server_reflexive(
            "1.2.3.4:5000".parse().unwrap(),
            "192.168.1.200:5000".parse().unwrap(),
        );

        let pair = CandidatePair::new(local, remote);
        assert!(pair.priority > 0);
    }

    #[test]
    fn test_utils_private_addr_detection() {
        let private_addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let public_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

        assert!(utils::is_private_addr(&private_addr));
        assert!(!utils::is_private_addr(&public_addr));
    }

    #[test]
    fn test_utils_subnet_detection() {
        let addr1: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.200:5000".parse().unwrap();
        let addr3: SocketAddr = "192.168.2.100:5000".parse().unwrap();

        assert!(utils::is_same_subnet(&addr1, &addr2));
        assert!(!utils::is_same_subnet(&addr1, &addr3));
    }
}