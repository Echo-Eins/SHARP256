// src/connectivity/mod.rs
//! SHARP-256 Connectivity Module
//!
//! Полнофункциональная система установления соединений с интеграцией webrtc-rs.
//!
//! ## Архитектура
//!
//! ### Уровень 1: WebRTC ICE (Primary)
//! - RFC 8445 совместимая реализация
//! - Candidate gathering, connectivity checks, nomination
//! - Интеграция с webrtc-rs библиотекой
//! - Отказоустойчивость и мониторинг
//!
//! ### Уровень 2: Fallback системы
//! - libp2p для сложных NAT сценариев
//! - NAT router pools с адаптивным обучением
//! - SHARP relay с шифрованием заголовков
//! - UPnP/IGD legacy поддержка
//!
//! ### Уровень 3: Transport абстракция
//! - Универсальный Transport trait
//! - Статистика и мониторинг
//! - Automatic failover и retry логика
//!
//! ## Использование
//!
//! ```rust
//  use sharp256::connectivity::Connectivity;
//!
//! // Создание с конфигурацией по умолчанию
//! let connectivity = Connectivity::new().await?;
//!
//! // Установление соединения
//! let connection = connectivity.establish_connection(
//!     socket,
//!     Some(peer_addr),
//!     true // controlling
//! ).await?;
//!
//! // Использование соединения
//! connection.send(data).await?;
//! let (size, addr) = connection.recv(&mut buffer).await?;
//! ```

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

// === МОДУЛИ ===

// PHASE 2: Manager will be rebuilt from scratch
// pub mod manager;

// PHASE 2 - STAGE 1: Transport layer (RFC 8445 compliant)
pub mod transport;

pub mod config;

// ICE modules (primary) - RFC 8445 compliant
#[cfg(feature = "webrtc-ice-stack")]
pub mod ice;

// STUN module (RFC 8489, RFC 5780)
pub mod stun;

// Signaling система
pub mod signaling;

// Encryption для relay
#[cfg(feature = "relay-encryption")]
pub mod encryption;

// Fallback модули
#[cfg(feature = "libp2p-fallback")]
pub mod fallback;

// NAT router pools
#[cfg(feature = "nat-router-pools")]
pub mod router_pools;

// UPnP legacy support
#[cfg(feature = "upnp-support")]
pub mod upnp;

// === RE-EXPORTS ===

// PHASE 2: Manager types will be defined here
// pub use manager::{ConnectivityManager, DetailedConnectivityStats};

// PHASE 2 - STAGE 1: Transport layer exports (RFC 8445 compliant)
pub use transport::{
    CandidatePairStats, ConnectionInfo, ConnectionState, ConsentStats, IceStats,
    PerformanceMetrics, QualityMetrics, SocketStats, Transport, TransportCapabilities,
    TransportEvent, TransportStats, TransportType,
};

pub use config::{
    ConnectionMethod, ConnectivityConfig, GeneralConfig, IceConfig, LibP2pConfig, RelayConfig,
};

// ICE specific exports
#[cfg(feature = "webrtc-ice-stack")]
pub use ice::{
    CandidateGatherer, CandidateNominator, ConnectivityChecker, ConnectivityState, GatheringState,
    IceAgent, IceAgentState, IceConnection, IceEvent, NominationState, ProductionIceAgent,
};

// STUN module exports (RFC 8489, RFC 5780)
pub use stun::{
    BindingResult, NatDetectionResult, NatDetector, NatFilteringBehavior, NatMappingBehavior,
    NatType, StunClient, StunClientConfig, StunConfig, StunError, StunMessage, StunMessageType,
    TransactionId,
};

// === ОСНОВНЫЕ ТИПЫ ===

/// ICE кандидат
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// Foundation (уникальный идентификатор типа кандидата)
    pub foundation: String,
    /// Приоритет кандидата
    pub priority: u32,
    /// Адрес кандидата
    pub address: SocketAddr,
    /// Тип кандидата
    pub candidate_type: CandidateType,
    /// Связанный адрес (для reflexive и relay кандидатов)
    pub related_address: Option<SocketAddr>,
    /// Дополнительные атрибуты
    pub attributes: CandidateAttributes,
}

impl Candidate {
    /// Создание host кандидата
    pub fn host(address: SocketAddr) -> Self {
        Self {
            foundation: ice::utils::generate_foundation(CandidateType::Host, address, None),
            priority: ice::utils::calculate_candidate_priority(CandidateType::Host, 65535, 1),
            address,
            candidate_type: CandidateType::Host,
            related_address: None,
            attributes: CandidateAttributes::default(),
        }
    }

    /// Создание server reflexive кандидата
    pub fn server_reflexive(
        public_address: SocketAddr,
        local_address: SocketAddr,
        stun_server: SocketAddr,
    ) -> Self {
        Self {
            foundation: ice::utils::generate_foundation(
                CandidateType::ServerReflexive,
                local_address,
                Some(stun_server),
            ),
            priority: ice::utils::calculate_candidate_priority(
                CandidateType::ServerReflexive,
                65534,
                1,
            ),
            address: public_address,
            candidate_type: CandidateType::ServerReflexive,
            related_address: Some(local_address),
            attributes: CandidateAttributes::default(),
        }
    }

    /// Создание relay кандидата
    pub fn relay(relay_address: SocketAddr, local_address: SocketAddr, secure: bool) -> Self {
        let priority_offset = if secure { 0 } else { 10 };
        Self {
            foundation: ice::utils::generate_foundation(CandidateType::Relay, local_address, None),
            priority: ice::utils::calculate_candidate_priority(
                CandidateType::Relay,
                65533 - priority_offset,
                1,
            ),
            address: relay_address,
            candidate_type: CandidateType::Relay,
            related_address: Some(local_address),
            attributes: CandidateAttributes::default(),
        }
    }

    /// Проверка, является ли кандидат публичным
    pub fn is_public(&self) -> bool {
        ice::utils::is_public_address(&self.address)
    }

    /// Получение стоимости сети
    pub fn network_cost(&self) -> u16 {
        self.attributes.network_cost
    }
}

/// Transport protocol for ICE candidates
///
/// RFC 8445 Section 5.1.2.1: Transport Protocol
/// "The transport protocol used by the candidate. This specification
///  only defines UDP. However, extensibility is provided to allow for
///  future transport protocols to be used with ICE, such as TCP active,
///  TCP passive, or TCP simultaneous-open."
///
/// RFC 6544: ICE-TCP (TCP Candidates with Interactive Connectivity Establishment)
/// Defines how TCP can be used as a transport protocol for ICE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportProtocol {
    /// UDP transport (RFC 8445 default)
    /// The primary transport protocol for ICE, providing best compatibility
    /// and performance for NAT traversal scenarios.
    Udp,

    /// TCP transport (RFC 6544: ICE-TCP)
    /// Alternative transport when UDP is blocked by firewalls.
    /// Supports Active, Passive, and Simultaneous-Open connection types.
    Tcp,
}

impl TransportProtocol {
    /// Convert to protocol string for SDP/ICE messages
    /// Returns "udp" or "tcp" as per RFC 8445 Section 5.1.2.1
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }

    /// Parse from protocol string
    /// Accepts "UDP", "udp", "TCP", "tcp" (case-insensitive per RFC 8445)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "udp" => Some(Self::Udp),
            "tcp" => Some(Self::Tcp),
            _ => None,
        }
    }

    /// Check if this is a reliable transport
    /// TCP provides reliability, UDP does not (per RFC 793 and RFC 768)
    pub fn is_reliable(&self) -> bool {
        matches!(self, Self::Tcp)
    }

    /// Get default port for this protocol
    /// These are IANA registered ports for ICE/STUN
    pub fn default_port(&self) -> u16 {
        match self {
            Self::Udp => 3478, // STUN default UDP port (RFC 8489)
            Self::Tcp => 3478, // STUN default TCP port (RFC 8489)
        }
    }
}

impl Default for TransportProtocol {
    /// Default to UDP per RFC 8445 Section 2.1
    fn default() -> Self {
        Self::Udp
    }
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Тип ICE кандидата
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CandidateType {
    /// Host кандидат (локальный адрес)
    Host,
    /// Server reflexive (определен через STUN)
    ServerReflexive,
    /// Peer reflexive (обнаружен во время connectivity checks)
    PeerReflexive,
    /// Relay кандидат (через TURN сервер)
    Relay,
    /// Router pool кандидат (из пула роутеров)
    RouterPool,
    /// Hairpin кандидат (NAT loopback)
    Hairpin,
}

/// Атрибуты кандидата
///
/// RFC 8445 Section 5.1: Candidate Attributes
/// Contains all necessary attributes for ICE candidate description
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateAttributes {
    /// Транспортный протокол (RFC 8445 Section 5.1.2.1)
    /// UDP (default) or TCP (RFC 6544)
    pub transport: TransportProtocol,

    /// ID компонента (RFC 8445 Section 5.1.2.2)
    /// 1 for RTP, 2 for RTCP, per RFC 5245 conventions
    pub component: u16,

    /// Стоимость сети (RFC 8445 Section 5.1.2)
    /// Lower values indicate higher preference
    /// Range: 0-65535, where 0 is highest cost
    pub network_cost: u16,

    /// Поколение ICE (RFC 8445 Section 2.5: ICE Restart)
    /// Incremented each time ICE restarts
    pub generation: u32,

    /// ID сети (RFC 8445 Section 5.1.3)
    /// Identifies the network interface for multi-homed hosts
    pub network_id: u32,

    /// Дополнительные расширения (RFC 8445 Section 5.1)
    /// Allows for future extensibility without breaking compatibility
    pub extensions: std::collections::HashMap<String, String>,

    /// SHARP-256 extension: hairpin detection capability
    pub hairpin_capable: bool,

    /// SHARP-256 extension: encryption capability
    pub encryption_capable: bool,
}

impl Default for CandidateAttributes {
    fn default() -> Self {
        Self {
            // Default to UDP per RFC 8445
            transport: TransportProtocol::Udp,
            // Component 1 (RTP) is the default per RFC 5245
            component: 1,
            // Network cost 0 = highest preference
            network_cost: 0,
            // Initial generation
            generation: 0,
            // Default network ID
            network_id: 1,
            // No extensions by default
            extensions: std::collections::HashMap::new(),
            // SHARP-256 extensions default to false
            hairpin_capable: false,
            encryption_capable: false,
        }
    }
}

impl CandidateAttributes {
    /// Create attributes for a specific transport protocol
    pub fn with_transport(transport: TransportProtocol) -> Self {
        Self {
            transport,
            ..Default::default()
        }
    }

    /// Create attributes with custom component ID
    pub fn with_component(component: u16) -> Self {
        Self {
            component,
            ..Default::default()
        }
    }

    /// Check if attributes are compatible for pairing
    /// Per RFC 8445 Section 6.1.2.2: candidates must have matching transport and component
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.transport == other.transport && self.component == other.component
    }
}

/// Пара кандидатов для connectivity checks
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidatePair {
    /// Локальный кандидат
    pub local: Candidate,
    /// Удаленный кандидат
    pub remote: Candidate,
    /// Приоритет пары
    pub priority: u64,
    /// Состояние пары
    pub state: CandidatePairState,
    /// Номинирована ли пара
    pub nominated: bool,
    /// Время последней активности
    #[serde(skip)]
    pub last_activity: Option<Instant>,
    /// Round-Trip Time (RFC 8445 Section 6)
    /// Measured during connectivity checks during STUN binding requests
    pub rtt: Option<Duration>,
}

impl CandidatePair {
    /// Создание новой пары кандидатов
    pub fn new(local: Candidate, remote: Candidate) -> Self {
        let priority = ice::utils::calculate_pair_priority(true, local.priority, remote.priority);
        Self {
            local,
            remote,
            priority,
            state: CandidatePairState::Waiting,
            nominated: false,
            last_activity: None,
            rtt: None,
        }
    }

    /// Обновление состояния пары
    pub fn update_state(&mut self, new_state: CandidatePairState) {
        self.state = new_state;
        self.last_activity = Some(Instant::now());
    }

    /// Проверка совместимости кандидатов
    ///
    /// RFC 8445 Section 6.1.2.2: Forming Candidate Pairs
    /// "Candidates MUST have the same IP address version and transport protocol"
    pub fn is_compatible(&self) -> bool {
        // IP версии должны совпадать (RFC 8445 Section 6.1.2.2)
        if self.local.address.is_ipv4() != self.remote.address.is_ipv4() {
            return false;
        }

        // Транспорт и компонент должны совпадать (RFC 8445 Section 6.1.2.2)
        if !self
            .local
            .attributes
            .is_compatible_with(&self.remote.attributes)
        {
            return false;
        }

        true
    }
}

/// Состояние пары кандидатов
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidatePairState {
    /// Ожидает проверки
    Waiting,
    /// Проверка в процессе
    InProgress,
    /// Проверка успешна
    Succeeded,
    /// Проверка неудачна
    Failed,
    /// Заморожена (будет проверена позже)
    Frozen,
}

/// Результат connectivity check
#[derive(Debug, Clone)]
pub struct ConnectivityCheckResult {
    /// Проверенная пара
    pub pair: CandidatePair,
    /// Успешность проверки
    pub success: bool,
    /// Round-trip time
    pub rtt: Option<Duration>,
    /// Сообщение об ошибке
    pub error: Option<String>,
    /// Время проверки
    pub timestamp: Instant,
}

/// Метрики connectivity
#[derive(Debug, Clone, Default)]
pub struct ConnectivityMetrics {
    /// Время начала
    pub started_at: Option<Instant>,
    /// Время завершения
    pub completed_at: Option<Instant>,
    /// Количество собранных кандидатов
    pub candidates_gathered: u64,
    /// Количество connectivity checks
    pub connectivity_checks: u64,
    /// Количество успешных checks
    pub successful_checks: u64,
    /// Количество номинаций
    pub nominations: u64,
    /// Среднее RTT
    pub average_rtt: Option<Duration>,
}

impl ConnectivityMetrics {
    pub fn new() -> Self {
        Self {
            started_at: Some(Instant::now()),
            ..Default::default()
        }
    }

    pub fn duration(&self) -> Option<Duration> {
        if let (Some(start), Some(end)) = (self.started_at, self.completed_at) {
            Some(end - start)
        } else {
            None
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.connectivity_checks > 0 {
            self.successful_checks as f64 / self.connectivity_checks as f64
        } else {
            0.0
        }
    }
}

/// События connectivity системы
#[derive(Debug, Clone)]
pub enum ConnectivityEvent {
    /// Начался сбор кандидатов
    GatheringStarted,
    /// Новый кандидат найден
    CandidateGathered(Candidate),
    /// Сбор кандидатов завершен
    GatheringComplete(Vec<Candidate>),
    /// Начались connectivity checks
    ConnectivityChecksStarted,
    /// Результат connectivity check
    ConnectivityCheckResult(ConnectivityCheckResult),
    /// Nomination начата для пары
    NominationStarted {
        component_id: u32,
        pair: CandidatePair,
    },
    /// Пара кандидатов номинирована
    CandidatePairNominated(CandidatePair),
    /// Соединение установлено (PHASE 2: will include connection info)
    ConnectionEstablished,
    /// Соединение закрыто
    ConnectionClosed,
    /// Ошибка в процессе подключения
    Error(String),
    /// Метрики обновлены
    MetricsUpdated(ConnectivityMetrics),
}

/// === ГЛАВНАЯ СТРУКТУРА CONNECTIVITY ===

/* PHASE 2: Connectivity wrapper will be rebuilt from scratch
/// Главная структура для управления connectivity
pub struct Connectivity {
    /// Менеджер connectivity
    manager: Arc<ConnectivityManager>,
    /// Конфигурация
    config: ConnectivityConfig,
    /// События
    event_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<ConnectivityEvent>>>>,
}

impl Connectivity {
    /// Создание новой connectivity системы с конфигурацией по умолчанию
    pub async fn new() -> Result<Self> {
        let config = ConnectivityConfig::default();
        Self::with_config(config).await
    }

    /// Создание с пользовательской конфигурацией
    pub async fn with_config(config: ConnectivityConfig) -> Result<Self> {
        let mut manager = ConnectivityManager::new(config.clone()).await?;

        // Получаем event receiver
        let event_rx = manager.take_event_receiver().await;

        Ok(Self {
            manager: Arc::new(manager),
            config,
            event_rx: Arc::new(Mutex::new(event_rx)),
        })
    }

    /// Создание для controlling роли
    pub async fn new_controlling() -> Result<Self> {
        let mut config = ConnectivityConfig::default();
        config.ice.controlling_role = Some(true);
        Self::with_config(config).await
    }

    /// Создание для controlled роли
    pub async fn new_controlled() -> Result<Self> {
        let mut config = ConnectivityConfig::default();
        config.ice.controlling_role = Some(false);
        Self::with_config(config).await
    }

    /// Создание оптимизированной конфигурации для P2P
    pub async fn new_p2p_optimized() -> Result<Self> {
        let mut config = ConnectivityConfig::default();
        #[cfg(feature = "webrtc-ice-stack")]
        {
            config.ice = create_p2p_ice_config();
        }
        config.general.connection_methods_order = vec![
            ConnectionMethod::Ice,
            ConnectionMethod::Direct,
            ConnectionMethod::LibP2p,
        ];
        Self::with_config(config).await
    }

    /// Создание для тестирования
    pub async fn new_for_testing() -> Result<Self> {
        let mut config = ConnectivityConfig::default();
        #[cfg(feature = "webrtc-ice-stack")]
        {
            config.ice = create_test_ice_config();
        }
        config.general.connection_methods_order = vec![
            ConnectionMethod::Ice,
            ConnectionMethod::Direct,
        ];
        Self::with_config(config).await
    }

    /// === ОСНОВНЫЕ МЕТОДЫ ===

    /// Установление соединения
    pub async fn establish_connection(
        &self,
        socket: Arc<UdpSocket>,
        peer_hint: Option<SocketAddr>,
        is_controlling: bool,
    ) -> Result<EstablishedConnection> {
        self.manager.establish_connection(socket, peer_hint, is_controlling).await
    }

    /// Получение connectable адреса
    pub async fn get_connectable_address(&self) -> Result<SocketAddr> {
        self.manager.get_connectable_address().await
    }

    /// Добавление удаленного кандидата
    pub async fn add_remote_candidate(&self, candidate: Candidate) -> Result<()> {
        self.manager.add_remote_candidate(candidate).await
    }

    /// Получение локальных кандидатов
    pub async fn get_local_candidates(&self) -> Vec<Candidate> {
        self.manager.get_local_candidates().await
    }

    /// === MONITORING И СТАТИСТИКА ===

    /// Получение текущего состояния
    pub async fn get_state(&self) -> ConnectionState {
        self.manager.get_state().await
    }

    /// Получение базовых метрик
    pub async fn get_metrics(&self) -> ConnectivityMetrics {
        self.manager.get_metrics().await
    }

    /// Получение детальной статистики
    pub async fn get_detailed_stats(&self) -> DetailedConnectivityStats {
        self.manager.get_detailed_stats().await
    }

    /// Получение receiver для событий
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<ConnectivityEvent>> {
        self.event_rx.lock().take()
    }

    /// === ICE СПЕЦИФИЧНЫЕ МЕТОДЫ ===

    /// Restart ICE процесса (только для ICE)
    #[cfg(feature = "webrtc-ice-stack")]
    pub async fn restart_ice(&self) -> Result<()> {
        self.manager.restart_ice().await
    }

    /// === УТИЛИТЫ ===

    /// Проверка поддержки различных features
    pub fn get_supported_features(&self) -> SupportedFeatures {
        SupportedFeatures {
            webrtc_ice: cfg!(feature = "webrtc-ice-stack"),
            libp2p_fallback: cfg!(feature = "libp2p-fallback"),
            relay_encryption: cfg!(feature = "relay-encryption"),
            nat_router_pools: cfg!(feature = "nat-router-pools"),
            upnp_support: cfg!(feature = "upnp-support"),
        }
    }

    /// Валидация конфигурации
    pub fn validate_config(&self) -> Result<()> {
        self.config.validate()
    }

    /// Проверка готовности к установлению соединения
    pub async fn is_ready(&self) -> bool {
        match self.get_state().await {
            ConnectionState::New => true,
            ConnectionState::Failed => true,
            ConnectionState::Closed => false,
            _ => false,
        }
    }

    /// Остановка connectivity системы
    pub async fn shutdown(&self) -> Result<()> {
        self.manager.shutdown().await
    }
}
*/

/// Поддерживаемые возможности
#[derive(Debug, Clone)]
pub struct SupportedFeatures {
    pub webrtc_ice: bool,
    pub libp2p_fallback: bool,
    pub relay_encryption: bool,
    pub nat_router_pools: bool,
    pub upnp_support: bool,
}

impl SupportedFeatures {
    /// Получение списка активных features
    pub fn active_features(&self) -> Vec<&'static str> {
        let mut features = Vec::new();
        if self.webrtc_ice {
            features.push("webrtc-ice-stack");
        }
        if self.libp2p_fallback {
            features.push("libp2p-fallback");
        }
        if self.relay_encryption {
            features.push("relay-encryption");
        }
        if self.nat_router_pools {
            features.push("nat-router-pools");
        }
        if self.upnp_support {
            features.push("upnp-support");
        }
        features
    }

    /// Проверка минимальных требований
    pub fn meets_minimum_requirements(&self) -> bool {
        // Минимум нужен хотя бы один метод подключения
        self.webrtc_ice || self.libp2p_fallback
    }
}

/* PHASE 2: Utility functions will be rebuilt
/// === UTILITY ФУНКЦИИ ===

/// Создание стандартной connectivity системы
pub async fn create_standard_connectivity() -> Result<Connectivity> {
    Connectivity::new().await
}

/// Создание connectivity для P2P файлообмена
pub async fn create_p2p_connectivity() -> Result<Connectivity> {
    Connectivity::new_p2p_optimized().await
}

/// Создание connectivity для тестирования
pub async fn create_test_connectivity() -> Result<Connectivity> {
    Connectivity::new_for_testing().await
}

/// Автоматическое создание connectivity с оптимальной конфигурацией
pub async fn create_auto_connectivity() -> Result<Connectivity> {
    // Определяем лучшую конфигурацию на основе окружения
    let features = SupportedFeatures {
        webrtc_ice: cfg!(feature = "webrtc-ice-stack"),
        libp2p_fallback: cfg!(feature = "libp2p-fallback"),
        relay_encryption: cfg!(feature = "relay-encryption"),
        nat_router_pools: cfg!(feature = "nat-router-pools"),
        upnp_support: cfg!(feature = "upnp-support"),
    };

    if !features.meets_minimum_requirements() {
        return Err(anyhow::anyhow!(
            "No connectivity methods available. Enable at least webrtc-ice-stack or libp2p-fallback features"
        ));
    }

    if features.webrtc_ice {
        // Предпочитаем WebRTC ICE если доступно
        create_p2p_connectivity().await
    } else if features.libp2p_fallback {
        // Fallback на libp2p
        let mut config = ConnectivityConfig::default();
        config.general.connection_methods_order = vec![
            ConnectionMethod::LibP2p,
            ConnectionMethod::Direct,
        ];
        Connectivity::with_config(config).await
    } else {
        // Минимальная конфигурация только с Direct
        let mut config = ConnectivityConfig::default();
        config.general.connection_methods_order = vec![ConnectionMethod::Direct];
        Connectivity::with_config(config).await
    }
}
*/

/* PHASE 2: Compatibility layer will be removed
/// === COMPATIBILITY LAYER ===

/// Compatibility layer для старого NAT API
#[cfg(feature = "webrtc-ice-stack")]
pub mod nat_compat {
    //! Совместимость с старым NAT API для плавного перехода

    use super::*;
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    /// Эмуляция старого NatManager
    pub struct NatManager {
        connectivity: Connectivity,
    }

    impl NatManager {
        /// Создание нового NAT manager (теперь использует connectivity)
        pub async fn new() -> Result<Self> {
            let connectivity = Connectivity::new().await?;
            Ok(Self { connectivity })
        }

        /// Инициализация (совместимость)
        pub async fn initialize(&self, _socket: &UdpSocket) -> Result<()> {
            // В новой системе инициализация происходит при создании соединения
            Ok(())
        }

        /// Получение connectable адреса
        pub async fn get_connectable_address(&self) -> Result<SocketAddr> {
            self.connectivity.get_connectable_address().await
        }

        /// Подготовка соединения
        pub async fn prepare_connection(
            &self,
            socket: &UdpSocket,
            peer_addr: SocketAddr,
            is_initiator: bool,
        ) -> Result<()> {
            let socket_arc = Arc::new(socket.try_clone()?);
            let _connection = self.connectivity.establish_connection(
                socket_arc,
                Some(peer_addr),
                is_initiator
            ).await?;
            Ok(())
        }

        /// Cleanup (совместимость)
        pub async fn cleanup(&self) -> Result<()> {
            self.connectivity.shutdown().await
        }
    }
}
*/

/// === КОНСТАНТЫ И ВЕРСИИ ===

/// Версия connectivity модуля
pub const CONNECTIVITY_VERSION: &str = "2.0.0";

/// Поддерживаемые спецификации
pub const SUPPORTED_SPECIFICATIONS: &[&str] = &[
    "RFC 8445 - Interactive Connectivity Establishment (ICE)",
    "RFC 8838 - Trickle ICE",
    "RFC 7675 - STUN Usage for Consent Freshness",
    "RFC 8421 - Guidelines for Multihomed and IPv4/IPv6 Dual-Stack ICE",
    "SHARP-256 Protocol Extensions",
];

/// Информация о системе connectivity
pub fn connectivity_info() -> String {
    let features = SupportedFeatures {
        webrtc_ice: cfg!(feature = "webrtc-ice-stack"),
        libp2p_fallback: cfg!(feature = "libp2p-fallback"),
        relay_encryption: cfg!(feature = "relay-encryption"),
        nat_router_pools: cfg!(feature = "nat-router-pools"),
        upnp_support: cfg!(feature = "upnp-support"),
    };

    format!(
        "SHARP-256 Connectivity v{}\nActive features: {:?}\nSupported specs: {:?}",
        CONNECTIVITY_VERSION,
        features.active_features(),
        SUPPORTED_SPECIFICATIONS
    )
}

/// === TESTS ===

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    /* PHASE 2: Connectivity tests will be rewritten
    #[tokio::test]
    async fn test_connectivity_creation() {
        let connectivity = create_test_connectivity().await;
        assert!(connectivity.is_ok());

        let connectivity = connectivity.unwrap();
        assert!(connectivity.is_ready().await);
    }

    #[tokio::test]
    async fn test_supported_features() {
        let connectivity = create_test_connectivity().await.unwrap();
        let features = connectivity.get_supported_features();

        // В тестах должен быть доступен хотя бы один метод
        assert!(features.meets_minimum_requirements());
    }
    */

    #[tokio::test]
    async fn test_candidate_creation() {
        let host_candidate = Candidate::host("192.168.1.1:5000".parse().unwrap());
        assert_eq!(host_candidate.candidate_type, CandidateType::Host);
        assert!(!host_candidate.is_public());

        let public_candidate = Candidate::host("8.8.8.8:53".parse().unwrap());
        assert!(public_candidate.is_public());
    }

    #[tokio::test]
    async fn test_candidate_pair() {
        let local = Candidate::host("192.168.1.1:5000".parse().unwrap());
        let remote = Candidate::host("192.168.1.2:5000".parse().unwrap());

        let pair = CandidatePair::new(local, remote);
        assert!(pair.is_compatible());
        assert_eq!(pair.state, CandidatePairState::Waiting);
        assert!(pair.priority > 0);
    }

    #[cfg(feature = "webrtc-ice-stack")]
    #[tokio::test]
    async fn test_ice_config_validation() {
        let config = create_test_ice_config();
        assert!(validate_ice_config(&config).is_ok());
    }

    #[tokio::test]
    async fn test_connectivity_info() {
        let info = connectivity_info();
        assert!(info.contains("SHARP-256 Connectivity"));
        assert!(info.contains("v2.0.0"));
    }

    /* PHASE 2: Tests will be rewritten when Connectivity is rebuilt
    #[tokio::test]
    async fn test_auto_connectivity_creation() {
        let connectivity = create_auto_connectivity().await;
        // Должен создаться даже если не все features доступны
        assert!(connectivity.is_ok());
    }

    #[cfg(feature = "webrtc-ice-stack")]
    #[tokio::test]
    async fn test_nat_compat() {
        let nat_manager = nat_compat::NatManager::new().await;
        assert!(nat_manager.is_ok());
    }
    */
}
